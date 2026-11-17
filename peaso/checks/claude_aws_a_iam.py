"""claude_aws_a IAM: Steampipe (aws-compliance / aws-perimeter) policy, principal,
credential-report and account predicates, plus the Prowler identity-hygiene checks.

Policy text follows Steampipe ``policy_std``: actions are lowercased, Action/Resource
become arrays, a statement without Resource yields no Resource rows, and SQL ``LIKE``
patterns without ``%`` are exact equality (``*`` is literal). Prowler checks use the raw
documents. Membership of groups comes from each user's GAAD ``GroupList``.
"""
from __future__ import annotations

from fnmatch import fnmatchcase

import json
from collections.abc import Mapping
from datetime import timedelta

from .facts import MemoIndex, Unavailable, get, list_of_objects, guard, memoized, optional
from .claude_aws_a_common import (install, absent_or, items, clock, parse_time, policy_document, text, strings, as_list,
    turbot_public_statements, _statement_effect, idx, C, P, R, ACCOUNT)
from .claude_aws_a_ec2 import w, DROP, partition, midnight_cutoff

IAM_API = "https://docs.aws.amazon.com/IAM/latest/APIReference/"
IAM_UG = "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
GAAD = IAM_API + "API_GetAccountAuthorizationDetails.html"
CRED = IAM_UG + "id_credentials_getting-report.html"

PRINCIPALS = {"iam_user": ("UserName", "UserPolicyList", "user"), "iam_role": ("RoleName", "RolePolicyList", "role"),
              "iam_group": ("GroupName", "GroupPolicyList", "group")}


# --------------------------------------------------------------------------- shared accessors
def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    out = {"Effect": "Allow", "Action": action}
    if resource is not None:
        out["Resource"] = resource
    out.update(extra)
    return out


def arn_account(arn):
    parts = text(arn, "ARN").split(":")
    if len(parts) < 6 or parts[0] != "arn":
        raise Unavailable("malformed ARN")
    return parts[4]


def is_aws_managed(policy):
    return arn_account(get(policy, "Arn", str)) == "aws"


def default_document(policy):
    version_id = get(policy, "DefaultVersionId", str)
    if not version_id:
        raise Unavailable("default policy version ID empty")
    versions = list_of_objects(get(policy, "PolicyVersionList", list))
    version_ids = [get(v, "VersionId", str) for v in versions]
    if any(not v for v in version_ids) or len(set(version_ids)) != len(version_ids):
        raise Unavailable("policy version IDs empty or duplicated")
    defaults = [v for v in versions if get(v, "IsDefaultVersion", bool)]
    if len(defaults) != 1 or get(defaults[0], "VersionId", str) != version_id:
        raise Unavailable("exactly one matching default policy version required")
    return get(defaults[0], "Document")


def policy_attached(policy):
    count = get(policy, "AttachmentCount", int)
    if count < 0:
        raise Unavailable("negative attachment count")
    return count > 0


def std(statements, *, principal_aws=False, resource_policy=False, principal_action_ok=None):
    """Steampipe projection; trust and selected resource policies consume Principal.AWS."""
    out = []
    for s in statements:
        row = {"Effect": _statement_effect(s), "_raw": s}
        if resource_policy:
            if principal_aws or principal_action_ok is None:
                raise ValueError("resource policy needs an action selector")
            # Only a matching Allow row can contribute a principal to these
            # source predicates. Deny and unrelated actions consume no principal.
            if row["Effect"] != "Allow":
                out.append(row)
                continue
            for key in ("Action", "NotAction"):
                value = optional(s, key, None) if key == "Action" else s.get(key)
                if value is not None:
                    row[key] = sorted({a.lower() for a in strings(as_list(value), key)})
            if not principal_action_ok(row.get("Action", [])):
                out.append(row)
                continue
            for key in ("Resource", "NotResource"):
                value = optional(s, key, None) if key == "Resource" else s.get(key)
                if value is not None:
                    row[key] = sorted(set(strings(as_list(value), key)))
        if principal_aws or resource_policy:
            # The caller counts Allow statements only.  A known Deny cannot
            # contribute a cross-account principal, so its Principal is unused.
            if row["Effect"] != "Allow":
                out.append(row)
                continue
            principal = optional(s, "Principal", None)
            if principal == "*":
                row["PrincipalAWS"] = ["*"]
            elif isinstance(principal, dict):
                # AWS may be omitted, but a declared unreadable AWS child is
                # still selected authority even when Service is present.
                optional(principal, "AWS", None)
                keys = set(principal) - {"_coverage", "collection_status"}
                if not keys or not keys <= {"AWS", "Service", "Federated", "CanonicalUser"}:
                    raise Unavailable("malformed trust Principal")
                for key in keys:
                    value = optional(principal, key, None)
                    if isinstance(value, str):
                        values = [value]
                    elif isinstance(value, list):
                        values = strings(value, "Principal." + key)
                    else:
                        raise Unavailable("malformed trust Principal." + key)
                    if not values or any(not v.strip() for v in values):
                        raise Unavailable("empty trust Principal." + key)
                    if key == "AWS":
                        row["PrincipalAWS"] = sorted(set(values))
            else:
                raise Unavailable("malformed trust Principal")
        else:
            for key in ("Action", "NotAction"):
                value = optional(s, key, None) if key == "Action" else s.get(key)
                if value is not None:
                    row[key] = sorted({a.lower() for a in strings(as_list(value), key)})
            for key in ("Resource", "NotResource"):
                value = optional(s, key, None) if key == "Resource" else s.get(key)
                if value is not None:
                    row[key] = sorted(set(strings(as_list(value), key)))
        out.append(row)
    return out


def _identity_existential_hits(document_readers, predicate):
    """Count independently observed violations; uncertainty cannot establish PASS."""
    hits, uncertain = 0, False
    for read_document in document_readers:
        try:
            statements = policy_document(read_document())
        except Unavailable:
            uncertain = True
            continue
        for statement in statements:
            try:
                if _statement_effect(statement) != "Allow":
                    continue  # These identity predicates never count Deny rows.
                hits += predicate(std([statement]))
            except Unavailable:
                uncertain = True
    if hits:
        return hits
    if uncertain:
        raise Unavailable("identity policy statements unresolved")
    return 0


def _identity_policy_hits(policy, predicate):
    return _identity_existential_hits([lambda: default_document(policy)], predicate)


def _identity_inline_hits(item, kind, predicate):
    readers = [lambda policy=policy: get(policy, "PolicyDocument") for policy in inline_policies(item, kind)]
    return _identity_existential_hits(readers, predicate)


def policy_std(policy):
    return std(policy_document(default_document(policy)))


def count_rows(statements, action_ok, resource_ok=lambda r: True):
    """Number of (statement, resource, action) rows of the Steampipe cross join that match."""
    hits = 0
    for s in statements:
        if s["Effect"] != "Allow":
            continue
        for resource in s.get("Resource", []):
            if not resource_ok(resource):
                continue
            hits += sum(1 for a in s.get("Action", []) if action_ok(a))
    return hits


_ANY_KEY_IDS = ("0f1e2d3c-4b5a-6978-8a9b-acbdcedf0011", "mrk-5a6b7c8d9e0f11223344556677889900")


def kms_all_keys_resource(resource):
    """Whether a Resource pattern covers arbitrary KMS keys ("*", key/*, alias/*, arn:aws:kms:*...).

    A single key ARN, or a pattern pinned to a specific key or alias name, covers one key. The
    pattern is tested against two unrelated key IDs in the pattern's own region and account, so
    only a wildcard in the key/alias position (or a bare "*") counts.
    """
    if not isinstance(resource, str):
        return False
    if resource == "*":
        return True
    parts = resource.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not fnmatchcase("kms", parts[2]):
        return False
    region = parts[3] if not any(c in parts[3] for c in "*?") else "us-east-1"
    acct = parts[4] if not any(c in parts[4] for c in "*?") else "123456789012"
    partition = parts[1] if not any(c in parts[1] for c in "*?") else "aws"
    for kind, names in (("key", _ANY_KEY_IDS), ("alias", ("alias/zz-unrelated-a", "alias/zz-unrelated-b"))):
        candidates = ["arn:%s:kms:%s:%s:%s" % (partition, region, acct, n if kind == "alias" else "key/" + n) for n in names]
        if all(fnmatchcase(c, resource) for c in candidates):
            return True
    return False


def _pinned(values):
    values = values if isinstance(values, list) else [values]
    # "?" matches one character (e.g. the 6-character Secrets Manager ARN suffix); "*" opens the value up.
    return bool(values) and all(isinstance(v, str) and "*" not in v and v.strip("?") for v in values)


def kms_condition_restricts_keys(statement):
    """Condition pins the usable keys or ciphertexts to specific values.

    kms:EncryptionContext:<k> / kms:EncryptionContextKeys / aws:ResourceTag/<k> / kms:KeyOrigin-style
    values under a positive String operator (StringEquals, StringLike without wildcard, ForAnyValue)
    restrict which data or keys can be decrypted. IfExists and ForAllValues operators do not: they
    also match a request that carries no such key (for example a ciphertext without encryption
    context), so every key and ciphertext stays usable. kms:ViaService alone does not either.
    """
    condition = statement.get("Condition") if isinstance(statement, dict) else None
    if not isinstance(condition, dict):
        return False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        lowered = operator.lower()
        if lowered.endswith("ifexists") or lowered.startswith("forallvalues:"):
            continue
        op = lowered.split(":")[-1]
        if op not in ("stringequals", "stringequalsignorecase", "stringlike", "arnequals", "arnlike"):
            continue
        for key, value in block.items():
            k = key.lower() if isinstance(key, str) else ""
            if (k.startswith("kms:encryptioncontext:") or k in ("kms:encryptioncontextkeys", "kms:grantoperations")
                    or k.startswith("aws:resourcetag/")) and _pinned(value):
                return True
    return False


def kms_blocked_rows(statements, actions):
    """Allow rows granting ``actions`` on all KMS keys without a key-restricting condition."""
    return count_rows([s for s in statements if not kms_condition_restricts_keys(s.get("_raw"))],
                      lambda a: a in actions, kms_all_keys_resource)


def star_star(statements):
    return count_rows(statements, lambda a: a in ("*", "*:*"), lambda r: r == "*")


def inline_policies(item, kind):
    name_key, list_key, _ = PRINCIPALS[kind]
    return list_of_objects(absent_or(item, name_key, list_key, [], list))


def inline_std(item, kind):
    out = []
    for policy in inline_policies(item, kind):
        out.extend(std(policy_document(get(policy, "PolicyDocument"))))
    return out


def attached_arns(item, kind):
    name_key = PRINCIPALS[kind][0]
    return [text(get(p, "PolicyArn", str)) for p in list_of_objects(absent_or(item, name_key, "AttachedManagedPolicies", [], list))]


def attached_names(item, kind):
    name_key = PRINCIPALS[kind][0]
    return [text(get(p, "PolicyName", str)) for p in list_of_objects(absent_or(item, name_key, "AttachedManagedPolicies", [], list))]


def service_role_path(item):
    return "service-role/" in get(item, "Arn", str)


def group_members(index, group_name):
    members = []
    for user in items(index, "iam_user"):
        groups = strings(get(user, "GroupList", list), "GroupList")
        if group_name in groups:
            members.append(get(user, "UserName", str))
    return members


def _in_use_arns(index):
    arns = set()
    for user in items(index, "iam_user"):
        arns.update(attached_arns(user, "iam_user"))
    populated = set()
    for user in items(index, "iam_user"):
        populated.update(strings(get(user, "GroupList", list), "GroupList"))
    for group in items(index, "iam_group"):
        if get(group, "GroupName", str) in populated:
            arns.update(attached_arns(group, "iam_group"))
    for role in items(index, "iam_role"):
        arns.update(attached_arns(role, "iam_role"))
    return arns


def in_use_arns(index):
    # MemoIndex belongs to one sealed snapshot scope. Cache immutable membership
    # and give callers their own set; a plain dict keeps the original read path.
    if type(index) is MemoIndex:
        return set(memoized(index, ("iam_in_use_arns",), lambda: frozenset(_in_use_arns(index))))
    return _in_use_arns(index)


def _role_attached_arns(index):
    arns = set()
    for role in items(index, "iam_role"):
        arns.update(attached_arns(role, "iam_role"))
    return arns


def role_attached_arns(index):
    if type(index) is MemoIndex:
        return set(memoized(index, ("iam_role_attached_arns",), lambda: frozenset(_role_attached_arns(index))))
    return _role_attached_arns(index)


# --------------------------------------------------------------------------- fixtures
CUSTOM_ARN = "arn:aws:iam::%s:policy/app" % ACCOUNT
AWS_ARN = "arn:aws:iam::aws:policy/PowerUserAccess"


def pol(*statements, arn=CUSTOM_ARN, attached=1):
    return {"PolicyName": arn.rsplit("/", 1)[1], "Arn": arn, "AttachmentCount": attached, "DefaultVersionId": "v1",
            "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": doc(*statements)}]}


SAFE = pol(allow("s3:GetObject", "arn:aws:s3:::bucket/*"))
STAR = pol(allow("*"))
USER = {"UserName": "alice", "UserId": "AIDA1", "Arn": "arn:aws:iam::%s:user/alice" % ACCOUNT, "Path": "/",
        "GroupList": ["devs"], "UserPolicyList": [], "AttachedManagedPolicies": [],
        "AccessKeys": {"collection_status": "collected", "items": []}, "MFADevices": {"collection_status": "collected", "items": [{"SerialNumber": "arn:aws:iam::%s:mfa/alice" % ACCOUNT}]}}
GROUP = {"GroupName": "devs", "GroupId": "AGPA1", "Arn": "arn:aws:iam::%s:group/devs" % ACCOUNT, "Path": "/", "GroupPolicyList": [], "AttachedManagedPolicies": []}
TRUST = doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"})
ROLE = {"RoleName": "app", "RoleId": "AROA1", "Arn": "arn:aws:iam::%s:role/app" % ACCOUNT, "Path": "/", "AssumeRolePolicyDocument": TRUST,
        "RolePolicyList": [], "AttachedManagedPolicies": [], "RoleLastUsed": {"LastUsedDate": "2025-12-30T00:00:00+00:00", "Region": "us-east-1"}}
SVC_ROLE = w(ROLE, Arn="arn:aws:iam::%s:role/service-role/app" % ACCOUNT, Path="/service-role/")
FIXTURE = {"iam_user": USER, "iam_role": ROLE, "iam_group": GROUP}


def inline(kind, *statements, name="inline"):
    return w(FIXTURE[kind], **{PRINCIPALS[kind][1]: [{"PolicyName": name, "PolicyDocument": doc(*statements)}]})


def attach(kind, arn, base=None):
    return w(base or FIXTURE[kind], AttachedManagedPolicies=[{"PolicyArn": arn, "PolicyName": arn.rsplit("/", 1)[1]}])


# =========================================================================== Steampipe customer/AWS managed policies
@install("aws.claude_a.iam.custom_policy_no_star_star", "iam_policy", "Customer managed policy does not allow \"*\" on \"*\"",
    SAFE, STAR, rows=[C + "iam_policy_no_star_star"], severity="high", category="least_privilege", control="AC-6",
    remediation="Replace Action \"*\"/\"*:*\" on Resource \"*\" with the specific actions and resources the workload needs.",
    docs=[GAAD, IAM_UG + "best-practices.html#grant-least-privilege"], extra={"na": pol(allow("*"), arn=AWS_ARN)},
    note="Default policy version; aws-managed policies are outside the source population.")
def custom_star_star(item, index):
    if is_aws_managed(item):
        return "NOT_APPLICABLE", {"reason": "AWS managed policy"}
    hits = _identity_policy_hits(item, star_star)
    return result_rows(hits)


def result_rows(hits, **extra):
    from . import result
    return result(hits > 0, matching_statement_rows=hits, **extra)


@install("aws.claude_a.iam.custom_attached_policy_no_star_star", "iam_policy", "Attached customer managed policy does not allow \"*\" on \"*\"",
    SAFE, STAR, rows=[C + "iam_policy_custom_attached_no_star_star", C + "foundational_security_iam_1"], severity="high",
    category="least_privilege", control="AC-6", remediation="Remove full administrative \"*:*\" statements from attached customer managed policies.",
    docs=[GAAD, "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1"],
    extra={"na": pol(allow("*"), arn=AWS_ARN), "pass_unattached": pol(allow("*"), attached=0)},
    note="Source counts bad statements only while attached; unattached customer policies are reported ok.")
def custom_attached_star_star(item, index):
    if is_aws_managed(item):
        return "NOT_APPLICABLE", {"reason": "AWS managed policy"}
    hits = _identity_policy_hits(item, star_star) if policy_attached(item) else 0
    return result_rows(hits, attached=policy_attached(item))


@install("aws.claude_a.iam.custom_unattached_policy_no_star_star", "iam_policy", "Unattached customer managed policy does not allow \"*\" on \"*\"",
    pol(allow("s3:GetObject"), attached=0), pol(allow("*:*"), attached=0), rows=[C + "iam_custom_policy_unattached_no_star_star"],
    severity="medium", category="least_privilege", control="AC-6", remediation="Delete or narrow unattached customer managed policies granting \"*:*\".",
    docs=[GAAD], extra={"na": STAR})
def custom_unattached_star_star(item, index):
    if is_aws_managed(item) or policy_attached(item):
        return "NOT_APPLICABLE", {"reason": "AWS managed or attached policy"}
    return result_rows(_identity_policy_hits(item, star_star))


@install("aws.claude_a.iam.attached_policy_no_star_star", "iam_policy", "Attached IAM policy does not allow \"*\" on \"*\"",
    SAFE, STAR, rows=[C + "iam_policy_all_attached_no_star_star"], severity="high", category="least_privilege", control="AC-6",
    remediation="Detach or narrow attached policies that grant \"*\" on \"*\"; review AWS managed admin policies attached to principals.",
    docs=[GAAD], extra={"na": pol(allow("*"), attached=0), "pass_aws_clean": pol(allow("s3:Get*"), arn=AWS_ARN)},
    note="Source reports an attached AWS managed policy with \"*:*\" as info, which is mapped to NOT_APPLICABLE.")
def attached_star_star(item, index):
    if not policy_attached(item):
        return "NOT_APPLICABLE", {"reason": "policy not attached"}
    hits = _identity_policy_hits(item, star_star)
    if hits and is_aws_managed(item):
        return "NOT_APPLICABLE", {"reason": "source info status: AWS managed policy with \"*:*\"", "matching_statement_rows": hits}
    return result_rows(hits)


def _custom_action_check(cid, title, rows, matcher, failing, *, resource_ok=lambda r: r == "*", statement_ok=lambda raw: True, severity="high",
                         remediation, note=None, docs=(GAAD,)):
    @install(cid, "iam_policy", title, SAFE, failing, rows=rows, severity=severity, category="least_privilege", control="AC-6",
        remediation=remediation, docs=list(docs), extra={"na": w(failing, Arn=AWS_ARN)}, note=note)
    def evaluate(item, index):
        if is_aws_managed(item):
            return "NOT_APPLICABLE", {"reason": "AWS managed policy"}
        matched = set()
        def count_and_describe(rows):
            rows = [r for r in rows if statement_ok(r.get("_raw"))]
            hits = count_rows(rows, matcher, resource_ok)
            if hits:
                for statement in rows:
                    if statement["Effect"] == "Allow" and any(resource_ok(r) for r in statement.get("Resource", [])):
                        matched.update(a for a in statement.get("Action", []) if matcher(a))
            return hits
        return result_rows(_identity_policy_hits(item, count_and_describe), matching_actions=sorted(matched))
    return evaluate


_custom_action_check("aws.claude_a.iam.custom_policy_no_service_wildcard", "Customer managed policy does not allow a whole service (\"svc:*\" or \"*\") on \"*\"",
    [C + "iam_all_policy_no_service_wild_card", C + "foundational_security_iam_21"], lambda a: a == "*" or a.endswith(":*"),
    pol(allow("s3:*")), remediation="Replace service wildcards on Resource \"*\" with explicit actions.",
    docs=(GAAD, "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-21"))
_custom_action_check("aws.claude_a.iam.custom_policy_no_cloudtrail_star", "Customer managed policy does not allow \"cloudtrail:*\" on \"*\"",
    [C + "iam_policy_no_full_access_to_cloudtrail"], lambda a: a == "cloudtrail:*", pol(allow("cloudtrail:*")),
    remediation="Remove cloudtrail:* on \"*\"; grant only required CloudTrail actions to dedicated roles.")
_custom_action_check("aws.claude_a.iam.custom_policy_no_kms_star", "Customer managed policy does not allow \"kms:*\" on \"*\"",
    [C + "iam_policy_no_full_access_to_kms"], lambda a: a == "kms:*", pol(allow("kms:*")),
    remediation="Remove kms:* on \"*\"; grant key usage per key ARN.")
_custom_action_check("aws.claude_a.iam.custom_policy_no_blocked_kms_actions", "Customer managed policy does not allow kms:Decrypt or kms:ReEncryptFrom",
    [C + "iam_policy_custom_no_blocked_kms_actions"], lambda a: a in ("kms:decrypt", "kms:reencryptfrom"),
    pol(allow("kms:Decrypt", "*")), resource_ok=kms_all_keys_resource,
    statement_ok=lambda raw: not kms_condition_restricts_keys(raw), severity="medium",
    remediation="Remove kms:Decrypt/kms:ReEncryptFrom from customer managed policies or scope them to approved keys.",
    note="Exact lowercased actions kms:decrypt / kms:reencryptfrom (kms:* is not counted) on all keys (\"*\" or a key/alias wildcard); single-key resources and statements whose condition pins the encryption context or resource tags are scoped and do not count.")


def kms_decrypt_statements(statements, acct):
    resources = {"*", "arn:aws:kms:*:%s:key/*" % acct, "arn:aws:kms:*:%s:alias/*" % acct}
    actions = {"*", "kms:*", "kms:decrypt", "kms:reencryptfrom", "kms:reencrypt*"}
    return [s for s in statements if s["Effect"] == "Allow" and resources & set(s.get("Resource", [])) and actions & set(s.get("Action", []))]


@install("aws.claude_a.iam.custom_policy_kms_decrypt_restricted", "iam_policy", "Customer managed policy does not allow KMS decryption on all keys",
    SAFE, pol(allow("kms:Decrypt", "arn:aws:kms:*:%s:key/*" % ACCOUNT)),
    rows=[C + "kms_key_decryption_restricted_in_iam_customer_managed_policy", C + "foundational_security_kms_1"], severity="medium",
    category="least_privilege", control="AC-6", remediation="Scope kms:Decrypt/kms:ReEncryptFrom to the specific key ARNs.",
    docs=[GAAD, "https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-1"], extra={"na": w(STAR, Arn=AWS_ARN)},
    note="Exact array-element matches (?|) of Resource against *, arn:aws:kms:*:<account>:key/* or alias/* and Action against *, kms:*, kms:decrypt, kms:reencryptfrom, kms:reencrypt*.")
def custom_kms_decrypt(item, index):
    if is_aws_managed(item):
        return "NOT_APPLICABLE", {"reason": "AWS managed policy"}
    acct = arn_account(get(item, "Arn", str))
    hits = _identity_policy_hits(item, lambda rows: len(kms_decrypt_statements(rows, acct)))
    from . import result
    return result(bool(hits), matching_statements=hits)


def _role_attachment_check(cid, title, rows, aws_managed):
    target = pol(allow("s3:GetObject"), arn=AWS_ARN if aws_managed else CUSTOM_ARN)
    @install(cid, "iam_policy", title, target, w(target, Arn=target["Arn"] + "Other"), rows=rows, severity="low", control="AC-6",
        index=idx(iam_role=[attach("iam_role", target["Arn"])]), dependencies=["iam_policy", "iam_role"],
        remediation="Review managed policies that are not attached to any role and remove those that are not needed.", docs=[GAAD],
        extra={"na": (w(target, Arn=CUSTOM_ARN if aws_managed else AWS_ARN), idx(iam_role=[]))})
    def evaluate(item, index):
        if is_aws_managed(item) != aws_managed:
            return "NOT_APPLICABLE", {"reason": "outside source policy population"}
        arn = get(item, "Arn", str)
        from . import result
        attached = arn in role_attached_arns(index)
        return result(not attached, policy_arn=arn, role_attachment_found=attached)
    return evaluate


_role_attachment_check("aws.claude_a.iam.aws_managed_policy_attached_to_role", "AWS managed policy is attached to an IAM role",
    [C + "iam_managed_policy_attached_to_role"], True)
_role_attachment_check("aws.claude_a.iam.custom_policy_attached_to_role", "Customer managed policy is attached to an IAM role",
    [C + "iam_custom_managed_policy_attached_to_role"], False)

USE_INDEX = idx(iam_user=[attach("iam_user", CUSTOM_ARN)], iam_group=[GROUP], iam_role=[ROLE])


def _policy_in_use(cid, title, rows, custom_only):
    @install(cid, "iam_policy", title, SAFE, w(SAFE, Arn=CUSTOM_ARN + "2"), rows=rows, severity="low", control="CM-7",
        index=USE_INDEX, dependencies=["iam_policy", "iam_user", "iam_group", "iam_role"],
        remediation="Delete managed policies not attached to any user, populated group or role.", docs=[GAAD],
        extra={"fail_empty_group": (SAFE, idx(iam_user=[w(USER, GroupList=[])], iam_group=[attach("iam_group", CUSTOM_ARN)], iam_role=[]))}
        | ({"na": (w(SAFE, Arn=AWS_ARN), USE_INDEX)} if custom_only else {}),
        note="Group attachments count only when some user lists the group in GroupList (Steampipe users > 0).")
    def evaluate(item, index):
        if custom_only and is_aws_managed(item):
            return "NOT_APPLICABLE", {"reason": "AWS managed policy"}
        arn = get(item, "Arn", str)
        from . import result
        attached = arn in in_use_arns(index)
        return result(not attached, policy_arn=arn, attached_to_active_identity=attached)
    return evaluate


_policy_in_use("aws.claude_a.iam.policy_in_use", "Managed policy is attached to a user, populated group or role", [C + "iam_policy_unused"], False)
_policy_in_use("aws.claude_a.iam.custom_policy_in_use", "Customer managed policy is attached to a user, populated group or role", [C + "iam_custom_policy_unused"], True)


# =========================================================================== Steampipe per-principal inline / attachment predicates
def _principal_checks():
    from . import result
    for kind, (name_key, list_key, label) in PRINCIPALS.items():
        base = FIXTURE[kind]

        def make(kind=kind, label=label, base=base):
            @install("aws.claude_a.iam.%s_inline_no_blocked_kms_actions" % label, kind, "IAM %s inline policies do not allow blocked KMS decrypt actions" % label,
                base, inline(kind, allow("kms:Decrypt*", "*")), rows=[C + "iam_policy_inline_no_blocked_kms_actions"], severity="medium",
                category="least_privilege", control="AC-6", remediation="Remove broad KMS decrypt grants from inline policies; scope to approved keys.",
                docs=[GAAD], note="Exact lowercased actions kms:decrypt, kms:decrypt*, kms:reencryptfrom, kms:*, kms:reencrypt* on all keys (\"*\" or a key/alias wildcard); single-key resources and statements whose condition pins the encryption context or resource tags are scoped and do not count (kms:ViaService alone does not scope).")
            def blocked(item, index):
                hits = _identity_inline_hits(item, kind, lambda rows: kms_blocked_rows(rows, ("kms:decrypt", "kms:decrypt*", "kms:reencryptfrom", "kms:*", "kms:reencrypt*")))
                return result(hits > 0, matching_statement_rows=hits)

            na = {"na": w(SVC_ROLE, RolePolicyList=[{"PolicyName": "x", "PolicyDocument": doc(allow("kms:*"))}])} if kind == "iam_role" else {}

            @install("aws.claude_a.iam.%s_inline_kms_decrypt_restricted" % label, kind, "IAM %s inline policies do not allow KMS decryption on all keys" % label,
                base, inline(kind, allow("kms:Decrypt", "*")), rows=[C + "kms_key_decryption_restricted_in_iam_inline_policy", C + "foundational_security_kms_2"],
                severity="medium", category="least_privilege", control="AC-6", remediation="Scope inline kms:Decrypt/kms:ReEncryptFrom grants to specific key ARNs.",
                docs=[GAAD, "https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-2"], extra=na,
                note="Source action list is ['*','kms:*','kms:decrypt','kms:deencrypt*','kms:reencryptfrom'] (typo kept); roles under service-role/ are excluded.")
            def decrypt(item, index):
                if kind == "iam_role" and service_role_path(item):
                    return "NOT_APPLICABLE", {"reason": "service-role path"}
                acct = arn_account(get(item, "Arn", str))
                resources = {"*", "arn:aws:kms:*:%s:key/*" % acct, "arn:aws:kms:*:%s:alias/*" % acct}
                actions = {"*", "kms:*", "kms:decrypt", "kms:deencrypt*", "kms:reencryptfrom"}
                hits = _identity_inline_hits(item, kind, lambda rows: sum(1 for s in rows if s["Effect"] == "Allow" and resources & set(s.get("Resource", [])) and actions & set(s.get("Action", []))))
                return result(bool(hits), matching_statements=hits)

            @install("aws.claude_a.iam.%s_inline_no_admin" % label, kind, "IAM %s inline policies do not allow \"*\" on \"*\"" % label,
                base, inline(kind, allow("*:*")), rows=[C + "iam_inline_policy_no_administrative_privileges"], severity="high",
                category="least_privilege", control="AC-6", remediation="Remove administrative \"*\" grants from inline policies.", docs=[GAAD])
            def admin(item, index):
                hits = _identity_inline_hits(item, kind, star_star)
                return result(hits > 0, matching_statement_rows=hits)

            @install("aws.claude_a.iam.%s_no_inline_policies" % label, kind, ("IAM role outside service-role path has no inline policies" if label == "role" else "IAM %s has no inline policies" % label),
                base, inline(kind, allow("s3:GetObject")), rows=[C + "iam_group_user_role_no_inline_policies"], severity="low",
                category="least_privilege", control="AC-6", remediation="Move inline policies to managed policies that can be reviewed and versioned.",
                docs=[GAAD], extra=na, note="Roles under service-role/ are excluded by the source.")
            def no_inline(item, index):
                if kind == "iam_role" and service_role_path(item):
                    return "NOT_APPLICABLE", {"reason": "service-role path"}
                count = len(inline_policies(item, kind))
                return result(count > 0, inline_policy_count=count)

            @install("aws.claude_a.iam.%s_no_cloudshell_full_access" % label, kind, "IAM %s does not have AWSCloudShellFullAccess attached" % label,
                base, attach(kind, "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"), rows=[C + "iam_user_group_role_cloudshell_fullaccess_restricted"],
                severity="medium", category="least_privilege", control="AC-6", remediation="Detach AWSCloudShellFullAccess and grant scoped CloudShell permissions.",
                docs=[GAAD, IAM_UG + "reference_policies_examples_aws_cloudshell.html"], note="Exact commercial-partition ARN, as in the source.")
            def cloudshell(item, index):
                hit = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess" in attached_arns(item, kind)
                return result(hit, attached=hit)
        make()


_principal_checks()


# =========================================================================== Steampipe users
from . import result  # noqa: E402


@install("aws.claude_a.iam.user_inline_no_assume_role_text", "iam_user", "IAM user inline policies do not mention AssumeRole",
    USER, inline("iam_user", allow("sts:AssumeRole", "arn:aws:iam::%s:role/x" % ACCOUNT)), rows=[C + "iam_policy_custom_no_assume_role"],
    severity="medium", category="least_privilege", control="AC-6", remediation="Grant role assumption through reviewed managed policies and scoped trust policies.",
    docs=[GAAD], note="Source matches the case-sensitive text 'AssumeRole' anywhere in each inline policy JSON (name or document).")
def user_assume_role_text(item, index):
    hits = []
    for policy in inline_policies(item, "iam_user"):
        name = get(policy, "PolicyName", str)
        document = get(policy, "PolicyDocument")
        if not name:
            raise Unavailable("inline policy name unavailable")
        policy_document(document)  # Missing/denied/malformed documents are not negative text evidence.
        if "AssumeRole" in json.dumps({"PolicyDocument": document, "PolicyName": name}):
            hits.append(name)
    return result(bool(hits), policies=hits)


@install("aws.claude_a.iam.user_in_group", "iam_user", "IAM user is a member of at least one group",
    USER, w(USER, GroupList=[]), rows=[C + "iam_user_in_group"], severity="low", control="AC-2",
    remediation="Manage user permissions through group membership.", docs=[GAAD])
def user_in_group(item, index):
    groups = strings(get(item, "GroupList", list), "GroupList")
    return result(not groups, group_count=len(groups))


def access_keys(item):
    keys = get(item, "AccessKeys", dict)
    return list_of_objects(get(keys, "items", list))


@install("aws.claude_a.iam.user_one_active_key", "iam_user", "IAM user has at most one active access key",
    w(USER, AccessKeys={"collection_status": "collected", "items": [{"AccessKeyId": "AKIA1", "Status": "Active"}, {"AccessKeyId": "AKIA2", "Status": "Inactive"}]}),
    w(USER, AccessKeys={"collection_status": "collected", "items": [{"AccessKeyId": "AKIA1", "Status": "Active"}, {"AccessKeyId": "AKIA2", "Status": "Active"}]}),
    rows=[C + "iam_user_one_active_key"], severity="medium", control="IA-5", remediation="Deactivate and delete the extra active access key.",
    docs=[IAM_API + "API_ListAccessKeys.html"], extra={"na": w(USER, AccessKeys={"collection_status": "collected", "items": [{"AccessKeyId": "AKIA2", "Status": "Inactive"}]}),
                                                      "pass_no_keys": USER},
    note="Source WHERE keeps users with no keys (ok) or with active keys; users with only inactive keys produce no row. The source joins keys "
         "by ARN text LIKE, which can also count another user's keys sharing a name prefix or miss path users; the user's own keys are used.")
def user_one_active_key(item, index):
    keys = access_keys(item)
    statuses = [get(k, "Status", str) for k in keys]
    if any(s not in ("Active", "Inactive") for s in statuses):
        raise Unavailable("unrecognized access key status")
    active = statuses.count("Active")
    if keys and not active:
        return "NOT_APPLICABLE", {"reason": "only inactive access keys"}
    return result(active > 1, active_keys=active)


@install("aws.claude_a.iam.access_key_age_365", "iam_access_key", "IAM access key was created less than 365 days before the captured date",
    {"AccessKeyId": "AKIA1", "UserName": "alice", "Status": "Inactive", "CreateDate": "2025-06-01T00:00:00+00:00"},
    {"AccessKeyId": "AKIA1", "UserName": "alice", "Status": "Inactive", "CreateDate": "2025-01-01T00:00:00+00:00"}, index=idx(),
    rows=[C + "iam_user_access_key_age_365"], severity="medium", control="IA-5", remediation="Rotate or delete access keys older than one year.",
    docs=[IAM_API + "API_AccessKeyMetadata.html"], note="Any status; CreateDate <= current_date - 365 days (UTC midnight of the captured clock).")
def access_key_age_365(item, index):
    created = parse_time(get(item, "CreateDate", str))
    cutoff = midnight_cutoff(item, index, 365)
    return result(created <= cutoff, created=created.isoformat(), cutoff=cutoff.isoformat())


ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def split_name(arn):
    parts = arn.split("/")
    return parts[1] if len(parts) > 1 else ""


@install("aws.claude_a.iam.admin_user_has_mfa", "iam_user", "IAM user with AdministratorAccess attached has an MFA device",
    attach("iam_user", ADMIN), w(attach("iam_user", ADMIN), MFADevices={"collection_status": "collected", "items": []}),
    rows=[C + "iam_user_with_administrator_access_mfa_enabled"], severity="high", control="IA-2",
    remediation="Enable MFA for the administrator user or remove the direct AdministratorAccess attachment.",
    docs=[IAM_API + "API_ListMFADevices.html"], extra={"na": USER}, note="Attachment matched by split_part(arn,'/',2) = AdministratorAccess.")
def admin_user_mfa(item, index):
    if not any(split_name(a) == "AdministratorAccess" for a in attached_arns(item, "iam_user")):
        return "NOT_APPLICABLE", {"reason": "no AdministratorAccess attachment"}
    devices = list_of_objects(get(get(item, "MFADevices", dict), "items", list))
    return result(not devices, mfa_devices=len(devices))


# =========================================================================== Steampipe roles
@install("aws.claude_a.iam.role_no_administrator_access", "iam_role", "IAM role does not have AdministratorAccess attached",
    ROLE, attach("iam_role", ADMIN), rows=[C + "iam_role_no_administrator_access_policy_attached"], severity="high", category="least_privilege",
    control="AC-6", remediation="Replace AdministratorAccess on roles with least-privilege policies.", docs=[GAAD])
def role_no_admin(item, index):
    hit = any(split_name(a) == "AdministratorAccess" for a in attached_arns(item, "iam_role"))
    return result(hit, administrator_access=hit)


READONLY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
XTRUST = doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"})


@install("aws.claude_a.iam.role_readonly_not_cross_account", "iam_role", "IAM role with ReadOnlyAccess is not assumable from other accounts",
    attach("iam_role", READONLY, w(ROLE, AssumeRolePolicyDocument=doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"}))),
    attach("iam_role", READONLY, w(ROLE, AssumeRolePolicyDocument=XTRUST)), rows=[C + "iam_role_cross_account_read_only_access_policy"],
    severity="medium", category="exposure", control="AC-3", remediation="Restrict the trust policy of ReadOnlyAccess roles to the owning account or approved principals.",
    docs=[GAAD], extra={"na": ROLE}, note="Exact commercial ReadOnlyAccess ARN; Principal.AWS '*' or not containing the role's account fails.")
def role_readonly_cross(item, index):
    if READONLY not in attached_arns(item, "iam_role"):
        return "NOT_APPLICABLE", {"reason": "ReadOnlyAccess not attached"}
    acct = arn_account(get(item, "Arn", str))
    bad, uncertain = [], False
    for statement in policy_document(get(item, "AssumeRolePolicyDocument")):
        try:
            for row in std([statement], principal_aws=True):
                if row["Effect"] == "Allow":
                    bad.extend(p for p in row.get("PrincipalAWS", []) if p == "*" or acct not in p)
        except Unavailable:
            uncertain = True
    if bad:
        return result(True, cross_account_principals=bad)
    if uncertain:
        raise Unavailable("trust statement unresolved")
    return result(False, cross_account_principals=[])


@install("aws.claude_a.iam.role_used_within_60_days", "iam_role", "IAM role was used after the captured date minus 60 days",
    ROLE, w(ROLE, RoleLastUsed={"Region": "us-east-1", "LastUsedDate": "2025-10-01T00:00:00+00:00"}), index=idx(),
    rows=[C + "iam_role_unused_60"], severity="low", control="AC-2", remediation="Delete roles that have not been used in 60 days.",
    docs=[IAM_API + "API_RoleLastUsed.html"], extra={"fail_never": w(ROLE, RoleLastUsed={})},
    note="RoleLastUsed.LastUsedDate <= current_date - 60 days, or no recorded use, fails (source alarms on null).")
def role_unused_60(item, index):
    last = absent_or(item, "RoleName", "RoleLastUsed.LastUsedDate", None, str)
    if last is None:
        return result(True, last_used=None)
    cutoff = midnight_cutoff(item, index, 60)
    stamp = parse_time(last)
    return result(stamp <= cutoff, last_used=stamp.isoformat(), cutoff=cutoff.isoformat())


@install("aws.claude_a.iam.role_trust_not_public", "iam_role", "IAM role trust policy does not allow any principal without a restricting condition",
    ROLE, w(ROLE, AssumeRolePolicyDocument=doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})),
    rows=[R + "iam_role_trust_policy_prohibit_public_access"], severity="critical", category="exposure", control="AC-3",
    remediation="Replace the wildcard principal with specific accounts or add aws:PrincipalOrgID / aws:SourceAccount conditions.",
    docs=[IAM_UG + "reference_policies_elements_principal.html"],
    extra={"pass_conditioned": w(ROLE, AssumeRolePolicyDocument=doc({"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
                                                                       "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}))})
def role_trust_public(item, index):
    bad = turbot_public_statements(policy_document(get(item, "AssumeRolePolicyDocument")))
    return result(bool(bad), public_statements=len(bad))


# =========================================================================== Steampipe groups / account
@install("aws.claude_a.iam.group_not_empty", "iam_group", "IAM group has at least one member",
    GROUP, w(GROUP, GroupName="empty"), index=idx(iam_user=[USER]), dependencies=["iam_group", "iam_user"],
    rows=[C + "iam_group_not_empty"], severity="low", control="AC-2", remediation="Delete IAM groups with no members.", docs=[GAAD])
def group_not_empty(item, index):
    members = group_members(index, get(item, "GroupName", str))
    return result(not members, members=len(members))


@install("aws.claude_a.iam.root_console_has_mfa", "iam_account_summary", "Root account with a console password has MFA enabled",
    {"SummaryMap": {"AccountPasswordPresent": 1, "AccountMFAEnabled": 1}}, {"SummaryMap": {"AccountPasswordPresent": 1, "AccountMFAEnabled": 0}},
    rows=[C + "iam_root_user_account_console_access_mfa_enabled"], severity="critical", control="IA-2",
    remediation="Enable MFA on the root user or remove the root console password.", docs=[IAM_API + "API_GetAccountSummary.html"],
    extra={"pass_no_password": {"SummaryMap": {"AccountPasswordPresent": 0, "AccountMFAEnabled": 0}}})
def root_console_mfa(item, index):
    password = get(item, "SummaryMap.AccountPasswordPresent", int)
    mfa = get(item, "SummaryMap.AccountMFAEnabled", int)
    if password not in (0, 1) or mfa not in (0, 1):
        raise Unavailable("unexpected account summary flags")
    return result(bool(password) and not mfa, password_present=password, mfa_enabled=mfa)


ANALYZER = {"arn": "arn:aws:access-analyzer:us-east-1:%s:analyzer/a" % ACCOUNT, "name": "a", "type": "ACCOUNT", "status": "ACTIVE", "Findings": []}


@install("aws.claude_a.accessanalyzer.active_without_findings", "access_analyzer", "Region has an active IAM Access Analyzer with no findings",
    {}, {}, target="scope", pass_index=idx(access_analyzer=[ANALYZER]), fail_index=idx(access_analyzer=[w(ANALYZER, Findings=[{"id": "f1", "status": "ACTIVE"}])]),
    rows=[C + "iam_access_analyzer_enabled_without_findings"], severity="medium", control="AC-6",
    remediation="Enable an analyzer in every region and resolve or archive its findings after review.",
    docs=["https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListFindingsV2.html"],
    extra={"fail_none": ({}, idx(access_analyzer=[])), "fail_inactive": ({}, idx(access_analyzer=[w(ANALYZER, status="DISABLED", Findings=DROP)]))},
    allow_incomplete_failure=True,
    note="Active finding rows alarm; all unused roles, credentials and permissions remain Hardening evidence independently of Least Privilege. Missing or incomplete finding inventory cannot pass.")
def analyzer_without_findings(context, index):
    # Positive provider findings remain failures even if another page/analyzer
    # was unreadable. Missing inventory must never turn into a clean result.
    # A scan-created temporary analyzer is not the customer's: its findings are
    # reported by the resource they name, and it never satisfies "has an analyzer".
    from .aws_access_analyzer_scope import inventory, is_scan_temporary
    rows = index.get("access_analyzer", [])
    observed = []
    for row in rows:
        analyzer = row.get("data", row) if isinstance(row, Mapping) else {}
        temporary = is_scan_temporary(analyzer)
        for finding in analyzer.get("Findings", []) or []:
            if not isinstance(finding, Mapping) or finding.get("status") not in (None, "ACTIVE"):
                continue
            observed.append({**({"analyzer_source": "temporary PEASO scan analyzer (deleted after the scan)"} if temporary
                               else {"analyzer": analyzer.get("arn")}),
                "analyzer_type": analyzer.get("type"),
                "unused_access_days": ((analyzer.get("configuration") or {}).get("unusedAccess") or {}).get("unusedAccessAge"),
                **finding})
    if observed:
        return result(True, findings=len(observed), access_analyzer_findings=observed,
            unused_access_findings=sum(str(f.get("findingType", "")).startswith("Unused") for f in observed))
    customer, temporary, listing_complete = inventory(index)
    if not listing_complete:
        raise Unavailable("incomplete inventory: access_analyzer")
    if not customer:
        return result(True, analyzers=0, scan_temporary_analyzers=len(temporary))
    if any(get(a, "status", str) != "ACTIVE" for a in customer):
        return result(True, statuses=[a["status"] for a in customer])
    if temporary:
        raise Unavailable("scan temporary analyzer initial analysis is incomplete")
    analyzers = items(index, "access_analyzer")
    for analyzer in analyzers:
        initial = analyzer.get("_coverage", {}).get("InitialAnalysis", {})
        if initial.get("status") not in (None, "collected", "empty"):
            raise Unavailable("Access Analyzer initial analysis is incomplete")
        list_of_objects(get(analyzer, "Findings", list))
    return result(False, findings=0)


# =========================================================================== credential report helpers
NULLS = ("N/A", "no_information", "not_supported")


def report_time(row, field):
    value = get(row, field, str)
    return None if value in NULLS else parse_time(value)


def flag(row, field):
    value = get(row, field, str)
    if value not in ("true", "false"):
        raise Unavailable("credential report boolean not true/false: " + field)
    return value == "true"


def is_root(row):
    return get(row, "user", str) == "<root_account>"


ROW = {"user": "alice", "arn": "arn:aws:iam::%s:user/alice" % ACCOUNT, "user_creation_time": "2025-01-01T00:00:00+00:00",
       "password_enabled": "true", "password_last_used": "2025-12-30T00:00:00+00:00", "password_last_changed": "2025-01-01T00:00:00+00:00",
       "mfa_active": "true", "access_key_1_active": "true", "access_key_1_last_rotated": "2025-12-01T00:00:00+00:00",
       "access_key_1_last_used_date": "2025-12-31T00:00:00+00:00", "access_key_2_active": "false", "access_key_2_last_rotated": "N/A",
       "access_key_2_last_used_date": "N/A"}
ROOT = w(ROW, user="<root_account>", arn="arn:aws:iam::%s:root" % ACCOUNT, password_enabled="not_supported", password_last_used="no_information",
         access_key_1_active="false", access_key_1_last_rotated="N/A", access_key_1_last_used_date="N/A")


def now(row, index):
    return clock(row, index)


@install("aws.claude_a.iam.console_password_used_45", "iam_credential_report", "Console password is used within 45 days of the captured date (Steampipe)",
    ROW, w(ROW, password_last_used="2025-10-01T00:00:00+00:00"), index=idx(), rows=[C + "iam_user_console_access_unused_45"], severity="medium",
    control="AC-2", remediation="Remove console passwords that are unused for 45 days or more.", docs=[CRED],
    extra={"na": ROOT, "fail_never": w(ROW, password_last_used="no_information"), "pass_no_password": w(ROW, password_enabled="false", password_last_used="N/A")},
    note="password_last_used < current_date - 45 days or never used fails; root row is outside the population.")
def console_used_45(item, index):
    if is_root(item):
        return "NOT_APPLICABLE", {"reason": "root account row"}
    if not flag(item, "password_enabled"):
        return result(False, password_enabled=False)
    last = report_time(item, "password_last_used")
    if last is None:
        return result(True, password_last_used=None)
    return result(last < midnight_cutoff(item, index, 45), password_last_used=last.isoformat())


@install("aws.claude_a.iam.prowler_console_password_used_45", "iam_credential_report", "Console password was used within the last 45 days (Prowler)",
    ROW, w(ROW, password_last_used="2025-11-01T00:00:00+00:00"), index=idx(), rows=[P + "iam_user_console_access_unused"], severity="medium",
    control="AC-2", remediation="Disable console access for users who have not signed in for 45 days.", docs=[CRED],
    extra={"na": ROOT, "pass_never_recent": w(ROW, password_last_used="no_information", password_last_changed="2025-12-30T00:00:00+00:00")},
    note="Never-used console passwords are evaluated against their last-change age.")
def prowler_console_45(item, index):
    if is_root(item):
        return "NOT_APPLICABLE", {"reason": "root account row"}
    if not flag(item, "password_enabled"):
        return result(False, password_enabled=False)
    last = report_time(item, "password_last_used")
    if last is None:
        return result((now(item, index) - _credential_age_date(item, "password_last_changed")).days > 45, password_last_used=None)
    days = (now(item, index) - last).days
    return result(days > 45, days_since_use=days)


@install("aws.claude_a.iam.access_keys_rotated_90", "iam_credential_report", "Active access keys were rotated within 90 days (Prowler)",
    ROW, w(ROW, access_key_1_last_rotated="2025-09-01T00:00:00+00:00"), index=idx(), rows=[P + "iam_rotate_access_key_90_days"],
    severity="medium", control="IA-5", remediation="Rotate active access keys at least every 90 days.", docs=[CRED],
    extra={"pass_no_keys": w(ROW, access_key_1_last_rotated="N/A", access_key_1_active="false")},
    note="Includes the root row; (now - last_rotated).days > 90 for an active key fails.")
def keys_rotated_90(item, index):
    active = {n: flag(item, "access_key_%d_active" % n) for n in (1, 2)}
    old = []
    for n in (1, 2):
        if active[n]:
            rotated = _credential_age_date(item, "access_key_%d_last_rotated" % n)
            if (now(item, index) - rotated).days > 90:
                old.append(n)
    return result(bool(old), stale_keys=old)


@install("aws.claude_a.iam.access_keys_used_45", "iam_credential_report", "Active access keys were used within 45 days (Prowler)",
    ROW, w(ROW, access_key_1_last_used_date="2025-10-01T00:00:00+00:00"), index=idx(), rows=[P + "iam_user_accesskey_unused"],
    severity="medium", control="AC-2", remediation="Deactivate or delete access keys unused for 45 days.", docs=[CRED],
    extra={"pass_never_used_recent": w(ROW, access_key_1_last_used_date="N/A", access_key_1_last_rotated="2025-12-30T00:00:00+00:00")},
    note="Never-used active keys are evaluated against their creation/rotation age.")
def keys_used_45(item, index):
    active = {n: flag(item, "access_key_%d_active" % n) for n in (1, 2)}
    if not any(active.values()):
        return result(False, active_keys=0)
    old = []
    for n in (1, 2):
        if active[n]:
            used = get(item, "access_key_%d_last_used_date" % n, str)
            if (now(item, index) - (_credential_age_date(item, "access_key_%d_last_rotated" % n) if used == "N/A" else parse_time(used))).days > 45:
                old.append(n)
    return result(bool(old), stale_keys=old)


@install("aws.claude_a.iam.no_unused_initial_access_key", "iam_credential_report", "Console users have no never-used active access key (Prowler)",
    ROW, w(ROW, access_key_1_last_used_date="N/A"), rows=[P + "iam_user_no_setup_initial_access_key"], severity="medium", control="IA-5",
    remediation="Delete access keys created at user setup that were never used.", docs=[CRED])
def no_initial_key(item, index):
    pw = get(item, "password_enabled", str) == "true"
    active = {n: flag(item, "access_key_%d_active" % n) for n in (1, 2)}
    bad = [n for n in (1, 2) if active[n]
           and get(item, "access_key_%d_last_used_date" % n, str) == "N/A" and pw]
    return result(bool(bad), never_used_keys=bad)


@install("aws.claude_a.iam.not_two_active_keys", "iam_credential_report", "Principal does not have two active access keys (Prowler)",
    ROW, w(ROW, access_key_2_active="true"), rows=[P + "iam_user_two_active_access_key"], severity="medium", control="IA-5",
    remediation="Deactivate one of the two active access keys after rotation.", docs=[CRED])
def two_active(item, index):
    active = [flag(item, "access_key_%d_active" % n) for n in (1, 2)]
    both = all(active)
    return result(both, both_active=both)


ROOT_CREDS = w(ROOT, password_enabled="true")
SUMMARY = {"SummaryMap": {"AccountMFAEnabled": 1, "AccountPasswordPresent": 1}}
HW_INDEX = idx(iam_account_summary=[SUMMARY], iam_virtual_mfa_device=[])


@install("aws.claude_a.iam.prowler_root_hardware_mfa", "iam_credential_report", "Root user with credentials uses hardware MFA (Prowler)",
    ROOT_CREDS, ROOT_CREDS, pass_index=HW_INDEX,
    fail_index=idx(iam_account_summary=[SUMMARY], iam_virtual_mfa_device=[{"SerialNumber": "arn:aws:iam::%s:mfa/root-account-mfa-device" % ACCOUNT,
                                                                           "User": {"Arn": "arn:aws:iam::%s:root" % ACCOUNT}}]),
    index=HW_INDEX, rows=[P + "iam_root_hardware_mfa_enabled"], severity="critical", control="IA-2",
    remediation="Replace the root virtual MFA device with a hardware MFA device.", docs=[IAM_API + "API_ListVirtualMFADevices.html"],
    dependencies=["iam_credential_report", "iam_account_summary", "iam_virtual_mfa_device"],
    extra={"na": (ROW, HW_INDEX), "fail_no_mfa": (ROOT_CREDS, idx(iam_account_summary=[{"SummaryMap": {"AccountMFAEnabled": 0}}], iam_virtual_mfa_device=[]))},
    note="Commercial partition only; only reported when root has a password or an active key; any virtual device whose User.Arn contains 'root' fails.")
def prowler_root_hw(item, index):
    if not is_root(item):
        return "NOT_APPLICABLE", {"reason": "not the root row"}
    if get(item, "arn", str).split(":")[1] != "aws":
        return "NOT_APPLICABLE", {"reason": "non-commercial partition"}
    creds = any(get(item, f, str) == "true" for f in ("password_enabled", "access_key_1_active", "access_key_2_active"))
    if not creds:
        return "NOT_APPLICABLE", {"reason": "root has no credentials"}
    summaries = items(index, "iam_account_summary")
    if len(summaries) != 1:
        raise Unavailable("exactly one account summary required")
    if not get(summaries[0], "SummaryMap.AccountMFAEnabled", int) > 0:
        return result(True, account_mfa_enabled=False)
    virtual = [d for d in items(index, "iam_virtual_mfa_device")
               if "root" in (d.get("User", {}) or {}).get("Arn", "")]
    return result(bool(virtual), virtual_root_mfa=bool(virtual))


@install("aws.claude_a.iam.server_certificate_not_expired_now", "iam_server_certificate", "IAM server certificate is not expired at the captured time (Prowler)",
    {"ServerCertificateName": "c", "Arn": "arn:aws:iam::%s:server-certificate/c" % ACCOUNT, "Expiration": "2026-06-01T00:00:00+00:00"},
    {"ServerCertificateName": "c", "Arn": "arn:aws:iam::%s:server-certificate/c" % ACCOUNT, "Expiration": "2025-12-31T23:00:00+00:00"},
    index=idx(), rows=[P + "iam_no_expired_server_certificates_stored"], severity="critical", control="SC-17",
    remediation="Delete expired IAM server certificates and deploy renewed certificates (prefer ACM).", docs=[IAM_API + "API_ServerCertificateMetadata.html"],
    note="Prowler fails when (now - expiration).days >= 0, i.e. at or after the expiration instant.")
def server_cert_now(item, index):
    expiry = parse_time(get(item, "Expiration", str))
    days = (now(item, index) - expiry).days
    return result(days >= 0, expires=expiry.isoformat())


# =========================================================================== Prowler principal attachment / MFA checks
def _named_admin(kind, label, row, base, title):
    @install("aws.claude_a.iam.prowler_%s_no_administratoraccess" % label, kind, title, base, attach(kind, ADMIN, base), rows=[P + row],
        severity="high", category="least_privilege", control="AC-6", remediation="Detach AdministratorAccess and grant least-privilege permissions.",
        docs=[GAAD], extra={"na": attach(kind, ADMIN, w(ROLE, AssumeRolePolicyDocument=TRUST))} if kind == "iam_role" else None,
        note="Matches attached PolicyName == AdministratorAccess" + ("; service roles (Prowler is_service_role) are skipped." if kind == "iam_role" else "."))
    def evaluate(item, index):
        if kind == "iam_role" and is_service_role(item):
            return "NOT_APPLICABLE", {"reason": "service role"}
        hit = "AdministratorAccess" in attached_names(item, kind)
        return result(hit, administrator_access=hit)


def is_service_role(role):
    """Prowler is_service_role, including its Python ``in`` semantics on Action."""
    statements = policy_document(get(role, "AssumeRolePolicyDocument"))
    for s in statements:
        if _statement_effect(s) != "Allow":
            return False
        action = optional(s, "Action", [])
        if not any(a in action for a in ("sts:AssumeRole", "sts:*", "*")):
            return False
        principal = optional(s, "Principal", None)
        if isinstance(principal, str):
            if not principal.strip():
                raise Unavailable("empty trust Principal")
            return False
        if not isinstance(principal, dict):
            raise Unavailable("malformed trust Principal")
        keys = set(principal.keys()) - {"_coverage", "collection_status"}
        if not keys:
            optional(principal, "Service", None)
            raise Unavailable("empty trust Principal")
        if keys != {"Service"}:
            return False
        service = optional(principal, "Service", None)
        values = [service] if isinstance(service, str) else service
        if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value.strip() for value in values):
            raise Unavailable("malformed service trust principal")
    return True


USER_TRUST = doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"})
HUMAN_ROLE = w(ROLE, AssumeRolePolicyDocument=USER_TRUST)
_named_admin("iam_user", "user", "iam_user_administrator_access_policy", USER, "IAM user does not have AdministratorAccess attached (Prowler)")
_named_admin("iam_group", "group", "iam_group_administrator_access_policy", GROUP, "IAM group does not have AdministratorAccess attached (Prowler)")
_named_admin("iam_role", "role", "iam_role_administratoraccess_policy", HUMAN_ROLE, "Non-service IAM role does not have AdministratorAccess attached (Prowler)")


@install("aws.claude_a.iam.prowler_role_readonly_not_cross_account", "iam_role", "Non-service role with ReadOnlyAccess is not trusted cross-account (Prowler)",
    attach("iam_role", READONLY, HUMAN_ROLE), attach("iam_role", READONLY, w(ROLE, AssumeRolePolicyDocument=XTRUST)), index=idx(),
    rows=[P + "iam_role_cross_account_readonlyaccess_policy"], severity="high", category="exposure", control="AC-3",
    remediation="Remove ReadOnlyAccess from cross-account roles or restrict the trusting principals.", docs=[GAAD],
    extra={"na": attach("iam_role", READONLY, ROLE), "pass_no_readonly": HUMAN_ROLE},
    note="PolicyName ReadOnlyAccess; an Allow statement with Principal.AWS lacking the audited account or equal to '*' fails.")
def prowler_readonly(item, index):
    from .claude_aws_a_common import account
    uncertain = False
    try:
        if is_service_role(item):
            return "NOT_APPLICABLE", {"reason": "service role"}
    except Unavailable:
        uncertain = True
    if "ReadOnlyAccess" not in attached_names(item, "iam_role"):
        return result(False, readonly=False)
    acct = account(index)
    for s in policy_document(get(item, "AssumeRolePolicyDocument")):
        try:
            if _statement_effect(s) != "Allow":
                continue
            principal = optional(s, "Principal", None)
            if isinstance(principal, str):
                if not principal.strip():
                    raise Unavailable("empty trust Principal")
                continue
            if not isinstance(principal, dict):
                raise Unavailable("malformed trust Principal")
            keys = set(principal) - {"_coverage", "collection_status"}
            if not keys:
                raise Unavailable("empty trust Principal")
            values = optional(principal, "AWS", None)
            if "AWS" in principal:
                values = [values] if isinstance(values, str) else values
                if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value.strip() for value in values):
                    raise Unavailable("malformed AWS trust principal")
                for value in values:
                    if acct not in value or value == "*":
                        return result(True, principal=value)
        except Unavailable:
            uncertain = True
    if uncertain:
        raise Unavailable("trust Principal unresolved")
    return result(False, readonly=True)


@install("aws.claude_a.iam.prowler_admin_group_members_mfa", "iam_group", "Members of groups with AdministratorAccess have MFA (Prowler)",
    attach("iam_group", ADMIN), attach("iam_group", ADMIN), pass_index=idx(iam_user=[USER], iam_credential_report=[ROW]), index=idx(iam_user=[USER], iam_credential_report=[ROW]),
    fail_index=idx(iam_user=[USER], iam_credential_report=[w(ROW, mfa_active="false")]), rows=[P + "iam_administrator_access_with_mfa"],
    severity="high", control="IA-2", remediation="Enable MFA for every member of administrator groups.", docs=[CRED],
    dependencies=["iam_group", "iam_user", "iam_credential_report"], extra={"pass_no_admin": (GROUP, idx(iam_user=[USER], iam_credential_report=[ROW]))},
    note="Membership from user GroupList; a member missing from the credential report is UNKNOWN (Prowler would pass it).")
def admin_group_mfa(item, index):
    admin = "arn:%s:iam::aws:policy/AdministratorAccess" % get(item, "Arn", str).split(":")[1]
    if admin not in attached_arns(item, "iam_group"):
        return result(False, administrator_access=False)
    rows = {}
    for row in items(index, "iam_credential_report"):
        name = get(row, "user", str)
        if not name or name in rows:
            raise Unavailable("credential report username empty or duplicated")
        rows[name] = row
    without = []
    for member in group_members(index, get(item, "GroupName", str)):
        if member not in rows:
            raise Unavailable("group member missing from credential report")
        if not flag(rows[member], "mfa_active"):
            without.append(member)
    return result(bool(without), members_without_mfa=without)


@install("aws.claude_a.iam.prowler_user_hardware_mfa", "iam_user", "IAM user has MFA devices and none is virtual or SMS (Prowler)",
    w(USER, MFADevices={"collection_status": "collected", "items": [{"SerialNumber": "GAHT12345678"}]}), USER,
    rows=[P + "iam_user_hardware_mfa_enabled"], severity="medium", control="IA-2", remediation="Replace virtual MFA devices with hardware or FIDO security keys.",
    docs=[IAM_API + "API_MFADevice.html"], extra={"fail_none": w(USER, MFADevices={"collection_status": "collected", "items": []})},
    note="Device type = SerialNumber.split(':')[5].split('/')[0], hardware when that index does not exist; 'mfa'/'sms-mfa' fail.")
def prowler_user_hw(item, index):
    devices = list_of_objects(get(get(item, "MFADevices", dict), "items", list))
    if not devices:
        return result(True, devices=0)
    kinds = []
    for d in devices:
        serial = get(d, "SerialNumber", str)
        try:
            kinds.append(serial.split(":")[5].split("/")[0])
        except IndexError:
            kinds.append("hardware")
    return result(any(k in ("mfa", "sms-mfa") for k in kinds), device_types=kinds)


def last_accessed(item):
    return list_of_objects(get(item, "ServicesLastAccessed", list))


@install("aws.claude_a.iam.user_long_lived_keys_only_iam_sts", "iam_user", "IAM user with access keys does not use services other than IAM/STS (Prowler)",
    w(USER, ServicesLastAccessed=[{"ServiceNamespace": "s3"}]), w(USER, AccessKeys={"collection_status": "collected", "items": [{"AccessKeyId": "AKIA1", "Status": "Active"}]},
    ServicesLastAccessed=[{"ServiceNamespace": "s3"}]), rows=[P + "iam_user_with_temporary_credentials"], severity="medium", control="IA-5",
    remediation="Replace the user's long-lived access keys with role-based temporary credentials.", docs=[IAM_API + "API_GetServiceLastAccessedDetails.html"],
    note="Needs ServicesLastAccessed (GenerateServiceLastAccessedDetails/GetServiceLastAccessedDetails); every listed namespace counts, accessed or not.")
def user_temp_creds(item, index):
    keys = access_keys(item)
    services = [get(s, "ServiceNamespace", str) for s in last_accessed(item)]
    other = [s for s in services if s not in ("iam", "sts")]
    return result(bool(other) and bool(keys), access_keys=len(keys), other_services=len(other), non_iam_sts_services=other)


def _stale(kind, label, namespace, days, row):
    base = w(FIXTURE[kind], ServicesLastAccessed=[{"ServiceNamespace": namespace, "LastAuthenticated": "2025-12-20T00:00:00+00:00"}])

    @install("aws.claude_a.iam.%s_%s_access_not_stale" % (label, namespace), kind, "IAM %s with %s permissions used them within %d days (Prowler)" % (label, namespace, days),
        base, w(base, ServicesLastAccessed=[{"ServiceNamespace": namespace}]), index=idx(), rows=[P + row], severity="medium", category="least_privilege",
        control="AC-6", remediation="Remove unused %s permissions from the %s." % (namespace, label), docs=[IAM_API + "API_ServiceLastAccessed.html"],
        extra={"na": w(base, ServicesLastAccessed=[{"ServiceNamespace": "s3"}]),
               "fail_old": w(base, ServicesLastAccessed=[{"ServiceNamespace": namespace, "LastAuthenticated": "2025-01-01T00:00:00+00:00"}])},
        note="No %s namespace entry: no finding; LastAuthenticated absent fails; (now - last).days > %d fails." % (namespace, days))
    def evaluate(item, index):
        status = item.get("ServicesLastAccessedStatus")
        if "ServicesLastAccessed" not in item and isinstance(status, dict) and status.get("collection_status") == "not_collected" \
                and status.get("reason") == "identity_policies_cannot_allow_namespaces" and namespace in (status.get("namespaces") or []):
            # The collector's intentional not_collected proof is valid without
            # markers, but an explicit unavailable marker cannot authenticate it.
            item_coverage = item.get("_coverage", {})
            if "ServicesLastAccessedStatus" in item_coverage:
                marker = item_coverage["ServicesLastAccessedStatus"]
                if not isinstance(marker, dict) or marker.get("status") != "collected":
                    raise Unavailable("service access exclusion status unavailable")
            status_coverage = status.get("_coverage", {})
            if not isinstance(status_coverage, dict):
                raise Unavailable("malformed service access exclusion coverage")
            for field in ("collection_status", "reason", "namespaces"):
                if field in status_coverage:
                    marker = status_coverage[field]
                    if not isinstance(marker, dict) or marker.get("status") != "collected":
                        raise Unavailable("service access exclusion proof unavailable")
            if not isinstance(status["namespaces"], list) or any(not isinstance(value, str) for value in status["namespaces"]):
                raise Unavailable("malformed service access exclusion namespaces")
            # Collector proved no inline/attached identity policy statement can allow this namespace,
            # so the access report could not list it (same outcome as a report without the entry).
            return "NOT_APPLICABLE", {"reason": "no %s permissions in identity policies" % namespace}
        matches = [s for s in last_accessed(item) if get(s, "ServiceNamespace", str) == namespace]
        if len(matches) > 1:
            raise Unavailable("duplicate service access namespace")
        if not matches:
            return "NOT_APPLICABLE", {"reason": "no %s permissions" % namespace}
        entry = matches[0]
        if "LastAuthenticated" not in entry:
            coverage = entry.get("_coverage", {})
            if "LastAuthenticated" in coverage and (not isinstance(coverage["LastAuthenticated"], dict)
                    or coverage["LastAuthenticated"].get("status") != "empty"):
                raise Unavailable("service authentication timestamp unavailable")
            return result(True, last_authenticated=None)
        last = get(entry, "LastAuthenticated")
        if last is None:
            return result(True, last_authenticated=None)
        age = (now(item, index) - parse_time(last)).days
        return result(age > days, days_since_access=age)


_stale("iam_user", "user", "bedrock", 60, "iam_user_access_not_stale_to_bedrock")
_stale("iam_role", "role", "bedrock", 60, "iam_role_access_not_stale_to_bedrock")
_stale("iam_user", "user", "sagemaker", 90, "iam_user_access_not_stale_to_sagemaker")


# =========================================================================== Prowler account-scope checks
def _role_with_policy(cid, row, name, title):
    @install(cid, "iam_role", title, {}, {}, target="scope", pass_index=idx(iam_role=[attach("iam_role", "arn:aws:iam::aws:policy/" + name)]),
        fail_index=idx(iam_role=[ROLE]), rows=[P + row], severity="low" if name == "AWSSupportAccess" else "medium", control="IR-7",
        remediation="Create a role with the AWS managed %s policy for the responsible team." % name, docs=[GAAD],
        note="Prowler ListEntitiesForPolicy(EntityFilter=Role); equivalently any role with the managed policy attached.")
    def evaluate(context, index):
        target = "arn:%s:iam::aws:policy/%s" % (partition(index), name)
        roles = [get(r, "RoleName", str) for r in items(index, "iam_role") if target in attached_arns(r, "iam_role")]
        return result(not roles, roles=roles)


_role_with_policy("aws.claude_a.iam.support_role_exists", "iam_support_role_created", "AWSSupportAccess", "A role with AWSSupportAccess exists (Prowler)")
_role_with_policy("aws.claude_a.iam.securityaudit_role_exists", "iam_securityaudit_role_created", "SecurityAudit", "A role with SecurityAudit exists (Prowler)")

CS = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"


@install("aws.claude_a.iam.cloudshell_full_access_not_attached", "iam_policy", "AWSCloudShellFullAccess is not attached to any identity (Prowler)",
    {}, {}, target="scope", pass_index=idx(iam_user=[USER], iam_group=[GROUP], iam_role=[ROLE]),
    fail_index=idx(iam_user=[USER], iam_group=[attach("iam_group", CS)], iam_role=[ROLE]), dependencies=["iam_user", "iam_group", "iam_role"],
    rows=[P + "iam_policy_cloudshell_admin_not_attached"], severity="medium", category="least_privilege", control="AC-6",
    remediation="Detach AWSCloudShellFullAccess and use scoped CloudShell permissions.", docs=[GAAD])
def cloudshell_scope(context, index):
    target = "arn:%s:iam::aws:policy/AWSCloudShellFullAccess" % partition(index)
    hits = [get(e, PRINCIPALS[k][0], str) for k in ("iam_user", "iam_group", "iam_role") for e in items(index, k) if target in attached_arns(e, k)]
    return result(bool(hits), entities=hits)


@install("aws.claude_a.iam.saml_provider_present", "iam_saml_provider", "Account has an IAM SAML identity provider (Prowler)",
    {}, {}, target="scope", pass_index=idx(iam_saml_provider=[{"Arn": "arn:aws:iam::%s:saml-provider/idp" % ACCOUNT}]), fail_index=idx(iam_saml_provider=[]),
    rows=[P + "iam_check_saml_providers_sts"], severity="low", control="IA-2", remediation="Federate human access through a SAML or IAM Identity Center provider.",
    docs=[IAM_API + "API_ListSAMLProviders.html"], note="Needs iam:ListSAMLProviders (collector fact iam_saml_provider).")
def saml_present(context, index):
    providers = items(index, "iam_saml_provider")
    return result(not providers, providers=len(providers))


ORG_CFG = {"id": "account-configuration", "Partition": "aws", "Organization": {"collection_status": "collected", "OrganizationId": "o-abc1234567"}}
NO_ORG_CFG = {"id": "account-configuration", "Partition": "aws", "Organization": {"collection_status": "empty", "absent": True}}


@install("aws.claude_a.iam.root_credentials_management", "iam_organization_features", "Organization centralizes root credentials management (Prowler)",
    {}, {}, target="scope", pass_index=idx(aws_account_configuration=[ORG_CFG], iam_organization_features=[{"EnabledFeatures": ["RootCredentialsManagement"]}]),
    fail_index=idx(aws_account_configuration=[ORG_CFG], iam_organization_features=[{"EnabledFeatures": []}]),
    dependencies=["aws_account_configuration", "iam_organization_features"], rows=[P + "iam_root_credentials_management_enabled"], severity="medium", control="AC-2",
    remediation="Enable centralized root access (RootCredentialsManagement) from the management account.",
    docs=[IAM_API + "API_ListOrganizationsFeatures.html"],
    extra={"na": ({}, idx(aws_account_configuration=[NO_ORG_CFG], iam_organization_features=[{"EnabledFeatures": []}]))},
    note="Organization membership from aws_account_configuration.Organization (organizations:DescribeOrganization); needs iam:ListOrganizationsFeatures "
         "(kind iam_organization_features, collector fact). No organization: no finding (NOT_APPLICABLE).")
def root_creds_mgmt(context, index):
    configs = items(index, "aws_account_configuration")
    if len(configs) != 1:
        raise Unavailable("account configuration unavailable")
    org = get(configs[0], "Organization", dict)
    if org.get("collection_status") == "empty" and org.get("absent") is True:
        return "NOT_APPLICABLE", {"reason": "account not in an organization"}
    if not get(org, "OrganizationId", str).startswith("o-"):
        raise Unavailable("organization id unavailable")
    features = items(index, "iam_organization_features")
    if len(features) != 1:
        raise Unavailable("organization features response unavailable")
    enabled = strings(get(features[0], "EnabledFeatures", list))
    return result("RootCredentialsManagement" not in enabled, enabled_features=enabled)


def _credential_age_date(item, field):
    stamp = report_time(item, field)
    if stamp is None:
        raise Unavailable("credential creation/change age unavailable: " + field)
    return stamp


__all__ = ["guard", "is_service_role", "arn_account", "is_aws_managed", "default_document", "policy_attached", "pol", "allow", "doc",
           "inline", "attach", "FIXTURE", "PRINCIPALS", "USER", "ROLE", "GROUP", "CUSTOM_ARN", "AWS_ARN", "HUMAN_ROLE", "timedelta"]
