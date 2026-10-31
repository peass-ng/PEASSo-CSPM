"""Signed IAM and KMS compliance predicates for the sw40 slice.

Only complete, account-bound snapshot facts can establish an inventory-wide PASS.
Policy evaluation deliberately returns UNKNOWN for effective-access constructs that
cannot be resolved from the collected declarations alone.
"""
from __future__ import annotations

from dataclasses import replace
import json
import re
from urllib.parse import unquote

from . import CHECKS, register, result, unknown
from .aws_all_policies import scan as _customer_policy_scan
from .facts import Unavailable, complete_items, get, optional, list_of_objects

_ACCOUNT = re.compile(r"^[0-9]{12}$")
_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):iam::([0-9]{12}|aws):policy/.+$")
_KEY_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/.+$")
_SERVICE = re.compile(r"^[a-z0-9-]+:\*$", re.I)
_SENSITIVE = {"kms:decrypt", "kms:schedulekeydeletion", "kms:putkeypolicy"}


def _sensitive_action(action):
    a = action.lower()
    return a in _SENSITIVE or a.startswith("kms:reencrypt") or a.startswith("kms:generatedatakey") or a in {"kms:*", "*"}


def _sensitive_grant(operation):
    o = operation.lower()
    return o in {"decrypt", "schedulekeydeletion", "putkeypolicy"} or o.startswith("reencrypt") or o.startswith("generatedatakey")


def _context(index):
    ctx = get(index, "context", dict)
    if get(ctx, "provider", str) != "aws":
        raise Unavailable("AWS provider authority missing")
    scope = get(ctx, "scope", str)
    account = scope.split("/", 1)[0]
    if not _ACCOUNT.fullmatch(account) or "/" not in scope:
        raise Unavailable("AWS account scope missing")
    return ctx, account


def _rows(index, kind, *, global_kind=False):
    ctx, account = _context(index)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("collection authority missing or ambiguous: " + kind)
    env = envelopes[0]
    if not isinstance(env, dict) or env.get("type") != kind or env.get("account_id") != account:
        raise Unavailable("foreign collection authority: " + kind)
    if global_kind:
        if env.get("global") is not True or env.get("scope") != account + "/global":
            raise Unavailable("IAM global scope unproven: " + kind)
    elif env.get("scope") != ctx["scope"]:
        raise Unavailable("foreign regional scope: " + kind)
    wrappers = index.get(kind, [])
    if not isinstance(wrappers, list) or any(not isinstance(w, dict) or
            ("scope" in w and w["scope"] != env["scope"]) or
            ("type" in w and w["type"] != kind) for w in wrappers):
        raise Unavailable("foreign or malformed resource wrapper: " + kind)
    return complete_items(index, kind)


def _document(value):
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except (ValueError, TypeError):
            raise Unavailable("policy document cannot be parsed")
    if not isinstance(value, dict):
        raise Unavailable("policy document malformed")
    rows = get(value, "Statement")
    rows = [rows] if isinstance(rows, dict) else rows
    if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
        raise Unavailable("policy statements malformed or empty")
    return rows


def _terms(statement, field):
    value = get(statement, field)
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(x, str) or not x for x in values):
        raise Unavailable("malformed policy " + field)
    return values


def _statement(statement):
    effect = get(statement, "Effect", str)
    if effect not in {"Allow", "Deny"}:
        raise Unavailable("unknown policy Effect")
    if ("Action" in statement) == ("NotAction" in statement) or ("Resource" in statement) == ("NotResource" in statement):
        raise Unavailable("policy action/resource mode malformed")
    action_key = "Action" if "Action" in statement else "NotAction"
    resource_key = "Resource" if "Resource" in statement else "NotResource"
    actions, resources = _terms(statement, action_key), _terms(statement, resource_key)
    condition = statement.get("Condition")
    if condition is not None:
        if not isinstance(condition, dict) or not condition:
            raise Unavailable("malformed policy Condition")
        for operator, predicates in condition.items():
            if not isinstance(operator, str) or not operator or not isinstance(predicates, dict) or not predicates:
                raise Unavailable("malformed policy Condition")
            for key, value in predicates.items():
                values = [value] if isinstance(value, (str, bool, int)) else value
                if not isinstance(key, str) or not key or not isinstance(values, list) or not values or any(
                        not isinstance(v, (str, bool, int)) for v in values):
                    raise Unavailable("malformed policy Condition value")
    return effect, action_key, actions, resource_key, resources, condition


def _managed_document(row, account):
    arn = get(row, "Arn", str)
    match = _ARN.fullmatch(arn)
    if match is None or match.group(2) not in {account, "aws"}:
        raise Unavailable("foreign or malformed managed-policy ARN")
    versions = list_of_objects(get(row, "PolicyVersionList", list)); version_id = get(row, "DefaultVersionId", str)
    version_ids = [get(v, "VersionId", str) for v in versions]; defaults = [v for v in versions if get(v, "IsDefaultVersion", bool)]
    if not version_id or any(not v for v in version_ids) or len(set(version_ids)) != len(version_ids) or len(defaults) != 1 or get(defaults[0], "VersionId", str) != version_id:
        raise Unavailable("exactly one matching default policy version required")
    return arn, _document(get(defaults[0], "Document"))


def _all_policy_statements(index, *, managed_only=False):
    _, account = _context(index)
    found = []
    seen = set()
    for row in _rows(index, "iam_policy", global_kind=True):
        arn, statements = _managed_document(row, account)
        if arn in seen:
            raise Unavailable("duplicate managed-policy ARN")
        seen.add(arn)
        found.extend((arn, statement) for statement in statements)
    if not managed_only:
        for kind, name_key, field in (("iam_user", "UserName", "UserPolicyList"),
                                      ("iam_group", "GroupName", "GroupPolicyList"),
                                      ("iam_role", "RoleName", "RolePolicyList")):
            for row in _rows(index, kind, global_kind=True):
                arn = get(row, "Arn", str)
                if not arn.startswith("arn:") or f":iam::{account}:" not in arn:
                    raise Unavailable("foreign IAM principal")
                name = get(row, name_key, str)
                if not name or arn in seen:
                    raise Unavailable("missing or duplicate IAM principal")
                seen.add(arn)
                for policy in get(row, field, list):
                    if not isinstance(policy, dict):
                        raise Unavailable("malformed inline policy")
                    policy_name = get(policy, "PolicyName", str)
                    if not policy_name:
                        raise Unavailable("inline policy name missing")
                    found.extend((arn + "/" + policy_name, statement)
                                 for statement in _document(get(policy, "PolicyDocument")))
    return found


def _policy_scan(index, mode):
    # The global IAM projection lacks proof that all AWS-managed default versions
    # and inline identity policies were read. A collector-supplied completeness
    # record is required before either positive or negative account-wide grading.
    coverage = get(get(index, "context", dict), "metadata.compliance.iam_policy_inventory", dict)
    if (coverage.get("status") != "collected" or coverage.get("managed_scope") != "All" or
            (mode != "managed_service" and coverage.get("inline_complete") is not True)):
        raise Unavailable("all-policy inventory coverage unproven")
    _, account = _context(index)
    if coverage.get("account_id") != account:
        raise Unavailable("foreign all-policy inventory coverage")
    found = _all_policy_statements(index, managed_only=mode == "managed_service")
    hits, uncertain = [], False
    for source, raw in found:
        effect, ak, actions, rk, resources, condition = _statement(raw)
        if effect != "Allow":
            if mode.startswith("effective"):
                uncertain = True
            continue
        star = ak == "Action" and any(a in {"*", "*:*"} for a in actions)
        service = ak == "Action" and any(_SERVICE.fullmatch(a) or a in {"*", "*:*"} for a in actions)
        resource_star = rk == "Resource" and "*" in resources
        scoped = rk == "Resource" and any(r.startswith("arn:") and "*" not in r for r in resources)
        match = (star and resource_star) if mode in {"star", "effective_star"} else (service and resource_star) if mode in {"service", "managed_service", "effective_service"} else (service and scoped)
        if ak == "NotAction" or rk == "NotResource":
            uncertain = True
        if mode == "service" and service and rk == "Resource" and any("*" in r and r != "*" for r in resources):
            uncertain = True
        if match:
            if mode.startswith("effective") and condition:
                uncertain = True
            elif mode.startswith("effective") and any(_statement(other)[0] == "Deny" for _, other in found):
                uncertain = True
            else:
                hits.append(source)
    if uncertain:
        return unknown("effective policy semantics or NotAction/NotResource cannot be resolved safely")
    return result(bool(hits), matching_policy_sources=sorted(set(hits)), scanned_statements=len(found))


def _one_policy(item, index):
    _, account = _context(index)
    rows = _rows(index, "iam_policy", global_kind=True)
    arn = get(item, "Arn", str)
    matched = [row for row in rows if get(row, "Arn", str) == arn]
    if len(matched) != 1:
        raise Unavailable("policy absent or duplicated in complete IAM inventory")
    if item != matched[0]:
        raise Unavailable("selected policy differs from scoped inventory")
    source, statements = _managed_document(item, account)
    if source != arn:
        raise Unavailable("policy identity mismatch")
    return arn, statements


def _policy_scoped_action(item, index):
    arn, statements = _one_policy(item, index)
    if ":iam::aws:" in arn:
        return "NOT_APPLICABLE", {"reason": "predicate selects customer-managed policies"}
    hits = []
    uncertain = False
    for n, raw in enumerate(statements):
        effect, ak, actions, rk, resources, condition = _statement(raw)
        if effect != "Allow":
            continue
        if ak == "NotAction" or rk == "NotResource":
            uncertain = True
        if ak == "Action" and any(a in {"*", "*:*"} for a in actions) and rk == "Resource" and any(r.startswith("arn:") and "*" not in r for r in resources):
            hits.append(n)
    if uncertain:
        return unknown("NotAction, NotResource or condition needs effective-action review")
    return result(bool(hits), statement_indexes=hits, policy_arn=arn)


def _native_policy_attachment(item, index, arn):
    """Join a complete authorization-detail projection without inventing activity."""
    _, account = _context(index)
    policy_provenance = get(item, "_provenance", dict)
    if (get(policy_provenance, "operation", str) != "iam:GetAccountAuthorizationDetails" or
            get(policy_provenance, "native_response_complete", bool) is not True):
        raise Unavailable("native IAM policy attachment provenance unavailable")
    expected_count = get(item, "AttachmentCount", int)
    if type(expected_count) is not int or expected_count < 0:
        raise Unavailable("native policy attachment count unavailable")
    partition = _ARN.fullmatch(arn).group(1)
    attached, principals = [], {}
    for kind, suffix in (("iam_user", "user"), ("iam_group", "group"), ("iam_role", "role")):
        seen = set()
        principals[kind] = {}
        for row in _rows(index, kind, global_kind=True):
            principal_arn = get(row, "Arn", str)
            if not re.fullmatch(r"arn:" + re.escape(partition) + r":iam::" + account +
                    r":" + suffix + r"/.+", principal_arn) or principal_arn in seen:
                raise Unavailable("foreign or duplicate IAM attachment principal")
            seen.add(principal_arn)
            provenance = get(row, "_provenance", dict)
            if (get(provenance, "operation", str) != "iam:GetAccountAuthorizationDetails" or
                    get(provenance, "native_response_complete", bool) is not True):
                raise Unavailable("native IAM principal attachment provenance unavailable")
            policies = get(row, "AttachedManagedPolicies", list)
            policy_arns = []
            for policy in policies:
                candidate = get(policy, "PolicyArn", str)
                match = _ARN.fullmatch(candidate) if isinstance(candidate, str) else None
                if match is None or match.group(1) != partition or match.group(2) not in {account, "aws"}:
                    raise Unavailable("foreign or malformed attached policy ARN")
                policy_arns.append(candidate)
            if len(policy_arns) != len(set(policy_arns)):
                raise Unavailable("duplicate managed-policy attachment")
            principals[kind][principal_arn] = row
            if arn in policy_arns:
                attached.append((kind, principal_arn))
    if len(attached) != expected_count:
        raise Unavailable("native policy attachment count mismatch")
    if not attached:
        return result(True, policy_arn=arn, attachment_count=0,
                      criterion="declared attachment; usage unassessed")

    names = {"iam_user": {}, "iam_group": {}, "iam_role": {}}
    for kind in names:
        for principal_arn, row in principals[kind].items():
            name = get(row, {"iam_user": "UserName", "iam_group": "GroupName", "iam_role": "RoleName"}[kind], str)
            if not name or principal_arn.rsplit("/", 1)[-1] != name or name in names[kind]:
                raise Unavailable("IAM principal name and ARN identity mismatch")
            names[kind][name] = principal_arn
    memberships = set()
    for name, user_arn in names["iam_user"].items():
        # UserDetail.GroupList is the complete native group-membership list.
        groups = optional(principals["iam_user"][user_arn], "GroupList", [], list)
        if any(not isinstance(group, str) or not group or group not in names["iam_group"]
               for group in groups) or len(groups) != len(set(groups)):
            raise Unavailable("malformed or unbound IAM user group membership")
        memberships.update(groups)

    if any(kind == "iam_user" for kind, _ in attached):
        return result(False, policy_arn=arn, attachment_kind="iam_user",
                      criterion="declared attachment; usage unassessed")
    if any(kind == "iam_group" and get(principals[kind][principal_arn], "GroupName", str) in memberships
           for kind, principal_arn in attached):
        return result(False, policy_arn=arn, attachment_kind="populated_iam_group",
                      criterion="declared attachment; usage unassessed")
    unresolved_role = None
    for kind, principal_arn in attached:
        if kind != "iam_role":
            continue
        try:
            trusted = _declared_role_trust(principals[kind][principal_arn], partition, account)
        except Unavailable as exc:
            if unresolved_role is None:
                unresolved_role = exc
            continue
        if trusted:
            return result(False, policy_arn=arn, attachment_kind="trusted_iam_role",
                          criterion="declared attachment; usage unassessed")
    if unresolved_role is not None:
        raise unresolved_role
    return result(True, policy_arn=arn, attachment_count=expected_count,
                  criterion="declared attachment; usage unassessed")


_TRUST_SEGMENT = re.compile(r"[A-Za-z0-9_+=,.@-]+\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z", re.I)
_REGION_LABEL = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+\Z")
_MULTILABEL_SERVICE_PREFIXES = {
    "apidestinations.events", "ops.apigateway",
    "application-signals.cloudwatch", "streams.metrics.cloudwatch",
    "monitoring.rds", "replicator.lambda", "logger.cloudfront",
    # AWS-managed service-linked role trusts returned by live IAM reads.
    "email.cognito-idp", "ops.emr-serverless", "malware-protection.guardduty",
    "runtime-identity.bedrock-agentcore", "member.org.stacksets.cloudformation",
    "vpcorigin.cloudfront", "replication.dynamodb", "settings.replication.dynamodb",
    "delivery.logs", "systemtables.cloudwatch",
}
_BUILTIN_OIDC = {"cognito-identity.amazonaws.com", "www.amazon.com", "graph.facebook.com", "accounts.google.com"}


def _identity_segments(resource, prefix, *, minimum, maximum):
    parts = resource.split("/")
    return (parts[0] == prefix and len(parts) >= minimum and (maximum is None or len(parts) <= maximum) and
            all(_TRUST_SEGMENT.fullmatch(part) for part in parts[1:]))


def _trust_principal_form(key, value, partition, account):
    """Recognize documented literal trust forms, without asserting live identity."""
    if key == "AWS" and (value == "*" or _ACCOUNT.fullmatch(value)):
        return "aws"
    if key == "Service":
        suffix = ".amazonaws.com.cn" if partition == "aws-cn" else ".amazonaws.com"
        labels = value[:-len(suffix)].split(".") if value.endswith(suffix) else []
        if (labels and all(_DNS_LABEL.fullmatch(label) for label in labels)
                and (len(labels) == 1 or len(labels) == 2 and _REGION_LABEL.fullmatch(labels[1])
                     or ".".join(labels) in _MULTILABEL_SERVICE_PREFIXES)):
            return "service"
        raise Unavailable("unrecognized IAM service principal form")
    if key == "Federated" and value in _BUILTIN_OIDC:
        return "web"
    parts = value.split(":", 5)
    if (len(parts) != 6 or parts[:2] != ["arn", partition] or parts[2] not in {"iam", "sts"}
            or parts[3] or not _ACCOUNT.fullmatch(parts[4])):
        raise Unavailable("unrecognized IAM trust principal ARN")
    resource = parts[5]
    if not resource or any(char.isspace() for char in resource) or "*" in resource or "?" in resource:
        raise Unavailable("malformed IAM trust principal resource")
    if key == "AWS":
        if parts[2] == "iam" and (resource == "root" or
                _identity_segments(resource, "user", minimum=2, maximum=None) or
                _identity_segments(resource, "role", minimum=2, maximum=None)):
            return "aws"
        if parts[2] == "sts" and (_identity_segments(resource, "assumed-role", minimum=3, maximum=3) or
                _identity_segments(resource, "federated-user", minimum=2, maximum=2)):
            return "aws"
        raise Unavailable("unrecognized AWS account, user, role, or session principal")
    if key == "Federated" and parts[2] == "iam" and parts[4] == account:
        if _identity_segments(resource, "saml-provider", minimum=2, maximum=2):
            return "saml"
        if resource.startswith("oidc-provider/"):
            issuer = resource.split("/", 1)[1]
            host, *path = issuer.split("/")
            if (len(host.split(".")) >= 2 and all(_DNS_LABEL.fullmatch(label) for label in host.split("."))
                    and all(segment and not any(c.isspace() or c in "?#" for c in segment) for segment in path)):
                return "web"
    raise Unavailable("unrecognized or cross-account federated principal")


def _declared_role_trust(role, partition, account):
    """A declared allow for an STS assume action, not effective assume access."""
    trusted = False
    denied = False
    for statement in _document(get(role, "AssumeRolePolicyDocument")):
        effect = get(statement, "Effect", str)
        if effect not in {"Allow", "Deny"} or "NotAction" in statement or "NotPrincipal" in statement:
            raise Unavailable("role trust action or principal cannot be resolved")
        if "Condition" in statement:
            raise Unavailable("conditional role trust requires effective-access review")
        action = get(statement, "Action")
        actions = [action] if isinstance(action, str) else action
        if not isinstance(actions, list) or not actions or any(not isinstance(a, str) or not a for a in actions):
            raise Unavailable("malformed role trust action")
        principal = get(statement, "Principal")
        if principal == "*":
            principal = {"AWS": "*"}
        if not isinstance(principal, dict) or not principal or any(key not in {"AWS", "Service", "Federated"}
                                                                for key in principal):
            raise Unavailable("malformed role trust principal")
        forms = set()
        for key, value in principal.items():
            values = [value] if isinstance(value, str) else value
            if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
                raise Unavailable("malformed role trust principal")
            forms.update(_trust_principal_form(key, v, partition, account) for v in values)
        if effect == "Deny":
            denied = True
            continue
        actions = {a.casefold() for a in actions}
        matching = ((forms & {"aws", "service"} and actions & {"sts:assumerole", "sts:*", "*"}) or
                    ("saml" in forms and actions & {"sts:assumerolewithsaml", "sts:*", "*"}) or
                    ("web" in forms and actions & {"sts:assumerolewithwebidentity", "sts:*", "*"}))
        trusted = trusted or matching
    if denied and trusted:
        raise Unavailable("role trust Deny needs effective-access review")
    return trusted


def _policy_attachment(item, index):
    arn, _ = _one_policy(item, index)
    if ("_provenance" in item or "_provenance" in item.get("_coverage", {}) or
            not any(field in item for field in ("AttachedUsers", "AttachedGroups", "AttachedRoles"))):
        return _native_policy_attachment(item, index, arn)
    users = get(item, "AttachedUsers", list)
    groups = get(item, "AttachedGroups", list)
    roles = get(item, "AttachedRoles", list)
    if (any(not isinstance(x, str) or not x for x in users + groups + roles) or
            any(len(values) != len(set(values)) for values in (users, groups, roles))):
        raise Unavailable("malformed policy attachment ARN")
    principal_rows = {}
    for kind in ("iam_user", "iam_group", "iam_role"):
        principal_rows[kind] = {get(row, "Arn", str): row for row in _rows(index, kind, global_kind=True)}
    for user in users:
        if user not in principal_rows["iam_user"]:
            raise Unavailable("attached user absent from complete inventory")
    for group in groups:
        row = principal_rows["iam_group"].get(group)
        if row is None:
            raise Unavailable("attached group absent from complete inventory")
        members = get(row, "Users", list)
        if any(not isinstance(member, dict) or not isinstance(member.get("UserName"), str) or
               not member["UserName"] for member in members):
            raise Unavailable("malformed IAM group membership")
        users_by_name = {get(u, "UserName", str) for u in principal_rows["iam_user"].values()}
        if any(member["UserName"] not in users_by_name for member in members):
            raise Unavailable("group member absent from complete user inventory")
        if members:
            return result(False, active_attachment=group)
    for role in roles:
        row = principal_rows["iam_role"].get(role)
        if row is None:
            raise Unavailable("attached role absent from complete inventory")
        for statement in _document(get(row, "AssumeRolePolicyDocument")):
            effect = get(statement, "Effect", str)
            if effect not in {"Allow", "Deny"}:
                raise Unavailable("malformed role trust effect")
            principal = statement.get("Principal")
            action = statement.get("Action")
            actions = [action] if isinstance(action, str) else action
            if not isinstance(actions, list) or not actions or any(not isinstance(a, str) for a in actions):
                raise Unavailable("malformed role trust action")
            if effect == "Allow" and any(a in {"sts:AssumeRole", "sts:*", "*"} for a in actions) and (isinstance(principal, str) and principal or
                    isinstance(principal, dict) and any(isinstance(value, str) and value or
                    isinstance(value, list) and any(isinstance(x, str) and x for x in value)
                    for value in principal.values())):
                return result(False, active_attachment=role)
    if users:
        return result(False, active_attachment=users[0])
    return result(True, policy_arn=arn, usable_attachment=False)


def _nonconsole_mfa(item, index):
    _, statements = _one_policy(item, index)
    administrative = []
    missing_mfa = []
    uncertain = False
    for n, raw in enumerate(statements):
        effect, ak, actions, rk, resources, condition = _statement(raw)
        if effect == "Deny":
            uncertain = True
            continue
        if ak == "NotAction" or rk == "NotResource":
            uncertain = True
            continue
        if not any(a in {"*", "*:*"} or a.lower() in {"iam:*", "kms:*", "organizations:*"} for a in actions):
            continue
        administrative.append(n)
        bool_conditions = condition.get("Bool") if isinstance(condition, dict) else None
        if not isinstance(bool_conditions, dict) or bool_conditions.get("aws:MultiFactorAuthPresent") not in {"true", True}:
            missing_mfa.append(n)
    if uncertain:
        return unknown("administrative deny or NotAction semantics cannot be resolved")
    return result(bool(missing_mfa), administrative_statement_indexes=administrative,
                  missing_mfa_statement_indexes=missing_mfa)


def _kms(item, index):
    ctx, account = _context(index)
    rows = _rows(index, "kms_key")
    key_id = get(item, "KeyId", str)
    matched = [r for r in rows if get(r, "KeyId", str) == key_id]
    if len(matched) != 1 or item != matched[0]:
        raise Unavailable("KMS key missing, duplicated or different from scoped inventory")
    meta = get(item, "Metadata.KeyMetadata", dict)
    arn = get(meta, "Arn", str)
    match = _KEY_ARN.fullmatch(arn)
    if match is None or match.group(3) != account or not ctx["scope"].endswith("/" + match.group(2)):
        raise Unavailable("KMS key ARN outside regional account scope")
    return arn, meta


def _kms_policy(item):
    return _document(get(item, "Policy.Policy"))


def _approved(index, name):
    ctx, account = _context(index)
    compliance = get(ctx, "metadata.compliance", dict)
    if compliance.get("account_id") != account:
        raise Unavailable("approved inventory account mismatch")
    values = get(compliance, name, list)
    if any(not isinstance(x, str) or not x for x in values) or len(values) != len(set(values)):
        raise Unavailable("malformed approved inventory: " + name)
    return set(values)


def _kms_enclave(item, index):
    arn, _ = _kms(item, index)
    selected = _approved(index, "enclave_key_arns")
    if arn not in selected:
        return "NOT_APPLICABLE", {"reason": "key is not designated for enclaves"}
    approved = _approved(index, "approved_enclave_measurements")
    if not approved:
        raise Unavailable("approved enclave measurements absent")
    statements = _kms_policy(item)
    hits = []
    for n, raw in enumerate(statements):
        effect, ak, actions, rk, resources, condition = _statement(raw)
        if effect != "Allow":
            continue
        if ak == "NotAction" or rk == "NotResource":
            raise Unavailable("KMS NotAction/NotResource requires access analysis")
        if not any(a.lower() in {"kms:decrypt", "kms:reencryptfrom", "kms:reencrypt*", "kms:*", "*"} for a in actions):
            continue
        if condition is None:
            hits.append(n)
            continue
        attest = [v for operator, kv in condition.items() if isinstance(kv, dict) and operator in {"StringEquals", "ForAnyValue:StringEquals"}
                  for k, v in kv.items() if k.startswith("kms:RecipientAttestation:ImageSha384") or k.startswith("kms:RecipientAttestation:PCR")]
        if not attest or any(not isinstance(v, str) or v not in approved for v in attest):
            raise Unavailable("attestation condition unapproved or ambiguous")
    return result(bool(hits), unconditioned_statement_indexes=hits, key_arn=arn)


def _key_grants(index, arn):
    rows = _rows(index, "kms_grant")
    grants = [r for r in rows if get(r, "KeyArn", str) == arn]
    for r in rows:
        grant_arn = get(r, "KeyArn", str)
        parsed = _KEY_ARN.fullmatch(grant_arn)
        key_region_account = _KEY_ARN.fullmatch(arn)
        if parsed is None or parsed.group(1, 2, 3) != key_region_account.group(1, 2, 3):
            raise Unavailable("foreign or malformed KMS grant key ARN")
    return grants



def _kms_iam_principals(index, arn):
    compliance = get(get(index, "context", dict), "metadata.compliance", dict)
    if compliance.get("kms_iam_access_complete") is not True:
        raise Unavailable("KMS IAM access inventory incomplete")
    by_key = get(compliance, "kms_iam_access_by_key", dict)
    principals = get(by_key, arn, list)
    if any(not isinstance(p, str) or not p for p in principals) or len(principals) != len(set(principals)):
        raise Unavailable("malformed KMS IAM principal list")
    return principals

def _kms_custodian(item, index):
    arn, _ = _kms(item, index)
    approved = _approved(index, "approved_custodian_arns")
    if not approved:
        raise Unavailable("approved custodian inventory empty")
    # The effective IAM delegation and attached-policy inventory is a required
    # independent fact; an absent one cannot establish a clean result.
    iam_principals = _kms_iam_principals(index, arn)
    bad = [p for p in iam_principals if p not in approved]
    for raw in _kms_policy(item):
        effect, ak, actions, rk, resources, condition = _statement(raw)
        if effect != "Allow":
            continue
        if ak != "Action" or rk != "Resource" or condition:
            raise Unavailable("conditional KMS authorization needs effective analysis")
        if not any(_sensitive_action(a) for a in actions):
            continue
        principal = get(raw, "Principal")
        arns = [principal] if isinstance(principal, str) else principal.get("AWS") if isinstance(principal, dict) else None
        arns = [arns] if isinstance(arns, str) else arns
        if not isinstance(arns, list) or any(not isinstance(x, str) for x in arns):
            raise Unavailable("KMS policy Principal cannot be resolved")
        bad.extend(x for x in arns if x not in approved)
    for grant in _key_grants(index, arn):
        operations = get(grant, "Operations", list)
        if any(not isinstance(x, str) for x in operations):
            raise Unavailable("malformed KMS grant operations")
        if any(_sensitive_grant(x) for x in operations):
            principal = get(grant, "GranteePrincipal", str)
            if principal not in approved:
                bad.append(principal)
    return result(bool(bad), unapproved_principals=sorted(set(bad)), key_arn=arn)


def _kms_compromised(item, index):
    arn, meta = _kms(item, index)
    tags = get(item, "Tags", list)
    if any(not isinstance(t, dict) or not isinstance(t.get("TagKey"), str) or not isinstance(t.get("TagValue"), str) for t in tags):
        raise Unavailable("malformed KMS tags")
    values = [t["TagValue"].lower() for t in tags if t["TagKey"].lower() == "compromised"]
    if len(values) > 1 or any(v not in {"true", "false"} for v in values):
        raise Unavailable("compromised tag ambiguous")
    if not values or values[0] == "false":
        return "NOT_APPLICABLE", {"reason": "key is not tagged Compromised=true"}
    state = get(meta, "KeyState", str)
    if state == "Disabled":
        return result(False, key_arn=arn, key_state=state)
    if state != "Enabled":
        return unknown("KMS key state is transitional or unrecognized")
    statements = _kms_policy(item)
    # A policy-wide deny is hard to establish from a single statement when IAM
    # delegation, conditions or NotAction can change the effective result.
    if any(_statement(s)[0] == "Deny" for s in statements):
        return unknown("KMS deny coverage and effective access unproven")
    for raw in statements:
        effect, ak, actions, rk, resources, condition = _statement(raw)
        if effect == "Allow" and ak == "Action" and rk == "Resource" and condition is None and any(a.lower() in {"kms:encrypt", "kms:generatedatakey", "kms:generatedatakey*", "kms:*", "*"} for a in actions):
            return result(True, key_arn=arn, key_state=state)
    return unknown("no proven policy-wide deny of new encryption operations")


def _kms_customer(item, index):
    arn, meta = _kms(item, index)
    selected = _approved(index, "customer_data_key_arns")
    if arn not in selected:
        return "NOT_APPLICABLE", {"reason": "key is not designated for customer data"}
    manager, state = get(meta, "KeyManager", str), get(meta, "KeyState", str)
    if manager not in {"CUSTOMER", "AWS"} or state not in {"Enabled", "Disabled", "PendingDeletion", "PendingImport", "Unavailable"}:
        raise Unavailable("unrecognized KMS key manager or state")
    if manager != "CUSTOMER" or state != "Enabled":
        return result(True, key_arn=arn, key_manager=manager, key_state=state)
    approved = _approved(index, "approved_key_principal_arns")
    if not approved:
        raise Unavailable("approved KMS principal inventory empty")
    iam_principals = _kms_iam_principals(index, arn)
    bad = [p for p in iam_principals if p not in approved]
    for raw in _kms_policy(item):
        effect, ak, actions, rk, resources, condition = _statement(raw)
        if effect != "Allow":
            continue
        if ak != "Action" or rk != "Resource" or condition:
            raise Unavailable("KMS policy authorization needs effective analysis")
        if not any(_sensitive_action(a) for a in actions):
            continue
        principal = get(raw, "Principal")
        principals = [principal] if isinstance(principal, str) else principal.get("AWS") if isinstance(principal, dict) else None
        principals = [principals] if isinstance(principals, str) else principals
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            raise Unavailable("unresolvable KMS principal")
        bad.extend(x for x in principals if x not in approved)
    for grant in _key_grants(index, arn):
        operations = get(grant, "Operations", list)
        if any(not isinstance(x, str) for x in operations):
            raise Unavailable("malformed KMS grant operations")
        if any(_sensitive_grant(x) for x in operations):
            principal = get(grant, "GranteePrincipal", str)
            if principal not in approved:
                bad.append(principal)
    return result(bool(bad), key_arn=arn, unapproved_principals=sorted(set(bad)))


# SPEC_DATA and registrations are generated from the immutable ten-field ledger.
SPECS = {'aws.nist.all_iam_policies_no_star_star': {'provider': 'aws',
                                            'resource_kind': 'iam_policy',
                                            'severity': 'medium',
                                            'category': 'hardening',
                                            'title': 'IAM managed and inline policies avoid full '
                                                     'administrator grants',
                                            'remediation_hint': 'Remove Allow Action=* Resource=* statements '
                                                                'from IAM policy documents.',
                                            'proposed_spec_sha256': '887071640abdd9478901e7d72b8630fb23549894a1b85aedb67f4053e1f82a6d'},
 'aws.nist.all_managed_policies_no_service_wildcard': {'provider': 'aws',
                                                       'resource_kind': 'iam_policy',
                                                       'severity': 'medium',
                                                       'category': 'hardening',
                                                       'title': 'Managed IAM policies avoid service-wide '
                                                                'wildcard grants',
                                                       'remediation_hint': 'Replace service-wide wildcard '
                                                                           'actions with required actions '
                                                                           'and resources.',
                                                       'proposed_spec_sha256': '2479588276577b7b16e9a66aa58acc88a951bd7cb2973aef8b9fc22d6bb8c5ec'},
 'aws.pci.iam.nonconsole_mfa_policy': {'provider': 'aws',
                                       'resource_kind': 'iam_policy',
                                       'severity': 'high',
                                       'category': 'identity',
                                       'title': 'Administrative API access requires MFA',
                                       'remediation_hint': 'Add an IAM deny for administrative API actions '
                                                           'unless aws:MultiFactorAuthPresent is true, or '
                                                           'require an MFA-backed session policy.',
                                       'proposed_spec_sha256': '3b7d7d58c4207f9612a05a53feac35862e95a2261c25f49e70ff54abc3eea8a7'},
 'aws.pci.iam.policy_attached_to_active_principal': {'provider': 'aws',
                                                     'resource_kind': 'iam_policy',
                                                     'severity': 'medium',
                                                     'category': 'hardening',
                                                     'title': 'IAM policy is attached to an active principal',
                                                     'remediation_hint': 'Attach the configured policy to an '
                                                                         'active IAM user, populated group '
                                                                         'or assumable role; remove any '
                                                                         'unused standalone policy.',
                                                     'proposed_spec_sha256': 'f67db7256e23df1d212a33bfa77e7b3e27e9aee669562eeda5fdab08c878edbb'},
 'aws.pci.iam.wildcard_action_scoped_resource': {'provider': 'aws',
                                                 'resource_kind': 'iam_policy',
                                                 'severity': 'high',
                                                 'category': 'hardening',
                                                 'title': 'IAM policies avoid all actions on scoped '
                                                          'resources',
                                                 'remediation_hint': 'Replace Allow statements using '
                                                                     'Action:* or equivalent NotAction with '
                                                                     'explicit required actions and Resource '
                                                                     'ARNs.',
                                                 'proposed_spec_sha256': '62fc3984f9c8cf62ce9332649e33531667ac1bc9d98b348734409f691eca33fa'},
 'aws_fedramp_iam_all_policies_no_admin_star': {'provider': 'aws',
                                                'resource_kind': 'iam_policy',
                                                'severity': 'medium',
                                                'category': 'compliance',
                                                'title': 'All IAM policy types avoid star-star '
                                                         'administration',
                                                'remediation_hint': 'Configure the named AWS resource to '
                                                                    'satisfy the predicate and verify all '
                                                                    'in-scope resources.',
                                                'proposed_spec_sha256': 'b41125f98eca9a56141be387efa0112884b581fb631c2201e4ae4c7bdcac6775'},
 'aws_fedramp_iam_all_policies_no_service_wildcard': {'provider': 'aws',
                                                      'resource_kind': 'iam_policy',
                                                      'severity': 'medium',
                                                      'category': 'compliance',
                                                      'title': 'All IAM policy types avoid unrestricted '
                                                               'service access',
                                                      'remediation_hint': 'Configure the named AWS resource '
                                                                          'to satisfy the predicate and '
                                                                          'verify all in-scope resources.',
                                                      'proposed_spec_sha256': '5a61f47e8b69c270949b86a60ae65a3e355fa2d9a086578e12708ce9caff92fa'},
 'aws_g6_iam_all_policy_service_wildcard': {'provider': 'aws',
                                            'resource_kind': 'iam_policy',
                                            'severity': 'high',
                                            'category': 'least_privilege',
                                            'title': 'All IAM policy types avoid service-wide grants to '
                                                     'resources',
                                            'remediation_hint': 'Replace service-wide action grants with the '
                                                                'minimum required actions.',
                                            'proposed_spec_sha256': '07a14e1d9dcee98a5d7e16908c6b6d871b64f3a6bd7521e6562010157da608f8'},
 'aws_g6_iam_all_policy_star_star': {'provider': 'aws',
                                     'resource_kind': 'iam_policy',
                                     'severity': 'high',
                                     'category': 'least_privilege',
                                     'title': 'IAM policies avoid full administrator statements',
                                     'remediation_hint': 'Remove unrestricted Action and Resource wildcard '
                                                         'grants or scope them to least privilege.',
                                     'proposed_spec_sha256': '378b908ee2ac103f4eca940875d094f4576643be777a3b182aa39bdaba17b539'},
 'aws_nist_iam_all_policy_no_service_wild_card': {'provider': 'aws',
                                                  'resource_kind': 'iam_policy',
                                                  'severity': 'medium',
                                                  'category': 'compliance',
                                                  'title': 'Ensure IAM policy should not grant full access '
                                                           'to service',
                                                  'remediation_hint': 'Configure the resource to satisfy the '
                                                                      'stated predicate and review missing '
                                                                      'inventory or policy inputs.',
                                                  'proposed_spec_sha256': 'c8848c4102f3b1a86d3de195d194eff190acfb60d412f428953a2ce8cbbf9aee'},
 'aws_nist_iam_policy_no_star_star': {'provider': 'aws',
                                      'resource_kind': 'iam_policy',
                                      'severity': 'medium',
                                      'category': 'compliance',
                                      'title': 'IAM policy should not have statements with admin access',
                                      'remediation_hint': 'Configure the resource to satisfy the stated '
                                                          'predicate and review missing inventory or policy '
                                                          'inputs.',
                                      'proposed_spec_sha256': '739d3a83e07f4d435eeb5eb44b46289c70f07cd5f03430a54a6b95922bc08c1a'},
 'aws.pci.kms.enclave_attestation_policy': {'provider': 'aws',
                                            'resource_kind': 'kms_key',
                                            'severity': 'high',
                                            'category': 'hardening',
                                            'title': 'Enclave KMS policies require attestation',
                                            'remediation_hint': 'Add kms:RecipientAttestation:ImageSha384 or '
                                                                'approved PCR conditions to every KMS '
                                                                'decrypt and unwrap Allow path.',
                                            'proposed_spec_sha256': 'c1deec54c1ef53bda6a38847c66b8774d9db59f45fa616cbdf8073ec43403462'},
 'aws.pci.kms.key_custodian_access': {'provider': 'aws',
                                      'resource_kind': 'kms_key',
                                      'severity': 'high',
                                      'category': 'hardening',
                                      'title': 'KMS key access is restricted to custodians',
                                      'remediation_hint': 'Remove unapproved principals from KMS key '
                                                          'policies, grants and IAM policies granting '
                                                          'decrypt, re-encrypt, deletion or administration.',
                                      'proposed_spec_sha256': '9738c441ec6fd58bd97106ba12098c32f5f78d47917e6fcf0820702dad0abee1'},
 'aws_kms_compromised_key_restricted': {'provider': 'aws',
                                        'resource_kind': 'kms_key',
                                        'severity': 'critical',
                                        'category': 'hardening',
                                        'title': 'Compromised KMS keys cannot create new ciphertext',
                                        'remediation_hint': 'Disable compromised keys or restrict them to '
                                                            'controlled recovery operations.',
                                        'proposed_spec_sha256': '6db025dd077a5a804935aef8784722b5d4dc5915a4736f17f3afd18a585a96e7'},
 'aws_kms_customer_key_control': {'provider': 'aws',
                                  'resource_kind': 'kms_key',
                                  'severity': 'high',
                                  'category': 'hardening',
                                  'title': 'Customer data KMS keys have restricted control',
                                  'remediation_hint': 'Use customer managed keys and restrict key policy '
                                                      'principals.',
                                  'proposed_spec_sha256': 'edb96b4755ff40f7e9d42079479cea23b45569ce0cb33cc019cfe01f1a72686f'}}

_EVALUATORS = {
    "aws.nist.all_iam_policies_no_star_star": lambda item, index: _policy_scan(index, "star"),
    "aws.nist.all_managed_policies_no_service_wildcard": lambda item, index: _policy_scan(index, "managed_service"),
    "aws.pci.iam.nonconsole_mfa_policy": _nonconsole_mfa,
    "aws.pci.iam.policy_attached_to_active_principal": _policy_attachment,
    "aws.pci.iam.wildcard_action_scoped_resource": _policy_scoped_action,
    "aws_fedramp_iam_all_policies_no_admin_star": lambda item, index: _customer_policy_scan(index, "star"),
    "aws_fedramp_iam_all_policies_no_service_wildcard": lambda item, index: _customer_policy_scan(index, "service"),
    "aws_g6_iam_all_policy_service_wildcard": lambda item, index: _policy_scan(index, "scoped_service"),
    "aws_g6_iam_all_policy_star_star": lambda item, index: _policy_scan(index, "star"),
    "aws_nist_iam_all_policy_no_service_wild_card": lambda item, index: _policy_scan(index, "service"),
    "aws_nist_iam_policy_no_star_star": lambda item, index: _policy_scan(index, "star"),
    "aws.pci.kms.enclave_attestation_policy": _kms_enclave,
    "aws.pci.kms.key_custodian_access": _kms_custodian,
    "aws_kms_compromised_key_restricted": _kms_compromised,
    "aws_kms_customer_key_control": _kms_customer,
}

_SCOPE_IDS = {
    "aws.nist.all_iam_policies_no_star_star", "aws.nist.all_managed_policies_no_service_wildcard",
    "aws_fedramp_iam_all_policies_no_admin_star", "aws_fedramp_iam_all_policies_no_service_wildcard",
    "aws_g6_iam_all_policy_service_wildcard", "aws_g6_iam_all_policy_star_star",
    "aws_nist_iam_all_policy_no_service_wild_card", "aws_nist_iam_policy_no_star_star",
}
_FEDRAMP_CUSTOMER_POLICY_IDS = {
    "aws_fedramp_iam_all_policies_no_admin_star", "aws_fedramp_iam_all_policies_no_service_wildcard",
}

for _id, _spec in SPECS.items():
    _deps = (["iam_customer_policy"] if _id in _FEDRAMP_CUSTOMER_POLICY_IDS else
             ["iam_policy", "iam_user", "iam_group", "iam_role"] if _id in _SCOPE_IDS and
             _id != "aws.nist.all_managed_policies_no_service_wildcard" else
             ["iam_policy"] if _spec["resource_kind"] == "iam_policy" else
             ["kms_key", "kms_grant"] if _id in {"aws.pci.kms.key_custodian_access", "aws_kms_customer_key_control"} else
             ["kms_key"])
    if _id == "aws.pci.iam.policy_attached_to_active_principal":
        _deps = ["iam_policy", "iam_user", "iam_group", "iam_role"]
    _fn = _EVALUATORS[_id]
    register(_id, "aws", _spec["category"] if _spec["category"] in {"hardening", "least_privilege"} else "hardening",
             _spec["resource_kind"], _spec["title"], _spec["severity"], "AC-6",
             _spec["remediation_hint"], target="scope" if _id in _SCOPE_IDS else "resource",
             dependencies=_deps)(_fn)
    # The legacy registry validator predates the signed compliance category.
    # Preserve the exact signed category in the immutable Check metadata.
    if _spec["category"] not in {"hardening", "least_privilege"}:
        CHECKS[-1] = replace(CHECKS[-1], category=_spec["category"])
