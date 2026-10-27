"""claude_aws_a IAM: Prowler policy-document engines (admin access, full service access,
marketplace subscribe, privilege escalation, AgentCore, trust policies).

Prowler expands Action/NotAction patterns over the whole pinned IAM catalog. Each predicate here
only asks whether specific concrete actions survive the Allow/Deny/NotAction algebra, so the
algebra is evaluated over that finite set of concrete actions (``claude_aws_a_iam_catalog``),
which is exact: a concrete action belongs to a pattern's expansion iff it matches the pattern
under py-iam-expand semantics (split at the first colon, lowercase, ``fnmatchcase`` when the
part has ``*``/``?``, otherwise equality; a pattern without a colon or with an empty part, other
than the bare ``*``, expands to nothing).

Prowler's policy population: customer ("Custom") policies only when attached (scan_unused_services
defaults to False), AWS-managed policies only when attached, inline policies per user/group/role.
Inline results are reported per principal: FAIL when any of its inline policies fails, and
NOT_APPLICABLE for a principal without inline policies (Prowler emits no finding there).
"""
from __future__ import annotations

from fnmatch import fnmatchcase
from functools import lru_cache

from . import result
from .facts import Unavailable, get, list_of_objects
from .claude_aws_a_common import install, is_policy_public, account, idx, P, ACCOUNT
from .claude_aws_a_ec2 import w
from .claude_aws_a_iam import (is_service_role, is_aws_managed, default_document, policy_attached, pol, allow, doc,
                               inline, attach, inline_policies, PRINCIPALS, FIXTURE, ROLE, GAAD, IAM_UG, CUSTOM_ARN, AWS_ARN)
from .claude_aws_a_iam_catalog import ESCALATION_COMBOS, SERVICE_ACTIONS, MARKETPLACE_SUBSCRIBE, AWS_SERVICE_KEYS, CATALOG
from . import claude_aws_a_lib_agentcore as agentcore
from . import claude_aws_a_lib_passrole as passrole
from . import claude_aws_a_lib_trust as trust

PRIVESC = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"


# --------------------------------------------------------------------------- py-iam-expand membership
def expands_to(pattern, action):
    """Whether concrete catalog ``action`` is in expand_actions(pattern, REMOVE)."""
    if pattern == "*":
        return True
    if ":" not in pattern:
        return False
    svc_pat, act_pat = pattern.lower().split(":", 1)
    if not svc_pat or not act_pat:
        return False
    svc, name = action.lower().split(":", 1)

    def part(pat, value):
        if pat == "*":
            return True
        if "*" in pat or "?" in pat:
            return fnmatchcase(value, pat)
        return pat == value
    return part(svc_pat, svc) and part(act_pat, name)


def patterns(value):
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {v for v in value if isinstance(v, str)}
    return set()


@lru_cache(maxsize=65536)
def _expand_one(pattern, universe):
    """The actions of the (frozen) universe one pattern expands to; patterns and universes repeat across policies."""
    return frozenset(a for a in universe if expands_to(pattern, a))


def expand(values, universe):
    """{a in universe : some pattern of values expands to a}; callers only use membership/subset/sorted results."""
    pats = patterns(values)
    if not pats:
        return set()
    universe = universe if isinstance(universe, frozenset) else frozenset(universe)
    out = set()
    for p in pats:
        out |= _expand_one(p, universe)
    return out


def statements_of(document):
    statements = document.get("Statement", [])
    return statements if isinstance(statements, list) else [statements]


def effective_actions(document, universe):
    """get_effective_actions(document) intersected with ``universe``."""
    if not document or "Statement" not in document:
        return set()
    allowed, denied, allow_ex, deny_ex = set(), set(), set(), set()
    has_allow_not = has_deny_not = False
    for s in statements_of(document):
        effect = s.get("Effect", "")
        if not isinstance(effect, str):
            continue
        effect = effect.strip().lower()
        if effect not in ("allow", "deny"):
            continue
        (allowed if effect == "allow" else denied).update(expand(s.get("Action"), universe))
        if patterns(s.get("NotAction")):
            if effect == "allow":
                allow_ex.update(expand(s.get("NotAction"), universe))
                has_allow_not = True
            else:
                deny_ex.update(expand(s.get("NotAction"), universe))
                has_deny_not = True
    if has_allow_not:
        allowed |= set(universe) - allow_ex
    if has_deny_not:
        denied |= set(universe) - deny_ex
    return allowed - denied


def full_service_access(service, document):
    """check_full_service_access(service, document) for service in SERVICE_ACTIONS."""
    if not document or "Statement" not in document:
        return False
    target = set(SERVICE_ACTIONS[service])
    if not target.issubset(effective_actions(document, target)):
        return False
    on_all = set()
    for s in statements_of(document):
        effect = s.get("Effect", "")
        resources = s.get("Resource", [])
        if not isinstance(effect, str) or effect.strip().lower() != "allow":
            continue
        if isinstance(resources, str):
            resources = [resources]
        if "*" not in resources:
            continue
        granted = expand(s.get("Action"), target)
        if patterns(s.get("NotAction")):
            granted |= target - expand(s.get("NotAction"), target)
        on_all |= granted
    return target.issubset(on_all)


def admin_access(document):
    """Prowler check_admin_access."""
    if not document:
        return False
    allowed, allowed_not = set(), set()

    def add(actions, target):
        if actions:
            if isinstance(actions, str):
                target.add(actions)
            elif isinstance(actions, list):
                target.update(actions)
    for s in statements_of(document):
        not_resource = s.get("NotResource")
        if s.get("Resource") in ["*", ["*"], ["*/*"], "*/*", ["*:*"], "*:*"] or (not_resource and not_resource not in ["*", ["*"]]):
            if s.get("Effect") == "Allow":
                add(s.get("Action"), allowed)
                add(s.get("NotAction"), allowed_not)
    if not allowed and allowed_not:
        allowed.add("*")
    if allowed_not and any(a.split(":")[0] not in AWS_SERVICE_KEYS for a in allowed_not):
        allowed.add("*")
    return "*" in allowed


def marketplace_subscribe(document):
    """Prowler policy_allows_marketplace_subscribe_on_all_resources."""
    if not document or "Statement" not in document:
        return False
    target = set(MARKETPLACE_SUBSCRIBE)
    allowed, denied = set(), set()
    for s in statements_of(document):
        effect = s.get("Effect", "")
        if not isinstance(effect, str):
            continue
        effect = effect.strip().lower()
        if effect not in ("allow", "deny"):
            continue
        resources = s.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" not in resources:
            continue
        if effect == "deny" and "Condition" in s:
            continue
        acts = expand(s.get("Action"), target)
        if patterns(s.get("NotAction")):
            acts |= target - expand(s.get("NotAction"), target)
        (allowed if effect == "allow" else denied).update(acts)
    return bool(target & (allowed - denied))


ESCALATION_UNIVERSE = frozenset(a for _, concrete in ESCALATION_COMBOS.values() for a in concrete)


def privilege_escalation(document):
    """Prowler check_privilege_escalation: sorted matched combination patterns."""
    if not document:
        return []
    effective = effective_actions(document, ESCALATION_UNIVERSE)
    matched = set()
    for pats, concrete in ESCALATION_COMBOS.values():
        if concrete and set(concrete).issubset(effective):
            matched.update(pats)
    return sorted(matched)


def permissive_role_assumption(document):
    for s in statements_of(document):
        resource = s.get("Resource")
        wildcard = ("*" in resource) if isinstance(resource, str) else any("*" in r for r in resource) if isinstance(resource, list) else False
        if s.get("Effect") == "Allow" and "Action" in s and "Resource" in s and wildcard:
            actions = s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
            if any(a in ["sts:AssumeRole", "sts:*", "*"] for a in actions):
                return True
    return False


def document_of(value, *, identity=True):
    if not isinstance(value, dict):
        raise Unavailable("policy document is not an object")
    statements = get(value, "Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise Unavailable("policy Statement is not an object or list")
    for statement in statements:
        if get(statement, "Effect", str) not in {"Allow", "Deny"}:
            raise Unavailable("policy statement Effect is not Allow or Deny")
        selectors = (("Action", "NotAction"), ("Resource", "NotResource")) if identity else (("Action", "NotAction"),)
        for positive, negative in selectors:
            if (positive in statement) == (negative in statement):
                raise Unavailable("policy statement requires exactly one " + positive + " selector")
            selected = get(statement, positive if positive in statement else negative)
            selected = [selected] if isinstance(selected, str) else selected
            if (not isinstance(selected, list) or not selected or
                    any(not isinstance(v, str) or not v.strip() for v in selected)):
                raise Unavailable("policy statement selector malformed: " + positive)
        if "Condition" in statement:
            get(statement, "Condition", dict)
    return value


# --------------------------------------------------------------------------- managed policy population
def custom_attached(item):
    if is_aws_managed(item):
        return False, "AWS managed policy"
    if not policy_attached(item):
        return False, "unattached customer policy (Prowler scan_unused_services is off by default)"
    return True, None


def _managed(cid, title, rows, engine, failing, *, population, severity, remediation, docs, note=None, na=None, extra=None):
    cases = dict(extra or {})
    if na is not None:
        cases["na"] = na

    @install(cid, "iam_policy", title, {"aws": pol(allow("s3:Get*"), arn=AWS_ARN), "custom_attached": pol(allow("s3:GetObject", "arn:aws:s3:::b/*")),
         "custom_unattached": pol(allow("s3:GetObject", "arn:aws:s3:::b/*"), attached=0)}[population],
        failing, rows=rows, severity=severity, category="least_privilege", control="AC-6", remediation=remediation, docs=docs,
        extra=cases, note=note)
    def evaluate(item, index):
        aws = is_aws_managed(item)
        attached = policy_attached(item)
        wanted = {"aws": aws and attached, "custom_attached": not aws and attached, "custom_unattached": not aws and not attached}[population]
        if not wanted:
            return "NOT_APPLICABLE", {"reason": "outside Prowler policy population"}
        document = document_of(default_document(item))
        return engine(document)
    return evaluate


def bool_engine(function, label):
    def engine(document):
        hit = bool(document) and function(document)
        return result(hit, **{label: hit})
    return engine


def privesc_engine(document):
    found = privilege_escalation(document)
    return result(bool(found), escalation_actions=found)


ADMIN_DOCS = [GAAD, "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1"]
NA_AWS = pol(allow("*"), arn=AWS_ARN)
NA_UNATTACHED = pol(allow("*"), attached=0)

_managed("aws.claude_a.iam.prowler_aws_attached_policy_no_admin", "Attached AWS managed policy does not grant administrative access (Prowler)",
    [P + "iam_aws_attached_policy_no_administrative_privileges"], bool_engine(admin_access, "admin_access"), pol(allow("*"), arn=AWS_ARN),
    population="aws", severity="high", remediation="Detach AWS managed administrator policies and grant least privilege.", docs=ADMIN_DOCS,
    na=pol(allow("*")), note="Prowler check_admin_access: Allow with Action \"*\" (or only NotAction / NotAction naming an unknown service) on Resource *, */*, *:*, or a NotResource other than *.")
_managed("aws.claude_a.iam.prowler_customer_attached_policy_no_admin", "Attached customer managed policy does not grant administrative access (Prowler)",
    [P + "iam_customer_attached_policy_no_administrative_privileges"], bool_engine(admin_access, "admin_access"), pol(allow("*")),
    population="custom_attached", severity="high", remediation="Remove \"*\" administrative statements from attached customer managed policies.",
    docs=ADMIN_DOCS, na=NA_AWS, extra={"fail_notaction": pol({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})})
_managed("aws.claude_a.iam.prowler_customer_unattached_policy_no_admin", "Unattached customer managed policy does not grant administrative access (Prowler)",
    [P + "iam_customer_unattached_policy_no_administrative_privileges"], bool_engine(admin_access, "admin_access"), pol(allow("*"), attached=0),
    population="custom_unattached", severity="medium", remediation="Delete or narrow unattached customer managed policies granting \"*\".",
    docs=ADMIN_DOCS, na=pol(allow("*")))
_managed("aws.claude_a.iam.prowler_customer_policy_no_privilege_escalation", "Attached customer managed policy allows no known privilege-escalation combination (Prowler)",
    [P + "iam_policy_allows_privilege_escalation"], privesc_engine, pol(allow(["iam:PassRole", "ec2:RunInstances"])),
    population="custom_attached", severity="high", remediation="Remove the action combinations that allow privilege escalation or scope them to specific resources.",
    docs=[PRIVESC], na=NA_UNATTACHED, note="Prowler privilege_escalation_policies_combination evaluated over " + CATALOG + "; resources and conditions are not evaluated, as upstream.")
_managed("aws.claude_a.iam.prowler_customer_policy_no_cloudtrail_full_access", "Attached customer managed policy does not grant every CloudTrail action on * (Prowler)",
    [P + "iam_policy_no_full_access_to_cloudtrail"], bool_engine(lambda d: full_service_access("cloudtrail", d), "full_access"), pol(allow("cloudtrail:*")),
    population="custom_attached", severity="critical", remediation="Replace cloudtrail:* with the specific CloudTrail actions required.", docs=[GAAD], na=NA_UNATTACHED)
_managed("aws.claude_a.iam.prowler_customer_policy_no_kms_full_access", "Attached customer managed policy does not grant every KMS action on * (Prowler)",
    [P + "iam_policy_no_full_access_to_kms"], bool_engine(lambda d: full_service_access("kms", d), "full_access"), pol(allow("kms:*")),
    population="custom_attached", severity="critical", remediation="Replace kms:* with the specific KMS actions and key ARNs required.", docs=[GAAD], na=NA_UNATTACHED,
    extra={"pass_denied": pol(allow("kms:*"), {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*"})})
_managed("aws.claude_a.iam.prowler_customer_policy_no_marketplace_subscribe", "Attached customer managed policy does not allow aws-marketplace:Subscribe on * (Prowler)",
    [P + "iam_policy_no_wildcard_marketplace_subscribe"], bool_engine(marketplace_subscribe, "subscribe_on_all"), pol(allow("aws-marketplace:*")),
    population="custom_attached", severity="medium", remediation="Remove aws-marketplace:Subscribe from this customer policy where purchasing is unauthorized; if purchasing is required, use a separately governed procurement role and reviewed exception. AWS Marketplace Subscribe cannot be scoped to product ARNs.",
    docs=["https://docs.aws.amazon.com/marketplace/latest/buyerguide/buyer-iam-users-groups-policies.html"], na=NA_UNATTACHED)
_managed("aws.claude_a.iam.prowler_customer_policy_no_permissive_role_assumption", "Attached customer managed policy does not allow sts:AssumeRole on wildcard resources (Prowler)",
    [P + "iam_no_custom_policy_permissive_role_assumption"], bool_engine(permissive_role_assumption, "permissive"), pol(allow("sts:AssumeRole", "arn:aws:iam::*:role/*")),
    population="custom_attached", severity="medium", remediation="List the specific role ARNs the principal may assume.",
    docs=[IAM_UG + "id_roles_use_permissions-to-switch.html"], na=NA_UNATTACHED,
    note="Exact, case-sensitive Action values sts:AssumeRole, sts:* or * with a Resource containing *.")


def agentcore_engine(document):
    if not document:
        return "MANUAL", {"reason": "policy document was not retrieved"}
    if agentcore._has_unevaluated_notaction(document):
        return "MANUAL", {"reason": "Allow statement uses NotAction, which the source does not evaluate"}
    denied = agentcore._denied_token_operations(document)
    unscoped = set()
    for s in agentcore._statements(document):
        if s.get("Effect") != "Allow" or agentcore._is_workload_identity_scoped(s):
            continue
        unscoped |= agentcore._covered_token_operations(s) - denied
    return result(bool(unscoped), unscoped_token_operations=sorted(unscoped))


def passrole_engine(document):
    if not document:
        return "MANUAL", {"reason": "policy document was not retrieved"}
    if passrole._has_unevaluated_notaction(document):
        return "MANUAL", {"reason": "Allow statement uses NotAction, which the source does not evaluate"}
    unrestricted = False
    if not passrole._denies_passrole_everywhere(document):
        unrestricted = any(s.get("Effect") == "Allow" and passrole._covers_passrole(s) and passrole._allows_any_role(s)
                           and passrole._targets_agentcore(s, document) for s in passrole._statements(document))
    return result(unrestricted, passrole_to_agentcore_on_all_roles=unrestricted)


AC_ARN = "arn:aws:bedrock-agentcore:us-east-1:%s:workload-identity-directory/default/workload-identity/agent" % ACCOUNT
_managed("aws.claude_a.iam.prowler_policy_agentcore_token_scoped", "Customer policy confines AgentCore workload access tokens to workload identities (Prowler)",
    [P + "iam_policy_no_agentcore_workload_access_token_wildcard"], agentcore_engine, pol(allow("bedrock-agentcore:GetWorkloadAccessToken*")),
    population="custom_attached", severity="high", remediation="Scope GetWorkloadAccessToken* to the agent's own workload identity ARN.",
    docs=["https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-iam-awsmanpol.html"], na=NA_UNATTACHED,
    extra={"pass_scoped": pol(allow("bedrock-agentcore:GetWorkloadAccessToken", AC_ARN))},
    note="Verbatim transcription of the upstream helpers (claude_aws_a_lib_agentcore); NotAction or a missing document is MANUAL, as upstream.")
_managed("aws.claude_a.iam.prowler_policy_passrole_agentcore_restricted", "Customer policy does not pass every role to Bedrock AgentCore (Prowler)",
    [P + "iam_policy_passrole_to_bedrock_agentcore_restricted"], passrole_engine,
    pol(allow("iam:PassRole", "*", Condition={"StringEquals": {"iam:PassedToService": "bedrock-agentcore.amazonaws.com"}})),
    population="custom_attached", severity="high", remediation="Limit iam:PassRole for AgentCore to the specific execution role ARNs.",
    docs=[IAM_UG + "id_roles_use_passrole.html"], na=NA_UNATTACHED,
    note="Verbatim transcription of the upstream helpers (claude_aws_a_lib_passrole); NotAction or a missing document is MANUAL, as upstream.")


# --------------------------------------------------------------------------- inline policies per principal
def _inline(suffix, title, row, engine, statement, *, severity, remediation, docs, note=None):
    for kind, (name_key, list_key, label) in PRINCIPALS.items():
        def make(kind=kind, label=label):
            @install("aws.claude_a.iam.prowler_%s_inline_%s" % (label, suffix), kind, "IAM %s inline policies: %s (Prowler)" % (label, title),
                inline(kind, allow("s3:GetObject", "arn:aws:s3:::b/*")), inline(kind, statement), rows=[P + row], severity=severity,
                category="least_privilege", control="AC-6", remediation=remediation, docs=docs, extra={"na": FIXTURE[kind]}, note=note)
            def evaluate(item, index):
                policies = inline_policies(item, kind)
                if not policies:
                    return "NOT_APPLICABLE", {"reason": "no inline policies"}
                failing = []
                for p in policies:
                    status, _ = engine(document_of(get(p, "PolicyDocument")))
                    if status == "FAIL":
                        failing.append(get(p, "PolicyName", str))
                return result(bool(failing), failing_policies=failing)
        make()


_inline("no_admin", "no administrative access", "iam_inline_policy_no_administrative_privileges", bool_engine(admin_access, "admin"), allow("*"),
    severity="high", remediation="Remove \"*\" administrative grants from inline policies.", docs=ADMIN_DOCS)
_inline("no_privilege_escalation", "no privilege-escalation combination", "iam_inline_policy_allows_privilege_escalation", privesc_engine,
    allow(["iam:CreatePolicyVersion"]), severity="high", remediation="Remove privilege-escalation action combinations from inline policies.", docs=[PRIVESC])
_inline("no_cloudtrail_full_access", "no full CloudTrail access on *", "iam_inline_policy_no_full_access_to_cloudtrail",
    bool_engine(lambda d: full_service_access("cloudtrail", d), "full"), allow("cloudtrail:*"), severity="critical",
    remediation="Replace cloudtrail:* in inline policies with specific actions.", docs=[GAAD])
_inline("no_kms_full_access", "no full KMS access on *", "iam_inline_policy_no_full_access_to_kms",
    bool_engine(lambda d: full_service_access("kms", d), "full"), allow("kms:*"), severity="critical",
    remediation="Replace kms:* in inline policies with specific actions and key ARNs.", docs=[GAAD])
_inline("no_marketplace_subscribe", "no aws-marketplace:Subscribe on *", "iam_inline_policy_no_wildcard_marketplace_subscribe",
    bool_engine(marketplace_subscribe, "subscribe"), allow("aws-marketplace:Subscribe"), severity="medium",
    remediation="Scope or remove aws-marketplace:Subscribe in inline policies.",
    docs=["https://docs.aws.amazon.com/marketplace/latest/buyerguide/buyer-iam-users-groups-policies.html"])


# --------------------------------------------------------------------------- role trust policies
SVC_TRUST = doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole",
                 "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}}})
OPEN_SVC = doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"})
HUMAN = doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"})


@install("aws.claude_a.iam.prowler_role_confused_deputy_prevented", "iam_role", "Service role trust policy prevents cross-service confused deputy (Prowler)",
    w(ROLE, AssumeRolePolicyDocument=SVC_TRUST), w(ROLE, AssumeRolePolicyDocument=OPEN_SVC), index=idx(),
    rows=[P + "iam_role_cross_service_confused_deputy_prevention"], severity="high", category="exposure", control="AC-3",
    remediation="Add aws:SourceAccount or aws:SourceArn conditions to service trust statements.",
    docs=[IAM_UG + "confused-deputy.html"], extra={"na": w(ROLE, AssumeRolePolicyDocument=HUMAN)},
    note="Applies to Prowler service roles outside aws-service-role/; uses is_policy_public with check_cross_service_confused_deputy.")
def confused_deputy(item, index):
    if not is_service_role(item) or "aws-service-role" in get(item, "Arn", str):
        return "NOT_APPLICABLE", {"reason": "not a customer service role"}
    statements = statements_of(document_of(get(item, "AssumeRolePolicyDocument"), identity=False))
    public = is_policy_public(statements, account(index), check_cross_service_confused_deputy=True,
                              not_allowed_actions=["sts:AssumeRole", "sts:*"])
    return result(bool(public), confused_deputy_exposed=bool(public))


@install("aws.claude_a.iam.prowler_role_service_trust_bound_to_account", "iam_role", "Conditioned service-principal trust binds the source account (Prowler)",
    w(ROLE, AssumeRolePolicyDocument=SVC_TRUST),
    w(ROLE, AssumeRolePolicyDocument=doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole",
                                          "Condition": {"StringEquals": {"aws:SourceIp": "10.0.0.1"}}})),
    rows=[P + "iam_role_service_trust_restricts_source_to_account"], severity="high", category="exposure", control="AC-3",
    remediation="Pin aws:SourceAccount, aws:SourceArn (with an account) or aws:SourceOrgID in the service trust statement.",
    docs=[IAM_UG + "confused-deputy.html"], extra={"na": w(ROLE, AssumeRolePolicyDocument=OPEN_SVC)},
    note="Verbatim transcription of upstream helpers (claude_aws_a_lib_trust); Allow NotAction is MANUAL; plain unconditioned service trust has no finding.")
def service_trust(item, index):
    if "aws-service-role" in get(item, "Arn", str):
        return "NOT_APPLICABLE", {"reason": "service-linked role"}
    document = get(item, "AssumeRolePolicyDocument")
    if not isinstance(document, dict):
        raise Unavailable("trust policy is not an object")
    statements = statements_of(document)
    if any(isinstance(s, dict) and s.get("Effect") == "Allow" and "NotAction" in s for s in statements):
        return "MANUAL", {"reason": "Allow statement uses NotAction, which the source does not evaluate"}
    service = [s for s in statements if isinstance(s, dict) and s.get("Effect") == "Allow"
               and trust._grants_assume_role(s) and trust._trusts_service_principal(s)]
    if not service:
        return "NOT_APPLICABLE", {"reason": "no service-principal trust statement"}
    # The subject is a conditioned service trust. An unconditional service
    # principal remains outside this check even when the same statement also
    # names an AWS principal; the separate confused-deputy check handles it.
    in_scope = [s for s in service if trust._has_enforced_condition(s)]
    if not in_scope:
        return "NOT_APPLICABLE", {"reason": "plain unconditioned service trust (covered by the confused-deputy check)"}
    unscoped = [s for s in in_scope if not trust._prevents_confused_deputy(s)]
    return result(bool(unscoped), unscoped_statements=len(unscoped))


__all__ = ["expands_to", "effective_actions", "full_service_access", "admin_access", "marketplace_subscribe", "privilege_escalation",
           "list_of_objects", "attach", "CUSTOM_ARN"]
