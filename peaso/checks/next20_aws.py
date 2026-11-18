"""Opt-in candidate predicates for two manifest-bound AWS proposals.

This file is portable to peaso/checks/; it reads only the supplied snapshot.
The enclosing private bundle is intentionally not imported by the registry.
"""
from __future__ import annotations

import re

from . import register, result, unknown
from .aws_backup_plan_frequency import required_frequency_hours, schedule_gap
from .compliance_new_aws_backup import _authority, _scoped_plans
from .facts import Unavailable, complete_items, get, list_of_objects, memoized


PROPOSED_SPEC_SHA256 = {
    "aws_backup_plan_rule_required_frequency": "a066b3c973571b3d1df8aa9871dba4858a8c9c4c707897639d99e116ec71d1ea",
    "aws_cis_elbv2_only_tls_listeners": "231d76c0f4c55afb1796004b6ab2070eff65c74e39b84e4ca4406585b52e3396",
}


def _signed(check_id, category, kind, title, severity, control):
    def decorate(fn):
        register(check_id, "aws", category if category in {"hardening", "exposure", "least_privilege", "iam_graph", "network"} else "hardening",
                 kind, title, severity, control, "Review the complete facts and source-bound policy before remediation.",
                 dependencies=[kind])(fn)
        return fn
    return decorate


_PLAN_ARN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):backup:([a-z0-9-]+):([0-9]{12}):(?:backup-plan|plan):[^:/]+$")
_ELB_ARN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):elasticloadbalancing:([a-z0-9-]+):([0-9]{12}):loadbalancer/(app|net|gwy)/[^:/]+/[^:/]+$")


@_signed("aws_backup_plan_rule_required_frequency", "compliance", "backup_plan",
         "AWS Backup plan rules meet the required backup frequency", "medium", "CP-9")
def backup_rule_frequency(item, index):
    arn = get(item, "BackupPlanArn", str)
    account, region, partition = memoized(index, ("aws_backup_scope_authority",), lambda: _authority(index))
    match = _PLAN_ARN.fullmatch(arn)
    if not match or (match.group(1), match.group(2), match.group(3)) != (partition, region, account):
        raise Unavailable("backup plan ARN outside audited scope")
    if memoized(index, ("aws_backup_plans",), lambda: _scoped_plans(index)).get(arn) != item:
        raise Unavailable("backup plan absent from complete scoped inventory")
    detail = get(item, "Plan", dict)
    if get(detail, "collection_status", str) != "collected":
        raise Unavailable("GetBackupPlan detail unavailable")
    if detail.get("BackupPlanArn", arn) != arn or ("BackupPlanId" in item and detail.get("BackupPlanId", item["BackupPlanId"]) != item["BackupPlanId"]):
        raise Unavailable("GetBackupPlan identity mismatch")
    rules = list_of_objects(get(detail, "BackupPlan.Rules", list))
    if not rules:
        raise Unavailable("backup plan rules absent")
    scope = account + "/" + region
    required = required_frequency_hours(index, scope)
    failed, unresolved, maximum_gaps = [], [], []
    for number, rule in enumerate(rules, 1):
        try:
            gap, form = schedule_gap(rule)
            maximum_gaps.append({"rule": number, "hours": gap, "form": form})
            if gap <= required:
                continue
            continuous = rule.get("EnableContinuousBackup", False)
            if type(continuous) is not bool:
                raise Unavailable("malformed continuous-backup flag")
            if continuous:
                unresolved.append(number)  # plan alone cannot prove resource-level PITR coverage
            else:
                failed.append(number)
        except Unavailable:
            unresolved.append(number)
    evidence = {"backup_plan_arn": arn, "scope": scope, "quantifier": "every_rule", "required_frequency_hours": required,
                "frequency_policy_source": "operator-supplied", "rule_count": len(rules), "failed_rules": failed,
                "unresolved_rules": unresolved, "maximum_gaps": maximum_gaps,
                "semantics": "configured schedule coverage only; no claim about completed backup jobs"}
    if failed:
        return result(True, **evidence)
    if unresolved:
        return unknown("one or more rule frequencies cannot be proven", **evidence)
    return result(False, **evidence)


def _lb_by_arn(index):
    account, region, partition = memoized(index, ("aws_backup_scope_authority",), lambda: _authority(index))
    scope = account + "/" + region
    envelopes = get(index, "collections.load_balancer", list)
    if len(envelopes) != 1:
        raise Unavailable("single load-balancer inventory unavailable")
    envelope = get({"envelope": envelopes[0]}, "envelope", dict)
    if envelope.get("type") != "load_balancer" or envelope.get("scope") != scope or envelope.get("status") not in ("collected", "empty"):
        raise Unavailable("load-balancer inventory incomplete or foreign")
    rows = complete_items(index, "load_balancer")
    declared = list_of_objects(get(envelope, "items", list))
    wrappers = list_of_objects(get(index, "load_balancer", list))
    if len(rows) != len(declared) or len(rows) != len(wrappers):
        raise Unavailable("load-balancer inventory cardinality mismatch")
    by_arn = {}
    for row in rows:
        arn = get(row, "LoadBalancerArn", str)
        match = _ELB_ARN.fullmatch(arn)
        if not match or (match.group(1), match.group(2), match.group(3)) != (partition, region, account) or arn in by_arn:
            raise Unavailable("load-balancer ARN foreign, malformed, or duplicated")
        by_arn[arn] = row
    for row in declared:
        arn = get(row, "LoadBalancerArn", str)
        if by_arn.get(arn) != row:
            raise Unavailable("declared load balancer differs from scoped wrapper")
    for wrapper in wrappers:
        if wrapper.get("type") != "load_balancer" or wrapper.get("scope") != scope or wrapper.get("provider", "aws") != "aws":
            raise Unavailable("foreign load-balancer wrapper")
    return by_arn


@_signed("aws_cis_elbv2_only_tls_listeners", "hardening", "load_balancer",
         "ALB and NLB listeners require TLS", "medium", "CM-6")
def elbv2_tls_listeners(item, index):
    arn = get(item, "LoadBalancerArn", str)
    if memoized(index, ("next20_aws_lb_by_arn",), lambda: _lb_by_arn(index)).get(arn) != item:
        raise Unavailable("load balancer absent from complete scoped inventory")
    match = _ELB_ARN.fullmatch(arn)
    kind = get(item, "Type", str)
    if not match or kind != {"app": "application", "net": "network", "gwy": "gateway"}[match.group(4)]:
        raise Unavailable("load-balancer ARN/type mismatch")
    if kind == "gateway":
        return "NOT_APPLICABLE", {"load_balancer_arn": arn, "reason": "gateway load balancer has no ALB/NLB listener"}
    listeners = get(item, "Listeners", dict)
    if get(listeners, "collection_status", str) not in ("collected", "empty"):
        raise Unavailable("DescribeListeners inventory incomplete")
    rows = list_of_objects(get(listeners, "items", list))
    if not rows:
        raise Unavailable("no listeners to assess")
    bad, unresolved, redirect_review, seen = [], [], [], set()
    for listener in rows:
        listener_arn = get(listener, "ListenerArn", str)
        if listener_arn in seen or not listener_arn.startswith(arn.replace("loadbalancer/", "listener/") + "/"):
            raise Unavailable("listener identity foreign or duplicated")
        seen.add(listener_arn)
        protocol = get(listener, "Protocol", str)
        if (kind, protocol) in (("application", "HTTPS"), ("network", "TLS")):
            continue
        if (kind, protocol) == ("network", "TCP"):
            bad.append(listener_arn)
        elif (kind, protocol) == ("application", "HTTP"):
            actions = list_of_objects(get(listener, "DefaultActions", list))
            redirects = [action for action in actions if get(action, "Type", str) == "redirect"]
            if redirects:
                config = get(redirects[-1], "RedirectConfig", dict)
                target = get(config, "Protocol", str)
                if target == "HTTPS":
                    redirect_review.append(listener_arn)
                elif target in {"HTTP", "#{protocol}"}:
                    bad.append(listener_arn)
                else:
                    unresolved.append(listener_arn)
            else:
                bad.append(listener_arn)
        else:
            unresolved.append(listener_arn)
    evidence = {"load_balancer_arn": arn, "plaintext_listener_arns": bad, "unresolved_listener_arns": unresolved,
                "scope": get(index, "context.scope", str), "listener_count": len(rows)}
    if bad:
        return result(True, **evidence)
    if unresolved:
        return unknown("listener protocol or redirect target is unrecognized", **evidence)
    if redirect_review:
        return "MANUAL", dict(evidence, redirect_listener_arns=redirect_review,
                              reason="HTTP listeners redirect to HTTPS; owner approval of a plaintext redirect endpoint is required by this control")
    return result(False, **evidence)


