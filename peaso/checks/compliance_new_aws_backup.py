"""Signed AWS Backup cross-Region copy configuration predicate."""
from __future__ import annotations

import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, memoized, optional
from .fixtures import CASES


CHECK_ID = "aws_backup_cross_region_copy"
_PLAN_ARN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):backup:([a-z0-9-]+):([0-9]{12}):(?:backup-plan|plan):[^:/]+$")
_VAULT_ARN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):backup:([a-z0-9-]+):([0-9]{12}):backup-vault:[^:]+$")
_REGIONAL_SCOPE = re.compile(r"^([0-9]{12})/([a-z0-9-]+)$")
_CALLER_ARN = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):[^:]+:[^:]*:([0-9]{12}):.+$")


def _authority(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS scope authority unavailable")
    scope = _REGIONAL_SCOPE.fullmatch(get(context, "scope", str))
    account = get(context, "Account", str)
    if not scope or account != scope.group(1):
        raise Unavailable("audited backup plan account or Region unavailable")
    callers = get(context, "metadata.caller_identities", list)
    partitions = set()
    for caller in callers:
        if not isinstance(caller, dict):
            raise Unavailable("malformed caller identity")
        if caller.get("Account") != account:
            continue
        arn = _CALLER_ARN.fullmatch(get(caller, "Arn", str))
        if arn is None or arn.group(2) != account:
            raise Unavailable("caller ARN does not prove audited account and partition")
        partitions.add(arn.group(1))
    if len(partitions) != 1:
        raise Unavailable("audited AWS partition unavailable or ambiguous")
    return account, scope.group(2), partitions.pop()


def _scoped_plans(index):
    plans = complete_items(index, "backup_plan")
    by_arn = {}
    for plan in plans:
        arn = get(plan, "BackupPlanArn", str)
        if arn in by_arn:
            raise Unavailable("duplicate backup plan ARN in scoped inventory")
        by_arn[arn] = plan
    return by_arn


@register(CHECK_ID, "aws", "hardening", "backup_plan",
          "Every AWS Backup rule declares a cross-Region copy destination", "high", "CP-9",
          "Add an owner-approved cross-Region copy action to every applicable backup rule and verify its destination vault ARN.",
          dependencies=["backup_plan"])
def cross_region_copy(item, index):
    arn = get(item, "BackupPlanArn", str)
    account, region, partition = memoized(index, ("aws_backup_scope_authority",), lambda: _authority(index))
    source = _PLAN_ARN.fullmatch(arn)
    if not source or source.group(1) != partition or source.group(2) != region or source.group(3) != account:
        raise Unavailable("backup plan ARN does not match audited regional account scope")
    scoped_plan = memoized(index, ("aws_backup_plans",), lambda: _scoped_plans(index)).get(arn)
    if scoped_plan is None or scoped_plan != item:
        raise Unavailable("backup plan absent from complete scoped inventory")
    detail = get(item, "Plan", dict)
    if get(detail, "collection_status", str) != "collected":
        raise Unavailable("full GetBackupPlan response unavailable")
    rules = list_of_objects(get(detail, "BackupPlan.Rules", list))
    if not rules:
        raise Unavailable("backup plan has no valid rule to assess")
    missing, uncertain = [], []
    for number, rule in enumerate(rules, 1):
        try:
            actions = list_of_objects(optional(rule, "CopyActions", [], list))
        except Unavailable:
            uncertain.append(number)
            continue
        has_cross_region, untrusted_destination = False, False
        for action in actions:
            try:
                destination = get(action, "DestinationBackupVaultArn", str)
            except Unavailable:
                untrusted_destination = True
                continue
            vault = _VAULT_ARN.fullmatch(destination)
            if not vault or vault.group(1) != partition:
                untrusted_destination = True
            elif vault.group(2) != region:
                has_cross_region = True
        if has_cross_region:
            continue
        if untrusted_destination:
            uncertain.append(number)
        else:
            missing.append(number)
    if missing:
        return result(True, backup_plan_arn=arn, rule_count=len(rules),
                      missing_cross_region_rules=missing, uncertain_rules=uncertain)
    if uncertain:
        return unknown("backup copy destination ARN unavailable or malformed",
                       backup_plan_arn=arn, rule_count=len(rules), uncertain_rules=uncertain)
    return result(False, backup_plan_arn=arn, rule_count=len(rules),
                  cross_region_rules=len(rules))


_plan_arn = "arn:aws:backup:eu-west-1:123456789012:plan:11111111-1111-1111-1111-111111111111"
_remote_vault = "arn:aws:backup:eu-central-1:123456789012:backup-vault:remote"
_local_vault = "arn:aws:backup:eu-west-1:123456789012:backup-vault:local"


def _backup_plan(destination):
    return {"BackupPlanArn": _plan_arn, "Plan": {"collection_status": "collected",
        "BackupPlan": {"Rules": [{"RuleName": "daily", "CopyActions": [
            {"DestinationBackupVaultArn": destination}]}]}}}


def _backup_index(row):
    scope = "123456789012/eu-west-1"
    return {"context": {"provider": "aws", "scope": scope, "Account": "123456789012",
        "metadata": {"caller_identities": [{"Account": "123456789012", "Arn":
            "arn:aws:sts::123456789012:assumed-role/Audit/peaso-read-only"}]}},
        "collections": {"backup_plan": [{"type": "backup_plan", "scope": scope,
            "status": "collected", "items": [row]}]},
        "backup_plan": [{"type": "backup_plan", "scope": scope, "data": row}]}


_backup_pass, _backup_fail = _backup_plan(_remote_vault), _backup_plan(_local_vault)
_backup_unknown = _backup_plan(_remote_vault)
_backup_unknown["Plan"] = {"collection_status": "denied"}
CASES[CHECK_ID] = {"pass": _backup_pass, "pass_index": _backup_index(_backup_pass),
    "fail": _backup_fail, "fail_index": _backup_index(_backup_fail),
    "unknown": _backup_unknown, "unknown_index": _backup_index(_backup_unknown),
    "index": _backup_index(_backup_pass)}
