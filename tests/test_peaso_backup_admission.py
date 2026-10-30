"""Public source-grounded AWS Backup frequency and retention admission fixture."""
from __future__ import annotations


import copy
import hashlib
import json
import math
from pathlib import Path

import pytest


from peaso.checks import CHECKS, aws_backup_plan_frequency as backup

from peaso.checks.fixtures import CASES
from peaso.collectors import aws_policy
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot, validate


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/compliance-ledgers"
PACK = ROOT / "peaso/rulepacks"
CID = backup.CHECK_ID
FREQ, PCI = "aws_backup_plan_rule_required_frequency", "aws.pci.backup.plan_frequency_retention"
KEYS = ("id", "provider", "resource_kind", "data_source", "predicate", "severity", "category", "title", "description", "remediation_hint")
ACCOUNT, REGION = "123456789012", "eu-west-1"
SCOPE = ACCOUNT + "/" + REGION
PLAN_ID = "22222222-2222-2222-2222-222222222222"
ARN = f"arn:aws:backup:{REGION}:{ACCOUNT}:plan:{PLAN_ID}"
DAILY = "cron(0 5 ? * * *)"
STEAMPIPE_FRAMEWORKS = sorted("aws-compliance.benchmark." + name for name in (
    "acsc_essential_eight", "cisa_cyber_essentials", "fedramp_low_rev_4", "fedramp_moderate_rev_4", "ffiec",
    "gxp_21_cfr_part_11", "gxp_eu_annex_11", "hipaa_final_omnibus_security_rule_2013", "hipaa_security_rule_2003",
    "nist_800_171_rev_2", "nist_csf", "nist_csf_v2", "nydfs_23", "pci_dss_v321", "pci_dss_v40", "rbi_itf_nbfc", "soc_2"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def spec_digest(spec):
    return sha(json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def check():
    matches = [item for item in CHECKS if item.id == CID]
    assert len(matches) == 1
    return matches[0]


def rule(schedule=DAILY, days=35, **extra):
    out = {"RuleName": "r", "TargetBackupVaultName": "vault", **extra}
    if schedule is not None:
        out["ScheduleExpression"] = schedule
    if days is not None:
        out["Lifecycle"] = {"DeleteAfterDays": days}
    return out


def plan(*rules, arn=ARN, **detail):
    return {"BackupPlanId": PLAN_ID, "BackupPlanArn": arn, "BackupPlanName": "p",
            "Plan": {"collection_status": "collected", "BackupPlanId": PLAN_ID, "BackupPlanArn": arn,
                     "BackupPlan": {"BackupPlanName": "p", "Rules": list(rules)}, **detail}}


def policy(hours=24, applies=(SCOPE,), **override):
    return {"status": "collected", "source": "operator-supplied", "basis": aws_policy.BASIS, "applies_to": list(applies),
            "required_frequency_hours": hours, "unmatched_scopes": [], **override}


def index(item, body="default", *, callers=None, status="collected", scope=SCOPE):
    metadata = {"caller_identities": callers if callers is not None else
                [{"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Audit/peaso-read-only"}]}
    if body == "default":
        body = policy()
    if body is not None:
        metadata["compliance_policy"] = {"aws_backup_plan": body}
    return {"context": {"provider": "aws", "scope": scope, "Account": scope.split("/")[0], "metadata": metadata},
            "collections": {"backup_plan": [{"type": "backup_plan", "scope": scope, "status": status,
                                             "items": [] if status != "collected" else [item]}]},
            "backup_plan": [{"type": "backup_plan", "scope": scope, "data": item}]}


def status(item, idx=None):
    return check().evaluate(item, index(item) if idx is None else idx)


# ------------------------------------------------------------------ registration and imports


def test_generic_behavior_fixture_contract():
    item, cases = check(), CASES[CID]
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN")):
        data, scoped = copy.deepcopy(cases[name]), copy.deepcopy(cases[name + "_index"])
        before, before_index = copy.deepcopy(data), copy.deepcopy(scoped)
        assert item.evaluate(data, scoped)[0] == expected
        assert data == before and scoped == before_index
    for value in ({}, None, {"collection_status": "denied"}):
        assert item.evaluate(value, cases["index"])[0] == "UNKNOWN"
    assert item.evaluate(cases["pass"], cases["index"])[0] == "UNKNOWN"  # fixture index has no operator policy


@pytest.mark.parametrize("collection_status,expected", [("denied", "DENIED"), ("unknown", "UNKNOWN"), ("malformed", "UNKNOWN"), ("empty", "EMPTY")])
def test_unavailable_inventory_never_passes(collection_status, expected):
    snapshot = make_snapshot("aws", ["test-scope"], [{"type": "backup_plan", "scope": "test-scope", "service": "test",
                                                     "status": collection_status, "items": []}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID])
    assert report["findings"][0]["status"] == expected and "PASS" not in report["stats"]["by_status"]


# ------------------------------------------------------------------ signed spec, supersession and provenance


# ------------------------------------------------------------------ framework links and compiled packs


# ------------------------------------------------------------------ evaluator semantics (at least one rule)

@pytest.mark.parametrize("rules,hours,expected", [
    ((rule(days=7), rule(days=None)), 24, "PASS"),                      # never-expiring daily rule qualifies
    ((rule(days=34), rule(days=35)), 24, "PASS"),                       # 35 days is the inclusive minimum
    ((rule("cron(0 5 ? * MON *)", 365), rule(DAILY, 35)), 24, "PASS"),  # one qualifying rule is enough
    ((rule(DAILY, 35),), 24, "PASS"),                                   # gap equal to the requirement qualifies
    ((rule("cron(0/30 * ? * * *)", 35),), 0.5, "PASS"),                 # fractional operator interval
    ((rule(DAILY, 35, ScheduleExpressionTimezone="Etc/GMT-14"),), 24, "PASS"),  # fixed-offset zone
    ((rule(DAILY, 35), rule("rate(1 day)", 35)), 24, "PASS"),           # proven qualifier outweighs an unresolved rule
    ((rule(DAILY, 34),), 24, "FAIL"),                                   # retention miss
    ((rule("cron(0 5 ? * MON *)", 35),), 24, "FAIL"),                   # frequency miss
    ((rule(DAILY, 34), rule("cron(0 5 ? * MON *)", 90)), 24, "FAIL"),   # every rule misses something
    ((rule(DAILY, 35),), 23.9, "FAIL"),
    ((rule("cron(0 5 29 2 ? *)", 35),), 744, "FAIL"),                   # leap-day cron: 2921-day exact gap
    ((rule("cron(0 5 31 * ? *)", 35),), 744, "FAIL"),                   # 31st: 61-day exact gap
    ((rule("cron(0 5 1 * ? *)", 35),), 744, "PASS"),                    # monthly 1st: 31-day gap fits 744 hours
    ((), 24, "FAIL"),                                                   # no rule can satisfy the requirement
    ((rule("rate(1 day)", 35),), 24, "UNKNOWN"),                        # rate() is not a documented Backup form
    ((rule(DAILY, 35, ScheduleExpressionTimezone="America/New_York"),), 24, "UNKNOWN"),
    ((rule("cron(0 5 L * ? *)", 35),), 744, "UNKNOWN"),
    ((rule("cron(0 5 ? * * 2030)", 35),), 24, "UNKNOWN"),
    ((rule("cron(0 5 ? * FRI-MON *)", 35),), 168, "UNKNOWN"),          # wrapping range
    ((rule(DAILY, None, Lifecycle={"DeleteAfterEvent": "DELETED"}),), 24, "UNKNOWN"),
    ((rule("cron(0 5 ? * MON *)", 35, EnableContinuousBackup=True),), 24, "UNKNOWN"),  # PITR coverage not proven
    ((rule(DAILY, 34), rule("rate(1 day)", 35)), 24, "UNKNOWN"),       # no proven qualifier, one unresolved
    ((rule(None, 35),), 24, "UNKNOWN"),                                 # missing schedule is never defaulted
    ((rule(DAILY, 0),), 24, "UNKNOWN"),                                 # invalid DeleteAfterDays
    ((rule(DAILY, -1),), 24, "UNKNOWN"),                                # removal sentinel needs verified GetBackupPlan semantics
    ((rule(DAILY, True),), 24, "UNKNOWN"),                              # bool is not an int day count
])
def test_rule_quantifier_and_bounds(rules, hours, expected):
    item = plan(*rules)
    outcome, evidence = status(item, index(item, policy(hours)))
    assert outcome == expected, evidence
    if outcome in ("PASS", "FAIL"):
        assert evidence["quantifier"] == "at_least_one_rule" and evidence["required_retention_days"] == 35
        assert evidence["required_frequency_hours"] == hours and evidence["frequency_policy_source"] == "operator-supplied"
        assert evidence["semantics"].startswith("configured schedule and lifecycle coverage only")


def test_continuous_rule_that_meets_by_schedule_still_qualifies():
    item = plan(rule(DAILY, 35, EnableContinuousBackup=True))
    assert status(item)[0] == "PASS"


def test_denied_rule_fields_are_unresolved_not_failures():
    item = plan(rule(DAILY, 35))
    item["Plan"]["BackupPlan"]["Rules"][0]["_coverage"] = {"Lifecycle": {"status": "denied"}}
    assert status(item)[0] == "UNKNOWN"
    item = plan(rule(DAILY, 35), rule(DAILY, 35))
    item["Plan"]["BackupPlan"]["Rules"][1]["_coverage"] = {"ScheduleExpression": {"status": "denied"}}
    assert status(item)[0] == "PASS"


def test_calendar_cache_stays_bounded():
    backup.max_day_gap.cache_clear()
    item = plan(*(rule(f"cron(0 5 {day} * ? *)", 35) for day in range(1, 29)))
    assert status(item, index(item, policy(744)))[0] == "PASS"
    info = backup.max_day_gap.cache_info()
    assert info.maxsize == 256 and info.currsize <= 28


# ------------------------------------------------------------------ operator policy input at evaluation

@pytest.mark.parametrize("body", [
    None,                                               # no declaration: never defaulted
    policy(status="unknown"),
    policy(source="observed"),
    policy(applies=("999999999999/eu-west-1",)),        # does not cover this scope
    policy(applies=("*",)),                             # no wildcard coverage
    policy(hours=True), policy(hours=0), policy(hours=-1), policy(hours=745), policy(hours=math.nan),
    policy(hours=math.inf), policy(hours="24"), policy(hours=None),
    "not-an-object",
])
def test_missing_or_invalid_policy_is_unknown(body):
    item = plan(rule(DAILY, 35))
    outcome, evidence = status(item, index(item, body))
    assert outcome == "UNKNOWN", evidence


def test_policy_without_applies_to_is_unknown():
    item = plan(rule(DAILY, 35))
    body = policy()
    del body["applies_to"]
    assert status(item, index(item, body))[0] == "UNKNOWN"


# ------------------------------------------------------------------ scope and identity errors

@pytest.mark.parametrize("arn", [
    f"arn:aws:backup:us-east-1:{ACCOUNT}:plan:{PLAN_ID}",          # other Region
    f"arn:aws:backup:{REGION}:111111111111:plan:{PLAN_ID}",         # other account
    f"arn:aws-cn:backup:{REGION}:{ACCOUNT}:plan:{PLAN_ID}",         # other partition
    f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{PLAN_ID}",    # not a plan
])
def test_foreign_or_malformed_plan_arn_is_unknown(arn):
    item = plan(rule(DAILY, 35), arn=arn)
    assert status(item)[0] == "UNKNOWN"


def test_both_documented_plan_arn_spellings_are_accepted():
    item = plan(rule(DAILY, 35), arn=f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:{PLAN_ID}")
    assert status(item)[0] == "PASS"


def test_inventory_identity_and_detail_errors_are_unknown():
    item = plan(rule(DAILY, 35))
    other = copy.deepcopy(item)
    other["BackupPlanName"] = "different"
    assert status(item, index(other))[0] == "UNKNOWN"                       # absent from complete scoped inventory
    assert status(item, index(item, status="partial"))[0] == "UNKNOWN"      # incomplete inventory
    assert status(item, index(item, callers=[]))[0] == "UNKNOWN"            # no audited partition
    for detail in ({"collection_status": "denied"}, "malformed"):
        broken = dict(item, Plan=detail)
        assert status(broken)[0] == "UNKNOWN"
    deleted = plan(rule(DAILY, 35), DeletionDate="2026-01-01T00:00:00Z")
    assert status(deleted)[0] == "UNKNOWN"
    mismatched = plan(rule(DAILY, 35))
    mismatched["Plan"]["BackupPlanArn"] = f"arn:aws:backup:{REGION}:{ACCOUNT}:plan:other"
    assert status(mismatched)[0] == "UNKNOWN"


# ------------------------------------------------------------------ collector ingestion (operator declaration)

def test_collector_records_a_validated_declaration_only():
    declared = aws_policy.backup_plan_policy({"compliance_policy": {"aws_backup_plan": {
        "applies_to": ["123456789012/us-east-1", SCOPE], "required_frequency_hours": 24}}})
    assert declared == {"status": "collected", "source": "operator-supplied", "basis": aws_policy.BASIS,
                        "applies_to": [SCOPE, "123456789012/us-east-1"], "required_frequency_hours": 24}
    bound = aws_policy.bind_backup_plan_policy(declared, [SCOPE])
    assert bound["unmatched_scopes"] == ["123456789012/us-east-1"] and bound["applies_to"] == declared["applies_to"]
    from peaso.collectors.aws import _safe
    assert _safe({"compliance_policy": {"aws_backup_plan": bound}}) == {"compliance_policy": {"aws_backup_plan": bound}}
    assert aws_policy.backup_plan_policy({}) is None
    assert aws_policy.backup_plan_policy({"compliance_policy": {"other": {}}}) is None


@pytest.mark.parametrize("options", [
    {"compliance_policy": []},
    {"compliance_policy": {"aws_backup_plan": []}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE]}}},
    {"compliance_policy": {"aws_backup_plan": {"required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE], "required_frequency_hours": 24, "required_retention_days": 35}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE, SCOPE], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": ["*"], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [ACCOUNT], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [[SCOPE]], "required_frequency_hours": 24}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE] * 2 + ["x"] * 999, "required_frequency_hours": 24}}},
    *({"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE], "required_frequency_hours": value}}}
      for value in (True, 0, -1, 745, math.nan, math.inf, "24", None)),
])
def test_collector_rejects_malformed_declarations(options):
    with pytest.raises(ValueError):
        aws_policy.backup_plan_policy(options)


# ------------------------------------------------------------------ end to end through the engine

def snapshot_for(plans_by_scope, body):
    collections = [{"type": "backup_plan", "scope": scope, "service": "backup", "status": "collected", "items": items}
                   for scope, items in plans_by_scope.items()]
    metadata = {"caller_identities": [{"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Audit/peaso-read-only"}]}
    if body is not None:
        metadata["compliance_policy"] = {"aws_backup_plan": body}
    return make_snapshot("aws", sorted(plans_by_scope), collections, created_at="2026-10-13T00:00:00+00:00", metadata=metadata)


def findings(snapshot):
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID])
    return sorted(report["findings"], key=lambda row: (row["scope"], row["resource_id"]))


def test_engine_evaluates_each_scope_with_its_own_declaration_without_duplicates():
    east = "123456789012/us-east-1"
    east_arn = f"arn:aws:backup:us-east-1:{ACCOUNT}:plan:{PLAN_ID}"
    snapshot = snapshot_for({SCOPE: [plan(rule(DAILY, 35))], east: [plan(rule(DAILY, 35), arn=east_arn)]}, policy(24, (SCOPE,)))
    rows = findings(snapshot)
    assert {row["scope"]: row["status"] for row in rows} == {east: "UNKNOWN", SCOPE: "PASS"}
    assert len({row["id"] for row in rows}) == 2 and rows == findings(snapshot)  # deterministic, deduplicated
    assert all(row["check_id"] == CID for row in rows)
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID])
    assert report["check_meta"][CID]["category"] == "hardening"


def test_engine_without_declaration_is_unknown_and_declaration_is_sealed():
    without = snapshot_for({SCOPE: [plan(rule(DAILY, 35))]}, None)
    assert [row["status"] for row in findings(without)] == ["UNKNOWN"]
    declared = snapshot_for({SCOPE: [plan(rule(DAILY, 35))]}, policy())
    assert declared["snapshot_id"] != without["snapshot_id"]
    tampered = copy.deepcopy(declared)
    tampered["metadata"]["compliance_policy"]["aws_backup_plan"]["required_frequency_hours"] = 744
    with pytest.raises(ValueError):
        validate(tampered)
