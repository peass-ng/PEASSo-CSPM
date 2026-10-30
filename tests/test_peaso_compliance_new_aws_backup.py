"""Signed AWS Backup copy-rule fixtures over cached native plan details."""

import boto3
from botocore.stub import Stubber

from peaso.checks import evaluate_check
from peaso.collectors import aws, aws_b_services
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import compliance_new_aws_backup  # noqa: F401  (registration side effect)
from peaso.checks import CHECKS, evaluate_check


CHECK_ID = "aws_backup_cross_region_copy"
SCOPE = "123456789012/eu-west-1"
PLAN_ARN = "arn:aws:backup:eu-west-1:123456789012:plan:11111111-1111-1111-1111-111111111111"
SAME = "arn:aws:backup:eu-west-1:123456789012:backup-vault:local"
CROSS = "arn:aws:backup:eu-central-1:123456789012:backup-vault:remote"
CALLER = {"Account": "123456789012",
          "Arn": "arn:aws:sts::123456789012:assumed-role/Audit/peaso-read-only"}


def rule(*destinations):
    return {"RuleName": "daily", "CopyActions": [{"DestinationBackupVaultArn": arn}
                                           for arn in destinations]}


def plan(rules):
    return {"BackupPlanId": "11111111-1111-1111-1111-111111111111", "BackupPlanArn": PLAN_ARN,
            "Plan": {"collection_status": "collected", "BackupPlan": {"BackupPlanName": "reviewed",
                                                                 "Rules": rules}}}


def index(plans, *, status="collected", scope=SCOPE, callers=None):
    return {"context": {"provider": "aws", "scope": scope, "Account": "123456789012",
                        "metadata": {"caller_identities": [CALLER] if callers is None else callers}},
            "collections": {"backup_plan": [{"type": "backup_plan", "scope": scope,
                                               "status": status, "items": plans}]},
            "backup_plan": [{"type": "backup_plan", "scope": scope, "data": row} for row in plans]}


def evaluate(row, rows=None, **kwargs):
    return evaluate_check(CHECK_ID, row, index([row] if rows is None else rows, **kwargs))


def test_each_rule_needs_one_cross_region_destination():
    good = plan([rule(SAME, CROSS), rule(CROSS)])
    assert evaluate(good)[0] == "PASS"
    one_bad = plan([rule(CROSS), rule(SAME)])
    status, evidence = evaluate(one_bad)
    assert status == "FAIL" and evidence["missing_cross_region_rules"] == [2]
    assert evaluate(plan([rule(SAME)]))[0] == "FAIL"
    assert evaluate(plan([{"RuleName": "daily"}]))[0] == "FAIL"
    assert evaluate(plan([]))[0] == "UNKNOWN"


def test_missing_denied_malformed_and_partition_facts_stay_unknown():
    good = plan([rule(CROSS)])
    assert evaluate(good, status="partial")[0] == "UNKNOWN"
    denied = plan([rule(CROSS)])
    denied["Plan"] = {"collection_status": "denied"}
    assert evaluate(denied)[0] == "UNKNOWN"
    unknown_action = plan([{"RuleName": "daily", "CopyActions": [{}]}])
    assert evaluate(unknown_action)[0] == "UNKNOWN"
    untrusted = plan([rule("arn:aws-cn:backup:cn-north-1:123456789012:backup-vault:other")])
    assert evaluate(untrusted)[0] == "UNKNOWN"
    coverage = plan([{"RuleName": "daily", "_coverage": {"CopyActions": {"status": "denied"}}}])
    assert evaluate(coverage)[0] == "UNKNOWN"
    wrong_scope = plan([rule(CROSS)])
    assert evaluate(wrong_scope, scope="123456789012/us-east-1")[0] == "UNKNOWN"
    assert evaluate(good, callers=[])[0] == "UNKNOWN"
    mismatched = {"Account": "123456789012", "Arn": "arn:aws-cn:sts::123456789012:assumed-role/Audit/read"}
    assert evaluate(good, callers=[mismatched])[0] == "UNKNOWN"
    assert evaluate(good, callers=[CALLER, mismatched])[0] == "UNKNOWN"
    absent_rules = plan([rule(CROSS)])
    del absent_rules["Plan"]["BackupPlan"]["Rules"]
    assert evaluate(absent_rules)[0] == "UNKNOWN"


def test_definite_missing_rule_fails_despite_another_uncertain_rule():
    row = plan([rule(SAME), rule("unparseable")])
    assert evaluate(row)[0] == "FAIL"
    row = plan([rule(CROSS), rule("unparseable")])
    assert evaluate(row)[0] == "UNKNOWN"


def test_duplicate_or_detached_plan_source_cannot_pass():
    good = plan([rule(CROSS)])
    duplicate = plan([rule(SAME)])
    assert evaluate(good, [good, duplicate])[0] == "UNKNOWN"
    assert evaluate(good, [duplicate])[0] == "UNKNOWN"


def test_production_engine_uses_same_region_cached_plan_detail():
    row = plan([rule(CROSS)])
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "backup_plan", "scope": SCOPE,
        "service": "backup", "status": "collected", "items": [row]}],
        created_at="2026-10-12T00:00:00+00:00", metadata={"caller_identities": [CALLER]})
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CHECK_ID])
    findings = [finding for finding in report["findings"] if finding["check_id"] == CHECK_ID]
    assert len(findings) == 1 and findings[0]["status"] == "PASS"


def test_botocore_full_get_plan_omission_means_no_copy_action(monkeypatch):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert",
                            region_name="eu-west-1")
    client = session.client("backup", region_name="eu-west-1")
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: client)
    requests = aws.Requests({"max_calls": 2, "retry_attempts": 1})
    with Stubber(client) as stub:
        stub.add_response("list_backup_plans", {"BackupPlansList": [{"BackupPlanId": "plan-1",
            "BackupPlanArn": PLAN_ARN}]})
        stub.add_response("get_backup_plan", {"BackupPlan": {"BackupPlanName": "reviewed",
            "Rules": [{"RuleName": "daily", "TargetBackupVaultName": "local"}]},
            "BackupPlanId": "plan-1", "BackupPlanArn": PLAN_ARN}, {"BackupPlanId": "plan-1"})
        read = requests.pages(session, "backup", "eu-west-1", "list_backup_plans", "BackupPlansList")
        assert read.status == "collected"
        row = aws_b_services.ENRICHERS["backup_plan"](requests, session, "eu-west-1", read.items)[0]
        assert row["Plan"]["collection_status"] == "collected"
        assert "CopyActions" not in row["Plan"]["BackupPlan"]["Rules"][0]
        assert evaluate(row)[0] == "FAIL" and requests.calls == 2
        stub.assert_no_pending_responses()
