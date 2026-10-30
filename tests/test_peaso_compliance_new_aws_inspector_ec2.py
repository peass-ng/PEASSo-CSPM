"""Source-bound Inspector EC2 severity and coverage fixtures; no AWS calls."""
from __future__ import annotations

import copy

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_aws_inspector_ec2 as rule
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import CHECKS, evaluate_check


SCOPE = "123456789012/us-east-1"


def finding(*, severity="HIGH", resource_type="AWS_EC2_INSTANCE", **fields):
    return {"findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/ffffffffffffffffffffffffffffffff",
            "awsAccountId": "123456789012", "status": "ACTIVE", "severity": severity,
            "resources": [{"type": resource_type, "id": "i-0123456789abcdef0"}], **fields}


def account(*, account_status="ENABLED", ec2_status="ENABLED"):
    return {"id": "inspector2/123456789012/us-east-1", "accountId": "123456789012",
            "State": {"status": account_status}, "ResourceState": {"ec2": {"status": ec2_status}}}


def scoped(findings, accounts=None, *, finding_status="collected", account_status="collected", scope=SCOPE):
    accounts = [account()] if accounts is None else accounts
    return {"context": {"provider": "aws", "scope": scope,
                        "created_at": "2026-10-12T00:00:00+00:00"},
            "collections": {
                "inspector2_finding": [{"type": "inspector2_finding", "scope": scope,
                                        "status": finding_status, "items": findings}],
                "inspector2_account_status": [{"type": "inspector2_account_status", "scope": scope,
                                               "status": account_status, "items": accounts}]},
            "inspector2_finding": [{"type": "inspector2_finding", "scope": scope, "data": row}
                                   for row in findings],
            "inspector2_account_status": [{"type": "inspector2_account_status", "scope": scope,
                                           "data": row} for row in accounts]}


def verdict(index):
    return evaluate_check(rule.CHECK_ID, {}, index)


def test_complete_active_ec2_severity_and_coverage():
    assert verdict(scoped([]))[0] == "PASS"
    assert verdict(scoped([finding(severity="LOW")]))[0] == "PASS"
    assert verdict(scoped([finding(severity="HIGH", resource_type="AWS_ECR_CONTAINER_IMAGE")]))[0] == "PASS"
    status, evidence = verdict(scoped([finding()]))
    assert status == "FAIL" and evidence["active_high_critical_ec2_findings"] == [finding()["findingArn"]]
    assert verdict(scoped([finding(severity="CRITICAL")]))[0] == "FAIL"
    assert verdict(scoped([], [account(ec2_status="DISABLED")]))[0] == "UNKNOWN"
    assert verdict(scoped([], [account(account_status="DISABLED")]))[0] == "UNKNOWN"


def test_partial_denied_malformed_and_foreign_facts_are_unknown():
    assert verdict(scoped([], finding_status="partial"))[0] == "UNKNOWN"
    assert verdict(scoped([], finding_status="denied"))[0] == "UNKNOWN"
    assert verdict(scoped([], account_status="denied"))[0] == "UNKNOWN"
    assert verdict(scoped([], []))[0] == "UNKNOWN"
    assert verdict(scoped([], [account(), account()]))[0] == "UNKNOWN"
    assert verdict(scoped([], [account()], scope="123456789012/eu-west-1"))[0] == "UNKNOWN"
    assert verdict(scoped([finding(status="SUPPRESSED")]))[0] == "UNKNOWN"
    assert verdict(scoped([finding(resources=[])]))[0] == "UNKNOWN"
    assert verdict(scoped([finding(severity="FUTURE")]))[0] == "UNKNOWN"
    assert verdict(scoped([finding(awsAccountId="000000000000")]))[0] == "UNKNOWN"
    assert verdict(scoped([finding(findingArn="arn:aws:inspector2:eu-west-1:123456789012:finding/ffffffffffffffffffffffffffffffff")]))[0] == "UNKNOWN"
    missing_clock = scoped([])
    missing_clock["context"].pop("created_at")
    assert verdict(missing_clock)[0] == "UNKNOWN"


def test_immutable_evaluation_and_production_scoped_snapshot():
    index = scoped([finding(severity="MEDIUM")])
    original = copy.deepcopy(index)
    assert verdict(index)[0] == "PASS"
    assert verdict(index)[0] == "PASS"
    assert index == original
    snapshot = make_snapshot("aws", [SCOPE], [
        {"type": "inspector2_finding", "scope": SCOPE, "service": "inspector2",
         "status": "collected", "items": [finding()]},
        {"type": "inspector2_account_status", "scope": SCOPE, "service": "inspector2",
         "status": "collected", "items": [account()]},
    ], created_at="2026-10-12T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[rule.CHECK_ID])
    assert [f["status"] for f in report["findings"] if f["check_id"] == rule.CHECK_ID] == ["FAIL"]
