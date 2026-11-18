"""Captured-time/applicability/bucket-join truth cases from pinned CloudTrail."""
import copy

import pytest

from peaso.checks import CHECKS, aws_a_cloudtrail
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture

REGISTRY = {c.id: c for c in CHECKS if c.id in aws_a_cloudtrail.NATIVE_IDS}


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_cloudtrail_predicate_states_and_immutability(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("not_applicable", "NOT_APPLICABLE")):
        if state not in cases:
            continue
        item = copy.deepcopy(cases[state])
        index = copy.deepcopy(cases.get(state + "_index", cases.get("index", {})))
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == expected, (cid, state)
        assert (item, index) == before
    assert check.evaluate({"collection_status": "denied"}, cases.get("index", {}))[0] == "UNKNOWN"


@pytest.mark.parametrize("stamp,expected", [("2026-10-09T12:00:00+00:00", "PASS"), ("2026-10-09T11:59:59+00:00", "FAIL"), ("2026-10-10T13:00:00+00:00", "UNKNOWN"), ("2026-10-09T12:00:00", "UNKNOWN")])
def test_delivery_uses_captured_clock_and_exact_greater_than_24h_boundary(stamp, expected):
    item = {"Name": "audit", "Status": {"LatestCloudWatchLogsDeliveryTime": stamp}}
    index = {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}
    assert REGISTRY["aws.a.cloudtrail.cloudwatch_delivery_24h"].evaluate(item, index)[0] == expected


def test_delivery_missing_known_omission_denial_and_clock_are_distinct():
    check = REGISTRY["aws.a.cloudtrail.cloudwatch_delivery_24h"]
    assert check.evaluate({"Name": "audit", "Status": {"collection_status": "collected"}}, {})[0] == "FAIL"
    assert check.evaluate({"Name": "audit", "Status": {}}, {})[0] == "UNKNOWN"
    assert check.evaluate({"Name": "audit", "Status": {"collection_status": "denied"}}, {})[0] == "UNKNOWN"
    assert check.evaluate({"Name": "audit", "Status": {"LatestCloudWatchLogsDeliveryTime": "2026-10-09T12:00:00+00:00"}}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", ["aws.a.cloudtrail.bucket_mfa_delete", "aws.a.cloudtrail.bucket_access_logging"])
def test_out_of_scope_bucket_requires_owner_account_review(cid):
    check = REGISTRY[cid]
    item = {"Name": "audit", "Status": {"IsLogging": True}, "S3BucketName": "external-bucket"}
    context = {"context": {"scope": "123456789012/us-east-1"}}
    assert check.evaluate(item, {**scope_fixture("bucket", []), **context})[0] == "MANUAL"
    assert check.evaluate(item, {**scope_fixture("bucket", [], status="denied"), **context})[0] == "UNKNOWN"
    index = copy.deepcopy(CASES[cid]["index"])
    envelope = index["collections"]["bucket"][0]
    envelope["account_id"] = "999999999999"
    envelope["scope"] = "999999999999/us-east-1"
    assert check.evaluate(CASES[cid]["pass"], index)[0] == "UNKNOWN"


def test_insights_applicability_and_known_absence_are_not_confused_with_denial():
    check = REGISTRY["aws.a.cloudtrail.insights_logging_trail"]
    assert check.evaluate({"Status": {"IsLogging": False}}, {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"Status": {"IsLogging": True}, "InsightSelectors": {"collection_status": "empty", "absent": True}}, {})[0] == "FAIL"
    assert check.evaluate({"Status": {"IsLogging": True}, "InsightSelectors": {"collection_status": "denied"}}, {})[0] == "UNKNOWN"
