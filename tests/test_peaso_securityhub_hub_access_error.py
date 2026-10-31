"""DescribeHub SDK errors keep their native provenance through registered checks."""
from __future__ import annotations

import boto3
import pytest
from botocore.exceptions import ReadTimeoutError
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.collectors.aws_facts_cb_ca import FETCHERS
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
CHECKS = (
    "aws.claude_a.securityhub.enabled_with_standard_or_integration",
    "aws.claude_a.securityhub.prowler_delegated_admin_region",
    "aws.gap.securityhub.region_hub_enabled",
    "aws_securityhub_no_critical_findings",
)


def _native_decisions(read):
    collection = {"type": "securityhub_hub", "scope": SCOPE, "service": "securityhub",
                  "status": read.status, "items": read.items, "account_id": ACCOUNT, "global": False}
    if read.error:
        collection["error"] = read.error
    snapshot = make_snapshot("aws", [SCOPE], [collection])
    result = evaluate_snapshot(snapshot, checks=list(CHECKS))
    findings = {row["check_id"]: row["status"] for row in result["findings"]}
    assert set(findings) == set(CHECKS)
    return collection, findings


@pytest.mark.parametrize("code,http,expected", [
    ("InvalidAccessException", 401, "unknown"),
    ("AccessDeniedException", 403, "denied"),
    ("ResourceNotFoundException", 404, "empty"),
    ("LimitExceededException", 429, "unknown"),
])
def test_describe_hub_sdk_error_to_native_collection_and_engine(code, http, expected):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    client = session.client("securityhub", region_name=REGION)
    with Stubber(client) as stub:
        stub.add_client_error("describe_hub", service_error_code=code, http_status_code=http)
        requests = aws.Requests({"retry_attempts": 1})
        requests.client = lambda _session, service, region: client
        read = FETCHERS["securityhub_hub"](requests, session, REGION, ACCOUNT)
        stub.assert_no_pending_responses()
    assert read.status == expected and read.items == []
    assert read.error == ({"code": code} if expected == "empty" else
                          {"code": code, "operation": "describe_hub"})
    collection, findings = _native_decisions(read)
    assert collection["status"] == expected and collection["error"]["code"] == code
    if expected != "empty":
        assert set(findings.values()) <= {"UNKNOWN", "DENIED"}, findings
    else:
        # A documented missing hub is allowed to drive absence-based decisions.
        assert findings["aws.gap.securityhub.region_hub_enabled"] == "FAIL"


def test_describe_hub_transport_timeout_to_native_collection_and_engine():
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    client = session.client("securityhub", region_name=REGION)
    def timeout(operation, parameters):
        assert operation == "DescribeHub" and parameters == {}
        raise ReadTimeoutError(endpoint_url="https://securityhub.us-east-1.amazonaws.com")
    client._make_api_call = timeout
    requests = aws.Requests({"retry_attempts": 1})
    requests.client = lambda _session, service, region: client
    read = FETCHERS["securityhub_hub"](requests, session, REGION, ACCOUNT)
    assert read.status == "timeout" and read.items == []
    collection, findings = _native_decisions(read)
    assert collection["status"] == "timeout"
    assert set(findings.values()) <= {"UNKNOWN"}, findings


def test_describe_hub_success_collects_hub_and_registered_engine_can_pass():
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    client = session.client("securityhub", region_name=REGION)
    arn = f"arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default"
    with Stubber(client) as stub:
        stub.add_response("describe_hub", {"HubArn": arn, "SubscribedAt": "2026-10-18T00:00:00Z"}, {})
        stub.add_response("get_enabled_standards", {"StandardsSubscriptions": [{
            "StandardsArn": f"arn:aws:securityhub:{REGION}::standards/aws-foundational-security-best-practices/v/1.0.0",
            "StandardsSubscriptionArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:subscription/aws-foundational-security-best-practices/v/1.0.0",
            "StandardsInput": {},
            "StandardsStatus": "READY"}]}, {})
        stub.add_response("list_enabled_products_for_import", {"ProductSubscriptions": []}, {})
        stub.add_response("describe_organization_configuration", {"AutoEnable": False}, {})
        requests = aws.Requests({"retry_attempts": 1})
        requests.client = lambda _session, service, region: client
        read = FETCHERS["securityhub_hub"](requests, session, REGION, ACCOUNT)
        stub.assert_no_pending_responses()
    assert read.status == "collected" and len(read.items) == 1
    assert read.items[0]["HubArn"] == arn
    collection, findings = _native_decisions(read)
    assert collection["status"] == "collected"
    assert findings["aws.gap.securityhub.region_hub_enabled"] == "PASS"


def test_describe_hub_not_subscribed_reply_is_a_missing_hub():
    # Security Hub uses InvalidAccessException for both missing permission and
    # an account with no hub; only the "not subscribed" reply is a missing hub.
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name=REGION)
    client = session.client("securityhub", region_name=REGION)
    with Stubber(client) as stub:
        stub.add_client_error("describe_hub", service_error_code="InvalidAccessException", http_status_code=401,
                              service_message=f"Account {ACCOUNT} is not subscribed to AWS Security Hub CSPM")
        requests = aws.Requests({"retry_attempts": 1})
        requests.client = lambda _session, service, region: client
        read = FETCHERS["securityhub_hub"](requests, session, REGION, ACCOUNT)
        stub.assert_no_pending_responses()
    assert read.status == "empty" and read.items == []
    _, findings = _native_decisions(read)
    assert findings["aws.gap.securityhub.region_hub_enabled"] == "FAIL"
    assert findings["aws.claude_a.securityhub.enabled_with_standard_or_integration"] == "FAIL"
