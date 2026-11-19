"""Offline regression cases for AWS transport and Shield applicability."""
from __future__ import annotations

import pytest
from botocore.exceptions import ConnectTimeoutError, EndpointConnectionError

from peaso.collectors import aws, aws_region_shield_native as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"


class _Session:
    def __init__(self, supported=None):
        self.supported = supported

    def get_partition_for_region(self, region):
        return "aws"

    def get_available_regions(self, service, partition_name=None):
        assert service == "appstream" and partition_name == "aws"
        return self.supported


class _FailureClient:
    def __init__(self, error):
        self.error = error

    def describe_fleets(self):
        raise self.error


@pytest.mark.parametrize("error_type,supported,status,code", [
    (ConnectTimeoutError, ["us-east-1"], "not_collected", "unsupported_region_service"),
    (ConnectTimeoutError, ["us-west-1"], "timeout", "read_failed"),
    (EndpointConnectionError, ["us-east-1"], "not_collected", "unsupported_region_service"),
    (EndpointConnectionError, ["us-west-1"], "unknown", "endpoint_unreachable"),
    (ConnectTimeoutError, [], "timeout", "read_failed"),
])
def test_appstream_transport_classification(monkeypatch, error_type, supported, status, code):
    error = error_type(endpoint_url="https://example.invalid")
    monkeypatch.setattr(aws.Requests, "client", lambda self, *args: _FailureClient(error))
    with pytest.raises(aws.ReadFailure) as failure:
        aws.Requests({"retry_attempts": 1}).call(_Session(supported), "appstream", "us-west-1", "describe_fleets")
    assert (failure.value.status, failure.value.code) == (status, code)


class _ShieldRequests:
    def __init__(self, listed, subscription=None):
        self.listed, self.subscription = listed, subscription
        self.calls = []

    def pages(self, session, service, region, operation, expression):
        self.calls.append((service, region, operation))
        return self.listed

    def detail(self, session, service, region, operation):
        self.calls.append((service, region, operation))
        return self.subscription


@pytest.mark.parametrize("listed,subscription,status,finding,call_count", [
    (aws.ReadResult([], "unknown", {"code": "ResourceNotFoundException"}),
     {"collection_status": "collected", "SubscriptionState": "INACTIVE"}, "empty", "NOT_APPLICABLE", 2),
    (aws.ReadResult([], "unknown", {"code": "ResourceNotFoundException"}),
     {"collection_status": "collected", "SubscriptionState": "ACTIVE"}, "unknown", "UNKNOWN", 2),
    (aws.ReadResult([], "unknown", {"code": "ResourceNotFoundException"}),
     {"collection_status": "denied", "error": {"code": "AccessDeniedException"}}, "unknown", "UNKNOWN", 2),
    (aws.ReadResult([], "unknown", {"code": "ResourceNotFoundException"}),
     {"collection_status": "collected", "SubscriptionState": "OTHER"}, "unknown", "UNKNOWN", 2),
    (aws.ReadResult([], "unknown", {"code": "ResourceNotFoundException"}),
     {"collection_status": "malformed", "SubscriptionState": "INACTIVE"}, "unknown", "UNKNOWN", 2),
    (aws.ReadResult([], "denied", {"code": "AccessDeniedException"}), None, "denied", "DENIED", 1),
    (aws.ReadResult([], "empty"), None, "empty", "NOT_APPLICABLE", 1),
])
def test_shield_inactive_guard_decision(listed, subscription, status, finding, call_count):
    requests = _ShieldRequests(listed, subscription)
    read = native.shield_protection_region(requests, _Session(), REGION, ACCOUNT)
    assert read.status == status
    assert requests.calls[0] == ("shield", "us-east-1", "list_protections")
    if call_count == 2:
        assert requests.calls[1] == ("shield", "us-east-1", "get_subscription_state")
    assert len(requests.calls) == call_count
    if status == "empty" and listed.status == "unknown":
        assert read.error == {"code": "shield_subscription_inactive"}
    snapshot = make_snapshot("aws", [SCOPE], [
        {"type": "shield_protection_region", "scope": SCOPE, "status": read.status, "items": read.items},
        {"type": "cloudwatch_alarm", "scope": SCOPE, "status": "empty", "items": []},
    ])
    findings = evaluate_snapshot(snapshot, checks=["aws_shield_ddos_detected_alarm"])["findings"]
    assert [row["status"] for row in findings] == [finding]
