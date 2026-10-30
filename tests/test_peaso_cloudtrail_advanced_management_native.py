"""Actual SDK, collector, and engine regression for native management selectors."""
from contextlib import ExitStack

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws, collect_live
from peaso.engine import evaluate_snapshot

ACCOUNT = "123456789012"
REGION = "us-east-1"
ARN = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/test"
CHECK = "aws.cloudtrail.management_events"


def field(name, op, values):
    return {"Field": name, op: values}


def selector(*fields):
    return {"FieldSelectors": list(fields)}


MGMT = field("eventCategory", "Equals", ["Management"])
DATA = field("eventCategory", "Equals", ["Data"])
READ = field("readOnly", "Equals", ["true"])
WRITE = field("readOnly", "Equals", ["false"])


@pytest.mark.parametrize("label,rows,wanted", [
    ("full_management", [selector(MGMT)], "PASS"),
    ("data_only", [selector(DATA, field("resources.type", "Equals", ["AWS::S3::Object"]))], "FAIL"),
    ("read_only", [selector(MGMT, READ)], "FAIL"),
    ("both_read_write_union", [selector(MGMT, READ), selector(MGMT, WRITE)], "PASS"),
    ("source_exclusion", [selector(MGMT, field("eventSource", "NotEquals", ["kms.amazonaws.com"]))], "FAIL"),
    ("unsupported_field", [selector(MGMT, field("eventName", "Equals", ["CreateTrail"]))], "UNKNOWN"),
    ("native_identity", [selector(DATA), selector(MGMT)], "PASS"),
    ("complementary_source_exclusions", [selector(MGMT, field("eventSource", "NotEquals", ["kms.amazonaws.com"])), selector(MGMT, field("eventSource", "NotEquals", ["rdsdata.amazonaws.com"]))], "PASS"),
    ("read_write_source_cross_union", [selector(MGMT, READ, field("eventSource", "NotEquals", ["kms.amazonaws.com"])), selector(MGMT, READ, field("eventSource", "NotEquals", ["rdsdata.amazonaws.com"])), selector(MGMT, WRITE)], "PASS"),
    ("read_write_source_cross_missing", [selector(MGMT, READ, field("eventSource", "NotEquals", ["kms.amazonaws.com"])), selector(MGMT, WRITE, field("eventSource", "NotEquals", ["rdsdata.amazonaws.com"]))], "FAIL"),
    ("unsupported_operator", [selector(MGMT, field("eventSource", "StartsWith", ["kms"]))], "UNKNOWN"),
    ("unsupported_operator_plus_full", [selector(MGMT, field("eventSource", "StartsWith", ["kms"])), selector(MGMT)], "PASS"),
    ("source_excluded_plus_full", [selector(MGMT, field("eventSource", "NotEquals", ["kms.amazonaws.com"])), selector(MGMT)], "PASS"),
    ("read_plus_excluded_write", [selector(MGMT, READ), selector(MGMT, WRITE, field("eventSource", "NotEquals", ["rdsdata.amazonaws.com"]))], "FAIL"),
    ("malformed_read_only", [selector(MGMT, field("readOnly", "Equals", ["maybe"]))], "UNKNOWN"),
    ("unsupported_plus_full", [selector(MGMT, field("eventName", "Equals", ["CreateTrail"])), selector(MGMT)], "PASS"),
    ("both_selector_families", [selector(MGMT)], "UNKNOWN"),
    ("basic_full", [{"IncludeManagementEvents": True, "ReadWriteType": "All"}], "PASS"),
    ("basic_excluded", [{"IncludeManagementEvents": True, "ReadWriteType": "All", "ExcludeManagementEventSources": ["kms.amazonaws.com"]}], "FAIL"),
])
@pytest.mark.parametrize("identity", ["matching", "foreign", "missing", "denied"])
def test_actual_collector_to_real_engine(monkeypatch, label, rows, wanted, identity):
    session = boto3.Session(aws_access_key_id="INERT", aws_secret_access_key="INERT", region_name=REGION)
    clients = {}
    with ExitStack() as stack:
        def add(service):
            client = session.client(service, region_name=REGION)
            stub = stack.enter_context(Stubber(client))
            clients[service] = (client, stub)
            return stub
        sts, ct = add("sts"), add("cloudtrail")
        original_client = session.client
        monkeypatch.setattr(session, "client", lambda service, **kw: clients[service][0] if service in clients else original_client(service, **kw))
        monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "inert-pinned"))
        sts.add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/test", "UserId": "test"}, {})
        ct.add_response("describe_trails", {"trailList": [{"Name": "test", "TrailARN": ARN, "HomeRegion": REGION, "IsMultiRegionTrail": True}]}, {"includeShadowTrails": True})
        ct.add_response("get_trail_status", {"IsLogging": True}, {"Name": ARN})
        if identity == "denied":
            ct.add_client_error("get_event_selectors", "AccessDeniedException", http_status_code=403, expected_params={"TrailName": ARN})
        else:
            key = "EventSelectors" if label.startswith("basic_") else "AdvancedEventSelectors"
            response = {key: rows}
            if label == "both_selector_families":
                response["EventSelectors"] = [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]
            if identity != "missing":
                response["TrailARN"] = ARN if identity == "matching" else ARN + "-foreign"
            ct.add_response("get_event_selectors", response, {"TrailName": ARN})
        ct.add_response("get_insight_selectors", {"TrailARN": ARN, "InsightSelectors": []}, {"TrailName": ARN})
        snap = collect_live({"provider": "aws", "scopes": [ACCOUNT], "options": {"regions": [REGION], "service_concurrency": 1, "retry_attempts": 1}}, ["cloudtrail"])
        finding = next(f for f in evaluate_snapshot(snap, checks=[CHECK])["findings"] if f["check_id"] == CHECK)
        assert finding["check_id"] == CHECK
        assert finding["status"] == (wanted if identity == "matching" else "UNKNOWN"), (label, identity, finding)
        assert any(c["type"] == "cloudtrail" for c in snap["collections"])
        if identity == "denied":
            assert "denied" in str(finding["evidence"]).lower()
        if identity in {"foreign", "missing"}:
            # The collector rejects unbound selector facts before evaluation;
            # the engine reports the unavailable detail, not its error code.
            trail = next(item for c in snap["collections"] if c["type"] == "cloudtrail"
                         for item in c["items"] if item["TrailARN"] == ARN)
            assert trail["EventSelectors"] == {
                "collection_status": "malformed",
                "error": {"code": "cloudtrail_selector_identity_mismatch"},
            }
            assert finding["evidence"] == {"reason": "resource detail unavailable: malformed"}
        for _, stub in clients.values():
            stub.assert_no_pending_responses()
