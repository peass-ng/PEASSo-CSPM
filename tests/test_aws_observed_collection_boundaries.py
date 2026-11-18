"""Native empty and region coverage behavior; inert clients and no cloud credentials."""
from datetime import datetime, timezone
from types import SimpleNamespace
import copy
import boto3
from botocore.stub import Stubber
from peaso.collectors.aws import Requests, ReadResult
from peaso.collectors.aws_identity_center_regions import remember, finalize
from peaso.collectors.aws_macie_coverage_native import collect as macie

ACCOUNT = "123456789012"


def test_budget_sdk_omitted_optional_list_is_empty_but_null_is_malformed():
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    client = session.client("budgets", region_name="us-east-1")
    requests = Requests({}); requests.client = lambda *args, **kwargs: client
    with Stubber(client) as stub:
        stub.add_response("describe_budgets", {}, {"AccountId": ACCOUNT})
        assert requests.pages(session, "budgets", "us-east-1", "describe_budgets", "Budgets", AccountId=ACCOUNT).status == "empty"
    bad = Requests({}); bad.client = lambda *args, **kwargs: client
    bad.call = lambda *args, **kwargs: {"Budgets": None}
    assert bad.pages(session, "budgets", "us-east-1", "describe_budgets", "Budgets", AccountId=ACCOUNT).status == "malformed"


def test_identity_nonhome_emptiness_needs_native_account_specific_home_discovery():
    requests = SimpleNamespace()
    def row(account=ACCOUNT, region="us-west-2", state="not_collected"):
        return {"type": "identity_center", "scope": account + "/" + region, "status": state, "items": [], "error": {"code": "identity_center_home_region_unresolved"}}
    rows = [row(), row("999999999999"), row(region="us-east-1"), row(state="denied")]
    metadata = {}; finalize(requests, rows, metadata)
    assert all(r["status"] != "empty" for r in rows)
    remember(requests, ACCOUNT, "us-east-1"); finalize(requests, rows, metadata)
    assert [r["status"] for r in rows] == ["empty", "not_collected", "not_collected", "denied"]
    assert rows[0]["home_regions"] == ["us-east-1"] and "error" not in rows[0]


def test_macie_native_region_universe_respects_proven_scp_exclusions():
    class Native:
        audited_regions_by_account = {ACCOUNT: ["us-east-1"]}
        scp_denied_regions_by_account = {ACCOUNT: ["us-west-2"]}
        observed_at = datetime(2026, 11, 18, tzinfo=timezone.utc)
        def detail(self, session, service, region, operation, **kwargs):
            if operation == "get_caller_identity":
                return {"collection_status": "collected", "Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:role/audit"}
            assert operation == "get_macie_session" and region == "us-east-1"
            return {"collection_status": "empty", "absent": True, "error": {"code": "service_not_enabled"}}
        def pages(self, session, service, region, operation, field, **kwargs):
            if operation == "describe_regions":
                return ReadResult([{"RegionName": r, "OptInStatus": "opt-in-not-required"} for r in ("us-east-1", "us-west-2")], "collected")
            assert operation == "list_classification_jobs" and region == "us-east-1"
            return ReadResult([], "empty")
    session = SimpleNamespace(get_partition_for_region=lambda _: "aws")
    native = Native(); captured = macie(native, session, "us-east-1", ACCOUNT)
    assert captured.status == "collected"
    assert [r["Region"] for r in captured.items[0]["Regions"]] == ["us-east-1"]
    assert captured.items[0]["_provenance"]["scp_denied_regions"] == ["us-west-2"]
    native.scp_denied_regions_by_account = {ACCOUNT: ["eu-west-1"]}
    assert macie(native, session, "us-east-1", ACCOUNT).status == "malformed"
