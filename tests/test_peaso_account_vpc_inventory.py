"""Account scope aggregates only complete regional VPC facts without new API calls."""
import copy
from contextlib import ExitStack

from peaso.collectors.aws_inventory import vpc_account_inventory
from peaso.collectors import supported_types
from peaso.checks import CHECKS

ACCOUNT = "123456789012"
REGIONS = ["us-east-1", "eu-west-1"]


def collections():
    return [{"type": "vpc", "scope": f"{ACCOUNT}/{region}", "status": "collected", "items": [{"VpcId": "vpc-same", "IsDefault": False}]} for region in REGIONS]


def test_complete_account_projection_preserves_regions_native_ids_and_input():
    source = collections()
    before = copy.deepcopy(source)
    items, status, error = vpc_account_inventory(source, ACCOUNT, REGIONS, full_region_coverage=True)
    assert status == "collected" and error is None
    assert {row["Region"] for row in items} == set(REGIONS)
    assert len({row["id"] for row in items}) == 2
    assert all(row["AccountId"] == ACCOUNT and row["_provenance"]["inventory"] == "vpc" for row in items)
    assert source == before


def test_explicit_region_subset_cannot_claim_account_wide_completeness():
    assert vpc_account_inventory(collections(), ACCOUNT, REGIONS, full_region_coverage=False)[1] == "not_collected"


def test_denied_or_missing_region_preserves_partial_evidence():
    source = collections()
    source[1].update(status="denied", items=[])
    items, status, error = vpc_account_inventory(source, ACCOUNT, REGIONS, full_region_coverage=True)
    assert len(items) == 1 and status == "partial" and error["regions"] == [REGIONS[1]]
    assert vpc_account_inventory(source[:1], ACCOUNT, REGIONS, full_region_coverage=True)[1] == "partial"


def test_empty_complete_regions_are_distinct_from_missing_evidence():
    source = collections()
    for row in source:
        row.update(status="empty", items=[])
    assert vpc_account_inventory(source, ACCOUNT, REGIONS, full_region_coverage=True) == ([], "empty", None)


def test_no_native_check_requires_an_unregistered_inventory_kind():
    from tests.release_successor_history import registered_before_bulk
    # Preserve the complete native dependency guarantee for all 3,434 original
    # definitions. The exact signed bulk successor has its separately tested,
    # explicit unavailable-evidence contract; it is not native coverage.
    for check in registered_before_bulk(CHECKS):
        assert set(check.dependencies) <= set(supported_types(check.provider)), check.id


def test_collector_derives_complete_account_view_without_duplicate_vpc_calls(monkeypatch):
    import boto3
    from botocore.stub import Stubber
    from peaso.collectors import aws
    from peaso.engine import evaluate_snapshot
    session = boto3.Session(aws_access_key_id="fixture-key", aws_secret_access_key="fixture-secret", region_name=REGIONS[0])
    clients = {(service, region): session.client(service, region_name=region)
               for service, region in [("sts", REGIONS[0]), ("ec2", REGIONS[0]), ("ec2", REGIONS[1])]}
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    monkeypatch.setattr(aws.Requests, "client", lambda self, selected, service, region: clients[(service, region)])
    with ExitStack() as stack:
        stubs = {key: stack.enter_context(Stubber(client)) for key, client in clients.items()}
        stubs[("sts", REGIONS[0])].add_response("get_caller_identity", {"Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/fixture", "UserId": "fixture"}, {})
        stubs[("ec2", REGIONS[0])].add_response("describe_regions", {"Regions": [
            {"RegionName": region, "OptInStatus": "opt-in-not-required"} for region in REGIONS]}, {"AllRegions": True})
        for region in REGIONS:
            stubs[("ec2", region)].add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-same", "IsDefault": False}]}, {})
            # The regional VPC reader enriches each VPC with its two DNS attributes.
            stubs[("ec2", region)].add_response("describe_vpc_attribute", {"VpcId": "vpc-same",
                "EnableDnsSupport": {"Value": True}}, {"VpcId": "vpc-same", "Attribute": "enableDnsSupport"})
            stubs[("ec2", region)].add_response("describe_vpc_attribute", {"VpcId": "vpc-same",
                "EnableDnsHostnames": {"Value": True}}, {"VpcId": "vpc-same", "Attribute": "enableDnsHostnames"})
        snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT]}, ["vpc_account_inventory"])
        derived = next(c for c in snapshot["collections"] if c["type"] == "vpc_account_inventory")
        assert derived["status"] == "collected" and derived["global"] is True
        # STS, DescribeRegions, then one DescribeVpcs and two VPC DNS attribute reads per Region;
        # the account-wide view itself adds no API calls.
        assert snapshot["metadata"]["calls"] == 8
        assert len({i["id"] for i in derived["items"]}) == 2
        report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[
            "aws.claude_a.vpc.vpcs_in_multiple_regions", "aws.claude_a.vpc.nondefault_vpcs_in_multiple_regions"])
        assert report["findings"] and {f["status"] for f in report["findings"]} == {"PASS"}
        for stub in stubs.values():
            stub.assert_no_pending_responses()
