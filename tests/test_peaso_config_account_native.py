"""Focused native Config account proof; no AWS network access."""
import copy
from unittest.mock import patch

import boto3
from botocore.stub import Stubber

from peaso.checks import CHECKS
from peaso.collectors import aws
from peaso.collectors.aws import Requests
from peaso.collectors.aws_config_account_native import KIND, derive
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

A = "123456789012"
B = "210987654321"
NOW = "2026-10-18T00:00:00+00:00"
CHECK = "aws_nist_config_enabled_all_regions"


def facts(account=A, *, regions=("eu-west-1", "us-east-1")):
    caller = {"Account": account, "Arn": f"arn:aws:sts::{account}:assumed-role/test/probe"}
    raw = [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
           {"RegionName": "eu-west-1", "OptInStatus": "opted-in"},
           {"RegionName": "ap-south-1", "OptInStatus": "not-opted-in"}]
    discovery = [{"account_id": account, "caller_account_id": account,
                  "scope": account + "/global", "partition": "aws",
                  "source_operation": "ec2:DescribeRegions", "all_regions": True,
                  "read_only": True, "observed_at": NOW, "raw_regions": raw,
                  "regions": list(regions), "status": "collected"}]
    collections = []
    for region in regions:
        recorder = {"name": "default", "Status": {"collection_status": "collected",
                    "ConfigurationRecordersStatus": [{"name": "default", "recording": True,
                                                      "lastStatus": "SUCCESS"}]},
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}}
        for kind, rows in (("config_recorder", [recorder]),
                           ("config_delivery_channel", [{"name": "default"}])):
            for item in rows:
                item.update(AccountId=account, Region=region)
            collections.append({"type": kind, "scope": f"{account}/{region}",
                                "account_id": account, "global": False,
                                "status": "collected", "items": rows})
    return caller, discovery, collections


def verdict(account, identity, discoveries, regional, *, metadata=None):
    rows, status, error = derive(account, identity, discoveries, regional, NOW)
    envelope = {"type": KIND, "scope": f"{account}/global", "service": "config",
                "account_id": account, "global": True, "status": status, "items": rows}
    if error:
        envelope["error"] = error
    snapshot = make_snapshot("aws", [f"{account}/us-east-1"], [envelope],
                             created_at=NOW, metadata=metadata or {"collection": "read-only"})
    found = evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
    assert len(found) == 1 and found[0]["scope"] == f"{account}/global"
    return found[0]["status"], found[0]["evidence"], status


def test_actual_sdk_shape_and_native_account_pass():
    session = boto3.Session(aws_access_key_id="probe", aws_secret_access_key="probe",
                            region_name="us-east-1")
    client = session.client("ec2", region_name="us-east-1")
    requests = Requests({})
    requests.client = lambda _session, _service, _region: client
    with Stubber(client) as stub:
        stub.add_response("describe_regions", {"Regions": [
            {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "eu-west-1", "OptInStatus": "opted-in"},
            {"RegionName": "ap-south-1", "OptInStatus": "not-opted-in"}]},
            {"AllRegions": True})
        read = requests.pages(session, "ec2", "us-east-1", "describe_regions", "Regions", AllRegions=True)
    assert read.status == "collected" and len(read.items) == 3
    identity, discovery, regional = facts()
    discovery[0]["raw_regions"] = read.items
    assert verdict(A, identity, discovery, regional)[0] == "PASS"
    assert verdict(A, identity, discovery, regional, metadata={"parameters": {
        "enabled_regions": ["us-east-1"], "global_resource_regions": []}})[0] == "PASS"
    check = next(c for c in CHECKS if c.id == CHECK)
    assert check.dependencies == [KIND]


def test_full_collector_stubbed_sdk_pass_and_denied():
    # Production boto3/botocore shapes and the real collector/engine path; no wire calls.
    for deny_channel, expected in ((False, "PASS"), (True, "DENIED")):
        session = boto3.Session(aws_access_key_id="probe", aws_secret_access_key="probe",
                                region_name="us-east-1")
        sts = session.client("sts", region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        config = session.client("config", region_name="us-east-1")
        with Stubber(sts) as identity_stub, Stubber(ec2) as regions_stub, Stubber(config) as config_stub:
            identity_stub.add_response("get_caller_identity", {"UserId": "PROBE", "Account": A,
                "Arn": f"arn:aws:sts::{A}:assumed-role/test/probe"}, {})
            regions_stub.add_response("describe_regions", {"Regions": [
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "eu-west-1", "OptInStatus": "not-opted-in"}]}, {"AllRegions": True})
            # One service worker makes the queued regional jobs deterministic:
            # delivery channel precedes recorder in the sorted kind list.
            if deny_channel:
                config_stub.add_client_error("describe_delivery_channels",
                    service_error_code="AccessDeniedException", http_status_code=403,
                    expected_params={})
            else:
                config_stub.add_response("describe_delivery_channels", {
                    "DeliveryChannels": [{"name": "default"}]}, {})
            config_stub.add_response("describe_configuration_recorders", {"ConfigurationRecorders": [{
                "name": "default", "roleARN": f"arn:aws:iam::{A}:role/config",
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}}]}, {})
            config_stub.add_response("describe_configuration_recorder_status", {
                "ConfigurationRecordersStatus": [{"name": "default", "recording": True,
                                                  "lastStatus": "SUCCESS"}]},
                {"ConfigurationRecorderNames": ["default"]})
            clients = {("sts", "us-east-1"): sts, ("ec2", "us-east-1"): ec2,
                       ("config", "us-east-1"): config}
            with patch.object(aws.Requests, "client",
                              lambda self, _session, service, region: clients[(service, region)]):
                snapshot = aws.collect({"scopes": [A], "auth": {"method": "access_keys",
                    "aws_access_key_id": "probe", "aws_secret_access_key": "probe"},
                    "options": {"inventories": [KIND], "service_concurrency": 1,
                                "scope_concurrency": 1, "region_concurrency": 1}}, requirements=[KIND])
        proof = next(c for c in snapshot["collections"] if c["type"] == KIND)
        assert proof["scope"] == A + "/global"
        assert proof["status"] == ("denied" if deny_channel else "collected")
        found = evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
        assert [(row["status"], row["scope"]) for row in found] == [(expected, A + "/global")]


def test_complete_empty_is_fail_but_absent_or_denied_is_not_pass():
    identity, discovery, regional = facts()
    row = next(c for c in regional if c["scope"].endswith("eu-west-1")
               and c["type"] == "config_recorder")
    row.update(status="empty", items=[])
    assert verdict(A, identity, discovery, regional)[0] == "FAIL"
    regional.remove(row)
    assert verdict(A, identity, discovery, regional)[0] == "UNKNOWN"
    regional.append({**row, "status": "denied", "items": []})
    assert verdict(A, identity, discovery, regional)[0] == "DENIED"


def test_wrong_account_partial_duplicate_conflicting_and_capture_are_unavailable():
    identity, discovery, regional = facts()
    wrong = copy.deepcopy(identity)
    wrong["Account"] = B
    assert verdict(A, wrong, discovery, regional)[0] == "UNKNOWN"
    partial = copy.deepcopy(discovery)
    partial[0]["status"] = "partial"
    assert verdict(A, identity, partial, regional)[0] == "UNKNOWN"
    duplicate = copy.deepcopy(discovery)
    duplicate[0]["raw_regions"].append(copy.deepcopy(duplicate[0]["raw_regions"][0]))
    assert verdict(A, identity, duplicate, regional)[0] == "UNKNOWN"
    conflicting = copy.deepcopy(discovery)
    conflicting[0]["raw_regions"].append({"RegionName": "eu-west-1", "OptInStatus": "not-opted-in"})
    assert verdict(A, identity, conflicting, regional)[0] == "UNKNOWN"
    stale = copy.deepcopy(discovery)
    stale[0]["observed_at"] = "2026-10-17T00:00:00+00:00"
    assert verdict(A, identity, stale, regional)[0] == "UNKNOWN"
    assert verdict(A, identity, [], regional)[0] == "UNKNOWN"


def test_duplicate_foreign_or_partial_config_and_global_subclaim_unknown():
    identity, discovery, regional = facts()
    assert verdict(A, identity, discovery, regional + [copy.deepcopy(regional[0])])[0] == "UNKNOWN"
    foreign = copy.deepcopy(regional)
    foreign[0]["account_id"] = B
    assert verdict(A, identity, discovery, foreign)[0] == "UNKNOWN"
    foreign_item = copy.deepcopy(regional)
    foreign_item[0]["items"][0]["AccountId"] = B
    assert verdict(A, identity, discovery, foreign_item)[0] == "UNKNOWN"
    incomplete = copy.deepcopy(regional)
    incomplete[0]["status"] = "partial"
    assert verdict(A, identity, discovery, incomplete)[0] == "UNKNOWN"
    unknown_global = copy.deepcopy(regional)
    unknown_global[0]["items"][0]["recordingGroup"]["includeGlobalResourceTypes"] = False
    assert verdict(A, identity, discovery, unknown_global)[0] == "UNKNOWN"


def test_accounts_isolate_and_not_opted_in_region_is_not_required():
    identity, discovery, regional = facts()
    assert verdict(A, identity, discovery, regional)[0] == "PASS"
    other, other_discovery, other_regional = facts(B)
    other_regional[0]["items"] = []
    other_regional[0]["status"] = "empty"
    assert verdict(B, other, other_discovery, other_regional)[0] == "FAIL"
    assert verdict(A, identity, discovery, regional + other_regional)[0] == "PASS"


def test_cross_partition_region_name_rejected_in_derivation_and_evaluation():
    identity, discovery, regional = facts()
    forged = copy.deepcopy(discovery)
    forged[0]["raw_regions"][0]["RegionName"] = "cn-north-1"
    forged[0]["regions"] = ["cn-north-1", "eu-west-1"]
    assert verdict(A, identity, forged, regional)[0] == "UNKNOWN"
    rows, state, _ = derive(A, identity, discovery, regional, NOW)
    assert state == "collected"
    rows[0]["Discovery"]["raw_regions"][0]["RegionName"] = "cn-north-1"
    envelope = {"type": KIND, "scope": A + "/global", "service": "config",
                "account_id": A, "global": True, "status": "collected", "items": rows}
    snapshot = make_snapshot("aws", [A + "/us-east-1"], [envelope], created_at=NOW)
    found = evaluate_snapshot(snapshot, checks=[CHECK])["findings"]
    assert len(found) == 1 and found[0]["status"] == "UNKNOWN"


def test_scp_denied_region_leaves_the_required_config_regions():
    # eu-west-1 is enabled but an Organizations SCP denies it, so the scan
    # excluded it: it cannot hold a recorder and must not be demanded.
    identity, discovery, regional = facts(regions=("us-east-1",))
    assert verdict(A, identity, discovery, regional)[0] != "PASS"
    discovery[0]["scp_denied_regions"] = ["eu-west-1"]
    assert verdict(A, identity, discovery, regional)[0] == "PASS"
    # An exclusion naming a Region that was never enabled is not trusted.
    discovery[0]["scp_denied_regions"] = ["eu-west-1", "ap-south-1"]
    assert verdict(A, identity, discovery, regional)[0] != "PASS"
