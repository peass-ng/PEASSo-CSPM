"""Grouped findings keep every verdict/asset and remain bounded and deterministic."""
from copy import deepcopy

import pytest

from peaso.finding_groups import group_findings, group_report, placement
from peaso.finding_subjects import subject


def row(number, provider="aws", status="FAIL", cid="retention", region="us-east-1", account="123456789012"):
    scope = account + "/" + region if provider == "aws" else f"projects/{account}" if provider == "gcp" else f"/subscriptions/{account}"
    return dict(id=str(number), check_id=cid, provider=provider, category="hardening", severity="medium", scope=scope,
        resource_id=f"stable-{number}", native_resource_id=f"log-{number}", resource_name=f"Log {number}",
        affected_subjects=[subject(provider, scope, 'log', f'log-{number}')] if status == 'FAIL' else [],
        title="Retention", status=status, evidence={"retention_days": 7}, region=region, frameworks=["Reviewed"])


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "k8s"])
def test_one_group_per_check_with_all_regions_assets_and_raw_observations(provider):
    rows = [row(i, provider, region=region) for i, region in enumerate(["us-east-1", "eu-north-1", "us-east-1"])]
    original = deepcopy(rows)
    groups = group_findings(rows, observations=True)
    assert len(groups) == 1
    group = groups[0]
    assert group["member_count"] == group["affected_asset_count"] == 3
    assert group["affected_regions"] == ["eu-north-1", "us-east-1"]
    assert {r["native_resource_id"] for r in group["observations"]} == {"log-0", "log-1", "log-2"}
    assert rows == original
    assert group_findings(list(reversed(rows)), observations=True) == groups


def test_mixed_outcomes_never_hide_failures_or_unknowns_behind_a_pass():
    groups = group_findings([row(1, status="PASS"), row(2, status="UNKNOWN"), row(3, status="FAIL"), row(4, status="DENIED")])
    group = groups[0]
    assert group["status"] == "FAIL" and group["assessment_complete"] is False
    assert group["status_counts"] == {"DENIED": 1, "FAIL": 1, "PASS": 1, "UNKNOWN": 1}
    assert group["affected_asset_count"] == 1
    assert group_findings([row(1, status="PASS"), row(2, status="DENIED")])[0]["status"] == "UNKNOWN"
    assert group_findings([row(1, status="DENIED")])[0]["status"] == "DENIED"


def test_internet_exposure_keeps_asset_specific_titles_services_and_evidence():
    findings = []
    for number, service, title, kind in [
        (1, "apigateway", "Internet access to an API endpoint", "api"),
        (2, "s3", "Public stored-data access", "data_share"),
        (3, "lambda", "Internet access to a Lambda URL", "function_url"),
    ]:
        item = row(number, cid="analysis.internet_exposure")
        item.update(category="exposure", service=service, title=title,
                    evidence={"exposure_kind": kind}, evidence_summary=f"{service} observation")
        findings.append(item)
    grouped = group_findings(findings, observations=True)
    assert len(grouped) == 3
    assert [(item["service"], item["title"], item["evidence"]["exposure_kind"])
            for item in grouped] == [("apigateway", "Internet access to an API endpoint", "api"),
                                     ("s3", "Public stored-data access", "data_share"),
                                     ("lambda", "Internet access to a Lambda URL", "function_url")]
    assert all(not item.get("grouped") and len(item["observations"]) == 1 for item in grouped)


def test_resource_ids_are_not_collapsed_across_accounts_and_severity_is_conservative():
    a, b = row(1), row(1, account="210987654321")
    a["severity"] = "high"
    b["severity"] = "low"
    grouped = group_findings([a, b])[0]
    assert grouped["affected_asset_count"] == 2 and grouped["severity"] == "high"
    assert len(grouped["affected_accounts"]) == 2


def test_group_report_is_idempotent_and_keeps_observation_data_and_counts():
    source = {"provider": "aws", "findings": [row(1), row(2), row(3, cid="other", status="PASS")],
              "stats": {"finding_count": 3, "by_status": {"FAIL": 2, "PASS": 1}, "by_severity": {"medium": 2}}, "coverage": [{"status": "collected"}]}
    grouped = group_report(source)
    assert len(grouped["findings"]) == 2 and grouped["stats"]["finding_count"] == 2
    assert grouped["stats"]["by_status"] == {"FAIL": 1, "PASS": 1}
    assert grouped["stats"]["by_severity"] == {"medium": 1}
    assert grouped["stats"]["observation_count"] == 3
    assert grouped["stats"]["observation_by_status"] == source["stats"]["by_status"]
    assert grouped["coverage"] == source["coverage"]
    assert group_report(grouped) is grouped
    assert len(source["findings"]) == 3


def test_native_location_and_scope_based_location_are_provider_specific():
    assert placement({"provider": "aws", "scope": "123456789012/global"}) == ("123456789012", "")
    assert placement({"provider": "azure", "scope": "/subscriptions/sub-id"}, {"location": "westeurope"}) == ("sub-id", "westeurope")
    assert placement({"provider": "gcp", "scope": "projects/proj", "native_resource_id": "projects/proj/zones/us-east1-b/instances/vm"}) == ("proj", "us-east1")


@pytest.mark.parametrize("location,expected", [
    ({"collection_status": "collected", "LocationConstraint": "EU"}, "eu-west-1"),
    ({"collection_status": "collected"}, "us-east-1"),
    ({"collection_status": "collected", "LocationConstraint": "ap-south-1"}, "ap-south-1"),
    ({"collection_status": "denied"}, ""),
    ({"collection_status": "collected", "LocationConstraint": "not-a-region"}, ""),
])
def test_global_bucket_inventory_uses_its_native_storage_location(location, expected):
    finding = {"provider": "aws", "service": "s3", "scope": "123456789012/global"}
    assert placement(finding, {"Name": "logs", "Location": location}) == ("123456789012", expected)


def test_bucket_location_survives_evaluation_and_grouped_report():
    from peaso.checks.claude_aws_a_s3 import B
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    bucket = deepcopy(B)
    bucket["Location"] = {"collection_status": "collected", "LocationConstraint": "ap-south-1"}
    snapshot = make_snapshot("aws", ["123456789012/us-east-1"], [{
        "type": "bucket", "scope": "123456789012/global", "global": True,
        "account_id": "123456789012", "status": "collected", "items": [bucket]}])
    report = evaluate_snapshot(snapshot, checks=["aws.claude_a.s3.prowler_bucket_level_public_access_block"])
    assert report["findings"] and all(row["region"] == "ap-south-1" for row in report["findings"])
    assert group_report(report)["findings"][0]["affected_regions"] == ["ap-south-1"]


def test_grouping_contract_covers_every_registered_check_without_dropping_members():
    from peaso.engine import _registry
    from peaso.checks import CHECKS
    _registry()
    observations = []
    for number, check in enumerate(CHECKS):
        observations.extend([dict(row(2 * number, check.provider, "PASS", check.id), category=check.category),
                             dict(row(2 * number + 1, check.provider, "FAIL", check.id, "eu-north-1"), category=check.category)])
    grouped = group_findings(observations, observations=True)
    assert len(grouped) == len(CHECKS)
    assert {(group["provider"], group["check_id"]) for group in grouped} == {(check.provider, check.id) for check in CHECKS}
    assert all(group["member_count"] == 2 and group["status_counts"] == {"FAIL": 1, "PASS": 1} for group in grouped)
    assert {member["id"] for group in grouped for member in group["observations"]} == {member["id"] for member in observations}


def test_historical_global_root_findings_do_not_claim_regional_placement():
    from peaso.engine import _registry
    _registry()
    cid = "aws.a.iam.root_hardware_mfa"
    a, b = row(1, cid=cid), row(2, cid=cid, region="eu-north-1")
    a["resource_id"], b["resource_id"] = "scope:" + a["scope"], "scope:" + b["scope"]
    a.pop('affected_subjects')
    b.pop('affected_subjects')
    group = group_findings([a, b])[0]
    assert group["affected_regions"] == []
    assert group["affected_scopes"] == []
    assert group["observed_scopes"] == ["123456789012/global"]
    assert group["affected_accounts"] == ["123456789012"]
    assert "Regions:" not in group["evidence_summary"]


def test_coalesced_inventory_rows_keep_every_account_in_grouped_evidence():
    item = row(1)
    item.update(resource_id="inventory:iam_account_summary", scope="selected_scopes", evidence={"scopes": ["123456789012/global", "210987654321/global"]})
    item.pop('affected_subjects')
    grouped = group_findings([item])[0]
    assert grouped["affected_accounts"] == ["123456789012", "210987654321"]
    assert grouped["affected_scopes"] == []
    assert grouped["observed_scopes"] == ["123456789012/global", "210987654321/global"]
