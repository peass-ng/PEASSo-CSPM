"""Bounded cases for the signed native aws_config_all_resources_recorded (real engine + scoped MemoIndex).

The check is the one registered by peaso.checks through peaso/checks/aws_config_recording.py.
No network: the engine evaluates sealed in-memory snapshots.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from peaso.checks import CHECKS, aws_config_recording
from peaso.checks.aws_a_facts import scope_fixture
from peaso.checks.facts import MemoIndex
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ROOT = Path(__file__).resolve().parents[1]
MODULE = Path(aws_config_recording.__file__).resolve()
CID = "aws_config_all_resources_recorded"
ACCOUNT = "123456789012"
SCOPE = ACCOUNT + "/us-east-1"
SLR_ROLE = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
ROSTER = {
    ("aws-nist-ffiec-nydfs", "aws-compliance.benchmark.nist_800_171_rev_2", "aws-compliance.control.config_enabled_all_regions"),
    ("aws-nist-ffiec-nydfs", "aws-compliance.benchmark.nist_csf_v2", "aws-compliance.control.config_enabled_all_regions"),
    ("aws-kisa-ens-secnum-nis2", "ens_rd2022_aws", "op.exp.1.aws.cfg.1"),
    ("aws-kisa-ens-secnum-nis2", "ens_rd2022_aws", "op.exp.1.aws.cfg.2"),
    ("aws-kisa-ens-secnum-nis2", "ens_rd2022_aws", "op.exp.1.r2.aws.sminv.1"),
    ("aws-kisa-ens-secnum-nis2", "ens_rd2022_aws", "op.exp.3.aws.cfg.1"),
    ("aws-kisa-ens-secnum-nis2", "kisa_isms_p_2023_aws", "1.2.1"),
    ("aws-kisa-ens-secnum-nis2", "kisa_isms_p_2023_korean_aws", "1.2.1"),
    ("aws-kisa-ens-secnum-nis2", "secnumcloud_3.2_aws", "13.1"),
    ("aws-kisa-ens-secnum-nis2", "secnumcloud_3.2_aws", "8.1"),
}


def _registered():
    matches = [c for c in CHECKS if c.id == CID]
    assert len(matches) == 1
    assert Path(matches[0].evaluate.__wrapped__.__code__.co_filename).resolve() == MODULE == ROOT / "peaso/checks/aws_config_recording.py"
    return matches[0]


CHECK = _registered()
EXISTING = next(c for c in CHECKS if c.id == "aws.a.config.region_recorder_enabled")


def status(name="default", recording=True, last="Success", **extra):
    row = {"name": name, "recording": recording, **extra}
    if last is not None:
        row["lastStatus"] = last
    return {"ConfigurationRecordersStatus": [row], "collection_status": "collected"}


def recorder(name="default", *, group=None, run=None, **extra):
    row = {"name": name, "roleARN": "arn:aws:iam::123456789012:role/config-recorder",
        "recordingGroup": copy.deepcopy(group if group is not None else CURRENT_ALL),
        "Status": run if run is not None else status(name)}
    row.update(extra)
    return row


# API shape versions: pre-2023 (no recordingStrategy), 2023 strategy shape, 2024+ recorder ARN/scope fields.
LEGACY_ALL = {"allSupported": True, "includeGlobalResourceTypes": False, "resourceTypes": []}
CURRENT_ALL = {"allSupported": True, "includeGlobalResourceTypes": True, "resourceTypes": [],
    "exclusionByResourceTypes": {"resourceTypes": []}, "recordingStrategy": {"useOnly": "ALL_SUPPORTED_RESOURCE_TYPES"}}
INCLUSION = {"allSupported": False, "includeGlobalResourceTypes": False, "resourceTypes": ["AWS::EC2::Instance"],
    "exclusionByResourceTypes": {"resourceTypes": []}, "recordingStrategy": {"useOnly": "INCLUSION_BY_RESOURCE_TYPES"}}
EXCLUSION = {"allSupported": False, "includeGlobalResourceTypes": False, "resourceTypes": [],
    "exclusionByResourceTypes": {"resourceTypes": ["AWS::EC2::NetworkInterface"]}, "recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"}}
LINKED = {"name": "AWSConfigurationRecorderForSecurityHub", "arn": "arn:aws:config:us-east-1:123456789012:configuration-recorder/AWSConfigurationRecorderForSecurityHub/x",
    "servicePrincipal": "securityhub.amazonaws.com", "recordingScope": "INTERNAL",
    "recordingGroup": {"allSupported": False, "resourceTypes": ["AWS::EC2::Instance"], "recordingStrategy": {"useOnly": "INCLUSION_BY_RESOURCE_TYPES"}},
    "Status": status("AWSConfigurationRecorderForSecurityHub", servicePrincipal="securityhub.amazonaws.com")}


def without(row, key, *, status):
    """Field omitted while its explicit collection coverage is not collected."""
    trimmed = {k: copy.deepcopy(v) for k, v in row.items() if k != key}
    trimmed["_coverage"] = {**trimmed.get("_coverage", {}), key: {"status": status, "error": {"code": "AccessDenied"}}}
    return trimmed


def engine(collections_by_scope, *, metadata=None, scopes=None):
    collections = [{"type": "config_recorder", "scope": scope, "service": "config", **({"status": envelope} if isinstance(envelope, str)
        else {"status": "collected" if envelope else "empty", "items": envelope})} for scope, envelope in collections_by_scope.items()
        if envelope is not None]
    for collection in collections:
        collection.setdefault("items", [])
    snapshot = make_snapshot("aws", scopes or list(collections_by_scope), collections, metadata=metadata or {})
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID, EXISTING.id])
    return {(f["check_id"], f["scope"]): f for f in report["findings"]}


def verdict(items, **kwargs):
    findings = engine({SCOPE: items}, **kwargs)
    return findings[(CID, SCOPE)]["status"]


CASES = {
    "pass_legacy_all_supported": ([recorder(group=LEGACY_ALL)], "PASS"),
    "pass_current_all_supported_strategy": ([recorder()], "PASS"),
    "pass_2024_shape_customer_managed_with_arn": ([recorder(arn="arn:aws:config:us-east-1:123456789012:configuration-recorder/default/x", recordingScope="PAID",
        recordingMode={"recordingFrequency": "DAILY", "recordingModeOverrides": []})], "PASS"),
    "pass_customer_managed_using_service_linked_role": ([recorder(roleARN=SLR_ROLE)], "PASS"),
    "pass_customer_managed_overlapping_service_linked_recorder": ([recorder(), copy.deepcopy(LINKED)], "PASS"),
    "fail_complete_empty_regional_inventory": ([], "FAIL"),
    "fail_only_service_linked_recorder": ([copy.deepcopy(LINKED)], "FAIL"),
    "fail_stopped_never_started_no_last_status": ([recorder(run=status(recording=False, last=None))], "FAIL"),
    "fail_stopped_after_success": ([recorder(run=status(recording=False, last="Success"))], "FAIL"),
    "fail_stopped_even_with_malformed_group": ([recorder(group={"allSupported": "yes"}, run=status(recording=False))], "FAIL"),
    "fail_last_status_failure": ([recorder(run=status(last="Failure"))], "FAIL"),
    "fail_inclusion_strategy": ([recorder(group=INCLUSION)], "FAIL"),
    "fail_exclusion_strategy_overrides_all_supported": ([recorder(group={**EXCLUSION, "allSupported": True})], "FAIL"),
    "fail_legacy_selected_types": ([recorder(group={"allSupported": False, "resourceTypes": ["AWS::S3::Bucket"]})], "FAIL"),
    "fail_restricted_while_pending": ([recorder(group=INCLUSION, run=status(last="Pending"))], "FAIL"),
    "unknown_pending": ([recorder(run=status(last="Pending"))], "UNKNOWN"),
    "unknown_not_applicable": ([recorder(run=status(last="NotApplicable"))], "UNKNOWN"),
    "unknown_wrong_case_success": ([recorder(run=status(last="SUCCESS"))], "UNKNOWN"),
    "unknown_recording_without_last_status": ([recorder(run=status(last=None))], "UNKNOWN"),
    "unknown_status_detail_denied": ([recorder(run={"collection_status": "denied", "error": {"code": "AccessDenied"}})], "UNKNOWN"),
    "unknown_status_foreign_name": ([recorder(run=status("other"))], "UNKNOWN"),
    "unknown_status_duplicate_name": ([recorder(run={"ConfigurationRecordersStatus": status()["ConfigurationRecordersStatus"] * 2, "collection_status": "collected"})], "UNKNOWN"),
    "unknown_unsupported_strategy_enum": ([recorder(group={**CURRENT_ALL, "recordingStrategy": {"useOnly": "FUTURE_STRATEGY"}})], "UNKNOWN"),
    "unknown_all_supported_strategy_contradiction": ([recorder(group={**CURRENT_ALL, "allSupported": False})], "UNKNOWN"),
    "unknown_all_supported_with_listed_exclusions": ([recorder(group={**CURRENT_ALL, "exclusionByResourceTypes": {"resourceTypes": ["AWS::EC2::VPC"]}})], "UNKNOWN"),
    "unknown_exclusion_strategy_without_types": ([recorder(group={**EXCLUSION, "exclusionByResourceTypes": {"resourceTypes": []}})], "UNKNOWN"),
    "unknown_missing_all_supported": ([recorder(group={"recordingStrategy": {"useOnly": "ALL_SUPPORTED_RESOURCE_TYPES"}})], "UNKNOWN"),
    "unknown_missing_recording_group": ([{k: v for k, v in recorder().items() if k != "recordingGroup"}], "UNKNOWN"),
    "unknown_duplicate_customer_managed": ([recorder("a"), recorder("b")], "UNKNOWN"),
    "unknown_service_linked_name_without_principal": ([recorder("AWSConfigurationRecorderForX")], "UNKNOWN"),
    # Omitted optional fields only default when no explicit non-collected coverage marks them (strict facts.optional).
    "pass_minimal_unmarked_legacy_shape": ([recorder(group={"allSupported": True})], "PASS"),
    "unknown_omitted_strategy_denied_coverage": ([recorder(group=without(CURRENT_ALL, "recordingStrategy", status="denied"))], "UNKNOWN"),
    "unknown_omitted_strategy_partial_coverage": ([recorder(group=without(CURRENT_ALL, "recordingStrategy", status="partial"))], "UNKNOWN"),
    "unknown_omitted_exclusions_denied_coverage": ([recorder(group=without(CURRENT_ALL, "exclusionByResourceTypes", status="denied"))], "UNKNOWN"),
    "unknown_omitted_nested_exclusion_types_denied": ([recorder(group={**CURRENT_ALL, "exclusionByResourceTypes": {"_coverage": {"resourceTypes": {"status": "denied"}}}})], "UNKNOWN"),
    "unknown_omitted_resource_types_denied_coverage": ([recorder(group=without(CURRENT_ALL, "resourceTypes", status="denied"))], "UNKNOWN"),
    "unknown_omitted_recording_group_denied_coverage": ([without(recorder(), "recordingGroup", status="denied")], "UNKNOWN"),
    "unknown_omitted_service_principal_denied_coverage": ([without(recorder(), "servicePrincipal", status="denied")], "UNKNOWN"),
    "unknown_empty_service_principal": ([recorder(servicePrincipal="")], "UNKNOWN"),
    "unknown_inclusion_with_empty_types": ([recorder(group={**INCLUSION, "resourceTypes": []})], "UNKNOWN"),
    "unknown_inclusion_with_omitted_types": ([recorder(group={k: v for k, v in INCLUSION.items() if k != "resourceTypes"})], "UNKNOWN"),
    "unknown_legacy_selected_without_types": ([recorder(group={"allSupported": False})], "UNKNOWN"),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_engine_regional_truth_table(case):
    items, expected = CASES[case]
    before = copy.deepcopy(items)
    assert verdict(copy.deepcopy(items)) == expected
    assert items == before


@pytest.mark.parametrize("state,expected", [("denied", "DENIED"), ("partial", "UNKNOWN"), ("timeout", "UNKNOWN"), (None, "UNKNOWN")])
def test_incomplete_or_absent_regional_inventory_never_concludes(state, expected):
    findings = engine({SCOPE: state}, scopes=[SCOPE])
    assert findings[(CID, SCOPE)]["status"] == expected


def test_multi_region_is_per_scope_and_never_account_wide():
    west = ACCOUNT + "/eu-west-1"
    south = ACCOUNT + "/ap-south-1"
    metadata = {"region_discovery": [{"account_id": ACCOUNT, "status": "collected", "regions": ["us-east-1", "eu-west-1", "ap-south-1"]}]}
    findings = engine({SCOPE: [recorder()], west: [], south: "denied"}, metadata=metadata)
    assert [findings[(CID, s)]["status"] for s in (SCOPE, west, south)] == ["PASS", "FAIL", "DENIED"]
    for scope in (SCOPE, west):
        evidence = findings[(CID, scope)]["evidence"]
        assert evidence["account_wide_claim"] is False and evidence["region_inventory"] == "discovered_enabled_region"


@pytest.mark.parametrize("metadata,authority", [
    ({}, "not_proven"),
    ({"region_discovery": [{"account_id": ACCOUNT, "status": "denied", "error": {"code": "AccessDenied"}}]}, "discovery_incomplete"),
    ({"region_discovery": [{"account_id": ACCOUNT, "status": "collected", "regions": ["eu-west-1"]}]}, "outside_discovered_enabled_regions"),
])
def test_region_authority_is_reported_not_assumed(metadata, authority):
    finding = engine({SCOPE: [recorder()]}, metadata=metadata)[(CID, SCOPE)]
    assert finding["status"] == "PASS"
    assert finding["evidence"]["region_inventory"] == authority and finding["evidence"]["account_wide_claim"] is False


@pytest.mark.parametrize("items,existing,candidate", [
    ([recorder(run=status(last="Pending"))], "PASS", "UNKNOWN"),
    ([recorder(group=INCLUSION)], "PASS", "FAIL"),
    ([recorder(group=EXCLUSION)], "PASS", "FAIL"),
    ([recorder()], "PASS", "PASS"),
    ([], "FAIL", "FAIL"),
])
def test_differential_against_existing_region_recorder_check(items, existing, candidate):
    findings = engine({SCOPE: items})
    assert (findings[(EXISTING.id, SCOPE)]["status"], findings[(CID, SCOPE)]["status"]) == (existing, candidate)


def test_scoped_memo_index_matches_plain_index_and_is_pure():
    plain = scope_fixture("config_recorder", [recorder(), copy.deepcopy(LINKED)])
    memo = MemoIndex(copy.deepcopy(plain))
    before = copy.deepcopy(plain)
    subject = {"scope": SCOPE}
    assert CHECK.evaluate(subject, plain) == CHECK.evaluate(subject, memo)
    assert CHECK.evaluate(subject, plain)[0] == "PASS" and plain == before
    assert CHECK.evaluate({"scope": ACCOUNT + "/global"}, plain)[0] == "UNKNOWN"


def test_observed_out_of_predicate_facts_are_reported_without_changing_verdict():
    daily = recorder(recordingMode={"recordingFrequency": "DAILY", "recordingModeOverrides": []})
    finding = engine({SCOPE: [daily]})[(CID, SCOPE)]
    assert finding["status"] == "PASS"
    assert finding["evidence"]["observed"] == {"include_global_resource_types": True, "recording_frequency": "DAILY"}
    hidden = recorder(group=without(CURRENT_ALL, "includeGlobalResourceTypes", status="denied"))
    finding = engine({SCOPE: [hidden]})[(CID, SCOPE)]
    assert finding["status"] == "PASS"
    assert finding["evidence"]["observed"] == {"include_global_resource_types": "unavailable", "recording_frequency": "absent"}
