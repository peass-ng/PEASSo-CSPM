"""Behaviour tests for the claude_aws_a native ports (AWS services ebs..vpc)."""
from peaso.checks.hacktricks_scope import includes
import copy
import importlib
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import claude_aws_a
from peaso.checks.claude_aws_a_common import CHECK_IDS, ROWS, CONTEXT, idx

for _module in claude_aws_a.MERGE_MODULES:  # merge targets that the runtime registry may not import yet
    importlib.import_module("peaso.checks." + _module)

REGISTRY = {check.id: check for check in CHECKS}
HACKTRICKS = "HackTricks Cloud Best Practices"


def test_marketplace_customer_policy_fallback_uses_supported_subscribe_scope():
    guidance = REGISTRY["aws.claude_a.iam.prowler_customer_policy_no_marketplace_subscribe"].remediation
    assert "Remove aws-marketplace:Subscribe" in guidance
    assert "separately governed procurement role" in guidance
    assert "cannot be scoped to product ARNs" in guidance
    assert "Scope aws-marketplace:Subscribe to approved product ARNs" not in guidance


def _run(cid, data, index):
    data, index = copy.deepcopy(data), copy.deepcopy(index)
    before, before_index = copy.deepcopy(data), copy.deepcopy(index)
    status = REGISTRY[cid].evaluate(data, index)[0]
    assert data == before and index == before_index, cid + " mutated its inputs"
    return status


# The reviewed role-activity successor ships pass/fail/missing/malformed cases
# only. Its UNKNOWN branch is an old role whose RoleLastUsed has no date.
_ROLE_ACTIVITY = "aws.claude_a.iam.role_used_within_60_days"
_SUCCESSOR_CASES = {_ROLE_ACTIVITY: {"unknown": {**CASES[_ROLE_ACTIVITY]["fail"], "RoleLastUsed": {}}}}


def _evaluate(cid, name):
    cases = {**CASES[cid], **_SUCCESSOR_CASES.get(cid, {})}
    return _run(cid, cases[name], cases.get(name + "_index", cases.get("index", {})))


@pytest.mark.parametrize("cid", CHECK_IDS)
def test_pass_fail_unknown(cid):
    check = REGISTRY[cid]
    cases = CASES[cid]
    base = cases.get("index", {})
    assert _evaluate(cid, "pass") == "PASS"
    if cid == "aws.claude_a.networkfirewall.in_vpc":
        # The prior empty VpcId fixture is incomplete placement evidence.
        # Valid AWS firewall modes all have a documented association, so this
        # VPC-only predicate has no source-backed definite FAIL case.
        assert _evaluate(cid, "fail") == "UNKNOWN"
    else:
        assert _evaluate(cid, "fail") == "FAIL"
    assert _evaluate(cid, "unknown") == "UNKNOWN"
    assert _evaluate(cid, "missing") == "UNKNOWN"
    assert _evaluate(cid, "malformed") == "UNKNOWN"
    # The role-activity successor reports a denied role read as DENIED, not as an unresolved fact.
    assert _run(cid, {"collection_status": "denied"}, base) == ("DENIED" if cid == _ROLE_ACTIVITY else "UNKNOWN")
    if "not_applicable" in cases:
        assert _evaluate(cid, "not_applicable") == "NOT_APPLICABLE"
    assert (HACKTRICKS in check.frameworks) == includes(check.id)
    assert ROWS[cid]


VARIANTS = [(cid, n, want, item, index) for cid in CHECK_IDS for n, (want, item, index) in enumerate(CASES[cid].get("variants", []))]


@pytest.mark.parametrize("cid,n,want,item,index", VARIANTS, ids=["%s-%d" % (v[0], v[1]) for v in VARIANTS])
def test_named_variants(cid, n, want, item, index):
    assert _run(cid, item, index if index is not None else CASES[cid].get("index", {})) == want


@pytest.mark.parametrize("cid", [c for c in CHECK_IDS if any(k != "context" for k in CASES[c].get("pass_index", CASES[c].get("index", {})))])
def test_dependency_missing_is_not_a_finding(cid):
    """Without its dependency inventories a predicate never reports FAIL."""
    cases = CASES[cid]
    status = _run(cid, cases["pass"], {"context": dict(CONTEXT)})
    assert status != "FAIL"


# --------------------------------------------------------------------------- focused semantics
from peaso.checks import claude_aws_a_s3 as s3  # noqa: E402
from peaso.checks import CHECKS, CHECK_ALIASES

def test_s3_prowler_acl_requires_collected_ownership_detail():
    cid = "aws.claude_a.s3.prowler_acl_disabled"
    failing = copy.deepcopy(CASES[cid]["fail"])
    assert _run(cid, failing, {}) == "FAIL"
    for status in (None, "partial", "denied"):
        incomplete = copy.deepcopy(failing)
        if status is None:
            incomplete["OwnershipControls"].pop("collection_status")
        else:
            incomplete["OwnershipControls"]["collection_status"] = status
        assert _run(cid, incomplete, {}) == "UNKNOWN"
    absent = copy.deepcopy(failing)
    absent["OwnershipControls"] = {"collection_status": "empty", "absent": True}
    assert _run(cid, absent, {}) == "FAIL"


def test_s3_prowler_replication_unresolved_destination_is_manual():
    item = copy.deepcopy(s3.B)
    item["Replication"]["ReplicationConfiguration"]["Rules"][0]["Destination"]["Bucket"] = "arn:aws:s3:::elsewhere"
    assert _run("aws.claude_a.s3.prowler_cross_region_replication", item, idx(bucket=[s3.B])) == "MANUAL"


def test_s3_object_logging_other_region_bucket_is_unknown_not_fail():
    item = s3.w(s3.B, Location__LocationConstraint="eu-west-1")
    assert _run("aws.claude_a.s3.object_level_logging", item, idx(cloudtrail=[])) == "UNKNOWN"


def test_s3_account_block_absent_configuration_fails():
    assert _run("aws.claude_a.s3.account_public_access_block_all", {}, idx(s3_account_public_access_block=[])) == "FAIL"


def test_s3_public_access_account_block_wins_over_public_acl():
    item = s3.w(s3.B, PublicAccessBlock=s3.ABSENT, Acl=s3.acl_with(s3.ALL_USERS, "READ"))
    assert _run("aws.claude_a.s3.prowler_public_access", item, s3.IDX_ACCOUNT_OK) == "PASS"
    assert _run("aws.claude_a.s3.prowler_public_access", item, s3.IDX) == "FAIL"
    assert _run("aws.claude_a.s3.prowler_public_access", item, idx(s3_account_public_access_block=None, bucket=[s3.B])) == "UNKNOWN"


def test_s3_cross_account_changes_ignores_wildcard_actions():
    policy = {"collection_status": "collected", "Policy": {"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "s3:*", "Resource": "*"}]}}
    assert _run("aws.claude_a.s3.policy_no_cross_account_permission_changes", s3.w(s3.B, Policy=policy), idx()) == "PASS"


def test_s3_denied_policy_detail_is_unknown():
    item = s3.w(s3.B, Policy={"collection_status": "denied"})
    for cid in ("aws.claude_a.s3.policy_restrict_public_access", "aws.claude_a.s3.perimeter_policy_not_public", "aws.claude_a.s3.restrict_public_read"):
        assert _run(cid, item, CASES[cid].get("index", {})) == "UNKNOWN"


def test_scp_restricts_regions_handles_real_frozen_scp_shapes():
    # Real DescribePolicy shapes from a live organization: the engine freezes
    # snapshot lists (FrozenList, a list subclass), Content may stay a JSON
    # string, Statement may be a dict, and Condition values a string or list.
    from peaso.snapshot import freeze
    from peaso.checks import claude_aws_a_security as sec
    cid = "aws.claude_a.organizations.scp_restricts_regions"
    full_access = {"Id": "p-FullAWSAccess", "Type": "SERVICE_CONTROL_POLICY", "AwsManaged": True,
                       "Targets": [{"TargetId": "123456789012"}], "Content": {"Statement": [{"Action": "*", "Effect": "Allow", "Resource": "*"}], "Version": "2012-10-17"}}
    deny_string = {"Id": "p-region", "Type": "SERVICE_CONTROL_POLICY", "Content": json.dumps({"Version": "2012-10-17", "Statement": {
        "Effect": "Deny", "NotAction": "iam:*", "Resource": "*", "Condition": {"StringNotEquals": {"aws:RequestedRegion": "eu-west-1"}}}}), "Targets": [{"TargetId": "123456789012"}]}
    deny_list = {"Id": "p-region2", "Type": "SERVICE_CONTROL_POLICY", "Content": {"Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-1", "us-east-1"]}}}]}, "Targets": [{"TargetId": "123456789012"}]}
    for policies, want in (([full_access], "FAIL"), ([full_access, deny_string], "PASS"), ([deny_list], "PASS")):
        index = freeze(idx(aws_account_configuration=[sec.ACCT_CFG], organization_policy=policies))
        assert REGISTRY[cid].evaluate(freeze({}), index)[0] == want
    malformed = {"Id": "p-bad", "Type": "SERVICE_CONTROL_POLICY", "Content": "{not json"}
    assert REGISTRY[cid].evaluate(freeze({}), freeze(idx(aws_account_configuration=[sec.ACCT_CFG], organization_policy=[malformed])))[0] == "UNKNOWN"


def _global(index):
    from peaso.checks.claude_aws_a_common import ACCOUNT
    index = copy.deepcopy(index)
    index["context"]["scope"] = index["context"]["_scope"] = ACCOUNT + "/global"
    return index


def test_s3_object_logging_global_scope_uses_account_trail_inventory():
    from peaso.checks import claude_aws_a_s3 as s3
    cid = "aws.claude_a.s3.object_level_logging"
    selectors = lambda values: {"collection_status": "collected", "EventSelectors": [{"DataResources": [{"Type": "AWS::S3::Object", "Values": values}]}]}
    trail = lambda **kw: {"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/t", "HomeRegion": "us-east-1", "IsMultiRegionTrail": True, "EventSelectors": selectors(["arn:aws:s3:::b1/"]), **kw}
    from peaso.checks.claude_aws_a_security import ACCT_CFG
    run = lambda trails: _run(cid, s3.B, _global(idx(cloudtrail_account_inventory=trails, aws_account_configuration=[ACCT_CFG])))
    assert run([trail()]) == "PASS"
    assert run([trail(EventSelectors=selectors(["arn:aws:s3"]))]) == "PASS"
    assert run([trail(EventSelectors=selectors([]))]) == "FAIL"
    assert run([]) == "FAIL"
    # A single-Region trail homed elsewhere cannot log this bucket's data events.
    assert run([trail(IsMultiRegionTrail=False, HomeRegion="eu-west-1")]) == "FAIL"
    assert run([trail(EventSelectors={"collection_status": "denied"})]) == "UNKNOWN"
    assert _run(cid, s3.B, _global(idx(cloudtrail_account_inventory=None, aws_account_configuration=[ACCT_CFG]))) == "UNKNOWN"


def test_s3_protected_by_macie_global_scope_states():
    from peaso.checks import claude_aws_a_s3 as s3
    cid = "aws.claude_a.s3.protected_by_macie"
    row = lambda state, jobs, status="collected": {"id": "macie-jobs/123456789012/us-east-1", "SourceRegion": "us-east-1", "ServiceState": state,
                                                   "Jobs": {"collection_status": status, "items": jobs}}
    run = lambda rows: _run(cid, s3.B, _global(idx(macie2_account_classification_job_inventory=rows)))
    assert run([row("service_not_enabled", [], "empty")]) == "NOT_APPLICABLE"
    assert run([row("available", [s3.MACIE_JOB])]) == "PASS"
    assert run([row("available", [])]) == "FAIL"
    assert run([row("unavailable", [], "denied")]) == "UNKNOWN"
    assert run([]) == "UNKNOWN"
    assert run([row("available", [{"jobId": "j2", "s3JobDefinition": {"bucketCriteria": {"includes": {}}}}])]) == "UNKNOWN"


def test_role_bedrock_staleness_not_applicable_only_for_policy_proven_exclusion():
    from peaso.checks.claude_aws_a_iam import FIXTURE
    cid = "aws.claude_a.iam.role_bedrock_access_not_stale"
    excluded = {"collection_status": "not_collected", "reason": "identity_policies_cannot_allow_namespaces", "namespaces": ["bedrock"]}
    role = {k: v for k, v in FIXTURE["iam_role"].items() if k != "ServicesLastAccessed"}
    assert _run(cid, {**role, "ServicesLastAccessedStatus": excluded}, idx()) == "NOT_APPLICABLE"
    assert _run(cid, {**role, "ServicesLastAccessedStatus": {**excluded, "namespaces": ["sagemaker"]}}, idx()) == "UNKNOWN"
    assert _run(cid, {**role, "ServicesLastAccessedStatus": {"collection_status": "timeout", "error": {"code": "usage_report_generation_timeout"}}}, idx()) == "UNKNOWN"


@pytest.mark.parametrize('kind,namespace', [('iam_user', 'bedrock'), ('iam_role', 'bedrock'),
                                            ('iam_user', 'sagemaker')])
@pytest.mark.parametrize('case,expected', [
    ('unreadable_matching_namespace', 'UNKNOWN'),
    ('unreadable_nonmatching_namespace', 'UNKNOWN'),
    ('unreadable_timestamp', 'UNKNOWN'),
    ('unreadable_missing_timestamp', 'UNKNOWN'),
    ('confirmed_empty_timestamp', 'FAIL'),
    ('duplicate_matching_namespace', 'UNKNOWN'),
    ('complete_missing_timestamp', 'FAIL'),
    ('complete_no_namespace', 'NOT_APPLICABLE'),
])
def test_stale_access_report_selected_fields_are_authoritative(kind, namespace, case, expected):
    from peaso.checks.claude_aws_a_iam import FIXTURE
    label = 'role' if kind == 'iam_role' else 'user'
    cid = f'aws.claude_a.iam.{label}_{namespace}_access_not_stale'
    recent = {'ServiceNamespace': namespace, 'LastAuthenticated': '2025-12-20T00:00:00+00:00'}
    if case == 'unreadable_matching_namespace':
        rows = [{**recent, '_coverage': {'ServiceNamespace': {'status': 'partial'}}}]
    elif case == 'unreadable_nonmatching_namespace':
        rows = [{'ServiceNamespace': 's3', '_coverage': {'ServiceNamespace': {'status': 'partial'}}}]
    elif case == 'unreadable_timestamp':
        rows = [{**recent, '_coverage': {'LastAuthenticated': {'status': 'partial'}}}]
    elif case == 'unreadable_missing_timestamp':
        rows = [{'ServiceNamespace': namespace, '_coverage': {'LastAuthenticated': {'status': 'partial'}}}]
    elif case == 'confirmed_empty_timestamp':
        rows = [{'ServiceNamespace': namespace, '_coverage': {'LastAuthenticated': {'status': 'empty'}}}]
    elif case == 'duplicate_matching_namespace':
        rows = [recent, {'ServiceNamespace': namespace, 'LastAuthenticated': '2025-01-01T00:00:00+00:00'}]
    elif case == 'complete_missing_timestamp':
        rows = [{'ServiceNamespace': namespace}]
    else:
        rows = [{'ServiceNamespace': 's3'}]
    item = copy.deepcopy(FIXTURE[kind])
    item['ServicesLastAccessed'] = rows
    assert _run(cid, item, idx()) == expected


@pytest.mark.parametrize('kind,namespace', [('iam_user', 'bedrock'), ('iam_role', 'bedrock'),
                                            ('iam_user', 'sagemaker')])
@pytest.mark.parametrize('proof,expected', [
    ('top_status_partial', 'UNKNOWN'),
    ('top_status_null', 'UNKNOWN'),
    ('top_status_empty', 'UNKNOWN'),
    ('reason_partial', 'UNKNOWN'),
    ('reason_empty', 'UNKNOWN'),
    ('namespaces_partial', 'UNKNOWN'),
    ('collected_markers', 'NOT_APPLICABLE'),
    ('legacy_no_markers', 'NOT_APPLICABLE'),
])
def test_stale_access_policy_exclusion_requires_readable_selected_proof(kind, namespace, proof, expected):
    from peaso.checks.claude_aws_a_iam import FIXTURE
    label = 'role' if kind == 'iam_role' else 'user'
    cid = f'aws.claude_a.iam.{label}_{namespace}_access_not_stale'
    item = copy.deepcopy(FIXTURE[kind])
    item.pop('ServicesLastAccessed', None)
    item['ServicesLastAccessedStatus'] = {
        'collection_status': 'not_collected',
        'reason': 'identity_policies_cannot_allow_namespaces',
        'namespaces': [namespace],
    }
    if proof.startswith('top_status_'):
        marker = proof.removeprefix('top_status_')
        item['_coverage'] = {'ServicesLastAccessedStatus': (
            None if marker == 'null' else {'status': marker})}
    elif proof in ('reason_partial', 'reason_empty', 'namespaces_partial'):
        field, marker = proof.rsplit('_', 1)
        item['ServicesLastAccessedStatus']['_coverage'] = {field: {'status': marker}}
    elif proof == 'collected_markers':
        item['_coverage'] = {'ServicesLastAccessedStatus': {'status': 'collected'}}
        item['ServicesLastAccessedStatus']['_coverage'] = {
            field: {'status': 'collected'} for field in ('collection_status', 'reason', 'namespaces')}
    assert _run(cid, item, idx()) == expected
