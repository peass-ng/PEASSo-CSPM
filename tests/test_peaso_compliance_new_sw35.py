"""Isolated contract tests for the sw35 signed compliance draft."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import CHECKS
from peaso.checks import compliance_new_sw35 as sw

SCOPE = "123456789012/us-east-1"
TRAIL = "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"
GROUP = "arn:aws:logs:us-east-1:123456789012:log-group:trail"
KEY = "arn:aws:kms:us-east-1:123456789012:key/key1"


@pytest.fixture(scope="module", autouse=True)
def registry_cleanup():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.META]


def index():
    trail = {"TrailARN": TRAIL, "Name": "main", "HomeRegion": "us-east-1", "SourceRegion": "us-east-1",
             "_provenance": {"operation": "cloudtrail:DescribeTrails", "native_response_complete": True},
             "S3BucketName": "trail-bucket", "S3KeyPrefix": "", "KmsKeyId": KEY,
             "CloudWatchLogsLogGroupArn": GROUP, "CloudWatchLogsRoleArn": "arn:aws:iam::123456789012:role/trail",
             "CloudWatchLogsRole": {"role_arn": "arn:aws:iam::123456789012:role/trail", "log_group_arn": GROUP,
                                    "simulation_context_complete": True, "trust_valid": True,
                                    "full_role_stream_scope_proven": True,
                                    "supported_stream_prefix": "arn:aws:logs:us-east-1:123456789012:log-group:trail:log-stream:123456789012_CloudTrail_us-east-1*",
                                    "decisions": {"logs:CreateLogStream": "allowed", "logs:PutLogEvents": "allowed"},
                                    "_provenance": {"read_only": True, "trail_arn": TRAIL,
                                                    "role_scope_proof": {"method": "complete_native_role_policies_v1",
                                                                         "operations": ["ListRolePolicies", "ListAttachedRolePolicies", "GetRolePolicy"],
                                                                         "identity_policy_inventory_complete": True,
                                                                         "permissions_boundary_policy_complete": True,
                                                                         "stream_prefix": "arn:aws:logs:us-east-1:123456789012:log-group:trail:log-stream:123456789012_CloudTrail_us-east-1*",
                                                                         "SCP_RCP_verified": False, "effective_live_delivery_verified": False},
                                                    "simulated_resource_arn": "arn:aws:logs:us-east-1:123456789012:log-group:trail:log-stream:123456789012_CloudTrail_us-east-1",
                                                    "effective_live_delivery_verified": False, "SCP_RCP_verified": False,
                                                    "operations": ["DescribeTrails", "GetTrailStatus", "GetEventSelectors", "GetRole", "GetContextKeysForPrincipalPolicy", "SimulatePrincipalPolicy"]}},
             "IsOrganizationTrail": False, "IsMultiRegionTrail": False,
             "Status": {"IsLogging": True, "LatestDeliveryError": "", "LatestDeliveryTime": "2026-10-11T23:00:00Z"},
             "CloudTrailS3DeliveryObjects": {"collection_status": "collected", "listing_complete": True,
                 "TrailARN": TRAIL, "AccountId": "123456789012", "HomeRegion": "us-east-1",
                 "Bucket": "trail-bucket", "BucketRegion": "us-east-1", "ExpectedBucketOwner": "123456789012",
                 "S3KeyPrefix": "", "OrganizationId": "o-1234567890",
                 "Prefix": "AWSLogs/o-1234567890/123456789012/CloudTrail/us-east-1/",
                 "source_operation": "s3:ListObjectsV2", "Contents": [{
                     "Key": "AWSLogs/o-1234567890/123456789012/CloudTrail/us-east-1/2026/10/11/123456789012_CloudTrail_us-east-1_20261011T2300Z_0123456789abcdef.json.gz",
                     "LastModified": "2026-10-11T23:00:00Z"}],
                 "_provenance": {"profile": "aws-cloudtrail-s3-delivery-metadata-v1", "read_only": True,
                     "identity_operation": "sts:GetCallerIdentity", "organization_operation": "organizations:DescribeOrganization",
                     "describe_operation": "cloudtrail:DescribeTrails", "native_destination_unique": True,
                     "scope": "unique_destination_account_region_object_metadata_correlation", "siem_receipt_verified": False}}}
    bucket = {"Name": "trail-bucket", "Logging": {"collection_status": "collected", "LoggingEnabled": {"TargetBucket": "access-bucket", "TargetPrefix": "logs/"}},
              "Lifecycle": {"collection_status": "collected", "Rules": []},
              "ObjectLock": {"collection_status": "collected", "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 365}}}}}
    ssm = {"InstanceId": "i-123", "ApplicationInventory": {"collection_status": "collected", "source_operation": "ssm:ListInventoryEntries", "InstanceId": "i-123", "TypeName": "AWS:Application",
             "Entries": [{"Name": "agent", "Version": "2.0"}]},
           "TimeSyncCompliance": {"collection_status": "collected", "source_operation": "ssm:ListComplianceItems", "ComplianceType": "Custom:TimeSync",
             "ComplianceItems": [{"ResourceId": "i-123", "Status": "COMPLIANT", "ExecutionSummary": {"ExecutionTime": "2026-10-11T23:00:00Z"}, "Details": {"offsetMilliseconds": 50}}]},
           "MalwareDefinitionsCompliance": {"collection_status": "collected", "source_operation": "ssm:ListComplianceItems", "ComplianceType": "Custom:MalwareDefinitions",
             "ComplianceItems": [{"ResourceId": "i-123", "Status": "COMPLIANT", "ExecutionSummary": {"ExecutionTime": "2026-10-11T23:00:00Z"}, "Details": {"definitionVersion": "42"}}]}}
    rows = {"cloudtrail_account_inventory": [trail], "bucket": [bucket], "log_group": [{"arn": GROUP + ":*", "kmsKeyId": KEY}],
            "kms_key": [{"KeyArn": KEY, "Metadata": {"KeyMetadata": {"Arn": KEY, "KeyManager": "CUSTOMER", "KeyState": "Enabled"}}}],
            "ssm_managed_instance": [ssm]}
    collections = {}
    resources = {}
    for kind, values in rows.items():
        global_kind = kind in ("cloudtrail_account_inventory", "bucket")
        envelope = {"type": kind, "scope": "123456789012/global" if global_kind else SCOPE,
                    "status": "collected", "items": values}
        if global_kind:
            envelope.update({"global": True, "account_id": "123456789012"})
        collections[kind] = [envelope]
        resources[kind] = [{"data": value} for value in values]
    context = {"provider": "aws", "scope": SCOPE, "created_at": "2026-10-12T00:00:00Z",
               "metadata": {"compliance_policy": {"status": "collected", "scope": SCOPE,
                   "approved_antimalware_packages": {"agent": "1.0"},
                   "required_applications": [{"Name": "agent", "minimumVersion": "1.0"}],
                   "logging_host_instance_ids": ["i-123"], "malware_managed_instance_ids": ["i-123"]}}}
    return {"context": context, "collections": collections, **resources}


def evaluate(check_id, facts):
    return next(c for c in CHECKS if c.id == check_id).evaluate(facts["context"], facts)[0]


def mutate_failure(check_id, facts):
    trail = facts["cloudtrail_account_inventory"][0]["data"]
    bucket = facts["bucket"][0]["data"]
    ssm = facts["ssm_managed_instance"][0]["data"]
    if check_id in sw._BUCKET_LOG_IDS:
        bucket["Logging"] = {"collection_status": "collected"}
    elif check_id == "aws_cloudtrail_bucket_lifecycle_retention_365":
        bucket["Lifecycle"]["Rules"] = [{"Status": "Enabled", "Prefix": "AWSLogs/", "Expiration": {"Days": 30}}]
    elif check_id == "aws_cloudtrail_s3_siem_delivery":
        trail["IsOrganizationTrail"] = True
        trail["Status"]["LatestDeliveryError"] = "AccessDenied"
    elif check_id in sw._INTEGRATION_IDS:
        trail["CloudWatchLogsLogGroupArn"] = ""
    elif check_id in sw._KMS_IDS:
        trail["KmsKeyId"] = ""
    elif check_id in ("aws.pci.ssm.antimalware_inventory", "aws.pci.ssm.required_applications"):
        ssm["ApplicationInventory"]["Entries"] = []
    elif check_id == "aws_log_clock_sync_compliance":
        ssm["TimeSyncCompliance"]["ComplianceItems"][0]["Details"]["offsetMilliseconds"] = 2000
    elif check_id == "aws_malware_definitions_fresh":
        ssm["MalwareDefinitionsCompliance"]["ComplianceItems"][0]["Status"] = "NON_COMPLIANT"


@pytest.mark.parametrize("check_id", list(sw.META))
def test_pass_fail_unknown_and_signed_metadata(check_id):
    facts = index()
    if check_id == "aws_cloudtrail_s3_siem_delivery":
        facts["cloudtrail_account_inventory"][0]["data"]["IsOrganizationTrail"] = True
    assert evaluate(check_id, facts) == "PASS"
    broken = copy.deepcopy(facts)
    mutate_failure(check_id, broken)
    assert evaluate(check_id, broken) == "FAIL"
    kind = "ssm_managed_instance" if check_id.startswith("aws.pci.ssm.") or check_id in ("aws_log_clock_sync_compliance", "aws_malware_definitions_fresh") else "cloudtrail_account_inventory"
    incomplete = copy.deepcopy(facts)
    incomplete["collections"][kind][0]["status"] = "partial"
    assert evaluate(check_id, incomplete) == "UNKNOWN"
    missing = copy.deepcopy(facts)
    del missing["collections"][kind]
    assert evaluate(check_id, missing) == "UNKNOWN"
    malformed = copy.deepcopy(facts)
    malformed["context"]["scope"] = "foreign"
    assert evaluate(check_id, malformed) == "UNKNOWN"


@pytest.mark.parametrize("check_id", list(sw.META))
def test_foreign_scope_and_missing_needed_fact_are_unknown(check_id):
    facts = index()
    kind = "ssm_managed_instance" if check_id.startswith("aws.pci.ssm.") or check_id in ("aws_log_clock_sync_compliance", "aws_malware_definitions_fresh") else "cloudtrail_account_inventory"
    facts["collections"][kind][0]["scope"] = "999999999999/us-east-1"
    assert evaluate(check_id, facts) == "UNKNOWN"
    facts = index()
    if kind == "ssm_managed_instance":
        del facts["context"]["metadata"]["compliance_policy"]
    else:
        del facts["cloudtrail_account_inventory"][0]["data"]["TrailARN"]
    assert evaluate(check_id, facts) == "UNKNOWN"


@pytest.mark.parametrize("check_id", list(sw.META))
def test_empty_applicable_inventory_not_applicable(check_id):
    facts = index()
    kind = "ssm_managed_instance" if check_id.startswith("aws.pci.ssm.") or check_id in ("aws_log_clock_sync_compliance", "aws_malware_definitions_fresh") else "cloudtrail_account_inventory"
    if kind == "ssm_managed_instance" and check_id not in ("aws.pci.ssm.antimalware_inventory", "aws.pci.ssm.required_applications"):
        return
    facts["collections"][kind][0]["items"] = []
    facts["collections"][kind][0]["status"] = "empty"
    facts[kind] = []
    assert evaluate(check_id, facts) == "NOT_APPLICABLE"


def test_complete_missing_log_group_fails_integration_but_unresolved_key_join_is_unknown():
    facts = index()
    facts["log_group"] = []
    facts["collections"]["log_group"][0]["items"] = []
    facts["collections"]["log_group"][0]["status"] = "empty"
    assert evaluate("aws.nist.cloudtrail_cloudwatch_integration", facts) == "FAIL"
    assert evaluate("aws_g6_cloudtrail_all_trails_cloudwatch_integration", facts) == "FAIL"
    assert evaluate("aws_g6_cloudtrail_kms_destination_join", facts) == "UNKNOWN"


def test_retention_unproven_object_lock_and_ambiguous_lifecycle_unknown():
    facts = index()
    facts["bucket"][0]["data"]["ObjectLock"] = {"collection_status": "collected", "ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}}
    assert evaluate("aws_cloudtrail_bucket_lifecycle_retention_365", facts) == "UNKNOWN"
    facts = index()
    facts["bucket"][0]["data"]["Lifecycle"]["Rules"] = [{"Status": "Enabled", "Filter": {"Tag": {"Key": "env", "Value": "prod"}}, "Expiration": {"Days": 30}}]
    assert evaluate("aws_cloudtrail_bucket_lifecycle_retention_365", facts) == "UNKNOWN"


def test_custom_ssm_producer_absent_is_unknown():
    for check_id, field in (("aws_log_clock_sync_compliance", "TimeSyncCompliance"), ("aws_malware_definitions_fresh", "MalwareDefinitionsCompliance")):
        facts = index()
        del facts["ssm_managed_instance"][0]["data"][field]
        assert evaluate(check_id, facts) == "UNKNOWN"


def test_antimalware_accepts_any_approved_package_required_apps_need_all():
    facts = index()
    policy = facts["context"]["metadata"]["compliance_policy"]
    policy["approved_antimalware_packages"] = {"agent": "1.0", "alternative": "1.0"}
    policy["required_applications"].append({"Name": "alternative", "minimumVersion": "1.0"})
    assert evaluate("aws.pci.ssm.antimalware_inventory", facts) == "PASS"
    assert evaluate("aws.pci.ssm.required_applications", facts) == "FAIL"


def foreign_organization_index():
    facts = index()
    trail = facts["cloudtrail_account_inventory"][0]["data"]
    trail["TrailARN"] = "arn:aws:cloudtrail:us-east-1:999999999999:trail/org"
    trail["CloudTrailS3DeliveryObjects"]["TrailARN"] = trail["TrailARN"]
    trail["IsOrganizationTrail"] = True
    trail["IsMultiRegionTrail"] = True
    trail["AccountId"] = SCOPE.split("/")[0]
    trail["_account_trail_binding"] = {
        "caller_account_id": SCOPE.split("/")[0],
        "identity_operation": "sts:GetCallerIdentity",
        "describe_operation": "cloudtrail:DescribeTrails",
        "include_shadow_trails": True,
        "trail_arn": trail["TrailARN"],
        "capture_observed_at": facts["context"]["created_at"],
    }
    return facts


def test_foreign_organization_trail_requires_native_caller_binding_and_destination_evidence():
    facts = foreign_organization_index()
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == "UNKNOWN"
    for check_id in ("aws.nist.cloudtrail_cloudwatch_destination_kms",
                     "aws_cloudtrail_bucket_lifecycle_retention_365",
                     "aws_cloudtrail_s3_siem_delivery"):
        assert evaluate(check_id, facts) == "PASS"
    # A foreign destination cannot be inferred from the trail ARN or org flag.
    facts["cloudtrail_account_inventory"][0]["data"]["CloudWatchLogsLogGroupArn"] = (
        "arn:aws:logs:us-east-1:999999999999:log-group:foreign")
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == "UNKNOWN"


@pytest.mark.parametrize("defect", ["no_binding", "not_org", "wrong_account", "wrong_clock",
                                    "no_shadow_proof", "manual_pointer", "wrong_scope", "missing_home"])
def test_foreign_organization_trail_ambiguous_binding_stays_unknown(defect):
    facts = foreign_organization_index()
    trail = facts["cloudtrail_account_inventory"][0]["data"]
    binding = trail["_account_trail_binding"]
    if defect == "no_binding":
        del trail["_account_trail_binding"]
    elif defect == "not_org":
        trail["IsOrganizationTrail"] = False
    elif defect == "wrong_account":
        trail["AccountId"] = "999999999999"
    elif defect == "wrong_clock":
        binding["capture_observed_at"] = "2026-10-11T00:00:00Z"
    elif defect == "no_shadow_proof":
        binding["include_shadow_trails"] = False
    elif defect == "manual_pointer":
        trail["_account_trail_binding"] = {"caller_account_id": SCOPE.split("/")[0]}
    elif defect == "wrong_scope":
        facts["context"]["scope"] = "999999999999/us-east-1"
    elif defect == "missing_home":
        trail["SourceRegion"] = "eu-west-1"
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == "UNKNOWN"


def test_cloudtrail_duplicate_home_rows_stay_unknown_at_signed_gate():
    facts = foreign_organization_index()
    original = facts["cloudtrail_account_inventory"][0]["data"]
    duplicate = copy.deepcopy(original)
    duplicate["Name"] = "conflict"
    facts["cloudtrail_account_inventory"].append({"data": duplicate})
    facts["collections"]["cloudtrail_account_inventory"][0]["items"].append(duplicate)
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == "UNKNOWN"


@pytest.mark.parametrize("mutation,expected", [
    ("allow", "PASS"), ("deny", "FAIL"), ("wrong_stream", "UNKNOWN"),
    ("unbound", "UNKNOWN"), ("multi", "UNKNOWN"), ("org", "UNKNOWN"),
])
def test_nist_cloudtrail_permission_evidence_is_bound_and_bounded(mutation, expected):
    facts = index()
    trail = facts["cloudtrail_account_inventory"][0]["data"]
    role = trail["CloudWatchLogsRole"]
    if mutation == "deny":
        role["decisions"]["logs:PutLogEvents"] = "implicitDeny"
    elif mutation == "wrong_stream":
        role["_provenance"]["simulated_resource_arn"] += "_1"
    elif mutation == "unbound":
        role["_provenance"]["trail_arn"] += "-other"
    elif mutation == "multi":
        trail["IsMultiRegionTrail"] = True
    elif mutation == "org":
        trail["IsOrganizationTrail"] = True
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == expected


@pytest.mark.parametrize("short,expected", [(False, "UNKNOWN"), (True, "FAIL")])
def test_proven_absent_object_lock_preserves_short_lifecycle_failure(short, expected):
    facts = index()
    trail = facts["cloudtrail_account_inventory"][0]["data"]
    trail.pop("S3KeyPrefix")
    trail["S3KeyPrefix"] = ""
    trail.setdefault("_coverage", {})["S3KeyPrefix"] = {"status": "empty", "reason": "documented_optional_api_omission", "source_operation": "cloudtrail:DescribeTrails"}
    bucket = facts["bucket"][0]["data"]
    bucket["ObjectLock"] = {"collection_status": "empty", "absent": True, "error": {"code": "ObjectLockConfigurationNotFoundError"}}
    if short:
        bucket["Lifecycle"]["Rules"] = [{"Status": "Enabled", "Prefix": "AWSLogs/", "Expiration": {"Days": 30}}]
    assert evaluate("aws_cloudtrail_bucket_lifecycle_retention_365", facts) == expected


def test_lifecycle_coverage_denial_remains_unknown_with_absent_object_lock():
    facts = index()
    bucket = facts["bucket"][0]["data"]
    bucket["ObjectLock"] = {"collection_status": "empty", "absent": True, "error": {"code": "ObjectLockConfigurationNotFoundError"}}
    bucket["Lifecycle"] = {"collection_status": "denied", "error": {"code": "AccessDenied"}}
    assert evaluate("aws_cloudtrail_bucket_lifecycle_retention_365", facts) == "UNKNOWN"


def test_s3_key_prefix_field_coverage_denial_is_not_defaulted():
    facts = index()
    trail = facts["cloudtrail_account_inventory"][0]["data"]
    trail["_coverage"] = {"S3KeyPrefix": {"status": "denied", "source_operation": "cloudtrail:DescribeTrails"}}
    assert evaluate("aws_cloudtrail_bucket_lifecycle_retention_365", facts) == "UNKNOWN"


@pytest.mark.parametrize("flag", ["IsOrganizationTrail", "IsMultiRegionTrail"])
@pytest.mark.parametrize("missing", ["CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn", "group"])
def test_unsupported_permission_scope_preserves_conclusive_configuration_failure(flag, missing):
    facts = index()
    trail = facts["cloudtrail_account_inventory"][0]["data"]
    trail[flag] = True
    if missing == "group":
        facts["log_group"] = []
        facts["collections"]["log_group"][0].update(items=[], status="empty")
    else:
        trail[missing] = ""
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == "FAIL"


@pytest.mark.parametrize("decision", ["unknown", "", "Allowed"])
def test_unrecognized_simulation_decision_is_unknown(decision):
    facts = index()
    facts["cloudtrail_account_inventory"][0]["data"]["CloudWatchLogsRole"]["decisions"]["logs:PutLogEvents"] = decision
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == "UNKNOWN"


@pytest.mark.parametrize("full_proof", [False, None])
def test_base_only_simulation_cannot_prove_full_role_stream_scope(full_proof):
    facts = index()
    role = facts["cloudtrail_account_inventory"][0]["data"]["CloudWatchLogsRole"]
    if full_proof is None:
        role.pop("full_role_stream_scope_proven")
    else:
        role["full_role_stream_scope_proven"] = full_proof
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == "UNKNOWN"


@pytest.mark.parametrize("region_scope,expected", [("all_source_regions", "PASS"), ("home_region", "UNKNOWN"), (None, "UNKNOWN"), ("other", "UNKNOWN")])
def test_multiregion_proof_scope_is_explicit(region_scope, expected):
    facts = index()
    trail = facts["cloudtrail_account_inventory"][0]["data"]
    trail["IsMultiRegionTrail"] = True
    prefix = GROUP + ":log-stream:123456789012_CloudTrail_*"
    fact = trail["CloudWatchLogsRole"]
    fact["supported_stream_prefix"] = prefix
    proof = fact["_provenance"]["role_scope_proof"]
    proof["stream_prefix"] = prefix
    if region_scope is not None:
        proof["stream_region_scope"] = region_scope
    assert evaluate("aws_nist_cloudtrail_trail_integrated_with_logs", facts) == expected
