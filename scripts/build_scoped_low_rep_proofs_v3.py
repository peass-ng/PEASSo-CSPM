#!/usr/bin/env python3
"""Build explicit source/index proofs for the disjoint 72-ID low-rep slice."""
import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = "333ccb7146e02db59f14b2f8056c54bcbad266c5b55e696ced3ab5f19eb52eb3"
ENGINE = "peaso/engine.py:1488"
FACTS = "peaso/checks/facts.py:109"
AWS_A = "peaso/checks/aws_a_facts.py:20"
BATCH = "peaso/checks/batch_remaining_aws.py:93"
POST = "peaso/checks/post_dfaf_aws.py:37"
AUTHORITY = "peaso/checks/remaining_aws_gcp_native.py:22"
PROOFS = {}
EXCLUSIONS = {}


def approve(ids, source, predicate, completeness, *helpers):
    for ident in ids.split():
        if ident in PROOFS or ident in EXCLUSIONS:
            raise ValueError("duplicate decision: " + ident)
        PROOFS[ident] = {
            "predicate_source": source,
            "predicate": predicate,
            "completeness_sources": [ENGINE, *completeness],
            "helper_sources": list(helpers),
        }


def exclude(ids, source, reason):
    for ident in ids.split():
        if ident in PROOFS or ident in EXCLUSIONS:
            raise ValueError("duplicate decision: " + ident)
        EXCLUSIONS[ident] = {"source": source, "reason": reason}


# Direct current-resource reads and captured-time comparisons.
approve("aws.a.cloudtrail.cloudwatch_delivery_24h", "peaso/checks/aws_a_cloudtrail.py:33",
        "GetTrailStatus.LatestCloudWatchLogsDeliveryTime absent on a successful status read or older than the captured 24-hour cutoff is FAIL; malformed/future time is unresolved (lines 33-48).",
        [], "peaso/checks/aws_a_facts.py:49", "peaso/checks/facts.py:30")
approve("aws.a.cloudtrail.home_cloudwatch_date", "peaso/checks/aws_a_cloudtrail_variants.py:63",
        "Home-region filter, recorded CloudWatchLogsLogGroupArn and GetTrailStatus delivery time determine FAIL at the captured prior-UTC-date boundary; incomplete omission is unresolved (lines 63-85).",
        [], "peaso/checks/aws_a_cloudtrail_variants.py:17", "peaso/checks/aws_a_facts.py:70", "peaso/checks/aws_a_facts.py:49")
approve("aws.claude_a.ec2.account_imdsv2_default", "peaso/checks/claude_aws_a_ec2.py:300",
        "GetInstanceMetadataDefaults.HttpTokens other than required FAILs only when the scoped instance inventory is nonempty (lines 300-305).",
        [FACTS], "peaso/checks/claude_aws_a_common.py:122")
approve("aws.claude_a.iam.access_keys_rotated_90", "peaso/checks/claude_aws_a_iam.py:793",
        "Active credential-report access key last-rotated dates older than 90 whole days at captured time FAIL (lines 793-801).",
        [], "peaso/checks/claude_aws_a_iam.py:751", "peaso/checks/claude_aws_a_iam.py:1165")
approve("aws.gap.iam.root_not_used_90_days", "peaso/checks/aws_gap_core.py:511",
        "Root credential-report last-use timestamps within 90 captured days determine FAIL; unparseable markers do not become recent-use evidence (lines 511-527).",
        [], "peaso/checks/claude_aws_a_iam.py:751", "peaso/checks/claude_aws_a_iam.py:726")

# Complete regional inventories: absence is meaningful only after collected/empty envelopes.
approve("aws.a.config.region_recorder_enabled", "peaso/checks/aws_a_regional.py:36",
        "Complete regional Config recorder inventory empty, or a named recorder status recording=false/lastStatus=Failure, FAILs (lines 36-53).",
        [AWS_A], "peaso/checks/aws_a_facts.py:10")
approve("aws.a.guardduty.region_enabled", "peaso/checks/aws_a_regional.py:16",
        "Complete regional detector inventory empty or its unique Configuration.Status differs from ENABLED FAILs (lines 16-25).",
        [AWS_A], "peaso/checks/aws_a_facts.py:10")
approve("aws.b.backup_plan.regional_presence aws.b.backup_vault.regional_presence", "peaso/checks/aws_b_regional.py:14",
        "Generated scope evaluator FAILs iff the corresponding complete backup plan or vault inventory is empty (lines 8-22).",
        [FACTS], "peaso/checks/aws_b_regional.py:8")
approve("aws.b.backup.report_plan_presence", "peaso/checks/aws_b_regional.py:28",
        "With a complete nonempty backup-plan inventory, a complete empty report-plan inventory FAILs (lines 28-34).",
        [FACTS])
approve("aws.c2b.backup.report_plans_when_plans", "peaso/checks/claude2_aws_b_data.py:251",
        "Scoped backup plans are complete and nonempty before a complete empty report-plan inventory FAILs (lines 251-256).",
        [FACTS], "peaso/checks/claude_aws_b_common.py:647")
approve("aws.c2b.bedrock.guardrails_configured", "peaso/checks/claude2_aws_b_identity.py:633",
        "Scope FAILs iff complete ListGuardrails inventory is empty (lines 633-636).",
        [FACTS], "peaso/checks/claude_aws_b_common.py:647")
approve("aws.c2b.bedrock.prompt_management_exists", "peaso/checks/claude2_aws_b_identity.py:796",
        "Scope FAILs iff complete ListPrompts inventory is empty (lines 796-799).",
        [FACTS], "peaso/checks/claude_aws_b_common.py:647")
approve("aws.c2b.ecr.registry_enhanced_scanning", "peaso/checks/claude2_aws_b_devtools.py:540",
        "A unique complete registry scan configuration with repositories present FAILs iff scanType is not ENHANCED (lines 540-546).",
        [FACTS], "peaso/checks/claude2_aws_b_devtools.py:526")
approve("aws.claude_a.iam.saml_provider_present", "peaso/checks/claude_aws_a_iam.py:1131",
        "Scope FAILs iff the complete IAM SAML-provider inventory is empty (lines 1131-1133).",
        [FACTS], "peaso/checks/claude_aws_a_common.py:122")

# Credential report: the delegate checks report age, identity, coverage, and tracking bounds.
approve("aws.a.iam.unused_credentials_45_days aws.claude_a.iam.access_keys_used_45 aws.gap.iam.active_keys_used_within_45_days", "peaso/unused_iam_aws_completion.py:256",
        "Registered successor calls strict credential-report evaluator with a fixed 45-day cutoff; current account/user, report age, enabled state, last use, tracking start, and creation/rotation bounds are checked before FAIL (lines 128-224, 227-264).",
        ["peaso/unused_iam_aws_completion.py:128"], "peaso/unused_iam_aws_completion.py:227")
approve("aws.a.iam.unused_credentials_90_days", "peaso/unused_iam_aws_completion.py:256",
        "Registered successor calls the same strict credential-report evaluator with a fixed 90-day cutoff and identity/report/tracking guards (lines 128-224, 227-264).",
        ["peaso/unused_iam_aws_completion.py:128"], "peaso/unused_iam_aws_completion.py:227")

# Pure joins over complete KMS, RDS, Glue, and EMR inventories.
approve("aws.b.efs.customer_managed_key", "peaso/checks/aws_b_storage.py:18",
        "EFS Encrypted flag and uniquely joined KMS KeyManager/Enabled fields determine FAIL; unresolved key joins are UNKNOWN (lines 18-35).",
        [FACTS])
approve("aws.c2b.elasticache.cmk_enabled", "peaso/checks/claude2_aws_b_data.py:1144",
        "AtRestEncryptionEnabled false, missing KmsKeyId, or uniquely joined KMS Enabled false FAILs; unresolved joins are UNKNOWN (lines 1144-1155).",
        [FACTS])
approve("aws.cb.glue.catalog_metadata_sse_kms_with_tables", "peaso/checks/claude_aws_b_storage.py:286",
        "With complete nonempty Glue table inventory, CatalogEncryptionMode other than SSE-KMS FAILs (lines 282-288).",
        [FACTS], "peaso/checks/claude_aws_b_storage.py:264")
approve("aws.cb.glue.catalog_password_encryption_with_tables", "peaso/checks/claude_aws_b_storage.py:274",
        "With complete nonempty Glue table inventory, ReturnConnectionPasswordEncrypted=false FAILs (lines 269-276).",
        [FACTS], "peaso/checks/claude_aws_b_storage.py:264")
approve("aws.cb.rds.instance_multi_az_or_cluster", "peaso/checks/claude_aws_b_db.py:668",
        "Recorded instance MultiAZ or uniquely joined cluster MultiAZ controls FAIL; a missing cluster in a complete cluster inventory is an explicit FAIL (lines 633-640, 668-673).",
        [FACTS], "peaso/checks/claude_aws_b_db.py:633")
approve("aws.cb.rds.instance_critical_event_subscription aws.cb.rds.parameter_group_critical_event_subscription aws.cb.rds.security_group_critical_event_subscription", "peaso/checks/claude_aws_b_db.py:947",
        "With complete triggering RDS inventory, complete event-subscription inventory is filtered by SourceType, Enabled and fixed required EventCategoriesList membership; absence FAILs (lines 925-963).",
        [FACTS], "peaso/checks/claude_aws_b_db.py:925")

for ident, rule, line in (
    ("aws.c2b.emr.cluster_at_rest_encryption", "EnableAtRestEncryption is not true", 482),
    ("aws.c2b.emr.cluster_in_transit_encryption", "EnableInTransitEncryption is not true", 487),
    ("aws.c2b.emr.cluster_at_rest_cse_custom", "S3 EncryptionMode differs from CSE-Custom", 492),
    ("aws.c2b.emr.cluster_at_rest_sse_kms", "S3 EncryptionMode differs from SSE-KMS", 492),
    ("aws.c2b.emr.cluster_local_disk_cmk", "LocalDiskEncryptionConfiguration provider type differs from Custom", 502),
    ("aws.c2b.emr.cluster_local_disk_encryption", "at-rest flag is false or LocalDiskEncryptionConfiguration absent", 510),
):
    approve(ident, "peaso/checks/claude2_aws_b_analytics.py:466",
            f"Cluster SecurityConfiguration name joins uniquely to a complete DescribeSecurityConfiguration inventory; absent configuration or {rule} FAILs (lines 418-479, {line}).",
            [FACTS], "peaso/checks/claude2_aws_b_analytics.py:414",
            "peaso/checks/claude2_aws_b_analytics.py:433", f"peaso/checks/claude2_aws_b_analytics.py:{line}")

# Secrets Manager: source coverage and optional omissions are explicitly guarded.
approve("aws.cb.secretsmanager.rotation_rules_present", "peaso/checks/claude_aws_b_security.py:491",
        "DescribeSecret RotationRules absent under a bound disabled-rotation omission or recorded null FAILs; incomplete coverage is UNKNOWN (lines 456-493).",
        [AUTHORITY], "peaso/checks/claude_aws_b_security.py:457")
approve("aws.cb.secretsmanager.rotation_lambda", "peaso/checks/claude_aws_b_security.py:500",
        "Bound RotationRules absent or RotationLambdaARN empty FAILs; incomplete omission is UNKNOWN (lines 456-505).",
        [AUTHORITY], "peaso/checks/claude_aws_b_security.py:457")
approve("aws.cb.secretsmanager.cmk_encryption", "peaso/checks/claude_aws_b_security.py:527",
        "Exact scoped secret identity and documented KmsKeyId omission are bound; explicit key joins a complete KMS inventory and KeyManager!=CUSTOMER FAILs (lines 527-549).",
        [AUTHORITY, FACTS], "peaso/checks/remaining_aws_gcp_native.py:202", "peaso/checks/claude_aws_b_common.py:563")
approve("aws.cb.secretsmanager.rotated_as_scheduled", "peaso/checks/claude_aws_b_security.py:586",
        "Bound RotationRules absence FAILs; otherwise recorded AutomaticallyAfterDays and LastRotatedDate/CreatedDate compare with captured calendar age; unsupported schedules are UNKNOWN (lines 586-599).",
        [AUTHORITY], "peaso/checks/claude_aws_b_security.py:457", "peaso/checks/claude_aws_b_security.py:48")
approve("aws.cb.secretsmanager.rotated_within_90_days", "peaso/checks/claude_aws_b_security.py:608",
        "Recorded LastRotatedDate absent or older than 90 whole captured days FAILs (lines 608-613).",
        [], "peaso/checks/claude_aws_b_common.py:113")
approve("aws.cb.secretsmanager.accessed_within_90_days", "peaso/checks/claude_aws_b_security.py:619",
        "Recorded LastAccessedDate absent or more than 90 captured 24-hour periods old FAILs (lines 619-623).",
        [], "peaso/checks/claude_aws_b_common.py:113")
approve("aws.cb.secretsmanager.accessed_within_90_calendar_days", "peaso/checks/claude_aws_b_security.py:630",
        "Recorded LastAccessedDate absent or over 90 calendar days at captured clock FAILs (lines 630-635).",
        [], "peaso/checks/claude_aws_b_security.py:48")

# Fixed runtime dates and structured GuardDuty/IAM/EC2/VPC settings.
approve("aws.cb.lambda.runtime_not_deprecated_list", "peaso/checks/claude_aws_b_compute.py:141",
        "Zip managed Runtime enum is looked up in pinned deprecation-date table; captured date >= mapped date FAILs only within code-enforced 180-day review window (lines 109-157).",
        [], "peaso/checks/claude_aws_b_compute.py:109", "peaso/checks/claude_aws_b_compute.py:115")
approve("aws.claude_a.guardduty.prowler_delegated_admin_region", "peaso/checks/claude_aws_a_security.py:290",
        "Complete detector/admin inventories, detector Status, admin AdminStatus and OrganizationConfiguration.AutoEnableOrganizationMembers determine FAIL (lines 290-303).",
        [FACTS], "peaso/checks/claude_aws_a_security.py:59")
approve("aws.claude_a.guardduty.region_centrally_configured", "peaso/checks/claude_aws_a_security.py:129",
        "Complete detector inventory, Status and collected Administrator.AccountId determine regional FAIL outside fixed skip-region list (lines 118-142).",
        [FACTS], "peaso/checks/claude_aws_a_security.py:24", "peaso/checks/claude_aws_a_security.py:59")
approve("aws.claude_a.iam.securityaudit_role_exists aws.claude_a.iam.support_role_exists", "peaso/checks/claude_aws_a_iam.py:1104",
        "Complete IAM role inventory and exact AWS-managed SecurityAudit/AWSSupportAccess attached-policy ARN membership determine regional absence FAIL (lines 1099-1111).",
        [FACTS], "peaso/checks/claude_aws_a_iam.py:206")
approve("aws.claude_a.vpc.flow_logs_active", "peaso/checks/claude_aws_a_network.py:501",
        "Owned VPC and complete flow-log inventory join by ResourceId; no logs or any FlowLogStatus!=ACTIVE FAILs (lines 501-507).",
        [FACTS])

# Strict scoped resource and alarm joins.
approve("aws.network.target_group_has_load_balancer", "peaso/unused_network_aws.py:125",
        "Target-group association ARN list empty FAILs only when current same-scope native collection and wrapper projection are complete (lines 28-54, 125-145).",
        ["peaso/unused_network_aws.py:28"])
approve("aws.nist.cloudtrail_cloudwatch_integration aws_g6_cloudtrail_all_trails_cloudwatch_integration", "peaso/checks/batch_remaining_aws.py:941",
        "Home-region CloudTrail configuration, resolved complete same-scope CloudWatch log-group join and variant logging/role flags determine FAIL (lines 941-968).",
        [BATCH], "peaso/checks/batch_remaining_aws.py:970", "peaso/checks/batch_remaining_aws.py:1159")
approve("aws_fedramp_cloudtrail_destination_kms aws_g6_cloudtrail_kms_destination_join aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk", "peaso/checks/batch_remaining_aws.py:1072",
        "Home-region trail and complete same-scope KMS/log-group inventories join exact KmsKeyId, KeyManager, KeyState and destination configuration; non-customer/disabled or missing configured key FAILs (lines 1072-1133).",
        [BATCH], "peaso/checks/batch_remaining_aws.py:970", "peaso/checks/batch_remaining_aws.py:1164")
approve("aws_g6_ecs_all_containers_logging", "peaso/checks/batch_remaining_aws.py:226",
        "Exact scoped ECS task definition and active status; any container missing recorded logConfiguration.logDriver FAILs (lines 226-241).",
        [BATCH])
approve("aws_cis_lambda_config_recorded", "peaso/checks/batch_remaining_aws.py:724",
        "Exact Lambda membership and complete Config recorder inventory; no customer recorder, stopped/failed state or Lambda type outside recorded strategy FAILs (lines 724-760). Ambiguous recorder-name ownership is UNKNOWN.",
        [BATCH], "peaso/checks/aws_config_recording.py:47", "peaso/checks/aws_config_recording.py:94")
approve("aws_nist_dynamodb_table_encrypted_with_kms", "peaso/checks/batch_remaining_aws.py:521",
        "Exact scoped DynamoDB table detail; absent SSEDescription or recorded SSEType/KMSMasterKeyArn/Status not denoting enabled KMS FAILs (lines 521-540).",
        [BATCH])
approve("aws_route53_hosted_zone_dnssec_enabled", "peaso/checks/batch_remaining_aws.py:543",
        "Exact public hosted zone and DNSSEC detail; ServeSignature!=SIGNING or no ACTIVE key-signing key FAILs (lines 543-556).",
        [BATCH])
approve("aws_lambda_code_signing_configured", "peaso/checks/batch_remaining_aws.py:559",
        "Exact active ZIP Lambda and collected GetFunctionCodeSigningConfig detail; absent config, empty AllowedPublishers list, or CodeSigningPolicies.UntrustedArtifactOnDeployment != Enforce FAILs after identity guards (lines 559-609).",
        [BATCH])
approve("aws_sns_delivery_failure_alarm_present aws_sqs_queue_depth_alarm_present", "peaso/checks/batch_remaining_aws.py:418",
        "Complete same-scope CloudWatch alarm inventory is filtered by fixed metric namespace/name/dimension and enabled action list; absent matching alarm FAILs only when unresolved alarms cannot affect absence (lines 418-480, 1055-1069).",
        [BATCH], "peaso/checks/batch_remaining_aws.py:1055")
approve("aws_g6_elbv2_only_https_tls_listeners", "peaso/checks/post_dfaf_aws.py:136",
        "Exact scoped ALB/NLB member and listener child coverage; observed non-HTTPS/TLS protocol or missing certificate is a definite FAIL, while incomplete negative evidence is UNKNOWN (lines 37-88, 136-174).",
        [POST], "peaso/checks/post_dfaf_aws.py:84")
approve("aws_cis_elbv2_only_tls_listeners", "peaso/checks/next20_aws.py:115",
        "Complete scoped ALB/NLB and DescribeListeners child inventory; definite plain TCP/HTTP without redirect FAILs, redirect approval and unsupported protocol remain UNKNOWN (lines 82-110, 115-157).",
        ["peaso/checks/next20_aws.py:82"])
approve("aws_nist_s3_bucket_cross_region_replication_enabled", "peaso/checks/compliance_new_aws_s3.py:80",
        "Complete account-global bucket inventory and exact source membership; enabled replication rules join destination bucket LocationConstraint, and no cross-region destination FAILs only after unresolved destinations are excluded (lines 17-71, 80-141).",
        [FACTS], "peaso/checks/compliance_new_aws_s3.py:17", "peaso/checks/compliance_new_aws_s3.py:54")
approve("aws.pci.shield.protection_all_internet_resources", "peaso/checks/compliance_new_sw37.py:135",
        "Complete scoped Shield, ELB, CloudFront and elastic-IP inventories; recorded Type/Scheme/ARN membership determines which configured resources lack a Shield protection (lines 58-75, 135-159).",
        ["peaso/checks/compliance_new_sw37.py:58"])
approve("aws_g6_api_stage_effective_waf_acl", "peaso/checks/compliance_new_sw37.py:179",
        "Exact stage identity and complete WAF association/ACL inventories; declared webAclArn missing, effective association absent/mismatched, or ACL absent FAILs (lines 58-75, 123-132, 179-191).",
        ["peaso/checks/compliance_new_sw37.py:58"], "peaso/checks/compliance_new_sw37.py:123")

# Explicit retained-AI subjects under the supervisor's free-text/policy criterion.
exclude("aws.b.ecr.effective_scan_configuration", "peaso/checks/aws_b_ecr.py:47",
        "Repository rule selection uses fnmatchcase on a free-text filter pattern (lines 47-57); retain AI.")
exclude("aws.claude_a.iam.role_bedrock_access_not_stale", "peaso/checks/claude_aws_a_iam.py:1051",
        "Evaluator includes policy-derived collector exclusion at lines 1051-1073; retain AI despite timestamp FAIL branch.")
exclude("aws.gap.cloudtrail.trail_security_best_practices", "peaso/checks/aws_gap_core.py:75",
        "Advanced event-selector pattern interpretation and management-event coverage intent at lines 75-112/307-312; retain AI.")
exclude("aws.nist.all_iam_policies_no_star_star aws.nist.all_managed_policies_no_service_wildcard", "peaso/checks/aws_all_policies.py:77",
        "Default IAM policy Action/Resource statement interpretation at lines 77-102 is policy intent; retain AI.")
exclude("aws.review.secretsmanager.explicit_principal_deny", "peaso/checks/aws_policy_constraints_review_20261019.py:104",
        "Secret resource-policy Principal/Condition deny analysis is policy intent; retain AI.")
exclude("aws_api_customer_log_delivery", "peaso/checks/compliance_new_sw49.py:249",
        "Access-log format requires free-text $context token interpretation at lines 249-260; retain AI.")
exclude("aws_config_all_resources_recorded", "peaso/checks/aws_config_recording.py:142",
        "Recorder ownership can be inferred from a service-linked name prefix at lines 137-145; retain AI without a bound ownership field.")


PARAMETER_BINDINGS = {
    "aws.a.iam.unused_credentials_45_days": {"days": 45, "include_password": True, "include_keys": True},
    "aws.a.iam.unused_credentials_90_days": {"days": 90, "include_password": True, "include_keys": True},
    "aws.claude_a.iam.access_keys_used_45": {"days": 45, "include_password": False, "include_keys": True},
    "aws.gap.iam.active_keys_used_within_45_days": {"days": 45, "include_password": False, "include_keys": True},
    "aws.cb.rds.instance_critical_event_subscription": {"source_type": "db-instance", "required_categories": ["configuration change", "failure", "maintenance"]},
    "aws.cb.rds.parameter_group_critical_event_subscription": {"source_type": "db-parameter-group", "required_categories": ["configuration change"]},
    "aws.cb.rds.security_group_critical_event_subscription": {"source_type": "db-security-group", "required_categories": ["configuration change", "failure"]},
    "aws.claude_a.iam.securityaudit_role_exists": {"managed_policy_name": "SecurityAudit"},
    "aws.claude_a.iam.support_role_exists": {"managed_policy_name": "AWSSupportAccess"},
    "aws.nist.cloudtrail_cloudwatch_integration": {"require_logging": True, "require_delivery_role": False},
    "aws_g6_cloudtrail_all_trails_cloudwatch_integration": {"require_logging": False, "require_delivery_role": True},
    "aws_fedramp_cloudtrail_destination_kms": {"active_only": True},
    "aws_g6_cloudtrail_kms_destination_join": {"active_only": False},
    "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk": {"active_only": True},
    "aws_sns_delivery_failure_alarm_present": {"namespace": "AWS/SNS", "metric": "NumberOfNotificationsFailed"},
    "aws_sqs_queue_depth_alarm_present": {"namespace": "AWS/SQS", "metric": "ApproximateNumberOfMessagesVisible"},
    "aws.b.backup_plan.regional_presence": {"inventory_kind": "backup_plan"},
    "aws.b.backup_vault.regional_presence": {"inventory_kind": "backup_vault"},
}


def source_digest(reference):
    name, line = reference.rsplit(":", 1)
    path = (ROOT / name).resolve()
    if (not path.is_relative_to(ROOT) or not path.is_file() or not line.isdecimal() or
            int(line) < 1 or int(line) > len(path.read_text().splitlines())):
        raise ValueError("invalid source line: " + reference)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("low_rep_receipt", help="Exact signed code-worker receipt; SHA256 is pinned")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    frozen = json.loads((ROOT / "docs/ai-review/native-final-scoped-low-rep-slice-v3.json").read_text())
    original_raw = Path(args.low_rep_receipt).read_bytes()
    if (frozen["source_low_rep_receipt_sha256"] != SOURCE_SHA256 or
            hashlib.sha256(original_raw).hexdigest() != SOURCE_SHA256):
        raise ValueError("code-worker low-rep source receipt changed")
    original = {row["check_id"]: row for row in json.loads(original_raw)["checks"]}
    numeric = {row["check_id"]: row for row in json.loads(
        (ROOT / "outputs/native-final-audit-992-v3-numeric.json").read_text())["per_check"]}
    slice_rows = {row["check_id"]: row for row in frozen["checks"]}
    if (set(PROOFS) & set(EXCLUSIONS) or set(PROOFS) | set(EXCLUSIONS) != set(slice_rows)
            or set(PARAMETER_BINDINGS) - set(PROOFS)):
        raise ValueError("72-ID disjoint slice has missing or extra decisions")
    rows = []
    for ident in sorted(slice_rows):
        prior = slice_rows[ident]
        source = original[ident]
        if (source["initial_representatives"] != prior["initial_representatives"] or
                source["native_fail_count"] != prior["native_fail_count"] or
                source["evaluator"] != prior["prior_evaluator"]):
            raise ValueError("source row changed: " + ident)
        if (numeric[ident]["native_fail"] != prior["native_fail_count"] or
                numeric[ident]["initial_representatives"] != prior["initial_representatives"] or
                numeric[ident]["ai_disagreement"] != 0 or
                numeric[ident]["ai_verdicts"] != {"FAIL": prior["native_fail_count"]}):
            raise ValueError("exact 992 native/review evidence differs: " + ident)
        proof = PROOFS.get(ident)
        if proof is not None:
            proof = {**proof, "parameter_binding": PARAMETER_BINDINGS.get(ident, {})}
            refs = [proof["predicate_source"], *proof["completeness_sources"], *proof["helper_sources"]]
            hashes = {ref.rsplit(":", 1)[0]: source_digest(ref) for ref in refs}
            decision = "native_final_source_proven"
            entry = {"predicate_proof": proof, "source_file_sha256": hashes}
        else:
            exclusion = EXCLUSIONS[ident]
            hashes = {exclusion["source"].rsplit(":", 1)[0]: source_digest(exclusion["source"])}
            decision = "retain_ai"
            entry = {"exclusion": exclusion, "source_file_sha256": hashes}
        rows.append({"check_id": ident, "decision": decision,
                     "initial_representatives": prior["initial_representatives"],
                     "native_fail_count": prior["native_fail_count"],
                     "ai_verdict_counts": numeric[ident]["ai_verdicts"],
                     "recorded_evidence_keys": source["evidence_keys"],
                     "evaluator": prior["prior_evaluator"], **entry})
    receipt = {"schema_version": 1, "scan_id": frozen["scan_id"],
               "source_commit": frozen["source_commit"],
               "source_low_rep_receipt_sha256": frozen["source_low_rep_receipt_sha256"],
               "scope": "Only the 72 scoped/index dependency IDs in the frozen disjoint slice",
               "status": "source_proposal_only", "checks": rows,
               "native_final_source_proven_count": len(PROOFS),
               "retain_ai_count": len(EXCLUSIONS),
               "approved_initial_representatives": sum(r["initial_representatives"] for r in rows if r["decision"] == "native_final_source_proven"),
               "approved_native_fail_count": sum(r["native_fail_count"] for r in rows if r["decision"] == "native_final_source_proven")}
    Path(args.output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: receipt[k] for k in ("native_final_source_proven_count", "retain_ai_count", "approved_initial_representatives", "approved_native_fail_count")}))


if __name__ == "__main__":
    main()
