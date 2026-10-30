#!/usr/bin/env python3
"""Extend the inactive high-20 manifest with 64 explicitly reviewed scoped proofs."""
import argparse
import hashlib
import json
from pathlib import Path

from build_native_final_code_candidate_v2 import ROOT, SNAPSHOT_SHA256, field, operation, captured


SCOPED_RECEIPT = ROOT / "docs/ai-review/native-final-scoped-low-rep-proofs-v3.json"
SCOPED_SHA256 = "d244169401807d3ebb2f98cc87c50b934d637b9841a4edac2f273ea0e0120889"
SOURCE_LOW_SHA256 = "333ccb7146e02db59f14b2f8056c54bcbad266c5b55e696ced3ab5f19eb52eb3"
RUNTIME_SOURCE_SHA256 = "969058175c791c7b7e16c60483ab0e51a09cd7d1567171e961d4f02c015fc8c1"
HIGH_CANDIDATE = ROOT / "docs/ai-review/native-final-code-manifest-v2-candidate-high20.json"
HIGH_SHA256 = "1e88920d30f115f653902827fb2f75a5a5aaffbb3db4c80037864aa13300fb90"


def f(api, kind, path, typ, observed=None):
    return field(api, kind, path, typ, evidence_path=observed)


def inventory(api, kind, result_field):
    """A successful empty List response is pinned by collection status."""
    return f(api, kind, result_field, "list", "@")


SPECS = {}


def add(ids, fields, op, scan_time=None):
    for ident in ids.split():
        if ident in SPECS:
            raise ValueError("duplicate scoped spec: " + ident)
        SPECS[ident] = (fields, op, scan_time)


# CloudTrail and regional service inventories.
add("aws.a.cloudtrail.cloudwatch_delivery_24h",
    [f("cloudtrail:GetTrailStatus", "cloudtrail", "Status.LatestCloudWatchLogsDeliveryTime", "timestamp", "Status"),
     f("cloudtrail:GetTrailStatus", "cloudtrail", "Status.collection_status", "enum")],
    operation("age_comparison", "gt", 1, "days"), captured("cloudtrail"))
add("aws.a.cloudtrail.home_cloudwatch_date",
    [f("cloudtrail:DescribeTrails", "cloudtrail", "HomeRegion", "enum"),
     f("cloudtrail:DescribeTrails", "cloudtrail", "CloudWatchLogsLogGroupArn", "enum", "."),
     f("cloudtrail:GetTrailStatus", "cloudtrail", "Status.LatestCloudWatchLogsDeliveryTime", "timestamp", "Status")],
    operation("age_comparison", "gt", 1, "days"), captured("cloudtrail"))
add("aws.a.config.region_recorder_enabled",
    [inventory("config:DescribeConfigurationRecorders", "config_recorder", "ConfigurationRecorders[]"),
     inventory("config:DescribeConfigurationRecorderStatus", "config_recorder", "ConfigurationRecordersStatus[]")],
    operation("boolean_combination", "or"))
add("aws.a.guardduty.region_enabled",
    [inventory("guardduty:ListDetectors", "guardduty_detector", "DetectorIds[]"),
     f("guardduty:GetDetector", "guardduty_detector", "Configuration.Status", "enum", "Configuration")],
    operation("boolean_combination", "or"))

# Credential-report timestamps are compared only by the reviewed strict helper.
credential = [f("iam:GetCredentialReport", "iam_credential_report", p, t)
              for p, t in (("ReportGeneratedTime", "timestamp"), ("user", "enum"),
                           ("password_enabled", "boolean"), ("password_last_used", "timestamp"),
                           ("access_key_1_active", "boolean"), ("access_key_1_last_used_date", "timestamp"),
                           ("access_key_2_active", "boolean"), ("access_key_2_last_used_date", "timestamp"))]
add("aws.a.iam.unused_credentials_45_days aws.claude_a.iam.access_keys_used_45 aws.gap.iam.active_keys_used_within_45_days",
    credential, operation("age_comparison", "gt", 45, "days"), captured("iam_credential_report"))
add("aws.a.iam.unused_credentials_90_days", credential,
    operation("age_comparison", "gt", 90, "days"), captured("iam_credential_report"))

add("aws.b.backup_plan.regional_presence",
    [inventory("backup:ListBackupPlans", "backup_plan", "BackupPlansList[]")],
    operation("count_comparison", "eq", 0, "items"))
add("aws.b.backup_vault.regional_presence",
    [inventory("backup:ListBackupVaults", "backup_vault", "BackupVaultList[]")],
    operation("count_comparison", "eq", 0, "items"))
add("aws.b.backup.report_plan_presence aws.c2b.backup.report_plans_when_plans",
    [f("backup:ListBackupPlans", "backup_plan", "BackupPlansList[]", "list", "@"),
     inventory("backup:ListReportPlans", "backup_report_plan", "ReportPlans[]")],
    operation("boolean_combination", "and"))
add("aws.b.efs.customer_managed_key",
    [f("elasticfilesystem:DescribeFileSystems", "efs_file_system", "Encrypted", "boolean"),
     f("elasticfilesystem:DescribeFileSystems", "efs_file_system", "KmsKeyId", "enum"),
     f("kms:DescribeKey", "kms_key", "Metadata.KeyMetadata.KeyManager", "enum", "Metadata.KeyMetadata"),
     f("kms:DescribeKey", "kms_key", "Metadata.KeyMetadata.Enabled", "boolean", "Metadata.KeyMetadata")],
    operation("boolean_combination", "or"))
add("aws.c2b.bedrock.guardrails_configured",
    [inventory("bedrock:ListGuardrails", "bedrock_guardrail", "guardrails[]")],
    operation("count_comparison", "eq", 0, "items"))
add("aws.c2b.bedrock.prompt_management_exists",
    [inventory("bedrock-agent:ListPrompts", "bedrock_prompt", "promptSummaries[]")],
    operation("count_comparison", "eq", 0, "items"))
add("aws.c2b.ecr.registry_enhanced_scanning",
    [f("ecr:GetRegistryScanningConfiguration", "ecr_registry_scanning_configuration", "scanningConfiguration.scanType", "enum"),
     f("ecr:DescribeRepositories", "ecr_repository", "repositoryArn", "enum")],
    operation("boolean_combination", "and"))
add("aws.c2b.elasticache.cmk_enabled",
    [f("elasticache:DescribeReplicationGroups", "elasticache_replication_group", "AtRestEncryptionEnabled", "boolean"),
     f("elasticache:DescribeReplicationGroups", "elasticache_replication_group", "KmsKeyId", "enum", "."),
     f("kms:DescribeKey", "kms_key", "Metadata.KeyMetadata.Enabled", "boolean", "Metadata.KeyMetadata")],
    operation("boolean_combination", "or"))

emr = [f("emr:DescribeCluster", "emr_cluster", "Cluster.Cluster.SecurityConfiguration", "enum", "Cluster.Cluster"),
       inventory("emr:DescribeSecurityConfiguration", "emr_security_configuration", "SecurityConfiguration[]")]
for suffix, path, threshold in (
        ("at_rest_cse_custom", "EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode", "CSE-Custom"),
        ("at_rest_encryption", "EncryptionConfiguration.EnableAtRestEncryption", True),
        ("at_rest_sse_kms", "EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode", "SSE-KMS"),
        ("in_transit_encryption", "EncryptionConfiguration.EnableInTransitEncryption", True),
        ("local_disk_cmk", "EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType", "Custom"),
        ("local_disk_encryption", "EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration", True)):
    add("aws.c2b.emr.cluster_" + suffix,
        [*emr, f("emr:DescribeSecurityConfiguration", "emr_security_configuration", path,
                 "boolean" if isinstance(threshold, bool) else "enum", "@")],
        operation("boolean_combination", "or"))

add("aws.cb.glue.catalog_metadata_sse_kms_with_tables",
    [f("glue:GetDataCatalogEncryptionSettings", "glue_data_catalog", "EncryptionSettings.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode", "enum", "EncryptionSettings.DataCatalogEncryptionSettings"),
     f("glue:GetTables", "glue_table", "TableList[]", "list", "@")],
    operation("boolean_combination", "and"))
add("aws.cb.glue.catalog_password_encryption_with_tables",
    [f("glue:GetDataCatalogEncryptionSettings", "glue_data_catalog", "EncryptionSettings.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted", "boolean", "EncryptionSettings.DataCatalogEncryptionSettings"),
     f("glue:GetTables", "glue_table", "TableList[]", "list", "@")],
    operation("boolean_combination", "and"))
add("aws.cb.lambda.runtime_not_deprecated_list",
    [f("lambda:ListFunctions", "lambda_function", "Runtime", "enum"),
     f("lambda:ListFunctions", "lambda_function", "PackageType", "enum")],
    {"kind": "versioned_lookup_date", "comparison": "gte", "threshold": None,
     "threshold_unit": None,
     "lookup_table": {"symbol": "RUNTIME_DEPRECATION",
                      "source_sha256": RUNTIME_SOURCE_SHA256,
                      "reviewed_at": "2026-10-12",
                      "valid_through_symbol": "RUNTIME_POLICY_VALID_THROUGH",
                      "audit_ref": "peaso/checks/claude_aws_b_compute.py:109-158"}},
    {"source_field": "context.created_at",
     "recorded_evidence_ref": f"sha256:{SNAPSHOT_SHA256}#created_at"})

subscription = [f("rds:DescribeEventSubscriptions", "rds_event_subscription", "EventSubscriptionsList[]", "list", "@"),
                f("rds:DescribeDBInstances", "rds_instance", "DBInstanceIdentifier", "enum")]
add("aws.cb.rds.instance_critical_event_subscription aws.cb.rds.parameter_group_critical_event_subscription aws.cb.rds.security_group_critical_event_subscription",
    subscription, operation("boolean_combination", "and"))
add("aws.cb.rds.instance_multi_az_or_cluster",
    [f("rds:DescribeDBInstances", "rds_instance", "MultiAZ", "boolean"),
     inventory("rds:DescribeDBClusters", "rds_cluster", "DBClusters[]")],
    operation("boolean_combination", "or"))

add("aws.cb.secretsmanager.accessed_within_90_calendar_days aws.cb.secretsmanager.accessed_within_90_days",
    [f("secretsmanager:ListSecrets", "secret", "LastAccessedDate", "timestamp", "."),
     f("secretsmanager:ListSecrets", "secret", "ARN", "enum")],
    operation("age_comparison", "gt", 90, "days"), captured("secret"))
add("aws.cb.secretsmanager.cmk_encryption",
    [f("secretsmanager:DescribeSecret", "secret", "KmsKeyId", "enum", "."),
     f("secretsmanager:DescribeSecret", "secret", "_coverage.KmsKeyId", "enum"),
     f("kms:DescribeKey", "kms_key", "Metadata.KeyMetadata.KeyManager", "enum", "Metadata.KeyMetadata")],
    operation("boolean_combination", "or"))
add("aws.cb.secretsmanager.rotated_as_scheduled",
    [f("secretsmanager:DescribeSecret", "secret", "_coverage.RotationRules.status", "enum"),
     f("secretsmanager:DescribeSecret", "secret", "RotationRules.AutomaticallyAfterDays", "number", "."),
     f("secretsmanager:ListSecrets", "secret", "CreatedDate", "timestamp"),
     f("secretsmanager:DescribeSecret", "secret", "LastRotatedDate", "timestamp", ".")],
    operation("age_comparison", "gt", 0, "days"), captured("secret"))
add("aws.cb.secretsmanager.rotated_within_90_days",
    [f("secretsmanager:DescribeSecret", "secret", "LastRotatedDate", "timestamp", "."),
     f("secretsmanager:ListSecrets", "secret", "ARN", "enum")],
    operation("age_comparison", "gt", 90, "days"), captured("secret"))
add("aws.cb.secretsmanager.rotation_lambda",
    [f("secretsmanager:DescribeSecret", "secret", "_coverage.RotationRules.status", "enum"),
     f("secretsmanager:DescribeSecret", "secret", "RotationLambdaARN", "enum", ".")],
    operation("boolean_combination", "or"))
add("aws.cb.secretsmanager.rotation_rules_present",
    [f("secretsmanager:DescribeSecret", "secret", "RotationEnabled", "boolean"),
     f("secretsmanager:DescribeSecret", "secret", "_coverage.RotationRules", "enum")],
    operation("boolean_combination", "or"))

add("aws.claude_a.ec2.account_imdsv2_default",
    [f("ec2:GetInstanceMetadataDefaults", "ec2_regional_settings", "InstanceMetadataDefaults.HttpTokens", "enum", "InstanceMetadataDefaults"),
     f("ec2:DescribeInstances", "instance", "InstanceId", "enum")],
    operation("boolean_combination", "and"))
add("aws.claude_a.guardduty.prowler_delegated_admin_region",
    [inventory("guardduty:ListDetectors", "guardduty_detector", "DetectorIds[]"),
     inventory("guardduty:ListOrganizationAdminAccounts", "guardduty_organization_admin_account", "AdminAccounts[]"),
     f("guardduty:GetDetector", "guardduty_detector", "Configuration.Status", "enum", "Configuration")],
    operation("boolean_combination", "or"))
add("aws.claude_a.guardduty.region_centrally_configured",
    [inventory("guardduty:ListDetectors", "guardduty_detector", "DetectorIds[]"),
     f("guardduty:GetDetector", "guardduty_detector", "Administrator.AccountId", "enum", "Administrator")],
    operation("boolean_combination", "or"))
add("aws.claude_a.iam.access_keys_rotated_90",
    [f("iam:GetCredentialReport", "iam_credential_report", "access_key_1_last_rotated", "timestamp"),
     f("iam:GetCredentialReport", "iam_credential_report", "access_key_2_last_rotated", "timestamp"),
     f("iam:GetCredentialReport", "iam_credential_report", "access_key_1_active", "boolean")],
    operation("age_comparison", "gt", 90, "days"), captured("iam_credential_report"))
add("aws.claude_a.iam.saml_provider_present",
    [inventory("iam:ListSAMLProviders", "iam_saml_provider", "SAMLProviderList[]")],
    operation("count_comparison", "eq", 0, "items"))
add("aws.claude_a.iam.securityaudit_role_exists aws.claude_a.iam.support_role_exists",
    [inventory("iam:ListRoles", "iam_role", "Roles[]"),
     f("iam:ListAttachedRolePolicies", "iam_role", "AttachedManagedPolicies", "list")],
    operation("boolean_combination", "and"))
add("aws.claude_a.vpc.flow_logs_active",
    [f("ec2:DescribeVpcs", "vpc", "VpcId", "enum"),
     f("ec2:DescribeFlowLogs", "flow_log", "FlowLogs[]", "list", "@")],
    operation("boolean_combination", "or"))
add("aws.gap.iam.root_not_used_90_days",
    [f("iam:GetCredentialReport", "iam_credential_report", "password_last_used", "timestamp"),
     f("iam:GetCredentialReport", "iam_credential_report", "access_key_1_last_used_date", "timestamp"),
     f("iam:GetCredentialReport", "iam_credential_report", "access_key_2_last_used_date", "timestamp")],
    operation("age_comparison", "lte", 90, "days"), captured("iam_credential_report"))
add("aws.network.target_group_has_load_balancer",
    [f("elbv2:DescribeTargetGroups", "target_group", "TargetGroupArn", "enum"),
     f("elbv2:DescribeTargetGroups", "target_group", "LoadBalancerArns", "list")],
    operation("count_comparison", "eq", 0, "items"))

trail_logs = [f("cloudtrail:DescribeTrails", "cloudtrail", "HomeRegion", "enum"),
              f("cloudtrail:DescribeTrails", "cloudtrail", "CloudWatchLogsLogGroupArn", "enum", "."),
              f("cloudtrail:GetTrailStatus", "cloudtrail", "Status.IsLogging", "boolean", "Status"),
              f("logs:DescribeLogGroups", "cloudwatch_log_group", "logGroupArn", "enum")]
add("aws.nist.cloudtrail_cloudwatch_integration aws_g6_cloudtrail_all_trails_cloudwatch_integration",
    trail_logs, operation("boolean_combination", "and"))
add("aws.pci.shield.protection_all_internet_resources",
    [inventory("shield:ListProtections", "shield_protection", "Protections[]"),
     f("elbv2:DescribeLoadBalancers", "load_balancer", "Scheme", "enum"),
     f("cloudfront:ListDistributions", "cloudfront_distribution", "ARN", "enum")],
    operation("boolean_combination", "and"))
add("aws_cis_elbv2_only_tls_listeners aws_g6_elbv2_only_https_tls_listeners",
    [f("elbv2:DescribeLoadBalancers", "load_balancer", "Type", "enum"),
     f("elbv2:DescribeListeners", "load_balancer", "Listeners.items[].Protocol", "list", "Listeners"),
     f("elbv2:DescribeListeners", "load_balancer", "Listeners.collection_status", "enum", "Listeners")],
    operation("boolean_combination", "or"))
add("aws_cis_lambda_config_recorded",
    [f("lambda:ListFunctions", "lambda_function", "FunctionArn", "enum"),
     inventory("config:DescribeConfigurationRecorders", "config_recorder", "ConfigurationRecorders[]")],
    operation("boolean_combination", "or"))
trail_kms = [f("cloudtrail:DescribeTrails", "cloudtrail", "KmsKeyId", "enum", "."),
             f("cloudtrail:DescribeTrails", "cloudtrail", "CloudWatchLogsLogGroupArn", "enum", "."),
             f("kms:DescribeKey", "kms_key", "Metadata.KeyMetadata.KeyManager", "enum", "Metadata.KeyMetadata"),
             f("kms:DescribeKey", "kms_key", "Metadata.KeyMetadata.KeyState", "enum", "Metadata.KeyMetadata"),
             f("logs:DescribeLogGroups", "cloudwatch_log_group", "logGroupArn", "enum")]
add("aws_fedramp_cloudtrail_destination_kms aws_g6_cloudtrail_kms_destination_join aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk",
    trail_kms, operation("boolean_combination", "or"))
add("aws_g6_api_stage_effective_waf_acl",
    [f("apigateway:GetStage", "rest_api_stage", "webAclArn", "enum", "."),
     f("wafv2:GetWebACLForResource", "stage_waf_association", "webAclArn", "enum"),
     inventory("wafv2:ListWebACLs", "wafv2_web_acl", "WebACLs[]")],
    operation("boolean_combination", "or"))
add("aws_g6_ecs_all_containers_logging",
    [f("ecs:DescribeTaskDefinition", "ecs_task_definition", "Definition.taskDefinition.status", "enum", "Definition.taskDefinition"),
     f("ecs:DescribeTaskDefinition", "ecs_task_definition", "Definition.taskDefinition.containerDefinitions", "list", "Definition.taskDefinition")],
    operation("boolean_combination", "or"))
add("aws_lambda_code_signing_configured",
    [f("lambda:ListFunctions", "lambda_function", "PackageType", "enum"),
     f("lambda:GetFunctionCodeSigningConfig", "lambda_function", "CodeSigning.CodeSigningConfigArn", "enum", "CodeSigning"),
     f("lambda:GetFunctionCodeSigningConfig", "lambda_function", "CodeSigning.collection_status", "enum")],
    operation("boolean_combination", "or"))
add("aws_nist_dynamodb_table_encrypted_with_kms",
    [f("dynamodb:DescribeTable", "dynamodb_table", "Table.Table.SSEDescription.SSEType", "enum", "Table.Table"),
     f("dynamodb:DescribeTable", "dynamodb_table", "Table.Table.SSEDescription.Status", "enum", "Table.Table"),
     f("dynamodb:DescribeTable", "dynamodb_table", "Table.Table.TableName", "enum")],
    operation("boolean_combination", "or"))
add("aws_nist_s3_bucket_cross_region_replication_enabled",
    [f("s3:GetBucketReplication", "bucket", "Replication.ReplicationConfiguration.Rules", "list", "Replication"),
     f("s3:GetBucketLocation", "bucket", "Location.LocationConstraint", "enum", "Location")],
    operation("boolean_combination", "or"))
add("aws_route53_hosted_zone_dnssec_enabled",
    [f("route53:GetDNSSEC", "route53_zone", "DNSSEC.Status.ServeSignature", "enum"),
     f("route53:GetDNSSEC", "route53_zone", "DNSSEC.KeySigningKeys", "list")],
    operation("boolean_combination", "or"))
alarm = [inventory("cloudwatch:DescribeAlarms", "cloudwatch_alarm", "MetricAlarms[]"),
         f("cloudwatch:DescribeAlarms", "cloudwatch_alarm", "Namespace", "enum", "@"),
         f("cloudwatch:DescribeAlarms", "cloudwatch_alarm", "MetricName", "enum", "@")]
add("aws_sns_delivery_failure_alarm_present",
    [*alarm, f("sns:ListTopics", "sns_topic", "TopicArn", "enum")],
    operation("boolean_combination", "and"))
add("aws_sqs_queue_depth_alarm_present",
    [*alarm, f("sqs:ListQueues", "sqs_queue", "QueueUrl", "enum")],
    operation("boolean_combination", "and"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    scoped_raw = SCOPED_RECEIPT.read_bytes()
    high_raw = HIGH_CANDIDATE.read_bytes()
    if hashlib.sha256(scoped_raw).hexdigest() != SCOPED_SHA256:
        raise ValueError("scoped source proof receipt changed")
    if hashlib.sha256(high_raw).hexdigest() != HIGH_SHA256:
        raise ValueError("high-20 candidate changed")
    scoped = json.loads(scoped_raw)
    high = json.loads(high_raw)
    if (scoped["source_low_rep_receipt_sha256"] != SOURCE_LOW_SHA256 or
            scoped["status"] != "source_proposal_only" or
            high["replay_qualification"] != {"status": "pending", "receipt_sha256": None}):
        raise ValueError("source binding or replay state changed")
    approved = {r["check_id"]: r for r in scoped["checks"]
                if r["decision"] == "native_final_source_proven"}
    if len(SPECS) != 64 or set(SPECS) != set(approved):
        raise ValueError("scoped specs differ from 64 explicit approvals")
    checks = list(high["checks"])
    for ident in sorted(SPECS):
        row = approved[ident]
        fields, op, scan_time = SPECS[ident]
        evaluator = row["evaluator"]
        path = evaluator["path"]
        source_sha = row["source_file_sha256"][path]
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != source_sha:
            raise ValueError("whole-file evaluator hash changed: " + ident)
        if ident == "aws.cb.lambda.runtime_not_deprecated_list" and source_sha != RUNTIME_SOURCE_SHA256:
            raise ValueError("versioned runtime table source changed")
        if row["ai_verdict_counts"] != {"FAIL": row["native_fail_count"]}:
            raise ValueError("scoped verdict changed: " + ident)
        checks.append({"check_id": ident, "prod992_disagreements": 0,
                       "prod992_reviewed_failures": row["native_fail_count"],
                       "audit_receipt_sha256": SCOPED_SHA256,
                       "deterministic_evidence": {
                           "source_fields": fields, "operation": op, "scan_time": scan_time,
                           "code_path_audit_ref": {
                               "path": path, "symbol": evaluator["symbol"],
                               "source_sha256": source_sha,
                               "audit_ref": f"docs/ai-review/native-final-scoped-low-rep-proofs-v3.json#{ident}",
                           }}})
    checks.sort(key=lambda row: row["check_id"])
    if len(checks) != 84 or len({r["check_id"] for r in checks}) != 84:
        raise ValueError("84-check candidate count/uniqueness changed")
    high["checks"] = checks
    Path(args.output).write_text(json.dumps(high, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"candidate_checks": len(checks), "scoped_added": len(SPECS),
                      "replay_status": high["replay_qualification"]["status"]}))


if __name__ == "__main__":
    main()
