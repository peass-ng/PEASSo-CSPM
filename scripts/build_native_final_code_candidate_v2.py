#!/usr/bin/env python3
"""Build the explicit, inactive schema-v2 code candidate for 20 audited checks."""
import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_SHA256 = "3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f"
BASE_COMMIT = "d3e0e0ebfc8cf85196951460ed6db99f59e99c19"


def field(api, kind, path, field_type, *, evidence_path=None):
    return {
        "api": api,
        "field_path": path,
        "field_type": field_type,
        "source_semantics": "recorded_api_timestamp" if field_type == "timestamp" else "recorded_api_field",
        "recorded_evidence_ref": (
            f"sha256:{SNAPSHOT_SHA256}#collections[type={kind}]"
            + (".status" if evidence_path == "@" else ".items[]"
               + (f".{evidence_path or path}" if evidence_path != "." else ""))),
    }


def operation(kind, comparison, threshold=None, unit=None):
    return {"kind": kind, "comparison": comparison,
            "threshold": threshold, "threshold_unit": unit}


def captured(kind):
    return {
        "source_field": f"collections[type={kind}].items[]._provenance.collected_at or snapshot.created_at",
        "recorded_evidence_ref": (
            f"sha256:{SNAPSHOT_SHA256}#collections[type={kind}].items[]._provenance.collected_at|created_at"),
    }


# Every entry was selected by the separate evaluator/helper proof ledger. The
# schema operation describes the predicate class; that ledger preserves exact
# branching, joins, missing-field semantics, and boundary comparisons.
SPECS = {
    "aws.claude_a.iam.role_used_within_60_days": (
        [field("iam:ListRoles", "iam_role", "CreateDate", "timestamp"),
         field("iam:ListRoles", "iam_role", "RoleLastUsed.LastUsedDate", "timestamp"),
         field("iam:ListRoles", "iam_role", "RoleName", "enum"),
         field("iam:ListRoles", "iam_role", "RoleId", "enum"),
         field("iam:ListRoles", "iam_role", "Arn", "enum")],
        operation("age_comparison", "gt", 60, "days"), captured("iam_role")),
    "aws.cb.secretsmanager.changed_within_90_days": (
        [field("secretsmanager:ListSecrets", "secret", "LastChangedDate", "timestamp")],
        operation("age_comparison", "gt", 90, "days"), captured("secret")),
    "aws.cb.secretsmanager.changed_within_365_days": (
        [field("secretsmanager:ListSecrets", "secret", "LastChangedDate", "timestamp")],
        operation("age_comparison", "gt", 365, "days"), captured("secret")),
    "aws.b.ecs.all_readonly_roots": (
        [field("ecs:DescribeTaskDefinition", "ecs_task_definition",
               "Definition.taskDefinition.containerDefinitions[].readonlyRootFilesystem", "list",
               evidence_path="Definition.taskDefinition.containerDefinitions")],
        operation("list_membership", "contains", False), None),
    "aws.a.iam.active_key_age_90": (
        [field("iam:ListAccessKeys", "iam_access_key", "Status", "enum"),
         field("iam:ListAccessKeys", "iam_access_key", "CreateDate", "timestamp")],
        operation("age_comparison", "gte", 90, "days"), captured("iam_access_key")),
    "aws.claude_a.iam.user_long_lived_keys_only_iam_sts": (
        [field("iam:ListAccessKeys", "iam_user", "AccessKeys.items", "list"),
         field("iam:GetServiceLastAccessedDetails", "iam_user",
               "ServicesLastAccessed[].ServiceNamespace", "list")],
        operation("boolean_combination", "and"), None),
    "aws.claude_a.iam.access_key_age_365": (
        [field("iam:ListAccessKeys", "iam_access_key", "CreateDate", "timestamp")],
        operation("age_comparison", "gte", 365, "days"), captured("iam_access_key")),
    "aws.c2b.elbv2.listeners_acm_certificate": (
        [field("elbv2:DescribeLoadBalancers", "load_balancer", "Type", "enum"),
         field("elbv2:DescribeListeners", "load_balancer",
               "Listeners.items[].Certificates[].CertificateArn", "list")],
        operation("boolean_combination", "or"), None),
    "aws.claude_a.ec2.instance_not_older_than_180_days": (
        [field("ec2:DescribeInstances", "instance", "LaunchTime", "timestamp")],
        operation("age_comparison", "gt", 180, "days"), captured("instance")),
    "aws.a.cloudwatch.finite_retention_365": (
        [field("logs:DescribeLogGroups", "log_group", "logGroupName", "enum"),
         field("logs:DescribeLogGroups", "log_group", "retentionInDays", "number")],
        operation("boolean_combination", "or"), None),
    "aws.a.cloudwatch.log_retention_at_least_365": (
        [field("logs:DescribeLogGroups", "log_group", "logGroupName", "enum"),
         field("logs:DescribeLogGroups", "log_group", "retentionInDays", "number")],
        operation("boolean_combination", "and"), None),
    "aws.c2b.cloudfront.pqc_tls": (
        [field("cloudfront:GetDistributionConfig", "cloudfront_distribution",
               "Config.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate", "boolean"),
         field("cloudfront:GetDistributionConfig", "cloudfront_distribution",
               "Config.DistributionConfig.ViewerCertificate.MinimumProtocolVersion", "enum")],
        operation("boolean_combination", "or"), None),
    "aws_backup_failure_notification": (
        [field("backup:GetBackupVaultNotifications", "backup_vault", "Notifications.collection_status", "enum"),
         field("backup:GetBackupVaultNotifications", "backup_vault", "Notifications.absent", "boolean"),
         field("backup:GetBackupVaultNotifications", "backup_vault", "Notifications.SNSTopicArn", "enum",
               evidence_path="Notifications"),
         field("backup:GetBackupVaultNotifications", "backup_vault", "Notifications.BackupVaultEvents", "list",
               evidence_path="Notifications")],
        operation("boolean_combination", "or"), None),
    "aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled": (
        [field("rds:DescribeDBInstances", "rds_instance", "MonitoringInterval", "number"),
         field("rds:DescribeDBInstances", "rds_instance", "MonitoringRoleArn", "enum",
               evidence_path="."),
         field("rds:DescribeDBInstances", "rds_instance", "EnhancedMonitoringResourceArn", "enum",
               evidence_path="."),
         field("rds:DescribeDBClusters", "rds_cluster", "DBClusterMembers[].DBInstanceIdentifier", "list",
               evidence_path="@")],
        operation("boolean_combination", "or"), None),
    "aws.c2b.autoscaling.instance_types_per_az": (
        [field("autoscaling:DescribeAutoScalingGroups", "autoscaling_group",
               "Instances[].AvailabilityZone", "list"),
         field("autoscaling:DescribeAutoScalingGroups", "autoscaling_group",
               "Instances[].InstanceType", "list")],
        operation("boolean_combination", "or"), None),
    "aws.c2b.cloudfront.s3_origin_access_control": (
        [field("cloudfront:GetDistributionConfig", "cloudfront_distribution",
               "Config.DistributionConfig.Origins.Items[].S3OriginConfig", "list"),
         field("cloudfront:GetDistributionConfig", "cloudfront_distribution",
               "Config.DistributionConfig.Origins.Items[].OriginAccessControlId", "list")],
        operation("boolean_combination", "and"), None),
    "aws.claude_a.s3.prowler_cross_region_replication": (
        [field("s3:GetBucketVersioning", "bucket", "Versioning.Status", "enum"),
         field("s3:GetBucketReplication", "bucket", "Replication.ReplicationConfiguration.Rules[].Status", "list",
               evidence_path="Replication"),
         field("s3:GetBucketReplication", "bucket",
               "Replication.ReplicationConfiguration.Rules[].Destination.Bucket", "list",
               evidence_path="Replication"),
         field("s3:GetBucketLocation", "bucket", "Location.LocationConstraint", "enum")],
        operation("boolean_combination", "or"), None),
    "aws.pci.sns.delivery_status_logging": (
        [field("sns:ListSubscriptions", "sns_subscription", "TopicArn", "enum"),
         field("sns:ListSubscriptions", "sns_subscription", "Protocol", "enum"),
         field("sns:GetTopicAttributes", "sns_topic", "Attributes.Attributes.TopicArn", "enum")]
        + [field("sns:GetTopicAttributes", "sns_topic", f"Attributes.Attributes.{prefix}{suffix}", "enum",
                 evidence_path="Attributes.Attributes")
           for prefix in ("HTTP", "Lambda", "SQS", "Application", "Firehose")
           for suffix in ("FailureFeedbackRoleArn", "SuccessFeedbackRoleArn", "SuccessFeedbackSampleRate")],
        operation("boolean_combination", "or"), None),
    "aws_fedramp_acm_all_certificates_30_day_expiry": (
        [field("acm:ListCertificates", "acm_certificate", "CertificateArn", "enum"),
         field("acm:DescribeCertificate", "acm_certificate", "Certificate.Certificate.Status", "enum"),
         field("acm:DescribeCertificate", "acm_certificate", "Certificate.Certificate.NotAfter", "timestamp")],
        operation("age_comparison", "lte", 30, "days"), captured("acm_certificate")),
    "aws_g6_acm_all_certificates_30_day_expiry": (
        [field("acm:ListCertificates", "acm_certificate", "CertificateArn", "enum"),
         field("acm:DescribeCertificate", "acm_certificate", "Certificate.Certificate.Status", "enum"),
         field("acm:DescribeCertificate", "acm_certificate", "Certificate.Certificate.NotAfter", "timestamp")],
        operation("age_comparison", "lt", 30, "days"), captured("acm_certificate")),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    proofs = json.loads((ROOT / "docs/ai-review/native-final-proofs-v3.json").read_text())
    numeric_path = ROOT / "outputs/native-final-audit-992-v3-numeric.json"
    numeric = json.loads(numeric_path.read_text())
    receipt_sha = hashlib.sha256(numeric_path.read_bytes()).hexdigest()
    approved = proofs["approved_check_proofs"]
    counts = {row["check_id"]: row for row in numeric["per_check"]}
    if set(SPECS) != set(approved) or len(SPECS) != 20:
        raise ValueError("explicit candidate differs from signed high-representative approvals")
    checks = []
    for ident in sorted(SPECS):
        fields, op, scan_time = SPECS[ident]
        source = approved[ident]["code_path_audit_ref"]
        if (hashlib.sha256((ROOT / source["path"]).read_bytes()).hexdigest()
                != source["source_sha256"]):
            raise ValueError("approved whole-file source changed: " + ident)
        row = counts[ident]
        if row["ai_disagreement"] or row["v3_decision"] != "native_final_proposed":
            raise ValueError("unapproved or disagreed check: " + ident)
        checks.append({
            "check_id": ident,
            "prod992_disagreements": 0,
            "prod992_reviewed_failures": row["ai_verdicts"]["FAIL"],
            "audit_receipt_sha256": receipt_sha,
            "deterministic_evidence": {
                "source_fields": fields,
                "operation": op,
                "scan_time": scan_time,
                "code_path_audit_ref": source,
            },
        })
    candidate = {
        "version": 2,
        "source_scan_id": numeric["scan_id"],
        "base_commit": BASE_COMMIT,
        "replay_qualification": {"status": "pending", "receipt_sha256": None},
        "checks": checks,
    }
    Path(args.output).write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"candidate_checks": len(checks), "replay_status": "pending"}))


if __name__ == "__main__":
    main()
