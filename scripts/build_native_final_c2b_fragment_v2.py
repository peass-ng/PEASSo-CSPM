#!/usr/bin/env python3
"""Build the inactive schema-v2 fragment from 24 explicit c2b source proofs."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "docs/ai-review/native-final-c2b-low-rep-proofs-v1.json"
PROOF_SHA = "2faa2cd0f4244b22ce7337905104dbbbf78ea0c79aaf5503f044277d0fee51ca"
SNAP_SHA = "3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f"
OUT = ROOT / "docs/ai-review/native-final-code-manifest-v2-fragment-c2b24.json"


def F(api, path, typ, evidence):
    return (api, path, typ, evidence)


def O(kind, comparison, threshold, unit=None):
    return {"kind": kind, "comparison": comparison, "threshold": threshold, "threshold_unit": unit}


# Explicitly reviewed per-check inputs and operations. Evidence references point
# to the exact recorded field, or to its complete parent response when the FAIL
# predicate depends on documented optional omission. No name-based admission.
SPEC = {
    "aws.c2b.apigateway.methods_request_validator": ([F("apigateway:GetResources(embed=methods)", "Resources.items[].resourceMethods.*.requestValidatorId", "list", "Resources.items[]")], O("list_membership", "not_contains", "requestValidatorId")),
    "aws.c2b.apigateway.stage_execution_logging": ([F("apigateway:GetStages", "methodSettings.*.loggingLevel", "list", "methodSettings")], O("count_comparison", "eq", 0, "items")),
    "aws.c2b.athena.cloudwatch_metrics": ([F("athena:GetWorkGroup", "WorkGroup.WorkGroup.Configuration.PublishCloudWatchMetricsEnabled", "boolean", "WorkGroup.WorkGroup.Configuration")], O("literal_comparison", "eq", False)),
    "aws.c2b.athena.cloudwatch_metrics_prowler": ([F("athena:GetWorkGroup", "WorkGroup.WorkGroup.State", "enum", "WorkGroup.WorkGroup.State"), F("athena:GetWorkGroup", "WorkGroup.WorkGroup.Configuration.PublishCloudWatchMetricsEnabled", "boolean", "WorkGroup.WorkGroup.Configuration")], O("boolean_combination", "and", None)),
    "aws.c2b.athena.enforce_configuration": ([F("athena:GetWorkGroup", "WorkGroup.WorkGroup.Configuration.EnforceWorkGroupConfiguration", "boolean", "WorkGroup.WorkGroup.Configuration")], O("literal_comparison", "eq", False)),
    "aws.c2b.athena.enforce_configuration_prowler": ([F("athena:GetWorkGroup", "WorkGroup.WorkGroup.State", "enum", "WorkGroup.WorkGroup.State"), F("athena:GetWorkGroup", "WorkGroup.WorkGroup.Configuration.EnforceWorkGroupConfiguration", "boolean", "WorkGroup.WorkGroup.Configuration")], O("boolean_combination", "and", None)),
    "aws.c2b.athena.results_encrypted": ([F("athena:GetWorkGroup", "WorkGroup.WorkGroup.Configuration.ManagedQueryResultsConfiguration.Enabled", "boolean", "WorkGroup.WorkGroup.Configuration"), F("athena:GetWorkGroup", "WorkGroup.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption", "enum", "WorkGroup.WorkGroup.Configuration")], O("boolean_combination", "and", None)),
    "aws.c2b.athena.results_encrypted_prowler": ([F("athena:GetWorkGroup", "WorkGroup.WorkGroup.State", "enum", "WorkGroup.WorkGroup.State"), F("athena:GetWorkGroup", "WorkGroup.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption", "enum", "WorkGroup.WorkGroup.Configuration")], O("boolean_combination", "and", None)),
    "aws.c2b.autoscaling.mixed_policy_multiple_types": ([F("autoscaling:DescribeAutoScalingGroups", "MixedInstancesPolicy.LaunchTemplate.Overrides[].InstanceType", "list", "")], O("count_comparison", "lt", 2, "items")),
    "aws.c2b.dynamodb.sse_kms": ([F("dynamodb:DescribeTable", "Table.Table.SSEDescription.SSEType", "enum", "Table.Table")], O("literal_comparison", "ne", "KMS")),
    "aws.c2b.ecs.cluster_has_active_services": ([F("ecs:DescribeClusters", "Configuration.clusters[].activeServicesCount", "number", "Configuration.clusters[].activeServicesCount"), F("ecs:DescribeClusters", "Configuration.clusters[].clusterArn", "enum", "Configuration.clusters[]")], O("count_comparison", "lte", 0, "items")),
    "aws.c2b.ecs.container_insights": ([F("ecs:DescribeClusters(include=SETTINGS,CONFIGURATIONS)", "Configuration.clusters[].settings[].name", "enum", "Configuration.clusters[]"), F("ecs:DescribeClusters(include=SETTINGS,CONFIGURATIONS)", "Configuration.clusters[].settings[].value", "enum", "Configuration.clusters[]")], O("boolean_combination", "and", None)),
    "aws.c2b.ecs.container_insights_setting": ([F("ecs:DescribeClusters(include=SETTINGS,CONFIGURATIONS)", "Configuration.clusters[].settings[].name", "enum", "Configuration.clusters[]"), F("ecs:DescribeClusters(include=SETTINGS,CONFIGURATIONS)", "Configuration.clusters[].settings[].value", "enum", "Configuration.clusters[]")], O("boolean_combination", "or", None)),
    "aws.c2b.ecs.service_load_balancer_attached": ([F("ecs:DescribeServices", "loadBalancers", "list", "loadBalancers")], O("count_comparison", "eq", 0, "items")),
    "aws.c2b.efs.automatic_backups_enabled": ([F("efs:DescribeBackupPolicy", "BackupPolicy.BackupPolicy.Status", "enum", "BackupPolicy"), F("efs:DescribeBackupPolicy", "BackupPolicy.absent", "boolean", "BackupPolicy")], O("boolean_combination", "or", None)),
    "aws.c2b.efs.backup_not_disabled": ([F("efs:DescribeBackupPolicy", "BackupPolicy.BackupPolicy.Status", "enum", "BackupPolicy"), F("efs:DescribeBackupPolicy", "BackupPolicy.absent", "boolean", "BackupPolicy")], O("boolean_combination", "or", None)),
    "aws.c2b.elasticache.rg_backup_retention_15": ([F("elasticache:DescribeReplicationGroups", "SnapshotRetentionLimit", "number", "SnapshotRetentionLimit")], O("count_comparison", "lt", 15, "items")),
    "aws.c2b.elbv2.listener_fips_tls": ([F("elbv2:DescribeLoadBalancers", "Type", "enum", "Type"), F("elbv2:DescribeListeners", "Listeners.items[].Protocol", "enum", "Listeners.items[]"), F("elbv2:DescribeListeners", "Listeners.items[].SslPolicy", "enum", "Listeners.items[]")], O("boolean_combination", "and", None)),
    "aws.c2b.elbv2.listener_pqc_tls": ([F("elbv2:DescribeLoadBalancers", "Type", "enum", "Type"), F("elbv2:DescribeListeners", "Listeners.items[].Protocol", "enum", "Listeners.items[]"), F("elbv2:DescribeListeners", "Listeners.items[].SslPolicy", "enum", "Listeners.items[]")], O("boolean_combination", "and", None)),
    "aws.c2b.elbv2.listeners_secure_protocol": ([F("elbv2:DescribeLoadBalancers", "Type", "enum", "Type"), F("elbv2:DescribeListeners", "Listeners.items[].Protocol", "enum", "Listeners.items[]"), F("elbv2:DescribeListeners", "Listeners.items[].Port", "number", "Listeners.items[]")], O("boolean_combination", "and", None)),
    "aws.c2b.elbv2.nlb_tls_termination": ([F("elbv2:DescribeLoadBalancers", "Type", "enum", "Type"), F("elbv2:DescribeListeners", "Listeners.items[].Protocol", "enum", "Listeners.items[]")], O("boolean_combination", "and", None)),
    "aws.c2b.elbv2.recommended_tls_policy": ([F("elbv2:DescribeLoadBalancers", "Type", "enum", "Type"), F("elbv2:DescribeListeners", "Listeners.items[].Protocol", "enum", "Listeners.items[]"), F("elbv2:DescribeListeners", "Listeners.items[].SslPolicy", "enum", "Listeners.items[]")], O("boolean_combination", "and", None)),
    "aws.c2b.emr.cluster_security_configuration": ([F("emr:DescribeCluster", "Cluster.Cluster.SecurityConfiguration", "enum", "Cluster.Cluster")], O("literal_comparison", "eq", "absent")),
    "aws.c2b.lambda.runtime_not_obsolete": ([F("lambda:ListFunctions", "Runtime", "enum", "Runtime")], O("list_membership", "contains", "source-pinned OBSOLETE enum")),
}


def main():
    assert hashlib.sha256(PROOF.read_bytes()).hexdigest() == PROOF_SHA
    proof = json.loads(PROOF.read_text())
    source = {r["check_id"]: r for r in proof["checks"]}
    assert set(source) == set(SPEC) and len(source) == 24
    checks = []
    for cid, (fields, operation) in sorted(SPEC.items()):
        row = source[cid]
        assert row["decision"] == "source_proven_candidate"
        evaluator = row["evaluator_ref"]
        collector = row["collector_ref"]
        for ref in (evaluator, collector):
            assert hashlib.sha256((ROOT / ref["path"]).read_bytes()).hexdigest() == ref["source_sha256"]
        typed = [{"api": api, "field_path": field_path, "field_type": typ,
                  "source_semantics": "recorded_api_field",
                  "recorded_evidence_ref": "sha256:" + SNAP_SHA + "#collections[type=" + proof_kind(cid) + "].items[]" + ("." + evidence if evidence else "")}
                 for api, field_path, typ, evidence in fields]
        checks.append({"check_id": cid, "prod992_disagreements": 0,
                       "prod992_reviewed_failures": row["native_fail_count"],
                       "audit_receipt_sha256": PROOF_SHA,
                       "deterministic_evidence": {
                           "source_fields": typed, "operation": operation, "scan_time": None,
                           "code_path_audit_ref": {"path": evaluator["path"], "symbol": evaluator["symbol"],
                                                   "source_sha256": evaluator["source_sha256"],
                                                   "audit_ref": "docs/ai-review/native-final-c2b-low-rep-proofs-v1.json#" + cid}}})
    manifest = {"version": 2, "source_scan_id": "992d7b8cbd4340a79e41139ba1a44c1e",
                "base_commit": "d3e0e0ebfc8cf85196951460ed6db99f59e99c19",
                "replay_qualification": {"status": "pending", "receipt_sha256": None}, "checks": checks}
    OUT.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"checks": len(checks), "reviewed_failures": sum(r["prod992_reviewed_failures"] for r in checks),
                      "sha256": hashlib.sha256(OUT.read_bytes()).hexdigest()}))


def proof_kind(cid):
    if cid.endswith("methods_request_validator"):
        return "rest_api"
    if cid.endswith("stage_execution_logging"):
        return "rest_api_stage"
    if cid.endswith("service_load_balancer_attached"):
        return "ecs_service"
    return {"athena": "athena_workgroup", "autoscaling": "autoscaling_group", "dynamodb": "dynamodb_table",
            "ecs": "ecs_cluster", "efs": "efs_file_system", "elasticache": "elasticache_replication_group",
            "elbv2": "load_balancer", "emr": "emr_cluster", "lambda": "lambda_function"}[cid.split(".")[2]]


if __name__ == "__main__":
    main()
