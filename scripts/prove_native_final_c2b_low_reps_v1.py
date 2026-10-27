#!/usr/bin/env python3
"""Fail-closed, numeric-only proof for the disjoint c2b provisional slice.

This is a proposal receipt, not an activation or a replay qualification.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

from peaso.checks import CHECKS, evaluate_check


ROOT = Path(__file__).resolve().parents[1]
SOURCE_RECEIPT_SHA256 = "de1fa203a2470964000453b97ca07e157017fd79f81beb67037fa5da1bb87d3e"
PARENT_RECEIPT_SHA256 = "8c63ff60682eef64259c0946d8372b5eff82012bfaceec23d680a68b169f0845"
SNAPSHOT_SHA256 = "3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f"
PRE_AI_SHA256 = "4dcaa76a21c6b3bfff2b4859c1d4c763964c92c69041fe2d95702315fffde2ba"
NUMERIC_SHA256 = "885e63bec3551463dca3ba8b1d449ba7cc7122fbfb33a0c41184fc3e6ad94fea"


def spec(kind, predicate, evaluator_lines, collector, collector_lines, fields, completeness):
    return dict(kind=kind, predicate=predicate, evaluator_lines=evaluator_lines,
                collector=collector, collector_lines=collector_lines,
                recorded_fields=fields, completeness=completeness)


# Each admission is explicit. The line references identify the actual branch and
# helper path reviewed, rather than deriving approval from a name or evidence key.
SPECS = {
    "aws.c2b.apigateway.methods_request_validator": spec("rest_api", "Any collected method has absent requestValidatorId; observed methods establish FAIL.", "1075-1083,1195-1207", "peaso/collectors/aws_facts_compute_edge.py", "404-414,455-473", ["Resources.items[].resourceMethods.*.requestValidatorId"], "Resources child pagination collected"),
    "aws.c2b.apigateway.stage_execution_logging": spec("rest_api_stage", "No methodSettings entry has a loggingLevel other than OFF.", "1043-1048,1131-1139", "peaso/collectors/aws_b_services.py", "252-275", ["methodSettings.*.loggingLevel"], "get_stages collected; optional_fields_complete includes methodSettings"),
    "aws.c2b.athena.cloudwatch_metrics": spec("athena_workgroup", "EnforceWorkGroupConfiguration independent; PublishCloudWatchMetricsEnabled is false or absent.", "133-151,190-200", "peaso/collectors/aws_facts_data_identity.py", "415-417", ["WorkGroup.WorkGroup.Configuration.PublishCloudWatchMetricsEnabled"], "GetWorkGroup detail collected"),
    "aws.c2b.athena.cloudwatch_metrics_prowler": spec("athena_workgroup", "Enabled workgroup and PublishCloudWatchMetricsEnabled false or absent.", "133-151,190-200", "peaso/collectors/aws_facts_data_identity.py", "415-417", ["WorkGroup.WorkGroup.State", "WorkGroup.WorkGroup.Configuration.PublishCloudWatchMetricsEnabled"], "GetWorkGroup detail collected"),
    "aws.c2b.athena.enforce_configuration": spec("athena_workgroup", "EnforceWorkGroupConfiguration false or absent.", "133-151,190-200", "peaso/collectors/aws_facts_data_identity.py", "415-417", ["WorkGroup.WorkGroup.Configuration.EnforceWorkGroupConfiguration"], "GetWorkGroup detail collected"),
    "aws.c2b.athena.enforce_configuration_prowler": spec("athena_workgroup", "Enabled workgroup and EnforceWorkGroupConfiguration false or absent.", "133-151,190-200", "peaso/collectors/aws_facts_data_identity.py", "415-417", ["WorkGroup.WorkGroup.State", "WorkGroup.WorkGroup.Configuration.EnforceWorkGroupConfiguration"], "GetWorkGroup detail collected"),
    "aws.c2b.athena.results_encrypted": spec("athena_workgroup", "ManagedQueryResultsConfiguration.Enabled false or absent and EncryptionOption outside fixed SSE enum.", "133-167", "peaso/collectors/aws_facts_data_identity.py", "415-417", ["WorkGroup.WorkGroup.Configuration.ManagedQueryResultsConfiguration.Enabled", "WorkGroup.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption"], "GetWorkGroup detail collected"),
    "aws.c2b.athena.results_encrypted_prowler": spec("athena_workgroup", "Enabled workgroup and EncryptionOption outside fixed SSE enum.", "133-181", "peaso/collectors/aws_facts_data_identity.py", "415-417", ["WorkGroup.WorkGroup.State", "WorkGroup.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption"], "GetWorkGroup detail collected"),
    "aws.c2b.autoscaling.mixed_policy_multiple_types": spec("autoscaling_group", "Distinct explicit Override.InstanceType count is below two; observed FAIL rows have no mixed policy.", "950-966", "peaso/collectors/aws.py", "1067,2880-2930", ["MixedInstancesPolicy.LaunchTemplate.Overrides[].InstanceType"], "DescribeAutoScalingGroups collection collected; absent policy is complete absence"),
    "aws.c2b.dynamodb.sse_kms": spec("dynamodb_table", "DescribeTable SSEDescription.SSEType differs from KMS or is absent.", "435-438,976-983", "peaso/collectors/aws.py", "1450-1453", ["Table.Table.SSEDescription.SSEType"], "DescribeTable detail collected"),
    "aws.c2b.ecs.cluster_has_active_services": spec("ecs_cluster", "activeServicesCount <= 0.", "365-405", "peaso/collectors/aws_b_services.py", "477-480", ["activeServicesCount", "Configuration.clusters[].clusterArn"], "DescribeClusters SETTINGS/CONFIGURATIONS detail collected and unique ARN"),
    "aws.c2b.ecs.container_insights": spec("ecs_cluster", "No containerInsights setting has enabled/enhanced value.", "365-388", "peaso/collectors/aws_b_services.py", "477-480", ["Configuration.clusters[].settings[].name", "Configuration.clusters[].settings[].value"], "DescribeClusters SETTINGS/CONFIGURATIONS detail collected and unique ARN"),
    "aws.c2b.ecs.container_insights_setting": spec("ecs_cluster", "No containerInsights values or at least one is outside enabled/enhanced enum.", "365-399", "peaso/collectors/aws_b_services.py", "477-480", ["Configuration.clusters[].settings[].name", "Configuration.clusters[].settings[].value"], "DescribeClusters SETTINGS/CONFIGURATIONS detail collected and unique ARN"),
    "aws.c2b.ecs.service_load_balancer_attached": spec("ecs_service", "loadBalancers recorded list is empty.", "654-661", "peaso/collectors/aws_facts_compute_edge.py", "125-220", ["loadBalancers"], "ListServices and DescribeServices identity-checked collected response"),
    "aws.c2b.efs.automatic_backups_enabled": spec("efs_file_system", "DescribeBackupPolicy absent marker or Status != ENABLED.", "113-151", "peaso/collectors/aws_facts_data_identity.py", "442-449", ["BackupPolicy.BackupPolicy.Status", "BackupPolicy.absent"], "DescribeBackupPolicy collected or PolicyNotFound marker"),
    "aws.c2b.efs.backup_not_disabled": spec("efs_file_system", "DescribeBackupPolicy absent marker or Status in DISABLED/DISABLING.", "113-141", "peaso/collectors/aws_facts_data_identity.py", "442-449", ["BackupPolicy.BackupPolicy.Status", "BackupPolicy.absent"], "DescribeBackupPolicy collected or PolicyNotFound marker"),
    "aws.c2b.elasticache.rg_backup_retention_15": spec("elasticache_replication_group", "SnapshotRetentionLimit integer < 15.", "1078-1095", "peaso/collectors/aws.py", "2911-2927", ["SnapshotRetentionLimit"], "DescribeReplicationGroups complete native response; field present in FAIL"),
    "aws.c2b.elbv2.listener_fips_tls": spec("load_balancer", "At least one HTTPS/TLS SslPolicy enum lacks FIPS token.", "507-523,587-601", "peaso/collectors/aws.py", "1431-1439", ["Type", "Listeners.items[].Protocol", "Listeners.items[].SslPolicy"], "DescribeListeners pagination collected with LoadBalancerArn identity guard"),
    "aws.c2b.elbv2.listener_pqc_tls": spec("load_balancer", "At least one HTTPS/TLS SslPolicy outside source-pinned PQ policy enum.", "507-523,603-613", "peaso/collectors/aws.py", "1431-1439", ["Type", "Listeners.items[].Protocol", "Listeners.items[].SslPolicy"], "DescribeListeners pagination collected with LoadBalancerArn identity guard"),
    "aws.c2b.elbv2.listeners_secure_protocol": spec("load_balancer", "At least one listener protocol differs from fixed ALB HTTPS / NLB TLS enum.", "507-523,921-935", "peaso/collectors/aws.py", "1431-1439", ["Type", "Listeners.items[].Protocol", "Listeners.items[].Port"], "DescribeListeners pagination collected with LoadBalancerArn identity guard"),
    "aws.c2b.elbv2.nlb_tls_termination": spec("load_balancer", "Network load balancer has no TLS listener.", "507-523,626-636", "peaso/collectors/aws.py", "1431-1439", ["Type", "Listeners.items[].Protocol"], "DescribeListeners pagination collected with LoadBalancerArn identity guard"),
    "aws.c2b.elbv2.recommended_tls_policy": spec("load_balancer", "At least one wanted listener SslPolicy belongs to reviewed nonrecommended fixed set; unresolved-only is UNKNOWN.", "460-469,507-523,875-904", "peaso/collectors/aws.py", "1431-1439", ["Type", "Listeners.items[].Protocol", "Listeners.items[].SslPolicy"], "DescribeListeners pagination collected with LoadBalancerArn identity guard"),
    "aws.c2b.emr.cluster_security_configuration": spec("emr_cluster", "DescribeCluster SecurityConfiguration absent.", "400-407,552-558", "peaso/collectors/aws_network_catalog.py", "79,286-310", ["Cluster.Cluster.SecurityConfiguration"], "DescribeCluster detail collected; Id matches parent"),
    "aws.c2b.lambda.runtime_not_obsolete": spec("lambda_function", "Runtime belongs to source-pinned OBSOLETE enum.", "219-233", "peaso/collectors/aws.py", "1120", ["Runtime", "PackageType"], "ListFunctions collection collected; Runtime field present"),
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_gzip(path, expected):
    assert sha(path) == expected, f"input SHA mismatch: {path.name}"
    with gzip.open(path, "rt") as handle:
        return json.load(handle)


def complete(cid, item):
    if ".athena." in cid:
        detail = item["WorkGroup"]
        return detail.get("collection_status") == "collected" and detail["WorkGroup"]["Name"] == item["Name"] and isinstance(detail["WorkGroup"]["Configuration"], dict)
    if cid.endswith("methods_request_validator"):
        return item["Resources"].get("collection_status") == "collected" and bool(item["Resources"].get("items"))
    if cid.endswith("stage_execution_logging"):
        return isinstance(item.get("methodSettings"), dict) and "methodSettings" in item.get("_provenance", {}).get("optional_fields_complete", [])
    if cid.endswith("mixed_policy_multiple_types"):
        return "AutoScalingGroupARN" in item and "MixedInstancesPolicy" not in item
    if cid.endswith("sse_kms"):
        return item["Table"].get("collection_status") == "collected" and item["Table"]["Table"]["TableName"] == item["TableName"] and isinstance(item["Table"]["Table"].get("TableArn"), str)
    if ".ecs." in cid and cid.endswith("service_load_balancer_attached"):
        return isinstance(item.get("loadBalancers"), list)
    if ".ecs." in cid:
        detail = item["Configuration"]
        rows = [r for r in detail.get("clusters", []) if r.get("clusterArn") == item.get("clusterArn")]
        return detail.get("collection_status") == "collected" and len(rows) == 1 and ("settings" in rows[0] or cid.endswith("cluster_has_active_services"))
    if ".efs." in cid:
        detail = item["BackupPolicy"]
        return detail.get("collection_status") == "collected" or (detail.get("collection_status") == "empty" and detail.get("absent") is True)
    if cid.endswith("rg_backup_retention_15"):
        return type(item.get("SnapshotRetentionLimit")) is int and item.get("_provenance", {}).get("native_response_complete") is True
    if ".elbv2." in cid:
        detail = item["Listeners"]
        return detail.get("collection_status") == "collected" and isinstance(detail.get("items"), list) and item.get("Type") in ("application", "network")
    if cid.endswith("cluster_security_configuration"):
        detail = item["Cluster"]
        return detail.get("collection_status") == "collected" and detail["Cluster"]["Id"] == item["Id"]
    if cid.endswith("runtime_not_obsolete"):
        return isinstance(item.get("Runtime"), str) and item.get("PackageType") == "Zip"
    raise AssertionError(cid)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code-worker-receipt", type=Path, required=True)
    ap.add_argument("--snapshot", type=Path, required=True)
    ap.add_argument("--pre-ai", type=Path, required=True)
    ap.add_argument("--numeric", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert sha(args.code_worker_receipt) == SOURCE_RECEIPT_SHA256
    inventory = json.loads(args.code_worker_receipt.read_text())
    assert inventory["parent_receipt_sha256"] == PARENT_RECEIPT_SHA256
    candidates = {r["check_id"]: r for r in inventory["checks"] if r["check_id"].startswith("aws.c2b.") and r["decision"] == "provisional_source_candidate"}
    assert set(candidates) == set(SPECS) and len(candidates) == 24
    snap = load_gzip(args.snapshot, SNAPSHOT_SHA256)
    pre = load_gzip(args.pre_ai, PRE_AI_SHA256)
    assert sha(args.numeric) == NUMERIC_SHA256
    numeric = {r["check_id"]: r for r in json.loads(args.numeric.read_text())["per_check"]}
    collections = {(c["type"], c["scope"]): c for c in snap["collections"]}
    findings = {}
    for f in pre["findings"]:
        if f["check_id"] in SPECS:
            findings.setdefault(f["check_id"], []).extend(o for o in f["observations"] if o["status"] == "FAIL")
    registered = {c.id: c for c in CHECKS}
    output = []
    for cid, proof in sorted(SPECS.items()):
        source = candidates[cid]
        evaluator = source["evaluator"]
        assert sha(ROOT / evaluator["path"]) == evaluator["source_file_sha256"]
        collector_hash = sha(ROOT / proof["collector"])
        assert registered[cid].kind == proof["kind"]
        observations = findings[cid]
        assert len(observations) == source["native_fail_count"]
        assert numeric[cid]["native_fail"] == len(observations)
        assert numeric[cid]["initial_representatives"] == source["initial_representatives"]
        assert numeric[cid]["ai_disagreement"] == numeric[cid]["published_severity_changes"] == 0
        assert numeric[cid]["ai_verdicts"] == {"FAIL": len(observations)}
        for obs in observations:
            collection = collections[(proof["kind"], obs["scope"])]
            assert collection["status"] == "collected", cid
            matches = [i for i in collection["items"] if i["id"] == obs["native_resource_id"]]
            assert len(matches) == 1, cid
            item = matches[0]
            assert complete(cid, item), cid
            assert evaluate_check(cid, item)[0] == "FAIL", cid
        output.append({"check_id": cid, "decision": "source_proven_candidate", "initial_representatives": source["initial_representatives"],
                       "native_fail_count": len(observations), "exact_992_fail_rows_checked": len(observations),
                       "predicate_proof": proof["predicate"], "recorded_api_fields": proof["recorded_fields"],
                       "collector_completeness_proof": proof["completeness"],
                       "evaluator_ref": {"path": evaluator["path"], "symbol": evaluator["symbol"], "lines": proof["evaluator_lines"], "source_sha256": evaluator["source_file_sha256"]},
                       "collector_ref": {"path": proof["collector"], "lines": proof["collector_lines"], "source_sha256": collector_hash}})
    receipt = {"schema_version": 1, "status": "inactive_source_proof_proposal", "scan_id": "992d7b8c", "scope": "disjoint_24_provisional_aws_c2b_only",
               "source_inventory_sha256": SOURCE_RECEIPT_SHA256, "parent_source_inventory_sha256": PARENT_RECEIPT_SHA256,
               "snapshot_sha256": SNAPSHOT_SHA256, "pre_ai_report_sha256": PRE_AI_SHA256,
               "numeric_crosscheck_sha256": NUMERIC_SHA256,
               "approved_candidate_count": len(output), "retained_count": 0, "initial_representatives": sum(r["initial_representatives"] for r in output),
               "native_fail_count": sum(r["native_fail_count"] for r in output), "checks": output,
               "replay_qualification": "pending", "allowlist_activation": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: receipt[k] for k in ("approved_candidate_count", "retained_count", "initial_representatives", "native_fail_count")}))


if __name__ == "__main__":
    main()
