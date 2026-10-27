#!/usr/bin/env python3
"""Fail-closed source and exact-scope proof for the frozen non-c2b provisional slice."""
import gzip
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from peaso.checks import CHECKS, evaluate_check
from validate_native_final_code_candidate_v2 import descend

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/ai-review/native-final-nonc2b-provisional-source-v1.json"
SOURCE_SHA = "0a65637c59ef7bb7986d2f58ee0f5d04bffdf07889e29a8818accf87c0a4e897"
PARENT_SHA = "c2e943107562db3f5bfd07e2b7611ee7ae28fb26e64ab9b9686f63bce29f36db"
SNAP_SHA = "3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f"
PRE_SHA = "4dcaa76a21c6b3bfff2b4859c1d4c763964c92c69041fe2d95702315fffde2ba"
NUM_SHA = "885e63bec3551463dca3ba8b1d449ba7cc7122fbfb33a0c41184fc3e6ad94fea"
SNAP = Path("/Users/carlospolop/peaso-work/replay/snapshot.bin")
PRE = Path("/Users/carlospolop/peaso-work/replay/pre-ai-report.bin")
NUMERIC = ROOT / "outputs/native-final-audit-992-v3-numeric.json"
RECONCILIATION = ROOT / "docs/ai-review/native-final-nonc2b-worker-reconciliation-v1.json"
RECONCILIATION_SHA = "ba06be850310afb0710d38c95010e54c4d774844747695293f9038ec26953a3a"
OUT = ROOT / "docs/ai-review/native-final-nonc2b-remaining-proofs-v1.json"
FUTURE_PATH_PENDING = {
    "aws.claude_a.guardduty.detector_no_findings",
    "aws.claude_a.guardduty.prowler_ai_protection",
    "aws.claude_a.guardduty.prowler_no_high_severity_findings",
    "aws.claude_a.guardduty.prowler_runtime_monitoring",
    "aws.iam.console_mfa",
    "aws.logs.retention",
}
EXACT_992_BRANCH_PROOF = {
    "aws.claude_a.guardduty.detector_no_findings": "Exact FAIL has HighSeverityFindingIds.collection_status=collected and a nonempty filtered ListFindings result; collected() missing-status default is not taken.",
    "aws.claude_a.guardduty.prowler_ai_protection": "Exact FAIL has a unique AI_PROTECTION feature with recorded Name and Status=DISABLED; prowler_flags dict.get fallback is not taken.",
    "aws.claude_a.guardduty.prowler_no_high_severity_findings": "Exact FAIL has HighSeverityFindingIds.collection_status=collected and a nonempty filtered ListFindings result; collected() missing-status default is not taken.",
    "aws.claude_a.guardduty.prowler_runtime_monitoring": "Exact FAIL has a unique RUNTIME_MONITORING feature with recorded Name and Status=DISABLED; prowler_flags dict.get fallback is not taken.",
    "aws.iam.console_mfa": "All four exact FAIL rows have collected LoginProfile and MFADevices.collection_status=empty with zero items; malformed or unknown collection-status paths are not taken.",
    "aws.logs.retention": "All twelve exact FAIL rows have logs:DescribeLogGroups native_response_complete=true and omit retentionInDays; the optional default is bound to a complete response.",
}
FUTURE_PATH_BLOCKER = {
    "aws.claude_a.guardduty.detector_no_findings": "collected() at peaso/checks/claude_aws_a_security.py:24-30 accepts an omitted nested collection_status; future partial finding lists can reach FAIL.",
    "aws.claude_a.guardduty.prowler_ai_protection": "prowler_flags() at peaso/checks/claude_aws_a_security.py:174-190 defaults missing feature Name or Status; a future malformed feature can reach FAIL.",
    "aws.claude_a.guardduty.prowler_no_high_severity_findings": "collected() at peaso/checks/claude_aws_a_security.py:24-30 accepts an omitted nested collection_status; future partial finding lists can reach FAIL.",
    "aws.claude_a.guardduty.prowler_runtime_monitoring": "prowler_flags() at peaso/checks/claude_aws_a_security.py:174-190 defaults missing feature Name or Status; a future malformed feature can reach FAIL.",
    "aws.iam.console_mfa": "aws_mfa() at peaso/checks/__init__.py:358-379 does not require MFADevices collection_status to be collected or empty before returning FAIL.",
    "aws.logs.retention": "_native_optional() at peaso/checks/aws.py:26-34 accepts omitted retentionInDays without requiring native_response_complete from DescribeLogGroups.",
}

# Short source names below resolve to pinned whole files in the receipt.
COLLECTOR = {
    "base": ("peaso/collectors/aws.py", "1060-1130,1234-1500,2799-2920"),
    "services": ("peaso/collectors/aws_b_services.py", "129-275,447-535"),
    "facts": ("peaso/collectors/aws_facts_cb_ca.py", "887-909,965-975,1092-1105,1316-1330"),
}


def P(predicate, fields, collector, statuses=()):
    return {"predicate": predicate, "recorded_paths": fields, "collector": collector,
            "nested_statuses": statuses}


# Explicit source review, including helper/default branches. Paths are the
# recorded evidence anchors; optional omissions bind to a collected parent.
PROOF = {
    "aws.a.iam.report_all_mfa": P("csv_boolean(mfa_active) == false", ["mfa_active"], "base"),
    "aws.b.acm.no_failed_validation": P("DescribeCertificate Status is FAILED or VALIDATION_TIMED_OUT", ["Certificate.Certificate.Status"], "services", ["Certificate"]),
    "aws.b.apigateway.http_execution_logging": P("DefaultRouteSettings.LoggingLevel is OFF or empty", ["DefaultRouteSettings"], "services"),
    "aws.b.codebuild.artifact_encryption": P("primary encryptionDisabled is not explicitly false or a secondary flag is true", ["Configuration.projects[]"], "services", ["Configuration"]),
    "aws.b.codebuild.nonprivileged": P("single matched BatchGetProjects environment.privilegedMode is true", ["Configuration.projects[].environment.privilegedMode"], "services", ["Configuration"]),
    "aws.b.cognito.admin_only_signup": P("collected UserPool AdminCreateUserConfig.AllowAdminCreateUserOnly defaults false or is false", ["Configuration.UserPool"], "services", ["Configuration"]),
    "aws.b.cognito.block_all_takeover_risks": P("collected UserPool AdvancedSecurityMode defaults OFF; exact FAIL takes mode != ENFORCED branch", ["Configuration.UserPool"], "services", ["Configuration"]),
    "aws.b.cognito.block_compromised_signin": P("collected UserPool AdvancedSecurityMode defaults OFF; exact FAIL takes mode != ENFORCED branch", ["Configuration.UserPool"], "services", ["Configuration"]),
    "aws.b.cognito.deletion_protection": P("collected UserPool DeletionProtection differs from ACTIVE", ["Configuration.UserPool"], "services", ["Configuration"]),
    "aws.b.cognito.enforced_threat_protection": P("collected UserPool AdvancedSecurityMode differs from ENFORCED", ["Configuration.UserPool"], "services", ["Configuration"]),
    "aws.b.cognito.no_guest_identities": P("DescribeIdentityPool AllowUnauthenticatedIdentities is true", ["Configuration.AllowUnauthenticatedIdentities"], "services", ["Configuration"]),
    "aws.b.cognito.password_minimum_fourteen": P("collected UserPool minimum password length is below fixed 14", ["Configuration.UserPool"], "services", ["Configuration"]),
    "aws.b.cognito.required_mfa": P("collected UserPool MfaConfiguration differs from ON", ["Configuration.UserPool"], "services", ["Configuration"]),
    "aws.b.dynamodb.deletion_protection": P("DescribeTable DeletionProtectionEnabled is false", ["Table.Table.DeletionProtectionEnabled"], "base", ["Table"]),
    "aws.b.dynamodb.point_in_time_recovery": P("DescribeContinuousBackups PointInTimeRecoveryStatus differs from ENABLED", ["ContinuousBackups.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus"], "services", ["ContinuousBackups"]),
    "aws.b.rds_instance.iam_authentication": P("DescribeDBInstances IAMDatabaseAuthenticationEnabled is false", ["IAMDatabaseAuthenticationEnabled"], "base"),
    "aws.b.rds_instance.snapshot_tags": P("DescribeDBInstances CopyTagsToSnapshot is false", ["CopyTagsToSnapshot"], "base"),
    "aws.cb.apigatewayv2.stage_access_logging": P("GetStages StageName binds documented absent AccessLogSettings", ["StageName"], "services"),
    "aws.cb.rds.instance_enhanced_monitoring_except_m1_small": P("non-m1.small DescribeDBInstances lacks EnhancedMonitoringResourceArn", ["DBInstanceClass", "DBInstanceArn"], "base"),
    "aws.cb.rds.instance_extended_support": P("DescribeDBInstances EngineLifecycleSupport equals extended-support enum", ["DBInstanceArn", "EngineLifecycleSupport"], "base"),
    "aws.cb.rds.instance_iam_auth_supported_engines": P("supported Engine enum/substring and absent or false IAMDatabaseAuthenticationEnabled", ["Engine", "DBInstanceArn"], "base"),
    "aws.cb.sagemaker.training_output_kms": P("DescribeTrainingJob OutputDataConfig has S3OutputPath sentinel and absent or empty KmsKeyId", ["OutputDataConfig.S3OutputPath", "OutputDataConfig"], "facts"),
    "aws.cb.sagemaker.training_volume_kms": P("DescribeTrainingJob ResourceConfig has InstanceType sentinel and absent or empty VolumeKmsKeyId", ["ResourceConfig.InstanceType", "ResourceConfig"], "facts"),
    "aws.cb.ssmincidents.active_with_response_plans": P("complete ListReplicationSets and ListResponsePlans are both empty", ["ReplicationSets", "ResponsePlans"], "facts", ["ReplicationSets", "ResponsePlans"]),
    "aws.claude_a.ebs.attached_delete_on_termination": P("in-use DescribeVolumes Attachments has no all-true DeleteOnTermination flags", ["State", "Attachments"], "base"),
    "aws.claude_a.ec2.ami_ebs_encrypted": P("DescribeImages block-device list contains EBS mapping without Encrypted true", ["BlockDeviceMappings"], "base"),
    "aws.claude_a.ec2.eni_in_use": P("DescribeNetworkInterfaces Status available and Attachment.InstanceId absent", ["Status", "NetworkInterfaceId"], "base"),
    "aws.claude_a.ec2.instance_ebs_delete_on_termination": P("complete DescribeInstances block-device EBS mapping has DeleteOnTermination false", ["BlockDeviceMappings"], "base"),
    "aws.claude_a.ec2.launch_template_default_ebs_encrypted": P("complete DescribeLaunchTemplateVersions resolves one default version and an EBS mapping lacks Encrypted true", ["Versions"], "facts"),
    "aws.claude_a.guardduty.detector_no_findings": P("enabled GetDetector and complete filtered ListFindings has positive active severity-8 count", ["Configuration.Status", "HighSeverityFindingIds.items"], "base+facts", ["Configuration", "HighSeverityFindingIds"]),
    "aws.claude_a.guardduty.prowler_ai_protection": P("enabled GetDetector AI_PROTECTION feature Status is DISABLED", ["Configuration.Status", "Configuration.Features"], "base", ["Configuration"]),
    "aws.claude_a.guardduty.prowler_no_high_severity_findings": P("complete filtered ListFindings has positive active severity-8 count", ["HighSeverityFindingIds.items"], "facts", ["HighSeverityFindingIds"]),
    "aws.claude_a.guardduty.prowler_runtime_monitoring": P("enabled GetDetector RUNTIME_MONITORING feature Status is DISABLED", ["Configuration.Status", "Configuration.Features"], "base", ["Configuration"]),
    "aws.claude_a.iam.not_two_active_keys": P("both credential-report access_key_1_active and access_key_2_active parse true", ["access_key_1_active", "access_key_2_active"], "base"),
    "aws.claude_a.kms.customer_key_not_pending_deletion": P("DescribeKey customer KeyManager and KeyState PendingDeletion", ["Metadata.KeyMetadata.KeyManager", "Metadata.KeyMetadata.KeyState"], "base", ["Metadata"]),
    "aws.guardduty.runtime_monitoring": P("GetDetector Status or matching RUNTIME_MONITORING feature Status differs from ENABLED", ["Configuration.Status", "Configuration.Features"], "base", ["Configuration"]),
    "aws.iam.console_mfa": P("GetLoginProfile collected; complete ListMFADevices empty", ["LoginProfile", "MFADevices"], "base", ["LoginProfile", "MFADevices"]),
    "aws.kms.rotation": P("DescribeKey customer symmetric AWS_KMS metadata and GetKeyRotationStatus false", ["Metadata.KeyMetadata", "Rotation.KeyRotationEnabled"], "base", ["Metadata", "Rotation"]),
    "aws.logs.retention": P("complete DescribeLogGroups omits retentionInDays on log group identity", ["logGroupName", "_provenance.native_response_complete"], "base"),
    "aws.sns.kms_encryption": P("GetTopicAttributes KmsMasterKeyId is empty after documented omission normalization", ["Attributes.Attributes.KmsMasterKeyId"], "base", ["Attributes"]),
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def branch_proof(cid, item):
    """Pin the optional/default and scope branches that a FAIL alone cannot prove."""
    if cid in {"aws.b.cognito.block_all_takeover_risks", "aws.b.cognito.block_compromised_signin"}:
        assert item["Configuration"]["UserPool"]["Id"] == item["Id"]
        assert item["Configuration"]["UserPool"].get("UserPoolAddOns", {}).get("AdvancedSecurityMode", "OFF") != "ENFORCED"
    if cid.startswith("aws.b.cognito.") and cid != "aws.b.cognito.no_guest_identities":
        assert item["Configuration"]["UserPool"]["Id"] == item["Id"]
    if cid == "aws.b.cognito.no_guest_identities":
        assert item["Configuration"]["IdentityPoolId"] == item["IdentityPoolId"]
    if cid == "aws.b.acm.no_failed_validation":
        assert item["Certificate"]["Certificate"]["CertificateArn"] == item["CertificateArn"]
    if cid.startswith("aws.b.codebuild."):
        assert len(item["Configuration"]["projects"]) == 1
        assert item["Configuration"]["projects"][0]["name"] == item["name"]
    if cid == "aws.b.codebuild.artifact_encryption":
        project = item["Configuration"]["projects"][0]
        assert project["artifacts"].get("encryptionDisabled") is not False
        assert project.get("secondaryArtifacts", []) == []
    if cid == "aws.b.apigateway.http_execution_logging":
        assert item["DefaultRouteSettings"].get("LoggingLevel", "OFF") in ("OFF", "")
    if cid == "aws.cb.apigatewayv2.stage_access_logging":
        assert "AccessLogSettings" not in item
        assert item.get("_provenance", {}).get("source_operation") == "get_stages"
    if cid == "aws.b.dynamodb.deletion_protection":
        assert item["Table"]["Table"]["TableName"] == item["TableName"]
    if cid == "aws.cb.rds.instance_enhanced_monitoring_except_m1_small":
        assert item["DBInstanceClass"] != "db.m1.small" and "EnhancedMonitoringResourceArn" not in item
    if cid == "aws.cb.rds.instance_extended_support":
        assert item["EngineLifecycleSupport"] == "open-source-rds-extended-support"
    if cid == "aws.cb.rds.instance_iam_auth_supported_engines":
        assert item["IAMDatabaseAuthenticationEnabled"] is False
    if cid == "aws.cb.sagemaker.training_output_kms":
        assert item["OutputDataConfig"]["S3OutputPath"]
        assert item["OutputDataConfig"].get("KmsKeyId") == ""
    if cid == "aws.cb.sagemaker.training_volume_kms":
        assert item["ResourceConfig"]["InstanceType"]
        assert "VolumeKmsKeyId" not in item["ResourceConfig"]
    if cid == "aws.cb.ssmincidents.active_with_response_plans":
        assert item["ReplicationSets"]["collection_status"] == "empty" and item["ReplicationSets"]["items"] == []
        assert item["ResponsePlans"]["collection_status"] == "empty" and item["ResponsePlans"]["items"] == []
    if cid == "aws.claude_a.ec2.eni_in_use":
        assert item["Status"] == "available" and "Attachment" not in item
    if cid == "aws.claude_a.ec2.instance_ebs_delete_on_termination":
        assert item.get("_provenance", {}).get("native_response_complete") is True
    if cid == "aws.claude_a.ec2.launch_template_default_ebs_encrypted":
        defaults = [v for v in item["Versions"] if v.get("DefaultVersion") is True]
        assert len(defaults) == 1
        assert defaults[0].get("LaunchTemplateData", {}).get("BlockDeviceMappings")
    if cid in {"aws.claude_a.guardduty.detector_no_findings", "aws.claude_a.guardduty.prowler_no_high_severity_findings"}:
        assert item["HighSeverityFindingIds"]["collection_status"] == "collected"
        assert item["HighSeverityFindingIds"]["items"]
        assert all(isinstance(value, str) and value for value in item["HighSeverityFindingIds"]["items"])
    if cid == "aws.claude_a.guardduty.detector_no_findings":
        assert item["Configuration"]["Status"] == "ENABLED"
    if cid in {"aws.claude_a.guardduty.prowler_ai_protection", "aws.claude_a.guardduty.prowler_runtime_monitoring"}:
        feature = "AI_PROTECTION" if cid.endswith("prowler_ai_protection") else "RUNTIME_MONITORING"
        matching = [row for row in item["Configuration"]["Features"] if row.get("Name") == feature]
        assert len(matching) == 1 and matching[0].get("Status") == "DISABLED"
        assert item["Configuration"]["Status"] == "ENABLED"
    if cid == "aws.iam.console_mfa":
        assert item["LoginProfile"]["collection_status"] == "collected"
        assert item["MFADevices"]["collection_status"] == "empty" and item["MFADevices"]["items"] == []
    if cid == "aws.claude_a.kms.customer_key_not_pending_deletion":
        meta = item["Metadata"]["KeyMetadata"]
        assert meta["KeyManager"] == "CUSTOMER" and meta["KeyState"] == "PendingDeletion"
    if cid == "aws.kms.rotation":
        meta = item["Metadata"]["KeyMetadata"]
        assert meta["KeyManager"] == "CUSTOMER" and meta["Origin"] == "AWS_KMS" and meta["KeySpec"] == "SYMMETRIC_DEFAULT"
        assert item["Rotation"]["KeyRotationEnabled"] is False
    if cid == "aws.logs.retention":
        assert item.get("_provenance", {}).get("operation") == "logs:DescribeLogGroups"
        assert item.get("_provenance", {}).get("native_response_complete") is True
        assert "retentionInDays" not in item
    if cid == "aws.sns.kms_encryption":
        assert item["Attributes"]["Attributes"]["KmsMasterKeyId"] == ""


def main():
    assert sha(SOURCE) == SOURCE_SHA
    source = json.loads(SOURCE.read_text())
    assert source["parent_receipt_sha256"] == PARENT_SHA
    assert sha(RECONCILIATION) == RECONCILIATION_SHA
    worker = json.loads(RECONCILIATION.read_text())
    assert worker["worker_receipt_sha256"] == "0d0ed1292c24ba8d3b722ad21a1f522dce3b219392d1eee4b3e9192a9640b02b"
    worker_decisions = {r["check_id"]: r["decision"] for r in worker["checks"]}
    candidates = {r["check_id"]: r for r in source["checks"]}
    assert set(candidates) == set(PROOF) and len(candidates) == 40
    assert set(EXACT_992_BRANCH_PROOF) == set(FUTURE_PATH_BLOCKER) == FUTURE_PATH_PENDING
    assert set(worker_decisions) == set(PROOF)
    assert {cid for cid, decision in worker_decisions.items() if decision == "retain_ai"} == FUTURE_PATH_PENDING
    assert all(decision == "native_final_source_proven" for cid, decision in worker_decisions.items() if cid not in FUTURE_PATH_PENDING)
    assert sha(SNAP) == SNAP_SHA and sha(PRE) == PRE_SHA and sha(NUMERIC) == NUM_SHA
    snap = json.loads(gzip.decompress(SNAP.read_bytes()))
    pre = json.loads(gzip.decompress(PRE.read_bytes()))
    numeric = {r["check_id"]: r for r in json.loads(NUMERIC.read_text())["per_check"]}
    collections = {(c["type"], c["scope"]): c for c in snap["collections"]}
    observations = defaultdict(list)
    for finding in pre["findings"]:
        if finding["check_id"] in candidates:
            observations[finding["check_id"]].extend(o for o in finding["observations"] if o["status"] == "FAIL")
    checks = {check.id: check for check in CHECKS}
    output = []
    for cid, spec in sorted(PROOF.items()):
        source_row = candidates[cid]
        evaluator = source_row["evaluator"]
        assert sha(ROOT / evaluator["path"]) == evaluator["source_file_sha256"]
        helper_refs = []
        for helper in source_row["helper_source_refs"]:
            helper_hash = sha(ROOT / helper["path"])
            assert helper.get("source_file_sha256", helper_hash) == helper_hash
            helper_refs.append({"path": helper["path"], "lines": helper["lines"],
                                "symbol": helper.get("symbol"), "source_sha256": helper_hash})
        collector_keys = spec["collector"].split("+")
        collector_refs = []
        for key in collector_keys:
            coll_path, coll_lines = COLLECTOR[key]
            collector_refs.append({"path": coll_path, "lines": coll_lines, "source_sha256": sha(ROOT / coll_path)})
        assert len(observations[cid]) == source_row["native_fail_count"] == numeric[cid]["native_fail"]
        assert source_row["initial_representatives"] == numeric[cid]["initial_representatives"]
        assert numeric[cid]["ai_disagreement"] == numeric[cid]["published_severity_changes"] == 0
        assert numeric[cid]["ai_verdicts"] == {"FAIL": len(observations[cid])}
        bound = 0
        for obs in observations[cid]:
            collection = collections[(checks[cid].kind, obs["scope"])]
            assert collection["status"] == "collected", cid
            identity = "arn" if cid == "aws.logs.retention" else "id"
            matches = [item for item in collection["items"] if item.get(identity) == obs["native_resource_id"]]
            assert len(matches) == 1, cid
            item = matches[0]
            for path in spec["recorded_paths"]:
                assert descend([item], path), (cid, path)
                bound += 1
            for path in spec["nested_statuses"]:
                value = descend([item], path + ".collection_status")
                assert len(value) == 1 and value[0] in ("collected", "empty"), (cid, path)
            branch_proof(cid, item)
            assert evaluate_check(cid, item)[0] == "FAIL", cid
        output.append({"check_id": cid, "decision": "retain_ai_pending_evaluator_fail_closed_fix" if cid in FUTURE_PATH_PENDING else "independent_confirmation_of_worker_proof",
                       "worker_decision_at_reconciliation": worker_decisions[cid],
                       "exact_992_branch_proof": EXACT_992_BRANCH_PROOF.get(cid),
                       "future_path_safety_blocker": FUTURE_PATH_BLOCKER.get(cid),
                       "global_allowlist_eligible": cid not in FUTURE_PATH_PENDING,
                       "initial_representatives": source_row["initial_representatives"],
                       "native_fail_count": len(observations[cid]), "exact_992_fail_rows_checked": len(observations[cid]),
                       "exact_recorded_path_bindings": bound, "predicate_proof": spec["predicate"],
                       "recorded_evidence_paths": spec["recorded_paths"], "required_nested_collections": spec["nested_statuses"],
                       "evaluator_ref": {"path": evaluator["path"], "symbol": evaluator["symbol"],
                                         "lines": str(evaluator["first_line"]) + "-" + str(evaluator["last_line"]),
                                         "source_sha256": evaluator["source_file_sha256"]},
                       "helper_refs": helper_refs,
                       "collector_refs": collector_refs})
    receipt = {"schema_version": 1, "status": "inactive_source_proof_proposal", "scan_id": "992d7b8c",
               "scope": "frozen_40_provisional_non_c2b", "source_inventory_sha256": SOURCE_SHA,
               "parent_source_inventory_sha256": PARENT_SHA, "snapshot_sha256": SNAP_SHA,
               "pre_ai_report_sha256": PRE_SHA, "numeric_crosscheck_sha256": NUM_SHA,
               "worker_reconciliation_sha256": RECONCILIATION_SHA,
               "audited_check_count": len(output), "new_allowlist_candidate_count": 0,
               "independently_confirmed_worker_proof_count": len(output) - len(FUTURE_PATH_PENDING),
               "future_path_pending_count": len(FUTURE_PATH_PENDING),
               "future_path_pending_initial_representatives": sum(r["initial_representatives"] for r in output if r["check_id"] in FUTURE_PATH_PENDING),
               "future_path_pending_exact_992_fail_count": sum(r["native_fail_count"] for r in output if r["check_id"] in FUTURE_PATH_PENDING),
               "retained_count": len(FUTURE_PATH_PENDING),
               "initial_representatives": sum(r["initial_representatives"] for r in output),
               "native_fail_count": sum(r["native_fail_count"] for r in output),
               "exact_recorded_path_bindings": sum(r["exact_recorded_path_bindings"] for r in output),
               "replay_qualification": "blocked_by_future_path_safety", "allowlist_activation": False, "checks": output}
    OUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: receipt[k] for k in ("audited_check_count", "new_allowlist_candidate_count", "independently_confirmed_worker_proof_count", "future_path_pending_count", "future_path_pending_exact_992_fail_count", "exact_recorded_path_bindings")}))


if __name__ == "__main__":
    main()
