"""Isolated signed AWS sw43 checks; run with --noconftest."""
from __future__ import annotations

import base64
import copy
import json
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from peaso.checks import evaluate_check
sw = sys.modules["peaso.checks._bulk_pending_compliance_new_sw43"]

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
GLOBAL = f"{ACCOUNT}/global"
DIGEST = "sha256:" + "a" * 64


def index(kinds, *, metadata=None, global_scope=False, created_at="2026-10-12T00:00:00+00:00", status="collected"):
    scope = GLOBAL if global_scope else SCOPE
    context = {"provider": "aws", "scope": scope, "Account": ACCOUNT,
               "metadata": metadata or {}, "created_at": created_at}
    collections, wrappers = {}, {}
    for kind, rows in kinds.items():
        collections[kind] = [{"type": kind, "scope": scope, "account_id": ACCOUNT,
                              "global": global_scope, "status": status,
                              "items": rows}]
        wrappers[kind] = [{"type": kind, "scope": scope, "data": row} for row in rows]
    return {"context": context, "collections": collections, **wrappers}


def evaluate(check_id, item, facts):
    return evaluate_check(check_id, item, facts)[0]


def rds_case(kind="rds_cluster", *, interval=60, role="arn:aws:iam::123456789012:role/rds", monitoring="arn:aws:rds:us-east-1:123456789012:em:one"):
    cluster = {"DBClusterIdentifier": "cluster-1", "DBClusterArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:cluster:cluster-1",
               "AccountId": ACCOUNT, "Region": REGION,
               "DBClusterMembers": [{"DBInstanceIdentifier": "member-1"}]}
    instance = {"DBInstanceIdentifier": "member-1", "DBInstanceArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:member-1",
                "AccountId": ACCOUNT, "Region": REGION,
                "DBClusterIdentifier": "cluster-1", "DBInstanceClass": "db.r6g.large", "MonitoringInterval": interval, "MonitoringRoleArn": role,
                "EnhancedMonitoringResourceArn": monitoring, "Engine": "aurora-mysql"}
    caller = {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/fixture/session"}
    return cluster, index({kind: [cluster], "rds_instance": [instance]}, metadata={"caller_identities": [caller]})


@pytest.mark.parametrize("check_id,kind,resource_arn", [
    ("aws.nist.rds_cluster_member_enhanced_monitoring", "rds_cluster", False),
    ("aws_fedramp_rds_cluster_members_enhanced_monitoring", "rds_cluster", False),
    ("aws_g6_rds_cluster_members_enhanced_monitoring", "rds_cluster", True),
])
def test_cluster_member_monitoring(check_id, kind, resource_arn):
    good, facts = rds_case(kind)
    assert evaluate(check_id, good, facts) == "PASS"
    bad, facts = rds_case(kind, interval=0)
    assert evaluate(check_id, bad, facts) == "FAIL"
    bad, facts = rds_case(kind, role="")
    assert evaluate(check_id, bad, facts) == "FAIL"
    if resource_arn:
        bad, facts = rds_case(kind, monitoring="")
        assert evaluate(check_id, bad, facts) == "FAIL"
        small, facts = rds_case(kind, interval=0, monitoring="")
        facts["rds_instance"][0]["data"]["DBInstanceClass"] = "db.m1.small"
        facts["collections"]["rds_instance"][0]["items"][0]["DBInstanceClass"] = "db.m1.small"
        assert evaluate(check_id, small, facts) == "PASS"
    absent = copy.deepcopy(facts)
    absent["collections"].pop("rds_instance")
    assert evaluate(check_id, bad, absent) == "UNKNOWN"
    incomplete = copy.deepcopy(facts)
    incomplete["collections"][kind][0]["status"] = "partial"
    assert evaluate(check_id, bad, incomplete) == "UNKNOWN"
    malformed = copy.deepcopy(facts)
    if resource_arn:
        malformed["rds_instance"][0]["data"]["DBInstanceClass"] = "db.r6g.large"
        malformed["collections"]["rds_instance"][0]["items"][0]["DBInstanceClass"] = "db.r6g.large"
    malformed["rds_instance"][0]["data"]["MonitoringInterval"] = "zero"
    malformed["collections"]["rds_instance"][0]["items"][0]["MonitoringInterval"] = "zero"
    assert evaluate(check_id, bad, malformed) == "UNKNOWN"
    foreign = copy.deepcopy(facts)
    foreign["collections"][kind][0]["scope"] = "123456789012/eu-west-1"
    assert evaluate(check_id, bad, foreign) == "UNKNOWN"


def test_aurora_backtracking():
    check_id = "aws_nist_rds_db_cluster_aurora_backtracking_enabled"
    row = {"DBClusterIdentifier": "cluster-1", "Engine": "aurora-mysql", "BacktrackWindow": 3600}
    assert evaluate(check_id, row, index({"rds_cluster": [row]})) == "PASS"
    row["BacktrackWindow"] = 0
    assert evaluate(check_id, row, index({"rds_cluster": [row]})) == "FAIL"
    row.pop("BacktrackWindow")
    assert evaluate(check_id, row, index({"rds_cluster": [row]})) == "UNKNOWN"
    row["Engine"] = "aurora-postgresql"
    assert evaluate(check_id, row, index({"rds_cluster": [row]})) == "NOT_APPLICABLE"
    row.pop("Engine")
    assert evaluate(check_id, row, index({"rds_cluster": [row]})) == "UNKNOWN"
    row["Engine"] = "aurora-mysql"
    assert evaluate(check_id, row, index({"rds_cluster": [row]}, status="partial")) == "UNKNOWN"


def table(sse):
    return {"TableName": "payments", "Table": {"collection_status": "collected", "Table": {"TableName": "payments", "SSEDescription": sse}}}


def test_dynamodb_kms():
    check_id = "aws_nist_dynamodb_table_encrypted_with_kms"
    key = "arn:aws:kms:us-east-1:123456789012:key/abc"
    good = table({"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": key})
    assert evaluate(check_id, good, index({"dynamodb_table": [good]})) == "PASS"
    bad = table({"Status": "ENABLED", "SSEType": "AES256", "KMSMasterKeyArn": ""})
    assert evaluate(check_id, bad, index({"dynamodb_table": [bad]})) == "FAIL"
    partial = table({"Status": "UPDATING", "SSEType": "KMS", "KMSMasterKeyArn": key})
    assert evaluate(check_id, partial, index({"dynamodb_table": [partial]})) == "UNKNOWN"
    malformed = table({"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": 1})
    assert evaluate(check_id, malformed, index({"dynamodb_table": [malformed]})) == "UNKNOWN"
    missing = table({"Status": "ENABLED", "SSEType": "KMS"})
    assert evaluate(check_id, missing, index({"dynamodb_table": [missing]}, status="partial")) == "UNKNOWN"


def test_efs_access_point_root():
    check_id = "aws_nist_efs_access_point_enforce_root_directory"
    arn = "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-1"
    def row(path): return {"AccessPointArn": arn, "RootDirectory": {"Path": path},
                           "_provenance": {"operation": "efs:DescribeAccessPoints",
                                           "root_directory_representation_complete": True}}
    good = row("/tenant")
    assert evaluate(check_id, good, index({"efs_access_point": [good]})) == "PASS"
    for path in ("", "/"):
        bad = row(path)
        assert evaluate(check_id, bad, index({"efs_access_point": [bad]})) == "FAIL"
    malformed = row(1)
    assert evaluate(check_id, malformed, index({"efs_access_point": [malformed]})) == "UNKNOWN"
    assert evaluate(check_id, good, index({}, status="partial")) == "UNKNOWN"


def test_stage_logging():
    check_id = "aws_nist_apigateway_stage_logging_enabled"
    subject = {"scope": SCOPE}
    rest_arn = "arn:aws:apigateway:us-east-1::/restapis/api1/stages/prod"
    rest = {"id": rest_arn, "ParentApiId": "api1", "stageName": "prod", "deploymentId": "dep1",
            "methodSettings": {"*/*": {"loggingLevel": "INFO"}},
            "_provenance": {"source_operation": "get_stages", "parent_api_id": "api1", "read_only": True}}
    method = {"id": rest_arn + "/deployed-method/%2Fpets%2FGET", "stageArn": rest_arn,
              "restApiId": "api1", "deploymentId": "dep1", "resourcePath": "/pets", "httpMethod": "GET",
              "methodSettingKey": "/pets/GET", "_provenance": {"source_operation": "GetDeployment",
              "read_only": True, "embed": "apisummary", "stage_deployment_join_verified": True}}
    http = {"id": "arn:aws:apigateway:us-east-1::/apis/api2/stages/prod", "ParentApiId": "api2",
            "ParentProtocolType": "HTTP", "StageName": "prod", "_provenance": {
            "source_operation": "get_stages", "parent_api_id": "api2", "parent_protocol_source_operation": "get_apis",
            "read_only": True}}
    facts = lambda: index({"rest_api_stage": [rest], "rest_api_method": [method], "http_api_stage": [http]})
    assert evaluate(check_id, subject, facts()) == "PASS"
    rest["methodSettings"]["*/*"]["loggingLevel"] = "OFF"
    assert evaluate(check_id, subject, facts()) == "FAIL"
    rest["methodSettings"]["*/*"]["loggingLevel"] = "INFO"
    rest["canarySettings"] = {"percentTraffic": 10}
    assert evaluate(check_id, subject, facts()) == "UNKNOWN"
    rest.pop("canarySettings")
    assert evaluate(check_id, subject, index({"rest_api_stage": [], "rest_api_method": [], "http_api_stage": [http]})) == "NOT_APPLICABLE"
    assert evaluate(check_id, subject, index({"rest_api_stage": [rest], "rest_api_method": [method],
                                             "http_api_stage": [http]}, status="partial")) == "UNKNOWN"


def backup_case(*, enabled=True, selected=True, role=True):
    arn = "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-1"
    fs = {"FileSystemArn": arn, "Tags": [{"Key": "backup", "Value": "yes"}]}
    selection = {"Resources": [arn] if selected else [], "NotResources": [], "ListOfTags": [], "Conditions": {}, "IamRoleArn": "arn:aws:iam::123456789012:role/backup" if role else ""}
    plan = {"BackupPlanArn": "arn:aws:backup:us-east-1:123456789012:backup-plan:one", "Enabled": enabled,
            "Selections": {"collection_status": "collected", "items": [{"Selection": {"collection_status": "collected", "BackupSelection": selection}}]}}
    return fs, index({"efs_file_system": [fs], "backup_plan": [plan]})


@pytest.mark.parametrize("check_id,effective", [
    ("aws_nist_efs_file_system_in_backup_plan", False),
    ("aws_g6_efs_effective_backup_plan_selection", True),
])
def test_efs_backup_selection(check_id, effective):
    fs, facts = backup_case()
    assert evaluate(check_id, fs, facts) == "PASS"
    fs, facts = backup_case(selected=False)
    assert evaluate(check_id, fs, facts) == "FAIL"
    fs, facts = backup_case()
    facts["backup_plan"][0]["data"]["Selections"]["items"][0]["Selection"]["BackupSelection"]["NotResources"] = [fs["FileSystemArn"]]
    assert evaluate(check_id, fs, facts) == "FAIL"
    fs, facts = backup_case(enabled=False)
    assert evaluate(check_id, fs, facts) == "FAIL"
    fs, facts = backup_case(role=False)
    assert evaluate(check_id, fs, facts) == ("FAIL" if effective else "PASS")
    fs, facts = backup_case()
    facts["collections"]["backup_plan"][0]["status"] = "partial"
    assert evaluate(check_id, fs, facts) == "UNKNOWN"
    fs, facts = backup_case()
    fs["Tags"] = "bad"
    assert evaluate(check_id, fs, facts) == "UNKNOWN"
    fs, facts = backup_case()
    facts["collections"].pop("backup_plan")
    assert evaluate(check_id, fs, facts) == "UNKNOWN"


def test_restore_testing_schedule():
    check_id = "aws_backup_restore_tests_recent"
    arn = "arn:aws:ec2:us-east-1:123456789012:volume/vol-1"
    job = {"RestoreJobId": "job-1", "SourceResourceArn": arn, "Status": "COMPLETED", "CompletionDate": "2026-10-10T00:00:00Z", "CreatedBy": {"RestoreTestingPlanArn": "arn:aws:backup:us-east-1:123456789012:restore-testing-plan:p"}}
    metadata = {"approved_protected_resources": [{"ResourceArn": arn, "IntervalDays": 7}]}
    subject = {"scope": SCOPE}
    assert evaluate(check_id, subject, index({"backup_restore_job": [job]}, metadata=metadata)) == "PASS"
    assert evaluate(check_id, subject, index({"backup_restore_job": []}, metadata=metadata)) == "FAIL"
    assert evaluate(check_id, subject, index({}, metadata=metadata)) == "UNKNOWN"
    assert evaluate(check_id, subject, index({"backup_restore_job": [job]}, metadata=metadata, status="partial")) == "UNKNOWN"
    malformed = dict(job, CompletionDate="bad")
    assert evaluate(check_id, subject, index({"backup_restore_job": [malformed]}, metadata=metadata)) == "UNKNOWN"


def test_capacity_thresholds():
    check_id = "aws.nist.sc_5_2_coverage"
    row = {"id": "group-1", "DocumentedMinimum": 2, "ConfiguredCapacity": 2,
           "AvailabilityZones": ["us-east-1a", "us-east-1b"]}
    assert evaluate(check_id, row, index({"capacity_group": [row]})) == "PASS"
    bad = dict(row, ConfiguredCapacity=1)
    assert evaluate(check_id, bad, index({"capacity_group": [bad]})) == "FAIL"
    bad = dict(row, AvailabilityZones=["us-east-1a"])
    assert evaluate(check_id, bad, index({"capacity_group": [bad]})) == "FAIL"
    bad = dict(row, DocumentedMinimum="two")
    assert evaluate(check_id, bad, index({"capacity_group": [bad]})) == "UNKNOWN"
    assert evaluate(check_id, row, index({})) == "UNKNOWN"


def test_org_guardrails():
    check_id = "aws_cis_organization_account_guardrails"
    policy = {"Name": "deny-root", "Content": {"Statement": [{"Effect": "Deny", "Action": "iam:CreateUser", "Resource": "*"}]}}
    row = {"Id": ACCOUNT, "Status": "ACTIVE", "EffectiveScpPolicies": {"collection_status": "collected", "InheritanceComplete": True, "items": [policy]}}
    metadata = {"prohibited_actions": ["iam:CreateUser"]}
    assert evaluate(check_id, row, index({"organization_account": [row]}, metadata=metadata, global_scope=True)) == "PASS"
    row["EffectiveScpPolicies"]["items"] = [{"Name": "FullAWSAccess", "Content": {"Statement": []}}]
    assert evaluate(check_id, row, index({"organization_account": [row]}, metadata=metadata, global_scope=True)) == "FAIL"
    row["EffectiveScpPolicies"]["InheritanceComplete"] = False
    assert evaluate(check_id, row, index({"organization_account": [row]}, metadata=metadata, global_scope=True)) == "UNKNOWN"
    row["Status"] = "SUSPENDED"
    assert evaluate(check_id, row, index({"organization_account": [row]}, metadata=metadata, global_scope=True)) == "NOT_APPLICABLE"
    row["Status"] = "ACTIVE"
    assert evaluate(check_id, row, index({}, metadata=metadata, global_scope=True)) == "UNKNOWN"


def test_management_account_workloads():
    check_id = "aws_cis_organizations_management_account_workloads"
    inventory = {"collection_status": "collected", "account_id": ACCOUNT,
                 "items": [{"kind": "lambda_function", "id": "arn:aws:lambda:us-east-1:123456789012:function:governance"}]}
    row = {"Id": ACCOUNT, "Status": "ACTIVE", "WorkloadInventory": inventory}
    metadata = {"management_account_id": ACCOUNT, "governance_resource_allowlist": [inventory["items"][0]["id"]]}
    assert evaluate(check_id, row, index({"organization_account": [row]}, metadata=metadata, global_scope=True)) == "PASS"
    metadata["governance_resource_allowlist"] = []
    assert evaluate(check_id, row, index({"organization_account": [row]}, metadata=metadata, global_scope=True)) == "FAIL"
    row["WorkloadInventory"]["collection_status"] = "partial"
    assert evaluate(check_id, row, index({"organization_account": [row]}, metadata=metadata, global_scope=True)) == "UNKNOWN"
    row["Id"] = "222222222222"
    assert evaluate(check_id, row, index({"organization_account": [row]}, metadata=metadata, global_scope=True)) == "NOT_APPLICABLE"
    assert evaluate(check_id, row, index({}, metadata=metadata, global_scope=True)) == "UNKNOWN"


def ecr_case(artifact):
    image = {"imageDigest": DIGEST}
    return image, index({"ecr_image": [image], "ecr_oci_artifact": [artifact] if artifact else []},
                        metadata={"deployed_image_digests": [DIGEST]})


def test_ecr_sbom():
    check_id = "aws_ecr_sbom_present"
    artifact = {"artifactDigest": "sha256:" + "b" * 64, "artifactType": "application/spdx+json", "subject": {"digest": DIGEST},
                "payload": json.dumps({"spdxVersion": "SPDX-2.3", "packages": []})}
    image, facts = ecr_case(artifact)
    assert evaluate(check_id, image, facts) == "PASS"
    image, facts = ecr_case(None)
    assert evaluate(check_id, image, facts) == "FAIL"
    image, facts = ecr_case(artifact)
    facts["context"]["metadata"]["deployed_image_digests"] = []
    assert evaluate(check_id, image, facts) == "NOT_APPLICABLE"
    facts["context"]["metadata"].pop("deployed_image_digests")
    assert evaluate(check_id, image, facts) == "UNKNOWN"
    image, facts = ecr_case(dict(artifact, payload="{"))
    assert evaluate(check_id, image, facts) == "FAIL"
    image, facts = ecr_case(dict(artifact, payload=7))
    assert evaluate(check_id, image, facts) == "UNKNOWN"
    facts["collections"]["ecr_oci_artifact"][0]["status"] = "partial"
    assert evaluate(check_id, image, facts) == "UNKNOWN"


def test_ecr_signature_provenance():
    check_id = "aws_ecr_image_provenance"
    private = Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    payload = json.dumps({"critical": {"identity": {"docker-reference": "example/workload"}, "image": {"docker-manifest-digest": DIGEST}, "type": "cosign container image signature"}, "optional": None}, separators=(",", ":"))
    signature = base64.b64encode(private.sign(payload.encode())).decode()
    artifact = {"artifactDigest": "sha256:" + "c" * 64, "artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
                "subject": {"digest": DIGEST}, "payload": payload, "signature": signature, "keyId": "key-1"}
    image, facts = ecr_case(artifact)
    facts["context"]["metadata"]["approved_signing_public_keys"] = [{"KeyId": "key-1", "PublicKeyPem": pem}]
    assert evaluate(check_id, image, facts) == "PASS"
    artifact["signature"] = base64.b64encode(b"invalid").decode()
    assert evaluate(check_id, image, facts) == "FAIL"
    facts["context"]["metadata"].pop("approved_signing_public_keys")
    assert evaluate(check_id, image, facts) == "UNKNOWN"
    facts["collections"]["ecr_oci_artifact"][0]["status"] = "partial"
    assert evaluate(check_id, image, facts) == "UNKNOWN"
    facts["context"]["metadata"]["deployed_image_digests"] = []
    assert evaluate(check_id, image, facts) == "NOT_APPLICABLE"
