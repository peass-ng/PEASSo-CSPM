"""Source and command gate for the separately reviewed AWS service families."""

import ast
from collections import Counter
import hashlib
import inspect
import json
from pathlib import Path
import re

import botocore.session
from botocore import xform_name

from peaso.checks import CHECKS
from peaso.checks.claude_aws_a_ec2 import INSTANCE_PORTS
from peaso.checks.claude_aws_a_network import ENDPOINT_SERVICES, SG_PORTS
from peaso.remediation import template
from tests.release_successor_history import (historical_bytes, _source414_reviewed_baseline,
    _IAM_EVIDENCE_ONLY_REVERSE_HUNKS, _IAM_HISTORICAL_BASELINE_SHA256,
    _IAM_UNUSED_ACCESS_SUCCESSOR_SHA256)


ROOT = Path(__file__).resolve().parents[1]
SHARD = ROOT / "peaso/rulepacks/remediation_aws_families_reviewed.json"
CENTRAL = ROOT / "peaso/rulepacks/remediation_curated.json"
PREAPPROVED = "aws.claude_a.iam.prowler_customer_policy_no_privilege_escalation"
OTHER_AWS_SHARD_IDS = frozenset({
    "aws.claude_a.vpc.sg_world_any_cifs",
    "aws.claude_a.vpc.sg_world_any_kafka",
    "aws.claude_a.vpc.sg_world_any_kibana",
    "aws.claude_a.vpc.sg_world_any_redis",
    "aws.claude_a.vpc.sg_world_any_remote_admin",
    "aws.claude_a.vpc.sg_world_v4_cassandra",
    "aws.claude_a.vpc.sg_world_v4_common20",
    "aws.claude_a.vpc.sg_world_v4_common6",
    "aws.claude_a.vpc.sg_world_v4_memcached",
    "aws.claude_a.vpc.sg_world_v4_mongodb",
    "aws.claude_a.vpc.sg_world_v4_no_tcp_udp",
    "aws.claude_a.vpc.sg_world_v4_oracle",
    "aws.claude_a.vpc.sg_world_v4_rdp",
    "aws.claude_a.vpc.sg_world_v4_ssh",
    "aws.claude_a.vpc.sg_world_v6_remote_admin",
})


def reviewed():
    return json.loads(SHARD.read_text())


def _registered_iam_helper_matches_historical(check, helper_path, helper_line):
    """Bind the old source line and the currently registered, unwrapped helper."""
    assert helper_path == "peaso/checks/claude_aws_a_iam.py"
    archive = ROOT / "infra/aws/build/peaso-source-414e037b411d4e5abd0a214fc67b4b8bd96aede52dc843cf23748054f4dfbe6d.zip"
    historical = historical_bytes(archive, helper_path)
    assert hashlib.sha256(historical).hexdigest() == "84b8346563444a732479c1dd1a692c3fff79e7bc3253f16eecbcbe30c8793425"
    lines = historical.decode().splitlines()
    assert lines[helper_line - 1].lstrip().startswith("def evaluate(")
    tree = ast.parse(historical)
    enclosing = [parent.name for parent in tree.body if isinstance(parent, ast.FunctionDef)
                 for nested in ast.walk(parent) if isinstance(nested, ast.FunctionDef)
                 and nested.name == "evaluate" and nested.lineno == helper_line]
    assert len(enclosing) == 1
    registered = inspect.unwrap(check.evaluate)
    assert registered.__module__ == "peaso.checks.claude_aws_a_iam"
    assert registered.__qualname__ == f"{enclosing[0]}.<locals>.evaluate"
    assert Path(inspect.getsourcefile(registered)).resolve() == (ROOT / helper_path).resolve()
    source, _ = inspect.getsourcelines(registered)
    assert sum(line.lstrip().startswith("def evaluate(") for line in source) == 1




def test_each_approval_has_specific_action_and_primary_reference():
    entries = reviewed()
    repeated = Counter(row["summary"] for row in entries.values())
    assert max(repeated.values()) <= 3
    for cid, row in entries.items():
        assert cid not in row["summary"]
        assert not re.search(r"\b(?:Prowler|Steampipe|source predicate|source requirement|source policy|evaluator|upstream|helper|predicate)\b",
                             row["summary"], re.I)
        assert 1 <= len(row["steps"]) <= 5
        assert all(len(step.strip()) > 30 for step in row["steps"])
        assert row["caveats"] and row["iac"]["code"]
        field_tokens = re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", row["field_binding"]["path"])
        assert any(token.lower() in row["iac"]["code"].lower() for token in field_tokens)
        assert row["references"]
        assert all(ref["url"].startswith("https://docs.aws.amazon.com/") for ref in row["references"])
        assert isinstance(row["cli"], list)
        for command in row["cli"]:
            assert command["shell"] == "bash"
            assert command["code"].startswith("aws ")
            words = command["code"].split()
            if cid.startswith("aws.cb.waf."):
                assert words[1] == "waf"
                assert "--region us-east-1" in command["code"]
            elif cid.startswith("aws.cb.wafregional."):
                assert words[1] == "waf-regional"
                assert "--region <REGION>" in command["code"]
            if cid == "aws.claude_a.s3.multi_region_access_point_public_access_block":
                assert words[1] == "s3control"
                assert "--region us-west-2" in command["code"]
            elif words[1] not in {"iam", "organizations", "cloudfront", "route53", "route53domains",
                                "globalaccelerator", "support", "waf"}:
                assert "--region <REGION>" in command["code"], (cid, command["code"])
            assert not re.search(r"\$\(|`|\b--profile\b", command["code"])
            assert not words[2].startswith("delete-"), (cid, command["code"])
            if re.search(r"\bput-\w+", command["code"]):
                assert ((cid == "aws.cb.glue.catalog_policy_not_public"
                         and "put-resource-policy" in command["code"]
                         and "<REVIEWED_GLUE_CATALOG_POLICY_REQUEST_JSON>" in command["code"])
                        or ("put-key-policy" in command["code"] and "<REVIEWED_KMS_POLICY_FILE>" in command["code"])
                        or (cid == "aws.cb.ses.dkim_signing" and "put-email-identity-dkim-attributes" in command["code"])
                        or (cid == "aws.cb.wafv2.web_acl_logging" and "put-logging-configuration" in command["code"]
                            and "<REVIEWED_WAF_LOGGING_JSON>" in command["code"])
                        or (cid in {"aws.cb.lightsail.instance_not_public", "aws.cb.lightsail.ssh_restricted",
                                    "aws.cb.lightsail.rdp_restricted",
                                    "aws.cb.lightsail.ssh_rdp_http_world_closed"} and "put-instance-public-ports" in command["code"]
                            and "<REVIEWED_FULL_LIGHTSAIL_PORTS_JSON>" in command["code"])
                        or (cid in {"aws.cb.secretsmanager.policy_not_public",
                                    "aws.cb.secretsmanager.policy_prohibit_public_access_perimeter"}
                            and "put-resource-policy" in command["code"]
                            and "<REVIEWED_SECRET_POLICY_JSON>" in command["code"])
                        or (cid in {"aws.cb.glue.catalog_metadata_encryption",
                                    "aws.cb.glue.catalog_password_encryption",
                                    "aws.cb.glue.catalog_password_encryption_with_tables",
                                    "aws.cb.glue.catalog_metadata_sse_kms_with_tables"}
                            and "put-data-catalog-encryption-settings" in command["code"]
                            and "<REVIEWED_GLUE_CATALOG_ENCRYPTION_JSON>" in command["code"])
                        or (cid in {"aws.claude_a.s3.account_public_access_block_all",
                                    "aws.claude_a.s3.bucket_public_access_block_all",
                                    "aws.claude_a.s3.prowler_account_ignore_restrict",
                                    "aws.claude_a.s3.prowler_bucket_level_public_access_block"}
                            and "put-public-access-block" in command["code"]
                            and "<REVIEWED_S3_PUBLIC_ACCESS_BLOCK_JSON>" in command["code"])
                        or (cid in {"aws.claude_a.s3.default_encryption_kms_key",
                                    "aws.claude_a.s3.prowler_kms_encryption"}
                            and "put-bucket-encryption" in command["code"]
                            and "<REVIEWED_S3_ENCRYPTION_JSON>" in command["code"])
                        or (cid in {"aws.claude_a.s3.lifecycle_rule_enabled",
                                    "aws.claude_a.s3.versioning_and_lifecycle"}
                            and "put-bucket-lifecycle-configuration" in command["code"]
                            and "<REVIEWED_S3_LIFECYCLE_JSON>" in command["code"])
                        or (cid == "aws.claude_a.s3.versioning_and_lifecycle"
                            and "put-bucket-versioning" in command["code"]
                            and "Status=Enabled" in command["code"])
                        or (cid in {"aws.claude_a.s3.replication_rule_enabled",
                                    "aws.claude_a.s3.prowler_cross_region_replication"}
                            and "put-bucket-replication" in command["code"]
                            and "<REVIEWED_S3_REPLICATION_JSON>" in command["code"])
                        or (cid == "aws.claude_a.s3.prowler_cross_region_replication"
                            and "put-bucket-versioning" in command["code"]
                            and "Status=Enabled" in command["code"])
                        or (cid == "aws.claude_a.s3.object_lock_configured"
                            and "put-object-lock-configuration" in command["code"]
                            and "<REVIEWED_S3_OBJECT_LOCK_JSON>" in command["code"])
                        or (cid == "aws.claude_a.s3.event_notifications"
                            and "put-bucket-notification-configuration" in command["code"]
                            and "<REVIEWED_S3_NOTIFICATIONS_JSON>" in command["code"])
                        or (cid in {"aws.claude_a.s3.acls_prohibit_user_access",
                                    "aws.claude_a.s3.prowler_acl_disabled"}
                            and "put-bucket-ownership-controls" in command["code"]
                            and "<REVIEWED_S3_OWNERSHIP_JSON>" in command["code"])
                        or (cid in {"aws.claude_a.s3.acls_prohibit_user_access",
                                    "aws.claude_a.s3.no_authenticated_users_acl",
                                    "aws.claude_a.s3.restrict_public_read"}
                            and "put-bucket-acl" in command["code"]
                            and "<REVIEWED_S3_ACL_JSON>" in command["code"])
                        or (cid in {"aws.claude_a.s3.prowler_public_access",
                                    "aws.claude_a.s3.prowler_public_list_acl",
                                    "aws.claude_a.s3.prowler_public_write_acl"}
                            and "put-public-access-block" in command["code"]
                            and "<REVIEWED_S3_PUBLIC_ACCESS_BLOCK_JSON>" in command["code"])
                        or (cid in {"aws.claude_a.s3.prowler_public_access",
                                    "aws.claude_a.s3.prowler_public_list_acl",
                                    "aws.claude_a.s3.prowler_public_write_acl"}
                            and "put-bucket-acl" in command["code"]
                            and "<REVIEWED_S3_ACL_JSON>" in command["code"])
                        or (cid == "aws.claude_a.s3.prowler_public_access"
                            and "put-bucket-policy" in command["code"]
                            and "<REVIEWED_S3_BUCKET_POLICY_JSON>" in command["code"])
                        or (cid in {"aws.claude_a.s3.policy_no_cross_account_permission_changes",
                                    "aws.claude_a.s3.perimeter_policy_not_public",
                                    "aws.claude_a.s3.prowler_cross_account_policy",
                                    "aws.claude_a.s3.prowler_policy_public_write",
                                    "aws.claude_a.s3.restrict_public_read",
                                    "aws.claude_a.s3.policy_restrict_public_access"}
                            and "put-bucket-policy" in command["code"]
                            and "<REVIEWED_S3_BUCKET_POLICY_JSON>" in command["code"])
                        or (cid == "aws.claude_a.s3.prowler_policy_public_write"
                            and "put-public-access-block" in command["code"]
                            and "<REVIEWED_S3_PUBLIC_ACCESS_BLOCK_JSON>" in command["code"])
                        or (cid == "aws.claude_a.s3.object_level_logging"
                            and "put-event-selectors" in command["code"]
                            and "<REVIEWED_S3_DATA_SELECTORS_JSON>" in command["code"])
                        or (cid == "aws.cb.lambda.cloudtrail_data_events"
                            and "put-event-selectors" in command["code"]
                            and "<REVIEWED_LAMBDA_DATA_SELECTORS_JSON>" in command["code"])
                        or (row["source_proof"].get("generated_family") == "IAM_PRINCIPAL"
                            and row["source_proof"]["suffix"].startswith("inline_")
                            and f"put-{row['source_proof']['principal_type']}-policy" in command["code"]
                            and "<REVIEWED_POLICY_INPUT_FILE>" in command["code"])
                        or (row["source_proof"].get("generated_family") == "PROWLER_INLINE"
                            and f"put-{row['source_proof']['principal_type']}-policy" in command["code"]
                            and "<REVIEWED_POLICY_INPUT_FILE>" in command["code"])
                        or (cid == "aws.claude_a.s3.directory_bucket_lifecycle"
                            and "put-bucket-lifecycle-configuration" in command["code"]
                            and "<REVIEWED_DIRECTORY_LIFECYCLE_JSON>" in command["code"]))
            placeholders = set(re.findall(r"<([A-Z][A-Z0-9_]*)>", command["code"]))
            assert placeholders <= {"RESOURCE_ID", "RESOURCE_ARN", "RESOURCE_NAME", "REGION",
                                    "INSTANCE_ID", "IMAGE_ID", "REVIEWED_HVM_AMI_ID",
                                    "REVIEWED_SECURITY_GROUP_IDS", "REVIEWED_INSTANCE_PROFILE_NAME",
                                    "NETWORK_INTERFACE_ID",
                                    "BACKUP_PLAN_ID", "SELECTION_ID", "REVIEWED_SELECTION_FILE",
                                    "SECURITY_GROUP_ID", "RULE_ID", "REVIEWED_INSTANCE_PROFILE_NAME", "ROLE_NAME",
                                    "INLINE_POLICY_NAME", "POLICY_ARN", "VERSION_ID", "VAULT_NAME",
                                    "ACCOUNT_ID", "REVIEWED_POLICY_INPUT_FILE", "API_ID", "STAGE_NAME",
                                    "REVIEWED_ACCESS_LOG_SETTINGS_JSON", "REVIEWED_SUBNET_ID",
                                    "REVIEWED_SECURITY_GROUP_ID", "DETECTOR_ID", "REVIEWED_FEATURES_JSON",
                                    "BROKER_ID", "REVIEWED_LOG_CONFIG_JSON", "REVIEWED_KMS_POLICY_FILE",
                                    "REVIEWED_ENCRYPTION_CONFIG_JSON", "SERVER_ID", "CONNECTOR_ID",
                                    "REVIEWED_PROTOCOLS_JSON", "APPROVED_FIPS_POLICY_NAME",
                                    "APPROVED_PQC_POLICY_NAME", "REVIEWED_ROLE_ARN", "EMAIL_IDENTITY",
                                    "POLICY_NAME", "REVIEWED_SES_POLICY_FILE", "REVIEWED_KMS_KEY_ARN",
                                    "DELIVERY_STREAM_NAME", "REVIEWED_ENCRYPTION_CONFIG_JSON",
                                    "WORKSPACE_ID", "REVIEWED_WORKSPACE_REQUESTS_JSON", "NETWORK_ACL_ID",
                                    "REVIEWED_WEB_ACL_UPDATE_JSON", "REVIEWED_WAF_LOGGING_JSON",
                                    "REVIEWED_RULE_GROUP_UPDATE_JSON", "WORKLOAD_ID", "LENS_ALIAS",
                                    "FINDING_ID", "REVIEWED_SEVERITY8_ACTIVE_FILTER_JSON",
                                    "DOCUMENT_NAME", "REVIEWED_ACCOUNT_ID_OR_ALL", "QUEUE_URL",
                                    "REVIEWED_SQS_ATTRIBUTES_JSON", "REVIEWED_SQS_POLICY_ATTRIBUTES_JSON",
                                    "DOMAIN_NAME", "CURRENT_EXPIRY_YEAR", "REVIEWED_YEARS",
                                    "HOSTED_ZONE_ID", "REVIEWED_LOG_GROUP_ARN",
                                    "REVIEWED_PROTOCOL_FAILURE_ROLE_ATTRIBUTE", "REVIEWED_FEEDBACK_ROLE_ARN",
                                    "TOPIC_ARN", "REVIEWED_HTTPS_ENDPOINT",
                                    "REVIEWED_SNS_POLICY_FILE", "REVIEWED_LAMBDA_LOGGING_JSON",
                                    "REVIEWED_SUBNET_IDS", "REVIEWED_LAMBDA_VPC_JSON",
                                    "REVIEWED_STATEMENT_ID", "CLUSTER_NAME",
                                    "REVIEWED_MEMORYDB_CREATE_JSON", "NAMESPACE_NAME",
                                    "WORKGROUP_NAME", "REVIEWED_LOG_EXPORTS_JSON",
                                    "REVIEWED_ADMIN_USERNAME", "REVIEWED_NAMESPACE_CREATE_JSON",
                                    "REVIEWED_WORKGROUP_PARAMS_JSON",
                                    "REVIEWED_INSPECTOR_RESOURCE_TYPES_JSON",
                                    "REVIEWED_COVERAGE_FILTER_JSON",
                                    "REVIEWED_ACTIVE_FINDINGS_FILTER_JSON", "REVIEWED_FINDING_ARNS",
                                    "REVIEWED_SSM_RESOURCE_FILTER_JSON",
                                    "REVIEWED_CONNECTOR_CREATE_JSON", "CURRENT_CLUSTER_VERSION",
                                    "REVIEWED_MSK_CLUSTER_CREATE_JSON", "REVIEWED_MONITORING_LEVEL",
                                    "REVIEWED_MSK_TRANSIT_JSON", "REVIEWED_MSK_CONNECTIVITY_JSON",
                                    "REVIEWED_MSK_AUTH_JSON", "REVIEWED_COMPATIBLE_ACTIVE_KAFKA_VERSION", "DB_CLUSTER_ID",
                                    "REVIEWED_RETENTION_DAYS", "PARAM_GROUP_NAME",
                                    "REVIEWED_NEPTUNE_AUDIT_PARAMS_JSON", "REVIEWED_NEPTUNE_EXPORTS_JSON",
                                    "SNAPSHOT_ID_OR_ARN", "REVIEWED_ENCRYPTED_SNAPSHOT_ID",
                                    "REVIEWED_SOURCE_SNAPSHOT_ID", "REVIEWED_NEPTUNE_RESTORE_JSON",
                                    "REVIEWED_READER_ID", "REVIEWED_INSTANCE_CLASS", "REVIEWED_AZ",
                                    "DB_SUBNET_GROUP_NAME", "REVIEWED_ROUTE_TABLE_IDS",
                                    "INSTANCE_NAME", "DATABASE_NAME", "STATIC_IP_NAME",
                                    "REVIEWED_INSTANCE_NAME", "REVIEWED_FULL_LIGHTSAIL_PORTS_JSON",
                                    "REVIEWED_PROTECTION_NAME", "REVIEWED_ROTATION_LAMBDA_ARN",
                                    "REVIEWED_ROTATION_DAYS", "REVIEWED_SECRET_POLICY_JSON",
                                    "PORTFOLIO_ID", "REVIEWED_TRAIL_NAME", "REVIEWED_TRAIL_BUCKET_NAME",
                                    "REVIEWED_STANDARDS_REQUESTS_JSON", "REVIEWED_DEVICE_NAME",
                                    "CHECK_ID", "TRUST_ANCHOR_ID", "REVIEWED_CA_ARN",
                                    "REVIEWED_TRUST_ANCHOR_SOURCE_JSON", "LAUNCH_TEMPLATE_ID",
                                    "CURRENT_DEFAULT_VERSION", "REVIEWED_LAUNCH_TEMPLATE_DATA_JSON",
                                    "REVIEWED_NEW_VERSION", "CATALOG_ID",
                                    "REVIEWED_GLUE_CATALOG_ENCRYPTION_JSON", "CONNECTION_NAME",
                                    "REVIEWED_GLUE_CONNECTION_INPUT_JSON", "TRANSFORM_ID",
                                    "JOB_NAME", "REVIEWED_GLUE_JOB_UPDATE_JSON",
                                    "REVIEWED_RDS_LOG_EXPORTS_JSON", "KMS_KEY_ID",
                                    "REVIEWED_RDS_CLUSTER_PARAMS_JSON",
                                    "REVIEWED_RDS_INSTANCE_PARAMS_JSON",
                                    "DB_INSTANCE_ID", "ENGINE", "ENGINE_VERSION", "DB_INSTANCE_CLASS",
                                    "REVIEWED_MONITORING_ROLE_NAME",
                                    "REVIEWED_MONITORING_INTERVAL", "REVIEWED_MONITORING_ROLE_ARN",
                                    "BUCKET_NAME", "REVIEWED_S3_PUBLIC_ACCESS_BLOCK_JSON",
                                    "REVIEWED_S3_ENCRYPTION_JSON", "REVIEWED_S3_LIFECYCLE_JSON",
                                    "REVIEWED_S3_REPLICATION_JSON", "REVIEWED_DEST_BUCKET_NAME",
                                    "REVIEWED_S3_OBJECT_LOCK_JSON", "REVIEWED_S3_NOTIFICATIONS_JSON",
                                    "RULE_GROUP_ID", "WEB_ACL_ID", "WEB_ACL_ARN",
                                    "REVIEWED_S3_OWNERSHIP_JSON", "REVIEWED_S3_ACL_JSON",
                                    "REVIEWED_S3_BUCKET_POLICY_JSON", "ACCESS_POINT_NAME",
                                    "REVIEWED_ACCESS_POINT_CREATE_JSON", "MRAP_NAME",
                                    "REVIEWED_NEW_MRAP_NAME", "REVIEWED_MRAP_DETAILS_JSON",
                                    "REVIEWED_MRAP_IDEMPOTENCY_TOKEN",
                                    "DIRECTORY_BUCKET_NAME", "REVIEWED_DIRECTORY_LIFECYCLE_JSON",
                                    "TRAIL_NAME", "REVIEWED_S3_DATA_SELECTORS_JSON", "JOB_ID",
                                    "REVIEWED_MACIE_JOB_JSON", "REVIEWED_REDSHIFT_CREATE_JSON",
                                    "REVIEWED_KMS_KEY_ARN", "CLUSTER_ID",
                                    "REVIEWED_REDSHIFT_SSL_PARAMS_JSON", "REVIEWED_SNAPSHOT_ID",
                                    "SUBNET_GROUP_NAME", "REVIEWED_OPENSEARCH_ENCRYPTION_JSON",
                                    "REVIEWED_OPENSEARCH_FGAC_JSON", "REVIEWED_OPENSEARCH_IDENTITY_JSON",
                                    "REVIEWED_OPENSEARCH_DATA_NODES_JSON", "REVIEWED_OPENSEARCH_MASTER_NODES_JSON",
                                    "REVIEWED_OPENSEARCH_COGNITO_JSON", "REVIEWED_OPENSEARCH_DASHBOARDS_AUTH_JSON",
                                    "REVIEWED_OPENSEARCH_NODE_TLS_JSON", "REVIEWED_OPENSEARCH_HTTPS_JSON",
                                    "REVIEWED_LOG_GROUP_NAME", "REVIEWED_OPENSEARCH_AUDIT_LOGS_JSON",
                                    "REVIEWED_OPENSEARCH_SLOW_LOGS_JSON", "REVIEWED_OPENSEARCH_LOG_GROUPS_JSON",
                                    "REVIEWED_VPC_ID", "REVIEWED_OPENSEARCH_VPC_DOMAIN_JSON",
                                    "REVIEWED_OPENSEARCH_ACCESS_POLICY_JSON",
                                    "REVIEWED_GLUE_CATALOG_POLICY_REQUEST_JSON", "ENDPOINT_NAME",
                                    "SECURITY_CONFIGURATION_NAME", "REVIEWED_GLUE_DEV_ENDPOINT_CREATE_JSON",
                                    "REVIEWED_GLUE_JOB_UPDATE_JSON", "REVIEWED_GLUE_SECURITY_CONFIGURATION_JSON",
                                    "REVIEWED_SUPPORTED_RUNTIME", "REVIEWED_LAMBDA_DATA_SELECTORS_JSON",
                                    "REVIEWED_INCIDENT_REPLICATION_JSON", "REVIEWED_INCIDENT_RESPONSE_PLAN_JSON",
                                    "ANALYZER_ARN", "REVIEWED_ANALYZER_NAME", "CURRENT_UPDATE_TOKEN", "REVIEWED_NFW_LOGGING_JSON", "REVIEWED_NFW_CREATE_JSON",
                                    "REVIEWED_NFW_POLICY_JSON", "REVIEWED_NFW_RULE_GROUP_UPDATE_JSON",
                                    "NOTEBOOK_INSTANCE_NAME", "REVIEWED_SAGEMAKER_NOTEBOOK_CREATE_JSON",
                                    "MODEL_NAME", "REVIEWED_SAGEMAKER_MODEL_CREATE_JSON",
                                    "TRAINING_JOB_NAME", "REVIEWED_SAGEMAKER_TRAINING_JOB_JSON",
                                    "ENDPOINT_CONFIG_NAME", "REVIEWED_SAGEMAKER_ENDPOINT_CONFIG_JSON",
                                    "REVIEWED_ENDPOINT_CONFIG_NAME", "DOMAIN_ID",
                                    "REVIEWED_SAGEMAKER_SSO_DOMAIN_JSON", "MONITORING_SCHEDULE_NAME",
                                    "REVIEWED_SAGEMAKER_MONITORING_JSON", "MODEL_PACKAGE_GROUP_NAME",
                                    "MODEL_PACKAGE_ARN", "REVIEWED_MODEL_PACKAGE_JSON",
                                    "REVIEWED_MODEL_PACKAGE_GROUP_JSON", "PROCESSING_JOB_NAME",
                                    "REVIEWED_SAGEMAKER_CLARIFY_JOB_JSON", "VPC_ID",
                                    "REVIEWED_VPC_FLOW_LOG_JSON", "REVIEWED_SUBNET_CREATE_JSON",
                                    "SUBNET_ID", "REVIEWED_SERVICE_PRINCIPAL", "TARGET_ID",
                                    "REVIEWED_EC2_ENDPOINT_JSON", "VPC_ENDPOINT_ID",
                                    "SERVICE_ID", "REVIEWED_ENDPOINT_PRINCIPALS_JSON",
                                    "VPN_CONNECTION_ID", "REVIEWED_VPN_TUNNEL_OPTIONS_JSON",
                                    "POLICY_ID", "INTERNET_GATEWAY_ID", "ROUTE_TABLE_ID",
                                    "PEERING_CONNECTION_ID", "REVIEWED_ENDPOINT_POLICY_JSON",
                                    "USER_NAME", "GROUP_NAME", "ACCESS_KEY_ID",
                                    "REVIEWED_GROUP_NAME", "REVIEWED_ADMIN_POLICY_ARN",
                                    "REVIEWED_TRUST_POLICY_FILE", "REVIEWED_BACKUP_SELECTION_JSON",
                                    "REVIEWED_ROLE_NAME", "REVIEWED_SAML_METADATA_XML",
                                    "REVIEWED_SAML_PROVIDER_NAME", "DB_SNAPSHOT_ID",
                                    "DB_CLUSTER_SNAPSHOT_ID", "REVIEWED_SNAPSHOT_SHARE_VALUE",
                                    "REVIEWED_TARGET_SNAPSHOT_ID", "EVENT_SUBSCRIPTION_NAME",
                                    "REVIEWED_RDS_EVENT_SUBSCRIPTION_JSON",
                                    "REVIEWED_ENGINE_NAME", "REVIEWED_CA_ID"}
            if words[1] in {"wafv2", "memorydb", "redshift-serverless", "redshift", "opensearch", "glue", "ssm-incidents", "network-firewall", "sagemaker", "kafkaconnect", "kafka", "neptune", "s3control", "macie2", "ec2", "backup", "rds"} and "--cli-input-json" in words:
                assert any("file://<REVIEWED_" in word and word.endswith("_JSON>") for word in words)


def test_inspection_cli_operation_and_required_flags_exist_in_botocore():
    session = botocore.session.get_session()
    for cid, row in reviewed().items():
        for command in row["cli"]:
            words = command["code"].split()
            model = session.get_service_model({"s3api": "s3"}.get(words[1], words[1]))
            operation = next((name for name in model.operation_names if xform_name(name, "-") == words[2]), None)
            assert operation, (cid, command["code"])
            shape = model.operation_model(operation).input_shape
            if words[1] in {"wafv2", "memorydb", "redshift-serverless", "redshift", "opensearch", "glue", "ssm-incidents", "network-firewall", "sagemaker", "kafkaconnect", "kafka", "neptune", "s3control", "macie2", "ec2", "backup", "rds"} and "--cli-input-json" in words:
                continue  # The reviewed complete JSON document supplies every required API member.
            for member in shape.required_members if shape else []:
                assert "--" + xform_name(member, "-") in words, (cid, member)


def test_ebs_predicates_preserve_immutable_and_selection_semantics():
    entries = reviewed()
    assert "cannot be enabled in place" in entries["aws.claude_a.ebs.attached_volume_encrypted"]["caveats"][0]
    assert "immutable" in entries["aws.claude_a.ebs.snapshot_encrypted"]["caveats"][0]
    assert "without values" in entries["aws.claude_a.ebs.volume_in_backup_selection"]["caveats"][0]
    assert "UpdateBackupSelection" in entries["aws.claude_a.ebs.volume_in_backup_selection"]["caveats"][0]
    assert "CreateVolumePermissions" in entries["aws.claude_a.ebs.snapshot_not_public"]["field_binding"]["path"]


def test_s3_immutable_access_points_require_replacement_and_correct_home_region():
    entries = reviewed()
    ap = entries["aws.claude_a.s3.access_point_public_access_block"]
    mrap = entries["aws.claude_a.s3.multi_region_access_point_public_access_block"]
    assert "cannot be changed after creation" in ap["caveats"][0]
    assert "cannot change after creation" in mrap["caveats"][0]
    assert "create-access-point --cli-input-json file://<REVIEWED_ACCESS_POINT_CREATE_JSON>" in ap["cli"][1]["code"]
    assert all("--region us-west-2" in command["code"] for command in mrap["cli"])
    assert "--client-token <REVIEWED_MRAP_IDEMPOTENCY_TOKEN>" in mrap["cli"][1]["code"]
    website = entries["aws.claude_a.s3.static_website_disabled"]
    assert "cannot use OAC with an S3 website endpoint" in website["caveats"][0]
    directory = entries["aws.claude_a.s3.directory_bucket_lifecycle"]
    assert "not storage-class transitions" in directory["caveats"][0]




def test_fsx_multi_az_family_requires_replacement_and_exact_modes():
    expected = {
        "aws.cb.fsx.ontap_multi_az": ("ONTAP", ["MULTI_AZ_1", "MULTI_AZ_2"]),
        "aws.cb.fsx.openzfs_multi_az": ("OPENZFS", ["MULTI_AZ_1"]),
        "aws.cb.fsx.windows_multi_az_deployment": ("WINDOWS", ["MULTI_AZ_1"]),
    }
    rows = reviewed()
    for cid, (file_system_type, modes) in expected.items():
        assert rows[cid]["source_proof"]["file_system_type"] == file_system_type
        assert rows[cid]["source_proof"]["accepted"] == modes
        assert "cannot be changed in place" in rows[cid]["caveats"][0]
        assert not any("update-file-system" in command["code"] for command in rows[cid]["cli"])


def test_vpc_endpoint_family_explains_source_name_only_semantics():
    rows = reviewed()
    endpoint_rows = {cid: row for cid, row in rows.items() if row["source_proof"].get("generated_family") == "ENDPOINT_SERVICES"}
    assert len(endpoint_rows) == len(ENDPOINT_SERVICES)
    for row in endpoint_rows.values():
        assert "does not evaluate endpoint state or type" in row["steps"][2]
        assert "<REVIEWED_SUBNET_ID>" in row["cli"][1]["code"]


def test_security_group_port_family_uses_exact_source_tuples_and_rule_ids():
    rows = reviewed()
    group_rows = {cid: row for cid, row in rows.items() if row["source_proof"].get("generated_family") == "SG_PORTS"}
    assert len(group_rows) == len(SG_PORTS)
    for row in group_rows.values():
        assert "NOT_APPLICABLE" in row["caveats"][0]
        assert "--security-group-rule-ids <RULE_ID>" in row["cli"][1]["code"]


def test_nacl_ordered_and_unordered_predicates_keep_distinct_limits():
    rows = reviewed()
    for cid in ("aws.claude_a.vpc.nacl_no_world_all_ports",
                "aws.claude_a.vpc.nacl_no_world_tcp_22",
                "aws.claude_a.vpc.nacl_no_world_tcp_3389"):
        assert rows[cid]["source_proof"]["generated_family"] == "NACL_ORDER"
        assert "No single safe CLI mutation" in rows[cid]["caveats"][0]
    assert "earlier Deny" in rows["aws.claude_a.vpc.nacl_no_world_remote_admin"]["caveats"][0]


def test_guardduty_data_sources_do_not_claim_a_deprecated_mutation():
    rows = reviewed()
    for cid in ("aws.claude_a.guardduty.prowler_s3_protection",
                "aws.claude_a.guardduty.prowler_eks_audit_logs",
                "aws.claude_a.guardduty.prowler_ec2_malware_protection"):
        row = rows[cid]
        assert "DataSources" in row["field_binding"]["path"]
        assert "deprecated" in " ".join(row["caveats"])
        assert all("--data-sources" not in command["code"] for command in row["cli"])
    assert "MANUAL" in " ".join(rows["aws.claude_a.guardduty.prowler_ai_protection"]["caveats"])
    assert "Legacy EKS_RUNTIME_MONITORING alone" in " ".join(rows["aws.claude_a.guardduty.prowler_runtime_monitoring"]["caveats"])


def test_kms_state_and_immutable_region_guidance_keeps_source_semantics():
    rows = reviewed()
    assert "PendingDeletion passes" in rows["aws.claude_a.kms.customer_key_enabled_or_pending_deletion"]["caveats"][0]
    assert "PendingDeletion counts as passing" in rows["aws.claude_a.kms.prowler_cmk_used"]["caveats"][0]
    assert "MultiRegion is immutable" in rows["aws.claude_a.kms.prowler_cmk_single_region"]["caveats"][0]
    assert "EXTERNAL origin" in rows["aws.claude_a.kms.prowler_cmk_rotation"]["caveats"][0]
    for cid in ("aws.claude_a.kms.key_policy_not_public", "aws.claude_a.kms.prowler_key_not_public"):
        assert "<REVIEWED_KMS_POLICY_FILE>" in rows[cid]["cli"][-1]["code"]


def test_step_functions_logging_predicates_keep_distinct_absent_behavior():
    rows = reviewed()
    assert "absent loggingConfiguration is treated as passing" in rows["aws.cb.sfn.logging_not_off"]["summary"]
    assert "absent or OFF fails" in rows["aws.cb.stepfunctions.logging_enabled"]["summary"]


def test_kinesis_retention_and_key_literal_do_not_overstate_coverage():
    rows = reviewed()
    assert "at least 168" in rows["aws.cb.kinesis.retention_at_least_168h"]["summary"]
    assert "equal 168 exactly" in rows["aws.cb.kinesis.retention_exactly_168h"]["summary"]
    assert "Decreasing" in rows["aws.cb.kinesis.retention_exactly_168h"]["caveats"][0]
    assert "not proof of a customer managed key" in rows["aws.cb.kinesis.customer_kms_key"]["caveats"][0]


def test_wafv2_reviews_keep_rule_list_and_full_update_semantics():
    rows = reviewed()
    broad = rows["aws.cb.wafv2.web_acl_has_rules_or_fms_groups"]
    narrow = rows["aws.cb.wafv2.web_acl_has_rules"]
    assert "PreProcessFirewallManagerRuleGroups" in broad["field_binding"]["path"]
    assert narrow["field_binding"]["path"] == "WebACL.Rules"
    assert "Firewall Manager groups do not satisfy" in narrow["caveats"][0]
    for cid in ("aws.cb.wafv2.web_acl_has_rules_or_fms_groups", "aws.cb.wafv2.web_acl_has_rules",
                "aws.cb.wafv2.web_acl_rule_metrics", "aws.cb.wafv2.rule_group_metrics"):
        row = rows[cid]
        assert "lock token" in " ".join(row["steps"] + row["caveats"]).lower()
        assert any("--cli-input-json file://<REVIEWED_" in command["code"] for command in row["cli"])
    assert "ACL with no rules" in rows["aws.cb.wafv2.web_acl_rule_metrics"]["caveats"][0]


def test_guardduty_finding_archival_is_incident_review_not_a_resource_fix():
    rows = reviewed()
    archived = rows["aws.claude_a.guardduty.finding_archived"]
    high = rows["aws.claude_a.guardduty.prowler_no_high_severity_findings"]
    assert "Service.Archived" == archived["field_binding"]["path"]
    assert "Archiving does not remediate" in archived["caveats"][0]
    assert "HighSeverityFindingIds.items" == high["field_binding"]["path"]
    assert "<REVIEWED_SEVERITY8_ACTIVE_FILTER_JSON>" in high["cli"][0]["code"]
    corrected = rows["aws.claude_a.guardduty.detector_no_findings"]
    assert corrected["field_binding"]["path"] == high["field_binding"]["path"]
    assert "<REVIEWED_SEVERITY8_ACTIVE_FILTER_JSON>" in corrected["cli"][0]["code"]
    assert "Archiving before actual resource remediation" in corrected["caveats"][1]


def test_ssm_public_sharing_setting_uses_documented_disable_value():
    rows = reviewed()
    public = rows["aws.cb.ssm.block_public_document_sharing"]
    logs = rows["aws.cb.ssm.automation_logs_to_cloudwatch"]
    assert "--setting-value Disable" in public["cli"][1]["code"]
    assert "existing documents" in public["caveats"][0]
    assert "--setting-value CloudWatch" in logs["cli"][1]["code"]
    document = rows["aws.cb.ssm.document_shared_only_with_trusted"]
    assert document["field_binding"]["path"] == "Permissions.AccountIds"
    assert "<REVIEWED_ACCOUNT_ID_OR_ALL>" in document["cli"][1]["code"]
    assert "legitimate cross-account share" in document["caveats"][0]


def test_sqs_queue_attributes_require_owned_target_and_key_review():
    rows = reviewed()
    dlq = rows["aws.cb.sqs.dead_letter_queue"]
    key = rows["aws.cb.sqs.cmk_encryption"]
    assert dlq["field_binding"]["path"] == "Attributes.Attributes.RedrivePolicy"
    assert "does not validate the target queue" in dlq["caveats"][0]
    assert "maxReceiveCount" in dlq["steps"][1]
    assert key["field_binding"]["path"] == "Attributes.Attributes.KmsMasterKeyId"
    assert "Existing messages may remain encrypted" in key["caveats"][0]
    for row in (dlq, key):
        assert "<QUEUE_URL>" in row["cli"][0]["code"]
        assert "<REVIEWED_SQS_ATTRIBUTES_JSON>" in row["cli"][1]["code"]


def test_sqs_policy_checks_keep_distinct_condition_semantics():
    rows = reviewed()
    strict = rows["aws.cb.sqs.policy_no_wildcard_allow"]
    perimeter = rows["aws.cb.sqs.policy_prohibit_public_access_perimeter"]
    public = rows["aws.cb.sqs.queue_not_public_prowler"]
    assert "even if" in strict["summary"] and "Condition" in strict["summary"]
    assert "absent Policy is not applicable" in perimeter["caveats"][0]
    assert "unlike the unconditional wildcard-principal check" in public["caveats"][0]
    for row in (strict, perimeter, public):
        assert row["field_binding"]["path"] == "Attributes.Attributes.Policy"
        assert "<REVIEWED_SQS_POLICY_ATTRIBUTES_JSON>" in row["cli"][1]["code"]


def test_route53_domain_thresholds_and_registration_actions_are_distinct():
    rows = reviewed()
    assert "Detail.AdminPrivacy" == rows["aws.cb.route53.domain_privacy_protection"]["field_binding"]["path"]
    assert "only" in rows["aws.cb.route53.domain_privacy_protection"]["caveats"][0]
    assert "clientTransferProhibited" in rows["aws.cb.route53.domain_transfer_lock"]["summary"]
    for days in (30, 7):
        row = rows[f"aws.cb.route53.domain_expires_after_{days}_days"]
        assert f"calendar days" in row["summary"]
        assert "<CURRENT_EXPIRY_YEAR>" in row["cli"][1]["code"]
        assert "billable" in row["caveats"][0].lower()
    expired = rows["aws.cb.route53.domain_not_expired"]
    assert len(expired["cli"]) == 1
    assert "No universal safe renewal command" in expired["caveats"][0]
    zone = rows["aws.cb.route53.public_zone_query_logging"]
    assert "Config.PrivateZone" in zone["field_binding"]["path"]
    assert "<REVIEWED_LOG_GROUP_ARN>" in zone["cli"][1]["code"]


def test_sns_feedback_and_http_subscription_do_not_overstate_fix():
    rows = reviewed()
    feedback = rows["aws.cb.sns.failure_feedback_role"]
    http = rows["aws.cb.sns.subscription_not_http"]
    assert "any one failure role" in feedback["caveats"][0]
    assert "<REVIEWED_PROTOCOL_FAILURE_ROLE_ATTRIBUTE>" in feedback["cli"][1]["code"]
    assert "PendingConfirmation" in http["caveats"][0]
    assert "does not clear the old HTTP finding" in http["caveats"][0]
    assert "<REVIEWED_HTTPS_ENDPOINT>" in http["cli"][1]["code"]


def test_sns_policy_approvals_preserve_action_and_loop_limits():
    rows = reviewed()
    publish = rows["aws.cb.sns.policy_no_public_publish"]
    subscribe = rows["aws.cb.sns.policy_no_public_subscribe"]
    assert publish["source_proof"]["actions"] == ("sns:publish",) or publish["source_proof"]["actions"] == ["sns:publish"]
    assert set(subscribe["source_proof"]["actions"]) == {"sns:subscribe", "sns:receive"}
    assert "does not match a wildcard action" in publish["caveats"][0]
    assert "does not catch sns:*" in subscribe["caveats"][0]
    assert "return passing early" in rows["aws.cb.sns.topic_not_publicly_accessible_prowler"]["caveats"][0]
    for cid in ("aws.cb.sns.policy_no_unrestricted_wildcard",
                "aws.cb.sns.policy_prohibit_public_access_perimeter",
                "aws.cb.sns.policy_no_public_publish", "aws.cb.sns.policy_no_public_subscribe",
                "aws.cb.sns.topic_not_publicly_accessible_prowler"):
        assert "<REVIEWED_SNS_POLICY_FILE>" in rows[cid]["cli"][1]["code"]


def test_lambda_config_templates_keep_evidence_and_network_limits():
    rows = reviewed()
    kms = rows["aws.cb.lambda.kms_key_configured"]
    logging = rows["aws.cb.lambda.logging_config_present"]
    vpc = rows["aws.cb.lambda.vpc_multiple_az"]
    assert "does not prove customer-managed ownership" in kms["caveats"][0]
    assert "explicitly null" in logging["summary"]
    assert "UNKNOWN" in logging["caveats"][0]
    assert "subnet.AvailabilityZoneId" in vpc["field_binding"]["path"]
    assert "not prove subnet health" in vpc["caveats"][0]
    assert "<REVIEWED_LAMBDA_VPC_JSON>" in vpc["cli"][-1]["code"]
    strict = rows["aws.cb.lambda.policy_no_wildcard_allow"]
    perimeter = rows["aws.cb.lambda.policy_prohibit_public_access_perimeter"]
    assert "even when" in strict["summary"]
    assert "no permission is assumed unused" in strict["caveats"][0]
    assert "absent resource policy is not applicable" in perimeter["caveats"][0]
    for row in (strict, perimeter):
        assert "<REVIEWED_STATEMENT_ID>" in row["cli"][1]["code"]


def test_macie_scope_checks_require_bucket_region_and_discovery_status():
    rows = reviewed()
    session = rows["aws.cb.macie.enabled_where_buckets"]
    discovery = rows["aws.cb.macie.automated_discovery"]
    assert session["field_binding"]["target"] == "scope"
    assert "bucket.LocationConstraint" in session["field_binding"]["path"]
    assert "without buckets is outside" in session["summary"]
    assert any("update-macie-session" in command["code"] for command in session["cli"])
    assert "AutomatedDiscovery.status" in discovery["field_binding"]["path"]
    assert "disabled Macie session is not applicable" in discovery["caveats"][0]


def test_memorydb_settings_require_replacement_not_invalid_update_flags():
    rows = reviewed()
    for cid, field in (("aws.cb.memorydb.auto_minor_version_upgrade", "AutoMinorVersionUpgrade"),
                       ("aws.cb.memorydb.tls_enabled", "TLSEnabled")):
        row = rows[cid]
        assert row["field_binding"]["path"] == field
        assert "absent from UpdateCluster" in row["caveats"][0]
        assert all("update-cluster" not in command["code"] for command in row["cli"])
        assert "<REVIEWED_MEMORYDB_CREATE_JSON>" in row["cli"][1]["code"]


def test_redshift_serverless_namespace_and_workgroup_actions_match_api_fields():
    rows = reviewed()
    logs = rows["aws.cb.redshiftserverless.connection_user_log_exports"]
    admin = rows["aws.cb.redshiftserverless.non_default_admin_username"]
    db = rows["aws.cb.redshiftserverless.non_default_database_name"]
    ssl = rows["aws.cb.redshiftserverless.require_ssl"]
    routing = rows["aws.cb.redshiftserverless.enhanced_vpc_routing"]
    public = rows["aws.cb.redshiftserverless.not_publicly_accessible"]
    assert "preserving any other required exports" in logs["steps"][1]
    assert "--admin-username <REVIEWED_ADMIN_USERNAME>" in admin["cli"][1]["code"]
    assert "absent from UpdateNamespace" in db["caveats"][0]
    assert "<REVIEWED_NAMESPACE_CREATE_JSON>" in db["cli"][1]["code"]
    assert "parameterKey=require_ssl" in ssl["field_binding"]["path"]
    assert "<REVIEWED_WORKGROUP_PARAMS_JSON>" in ssl["cli"][1]["code"]
    assert "--enhanced-vpc-routing" in routing["cli"][1]["code"]
    assert "--no-publicly-accessible" in public["cli"][1]["code"]


def test_inspector2_region_and_coverage_actions_preserve_state_limits():
    rows = reviewed()
    enabled = rows["aws.cb.inspector2.enabled_for_present_resources"]
    active = rows["aws.cb.inspector2.coverage_scan_active"]
    recent = rows["aws.cb.inspector2.coverage_recently_scanned"]
    assert enabled["field_binding"]["target"] == "scope"
    assert "present EC2, ECR, Lambda or Lambda Code" in enabled["summary"]
    assert "<REVIEWED_INSPECTOR_RESOURCE_TYPES_JSON>" in enabled["cli"][1]["code"]
    assert "No universal safe Inspector2 mutation" in active["caveats"][0]
    assert "PENDING_INITIAL_SCAN" in recent["caveats"][0]
    assert "lastScannedAt" in recent["field_binding"]["path"]
    assert "192" in rows["aws.cb.inspector2.findings_within_max_age"]["summary"]
    assert "cisaData" in rows["aws.cb.inspector2.no_known_exploited_findings"]["field_binding"]["path"]
    assert "dateDue" in rows["aws.cb.inspector2.kev_findings_within_due_date"]["field_binding"]["path"]
    for cid in ("aws.cb.inspector2.no_active_findings", "aws.cb.inspector2.findings_within_max_age",
                "aws.cb.inspector2.no_known_exploited_findings", "aws.cb.inspector2.kev_findings_within_due_date"):
        row = rows[cid]
        assert "<REVIEWED_ACTIVE_FINDINGS_FILTER_JSON>" in row["cli"][0]["code"]
        assert "no universal safe" in " ".join(row["caveats"]).lower()


def test_ssm_compliance_remediation_uses_underlying_type_and_empty_semantics():
    rows = reviewed()
    summary = rows["aws.cb.ssm.resource_compliance_summary_compliant"]
    association = rows["aws.cb.ssm.instance_association_compliant"]
    patch = rows["aws.cb.ssm.instance_patch_compliant"]
    assert "regardless of the reported ComplianceType" in summary["summary"]
    assert "Empty Status counts as noncompliant" in association["caveats"][0]
    assert association["source_proof"]["skip_empty"] is False
    assert "only empty Patch statuses" in patch["caveats"][0]
    assert patch["source_proof"]["skip_empty"] is True
    assert all("no universal safe" in " ".join(row["caveats"]).lower() for row in (summary, association, patch))


def test_msk_connect_create_time_fields_require_replacement():
    rows = reviewed()
    for cid, field in (("aws.cb.mskconnect.tls_to_cluster", "kafkaClusterEncryptionInTransit.encryptionType"),
                       ("aws.cb.mskconnect.log_delivery", "logDelivery")):
        row = rows[cid]
        assert row["field_binding"]["path"] == field
        assert "UpdateConnector" in row["steps"][1] or "create-time" in row["caveats"][0]
        assert "<REVIEWED_CONNECTOR_CREATE_JSON>" in row["cli"][1]["code"]
        assert all("update-connector" not in command["code"] for command in row["cli"])


def test_msk_encryption_review_separates_immutable_from_client_updates():
    rows = reviewed()
    cmk = rows["aws.cb.kafka.cmk_encryption_at_rest"]
    both = rows["aws.cb.kafka.tls_client_and_in_cluster"]
    client = rows["aws.cb.msk.client_broker_tls"]
    assert "cannot be changed on an existing cluster" in cmk["caveats"][0]
    assert all("update-security" not in command["code"] for command in cmk["cli"])
    assert "not InCluster" in both["caveats"][0]
    assert any("create-cluster-v2" in command["code"] for command in both["cli"])
    assert all("create-cluster-v2" not in command["code"] for command in client["cli"])
    assert "<REVIEWED_MSK_CONNECTIVITY_JSON>" in rows["aws.cb.kafka.public_access_disabled"]["cli"][1]["code"]
    assert "<REVIEWED_MSK_AUTH_JSON>" in rows["aws.cb.kafka.mutual_tls_authentication"]["cli"][1]["code"]
    assert "UNKNOWN" in rows["aws.cb.kafka.unauthenticated_access_disabled"]["caveats"][0]
    latest = rows["aws.cb.kafka.latest_version"]
    assert "GetCompatibleKafkaVersions" in latest["field_binding"]["path"]
    assert "--current-version <CURRENT_CLUSTER_VERSION>" in latest["cli"][-1]["code"]


def test_neptune_simple_cluster_settings_keep_recovery_and_client_limits():
    rows = reviewed()
    retention = rows["aws.cb.neptune.backup_retention_7_days"]
    tags = rows["aws.cb.neptune.copy_tags_to_snapshot"]
    protection = rows["aws.cb.neptune.deletion_protection"]
    auth = rows["aws.cb.neptune.iam_authentication"]
    assert "at least seven days" in retention["steps"][1]
    assert "does not prove backups completed" in retention["caveats"][0]
    assert "does not retroactively tag existing snapshots" in tags["caveats"][0]
    assert "does not replace backups" in protection["caveats"][0]
    assert "does not migrate clients" in auth["caveats"][0]
    audit = rows["aws.cb.neptune.audit_log_export"]
    assert "neptune_enable_audit_log" in audit["caveats"][0]
    assert "<REVIEWED_NEPTUNE_EXPORTS_JSON>" in audit["cli"][-1]["code"]
    encrypted = rows["aws.cb.neptune.snapshot_encrypted"]
    broad = rows["aws.cb.neptune.snapshot_not_public_prowler"]
    exact = rows["aws.cb.neptune.snapshot_restore_not_all_exact"]
    assert "cannot be switched on" in encrypted["caveats"][0]
    assert "any collected snapshot attribute" in broad["summary"]
    assert "both all and an account ID can pass" in exact["caveats"][0]
    for row in (broad, exact):
        assert "--values-to-remove all" in row["cli"][1]["code"]
    storage = rows["aws.cb.neptune.storage_encrypted"]
    multi = rows["aws.cb.neptune.multi_az"]
    assert "not an existing unencrypted cluster to be converted" in storage["caveats"][0]
    assert "<REVIEWED_NEPTUNE_RESTORE_JSON>" in storage["cli"][-1]["code"]
    assert "different AZ" in multi["steps"][1]
    assert "<REVIEWED_AZ>" in multi["cli"][-1]["code"]
    igw = rows["aws.cb.neptune.no_public_subnet_prowler"]
    assert "igw-" in igw["summary"]
    assert "does not prove" in igw["caveats"][0]
    assert "DBSubnetGroup is absent from ModifyDBCluster" in igw["caveats"][0]
    igw_sibling = rows["aws.cb.neptune.no_public_subnet_steampipe"]
    assert "igw-" in igw_sibling["summary"]
    assert "outbound NAT" in igw_sibling["caveats"][0]
    assert "<REVIEWED_NEPTUNE_RESTORE_JSON>" in igw_sibling["cli"][-1]["code"]


def test_lightsail_snapshot_database_and_static_ip_require_owner_review():
    rows = reviewed()
    snapshot = rows["aws.cb.lightsail.instance_auto_snapshot"]
    database = rows["aws.cb.lightsail.database_not_public"]
    static = rows["aws.cb.lightsail.static_ip_attached"]
    assert "completed snapshot" in snapshot["steps"][2]
    assert "--no-publicly-accessible" in database["cli"][1]["code"]
    assert "not prove an unattached IP is unnecessary" in static["caveats"][0]
    assert all("release-static-ip" not in command["code"] for command in static["cli"])
    broad = rows["aws.cb.lightsail.instance_not_public"]
    ssh = rows["aws.cb.lightsail.ssh_restricted"]
    rdp = rows["aws.cb.lightsail.rdp_restricted"]
    assert "even one limited to a narrow CIDR" in broad["caveats"][0]
    assert ssh["source_proof"]["tcp_port"] == 22
    assert rdp["source_proof"]["tcp_port"] == 3389
    assert "IPv6 ::/0" in ssh["caveats"][0]
    assert all("<REVIEWED_FULL_LIGHTSAIL_PORTS_JSON>" in row["cli"][1]["code"] for row in (broad, ssh, rdp))
    combined = rows["aws.cb.lightsail.ssh_rdp_http_world_closed"]
    ipv6 = rows["aws.cb.lightsail.instance_ipv6_disabled"]
    assert "HTTP may be intentionally public" in combined["caveats"][0]
    assert "<REVIEWED_FULL_LIGHTSAIL_PORTS_JSON>" in combined["cli"][-1]["code"]
    assert "no DisableInstanceIpv6 operation" in ipv6["caveats"][0]
    assert len(ipv6["cli"]) == 1


IAM_EVIDENCE_ONLY_SUCCESSOR = [('        matched = set()\n'
  '        def count_and_describe(rows):\n'
  '            hits = count_rows(rows, matcher, resource_ok)\n'
  '            if hits:\n'
  '                for statement in rows:\n'
  '                    if statement["Effect"] == "Allow" and any(resource_ok(r) for r in '
  'statement.get("Resource", [])):\n'
  '                        matched.update(a for a in statement.get("Action", []) if matcher(a))\n'
  '            return hits\n'
  '        return result_rows(_identity_policy_hits(item, count_and_describe), '
  'matching_actions=sorted(matched))\n',
  '        return result_rows(_identity_policy_hits(item, lambda rows: count_rows(rows, matcher, '
  'resource_ok)))\n'),
 ('        attached = arn in role_attached_arns(index)\n'
  '        return result(not attached, policy_arn=arn, role_attachment_found=attached)\n',
  '        return result(arn not in role_attached_arns(index), policy_arn=arn)\n'),
 ('        attached = arn in in_use_arns(index)\n'
  '        return result(not attached, policy_arn=arn, attached_to_active_identity=attached)\n',
  '        return result(arn not in in_use_arns(index), policy_arn=arn)\n'),
 ('    return result(bool(other) and bool(keys), access_keys=len(keys), other_services=len(other), '
  'non_iam_sts_services=other)\n',
  '    return result(bool(other) and bool(keys), access_keys=len(keys), other_services=len(other))\n')]
