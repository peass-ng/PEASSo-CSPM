"""Guard the evaluator-reviewed native AWS remediation shard."""

import json
import hashlib
from collections import Counter
from pathlib import Path
import re
import shlex

from botocore import xform_name
import botocore.session

from peaso.checks import CHECKS
from peaso.checks.claude2_aws_b_common import DOCS as C2B_DOCS
from peaso.remediation import template
from scripts.peaso_compliance_compile import spec_digest
from scripts.peaso_compliance_merge_new import signed_proposals
from tests.release_successor_history import historical_bytes


ROOT = Path(__file__).resolve().parents[1]
SHARD = ROOT / "peaso/rulepacks/remediation_aws_reviewed.json"
CENTRAL = ROOT / "peaso/rulepacks/remediation_details.json"
CURATED = ROOT / "peaso/rulepacks/remediation_curated.json"


def reviewed():
    return json.loads(SHARD.read_text())



def shard_before_reference_titles(path="peaso/rulepacks/remediation_aws_reviewed.json",
                                   rows_count=271, ensure_ascii=True):
    """Exact shard bytes before the reviewed documentation-label overlay (98b81b17).

    Each shard keeps its own encoding: ASCII-escaped for the central shard and
    literal UTF-8 for the family shard.
    """
    raw = (ROOT / path).read_bytes()
    data = json.loads(raw)
    assert (json.dumps(data, indent=2, ensure_ascii=ensure_ascii) + "\n").encode() == raw
    overlay = json.loads((ROOT / "tests/fixtures/remediation_reference_title_overlay.json").read_text())
    assert overlay["schema_version"] == 1
    rows = overlay["sources"][path]
    assert len(rows) == rows_count
    for row in rows:
        reference = data[row["id"]]["references"][row["index"]]
        assert reference == {"title": row["new_title"], "url": row["url"]}, row
        reference["title"] = row["old_title"]
    return (json.dumps(data, indent=2, ensure_ascii=ensure_ascii) + "\n").encode()











def test_each_review_has_specific_setting_steps_primary_reference_and_inspection():
    entries = reviewed()
    repetitions = Counter(entry["summary"] for entry in entries.values())
    assert max(repetitions.values()) == 1
    for check_id, entry in entries.items():
        assert check_id not in entry["summary"]
        assert 1 <= len(entry["steps"]) <= 5
        assert all(step.strip() and len(step) > 30 for step in entry["steps"])
        assert not any(step.startswith("Review the declared setting and configure it") for step in entry["steps"])
        assert entry["references"]
        assert all(row["url"].startswith("https://docs.aws.amazon.com/") for row in entry["references"])
        assert entry["cli"] and entry["cli"][0]["code"].startswith("aws ")
        assert entry["caveats"]
        if "iac" in entry:
            assert entry["iac"]["code"]
        for command in entry["cli"]:
            assert command["shell"] == "bash"
            assert not re.search(r"\$\(|`|\b--profile\b", command["code"])
            placeholders = set(re.findall(r"<([A-Z][A-Z0-9_]*)>", command["code"]))
            safe_identity = {"RESOURCE_ID", "RESOURCE_ARN", "RESOURCE_NAME", "REGION", "ACCOUNT_ID"}
            manual_inputs = {
                "RESOURCE_ID", "RESOURCE_ARN", "RESOURCE_NAME", "BUCKET_NAME", "REPOSITORY_NAME",
                "REGION", "APPROVED_RETENTION_DAYS", "REPLACEMENT_POLICY_FILE",
                "DETECTOR_ID", "QUEUE_URL",
                "KMS_KEY_ARN",
                "TRAIL_BUCKET_NAME", "DEFAULT_VERSION_ID",
                "LOG_GROUP_NAME", "WINDOW_START", "WINDOW_END",
                "KEY_ARN", "VERSION_NUMBER",
                "CLUSTER_ARN", "APPLICATION_NAME", "SERVICE_NAME", "EC2_INSTANCE_ID", "VOLUME_ID",
                "TRAIL_NAME", "LISTENER_ARN", "WEB_ACL_ARN", "ACM_CERT_ARN", "REST_API_ID", "ROUTE_ID",
                "API_NAME", "CURRENT_AUTH_TYPE", "CLIENT_ID", "USER_NAME", "SHARED_ACCOUNT_ID",
                "SNS_TOPIC_NAME", "DOMAIN_NAME", "PACKAGE_FORMAT", "PACKAGE_NAME", "CREDENTIAL_ID",
                "DATA_SOURCE_ID", "IMAGE_DIGEST", "PARAMETER_GROUP_NAME", "SECURITY_CONFIGURATION_NAME",
                "SUBNET_GROUP_NAME", "VAULT_NAME", "SUBNET_ID", "PRIMARY_INSTANCE_ID", "SECURITY_GROUP_ID",
                "ORIGIN_BUCKET_NAME", "BACKUP_PLAN_ID", "LOG_GROUP_ARN", "STATEMENT_ID", "CURRENT_ETAG",
                "APPROVED_ACCOUNT_ID", "APPROVED_LAYER_ARNS", "APPROVED_RUNTIME", "APPROVED_SUBNET_IDS",
                "APPROVED_K8S_VERSION", "METHOD_RESOURCE_ID", "HTTP_METHOD", "APPROVED_AUTH_TYPE",
                "AUTHORIZER_ID", "APPROVED_INSTANCE_ID", "LISTENER_PORT", "NEW_SNAPSHOT_ID", "WEB_ACL_ID",
                "REVIEWED_SECURITY_GROUP_IDS",
                "AFFECTED_GROUP_ID", "REVIEWED_WORLD_OPEN_RULE_ID", "REVIEWED_EGRESS_PERMISSIONS_JSON",
                "REVIEWED_CLIENT_TOKEN",
                "REVIEWED_CACHE_TYPE", "REVIEWED_CACHING_BEHAVIOR", "REVIEWED_TTL_SECONDS",
                "APPROVED_UID", "APPROVED_GID", "REVIEWED_ROOT_DIRECTORY_JSON",
                "APPROVED_SECOND_AZ_SUBNET_ID",
                "FILE_SYSTEM_ID", "REVIEWED_ACCESS_POINT_JSON",
                "REVIEWED_DAX_CLUSTER_JSON", "REVIEWED_NODE_COUNT", "REVIEWED_AZ_LIST",
                "REVIEWED_SNAPSHOT_ID", "REVIEWED_DS_CERTIFICATE_JSON", "REVIEWED_OLD_CERT_ID",
                "AFFECTED_SUBNET_ID", "REVIEWED_VPC_ID", "REVIEWED_DMS_CERTIFICATE_JSON",
                "REVIEWED_ENDPOINT_ARN", "NEW_CERTIFICATE_ARN", "NEW_REPLICA_IDENTIFIER",
                "REVIEWED_INSTANCE_CLASS", "REVIEWED_SECOND_AZ", "SOURCE_CLUSTER_ID",
                "REVIEWED_DOCDB_RESTORE_JSON", "REVIEWED_DOCDB_INSTANCE_JSON",
                "REVIEWED_HTTPS_LISTENERS_JSON", "REVIEWED_OLD_LISTENER_PORTS",
                "REVIEWED_BEDROCK_DATA_SOURCE_JSON", "REVIEWED_LOG_BUCKET_NAME",
                "REVIEWED_LOG_GROUP_NAME", "REVIEWED_BUCKET_ENCRYPTION_JSON",
                "REVIEWED_KMS_KEY_ARN",
                "CONTAINER_INSTANCE_ARN", "REVIEWED_SNAPSHOT_DESCRIPTION",
                "REVIEWED_AVAILABILITY_ZONE", "REVIEWED_ECS_TASK_SET_JSON",
                "REVIEWED_SECURITY_GROUP_ID",
                "REVIEWED_AUTH_UPDATE_JSON",
                "FMS_POLICY_ID", "MEMBER_ACCOUNT_ID",
                "REVIEWED_OS_VPC_DOMAIN_JSON", "REVIEWED_OS_SECURITY_JSON",
                "NEW_SECURITY_CONFIGURATION_NAME", "REVIEWED_EMR_SECURITY_CONFIGURATION_JSON",
                "REVIEWED_EMR_CLUSTER_JSON",
                "REVIEWED_ELBV2_LISTENER_JSON", "REVIEWED_INTERNAL_ELBV2_JSON",
                "REVIEWED_ELASTICACHE_REPLACEMENT_JSON",
                "REVIEWED_BEDROCK_CUSTOMIZATION_JSON", "REVIEWED_BEDROCK_IMPORT_JSON",
                "STOPPED_SOURCE_SERVER_ID",
                    "REVIEWED_EC2_SERVICE_ARN",
            }
            assert placeholders <= safe_identity | manual_inputs | {
                "REVIEWED_" + suffix for suffix in (
                    "CORS_JSON", "TASK_DEFINITION_JSON", "SERVICE_UPDATE_JSON", "ENCRYPTION_JSON", "ADDON_JSON",
                    "DISTRIBUTION_JSON", "STAGE_PATCH_JSON", "API_PATCH_JSON", "LOG_CONFIG_JSON",
                    "WORKGROUP_JSON", "BACKUP_PLAN_JSON", "POLICY_FILE", "MONGODB_SETTINGS_JSON",
                    "NEPTUNE_SETTINGS_JSON", "REDIS_SETTINGS_JSON", "TASK_SETTINGS_JSON", "PARAMETERS_JSON",
                    "MIXED_INSTANCES_JSON", "LAUNCH_TEMPLATE_JSON", "TAGS_JSON", "BLOCK_PUBLIC_ACCESS_JSON",
                    "LOG_PUBLISHING_JSON", "GUARDRAIL_JSON", "AGENT_JSON", "PROMPT_JSON", "LOGGING_JSON",
                    "CLIENT_JSON", "RADIUS_JSON", "ENVIRONMENT_JSON", "EXPORT_JSON", "LOGS_JSON",
                    "WEBHOOK_FILTERS_JSON", "SCANNING_RULES_JSON",
                    "METHOD_PATCH_JSON", "AUTHORIZER_JSON", "GRAPHQL_API_JSON", "REPORT_PLAN_JSON",
                    "ENDPOINT_JSON", "STACK_UPDATE_JSON", "SOURCE_JSON", "LIFECYCLE_POLICY_JSON",
                    "ACTIONS_JSON", "LISTENER_JSON", "EVENT_SELECTORS_JSON", "SELECTION_JSON",
                )
            }, (check_id, placeholders)


def test_immutability_and_source_scope_are_preserved():
    entries = reviewed()
    assert "replacement" in " ".join(entries["aws.rds.encryption"]["steps"]).lower()
    assert "replacement" in " ".join(entries["aws.ebs.encryption"]["steps"]).lower()
    assert "account-level" in " ".join(entries["aws.s3.public_access_block"]["steps"])
    assert "S3 encrypts new objects by default" in " ".join(entries["aws.s3.default_encryption"]["caveats"])
    assert "manual" in " ".join(entries["aws.s3.no_public_acl"]["caveats"]).lower()
    assert "version" in " ".join(entries["aws.eks.secrets_encryption"]["steps"]).lower()
    assert "zero" in " ".join(entries["aws.b.lambda.reserved_concurrency"]["caveats"]).lower()
    assert "DynamoDB-owned default encryption" in " ".join(entries["aws.b.dynamodb.kms_description"]["caveats"])
    assert "UNKNOWN" in " ".join(entries["aws.b.ecs.declared_nonroot_users"]["caveats"])
    assert "MANUAL" in " ".join(entries["aws.b.acm.pending_validation_review"]["caveats"])
    assert "not proof" in " ".join(entries["aws.b.rds_instance.nondefault_admin"]["caveats"])
    assert "does not prove physical possession" in " ".join(entries["aws.a.iam.root_hardware_mfa"]["caveats"])
    assert "UNKNOWN" in " ".join(template("aws.a.cloudtrail.bucket_mfa_delete")["caveats"])
    assert "not proof of effective public access" in " ".join(entries["aws.a.cloudtrail.joined_bucket_declared_public_grants"]["caveats"])
    assert "never collected" in " ".join(entries["aws.htbp.lambda.env_var_names_not_credentials"]["caveats"])
    assert "MANUAL" in " ".join(entries["aws.htbp.ecr.registry_policy_trust_boundary"]["caveats"])
    assert "not proof of malicious intent" in " ".join(entries["aws.claude2_a.cloudtrail.threat_detection_enumeration"]["caveats"])
    assert "confirmed SNS subscription" in entries["aws.gap.cloudwatch.cis_alarm.root_account_usage"]["summary"]
    assert "not a proof of effective public write" in " ".join(entries["aws.gap.s3.no_public_write_acl_or_policy"]["caveats"])
    assert "does not establish a concrete attack path" in " ".join(entries["aws.gap.ec2.instance_no_iam_role_with_management_level_access"]["caveats"])
    assert entries["aws.gap.ec2.instance_no_iam_passrole_and_lambda_invoke_function_access"]["field_binding"]["predicate"].startswith("all_of:")
    assert "--cluster <CLUSTER_ARN>" in entries["aws.c2b.ecs.service_no_public_ip"]["cli"][0]["code"]
    assert "--application-name <APPLICATION_NAME>" in entries["aws.c2b.codedeploy.lambda_not_all_at_once"]["cli"][0]["code"]
    assert "get-function-configuration" in entries["aws.c2b.lambda.env_vars_cmk"]["cli"][0]["code"]
    assert "Environment.Variables" not in entries["aws.c2b.lambda.env_vars_cmk"]["cli"][0]["code"]
    assert "MANUAL" in " ".join(entries["aws.c2b.directoryservice.shared_accounts_review"]["caveats"])


def test_c2b_command_scope_and_actionable_families():
    entries = reviewed()
    global_endpoints = {"iam", "cloudfront", "s3api"}
    for check_id, entry in entries.items():
        if not check_id.startswith("aws.c2b."):
            continue
        assert "Prowler:" not in entry["summary"] and "Steampipe:" not in entry["summary"]
        assert "Apply through the existing Terraform/CloudFormation" not in entry.get("iac", {}).get("code", "")
        for command in entry["cli"]:
            words = shlex.split(command["code"])
            if words[1] not in global_endpoints:
                assert "--region" in words, (check_id, command["code"])
    assert "--cluster <CLUSTER_ARN>" in entries["aws.c2b.ecs.service_no_public_ip"]["cli"][0]["code"]
    assert "--application-name <APPLICATION_NAME>" in entries["aws.c2b.codedeploy.lambda_not_all_at_once"]["cli"][0]["code"]
    assert any("update-project-visibility" in c["code"] for c in entries["aws.c2b.codebuild.project_private"]["cli"])
    assert any("update-fleet" in c["code"] for c in entries["aws.c2b.appstream.no_default_internet"]["cli"])
    assert any("update-work-group" in c["code"] for c in entries["aws.c2b.athena.enforce_configuration"]["cli"])
    assert any("get-function-configuration" in c["code"] for c in entries["aws.c2b.lambda.env_vars_cmk"]["cli"])
    assert all("--region" not in c["code"] for c in entries["aws.c2b.cloudfront.custom_ssl_certificate"]["cli"])


def test_inspection_cli_names_and_required_flags_exist_in_aws_api_model():
    session = botocore.session.get_session()
    aliases = {"s3api": "s3", "configservice": "config"}
    for check_id, entry in reviewed().items():
        for command in entry["cli"]:
            words = shlex.split(command["code"])
            model = session.get_service_model(aliases.get(words[1], words[1]))
            operation = next((name for name in model.operation_names if xform_name(name, "-") == words[2]), None)
            if words[1:3] == ["emr", "create-cluster"]:
                # The AWS CLI exposes RunJobFlow as the high-level create-cluster command.
                operation = "RunJobFlow"
            assert operation, (check_id, command["code"])
            shape = model.operation_model(operation).input_shape
            if check_id.startswith("aws.c2b."):
                allowed = {"--cli-input-json", "--query", "--region", "--output", "--page-size"}
                for member, member_shape in (shape.members if shape else {}).items():
                    flag = "--" + xform_name(member, "-")
                    allowed.add(flag)
                    if member_shape.type_name == "boolean":
                        allowed.add("--no-" + xform_name(member, "-"))
                    if words[1:3] == ["ec2", "modify-subnet-attribute"] and member == "MapPublicIpOnLaunch":
                        # CLI renders this structure-valued EC2 switch as a boolean pair.
                        allowed.add("--no-map-public-ip-on-launch")
                assert {word for word in words[3:] if word.startswith("--")} <= allowed, (check_id, command["code"])
            if "--cli-input-json" in words:
                continue  # The complete owner-reviewed request supplies required API members.
            for member in (shape.required_members if shape else []):
                # AWS CLI's paginated list-user-pools supplies MaxResults through
                # --page-size rather than exposing the API member as a CLI flag.
                if words[1:3] == ["cognito-idp", "list-user-pools"] and member == "MaxResults":
                    continue
                assert "--" + xform_name(member, "-") in words, (check_id, member)


def test_customer_summaries_do_not_expose_evaluator_provenance():
    entries = reviewed()
    for check_id, entry in entries.items():
        assert not re.search(r"(?i)\b(evaluator|Prowler|Steampipe|upstream)\b", entry["summary"]), check_id
    assert "active state" in entries["aws.a.accessanalyzer.region_active"]["summary"]
    assert "BLOCK" in entries["aws.c2b.codeartifact.internal_packages_block_upstream"]["summary"]
    assert "source_note" in entries["aws.a.accessanalyzer.region_active"]["field_binding"]


def test_acm_expiry_review_branches_on_certificate_type_and_eligibility():
    entry = reviewed()["aws.c2b.acm.in_use_not_expiring_7_days"]
    text = " ".join(entry["steps"])
    assert all(token in text for token in (
        "Type", "Status", "NotAfter", "InUseBy", "RenewalEligibility",
        "Amazon-issued public", "ACM-issued private", "IMPORTED",
        "Reimport certificate", "more than seven days",
    ))
    assert "private key" in text and "private key" not in " ".join(command["code"] for command in entry["cli"])
    assert "previously exported" in entry["cli"][1]["label"]
    assert "renew-certificate" in entry["cli"][1]["code"]
    assert "an IaC declaration alone does not rotate it" in entry["iac"]["code"]
    assert "NOT_APPLICABLE" in " ".join(entry["caveats"])
    assert "UNKNOWN" in " ".join(entry["caveats"])
    assert any("import-reimport.html" in ref["url"] for ref in entry["references"])


def test_ecs_review_respects_fargate_fact_and_controller_specific_replacement():
    entries = reviewed()
    registered = entries["aws.c2b.ecs.cluster_has_registered_instances"]
    assert registered["review_status"] == "approved"
    assert "desiredCount>0 launchType=EC2" in registered["field_binding"]["path"]
    assert "Fargate-only NOT_APPLICABLE" in registered["field_binding"]["path"]
    assert "unresolved UNKNOWN" in registered["field_binding"]["path"]
    assert "Fargate-only" in " ".join(registered["caveats"])
    assert "does not prove agent connectivity" in " ".join(registered["caveats"])
    in_vpc = entries["aws.c2b.ecs.container_instance_in_vpc"]
    assert in_vpc["review_status"] == "approved"
    assert "no FAIL branch" in in_vpc["field_binding"]["path"]
    assert "mi-* NOT_APPLICABLE" in in_vpc["field_binding"]["path"]
    assert "missing/denied/null/malformed UNKNOWN" in in_vpc["field_binding"]["path"]
    assert "retired" in " ".join(in_vpc["caveats"])
    encrypted = entries["aws.c2b.ecs.cluster_instance_volumes_encrypted"]
    assert "existing volumes" in " ".join(encrypted["steps"])
    assert any("create-volume" in command["code"] and "--encrypted" in command["code"]
               for command in encrypted["cli"])
    task_set = entries["aws.c2b.ecs.task_set_no_public_ip"]
    assert "EXTERNAL" in " ".join(task_set["steps"])
    assert "CODE_DEPLOY" in " ".join(task_set["steps"])
    assert "UpdateTaskSet only changes scale" in " ".join(task_set["steps"])
    assert any("create-task-set" in command["code"] for command in task_set["cli"])


def test_eks_additional_security_group_count_uses_supported_cluster_update():
    entry = reviewed()["aws.c2b.eks.single_security_group"]
    assert "additional" in entry["summary"]
    assert "clusterSecurityGroupId is separate" in " ".join(entry["caveats"])
    assert any("update-cluster-config" in command["code"] and
               "securityGroupIds=<REVIEWED_SECURITY_GROUP_ID>" in command["code"]
               for command in entry["cli"])
    assert "asynchronous" in " ".join(entry["steps"])


def test_pre6_redis_auth_is_staged_only_for_eligible_tls_group_without_token_leak():
    entry = reviewed()["aws.c2b.elasticache.redis_auth_pre6"]
    steps = " ".join(entry["steps"])
    assert all(term in steps for term in ("5.0.6", "TLS", "ROTATE", "SET", "client", "NOT_APPLICABLE"))
    commands = " ".join(command["code"] for command in entry["cli"])
    assert "modify-replication-group --cli-input-json file://<REVIEWED_AUTH_UPDATE_JSON>" in commands
    assert "--auth-token" not in commands
    assert "secret" in " ".join(entry["caveats"]).lower()


def test_ecr_latest_image_guidance_uses_corrected_complete_exact_digest_facts():
    entry = reviewed()["aws.c2b.ecr.latest_image_no_medium_plus_findings"]
    steps = " ".join(entry["steps"])
    assert all(term in steps for term in ("imageDigest", "DescribeImageScanFindings", "COMPLETE",
                                          "aggregate count map", "completion time", "UNKNOWN"))
    assert "ScanFindings" in entry["field_binding"]["path"]
    assert "scan_completed_at" in entry["field_binding"]["observed_fail_evidence"]
    assert "clean result cannot be inferred from DescribeImages alone" in " ".join(entry["caveats"])


def test_eks_cluster_security_group_guidance_matches_presence_and_platform_states():
    entry = reviewed()["aws.c2b.eks.cluster_security_group_present"]
    assert entry["review_status"] == "approved"
    steps = " ".join(entry["steps"])
    caveats = " ".join(entry["caveats"])
    assert "clusterSecurityGroupId" in steps
    assert "Kubernetes NetworkPolicy" in steps
    assert "UNKNOWN" in steps and "NOT_APPLICABLE" in steps
    assert "1.14-eks.3" in caveats
    assert "automatically" in caveats and "replacement" in caveats


def test_msk_version_guidance_uses_cluster_specific_targets_and_current_token():
    family = json.loads((ROOT / "peaso/rulepacks/remediation_aws_families_reviewed.json").read_text())
    entry = family["aws.cb.kafka.latest_version"]
    from tests.reviewed_guidance_presentation import assert_approved_presentation
    current=assert_approved_presentation("aws.cb.kafka.latest_version",entry)
    assert "fresh DescribeClusterV2 Version" in " ".join(current["caveats"])
    assert "compatible target returned for this cluster" in " ".join(current["caveats"])
    assert entry["review_status"] == "approved"
    binding = entry["field_binding"]
    assert binding["kind"] == "msk_cluster" and binding["target"] == "resource"
    assert "ClusterArn GetCompatibleKafkaVersions SourceVersion/TargetVersions" in binding["path"]
    assert "ListKafkaVersions Status" in binding["path"]
    steps = " ".join(entry["steps"])
    caveats = " ".join(entry["caveats"])
    assert "deprecated current version fails independently" in steps
    assert "newer ACTIVE target returned for this cluster" in steps
    assert "no valid compatible target" in steps and "fabricating an upgrade path" in steps
    assert "UNKNOWN" in steps and "client compatibility" in steps
    assert "not the Apache Kafka version string" in caveats
    assert "--cluster-arn <RESOURCE_ARN>" in entry["cli"][2]["code"]
    assert "--current-version <CURRENT_CLUSTER_VERSION>" in entry["cli"][3]["code"]
    assert "--target-kafka-version <REVIEWED_COMPATIBLE_ACTIVE_KAFKA_VERSION>" in entry["cli"][3]["code"]


def test_rds_audit_and_tls_guidance_uses_engine_specific_parameter_values():
    family = json.loads((ROOT / "peaso/rulepacks/remediation_aws_families_reviewed.json").read_text())
    audit = family["aws.cb.rds.aurora_mysql_server_audit_logging"]
    instance = family["aws.cb.rds.instance_tls_parameters"]
    maria = family["aws.cb.rds.mariadb_require_secure_transport"]
    for check_id, entry in (("aws.cb.rds.aurora_mysql_server_audit_logging", audit),
                            ("aws.cb.rds.instance_tls_parameters", instance),
                            ("aws.cb.rds.mariadb_require_secure_transport", maria)):
        assert entry["review_status"] == "approved"
        from tests.reviewed_guidance_presentation import assert_approved_presentation
        assert_approved_presentation(check_id,entry)
        assert entry["source_proof"]["evaluator"].startswith("peaso/checks/claude_aws_b_db.py:")
        assert "UNKNOWN" in " ".join(entry["steps"] + entry["caveats"])
        assert "--cli-input-json file://<REVIEWED_RDS_" in entry["cli"][-1]["code"]
    assert "server_audit_logging ON/1" in audit["field_binding"]["path"]
    assert "server_audit_events" in audit["field_binding"]["path"]
    assert "QUERY_DCL" in " ".join(audit["steps"])
    assert "no spaces" in " ".join(audit["steps"])
    assert "not log generation" in " ".join(audit["caveats"])
    assert "DBClusterIdentifier absent" in instance["field_binding"]["path"]
    assert "rds.force_ssl=1 OR require_secure_transport ON/1 by engine" in instance["field_binding"]["path"]
    assert "universal reboot" in " ".join(instance["caveats"])
    assert "EngineVersion>=10.5" in maria["field_binding"]["path"]
    assert "require_secure_transport ON/1" in maria["field_binding"]["path"]
    assert "no instance reboot for this parameter update" in " ".join(maria["steps"])


def test_rds_instance_iam_auth_guidance_requires_exact_supported_standalone_option():
    family = json.loads((ROOT / "peaso/rulepacks/remediation_aws_families_reviewed.json").read_text())
    check_id = "aws.cb.rds.instance_iam_auth_all_engines"
    entry = family[check_id]
    from tests.reviewed_guidance_presentation import assert_approved_presentation
    current=assert_approved_presentation(check_id,entry)
    assert "conflicting" in " ".join(current["caveats"])
    assert "maintenance window" in " ".join(current["caveats"])
    assert entry["review_status"] == "approved"
    assert entry["source_proof"]["evaluator"] == "peaso/checks/claude_aws_b_db.py:515"
    path = entry["field_binding"]["path"]
    for field in ("DBClusterIdentifier", "SubnetOutpost.Arn", "EngineVersion", "DBInstanceClass",
                  "SupportsIAMDatabaseAuthentication=true"):
        assert field in path
    steps = " ".join(entry["steps"])
    caveats = " ".join(entry["caveats"])
    assert "UNKNOWN" in steps and "UNKNOWN" in caveats
    assert "maintenance window" in steps
    assert "observed true flag can pass" in caveats
    assert "RDS on Outposts" in caveats
    assert all("--apply-immediately" not in command["code"] for command in entry["cli"])
    assert any("describe-orderable-db-instance-options" in command["code"] for command in entry["cli"])
    assert any("--enable-iam-database-authentication" in command["code"] for command in entry["cli"])


def test_fms_scope_guidance_separates_missing_evaluation_from_violation():
    entry = reviewed()["aws.c2b.fms.policies_compliant"]
    assert entry["field_binding"]["target"] == "scope"
    assert "EvaluationResults[]" in entry["field_binding"]["path"]
    assert "every returned policy/member" in entry["field_binding"]["path"]
    assert "incomplete_evaluations[] may coexist" in entry["field_binding"]["observed_fail_evidence"]
    assert "does not prove that every organization account was returned" in " ".join(entry["caveats"])
    assert "Do not enable automatic FMS remediation" in " ".join(entry["steps"])
    assert any("get-compliance-detail" in command["code"] and
               "--member-account <MEMBER_ACCOUNT_ID>" in command["code"]
               for command in entry["cli"])


def test_opensearch_vpc_replacement_and_internal_user_policy_conflict():
    entries = reviewed()
    vpc = entries["aws.c2b.es.in_vpc"]
    assert "separate VPC-access domain" in " ".join(vpc["steps"])
    assert "cannot change in place" in " ".join(vpc["caveats"])
    assert any("create-domain --cli-input-json file://<REVIEWED_OS_VPC_DOMAIN_JSON>" in command["code"]
               for command in vpc["cli"])
    internal = entries["aws.c2b.es.internal_user_database_enabled"]
    assert "opposite" in " ".join(internal["steps"])
    assert "secret" in " ".join(internal["caveats"]).lower()
    assert all("MasterUserPassword" not in command["code"] for command in internal["cli"])


def test_emr_public_ingress_removes_only_verified_rule_on_joined_group():
    entry = reviewed()["aws.c2b.emr.cluster_not_publicly_accessible"]
    commands = " ".join(command["code"] for command in entry["cli"])
    assert "describe-security-group-rules" in commands
    assert "revoke-security-group-ingress --group-id <AFFECTED_GROUP_ID>" in commands
    assert "--security-group-rule-ids <REVIEWED_WORLD_OPEN_RULE_ID>" in commands
    assert "full 0-65535" in " ".join(entry["steps"])
    assert "shared" in " ".join(entry["caveats"])


def test_emr_encryption_configurations_require_new_named_config_and_cluster_cutover():
    entries = reviewed()
    cluster_ids = (
        "cluster_at_rest_encryption", "cluster_in_transit_encryption",
        "cluster_at_rest_cse_custom", "cluster_at_rest_sse_kms",
        "cluster_local_disk_cmk", "cluster_local_disk_encryption",
    )
    for suffix in cluster_ids:
        entry = entries["aws.c2b.emr." + suffix]
        assert "Cluster.Cluster.SecurityConfiguration -> joined" in entry["field_binding"]["path"]
        assert "new security configuration" in " ".join(entry["steps"])
        assert "replacement EMR capacity" in " ".join(entry["steps"])
        assert any("create-security-configuration" in command["code"] for command in entry["cli"])
    assert "mutually exclusive" in " ".join(entries["aws.c2b.emr.cluster_at_rest_cse_custom"]["caveats"])
    assert "AwsKms does not satisfy" in " ".join(entries["aws.c2b.emr.cluster_local_disk_cmk"]["steps"])
    for suffix in ("security_configuration_at_rest", "security_configuration_in_transit"):
        entry = entries["aws.c2b.emr." + suffix]
        assert "Configuration.SecurityConfiguration.EncryptionConfiguration." in entry["field_binding"]["path"]
        assert "old configuration" in " ".join(entry["steps"])


def test_emr_launch_time_guidance_does_not_claim_subnet_flag_fixes_current_node():
    entries = reviewed()
    kerberos = entries["aws.c2b.emr.cluster_kerberos_enabled"]
    assert "KerberosAttributes" in " ".join(kerberos["steps"])
    assert "passwords" in " ".join(kerberos["caveats"])
    assert all("KdcAdminPassword" not in command["code"] for command in kerberos["cli"])
    attached = entries["aws.c2b.emr.cluster_security_configuration"]
    assert "does not validate encryption" in " ".join(attached["caveats"])
    public_dns = entries["aws.c2b.emr.master_no_public_dns"]
    assert "DNS suffix alone" in " ".join(public_dns["steps"])
    subnet = entries["aws.c2b.emr.master_subnet_no_auto_public_ip"]
    assert "affects future launches only" in " ".join(subnet["steps"])
    assert any("modify-subnet-attribute --subnet-id <AFFECTED_SUBNET_ID>" in command["code"] and
               "--no-map-public-ip-on-launch" in command["code"] for command in subnet["cli"])
    assert "future-launch subnet setting" in " ".join(subnet["caveats"])


def test_backup_vault_key_guidance_matches_observed_metadata_only():
    entry = reviewed()["aws.c2b.backup.vault_encrypted"]
    assert entry["review_status"] == "approved"
    assert "ListBackupVaults" in entry["field_binding"]["path"]
    assert "DescribeBackupVault" in entry["field_binding"]["path"]
    assert "no supported unencrypted-vault FAIL branch" in " ".join(entry["caveats"])
    assert "each recovery point IsEncrypted" in " ".join(entry["steps"])
    assert all("create-backup-vault" not in command["code"] for command in entry["cli"])


def test_elbv2_ingress_listener_and_scheme_repairs_track_distinct_predicates():
    entries = reviewed()
    ingress = entries["aws.c2b.elbv2.internet_facing_open_sg"]
    assert "Scheme=internet-facing" in ingress["field_binding"]["path"]
    assert "full TCP 0-65535" in " ".join(ingress["steps"])
    assert "HTTPS/443 open to the world is not itself a failure" in " ".join(ingress["steps"])
    assert any("revoke-security-group-ingress" in c["code"] and
               "<REVIEWED_WORLD_OPEN_RULE_ID>" in c["code"] for c in ingress["cli"])
    listeners = entries["aws.c2b.elbv2.listeners_secure_protocol"]
    assert "HTTP-to-HTTPS redirect" in " ".join(listeners["steps"])
    assert "TCP pass-through" in " ".join(listeners["steps"])
    assert any("modify-listener --cli-input-json" in c["code"] for c in listeners["cli"])
    scheme = entries["aws.c2b.elbv2.not_internet_facing"]
    assert "scheme-only" in " ".join(scheme["caveats"])
    assert "replacement" in " ".join(scheme["caveats"])
    assert any("create-load-balancer --cli-input-json" in c["code"] for c in scheme["cli"])


def test_elasticache_key_guidance_separates_disabled_key_and_immutable_group():
    entry = reviewed()["aws.c2b.elasticache.cmk_enabled"]
    assert "AtRestEncryptionEnabled" in entry["field_binding"]["path"]
    assert "KeyManager" in " ".join(entry["caveats"])
    assert "StorageEncryptionType" in " ".join(entry["steps"])
    assert any("kms enable-key" in command["code"] for command in entry["cli"])
    assert any("elasticache create-replication-group --cli-input-json" in command["code"]
               for command in entry["cli"])


def test_bedrock_custom_model_key_guidance_branches_on_model_origin():
    entry = reviewed()["aws.c2b.bedrock.custom_model_cmk"]
    assert entry["field_binding"]["path"] == "Model.modelKmsKeyArn (GetCustomModel detail)"
    assert "customizationType" in " ".join(entry["steps"])
    assert "customModelKmsKeyId" in " ".join(entry["steps"])
    assert "modelKmsKeyArn" in " ".join(entry["steps"])
    assert any("create-model-customization-job --cli-input-json" in c["code"] for c in entry["cli"])
    assert any("create-custom-model --cli-input-json" in c["code"] for c in entry["cli"])
    assert "does not imply same-Region re-encryption" in " ".join(entry["caveats"])


def test_drs_guidance_tracks_current_source_replication_not_historical_jobs():
    entry = reviewed()["aws.c2b.drs.region_has_job"]
    assert entry["review_status"] == "approved"
    assert entry["field_binding"]["kind"] == "drs_source_server"
    assert "dataReplicationInfo.dataReplicationState" in entry["field_binding"]["path"]
    assert "DescribeJobs history" in " ".join(entry["caveats"])
    assert "NOT_APPLICABLE" in " ".join(entry["steps"])
    assert any("start-replication --source-server-id <STOPPED_SOURCE_SERVER_ID>" in c["code"]
               for c in entry["cli"])
    assert "billing" in " ".join(entry["caveats"])
    assert all("start-recovery" not in c["code"] for c in entry["cli"])
