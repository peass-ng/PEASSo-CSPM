"""Static customer metadata policy: verified aliases, no values/grants, size limits."""
import json
import hashlib
from pathlib import Path
import pytest
import scripts.peaso_deploy_customer_policy as policy_module
from tests.customer_policy_history import historical_role_bytes, historical_role_template, historical_derivative_sha256
from scripts.peaso_deploy_customer_policy import (
    ACTION_ALIASES, SERVICE_PREFIXES, VERIFIED_ACTIONS, REFERENCE_URL,
    UNGRANTED_CREDENTIAL_OPERATIONS,
    build_policy, iam_action, policy_size, split_policy, IAM_MANAGED_POLICY_LIMIT, IAM_MANAGED_POLICIES_PER_ROLE,
)


@pytest.mark.parametrize("service,operation,expected", [
    ("accessanalyzer", "list_analyzers", "access-analyzer:ListAnalyzers"),
    ("iam", "list_server_certificates", "iam:ListServerCertificates"),
    ("iam", "list_virtual_mfa_devices", "iam:ListVirtualMFADevices"),
    ("cloudtrail", "lookup_events", "cloudtrail:LookupEvents"),
    ("sso-admin", "list_instances", "sso:ListInstances"),
    ("sso-admin", "get_inline_policy_for_permission_set", "sso:GetInlinePolicyForPermissionSet"),
    ("identitystore", "list_users", "identitystore:ListUsers"),
    ("s3", "list_buckets", "s3:ListAllMyBuckets"),
    ("s3", "get_bucket_lifecycle_configuration", "s3:GetLifecycleConfiguration"),
    ("s3", "get_object_lock_configuration", "s3:GetBucketObjectLockConfiguration"),
    ("s3", "get_bucket_notification_configuration", "s3:GetBucketNotification"),
    ("s3", "get_bucket_replication", "s3:GetReplicationConfiguration"),
    ("s3", "get_bucket_encryption", "s3:GetEncryptionConfiguration"),
    ("s3control", "get_public_access_block", "s3:GetAccountPublicAccessBlock"),
    ("ec2", "describe_iam_instance_profile_associations", "ec2:DescribeIamInstanceProfileAssociations"),
    ("codepipeline", "get_pipeline", "codepipeline:GetPipeline"),
    ("efs", "describe_file_systems", "elasticfilesystem:DescribeFileSystems"),
    ("efs", "describe_backup_policy", "elasticfilesystem:DescribeBackupPolicy"),
    ("elb", "describe_load_balancers", "elasticloadbalancing:DescribeLoadBalancers"),
    ("elbv2", "describe_listeners", "elasticloadbalancing:DescribeListeners"),
    ("docdb", "describe_db_clusters", "rds:DescribeDBClusters"),
    ("neptune", "describe_db_clusters", "rds:DescribeDBClusters"),
    ("opensearch", "describe_domain", "es:DescribeDomain"),
    ("cloudformation", "list_stacks", "cloudformation:ListStacks"),
    ("drs", "describe_source_servers", "drs:DescribeSourceServers"),
    ("kafka", "get_compatible_kafka_versions", "kafka:GetCompatibleKafkaVersions"),
    ("ecr", "describe_image_scan_findings", "ecr:DescribeImageScanFindings"),
    ("rds", "describe_orderable_db_instance_options", "rds:DescribeOrderableDBInstanceOptions"),
    ("secretsmanager", "describe_secret", "secretsmanager:DescribeSecret"),
])
def test_sdk_aliases_are_real_reviewed_iam_permissions(service, operation, expected):
    assert iam_action(service, operation) == expected
    assert expected in VERIFIED_ACTIONS


@pytest.mark.parametrize("service,operation", [
    ("secretsmanager", "get_secret_value"), ("secretsmanager", "batch_get_secret_value"),
    ("ssm", "get_parameter"), ("ssm", "get_parameters_by_path"),
    ("s3", "get_object"), ("lambda", "get_function"), ("ecr", "get_authorization_token"),
    ("logs", "get_log_events"), ("acm", "export_certificate"),
    ("iam", "create_role"), ("iam", "put_role_policy"), ("ec2", "run_instances"),
])
def test_content_credentials_and_mutation_operations_are_rejected(service, operation):
    with pytest.raises(ValueError):
        build_policy({(service, operation)}, include_credential_report_generation=False)


def test_current_declared_read_actions_are_verified_and_sts_not_granted():
    from peaso.collectors.aws import READ_ACTIONS
    assert UNGRANTED_CREDENTIAL_OPERATIONS <= READ_ACTIONS
    policy = build_policy(READ_ACTIONS)
    actions = {action for statement in policy["Statement"] for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])}
    assert actions.issubset(VERIFIED_ACTIONS)
    assert "sts:AssumeRole" not in actions and "sts:GetCallerIdentity" not in actions
    assert "iam:GenerateCredentialReport" in actions
    assert "iam:GenerateServiceLastAccessedDetails" in actions
    for action in actions - {"apigateway:GET", "cloudtrail:LookupEvents", "iam:SimulatePrincipalPolicy", "ec2:SearchTransitGatewayRoutes", "iam:GenerateCredentialReport", "iam:GenerateServiceLastAccessedDetails", "braket:SearchDevices"}:
        assert action.split(":", 1)[1].startswith(("Get", "List", "Describe", "BatchGet"))
    documents = split_policy(policy)
    assert len(documents) <= IAM_MANAGED_POLICIES_PER_ROLE
    assert all(policy_size(document) <= IAM_MANAGED_POLICY_LIMIT for document in documents)


def test_client_vpn_route_inventory_has_only_endpoint_scoped_read_grants():
    from peaso.collectors.aws import READ_ACTIONS
    pairs = {
        ("ec2", "describe_client_vpn_routes"),
        ("ec2", "describe_client_vpn_target_networks"),
    }
    assert pairs <= READ_ACTIONS
    policy = build_policy(pairs, include_credential_report_generation=False)
    assert policy["Statement"] == [{
        "Sid": "ClientVpnRouteInventoryRead", "Effect": "Allow",
        "Action": ["ec2:DescribeClientVpnRoutes", "ec2:DescribeClientVpnTargetNetworks"],
        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:ec2:*:${AWS::AccountId}:client-vpn-endpoint/*"},
    }]
    assert set(policy["Statement"][0]["Action"]) <= VERIFIED_ACTIONS


def test_generated_customer_role_keeps_client_vpn_route_reads_endpoint_scoped():
    template = json.loads((Path(__file__).resolve().parents[1] / "infra/aws/customer-role.json").read_text())
    documents = [resource["Properties"]["PolicyDocument"] for resource in template["Resources"].values()
                 if resource.get("Type") == "AWS::IAM::ManagedPolicy"]
    target_actions = {"ec2:DescribeClientVpnRoutes", "ec2:DescribeClientVpnTargetNetworks"}
    statements = [statement for document in documents for statement in document["Statement"]]
    selected = [statement for statement in statements
                if target_actions & set(statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]])]
    assert len(selected) == 1
    assert set(selected[0]["Action"]) == target_actions
    assert selected[0]["Resource"] == {"Fn::Sub": "arn:${AWS::Partition}:ec2:*:${AWS::AccountId}:client-vpn-endpoint/*"}
    assert len(documents) <= IAM_MANAGED_POLICIES_PER_ROLE
    assert all(policy_size(document) <= IAM_MANAGED_POLICY_LIMIT for document in documents)


def test_credential_report_evidence_refresh_is_separate_and_optional():
    policy = build_policy({("iam", "get_credential_report"), ("iam", "generate_credential_report")}, include_credential_report_generation=False)
    assert policy["Statement"][0]["Action"] == ["iam:GetCredentialReport"]
    assert len(policy["Statement"]) == 1
    policy = build_policy({("iam", "get_credential_report")})
    assert len(policy["Statement"]) == 1
    policy = build_policy({("iam", "get_credential_report")}, include_credential_report_generation=True)
    assert policy["Statement"][1]["Action"] == "iam:GenerateCredentialReport"


def test_api_gateway_get_resources_are_partition_aware_configuration_paths():
    policy = build_policy({("apigateway", "get_rest_apis"), ("apigatewayv2", "get_stages")}, include_credential_report_generation=False)
    gateway = next(statement for statement in policy["Statement"] if statement["Sid"] == "ApiGatewayConfigurationRead")
    assert gateway["Action"] == "apigateway:GET"
    assert gateway["Resource"] == [{"Fn::Sub": "arn:${AWS::Partition}:apigateway:*::" + path} for path in ("/apis/*/stages", "/restapis")]
    assert all("apikey" not in str(resource).lower() for resource in gateway["Resource"])


def test_client_certificate_metadata_path_is_exact_and_credential_read_is_ungranted():
    policy = build_policy({("apigateway", "get_client_certificate")}, include_credential_report_generation=False)
    assert policy["Statement"] == [{
        "Sid": "ApiGatewayConfigurationRead", "Effect": "Allow", "Action": "apigateway:GET",
        "Resource": [{"Fn::Sub": "arn:${AWS::Partition}:apigateway:*::/clientcertificates/*"}],
    }]
    assert UNGRANTED_CREDENTIAL_OPERATIONS == {("lightsail", "get_bucket_access_keys")}
    with pytest.raises(ValueError, match="Credential API prohibited"):
        iam_action("lightsail", "get_bucket_access_keys")
    with pytest.raises(ValueError, match="No reviewed metadata permissions"):
        build_policy(UNGRANTED_CREDENTIAL_OPERATIONS, include_credential_report_generation=False)


def test_unreviewed_sdk_permission_fails_closed():
    # This is a real read-only SDK operation absent from the captured audit
    # allowlist: action-name existence alone must not broaden the customer role.
    with pytest.raises(ValueError, match="reference review"):
        iam_action("ec2", "describe_host_reservations")


def test_association_mapping_cannot_alias_to_another_reviewed_action(monkeypatch):
    assert policy_module.ASSOCIATION_REFERENCE == (
        "ec2:DescribeIamInstanceProfileAssociations",
        "https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html",
    )
    monkeypatch.setitem(ACTION_ALIASES, ("ec2", "describe_iam_instance_profile_associations"),
                        "ec2:DescribeInstances")
    with pytest.raises(ValueError, match="mapping differs from reviewed reference"):
        iam_action("ec2", "describe_iam_instance_profile_associations")


def test_gateway_only_policy_has_no_empty_action_statement_and_sts_never_becomes_a_grant():
    policy = build_policy({("apigateway", "get_rest_apis")}, include_credential_report_generation=False)
    assert len(policy["Statement"]) == 1
    assert policy["Statement"][0]["Action"] == "apigateway:GET"
    assert iam_action("sts", "assume_role") is None
    assert iam_action("sts", "get_caller_identity") is None
    with pytest.raises(ValueError, match="No reviewed"):
        build_policy(set(), include_credential_report_generation=False)


def _grants(statements):
    out = set()
    for statement in statements:
        actions = [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
        resources = statement["Resource"] if isinstance(statement["Resource"], list) else [statement["Resource"]]
        out.update((statement["Effect"], action, json.dumps(resource, sort_keys=True)) for action in actions for resource in resources)
    return out


def test_current_role_adds_only_reviewed_cloudtrail_delivery_policy_reads():
    role_root = Path(__file__).resolve().parents[1] / "infra/aws"
    previous = historical_role_template("a33c84bde052ee1dd9ff393cfa702f56bbfa76db954c4f9f18a5e64150f72d02")
    # Freeze this historical transition; current-role additions are tested below.
    active_bytes = historical_role_bytes("b3ba1910f63def680269a6877ae106fd6a7001c00f9d9d6e0b07d9600ae21535")
    assert hashlib.sha256(active_bytes).hexdigest() == historical_derivative_sha256(
        "b3ba1910f63def680269a6877ae106fd6a7001c00f9d9d6e0b07d9600ae21535")
    active = json.loads(active_bytes)
    assert active["Parameters"] == previous["Parameters"]
    assert active["Outputs"] == previous["Outputs"]
    assert active["Resources"]["AuditRole"] == previous["Resources"]["AuditRole"]
    assert set(active["Resources"]) == set(previous["Resources"])
    assert {name: value for name, value in active["Metadata"].items() if name in previous["Metadata"]} == previous["Metadata"]
    assert set(active["Metadata"]) - set(previous["Metadata"]) == {"HackTricksCspmIamRolePolicyMetadataReference"}
    def managed_grants(template):
        return _grants(row for resource in template["Resources"].values()
                       if resource["Type"] == "AWS::IAM::ManagedPolicy"
                       for row in resource["Properties"]["PolicyDocument"]["Statement"])
    assert managed_grants(active) - managed_grants(previous) == {
        ("Allow", action, json.dumps("*")) for action in policy_module.IAM_ROLE_POLICY_METADATA_REFERENCES
    }
    assert not managed_grants(previous) - managed_grants(active)
    for name, resource in active["Resources"].items():
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            assert resource["Properties"]["Description"] == previous["Resources"][name]["Properties"]["Description"]
            assert policy_size(resource["Properties"]["PolicyDocument"]) <= IAM_MANAGED_POLICY_LIMIT


# These SDK reads were introduced after all four archived templates below.
# Keep their captured input universe fixed; current-role grants are tested separately.
_POST_HISTORICAL_METADATA_READS = {
    ('cloudfront', 'get_continuous_deployment_policy'),
    ('rds', 'describe_db_cluster_endpoints'),
    ('accessanalyzer', 'get_analyzer'),
    ('apigateway', 'get_base_path_mappings'),
    ('apigatewayv2', 'get_api_mappings'), ('apigatewayv2', 'get_domain_names'),
    ('apigatewayv2', 'get_integrations'),
    ('scheduler', 'get_schedule'), ('scheduler', 'list_schedules'), ('sqs', 'list_dead_letter_source_queues'),
    ('cloudfront', 'list_vpc_origins'), ('cloudfront', 'get_vpc_origin'),
    ('efs', 'describe_mount_target_security_groups'),
    ('memorydb', 'describe_subnet_groups'),
    ('elasticbeanstalk', 'describe_environment_resources'),
    ('ec2', 'get_launch_template_data'), ('ec2', 'describe_spot_instance_requests'),
    ('ec2', 'describe_instance_credit_specifications'), ('cloudwatch', 'get_metric_statistics'),
    ('kms', 'list_aliases'), ('bedrock-agent', 'get_agent'),
    ('s3', 'list_objects_v2'), ('s3', 'get_object_acl'),
    ('ssm', 'get_document'), ('sagemaker', 'describe_notebook_instance_lifecycle_config'),
    ('datapipeline', 'list_pipelines'), ('datapipeline', 'get_pipeline_definition'),
    ('bedrock-agent', 'list_agent_aliases'),
    ('bedrock-agent', 'get_agent_alias'),
    ('bedrock-agent', 'get_agent_version'),
    ('bedrock', 'get_automated_reasoning_policy'),
    ('resourcegroupstaggingapi', 'get_resources'),
    ('organizations', 'describe_effective_policy'),
    ('organizations', 'describe_organizational_unit'),
    ('budgets', 'describe_budget_actions_for_account'),
    ('budgets', 'describe_budget_action'),
    ('ec2', 'describe_tags'),
    ('lambda', 'list_tags'),
    ('route53resolver', 'list_firewall_domain_lists'),
    ('sagemaker', 'list_endpoints'),
    ('sagemaker', 'describe_endpoint'),
    ('sagemaker', 'list_monitoring_executions'),
    ('iam', 'get_role'),
    ('iam', 'get_context_keys_for_principal_policy'),
    ('iam', 'simulate_principal_policy'),
    ('iam', 'get_policy'),
    ('iam', 'get_role_policy'),
    ('iam', 'list_attached_role_policies'),
    ('iam', 'list_role_policies'),
    ('accessanalyzer', 'get_finding_v2'),
    ('codecommit', 'list_repositories'),
    ('codecommit', 'list_pull_requests'),
    ('codecommit', 'get_pull_request'),
    ('codecommit', 'describe_pull_request_events'),
    ('codecommit', 'get_pull_request_approval_states'),
    ('controltower', 'list_landing_zones'),
    ('controltower', 'get_landing_zone'),
    ('dynamodb', 'list_backups'),
    ('ec2', 'describe_transit_gateway_vpc_attachments'),
    ('ec2', 'get_transit_gateway_route_table_associations'),
    ('ec2', 'search_transit_gateway_routes'),
    ('elb', 'describe_load_balancer_policies'),
    ('macie2', 'get_findings'),
    ('macie2', 'list_findings'),
    ('outposts', 'list_outposts'),
    ('rds', 'describe_db_cluster_automated_backups'),
    ('rds', 'describe_db_instance_automated_backups'),
    ('redshift-serverless', 'list_recovery_points'),
    ('redshift-serverless', 'list_snapshots'),
    ('s3control', 'list_regional_buckets'),
    ('s3tables', 'list_table_buckets'),
    ('s3vectors', 'list_vector_buckets'),
    ('securityhub', 'get_finding_history'),
    ('amplify', 'list_branches'),
    ('appstream', 'describe_app_block_builder_app_block_associations'),
    ('appstream', 'describe_app_blocks'), ('appstream', 'describe_images'),
    ('appstream', 'list_associated_stacks'),
    ('athena', 'get_session'), ('athena', 'list_sessions'),
    ('batch', 'describe_job_queues'), ('braket', 'search_devices'),
    ('cloudformation', 'describe_organizations_access'),
    ('deadline', 'get_queue'), ('deadline', 'list_queues'), ('deadline', 'list_workers'),
    ('devicefarm', 'get_device_pool_compatibility'), ('devicefarm', 'list_device_pools'),
    ('devicefarm', 'list_uploads'),
    ('gamelift', 'describe_fleet_attributes'), ('gamelift', 'list_compute'),
    ('gamelift', 'list_fleets'),
    ('gameliftstreams', 'list_stream_groups'), ('gameliftstreams', 'list_stream_sessions'),
    ('glue', 'get_triggers'), ('glue', 'list_sessions'),
    ('grafana', 'list_workspace_service_accounts'),
    ('iam', 'list_ssh_public_keys'),
    ('iot', 'describe_role_alias'), ('iot', 'list_role_aliases'),
    ('lambda-microvms', 'list_microvm_images'),
    ('quicksight', 'describe_account_subscription'),
    ('sagemaker', 'describe_space'), ('sagemaker', 'list_apps'),
    ('sagemaker', 'list_notebook_instance_lifecycle_configs'),
    ('sagemaker', 'list_spaces'), ('sagemaker', 'list_studio_lifecycle_configs'),
    ('ssm', 'describe_maintenance_window_tasks'), ('ssm', 'describe_maintenance_windows'),
    ('amplify', 'list_domain_associations'),
    ('apigatewayv2', 'list_routing_rules'),
    ('ec2', 'describe_client_vpn_routes'),
    ('ec2', 'describe_client_vpn_target_networks'),
    ('cloudfront', 'get_cloud_front_origin_access_identity'),
    ('cloudfront', 'get_origin_access_control'),
    ('elb', 'describe_instance_health'),
    ('elbv2', 'describe_target_group_attributes'),
    ('logs', 'describe_account_policies'),
    ('sns', 'list_subscriptions_by_topic'),
}

# Resource-policy discovery extends the live input universe. These historical
# transition tests continue to reproduce the SDK operations available then.
_POST_HISTORICAL_METADATA_READS.update(tuple(pair.split("/", 1)) for pair in
    policy_module.RESOURCE_POLICY_REFERENCE["added_operations"])
from peaso.collectors.aws_network_catalog import SPECS as _NETWORK_SPECS, READ_ACTIONS as _NETWORK_READS
_POST_HISTORICAL_METADATA_READS.update((_NETWORK_READS | {(s, o) for s, o, _ in _NETWORK_SPECS.values()}) - {
    ('emr', 'describe_cluster'), ('eks', 'list_clusters'), ('globalaccelerator', 'list_accelerators'),
    ('apigateway', 'get_resources'),
    ('elasticbeanstalk', 'describe_configuration_settings'),
    ('route53resolver', 'list_resolver_rules'), ('sagemaker', 'describe_cluster'), ('sagemaker', 'describe_endpoint')})


from peaso.collectors.aws_network_inventory import READ_ACTIONS as _NATIVE_NETWORK_READS
_NETWORK_HISTORY = historical_role_template('e2b8788e174bba78779421bb13b2c5d12ae1dd2599715653e7ea62f4463bcc0d')
_NETWORK_HISTORY_ACTIONS = {action for resource in _NETWORK_HISTORY['Resources'].values()
    if resource.get('Type') == 'AWS::IAM::ManagedPolicy'
    for statement in resource['Properties']['PolicyDocument']['Statement']
    for action in ([statement['Action']] if isinstance(statement['Action'], str) else statement['Action'])}
_POST_HISTORICAL_METADATA_READS.update(pair for pair in _NATIVE_NETWORK_READS
    if iam_action(*pair) not in _NETWORK_HISTORY_ACTIONS)


def _build_historical_policy(*args, **kwargs):
    # Resource-policy companion IAM actions were absent when these immutable
    # archives were signed. Reconstruct that dependency table only in this
    # test context; live generation retains every reviewed companion read.
    with pytest.MonkeyPatch.context() as patch:
        historical_dependencies = dict(policy_module.DEPENDENT_ACTIONS)
        for pair in policy_module.RESOURCE_POLICY_REFERENCE["additional_actions"]:
            historical_dependencies.pop(tuple(pair.split("/", 1)), None)
        patch.setattr(policy_module, "DEPENDENT_ACTIONS", historical_dependencies)
        return build_policy(*args, **kwargs)


def test_generated_template_matches_policy_without_live_changes():
    role_root = Path(__file__).resolve().parents[1] / "infra/aws"
    current_bytes = historical_role_bytes("e2b8788e174bba78779421bb13b2c5d12ae1dd2599715653e7ea62f4463bcc0d")
    signed_hash = 'e2b8788e174bba78779421bb13b2c5d12ae1dd2599715653e7ea62f4463bcc0d'
    assert hashlib.sha256(current_bytes).hexdigest() == historical_derivative_sha256(signed_hash)
    template = json.loads(current_bytes)
    managed = [resource for name, resource in sorted(template["Resources"].items()) if resource["Type"] == "AWS::IAM::ManagedPolicy"]
    documents = [resource["Properties"]["PolicyDocument"] for resource in managed]
    from peaso.collectors.aws import READ_ACTIONS
    historical_policy = _build_historical_policy((READ_ACTIONS | policy_module.PRESERVED_TEMPLATE_READ_ACTIONS) - {
        ("wafv2", "list_ip_sets"), ("wafv2", "get_ip_set"),
        ('organizations', 'describe_resource_policy'), ('cloudwatch', 'list_metrics'), ('apigateway', 'get_deployment'),
        ('identitystore', 'describe_user'), ('identitystore', 'list_group_memberships')} - _POST_HISTORICAL_METADATA_READS
        | {('iam', 'generate_service_last_accessed_details')},
        include_credential_report_generation=True, include_waf_association_companions=False)
    prospective = split_policy(historical_policy)
    assert documents == prospective
    assert len(documents) == 3
    assert [policy_size(document) for document in documents] == [6136, 6129, 5215]
    prior = historical_role_template("9254e0c0c0a7519c7a0a0c128e9d147d799dba3ca9cf9ff76902fcb4cd5ab08f")
    assert template["Resources"]["AuditRole"] == prior["Resources"]["AuditRole"]
    assert documents[:2] == [prior["Resources"][f"CspmConfigurationReadOnly{number}"]["Properties"]["PolicyDocument"] for number in (1, 2)]
    signed_grants = _grants(statement for number in (1, 2, 3) for statement in prior["Resources"][f"CspmConfigurationReadOnly{number}"]["Properties"]["PolicyDocument"]["Statement"])
    candidate_grants = _grants(statement for document in documents for statement in document["Statement"])
    assert candidate_grants - signed_grants == {
        ("Allow", "ec2:DescribeIamInstanceProfileAssociations", json.dumps("*")),
        ("Allow", "secretsmanager:DescribeSecret", json.dumps("*")),
        ("Allow", "iam:ListPolicies", json.dumps("*")),
        ("Allow", "iam:GetPolicyVersion", json.dumps("*")),
        ("Allow", "elasticmapreduce:ListInstances", json.dumps("*")),
    } | {("Allow", action, json.dumps("*")) for action in policy_module.BULK_METADATA_REFERENCES}
    assert not signed_grants - candidate_grants
    assert candidate_grants == _grants(historical_policy["Statement"])
    assert all(policy_size(document) <= IAM_MANAGED_POLICY_LIMIT for document in documents)
    assert len(documents) <= IAM_MANAGED_POLICIES_PER_ROLE
    assert all(resource["Properties"]["Roles"] == [{"Ref": "AuditRole"}] for resource in managed)
    assert all("*" not in action.split(":", 1)[1] for document in documents for statement in document["Statement"]
               for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]))
    assert template["Metadata"]["PeasoPermissionReference"]["Source"] == REFERENCE_URL


@pytest.mark.parametrize("mutation", ("strict_subset", "modified_action", "narrow_resource", "condition"))
def test_signed_allocation_is_used_only_for_the_exact_logical_policy(mutation):
    original = build_policy()
    signed_documents = split_policy(original)
    changed = json.loads(json.dumps(original))
    statement = changed["Statement"][0]
    if mutation == "strict_subset":
        statement["Action"].pop()
    elif mutation == "modified_action":
        statement["Action"][0] = statement["Action"][1]  # Duplicate one read; add no grant.
    elif mutation == "narrow_resource":
        statement["Resource"] = "arn:aws:s3:::example"
    else:
        statement["Condition"] = {"Bool": {"aws:SecureTransport": "true"}}
    actual = split_policy(changed)
    assert actual != signed_documents
    assert len(actual) <= IAM_MANAGED_POLICIES_PER_ROLE
    assert all(policy_size(document) <= IAM_MANAGED_POLICY_LIMIT for document in actual)
    statements = [s for document in actual for s in document["Statement"]]
    if mutation == "narrow_resource":
        assert any(s.get("Resource") == "arn:aws:s3:::example" for s in statements)
    elif mutation == "condition":
        assert any("Condition" in s for s in statements)
    else:
        assert _grants(statements) != _grants(
            s for document in signed_documents for s in document["Statement"])


def test_tampered_signed_allocation_fails_closed(tmp_path, monkeypatch):
    original = build_policy()
    tampered = tmp_path / "customer-role-9254.json"
    tampered.write_bytes(policy_module.REVIEWED_ROLE_PATH.read_bytes() + b" ")
    monkeypatch.setattr(policy_module, "REVIEWED_ROLE_PATH", tampered)
    with pytest.raises(ValueError, match="archive changed"):
        split_policy(original)


def test_generic_split_still_rejects_oversize_statement():
    with pytest.raises(ValueError, match="statement exceeds managed policy size"):
        split_policy({"Version": "2012-10-17", "Statement": [{
            "Sid": "x" * (IAM_MANAGED_POLICY_LIMIT + 1), "Effect": "Allow",
            "Action": "ec2:DescribeInstances", "Resource": "*",
        }]})


def test_default_generation_retains_published_list_stacks_supplement():
    from peaso.collectors.aws import READ_ACTIONS
    from scripts.peaso_deploy_customer_policy import PRESERVED_TEMPLATE_READ_ACTIONS
    assert ("cloudformation", "list_stacks") not in READ_ACTIONS
    assert PRESERVED_TEMPLATE_READ_ACTIONS == {("cloudformation", "list_stacks")}
    policy = build_policy()
    actions = [action for statement in policy["Statement"]
               for action in (statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]])]
    assert actions.count("cloudformation:ListStacks") == 1


def test_each_signed_template_transition_adds_only_reviewed_reads():
    root = Path(__file__).resolve().parents[1] / "infra/aws"
    hashes = (
        "7e6fc610eee9021025ffd498c8dc924d740975a34c56f291bc7317a7db182dbe",
        "04fbe795580c205cb86e6ad71a73c52935628bd43c5d5ee398b4333b2155748a",
        "25b895c00a3fad47f390e4946c83f6e47487c8e52e8342cf136d1a1eb1c1ea17",
        "9254e0c0c0a7519c7a0a0c128e9d147d799dba3ca9cf9ff76902fcb4cd5ab08f",
        "6d31b087d5542e740af07fa1e05ede2c7faca0b712ffdb8dba43c19d2cb2ce21",
        "95e70cc9e033643bb3d7e0a400246f7ee392c5d3301319027482bc4350c09a25",
        "e2b8788e174bba78779421bb13b2c5d12ae1dd2599715653e7ea62f4463bcc0d",
    )
    templates = []
    for digest in hashes:
        frozen = historical_role_bytes(digest)
        assert hashlib.sha256(frozen).hexdigest() == historical_derivative_sha256(digest)
        templates.append(json.loads(frozen))
    assert hashes[-1] == "e2b8788e174bba78779421bb13b2c5d12ae1dd2599715653e7ea62f4463bcc0d"

    def actions(resources):
        values = []
        for row in resources.values():
            if row["Type"] != "AWS::IAM::ManagedPolicy":
                continue
            for statement in row["Properties"]["PolicyDocument"]["Statement"]:
                raw = statement["Action"]
                values.extend(raw if isinstance(raw, list) else [raw])
        return values

    expected_additions = (
        {"drs:DescribeSourceServers", "kafka:GetCompatibleKafkaVersions",
         "ecr:DescribeImageScanFindings", "rds:DescribeOrderableDBInstanceOptions"},
        {"backup:GetBackupVaultNotifications", "batch:DescribeJobDefinitions", "codepipeline:GetPipeline",
         "ec2:DescribeClientVpnAuthorizationRules", "ecr-public:DescribeRepositories",
         "kafka:DescribeClusterV2", "kms:DescribeCustomKeyStores", "kms:ListResourceTags",
         "lambda:GetCodeSigningConfig", "lambda:GetFunctionCodeSigningConfig", "lightsail:GetBuckets",
         "route53:GetDNSSEC", "route53:GetHealthCheck", "securityhub:GetFindings",
         "shield:DescribeProtection"},
        {"detective:ListGraphs", "ec2:DescribeDhcpOptions", "events:ListRules",
         "events:ListTargetsByRule", "shield:DescribeDRTAccess", "ssm:ListComplianceItems",
         "ssm:ListInventoryEntries"},
        {'ec2:DescribeIamInstanceProfileAssociations', 'secretsmanager:DescribeSecret',
         'iam:ListPolicies', 'iam:GetPolicyVersion', 'elasticmapreduce:ListInstances'},
        {'ce:GetAnomalyMonitors', 'ce:GetAnomalySubscriptions', 'backup:ListRestoreJobs',
         'backup:ListRestoreTestingPlans', 'backup:ListRestoreTestingSelections',
         'organizations:ListAWSServiceAccessForOrganization'},
        {'route53resolver:ListFirewallRuleGroupAssociations', 'route53resolver:ListFirewallRules',
         'route53resolver:ListFirewallRuleGroups', 'route53resolver:ListResolverQueryLogConfigs',
         'route53resolver:ListResolverQueryLogConfigAssociations', 'logs:DescribeSubscriptionFilters',
         'logs:DescribeDestinations', 'ec2:DescribeInstanceTypes', 'eks:DescribeClusterVersions'},
    )
    expected_changed_resources = (
        {"CspmConfigurationReadOnly1", "CspmConfigurationReadOnly2", "CspmConfigurationReadOnly3"},
        {"CspmConfigurationReadOnly3"},
        {"CspmConfigurationReadOnly3"},
        {"CspmConfigurationReadOnly3"},
        {"CspmConfigurationReadOnly3"},
        {"CspmConfigurationReadOnly3"},
    )
    assert len(expected_additions) == len(expected_changed_resources) == len(templates) - 1
    for position, (before_template, after_template, added, changed) in enumerate(zip(
            templates, templates[1:], expected_additions, expected_changed_resources)):
        assert before_template.keys() == after_template.keys()
        assert all(before_template[key] == after_template[key] for key in ("Parameters", "Outputs"))
        if position == len(expected_additions) - 1:
            metadata = dict(after_template['Metadata'])
            new_reference = metadata.pop('PeasoSprintMetadataReference')
            assert metadata == before_template['Metadata']
            assert new_reference['Actions'] == sorted(added)
            assert new_reference['SHA256'] == policy_module.SPRINT_METADATA_REFERENCE_SHA256
            assert new_reference['Source'] == policy_module.REFERENCE_URL
        else:
            assert before_template['Metadata'] == after_template['Metadata']
        before, after = before_template["Resources"], after_template["Resources"]
        assert before.keys() == after.keys()
        assert before["AuditRole"] == after["AuditRole"]  # Synthetic trust and ExternalId structure stay unchanged.
        assert {key for key in before if before[key] != after[key]} == changed
        previous, present = actions(before), actions(after)
        assert set(present) - set(previous) == added
        assert set(previous) - set(present) == set()
        assert len(present) == len(set(present))
        assert "cloudformation:ListStacks" in present
        assert "lightsail:GetBucketAccessKeys" not in present


def test_unknown_api_gateway_path_is_not_a_generic_get_grant():
    with pytest.raises(ValueError, match="path mapping"):
        build_policy({("apigateway", "get_export")}, include_credential_report_generation=False)


def test_aggregate_inline_limit_includes_existing_template_policies(tmp_path):
    from scripts.peaso_deploy_customer_policy import refresh
    root = Path(__file__).resolve().parents[1]
    original = json.loads((root / "infra/aws/customer-role.json").read_text())
    original["Resources"]["AuditRole"]["Properties"].setdefault("Policies", []).append({"PolicyName": "Existing", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*", "Sid": "x" * 10300}]}})
    target = tmp_path / "infra/aws/customer-role.json"
    target.parent.mkdir(parents=True)
    before = json.dumps(original)
    target.write_text(before)
    with pytest.raises(ValueError, match="aggregate"):
        refresh(tmp_path)
    assert target.read_text() == before


def test_existing_inline_policies_are_preserved_beside_managed_policies(tmp_path):
    from scripts.peaso_deploy_customer_policy import refresh
    root = Path(__file__).resolve().parents[1]
    original = json.loads((root / "infra/aws/customer-role.json").read_text())
    existing = {"PolicyName": "Existing", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}]}}
    original["Resources"]["AuditRole"]["Properties"]["Policies"] = [existing]
    original["Resources"]["CspmConfigurationReadOnly9"] = {"Type": "AWS::IAM::ManagedPolicy", "Properties": {}}  # stale split is removed
    target = tmp_path / "infra/aws/customer-role.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(original))
    refresh(tmp_path)
    written = json.loads(target.read_text())
    assert written["Resources"]["AuditRole"]["Properties"]["Policies"] == [existing]
    assert "CspmConfigurationReadOnly9" not in written["Resources"]
    signed = json.loads((root / "infra/aws/customer-role.json").read_text())["Resources"]
    expected = signed | {"AuditRole": written["Resources"]["AuditRole"]}
    for number, document in enumerate(split_policy(build_policy()), 1):
        expected[f"CspmConfigurationReadOnly{number}"] = {
            **signed[f"CspmConfigurationReadOnly{number}"],
            "Properties": {**signed[f"CspmConfigurationReadOnly{number}"]["Properties"],
                           "PolicyDocument": document},
        }
    assert written["Resources"]["AuditRole"] == expected["AuditRole"]
    assert {name for name in written["Resources"] if name.startswith("CspmConfigurationReadOnly")} == {
        f"CspmConfigurationReadOnly{number}" for number in range(1, len(split_policy(build_policy())) + 1)}
    for number, document in enumerate(split_policy(build_policy()), 1):
        assert written["Resources"][f"CspmConfigurationReadOnly{number}"]["Properties"]["PolicyDocument"] == document
    assert {key: value for key, value in written["Resources"].items()
            if not key.startswith("CspmConfigurationReadOnly")} == {
        key: value for key, value in expected.items() if not key.startswith("CspmConfigurationReadOnly")}


def test_waf_ip_set_template_adds_only_two_reviewed_configuration_reads():
    root = Path(__file__).resolve().parents[1] / "infra/aws"
    digest = "f46db717efb93db136ec5893e819904b0fb931f4ba512f52d6cdb907a6e6a04c"
    source = historical_role_bytes(digest)
    assert hashlib.sha256(source).hexdigest() == historical_derivative_sha256(digest)
    before = historical_role_template("e2b8788e174bba78779421bb13b2c5d12ae1dd2599715653e7ea62f4463bcc0d")
    after = json.loads(source)
    assert before.keys() == after.keys()
    assert before["Parameters"] == after["Parameters"] and before["Outputs"] == after["Outputs"]
    assert before["Resources"].keys() == after["Resources"].keys()
    assert {key for key in before["Resources"] if before["Resources"][key] != after["Resources"][key]} == {"CspmConfigurationReadOnly3"}
    documents = [after["Resources"][f"CspmConfigurationReadOnly{i}"]["Properties"]["PolicyDocument"] for i in (1, 2, 3)]
    prior = [before["Resources"][f"CspmConfigurationReadOnly{i}"]["Properties"]["PolicyDocument"] for i in (1, 2, 3)]
    from peaso.collectors.aws import READ_ACTIONS
    historical_actions = READ_ACTIONS | policy_module.PRESERVED_TEMPLATE_READ_ACTIONS
    historical_actions -= {('organizations', 'describe_resource_policy'), ('cloudwatch', 'list_metrics'), ('apigateway', 'get_deployment'),
                           ('identitystore', 'describe_user'), ('identitystore', 'list_group_memberships')} | _POST_HISTORICAL_METADATA_READS
    assert documents == split_policy(_build_historical_policy(
        historical_actions | {('iam', 'generate_service_last_accessed_details')},
        include_credential_report_generation=True, include_waf_association_companions=False))
    assert [policy_size(doc) for doc in documents] == [6136, 6129, 5325]
    assert _grants(statement for doc in documents for statement in doc["Statement"]) - _grants(statement for doc in prior for statement in doc["Statement"]) == {
        ("Allow", action, json.dumps("*")) for action in policy_module.WAF_IP_SET_ACTIONS}
    assert not _grants(statement for doc in prior for statement in doc["Statement"]) - _grants(statement for doc in documents for statement in doc["Statement"])
    metadata = dict(after["Metadata"])
    reference = metadata.pop("PeasoWafIpSetMetadataReference")
    assert metadata == before["Metadata"]
    assert reference["Actions"] == ["wafv2:GetIPSet", "wafv2:ListIPSets"]
    assert reference["SHA256"] == policy_module.WAF_IP_SET_REFERENCE_SHA256
    assert reference["Source"] == policy_module.REFERENCE_URL


def test_native_batch_role_adds_only_reviewed_metadata_and_scoped_deployment_read():
    root = Path(__file__).resolve().parents[1] / 'infra/aws'
    digest = '2204d577d48f10958947199b840d0989b88bbeee4e4b396193cc427b59f39ccf'
    source = historical_role_bytes(digest)
    assert hashlib.sha256(source).hexdigest() == historical_derivative_sha256(digest)
    before = historical_role_template("f46db717efb93db136ec5893e819904b0fb931f4ba512f52d6cdb907a6e6a04c")
    after = json.loads(source)
    assert before.keys() == after.keys()
    assert before['Parameters'] == after['Parameters'] and before['Outputs'] == after['Outputs']
    assert before['Resources'].keys() == after['Resources'].keys()
    assert {key for key in before['Resources'] if before['Resources'][key] != after['Resources'][key]} == {'CspmConfigurationReadOnly3'}
    documents = [after['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument'] for i in (1, 2, 3)]
    prior = [before['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument'] for i in (1, 2, 3)]
    from peaso.collectors.aws import READ_ACTIONS
    historical_actions = (READ_ACTIONS | policy_module.PRESERVED_TEMPLATE_READ_ACTIONS) - {
        ('identitystore', 'describe_user'), ('identitystore', 'list_group_memberships')} - _POST_HISTORICAL_METADATA_READS
    assert documents == split_policy(_build_historical_policy(
        historical_actions | {('iam', 'generate_service_last_accessed_details')},
        include_credential_report_generation=True, include_waf_association_companions=False))
    assert [policy_size(document) for document in documents] == [6136, 6129, 5663]
    expected = {('Allow', action, json.dumps('*')) for action in policy_module.NATIVE_BATCH_ACTIONS}
    expected.add(('Allow', 'apigateway:GET', json.dumps({'Fn::Sub': 'arn:${AWS::Partition}:apigateway:*::/restapis/*/deployments/*'})))
    current_grants = _grants(statement for document in documents for statement in document['Statement'])
    prior_grants = _grants(statement for document in prior for statement in document['Statement'])
    assert current_grants - prior_grants == expected
    assert not prior_grants - current_grants
    metadata = dict(after['Metadata']);reference = metadata.pop('PeasoNativeBatchMetadataReference')
    assert metadata == before['Metadata']
    assert reference['Actions'] == sorted(policy_module.NATIVE_BATCH_ACTIONS)
    assert reference['SHA256'] == policy_module.NATIVE_BATCH_REFERENCE_SHA256


def test_identity_center_role_adds_only_two_status_and_membership_reads():
    root = Path(__file__).resolve().parents[1] / 'infra/aws'
    source = historical_role_bytes("a57cdf166f64c9ad96a367a48fb62e54754a58a89ed767119f9dc46c05e46980")
    digest = 'a57cdf166f64c9ad96a367a48fb62e54754a58a89ed767119f9dc46c05e46980'
    assert hashlib.sha256(source).hexdigest() == historical_derivative_sha256(digest)
    before = historical_role_template("2204d577d48f10958947199b840d0989b88bbeee4e4b396193cc427b59f39ccf")
    after = json.loads(source)
    assert before.keys() == after.keys()
    assert before['Parameters'] == after['Parameters'] and before['Outputs'] == after['Outputs']
    assert before['Resources'].keys() == after['Resources'].keys()
    assert {key for key in before['Resources'] if before['Resources'][key] != after['Resources'][key]} == {'CspmConfigurationReadOnly3'}
    documents = [after['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument'] for i in (1, 2, 3)]
    prior = [before['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument'] for i in (1, 2, 3)]
    from peaso.collectors.aws import READ_ACTIONS
    historical_actions = (READ_ACTIONS | policy_module.PRESERVED_TEMPLATE_READ_ACTIONS) - _POST_HISTORICAL_METADATA_READS
    assert documents == split_policy(_build_historical_policy(
        historical_actions | {('iam', 'generate_service_last_accessed_details')},
        include_credential_report_generation=True, include_waf_association_companions=False))
    assert documents[:2] == prior[:2]
    assert [policy_size(document) for document in documents] == [6136, 6129, 5819]
    grants = _grants(statement for document in documents for statement in document['Statement'])
    prior_grants = _grants(statement for document in prior for statement in document['Statement'])
    assert grants - prior_grants == {('Allow', action, json.dumps('*')) for action in policy_module.IDENTITY_CENTER_ACTIONS}
    assert not prior_grants - grants
    metadata = dict(after['Metadata']);reference = metadata.pop('PeasoIdentityCenterMetadataReference')
    assert metadata == before['Metadata']
    assert reference['Actions'] == sorted(policy_module.IDENTITY_CENTER_ACTIONS)
    assert reference['SHA256'] == policy_module.IDENTITY_CENTER_REFERENCE_SHA256


def test_aws_review_role_exact_configuration_read_delta():
    root = Path(__file__).resolve().parents[1] / 'infra/aws'
    previous = historical_role_template("b3ba1910f63def680269a6877ae106fd6a7001c00f9d9d6e0b07d9600ae21535")
    # Freeze this historical transition; resource-policy expansion has its own delta test.
    active_bytes = historical_role_bytes("ae1b7534ceca1ddf593d1ba9cb04fd8baacf68eebc3bdc891a23d39d915a9893")
    assert hashlib.sha256(active_bytes).hexdigest() == historical_derivative_sha256(
        "ae1b7534ceca1ddf593d1ba9cb04fd8baacf68eebc3bdc891a23d39d915a9893")
    active = json.loads(active_bytes)
    for key in ('Parameters', 'Outputs', 'Metadata'):
        assert active[key] == previous[key]
    assert active['Resources']['AuditRole'] == previous['Resources']['AuditRole']
    def grants(template):
        return _grants(s for r in template['Resources'].values() if r['Type'] == 'AWS::IAM::ManagedPolicy'
                       for s in r['Properties']['PolicyDocument']['Statement'])
    expected = {'bedrock:GetAgent', 'kms:ListAliases', 's3:GetObjectAcl', 's3:ListBucket',
                'ssm:GetDocument', 'sagemaker:DescribeNotebookInstanceLifecycleConfig',
                'datapipeline:ListPipelines', 'datapipeline:GetPipelineDefinition',
                'ec2:GetLaunchTemplateData', 'ec2:DescribeSpotInstanceRequests',
                'ec2:DescribeInstanceCreditSpecifications', 'cloudwatch:GetMetricStatistics',
                'elasticbeanstalk:DescribeEnvironmentResources'}
    assert grants(active) - grants(previous) == {('Allow', a, json.dumps('*')) for a in expected}
    assert not grants(previous) - grants(active)
    for operation in policy_module.UNGRANTED_CONTENT_OPERATIONS:
        with pytest.raises(ValueError, match='No reviewed metadata permissions selected'):
            build_policy({operation}, include_credential_report_generation=False)
    assert iam_action('ssm', 'get_document') == 'ssm:GetDocument'
