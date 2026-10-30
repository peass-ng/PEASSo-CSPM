"""Static customer metadata policy: verified aliases, no values/grants, size limits."""
import json
from pathlib import Path
import pytest
import scripts.peaso_deploy_customer_policy as policy_module
from scripts.peaso_deploy_customer_policy import (
    ACTION_ALIASES, VERIFIED_ACTIONS,
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
    # AWS authorizes the Budgets read APIs as budgets:ViewBudget plus aws-portal:ViewBilling.
    for action in actions - {"apigateway:GET", "cloudtrail:LookupEvents", "iam:SimulatePrincipalPolicy", "ec2:SearchTransitGatewayRoutes", "iam:GenerateCredentialReport", "iam:GenerateServiceLastAccessedDetails", "braket:SearchDevices",
                             "budgets:ViewBudget", "aws-portal:ViewBilling"}:
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


