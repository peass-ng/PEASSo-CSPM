"""HackTricks BP / privesc collector facts (aws_facts_ext): per-call Stubber coverage, sanitizing and failure semantics."""
import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.collectors import aws_facts_ext as ext

ACCOUNT = "123456789012"
OTHER = "999999999999"
REGION = "us-east-1"
FN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:app"


@pytest.fixture
def stub(monkeypatch):
    session = boto3.Session(aws_access_key_id="k", aws_secret_access_key="s", region_name=REGION)
    clients, stubs = {}, {}

    def add(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service])
            stubs[service].activate()
        return stubs[service]

    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: clients[service])
    yield session, add
    for item in stubs.values():
        item.assert_no_pending_responses()
        item.deactivate()


def run(kind, session, requests=None):
    return ext.FETCHERS[kind](requests or aws.Requests({}), session, REGION, ACCOUNT)


def test_organizations_access_validation_error_keeps_unknown(stub):
    session, add = stub
    add('cloudformation').add_client_error('describe_organizations_access', 'ValidationError', expected_params={})
    read = run('cloudformation_organizations_access', session)
    assert read.status == 'unknown' and read.items == []
    assert read.error == {'code': 'ValidationError', 'cause_status': 'unknown'}


def test_organizations_access_documented_disabled_state(stub):
    session, add = stub
    add('cloudformation').add_response('describe_organizations_access', {'Status': 'DISABLED'}, {})
    read = run('cloudformation_organizations_access', session)
    assert read.status == 'collected' and read.items == [{'id': f'{ACCOUNT}/{REGION}', 'Status': 'DISABLED'}]


def test_extension_registers_read_only_kinds():
    for kind in ext.SPECS:
        assert kind in aws.AWS_TYPES and aws.FETCHERS[kind] is ext.FETCHERS[kind]
    assert set(ext.SPECS) == set(ext.FETCHERS)
    assert "route53_record_set" in aws.GLOBAL_TYPES
    assert ext.READ_ACTIONS <= aws.READ_ACTIONS
    assert all(op.startswith(("list_", "describe_", "get_")) for _, op in ext.READ_ACTIONS)
    historical = (
        "peaso.collectors.aws_facts_ext", "peaso.collectors.aws_facts_v4_holds",
        "peaso.collectors.aws_bulk_inventory")
    start = aws.EXTENSION_MODULES.index(historical[0])
    assert aws.EXTENSION_MODULES[start:start + len(historical)] == historical
    operational = "peaso.collectors.aws_operational_groups_native"
    assert aws.EXTENSION_MODULES.index(operational) > start + len(historical) - 1
    assert len(set(aws.EXTENSION_MODULES)) == len(aws.EXTENSION_MODULES)
    from peaso.collectors import aws_operational_groups_native
    assert aws_operational_groups_native.READ_ACTIONS <= aws.READ_ACTIONS
    assert all(op.startswith(("list_", "describe_", "get_"))
               for _, op in aws_operational_groups_native.READ_ACTIONS)
    for kind in aws_operational_groups_native.SPECS:
        assert kind in aws.AWS_TYPES
        assert aws.FETCHERS[kind] is aws_operational_groups_native.FETCHERS[kind]
    from peaso.collectors import aws_bulk_inventory
    for kind in aws_bulk_inventory.SPECS:
        assert kind in aws.AWS_TYPES and aws.FETCHERS[kind] is aws_bulk_inventory.FETCHERS[kind]
    assert aws.FETCHERS["lambda_layer_version"] is ext.FETCHERS["lambda_layer_version"]


def test_layer_versions_with_public_policy_and_absent_policy(stub):
    session, add = stub
    lam = add("lambda")
    lam.add_response("list_layers", {"Layers": [{"LayerName": "shared", "LayerArn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:layer:shared"}]})
    lam.add_response("list_layer_versions", {"LayerVersions": [
        {"LayerVersionArn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:layer:shared:2", "Version": 2},
        {"LayerVersionArn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:layer:shared:1", "Version": 1}]}, {"LayerName": "shared"})
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "lambda:GetLayerVersion", "Resource": "*"}]}
    lam.add_response("get_layer_version_policy", {"Policy": json.dumps(policy), "RevisionId": "r"}, {"LayerName": "shared", "VersionNumber": 2})
    lam.add_client_error("get_layer_version_policy", "ResourceNotFoundException", expected_params={"LayerName": "shared", "VersionNumber": 1})
    read = run("lambda_layer_version", session)
    assert read.status == "collected" and len(read.items) == 2
    assert read.items[0]["Policy"]["collection_status"] == "collected"
    assert read.items[0]["Policy"]["Policy"]["Statement"][0]["Principal"] == "*"
    assert read.items[1]["Policy"] == {"collection_status": "empty", "absent": True, "error": {"code": "ResourceNotFoundException"}}


def test_layer_policy_denied_keeps_status(stub):
    session, add = stub
    lam = add("lambda")
    lam.add_response("list_layers", {"Layers": [{"LayerName": "shared"}]})
    lam.add_response("list_layer_versions", {"LayerVersions": [{"Version": 1}]}, {"LayerName": "shared"})
    lam.add_client_error("get_layer_version_policy", "AccessDeniedException", expected_params={"LayerName": "shared", "VersionNumber": 1})
    read = run("lambda_layer_version", session)
    assert read.items[0]["Policy"]["collection_status"] == "denied"


def test_list_layers_denied_is_denied(stub):
    session, add = stub
    add("lambda").add_client_error("list_layers", "AccessDeniedException")
    read = run("lambda_layer_version", session)
    assert read.status == "denied" and read.items == []


def test_aliases_and_event_source_mappings(stub):
    session, add = stub
    lam = add("lambda")
    lam.add_response("list_functions", {"Functions": [{"FunctionName": "app", "FunctionArn": FN}]})
    lam.add_response("list_aliases", {"Aliases": [{"AliasArn": FN + ":live", "Name": "live", "FunctionVersion": "3",
        "RoutingConfig": {"AdditionalVersionWeights": {"4": 0.1}}}]}, {"FunctionName": "app"})
    lam.add_client_error("get_function_url_config", "ResourceNotFoundException",
                         expected_params={"FunctionName": "app", "Qualifier": "live"})
    lam.add_response("list_event_source_mappings", {"EventSourceMappings": [{"UUID": "11111111-2222-3333-4444-555555555555", "FunctionArn": FN, "State": "Enabled",
        "EventSourceArn": f"arn:aws:sqs:{REGION}:{OTHER}:q", "FilterCriteria": {"Filters": [{"Pattern": "{\"secret\":[\"x\"]}"}]},
        "SourceAccessConfigurations": [{"Type": "BASIC_AUTH", "URI": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:s"}],
        "SelfManagedEventSource": {"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": ["b-1:9092"]}}}]})
    aliases = run("lambda_alias", session)
    assert aliases.status == "collected" and aliases.items[0]["id"] == FN + ":live" and aliases.items[0]["FunctionName"] == "app"
    assert aliases.items[0]["FunctionUrl"]["absent"] is True
    esm = run("lambda_event_source_mapping", session)
    row = esm.items[0]
    assert esm.status == "collected" and row["id"] == "11111111-2222-3333-4444-555555555555" and row["FilterCount"] == 1
    assert row["SelfManagedEventSource"] == {"EndpointTypes": ["KAFKA_BOOTSTRAP_SERVERS"]}
    assert "Pattern" not in json.dumps(row) and "b-1:9092" not in json.dumps(row)


def test_alias_url_and_policy_are_cached_read_only_facts(stub):
    session, add = stub
    lam = add("lambda")
    lam.add_response("list_functions", {"Functions": [{"FunctionName": "app", "FunctionArn": FN}]})
    lam.add_response("list_aliases", {"Aliases": [{"AliasArn": FN + ":live", "Name": "live", "FunctionVersion": "3"}]},
                     {"FunctionName": "app"})
    lam.add_response("get_function_url_config", {"FunctionArn": FN + ":live", "AuthType": "NONE",
                     "FunctionUrl": "https://abc.lambda-url.us-east-1.on.aws/",
                     "CreationTime": "2026-01-01T00:00:00Z", "LastModifiedTime": "2026-01-01T00:00:00Z"},
                     {"FunctionName": "app", "Qualifier": "live"})
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
              "Action": ["lambda:InvokeFunctionUrl", "lambda:InvokeFunction"], "Resource": FN + ":live"}]}
    lam.add_response("get_policy", {"Policy": json.dumps(policy)}, {"FunctionName": "app", "Qualifier": "live"})
    read = run("lambda_alias", session)
    assert read.status == "collected"
    assert read.items[0]["FunctionUrl"]["FunctionArn"] == FN + ":live"
    assert read.items[0]["Policy"]["Policy"] == policy


def test_lambda_env_var_names_only_and_runtime_management(stub):
    session, add = stub
    lam = add("lambda")
    lam.add_response("get_function_configuration", {"FunctionName": "app", "Environment": {"Variables": {"DB_PASSWORD": "hunter2", "STAGE": "prod"}}},
                     {"FunctionName": "app"})
    lam.add_response("get_runtime_management_config", {"UpdateRuntimeOn": "Manual",
        "RuntimeVersionArn": f"arn:aws:lambda:{REGION}::runtime:abc"}, {"FunctionName": "app"})
    lam.add_response("get_function_configuration", {"FunctionName": "img"}, {"FunctionName": "img"})
    items = ext.ENRICHERS["lambda_function"](aws.Requests({}), session, REGION,
        [{"FunctionName": "app", "PackageType": "Zip"}, {"FunctionName": "img", "PackageType": "Image"}])
    assert items[0]["EnvironmentVariableNames"] == {"collection_status": "collected", "names": ["DB_PASSWORD", "STAGE"]}
    assert items[0]["RuntimeManagement"]["UpdateRuntimeOn"] == "Manual"
    assert "hunter2" not in json.dumps(items, default=str)
    assert items[1]["EnvironmentVariableNames"]["collection_status"] == "empty"
    assert items[1]["RuntimeManagement"]["reason"] == "container_image_function"


def test_lambda_env_names_denied(stub):
    session, add = stub
    lam = add("lambda")
    lam.add_client_error("get_function_configuration", "AccessDeniedException", expected_params={"FunctionName": "app"})
    lam.add_client_error("get_runtime_management_config", "AccessDeniedException", expected_params={"FunctionName": "app"})
    item = ext.ENRICHERS["lambda_function"](aws.Requests({}), session, REGION, [{"FunctionName": "app"}])[0]
    assert item["EnvironmentVariableNames"]["collection_status"] == "denied"
    assert item["RuntimeManagement"]["collection_status"] == "denied"


def test_ecr_registry_row(stub):
    session, add = stub
    ecr = add("ecr")
    ecr.add_response("describe_registry", {"registryId": ACCOUNT, "replicationConfiguration": {"rules": [
        {"destinations": [{"region": "eu-west-1", "registryId": OTHER}]}]}})
    ecr.add_client_error("get_registry_policy", "RegistryPolicyNotFoundException")
    ecr.add_response("describe_pull_through_cache_rules", {"pullThroughCacheRules": [{"ecrRepositoryPrefix": "hub",
        "upstreamRegistryUrl": "registry-1.docker.io", "credentialArn": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:ecr-pullthroughcache/x"}]})
    ecr.add_response("describe_repository_creation_templates", {"registryId": ACCOUNT, "repositoryCreationTemplates": [
        {"prefix": "ROOT", "repositoryPolicy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "ecr:*"}]})}]})
    read = run("ecr_registry", session)
    row = read.items[0]
    assert read.status == "collected" and row["id"] == f"ecr-registry/{ACCOUNT}/{REGION}"
    assert row["Replication"]["rules"][0]["destinations"][0]["registryId"] == OTHER
    assert row["RegistryPolicy"]["absent"] is True
    assert row["PullThroughCacheRules"]["items"][0]["ecrRepositoryPrefix"] == "hub"
    assert row["RepositoryCreationTemplates"]["items"][0]["repositoryPolicy"]["Statement"][0]["Principal"] == "*"


def test_ecr_registry_all_denied(stub):
    session, add = stub
    ecr = add("ecr")
    for op in ("describe_registry", "get_registry_policy", "describe_pull_through_cache_rules", "describe_repository_creation_templates"):
        ecr.add_client_error(op, "AccessDeniedException")
    read = run("ecr_registry", session)
    assert read.status == "denied" and read.items == []


def test_eks_access_entries_and_config_map_cluster(stub):
    session, add = stub
    eks = add("eks")
    eks.add_response("list_clusters", {"clusters": ["prod", "legacy"]})
    principal = f"arn:aws:iam::{OTHER}:role/ext"
    eks.add_response("list_access_entries", {"accessEntries": [principal]}, {"clusterName": "prod"})
    eks.add_response("describe_access_entry", {"accessEntry": {"clusterName": "prod", "principalArn": principal, "type": "STANDARD",
        "kubernetesGroups": ["system:masters"], "accessEntryArn": "arn:aws:eks:us-east-1:123456789012:access-entry/prod/role/x"}},
        {"clusterName": "prod", "principalArn": principal})
    eks.add_response("list_associated_access_policies", {"clusterName": "prod", "principalArn": principal, "associatedAccessPolicies": [
        {"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy", "accessScope": {"type": "cluster"}}]},
        {"clusterName": "prod", "principalArn": principal})
    eks.add_client_error("list_access_entries", "InvalidRequestException", expected_params={"clusterName": "legacy"})
    read = run("eks_access_entry", session)
    assert read.status == "collected" and len(read.items) == 1
    row = read.items[0]
    assert row["type"] == "STANDARD" and row["kubernetesGroups"] == ["system:masters"]
    assert row["AssociatedAccessPolicies"]["items"][0]["policyArn"].endswith("AmazonEKSClusterAdminPolicy")


def test_eks_pod_identity_roles(stub):
    session, add = stub
    eks = add("eks")
    eks.add_response("list_clusters", {"clusters": ["prod"]})
    eks.add_response("list_pod_identity_associations", {"associations": [{"clusterName": "prod", "namespace": "ns", "serviceAccount": "sa",
        "associationId": "a-1", "associationArn": "arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod/a-1"}]}, {"clusterName": "prod"})
    eks.add_response("describe_pod_identity_association", {"association": {"roleArn": f"arn:aws:iam::{ACCOUNT}:role/pod", "externalId": "x"}},
                     {"clusterName": "prod", "associationId": "a-1"})
    read = run("eks_pod_identity_association", session)
    assert read.items[0]["roleArn"].endswith("role/pod") and "externalId" not in read.items[0]


def test_kms_grants_customer_keys_only_constraint_keys(stub):
    session, add = stub
    kms = add("kms")
    kms.add_response("list_keys", {"Keys": [{"KeyId": "k1", "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/k1"}, {"KeyId": "k2"}]})
    kms.add_response("describe_key", {"KeyMetadata": {"KeyId": "k1", "KeyManager": "CUSTOMER"}}, {"KeyId": "k1"})
    kms.add_response("list_grants", {"Grants": [{"KeyId": "k1", "GrantId": "g1", "GranteePrincipal": f"arn:aws:iam::{OTHER}:root",
        "Operations": ["Decrypt"], "Constraints": {"EncryptionContextEquals": {"tenant": "secret-tenant"}}}]}, {"KeyId": "k1"})
    kms.add_response("describe_key", {"KeyMetadata": {"KeyId": "k2", "KeyManager": "AWS"}}, {"KeyId": "k2"})
    read = run("kms_grant", session)
    assert read.status == "collected" and len(read.items) == 1
    assert read.items[0]["ConstraintKeys"] == {"EncryptionContextEquals": ["tenant"]}
    assert "secret-tenant" not in json.dumps(read.items)


def test_cognito_enrichers(stub):
    session, add = stub
    ident, idp = add("cognito-identity"), add("cognito-idp")
    ident.add_response("get_identity_pool_roles", {"IdentityPoolId": "us-east-1:p", "Roles": {"authenticated": f"arn:aws:iam::{ACCOUNT}:role/auth"}},
                       {"IdentityPoolId": "us-east-1:p"})
    pools = ext.ENRICHERS["cognito_identity_pool"](aws.Requests({}), session, REGION, [{"IdentityPoolId": "us-east-1:p"}])
    assert pools[0]["Roles"]["Roles"]["authenticated"].endswith("role/auth")
    idp.add_response("list_identity_providers", {"Providers": [{"ProviderName": "Google", "ProviderType": "Google"}]},
                     {"UserPoolId": "us-east-1_X", "MaxResults": 60})
    idp.add_response("get_user_pool_mfa_config", {"MfaConfiguration": "OPTIONAL", "SoftwareTokenMfaConfiguration": {"Enabled": True},
        "SmsMfaConfiguration": {"SmsConfiguration": {"SnsCallerArn": "arn:aws:iam::123456789012:role/sns", "ExternalId": "secret-ext"}}},
        {"UserPoolId": "us-east-1_X"})
    idp.add_response("list_groups", {"Groups": [{"GroupName": "admins", "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/admin", "Precedence": 1}]},
                     {"UserPoolId": "us-east-1_X"})
    item = ext.ENRICHERS["cognito_user_pool"](aws.Requests({}), session, REGION, [{"Id": "us-east-1_X"}])[0]
    assert item["IdentityProviders"]["items"] == [{"ProviderName": "Google", "ProviderType": "Google"}]
    assert item["MfaConfig"]["MfaConfiguration"] == "OPTIONAL" and item["MfaConfig"]["SmsMfaConfigured"] is True
    assert item["Groups"]["items"][0]["RoleArn"].endswith("role/admin")
    assert "secret-ext" not in json.dumps(item)


def test_opensearch_connections_both_directions(stub):
    session, add = stub
    os_ = add("opensearch")
    remote = {"AWSDomainInformation": {"OwnerId": OTHER, "DomainName": "far", "Region": REGION}}
    local = {"AWSDomainInformation": {"OwnerId": ACCOUNT, "DomainName": "near", "Region": REGION}}
    os_.add_response("describe_outbound_connections", {"Connections": [{"ConnectionId": "cc-connection1", "LocalDomainInfo": local,
        "RemoteDomainInfo": remote, "ConnectionStatus": {"StatusCode": "ACTIVE"}}]})
    os_.add_response("describe_inbound_connections", {"Connections": []})
    read = run("opensearch_connection", session)
    assert read.status == "collected" and read.items[0]["Direction"] == "outbound" and read.items[0]["StatusCode"] == "ACTIVE"


def test_route53_records_keep_values_only_for_address_types(stub):
    session, add = stub
    r53 = add("route53")
    r53.add_response("list_hosted_zones", {"HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com.", "CallerReference": "c",
        "Config": {"PrivateZone": False}}], "IsTruncated": False, "Marker": "", "MaxItems": "100"})
    r53.add_response("list_resource_record_sets", {"ResourceRecordSets": [
        {"Name": "www.example.com.", "Type": "CNAME", "TTL": 60, "ResourceRecords": [{"Value": "bucket.s3-website-us-east-1.amazonaws.com"}]},
        {"Name": "example.com.", "Type": "TXT", "TTL": 60, "ResourceRecords": [{"Value": "\"google-site-verification=secret\""}]}],
        "IsTruncated": False, "MaxItems": "100"}, {"HostedZoneId": "/hostedzone/Z1"})
    read = run("route53_record_set", session)
    cname, txt = read.items
    assert cname["Values"] == ["bucket.s3-website-us-east-1.amazonaws.com"] and txt["ValueCount"] == 1
    assert "google-site-verification" not in json.dumps(read.items)


def test_stack_instances_and_instance_connect_endpoints(stub):
    session, add = stub
    cfn, ec2 = add("cloudformation"), add("ec2")
    cfn.add_response("list_stack_sets", {"Summaries": [{"StackSetName": "base", "StackSetId": "base:1", "PermissionModel": "SERVICE_MANAGED"}]},
                     {"Status": "ACTIVE"})
    cfn.add_response("list_stack_instances", {"Summaries": [{"StackSetId": "base:1", "Account": OTHER, "Region": REGION, "Status": "CURRENT"}]},
                     {"StackSetName": "base"})
    read = run("cloudformation_stack_instance", session)
    assert read.items[0]["Account"] == OTHER and read.items[0]["PermissionModel"] == "SERVICE_MANAGED"
    ec2.add_response("describe_instance_connect_endpoints", {"InstanceConnectEndpoints": [{"InstanceConnectEndpointId": "eice-1",
        "VpcId": "vpc-1", "SubnetId": "subnet-1", "PreserveClientIp": True, "SecurityGroupIds": ["sg-1"]}]})
    read = run("ec2_instance_connect_endpoint", session)
    assert read.items[0]["id"] == "eice-1" and read.items[0]["PreserveClientIp"] is True


def test_rolesanywhere_profiles(stub):
    session, add = stub
    ra = add("rolesanywhere")
    arn = f"arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:profile/11111111-2222-3333-4444-555555555555"
    ra.add_response("list_profiles", {"profiles": [{"profileArn": arn, "profileId": "11111111-2222-3333-4444-555555555555", "enabled": True,
        "roleArns": [f"arn:aws:iam::{ACCOUNT}:role/edge"], "sessionPolicy": json.dumps({"Statement": []})}]})
    read = run("rolesanywhere_profile", session)
    assert read.items[0]["id"] == arn and read.items[0]["roleArns"] == [f"arn:aws:iam::{ACCOUNT}:role/edge"]
    assert read.items[0]["SessionPolicy"] == {"Statement": []}


def test_image_pipelines_join_instance_profile(stub):
    session, add = stub
    ib = add("imagebuilder")
    infra = f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:infrastructure-configuration/i"
    ib.add_response("list_image_pipelines", {"imagePipelineList": [{"arn": f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:image-pipeline/p",
        "name": "p", "infrastructureConfigurationArn": infra}]})
    ib.add_response("list_infrastructure_configurations", {"infrastructureConfigurationSummaryList": [{"arn": infra, "instanceProfileName": "builder"}]})
    read = run("imagebuilder_pipeline", session)
    assert read.status == "collected" and read.items[0]["InstanceProfileName"] == "builder"


def test_image_pipelines_keep_recipe_component_arns_only(stub):
    session, add = stub
    ib = add("imagebuilder")
    recipe = f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:image-recipe/r/1.0.0"
    component = f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:component/app/1.x.x"
    pipelines = [{"arn": f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:image-pipeline/{n}", "name": n, "imageRecipeArn": recipe} for n in ("p", "q")]
    ib.add_response("list_image_pipelines", {"imagePipelineList": pipelines})
    ib.add_response("list_infrastructure_configurations", {"infrastructureConfigurationSummaryList": []})
    ib.add_response("get_image_recipe", {"imageRecipe": {"arn": recipe, "name": "r", "parentImage": "ami-1", "components": [
        {"componentArn": component, "parameters": [{"name": "secret", "value": ["v"]}]}],
        "additionalInstanceConfiguration": {"userDataOverride": "IyEvYmluL3NoCmVjaG8gc2VjcmV0"}}}, {"imageRecipeArn": recipe})
    read = run("imagebuilder_pipeline", session)  # one GetImageRecipe per distinct recipe
    assert [i["RecipeComponents"] for i in read.items] == [{"collection_status": "collected", "items": [component]}] * 2
    assert "secret" not in str(read.items) and "userDataOverride" not in str(read.items) and "IyEv" not in str(read.items)


def test_image_recipe_denied_keeps_its_status(stub):
    session, add = stub
    ib = add("imagebuilder")
    recipe = f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:image-recipe/r/1.0.0"
    ib.add_response("list_image_pipelines", {"imagePipelineList": [{"arn": f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:image-pipeline/p",
                                                                    "imageRecipeArn": recipe}]})
    ib.add_response("list_infrastructure_configurations", {"infrastructureConfigurationSummaryList": []})
    ib.add_client_error("get_image_recipe", "AccessDeniedException", http_status_code=403)
    read = run("imagebuilder_pipeline", session)
    assert read.items[0]["RecipeComponents"]["collection_status"] == "denied" and "items" not in read.items[0]["RecipeComponents"]


def test_sagemaker_user_profiles_domain_default_and_clusters(stub):
    session, add = stub
    sm = add("sagemaker")
    sm.add_response("list_user_profiles", {"UserProfiles": [{"DomainId": "d-1", "UserProfileName": "alice"}]})
    sm.add_response("describe_user_profile", {"DomainId": "d-1", "UserProfileName": "alice",
        "UserProfileArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:user-profile/d-1/alice", "UserSettings": {}},
        {"DomainId": "d-1", "UserProfileName": "alice"})
    sm.add_response("describe_domain", {"DomainId": "d-1", "DefaultUserSettings": {"ExecutionRole": f"arn:aws:iam::{ACCOUNT}:role/sm"}},
                    {"DomainId": "d-1"})
    read = run("sagemaker_user_profile", session)
    assert read.items[0]["ExecutionRole"].endswith("role/sm") and read.items[0]["ExecutionRoleSource"] == "domain_default"
    sm.add_response("list_clusters", {"ClusterSummaries": [{"ClusterArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:cluster/c", "ClusterName": "c",
        "ClusterStatus": "InService", "CreationTime": "2026-01-01T00:00:00Z"}]})
    sm.add_response("describe_cluster", {"ClusterArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:cluster/c", "ClusterStatus": "InService",
        "InstanceGroups": [{"InstanceGroupName": "g", "ExecutionRole": f"arn:aws:iam::{ACCOUNT}:role/hp"}]}, {"ClusterName": "c"})
    read = run("sagemaker_cluster", session)
    assert read.items[0]["InstanceGroups"][0]["ExecutionRole"].endswith("role/hp")


def test_sagemaker_spaces_join_shared_and_private_execution_roles(stub):
    session, add = stub
    sm = add("sagemaker")
    shared_arn = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:space/d-example/shared"
    private_arn = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:space/d-example/private"
    shared_role = f"arn:aws:iam::{ACCOUNT}:role/shared-space"
    private_role = f"arn:aws:iam::{ACCOUNT}:role/owner"
    sm.add_response("list_spaces", {"Spaces": [
        {"DomainId": "d-example", "SpaceName": "shared"},
        {"DomainId": "d-example", "SpaceName": "private"}]})
    sm.add_response("describe_space", {"DomainId": "d-example", "SpaceName": "shared", "SpaceArn": shared_arn,
        "Status": "InService", "SpaceSettings": {"AppType": "JupyterLab"},
        "SpaceSharingSettings": {"SharingType": "Shared"}},
        {"DomainId": "d-example", "SpaceName": "shared"})
    sm.add_response("describe_domain", {"DomainId": "d-example", "DefaultSpaceSettings": {"ExecutionRole": shared_role}},
        {"DomainId": "d-example"})
    sm.add_response("describe_space", {"DomainId": "d-example", "SpaceName": "private", "SpaceArn": private_arn,
        "Status": "InService", "SpaceSettings": {"AppType": "CodeEditor"},
        "SpaceSharingSettings": {"SharingType": "Private"},
        "OwnershipSettings": {"OwnerUserProfileName": "alice"}},
        {"DomainId": "d-example", "SpaceName": "private"})
    sm.add_response("describe_user_profile", {"DomainId": "d-example", "UserProfileName": "alice",
        "UserSettings": {"ExecutionRole": private_role}},
        {"DomainId": "d-example", "UserProfileName": "alice"})
    read = run("sagemaker_space", session)
    assert read.status == "collected"
    assert [(r["SpaceArn"], r["ExecutionRole"], r["ExecutionRoleSource"]) for r in read.items] == [
        (shared_arn, shared_role, "domain_default_space"),
        (private_arn, private_role, "owner_user_settings")]


def test_sagemaker_space_denied_detail_does_not_infer_role(stub):
    session, add = stub
    sm = add("sagemaker")
    sm.add_response("list_spaces", {"Spaces": [{"DomainId": "d-example", "SpaceName": "private"}]})
    sm.add_client_error("describe_space", "AccessDeniedException", http_status_code=403,
                        expected_params={"DomainId": "d-example", "SpaceName": "private"})
    read = run("sagemaker_space", session)
    assert read.status == "partial"
    assert "ExecutionRole" not in read.items[0]
    assert read.items[0]["_coverage"]["SpaceDetails"]["source_operation"] == "sagemaker:DescribeSpace"


def test_service_planes_drop_secrets(stub):
    session, add = stub
    graf, qs, scn, amp = add("grafana"), add("quicksight"), add("supplychain"), add("amplify")
    graf.add_response("list_workspaces", {"workspaces": [{"id": "g-1", "name": "ops", "status": "ACTIVE", "authentication": {"providers": ["SAML"]},
        "endpoint": "g-1.grafana", "grafanaVersion": "10", "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
        "grafanaToken": "glsa_secret"}]})
    read = run("grafana_workspace", session)
    assert read.items[0]["Arn"] == f"arn:aws:grafana:{REGION}:{ACCOUNT}:/workspaces/g-1" and "glsa_secret" not in json.dumps(read.items, default=str)
    qs.add_response("list_users", {"UserList": [{"Arn": f"arn:aws:quicksight:{REGION}:{ACCOUNT}:user/default/bob", "Role": "ADMIN",
        "Email": "bob@example.com", "IdentityType": "IAM", "Active": True,
        "CustomPermissionsName": "restricted"}]}, {"AwsAccountId": ACCOUNT, "Namespace": "default"})
    read = run("quicksight_user", session)
    assert read.items[0]["Role"] == "ADMIN" and read.items[0]["CustomPermissionsName"] == "restricted"
    assert "bob@example.com" not in json.dumps(read.items)
    scn.add_response("list_instances", {"instances": [{"instanceId": "11111111-2222-3333-4444-555555555555", "awsAccountId": ACCOUNT, "state": "Active"}]})
    read = run("supplychain_instance", session)
    assert read.items[0]["Arn"] == f"arn:aws:scn:{REGION}:{ACCOUNT}:instance/11111111-2222-3333-4444-555555555555"
    amp.add_response("list_apps", {"apps": [{"appId": "a1", "appArn": f"arn:aws:amplify:{REGION}:{ACCOUNT}:apps/a1", "name": "web",
        "description": "", "repository": "", "platform": "WEB", "createTime": "2026-01-01T00:00:00Z", "updateTime": "2026-01-01T00:00:00Z",
        "environmentVariables": {"API_KEY": "sk_live_secret"}, "defaultDomain": "a1.amplifyapp.com", "enableBranchAutoBuild": False,
        "enableBasicAuth": True, "basicAuthCredentials": "dXNlcjpwYXNz", "buildSpec": "secret-build"}]})
    amp.add_response("list_backend_environments", {"backendEnvironments": [{"backendEnvironmentArn": "arn:aws:amplify:us-east-1:123456789012:apps/a1/backendenvironments/dev",
        "environmentName": "dev", "createTime": "2026-01-01T00:00:00Z", "updateTime": "2026-01-01T00:00:00Z"}]}, {"appId": "a1"})
    amp.add_response("list_branches", {"branches": [{"branchArn": f"arn:aws:amplify:{REGION}:{ACCOUNT}:apps/a1/branches/main",
        "branchName": "main", "description": "", "displayName": "main", "stage": "PRODUCTION",
        "enableAutoBuild": True, "enableNotification": False, "createTime": "2026-01-01T00:00:00Z",
        "updateTime": "2026-01-01T00:00:00Z", "customDomains": [], "framework": "React",
        "activeJobId": "1", "totalNumberOfJobs": "1", "enableBasicAuth": False,
        "ttl": "5", "enablePullRequestPreview": False,
        "environmentVariables": {"TOKEN": "branch-secret"}, "buildSpec": "branch-secret-build"}]}, {"appId": "a1"})
    amp.add_response("list_domain_associations", {"domainAssociations": [{
        "domainAssociationArn": f"arn:aws:amplify:{REGION}:{ACCOUNT}:apps/a1/domains/example.com",
        "domainName": "example.com", "enableAutoSubDomain": False, "domainStatus": "AVAILABLE", "statusReason": "",
        "subDomains": [{"subDomainSetting": {"prefix": "www", "branchName": "main"},
                        "verified": True, "dnsRecord": "www CNAME target"}]}]}, {"appId": "a1"})
    read = run("amplify_app", session)
    dumped = json.dumps(read.items, default=str)
    assert read.items[0]["BackendEnvironments"]["items"][0]["environmentName"] == "dev"
    assert read.items[0]["Branches"]["items"][0]["branchName"] == "main"
    assert read.items[0]["Branches"]["items"][0]["enableBasicAuth"] is False
    assert read.items[0]["DomainAssociations"]["items"][0]["subDomains"][0]["subDomainSetting"]["prefix"] == "www"
    assert read.items[0]["RepositoryConnected"] is False
    assert read.items[0]["AppBuildSpecPresent"] is True
    assert read.items[0]["Branches"]["items"][0]["BranchBuildSpecPresent"] is True
    assert "sk_live_secret" not in dumped and "dXNlcjpwYXNz" not in dumped and "secret-build" not in dumped
    assert "branch-secret" not in dumped


def test_amplify_app_without_build_spec_does_not_claim_one(stub):
    session, add = stub
    amp = add("amplify")
    amp.add_response("list_apps", {"apps": [{
        "appId": "a2", "appArn": f"arn:aws:amplify:{REGION}:{ACCOUNT}:apps/a2",
        "name": "plain", "description": "", "repository": "", "platform": "WEB",
        "createTime": "2026-01-01T00:00:00Z", "updateTime": "2026-01-01T00:00:00Z",
        "environmentVariables": {}, "defaultDomain": "a2.amplifyapp.com",
        "enableBranchAutoBuild": False, "enableBasicAuth": False,
    }]})
    amp.add_response("list_backend_environments", {"backendEnvironments": []}, {"appId": "a2"})
    amp.add_response("list_branches", {"branches": []}, {"appId": "a2"})
    amp.add_response("list_domain_associations", {"domainAssociations": []}, {"appId": "a2"})
    read = run("amplify_app", session)
    assert read.items[0]["AppBuildSpecPresent"] is False
    assert "buildSpec" not in json.dumps(read.items, default=str)


def test_quicksight_not_subscribed_is_empty(stub):
    session, add = stub
    add("quicksight").add_client_error("list_users", "ResourceNotFoundException", expected_params={"AwsAccountId": ACCOUNT, "Namespace": "default"})
    read = run("quicksight_user", session)
    assert read.status == "empty"


def test_identity_center_account_assignments_with_group_names(stub):
    session, add = stub
    sso, store = add("sso-admin"), add("identitystore")
    inst = "arn:aws:sso:::instance/ssoins-1"
    ps = "arn:aws:sso:::permissionSet/ssoins-1/ps-1"
    sso.add_response("list_instances", {"Instances": [{"InstanceArn": inst, "IdentityStoreId": "d-1", "OwnerAccountId": ACCOUNT}]})
    group = {"GroupId": "g-1", "DisplayName": "Admins", "IdentityStoreId": "d-1"}
    # Newer botocore models require GroupArn/Revision in list_groups responses; older ones reject them.
    members = store.client.meta.service_model.shape_for("Group").members
    group.update({k: v for k, v in {"GroupArn": "arn:aws:identitystore:::group/11111111-2222-3333-4444-555555555555",
                                    "Revision": "1"}.items() if k in members})
    store.add_response("list_groups", {"Groups": [group]}, {"IdentityStoreId": "d-1"})
    sso.add_response("list_permission_sets", {"PermissionSets": [ps]}, {"InstanceArn": inst})
    sso.add_response("list_accounts_for_provisioned_permission_set", {"AccountIds": [OTHER]}, {"InstanceArn": inst, "PermissionSetArn": ps})
    sso.add_response("list_account_assignments", {"AccountAssignments": [{"AccountId": OTHER, "PermissionSetArn": ps, "PrincipalType": "GROUP",
        "PrincipalId": "g-1"}]}, {"InstanceArn": inst, "AccountId": OTHER, "PermissionSetArn": ps})
    read = run("aws_identity_center_account_assignment", session)
    assert read.status == "collected" and read.items[0]["GroupDisplayName"] == "Admins" and read.items[0]["AccountId"] == OTHER


def test_identity_center_partial_on_assignment_denied(stub):
    session, add = stub
    sso = add("sso-admin")
    inst = "arn:aws:sso:::instance/ssoins-1"
    ps = "arn:aws:sso:::permissionSet/ssoins-1/ps-1"
    sso.add_response("list_instances", {"Instances": [{"InstanceArn": inst}]})
    sso.add_response("list_permission_sets", {"PermissionSets": [ps, ps + "b"]}, {"InstanceArn": inst})
    sso.add_response("list_accounts_for_provisioned_permission_set", {"AccountIds": [ACCOUNT]}, {"InstanceArn": inst, "PermissionSetArn": ps})
    sso.add_response("list_account_assignments", {"AccountAssignments": [{"AccountId": ACCOUNT, "PermissionSetArn": ps, "PrincipalType": "USER",
        "PrincipalId": "u-1"}]}, {"InstanceArn": inst, "AccountId": ACCOUNT, "PermissionSetArn": ps})
    sso.add_client_error("list_accounts_for_provisioned_permission_set", "AccessDeniedException",
                         expected_params={"InstanceArn": inst, "PermissionSetArn": ps + "b"})
    read = run("aws_identity_center_account_assignment", session)
    assert read.status == "partial" and read.error["cause_status"] == "denied" and len(read.items) == 1
