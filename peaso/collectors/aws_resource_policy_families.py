"""Reviewed read-only policy discovery recipes. No dynamic API-name guessing.

Each path is checked against the pinned Botocore models by the coverage tests.
Only policy documents and resource identities leave this collector.
"""
from dataclasses import dataclass
import json
from urllib.parse import unquote

import jmespath


@dataclass(frozen=True)
class Recipe:
    id: str
    service: str
    steps: tuple
    operation: str | None
    parameters: dict
    document: str
    resource: str
    region: str | None = None
    absent: tuple = ()
    normalizer: str | None = None


def step(operation, path, **parameters):
    return operation, path, parameters


def recipe(id, service, listing, path, operation, parameter, identity, document="Policy", resource="$Arn", *, parameters=None, region=None, absent=()):
    return Recipe(id, service, (step(listing, path, **(parameters or {})),), operation,
                  {parameter: identity} if parameter else {}, document, resource, region, absent)


# ARN/name selectors are intentionally explicit: identical API names do not
# imply identical resource semantics. Global APIs use their supported endpoint.
RECIPES = [
    recipe("s3-buckets", "s3", "list_buckets", "Buckets", "get_bucket_policy", "Bucket", "$Name", resource="arn:{partition}:s3:::{Name}", absent=("NoSuchBucketPolicy",)),
    recipe("s3-directory-buckets", "s3", "list_directory_buckets", "Buckets", "get_bucket_policy", "Bucket", "$Name", resource="arn:{partition}:s3express:{region}:{account}:bucket/{Name}", absent=("NoSuchBucketPolicy",)),
    recipe("s3-access-points", "s3control", "list_access_points", "AccessPointList", "get_access_point_policy", "Name", "$Name", resource="$AccessPointArn", parameters={"AccountId": "{account}"}, absent=("NoSuchAccessPointPolicy",)),
    recipe("s3-directory-access-points", "s3control", "list_access_points_for_directory_buckets", "AccessPointList", "get_access_point_policy", "Name", "$Name", resource="$AccessPointArn", parameters={"AccountId": "{account}"}, absent=("NoSuchAccessPointPolicy",)),
    recipe("s3-object-lambda-access-points", "s3control", "list_access_points_for_object_lambda", "ObjectLambdaAccessPointList", "get_access_point_policy_for_object_lambda", "Name", "$Name", resource="$ObjectLambdaAccessPointArn", parameters={"AccountId": "{account}"}, absent=("NoSuchAccessPointPolicy",)),
    recipe("s3-multi-region-access-points", "s3control", "list_multi_region_access_points", "AccessPoints", "get_multi_region_access_point_policy", "Name", "$Name", "Policy.Established.Document", "arn:{partition}:s3::{account}:accesspoint/{Alias}", parameters={"AccountId": "{account}"}, region="us-west-2", absent=("NoSuchMultiRegionAccessPointPolicy",)),
    recipe("s3-outposts-buckets", "s3control", "list_regional_buckets", "RegionalBucketList", "get_bucket_policy", "Bucket", "$BucketArn", resource="$BucketArn", parameters={"AccountId": "{account}"}, absent=("NoSuchBucketPolicy",)),
    recipe("s3-access-grants", "s3control", "list_access_grants_instances", "AccessGrantsInstancesList", "get_access_grants_instance_resource_policy", None, None, resource="$AccessGrantsInstanceArn", parameters={"AccountId": "{account}"}, absent=("NoSuchAccessGrantsInstancePolicy",)),
    recipe("s3-tables", "s3tables", "list_table_buckets", "tableBuckets", "get_table_bucket_policy", "tableBucketARN", "$arn", "resourcePolicy", "$arn", absent=("NotFoundException",)),
    recipe("s3-vectors", "s3vectors", "list_vector_buckets", "vectorBuckets", "get_vector_bucket_policy", "vectorBucketArn", "$vectorBucketArn", "policy", "$vectorBucketArn", absent=("NotFoundException",)),
    recipe("s3-files", "s3files", "list_file_systems", "fileSystems", "get_file_system_policy", "fileSystemId", "$fileSystemId", "policy", "$fileSystemArn", absent=("PolicyNotFound",)),
    recipe("kms-keys", "kms", "list_keys", "Keys", "get_key_policy", "KeyId", "$KeyId", resource="$KeyArn"),
    recipe("secrets", "secretsmanager", "list_secrets", "SecretList", "get_resource_policy", "SecretId", "$ARN", "ResourcePolicy", "$ARN"),
    recipe("efs-filesystems", "efs", "describe_file_systems", "FileSystems", "describe_file_system_policy", "FileSystemId", "$FileSystemId", resource="$FileSystemArn", absent=("PolicyNotFound",)),
    recipe("backup-vaults", "backup", "list_backup_vaults", "BackupVaultList", "get_backup_vault_access_policy", "BackupVaultName", "$BackupVaultName", resource="$BackupVaultArn", absent=("ResourceNotFoundException",)),
    recipe("private-ca", "acm-pca", "list_certificate_authorities", "CertificateAuthorities", "get_policy", "ResourceArn", "$Arn", resource="$Arn", absent=("ResourceNotFoundException",)),
    recipe("kinesis-streams", "kinesis", "list_streams", "StreamSummaries", "get_resource_policy", "ResourceARN", "$StreamARN", resource="$StreamARN", absent=("ResourceNotFoundException",)),
    recipe("eventbridge-buses", "events", "list_event_buses", "EventBuses", "describe_event_bus", "Name", "$Name", resource="$Arn"),
    recipe("eventbridge-schemas", "schemas", "list_registries", "Registries", "get_resource_policy", "RegistryName", "$RegistryName", resource="$RegistryArn", absent=("NotFoundException",)),
    recipe("codeartifact-domains", "codeartifact", "list_domains", "domains", "get_domain_permissions_policy", "domain", "$name", "policy.document", "$arn", absent=("ResourceNotFoundException",)),
    recipe("codeartifact-repositories", "codeartifact", "list_repositories", "repositories", "get_repository_permissions_policy", "repository", "$name", "policy.document", "$arn", absent=("ResourceNotFoundException",)),
    recipe("codebuild-projects", "codebuild", "list_projects", "projects", "get_resource_policy", "resourceArn", "arn:{partition}:codebuild:{region}:{account}:project/{value}", "policy", "arn:{partition}:codebuild:{region}:{account}:project/{value}", absent=("ResourceNotFoundException",)),
    recipe("codebuild-report-groups", "codebuild", "list_report_groups", "reportGroups", "get_resource_policy", "resourceArn", "$value", "policy", "$value", absent=("ResourceNotFoundException",)),
    recipe("cloudtrail-channels", "cloudtrail", "list_channels", "Channels", "get_resource_policy", "ResourceArn", "$ChannelArn", "ResourcePolicy", "$ChannelArn", absent=("ResourcePolicyNotFoundException",)),
    recipe("cloudtrail-event-stores", "cloudtrail", "list_event_data_stores", "EventDataStores", "get_resource_policy", "ResourceArn", "$EventDataStoreArn", "ResourcePolicy", "$EventDataStoreArn", absent=("ResourcePolicyNotFoundException",)),
    recipe("public-ecr-repositories", "ecr-public", "describe_repositories", "repositories", "get_repository_policy", "repositoryName", "$repositoryName", "policyText", "$repositoryArn", region="us-east-1", absent=("RepositoryPolicyNotFoundException",)),
    recipe("prometheus-workspaces", "amp", "list_workspaces", "workspaces", "describe_resource_policy", "workspaceId", "$workspaceId", "policyDocument", "$arn", absent=("ResourceNotFoundException",)),
    recipe("observability-sinks", "oam", "list_sinks", "Items", "get_sink_policy", "SinkIdentifier", "$Arn", resource="$Arn", absent=("ResourceNotFoundException",)),
    recipe("rum-monitors", "rum", "list_app_monitors", "AppMonitorSummaries", "get_resource_policy", "Name", "$Name", "PolicyDocument", "arn:{partition}:rum:{region}:{account}:appmonitor/{Name}", absent=("ResourceNotFoundException",)),
    recipe("refactor-environments", "migration-hub-refactor-spaces", "list_environments", "EnvironmentSummaryList", "get_resource_policy", "Identifier", "$Arn", resource="$Arn", absent=("ResourceNotFoundException",)),
    recipe("network-firewall-rule-groups", "network-firewall", "list_rule_groups", "RuleGroups", "describe_resource_policy", "ResourceArn", "$Arn", resource="$Arn", absent=("ResourceNotFoundException",)),
    recipe("network-firewall-policies", "network-firewall", "list_firewall_policies", "FirewallPolicies", "describe_resource_policy", "ResourceArn", "$Arn", resource="$Arn", absent=("ResourceNotFoundException",)),
    recipe("core-networks", "networkmanager", "list_core_networks", "CoreNetworks", "get_resource_policy", "ResourceArn", "$CoreNetworkArn", "PolicyDocument", "$CoreNetworkArn", region="us-west-2", absent=("ResourceNotFoundException",)),
    recipe("osis-pipelines", "osis", "list_pipelines", "Pipelines", "get_resource_policy", "ResourceArn", "$PipelineArn", resource="$PipelineArn", absent=("ResourceNotFoundException",)),
    recipe("payment-keys", "payment-cryptography", "list_keys", "Keys", "get_resource_policy", "ResourceArn", "$KeyArn", resource="$KeyArn", absent=("ResourceNotFoundException",)),
    recipe("incident-response-plans", "ssm-incidents", "list_response_plans", "responsePlanSummaries", "get_resource_policies", "resourceArn", "$arn", "resourcePolicies[].policyDocument", "$arn", absent=("ResourceNotFoundException",)),
    recipe("incident-contacts", "ssm-contacts", "list_contacts", "Contacts", "get_contact_policy", "ContactArn", "$ContactArn", resource="$ContactArn", absent=("ResourceNotFoundException",)),
    recipe("ssm-parameters", "ssm", "describe_parameters", "Parameters", "get_resource_policies", "ResourceArn", "$ARN", "Policies[].Policy", "$ARN"),
    recipe("lattice-service-networks", "vpc-lattice", "list_service_networks", "items", "get_resource_policy", "resourceArn", "$arn", "policy", "$arn", absent=("ResourceNotFoundException",)),
    recipe("lattice-services", "vpc-lattice", "list_services", "items", "get_resource_policy", "resourceArn", "$arn", "policy", "$arn", absent=("ResourceNotFoundException",)),
    recipe("lattice-resources", "vpc-lattice", "list_resource_configurations", "items", "get_resource_policy", "resourceArn", "$arn", "policy", "$arn", absent=("ResourceNotFoundException",)),
    recipe("ses-identities", "sesv2", "list_email_identities", "EmailIdentities", "get_email_identity_policies", "EmailIdentity", "$IdentityName", "Policies.*", "arn:{partition}:ses:{region}:{account}:identity/{IdentityName}"),
    recipe("entity-id-namespaces", "entityresolution", "list_id_namespaces", "idNamespaceSummaries", "get_policy", "arn", "$idNamespaceArn", "policy", "$idNamespaceArn", absent=("ResourceNotFoundException",)),
    recipe("entity-id-mapping", "entityresolution", "list_id_mapping_workflows", "workflowSummaries", "get_policy", "arn", "$workflowArn", "policy", "$workflowArn", absent=("ResourceNotFoundException",)),
    recipe("redshift-namespaces", "redshift-serverless", "list_namespaces", "namespaces", "get_resource_policy", "resourceArn", "$namespaceArn", "resourcePolicy.policy", "$namespaceArn", absent=("ResourceNotFoundException",)),
    recipe("redshift-snapshots", "redshift-serverless", "list_snapshots", "snapshots", "get_resource_policy", "resourceArn", "$snapshotArn", "resourcePolicy.policy", "$snapshotArn", absent=("ResourceNotFoundException",)),
    recipe("redshift-cluster-namespaces", "redshift", "describe_clusters", "Clusters", "get_resource_policy", "ResourceArn", "$ClusterNamespaceArn", "ResourcePolicy.Policy", "$ClusterNamespaceArn", absent=("ResourceNotFoundFault",)),
    recipe("arc-clusters", "route53-recovery-control-config", "list_clusters", "Clusters", "get_resource_policy", "ResourceArn", "$ClusterArn", resource="$ClusterArn", region="us-west-2", absent=("ResourceNotFoundException",)),
    recipe("comprehend-classifiers", "comprehend", "list_document_classifiers", "DocumentClassifierPropertiesList", "describe_resource_policy", "ResourceArn", "$DocumentClassifierArn", "ResourcePolicy", "$DocumentClassifierArn", absent=("ResourceNotFoundException",)),
    recipe("comprehend-recognizers", "comprehend", "list_entity_recognizers", "EntityRecognizerPropertiesList", "describe_resource_policy", "ResourceArn", "$EntityRecognizerArn", "ResourcePolicy", "$EntityRecognizerArn", absent=("ResourceNotFoundException",)),
    recipe("lookout-models", "lookoutequipment", "list_models", "ModelSummaries", "describe_resource_policy", "ResourceArn", "$ModelArn", "ResourcePolicy", "$ModelArn", absent=("ResourceNotFoundException",)),
    recipe("bedrock-custom-models", "bedrock", "list_custom_models", "modelSummaries", "get_resource_policy", "resourceArn", "$modelArn", "resourcePolicy", "$modelArn", absent=("ResourceNotFoundException",)),
    recipe("bedrock-guardrails", "bedrock", "list_guardrails", "guardrails", "get_resource_policy", "resourceArn", "$arn", "resourcePolicy", "$arn", absent=("ResourceNotFoundException",)),
    recipe("agentcore-runtimes", "bedrock-agentcore-control", "list_agent_runtimes", "agentRuntimes", "get_resource_policy", "resourceArn", "$agentRuntimeArn", "policy", "$agentRuntimeArn", absent=("ResourceNotFoundException",)),
    recipe("billing-views", "billing", "list_billing_views", "billingViews", "get_resource_policy", "resourceArn", "$arn", "policy", "$arn", region="us-east-1", absent=("ResourceNotFoundException",)),
    recipe("billing-dashboards", "bcm-dashboards", "list_dashboards", "dashboards", "get_resource_policy", "resourceArn", "$arn", "policyDocument", "$arn", region="us-east-1", absent=("ResourceNotFoundException",)),
]

# Additional parameter bindings and nested resources.
RECIPES = [Recipe(r.id, r.service, r.steps, r.operation,
    {**r.parameters, **({"AccountId": "{account}"} if r.service == "s3control" else {}),
     **({"domain": "$domainName", "domainOwner": "$domainOwner"} if r.id == "codeartifact-repositories" else {}),
     **({"domainOwner": "$owner"} if r.id == "codeartifact-domains" else {}),
     **({"ExpectedBucketOwner": "{account}"} if r.id == "s3-buckets" else {})},
    r.document, r.resource, r.region, r.absent, r.normalizer) for r in RECIPES]

RECIPES += [
    Recipe("dynamodb-tables", "dynamodb", (step("list_tables", "TableNames"), step("describe_table", "[Table]", TableName="$value")), "get_resource_policy", {"ResourceArn": "$TableArn"}, "Policy", "$TableArn", absent=("PolicyNotFoundException",)),
    Recipe("dynamodb-streams", "dynamodb", (step("list_tables", "TableNames"), step("describe_table", "[Table]", TableName="$value")), "get_resource_policy", {"ResourceArn": "$LatestStreamArn"}, "Policy", "$LatestStreamArn", absent=("PolicyNotFoundException",)),
    Recipe("kinesis-consumers", "kinesis", (step("list_streams", "StreamSummaries"), step("list_stream_consumers", "Consumers", StreamARN="$StreamARN")), "get_resource_policy", {"ResourceARN": "$ConsumerARN"}, "Policy", "$ConsumerARN", absent=("ResourceNotFoundException",)),
    Recipe("kafka-clusters", "kafka", (step("list_clusters_v2", "ClusterInfoList"),), "get_cluster_policy", {"ClusterArn": "$ClusterArn"}, "Policy", "$ClusterArn", absent=("NotFoundException",)),
    Recipe("lex-bots", "lexv2-models", (step("list_bots", "botSummaries"),), "describe_resource_policy", {"resourceArn": "arn:{partition}:lex:{region}:{account}:bot/{botId}"}, "policy", "arn:{partition}:lex:{region}:{account}:bot/{botId}", absent=("ResourceNotFoundException",)),
    Recipe("lex-aliases", "lexv2-models", (step("list_bots", "botSummaries"), step("list_bot_aliases", "botAliasSummaries", botId="$botId")), "describe_resource_policy", {"resourceArn": "arn:{partition}:lex:{region}:{account}:bot-alias/{botId}/{botAliasId}"}, "policy", "arn:{partition}:lex:{region}:{account}:bot-alias/{botId}/{botAliasId}", absent=("ResourceNotFoundException",)),
    Recipe("lambda-aliases", "lambda", (step("list_functions", "Functions"), step("list_aliases", "Aliases", FunctionName="$FunctionName")), "get_policy", {"FunctionName": "$FunctionName", "Qualifier": "$Name"}, "Policy", "$AliasArn", absent=("ResourceNotFoundException",)),
    Recipe("lambda-versions", "lambda", (step("list_functions", "Functions"), step("list_versions_by_function", "Versions", FunctionName="$FunctionName")), "get_policy", {"FunctionName": "$FunctionName", "Qualifier": "$Version"}, "Policy", "$FunctionArn", absent=("ResourceNotFoundException",)),
    Recipe("lambda-layers", "lambda", (step("list_layers", "Layers"), step("list_layer_versions", "LayerVersions", LayerName="$LayerName")), "get_layer_version_policy", {"LayerName": "$LayerName", "VersionNumber": "$Version"}, "Policy", "$LayerVersionArn", absent=("ResourceNotFoundException",)),
    Recipe("mediapackage-endpoints", "mediapackagev2", (step("list_channel_groups", "Items"), step("list_channels", "Items", ChannelGroupName="$ChannelGroupName"), step("list_origin_endpoints", "Items", ChannelGroupName="$ChannelGroupName", ChannelName="$ChannelName")), "get_origin_endpoint_policy", {"ChannelGroupName": "$ChannelGroupName", "ChannelName": "$ChannelName", "OriginEndpointName": "$OriginEndpointName"}, "Policy", "$Arn", absent=("ResourceNotFoundException",)),
    Recipe("mediastore-containers", "mediastore", (step("list_containers", "Containers"),), "get_container_policy", {"ContainerName": "$Name"}, "Policy", "$ARN", absent=("PolicyNotFoundException",)),
    Recipe("glacier-vaults", "glacier", (step("list_vaults", "VaultList", accountId="{account}"),), "get_vault_access_policy", {"accountId": "{account}", "vaultName": "$VaultName"}, "policy.Policy", "$VaultARN", absent=("ResourceNotFoundException",)),
    Recipe("api-gateway-apis", "apigateway", (step("get_rest_apis", "items"),), None, {}, "$policy", "arn:{partition}:apigateway:{region}::/restapis/{id}"),
    Recipe("api-gateway-domains", "apigateway", (step("get_domain_names", "items"),), None, {}, "$policy", "$domainNameArn"),
    Recipe("api-gateway-domain-management", "apigateway", (step("get_domain_names", "items"),), None, {}, "$managementPolicy", "$domainNameArn"),
    Recipe("vpc-endpoints", "ec2", (step("describe_vpc_endpoints", "VpcEndpoints"),), None, {}, "$PolicyDocument", "arn:{partition}:ec2:{region}:{account}:vpc-endpoint/{VpcEndpointId}"),
    Recipe("logs-policies", "logs", (step("describe_resource_policies", "resourcePolicies"),), None, {}, "$policyDocument", "arn:{partition}:logs:{region}:{account}:resource-policy:{policyName}"),
    Recipe("glue-catalog", "glue", (step("get_resource_policies", "GetResourcePoliciesResponseList"),), None, {}, "$PolicyInJson", "arn:{partition}:glue:{region}:{account}:catalog"),
    Recipe("xray-policies", "xray", (step("list_resource_policies", "ResourcePolicies"),), None, {}, "$PolicyDocument", "arn:{partition}:xray:{region}:{account}:resource-policy/{PolicyName}"),
    Recipe("rekognition-projects", "rekognition", (step("describe_projects", "ProjectDescriptions"), step("list_project_policies", "ProjectPolicies", ProjectArn="$ProjectArn")), None, {}, "$PolicyDocument", "$ProjectArn"),
    Recipe("iam-role-trust", "iam", (step("list_roles", "Roles"),), None, {}, "$AssumeRolePolicyDocument", "$Arn", region="us-east-1"),
    Recipe("organization-delegation", "organizations", (), "describe_resource_policy", {}, "ResourcePolicy.Content", "arn:{partition}:organizations::{account}:resourcepolicy/default", region="us-east-1", absent=("ResourcePolicyNotFoundException",)),
    Recipe("ecr-registry", "ecr", (), "get_registry_policy", {}, "policyText", "arn:{partition}:ecr:{region}:{account}:registry/{account}", absent=("RegistryPolicyNotFoundException",)),
]

READ_ACTIONS = {(r.service, op) for r in RECIPES for op in ([r.operation] if r.operation else []) + [s[0] for s in r.steps]}

RECIPES += [
    Recipe("cloudfront-vpc-origins", "cloudfront", (step("list_vpc_origins", "VpcOriginList.Items"),), "get_resource_policy", {"ResourceArn": "$Arn"}, "PolicyDocument", "$Arn", region="us-east-1", absent=("EntityNotFound",)),
    Recipe("cloudhsm-backups", "cloudhsmv2", (step("describe_backups", "Backups", Shared=False),), "get_resource_policy", {"ResourceArn": "$BackupArn"}, "Policy", "$BackupArn", absent=("ResourceNotFoundException",)),
    Recipe("elb-trust-stores", "elbv2", (step("describe_trust_stores", "TrustStores"),), "get_resource_policy", {"ResourceArn": "$TrustStoreArn"}, "Policy", "$TrustStoreArn", absent=("ResourceNotFoundException",)),
    Recipe("mpa-approval-teams", "mpa", (step("list_approval_teams", "ApprovalTeams"), step("list_resource_policies", "ResourcePolicies", ResourceArn="$Arn")), "get_resource_policy", {"ResourceArn": "$Arn", "PolicyName": "$PolicyName", "PolicyType": "$PolicyType"}, "PolicyDocument", "$Arn", region="us-east-1", absent=("ResourceNotFoundException",)),
    Recipe("sign-in-policy", "signin", (), "get_resource_policy", {}, "signinResourceBasedPolicy", "arn:{partition}:signin::{account}:resourcepolicy/default", region="us-east-1", normalizer="signin"),
    Recipe("ram-shared-resources", "ram", (step("list_resources", "resources", resourceOwner="SELF"),), "get_resource_policies", {"resourceArns": ["$arn"]}, "policies[]", "$arn"),
    Recipe("ssm-documents", "ssm", (step("list_documents", "DocumentIdentifiers", Filters=[{"Key": "Owner", "Values": ["Self"]}]),), "describe_document_permission", {"Name": "$Name", "PermissionType": "Share"}, "AccountIds", "arn:{partition}:ssm:{region}:{account}:document/{Name}", normalizer="ssm_document"),
    Recipe("serverless-applications", "serverlessrepo", (step("list_applications", "Applications"),), "get_application_policy", {"ApplicationId": "$ApplicationId"}, "Statements", "$ApplicationId", normalizer="serverlessrepo"),
    Recipe("signing-profiles", "signer", (step("list_signing_profiles", "profiles", includeCanceled=True), step("list_profile_permissions", "permissions", profileName="$profileName")), None, {}, "$permission_document", "$arn", normalizer="signer"),
    Recipe("vpc-endpoint-services", "ec2", (step("describe_vpc_endpoint_service_configurations", "ServiceConfigurations"), step("describe_vpc_endpoint_service_permissions", "AllowedPrincipals", ServiceId="$ServiceId")), None, {}, "$permission_document", "arn:{partition}:ec2:{region}:{account}:vpc-endpoint-service/{ServiceId}", normalizer="vpc_service"),
    Recipe("agentcore-runtime-endpoints", "bedrock-agentcore-control", (step("list_agent_runtimes", "agentRuntimes"), step("list_agent_runtime_endpoints", "runtimeEndpoints", agentRuntimeId="$agentRuntimeId")), "get_resource_policy", {"resourceArn": "$agentRuntimeEndpointArn"}, "policy", "$agentRuntimeEndpointArn", absent=("ResourceNotFoundException",)),
    Recipe("agentcore-gateways", "bedrock-agentcore-control", (step("list_gateways", "items"),), "get_resource_policy", {"resourceArn": "arn:{partition}:bedrock-agentcore:{region}:{account}:gateway/{gatewayId}"}, "policy", "arn:{partition}:bedrock-agentcore:{region}:{account}:gateway/{gatewayId}", absent=("ResourceNotFoundException",)),
]
for scope, endpoint in (("REGIONAL", None), ("CLOUDFRONT", "us-east-1")):
    RECIPES.append(Recipe("wafv2-" + scope.lower(), "wafv2", (step("list_rule_groups", "RuleGroups", Scope=scope),), "get_permission_policy", {"ResourceArn": "$ARN"}, "Policy", "$ARN", region=endpoint, absent=("WAFNonexistentItemException",)))
for service, endpoint in (("waf", "us-east-1"), ("waf-regional", None)):
    RECIPES.append(Recipe(service + "-rule-groups", service, (step("list_rule_groups", "RuleGroups"),), "get_permission_policy", {"ResourceArn": "arn:{partition}:" + ("waf" if service == "waf" else "waf-regional") + ":" + ("" if service == "waf" else "{region}") + ":{account}:rulegroup/{RuleGroupId}"}, "Policy", "arn:{partition}:" + ("waf" if service == "waf" else "waf-regional") + ":" + ("" if service == "waf" else "{region}") + ":{account}:rulegroup/{RuleGroupId}", region=endpoint, absent=("WAFNonexistentItemException",)))
for entity_type in ("AmiProduct", "ContainerProduct", "DataProduct", "SaaSProduct", "Offer", "ResaleAuthorization", "MachineLearningProduct", "OfferSet"):
    RECIPES.append(Recipe("marketplace-" + entity_type, "marketplace-catalog", (step("list_entities", "EntitySummaryList", Catalog="AWSMarketplace", EntityType=entity_type),), "get_resource_policy", {"ResourceArn": "$EntityArn"}, "Policy", "$EntityArn", region="us-east-1", absent=("ResourceNotFoundException",)))
for operation, path, arn in (("describe_phone_numbers", "PhoneNumbers", "PhoneNumberArn"), ("describe_pools", "Pools", "PoolArn"), ("describe_opt_out_lists", "OptOutLists", "OptOutListArn"), ("describe_sender_ids", "SenderIds", "SenderIdArn")):
    RECIPES.append(Recipe("sms-" + operation, "pinpoint-sms-voice-v2", (step(operation, path),), "get_resource_policy", {"ResourceArn": "$" + arn}, "Policy", "$" + arn, absent=("ResourceNotFoundException",)))
RECIPES = [Recipe(r.id, r.service, r.steps, r.operation, r.parameters,
                   "Policy.Established.Policy" if r.id == "s3-multi-region-access-points" else r.document,
                   r.resource, r.region, r.absent, r.normalizer) for r in RECIPES]
RECIPES += [
    Recipe("opensearch-domains", "opensearch", (step("list_domain_names", "DomainNames"), step("describe_domain", "[DomainStatus]", DomainName="$DomainName")), None, {}, "$AccessPolicies", "$ARN"),
    recipe("sagemaker-model-groups", "sagemaker", "list_model_package_groups", "ModelPackageGroupSummaryList", "get_model_package_group_policy", "ModelPackageGroupName", "$ModelPackageGroupName", "ResourcePolicy", "$ModelPackageGroupArn", absent=("ResourceNotFound",)),
    recipe("sagemaker-lineage-groups", "sagemaker", "list_lineage_groups", "LineageGroupSummaries", "get_lineage_group_policy", "LineageGroupName", "$LineageGroupName", "ResourcePolicy", "$LineageGroupArn", absent=("ResourceNotFound",)),
    Recipe("s3-individual-tables", "s3tables", (step("list_table_buckets", "tableBuckets"), step("list_tables", "tables", tableBucketARN="$arn")), "get_table_policy", {"tableBucketARN": "$arn", "namespace": "$namespace[0]", "name": "$name"}, "resourcePolicy", "$tableARN", absent=("NotFoundException",)),
    recipe("investigation-groups", "aiops", "list_investigation_groups", "investigationGroups", "get_investigation_group_policy", "identifier", "$arn", "policy", "$arn", absent=("ResourceNotFoundException",)),
    recipe("api-portal-products", "apigatewayv2", "list_portal_products", "Items", "get_portal_product_sharing_policy", "PortalProductId", "$PortalProductId", "PolicyDocument", "$PortalProductArn", parameters={"ResourceOwner": "SELF"}, absent=("NotFoundException",)),
    recipe("cloudsearch-domains", "cloudsearch", "describe_domains", "DomainStatusList", "describe_service_access_policies", "DomainName", "$DomainName", "AccessPolicies.Options", "$ARN"),
    recipe("profiling-groups", "codeguruprofiler", "list_profiling_groups", "profilingGroups", "get_policy", "profilingGroupName", "$name", "policy", "$arn", parameters={"includeDescription": True}, absent=("ResourceNotFoundException",)),
    recipe("dsql-clusters", "dsql", "list_clusters", "clusters", "get_cluster_policy", "identifier", "$identifier", "policy", "$arn", absent=("ResourceNotFoundException",)),
    recipe("log-delivery-destinations", "logs", "describe_delivery_destinations", "deliveryDestinations", "get_delivery_destination_policy", "deliveryDestinationName", "$name", "policy.deliveryDestinationPolicy", "$arn", absent=("ResourceNotFoundException",)),
    Recipe("mediapackage-channels", "mediapackagev2", (step("list_channel_groups", "Items"), step("list_channels", "Items", ChannelGroupName="$ChannelGroupName")), "get_channel_policy", {"ChannelGroupName": "$ChannelGroupName", "ChannelName": "$ChannelName"}, "Policy", "$Arn", absent=("ResourceNotFoundException",)),
    recipe("mediatailor-channels", "mediatailor", "list_channels", "Items", "get_channel_policy", "ChannelName", "$ChannelName", "Policy", "$Arn", absent=("ResourceNotFoundException",)),
    recipe("qbusiness-applications", "qbusiness", "list_applications", "applications", "get_policy", "applicationId", "$applicationId", "policy", "arn:{partition}:qbusiness:{region}:{account}:application/{applicationId}", absent=("ResourceNotFoundException",)),
]
RECIPES += [
    Recipe("logs-resource-policies", "logs", (step("describe_resource_policies", "resourcePolicies", policyScope="RESOURCE"),), None, {}, "$policyDocument", "$resourceArn"),
    Recipe("omics-store-access", "omics", (step("list_sequence_stores", "sequenceStores"), step("get_sequence_store", "[s3Access] | [?s3AccessPointArn]", id="$id")), "get_s3_access_policy", {"s3AccessPointArn": "$s3AccessPointArn"}, "s3AccessPolicy", "$s3AccessPointArn", absent=("ResourceNotFoundException",)),
]
RECIPES += [
    recipe("cleanrooms-audience-models", "cleanroomsml", "list_configured_audience_models", "configuredAudienceModels", "get_configured_audience_model_policy", "configuredAudienceModelArn", "$configuredAudienceModelArn", "configuredAudienceModelPolicy", "$configuredAudienceModelArn", absent=("ResourceNotFoundException",)),
    recipe("resolver-firewall-groups", "route53resolver", "list_firewall_rule_groups", "FirewallRuleGroups", "get_firewall_rule_group_policy", "Arn", "$Arn", "FirewallRuleGroupPolicy", "$Arn", absent=("ResourceNotFoundException",)),
    recipe("resolver-query-log-configs", "route53resolver", "list_resolver_query_log_configs", "ResolverQueryLogConfigs", "get_resolver_query_log_config_policy", "Arn", "$Arn", "ResolverQueryLogConfigPolicy", "$Arn", absent=("ResourceNotFoundException",)),
    recipe("resolver-rules", "route53resolver", "list_resolver_rules", "ResolverRules", "get_resolver_rule_policy", "Arn", "$Arn", "ResolverRulePolicy", "$Arn", absent=("ResourceNotFoundException",)),
]
for family, listing, path, operation, parameter in (
    ("components", "list_components", "componentVersionList", "get_component_policy", "componentArn"),
    ("images", "list_images", "imageVersionList", "get_image_policy", "imageArn"),
    ("image-recipes", "list_image_recipes", "imageRecipeSummaryList", "get_image_recipe_policy", "imageRecipeArn"),
    ("container-recipes", "list_container_recipes", "containerRecipeSummaryList", "get_container_recipe_policy", "containerRecipeArn"),
):
    RECIPES.append(recipe("imagebuilder-" + family, "imagebuilder", listing, path, operation, parameter, "$arn", "policy", "$arn", parameters={"owner": "Self"}, absent=("ResourceNotFoundException",)))
for family, listing in (("services", "list_services"), ("networks", "list_service_networks")):
    RECIPES.append(recipe("lattice-auth-" + family, "vpc-lattice", listing, "items", "get_auth_policy", "resourceIdentifier", "$arn", "policy", "$arn", absent=("ResourceNotFoundException",)))
# Supported policy targets are reviewed against AWS Service Authorization
# resource types, not inferred from the existence of a generic GetResourcePolicy.
RECIPES += [
    recipe("bedrock-knowledge-bases", "bedrock-agent", "list_knowledge_bases", "knowledgeBaseSummaries", "get_resource_policy", "resourceArn", "arn:{partition}:bedrock:{region}:{account}:knowledge-base/{knowledgeBaseId}", "policy", "arn:{partition}:bedrock:{region}:{account}:knowledge-base/{knowledgeBaseId}", absent=("ResourceNotFoundException",)),
    Recipe("bedrock-guardrail-profiles", "bedrock", (step("list_guardrails", "guardrails"), step("list_guardrails", "guardrails", guardrailIdentifier="$arn"), step("get_guardrail", "[crossRegionDetails] | [?guardrailProfileArn]", guardrailIdentifier="$id", guardrailVersion="$version")), "get_resource_policy", {"resourceArn": "$guardrailProfileArn"}, "resourcePolicy", "$guardrailProfileArn", absent=("ResourceNotFoundException",)),
    recipe("cloudtrail-dashboards", "cloudtrail", "list_dashboards", "Dashboards", "get_resource_policy", "ResourceArn", "$DashboardArn", "ResourcePolicy", "$DashboardArn", absent=("ResourcePolicyNotFoundException",)),
    recipe("network-firewall-firewalls", "network-firewall", "list_firewalls", "Firewalls", "describe_resource_policy", "ResourceArn", "$FirewallArn", resource="$FirewallArn", absent=("ResourceNotFoundException",)),
    recipe("sap-databases", "ssm-sap", "list_databases", "Databases", "get_resource_permission", "ResourceArn", "$Arn", resource="$Arn", absent=("ResourceNotFoundException",)),
    recipe("lookout-datasets", "lookoutequipment", "list_datasets", "DatasetSummaries", "describe_resource_policy", "ResourceArn", "$DatasetArn", "ResourcePolicy", "$DatasetArn", absent=("ResourceNotFoundException",)),
    Recipe("lookout-model-versions", "lookoutequipment", (step("list_models", "ModelSummaries"), step("list_model_versions", "ModelVersionSummaries", ModelName="$ModelName")), "describe_resource_policy", {"ResourceArn": "$ModelVersionArn"}, "ResourcePolicy", "$ModelVersionArn", absent=("ResourceNotFoundException",)),
    Recipe("ssm-opsitem-groups", "ssm", (), "get_resource_policies", {"ResourceArn": "arn:{partition}:ssm:{region}:{account}:opsitemgroup/default"}, "Policies[].Policy", "arn:{partition}:ssm:{region}:{account}:opsitemgroup/default"),
    Recipe("s3-outposts-access-points", "s3control", (step("list_regional_buckets", "RegionalBucketList", AccountId="{account}"), step("list_access_points", "AccessPointList", AccountId="{account}", Bucket="$BucketArn")), "get_access_point_policy", {"Name": "$AccessPointArn", "AccountId": "{account}"}, "Policy", "$AccessPointArn", absent=("NoSuchAccessPointPolicy",)),
]
RECIPES = [Recipe(r.id, r.service, r.steps, r.operation,
    {**r.parameters, "Deployed": True} if r.id == "cloudsearch-domains" else r.parameters,
    "[ResourcePolicy, DelegatedAdminResourcePolicy] | [?@ != null]" if r.service == "cloudtrail" else r.document,
    r.resource, r.region, r.absent, r.normalizer) for r in RECIPES]

# Policies on images and components are attached to concrete build versions.
# ListImages/ListComponents return three-node version ARNs, which the policy
# Get APIs reject; traverse every build rather than checking only a latest one.
RECIPES = [Recipe(r.id, r.service,
    r.steps + (step("list_image_build_versions", "imageSummaryList", imageVersionArn="$arn"),)
        if r.id == "imagebuilder-images" else
    r.steps + (step("list_component_build_versions", "componentSummaryList", componentVersionArn="$arn"),)
        if r.id == "imagebuilder-components" else r.steps,
    r.operation, r.parameters, r.document, r.resource, r.region, r.absent, r.normalizer)
    for r in RECIPES]
READ_ACTIONS = {(r.service, op) for r in RECIPES for op in ([r.operation] if r.operation else []) + [s[0] for s in r.steps]}



def recipe_operations(r):
    return {operation for operation in ([r.operation] if r.operation else []) +
            [step[0] for step in r.steps]}


def unsupported_operations(r, session):
    """Check this finite recipe against the installed SDK, without API calls."""
    from botocore import xform_name
    from botocore.exceptions import UnknownServiceError
    try:
        model = session.get_service_model(r.service)
    except UnknownServiceError:
        return sorted(recipe_operations(r))
    available = {xform_name(name) for name in model.operation_names}
    return sorted(recipe_operations(r) - available)


# Role generation must consume only recipes executable by its installed SDK.
# Keep unsupported recipes in RECIPES so collection reports explicit gaps.
import botocore.session as _botocore_session
_capability_session = _botocore_session.get_session()
# Same answer as checking every model here; a recorded result is reused only when it provably applies.
from .aws_sdk_recipe_capabilities import unsupported_recipes as _unsupported_recipes
UNSUPPORTED_RECIPES = _unsupported_recipes(RECIPES, recipe_operations, unsupported_operations, _capability_session)
DECLARED_READ_ACTIONS = READ_ACTIONS
READ_ACTIONS = {(r.service, operation) for r in RECIPES
                if r.id not in UNSUPPORTED_RECIPES for operation in recipe_operations(r)}
del _capability_session


def resolve(value, context):
    if isinstance(value, list):
        return [resolve(item, context) for item in value]
    if isinstance(value, dict):
        return {key: resolve(item, context) for key, item in value.items()}
    if not isinstance(value, str):
        return value
    if value.startswith("$"):
        resolved = jmespath.search(value[1:], context)
        if resolved is None:
            raise KeyError(value)
        return resolved
    return value.format_map(context)


def collect(requests, session, region, account, recipes=None):
    from .aws import ReadResult
    selected = RECIPES if recipes is None else recipes
    partition = session.get_partition_for_region(region)
    policies, failures = {}, []

    def failure(r, status, code):
        failures.append({"family": r.id, "status": status, "code": code})

    for r in selected:
        # Test adapters may provide only partition lookup; real collection uses
        # a Botocore session and checks that exact session's service models.
        missing = (unsupported_operations(r, session) if hasattr(session, "get_service_model")
                   else UNSUPPORTED_RECIPES.get(r.id, []))
        if missing:
            failure(r, "not_supported", "sdk_operations_unavailable:" + ",".join(missing))
            continue
        api_region = r.region or region
        if r.region and partition != "aws":
            api_region = {"aws-cn": "cn-north-1", "aws-us-gov": "us-gov-west-1"}.get(partition, region)
        context = {"partition": partition, "region": api_region, "account": account}
        contexts = [context]
        try:
            for operation, path, bindings in r.steps:
                next_contexts = []
                for parent in contexts:
                    read = requests.pages(session, r.service, api_region, operation, path, **{key: resolve(value, parent) for key, value in bindings.items()})
                    if read.status not in {"collected", "empty"}:
                        failure(r, read.status, (read.error or {}).get("code", "policy_listing_incomplete"))
                    for item in read.items:
                        if not isinstance(item, (dict, str)):
                            failure(r, "malformed", "policy_resource_identity_invalid")
                            continue
                        next_contexts.append({**parent, **(item if isinstance(item, dict) else {"value": item})})
                contexts = next_contexts
            for current in contexts:
                try:
                    # DynamoDB does not always have an enabled stream. Public API
                    # Gateway domains have no domain resource policy/ARN.
                    if r.id == "dynamodb-streams" and not current.get("LatestStreamArn"):
                        continue
                    if r.id.startswith("api-gateway-domain") and not current.get("domainNameArn"):
                        continue
                    if r.id == "lambda-versions" and current.get("Version") == "$LATEST":
                        continue
                    arn = resolve(r.resource, current)
                    if not isinstance(arn, str) or not arn.startswith("arn:"):
                        raise ValueError("resource ARN unavailable")
                    parts = arn.split(":", 5)
                    if len(parts) != 6 or parts[1] != partition or parts[4] not in (account, "") or parts[3] not in (api_region, ""):
                        failure(r, "malformed", "policy_resource_outside_account_or_region")
                        continue
                    if r.operation:
                        arguments = {key: resolve(value, current) for key, value in r.parameters.items()}
                        if "[]" in r.document or r.normalizer == "ssm_document":
                            read = requests.pages(session, r.service, api_region, r.operation, r.document, **arguments)
                            if read.status not in {"collected", "empty"}:
                                failure(r, read.status, (read.error or {}).get("code", "policy_detail_incomplete"))
                            response = {"collection_status": "collected", "documents": read.items}
                            raw = read.items
                        else:
                            response = requests.detail(session, r.service, api_region, r.operation,
                                absent=r.absent, **arguments)
                            raw = jmespath.search(r.document, response)
                        status = response.get("collection_status")
                        if status == "empty" and response.get("absent") is True:
                            continue
                        if status != "collected":
                            failure(r, status or "unknown", (response.get("error") or {}).get("code", "policy_detail_incomplete"))
                            continue
                    else:
                        raw = current if r.normalizer else current.get(r.document[1:])
                    if r.normalizer == "signin" and isinstance(raw, dict):
                        raw = {"Version": raw.get("version"), "Statement": [{key.capitalize() if key != "notprincipal" else "NotPrincipal": value for key, value in statement.items()} for statement in raw.get("statement", [])]}
                    elif r.normalizer == "ssm_document":
                        raw = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*" if value == "all" else value}, "Action": "ssm:GetDocument", "Resource": arn} for value in raw]}
                    elif r.normalizer == "serverlessrepo":
                        raw = {"Statement": [{"Sid": value.get("StatementId", ""), "Effect": "Allow", "Principal": {"AWS": value["Principals"]}, "Action": value["Actions"], "Resource": arn,
                            **({"Condition": {"StringEquals": {"aws:PrincipalOrgID": value["PrincipalOrgIDs"]}}} if value.get("PrincipalOrgIDs") else {})} for value in raw]}
                    elif r.normalizer == "signer":
                        raw = {"Statement": [{"Sid": current.get("statementId", ""), "Effect": "Allow", "Principal": {"AWS": current["principal"]}, "Action": current["action"], "Resource": arn}]}
                    elif r.normalizer == "vpc_service":
                        raw = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": current["Principal"]}, "Action": "ec2:Connect", "Resource": arn}]}
                    if raw in (None, "", []):
                        # These successful APIs expressly allow no attached policy.
                        # A missing mandatory document is incomplete evidence.
                        if not r.operation or r.id in {"secrets", "eventbridge-buses", "s3-multi-region-access-points", "sign-in-policy"} or "[]" in r.document or r.document.endswith(".*") or r.normalizer == "ssm_document":
                            continue
                        failure(r, "malformed", "policy_document_missing")
                        continue
                    documents = raw if isinstance(raw, list) else [raw]
                    for document in documents:
                        if isinstance(document, str):
                            try:
                                document = json.loads(document)
                            except ValueError:
                                document = json.loads(unquote(document))
                        if not isinstance(document, dict) or not isinstance(document.get("Statement"), (dict, list)):
                            raise ValueError("IAM policy document unavailable")
                        statements = document["Statement"]
                        statements = [statements] if isinstance(statements, dict) else statements
                        if any(not isinstance(statement, dict) for statement in statements):
                            raise ValueError("IAM policy statements malformed")
                        row = policies.setdefault(arn, {"ResourceArn": arn, "Policy": {"Version": "2012-10-17", "Statement": []},
                            "_provenance": {"read_only": True, "owner_account": account, "source_region": api_region,
                                "collection_region": region, "families": [], "source_operations": []}})
                        row["Policy"]["Statement"].extend(statements)
                        if r.id not in row["_provenance"]["families"]:
                            row["_provenance"]["families"].append(r.id)
                        source_operation = r.service + ":" + (r.operation or r.steps[-1][0])
                        if source_operation not in row["_provenance"]["source_operations"]:
                            row["_provenance"]["source_operations"].append(source_operation)
                except (KeyError, TypeError, ValueError, IndexError):
                    failure(r, "malformed", "policy_resource_or_document_invalid")
        except (KeyError, TypeError, ValueError, IndexError):
            failure(r, "malformed", "policy_resource_or_document_invalid")
    rows = [policies[key] for key in sorted(policies)]
    if failures:
        status = "partial" if rows else "denied" if all(f["status"] == "denied" for f in failures) else "unknown"
        return ReadResult(rows, status, {"code": "resource_policy_coverage_incomplete", "families": failures})
    return ReadResult(rows, "collected" if rows else "empty")
