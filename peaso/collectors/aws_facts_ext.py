"""Read-only AWS facts for the HackTricks Best Practices checks and the privesc evaluator.

Every request is a list/describe/get metadata read issued through the shared scan
request context (single-flight cache, retries, max_pages/max_resources bounds).
Outputs are explicit field allowlists:

* Lambda: layer versions with their resource policy, function aliases, event source
  mappings, and on ``lambda_function`` the environment variable *names* (never
  values, taken from the cached GetFunctionConfiguration response) plus the runtime
  management mode.
* ECR registry (replication rules, registry policy, pull-through cache rules,
  repository creation templates), EKS access entries (type, groups, associated
  access policies) and pod identity associations, KMS grants of customer keys
  (encryption-context constraint *keys* only), OpenSearch cross-cluster connections.
* Cognito: identity-pool role map (GetIdentityPoolRoles), user-pool identity
  providers (name/type only), MFA mode and groups with their IAM role.
* Route 53 record sets (record values only for A/AAAA/CNAME/NS; other types keep
  a value count), CloudFormation StackSet instances and Organizations access status, EC2 Instance Connect
  endpoints, IAM Roles Anywhere profiles.
* Workload hosts: Image Builder pipelines with their infrastructure instance
  profile and their image recipe's component ARNs (GetImageRecipe; no recipe
  content, parameters or user data), SageMaker user profiles / spaces / HyperPod clusters with their execution roles,
  SageMaker domain default execution roles.
* Application planes: Managed Grafana workspaces, QuickSight users (role and
  identity type, no e-mail) and subscription status/authentication type,
  Supply Chain instances, Amplify apps with their
  Gen 1 backend environments (no environment variables, build specs or basic-auth
  credentials), Device Farm uploads and device pools (no signed upload URLs or test content).
* IAM Identity Center account assignments (permission set, account, principal
  type/id) and group display names.

A denied or failed read keeps its own status; only documented "not found" codes
mean absence.
"""
from __future__ import annotations

import copy
from datetime import datetime
import hashlib
import json
import re
from urllib.parse import urlsplit

OK = ("collected", "empty")

SPECS = {
    'agentcore_gateway': ("bedrock-agentcore-control", "list_gateways", "items"),
    'auditmanager_report_destination': ("auditmanager", "list_assessments", "assessmentMetadata"),
    'cleanrooms_collaboration_exposure': ("cleanrooms", "list_memberships", "membershipSummaries"),
    'eventbridge_pipe_exposure': ("pipes", "list_pipes", "Pipes"),
    "transit_gateway_peering_attachment": ("ec2", "describe_transit_gateway_peering_attachments", "TransitGatewayPeeringAttachments"),
    "lambda_layer_version": ("lambda", "list_layers", "Layers"),
    "lambda_version": ("lambda", "list_versions_by_function", "Versions"),
    "redshiftserverless_snapshot": ("redshift-serverless", "list_snapshots", "snapshots"),
    "docdb_cluster_snapshot": ("docdb", "describe_db_cluster_snapshots", "DBClusterSnapshots"),
    "neptune_cluster_snapshot": ("neptune", "describe_db_cluster_snapshots", "DBClusterSnapshots"),
    "lambda_alias": ("lambda", "list_aliases", "Aliases"),
    "client_vpn_routing": ("ec2", "describe_client_vpn_endpoints", "ClientVpnEndpoints"),
    "lambda_event_source_mapping": ("lambda", "list_event_source_mappings", "EventSourceMappings"),
    "ecr_registry": ("ecr", "describe_registry", None),
    "eks_access_entry": ("eks", "list_access_entries", "accessEntries"),
    "eks_pod_identity_association": ("eks", "list_pod_identity_associations", "associations"),
    "kms_grant": ("kms", "list_grants", "Grants"),
    "opensearch_connection": ("opensearch", "describe_outbound_connections", "Connections"),
    "route53_record_set": ("route53", "list_resource_record_sets", "ResourceRecordSets"),
    "cloudformation_stack_instance": ("cloudformation", "list_stack_instances", "Summaries"),
    "cloudformation_organizations_access": ("cloudformation", "describe_organizations_access", None),
    "ec2_instance_connect_endpoint": ("ec2", "describe_instance_connect_endpoints", "InstanceConnectEndpoints"),
    "rolesanywhere_profile": ("rolesanywhere", "list_profiles", "profiles"),
    "imagebuilder_pipeline": ("imagebuilder", "list_image_pipelines", "imagePipelineList"),
    "imagebuilder_distribution": ("imagebuilder", "list_distribution_configurations", "distributionConfigurationSummaryList"),
    "agentcore_gateway": ("bedrock-agentcore-control", "list_gateways", "items"),
    "eventbridge_pipe_exposure": ("pipes", "list_pipes", "Pipes"),
    "cleanrooms_collaboration_exposure": ("cleanrooms", "list_memberships", "membershipSummaries"),
    "auditmanager_report_destination": ("auditmanager", "list_assessments", "assessmentMetadata"),
    "lightsail_distribution": ("lightsail", "get_distributions", "distributions"),
    "sagemaker_user_profile": ("sagemaker", "list_user_profiles", "UserProfiles"),
    "sagemaker_space": ("sagemaker", "list_spaces", "Spaces"),
    "sagemaker_cluster": ("sagemaker", "list_clusters", "ClusterSummaries"),
    "grafana_workspace": ("grafana", "list_workspaces", "workspaces"),
    "gamelift_ec2_compute": ("gamelift", "list_fleets", "FleetIds"),
    "iot_role_alias": ("iot", "list_role_aliases", "roleAliases"),
    "iot_credentials_endpoint": ("iot", "describe_endpoint", None),
    "iot_data_domain": ("iot", "list_domain_configurations", "domainConfigurations"),
    "iot_topic_rule": ("iot", "list_topic_rules", "rules"),
    "cognito_user_pool_endpoint": ("cognito-idp", "list_user_pools", "UserPools"),
    "apigatewayv2_portal": ("apigatewayv2", "list_portals", "Items"),
    "appflow_flow": ("appflow", "list_flows", "flows"),
    "cloudmap_public_service": ("servicediscovery", "list_namespaces", "Namespaces"),
    "cloudsearch_domain_endpoint": ("cloudsearch", "describe_domains", "DomainStatusList"),
    "rum_app_monitor_endpoint": ("rum", "list_app_monitors", "AppMonitorSummaries"),
    "config_aggregation_authorization": ("config", "describe_aggregation_authorizations", "AggregationAuthorizations"),
    "config_conformance_pack_delivery": ("config", "describe_conformance_packs", "ConformancePackDetails"),
    "config_organization_pack_delivery": ("config", "describe_organization_conformance_packs", "OrganizationConformancePacks"),
    "config_rule_lambda_delivery": ("config", "describe_config_rules", "ConfigRules"),
    "config_organization_rule_lambda_delivery": ("config", "describe_organization_config_rules", "OrganizationConfigRules"),
    "backup_search_export": ("backupsearch", "list_search_result_export_jobs", "ExportJobs"),
    "devicefarm_upload": ("devicefarm", "list_uploads", "uploads"),
    "devicefarm_device_pool": ("devicefarm", "list_device_pools", "devicePools"),
    "quicksight_user": ("quicksight", "list_users", "UserList"),
    "quicksight_account_subscription": ("quicksight", "describe_account_subscription", None),
    "supplychain_instance": ("supplychain", "list_instances", "instances"),
    "amplify_app": ("amplify", "list_apps", "apps"),
    "aws_identity_center_account_assignment": ("sso-admin", "list_account_assignments", "AccountAssignments"),
    "cloud9_environment_share": ("cloud9", "list_environments", "environmentIds"),
    "omics_resource_share": ("omics", "list_shares", "shares"),
    "wellarchitected_workload_share": ("wellarchitected", "list_workloads", "WorkloadSummaries"),
    "wellarchitected_lens_share": ("wellarchitected", "list_lenses", "LensSummaries"),
    "wellarchitected_profile_share": ("wellarchitected", "list_profiles", "ProfileSummaries"),
    "wellarchitected_template_share": ("wellarchitected", "list_review_templates", "ReviewTemplates"),
    "ec2_fpga_image": ("ec2", "describe_fpga_images", "FpgaImages"),
    "ds_directory_share": ("ds", "describe_directories", "DirectoryDescriptions"),
    "auditmanager_framework_share": ("auditmanager", "list_assessment_framework_share_requests", "assessmentFrameworkShareRequests"),
    "workdocs_document_share": ("workdocs", "describe_users", "Users"),
    "cleanrooms_table_share": ("cleanrooms", "list_memberships", "membershipSummaries"),
    "dataexchange_data_grant": ("dataexchange", "list_data_grants", "DataGrantSummaries"),
    "quicksight_public_dashboard": ("quicksight", "list_dashboards", "DashboardSummaryList"),
    "license_manager_distributed_grant": ("license-manager", "list_distributed_grants", "Grants"),
    "lakeformation_table_grant": ("lakeformation", "list_permissions", "PrincipalResourcePermissions"),
    "lakeformation_tag_policy_grant": ("lakeformation", "list_permissions", "PrincipalResourcePermissions"),
    "securitylake_subscriber_share": ("securitylake", "list_subscribers", "subscribers"),
    "s3_access_grant_share": ("s3control", "list_access_grants", "AccessGrantsList"),
    "workspaces_connection_alias_share": ("workspaces", "describe_connection_aliases", "ConnectionAliases"),
}
NATIVE_IDS = {kind: "id" for kind in SPECS}
GLOBAL_TYPES = {"route53_record_set"}
READ_ACTIONS = {
    ('auditmanager', 'get_assessment'),
    ('auditmanager', 'get_settings'),
    ('auditmanager', 'list_assessments'),
    ('bedrock-agentcore-control', 'get_gateway'),
    ('bedrock-agentcore-control', 'list_gateways'),
    ('imagebuilder', 'list_distribution_configurations'),
    ('pipes', 'describe_pipe'),
    ('pipes', 'list_pipes'),
    ("ec2", "describe_client_vpn_authorization_rules"),
    ("ec2", "describe_transit_gateway_peering_attachments"),
    ("lambda", "list_functions"), ("lambda", "list_layer_versions"), ("lambda", "list_versions_by_function"), ("lambda", "get_layer_version_policy"),
    ("lambda", "get_function_url_config"), ("lambda", "get_policy"),
    ("lambda", "get_function_configuration"), ("lambda", "get_runtime_management_config"),
    ("ec2", "describe_client_vpn_routes"), ("ec2", "describe_client_vpn_target_networks"),
    ("ecr", "get_registry_policy"), ("ecr", "describe_pull_through_cache_rules"), ("ecr", "describe_repository_creation_templates"),
    ("redshift-serverless", "list_snapshots"),
    ("docdb", "describe_db_cluster_snapshot_attributes"), ("neptune", "describe_db_cluster_snapshot_attributes"),
    ("eks", "list_clusters"), ("eks", "describe_access_entry"), ("eks", "list_associated_access_policies"),
    ("eks", "describe_pod_identity_association"),
    ("kms", "list_keys"), ("kms", "describe_key"),
    ("cognito-identity", "get_identity_pool_roles"),
    ("cognito-idp", "list_identity_providers"), ("cognito-idp", "get_user_pool_mfa_config"), ("cognito-idp", "list_groups"),
    ("cognito-idp", "describe_user_pool"), ("cognito-idp", "describe_user_pool_domain"),
    ("cognito-idp", "list_user_pool_clients"), ("cognito-idp", "describe_user_pool_client"),
    ("opensearch", "describe_inbound_connections"),
    ("route53", "list_hosted_zones"),
    ("cloudformation", "list_stack_sets"),
    ("cloudformation", "describe_organizations_access"),
    ("imagebuilder", "list_infrastructure_configurations"), ("imagebuilder", "get_image_recipe"),
    ("imagebuilder", "get_distribution_configuration"),
    ("sagemaker", "describe_user_profile"), ("sagemaker", "describe_cluster"), ("sagemaker", "describe_domain"),
    ("sagemaker", "describe_space"),
    ("amplify", "list_backend_environments"), ("amplify", "list_branches"), ("amplify", "list_domain_associations"),
    ("grafana", "list_workspace_service_accounts"),
    ("quicksight", "describe_account_subscription"),
    ("gamelift", "describe_fleet_attributes"), ("gamelift", "list_compute"), ("gamelift", "describe_fleet_port_settings"),
    ("devicefarm", "list_projects"), ("devicefarm", "get_device_pool_compatibility"),
    ("iot", "describe_role_alias"),
    ("iot", "describe_endpoint"),
    ("iot", "describe_domain_configuration"),
    ("iot", "get_topic_rule"),
    ("iot", "list_topic_rule_destinations"),
    ("appflow", "describe_flow"),
    ("servicediscovery", "list_services"), ("servicediscovery", "list_instances"),
    ("cloudsearch", "describe_service_access_policies"), ("cloudsearch", "describe_domain_endpoint_options"),
    ("rum", "get_app_monitor"), ("rum", "get_resource_policy"), ("rum", "list_rum_metrics_destinations"),
    ("backupsearch", "get_search_result_export_job"),
    ("sso-admin", "list_instances"), ("sso-admin", "list_permission_sets"),
    ("sso-admin", "list_accounts_for_provisioned_permission_set"), ("identitystore", "list_groups"),
    ("cloud9", "list_environments"), ("cloud9", "describe_environments"),
    ("cloud9", "describe_environment_memberships"),
    ("omics", "list_shares"),
    ("wellarchitected", "list_workloads"), ("wellarchitected", "list_workload_shares"),
    ("wellarchitected", "list_lenses"), ("wellarchitected", "list_lens_shares"),
    ("wellarchitected", "list_profiles"), ("wellarchitected", "list_profile_shares"),
    ("wellarchitected", "list_review_templates"), ("wellarchitected", "list_template_shares"),
    ("ec2", "describe_fpga_images"), ("ec2", "describe_fpga_image_attribute"),
    ("ds", "describe_directories"), ("ds", "describe_shared_directories"),
    ("auditmanager", "list_assessment_framework_share_requests"),
    ("workdocs", "describe_users"), ("workdocs", "describe_folder_contents"),
    ("workdocs", "describe_resource_permissions"),
    ("cleanrooms", "list_memberships"), ("cleanrooms", "list_members"),
    ("cleanrooms", "list_configured_table_associations"),
    ("dataexchange", "list_data_grants"),
    ("quicksight", "list_dashboards"), ("quicksight", "describe_dashboard_permissions"),
    ("quicksight", "describe_account_settings"),
    ("license-manager", "list_distributed_grants"),
    ("lakeformation", "list_permissions"),
    ("securitylake", "list_subscribers"),
    ("s3control", "list_access_grants"),
    ("workspaces", "describe_connection_aliases"), ("workspaces", "describe_connection_alias_permissions"),
}

# Route 53 record types whose values are kept (addresses / delegation / aliasing targets).
_RECORD_VALUE_TYPES = {"A", "AAAA", "CNAME", "NS"}
_ESM_FIELDS = ("UUID", "EventSourceMappingArn", "EventSourceArn", "FunctionArn", "State", "StateTransitionReason", "LastModified",
               "BatchSize", "StartingPosition", "MaximumRetryAttempts", "MaximumRecordAgeInSeconds", "BisectBatchOnFunctionError",
               "DestinationConfig", "Topics", "Queues", "KMSKeyArn", "FunctionResponseTypes")


def _aws():
    from . import aws
    return aws


def _transit_gateway_system_routes(requests, session, region, items):
    """Read the system route class omitted by the pinned static/propagated searches."""
    for item in items:
        table_id = item.get("TransitGatewayRouteTableId") if isinstance(item, dict) else None
        if not isinstance(table_id, str) or not table_id:
            continue
        read = requests.pages(session, "ec2", region, "search_transit_gateway_routes", "Routes",
                              TransitGatewayRouteTableId=table_id,
                              Filters=[{"Name": "type", "Values": ["system"]}])
        item["SystemRouteInventory"] = {"collection_status": read.status, "items": read.items,
                                        "queries": ["type=system"],
                                        **({"error": read.error} if read.error else {})}
    return items


def _iot_role_aliases(requests, session, region, account):
    read = requests.pages(session, "iot", region, "list_role_aliases", "roleAliases",
                          _tokens=("marker", "nextMarker"))
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for name in read.items:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_=,@-]{1,128}", name):
            failure = failure or ("malformed", {"code": "malformed_iot_role_alias"})
            continue
        arn = f"arn:{_partition(region)}:iot:{region}:{account}:rolealias/{name}"
        detail = requests.detail(session, "iot", region, "describe_role_alias", roleAlias=name)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "unknown",
                                  {"code": "iot_role_alias_detail_unavailable"})
            continue
        description = detail.get("roleAliasDescription")
        role_arn = description.get("roleArn") if isinstance(description, dict) else None
        if (not isinstance(description, dict) or description.get("roleAlias") != name or
                description.get("roleAliasArn") != arn or
                not isinstance(role_arn, str) or not re.fullmatch(
                    rf"arn:{_partition(region)}:iam::{account}:role/.+", role_arn)):
            failure = failure or ("malformed", {"code": "malformed_iot_role_alias_detail"})
            continue
        rows.append({"RoleAlias": name, "RoleAliasArn": arn, "RoleArn": role_arn, "id": arn})
    return _finish(rows, failure)


def _iot_credentials_endpoint(requests, session, region, account):
    aliases = requests.pages(session, "iot", region, "list_role_aliases", "roleAliases",
                             _tokens=("marker", "nextMarker"))
    if aliases.status not in OK:
        return _finish([], _cause(aliases))
    if not aliases.items:
        return _finish([], None)
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_=,@-]{1,128}", name)
           for name in aliases.items):
        return _finish([], ("malformed", {"code": "malformed_iot_role_alias"}))
    detail = requests.detail(session, "iot", region, "describe_endpoint",
                             endpointType="iot:CredentialProvider")
    if detail.get("collection_status") != "collected":
        return _finish([], (detail.get("collection_status") or "unknown",
                            {"code": "iot_credentials_endpoint_unavailable"}))
    address = detail.get("endpointAddress")
    if not isinstance(address, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", address) or "." not in address:
        return _finish([], ("malformed", {"code": "malformed_iot_credentials_endpoint"}))
    return _finish([{"id": f"{account}/{region}/iot:CredentialProvider",
                     "EndpointAddress": address, "RoleAliasCount": len(aliases.items)}], None)


def _iot_data_domains(requests, session, region, account):
    read = requests.pages(session, "iot", region, "list_domain_configurations", "domainConfigurations",
                          _tokens=("marker", "nextMarker"), serviceType="DATA")
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for summary in read.items:
        name = summary.get("domainConfigurationName") if isinstance(summary, dict) else None
        arn = summary.get("domainConfigurationArn") if isinstance(summary, dict) else None
        if (not isinstance(name, str) or not name or not isinstance(arn, str) or
                not arn.startswith(f"arn:{_partition(region)}:iot:{region}:{account}:domainconfiguration/")):
            failure = failure or ("malformed", {"code": "iot_data_domain_identity_invalid"})
            continue
        detail = requests.detail(session, "iot", region, "describe_domain_configuration",
                                 domainConfigurationName=name)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status", "unknown"),
                                  {"code": "iot_data_domain_detail_unavailable"})
            continue
        if detail.get("domainConfigurationName") != name or detail.get("domainConfigurationArn") != arn:
            failure = failure or ("malformed", {"code": "iot_data_domain_detail_identity_invalid"})
            continue
        authorizer = detail.get("authorizerConfig")
        rows.append({"id": arn, "DomainConfigurationArn": arn, "DomainConfigurationName": name,
                     "DomainName": detail.get("domainName"),
                     "Status": detail.get("domainConfigurationStatus"),
                     "DomainType": detail.get("domainType"),
                     "ServiceType": detail.get("serviceType") or summary.get("serviceType") or "DATA",
                     "AuthenticationType": detail.get("authenticationType"),
                     "ApplicationProtocol": detail.get("applicationProtocol"),
                     "DefaultAuthorizerName": authorizer.get("defaultAuthorizerName") if isinstance(authorizer, dict) else None,
                     "AllowAuthorizerOverride": authorizer.get("allowAuthorizerOverride") if isinstance(authorizer, dict) else None})
    return _finish(rows, failure)


def _iot_action_destinations(rule, *, on_error=False, http_destinations=None):
    actions = rule if isinstance(rule, list) else []
    destinations = []
    for action in actions:
        if not isinstance(action, dict):
            destinations.append({"Kind": "unknown", "OnError": on_error})
            continue
        for kind, config in action.items():
            row = {"Kind": kind, "OnError": on_error}
            if not isinstance(config, dict):
                row["Unresolved"] = True
            elif kind in ("http", "salesforce", "openSearch", "elasticsearch"):
                value = config.get("url" if kind in ("http", "salesforce") else "endpoint")
                row["DynamicUrl"] = isinstance(value, str) and "${" in value
                try:
                    parsed = urlsplit(value) if isinstance(value, str) else None
                except ValueError:
                    parsed = None
                row["TargetHost"] = (parsed.hostname if parsed and parsed.scheme == "https" and
                    parsed.hostname and "${" not in parsed.hostname and not parsed.username and not parsed.password else None)
                if kind == "http":
                    confirmation = config.get("confirmationUrl")
                    try:
                        confirmed = urlsplit(confirmation) if isinstance(confirmation, str) and "${" not in confirmation else None
                    except ValueError:
                        confirmed = None
                    row["ConfirmationHost"] = confirmed.hostname if confirmed and confirmed.scheme == "https" and not confirmed.username and not confirmed.password else None
                    if http_destinations is None:
                        row["DestinationStatus"] = "UNKNOWN"
                    else:
                        matches = []
                        for destination in http_destinations:
                            summary = destination.get("httpUrlSummary") if isinstance(destination, dict) else None
                            prefix = summary.get("confirmationUrl") if isinstance(summary, dict) else None
                            if not isinstance(prefix, str) or not isinstance(value, str) or not value.startswith(prefix):
                                continue
                            try:
                                confirmed_url = urlsplit(prefix)
                                target_url = urlsplit(value)
                                same_port = confirmed_url.port == target_url.port
                            except ValueError:
                                continue
                            if (confirmed_url.scheme == target_url.scheme == "https" and
                                    confirmed_url.hostname == target_url.hostname and
                                    same_port and
                                    confirmed_url.username is None and target_url.username is None and
                                    confirmed_url.password is None and target_url.password is None):
                                matches.append(destination.get("status"))
                        row["DestinationStatus"] = "ENABLED" if "ENABLED" in matches else "UNCONFIRMED" if not matches else "DISABLED"
            elif kind == "s3":
                row["BucketName"] = config.get("bucketName")
                row["CannedAcl"] = config.get("cannedAcl")
            elif kind in ("sns", "lambda"):
                row["TargetArn"] = config.get("targetArn" if kind == "sns" else "functionArn")
            elif kind in ("kafka", "influxDB"):
                row["DestinationArn"] = config.get("destinationArn")
            elif kind == "sqs":
                queue_url = config.get("queueUrl")
                try:
                    parsed = urlsplit(queue_url) if isinstance(queue_url, str) else None
                except ValueError:
                    parsed = None
                match = re.fullmatch(r"/([0-9]{12})/[^/]+", parsed.path) if parsed and parsed.scheme == "https" else None
                row["TargetAccount"] = match.group(1) if match else None
            destinations.append(row)
    return destinations


def _iot_topic_rules(requests, session, region, account):
    read = requests.pages(session, "iot", region, "list_topic_rules", "rules",
                          _tokens=("nextToken", "nextToken"))
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure, http_destinations = [], None, None
    for summary in read.items:
        name = summary.get("ruleName") if isinstance(summary, dict) else None
        arn = summary.get("ruleArn") if isinstance(summary, dict) else None
        if (not isinstance(name, str) or not name or not isinstance(arn, str) or
                not arn.startswith(f"arn:{_partition(region)}:iot:{region}:{account}:rule/")):
            failure = failure or ("malformed", {"code": "iot_topic_rule_identity_invalid"})
            continue
        detail = requests.detail(session, "iot", region, "get_topic_rule", ruleName=name)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status", "unknown"),
                                  {"code": "iot_topic_rule_detail_unavailable"})
            continue
        rule = detail.get("rule")
        if detail.get("ruleArn") != arn or not isinstance(rule, dict) or rule.get("ruleName") != name:
            failure = failure or ("malformed", {"code": "iot_topic_rule_detail_identity_invalid"})
            continue
        all_actions = ((rule.get("actions") if isinstance(rule.get("actions"), list) else []) +
                       ([rule["errorAction"]] if rule.get("errorAction") else []))
        if http_destinations is None and any(isinstance(action, dict) and "http" in action for action in all_actions):
            destination_read = requests.pages(session, "iot", region, "list_topic_rule_destinations",
                                              "destinationSummaries", _tokens=("nextToken", "nextToken"))
            http_destinations = destination_read.items if destination_read.status in OK else False
        destinations = _iot_action_destinations(rule.get("actions"),
            http_destinations=http_destinations if isinstance(http_destinations, list) else None)
        if rule.get("errorAction"):
            destinations.extend(_iot_action_destinations([rule["errorAction"]], on_error=True,
                http_destinations=http_destinations if isinstance(http_destinations, list) else None))
        rows.append({"id": arn, "RuleArn": arn, "RuleName": name,
                     "RuleDisabled": rule.get("ruleDisabled"), "ActionDestinations": destinations})
    return _finish(rows, failure)


def _cognito_user_pool_endpoints(requests, session, region, account):
    pools = requests.pages(session, "cognito-idp", region, "list_user_pools", "UserPools",
                           _tokens=("NextToken", "NextToken"), MaxResults=60)
    if pools.status not in OK:
        return _finish([], _cause(pools))
    rows, failure = [], None
    for summary in pools.items:
        pool_id = summary.get("Id") if isinstance(summary, dict) else None
        if not isinstance(pool_id, str) or not re.fullmatch(rf"{re.escape(region)}_[A-Za-z0-9]+", pool_id):
            failure = failure or ("malformed", {"code": "cognito_user_pool_id_invalid"})
            continue
        detail = requests.detail(session, "cognito-idp", region, "describe_user_pool", UserPoolId=pool_id)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "unknown", {"code": "cognito_user_pool_detail_unavailable"})
            continue
        config = detail.get("UserPool")
        arn = f"arn:{_partition(region)}:cognito-idp:{region}:{account}:userpool/{pool_id}"
        if not isinstance(config, dict) or config.get("Id") != pool_id or config.get("Arn") != arn:
            failure = failure or ("malformed", {"code": "cognito_user_pool_detail_identity_invalid"})
            continue
        clients = requests.pages(session, "cognito-idp", region, "list_user_pool_clients", "UserPoolClients",
                                 _tokens=("NextToken", "NextToken"), UserPoolId=pool_id, MaxResults=60)
        if clients.status not in OK:
            failure = failure or _cause(clients)
        public_clients, callback_hosts, client_complete, other_callbacks = 0, set(), clients.status in OK, 0
        supported_providers = set()
        for client in clients.items:
            client_id = client.get("ClientId") if isinstance(client, dict) else None
            if not isinstance(client_id, str) or not client_id:
                failure = failure or ("malformed", {"code": "cognito_user_pool_client_id_invalid"})
                client_complete = False
                continue
            client_detail = requests.detail(session, "cognito-idp", region, "describe_user_pool_client",
                                            UserPoolId=pool_id, ClientId=client_id)
            if client_detail.get("collection_status") != "collected":
                failure = failure or (client_detail.get("collection_status") or "unknown",
                                      {"code": "cognito_user_pool_client_detail_unavailable"})
                client_complete = False
                continue
            client_config = client_detail.get("UserPoolClient")
            if not isinstance(client_config, dict) or client_config.get("UserPoolId") != pool_id or client_config.get("ClientId") != client_id:
                failure = failure or ("malformed", {"code": "cognito_user_pool_client_detail_invalid"})
                client_complete = False
                continue
            if client_config.get("ClientSecretPresent") is False:
                public_clients += 1
            elif client_config.get("ClientSecretPresent") is not True:
                failure = failure or ("malformed", {"code": "cognito_user_pool_client_secret_state_invalid"})
                client_complete = False
            for provider in client_config.get("SupportedIdentityProviders") or []:
                if isinstance(provider, str) and provider != "COGNITO":
                    supported_providers.add(provider)
            oauth_enabled = client_config.get("AllowedOAuthFlowsUserPoolClient") is True and any(
                flow in ("code", "implicit") for flow in client_config.get("AllowedOAuthFlows") or [])
            for callback in client_config.get("CallbackURLs") or []:
                if not oauth_enabled:
                    continue
                try:
                    parsed = urlsplit(callback) if isinstance(callback, str) else None
                except ValueError:
                    parsed = None
                if (parsed and parsed.scheme == "https" and parsed.hostname and
                        parsed.username is None and parsed.password is None):
                    callback_hosts.add(parsed.hostname)
                else:
                    other_callbacks += 1
        providers = None
        if supported_providers:
            providers = requests.pages(session, "cognito-idp", region, "list_identity_providers", "Providers",
                                       _tokens=("NextToken", "NextToken"), UserPoolId=pool_id, MaxResults=60)
            if providers.status not in OK:
                failure = failure or _cause(providers)
        provider_types = {provider.get("ProviderName"): provider.get("ProviderType") for provider in providers.items
                          if isinstance(provider, dict) and isinstance(provider.get("ProviderName"), str)} if providers else {}
        federated_types = sorted({provider_types.get(name) or "UNKNOWN" for name in supported_providers})
        domains = []
        for kind, name in (("PREFIX", config.get("Domain")), ("CUSTOM", config.get("CustomDomain"))):
            if name is None:
                continue
            if not isinstance(name, str) or not name or len(name) > 253:
                failure = failure or ("malformed", {"code": "cognito_user_pool_domain_invalid"})
                continue
            found = requests.detail(session, "cognito-idp", region, "describe_user_pool_domain", Domain=name)
            if found.get("collection_status") != "collected":
                failure = failure or (found.get("collection_status") or "unknown", {"code": "cognito_user_pool_domain_unavailable"})
                domains.append({"Kind": kind, "Name": name, "Status": "UNKNOWN"})
                continue
            description = found.get("DomainDescription")
            if (not isinstance(description, dict) or description.get("Domain") != name or
                    description.get("UserPoolId") != pool_id or description.get("AWSAccountId") not in (None, account)):
                failure = failure or ("malformed", {"code": "cognito_user_pool_domain_identity_invalid"})
                domains.append({"Kind": kind, "Name": name, "Status": "UNKNOWN"})
                continue
            domains.append({"Kind": kind, "Name": name, "Status": description.get("Status")})
        signup = config.get("AdminCreateUserConfig")
        rows.append({"id": arn, "UserPoolArn": arn, "UserPoolId": pool_id,
                     "AppClientCount": len(clients.items) if clients.status in OK else None,
                     "PublicAppClientCount": public_clients if client_complete else None,
                     "OAuthCallbackHosts": sorted(callback_hosts),
                     "OtherOAuthCallbackCount": other_callbacks,
                     "FederatedProviderTypes": federated_types if client_complete and
                         (providers is None or providers.status in OK) else None,
                     "SelfSignup": signup.get("AllowAdminCreateUserOnly") is False if isinstance(signup, dict) and
                         type(signup.get("AllowAdminCreateUserOnly")) is bool else None,
                     "Domains": domains})
    return _finish(rows, failure)


def _apigatewayv2_portals(requests, session, region, account):
    read = requests.pages(session, "apigatewayv2", region, "list_portals", "Items",
                          _tokens=("NextToken", "NextToken"))
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for portal in read.items:
        portal_id = portal.get("PortalId") if isinstance(portal, dict) else None
        arn = portal.get("PortalArn") if isinstance(portal, dict) else None
        expected = f"arn:{_partition(region)}:apigateway:{region}:{account}:/portals/{portal_id}"
        if (not isinstance(portal_id, str) or not re.fullmatch(r"[a-z0-9]{10,30}", portal_id) or
                arn != expected):
            failure = failure or ("malformed", {"code": "apigatewayv2_portal_identity_invalid"})
            continue
        endpoint = portal.get("EndpointConfiguration")
        authorization = portal.get("Authorization")
        if not isinstance(endpoint, dict) or not isinstance(authorization, dict):
            failure = failure or ("malformed", {"code": "apigatewayv2_portal_configuration_invalid"})
            continue
        auth_type = "NONE" if "None" in authorization else "COGNITO" if "CognitoConfig" in authorization else "UNKNOWN"
        preview = portal.get("Preview")
        preview_url = preview.get("PreviewUrl") if isinstance(preview, dict) else None
        try:
            parsed_preview = urlsplit(preview_url) if isinstance(preview_url, str) else None
        except ValueError:
            parsed_preview = None
        preview_host = (parsed_preview.hostname if parsed_preview and parsed_preview.scheme == "https" and
                        parsed_preview.username is None and parsed_preview.password is None else None)
        products = portal.get("IncludedPortalProductArns")
        foreign_products, product_owner_unknown = set(), False
        for product in products if isinstance(products, list) else []:
            parts = product.split(":", 5) if isinstance(product, str) else []
            if (len(parts) != 6 or parts[0:2] != ["arn", _partition(region)] or parts[2] != "apigateway" or
                    parts[3] != region or not re.fullmatch(r"[0-9]{12}", parts[4]) or
                    not re.fullmatch(r"/portalproducts/[a-z0-9]{10,30}", parts[5])):
                product_owner_unknown = True
            elif parts[4] != account:
                foreign_products.add(parts[4])
        rows.append({"id": arn, "PortalArn": arn, "PortalId": portal_id,
                     "PublishStatus": portal.get("PublishStatus"),
                     "DefaultDomain": endpoint.get("PortalDefaultDomainName"),
                     "CustomDomain": endpoint.get("DomainName"),
                     "AuthType": auth_type,
                     "IncludedProductCount": len(products) if isinstance(products, list) else None,
                     "IncludedForeignProductAccounts": sorted(foreign_products),
                     "IncludedProductOwnershipUnknown": product_owner_unknown or products is None,
                     "PreviewStatus": preview.get("PreviewStatus") if isinstance(preview, dict) else None,
                     "PreviewHost": preview_host})
    return _finish(rows, failure)


def _appflow_flows(requests, session, region, account):
    read = requests.pages(session, "appflow", region, "list_flows", "flows",
                          _tokens=("nextToken", "nextToken"))
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for summary in read.items:
        name = summary.get("flowName") if isinstance(summary, dict) else None
        arn = summary.get("flowArn") if isinstance(summary, dict) else None
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][\w!@#.-]{1,255}", name) or
                arn != f"arn:{_partition(region)}:appflow:{region}:{account}:flow/{name}"):
            failure = failure or ("malformed", {"code": "appflow_flow_identity_invalid"})
            continue
        detail = requests.detail(session, "appflow", region, "describe_flow", flowName=name)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "unknown", {"code": "appflow_flow_detail_unavailable"})
            continue
        if detail.get("flowName") != name or detail.get("flowArn") != arn:
            failure = failure or ("malformed", {"code": "appflow_flow_detail_identity_invalid"})
            continue
        destinations = []
        raw_destinations = detail.get("destinationFlowConfigList")
        if not isinstance(raw_destinations, list):
            failure = failure or ("malformed", {"code": "appflow_flow_destinations_unavailable"})
            raw_destinations = []
        for destination in raw_destinations:
            if not isinstance(destination, dict) or not isinstance(destination.get("connectorType"), str):
                destinations.append({"ConnectorType": "UNKNOWN"})
                continue
            kind = destination["connectorType"]
            props = destination.get("destinationConnectorProperties")
            config = props.get(kind) if isinstance(props, dict) else None
            row = {"ConnectorType": kind, "ConnectorLabelPresent": bool(destination.get("connectorLabel"))}
            if kind in ("S3", "Upsolver"):
                row["BucketName"] = config.get("bucketName") if isinstance(config, dict) else None
            elif kind in ("Redshift", "Snowflake"):
                row["IntermediateBucketName"] = config.get("intermediateBucketName") if isinstance(config, dict) else None
            elif kind == "EventBridge":
                row["EventBus"] = config.get("object") if isinstance(config, dict) else None
            if isinstance(config, dict) and isinstance(config.get("errorHandlingConfig"), dict):
                row["ErrorBucketName"] = config["errorHandlingConfig"].get("bucketName")
            destinations.append(row)
        trigger = detail.get("triggerConfig")
        rows.append({"id": arn, "FlowArn": arn, "FlowName": name, "FlowStatus": detail.get("flowStatus"),
                     "TriggerType": trigger.get("triggerType") if isinstance(trigger, dict) else None,
                     "SourceConnectorType": (detail.get("sourceFlowConfig") or {}).get("connectorType"),
                     "Destinations": destinations})
    return _finish(rows, failure)


def _cloudmap_public_services(requests, session, region, account):
    namespaces = requests.pages(session, "servicediscovery", region, "list_namespaces", "Namespaces",
                                _tokens=("NextToken", "NextToken"))
    if namespaces.status not in OK:
        return _finish([], _cause(namespaces))
    rows, failure = [], None
    for namespace in namespaces.items:
        if not isinstance(namespace, dict) or namespace.get("Type") != "DNS_PUBLIC":
            continue
        namespace_id, name, namespace_arn = namespace.get("Id"), namespace.get("Name"), namespace.get("Arn")
        if (not isinstance(namespace_id, str) or not re.fullmatch(r"ns-[A-Za-z0-9]+", namespace_id) or
                not isinstance(name, str) or not name or
                namespace_arn != f"arn:{_partition(region)}:servicediscovery:{region}:{account}:namespace/{namespace_id}" or
                namespace.get("ResourceOwner") not in (None, account)):
            failure = failure or ("malformed", {"code": "cloudmap_public_namespace_identity_invalid"})
            continue
        services = requests.pages(session, "servicediscovery", region, "list_services", "Services",
                                  _tokens=("NextToken", "NextToken"),
                                  Filters=[{"Name": "NAMESPACE_ID", "Values": [namespace_id], "Condition": "EQ"}])
        if services.status not in OK:
            failure = failure or _cause(services)
        for service in services.items:
            service_id = service.get("Id") if isinstance(service, dict) else None
            service_arn = service.get("Arn") if isinstance(service, dict) else None
            config = service.get("DnsConfig") if isinstance(service, dict) else None
            if (not isinstance(service_id, str) or not re.fullmatch(r"srv-[A-Za-z0-9]+", service_id) or
                    service_arn != f"arn:{_partition(region)}:servicediscovery:{region}:{account}:service/{service_id}" or
                    not isinstance(config, dict) or config.get("NamespaceId") != namespace_id or
                    service.get("ResourceOwner") not in (None, account)):
                failure = failure or ("malformed", {"code": "cloudmap_public_service_identity_invalid"})
                continue
            instances = requests.pages(session, "servicediscovery", region, "list_instances", "Instances",
                                       _tokens=("NextToken", "NextToken"), ServiceId=service_id)
            if instances.status not in OK:
                failure = failure or _cause(instances)
            records = config.get("DnsRecords")
            types = sorted({record.get("Type") for record in records if isinstance(record, dict) and
                            isinstance(record.get("Type"), str)}) if isinstance(records, list) else []
            projected_instances = []
            for instance in instances.items:
                attributes = instance.get("Attributes") if isinstance(instance, dict) else None
                if not isinstance(attributes, dict):
                    failure = failure or ("malformed", {"code": "cloudmap_public_instance_attributes_invalid"})
                    continue
                projected_instances.append({"Ipv4": attributes.get("AWS_INSTANCE_IPV4"),
                                            "Ipv6": attributes.get("AWS_INSTANCE_IPV6"),
                                            "Cname": attributes.get("AWS_INSTANCE_CNAME"),
                                            "Alias": attributes.get("AWS_ALIAS_DNS_NAME"),
                                            "Port": attributes.get("AWS_INSTANCE_PORT"),
                                            "CreatedByAccount": instance.get("CreatedByAccount")})
            rows.append({"id": service_arn, "ServiceArn": service_arn, "ServiceName": service.get("Name"),
                         "NamespaceArn": namespace_arn, "NamespaceName": name, "DnsRecordTypes": types,
                         "CreatedByAccount": service.get("CreatedByAccount"),
                         "Instances": projected_instances if instances.status in OK else None})
    return _finish(rows, failure)


def _cloudsearch_domain_endpoints(requests, session, region, account):
    """Collect deployed CloudSearch endpoints, access policy and HTTPS setting."""
    detail = requests.detail(session, "cloudsearch", region, "describe_domains")
    if detail.get("collection_status") != "collected":
        status = detail.get("collection_status", "malformed")
        return _finish([], (status, {"code": (detail.get("error") or {}).get("code", "cloudsearch_domains_unavailable")}))
    domains = detail.get("DomainStatusList")
    if not isinstance(domains, list):
        return _finish([], ("malformed", {"code": "cloudsearch_domains_malformed"}))
    rows, failure = [], None
    for domain in domains:
        if not isinstance(domain, dict) or domain.get("Deleted") is True:
            continue
        name, arn = domain.get("DomainName"), domain.get("ARN")
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,27}", name) or
                arn != f"arn:{_partition(region)}:cloudsearch:{region}:{account}:domain/{name}"):
            failure = failure or ("malformed", {"code": "cloudsearch_domain_identity_invalid"})
            continue
        policy = requests.detail(session, "cloudsearch", region, "describe_service_access_policies",
                                 DomainName=name, Deployed=True)
        options = requests.detail(session, "cloudsearch", region, "describe_domain_endpoint_options",
                                  DomainName=name, Deployed=True)
        policy_status = _status(policy)
        if policy.get("collection_status") == "collected":
            access = policy.get("AccessPolicies")
            if isinstance(access, dict):
                policy_status["Options"] = access.get("Options")
                policy_status["State"] = (access.get("Status") or {}).get("State")
            else:
                failure = failure or ("malformed", {"code": "cloudsearch_access_policy_malformed"})
        else:
            failure = failure or (policy.get("collection_status", "malformed"),
                                  {"code": (policy.get("error") or {}).get("code", "cloudsearch_access_policy_unavailable")})
        endpoint_status = _status(options)
        if options.get("collection_status") == "collected":
            endpoint = options.get("DomainEndpointOptions")
            endpoint_status["EnforceHTTPS"] = (endpoint.get("Options") or {}).get("EnforceHTTPS") if isinstance(endpoint, dict) else None
        else:
            failure = failure or (options.get("collection_status", "malformed"),
                                  {"code": (options.get("error") or {}).get("code", "cloudsearch_endpoint_options_unavailable")})
        rows.append({"id": arn, "ARN": arn, "DomainName": name, "Created": domain.get("Created"),
                     "Processing": domain.get("Processing"),
                     "SearchEndpoint": (domain.get("SearchService") or {}).get("Endpoint") if isinstance(domain.get("SearchService"), dict) else None,
                     "DocumentEndpoint": (domain.get("DocService") or {}).get("Endpoint") if isinstance(domain.get("DocService"), dict) else None,
                     "DeployedPolicy": policy_status, "EndpointOptions": endpoint_status})
    return _finish(rows, failure)


def _rum_app_monitor_endpoints(requests, session, region, account):
    """Read RUM monitor ingestion configuration, policy and metrics recipients."""
    monitors = requests.pages(session, "rum", region, "list_app_monitors", "AppMonitorSummaries",
                              _tokens=("NextToken", "NextToken"))
    if monitors.status not in OK:
        return _finish([], _cause(monitors))
    rows, failure = [], None
    for summary in monitors.items:
        name = summary.get("Name") if isinstance(summary, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_#-][A-Za-z0-9._#-]{0,254}", name):
            failure = failure or ("malformed", {"code": "rum_monitor_name_invalid"})
            continue
        detail = requests.detail(session, "rum", region, "get_app_monitor", Name=name)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status", "malformed"),
                                  {"code": (detail.get("error") or {}).get("code", "rum_monitor_unavailable")})
            continue
        monitor = detail.get("AppMonitor")
        if (not isinstance(monitor, dict) or monitor.get("Name") != name or
                not isinstance(monitor.get("Id"), str) or monitor.get("Id") != summary.get("Id") or
                not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", monitor["Id"])):
            failure = failure or ("malformed", {"code": "rum_monitor_identity_invalid"})
            continue
        policy = requests.detail(session, "rum", region, "get_resource_policy", Name=name)
        policy_row = _status(policy)
        if policy.get("collection_status") == "collected":
            policy_row["PolicyDocument"] = policy.get("PolicyDocument")
        elif not policy.get("absent"):
            failure = failure or (policy.get("collection_status", "malformed"),
                                  {"code": (policy.get("error") or {}).get("code", "rum_policy_unavailable")})
        destinations = requests.pages(session, "rum", region, "list_rum_metrics_destinations", "Destinations",
                                      _tokens=("NextToken", "NextToken"), AppMonitorName=name)
        if destinations.status not in OK:
            failure = failure or _cause(destinations)
        config = monitor.get("AppMonitorConfiguration") or {}
        if not isinstance(config, dict):
            failure = failure or ("malformed", {"code": "rum_monitor_configuration_invalid"})
            config = {}
        rows.append({"id": f"arn:{_partition(region)}:rum:{region}:{account}:appmonitor/{name}",
                     "Name": name, "Id": monitor["Id"], "State": monitor.get("State"),
                     "IdentityPoolId": config.get("IdentityPoolId"), "GuestRoleArn": config.get("GuestRoleArn"),
                     "ResourcePolicy": policy_row,
                     "MetricsDestinations": _child(destinations, [_pick(d, ("Destination", "DestinationArn", "IamRoleArn"))
                                                               for d in destinations.items if isinstance(d, dict)])})
    return _finish(rows, failure)


def _config_delivery_edges(kind):
    """Project only Config cross-account authorization and delivery targets."""
    operation, expression = {
        "config_aggregation_authorization": ("describe_aggregation_authorizations", "AggregationAuthorizations"),
        "config_conformance_pack_delivery": ("describe_conformance_packs", "ConformancePackDetails"),
        "config_organization_pack_delivery": ("describe_organization_conformance_packs", "OrganizationConformancePacks"),
        "config_rule_lambda_delivery": ("describe_config_rules", "ConfigRules"),
        "config_organization_rule_lambda_delivery": ("describe_organization_config_rules", "OrganizationConfigRules"),
    }[kind]

    def fetch(requests, session, region, account):
        read = requests.pages(session, "config", region, operation, expression, _tokens=("NextToken", "NextToken"))
        if read.status not in OK:
            return _finish([], _cause(read))
        rows, failure = [], None
        for item in read.items:
            if not isinstance(item, dict):
                failure = failure or ("malformed", {"code": "config_delivery_item_invalid"})
                continue
            if kind == "config_aggregation_authorization":
                arn = item.get("AggregationAuthorizationArn")
                recipient, target_region = item.get("AuthorizedAccountId"), item.get("AuthorizedAwsRegion")
                if (not re.fullmatch(r"[0-9]{12}", str(recipient or "")) or
                        not isinstance(target_region, str) or not target_region or
                        (arn is not None and (not isinstance(arn, str) or not arn.startswith(f"arn:{_partition(region)}:config:")))):
                    failure = failure or ("malformed", {"code": "config_aggregation_identity_invalid"})
                    continue
                row = {**_pick(item, ("AggregationAuthorizationArn", "AuthorizedAccountId", "AuthorizedAwsRegion")),
                       "id": f"{account}/{region}/config-authorization/{recipient}/{target_region}"}
            elif kind == "config_conformance_pack_delivery":
                arn = item.get("ConformancePackArn")
                if not isinstance(arn, str) or not arn.startswith(f"arn:{_partition(region)}:config:{region}:{account}:"):
                    failure = failure or ("malformed", {"code": "config_pack_identity_invalid"})
                    continue
                row = {**_pick(item, ("ConformancePackArn", "ConformancePackName", "DeliveryS3Bucket")), "id": arn}
            elif kind == "config_organization_pack_delivery":
                arn = item.get("OrganizationConformancePackArn")
                if not isinstance(arn, str) or not arn.startswith(f"arn:{_partition(region)}:config:{region}:{account}:"):
                    failure = failure or ("malformed", {"code": "config_organization_pack_identity_invalid"})
                    continue
                row = {**_pick(item, ("OrganizationConformancePackArn", "OrganizationConformancePackName", "DeliveryS3Bucket")), "id": arn}
            elif kind == "config_organization_rule_lambda_delivery":
                arn = item.get("OrganizationConfigRuleArn")
                if not isinstance(arn, str) or not arn.startswith(f"arn:{_partition(region)}:config:{region}:{account}:"):
                    failure = failure or ("malformed", {"code": "config_organization_rule_identity_invalid"})
                    continue
                metadata = item.get("OrganizationCustomRuleMetadata")
                row = {**_pick(item, ("OrganizationConfigRuleArn", "OrganizationConfigRuleName")),
                       "LambdaFunctionArn": metadata.get("LambdaFunctionArn") if isinstance(metadata, dict) else None,
                       "id": arn}
            else:
                arn = item.get("ConfigRuleArn")
                if not isinstance(arn, str) or not arn.startswith(f"arn:{_partition(region)}:config:{region}:{account}:"):
                    failure = failure or ("malformed", {"code": "config_rule_identity_invalid"})
                    continue
                source = item.get("Source")
                if not isinstance(source, dict):
                    failure = failure or ("malformed", {"code": "config_rule_source_invalid"})
                    continue
                row = {**_pick(item, ("ConfigRuleArn", "ConfigRuleName", "ConfigRuleState")),
                       "Source": _pick(source, ("Owner", "SourceIdentifier")), "id": arn}
            rows.append(row)
        return _finish(rows, failure)
    return fetch


def _backup_search_exports(requests, session, region, account):
    """Export-job status and bucket only; no search terms or result paths."""
    exports = requests.pages(session, "backupsearch", region, "list_search_result_export_jobs", "ExportJobs",
                             _tokens=("NextToken", "NextToken"))
    if exports.status not in OK:
        return _finish([], _cause(exports))
    rows, failure = [], None
    for summary in exports.items:
        job_id = summary.get("ExportJobIdentifier") if isinstance(summary, dict) else None
        arn = summary.get("ExportJobArn") if isinstance(summary, dict) else None
        if (not isinstance(job_id, str) or not job_id or
                arn != f"arn:{_partition(region)}:backup-search:{region}:{account}:search-export-job/{job_id}"):
            failure = failure or ("malformed", {"code": "backup_search_export_identity_invalid"})
            continue
        detail = requests.detail(session, "backupsearch", region, "get_search_result_export_job",
                                 ExportJobIdentifier=job_id)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status", "malformed"),
                                  {"code": (detail.get("error") or {}).get("code", "backup_search_export_unavailable")})
            continue
        if detail.get("ExportJobIdentifier") != job_id or detail.get("ExportJobArn") != arn:
            failure = failure or ("malformed", {"code": "backup_search_export_detail_mismatch"})
            continue
        spec = detail.get("ExportSpecification")
        s3 = spec.get("s3ExportSpecification") if isinstance(spec, dict) else None
        if not isinstance(s3, dict) or not isinstance(s3.get("DestinationBucket"), str):
            failure = failure or ("malformed", {"code": "backup_search_export_destination_invalid"})
            continue
        rows.append({"id": arn, "ExportJobArn": arn, "ExportJobIdentifier": job_id,
                     "Status": detail.get("Status"), "DestinationBucket": s3["DestinationBucket"]})
    return _finish(rows, failure)


def _devicefarm_project_children(kind):
    operation, response_key, fields = {
        "devicefarm_upload": ("list_uploads", "uploads", ("arn", "name", "type", "status", "category")),
        "devicefarm_device_pool": ("list_device_pools", "devicePools", ("arn", "name", "type", "maxDevices")),
    }[kind]

    def fetch(requests, session, region, account):
        projects = requests.pages(session, "devicefarm", region, "list_projects", "projects")
        if projects.status not in OK:
            return _finish([], _cause(projects))
        rows, failure = [], None
        project_prefix = f"arn:{_partition(region)}:devicefarm:{region}:{account}:project:"
        for project in projects.items:
            project_arn = project.get("arn") if isinstance(project, dict) else None
            if (not isinstance(project_arn, str) or not project_arn.startswith(project_prefix)
                    or not re.fullmatch(r"[A-Za-z0-9-]+", project_arn[len(project_prefix):])):
                failure = failure or ("malformed", {"code": "malformed_devicefarm_project"})
                continue
            children = requests.pages(session, "devicefarm", region, operation, response_key, arn=project_arn)
            if children.status not in OK:
                failure = failure or _cause(children)
            for child in children.items:
                arn = child.get("arn") if isinstance(child, dict) else None
                if kind == "devicefarm_upload":
                    valid_arn = isinstance(arn, str) and arn.startswith(
                        project_arn.replace(":project:", ":upload:") + "/")
                else:
                    pool_prefix = f"arn:{_partition(region)}:devicefarm:{region}:"
                    valid_arn = isinstance(arn, str) and any(
                        arn.startswith(pool_prefix + owner + ":devicepool:") and
                        re.fullmatch(r"[A-Za-z0-9-]+", arn[len(pool_prefix + owner + ":devicepool:"):])
                        for owner in (account, ""))
                if not valid_arn:
                    failure = failure or ("malformed", {"code": "malformed_devicefarm_child"})
                    continue
                row = {**_pick(child, fields), "ProjectArn": project_arn, "id": arn}
                if kind == "devicefarm_device_pool":
                    compatibility = requests.detail(session, "devicefarm", region,
                        "get_device_pool_compatibility", devicePoolArn=arn,
                        projectArn=project_arn, testType="APPIUM_WEB_NODE")
                    status = compatibility.get("collection_status")
                    if status != "collected":
                        failure = failure or (status or "unknown", {"code": "devicefarm_pool_compatibility_unavailable"})
                    elif not isinstance(compatibility.get("compatibleDevices"), list):
                        failure = failure or ("malformed", {"code": "malformed_devicefarm_pool_compatibility"})
                    else:
                        row["CompatibleWebNodeDevices"] = sum(
                            device.get("compatible") is True for device in compatibility["compatibleDevices"]
                            if isinstance(device, dict))
                rows.append(row)
        return _finish(rows, failure)
    return fetch


def _partition(region):
    return "aws-us-gov" if region.startswith("us-gov-") else "aws-cn" if region.startswith("cn-") else "aws"


def _pick(value, keys):
    return {key: copy.deepcopy(value[key]) for key in keys if isinstance(value, dict) and key in value}


def _cause(read, default="read_incomplete"):
    error = read.error or {}
    return error.get("cause_status", read.status), {"code": error.get("code", default)}


def _finish(items, failure):
    ReadResult = _aws().ReadResult
    if failure:
        status, error = failure
        return ReadResult(items, "partial" if items else status, {**error, "cause_status": status})
    return ReadResult(items, "collected" if items else "empty")


def _child(read, rows=None):
    out = {"collection_status": read.status, "items": read.items if rows is None else rows}
    if read.error:
        out["error"] = {"code": (read.error or {}).get("code")}
    return out


def _status(response):
    """Detail response metadata only (status, absence, error code)."""
    out = {"collection_status": response.get("collection_status")}
    if response.get("absent"):
        out["absent"] = True
    if response.get("error"):
        out["error"] = {"code": (response.get("error") or {}).get("code")}
    return out


def _raw(requests, session, service, region, operation, **arguments):
    """(response, None) or (None, (status, code)). Identical reads are single-flight cache hits."""
    try:
        return requests.call(session, service, region, operation, **arguments), None
    except Exception as exc:
        failure = _aws()._failure(exc)
        return None, (failure.status, failure.code)


def _functions(requests, session, region):
    # Identical to the lambda_function inventory read (single-flight cache).
    return requests.pages(session, "lambda", region, "list_functions", "Functions")


def _clusters(requests, session, region):
    return requests.pages(session, "eks", region, "list_clusters", "clusters")


# ------------------------------------------------------------------------- Lambda
def _layer_versions(requests, session, region, account):
    layers = requests.pages(session, "lambda", region, "list_layers", "Layers")
    if layers.status not in OK:
        return _finish([], _cause(layers))
    policy = _aws()._policy
    items, failure = [], None
    for layer in layers.items:
        name = layer.get("LayerName") if isinstance(layer, dict) else None
        if not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_layer"})
            continue
        versions = requests.pages(session, "lambda", region, "list_layer_versions", "LayerVersions", LayerName=name)
        if versions.status not in OK:
            failure = failure or _cause(versions)
        for version in versions.items:
            number = version.get("Version") if isinstance(version, dict) else None
            if not isinstance(number, int) or isinstance(number, bool):
                failure = failure or ("malformed", {"code": "malformed_layer_version"})
                continue
            row = {"LayerName": name, "LayerArn": layer.get("LayerArn"),
                   **_pick(version, ("LayerVersionArn", "Version", "CreatedDate", "CompatibleRuntimes", "CompatibleArchitectures"))}
            row["id"] = row.get("LayerVersionArn") or f"{name}:{number}"
            response = requests.detail(session, "lambda", region, "get_layer_version_policy", absent=("ResourceNotFoundException",),
                                       LayerName=name, VersionNumber=number)
            row["Policy"] = _status(response)
            if response.get("collection_status") == "collected":
                row["Policy"]["Policy"] = policy(response.get("Policy"))
            items.append(row)
    return _finish(items, failure)


def _versions(requests, session, region, account):
    functions = _functions(requests, session, region)
    if functions.status not in OK:
        return _finish([], _cause(functions))
    items, failure = [], None
    for function in functions.items:
        name = function.get("FunctionName") if isinstance(function, dict) else None
        base = function.get("FunctionArn") if isinstance(function, dict) else None
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or
                base != f"arn:{_partition(region)}:lambda:{region}:{account}:function:{name}"):
            failure = failure or ("malformed", {"code": "lambda_function_identity_mismatch"})
            continue
        versions = requests.pages(session, "lambda", region, "list_versions_by_function", "Versions", FunctionName=name)
        if versions.status not in OK:
            failure = failure or _cause(versions)
        for version in versions.items:
            number = version.get("Version") if isinstance(version, dict) else None
            arn = version.get("FunctionArn") if isinstance(version, dict) else None
            if number == "$LATEST":
                continue
            if (not isinstance(number, str) or not number.isdigit() or int(number) < 1 or
                    arn != f"{base}:{number}"):
                failure = failure or ("malformed", {"code": "lambda_version_identity_mismatch"})
                continue
            policy = requests.detail(session, "lambda", region, "get_policy",
                                     FunctionName=name, Qualifier=number, absent=("ResourceNotFoundException",))
            if "Policy" in policy:
                policy["Policy"] = _aws()._policy(policy["Policy"])
            items.append({"id": arn, "FunctionName": name, "BaseFunctionArn": base,
                          "FunctionArn": arn, "Version": number, "Role": version.get("Role"), "Policy": policy})
    return _finish(items, failure)


def _client_vpn_routing(requests, session, region, account):
    endpoints = requests.pages(session, "ec2", region, "describe_client_vpn_endpoints", "ClientVpnEndpoints")
    if endpoints.status not in OK:
        return _finish([], _cause(endpoints))
    rows, failure, seen = [], None, set()
    for endpoint in endpoints.items:
        eid = endpoint.get("ClientVpnEndpointId") if isinstance(endpoint, dict) else None
        if not isinstance(eid, str) or not re.fullmatch(r"cvpn-endpoint-[a-z0-9]+", eid) or eid in seen:
            failure = failure or ("malformed", {"code": "client_vpn_endpoint_identity_invalid"})
            continue
        seen.add(eid)
        status = endpoint.get("Status")
        if not isinstance(status, dict) or status.get("Code") != "available":
            continue
        routes = requests.pages(session, "ec2", region, "describe_client_vpn_routes", "Routes", ClientVpnEndpointId=eid)
        targets = requests.pages(session, "ec2", region, "describe_client_vpn_target_networks", "ClientVpnTargetNetworks", ClientVpnEndpointId=eid)
        rules = requests.pages(session, "ec2", region, "describe_client_vpn_authorization_rules", "AuthorizationRules", ClientVpnEndpointId=eid)
        if routes.status not in OK:
            failure = failure or _cause(routes)
        if targets.status not in OK:
            failure = failure or _cause(targets)
        if rules.status not in OK:
            failure = failure or _cause(rules)
        rows.append({"id": eid, "ClientVpnEndpointId": eid,
            "Routes": {"ClientVpnEndpointId": eid, **_child(routes, [_pick(item, (
                "ClientVpnEndpointId", "DestinationCidr", "TargetSubnet", "Type", "Origin", "Status", "TransitGatewayAttachmentId"))
                for item in routes.items])},
            "TargetNetworks": {"ClientVpnEndpointId": eid, **_child(targets, [_pick(item, (
                "AssociationId", "VpcId", "TargetNetworkId", "ClientVpnEndpointId", "Status", "SecurityGroups"))
                for item in targets.items])},
            "AuthorizationRules": {"ClientVpnEndpointId": eid, **_child(rules, [_pick(item, (
                "ClientVpnEndpointId", "Status", "AccessAll", "GroupId", "DestinationCidr"))
                for item in rules.items])}})
    return _finish(rows, failure)


def _transit_gateway_peering(requests, session, region, account):
    read = requests.pages(session, "ec2", region, "describe_transit_gateway_peering_attachments",
                          "TransitGatewayPeeringAttachments")
    if read.status not in OK and not read.items:
        return _finish([], _cause(read))
    rows, failure = [], _cause(read) if read.status not in OK else None
    for item in read.items:
        attachment = item.get("TransitGatewayAttachmentId") if isinstance(item, dict) else None
        if not isinstance(attachment, str) or not re.fullmatch(r"tgw-attach-[0-9a-f]+", attachment):
            failure = failure or ("malformed", {"code": "malformed_transit_gateway_peering_attachment"})
            continue
        row = _pick(item, ("TransitGatewayAttachmentId", "State", "RequesterTgwInfo", "AccepterTgwInfo"))
        row["id"] = attachment
        rows.append(row)
    return _finish(rows, failure)


def _redshiftserverless_snapshots(requests, session, region, account):
    read = requests.pages(session, "redshift-serverless", region, "list_snapshots", "snapshots")
    if read.status not in OK:
        return _finish([], _cause(read))
    items, failure = [], None
    for item in read.items:
        if not isinstance(item, dict) or not isinstance(item.get("snapshotArn"), str):
            failure = failure or ("malformed", {"code": "malformed_serverless_snapshot"})
            continue
        row = _pick(item, ("snapshotArn", "snapshotName", "ownerAccount", "status", "kmsKeyId",
                           "accountsWithRestoreAccess", "accountsWithProvisionedRestoreAccess"))
        row["id"] = item["snapshotArn"]
        items.append(row)
    return _finish(items, failure)


def _cluster_snapshots(service):
    def fetch(requests, session, region, account):
        read = requests.pages(session, service, region, "describe_db_cluster_snapshots", "DBClusterSnapshots",
                              IncludeShared=False, IncludePublic=False)
        if read.status not in OK:
            return _finish([], _cause(read))
        items, failure = [], None
        for item in read.items:
            name = item.get("DBClusterSnapshotIdentifier") if isinstance(item, dict) else None
            arn = item.get("DBClusterSnapshotArn") if isinstance(item, dict) else None
            if not isinstance(name, str) or not name or not isinstance(arn, str):
                failure = failure or ("malformed", {"code": "malformed_cluster_snapshot"})
                continue
            row = _pick(item, ("DBClusterSnapshotIdentifier", "DBClusterSnapshotArn", "DBClusterIdentifier",
                               "SnapshotType", "Status", "StorageEncrypted", "KmsKeyId", "Engine"))
            row["id"] = arn
            if item.get("SnapshotType") == "manual":
                detail = requests.detail(session, service, region, "describe_db_cluster_snapshot_attributes",
                                         DBClusterSnapshotIdentifier=name, absent=("DBClusterSnapshotNotFoundFault",))
                row["Attributes"] = _status(detail)
                if detail.get("collection_status") == "collected":
                    row["Attributes"]["DBClusterSnapshotAttributesResult"] = _pick(
                        detail.get("DBClusterSnapshotAttributesResult"),
                        ("DBClusterSnapshotIdentifier", "DBClusterSnapshotAttributes"))
            items.append(row)
        return _finish(items, failure)
    return fetch


def _aliases(requests, session, region, account):
    functions = _functions(requests, session, region)
    if functions.status not in OK:
        return _finish([], _cause(functions))
    items, failure = [], None
    for function in functions.items:
        name = function.get("FunctionName") if isinstance(function, dict) else None
        if not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_function"})
            continue
        read = requests.pages(session, "lambda", region, "list_aliases", "Aliases", FunctionName=name)
        if read.status not in OK:
            failure = failure or _cause(read)
        for alias in read.items:
            if not isinstance(alias, dict) or not isinstance(alias.get("AliasArn"), str):
                failure = failure or ("malformed", {"code": "malformed_alias"})
                continue
            alias_name = alias.get("Name")
            if (not isinstance(alias_name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", alias_name)
                    or alias_name.isdigit() or alias["AliasArn"] != str(function.get("FunctionArn")) + ":" + alias_name):
                failure = failure or ("malformed", {"code": "lambda_alias_identity_mismatch"})
                continue
            row = _pick(alias, ("AliasArn", "Name", "FunctionVersion", "RoutingConfig"))
            row.update({"FunctionName": name, "FunctionArn": function.get("FunctionArn"), "id": alias["AliasArn"]})
            url = requests.detail(session, "lambda", region, "get_function_url_config",
                                  FunctionName=name, Qualifier=alias_name, absent=("ResourceNotFoundException",))
            if url.get("collection_status") == "collected" and url.get("FunctionArn") != alias["AliasArn"]:
                url = {"collection_status": "malformed", "error": {"code": "lambda_alias_url_identity_mismatch"}}
            row["FunctionUrl"] = url
            policy = requests.detail(session, "lambda", region, "get_policy",
                                     FunctionName=name, Qualifier=alias_name, absent=("ResourceNotFoundException",))
            if "Policy" in policy:
                policy["Policy"] = _aws()._policy(policy["Policy"])
            row["Policy"] = policy
            items.append(row)
    return _finish(items, failure)


def _event_source_mappings(requests, session, region, account):
    read = requests.pages(session, "lambda", region, "list_event_source_mappings", "EventSourceMappings")
    items = []
    for mapping in read.items:
        if not isinstance(mapping, dict) or not isinstance(mapping.get("UUID"), str):
            continue
        row = _pick(mapping, _ESM_FIELDS)
        if isinstance(mapping.get("FilterCriteria"), dict):
            row["FilterCount"] = len(mapping["FilterCriteria"].get("Filters") or [])
        if isinstance(mapping.get("SourceAccessConfigurations"), list):
            # References only (secret / VPC ARNs), never resolved.
            row["SourceAccessConfigurations"] = [_pick(x, ("Type", "URI")) for x in mapping["SourceAccessConfigurations"] if isinstance(x, dict)]
        if isinstance(mapping.get("SelfManagedEventSource"), dict):
            row["SelfManagedEventSource"] = {"EndpointTypes": sorted((mapping["SelfManagedEventSource"].get("Endpoints") or {}).keys())}
        row["id"] = mapping.get("EventSourceMappingArn") or mapping["UUID"]
        items.append(row)
    if len(items) != len(read.items) and read.status in OK:
        return _finish(items, ("malformed", {"code": "malformed_event_source_mapping"}))
    read.items = items
    return read


def _lambda_function(requests, session, region, items):
    """Environment variable NAMES (from the cached GetFunctionConfiguration response) and runtime management mode."""
    output = []
    for item in items:
        item = copy.deepcopy(item)
        name = item.get("FunctionName") if isinstance(item, dict) else None
        if not isinstance(name, str):
            output.append(item)
            continue
        response, failure = _raw(requests, session, "lambda", region, "get_function_configuration", FunctionName=name)
        if failure:
            item["EnvironmentVariableNames"] = {"collection_status": failure[0], "error": {"code": failure[1]}}
        else:
            environment = response.get("Environment") if isinstance(response, dict) else None
            variables = environment.get("Variables") if isinstance(environment, dict) else None
            if environment is None or (isinstance(environment, dict) and variables is None and not environment.get("Error")):
                item["EnvironmentVariableNames"] = {"collection_status": "empty", "names": []}
            elif isinstance(variables, dict):
                names = sorted(str(key) for key in variables)
                item["EnvironmentVariableNames"] = {"collection_status": "collected" if names else "empty", "names": names}
            else:
                item["EnvironmentVariableNames"] = {"collection_status": "not_collected", "error": {"code": "environment_unreadable"}}
        if item.get("PackageType") == "Image":
            item["RuntimeManagement"] = {"collection_status": "empty", "absent": True, "reason": "container_image_function"}
        else:
            runtime = requests.detail(session, "lambda", region, "get_runtime_management_config", FunctionName=name)
            item["RuntimeManagement"] = {**_status(runtime), **_pick(runtime, ("UpdateRuntimeOn", "RuntimeVersionArn"))}
        output.append(item)
    return output


# ------------------------------------------------------------------------- ECR
def _ecr_registry(requests, session, region, account):
    policy = _aws()._policy
    registry = requests.detail(session, "ecr", region, "describe_registry")
    registry_policy = requests.detail(session, "ecr", region, "get_registry_policy", absent=("RegistryPolicyNotFoundException",))
    caches = requests.pages(session, "ecr", region, "describe_pull_through_cache_rules", "pullThroughCacheRules")
    templates = requests.pages(session, "ecr", region, "describe_repository_creation_templates", "repositoryCreationTemplates")
    statuses = [registry.get("collection_status"), registry_policy.get("collection_status"), caches.status, templates.status]
    if all(status not in OK for status in statuses) and len(set(statuses)) == 1:
        return _aws().ReadResult([], statuses[0], {"code": (registry.get("error") or {}).get("code", "registry_unreadable")})
    row = {"id": f"ecr-registry/{account}/{region}", "registryId": registry.get("registryId") or account}
    row["Replication"] = _status(registry)
    if registry.get("collection_status") == "collected":
        configuration = registry.get("replicationConfiguration")
        rules = configuration.get("rules", []) if isinstance(configuration, dict) else ([] if configuration is None else None)
        if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
            row["Replication"]["collection_status"] = "malformed"
            row["Replication"]["error"] = {"code": "malformed_replication_rules"}
        else:
            row["Replication"]["rules"] = [_pick(rule, ("destinations", "repositoryFilters")) for rule in rules]
    row["RegistryPolicy"] = _status(registry_policy)
    if registry_policy.get("collection_status") == "collected":
        row["RegistryPolicy"]["policyText"] = policy(registry_policy.get("policyText"))
    row["PullThroughCacheRules"] = _child(caches, [_pick(x, ("ecrRepositoryPrefix", "upstreamRegistryUrl", "upstreamRegistry",
        "upstreamRepositoryPrefix", "credentialArn", "customRoleArn", "registryId")) for x in caches.items if isinstance(x, dict)])
    rows = []
    for template in templates.items:
        if not isinstance(template, dict):
            continue
        entry = _pick(template, ("prefix", "appliedFor", "imageTagMutability", "customRoleArn", "encryptionConfiguration"))
        if "repositoryPolicy" in template:
            entry["repositoryPolicy"] = policy(template.get("repositoryPolicy"))
        rows.append(entry)
    row["RepositoryCreationTemplates"] = _child(templates, rows)
    return _aws().ReadResult([row], "collected")


# ------------------------------------------------------------------------- EKS
def _access_entries(requests, session, region, account):
    clusters = _clusters(requests, session, region)
    if clusters.status not in OK:
        return _finish([], _cause(clusters))
    items, failure = [], None
    for cluster in clusters.items:
        if not isinstance(cluster, str):
            failure = failure or ("malformed", {"code": "malformed_cluster"})
            continue
        entries = requests.pages(session, "eks", region, "list_access_entries", "accessEntries", clusterName=cluster)
        if entries.status not in OK:
            # Clusters in CONFIG_MAP mode answer InvalidRequestException: no access entries API.
            if (entries.error or {}).get("code") != "InvalidRequestException":
                failure = failure or _cause(entries)
            continue
        for principal in entries.items:
            if not isinstance(principal, str):
                failure = failure or ("malformed", {"code": "malformed_access_entry"})
                continue
            row = {"clusterName": cluster, "principalArn": principal, "id": f"{cluster}/{principal}"}
            detail = requests.detail(session, "eks", region, "describe_access_entry", clusterName=cluster, principalArn=principal)
            entry = detail.get("accessEntry") if detail.get("collection_status") == "collected" else None
            if isinstance(entry, dict):
                row.update(_pick(entry, ("accessEntryArn", "type", "kubernetesGroups", "username", "createdAt", "modifiedAt")))
                row["id"] = entry.get("accessEntryArn") or row["id"]
            else:
                row["_coverage"] = {"type": {"status": detail.get("collection_status") or "malformed", "source_operation": "eks:DescribeAccessEntry"}}
            policies = requests.pages(session, "eks", region, "list_associated_access_policies", "associatedAccessPolicies",
                                      clusterName=cluster, principalArn=principal)
            row["AssociatedAccessPolicies"] = _child(policies, [_pick(x, ("policyArn", "accessScope")) for x in policies.items if isinstance(x, dict)])
            items.append(row)
    return _finish(items, failure)


def _pod_identity_associations(requests, session, region, account):
    clusters = _clusters(requests, session, region)
    if clusters.status not in OK:
        return _finish([], _cause(clusters))
    items, failure = [], None
    for cluster in clusters.items:
        if not isinstance(cluster, str):
            continue
        read = requests.pages(session, "eks", region, "list_pod_identity_associations", "associations", clusterName=cluster)
        if read.status not in OK:
            failure = failure or _cause(read)
        for association in read.items:
            if not isinstance(association, dict) or not isinstance(association.get("associationId"), str):
                failure = failure or ("malformed", {"code": "malformed_pod_identity_association"})
                continue
            row = _pick(association, ("clusterName", "namespace", "serviceAccount", "associationArn", "associationId", "ownerArn"))
            row["clusterName"] = cluster
            row["id"] = association.get("associationArn") or f"{cluster}/{association['associationId']}"
            detail = requests.detail(session, "eks", region, "describe_pod_identity_association", clusterName=cluster,
                                     associationId=association["associationId"])
            found = detail.get("association") if detail.get("collection_status") == "collected" else None
            if isinstance(found, dict):
                row.update(_pick(found, ("roleArn", "targetRoleArn", "disableSessionTags", "externalId")))
                row.pop("externalId", None)
            else:
                row["_coverage"] = {"roleArn": {"status": detail.get("collection_status") or "malformed",
                                                "source_operation": "eks:DescribePodIdentityAssociation"}}
            items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- KMS
def _kms_grants(requests, session, region, account):
    keys = requests.pages(session, "kms", region, "list_keys", "Keys")
    if keys.status not in OK:
        return _finish([], _cause(keys))
    items, failure = [], None
    for key in keys.items:
        key_id = key.get("KeyId") if isinstance(key, dict) else None
        if not isinstance(key_id, str):
            failure = failure or ("malformed", {"code": "malformed_key"})
            continue
        # Same read as the kms_key inventory enrichment (cache hit).
        metadata = requests.detail(session, "kms", region, "describe_key", KeyId=key_id)
        manager = (metadata.get("KeyMetadata") or {}).get("KeyManager") if metadata.get("collection_status") == "collected" else None
        if manager == "AWS":
            continue  # AWS managed keys carry service grants only.
        if manager is None:
            failure = failure or (metadata.get("collection_status") or "malformed", {"code": "key_metadata_unavailable"})
            continue
        read = requests.pages(session, "kms", region, "list_grants", "Grants", KeyId=key_id)
        if read.status not in OK:
            failure = failure or _cause(read)
        for grant in read.items:
            if not isinstance(grant, dict) or not isinstance(grant.get("GrantId"), str):
                failure = failure or ("malformed", {"code": "malformed_grant"})
                continue
            row = _pick(grant, ("GrantId", "Name", "GranteePrincipal", "RetiringPrincipal", "IssuingAccount", "Operations", "CreationDate"))
            constraints = grant.get("Constraints")
            if isinstance(constraints, dict):
                row["ConstraintKeys"] = {name: sorted(value) for name, value in constraints.items() if isinstance(value, dict)}
            row.update({"KeyId": key_id, "KeyArn": key.get("KeyArn"), "id": f"{key.get('KeyArn') or key_id}/grant/{grant['GrantId']}"})
            items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- Cognito
def _identity_pool(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        pool = item.get("IdentityPoolId") if isinstance(item, dict) else None
        if isinstance(pool, str):
            response = requests.detail(session, "cognito-identity", region, "get_identity_pool_roles", IdentityPoolId=pool)
            item["Roles"] = {**_status(response), **_pick(response, ("Roles", "RoleMappings"))}
        output.append(item)
    return output


def _user_pool(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        pool = item.get("Id") if isinstance(item, dict) else None
        if isinstance(pool, str):
            providers = requests.pages(session, "cognito-idp", region, "list_identity_providers", "Providers", UserPoolId=pool, MaxResults=60)
            item["IdentityProviders"] = _child(providers, [_pick(x, ("ProviderName", "ProviderType")) for x in providers.items if isinstance(x, dict)])
            mfa = requests.detail(session, "cognito-idp", region, "get_user_pool_mfa_config", UserPoolId=pool)
            row = {**_status(mfa), **_pick(mfa, ("MfaConfiguration",))}
            if mfa.get("collection_status") == "collected":
                row["SoftwareTokenMfaEnabled"] = bool((mfa.get("SoftwareTokenMfaConfiguration") or {}).get("Enabled"))
                row["SmsMfaConfigured"] = "SmsMfaConfiguration" in mfa
                row["EmailMfaConfigured"] = "EmailMfaConfiguration" in mfa
                row["WebAuthnConfigured"] = "WebAuthnConfiguration" in mfa
            item["MfaConfig"] = row
            groups = requests.pages(session, "cognito-idp", region, "list_groups", "Groups", UserPoolId=pool)
            item["Groups"] = _child(groups, [_pick(x, ("GroupName", "RoleArn", "Precedence")) for x in groups.items if isinstance(x, dict)])
        output.append(item)
    return output


# ------------------------------------------------------------------------- OpenSearch
def _opensearch_connections(requests, session, region, account):
    keys = ("ConnectionId", "ConnectionAlias", "ConnectionMode", "LocalDomainInfo", "RemoteDomainInfo")
    items, failure = [], None
    for direction, operation in (("outbound", "describe_outbound_connections"), ("inbound", "describe_inbound_connections")):
        read = requests.pages(session, "opensearch", region, operation, "Connections", _tokens=("NextToken", "NextToken"))
        if read.status not in OK:
            failure = failure or _cause(read)
        for connection in read.items:
            if not isinstance(connection, dict) or not isinstance(connection.get("ConnectionId"), str):
                failure = failure or ("malformed", {"code": "malformed_connection"})
                continue
            row = _pick(connection, keys)
            row["StatusCode"] = (connection.get("ConnectionStatus") or {}).get("StatusCode")
            row.update({"Direction": direction, "id": f"{direction}/{connection['ConnectionId']}"})
            items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- Route 53 (global)
def _record_sets(requests, session, region, account):
    zones = requests.pages(session, "route53", region, "list_hosted_zones", "HostedZones")
    if zones.status not in OK:
        return _finish([], _cause(zones))
    items, failure = [], None
    for zone in zones.items:
        zone_id = zone.get("Id") if isinstance(zone, dict) else None
        if not isinstance(zone_id, str):
            failure = failure or ("malformed", {"code": "malformed_zone"})
            continue
        private = bool((zone.get("Config") or {}).get("PrivateZone"))
        read = requests.pages(session, "route53", region, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zone_id)
        if read.status not in OK:
            failure = failure or _cause(read)
        for record in read.items:
            if not isinstance(record, dict) or not isinstance(record.get("Name"), str) or not isinstance(record.get("Type"), str):
                failure = failure or ("malformed", {"code": "malformed_record"})
                continue
            row = _pick(record, ("Name", "Type", "TTL", "SetIdentifier", "AliasTarget", "Region", "Failover", "HealthCheckId"))
            values = [x.get("Value") for x in record.get("ResourceRecords") or [] if isinstance(x, dict)]
            if record["Type"] in _RECORD_VALUE_TYPES:
                row["Values"] = [v for v in values if isinstance(v, str)]
            else:
                row["ValueCount"] = len(values)
            row.update({"HostedZoneId": zone_id, "HostedZoneName": zone.get("Name"), "PrivateZone": private, "AccountId": account,
                        "id": f"{zone_id}/{record['Name']}/{record['Type']}/{record.get('SetIdentifier', '')}"})
            items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- CloudFormation / EC2 / Roles Anywhere
def _stack_instances(requests, session, region, account):
    sets = requests.pages(session, "cloudformation", region, "list_stack_sets", "Summaries", Status="ACTIVE")
    if sets.status not in OK:
        return _finish([], _cause(sets))
    items, failure = [], None
    for stack_set in sets.items:
        name = stack_set.get("StackSetName") if isinstance(stack_set, dict) else None
        if not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_stack_set"})
            continue
        read = requests.pages(session, "cloudformation", region, "list_stack_instances", "Summaries", StackSetName=name)
        if read.status not in OK:
            failure = failure or _cause(read)
        for instance in read.items:
            if not isinstance(instance, dict):
                continue
            row = _pick(instance, ("StackSetId", "Account", "Region", "StackId", "Status", "OrganizationalUnitId", "DriftStatus"))
            row.update({"StackSetName": name, "PermissionModel": stack_set.get("PermissionModel"),
                        "AutoDeployment": copy.deepcopy(stack_set.get("AutoDeployment")),
                        "id": f"{stack_set.get('StackSetId') or name}/{instance.get('Account')}/{instance.get('Region')}"})
            items.append(row)
    return _finish(items, failure)


def _stackset_organizations_access(requests, session, region, account):
    response, failure = _raw(requests, session, "cloudformation", region, "describe_organizations_access")
    if failure:
        status, code = failure
        return _finish([], (status, {"code": code}))
    status = response.get("Status") if isinstance(response, dict) else None
    if status not in {"ENABLED", "DISABLED", "DISABLED_PERMANENTLY"}:
        return _finish([], ("malformed", {"code": "invalid_organizations_access_status"}))
    return _finish([{"id": f"{account}/{region}", "Status": status}], None)


def _instance_connect_endpoints(requests, session, region, account):
    read = requests.pages(session, "ec2", region, "describe_instance_connect_endpoints", "InstanceConnectEndpoints")
    keys = ("InstanceConnectEndpointId", "InstanceConnectEndpointArn", "OwnerId", "State", "VpcId", "SubnetId", "AvailabilityZone",
            "PreserveClientIp", "SecurityGroupIds", "IpAddressType", "CreatedAt", "Tags")
    items = []
    for endpoint in read.items:
        if isinstance(endpoint, dict) and isinstance(endpoint.get("InstanceConnectEndpointId"), str):
            row = _pick(endpoint, keys)
            row["id"] = endpoint.get("InstanceConnectEndpointArn") or endpoint["InstanceConnectEndpointId"]
            items.append(row)
    read.items = items
    return read


def _rolesanywhere_profiles(requests, session, region, account):
    read = requests.pages(session, "rolesanywhere", region, "list_profiles", "profiles")
    policy = _aws()._policy
    keys = ("profileArn", "profileId", "name", "enabled", "roleArns", "managedPolicyArns", "requireInstanceProperties",
            "durationSeconds", "acceptRoleSessionName", "attributeMappings", "createdAt", "updatedAt")
    items = []
    for profile in read.items:
        if not isinstance(profile, dict) or not isinstance(profile.get("profileArn"), str):
            continue
        row = _pick(profile, keys)
        if "managedPolicyArns" in profile:
            managed = profile["managedPolicyArns"]
            if (not isinstance(managed, list) or any(not isinstance(arn, str) or
                    re.fullmatch(r"arn:[a-z0-9-]+:iam::(?:[0-9]{12}|aws):policy/\S+", arn) is None
                    for arn in managed)):
                continue
        elif read.status in OK:
            # ProfileDetail omits this optional array when no managed session
            # policies are configured. Only a successful complete ListProfiles
            # read authenticates that omission; unreadability is not absence.
            row["managedPolicyArns"] = []
            row.setdefault("_coverage", {})["managedPolicyArns"] = {
                "status": "empty", "reason": "documented_optional_api_omission",
                "source_operation": "rolesanywhere:ListProfiles", "native_member_present": False}
        row["SessionPolicy"] = policy(profile["sessionPolicy"]) if profile.get("sessionPolicy") else None
        row["id"] = profile["profileArn"]
        items.append(row)
    if len(items) != len(read.items) and read.status in OK:
        return _finish(items, ("malformed", {"code": "malformed_profile"}))
    read.items = items
    return read


# ------------------------------------------------------------------------- workload hosts
def _recipe_components(requests, session, region, recipe):
    """Component ARNs of an image recipe only: no recipe content, component parameters, block devices or user data."""
    response = requests.detail(session, "imagebuilder", region, "get_image_recipe", imageRecipeArn=recipe)
    out = _status(response)
    if response.get("collection_status") == "collected":
        components = ((response.get("imageRecipe") or {}).get("components"))
        arns = [c.get("componentArn") for c in components or () if isinstance(c, dict)]
        if not isinstance(components, list) or not all(isinstance(a, str) for a in arns):
            return {"collection_status": "malformed", "error": {"code": "malformed_image_recipe"}}
        out["items"] = list(dict.fromkeys(arns))
    return out


def _image_pipelines(requests, session, region, account):
    pipelines = requests.pages(session, "imagebuilder", region, "list_image_pipelines", "imagePipelineList")
    if pipelines.status not in OK:
        return _finish([], _cause(pipelines))
    configs = requests.pages(session, "imagebuilder", region, "list_infrastructure_configurations", "infrastructureConfigurationSummaryList")
    profiles = {c.get("arn"): c.get("instanceProfileName") for c in configs.items if isinstance(c, dict)}
    items, failure, recipes = [], None, {}
    for pipeline in pipelines.items:
        if not isinstance(pipeline, dict) or not isinstance(pipeline.get("arn"), str):
            failure = failure or ("malformed", {"code": "malformed_pipeline"})
            continue
        row = _pick(pipeline, ("arn", "name", "status", "platform", "infrastructureConfigurationArn", "executionRole", "imageRecipeArn",
                               "containerRecipeArn", "dateLastRun"))
        infra = pipeline.get("infrastructureConfigurationArn")
        if isinstance(profiles.get(infra), str):
            row["InstanceProfileName"] = profiles[infra]
        else:
            row["_coverage"] = {"InstanceProfileName": {"status": configs.status if configs.status not in OK else "not_collected",
                                                        "source_operation": "imagebuilder:ListInfrastructureConfigurations"}}
        recipe = pipeline.get("imageRecipeArn")
        if isinstance(recipe, str):
            if recipe not in recipes:
                recipes[recipe] = _recipe_components(requests, session, region, recipe)
            row["RecipeComponents"] = copy.deepcopy(recipes[recipe])
        row["id"] = pipeline["arn"]
        items.append(row)
    if configs.status not in OK and items:
        failure = failure or _cause(configs)
    return _finish(items, failure)


def _image_distributions(requests, session, region, account):
    """Keep only account selectors from Image Builder AMI distribution settings."""
    read = requests.pages(session, "imagebuilder", region, "list_distribution_configurations",
                          "distributionConfigurationSummaryList")
    if read.status not in OK and not read.items:
        return _finish([], _cause(read))
    items, failure = [], _cause(read) if read.status not in OK else None
    prefix = f"arn:{_partition(region)}:imagebuilder:{region}:{account}:distribution-configuration/"
    for summary in read.items:
        arn = summary.get("arn") if isinstance(summary, dict) else None
        if not isinstance(arn, str) or not arn.startswith(prefix) or not arn[len(prefix):]:
            failure = failure or ("malformed", {"code": "unattributed_image_distribution"})
            continue
        row = {"id": arn, "arn": arn}
        detail = requests.detail(session, "imagebuilder", region, "get_distribution_configuration",
                                 distributionConfigurationArn=arn)
        status = detail.get("collection_status")
        config = detail.get("distributionConfiguration")
        if status != "collected":
            row["Distribution"] = {"collection_status": status,
                                   "error": {"code": (detail.get("error") or {}).get("code")}}
        elif not isinstance(config, dict) or config.get("arn") != arn or not isinstance(config.get("distributions"), list):
            row["Distribution"] = {"collection_status": "malformed"}
        else:
            regions = []
            for distribution in config["distributions"]:
                if not isinstance(distribution, dict):
                    regions.append(None)
                    continue
                ami = distribution.get("amiDistributionConfiguration")
                regions.append({"region": distribution.get("region"),
                                "ami": _pick(ami, ("targetAccountIds", "launchPermission")) if isinstance(ami, dict) else None})
            row["Distribution"] = {"collection_status": "collected", "arn": arn, "items": regions}
        items.append(row)
    return _finish(items, failure)


def _agentcore_gateways(requests, session, region, account):
    """Project gateway URL and inbound auth state without JWT settings or interceptor content."""
    read = requests.pages(session, "bedrock-agentcore-control", region, "list_gateways", "items")
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for summary in read.items:
        gateway_id = summary.get("gatewayId") if isinstance(summary, dict) else None
        if not isinstance(gateway_id, str) or not gateway_id:
            failure = failure or ("malformed", {"code": "agentcore_gateway_id_invalid"})
            continue
        detail = requests.detail(session, "bedrock-agentcore-control", region, "get_gateway",
                                 gatewayIdentifier=gateway_id)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "not_collected",
                                  {"code": "agentcore_gateway_detail_unavailable"})
            continue
        arn = f"arn:{_partition(region)}:bedrock-agentcore:{region}:{account}:gateway/{gateway_id}"
        if detail.get("gatewayId") != gateway_id or detail.get("gatewayArn") != arn:
            failure = failure or ("malformed", {"code": "agentcore_gateway_identity_invalid"})
            continue
        rows.append({"id": arn, "GatewayArn": arn, "GatewayUrl": detail.get("gatewayUrl"),
                     "Status": detail.get("status"), "AuthorizerType": detail.get("authorizerType"),
                     "HasInterceptor": bool(detail.get("interceptorConfigurations")),
                     "PolicyEngineMode": (detail.get("policyEngineConfiguration") or {}).get("mode")
                                         if isinstance(detail.get("policyEngineConfiguration"), dict) else None,
                     "WebAclArn": detail.get("webAclArn"),
                     "_provenance": {"source_operation": "bedrock-agentcore-control:GetGateway", "read_only": True}})
    return _finish(rows, failure)


def _eventbridge_pipes(requests, session, region, account):
    """Keep Pipe destination identities, not filter patterns, input templates or credentials."""
    read = requests.pages(session, "pipes", region, "list_pipes", "Pipes")
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for summary in read.items:
        name = summary.get("Name") if isinstance(summary, dict) else None
        arn = f"arn:{_partition(region)}:pipes:{region}:{account}:pipe/{name}"
        if not isinstance(name, str) or not name or summary.get("Arn") != arn:
            failure = failure or ("malformed", {"code": "eventbridge_pipe_identity_invalid"})
            continue
        detail = requests.detail(session, "pipes", region, "describe_pipe", Name=name)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "not_collected",
                                  {"code": "eventbridge_pipe_detail_unavailable"})
            continue
        if detail.get("Arn") != arn or detail.get("Name") != name:
            failure = failure or ("malformed", {"code": "eventbridge_pipe_detail_identity_invalid"})
            continue
        log = detail.get("LogConfiguration") or {}
        source = detail.get("SourceParameters") or {}
        dead_letters = []
        for key in ("DynamoDBStreamParameters", "KinesisStreamParameters"):
            part = source.get(key) if isinstance(source, dict) else None
            dlq = part.get("DeadLetterConfig") if isinstance(part, dict) else None
            if isinstance(dlq, dict) and isinstance(dlq.get("Arn"), str):
                dead_letters.append(dlq["Arn"])
        rows.append({"id": arn, "Arn": arn, "Name": name,
                     "CurrentState": detail.get("CurrentState"), "DesiredState": detail.get("DesiredState"),
                     "TargetArn": detail.get("Target"), "EnrichmentArn": detail.get("Enrichment"),
                     "DeadLetterArns": dead_letters,
                     "LogFirehoseArn": (log.get("FirehoseLogDestination") or {}).get("DeliveryStreamArn")
                                       if isinstance(log.get("FirehoseLogDestination"), dict) else None,
                     "LogBucketOwner": (log.get("S3LogDestination") or {}).get("BucketOwner")
                                       if isinstance(log.get("S3LogDestination"), dict) else None,
                     "LogBucketName": (log.get("S3LogDestination") or {}).get("BucketName")
                                      if isinstance(log.get("S3LogDestination"), dict) else None,
                     "_provenance": {"source_operation": "pipes:DescribePipe", "read_only": True}})
    return _finish(rows, failure)


def _cleanrooms_collaborations(requests, session, region, account):
    """Active memberships, associated table count, and collaborator account IDs only."""
    read = requests.pages(session, "cleanrooms", region, "list_memberships", "membershipSummaries")
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for member in read.items:
        if not isinstance(member, dict) or member.get("status") != "ACTIVE":
            continue
        mid, cid = member.get("id"), member.get("collaborationId")
        arn = member.get("arn")
        if not all(isinstance(x, str) and x for x in (mid, cid, arn)) or f":{account}:membership/" not in arn:
            failure = failure or ("malformed", {"code": "cleanrooms_membership_identity_invalid"})
            continue
        collaborators = requests.pages(session, "cleanrooms", region, "list_members", "memberSummaries",
                                       collaborationIdentifier=cid)
        associations = requests.pages(session, "cleanrooms", region, "list_configured_table_associations",
                                      "configuredTableAssociationSummaries", membershipIdentifier=mid)
        if collaborators.status not in OK or associations.status not in OK:
            failure = failure or _cause(collaborators if collaborators.status not in OK else associations)
        rows.append({"id": arn, "MembershipArn": arn, "CollaborationId": cid,
                     "CreatorAccountId": member.get("collaborationCreatorAccountId"),
                     "MemberAccounts": [_pick(x, ("accountId", "status", "abilities")) for x in collaborators.items
                                        if isinstance(x, dict)],
                     "MemberReadStatus": collaborators.status, "AssociationReadStatus": associations.status,
                     "AssociatedTableCount": len(associations.items),
                     "_provenance": {"source_operation": "cleanrooms:ListMemberships,ListMembers,ListConfiguredTableAssociations",
                                     "read_only": True}})
    return _finish(rows, failure)


def _auditmanager_destinations(requests, session, region, account):
    """Assessment and default report/export bucket locations, without assessment evidence."""
    read = requests.pages(session, "auditmanager", region, "list_assessments", "assessmentMetadata")
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    settings, error = _raw(requests, session, "auditmanager", region, "get_settings", attribute="ALL")
    if error:
        failure = (error[0], {"code": error[1]})
    else:
        info = settings.get("settings") if isinstance(settings, dict) else None
        if isinstance(info, dict):
            for name, key in (("default_report", "defaultAssessmentReportsDestination"),
                              ("default_export", "defaultExportDestination")):
                dest = info.get(key)
                if isinstance(dest, dict) and isinstance(dest.get("destination"), str):
                    rows.append({"id": f"arn:{_partition(region)}:auditmanager:{region}:{account}:settings/{name}",
                                 "DestinationKind": name, "Destination": dest["destination"]})
    for summary in read.items:
        aid = summary.get("id") if isinstance(summary, dict) else None
        if not isinstance(aid, str) or not aid:
            failure = failure or ("malformed", {"code": "auditmanager_assessment_id_invalid"})
            continue
        detail, error = _raw(requests, session, "auditmanager", region, "get_assessment", assessmentId=aid)
        if error:
            failure = failure or (error[0], {"code": error[1]})
            continue
        assessment = detail.get("assessment") if isinstance(detail, dict) else None
        metadata = assessment.get("metadata") if isinstance(assessment, dict) else None
        dest = metadata.get("assessmentReportsDestination") if isinstance(metadata, dict) else None
        if isinstance(dest, dict) and isinstance(dest.get("destination"), str):
            rows.append({"id": f"arn:{_partition(region)}:auditmanager:{region}:{account}:assessment/{aid}",
                         "DestinationKind": "assessment_report", "Destination": dest["destination"]})
    return _finish(rows, failure)


def _lightsail_distributions(requests, session, region, account):
    if region != "us-east-1":
        return _finish([], None)
    read = requests.pages(session, "lightsail", region, "get_distributions", "distributions",
                          _tokens=("pageToken", "nextPageToken"))
    if read.status not in OK:
        return _finish([], _cause(read))
    rows = [{**_pick(x, ("arn", "isEnabled", "domainName", "status")), "id": x.get("arn")}
            for x in read.items if isinstance(x, dict) and isinstance(x.get("arn"), str)]
    return _finish(rows, None)


def _domain_roles(requests, session, region, domain):
    response, failure = _raw(requests, session, "sagemaker", region, "describe_domain", DomainId=domain)
    if failure or not isinstance(response, dict):
        return None
    return {"DefaultUserExecutionRole": (response.get("DefaultUserSettings") or {}).get("ExecutionRole"),
            "DefaultSpaceExecutionRole": (response.get("DefaultSpaceSettings") or {}).get("ExecutionRole")}


def _user_profiles(requests, session, region, account):
    read = requests.pages(session, "sagemaker", region, "list_user_profiles", "UserProfiles")
    if read.status not in OK:
        return _finish([], _cause(read))
    items, failure = [], None
    for profile in read.items:
        domain = profile.get("DomainId") if isinstance(profile, dict) else None
        name = profile.get("UserProfileName") if isinstance(profile, dict) else None
        if not isinstance(domain, str) or not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_user_profile"})
            continue
        row = {"DomainId": domain, "UserProfileName": name, "Status": profile.get("Status"), "id": f"{domain}/{name}"}
        detail = requests.detail(session, "sagemaker", region, "describe_user_profile", DomainId=domain, UserProfileName=name)
        if detail.get("collection_status") != "collected":
            row["_coverage"] = {"ExecutionRole": {"status": detail.get("collection_status"), "source_operation": "sagemaker:DescribeUserProfile"}}
            items.append(row)
            continue
        row["UserProfileArn"] = detail.get("UserProfileArn")
        row["id"] = detail.get("UserProfileArn") or row["id"]
        role = (detail.get("UserSettings") or {}).get("ExecutionRole")
        if isinstance(role, str) and role:
            row.update({"ExecutionRole": role, "ExecutionRoleSource": "user_settings"})
        else:
            defaults = _domain_roles(requests, session, region, domain)
            if defaults is None:
                row["_coverage"] = {"ExecutionRole": {"status": "not_collected", "source_operation": "sagemaker:DescribeDomain"}}
            elif defaults.get("DefaultUserExecutionRole"):
                row.update({"ExecutionRole": defaults["DefaultUserExecutionRole"], "ExecutionRoleSource": "domain_default"})
            else:
                row["ExecutionRole"] = None
        items.append(row)
    return _finish(items, failure)


def _sagemaker_domain(requests, session, region, items):
    output = []
    for item in items:
        item = copy.deepcopy(item)
        domain = item.get("DomainId") if isinstance(item, dict) else None
        defaults = _domain_roles(requests, session, region, domain) if isinstance(domain, str) else None
        if defaults is not None:
            item.update({key: value for key, value in defaults.items() if value})
        output.append(item)
    return output


def _spaces(requests, session, region, account):
    read = requests.pages(session, "sagemaker", region, "list_spaces", "Spaces")
    if read.status not in OK:
        return _finish([], _cause(read))
    output, failure = [], None
    for space in read.items:
        domain = space.get("DomainId") if isinstance(space, dict) else None
        name = space.get("SpaceName") if isinstance(space, dict) else None
        if not isinstance(domain, str) or not domain or not isinstance(name, str) or not name:
            failure = failure or ("malformed", {"code": "malformed_space"})
            continue
        row = {"DomainId": domain, "SpaceName": name, "id": f"{domain}/{name}"}
        detail = requests.detail(session, "sagemaker", region, "describe_space", DomainId=domain, SpaceName=name)
        if detail.get("collection_status") != "collected":
            row["_coverage"] = {"SpaceDetails": {"status": detail.get("collection_status"),
                                                   "source_operation": "sagemaker:DescribeSpace"}}
            output.append(row)
            failure = failure or (detail.get("collection_status") or "not_collected", {"code": "space_detail_unavailable"})
            continue
        arn = detail.get("SpaceArn")
        expected_arn = f"arn:{_partition(region)}:sagemaker:{region}:{account}:space/{domain}/{name}"
        if arn != expected_arn or detail.get("DomainId") not in (None, domain) or detail.get("SpaceName") not in (None, name):
            failure = failure or ("malformed", {"code": "missing_space_arn"})
            output.append(row)
            continue
        settings = detail.get("SpaceSettings") or {}
        summary_settings = space.get("SpaceSettingsSummary") or {}
        detail_sharing = (detail.get("SpaceSharingSettings") or {}).get("SharingType")
        summary_sharing = (space.get("SpaceSharingSettingsSummary") or {}).get("SharingType")
        detail_owner = (detail.get("OwnershipSettings") or {}).get("OwnerUserProfileName")
        summary_owner = (space.get("OwnershipSettingsSummary") or {}).get("OwnerUserProfileName")
        detail_app, summary_app = settings.get("AppType"), summary_settings.get("AppType")
        if any(a and b and a != b for a, b in ((detail_sharing, summary_sharing),
                                                (detail_owner, summary_owner), (detail_app, summary_app),
                                                (detail.get("Status"), space.get("Status")))):
            row["_coverage"] = {"SpaceDetails": {"status": "malformed", "source_operation": "sagemaker:DescribeSpace"}}
            failure = failure or ("malformed", {"code": "space_list_detail_mismatch"})
            output.append(row)
            continue
        sharing = detail_sharing or summary_sharing
        owner = detail_owner or summary_owner
        row.update({"id": arn, "SpaceArn": arn, "Status": detail.get("Status") or space.get("Status"),
                    "AppType": detail_app or summary_app, "SharingType": sharing,
                    "OwnerUserProfileName": owner})
        if sharing == "Shared":
            defaults = _domain_roles(requests, session, region, domain)
            if defaults is None:
                row["_coverage"] = {"ExecutionRole": {"status": "not_collected", "source_operation": "sagemaker:DescribeDomain"}}
                failure = failure or ("not_collected", {"code": "space_domain_role_unavailable"})
            else:
                row["ExecutionRole"] = defaults.get("DefaultSpaceExecutionRole")
                row["ExecutionRoleSource"] = "domain_default_space"
        elif sharing == "Private" and isinstance(owner, str) and owner:
            profile = requests.detail(session, "sagemaker", region, "describe_user_profile",
                                      DomainId=domain, UserProfileName=owner)
            if profile.get("collection_status") != "collected":
                row["_coverage"] = {"ExecutionRole": {"status": profile.get("collection_status"),
                                                       "source_operation": "sagemaker:DescribeUserProfile"}}
                failure = failure or (profile.get("collection_status") or "not_collected", {"code": "space_owner_role_unavailable"})
            else:
                role = (profile.get("UserSettings") or {}).get("ExecutionRole")
                if isinstance(role, str) and role:
                    row["ExecutionRole"] = role
                    row["ExecutionRoleSource"] = "owner_user_settings"
                else:
                    defaults = _domain_roles(requests, session, region, domain)
                    if defaults is None:
                        row["_coverage"] = {"ExecutionRole": {"status": "not_collected", "source_operation": "sagemaker:DescribeDomain"}}
                        failure = failure or ("not_collected", {"code": "space_domain_role_unavailable"})
                    else:
                        row["ExecutionRole"] = defaults.get("DefaultUserExecutionRole")
                        row["ExecutionRoleSource"] = "domain_default_user"
        else:
            row["_coverage"] = {"ExecutionRole": {"status": "malformed", "source_operation": "sagemaker:DescribeSpace"}}
            failure = failure or ("malformed", {"code": "space_sharing_or_owner_missing"})
        output.append(row)
    return _finish(output, failure)


def _hyperpod_clusters(requests, session, region, account):
    read = requests.pages(session, "sagemaker", region, "list_clusters", "ClusterSummaries")
    if read.status not in OK:
        return _finish([], _cause(read))
    items, failure = [], None
    for cluster in read.items:
        name = cluster.get("ClusterName") if isinstance(cluster, dict) else None
        if not isinstance(name, str):
            failure = failure or ("malformed", {"code": "malformed_cluster"})
            continue
        row = {**_pick(cluster, ("ClusterArn", "ClusterName", "ClusterStatus")), "id": cluster.get("ClusterArn") or name}
        detail = requests.detail(session, "sagemaker", region, "describe_cluster", ClusterName=name)
        if detail.get("collection_status") != "collected":
            row["_coverage"] = {"InstanceGroups": {"status": detail.get("collection_status"), "source_operation": "sagemaker:DescribeCluster"}}
        else:
            groups = []
            for field in ("InstanceGroups", "RestrictedInstanceGroups"):
                groups += [_pick(g, ("InstanceGroupName", "InstanceType", "ExecutionRole", "CurrentCount", "Status", "ImageId"))
                           for g in detail.get(field) or [] if isinstance(g, dict)]
            row["InstanceGroups"] = groups
            row["Orchestrator"] = copy.deepcopy(detail.get("Orchestrator"))
        items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- application planes
def _gamelift_ec2_computes(requests, session, region, account):
    """Join fleet role configuration to its computes without requesting access tokens."""
    fleets = requests.pages(session, "gamelift", region, "list_fleets", "FleetIds")
    if fleets.status not in OK:
        return _finish([], _cause(fleets))
    rows, failure = [], None
    for fleet_id in fleets.items:
        if not isinstance(fleet_id, str) or not fleet_id:
            failure = failure or ("malformed", {"code": "malformed_fleet_id"})
            continue
        if fleet_id.startswith("containerfleet-"):
            # DescribeFleetAttributes supports EC2/Anywhere, not containers.
            continue
        attributes = requests.pages(session, "gamelift", region, "describe_fleet_attributes",
                                    "FleetAttributes", FleetIds=[fleet_id])
        if attributes.status not in OK:
            failure = failure or _cause(attributes)
            continue
        if len(attributes.items) != 1 or not isinstance(attributes.items[0], dict):
            failure = failure or ("malformed", {"code": "missing_fleet_attributes"})
            continue
        fleet = attributes.items[0]
        if fleet.get("ComputeType") != "EC2":
            continue
        arn = fleet.get("FleetArn")
        valid_arns = {f"arn:{_partition(region)}:gamelift:{region}:{owner}:fleet/{fleet_id}"
                      for owner in ("", account)}
        if fleet.get("FleetId") != fleet_id or arn not in valid_arns:
            failure = failure or ("malformed", {"code": "fleet_identity_mismatch"})
            continue
        computes = requests.pages(session, "gamelift", region, "list_compute", "ComputeList", FleetId=fleet_id)
        ports = requests.pages(session, "gamelift", region, "describe_fleet_port_settings", "InboundPermissions", FleetId=fleet_id)
        if computes.status not in OK:
            failure = failure or _cause(computes)
        if ports.status not in OK:
            failure = failure or _cause(ports)
        compute_rows = []
        for compute in computes.items:
            if (not isinstance(compute, dict) or compute.get("FleetId") != fleet_id
                    or (compute.get("FleetArn") not in (None, arn))
                    or not isinstance(compute.get("ComputeName"), str)):
                failure = failure or ("malformed", {"code": "compute_identity_mismatch"})
                continue
            compute_rows.append(_pick(compute, ("FleetId", "FleetArn", "ComputeName", "ComputeStatus", "IpAddress")))
        row = _pick(fleet, ("FleetId", "FleetArn", "ComputeType", "Status", "InstanceRoleArn",
                            "InstanceRoleCredentialsProvider"))
        row.update({"id": arn, "Computes": _child(computes, compute_rows),
                    "InboundPermissions": _child(ports, [_pick(x, ("FromPort", "ToPort", "IpRange", "Protocol"))
                                                       for x in ports.items if isinstance(x, dict)])})
        rows.append(row)
    return _finish(rows, failure)


def _grafana_workspaces(requests, session, region, account):
    read = requests.pages(session, "grafana", region, "list_workspaces", "workspaces")
    items = []
    for workspace in read.items:
        if isinstance(workspace, dict) and isinstance(workspace.get("id"), str):
            row = _pick(workspace, ("id", "name", "status", "authentication", "licenseType", "grafanaVersion", "created", "modified"))
            row["Arn"] = f"arn:{_partition(region)}:grafana:{region}:{account}:/workspaces/{workspace['id']}"
            version = re.match(r"^(\d+)(?:\.|$)", str(workspace.get("grafanaVersion") or ""))
            if version and int(version.group(1)) < 9:
                row["ServiceAccounts"] = {"collection_status": "empty", "items": []}
            else:
                accounts = requests.pages(session, "grafana", region,
                                          "list_workspace_service_accounts", "serviceAccounts",
                                          workspaceId=workspace["id"])
                summaries = [_pick(item, ("id", "name", "grafanaRole", "isDisabled"))
                             for item in accounts.items if isinstance(item, dict)]
                row["ServiceAccounts"] = _child(accounts, summaries)
            items.append(row)
    read.items = items
    return read


def _quicksight_users(requests, session, region, account):
    read = requests.pages(session, "quicksight", region, "list_users", "UserList", AwsAccountId=account, Namespace="default")
    if read.status not in OK and (read.error or {}).get("code") in ("ResourceNotFoundException", "UnsupportedUserEditionException"):
        # No QuickSight subscription (or no user management) in this account.
        return _aws().ReadResult([], "empty", {"code": "service_not_enabled"})
    items = []
    for user in read.items:
        if isinstance(user, dict) and isinstance(user.get("Arn"), str):
            items.append({**_pick(user, ("Arn", "UserName", "PrincipalId", "Role", "IdentityType", "Active", "CustomPermissionsName")), "id": user["Arn"]})
    read.items = items
    return read


def _quicksight_account_subscription(requests, session, region, account):
    response, failure = _raw(requests, session, "quicksight", region, "describe_account_subscription", AwsAccountId=account)
    if failure:
        status, code = failure
        if code in ("ResourceNotFoundException", "UnsupportedUserEditionException"):
            return _aws().ReadResult([], "empty", {"code": "service_not_enabled"})
        return _aws().ReadResult([], status, {"code": code})
    info = response.get("AccountInfo") if isinstance(response, dict) else None
    if not isinstance(info, dict) or not isinstance(info.get("AccountSubscriptionStatus"), str) or not isinstance(info.get("AuthenticationType"), str):
        return _aws().ReadResult([], "malformed", {"code": "missing_subscription_state"})
    row = _pick(info, ("AccountSubscriptionStatus", "AuthenticationType"))
    row["id"] = account
    return _aws().ReadResult([row], "collected")


def _supplychain_instances(requests, session, region, account):
    read = requests.pages(session, "supplychain", region, "list_instances", "instances")
    items = []
    for instance in read.items:
        if isinstance(instance, dict) and isinstance(instance.get("instanceId"), str):
            row = _pick(instance, ("instanceId", "awsAccountId", "state", "instanceName", "kmsKeyArn", "webAppDnsDomain", "createdTime"))
            row["Arn"] = f"arn:{_partition(region)}:scn:{region}:{instance.get('awsAccountId') or account}:instance/{instance['instanceId']}"
            row["id"] = row["Arn"]
            items.append(row)
    read.items = items
    return read


def _amplify_apps(requests, session, region, account):
    read = requests.pages(session, "amplify", region, "list_apps", "apps")
    if read.status not in OK:
        return _finish([], _cause(read))
    items, failure = [], None
    for app in read.items:
        if not isinstance(app, dict) or not isinstance(app.get("appId"), str):
            failure = failure or ("malformed", {"code": "malformed_app"})
            continue
        # Never environmentVariables, basicAuthCredentials, buildSpec or customHeaders.
        row = _pick(app, ("appId", "appArn", "name", "platform", "iamServiceRoleArn", "computeRoleArn", "defaultDomain", "enableBasicAuth",
                          "createTime", "updateTime"))
        row["RepositoryConnected"] = bool(app.get("repository"))
        row["AppBuildSpecPresent"] = (app["AppBuildSpecPresent"] if type(app.get("AppBuildSpecPresent")) is bool
                                      else bool(app.get("buildSpec")))
        if "AdditionalSecretIndicators" in app:
            row["AdditionalSecretIndicators"] = copy.deepcopy(app["AdditionalSecretIndicators"])
        row["id"] = app.get("appArn") or app["appId"]
        backends = requests.pages(session, "amplify", region, "list_backend_environments", "backendEnvironments",
                                  _tokens=("nextToken", "nextToken"), appId=app["appId"])
        row["BackendEnvironments"] = _child(backends, [_pick(x, ("backendEnvironmentArn", "environmentName", "stackName"))
                                                       for x in backends.items if isinstance(x, dict)])
        branches = requests.pages(session, "amplify", region, "list_branches", "branches",
                                  _tokens=("nextToken", "nextToken"), appId=app["appId"])
        row["Branches"] = _child(branches, [
            {**_pick(x, ("branchArn", "branchName", "displayName", "stage", "enableAutoBuild", "enableBasicAuth", "framework", "computeRoleArn")),
             "BranchBuildSpecPresent": bool(x.get("buildSpec"))}
            for x in branches.items if isinstance(x, dict)])
        domains = requests.pages(session, "amplify", region, "list_domain_associations", "domainAssociations",
                                 _tokens=("nextToken", "nextToken"), appId=app["appId"])
        row["DomainAssociations"] = _child(domains, [
            {**_pick(x, ("domainAssociationArn", "domainName", "domainStatus", "enableAutoSubDomain")),
             "subDomains": [
                 {"subDomainSetting": _pick(sub.get("subDomainSetting", {}), ("prefix", "branchName")),
                  "verified": sub.get("verified")}
                 for sub in x.get("subDomains", []) if isinstance(sub, dict)]}
            for x in domains.items if isinstance(x, dict)])
        items.append(row)
    return _finish(items, failure)


# ------------------------------------------------------------------------- Identity Center
def _account_assignments(requests, session, region, account):
    instances = requests.pages(session, "sso-admin", region, "list_instances", "Instances")
    if instances.status not in OK:
        return _finish([], _cause(instances))
    items, failure = [], None
    for instance in instances.items:
        arn = instance.get("InstanceArn") if isinstance(instance, dict) else None
        if not isinstance(arn, str):
            failure = failure or ("malformed", {"code": "malformed_identity_center_instance"})
            continue
        names = {}
        store = instance.get("IdentityStoreId")
        if isinstance(store, str) and store:
            groups = requests.pages(session, "identitystore", region, "list_groups", "Groups", IdentityStoreId=store)
            names = {g.get("GroupId"): g.get("DisplayName") for g in groups.items if isinstance(g, dict)}
        sets = requests.pages(session, "sso-admin", region, "list_permission_sets", "PermissionSets", InstanceArn=arn)
        if sets.status not in OK:
            failure = failure or _cause(sets)
        for permission_set in sets.items:
            if not isinstance(permission_set, str):
                failure = failure or ("malformed", {"code": "malformed_permission_set_arn"})
                continue
            accounts = requests.pages(session, "sso-admin", region, "list_accounts_for_provisioned_permission_set", "AccountIds",
                                      InstanceArn=arn, PermissionSetArn=permission_set)
            if accounts.status not in OK:
                failure = failure or _cause(accounts)
            for target in accounts.items:
                if not isinstance(target, str):
                    continue
                read = requests.pages(session, "sso-admin", region, "list_account_assignments", "AccountAssignments",
                                      InstanceArn=arn, AccountId=target, PermissionSetArn=permission_set)
                if read.status not in OK:
                    failure = failure or _cause(read)
                for assignment in read.items:
                    if not isinstance(assignment, dict) or not isinstance(assignment.get("PrincipalId"), str):
                        failure = failure or ("malformed", {"code": "malformed_account_assignment"})
                        continue
                    row = _pick(assignment, ("AccountId", "PermissionSetArn", "PrincipalType", "PrincipalId"))
                    row.update({"InstanceArn": arn, "InstanceOwnerAccountId": instance.get("OwnerAccountId"),
                                "id": f"{arn}/{target}/{permission_set}/{assignment.get('PrincipalType')}/{assignment['PrincipalId']}"})
                    if assignment.get("PrincipalType") == "GROUP" and names.get(assignment["PrincipalId"]):
                        row["GroupDisplayName"] = names[assignment["PrincipalId"]]
                    items.append(row)
    return _finish(items, failure)


def _cloud9_environment_shares(requests, session, region, account):
    listed = requests.pages(session, "cloud9", region, "list_environments", "environmentIds")
    failure = _cause(listed) if listed.status not in OK else None
    items = []
    for environment_id in listed.items:
        if not isinstance(environment_id, str) or not re.fullmatch(r"[A-Za-z0-9]{8,32}", environment_id):
            failure = failure or ("malformed", {"code": "malformed_cloud9_environment_id"})
            continue
        detail = requests.detail(session, "cloud9", region, "describe_environments", environmentIds=[environment_id])
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status", "malformed"),
                                  {"code": (detail.get("error") or {}).get("code", "cloud9_environment_detail_incomplete")})
            continue
        environments = detail.get("environments")
        if not isinstance(environments, list) or len(environments) != 1 or not isinstance(environments[0], dict):
            failure = failure or ("malformed", {"code": "malformed_cloud9_environment_detail"})
            continue
        environment = environments[0]
        arn = f"arn:{_partition(region)}:cloud9:{region}:{account}:environment:{environment_id}"
        if environment.get("id") != environment_id:
            failure = failure or ("malformed", {"code": "mismatched_cloud9_environment_detail"})
            continue
        # ListEnvironments also returns environments shared with the caller.
        observed_arn, owner_arn = environment.get("arn"), environment.get("ownerArn")
        observed = re.fullmatch(rf"arn:{_partition(region)}:cloud9:{region}:([0-9]{{12}}):environment:{environment_id}",
                                observed_arn) if isinstance(observed_arn, str) else None
        owner = re.fullmatch(rf"arn:{_partition(region)}:(?:iam|sts)::([0-9]{{12}}):"
                             r"(?:root|(?:user|role|federated-user|assumed-role)/\S+)",
                             owner_arn) if isinstance(owner_arn, str) else None
        if not observed or not owner or observed.group(1) != owner.group(1):
            failure = failure or ("malformed", {"code": "unattributed_cloud9_environment"})
            continue
        if observed.group(1) != account:
            continue
        members = requests.pages(session, "cloud9", region, "describe_environment_memberships", "memberships",
                                 environmentId=environment_id)
        rows = [_pick(member, ("environmentId", "permissions", "userArn")) if isinstance(member, dict) else None
                for member in members.items]
        row = {"id": arn, "arn": arn, "environmentId": environment_id,
               "ownerArn": owner_arn, "Members": _child(members, rows)}
        items.append(row)
    return _finish(items, failure)


def _omics_resource_shares(requests, session, region, account):
    read = requests.pages(session, "omics", region, "list_shares", "shares", resourceOwner="SELF")
    failure = _cause(read) if read.status not in OK else None
    items = []
    prefix = f"arn:{_partition(region)}:omics:{region}:{account}:"
    for share in read.items:
        if not isinstance(share, dict) or not isinstance(share.get("shareId"), str) or not share["shareId"]:
            failure = failure or ("malformed", {"code": "malformed_omics_share"})
            continue
        arn = share.get("resourceArn")
        if (not isinstance(arn, str) or not arn.startswith(prefix) or
                not re.fullmatch(r"(?:variantStore|annotationStore|workflow)/[^\s/:]+", arn[len(prefix):]) or
                share.get("ownerId") != account):
            failure = failure or ("malformed", {"code": "unattributed_omics_share"})
            continue
        row = _pick(share, ("shareId", "resourceArn", "ownerId", "principalSubscriber", "status"))
        row["id"] = f"{arn}/share/{share['shareId']}"
        items.append(row)
    return _finish(items, failure)


def _wellarchitected_workload_shares(requests, session, region, account):
    listed = requests.pages(session, "wellarchitected", region, "list_workloads", "WorkloadSummaries",
                            _tokens=("NextToken", "NextToken"))
    failure = _cause(listed) if listed.status not in OK else None
    items = []
    for workload in listed.items:
        if not isinstance(workload, dict):
            failure = failure or ("malformed", {"code": "malformed_wellarchitected_workload"})
            continue
        workload_id, owner, arn = workload.get("WorkloadId"), workload.get("Owner"), workload.get("WorkloadArn")
        if not isinstance(workload_id, str) or not re.fullmatch(r"[0-9a-f]{32}", workload_id):
            failure = failure or ("malformed", {"code": "malformed_wellarchitected_workload_id"})
            continue
        if (not isinstance(owner, str) or not re.fullmatch(r"[0-9]{12}", owner) or
                arn != f"arn:{_partition(region)}:wellarchitected:{region}:{owner}:workload/{workload_id}"):
            failure = failure or ("malformed", {"code": "unattributed_wellarchitected_workload"})
            continue
        if owner != account:
            continue
        shares = requests.pages(session, "wellarchitected", region, "list_workload_shares", "WorkloadShareSummaries",
                                _tokens=("NextToken", "NextToken"), WorkloadId=workload_id)
        rows = [_pick(share, ("ShareId", "SharedWith", "PermissionType", "Status"))
                if isinstance(share, dict) else None for share in shares.items]
        items.append({"id": arn, "WorkloadArn": arn, "WorkloadId": workload_id, "Owner": owner,
                      "Shares": {"WorkloadId": workload_id, **_child(shares, rows)}})
    return _finish(items, failure)


def _wellarchitected_lens_shares(requests, session, region, account):
    listed = requests.pages(session, "wellarchitected", region, "list_lenses", "LensSummaries",
                            _tokens=("NextToken", "NextToken"), LensType="CUSTOM_SELF", LensStatus="ALL")
    failure = _cause(listed) if listed.status not in OK else None
    items = []
    prefix = f"arn:{_partition(region)}:wellarchitected:{region}:{account}:lens/"
    for lens in listed.items:
        if not isinstance(lens, dict) or lens.get("LensType") != "CUSTOM_SELF":
            failure = failure or ("malformed", {"code": "malformed_wellarchitected_lens"})
            continue
        arn = lens.get("LensArn")
        if (not isinstance(arn, str) or not arn.startswith(prefix) or
                not re.fullmatch(r"[0-9a-f]{32}", arn[len(prefix):]) or
                lens.get("LensAlias") != arn or lens.get("Owner") != account):
            failure = failure or ("malformed", {"code": "unattributed_wellarchitected_lens"})
            continue
        shares = requests.pages(session, "wellarchitected", region, "list_lens_shares", "LensShareSummaries",
                                _tokens=("NextToken", "NextToken"), LensAlias=arn)
        rows = [_pick(share, ("ShareId", "SharedWith", "Status"))
                if isinstance(share, dict) else None for share in shares.items]
        items.append({"id": arn, "LensArn": arn, "LensAlias": arn, "Owner": account, "LensType": "CUSTOM_SELF",
                      "Shares": _child(shares, rows)})
    return _finish(items, failure)


def _wellarchitected_profile_shares(requests, session, region, account):
    listed = requests.pages(session, "wellarchitected", region, "list_profiles", "ProfileSummaries",
                            _tokens=("NextToken", "NextToken"), ProfileOwnerType="SELF")
    failure = _cause(listed) if listed.status not in OK else None
    items = []
    prefix = f"arn:{_partition(region)}:wellarchitected:{region}:{account}:profile/"
    for profile in listed.items:
        arn = profile.get("ProfileArn") if isinstance(profile, dict) else None
        if (not isinstance(arn, str) or not arn.startswith(prefix) or
                not re.fullmatch(r"[a-z0-9]+", arn[len(prefix):]) or profile.get("Owner") != account):
            failure = failure or ("malformed", {"code": "unattributed_wellarchitected_profile"})
            continue
        shares = requests.pages(session, "wellarchitected", region, "list_profile_shares", "ProfileShareSummaries",
                                _tokens=("NextToken", "NextToken"), ProfileArn=arn)
        rows = [_pick(share, ("ShareId", "SharedWith", "Status"))
                if isinstance(share, dict) else None for share in shares.items]
        items.append({"id": arn, "ProfileArn": arn, "Owner": account, "Shares": _child(shares, rows)})
    return _finish(items, failure)


def _wellarchitected_template_shares(requests, session, region, account):
    listed = requests.pages(session, "wellarchitected", region, "list_review_templates", "ReviewTemplates",
                            _tokens=("NextToken", "NextToken"))
    failure = _cause(listed) if listed.status not in OK else None
    items = []
    prefix = f"arn:{_partition(region)}:wellarchitected:{region}:{account}:review-template/"
    for template in listed.items:
        arn = template.get("TemplateArn") if isinstance(template, dict) else None
        if (not isinstance(arn, str) or not arn.startswith(prefix) or
                not re.fullmatch(r"[0-9a-f]{32}", arn[len(prefix):]) or template.get("Owner") != account):
            failure = failure or ("malformed", {"code": "unattributed_wellarchitected_template"})
            continue
        shares = requests.pages(session, "wellarchitected", region, "list_template_shares", "TemplateShareSummaries",
                                _tokens=("NextToken", "NextToken"), TemplateArn=arn)
        rows = [_pick(share, ("ShareId", "SharedWith", "Status"))
                if isinstance(share, dict) else None for share in shares.items]
        items.append({"id": arn, "TemplateArn": arn, "Owner": account,
                      "Shares": {"TemplateArn": arn, **_child(shares, rows)}})
    return _finish(items, failure)


def _ec2_fpga_images(requests, session, region, account):
    listed = requests.pages(session, "ec2", region, "describe_fpga_images", "FpgaImages", Owners=["self"])
    failure = _cause(listed) if listed.status not in OK else None
    items = []
    for image in listed.items:
        if not isinstance(image, dict):
            failure = failure or ("malformed", {"code": "malformed_fpga_image"})
            continue
        image_id = image.get("FpgaImageId")
        if (not isinstance(image_id, str) or not re.fullmatch(r"afi-[0-9a-f]+", image_id) or
                image.get("OwnerId") != account):
            failure = failure or ("malformed", {"code": "unattributed_fpga_image"})
            continue
        row = _pick(image, ("FpgaImageId", "OwnerId", "Public"))
        row["State"] = _pick(image.get("State"), ("Code",))
        row["id"] = image_id
        detail = requests.detail(session, "ec2", region, "describe_fpga_image_attribute",
                                 FpgaImageId=image_id, Attribute="loadPermission")
        if detail.get("collection_status") != "collected":
            row["LoadPermissions"] = {"collection_status": detail.get("collection_status", "unknown"),
                                      "error": {"code": (detail.get("error") or {}).get("code")}}
        else:
            attribute = detail.get("FpgaImageAttribute")
            permissions = attribute.get("LoadPermissions") if isinstance(attribute, dict) else None
            if (not isinstance(attribute, dict) or attribute.get("FpgaImageId") != image_id or
                    not isinstance(permissions, list)):
                row["LoadPermissions"] = {"collection_status": "malformed"}
            else:
                row["LoadPermissions"] = {"collection_status": "collected", "FpgaImageId": image_id,
                                          "items": [_pick(permission, ("UserId", "Group"))
                                                    if isinstance(permission, dict) else None for permission in permissions]}
        items.append(row)
    return _finish(items, failure)


def _ds_directory_shares(requests, session, region, account):
    listed = requests.pages(session, "ds", region, "describe_directories", "DirectoryDescriptions",
                            _tokens=("NextToken", "NextToken"))
    failure = _cause(listed) if listed.status not in OK else None
    items = []
    for directory in listed.items:
        if not isinstance(directory, dict) or not isinstance(directory.get("DirectoryId"), str) or not re.fullmatch(
                r"d-[0-9a-f]{10}", directory["DirectoryId"]):
            failure = failure or ("malformed", {"code": "malformed_directory_id"})
            continue
        owner = directory.get("OwnerDirectoryDescription")
        if isinstance(owner, dict) and owner.get("AccountId") != account:
            continue  # Directory shared into the scanned account.
        if directory.get("Type") != "MicrosoftAD":
            continue  # Only AWS Managed Microsoft AD supports this share API.
        directory_id = directory["DirectoryId"]
        shares = requests.pages(session, "ds", region, "describe_shared_directories", "SharedDirectories",
                                _tokens=("NextToken", "NextToken"), OwnerDirectoryId=directory_id)
        rows = [_pick(share, ("OwnerAccountId", "OwnerDirectoryId", "SharedAccountId", "SharedDirectoryId",
                               "ShareMethod", "ShareStatus")) if isinstance(share, dict) else None
                for share in shares.items]
        items.append({"id": directory_id, "DirectoryId": directory_id, "Type": "MicrosoftAD",
                      "Stage": directory.get("Stage"),
                      "Shares": {"OwnerDirectoryId": directory_id, **_child(shares, rows)}})
    return _finish(items, failure)


def _auditmanager_framework_shares(requests, session, region, account):
    read = requests.pages(session, "auditmanager", region, "list_assessment_framework_share_requests",
                          "assessmentFrameworkShareRequests", requestType="SENT")
    failure = _cause(read) if read.status not in OK else None
    items = []
    for share in read.items:
        if not isinstance(share, dict) or not isinstance(share.get("id"), str):
            failure = failure or ("malformed", {"code": "malformed_auditmanager_share"})
            continue
        items.append({"id": share["id"], **_pick(share, ("frameworkId", "sourceAccount",
                      "destinationAccount", "destinationRegion", "status"))})
    return _finish(items, failure)


def _workdocs_document_shares(requests, session, region, account):
    """Walk active user roots once and retain only folder/document IDs and grant types."""
    # IAM-signed DescribeUsers requires the WorkDocs site's directory ID
    # (organizationId); a Region without directories holds no WorkDocs sites.
    directories = requests.pages(session, "ds", region, "describe_directories", "DirectoryDescriptions")
    failure = _cause(directories) if directories.status not in OK else None
    user_rows = []
    for directory in directories.items:
        directory_id = directory.get("DirectoryId") if isinstance(directory, dict) else None
        if not isinstance(directory_id, str) or not re.fullmatch(r"d-[0-9a-f]{10}", directory_id):
            failure = failure or ("malformed", {"code": "malformed_directory_id"})
            continue
        users = requests.pages(session, "workdocs", region, "describe_users", "Users",
                               OrganizationId=directory_id, Include="ALL")
        if users.status not in OK:
            failure = failure or _cause(users)
        user_rows.extend(users.items)
    folders, visited, documents = [], set(), set()
    for user in user_rows:
        root = user.get("RootFolderId") if isinstance(user, dict) else None
        if not isinstance(root, str) or not re.fullmatch(r"[\w+\-.@]{1,128}", root):
            failure = failure or ("malformed", {"code": "malformed_workdocs_root"})
            continue
        folders.append(root)
    items = []
    limit = requests.max_items

    def permission_row(resource_id, kind):
        permissions = requests.pages(session, "workdocs", region, "describe_resource_permissions",
                                     "Principals", ResourceId=resource_id)
        rows = []
        for principal in permissions.items:
            if not isinstance(principal, dict) or not isinstance(principal.get("Roles"), list):
                rows.append(None)
            else:
                rows.append({"Id": principal.get("Id"), "Type": principal.get("Type"),
                             "Roles": [_pick(role, ("Role", "Type")) if isinstance(role, dict) else None
                                       for role in principal["Roles"]]})
        return {"id": resource_id, ("FolderId" if kind == "folder" else "DocumentId"): resource_id,
                "Permissions": {"ResourceId": resource_id, **_child(permissions, rows)}}

    expression = ("[Folders[].{kind: 'folder', id: Id, parent: ParentFolderId, state: ResourceState}, "
                  "Documents[].{kind: 'document', id: Id, parent: ParentFolderId, state: ResourceState}][]")
    while folders:
        folder_id = folders.pop()
        if folder_id in visited:
            continue
        if limit is not None and len(visited) + len(documents) >= limit:
            failure = failure or ("not_collected", {"code": "resource_limit"})
            break
        visited.add(folder_id)
        items.append(permission_row(folder_id, "folder"))
        children = requests.pages(session, "workdocs", region, "describe_folder_contents", expression,
                                  FolderId=folder_id)
        if children.status not in OK:
            failure = failure or _cause(children)
        for child in children.items:
            if (not isinstance(child, dict) or child.get("parent") != folder_id or
                    child.get("kind") not in ("folder", "document") or
                    not isinstance(child.get("id"), str) or not re.fullmatch(r"[\w+\-.@]{1,128}", child["id"])):
                failure = failure or ("malformed", {"code": "malformed_workdocs_child"})
                continue
            if child.get("state") != "ACTIVE":
                continue
            child_id = child["id"]
            if child["kind"] == "folder":
                if child_id not in visited:
                    folders.append(child_id)
                continue
            if child_id in documents:
                continue
            if limit is not None and len(visited) + len(documents) >= limit:
                failure = failure or ("not_collected", {"code": "resource_limit"})
                break
            documents.add(child_id)
            items.append(permission_row(child_id, "document"))
    return _finish(items, failure)


def _cleanrooms_table_shares(requests, session, region, account):
    memberships = requests.pages(session, "cleanrooms", region, "list_memberships", "membershipSummaries")
    failure = _cause(memberships) if memberships.status not in OK else None
    items = []
    for membership in memberships.items:
        if not isinstance(membership, dict) or not isinstance(membership.get("id"), str):
            failure = failure or ("malformed", {"code": "malformed_cleanrooms_membership"})
            continue
        membership_id = membership["id"]
        row = {"id": membership_id, **_pick(membership, ("arn", "collaborationId",
               "collaborationArn", "status"))}
        if membership.get("status") != "ACTIVE":
            items.append(row)
            continue
        if not isinstance(membership.get("collaborationId"), str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                membership["collaborationId"]):
            failure = failure or ("malformed", {"code": "malformed_cleanrooms_collaboration"})
            items.append(row)
            continue
        association_read = requests.pages(session, "cleanrooms", region,
            "list_configured_table_associations", "configuredTableAssociationSummaries",
            membershipIdentifier=membership_id)
        associations = [_pick(value, ("id", "configuredTableId", "membershipId", "membershipArn",
                        "analysisRuleTypes")) if isinstance(value, dict) else None
                        for value in association_read.items]
        members_read = requests.pages(session, "cleanrooms", region, "list_members", "memberSummaries",
                                     collaborationIdentifier=membership["collaborationId"])
        members = [_pick(value, ("accountId", "status", "abilities")) if isinstance(value, dict) else None
                   for value in members_read.items]
        row["Associations"] = {"membershipId": membership_id, **_child(association_read, associations)}
        row["Members"] = {"collaborationId": membership.get("collaborationId"), **_child(members_read, members)}
        items.append(row)
    return _finish(items, failure)


def _dataexchange_data_grants(requests, session, region, account):
    read = requests.pages(session, "dataexchange", region, "list_data_grants", "DataGrantSummaries")
    failure = _cause(read) if read.status not in OK else None
    items = []
    for grant in read.items:
        if not isinstance(grant, dict) or not isinstance(grant.get("Id"), str):
            failure = failure or ("malformed", {"code": "malformed_data_grant"})
            continue
        row = {"id": grant["Id"], **_pick(grant, ("Arn", "DataSetId", "SourceDataSetId",
               "SenderPrincipal", "ReceiverPrincipal", "AcceptanceState"))}
        if "EndsAt" in grant:
            end = grant["EndsAt"]
            row["EndsAt"] = end.isoformat() if isinstance(end, datetime) else end
        items.append(row)
    return _finish(items, failure)


def _quicksight_public_dashboards(requests, session, region, account):
    listed = requests.pages(session, "quicksight", region, "list_dashboards", "DashboardSummaryList",
                            AwsAccountId=account)
    failure = _cause(listed) if listed.status not in OK else None
    if not listed.items:
        return _finish([], failure)
    settings = requests.detail(session, "quicksight", region, "describe_account_settings", AwsAccountId=account)
    account_settings = settings.get("AccountSettings") if settings.get("collection_status") == "collected" else None
    public_enabled = account_settings.get("PublicSharingEnabled") if isinstance(account_settings, dict) else None
    items = []
    for dashboard in listed.items:
        if not isinstance(dashboard, dict) or not isinstance(dashboard.get("DashboardId"), str):
            failure = failure or ("malformed", {"code": "malformed_quicksight_dashboard"})
            continue
        dashboard_id = dashboard["DashboardId"]
        detail = requests.detail(session, "quicksight", region, "describe_dashboard_permissions",
                                 AwsAccountId=account, DashboardId=dashboard_id)
        link = detail.get("LinkSharingConfiguration") if detail.get("collection_status") == "collected" else None
        permissions = link.get("Permissions", []) if isinstance(link, dict) else [] if link is None else None
        projected = ([_pick(value, ("Principal", "Actions")) if isinstance(value, dict) else None
                      for value in permissions] if isinstance(permissions, list) else None)
        items.append({"id": dashboard_id, **_pick(dashboard, ("Arn", "DashboardId", "PublishedVersionNumber")),
                      "AccountSettings": {"collection_status": settings.get("collection_status"),
                                          "PublicSharingEnabled": public_enabled},
                      "LinkPermissions": {"collection_status": detail.get("collection_status"),
                                          "DashboardId": detail.get("DashboardId"),
                                          "DashboardArn": detail.get("DashboardArn"), "items": projected}})
    return _finish(items, failure)


def _license_manager_distributed_grants(requests, session, region, account):
    read = requests.pages(session, "license-manager", region, "list_distributed_grants", "Grants")
    failure = _cause(read) if read.status not in OK else None
    items = []
    for grant in read.items:
        if not isinstance(grant, dict) or not isinstance(grant.get("GrantArn"), str):
            failure = failure or ("malformed", {"code": "malformed_license_manager_grant"})
            continue
        items.append({"id": grant["GrantArn"], **_pick(grant, ("GrantArn", "LicenseArn",
            "GranteePrincipalArn", "GrantStatus", "GrantedOperations", "HomeRegion"))})
    return _finish(items, failure)


def _lakeformation_table_grants(requests, session, region, account):
    read = requests.pages(session, "lakeformation", region, "list_permissions",
                          "PrincipalResourcePermissions", CatalogId=account)
    failure = _cause(read) if read.status not in OK else None
    items = []
    for grant in read.items:
        if not isinstance(grant, dict):
            failure = failure or ("malformed", {"code": "malformed_lakeformation_permission"})
            continue
        resource = grant.get("Resource")
        table = (resource.get("Table") or resource.get("TableWithColumns")) if isinstance(resource, dict) else None
        if not isinstance(table, dict):
            continue
        column_scoped = isinstance(resource.get("TableWithColumns"), dict)
        principal = grant.get("Principal")
        principal_id = principal.get("DataLakePrincipalIdentifier") if isinstance(principal, dict) else None
        key = "|".join(str(value or "") for value in
                       (table.get("CatalogId"), table.get("DatabaseName"), table.get("Name"),
                        bool(table.get("TableWildcard") is not None), column_scoped,
                        tuple(table.get("ColumnNames", ())) if isinstance(table.get("ColumnNames", ()), list) else (),
                        principal_id))
        identity = f"{account}/{region}/table-grant/{hashlib.sha256(key.encode()).hexdigest()[:24]}"
        items.append({"id": identity, "Principal": principal_id,
            "Table": _pick(table, ("CatalogId", "DatabaseName", "Name", "TableWildcard")),
            "ColumnScope": {"scoped": column_scoped,
                "column_count": (len(table.get("ColumnNames", [])) if isinstance(table.get("ColumnNames", []), list)
                                 else None),
                "wildcard": isinstance(table.get("ColumnWildcard"), dict)},
            "Permissions": grant.get("Permissions")})
    return _finish(items, failure)


def _lakeformation_tag_policy_grants(requests, session, region, account):
    # Shares the exact cached ListPermissions request with named-table grants.
    read = requests.pages(session, "lakeformation", region, "list_permissions",
                          "PrincipalResourcePermissions", CatalogId=account)
    failure = _cause(read) if read.status not in OK else None
    items = []
    for grant in read.items:
        if not isinstance(grant, dict):
            failure = failure or ("malformed", {"code": "malformed_lakeformation_permission"})
            continue
        resource = grant.get("Resource")
        policy = resource.get("LFTagPolicy") if isinstance(resource, dict) else None
        if not isinstance(policy, dict):
            continue
        principal = grant.get("Principal")
        principal_id = principal.get("DataLakePrincipalIdentifier") if isinstance(principal, dict) else None
        expression = policy.get("Expression")
        selector = ("inline" if isinstance(expression, list) and expression else
                    "named" if isinstance(policy.get("ExpressionName"), str) and policy["ExpressionName"] else None)
        key = json.dumps((policy.get("CatalogId"), policy.get("ResourceType"), expression,
                          policy.get("ExpressionName"), principal_id), sort_keys=True, default=str)
        identity = f"{account}/{region}/tag-policy-grant/{hashlib.sha256(key.encode()).hexdigest()[:24]}"
        items.append({"id": identity, "Principal": principal_id,
            "TagPolicy": {**_pick(policy, ("CatalogId", "ResourceType")), "Selector": selector},
            "Permissions": grant.get("Permissions")})
    return _finish(items, failure)


def _securitylake_subscribers(requests, session, region, account):
    read = requests.pages(session, "securitylake", region, "list_subscribers", "subscribers")
    failure = _cause(read) if read.status not in OK else None
    items = []
    for subscriber in read.items:
        if not isinstance(subscriber, dict) or not isinstance(subscriber.get("subscriberId"), str):
            failure = failure or ("malformed", {"code": "malformed_securitylake_subscriber"})
            continue
        identity = subscriber.get("subscriberIdentity")
        items.append({"id": subscriber["subscriberId"],
            **_pick(subscriber, ("subscriberArn", "subscriberId", "subscriberStatus", "accessTypes")),
            "principal": identity.get("principal") if isinstance(identity, dict) else None,
            "source_count": len(subscriber["sources"]) if isinstance(subscriber.get("sources"), list) else None})
    return _finish(items, failure)


def _s3_access_grants(requests, session, region, account):
    read = requests.pages(session, "s3control", region, "list_access_grants",
                          "AccessGrantsList", AccountId=account)
    failure = _cause(read) if read.status not in OK else None
    items = []
    for grant in read.items:
        if not isinstance(grant, dict) or not isinstance(grant.get("AccessGrantArn"), str):
            failure = failure or ("malformed", {"code": "malformed_s3_access_grant"})
            continue
        grantee = grant.get("Grantee")
        scope = grant.get("GrantScope")
        match = re.fullmatch(r"s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/(.+)", scope) if isinstance(scope, str) else None
        items.append({"id": grant["AccessGrantArn"],
            **_pick(grant, ("AccessGrantArn", "AccessGrantId", "Permission")),
            "GranteeType": grantee.get("GranteeType") if isinstance(grantee, dict) else None,
            "GranteeIdentifier": grantee.get("GranteeIdentifier") if isinstance(grantee, dict) else None,
            "Bucket": match.group(1) if match else None,
            "ApplicationBound": bool(grant.get("ApplicationArn"))})
    return _finish(items, failure)


def _workspaces_connection_aliases(requests, session, region, account):
    listed = requests.pages(session, "workspaces", region, "describe_connection_aliases", "ConnectionAliases")
    failure = _cause(listed) if listed.status not in OK else None
    items = []
    for alias in listed.items:
        if not isinstance(alias, dict) or not isinstance(alias.get("AliasId"), str):
            failure = failure or ("malformed", {"code": "malformed_workspaces_alias"})
            continue
        alias_id = alias["AliasId"]
        associations = alias.get("Associations")
        projected = ([_pick(value, ("AssociatedAccountId", "AssociationStatus"))
                      if isinstance(value, dict) else None for value in associations]
                     if isinstance(associations, list) else None)
        row = {"id": alias_id, **_pick(alias, ("AliasId", "OwnerAccountId", "State")),
               "Associations": projected}
        if alias.get("OwnerAccountId") == account and re.fullmatch(r"wsca-[0-9a-z]{8,63}", alias_id):
            permissions = requests.pages(session, "workspaces", region,
                                         "describe_connection_alias_permissions", "ConnectionAliasPermissions",
                                         AliasId=alias_id)
            values = [_pick(value, ("SharedAccountId", "AllowAssociation"))
                      if isinstance(value, dict) else None for value in permissions.items]
            row["Permissions"] = {"AliasId": alias_id, **_child(permissions, values)}
        items.append(row)
    return _finish(items, failure)


def _imagebuilder_distributions(requests, session, region, account):
    """Retain distribution recipients only; drop AMI tags, names and parameter paths."""
    read = requests.pages(session, "imagebuilder", region, "list_distribution_configurations",
                          "distributionConfigurationSummaryList")
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    prefix = f"arn:{_partition(region)}:imagebuilder:{region}:{account}:distribution-configuration/"
    for summary in read.items:
        arn = summary.get("arn") if isinstance(summary, dict) else None
        if not isinstance(arn, str) or not arn.startswith(prefix):
            failure = failure or ("malformed", {"code": "imagebuilder_distribution_identity_invalid"})
            continue
        detail = requests.detail(session, "imagebuilder", region, "get_distribution_configuration",
                                 distributionConfigurationArn=arn)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "not_collected",
                                  {"code": "imagebuilder_distribution_detail_unavailable"})
            continue
        config = detail.get("distributionConfiguration")
        if not isinstance(config, dict) or config.get("arn") != arn or not isinstance(config.get("distributions"), list):
            failure = failure or ("malformed", {"code": "imagebuilder_distribution_detail_invalid"})
            continue
        destinations = []
        for distribution in config["distributions"]:
            if not isinstance(distribution, dict):
                failure = failure or ("malformed", {"code": "imagebuilder_distribution_region_invalid"})
                continue
            ami = distribution.get("amiDistributionConfiguration")
            launch = ami.get("launchPermission") if isinstance(ami, dict) else None
            destinations.append({"Region": distribution.get("region"),
                "TargetAccountIds": ami.get("targetAccountIds", []) if isinstance(ami, dict) else [],
                "LaunchUserIds": launch.get("userIds", []) if isinstance(launch, dict) else [],
                "LaunchUserGroups": launch.get("userGroups", []) if isinstance(launch, dict) else [],
                "LaunchOrganizationArns": launch.get("organizationArns", []) if isinstance(launch, dict) else [],
                "LaunchOrganizationalUnitArns": launch.get("organizationalUnitArns", []) if isinstance(launch, dict) else [],
                "LaunchTemplateAccountIds": [x.get("accountId") for x in (distribution.get("launchTemplateConfigurations") or [])
                                             if isinstance(x, dict)],
                "SsmParameterAccountIds": [x.get("amiAccountId") for x in (distribution.get("ssmParameterConfigurations") or [])
                                            if isinstance(x, dict) and x.get("amiAccountId")],
                "S3ExportBucket": (distribution.get("s3ExportConfiguration") or {}).get("s3Bucket")
                                  if isinstance(distribution.get("s3ExportConfiguration"), dict) else None})
        rows.append({"id": arn, "Arn": arn, "Distributions": destinations,
                     "_provenance": {"source_operation": "imagebuilder:GetDistributionConfiguration", "read_only": True}})
    return _finish(rows, failure)


def _agentcore_gateways(requests, session, region, account):
    """Project gateway URL and inbound auth state without JWT settings or interceptor content."""
    read = requests.pages(session, "bedrock-agentcore-control", region, "list_gateways", "items")
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for summary in read.items:
        gateway_id = summary.get("gatewayId") if isinstance(summary, dict) else None
        if not isinstance(gateway_id, str) or not gateway_id:
            failure = failure or ("malformed", {"code": "agentcore_gateway_id_invalid"})
            continue
        detail = requests.detail(session, "bedrock-agentcore-control", region, "get_gateway",
                                 gatewayIdentifier=gateway_id)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "not_collected",
                                  {"code": "agentcore_gateway_detail_unavailable"})
            continue
        arn = f"arn:{_partition(region)}:bedrock-agentcore:{region}:{account}:gateway/{gateway_id}"
        if detail.get("gatewayId") != gateway_id or detail.get("gatewayArn") != arn:
            failure = failure or ("malformed", {"code": "agentcore_gateway_identity_invalid"})
            continue
        rows.append({"id": arn, "GatewayArn": arn, "GatewayUrl": detail.get("gatewayUrl"),
                     "Status": detail.get("status"), "AuthorizerType": detail.get("authorizerType"),
                     "HasInterceptor": bool(detail.get("interceptorConfigurations")),
                     "PolicyEngineMode": (detail.get("policyEngineConfiguration") or {}).get("mode")
                                         if isinstance(detail.get("policyEngineConfiguration"), dict) else None,
                     "WebAclArn": detail.get("webAclArn"),
                     "_provenance": {"source_operation": "bedrock-agentcore-control:GetGateway", "read_only": True}})
    return _finish(rows, failure)


def _eventbridge_pipes(requests, session, region, account):
    """Keep Pipe destination identities, not filter patterns, input templates or credentials."""
    read = requests.pages(session, "pipes", region, "list_pipes", "Pipes")
    if read.status not in OK:
        return _finish([], _cause(read))
    rows, failure = [], None
    for summary in read.items:
        name = summary.get("Name") if isinstance(summary, dict) else None
        arn = f"arn:{_partition(region)}:pipes:{region}:{account}:pipe/{name}"
        if not isinstance(name, str) or not name or summary.get("Arn") != arn:
            failure = failure or ("malformed", {"code": "eventbridge_pipe_identity_invalid"})
            continue
        detail = requests.detail(session, "pipes", region, "describe_pipe", Name=name)
        if detail.get("collection_status") != "collected":
            failure = failure or (detail.get("collection_status") or "not_collected",
                                  {"code": "eventbridge_pipe_detail_unavailable"})
            continue
        if detail.get("Arn") != arn or detail.get("Name") != name:
            failure = failure or ("malformed", {"code": "eventbridge_pipe_detail_identity_invalid"})
            continue
        log = detail.get("LogConfiguration") or {}
        source = detail.get("SourceParameters") or {}
        dead_letters = []
        for key in ("DynamoDBStreamParameters", "KinesisStreamParameters"):
            part = source.get(key) if isinstance(source, dict) else None
            dlq = part.get("DeadLetterConfig") if isinstance(part, dict) else None
            if isinstance(dlq, dict) and isinstance(dlq.get("Arn"), str):
                dead_letters.append(dlq["Arn"])
        rows.append({"id": arn, "Arn": arn, "Name": name,
                     "CurrentState": detail.get("CurrentState"), "DesiredState": detail.get("DesiredState"),
                     "TargetArn": detail.get("Target"), "EnrichmentArn": detail.get("Enrichment"),
                     "DeadLetterArns": dead_letters,
                     "LogFirehoseArn": (log.get("FirehoseLogDestination") or {}).get("DeliveryStreamArn")
                                       if isinstance(log.get("FirehoseLogDestination"), dict) else None,
                     "LogBucketOwner": (log.get("S3LogDestination") or {}).get("BucketOwner")
                                       if isinstance(log.get("S3LogDestination"), dict) else None,
                     "LogBucketName": (log.get("S3LogDestination") or {}).get("BucketName")
                                      if isinstance(log.get("S3LogDestination"), dict) else None,
                     "_provenance": {"source_operation": "pipes:DescribePipe", "read_only": True}})
    return _finish(rows, failure)


FETCHERS = {
    'agentcore_gateway': _agentcore_gateways,
    'auditmanager_report_destination': _auditmanager_destinations,
    'cleanrooms_collaboration_exposure': _cleanrooms_collaborations,
    'eventbridge_pipe_exposure': _eventbridge_pipes,
    'lightsail_distribution': _lightsail_distributions,
    "transit_gateway_peering_attachment": _transit_gateway_peering,
    "lambda_layer_version": _layer_versions,
    "lambda_version": _versions,
    "redshiftserverless_snapshot": _redshiftserverless_snapshots,
    "docdb_cluster_snapshot": _cluster_snapshots("docdb"),
    "neptune_cluster_snapshot": _cluster_snapshots("neptune"),
    "lambda_alias": _aliases,
    "client_vpn_routing": _client_vpn_routing,
    "lambda_event_source_mapping": _event_source_mappings,
    "ecr_registry": _ecr_registry,
    "eks_access_entry": _access_entries,
    "eks_pod_identity_association": _pod_identity_associations,
    "kms_grant": _kms_grants,
    "opensearch_connection": _opensearch_connections,
    "route53_record_set": _record_sets,
    "cloudformation_stack_instance": _stack_instances,
    "cloudformation_organizations_access": _stackset_organizations_access,
    "ec2_instance_connect_endpoint": _instance_connect_endpoints,
    "rolesanywhere_profile": _rolesanywhere_profiles,
    "imagebuilder_pipeline": _image_pipelines,
    "imagebuilder_distribution": _image_distributions,
    "sagemaker_user_profile": _user_profiles,
    "sagemaker_space": _spaces,
    "sagemaker_cluster": _hyperpod_clusters,
    "grafana_workspace": _grafana_workspaces,
    "gamelift_ec2_compute": _gamelift_ec2_computes,
    "iot_role_alias": _iot_role_aliases,
    "iot_credentials_endpoint": _iot_credentials_endpoint,
    "iot_data_domain": _iot_data_domains,
    "iot_topic_rule": _iot_topic_rules,
    "cognito_user_pool_endpoint": _cognito_user_pool_endpoints,
    "apigatewayv2_portal": _apigatewayv2_portals,
    "appflow_flow": _appflow_flows,
    "cloudmap_public_service": _cloudmap_public_services,
    "cloudsearch_domain_endpoint": _cloudsearch_domain_endpoints,
    "rum_app_monitor_endpoint": _rum_app_monitor_endpoints,
    "config_aggregation_authorization": _config_delivery_edges("config_aggregation_authorization"),
    "config_conformance_pack_delivery": _config_delivery_edges("config_conformance_pack_delivery"),
    "config_organization_pack_delivery": _config_delivery_edges("config_organization_pack_delivery"),
    "config_rule_lambda_delivery": _config_delivery_edges("config_rule_lambda_delivery"),
    "config_organization_rule_lambda_delivery": _config_delivery_edges("config_organization_rule_lambda_delivery"),
    "backup_search_export": _backup_search_exports,
    "devicefarm_upload": _devicefarm_project_children("devicefarm_upload"),
    "devicefarm_device_pool": _devicefarm_project_children("devicefarm_device_pool"),
    "quicksight_user": _quicksight_users,
    "quicksight_account_subscription": _quicksight_account_subscription,
    "supplychain_instance": _supplychain_instances,
    "amplify_app": _amplify_apps,
    "aws_identity_center_account_assignment": _account_assignments,
    "cloud9_environment_share": _cloud9_environment_shares,
    "omics_resource_share": _omics_resource_shares,
    "wellarchitected_workload_share": _wellarchitected_workload_shares,
    "wellarchitected_lens_share": _wellarchitected_lens_shares,
    "wellarchitected_profile_share": _wellarchitected_profile_shares,
    "wellarchitected_template_share": _wellarchitected_template_shares,
    "ec2_fpga_image": _ec2_fpga_images,
    "ds_directory_share": _ds_directory_shares,
    "auditmanager_framework_share": _auditmanager_framework_shares,
    "workdocs_document_share": _workdocs_document_shares,
    "cleanrooms_table_share": _cleanrooms_table_shares,
    "dataexchange_data_grant": _dataexchange_data_grants,
    "quicksight_public_dashboard": _quicksight_public_dashboards,
    "license_manager_distributed_grant": _license_manager_distributed_grants,
    "lakeformation_table_grant": _lakeformation_table_grants,
    "lakeformation_tag_policy_grant": _lakeformation_tag_policy_grants,
    "securitylake_subscriber_share": _securitylake_subscribers,
    "s3_access_grant_share": _s3_access_grants,
    "workspaces_connection_alias_share": _workspaces_connection_aliases,
}
ENRICHERS = {
    "transit_gateway_route_table": _transit_gateway_system_routes,
    "lambda_function": _lambda_function,
    "cognito_identity_pool": _identity_pool,
    "cognito_user_pool": _user_pool,
    "sagemaker_domain": _sagemaker_domain,
}
