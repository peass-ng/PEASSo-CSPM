"""Canonical service labels for check targets and their collected inventories.

The manifest is keyed by provider and inventory kind. It is deliberately kept
separate from collection success: an unavailable inventory still has a service.
"""
from functools import lru_cache
import json
from pathlib import Path

CHECK_SERVICE_OVERRIDES = {
    # These checks share an umbrella target kind with controls for a different
    # product. The evaluated control, rather than the inventory wrapper, owns
    # the finding's service label.
    "azure.gap.monitor_log_profile_enabled_for_all_categories": "Microsoft.Insights",
    "azure.gap.audit_diagnostic_setting": "Microsoft.Insights",
    "aws.a.cloudwatch.cross_account_role_absent": "cloudwatch",
    "aws.claude2_a.cloudwatch.cross_account_sharing_role_absent": "cloudwatch",
    "aws.claude2_a.cloudtrail.account_has_logging_trail": "cloudtrail",
    "gcp.reviewed.project.os_login_2fa": "compute",
    "gcp.claude.project.oslogin_enabled": "compute",
    "gcp.claude.project.no_api_keys": "apikeys",
    "gcp.ports.project_no_api_key": "apikeys",
    "gcp.claude.project.storage_vpc_service_controls": "accesscontextmanager",
    "gcp.ports.project_service_cloudasset_api_enabled": "serviceusage",
    "gcp.ports.artifacts_container_analysis_enabled": "serviceusage",
    "gcp.claude.project.container_scanning_api_enabled": "serviceusage",
    "gcp.claude.project.gemini_api_disabled": "serviceusage",
    "gcp.iam.data_access_audit": "logging",
    "gcp.claude.project.storage_data_access_audit_logs": "logging",
    "gcp.claude.project.audit_logs_configured": "logging",
    "gcp_pci_iam_policy_ca1281da7ab2": "logging",
    "gcp_pci_iam_policy_9a8ce875703d": "logging",
    "gcp.logging.access_transparency_entries": "logging",
    "gcp_cloudsql_backup_failure_alert": "monitoring",
    "gcp_kms_key_destroy_alert": "monitoring",
    "gcp_logging_enumeration_alert": "monitoring",
    "gcp_logging_query_rate_alert": "monitoring",
}

CHECK_SERVICE_PREFIXES = (
    ("aws.a.iam.password_policy_", "iam"),
    ("gcp.claude.logging.", "logging"),
    ("gcp.claude2.logging.", "logging"),
    ("gcp.ports.logging_", "logging"),
    ("gcp.htbp.orgpolicy.", "orgpolicy"),
)

# Collector API clients and resource kinds are not always user-facing products.
# Apply these aliases to archived analysis findings, whose check IDs are not in
# the native check registry and whose bounded indexes retain only the service.
SERVICE_ALIASES = {
    "aws": {
        "apigatewayv2": "apigateway",
        "bedrock-agent": "bedrock",
        "elb": "elasticloadbalancing",
        "elbv2": "elasticloadbalancing",
        "redshift-serverless": "redshift",
        "s3control": "s3",
        "waf-regional": "waf",
        "wafv2": "waf",
    },
    "gcp": {"iam/cloudasset": "iam", "iam.googleapis.com": "iam", "recommender.googleapis.com": "recommender"},
}

# Exposure and network analysis can emit findings for supporting inventories
# that have no standalone native check. Older reports sometimes stored those
# inventory kinds directly as their service labels.
ANALYSIS_KIND_SERVICES = {
    "aws": {
        "apigatewayv2_domain_name": "apigateway",
        "cloudfront_vpc_origin": "cloudfront", "memorydb_subnet_group": "memorydb",
        "redshift_subnet_group": "redshift", "elasticache_subnet_group": "elasticache", "ecs_task": "ecs",
        "rds_db_subnet_group": "rds",
        "ec2_instance_connect_endpoint": "ec2", "managed_prefix_list": "ec2",
        "nat_gateway": "ec2", "target_group": "elasticloadbalancing",
        "transit_gateway_attachment": "ec2", "transit_gateway_route_table": "ec2",
        "transit_gateway_vpc_attachment": "ec2", "vpn_gateway": "ec2",
    },
    "gcp": {
        "service_attachment": "compute", "network_endpoint_group": "compute", "network_attachment": "compute",
        "vpc_access_connector": "vpcaccess", "filestore_instance": "file", "redis_instance": "redis",
        "address": "compute", "effective_firewall": "compute",
        "firewall_policy": "compute", "firewall_policy_association": "compute",
        "health_check": "compute", "hierarchical_firewall_policy": "compute",
        "instance_group": "compute", "network_firewall_policy": "networksecurity",
        "policy_based_route": "networkconnectivity", "route": "compute",
        "router": "compute", "shared_vpc": "compute", "vpn_gateway": "compute",
        "vpn_tunnel": "compute",
    },
    "azure": {
        "private_link_service": "Microsoft.Network",
        "mongo_cluster": "Microsoft.DocumentDB",
        "effective_route": "Microsoft.Network", "nat_gateway": "Microsoft.Network",
        "private_endpoint": "Microsoft.Network", "security_admin_rule": "Microsoft.Network",
        "service_tag": "Microsoft.Network", "vnet_peering": "Microsoft.Network",
    },
}

# Internet-exposure analysis also evaluates inventories that have no standalone
# native check. Each one keeps the service its collector stamps on the collection
# envelope, so a legacy report that stored the kind as its service groups with
# the findings of current scans.
EXPOSURE_KIND_SERVICES = {'aws': {'agentcore_gateway': 'bedrock-agentcore-control',
         'apigatewayv2_portal': 'apigateway',
         'appconfig_configuration_profile': 'appconfig',
         'appconfig_extension_association': 'appconfig',
         'appflow_flow': 'appflow',
         'appstream_image': 'appstream',
         'athena_query_export': 'athena',
         'auditmanager_framework_share': 'auditmanager',
         'auditmanager_report_destination': 'auditmanager',
         'backup_copy_job': 'backup',
         'backup_search_export': 'backupsearch',
         'budget_notification_recipients': 'budgets',
         'cleanrooms_collaboration_exposure': 'cleanrooms',
         'cleanrooms_table_share': 'cleanrooms',
         'client_vpn_routing': 'ec2',
         'cloud9_environment_share': 'cloud9',
         'cloudformation_stack_instance': 'cloudformation',
         'cloudmap_public_service': 'servicediscovery',
         'cloudsearch_domain_endpoint': 'cloudsearch',
         'cloudtrail_query_export': 'cloudtrail',
         'codepipeline_webhook': 'codepipeline',
         'codestar_notification_rule': 'codestar-notifications',
         'cognito_user_pool_endpoint': 'cognito-idp',
         'config_aggregation_authorization': 'config',
         'config_conformance_pack_delivery': 'config',
         'config_delivery_channel': 'config',
         'config_organization_pack_delivery': 'config',
         'config_organization_rule_lambda_delivery': 'config',
         'config_rule_lambda_delivery': 'config',
         'dataexchange_data_grant': 'dataexchange',
         'ds_directory_share': 'ds',
         'ec2_fpga_image': 'ec2',
         'ecr_public_repository': 'ecr-public',
         'ecs_task_network': 'ecs',
         'efs_replication': 'efs',
         'eventbridge_api_destination': 'events',
         'eventbridge_custom_bus': 'eventbridgev2',
         'eventbridge_pipe_exposure': 'pipes',
         'flow_log': 'ec2',
         'gamelift_ec2_compute': 'gamelift',
         'glacier_vault_notification': 'glacier',
         'globalaccelerator_cross_account_attachment': 'globalaccelerator',
         'globalaccelerator_custom_routing_accelerator': 'globalaccelerator',
         'globalaccelerator_custom_routing_listener': 'globalaccelerator',
         'http_api_deployed_route': 'apigateway',
         'imagebuilder_distribution': 'imagebuilder',
         'iot_credentials_endpoint': 'iot',
         'iot_data_domain': 'iot',
         'iot_topic_rule': 'iot',
         'lakeformation_permission': 'lakeformation',
         'lakeformation_settings': 'lakeformation',
         'lakeformation_table_grant': 'lakeformation',
         'lakeformation_tag_policy_grant': 'lakeformation',
         'lambda_alias': 'lambda',
         'lambda_version': 'lambda',
         'license_manager_distributed_grant': 'license-manager',
         'lightsail_distribution': 'lightsail',
         'log_account_subscription_policy': 'logs',
         'log_subscription_filter': 'logs',
         'mailmanager_rule_route': 'mailmanager',
         'marketplace_entity': 'marketplace-catalog',
         'mediapackage_origin_endpoint': 'mediapackage',
         'mediapackagev2_channel_listener': 'mediapackagev2',
         'mediapackagev2_harvest_job': 'mediapackagev2',
         'mediatailor_playback_configuration': 'mediatailor',
         'oam_link': 'oam',
         'omics_resource_share': 'omics',
         'opensearch_ui_application': 'opensearch',
         'opensearch_vpc_endpoint_access': 'opensearch',
         'quicksight_dashboard_share': 'quicksight',
         'quicksight_public_dashboard': 'quicksight',
         'rds_cluster_endpoint': 'rds',
         'redshift_datashare': 'redshift',
         'redshift_endpoint_authorization': 'redshift',
         'rest_api_method': 'apigateway',
         'rum_app_monitor_endpoint': 'rum',
         's3_access_grant_share': 's3',
         's3tables_lf_grant': 'lakeformation',
         'scheduler_schedule': 'scheduler',
         'security_ir_recipient_route': 'security-ir',
         'securitylake_exception_notification': 'securitylake',
         'securitylake_subscriber': 'securitylake',
         'securitylake_subscriber_share': 'securitylake',
         'sns_platform_endpoint': 'sns',
         'sns_topic_subscription': 'sns',
         'transit_gateway_peering_attachment': 'ec2',
         'wellarchitected_lens_share': 'wellarchitected',
         'wellarchitected_profile_share': 'wellarchitected',
         'wellarchitected_share': 'wellarchitected',
         'wellarchitected_template_share': 'wellarchitected',
         'wellarchitected_workload_share': 'wellarchitected',
         'workdocs_document_share': 'workdocs',
         'workspaces_connection_alias_share': 'workspaces',
         'workspaces_image': 'workspaces'},
 'azure': {'acat_report': 'Microsoft.AppComplianceAutomation',
           'acat_webhook': 'Microsoft.AppComplianceAutomation',
           'analysis_server': 'Microsoft.AnalysisServices',
           'app_configuration_event_subscription': 'Microsoft.AppConfiguration',
           'app_configuration_private_connection': 'Microsoft.AppConfiguration',
           'compute_gallery': 'Microsoft.Compute',
           'container_app_runtime': 'Microsoft.App',
           'cost_export': 'Microsoft.CostManagement',
           'data_share_invitation': 'Microsoft.DataShare',
           'data_share_provider_subscription': 'Microsoft.DataShare',
           'defender_automation': 'Microsoft.Security',
           'directory_app_role_assignment': 'Microsoft.Graph',
           'directory_membership': 'Microsoft.Graph',
           'easm_data_connection': 'Defender EASM',
           'entra_domain_service': 'Microsoft.AAD',
           'external_id_auth_extension': 'Microsoft.Graph',
           'external_id_cross_tenant_default': 'Microsoft.Graph',
           'external_id_cross_tenant_partner': 'Microsoft.Graph',
           'fabric_external_data_share': 'Microsoft Fabric',
           'fabric_item': 'Microsoft Fabric',
           'fabric_workspace': 'Microsoft Fabric',
           'foundry_agent': 'Microsoft Foundry',
           'foundry_connection': 'Microsoft Foundry',
           'foundry_project': 'Microsoft.CognitiveServices',
           'ip_group': 'Microsoft.Network',
           'lighthouse_assignment': 'Microsoft.ManagedServices',
           'lighthouse_delegation': 'Microsoft.ManagedServices',
           'managed_application': 'Microsoft.Solutions',
           'managed_application_definition': 'Microsoft.Solutions',
           'managed_identity': 'Microsoft.ManagedIdentity',
           'network_cloud_vm': 'Microsoft.NetworkCloud',
           'newrelic_monitor': 'NewRelic.Observability',
           'newrelic_monitored_resource': 'NewRelic.Observability',
           'nginx_deployment': 'Nginx.NginxPlus',
           'notification_hub_namespace': 'Microsoft.NotificationHubs',
           'openshift_hcp_cluster': 'Microsoft.RedHatOpenShift',
           'oracle_cloud_vm_cluster': 'Oracle.Database',
           'palo_alto_firewall': 'PaloAltoNetworks.Cloudngfw',
           'playwright_workspace': 'Microsoft.LoadTestService',
           'powerbi_capacity': 'Microsoft.PowerBIDedicated',
           'powerbi_org_link': 'Power BI',
           'powerbi_published_item': 'Power BI',
           'purview_ediscovery_case_member': 'Microsoft.Graph eDiscovery',
           'purview_metadata_policy': 'Purview Data Map',
           'purview_unified_policy': 'Purview Unified Catalog',
           'redis_enterprise_database': 'Microsoft.Cache',
           'sentinel_automation_rule': 'Microsoft.SecurityInsights',
           'sentinel_source_control': 'Microsoft.SecurityInsights',
           'service_fabric_managed_cluster': 'Microsoft.ServiceFabric',
           'snapshot': 'Microsoft.Compute',
           'traffic_manager_profile': 'Microsoft.Network'},
 'gcp': {'access_level': 'accesscontextmanager',
         'access_policy': 'accesscontextmanager',
         'alloydb_user': 'alloydb',
         'api_gateway': 'apigateway',
         'api_gateway_resource': 'apigateway',
         'apigee_route': 'apigee',
         'app_engine_domain_mapping': 'appengine',
         'app_engine_firewall_rule': 'appengine',
         'app_engine_iap_policy': 'iap',
         'app_engine_instance': 'appengine',
         'backend_service_health': 'compute',
         'bigquery_routine_metadata': 'bigquery',
         'bigtable_authorized_view': 'bigtableadmin',
         'bigtable_backup': 'bigtableadmin',
         'bigtable_logical_view': 'bigtableadmin',
         'bigtable_materialized_view': 'bigtableadmin',
         'bigtable_table': 'bigtableadmin',
         'binary_authorization_platform_policy': 'binaryauthorization',
         'binary_authorization_policy': 'binaryauthorization',
         'bucket_acl': 'storage',
         'bucket_effective_iam': 'storage',
         'ca_pool': 'privateca',
         'cloudbuild_connection': 'cloudbuild',
         'clouddeploy_delivery_pipeline': 'clouddeploy',
         'cloudrun_instance': 'run',
         'cloudtasks_delivery': 'cloudtasks',
         'cloudtasks_queue': 'cloudtasks',
         'cloudtasks_task': 'cloudtasks',
         'containeranalysis_note': 'containeranalysis',
         'containeranalysis_occurrence': 'containeranalysis',
         'default_object_acl': 'storage',
         'developerconnect_git_repository_link': 'developerconnect',
         'dialogflow_es_fulfillment': 'dialogflow',
         'dlp_exposure': 'dlp',
         'dns_response_policy': 'dns',
         'eventarc_channel': 'eventarc',
         'eventarc_channel_connection': 'eventarc',
         'eventarc_enrollment': 'eventarc',
         'eventarc_message_bus': 'eventarc',
         'firebase_apphosting_endpoint': 'firebaseapphosting',
         'firebase_database_rules': 'firebasedatabase',
         'firebase_rules_release': 'firebaserules',
         'firestore_database': 'firestore',
         'firestore_user_cred': 'firestore',
         'fraud_defense_exposure': 'recaptchaenterprise',
         'gke_exposure_endpointslice': 'kubernetes',
         'gke_exposure_gateway': 'kubernetes',
         'gke_exposure_gatewayclass': 'kubernetes',
         'gke_exposure_httproute': 'kubernetes',
         'gke_exposure_ingress': 'kubernetes',
         'gke_exposure_multiclusteringress': 'kubernetes',
         'gke_exposure_node': 'kubernetes',
         'gke_exposure_pod': 'kubernetes',
         'gke_exposure_service': 'kubernetes',
         'identityplatform_config': 'identitytoolkit',
         'identityplatform_tenant': 'identitytoolkit',
         'instance_effective_firewall': 'compute',
         'lakehouse_resource': 'biglake',
         'machine_image': 'compute',
         'managed_folder': 'storage',
         'media_cdn_keyset': 'networkservices',
         'media_cdn_origin': 'networkservices',
         'migration_job': 'datamigration',
         'model_armor_exposure': 'modelarmor',
         'multicloud_exposure': 'gkemulticloud',
         'object_acl': 'storage',
         'pubsub_schema_iam': 'cloudasset',
         'pubsub_topic_attachment': 'pubsub',
         'sac_exposure': 'networksecurity',
         'service_extension_exposure': 'networkservices',
         'service_usage': 'serviceusage',
         'sovereign_partner_exposure': 'assuredworkloads',
         'spanner_backup': 'spanner',
         'spanner_database': 'spanner',
         'spanner_instance': 'spanner',
         'workflows_workflow': 'workflows',
         'workstations_config': 'workstations',
         'workstations_workstation': 'workstations'}}
for _provider, _labels in EXPOSURE_KIND_SERVICES.items():
    ANALYSIS_KIND_SERVICES[_provider].update(_labels)




@lru_cache(maxsize=1)
def _manifest():
    return json.loads(Path(__file__).with_name("check_services.json").read_text())


def service_for(provider, kind, observed=None):
    """Return the reviewed service of a check target, including empty scopes."""
    service = _manifest().get(provider, {}).get(kind)
    if service:
        return service
    if observed and observed not in ("azure", kind):
        return canonical_observed_service(provider, observed)
    return "kubernetes" if provider == "k8s" else canonical_observed_service(provider, observed or kind)


def canonical_observed_service(provider, observed):
    """Normalize legacy service labels without guessing from finding titles."""
    if not isinstance(observed, str) or not observed:
        return observed
    if provider == "k8s":
        return "kubernetes"
    return (_manifest().get(provider, {}).get(observed)
            or ANALYSIS_KIND_SERVICES.get(provider, {}).get(observed)
            or SERVICE_ALIASES.get(provider, {}).get(observed)
            or observed)


def service_for_check(check_id, provider, kind, observed=None):
    override = CHECK_SERVICE_OVERRIDES.get(check_id)
    if override:
        return override
    for prefix, service in CHECK_SERVICE_PREFIXES:
        if check_id.startswith(prefix):
            return service
    return service_for(provider, kind, observed)


@lru_cache(maxsize=1)
def _check_kinds():
    from peaso.checks import CHECKS
    return {check.id: (check.provider, check.kind) for check in CHECKS}


def finding_service(finding):
    """Also repair labels in reports created before the service manifest."""
    pair = _check_kinds().get(finding.get("check_id"))
    if pair:
        return service_for_check(finding["check_id"], *pair, finding.get("service"))
    return canonical_observed_service(finding.get("provider"), finding.get("service"))


# Publish lookup functions before network catalog imports can load collectors.
# Azure collectors use service_for while analysis initializes its provider types.
from peaso.analysis.network_catalog import NETWORK_SERVICE_LABELS
for _provider, _labels in NETWORK_SERVICE_LABELS.items():
    ANALYSIS_KIND_SERVICES[_provider].update(_labels)
