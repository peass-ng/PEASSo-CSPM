"""Native, bounded Azure metadata reads. Tokens never enter snapshot payloads."""
from __future__ import annotations

import base64
import functools
import hashlib
import http.client
import json
import math
import re
import os
import threading
import time
import xml.etree.ElementTree as ET
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from urllib.parse import quote, urlencode, urlsplit, parse_qs, parse_qsl
from urllib.error import URLError
from urllib.request import Request, urlopen, HTTPRedirectHandler, HTTPSHandler, build_opener
import urllib.request as _urllib_request
from .base import Budget, _bound
from .azure_apim_native import collect_apim
from . import azure_apim_protocol_policy
from . import azure_apim_diagnostic_evidence_native
from . import azure_public_edge_native
from . import azure_certificate_issuance_native
from . import azure_devops_pipeline_native
from . import azure_devops_git_native, azure_arm_metadata_native, azure_monitor_inventory_native, azure_aks_workloads_native, azure_databricks_native
from . import azure_aks_legacy_projection_review_20261020
from . import azure_storage_backup_native
from . import azure_defender_network_native
from . import azure_adaptive_network_native
from . import azure_conditional_access_native
from . import azure_identity_enforcement_review_20261020
from . import azure_access_reviews_native
from . import azure_entitlement_native
from . import azure_database_native
from . import azure_vault_key_versions_native
from . import azure_functions_runtime_native
from . import azure_iot_policy_native, azure_function_limits_native, azure_sentinel_metadata_native, azure_assessment_criteria_native, azure_secret_versions_native, azure_storage_recovery_metadata_native
from . import azure_incident_inventory_native
from . import azure_security_correlation_native
from . import azure_storage_blob_keys_native
from . import azure_audit_storage_native
from . import azure_entra_user_native
from . import azure_wave_compute_native
from . import azure_wave_change_native
from . import azure_wave_network_controls
from . import azure_subnet_firewall_policy
from . import azure_nsg_ingress_native
from . import azure_storage_lifecycle_native
from . import azure_key_rotation_evidence_native
from . import azure_selected_configuration_secret_indicators
from . import azure_app_settings_secret_indicators
from . import azure_acr_image_secret_indicators
from . import azure_selected_aks_image_20261021
from . import azure_acr_image_vulnerabilities_20261021
from . import azure_sql_ltr_native
from . import azure_alert_routing_native
from . import azure_ai_services_native
from . import azure_application_compute_2_native
from . import azure_acr_public_ip_review_20261020
from . import azure_automation_aci_metadata_native_20261020
from . import azure_devtestlab_native
from . import azure_agent_identity_native
from . import azure_containerapp_runtime
from . import azure_containerapp_jobs
from . import azure_mongo_cluster_metadata
from . import azure_mongo_cluster_exposure
from . import azure_remaining_services_1_native
from . import azure_native_contract_closure_20261020
from peaso.snapshot import make_snapshot
from peaso.check_services import service_for
from . import azure_network_catalog
from . import azure_notification_hubs_native
from . import azure_relay_native
from . import azure_lighthouse_native
from . import azure_cost_exports_native
from . import azure_managed_application_definitions_native
from . import azure_attestation_native
from . import azure_domain_services_native
from . import azure_defender_automations_native
from . import azure_nginx_native
from . import azure_webpubsub_hubs_native

ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com"
VAULT = "https://vault.azure.net"
STORAGE = "https://storage.azure.com"
LOGS = "https://api.loganalytics.io"

# Preserve provider-native properties (including NotActions, conditions and NSG
# priorities) rather than approximating effective permission or reachability.
ENDPOINTS = {
    "vnet": ("Microsoft.Network/virtualNetworks", "2023-09-01"),
    "nsg": ("Microsoft.Network/networkSecurityGroups", "2023-09-01"),
    "nic": ("Microsoft.Network/networkInterfaces", "2023-09-01"),
    "route_table": ("Microsoft.Network/routeTables", "2025-07-01"),
    "ip_group": ("Microsoft.Network/ipGroups", "2025-05-01"),
    "nat_gateway": ("Microsoft.Network/natGateways", "2023-09-01"),
    "public_ip": ("Microsoft.Network/publicIPAddresses", "2023-09-01"),
    "load_balancer": ("Microsoft.Network/loadBalancers", "2023-09-01"),
    "application_gateway": ("Microsoft.Network/applicationGateways", "2023-09-01"),
    "private_endpoint": ("Microsoft.Network/privateEndpoints", "2023-09-01"),
    "private_link_service": ("Microsoft.Network/privateLinkServices", "2023-09-01"),
    "private_dns_zone": ("Microsoft.Network/privateDnsZones", "2020-06-01"),
    "dns_zone": ("Microsoft.Network/dnsZones", "2018-05-01"),
    "vm": ("Microsoft.Compute/virtualMachines", "2023-09-01"),
    "snapshot": ("Microsoft.Compute/snapshots", "2023-10-02"),
    "disk": ("Microsoft.Compute/disks", "2023-10-02"),
    "app_service": ("Microsoft.Web/sites", "2023-12-01"),
    "app_service_plan": ("Microsoft.Web/serverfarms", "2023-12-01"),
    "app_service_environment": ("Microsoft.Web/hostingEnvironments", "2023-12-01"),
    "automation_account": ("Microsoft.Automation/automationAccounts", "2023-11-01"),
    "security_pricing": ("Microsoft.Security/pricings", "2024-01-01"),
    "security_contact": ("Microsoft.Security/securityContacts", "2023-12-01-preview"),
    "security_setting": ("Microsoft.Security/settings", "2022-05-01"),
    "activity_log_alert": ("Microsoft.Insights/activityLogAlerts", "2020-10-01"),
    "metric_alert": ("Microsoft.Insights/metricAlerts", "2018-03-01"),
    "scheduled_query_rule": ("Microsoft.Insights/scheduledQueryRules", "2021-08-01"),
    "action_group": ("Microsoft.Insights/actionGroups", "2023-01-01"),
    "storage_account": ("Microsoft.Storage/storageAccounts", "2026-06-01"),
    "sql_server": ("Microsoft.Sql/servers", "2023-08-01"),
    "aks_cluster": ("Microsoft.ContainerService/managedClusters", "2024-05-01"),
    "vault": ("Microsoft.KeyVault/vaults", "2023-07-01"),
    "redis_cache": ("Microsoft.Cache/redis", "2024-11-01"),
    "cognitive_account": ("Microsoft.CognitiveServices/accounts", "2024-10-01"),
    "app_configuration": ("Microsoft.AppConfiguration/configurationStores", "2024-06-01"),
    "data_factory": ("Microsoft.DataFactory/factories", "2018-06-01"),
    "devtest_lab": ("Microsoft.DevTestLab/labs", "2018-09-15"),
    "api_management": ("Microsoft.ApiManagement/service", "2024-05-01"),
    "analysis_server": ("Microsoft.AnalysisServices/servers", "2017-08-01"),
    "search_service": ("Microsoft.Search/searchServices", "2023-11-01"),
    "managed_identity": ("Microsoft.ManagedIdentity/userAssignedIdentities", "2023-01-31"),
    "managed_application": ("Microsoft.Solutions/applications", "2019-07-01"),
    "powerbi_capacity": ("Microsoft.PowerBIDedicated/capacities", "2021-01-01"),
    "container_registry": ("Microsoft.ContainerRegistry/registries", "2023-07-01"),
    "cosmos_account": ("Microsoft.DocumentDB/databaseAccounts", "2024-05-15"),
    "purview_account": ("Microsoft.Purview/accounts", "2021-12-01"),
    "databox_job": ("Microsoft.DataBox/jobs", "2025-07-01"),
    "mongo_cluster": ("Microsoft.DocumentDB/mongoClusters", "2026-06-01"),
    "nginx_deployment": (azure_nginx_native.TYPE, azure_nginx_native.VERSION),
    "openshift_hcp_cluster": ("Microsoft.RedHatOpenShift/hcpOpenShiftClusters", "2026-09-01-preview"),
    "databricks_workspace": ("Microsoft.Databricks/workspaces", "2024-05-01"),
    "kusto_cluster": ("Microsoft.Kusto/clusters", "2024-04-13"),
    'vm_scale_set': ('Microsoft.Compute/virtualMachineScaleSets', '2024-07-01'),
    'container_group': ('Microsoft.ContainerInstance/containerGroups', '2023-05-01'),
    'disk_access': ('Microsoft.Compute/diskAccesses', '2023-10-02'),
    'compute_gallery': ('Microsoft.Compute/galleries', '2026-04-01'),
    'databox_edge_device': ('Microsoft.DataBoxEdge/dataBoxEdgeDevices', '2023-07-01'),
    'jit_network_access_policy': ('Microsoft.Security/jitNetworkAccessPolicies', '2020-01-01'),
    'resource_link': ('Microsoft.Resources/links', '2016-09-01'),
    'eventgrid_domain': ('Microsoft.EventGrid/domains', '2022-06-15'),
    'eventgrid_topic': ('Microsoft.EventGrid/topics', '2022-06-15'),
    'eventhub_namespace': ('Microsoft.EventHub/namespaces', '2024-01-01'),
    'azure_firewall': ('Microsoft.Network/azureFirewalls', '2023-09-01'),
    'bot_service': ('Microsoft.BotService/botServices', '2022-09-15'),
    'frontdoor': ('Microsoft.Network/frontDoors', '2021-06-01'),
    'cdn_profile': ('Microsoft.Cdn/profiles', '2025-04-15'),
    'frontdoor_waf_policy': ('Microsoft.Network/frontDoorWebApplicationFirewallPolicies', '2024-05-01'),
    'hdinsight_cluster': ('Microsoft.HDInsight/clusters', '2021-06-01'),
    'healthcare_fhir_service': ('Microsoft.HealthcareApis/services', '2021-11-01'),
    'hpc_cache': ('Microsoft.StorageCache/caches', '2024-03-01'),
    'iot_hub': ('Microsoft.Devices/IotHubs', '2023-06-30'),
    'managed_hsm': ('Microsoft.KeyVault/managedHSMs', '2023-07-01'),
    'network_watcher': ('Microsoft.Network/networkWatchers', '2023-09-01'),
    'bastion_host': ('Microsoft.Network/bastionHosts', '2023-09-01'),
    'log_analytics_workspace': ('Microsoft.OperationalInsights/workspaces', '2023-09-01'),
    'log_analytics_cluster': ('Microsoft.OperationalInsights/clusters', '2023-09-01'),
    'image_template': ('Microsoft.VirtualMachineImages/imageTemplates', '2022-07-01'),
    'defender_auto_provisioning_setting': ('Microsoft.Security/autoProvisioningSettings', '2017-08-01-preview'),
    'postgresql_single_server': ('Microsoft.DBforPostgreSQL/servers', '2017-12-01'),
    'mysql_single_server': ('Microsoft.DBforMySQL/servers', '2017-12-01'),
    'mariadb_server': ('Microsoft.DBforMariaDB/servers', '2018-06-01'),
    'logic_app_workflow': ('Microsoft.Logic/workflows', '2019-05-01'),
    'ml_workspace': ('Microsoft.MachineLearningServices/workspaces', '2026-03-01'),
    'mssql_managed_instance': ('Microsoft.Sql/managedInstances', '2023-08-01'),
    'mysql_flexible_server': ('Microsoft.DBforMySQL/flexibleServers', '2024-12-30'),
    'postgresql_flexible_server': ('Microsoft.DBforPostgreSQL/flexibleServers', '2025-08-01'),
    'recovery_vault': ('Microsoft.RecoveryServices/vaults', '2024-04-01'),
    'policy_assignment': ('Microsoft.Authorization/policyAssignments', '2023-04-01'),
    'security_assessment': ('Microsoft.Security/assessments', '2020-01-01'),
    'iot_security_solution': ('Microsoft.Security/iotSecuritySolutions', '2019-08-01'),
    'servicebus_namespace': ('Microsoft.ServiceBus/namespaces', '2022-10-01-preview'),
    'service_fabric_cluster': ('Microsoft.ServiceFabric/clusters', '2021-06-01'),
    'signalr_service': ('Microsoft.SignalRService/signalR', '2024-03-01'),
    'web_pubsub': ('Microsoft.SignalRService/webPubSub', '2024-03-01'),
    'spring_cloud_service': ('Microsoft.AppPlatform/Spring', '2023-12-01'),
    'storage_sync_service': ('Microsoft.StorageSync/storageSyncServices', '2022-06-01'),
    'stream_analytics_job': ('Microsoft.StreamAnalytics/streamingjobs', '2020-03-01'),
    'synapse_workspace': ('Microsoft.Synapse/workspaces', '2021-06-01'),
    'easm_workspace': ('Microsoft.Easm/workspaces', '2023-04-01-preview'),
    'monitor_log_profile': ('Microsoft.Insights/logProfiles', '2016-03-01'),
    'web_application_firewall_policy': ('Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies', '2023-09-01'),
    'firewall_policy': ('Microsoft.Network/firewallPolicies', '2023-09-01'),
    "batch_account": ("Microsoft.Batch/batchAccounts", "2024-07-01"),
    "application_insights": ("Microsoft.Insights/components", "2020-02-02"),
    "resource_group": ("resourcegroups", "2021-04-01"),
    "arc_kubernetes_cluster": ("Microsoft.Kubernetes/connectedClusters", "2024-01-01"),
    "integration_service_environment": ("Microsoft.Logic/integrationServiceEnvironments", "2019-05-01"),
}
ENDPOINTS.update(azure_network_catalog.ENDPOINTS)

# Proxy/extension resource kinds whose ARM provider rejects
# Microsoft.Insights/diagnosticSettings (HTTP 400 on every item in live tenants).
# Requesting them only produced UNKNOWN coverage noise and wall time.
NO_DIAGNOSTIC_KINDS = frozenset({"resource_group", "security_pricing", "security_contact", "security_setting", "security_assessment",
                                 "jit_network_access_policy", "resource_link", "policy_assignment", "network_watcher", "defender_auto_provisioning_setting"})
# Kinds that are not tracked resources, so the subscription-wide ARM resource
# list (GET /subscriptions/{id}/resources) cannot prove they are absent.
RESOURCE_INDEX_EXEMPT = frozenset({"resource_group", "security_pricing", "security_contact", "security_setting", "security_assessment",
                                   "jit_network_access_policy", "resource_link", "policy_assignment", "iot_security_solution",
                                   "scheduled_query_rule", "defender_auto_provisioning_setting", "monitor_log_profile"})
# The resource-index short cut only pays off for broad (default/full) collection.
RESOURCE_INDEX_MIN_KINDS = 8
# Subscriptions per Resource Graph query (the API accepts up to 1000).
ARG_BATCH = 100
# Activity-log events are telemetry; claims, httpRequest, authorization and
# free-form properties are dropped at the source (smaller snapshot, less PII).
ACTIVITY_SELECT = ("eventTimestamp,submissionTimestamp,operationName,operationId,caller,status,subStatus,resourceId,resourceType,"
                   "resourceProviderName,resourceGroupName,eventDataId,category,level,correlationId,subscriptionId,tenantId")
# Parent embeds are authoritative child GET/list responses, with field coverage.
EMBEDDED_LISTS = {
    "container_app_environment": (("httpRouteConfigs", "httpRouteConfigs", "2026-01-01"),),
    "batch_account": (("pools", "pools", "2025-06-01"),),
    "vm_scale_set": (("virtualMachines", "virtualMachines", "2024-07-01"),
                     ("vmssNetworkInterfaces", "networkInterfaces", "2018-10-01"),
                     ("vmssPublicIPAddresses", "publicipaddresses", "2018-10-01")),
    "app_service": (("slots", "slots", "2023-12-01"), ("vnetConnections", "virtualNetworkConnections", "2023-12-01")),
    # Webhooks: metadata only (the invocation URI is a bearer secret and is never kept).
    "automation_account": (("variables", "variables", "2023-11-01"), ("webhooks", "webhooks", "2015-10-31")),
    "vm": (("resources", "extensions", "2023-09-01"), ("guestConfigurationAssignments", "providers/Microsoft.GuestConfiguration/guestConfigurationAssignments", "2024-04-05")),
    "container_registry": (("replications", "replications", "2023-07-01"), ("tokens", "tokens", "2023-07-01"), ("scopeMaps", "scopeMaps", "2023-07-01"), ("cacheRules", "cacheRules", "2023-07-01")),
    "aks_cluster": (("managedNamespaces", "managedNamespaces", "2025-10-01"),),
    "eventhub_namespace": (("eventHubs", "eventhubs", "2024-01-01"), ("authorizationRules", "authorizationRules", "2024-01-01"), ("disasterRecoveryConfigs", "disasterRecoveryConfigs", "2024-01-01")),
    "servicebus_namespace": (("authorizationRules", "AuthorizationRules", "2024-01-01"),),
    "network_watcher": (("flowLogs", "flowLogs", "2023-09-01"),),
    "mysql_flexible_server": (("configurations", "configurations", "2023-12-30"), ("firewallRules", "firewallRules", "2023-12-30"), ("administrators", "administrators", "2023-12-30"),
                              ("privateEndpointConnections", "privateEndpointConnections", "2024-12-30")),
    "postgresql_flexible_server": (("configurations", "configurations", "2024-08-01"), ("firewallRules", "firewallRules", "2024-08-01"), ("administrators", "administrators", "2024-08-01"),
                                   ("privateEndpointConnections", "privateEndpointConnections", "2024-08-01")),
    "postgresql_single_server": (("configurations", "configurations", "2017-12-01"), ("firewallRules", "firewallRules", "2017-12-01")),
    "redis_cache": (("firewallRules", "firewallRules", "2024-11-01"),
                    ("privateEndpointConnections", "privateEndpointConnections", "2024-11-01")),
    "redis_enterprise_cluster": (("privateEndpointConnections", "privateEndpointConnections", "2025-07-01"),),
    "mysql_single_server": (("configurations", "configurations", "2017-12-01"),),
    "web_pubsub": (("privateEndpointConnections", "privateEndpointConnections", "2024-03-01"),),
    "ml_workspace": (("privateEndpointConnections", "privateEndpointConnections", "2024-04-01"),
                     ("onlineEndpoints", "onlineEndpoints", "2024-04-01")),
    "compute_gallery": (("images", "images", "2025-12-03"),),
    "stream_analytics_job": (("streamOutputs", "outputs", "2020-03-01"),),
    "recovery_vault": (("backupPolicies", "backupPolicies", "2024-04-01"), ("backupProtectedItems", "backupProtectedItems", "2024-04-01"),
                       ("backupJobs", "backupJobs", "2024-04-01")),
    "mssql_managed_instance": (("instanceAdministrators", "administrators", "2023-08-01"),
                               ("azureADOnlyAuthentications", "azureADOnlyAuthentications", "2023-08-01"),
                               ("encryptionProtectors", "encryptionProtector", "2023-08-01"), ("vulnerabilityAssessments", "vulnerabilityAssessments", "2023-08-01"),
                               ("databases", "databases", "2021-11-01")),
    "storage_account": (("blobContainers", "blobServices/default/containers", "2023-05-01"), ("encryptionScopes", "encryptionScopes", "2023-05-01"),
                        ("eventSubscriptions", "providers/Microsoft.EventGrid/eventSubscriptions", "2022-06-15"),
                        ("localUsers", "localUsers", "2023-05-01")),
    "arc_kubernetes_cluster": (("extensions", "providers/Microsoft.KubernetesConfiguration/extensions", "2023-05-01"),),
    "sql_server": (("serverAdministrators", "administrators", "2023-08-01"), ("azureADOnlyAuthentications", "azureADOnlyAuthentications", "2023-08-01"), ("virtualNetworkRules", "virtualNetworkRules", "2023-08-01"), ("firewallRules", "firewallRules", "2023-08-01"), ("securityAlertPolicies", "securityAlertPolicies", "2023-08-01"), ("privateEndpointConnections", "privateEndpointConnections", "2023-08-01")),
    "synapse_workspace": (("sqlPools", "sqlPools", "2021-06-01"), ("firewallRules", "firewallRules", "2021-06-01"),
                          ("privateEndpointConnections", "privateEndpointConnections", "2021-06-01"),
                          ("workspaceVulnerabilityAssessments", "vulnerabilityAssessments", "2021-06-01")),
    "sql_database": (("backupShortTermRetentionPolicies", "backupShortTermRetentionPolicies", "2023-08-01"),
                     ("backupLongTermRetentionPolicies", "backupLongTermRetentionPolicies", "2023-08-01"),
                     ("longTermRetentionBackups", "longTermRetentionBackups", "2023-08-01"),
                     ("restorePoints", "restorePoints", "2023-08-01"),
                     ("vulnerabilityAssessmentScans", "vulnerabilityAssessments/default/scans", "2023-08-01")),
}
EMBEDDED_SINGLETONS = {
    "app_service": (("configuration", "config/web", "2023-12-01"), ("authSettingsV2", "config/authsettingsV2", "2025-03-01"), ("logsConfiguration", "config/logs", "2023-12-01"),
                    # Microsoft.Web/sites/basicPublishingCredentialsPolicies/read: only the allow flag is kept.
                    ("scmBasicAuthPolicy", "basicPublishingCredentialsPolicies/scm", "2023-12-01"), ("ftpBasicAuthPolicy", "basicPublishingCredentialsPolicies/ftp", "2023-12-01")),
    "app_service_slot": (("configuration", "config/web", "2023-12-01"),
                         ("authSettingsV2", "config/authsettingsV2", "2025-05-01"),
                         ("scmBasicAuthPolicy", "basicPublishingCredentialsPolicies/scm", "2023-12-01")),
    "eventhub_namespace": (("networkRuleSet", "networkRuleSets/default", "2024-01-01"),),
    "servicebus_namespace": (("networkRuleSet", "networkRuleSets/default", "2022-10-01-preview"),),
    "sql_server": (("vulnerabilityAssessment", "vulnerabilityAssessments/default", "2023-08-01"), ("expressVulnerabilityAssessment", "sqlVulnerabilityAssessments/default", "2023-08-01-preview"), ("encryptionProtector", "encryptionProtector/current", "2023-08-01")),
}


APP_CONFIG_FIELDS = {"minTlsVersion", "scmMinTlsVersion", "ftpsState", "http20Enabled", "remoteDebuggingEnabled", "httpLoggingEnabled", "detailedErrorLoggingEnabled", "requestTracingEnabled", "cors", "ipSecurityRestrictions", "ipSecurityRestrictionsDefaultAction", "scmIpSecurityRestrictions", "scmIpSecurityRestrictionsDefaultAction", "vnetRouteAllEnabled", "alwaysOn", "javaVersion", "javaContainer", "linuxFxVersion", "phpVersion", "pythonVersion", "netFrameworkVersion", "healthCheckPath", "numberOfWorkers", "vnetName"}
APP_CONFIG_FIELDS.update({"xManagedServiceIdentityId", "managedServiceIdentityId", "scmIpSecurityRestrictionsUseMain"})
# These optional nullable fields come from one authoritative, unmasked config
# GET. Recording known API omission as null preserves declaration presence;
# denied/partial reads still never attach a configuration object.
APP_NULLABLE_CONFIG_FIELDS = {"xManagedServiceIdentityId", "managedServiceIdentityId", "vnetName", "javaVersion", "javaContainer", "phpVersion", "pythonVersion", "linuxFxVersion", "healthCheckPath"}


def _logs_metadata(props):
    """Site logging switches only: blob sinks carry SAS URLs, which are never kept."""
    keep = {"enabled", "level", "retentionInDays", "retentionInMb"}
    def flags(value):
        return {key: data for key, data in value.items() if key in keep} if isinstance(value, dict) else value
    def sinks(value):
        return {name: flags(sink) for name, sink in value.items()} if isinstance(value, dict) else value
    return {key: (sinks(data) if key in ("applicationLogs", "httpLogs") else flags(data))
            for key, data in props.items() if key in ("applicationLogs", "httpLogs", "failedRequestsTracing", "detailedErrorMessages")}


_NETWORK_PLATFORM_NATIVE_TYPES = {
    "aks_cluster": "Microsoft.ContainerService/managedClusters",
    "vnet": "Microsoft.Network/virtualNetworks", "nsg": "Microsoft.Network/networkSecurityGroups",
    "network_watcher": "Microsoft.Network/networkWatchers",
    "application_gateway": "Microsoft.Network/applicationGateways",
    "web_application_firewall_policy": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
    "load_balancer": "Microsoft.Network/loadBalancers", "public_ip": "Microsoft.Network/publicIPAddresses",
    "frontdoor": "Microsoft.Network/frontDoors", "cdn_profile": "Microsoft.Cdn/profiles",
    "subnet": "Microsoft.Network/virtualNetworks/subnets", "flow_log": "Microsoft.Network/networkWatchers/flowLogs",
}


def _arm_parent_native_type(row, kind):
    """A declared ARM parent type must agree with its authoritative endpoint."""
    if kind not in ENDPOINTS:
        return  # Graph and derived/projection kinds have separate contracts.
    if not isinstance(row, dict):
        raise ValueError("malformed native ARM parent")
    if "type" not in row:
        return  # Optional omissions remain subject to existing family guards.
    expected = "Microsoft.Resources/resourceGroups" if kind == "resource_group" else ENDPOINTS[kind][0]
    if kind == "jit_network_access_policy":
        expected = "Microsoft.Security/locations/jitNetworkAccessPolicies"
    value = row["type"]
    # The official 2016-03-01 LogProfiles List example explicitly returns "".
    if kind == "monitor_log_profile" and value == "":
        return
    # The Security Contacts LIST example returns the singular resource type.
    if kind == "security_contact" and isinstance(value, str) and value.casefold() == "microsoft.security/securitycontact":
        return
    if not isinstance(value, str) or value.casefold() != expected.casefold():
        raise ValueError("native ARM parent type contradicts selected endpoint")


def _network_platform_native_identity(row, scope, kind):
    """Validate real ARM types/identities before attaching native provenance."""
    expected = _NETWORK_PLATFORM_NATIVE_TYPES.get(kind)
    if expected is None:
        return
    if not isinstance(row, dict) or str(row.get("type", "")).casefold() != expected.casefold():
        raise ValueError("native network/platform type differs from selected inventory")
    segment = r"[^/?#%\\\s]+"
    namespace, *types = expected.split("/")
    pattern = re.escape(scope) + "/resourceGroups/" + segment + "/providers/" + re.escape(namespace)
    for resource_type in types:
        pattern += "/" + re.escape(resource_type) + "/" + segment
    rid = row.get("id")
    if (not isinstance(rid, str) or re.fullmatch(pattern, rid, re.I) is None
            or any(part in (".", "..") for part in rid.split("/"))):
        raise ValueError("native network/platform identity differs from selected kind/scope")


def _child_rows(rows, parent_id, field):
    if any(not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"].lower().startswith(parent_id.lower() + "/") for row in rows):
        raise ValueError("malformed or foreign embedded child identity")
    db_provider = next((provider for provider in ("Microsoft.DBforMySQL", "Microsoft.DBforPostgreSQL")
                        if "/providers/" + provider.casefold() + "/flexibleservers/" in parent_id.casefold()), None)
    if field == "privateEndpointConnections" and db_provider:
        seen, safe = set(), []
        expected_type = db_provider + "/flexibleServers/privateEndpointConnections"
        for row in rows:
            rid = row["id"]
            props = row.get("properties")
            endpoint = props.get("privateEndpoint") if isinstance(props, dict) else None
            state = props.get("privateLinkServiceConnectionState") if isinstance(props, dict) else None
            remote = endpoint.get("id") if isinstance(endpoint, dict) else None
            if (re.fullmatch(re.escape(parent_id + "/privateEndpointConnections/") + r"[^/?#%\\\s]+", rid, re.I) is None
                    or rid.casefold() in seen
                    or "type" in row and str(row["type"]).casefold() != expected_type.casefold()
                    or "name" in row and str(row["name"]).casefold() != rid.rsplit("/", 1)[-1].casefold()
                    or not isinstance(props, dict)
                    or remote is not None and (not isinstance(remote, str) or re.fullmatch(
                        r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/privateEndpoints/[^/]+", remote, re.I) is None)):
                raise ValueError("foreign or malformed database private endpoint connection")
            seen.add(rid.casefold())
            safe.append({"id": rid, "parent_id": parent_id,
                         "properties": {"privateEndpoint": {"id": remote},
                                        "privateLinkServiceConnectionState": {"status": state.get("status") if isinstance(state, dict) else None},
                                        "provisioningState": props.get("provisioningState")}})
        return safe
    if field == "httpRouteConfigs":
        seen = set()
        for row in rows:
            rid = row["id"]
            if (not re.fullmatch(re.escape(parent_id + "/httpRouteConfigs/") + r"[^/?#%\\\s]+", rid, re.I)
                    or str(row.get("type", "")).casefold() != "microsoft.app/managedenvironments/httprouteconfigs"
                    or not isinstance(row.get("properties"), dict)
                    or rid.casefold() in seen):
                raise ValueError("duplicate, foreign or malformed Container Apps HTTP route")
            props = row["properties"]
            rules = props.get("rules")
            if (props.get("provisioningState") == "Succeeded"
                    and (not isinstance(props.get("fqdn"), str) or not props["fqdn"])):
                raise ValueError("successful Container Apps HTTP route lacks its FQDN")
            if (not isinstance(rules, list) or any(
                    not isinstance(rule, dict) or not isinstance(rule.get("targets"), list)
                    or any(not isinstance(target, dict)
                           or not isinstance(target.get("containerApp"), str)
                           for target in rule["targets"])
                    for rule in rules)):
                raise ValueError("malformed Container Apps HTTP route targets")
            seen.add(rid.casefold())
    if field == "pools":
        seen, safe = set(), []
        for row in rows:
            rid = row["id"]
            identity = row.get("identity") or {}
            props = row.get("properties")
            if (not re.fullmatch(re.escape(parent_id + "/pools/") + r"[^/?#%\\\s]+", rid, re.I)
                    or str(row.get("type", "")).casefold() != "microsoft.batch/batchaccounts/pools"
                    or not isinstance(props, dict) or not isinstance(identity, dict)
                    or rid.casefold() in seen):
                raise ValueError("duplicate or malformed native Batch pool")
            seen.add(rid.casefold())
            assignments = identity.get("userAssignedIdentities") or {}
            if not isinstance(assignments, dict) or any(
                    not isinstance(key, str) or not isinstance(detail, dict)
                    for key, detail in assignments.items()):
                raise ValueError("malformed Batch pool identities")
            safe.append({"id": rid, "name": row.get("name"), "type": row["type"],
                         "identity": {"type": identity.get("type"),
                                      "userAssignedIdentities": {key: {name: value for name, value in detail.items()
                                                                       if name in ("principalId", "clientId")}
                                                                 for key, detail in assignments.items()}},
                         "properties": {key: value for key, value in props.items()
                                        if key in ("provisioningState", "allocationState", "currentDedicatedNodes",
                                                   "currentLowPriorityNodes", "targetDedicatedNodes",
                                                   "targetLowPriorityNodes", "enableAutoScale")}})
        return safe
    if field == "flowLogs":
        seen = set()
        for row in rows:
            _network_platform_native_identity(row, "/".join(parent_id.split("/")[:3]), "flow_log")
            identity = row["id"].casefold()
            if (identity in seen or not re.fullmatch(re.escape(parent_id + "/flowLogs/") + r"[^/?#%\\\s]+", row["id"], re.I)
                    or not isinstance(row.get("properties"), dict)):
                raise ValueError("duplicate, foreign or malformed native flow log child")
            seen.add(identity)
    if field == "slots":
        if any(not re.fullmatch(re.escape(parent_id + "/slots/") + r"[^/?#%]+", row["id"], re.I)
               or str(row.get("type", "")).casefold() != "microsoft.web/sites/slots"
               or not isinstance(row.get("properties"), dict) for row in rows):
            raise ValueError("foreign or malformed native App Service slot")
    if field in ("configurations", "firewallRules", "administrators", "diagnosticSettings", "backupPolicies", "serverAdministrators", "instanceAdministrators", "azureADOnlyAuthentications", "virtualNetworkRules", "securityAlertPolicies", "vulnerabilityAssessmentScans", "vulnerabilityAssessments", "encryptionProtectors", "onlineEndpoints"):
        segment = ("providers/Microsoft.Insights/diagnosticSettings" if field == "diagnosticSettings" else
                   "administrators" if field in ("serverAdministrators", "instanceAdministrators") else
                   "encryptionProtector" if field == "encryptionProtectors" else
                   "vulnerabilityAssessments/default/scans" if field == "vulnerabilityAssessmentScans" else field)
        parent_type = re.split(r"/providers/", parent_id, maxsplit=1, flags=re.I)[1].rsplit("/", 1)[0]
        expected_type = ("Microsoft.Insights/diagnosticSettings" if field == "diagnosticSettings" else
                         "Microsoft.Sql/servers/databases/vulnerabilityAssessments/scans" if field == "vulnerabilityAssessmentScans" else parent_type + "/" + segment)
        optional_mi_type = (field in ("vulnerabilityAssessments", "encryptionProtectors")
                            and parent_type.casefold() == "microsoft.sql/managedinstances")
        for row in rows:
            if (not re.fullmatch(re.escape(parent_id + "/" + segment) + r"/[^/?#%]+", row["id"], re.I)
                    or (not optional_mi_type or "type" in row) and str(row.get("type", "")).casefold() != expected_type.casefold()
                    or not isinstance(row.get("name"), str)
                    or row["name"].casefold() != row["id"].rsplit("/", 1)[-1].casefold()
                    or not isinstance(row.get("properties"), dict)):
                raise ValueError("foreign or malformed native embedded child")
    if field == "azureADOnlyAuthentications":
        if (len(rows) != 1 or rows[0]["name"].casefold() != "default"
                or type(rows[0]["properties"].get("azureADOnlyAuthentication")) is not bool):
            raise ValueError("missing or malformed native SQL authentication mode")
        row = rows[0]
        return [{"id": row["id"], "name": row["name"], "type": row["type"],
                 "parent_id": parent_id,
                 "properties": {"azureADOnlyAuthentication": row["properties"]["azureADOnlyAuthentication"]}}]
    if field in ("serverAdministrators", "instanceAdministrators"):
        if len(rows) > 1 or any(row["name"].casefold() != "activedirectory" for row in rows):
            raise ValueError("malformed native SQL administrator list")
        return [{"id": row["id"], "name": row["name"], "type": row["type"],
                 "parent_id": parent_id,
                 "properties": {key: value for key, value in row["properties"].items()
                                if key in ("sid", "login", "tenantId", "administratorType")}}
                for row in rows]
    paths = {"privateEndpointConnections": "privateEndpointConnections", "managedNamespaces": "managedNamespaces",
             "eventHubs": "eventhubs", "authorizationRules": "authorizationRules", "disasterRecoveryConfigs": "disasterRecoveryConfigs",
             "tokens": "tokens", "scopeMaps": "scopeMaps", "cacheRules": "cacheRules",
             "localUsers": "localUsers", "extensions": "providers/Microsoft.KubernetesConfiguration/extensions",
             "backupShortTermRetentionPolicies": "backupShortTermRetentionPolicies",
             "eventSubscriptions": "providers/Microsoft.EventGrid/eventSubscriptions"}
    if field in paths and any(not re.fullmatch(re.escape(parent_id + "/" + paths[field]) + r"/[^/?#]+", row["id"], re.I) for row in rows):
        raise ValueError("foreign embedded child kind")
    if field == "authorizationRules":
        projected, seen = [], set()
        for row in rows:
            properties = row.get("properties")
            rights = properties.get("rights") if isinstance(properties, dict) else None
            identity = row["id"].casefold()
            if (identity in seen or not isinstance(row.get("name"), str)
                    or row["name"].casefold() != row["id"].rsplit("/", 1)[-1].casefold()
                    or not str(row.get("type", "")).casefold().endswith("/authorizationrules")
                    or not isinstance(rights, list)
                    or any(right not in ("Manage", "Send", "Listen") for right in rights)):
                raise ValueError("malformed messaging authorization rule")
            seen.add(identity)
            projected.append({"id": row["id"], "name": row["name"], "type": row["type"],
                              "parent_id": parent_id, "properties": {"rights": rights}})
        return projected
    if field in ("localUsers", "extensions", "backupShortTermRetentionPolicies"):
        seen = set()
        allowed = {"localUsers": {"permissionScopes", "homeDirectory", "hasSshPassword", "hasSshKey", "allowAclAuthorization", "sid", "hasSharedKey"},
                   "extensions": {"extensionType", "provisioningState", "version", "autoUpgradeMinorVersion"},
                   "backupShortTermRetentionPolicies": {"retentionDays", "diffBackupIntervalInHours"}}[field]
        safe = []
        for row in rows:
            key = row['id'].casefold()
            if key in seen or not isinstance(row.get('properties'), dict):
                raise ValueError('duplicate or malformed native child')
            seen.add(key)
            properties = {key: data for key, data in row['properties'].items() if key in allowed}
            if field == 'localUsers' and 'permissionScopes' in properties:
                scopes = properties['permissionScopes']
                if not isinstance(scopes, list) or any(not isinstance(scope, dict) for scope in scopes):
                    raise ValueError('malformed local user permissions')
                properties['permissionScopes'] = [{key: data for key, data in scope.items() if key in ('permissions', 'service', 'resourceName')} for scope in scopes]
            safe.append({**{key: data for key, data in row.items() if key in ('id', 'name', 'type')},
                         'parent_id': parent_id, 'properties': properties,
                         '_provenance': {'source_operation': {'localUsers': 'LocalUsers_List', 'extensions': 'Extensions_List', 'backupShortTermRetentionPolicies': 'BackupShortTermRetentionPolicies_ListByDatabase'}[field],
                                         'read_only': True, 'api_version': '2023-08-01' if field == 'backupShortTermRetentionPolicies' else '2023-05-01',
                                         'representation': 'metadata'}})
        return safe
    if field in ("tokens", "scopeMaps", "cacheRules"):
        # ACR management metadata only; never keep a token credential value.
        allowed = {"tokens": {"status", "scopeMapId", "provisioningState"},
                   "scopeMaps": {"actions", "type"},
                   "cacheRules": {"sourceRepository", "targetRepository", "credentialSetResourceId", "provisioningState"}}[field]
        return [{**{key: data for key, data in row.items() if key in ("id", "name", "type")}, "parent_id": parent_id,
                 "properties": {key: data for key, data in row.get("properties", {}).items() if key in allowed}} for row in rows]
    if field == "resources":
        # Only the selected VM's immediate extensions LIST can establish an
        # installed extension; a different child below the VM is not one.
        seen = set()
        for row in rows:
            identity = row["id"].casefold()
            if (not re.fullmatch(re.escape(parent_id + "/extensions/") + r"[^/?#]+", row["id"], re.I)
                    or str(row.get("type", "")).casefold() != "microsoft.compute/virtualmachines/extensions"
                    or not isinstance(row.get("properties"), dict) or identity in seen):
                raise ValueError("foreign, duplicate or malformed VM extension child")
            seen.add(identity)
        return [{**{key: data for key, data in row.items() if key in ("id", "name", "type", "location")},
                 "properties": {key: data for key, data in row.get("properties", {}).items() if key in ("publisher", "type", "provisioningState", "autoUpgradeMinorVersion")}} for row in rows]
    if field == "configurations":
        # Database configuration endpoints can contain credential-shaped options.
        allowed = {"audit_log_enabled", "audit_log_events", "tls_version", "require_secure_transport", "log_checkpoints", "connection_throttle.enable", "connection_throttling", "log_retention_days", "logfiles.retention_days", "log_connections", "log_disconnections", "log_duration", "aad_auth_only", "pgbouncer.enabled"}
        return [{**{key: data for key, data in row.items() if key in ("id", "name", "type")}, "parent_id": parent_id,
                 "properties": {key: data for key, data in row.get("properties", {}).items()
                                if key in ("value", "isReadOnly", "isDynamicConfig")}}
                for row in rows if row.get("name") in allowed]
    if field == "variables":
        # Unencrypted Automation variables return their value; only metadata is kept.
        return [{**{key: data for key, data in row.items() if key in ("id", "name", "type")}, "parent_id": parent_id,
                 "properties": {key: data for key, data in row.get("properties", {}).items() if key in ("isEncrypted", "creationTime", "lastModifiedTime")}} for row in rows]
    if field == "webhooks":
        # properties.uri is the anonymous invocation secret and parameters may carry
        # runbook inputs; only trigger metadata is kept.
        return [{**{key: data for key, data in row.items() if key in ("id", "name", "type")}, "parent_id": parent_id,
                 "properties": {key: (({"name": data.get("name")} if isinstance(data, dict) else data) if key == "runbook" else data)
                                for key, data in row.get("properties", {}).items()
                                if key in ("isEnabled", "expiryTime", "creationTime", "lastInvokedTime", "lastModifiedTime", "runOn", "runbook")}} for row in rows]
    if field == "vnetConnections":
        # VNet connection objects may include certificate blobs; only the
        # authoritative network association is needed by security predicates.
        return [{**{key: data for key, data in row.items() if key in ("id", "name", "type")}, "parent_id": parent_id,
                 "properties": {key: data for key, data in row.get("properties", {}).items() if key == "vnetResourceId"}} for row in rows]
    if field in ("backupJobs", "backupProtectedItems"):
        operation = {"backupJobs": "BackupJobs_List", "backupProtectedItems": "BackupProtectedItems_List"}[field]
        return [{**_metadata_only({**row, "parent_id": parent_id}),
                 "_provenance": {"source_operation": operation, "read_only": True,
                    "api_version": "2024-04-01", "representation": "metadata",
                    "endpoint": parent_id + "/" + field}}
                for row in rows]
    if field == "backupPolicies":
        return [{**_metadata_only({**row, "parent_id": parent_id}),
                 "_provenance": {"source_operation": "BackupPolicies_List", "read_only": True,
                     "api_version": "2024-04-01", "scope": parent_id,
                     "request_path": parent_id + "/backupPolicies"}}
                for row in rows]
    if field == "diagnosticSettings" and re.fullmatch(r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.(?:KeyVault/(?:managedHSMs|vaults)|Network/(?:applicationGateways|loadBalancers))/[^/]+", parent_id, re.I):
        return [{**_metadata_only({**row, "parent_id": parent_id}),
                 "_provenance": {"source_operation": "DiagnosticSettings_List", "read_only": True,
                     "api_version": "2021-05-01-preview", "scope": parent_id,
                     "request_path": parent_id + "/providers/Microsoft.Insights/diagnosticSettings"}}
                for row in rows]
    return [_metadata_only({**row, "parent_id": parent_id}) for row in rows]


def _vault_diagnostic_settings_pages(reader, request, url, parent_id):
    """Native unfiltered diagnostic LIST; exact child identity and operation proof."""
    expected = ARM + parent_id + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
    if url != expected:
        raise ValueError("vault diagnostic request differs from selected parent")
    seen = {}
    for page in reader.pages(request, url):
        distinct = []
        for row in _child_rows(page, parent_id, "diagnosticSettings"):
            identity = row["id"].casefold()
            if identity in seen:
                if seen[identity] != row:
                    raise ValueError("conflicting native vault diagnostic identity")
                continue
            seen[identity] = row
            distinct.append(row)
        yield distinct


def _sql_projected_child_pages(reader, request, url, parent_id, kind, segment):
    """The four direct SQL projections retain their authoritative child contract."""
    contracts = {'sql_database': ('databases', 'Microsoft.Sql/servers/databases'),
                 'sql_firewall_rule': ('firewallRules', 'Microsoft.Sql/servers/firewallRules'),
                 'sql_audit': ('auditingSettings', 'Microsoft.Sql/servers/auditingSettings'),
                 'sql_security': ('securityAlertPolicies', 'Microsoft.Sql/servers/securityAlertPolicies')}
    expected_segment, native_type = contracts[kind]
    if segment != expected_segment or url != ARM + parent_id + '/' + segment + '?api-version=2023-08-01':
        raise ValueError('SQL projected child request differs from selected native parent')
    seen = {}
    for page in reader.pages(request, url):
        safe = []
        for row in page:
            rid = row.get('id') if isinstance(row, dict) else None
            if (not isinstance(rid, str) or re.fullmatch(re.escape(parent_id + '/' + segment + '/') + r'[^/?#%\\\s]+', rid, re.I) is None
                    or rid.rsplit('/', 1)[-1] in ('.', '..')
                    or 'type' in row and str(row['type']).casefold() != native_type.casefold()
                    or 'name' in row and str(row['name']).casefold() != rid.rsplit('/', 1)[-1].casefold()
                    or not isinstance(row.get('properties'), dict)):
                raise ValueError('foreign or contradictory native SQL projected child')
            projected = _metadata_only({k: v for k, v in row.items() if k in ('id', 'name', 'type', 'location', 'kind', 'sku', 'identity', 'etag', 'properties')})
            if rid.casefold() in seen:
                if seen[rid.casefold()] != projected:
                    raise ValueError('conflicting native SQL projected child identity')
                continue
            seen[rid.casefold()] = projected
            safe.append(projected)
        yield safe


def _service_diagnostic_settings_pages(reader, request, url, parent_id):
    """The two reviewed gateway kinds reuse exact native diagnostic LIST guards."""
    if re.fullmatch(r"/subscriptions/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}/resourceGroups/[^/?#%\\\s]+/providers/Microsoft\.Network/(?:applicationGateways|loadBalancers)/[^/?#%\\\s]+", parent_id, re.I) is None:
        raise ValueError("unsupported service diagnostic parent")
    # This receipt is recorded only after the real dedicated native LIST and
    # every continuation completed. It also exists when the response has no
    # rows, where row-level provenance cannot establish absence.
    yield from _vault_diagnostic_settings_pages(reader, request, url, parent_id)
    receipts = getattr(reader, '_service_diagnostic_receipts', None)
    if receipts is None:
        receipts = reader._service_diagnostic_receipts = {}
    key = parent_id.casefold()
    if key in receipts:
        raise ValueError('duplicate dedicated service diagnostic read')
    receipts[key] = {'source_operation': 'DiagnosticSettings_List',
                     'api_version': '2021-05-01-preview', 'read_only': True,
                     'scope': parent_id,
                     'request_path': parent_id + '/providers/Microsoft.Insights/diagnosticSettings'}


def _bind_service_diagnostic_receipt(collection, reader):
    """Attach completed dedicated service LIST receipts before scan binding."""
    if collection.get('type') != 'diagnostic_setting' or collection.get('status') not in ('collected', 'empty'):
        return
    proof = getattr(reader, '_service_diagnostic_receipts', {}).get(collection['scope'].casefold())
    if proof is not None:
        collection.setdefault('_provenance', {}).update(proof)


def _function_trigger_rows(rows, site_id):
    """Keep only HTTP trigger declarations from FunctionEnvelope LIST rows."""
    safe = []
    expected_types = ({"microsoft.web/sites/slots/functions", "microsoft.web/sites/functions"}
                      if "/slots/" in site_id.casefold() else {"microsoft.web/sites/functions"})
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("malformed FunctionEnvelope")
        rid = row.get("id")
        if (not isinstance(rid, str) or not re.fullmatch(
                re.escape(site_id + "/functions/") + r"[^/?#%\\\s]+", rid, re.I)
                or str(row.get("type", "")).casefold() not in expected_types):
            raise ValueError("foreign or malformed FunctionEnvelope identity")
        props = row.get("properties")
        if not isinstance(props, dict):
            raise ValueError("malformed FunctionEnvelope properties")
        config = props.get("config")
        bindings = config.get("bindings") if isinstance(config, dict) else None
        complete = isinstance(bindings, list)
        triggers = []
        if complete:
            for binding in bindings:
                if not isinstance(binding, dict) or not isinstance(binding.get("type"), str):
                    complete = False
                    continue
                if binding["type"].casefold() != "httptrigger":
                    continue
                methods = binding.get("methods")
                if methods is not None and (not isinstance(methods, list) or
                                            any(not isinstance(method, str) for method in methods)):
                    complete = False
                    methods = None
                triggers.append({"authLevel": binding.get("authLevel") if isinstance(binding.get("authLevel"), str) else None,
                                 "methods": methods,
                                 "route": binding.get("route") if isinstance(binding.get("route"), str) else None})
        safe.append({"id": rid, "type": row["type"], "name": row.get("name"),
                     "properties": {"isDisabled": props.get("isDisabled") if type(props.get("isDisabled")) is bool else None,
                                    "httpTriggers": triggers, "triggerConfigComplete": complete}})
    return safe


def _embed(reader, request, parents, diagnostics=None, skip=()):
    """Bound independent child reads; never fabricate empty on denied/partial.

    diagnostics: {parent id (casefolded): diagnostic_setting collection} already
    read for the same parent; reused instead of issuing the identical read twice.
    """
    jobs = []
    diagnostics = diagnostics or {}
    function_sites = {item["id"].casefold() for collection in reader.collections
                      if collection["type"] == "app_service" for item in collection["items"]
                      if isinstance(item.get("id"), str) and "functionapp" in
                      {part.strip().casefold() for part in str(item.get("kind", "")).split(",")}}
    for kind, item in parents:
        rid = item["id"]
        specs = list(EMBEDDED_LISTS.get(kind, ()))
        site_id = re.split(r"/slots/", rid, maxsplit=1, flags=re.I)[0] if kind == "app_service_slot" else rid
        if kind in ("app_service", "app_service_slot") and site_id.casefold() in function_sites:
            specs.append(("functions", "functions", "2025-05-01"))
        if kind == "container_registry" and item.get("sku", {}).get("name") != "Premium":
            specs = [spec for spec in specs if spec[0] != "replications"]
        known = diagnostics.get(rid.casefold())
        if known is not None:
            item.setdefault("_coverage", {})["diagnosticSettings"] = {key: known[key] for key in ("status", "error") if key in known}
            if known["status"] in ("collected", "empty") or known["items"]:
                if kind == "managed_hsm":
                    try:
                        item["diagnosticSettings"] = _child_rows(known["items"], rid, "diagnosticSettings")
                    except (ValueError, TypeError, KeyError):
                        item["_coverage"]["diagnosticSettings"] = {"status": "malformed"}
                        item.pop("diagnosticSettings", None)
                else:
                    item["diagnosticSettings"] = [_metadata_only({**row, "parent_id": rid}) for row in known["items"]]
        elif kind not in NO_DIAGNOSTIC_KINDS:
            specs.append(("diagnosticSettings", "providers/Microsoft.Insights/diagnosticSettings", "2021-05-01-preview"))
        if kind == "storage_service" and str(item.get("type", "")).lower().endswith("/fileservices"):
            specs.append(("shares", "shares", "2023-05-01"))
        for field, path, version in specs:
            if field in skip:
                continue
            if kind in ("mysql_flexible_server", "postgresql_flexible_server") and field == "privateEndpointConnections":
                props = item.get("properties")
                if isinstance(props, dict) and field in props:
                    embedded = props.pop(field)
                    try:
                        if not isinstance(embedded, list):
                            raise ValueError("malformed embedded MySQL private endpoints")
                        projected = _child_rows(embedded, rid, field)
                        item[field] = projected
                        item.setdefault("_coverage", {})[field] = {"status": "collected" if projected else "empty"}
                    except ValueError:
                        item.setdefault("_coverage", {})[field] = {"status": "malformed"}
                    continue
            url = ARM + rid + "/" + path + "?api-version=" + version
            def fetch(url=url, rid=rid, field=field, item=item, kind=kind):
                if field == 'longTermRetentionBackups':
                    native_path, _, _ = azure_sql_ltr_native.binding(item)
                    url = ARM + native_path + '?api-version=' + azure_sql_ltr_native.VERSION + '&databaseState=Live'
                    seen = set()
                    for page in reader.pages(request, url):
                        projected = azure_sql_ltr_native.project(page, item)
                        for backup in projected:
                            if backup['id'].casefold() in seen:
                                raise ValueError('duplicate SQL LTR backup across pages')
                            seen.add(backup['id'].casefold())
                        yield projected
                    return
                backup_seen = {}
                workspace_va_seen = {}
                messaging_rule_seen = set()
                for page in reader.pages(request, url):
                    if field == "streamOutputs":
                        projected = []
                        for row in page:
                            identity = row.get("id") if isinstance(row, dict) else None
                            props = row.get("properties") if isinstance(row, dict) else None
                            source = props.get("datasource") if isinstance(props, dict) else None
                            destination = source.get("properties") if isinstance(source, dict) else None
                            if (not isinstance(identity, str) or re.fullmatch(
                                    re.escape(rid + "/outputs/") + r"[^/?#%\\\s]+", identity, re.I) is None
                                    or str(row.get("type", "")).casefold() != "microsoft.streamanalytics/streamingjobs/outputs"
                                    or not isinstance(source, dict) or not isinstance(source.get("type"), str)
                                    or not isinstance(destination, dict) or identity.casefold() in backup_seen):
                                raise ValueError("duplicate, foreign or malformed Stream Analytics output")
                            backup_seen[identity.casefold()] = row
                            safe = {key: destination[key] for key in (
                                "tenantId", "accountName", "accountId", "server", "database",
                                "serviceBusNamespace", "functionAppName", "functionName",
                                "groupId", "groupName") if isinstance(destination.get(key), str)}
                            accounts = destination.get("storageAccounts")
                            if isinstance(accounts, list):
                                safe["storageAccounts"] = [{"accountName": account["accountName"]}
                                                           for account in accounts if isinstance(account, dict)
                                                           and isinstance(account.get("accountName"), str)]
                            projected.append({"id": identity, "parent_id": rid,
                                              "properties": {"datasource": {"type": source["type"],
                                                                              "properties": safe}}})
                        yield projected
                        continue
                    if kind == "vm_scale_set" and field in ("vmssNetworkInterfaces", "vmssPublicIPAddresses"):
                        projected = []
                        suffix = (r"/virtualMachines/[^/?#%\\\s]+/networkInterfaces/[^/?#%\\\s]+"
                                  if field == "vmssNetworkInterfaces" else
                                  r"/virtualMachines/[^/?#%\\\s]+/networkInterfaces/[^/?#%\\\s]+/ipConfigurations/[^/?#%\\\s]+/publicIPAddresses/[^/?#%\\\s]+")
                        for row in page:
                            identity = row.get("id") if isinstance(row, dict) else None
                            props = row.get("properties") if isinstance(row, dict) else None
                            if (not isinstance(identity, str) or re.fullmatch(re.escape(rid) + suffix, identity, re.I) is None
                                    or not isinstance(props, dict) or identity.casefold() in backup_seen):
                                raise ValueError("foreign, duplicate or malformed VMSS network child")
                            backup_seen[identity.casefold()] = row
                            if field == "vmssNetworkInterfaces":
                                fields = ("ipConfigurations", "networkSecurityGroup", "provisioningState")
                            else:
                                fields = ("ipAddress", "ipConfiguration", "provisioningState", "publicIPAddressVersion")
                            projected.append({"id": identity, "name": row.get("name"),
                                              "properties": _metadata_only({key: props[key] for key in fields if key in props}),
                                              **({"sku": row["sku"]} if "sku" in row else {})})
                        yield projected
                        continue
                    if field == "functions":
                        projected = _function_trigger_rows(page, rid)
                        for row in projected:
                            key = row["id"].casefold()
                            if key in backup_seen:
                                raise ValueError("duplicate function across pages")
                            backup_seen[key] = row
                        yield projected
                        continue
                    if field == "authorizationRules":
                        projected = _child_rows(page, rid, field)
                        if any(row["id"].casefold() in messaging_rule_seen for row in projected):
                            raise ValueError("duplicate messaging rule across pages")
                        messaging_rule_seen.update(row["id"].casefold() for row in projected)
                        yield projected
                        continue
                    if field == "workspaceVulnerabilityAssessments":
                        projected = []
                        for row in _child_rows(page, rid, field):
                            if (row["id"].casefold() != (rid + "/vulnerabilityAssessments/default").casefold() or
                                    str(row.get("type", "")).casefold() != "microsoft.synapse/workspaces/vulnerabilityassessments" or
                                    not isinstance(row.get("properties"), dict)):
                                raise ValueError("foreign or malformed workspace vulnerability assessment")
                            key = row["id"].casefold()
                            if key in workspace_va_seen:
                                if workspace_va_seen[key] != row:
                                    raise ValueError("conflicting workspace vulnerability assessment identity")
                                continue
                            workspace_va_seen[key] = row
                            projected.append({**{name: data for name, data in row.items() if name in ("id", "name", "type", "parent_id")},
                                              "properties": {name: data for name, data in row["properties"].items() if name == "recurringScans"}})
                        yield projected
                        continue
                    if field == "images":
                        projected = []
                        for row in page:
                            image_id = row.get("id") if isinstance(row, dict) else None
                            if (not isinstance(image_id, str) or re.fullmatch(
                                    re.escape(rid + "/images/") + r"[^/?#%\\\s]+", image_id, re.I) is None
                                    or str(row.get("type", "")).casefold() != "microsoft.compute/galleries/images"):
                                raise ValueError("foreign or malformed gallery image definition")
                            projected.append({"id": image_id, "name": row.get("name"), "type": row["type"]})
                        yield projected
                        continue
                    if field in ("backupJobs", "backupProtectedItems", "configurations", "firewallRules", "administrators", "diagnosticSettings", "backupPolicies", "slots", "serverAdministrators", "instanceAdministrators", "azureADOnlyAuthentications", "virtualNetworkRules", "securityAlertPolicies", "vulnerabilityAssessmentScans", "vulnerabilityAssessments", "encryptionProtectors", "onlineEndpoints"):
                        distinct = []
                        for row in page:
                            identity = row.get("id") if isinstance(row, dict) else None
                            if not isinstance(identity, str) or not identity:
                                raise ValueError("missing native backup child identity")
                            key = identity.casefold()
                            if key in backup_seen:
                                if backup_seen[key] != row:
                                    raise ValueError("conflicting native backup child identity")
                                continue
                            backup_seen[key] = row
                            distinct.append(row)
                        page = distinct
                    yield _child_rows(page, rid, field)
            jobs.append((item, field, True, ("embedded_" + field, rid, "Microsoft.Resources", fetch)))
        for field, path, version in EMBEDDED_SINGLETONS.get(kind, ()):
            if field in skip:
                continue
            url = ARM + rid + "/" + path + "?api-version=" + version
            def fetch(url=url, rid=rid, path=path, field=field):
                value = reader.call(request, url)
                if not isinstance(value, dict) or not isinstance(value.get("properties"), dict) or str(value.get("id", "")).lower() != (rid + "/" + path).lower():
                    raise ValueError("malformed embedded singleton")
                expected_sql_type = {"vulnerabilityAssessment": "Microsoft.Sql/servers/vulnerabilityAssessments",
                                     "expressVulnerabilityAssessment": "Microsoft.Sql/servers/sqlVulnerabilityAssessments",
                                     "encryptionProtector": "Microsoft.Sql/servers/encryptionProtector"}.get(field)
                if expected_sql_type and str(value.get("type", "")).casefold() != expected_sql_type.casefold():
                    raise ValueError("native SQL singleton type differs from requested child")
                if field == "configuration":
                    props = value["properties"]
                    projected = {key: data for key, data in props.items() if key in APP_CONFIG_FIELDS}
                    projected.update({key: None for key in APP_NULLABLE_CONFIG_FIELDS if key not in props})
                    value = {**{key: data for key, data in value.items() if key in ("id", "name", "type", "location")}, "properties": projected}
                elif field in ("scmBasicAuthPolicy", "ftpBasicAuthPolicy"):
                    value = {**{key: data for key, data in value.items() if key in ("id", "name", "type")},
                             "properties": {key: data for key, data in value["properties"].items() if key == "allow"}}
                elif field == "logsConfiguration":
                    value = {**{key: data for key, data in value.items() if key in ("id", "name", "type", "location")}, "properties": _logs_metadata(value["properties"])}
                elif field == "authSettingsV2":
                    props = value["properties"]
                    safe = {}
                    for key, fields in (("platform", ("enabled",)), ("globalValidation", ("requireAuthentication", "unauthenticatedClientAction", "excludedPaths"))):
                        if key in props:
                            safe[key] = {name: data for name, data in props[key].items() if name in fields} if isinstance(props[key], dict) else props[key]
                    if "identityProviders" in props:
                        providers = props["identityProviders"]
                        safe["identityProviders"] = {name: {key: data for key, data in settings.items() if key == "enabled"} if isinstance(settings, dict) else settings for name, settings in providers.items()} if isinstance(providers, dict) else providers
                    value = {**{key: data for key, data in value.items() if key in ("id", "name", "type", "location")}, "properties": safe}
                yield [_metadata_only(value)]
            jobs.append((item, field, False, ("embedded_" + field, rid, "Microsoft.Resources", fetch)))
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        results = pool.map(reader._read, [job[3] for job in jobs])
        for (item, field, is_list, _), read in zip(jobs, results):
            item.setdefault("_coverage", {})[field] = {key: read[key] for key in ("status", "error") if key in read}
            if field in ('localUsers', 'extensions', 'backupShortTermRetentionPolicies'):
                item['_coverage'][field]['parent_id'] = item['id']
            if field == 'guestConfigurationAssignments':
                item['_coverage'][field]['_provenance'] = {
                    'source_operation':'GuestConfigurationAssignments_List','read_only':True,
                    'api_version':'2024-04-05','observed_at':datetime.now(timezone.utc).isoformat()}
            if read["status"] in ("collected", "empty"):
                item[field] = read["items"] if is_list else read["items"][0]
            elif read["items"]:
                item[field] = read["items"] if is_list else read["items"][0]


def _collect_managed_application_jit(reader, request, parents):
    """One credential-free JIT request LIST per resource group with JIT applications."""
    groups = {}
    for kind, item in parents:
        if kind != "managed_application" or not isinstance(item.get("properties"), dict):
            continue
        policy = item["properties"].get("jitAccessPolicy")
        if not isinstance(policy, dict) or policy.get("jitAccessEnabled") is not True:
            continue
        match = re.fullmatch(r"(.+/resourceGroups/[^/?#%\\\s]+)/providers/Microsoft\.Solutions/applications/[^/?#%\\\s]+",
                             item["id"], re.I)
        if not match:
            item.setdefault("_coverage", {})["jitRequests"] = {"status": "malformed"}
            continue
        groups.setdefault(match.group(1), []).append(item)

    def job(group):
        url = ARM + group + "/providers/Microsoft.Solutions/jitRequests?api-version=2019-07-01"
        def fetch():
            seen = set()
            for page in reader.pages(request, url):
                projected = []
                for row in page:
                    rid = row.get("id") if isinstance(row, dict) else None
                    props = row.get("properties") if isinstance(row, dict) else None
                    if (not isinstance(rid, str) or re.fullmatch(
                            re.escape(group + "/providers/Microsoft.Solutions/jitRequests/") + r"[^/?#%\\\s]+", rid, re.I) is None
                            or str(row.get("type", "")).casefold() != "microsoft.solutions/jitrequests"
                            or not isinstance(props, dict) or not isinstance(props.get("applicationResourceId"), str)
                            or rid.casefold() in seen):
                        raise ValueError("duplicate, foreign or malformed managed application JIT request")
                    seen.add(rid.casefold())
                    schedule = props.get("jitSchedulingPolicy")
                    if schedule is not None and not isinstance(schedule, dict):
                        raise ValueError("malformed managed application JIT schedule")
                    projected.append({"id": rid, "properties": {
                        **{key: props[key] for key in ("applicationResourceId", "jitRequestState",
                                                         "publisherTenantId", "provisioningState") if key in props},
                        "jitSchedulingPolicy": {key: schedule[key] for key in ("startTime", "duration", "type")
                                                if key in schedule} if schedule else None}})
                yield projected
        return reader._read(("embedded_managedApplicationJitRequests", group, "Microsoft.Solutions", fetch))

    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        for group, result in zip(groups, pool.map(job, groups)):
            for item in groups[group]:
                item.setdefault("_coverage", {})["jitRequests"] = {key: result[key] for key in ("status", "error") if key in result}
                item["jitRequests"] = [row for row in result["items"]
                                       if row["properties"]["applicationResourceId"].casefold() == item["id"].casefold()]


def _collect_gallery_versions(reader, request, parents):
    """Resolve image-version identities only for observed gallery image definitions."""
    for kind, gallery in parents:
        if kind != "compute_gallery":
            continue
        image_coverage = (gallery.get("_coverage") or {}).get("images") or {}
        if image_coverage.get("status") not in ("collected", "empty"):
            continue
        for image in gallery.get("images", []):
            image_id = image["id"]
            url = ARM + image_id + "/versions?api-version=2025-12-03"
            def fetch(url=url, image_id=image_id):
                for page in reader.pages(request, url):
                    projected = []
                    for row in page:
                        version_id = row.get("id") if isinstance(row, dict) else None
                        if (not isinstance(version_id, str) or re.fullmatch(
                                re.escape(image_id + "/versions/") + r"[^/?#%\\\s]+", version_id, re.I) is None
                                or str(row.get("type", "")).casefold() != "microsoft.compute/galleries/images/versions"):
                            raise ValueError("foreign or malformed gallery image version")
                        props = row.get("properties") or {}
                        if not isinstance(props, dict):
                            raise ValueError("malformed gallery image version properties")
                        publishing = props.get("publishingProfile") or {}
                        if not isinstance(publishing, dict):
                            raise ValueError("malformed gallery image publishing profile")
                        projected.append({"id": version_id, "name": row.get("name"), "type": row["type"],
                                          "properties": {"provisioningState": props.get("provisioningState"),
                                                         "publishingProfile": {key: publishing[key] for key in ("publishedDate", "excludeFromLatest") if key in publishing}}})
                    yield projected
            read = reader._read(("embedded_galleryVersions", image_id, "Microsoft.Resources", fetch))
            image.setdefault("_coverage", {})["versions"] = {key: read[key] for key in ("status", "error") if key in read}
            if read["status"] in ("collected", "empty") or read["items"]:
                image["versions"] = read["items"]


def _collect_servicebus_entity_rules(reader, request, parents):
    """Read queue/topic SAS rule rights through bound, paged ARM LISTs."""
    for kind, namespace in parents:
        if kind != "servicebus_namespace":
            continue
        rid = namespace["id"]
        for field in ("queues", "topics"):
            list_url = ARM + rid + "/" + field + "?api-version=2024-01-01"
            def list_entities(list_url=list_url, rid=rid, field=field):
                seen = set()
                for page in reader.pages(request, list_url):
                    projected = []
                    for row in page:
                        entity_id = row.get("id") if isinstance(row, dict) else None
                        if (not isinstance(entity_id, str) or not re.fullmatch(
                                re.escape(rid + "/" + field + "/") + r"[^/?#%\\\s]+", entity_id, re.I)
                                or str(row.get("type", "")).casefold() !=
                                "microsoft.servicebus/namespaces/" + field
                                or not isinstance(row.get("name"), str)
                                or row["name"].casefold() != entity_id.rsplit("/", 1)[-1].casefold()
                                or entity_id.casefold() in seen):
                            raise ValueError("duplicate or malformed Service Bus entity")
                        seen.add(entity_id.casefold())
                        projected.append({"id": entity_id, "name": row["name"], "type": row["type"]})
                    yield projected
            read = reader._read(("servicebus_" + field, rid, "Microsoft.Resources", list_entities))
            namespace.setdefault("_coverage", {})[field] = {key: read[key] for key in ("status", "error") if key in read}
            if read["status"] in ("collected", "empty") or read["items"]:
                namespace[field] = read["items"]
            for entity in namespace.get(field, []):
                entity_id = entity["id"]
                rule_url = ARM + entity_id + "/authorizationRules?api-version=2024-01-01"
                def list_rules(rule_url=rule_url, entity_id=entity_id):
                    seen = set()
                    for page in reader.pages(request, rule_url):
                        projected = _child_rows(page, entity_id, "authorizationRules")
                        if any(row["id"].casefold() in seen for row in projected):
                            raise ValueError("duplicate Service Bus rule across pages")
                        seen.update(row["id"].casefold() for row in projected)
                        yield projected
                rule_read = reader._read(("servicebus_" + field + "_rules", entity_id,
                                          "Microsoft.Resources", list_rules))
                entity.setdefault("_coverage", {})["authorizationRules"] = {
                    key: rule_read[key] for key in ("status", "error") if key in rule_read}
                if rule_read["status"] in ("collected", "empty") or rule_read["items"]:
                    entity["authorizationRules"] = rule_read["items"]


def _collect_hsm_local_assignments(reader, request, transport, parents):
    """Read Managed HSM local RBAC at broad and observed key scopes."""
    for kind, hsm in parents:
        if kind != "managed_hsm":
            continue
        rid = hsm["id"]
        uri = (hsm.get("properties") or {}).get("hsmUri")
        coverage = hsm.setdefault("_coverage", {})
        try:
            name = rid.rsplit("/", 1)[-1]
            parsed = urlsplit(uri) if isinstance(uri, str) else None
            host = parsed.netloc.lower() if parsed else ""
            if (parsed is None or parsed.scheme != "https" or parsed.username or parsed.password
                    or parsed.port or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                    or re.fullmatch(r"(?:[a-z0-9-]+\.)?" + re.escape(name.lower())
                                    + r"\.managedhsm\.azure\.net", host) is None):
                raise ValueError("HSM data-plane URI does not match selected ARM parent")
            if hasattr(transport, "allow_hsm"):
                transport.allow_hsm(uri, name)
        except (ValueError, AzureReadError):
            coverage["localRoleAssignments"] = {"status": "malformed"}
            continue
        origin = "https://" + host
        found, states = {}, []
        def key_names():
            for page in reader.pages(request, origin + "/keys?api-version=2025-07-01", audience=VAULT):
                projected = []
                for row in page:
                    kid = row.get("kid") if isinstance(row, dict) else None
                    if (not isinstance(kid, str) or re.fullmatch(re.escape(origin + "/keys/")
                            + r"[^/?#%\\\s]+", kid, re.I) is None):
                        raise ValueError("foreign or malformed HSM key identity")
                    projected.append({"id": kid})
                yield projected
        key_read = reader._read(("embedded_hsmKeyNames", rid, "Microsoft.KeyVault", key_names))
        coverage["localRoleAssignmentKeys"] = {key: key_read[key] for key in ("status", "error") if key in key_read}
        scopes = ["/", "/keys"] + ["/keys/" + row["id"].rsplit("/", 1)[-1] for row in key_read["items"]]
        for scope in scopes:
            path = "/" + scope + ("/" if scope != "/" else "") + "providers/Microsoft.Authorization/roleAssignments"
            url = origin + path + "?api-version=2025-07-01"
            def fetch(url=url, scope=scope):
                for page in reader.pages(request, url, audience=VAULT):
                    projected = []
                    for row in page:
                        props = row.get("properties") if isinstance(row, dict) else None
                        assignment_id = row.get("id") if isinstance(row, dict) else None
                        if (not isinstance(props, dict) or not isinstance(assignment_id, str)
                                or not re.fullmatch(re.escape(scope.rstrip("/") + "/providers/Microsoft.Authorization/roleAssignments/")
                                                    + r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", assignment_id, re.I)
                                or props.get("scope") != scope
                                or not isinstance(props.get("principalId"), str)
                                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", props["principalId"], re.I)
                                or not isinstance(props.get("roleDefinitionId"), str)
                                or not re.fullmatch(r"/(?:keys(?:/[^/?#%\\\s]+)?/)?providers/Microsoft\.Authorization/roleDefinitions/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", props["roleDefinitionId"], re.I)
                                or str(row.get("type", "")).casefold() != "microsoft.authorization/roleassignments"):
                            raise ValueError("malformed HSM local role assignment")
                        projected.append({"id": assignment_id, "name": row.get("name"), "type": row["type"],
                                          "properties": {key: props[key] for key in ("principalId", "roleDefinitionId", "scope")}})
                    yield projected
            read = reader._read(("embedded_hsmLocalRoleAssignments", rid + scope, "Microsoft.KeyVault", fetch))
            states.append({"scope": scope, **{key: read[key] for key in ("status", "error") if key in read}})
            for row in read["items"]:
                found.setdefault(row["id"].casefold(), row)
        coverage["localRoleAssignments"] = {"status": "collected" if key_read["status"] in ("collected", "empty") and all(state["status"] in ("collected", "empty") for state in states)
                                            else "partial", "scopes": states}
        hsm["localRoleAssignments"] = list(found.values())
        def role_definitions():
            url = origin + "//keys/providers/Microsoft.Authorization/roleDefinitions?api-version=2025-07-01"
            for page in reader.pages(request, url, audience=VAULT):
                projected = []
                for row in page:
                    definition_id = row.get("id") if isinstance(row, dict) else None
                    props = row.get("properties") if isinstance(row, dict) else None
                    if (not isinstance(definition_id, str)
                            or re.fullmatch(r"/(?:keys/)?providers/Microsoft\.Authorization/roleDefinitions/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", definition_id, re.I) is None
                            or str(row.get("type", "")).casefold() != "microsoft.authorization/roledefinitions"
                            or not isinstance(props, dict) or not isinstance(props.get("permissions"), list)):
                        raise ValueError("malformed HSM local role definition")
                    permissions = []
                    for permission in props["permissions"]:
                        if not isinstance(permission, dict):
                            raise ValueError("malformed HSM role permissions")
                        selected = {}
                        for field in ("actions", "notActions", "dataActions", "notDataActions"):
                            values = permission.get(field, [])
                            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                                raise ValueError("malformed HSM role permission actions")
                            selected[field] = values
                        permissions.append(selected)
                    projected.append({"id": definition_id, "name": row.get("name"), "type": row["type"],
                                      "properties": {"roleName": props.get("roleName"), "permissions": permissions}})
                yield projected
        definitions_read = reader._read(("embedded_hsmLocalRoleDefinitions", rid, "Microsoft.KeyVault", role_definitions))
        coverage["localRoleDefinitions"] = {key: definitions_read[key] for key in ("status", "error") if key in definitions_read}
        hsm["localRoleDefinitions"] = definitions_read["items"]


AUTHORIZATION = {
    "role_assignment": "roleAssignments", "role_definition": "roleDefinitions",
    "deny_assignment": "denyAssignments",
}
# Documented Graph page maxima (fewer pages, identical items): users 999, but
# 500 while signInActivity is selected; groups and applications 999. Lists
# whose documented maximum is the default (servicePrincipals: 100) or that do
# not document $top keep the service default page size.
DIRECTORY = {
    "conditional_access_policy": "identity/conditionalAccess/policies",
    "named_location": "identity/conditionalAccess/namedLocations",
    "user_registration_detail": "reports/authenticationMethods/userRegistrationDetails?$select=id,isMfaCapable,isMfaRegistered,userPrincipalName",
    "directory_role": "directoryRoles?$select=id,displayName,roleTemplateId",
    "directory_setting": "groupSettings",
    "directory_user": "users?$select=id,displayName,userPrincipalName,accountEnabled,userType,creationType,externalUserState,identities,onPremisesImmutableId,signInActivity&$top=500",
    "directory_group": "groups?$select=id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,membershipRule,membershipRuleProcessingState,visibility,onPremisesSyncEnabled&$top=999",
    "directory_service_principal": "servicePrincipals?$select=id,appId,appOwnerOrganizationId,displayName,servicePrincipalType,alternativeNames,accountEnabled,appRoles,passwordCredentials,keyCredentials,preferredSingleSignOnMode,createdDateTime",
    "directory_application": "applications?$select=id,appId,displayName,requiredResourceAccess,signInAudience,passwordCredentials,keyCredentials,servicePrincipalLockConfiguration&$top=999",
    "directory_role_assignment": "roleManagement/directory/roleAssignments",
    "directory_role_definition": "roleManagement/directory/roleDefinitions",
    "directory_audit": "auditLogs/directoryAudits",
    "directory_domain": "domains?$select=id,isVerified,authenticationType,isDefault,isInitial,passwordValidityPeriodInDays,passwordNotificationWindowInDays",
    "directory_administrative_unit": "directory/administrativeUnits?$select=id,displayName,isMemberManagementRestricted,membershipRule,membershipRuleProcessingState,visibility",
    "directory_role_eligibility_schedule": "roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,roleDefinitionId,directoryScopeId,memberType,status",
    "directory_role_eligibility_instance": "roleManagement/directory/roleEligibilityScheduleInstances?$select=id,principalId,roleDefinitionId,directoryScopeId,startDateTime,endDateTime,memberType",
    "directory_role_assignment_instance": "roleManagement/directory/roleAssignmentScheduleInstances?$select=id,principalId,roleDefinitionId,directoryScopeId,startDateTime,endDateTime,memberType",
    "directory_oauth2_permission_grant": "oauth2PermissionGrants?$select=id,clientId,consentType,principalId,resourceId,scope",
    azure_entitlement_native.PARENT: "identityGovernance/entitlementManagement/accessPackages?$select=id,catalogId,displayName",
    azure_entitlement_native.CATALOG: "identityGovernance/entitlementManagement/catalogs?$select=id,displayName",
    azure_entitlement_native.ROLE_ASSIGNMENT: "roleManagement/entitlementManagement/roleAssignments?$select=id,principalId,roleDefinitionId,appScopeId,directoryScopeId",
}
DIRECTORY.update(azure_agent_identity_native.ENDPOINTS)
DIRECTORY_SINGLETONS = {
    "authentication_methods_policy": "policies/authenticationMethodsPolicy",
    "temporary_access_pass_policy": "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass",
    "directory_authorization_policy": "policies/authorizationPolicy",
    "directory_security_defaults": "policies/identitySecurityDefaultsEnforcementPolicy",
    "directory_device_registration_policy": "policies/deviceRegistrationPolicy",
}
TYPES = tuple(ENDPOINTS) + tuple(AUTHORIZATION) + tuple(DIRECTORY) + tuple(DIRECTORY_SINGLETONS) + (
    azure_entitlement_native.RESOURCE, azure_entitlement_native.CATALOG_RESOURCE,
    *azure_network_catalog.CHILDREN,
    *azure_aks_legacy_projection_review_20261020.NATIVE_TYPES,
    *azure_application_compute_2_native.NATIVE_TYPES,
    *azure_acr_public_ip_review_20261020.NATIVE_TYPES,
    *azure_automation_aci_metadata_native_20261020.NATIVE_TYPES,
    "certificate_issuance", *azure_nsg_ingress_native.NATIVE_TYPES,
    *azure_wave_compute_native.NATIVE_TYPES,
    *azure_wave_network_controls.NATIVE_TYPES,
    "subscription", "tenant", "management_group", "cost_export", "managed_application_definition", "attestation_provider", "entra_domain_service", "defender_automation", "resource_graph", "activity_log", "activity_log_coverage",
    "subnet", "vnet_peering", "effective_route", "security_admin_rule", "service_tag", "diagnostic_setting", "storage_service", "sql_database",
    "sql_firewall_rule", "sql_audit", "sql_security", "secret_metadata", "dns_record",
    "private_dns_link", "directory_membership", "azure_unused_iam_evidence", "azure_unused_role_evidence", "azure_unused_arm_role_evidence", "azure_unused_iam_user_success_evidence",
    "directory_group_pim_policy", "directory_group_pim_owner_policy",
    "directory_group_eligibility_schedule", "directory_group_eligibility_instance", "directory_role_pim_policy",
    "app_service_config", "app_service_identity_detail", "sql_tde",
    "directory_app_role_assignment", "directory_owner", "directory_administrative_unit_member",
    "managed_identity_federated_credential", "key_metadata", "key_rotation_policy", "key_vault_certificate_current",
    'key_vault_key', 'key_vault_certificate', 'key_vault_certificate_policy', 'flow_log', 'virtual_network_gateway', 'subscription_diagnostic_setting', 'subscription_tenant_policy', 'backup_protected_item', 'backup_policy', 'sql_database_ltr_policy', 'sql_vulnerability_assessment', 'sql_encryption_protector', 'storage_container', 'storage_encryption_scope',
    "app_service_slot", "automation_variable", "batch_pool", *azure_devtestlab_native.CHILDREN, azure_containerapp_runtime.KIND, *azure_containerapp_jobs.NATIVE_TYPES, "apim_native", "apim_api_evidence", "azure_sw24_evidence", "application_scope", "service_principal_scope",
    "directory_federated_credential", "directory_cba_configuration",
    "ml_compute", "management_group_descendant", "mysql_single_configuration", "bot_cmk_key", "defender_pricing", "diagnostic_category",
    "azure_diagnostic_eligible_resource", "databricks_account_workspace",
    "resource_diagnostic_setting",
    "azure_resource", "resource", "backup_job", "sql_ltr_backup", "sql_restore_point",
    "managed_instance_database", "managed_instance_tde", "sql_database_inventory", "sql_tde_inventory",
    azure_identity_enforcement_review_20261020.KIND, "guest_configuration_report", "azure_sw18_evidence", "mysql_postgresql_sql_server", *azure_conditional_access_native.NATIVE_TYPES,
    "devops_project", *azure_devops_pipeline_native.NATIVE_TYPES, *azure_access_reviews_native.NATIVE_TYPES, *azure_arm_metadata_native.NATIVE_TYPES, *azure_monitor_inventory_native.NATIVE_TYPES, *azure_aks_workloads_native.NATIVE_TYPES, "azure_detection_telemetry", "entra_diagnostic_setting", *azure_storage_backup_native.NATIVE_TYPES,
    *azure_defender_network_native.NATIVE_TYPES, *azure_adaptive_network_native.NATIVE_TYPES, *azure_entra_user_native.NATIVE_TYPES, "directory_user_group_membership", "sql_managed_instance_administrator", "intune_diagnostic_setting",
    "storage_local_user", "sql_backup_short_term_policy", "eventgrid_subscription",
    *azure_vault_key_versions_native.NATIVE_TYPES, *azure_iot_policy_native.NATIVE_TYPES, *azure_function_limits_native.NATIVE_TYPES, *azure_functions_runtime_native.NATIVE_TYPES, *azure_secret_versions_native.NATIVE_TYPES, *azure_storage_recovery_metadata_native.NATIVE_TYPES, "sentinel_workspace", *azure_incident_inventory_native.NATIVE_TYPES, *azure_security_correlation_native.NATIVE_TYPES, *azure_apim_diagnostic_evidence_native.NATIVE_TYPES, *azure_storage_blob_keys_native.NATIVE_TYPES, *azure_audit_storage_native.NATIVE_TYPES, "assessment_metadata",
    azure_app_settings_secret_indicators.KIND, azure_acr_image_secret_indicators.KIND, azure_acr_image_vulnerabilities_20261021.KIND, azure_selected_aks_image_20261021.KIND, azure_selected_aks_image_20261021.VULN_KIND, azure_selected_configuration_secret_indicators.KIND,
    *azure_ai_services_native.NATIVE_TYPES,
    *azure_public_edge_native.NATIVE_TYPES, *azure_storage_lifecycle_native.NATIVE_TYPES, *azure_key_rotation_evidence_native.NATIVE_TYPES, "frontdoor_and_cdn_endpoint", "afd_profile", "afd_domain", "afd_route", "afd_security_policy",
    azure_notification_hubs_native.KIND, azure_lighthouse_native.KIND,
)

# A LIST containing properties is not a full GET. These evaluators apply
# documented omitted defaults only to a verified resource detail response.
FULL_GET_KINDS = frozenset({"load_balancer", "public_ip", "recovery_vault", "vm", "vm_scale_set", "nic", "vnet", "nsg", "route_table", "storage_account", "security_pricing", "web_application_firewall_policy",
    "frontdoor", "cdn_profile", "frontdoor_waf_policy",
                            "hdinsight_cluster", "firewall_policy", "log_analytics_cluster",
                            "image_template", "compute_gallery",
                            "postgresql_single_server", "mysql_single_server", "mariadb_server", "aks_cluster",
                            "action_group", "bot_service", "databox_job", "purview_account", "mongo_cluster",
                            "integration_service_environment", "openshift_cluster", "openshift_hcp_cluster", "signalr_service", "web_pubsub"})


def _canonicalize_embedded(collections):
    """Staged offline conversion; activate only with the atomic index resolver gate.

    Reviewed fields/ARM identity only. Concrete payloads remain the collector's
    output until the index owner verifies reference materialization end to end.
    """
    resources = {item["id"].casefold(): item for collection in collections for item in collection["items"] if isinstance(item.get("id"), str) and collection["type"] in set(ENDPOINTS) | {"sql_database", "storage_service"}}
    kinds = {item["id"].casefold(): collection["type"] for collection in collections for item in collection["items"] if isinstance(item.get("id"), str) and collection["type"] in set(ENDPOINTS) | {"sql_database", "storage_service"}}
    # Keys have two reviewed inventory names; their one canonical representation
    # belongs to the exact ARM parent, with independent child-list coverage.
    for collection in collections:
        if collection["type"] != "key_metadata": continue
        parent = resources.get(collection["scope"].casefold())
        if parent is None or kinds.get(collection["scope"].casefold()) != "vault": continue
        parent.setdefault("_coverage", {})["keyVaultKeys"] = {key: collection[key] for key in ("status", "error") if key in collection}
        if collection["items"] or collection["status"] in ("collected", "empty"):
            parent["keyVaultKeys"] = collection["items"]
            for key in collection["items"]:
                resources[key["id"].casefold()] = key
                kinds[key["id"].casefold()] = "key_metadata"
    fields = {"diagnostic_setting": "diagnosticSettings", "flow_log": "flowLogs", "backup_protected_item": "backupProtectedItems", "backup_policy": "backupPolicies", "storage_container": "blobContainers", "storage_encryption_scope": "encryptionScopes", "sql_database_ltr_policy": "backupLongTermRetentionPolicies", "sql_vulnerability_assessment": "vulnerabilityAssessment", "sql_encryption_protector": "encryptionProtector", "key_metadata": "keyVaultKeys", "key_vault_key": "keyVaultKeys", "key_rotation_policy": "properties.rotationPolicy"}
    from peaso.checks.facts import EMBEDDED_FIELDS
    for collection in collections:
        field = fields.get(collection["type"])
        if field is None: continue
        allowed, shape = EMBEDDED_FIELDS[field]
        converted = []
        for item in collection["items"]:
            child_id = item.get("id")
            if not isinstance(child_id, str):
                raise ValueError("reference conversion requires authoritative child identity")
            parent_id = item.get("parent_id")
            if collection["type"] == "diagnostic_setting": parent_id = collection["scope"]
            if collection["type"] in ("key_metadata", "key_vault_key"): parent_id = collection["scope"]
            parent = resources.get(str(parent_id).casefold())
            if parent is None or allowed is not None and kinds.get(str(parent_id).casefold()) not in allowed:
                # Preserve concrete fact until a canonical authorized parent exists.
                converted.append(item)
                continue
            if shape == "list":
                values = parent.get(field)
                if not isinstance(values, list):
                    converted.append(item); continue
                positions = [position for position, value in enumerate(values) if isinstance(value, dict) and str(value.get("id", "")).casefold() == child_id.casefold()]
                if len(positions) != 1:
                    raise ValueError("canonical child identity missing or ambiguous")
                position = positions[0]
                # Parent canonical objects conserve all reviewed enrichment fields.
                values[position] = item
            else:
                position = None
                if field == "properties.rotationPolicy":
                    parent.setdefault("properties", {})["rotationPolicy"] = item["properties"]
                    parent["properties"]["rotationPolicy"].setdefault("_provenance", {})["native_id"] = child_id
                else:
                    parent[field] = item
            converted.append({"id": child_id, "parent_id": parent_id, "_embedded_ref": {"parent_id": parent_id, "field": field, "index": position}})
        collection["observed_count"] = len(collection["items"])
        collection["items"] = converted
        collection.setdefault("metadata", {})["schema"] = "embedded_refs_v1"
    return collections


class AzureReadError(RuntimeError):
    def __init__(self, code, status=None):
        super().__init__(code)
        self.code, self.status_code = code, status


class _CallerLimitError(Exception):
    """A byte-limit failure that belongs to the caller that set the limit."""

    def __init__(self, error, limit):
        super().__init__(str(error))
        self.error, self.limit = error, limit



def _validate_readonly_post(url, audience, body):
    """Only documented metadata-query POSTs may reach credential or HTTP use."""
    parsed = urlsplit(url)
    # A decoded/normalized operation must never differ from the reviewed path.
    if (not isinstance(body, dict) or parsed.scheme != "https" or
            parsed.username or parsed.password or parsed.fragment or
            parsed.port not in (None, 443) or "%" in parsed.path or
            "\\" in parsed.path or any(part in (".", "..") for part in parsed.path.split("/"))):
        raise AzureReadError("cloud_mutation_prohibited")
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise AzureReadError("cloud_mutation_prohibited") from None
    keys = [key.casefold() for key, _ in pairs]
    if len(keys) != len(set(keys)) or any(not key or not value for key, value in pairs):
        raise AzureReadError("cloud_mutation_prohibited")
    query = dict(pairs)
    uuid = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    version = query.get("api-version", "")
    version_valid = re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}(?:-preview)?", version) is not None
    arm = audience == ARM and parsed.netloc == "management.azure.com"
    arg = (arm and parsed.path == "/providers/Microsoft.ResourceGraph/resources" and
           set(query) == {"api-version"} and version_valid and
           set(body) <= {"subscriptions", "query", "options"} and
           isinstance(body.get("query"), str) and bool(body["query"].strip()) and
           isinstance(body.get("subscriptions"), list) and bool(body["subscriptions"]) and
           all(isinstance(value, str) and re.fullmatch(uuid, value) for value in body["subscriptions"]) and
           isinstance(body.get("options", {}), dict))
    logs = (audience == LOGS and parsed.netloc == "api.loganalytics.azure.com" and
            re.fullmatch(r"/v1/workspaces/" + uuid + r"/query", parsed.path) is not None and
            not query and set(body) <= {"query", "timespan"} and
            isinstance(body.get("query"), str) and bool(body["query"].strip()) and
            ("timespan" not in body or isinstance(body["timespan"], str) and bool(body["timespan"].strip())))
    policy = (arm and re.fullmatch(r"/subscriptions/" + uuid +
              r"/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults", parsed.path) is not None and
              version_valid and set(query) <= {"api-version", "$filter", "$top", "$skiptoken", "$skipToken", "$select", "$orderby", "$apply", "$expand", "$from", "$to"} and
              body == {})
    from . import azure_graph_batch
    graph_batch = (audience == GRAPH and parsed.netloc == "graph.microsoft.com" and not query and
                   (parsed.path == "/v1.0/$batch" and azure_graph_batch.valid_body(body) or
                    parsed.path == "/beta/$batch" and azure_graph_batch.valid_body(body, beta_members_only=True)))
    if not (arg or logs or policy or graph_batch):
        raise AzureReadError("cloud_mutation_prohibited")


def _claims(token):
    try:
        segment = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        return value if isinstance(value, dict) else {}
    except (ValueError, IndexError, TypeError):
        return {}


def credential_for(auth):
    """Build one explicitly selected SDK credential; never silently fall back."""
    from azure import identity
    method = auth.get("method", "auto")
    tenant = auth.get("tenant_id")
    client = auth.get("client_id")
    if method == "auto":
        if auth.get("client_secret"):
            method = "client-secret"
        elif auth.get("certificate_path") or auth.get("certificate_data") or auth.get("client_certificate"):
            method = "client-cert"
    if method == "client-secret":
        return identity.ClientSecretCredential(tenant, client, auth["client_secret"])
    if method in ("client-cert", "certificate"):
        inline = auth.get("certificate_data") or auth.get("client_certificate")
        certificate = {"certificate_data": inline.encode() if isinstance(inline, str) else inline} if inline else {"certificate_path": auth["certificate_path"]}
        return identity.CertificateCredential(tenant, client, **certificate, password=auth.get("certificate_password"))
    if method in ("az-cli", "azure-cli"):
        return identity.AzureCliCredential(**({"tenant_id": tenant} if tenant else {}), process_timeout=20)
    if method == "managed-identity":
        return identity.ManagedIdentityCredential(**({"client_id": client} if client else {}))
    if method == "workload-identity":
        if auth.get("federated_token"):
            assertion = auth["federated_token"]
            return identity.ClientAssertionCredential(tenant, client, lambda: assertion)
        return identity.WorkloadIdentityCredential(tenant_id=tenant, client_id=client, token_file_path=auth["token_file"])
    if method == "device-code":
        if not tenant or not client:
            raise ValueError("device-code requires tenant_id and client_id")
        return identity.DeviceCodeCredential(tenant_id=tenant, client_id=client, timeout=120)
    if method not in ("auto", "default"):
        raise ValueError("unsupported Azure authentication method")
    kwargs = {"exclude_interactive_browser_credential": True}
    if tenant:
        kwargs.update(shared_cache_tenant_id=tenant, interactive_browser_tenant_id=tenant,
                      workload_identity_tenant_id=tenant)
    if client:
        kwargs.update(managed_identity_client_id=client, workload_identity_client_id=client)
    return identity.DefaultAzureCredential(**kwargs)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AzureReadError("redirect_rejected")


# Persistent HTTPS connections. A fresh opener per request used to pay a CA
# bundle load plus a TCP/TLS handshake for every native read. The urllib
# pipeline (redirect refusal, HTTPError classification, environment proxies,
# timeouts, request headers) is unchanged; only the HTTPS connection is reused
# after a response body was completely and cleanly read.
_STDLIB_BUILD_OPENER = _urllib_request.build_opener
_STALE_CONNECTION_ERRORS = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


def _stale_connection(exc):
    import ssl
    errors = _STALE_CONNECTION_ERRORS + (ssl.SSLEOFError, ssl.SSLZeroReturnError)
    return isinstance(exc, errors) or (isinstance(exc, URLError) and isinstance(exc.reason, errors))


class _PooledHTTPResponse(http.client.HTTPResponse):
    """Return the connection to the pool only after a complete clean body read."""
    _peaso_release = None

    def close(self):
        # http.client drops fp exactly when the declared or chunked body ended.
        drained = self.fp is None
        try:
            super().close()
        finally:
            release, self._peaso_release = self._peaso_release, None
            if release is not None:
                release(drained and not self.will_close)


class _KeepAlivePool:
    """Thread-safe idle HTTPS connections; each connection serves one request at a time."""
    def __init__(self, max_idle_per_key=64, idle_seconds=50.0):
        self.max_idle_per_key, self.idle_seconds = max_idle_per_key, idle_seconds
        self.lock = threading.Lock()
        self.idle = {}
        self.created = 0
        self.reused = 0

    def acquire(self, key):
        stale = []
        now = time.monotonic()
        try:
            with self.lock:
                entries = self.idle.get(key)
                while entries:
                    connection, stamp = entries.pop()
                    if now - stamp <= self.idle_seconds and connection.sock is not None:
                        self.reused += 1
                        return connection
                    stale.append(connection)
            return None
        finally:
            for connection in stale:
                connection.close()

    def release(self, key, connection, reusable):
        if reusable and connection.sock is not None:
            with self.lock:
                entries = self.idle.setdefault(key, [])
                if len(entries) < self.max_idle_per_key:
                    entries.append((connection, time.monotonic()))
                    return
        connection.close()

    def clear(self):
        with self.lock:
            entries = [connection for values in self.idle.values() for connection, _ in values]
            self.idle.clear()
        for connection in entries:
            connection.close()


_KEEPALIVE_POOL = _KeepAlivePool()


def _forget_inherited_connections():
    # A forked child must never share a parent's TLS session. Drop references
    # without closing: closing could disturb the parent's live socket state.
    _KEEPALIVE_POOL.lock = threading.Lock()
    _KEEPALIVE_POOL.idle = {}


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_forget_inherited_connections)
_HTTPS_CONTEXT = None
_HTTPS_CONTEXT_LOCK = threading.Lock()


def _shared_https_context():
    """The same verified default context urllib builds per HTTPSHandler, built once."""
    global _HTTPS_CONTEXT
    with _HTTPS_CONTEXT_LOCK:
        if _HTTPS_CONTEXT is None:
            factory = getattr(http.client, "_create_https_context", None)
            if factory is not None:
                context = factory(http.client.HTTPSConnection._http_vsn)
            else:
                import ssl
                context = ssl._create_default_https_context()
                if http.client.HTTPSConnection._http_vsn == 11:
                    context.set_alpn_protocols(["http/1.1"])
                if context.post_handshake_auth is not None:
                    context.post_handshake_auth = True
            _HTTPS_CONTEXT = context
        return _HTTPS_CONTEXT


class _KeepAliveHTTPSHandler(HTTPSHandler):
    """urllib HTTPS handler mirroring AbstractHTTPHandler.do_open with pooled connections."""
    def __init__(self, pool=None):
        super().__init__(context=_shared_https_context())
        self._pool = _KEEPALIVE_POOL if pool is None else pool

    def https_open(self, req):
        host = req.host
        if not host:
            raise URLError("no host given")
        headers = dict(req.unredirected_hdrs)
        headers.update({k: v for k, v in req.headers.items() if k not in headers})
        headers = {name.title(): value for name, value in headers.items()}
        tunnel_headers = {}
        if req._tunnel_host and "Proxy-Authorization" in headers:
            # Proxy-Authorization should not be sent to the origin server.
            tunnel_headers["Proxy-Authorization"] = headers.pop("Proxy-Authorization")
        key = (host, req._tunnel_host, tunnel_headers.get("Proxy-Authorization"))
        for attempt in (0, 1):
            connection = self._pool.acquire(key) if attempt == 0 else None
            reused = connection is not None
            if connection is None:
                connection = http.client.HTTPSConnection(host, timeout=req.timeout, context=self._context)
                connection.set_debuglevel(self._debuglevel)
                connection.response_class = _PooledHTTPResponse
                if req._tunnel_host:
                    connection.set_tunnel(req._tunnel_host, headers=tunnel_headers)
                with self._pool.lock:
                    self._pool.created += 1
            else:
                connection.timeout = req.timeout
                connection.sock.settimeout(req.timeout)
            try:
                try:
                    connection.request(req.get_method(), req.selector, req.data, headers,
                                       encode_chunked=req.has_header("Transfer-encoding"))
                except OSError as err:
                    raise URLError(err)
                response = connection.getresponse()
            except BaseException as exc:
                connection.close()
                # Only an idle connection the server already closed is replayed,
                # once, on a fresh connection; a new connection's error is final.
                if reused and isinstance(exc, Exception) and _stale_connection(exc):
                    continue
                raise
            response._peaso_release = functools.partial(self._pool.release, key, connection)
            response.url = req.get_full_url()
            response.msg = response.reason
            return response


def _keepalive_build_opener(*handlers):
    """Stdlib ``build_opener`` whose HTTPS handler reuses pooled connections.

    Every other handler (redirect policy, HTTP error processing, proxies) is
    the stdlib default, so status, error and redirect semantics are unchanged.
    """
    return _STDLIB_BUILD_OPENER(*handlers, _KeepAliveHTTPSHandler())


def _native_open(request, timeout, opener_factory=None):
    """Open one native read through the no-redirect urllib pipeline.

    An injected ``build_opener`` (tests, sandboxes) keeps its exact one-policy
    call; the stdlib factory is upgraded to the pooled HTTPS handler.
    """
    factory = build_opener if opener_factory is None else opener_factory
    if factory is _STDLIB_BUILD_OPENER:
        factory = _keepalive_build_opener
    return factory(_NoRedirect()).open(request, timeout=timeout)


_FANOUT_SLOTS_LOCK = threading.Lock()


def _fanout_slots(reader):
    """Shared per-reader bound for nested fan-out, created on first use."""
    slots = getattr(reader, "fanout_slots", None)
    if slots is not None or not isinstance(reader, _Reader):
        return slots
    with _FANOUT_SLOTS_LOCK:
        slots = reader.__dict__.get("fanout_slots")
        if slots is None:
            slots = reader.fanout_slots = threading.BoundedSemaphore(reader.workers)
    return slots


def ordered_parallel(reader, function, items, *, limit=None):
    """Run independent reads concurrently and return results in input order.

    Each result is ``(True, value)`` or ``(False, exception)`` so callers keep
    their serial error handling. Concurrency is bounded by ``reader.workers``
    (and ``limit``) plus the reader's shared fan-out slots when present.
    """
    items = list(items)
    workers = getattr(reader, "workers", 1)
    workers = workers if type(workers) is int and workers > 0 else 1
    if limit is not None:
        workers = min(workers, limit)
    slots = _fanout_slots(reader)
    def run(item):
        try:
            if slots is None:
                return True, function(item)
            with slots:
                return True, function(item)
        except Exception as exc:
            return False, exc
    if workers <= 1 or len(items) <= 1:
        return [run(item) for item in items]
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        futures = [pool.submit(copy_context().run, run, item) for item in items]
        return [future.result() for future in futures]


def _strict_native_json(raw):
    """Decode complete native JSON without duplicate fields or nonfinite numbers."""
    import math
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('ambiguous native JSON')
            value[key] = item
        return value
    def reject_constant(value):
        raise ValueError('nonfinite native JSON')
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError('nonfinite native JSON')
        return number
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=reject_constant, parse_float=finite_float)


class AzureTransport:
    """Audience-separated refreshed tokens and origin-checked HTTPS requests."""
    # Accepts the reviewed read-only Graph $batch POST (azure_graph_batch).
    graph_batch = True

    def __init__(self, auth, credential=None):
        self.auth = auth
        import uuid
        self.ai_context_id = uuid.uuid4().hex
        self.credential = credential
        self.owned = credential is None
        self.direct = auth.get("method", "auto") in ("auto", "token", "arm-token") and bool(auth.get("arm_token") or auth.get("token") or auth.get("graph_token") or auth.get("vault_token") or auth.get("storage_token") or auth.get("logs_token"))
        if self.credential is None and not self.direct:
            self.credential = credential_for(auth)
        self.tokens = {}
        self.lock = threading.Lock()
        self.tenant = auth.get("tenant_id")
        self.vault_hosts = set()
        self.storage_hosts = set()
        self.verified_tenant = None
        from .scan_cache import RawResponseCache
        # Per-scan, per-credential single-flight cache of complete read bodies.
        self.response_cache = RawResponseCache()

    def allow_vault(self, uri):
        parsed = urlsplit(uri)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port or parsed.path not in ("", "/") or parsed.query or parsed.fragment or not re.fullmatch(r"[a-zA-Z0-9-]{3,24}\.vault\.azure\.net", parsed.netloc):
            raise AzureReadError("untrusted_vault_endpoint")
        with self.lock:
            self.vault_hosts.add(parsed.netloc.lower())

    def allow_hsm(self, uri, name):
        """Bind a Managed HSM data-plane origin to its selected ARM parent."""
        parsed = urlsplit(uri)
        host = parsed.netloc.lower()
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9-]{3,24}", name)
                or re.fullmatch(r"(?:[a-z0-9-]+\.)?" + re.escape(name.lower())
                                + r"\.managedhsm\.azure\.net", host) is None):
            raise AzureReadError("untrusted_hsm_endpoint")
        with self.lock:
            self.vault_hosts.add(host)

    def allow_storage(self, uri, account, service):
        parsed = urlsplit(uri)
        expected = account.lower() + "." + service + ".core.windows.net"
        if parsed.scheme != "https" or parsed.netloc.lower() != expected or parsed.username or parsed.password or parsed.port or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise AzureReadError("untrusted_storage_endpoint")
        with self.lock:
            self.storage_hosts.add(parsed.netloc.lower())

    def request_xml(self, url):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in self.storage_hosts or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment or parsed.path != "/" or parse_qs(parsed.query) != {"restype": ["service"], "comp": ["properties"]}:
            raise AzureReadError("untrusted_storage_endpoint")
        token = self.token(STORAGE)
        request = Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/xml", "x-ms-version": "2023-11-03", "x-ms-date": format_datetime(datetime.now(timezone.utc), usegmt=True)}, method="GET")
        with _native_open(request, 20, build_opener) as response:
            body = response.read(512001)
        if len(body) > 512000 or b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
            raise ValueError("malformed service-properties XML")
        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            raise ValueError("malformed service-properties XML") from exc
        values = {}
        for operation in ("Read", "Write", "Delete"):
            value = root.findtext("Logging/" + operation)
            if value not in ("true", "false"):
                raise ValueError("malformed storage analytics logging property")
            values[operation.lower()] = value == "true"
        return values

    def request_blob_inventory(self, url):
        """Only List Blobs XML metadata at a previously bound ARM blob origin."""
        from . import azure_blob_inventory_xml as projection
        try:
            binding = projection.validate_request(url, self.storage_hosts)
        except ValueError:
            raise AzureReadError('untrusted_storage_inventory_endpoint') from None
        token = self.token(STORAGE)
        request = Request(url, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/xml', 'x-ms-version': projection.API_VERSION,
            'x-ms-date': format_datetime(datetime.now(timezone.utc), usegmt=True)}, method='GET')
        with _native_open(request, 20, build_opener) as response:
            body = response.read(projection.MAX_BYTES + 1)
        return projection.project(body, binding)

    def token(self, audience):
        direct = (self.auth.get("arm_token") or self.auth.get("token")) if self.direct and audience == ARM else self.auth.get("graph_token") if audience == GRAPH else self.auth.get("vault_token") if audience == VAULT else self.auth.get("storage_token") if audience == STORAGE else self.auth.get("logs_token") if audience == LOGS else None
        with self.lock:
            if direct:
                token = direct
            else:
                if self.credential is None:
                    raise AzureReadError("audience_token_unavailable", 401)
                cached = self.tokens.get(audience)
                if cached is None or cached.expires_on < time.time() + 60:
                    cached = self.credential.get_token(audience + "/.default")
                    self.tokens[audience] = cached
                token = cached.token
            claims = _claims(token)
            tenant = claims.get("tid")
            if self.tenant and tenant and self.tenant.lower() != tenant.lower():
                raise AzureReadError("tenant_mismatch", 401)
            if tenant:
                self.verified_tenant = tenant
            if tenant and not self.tenant:
                self.tenant = tenant
            expected = audience
            actual = claims.get("aud")
            aliases = {ARM: {ARM, ARM + "/", "https://management.core.windows.net/"},
                       GRAPH: {GRAPH, GRAPH + "/", "00000003-0000-0000-c000-000000000000"},
                       VAULT: {VAULT, VAULT + "/", "cfa8b339-82a2-471a-a3c9-0fc0be7a4093"}}
            if actual and actual not in aliases.get(expected, {expected, expected + "/"}):
                raise AzureReadError("token_audience_mismatch", 401)
            from peaso.ai.access import bearer
            endpoints = (["https://" + host for host in self.vault_hosts] if audience == VAULT else
                         ["https://" + host for host in self.storage_hosts] if audience == STORAGE else [audience])
            bearer("azure", audience, token, context_id=self.ai_context_id, tenant_id=self.tenant,
                   expires_at=None if direct else cached.expires_on, endpoints=endpoints)
            return token

    def request(self, url, *, body=None, audience=ARM, capture_subject=False, max_response_bytes=None):
        raw, token = self._raw_response(url, body, audience, capture_subject, max_response_bytes)
        value = _strict_native_json(raw)
        from peaso.secret_evidence import native_environment_resources
        native_environment_resources(value, provider='azure', method='GET' if body is None else 'POST', url=url, body=body)
        from .azure_network_data import is_network_audience, project_response
        if is_network_audience(audience):
            value = project_response(value, audience)
        if capture_subject:
            from .azure_disclosure_native import accepted_subject
            if not hasattr(self, "disclosure_accepted_subjects"):
                self.disclosure_accepted_subjects = {}
            self.disclosure_accepted_subjects[audience] = accepted_subject(token, audience)
        return value

    def raw_get(self, url, *, audience=ARM):
        """Exact 200 response bytes of one validated GET, shared with request().

        Callers that apply their own stricter parsing reuse the per-scan
        response cache instead of opening a second connection for the same read.
        """
        return self._raw_response(url, None, audience, False, None)[0]

    def _raw_response(self, url, body, audience, capture_subject, max_response_bytes):
        parsed = urlsplit(url)
        origin_allowed = parsed.netloc == urlsplit(audience).netloc
        if audience == VAULT:
            origin_allowed = (parsed.hostname or "").lower() in self.vault_hosts and parsed.port in (None, 443)
        if audience == LOGS:
            origin_allowed = (parsed.hostname or "").lower() == "api.loganalytics.azure.com" and parsed.port in (None, 443)
        from .azure_network_data import is_network_audience, allowed_route
        if is_network_audience(audience):
            origin_allowed = body is None and allowed_route(url, audience)
        if parsed.scheme != "https" or not origin_allowed or parsed.username or parsed.password or parsed.fragment:
            raise AzureReadError("untrusted_continuation")
        if body is not None:
            _validate_readonly_post(url, audience, body)
        token = self.token(audience)
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method="POST" if body is not None else "GET")
        def valid_limit():
            if type(max_response_bytes) is not int or not 0 < max_response_bytes <= 20_000_000:
                raise ValueError("invalid response byte limit")
        owner = []
        def load():
            owner.append(True)
            with _native_open(request, 20, build_opener) as response:
                # These GET/read-only query endpoints document200 representations;
                # partial, asynchronous and empty responses are not native evidence.
                if type(getattr(response, 'status', None)) is not int or response.status != 200:
                    raise AzureReadError('incomplete_native_response')
                if max_response_bytes is None:
                    return response.read()
                try:
                    valid_limit()
                except ValueError as exc:
                    raise _CallerLimitError(exc, None) from None
                raw = response.read(max_response_bytes + 1)
                if len(raw) > max_response_bytes:
                    raise _CallerLimitError(AzureReadError("response_too_large"), max_response_bytes)
                return raw
        cache = getattr(self, "response_cache", None)
        if cache is None or capture_subject or parsed.path.endswith("/$batch"):
            # Graph $batch bodies are one-shot; retaining them has no reuse value.
            try:
                raw = load()
            except _CallerLimitError as exc:
                raise exc.error from None
        else:
            # Only validated reads reach here (GET or allow-listed query POST).
            # Same audience, URL and body within this scan reads the wire once;
            # failures are never retained. Parsing and projection rerun per call.
            try:
                raw = cache.fetch((audience, url, payload), load)
            except _CallerLimitError as exc:
                # Another in-flight caller's own byte limit failed. It decides
                # this read only when that limit was at least this caller's.
                if owner or (max_response_bytes is not None and exc.limit is not None
                             and type(max_response_bytes) is int and exc.limit >= max_response_bytes):
                    raise exc.error from None
                owner.clear()
                try:
                    raw = load()
                except _CallerLimitError as own:
                    raise own.error from None
            if max_response_bytes is not None:
                valid_limit()
            if max_response_bytes is not None and len(raw) > max_response_bytes:
                raise AzureReadError("response_too_large")
        return raw, token

    def request_databricks(self, url):
        return azure_databricks_native.request_metadata(url, self.auth)

    def close(self):
        cache = getattr(self, "response_cache", None)
        if cache is not None:
            cache.clear()
        if self.owned and self.credential is not None:
            self.credential.close()


def _safe_error(exc):
    """Never expose SDK exception bodies, URLs, credentials or response text."""
    code = _status_code(exc)
    if not isinstance(code, (str, int)):
        code = None
    if code in (401, 403, "401", "403") or type(exc).__name__ == "ClientAuthenticationError":
        status = "denied"
    elif code in (408, 504, "408", "504") or isinstance(exc, TimeoutError):
        status = "timeout"
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        status = "malformed"
    else:
        status = "unknown"
    safe_code = str(code) if code and re.fullmatch(r"[A-Za-z0-9_.-]{1,79}", str(code)) else "read_failed"
    return status, {"kind": type(exc).__name__, "code": safe_code}


def _retry_after(exc):
    """Return a server's full Retry-After minimum (seconds or HTTP-date)."""
    for candidate in (exc, getattr(exc, "__cause__", None)):
        headers = getattr(candidate, "headers", None)
        if headers is None:
            response = getattr(candidate, "response", None)
            headers = getattr(response, "headers", None)
        try:
            value = headers.get("Retry-After") if headers is not None else None
        except AttributeError:
            value = None
        if not isinstance(value, str):
            continue
        value = value.strip()
        try:
            if re.fullmatch(r"[0-9]+", value):
                minimum = float(value)
            else:
                stamp = parsedate_to_datetime(value)
                if stamp.tzinfo is None:
                    continue
                minimum = max(0.0, stamp.timestamp() - time.time())
            # Infinite numeric minima also abort at the caller's wait budget.
            return minimum
        except (TypeError, ValueError, OverflowError):
            pass
    return 2.0


def _status_code(exc):
    for candidate in (exc, getattr(exc, "__cause__", None)):
        code = getattr(candidate, "status_code", None) or getattr(candidate, "status", None) or getattr(candidate, "code", None)
        if code is not None:
            return code
    return None


def _metadata_only(value, secret=False):
    if isinstance(value, list):
        return [_metadata_only(item, secret) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: _metadata_only(item, secret) for key, item in value.items() if not (secret and key.lower() == "value") and key.lower() not in (
        "password", "adminpassword", "clientsecret", "accesstoken", "token",
        "connectionstring", "primarykey", "secondarykey", "privatekey", "customdata",
        "userdata", "protectedsettings", "protectedsettingsfromkeyvault", "appsettings",
        "machinekey", "decryptionkey", "validationkey", "sourceuri", "accesssas",
        "redisconfiguration", "tenantsettings", "apiproperties", "globalparameters",
        "migrationtoken", "secrettext", "webhookproperties", "storageaccountaccesskey", "storagecontainersaskey", "workspacekey", "securevalue", "pfx", "certificatepassword", "certificate", "privatekeybytes", "sharedaccesskey", "sharedaccesspolicykey", "accountkey", "storageaccountkey", "accesskey", "accesskeys", "sasuri", "sasurl", "sastoken", "secretvalue", "pullsecret", "apikey", "apikeys", "administratorloginpassword", "settings")}
    if isinstance(value.get("environmentVariables"), list):
        result["environmentVariables"] = [{key: ("[REDACTED]" if data is not None else None) if key in ("value", "secureValue") else _metadata_only(data, secret) for key, data in variable.items() if key in ("name", "value", "secureValue")} if isinstance(variable, dict) else _metadata_only(variable, secret) for variable in value["environmentVariables"]]
    for field in ("passwordCredentials", "keyCredentials"):
        if isinstance(value.get(field), list):
            result[field] = [{key: data for key, data in credential.items() if key in ("keyId", "startDateTime", "endDateTime")} if isinstance(credential, dict) else _metadata_only(credential, secret) for credential in value[field]]
    credential_names = {"token", "apitoken", "apikey", "accesskey", "accesskeyid",
                        "secretaccesskey", "accesskeysecret", "clientsecret", "secret",
                        "password", "passwd", "privatekey", "accesstoken", "refreshtoken",
                        "bearertoken", "authorization", "connectionstring", "sastoken",
                        "credential", "credentials", "workspacekey"}
    parameter_name = value.get("name") or value.get("parameterName")
    if isinstance(parameter_name, str) and re.sub(r"[^a-z0-9]", "", parameter_name.lower()) in credential_names | {"primarykey", "secondarykey", "sharedaccesskey", "sharedaccesspolicykey", "storageaccountkey", "storageaccountaccesskey", "storagecontainersaskey"}:
        if "value" in value:
            result["value"] = "[REDACTED]" if value["value"] is not None else None
    for field, tags in value.items():
        if field.lower() not in ("tags", "labels") or not isinstance(tags, dict):
            continue
        safe_tags, redacted = {}, []
        for key, item in tags.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            if normalized in credential_names:
                safe_tags[key] = "[REDACTED]"
                redacted.append({"key": key, "status": "redacted"})
            else:
                safe_tags[key] = _metadata_only(item, secret)
        result[field] = safe_tags
        if redacted:
            result.setdefault("_redacted_metadata", {})[field] = redacted
    return result


_DATABASE_CRYPTO_IDENTITY_KINDS = frozenset((
    "mysql_single_server", "postgresql_single_server", "mysql_flexible_server", "postgresql_flexible_server",
    "cosmos_account", "vault", "managed_hsm", "recovery_vault", "sql_server", "redis_cache"))


def _bind_hsm_diagnostic_context(collection, proof):
    """Bind actual HSM child-list receipts to this capture's opaque contexts."""
    if collection.get("type") != "managed_hsm":
        return
    for parent in collection["items"]:
        rows = parent.get("diagnosticSettings", [])
        if not isinstance(rows, list):
            continue
        for child in rows:
            if not isinstance(child, dict):
                continue
            native = child.get("_provenance")
            if (isinstance(native, dict) and native.get("source_operation") == "DiagnosticSettings_List"
                    and native.get("read_only") is True and native.get("scope") == parent.get("id")):
                native.update(proof)


def _database_crypto_parent_identity(item, scope, kind):
    """Bind only the reviewed native database/crypto/backup ARM parent kinds."""
    if kind not in _DATABASE_CRYPTO_IDENTITY_KINDS:
        return
    endpoint = ENDPOINTS[kind][0]
    rid = item.get("id") if isinstance(item, dict) else None
    if (not isinstance(rid, str)
            or not re.fullmatch(re.escape(scope) + r"/resourceGroups/[^/?#%]+/providers/" + re.escape(endpoint) + r"/[^/?#%]+", rid, re.I)
            or any(part in (".", "..") or any(ord(c) < 33 for c in part) for part in rid.split("/"))
            or str(item.get("type", "")).casefold() != endpoint.casefold()
            or "name" in item and (not isinstance(item["name"], str)
                                   or item["name"].casefold() != rid.rsplit("/", 1)[-1].casefold())):
        raise ValueError("native database/crypto/backup parent identity differs from selected inventory")
    _database_crypto_private_endpoint_identity(item, kind)


def _database_crypto_private_endpoint_identity(item, kind):
    """A private-connection declaration must belong to its native DB/vault parent."""
    if kind not in ("sql_server", "redis_cache", "cosmos_account", "vault"):
        return
    props = item.get("properties")
    if not isinstance(props, dict) or "privateEndpointConnections" not in props:
        return
    rows, seen = props["privateEndpointConnections"], {}
    valid = isinstance(rows, list)
    for row in rows if isinstance(rows, list) else []:
        identity = row.get("id") if isinstance(row, dict) else None
        expected_type = ENDPOINTS[kind][0] + "/privateEndpointConnections"
        if (not isinstance(identity, str)
                or re.fullmatch(re.escape(item["id"] + "/privateEndpointConnections/") + r"[^/?#%\\\s]+", identity, re.I) is None
                or identity.rsplit("/", 1)[-1] in (".", "..")
                or "type" in row and str(row["type"]).casefold() != expected_type.casefold()
                or "name" in row and str(row["name"]).casefold() != identity.rsplit("/", 1)[-1].casefold()
                or not isinstance(row.get("properties"), dict)
                or identity.casefold() in seen and seen[identity.casefold()] != row):
            valid = False
            break
        seen[identity.casefold()] = row
    if not valid:
        # Keep independent scalar declarations usable; the unresolved child
        # field cannot supply either a compliance PASS or an absence FAIL.
        props.setdefault("_coverage", {})["privateEndpointConnections"] = {"status": "malformed"}


def _remaining_service_parent_identity(item, scope, kind, seen=None):
    """Bind only the three reviewed native service parents and their connections."""
    if kind not in ('app_configuration', 'data_factory', 'search_service'):
        return True
    endpoint = ENDPOINTS[kind][0]
    rid = item.get('id') if isinstance(item, dict) else None
    if (not isinstance(rid, str) or re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/?#%\\\s]+/providers/' + re.escape(endpoint) + r'/[^/?#%\\\s]+', rid, re.I) is None
            or any(p in ('.', '..') for p in rid.split('/'))
            or str(item.get('type', '')).casefold() != endpoint.casefold()
            or not isinstance(item.get('name'), str) or item['name'].casefold() != rid.rsplit('/', 1)[-1].casefold()):
        raise ValueError('native service parent path/type/name differs from selected inventory')
    if seen is not None:
        value = _metadata_only({k: v for k, v in item.items() if k in ('id', 'name', 'type', 'location', 'properties', 'sku', 'identity')})
        for k in ('id', 'name', 'type'):
            value[k] = value[k].casefold()
        if rid.casefold() in seen:
            if seen[rid.casefold()] != value:
                raise ValueError('conflicting native service parent identity')
            return False
        seen[rid.casefold()] = value
    props = item.get('properties')
    if not isinstance(props, dict) or 'privateEndpointConnections' not in props:
        return True
    rows, identities, valid = props['privateEndpointConnections'], {}, isinstance(props['privateEndpointConnections'], list)
    for row in rows if isinstance(rows, list) else []:
        identity = row.get('id') if isinstance(row, dict) else None
        if (not isinstance(identity, str) or re.fullmatch(re.escape(rid + '/privateEndpointConnections/') + r'[^/?#%\\\s]+', identity, re.I) is None
                or identity.rsplit('/', 1)[-1] in ('.', '..')
                or 'type' in row and str(row['type']).casefold() != (endpoint + '/privateEndpointConnections').casefold()
                or 'name' in row and str(row['name']).casefold() != identity.rsplit('/', 1)[-1].casefold()
                or not isinstance(row.get('properties'), dict)
                or identity.casefold() in identities and identities[identity.casefold()] != row):
            valid = False
            break
        identities[identity.casefold()] = row
    if not valid:
        props.setdefault('_coverage', {})['privateEndpointConnections'] = {'status': 'malformed'}
        props.pop('privateEndpointConnections', None)
    else:
        props['privateEndpointConnections'] = list(identities.values())
    return True


def _remaining_services_private_links(item, kind):
    """Keep only coherent immediate private-connection declarations for these services."""
    if kind not in ("servicebus_namespace", "signalr_service", "storage_sync_service"):
        return
    props = item.get("properties")
    if not isinstance(props, dict) or "privateEndpointConnections" not in props:
        return
    rows, seen = props["privateEndpointConnections"], {}
    valid = isinstance(rows, list)
    expected_type = ENDPOINTS[kind][0] + "/privateEndpointConnections"
    prefix = item["id"] + "/privateEndpointConnections/"
    for row in rows if isinstance(rows, list) else []:
        identity = row.get("id") if isinstance(row, dict) else None
        if (not isinstance(identity, str)
                or re.fullmatch(re.escape(prefix) + r"[^/?#%\\\s]+", identity, re.I) is None
                or identity.rsplit("/", 1)[-1] in (".", "..")
                or "type" in row and str(row["type"]).casefold() != expected_type.casefold()
                or "name" in row and str(row["name"]).casefold() != identity.rsplit("/", 1)[-1].casefold()
                or not isinstance(row.get("properties"), dict)
                or identity.casefold() in seen and seen[identity.casefold()] != row):
            valid = False
            break
        seen[identity.casefold()] = row
    if not valid:
        props.setdefault("_coverage", {})["privateEndpointConnections"] = {"status": "malformed"}
        props.pop("privateEndpointConnections", None)
    else:
        props["privateEndpointConnections"] = list(seen.values())


def _bound_vault_metadata_origin(item, rid):
    """Selected native vault endpoint, never a caller-selected data-plane origin."""
    uri = item.get("properties", {}).get("vaultUri")
    parsed = urlsplit(uri) if isinstance(uri, str) else None
    name = rid.rsplit("/", 1)[-1]
    if (parsed is None or parsed.scheme != "https" or parsed.username or parsed.password or parsed.port
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")
            or not re.fullmatch(r"[a-zA-Z0-9-]{3,24}", name)
            or parsed.netloc.casefold() != (name + ".vault.azure.net").casefold()):
        raise ValueError("authoritative vault endpoint differs from selected native vault")
    return "https://" + parsed.netloc


def _normalize_vault_expiration(collection, vaults):
    """Optional exp omission means no expiry only on a complete bound metadata LIST."""
    kind = collection.get("type")
    if kind not in ("key_metadata", "secret_metadata") or collection.get("status") not in ("collected", "empty"):
        return
    parent = vaults.get(str(collection.get("scope", "")).casefold())
    if parent is None:
        return
    rid = parent["id"]
    origin = _bound_vault_metadata_origin(parent, rid)
    segment = "keys" if kind == "key_metadata" else "secrets"
    for item in collection["items"]:
        proof = item.get("_provenance", {})
        attrs = item.get("properties", {}).get("attributes")
        identifier = item.get("id")
        if (not isinstance(identifier, str)
                or not re.fullmatch(re.escape(rid + "/" + segment + "/") + r"[A-Za-z0-9-]{1,127}", identifier, re.I)
                or item.get("parent_id", "").casefold() != rid.casefold()
                or item.get("data_plane_id", "").casefold() != (origin + "/" + segment + "/" + identifier.rsplit("/", 1)[-1]).casefold()
                or proof.get("endpoint") != segment + "/list" or proof.get("audience") != VAULT or proof.get("read_only") is not True
                or not isinstance(attrs, dict) or type(attrs.get("enabled")) is not bool):
            continue
        attrs.setdefault("exp", None)


def _policy_assignment_scope_allowed(kind, selected_scope, resource_id):
    """Allow only documented MG-policy rows from a subscription-bound List."""
    if resource_id.casefold() == selected_scope.casefold() or resource_id.casefold().startswith(selected_scope.casefold() + '/'):
        return True
    return kind == 'policy_assignment' and re.fullmatch(
        r'/providers/Microsoft\.Management/managementGroups/[^/?#]+'
        r'/providers/Microsoft\.Authorization/policyAssignments/[^/?#]+', resource_id, re.I) is not None


class _Reader:
    """Shared native read scheduler; budgets include retry attempts."""
    def __init__(self, options):
        self.budget = Budget({key: value for key, value in options.items() if value is not None})
        # Complete collection is the default. Limits exist only when supplied
        # explicitly by the caller or trusted hosted execution policy.
        self.budget.max_pages = options.get("max_pages")
        self.budget.max_items = options.get("max_resources")
        self.budget.max_calls = options.get("max_calls")
        self.explicit_limits = {key: options[key] for key in ("max_pages", "max_resources", "max_calls", "max_scopes") if options.get(key) is not None}
        self.cancel_check = options.get("_cancel_check")
        if self.cancel_check is not None and not callable(self.cancel_check):
            raise ValueError("_cancel_check must be a callable runtime hook")
        deadline = options.get("collection_deadline_seconds")
        if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline) or deadline <= 0):
            raise ValueError("collection_deadline_seconds must be positive")
        self.deadline = time.monotonic() + deadline if deadline is not None else None
        self.deadline_seconds = deadline
        # Collection is latency-bound (hundreds of ms per ARM/Graph read), so the
        # shared bounded pool defaults to 12 workers; ARM/Graph 429s back off below.
        self.workers = _bound(options.get("concurrency", 12), "concurrency", 1, 32)
        self.retries = _bound(options.get("retries", 2), "retries", 0, 5)
        self.page_size = _bound(options.get("page_size", 200), "page_size", 1, 1000)
        self.lock = threading.Lock()
        self.collections = []
        self.total = 0
        # Enabled by this provider's collect(), so shared K8s readers do not
        # accidentally publish Azure progress.
        self.progress_callback = None
        self.progress_provider = None
        self.progress_phase = "discovering"
        self.progress_settled = 0
        self.progress_identities = set()
        self.progress_lock = threading.Lock()

    def progress(self, phase=None, scope="", settled=None):
        if self.progress_provider is None:
            return
        from peaso.progress import emit_progress
        safe_scope = scope
        if scope.startswith(("/subscriptions/", "/tenants/")):
            safe_scope = "/" + "/".join(scope.strip("/").split("/")[:2])
        else:
            safe_scope = ""
        with self.progress_lock:
            if settled is not None:
                self.progress_settled += 1
                for item in settled.get("items", []):
                    rid = item.get("id")
                    if isinstance(rid, str):
                        self.progress_identities.add(rid.casefold() if rid.startswith("/") else (safe_scope.casefold(), rid))
            emit_progress(self.progress_callback, phase=phase or self.progress_phase, provider=self.progress_provider,
                          scope=safe_scope, completed=self.progress_settled, total=None,
                          resources=len(self.progress_identities), dynamic_total=True)

    def check_cancelled(self):
        event = getattr(self.budget, "cancel_event", None)
        if event is not None and event.is_set():
            raise AzureReadError("collection_cancelled")
        absolute_deadline = getattr(self.budget, "deadline", None)
        if absolute_deadline is not None and time.time() >= absolute_deadline:
            raise AzureReadError("deadline_exceeded", 408)
        if self.cancel_check is not None and self.cancel_check():
            raise AzureReadError("collection_cancelled")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise AzureReadError("deadline_exceeded", 408)

    def call(self, operation, *args, **kwargs):
        attempt = -1
        while True:
            attempt += 1
            self.check_cancelled()
            with self.lock:
                if self.budget.max_calls is not None and self.budget.calls >= self.budget.max_calls:
                    raise AzureReadError("call_limit")
                self.budget.calls += 1
            try:
                return operation(*args, **kwargs)
            except Exception as exc:
                code = _status_code(exc)
                throttled = code in (429, "429")
                # Throttling gets extra attempts; it is the provider asking us to slow down.
                limit = max(self.retries, 4) if throttled else self.retries
                if code not in (429, 500, 502, 503, 504, "429", "500", "502", "503", "504") or attempt >= limit:
                    raise
                delay = _retry_after(exc) if throttled else min(0.2 * 2**attempt, 2)
                # Honor Retry-After as a lower bound; if it cannot fit the
                # bounded wait or active deadline, keep inventory incomplete.
                if not math.isfinite(delay) or delay > 30:
                    raise AzureReadError("retry_after_exceeds_budget", 408)
                if ((self.deadline is not None and time.monotonic() + delay >= self.deadline) or
                        (self.budget.deadline is not None and time.time() + delay >= self.budget.deadline)):
                    raise AzureReadError("deadline_exceeded", 408)
                time.sleep(delay)

    def pages(self, request, url, *, audience=ARM, key="value", next_key="nextLink", body=None):
        origin = urlsplit(url)
        seen = set()
        page = 0
        while self.budget.max_pages is None or page < self.budget.max_pages:
            self.check_cancelled()
            parsed = urlsplit(url)
            if parsed.scheme != "https" or ((parsed.hostname or "").lower(), parsed.port or 443) != ((origin.hostname or "").lower(), origin.port or 443) or parsed.path != origin.path or parsed.fragment or parsed.username or parsed.password:
                raise AzureReadError("untrusted_continuation")
            response = self.call(request, url, body=body, audience=audience)
            page += 1
            if not isinstance(response, dict) or not isinstance(response.get(key), list):
                raise ValueError("malformed list")
            yield response[key]
            token = response.get(next_key)
            if not token:
                if body is not None and response.get("resultTruncated") in (True, "true"):
                    raise AzureReadError("graph_truncated")
                return
            if not isinstance(token, str) or token in seen:
                raise ValueError("malformed continuation")
            seen.add(token)
            if body is not None:
                body = {**body, "options": {**body.get("options", {}), "$skipToken": token}}
            else:
                url = token
        raise AzureReadError("page_limit")

    def _read(self, job):
        kind, scope, service, fetch = job
        items = {}
        status, error = "collected", None
        scoped_types = set(ENDPOINTS) | {"key_vault_certificate", "resource_graph", "subnet", "vnet_peering", "diagnostic_setting", "storage_service", "sql_database", "sql_firewall_rule", "sql_audit", "sql_security", "secret_metadata", "dns_record", "private_dns_link", "app_service_config", "app_service_identity_detail", "sql_tde", "managed_identity_federated_credential", "key_metadata", "key_rotation_policy", "key_vault_certificate_policy", "sql_vulnerability_assessment", "sql_encryption_protector", "storage_container", "storage_encryption_scope"}
        try:
            self.check_cancelled()
            for page in fetch():
                self.check_cancelled()
                if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                    raise ValueError("malformed page")
                for item in page:
                    identifier = item.get("id")
                    if not isinstance(identifier, str) or not identifier:
                        raise ValueError("missing authoritative resource identity")
                    if service != "kubernetes" and kind in scoped_types and scope.startswith("/subscriptions/") and not _policy_assignment_scope_allowed(kind, scope, identifier):
                        raise ValueError("resource outside selected ARM scope")
                    normalized = identifier.lower() if service != "kubernetes" else identifier
                    if normalized not in items and self.budget.max_items is not None and len(items) >= self.budget.max_items:
                        raise AzureReadError("resource_limit")
                    projected = item if service == "kubernetes" else _metadata_only(item, kind == "secret_metadata" or str(item.get("type", "")).lower().endswith("/secrets"))
                    if kind == "app_service":
                        projected = azure_functions_runtime_native.safe_site_inventory(projected)
                    if kind in azure_alert_routing_native.CONTRACTS:
                        try:
                            projected = azure_alert_routing_native.project(kind, scope, projected, ENDPOINTS[kind][1])
                        except ValueError:
                            # Preserve native metadata for other controls while
                            # making unavailable routing interpretation explicit.
                            projected = {**projected, '_routing_provenance': {
                                'status': 'unavailable', 'code': 'native_routing_unresolved'}}
                    if kind in ('storage_account', 'embedded_blobContainers', 'embedded_encryptionScopes') and normalized in items:
                        raise ValueError('duplicate native storage identity')
                    if kind == 'subscription' and normalized in items and items[normalized] != projected:
                        raise ValueError('conflicting subscription tenant identity')
                    if kind in ('aks_cluster', 'embedded_localUsers', 'embedded_extensions', 'embedded_backupShortTermRetentionPolicies', 'embedded_eventSubscriptions') and normalized in items:
                        raise ValueError('duplicate native child identity')
                    if kind in ('conditional_access_policy', 'named_location') and normalized in items:
                        raise ValueError('duplicate native Conditional Access policy or location identity')
                    if kind in azure_alert_routing_native.CONTRACTS and normalized in items:
                        raise ValueError('duplicate native alert identity')
                    if kind == 'security_assessment' and normalized in items and items[normalized] != projected:
                        raise ValueError('conflicting native security assessment identity')
                    if kind == 'embedded_guestConfigurationAssignments' and normalized in items and items[normalized] != projected:
                        raise ValueError('conflicting guest assignment identity')
                    if kind == 'embedded_backupProtectedItems' and normalized in items and items[normalized] != projected:
                        raise ValueError('conflicting backup protected item identity')
                    if kind == 'policy_assignment' and normalized in items:
                        raise ValueError('duplicate native policy assignment identity')
                    items.setdefault(normalized, projected)
        except Exception as exc:
            status, error = _safe_error(exc)
            if items or getattr(exc, "code", "") in ("resource_limit", "page_limit", "call_limit", "graph_truncated", "scope_limit", "collection_cancelled"):
                status = "partial"
        if status == "collected" and not items:
            status = "empty"
        result = {"type": kind, "scope": scope, "service": service, "status": status, "items": list(items.values())}
        if error:
            result["error"] = error
        self.progress(scope=scope, settled=result)
        return result

    def run(self, jobs):
        # Results are reduced in request order for deterministic total resource caps.
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = pool.map(self._read, jobs)
            for result in results:
                capacity = len(result["items"]) if self.budget.max_items is None else max(0, self.budget.max_items - self.total)
                if len(result["items"]) > capacity:
                    result["items"] = result["items"][:capacity]
                    result.update(status="partial", error={"code": "resource_limit"})
                self.total += len(result["items"])
                self.collections.append(result)

    def unavailable(self, kind, scope, service, exc):
        status, error = _safe_error(exc)
        value = {"type": kind, "scope": scope, "service": service, "status": status, "items": [], "error": error}
        self.collections.append(value)
        self.progress(scope=scope, settled=value)

    def metadata(self):
        return {"collection": "read-only", "calls": self.budget.calls, "max_calls": self.budget.max_calls,
                "max_pages": self.budget.max_pages, "max_resources": self.budget.max_items,
                "concurrency": self.workers, "retries": self.retries,
                "explicit_limits": dict(self.explicit_limits), "collection_deadline_seconds": self.deadline_seconds,
                "intentional_partial": any(c.get("error", {}).get("code") in ("resource_limit", "page_limit", "call_limit", "scope_limit", "deadline_exceeded", "collection_cancelled") for c in self.collections)}


def _selected(options, requirements):
    wanted = options.get("inventories", [kind for kind in TYPES if kind not in ("app_service_identity_detail", azure_app_settings_secret_indicators.KIND, azure_acr_image_secret_indicators.KIND, azure_acr_image_vulnerabilities_20261021.KIND, azure_selected_aks_image_20261021.KIND, azure_selected_aks_image_20261021.VULN_KIND, azure_selected_configuration_secret_indicators.KIND, azure_selected_storage_secret_indicators.KIND, azure_devops_selected_content_secret_indicators.KIND) + azure_selected_declaration_secret_indicators.KINDS + azure_selected_log_sample_secret_indicators.KINDS + (azure_ml_selected_job_secret_indicators.KIND, azure_databricks_notebook_secret_indicators.KIND, azure_synapse_selected_notebook_secret_indicators.KIND, azure_function_settings_declarations_20261020.KIND) + azure_ml_selected_asset_secret_indicators.KINDS]) if requirements is None else requirements
    if not isinstance(wanted, (list, tuple)) or any(kind not in TYPES for kind in wanted):
        raise ValueError("unsupported Azure inventory requirement")
    selected = set(wanted)
    from .azure_unused_iam_20261021 import required_types as unused_iam_required_types
    selected.update(unused_iam_required_types(selected))
    if selected.intersection(azure_nsp_query_cmk_runtime_20261020.KINDS):
        selected.add("subscription")
    selected.update(azure_identity_enforcement_review_20261020.required_types(selected))
    selected.update(azure_entitlement_native.required_types(selected))
    selected.update(azure_application_compute_2_native.required_types(selected))
    selected.update(azure_acr_public_ip_review_20261020.required_types(selected))
    selected.update(azure_automation_aci_metadata_native_20261020.required_types(selected))
    selected.update(azure_devtestlab_native.required_types(selected))
    if "activity_log_coverage" in selected:
        selected.add("activity_log")
    if azure_subnet_firewall_policy.active(options):
        selected.update(azure_wave_network_controls.required_types(selected))
    if "effective_route" in selected:
        selected.add("nic")
    if "security_admin_rule" in selected:
        selected.add("vnet")
    selected.update(azure_certificate_issuance_native.required_types(selected))
    selected.update(azure_nsg_ingress_native.required_types(selected))
    selected.update(azure_aks_workloads_native.required_types(selected))
    selected.update(azure_aks_legacy_projection_review_20261020.required_types(selected))
    selected.update(azure_entra_user_native.required_types(selected))
    selected.update(azure_public_edge_native.required_types(selected))
    selected.update(azure_storage_recovery_metadata_native.required_types(selected))
    selected.update(azure_storage_lifecycle_native.required_types(selected))
    selected.update(azure_key_rotation_evidence_native.required_types(selected))
    selected.update(azure_secret_versions_native.required_types(selected))
    selected.update(azure_vault_key_versions_native.required_types(selected))
    if "assessment_metadata" in selected:
        selected.add("security_assessment")
    selected.update(azure_function_limits_native.required_types(selected, options))
    selected.update(azure_functions_runtime_native.required_types(selected))
    if "apim_api_evidence" in selected:
        selected.update(("api_management", "apim_native"))
    if "azure_sw24_evidence" in selected and options.get("_azure_apim_diagnostics_checks") != []:
        selected.update(("api_management", "apim_native"))
    selected.update(azure_database_native.required_types(selected))
    selected.update(azure_arm_metadata_native.required_types(selected))
    selected.update(azure_storage_backup_native.required_types(selected))
    selected.update(azure_defender_network_native.required_types(selected))
    selected.update(azure_adaptive_network_native.required_types(selected))
    selected.update(azure_incident_inventory_native.required_types(selected))
    selected.update(azure_storage_blob_keys_native.required_types(selected))
    selected.update(azure_audit_storage_native.required_types(selected))
    selected.update(azure_wave_compute_native.required_types(selected))
    selected.update(azure_apim_diagnostic_evidence_native.required_types(selected))
    if "azure_detection_telemetry" in selected:
        selected.update(("log_analytics_workspace", "scheduled_query_rule", "action_group"))
    if "sql_tde_inventory" in selected: selected.update(("sql_database_inventory", "sql_tde"))
    if "sql_database_inventory" in selected: selected.add("sql_database")
    if "application_scope" in selected:
        selected.add("directory_application")
    if "service_principal_scope" in selected:
        selected.add("directory_service_principal")
    if "directory_membership" in selected:
        selected.add("directory_group")
    if "management_group" in selected:
        selected.update(("role_assignment", "role_definition", "directory_user",
                         "directory_group", "directory_service_principal", "directory_membership"))
    if "cost_export" in selected:
        selected.update(("resource_group", "management_group"))
    if "managed_application_definition" in selected:
        selected.update(("resource_group", "managed_application", "directory_domain"))
    if "entra_domain_service" in selected:
        selected.update(("vnet", "subnet", "nsg", "directory_domain"))
    if "powerbi_capacity" in selected:
        selected.add("directory_domain")
    if "security_contact" in selected:
        selected.add("directory_domain")
    if selected.intersection(("directory_group_pim_policy", "directory_group_pim_owner_policy",
                              "directory_group_eligibility_schedule", "directory_group_eligibility_instance")):
        selected.add("directory_group")
    # This evidence kind is shared with subscription-scoped Guest Configuration.
    # Only the directory-user consumer requests the tenant-scoped MFA producer.
    if "azure_sw18_evidence" in selected and "directory_user" in selected:
        selected.update(("directory_user", "directory_group", "directory_membership",
                         "directory_user_group_membership", "directory_role_assignment",
                         "directory_role_definition", "directory_role_eligibility_schedule",
                         "directory_role_eligibility_instance", "directory_role_assignment_instance",
                         "user_registration_detail"))
    if "ml_compute" in selected:
        selected.add("ml_workspace")
    if selected.intersection({"key_vault_certificate", "key_vault_certificate_current"}):
        selected.add("vault")
    if "key_vault_key" in selected:
        selected.update(("key_metadata", "key_rotation_policy"))
    if "flow_log" in selected:
        selected.add("network_watcher")
    if selected.intersection(("backup_protected_item", "backup_policy")):
        selected.add("recovery_vault")
    if "virtual_network_gateway" in selected:
        selected.add("resource_group")
    if azure_lighthouse_native.KIND in selected:
        selected.add("resource_group")
    if selected.intersection(("sql_database_ltr_policy",)):
        selected.update(("sql_database", "sql_database_inventory"))
    if "key_rotation_policy" in selected:
        selected.add("key_metadata")
    if "sql_tde" in selected:
        selected.add("sql_database")
    if "directory_app_role_assignment" in selected:
        selected.add("directory_service_principal")
    if "directory_owner" in selected:
        selected.update(("directory_application", "directory_service_principal", "directory_group"))
    if "directory_administrative_unit_member" in selected:
        selected.add("directory_administrative_unit")
    if "app_service_slot" in selected:
        selected.add("app_service")
    if "automation_variable" in selected:
        selected.add("automation_account")
    if "batch_pool" in selected:
        selected.add("batch_account")
    if "mysql_single_configuration" in selected:
        selected.add("mysql_single_server")
    if "bot_cmk_key" in selected:
        selected.add("bot_service")
    if "backup_job" in selected:
        selected.add("recovery_vault")
    if selected.intersection(("sql_ltr_backup", "sql_restore_point")):
        selected.update(("sql_database", "sql_database_inventory"))
    if "managed_instance_tde" in selected:
        selected.add("managed_instance_database")
    if "managed_instance_database" in selected:
        selected.add("mssql_managed_instance")
    if "defender_pricing" in selected:
        selected.add("aks_cluster")
    if "guest_configuration_report" in selected:
        selected.add("vm")
    if "storage_local_user" in selected or "eventgrid_subscription" in selected:
        selected.add("storage_account")
    if "sql_backup_short_term_policy" in selected:
        selected.add("sql_database_inventory")
        selected.add("sql_database")
    if "diagnostic_category" in selected:
        selected.update(("application_gateway", "load_balancer", "app_service_environment",
                         "aks_cluster", "cosmos_account", "mongo_cluster", "sql_database"))
    if "directory_federated_credential" in selected:
        selected.add("directory_application")
    return selected


def _subscription(scope):
    value = scope.removeprefix("/subscriptions/").strip("/")
    if not value or "/" in value or not all(c.isalnum() or c in "-_." for c in value):
        raise ValueError("invalid subscription scope")
    return "/subscriptions/" + value


def _trusted_scopes(options):
    values = options.get("trusted_scope_ids", [])
    if not isinstance(values, list) or len(values) > 100 or any(not isinstance(value, str) or not value or len(value) > 2048 for value in values):
        raise ValueError("trusted_scope_ids must be an explicit bounded string list")
    return list(dict.fromkeys(values))


def _defender_containers_policy(options, scopes, captured_at):
    """Whitelisted owner extension requirements; no Azure request is made."""
    supported_extensions = frozenset({
        "AgentlessDiscoveryForKubernetes", "ContainerRegistriesVulnerabilityAssessments",
        "AgentlessVmScanning", "ContainerSensor", "ContainerIntegrityContribution",
    })
    def unresolved(reason):
        return {"status": "unknown", "reason": reason, "source": "operator-supplied"}

    parent = options.get("compliance_policy")
    raw = parent.get("defender_containers") if isinstance(parent, dict) else None
    base = {"max_policy_items", "subscriptions"}
    timed = {"observed_at", "max_age_seconds"}
    if not isinstance(raw, dict) or set(raw) not in (base, base | timed):
        return unresolved("defender_containers_policy_missing_or_malformed")
    budget = raw["max_policy_items"]
    if type(budget) is not int or not 0 < budget <= 1000:
        return unresolved("defender_containers_policy_bounds_invalid")
    expiry = {}
    if timed <= set(raw):
        age, observed = raw["max_age_seconds"], raw["observed_at"]
        if type(age) is not int or age <= 0 or not isinstance(observed, str) or len(observed) > 64 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", observed):
            return unresolved("defender_containers_policy_timestamp_invalid")
        try:
            delta = (datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
                     - datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds()
        except ValueError:
            return unresolved("defender_containers_policy_timestamp_invalid")
        if not 0 <= delta <= age:
            return unresolved("defender_containers_policy_stale_or_future")
        expiry = {"observed_at": observed, "max_age_seconds": age}
    rows = raw["subscriptions"]
    if not isinstance(rows, list) or not rows or len(rows) > budget:
        return unresolved("defender_containers_policy_subscription_set_invalid")
    selected, count = {}, 0
    scanned = {scope.casefold() for scope in scopes}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"scope", "required_extensions"}:
            return unresolved("defender_containers_policy_subscription_entry_invalid")
        scope, names = row["scope"], row["required_extensions"]
        if not isinstance(scope, str) or not re.fullmatch(r"/subscriptions/[A-Za-z0-9._-]{1,128}", scope) or scope.casefold() not in scanned or scope.casefold() in selected:
            return unresolved("defender_containers_policy_scope_foreign_or_duplicate")
        if not isinstance(names, list) or not names or len(names) > budget or any(type(name) is not str or name not in supported_extensions for name in names) or len(names) != len(set(names)):
            return unresolved("defender_containers_policy_extension_set_invalid")
        selected[scope.casefold()] = {"scope": scope, "required_extensions": list(names)}
        count += 1 + len(names)
        if count > budget:
            return unresolved("defender_containers_policy_item_budget_exceeded")
    return {"status": "collected", "source": "operator-supplied", **expiry,
            "max_policy_items": budget,
            "subscriptions": list(selected.values())}


def _cosmos_backup_retention_policy(options, scopes, captured_at):
    """Keep only exact account-bound owner minimums; never read Cosmos data."""
    def unresolved(reason):
        return {"status": "unknown", "reason": reason, "source": "operator-supplied"}

    parent = options.get("compliance_policy")
    raw = parent.get("cosmos_backup_retention") if isinstance(parent, dict) else None
    base = {"max_policy_items", "accounts"}
    timed = {"observed_at", "max_age_seconds"}
    if not isinstance(raw, dict) or set(raw) not in (base, base | timed):
        return unresolved("cosmos_backup_owner_policy_missing_or_malformed")
    budget, rows = raw["max_policy_items"], raw["accounts"]
    if type(budget) is not int or budget <= 0 or not isinstance(rows, list) or not rows or len(rows) > budget:
        return unresolved("cosmos_backup_owner_policy_bounds_invalid")
    expiry = {}
    if timed <= set(raw):
        observed, age = raw["observed_at"], raw["max_age_seconds"]
        if type(age) is not int or age <= 0 or not isinstance(observed, str) or len(observed) > 64 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", observed):
            return unresolved("cosmos_backup_owner_policy_timestamp_invalid")
        try:
            elapsed = (datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
                       - datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds()
        except ValueError:
            return unresolved("cosmos_backup_owner_policy_timestamp_invalid")
        if not 0 <= elapsed <= age:
            return unresolved("cosmos_backup_owner_policy_stale_or_future")
        expiry = {"observed_at": observed, "max_age_seconds": age}
    selected = {scope.casefold() for scope in scopes}
    account_pattern = re.compile(r"/subscriptions/[A-Za-z0-9._-]{1,128}/resourceGroups/[^/?#\x00-\x1f]{1,90}/providers/Microsoft\.DocumentDB/databaseAccounts/[^/?#\x00-\x1f]{1,256}\Z", re.I)
    accounts, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"subscription_scope", "resource_id", "min_retention_days"}:
            return unresolved("cosmos_backup_owner_account_shape_invalid")
        scope, rid, days = row["subscription_scope"], row["resource_id"], row["min_retention_days"]
        if not isinstance(scope, str) or not re.fullmatch(r"/subscriptions/[A-Za-z0-9._-]{1,128}", scope, re.I) or scope.casefold() not in selected:
            return unresolved("cosmos_backup_owner_subscription_foreign")
        if not isinstance(rid, str) or not account_pattern.fullmatch(rid) or not rid.casefold().startswith(scope.casefold() + "/") or rid.casefold() in seen or type(days) is not int or days <= 0:
            return unresolved("cosmos_backup_owner_account_identity_or_minimum_invalid")
        seen.add(rid.casefold())
        accounts.append({"subscription_scope": scope, "resource_id": rid, "min_retention_days": days})
    return {"status": "collected", "source": "operator-supplied", **expiry,
            "max_policy_items": budget, "accounts": accounts}


def _complete_diagnostic_inventory(reader, scopes):
    """Settle a requested diagnostic inventory when no resource child was read."""
    required = set(ENDPOINTS) - NO_DIAGNOSTIC_KINDS
    for scope in scopes:
        prefix = scope.casefold()
        if any(c["type"] == "diagnostic_setting" and
               (c["scope"].casefold() == prefix or c["scope"].casefold().startswith(prefix + "/"))
               for c in reader.collections):
            continue
        sources = [c for c in reader.collections if c["type"] in required and c["scope"].casefold() == prefix]
        empty = (set(c["type"] for c in sources) == required and
                 all(c["status"] in ("collected", "empty") and not c["items"] for c in sources))
        reader.collections.append({"type": "diagnostic_setting", "scope": scope,
                                   "service": "Microsoft.Insights", "status": "empty" if empty else "partial", "items": [],
                                   **({"parent_inventory": "diagnostic_resource_universe"} if empty else
                                      {"error": {"code": "parent_inventory_incomplete"}})})


from . import azure_selected_storage_secret_indicators, azure_devops_selected_content_secret_indicators
from . import azure_flex_deployment_archives_20261021
from . import azure_selected_secret_integration_20261020
from . import azure_selected_declaration_secret_indicators
from . import azure_selected_log_sample_secret_indicators
from . import azure_ml_selected_job_secret_indicators
from . import azure_databricks_notebook_secret_indicators
from . import azure_synapse_selected_notebook_secret_indicators
from . import azure_ml_selected_asset_secret_indicators
from . import azure_function_settings_declarations_20261020, azure_function_settings_runtime_hooks_20261020
from . import azure_nsp_query_cmk_runtime_20261020
TYPES += azure_nsp_query_cmk_runtime_20261020.KINDS
from . import azure_function_package_integration_20261020 as package_source
TYPES += (package_source.KIND,)
TYPES += (azure_selected_storage_secret_indicators.KIND, azure_devops_selected_content_secret_indicators.KIND, azure_flex_deployment_archives_20261021.KIND) + azure_selected_declaration_secret_indicators.KINDS + azure_selected_log_sample_secret_indicators.KINDS + (azure_ml_selected_job_secret_indicators.KIND, azure_databricks_notebook_secret_indicators.KIND, azure_synapse_selected_notebook_secret_indicators.KIND, azure_function_settings_declarations_20261020.KIND) + azure_ml_selected_asset_secret_indicators.KINDS


class _MetadataOnlyCollection(Exception):
    """Skip native IO for an empty selection, retaining normal metadata output."""


def collect(connector, requirements=None, *, transport=None):
    """Return native facts with separate directory, inheritance and usage coverage."""
    options, auth = connector.get("options", {}), connector.get("auth", {})
    package_grant = package_source.authorize(options, connector.get('scopes', []))
    azure_devops_git_native.normalize(options, auth)
    azure_devops_pipeline_native.normalize(options, auth)
    azure_aks_workloads_native.normalize(options, auth)
    if not isinstance(options, dict) or not isinstance(auth, dict):
        raise ValueError("auth and options must be objects")
    from .azure_resource_logging_policy import normalize as normalize_resource_logging
    resource_logging_owner = normalize_resource_logging(options)
    nsg_owner = azure_nsg_ingress_native.normalize(options)
    sw32_owner = None
    sw15_owner = None
    from peaso.azure_tls_owner_policy import normalize as normalize_tls_owner, bind_scopes as bind_tls_scopes, merge_metadata as merge_tls_metadata
    tls_owner = normalize_tls_owner(options)
    supplied_policy = options.get("compliance_policy")
    if isinstance(supplied_policy, dict) and "sw15" in supplied_policy:
        from .azure_sw15_policy import normalize as normalize_sw15
        sw15_owner = normalize_sw15(options)
    if isinstance(supplied_policy, dict) and "sw32" in supplied_policy:
        from peaso.azure_sw32_policy import normalize_sw32
        sw32_owner = normalize_sw32(supplied_policy["sw32"])
    content_grants = options.get('_content_secret_scan_kinds', [])
    auto_app_settings = (options.get('content_secret_scans') is True
        and azure_app_settings_secret_indicators.KIND in content_grants
        and azure_app_settings_secret_indicators.OPTION not in options)
    auto_container_literals = (options.get('content_secret_scans') is True
        and azure_selected_configuration_secret_indicators.KIND in content_grants
        and azure_selected_configuration_secret_indicators.OPTION not in options)
    if not auto_container_literals:
        azure_selected_configuration_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_selected_declaration_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_selected_log_sample_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_ml_selected_job_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_databricks_notebook_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_synapse_selected_notebook_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_ml_selected_asset_secret_indicators.selected_targets(options, connector.get('scopes', []))
    function_targets, function_checks = azure_function_settings_declarations_20261020.preflight(
        options, connector.get('scopes', []), options.get('_azure_function_settings_checks', []))
    if function_targets:
        from peaso.rawv2_private_source_successor_20261021 import install_admission
        install_admission('azure_function_settings_runtime_admission_20261020')
    azure_selected_storage_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_flex_deployment_archives_20261021.selected_targets(options, connector.get('scopes', []))
    azure_devops_selected_content_secret_indicators.selected_targets(options, connector.get('scopes', []), auth)
    if not auto_app_settings:
        azure_app_settings_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_acr_image_secret_indicators.selected_targets(options, connector.get('scopes', []))
    azure_selected_aks_image_20261021.selected_targets(options, connector.get('scopes', []), options.get('_azure_aks_image_named_checks', []))
    azure_acr_image_vulnerabilities_20261021.selected_targets(options, connector.get('scopes', []))
    azure_databricks_native.validate_auth(auth)
    azure_databricks_native.normalize(options)
    wanted = _selected(options, requirements)
    if auto_app_settings and azure_app_settings_secret_indicators.KIND in wanted:
        wanted.update(('app_service', 'app_service_slot'))
    else:
        auto_app_settings = False
    if auto_container_literals and azure_selected_configuration_secret_indicators.KIND in wanted:
        wanted.update(('container_group', 'container_app'))
    else:
        auto_container_literals = False
    metadata_only_selection = False
    if package_grant is None:
        wanted.discard(package_source.KIND)
        metadata_only_selection = not wanted or bool(requirements and set(requirements) == {package_source.KIND})
    if "databricks_account_workspace" in wanted:
        wanted.add("databricks_workspace")
    from . import azure_disclosure_native
    wanted |= azure_disclosure_native.required_types(options)
    from . import azure_identity_intune_native
    wanted |= azure_identity_intune_native.required_types(wanted)
    wanted |= azure_access_reviews_native.required_types(wanted)
    from . import azure_frontdoor_native
    wanted |= azure_frontdoor_native.required_parents(wanted)
    if metadata_only_selection:
        wanted.clear()  # An ungranted package cannot trigger dependency reads.
    functions_native_only = ("function_app_runtime_native" in wanted and wanted <=
        {"app_service", "app_service_plan", "subscription", "function_app_runtime_native", "function_app_configuration"})
    from .azure_guest_policy import normalize as normalize_guest_policy
    guest_policy = normalize_guest_policy(options)
    lifecycle_owner = azure_storage_lifecycle_native.normalize(options)
    from . import azure_swc, azure_appservice_identity_followup
    trusted_scopes = _trusted_scopes(options)
    reader = _Reader(options)
    reader.progress_callback = options.get("_progress_callback")
    from peaso.collection_events import SettledCollections
    deferred = {"subscription", "network_interface"}
    if auto_app_settings:
        deferred.add(azure_app_settings_secret_indicators.KIND)
    if auto_container_literals:
        deferred.add(azure_selected_configuration_secret_indicators.KIND)
    reader.collections = SettledCollections(options.get("_collection_callback"), deferred=deferred)
    reader.progress_provider = "azure"
    reader.progress("discovering")
    credential_context_id = uuid4().hex
    customer_context_id = "scan-local:" + credential_context_id
    if package_grant is not None:
        customer_context_id = 'package-customer-' + credential_context_id
    raw_scopes = connector.get("scopes") or ["*"]
    if not isinstance(raw_scopes, list) or any(not isinstance(x, str) for x in raw_scopes):
        raise ValueError("scopes must contain subscription IDs")
    max_scopes = options.get("max_scopes")
    if max_scopes is not None and (isinstance(max_scopes, bool) or not isinstance(max_scopes, int) or max_scopes < 1):
        raise ValueError("max_scopes must be a positive integer")
    scopes = list(dict.fromkeys(_subscription(x) for x in raw_scopes if x != "*"))
    scopes_limited = max_scopes is not None and len(scopes) > max_scopes
    if scopes_limited:
        scopes = scopes[:max_scopes]
    discover_all = "*" in raw_scopes
    if lifecycle_owner is not None and not discover_all and lifecycle_owner['scope'].casefold() not in {scope.casefold() for scope in scopes}:
        raise ValueError('storage lifecycle approval outside selected subscriptions')
    if nsg_owner is not None:
        if discover_all:
            raise ValueError("NSG owner criteria require explicit selected subscription")
        azure_nsg_ingress_native.normalize(options, scopes)
    if not discover_all:azure_aks_workloads_native.bind_scopes(options, auth, scopes)
    if not discover_all:bind_tls_scopes(tls_owner, scopes)
    if not discover_all and set(azure_devops_git_native.normalize(options, auth)) - {s.lower() for s in scopes}:
        raise ValueError('DevOps applicability outside selected subscriptions')
    if sw15_owner is not None and not discover_all and sw15_owner["scope"].casefold() not in {s.casefold() for s in scopes}:
        raise ValueError("SW15 approval is outside the selected subscriptions")
    if sw32_owner is not None and not discover_all and sw32_owner["scope"].casefold() not in {s.casefold() for s in scopes}:
        raise ValueError("SW32 approval is outside the selected subscriptions")
    if guest_policy and not discover_all and guest_policy['scope'].casefold() not in {scope.casefold() for scope in scopes}:
        raise ValueError('guest baseline policy is outside the selected subscriptions')
    if resource_logging_owner is not None and not discover_all and resource_logging_owner['scope'].casefold() not in {scope.casefold() for scope in scopes}:
        raise ValueError('diagnostic approval outside selected subscriptions')
    if package_grant is not None and tuple(scopes) != package_grant.scopes:
        raise ValueError('package_scope_limit_changed')
    owned = transport is None
    tenant_scope = "/tenants/" + (auth.get("tenant_id") or "selected")
    now = datetime.now(timezone.utc)
    days = _bound(options.get("activity_days", 30), "activity_days", 1, 90)
    start, end = (now - timedelta(days=days)).isoformat(), now.isoformat()
    request = None  # Bound only after explicit authentication validation succeeds.
    try:
        if metadata_only_selection:
            raise _MetadataOnlyCollection
        if options.get("hosted"):
            if any(auth.get(key) for key in ("certificate_path", "token_file")):
                raise ValueError("hosted Azure credentials require inline material")
            if not (auth.get("arm_token") or auth.get("token") or auth.get("client_secret") or auth.get("certificate_data") or auth.get("client_certificate") or auth.get("federated_token")):
                raise ValueError("hosted Azure requires tenant-provided explicit credentials")
            method = auth.get("method", "auto")
            if method == "auto":
                method = "token" if auth.get("arm_token") or auth.get("token") else "client-secret" if auth.get("client_secret") else "client-cert" if auth.get("certificate_data") or auth.get("client_certificate") else "workload-identity"
            if method not in ("token", "client-secret", "client-cert", "certificate", "workload-identity"):
                raise ValueError("hosted Azure cannot select worker identity sources")
            auth = {**auth, "method": method}
        if owned:
            if function_targets:
                with azure_function_settings_declarations_20261020.private_native_logs():
                    transport = AzureTransport(auth)
            else:
                transport = AzureTransport(auth)
        cache, cache_locks, cache_guard = {}, {}, threading.Lock()
        def request(url, *, body=None, audience=ARM):
            key = (audience, url, json.dumps(body, sort_keys=True) if body is not None else None)
            with cache_guard:
                lock = cache_locks.setdefault(key, threading.Lock())
            with lock:
                if key not in cache:
                    value = transport.request(url, body=body, audience=audience)
                    if body is None and audience == ARM and azure_automation_aci_metadata_native_20261020.aci_metadata_route(url, scopes):
                        value = _metadata_only(value)
                    cache[key] = value
                return cache[key]
        jobs = []
        nsp_query_selected = bool(wanted.intersection(azure_nsp_query_cmk_runtime_20261020.KINDS))
        if discover_all:
            reader.run([("subscription", tenant_scope, "Microsoft.Resources", lambda: reader.pages(request, ARM + "/subscriptions?api-version=2022-12-01"))])
            scopes = [item["id"] for item in reader.collections[-1]["items"] if isinstance(item.get("subscriptionId"), str)]
            if max_scopes is not None and len(scopes) > max_scopes:
                scopes = scopes[:max_scopes]
                scopes_limited = True
                reader.collections[-1].update(status="partial", error={"code": "scope_limit"})
            from peaso.collection_events import emit_collection
            emit_collection(options.get('_collection_callback'), reader.collections[-1])
        elif "subscription" in wanted:
            # An explicit scan must not turn a tenant-wide subscription LIST
            # into subjects for checks bound to the selected subscription.
            for scope in scopes:
                if nsp_query_selected:
                    reader.run([azure_nsp_query_cmk_runtime_20261020.subscription_job(
                        reader, transport, scope, credential_context_id=credential_context_id,
                        customer_context_id=customer_context_id)])
                    continue
                def selected_subscription(scope=scope):
                    value = reader.call(request, ARM + scope + "?api-version=2022-12-01")
                    guid = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
                    selected_id = scope.rsplit("/", 1)[-1]
                    subscription_id = value.get("subscriptionId") if isinstance(value, dict) else None
                    tenant_id = value.get("tenantId") if isinstance(value, dict) else None
                    expected_tenants = (auth.get("tenant_id"), getattr(transport, "verified_tenant", None))
                    if (not isinstance(value, dict) or not isinstance(value.get("id"), str)
                            or value["id"].lower() != scope.lower()
                            or not isinstance(subscription_id, str) or not re.fullmatch(guid, subscription_id)
                            or subscription_id.lower() != selected_id.lower()
                            or not isinstance(tenant_id, str) or not re.fullmatch(guid, tenant_id)
                            or any(expected is not None and
                                (not isinstance(expected, str) or expected.lower() != tenant_id.lower())
                                for expected in expected_tenants)):
                        raise ValueError("subscription tenant binding unavailable")
                    yield [value]
                reader.run([("subscription", scope, "Microsoft.Resources", selected_subscription)])
        if nsp_query_selected and scopes:
            if discover_all:
                # The discovery LIST is not a selected subscription GET receipt.
                reader.run([azure_nsp_query_cmk_runtime_20261020.subscription_job(
                    reader, transport, scope, credential_context_id=credential_context_id,
                    customer_context_id=customer_context_id) for scope in scopes])
            try:
                nsp_query_parent = azure_nsp_query_cmk_runtime_20261020.parent_metadata_from_inventory(
                    reader, transport, scopes, credential_context_id=credential_context_id,
                    customer_context_id=customer_context_id)
            except azure_nsp_query_cmk_runtime_20261020.ContextUnavailable:
                # No guessed tenant mapping can bootstrap these declarations.
                nsp_query_parent = {}
            reader.nsp_query_cmk_metadata = azure_nsp_query_cmk_runtime_20261020.collect_into(
                reader, transport, scopes, wanted, parent_metadata=nsp_query_parent)
        if discover_all:bind_tls_scopes(tls_owner, scopes)
        if "tenant" in wanted:
            jobs.append(("tenant", tenant_scope, "Microsoft.Resources", lambda: reader.pages(request, ARM + "/tenants?api-version=2022-12-01")))
        start, end = azure_swc.activity_bounds(options, scopes, start, end)
        if "management_group" in wanted or wanted.intersection(AUTHORIZATION):
            def management_groups():
                incomplete = None
                for page in reader.pages(request, ARM + "/providers/Microsoft.Management/managementGroups?api-version=2020-05-01"):
                    for item in page:
                        try:
                            rid = item["id"]
                            if not rid.startswith("/providers/Microsoft.Management/managementGroups/"):
                                raise ValueError("malformed management group ID")
                            detail = reader.call(request, ARM + rid + "?api-version=2020-05-01&$expand=children&$recurse=true")
                            if not isinstance(detail, dict) or detail.get("id") != rid:
                                raise ValueError("malformed management group detail")
                            yield [detail]
                        except Exception as exc:
                            incomplete = exc
                            yield [{**item, "detail": {"collection_status": _safe_error(exc)[0], "error": _safe_error(exc)[1]}}]
                if incomplete:
                    raise incomplete
            jobs.append(("management_group", tenant_scope, "Microsoft.Management", management_groups))
        directory_kinds = set(DIRECTORY) | set(DIRECTORY_SINGLETONS)
        if wanted.intersection(directory_kinds) and wanted.intersection(set(ENDPOINTS) | set(AUTHORIZATION)):
            # An attempted selected-subscription read is already the authoritative
            # envelope for that scope, even when denied or malformed. Retrying it
            # here would create a duplicate type/scope and invalidate the scan.
            known = {collection["scope"].lower() for collection in reader.collections
                     if collection["type"] == "subscription"}
            for scope in scopes:
                if scope.lower() in known: continue
                def subscription_binding(scope=scope):
                    value = reader.call(request, ARM + scope + "?api-version=2022-12-01")
                    if not isinstance(value, dict) or str(value.get("id", "")).lower() != scope.lower() or not isinstance(value.get("tenantId"), str):
                        raise ValueError("subscription tenant binding unavailable")
                    yield [value]
                jobs.append(("subscription", scope, "Microsoft.Resources", subscription_binding))
        if "subscription_tenant_policy" in wanted:
            def tenant_policy():
                value = reader.call(request, ARM + "/providers/Microsoft.Subscription/policies/default?api-version=2021-10-01")
                policy_id = "/providers/Microsoft.Subscription/policies/default"
                if not isinstance(value, dict) or not isinstance(value.get("properties"), dict) or value.get("id") not in (policy_id, policy_id.lstrip("/")):
                    raise ValueError("malformed subscription tenant policy")
                yield [{**value, "id": policy_id, "_provenance": {"tenant_id": getattr(transport, "tenant", None) or auth.get("tenant_id"), "tenant_verified": bool(getattr(transport, "verified_tenant", None)), "endpoint": "Microsoft.Subscription/policies/default", "read_only": True}}]
            jobs.append(("subscription_tenant_policy", tenant_scope, "Microsoft.Subscription", tenant_policy))
        if "subscription_diagnostic_setting" in wanted:
            for scope in scopes:
                url = ARM + scope + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
                def subscription_diagnostics(url=url, scope=scope):
                    seen = set()
                    for page in reader.pages(request, url):
                        for row in page:
                            identity = row.get("id") if isinstance(row, dict) else None
                            if (not isinstance(identity, str)
                                    or re.fullmatch(re.escape(scope + "/providers/Microsoft.Insights/diagnosticSettings/") + r"[^/?#%\\\s]+", identity, re.I) is None
                                    or identity.rsplit("/", 1)[-1] in (".", "..")
                                    or str(row.get("type", "")).casefold() != "microsoft.insights/diagnosticsettings"
                                    or "name" in row and str(row["name"]).casefold() != identity.rsplit("/", 1)[-1].casefold()
                                    or identity.casefold() in seen):
                                raise ValueError("foreign, duplicate or malformed native subscription diagnostic identity")
                            seen.add(identity.casefold())
                        yield page
                jobs.append(("subscription_diagnostic_setting", scope, "Microsoft.Insights", subscription_diagnostics))
        # Query each selected subscription before detail reads. The discovery
        # collection is retained even when only downstream inventories are wanted.
        need_resources = wanted.intersection(set(ENDPOINTS) | {"diagnostic_setting", "subnet", "vnet_peering", "secret_metadata", "storage_service", "sql_database", "sql_firewall_rule", "sql_audit", "sql_security", "dns_record", "private_dns_link", "resource_graph", "app_service_config", "app_service_identity_detail", "sql_tde", "managed_identity_federated_credential", "key_metadata", "key_rotation_policy", "key_vault_certificate_policy", "sql_vulnerability_assessment", "sql_encryption_protector", "storage_container", "storage_encryption_scope", "app_service_slot", "automation_variable", "batch_pool"} | set(azure_devtestlab_native.CHILDREN))
        if need_resources and not functions_native_only:
            # One Resource Graph query covers a batch of subscriptions (ARG
            # throttles per caller at ~15 queries/5 s; per-subscription queries
            # produced 429s at 89 subscriptions). Results are split back into the
            # same per-subscription collections; a batch failure fails each member.
            top = reader.page_size if options.get("page_size") is not None else 1000
            batches = [scopes[i:i + ARG_BATCH] for i in range(0, len(scopes), ARG_BATCH)]
            batch_results, batch_locks = {}, {index: threading.Lock() for index in range(len(batches))}
            def batch_rows(index):
                with batch_locks[index]:
                    if index not in batch_results:
                        members = batches[index]
                        body = {"subscriptions": [scope.rsplit("/", 1)[-1] for scope in members], "query": "Resources | project id, type, name, location, tags, identity, properties, subscriptionId, resourceGroup | order by id asc", "options": {"resultFormat": "objectArray", "$top": top}}
                        try:
                            split = {scope.lower(): [] for scope in members}
                            for page in reader.pages(request, ARM + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01", body=body, key="data", next_key="$skipToken"):
                                for item in page:
                                    rid = str(item.get("id", "")).lower() if isinstance(item, dict) else ""
                                    parts = rid.split("/", 3)
                                    owner = "/".join(parts[:3]) if len(parts) == 4 else None
                                    if owner not in split or not rid.startswith(owner + "/"):
                                        raise ValueError("Resource Graph returned another scope")
                                    split[owner].append(item)
                            batch_results[index] = split
                        except Exception as exc:
                            batch_results[index] = exc
                    value = batch_results[index]
                if isinstance(value, Exception):
                    raise value
                return value
            for index, members in enumerate(batches):
                for scope in members:
                    def discovery(index=index, scope=scope):
                        yield batch_rows(index)[scope.lower()]
                    jobs.append(("resource_graph", scope, "Microsoft.ResourceGraph", discovery))
        if wanted.intersection(("azure_resource", "resource")):
            native_kind = "azure_resource" if "azure_resource" in wanted else "resource"
            for scope in scopes:
                url = ARM + scope + "/resources?api-version=2021-04-01&$top=1000"
                def resource_list(url=url, scope=scope):
                    for page in reader.pages(request, url):
                        if any(not isinstance(row, dict) or not isinstance(row.get("id"), str)
                               or not row["id"].casefold().startswith(scope.casefold() + "/") for row in page):
                            raise ValueError("foreign ARM resource list item")
                        yield page
                jobs.append((native_kind, scope, "Microsoft.Resources", resource_list))
        reader.run(jobs)
        azure_containerapp_runtime.collect(reader, request, scopes, wanted)
        azure_containerapp_jobs.collect(reader, request, scopes, wanted)
        if wanted.intersection(("azure_resource", "resource")) == {"azure_resource", "resource"}:
            reader.collections.extend({**row, "type": "resource"} for row in list(reader.collections)
                                      if row["type"] == "azure_resource")
        jobs = []
        reader.progress_phase = "collecting"
        reader.progress("collecting")
        groups = [item["id"] for c in reader.collections if c["type"] == "management_group" for item in c["items"]]
        authorization_scopes = list(dict.fromkeys(scopes + groups + (["/"] if wanted.intersection(AUTHORIZATION) else [])))
        for scope in authorization_scopes:
            for kind, endpoint in AUTHORIZATION.items():
                if kind in wanted:
                    url = ARM + scope.rstrip("/") + "/providers/Microsoft.Authorization/" + endpoint + "?api-version=2022-04-01"
                    if scope == "/" and kind in ("role_assignment", "deny_assignment"):
                        url += "&" + urlencode({"$filter": "atScope()"})
                    elif scope != "/" and kind == "role_definition" and "/" in authorization_scopes:
                        # Built-in roles are tenant-wide and identical at every scope:
                        # they are collected once from "/" (deduplicated by GUID);
                        # subscriptions and management groups list only their custom roles.
                        url += "&" + urlencode({"$filter": "type eq 'CustomRole'"})
                    if kind in ('role_assignment', 'role_definition'):
                        def authorization_rows(url=url, kind=kind, scope=scope):
                            yield from azure_remaining_services_1_native.authorization_pages(reader, request, url, kind, scope)
                        jobs.append((kind, scope, "Microsoft.Authorization", authorization_rows))
                    else:
                        jobs.append((kind, scope, "Microsoft.Authorization", lambda url=url: reader.pages(request, url)))
        if "virtual_network_gateway" in wanted:
            for scope in scopes:
                def gateways(scope=scope):
                    groups, seen = set(), set()
                    segment = r"[^/?#%\\\s]+"
                    for group_page in reader.pages(request, ARM + scope + "/resourcegroups?api-version=2021-04-01"):
                        for group in group_page:
                            gid = group.get("id") if isinstance(group, dict) else None
                            if (not isinstance(gid, str)
                                    or re.fullmatch(re.escape(scope) + "/resourceGroups/" + segment, gid, re.I) is None
                                    or gid.rsplit("/", 1)[-1] in (".", "..")
                                    or str(group.get("type", "")).casefold() != "microsoft.resources/resourcegroups"
                                    or "name" in group and str(group["name"]).casefold() != gid.rsplit("/", 1)[-1].casefold()
                                    or gid.casefold() in groups):
                                raise ValueError("malformed resource group identity")
                            groups.add(gid.casefold())
                            prefix = gid + "/providers/Microsoft.Network/virtualNetworkGateways/"
                            for page in reader.pages(request, ARM + prefix.rstrip("/") + "?api-version=2023-09-01"):
                                for row in page:
                                    rid = row.get("id") if isinstance(row, dict) else None
                                    if (not isinstance(rid, str)
                                            or re.fullmatch(re.escape(prefix) + segment, rid, re.I) is None
                                            or rid.rsplit("/", 1)[-1] in (".", "..")
                                            or str(row.get("type", "")).casefold() != "microsoft.network/virtualnetworkgateways"
                                            or "name" in row and str(row["name"]).casefold() != rid.rsplit("/", 1)[-1].casefold()
                                            or rid.casefold() in seen):
                                        raise ValueError("foreign, duplicate or malformed native VPN gateway identity")
                                    seen.add(rid.casefold())
                                yield page
                jobs.append(("virtual_network_gateway", scope, "Microsoft.Network", gateways))
        # Discovery supplies IDs; ARM GET provides authoritative current details.
        child_dependencies = {"batch_pool": "batch_account", "subnet": "vnet", "vnet_peering": "vnet", "storage_service": "storage_account", "sql_database": "sql_server", "sql_firewall_rule": "sql_server", "sql_audit": "sql_server", "sql_security": "sql_server", "secret_metadata": "vault", "dns_record": "dns_zone", "private_dns_link": "private_dns_zone", "app_service_config": "app_service", "app_service_identity_detail": "app_service", "sql_tde": "sql_server", "managed_identity_federated_credential": "managed_identity", "key_metadata": "vault", "key_rotation_policy": "vault", "key_vault_certificate_policy": "vault", "sql_vulnerability_assessment": "sql_server", "sql_encryption_protector": "sql_server", "storage_container": "storage_account", "storage_encryption_scope": "storage_account", "app_service_slot": "app_service", "automation_variable": "automation_account", "apim_native": "api_management"}
        parents = wanted.intersection(ENDPOINTS) | {parent for child, parent in child_dependencies.items() if child in wanted}
        parents |= azure_network_catalog.required_parents(wanted)
        if "diagnostic_setting" in wanted:
            parents |= set(ENDPOINTS) - {"resource_group"}
        # These requested inventories already have an authoritative LIST+GET
        # producer above. Keep generic discovery only when they are implicit
        # parents of another requested inventory (for example diagnostics).
        parents -= wanted.intersection(azure_containerapp_jobs.NATIVE_TYPES)
        # Broad collection: one authoritative ARM list of every tracked resource
        # per subscription proves which provider lists are empty, so ~70 list
        # reads per subscription shrink to the types actually present. A failed
        # or partial index falls back to listing every kind for that subscription.
        present_types = {}
        if len(parents - RESOURCE_INDEX_EXEMPT) >= RESOURCE_INDEX_MIN_KINDS:
            def resource_index(scope):
                types = set()
                for page in reader.pages(request, ARM + scope + "/resources?api-version=2021-04-01&$top=1000"):
                    for item in page:
                        rid, rtype = (item.get("id"), item.get("type")) if isinstance(item, dict) else (None, None)
                        if not isinstance(rid, str) or not rid.lower().startswith(scope.lower() + "/") or not isinstance(rtype, str) or not rtype:
                            raise ValueError("malformed subscription resource index")
                        types.add(rtype.lower())
                return types
            def index_or_none(scope):
                try:
                    return scope, resource_index(scope)
                except Exception:
                    return scope, None
            with ThreadPoolExecutor(max_workers=reader.workers) as pool:
                present_types = {scope: types for scope, types in pool.map(index_or_none, scopes) if types is not None}
        for scope in scopes:
            for kind in sorted(parents):
                endpoint, version = ENDPOINTS[kind]
                if scope in present_types and kind not in RESOURCE_INDEX_EXEMPT and endpoint.lower() not in present_types[scope]:
                    reader.collections.append({"type": kind, "scope": scope, "service": endpoint.split("/")[0], "status": "empty", "items": [],
                                               "_provenance": {"empty_basis": "arm_subscription_resource_list", "read_only": True}})
                    continue
                url = ARM + scope + ("/" if kind == "resource_group" else "/providers/") + endpoint + "?api-version=" + version
                def detail(url=url, version=version, scope=scope, kind=kind):
                    incomplete = None
                    # ARG is eventually consistent. Only an authoritative ARM
                    # list can establish membership or an empty inventory.
                    seen_easm = set()
                    remaining_service_seen = {}
                    assessment_captures = {}
                    def assessment_list_request(page_url, *, body=None, audience=ARM):
                        # Capture when transport first returns this page, not when
                        # a later cache consumer processes the old response.
                        key = (audience, page_url, json.dumps(body, sort_keys=True) if body is not None else None)
                        with cache_guard:
                            page_lock = cache_locks.setdefault(key, threading.Lock())
                        with page_lock:
                            if key not in cache:
                                cache[key] = transport.request(page_url, body=body, audience=audience)
                                assessment_captures[key] = datetime.now(timezone.utc).isoformat()
                            elif key not in assessment_captures:
                                raise AzureReadError('assessment_list_cached_without_capture')
                            response = cache[key]
                            observed_at = assessment_captures[key]
                        if not isinstance(response, dict) or not isinstance(response.get('value'), list):
                            return response
                        proof = {'source_operation': 'Assessments_List', 'read_only': True,
                                 'observed_at': observed_at, 'api_version': version,
                                 'representation': 'metadata', 'scope': scope,
                                 'credential_context_id': credential_context_id,
                                 'customer_context_id': customer_context_id}
                        return {**response, 'value': [
                            {**item, '_provenance': dict(proof)} if isinstance(item, dict) else item
                            for item in response['value']]}
                    def policy_assignment_list_request(page_url, *, body=None, audience=ARM):
                        # Only an unfiltered List for this selected subscription can
                        # establish that a returned management-group row applies here.
                        parts = urlsplit(page_url)
                        query = parse_qsl(parts.query, keep_blank_values=True)
                        keys = [key.casefold() for key, _ in query]
                        if (body is not None or audience != ARM or
                                parts.path.casefold() != (scope + '/providers/Microsoft.Authorization/policyAssignments').casefold() or
                                [value for key, value in query if key.casefold() == 'api-version'] != [version] or
                                any(key.lstrip('$') in ('filter', 'top') for key in keys)):
                            raise ValueError('policy assignment List source binding unavailable')
                        return request(page_url, body=body, audience=audience)
                    page_request = (assessment_list_request if kind == 'security_assessment' else
                                    policy_assignment_list_request if kind == 'policy_assignment' else request)
                    policy_list_proof = {'source_operation': 'PolicyAssignments_List', 'api_version': version,
                                         'read_only': True, 'selected_scope': scope, 'filter': None,
                                         'request_path': scope + '/providers/Microsoft.Authorization/policyAssignments'}
                    def bound_policy_row(row):
                        if kind != 'policy_assignment':
                            return row
                        if '_native_policy_assignment_list' in row:
                            raise ValueError('conflicting policy assignment List source marker')
                        return {**row, '_native_policy_assignment_list': dict(policy_list_proof)}
                    for page in reader.pages(page_request, url):
                        planned = []
                        for item in page:
                            rid = item.get("id") if isinstance(item, dict) else None
                            if not isinstance(rid, str) or not _policy_assignment_scope_allowed(kind, scope, rid):
                                raise ValueError("resource outside selected subscription")
                            _arm_parent_native_type(item, kind)
                            _network_platform_native_identity(item, scope, kind)
                            _database_crypto_parent_identity(item, scope, kind)
                            if not _remaining_service_parent_identity(item, scope, kind, remaining_service_seen):
                                continue
                            _remaining_services_private_links(item, kind)
                            if kind in ("security_contact", "security_setting", "security_assessment", "log_analytics_workspace") and str(item.get("type", "")).casefold() not in ((ENDPOINTS[kind][0].casefold(), "microsoft.security/securitycontact") if kind == "security_contact" else (ENDPOINTS[kind][0].casefold(),)):
                                raise ValueError("native monitoring type differs from selected inventory")
                            if kind in ("easm_workspace", "monitor_log_profile", "arc_kubernetes_cluster", "integration_service_environment", "databricks_workspace"):
                                identity = rid.casefold()
                                native_type = ENDPOINTS[kind][0].casefold()
                                if identity in seen_easm or (str(item.get("type", "")).casefold() not in ((native_type, '') if kind == 'monitor_log_profile' else (native_type,))):
                                    raise ValueError("duplicate or malformed selected Azure identity")
                                seen_easm.add(identity)
                            managed_app_fields = ("managedResourceGroupId", "publisherTenantId", "managementMode", "authorizations", "provisioningState")
                            managed_app_complete = (kind != "managed_application" or all(
                                key in item["properties"] for key in managed_app_fields)) if isinstance(item.get("properties"), dict) else False
                            powerbi_complete = (kind != "powerbi_capacity" or isinstance(
                                item["properties"].get("administration"), dict) and isinstance(
                                item["properties"]["administration"].get("members"), list)) if isinstance(item.get("properties"), dict) else False
                            if isinstance(item.get("properties"), dict) and managed_app_complete and powerbi_complete and kind != "container_group" and kind not in FULL_GET_KINDS and kind != "stream_analytics_job":
                                planned.append((True, bound_policy_row(azure_swc.list_detail(item, kind))))
                                continue
                            planned.append((False, item))
                        def read_detail(item):
                            rid = item["id"]
                            detail_url = ARM + rid + "?api-version=" + version
                            if kind == "vm":
                                detail_url += "&$expand=instanceView"
                            if kind == "databox_job":
                                detail_url += "&$expand=details"
                            result = reader.call(request, detail_url)
                            if not isinstance(result, dict) or str(result.get("id", "")).lower() != rid.lower() or (kind in FULL_GET_KINDS and not isinstance(result.get("properties"), dict)):
                                raise ValueError("malformed resource detail")
                            _arm_parent_native_type(result, kind)
                            _network_platform_native_identity(result, scope, kind)
                            if kind in ("vm", "nsg", "storage_account", "container_group", "vm_scale_set", "security_pricing") and str(result.get("type", "")).casefold() != ENDPOINTS[kind][0].casefold():
                                raise ValueError("native resource detail type differs from selected inventory")
                            if kind == "security_pricing" and str(result.get("name", "")).casefold() != rid.rsplit("/", 1)[-1].casefold():
                                raise ValueError("native pricing detail name differs from selected identity")
                            _database_crypto_parent_identity(result, scope, kind)
                            _remaining_service_parent_identity(result, scope, kind)
                            _remaining_services_private_links(result, kind)
                            if kind in FULL_GET_KINDS:
                                result = azure_swc.full_detail(result, kind, version)
                            if kind == "mongo_cluster":
                                result = azure_mongo_cluster_metadata.project(result)
                            if kind in ("frontdoor", "cdn_profile"):
                                result = azure_frontdoor_native.metadata_projection(result)
                            result = azure_swc.list_detail(result, kind)
                            result = azure_native_contract_closure_20261020.metadata_detail(result, kind, scope, version)
                            return bound_policy_row(result)
                        # Per-resource detail GETs are independent: run them bounded in
                        # parallel and settle rows in list order, so evidence and the
                        # surfaced (last) incomplete error match the serial read.
                        fetched = iter(ordered_parallel(reader, read_detail, [value for done, value in planned if not done]))
                        detailed = []
                        for done, value in planned:
                            if done:
                                detailed.append(value)
                                continue
                            ok, result = next(fetched)
                            if ok:
                                detailed.append(result)
                                continue
                            exc, item, rid = result, value, value["id"]
                            incomplete = exc
                            detailed.append({"id": rid, "type": item.get("type"), "name": item.get("name"), "detail": {"collection_status": _safe_error(exc)[0], "error": _safe_error(exc)[1]}})
                        yield detailed
                    if incomplete:
                        raise incomplete
                jobs.append((kind, scope, endpoint.split("/")[0], detail))
            if "activity_log" in wanted:
                # ActivityLogs_List accepts an inclusive upper comparator.
                # Filter its boundary event locally to retain our half-open window.
                url = ARM + scope + "/providers/Microsoft.Insights/eventtypes/management/values?" + urlencode({"api-version": "2015-04-01", "$filter": f"eventTimestamp ge '{start}' and eventTimestamp le '{end}'", "$select": ACTIVITY_SELECT})
                def activities(url=url, scope=scope):
                    seen_events = {}
                    upper_bound = datetime.fromisoformat(end)
                    for page_number, page in enumerate(reader.pages(request, url)):
                        retained = []
                        for item in page:
                            timestamp = item.get("eventTimestamp") if isinstance(item, dict) else None
                            if isinstance(timestamp, str):
                                try:
                                    observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                                except ValueError:
                                    observed = None  # Existing coverage validation rejects malformed timestamps.
                                if observed is not None and observed.tzinfo is not None and observed.utcoffset() is not None:
                                    if observed > upper_bound:
                                        raise ValueError("Activity Log event beyond native query window")
                                    if observed == upper_bound:
                                        continue
                            if isinstance(item, dict) and not item.get("id") and item.get("eventDataId"):
                                item["id"] = "azure-activity://" + quote(scope, safe="") + "/" + quote(item["eventDataId"], safe="")
                            if "activity_log_coverage" in wanted and isinstance(item, dict):
                                event_id = item.get('id')
                                if not isinstance(event_id, str):
                                    raise ValueError('missing native Activity Log identity')
                                digest = hashlib.sha256(json.dumps(item, sort_keys=True, separators=(',', ':')).encode()).digest()
                                previous = seen_events.get(event_id)
                                if previous is not None:
                                    if previous[0] == digest and previous[1] != page_number:
                                        continue  # Exact overlap across native continuation pages.
                                    raise ValueError('conflicting or duplicate native Activity Log identity')
                                seen_events[event_id] = (digest, page_number)
                            retained.append(item)
                        yield retained
                jobs.append(("activity_log", scope, "Microsoft.Insights", activities))
        reader.run(jobs)
        for collection in reader.collections:
            if collection["type"] == "activity_log":
                collection["queryWindow"] = {"start": start, "end": end, "endExclusive": True}
                collection['native_query_provenance'] = {'source_operation': 'ActivityLogs_List',
                    'api_version': '2015-04-01', 'read_only': True}
        azure_wave_change_native.collect(reader, scopes, wanted)
        azure_public_edge_native.collect(reader, request, scopes, wanted)
        azure_nsg_ingress_native.collect(reader, request, transport, scopes, wanted, options)
        azure_swc.collect_facts(reader, request, wanted, scopes, options)
        azure_frontdoor_native.collect(reader, request, scopes, wanted)
        if "key_vault_certificate" in wanted:
            azure_swc.collect_current_certificates(reader, request, scopes, getattr(transport, "allow_vault", None))
        azure_certificate_issuance_native.collect(reader, scopes, wanted)
        if "key_vault_certificate_current" in wanted:
            azure_swc.collect_current_certificates(reader, request, scopes, getattr(transport, "allow_vault", None),
                                                   kind="key_vault_certificate_current")
        azure_swc.collect_defender_pricing(reader, request, scopes, wanted)
        jobs = []
        for collection in list(reader.collections):
            for item in collection["items"]:
                rid = item["id"]
                kind = collection["type"]
                if kind in parents and "diagnostic_setting" in wanted and kind not in NO_DIAGNOSTIC_KINDS:
                    url = ARM + rid + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
                    operation = (lambda url=url, rid=rid: _vault_diagnostic_settings_pages(reader, request, url, rid)) if kind in ("vault", "managed_hsm") else (lambda url=url: reader.pages(request, url))
                    if kind in ("application_gateway", "load_balancer"):
                        operation = lambda url=url, rid=rid: _service_diagnostic_settings_pages(reader, request, url, rid)
                    jobs.append(("diagnostic_setting", rid, "Microsoft.Insights", operation))
                if kind == "vnet":
                    for child, field in (("subnet", "subnets"), ("vnet_peering", "virtualNetworkPeerings")):
                        if child in wanted:
                            def embedded(item=item, field=field, child=child):
                                value = item.get("properties", {}).get(field)
                                if not isinstance(value, list):
                                    raise ValueError("missing child detail")
                                prefix = item["id"].lower() + "/" + field.lower() + "/"
                                for reference in value:
                                    child_id = reference.get("id") if isinstance(reference, dict) else None
                                    if not isinstance(child_id, str) or not child_id.lower().startswith(prefix):
                                        raise ValueError("malformed child identity")
                                    detail = reader.call(request, ARM + child_id + "?api-version=" + ENDPOINTS["vnet"][1])
                                    if (not isinstance(detail, dict) or str(detail.get("id", "")).lower() != child_id.lower() or
                                        not isinstance(detail.get("properties"), dict)):
                                        raise ValueError("malformed child detail")
                                    _network_platform_native_identity(detail, "/".join(item["id"].split("/")[:3]), child)
                                    yield [azure_swc.full_detail(detail, child, ENDPOINTS["vnet"][1])]
                                if not value:
                                    yield []
                            jobs.append((child, rid, "Microsoft.Network", embedded))
                child_paths = []
                if kind == "storage_account" and "storage_service" in wanted:
                    for service in ("blobServices", "fileServices", "queueServices", "tableServices"):
                        child_scope = rid + "/" + service
                        url = ARM + child_scope + "/default?api-version=2023-05-01"
                        def storage_config(url=url, child_scope=child_scope):
                            detail = reader.call(request, url)
                            expected_type = "microsoft.storage/storageaccounts/" + child_scope.rsplit("/", 1)[-1].casefold()
                            if (not isinstance(detail, dict) or str(detail.get("id", "")).lower() != (child_scope + "/default").lower()
                                    or str(detail.get("type", "")).casefold() != expected_type
                                    or not isinstance(detail.get("properties"), dict)):
                                raise ValueError("malformed storage service metadata")
                            yield [detail]
                        jobs.append(("storage_service", child_scope, "Microsoft.Storage", storage_config))
                if kind == "sql_server":
                    child_paths.extend((child, path, "2023-08-01") for child, path in (("sql_database", "databases"), ("sql_firewall_rule", "firewallRules"), ("sql_audit", "auditingSettings"), ("sql_security", "securityAlertPolicies")) if child in wanted)
                if kind == "vault" and "key_metadata" in wanted:
                    def vault_keys(item=item, rid=rid):
                        origin = _bound_vault_metadata_origin(item, rid)
                        if hasattr(transport, "allow_vault"):
                            transport.allow_vault(origin)
                        parsed = urlsplit(origin)
                        seen = {}
                        for page in reader.pages(request, origin + "/keys?api-version=2025-07-01", audience=VAULT):
                            safe = []
                            for key in page:
                                kid = key.get("kid") if isinstance(key, dict) else None
                                identity = urlsplit(kid) if isinstance(kid, str) else None
                                parts = identity.path.strip("/").split("/") if identity else []
                                if identity is None or identity.scheme != "https" or ((identity.hostname or "").lower(), identity.port or 443) != ((parsed.hostname or "").lower(), parsed.port or 443) or identity.username or identity.password or identity.query or identity.fragment or len(parts) != 2 or parts[0] != "keys" or not re.fullmatch(r"[A-Za-z0-9-]{1,127}", parts[1]):
                                    raise ValueError("malformed or foreign key metadata identity")
                                attrs = key.get("attributes")
                                if not isinstance(attrs, dict):
                                    raise ValueError("malformed key attributes")
                                projected = {"id": rid + "/keys/" + parts[1], "type": "Microsoft.KeyVault/vaults/keys", "name": parts[1], "parent_id": rid,
                                             "vaultProperties": {key: value for key, value in item.get("properties", {}).items() if key == "enableRbacAuthorization"}, "data_plane_id": origin + "/keys/" + parts[1], "properties": {"attributes": {field: value for field, value in attrs.items() if field in ("enabled", "exp", "nbf", "created", "updated", "recoverableDays", "recoveryLevel")}},
                                             "_provenance": {"endpoint": "keys/list", "audience": VAULT, "read_only": True}}
                                identity = projected['id'].casefold()
                                if identity in seen:
                                    if seen[identity] != projected:
                                        raise ValueError('conflicting native key metadata identity')
                                    continue
                                seen[identity] = projected
                                safe.append(projected)
                            yield safe
                    jobs.append(("key_metadata", rid, "Microsoft.KeyVault", vault_keys))
                if kind == "vault" and "key_vault_certificate_policy" in wanted:
                    def certificates(item=item, rid=rid):
                        uri = item.get("properties", {}).get("vaultUri")
                        if not isinstance(uri, str) or not re.fullmatch(r"https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/?", uri):
                            raise ValueError("malformed certificate vault endpoint")
                        if hasattr(transport, "allow_vault"): transport.allow_vault(uri)
                        origin = uri.rstrip("/")
                        for page in reader.pages(request, origin + "/certificates?api-version=7.4", audience=VAULT):
                            safe = []
                            for certificate in page:
                                cid = certificate.get("id") if isinstance(certificate, dict) else None
                                if not isinstance(cid, str) or not re.fullmatch(re.escape(origin) + r"/certificates/[A-Za-z0-9-]{1,127}", cid):
                                    raise ValueError("malformed or foreign certificate identity")
                                policy = reader.call(request, cid + "/policy?api-version=7.4", audience=VAULT)
                                if not isinstance(policy, dict) or not isinstance(policy.get("x509_props"), dict):
                                    raise ValueError("malformed certificate policy")
                                safe.append({"id": rid + "/certificates/" + cid.rsplit("/", 1)[-1] + "/policy", "parent_id": rid,
                                             "x509_props": {key: value for key, value in policy["x509_props"].items() if key == "validity_months"},
                                             "_provenance": {"endpoint": "certificates/policy/get", "audience": VAULT, "read_only": True}})
                            yield safe
                    jobs.append(("key_vault_certificate_policy", rid, "Microsoft.KeyVault", certificates))
                if kind == "vault" and "secret_metadata" in wanted:
                    # ARM metadata listing remains an alternative for thin vault
                    # records; a native vault URI uses the documented data-plane
                    # list operation, which returns attributes and no values.
                    uri = item.get("properties", {}).get("vaultUri")
                    if uri is None:
                        child_paths.append(("secret_metadata", "secrets", "2023-07-01"))
                    else:
                        def secrets(item=item, rid=rid, uri=uri):
                            origin = _bound_vault_metadata_origin(item, rid)
                            if hasattr(transport, "allow_vault"): transport.allow_vault(origin)
                            for page in reader.pages(request, origin + "/secrets?api-version=2025-07-01", audience=VAULT):
                                safe = []
                                for secret in page:
                                    sid = secret.get("id") if isinstance(secret, dict) else None
                                    parsed = urlsplit(sid) if isinstance(sid, str) else None
                                    parts = parsed.path.strip("/").split("/") if parsed else []
                                    if parsed is None or parsed.scheme != "https" or (parsed.hostname or "").lower() != urlsplit(origin).hostname.lower() or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.query or parsed.fragment or len(parts) != 2 or parts[0] != "secrets" or not re.fullmatch(r"[A-Za-z0-9-]{1,127}", parts[1]):
                                        raise ValueError("malformed or foreign secret metadata identity")
                                    attrs = secret.get("attributes")
                                    if not isinstance(attrs, dict): raise ValueError("malformed secret attributes")
                                    safe.append({"id": rid + "/secrets/" + parts[1], "parent_id": rid, "type": "Microsoft.KeyVault/vaults/secrets", "name": parts[1],
                                                 "data_plane_id": origin + "/secrets/" + parts[1], "properties": {"attributes": {key: value for key, value in attrs.items() if key in ("enabled", "exp", "nbf", "created", "updated", "recoverableDays", "recoveryLevel")}},
                                                 "vaultProperties": {key: value for key, value in item.get("properties", {}).items() if key == "enableRbacAuthorization"},
                                                 "_provenance": {"endpoint": "secrets/list", "audience": VAULT, "read_only": True}})
                                yield safe
                        jobs.append(("secret_metadata", rid, "Microsoft.KeyVault", secrets))
                if kind == "dns_zone" and "dns_record" in wanted:
                    child_paths.append(("dns_record", "all", "2018-05-01"))
                if kind == "private_dns_zone" and "private_dns_link" in wanted:
                    child_paths.append(("private_dns_link", "virtualNetworkLinks", "2020-06-01"))
                if kind == "managed_identity" and "managed_identity_federated_credential" in wanted:
                    child_paths.append(("managed_identity_federated_credential", "federatedIdentityCredentials", "2025-05-31-preview"))
                if kind == "app_service" and "app_service_identity_detail" in wanted:
                    jobs.append(azure_appservice_identity_followup.site_identity_job(reader, request, ARM, item))
                if kind == "app_service" and "app_service_config" in wanted:
                    url = ARM + rid + "/config/web?api-version=2023-12-01"
                    def app_config(url=url, rid=rid):
                        detail = reader.call(request, url)
                        if (not isinstance(detail, dict) or not isinstance(detail.get("id"), str) or
                                detail["id"].casefold() != (rid + "/config/web").casefold() or
                                not isinstance(detail.get("type"), str) or
                                detail["type"].casefold() != "microsoft.web/sites/config"):
                            raise ValueError("malformed App Service configuration")
                        props = detail.get("properties")
                        if not isinstance(props, dict):
                            raise ValueError("malformed App Service configuration properties")
                        safe_fields = APP_CONFIG_FIELDS
                        yield [{**{k: v for k, v in detail.items() if k in ("id", "name", "type", "location")}, "properties": {k: v for k, v in props.items() if k in safe_fields}, "parent_id": rid}]
                    jobs.append(("app_service_config", rid, "Microsoft.Web", app_config))
                for child, path, version in child_paths:
                    url = ARM + rid + "/" + path + "?api-version=" + version
                    # One storage collection per account, not duplicate service scopes.
                    child_scope = rid + "/" + path if child == "storage_service" else rid
                    fetch = lambda url=url: reader.pages(request, url)
                    if kind == "sql_server" and child in ("sql_database", "sql_firewall_rule", "sql_audit", "sql_security"):
                        fetch = lambda url=url, rid=rid, child=child, path=path: _sql_projected_child_pages(reader, request, url, rid, child, path)
                    jobs.append((child, child_scope, ENDPOINTS[kind][0].split("/")[0], fetch))
        reader.run(jobs)
        jobs = []
        if options.get("_azure_app_service_runtime_checks") == ["azure.review.app_service.runtime_support_declared"]:
            from . import azure_app_service_runtime_producer_20261021
            azure_app_service_runtime_producer_20261021.collect_selected(
                reader, transport.request, scopes, list(reader.collections))
        if "key_rotation_policy" in wanted:
            for collection in [c for c in reader.collections if c["type"] == "key_metadata"]:
                if collection["status"] not in ("collected", "empty"):
                    reader.collections.append({"type": "key_rotation_policy", "scope": collection["scope"], "service": "Microsoft.KeyVault", "status": collection["status"], "items": [], "error": {"code": "parent_keys_unavailable"}})
                    continue
                if not collection["items"]:
                    reader.collections.append({"type": "key_rotation_policy", "scope": collection["scope"], "service": "Microsoft.KeyVault", "status": "empty", "items": []})
                for key in collection["items"]:
                    rid, endpoint = key["id"], key["data_plane_id"]
                    def key_policy(rid=rid, endpoint=endpoint):
                        policy = reader.call(request, endpoint + "/rotationpolicy?api-version=2025-07-01", audience=VAULT)
                        if not isinstance(policy, dict):
                            raise ValueError("malformed key rotation policy")
                        pid = policy.get("id")
                        if pid is not None and (not isinstance(pid, str) or pid.lower() != (endpoint + "/rotationpolicy").lower()):
                            raise ValueError("foreign key rotation policy")
                        yield [{"id": rid + "/rotationpolicy", "type": "Microsoft.KeyVault/vaults/keys/rotationpolicy", "parent_id": rid,
                                "properties": {field: value for field, value in policy.items() if field in ("lifetimeActions", "attributes")},
                                "_provenance": {"endpoint": "keys/rotationpolicy/get", "audience": VAULT, "read_only": True}}]
                    jobs.append(("key_rotation_policy", rid, "Microsoft.KeyVault", key_policy))
        if "sql_tde" in wanted:
            for c in reader.collections:
                if c["type"] != "sql_database":
                    continue
                for database in c["items"]:
                    rid = database["id"]
                    if rid.rsplit("/", 1)[-1].lower() == "master":
                        continue
                    url = ARM + rid + "/transparentDataEncryption/current?api-version=2023-08-01"
                    def tde(url=url, rid=rid):
                        detail = reader.call(request, url)
                        if (not isinstance(detail, dict)
                                or str(detail.get("id", "")).casefold() not in (rid.casefold(), (rid + "/transparentDataEncryption/current").casefold())
                                or str(detail.get("id", "")).casefold() == rid.casefold() and (
                                    str(detail.get("name", "")).casefold() != "current"
                                    or str(detail.get("type", "")).casefold() != "microsoft.sql/servers/databases/transparentdataencryption")
                                or "type" in detail and str(detail["type"]).casefold() != "microsoft.sql/servers/databases/transparentdataencryption"
                                or "name" in detail and str(detail["name"]).casefold() != "current"
                                or not isinstance(detail.get("properties"), dict)):
                            raise ValueError("malformed SQL TDE metadata")
                        yield [{**detail, "parent_id": rid}]
                    jobs.append(("sql_tde", rid, "Microsoft.Sql", tde))
            reader.run(jobs)
            jobs = []
        if jobs:
            reader.run(jobs)
            jobs = []
        vaults_by_id = {item["id"].lower(): item for collection in reader.collections if collection["type"] == "vault" for item in collection["items"]}
        key_by_id = {item["id"].lower(): item for collection in reader.collections if collection["type"] == "key_metadata" for item in collection["items"]}
        for collection in reader.collections:
            _normalize_vault_expiration(collection, vaults_by_id)
            if collection["type"] == "secret_metadata":
                for item in collection["items"]:
                    parent = vaults_by_id.get(collection["scope"].lower())
                    if parent is not None:
                        item["vaultProperties"] = {key: value for key, value in parent.get("properties", {}).items() if key == "enableRbacAuthorization"}
            elif collection["type"] == "key_rotation_policy":
                key = key_by_id.get(collection["scope"].lower())
                if key is not None:
                    key.setdefault("properties", {}).setdefault("_coverage", {})["rotationPolicy"] = {field: collection[field] for field in ("status", "error") if field in collection}
                    if collection["status"] == "collected" and len(collection["items"]) == 1:
                        key["properties"]["rotationPolicy"] = collection["items"][0]["properties"]
        embedded_parents = [(collection["type"], item) for collection in reader.collections for item in collection["items"]
                            if collection["type"] in set(ENDPOINTS) | {"sql_database", "storage_service"} and collection["type"] != "resource_group" and isinstance(item.get("properties"), dict)
                            and not (functions_native_only and collection["type"] in ("app_service", "app_service_plan"))]
        known_diagnostics = {collection["scope"].casefold(): collection for collection in reader.collections if collection["type"] == "diagnostic_setting"}
        if "apim_native" in wanted:
            reader.collections.extend(collect_apim(reader, request, reader.collections))
        # Basic-auth policies are only read when sites themselves were requested,
        # not when app_service is merely the parent of app_service_config.
        skipped_embeds = set() if "app_service" in wanted or "app_service_slot" in wanted else {"scmBasicAuthPolicy", "ftpBasicAuthPolicy"}
        # LTR copies may span many pages. Only their declared consumer needs
        # that inventory; short-term backup checks must not enumerate it.
        if "sql_ltr_backup" not in wanted:
            skipped_embeds.add("longTermRetentionBackups")
        if "batch_pool" not in wanted:
            skipped_embeds.add("pools")
        _embed(reader, request, embedded_parents, known_diagnostics, skipped_embeds)
        azure_cost_exports_native.collect(reader, request, scopes, wanted)
        azure_managed_application_definitions_native.collect(reader, request, wanted)
        azure_attestation_native.collect(reader, request, scopes, wanted)
        azure_domain_services_native.collect(reader, request, scopes, wanted)
        azure_defender_automations_native.collect(reader, request, scopes, wanted)
        _collect_managed_application_jit(reader, request, embedded_parents)
        _collect_servicebus_entity_rules(reader, request, embedded_parents)
        _collect_gallery_versions(reader, request, embedded_parents)
        if "managed_hsm" in wanted:
            _collect_hsm_local_assignments(reader, request, transport, embedded_parents)
        azure_swc.collect_nested_metadata(reader, request, embedded_parents)
        azure_network_catalog.collect_children(reader, request, scopes, wanted)
        azure_swc.collect_diagnostic_categories(reader, request, embedded_parents, scopes, wanted)
        azure_swc.collect_vm_instance_views(reader, request, embedded_parents)
        azure_wave_compute_native.collect(reader, request, scopes, wanted, options)
        from .azure_guest_reports import collect_reports
        collect_reports(reader, request, scopes, wanted)
        from .azure_guest_configuration_native import collect as collect_guest_baselines
        collect_guest_baselines(reader, request, scopes, wanted, options)
        azure_database_native.collect(reader, request, scopes, wanted, options)
        azure_swc.collect_mysql_configurations(reader, scopes, wanted)
        azure_swc.mark_unresolved_bot_keys(reader, scopes, wanted)
        registry_jobs = []
        for kind, item in embedded_parents:
            if kind != "container_registry" or "virtualNetworkRules" in item.get("properties", {}).get("networkRuleSet", {}): continue
            rid = item["id"]
            def registry_rules(rid=rid):
                value = reader.call(request, ARM + rid + "?api-version=2023-11-01-preview")
                if not isinstance(value, dict) or str(value.get("id", "")).lower() != rid.lower():
                    raise ValueError("malformed registry preview metadata")
                rules = value.get("properties", {}).get("networkRuleSet", {}).get("virtualNetworkRules")
                if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
                    raise ValueError("registry virtual-network metadata absent")
                yield [{"id": rid + "/virtualNetworkRules", "rules": rules}]
            registry_jobs.append((item, ("registry_vnet_rules", rid, "Microsoft.ContainerRegistry", registry_rules)))
        with ThreadPoolExecutor(max_workers=reader.workers) as pool:
            for (item, _), read in zip(registry_jobs, pool.map(reader._read, [job[1] for job in registry_jobs])):
                nrs = item.setdefault("properties", {}).setdefault("networkRuleSet", {})
                nrs.setdefault("_coverage", {})["virtualNetworkRules"] = {key: read[key] for key in ("status", "error") if key in read}
                if read["status"] == "collected": nrs["virtualNetworkRules"] = read["items"][0]["rules"]
        synapse_jobs = []
        for kind, item in embedded_parents:
            if kind != "synapse_workspace": continue
            rid = item["id"]
            def synapse_assessments(item=item, rid=rid):
                if item.get("_coverage", {}).get("sqlPools", {}).get("status") not in ("collected", "empty"):
                    raise AzureReadError("parent_sql_pools_unavailable")
                seen = {}
                for pool in item["sqlPools"]:
                    pid = pool["id"]
                    for page in reader.pages(request, ARM + pid + "/vulnerabilityAssessments?api-version=2021-06-01"):
                        distinct = []
                        for row in _child_rows(page, pid, "sqlVulnerabilityAssessments"):
                            key = row["id"].casefold()
                            if key in seen:
                                if seen[key] != row:
                                    raise ValueError("conflicting SQL vulnerability assessment identity")
                                continue
                            seen[key] = row
                            distinct.append(row)
                        yield distinct
            synapse_jobs.append((item, ("synapse_assessments", rid, "Microsoft.Synapse", synapse_assessments)))
        with ThreadPoolExecutor(max_workers=reader.workers) as pool:
            for (item, _), read in zip(synapse_jobs, pool.map(reader._read, [job[1] for job in synapse_jobs])):
                item.setdefault("_coverage", {})["sqlVulnerabilityAssessments"] = {key: read[key] for key in ("status", "error") if key in read}
                if read["status"] in ("collected", "empty"):
                    item["sqlVulnerabilityAssessments"] = read["items"]
        azure_application_compute_2_native.collect_synapse_sql_private_endpoints(reader, request, reader.collections, wanted)
        azure_acr_public_ip_review_20261020.collect(reader, request, scopes, wanted)
        azure_automation_aci_metadata_native_20261020.collect(reader, request, scopes, wanted)
        azure_devtestlab_native.collect(reader, request, scopes, wanted)
        # Authoritative parent gathers reduce to one complete subscription scope.
        derived = {
            "flow_log": ("network_watcher", "flowLogs"), "backup_protected_item": ("recovery_vault", "backupProtectedItems"), "backup_policy": ("recovery_vault", "backupPolicies"), "backup_job": ("recovery_vault", "backupJobs"),
            "storage_container": ("storage_account", "blobContainers"), "storage_encryption_scope": ("storage_account", "encryptionScopes"),
            "storage_local_user": ("storage_account", "localUsers"), "eventgrid_subscription": ("storage_account", "eventSubscriptions"),
            "sql_backup_short_term_policy": ("sql_database", "backupShortTermRetentionPolicies"),
            "sql_database_ltr_policy": ("sql_database", "backupLongTermRetentionPolicies"), "sql_ltr_backup": ("sql_database", "longTermRetentionBackups"), "sql_restore_point": ("sql_database", "restorePoints"), "sql_vulnerability_assessment": ("sql_server", "vulnerabilityAssessment"), "sql_encryption_protector": ("sql_server", "encryptionProtector"),
            "managed_instance_database": ("mssql_managed_instance", "databases"),
            "app_service_slot": ("app_service", "slots"), "automation_variable": ("automation_account", "variables"),
            "batch_pool": ("batch_account", "pools"),
        }
        for output, (parent_kind, field) in derived.items():
            if output not in wanted:
                continue
            for scope in scopes:
                sources = [row for row in reader.collections if row["type"] == parent_kind and (row["scope"].lower() == scope.lower() or row["scope"].lower().startswith(scope.lower() + "/"))]
                if not sources:
                    if parent_kind == 'sql_database':
                        servers = [row for row in reader.collections if row['type'] == 'sql_server' and row['scope'].casefold() == scope.casefold()]
                        if servers and all(row['status'] == 'empty' and not row['items'] for row in servers):
                            reader.collections.append({'type': output, 'scope': scope, 'service': service_for('azure', output, service_for('azure', parent_kind)), 'status': 'empty', 'items': [], 'parent_inventory': 'sql_server'})
                            continue
                    reader.collections.append({"type": output, "scope": scope, "service": service_for('azure', output, service_for('azure', parent_kind)), "status": "not_collected", "items": []})
                    continue
                states, items = [], []
                for source in sources:
                    states.append(source["status"])
                    for parent in source["items"]:
                        coverage = parent.get("_coverage", {}).get(field, {})
                        states.append(coverage.get("status", "not_collected"))
                        child = parent.get(field)
                        values = child if isinstance(child, list) else [child] if isinstance(child, dict) else []
                        for value in values:
                            item = {**value, "parent_id": parent["id"]}
                            if output == "sql_vulnerability_assessment":
                                express = parent.get("expressVulnerabilityAssessment")
                                if isinstance(express, dict): item["expressVulnerabilityAssessment"] = express
                                else: item.setdefault("_coverage", {})["expressVulnerabilityAssessment"] = parent.get("_coverage", {}).get("expressVulnerabilityAssessment", {"status": "not_collected"})
                            items.append(item)
                bad = next((state for state in states if state not in ("collected", "empty")), None)
                status = "partial" if bad and items else bad if bad else "collected" if items else "empty"
                reader.collections.append({"type": output, "scope": scope, "service": service_for('azure', output, service_for('azure', parent_kind)), "status": status, "items": items,
                                           **({"error": {"code": "parent_inventory_incomplete"}} if bad else {})})
        if "app_service_slot" in wanted:
            slot_parents = [("app_service_slot", item) for collection in reader.collections
                            if collection["type"] == "app_service_slot" for item in collection["items"]
                            if isinstance(item.get("properties"), dict)]
            _embed(reader, request, slot_parents)
        azure_swc.collect_managed_instance_tde(reader, request, scopes, wanted)
        storage_jobs = []
        for collection in reader.collections:
            if collection["type"] != "storage_account": continue
            for item in collection["items"]:
                rid = item["id"]
                account = rid.rsplit("/", 1)[-1]
                for service in ("blob", "queue", "table"):
                    diag_url = ARM + rid + "/" + service + "Services/default/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
                    def service_diagnostics(diag_url=diag_url, rid=rid):
                        for page in reader.pages(request, diag_url):
                            yield _child_rows(page, rid, "serviceDiagnosticSettings")
                    storage_jobs.append((item, "serviceDiagnosticSettings", service, ("storage_diagnostics_" + service, rid, "Microsoft.Insights", service_diagnostics)))
                    endpoint = item.get("properties", {}).get("primaryEndpoints", {}).get(service)
                    def analytics(endpoint=endpoint, account=account, service=service, rid=rid):
                        if not isinstance(endpoint, str) or not re.fullmatch('https://' + re.escape(account) + r'\.' + service + r'\.core\.windows\.net/?', endpoint, re.I):
                            raise ValueError("storage endpoint absent or invalid")
                        if not hasattr(transport, "request_xml") or not hasattr(transport, "allow_storage"):
                            raise AzureReadError("storage_oauth_metadata_unavailable")
                        transport.allow_storage(endpoint, account, service)
                        value = reader.call(transport.request_xml, endpoint.rstrip("/") + "/?restype=service&comp=properties")
                        if not isinstance(value, dict) or any(type(value.get(key)) is not bool for key in ("read", "write", "delete")):
                            raise ValueError("malformed storage logging metadata")
                        yield [{"id": rid + "/" + service + "Services/default/analytics", **value}]
                    storage_jobs.append((item, "serviceAnalyticsLogging", service, ("storage_analytics_" + service, rid, "Microsoft.Storage", analytics)))
        with ThreadPoolExecutor(max_workers=reader.workers) as pool:
            for (item, field, service, _), read in zip(storage_jobs, pool.map(reader._read, [job[3] for job in storage_jobs])):
                parent = item.setdefault(field, {})
                parent.setdefault("_coverage", {})[service] = {key: read[key] for key in ("status", "error") if key in read}
                if read["status"] in ("collected", "empty"):
                    parent[service] = read["items"] if field == "serviceDiagnosticSettings" else {key: read["items"][0][key] for key in ("read", "write", "delete")}
        if "key_vault_key" in wanted:
            for collection in [row for row in reader.collections if row["type"] == "key_metadata"]:
                reader.collections.append({**collection, "type": "key_vault_key"})
        tenant_scope = "/tenants/" + (getattr(transport, "tenant", None) or auth.get("tenant_id") or "selected")
        for kind, endpoint in DIRECTORY.items():
            if kind in wanted:
                url = GRAPH + "/v1.0/" + endpoint
                if kind == "directory_audit":
                    url += "?" + urlencode({"$filter": f"activityDateTime ge {start} and activityDateTime le {end}"})
                def directory_rows(url=url, kind=kind):
                    failure = None
                    seen_graph = set()
                    try:
                        for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
                            if kind == "user_registration_detail":
                                for row in page:
                                    identity = row.get("id") if isinstance(row, dict) else None
                                    if (not isinstance(identity, str) or re.fullmatch(
                                            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", identity) is None):
                                        raise ValueError("malformed native user registration GUID")
                            if kind == 'named_location':
                                for row in page:
                                    azure_remaining_services_1_native.graph_identity(kind, row)
                            if kind in azure_agent_identity_native.ENDPOINTS:
                                page = [azure_agent_identity_native.project(kind, row) for row in page]
                                for row in page:
                                    if row["id"].casefold() in seen_graph:
                                        raise ValueError("duplicate Graph agent identity")
                                    seen_graph.add(row["id"].casefold())
                            if kind in ("directory_application", "directory_service_principal", "directory_user",
                                        "directory_group", "user_registration_detail", "directory_role_assignment",
                                        "directory_role_definition", azure_entitlement_native.PARENT,
                                        azure_entitlement_native.CATALOG, azure_entitlement_native.ROLE_ASSIGNMENT,
                                        "directory_role_eligibility_schedule",
                                        "directory_role_eligibility_instance", "directory_role_assignment_instance"):
                                for row in page:
                                    rid = row.get("id") if isinstance(row, dict) else None
                                    if not isinstance(rid, str) or not rid or rid.casefold() in seen_graph:
                                        raise ValueError("malformed or duplicate Graph principal identity")
                                    seen_graph.add(rid.casefold())
                            yield [{**row, "_provenance": {"tenant_id": getattr(transport, "tenant", None), "tenant_verified": bool(getattr(transport, "verified_tenant", None)), "endpoint": urlsplit(url).path, "read_only": True}} if isinstance(row, dict) else row for row in page]
                        return
                    except Exception as exc:
                        if (kind != "directory_user" or _status_code(exc) not in (400, 403, "400", "403")
                                or seen_graph):
                            raise
                        failure = _safe_error(exc)
                    base_url = url.replace(",signInActivity", "").replace("&$top=500", "&$top=999")
                    for page in reader.pages(request, base_url, audience=GRAPH, next_key="@odata.nextLink"):
                        for row in page:
                            rid = row.get("id") if isinstance(row, dict) else None
                            if not isinstance(rid, str) or not rid or rid.casefold() in seen_graph:
                                raise ValueError("malformed or duplicate Graph principal identity")
                            seen_graph.add(rid.casefold())
                        yield [{**row, "_coverage": {**row.get("_coverage", {}), "signInActivity": {"status": failure[0], "error": failure[1]}},
                                "_provenance": {"tenant_id": getattr(transport, "tenant", None), "tenant_verified": bool(getattr(transport, "verified_tenant", None)), "endpoint": urlsplit(base_url).path, "read_only": True}} if isinstance(row, dict) else row for row in page]
                jobs.append((kind, tenant_scope, "Microsoft.Graph", directory_rows))
        for kind, endpoint in DIRECTORY_SINGLETONS.items():
            if kind in wanted:
                url = GRAPH + "/v1.0/" + endpoint
                def singleton(url=url, kind=kind):
                    value = reader.call(request, url, audience=GRAPH)
                    if not isinstance(value, dict) or not value.get("id"):
                        raise ValueError("malformed directory singleton metadata")
                    if kind == 'authentication_methods_policy':
                        azure_remaining_services_1_native.graph_identity(kind, value)
                    yield [{**value, "_provenance": {"tenant_id": tenant_scope.removeprefix("/tenants/"), "endpoint": urlsplit(url).path, "read_only": True}}]
                jobs.append((kind, tenant_scope, "Microsoft.Graph", singleton))
        if "directory_cba_configuration" in wanted:
            def cba_configuration():
                # Organization.Read.All: the tenant CBA trust store. Public CA
                # certificates are dropped by _metadata_only ("certificate");
                # issuer, SKI, root flag and CRL locations remain.
                organizations = []
                for page in reader.pages(request, GRAPH + "/v1.0/organization?$select=id", audience=GRAPH, next_key="@odata.nextLink"):
                    organizations.extend(page)
                if len(organizations) != 1 or not isinstance(organizations[0], dict) or not isinstance(organizations[0].get("id"), str) or not organizations[0]["id"]:
                    raise ValueError("malformed organization metadata")
                org_id = organizations[0]["id"]
                url = GRAPH + "/v1.0/organization/" + quote(org_id, safe="") + "/certificateBasedAuthConfiguration"
                for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
                    rows = []
                    for row in page:
                        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not isinstance(row.get("certificateAuthorities", []), list):
                            raise ValueError("malformed certificate-based authentication configuration")
                        rows.append({"id": row["id"], "organizationId": org_id,
                                     "certificateAuthorities": [{key: data for key, data in authority.items() if key in ("isRootAuthority", "issuer", "issuerSki", "certificateRevocationListUrl", "deltaCertificateRevocationListUrl")} if isinstance(authority, dict) else authority for authority in row.get("certificateAuthorities", [])],
                                     "_provenance": {"tenant_id": tenant_scope.removeprefix("/tenants/"), "endpoint": urlsplit(url).path, "read_only": True}})
                    yield rows
            jobs.append(("directory_cba_configuration", tenant_scope, "Microsoft.Graph", cba_configuration))
        reader.run(jobs)
        azure_entitlement_native.collect(reader, request, wanted, tenant_scope, GRAPH)
        for aggregate_kind, parent_kind in (("application_scope", "directory_application"),
                                             ("service_principal_scope", "directory_service_principal")):
            if aggregate_kind not in wanted:
                continue
            # Synthetic evaluation subject binds a complete Graph tenant inventory,
            # including a legitimately empty one, to one resource finding.
            parents = [c for c in reader.collections if c["type"] == parent_kind]
            verified = bool(getattr(transport, "verified_tenant", None))
            tenant = getattr(transport, "tenant", None)
            parent = parents[0] if len(parents) == 1 else None
            status = parent["status"] if parent is not None else "unknown"
            if not verified or not isinstance(tenant, str) or parent is None or parent["scope"].casefold() != ("/tenants/" + tenant).casefold():
                status = "unknown"
            suffix = "applicationScope" if aggregate_kind == "application_scope" else "servicePrincipalScope"
            item = {"id": "/tenants/" + tenant + "/" + suffix, "parent_scope": "/tenants/" + tenant,
                    "member_count": len(parent["items"]),
                    "_provenance": {"source_collection": parent_kind, "tenant_id": tenant,
                                    "tenant_verified": True, "read_only": True}} if status in ("collected", "empty") else None
            reader.collections.append({"type": aggregate_kind, "scope": "/tenants/" + tenant if isinstance(tenant, str) else "/tenants/selected",
                                       "service": "Microsoft.Graph", "status": "collected" if item else status,
                                       "items": [item] if item else [],
                                       "parent_inventory": parent_kind,
                                       **({"error": parent["error"]} if item is None and parent is not None and "error" in parent else {})})
        object_collections = {kind: [item for c in reader.collections if c["type"] == kind for item in c["items"]]
                              for kind in ("directory_application", "directory_service_principal", "directory_group", "directory_administrative_unit")}
        for kind, endpoint in (("directory_group_eligibility_schedule", "eligibilitySchedules"),
                               ("directory_group_eligibility_instance", "eligibilityScheduleInstances")):
            if kind not in wanted:
                continue
            jobs = []
            for group in object_collections["directory_group"]:
                group_id = group.get("id")
                if not isinstance(group_id, str) or not group_id:
                    continue
                query = urlencode({"$filter": f"groupId eq '{group_id}'"})
                url = GRAPH + "/v1.0/identityGovernance/privilegedAccess/group/" + endpoint + "?" + query
                def eligibility_rows(url=url, group_id=group_id):
                    for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
                        for row in page:
                            if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                                    or str(row.get("groupId", "")).casefold() != group_id.casefold()
                                    or not isinstance(row.get("principalId"), str)
                                    or str(row.get("accessId", "")).casefold() not in ("member", "owner")):
                                raise ValueError("malformed or cross-group PIM eligibility")
                        yield page
                jobs.append((kind, tenant_scope + "/groups/" + group_id, "Microsoft.Graph", eligibility_rows))
            reader.run(jobs)
            parents = [c for c in reader.collections if c["type"] == "directory_group" and c["scope"] == tenant_scope]
            parent_states = {c["status"] for c in parents}
            if not parents or not parent_states <= {"collected", "empty"}:
                reader.collections.append({"type": kind, "scope": tenant_scope, "service": "Microsoft.Graph",
                                           "status": "not_collected" if not parents else next(iter(sorted(parent_states - {"collected", "empty"}))),
                                           "items": [], "error": {"code": "parent_inventory_unavailable"}, "parent_inventory": "directory_group"})
            elif not jobs:
                reader.collections.append({"type": kind, "scope": tenant_scope, "service": "Microsoft.Graph",
                                           "status": "empty", "items": [], "parent_inventory": "directory_group"})
        if "directory_role_pim_policy" in wanted:
            query = urlencode({"$filter": "scopeId eq '/' and scopeType eq 'DirectoryRole'",
                               "$expand": "policy($expand=rules)"})
            url = GRAPH + "/v1.0/policies/roleManagementPolicyAssignments?" + query
            def role_policy_rows():
                for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
                    for row in page:
                        if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                                or row.get("scopeId") != "/"
                                or str(row.get("scopeType", "")).casefold() not in ("directoryrole", "directory")
                                or not isinstance(row.get("roleDefinitionId"), str)
                                or not isinstance(row.get("policy"), dict)):
                            raise ValueError("malformed directory PIM policy assignment")
                    yield page
            reader.run([("directory_role_pim_policy", tenant_scope, "Microsoft.Graph", role_policy_rows)])
        for policy_kind, access_id in (("directory_group_pim_policy", "member"),
                                       ("directory_group_pim_owner_policy", "owner")):
            if policy_kind not in wanted:
                continue
            jobs = []
            for group in object_collections["directory_group"]:
                group_id = group.get("id")
                if not isinstance(group_id, str) or not group_id:
                    continue
                query = urlencode({"$filter": f"scopeId eq '{group_id}' and scopeType eq 'Group' and roleDefinitionId eq '{access_id}'",
                                   "$expand": "policy($expand=rules)"})
                url = GRAPH + "/v1.0/policies/roleManagementPolicyAssignments?" + query
                def policy_rows(url=url, group_id=group_id, access_id=access_id):
                    for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
                        for row in page:
                            if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                                    or str(row.get("scopeId", "")).casefold() != group_id.casefold()
                                    or str(row.get("roleDefinitionId", "")).casefold() != access_id
                                    or not isinstance(row.get("policy"), dict)):
                                raise ValueError("malformed or cross-group PIM policy assignment")
                        yield page
                jobs.append((policy_kind, tenant_scope + "/groups/" + group_id,
                             "Microsoft.Graph", policy_rows))
            reader.run(jobs)
            parents = [c for c in reader.collections if c["type"] == "directory_group" and c["scope"] == tenant_scope]
            parent_states = {c["status"] for c in parents}
            if not parents or not parent_states <= {"collected", "empty"}:
                reader.collections.append({"type": policy_kind, "scope": tenant_scope,
                                           "service": "Microsoft.Graph", "status": "not_collected" if not parents else next(iter(sorted(parent_states - {"collected", "empty"}))),
                                           "items": [], "error": {"code": "parent_inventory_unavailable"}, "parent_inventory": "directory_group"})
            elif not jobs:
                reader.collections.append({"type": policy_kind, "scope": tenant_scope,
                                           "service": "Microsoft.Graph", "status": "empty", "items": [], "parent_inventory": "directory_group"})
        from . import azure_graph_batch
        graph_batching = (getattr(transport, "graph_batch", False) is True
                          and not reader.explicit_limits)
        if "directory_owner" in wanted or "directory_administrative_unit_member" in wanted:
            jobs, graph_urls = [], []
            owner_types = (("directory_application", "applications", "application"),
                           ("directory_service_principal", "servicePrincipals", "servicePrincipal"),
                           ("directory_group", "groups", "group"))
            for parent_kind, endpoint, object_type in owner_types:
                if "directory_owner" not in wanted:
                    break
                for parent in object_collections[parent_kind]:
                    object_id = parent["id"]
                    url = GRAPH + "/v1.0/" + endpoint + "/" + quote(object_id, safe="") + "/owners?$select=id"
                    graph_urls.append(url)
                    def owners(url=url, object_id=object_id, object_type=object_type):
                        owner_ids = []
                        try:
                            for page in reader.pages(graph_request, url, audience=GRAPH, next_key="@odata.nextLink"):
                                if any(not isinstance(owner, dict) or not isinstance(owner.get("id"), str) or not owner["id"] for owner in page):
                                    raise ValueError("malformed directory owner metadata")
                                owner_ids.extend(owner["id"] for owner in page)
                        except Exception as exc:
                            if owner_ids:
                                yield [{"id": object_id, "objectId": object_id, "objectType": object_type, "ownerIds": list(dict.fromkeys(owner_ids)),
                                        "_coverage": {"ownerIds": {"status": "partial", "error": _safe_error(exc)[1]}},
                                        "_provenance": {"tenant_id": tenant_scope.removeprefix("/tenants/"), "endpoint": urlsplit(url).path, "read_only": True}}]
                            raise
                        yield [{"id": object_id, "objectId": object_id, "objectType": object_type, "ownerIds": list(dict.fromkeys(owner_ids)),
                                "_provenance": {"tenant_id": tenant_scope.removeprefix("/tenants/"), "endpoint": urlsplit(url).path, "read_only": True}}]
                    jobs.append(("directory_owner", tenant_scope + "/" + endpoint + "/" + object_id, "Microsoft.Graph", owners))
            if "directory_administrative_unit_member" in wanted:
                for unit in object_collections["directory_administrative_unit"]:
                    object_id = unit["id"]
                    url = GRAPH + "/v1.0/directory/administrativeUnits/" + quote(object_id, safe="") + "/members?$select=id"
                    graph_urls.append(url)
                    def members(url=url, object_id=object_id):
                        for page in reader.pages(graph_request, url, audience=GRAPH, next_key="@odata.nextLink"):
                            if any(not isinstance(member, dict) or not isinstance(member.get("id"), str) for member in page):
                                raise ValueError("malformed administrative unit membership")
                            yield [{**member, "administrativeUnitId": object_id,
                                    "_provenance": {"tenant_id": tenant_scope.removeprefix("/tenants/"), "endpoint": urlsplit(url).path, "read_only": True}} for member in page]
                    jobs.append(("directory_administrative_unit_member", tenant_scope + "/administrativeUnits/" + object_id, "Microsoft.Graph", members))
            with azure_graph_batch.first_pages(reader, transport, request, graph_urls, enabled=graph_batching) as graph_request:
                reader.run(jobs)
            # Privesc reads directory_administrative_unit.memberIds. Only a complete
            # member read sets it; denied/partial leaves it absent (unknown, not empty).
            member_reads = {c["scope"].rsplit("/", 1)[-1]: c for c in reader.collections if c["type"] == "directory_administrative_unit_member"}
            for unit in object_collections["directory_administrative_unit"]:
                read = member_reads.get(unit["id"])
                if read is None:
                    continue
                unit.setdefault("_coverage", {})["memberIds"] = {key: read[key] for key in ("status", "error") if key in read}
                if read["status"] in ("collected", "empty"):
                    unit["memberIds"] = list(dict.fromkeys(member["id"] for member in read["items"]))
        if "directory_federated_credential" in wanted:
            # Application.Read.All: one bounded, paginated read per collected
            # application. Each envelope is that application's complete (or
            # denied/partial) FIC list; issuer/subject/audiences carry no secret.
            jobs, graph_urls = [], []
            for application in object_collections["directory_application"]:
                object_id = application.get("id")
                if not isinstance(object_id, str) or not object_id:
                    continue
                url = GRAPH + "/v1.0/applications/" + quote(object_id, safe="") + "/federatedIdentityCredentials?$select=id,name,issuer,subject,audiences"
                graph_urls.append(url)
                def credentials(url=url, object_id=object_id, app_id=application.get("appId")):
                    for page in reader.pages(graph_request, url, audience=GRAPH, next_key="@odata.nextLink"):
                        rows = []
                        for row in page:
                            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
                                raise ValueError("malformed federated identity credential")
                            rows.append({key: data for key, data in row.items() if key in ("name", "issuer", "subject", "audiences")} | {
                                "id": "applications/" + object_id + "/federatedIdentityCredentials/" + row["id"], "credentialId": row["id"],
                                "applicationObjectId": object_id, "appId": app_id,
                                "_provenance": {"tenant_id": tenant_scope.removeprefix("/tenants/"), "endpoint": urlsplit(url).path, "read_only": True}})
                        yield rows
                jobs.append(("directory_federated_credential", tenant_scope + "/applications/" + object_id, "Microsoft.Graph", credentials))
            with azure_graph_batch.first_pages(reader, transport, request, graph_urls, enabled=graph_batching) as graph_request:
                reader.run(jobs)
            parents = [c for c in reader.collections if c["type"] == "directory_application"]
            parent_states = {c["status"] for c in parents}
            if not parents or not parent_states <= {"collected", "empty"}:
                # Without the complete application list, absence of FICs is unknown.
                reader.collections.append({"type": "directory_federated_credential", "scope": tenant_scope, "service": "Microsoft.Graph",
                                           "status": "not_collected" if not parents else next(iter(sorted(parent_states - {"collected", "empty"}))),
                                           "items": [], "error": {"code": "parent_inventory_unavailable"}, "parent_inventory": "directory_application"})
            elif not jobs:
                reader.collections.append({"type": "directory_federated_credential", "scope": tenant_scope, "service": "Microsoft.Graph",
                                           "status": "empty", "items": [], "parent_inventory": "directory_application"})
        if "directory_app_role_assignment" in wanted:
            resources = {sp["id"]: sp for sp in object_collections["directory_service_principal"]}
            cache_lock = threading.Lock()
            def role_metadata(resource_id):
                with cache_lock:
                    cached = resources.get(resource_id)
                    if cached is not None and (isinstance(cached.get("appRoles"), list) or cached.get("collection_status")):
                        return cached
                    try:
                        url = GRAPH + "/v1.0/servicePrincipals/" + quote(resource_id, safe="") + "?$select=id,appId,appRoles"
                        cached = reader.call(request, url, audience=GRAPH)
                        if not isinstance(cached, dict) or cached.get("id") != resource_id or not isinstance(cached.get("appRoles"), list):
                            raise ValueError("malformed resource service principal roles")
                    except Exception as exc:
                        cached = {"id": resource_id, "collection_status": _safe_error(exc)[0], "error": _safe_error(exc)[1]}
                    resources[resource_id] = cached
                    return cached
            jobs, graph_urls = [], []
            for principal in object_collections["directory_service_principal"]:
                principal_id = principal["id"]
                url = GRAPH + "/v1.0/servicePrincipals/" + quote(principal_id, safe="") + "/appRoleAssignments"
                graph_urls.append(url)
                def assignments(url=url, principal_id=principal_id):
                    for page in reader.pages(graph_request, url, audience=GRAPH, next_key="@odata.nextLink"):
                        enriched = []
                        for assignment in page:
                            if not isinstance(assignment, dict) or assignment.get("principalId") != principal_id or not all(isinstance(assignment.get(key), str) for key in ("id", "resourceId", "appRoleId")):
                                raise ValueError("malformed or cross-principal app role assignment")
                            row = {**assignment, "_provenance": {"tenant_id": tenant_scope.removeprefix("/tenants/"), "endpoint": urlsplit(url).path,
                                                                  "appRoleValue_source": "resource servicePrincipal.appRoles", "effective_access": "not_computed"}}
                            if assignment["appRoleId"] == "00000000-0000-0000-0000-000000000000":
                                row.update(appRoleValue=None, defaultAppRole=True)
                            else:
                                resource = role_metadata(assignment["resourceId"])
                                roles = resource.get("appRoles", [])
                                matches = [role for role in roles if isinstance(role, dict) and role.get("id") == assignment["appRoleId"]]
                                if len(matches) == 1 and isinstance(matches[0].get("value"), str):
                                    row.update(appRoleValue=matches[0]["value"], appRoleEnabled=matches[0].get("isEnabled"))
                                else:
                                    row["_coverage"] = {"appRoleValue": {"status": resource.get("collection_status", "unknown"), "reason": "resource role metadata denied, missing or ambiguous"}}
                            enriched.append(row)
                        yield enriched
                jobs.append(("directory_app_role_assignment", tenant_scope + "/servicePrincipals/" + principal_id, "Microsoft.Graph", assignments))
            with azure_graph_batch.first_pages(reader, transport, request, graph_urls, enabled=graph_batching) as graph_request:
                reader.run(jobs)
        if "directory_membership" in wanted:
            jobs, graph_urls = [], []
            # Graph v1.0 omits service-principal group members. Exposure scans
            # need the documented beta workaround to see outside SP grantees.
            member_version = "beta" if "role_assignment" in wanted else "v1.0"
            for c in reader.collections:
                if c["type"] == "directory_group":
                    for group in c["items"]:
                        url = GRAPH + "/" + member_version + "/groups/" + quote(group["id"], safe="") + "/members?$select=id"
                        graph_urls.append(url)
                        jobs.append(("directory_membership", tenant_scope + "/groups/" + group["id"], "Microsoft.Graph", lambda url=url: reader.pages(graph_request, url, audience=GRAPH, next_key="@odata.nextLink")))
            with azure_graph_batch.first_pages(reader, transport, request, graph_urls, enabled=graph_batching) as graph_request:
                reader.run(jobs)
            unresolved_groups = {group["id"] for group in object_collections["directory_group"]
                                 if "DynamicMembership" in group.get("groupTypes", []) or group.get("visibility") == "HiddenMembership"}
            for collection in reader.collections:
                if collection["type"] == "directory_membership" and collection["scope"].rsplit("/", 1)[-1] in unresolved_groups and collection["status"] in ("collected", "empty"):
                    collection.update(status="partial", error={"code": "dynamic_or_hidden_membership_unresolved"})
            group_parents = [c for c in reader.collections if c["type"] == "directory_group" and c["scope"] == tenant_scope]
            parent_states = {c["status"] for c in group_parents}
            if not group_parents or not parent_states <= {"collected", "empty"}:
                reader.collections.append({"type": "directory_membership", "scope": tenant_scope,
                                           "service": "Microsoft.Graph",
                                           "status": "not_collected" if not group_parents else next(iter(sorted(parent_states - {"collected", "empty"}))),
                                           "items": [], "error": {"code": "parent_inventory_unavailable"},
                                           "parent_inventory": "directory_group"})
            elif not jobs:
                reader.collections.append({"type": "directory_membership", "scope": tenant_scope,
                                           "service": "Microsoft.Graph", "status": "empty",
                                           "items": [], "parent_inventory": "directory_group"})
        from .azure_detection_telemetry import collect as collect_detection_telemetry
        from .azure_resource_diagnostics_native import collect as collect_resource_diagnostics
        collect_resource_diagnostics(reader, request, scopes, wanted)
        azure_secret_versions_native.collect(reader, transport, scopes, wanted)
        azure_vault_key_versions_native.collect(reader, transport, scopes, wanted)
        azure_assessment_criteria_native.collect(reader, request, scopes, wanted, options)
        azure_function_limits_native.collect(reader, request, scopes, wanted, options)
        azure_functions_runtime_native.collect(reader, request, scopes, wanted,
            tenant_id=getattr(transport, "tenant", None) or auth.get("tenant_id"),
            tenant_verified=bool(getattr(transport, "verified_tenant", None)))
        azure_sentinel_metadata_native.collect(reader, request, scopes, wanted)
        azure_incident_inventory_native.collect(reader, scopes, wanted)
        azure_iot_policy_native.collect(reader, request, scopes, wanted, options)
        azure_storage_recovery_metadata_native.collect(reader, request, scopes, wanted, options)
        azure_storage_lifecycle_native.collect(reader, request, scopes, wanted, options)
        azure_key_rotation_evidence_native.collect(reader, scopes, wanted)
        azure_storage_backup_native.collect(reader, request, scopes, wanted)
        azure_arm_metadata_native.collect(reader, request, scopes, wanted)
        azure_monitor_inventory_native.collect(reader, request, scopes, wanted)
        azure_aks_workloads_native.collect(reader, request, transport, scopes, wanted, options, auth)
        azure_aks_legacy_projection_review_20261020.collect_diagnostics(reader, request, scopes, wanted)
        azure_aks_legacy_projection_review_20261020.collect_hsm_categories(reader, request, scopes, wanted)
        azure_databricks_native.collect(reader, request, transport, scopes, wanted, options, auth)
        azure_devops_git_native.collect(reader, request, transport, scopes, wanted, options, auth)
        azure_devops_pipeline_native.collect(reader, request, transport, scopes, wanted, options, auth)
        from .azure_docker_assessment_native import collect as collect_docker_assessment_metadata
        collect_docker_assessment_metadata(reader, request, scopes, wanted, credential_context_id, customer_context_id)
        azure_defender_network_native.collect(reader, request, scopes, wanted)
        azure_adaptive_network_native.collect(reader, request, scopes, wanted)
        azure_conditional_access_native.collect(reader, request, wanted, transport)
        azure_access_reviews_native.collect(reader, request, wanted, transport)
        azure_identity_intune_native.collect(reader, request, scopes, wanted, transport)
        if requirements is None or "directory_user" in requirements:
            from . import azure_sw18_mfa_native
            azure_sw18_mfa_native.collect(reader, request, wanted, transport,
                                         credential_context_id, customer_context_id)
        from .azure_entra_diagnostics_native import collect as collect_entra_diagnostics
        collect_entra_diagnostics(reader, request, scopes, wanted, transport)
        from .azure_apim_diagnostics_native import collect as collect_apim_diagnostics
        collect_apim_diagnostics(reader, request, scopes, wanted, options)
        azure_storage_blob_keys_native.collect(reader, request, transport, scopes, wanted, options)
        azure_audit_storage_native.collect(reader, request, scopes, wanted, options)
        azure_security_correlation_native.collect(reader, request, scopes, wanted, options)
        collect_detection_telemetry(reader, request, scopes, wanted, options,
                                    verified_tenant=getattr(transport, "verified_tenant", None))
        if package_grant is not None:
            package_source.collect(reader, transport, package_grant, scopes,
                customer_context_id=customer_context_id, credential_context_id=credential_context_id)
        if auto_container_literals:
            from . import workload_environment_discovery as environment_discovery
            container_plan = environment_discovery.azure_containers(reader.collections, expected_scopes=scopes)
            reader.automatic_container_literal_batches = []
            container_redactions = set()
            if container_plan.targets:
                for scope in scopes:
                    targets = [t for t in container_plan.targets
                        if azure_selected_configuration_secret_indicators.parse(t)[1].casefold() == scope.casefold()]
                    for batch in environment_discovery.batches(targets, 8):
                        azure_selected_configuration_secret_indicators.collect(reader, transport, [scope], wanted,
                            {**options, azure_selected_configuration_secret_indicators.OPTION: list(batch)})
                        batch_id = azure_selected_configuration_secret_indicators.KIND + ':' + str(
                            len(reader.automatic_container_literal_batches) + 1)
                        reader.collections[-1]['automatic_batch'] = batch_id
                        reader.automatic_container_literal_batches.append({'id': batch_id, 'scope': scope,
                            'metadata': reader.configuration_secret_metadata.copy(),
                            'issues': environment_discovery.native_denial_issues(
                                azure_selected_configuration_secret_indicators.KIND,
                                azure_selected_configuration_secret_indicators.MARKER,
                                reader.collections[-1]['items'], reader.configuration_secret_metadata)})
                        container_redactions.update(reader.configuration_secret_redactions)
                reader.configuration_secret_redactions = container_redactions
                environment_discovery.fold_collections(reader.collections,
                    azure_selected_configuration_secret_indicators.KIND,
                    reader.automatic_container_literal_batches)
            else:
                reader.configuration_secret_redactions = set()
                reader.configuration_secret_metadata = {}
                for scope in scopes:
                    reader.collections.append({'type': azure_selected_configuration_secret_indicators.KIND,
                        'scope': scope, 'service': 'Microsoft.Resources', 'items': [],
                        'status': 'empty' if container_plan.complete else 'unknown',
                        **({} if container_plan.complete else {'error': {'code': container_plan.reason}})})
            container_content_complete = True
            for row in reader.collections:
                if row['type'] == azure_selected_configuration_secret_indicators.KIND:
                    if row['status'] not in ('collected', 'empty'):
                        container_content_complete = False
                    if any(not item.get(azure_selected_configuration_secret_indicators.MARKER, {}).get('complete')
                           for item in row['items']):
                        container_content_complete = False
            reader.automatic_container_literal_coverage = {'discovered': container_plan.discovered,
                'planned': len(container_plan.targets),
                'inspected': sum(len(r['items']) for r in reader.collections if r['type'] == azure_selected_configuration_secret_indicators.KIND),
                'targets': environment_discovery.target_coverage(container_plan.targets,
                    azure_selected_configuration_secret_indicators.identity, reader.collections,
                    azure_selected_configuration_secret_indicators.KIND,
                    azure_selected_configuration_secret_indicators.MARKER,
                    {ident: issue for batch in reader.automatic_container_literal_batches
                     for ident, issue in batch['issues'].items()}),
                'complete': container_plan.complete and container_content_complete,
                'reason': container_plan.reason if not container_plan.complete else
                          'automatic_content_incomplete' if not container_content_complete else 'complete'}
        else:
            azure_selected_configuration_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_selected_declaration_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_selected_log_sample_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_ml_selected_job_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_databricks_notebook_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_synapse_selected_notebook_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_ml_selected_asset_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_function_settings_declarations_20261020.collect(reader, transport, scopes, wanted, options,
            named_checks=function_checks, credential_context_id=credential_context_id, customer_context_id=customer_context_id)
        azure_selected_storage_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_flex_deployment_archives_20261021.collect(reader, transport, scopes, wanted, options)
        azure_devops_selected_content_secret_indicators.collect(reader, request, transport, scopes, wanted, options, auth)
        if auto_app_settings:
            from . import workload_environment_discovery as environment_discovery
            settings_plan = environment_discovery.azure_settings(reader.collections, expected_scopes=scopes)
            reader.automatic_app_settings_batches = []
            app_redactions = set()
            if settings_plan.targets:
                for scope in scopes:
                    targets = [t for t in settings_plan.targets
                        if azure_app_settings_secret_indicators._RESOURCE.fullmatch(t)[1].casefold() == scope.casefold()]
                    for batch in environment_discovery.batches(targets, 8):
                        azure_app_settings_secret_indicators.collect(reader, transport, [scope], wanted,
                            {**options, azure_app_settings_secret_indicators.OPTION: list(batch)})
                        batch_id = azure_app_settings_secret_indicators.KIND + ':' + str(
                            len(reader.automatic_app_settings_batches) + 1)
                        reader.collections[-1]['automatic_batch'] = batch_id
                        reader.automatic_app_settings_batches.append({'id': batch_id, 'scope': scope,
                            'metadata': reader.app_setting_secret_metadata.copy(),
                            'issues': environment_discovery.native_denial_issues(
                                azure_app_settings_secret_indicators.KIND,
                                azure_app_settings_secret_indicators.MARKER,
                                reader.collections[-1]['items'], reader.app_setting_secret_metadata)})
                        app_redactions.update(reader.app_setting_secret_redactions)
                reader.app_setting_secret_redactions = app_redactions
                environment_discovery.fold_collections(reader.collections,
                    azure_app_settings_secret_indicators.KIND,
                    reader.automatic_app_settings_batches)
            else:
                reader.app_setting_secret_redactions = set()
                reader.app_setting_secret_metadata = {}
                for scope in scopes:
                    reader.collections.append({'type': azure_app_settings_secret_indicators.KIND,
                        'scope': scope, 'service': 'Microsoft.Web', 'items': [],
                        'status': 'empty' if settings_plan.complete else 'unknown',
                        **({} if settings_plan.complete else {'error': {'code': settings_plan.reason}})})
            settings_content_complete = True
            for row in reader.collections:
                if row['type'] == azure_app_settings_secret_indicators.KIND:
                    if row['status'] not in ('collected', 'empty'):
                        settings_content_complete = False
                    if any(not item.get(azure_app_settings_secret_indicators.MARKER, {}).get('complete')
                           for item in row['items']):
                        settings_content_complete = False
            reader.automatic_app_settings_coverage = {'discovered': settings_plan.discovered,
                'planned': len(settings_plan.targets),
                'inspected': sum(len(r['items']) for r in reader.collections if r['type'] == azure_app_settings_secret_indicators.KIND),
                'targets': environment_discovery.target_coverage(settings_plan.targets,
                    azure_app_settings_secret_indicators.identity, reader.collections,
                    azure_app_settings_secret_indicators.KIND,
                    azure_app_settings_secret_indicators.MARKER,
                    {ident: issue for batch in reader.automatic_app_settings_batches
                     for ident, issue in batch['issues'].items()}),
                'complete': settings_plan.complete and settings_content_complete,
                'reason': settings_plan.reason if not settings_plan.complete else
                          'automatic_content_incomplete' if not settings_content_complete else 'complete'}
        else:
            azure_app_settings_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_acr_image_secret_indicators.collect(reader, transport, scopes, wanted, options)
        azure_selected_aks_image_20261021.collect(reader, request, transport, scopes, wanted, options, auth)
        azure_acr_image_vulnerabilities_20261021.collect(reader, transport, scopes, wanted, options)
        azure_ai_services_native.collect(reader, request, scopes, wanted)
        azure_notification_hubs_native.collect(reader, request, scopes, wanted)
        azure_relay_native.collect(reader, request, scopes, wanted)
        azure_lighthouse_native.collect(reader, request, scopes, wanted)
        azure_nginx_native.collect(reader, request, scopes, wanted)
        azure_webpubsub_hubs_native.collect(reader, request, scopes, wanted)
        azure_mongo_cluster_exposure.collect(reader, request, scopes, wanted)
        azure_disclosure_native.collect(reader, transport, scopes, options,
                                        credential_context_id, customer_context_id)
        from .azure_effective_routes_native import collect as collect_effective_routes
        collect_effective_routes(reader, transport, scopes, wanted)
        azure_subnet_firewall_policy.project(reader, scopes, options)
        azure_wave_network_controls.collect(reader, scopes, wanted)
        from .azure_service_tags_native import collect as collect_service_tags
        collect_service_tags(reader, request, scopes, wanted, options)
    except _MetadataOnlyCollection:
        pass  # Continue the same metadata assembly after scope/owner preflight.
    except Exception as exc:
        existing = {(c["type"], c["scope"]) for c in reader.collections}
        for scope in scopes or [tenant_scope]:
            for kind in sorted(wanted):
                if (kind, scope) not in existing:
                    reader.unavailable(kind, scope, "azure", exc)
    finally:
        if owned and transport is not None:
            if function_targets:
                transport.tokens.clear()
                with azure_function_settings_declarations_20261020.private_native_logs():
                    transport.close()
            else:
                transport.close()
    # Complete empty parent lists prove no child instances; denied/partial
    # parents never fabricate an empty child envelope.
    child_parents = {"key_metadata": "vault", "key_vault_key": "vault", "key_rotation_policy": "vault", "key_vault_certificate_policy": "vault", "secret_metadata": "vault",
                     "subnet": "vnet", "vnet_peering": "vnet", "storage_service": "storage_account", "sql_database": "sql_server", "sql_firewall_rule": "sql_server", "sql_audit": "sql_server", "sql_security": "sql_server", "sql_tde": "sql_database",
                     "dns_record": "dns_zone", "private_dns_link": "private_dns_zone", "managed_identity_federated_credential": "managed_identity",
                     "app_service_config": "app_service", "app_service_identity_detail": "app_service"}
    for child, parent in child_parents.items():
        if child not in wanted: continue
        for scope in scopes:
            if any(collection["type"] == child and (collection["scope"].lower() == scope.lower() or collection["scope"].lower().startswith(scope.lower() + "/")) for collection in reader.collections): continue
            sources = [collection for collection in reader.collections if collection["type"] == parent and (collection["scope"].lower() == scope.lower() or collection["scope"].lower().startswith(scope.lower() + "/"))]
            if sources and all(collection["status"] in ("collected", "empty") and not collection["items"] for collection in sources):
                reader.collections.append({"type": child, "scope": scope, "service": service_for('azure', child, service_for('azure', parent)), "status": "empty", "items": [], "parent_inventory": parent})
            elif sources and any(collection["status"] not in ("collected", "empty") for collection in sources):
                state = next(collection["status"] for collection in sources if collection["status"] not in ("collected", "empty"))
                reader.collections.append({"type": child, "scope": scope, "service": service_for('azure', child, service_for('azure', parent)), "status": state, "items": [], "error": {"code": "parent_inventory_unavailable"}})
    if "diagnostic_setting" in wanted:
        _complete_diagnostic_inventory(reader, scopes)
    from .azure_sql_inventory import project as project_sql_inventory
    project_sql_inventory(reader, scopes, wanted)
    authenticated_tenant = getattr(transport, "tenant", None)
    if authenticated_tenant:
        for collection in reader.collections:
            # The ARM tenant record joins the Graph directory facts of the same
            # authenticated tenant; a placeholder scope leaves tenant checks UNKNOWN.
            if (collection["service"] == "Microsoft.Graph" or collection["type"] == "tenant") and collection["scope"].startswith("/tenants/selected"):
                collection["scope"] = collection["scope"].replace("/tenants/selected", "/tenants/" + authenticated_tenant, 1)
            if collection["service"] == "Microsoft.Graph":
                for item in collection["items"]:
                    item.setdefault("_provenance", {}).update(tenant_id=authenticated_tenant, tenant_verified=bool(getattr(transport, "verified_tenant", None)))
    if "entra_user" in wanted:
        reader.collections.extend(azure_entra_user_native.project(
            reader.collections, scopes, tenant_id=authenticated_tenant,
            verified_tenant=getattr(transport, "verified_tenant", None)))
    # Scan-local opaque binding is generated here, never accepted from portable
    # connector input, and is unique across credentials/captures/customers.
    from .azure_unused_iam_20261021 import collect as collect_unused_iam
    collect_unused_iam(reader, request, scopes, wanted, transport, credential_context_id, customer_context_id)
    for collection in reader.collections:
        _bind_service_diagnostic_receipt(collection, reader)
        proof = {"credential_context_id": credential_context_id, "customer_context_id": customer_context_id}
        if collection["service"] == "Microsoft.Graph":
            proof.update(tenant_id=authenticated_tenant, tenant_verified=bool(getattr(transport, "verified_tenant", None)))
        collection.setdefault("_provenance", {}).update(proof)
        for item in collection["items"]:
            item.setdefault("_provenance", {}).update(proof)
        _bind_hsm_diagnostic_context(collection, proof)
    if request is not None:
        azure_identity_enforcement_review_20261020.collect(reader, request, scopes, wanted, transport,
            credential_context_id, customer_context_id)
    metadata = reader.metadata()
    if auto_container_literals or auto_app_settings:
        metadata['automatic_workload_environment_coverage'] = {}
        metadata['automatic_workload_environment_batches'] = {}
        if auto_container_literals:
            metadata['automatic_workload_environment_coverage'][azure_selected_configuration_secret_indicators.KIND] = reader.automatic_container_literal_coverage
            metadata['automatic_workload_environment_batches'][azure_selected_configuration_secret_indicators.KIND] = reader.automatic_container_literal_batches
        if auto_app_settings:
            metadata['automatic_workload_environment_coverage'][azure_app_settings_secret_indicators.KIND] = reader.automatic_app_settings_coverage
            metadata['automatic_workload_environment_batches'][azure_app_settings_secret_indicators.KIND] = reader.automatic_app_settings_batches
    metadata.update(getattr(reader, 'unused_arm_role_metadata', {}))
    metadata.update(getattr(reader, "nsp_query_cmk_metadata", {}))
    metadata.update(getattr(reader, 'configuration_secret_metadata', {}))
    metadata.update(getattr(reader, 'declaration_secret_metadata', {}))
    metadata.update(getattr(reader, 'log_sample_secret_metadata', {}))
    metadata.update(getattr(reader, 'ml_command_job_secret_metadata', {}))
    metadata.update(getattr(reader, 'databricks_notebook_secret_metadata', {}))
    metadata.update(getattr(reader, 'synapse_notebook_secret_metadata', {}))
    metadata.update(getattr(reader, 'ml_asset_secret_metadata', {}))
    metadata.update(getattr(reader, 'function_declaration_metadata', {}))
    metadata.update(getattr(reader, 'storage_source_secret_metadata', {}))
    metadata.update(getattr(reader, 'flex_archive_metadata', {}))
    metadata.update(getattr(reader, 'devops_selected_metadata', {}))
    metadata.update(getattr(reader, 'app_setting_secret_metadata', {}))
    metadata.update(getattr(reader, 'acr_image_secret_metadata', {}))
    metadata.update(getattr(reader, 'azure_aks_image_metadata', {}))
    metadata.update(getattr(reader, 'acr_image_vulnerability_metadata', {}))
    if "security_admin_rule" in wanted:
        admin_rows = [c for c in reader.collections if c["type"] == "security_admin_rule" and c["scope"] in scopes]
        vnet_rows = {c["scope"]: c for c in reader.collections if c["type"] == "vnet" and c["scope"] in scopes}
        complete = len(admin_rows) == len(scopes) and all(c["status"] in {"collected", "empty"} for c in admin_rows)
        for row in admin_rows:
            parents = vnet_rows.get(row["scope"])
            expected = {item["id"].lower() for item in parents["items"]} if parents and parents["status"] in {"collected", "empty"} else None
            observed = {proof.get("resource_id", "").lower() for proof in row.get("source_evidence", [])
                if proof.get("source_operation") == "listNetworkManagerEffectiveSecurityAdminRules"
                and isinstance(proof.get("response_sha256"), str)}
            if expected is None or observed != expected:
                complete = False
        evidence = [{"collection_type": "security_admin_rule", "scope": c["scope"],
            "source_operation": "listNetworkManagerEffectiveSecurityAdminRules",
            "query_proofs": c.get("source_evidence", [])} for c in admin_rows]
        metadata.setdefault("network_context", {}).setdefault("azure", {})["security_admin"] = {
            "status": "collected" if complete else "unknown", "complete": complete,
            "policies": [item["id"] for c in admin_rows for item in c["items"]] if complete else None,
            "source_evidence": evidence}
    accepted_subjects = getattr(transport, 'disclosure_accepted_subjects', {})
    if (options.get('native_disclosure_metadata') and accepted_subjects.get(ARM)
            and accepted_subjects.get(ARM) == accepted_subjects.get(VAULT)):
        metadata['native_disclosure_subject'] = dict(accepted_subjects[ARM])
    if scopes_limited:
        metadata.update(intentional_partial=True, scope_coverage={"status": "partial", "reason": "explicit max_scopes limit", "max_scopes": max_scopes})
    def field_states(value):
        if isinstance(value, dict):
            coverage = value.get("_coverage", {})
            if isinstance(coverage, dict):
                for field in coverage.values():
                    if isinstance(field, dict): yield field.get("status", "unknown")
            for child in value.values(): yield from field_states(child)
        elif isinstance(value, list):
            for child in value: yield from field_states(child)
    directory = [c for c in reader.collections if c["service"] == "Microsoft.Graph"]
    directory_fields_complete = all(state in ("collected", "empty") for collection in directory for state in field_states(collection["items"]))
    def field_limit_reached(value):
        if isinstance(value, dict):
            if isinstance(value.get("_coverage"), dict) and any(isinstance(field, dict) and field.get("error", {}).get("code") in ("resource_limit", "page_limit", "call_limit", "scope_limit", "deadline_exceeded", "collection_cancelled") for field in value["_coverage"].values()):
                return True
            return any(field_limit_reached(child) for child in value.values())
        return any(field_limit_reached(child) for child in value) if isinstance(value, list) else False
    if any(field_limit_reached(collection["items"]) for collection in reader.collections):
        metadata["intentional_partial"] = True
    metadata.update(credential_context_id=credential_context_id, customer_context_id=customer_context_id, context_binding="scan_local", tenant_id=getattr(transport, "tenant", None) or auth.get("tenant_id"), tenant_verified=bool(getattr(transport, "verified_tenant", None)),
                    trusted_scope_ids=trusted_scopes,
                    subscription_tenants={**{item["id"]: item["tenantId"] for collection in reader.collections if collection["type"] == "subscription" for item in collection["items"] if isinstance(item.get("id"), str) and isinstance(item.get("tenantId"), str)}, **getattr(reader, "native_subscription_tenants", {})},
                    directory_coverage={"status": "not_collected" if not directory else "complete" if directory_fields_complete and all(c["status"] in ("collected", "empty") for c in directory) else "incomplete", "types": {c["type"]: c["status"] for c in directory}},
                    authorization_semantics={"effective_access": "not_computed", "control_data_separation": True, "not_actions_are_exclusions": True, "conditions_preserved": True, "management_group_visibility": "accessible_only"},
                    activity_window={"start": start, "end": end, "retention": "unknown", "complete": False, "reason": "provider retention and directory/data-plane events are not verified"},
                    omitted_inventories=sorted(set(TYPES) - wanted))
    metadata["defender_containers_policy"] = _defender_containers_policy(options, scopes, datetime.now(timezone.utc).isoformat())
    metadata["cosmos_backup_retention"] = _cosmos_backup_retention_policy(options, scopes, datetime.now(timezone.utc).isoformat())
    metadata.update(azure_swc.owner_metadata(options, scopes, metadata.get("tenant_id")))
    merge_tls_metadata(metadata, tls_owner)
    for namespace, fields in getattr(reader, "native_aks_workloads_metadata", {}).items():
        if namespace in ("sw25_policy", "sw22"):
            metadata[namespace] = {**metadata.get(namespace, {}), **fields}
        else:
            metadata[namespace] = fields
    if sw15_owner is not None:
        metadata.setdefault("compliance_policy", {})["sw15"] = sw15_owner
    databricks_policy = azure_databricks_native.owner_policy(options, scopes)
    if databricks_policy:
        parent_policy = metadata.setdefault("compliance_policy", {})
        raw_sw33 = options.get("compliance_policy", {}).get("sw33", {})
        merged_sw33 = {**raw_sw33, **parent_policy.get("sw33", {}), **databricks_policy}
        # Preserve independent owner requirements and their original authority;
        # a Databricks approval cannot refresh or rebind another SW33 family.
        for field in ("status", "scope", "observed_at", "max_age_seconds"):
            if field in raw_sw33:
                merged_sw33[field] = raw_sw33[field]
        parent_policy["sw33"] = merged_sw33
    arm_metadata = azure_arm_metadata_native.owner_metadata(reader, options, scopes)
    arm_policy = arm_metadata.pop('compliance_policy', {})
    metadata.update(arm_metadata)
    if arm_policy:
        existing_policy = metadata.get('compliance_policy', {})
        # A new baseline cannot rebind or refresh authority for other checks.
        if 'parameters' in existing_policy or any(key in existing_policy for key in ('status', 'scope', 'observed_at', 'max_age_seconds')):
            for key in ('status', 'scope', 'observed_at', 'max_age_seconds'):
                arm_policy.pop(key, None)
        if 'parameters' in arm_policy:
            arm_policy['parameters'] = {**existing_policy.get('parameters', {}), **arm_policy['parameters']}
        if 'sw27' in arm_policy and isinstance(existing_policy.get('sw27'), dict):
            arm_policy['sw27'] = {**existing_policy['sw27'], **arm_policy['sw27']}
            if 'status' in existing_policy['sw27']:
                arm_policy['sw27']['status'] = existing_policy['sw27']['status']
        metadata['compliance_policy'] = {**existing_policy, **arm_policy}
    from .azure_resource_logging_policy import owner_policy as resource_logging_policy
    logging_policy = resource_logging_policy(options, scopes)
    if logging_policy:
        parent_policy = metadata.get('compliance_policy', {})
        raw_sw16 = options.get('compliance_policy', {}).get('sw16', {})
        raw_sw16 = raw_sw16 if isinstance(raw_sw16, dict) else {}
        metadata['compliance_policy'] = {**parent_policy, 'sw16': {**raw_sw16, **parent_policy.get('sw16', {}), **logging_policy}}
    iot_policy = azure_iot_policy_native.owner_policy(options, scopes)
    if iot_policy:
        parent_policy = metadata.get("compliance_policy", {})
        raw_sw16 = options.get("compliance_policy", {}).get("sw16", {})
        raw_sw16 = raw_sw16 if isinstance(raw_sw16, dict) else {}
        metadata["compliance_policy"] = {**parent_policy, "sw16": {**raw_sw16, **parent_policy.get("sw16", {}), **iot_policy}}
    native_sw32 = getattr(reader, "native_sw32_policy", sw32_owner)
    if native_sw32 is not None:
        metadata["compliance_policy"] = {**metadata.get("compliance_policy", {}), "sw32": native_sw32}
    point_policy = azure_storage_recovery_metadata_native.owner_policy(options, scopes)
    if point_policy:
        parent_policy = metadata.get('compliance_policy', {})
        raw_policy = options.get('compliance_policy', {})
        raw_prior = raw_policy.get('sw13', {}) if isinstance(raw_policy, dict) else {}
        derived_prior = parent_policy.get('sw13', {})
        authority = ('scope','status','authorized_by','document_id','observed_at','expires_at')
        # Bulk evidence merges namespaces shallowly: retain raw siblings and their
        # authority before adding this control. Never refresh/rebind another review.
        if (isinstance(raw_prior, dict) and isinstance(derived_prior, dict) and
                isinstance(raw_prior.get('checks', {}), dict) and isinstance(derived_prior.get('checks', {}), dict)):
            prior = {**raw_prior, **derived_prior}
            prior['checks'] = {**raw_prior.get('checks', {}), **derived_prior.get('checks', {})}
            for key in authority:
                if key in raw_prior:
                    prior[key] = raw_prior[key]
            if not raw_prior and not derived_prior:
                prior = point_policy
            elif all(prior.get(k) == point_policy.get(k) for k in authority):
                prior['checks'] = {**prior['checks'], **point_policy['checks']}
            metadata['compliance_policy'] = {**parent_policy, 'sw13': prior}
    if guest_policy:
        metadata['compliance_policy'] = {**metadata.get('compliance_policy',{}), **guest_policy}
    if "maxCredentialAgeDays" in options:
        age = options["maxCredentialAgeDays"]
        if type(age) is not int or age <= 0:
            raise ValueError("maxCredentialAgeDays must be a positive integer")
        metadata["parameters"] = {"maxCredentialAgeDays": age}
    try:
        native_instant = azure_storage_recovery_metadata_native.snapshot_instant(reader.collections, wanted)
        native_instant = azure_storage_lifecycle_native.snapshot_instant(reader.collections, wanted, native_instant)
        native_instant = azure_apim_protocol_policy.project(reader, scopes, wanted, options, native_instant)
        native_instant = azure_apim_diagnostic_evidence_native.project(reader, scopes, wanted, options, native_instant)
        native_instant = azure_storage_blob_keys_native.snapshot_instant(reader.collections, wanted, native_instant)
        native_instant = azure_audit_storage_native.snapshot_instant(reader.collections, wanted, native_instant)
        if "apim_api_evidence" in wanted:
            metadata["intentional_partial"] = bool(metadata.get("intentional_partial") or reader.metadata()["intentional_partial"])
        devops_scopes = getattr(reader, 'native_devops_pipeline_scopes', [])
        if devops_scopes:
            metadata['native_devops_pipeline_capture'] = reader.native_devops_pipeline_capture
            metadata['sw14Policy'] = reader.native_devops_pipeline_policy
        if nsg_owner is not None:
            native_instant = native_instant or datetime.now(timezone.utc).isoformat()
            approved = azure_nsg_ingress_native.owner_metadata(nsg_owner, native_instant)
            if approved:
                metadata["compliance_policy"] = {**metadata.get("compliance_policy", {}), "sw31": approved}
        snapshot = make_snapshot("azure", scopes + devops_scopes, reader.collections, metadata=metadata, created_at=native_instant)
        if devops_scopes:
            snapshot = azure_devops_pipeline_native.bind_snapshot(snapshot)
    except Exception:
        reader.progress("error")
        raise
    if package_grant is not None:
        snapshot = package_source.finish(reader, snapshot, options, transport,
            locals().get('cache', {}), locals().get('cache_locks', {}))
        reader.progress('completed')
        return snapshot
    snapshot = azure_function_settings_runtime_hooks_20261020.final_snapshot(reader, snapshot)
    reader.progress("completed")
    return snapshot

