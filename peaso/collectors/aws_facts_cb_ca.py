"""Collector facts for the claude AWS-B / claude AWS-A predicate families.

Read-only list/get/describe/batch_get calls only, issued through the shared
scan request context (single-flight cache, retry budget and pagination). A
denied or failed read is recorded with its status and never presented as an
empty inventory or setting; only documented not-found codes are absent.
Secret-bearing or code-bearing response fields are dropped through explicit
allowlists before any record is returned.
"""
from __future__ import annotations
import copy
import hashlib

SPECS = {
    # EC2 / VPC
    "elastic_ip": ("ec2", "describe_addresses", "Addresses"),
    "ec2_eip": ("ec2", "describe_addresses", "Addresses"),
    "ec2_client_vpn_endpoint": ("ec2", "describe_client_vpn_endpoints", "ClientVpnEndpoints"),
    "ec2_spot_fleet_request": ("ec2", "describe_spot_fleet_requests", "SpotFleetRequestConfigs"),
    "ec2_launch_template": ("ec2", "describe_launch_templates", "LaunchTemplates"),
    "ec2_instance_image": ("ec2", "describe_images", "Images"),
    "vpc_block_public_access_options": ("ec2", "describe_vpc_block_public_access_options", None),
    "vpc_endpoint_service": ("ec2", "describe_vpc_endpoint_service_configurations", "ServiceConfigurations"),
    "network_firewall": ("network-firewall", "list_firewalls", "Firewalls"),
    "network_firewall_policy": ("network-firewall", "list_firewall_policies", "FirewallPolicies"),
    "network_firewall_rule_group": ("network-firewall", "list_rule_groups", "RuleGroups"),
    "batch_compute_environment": ("batch", "describe_compute_environments", "computeEnvironments"),
    "batch_job_queue": ("batch", "describe_job_queues", "jobQueues"),
    "workspaces_workspace": ("workspaces", "describe_workspaces", "Workspaces"),
    # Databases / analytics
    "rds_db_subnet_group": ("rds", "describe_db_subnet_groups", "DBSubnetGroups"),
    "rds_cluster_endpoint": ("rds", "describe_db_cluster_endpoints", "DBClusterEndpoints[].{DBClusterEndpointArn: DBClusterEndpointArn, DBClusterEndpointIdentifier: DBClusterEndpointIdentifier, DBClusterIdentifier: DBClusterIdentifier, Endpoint: Endpoint, EndpointType: EndpointType, CustomEndpointType: CustomEndpointType, StaticMembers: StaticMembers, ExcludedMembers: ExcludedMembers, Status: Status}"),
    "rds_engine_version": ("rds", "describe_db_engine_versions", "DBEngineVersions"),
    "rds_iam_auth_capability": ("rds", "describe_orderable_db_instance_options", "OrderableDBInstanceOptions"),
    "redshift_subnet_group": ("redshift", "describe_cluster_subnet_groups", "ClusterSubnetGroups"),
    "redshiftserverless_namespace": ("redshift-serverless", "list_namespaces", "namespaces"),
    "redshiftserverless_workgroup": ("redshift-serverless", "list_workgroups", "workgroups"),
    "kafka_version": ("kafka", "list_kafka_versions", "KafkaVersions"),
    "msk_cluster": ("kafka", "list_clusters_v2", "ClusterInfoList"),
    # Selected only by the Kafka version check; the list read shares the
    # scan-local ListClustersV2 cache with msk_cluster.
    "msk_compatible_version": ("kafka", "list_clusters_v2", "ClusterInfoList"),
    "mskconnect_connector": ("kafkaconnect", "list_connectors", "connectors"),
    "kinesis_stream": ("kinesis", "list_streams", "StreamNames"),
    "glue_connection": ("glue", "get_connections", "ConnectionList"),
    "glue_trigger": ("glue", "get_triggers", "Triggers"),
    "glue_session": ("glue", "list_sessions", "Ids"),
    "glue_data_catalog": ("glue", "get_data_catalog_encryption_settings", None),
    "glue_dev_endpoint": ("glue", "get_dev_endpoints", "DevEndpoints"),
    "glue_ml_transform": ("glue", "get_ml_transforms", "Transforms"),
    "glue_table": ("glue", "get_tables", "TableList"),
    # Storage
    "glacier_vault": ("glacier", "list_vaults", "VaultList"),
    "media_store_container": ("mediastore", "list_containers", "Containers"),
    "s3_access_point": ("s3control", "list_access_points", "AccessPointList"),
    "s3_directory_bucket": ("s3", "list_directory_buckets", "Buckets"),
    "storagegateway_gateway": ("storagegateway", "list_gateways", "Gateways"),
    "storagegateway_file_share": ("storagegateway", "list_file_shares", "FileShareInfoList"),
    "backup_selection": ("backup", "list_backup_selections", "BackupSelectionsList"),
    # Compute / application services
    "lightsail_instance": ("lightsail", "get_instances", "instances"),
    "lightsail_database": ("lightsail", "get_relational_databases", "relationalDatabases"),
    "lightsail_static_ip": ("lightsail", "get_static_ips", "staticIps"),
    "sfn_state_machine": ("stepfunctions", "list_state_machines", "stateMachines"),
    "transfer_server": ("transfer", "list_servers", "Servers"),
    "transfer_web_app": ("transfer", "list_web_apps", "WebApps"),
    "transfer_connector": ("transfer", "list_connectors", "Connectors"),
    "ses_email_identity": ("sesv2", "list_email_identities", "EmailIdentities"),
    "sns_subscription": ("sns", "list_subscriptions", "Subscriptions"),
    "sagemaker_notebook_instance": ("sagemaker", "list_notebook_instances", "NotebookInstances"),
    "sagemaker_notebook_lifecycle_config": ("sagemaker", "list_notebook_instance_lifecycle_configs", "NotebookInstanceLifecycleConfigs"),
    "sagemaker_studio_lifecycle_config": ("sagemaker", "list_studio_lifecycle_configs", "StudioLifecycleConfigs"),
    "sagemaker_app": ("sagemaker", "list_apps", "Apps"),
    "sagemaker_model": ("sagemaker", "list_models", "Models"),
    "sagemaker_training_job": ("sagemaker", "list_training_jobs", "TrainingJobSummaries"),
    "sagemaker_endpoint_config": ("sagemaker", "list_endpoint_configs", "EndpointConfigs"),
    "sagemaker_domain": ("sagemaker", "list_domains", "Domains"),
    "sagemaker_processing_job": ("sagemaker", "list_processing_jobs", "ProcessingJobSummaries"),
    "sagemaker_monitoring_schedule": ("sagemaker", "list_monitoring_schedules", "MonitoringScheduleSummaries"),
    "sagemaker_model_package_group": ("sagemaker", "list_model_package_groups", "ModelPackageGroupSummaryList"),
    "braket_device": ("braket", "search_devices", "devices"),
    # Security / governance
    "guardduty_finding": ("guardduty", "list_findings", "FindingIds"),
    "guardduty_organization_admin_account": ("guardduty", "list_organization_admin_accounts", "AdminAccounts"),
    "securityhub_hub": ("securityhub", "describe_hub", None),
    "securityhub_organization_admin_account": ("securityhub", "list_organization_admin_accounts", "AdminAccounts"),
    "inspector2_account_status": ("inspector2", "batch_get_account_status", "accounts"),
    "inspector2_finding": ("inspector2", "list_findings", "findings"),
    "inspector2_coverage": ("inspector2", "list_coverage", "coveredResources"),
    "macie_session": ("macie2", "get_macie_session", None),
    "macie2_classification_job": ("macie2", "list_classification_jobs", "items"),
    "ram_resource_share": ("ram", "get_resource_shares", "resourceShares"),
    "oam_link": ("oam", "list_links", "Items"),
    "rolesanywhere_trust_anchor": ("rolesanywhere", "list_trust_anchors", "trustAnchors"),
    "resourceexplorer2_index": ("resource-explorer-2", "list_indexes", "Indexes"),
    "ssm_resource_compliance_summary": ("ssm", "list_resource_compliance_summaries", "ResourceComplianceSummaryItems"),
    "wellarchitected_workload": ("wellarchitected", "list_workloads", "WorkloadSummaries"),
    # Account-global inventories
    "organization": ("organizations", "describe_organization", None),
    "organization_policy": ("organizations", "list_policies", "Policies"),
    "iam_organization_features": ("iam", "list_organizations_features", None),
    "route53_domain": ("route53domains", "list_domains", "Domains"),
    "shield_subscription": ("shield", "get_subscription_state", None),
    "shield_protection": ("shield", "list_protections", "Protections"),
    "trustedadvisor_support": ("support", "describe_severity_levels", None),
    "trustedadvisor_check": ("support", "describe_trusted_advisor_checks", "checks"),
    "s3_multi_region_access_point": ("s3control", "list_multi_region_access_points", "AccessPoints"),
    "globalaccelerator_accelerator": ("globalaccelerator", "list_accelerators", "Accelerators"),
    "globalaccelerator_custom_routing_accelerator": ("globalaccelerator", "list_custom_routing_accelerators", "Accelerators"),
    "globalaccelerator_custom_routing_listener": ("globalaccelerator", "list_custom_routing_listeners", "Listeners"),
    "globalaccelerator_cross_account_attachment": ("globalaccelerator", "list_cross_account_attachments", "CrossAccountAttachments"),
    "ssmincidents_account": ("ssm-incidents", "list_replication_sets", "replicationSetArns"),
}
NATIVE_IDS = {
    "elastic_ip": "AllocationId", "ec2_eip": "AllocationId", "ec2_client_vpn_endpoint": "ClientVpnEndpointId",
    "ec2_spot_fleet_request": "SpotFleetRequestId", "ec2_launch_template": "LaunchTemplateId", "ec2_instance_image": "ImageId",
    "vpc_block_public_access_options": "id", "vpc_endpoint_service": "ServiceId",
    "network_firewall": "FirewallArn", "network_firewall_policy": "id", "network_firewall_rule_group": "id",
    "batch_compute_environment": "computeEnvironmentArn", "batch_job_queue": "jobQueueArn", "workspaces_workspace": "WorkspaceId",
    "rds_db_subnet_group": "DBSubnetGroupArn", "rds_cluster_endpoint": "DBClusterEndpointIdentifier", "rds_engine_version": "id", "rds_iam_auth_capability": "id", "redshift_subnet_group": "ClusterSubnetGroupName",
    "redshiftserverless_namespace": "namespaceArn", "redshiftserverless_workgroup": "workgroupArn",
    "kafka_version": "Version", "msk_cluster": "ClusterArn", "msk_compatible_version": "ClusterArn",
    "mskconnect_connector": "connectorArn", "kinesis_stream": "StreamARN",
    "glue_trigger": "Name",
    "glue_session": "Id",
    "glue_connection": "Name", "glue_data_catalog": "id", "glue_dev_endpoint": "EndpointName", "glue_ml_transform": "TransformId", "glue_table": "id",
    "glacier_vault": "VaultARN", "media_store_container": "ARN", "s3_access_point": "AccessPointArn", "s3_directory_bucket": "Name",
    "storagegateway_gateway": "GatewayARN", "storagegateway_file_share": "FileShareARN", "backup_selection": "id",
    "lightsail_instance": "arn", "lightsail_database": "arn", "lightsail_static_ip": "arn",
    "sfn_state_machine": "stateMachineArn", "transfer_server": "Arn", "transfer_web_app": "Arn", "transfer_connector": "Arn",
    "ses_email_identity": "IdentityName", "sns_subscription": "id",
    "sagemaker_notebook_instance": "NotebookInstanceArn", "sagemaker_notebook_lifecycle_config": "NotebookInstanceLifecycleConfigArn",
    "sagemaker_studio_lifecycle_config": "StudioLifecycleConfigArn",
    "braket_device": "deviceArn",
    "sagemaker_app": "id", "sagemaker_model": "ModelArn", "sagemaker_training_job": "TrainingJobArn",
    "sagemaker_endpoint_config": "EndpointConfigArn", "sagemaker_domain": "DomainArn", "sagemaker_processing_job": "ProcessingJobArn",
    "sagemaker_monitoring_schedule": "MonitoringScheduleArn", "sagemaker_model_package_group": "ModelPackageGroupArn",
    "guardduty_finding": "Arn", "guardduty_organization_admin_account": "AdminAccountId", "securityhub_hub": "HubArn",
    "securityhub_organization_admin_account": "AccountId", "inspector2_account_status": "id", "inspector2_finding": "findingArn",
    "inspector2_coverage": "id", "macie_session": "id", "macie2_classification_job": "jobId", "ram_resource_share": "resourceShareArn",
    "rolesanywhere_trust_anchor": "trustAnchorArn", "resourceexplorer2_index": "Arn", "ssm_resource_compliance_summary": "id",
    "oam_link": "Arn",
    "wellarchitected_workload": "WorkloadArn",
    "organization": "id", "organization_policy": "Id", "iam_organization_features": "id", "route53_domain": "DomainName",
    "shield_subscription": "id", "shield_protection": "Id", "trustedadvisor_support": "id", "trustedadvisor_check": "id",
    "s3_multi_region_access_point": "Alias", "globalaccelerator_accelerator": "AcceleratorArn",
    "globalaccelerator_custom_routing_accelerator": "AcceleratorArn", "globalaccelerator_custom_routing_listener": "ListenerArn",
    "globalaccelerator_cross_account_attachment": "AttachmentArn", "ssmincidents_account": "id",
}
GLOBAL_TYPES = {"organization", "organization_policy", "iam_organization_features", "route53_domain", "shield_subscription",
                "shield_protection", "trustedadvisor_support", "trustedadvisor_check", "s3_multi_region_access_point",
                "globalaccelerator_accelerator", "globalaccelerator_custom_routing_accelerator",
                "globalaccelerator_custom_routing_listener", "globalaccelerator_cross_account_attachment", "ssmincidents_account"}
READ_ACTIONS = {(service, operation) for service, operation, expression in SPECS.values()}
READ_ACTIONS.update({
    ("globalaccelerator", "list_custom_routing_accelerators"),
    ("globalaccelerator", "list_custom_routing_endpoint_groups"),
    ("kafka", "get_compatible_kafka_versions"),
    ("ec2", "describe_launch_template_versions"), ("ec2", "describe_instances"), ("ec2", "describe_vpc_endpoint_service_permissions"),
    ("ec2", "describe_vpc_endpoint_connections"),
    ("network-firewall", "describe_firewall"), ("network-firewall", "describe_logging_configuration"),
    ("network-firewall", "describe_firewall_policy"), ("network-firewall", "describe_rule_group"),
    ("rds", "describe_db_instances"), ("rds", "describe_db_parameters"), ("rds", "describe_db_cluster_parameters"),
    ("rds", "describe_orderable_db_instance_options"),
    ("redshift", "describe_logging_status"), ("redshift", "describe_cluster_parameters"),
    ("kinesis", "describe_stream_summary"),
    ("glue", "get_resource_policy"), ("glue", "get_databases"),
    ("glacier", "get_vault_access_policy"), ("mediastore", "get_container_policy"),
    ("s3control", "get_access_point"), ("s3", "get_bucket_lifecycle_configuration"), ("s3", "get_bucket_website"),
    ("storagegateway", "describe_nfs_file_shares"), ("storagegateway", "describe_smb_file_shares"),
    ("backup", "list_backup_plans"), ("backup", "get_backup_selection"),
    ("stepfunctions", "describe_state_machine"), ("transfer", "describe_server"), ("transfer", "describe_connector"),
    ("sesv2", "get_email_identity"),
    ("sagemaker", "describe_notebook_instance"), ("sagemaker", "describe_model"), ("sagemaker", "describe_training_job"),
    ("sagemaker", "describe_endpoint_config"), ("sagemaker", "describe_domain"), ("sagemaker", "describe_processing_job"),
    ("sagemaker", "list_model_packages"),
    ("guardduty", "list_detectors"), ("guardduty", "get_findings"), ("guardduty", "get_administrator_account"),
    ("guardduty", "list_members"), ("guardduty", "describe_organization_configuration"),
    ("securityhub", "get_enabled_standards"), ("securityhub", "list_enabled_products_for_import"),
    ("securityhub", "describe_organization_configuration"),
    ("inspector2", "batch_get_finding_details"),
    ("macie2", "get_automated_discovery_configuration"), ("macie2", "describe_classification_job"),
    ("ram", "get_resource_share_associations"),
    ("organizations", "describe_policy"), ("organizations", "list_targets_for_policy"), ("organizations", "list_delegated_administrators"),
    ("route53domains", "get_domain_detail"), ("route53", "list_query_logging_configs"),
    ("support", "describe_trusted_advisor_check_summaries"),
    ("ssm-incidents", "get_replication_set"), ("ssm-incidents", "list_response_plans"),
    ("ssm", "get_service_setting"),
    ("accessanalyzer", "list_findings_v2"), ("accessanalyzer", "get_finding_v2"), ("accessanalyzer", "get_analyzer"),
})

_OK = ("collected", "empty")


def _result(items, status=None, error=None):
    from .aws import ReadResult
    return ReadResult(items, status or ("collected" if items else "empty"), error)


def _cause(read):
    """(status, error) of a failed ReadResult, keeping the underlying cause."""
    error = dict(read.error or {})
    return error.get("cause_status", read.status) if read.status == "partial" else read.status, error


def _finish(items, failure=None):
    if failure:
        status, error = failure
        return _result(items, "partial" if items else status, error)
    return _result(items)


def _detail_failure(response, operation):
    return response.get("collection_status", "unknown"), {**dict(response.get("error") or {}), "operation": operation}


def _failed(response):
    return not isinstance(response, dict) or response.get("collection_status") not in _OK


def _pick(value, keys):
    return {key: copy.deepcopy(value[key]) for key in keys if isinstance(value, dict) and key in value}


def _mark(item, response, operation):
    """The merged top-level facts of `item` are unreadable: predicates go UNKNOWN."""
    status, error = _detail_failure(response, operation)
    item["collection_status"] = status
    item["error"] = error


def _cover(item, field, status, error=None, **extra):
    item.setdefault("_coverage", {})[field] = {"status": status, **({"error": error} if error else {}), **extra}


def _listing(read):
    output = {"collection_status": read.status, "items": copy.deepcopy(read.items)}
    if read.error:
        output["error"] = read.error
    return output


def _sagemaker_apps(requests, session, region, account):
    read = requests.pages(session, "sagemaker", region, "list_apps", "Apps")
    if read.status not in _OK:
        return _result([], *_cause(read))
    rows, failure = [], None
    for app in read.items:
        if not isinstance(app, dict) or not all(isinstance(app.get(key), str) for key in
                                                 ("DomainId", "AppType", "AppName", "Status")):
            failure = failure or ("malformed", {"code": "malformed_sagemaker_app"})
            continue
        row = _pick(app, ("DomainId", "UserProfileName", "SpaceName", "AppType", "AppName", "Status"))
        row["id"] = "/".join(str(row.get(key) or "") for key in
                             ("DomainId", "UserProfileName", "SpaceName", "AppType", "AppName"))
        rows.append(row)
    return _finish(rows, failure)


def _braket_devices(requests, session, region, account):
    """Read only the documented SV1 simulator; SearchDevices requires an ARN filter."""
    arn = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"
    read = requests.pages(session, "braket", region, "search_devices", "devices",
                          filters=[{"name": "deviceArn", "values": [arn]}],
                          _tokens=("nextToken", "nextToken"))
    if read.status not in _OK:
        return _result([], *_cause(read))
    rows, failure = [], None
    for device in read.items:
        if not isinstance(device, dict) or device.get("deviceArn") != arn or \
                device.get("deviceType") != "SIMULATOR" or \
                device.get("deviceStatus") not in ("ONLINE", "OFFLINE", "RETIRED"):
            failure = failure or ("malformed", {"code": "malformed_braket_device"})
            continue
        rows.append(_pick(device, ("deviceArn", "deviceName", "deviceStatus", "deviceType", "providerName")))
    return _finish(rows, failure)


def _msk_compatible_versions(requests, session, region, account):
    """Cluster-scoped upgrade targets, only when the version check selects this kind.

    ListClustersV2 is single-flight cached with the ordinary msk_cluster kind.
    GetCompatibleKafkaVersions has no pagination token; each provisioned ARN
    receives one read through the shared scan call budget and retry limits.
    """
    clusters = requests.pages(session, "kafka", region, "list_clusters_v2", "ClusterInfoList")
    if clusters.status not in _OK:
        return _result([], clusters.status, clusters.error)
    rows = []
    for cluster in clusters.items:
        if not isinstance(cluster, dict):
            return _result([], "malformed", {"code": "malformed_msk_cluster_summary"})
        kind = cluster.get("ClusterType")
        if kind == "SERVERLESS":
            continue
        arn = cluster.get("ClusterArn")
        if kind != "PROVISIONED" or not isinstance(arn, str) or not arn:
            return _result([], "malformed", {"code": "malformed_msk_cluster_summary"})
        response = requests.detail(session, "kafka", region, "get_compatible_kafka_versions", ClusterArn=arn)
        if _failed(response):
            compatible = {"collection_status": response.get("collection_status", "unknown"),
                          "error": response.get("error", {})}
        else:
            versions = response.get("CompatibleKafkaVersions")
            if not isinstance(versions, list) or any(not isinstance(row, dict) for row in versions):
                compatible = {"collection_status": "malformed", "error": {"code": "malformed_compatible_versions"}}
            else:
                compatible = {"collection_status": "collected", "items": [_pick(row, ("SourceVersion", "TargetVersions")) for row in versions]}
        rows.append({"ClusterArn": arn, "CompatibleVersions": compatible})
    return _result(rows, clusters.status, clusters.error)


def _msk_public_bootstrap(requests, session, region, items):
    """Read public bootstrap hosts only for provisioned clusters with public access enabled."""
    keys = ("BootstrapBrokerStringPublicTls", "BootstrapBrokerStringPublicSaslScram",
            "BootstrapBrokerStringPublicSaslIam", "BootstrapBrokerStringIpv6",
            "BootstrapBrokerStringTlsIpv6", "BootstrapBrokerStringSaslScramIpv6",
            "BootstrapBrokerStringSaslIamIpv6")
    output = []
    for original in items:
        item = copy.deepcopy(original)
        broker = (item.get("Provisioned") or {}).get("BrokerNodeGroupInfo")
        connectivity = broker.get("ConnectivityInfo") if isinstance(broker, dict) else None
        public = connectivity.get("PublicAccess") if isinstance(connectivity, dict) else None
        if isinstance(public, dict) and public.get("Type") == "SERVICE_PROVIDED_EIPS":
            arn = item.get("ClusterArn")
            if not isinstance(arn, str) or not arn:
                item["PublicBootstrapBrokers"] = {"collection_status": "malformed", "error": {"code": "missing_cluster_arn"}}
            else:
                response = requests.detail(session, "kafka", region, "get_bootstrap_brokers", ClusterArn=arn)
                if _failed(response):
                    item["PublicBootstrapBrokers"] = _pick(response, ("collection_status", "error"))
                else:
                    item["PublicBootstrapBrokers"] = {**_pick(response, keys), "collection_status": "collected"}
        output.append(item)
    return output


def _chunks(values, size):
    return [values[offset:offset + size] for offset in range(0, len(values), size)]


def _partition(region):
    return "aws-us-gov" if region.startswith("us-gov-") else "aws-cn" if region.startswith("cn-") else "aws"


def _home(region, default):
    """Commercial control-plane region for account-global APIs; other partitions stay in-partition."""
    return region if _partition(region) != "aws" or region.startswith(("us-iso", "eu-isoe")) else default


def _with_ids(read, make_id):
    for item in read.items:
        if isinstance(item, dict):
            item["id"] = make_id(item)
    return read


# --------------------------------------------------------------------------- fetchers

def _paged(kind, _tokens=None, projection=None, make_id=None, **arguments):
    def fetch(requests, session, region, account):
        service, operation, expression = SPECS[kind]
        read = requests.pages(session, service, region, operation, projection or expression, _tokens=_tokens, **arguments)
        return _with_ids(read, make_id) if make_id else read
    return fetch


def _home_paged(kind, default, _tokens=None, with_account=False, absent=()):
    def fetch(requests, session, region, account):
        service, operation, expression = SPECS[kind]
        arguments = {"AccountId": account} if with_account else {}
        read = requests.pages(session, service, _home(region, default), operation, expression, _tokens=_tokens, **arguments)
        if read.status not in _OK and not read.items and (read.error or {}).get("code") in absent:
            return _result([], "empty", read.error)
        return read
    return fetch


def _vpc_block_public_access(requests, session, region, account):
    response = requests.detail(session, "ec2", region, "describe_vpc_block_public_access_options")
    if _failed(response):
        return _result([], *_detail_failure(response, "describe_vpc_block_public_access_options"))
    options = response.get("VpcBlockPublicAccessOptions")
    if not isinstance(options, dict):
        return _result([], "malformed", {"code": "malformed_vpc_block_public_access_options"})
    return _result([{"id": f"vpc-block-public-access/{account}/{region}", "VpcBlockPublicAccessOptions": options}])


def _endpoint_services(requests, session, region, account):
    read = requests.pages(session, "ec2", region, "describe_vpc_endpoint_service_configurations", "ServiceConfigurations")
    if read.status not in _OK:
        return read
    if not read.items:
        return read
    connections = requests.pages(session, "ec2", region, "describe_vpc_endpoint_connections", "VpcEndpointConnections")
    by_service = {}
    valid_connections = connections.status in _OK and all(
        isinstance(row, dict) and isinstance(row.get("ServiceId"), str) for row in connections.items)
    if valid_connections:
        for row in connections.items:
            by_service.setdefault(row["ServiceId"], []).append(_pick(row, (
                "ServiceId", "VpcEndpointId", "VpcEndpointOwner", "VpcEndpointState")))
    for item in read.items:
        # DescribeVpcEndpointServiceConfigurations only returns services this
        # account owns; the API carries no Owner field.
        item["Owner"] = account
        principals = requests.pages(session, "ec2", region, "describe_vpc_endpoint_service_permissions", "AllowedPrincipals[].Principal", ServiceId=item.get("ServiceId"))
        if principals.status in _OK and all(isinstance(value, str) for value in principals.items):
            item["AllowedPrincipals"] = principals.items
        else:
            _cover(item, "AllowedPrincipals", *(_cause(principals) if principals.status not in _OK else ("malformed", {"code": "malformed_allowed_principal"})))
        if valid_connections:
            item["EndpointConnections"] = by_service.get(item.get("ServiceId"), [])
        else:
            _cover(item, "EndpointConnections", *(_cause(connections) if connections.status not in _OK else
                ("malformed", {"code": "malformed_endpoint_connection"})))
    return read


def _instance_images(requests, session, region, account):
    instances = requests.pages(session, "ec2", region, "describe_instances", "Reservations[].Instances[]")
    if instances.status not in _OK:
        return _result([], *_cause(instances))
    image_ids = sorted({item.get("ImageId") for item in instances.items if isinstance(item, dict) and isinstance(item.get("ImageId"), str)})
    items, failure = [], None
    projection = "Images[].{ImageId: ImageId, ImageOwnerAlias: ImageOwnerAlias, OwnerId: OwnerId, Name: Name, State: State, Public: Public, CreationDate: CreationDate, DeprecationTime: DeprecationTime}"
    for chunk in _chunks(image_ids, 100):
        read = requests.pages(session, "ec2", region, "describe_images", projection, Filters=[{"Name": "image-id", "Values": chunk}], IncludeDeprecated=True, IncludeDisabled=True)
        items.extend({key: value for key, value in row.items() if value is not None} for row in read.items if isinstance(row, dict))
        if read.status not in _OK:
            failure = failure or _cause(read)
    return _finish(items, failure)


def _engine_versions(requests, session, region, account):
    """Offered versions of each engine actually used by this region's DB instances."""
    instances = requests.pages(session, "rds", region, "describe_db_instances", "DBInstances")
    if instances.status not in _OK:
        return _result([], *_cause(instances))
    engines = sorted({item.get("Engine") for item in instances.items if isinstance(item, dict) and isinstance(item.get("Engine"), str)})
    items, failure = [], None
    for engine in engines:
        read = requests.pages(session, "rds", region, "describe_db_engine_versions", "DBEngineVersions[].{Engine: Engine, EngineVersion: EngineVersion, Status: Status}", Engine=engine)
        for row in read.items:
            if isinstance(row, dict) and isinstance(row.get("EngineVersion"), str):
                items.append({**row, "id": f"{row.get('Engine')}/{row['EngineVersion']}"})
        if read.status not in _OK:
            failure = failure or _cause(read)
    return _finish(items, failure)


def _rds_iam_auth_capabilities(requests, session, region, account):
    """Read one exact orderable option tuple per existing standalone RDS shape."""
    instances = requests.pages(session, "rds", region, "describe_db_instances", "DBInstances")
    if instances.status not in _OK:
        return _result([], *_cause(instances))
    output, cache = [], {}
    projection = "OrderableDBInstanceOptions[].{Engine: Engine, EngineVersion: EngineVersion, DBInstanceClass: DBInstanceClass, SupportsIAMDatabaseAuthentication: SupportsIAMDatabaseAuthentication}"
    for instance in instances.items:
        if not isinstance(instance, dict) or instance.get("Engine") not in ("mysql", "mariadb", "postgres") or instance.get("DBClusterIdentifier"):
            continue
        arn = instance.get("DBInstanceArn")
        if not isinstance(arn, str) or not arn:
            continue
        row = {"id": arn, "DBInstanceArn": arn}
        triple = tuple(instance.get(field) for field in ("Engine", "EngineVersion", "DBInstanceClass"))
        if any(not isinstance(value, str) or not value for value in triple):
            _cover(row, "SupportsIAMDatabaseAuthentication", "malformed", {"code": "missing_engine_version_or_class"})
            output.append(row)
            continue
        row.update(zip(("Engine", "EngineVersion", "DBInstanceClass"), triple))
        if triple not in cache:
            read = requests.pages(session, "rds", region, "describe_orderable_db_instance_options", projection,
                                  Engine=triple[0], EngineVersion=triple[1], DBInstanceClass=triple[2])
            if read.status not in _OK:
                cache[triple] = (None, *_cause(read))
            elif not read.items:
                cache[triple] = (None, "empty", {"code": "no_current_orderable_option"})
            elif any(not isinstance(option, dict) or tuple(option.get(field) for field in ("Engine", "EngineVersion", "DBInstanceClass")) != triple
                     or type(option.get("SupportsIAMDatabaseAuthentication")) is not bool for option in read.items):
                cache[triple] = (None, "malformed", {"code": "invalid_orderable_option"})
            else:
                values = {option["SupportsIAMDatabaseAuthentication"] for option in read.items}
                cache[triple] = (next(iter(values)), "collected", {}) if len(values) == 1 else (None, "malformed", {"code": "conflicting_orderable_options"})
        supported, status, error = cache[triple]
        if status == "collected":
            row["SupportsIAMDatabaseAuthentication"] = supported
        else:
            _cover(row, "SupportsIAMDatabaseAuthentication", status, error)
        output.append(row)
    return _result(output)


def _glacier_vaults(requests, session, region, account):
    return requests.pages(session, "glacier", region, "list_vaults", "VaultList", accountId="-")


def _glue_sessions(requests, session, region, account):
    # Botocore has no paginator for ListSessions, although the API returns NextToken.
    ids = requests.pages(session, "glue", region, "list_sessions", "Ids", _tokens=("NextToken", "NextToken"))
    details = requests.pages(session, "glue", region, "list_sessions",
                             "Sessions[].{Id: Id, Role: Role, Status: Status}",
                             _tokens=("NextToken", "NextToken"))
    complete = (ids.status in ("collected", "empty") and details.status in ("collected", "empty")
                and all(isinstance(value, str) and value for value in ids.items)
                and all(isinstance(row, dict) and isinstance(row.get("Id"), str) and row["Id"]
                        for row in details.items)
                and len(ids.items) == len(details.items)
                and set(ids.items) == {row["Id"] for row in details.items})
    if not complete:
        details.status = "partial" if details.items else "not_collected"
        details.error = details.error or ids.error or {"code": "glue_session_ids_and_details_not_joined"}
    return details


_GLUE_CONNECTION_KEYS = ("Name", "Description", "ConnectionType", "CreationTime", "LastUpdatedTime", "Status", "ConnectionSchemaVersion")
# Only non-secret TLS/validation flags; never URLs, user names, passwords or secret references.
_GLUE_CONNECTION_PROPERTIES = ("JDBC_ENFORCE_SSL", "KAFKA_SSL_ENABLED", "SKIP_CUSTOM_JDBC_CERT_VALIDATION", "KAFKA_SKIP_CUSTOM_CERT_VALIDATION", "JDBC_ENGINE", "JDBC_ENGINE_VERSION")


def _glue_connections(requests, session, region, account):
    read = requests.pages(session, "glue", region, "get_connections", "ConnectionList", HidePassword=True)
    output = []
    for original in read.items:
        if not isinstance(original, dict):
            continue
        item = _pick(original, _GLUE_CONNECTION_KEYS)
        if "AdditionalSecretIndicators" in original:
            item["AdditionalSecretIndicators"] = copy.deepcopy(original["AdditionalSecretIndicators"])
        properties = original.get("ConnectionProperties")
        item["ConnectionProperties"] = {key: value for key, value in (properties or {}).items() if key in _GLUE_CONNECTION_PROPERTIES and isinstance(value, str)} if isinstance(properties, dict) or properties is None else {}
        physical = original.get("PhysicalConnectionRequirements")
        if isinstance(physical, dict):
            item["PhysicalConnectionRequirements"] = _pick(physical, ("SubnetId", "SecurityGroupIdList", "AvailabilityZone"))
        output.append(item)
    read.items = output
    return read


def _glue_data_catalog(requests, session, region, account):
    encryption = requests.detail(session, "glue", region, "get_data_catalog_encryption_settings")
    policy = requests.detail(session, "glue", region, "get_resource_policy", absent=("EntityNotFoundException",))
    row = {"id": f"arn:{_partition(region)}:glue:{region}:{account}:catalog", "CatalogId": account}
    failure = None
    if _failed(encryption):
        row["EncryptionSettings"] = {"collection_status": encryption.get("collection_status", "unknown"), "error": encryption.get("error", {})}
        failure = _detail_failure(encryption, "get_data_catalog_encryption_settings")
    else:
        row["EncryptionSettings"] = _pick(encryption, ("DataCatalogEncryptionSettings", "collection_status"))
    if _failed(policy):
        failure = failure or _detail_failure(policy, "get_resource_policy")
    row["ResourcePolicy"] = _pick(policy, ("PolicyInJson", "CreateTime", "UpdateTime", "collection_status", "absent", "error"))
    return _result([row], "partial" if failure else "collected", failure[1] if failure else None)


def _glue_dev_endpoints(requests, session, region, account):
    keys = ("EndpointName", "RoleArn", "SecurityGroupIds", "SubnetId", "VpcId", "AvailabilityZone", "PrivateAddress", "PublicAddress", "Status",
            "WorkerType", "GlueVersion", "NumberOfWorkers", "NumberOfNodes", "SecurityConfiguration", "CreatedTimestamp", "LastModifiedTimestamp")
    read = requests.pages(session, "glue", region, "get_dev_endpoints", "DevEndpoints")
    # SSH public key counts and legacy-key presence only; the keys themselves are never kept.
    read.items = [{**_pick(item, keys),
                   "PublicKeyCount": len(set(item.get("PublicKeys") or []) | ({item["PublicKey"]} if item.get("PublicKey") else set())),
                   "ManagedPublicKeyCount": len(item.get("PublicKeys") or []),
                   "LegacyPublicKeyPresent": bool(item.get("PublicKey"))}
                  for item in read.items if isinstance(item, dict)]
    return read


def _glue_ml_transforms(requests, session, region, account):
    keys = ("TransformId", "Name", "Status", "Role", "GlueVersion", "WorkerType", "NumberOfWorkers", "CreatedOn", "LastModifiedOn", "TransformEncryption")
    read = requests.pages(session, "glue", region, "get_ml_transforms", "Transforms", _tokens=("NextToken", "NextToken"))
    read.items = [_pick(item, keys) for item in read.items if isinstance(item, dict)]
    return read


def _glue_tables(requests, session, region, account):
    databases = requests.pages(session, "glue", region, "get_databases", "DatabaseList[].Name")
    if databases.status not in _OK:
        return _result([], *_cause(databases))
    items, failure = [], None
    for database in databases.items:
        if not isinstance(database, str):
            failure = failure or ("malformed", {"code": "malformed_database_name"})
            continue
        tables = requests.pages(session, "glue", region, "get_tables", "TableList[].Name", DatabaseName=database)
        items.extend({"id": f"{database}/{name}", "DatabaseName": database, "Name": name} for name in tables.items if isinstance(name, str))
        if tables.status not in _OK:
            failure = failure or _cause(tables)
    return _finish(items, failure)


def _inspector_status(requests, session, region, account):
    try:
        response = requests.call(session, "inspector2", region, "batch_get_account_status", accountIds=[account])
    except Exception as exc:
        from .aws import _failure
        failure = _failure(exc)
        return _result([], failure.status, {"code": failure.code})
    rows = [row for row in response.get("accounts") or [] if isinstance(row, dict) and row.get("accountId") == account]
    if len(rows) != 1:
        failed = [row for row in response.get("failedAccounts") or [] if isinstance(row, dict) and row.get("accountId") == account]
        code = failed[0].get("errorCode") if failed else "account_status_missing"
        return _result([], "unknown", {"code": code})
    row = rows[0]
    return _result([{"id": f"inspector2/{account}/{region}", "accountId": account, "State": copy.deepcopy(row.get("state")), "ResourceState": copy.deepcopy(row.get("resourceState"))}])


_INSPECTOR_FINDING = ("findings[].{findingArn: findingArn, awsAccountId: awsAccountId, type: type, severity: severity, status: status, "
                      "firstObservedAt: firstObservedAt, lastObservedAt: lastObservedAt, updatedAt: updatedAt, inspectorScore: inspectorScore, "
                      "exploitAvailable: exploitAvailable, fixAvailable: fixAvailable, "
                      "packageVulnerabilityDetails: packageVulnerabilityDetails.{vulnerabilityId: vulnerabilityId, source: source}, "
                      "resources: resources[].{type: type, id: id}}")


def _inspector_findings(requests, session, region, account):
    read = requests.pages(session, "inspector2", region, "list_findings", _INSPECTOR_FINDING,
                          filterCriteria={"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]})
    items = [{key: value for key, value in row.items() if value is not None} for row in read.items if isinstance(row, dict)]
    by_arn = {row["findingArn"]: row for row in items if isinstance(row.get("findingArn"), str)}
    for chunk in _chunks(sorted(by_arn), 10):
        response = requests.detail(session, "inspector2", region, "batch_get_finding_details", findingArns=chunk)
        if _failed(response):
            for arn in chunk:
                by_arn[arn]["Details"] = {"collection_status": response.get("collection_status", "unknown"), "error": response.get("error", {})}
            continue
        for detail in response.get("findingDetails") or []:
            if isinstance(detail, dict) and detail.get("findingArn") in by_arn:
                by_arn[detail["findingArn"]]["Details"] = {"collection_status": "collected", **_pick(detail, ("findingArn", "cisaData", "epssScore", "exploitObserved", "cwes"))}
        for error in response.get("errors") or []:
            if isinstance(error, dict) and error.get("findingArn") in by_arn:
                by_arn[error["findingArn"]]["Details"] = {"collection_status": "unknown", "error": {"code": error.get("errorCode", "finding_detail_error")}}
        for arn in chunk:
            by_arn[arn].setdefault("Details", {"collection_status": "unknown", "error": {"code": "finding_detail_missing"}})
    read.items = items
    return read


def _inspector_coverage(requests, session, region, account):
    projection = "coveredResources[].{resourceId: resourceId, resourceType: resourceType, accountId: accountId, scanType: scanType, scanStatus: scanStatus, scanMode: scanMode, lastScannedAt: lastScannedAt}"
    read = requests.pages(session, "inspector2", region, "list_coverage", projection)
    read.items = [{key: value for key, value in row.items() if value is not None} for row in read.items if isinstance(row, dict)]
    return _with_ids(read, lambda item: f"{item.get('resourceType')}/{item.get('resourceId')}/{item.get('scanType')}")


def _kinesis_streams(requests, session, region, account):
    read = requests.pages(session, "kinesis", region, "list_streams", "StreamNames")
    read.items = [{"StreamName": name, "StreamARN": f"arn:{_partition(region)}:kinesis:{region}:{account}:stream/{name}"} for name in read.items if isinstance(name, str)]
    return read


def _macie_session(requests, session, region, account):
    macie = requests.detail(session, "macie2", region, "get_macie_session", absent=("ResourceNotFoundException",))
    row = {"id": f"macie/{account}/{region}", "accountId": account,
           "Session": _pick(macie, ("status", "findingPublishingFrequency", "serviceRole", "createdAt", "updatedAt", "collection_status", "absent", "error"))}
    if macie.get("collection_status") == "collected" and macie.get("status") == "ENABLED":
        discovery = requests.detail(session, "macie2", region, "get_automated_discovery_configuration")
        row["AutomatedDiscovery"] = _pick(discovery, ("status", "autoEnableOrganizationMembers", "firstEnabledAt", "lastUpdatedAt", "disabledAt", "collection_status", "error"))
    return _result([row])


def _ram_shares(requests, session, region, account):
    read = requests.pages(session, "ram", region, "get_resource_shares", "resourceShares", resourceOwner="SELF")
    if read.status not in _OK:
        return read
    shares = {item["resourceShareArn"]: item for item in read.items if isinstance(item, dict) and isinstance(item.get("resourceShareArn"), str)}
    projection = "resourceShareAssociations[].{resourceShareArn: resourceShareArn, associatedEntity: associatedEntity, associationType: associationType, status: status, external: external}"
    for association, field in (("PRINCIPAL", "PrincipalAssociations"), ("RESOURCE", "ResourceAssociations")):
        for chunk in _chunks(sorted(shares), 25):
            listed = requests.pages(session, "ram", region, "get_resource_share_associations", projection, associationType=association, resourceShareArns=chunk)
            for arn in chunk:
                if listed.status in _OK:
                    rows = [row for row in listed.items if isinstance(row, dict) and row.get("resourceShareArn") == arn]
                    shares[arn][field] = {"collection_status": "collected", "resourceShareAssociations": rows}
                else:
                    status, error = _cause(listed)
                    shares[arn][field] = {"collection_status": status, "error": error}
    return read


def _trust_anchors(requests, session, region, account):
    read = requests.pages(session, "rolesanywhere", region, "list_trust_anchors", "trustAnchors")
    for item in read.items:
        source = item.get("source") if isinstance(item, dict) else None
        data = source.get("sourceData") if isinstance(source, dict) else None
        if isinstance(data, dict):
            # Certificate bodies are never stored; the PCA ARN is the fact used.
            data.pop("x509CertificateData", None)
    return read


def _s3_access_points(requests, session, region, account):
    read = requests.pages(session, "s3control", region, "list_access_points", "AccessPointList", _tokens=("NextToken", "NextToken"), AccountId=account)
    keys = ("Bucket", "BucketAccountId", "NetworkOrigin", "VpcConfiguration", "PublicAccessBlockConfiguration", "CreationDate", "Alias", "DataSourceId", "DataSourceType")
    for item in read.items:
        if not isinstance(item, dict):
            continue
        response = requests.detail(session, "s3control", region, "get_access_point", AccountId=account, Name=item.get("Name"))
        if _failed(response):
            _mark(item, response, "get_access_point")
        else:
            item.update(_pick(response, keys))
    return read


def _sns_subscriptions(requests, session, region, account):
    read = requests.pages(session, "sns", region, "list_subscriptions", "Subscriptions")
    output = []
    for item in read.items:
        if not isinstance(item, dict):
            continue
        arn, endpoint = item.get("SubscriptionArn"), item.get("Endpoint")
        row = _pick(item, ("SubscriptionArn", "Owner", "Protocol", "TopicArn"))
        if isinstance(arn, str) and arn.startswith("arn:"):
            row["id"] = arn
        else:
            # Pending confirmations share the literal ARN "PendingConfirmation";
            # the endpoint (possibly a tokenised URL) is hashed, never stored.
            row["id"] = f"{item.get('TopicArn')}/pending/" + hashlib.sha256(str(endpoint).encode()).hexdigest()[:16]
        output.append(row)
    read.items = output
    return read


def _compliance_summaries(requests, session, region, account):
    projection = "ResourceComplianceSummaryItems[].{ResourceId: ResourceId, ResourceType: ResourceType, ComplianceType: ComplianceType, Status: Status, OverallSeverity: OverallSeverity}"
    read = requests.pages(session, "ssm", region, "list_resource_compliance_summaries", projection)
    return _with_ids(read, lambda item: f"{item.get('ResourceType')}/{item.get('ResourceId')}/{item.get('ComplianceType')}")


def _backup_selections(requests, session, region, account):
    plans = requests.pages(session, "backup", region, "list_backup_plans", "BackupPlansList")
    if plans.status not in _OK:
        return _result([], *_cause(plans))
    items, failure = [], None
    for plan in plans.items:
        plan_id = plan.get("BackupPlanId") if isinstance(plan, dict) else None
        if not isinstance(plan_id, str):
            failure = failure or ("malformed", {"code": "malformed_backup_plan"})
            continue
        selections = requests.pages(session, "backup", region, "list_backup_selections", "BackupSelectionsList", BackupPlanId=plan_id)
        if selections.status not in _OK:
            failure = failure or _cause(selections)
        for selection in selections.items:
            selection_id = selection.get("SelectionId") if isinstance(selection, dict) else None
            response = requests.detail(session, "backup", region, "get_backup_selection", BackupPlanId=plan_id, SelectionId=selection_id)
            row = {"id": f"{plan_id}/{selection_id}", "BackupPlanId": plan_id, "SelectionId": selection_id, "SelectionName": selection.get("SelectionName")}
            if _failed(response) or not isinstance(response.get("BackupSelection"), dict):
                _mark(row, response if _failed(response) else {"collection_status": "malformed"}, "get_backup_selection")
            else:
                row.update(_pick(response["BackupSelection"], ("SelectionName", "IamRoleArn", "Resources", "ListOfTags", "NotResources", "Conditions")))
            items.append(row)
    return _finish(items, failure)


def _guardduty_findings(requests, session, region, account):
    detectors = requests.pages(session, "guardduty", region, "list_detectors", "DetectorIds")
    if detectors.status not in _OK:
        return _result([], *_cause(detectors))
    projection = ("Findings[].{Id: Id, Arn: Arn, AccountId: AccountId, Region: Region, Type: Type, Severity: Severity, CreatedAt: CreatedAt, "
                  "UpdatedAt: UpdatedAt, ResourceType: Resource.ResourceType, Service: Service.{Archived: Archived, Count: Count, DetectorId: DetectorId}}")
    items, failure = [], None
    for detector in detectors.items:
        ids = requests.pages(session, "guardduty", region, "list_findings", "FindingIds", DetectorId=detector)
        if ids.status not in _OK:
            failure = failure or _cause(ids)
        for chunk in _chunks([value for value in ids.items if isinstance(value, str)], 50):
            read = requests.pages(session, "guardduty", region, "get_findings", projection, DetectorId=detector, FindingIds=chunk)
            items.extend(read.items)
            if read.status not in _OK:
                failure = failure or _cause(read)
            elif len(read.items) != len(chunk):
                # Findings deleted between the two reads; the inventory is no longer a complete snapshot.
                failure = failure or ("unknown", {"code": "finding_set_changed"})
    return _finish(items, failure)


def _securityhub_hub(requests, session, region, account):
    # DescribeHub documents InvalidAccessException as insufficient permission.
    # Only ResourceNotFoundException establishes an absent regional hub.
    hub = requests.detail(session, "securityhub", region, "describe_hub", absent=("ResourceNotFoundException",))
    if hub.get("absent") is True:
        # Security Hub is not enabled in this region: a complete empty inventory.
        return _result([], "empty", hub.get("error"))
    if _failed(hub):
        return _result([], *_detail_failure(hub, "describe_hub"))
    row = _pick(hub, ("HubArn", "SubscribedAt", "AutoEnableControls", "ControlFindingGenerator"))
    row["EnabledStandards"] = _listing(requests.pages(session, "securityhub", region, "get_enabled_standards",
        "StandardsSubscriptions[].{StandardsArn: StandardsArn, StandardsSubscriptionArn: StandardsSubscriptionArn, StandardsStatus: StandardsStatus}"))
    row["ProductSubscriptions"] = _listing(requests.pages(session, "securityhub", region, "list_enabled_products_for_import", "ProductSubscriptions"))
    organization = requests.detail(session, "securityhub", region, "describe_organization_configuration")
    row["OrganizationConfiguration"] = _pick(organization, ("AutoEnable", "AutoEnableStandards", "MemberAccountLimitReached", "OrganizationConfiguration", "collection_status", "error"))
    return _result([row])


def _model_package_groups(requests, session, region, account):
    read = requests.pages(session, "sagemaker", region, "list_model_package_groups", "ModelPackageGroupSummaryList")
    for item in read.items:
        if not isinstance(item, dict):
            continue
        approved = requests.pages(session, "sagemaker", region, "list_model_packages", "ModelPackageSummaryList[].ModelPackageArn",
                                  ModelPackageGroupName=item.get("ModelPackageGroupName"), ModelApprovalStatus="Approved")
        if approved.status in _OK:
            item["ApprovedPackages"] = len(approved.items)
        else:
            _cover(item, "ApprovedPackages", *_cause(approved))
    return read


def _ses_identities(requests, session, region, account):
    return requests.pages(session, "sesv2", region, "list_email_identities", "EmailIdentities", _tokens=("NextToken", "NextToken"))


def _wellarchitected(requests, session, region, account):
    return requests.pages(session, "wellarchitected", region, "list_workloads", "WorkloadSummaries", _tokens=("NextToken", "NextToken"))


# ---------------------------------------------------------------- global fetchers

def _organization(requests, session, region, account):
    response = requests.detail(session, "organizations", region, "describe_organization", absent=("AWSOrganizationsNotInUseException",))
    if response.get("absent") is True:
        return _result([], "empty", response.get("error"))
    if _failed(response) or not isinstance(response.get("Organization"), dict):
        return _result([], *(_detail_failure(response, "describe_organization") if _failed(response) else ("malformed", {"code": "malformed_organization"})))
    organization = _pick(response["Organization"], ("Id", "Arn", "FeatureSet", "MasterAccountId", "MasterAccountArn", "AvailablePolicyTypes"))
    return _result([{"id": organization.get("Id") or "organization", "Organization": organization}])


_ORGANIZATION_POLICY_TYPES = ("SERVICE_CONTROL_POLICY", "AISERVICES_OPT_OUT_POLICY", "TAG_POLICY")


def _organization_policies(requests, session, region, account):
    from .aws import _policy
    items, failure = [], None
    for policy_type in _ORGANIZATION_POLICY_TYPES:
        listed = requests.pages(session, "organizations", region, "list_policies", "Policies", Filter=policy_type)
        if listed.status not in _OK:
            if not items and (listed.error or {}).get("code") == "AWSOrganizationsNotInUseException":
                return _result([], "empty", listed.error)
            failure = failure or _cause(listed)
        for summary in listed.items:
            if not isinstance(summary, dict) or not isinstance(summary.get("Id"), str):
                failure = failure or ("malformed", {"code": "malformed_policy_summary"})
                continue
            row = _pick(summary, ("Id", "Arn", "Name", "Type", "AwsManaged"))
            described = requests.detail(session, "organizations", region, "describe_policy", PolicyId=summary["Id"])
            content = (described.get("Policy") or {}).get("Content") if isinstance(described.get("Policy"), dict) else None
            if _failed(described) or content is None:
                _mark(row, described if _failed(described) else {"collection_status": "malformed"}, "describe_policy")
            else:
                row["Content"] = _policy(content)
            targets = requests.pages(session, "organizations", region, "list_targets_for_policy", "Targets", PolicyId=summary["Id"])
            if targets.status in _OK:
                row["Targets"] = targets.items
            else:
                _cover(row, "Targets", *_cause(targets))
            items.append(row)
    return _finish(items, failure)


def _iam_organization_features(requests, session, region, account):
    response = requests.detail(session, "iam", region, "list_organizations_features", absent=("ServiceAccessNotEnabledException", "OrganizationNotFoundException"))
    code = (response.get("error") or {}).get("code")
    if code == "OrganizationNotFoundException":
        return _result([], "empty", response.get("error"))
    if code == "ServiceAccessNotEnabledException":
        # Trusted access for IAM is disabled, so no centralized root feature can be enabled.
        return _result([{"id": "iam-organization-features", "EnabledFeatures": [], "reason": "iam_trusted_access_not_enabled"}])
    if _failed(response):
        return _result([], *_detail_failure(response, "list_organizations_features"))
    return _result([{"id": "iam-organization-features", **_pick(response, ("OrganizationId", "EnabledFeatures"))}])


def _route53_domains(requests, session, region, account):
    home = _home(region, "us-east-1")
    read = requests.pages(session, "route53domains", home, "list_domains", "Domains")
    keys = ("DomainName", "AutoRenew", "AdminPrivacy", "RegistrantPrivacy", "TechPrivacy", "BillingPrivacy", "StatusList", "CreationDate", "UpdatedDate",
            "ExpirationDate", "Nameservers", "DnsSec", "RegistrarName")
    output = []
    for summary in read.items:
        if not isinstance(summary, dict):
            continue
        row = _pick(summary, ("DomainName", "AutoRenew", "TransferLock", "Expiry"))
        detail = requests.detail(session, "route53domains", home, "get_domain_detail", DomainName=summary.get("DomainName"))
        # Contact records (registrant/admin/tech/billing PII) are never stored.
        row["Detail"] = {"collection_status": detail.get("collection_status"), "error": detail.get("error", {})} if _failed(detail) else {**_pick(detail, keys), "collection_status": "collected"}
        output.append(row)
    read.items = output
    return read


def _shield_subscription(requests, session, region, account):
    response = requests.detail(session, "shield", _home(region, "us-east-1"), "get_subscription_state")
    if _failed(response):
        return _result([], *_detail_failure(response, "get_subscription_state"))
    return _result([{"id": f"shield-subscription/{account}", "SubscriptionState": response.get("SubscriptionState")}])


def _shield_protections(requests, session, region, account):
    read = requests.pages(session, "shield", _home(region, "us-east-1"), "list_protections", "Protections[].{Id: Id, Name: Name, ResourceArn: ResourceArn, ProtectionArn: ProtectionArn, HealthCheckIds: HealthCheckIds}")
    if read.status not in _OK and not read.items and (read.error or {}).get("code") == "ResourceNotFoundException":
        # ListProtections documents ResourceNotFoundException for "no protections".
        return _result([], "empty", read.error)
    return read


def _support_level(requests, session, region, account):
    response = requests.detail(session, "support", _home(region, "us-east-1"), "describe_severity_levels", absent=("SubscriptionRequiredException",), language="en")
    if response.get("absent") is True:
        return _result([{"id": f"support/{account}", "AccountId": account, "PremiumSupport": False}])
    if _failed(response):
        return _result([], *_detail_failure(response, "describe_severity_levels"))
    return _result([{"id": f"support/{account}", "AccountId": account, "PremiumSupport": True}])


def _trusted_advisor_checks(requests, session, region, account):
    home = _home(region, "us-east-1")
    read = requests.pages(session, "support", home, "describe_trusted_advisor_checks", "checks[].{id: id, name: name, category: category}", language="en")
    if read.status not in _OK:
        if not read.items and (read.error or {}).get("code") == "SubscriptionRequiredException":
            # The Trusted Advisor API is only offered with Business/Enterprise support.
            return _result([], "empty", read.error)
        return read
    checks = {item["id"]: item for item in read.items if isinstance(item, dict) and isinstance(item.get("id"), str)}
    failure = None
    projection = "summaries[].{checkId: checkId, status: status, timestamp: timestamp, hasFlaggedResources: hasFlaggedResources, resourcesSummary: resourcesSummary}"
    for chunk in _chunks(sorted(checks), 50):
        summaries = requests.pages(session, "support", home, "describe_trusted_advisor_check_summaries", projection, checkIds=chunk)
        found = {row.get("checkId"): row for row in summaries.items if isinstance(row, dict)}
        for check_id in chunk:
            if summaries.status in _OK and check_id in found:
                checks[check_id]["Result"] = {**found[check_id], "collection_status": "collected"}
            else:
                checks[check_id]["Result"] = {"collection_status": summaries.status if summaries.status not in _OK else "unknown", "error": summaries.error or {"code": "check_summary_missing"}}
        if summaries.status not in _OK:
            failure = failure or _cause(summaries)
    return _finish(list(checks.values()), failure)


def _incident_manager(requests, session, region, account):
    sets = requests.pages(session, "ssm-incidents", region, "list_replication_sets", "replicationSetArns")
    replication = {"collection_status": sets.status, "items": []}
    if sets.status in _OK:
        for arn in sets.items:
            response = requests.detail(session, "ssm-incidents", region, "get_replication_set", arn=arn)
            body = response.get("replicationSet") if isinstance(response.get("replicationSet"), dict) else None
            if _failed(response) or body is None:
                replication = {"collection_status": response.get("collection_status", "malformed") if _failed(response) else "malformed", "error": response.get("error", {})}
                break
            replication["items"].append(_pick(body, ("arn", "status", "deletionProtected", "regionMap", "createdTime", "lastModifiedTime")))
        else:
            replication["collection_status"] = "collected" if replication["items"] else "empty"
    else:
        replication["error"] = sets.error
    plans = requests.pages(session, "ssm-incidents", region, "list_response_plans", "responsePlanSummaries[].{arn: arn, name: name, displayName: displayName}")
    return _result([{"id": f"ssm-incidents/{account}", "AccountId": account, "ReplicationSets": replication, "ResponsePlans": _listing(plans)}])


def _custom_routing_listeners(requests, session, region, account):
    """Join custom listeners to the protocols of their endpoint groups."""
    home = _home(region, "us-west-2")
    roots = requests.pages(session, "globalaccelerator", home, "list_custom_routing_accelerators",
                          "Accelerators", _tokens=("NextToken", "NextToken"))
    if roots.status not in _OK:
        return roots
    rows, failure = [], None
    for root in roots.items:
        arn = root.get("AcceleratorArn") if isinstance(root, dict) else None
        if not isinstance(arn, str):
            failure = failure or ("malformed", {"code": "custom_routing_accelerator_identity_missing"})
            continue
        listeners = requests.pages(session, "globalaccelerator", home, "list_custom_routing_listeners",
                                   "Listeners", _tokens=("NextToken", "NextToken"), AcceleratorArn=arn)
        if listeners.status not in _OK:
            failure = failure or _cause(listeners)
        for listener in listeners.items:
            listener_arn = listener.get("ListenerArn") if isinstance(listener, dict) else None
            if not isinstance(listener_arn, str):
                failure = failure or ("malformed", {"code": "custom_routing_listener_identity_missing"})
                continue
            groups = requests.pages(session, "globalaccelerator", home, "list_custom_routing_endpoint_groups",
                                    "EndpointGroups", _tokens=("NextToken", "NextToken"), ListenerArn=listener_arn)
            if groups.status not in _OK:
                failure = failure or _cause(groups)
            malformed = any(not isinstance(group, dict) or
                            not isinstance(group.get("EndpointGroupArn"), str) or
                            not group["EndpointGroupArn"].startswith(listener_arn + "/endpoint-group/") or
                            not isinstance(group.get("DestinationDescriptions"), list) or
                            any(not isinstance(description, dict) or
                                not isinstance(description.get("Protocols"), list) or
                                any(protocol not in ("TCP", "UDP") for protocol in description["Protocols"])
                                for description in group["DestinationDescriptions"])
                            for group in groups.items)
            if malformed:
                failure = failure or ("malformed", {"code": "custom_routing_endpoint_group_malformed"})
            protocols = sorted({protocol for group in groups.items if isinstance(group, dict) and isinstance(group.get("DestinationDescriptions"), list)
                                for description in group["DestinationDescriptions"] if isinstance(description, dict) and isinstance(description.get("Protocols"), list)
                                for protocol in description["Protocols"] if isinstance(protocol, str)})
            rows.append({"ListenerArn": listener_arn, "AcceleratorArn": arn,
                         "PortRanges": listener.get("PortRanges"), "Protocols": protocols,
                         "EndpointGroupsStatus": "malformed" if malformed else groups.status})
    return _finish(rows, failure)


FETCHERS = {
    "sagemaker_app": _sagemaker_apps,
    "braket_device": _braket_devices,
    "glue_session": _glue_sessions,
    "msk_compatible_version": _msk_compatible_versions,
    "vpc_block_public_access_options": _vpc_block_public_access,
    "vpc_endpoint_service": _endpoint_services,
    "ec2_instance_image": _instance_images,
    "rds_engine_version": _engine_versions,
    "rds_iam_auth_capability": _rds_iam_auth_capabilities,
    "glacier_vault": _glacier_vaults,
    "glue_connection": _glue_connections,
    "glue_data_catalog": _glue_data_catalog,
    "glue_dev_endpoint": _glue_dev_endpoints,
    "glue_ml_transform": _glue_ml_transforms,
    "glue_table": _glue_tables,
    "inspector2_account_status": _inspector_status,
    "inspector2_finding": _inspector_findings,
    "inspector2_coverage": _inspector_coverage,
    "kinesis_stream": _kinesis_streams,
    "macie_session": _macie_session,
    "ram_resource_share": _ram_shares,
    "oam_link": _paged("oam_link", _tokens=("NextToken", "NextToken")),
    "rolesanywhere_trust_anchor": _trust_anchors,
    "s3_access_point": _s3_access_points,
    "sns_subscription": _sns_subscriptions,
    "ssm_resource_compliance_summary": _compliance_summaries,
    "backup_selection": _backup_selections,
    "guardduty_finding": _guardduty_findings,
    "securityhub_hub": _securityhub_hub,
    "sagemaker_model_package_group": _model_package_groups,
    "ses_email_identity": _ses_identities,
    "wellarchitected_workload": _wellarchitected,
    "organization": _organization,
    "organization_policy": _organization_policies,
    "iam_organization_features": _iam_organization_features,
    "route53_domain": _route53_domains,
    "shield_subscription": _shield_subscription,
    "shield_protection": _shield_protections,
    "trustedadvisor_support": _support_level,
    "trustedadvisor_check": _trusted_advisor_checks,
    "s3_multi_region_access_point": _home_paged("s3_multi_region_access_point", "us-west-2", _tokens=("NextToken", "NextToken"), with_account=True),
    "globalaccelerator_accelerator": _home_paged("globalaccelerator_accelerator", "us-west-2"),
    "globalaccelerator_custom_routing_accelerator": _home_paged("globalaccelerator_custom_routing_accelerator", "us-west-2", _tokens=("NextToken", "NextToken")),
    "globalaccelerator_custom_routing_listener": _custom_routing_listeners,
    "globalaccelerator_cross_account_attachment": _home_paged("globalaccelerator_cross_account_attachment", "us-west-2", _tokens=("NextToken", "NextToken")),
    "ssmincidents_account": _incident_manager,
}


# -------------------------------------------------------------- detail enrichers

# kind: (service, operation, argument, item key, response root, allowlisted keys)
_MERGES = {
    "network_firewall": ("network-firewall", "describe_firewall", "FirewallArn", "FirewallArn", "Firewall",
        ("FirewallName", "FirewallArn", "FirewallPolicyArn", "VpcId", "SubnetMappings", "DeleteProtection", "SubnetChangeProtection",
         "FirewallPolicyChangeProtection", "EncryptionConfiguration", "Description", "FirewallId", "EnabledAnalysisTypes",
         "TransitGatewayId", "TransitGatewayOwnerAccountId", "AvailabilityZoneMappings", "NoSourcePreservation", "VpcEndpoint")),
    "sagemaker_notebook_instance": ("sagemaker", "describe_notebook_instance", "NotebookInstanceName", "NotebookInstanceName", None,
        ("NotebookInstanceArn", "NotebookInstanceName", "NotebookInstanceStatus", "NotebookInstanceLifecycleConfigName", "InstanceType", "SubnetId", "SecurityGroups", "RoleArn", "KmsKeyId",
         "DirectInternetAccess", "RootAccess", "PlatformIdentifier", "InstanceMetadataServiceConfiguration", "CreationTime")),
    "sagemaker_model": ("sagemaker", "describe_model", "ModelName", "ModelName", None,
        ("ModelName", "ModelArn", "ExecutionRoleArn", "VpcConfig", "EnableNetworkIsolation", "CreationTime")),
    "sagemaker_training_job": ("sagemaker", "describe_training_job", "TrainingJobName", "TrainingJobName", None,
        ("TrainingJobName", "TrainingJobArn", "TrainingJobStatus", "RoleArn", "VpcConfig", "EnableNetworkIsolation", "EnableInterContainerTrafficEncryption",
         "OutputDataConfig", "ResourceConfig", "CreationTime")),
    "sagemaker_endpoint_config": ("sagemaker", "describe_endpoint_config", "EndpointConfigName", "EndpointConfigName", None,
        ("EndpointConfigName", "EndpointConfigArn", "KmsKeyId", "ProductionVariants", "DataCaptureConfig", "VpcConfig", "EnableNetworkIsolation", "CreationTime")),
    "sagemaker_domain": ("sagemaker", "describe_domain", "DomainId", "DomainId", None,
        ("DomainArn", "DomainId", "DomainName", "Status", "AuthMode", "SingleSignOnApplicationArn", "AppNetworkAccessType", "SubnetIds", "VpcId", "KmsKeyId", "CreationTime")),
    "sfn_state_machine": ("stepfunctions", "describe_state_machine", "stateMachineArn", "stateMachineArn", None,
        ("stateMachineArn", "name", "status", "type", "roleArn", "loggingConfiguration", "tracingConfiguration", "encryptionConfiguration", "creationDate", "PayloadSecretIndicators")),
    "kinesis_stream": ("kinesis", "describe_stream_summary", "StreamName", "StreamName", "StreamDescriptionSummary",
        ("StreamName", "StreamARN", "StreamStatus", "StreamModeDetails", "RetentionPeriodHours", "StreamCreationTimestamp", "EnhancedMonitoring",
         "EncryptionType", "KeyId", "OpenShardCount", "ConsumerCount")),
    "macie2_classification_job": ("macie2", "describe_classification_job", "jobId", "jobId", None,
        ("jobId", "jobArn", "name", "jobStatus", "jobType", "createdAt", "lastRunTime")),
    "sagemaker_processing_job": ("sagemaker", "describe_processing_job", "ProcessingJobName", "ProcessingJobName", None,
        ("ProcessingJobName", "ProcessingJobArn", "ProcessingJobStatus", "RoleArn", "NetworkConfig", "ProcessingResources", "CreationTime")),
}
# Nested members kept through a second allowlist (container arguments and
# entrypoints may embed secrets; scoping criteria are not needed).
_NESTED = {
    "sagemaker_processing_job": ("AppSpecification", ("ImageUri",)),
    "macie2_classification_job": ("s3JobDefinition", ("bucketDefinitions", "bucketCriteria")),
}

# kind: (field, service, operation, argument, item key, absent codes, allowlisted keys or None)
_CONTAINERS = {
    "glacier_vault": ("Policy", "glacier", "get_vault_access_policy", "vaultName", "VaultName", ("ResourceNotFoundException",), None),
    "media_store_container": ("Policy", "mediastore", "get_container_policy", "ContainerName", "Name", ("PolicyNotFoundException",), None),
    "s3_directory_bucket": ("Lifecycle", "s3", "get_bucket_lifecycle_configuration", "Bucket", "Name", ("NoSuchLifecycleConfiguration",), ("Rules", "TransitionDefaultMinimumObjectSize")),
    "transfer_server": ("Server", "transfer", "describe_server", "ServerId", "ServerId", (), ("Arn", "ServerId", "Domain", "EndpointType", "EndpointDetails", "IdentityProviderType",
        "LoggingRole", "StructuredLogDestinations", "Protocols", "ProtocolDetails", "SecurityPolicyName", "State", "Certificate")),
    "transfer_web_app": ("WebApp", "transfer", "describe_web_app", "WebAppId", "WebAppId", (),
        ("Arn", "WebAppId", "EndpointType", "AccessEndpoint", "WebAppEndpoint", "DescribedEndpointDetails")),
    "transfer_connector": ("Connector", "transfer", "describe_connector", "ConnectorId", "ConnectorId", (), ("Arn", "ConnectorId", "Url", "AccessRole", "LoggingRole", "SecurityPolicyName")),
    "ses_email_identity": ("Identity", "sesv2", "get_email_identity", "EmailIdentity", "IdentityName", (), ("IdentityType", "FeedbackForwardingStatus", "VerifiedForSendingStatus",
        "VerificationStatus", "DkimAttributes", "MailFromAttributes", "Policies", "ConfigurationSetName")),
}
_CONTAINER_ROOTS = {"transfer_server": "Server", "transfer_web_app": "WebApp", "transfer_connector": "Connector"}
_EXTRA_ARGUMENTS = {"glacier_vault": {"accountId": "-"}}


def _merge_enricher(kind):
    service, operation, argument, key, root, keys = _MERGES[kind]

    def enrich(requests, session, region, items):
        output = []
        for original in items:
            item = copy.deepcopy(original)
            extra = {"includedData": "METADATA_ONLY"} if kind == "sfn_state_machine" else {}
            response = requests.detail(session, service, region, operation, **{argument: item.get(key)}, **extra)
            body = response.get(root) if root else response
            if _failed(response):
                _mark(item, response, operation)
            elif not isinstance(body, dict):
                _mark(item, {"collection_status": "malformed", "error": {"code": "malformed_detail"}}, operation)
            elif kind == "network_firewall" and body.get("FirewallArn") != item.get("FirewallArn"):
                _mark(item, {"collection_status": "malformed", "error": {"code": "firewall_identity_mismatch"}}, operation)
            else:
                item.update(_pick(body, keys))
                if kind in _NESTED:
                    field, nested = _NESTED[kind]
                    if isinstance(body.get(field), dict):
                        item[field] = _pick(body[field], nested)
            output.append(item)
        return output
    return enrich


def _container_enricher(kind):
    field, service, operation, argument, key, absent, keys = _CONTAINERS[kind]
    root = _CONTAINER_ROOTS.get(kind)

    def enrich(requests, session, region, items):
        output = []
        for original in items:
            item = copy.deepcopy(original)
            response = requests.detail(session, service, region, operation, absent=absent, **_EXTRA_ARGUMENTS.get(kind, {}), **{argument: item.get(key)})
            if _failed(response) or response.get("absent") is True:
                item[field] = response
            else:
                body = response.get(root) if root else response
                if not isinstance(body, dict):
                    item[field] = {"collection_status": "malformed", "error": {"code": "malformed_detail"}}
                else:
                    value = _pick(body, keys) if keys else {k: v for k, v in body.items() if k != "collection_status"}
                    if kind == "ses_email_identity" and isinstance(value.get("DkimAttributes"), dict):
                        value["DkimAttributes"].pop("Tokens", None)
                    item[field] = {**value, "collection_status": "collected"}
            output.append(item)
        return output
    return enrich


def _network_firewall(requests, session, region, items):
    output = []
    for item in _merge_enricher("network_firewall")(requests, session, region, items):
        logging = requests.detail(session, "network-firewall", region, "describe_logging_configuration", FirewallArn=item.get("FirewallArn"))
        if _failed(logging):
            item["LoggingConfiguration"] = {"collection_status": logging.get("collection_status", "unknown"), "error": logging.get("error", {})}
        elif isinstance(logging.get("LoggingConfiguration"), dict):
            item["LoggingConfiguration"] = _pick(logging["LoggingConfiguration"], ("LogDestinationConfigs",))
        else:
            # DescribeLoggingConfiguration omits LoggingConfiguration when no destination is set.
            item["LoggingConfiguration"] = {"LogDestinationConfigs": []}
            _cover(item, "LoggingConfiguration", "empty", reason="documented_optional_api_omission", source_operation="network-firewall:DescribeLoggingConfiguration")
        output.append(item)
    return output


def _firewall_document(operation, argument, response_key, document_key):
    def enrich(requests, session, region, items):
        output = []
        for original in items:
            item = copy.deepcopy(original)
            response = requests.detail(session, "network-firewall", region, operation, **{argument: item.get("Arn")})
            item["id"] = item.get("Arn")
            if _failed(response):
                _mark(item, response, operation)
            elif not isinstance(response.get(response_key), dict) or not isinstance(response.get(document_key), dict):
                _mark(item, {"collection_status": "malformed", "error": {"code": "malformed_detail"}}, operation)
            else:
                # UpdateToken is a write-concurrency token, never kept.
                item[response_key] = copy.deepcopy(response[response_key])
                item[document_key] = copy.deepcopy(response[document_key])
            output.append(item)
        return output
    return enrich


def _launch_template_versions(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        versions = requests.pages(session, "ec2", region, "describe_launch_template_versions", "LaunchTemplateVersions", LaunchTemplateId=item.get("LaunchTemplateId"))
        if versions.status in _OK:
            item["Versions"] = versions.items
        else:
            _cover(item, "Versions", *_cause(versions), source_operation="ec2:DescribeLaunchTemplateVersions")
        output.append(item)
    return output


def _file_shares(requests, session, region, items):
    output = [copy.deepcopy(item) for item in items]
    keys = ("FileShareARN", "FileShareId", "FileShareName", "FileShareStatus", "GatewayARN", "KMSEncrypted", "KMSKey", "EncryptionType", "Path", "Role", "LocationARN",
            "ObjectACL", "ReadOnly", "ClientList", "Squash", "BucketRegion", "AuditDestinationARN", "Authentication", "AccessBasedEnumeration", "SMBACLEnabled")
    for share_type, operation, result_key in (("NFS", "describe_nfs_file_shares", "NFSFileShareInfoList"), ("SMB", "describe_smb_file_shares", "SMBFileShareInfoList")):
        group = {item.get("FileShareARN"): item for item in output if item.get("FileShareType") == share_type and isinstance(item.get("FileShareARN"), str)}
        for chunk in _chunks(sorted(group), 10):
            response = requests.detail(session, "storagegateway", region, operation, FileShareARNList=chunk)
            found = {row.get("FileShareARN"): row for row in response.get(result_key) or [] if isinstance(row, dict)} if not _failed(response) else {}
            for arn in chunk:
                if arn in found:
                    group[arn].update(_pick(found[arn], keys))
                else:
                    _mark(group[arn], response if _failed(response) else {"collection_status": "unknown", "error": {"code": "file_share_detail_missing"}}, operation)
    for item in output:
        if item.get("FileShareType") not in ("NFS", "SMB"):
            _mark(item, {"collection_status": "not_collected", "error": {"code": "unsupported_file_share_type"}}, "list_file_shares")
    return output


# ----------------------------------------------- enrichers on existing inventories

def _query_logging(requests, session, region, items):
    configs = requests.pages(session, "route53", region, "list_query_logging_configs", "QueryLoggingConfigs")
    output = []
    for original in items:
        item = copy.deepcopy(original)
        zone = str(item.get("Id", "")).rsplit("/", 1)[-1]
        if configs.status in _OK:
            rows = [row for row in configs.items if isinstance(row, dict) and row.get("HostedZoneId") == zone]
            item["QueryLoggingConfigs"] = {"collection_status": "collected", "QueryLoggingConfigs": rows}
        else:
            status, error = _cause(configs)
            item["QueryLoggingConfigs"] = {"collection_status": status, "error": error}
        output.append(item)
    return output


def _managed_instance_compliance(requests, session, region, items):
    # One account-wide summary read (shared with ssm_resource_compliance_summary)
    # instead of a per-instance ListComplianceItems loop.
    projection = "ResourceComplianceSummaryItems[].{ResourceId: ResourceId, ResourceType: ResourceType, ComplianceType: ComplianceType, Status: Status, OverallSeverity: OverallSeverity}"
    summaries = requests.pages(session, "ssm", region, "list_resource_compliance_summaries", projection)
    output = []
    for original in items:
        item = copy.deepcopy(original)
        if summaries.status in _OK:
            rows = [{"Id": row.get("ResourceId"), "ComplianceType": row.get("ComplianceType"), "Status": row.get("Status"), "Severity": row.get("OverallSeverity")}
                    for row in summaries.items if isinstance(row, dict) and row.get("ResourceType") == "ManagedInstance" and row.get("ResourceId") == item.get("InstanceId")]
            item["ComplianceItems"] = {"collection_status": "collected", "ComplianceItems": rows, "source_operation": "ssm:ListResourceComplianceSummaries"}
        else:
            status, error = _cause(summaries)
            item["ComplianceItems"] = {"collection_status": status, "error": error}
        output.append(item)
    return output


_AUTOMATION_LOG_SETTING = "/ssm/automation/customer-script-log-destination"


def _automation_log_setting(requests, session, region, items):
    output = [copy.deepcopy(item) for item in items]
    response = requests.detail(session, "ssm", region, "get_service_setting", SettingId=_AUTOMATION_LOG_SETTING)
    row = {"id": f"ssm-service-setting{_AUTOMATION_LOG_SETTING}", "RequestedSettingId": _AUTOMATION_LOG_SETTING}
    if _failed(response) or not isinstance(response.get("ServiceSetting"), dict):
        _mark(row, response if _failed(response) else {"collection_status": "malformed"}, "get_service_setting")
    else:
        row["ServiceSetting"] = _pick(response["ServiceSetting"], ("SettingId", "SettingValue", "Status", "LastModifiedDate", "ARN"))
    output.append(row)
    return output


# Non-secret engine flags only: TLS enforcement, audit and log switches.
_RDS_PARAMETERS = {"rds.force_ssl", "require_secure_transport", "ssl", "tls_version", "server_audit_logging", "server_audit_events", "server_audit_excl_users",
                   "log_connections", "log_disconnections", "log_statement", "log_min_duration_statement", "pgaudit.log", "pgaudit.role",
                   "general_log", "slow_query_log", "log_output", "audit_logs", "tls", "neptune_enable_audit_log", "rds.restrict_password_commands"}
_REDSHIFT_PARAMETERS = {"require_ssl", "enable_user_activity_logging", "use_fips_ssl"}


def _parameter_values(requests, session, region, service, operation, argument, group, allowed):
    read = requests.pages(session, service, region, operation, "Parameters[].{ParameterName: ParameterName, ParameterValue: ParameterValue}", **{argument: group})
    if read.status not in _OK:
        return None, _cause(read)
    return {row["ParameterName"]: row["ParameterValue"] for row in read.items
            if isinstance(row, dict) and row.get("ParameterName") in allowed and isinstance(row.get("ParameterValue"), str)}, None


def _rds_parameters(field, operation, argument, groups_of):
    def enrich(requests, session, region, items):
        output = []
        for original in items:
            item = copy.deepcopy(original)
            groups = groups_of(item)
            if len(groups) != 1:
                _cover(item, field, "malformed", {"code": "parameter_group_not_unique"})
            else:
                values, failure = _parameter_values(requests, session, region, "rds", operation, argument, groups[0], _RDS_PARAMETERS)
                if failure:
                    _cover(item, field, *failure)
                else:
                    item[field] = values
            output.append(item)
        return output
    return enrich


def _instance_groups(item):
    groups = item.get("DBParameterGroups")
    return [group.get("DBParameterGroupName") for group in groups if isinstance(group, dict) and isinstance(group.get("DBParameterGroupName"), str)] if isinstance(groups, list) else []


def _cluster_groups(item):
    group = item.get("DBClusterParameterGroup")
    return [group] if isinstance(group, str) else []


def _redshift_facts(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        logging = requests.detail(session, "redshift", region, "describe_logging_status", ClusterIdentifier=item.get("ClusterIdentifier"))
        item["LoggingStatus"] = logging if _failed(logging) else _pick(logging, ("LoggingEnabled", "BucketName", "S3KeyPrefix", "LogDestinationType", "LogExports", "collection_status"))
        groups = [group.get("ParameterGroupName") for group in item.get("ClusterParameterGroups") or [] if isinstance(group, dict) and isinstance(group.get("ParameterGroupName"), str)]
        if len(groups) != 1:
            _cover(item, "ParameterGroupValues", "malformed", {"code": "parameter_group_not_unique"})
        else:
            values, failure = _parameter_values(requests, session, region, "redshift", "describe_cluster_parameters", "ParameterGroupName", groups[0], _REDSHIFT_PARAMETERS)
            if failure:
                _cover(item, "ParameterGroupValues", *failure)
            else:
                item["ParameterGroupValues"] = values
        output.append(item)
    return output


# Non-secret Glue job switches. Free-form arguments (connection strings,
# credentials, script parameters) are never stored.
_GLUE_FLAGS = {"--encryption-type", "--enable-continuous-cloudwatch-log", "--enable-continuous-log-filter", "--enable-spark-ui", "--enable-metrics",
               "--enable-observability-metrics", "--enable-job-insights", "--enable-glue-datacatalog", "--job-bookmark-option", "--job-language",
               "--enable-auto-scaling", "--continuous-log-logGroup"}
_GLUE_CODE_ARGUMENTS = frozenset({"--scriptLocation", "--extra-py-files", "--extra-jars",
                                  "--additional-python-modules", "--python-virtual-env"})


def _glue_job_flags(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        defaults = item.pop("DefaultArguments", None)
        fixed = item.pop("NonOverridableArguments", None)
        if (defaults is not None and not isinstance(defaults, dict)) or (fixed is not None and not isinstance(fixed, dict)):
            _cover(item, "DefaultArgumentFlags", "malformed", {"code": "malformed_job_arguments"})
        else:
            merged = {**(defaults or {}), **(fixed or {})}
            item["DefaultArgumentFlags"] = {key: value for key, value in merged.items() if key in _GLUE_FLAGS and isinstance(value, str)}
            # Only known argument names are retained. Their values can contain credentials or private paths.
            item["DefaultCodeArguments"] = sorted(_GLUE_CODE_ARGUMENTS.intersection(defaults or {}))
            item["NonOverridableCodeArguments"] = sorted(_GLUE_CODE_ARGUMENTS.intersection(fixed or {}))
        output.append(item)
    return output


def _glue_trigger_names(requests, session, region, items):
    # Trigger Actions can contain job arguments and secrets. Keep only metadata needed to bind a run to a job.
    output = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("Name"), str):
            output.append({"collection_status": "malformed"})
            continue
        actions = item.get("Actions")
        output.append({
            "Name": item["Name"], "Type": item.get("Type"), "State": item.get("State"),
            "HasSchedule": isinstance(item.get("Schedule"), str) and bool(item["Schedule"]),
            "JobActions": [action["JobName"] for action in actions
                           if isinstance(action, dict) and isinstance(action.get("JobName"), str)]
                          if isinstance(actions, list) else None,
            "ActionsComplete": isinstance(actions, list) and all(isinstance(action, dict) for action in actions),
            "ScriptOverrideJobActions": [action.get("JobName") for action in actions
                                         if isinstance(action, dict) and isinstance(action.get("JobName"), str)
                                         and isinstance(action.get("Arguments"), dict)
                                         and "--scriptLocation" in action["Arguments"]]
                                        if isinstance(actions, list) else None,
            "ActionArgumentsComplete": isinstance(actions, list) and all(
                isinstance(action, dict) and (action.get("Arguments") is None or
                                              isinstance(action.get("Arguments"), dict)) for action in actions),
        })
    return output


def _glue_session_ids(requests, session, region, items):
    return [{key: row[key] for key in ("Id", "Role", "Status") if key in row}
            if isinstance(row, dict) and isinstance(row.get("Id"), str) and row["Id"]
            else {"collection_status": "malformed"} for row in items]


def _bucket_website(requests, session, region, items):
    output = []
    for original in items:
        item = copy.deepcopy(original)
        location = item.get("Location") if isinstance(item.get("Location"), dict) else {}
        selected = location.get("LocationConstraint") or region
        if location.get("collection_status") in (None, "collected"):
            selected = "eu-west-1" if selected == "EU" else selected
            if location.get("LocationConstraint") is None:
                selected = "us-east-1"
        website = requests.detail(session, "s3", selected, "get_bucket_website", Bucket=item.get("Name"), absent=("NoSuchWebsiteConfiguration",))
        item["Website"] = website if _failed(website) or website.get("absent") else _pick(website, ("IndexDocument", "ErrorDocument", "RedirectAllRequestsTo", "RoutingRules", "collection_status"))
        output.append(item)
    return output


def _guardduty_detector(requests, session, region, items):
    output = []
    high = {"Criterion": {"severity": {"Eq": ["8"]}, "service.archived": {"Eq": ["false"]}}}
    for original in items:
        item = copy.deepcopy(original)
        detector = item.get("DetectorId")
        item["Administrator"] = requests.detail(session, "guardduty", region, "get_administrator_account", DetectorId=detector)
        members = requests.pages(session, "guardduty", region, "list_members",
                                 "Members[].{AccountId: AccountId, DetectorId: DetectorId, RelationshipStatus: RelationshipStatus, AdministratorId: AdministratorId}", DetectorId=detector)
        item["Members"] = _listing(members)
        item["FindingIds"] = _listing(requests.pages(session, "guardduty", region, "list_findings", "FindingIds", DetectorId=detector))
        item["HighSeverityFindingIds"] = _listing(requests.pages(session, "guardduty", region, "list_findings", "FindingIds", DetectorId=detector, FindingCriteria=high))
        organization = requests.detail(session, "guardduty", region, "describe_organization_configuration", DetectorId=detector)
        item["OrganizationConfiguration"] = _pick(organization, ("AutoEnable", "AutoEnableOrganizationMembers", "MemberAccountLimitReached", "DataSources", "Features", "collection_status", "error"))
        output.append(item)
    return output


def _delegated_administrators(requests, session, region, items):
    read = requests.pages(session, "organizations", region, "list_delegated_administrators",
                          "DelegatedAdministrators[].{Id: Id, Arn: Arn, Name: Name, Status: Status, State: State, JoinedMethod: JoinedMethod, DelegationEnabledDate: DelegationEnabledDate}")
    if read.status not in _OK and not read.items and (read.error or {}).get("code") == "AWSOrganizationsNotInUseException":
        value = {"collection_status": "empty", "absent": True, "error": {"code": "AWSOrganizationsNotInUseException"}}
    else:
        value = _listing(read)
    output = []
    for original in items:
        item = copy.deepcopy(original)
        item["DelegatedAdministrators"] = copy.deepcopy(value)
        output.append(item)
    return output


def _analyzer_findings(requests, session, region, items):
    output = []
    projection = "findings"
    for original in items:
        item = copy.deepcopy(original)
        if item.get("status") == "ACTIVE" and isinstance(item.get("arn"), str):
            if (item.get("type") in {"ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS"}
                    and not item.get("configuration") and isinstance(item.get("name"), str)):
                configuration = requests.pages(session, "accessanalyzer", region, "get_analyzer", "[analyzer]",
                    analyzerName=item["name"])
                if configuration.status in _OK and len(configuration.items) == 1 and isinstance(configuration.items[0], dict) and configuration.items[0].get("arn") == item["arn"]:
                    item.update(copy.deepcopy(configuration.items[0]))
                elif configuration.status in _OK:
                    _cover(item, "configuration", "malformed", {"code": "invalid_analyzer_response"}, source_operation="access-analyzer:GetAnalyzer")
                else:
                    _cover(item, "configuration", *_cause(configuration), source_operation="access-analyzer:GetAnalyzer")
            findings = requests.pages(session, "accessanalyzer", region, "list_findings_v2", projection, analyzerArn=item["arn"], filter={"status": {"eq": ["ACTIVE"]}})
            # Retain every returned summary, including timestamps and any positive
            # evidence obtained before a pagination failure or collection limit.
            item["Findings"] = copy.deepcopy(findings.items)
            if findings.status not in _OK:
                _cover(item, "Findings", *_cause(findings), source_operation="access-analyzer:ListFindingsV2")
            for finding in item["Findings"]:
                if not isinstance(finding, dict) or not isinstance(finding.get("id"), str):
                    continue
                detail = requests.pages(session, "accessanalyzer", region, "get_finding_v2", "[@]",
                    analyzerArn=item["arn"], id=finding["id"])
                finding["FindingDetails"] = _listing(detail)
                finding["FindingDetails"]["items"] = []
                for page in detail.items:
                    if not isinstance(page, dict) or page.get("id") != finding["id"] or not isinstance(page.get("findingDetails"), list):
                        finding["FindingDetails"].update(collection_status="malformed", error={"code": "invalid_finding_detail_response"})
                        continue
                    # Keep the current status, timestamps, policy restrictions and
                    # other response metadata, as well as every page of details.
                    finding.update({key: copy.deepcopy(value) for key, value in page.items()
                                    if key not in {"findingDetails", "nextToken", "ResponseMetadata"}})
                    finding["FindingDetails"]["items"].extend(copy.deepcopy(page["findingDetails"]))
                if finding.get("findingType") == "UnusedPermission":
                    finding["UnusedPermissionDetails"] = copy.deepcopy(finding["FindingDetails"])
        output.append(item)
    return output


ENRICHERS = {kind: _merge_enricher(kind) for kind in _MERGES if kind != "network_firewall"}
ENRICHERS.update({kind: _container_enricher(kind) for kind in _CONTAINERS})
ENRICHERS.update({
    "msk_cluster": _msk_public_bootstrap,
    "network_firewall": _network_firewall,
    "network_firewall_policy": _firewall_document("describe_firewall_policy", "FirewallPolicyArn", "FirewallPolicyResponse", "FirewallPolicy"),
    "network_firewall_rule_group": _firewall_document("describe_rule_group", "RuleGroupArn", "RuleGroupResponse", "RuleGroup"),
    "ec2_launch_template": _launch_template_versions,
    "storagegateway_file_share": _file_shares,
    # Existing inventories (chained after earlier enrichers by the loader).
    "route53_zone": _query_logging,
    "ssm_managed_instance": _managed_instance_compliance,
    "ssm_service_settings": _automation_log_setting,
    "rds_instance": _rds_parameters("ParameterGroupValues", "describe_db_parameters", "DBParameterGroupName", _instance_groups),
    "rds_cluster": _rds_parameters("ClusterParameterGroupValues", "describe_db_cluster_parameters", "DBClusterParameterGroupName", _cluster_groups),
    "redshift_cluster": _redshift_facts,
    "glue_job": _glue_job_flags,
    "glue_trigger": _glue_trigger_names,
    "glue_session": _glue_session_ids,
    "bucket": _bucket_website,
    "guardduty_detector": _guardduty_detector,
    "aws_account_configuration": _delegated_administrators,
    "access_analyzer": _analyzer_findings,
})
