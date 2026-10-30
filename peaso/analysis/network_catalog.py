"""Audited network service families, including supporting and declared topology.

Keep this finite catalog independent of collector imports. Its regression tests
require a collection plan and AI projection for every member.
"""
NETWORK_SERVICE_GROUPS = {
    "aws": {
        "application_compute": {"app_runner_service", "app_runner_vpc_connector", "app_runner_vpc_ingress_connection",
            "batch_compute_environment", "autoscaling_group", "elastic_beanstalk_environment", "appstream_fleet",
            "workspaces_workspace", "directory_service_directory", "emr_cluster", "codebuild_project", "ec2_spot_fleet_request", "emr_serverless_application",
            "eks_nodegroup", "eks_fargate_profile", "lightsail_instance", "lightsail_database", "lightsail_load_balancer", "lightsail_container_service", "appsync_graphql_api"},
        "ml_analytics": {"sagemaker_notebook_instance", "sagemaker_domain", "sagemaker_cluster", "sagemaker_endpoint",
            "sagemaker_model", "sagemaker_endpoint_config", "sagemaker_training_job", "sagemaker_processing_job",
            "glue_connection", "glue_dev_endpoint", "dax_cluster", "dax_subnet_group", "redshiftserverless_workgroup",
            "mskconnect_connector", "grafana_workspace", "firehose_delivery_stream", "elasticache_serverless_cache", "aoss_vpc_endpoint",
            "quicksight_vpc_connection", "influxdb_instance", "influxdb_cluster", "osis_pipeline", "datasync_agent", "storagegateway_gateway", "storagegateway_file_share", "cloudhsm_cluster", "kms_external_key_store"},
        "private_service_frontends": {"rest_api", "http_api", "apigateway_vpc_link", "apigatewayv2_vpc_link",
            "s3_access_point", "transfer_server", "transfer_connector", "globalaccelerator_accelerator", "elbv2_listener", "dms_endpoint", "apigateway_domain_name",
            "globalaccelerator_listener", "globalaccelerator_endpoint_group", "lattice_service_network", "lattice_service",
            "lattice_vpc_association", "lattice_service_association", "lattice_resource_gateway", "lattice_target_group", "lattice_resource_configuration", "lattice_resource_association", "lattice_listener", "lattice_listener_rule",
            "verified_access_endpoint", "verified_access_group", "verified_access_instance"},
        "dns_hybrid": {"flow_log", "managed_prefix_list", "resolver_endpoint", "resolver_rule", "resolver_rule_association", "resolver_firewall_rule_group_association",
            "route53_zone", "route53_record_set", "route53_health_check", "route53_domain", "resolver_firewall_rule", "dhcp_options", "customer_gateway", "directconnect_connection",
            "directconnect_virtual_interface", "directconnect_gateway", "directconnect_gateway_association"},
    },
    "azure": {
        "application_compute": {"container_app", "container_app_environment", "container_app_job", "registry_agent_pool", "vm_scale_set", "service_fabric_cluster",
            "spring_cloud_service", "integration_service_environment", "logic_app_workflow", "app_service_slot", "ml_compute", "datafactory_managed_vnet", "datafactory_managed_private_endpoint"},
        "data_platform": {"hdinsight_cluster", "healthcare_fhir_service", "hpc_cache", "iot_hub", "bot_service",
            "postgresql_single_server", "mysql_single_server", "mariadb_server", "netapp_account",
            "netapp_capacity_pool", "netapp_volume", "disk_access", "log_analytics_workspace", "application_insights", "redis_enterprise_cluster", "redis_enterprise_database", "automation_account", "iot_dps", "storage_sync_service", "log_analytics_cluster",
            "monitor_private_link_scope", "monitor_scoped_resource", "monitor_data_collection_endpoint"},
        "dns_hybrid": {"synapse_managed_private_endpoint", "load_test_network_test", "hub_bgp_connection", "hub_route_table", "hub_route_map", "hub_vpn_connection", "hub_vpn_link_connection", "hub_expressroute_connection",
            "flow_log", "private_dns_zone", "private_dns_link", "dns_zone", "bastion_host", "local_network_gateway",
            "network_connection", "expressroute_circuit", "virtual_wan", "virtual_hub", "hub_vnet_connection",
            "hub_vpn_gateway", "hub_expressroute_gateway", "vpn_site", "dns_resolver", "dns_inbound_endpoint",
            "dns_outbound_endpoint", "dns_forwarding_ruleset", "dns_forwarding_rule", "dns_forwarding_vnet_link", "private_dns_record_set", "dns_record", "network_watcher", "web_application_firewall_policy", "frontdoor_waf_policy", "traffic_manager_profile"},
    },
    "gcp": {
        "application_compute": {"app_engine_application", "app_engine_service", "app_engine_network_version",
            "dataflow_network_job", "batch_network_job", "instance_group_manager", "instance_template", "autoscaler", "cloudrun_worker_pool", "vertex_endpoint", "target_pool", "target_instance"},
        "private_services": {"redis_cluster", "service_networking_connection", "service_connection_policy",
            "network_connectivity_hub", "network_connectivity_spoke", "netapp_storage_pool", "netapp_volume", "interconnect", "interconnect_attachment",
            "managed_kafka_cluster", "memorystore_instance", "datastream_private_connection", "migration_private_connection"},
        "dns_policy": {"vpc_flow_logs_config", "domains_registration", "dns_managed_zone", "dns_policy", "security_policy", "ssl_policy", "server_tls_policy", "client_tls_policy", "authorization_policy", "dns_record", "dns_record_set"},
        "service_mesh": {"service_mesh", "mesh_gateway", "mesh_endpoint_policy", "mesh_http_route", "mesh_grpc_route", "mesh_tcp_route", "mesh_tls_route"},
    },
    "k8s": {
        "workload_owners": {"deployment", "daemonset", "statefulset", "replicaset", "replicationcontroller", "job", "cronjob", "podtemplate"},
        "routing": {"endpoint", "ingressclass", "gatewayclass", "gateway", "httproute", "grpcroute", "tlsroute",
            "tcproute", "udproute", "referencegrant", "backendtlspolicy", "servicecidr", "ipaddress"},
        "storage": {"storageclass", "csidriver", "csinode", "volumeattachment"},
    },
}
CONTROL_TYPES = {"aws": {"resolver_firewall_rule"}, "k8s": {"cilium_networkpolicy", "cilium_clusterwide_networkpolicy", "calico_networkpolicy",
    "calico_global_networkpolicy", "admin_networkpolicy", "baseline_admin_networkpolicy", "cluster_networkpolicy"},
    "gcp": {"service_perimeter", "security_policy", "firewall_policy_association", "effective_firewall", "policy_based_route", "authorization_policy"},
    "azure": {"web_application_firewall_policy", "frontdoor_waf_policy", "security_admin_rule", "ip_group"}}

# The SDK schema audit also finds aliases, historical resources and evidence
# inventories that reuse a network API. They do not represent additional live
# network assets; keeping the reasons explicit prevents silent omissions.
AWS_SCHEMA_EXCLUSIONS = {
    **dict.fromkeys({"client_vpn_endpoint", "load_balancer_v2", "vpc_peering_connection"},
        "Legacy/import aliases; the canonical native network inventory is requested."),
    **dict.fromkeys({"rds_cluster_snapshot", "rds_snapshot", "redshift_snapshot", "docdb_cluster_snapshot", "neptune_cluster_snapshot"},
        "Historical backup metadata; its VPC is not a current workload attachment."),
    **dict.fromkeys({"aws_tagged_resource", "ec2_effective_ingress", "environment_boundary_link", "environment_workload_resource",
        "recovery_group", "resolver_firewall", "securityhub_finding", "vpc_account_inventory", "msk_compatible_version"},
        "Derived findings, coverage or compliance evidence; native assets are collected separately."),
    "lambda_selected_environment": "Opt-in application-content inspection; native Lambda network configuration is collected separately.",
    **dict.fromkeys({"client_vpn_routing", "ds_directory_share"},
        "Exposure join views over the same native read as the mapped ec2_client_vpn_endpoint and directory_service_directory inventories."),
    "lambda_version": "Published-version records read for invoke-permission exposure; the function's VPC attachment is mapped from lambda_function.",
}

NETWORK_SERVICE_LABELS = {
    "aws": {
        **dict.fromkeys({"app_runner_service", "app_runner_vpc_connector", "app_runner_vpc_ingress_connection"}, "apprunner"),
        **dict.fromkeys(NETWORK_SERVICE_GROUPS["aws"]["ml_analytics"] & {
            "sagemaker_notebook_instance", "sagemaker_domain", "sagemaker_cluster", "sagemaker_endpoint", "sagemaker_model",
            "sagemaker_endpoint_config", "sagemaker_training_job", "sagemaker_processing_job"}, "sagemaker"),
        "batch_compute_environment": "batch", "autoscaling_group": "autoscaling", "elastic_beanstalk_environment": "elasticbeanstalk",
        "appstream_fleet": "appstream", "workspaces_workspace": "workspaces", "directory_service_directory": "ds",
        "emr_cluster": "emr", "codebuild_project": "codebuild", "glue_connection": "glue", "glue_dev_endpoint": "glue",
        "ec2_spot_fleet_request": "ec2", "firehose_delivery_stream": "firehose",
        "eks_nodegroup": "eks", "eks_fargate_profile": "eks", "quicksight_vpc_connection": "quicksight",
        "influxdb_instance": "timestream-influxdb", "influxdb_cluster": "timestream-influxdb", "osis_pipeline": "osis", "datasync_agent": "datasync",
        "storagegateway_gateway": "storagegateway", "storagegateway_file_share": "storagegateway",
        "emr_serverless_application": "emr-serverless", "elasticache_serverless_cache": "elasticache", "aoss_vpc_endpoint": "opensearchserverless",
        **dict.fromkeys({"lattice_service_network", "lattice_service", "lattice_vpc_association", "lattice_service_association", "lattice_resource_gateway"}, "vpc-lattice"),
        "dax_cluster": "dax", "dax_subnet_group": "dax", "redshiftserverless_workgroup": "redshift",
        "mskconnect_connector": "kafkaconnect", "grafana_workspace": "grafana", "rest_api": "apigateway", "http_api": "apigateway",
        "apigateway_vpc_link": "apigateway", "apigatewayv2_vpc_link": "apigateway", "s3_access_point": "s3", "transfer_server": "transfer",
        "transfer_connector": "transfer", **dict.fromkeys({"globalaccelerator_accelerator", "globalaccelerator_listener", "globalaccelerator_endpoint_group"}, "globalaccelerator"),
        "elbv2_listener": "elasticloadbalancing", "dms_endpoint": "dms", "apigateway_domain_name": "apigateway",
        "resolver_firewall_rule": "route53resolver", "route53_health_check": "route53", "route53_domain": "route53domains",
        **dict.fromkeys({"lightsail_instance", "lightsail_database", "lightsail_load_balancer", "lightsail_container_service"}, "lightsail"),
        "appsync_graphql_api": "appsync",
        "cloudhsm_cluster": "cloudhsm", "kms_external_key_store": "kms",
        **dict.fromkeys({"verified_access_endpoint", "verified_access_group", "verified_access_instance"}, "ec2"),
        **dict.fromkeys({"lattice_target_group", "lattice_resource_configuration", "lattice_resource_association", "lattice_listener", "lattice_listener_rule"}, "vpc-lattice"),
        **dict.fromkeys({"resolver_endpoint", "resolver_rule", "resolver_rule_association", "resolver_firewall_rule_group_association"}, "route53resolver"),
        "route53_zone": "route53", "route53_record_set": "route53", "dhcp_options": "ec2", "customer_gateway": "ec2",
        **dict.fromkeys({"directconnect_connection", "directconnect_virtual_interface", "directconnect_gateway", "directconnect_gateway_association"}, "directconnect"),
    },
    "azure": {
        **dict.fromkeys(NETWORK_SERVICE_GROUPS["azure"]["dns_hybrid"], "Microsoft.Network"),
        "synapse_managed_private_endpoint": "Microsoft.Synapse", "load_test_network_test": "Microsoft.LoadTestService",
        "container_app": "Microsoft.App", "container_app_environment": "Microsoft.App", "vm_scale_set": "Microsoft.Compute",
        "container_app_job": "Microsoft.App", "registry_agent_pool": "Microsoft.ContainerRegistry", "redis_enterprise_cluster": "Microsoft.Cache", "redis_enterprise_database": "Microsoft.Cache",
        "service_fabric_cluster": "Microsoft.ServiceFabric", "spring_cloud_service": "Microsoft.AppPlatform",
        "integration_service_environment": "Microsoft.Logic", "logic_app_workflow": "Microsoft.Logic", "app_service_slot": "Microsoft.Web",
        "hdinsight_cluster": "Microsoft.HDInsight", "healthcare_fhir_service": "Microsoft.HealthcareApis", "hpc_cache": "Microsoft.StorageCache",
        "iot_hub": "Microsoft.Devices", "bot_service": "Microsoft.BotService", "postgresql_single_server": "Microsoft.DBforPostgreSQL",
        "mysql_single_server": "Microsoft.DBforMySQL", "mariadb_server": "Microsoft.DBforMariaDB",
        **dict.fromkeys({"netapp_account", "netapp_capacity_pool", "netapp_volume"}, "Microsoft.NetApp"),
        "disk_access": "Microsoft.Compute", "log_analytics_workspace": "Microsoft.OperationalInsights", "application_insights": "Microsoft.Insights",
        "ml_compute": "Microsoft.MachineLearningServices",
        "datafactory_managed_vnet": "Microsoft.DataFactory", "datafactory_managed_private_endpoint": "Microsoft.DataFactory",
        "automation_account": "Microsoft.Automation", "iot_dps": "Microsoft.Devices", "storage_sync_service": "Microsoft.StorageSync",
        "log_analytics_cluster": "Microsoft.OperationalInsights", "monitor_private_link_scope": "Microsoft.Insights",
        "monitor_scoped_resource": "Microsoft.Insights", "monitor_data_collection_endpoint": "Microsoft.Insights",
    },
    "gcp": {"vpc_flow_logs_config": "networkmanagement", "domains_registration": "domains", "app_engine_application": "appengine", "app_engine_service": "appengine", "app_engine_network_version": "appengine",
        "dataflow_network_job": "dataflow", "batch_network_job": "batch", "instance_group_manager": "compute", "instance_template": "compute",
        "autoscaler": "compute", "target_pool": "compute", "target_instance": "compute",
        "cloudrun_worker_pool": "run", "vertex_endpoint": "aiplatform", "managed_kafka_cluster": "managedkafka", "memorystore_instance": "memorystore",
        "datastream_private_connection": "datastream", "migration_private_connection": "datamigration",
        "redis_cluster": "redis", "service_networking_connection": "servicenetworking", "service_connection_policy": "networkconnectivity",
        "network_connectivity_hub": "networkconnectivity", "network_connectivity_spoke": "networkconnectivity",
        "interconnect": "compute", "interconnect_attachment": "compute",
        "netapp_storage_pool": "netapp", "netapp_volume": "netapp", "dns_managed_zone": "dns", "dns_policy": "dns",
        "security_policy": "compute", "ssl_policy": "compute", "server_tls_policy": "networksecurity"},
}
from pathlib import Path
import json
_AWS_NATIVE_NETWORK_PLANS = json.loads((Path(__file__).parents[1] / "collectors" / "aws_network_inventory.json").read_text())
NETWORK_SERVICE_GROUPS["aws"]["native_vpc_workloads"] = set(_AWS_NATIVE_NETWORK_PLANS)
NETWORK_SERVICE_LABELS["aws"].update({kind: plan["service"] for kind, plan in _AWS_NATIVE_NETWORK_PLANS.items()})
_AZURE_PRIVATE_SERVICES = json.loads((Path(__file__).parents[1] / "collectors" / "azure_network_private_services.json").read_text())
NETWORK_SERVICE_GROUPS["azure"]["private_service_targets"] = set(_AZURE_PRIVATE_SERVICES)
_AZURE_PRIVATE_CHILDREN = json.loads((Path(__file__).parents[1] / 'collectors/azure_network_private_children.json').read_text())
NETWORK_SERVICE_GROUPS['azure']['private_service_children'] = set(_AZURE_PRIVATE_CHILDREN)
# DPS compliance observations intentionally contain identities only. The network
# reader carries the full native provisioning-service network configuration.
NETWORK_SERVICE_GROUPS['azure']['data_platform'].discard('iot_dps')
NETWORK_SERVICE_GROUPS['azure']['private_service_children'].update({'cassandra_data_center', 'grafana_managed_private_endpoint', 'elastic_san_volume_group'})
NETWORK_SERVICE_LABELS['azure'].update({kind: 'Microsoft.ServiceNetworking' if kind.startswith('traffic_controller_') else
    'Microsoft.HealthcareApis' if kind.startswith('healthcare_') else 'Microsoft.Kusto' for kind in _AZURE_PRIVATE_CHILDREN})
NETWORK_SERVICE_LABELS['azure'].update({'cassandra_data_center': 'Microsoft.DocumentDB', 'grafana_managed_private_endpoint': 'Microsoft.Dashboard', 'elastic_san_volume_group': 'Microsoft.ElasticSan'})
NETWORK_SERVICE_LABELS["azure"].update({kind: row["resource_type"].split('/')[0] for kind, row in _AZURE_PRIVATE_SERVICES.items()})
_GCP_PRIVATE_SERVICES = json.loads((Path(__file__).parents[1] / "collectors" / "gcp_network_private_services.json").read_text())
NETWORK_SERVICE_GROUPS["gcp"]["private_service_workloads"] = set(_GCP_PRIVATE_SERVICES)
NETWORK_SERVICE_LABELS["gcp"].update({kind: row["service"] for kind, row in _GCP_PRIVATE_SERVICES.items()})
_K8S_NETWORK_EXTENSIONS = json.loads((Path(__file__).parents[1] / "collectors" / "k8s_network_extensions.json").read_text())
_K8S_NETWORK_EXTENSIONS.update(json.loads((Path(__file__).parents[1] / "collectors" / "k8s_network_route_extensions.json").read_text()))
NETWORK_SERVICE_GROUPS['k8s']['cni_load_balancer_mesh'] = set(_K8S_NETWORK_EXTENSIONS)

NETWORK_SERVICE_LABELS["gcp"].update(dict.fromkeys(NETWORK_SERVICE_GROUPS["gcp"]["service_mesh"], "networkservices"))
NETWORK_SERVICE_LABELS["gcp"].update({"client_tls_policy": "networksecurity", "authorization_policy": "networksecurity", "dns_record": "dns", "dns_record_set": "dns"})

# Positive projection extensions; no job payloads, container settings, SQL,
# credentials, connection strings, HTTP headers or arbitrary template values.
NETWORK_FIELDS = set("""
NetworkDetails NetworkConfig VpcConfiguration EgressConfiguration IngressConfiguration VpcConnectorArn
ClientVpnEndpointId TargetSubnet DestinationCidr
exportPolicy exportRules accessRules allowedClients deniedClients accessType rootSquash squashMode
sourceIpAddresses destinationIpAddresses sourceIpRanges destinationIpRanges sourceIp destinationIp
services upstreams includes delegate entryPoints entrypoints serviceName virtualHost fqdn
targetRefs targetRef requiredAuthenticationRefs server client networks unauthenticated mtls mode
layer2 layer3 topology role primaryNetwork subnetSelector podSelector namespaceSelector
gkeCluster onPremCluster multiCloudCluster resourceLink executionConfigs privatePool membership
targetResourceId DestinationType TrafficType MaxAggregationInterval LogFormat
cniVersion master bridge vlan mtu plugins ipam ranges rangeStart rangeEnd gateway routes dst gw addresses
Target Targets EcsParameters TaskDefinitionArn InvocationEndpoint ConnectionArn
nextHops nextHop nextHopType nextHopIpAddress destinationType routeTables routeMaps bgpConnections bgpPeer
virtualRouterAsn virtualRouterIps circuit expressRouteID networkBlock replicaSets masterProfile workerProfiles
fabricProfile filesystemSubnet delegatedManagementSubnetId
PrefixListId PrefixListName AddressFamily Entries Cidr PrefixListIds OwnerId OwnerAccountId
FlowLogId FlowLogStatus DeliverLogsStatus TrafficType ResourceId LogDestination LogDestinationType LogFormat
toEndpoints fromEndpoints toCIDR fromCIDR toCIDRSet fromCIDRSet toEntities fromEntities toFQDNs
fromRequires toRequires toServices k8sService k8sServiceSelector serviceName selector endpointRoutes
matchPattern matchName dns icmps fields family
nets notNets notSelector notPorts notProtocol source destination order preDNAT doNotTrack applyOnForward ipVersion
excludeCIDRs selectors egressGateway egressIP interface interfaces nicSelector allocationMode serviceSelector
bgpInstances bgpPeers localASN peerASN peerAddress peerPort gracefulRestart families advertisements poolSelectors
ipPools blocks start end autoAssign avoidBuggyIPs natOutgoing ipipMode vxlanMode disabled blockSize allowedUses
nodeSelectors serviceSelectors endpointSelector endpointSelectors externalIPPool externalIPPoolSelector
appliedTo ipBlock except cidr matchLabels matchExpressions matchIndex networkSelector podSelector namespaceSelector
hosts http tcp tls route destination subset workloadSelector captureMode portLevelSettings trafficPolicy
connectionPool outlierDetection meshExternal resolution exportTo locality targetPorts bind
VpcIngressConnectionArn ServiceArn ServiceUrl ServiceId VpcEndpointId VpcEndpointIds vpcEndpointIds
VpcIngressConnectionName VpcConnectorName Subnets SecurityGroupIdList VpcSecurityGroupIds
PhysicalConnectionRequirements NetworkSettings computeResources VPCZoneIdentifier AvailabilityZone
NetworkInterfaces EndpointDetails Server networkConfig vpc network subnetwork NetworkConfiguration
EndpointConfigName EndpointName ProductionVariants ModelName EndpointArn DirectInternetAccess AppNetworkAccessType
AppNetworkAccessType DirectInternetAccess EnableNetworkIsolation EnableInterContainerTrafficEncryption
Ec2InstanceAttributes Ec2SubnetId RequestedEc2SubnetIds EmrManagedMasterSecurityGroup EmrManagedSlaveSecurityGroup
ServiceAccessSecurityGroup AdditionalMasterSecurityGroups AdditionalSlaveSecurityGroups
subnetGroupName SubnetGroup SubnetIdentifier VpcEndpointServiceName SecurityGroupMemberships
securityGroupId VpcEndpoint ingressConfiguration egressConfiguration connectionId connectionType
ConnectionType ConnectionId VpcLinkId VpcLinkStatus connectionType connectionId targetArns endpointConfiguration
NetworkOrigin Alias HostedZoneId VPCs VPCRegion VPCId ResolverEndpointId ResolverRuleId ResolverRuleAssociations
Direction IpAddresses IpAddressCount ResolverRuleType RuleType TargetIps DnsName dnsName DHCPOptionsId
DhcpConfigurations DhcpOptionsId directConnectGatewayId virtualGatewayId associatedGateway associationState
directConnectGatewayAssociationId virtualInterfaceId connectionId virtualGatewayId directConnectGatewayId
AcceleratorArn ListenerArn EndpointGroupArn EndpointDescriptions EndpointId EndpointRegion
NetworkType IpAddressType IpSets IpAddresses HealthState HealthReason ListenerArn PortRanges FromPort ToPort
NetworkProfile ipConfigurations infrastructureSubnetId managedEnvironmentId environmentId vnetConfiguration
external allowInsecure targetPort exposedPort transport customDomains workloadProfiles
hubVirtualNetworkConnections remoteVirtualNetwork virtualHub virtualWan virtualNetworkGateway1 virtualNetworkGateway2
peer localNetworkGateway1 localNetworkGateway2 expressRouteCircuit subnetId subnet delegatedSubnetId
addressPrefixes addressPrefix addressSpace connectionType connectionStatus gatewayIpAddress
linkedVirtualNetworkType virtualNetworkLink registrationEnabled virtualNetworkLinks inboundEndpoints outboundEndpoints
forwardingRules outboundEndpoint dnsResolver dnsForwardingRuleset vpnSites ipAddress localAddress
poolId networkFeatures protocolTypes mountTargets creationToken serviceLevel throughputMibps
publicNetworkAccessForIngestion publicNetworkAccessForQuery networkAccessPolicy privateEndpointConnections
appEngine serviceName servingStatus env network instanceIpMode vpcAccessConnector
allocationPolicy networkInterfaces noExternalIpAddress ipConfiguration workerPools workerPool networkConfig
peerNetwork peering peeredNetworkIpRange reservedPeeringRanges service networkingConfig
pscConfigs pscAutoConnections pscConnections producerNetwork consumerNetwork connectionType
linkedVpnTunnels linkedInterconnectAttachments linkedVpcs linkedRouterApplianceInstances uris
spokeType hub linkedVpcNetwork subnetworks ipCidrRange forwardingConfig targetNameServers ipv4Address
privateVisibilityConfig networks peeringConfig targetNetwork enableInboundForwarding enableLogging
rules priority action match srcIpRanges destIpRanges layer4Configs ipProtocol ports
spec metadata status template jobTemplate selector matchLabels matchExpressions ownerReferences
uid name namespace apiVersion kind controller serviceName serviceAccountName podSelector namespaceSelector
containers initContainers ports containerPort hostPort protocol hostNetwork nodeName nodeSelector
subsets addresses notReadyAddresses targetRef nodeName endpoints hostname ip
parentRefs backendRefs backendRef gatewayClassName controllerName listeners allowedRoutes namespaces from to
sectionName group kind name namespace port weight hostnames addresses routes conditions type status reason
provisioner parameters volumeBindingMode allowedTopologies topologyKeys drivers nodeID topology
attacher nodeName source persistentVolumeName podInfoOnMount attachRequired volumeLifecycleModes
network domainName suffixMatch publicZone forwardingTargets target localData privateZone
HostVPCId VpcSettings SubnetGroupName EndpointGroupRegion networkUrl peeredNetwork interconnect storageClassName
backend externalName subnetId storagePool NetworkInterfaceId networkInterfaces defaultBackend ingressClassName environment
firewallPolicy Ec2InstanceAttributes VpcSettings SecurityGroupMemberships LaunchSpecifications LaunchTemplateConfigs
LaunchTemplateSpecification Overrides VpcConfig SubnetGroupName Destinations AmazonopensearchserviceDestinationDescription
ElasticsearchDestinationDescription AmazonOpenSearchServerlessDestinationDescription VpcConfiguration VpcEndpointId
IngressVpcConfiguration SecurityGroupIdentifier Ip Ipv6 associatedGateway ownerAccount
vpcOwnerId serviceNetworkArn serviceNetworkId serviceArn serviceId resourceGatewayId application networkConfiguration
privateServiceConnectConfig privateEndpoints dedicatedEndpointDns publicPredictionDomainName gcpConfig accessConfig networkConfigs
connections pscAutoConnection pscConnection virtualNetworkSubnetResourceId types disableExecuteApiEndpoint
networkInterfaceIds kafkaCluster apacheKafkaCluster
vpcSubnetIds vpcSecurityGroupIds publiclyAccessible nodegroupArn nodegroupName fargateProfileArn fargateProfileName
remoteAccess sourceSecurityGroups ec2SshKey resources autoScalingGroups clusterName
PrivateLinkConfig SubnetArns SecurityGroupArns PrivateLinkEndpoint VpcEndpoints VpcEndpointService
GatewayNetworkInterfaces Ipv4Address Ipv6Address MacAddress Ec2InstanceId Ec2InstanceRegion VPCEndpoint GatewayARN
FileShareARN NFSFileShareInfoList SMBFileShareInfoList DnsResolvers VPCConnectionId VPCConnectionArn
PipelineName PipelineArn IngestEndpointUrls VpcEndpointManagement VpcAttachmentOptions AttachToVpc
PrivateZone
configuration ipSecurityRestrictions ipAddressRange clientCertificateMode additionalPortMappings
integrationServiceEnvironment environmentResourceId
resourceMethods methodIntegration NetworkResources NetworkIntegrations httpMethod IntegrationUri IntegrationId ConnectionId ConnectionType
LoadBalancerArn SslPolicy MutualAuthentication Mode TrustStoreArn IgnoreClientCertificateExpiry Certificates CertificateArn
HealthCheckConfig IPAddress FullyQualifiedDomainName ServerName DomainName NameServers GlueIps ResourceRecords Value TTL
regionalDomainName distributionDomainName endpointConfiguration FirewallRuleGroupId FirewallDomainListId Action Priority BlockResponse Qtype
ConfigurationSettings OptionSettings Namespace OptionName DeploymentStatus
resourceConfigurationId resourceConfigurationArn ResourceConfigurationArn resourceConfigurationGroupId
ServiceNetworkArn resourceConfigurationDefinition dnsResource domainName ipResource ipAddress arnResource
targetGroupId targetGroupArn vpcIdentifier serviceArns portRanges NetworkTargets target
publicIpAddress privateIpAddress ipv6Addresses dnsName publicPorts instancePort instanceProtocol
relationalDatabaseArn relationalDatabaseName masterEndpoint publiclyAccessible isSslEnabled
currentDeployment nextDeployment publicEndpoint containerName containerPort healthCheck domainName domainNames
privateRegistryAccess visibility uris GRAPHQL REALTIME
networkSettings privateIpAddress publicIpAddress privateDnsZoneArmResourceId privateDnsZoneId
targetDnsServers forwardingRuleState outboundEndpoints metadata
aRecords aaaaRecords cnameRecord mxRecords ptrRecords soaRecord srvRecords fqdn ttl TTL
ipv4Address ipv6Address cname exchange ptrdname priority weight target port host email serialNumber
mesh meshes gateways destinations serviceName serverTlsPolicy clientTlsPolicy authorizationPolicy
endpointMatcher metadataLabelMatcher metadataLabels trafficPortSelector trafficPorts interceptionPort
targetRefs validation wellKnownCACertificates caCertificateRefs subjectAltNames dnsNames
allowOpen mtlsPolicy clientValidationCa clientCertificate serverCertificate certificateProviderInstance pluginInstance instanceName
dnsName skipValidation
defaultAction forward targetGroups targetGroupIdentifier listenerArn httpMatch pathMatch exact prefix method
dnsResolverOutboundEndpoints
targetDnsServers forwardingRuleState rrdatas managedZone ApplicationName EnvironmentName EnvironmentId
managedNetwork isolationMode outboundRules destination serviceResourceId subresourceTarget fqdns groupId connectionState
labelName labelValue metadataLabelMatchCriteria
url publicDomainNames instanceHealthSummary instanceName CNAME EndpointURL
vpcPeeringConfig pscInterfaceConfig reservedPublicIpConfig
linkedResourceId accessModeSettings ingestionAccessMode queryAccessMode exclusions privateEndpointConnectionName
logsIngestion metricsIngestion configurationAccess cidrs parentRef resource
SecurityGroup SubnetMapping Hsms HsmId ClusterId EniId EniIp EniIpV6
VerifiedAccessEndpointId VerifiedAccessGroupId VerifiedAccessInstanceId LoadBalancerOptions NetworkInterfaceOptions CidrOptions
EndpointDomain ApplicationDomain DomainCertificateArn PolicyEnabled
CustomKeyStoreId CustomKeyStoreName CustomKeyStoreType CloudHsmClusterId XksProxyConfiguration UriEndpoint VpcEndpointServiceName
privateEnvironmentConfig enablePrivateEnvironment enablePrivateBuildsOnly cloudSqlIpv4CidrBlock webServerIpv4CidrBlock
cloudComposerConnectionSubnetwork privateClusterConfig privateEndpoint reservedIpRange
""".split())
