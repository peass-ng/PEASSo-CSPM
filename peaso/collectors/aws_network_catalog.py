"""Additional native network service metadata, using the shared read scheduler."""

SPECS = {
    "cloudhsm_cluster": ("cloudhsmv2", "describe_clusters", "Clusters"),
    "verified_access_endpoint": ("ec2", "describe_verified_access_endpoints", "VerifiedAccessEndpoints"),
    "verified_access_group": ("ec2", "describe_verified_access_groups", "VerifiedAccessGroups"),
    "verified_access_instance": ("ec2", "describe_verified_access_instances", "VerifiedAccessInstances"),
    "lightsail_load_balancer": ("lightsail", "get_load_balancers", "loadBalancers"),
    "lightsail_container_service": ("lightsail", "get_container_services", "containerServices"),
    "lattice_target_group": ("vpc-lattice", "list_target_groups", "items"),
    "lattice_resource_configuration": ("vpc-lattice", "list_resource_configurations", "items"),
    "lattice_resource_association": ("vpc-lattice", "list_service_network_resource_associations", "items"),
    "lattice_listener": ("vpc-lattice", "list_listeners", "items"),
    "lattice_listener_rule": ("vpc-lattice", "list_rules", "items"),
    "quicksight_vpc_connection": ("quicksight", "list_vpc_connections", "VPCConnectionSummaries"),
    "influxdb_instance": ("timestream-influxdb", "list_db_instances", "items"),
    "osis_pipeline": ("osis", "list_pipelines", "Pipelines"),
    "datasync_agent": ("datasync", "list_agents", "Agents"),
    "eks_nodegroup": ("eks", "list_nodegroups", "nodegroups"),
    "eks_fargate_profile": ("eks", "list_fargate_profiles", "fargateProfileNames"),
    "elasticache_serverless_cache": ("elasticache", "describe_serverless_caches", "ServerlessCaches"),
    "aoss_vpc_endpoint": ("opensearchserverless", "list_vpc_endpoints", "vpcEndpointSummaries"),
    "emr_serverless_application": ("emr-serverless", "list_applications", "applications"),
    "lattice_service_network": ("vpc-lattice", "list_service_networks", "items"),
    "lattice_service": ("vpc-lattice", "list_services", "items"),
    "lattice_vpc_association": ("vpc-lattice", "list_service_network_vpc_associations", "items"),
    "lattice_service_association": ("vpc-lattice", "list_service_network_service_associations", "items"),
    "lattice_resource_gateway": ("vpc-lattice", "list_resource_gateways", "items"),
    "app_runner_service": ("apprunner", "list_services", "ServiceSummaryList"),
    "app_runner_vpc_connector": ("apprunner", "list_vpc_connectors", "VpcConnectors"),
    "app_runner_vpc_ingress_connection": ("apprunner", "list_vpc_ingress_connections", "VpcIngressConnectionSummaryList"),
    "apigateway_vpc_link": ("apigateway", "get_vpc_links", "items"),
    "apigatewayv2_vpc_link": ("apigatewayv2", "get_vpc_links", "Items"),
    "resolver_endpoint": ("route53resolver", "list_resolver_endpoints", "ResolverEndpoints"),
    "resolver_rule": ("route53resolver", "list_resolver_rules", "ResolverRules"),
    "resolver_rule_association": ("route53resolver", "list_resolver_rule_associations", "ResolverRuleAssociations"),
    "customer_gateway": ("ec2", "describe_customer_gateways", "CustomerGateways"),
    "dax_subnet_group": ("dax", "describe_subnet_groups", "SubnetGroups"),
    "directconnect_gateway": ("directconnect", "describe_direct_connect_gateways", "directConnectGateways"),
    "directconnect_gateway_association": ("directconnect", "describe_direct_connect_gateway_associations", "directConnectGatewayAssociations"),
    "globalaccelerator_listener": ("globalaccelerator", "list_listeners", "Listeners"),
    "globalaccelerator_endpoint_group": ("globalaccelerator", "list_endpoint_groups", "EndpointGroups"),
}
NATIVE_IDS = {
    "cloudhsm_cluster": "ClusterId", "verified_access_endpoint": "VerifiedAccessEndpointId",
    "verified_access_group": "VerifiedAccessGroupId", "verified_access_instance": "VerifiedAccessInstanceId",
    "lightsail_load_balancer": "arn", "lightsail_container_service": "arn",
    "lattice_target_group": "id", "lattice_resource_configuration": "id", "lattice_resource_association": "id",
    "lattice_listener": "arn", "lattice_listener_rule": "arn",
    "quicksight_vpc_connection": "Arn", "influxdb_instance": "arn", "osis_pipeline": "PipelineArn",
    "datasync_agent": "AgentArn", "eks_nodegroup": "nodegroupArn", "eks_fargate_profile": "fargateProfileArn",
    "elasticache_serverless_cache": "ARN", "aoss_vpc_endpoint": "id", "emr_serverless_application": "id",
    **dict.fromkeys({"lattice_service_network", "lattice_service", "lattice_vpc_association", "lattice_service_association", "lattice_resource_gateway"}, "id"),
    "app_runner_service": "ServiceArn", "app_runner_vpc_connector": "VpcConnectorArn",
    "app_runner_vpc_ingress_connection": "VpcIngressConnectionArn", "apigateway_vpc_link": "id",
    "apigatewayv2_vpc_link": "VpcLinkId", "resolver_endpoint": "Id", "resolver_rule": "Id",
    "resolver_rule_association": "Id", "customer_gateway": "CustomerGatewayId", "dax_subnet_group": "SubnetGroupName",
    "directconnect_gateway": "directConnectGatewayId", "directconnect_gateway_association": "directConnectGatewayAssociationId",
    "globalaccelerator_listener": "ListenerArn", "globalaccelerator_endpoint_group": "EndpointGroupArn",
}
GLOBAL_TYPES = {"globalaccelerator_listener", "globalaccelerator_endpoint_group"}
# kind: service, operation, argument, native identity field, response root
DETAILS = {
    "lattice_target_group": ("vpc-lattice", "get_target_group", "targetGroupIdentifier", "id", None),
    "lattice_resource_configuration": ("vpc-lattice", "get_resource_configuration", "resourceConfigurationIdentifier", "id", None),
    "route53_zone": ("route53", "get_hosted_zone", "Id", "Id", None),
    "influxdb_instance": ("timestream-influxdb", "get_db_instance", "identifier", "id", None),
    "osis_pipeline": ("osis", "get_pipeline", "PipelineName", "PipelineName", "Pipeline"),
    "datasync_agent": ("datasync", "describe_agent", "AgentArn", "AgentArn", None),
    "storagegateway_gateway": ("storagegateway", "describe_gateway_information", "GatewayARN", "GatewayARN", None),
    "emr_serverless_application": ("emr-serverless", "get_application", "applicationId", "id", "application"),
    "lattice_resource_gateway": ("vpc-lattice", "get_resource_gateway", "resourceGatewayIdentifier", "id", None),
    "lattice_vpc_association": ("vpc-lattice", "get_service_network_vpc_association", "serviceNetworkVpcAssociationIdentifier", "id", None),
    "app_runner_service": ("apprunner", "describe_service", "ServiceArn", "ServiceArn", "Service"),
    "app_runner_vpc_ingress_connection": ("apprunner", "describe_vpc_ingress_connection", "VpcIngressConnectionArn", "VpcIngressConnectionArn", "VpcIngressConnection"),
    "grafana_workspace": ("grafana", "describe_workspace", "workspaceId", "id", "workspace"),
    "sagemaker_cluster": ("sagemaker", "describe_cluster", "ClusterName", "ClusterName", None),
    "sagemaker_endpoint": ("sagemaker", "describe_endpoint", "EndpointName", "EndpointName", None),
    "emr_cluster": ("emr", "describe_cluster", "ClusterId", "Id", "Cluster"),
}
READ_ACTIONS = {(s, op) for s, op, *_ in DETAILS.values()} | {
    ("vpc-lattice", "get_listener"), ("vpc-lattice", "get_rule"),
    ("elasticbeanstalk", "describe_configuration_settings"), ("vpc-lattice", "list_targets"),
    ("apigateway", "get_resources"), ("apigatewayv2", "get_integrations"),
    ("eks", "list_clusters"), ("eks", "describe_nodegroup"), ("eks", "describe_fargate_profile"),
    ("globalaccelerator", "list_accelerators"), ("route53resolver", "list_resolver_endpoint_ip_addresses"),
    ("opensearchserverless", "batch_get_vpc_endpoint")}


class MetadataClient:
    """Project configuration responses before the shared request cache sees them."""
    ROOTS = {("apprunner", "describe_service"): "Service", ("osis", "get_pipeline"): "Pipeline",
             ("apigateway", "get_resources"): "items", ("apigatewayv2", "get_integrations"): "Items",
             ("emr-serverless", "get_application"): "application",
             ("elasticbeanstalk", "describe_configuration_settings"): "ConfigurationSettings",
             ("lightsail", "get_container_services"): "containerServices",
             ("vpc-lattice", "get_listener"): None, ("vpc-lattice", "get_rule"): None,
             ("timestream-influxdb", "get_db_instance"): None,
             ("timestream-influxdb", "list_db_instances"): "items"}

    def __init__(self, native, service):
        self.native, self.service = native, service

    def __getattr__(self, name):
        method = getattr(self.native, name)
        root = self.ROOTS.get((self.service, name))
        if (self.service, name) not in self.ROOTS:
            return method
        def read(**arguments):
            from .aws_content_sdk_logging import private_sdk_logs
            from peaso.analysis.network_services import project_network_data
            with private_sdk_logs():
                response = method(**arguments)
            body = response.get(root) if root and isinstance(response, dict) else response
            if not isinstance(body, (dict, list)):
                return {}  # Ordinary detail handling records malformed coverage.
            if self.service == "timestream-influxdb":
                fields = ("id", "arn", "status", "endpoint", "readerEndpoint", "port",
                          "publiclyAccessible", "networkType", "vpcSubnetIds",
                          "vpcSecurityGroupIds", "dbClusterId")
                def project(row):
                    return {key: row[key] for key in fields if key in row} if isinstance(row, dict) else {}
                projected = [project(row) for row in body] if isinstance(body, list) else project(body)
                return ({root: projected} if root else projected) | {
                    key: response[key] for key in ("nextToken",) if key in response}
            if (self.service, name) == ("osis", "get_pipeline"):
                from urllib.parse import urlsplit
                from .aws_osis_sinks import project_sinks
                base = project_network_data(body)
                sinks = project_sinks(body.get("PipelineConfigurationBody"))
                endpoints = body.get("IngestEndpointUrls")
                if not isinstance(endpoints, list):
                    return {"Pipeline": base | {"PipelineName": body.get("PipelineName"),
                                               "PipelineArn": body.get("PipelineArn"),
                                               "Status": body.get("Status"), "NetworkMode": "UNKNOWN",
                                               "SinkTargets": sinks["targets"], "SinkCoverage": sinks["status"]}}
                hosts = []
                for endpoint in endpoints:
                    if not isinstance(endpoint, str):
                        return {}
                    try:
                        parsed = urlsplit(endpoint if "://" in endpoint else "https://" + endpoint)
                        valid = (parsed.scheme == "https" and parsed.hostname and not parsed.username
                                 and not parsed.password and parsed.port in (None, 443))
                    except ValueError:
                        valid = False
                    if not valid:
                        return {}
                    hosts.append(parsed.hostname.lower())
                vpc = body.get("VpcEndpoints")
                private = bool(vpc) or bool(body.get("VpcEndpointService"))
                return {"Pipeline": base | {"PipelineName": body.get("PipelineName"),
                                            "PipelineArn": body.get("PipelineArn"),
                                            "Status": body.get("Status"),
                                            "NetworkMode": "PRIVATE" if private else "PUBLIC",
                                            "IngestHosts": sorted(set(hosts)),
                                            "SinkTargets": sinks["targets"],
                                            "SinkCoverage": sinks["status"]}}
            projected = project_network_data(body)
            if (self.service, name) == ("apprunner", "describe_service") and isinstance(projected, dict):
                instance = body.get("InstanceConfiguration")
                role_arn = instance.get("InstanceRoleArn") if isinstance(instance, dict) else None
                if isinstance(role_arn, str) and role_arn.startswith("arn:"):
                    projected["InstanceRoleArn"] = role_arn
                source = body.get("SourceConfiguration")
                if isinstance(source, dict):
                    image = isinstance(source.get("ImageRepository"), dict)
                    code = isinstance(source.get("CodeRepository"), dict)
                    if image != code:
                        projected["SourceType"] = "IMAGE" if image else "CODE"
                    if type(source.get("AutoDeploymentsEnabled")) is bool:
                        projected["AutoDeploymentsEnabled"] = source["AutoDeploymentsEnabled"]
                    if image:
                        image_id = source["ImageRepository"].get("ImageIdentifier")
                        if isinstance(image_id, str):
                            projected["ImageIdentifier"] = image_id
            if (self.service, name) == ("emr-serverless", "get_application") and isinstance(projected, dict):
                auto_start = body.get("autoStartConfiguration")
                if isinstance(auto_start, dict) and type(auto_start.get("enabled")) is bool:
                    projected["AutoStartEnabled"] = auto_start["enabled"]
            if (self.service, name) == ("elasticbeanstalk", "describe_configuration_settings") and isinstance(projected, list):
                # The shared secret-indicator producer intentionally removes all
                # option values. Keep this already-filtered network subset in a
                # separate metadata field while it processes the response.
                for row in projected:
                    row["NetworkOptions"] = row.get("OptionSettings", [])
            return ({root: projected} if root else projected) | {key: response[key] for key in
                ("position", "NextToken", "nextToken", "nextPageToken") if key in response}
        return read


def protect_client(client, service):
    return MetadataClient(client, service) if service in {key[0] for key in MetadataClient.ROOTS} else client


class MetadataSession:
    """Keep network configuration projection local to these metadata reads."""
    def __init__(self, native):
        self.native = native

    def client(self, service, **arguments):
        return protect_client(self.native.client(service, **arguments), service)


def quicksight_connections(requests, session, region, account):
    return requests.pages(session, "quicksight", region, "list_vpc_connections", "VPCConnectionSummaries", AwsAccountId=account)


def lightsail_containers(requests, session, region, account):
    return requests.pages(MetadataSession(session), "lightsail", region, "get_container_services", "containerServices")


def influxdb_instances(requests, session, region, account):
    return requests.pages(MetadataSession(session), "timestream-influxdb", region, "list_db_instances", "items")


def lattice_network_associations(operation):
    """The association list APIs require a service network (or VPC/service)
    identifier; an unscoped call is a ValidationException. List them per
    owned-or-shared service network instead."""
    def fetch(requests, session, region, account):
        from .aws import ReadResult
        session = MetadataSession(session)
        networks = requests.pages(session, "vpc-lattice", region, "list_service_networks", "items")
        if networks.status not in {"collected", "empty"}:
            return networks
        rows, failures, seen = [], [], set()
        for network in networks.items:
            if not isinstance(network.get("id"), str):
                failures.append("malformed")
                continue
            read = requests.pages(session, "vpc-lattice", region, operation, "items", serviceNetworkIdentifier=network["id"])
            if read.status not in {"collected", "empty"}:
                failures.append(read.status)
            for row in read.items:
                if isinstance(row, dict) and row.get("id") not in seen:
                    seen.add(row.get("id"))
                    rows.append(row)
        return ReadResult(rows, "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty",
                          {"code": "lattice_association_inventory_incomplete"} if failures else None)
    return fetch


def lattice_routes(kind):
    def fetch(requests, session, region, account):
        from .aws import ReadResult, _single
        session = MetadataSession(session)
        services = requests.pages(session, "vpc-lattice", region, "list_services", "items")
        if services.status not in {"collected", "empty"}:
            return services
        rows, failures = [], []
        for service in services.items:
            if not isinstance(service.get("id"), str):
                failures.append("malformed")
                continue
            args = {"serviceIdentifier": service["id"]}
            listeners = requests.pages(session, "vpc-lattice", region, "list_listeners", "items", **args)
            if listeners.status not in {"collected", "empty"}:
                failures.append(listeners.status)
            for listener in listeners.items:
                if not isinstance(listener.get("id"), str):
                    failures.append("malformed")
                    continue
                child_args = dict(args, listenerIdentifier=listener["id"])
                if kind == "lattice_listener":
                    reads = [(listener, "get_listener", child_args)]
                else:
                    rules = requests.pages(session, "vpc-lattice", region, "list_rules", "items", **child_args)
                    if rules.status not in {"collected", "empty"}:
                        failures.append(rules.status)
                    reads = [(rule, "get_rule", dict(child_args, ruleIdentifier=rule.get("id"))) for rule in rules.items]
                for summary, operation, arguments in reads:
                    if not isinstance(summary.get("id"), str):
                        failures.append("malformed")
                        continue
                    detail = _single(requests, session, region, "vpc-lattice", operation, **arguments)
                    body = detail.items[0] if detail.status == "collected" and len(detail.items) == 1 else None
                    if isinstance(body, dict) and body.get("id") == summary["id"] and body.get("arn") == summary.get("arn"):
                        rows.append(dict(body, serviceArn=service.get("arn"), serviceId=service["id"],
                                         **({"listenerArn": listener.get("arn")} if kind == "lattice_listener_rule" else {})))
                    else:
                        failures.append(detail.status if detail.status != "collected" else "malformed")
        return ReadResult(rows, "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty",
                          {"code": "lattice_routing_inventory_incomplete"} if failures else None)
    return fetch


def beanstalk_networks(requests, session, region, items):
    from .aws import _single
    session = MetadataSession(session)
    for row in items:
        app, name = row.get("ApplicationName"), row.get("EnvironmentName")
        if not isinstance(app, str) or not isinstance(name, str):
            row["NetworkSettings"] = {"_coverage": {"network": {"status": "malformed"}}}
            continue
        result = _single(requests, session, region, "elasticbeanstalk", "describe_configuration_settings",
                         ApplicationName=app, EnvironmentName=name)
        body = result.items[0] if result.status == "collected" and len(result.items) == 1 else {}
        settings = body.get("ConfigurationSettings")
        if isinstance(settings, list) and settings:
            from peaso.analysis.network_services import project_network_data
            row["NetworkSettings"] = [project_network_data(dict(setting, OptionSettings=setting.get("NetworkOptions", [])))
                                      for setting in settings]
        else:
            row["NetworkSettings"] = {"_coverage": {"network": {"status": result.status if result.status != "collected" else "malformed"}}}
    return items


def lattice_targets(requests, session, region, items):
    for row in items:
        if not isinstance(row.get("id"), str):
            continue
        result = requests.pages(session, "vpc-lattice", region, "list_targets", "items", targetGroupIdentifier=row["id"])
        row["NetworkTargets"] = result.items
        row.setdefault("_coverage", {})["NetworkTargets"] = {"status": result.status}
    return items


def eks_children(kind):
    def fetch(requests, session, region, account):
        from .aws import ReadResult, _single
        clusters = requests.pages(session, "eks", region, "list_clusters", "clusters")
        if clusters.status not in {"collected", "empty"}:
            return clusters
        operation, key, argument, detail, root = (
            ("list_nodegroups", "nodegroups", "nodegroupName", "describe_nodegroup", "nodegroup") if kind == "eks_nodegroup" else
            ("list_fargate_profiles", "fargateProfileNames", "fargateProfileName", "describe_fargate_profile", "fargateProfile"))
        rows, failures = [], []
        for cluster in clusters.items:
            names = requests.pages(session, "eks", region, operation, key, clusterName=cluster)
            if names.status not in {"collected", "empty"}:
                failures.append(names.status)
            for name in names.items:
                result = _single(requests, session, region, "eks", detail, clusterName=cluster, **{argument: name})
                body = result.items[0].get(root) if result.status == "collected" and len(result.items) == 1 else None
                if isinstance(body, dict):
                    rows.append(body)
                else:
                    failures.append(result.status if result.status != "collected" else "malformed")
        return ReadResult(rows, "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty",
                          {"code": "eks_network_children_incomplete"} if failures else None)
    return fetch


def aoss_endpoints(requests, session, region, items):
    from .aws import _single
    for row in items:
        if not isinstance(row.get("id"), str):
            continue
        read = _single(requests, session, region, "opensearchserverless", "batch_get_vpc_endpoint", ids=[row["id"]])
        body = read.items[0] if read.status == "collected" and len(read.items) == 1 else {}
        details = body.get("vpcEndpointDetails", [])
        matches = [item for item in details if isinstance(item, dict) and item.get("id") == row["id"]]
        if len(matches) == 1 and not body.get("vpcEndpointErrorDetails"):
            row["NetworkDetails"] = matches[0]
        else:
            row["NetworkDetails"] = {"_coverage": {"network": {"status": read.status if read.status != "collected" else "partial"}}}
    return items


def detail_enricher(kind):
    def enrich(requests, session, region, items):
        from .aws import _single
        from peaso.analysis.network_services import project_network_data
        service, operation, argument, field, root = DETAILS[kind]
        if (service, operation) in MetadataClient.ROOTS:
            session = MetadataSession(session)
        for row in items:
            identity = row.get(field)
            if not isinstance(identity, str) or not identity:
                row["NetworkDetails"] = {"_coverage": {"network": {"status": "malformed", "source_operation": operation}}}
                continue
            result = _single(requests, session, region, service, operation, **{argument: identity})
            body = result.items[0] if result.status == "collected" and len(result.items) == 1 else None
            body = body.get(root) if isinstance(body, dict) and root else body
            if isinstance(body, dict):
                row["NetworkDetails"] = project_network_data(body)
                if kind in {"influxdb_instance", "influxdb_cluster"}:
                    row["NetworkDetails"].update({key: body[key] for key in
                        ("id", "arn", "status", "endpoint", "readerEndpoint", "port",
                         "publiclyAccessible", "networkType", "vpcSubnetIds",
                         "vpcSecurityGroupIds", "dbClusterId") if key in body})
                if kind == "osis_pipeline":
                    row["NetworkDetails"].update({key: body[key] for key in
                        ("PipelineName", "PipelineArn", "Status", "NetworkMode", "IngestHosts",
                         "SinkTargets", "SinkCoverage")
                        if key in body})
                if kind == "app_runner_service":
                    for attribute in ("AutoDeploymentsEnabled", "ImageIdentifier"):
                        value = body.get(attribute)
                        if (attribute == "AutoDeploymentsEnabled" and type(value) is bool or
                                attribute == "ImageIdentifier" and isinstance(value, str)):
                            row["NetworkDetails"][attribute] = value
                    instance = body.get("InstanceConfiguration")
                    role_arn = body.get("InstanceRoleArn") or (instance.get("InstanceRoleArn") if isinstance(instance, dict) else None)
                    if isinstance(role_arn, str) and role_arn.startswith("arn:"):
                        row["NetworkDetails"]["InstanceRoleArn"] = role_arn
                    source = body.get("SourceConfiguration")
                    source_type = body.get("SourceType")
                    if isinstance(source, dict):
                        image, code = isinstance(source.get("ImageRepository"), dict), isinstance(source.get("CodeRepository"), dict)
                        if image != code:
                            source_type = "IMAGE" if image else "CODE"
                        if type(source.get("AutoDeploymentsEnabled")) is bool:
                            row["NetworkDetails"]["AutoDeploymentsEnabled"] = source["AutoDeploymentsEnabled"]
                        if image:
                            image_id = source["ImageRepository"].get("ImageIdentifier")
                            if isinstance(image_id, str):
                                row["NetworkDetails"]["ImageIdentifier"] = image_id
                    if source_type in ("IMAGE", "CODE"):
                        row["NetworkDetails"]["SourceType"] = source_type
                if kind == "emr_serverless_application" and type(body.get("AutoStartEnabled")) is bool:
                    row["NetworkDetails"]["AutoStartEnabled"] = body["AutoStartEnabled"]
                from peaso.analysis.network_observations import network_observations
                row["NetworkDetails"]["NetworkAttributes"] = network_observations(body)
            else:
                row["NetworkDetails"] = {"_coverage": {"network": {"status": result.status if result.status != "collected" else "malformed", "source_operation": operation}}}
        return items
    return enrich


def resolver_ips(requests, session, region, items):
    for row in items:
        if isinstance(row.get("Id"), str):
            result = requests.pages(session, "route53resolver", region, "list_resolver_endpoint_ip_addresses", "IpAddresses", ResolverEndpointId=row["Id"])
            row["NetworkDetails"] = {"IpAddresses": result.items,
                "_coverage": {"IpAddresses": {"status": result.status}}}
    return items


def api_integrations(kind):
    def enrich(requests, session, region, items):
        service, operation, expression, argument, identity, field = (
            ("apigateway", "get_resources", "items", "restApiId", "id", "NetworkResources") if kind == "rest_api" else
            ("apigatewayv2", "get_integrations", "Items", "ApiId", "ApiId", "NetworkIntegrations"))
        session = MetadataSession(session)
        for row in items:
            if not isinstance(row.get(identity), str):
                row.setdefault("_coverage", {})[field] = {"status": "malformed"}
                continue
            args = {argument: row[identity], **({"embed": ["methods"]} if kind == "rest_api" else {})}
            result = requests.pages(session, service, region, operation, expression, **args)
            row[field] = result.items
            row.setdefault("_coverage", {})[field] = {"status": result.status}
        return items
    return enrich


def accelerator_children(kind):
    def fetch(requests, session, region, account):
        from .aws import ReadResult
        # Global Accelerator's control plane is served from us-west-2.
        home = "us-west-2"
        roots = requests.pages(session, "globalaccelerator", home, "list_accelerators", "Accelerators")
        rows, failures = [], []
        if roots.status not in {"collected", "empty"}:
            return roots
        for root in roots.items:
            arn = root.get("AcceleratorArn")
            if not isinstance(arn, str):
                failures.append("malformed")
                continue
            listeners = requests.pages(session, "globalaccelerator", home, "list_listeners", "Listeners", AcceleratorArn=arn)
            if listeners.status not in {"collected", "empty"}:
                failures.append(listeners.status)
            for listener in listeners.items:
                if kind == "globalaccelerator_listener":
                    rows.append(dict(listener, AcceleratorArn=arn))
                    continue
                if not isinstance(listener.get("ListenerArn"), str):
                    failures.append("malformed")
                    continue
                groups = requests.pages(session, "globalaccelerator", home, "list_endpoint_groups", "EndpointGroups", ListenerArn=listener["ListenerArn"])
                rows.extend(dict(group, ListenerArn=listener["ListenerArn"], AcceleratorArn=arn) for group in groups.items)
                if groups.status not in {"collected", "empty"}:
                    failures.append(groups.status)
        return ReadResult(rows, "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty",
                          {"code": "accelerator_children_incomplete"} if failures else None)
    return fetch


ENRICHERS = {kind: detail_enricher(kind) for kind in DETAILS}
ENRICHERS["resolver_endpoint"] = resolver_ips
ENRICHERS["aoss_vpc_endpoint"] = aoss_endpoints
ENRICHERS.update({kind: api_integrations(kind) for kind in {"rest_api", "http_api"}})
ENRICHERS["elastic_beanstalk_environment"] = beanstalk_networks
_target_group_details = ENRICHERS["lattice_target_group"]
def enrich_lattice_target_group(requests, session, region, items):
    return lattice_targets(requests, session, region, _target_group_details(requests, session, region, items))
ENRICHERS["lattice_target_group"] = enrich_lattice_target_group
FETCHERS = {kind: accelerator_children(kind) for kind in GLOBAL_TYPES}
FETCHERS.update({"quicksight_vpc_connection": quicksight_connections,
                 "lightsail_container_service": lightsail_containers,
                 "influxdb_instance": influxdb_instances,
                 **{kind: lattice_routes(kind) for kind in {"lattice_listener", "lattice_listener_rule"}},
                 "lattice_vpc_association": lattice_network_associations("list_service_network_vpc_associations"),
                 "lattice_service_association": lattice_network_associations("list_service_network_service_associations"),
                 **{kind: eks_children(kind) for kind in {"eks_nodegroup", "eks_fargate_profile"}}})
