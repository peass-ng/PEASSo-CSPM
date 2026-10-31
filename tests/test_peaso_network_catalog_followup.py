"""Native configuration, DNS, mesh and Gateway policy gaps found on re-audit."""
import json
from types import SimpleNamespace

import pytest

from tests.test_peaso_network_managed_services import topology, node, linked
from tests.test_peaso_collectors_gcp import snapshot, collection
from peaso.collectors.gcp_network_catalog import api_root


def network_projection(ai):
    """The network-only agent view; source_* keep the full original evidence by design."""
    return {key: value for key, value in ai.items() if key not in ("source_inventory", "source_report")}


def test_beanstalk_reads_real_vpc_options_and_filters_application_values_before_cache():
    from peaso.collectors.aws import Requests
    from peaso.collectors.aws_network_catalog import beanstalk_networks
    class Client:
        def describe_configuration_settings(self, **args):
            assert args == {"ApplicationName": "app", "EnvironmentName": "prod"}
            return {"ConfigurationSettings": [{"DeploymentStatus": "deployed", "OptionSettings": [
                {"Namespace": "aws:ec2:vpc", "OptionName": "VPCId", "Value": "vpc-one"},
                {"Namespace": "aws:ec2:vpc", "OptionName": "Subnets", "Value": "subnet-one,subnet-two"},
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "SecurityGroups", "Value": "sg-one"},
                {"Namespace": "aws:elasticbeanstalk:application:environment", "OptionName": "VPCId", "Value": "SECRET_SENTINEL"},
            ]}]}
    class Session:
        def client(self, service, **kwargs):
            assert service == "elasticbeanstalk"
            return Client()
    reader = Requests({"retry_attempts": 1})
    data = beanstalk_networks(reader, Session(), "us-east-1", [{"ApplicationName": "app", "EnvironmentName": "prod"}])[0]
    assert "SECRET_SENTINEL" not in json.dumps([f.result() for f in reader._cache.values()])
    assert data["NetworkSettings"][0]["DeploymentStatus"] == "deployed"
    scope = "111111111111/us-east-1"
    graph, ai = topology("aws", [("elastic_beanstalk_environment", "prod", scope, data), ("vpc", "vpc-one", scope, {}),
        ("subnet", "subnet-one", scope, {}), ("security_group", "sg-one", scope, {})])
    for kind, identity in [("vpc", "vpc-one"), ("subnet", "subnet-one"), ("security_group", "sg-one")]:
        assert linked(graph, node(graph, "elastic_beanstalk_environment", "prod"), node(graph, kind, identity))
    assert "subnet-two" in json.dumps(ai)


def test_lightsail_container_network_metadata_excludes_environment_even_with_network_field_names():
    from peaso.collectors.aws import Requests
    from peaso.collectors.aws_network_catalog import lightsail_containers
    class Client:
        def can_paginate(self, operation):
            return False
        def get_container_services(self, **args):
            return {"containerServices": [{"arn": "arn:aws:lightsail:us-east-1:111111111111:ContainerService/service", "url": "https://service.example.com",
                "currentDeployment": {"publicEndpoint": {"containerName": "config", "containerPort": 8080},
                    "containers": {"config": {"environment": {"network": "SECRET_SENTINEL"}}}}}]}
    class Session:
        def client(self, service, **kwargs):
            return Client()
    reader = Requests({"retry_attempts": 1})
    result = lightsail_containers(reader, Session(), "us-east-1", "111111111111")
    assert result.status == "collected"
    assert result.items[0]["currentDeployment"]["publicEndpoint"]["containerPort"] == 8080
    assert "SECRET_SENTINEL" not in json.dumps([f.result() for f in reader._cache.values()])


def test_lattice_targets_and_resource_configuration_resolve_owned_resources():
    scope = "111111111111/us-east-1"
    graph, ai = topology("aws", [
        ("lattice_target_group", "tg", scope, {"NetworkDetails": {"config": {"vpcIdentifier": "vpc-one"}}, "NetworkTargets": [{"id": "i-one", "port": 8080}]}),
        ("instance", "i-one", scope, {}), ("vpc", "vpc-one", scope, {}),
        ("lattice_resource_gateway", "rgw", scope, {}),
        ("lattice_resource_configuration", "rcfg", scope, {"arn": "arn:aws:vpc-lattice:us-east-1:111111111111:resourceconfiguration/rcfg", "NetworkDetails": {"resourceGatewayId": "rgw"}}),
        ("lattice_resource_association", "association", scope, {"resourceConfigurationId": "rcfg"}),
        ("vpc_endpoint", "vpce", scope, {"ResourceConfigurationArn": "arn:aws:vpc-lattice:us-east-1:111111111111:resourceconfiguration/rcfg"}),
    ])
    for source_kind, source_id, target_kind, target_id in [
        ("lattice_target_group", "tg", "instance", "i-one"), ("lattice_target_group", "tg", "vpc", "vpc-one"),
        ("lattice_resource_configuration", "rcfg", "lattice_resource_gateway", "rgw"),
        ("lattice_resource_association", "association", "lattice_resource_configuration", "rcfg"),
        ("vpc_endpoint", "vpce", "lattice_resource_configuration", "rcfg")]:
        assert linked(graph, node(graph, source_kind, source_id), node(graph, target_kind, target_id))
    assert "i-one" in json.dumps(ai)


def test_hsm_and_verified_access_native_network_fields_reach_graph_and_agent():
    scope = "111111111111/us-east-1"
    graph, ai = topology("aws", [("cloudhsm_cluster", "hsm", scope, {"VpcId": "vpc-one", "SecurityGroup": "sg-one",
        "SubnetMapping": {"us-east-1a": "subnet-one"}, "Hsms": [{"EniId": "eni-one", "EniIp": "10.0.0.4"}]}),
        ("vpc", "vpc-one", scope, {}), ("subnet", "subnet-one", scope, {}), ("security_group", "sg-one", scope, {}),
        ("network_interface", "eni-one", scope, {}), ("verified_access_instance", "vai", scope, {}),
        ("verified_access_group", "vag", scope, {"VerifiedAccessInstanceId": "vai"}),
        ("verified_access_endpoint", "vae", scope, {"VerifiedAccessGroupId": "vag", "VpcId": "vpc-one", "NetworkInterfaceOptions": {"NetworkInterfaceId": "eni-one"}}),
        ("kms_external_key_store", "xks", scope, {"CloudHsmClusterId": "hsm", "XksProxyConfiguration": {"UriEndpoint": "https://proxy.example.com",
            "AuthenticationCredential": {"RawSecretAccessKey": "SECRET_SENTINEL"}}})])
    for source_kind, source_id, target_kind, identity in [
        ("cloudhsm_cluster", "hsm", "vpc", "vpc-one"), ("cloudhsm_cluster", "hsm", "subnet", "subnet-one"),
        ("cloudhsm_cluster", "hsm", "security_group", "sg-one"), ("cloudhsm_cluster", "hsm", "network_interface", "eni-one"),
        ("verified_access_endpoint", "vae", "verified_access_group", "vag"), ("verified_access_group", "vag", "verified_access_instance", "vai"),
        ("verified_access_endpoint", "vae", "network_interface", "eni-one"), ("kms_external_key_store", "xks", "cloudhsm_cluster", "hsm")]:
        assert linked(graph, node(graph, source_kind, source_id), node(graph, target_kind, identity))
    assert "10.0.0.4" in json.dumps(ai)
    assert "SECRET_SENTINEL" not in json.dumps(network_projection(ai))


@pytest.mark.parametrize("kind", ["lattice_listener", "lattice_listener_rule"])
def test_lattice_routing_native_reads_keep_default_actions_and_parent_identity(kind):
    from peaso.collectors.aws import ReadResult
    from peaso.collectors.aws_network_catalog import lattice_routes, MetadataClient
    service_arn = "arn:aws:vpc-lattice:us-east-1:111111111111:service/svc"
    listener_arn = service_arn + "/listener/lst"
    rule_arn = listener_arn + "/rule/rule"
    class Client:
        def get_listener(self, **args):
            assert args == {"serviceIdentifier": "svc", "listenerIdentifier": "lst"}
            return {"id": "lst", "arn": listener_arn, "defaultAction": {"forward": {"targetGroups": [{"targetGroupIdentifier": "tg", "weight": 1}]}}}
        def get_rule(self, **args):
            assert args == {"serviceIdentifier": "svc", "listenerIdentifier": "lst", "ruleIdentifier": "rule"}
            return {"id": "rule", "arn": rule_arn, "action": {"forward": {"targetGroups": [{"targetGroupIdentifier": "tg"}]}},
                "match": {"httpMatch": {"headerMatches": [{"match": {"exact": "SECRET_SENTINEL"}}], "pathMatch": {"exact": "/api"}}}}
    class Requests:
        def pages(self, session, service, region, operation, key, **args):
            rows = {"list_services": [{"id": "svc", "arn": service_arn}], "list_listeners": [{"id": "lst", "arn": listener_arn}],
                    "list_rules": [{"id": "rule", "arn": rule_arn}]}
            return ReadResult(rows[operation], "collected")
        def call(self, session, service, region, operation, **args):
            return getattr(MetadataClient(Client(), service), operation)(**args)
    result = lattice_routes(kind)(Requests(), None, "us-east-1", "111111111111")
    assert result.status == "collected" and result.items[0]["serviceArn"] == service_arn
    assert "SECRET_SENTINEL" not in json.dumps(result.items)
    scope = "111111111111/us-east-1"
    graph, ai = topology("aws", [(kind, "route", scope, result.items[0]), ("lattice_service", service_arn, scope, {}), ("lattice_target_group", "tg", scope, {})])
    assert linked(graph, node(graph, kind, "route"), node(graph, "lattice_service", service_arn))
    assert linked(graph, node(graph, kind, "route"), node(graph, "lattice_target_group", "tg"))


@pytest.mark.parametrize("kind,operation", [("lattice_vpc_association", "list_service_network_vpc_associations"),
                                            ("lattice_service_association", "list_service_network_service_associations")])
def test_lattice_associations_are_listed_per_service_network(kind, operation):
    # The association APIs reject an unscoped call with a ValidationException.
    from peaso.collectors.aws import ReadResult
    from peaso.collectors.aws_network_catalog import FETCHERS
    calls = []
    class Requests:
        def __init__(self, networks): self.networks = networks
        def pages(self, session, service, region, op, key, **args):
            calls.append((op, args))
            if op == "list_service_networks":
                return ReadResult(self.networks, "collected" if self.networks else "empty")
            assert op == operation and set(args) == {"serviceNetworkIdentifier"}
            return ReadResult([{"id": "assoc-" + args["serviceNetworkIdentifier"]}], "collected")
    result = FETCHERS[kind](Requests([{"id": "sn-a"}, {"id": "sn-b"}]), None, "us-east-1", "111111111111")
    assert result.status == "collected" and [row["id"] for row in result.items] == ["assoc-sn-a", "assoc-sn-b"]
    calls.clear()
    result = FETCHERS[kind](Requests([]), None, "us-east-1", "111111111111")
    assert result.status == "empty" and [op for op, _ in calls] == ["list_service_networks"]


@pytest.mark.parametrize("kind,segment", [("mesh_http_route", "httpRoutes"), ("mesh_tcp_route", "tcpRoutes"),
    ("mesh_tls_route", "tlsRoutes"), ("mesh_grpc_route", "grpcRoutes"), ("service_mesh", "meshes"), ("mesh_gateway", "gateways"),
    ("mesh_endpoint_policy", "endpointPolicies")])
def test_gcp_mesh_discovery_collects_global_and_selected_regions_with_pagination(kind, segment):
    def resolver(request):
        assert request["url"].startswith("https://networkservices.googleapis.com/v1/projects/p-one/locations/")
        location = request["url"].split("/locations/")[1].split("/")[0]
        assert location in {"global", "us-central1"}
        params = request.get("params", {})
        if kind.endswith("_route"):
            assert "destinations(serviceName,weight)" in params["fields"]
            assert "HeaderModifier" not in params["fields"] and "directResponse" not in params["fields"]
        token = params.get("pageToken")
        return {segment: [{"name": f"projects/p-one/locations/{location}/{segment}/{'two' if token else 'one'}"}],
                **({} if token else {"nextPageToken": "two"})}
    snap, transport = snapshot([kind], resolver, regions=["us-central1"])
    assert collection(snap, kind)["status"] == "collected"
    assert len(collection(snap, kind)["items"]) == 4 and len(transport.requests) == 4


def test_gcp_denied_location_is_coverage_gap_even_when_org_policy_excludes_it():
    from peaso.collectors.gcp import ReadError
    def resolver(request):
        if "/global/" in request["url"]:
            return {"gateways": [{"name": "projects/p-one/locations/global/gateways/global"}]}
        raise ReadError("denied", "location_denied", reason="LOCATION_POLICY_VIOLATED")
    snap, _ = snapshot(["mesh_gateway"], resolver, regions=["us-central1"])
    assert collection(snap, "mesh_gateway")["status"] == "partial"


@pytest.mark.parametrize("kind,service", [("datastream_private_connection", "datastream"), ("migration_private_connection", "datamigration")])
def test_gcp_database_private_connectivity_native_and_project_qualified_attachments(kind, service):
    vpc = "projects/host/global/networks/net"
    attachment = "projects/host/regions/us-central1/networkAttachments/attachment"
    def resolver(request):
        listed = api_root(service, "v1", "us-central1") + "/projects/p-one/locations/us-central1/privateConnections"
        if request["url"] == listed + "/private:getIamPolicy":
            return {"bindings": []}
        assert request["url"] == listed
        return {"privateConnections": [{"name": "projects/p-one/locations/us-central1/privateConnections/private", "vpcPeeringConfig": {"vpc": vpc, "subnet": "10.0.0.0/29"},
            "pscInterfaceConfig": {"networkAttachment": attachment}}]}
    snap, _ = snapshot([kind], resolver, regions=["us-central1"])
    row = collection(snap, kind)
    assert row["status"] == "collected"
    graph, ai = topology("gcp", [(kind, "private", "projects/p-one", row["items"][0]),
        ("network", "https://www.googleapis.com/compute/v1/" + vpc, "projects/host", {}),
        ("network_attachment", "https://www.googleapis.com/compute/v1/" + attachment, "projects/host", {})])
    for target in ("network", "network_attachment"):
        assert any(edge["source"] == node(graph, kind, "private")["id"] and edge["target"] == next(n["id"] for n in graph["nodes"] if n["type"] == target) for edge in graph["edges"])
    assert "10.0.0.0/29" in json.dumps(ai)


def test_gcp_native_tls_inventory_is_not_replaced_by_proxy_reference_subset():
    def resolver(request):
        if request["url"].endswith("/serverTlsPolicies"):
            return {"serverTlsPolicies": [{"name": "projects/p-one/locations/global/serverTlsPolicies/unreferenced", "allowOpen": False}]}
        if request["url"].endswith("/locations"):
            return {"locations": []}
        return {"items": {}}
    snap, _ = snapshot(["server_tls_policy"], resolver, regions=[])
    envelopes = [row for row in snap["collections"] if row["type"] == "server_tls_policy"]
    assert len(envelopes) == 1 and envelopes[0]["status"] == "collected"
    assert envelopes[0]["items"][0]["name"].endswith("/unreferenced")


def test_gcp_global_policies_remain_available_when_location_discovery_is_denied():
    from peaso.collectors.gcp import ReadError
    def resolver(request):
        if request["url"].endswith("/locations"):
            raise ReadError("denied", "locations_denied")
        if request["url"].endswith("/locations/global/clientTlsPolicies/tls:getIamPolicy"):
            return {"bindings": []}
        assert request["url"].endswith("/locations/global/clientTlsPolicies")
        return {"clientTlsPolicies": [{"name": "projects/p-one/locations/global/clientTlsPolicies/tls"}]}
    snap, _ = snapshot(["client_tls_policy"], resolver)
    row = collection(snap, "client_tls_policy")
    assert row["status"] == "partial" and len(row["items"]) == 1


def test_composer_private_environment_configuration_is_network_data_in_agent_context():
    graph, ai = topology("gcp", [("composer_environment", "composer", "projects/app", {"config": {"privateEnvironmentConfig": {
        "enablePrivateEnvironment": True, "cloudSqlIpv4CidrBlock": "10.20.0.0/24"}}, "environment": {"network": "SECRET_SENTINEL"}})])
    data = ai["inventory"][0]["data"]
    assert data["config"]["privateEnvironmentConfig"]["enablePrivateEnvironment"] is True
    assert "SECRET_SENTINEL" not in json.dumps(network_projection(ai))


def test_gcp_mesh_routes_link_mesh_gateway_backend_and_security_policy():
    mesh = "projects/app/locations/global/meshes/mesh"
    gateway = "projects/app/locations/global/gateways/gateway"
    policy = "projects/app/locations/global/serverTlsPolicies/tls"
    backend = "https://www.googleapis.com/compute/v1/projects/host/global/backendServices/backend"
    graph, ai = topology("gcp", [
        ("service_mesh", mesh, "projects/app", {}), ("mesh_gateway", gateway, "projects/app", {"serverTlsPolicy": policy}),
        ("server_tls_policy", policy, "projects/app", {"allowOpen": False}), ("backend_service", backend, "projects/host", {}),
        ("mesh_http_route", "route", "projects/app", {"meshes": [mesh], "gateways": [gateway], "rules": [{"action": {"destinations": [{"serviceName": backend, "weight": 1}]}}]})])
    for target_kind, identity in [("service_mesh", mesh), ("mesh_gateway", gateway), ("backend_service", backend)]:
        assert linked(graph, node(graph, "mesh_http_route", "route"), node(graph, target_kind, identity))
    assert linked(graph, node(graph, "mesh_gateway", gateway), node(graph, "server_tls_policy", policy))
    assert backend in json.dumps(ai)


def test_gcp_public_dns_records_read_addresses_but_never_request_txt_bodies():
    def resolver(request):
        if request["url"].endswith("/managedZones"):
            return {"managedZones": [{"name": "public"}]}
        params = request["params"]
        if "name" not in params:
            assert params["fields"] == "rrsets(name,type,ttl),nextPageToken"
            return {"rrsets": [{"name": "app.example.com.", "type": "A", "ttl": 300}, {"name": "example.com.", "type": "TXT", "ttl": 300}]}
        assert params["type"] == "A" and params["name"] == "app.example.com."
        assert "rrdatas" in params["fields"]
        return {"rrsets": [{"name": "app.example.com.", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.10"]}]}
    snap, transport = snapshot(["dns_record_set"], resolver)
    rows = collection(snap, "dns_record_set")
    assert rows["status"] == "collected" and len(rows["items"]) == 2
    assert len(transport.requests) == 3
    address = next(row for row in rows["items"] if row["type"] == "A")
    txt = next(row for row in rows["items"] if row["type"] == "TXT")
    assert "rrdatas" not in txt and txt["_coverage"]["rrdatas"]["status"] == "not_collected"
    graph, ai = topology("gcp", [("dns_managed_zone", "public", "projects/p-one", {"name": "public"}),
        ("dns_record_set", address["resource"], "projects/p-one", address)])
    assert linked(graph, node(graph, "dns_record_set", address["resource"]), node(graph, "dns_managed_zone", "public"))
    assert "192.0.2.10" in json.dumps(ai)


@pytest.mark.parametrize("kind,parent_kind,parent_segment,segment,record_segment", [
    ("dns_forwarding_rule", "dns_forwarding_ruleset", "dnsForwardingRulesets", "forwardingRules", "forwardingRules"),
    ("dns_forwarding_vnet_link", "dns_forwarding_ruleset", "dnsForwardingRulesets", "virtualNetworkLinks", "virtualNetworkLinks"),
    ("private_dns_record_set", "private_dns_zone", "privateDnsZones", "ALL", "A"),
])
def test_azure_dns_native_children_keep_parent_scope_and_graph_relationship(kind, parent_kind, parent_segment, segment, record_segment):
    from peaso.collectors import azure
    from peaso.snapshot import resources
    from peaso.ai.network import native_network_resource
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, parent, envelope
    rid = BASE + "Microsoft.Network/" + parent_segment + "/parent"
    child = rid + "/" + record_segment + "/child"
    native = routes(parent_kind, rid, {})
    native[rid + "/" + segment] = {"value": [parent(child, "Microsoft.Network/" + parent_segment + "/" + record_segment,
        {"domainName": "example.com.", "targetDnsServers": [{"ipAddress": "10.0.0.53", "port": 53}], "aRecords": [{"ipv4Address": "10.0.0.4"}]})]}
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, [kind], transport=Transport(native))
    assert envelope(snap, kind)["status"] == "collected"
    row = next(row for row in resources(snap) if row["type"] == kind)
    assert native_network_resource(row)["data"]["properties"]["aRecords"][0]["ipv4Address"] == "10.0.0.4"
    graph, _ = topology("azure", [(parent_kind, rid, SCOPE, {}), (kind, child, SCOPE, row["data"])])
    assert linked(graph, node(graph, kind, child), node(graph, parent_kind, rid))


@pytest.mark.parametrize("denied", [False, True])
def test_azure_nested_managed_endpoints_discover_ancestors_and_propagate_denied_parents(denied):
    from peaso.collectors import azure
    from peaso.snapshot import resources
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, parent, envelope
    factory = BASE + "Microsoft.DataFactory/factories/factory"
    managed = factory + "/managedVirtualNetworks/default"
    endpoint = managed + "/managedPrivateEndpoints/storage"
    storage = BASE + "Microsoft.Storage/storageAccounts/storage"
    native = routes("data_factory", factory, {})
    native[factory + "/managedVirtualNetworks"] = (azure.AzureReadError("forbidden", 403) if denied else {"value": [parent(managed,
        "Microsoft.DataFactory/factories/managedVirtualNetworks", {})]})
    native[managed + "/managedPrivateEndpoints"] = {"value": [parent(endpoint, "Microsoft.DataFactory/factories/managedVirtualNetworks/managedPrivateEndpoints", {
        "privateLinkResourceId": storage, "groupId": "blob", "fqdns": ["storage.blob.core.windows.net"]})]}
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["datafactory_managed_private_endpoint"], transport=Transport(native))
    record = envelope(snap, "datafactory_managed_private_endpoint")
    if denied:
        assert record["status"] not in {"collected", "empty"}
        return
    assert record["status"] == "collected"
    assert envelope(snap, "datafactory_managed_vnet")["status"] == "collected"
    data = next(r["data"] for r in resources(snap) if r["type"] == "datafactory_managed_private_endpoint")
    graph, ai = topology("azure", [("data_factory", factory, SCOPE, {}), ("datafactory_managed_vnet", managed, SCOPE, {}),
        ("datafactory_managed_private_endpoint", endpoint, SCOPE, data), ("storage_account", storage, SCOPE, {})])
    assert linked(graph, node(graph, "datafactory_managed_private_endpoint", endpoint), node(graph, "storage_account", storage))
    assert linked(graph, node(graph, "datafactory_managed_private_endpoint", endpoint), node(graph, "datafactory_managed_vnet", managed))
    assert linked(graph, node(graph, "datafactory_managed_vnet", managed), node(graph, "data_factory", factory))


def test_monitor_private_link_scope_members_are_native_resources_and_link_to_workspace():
    from peaso.collectors import azure
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, parent, envelope
    ampls = BASE + "Microsoft.Insights/privateLinkScopes/scope"
    member = ampls + "/scopedResources/logs"
    workspace = BASE + "Microsoft.OperationalInsights/workspaces/logs"
    native = routes("monitor_private_link_scope", ampls, {})
    native[ampls + "/scopedResources"] = {"value": [parent(member, "Microsoft.Insights/privateLinkScopes/scopedResources", {"linkedResourceId": workspace})]}
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["monitor_scoped_resource"], transport=Transport(native))
    record = envelope(snap, "monitor_scoped_resource")
    assert record["status"] == "collected"
    graph, ai = topology("azure", [("monitor_scoped_resource", member, SCOPE, record["items"][0]),
        ("monitor_private_link_scope", ampls, SCOPE, {}), ("log_analytics_workspace", workspace, SCOPE, {})])
    assert linked(graph, node(graph, "monitor_scoped_resource", member), node(graph, "monitor_private_link_scope", ampls))
    assert linked(graph, node(graph, "monitor_scoped_resource", member), node(graph, "log_analytics_workspace", workspace))


def test_azure_ml_managed_network_outbound_rule_retains_declared_private_link_target():
    scope = "/subscriptions/one"
    target = scope + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storage"
    graph, ai = topology("azure", [("ml_workspace", "ml", scope, {"properties": {"managedNetwork": {"isolationMode": "AllowOnlyApprovedOutbound",
        "outboundRules": {"storage-private": {"type": "PrivateEndpoint", "destination": {"serviceResourceId": target, "subresourceTarget": "blob"}}}}}}),
        ("storage_account", target, scope, {})])
    assert linked(graph, node(graph, "ml_workspace", "ml"), node(graph, "storage_account", target))
    assert "AllowOnlyApprovedOutbound" in json.dumps(ai)


def test_k8s_backend_tls_policy_negotiates_alpha3_and_reaches_agent_and_service():
    from peaso.collectors import k8s
    from peaso.snapshot import resources
    from peaso.ai.network import native_network_resource
    from tests.test_peaso_collectors_azurek8s import FakeKube, kube_list
    def resolver(path, params):
        if path == "/apis":
            return {"groups": [{"name": "gateway.networking.k8s.io", "versions": [{"version": "v1alpha3"}]}]}
        if path.endswith("/v1alpha3"):
            return {"resources": [{"name": "backendtlspolicies", "namespaced": True, "verbs": ["list"]}]}
        assert path.endswith("/v1alpha3/namespaces/apps/backendtlspolicies")
        return kube_list([{"metadata": {"name": "tls", "namespace": "apps", "uid": "tls-uid"},
            "spec": {"targetRefs": [{"group": "", "kind": "Service", "name": "backend"}],
                "validation": {"hostname": "backend.internal", "wellKnownCACertificates": "System"}}}])
    snap = k8s.collect({"scopes": ["apps"], "metadata": {"cluster_id": "cluster"}}, ["backendtlspolicy"], api=FakeKube(resolver))
    assert next(c for c in snap["collections"] if c["type"] == "backendtlspolicy")["status"] == "collected"
    policy = next(r for r in resources(snap) if r["type"] == "backendtlspolicy")
    assert native_network_resource(policy)["data"]["spec"]["validation"]["hostname"] == "backend.internal"
    from peaso.analysis.network import _k8s_context
    cluster, _ = _k8s_context(snap, policy)
    graph, ai = topology("k8s", [("backendtlspolicy", "tls", "apps", policy["data"]),
        ("service", "backend", "apps", {"metadata": {"name": "backend", "namespace": "apps"}})], {"cluster_id": cluster})
    assert linked(graph, node(graph, "backendtlspolicy", "tls"), node(graph, "service", "backend"))


def test_k8s_service_address_allocations_keep_native_service_owner_and_cidr():
    graph, ai = topology("k8s", [("servicecidr", "pool", "cluster", {"spec": {"cidrs": ["10.96.0.0/12"]}}),
        ("ipaddress", "10.96.0.2", "cluster", {"metadata": {"name": "10.96.0.2"}, "spec": {"parentRef": {"group": "", "resource": "services", "namespace": "apps", "name": "backend"}}}),
        ("service", "backend", "apps", {"metadata": {"name": "backend", "namespace": "apps"}})], {"cluster_id": "cluster"})
    assert linked(graph, node(graph, "ipaddress", "10.96.0.2"), node(graph, "service", "backend"))
    assert "10.96.0.0/12" in json.dumps(ai)


@pytest.mark.parametrize("kind", ["servicecidr", "ipaddress"])
def test_k8s_service_address_inventories_use_registered_native_read_paths(kind):
    from peaso.collectors import k8s
    from tests.test_peaso_collectors_azurek8s import FakeKube, kube_list
    path = k8s.ENDPOINTS[kind][0]
    def resolver(request_path, params):
        assert request_path == path
        spec = {"cidrs": ["10.96.0.0/12"]} if kind == "servicecidr" else {"parentRef": {"group": "", "resource": "services", "namespace": "apps", "name": "backend"}}
        return kube_list([{"metadata": {"name": "pool" if kind == "servicecidr" else "10.96.0.2", "uid": "uid"}, "spec": spec}])
    snap = k8s.collect({"scopes": ["apps"]}, [kind], api=FakeKube(resolver))
    assert next(row for row in snap["collections"] if row["type"] == kind)["status"] == "collected"
