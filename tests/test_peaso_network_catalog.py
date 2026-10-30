"""Second-pass service audit: native facts must reach both topology and AI."""
import json
from types import SimpleNamespace

import pytest

from peaso.analysis import REQUIRED_TYPES
from peaso.analysis.network import NETWORK_TYPES
from peaso.analysis.network_catalog import NETWORK_SERVICE_GROUPS, CONTROL_TYPES
from peaso.ai.network import native_network_resource
from peaso.collectors import supported_types
from tests.test_peaso_network_managed_services import topology, node, linked


@pytest.mark.parametrize("provider", NETWORK_SERVICE_GROUPS)
def test_audited_families_are_collected_mapped_and_given_to_ai(provider):
    from peaso.engine import plan_collection
    kinds = set().union(*NETWORK_SERVICE_GROUPS[provider].values()) | CONTROL_TYPES.get(provider, set())
    assert kinds <= set(supported_types(provider))
    assert kinds <= NETWORK_TYPES
    assert kinds <= set(REQUIRED_TYPES[provider]["network"])
    assert kinds <= set(plan_collection({"connector": {"provider": provider}, "categories": ["network"], "checks": [], "frameworks": []}))
    scope = {"aws": "111111111111/us-east-1", "azure": "/subscriptions/one", "gcp": "projects/app", "k8s": "apps"}[provider]
    graph, ai = topology(provider, [(kind, "native-" + kind, scope, {"name": kind}) for kind in sorted(kinds)], {"cluster_id": "cluster"})
    assert kinds <= {n["type"] for n in graph["nodes"]}
    assert kinds <= {r["type"] for r in ai["inventory"]}


@pytest.mark.parametrize("kind,data,target_kind,target", [
    ("sagemaker_notebook_instance", {"SubnetId": "subnet-one", "DirectInternetAccess": "Disabled"}, "subnet", "subnet-one"),
    ("sagemaker_training_job", {"VpcConfig": {"Subnets": ["subnet-one"]}}, "subnet", "subnet-one"),
    ("glue_connection", {"PhysicalConnectionRequirements": {"SecurityGroupIdList": ["sg-one"]}}, "security_group", "sg-one"),
    ("batch_compute_environment", {"computeResources": {"subnets": ["subnet-one"]}}, "subnet", "subnet-one"),
    ("codebuild_project", {"Configuration": {"projects": [{"vpcConfig": {"vpcId": "vpc-one"}}]}}, "vpc", "vpc-one"),
    ("emr_cluster", {"NetworkDetails": {"Ec2InstanceAttributes": {"Ec2SubnetId": "subnet-one"}}}, "subnet", "subnet-one"),
    ("app_runner_vpc_ingress_connection", {"NetworkDetails": {"IngressVpcConfiguration": {"VpcEndpointId": "vpce-one"}}}, "vpc_endpoint", "vpce-one"),
    ("app_runner_service", {"NetworkDetails": {"NetworkConfiguration": {"EgressConfiguration": {"VpcConnectorArn": "arn:aws:apprunner:us-east-1:111111111111:vpcconnector/one"}}}}, "app_runner_vpc_connector", "arn:aws:apprunner:us-east-1:111111111111:vpcconnector/one"),
    ("rest_api", {"endpointConfiguration": {"types": ["PRIVATE"], "vpcEndpointIds": ["vpce-one"]}}, "vpc_endpoint", "vpce-one"),
    ("apigateway_vpc_link", {"targetArns": ["arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/net/a/1"]}, "load_balancer", "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/net/a/1"),
    ("resolver_endpoint", {"HostVPCId": "vpc-one", "NetworkDetails": {"IpAddresses": [{"SubnetId": "subnet-one", "Ip": "10.0.0.4"}]}}, "subnet", "subnet-one"),
    ("autoscaling_group", {"VPCZoneIdentifier": "subnet-one,subnet-two"}, "subnet", "subnet-one"),
    ("firehose_delivery_stream", {"Destinations": [{"AmazonopensearchserviceDestinationDescription": {"VpcConfiguration": {"VpcId": "vpc-one"}}}]}, "vpc", "vpc-one"),
    ("elasticache_serverless_cache", {"SubnetIds": ["subnet-one"]}, "subnet", "subnet-one"),
    ("aoss_vpc_endpoint", {"NetworkDetails": {"networkInterfaceIds": ["eni-one"]}}, "network_interface", "eni-one"),
    ("lattice_resource_gateway", {"NetworkDetails": {"subnetIds": ["subnet-one"]}}, "subnet", "subnet-one"),
    ("emr_serverless_application", {"NetworkDetails": {"networkConfiguration": {"subnetIds": ["subnet-one"]}}}, "subnet", "subnet-one"),
    ("influxdb_instance", {"NetworkDetails": {"vpcSubnetIds": ["subnet-one"]}}, "subnet", "subnet-one"),
    ("osis_pipeline", {"NetworkDetails": {"VpcEndpoints": [{"VpcId": "vpc-one"}]}}, "vpc", "vpc-one"),
    ("datasync_agent", {"NetworkDetails": {"PrivateLinkConfig": {"VpcEndpointId": "vpce-one"}}}, "vpc_endpoint", "vpce-one"),
    ("quicksight_vpc_connection", {"NetworkInterfaces": [{"SubnetId": "subnet-one"}]}, "subnet", "subnet-one"),
    ("eks_nodegroup", {"subnets": ["subnet-one"]}, "subnet", "subnet-one"),
    ("eks_fargate_profile", {"subnets": ["subnet-one"]}, "subnet", "subnet-one"),
    ("storagegateway_gateway", {"NetworkDetails": {"Ec2InstanceId": "i-one"}}, "instance", "i-one"),
    ("rest_api", {"NetworkResources": [{"resourceMethods": {"GET": {"methodIntegration": {"connectionType": "VPC_LINK", "connectionId": "link"}}}}]}, "apigateway_vpc_link", "link"),
    ("http_api", {"NetworkIntegrations": [{"ConnectionType": "VPC_LINK", "ConnectionId": "link"}]}, "apigatewayv2_vpc_link", "link"),
])
def test_aws_native_service_attachment_paths_survive_both_projections(kind, data, target_kind, target):
    scope = "111111111111/us-east-1"
    graph, ai = topology("aws", [(kind, "service", scope, data), (target_kind, target, scope, {})])
    assert linked(graph, node(graph, kind, "service"), node(graph, target_kind, target))
    projected = next(r for r in ai["inventory"] if r["type"] == kind)
    assert target in json.dumps(projected["data"])


def test_gcp_jobs_keep_worker_networks_but_not_job_payloads():
    network = "https://www.googleapis.com/compute/v1/projects/host/global/networks/net"
    subnet = "https://www.googleapis.com/compute/v1/projects/host/regions/us-central1/subnetworks/sub"
    graph, ai = topology("gcp", [
        ("network", network, "projects/host", {}), ("subnetwork", subnet, "projects/host", {}),
        ("dataflow_network_job", "job", "projects/app", {"environment": {"workerPools": [{"network": network, "subnetwork": subnet,
            "ipConfiguration": "WORKER_IP_PRIVATE", "metadata": {"password": "SECRET_SENTINEL"}}]}, "steps": [{"value": "SECRET_SENTINEL"}]}),
        ("batch_network_job", "batch", "projects/app", {"allocationPolicy": {"network": {"networkInterfaces": [{"network": network, "subnetwork": subnet}]}},
            "taskGroups": [{"runnables": [{"script": {"text": "SECRET_SENTINEL"}}]}]}),
    ])
    assert linked(graph, node(graph, "dataflow_network_job", "job"), node(graph, "subnetwork", subnet))
    assert linked(graph, node(graph, "batch_network_job", "batch"), node(graph, "network", network))
    projected = next(r for r in ai["inventory"] if r["type"] == "dataflow_network_job")["data"]
    assert projected["environment"]["workerPools"][0]["subnetwork"] == subnet
    # First reads are network-only projections; the complete native record is
    # handed over separately as the full source lookup (full AI evidence).
    assert "SECRET_SENTINEL" not in json.dumps({"report": ai["report"], "inventory": ai["inventory"]})
    assert "SECRET_SENTINEL" in json.dumps(ai["source_inventory"])


@pytest.mark.parametrize("kind,data", [
    ("managed_kafka_cluster", {"gcpConfig": {"accessConfig": {"networkConfigs": [{"subnet": "projects/host/regions/us-central1/subnetworks/sub"}]}}}),
    ("memorystore_instance", {"pscAutoConnections": [{"consumerNetwork": "projects/host/global/networks/net"}]}),
    ("vertex_endpoint", {"network": "projects/host/global/networks/net", "enablePrivateServiceConnect": True}),
    ("cloudrun_worker_pool", {"template": {"vpcAccess": {"networkInterfaces": [{"network": "projects/host/global/networks/net"}]}}}),
])
def test_modern_gcp_service_networks_reach_graph_and_agent(kind, data):
    net = "https://www.googleapis.com/compute/v1/projects/host/global/networks/net"
    sub = "https://www.googleapis.com/compute/v1/projects/host/regions/us-central1/subnetworks/sub"
    graph, ai = topology("gcp", [(kind, "service", "projects/app", data), ("network", net, "projects/host", {}), ("subnetwork", sub, "projects/host", {})])
    target = node(graph, "subnetwork", sub) if kind == "managed_kafka_cluster" else node(graph, "network", net)
    assert linked(graph, node(graph, kind, "service"), target)
    assert next(r for r in ai["inventory"] if r["type"] == kind)["data"]


def test_eks_children_retain_partition_and_cluster_identity():
    cluster = "arn:aws-us-gov:eks:us-gov-west-1:111111111111:cluster/cluster"
    child = "arn:aws-us-gov:eks:us-gov-west-1:111111111111:nodegroup/cluster/nodes/id"
    scope = "111111111111/us-gov-west-1"
    graph, _ = topology("aws", [("eks_cluster", cluster, scope, {"name": "cluster"}), ("eks_nodegroup", child, scope, {"clusterName": "cluster"})])
    assert linked(graph, node(graph, "eks_nodegroup", child), node(graph, "eks_cluster", cluster))


def test_datasync_subnet_arns_keep_remote_ownership_and_resolve_native_subnet_ids():
    arn = "arn:aws:ec2:eu-west-1:222222222222:subnet/subnet-one"
    graph, _ = topology("aws", [
        ("datasync_agent", "agent", "111111111111/us-east-1", {"NetworkDetails": {"PrivateLinkConfig": {"SubnetArns": [arn]}}}),
        ("subnet", "subnet-one", "222222222222/eu-west-1", {}),
    ])
    assert linked(graph, node(graph, "datasync_agent", "agent"), node(graph, "subnet", "subnet-one"))


def test_private_route53_associations_preserve_region_without_inventing_vpc_owner():
    graph, ai = topology("aws", [("route53_zone", "zone", "111111111111/global", {
        "Config": {"PrivateZone": True}, "NetworkDetails": {"VPCs": [{"VPCId": "vpc-one", "VPCRegion": "eu-west-1"}]}})])
    vpc = node(graph, "vpc", "vpc-one")
    assert vpc["scope"] == "owner-unverified/eu-west-1"
    assert vpc["evidence"]["inventory_status"] == "reference_only"
    assert ai["inventory"][0]["data"]["Config"]["PrivateZone"] is True


def test_http_private_integration_resolves_listener_and_load_balancer():
    scope = "111111111111/us-east-1"
    listener = "arn:aws:elasticloadbalancing:us-east-1:111111111111:listener/app/lb/one/listener"
    lb = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/lb/one"
    graph, ai = topology("aws", [("http_api", "api", scope, {"NetworkIntegrations": [{"IntegrationUri": listener}]}),
        ("elbv2_listener", listener, scope, {"ListenerArn": listener, "LoadBalancerArn": lb, "Port": 443, "Protocol": "HTTPS"}),
        ("load_balancer", lb, scope, {})])
    assert linked(graph, node(graph, "http_api", "api"), node(graph, "elbv2_listener", listener))
    assert linked(graph, node(graph, "elbv2_listener", listener), node(graph, "load_balancer", lb))
    assert next(r for r in ai["inventory"] if r["type"] == "elbv2_listener")["data"]["Port"] == 443


def test_azure_container_app_environment_and_nested_dns_endpoint_link():
    scope = "/subscriptions/one"
    base = scope + "/resourceGroups/rg/providers/"
    env = base + "Microsoft.App/managedEnvironments/env"
    subnet = base + "Microsoft.Network/virtualNetworks/net/subnets/sub"
    resolver = base + "Microsoft.Network/dnsResolvers/resolver"
    endpoint = resolver + "/inboundEndpoints/in"
    graph, ai = topology("azure", [
        ("container_app", "app", scope, {"properties": {"managedEnvironmentId": env, "configuration": {
            "ingress": {"external": True, "targetPort": 8080, "fqdn": "app.example.com"}, "secrets": [{"value": "SECRET_SENTINEL"}]}}}),
        ("container_app_environment", env, scope, {"properties": {"vnetConfiguration": {"infrastructureSubnetId": subnet}}}),
        ("subnet", subnet, scope, {}), ("dns_resolver", resolver, scope, {}),
        ("dns_inbound_endpoint", endpoint, resolver, {"properties": {"ipConfigurations": [{"subnet": {"id": subnet}}]}}),
    ])
    assert linked(graph, node(graph, "container_app", "app"), node(graph, "container_app_environment", env))
    assert linked(graph, node(graph, "container_app_environment", env), node(graph, "subnet", subnet))
    assert linked(graph, node(graph, "dns_inbound_endpoint", endpoint), node(graph, "dns_resolver", resolver))
    assert linked(graph, node(graph, "dns_inbound_endpoint", endpoint), node(graph, "subnet", subnet))
    # First reads are network-only projections; the complete native record is
    # handed over separately as the full source lookup (full AI evidence).
    assert "SECRET_SENTINEL" not in json.dumps({"report": ai["report"], "inventory": ai["inventory"]})
    assert "SECRET_SENTINEL" in json.dumps(ai["source_inventory"])
    app = next(r for r in ai["inventory"] if r["type"] == "container_app")
    assert app["data"]["properties"]["managedEnvironmentId"] == env
    assert app["data"]["properties"]["configuration"]["ingress"]["targetPort"] == 8080
    assert native_network_resource(app)["data"] == app["data"]


def test_k8s_owners_gateway_routes_and_legacy_endpoints_are_not_dropped():
    scope = "apps"
    graph, ai = topology("k8s", [
        ("deployment", "deployment", scope, {"metadata": {"name": "app", "namespace": scope, "uid": "dep-uid"},
            "spec": {"template": {"metadata": {"labels": {"app": "app"}}, "spec": {"containers": [{"name": "app", "ports": [{"containerPort": 8080}], "env": [{"value": "SECRET_SENTINEL"}]}]}}}}),
        ("replicaset", "rs", scope, {"metadata": {"name": "rs", "namespace": scope, "uid": "rs-uid", "ownerReferences": [{"name": "app", "uid": "dep-uid", "kind": "Deployment"}]}}),
        ("pod", "pod", scope, {"metadata": {"name": "pod", "namespace": scope, "uid": "pod-uid", "ownerReferences": [{"name": "rs", "uid": "rs-uid", "kind": "ReplicaSet"}]}}),
        ("service", "svc", scope, {"metadata": {"name": "svc", "namespace": scope}}),
        ("gateway", "gw", scope, {"metadata": {"name": "gw", "namespace": scope}}),
        ("httproute", "route", scope, {"metadata": {"name": "route", "namespace": scope}, "spec": {"parentRefs": [{"name": "gw"}], "rules": [{"backendRefs": [{"name": "svc", "port": 8080}]}]}}),
        ("endpoint", "ep", scope, {"metadata": {"name": "svc", "namespace": scope}, "subsets": [{"addresses": [{"ip": "10.0.0.1", "targetRef": {"kind": "Pod", "name": "pod", "uid": "pod-uid"}}]}]}),
    ], {"cluster_id": "cluster"})
    for sk, sn, dk, dn in [("replicaset", "rs", "deployment", "deployment"), ("pod", "pod", "replicaset", "rs"),
            ("httproute", "route", "gateway", "gw"), ("httproute", "route", "service", "svc"), ("endpoint", "ep", "pod", "pod")]:
        assert linked(graph, node(graph, sk, sn), node(graph, dk, dn))
    # First reads are network-only projections; the complete native record is
    # handed over separately as the full source lookup (full AI evidence).
    assert "SECRET_SENTINEL" not in json.dumps({"report": ai["report"], "inventory": ai["inventory"]})
    assert "SECRET_SENTINEL" in json.dumps(ai["source_inventory"])
    dep = next(r for r in ai["inventory"] if r["type"] == "deployment")["data"]
    assert dep["spec"]["template"]["spec"]["containers"][0]["ports"][0]["containerPort"] == 8080


def test_all_native_azure_network_services_have_map_coverage():
    from peaso.collectors.azure import ENDPOINTS
    from peaso.collectors.azure_network_catalog import CHILDREN
    assert not {kind for kind, (resource_type, _) in ENDPOINTS.items() if resource_type.startswith("Microsoft.Network/")} - NETWORK_TYPES
    assert not set(CHILDREN) - NETWORK_TYPES


def test_k8s_endpoint_registry_has_no_unclassified_network_resource():
    from peaso.collectors.k8s import ENDPOINTS
    excluded = {"role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount", "resourcequota", "limitrange",
        # Config Sync and Config Connector objects carry GitOps, IAM and project bindings, not traffic paths.
        "configsync_rootsync", "configconnector", "configconnectorcontext", "kcc_iampolicy", "kcc_iampartialpolicy", "kcc_project",
        # Same /api/v1/endpoints list as the network "endpoint" inventory, kept under its own kind for the unused-network checks.
        "endpoints"}
    from peaso.collectors.k8s_network_catalog import ENDPOINTS as NETWORK_ENDPOINTS
    assert ENDPOINTS["endpoints"] == NETWORK_ENDPOINTS["endpoint"]
    assert not set(ENDPOINTS) - NETWORK_TYPES - excluded


def test_aws_sdk_network_schemas_have_no_unreviewed_live_inventory_omissions():
    import botocore.session
    from botocore import xform_name
    from peaso.collectors.aws import SPECS
    from peaso.analysis.network_catalog import AWS_SCHEMA_EXCLUSIONS
    from scripts.peaso_deploy_customer_policy import UNAVAILABLE_SDK_METADATA_OPERATIONS
    available = set(botocore.session.get_session().get_available_services())
    session = botocore.session.get_session()
    markers = {"VpcId", "VpcIds", "SubnetId", "SubnetIds", "SecurityGroupIds", "VpcConfig", "VpcConfiguration", "VpcOptions",
        "VpcEndpointId", "VpcEndpointIds", "NetworkInterfaces", "NetworkInterfaceId", "VpcSubnetIds", "VpcSecurityGroupIds"}
    def network_schema(shape, depth=0, ancestors=()):
        if shape is None or depth > 9 or shape.name in ancestors:
            return False
        if shape.type_name == "structure":
            return bool(set(shape.members) & markers) or any(network_schema(child, depth + 1, ancestors + (shape.name,)) for child in shape.members.values())
        if shape.type_name in {"list", "map"}:
            return network_schema(shape.member if shape.type_name == "list" else shape.value, depth + 1, ancestors + (shape.name,))
        return False
    missing = []
    for kind, (service, operation, _) in SPECS.items():
        if kind in NETWORK_TYPES or kind in AWS_SCHEMA_EXCLUSIONS:
            continue
        if service not in available:
            # The pinned SDK has no model for this client; only reviewed unavailable reads may appear here.
            assert (service, operation) in UNAVAILABLE_SDK_METADATA_OPERATIONS, kind
            continue
        model = session.get_service_model(service)
        native_operation = next((name for name in model.operation_names if xform_name(name) == operation), None)
        if native_operation and network_schema(model.operation_model(native_operation).output_shape):
            missing.append(kind)
    assert not missing, f"Network-capable SDK inventories need a graph/AI path or an explicit review: {sorted(missing)}"


def test_gateway_collector_negotiates_versions_and_keeps_discovery_denial_unknown():
    from peaso.collectors import k8s
    from tests.test_peaso_collectors_azurek8s import FakeKube, kube_list
    def handler(path, params):
        if path == "/apis":
            return {"groups": [{"name": "gateway.networking.k8s.io", "versions": [{"version": "v1beta1"}]}]}
        if path.endswith("/v1beta1"):
            return {"resources": [{"name": "httproutes", "namespaced": True, "verbs": ["list"]}]}
        assert path == "/apis/gateway.networking.k8s.io/v1beta1/namespaces/apps/httproutes"
        return kube_list([{"metadata": {"name": "route", "namespace": "apps", "uid": "route-uid"}, "spec": {"rules": []}}])
    api = FakeKube(handler)
    snap = k8s.collect({"scopes": ["apps"]}, ["httproute"], api=api)
    row = next(c for c in snap["collections"] if c["type"] == "httproute")
    assert row["status"] == "collected" and len(row["items"]) == 1
    denied = FakeKube(lambda *args: (_ for _ in ()).throw(k8s.K8sReadError("forbidden", 403)))
    snap = k8s.collect({"scopes": ["apps"]}, ["httproute"], api=denied)
    assert next(c for c in snap["collections"] if c["type"] == "httproute")["status"] == "denied"


def test_uninstalled_gateway_api_has_explicit_empty_coverage():
    from peaso.collectors import k8s
    from tests.test_peaso_collectors_azurek8s import FakeKube
    api = FakeKube(lambda path, params: {"groups": []})
    snap = k8s.collect({"scopes": ["apps"]}, ["gateway", "httproute"], api=api)
    assert all(c["status"] == "empty" and c["applicability"]["observed_api_group_absent"] == "gateway.networking.k8s.io" for c in snap["collections"])
