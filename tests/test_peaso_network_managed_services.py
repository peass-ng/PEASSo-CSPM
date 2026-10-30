"""Managed network chains must survive collection, graph selection and AI export."""
import json

import pytest

from peaso.analysis import REQUIRED_TYPES
from peaso.analysis.common import analysis_context
from peaso.analysis.network import build_network, NETWORK_TYPES
from peaso.analysis.network_services import SERVICE_TYPES
from peaso.ai.network import prepare
from peaso.collectors import supported_types
from peaso.snapshot import make_snapshot, resources


def topology(provider, rows, metadata=None):
    collections = {}
    for kind, native, scope, data in rows:
        collections.setdefault((kind, scope), []).append(dict(data, _resource_id=native))
    snap = make_snapshot(provider, sorted({s for _, s in collections}), [
        {"type": k, "scope": s, "status": "collected", "items": items}
        for (k, s), items in collections.items()], metadata=metadata or {})
    inventory = resources(snap)
    with analysis_context(snap):
        graph = build_network(snap, inventory)
    assert len({e["id"] for e in graph["edges"]}) == len(graph["edges"])
    report = {"provider": provider, "graphs": {"network": graph}, "coverage": [
        {"type": k, "scope": s, "status": "denied"} for k, s in collections]}
    ai = prepare(report, inventory, snap)
    assert {r["id"] for r in inventory} <= {r["id"] for r in ai["inventory"]}
    assert len(ai["report"]["coverage"]) == len(collections)
    return graph, ai


def node(graph, kind, native):
    return next(n for n in graph["nodes"] if n["type"] == kind and n["native_id"] == native)


def linked(graph, src, dst, relation=None):
    return [e for e in graph["edges"] if e["source"] == src["id"] and e["target"] == dst["id"]
            and (relation is None or e["type"] == relation)]


@pytest.mark.parametrize("provider", SERVICE_TYPES)
def test_service_catalog_has_collectors_and_network_dependencies(provider):
    from peaso.engine import plan_collection
    types = SERVICE_TYPES[provider]
    assert types <= set(supported_types(provider))
    assert types <= NETWORK_TYPES
    assert types <= set(REQUIRED_TYPES[provider]["network"])
    plan = plan_collection({"connector": {"provider": provider}, "categories": ["network"], "checks": [], "frameworks": []})
    assert types <= set(plan)


def test_aws_ecs_efs_and_cloudfront_chains_retain_native_scopes_and_ai_facts():
    scope, global_scope = "111111111111/us-east-1", "111111111111/global"
    cluster = "arn:aws:ecs:us-east-1:111111111111:cluster/app"
    lb = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/backend/1"
    fs = "arn:aws:elasticfilesystem:us-east-1:111111111111:file-system/fs-one"
    graph, ai = topology("aws", [
        ("vpc", "vpc-one", scope, {}), ("subnet", "subnet-one", scope, {"VpcId": "vpc-one"}),
        ("security_group", "sg-one", scope, {"VpcId": "vpc-one"}),
        ("network_interface", "eni-one", scope, {"SubnetId": "subnet-one", "VpcId": "vpc-one"}),
        ("load_balancer", lb, scope, {"VpcId": "vpc-one"}),
        ("ecs_cluster", cluster, scope, {"clusterArn": cluster}),
        ("ecs_service", "svc-one", scope, {"clusterArn": cluster, "serviceName": "app", "networkConfiguration": {
            "awsvpcConfiguration": {"subnets": ["subnet-one"], "securityGroups": ["sg-one"], "assignPublicIp": "DISABLED"}},
            "environment": [{"name": "bad", "value": "secret-sentinel"}]}),
        ("ecs_task", "task-one", scope, {"clusterArn": cluster, "group": "service:app", "attachments": [{"type": "ElasticNetworkInterface", "details": [
            {"name": "subnetId", "value": "subnet-one"}, {"name": "networkInterfaceId", "value": "eni-one"},
            {"name": "credential", "value": "secret-sentinel"}]}]}),
        ("efs_file_system", fs, scope, {"FileSystemId": "fs-one"}),
        ("efs_mount_target", "fsmt-one", scope, {"FileSystemId": "fs-one", "SubnetId": "subnet-one",
            "NetworkInterfaceId": "eni-one", "SecurityGroups": ["sg-one"]}),
        ("cloudfront_distribution", "dist-one", global_scope, {"Config": {"DistributionConfig": {"Origins": {"Items": [{
            "VpcOriginConfig": {"VpcOriginId": "vo-one"}, "CustomHeaders": {"Items": [{"HeaderValue": "secret-sentinel"}]}}]}}}}),
        ("cloudfront_vpc_origin", "vo-one", global_scope, {"VpcOrigin": {"VpcOriginEndpointConfig": {"Arn": lb, "HTTPSPort": 443}}}),
    ])
    for src_kind, src_native, dst_kind, dst_native in [
        ("ecs_service", "svc-one", "subnet", "subnet-one"), ("ecs_service", "svc-one", "security_group", "sg-one"),
        ("ecs_task", "task-one", "network_interface", "eni-one"), ("ecs_task", "task-one", "subnet", "subnet-one"),
        ("ecs_task", "task-one", "ecs_service", "svc-one"),
        ("efs_mount_target", "fsmt-one", "efs_file_system", fs), ("efs_mount_target", "fsmt-one", "security_group", "sg-one"),
        ("cloudfront_distribution", "dist-one", "cloudfront_vpc_origin", "vo-one"),
        ("cloudfront_vpc_origin", "vo-one", "load_balancer", lb),
    ]:
        assert linked(graph, node(graph, src_kind, src_native), node(graph, dst_kind, dst_native))
    assert node(graph, "ecs_task", "task-one")["parent_id"] == node(graph, "subnet", "subnet-one")["id"]
    data = {r["type"]: r["data"] for r in ai["inventory"]}
    assert data["ecs_service"]["networkConfiguration"]["awsvpcConfiguration"]["securityGroups"] == ["sg-one"]
    assert data["ecs_task"]["attachments"][0]["details"][1]["value"] == "eni-one"
    assert data["cloudfront_vpc_origin"]["VpcOrigin"]["VpcOriginEndpointConfig"]["HTTPSPort"] == 443
    # Network-only first reads omit workload secrets; the complete native
    # record is handed over separately as the full source lookup.
    assert "secret-sentinel" not in json.dumps({"report": ai["report"], "inventory": ai["inventory"]})
    assert "secret-sentinel" in json.dumps(ai["source_inventory"])
    assert all(e["layer"] == "structural" for e in graph["edges"])


def test_azure_private_link_target_resolves_case_insensitively_across_subscriptions():
    local, remote = "/subscriptions/one", "/subscriptions/two"
    subnet = local + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/net/subnets/sub"
    pe = local + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe"
    target = remote + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store"
    graph, ai = topology("azure", [
        ("subnet", subnet, local, {}), ("storage_account", target, remote, {"id": target, "properties": {
            "publicNetworkAccess": "Disabled", "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": pe}}}],
            "networkAcls": {"defaultAction": "Deny"}, "appSettings": {"name": "secret-sentinel"}}}),
        ("private_endpoint", pe, local, {"id": pe, "properties": {"subnet": {"id": subnet},
            "manualPrivateLinkServiceConnections": [{"properties": {"privateLinkServiceId": target.upper(), "groupIds": ["blob"]}}]}}),
        ("app_service", "app", local, {"properties": {"virtualNetworkSubnetId": subnet}}),
    ])
    assert linked(graph, node(graph, "private_endpoint", pe), node(graph, "storage_account", target), "private_link_target")
    assert linked(graph, node(graph, "storage_account", target), node(graph, "private_endpoint", pe))
    assert linked(graph, node(graph, "app_service", "app"), node(graph, "subnet", subnet))
    assert not any(n["type"] == "private_link_service_reference" for n in graph["nodes"])
    storage = next(r["data"] for r in ai["inventory"] if r["type"] == "storage_account")
    assert storage["properties"]["networkAcls"]["defaultAction"] == "Deny"
    # Network-only first reads omit workload secrets; the complete native
    # record is handed over separately as the full source lookup.
    assert "secret-sentinel" not in json.dumps({"report": ai["report"], "inventory": ai["inventory"]})
    assert "secret-sentinel" in json.dumps(ai["source_inventory"])


def test_gcp_psc_neg_sql_and_serverless_use_remote_project_and_connector_links():
    scope, remote = "projects/app", "projects/host"
    base = "https://www.googleapis.com/compute/v1/"
    network = base + remote + "/global/networks/net"
    subnet = base + remote + "/regions/us-central1/subnetworks/sub"
    attachment = base + remote + "/regions/us-central1/serviceAttachments/producer"
    neg = base + scope + "/regions/us-central1/networkEndpointGroups/psc"
    connector = scope + "/locations/us-central1/connectors/connector"
    graph, ai = topology("gcp", [
        ("network", network, remote, {}), ("subnetwork", subnet, remote, {"network": network}),
        ("service_attachment", attachment, remote, {"natSubnets": [subnet]}),
        ("network_endpoint_group", neg, scope, {"pscTargetService": attachment}),
        ("backend_service", "backend", scope, {"backends": [{"group": neg}]}),
        ("forwarding_rule", "consumer", scope, {"target": attachment, "network": network}),
        ("vpc_access_connector", connector, scope, {"name": connector, "subnet": {"name": "sub", "projectId": "host"}}),
        ("cloudrun_service", "run", scope, {"template": {"vpcAccess": {"connector": connector, "egress": "ALL_TRAFFIC"},
            "containers": [{"env": [{"name": "bad", "value": "secret-sentinel"}]}]}}),
        ("sql_instance", "sql", scope, {"settings": {"ipConfiguration": {"privateNetwork": network, "pscConfig": {"pscEnabled": True}}},
            "pscServiceAttachmentLink": attachment}),
    ])
    for sk, sn, dk, dn in [
        ("service_attachment", attachment, "subnetwork", subnet), ("network_endpoint_group", neg, "service_attachment", attachment),
        ("backend_service", "backend", "network_endpoint_group", neg), ("forwarding_rule", "consumer", "service_attachment", attachment),
        ("vpc_access_connector", connector, "subnetwork", subnet), ("cloudrun_service", "run", "vpc_access_connector", connector),
        ("sql_instance", "sql", "network", network),
    ]:
        assert linked(graph, node(graph, sk, sn), node(graph, dk, dn))
    assert not any(n["type"] in {"target_proxy", "instance_group"} and n["native_id"] in {attachment, neg} for n in graph["nodes"])
    # Network-only first reads omit workload secrets; the complete native
    # record is handed over separately as the full source lookup.
    assert "secret-sentinel" not in json.dumps({"report": ai["report"], "inventory": ai["inventory"]})
    assert "secret-sentinel" in json.dumps(ai["source_inventory"])
    assert next(r for r in ai["inventory"] if r["type"] == "cloudrun_service")["data"]["template"]["vpcAccess"]["egress"] == "ALL_TRAFFIC"


def test_ai_preserves_existing_eks_gke_and_rds_network_paths():
    from peaso.ai.network import native_network_resource
    for provider, kind, data in [
        ("aws", "eks_cluster", {"Cluster": {"cluster": {"endpoint": "https://eks", "resourcesVpcConfig": {"vpcId": "vpc-one", "subnetIds": ["subnet-one"]}}}}),
        ("aws", "rds_cluster", {"DBSubnetGroupDetails": {"VpcId": "vpc-one", "Subnets": [{"SubnetIdentifier": "subnet-one"}]}}),
        ("gcp", "gke_cluster", {"network": "projects/p/global/networks/n", "subnetwork": "projects/p/regions/r/subnetworks/s"}),
    ]:
        assert native_network_resource({"provider": provider, "type": kind, "data": data})["data"] == data


def test_memorydb_subnet_groups_and_collected_privatelink_services_resolve():
    scope = "111111111111/us-east-1"
    service = "com.amazonaws.vpce.us-east-1.vpce-svc-one"
    graph, _ = topology("aws", [
        ("subnet", "subnet-one", scope, {}),
        ("memorydb_cluster", "cache", scope, {"SubnetGroupName": "cache-subnets"}),
        ("memorydb_subnet_group", "cache-subnets", scope, {"Subnets": [{"Identifier": "subnet-one"}]}),
        ("vpc_endpoint", "vpce-one", scope, {"ServiceName": service}),
        ("vpc_endpoint_service", "vpce-svc-one", scope, {"ServiceName": service}),
    ])
    assert linked(graph, node(graph, "memorydb_cluster", "cache"), node(graph, "memorydb_subnet_group", "cache-subnets"))
    assert linked(graph, node(graph, "memorydb_subnet_group", "cache-subnets"), node(graph, "subnet", "subnet-one"))
    assert linked(graph, node(graph, "vpc_endpoint", "vpce-one"), node(graph, "vpc_endpoint_service", "vpce-svc-one"))


def test_gcp_serverless_neg_resolves_the_collected_cloudrun_service():
    scope = "projects/app"
    service = scope + "/locations/us-central1/services/app"
    neg = "https://www.googleapis.com/compute/v1/projects/app/regions/us-central1/networkEndpointGroups/serverless"
    graph, _ = topology("gcp", [
        ("network_endpoint_group", neg, scope, {"cloudRun": {"service": "app"}}),
        ("cloudrun_service", service, scope, {"name": service}),
    ])
    assert linked(graph, node(graph, "network_endpoint_group", neg), node(graph, "cloudrun_service", service), "serverless_backend")


def test_gcp_peering_and_psc_consumer_networks_do_not_assign_producer_containment():
    scope = "projects/app"
    base = "https://www.googleapis.com/compute/v1/projects/app/"
    graph, _ = topology("gcp", [
        ("network", base + "global/networks/a", scope, {"peerings": [{"network": base + "global/networks/b"}]}),
        ("network", base + "global/networks/b", scope, {}),
        ("service_attachment", "producer", scope, {"connectedEndpoints": [{"consumerNetwork": base + "global/networks/b"}]}),
    ])
    assert "parent_id" not in node(graph, "network", base + "global/networks/a")
    assert "parent_id" not in node(graph, "service_attachment", "producer")


def test_k8s_pod_claim_volume_cloud_handle_chain_and_binding_uid():
    scope = "apps"
    graph, ai = topology("k8s", [
        ("pod", "pod", scope, {"metadata": {"name": "app", "namespace": "apps"}, "spec": {"volumes": [
            {"name": "data", "persistentVolumeClaim": {"claimName": "data"}}]}}),
        ("persistentvolumeclaim", "claim", scope, {"metadata": {"name": "data", "namespace": "apps", "uid": "uid-one"}, "spec": {"volumeName": "volume"}}),
        ("persistentvolume", "volume", "_cluster", {"metadata": {"name": "volume"}, "spec": {
            "claimRef": {"name": "data", "namespace": "apps", "uid": "uid-one"},
            "csi": {"driver": "efs.csi.aws.com", "volumeHandle": "fs-one::fsap-one", "nodePublishSecretRef": {"name": "secret-sentinel"}}}}),
    ], {"cluster_id": "cluster-one"})
    assert linked(graph, node(graph, "pod", "pod"), node(graph, "persistentvolumeclaim", "claim"))
    assert linked(graph, node(graph, "persistentvolumeclaim", "claim"), node(graph, "persistentvolume", "volume"))
    assert linked(graph, node(graph, "persistentvolume", "volume"), node(graph, "external_service_reference", "fs-one::fsap-one"))
    # Network-only first reads omit workload secrets; the complete native
    # record is handed over separately as the full source lookup.
    assert "secret-sentinel" not in json.dumps({"report": ai["report"], "inventory": ai["inventory"]})
    assert "secret-sentinel" in json.dumps(ai["source_inventory"])
    assert next(r for r in ai["inventory"] if r["type"] == "pod")["data"]["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] == "data"


def test_k8s_native_storage_collection_retains_cluster_and_namespace_identity():
    from peaso.collectors import k8s
    from tests.test_peaso_collectors_azurek8s import FakeKube, kube_list
    def handler(path, params):
        if path == "/api/v1/persistentvolumes":
            return kube_list([{"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "disk", "uid": "pv-uid"},
                "spec": {"csi": {"driver": "efs.csi.aws.com", "volumeHandle": "fs-one"}}}])
        assert path == "/api/v1/namespaces/apps/persistentvolumeclaims"
        return kube_list([{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "claim", "namespace": "apps", "uid": "pvc-uid"},
            "spec": {"volumeName": "disk"}}])
    api = FakeKube(handler)
    snap = k8s.collect({"scopes": ["apps"]}, ["persistentvolume", "persistentvolumeclaim"], api=api)
    assert all(c["status"] == "collected" for c in snap["collections"])
    assert {r["type"] for r in resources(snap)} == {"persistentvolume", "persistentvolumeclaim"}
    with analysis_context(snap):
        graph = build_network(snap, resources(snap))
    assert any(e["type"] == "storage_attachment" for e in graph["edges"])


def test_azure_native_private_link_service_collection():
    from peaso.collectors import azure
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, envelope
    rid = BASE + "Microsoft.Network/privateLinkServices/service"
    api = Transport(routes("private_link_service", rid, {"visibility": {"subscriptions": ["*"]},
        "autoApproval": {"subscriptions": []}, "privateEndpointConnections": []}))
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["private_link_service"], transport=api)
    assert envelope(snap, "private_link_service")["status"] == "collected"
    assert envelope(snap, "private_link_service")["items"][0]["id"] == rid
    assert any(SCOPE + "/providers/Microsoft.Network/privateLinkServices" in url for url in api.calls)


def test_agent_bundle_keeps_service_facts_after_second_projection(tmp_path):
    import sqlite3
    from peaso.ai.network import build
    scope = "111111111111/us-east-1"
    graph, platform = topology("aws", [
        ("ecs_service", "service", scope, {"networkConfiguration": {"awsvpcConfiguration": {
            "subnets": ["subnet-one"], "securityGroups": ["sg-one"]}}, "environment": {"apiKey": "secret-sentinel"}}),
        ("efs_mount_target", "mount", scope, {"FileSystemId": "fs-one", "SubnetId": "subnet-one"}),
    ])
    def write(path, value):
        path.write_text(json.dumps(value))
    build(tmp_path, platform, [], write)
    with sqlite3.connect(tmp_path / "context.sqlite") as db:
        records = [json.loads(row[0]) for row in db.execute("SELECT detail FROM records WHERE domain='resources'")]
    service = next(r for r in records if r["type"] == "ecs_service")
    assert service["data"]["networkConfiguration"]["awsvpcConfiguration"]["subnets"] == ["subnet-one"]
    assert "secret-sentinel" not in json.dumps(records)
    topology_data = json.loads((tmp_path / "topology.json").read_text())
    assert topology_data["resource_counts"]["efs_mount_target"] == 1
    assert sum(r["count"] for r in topology_data["edge_groups"]) == len(graph["edges"])
