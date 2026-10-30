"""Native collectors: permission boundaries, authentication, caps and scope identity."""
import base64
import copy
from urllib.parse import urlparse
import json
import threading
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, k8s
from peaso.snapshot import resources, validate


class ReadError(RuntimeError):
    def __init__(self, status, message="sensitive upstream body: fake-token"):
        super().__init__(message)
        self.status = status


class FakeAzure:
    tenant = "tenant-a"

    def __init__(self, handler):
        self.handler, self.calls = handler, []
        self.closed = False

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, copy.deepcopy(body), audience))
        return copy.deepcopy(self.handler(url, body, audience))

    def close(self):
        self.closed = True


class FakeKube:
    server = "https://cluster-a.example"

    def __init__(self, handler):
        self.handler, self.calls = handler, []
        self.closed = False

    def get_json(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        return copy.deepcopy(self.handler(path, params or {}))

    def close(self):
        self.closed = True


def collection(snapshot, kind, scope=None):
    return next(c for c in snapshot["collections"] if c["type"] == kind and (scope is None or c["scope"] == scope))


def kube_item(name="same", namespace="team-a", **fields):
    return {"apiVersion": "v1", "metadata": {"name": name, "namespace": namespace, "uid": "uid-" + name}, **fields}


def kube_list(items=(), continuation="", version="12"):
    return {"items": list(items), "metadata": {"continue": continuation, "resourceVersion": version}}


def test_k8s_custom_network_policy_inventory_uses_api_discovery():
    def absent(path, _params):
        assert path == "/apis"
        return {"groups": []}
    kinds = ["cilium_networkpolicy", "cilium_clusterwide_networkpolicy", "calico_networkpolicy", "calico_global_networkpolicy",
        "admin_networkpolicy", "baseline_admin_networkpolicy", "cluster_networkpolicy"]
    snapshot = k8s.collect({"scopes": ["team-a"]}, kinds,
        api=FakeKube(absent))
    for kind in kinds:
        row = collection(snapshot, kind, "team-a")
        assert row["status"] == "empty"
        assert row["applicability"]["source"] == "GET /apis"

    def present(path, _params):
        if path == "/apis":
            return {"groups": [{"name": "cilium.io", "versions": [{"version": "v2"}]}]}
        if path == "/apis/cilium.io/v2/namespaces/team-a/ciliumnetworkpolicies":
            return kube_list([kube_item("restrict", apiVersion="cilium.io/v2", spec={"endpointSelector": {}})])
        assert path == "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies"
        return kube_list([{"apiVersion": "cilium.io/v2", "metadata": {"name": "global-restrict", "uid": "uid-global"},
            "spec": {"endpointSelector": {}}}])
    api = FakeKube(present)
    snapshot = k8s.collect({"scopes": ["team-a"]}, kinds, api=api)
    assert collection(snapshot, "cilium_networkpolicy", "team-a")["status"] == "collected"
    assert len(collection(snapshot, "cilium_networkpolicy", "team-a")["items"]) == 1
    assert collection(snapshot, "cilium_clusterwide_networkpolicy", "team-a")["status"] == "collected"
    assert len(collection(snapshot, "cilium_clusterwide_networkpolicy", "team-a")["items"]) == 1
    assert collection(snapshot, "calico_networkpolicy", "team-a")["status"] == "empty"
    assert collection(snapshot, "calico_global_networkpolicy", "team-a")["status"] == "empty"
    assert collection(snapshot, "admin_networkpolicy", "team-a")["status"] == "empty"
    assert collection(snapshot, "baseline_admin_networkpolicy", "team-a")["status"] == "empty"
    assert collection(snapshot, "cluster_networkpolicy", "team-a")["status"] == "empty"


def test_k8s_admin_policy_inventory_distinguishes_served_versions():
    def handler(path, _params):
        if path == "/apis":
            return {"groups": [{"name": "policy.networking.k8s.io", "versions": [{"version": "v1alpha1"}]}]}
        assert path in {"/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies",
            "/apis/policy.networking.k8s.io/v1alpha1/baselineadminnetworkpolicies"}
        return kube_list([{"apiVersion": "policy.networking.k8s.io/v1alpha1", "metadata": {"name": "guard", "uid": "uid-guard"},
            "spec": {"subject": {"namespaces": {}}}}])
    snapshot = k8s.collect({"scopes": ["team-a"]},
        ["admin_networkpolicy", "baseline_admin_networkpolicy", "cluster_networkpolicy"], api=FakeKube(handler))
    assert collection(snapshot, "admin_networkpolicy")["status"] == "collected"
    assert collection(snapshot, "baseline_admin_networkpolicy")["status"] == "collected"
    assert collection(snapshot, "cluster_networkpolicy")["status"] not in {"collected", "empty"}


def test_k8s_custom_policy_lists_each_namespace_and_cluster_policy_once():
    def handler(path, _params):
        if path == "/apis":
            return {"groups": [{"name": "cilium.io", "versions": [{"version": "v2"}]}]}
        if path == "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies":
            return kube_list()
        namespace = path.split("/namespaces/", 1)[1].split("/", 1)[0]
        assert path == f"/apis/cilium.io/v2/namespaces/{namespace}/ciliumnetworkpolicies"
        return kube_list([kube_item("restrict", namespace=namespace, apiVersion="cilium.io/v2")])
    api = FakeKube(handler)
    snapshot = k8s.collect({"scopes": ["team-a", "team-b"]},
        ["cilium_networkpolicy", "cilium_clusterwide_networkpolicy"], api=api)
    assert collection(snapshot, "cilium_networkpolicy", "team-a")["status"] == "collected"
    assert collection(snapshot, "cilium_networkpolicy", "team-b")["status"] == "collected"
    assert sum(c["type"] == "cilium_clusterwide_networkpolicy" for c in snapshot["collections"]) == 1
    assert sum(path == "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies" for path, _ in api.calls) == 1


@pytest.mark.parametrize("identifier", [
    "/providers/Microsoft.Subscription/policies/default",
    "providers/Microsoft.Subscription/policies/default",
    "providers/Microsoft.Subscription/policies/unrelated",
])
def test_tenant_subscription_policy_normalizes_only_expected_identity(identifier):
    policy = {"id": identifier, "properties": {"blockSubscriptionsLeavingTenant": True}}
    transport = FakeAzure(lambda url, body, audience: policy)
    transport.verified_tenant = True
    snapshot = azure.collect({"scopes": ["sub-a"], "options": {"retries": 0}},
                             ["subscription_tenant_policy"], transport=transport)
    result = collection(snapshot, "subscription_tenant_policy")
    if identifier.endswith("/unrelated"):
        assert result["status"] == "malformed" and result["items"] == []
    else:
        assert result["status"] == "collected"
        assert result["items"][0]["id"] == "/providers/Microsoft.Subscription/policies/default"
        assert result["items"][0]["_provenance"]["tenant_verified"] is True


def test_azure_vm_full_detail_requests_instance_view_power_state():
    rid = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/server"
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == rid:
            assert "$expand=instanceView" in urlsplit(url).query
            return {"id": rid, "type": "Microsoft.Compute/virtualMachines", "name": "server", "properties": {"provisioningState": "Succeeded",
                "instanceView": {"statuses": [{"code": "PowerState/running"}]}}}
        if path == "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Compute/virtualMachines":
            return {"value": [{"id": rid, "type": "Microsoft.Compute/virtualMachines", "name": "server"}]}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["vm"], transport=api)
    vm = collection(snapshot, "vm")["items"][0]
    assert vm["properties"]["instanceView"]["statuses"] == [{"code": "PowerState/running"}]
    assert vm["_provenance"]["expand"] == "instanceView"


def test_azure_graph_pagination_then_arm_details_cross_subscription():
    def handler(url, body, audience):
        if body is not None:
            # One batched Resource Graph query covers every subscription.
            if "$skipToken" not in body["options"]:
                return {"data": [{"id": f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/same", "type": "microsoft.network/virtualnetworks"} for sub in body["subscriptions"]], "$skipToken": "page-2"}
            return {"data": [], "resultTruncated": "false"}
        if "/providers/Microsoft.Insights/diagnosticSettings?" in url:
            return {"value": []}
        sub = urlsplit(url).path.split("/")[2]
        if urlsplit(url).path.endswith("/virtualNetworks/same"):
            return {"id": f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/same",
                "type": "Microsoft.Network/virtualNetworks", "properties": {"provisioningState": "Succeeded", "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": []}}
        return {"value": [{"id": f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/same", "type": "Microsoft.Network/virtualNetworks", "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": []}}]}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"], "options": {"concurrency": 2}}, ["vnet"], transport=api)
    assert validate(snapshot) == snapshot
    # Two graph pages, then one ARM inventory, VNet detail and diagnostic read per scope.
    assert len(api.calls) == 8
    graph = [body for _, body, _ in api.calls if body is not None]
    assert len(graph) == 2 and all(sorted(body["subscriptions"]) == ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"] for body in graph)
    assert len(collection(snapshot, "resource_graph", "/subscriptions/11111111-1111-1111-1111-111111111111")["items"]) == 1
    assert len(collection(snapshot, "resource_graph", "/subscriptions/22222222-2222-2222-2222-222222222222")["items"]) == 1
    assert sum("/providers/Microsoft.Insights/diagnosticSettings?" in url for url, _, _ in api.calls) == 2
    assert len({(url, repr(body), audience) for url, body, audience in api.calls}) == len(api.calls)
    assert collection(snapshot, "vnet", "/subscriptions/11111111-1111-1111-1111-111111111111")["status"] == "collected"
    assert collection(snapshot, "vnet", "/subscriptions/22222222-2222-2222-2222-222222222222")["status"] == "collected"
    ids = [r["id"] for r in resources(snapshot) if r["type"] == "vnet"]
    assert len(set(ids)) == 2
    assert not api.closed


def test_azure_route_table_detail_captures_peering_barrier_and_provisioning():
    route_id = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/routeTables/rt"
    def handler(url, body, audience):
        if body is not None:
            return {"data": []}
        if "/providers/Microsoft.Network/routeTables?" in url:
            return {"value": [{"id": route_id, "properties": {"routes": []}}]}
        if urlsplit(url).path == route_id:
            return {"id": route_id, "properties": {"disablePeeringRoute": "All",
                "provisioningState": "Succeeded", "routes": [{"name": "drop", "properties": {
                    "addressPrefix": "10.1.0.0/16", "nextHopType": "None",
                    "provisioningState": "Succeeded"}}]}}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["route_table"], transport=api)
    table = collection(snapshot, "route_table")["items"][0]
    assert collection(snapshot, "route_table")["status"] == "collected"
    assert table["properties"]["disablePeeringRoute"] == "All"
    assert table["properties"]["routes"][0]["properties"]["provisioningState"] == "Succeeded"
    assert table["_provenance"]["representation"] == "full"
    assert table["_provenance"]["api_version"] == "2025-07-01"
    assert any(urlsplit(url).path == route_id and "api-version=2025-07-01" in url
        for url, _, _ in api.calls)


def test_azure_nsg_detail_captures_rule_provisioning():
    nsg_id = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"
    def handler(url, body, audience):
        if body is not None:
            return {"data": []}
        if "/providers/Microsoft.Network/networkSecurityGroups?" in url:
            return {"value": [{"id": nsg_id, "type": "Microsoft.Network/networkSecurityGroups", "properties": {"securityRules": []}}]}
        if urlsplit(url).path == nsg_id:
            return {"id": nsg_id, "type": "Microsoft.Network/networkSecurityGroups", "properties": {"provisioningState": "Succeeded",
                "securityRules": [{"id": nsg_id + "/securityRules/allow", "name": "allow", "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                    "properties": {"provisioningState": "Succeeded", "priority": 100, "protocol": "Tcp", "sourcePortRange": "*", "destinationPortRange": "443",
                        "sourceAddressPrefix": "10.0.0.0/8", "destinationAddressPrefix": "*", "direction": "Inbound", "access": "Allow"}}]}}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["nsg"], transport=api)
    nsg = collection(snapshot, "nsg")["items"][0]
    assert collection(snapshot, "nsg")["status"] == "collected"
    assert nsg["properties"]["securityRules"][0]["properties"]["provisioningState"] == "Succeeded"
    assert nsg["_provenance"]["representation"] == "full"
    assert any(urlsplit(url).path == nsg_id for url, _, _ in api.calls)


def test_azure_subnet_and_peering_use_full_child_detail():
    vnet_id = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/net"
    subnet_id = vnet_id + "/subnets/app"
    peering_id = vnet_id + "/virtualNetworkPeerings/peer"
    def handler(url, body, audience):
        if body is not None:
            return {"data": []}
        path = urlsplit(url).path
        if "/providers/Microsoft.Network/virtualNetworks?" in url:
            return {"value": [{"type": "Microsoft.Network/virtualNetworks", "id": vnet_id, "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                "subnets": [{"type": "Microsoft.Network/virtualNetworks/subnets", "id": subnet_id, "properties": {}}],
                "virtualNetworkPeerings": [{"type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings", "id": peering_id, "properties": {}}]}}]}
        if path == vnet_id:
            return {"type": "Microsoft.Network/virtualNetworks", "id": vnet_id, "properties": {"provisioningState": "Succeeded",
                "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                "subnets": [{"type": "Microsoft.Network/virtualNetworks/subnets", "id": subnet_id}], "virtualNetworkPeerings": [{"type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings", "id": peering_id}]}}
        if path == subnet_id:
            return {"type": "Microsoft.Network/virtualNetworks/subnets", "id": subnet_id, "properties": {"provisioningState": "Succeeded",
                "addressPrefix": "10.0.1.0/24", "networkSecurityGroup": {"id": vnet_id.split("/providers/")[0] + "/providers/Microsoft.Network/networkSecurityGroups/nsg-a"},
                "routeTable": {"id": vnet_id.split("/providers/")[0] + "/providers/Microsoft.Network/routeTables/rt-a"}}}
        if path == peering_id:
            return {"type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings", "id": peering_id, "properties": {"provisioningState": "Succeeded",
                "peeringState": "Connected", "peeringSyncLevel": "FullyInSync"}}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["subnet", "vnet_peering"], transport=api)
    subnet = collection(snapshot, "subnet", vnet_id)["items"][0]
    peering = collection(snapshot, "vnet_peering", vnet_id)["items"][0]
    assert subnet["_provenance"]["representation"] == "full"
    assert peering["_provenance"]["representation"] == "full"
    assert subnet["properties"]["routeTable"]["id"] == vnet_id.split("/providers/")[0] + "/providers/Microsoft.Network/routeTables/rt-a"
    assert subnet["properties"]["networkSecurityGroup"]["id"] == vnet_id.split("/providers/")[0] + "/providers/Microsoft.Network/networkSecurityGroups/nsg-a"
    assert {subnet_id, peering_id} <= {urlsplit(url).path for url, _, _ in api.calls}


def test_azure_nat_gateway_is_native_network_inventory():
    nat_id = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/natGateways/nat-a"
    def handler(url, body, _audience):
        if body is not None:
            return {"data": [], "resultTruncated": "false"}
        if "/providers/Microsoft.Network/natGateways?" in url:
            return {"value": [{"id": nat_id, "properties": {"subnets": [{"id": "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"}]}}]}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["nat_gateway"], transport=FakeAzure(handler))
    row = collection(snapshot, "nat_gateway", "/subscriptions/sub-a")
    assert row["status"] == "collected"
    assert row["items"][0]["id"] == nat_id


def test_azure_effective_routes_are_bound_to_the_collected_nic(monkeypatch):
    from peaso.collectors import azure_effective_routes_native
    nic_id = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-a"
    class FakeQueries:
        def __init__(self, _reader, _transport, scope):
            assert scope == "/subscriptions/sub-a"
            self.proofs = []
        def pages(self, kind, parent):
            assert kind == "routes" and parent == nic_id
            self.proofs.append({"source_operation": "effectiveRouteTable", "resource_id": parent,
                "response_sha256": "a" * 64})
            yield [{"name": "local", "source": "Default", "state": "Active", "addressPrefix": ["10.0.0.0/16"], "nextHopType": "VnetLocal"}]
    monkeypatch.setattr(azure_effective_routes_native, "NetworkQueries", FakeQueries)
    def handler(url, body, _audience):
        if body is not None:
            return {"data": [], "resultTruncated": "false"}
        if "/providers/Microsoft.Network/networkInterfaces?" in url:
            return {"value": [{"id": nic_id, "properties": {"ipConfigurations": []}}]}
        if urlsplit(url).path == nic_id:
            return {"id": nic_id, "properties": {"provisioningState": "Succeeded", "ipConfigurations": []}}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["effective_route"], transport=FakeAzure(handler))
    row = collection(snapshot, "effective_route", "/subscriptions/sub-a")
    assert row["status"] == "collected"
    assert row["items"][0]["nic_id"] == nic_id
    assert row["items"][0]["route"]["nextHopType"] == "VnetLocal"
    assert row["items"][0]["_provenance"]["source_operation"] == "effectiveRouteTable"
    assert row["source_evidence"][0]["resource_id"] == nic_id


def test_azure_security_admin_absence_needs_complete_vnet_queries(monkeypatch):
    from peaso.collectors import azure_effective_routes_native
    vnet_id = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-a"
    class FakeQueries:
        def __init__(self, _reader, _transport, scope):
            assert scope == "/subscriptions/11111111-1111-1111-1111-111111111111"
            self.proofs = []
        def pages(self, kind, parent):
            assert kind == "admin" and parent == vnet_id
            self.proofs.append({"source_operation": "listNetworkManagerEffectiveSecurityAdminRules",
                "resource_id": parent, "response_sha256": "a" * 64})
            yield []
    monkeypatch.setattr(azure_effective_routes_native, "NetworkQueries", FakeQueries)
    def handler(url, body, _audience):
        if body is not None:
            return {"data": [], "resultTruncated": "false"}
        if "/providers/Microsoft.Network/virtualNetworks?" in url:
            return {"value": [{"id": vnet_id, "type": "Microsoft.Network/virtualNetworks", "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": []}}]}
        if urlsplit(url).path == vnet_id:
            return {"id": vnet_id, "type": "Microsoft.Network/virtualNetworks", "properties": {"provisioningState": "Succeeded",
                "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": []}}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["security_admin_rule"], transport=FakeAzure(handler))
    assert collection(snapshot, "security_admin_rule")["status"] == "empty"
    context = snapshot["metadata"]["network_context"]["azure"]["security_admin"]
    assert context["status"] == "collected" and context["complete"] is True and context["policies"] == []
    assert context["source_evidence"][0]["query_proofs"][0]["resource_id"] == vnet_id


def test_azure_failed_admin_query_cannot_prove_empty_policy_context(monkeypatch):
    from peaso.collectors import azure_effective_routes_native
    vnet_id = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-a"
    class FailedQueries:
        def __init__(self, *_args):
            self.proofs = []
        def pages(self, kind, parent):
            assert kind == "admin" and parent == vnet_id
            raise azure.AzureReadError("network_query_incomplete")
            yield []
    monkeypatch.setattr(azure_effective_routes_native, "NetworkQueries", FailedQueries)
    def handler(url, body, _audience):
        if body is not None:
            return {"data": [], "resultTruncated": "false"}
        if "/providers/Microsoft.Network/virtualNetworks?" in url:
            return {"value": [{"id": vnet_id, "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}, "subnets": []}}]}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["security_admin_rule"], transport=FakeAzure(handler))
    assert collection(snapshot, "security_admin_rule")["status"] not in {"collected", "empty"}
    context = snapshot["metadata"]["network_context"]["azure"]["security_admin"]
    assert context["status"] == "unknown" and context["complete"] is False


def test_azure_service_tags_preserve_subscription_prefix_proof():
    def handler(url, body, _audience):
        assert body is None
        assert url == ("https://management.azure.com/subscriptions/sub-a/providers/Microsoft.Network/locations/"
            "westcentralus/serviceTags?api-version=2025-09-01")
        return {"values": [{"name": "Storage.WestEurope", "properties": {"addressPrefixes": ["10.4.0.0/16"],
            "changeNumber": "7"}}]}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["service_tag"], transport=FakeAzure(handler))
    row = collection(snapshot, "service_tag", "/subscriptions/sub-a")
    assert row["status"] == "collected"
    assert row["items"][0]["properties"]["addressPrefixes"] == ["10.4.0.0/16"]
    assert row["items"][0]["_provenance"]["reference_location"] == "westcentralus"


def test_azure_graph_denial_falls_back_arm_and_graph_denial_explicit():
    def handler(url, body, audience):
        if body is not None or audience == azure.GRAPH:
            raise ReadError(403)
        account = {"id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account", "type": "Microsoft.Storage/storageAccounts", "name": "account", "properties": {"minimumTlsVersion": "TLS1_2"}}
        if urlparse(url).path.casefold() == account["id"].casefold():  # mandatory full-resource GET
            return account
        return {"value": [account]}
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["storage_account", "directory_user"], transport=FakeAzure(handler))
    assert collection(snapshot, "resource_graph")["status"] == "denied"
    assert collection(snapshot, "storage_account")["status"] == "collected"
    assert collection(snapshot, "directory_user")["status"] == "denied"
    assert snapshot["metadata"]["directory_coverage"]["status"] == "incomplete"
    assert "fake-token" not in json.dumps(snapshot)


def test_azure_discover_all_subscriptions_and_tenant_access():
    def handler(url, body, audience):
        if "/subscriptions?" in url:
            return {"value": [{"id": "/subscriptions/sub-a", "subscriptionId": "sub-a"}, {"id": "/subscriptions/sub-b", "subscriptionId": "sub-b"}]}
        return {"value": [{"id": "/tenants/tenant-a", "tenantId": "tenant-a"}]}
    snapshot = azure.collect({"scopes": ["*"]}, ["subscription", "tenant"], transport=FakeAzure(handler))
    assert snapshot["scopes"] == ["/subscriptions/sub-a", "/subscriptions/sub-b"]
    assert collection(snapshot, "subscription")["status"] == "collected"
    assert snapshot["metadata"]["tenant_id"] == "tenant-a"


def test_azure_preserves_permission_exclusions_conditions_deny_and_management_parent():
    mg = "/providers/Microsoft.Management/managementGroups/group-a"
    permission = {"actions": ["*"], "notActions": ["Microsoft.Authorization/*/write"], "dataActions": [], "notDataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]}
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path.endswith("managementGroups"):
            return {"value": [{"id": mg}]}
        if path == mg:
            return {"id": mg, "properties": {"details": {"parent": {"id": "/providers/Microsoft.Management/managementGroups/root"}}, "children": []}}
        if path.startswith("/providers/Microsoft.Authorization/"):
            return {"value": []}  # No synthetic tenant-root CustomRole or assignment.
        role="33333333-3333-3333-3333-333333333333"
        assignment="44444444-4444-4444-4444-444444444444"
        principal="55555555-5555-5555-5555-555555555555"
        parent=path.split("/providers/Microsoft.Authorization/")[0] or "/"
        if path.endswith("roleDefinitions"):
            return {"value": [{"id": path + "/" + role, "name": role, "type": "Microsoft.Authorization/roleDefinitions",
                "properties": {"roleName": "Review role", "roleType": "CustomRole", "assignableScopes": [parent], "permissions": [permission]}}]}
        if path.endswith("roleAssignments"):
            return {"value": [{"id": path + "/" + assignment, "name": assignment, "type": "Microsoft.Authorization/roleAssignments",
                "properties": {"scope": parent, "principalId": principal, "roleDefinitionId": parent.rstrip("/") + "/providers/Microsoft.Authorization/roleDefinitions/" + role,
                    "condition": "@Resource[tag] StringEquals 'production'", "conditionVersion": "2.0"}}]}
        return {"value": [{"id": path + "/66666666-6666-6666-6666-666666666666", "name": "66666666-6666-6666-6666-666666666666", "type": "Microsoft.Authorization/denyAssignments",
            "properties": {"scope": parent, "permissions": [permission], "doNotApplyToChildScopes": True}}]}
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["role_assignment", "role_definition", "deny_assignment"], transport=FakeAzure(handler))
    assert collection(snapshot, "role_definition", mg)["items"][0]["properties"]["permissions"] == [permission]
    assert collection(snapshot, "role_assignment", mg)["items"][0]["properties"]["conditionVersion"] == "2.0"
    assert collection(snapshot, "deny_assignment", mg)["items"][0]["properties"]["doNotApplyToChildScopes"]
    assert collection(snapshot, "management_group")["items"][0]["properties"]["details"]["parent"]


def test_azure_secret_metadata_and_vm_sensitive_fields_never_retained():
    vault = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault"
    def handler(url, body, audience):
        if body:
            return {"data": [{"id": vault, "type": "microsoft.keyvault/vaults"}]}
        if "/secrets?" in url:
            return {"value": [{"id": vault + "/secrets/name", "properties": {"value": "do-not-store", "attributes": {"enabled": True}}}]}
        native={"id": vault, "name": "vault", "type": "Microsoft.KeyVault/vaults", "properties": {"enableRbacAuthorization": True, "adminPassword": "do-not-store"}}
        if urlsplit(url).path==vault:return native
        return {"value": [native]}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["secret_metadata"], transport=api)
    secret = collection(snapshot, "secret_metadata")["items"][0]
    assert secret["properties"]["attributes"]["enabled"]
    assert "do-not-store" not in json.dumps(snapshot)
    assert all("/secrets/" not in url for url, _, _ in api.calls)


@pytest.mark.parametrize("next_link", ["https://attacker.example/list", "https://management.azure.com/subscriptions/unselected/list", "https://user@management.azure.com/list"])
def test_azure_untrusted_continuation_not_followed(next_link):
    api = FakeAzure(lambda *_: {"value": [{"id": "/subscriptions/sub-a", "subscriptionId": "sub-a"}], "nextLink": next_link})
    snapshot = azure.collect({"scopes": ["*"]}, ["subscription"], transport=api)
    assert collection(snapshot, "subscription")["status"] == "partial"
    assert len(api.calls) == 1


def test_azure_graph_cross_scope_rejected():
    api = FakeAzure(lambda url, body, audience: {"data": [{"id": "/subscriptions/other/providers/Microsoft.Network/virtualNetworks/v", "type": "microsoft.network/virtualnetworks"}]} if body else {"value": []})
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["vnet"], transport=api)
    assert collection(snapshot, "resource_graph")["status"] == "malformed"
    assert not collection(snapshot, "resource_graph")["items"]


def test_azure_activity_window_is_not_claimed_complete():
    api = FakeAzure(lambda *_: {"value": [{"eventDataId": "event-1", "operationName": {"value": "Microsoft.Storage/storageAccounts/read"}}]})
    snapshot = azure.collect({"scopes": ["sub-a"], "options": {"activity_days": 7}}, ["activity_log"], transport=api)
    assert not snapshot["metadata"]["activity_window"]["complete"]
    assert collection(snapshot, "activity_log")["items"][0]["operationName"]["value"].endswith("/read")
    assert "eventTimestamp" in api.calls[0][0]


def test_k8s_namespace_paginated_cluster_inventory_once_and_crossscope_ids():
    def handler(path, params):
        if "clusterroles" in path:
            return kube_list([{"metadata": {"name": "read", "uid": "cluster-uid"}, "rules": [{"resources": ["pods"], "verbs": ["get", "list"]}]}])
        namespace = path.split("/namespaces/")[1].split("/")[0]
        return kube_list([kube_item("second" if params.get("continue") else "first", namespace)], "" if params.get("continue") else "next")
    api = FakeKube(handler)
    snapshot = k8s.collect({"scopes": ["team-a", "team-b"]}, ["pod", "clusterrole"], api=api)
    assert len(api.calls) == 5
    assert len([c for c in snapshot["collections"] if c["type"] == "clusterrole"]) == 1
    assert all(c["status"] == "collected" for c in snapshot["collections"])
    assert len(set(r["id"] for r in resources(snapshot))) == 5
    assert not api.closed
    other = FakeKube(handler)
    other.server = "https://cluster-b.example"
    second = k8s.collect({"scopes": ["team-a"]}, ["pod"], api=other)
    assert collection(snapshot, "pod")["items"][0]["id"] != collection(second, "pod")["items"][0]["id"]
    assert snapshot["metadata"]["namespace_semantics"].endswith("not a subnet")


def test_k8s_denied_reads_do_not_hide_available_rbac_and_no_secret_paths():
    def handler(path, params):
        if path.endswith("pods"):
            raise ReadError(403)
        role=kube_item("read", "team-a", rules=[{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}])
        role.update(apiVersion="rbac.authorization.k8s.io/v1", kind="Role")
        role["metadata"].update(uid="33333333-3333-3333-3333-333333333333", resourceVersion="12")
        return kube_list([role])
    api = FakeKube(handler)
    snapshot = k8s.collect({"scopes": ["team-a"]}, ["role", "pod"], api=api)
    assert collection(snapshot, "pod")["status"] == "denied"
    assert collection(snapshot, "role")["status"] == "collected"
    assert "fake-token" not in json.dumps(snapshot)
    assert all(not any(segment in path for segment in ("/secrets", "/log", "/exec", "/token")) for path, _ in api.calls)


def test_k8s_wrong_namespace_malformed_not_a_subnet():
    snapshot = k8s.collect({"scopes": ["team-a"]}, ["pod"], api=FakeKube(lambda *_: kube_list([kube_item(namespace="team-b")])))
    assert collection(snapshot, "pod")["status"] == "malformed"
    assert not collection(snapshot, "pod")["items"]


@pytest.mark.parametrize("failure", ["repeat", "version", "shape", "expired"])
def test_k8s_pagination_failure_retains_partial_evidence(failure):
    def handler(path, params):
        if params.get("continue"):
            if failure == "expired":
                raise ReadError(410)
            if failure == "shape":
                return {"items": "malformed"}
            return kube_list([], "same", "new" if failure == "version" else "12")
        return kube_list([kube_item()], "same")
    snapshot = k8s.collect({"scopes": ["team-a"]}, ["pod"], api=FakeKube(handler))
    assert collection(snapshot, "pod")["status"] == "partial"
    assert len(collection(snapshot, "pod")["items"]) == 1


def test_k8s_workload_literals_redacted_but_identity_and_networkpolicy_kept():
    item = kube_item(spec={"containers": [{"name": "app", "image": "app:v1", "command": ["secret"], "args": ["secret"], "env": [{"name": "PASSWORD", "value": "secret"}, {"name": "REFERENCED", "valueFrom": {"secretKeyRef": {"name": "credential", "key": "password"}}}]}]})
    item["metadata"]["annotations"] = {"kubectl.kubernetes.io/last-applied-configuration": "secret", "eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/app"}
    snapshot = k8s.collect({"scopes": ["team-a"]}, ["pod"], api=FakeKube(lambda *_: kube_list([item])))
    data = collection(snapshot, "pod")["items"][0]
    assert "\"secret\"" not in json.dumps(data)
    container = data["spec"]["containers"][0]
    assert container["env"][0]["value_redacted"]
    assert container["env"][1]["valueFrom"]["secretKeyRef"]["name"] == "credential"
    assert data["metadata"]["annotations"]["eks.amazonaws.com/role-arn"]
    assert snapshot["metadata"]["network_policy_enforcement"]["status"] == "unknown"


def test_k8s_interfaces_observed_addresses_only():
    def handler(path, params):
        if path.endswith("nodes"):
            return kube_list([{"metadata": {"name": "node", "uid": "node-id"}, "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}}])
        return kube_list([kube_item(status={"podIPs": [{"ip": "10.1.0.2"}]}, spec={"nodeName": "node"})])
    snapshot = k8s.collect({"scopes": ["team-a"]}, ["network_interface"], api=FakeKube(handler))
    assert collection(snapshot, "network_interface")["status"] == "collected"
    assert all(not i["provenance"]["authoritative_interface_inventory"] for i in collection(snapshot, "network_interface")["items"])


def test_concurrency_retry_and_global_call_budget(monkeypatch):
    reader = azure._Reader({"concurrency": 2, "max_calls": 5, "retries": 1})
    lock = threading.Lock()
    # The first two calls meet at a barrier, so both are provably in flight at the same time
    # (a timeout breaks the barrier and fails the test instead of hanging). While they are
    # held, any worker beyond the limit would start a third call and raise the peak above 2.
    both_in_flight = threading.Barrier(2, timeout=10)
    active = peak = calls = 0
    def operation():
        nonlocal active, peak, calls
        with lock:
            calls += 1
            active += 1
            peak = max(peak, active)
            number = calls
        if number <= 2:
            both_in_flight.wait()
            time.sleep(0.05)
        with lock:
            active -= 1
        if number == 1:
            raise ReadError(429)
        return {"id": "resource-" + str(number)}
    def fetch():
        yield [reader.call(operation)]
    reader.run([("kind-" + str(i), "scope", "test", fetch) for i in range(8)])
    assert not both_in_flight.broken
    assert peak <= reader.workers == 2
    assert peak == 2
    assert calls == reader.budget.calls == 5
    assert any(c["status"] == "partial" for c in reader.collections)


@pytest.mark.parametrize("provider", ["azure", "k8s"])
def test_page_and_resource_caps_are_partial(provider):
    if provider == "azure":
        snapshot = azure.collect({"scopes": ["*"], "options": {"max_pages": 1}}, ["subscription"], transport=FakeAzure(lambda url, *_: {"value": [{"id": "/subscriptions/sub-a", "subscriptionId": "sub-a"}], "nextLink": url + "&page=2"}))
        assert collection(snapshot, "subscription")["status"] == "partial"
    else:
        snapshot = k8s.collect({"scopes": ["team-a"], "options": {"max_resources": 1}}, ["pod"], api=FakeKube(lambda *_: kube_list([kube_item("a"), kube_item("b")])))
        assert collection(snapshot, "pod")["status"] == "partial"
        assert len(collection(snapshot, "pod")["items"]) == 1


def test_auth_failure_produces_denied_coverage_not_exception_or_secret(monkeypatch):
    def fail(*_):
        raise ReadError(401)
    monkeypatch.setattr(k8s, "_new_api", fail)
    snapshot = k8s.collect({"scopes": ["team-a"], "auth": {"token": "fake-token"}}, ["pod", "role"])
    assert {c["status"] for c in snapshot["collections"]} == {"denied"}
    monkeypatch.setattr(azure, "AzureTransport", fail)
    monkeypatch.setattr(azure, "AzureTransportExposure", fail)
    snapshot = azure.collect({"scopes": ["sub-a"], "auth": {"client_secret": "fake-token"}}, ["vnet"])
    assert collection(snapshot, "vnet")["status"] == "denied"
    assert "fake-token" not in json.dumps(snapshot)


@pytest.mark.parametrize("method", ["client-secret", "client-cert", "az-cli", "default", "managed-identity", "workload-identity", "device-code"])
def test_azure_explicit_credential_modes(monkeypatch, method):
    from azure import identity
    calls = []
    names = {"client-secret": "ClientSecretCredential", "client-cert": "CertificateCredential", "az-cli": "AzureCliCredential", "default": "DefaultAzureCredential", "managed-identity": "ManagedIdentityCredential", "workload-identity": "WorkloadIdentityCredential", "device-code": "DeviceCodeCredential"}
    monkeypatch.setattr(identity, names[method], lambda *args, **kwargs: calls.append((args, kwargs)) or object())
    auth = {"method": method, "tenant_id": "tenant-a", "client_id": "client-a"}
    if method == "client-secret":
        auth["client_secret"] = "fake-token"
    if method == "client-cert":
        auth["certificate_path"] = "/fake/cert.pem"
    if method == "workload-identity":
        auth["token_file"] = "/fake/token"
    azure.credential_for(auth)
    assert len(calls) == 1
    assert "*" not in str(calls)


def jwt(claims):
    return "header." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".signature"


def test_azure_direct_tokens_tenant_and_audience_separation():
    arm = jwt({"tid": "tenant-a", "aud": azure.ARM})
    graph = jwt({"tid": "tenant-a", "aud": azure.GRAPH})
    transport = azure.AzureTransport({"tenant_id": "tenant-a", "arm_token": arm, "graph_token": graph})
    assert transport.token(azure.ARM) == arm
    assert transport.token(azure.GRAPH) == graph
    with pytest.raises(azure.AzureReadError, match="tenant_mismatch"):
        azure.AzureTransport({"tenant_id": "tenant-b", "arm_token": arm}).token(azure.ARM)
    with pytest.raises(azure.AzureReadError, match="token_audience_mismatch"):
        azure.AzureTransport({"arm_token": graph}).token(azure.ARM)
    with pytest.raises(azure.AzureReadError, match="untrusted_continuation"):
        transport.request("https://attacker.example/path")


def test_azure_sdk_tokens_use_fixed_scopes_refresh_and_pin_tenant():
    calls = []
    class Credential:
        def get_token(self, scope):
            calls.append(scope)
            return SimpleNamespace(token=jwt({"tid": "tenant-a", "aud": scope.removesuffix("/.default")}), expires_on=time.time() + 600)
    transport = azure.AzureTransport({}, credential=Credential())
    transport.token(azure.ARM)
    transport.token(azure.ARM)
    transport.token(azure.GRAPH)
    assert calls == [azure.ARM + "/.default", azure.GRAPH + "/.default"]
    assert transport.tenant == "tenant-a"


def _offline_k8s_client(configuration):
    """SDK-shaped inert client for auth selection tests; no request may leave this spy."""
    def unexpected_request(*args, **kwargs):
        pytest.fail("authentication test must not perform Kubernetes I/O")
    return SimpleNamespace(configuration=configuration,
                           rest_client=SimpleNamespace(pool_manager=SimpleNamespace(request=unexpected_request)),
                           close=lambda: None)


def test_k8s_direct_tls_token_file_and_certificate(monkeypatch, tmp_path):
    from kubernetes import client
    captured = []
    monkeypatch.setattr(client, "ApiClient", lambda cfg: captured.append(cfg) or _offline_k8s_client(cfg))
    token_file = tmp_path / "token"
    token_file.write_text("fake-token\n")
    k8s._new_api({"server": "https://cluster.example", "token_file": str(token_file), "ca_cert": "/fake/ca.pem"})
    cfg = captured[-1]
    assert cfg.verify_ssl and cfg.ssl_ca_cert == "/fake/ca.pem"
    assert cfg.api_key["authorization"] == "fake-token"
    k8s._new_api({"server": "https://cluster.example", "client_cert": "/fake/cert.pem", "client_key": "/fake/key.pem"})
    assert captured[-1].cert_file == "/fake/cert.pem"
    with pytest.raises(ValueError):
        k8s._new_api({"server": "http://cluster.example", "token": "fake-token"})


def test_k8s_data_only_context_and_incluster_reuse(monkeypatch, tmp_path):
    from kubernetes import client, config
    calls = []
    path = tmp_path / 'config'
    path.write_text(json.dumps(inline_config()))
    monkeypatch.setattr(config, "new_client_from_config", lambda **kwargs: pytest.fail('SDK credential helpers are prohibited'))
    monkeypatch.setattr(client, "ApiClient", lambda cfg: calls.append(cfg) or _offline_k8s_client(cfg))
    k8s._new_api({"kubeconfig": str(path), "context": "selected"})
    assert calls[0].host == 'https://cluster.example' and calls[0].api_key['authorization'] == 'fake-token'
    monkeypatch.setattr(config, "load_incluster_config", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(client, "ApiClient", lambda cfg: _offline_k8s_client(cfg))
    k8s._new_api({"in_cluster": True})
    assert "client_configuration" in calls[-1]


@pytest.mark.parametrize("provider,scopes", [("azure", ["sub-a/../../other"]), ("k8s", ["team-a/other"]), ("k8s", ["-invalid"])])
def test_invalid_scope_rejected_before_api(provider, scopes):
    module = azure if provider == "azure" else k8s
    with pytest.raises(ValueError):
        module.collect({"scopes": scopes}, [])


def inline_config():
    return {"apiVersion": "v1", "kind": "Config", "current-context": "selected",
            "clusters": [{"name": "cluster", "cluster": {"server": "https://cluster.example"}}],
            "users": [{"name": "reader", "user": {"token": "fake-token"}}],
            "contexts": [{"name": "selected", "context": {"cluster": "cluster", "user": "reader"}}]}


@pytest.mark.parametrize("field,value,section", [("exec", {"command": "sh"}, "user"), ("auth-provider", {"name": "gcp"}, "user"), ("tokenFile", "/etc/secret", "user"), ("client-key", "/etc/secret", "user"), ("certificate-authority", "/etc/secret", "cluster"), ("proxy-url", "http://169.254.169.254", "cluster"), ("insecure-skip-tls-verify", True, "cluster")])
def test_inline_kubeconfig_rejects_helpers_paths_and_insecure_tls(field, value, section):
    data = inline_config()
    data["users" if section == "user" else "clusters"][0][section][field] = value
    with pytest.raises(ValueError):
        k8s.validate_inline_kubeconfig(data)


def test_inline_kubeconfig_selected_auth_and_private_material_cleanup(monkeypatch):
    from kubernetes import client
    captured = []
    monkeypatch.setattr(client, "ApiClient", lambda cfg: captured.append(cfg) or _offline_k8s_client(cfg))
    config = inline_config()
    pem = "-----BEGIN CERTIFICATE-----\nfake-test-data\n-----END CERTIFICATE-----"
    config["clusters"][0]["cluster"]["certificate-authority-data"] = base64.b64encode(pem.encode()).decode()
    api = k8s._new_api({"kubeconfig_data": config})
    path = captured[-1].ssl_ca_cert
    import os
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert captured[-1].api_key["authorization"] == "fake-token"
    api.close()
    assert not os.path.exists(path)


@pytest.mark.parametrize("address", ["169.254.169.254", "127.0.0.1", "10.0.0.1", "::1", "fc00::1"])
def test_hosted_k8s_private_dns_destinations_rejected(monkeypatch, address):
    monkeypatch.setattr(k8s.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", (address, 443))])
    with pytest.raises(ValueError):
        k8s._public_server("https://cluster.example")


def test_hosted_public_server_pinned_and_tls_name_preserved(monkeypatch):
    monkeypatch.setattr(k8s.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("8.8.8.8", 443))])
    from kubernetes import client
    captured = []
    monkeypatch.setattr(client, "ApiClient", lambda cfg: captured.append(cfg) or _offline_k8s_client(cfg))
    api = k8s._new_api({"server": "https://cluster.example:6443", "token": "fake-token", "_hosted": True})
    cfg = captured[-1]
    assert cfg.host == "https://8.8.8.8:6443"
    assert cfg.tls_server_name == cfg.assert_hostname == "cluster.example"
    assert api.server == "https://cluster.example:6443"


def test_hosted_cannot_fallback_to_worker_identity(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("ambient auth loader must not run")
    monkeypatch.setattr(k8s, "_new_api", unexpected)
    snapshot = k8s.collect({"options": {"hosted": True}}, ["pod"])
    assert collection(snapshot, "pod")["status"] == "malformed"
    monkeypatch.setattr(azure, "AzureTransport", unexpected)
    monkeypatch.setattr(azure, "AzureTransportExposure", unexpected)
    snapshot = azure.collect({"scopes": ["sub-a"], "options": {"hosted": True}}, ["vnet"])
    assert collection(snapshot, "vnet")["status"] == "malformed"


def test_azure_explicit_cli_does_not_select_stale_secret(monkeypatch):
    from azure import identity
    calls = []
    monkeypatch.setattr(identity, "AzureCliCredential", lambda **kwargs: calls.append(kwargs) or object())
    monkeypatch.setattr(identity, "ClientSecretCredential", lambda *args, **kwargs: pytest.fail("wrong credential source"))
    azure.credential_for({"method": "az-cli", "tenant_id": "tenant-a", "client_secret": "stale-token"})
    assert calls[0]["tenant_id"] == "tenant-a"


def test_azure_inline_certificate_not_arbitrary_file(monkeypatch):
    from azure import identity
    calls = []
    monkeypatch.setattr(identity, "CertificateCredential", lambda *args, **kwargs: calls.append(kwargs) or object())
    azure.credential_for({"method": "client-cert", "tenant_id": "tenant-a", "client_id": "client-a", "certificate_data": "PEM-material"})
    assert calls == [{"certificate_data": b"PEM-material", "password": None}]


def test_resource_exact_cap_can_be_complete_and_empty_distinct():
    snapshot = k8s.collect({"scopes": ["team-a"], "options": {"max_resources": 1}}, ["pod"], api=FakeKube(lambda *_: kube_list([kube_item()])))
    assert collection(snapshot, "pod")["status"] == "collected"
    snapshot = k8s.collect({"scopes": ["team-a"]}, ["pod"], api=FakeKube(lambda *_: kube_list()))
    assert collection(snapshot, "pod")["status"] == "empty"


@pytest.mark.parametrize("kind,plural", [("role_assignment", "roleAssignments"), ("deny_assignment", "denyAssignments")])
def test_azure_root_assignment_uses_at_scope_filter(kind, plural):
    api = FakeAzure(lambda *_: {"value": []})
    azure.collect({"scopes": ["sub-a"]}, [kind], transport=api)
    root = [url for url, _, _ in api.calls if urlsplit(url).path == "/providers/Microsoft.Authorization/" + plural]
    assert len(root) == 1 and "%24filter=atScope%28%29" in root[0]


def test_azure_inline_workload_assertion_uses_selected_identity(monkeypatch):
    from azure import identity
    calls = []
    monkeypatch.setattr(identity, "ClientAssertionCredential", lambda tenant, client, callback: calls.append((tenant, client, callback())) or object())
    azure.credential_for({"method": "workload-identity", "tenant_id": "tenant-a", "client_id": "client-a", "federated_token": "fake-assertion"})
    assert calls == [("tenant-a", "client-a", "fake-assertion")]


def test_k8s_selected_direct_mode_never_falls_back_to_kubeconfig(monkeypatch):
    from kubernetes import config
    monkeypatch.setattr(config, "new_client_from_config", lambda **kwargs: pytest.fail("ambient identity selected"))
    with pytest.raises(ValueError, match="requires server"):
        k8s._new_api({"method": "token", "token": "fake-token"})


def test_k8s_selected_context_ignores_stale_direct_server(monkeypatch, tmp_path):
    from kubernetes import client, config
    calls = []
    path = tmp_path / 'config'
    path.write_text(json.dumps(inline_config()))
    monkeypatch.setattr(config, "new_client_from_config", lambda **kwargs: pytest.fail('SDK credential helpers are prohibited'))
    monkeypatch.setattr(client, "ApiClient", lambda cfg: calls.append(cfg) or _offline_k8s_client(cfg))
    k8s._new_api({"method": "kubeconfig", "kubeconfig": str(path), "context": "selected", "server": "https://stale.example", "token": "stale-token"})
    assert calls[0].host == 'https://cluster.example' and calls[0].api_key['authorization'] == 'fake-token'


def test_k8s_certificate_mode_ignores_stale_bearer(monkeypatch):
    from kubernetes import client
    configurations = []
    monkeypatch.setattr(client, "ApiClient", lambda cfg: configurations.append(cfg) or _offline_k8s_client(cfg))
    k8s._new_api({"method": "certificate", "server": "https://cluster.example", "client_cert": "/fake/cert", "client_key": "/fake/key", "token": "stale-token"})
    assert not configurations[-1].api_key


def test_k8s_sdk_transport_cannot_redirect_retry_or_write():
    calls = []
    pool = SimpleNamespace(request=lambda *args, **kwargs: calls.append((args, kwargs)) or object())
    bounded = k8s._BoundedPool(pool)
    bounded.request("GET", "https://cluster.example/api/v1/pods", redirect=True, retries=10)
    assert calls[0][1] == {"redirect": False, "retries": False}
    with pytest.raises(ValueError):
        bounded.request("POST", "https://cluster.example/api/v1/pods")
    assert len(calls) == 1


def test_azure_fallback_list_cross_subscription_rejected():
    def handler(url, body, audience):
        if body:
            raise ReadError(403)
        return {"value": [{"id": "/subscriptions/other/providers/Microsoft.Network/virtualNetworks/v"}]}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["vnet"], transport=FakeAzure(handler))
    assert collection(snapshot, "vnet")["status"] == "malformed"
    assert not collection(snapshot, "vnet")["items"]


def test_azure_resource_graph_lag_cannot_hide_new_arm_resource():
    rid = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/new/providers/Microsoft.Network/virtualNetworks/new"
    def handler(url, body, audience):
        if body:
            return {"data": [], "resultTruncated": "false"}
        if urlsplit(url).path == rid:
            return {"id": rid, "type": "Microsoft.Network/virtualNetworks", "properties": {"provisioningState": "Succeeded",
                "subnets": [], "virtualNetworkPeerings": []}}
        return {"value": [{"id": rid, "type": "Microsoft.Network/virtualNetworks", "properties": {"subnets": [], "virtualNetworkPeerings": []}}]}
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["vnet"], transport=FakeAzure(handler))
    assert collection(snapshot, "resource_graph")["status"] == "empty"
    assert collection(snapshot, "vnet")["status"] == "collected"
    assert collection(snapshot, "vnet")["items"][0]["id"] == rid


def test_azure_thin_arm_list_get_denial_retains_unavailable_detail():
    rid = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v"
    def handler(url, body, audience):
        if body:
            return {"data": []}
        if urlsplit(url).path == rid:
            raise ReadError(403)
        return {"value": [{"id": rid, "type": "Microsoft.Network/virtualNetworks"}]}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["vnet"], transport=FakeAzure(handler))
    result = collection(snapshot, "vnet")
    assert result["status"] == "partial"
    assert result["items"][0]["detail"]["collection_status"] == "denied"
    assert "properties" not in result["items"][0]


def test_azure_app_config_whitelists_settings_and_never_exports_credentials():
    rid = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    def handler(url, body, audience):
        if body:
            return {"data": []}
        if "/config/web?" in url:
            return {"id": rid + "/config/web", "name": "web", "type": "Microsoft.Web/sites/config", "properties": {"minTlsVersion": "1.3", "ftpsState": "FtpsOnly", "appSettings": [{"name": "PASSWORD", "value": "sensitive"}], "machineKey": {"validationKey": "sensitive"}}}
        native={"id": rid, "name": "app", "type": "Microsoft.Web/sites", "properties": {"httpsOnly": True}}
        if urlsplit(url).path==rid:return native
        return {"value": [native]}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["app_service_config"], transport=api)
    config = collection(snapshot, "app_service_config")["items"][0]
    assert config["properties"] == {"minTlsVersion": "1.3", "ftpsState": "FtpsOnly"}
    assert config["parent_id"] == rid
    assert "sensitive" not in json.dumps(snapshot)
    assert all("publishingcredentials" not in url.lower() and "appsettings" not in url.lower() for url, _, _ in api.calls)


def test_azure_storage_services_use_metadata_get_default_no_list_keys():
    rid = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account"
    def handler(url, body, audience):
        if body:
            return {"data": []}
        if "/default?" in url:
            service = urlsplit(url).path.split("/")[-2]
            return {"id": rid + "/" + service + "/default", "type": "Microsoft.Storage/storageAccounts/" + service, "properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}}}
        return {"value": [{"id": rid, "properties": {"minimumTlsVersion": "TLS1_2"}}]}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["storage_service"], transport=api)
    services = [c for c in snapshot["collections"] if c["type"] == "storage_service"]
    assert len(services) == 4 and all(c["status"] == "collected" for c in services)
    assert all("listkeys" not in url.lower() for url, _, _ in api.calls)


def test_azure_sql_tde_reads_user_database_metadata_and_preserves_native_parent_id():
    server = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Sql/servers/server"
    user = server + "/databases/application"
    def handler(url, body, audience):
        if body:
            return {"data": []}
        if "/transparentDataEncryption/current?" in url:
            return {"id": user, "name": "current", "type": "Microsoft.Sql/servers/databases/transparentDataEncryption", "properties": {"state": "Enabled"}}
        if "/databases?" in url:
            return {"value": [{"id": user, "name": "application", "type": "Microsoft.Sql/servers/databases", "properties": {}}, {"id": server + "/databases/master", "name": "master", "type": "Microsoft.Sql/servers/databases", "properties": {}}]}
        native={"id": server, "name": "server", "type": "Microsoft.Sql/servers", "properties": {"publicNetworkAccess": "Disabled"}}
        if urlsplit(url).path==server:return native
        return {"value": [native]}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["11111111-1111-1111-1111-111111111111"]}, ["sql_tde"], transport=api)
    record = collection(snapshot, "sql_tde")["items"][0]
    assert record["id"] == record["parent_id"] == user
    assert record["properties"]["state"] == "Enabled"
    assert all("/master/transparentDataEncryption" not in url for url, _, _ in api.calls)


@pytest.mark.parametrize("kind,plural", [("resourcequota", "resourcequotas"), ("limitrange", "limitranges")])
def test_k8s_quota_and_limitrange_keep_namespace_scopes_and_native_specs(kind, plural):
    api = FakeKube(lambda *_: kube_list([kube_item("limits", "team-a", spec={"hard": {"pods": "10"}, "limits": []})]))
    snapshot = k8s.collect({"scopes": ["team-a"]}, [kind], api=api)
    assert api.calls[0][0] == "/api/v1/namespaces/team-a/" + plural
    assert collection(snapshot, kind)["items"][0]["spec"]["hard"]["pods"] == "10"


def test_hosted_dns_change_is_revalidated_and_private_second_address_never_connected(monkeypatch):
    from kubernetes import client
    addresses = iter(["8.8.8.8", "169.254.169.254"])
    monkeypatch.setattr(k8s.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", (next(addresses), 443))])
    monkeypatch.setattr(client, "ApiClient", lambda *args, **kwargs: pytest.fail("private second address must not connect"))
    assert k8s._public_server("https://cluster.example")[0] == "https://8.8.8.8"
    with pytest.raises(ValueError, match="public addresses"):
        k8s._new_api({"server": "https://cluster.example", "token": "fake-token", "_hosted": True})


def test_inline_alias_requires_safe_inline_credentials(monkeypatch):
    from kubernetes import client
    captured = []
    monkeypatch.setattr(client, "ApiClient", lambda cfg: captured.append(cfg) or _offline_k8s_client(cfg))
    k8s._new_api({"method": "inline", "kubeconfig_data": inline_config()})
    assert captured[-1].host == "https://cluster.example"
    with pytest.raises(ValueError, match="requires kubeconfig_data"):
        k8s._new_api({"method": "inline"})


@pytest.mark.parametrize("module,scopes,kinds,transport", [(azure, ["sub-a"], ["subscription"], {"transport": FakeAzure(lambda *_: {"value": []})}), (k8s, ["team-a"], ["pod"], {"api": FakeKube(lambda *_: kube_list())})])
def test_explicit_trusted_scopes_are_preserved_without_inferring_selected_scope(module, scopes, kinds, transport):
    snapshot = module.collect({"scopes": scopes, "options": {"trusted_scope_ids": ["tenant-explicit", "tenant-explicit"]}}, kinds, **transport)
    assert snapshot["metadata"]["trusted_scope_ids"] == ["tenant-explicit"]
    assert scopes[0] not in snapshot["metadata"]["trusted_scope_ids"]


def test_selected_namespace_inventory_gets_only_selected_namespaces_in_their_scopes():
    def handler(path, params):
        assert path != "/api/v1/namespaces"
        namespace = path.rsplit("/", 1)[-1]
        return {"metadata": {"name": namespace, "uid": "namespace-" + namespace, "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}}
    api = FakeKube(handler)
    snapshot = k8s.collect({"scopes": ["team-a", "team-b"]}, ["namespace"], api=api)
    assert {c["scope"] for c in snapshot["collections"]} == {"team-a", "team-b"}
    for c in snapshot["collections"]:
        assert c["status"] == "collected"
        assert c["items"][0]["metadata"]["name"] == c["scope"]
    assert len(api.calls) == 2


def test_hosted_stale_credential_fields_cannot_authorize_ambient_method(monkeypatch):
    monkeypatch.setattr(azure, "AzureTransport", lambda *_: pytest.fail("Azure worker identity source must not run"))
    monkeypatch.setattr(azure, "AzureTransportExposure", lambda *_: pytest.fail("Azure worker identity source must not run"))
    snapshot = azure.collect({"scopes": ["sub-a"], "options": {"hosted": True}, "auth": {"method": "managed-identity", "client_secret": "stale-secret"}}, ["vnet"])
    assert collection(snapshot, "vnet")["status"] == "malformed"
    monkeypatch.setattr(k8s, "_new_api", lambda *_: pytest.fail("Kubeconfig worker identity source must not run"))
    snapshot = k8s.collect({"scopes": ["team-a"], "options": {"hosted": True}, "auth": {"method": "kubeconfig", "server": "https://stale.example", "token": "stale-token"}}, ["pod"])
    assert collection(snapshot, "pod")["status"] == "malformed"
