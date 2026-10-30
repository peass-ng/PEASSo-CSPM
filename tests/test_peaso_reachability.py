"""Configuration truth tests: no provider SDK, sockets, subprocesses, or probes."""
import copy
import json
import socket
import subprocess
import time
from pathlib import Path

import pytest

from peaso.analysis import REACHABILITY_TYPES, evaluate_reachability, evaluate_reachability_batch, evaluate_reachability_matrix, evaluate_reachability_grid, network_snapshot
from peaso.analysis.common import gcp_interface_resource_id
from peaso.analysis.network import build_network
from peaso.collectors import supported_types
from peaso.engine import plan_collection
from peaso.snapshot import make_snapshot, resources


def test_network_collection_plan_covers_native_reachability_dependencies():
    snapshot_only = {
        "aws": set(),
        "azure": set(),
        "gcp": {"hierarchical_firewall_policy", "network_firewall_policy"},
        "k8s": {"cni_configuration"},
    }
    for provider, dependencies in REACHABILITY_TYPES.items():
        native = set(supported_types(provider))
        planned = set(plan_collection({"connector": {"provider": provider}, "categories": ["network"]}))
        assert dependencies - native == snapshot_only[provider]
        assert dependencies & native <= planned


def sealed(provider, facts, metadata=None):
    collections = [{"type": kind, "scope": scope, "service": kind, "status": "collected" if items else "empty", "items": items}
        for (kind, scope), items in facts.items()]
    # Fixtures deliberately modify variants before resealing. Production native
    # facts remain frozen; deepcopy provides an independent mutable test draft.
    return copy.deepcopy(make_snapshot(provider, sorted({scope for _, scope in facts}), collections, metadata=metadata or {},
        created_at="2026-10-01T00:00:00+00:00"))


def reseal(snapshot):
    snapshot.pop("snapshot_id", None)
    return copy.deepcopy(make_snapshot(snapshot["provider"], snapshot["scopes"], snapshot["collections"],
        metadata=snapshot["metadata"], created_at=snapshot["created_at"]))


def native(snapshot, kind, name=None):
    matches = [r for r in resources(snapshot) if r["type"] == kind and (name is None or r["data"].get("name") == name or r["data"].get("id") == name or r["data"].get("metadata", {}).get("name") == name)]
    assert len(matches) == 1
    return matches[0]["id"]


def collection(snapshot, kind, scope=None):
    return next(c for c in snapshot["collections"] if c["type"] == kind and (scope is None or c["scope"] == scope))


def proof(**kwargs):
    return {"status": "collected", "complete": True, "source_evidence": [{"method": "read-only fixture capture", "path": "network_context"}], **kwargs}


def aws_fixture():
    scope = "111111111111/us-east-1"
    def sg_rule(prefix, ipv6prefix):
        return {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": prefix}], "Ipv6Ranges": [{"CidrIpv6": ipv6prefix}]}
    def acl(name, subnet):
        return {"id": name, "NetworkAclId": name, "VpcId": "vpc-a", "Associations": [{"SubnetId": subnet}],
            "Entries": [{"Egress": egress, "RuleNumber": number, "Protocol": "-1", "RuleAction": action, **ranges}
                for egress in (False, True) for number, action, ranges in (
                    (100, "allow", {"CidrBlock": "0.0.0.0/0"}), (101, "allow", {"Ipv6CidrBlock": "::/0"}),
                    (32767, "deny", {"CidrBlock": "0.0.0.0/0"}), (32768, "deny", {"Ipv6CidrBlock": "::/0"}))]}
    facts = {
        ("vpc", scope): [{"id": "vpc-a", "VpcId": "vpc-a", "OwnerId": "111111111111", "CidrBlock": "10.0.0.0/16", "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": "fd00::/48", "Ipv6CidrBlockState": {"State": "associated"}}]}],
        ("subnet", scope): [{"id": f"subnet-{i}", "SubnetId": f"subnet-{i}", "VpcId": "vpc-a", "CidrBlock": f"10.0.{i}.0/24", "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": f"fd00:0:0:{i}::/64", "Ipv6CidrBlockState": {"State": "associated"}}]} for i in (1, 2)],
        ("network_interface", scope): [{"id": name, "NetworkInterfaceId": name, "SubnetId": f"subnet-{i}", "VpcId": "vpc-a", "OwnerId": "111111111111", "Region": "us-east-1",
            "Status": "in-use", "Attachment": {"InstanceId": f"i-{name}", "Status": "attached"},
            "PrivateIpAddress": f"10.0.{i}.10", "Ipv6Addresses": [{"Ipv6Address": f"fd00:0:0:{i}::10"}], "Groups": [{"GroupId": group}]} for i, name, group in ((1, "source", "sg-source"), (2, "destination", "sg-destination"))],
        ("instance", scope): [{"id": f"i-{name}", "InstanceId": f"i-{name}", "State": {"Name": "running"},
            "NetworkInterfaces": [{"NetworkInterfaceId": name, "SubnetId": f"subnet-{i}", "VpcId": "vpc-a", "PrivateIpAddress": f"10.0.{i}.10"}]}
            for i, name in ((1, "source"), (2, "destination"))],
        ("security_group", scope): [{"id": "sg-source", "GroupId": "sg-source", "OwnerId": "111111111111", "VpcId": "vpc-a", "IpPermissions": [], "IpPermissionsEgress": [sg_rule("10.0.2.0/24", "fd00:0:0:2::/64")]},
            {"id": "sg-destination", "GroupId": "sg-destination", "OwnerId": "111111111111", "VpcId": "vpc-a", "IpPermissions": [sg_rule("10.0.1.0/24", "fd00:0:0:1::/64")], "IpPermissionsEgress": []}],
        ("route_table", scope): [{"id": "rt-a", "RouteTableId": "rt-a", "VpcId": "vpc-a", "Associations": [{"Main": True}],
            "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"}, {"DestinationIpv6CidrBlock": "fd00::/48", "GatewayId": "local", "State": "active"}]}],
        ("network_acl", scope): [acl("acl-source", "subnet-1"), acl("acl-destination", "subnet-2")],
        ("vpc_peering", scope): [],
    }
    return sealed("aws", facts)


def azure_fixture():
    scope = "/subscriptions/a"
    vnet = scope + "/resourceGroups/r/providers/Microsoft.Network/virtualNetworks/net"
    nsg = scope + "/resourceGroups/r/providers/Microsoft.Network/networkSecurityGroups/rules"
    subnets = [vnet + f"/subnets/s{i}" for i in (1, 2)]
    def rule(direction):
        return {"name": "allow-" + direction, "properties": {"provisioningState": "Succeeded", "priority": 200, "direction": direction, "access": "Allow",
            "protocol": "Tcp", "sourceAddressPrefix": "*", "destinationAddressPrefix": "*", "sourcePortRange": "*", "destinationPortRange": "443"}}
    facts = {
        ("vnet", scope): [{"id": vnet, "name": "net", "_provenance": {"representation": "full"},
            "properties": {"provisioningState": "Succeeded", "addressSpace": {"addressPrefixes": ["10.0.0.0/16", "fd00::/48"]}}}],
        ("subnet", scope): [{"id": subnet, "_provenance": {"representation": "full"},
            "properties": {"provisioningState": "Succeeded", "addressPrefixes": [f"10.0.{i}.0/24", f"fd00:0:0:{i}::/64"]}} for i, subnet in enumerate(subnets, 1)],
        ("nic", scope): [{"id": scope + f"/resourceGroups/r/providers/Microsoft.Network/networkInterfaces/{name}", "name": name,
            "_provenance": {"representation": "full"},
            "properties": {"provisioningState": "Succeeded", "virtualMachine": {"id": scope + f"/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/{name}"},
                "networkSecurityGroup": {"id": nsg}, "ipConfigurations": [
                {"name": "ipv4", "properties": {"privateIPAddress": f"10.0.{i}.10", "subnet": {"id": subnet}}},
                {"name": "ipv6", "properties": {"privateIPAddress": f"fd00:0:0:{i}::10", "subnet": {"id": subnet}}}]}}
            for i, name, subnet in ((1, "source", subnets[0]), (2, "destination", subnets[1]))],
        ("vm", scope): [{"id": scope + f"/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/{name}",
            "_provenance": {"representation": "full", "expand": "instanceView"},
            "properties": {"provisioningState": "Succeeded", "networkProfile": {"networkInterfaces": [{
                "id": scope + f"/resourceGroups/r/providers/Microsoft.Network/networkInterfaces/{name}"}]},
                "instanceView": {"statuses": [{"code": "PowerState/running"}]}}}
            for name in ("source", "destination")],
        ("nsg", scope): [{"id": nsg, "_provenance": {"representation": "full", "api_version": "2023-09-01"},
            "properties": {"provisioningState": "Succeeded", "securityRules": [rule("Outbound"), rule("Inbound")]}}],
        ("route_table", scope): [], ("vnet_peering", scope): [], ("security_admin_rule", scope): [],
    }
    snapshot = sealed("azure", facts, {"network_context": {"azure": {"routing": proof(bgp="none"), "security_admin": proof(policies=[])}}})
    collection(snapshot, "security_admin_rule")["source_evidence"] = [{
        "source_operation": "listNetworkManagerEffectiveSecurityAdminRules", "resource_id": vnet,
        "response_sha256": "a" * 64}]
    return reseal(snapshot)


def azure_effective_fixture():
    snapshot = azure_fixture()
    scope = "/subscriptions/a"
    rows = []
    for nic in collection(snapshot, "nic")["items"]:
        nic_id = nic["id"]
        rows.append({"id": nic_id + "/effectiveRoutes/0", "nic_id": nic_id,
            "_provenance": {"source_operation": "effectiveRouteTable", "read_only": True, "nic_id": nic_id},
            "route": {"name": "vnet-local", "source": "Default", "state": "Active",
                "addressPrefix": ["10.0.0.0/16"], "nextHopType": "VnetLocal"}})
    snapshot["collections"].append({"type": "effective_route", "scope": scope, "service": "Microsoft.Network",
        "status": "collected", "items": rows, "source_evidence": [
            {"source_operation": "effectiveRouteTable", "resource_id": nic["id"], "response_sha256": "a" * 64}
            for nic in collection(snapshot, "nic")["items"]]})
    snapshot["metadata"]["network_context"]["azure"].pop("routing")
    return reseal(snapshot)


def azure_effective_provenance(nic_id):
    return {"source_operation": "effectiveRouteTable", "read_only": True, "nic_id": nic_id}


def gcp_fixture():
    host, service = "projects/host", "projects/service"
    network = "https://www.googleapis.com/compute/v1/projects/host/global/networks/net"
    subnets = [f"https://www.googleapis.com/compute/v1/projects/host/regions/us-east1/subnetworks/s{i}" for i in (1, 2)]
    facts = {
        ("network", host): [{"name": "net", "selfLink": network, "peerings": []}],
        ("subnetwork", host): [{"name": f"s{i}", "selfLink": subnet, "network": network, "ipCidrRange": f"10.0.{i}.0/24", "internalIpv6Prefix": f"fd00:0:0:{i}::/64", "stackType": "IPV4_IPV6", "ipv6AccessType": "INTERNAL", "purpose": "PRIVATE"} for i, subnet in enumerate(subnets, 1)],
        ("instance", service): [{"name": "source", "status": "RUNNING", "tags": {"items": ["client"]}, "serviceAccounts": [{"email": "client@host.iam.gserviceaccount.com"}],
            "networkInterfaces": [{"name": "nic0", "network": network, "subnetwork": subnets[0], "networkIP": "10.0.1.10", "ipv6Address": "fd00:0:0:1::10", "stackType": "IPV4_IPV6", "ipv6AccessType": "INTERNAL"}]}],
        ("instance", host): [{"name": "destination", "status": "RUNNING", "tags": {"items": ["server"]}, "serviceAccounts": [{"email": "server@host.iam.gserviceaccount.com"}],
            "networkInterfaces": [{"name": "nic0", "network": network, "subnetwork": subnets[1], "networkIP": "10.0.2.10", "ipv6Address": "fd00:0:0:2::10", "stackType": "IPV4_IPV6", "ipv6AccessType": "INTERNAL"}]}],
        ("firewall", host): [{"name": "allow", "network": network, "direction": "INGRESS", "priority": 100,
            "sourceTags": ["client"], "targetTags": ["server"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
            {"name": "deny", "network": network, "direction": "INGRESS", "priority": 200, "sourceRanges": ["0.0.0.0/0", "::/0"], "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]}],
        ("route", host): [],
        ("firewall_policy", host): [],
        ("effective_firewall", host): [{"id": "projects/host/global/networks/net/regions/us-east1/effectiveFirewalls",
            "network": network, "region": "us-east1", "firewallPolicys": [],
            "effective_source_operation": "regionNetworkFirewallPolicies.getEffectiveFirewalls",
            "_provenance": {"source_requests": ["region-effective-firewalls"]}}],
        ("firewall_policy_association", "organizations/12"): [],
    }
    snapshot = sealed("gcp", facts, {"network_context": {"gcp": {
        "routing": proof(policy_based_routes="none", dynamic_routes="none"),
        "firewall_hierarchy": proof(policies=[], unaffected_projects=[host],
            project_ancestors={host: ["organizations/12"]})}}})
    collection(snapshot, "firewall_policy", host)["source_requests"] = ["project-policy-list"]
    collection(snapshot, "effective_firewall", host)["source_requests"] = ["region-effective-firewalls"]
    collection(snapshot, "firewall_policy_association", "organizations/12")["source_requests"] = ["ancestor-association-list"]
    return reseal(snapshot)


def k8s_fixture():
    scope = "*"
    facts = {
        ("namespace", scope): [{"metadata": {"name": name, "labels": {"team": name}}} for name in ("client", "server")],
        ("pod", scope): [{"metadata": {"name": name, "namespace": namespace, "labels": {"app": name}},
            "spec": {"containers": [{"name": "application", "ports": [{"name": "https", "protocol": "TCP", "containerPort": 443}]}]},
            "status": {"phase": "Running", "podIP": address, "podIPs": [{"ip": address}, {"ip": f"fd00::{i}"}]}, "provenance": {"cluster_id": "cluster-a"}}
            for i, name, namespace, address in ((1, "source", "client", "10.0.1.10"), (2, "destination", "server", "10.0.2.10"))],
        ("networkpolicy", scope): [
            {"metadata": {"name": "egress", "namespace": "client"}, "spec": {"podSelector": {"matchLabels": {"app": "source"}}, "policyTypes": ["Egress"],
                "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"team": "server"}}, "podSelector": {"matchLabels": {"app": "destination"}}}], "ports": [{"protocol": "TCP", "port": 443}]}]}},
            {"metadata": {"name": "ingress", "namespace": "server"}, "spec": {"podSelector": {"matchLabels": {"app": "destination"}}, "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"team": "client"}}, "podSelector": {"matchLabels": {"app": "source"}}}], "ports": [{"protocol": "TCP", "port": "https"}]}]}}],
        ("cilium_networkpolicy", scope): [],
        ("cilium_clusterwide_networkpolicy", scope): [],
        ("calico_networkpolicy", scope): [],
        ("calico_global_networkpolicy", scope): [],
        ("admin_networkpolicy", scope): [],
        ("baseline_admin_networkpolicy", scope): [],
        ("cluster_networkpolicy", scope): [],
        ("api_discovery", scope): [{"id": "k8s://cluster-a/api-discovery", "groups": [
            {"name": "networking.k8s.io", "versions": [{"version": "v1", "groupVersion": "networking.k8s.io/v1"}]}],
            "provenance": {"cluster_id": "cluster-a", "source": "GET /apis"}}],
    }
    for item in facts[("namespace", scope)]:
        item["provenance"] = {"cluster_id": "cluster-a", "namespace": "_cluster"}
    for item in facts[("networkpolicy", scope)]:
        item["provenance"] = {"cluster_id": "cluster-a", "namespace": item["metadata"]["namespace"]}
    return sealed("k8s", facts, {"cluster_id": "cluster-a", "network_context": {"k8s": {
        "cni": proof(enforces_network_policy=True, policy_sources="standard_networkpolicy_only", supports_end_port=True, ipblock_semantics="pod_ips_preserved"),
        "routing": proof(pod_network_connected=True)}}})


FIXTURES = {"aws": (aws_fixture, "network_interface"), "azure": (azure_fixture, "nic"), "gcp": (gcp_fixture, "instance"), "k8s": (k8s_fixture, "pod")}


@pytest.mark.parametrize("provider,kind", [
    *(('aws', kind) for kind in ('vpc', 'subnet', 'network_interface', 'instance', 'security_group', 'route_table', 'network_acl')),
    *(('azure', kind) for kind in ('vnet', 'subnet', 'nic', 'vm', 'nsg', 'security_admin_rule')),
    *(('gcp', kind) for kind in ('network', 'subnetwork', 'instance', 'firewall', 'route', 'firewall_policy', 'effective_firewall', 'firewall_policy_association')),
    *(('k8s', kind) for kind in ('namespace', 'pod', 'networkpolicy', 'cilium_networkpolicy',
        'cilium_clusterwide_networkpolicy', 'calico_networkpolicy', 'calico_global_networkpolicy',
        'admin_networkpolicy', 'baseline_admin_networkpolicy', 'cluster_networkpolicy', 'api_discovery')),
])
def test_incomplete_decisive_network_inventory_never_proves_allowance(provider, kind):
    snapshot = FIXTURES[provider][0]()
    assert query(snapshot)["decision"] == "allowed"
    collection(snapshot, kind)["status"] = "partial"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", (provider, kind, result)
    assert result["unresolved_dependencies"], (provider, kind, result)


@pytest.mark.parametrize("provider,control", [
    ("aws", "security_group"), ("azure", "nsg"), ("gcp", "firewall"), ("k8s", "networkpolicy"),
])
def test_duplicate_native_network_control_identity_cannot_prove_a_flow(provider, control):
    snapshot = FIXTURES[provider][0]()
    control_items = collection(snapshot, control)["items"]
    control_items.append(copy.deepcopy(control_items[0]))
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_inventory_identity_collision" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "k8s"])
def test_batch_reuses_index_without_sharing_decisions_or_evidence(provider):
    snapshot = FIXTURES[provider][0]()
    kind = FIXTURES[provider][1]
    source = native(snapshot, kind, "source")
    destination = native(snapshot, kind, "destination")
    ids = [destination, source]
    batch = evaluate_reachability_batch(snapshot, source, ids, "tcp", 443)
    singles = [evaluate_reachability(snapshot, source, target, "tcp", 443) for target in ids]
    assert batch == singles
    assert batch[0] is not batch[1]
    with pytest.raises(ValueError):
        evaluate_reachability_batch(snapshot, source, [destination, destination], "tcp", 443)
    with pytest.raises(ValueError):
        evaluate_reachability_batch(snapshot, source, [str(index) for index in range(25)], "tcp", 443)


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "k8s"])
def test_matrix_evaluates_both_directions_independently(provider):
    snapshot = FIXTURES[provider][0]()
    kind = FIXTURES[provider][1]
    endpoints = [native(snapshot, kind, name) for name in ("source", "destination")]
    matrix = evaluate_reachability_matrix(snapshot, endpoints, "tcp", 443, 54321)
    expected = [evaluate_reachability(snapshot, source, destination, "tcp", 443, 54321)
        for source in endpoints for destination in endpoints if source != destination]
    assert matrix == expected
    assert matrix[0] is not matrix[1]
    assert [row["query"]["source_resource_id"] for row in matrix] == endpoints
    with pytest.raises(ValueError):
        evaluate_reachability_matrix(snapshot, [endpoints[0], endpoints[0]], "tcp", 443)
    with pytest.raises(ValueError):
        evaluate_reachability_matrix(snapshot, [str(index) for index in range(13)], "tcp", 443)


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "k8s"])
def test_grid_evaluates_cross_window_pairs_in_both_directions(provider):
    snapshot = FIXTURES[provider][0]()
    kind = FIXTURES[provider][1]
    source, destination = [native(snapshot, kind, name) for name in ("source", "destination")]
    grid = evaluate_reachability_grid(snapshot, [source, "absent-endpoint"], [destination], "tcp", 443, 54321)
    pairs = [(source, destination), ("absent-endpoint", destination),
        (destination, source), (destination, "absent-endpoint")]
    assert [(row["query"]["source_resource_id"], row["query"]["destination_resource_id"]) for row in grid] == pairs
    assert grid == [evaluate_reachability(snapshot, first, second, "tcp", 443, 54321) for first, second in pairs]
    overlap = evaluate_reachability_grid(snapshot, [source, destination], [destination], "tcp", 443, 54321)
    assert len(overlap) == 2
    with pytest.raises(ValueError):
        evaluate_reachability_grid(snapshot, [source], [source], "tcp", 443)


def query(snapshot, port=443, source_port=54321, family="ipv4", protocol="tcp"):
    kind = FIXTURES[snapshot["provider"]][1]
    return evaluate_reachability(snapshot, native(snapshot, kind, "source"), native(snapshot, kind, "destination"), protocol, port, source_port, family)


@pytest.mark.parametrize("provider", FIXTURES)
@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_complete_path_all_providers_and_families(provider, family):
    snapshot = FIXTURES[provider][0]()
    before = copy.deepcopy(snapshot)
    result = query(snapshot, family=family)
    assert result["decision"] == "allowed", result
    assert result["application_listening"] == "unknown"
    assert result["modeled_configuration"] and result["new_flow_only"]
    assert result["routes"] and result["policy_decisions"] and result["evidence_refs"]
    assert result["unresolved_dependencies"] == []
    assert snapshot == before


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "k8s"])
@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_allowed_flow_has_every_required_route_and_policy_stage(provider, family):
    result = query(FIXTURES[provider][0](), family=family)
    assert result["decision"] == "allowed", result
    routes = {(step.get("direction"), step["decision"]) for step in result["routes"]}
    expected_routes = {("forward_and_return", "allowed")} if provider == "k8s" else {
        ("forward", "allowed"), ("return", "allowed")}
    assert expected_routes <= routes
    policies = [(step.get("control"), step.get("direction"), step.get("flow"), step["decision"])
        for step in result["policy_decisions"]]
    expected = {
        "aws": {("aws.security_group", "egress", None, "allowed"),
            ("aws.security_group", "ingress", None, "allowed"),
            *(("aws.network_acl", direction, flow, "allowed")
                for direction in ("egress", "ingress") for flow in ("forward", "return"))},
        "azure": {("azure.nsg", "Outbound", None, "allowed"),
            ("azure.nsg", "Inbound", None, "allowed")},
        "gcp": {("gcp.firewall", "EGRESS", None, "allowed"),
            ("gcp.firewall", "INGRESS", None, "allowed")},
        "k8s": {("k8s.networkpolicy", "Egress", None, "allowed"),
            ("k8s.networkpolicy", "Ingress", None, "allowed")},
    }
    assert expected[provider] <= set(policies)
    if provider == "azure":
        assert sum(control == "azure.nsg" and direction == "Outbound" for control, direction, _, _ in policies) == 2
        assert sum(control == "azure.nsg" and direction == "Inbound" for control, direction, _, _ in policies) == 2


def test_aws_stateful_sg_return_and_stateless_nacl_return():
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][1]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 10, "Protocol": "6", "PortRange": {"From": 54321, "To": 54321}, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert any(p.get("flow") == "return" and p["decision"] == "blocked" for p in result["policy_decisions"])
    assert any("stateful" in p.get("return_behavior", "") for p in result["policy_decisions"])


def test_aws_unrelated_numeric_protocol_rules_do_not_obscure_tcp():
    snapshot = aws_fixture()
    groups = collection(snapshot, "security_group")["items"]
    groups[1]["IpPermissions"].insert(0, {"IpProtocol": "80", "IpRanges": [{"CidrIp": "10.0.1.0/24"}]})
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 1, "Protocol": "80",
        "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    assert query(reseal(snapshot))["decision"] == "allowed"


@pytest.mark.parametrize("alias", ["any", "all", "*"])
def test_aws_unsupported_all_protocol_aliases_cannot_prove_allow(alias):
    snapshot = aws_fixture()
    group = collection(snapshot, "security_group")["items"][1]
    group["IpPermissions"][0]["IpProtocol"] = alias
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_aws_unsupported_nacl_protocol_alias_cannot_prove_allow():
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"][0]["Protocol"] = "any"
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_aws_malformed_nacl_port_range_is_unresolved():
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 1, "Protocol": "6",
        "PortRange": None, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "nacl_rule_unresolved" for g in result["unresolved_dependencies"])


def test_aws_return_source_port_required_only_when_rule_constrains_it():
    snapshot = aws_fixture()
    assert query(snapshot, source_port=None)["decision"] == "allowed"
    acl = collection(snapshot, "network_acl")["items"][1]
    acl["Entries"] = [r for r in acl["Entries"] if not r["Egress"] or r["RuleNumber"] == 32767]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 10, "Protocol": "6", "PortRange": {"From": 1024, "To": 65535}, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"})
    snapshot = reseal(snapshot)
    result = query(snapshot, source_port=None)
    assert result["decision"] == "unknown"
    assert any(g["code"] == "source_port_required" for g in result["unresolved_dependencies"])
    assert query(snapshot, source_port=54321)["decision"] == "allowed"
    assert query(snapshot, source_port=1000)["decision"] == "blocked"


def test_aws_instance_eni_attachment_must_match_in_both_native_views():
    snapshot = aws_fixture()
    scope = snapshot["scopes"][0]
    instance_id = "i-client"
    eni = collection(snapshot, "network_interface")["items"][0]
    eni["Attachment"] = {"InstanceId": instance_id, "Status": "attached"}
    declared = {"NetworkInterfaceId": eni["NetworkInterfaceId"], "SubnetId": eni["SubnetId"],
        "VpcId": eni["VpcId"], "PrivateIpAddress": eni["PrivateIpAddress"]}
    collection(snapshot, "instance", scope)["items"].append(
        {"id": instance_id, "InstanceId": instance_id, "State": {"Name": "running"}, "NetworkInterfaces": [declared]})
    def assess():
        sealed = reseal(snapshot)
        return evaluate_reachability(sealed, native(sealed, "instance", instance_id), native(sealed, "network_interface", "destination"), "tcp", 443, 54321)
    assert assess()["decision"] == "allowed"
    eni["Attachment"]["InstanceId"] = "i-other"
    result = assess()
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_association_mismatch" for g in result["unresolved_dependencies"])
    eni["Attachment"]["InstanceId"] = instance_id
    declared["SubnetId"] = "subnet-other"
    assert assess()["decision"] == "unknown"


def test_aws_instance_summary_without_interface_inventory_cannot_prove_path():
    snapshot = aws_fixture()
    scope = snapshot["scopes"][0]
    eni = collection(snapshot, "network_interface")["items"][0]
    instance_id = "i-summary"
    collection(snapshot, "instance", scope)["items"].append({"id": instance_id, "InstanceId": instance_id,
        "State": {"Name": "running"}, "SubnetId": eni["SubnetId"], "VpcId": eni["VpcId"],
        "PrivateIpAddress": eni["PrivateIpAddress"], "SecurityGroups": eni["Groups"]})
    snapshot = reseal(snapshot)
    result = evaluate_reachability(snapshot, native(snapshot, "instance", instance_id),
        native(snapshot, "network_interface", "destination"), "tcp", 443, 54321)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "endpoint_interface_ambiguous" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("mutation, gap", [
    ("eni_available", "endpoint_interface_not_attached"),
    ("attachment_detached", "endpoint_interface_not_attached"),
    ("instance_stopped", "endpoint_not_running"),
    ("reverse_reference_missing", "endpoint_association_mismatch"),
    ("reverse_address_mismatch", "endpoint_association_mismatch"),
    ("instance_inventory_missing", "endpoint_instance_inventory_incomplete"),
])
def test_aws_eni_needs_attached_running_native_instance(mutation, gap):
    snapshot = aws_fixture()
    eni = collection(snapshot, "network_interface")["items"][0]
    instance = collection(snapshot, "instance")["items"][0]
    if mutation == "eni_available":
        eni["Status"] = "available"
        eni.pop("Attachment")
    elif mutation == "attachment_detached":
        eni["Attachment"]["Status"] = "detached"
    elif mutation == "instance_stopped":
        instance["State"]["Name"] = "stopped"
    elif mutation == "reverse_reference_missing":
        instance["NetworkInterfaces"] = []
    elif mutation == "reverse_address_mismatch":
        instance["NetworkInterfaces"][0]["PrivateIpAddress"] = "10.0.1.99"
    else:
        collection(snapshot, "instance")["status"] = "partial"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == gap for g in result["unresolved_dependencies"])
    if mutation == "instance_stopped":
        sealed = reseal(snapshot)
        selected = evaluate_reachability(sealed, native(sealed, "instance", "i-source"),
            native(sealed, "network_interface", "destination"), "tcp", 443, 54321)
        assert selected["decision"] == "unknown", selected
        assert any(g["code"] == "endpoint_not_running" for g in selected["unresolved_dependencies"])


def test_endpoint_identity_gap_cannot_become_a_blocked_connection():
    aws = aws_fixture()
    collection(aws, "instance")["items"][0]["State"]["Name"] = "stopped"
    collection(aws, "route_table")["items"][0]["Routes"][0]["State"] = "blackhole"
    aws_result = query(reseal(aws))
    assert aws_result["decision"] == "unknown", aws_result
    assert any(route["decision"] == "blocked" for route in aws_result["routes"])

    azure = azure_effective_fixture()
    collection(azure, "vm")["items"][0]["properties"]["instanceView"]["statuses"][0]["code"] = "PowerState/deallocated"
    collection(azure, "effective_route")["items"][0]["route"]["nextHopType"] = "None"
    azure_result = query(reseal(azure))
    assert azure_result["decision"] == "unknown", azure_result
    assert any(route["decision"] == "blocked" for route in azure_result["routes"])

    gcp = gcp_fixture()
    collection(gcp, "instance", "projects/service")["items"][0]["status"] = "TERMINATED"
    collection(gcp, "firewall")["items"].append({"name": "deny-egress", "network": collection(gcp, "network")["items"][0]["selfLink"],
        "direction": "EGRESS", "priority": 50, "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    gcp_result = query(reseal(gcp))
    assert gcp_result["decision"] == "unknown", gcp_result
    assert any(policy["decision"] == "blocked" for policy in gcp_result["policy_decisions"])


def test_aws_disassociated_ipv6_domain_is_not_a_current_address_fact():
    snapshot = aws_fixture()
    collection(snapshot, "vpc")["items"][0]["Ipv6CidrBlockAssociationSet"][0]["Ipv6CidrBlockState"] = {"State": "disassociated"}
    assert query(reseal(snapshot), family="ipv6")["decision"] == "unknown"


def test_aws_disassociated_ipv4_domain_is_not_a_current_address_fact():
    snapshot = aws_fixture()
    vpc = collection(snapshot, "vpc")["items"][0]
    vpc["CidrBlock"] = "172.16.0.0/16"
    vpc["CidrBlockAssociationSet"] = [{"CidrBlock": "10.0.0.0/16", "CidrBlockState": {"State": "disassociated"}}]
    assert query(reseal(snapshot))["decision"] == "unknown"


@pytest.mark.parametrize("state", ["associating", "disassociating", "failed"])
def test_aws_transitioning_explicit_route_association_cannot_fall_back_to_main(state):
    snapshot = aws_fixture()
    table = collection(snapshot, "route_table")["items"][0]
    table["Associations"].append({"SubnetId": "subnet-1", "AssociationState": {"State": state}})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "route_association_transition" for g in result["unresolved_dependencies"])


def test_aws_disassociated_explicit_route_table_uses_main_table():
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"][0]["Associations"].append(
        {"SubnetId": "subnet-1", "AssociationState": {"State": "disassociated"}})
    assert query(reseal(snapshot))["decision"] == "allowed"


@pytest.mark.parametrize("associations", ["missing", None, "invalid", [None], [{"SubnetId": ["subnet-1"]}],
    [{}], [{"SubnetId": ""}], [{"Main": False}],
    [{"Main": True, "SubnetId": "subnet-1"}],
    [{"SubnetId": "subnet-1", "GatewayId": "igw-1"}],
    [{"Main": True, "GatewayId": "igw-1"}],
    [{"SubnetId": "subnet-1", "AssociationState": "associated"}]])
def test_aws_malformed_route_association_cannot_hide_explicit_table(associations):
    snapshot = aws_fixture()
    other = {"id": "rt-other", "RouteTableId": "rt-other", "VpcId": "vpc-a", "Routes": []}
    if associations != "missing":
        other["Associations"] = associations
    collection(snapshot, "route_table")["items"].append(other)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_association_malformed" for g in result["unresolved_dependencies"])


def test_aws_route_association_with_wrong_vpc_cannot_fall_back_to_main():
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"].append({
        "id": "rt-conflict", "RouteTableId": "rt-conflict", "VpcId": "vpc-other",
        "Associations": [{"SubnetId": "subnet-1"}], "Routes": [],
    })
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_association_mismatch" for g in result["unresolved_dependencies"])


def test_aws_gateway_route_table_association_does_not_hide_subnet_routing():
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"].append({
        "id": "rt-gateway", "RouteTableId": "rt-gateway", "VpcId": "vpc-a",
        "Associations": [{"GatewayId": "igw-1", "Main": False}], "Routes": [],
    })
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_aws_main_route_table_association_cannot_also_target_subnet():
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"][0]["Associations"][0]["SubnetId"] = "subnet-1"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_association_malformed" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("associations", ["missing", None, "invalid", [None], [{}],
    [{"SubnetId": None}], [{"SubnetId": ""}], [{"SubnetId": ["subnet-1"]}]])
def test_aws_malformed_nacl_association_cannot_hide_selected_subnet(associations):
    snapshot = aws_fixture()
    other = {"id": "acl-other", "NetworkAclId": "acl-other", "VpcId": "vpc-a", "Entries": []}
    if associations != "missing":
        other["Associations"] = associations
    collection(snapshot, "network_acl")["items"].append(other)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nacl_association_malformed" for g in result["unresolved_dependencies"])


def test_aws_nacl_association_with_wrong_vpc_cannot_prove_allow():
    snapshot = aws_fixture()
    collection(snapshot, "network_acl")["items"].append({
        "id": "acl-conflict", "NetworkAclId": "acl-conflict", "VpcId": "vpc-other",
        "Associations": [{"SubnetId": "subnet-1"}], "Entries": [],
    })
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nacl_association_mismatch" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("routes", [{}, None, [None]])
def test_aws_malformed_route_array_cannot_prove_missing_route(routes):
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"][0]["Routes"] = routes
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_rule_malformed" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("routes", [[], [
    {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-a", "State": "active"}
]])
def test_aws_route_table_missing_mandatory_vpc_entry_cannot_prove_no_path(routes):
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"][0]["Routes"] = routes
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_table_local_entry_missing" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("missing_family", ["secondary_ipv4", "ipv6"])
def test_aws_route_table_requires_every_associated_vpc_cidr(missing_family):
    snapshot = aws_fixture()
    if missing_family == "secondary_ipv4":
        collection(snapshot, "vpc")["items"][0]["CidrBlockAssociationSet"] = [{
            "CidrBlock": "10.2.0.0/16", "CidrBlockState": {"State": "associated"}}]
    else:
        table = collection(snapshot, "route_table")["items"][0]
        table["Routes"] = [route for route in table["Routes"] if "DestinationIpv6CidrBlock" not in route]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_table_local_entry_missing" for g in result["unresolved_dependencies"])


def test_aws_route_with_two_destination_selectors_cannot_prove_path():
    snapshot = aws_fixture()
    route = collection(snapshot, "route_table")["items"][0]["Routes"][0]
    route["DestinationIpv6CidrBlock"] = "fd00::/48"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_destination_ambiguous" for g in result["unresolved_dependencies"])


def test_aws_local_route_with_conflicting_next_hop_cannot_prove_path():
    snapshot = aws_fixture()
    route = collection(snapshot, "route_table")["items"][0]["Routes"][0]
    route["VpcPeeringConnectionId"] = "pcx-conflict"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_target_ambiguous" for g in result["unresolved_dependencies"])


def test_aws_peering_route_with_conflicting_next_hop_cannot_prove_path():
    snapshot = aws_peered_fixture()
    route = collection(snapshot, "route_table", "111111111111/us-east-1")["items"][0]["Routes"][2]
    route["NatGatewayId"] = "nat-conflict"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_target_ambiguous" for g in result["unresolved_dependencies"])


def test_aws_ordered_nacl_deny_and_same_subnet_exception():
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"].append({"Egress": True, "RuleNumber": 20, "Protocol": "-1", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    snapshot = reseal(snapshot)
    result = query(snapshot)
    assert result["decision"] == "blocked"
    assert any(p.get("control") == "aws.network_acl" and p["decision"] == "blocked" and p.get("flow") == "forward" for p in result["policy_decisions"])
    destination = collection(snapshot, "network_interface")["items"][1]
    destination["SubnetId"], destination["PrivateIpAddress"] = "subnet-1", "10.0.1.20"
    collection(snapshot, "instance")["items"][1]["NetworkInterfaces"][0].update(
        SubnetId="subnet-1", PrivateIpAddress="10.0.1.20")
    groups = collection(snapshot, "security_group")["items"]
    groups[0]["IpPermissionsEgress"][0]["IpRanges"] = [{"CidrIp": "10.0.1.0/24"}]
    assert query(reseal(snapshot))["decision"] == "allowed"


@pytest.mark.parametrize("number", [0, -1, 32768, 65535])
def test_aws_out_of_range_nacl_order_cannot_prove_first_match(number):
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": number, "Protocol": "-1",
        "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nacl_order_malformed" for g in result["unresolved_dependencies"])


def test_aws_reserved_nacl_rule_cannot_claim_a_custom_allow():
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][0]
    implicit = next(rule for rule in acl["Entries"] if rule["Egress"] and
        rule["RuleNumber"] == 32767 and "CidrBlock" in rule)
    implicit["RuleAction"] = "allow"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nacl_implicit_rule_malformed" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("family,number", [("ipv4", 32767), ("ipv6", 32768)])
def test_aws_missing_native_implicit_nacl_entry_cannot_prove_a_complete_rule_list(family, number):
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"] = [rule for rule in acl["Entries"] if not (
        rule["Egress"] and rule["RuleNumber"] == number)]
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nacl_implicit_rule_missing" for g in result["unresolved_dependencies"])


def test_aws_ipv6_native_implicit_nacl_rule_uses_32768():
    snapshot = aws_fixture()
    assert query(snapshot, family="ipv6")["decision"] == "allowed"
    acl = collection(snapshot, "network_acl")["items"][0]
    implicit = next(rule for rule in acl["Entries"] if rule["Egress"] and
        rule["RuleNumber"] == 32768 and "Ipv6CidrBlock" in rule)
    implicit["RuleAction"] = "allow"
    result = query(reseal(snapshot), family="ipv6")
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nacl_implicit_rule_malformed" for g in result["unresolved_dependencies"])


def test_aws_dual_family_nacl_entry_cannot_hide_ipv6_deny():
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 50, "Protocol": "-1",
        "RuleAction": "deny", "CidrBlock": "192.0.2.0/24", "Ipv6CidrBlock": "::/0"})
    result = query(reseal(snapshot), family="ipv6")
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nacl_rule_unresolved" for g in result["unresolved_dependencies"])


def test_aws_same_subnet_uses_direct_path_even_without_route_table_or_nacl_inventory():
    snapshot = aws_fixture()
    destination = collection(snapshot, "network_interface")["items"][1]
    destination.update(SubnetId="subnet-1", PrivateIpAddress="10.0.1.20")
    collection(snapshot, "instance")["items"][1]["NetworkInterfaces"][0].update(
        SubnetId="subnet-1", PrivateIpAddress="10.0.1.20")
    source_group = collection(snapshot, "security_group")["items"][0]
    source_group["IpPermissionsEgress"][0]["IpRanges"] = [{"CidrIp": "10.0.1.0/24"}]
    for kind in ("route_table", "network_acl"):
        collection(snapshot, kind).update(status="denied", items=[])
    result = query(reseal(snapshot), source_port=None)
    assert result["decision"] == "allowed", result
    assert len(result["routes"]) == 1
    assert result["routes"][0]["direction"] == "forward_and_return"
    assert not any(g["code"] in {"route_collection_incomplete", "nacl_collection_incomplete"}
        for g in result["unresolved_dependencies"])
    source_group["IpPermissionsEgress"] = []
    blocked = query(reseal(snapshot), source_port=None)
    assert blocked["decision"] == "blocked"
    assert any(step.get("control") == "aws.security_group" and step["decision"] == "blocked"
        for step in blocked["policy_decisions"])


def test_aws_referenced_security_groups_are_union_not_copied_peer_rules():
    snapshot = aws_fixture()
    groups = collection(snapshot, "security_group")["items"]
    groups[0]["IpPermissionsEgress"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "UserIdGroupPairs": [{"GroupId": "sg-destination", "UserId": "111111111111"}]}]
    groups[1]["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "UserIdGroupPairs": [{"GroupId": "sg-source", "UserId": "111111111111"}]}]
    assert query(reseal(snapshot))["decision"] == "allowed"
    groups[1]["IpPermissions"][0]["UserIdGroupPairs"][0]["UserId"] = "222222222222"
    assert query(reseal(snapshot))["decision"] == "blocked"


@pytest.mark.parametrize("association", ["missing", "malformed", "conflicting"])
def test_aws_unknown_peer_sg_membership_cannot_prove_reference_denial(association):
    snapshot = aws_fixture()
    groups = collection(snapshot, "security_group")["items"]
    groups[1]["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "UserIdGroupPairs": [{"GroupId": "sg-source", "UserId": "111111111111"}]}]
    assert query(reseal(snapshot))["decision"] == "allowed"
    source = collection(snapshot, "network_interface")["items"][0]
    if association == "missing":
        source.pop("Groups")
    elif association == "malformed":
        source["Groups"] = [{}]
    else:
        source["SecurityGroups"] = [{"GroupId": "sg-other"}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] in {"security_group_association_missing", "security_group_association_malformed"}
        for g in result["unresolved_dependencies"])


def test_aws_referenced_sg_must_belong_to_attached_eni_vpc():
    snapshot = aws_fixture()
    source = collection(snapshot, "network_interface")["items"][0]
    source["Groups"].append({"GroupId": "sg-foreign"})
    groups = collection(snapshot, "security_group")["items"]
    foreign = copy.deepcopy(groups[0])
    foreign.update(id="sg-foreign", GroupId="sg-foreign", VpcId="vpc-other")
    groups.append(foreign)
    groups[1]["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "UserIdGroupPairs": [{"GroupId": "sg-foreign", "UserId": "111111111111"}]}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "security_group_rules_incomplete" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("pair", [{"GroupName": "source"}, {"GroupId": None},
    {"GroupId": "sg-source", "VpcId": ["vpc-a"]}, {"GroupId": "sg-source", "UserId": ["111111111111"]}])
def test_aws_malformed_referenced_security_group_cannot_prove_no_allow(pair):
    snapshot = aws_fixture()
    group = collection(snapshot, "security_group")["items"][1]
    group["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "UserIdGroupPairs": [pair]}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "security_group_rules_incomplete" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("field", ["IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs"])
def test_aws_malformed_empty_sg_selector_container_cannot_decide(field):
    snapshot = aws_fixture()
    rule = collection(snapshot, "security_group")["items"][1]["IpPermissions"][0]
    rule[field] = {}
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "security_group_rules_incomplete" for g in result["unresolved_dependencies"])


def test_aws_sg_permission_without_any_peer_selector_cannot_prove_deny():
    snapshot = aws_fixture()
    group = collection(snapshot, "security_group")["items"][1]
    group["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "security_group_rules_incomplete" for g in result["unresolved_dependencies"])
    group["IpPermissions"][0]["IpProtocol"] = "80"
    assert query(reseal(snapshot))["decision"] == "blocked"


def test_aws_malformed_sg_permission_container_cannot_become_implicit_deny():
    snapshot = aws_fixture()
    collection(snapshot, "security_group")["items"][1]["IpPermissions"] = {}
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "security_group_rules_incomplete" for g in result["unresolved_dependencies"])


def test_aws_versioned_prefix_list_can_decide_sg_membership():
    snapshot = aws_fixture()
    scope = snapshot["scopes"][0]
    snapshot["collections"].append({"type": "managed_prefix_list", "scope": scope, "service": "ec2", "status": "collected", "items": [{
        "id": "pl-peer", "PrefixListId": "pl-peer", "AddressFamily": "IPv4", "State": "create-complete", "Version": 3, "EntriesVersion": 3,
        "Entries": {"collection_status": "collected", "items": [{"Cidr": "10.0.2.0/24"}]}}]})
    source = collection(snapshot, "security_group")["items"][0]
    source["IpPermissionsEgress"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "PrefixListIds": [{"PrefixListId": "pl-peer"}]}]
    assert query(reseal(snapshot))["decision"] == "allowed"
    prefix = collection(snapshot, "managed_prefix_list")["items"][0]
    prefix["Entries"]["items"] = [{"Cidr": "192.0.2.0/24"}]
    assert query(reseal(snapshot))["decision"] == "blocked"
    prefix["EntriesVersion"] = 2
    assert query(reseal(snapshot))["decision"] == "unknown"
    prefix["EntriesVersion"] = 3
    prefix["Entries"]["collection_status"] = "denied"
    assert query(reseal(snapshot))["decision"] == "unknown"
    snapshot["collections"] = [c for c in snapshot["collections"] if c["type"] != "managed_prefix_list"]
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_aws_unmatched_prefix_list_route_does_not_hide_native_local_route():
    snapshot = aws_fixture()
    scope = snapshot["scopes"][0]
    snapshot["collections"].append({"type": "managed_prefix_list", "scope": scope, "service": "ec2", "status": "collected", "items": [{
        "id": "pl-other", "PrefixListId": "pl-other", "AddressFamily": "IPv4", "State": "create-complete", "Version": 1, "EntriesVersion": 1,
        "Entries": {"collection_status": "collected", "items": [{"Cidr": "192.0.2.0/24"}]}}]})
    collection(snapshot, "route_table")["items"][0]["Routes"].append({
        "DestinationPrefixListId": "pl-other", "GatewayId": "igw-a", "State": "active"})
    assert query(reseal(snapshot))["decision"] == "allowed"
    prefix = collection(snapshot, "managed_prefix_list")["items"][0]
    prefix["Entries"]["items"] = [{"Cidr": "10.0.2.0/24"}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "unsupported_route_component" for g in result["unresolved_dependencies"])
    prefix["Entries"]["items"] = [{"Cidr": "10.0.0.0/16"}]
    assert query(reseal(snapshot))["decision"] == "allowed"
    prefix["EntriesVersion"] = 0
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_aws_local_route_precedes_more_specific_propagated_route_but_not_static_route():
    snapshot = aws_fixture()
    table = collection(snapshot, "route_table")["items"][0]
    table["Routes"].append({"DestinationCidrBlock": "10.0.2.0/24", "GatewayId": "vgw-a",
        "Origin": "EnableVgwRoutePropagation", "State": "active"})
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed", result
    assert any(route["decision"] == "allowed" and route.get("direction") == "forward"
        for route in result["routes"])
    table["Routes"].append({"DestinationCidrBlock": "10.0.2.10/32", "NetworkInterfaceId": "eni-appliance",
        "Origin": "CreateRoute", "State": "active"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "unsupported_route_component" for g in result["unresolved_dependencies"])


def test_aws_peering_route_can_use_versioned_prefix_list_destination():
    snapshot = aws_peered_fixture()
    source_scope = snapshot["scopes"][0]
    table = collection(snapshot, "route_table", source_scope)["items"][0]
    table["Routes"] = [route for route in table["Routes"] if route.get("DestinationCidrBlock") != "10.1.0.0/16"]
    table["Routes"].append({"DestinationPrefixListId": "pl-peer-vpc", "VpcPeeringConnectionId": "pcx-a", "State": "active"})
    snapshot["collections"].append({"type": "managed_prefix_list", "scope": source_scope, "service": "ec2", "status": "collected", "items": [{
        "id": "pl-peer-vpc", "PrefixListId": "pl-peer-vpc", "AddressFamily": "IPv4", "State": "create-complete",
        "Version": 1, "EntriesVersion": 1, "Entries": {"collection_status": "collected", "items": [{"Cidr": "10.1.0.0/16"}]}}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed", result
    assert any(ref["type"] == "managed_prefix_list" for ref in result["routes"][0]["evidence_refs"])


def test_aws_prefix_list_route_precedes_equal_propagated_route_and_overlap_is_ambiguous():
    snapshot = aws_fixture()
    scope = snapshot["scopes"][0]
    table = collection(snapshot, "route_table")["items"][0]
    table["Routes"].append({"DestinationCidrBlock": "10.0.2.0/24", "GatewayId": "vgw-a",
        "Origin": "EnableVgwRoutePropagation", "State": "active"})
    table["Routes"].append({"DestinationPrefixListId": "pl-drop", "GatewayId": "igw-a", "State": "blackhole"})
    snapshot["collections"].append({"type": "managed_prefix_list", "scope": scope, "service": "ec2", "status": "collected", "items": [{
        "id": "pl-drop", "PrefixListId": "pl-drop", "AddressFamily": "IPv4", "State": "create-complete",
        "Version": 1, "EntriesVersion": 1, "Entries": {"collection_status": "collected", "items": [{"Cidr": "10.0.2.0/24"}]}}]})
    assert query(reseal(snapshot))["decision"] == "blocked"
    table["Routes"].append({"DestinationPrefixListId": "pl-other-drop", "GatewayId": "igw-b", "State": "active"})
    collection(snapshot, "managed_prefix_list")["items"].append({
        "id": "pl-other-drop", "PrefixListId": "pl-other-drop", "AddressFamily": "IPv4", "State": "create-complete",
        "Version": 1, "EntriesVersion": 1, "Entries": {"collection_status": "collected", "items": [{"Cidr": "10.0.2.0/24"}]}})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "route_priority_ambiguous" for g in result["unresolved_dependencies"])


def test_aws_overlapping_prefix_lists_with_different_lengths_do_not_prove_a_route():
    snapshot = aws_fixture()
    scope = snapshot["scopes"][0]
    table = collection(snapshot, "route_table")["items"][0]
    table["Routes"] += [
        {"DestinationPrefixListId": "pl-wide", "GatewayId": "igw-a", "State": "active"},
        {"DestinationPrefixListId": "pl-narrow", "GatewayId": "igw-b", "State": "blackhole"},
    ]
    snapshot["collections"].append({"type": "managed_prefix_list", "scope": scope, "service": "ec2", "status": "collected", "items": [
        {"id": name, "PrefixListId": name, "AddressFamily": "IPv4", "State": "create-complete",
         "Version": 1, "EntriesVersion": 1, "Entries": {"collection_status": "collected", "items": [{"Cidr": prefix}]}}
        for name, prefix in (("pl-wide", "10.0.2.0/24"), ("pl-narrow", "10.0.2.0/25"))
    ]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_priority_ambiguous" for g in result["unresolved_dependencies"])
    table["Routes"].append({"DestinationCidrBlock": "10.0.2.10/32", "GatewayId": "igw-c",
        "Origin": "CreateRoute", "State": "blackhole"})
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result
    assert not any(g["code"] == "route_priority_ambiguous" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("kind", ["route_table", "network_acl", "security_group", "subnet"])
@pytest.mark.parametrize("status", ["denied", "partial", "not_collected"])
def test_aws_incomplete_dependency_never_invents_allowance(kind, status):
    snapshot = aws_fixture()
    c = collection(snapshot, kind)
    c["status"] = status
    if status != "partial":
        c["items"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert result["unresolved_dependencies"]


@pytest.mark.parametrize("component,value", [("NatGatewayId", "nat-a"), ("TransitGatewayId", "tgw-a"), ("NetworkInterfaceId", "appliance"), ("GatewayId", "igw-a")])
def test_aws_unsupported_next_hops_are_unknown(component, value):
    snapshot = aws_fixture()
    table = collection(snapshot, "route_table")["items"][0]
    table["Routes"].append({"DestinationCidrBlock": "10.0.2.10/32", component: value, "State": "active"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert result["translations"][0]["component"] == component


def test_aws_unknown_translation_cannot_prove_downstream_cidr_deny():
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"][0]["Routes"].append({"DestinationCidrBlock": "10.0.2.10/32", "NatGatewayId": "nat-a", "State": "active"})
    collection(snapshot, "security_group")["items"][1]["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "192.168.0.0/16"}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "blocked_candidate_not_proven" for g in result["unresolved_dependencies"])


def test_aws_unknown_appliance_port_translation_cannot_prove_downstream_sg_deny():
    snapshot = aws_fixture()
    ingress = collection(snapshot, "security_group")["items"][1]["IpPermissions"][0]
    ingress.update(FromPort=8443, ToPort=8443)
    assert query(reseal(snapshot))["decision"] == "blocked"
    collection(snapshot, "route_table")["items"][0]["Routes"].append({
        "DestinationCidrBlock": "10.0.2.10/32", "NetworkInterfaceId": "eni-appliance", "State": "active"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "blocked_candidate_not_proven" for g in result["unresolved_dependencies"])


def test_aws_empty_destination_sg_still_blocks_after_unknown_appliance_translation():
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"][0]["Routes"].append({
        "DestinationCidrBlock": "10.0.2.10/32", "NetworkInterfaceId": "eni-appliance", "State": "active"})
    collection(snapshot, "security_group")["items"][1]["IpPermissions"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result
    assert any(step.get("control") == "aws.security_group" and step["decision"] == "blocked" and
        step.get("address_translation_invariant") is True for step in result["policy_decisions"])


def test_aws_return_ingress_nacl_deny_needs_proven_return_route():
    snapshot = aws_fixture()
    tables = collection(snapshot, "route_table")["items"]
    tables.append({"id": "rt-return", "RouteTableId": "rt-return", "VpcId": "vpc-a",
        "Associations": [{"SubnetId": "subnet-2"}],
        "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"},
            {"DestinationCidrBlock": "10.0.1.10/32", "NetworkInterfaceId": "eni-appliance", "State": "active"}]})
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"].insert(0, {"Egress": False, "RuleNumber": 10, "Protocol": "6",
        "PortRange": {"From": 54321, "To": 54321}, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(step.get("control") == "aws.network_acl" and step.get("flow") == "return" and
        step.get("direction") == "ingress" and step["decision"] == "blocked" for step in result["policy_decisions"])
    assert any(g["code"] == "blocked_candidate_not_proven" for g in result["unresolved_dependencies"])


def test_aws_return_egress_nacl_deny_precedes_unknown_return_route():
    snapshot = aws_fixture()
    tables = collection(snapshot, "route_table")["items"]
    tables.append({"id": "rt-return", "RouteTableId": "rt-return", "VpcId": "vpc-a",
        "Associations": [{"SubnetId": "subnet-2"}],
        "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"},
            {"DestinationCidrBlock": "10.0.1.10/32", "NetworkInterfaceId": "eni-appliance", "State": "active"}]})
    acl = collection(snapshot, "network_acl")["items"][1]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 10, "Protocol": "6",
        "PortRange": {"From": 54321, "To": 54321}, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result
    assert any(step.get("control") == "aws.network_acl" and step.get("flow") == "return" and
        step.get("direction") == "egress" and step["decision"] == "blocked" for step in result["policy_decisions"])


def test_aws_explicit_source_block_is_decisive_with_route_gap():
    snapshot = aws_fixture()
    collection(snapshot, "security_group")["items"][0]["IpPermissionsEgress"] = []
    collection(snapshot, "route_table")["status"] = "denied"
    collection(snapshot, "route_table")["items"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert result["unresolved_dependencies"]


def test_azure_ordered_deny_and_default_stateful_rules():
    snapshot = azure_fixture()
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    deny = copy.deepcopy(rules[0])
    deny["properties"].update(priority=100, access="Deny")
    rules.append(deny)
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert any(p.get("control") == "azure.nsg" and p["decision"] == "blocked" for p in result["policy_decisions"])
    collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"] = []
    result = query(reseal(snapshot), source_port=None)
    assert result["decision"] == "allowed", result
    assert any(p.get("derived_default") for p in result["policy_decisions"])


def test_azure_nic_and_subnet_policy_intersection():
    snapshot = azure_fixture()
    subnet = collection(snapshot, "subnet")["items"][1]
    denied_nsg = copy.deepcopy(collection(snapshot, "nsg")["items"][0])
    denied_nsg["id"] += "-deny"
    denied_nsg["properties"]["securityRules"][1]["properties"]["access"] = "Deny"
    collection(snapshot, "nsg")["items"].append(denied_nsg)
    subnet["properties"]["networkSecurityGroup"] = {"id": denied_nsg["id"]}
    assert query(reseal(snapshot))["decision"] == "blocked"


@pytest.mark.parametrize("protocol", ["any", "all", "6", "tcp"])
def test_azure_unsupported_nsg_protocol_cannot_prove_allow(protocol):
    snapshot = azure_fixture()
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    rules[0]["properties"]["protocol"] = protocol
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nsg_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("alias", ["Any", "any"])
def test_azure_nsg_port_alias_is_not_native_wildcard(alias):
    snapshot = azure_fixture()
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    rules[0]["properties"]["destinationPortRange"] = alias
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nsg_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("alias", ["Any", "any"])
def test_azure_nsg_address_alias_is_not_native_wildcard(alias):
    snapshot = azure_fixture()
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    rules[0]["properties"]["sourceAddressPrefix"] = alias
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nsg_selector_unresolved" for g in result["unresolved_dependencies"])


def test_azure_valid_unrelated_nsg_protocol_does_not_hide_tcp_allow():
    snapshot = azure_fixture()
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    other = copy.deepcopy(rules[0])
    other["properties"].update(priority=100, protocol="Esp", access="Deny")
    rules.append(other)
    assert query(reseal(snapshot))["decision"] == "allowed"


@pytest.mark.parametrize("component,state,code", [
    ("nsg", "Updating", "nsg_not_ready"),
    ("nsg", None, "nsg_not_ready"),
    ("rule", "Failed", "nsg_rule_not_ready"),
    ("rule", None, "nsg_rule_not_ready"),
])
def test_azure_unprovisioned_nsg_cannot_prove_allow(component, state, code):
    snapshot = azure_fixture()
    props = collection(snapshot, "nsg")["items"][0]["properties"]
    if component == "nsg":
        props["provisioningState"] = state
    else:
        props["securityRules"][0]["properties"]["provisioningState"] = state
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == code for g in result["unresolved_dependencies"])


def test_azure_nsg_without_full_detail_cannot_prove_allow():
    snapshot = azure_fixture()
    collection(snapshot, "nsg")["items"][0]["_provenance"]["representation"] = "list"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nsg_detail_missing" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("kind,field,code", [
    ("nic", "_provenance", "endpoint_detail_missing"),
    ("subnet", "_provenance", "endpoint_detail_missing"),
    ("vnet", "_provenance", "endpoint_detail_missing"),
    ("nic", "provisioningState", "endpoint_not_ready"),
    ("subnet", "provisioningState", "endpoint_not_ready"),
    ("vnet", "provisioningState", "endpoint_not_ready"),
])
def test_azure_endpoint_needs_ready_full_nic_and_subnet(kind, field, code):
    snapshot = azure_fixture()
    resource = collection(snapshot, kind)["items"][0]
    if field == "_provenance":
        resource[field]["representation"] = "list"
    else:
        resource["properties"][field] = "Updating"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == code for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("field,value", [("securityRules", [None]), ("securityRules", [{"properties": None}]),
    ("defaultSecurityRules", "invalid"), ("defaultSecurityRules", [None])])
def test_azure_malformed_nsg_rule_collection_is_unknown(field, value):
    snapshot = azure_fixture()
    collection(snapshot, "nsg")["items"][0]["properties"][field] = value
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nsg_rule_malformed" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("association", ["invalid", {}, {"id": ""}])
def test_azure_malformed_nsg_association_is_unknown(association):
    snapshot = azure_fixture()
    collection(snapshot, "nic")["items"][0]["properties"]["networkSecurityGroup"] = association
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nsg_association_malformed" for g in result["unresolved_dependencies"])


def test_azure_malformed_plural_address_selector_cannot_match_as_characters():
    snapshot = azure_fixture()
    inbound = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"][1]["properties"]
    inbound.pop("sourceAddressPrefix")
    inbound["sourceAddressPrefixes"] = "*"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "nsg_selector_unresolved" for g in result["unresolved_dependencies"])


def test_azure_malformed_plural_port_selector_cannot_hide_earlier_deny():
    snapshot = azure_fixture()
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    earlier = copy.deepcopy(rules[1])
    earlier["properties"].update(priority=100, access="Deny")
    earlier["properties"].pop("destinationPortRange")
    earlier["properties"]["destinationPortRanges"] = "443"
    rules.insert(0, earlier)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "nsg_selector_unresolved" for g in result["unresolved_dependencies"])


def test_azure_unknown_nsg_direction_cannot_disappear_before_priority_order():
    snapshot = azure_fixture()
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    uncertain = copy.deepcopy(rules[1])
    uncertain["properties"].update(priority=100, direction="InBound", access="Deny")
    rules.insert(0, uncertain)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "nsg_direction_unknown" for g in result["unresolved_dependencies"])
    uncertain["properties"]["priority"] = 300
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_azure_vm_nic_attachment_must_not_contradict_reverse_native_reference():
    snapshot = azure_fixture()
    scope = snapshot["scopes"][0]
    vm_id = scope + "/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/client"
    nic = collection(snapshot, "nic")["items"][0]
    nic["properties"]["virtualMachine"] = {"id": vm_id}
    vm = collection(snapshot, "vm")["items"][0]
    vm["id"] = vm_id
    def assess():
        sealed = reseal(snapshot)
        return evaluate_reachability(sealed, native(sealed, "vm", vm_id), native(sealed, "nic", "destination"), "tcp", 443, 54321)
    assert assess()["decision"] == "allowed"
    nic["properties"]["virtualMachine"] = {"id": vm_id + "-other"}
    result = assess()
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_association_mismatch" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("change, gap", [
    ("vm_summary", "endpoint_detail_missing"),
    ("vm_not_ready", "endpoint_not_ready"),
    ("vm_collection_partial", "endpoint_association_incomplete"),
    ("nic_missing_reverse", "endpoint_association_mismatch"),
])
def test_azure_vm_endpoint_needs_full_ready_mutual_nic_attachment(change, gap):
    snapshot = azure_fixture()
    scope = snapshot["scopes"][0]
    vm_id = scope + "/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/client"
    nic = collection(snapshot, "nic")["items"][0]
    nic["properties"]["virtualMachine"] = {"id": vm_id}
    vm = collection(snapshot, "vm")["items"][0]
    vm["id"] = vm_id
    if change == "vm_summary":
        vm.pop("_provenance")
    elif change == "vm_not_ready":
        vm["properties"]["provisioningState"] = "Updating"
    elif change == "vm_collection_partial":
        collection(snapshot, "vm")["status"] = "partial"
    else:
        nic["properties"].pop("virtualMachine")
    sealed = reseal(snapshot)
    result = evaluate_reachability(sealed, native(sealed, "vm", vm_id), native(sealed, "nic", "destination"), "tcp", 443, 54321)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == gap for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("mutation, gap", [
    ("nic_unattached", "endpoint_vm_attachment_missing"),
    ("vm_deallocated", "endpoint_power_state_unproven"),
    ("instance_view_missing", "endpoint_power_state_unproven"),
    ("vm_reverse_nic_missing", "endpoint_association_mismatch"),
    ("vm_inventory_partial", "endpoint_association_incomplete"),
])
def test_azure_nic_needs_attached_running_vm(mutation, gap):
    snapshot = azure_fixture()
    nic = collection(snapshot, "nic")["items"][0]
    vm = collection(snapshot, "vm")["items"][0]
    if mutation == "nic_unattached":
        nic["properties"].pop("virtualMachine")
    elif mutation == "vm_deallocated":
        vm["properties"]["instanceView"]["statuses"][0]["code"] = "PowerState/deallocated"
    elif mutation == "instance_view_missing":
        vm["properties"].pop("instanceView")
    elif mutation == "vm_reverse_nic_missing":
        vm["properties"]["networkProfile"]["networkInterfaces"] = []
    else:
        collection(snapshot, "vm")["status"] = "partial"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == gap for g in result["unresolved_dependencies"])


def test_azure_duplicate_ip_configuration_cannot_claim_one_endpoint():
    snapshot = azure_fixture()
    configs = collection(snapshot, "nic")["items"][0]["properties"]["ipConfigurations"]
    configs.append(copy.deepcopy(configs[0]))
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_ip_configuration_ambiguous" for g in result["unresolved_dependencies"])


def test_azure_ipv6_ip_configuration_matches_normalized_address():
    snapshot = azure_fixture()
    source = collection(snapshot, "nic")["items"][0]
    source["properties"]["ipConfigurations"][1]["properties"]["privateIPAddress"] = "FD00:0:0:1::10"
    assert query(reseal(snapshot), family="ipv6")["decision"] == "allowed"


def test_azure_nsg_asg_membership_is_bound_to_selected_ip_configuration_and_vnet():
    snapshot = azure_fixture()
    scope = snapshot["scopes"][0]
    source_asg = scope + "/resourceGroups/r/providers/Microsoft.Network/applicationSecurityGroups/client"
    destination_asg = scope + "/resourceGroups/r/providers/Microsoft.Network/applicationSecurityGroups/server"
    nics = collection(snapshot, "nic")["items"]
    nics[0]["properties"]["ipConfigurations"][0]["properties"]["applicationSecurityGroups"] = [{"id": source_asg}]
    nics[1]["properties"]["ipConfigurations"][0]["properties"]["applicationSecurityGroups"] = [{"id": destination_asg}]
    def rule(direction, priority, access, use_asg):
        props = {"provisioningState": "Succeeded", "direction": direction, "priority": priority, "access": access, "protocol": "Tcp",
            "sourcePortRange": "*", "destinationPortRange": "443"}
        if use_asg:
            props.update(sourceApplicationSecurityGroups=[{"id": source_asg}],
                destinationApplicationSecurityGroups=[{"id": destination_asg}])
        else:
            props.update(sourceAddressPrefix="*", destinationAddressPrefix="*")
        return {"name": f"{access.lower()}-{direction.lower()}-{priority}", "properties": props}
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    rules[:] = [rule(direction, priority, access, use_asg) for direction in ("Outbound", "Inbound")
        for priority, access, use_asg in ((200, "Allow", True), (300, "Deny", False))]
    assert query(reseal(snapshot))["decision"] == "allowed"
    nics[1]["properties"]["ipConfigurations"][0]["properties"]["applicationSecurityGroups"] = []
    assert query(reseal(snapshot))["decision"] == "blocked"
    nics[1]["properties"]["ipConfigurations"][0]["properties"]["applicationSecurityGroups"] = [{"id": destination_asg}]
    nics[1]["properties"]["ipConfigurations"][0]["properties"]["applicationSecurityGroups"] = [{"name": "server"}]
    assert query(reseal(snapshot))["decision"] == "unknown"
    nics[1]["properties"]["ipConfigurations"][0]["properties"]["applicationSecurityGroups"] = [{"id": destination_asg}]
    rules[0]["properties"]["sourceAddressPrefix"] = "*"
    assert query(reseal(snapshot))["decision"] == "unknown"
    rules[0]["properties"].pop("sourceAddressPrefix")
    remote = azure_peered_fixture()
    collection(remote, "nic")["items"][0]["properties"]["ipConfigurations"][0]["properties"]["applicationSecurityGroups"] = [{"id": source_asg}]
    collection(remote, "nic")["items"][1]["properties"]["ipConfigurations"][0]["properties"]["applicationSecurityGroups"] = [{"id": destination_asg}]
    collection(remote, "nsg")["items"][0]["properties"]["securityRules"] = copy.deepcopy(rules)
    assert query(reseal(remote))["decision"] == "blocked"


def azure_peered_fixture():
    snapshot = azure_fixture()
    vnet = collection(snapshot, "vnet")["items"][0]
    remote = copy.deepcopy(vnet)
    remote["id"] += "-remote"
    remote["properties"]["addressSpace"]["addressPrefixes"] = ["10.1.0.0/16", "fd01::/48"]
    collection(snapshot, "vnet")["items"].append(remote)
    collection(snapshot, "security_admin_rule")["source_evidence"].append({
        "source_operation": "listNetworkManagerEffectiveSecurityAdminRules", "resource_id": remote["id"],
        "response_sha256": "b" * 64})
    subnet = collection(snapshot, "subnet")["items"][1]
    old_id = subnet["id"]
    subnet["id"] = subnet["id"].replace(vnet["id"], remote["id"])
    subnet["properties"]["addressPrefixes"] = ["10.1.2.0/24", "fd01:0:0:2::/64"]
    destination = collection(snapshot, "nic")["items"][1]
    for config in destination["properties"]["ipConfigurations"]:
        props = config["properties"]
        props["subnet"]["id"] = subnet["id"]
        props["privateIPAddress"] = "10.1.2.10" if config["name"] == "ipv4" else "fd01:0:0:2::10"
    c = collection(snapshot, "vnet_peering")
    c.update(status="collected", items=[{"id": a["id"] + "/virtualNetworkPeerings/peer", "_provenance": {"representation": "full"}, "properties": {
        "remoteVirtualNetwork": {"id": b["id"]}, "remoteAddressSpace": copy.deepcopy(b["properties"]["addressSpace"]),
        "provisioningState": "Succeeded", "peeringState": "Connected", "peeringSyncLevel": "FullyInSync", "allowVirtualNetworkAccess": True}}
        for a, b in ((vnet, remote), (remote, vnet))])
    return reseal(snapshot)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_azure_peered_path_requires_connected_synchronized_space(family):
    snapshot = azure_peered_fixture()
    assert query(snapshot, family=family)["decision"] == "allowed"
    collection(snapshot, "vnet_peering")["items"][0]["properties"]["peeringSyncLevel"] = "RemoteNotInSync"
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"
    collection(snapshot, "vnet_peering")["items"][0]["properties"].pop("peeringSyncLevel")
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"


@pytest.mark.parametrize("field,code", [
    ("_provenance", "peering_detail_missing"),
    ("provisioningState", "peering_not_ready"),
])
def test_azure_peering_needs_ready_full_detail(field, code):
    snapshot = azure_peered_fixture()
    peering = collection(snapshot, "vnet_peering")["items"][0]
    if field == "_provenance":
        peering[field]["representation"] = "list"
    else:
        peering["properties"][field] = "Updating"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == code for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_azure_subnet_peering_route_does_not_prove_all_subnets(family):
    snapshot = azure_peered_fixture()
    peerings = collection(snapshot, "vnet_peering")["items"]
    peering = peerings[0]["properties"]
    peering["peerCompleteVnets"] = False
    peering["localSubnetNames"] = ["s1"]
    peering["remoteSubnetNames"] = ["other-subnet"]
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "unknown"
    assert any(g["code"] == "subnet_peering_unmodeled" for g in result["unresolved_dependencies"])
    peering["remoteSubnetNames"] = ["s2"]
    reciprocal = peerings[1]["properties"]
    reciprocal.update(peerCompleteVnets=False, localSubnetNames=["s2"], remoteSubnetNames=["s1"])
    assert query(reseal(snapshot), family=family)["decision"] == "allowed"
    reciprocal["localSubnetNames"] = []
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"


def test_azure_ipv6_only_peering_does_not_prove_ipv4():
    snapshot = azure_peered_fixture()
    collection(snapshot, "vnet_peering")["items"][0]["properties"]["enableOnlyIPv6Peering"] = True
    result = query(reseal(snapshot), family="ipv4")
    assert result["decision"] == "unknown"
    assert any(g["code"] == "peering_address_family_unavailable" for g in result["unresolved_dependencies"])
    assert query(reseal(snapshot), family="ipv6")["decision"] == "allowed"


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_azure_virtualnetwork_default_nsg_rule_includes_synchronized_peer(family):
    snapshot = azure_peered_fixture()
    collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"] = []
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "allowed", result
    nsg_decisions = [p for p in result["policy_decisions"] if p.get("control") == "azure.nsg" and p.get("derived_default")]
    assert len(nsg_decisions) == 2 and all(p["decision"] == "allowed" for p in nsg_decisions)
    peerings = collection(snapshot, "vnet_peering")["items"]
    peerings[0]["properties"]["allowVirtualNetworkAccess"] = False
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"
    peerings[0]["properties"]["allowVirtualNetworkAccess"] = True
    peerings[0]["properties"]["remoteAddressSpace"]["addressPrefixes"] = ["172.16.0.0/16"]
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"
    peerings[0]["properties"]["remoteAddressSpace"]["addressPrefixes"] = ["10.1.0.0/16", "fd01::/48"]
    peerings[0]["properties"].pop("peeringSyncLevel")
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "unknown"
    assert any(g["code"] == "nsg_selector_unresolved" for g in result["unresolved_dependencies"])
    peerings[0]["properties"]["peeringSyncLevel"] = "FullyInSync"
    peerings[0]["properties"]["peerCompleteVnets"] = False
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "unknown"
    assert any(g["code"] == "nsg_selector_unresolved" for g in result["unresolved_dependencies"])
    peerings[0]["properties"].update(localSubnetNames=["s1"], remoteSubnetNames=["s2"])
    peerings[1]["properties"].update(peerCompleteVnets=False, localSubnetNames=["s2"], remoteSubnetNames=["s1"])
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "allowed"
    assert all(p["decision"] == "allowed" for p in result["policy_decisions"] if p.get("control") == "azure.nsg")


def test_azure_effective_peering_route_requires_explicit_sync_level():
    snapshot = azure_peered_fixture()
    nics = collection(snapshot, "nic")["items"]
    scope = collection(snapshot, "nic")["scope"]
    routes = [{"id": nic["id"] + "/effectiveRoutes/peer", "nic_id": nic["id"],
        "_provenance": azure_effective_provenance(nic["id"]), "route": {
        "name": "peer", "source": "Default", "state": "Active", "addressPrefix": [prefix], "nextHopType": "VnetPeering"}}
        for nic, prefix in zip(nics, ["10.1.0.0/16", "10.0.0.0/16"])]
    snapshot["collections"].append({"type": "effective_route", "scope": scope, "service": "Microsoft.Network",
        "status": "collected", "items": routes, "source_evidence": [
            {"source_operation": "effectiveRouteTable", "resource_id": nic["id"], "response_sha256": "a" * 64}
            for nic in nics]})
    assert query(reseal(snapshot))["decision"] == "allowed"
    collection(snapshot, "vnet_peering")["items"][0]["properties"].pop("peeringSyncLevel")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "peering_context_missing" for g in result["unresolved_dependencies"])
    peering = collection(snapshot, "vnet_peering")["items"][0]["properties"]
    peering["peeringSyncLevel"] = "FullyInSync"
    peering["peerCompleteVnets"] = False
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "subnet_peering_unmodeled" for g in result["unresolved_dependencies"])
    peering.update(localSubnetNames=["s1"], remoteSubnetNames=["s2"])
    collection(snapshot, "vnet_peering")["items"][1]["properties"].update(
        peerCompleteVnets=False, localSubnetNames=["s2"], remoteSubnetNames=["s1"])
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_azure_effective_peering_route_needs_matching_remote_address_space():
    snapshot = azure_peered_fixture()
    nics = collection(snapshot, "nic")["items"]
    scope = collection(snapshot, "nic")["scope"]
    snapshot["collections"].append({"type": "effective_route", "scope": scope, "service": "Microsoft.Network",
        "status": "collected", "items": [{"id": nic["id"] + "/effectiveRoutes/peer", "nic_id": nic["id"],
            "_provenance": azure_effective_provenance(nic["id"]), "route": {
            "source": "Default", "state": "Active", "addressPrefix": [prefix], "nextHopType": "VnetPeering"}}
            for nic, prefix in zip(nics, ["10.1.0.0/16", "10.0.0.0/16"])],
        "source_evidence": [{"source_operation": "effectiveRouteTable", "resource_id": nic["id"],
            "response_sha256": "a" * 64} for nic in nics]})
    assert query(reseal(snapshot))["decision"] == "allowed"
    peering = collection(snapshot, "vnet_peering")["items"][0]["properties"]
    peering["remoteAddressSpace"]["addressPrefixes"] = ["172.16.0.0/16"]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "effective_peering_address_space_unproven" for g in result["unresolved_dependencies"])


def test_azure_declared_peering_route_needs_matching_remote_address_space():
    snapshot = azure_peered_fixture()
    assert query(snapshot)["decision"] == "allowed"
    peering = collection(snapshot, "vnet_peering")["items"][0]["properties"]
    peering.pop("remoteAddressSpace")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "peering_address_space_unproven" for g in result["unresolved_dependencies"])


def test_azure_effective_peering_route_conflicting_with_disabled_table_is_unknown():
    snapshot = azure_peered_fixture()
    nics = collection(snapshot, "nic")["items"]
    scope = collection(snapshot, "nic")["scope"]
    routes = [{"id": nic["id"] + "/effectiveRoutes/peer", "nic_id": nic["id"],
        "_provenance": azure_effective_provenance(nic["id"]), "route": {
        "name": "peer", "source": "Default", "state": "Active", "addressPrefix": [prefix], "nextHopType": "VnetPeering"}}
        for nic, prefix in zip(nics, ["10.1.0.0/16", "10.0.0.0/16"])]
    snapshot["collections"].append({"type": "effective_route", "scope": scope, "service": "Microsoft.Network",
        "status": "collected", "items": routes, "source_evidence": [
            {"source_operation": "effectiveRouteTable", "resource_id": nic["id"], "response_sha256": "a" * 64}
            for nic in nics]})
    assert query(reseal(snapshot))["decision"] == "allowed"
    subnet = collection(snapshot, "subnet")["items"][0]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/no-peering"
    subnet["properties"]["routeTable"] = {"id": route_id}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": route_id,
        "_provenance": {"representation": "full", "api_version": "2025-07-01"},
        "properties": {"provisioningState": "Succeeded", "disablePeeringRoute": "All", "routes": []}}])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "effective_peering_route_conflict" for g in result["unresolved_dependencies"])


def test_azure_missing_admin_context_can_override_even_nsg_deny():
    snapshot = azure_fixture()
    snapshot["metadata"]["network_context"]["azure"].pop("security_admin")
    collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"][0]["properties"]["access"] = "Deny"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "azure_security_admin_context_missing" for g in result["unresolved_dependencies"])


def test_azure_empty_admin_assertion_requires_selected_vnet_query_proof():
    snapshot = azure_fixture()
    collection(snapshot, "security_admin_rule")["source_evidence"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "azure_security_admin_context_missing" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("digest", ["", "invalid", "g" * 64])
def test_azure_admin_empty_assertion_rejects_invalid_response_digest(digest):
    snapshot = azure_fixture()
    collection(snapshot, "security_admin_rule")["source_evidence"][0]["response_sha256"] = digest
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "azure_security_admin_context_missing" for g in result["unresolved_dependencies"])


def test_azure_peered_admin_absence_requires_both_vnet_queries():
    snapshot = azure_peered_fixture()
    collection(snapshot, "security_admin_rule")["source_evidence"].pop()
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "azure_security_admin_context_missing" for g in result["unresolved_dependencies"])


def test_azure_native_effective_routes_decide_without_synthetic_bgp_context():
    snapshot = azure_effective_fixture()
    result = query(snapshot)
    assert result["decision"] == "allowed", result
    assert len(result["routes"]) == 2
    assert all(r["decision"] == "allowed" and r["source"] == "Default" for r in result["routes"])


def test_azure_effective_routes_without_active_match_cannot_prove_drop():
    snapshot = azure_effective_fixture()
    source_nic = next(n["id"] for n in collection(snapshot, "nic")["items"] if n["name"] == "source")
    for row in collection(snapshot, "effective_route")["items"]:
        if row["nic_id"] == source_nic:
            row["route"]["state"] = "Invalid"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "effective_route_selection_unresolved" for g in result["unresolved_dependencies"])


def test_azure_effective_route_cannot_join_address_outside_native_vnet():
    snapshot = azure_effective_fixture()
    collection(snapshot, "vnet")["items"][0]["properties"]["addressSpace"]["addressPrefixes"] = ["172.16.0.0/16"]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_outside_vnet" for g in result["unresolved_dependencies"])


def test_azure_effective_user_drop_and_appliance_path():
    snapshot = azure_effective_fixture()
    effective = collection(snapshot, "effective_route")["items"]
    source_nic = next(n["id"] for n in collection(snapshot, "nic")["items"] if n["name"] == "source")
    effective.append({"id": source_nic + "/effectiveRoutes/1", "nic_id": source_nic,
        "_provenance": azure_effective_provenance(source_nic),
        "route": {"name": "drop", "source": "User", "state": "Active", "addressPrefix": ["10.0.2.0/24"], "nextHopType": "None"}})
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert any(r["decision"] == "blocked" and r.get("direction") == "forward" for r in result["routes"])
    effective[-1]["route"]["nextHopType"] = "VirtualAppliance"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "unsupported_route_component" for g in result["unresolved_dependencies"])


def test_azure_effective_user_route_cannot_claim_system_peering_hop():
    snapshot = azure_peered_fixture()
    nics = collection(snapshot, "nic")["items"]
    snapshot["collections"].append({"type": "effective_route", "scope": collection(snapshot, "nic")["scope"],
        "service": "Microsoft.Network", "status": "collected", "items": [
            {"id": nic["id"] + "/effectiveRoutes/peer", "nic_id": nic["id"],
                "_provenance": azure_effective_provenance(nic["id"]), "route": {
                "name": "peer", "source": "User" if nic["name"] == "source" else "Default", "state": "Active",
                "addressPrefix": ["10.1.0.0/16" if nic["name"] == "source" else "10.0.0.0/16"],
                "nextHopType": "VnetPeering"}} for nic in nics],
        "source_evidence": [{"source_operation": "effectiveRouteTable", "resource_id": nic["id"],
            "response_sha256": "a" * 64} for nic in nics]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "effective_route_next_hop_invalid" for g in result["unresolved_dependencies"])


def test_azure_service_endpoint_route_cannot_be_overridden_by_user_drop():
    snapshot = azure_effective_fixture()
    effective = collection(snapshot, "effective_route")["items"]
    source_nic = next(n["id"] for n in collection(snapshot, "nic")["items"] if n["name"] == "source")
    effective.extend([
        {"id": source_nic + "/effectiveRoutes/service", "nic_id": source_nic,
            "_provenance": azure_effective_provenance(source_nic),
            "route": {"name": "service", "source": "Default", "state": "Active",
                "addressPrefix": ["10.0.2.0/24"], "nextHopType": "VirtualNetworkServiceEndpoint"}},
        {"id": source_nic + "/effectiveRoutes/drop", "nic_id": source_nic,
            "_provenance": azure_effective_provenance(source_nic),
            "route": {"name": "drop", "source": "User", "state": "Active",
                "addressPrefix": ["10.0.2.0/24"], "nextHopType": "None"}},
    ])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(t["component"] == "VirtualNetworkServiceEndpoint" for t in result["translations"])


def test_azure_effective_local_route_precedes_more_specific_bgp_route():
    snapshot = azure_effective_fixture()
    effective = collection(snapshot, "effective_route")["items"]
    source_nic = next(n["id"] for n in collection(snapshot, "nic")["items"] if n["name"] == "source")
    effective.append({"id": source_nic + "/effectiveRoutes/1", "nic_id": source_nic,
        "_provenance": azure_effective_provenance(source_nic),
        "route": {"name": "learned", "source": "VirtualNetworkGateway", "state": "Active",
            "addressPrefix": ["10.0.2.0/24"], "nextHopType": "VirtualNetworkGateway"}})
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_azure_incomplete_effective_routes_do_not_fall_back_to_declared_udr():
    snapshot = azure_effective_fixture()
    effective = collection(snapshot, "effective_route")
    effective["status"] = "partial"
    effective["error"] = {"code": "network_query_incomplete"}
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "effective_route_inventory_incomplete" for g in result["unresolved_dependencies"])


def test_azure_effective_routes_without_native_query_proof_are_unknown():
    snapshot = azure_effective_fixture()
    collection(snapshot, "effective_route").pop("source_evidence")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "effective_route_proof_missing" for g in result["unresolved_dependencies"])


def test_azure_effective_route_rejects_invalid_response_digest():
    snapshot = azure_effective_fixture()
    collection(snapshot, "effective_route")["source_evidence"][0]["response_sha256"] = "invalid"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "effective_route_proof_missing" for g in result["unresolved_dependencies"])


def test_azure_effective_route_rejects_a_mixed_valid_and_invalid_nic_page():
    snapshot = azure_effective_fixture()
    proofs = collection(snapshot, "effective_route")["source_evidence"]
    proofs.append({"source_operation": "effectiveRouteTable", "resource_id": proofs[0]["resource_id"],
        "response_sha256": "invalid"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "effective_route_proof_missing" for g in result["unresolved_dependencies"])


def test_azure_effective_route_rejects_duplicate_row_identity():
    snapshot = azure_effective_fixture()
    rows = collection(snapshot, "effective_route")["items"]
    rows.append(copy.deepcopy(rows[0]))
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "effective_route_identity_ambiguous" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("mutation,code", [
    ("missing_row_provenance", "effective_route_row_proof_missing"),
    ("wrong_row_owner", "effective_route_row_proof_missing"),
    ("anonymous_row", "effective_route_identity_ambiguous"),
])
def test_azure_effective_route_rows_must_join_the_native_nic_query(mutation, code):
    snapshot = azure_effective_fixture()
    rows = collection(snapshot, "effective_route")["items"]
    if mutation == "missing_row_provenance":
        rows[0].pop("_provenance")
    elif mutation == "wrong_row_owner":
        rows[0]["_provenance"]["nic_id"] = "/subscriptions/a/other-nic"
    else:
        rows.append({"id": "/subscriptions/a/unknown/effectiveRoutes/0", "route": {
            "state": "Active", "source": "User", "addressPrefix": ["10.0.2.0/24"], "nextHopType": "None"}})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == code for g in result["unresolved_dependencies"])


def test_azure_observed_admin_rule_conflicts_with_empty_policy_proof():
    snapshot = azure_fixture()
    collection(snapshot, "security_admin_rule").update(status="collected", items=[{
        "id": "/subscriptions/a/providers/Microsoft.Network/networkManagers/m/securityAdminConfigurations/c/ruleCollections/r/rules/deny",
        "properties": {"access": "Deny"}}])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "azure_security_admin_inventory_conflict" for g in result["unresolved_dependencies"])


def test_azure_complete_allow_only_admin_rules_preserve_nsg_decision():
    snapshot = azure_fixture()
    vnet_id = collection(snapshot, "vnet")["items"][0]["id"]
    rule_id = vnet_id + "/effectiveSecurityAdminRules/allow"
    admin = {"type": "security_admin_rule", "scope": "/subscriptions/a", "service": "network",
        "status": "collected", "items": [{"id": rule_id, "vnet_id": vnet_id,
            "rule": {"kind": "Custom", "properties": {"access": "Allow"}}}],
        "source_evidence": [{"source_operation": "listNetworkManagerEffectiveSecurityAdminRules",
            "resource_id": vnet_id, "response_sha256": "a" * 64}]}
    collection(snapshot, "security_admin_rule").update(admin)
    snapshot["metadata"]["network_context"]["azure"]["security_admin"] = proof(policies=[rule_id])
    allowed = query(reseal(snapshot))
    assert allowed["decision"] == "allowed"
    assert any(step.get("control") == "azure.security_admin" and step["evidence_refs"]
        for step in allowed["policy_decisions"])
    collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"][0]["properties"]["access"] = "Deny"
    assert query(reseal(snapshot))["decision"] == "blocked"
    admin["items"][0]["rule"]["properties"]["access"] = "AlwaysAllow"
    assert query(reseal(snapshot))["decision"] == "unknown"
    admin["items"][0]["rule"]["properties"]["access"] = "Deny"
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_azure_allow_only_admin_rules_require_native_vnet_query_proof():
    snapshot = azure_fixture()
    vnet_id = collection(snapshot, "vnet")["items"][0]["id"]
    rule_id = vnet_id + "/effectiveSecurityAdminRules/allow"
    collection(snapshot, "security_admin_rule").update(status="collected", items=[{"id": rule_id, "vnet_id": vnet_id,
        "rule": {"kind": "Custom", "properties": {"access": "Allow"}}}], source_evidence=[])
    snapshot["metadata"]["network_context"]["azure"]["security_admin"] = proof(policies=[rule_id])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "azure_security_admin_context_missing" for g in result["unresolved_dependencies"])


def test_azure_service_tags_and_source_port_unknown_until_resolved():
    snapshot = azure_fixture()
    rule = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"][0]["properties"]
    rule["destinationAddressPrefix"] = "Storage"
    assert query(reseal(snapshot))["decision"] == "unknown"
    rule["destinationAddressPrefix"], rule["sourcePortRange"] = "*", "50000-60000"
    snapshot = reseal(snapshot)
    assert query(snapshot, source_port=None)["decision"] == "unknown"
    assert query(snapshot, source_port=54321)["decision"] == "allowed"


def test_azure_service_tag_membership_uses_selected_subscription_only():
    snapshot = azure_fixture()
    for rule in collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]:
        rule["properties"]["sourceAddressPrefix"] = "Storage.WestEurope"
    snapshot["scopes"].append("/subscriptions/b")
    for scope, prefix in (("/subscriptions/a", "10.0.0.0/16"), ("/subscriptions/b", "172.16.0.0/16")):
        snapshot["collections"].append({"type": "service_tag", "scope": scope, "service": "Microsoft.Network",
            "status": "collected", "items": [{"id": scope + "/providers/Microsoft.Network/serviceTags/Storage.WestEurope",
                "name": "Storage.WestEurope", "properties": {"addressPrefixes": [prefix]}}]})
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_azure_virtualnetwork_tag_inventory_cannot_prove_negative_membership():
    snapshot = azure_peered_fixture()
    collection(snapshot, "vnet_peering")["items"][0]["properties"]["allowVirtualNetworkAccess"] = False
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    rules.insert(0, {"name": "deny-vnet", "properties": {"provisioningState": "Succeeded", "priority": 100,
        "direction": "Outbound", "access": "Deny", "protocol": "Tcp", "sourceAddressPrefix": "*",
        "destinationAddressPrefix": "VirtualNetwork", "sourcePortRange": "*", "destinationPortRange": "443"}})
    scope = collection(snapshot, "nsg")["scope"]
    snapshot["collections"].append({"type": "service_tag", "scope": scope, "service": "Microsoft.Network", "status": "collected",
        "items": [{"id": scope + "/providers/Microsoft.Network/serviceTags/VirtualNetwork", "name": "VirtualNetwork",
            "properties": {"addressPrefixes": []}}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "nsg_selector_unresolved" for g in result["unresolved_dependencies"])


def test_azure_native_empty_plural_fields_preserve_singular_selectors():
    snapshot = azure_fixture()
    for rule in collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]:
        rule["properties"].update(sourceAddressPrefixes=[], destinationAddressPrefixes=[], sourcePortRanges=[], destinationPortRanges=[])
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_azure_invalid_native_priority_does_not_become_a_proven_deny():
    snapshot = azure_fixture()
    p = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"][0]["properties"]
    p.update(priority=50, access="Deny")
    assert query(reseal(snapshot))["decision"] == "unknown"


def mark_azure_route_table_full(snapshot, api_version="2025-07-01"):
    for table in collection(snapshot, "route_table")["items"]:
        table["_provenance"] = {"representation": "full", "api_version": api_version}


@pytest.mark.parametrize("hop,expected", [("None", "blocked"), ("VirtualAppliance", "unknown"), ("Internet", "unknown")])
def test_azure_udr_longest_prefix_and_unsupported_hops(hop, expected):
    snapshot = azure_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = subnet_scope = collection(snapshot, "subnet")["scope"]
    rid = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/rt"
    subnet["properties"]["routeTable"] = {"id": rid}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": rid, "properties": {"provisioningState": "Succeeded", "routes": [{"name": "chosen", "properties": {"provisioningState": "Succeeded", "addressPrefix": "10.0.2.10/32", "nextHopType": hop}}]}}])
    mark_azure_route_table_full(snapshot)
    result = query(reseal(snapshot))
    assert result["decision"] == expected, result


def test_azure_udr_cannot_claim_system_peering_next_hop():
    snapshot = azure_peered_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = collection(snapshot, "subnet")["scope"]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/invalid-peering"
    subnet["properties"]["routeTable"] = {"id": route_id}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": route_id,
        "properties": {"provisioningState": "Succeeded", "disablePeeringRoute": "None", "routes": [{"name": "invalid-peering", "properties": {
            "provisioningState": "Succeeded", "addressPrefix": "10.1.2.0/24", "nextHopType": "VnetPeering"}}]}}])
    mark_azure_route_table_full(snapshot)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_next_hop_invalid" for g in result["unresolved_dependencies"])


def test_azure_udr_vnetlocal_cannot_prove_remote_vnet_path():
    snapshot = azure_peered_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = collection(snapshot, "subnet")["scope"]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/local-only"
    subnet["properties"]["routeTable"] = {"id": route_id}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": route_id,
        "properties": {"provisioningState": "Succeeded", "disablePeeringRoute": "None", "routes": [{"name": "local-only", "properties": {
            "provisioningState": "Succeeded", "addressPrefix": "10.1.2.0/24", "nextHopType": "VnetLocal"}}]}}])
    mark_azure_route_table_full(snapshot)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_domain_mismatch" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("mode,expected,gap", [
    ("None", "allowed", None),
    ("All", "unknown", "route_not_proven"),
    (None, "unknown", "peering_route_setting_unknown"),
    ("invalid", "unknown", "peering_route_setting_unknown"),
    ({"invalid": True}, "unknown", "peering_route_setting_unknown"),
])
def test_azure_route_table_peering_route_setting(mode, expected, gap):
    snapshot = azure_peered_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = collection(snapshot, "subnet")["scope"]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/peering-setting"
    subnet["properties"]["routeTable"] = {"id": route_id}
    props = {"provisioningState": "Succeeded", "routes": []}
    if mode is not None:
        props["disablePeeringRoute"] = mode
    collection(snapshot, "route_table").update(status="collected", items=[{"id": route_id, "properties": props}])
    mark_azure_route_table_full(snapshot)
    result = query(reseal(snapshot))
    assert result["decision"] == expected, result
    if gap:
        assert any(g["code"] == gap for g in result["unresolved_dependencies"])


def test_azure_route_table_peering_disabled_keeps_explicit_drop():
    snapshot = azure_peered_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = collection(snapshot, "subnet")["scope"]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/drop-peering"
    subnet["properties"]["routeTable"] = {"id": route_id}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": route_id,
        "properties": {"provisioningState": "Succeeded", "disablePeeringRoute": "All", "routes": [{"name": "drop", "properties": {
            "provisioningState": "Succeeded", "addressPrefix": "10.1.2.0/24", "nextHopType": "None"}}]}}])
    mark_azure_route_table_full(snapshot)
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result


@pytest.mark.parametrize("provenance,code", [
    (None, "route_table_detail_missing"),
    ({"representation": "list", "api_version": "2025-07-01"}, "route_table_detail_missing"),
    ({"representation": "full", "api_version": "2023-09-01"}, "peering_route_api_version_old"),
])
def test_azure_peering_route_needs_current_full_route_table(provenance, code):
    snapshot = azure_peered_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = collection(snapshot, "subnet")["scope"]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/old"
    subnet["properties"]["routeTable"] = {"id": route_id}
    table = {"id": route_id, "properties": {"provisioningState": "Succeeded",
        "disablePeeringRoute": "None", "routes": []}}
    if provenance is not None:
        table["_provenance"] = provenance
    collection(snapshot, "route_table").update(status="collected", items=[table])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == code for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("state", ["Updating", "Failed", None])
def test_azure_unprovisioned_route_table_cannot_prove_path(state):
    snapshot = azure_peered_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = collection(snapshot, "subnet")["scope"]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/updating"
    subnet["properties"]["routeTable"] = {"id": route_id}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": route_id,
        "properties": {"provisioningState": state, "disablePeeringRoute": "None", "routes": []}}])
    mark_azure_route_table_full(snapshot)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_table_not_ready" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("state", ["Updating", "Failed", None])
def test_azure_unprovisioned_udr_cannot_prove_drop(state):
    snapshot = azure_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = collection(snapshot, "subnet")["scope"]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/not-ready-route"
    subnet["properties"]["routeTable"] = {"id": route_id}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": route_id,
        "properties": {"provisioningState": "Succeeded", "routes": [{"name": "drop", "properties": {
            "provisioningState": state, "addressPrefix": "10.0.2.0/24", "nextHopType": "None"}}]}}])
    mark_azure_route_table_full(snapshot)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_not_ready" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("association", [{}, {"id": ""}, "missing-id"])
def test_azure_malformed_udr_association_cannot_prove_local_route(association):
    snapshot = azure_fixture()
    collection(snapshot, "subnet")["items"][0]["properties"]["routeTable"] = association
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_table_association_malformed" for g in result["unresolved_dependencies"])


def test_azure_same_subnet_udr_drop_still_blocks_selected_flow():
    snapshot = azure_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    destination = collection(snapshot, "nic")["items"][1]
    destination["properties"]["ipConfigurations"][0]["properties"].update(
        privateIPAddress="10.0.1.20", subnet={"id": subnet["id"]})
    scope = collection(snapshot, "subnet")["scope"]
    route_id = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/drop-local"
    subnet["properties"]["routeTable"] = {"id": route_id}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": route_id,
        "properties": {"provisioningState": "Succeeded", "routes": [{"name": "drop-local", "properties": {
            "provisioningState": "Succeeded", "addressPrefix": "10.0.1.0/24", "nextHopType": "None"}}]}}])
    mark_azure_route_table_full(snapshot)
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert any(step["decision"] == "blocked" and step.get("direction") == "forward"
        for step in result["routes"])


def test_gcp_priority_deny_tie_and_hierarchy_gate():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules[1]["priority"] = 100
    assert query(reseal(snapshot))["decision"] == "blocked"
    snapshot["metadata"]["network_context"]["gcp"].pop("firewall_hierarchy")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_firewall_hierarchy_missing" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("status", [None, "TERMINATED", "STOPPING", "PROVISIONING"])
@pytest.mark.parametrize("endpoint", ["source", "destination"])
def test_gcp_vm_needs_running_status_before_network_path_is_allowed(status, endpoint):
    snapshot = gcp_fixture()
    vm = next(item for c in snapshot["collections"] if c["type"] == "instance"
        for item in c["items"] if item["name"] == endpoint)
    if status is None:
        vm.pop("status")
    else:
        vm["status"] = status
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "endpoint_not_running" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("endpoint", ["source", "destination"])
def test_gcp_multi_interface_vm_does_not_infer_a_route_from_its_first_nic(endpoint):
    snapshot = gcp_fixture()
    vm = next(item for c in snapshot["collections"] if c["type"] == "instance"
        for item in c["items"] if item["name"] == endpoint)
    second = copy.deepcopy(vm["networkInterfaces"][0])
    second["name"] = "nic1"
    second["networkIP"] = "10.0.9.20"
    vm["networkInterfaces"].append(second)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "endpoint_interface_ambiguous" for g in result["unresolved_dependencies"])
    assert not result["routes"]


def test_gcp_embedded_interface_ids_select_distinct_native_nics_in_graph_and_evaluator():
    snapshot = gcp_fixture()
    vm = collection(snapshot, "instance", "projects/service")["items"][0]
    network = "projects/host/global/networks/second"
    subnet = "projects/host/regions/us-east1/subnetworks/s3"
    vm["networkInterfaces"].append({"name": "nic1", "network": network,
        "subnetwork": subnet, "networkIP": "10.9.0.10"})
    collection(snapshot, "network", "projects/host")["items"].append({
        "name": "second", "selfLink": network, "peerings": []})
    collection(snapshot, "subnetwork", "projects/host")["items"].append({
        "name": "s3", "selfLink": subnet, "network": network, "ipCidrRange": "10.9.0.0/24", "purpose": "PRIVATE"})
    collection(snapshot, "instance", "projects/host")["items"].append({
        "name": "second-destination", "status": "RUNNING", "tags": {"items": ["server"]},
        "serviceAccounts": [{"email": "server@host.iam.gserviceaccount.com"}],
        "networkInterfaces": [{"name": "nic0", "network": network, "subnetwork": subnet,
            "networkIP": "10.9.0.20"}]})
    collection(snapshot, "firewall", "projects/host")["items"].append({
        "name": "second-allow", "network": network, "direction": "INGRESS", "priority": 100,
        "sourceTags": ["client"], "targetTags": ["server"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    collection(snapshot, "effective_firewall", "projects/host")["items"].append({
        "id": f"{network}/regions/us-east1/effectiveFirewalls", "network": network,
        "region": "us-east1", "firewallPolicys": [],
        "effective_source_operation": "regionNetworkFirewallPolicies.getEffectiveFirewalls",
        "_provenance": {"source_requests": ["region-effective-firewalls"]}})
    snapshot = reseal(snapshot)
    source = next(r for r in resources(snapshot) if r["type"] == "instance" and r["data"].get("name") == "source")
    destination = native(snapshot, "instance", "destination")
    ids = [gcp_interface_resource_id(source, i) for i in (0, 1)]
    graph = build_network(snapshot, resources(snapshot))
    graph_ids = {node["resource_id"] for node in graph["nodes"] if node["type"] == "network_interface"}
    assert set(ids) <= graph_ids
    first = evaluate_reachability(snapshot, ids[0], destination, "tcp", 443, 54321)
    second = evaluate_reachability(snapshot, ids[1], native(snapshot, "instance", "second-destination"), "tcp", 443, 54321)
    scoped_second = evaluate_reachability(network_snapshot(snapshot), ids[1],
        native(snapshot, "instance", "second-destination"), "tcp", 443, 54321)
    wrong_network = evaluate_reachability(snapshot, ids[1], destination, "tcp", 443, 54321)
    same_guest = evaluate_reachability(snapshot, ids[0], ids[1], "tcp", 443, 54321)
    assert first["decision"] == "allowed", first
    assert first["endpoints"]["source"]["resource_id"] == ids[0]
    assert second["decision"] == "allowed", second
    assert second["endpoints"]["source"]["resource_id"] == ids[1]
    assert scoped_second["decision"] == "allowed", scoped_second
    assert scoped_second["endpoints"]["source"]["resource_id"] == ids[1]
    assert wrong_network["decision"] == "unknown", wrong_network
    assert any(g["code"] == "peering_context_missing" for g in wrong_network["unresolved_dependencies"])
    assert same_guest["decision"] == "unknown"
    assert any(g["code"] == "self_traffic_semantics_unproven" for g in same_guest["unresolved_dependencies"])
    assert query(snapshot)["decision"] == "unknown"

    # Overlap between unpeered VPCs is valid. The same VM/IP must still be
    # checked against peers in the selected interface's own VPC on every
    # matrix row, even when an earlier row cached the other interface.
    colliding = copy.deepcopy(snapshot)
    collection(colliding, "instance", "projects/service")["items"][0]["networkInterfaces"][1]["networkIP"] = "10.0.1.10"
    collection(colliding, "subnetwork", "projects/host")["items"][-1]["ipCidrRange"] = "10.0.1.0/24"
    host_instances = collection(colliding, "instance", "projects/host")["items"]
    host_instances[-1]["networkInterfaces"][0]["networkIP"] = "10.0.1.20"
    duplicate = copy.deepcopy(host_instances[-1])
    duplicate["name"] = "second-collision"
    duplicate["networkInterfaces"][0]["networkIP"] = "10.0.1.10"
    host_instances.append(duplicate)
    colliding = reseal(colliding)
    matrix = evaluate_reachability_matrix(colliding,
        [ids[0], ids[1], native(colliding, "instance", "second-destination")], "tcp", 443, 54321)
    second_row = next(row for row in matrix if row["query"]["source_resource_id"] == ids[1] and
        row["query"]["destination_resource_id"] == native(colliding, "instance", "second-destination"))
    assert second_row["decision"] == "unknown", second_row
    assert any(g["code"] == "endpoint_address_collision" for g in second_row["unresolved_dependencies"])


def test_gcp_selected_interface_rejects_duplicate_ip_on_same_vm():
    snapshot = gcp_fixture()
    vm = collection(snapshot, "instance", "projects/service")["items"][0]
    duplicate = copy.deepcopy(vm["networkInterfaces"][0])
    duplicate["name"] = "nic1"
    vm["networkInterfaces"].append(duplicate)
    snapshot = reseal(snapshot)
    source = next(r for r in resources(snapshot) if r["type"] == "instance" and r["data"].get("name") == "source")
    result = evaluate_reachability(snapshot, gcp_interface_resource_id(source, 0),
        native(snapshot, "instance", "destination"), "tcp", 443, 54321)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "endpoint_address_collision" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_gcp_vm_own_primary_address_bypasses_vpc_firewall_and_routes(family):
    snapshot = gcp_fixture()
    source = native(snapshot, "instance", "source")
    collection(snapshot, "firewall", "projects/host")["items"] = [{
        "name": "deny-all", "direction": "EGRESS", "priority": 1,
        "network": collection(snapshot, "network")["items"][0]["selfLink"],
        "denied": [{"IPProtocol": "all"}],
    }]
    snapshot["metadata"]["network_context"]["gcp"].pop("firewall_hierarchy")
    snapshot["metadata"]["network_context"]["gcp"].pop("routing")
    result = evaluate_reachability(reseal(snapshot), source, source, "tcp", 443,
        address_family=family)
    assert result["decision"] == "allowed", result
    assert result["application_listening"] == "unknown"
    assert result["routes"][0]["direction"] == "forward_and_return"
    assert result["policy_decisions"][0]["direction"] == "self"


def test_gcp_unscoped_empty_hierarchy_assertion_cannot_prove_absence():
    snapshot = gcp_fixture()
    context = snapshot["metadata"]["network_context"]["gcp"]["firewall_hierarchy"]
    context.pop("unaffected_projects")
    context.pop("project_ancestors")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "gcp_firewall_hierarchy_missing" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("change,expected", [
    ("missing", "gcp_regional_firewall_inventory_incomplete"),
    ("partial", "gcp_regional_firewall_inventory_incomplete"),
    ("no_request", "gcp_regional_firewall_inventory_incomplete"),
    ("wrong_region", "gcp_regional_firewall_read_missing"),
    ("bad_source", "gcp_regional_firewall_read_malformed"),
    ("request_mismatch", "gcp_regional_firewall_read_malformed"),
    ("system_policy", "gcp_regional_firewall_policy_present"),
])
def test_gcp_regional_system_firewall_cannot_be_hidden_by_empty_project_policy_list(change, expected):
    snapshot = gcp_fixture()
    captured = collection(snapshot, "effective_firewall")
    if change == "missing":
        snapshot["collections"].remove(captured)
    elif change == "partial":
        captured["status"] = "partial"
    elif change == "no_request":
        captured.pop("source_requests")
    elif change == "wrong_region":
        captured["items"][0]["region"] = "us-west1"
    elif change == "bad_source":
        captured["items"][0]["effective_source_operation"] = "unknown"
    elif change == "request_mismatch":
        captured["items"][0]["_provenance"]["source_requests"] = ["a-different-read"]
    else:
        captured["items"][0]["firewallPolicys"] = [{"name": "managed", "type": "SYSTEM_REGIONAL",
            "rules": [{"action": "deny", "direction": "INGRESS"}]}]
    result = query(network_snapshot(reseal(snapshot)))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == expected for g in result["unresolved_dependencies"])
    assert not any(p["decision"] in {"allowed", "blocked"} and p.get("control") == "gcp.firewall"
        for p in result["policy_decisions"])


def test_gcp_observed_firewall_policy_conflicts_with_empty_hierarchy_proof():
    snapshot = gcp_fixture()
    collection(snapshot, "firewall_policy", "projects/host").update(status="collected", items=[
        {"name": "global-policy", "id": "12345", "rules": [{"action": "deny"}]}])
    result = query(network_snapshot(reseal(snapshot)))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_firewall_hierarchy_inventory_conflict" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("scoped", [False, True])
def test_gcp_network_policy_attachment_conflicts_with_empty_hierarchy_proof(scoped):
    snapshot = gcp_fixture()
    collection(snapshot, "network")["items"][0]["firewallPolicy"] = (
        "https://compute.googleapis.com/compute/v1/projects/host/global/firewallPolicies/policy")
    if not scoped:
        context = snapshot["metadata"]["network_context"]["gcp"]["firewall_hierarchy"]
        context.pop("unaffected_projects")
        context.pop("project_ancestors")
    result = query(network_snapshot(reseal(snapshot)))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_network_firewall_policy_attachment_conflict" for g in result["unresolved_dependencies"])


def test_gcp_ancestor_association_conflicts_with_empty_hierarchy_proof():
    snapshot = gcp_fixture()
    collection(snapshot, "firewall_policy_association", "organizations/12").update(status="collected", items=[
        {"name": "attached", "attachmentTarget": "organizations/12", "firewallPolicyId": "567"}])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_firewall_hierarchy_inventory_conflict" for g in result["unresolved_dependencies"])


def test_gcp_scoped_hierarchy_ignores_unassociated_and_unrelated_policies():
    snapshot = gcp_fixture()
    collection(snapshot, "firewall_policy", "projects/host").update(status="collected", items=[
        {"name": "unused", "rules": [{"action": "deny"}], "associations": [],
            "_provenance": {"representation": "full"}}])
    snapshot["collections"].append({"type": "firewall_policy", "scope": "projects/unrelated", "service": "compute",
        "status": "collected", "items": [{"name": "attached-elsewhere", "associations": [{"attachmentTarget": "elsewhere"}]}]})
    assert query(reseal(snapshot))["decision"] == "allowed"
    association = collection(snapshot, "firewall_policy_association", "organizations/12")
    association.update(status="collected", items=[{"name": "active", "attachmentTarget": "organizations/12"}])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"


@pytest.mark.parametrize("kind,scope", [
    ("network_firewall_policy", "projects/host"),
    ("hierarchical_firewall_policy", "organizations/12"),
])
def test_gcp_scoped_hierarchy_rejects_conflicting_imported_policy(kind, scope):
    snapshot = gcp_fixture()
    snapshot["collections"].append({"type": kind, "scope": scope, "service": "compute", "status": "collected",
        "items": [{"name": "imported-active-policy", "rules": [{"action": "deny"}]}]})
    result = query(network_snapshot(reseal(snapshot)))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_firewall_hierarchy_inventory_conflict" for g in result["unresolved_dependencies"])


def test_gcp_observed_policy_route_conflicts_with_empty_route_proof():
    snapshot = gcp_fixture()
    snapshot["collections"].append({"type": "policy_based_route", "scope": "projects/host", "service": "compute",
        "status": "collected", "items": [{"name": "redirect", "priority": 100, "nextHopOtherRoutes": "DEFAULT_ROUTING"}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_policy_route_inventory_conflict" for g in result["unresolved_dependencies"])


def test_gcp_same_subnet_policy_route_prevents_regular_subnet_allowance():
    snapshot = gcp_fixture()
    destination = collection(snapshot, "instance", "projects/host")["items"][0]
    source = collection(snapshot, "instance", "projects/service")["items"][0]
    destination["networkInterfaces"][0].update(
        subnetwork=source["networkInterfaces"][0]["subnetwork"], networkIP="10.0.1.20")
    snapshot["collections"].append({"type": "policy_based_route", "scope": "projects/host", "service": "networkconnectivity",
        "status": "collected", "items": [{"name": "projects/host/locations/global/policyBasedRoutes/redirect",
            "network": "projects/host/global/networks/net", "nextHopIlbIp": "10.0.1.30", "priority": 100}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_policy_route_inventory_conflict" for g in result["unresolved_dependencies"])


def test_gcp_observed_bgp_peer_conflicts_with_empty_dynamic_route_proof():
    snapshot = gcp_fixture()
    snapshot["collections"].append({"type": "router", "scope": "projects/host", "service": "compute",
        "status": "collected", "items": [{"name": "router", "network": "projects/host/global/networks/net",
            "bgpPeers": [{"name": "peer", "peerIpAddress": "169.254.1.2"}]}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_dynamic_route_inventory_conflict" for g in result["unresolved_dependencies"])


def test_gcp_complete_native_route_inventories_can_prove_absence_without_manual_context():
    snapshot = gcp_fixture()
    snapshot["metadata"]["network_context"]["gcp"].pop("routing")
    for kind in ("policy_based_route", "router"):
        snapshot["collections"].append({"type": kind, "scope": "projects/host", "service": "compute",
            "status": "empty", "items": [], **({"source_requests": ["policy-routes-list"]} if kind == "policy_based_route" else {})})
    assert query(reseal(snapshot))["decision"] == "allowed"
    collection(snapshot, "router")["items"] = [{"name": "router", "bgpPeers": [{"name": "peer"}]}]
    collection(snapshot, "router")["status"] = "collected"
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_gcp_peering_subnet_routes_need_native_policy_route_absence_not_empty_bgp():
    snapshot = gcp_peered_fixture()
    snapshot["metadata"]["network_context"]["gcp"].pop("routing")
    for scope in ("projects/host", "projects/other"):
        snapshot["collections"].append({"type": "policy_based_route", "scope": scope, "service": "networkconnectivity",
            "status": "empty", "items": [], "source_requests": [f"policy-routes-list:{scope}"]})
        snapshot["collections"].append({"type": "router", "scope": scope, "service": "compute",
            "status": "collected", "items": [{"name": "router", "bgpPeers": [{"name": "peer"}]}]})
    assert query(reseal(snapshot))["decision"] == "allowed"
    collection(snapshot, "policy_based_route", "projects/other")["items"] = [{"name": "redirect"}]
    collection(snapshot, "policy_based_route", "projects/other")["status"] = "collected"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_policy_route_inventory_conflict" for g in result["unresolved_dependencies"])


def test_gcp_empty_policy_route_collection_needs_native_query_evidence():
    snapshot = gcp_fixture()
    snapshot["metadata"]["network_context"]["gcp"].pop("routing")
    snapshot["collections"].append({"type": "policy_based_route", "scope": "projects/host",
        "service": "networkconnectivity", "status": "empty", "items": []})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "gcp_route_context_missing" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("peered", [False, True])
@pytest.mark.parametrize("endpoint", ["source", "destination"])
def test_gcp_hybrid_subnet_does_not_claim_regular_subnet_route(peered, endpoint):
    snapshot = gcp_peered_fixture() if peered else gcp_fixture()
    subnets = [item for c in snapshot["collections"] if c["type"] == "subnetwork" for item in c["items"]]
    target = next(item for item in subnets if item["name"] == ("s1" if endpoint == "source" else "s2"))
    target["allowSubnetCidrRoutesOverlap"] = True
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "hybrid_subnet_route_unknown" for g in result["unresolved_dependencies"])


def test_gcp_malformed_hybrid_subnet_state_cannot_prove_regular_route():
    snapshot = gcp_fixture()
    collection(snapshot, "subnetwork")["items"][1]["allowSubnetCidrRoutesOverlap"] = "false"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "hybrid_subnet_state_unknown" for g in result["unresolved_dependencies"])


def test_gcp_service_account_selectors_and_shared_global_domain():
    snapshot = gcp_fixture()
    rule = collection(snapshot, "firewall")["items"][0]
    rule.pop("sourceTags")
    rule.pop("targetTags")
    rule.update(sourceServiceAccounts=["client@host.iam.gserviceaccount.com"], targetServiceAccounts=["server@host.iam.gserviceaccount.com"])
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed", result
    assert result["endpoints"]["source"]["scope"] == "projects/service"
    assert result["endpoints"]["destination"]["scope"] == "projects/host"


def test_gcp_sdk_numeric_network_id_does_not_replace_project_qualified_selflink():
    snapshot = gcp_fixture()
    collection(snapshot, "network")["items"][0]["id"] = "1234567890123"
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_gcp_same_project_partial_interface_and_subnet_network_refs_join():
    snapshot = gcp_fixture()
    for instance in collection(snapshot, "instance", "projects/host")["items"]:
        interface = instance["networkInterfaces"][0]
        interface["network"] = "global/networks/net"
        interface["subnetwork"] = "regions/us-east1/subnetworks/s2"
    collection(snapshot, "subnetwork")["items"][1]["network"] = "global/networks/net"
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_gcp_network_subnet_inventory_cannot_contradict_selected_interface():
    snapshot = gcp_fixture()
    network = collection(snapshot, "network")["items"][0]
    subnets = collection(snapshot, "subnetwork")["items"]
    network["subnetworks"] = [subnet["selfLink"] for subnet in subnets]
    assert query(reseal(snapshot))["decision"] == "allowed"
    network["subnetworks"] = [subnets[0]["selfLink"]]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_domain_subnet_membership_mismatch" for g in result["unresolved_dependencies"])


def test_gcp_partial_service_project_network_ref_cannot_join_host_vpc():
    snapshot = gcp_fixture()
    source = collection(snapshot, "instance", "projects/service")["items"][0]
    source["networkInterfaces"][0]["network"] = "global/networks/net"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_domain_missing" for g in result["unresolved_dependencies"])


def test_gcp_service_project_firewall_inventory_cannot_prove_host_vpc_default_deny():
    snapshot = gcp_fixture()
    c = collection(snapshot, "firewall")
    c["scope"] = "projects/service"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "firewall_collection_incomplete" for g in result["unresolved_dependencies"])


def test_gcp_disabled_and_direction_rules_do_not_apply():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules[0]["disabled"] = True
    assert query(reseal(snapshot))["decision"] == "blocked"
    rules[0].pop("disabled")
    rules[1]["direction"] = "EGRESS"
    assert query(reseal(snapshot))["decision"] == "blocked"


@pytest.mark.parametrize("field,value", [("disabled", "true"), ("direction", "SIDEWAYS"), ("network", "unqualified-network")])
def test_gcp_malformed_higher_priority_firewall_rule_keeps_result_unknown(field, value):
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules.insert(0, {"name": "uncertain-deny", "network": rules[0]["network"], "direction": "INGRESS", "priority": 50,
        "sourceRanges": ["10.0.1.0/24"], "denied": [{"IPProtocol": "tcp", "ports": ["443"]}], field: value})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "firewall_selector_unresolved" for g in result["unresolved_dependencies"])


def test_gcp_malformed_rule_on_another_network_cannot_shadow_selected_firewall():
    snapshot = gcp_fixture()
    collection(snapshot, "firewall")["items"].insert(0, {"name": "other-network", "network": "projects/host/global/networks/other",
        "direction": "SIDEWAYS", "disabled": "true", "priority": 50,
        "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_gcp_malformed_firewall_tag_list_cannot_allow_by_character_match():
    snapshot = gcp_fixture()
    rule = collection(snapshot, "firewall")["items"][0]
    rule["targetTags"] = "s"
    collection(snapshot, "instance", "projects/host")["items"][0]["tags"]["items"] = ["s"]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "firewall_selector_unresolved" for g in result["unresolved_dependencies"])


def test_gcp_malformed_firewall_port_list_cannot_hide_higher_priority_deny():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules.insert(0, {"name": "uncertain-deny", "network": rules[0]["network"], "direction": "INGRESS", "priority": 50,
        "sourceRanges": ["10.0.1.0/24"], "denied": [{"IPProtocol": "tcp", "ports": "443"}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "firewall_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("alias", ["*", "Any", "any"])
def test_gcp_firewall_port_alias_is_not_a_native_numeric_port(alias):
    snapshot = gcp_fixture()
    collection(snapshot, "firewall")["items"][0]["allowed"][0]["ports"] = [alias]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "firewall_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("protocol", ["icmp", "all"])
def test_gcp_firewall_ports_on_non_port_protocol_cannot_hide_priority(protocol):
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules.insert(0, {"name": "uncertain-deny", "network": rules[0]["network"], "direction": "INGRESS", "priority": 50,
        "sourceRanges": ["10.0.1.0/24"], "denied": [{"IPProtocol": protocol, "ports": ["80"]}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "firewall_selector_unresolved" for g in result["unresolved_dependencies"])


def test_gcp_valid_unrelated_numeric_protocol_does_not_shadow_tcp_allow():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules.insert(0, {"name": "other-protocol", "network": rules[0]["network"], "direction": "INGRESS", "priority": 50,
        "sourceRanges": ["10.0.1.0/24"], "denied": [{"IPProtocol": "80"}]})
    assert query(reseal(snapshot))["decision"] == "allowed"


@pytest.mark.parametrize("protocol", ["any", "*", "-1", "TCP"])
def test_gcp_invalid_generic_protocol_cannot_allow_over_lower_deny(protocol):
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules[0]["denied"] = rules[0].pop("allowed")
    rules.insert(0, {"name": "uncertain-allow", "network": rules[0]["network"], "direction": "INGRESS", "priority": 50,
        "sourceRanges": ["10.0.1.0/24"], "allowed": [{"IPProtocol": protocol}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "firewall_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("selector", ["sourceTags", "sourceServiceAccounts"])
def test_gcp_egress_identity_source_cannot_be_ignored_for_higher_priority_rule(selector):
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules.insert(0, {"name": "uncertain-egress", "network": rules[0]["network"], "direction": "EGRESS", "priority": 50,
        selector: ["unmatched"], "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "firewall_selector_unresolved" for g in result["unresolved_dependencies"])


def test_gcp_malformed_instance_tags_cannot_decide_firewall_membership():
    snapshot = gcp_fixture()
    collection(snapshot, "instance", "projects/service")["items"][0]["tags"]["items"] = "client"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_firewall_identity_malformed" for g in result["unresolved_dependencies"])


def test_gcp_empty_native_range_lists_use_firewall_defaults():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules.insert(0, {"name": "deny-egress", "network": rules[0]["network"], "direction": "EGRESS", "priority": 50,
        "sourceRanges": [], "destinationRanges": [], "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    assert query(reseal(snapshot))["decision"] == "blocked"
    assert query(reseal(snapshot), family="ipv6")["decision"] == "allowed"
    rules.pop(0)
    rules[0].update(sourceTags=[], sourceRanges=[])
    assert query(reseal(snapshot))["decision"] == "allowed"
    assert query(reseal(snapshot), family="ipv6")["decision"] == "blocked"


@pytest.mark.parametrize("network_ref", [None, "global/networks/default"])
def test_gcp_firewall_default_network_reference_uses_host_project(network_ref):
    snapshot = gcp_fixture()
    old = collection(snapshot, "network")["items"][0]["selfLink"]
    new = old.rsplit("/", 1)[0] + "/default"
    collection(snapshot, "network")["items"][0]["selfLink"] = new
    effective = collection(snapshot, "effective_firewall")["items"][0]
    effective["id"] = effective["id"].replace("/net/", "/default/")
    effective["network"] = new
    for subnet in collection(snapshot, "subnetwork")["items"]:
        subnet["network"] = new
    for c in snapshot["collections"]:
        if c["type"] == "instance":
            for instance in c["items"]:
                instance["networkInterfaces"][0]["network"] = new
    rules = collection(snapshot, "firewall")["items"]
    rules[0]["network"] = network_ref
    rules[1]["network"] = new
    assert query(reseal(snapshot))["decision"] == "allowed"


def gcp_peered_fixture():
    snapshot = gcp_fixture()
    network = collection(snapshot, "network")["items"][0]
    remote = copy.deepcopy(network)
    remote["selfLink"] = remote["selfLink"].replace("projects/host/", "projects/other/")
    network["peerings"] = [{"network": remote["selfLink"], "state": "ACTIVE", "stackType": "IPV4_IPV6",
        "connectionStatus": {"trafficConfiguration": {"stackType": "IPV4_IPV6"}}}]
    remote["peerings"] = [{"network": network["selfLink"], "state": "ACTIVE", "stackType": "IPV4_IPV6",
        "connectionStatus": {"trafficConfiguration": {"stackType": "IPV4_IPV6"}}}]
    snapshot["collections"].append({"type": "network", "scope": "projects/other", "service": "compute", "status": "collected", "items": [remote]})
    snapshot["collections"].append({"type": "firewall_policy", "scope": "projects/other", "service": "compute", "status": "empty",
        "source_requests": ["other-project-policy-list"], "items": []})
    effective = copy.deepcopy(collection(snapshot, "effective_firewall", "projects/host")["items"][0])
    effective["id"] = effective["id"].replace("projects/host/", "projects/other/")
    effective["network"] = remote["selfLink"]
    effective["_provenance"]["source_requests"] = ["other-region-effective-firewalls"]
    snapshot["collections"].append({"type": "effective_firewall", "scope": "projects/other", "service": "compute",
        "status": "collected", "source_requests": ["other-region-effective-firewalls"], "items": [effective]})
    hierarchy = snapshot["metadata"]["network_context"]["gcp"]["firewall_hierarchy"]
    hierarchy["unaffected_projects"].append("projects/other")
    hierarchy["project_ancestors"]["projects/other"] = ["organizations/12"]
    subnet = collection(snapshot, "subnetwork")["items"][1]
    collection(snapshot, "subnetwork")["items"].remove(subnet)
    subnet.update(network=remote["selfLink"], selfLink=subnet["selfLink"].replace("projects/host/", "projects/other/"), ipCidrRange="10.1.2.0/24", internalIpv6Prefix="fd01:0:0:2::/64")
    snapshot["collections"].append({"type": "subnetwork", "scope": "projects/other", "service": "compute", "status": "collected", "items": [subnet]})
    destination = collection(snapshot, "instance", "projects/host")["items"][0]
    destination["networkInterfaces"][0].update(network=remote["selfLink"], subnetwork=subnet["selfLink"], networkIP="10.1.2.10", ipv6Address="fd01:0:0:2::10")
    rule = {"name": "remote-allow", "network": remote["selfLink"], "sourceRanges": ["0.0.0.0/0", "::/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]}
    snapshot["collections"] += [{"type": "firewall", "scope": "projects/other", "service": "compute", "status": "collected", "items": [rule]},
        {"type": "route", "scope": "projects/other", "service": "compute", "status": "empty", "items": []}]
    return reseal(snapshot)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_gcp_active_peering_subnet_path_and_inactive_unknown(family):
    snapshot = gcp_peered_fixture()
    assert query(snapshot, family=family)["decision"] == "allowed"
    collection(snapshot, "network")["items"][0]["peerings"][0]["state"] = "INACTIVE"
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"


@pytest.mark.parametrize("family,prefix_field,prefix,address_field,address", [
    ("ipv4", "ipCidrRange", "10.0.1.0/24", "networkIP", "10.0.1.20"),
    ("ipv6", "internalIpv6Prefix", "fd00:0:0:1::/64", "ipv6Address", "fd00:0:0:1::20"),
])
def test_gcp_peered_overlapping_subnet_family_cannot_prove_path(family, prefix_field, prefix, address_field, address):
    snapshot = gcp_peered_fixture()
    collection(snapshot, "subnetwork", "projects/other")["items"][0][prefix_field] = prefix
    collection(snapshot, "instance", "projects/host")["items"][0]["networkInterfaces"][0][address_field] = address
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "overlapping_address_domains" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("overlap", ["primary", "secondary", "nonselected"])
def test_gcp_peered_route_rejects_another_local_subnet_overlapping_peer(overlap):
    snapshot = gcp_peered_fixture()
    local = collection(snapshot, "subnetwork", "projects/host")["items"][0]
    conflicting = copy.deepcopy(local)
    conflicting["selfLink"] = conflicting["selfLink"].replace("/subnetworks/", "/subnetworks/overlap-")
    if overlap in {"primary", "nonselected"}:
        conflicting["ipCidrRange"] = "10.1.2.128/25" if overlap == "nonselected" else "10.1.2.0/24"
    else:
        conflicting["ipCidrRange"] = "10.9.0.0/24"
        conflicting["secondaryIpRanges"] = [{"rangeName": "alias", "ipCidrRange": "10.1.2.0/24"}]
    collection(snapshot, "subnetwork", "projects/host")["items"].append(conflicting)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "overlapping_address_domains" for g in result["unresolved_dependencies"])


def test_gcp_same_project_partial_peering_references_join_exact_vpcs():
    snapshot = gcp_fixture()
    network = collection(snapshot, "network")["items"][0]
    peer = copy.deepcopy(network)
    peer["name"] = "net-b"
    peer["selfLink"] = network["selfLink"].rsplit("/", 1)[0] + "/net-b"
    network["peerings"] = [{"network": "global/networks/net-b", "state": "ACTIVE"}]
    peer["peerings"] = [{"network": "global/networks/net", "state": "ACTIVE"}]
    collection(snapshot, "network")["items"].append(peer)
    effective = copy.deepcopy(collection(snapshot, "effective_firewall")["items"][0])
    effective["id"] = effective["id"].replace("/net/", "/net-b/")
    effective["network"] = peer["selfLink"]
    collection(snapshot, "effective_firewall")["items"].append(effective)
    subnet = collection(snapshot, "subnetwork")["items"][1]
    subnet.update(network=peer["selfLink"], ipCidrRange="10.1.2.0/24", internalIpv6Prefix="fd01:0:0:2::/64")
    destination = collection(snapshot, "instance", "projects/host")["items"][0]
    destination["networkInterfaces"][0].update(network=peer["selfLink"], networkIP="10.1.2.10",
        ipv6Address="fd01:0:0:2::10")
    rules = collection(snapshot, "firewall")["items"]
    for rule in rules:
        rule["network"] = peer["selfLink"]
    rules[0].pop("sourceTags")
    rules[0]["sourceRanges"] = ["10.0.1.0/24"]
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_gcp_partial_peering_reference_does_not_join_same_named_cross_project_vpc():
    snapshot = gcp_peered_fixture()
    collection(snapshot, "network", "projects/host")["items"][0]["peerings"][0]["network"] = "global/networks/net"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "peering_context_missing" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("peerings", [None, {}, ["broken"]])
def test_gcp_malformed_peering_inventory_explains_unknown(peerings):
    snapshot = gcp_peered_fixture()
    collection(snapshot, "network", "projects/host")["items"][0]["peerings"] = peerings
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "peering_inventory_malformed" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("field,value", [("connectionStatus", "broken"),
    ("trafficConfiguration", []), ("consensusState", "broken")])
def test_gcp_malformed_peering_effective_status_explains_unknown(field, value):
    snapshot = gcp_peered_fixture()
    peering = collection(snapshot, "network", "projects/host")["items"][0]["peerings"][0]
    if field == "connectionStatus":
        peering[field] = value
    else:
        peering["connectionStatus"] = {field: value}
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "peering_status_malformed" for g in result["unresolved_dependencies"])


def test_gcp_pending_consensus_update_preserves_existing_private_ipv4_subnet_exchange():
    snapshot = gcp_peered_fixture()
    for network in [collection(snapshot, "network", scope)["items"][0] for scope in ("projects/host", "projects/other")]:
        network["peerings"][0]["connectionStatus"] = {"consensusState": {
            "updateStatus": "PENDING_PEER_ACKNOWLEDGMENT"}}
    assert query(reseal(snapshot))["decision"] == "allowed"


@pytest.mark.parametrize("prefix,address", [("100.64.1.0/24", "100.64.1.10"),
    ("198.18.1.0/24", "198.18.1.10"), ("192.0.2.0/24", "192.0.2.10")])
def test_gcp_special_use_ipv4_subnet_peering_ignores_public_route_flags(prefix, address):
    snapshot = gcp_peered_fixture()
    collection(snapshot, "subnetwork", "projects/other")["items"][0]["ipCidrRange"] = prefix
    destination = collection(snapshot, "instance", "projects/host")["items"][0]
    destination["networkInterfaces"][0]["networkIP"] = address
    for scope in ("projects/host", "projects/other"):
        peering = collection(snapshot, "network", scope)["items"][0]["peerings"][0]
        peering["importSubnetRoutesWithPublicIp"] = False
        peering["exportSubnetRoutesWithPublicIp"] = False
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_gcp_public_ipv4_subnet_peering_needs_effective_import_and_export():
    snapshot = gcp_peered_fixture()
    destination_subnet = collection(snapshot, "subnetwork", "projects/other")["items"][0]
    destination_subnet["ipCidrRange"] = "11.1.2.0/24"
    destination = collection(snapshot, "instance", "projects/host")["items"][0]
    destination["networkInterfaces"][0]["networkIP"] = "11.1.2.10"
    local = collection(snapshot, "network", "projects/host")["items"][0]["peerings"][0]
    remote = collection(snapshot, "network", "projects/other")["items"][0]["peerings"][0]
    assert query(reseal(snapshot))["decision"] == "unknown"
    local["importSubnetRoutesWithPublicIp"] = True
    assert query(reseal(snapshot))["decision"] == "unknown"
    remote["exportSubnetRoutesWithPublicIp"] = True
    assert query(reseal(snapshot))["decision"] == "unknown"
    local["connectionStatus"]["consensusState"] = {"updateStatus": "IN_SYNC"}
    remote["connectionStatus"]["consensusState"] = {"updateStatus": "IN_SYNC"}
    assert query(reseal(snapshot))["decision"] == "unknown"
    local["connectionStatus"]["trafficConfiguration"]["importSubnetRoutesWithPublicIpFromPeer"] = True
    assert query(reseal(snapshot))["decision"] == "unknown"
    remote["connectionStatus"]["trafficConfiguration"]["exportSubnetRoutesWithPublicIpToPeer"] = True
    assert query(reseal(snapshot))["decision"] == "allowed"
    local["connectionStatus"] = {"consensusState": {"updateStatus": "PENDING_PEER_ACKNOWLEDGMENT"}}
    assert query(reseal(snapshot))["decision"] == "unknown"
    local["connectionStatus"]["trafficConfiguration"] = {"importSubnetRoutesWithPublicIpFromPeer": True}
    assert query(reseal(snapshot))["decision"] == "allowed"
    local["connectionStatus"] = {"trafficConfiguration": {"importSubnetRoutesWithPublicIpFromPeer": False}}
    assert query(reseal(snapshot))["decision"] == "unknown"


@pytest.mark.parametrize("consensus", [None, {"updateStatus": "IN_SYNC"}])
def test_gcp_requested_ipv6_stack_without_effective_status_cannot_prove_route(consensus):
    snapshot = gcp_peered_fixture()
    local = collection(snapshot, "network", "projects/host")["items"][0]["peerings"][0]
    del local["connectionStatus"]["trafficConfiguration"]
    if consensus is not None:
        local["connectionStatus"]["consensusState"] = consensus
    assert local["stackType"] == "IPV4_IPV6"
    result = query(reseal(snapshot), family="ipv6")
    assert result["decision"] == "unknown"
    assert any(g["code"] == "peering_ipv6_context_missing" for g in result["unresolved_dependencies"])


def test_gcp_peering_uses_effective_ipv6_stack_and_subnet_exchange_state():
    snapshot = gcp_peered_fixture()
    local = collection(snapshot, "network", "projects/host")["items"][0]["peerings"][0]
    local["connectionStatus"] = {"trafficConfiguration": {"stackType": "IPV4_ONLY"}}
    assert query(reseal(snapshot), family="ipv6")["decision"] == "unknown"
    local["connectionStatus"]["trafficConfiguration"]["stackType"] = "IPV4_IPV6"
    assert query(reseal(snapshot), family="ipv6")["decision"] == "allowed"
    local["connectionStatus"]["consensusState"] = {"updateStatus": "PENDING_PEER_ACKNOWLEDGMENT"}
    local["stackType"] = "IPV4_ONLY"
    assert query(reseal(snapshot), family="ipv6")["decision"] == "allowed"
    del local["connectionStatus"]["trafficConfiguration"]
    assert query(reseal(snapshot), family="ipv6")["decision"] == "unknown"
    local["exchangeSubnetRoutes"] = False
    assert query(reseal(snapshot), family="ipv4")["decision"] == "unknown"


@pytest.mark.parametrize("kind,field,value", [
    ("instance", "stackType", "IPV4_ONLY"),
    ("subnetwork", "stackType", "IPV4_ONLY"),
    ("subnetwork", "ipv6AccessType", "EXTERNAL"),
    ("instance", "stackType", None),
    ("subnetwork", "stackType", None),
])
def test_gcp_ipv6_address_needs_consistent_interface_and_subnet_capability(kind, field, value):
    snapshot = gcp_fixture()
    resource = collection(snapshot, kind)["items"][0]
    selected = resource["networkInterfaces"][0] if kind == "instance" else resource
    if value is None:
        selected.pop(field)
    else:
        selected[field] = value
    result = query(reseal(snapshot), family="ipv6")
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_ipv6_capability_conflict" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("kind", ["instance", "subnetwork"])
def test_gcp_ipv4_address_cannot_belong_to_ipv6_only_stack(kind):
    snapshot = gcp_fixture()
    resource = collection(snapshot, kind)["items"][0]
    selected = resource["networkInterfaces"][0] if kind == "instance" else resource
    selected["stackType"] = "IPV6_ONLY"
    result = query(reseal(snapshot), family="ipv4")
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_ipv4_capability_conflict" for g in result["unresolved_dependencies"])


def test_gcp_egress_default_ipv4_range_does_not_admit_ipv6_specific_rule():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules.append({"name": "egress-deny", "network": rules[0]["network"], "direction": "EGRESS", "priority": 50,
        "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    snapshot = reseal(snapshot)
    assert query(snapshot)["decision"] == "blocked"
    assert query(snapshot, family="ipv6")["decision"] == "allowed"


@pytest.mark.parametrize("mutation, gap", [
    ("missing_cluster_provenance", "cluster_namespace_context_missing"),
    ("malformed_status", "pod_endpoint_facts_malformed"),
    ("malformed_pod_ips", "pod_endpoint_ips_malformed"),
    ("malformed_metadata", "pod_endpoint_facts_malformed"),
])
def test_k8s_pod_needs_explicit_cluster_and_valid_native_status(mutation, gap):
    snapshot = k8s_fixture()
    pod = collection(snapshot, "pod")["items"][0]
    if mutation == "missing_cluster_provenance":
        pod["provenance"].pop("cluster_id")
    elif mutation == "malformed_status":
        pod["status"] = None
    elif mutation == "malformed_pod_ips":
        pod["status"]["podIPs"] = ["10.0.1.10"]
    else:
        pod["metadata"] = None
    sealed = reseal(snapshot)
    pods = [resource["id"] for resource in resources(sealed) if resource["type"] == "pod"]
    result = evaluate_reachability(sealed, pods[0], pods[1], "tcp", 443, 54321)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == gap for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("kind,change,expected", [
    ("networkpolicy", "missing", "network_policy_provenance_mismatch"),
    ("networkpolicy", "foreign_cluster", "network_policy_provenance_mismatch"),
    ("networkpolicy", "wrong_namespace", "network_policy_provenance_mismatch"),
    ("namespace", "missing", "namespace_provenance_mismatch"),
    ("namespace", "foreign_cluster", "namespace_provenance_mismatch"),
])
def test_k8s_policy_and_namespace_facts_must_belong_to_selected_cluster(kind, change, expected):
    snapshot = k8s_fixture()
    item = collection(snapshot, kind)["items"][0]
    if change == "missing":
        item.pop("provenance")
    elif change == "foreign_cluster":
        item["provenance"]["cluster_id"] = "another-cluster"
    else:
        item["provenance"]["namespace"] = "server"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == expected for g in result["unresolved_dependencies"])


def test_k8s_additive_union_not_ordered_deny_and_namespaces_are_not_subnets():
    snapshot = k8s_fixture()
    policies = collection(snapshot, "networkpolicy")["items"]
    policies.append({"metadata": {"name": "default-isolation", "namespace": "server"},
        "provenance": {"cluster_id": "cluster-a", "namespace": "server"},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": []}})
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed"
    policies[1]["spec"]["ingress"] = []
    assert query(reseal(snapshot))["decision"] == "blocked"
    assert not any("subnet" in r.get("message", "") for r in result["routes"])


def test_k8s_cni_evidence_required_for_allow_and_block():
    snapshot = k8s_fixture()
    snapshot["metadata"]["network_context"]["k8s"].pop("cni")
    assert query(reseal(snapshot))["decision"] == "unknown"
    collection(snapshot, "networkpolicy")["items"][0]["spec"]["egress"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cni_enforcement_unknown" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("change", ["succeeded", "failed", "pending", "missing_phase", "terminating"])
def test_k8s_stale_pod_ip_cannot_establish_a_network_endpoint(change):
    snapshot = k8s_fixture()
    pod = collection(snapshot, "pod")["items"][1]
    if change == "terminating":
        pod["metadata"]["deletionTimestamp"] = "2026-10-01T00:00:00Z"
    elif change == "missing_phase":
        pod["status"].pop("phase")
    else:
        pod["status"]["phase"] = change.capitalize()
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "pod_endpoint_not_active" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_k8s_third_active_pod_with_selected_ip_makes_path_unknown(family):
    snapshot = k8s_fixture()
    pods = collection(snapshot, "pod")["items"]
    duplicate = copy.deepcopy(pods[1])
    duplicate["metadata"]["name"] = "different-active-pod"
    if family == "ipv4":
        duplicate["status"]["podIPs"] = [{"ip": "10.0.2.10"}, {"ip": "fd00::99"}]
    else:
        duplicate["status"]["podIP"] = "10.0.2.99"
        duplicate["status"]["podIPs"] = [{"ip": "10.0.2.99"}, {"ip": "fd00::2"}]
    pods.append(duplicate)
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "pod_endpoint_address_collision" for g in result["unresolved_dependencies"])


def test_k8s_enforcing_cni_without_complete_policy_source_proof_is_unknown():
    snapshot = k8s_fixture()
    snapshot["metadata"]["network_context"]["k8s"]["cni"].pop("policy_sources")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cni_enforcement_unknown" for g in result["unresolved_dependencies"])


def test_k8s_custom_policy_absence_needs_api_discovery_evidence():
    snapshot = k8s_fixture()
    snapshot["collections"] = [c for c in snapshot["collections"] if c["type"] != "api_discovery"]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cni_custom_policy_context_unknown" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("change", ["missing_networking_group", "wrong_version", "wrong_cluster", "wrong_source"])
def test_k8s_discovery_must_match_networkpolicy_api_and_cluster(change):
    snapshot = k8s_fixture()
    item = collection(snapshot, "api_discovery")["items"][0]
    if change == "missing_networking_group":
        item["groups"] = []
    elif change == "wrong_version":
        item["groups"][0]["versions"] = [{"version": "v1beta1"}]
    elif change == "wrong_cluster":
        item["provenance"]["cluster_id"] = "cluster-other"
    else:
        item["provenance"]["source"] = "operator-supplied metadata"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "cni_custom_policy_context_unknown" for g in result["unresolved_dependencies"])


def test_k8s_custom_policy_and_malformed_cni_proof_cannot_be_ignored():
    snapshot = k8s_fixture()
    snapshot["metadata"]["network_context"]["k8s"]["cni"]["source_evidence"] = [True]
    assert query(reseal(snapshot))["decision"] == "unknown"
    snapshot = k8s_fixture()
    cilium = collection(snapshot, "cilium_networkpolicy")
    cilium["status"] = "collected"
    cilium["items"] = [{"metadata": {"name": "custom", "namespace": "server"}, "spec": {"endpointSelector": {}, "ingressDeny": [{}]}}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cni_custom_policy_context_unknown" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("kind", ["cilium_clusterwide_networkpolicy", "calico_global_networkpolicy",
    "admin_networkpolicy", "baseline_admin_networkpolicy", "cluster_networkpolicy"])
def test_k8s_clusterwide_policy_prevents_standard_only_allow(kind):
    snapshot = k8s_fixture()
    policy = collection(snapshot, kind)
    policy["status"] = "collected"
    policy["items"] = [{"metadata": {"name": "cluster-deny"}, "spec": {"ingressDeny": [{}]}}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cni_custom_policy_context_unknown" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("kind", ["cilium_networkpolicy", "cilium_clusterwide_networkpolicy", "calico_networkpolicy",
    "calico_global_networkpolicy", "admin_networkpolicy", "baseline_admin_networkpolicy", "cluster_networkpolicy"])
def test_k8s_uncollected_custom_policy_inventory_cannot_prove_allowance(kind):
    snapshot = k8s_fixture()
    snapshot["collections"] = [c for c in snapshot["collections"] if c["type"] != kind]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cni_custom_policy_context_unknown" for g in result["unresolved_dependencies"])


def test_k8s_namespace_and_pod_selectors_are_conjunction_within_peer():
    snapshot = k8s_fixture()
    peer = collection(snapshot, "networkpolicy")["items"][1]["spec"]["ingress"][0]["from"][0]
    peer["namespaceSelector"]["matchLabels"]["team"] = "server"
    assert query(reseal(snapshot))["decision"] == "blocked"
    peer["namespaceSelector"] = {"matchExpressions": [{"key": "team", "operator": "In", "values": ["client"]}]}
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_k8s_namespace_name_selector_requires_consistent_native_label():
    snapshot = k8s_fixture()
    policies = collection(snapshot, "networkpolicy")["items"]
    policies[0]["spec"]["egress"][0]["to"][0]["namespaceSelector"] = {
        "matchLabels": {"kubernetes.io/metadata.name": "server"}}
    policies[1]["spec"]["ingress"][0]["from"][0]["namespaceSelector"] = {
        "matchLabels": {"kubernetes.io/metadata.name": "client"}}
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    for namespace in collection(snapshot, "namespace")["items"]:
        namespace["metadata"]["labels"]["kubernetes.io/metadata.name"] = namespace["metadata"]["name"]
    assert query(reseal(snapshot))["decision"] == "allowed"
    collection(snapshot, "namespace")["items"][1]["metadata"]["labels"]["kubernetes.io/metadata.name"] = "different"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "cluster_namespace_context_missing" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("types", ["Egress", ["SIDEWAYS"], ["Egress", "Egress"]])
def test_k8s_malformed_policy_types_cannot_remove_source_isolation(types):
    snapshot = k8s_fixture()
    collection(snapshot, "networkpolicy")["items"][0]["spec"]["policyTypes"] = types
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


def test_k8s_malformed_policy_types_only_matter_for_selected_pods():
    snapshot = k8s_fixture()
    policies = collection(snapshot, "networkpolicy")["items"]
    unrelated = copy.deepcopy(policies[0])
    unrelated["metadata"]["name"] = "unrelated"
    unrelated["spec"]["podSelector"] = {"matchLabels": {"app": "another-pod"}}
    unrelated["spec"]["policyTypes"] = []
    policies.append(unrelated)
    assert query(reseal(snapshot))["decision"] == "allowed"
    unrelated["provenance"]["cluster_id"] = "another-cluster"
    assert query(reseal(snapshot))["decision"] == "allowed"
    unrelated["provenance"]["cluster_id"] = "cluster-a"
    unrelated["spec"]["podSelector"] = {"matchLabels": {"app": "source"}}
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_k8s_default_policy_types_require_an_egress_rule():
    snapshot = k8s_fixture()
    policy = collection(snapshot, "networkpolicy")["items"][0]["spec"]
    policy.pop("policyTypes")
    assert query(reseal(snapshot))["decision"] == "allowed"
    policy["egress"] = []
    assert query(reseal(snapshot))["decision"] == "allowed"
    policy["policyTypes"] = []
    assert query(reseal(snapshot))["decision"] == "allowed"
    policy["policyTypes"] = ["Egress"]
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert any(p.get("control") == "k8s.networkpolicy" and p.get("direction") == "Egress"
        and p.get("candidate_decision") == "blocked" for p in result["policy_decisions"])
    policy.pop("policyTypes")
    policy["egress"] = "invalid"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])
    policy.pop("egress")
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_k8s_omitted_pod_selector_defaults_to_all_pods_in_its_namespace():
    snapshot = k8s_fixture()
    policy = collection(snapshot, "networkpolicy")["items"][0]["spec"]
    policy.pop("podSelector")
    policy["egress"] = []
    assert query(reseal(snapshot))["decision"] == "blocked"


def test_k8s_missing_policy_namespace_cannot_be_discarded_as_unrelated():
    snapshot = k8s_fixture()
    policies = collection(snapshot, "networkpolicy")["items"]
    policies[0]["metadata"].pop("namespace")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])
    policies[0]["metadata"]["namespace"] = "client"
    extra = copy.deepcopy(policies[0])
    extra["metadata"].pop("namespace")
    policies.append(extra)
    assert query(reseal(snapshot))["decision"] == "allowed"
    extra["spec"]["podSelector"] = {"matchLabels": {"app": "different"}}
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_k8s_ipblock_exceptions_port_ranges_and_cni_translation_context():
    snapshot = k8s_fixture()
    rule = collection(snapshot, "networkpolicy")["items"][1]["spec"]["ingress"][0]
    rule["from"] = [{"ipBlock": {"cidr": "10.0.0.0/16", "except": ["10.0.1.0/24"]}}]
    assert query(reseal(snapshot))["decision"] == "blocked"
    rule["from"][0]["ipBlock"]["except"] = []
    rule["ports"] = [{"port": 440, "endPort": 450, "protocol": "TCP"}]
    assert query(reseal(snapshot))["decision"] == "allowed"
    snapshot["metadata"]["network_context"]["k8s"]["cni"].pop("supports_end_port")
    assert query(reseal(snapshot))["decision"] == "unknown"
    snapshot["metadata"]["network_context"]["k8s"]["cni"]["supports_end_port"] = True
    snapshot["metadata"]["network_context"]["k8s"]["cni"].pop("ipblock_semantics")
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_k8s_end_port_start_needs_cni_range_support():
    snapshot = k8s_fixture()
    ingress = collection(snapshot, "networkpolicy")["items"][1]["spec"]["ingress"][0]
    ingress["ports"] = [{"protocol": "TCP", "port": 443, "endPort": 450}]
    snapshot["metadata"]["network_context"]["k8s"]["cni"].pop("supports_end_port")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("exceptions", [{}, "", None, [7], ["bad-cidr"], ["2001:db8::/32"], ["10.2.0.0/16"]])
def test_k8s_malformed_ipblock_exception_list_cannot_prove_allow(exceptions):
    snapshot = k8s_fixture()
    rule = collection(snapshot, "networkpolicy")["items"][1]["spec"]["ingress"][0]
    rule["from"] = [{"ipBlock": {"cidr": "10.0.0.0/16", "except": exceptions}}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("spec", [
    None,
    {},
    {"containers": []},
    {"containers": [{"name": "application", "ports": {}}]},
    {"containers": [{"name": "application", "ports": [{"name": "https", "containerPort": None}]}]},
])
def test_k8s_named_port_needs_complete_destination_pod_spec(spec):
    snapshot = k8s_fixture()
    pod = collection(snapshot, "pod")["items"][1]
    if spec is None:
        pod.pop("spec")
    else:
        pod["spec"] = spec
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    expected = "pod_network_spec_unresolved" if spec is None or not spec.get("containers") else "network_policy_selector_unresolved"
    assert any(g["code"] == expected for g in result["unresolved_dependencies"])


def test_k8s_complete_destination_pod_without_named_port_can_be_denied():
    snapshot = k8s_fixture()
    collection(snapshot, "pod")["items"][1]["spec"] = {"containers": [{"name": "application"}]}
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result


@pytest.mark.parametrize("provider", ["azure", "gcp", "k8s"])
def test_missing_routing_context_stays_unknown_despite_policy_allow(provider):
    snapshot = FIXTURES[provider][0]()
    snapshot["metadata"]["network_context"][provider].pop("routing")
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_scoped_artifact_keeps_dependency_status_and_original_identity():
    snapshot = aws_fixture()
    snapshot["collections"].append({"type": "iam_policy", "scope": snapshot["scopes"][0], "service": "iam", "status": "collected", "items": [{"PolicyDocument": {"Statement": []}}]})
    snapshot = reseal(snapshot)
    projected = network_snapshot(snapshot)
    assert all(c["type"] in REACHABILITY_TYPES["aws"] for c in projected["collections"])
    assert projected["snapshot_id"] != snapshot["snapshot_id"]
    result = query(projected)
    assert result["decision"] == "allowed"
    assert result["snapshot_id"] == snapshot["snapshot_id"]
    assert result["scoped_snapshot_id"] == projected["snapshot_id"]
    assert query(network_snapshot(projected))["snapshot_id"] == snapshot["snapshot_id"]


def test_no_network_socket_or_subprocess_during_all_provider_evaluation(monkeypatch):
    snapshots = {p: factory() for p, (factory, _) in FIXTURES.items()}
    def fail(*args, **kwargs):
        pytest.fail("network/socket/subprocess called by pure evaluation")
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    for snapshot in snapshots.values():
        assert query(snapshot)["decision"] == "allowed"


@pytest.mark.parametrize("port", [True, False, 0, -1, 65536, 1.0, "443"])
def test_strict_port_validation(port):
    with pytest.raises(ValueError):
        evaluate_reachability(aws_fixture(), "source", "destination", "tcp", port)


def test_missing_ids_unknown_and_bad_protocol_family_rejected():
    snapshot = aws_fixture()
    result = evaluate_reachability(snapshot, "missing", "missing", "tcp", 443)
    assert result["decision"] == "unknown"
    assert result["unresolved_dependencies"][0]["code"] == "endpoint_inventory_missing"
    with pytest.raises(ValueError):
        evaluate_reachability(snapshot, "source", "destination", "icmp", 443)
    with pytest.raises(ValueError):
        evaluate_reachability(snapshot, "source", "destination", "tcp", 443, address_family="ipvx")


def aws_peered_fixture():
    snapshot = aws_fixture()
    a, b = snapshot["scopes"][0], "222222222222/us-east-1"
    snapshot["scopes"].append(b)
    def move(kind, item):
        collection(snapshot, kind)["items"].remove(item)
        snapshot["collections"].append({"type": kind, "scope": b, "service": kind, "status": "collected", "items": [item]})
    vpc = {"id": "vpc-b", "VpcId": "vpc-b", "OwnerId": "222222222222", "CidrBlock": "10.1.0.0/16", "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": "fd01::/48", "Ipv6CidrBlockState": {"State": "associated"}}]}
    snapshot["collections"].append({"type": "vpc", "scope": b, "service": "vpc", "status": "collected", "items": [vpc]})
    subnet = collection(snapshot, "subnet")["items"][1]
    subnet.update(VpcId="vpc-b", CidrBlock="10.1.2.0/24", Ipv6CidrBlockAssociationSet=[{"Ipv6CidrBlock": "fd01:0:0:2::/64", "Ipv6CidrBlockState": {"State": "associated"}}])
    move("subnet", subnet)
    interface = collection(snapshot, "network_interface")["items"][1]
    interface.update(VpcId="vpc-b", OwnerId="222222222222", PrivateIpAddress="10.1.2.10", Ipv6Addresses=[{"Ipv6Address": "fd01:0:0:2::10"}])
    move("network_interface", interface)
    instance = collection(snapshot, "instance")["items"][1]
    instance["NetworkInterfaces"][0].update(VpcId="vpc-b", PrivateIpAddress="10.1.2.10")
    move("instance", instance)
    group = collection(snapshot, "security_group")["items"][1]
    group["VpcId"] = "vpc-b"
    group["OwnerId"] = "222222222222"
    move("security_group", group)
    collection(snapshot, "security_group", a)["items"][0]["IpPermissionsEgress"][0]["IpRanges"] = [{"CidrIp": "10.1.2.0/24"}]
    collection(snapshot, "security_group", a)["items"][0]["IpPermissionsEgress"][0]["Ipv6Ranges"] = [{"CidrIpv6": "fd01:0:0:2::/64"}]
    acl = collection(snapshot, "network_acl")["items"][1]
    acl["VpcId"] = "vpc-b"
    move("network_acl", acl)
    collection(snapshot, "route_table", a)["items"][0]["Routes"] += [
        {"DestinationCidrBlock": "10.1.0.0/16", "VpcPeeringConnectionId": "pcx-a", "State": "active"},
        {"DestinationIpv6CidrBlock": "fd01::/48", "VpcPeeringConnectionId": "pcx-a", "State": "active"}]
    snapshot["collections"].append({"type": "route_table", "scope": b, "service": "ec2", "status": "collected", "items": [{"id": "rt-b", "VpcId": "vpc-b", "Associations": [{"Main": True}], "Routes": [
        {"DestinationCidrBlock": "10.1.0.0/16", "GatewayId": "local", "State": "active"}, {"DestinationIpv6CidrBlock": "fd01::/48", "GatewayId": "local", "State": "active"},
        {"DestinationCidrBlock": "10.0.0.0/16", "VpcPeeringConnectionId": "pcx-a", "State": "active"}, {"DestinationIpv6CidrBlock": "fd00::/48", "VpcPeeringConnectionId": "pcx-a", "State": "active"}]}]})
    collection(snapshot, "vpc_peering", a).update(status="collected", items=[{"id": "pcx-a", "VpcPeeringConnectionId": "pcx-a", "Status": {"Code": "active"},
        "RequesterVpcInfo": {"VpcId": "vpc-a", "OwnerId": "111111111111", "Region": "us-east-1"},
        "AccepterVpcInfo": {"VpcId": "vpc-b", "OwnerId": "222222222222", "Region": "us-east-1"}}])
    return reseal(snapshot)


def aws_transit_gateway_fixture():
    snapshot = aws_peered_fixture()
    a, b = snapshot["scopes"]
    gateway_id = "tgw-a"
    for scope, endpoint_subnet, attachment_subnet, vpc_id, zone, remote_prefix, remote_attachment, table_id in (
        (a, "subnet-1", "subnet-3", "vpc-a", "use1-az1", "10.1.0.0/16", "tgw-attach-b", "tgw-rtb-a"),
        (b, "subnet-2", "subnet-4", "vpc-b", "use1-az2", "10.0.0.0/16", "tgw-attach-a", "tgw-rtb-b"),
    ):
        subnets = collection(snapshot, "subnet", scope)["items"]
        subnets[0]["AvailabilityZoneId"] = zone
        attachment = copy.deepcopy(subnets[0])
        attachment.update(id=attachment_subnet, SubnetId=attachment_subnet,
            CidrBlock="10.0.3.0/24" if scope == a else "10.1.4.0/24")
        attachment["Ipv6CidrBlockAssociationSet"] = []
        subnets.append(attachment)
        acl = copy.deepcopy(collection(snapshot, "network_acl", scope)["items"][0])
        acl.update(id=f"acl-{attachment_subnet}", NetworkAclId=f"acl-{attachment_subnet}",
            Associations=[{"SubnetId": attachment_subnet}])
        collection(snapshot, "network_acl", scope)["items"].append(acl)
        routes = collection(snapshot, "route_table", scope)["items"][0]["Routes"]
        routes[:] = [route for route in routes if not route.get("VpcPeeringConnectionId")]
        routes.append({"DestinationCidrBlock": remote_prefix, "TransitGatewayId": gateway_id, "State": "active"})
        native_attachment = "tgw-attach-a" if scope == a else "tgw-attach-b"
        snapshot["collections"].append({"type": "transit_gateway_vpc_attachment", "scope": scope,
            "service": "ec2", "status": "collected", "items": [{"id": native_attachment,
                "TransitGatewayAttachmentId": native_attachment, "TransitGatewayId": gateway_id,
                "VpcId": vpc_id, "VpcOwnerId": scope.split("/")[0], "State": "available",
                "SubnetIds": [attachment_subnet]}]})
        snapshot["collections"].append({"type": "transit_gateway_attachment", "scope": scope,
            "service": "ec2", "status": "collected", "items": [{"id": native_attachment,
                "TransitGatewayAttachmentId": native_attachment, "TransitGatewayId": gateway_id,
                "ResourceType": "vpc", "ResourceId": vpc_id, "State": "available",
                "ResourceOwnerId": scope.split("/")[0], "TransitGatewayOwnerId": a.split("/")[0],
                "Association": {"TransitGatewayRouteTableId": table_id, "State": "associated"}}]})
        snapshot["collections"].append({"type": "transit_gateway_route_table", "scope": scope,
            "service": "ec2", "status": "collected", "items": [{"id": table_id,
                "TransitGatewayRouteTableId": table_id, "TransitGatewayId": gateway_id, "State": "available",
                "AssociationInventory": {"collection_status": "collected", "items": [{
                    "TransitGatewayAttachmentId": native_attachment, "State": "associated"}]},
                "RouteInventory": {"collection_status": "collected", "queries": ["type=static", "type=propagated"],
                    "items": [{"DestinationCidrBlock": remote_prefix, "Type": "static", "State": "active",
                        "TransitGatewayAttachments": [{"TransitGatewayAttachmentId": remote_attachment,
                            "ResourceType": "vpc", "ResourceId": "vpc-b" if scope == a else "vpc-a"}]}]},
                "SystemRouteInventory": {"collection_status": "empty", "queries": ["type=system"], "items": []}}]})
    collection(snapshot, "vpc_peering", a).update(status="empty", items=[])
    snapshot["collections"].append({"type": "transit_gateway", "scope": a, "service": "ec2", "status": "collected",
        "items": [{"id": gateway_id, "TransitGatewayId": gateway_id, "State": "available"}]})
    return reseal(snapshot)


def test_aws_transit_gateway_two_vpc_path_needs_attachment_routes_and_nacls():
    snapshot = aws_transit_gateway_fixture()
    result = query(snapshot)
    assert result["decision"] == "allowed", result
    assert len([r for r in result["routes"] if r["decision"] == "allowed"]) >= 4
    acl = next(a for a in collection(snapshot, "network_acl", snapshot["scopes"][0])["items"]
        if a["NetworkAclId"] == "acl-subnet-3")
    acl["Entries"].insert(0, {"Egress": False, "RuleNumber": 1, "Protocol": "6", "PortRange": {"From": 443, "To": 443},
        "RuleAction": "deny", "CidrBlock": "10.0.1.0/24"})
    denied = query(reseal(snapshot))
    assert denied["decision"] == "blocked", denied
    assert any(p["decision"] == "blocked" and p.get("flow") == "attachment_forward" for p in denied["policy_decisions"])


def test_aws_transit_gateway_missing_zone_or_routes_stays_unknown():
    snapshot = aws_transit_gateway_fixture()
    collection(snapshot, "subnet", snapshot["scopes"][0])["items"][0].pop("AvailabilityZoneId")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "tgw_attachment_zone_unproven" for g in result["unresolved_dependencies"])
    snapshot = aws_transit_gateway_fixture()
    collection(snapshot, "transit_gateway_route_table", snapshot["scopes"][0])["items"][0]["RouteInventory"]["collection_status"] = "partial"
    assert query(reseal(snapshot))["decision"] == "unknown"
    snapshot = aws_transit_gateway_fixture()
    collection(snapshot, "route_table", snapshot["scopes"][0])["items"][0]["Routes"][-1]["GatewayId"] = "igw-conflict"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "route_target_ambiguous" for g in result["unresolved_dependencies"])


def test_aws_transit_gateway_group_reference_requires_feature_proof():
    snapshot = aws_transit_gateway_fixture()
    destination = collection(snapshot, "security_group", snapshot["scopes"][1])["items"][0]
    destination["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "UserIdGroupPairs": [{"GroupId": "sg-source", "UserId": "111111111111"}]}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "tgw_sg_reference_unproven" for g in result["unresolved_dependencies"])

    gateway = collection(snapshot, "transit_gateway", snapshot["scopes"][0])["items"][0]
    attachments = [collection(snapshot, "transit_gateway_vpc_attachment", scope)["items"][0]
        for scope in snapshot["scopes"]]
    gateway["Options"] = {"SecurityGroupReferencingSupport": "enable"}
    for attachment in attachments:
        attachment.setdefault("Options", {})["SecurityGroupReferencingSupport"] = "enable"
    assert query(reseal(snapshot))["decision"] == "allowed"

    gateway["Options"]["SecurityGroupReferencingSupport"] = "disable"
    assert query(reseal(snapshot))["decision"] == "unknown"
    gateway["Options"]["SecurityGroupReferencingSupport"] = "enable"
    attachments[0]["Options"]["SecurityGroupReferencingSupport"] = "disable"
    assert query(reseal(snapshot))["decision"] == "unknown"
    attachments[0]["Options"]["SecurityGroupReferencingSupport"] = "enable"
    pair = destination["IpPermissions"][0]["UserIdGroupPairs"][0]
    pair["PeeringStatus"] = "deleted"
    assert query(reseal(snapshot))["decision"] == "unknown"
    pair.pop("PeeringStatus")
    for subnet in collection(snapshot, "subnet", snapshot["scopes"][0])["items"]:
        subnet["AvailabilityZoneId"] = "use1-az3"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "tgw_sg_reference_zone_unproven" for g in result["unresolved_dependencies"])


def test_aws_transit_gateway_outbound_cross_vpc_sg_reference_is_unsupported():
    snapshot = aws_transit_gateway_fixture()
    source = collection(snapshot, "security_group", snapshot["scopes"][0])["items"][0]
    source["IpPermissionsEgress"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "UserIdGroupPairs": [{"GroupId": "sg-destination", "UserId": "222222222222"}]}]
    gateway = collection(snapshot, "transit_gateway", snapshot["scopes"][0])["items"][0]
    gateway["Options"] = {"SecurityGroupReferencingSupport": "enable"}
    for scope in snapshot["scopes"]:
        collection(snapshot, "transit_gateway_vpc_attachment", scope)["items"][0]["Options"] = {
            "SecurityGroupReferencingSupport": "enable"}
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "tgw_sg_egress_reference_unsupported" for g in result["unresolved_dependencies"])


def test_aws_transit_gateway_route_blackhole_blocks_and_wrong_attachment_is_unknown():
    snapshot = aws_transit_gateway_fixture()
    route = collection(snapshot, "transit_gateway_route_table", snapshot["scopes"][0])["items"][0]["RouteInventory"]["items"][0]
    route["State"] = "blackhole"
    route["TransitGatewayAttachments"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result
    assert any(r["decision"] == "blocked" and r.get("direction") == "forward" for r in result["routes"])
    route["State"] = "active"
    route["TransitGatewayAttachments"] = [{"TransitGatewayAttachmentId": "tgw-attach-other",
        "ResourceType": "vpc", "ResourceId": "vpc-other"}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "tgw_route_target_unresolved" for g in result["unresolved_dependencies"])


def test_aws_transit_gateway_same_subnet_attachment_uses_native_nacl_direction():
    snapshot = aws_transit_gateway_fixture()
    for scope, subnet_id in ((snapshot["scopes"][0], "subnet-1"), (snapshot["scopes"][1], "subnet-2")):
        collection(snapshot, "transit_gateway_vpc_attachment", scope)["items"][0]["SubnetIds"] = [subnet_id]
    assert query(reseal(snapshot))["decision"] == "allowed"
    source_acl = collection(snapshot, "network_acl", snapshot["scopes"][0])["items"][0]
    source_acl["Entries"].insert(0, {"Egress": False, "RuleNumber": 1, "Protocol": "6",
        "PortRange": {"From": 443, "To": 443}, "RuleAction": "deny", "CidrBlock": "10.0.1.0/24"})
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result
    assert any(p["decision"] == "blocked" and p.get("flow") == "attachment_forward" for p in result["policy_decisions"])


@pytest.mark.parametrize("mutation, expected_gap", [
    ("wrong_attachment_owner", "tgw_attachment_mismatch"),
    ("subnet_outside_vpc", "tgw_attachment_subnet_domain_mismatch"),
    ("malformed_association", "tgw_route_inventory_incomplete"),
])
def test_aws_transit_gateway_identity_and_subnet_conflicts_stay_unknown(mutation, expected_gap):
    snapshot = aws_transit_gateway_fixture()
    scope = snapshot["scopes"][0]
    if mutation == "wrong_attachment_owner":
        collection(snapshot, "transit_gateway_attachment", scope)["items"][0]["ResourceOwnerId"] = "333333333333"
    elif mutation == "subnet_outside_vpc":
        collection(snapshot, "subnet", scope)["items"][1]["CidrBlock"] = "192.0.2.0/24"
    else:
        table = collection(snapshot, "transit_gateway_route_table", scope)["items"][0]
        table["AssociationInventory"]["items"].append({"State": "associated"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == expected_gap for g in result["unresolved_dependencies"])


def test_aws_transit_gateway_multi_zone_uses_source_zone_attachment_nacls():
    snapshot = aws_transit_gateway_fixture()
    for scope, extra_id, zone, cidr in (
        (snapshot["scopes"][0], "subnet-5", "use1-az2", "10.0.5.0/24"),
        (snapshot["scopes"][1], "subnet-6", "use1-az1", "10.1.6.0/24"),
    ):
        subnets = collection(snapshot, "subnet", scope)["items"]
        extra = copy.deepcopy(subnets[1])
        extra.update(id=extra_id, SubnetId=extra_id, AvailabilityZoneId=zone, CidrBlock=cidr)
        subnets.append(extra)
        acl = copy.deepcopy(collection(snapshot, "network_acl", scope)["items"][1])
        acl.update(id=f"acl-{extra_id}", NetworkAclId=f"acl-{extra_id}", Associations=[{"SubnetId": extra_id}])
        collection(snapshot, "network_acl", scope)["items"].append(acl)
        attachment = collection(snapshot, "transit_gateway_vpc_attachment", scope)["items"][0]
        attachment["SubnetIds"].append(extra_id)
        attachment["Options"] = {"ApplianceModeSupport": "disable"}
    assert query(reseal(snapshot))["decision"] == "allowed"
    destination_acl = next(acl for acl in collection(snapshot, "network_acl", snapshot["scopes"][1])["items"]
        if acl["NetworkAclId"] == "acl-subnet-6")
    destination_acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 1, "Protocol": "6",
        "PortRange": {"From": 443, "To": 443}, "RuleAction": "deny", "CidrBlock": "10.1.2.0/24"})
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result
    assert any(p["decision"] == "blocked" and p.get("flow") == "attachment_forward" for p in result["policy_decisions"])
    destination_acl["Entries"].pop(0)
    collection(snapshot, "transit_gateway_vpc_attachment", snapshot["scopes"][1])["items"][0]["Options"]["ApplianceModeSupport"] = "enable"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "tgw_target_zone_unproven" for g in result["unresolved_dependencies"])
    destination_attachment = collection(snapshot, "transit_gateway_vpc_attachment", snapshot["scopes"][1])["items"][0]
    destination_attachment["Options"]["ApplianceModeSupport"] = "disable"
    collection(snapshot, "subnet", snapshot["scopes"][1])["items"][2]["AvailabilityZoneId"] = "use1-az3"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "tgw_target_zone_unproven" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_aws_active_cross_account_peering_needs_routes_both_directions(family):
    snapshot = aws_peered_fixture()
    result = query(snapshot, family=family)
    assert result["decision"] == "allowed", result
    assert result["endpoints"]["source"]["scope"] != result["endpoints"]["destination"]["scope"]
    peer = collection(snapshot, "vpc_peering")["items"][0]
    peer["AccepterVpcInfo"]["OwnerId"] = "333333333333"
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"


def test_aws_peering_same_native_vpc_name_in_wrong_region_is_not_a_join():
    snapshot = aws_peered_fixture()
    collection(snapshot, "vpc_peering")["items"][0]["AccepterVpcInfo"]["Region"] = "us-west-2"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "peering_facts_missing" for g in result["unresolved_dependencies"])


def test_aws_interregion_peering_does_not_match_referenced_security_group():
    snapshot = aws_peered_fixture()
    old_scope, new_scope = "222222222222/us-east-1", "222222222222/us-west-2"
    snapshot["scopes"] = [new_scope if scope == old_scope else scope for scope in snapshot["scopes"]]
    for c in snapshot["collections"]:
        if c["scope"] == old_scope:
            c["scope"] = new_scope
    collection(snapshot, "network_interface", new_scope)["items"][0]["Region"] = "us-west-2"
    collection(snapshot, "vpc_peering")["items"][0]["AccepterVpcInfo"]["Region"] = "us-west-2"
    destination_group = collection(snapshot, "security_group", new_scope)["items"][0]
    destination_group["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "UserIdGroupPairs": [{"GroupId": "sg-source", "UserId": "111111111111"}]}]
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked", result
    assert any(p.get("control") == "aws.security_group" and p.get("direction") == "ingress" and
        p["decision"] == "blocked" for p in result["policy_decisions"])


def test_aws_referenced_security_group_owner_is_not_assumed_to_be_eni_owner():
    snapshot = aws_fixture()
    groups = collection(snapshot, "security_group")["items"]
    groups[1]["OwnerId"] = "222222222222"
    groups[0]["IpPermissionsEgress"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "UserIdGroupPairs": [{"GroupId": "sg-destination", "UserId": "222222222222"}]}]
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed", result


def test_aws_overlapping_scoped_networks_do_not_alias_even_matching_native_names():
    snapshot = aws_peered_fixture()
    b = "222222222222/us-east-1"
    collection(snapshot, "vpc", b)["items"][0]["CidrBlock"] = "10.0.0.0/16"
    collection(snapshot, "subnet", b)["items"][0]["CidrBlock"] = "10.0.2.0/24"
    collection(snapshot, "network_interface", b)["items"][0]["PrivateIpAddress"] = "10.0.2.10"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "overlapping_address_domains" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("provider,kind", [("azure", "nsg"), ("gcp", "firewall"), ("k8s", "networkpolicy")])
@pytest.mark.parametrize("status", ["denied", "partial", "not_collected"])
def test_other_provider_incomplete_policy_union_is_unknown(provider, kind, status):
    snapshot = FIXTURES[provider][0]()
    c = collection(snapshot, kind)
    c["status"] = status
    if status != "partial":
        c["items"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert result["unresolved_dependencies"]


def test_k8s_partial_selected_pod_inventory_cannot_prove_allowed_flow():
    snapshot = k8s_fixture()
    collection(snapshot, "pod")["status"] = "partial"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_association_incomplete" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("selector", [
    {"matchLabels": []},
    {"matchLabels": {"app": 7}},
    {"matchExpressions": [{"key": "app", "operator": "In", "values": [7]}]},
    {"matchExpressions": [None]},
])
def test_k8s_malformed_peer_selector_cannot_allow_a_flow(selector):
    snapshot = k8s_fixture()
    peer = collection(snapshot, "networkpolicy")["items"][1]["spec"]["ingress"][0]["from"][0]
    peer["podSelector"] = selector
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("policy_index,rule_key,field,value", [
    (0, "egress", None, {}),
    (1, "ingress", None, {}),
    (0, "egress", "to", {}),
    (1, "ingress", "from", {}),
    (0, "egress", "ports", {}),
    (1, "ingress", "ports", {}),
])
def test_k8s_malformed_rule_arrays_cannot_prove_allow_or_deny(policy_index, rule_key, field, value):
    snapshot = k8s_fixture()
    spec = collection(snapshot, "networkpolicy")["items"][policy_index]["spec"]
    if field is None:
        spec[rule_key] = value
    else:
        spec[rule_key][0][field] = value
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("port", [
    {"endPort": 444},
    {"port": None},
    {"port": 0},
    {"port": ""},
    {"port": 443, "endPort": 442},
    {"protocol": "bogus", "port": 443},
    {"protocol": "TCP", "port": 443, "futureConstraint": "unmodeled"},
])
def test_k8s_malformed_networkpolicy_port_cannot_prove_allow_or_deny(port):
    snapshot = k8s_fixture()
    collection(snapshot, "networkpolicy")["items"][1]["spec"]["ingress"][0]["ports"] = [port]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("location", ["spec", "rule", "ipblock"])
def test_k8s_unknown_policy_fields_cannot_prove_an_allowance(location):
    snapshot = k8s_fixture()
    spec = collection(snapshot, "networkpolicy")["items"][1]["spec"]
    if location == "spec":
        spec["futurePolicyConstraint"] = "unmodeled"
    elif location == "rule":
        spec["ingress"][0]["futureRuleConstraint"] = "unmodeled"
    else:
        spec["ingress"][0]["from"] = [{"ipBlock": {
            "cidr": "10.0.0.0/16", "futurePeerConstraint": "unmodeled"}}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


def test_k8s_missing_policy_spec_cannot_remove_source_isolation():
    snapshot = k8s_fixture()
    collection(snapshot, "networkpolicy")["items"][0].pop("spec")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("fixture,kinds", [
    (aws_fixture, ("network_interface", "subnet", "vpc", "security_group", "route_table", "network_acl")),
    (aws_peered_fixture, ("network_interface", "subnet", "vpc", "security_group", "route_table", "network_acl", "vpc_peering")),
    (azure_fixture, ("nic", "subnet", "vnet", "nsg")),
    (azure_peered_fixture, ("nic", "subnet", "vnet", "nsg", "vnet_peering")),
    (azure_effective_fixture, ("nic", "subnet", "vnet", "nsg", "effective_route")),
    (gcp_fixture, ("instance", "network", "subnetwork", "firewall", "route")),
    (gcp_peered_fixture, ("instance", "network", "subnetwork", "firewall", "route")),
    (k8s_fixture, ("pod", "namespace", "networkpolicy", "api_discovery")),
])
def test_selected_path_never_allows_with_partial_required_inventory(fixture, kinds):
    baseline = fixture()
    assert query(baseline)["decision"] == "allowed"
    for kind in kinds:
        draft = copy.deepcopy(baseline)
        found = False
        for row in draft["collections"]:
            if row["type"] == kind:
                row["status"] = "partial"
                found = True
        assert found, kind
        result = query(reseal(draft))
        assert result["decision"] != "allowed", (baseline["provider"], kind, result)


def test_native_kind_network_snapshot_preserves_policy_intent_without_claiming_cni_enforcement():
    captured = json.loads((Path(__file__).parent / "fixtures/native-kind-network-v27.json").read_text())
    scoped = network_snapshot(captured)
    pods = [row for row in resources(scoped) if row["type"] == "pod"]
    assert len(pods) == 3
    for source in pods:
        for destination in pods:
            if source["id"] == destination["id"]:
                continue
            result = evaluate_reachability(scoped, source["id"], destination["id"], "tcp", 8080, 54321)
            assert result["decision"] == "unknown"
            assert any(g["code"] == "cni_enforcement_unknown" for g in result["unresolved_dependencies"])
            assert any(g["code"] == "pod_routing_context_missing" for g in result["unresolved_dependencies"])
            if source["data"]["metadata"]["name"].startswith("other-"):
                assert any(step.get("direction") == "Ingress" and step.get("candidate_decision") == "blocked"
                    for step in result["policy_decisions"])


def test_azure_different_subscription_vnets_with_overlap_remain_unknown():
    snapshot = azure_fixture()
    destination = collection(snapshot, "nic")["items"][1]
    old_scope = collection(snapshot, "nic")["scope"]
    new_scope = "/subscriptions/b"
    old_vnet = collection(snapshot, "vnet")["items"][0]["id"]
    new_vnet = old_vnet.replace(old_scope, new_scope)
    copied = copy.deepcopy(collection(snapshot, "vnet")["items"][0])
    copied["id"] = new_vnet
    snapshot["collections"].append({"type": "vnet", "scope": new_scope, "service": "network", "status": "collected", "items": [copied]})
    subnet = collection(snapshot, "subnet")["items"][1]
    subnet["id"] = subnet["id"].replace(old_vnet, new_vnet)
    collection(snapshot, "subnet")["items"].remove(subnet)
    snapshot["collections"].append({"type": "subnet", "scope": new_scope, "service": "network", "status": "collected", "items": [subnet]})
    for configuration in destination["properties"]["ipConfigurations"]:
        configuration["properties"]["subnet"]["id"] = subnet["id"]
    collection(snapshot, "nic")["items"].remove(destination)
    destination["id"] = destination["id"].replace(old_scope, new_scope)
    snapshot["collections"].append({"type": "nic", "scope": new_scope, "service": "network", "status": "collected", "items": [destination]})
    snapshot["scopes"].append(new_scope)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "overlapping_address_domains" for g in result["unresolved_dependencies"])


def test_gcp_peered_overlapping_project_domains_stay_unknown():
    snapshot = gcp_fixture()
    network = collection(snapshot, "network")["items"][0]
    remote = copy.deepcopy(network)
    remote["selfLink"] = remote["selfLink"].replace("projects/host/", "projects/other/")
    remote["peerings"] = [{"network": network["selfLink"], "state": "ACTIVE", "stackType": "IPV4_IPV6"}]
    network["peerings"] = [{"network": remote["selfLink"], "state": "ACTIVE", "stackType": "IPV4_IPV6"}]
    snapshot["collections"].append({"type": "network", "scope": "projects/other", "service": "compute", "status": "collected", "items": [remote]})
    subnet = collection(snapshot, "subnetwork")["items"][1]
    subnet["network"] = remote["selfLink"]
    subnet["selfLink"] = subnet["selfLink"].replace("projects/host/", "projects/other/")
    subnet["ipCidrRange"] = "10.0.1.0/24"
    destination = collection(snapshot, "instance", "projects/host")["items"][0]
    destination["networkInterfaces"][0].update(network=remote["selfLink"], subnetwork=subnet["selfLink"], networkIP="10.0.1.20")
    snapshot["collections"] += [{"type": "firewall", "scope": "projects/other", "service": "compute", "status": "empty", "items": []},
        {"type": "route", "scope": "projects/other", "service": "compute", "status": "empty", "items": []}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "overlapping_address_domains" for g in result["unresolved_dependencies"])


def test_k8s_cluster_mismatch_and_duplicate_addresses_do_not_join():
    snapshot = k8s_fixture()
    destination = collection(snapshot, "pod")["items"][1]
    destination["provenance"]["cluster_id"] = "cluster-b"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cluster_namespace_context_missing" for g in result["unresolved_dependencies"])
    destination["provenance"]["cluster_id"] = "cluster-a"
    destination["status"].update(podIP="10.0.1.10", podIPs=[{"ip": "10.0.1.10"}])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_address_collision" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("provider,family", [("aws", "ipv4"), ("aws", "ipv6"),
    ("azure", "ipv4"), ("azure", "ipv6"), ("gcp", "ipv4"), ("gcp", "ipv6")])
def test_observed_third_interface_with_selected_ip_makes_path_unknown(provider, family):
    snapshot = FIXTURES[provider][0]()
    if provider == "aws":
        interfaces = collection(snapshot, "network_interface")["items"]
        duplicate = copy.deepcopy(interfaces[1])
        duplicate.update(id="eni-duplicate", NetworkInterfaceId="eni-duplicate")
        interfaces.append(duplicate)
    elif provider == "azure":
        interfaces = collection(snapshot, "nic")["items"]
        duplicate = copy.deepcopy(interfaces[1])
        duplicate["id"] += "-duplicate"
        duplicate["name"] = "duplicate"
        interfaces.append(duplicate)
    else:
        instances = collection(snapshot, "instance", "projects/host")["items"]
        duplicate = copy.deepcopy(instances[0])
        duplicate["name"] = "duplicate"
        instances.append(duplicate)
    result = query(reseal(snapshot), family=family)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "endpoint_address_collision" for g in result["unresolved_dependencies"])


def test_same_ip_in_another_aws_vpc_is_not_an_endpoint_collision():
    snapshot = aws_fixture()
    interfaces = collection(snapshot, "network_interface")["items"]
    duplicate = copy.deepcopy(interfaces[1])
    duplicate.update(id="eni-other-vpc", NetworkInterfaceId="eni-other-vpc", VpcId="vpc-other")
    interfaces.append(duplicate)
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed", result


def test_aws_shared_vpc_ip_claim_in_another_account_is_ambiguous():
    snapshot = aws_fixture()
    other_scope = "222222222222/us-east-1"
    duplicate = copy.deepcopy(collection(snapshot, "network_interface")["items"][1])
    duplicate.update(id="eni-participant", NetworkInterfaceId="eni-participant", OwnerId="222222222222")
    snapshot["scopes"].append(other_scope)
    snapshot["collections"].append({"type": "network_interface", "scope": other_scope,
        "service": "ec2", "status": "collected", "items": [duplicate]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "endpoint_address_collision" for g in result["unresolved_dependencies"])


def test_aws_same_vpc_id_and_ip_in_another_region_is_not_a_collision():
    snapshot = aws_fixture()
    other_scope = "222222222222/us-west-2"
    duplicate = copy.deepcopy(collection(snapshot, "network_interface")["items"][1])
    duplicate.update(id="eni-other-region", NetworkInterfaceId="eni-other-region",
        OwnerId="222222222222", Region="us-west-2")
    snapshot["scopes"].append(other_scope)
    snapshot["collections"].append({"type": "network_interface", "scope": other_scope,
        "service": "ec2", "status": "collected", "items": [duplicate]})
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed", result


@pytest.mark.parametrize("direction", ["INGRESS", "EGRESS"])
def test_gcp_omitted_firewall_range_defaults_only_to_ipv4(direction):
    snapshot = gcp_fixture()
    firewall = collection(snapshot, "firewall", "projects/host")["items"]
    firewall.append({"name": "ipv4-only-deny", "network": firewall[0]["network"],
        "direction": direction, "priority": 50, "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    snapshot = reseal(snapshot)
    assert query(snapshot, family="ipv4")["decision"] == "blocked"
    assert query(snapshot, family="ipv6")["decision"] == "allowed"


@pytest.mark.parametrize("provider,kind", [("aws", "network_interface"), ("azure", "nic")])
def test_vm_own_private_ip_is_not_declared_blocked_by_cloud_boundary_rules(provider, kind):
    snapshot = FIXTURES[provider][0]()
    if provider == "azure":
        rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
        for rule in rules:
            rule["properties"]["access"] = "Deny"
    snapshot = reseal(snapshot)
    selected = native(snapshot, kind, "source")
    result = evaluate_reachability(snapshot, selected, selected, "tcp", 443, 54321)
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "self_traffic_semantics_unproven" for g in result["unresolved_dependencies"])


def test_observed_ip_collision_survives_shared_matrix_index_with_evidence():
    snapshot = aws_fixture()
    interfaces = collection(snapshot, "network_interface")["items"]
    duplicate = copy.deepcopy(interfaces[1])
    duplicate.update(id="eni-duplicate", NetworkInterfaceId="eni-duplicate")
    interfaces.append(duplicate)
    snapshot = reseal(snapshot)
    selected = [native(snapshot, "network_interface", name) for name in ("source", "destination")]
    results = evaluate_reachability_matrix(snapshot, selected, "tcp", 443, 54321)
    assert len(results) == 2
    for result in results:
        assert result["decision"] == "unknown"
        gap = next(g for g in result["unresolved_dependencies"] if g["code"] == "endpoint_address_collision")
        assert any(ref["native_id"] == "eni-duplicate" for ref in gap["evidence_refs"])


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_same_ip_in_another_network_is_not_an_endpoint_collision(provider):
    snapshot = FIXTURES[provider][0]()
    if provider == "azure":
        interfaces = collection(snapshot, "nic")["items"]
        duplicate = copy.deepcopy(interfaces[1])
        duplicate["id"] += "-other-network"
        duplicate["name"] = "other-network"
        for config in duplicate["properties"]["ipConfigurations"]:
            config["properties"]["subnet"]["id"] = config["properties"]["subnet"]["id"].replace(
                "/virtualNetworks/net/", "/virtualNetworks/other/")
        interfaces.append(duplicate)
    else:
        instances = collection(snapshot, "instance", "projects/host")["items"]
        duplicate = copy.deepcopy(instances[0])
        duplicate["name"] = "other-network"
        duplicate["networkInterfaces"][0]["network"] = duplicate["networkInterfaces"][0]["network"].replace(
            "/networks/net", "/networks/other")
        instances.append(duplicate)
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_k8s_host_network_and_service_translation_are_explicitly_unsupported():
    snapshot = k8s_fixture()
    collection(snapshot, "pod")["items"][0]["spec"]["hostNetwork"] = True
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "host_network_semantics_unknown" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("spec", [None, {}, {"containers": []},
    {"containers": [{"name": "application"}], "hostNetwork": {}},
    {"containers": [{}]}])
def test_k8s_incomplete_pod_spec_cannot_prove_ordinary_pod_routing(spec):
    snapshot = k8s_fixture()
    source = collection(snapshot, "pod")["items"][0]
    if spec is None:
        source.pop("spec")
    else:
        source["spec"] = spec
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "pod_network_spec_unresolved" for g in result["unresolved_dependencies"])


def test_k8s_ephemeral_container_cannot_supply_named_networkpolicy_port():
    snapshot = k8s_fixture()
    destination = collection(snapshot, "pod")["items"][1]
    destination["spec"]["containers"][0]["ports"] = []
    destination["spec"]["ephemeralContainers"] = [{"name": "debug", "ports": [
        {"name": "https", "containerPort": 443, "protocol": "TCP"}]}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("restart_policy", [None, "Always"])
def test_k8s_init_container_alone_cannot_prove_named_networkpolicy_port(restart_policy):
    snapshot = k8s_fixture()
    destination = collection(snapshot, "pod")["items"][1]
    destination["spec"]["containers"][0]["ports"] = []
    init = {"name": "setup", "ports": [{"name": "https", "containerPort": 443, "protocol": "TCP"}]}
    if restart_policy:
        init["restartPolicy"] = restart_policy
    destination["spec"]["initContainers"] = [init]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "network_policy_selector_unresolved" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("provider", FIXTURES)
def test_udp_new_flows_use_native_udp_rules(provider):
    snapshot = FIXTURES[provider][0]()
    for c in snapshot["collections"]:
        for item in c["items"]:
            if c["type"] == "security_group":
                for field in ("IpPermissions", "IpPermissionsEgress"):
                    for rule in item[field]:
                        rule["IpProtocol"] = "udp"
            elif c["type"] == "nsg":
                for rule in item["properties"]["securityRules"]:
                    rule["properties"]["protocol"] = "Udp"
            elif c["type"] == "firewall":
                for field in ("allowed", "denied"):
                    for rule in item.get(field, []):
                        rule["IPProtocol"] = "udp"
            elif c["type"] == "networkpolicy":
                for field in ("ingress", "egress"):
                    for rule in item["spec"].get(field, []):
                        for port in rule.get("ports", []):
                            port["protocol"] = "UDP"
            elif c["type"] == "pod":
                item["spec"]["containers"][0]["ports"][0]["protocol"] = "UDP"
    assert query(reseal(snapshot), protocol="udp")["decision"] == "allowed"


def test_earlier_unresolved_ordered_rule_cannot_be_skipped_to_allow():
    snapshot = aws_fixture()
    collection(snapshot, "network_acl")["items"][0]["Entries"].insert(0, {"Egress": True, "RuleNumber": 1, "Protocol": "6", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    assert query(reseal(snapshot))["decision"] == "unknown"
    snapshot = gcp_fixture()
    collection(snapshot, "firewall")["items"].insert(0, {"name": "unknown", "network": collection(snapshot, "network")["items"][0]["selfLink"], "priority": 1,
        "sourceRanges": ["invalid-prefix"], "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_selected_path_benchmark_large_account_is_bounded_not_all_pairs():
    snapshot = aws_fixture()
    groups = collection(snapshot, "security_group")["items"]
    groups += [{"id": f"unrelated-{i}", "GroupId": f"unrelated-{i}", "VpcId": "vpc-a", "IpPermissions": [], "IpPermissionsEgress": []} for i in range(5000)]
    snapshot = reseal(snapshot)
    start = time.perf_counter()
    result = query(snapshot)
    elapsed = time.perf_counter() - start
    assert result["decision"] == "allowed"
    assert len(result["evidence_refs"]) < 40
    assert len(result["routes"]) == 2
    assert elapsed < 5, f"selected path evaluation unexpectedly unbounded: {elapsed:.3f}s"


@pytest.mark.parametrize("provider,path", [
    ("aws", "aws-snapshot.json"), ("azure", "azure-uncapped/azure-snapshot.json"), ("k8s", "k8s-snapshot.json")])
def test_real_captured_snapshots_have_truthful_explainable_states(provider, path):
    capture = Path(__file__).resolve().parents[1] / ".cache/peaso-qa/task_02a312b5ac1f" / path
    if not capture.is_file():
        pytest.skip("private QA capture is unavailable; no live collection attempted")
    captured = json.loads(capture.read_text())
    snapshot = network_snapshot(captured)
    kinds = {"aws": {"network_interface", "instance"}, "azure": {"nic", "vm"}, "k8s": {"pod"}}[provider]
    endpoints = [r for r in resources(snapshot) if r["type"] in kinds]
    source = endpoints[0]["id"] if endpoints else "not-collected:source"
    destination = endpoints[-1]["id"] if endpoints else "not-collected:destination"
    result = evaluate_reachability(snapshot, source, destination, "tcp", 443, 54321)
    assert result["snapshot_id"] == captured["snapshot_id"]
    assert result["decision"] in {"allowed", "blocked", "unknown"}
    if result["decision"] == "allowed":
        assert result["unresolved_dependencies"] == []
    elif result["decision"] == "unknown":
        assert result["unresolved_dependencies"]
    else:
        assert any(p["decision"] == "blocked" for p in result["policy_decisions"] + result["routes"])
