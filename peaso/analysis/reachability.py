"""Selected-flow native configuration model, never a probe or a path explorer.

Only TCP/UDP new flows between explicit private endpoints are supported. Every
allowance needs complete associations, policy/routing context, and address domain
evidence; unknown is a first-class result. See docs/network-and-exposure.md.
"""
from __future__ import annotations

import copy
import ipaddress
import re
from collections import defaultdict

from peaso.snapshot import make_snapshot, resource_id, resources, validate
from .common import gcp_interface_resource_id

# Includes legacy/imported snapshot types as well as native collector types.
# The collection planner filters this set through each collector's supported
# inventories; keep imported types here so a conflicting policy is not erased
# from a projected network snapshot before the evaluator sees it.
REACHABILITY_TYPES = {
    "aws": frozenset({"instance", "network_interface", "vpc", "subnet", "security_group", "managed_prefix_list", "network_acl",
        "route_table", "vpc_peering", "nat_gateway", "transit_gateway", "transit_gateway_attachment",
        "transit_gateway_vpc_attachment",
        "transit_gateway_route_table", "vpc_endpoint", "load_balancer"}),
    "azure": frozenset({"vm", "nic", "vnet", "subnet", "nsg", "route_table", "vnet_peering", "service_tag",
        "effective_route", "security_admin_rule", "public_ip", "nat_gateway", "load_balancer", "application_gateway"}),
    "gcp": frozenset({"instance", "network", "subnetwork", "firewall", "route", "shared_vpc", "router",
        "firewall_policy", "hierarchical_firewall_policy", "network_firewall_policy", "firewall_policy_association", "effective_firewall", "policy_based_route",
        "forwarding_rule", "backend_service"}),
    "k8s": frozenset({"pod", "namespace", "networkpolicy", "node", "service", "ingress", "daemonset",
        "cni_configuration", "cilium_networkpolicy", "cilium_clusterwide_networkpolicy",
        "calico_networkpolicy", "calico_global_networkpolicy", "admin_networkpolicy",
        "baseline_admin_networkpolicy", "cluster_networkpolicy", "api_discovery"}),
}


def network_snapshot(snapshot):
    """Seal a small native-network artifact without inventing collection coverage.

    Whole dependency collections and their original statuses remain intact.
    Native resource IDs and GCP embedded-interface IDs remain stable across
    projection. The original source digest is disclosed separately from this
    derived artifact's digest.
    """
    snapshot = validate(snapshot, read_only=True)
    metadata = {k: copy.deepcopy(v) for k, v in snapshot.get("metadata", {}).items()
        if k in {"network_context", "cluster_id", "account_id", "account_ids", "tenant_id", "requested_scopes",
                 "resolved_scopes", "scope_coverage", "collection", "collector", "limits", "budget"}}
    metadata["original_snapshot_id"] = snapshot.get("metadata", {}).get("original_snapshot_id", snapshot["snapshot_id"])
    metadata["projection"] = "complete native network dependency collections; unrelated identity inventory omitted"
    return make_snapshot(snapshot["provider"], snapshot["scopes"],
        [c for c in snapshot["collections"] if c["type"] in REACHABILITY_TYPES[snapshot["provider"]]],
        created_at=snapshot["created_at"], metadata=metadata)


def _all(values):
    values = list(values)
    return False if False in values else None if None in values else True


def _any(values):
    values = list(values)
    return True if True in values else None if None in values else False


def _cidr(value, address):
    if not isinstance(value, str):
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
        return address.version == network.version and address in network
    except (ValueError, TypeError):
        return None


def _ports(value, port):
    if value == "*":
        return True
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, int) or str(value).isdigit():
            low = high = int(value)
        else:
            low, high = (int(p) for p in str(value).split("-"))
        if not 0 <= low <= high <= 65535:
            return None
        if port is None:
            return True if low <= 1 and high == 65535 else None
        return low <= port <= high
    except (ValueError, TypeError):
        return None


def _sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


def _protocol(native, requested):
    text = str(native).lower()
    if text in {"-1", "*", "all", "any"}:
        return True
    if text in {"tcp", "6", "udp", "17", "icmp", "1", "icmpv6", "58", "sctp", "132", "esp", "50", "ah", "51"}:
        return text in {requested, "6" if requested == "tcp" else "17"}
    return None


def _aws_protocol(native, requested):
    if not isinstance(native, str):
        return None
    if native == "-1":
        return True
    if native in {"tcp", "udp", "icmp", "icmpv6"}:
        return native == requested
    if isinstance(native, str) and native.isascii() and native.isdecimal():
        number = int(native)
        if 0 <= number <= 255:
            return number == (6 if requested == "tcp" else 17)
    return None


def _azure_protocol(native, requested):
    if not isinstance(native, str):
        return None
    if native == "*":
        return True
    if native in {"Tcp", "Udp", "Icmp", "Esp", "Ah"}:
        return native.lower() == requested
    return None


class _Model:
    def __init__(self, snapshot, query, index=None):
        self.snapshot = snapshot
        self.provider = snapshot["provider"]
        if index is None:
            seen_native = set()
            self.identity_collisions = set()
            for collection in snapshot["collections"]:
                for item in collection["items"]:
                    key = (collection["type"], collection["scope"],
                        resource_id(self.provider, collection["type"], collection["scope"], item))
                    if key in seen_native:
                        self.identity_collisions.add(key)
                    seen_native.add(key)
            self.items = resources(snapshot)
            self.by_id = {r["id"]: r for r in self.items}
            self.kinds = defaultdict(list)
            self.native = defaultdict(list)
            self.collections = defaultdict(list)
            for resource in self.items:
                self.kinds[resource["type"]].append(resource)
                aliases = {str(resource["native_id"]), str(resource["data"].get("id", "")), str(resource["data"].get("selfLink", ""))}
                for alias in aliases - {""}:
                    alias = alias.lower() if self.provider == "azure" else _gcp_id(alias) if self.provider == "gcp" else alias
                    self.native[(resource["type"], resource["scope"], alias)].append(resource)
                    self.native[(resource["type"], None, alias)].append(resource)
            if self.provider == "gcp":
                for instance in self.kinds["instance"]:
                    interfaces = instance["data"].get("networkInterfaces")
                    if not isinstance(interfaces, list):
                        continue
                    for i, interface in enumerate(interfaces):
                        if not isinstance(interface, dict):
                            continue
                        native = f"{instance['native_id']}/networkInterfaces/{i}"
                        ident = gcp_interface_resource_id(instance, i)
                        self.by_id[ident] = {"id": ident, "native_id": native, "type": "instance_interface",
                            "provider": "gcp", "scope": instance["scope"],
                            "data": {"instance_resource_id": instance["id"], "interface_index": i}}
            for collection in snapshot["collections"]:
                self.collections[(collection["type"], collection["scope"])].append(collection)
            self.private_ip_collision_cache = {}
        else:
            (self.items, self.by_id, self.kinds, self.native, self.collections,
                self.identity_collisions, self.private_ip_collision_cache) = index
        self.index = (self.items, self.by_id, self.kinds, self.native, self.collections,
            self.identity_collisions, self.private_ip_collision_cache)
        self.result = {"decision": "unknown", "provider": self.provider,
            "snapshot_id": snapshot.get("metadata", {}).get("original_snapshot_id", snapshot["snapshot_id"]),
            "scoped_snapshot_id": snapshot["snapshot_id"], "query": query, "endpoints": {},
            "routes": [], "policy_decisions": [], "translations": [], "unresolved_dependencies": [],
            "evidence_refs": [], "context_evidence": [], "modeled_configuration": True, "application_listening": "unknown",
            "new_flow_only": True, "semantics": "A configuration allowance is not listening, packet delivery, or live telemetry"}
        self._evidence = set()
        self._context_seen = set()

    def ref(self, resource, path):
        ref = {"snapshot_id": self.result["snapshot_id"], "scoped_snapshot_id": self.snapshot["snapshot_id"],
            "resource_id": resource["id"], "native_id": resource["native_id"], "type": resource["type"],
            "scope": resource["scope"], "path": path}
        collections = self.collections.get((resource["type"], resource["scope"]), [])
        ref["collection_status"] = collections[0]["status"] if len(collections) == 1 else "unknown"
        key = (resource["id"], path)
        if key not in self._evidence:
            self.result["evidence_refs"].append(ref)
            self._evidence.add(key)
        return ref

    def gap(self, code, message, refs=()):
        value = {"code": code, "message": message, "evidence_refs": list(refs)}
        if value not in self.result["unresolved_dependencies"]:
            self.result["unresolved_dependencies"].append(value)
        return "unknown"

    def step(self, layer, decision, message, refs=(), **details):
        step = {"decision": decision, "message": message, "evidence_refs": list(refs), **details}
        self.result["routes" if layer == "route" else "policy_decisions"].append(step)
        return decision

    def complete(self, kind, scope):
        collections = self.collections.get((kind, scope), [])
        return len(collections) == 1 and collections[0]["status"] in {"collected", "empty"}

    def find(self, kind, native, scope=None):
        expected = str(native).lower() if self.provider == "azure" else _gcp_id(str(native)) if self.provider == "gcp" else str(native)
        # Multiple textual aliases may normalize to one provider identifier.
        matches = {r["id"]: r for r in self.native.get((kind, scope, expected), [])}
        matches = list(matches.values())
        return matches[0] if len(matches) == 1 else None

    def context(self, name):
        context = self.snapshot.get("metadata", {}).get("network_context", {}).get(self.provider, {}).get(name, {})
        context = context if isinstance(context, dict) else {}
        if name not in self._context_seen:
            self._context_seen.add(name)
            self.result["context_evidence"].append({"path": f"metadata.network_context.{self.provider}.{name}",
                "snapshot_id": self.result["snapshot_id"], "scoped_snapshot_id": self.snapshot["snapshot_id"],
                "status": context.get("status", "unknown"), "complete": context.get("complete", False),
                "source_evidence": copy.deepcopy(context.get("source_evidence", []))})
        return context

    def context_complete(self, name):
        value = self.context(name)
        evidence = value.get("source_evidence")
        return value.get("status") == "collected" and value.get("complete") is True and isinstance(evidence, list) and bool(evidence) and all(isinstance(e, dict) for e in evidence)


def _gcp_id(value):
    return "projects/" + value.split("/projects/", 1)[1] if "/projects/" in value else value.lstrip("/")


def _gcp_network_id(resource):
    # Native SDK objects often have a numeric id in addition to selfLink.
    # The network reference is project-qualified; a numeric id is not that URL.
    return _gcp_id(resource["data"].get("selfLink", resource["data"].get("_resource_id", resource["native_id"])))


def _gcp_scoped_ref(value, kind, scope):
    if not isinstance(value, str) or not isinstance(scope, str):
        return None
    identity = _gcp_id(value)
    parts = identity.split("/")
    tail = ["global", "networks"] if kind == "network" else ["regions", None, "subnetworks"]
    if parts[:1] == ["projects"]:
        project, path = parts[1], parts[2:]
    elif scope.startswith("projects/") and len(scope.split("/")) == 2:
        project, path = scope.split("/", 1)[1], parts
    else:
        return None
    if not project or len(path) != len(tail) + 1 or not path[-1]:
        return None
    if any(expected is not None and actual != expected for actual, expected in zip(path, tail)):
        return None
    if any(not part for part in path):
        return None
    return f"projects/{project}/{'/'.join(path)}"


def _gcp_peering_network_id(value, owner):
    if not isinstance(value, str):
        return None
    network_id = _gcp_id(value)
    if network_id.startswith("global/networks/"):
        if len(network_id.split("/")) != 3 or not network_id.rsplit("/", 1)[-1]:
            return None
        owner_id = _gcp_network_id(owner).split("/")
        if len(owner_id) != 5 or owner_id[0] != "projects" or owner_id[2:4] != ["global", "networks"]:
            return None
        return f"projects/{owner_id[1]}/{network_id}"
    parts = network_id.split("/")
    return network_id if len(parts) == 5 and parts[0] == "projects" and parts[2:4] == ["global", "networks"] and parts[1] and parts[4] else None


def _gcp_owner_scope(model, kind, network):
    identity = _gcp_network_id(network)
    parts = identity.split("/")
    if len(parts) < 2 or parts[0] != "projects":
        return None
    aliases = {"/".join(parts[:2]), parts[1]}
    scopes = {scope for (actual_kind, scope) in model.collections if actual_kind == kind and scope in aliases}
    return next(iter(scopes)) if len(scopes) == 1 else None


def _address(model, candidates, family, resource):
    addresses = set()
    for candidate in candidates:
        if candidate is None:
            continue
        if not isinstance(candidate, str):
            model.gap("malformed_endpoint_address", "Native endpoint addresses must be strings", [model.ref(resource, "addresses")])
            return None
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            model.gap("malformed_endpoint_address", "A native endpoint address is malformed", [model.ref(resource, "addresses")])
            return None
        if address.version == (4 if family == "ipv4" else 6):
            addresses.add(address)
    if len(addresses) != 1:
        model.gap("endpoint_address_missing" if not addresses else "endpoint_address_ambiguous",
            "The selected family requires exactly one native private endpoint address", [model.ref(resource, "addresses")])
        return None
    return addresses.pop()


def _aws_endpoint(model, resource, family):
    data = resource["data"]
    if resource["type"] not in {"instance", "network_interface"}:
        model.gap("unsupported_endpoint_type", "AWS selected endpoints must be an instance or network interface", [model.ref(resource, "data")])
        return None
    if resource["type"] == "instance":
        interfaces = data.get("NetworkInterfaces")
        if not isinstance(interfaces, list) or len(interfaces) != 1 or not isinstance(interfaces[0], dict):
            model.gap("endpoint_interface_ambiguous", "An instance needs exactly one native network interface; select an ENI for a multi-interface instance",
                [model.ref(resource, "NetworkInterfaces")])
            return None
        if not isinstance(data.get("State"), dict) or data["State"].get("Name") != "running":
            model.gap("endpoint_not_running", "The selected EC2 instance is not proven running", [model.ref(resource, "State.Name")])
    endpoint = resource
    if resource["type"] == "instance":
        declared = interfaces[0]
        collected = model.find("network_interface", declared.get("NetworkInterfaceId"), resource["scope"])
        if collected:
            attachment = collected["data"].get("Attachment")
            if (not isinstance(attachment, dict) or attachment.get("InstanceId") != data.get("InstanceId", resource["native_id"]) or
                attachment.get("Status") != "attached" or
                any(declared.get(field) is not None and declared[field] != collected["data"].get(field)
                    for field in ("SubnetId", "VpcId", "PrivateIpAddress"))):
                model.gap("endpoint_association_mismatch", "The collected ENI attachment or network identity disagrees with the selected instance",
                    [model.ref(resource, "NetworkInterfaces[0]"), model.ref(collected, "Attachment/SubnetId/VpcId/PrivateIpAddress")])
                return None
            endpoint, data = collected, collected["data"]
        else:
            model.gap("endpoint_interface_inventory_missing", "The selected instance's native ENI was not collected", [model.ref(resource, "NetworkInterfaces[0].NetworkInterfaceId")])
            data = declared
    if endpoint["type"] == "network_interface":
        attachment = data.get("Attachment")
        instance_id = attachment.get("InstanceId") if isinstance(attachment, dict) else None
        if data.get("Status") != "in-use" or not isinstance(attachment, dict) or attachment.get("Status") != "attached" or not isinstance(instance_id, str):
            model.gap("endpoint_interface_not_attached", "The selected native ENI is not proven attached to an EC2 instance",
                [model.ref(endpoint, "Status/Attachment")])
        elif not model.complete("instance", endpoint["scope"]):
            model.gap("endpoint_instance_inventory_incomplete", "The attached EC2 instance inventory is missing or incomplete",
                [model.ref(endpoint, "Attachment.InstanceId")])
        else:
            instance = model.find("instance", instance_id, endpoint["scope"])
            interfaces = instance["data"].get("NetworkInterfaces") if instance else None
            matching = ([item for item in interfaces if isinstance(item, dict) and
                item.get("NetworkInterfaceId") == endpoint["native_id"]]
                if isinstance(interfaces, list) else [])
            if instance is None or len(matching) != 1 or any(
                matching[0].get(field) != data.get(field) for field in ("SubnetId", "VpcId", "PrivateIpAddress")):
                model.gap("endpoint_association_mismatch", "The attached instance does not identify this ENI exactly once",
                    [model.ref(endpoint, "Attachment.InstanceId/SubnetId/VpcId/PrivateIpAddress"),
                     model.ref(instance, "NetworkInterfaces") if instance else model.ref(endpoint, "Attachment.InstanceId")])
            elif not isinstance(instance["data"].get("State"), dict) or instance["data"]["State"].get("Name") != "running":
                model.gap("endpoint_not_running", "The attached EC2 instance is not proven running", [model.ref(instance, "State.Name")])
    if data.get("InterfaceType", "interface") not in {"interface"}:
        model.gap("unsupported_interface_type", "Appliance, endpoint, and managed interface translations are not modeled", [model.ref(endpoint, "InterfaceType")])
        return None
    candidates = [data.get("PrivateIpAddress")]
    candidates += [p.get("PrivateIpAddress") for p in data.get("PrivateIpAddresses", [])]
    candidates += [p.get("Ipv6Address") for p in data.get("Ipv6Addresses", [])]
    address = _address(model, candidates, family, endpoint)
    groups = data.get("Groups", data.get("SecurityGroups"))
    if groups is None:
        model.gap("security_group_association_missing", "Endpoint security-group associations were not collected", [model.ref(endpoint, "Groups")])
    elif not isinstance(groups, list) or any(not isinstance(group, dict) or
        not isinstance(group.get("GroupId"), str) or not group["GroupId"] for group in groups):
        model.gap("security_group_association_malformed", "Endpoint security-group associations need nonempty native group IDs",
            [model.ref(endpoint, "Groups/SecurityGroups")])
        groups = None
    if groups is not None and "Groups" in data and "SecurityGroups" in data:
        alternate = data["SecurityGroups"]
        if (not isinstance(alternate, list) or any(not isinstance(group, dict) or
            not isinstance(group.get("GroupId"), str) or not group["GroupId"] for group in alternate) or
            {group["GroupId"] for group in groups} != {group["GroupId"] for group in alternate}):
            model.gap("security_group_association_malformed", "Conflicting native security-group association fields cannot establish peer membership",
                [model.ref(endpoint, "Groups/SecurityGroups")])
            groups = None
    subnet = model.find("subnet", data.get("SubnetId"), resource["scope"])
    vpc = model.find("vpc", data.get("VpcId"), resource["scope"])
    if subnet is None or vpc is None:
        model.gap("network_domain_missing", "Selected subnet and VPC facts are required in their exact account/region scope", [model.ref(endpoint, "SubnetId/VpcId")])
    elif subnet["data"].get("VpcId") != data.get("VpcId"):
        model.gap("network_domain_mismatch", "Endpoint and subnet VPC associations disagree", [model.ref(subnet, "VpcId")])
        subnet = None
    if address is not None and subnet:
        ranges = [subnet["data"].get("CidrBlock")] + [v.get("Ipv6CidrBlock") for v in subnet["data"].get("Ipv6CidrBlockAssociationSet", [])
            if v.get("Ipv6CidrBlockState", {}).get("State") == "associated"]
        matches = [_cidr(value, address) for value in ranges if value]
        if not matches or True not in matches:
            model.gap("endpoint_outside_subnet", "Private endpoint address is not proven inside the selected subnet address family", [model.ref(subnet, "CidrBlock/Ipv6CidrBlockAssociationSet")])
    if address is not None and vpc and not any(_cidr(p, address) is True for p in _aws_vpc_ranges(vpc["data"])):
        model.gap("network_domain_missing", "Selected address is not proven inside the native VPC address family", [model.ref(vpc, "CidrBlock/CidrBlockAssociationSet/Ipv6CidrBlockAssociationSet")])
    for dependency in (endpoint, subnet, vpc):
        if dependency and not model.complete(dependency["type"], dependency["scope"]):
            model.gap("endpoint_association_incomplete", "Native endpoint/subnet/VPC association collection is missing or partial", [model.ref(dependency, "data")])
    return {"resource": endpoint, "selected": resource, "address": address, "scope": resource["scope"],
            "subnet": subnet, "vpc": vpc, "group_ids": list(dict.fromkeys(g.get("GroupId") for g in groups)) if isinstance(groups, list) else None}


def _aws_prefix_list_networks(model, prefix_list_id, scope):
    if not isinstance(prefix_list_id, str) or not model.complete("managed_prefix_list", scope):
        return None
    prefix_list = model.find("managed_prefix_list", prefix_list_id, scope)
    if prefix_list is None:
        return None
    data = prefix_list["data"]
    entries = data.get("Entries")
    version = data.get("Version")
    model.ref(prefix_list, "Version/State/Entries")
    if (data.get("State") not in {"create-complete", "modify-complete", "restore-complete"} or
        isinstance(version, bool) or not isinstance(version, int) or version < 1 or
        data.get("EntriesVersion") != version or not isinstance(entries, dict) or
        entries.get("collection_status") != "collected" or not isinstance(entries.get("items"), list)):
        return None
    family = data.get("AddressFamily")
    if family not in {"IPv4", "IPv6"}:
        return None
    networks = []
    for entry in entries["items"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("Cidr"), str):
            return None
        try:
            network = ipaddress.ip_network(entry["Cidr"], strict=False)
        except ValueError:
            return None
        if network.version != (4 if family == "IPv4" else 6):
            return None
        networks.append(network)
    return networks


def _aws_prefix_list_match(model, prefix_list_id, scope, address):
    networks = _aws_prefix_list_networks(model, prefix_list_id, scope)
    return None if networks is None else any(address in network for network in networks if address.version == network.version)


def _aws_sg(model, endpoint, peer, direction, query):
    groups = endpoint["group_ids"]
    if not groups:
        return model.gap("security_group_association_missing", "The selected endpoint lacks a complete nonempty security-group association")
    known = []
    known_ip_allow = False
    known_cross_vpc_group_allow = False
    uncertain = False
    potential_translated_allow = False
    refs = []
    key = "IpPermissionsEgress" if direction == "egress" else "IpPermissions"
    for group_id in groups:
        group = model.find("security_group", group_id, endpoint["scope"])
        if group is None or key not in group["data"] or not model.complete("security_group", endpoint["scope"]):
            uncertain = True
            continue
        if endpoint["vpc"] is None or group["data"].get("VpcId") != endpoint["vpc"]["data"].get("VpcId"):
            uncertain = True
            continue
        refs.append(model.ref(group, key))
        if not isinstance(group["data"][key], list):
            uncertain = True
            continue
        for index, rule in enumerate(group["data"][key]):
            selector_keys = ("IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs")
            if (not isinstance(rule, dict) or any(
                not isinstance(rule.get(field, []), list) or
                any(not isinstance(value, dict) for value in rule.get(field, []))
                for field in selector_keys)):
                uncertain = True
                continue
            proto = _aws_protocol(rule.get("IpProtocol"), query["protocol"])
            port = True if str(rule.get("IpProtocol")) == "-1" else _all([
                _ports(f"{rule.get('FromPort')}-{rule.get('ToPort')}", query["destination_port"])])
            protocol_port_match = _all([proto, port])
            # An unmodeled appliance can rewrite addresses and destination
            # ports before this downstream SG. Any usable allow selector may
            # therefore match the translated flow, even if this query's
            # original protocol/port does not match the rule.
            if any(rule.get(field) for field in selector_keys):
                potential_translated_allow = True
            if not any(rule.get(field) for field in selector_keys):
                if protocol_port_match is not False:
                    uncertain = True
                continue
            selectors = [_cidr(r.get("CidrIp"), peer["address"]) for r in rule.get("IpRanges", [])]
            selectors += [_cidr(r.get("CidrIpv6"), peer["address"]) for r in rule.get("Ipv6Ranges", [])]
            for prefix_list in rule.get("PrefixListIds", []):
                selectors.append(_aws_prefix_list_match(model, prefix_list.get("PrefixListId"), endpoint["scope"], peer["address"]))
            group_selectors = []
            for pair in rule.get("UserIdGroupPairs", []):
                if (not isinstance(pair.get("GroupId"), str) or not pair["GroupId"] or
                    ("VpcId" in pair and not isinstance(pair["VpcId"], str)) or
                    ("UserId" in pair and not isinstance(pair["UserId"], str))):
                    group_selectors.append(None)
                    continue
                selected = pair.get("GroupId") in peer["group_ids"] if peer["group_ids"] else None
                if selected and pair.get("PeeringStatus") not in (None, "active"):
                    selected = None
                if selected and pair.get("VpcId") and peer["vpc"] and pair["VpcId"] != peer["vpc"]["data"].get("VpcId"):
                    selected = False
                peer_group = model.find("security_group", pair.get("GroupId"), peer["scope"])
                # A shared security group may belong to a different account
                # than its attached ENI. UserId is the SG owner, not ENI owner.
                peer_account = peer_group["data"].get("OwnerId") if peer_group else None
                if peer_group:
                    refs.append(model.ref(peer_group, "OwnerId/VpcId"))
                if (selected and peer_group and peer["vpc"] and
                    peer_group["data"].get("VpcId") != peer["vpc"]["data"].get("VpcId")):
                    selected = None
                if selected and pair.get("UserId") and str(pair["UserId"]) != str(peer_account):
                    selected = None if peer_account is None else False
                if selected and endpoint["vpc"] and peer["vpc"] and endpoint["vpc"]["id"] != peer["vpc"]["id"]:
                    # SG references across peering only work within one Region.
                    regions = [e["resource"]["data"].get("Region") or e["scope"].split("/")[-1] for e in (endpoint, peer)]
                    if regions[0] != regions[1]:
                        selected = False
                    if endpoint["scope"] != peer["scope"] and (not pair.get("UserId") or peer_account is None):
                        selected = None
                group_selectors.append(selected)
            matched = _all([proto, port, _any(selectors + group_selectors)])
            if matched is True:
                known.append(model.ref(group, f"{key}[{index}]"))
                known_ip_allow = known_ip_allow or True in selectors
                known_cross_vpc_group_allow = (known_cross_vpc_group_allow or
                    (endpoint["vpc"] and peer["vpc"] and endpoint["vpc"]["id"] != peer["vpc"]["id"] and
                     True in group_selectors and True not in selectors))
            elif matched is None:
                uncertain = True
    if known:
        if known_cross_vpc_group_allow and not known_ip_allow:
            model._aws_cross_vpc_group_only_allow = getattr(model, "_aws_cross_vpc_group_only_allow", set()) | {direction}
        return model.step("policy", "allowed", "Aggregated attached security-group allow matches this new flow", known,
            control="aws.security_group", direction=direction, return_behavior="stateful: matching response allowed without reverse SG rule")
    if uncertain:
        return model.gap("security_group_rules_incomplete", "Missing SG rules, prefix lists, or unresolved referenced-group membership prevent a definitive union result", refs)
    return model.step("policy", "blocked", "No allow in the complete attached security-group rule union", refs,
        control="aws.security_group", direction=direction, pre_route=direction == "egress",
        address_translation_invariant=not potential_translated_allow)


def _aws_route_table(model, endpoint):
    if not endpoint["subnet"] or not endpoint["vpc"]:
        return None
    if not model.complete("route_table", endpoint["scope"]):
        model.gap("route_collection_incomplete", "Route-table association inventory is missing, denied, or incomplete")
        return None
    subnet_id = endpoint["subnet"]["data"].get("SubnetId")
    explicit, main = [], []
    for table in model.kinds["route_table"]:
        if table["scope"] != endpoint["scope"]:
            continue
        associations = table["data"].get("Associations")
        if table["data"].get("VpcId") not in {None, endpoint["vpc"]["data"].get("VpcId")}:
            if isinstance(associations, list) and any(isinstance(a, dict) and a.get("SubnetId") == subnet_id for a in associations):
                model.gap("route_association_mismatch", "A route table associates the selected subnet but declares another VPC",
                    [model.ref(table, "VpcId/Associations")])
                return None
            continue
        if (table["data"].get("VpcId") is None or not isinstance(associations, list) or
            any(not isinstance(association, dict) or
                any(field in association and
                    (not isinstance(association[field], str) or not association[field])
                    for field in ("SubnetId", "GatewayId", "PublicIpv4Pool")) or
                ("Main" in association and not isinstance(association["Main"], bool)) or
                ("AssociationState" in association and not isinstance(association["AssociationState"], dict))
                or (int(association.get("Main") is True) + sum(bool(association.get(field))
                    for field in ("SubnetId", "GatewayId", "PublicIpv4Pool"))) != 1
                for association in associations)):
            model.gap("route_association_malformed", "A route table could hide the selected subnet or main association",
                [model.ref(table, "VpcId/Associations")])
            return None
        for association in associations:
            applies = association.get("SubnetId") == subnet_id or association.get("Main") is True
            if not applies:
                continue
            state = association.get("AssociationState", {}).get("State", "associated")
            if state not in {"associated", "disassociated"}:
                model.gap("route_association_transition", "The selected subnet or main route-table association is changing or unresolved", [model.ref(table, "Associations")])
                return None
            if state == "disassociated":
                continue
            if association.get("SubnetId") == subnet_id:
                explicit.append(table)
            if association.get("Main") is True:
                main.append(table)
    choices = explicit or main
    if len(choices) != 1:
        model.gap("route_association_missing", "Exactly one explicit subnet route table or proven VPC main table is required")
        return None
    return choices[0]


def _aws_route(model, endpoint, peer, direction):
    table = _aws_route_table(model, endpoint)
    if table is None or "Routes" not in table["data"]:
        return model.gap("route_rules_missing", "Associated native route entries are not available")
    if not isinstance(table["data"]["Routes"], list) or any(not isinstance(route, dict) for route in table["data"]["Routes"]):
        return model.gap("route_rule_malformed", "Native route entries must be a list of route objects", [model.ref(table, "Routes")])
    destinations = ("DestinationCidrBlock", "DestinationIpv6CidrBlock", "DestinationPrefixListId")
    if any(sum(route.get(field) not in (None, "") for field in destinations) != 1
        for route in table["data"]["Routes"]):
        return model.gap("route_destination_ambiguous", "Each native AWS route needs exactly one destination selector", [model.ref(table, "Routes")])
    primary_cidr = endpoint["vpc"]["data"].get("CidrBlock") if endpoint["vpc"] else None
    try:
        required = {ipaddress.ip_network(value, strict=False) for value in _aws_vpc_ranges(endpoint["vpc"]["data"])}
        observed = {ipaddress.ip_network(route[field], strict=False)
            for route in table["data"]["Routes"]
            for field in ("DestinationCidrBlock", "DestinationIpv6CidrBlock") if field in route}
    except (ValueError, TypeError, KeyError, AttributeError):
        return model.gap("route_rule_malformed", "VPC or route-table destinations are malformed", [model.ref(table, "Routes")])
    if not isinstance(primary_cidr, str) or not required or not required <= observed:
        return model.gap("route_table_local_entry_missing",
            "The associated route table lacks one or more mandatory VPC CIDR destinations",
            [model.ref(table, "Routes"), model.ref(endpoint["vpc"], "CidrBlock")] if endpoint["vpc"] else [model.ref(table, "Routes")])
    choices = []
    for i, route in enumerate(table["data"]["Routes"]):
        prefix = route.get("DestinationCidrBlock", route.get("DestinationIpv6CidrBlock"))
        if route.get("DestinationPrefixListId"):
            networks = _aws_prefix_list_networks(model, route["DestinationPrefixListId"], endpoint["scope"])
            if networks is None:
                return model.gap("route_prefix_list_unresolved", "Managed prefix-list route entries are unavailable or unversioned", [model.ref(table, f"Routes[{i}]")])
            matching = [network.prefixlen for network in networks if network.version == peer["address"].version and peer["address"] in network]
            if matching:
                choices.append((max(matching), i, route, "prefix_list"))
            continue
        match = _cidr(prefix, peer["address"])
        if match is None:
            return model.gap("route_rule_malformed", "A route prefix is missing or malformed", [model.ref(table, f"Routes[{i}]")])
        if match:
            choices.append((ipaddress.ip_network(prefix, strict=False).prefixlen, i, route, "cidr"))
    if not choices:
        return model.step("route", "blocked", "No route covers the selected private destination address", [model.ref(table, "Routes")], direction=direction)
    # VPC local routes beat VPN/Direct Connect propagated routes that overlap
    # them, even when the propagated prefix is more specific. Static routes
    # (including prefix-list routes) still participate in longest-prefix choice.
    local_choices = [choice for choice in choices if choice[2].get("GatewayId") == "local"]
    if local_choices:
        choices = [choice for choice in choices
            if choice[2].get("Origin") != "EnableVgwRoutePropagation"]
    matching_prefix_lists = [choice for choice in choices if choice[3] == "prefix_list"]
    if len(matching_prefix_lists) > 1:
        longest_prefix_list = max(choice[0] for choice in matching_prefix_lists)
        decisive_cidr = any(choice[3] == "cidr" and
            (choice[0] > longest_prefix_list or
             (choice[0] == longest_prefix_list and
              (choice[2].get("Origin") in {"CreateRoute", "CreateRouteTable"} or
               choice[2].get("GatewayId") == "local")))
            for choice in choices)
        if not decisive_cidr:
            return model.gap("route_priority_ambiguous",
                "Overlapping prefix-list routes can select different next hops even with different entry prefix lengths",
                [model.ref(table, f"Routes[{choice[1]}]") for choice in matching_prefix_lists])
    longest = max(c[0] for c in choices)
    choices = [c for c in choices if c[0] == longest]
    if len(choices) > 1:
        def rank(choice):
            _, _, route, kind = choice
            if kind == "prefix_list":
                return 1
            origin = route.get("Origin")
            if origin in {"CreateRoute", "CreateRouteTable"} or route.get("GatewayId") == "local":
                return 2
            if origin == "EnableVgwRoutePropagation":
                return 0
            return None
        ranks = [rank(choice) for choice in choices]
        if None in ranks:
            return model.gap("route_priority_ambiguous", "Equal-prefix routes lack native origin for static/prefix-list/propagated priority", [model.ref(table, "Routes")])
        best = max(ranks)
        choices = [choice for choice, priority in zip(choices, ranks) if priority == best]
    if len(choices) != 1:
        return model.gap("route_priority_ambiguous", "Equal-prefix route alternatives require native route-priority context", [model.ref(table, "Routes")])
    _, i, route, kind = choices[0]
    refs = [model.ref(table, f"Routes[{i}]")]
    if kind == "prefix_list":
        prefix_list = model.find("managed_prefix_list", route["DestinationPrefixListId"], endpoint["scope"])
        refs.append(model.ref(prefix_list, "Version/Entries"))
    if route.get("State") == "blackhole":
        return model.step("route", "blocked", "The longest-prefix selected route is a blackhole", refs, direction=direction)
    if route.get("State") != "active":
        return model.gap("route_state_unknown", "The selected route is not proven active", refs)
    target_fields = ("GatewayId", "VpcPeeringConnectionId", "NatGatewayId", "TransitGatewayId",
        "NetworkInterfaceId", "InstanceId", "VpcEndpointId", "EgressOnlyInternetGatewayId",
        "CarrierGatewayId", "LocalGatewayId", "CoreNetworkArn", "OdbNetworkArn", "IpAddress")
    selected_targets = [field for field in target_fields if route.get(field) not in (None, "")]
    if (route.get("GatewayId") == "local" or route.get("VpcPeeringConnectionId") or route.get("TransitGatewayId")) and len(selected_targets) != 1:
        return model.gap("route_target_ambiguous", "A local, peering, or Transit Gateway route has conflicting native next-hop fields", refs)
    if route.get("GatewayId") == "local":
        if endpoint["vpc"] and peer["vpc"] and endpoint["vpc"]["id"] == peer["vpc"]["id"]:
            return model.step("route", "allowed", "Active longest-prefix local route remains inside the same scoped VPC", refs, direction=direction)
        return model.gap("address_domain_collision", "A local route cannot establish connectivity to another account/VPC with overlapping address space", refs)
    peering_id = route.get("VpcPeeringConnectionId")
    if peering_id:
        peers = [r for r in model.kinds["vpc_peering"] if r["data"].get("VpcPeeringConnectionId", r["native_id"]) == peering_id]
        compatible = []
        for peering in peers:
            info = [peering["data"].get("RequesterVpcInfo", {}), peering["data"].get("AccepterVpcInfo", {})]
            target_ids = {e["vpc"]["data"].get("VpcId") for e in (endpoint, peer) if e["vpc"]}
            if len(target_ids) == 2 and {x.get("VpcId") for x in info} == target_ids:
                owners = {e["vpc"]["data"].get("VpcId"): e["vpc"]["data"].get("OwnerId", e["vpc"]["data"].get("AccountId")) for e in (endpoint, peer) if e["vpc"]}
                if any(owners.get(x.get("VpcId")) is not None and str(owners[x["VpcId"]]) != str(x.get("OwnerId")) for x in info):
                    continue
                if endpoint["scope"] != peer["scope"] and any(owners.get(x.get("VpcId")) is None or not x.get("OwnerId") for x in info):
                    continue
                regions = {e["vpc"]["data"].get("VpcId"): e["resource"]["data"].get("Region", e["vpc"]["data"].get("Region", e["scope"].rsplit("/", 1)[-1])) for e in (endpoint, peer) if e["vpc"]}
                if any(x.get("Region") and x["Region"] != regions.get(x.get("VpcId")) for x in info):
                    continue
                if endpoint["scope"] != peer["scope"] and any(not x.get("Region") for x in info):
                    continue
                if not model.complete("vpc_peering", peering["scope"]):
                    continue
                compatible.append(peering)
        if not compatible:
            return model.gap("peering_facts_missing", "A route references peering without compatible scoped native endpoint facts", refs)
        statuses = {r["data"].get("Status", {}).get("Code") for r in compatible}
        refs += [model.ref(r, "Status/RequesterVpcInfo/AccepterVpcInfo") for r in compatible]
        if statuses != {"active"}:
            return model.step("route", "blocked" if len(statuses) == 1 and None not in statuses else "unknown",
                "The referenced peering is not consistently proven active", refs, direction=direction)
        return model.step("route", "allowed", "Active selected route and peering join these two native VPC domains", refs, direction=direction)
    if route.get("TransitGatewayId"):
        model._aws_tgw_selected = True
        if getattr(model, "_aws_tgw_attachment_route", False):
            return model.gap("tgw_attachment_route_recursion", "An attachment subnet route loops back to the Transit Gateway", refs)
        decision = _aws_tgw_route(model, endpoint, peer, direction, route["TransitGatewayId"], refs)
        if decision != "allowed":
            model.result["translations"].append({"decision": "unknown", "component": "TransitGatewayId", "evidence_refs": refs})
        return decision
    component = next((key for key in ("NatGatewayId", "TransitGatewayId", "NetworkInterfaceId", "InstanceId", "GatewayId", "VpcEndpointId") if route.get(key)), "unknown_next_hop")
    model.result["translations"].append({"decision": "unknown", "component": component, "evidence_refs": refs})
    return model.gap("unsupported_route_component", "NAT, transit, Internet, VPN, endpoint, and appliance route transformations are not modeled", refs)


def _aws_tgw_route(model, endpoint, peer, direction, gateway_id, vpc_route_refs):
    def unknown(code, message, refs=()):
        model.gap(code, message, refs)
        return model.step("route", "unknown", message, refs, direction=direction)

    if endpoint["vpc"] is None or peer["vpc"] is None or endpoint["vpc"]["id"] == peer["vpc"]["id"]:
        return unknown("tgw_vpc_domain_unknown", "Transit Gateway routing needs two distinct native VPC domains", vpc_route_refs)
    gateways = [r for r in model.kinds["transit_gateway"] if r["data"].get("TransitGatewayId") == gateway_id]
    if len(gateways) != 1 or not model.complete("transit_gateway", gateways[0]["scope"]) or gateways[0]["data"].get("State") != "available":
        return unknown("tgw_gateway_unavailable", "The selected Transit Gateway is not uniquely collected and available", vpc_route_refs)
    gateway = gateways[0]
    attachments = {}
    for selected in (endpoint, peer):
        if not model.complete("transit_gateway_vpc_attachment", selected["scope"]) or not model.complete("transit_gateway_attachment", selected["scope"]):
            return unknown("tgw_attachment_inventory_incomplete", "Both VPC and route-table attachment inventories must be complete in each selected account", vpc_route_refs)
        vpc_id = selected["vpc"]["data"].get("VpcId")
        account = selected["scope"].split("/", 1)[0]
        matches = [r for r in model.kinds["transit_gateway_vpc_attachment"] if r["scope"] == selected["scope"] and
            r["data"].get("TransitGatewayId") == gateway_id and r["data"].get("VpcId") == vpc_id and
            str(r["data"].get("VpcOwnerId")) == account]
        if len(matches) != 1 or matches[0]["data"].get("State") != "available":
            return unknown("tgw_vpc_attachment_unavailable", "Exactly one available VPC attachment must join the selected VPC to this Transit Gateway", vpc_route_refs)
        attachment = matches[0]
        native_id = attachment["data"].get("TransitGatewayAttachmentId")
        generic = model.find("transit_gateway_attachment", native_id, selected["scope"])
        if (generic is None or generic["data"].get("State") != "available" or
            generic["data"].get("ResourceType") != "vpc" or generic["data"].get("ResourceId") != vpc_id or
            generic["data"].get("TransitGatewayId") != gateway_id or
            str(generic["data"].get("ResourceOwnerId")) != account or
            str(generic["data"].get("TransitGatewayOwnerId")) != gateway["scope"].split("/", 1)[0]):
            return unknown("tgw_attachment_mismatch", "Generic and VPC-specific attachment facts do not agree", [model.ref(attachment, "TransitGatewayId/VpcId/State")])
        subnet_ids = attachment["data"].get("SubnetIds")
        if (not isinstance(subnet_ids, list) or not subnet_ids or
            any(not isinstance(subnet_id, str) or not subnet_id for subnet_id in subnet_ids) or
            len(set(subnet_ids)) != len(subnet_ids)):
            return unknown("tgw_attachment_subnet_ambiguous", "The VPC attachment must list distinct native subnet IDs", [model.ref(attachment, "SubnetIds")])
        if not model.complete("subnet", selected["scope"]) or not selected["subnet"]:
            return unknown("tgw_attachment_subnet_missing", "The attachment needs complete native subnet and endpoint facts", [model.ref(attachment, "SubnetIds")])
        subnet_by_zone = {}
        for subnet_id in subnet_ids:
            subnet = model.find("subnet", subnet_id, selected["scope"])
            if subnet is None or subnet["data"].get("VpcId") != vpc_id:
                return unknown("tgw_attachment_subnet_missing", "Every attachment subnet must belong to the selected native VPC", [model.ref(attachment, "SubnetIds")])
            try:
                attachment_range = ipaddress.ip_network(subnet["data"].get("CidrBlock"), strict=False)
                in_vpc = attachment_range.version == 4 and any(attachment_range.subnet_of(ipaddress.ip_network(value, strict=False))
                    for value in _aws_vpc_ranges(selected["vpc"]["data"]) if ipaddress.ip_network(value, strict=False).version == 4)
            except (ValueError, TypeError, KeyError):
                in_vpc = False
            if not in_vpc:
                return unknown("tgw_attachment_subnet_domain_mismatch", "An attachment subnet IPv4 CIDR is not proven inside its VPC", [model.ref(subnet, "CidrBlock/VpcId")])
            zone = subnet["data"].get("AvailabilityZoneId")
            if not isinstance(zone, str) or not zone or zone in subnet_by_zone:
                return unknown("tgw_attachment_zone_unproven", "Attachment subnets need distinct observed Availability Zone IDs", [model.ref(attachment, "SubnetIds"), model.ref(subnet, "AvailabilityZoneId")])
            subnet_by_zone[zone] = subnet
        endpoint_zone = selected["subnet"]["data"].get("AvailabilityZoneId")
        if not isinstance(endpoint_zone, str) or endpoint_zone not in subnet_by_zone:
            return unknown("tgw_attachment_zone_unproven", "The originating endpoint needs an attachment subnet in its observed Availability Zone", [model.ref(selected["subnet"], "AvailabilityZoneId"), model.ref(attachment, "SubnetIds")])
        attachments[selected["vpc"]["id"]] = (attachment, generic, subnet_by_zone)
    source_attachment, source_generic, source_zones = attachments[endpoint["vpc"]["id"]]
    target_attachment, _, target_zones = attachments[peer["vpc"]["id"]]
    source_zone = endpoint["subnet"]["data"]["AvailabilityZoneId"]
    source_subnet = source_zones[source_zone]
    if len(target_zones) == 1:
        target_subnet = next(iter(target_zones.values()))
    elif (isinstance(target_attachment["data"].get("Options"), dict) and
        target_attachment["data"]["Options"].get("ApplianceModeSupport") == "disable" and source_zone in target_zones):
        target_subnet = target_zones[source_zone]
    else:
        return unknown("tgw_target_zone_unproven", "The destination attachment's selected Availability Zone is not deterministic from the collected facts", [model.ref(target_attachment, "SubnetIds/Options")])
    association = source_generic["data"].get("Association")
    table_id = association.get("TransitGatewayRouteTableId") if isinstance(association, dict) and association.get("State") == "associated" else None
    table = model.find("transit_gateway_route_table", table_id) if table_id else None
    if (table is None or not model.complete("transit_gateway_route_table", table["scope"]) or
        table["data"].get("State") != "available" or table["data"].get("TransitGatewayId") != gateway_id):
        return unknown("tgw_route_table_unavailable", "The source VPC attachment needs an associated available Transit Gateway route table", [model.ref(source_generic, "Association")])
    associations = table["data"].get("AssociationInventory")
    routes = table["data"].get("RouteInventory")
    system_routes = table["data"].get("SystemRouteInventory")
    selected_associations = ([a for a in associations.get("items", []) if isinstance(a, dict) and
        a.get("TransitGatewayAttachmentId") == source_attachment["native_id"]]
        if isinstance(associations, dict) and isinstance(associations.get("items"), list) else [])
    if (not isinstance(associations, dict) or associations.get("collection_status") not in {"collected", "empty"} or
        not isinstance(associations.get("items"), list) or
        any(not isinstance(a, dict) or not isinstance(a.get("TransitGatewayAttachmentId"), str) for a in associations["items"]) or
        len(selected_associations) != 1 or
        selected_associations[0].get("State") != "associated" or
        selected_associations[0].get("ResourceId", endpoint["vpc"]["data"].get("VpcId")) != endpoint["vpc"]["data"].get("VpcId") or
        selected_associations[0].get("ResourceType", "vpc") != "vpc" or
        not isinstance(routes, dict) or routes.get("collection_status") not in {"collected", "empty"} or
        routes.get("queries") != ["type=static", "type=propagated"] or not isinstance(routes.get("items"), list) or
        not isinstance(system_routes, dict) or system_routes.get("collection_status") not in {"collected", "empty"} or
        system_routes.get("queries") != ["type=system"] or not isinstance(system_routes.get("items"), list)):
        return unknown("tgw_route_inventory_incomplete", "Transit Gateway route and attachment-association reads must be complete and mutually consistent", [model.ref(table, "RouteInventory/SystemRouteInventory/AssociationInventory")])
    choices = []
    for origin, route_items, expected_types in (("RouteInventory", routes["items"], {"static", "propagated"}),
                                                ("SystemRouteInventory", system_routes["items"], {"system"})):
        for i, route in enumerate(route_items):
          route_ref = model.ref(table, f"{origin}.items[{i}]")
          if not isinstance(route, dict) or route.get("State") not in {"active", "blackhole"} or route.get("Type") not in expected_types:
              return unknown("tgw_route_malformed", "Transit Gateway route state or type is unresolved", [route_ref])
          if (route.get("PrefixListId") is None) == (route.get("DestinationCidrBlock") is None):
              return unknown("tgw_route_malformed", "Transit Gateway route needs exactly one CIDR or prefix-list destination", [route_ref])
          if route.get("PrefixListId"):
              networks = _aws_prefix_list_networks(model, route["PrefixListId"], table["scope"])
              if networks is None:
                  return unknown("tgw_prefix_list_unresolved", "A Transit Gateway prefix-list route needs complete versioned entries", [route_ref])
              prefix = max((network.prefixlen for network in networks if network.version == peer["address"].version and peer["address"] in network), default=None)
              rank = 1
          else:
              cidr = route.get("DestinationCidrBlock")
              matches = _cidr(cidr, peer["address"])
              if matches is None:
                  return unknown("tgw_route_malformed", "Transit Gateway route destination is missing or malformed", [route_ref])
              prefix = ipaddress.ip_network(cidr, strict=False).prefixlen if matches else None
              rank = {"static": 3, "system": 2, "propagated": 0}[route["Type"]]
          if prefix is not None:
              choices.append((prefix, rank, route_ref, route))
    if not choices:
        return unknown("tgw_route_missing", "No collected Transit Gateway route covers the selected destination", [model.ref(table, "RouteInventory")])
    winner = max((prefix, rank) for prefix, rank, _, _ in choices)
    choices = [choice for choice in choices if choice[:2] == winner]
    if len(choices) != 1:
        return unknown("tgw_route_ambiguous", "Equal-priority Transit Gateway routes do not select one attachment", [model.ref(table, "RouteInventory")])
    _, _, route_ref, route = choices[0]
    route_refs = vpc_route_refs + [model.ref(source_attachment, "SubnetIds/State"), route_ref]
    if route["State"] == "blackhole":
        return model.step("route", "blocked", "Selected Transit Gateway route is a blackhole", route_refs, direction=direction)
    targets = route.get("TransitGatewayAttachments")
    if (not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], dict) or
        targets[0].get("TransitGatewayAttachmentId") != target_attachment["native_id"] or
        targets[0].get("ResourceType") != "vpc" or targets[0].get("ResourceId") != peer["vpc"]["data"].get("VpcId")):
        return unknown("tgw_route_target_unresolved", "The selected gateway route does not prove the exact destination VPC attachment", route_refs)
    attached = {**peer, "subnet": target_subnet}
    model._aws_tgw_attachment_route = True
    try:
        local = _aws_route(model, attached, peer, direction)
    finally:
        model._aws_tgw_attachment_route = False
    if local != "allowed":
        return unknown("tgw_attachment_local_route_unproven", "Destination attachment subnet routing does not prove the selected endpoint", [model.ref(target_subnet, "SubnetId")])
    model._aws_tgw_paths = getattr(model, "_aws_tgw_paths", {})
    model._aws_tgw_paths[direction] = (source_subnet, target_subnet)
    if direction == "forward":
        model._aws_tgw_forward_sg_context = (gateway, source_attachment, target_attachment)
    return model.step("route", "allowed", "VPC route, Transit Gateway association and route, and destination attachment subnet route reach the selected VPC", route_refs,
        direction=direction)


def _aws_acl(model, endpoint, other, egress, port, protocol, flow):
    if not endpoint["subnet"] or not endpoint["vpc"]:
        return model.gap("nacl_association_missing", "Subnet or VPC context is missing for the stateless NACL stage")
    if not model.complete("network_acl", endpoint["scope"]):
        return model.gap("nacl_collection_incomplete", "NACL association inventory is missing, denied, or incomplete")
    subnet_id = endpoint["subnet"]["data"].get("SubnetId")
    acls = []
    for acl in model.kinds["network_acl"]:
        if acl["scope"] != endpoint["scope"]:
            continue
        associations = acl["data"].get("Associations")
        if acl["data"].get("VpcId") not in {None, endpoint["vpc"]["data"].get("VpcId")}:
            if isinstance(associations, list) and any(isinstance(a, dict) and a.get("SubnetId") == subnet_id for a in associations):
                return model.gap("nacl_association_mismatch", "A NACL associates the selected subnet but declares another VPC",
                    [model.ref(acl, "VpcId/Associations")])
            continue
        if (acl["data"].get("VpcId") is None or not isinstance(associations, list) or
            any(not isinstance(association, dict) or
                not isinstance(association.get("SubnetId"), str) or not association["SubnetId"]
                for association in associations)):
            return model.gap("nacl_association_malformed", "A NACL could hide the selected subnet association",
                [model.ref(acl, "VpcId/Associations")])
        if any(association.get("SubnetId") == subnet_id for association in associations):
            acls.append(acl)
    if len(acls) != 1 or not isinstance(acls[0]["data"].get("Entries"), list):
        return model.gap("nacl_association_missing", "Exactly one associated native NACL with entries is required")
    acl = acls[0]
    if any(not isinstance(r, dict) or not isinstance(r.get("Egress"), bool) or
        ("CidrBlock" in r) == ("Ipv6CidrBlock" in r) for r in acl["data"]["Entries"]):
        return model.gap("nacl_rule_unresolved", "Native NACL entries need a direction and exactly one IPv4 or IPv6 CIDR", [model.ref(acl, "Entries")])
    rules = [(r.get("RuleNumber"), i, r) for i, r in enumerate(acl["data"]["Entries"]) if r.get("Egress") is egress
             and ("Ipv6CidrBlock" in r if other["address"].version == 6 else "CidrBlock" in r)]
    implicit_number = 32767 if other["address"].version == 4 else 32768
    if any(isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= implicit_number
        for n, _, _ in rules):
        return model.gap("nacl_order_malformed", "NACL order contains missing or out-of-range rule numbers", [model.ref(acl, "Entries")])
    if any(n in {32767, 32768} and (n != implicit_number or rule.get("RuleAction") != "deny" or rule.get("Protocol") != "-1" or
        rule.get("Ipv6CidrBlock" if other["address"].version == 6 else "CidrBlock") !=
            ("::/0" if other["address"].version == 6 else "0.0.0.0/0"))
        for n, _, rule in rules):
        return model.gap("nacl_implicit_rule_malformed", "The family-specific reserved NACL rule must be the native all-traffic implicit deny", [model.ref(acl, "Entries")])
    if len({n for n, _, _ in rules}) != len(rules):
        return model.gap("nacl_order_ambiguous", "Duplicate NACL rule numbers prevent ordered matching", [model.ref(acl, "Entries")])
    if not any(n == implicit_number for n, _, _ in rules):
        return model.gap("nacl_implicit_rule_missing", "The native NACL list lacks its family-specific implicit deny entry; rule capture may be truncated", [model.ref(acl, "Entries")])
    for number, i, rule in sorted(rules):
        proto = _aws_protocol(rule.get("Protocol"), protocol)
        network = rule["Ipv6CidrBlock"] if other["address"].version == 6 else rule["CidrBlock"]
        port_range = rule.get("PortRange", {})
        ports = (True if rule.get("Protocol") == "-1" else
            _ports(f"{port_range.get('From')}-{port_range.get('To')}", port) if isinstance(port_range, dict) else None)
        matched = _all([proto, _cidr(network, other["address"]), ports])
        refs = [model.ref(acl, f"Entries[{i}]")]
        if matched is None:
            if port is None:
                return model.gap("source_port_required", "Stateless NACL return rules require the exact initiating source port", refs)
            return model.gap("nacl_rule_unresolved", "An earlier NACL rule cannot be definitively matched", refs)
        if matched:
            action = rule.get("RuleAction")
            if action not in {"allow", "deny"}:
                return model.gap("nacl_action_unknown", "Matching NACL action is not recognized", refs)
            return model.step("policy", "allowed" if action == "allow" else "blocked",
                "Native NACL implicit deny after no matching lower rule" if number == implicit_number else
                "First ordered matching stateless NACL rule", refs,
                control="aws.network_acl", direction="egress" if egress else "ingress", flow=flow,
                pre_route=egress and flow == "forward",
                requires_return_route=flow == "return" and not egress)
    return model.step("policy", "blocked", "Native NACL implicit deny after no matching rule", [model.ref(acl, "Entries")],
        control="aws.network_acl", direction="egress" if egress else "ingress", flow=flow,
        pre_route=egress and flow == "forward",
        requires_return_route=flow == "return" and not egress)


def _aws_tgw_acls(model, src, dst, query):
    paths = getattr(model, "_aws_tgw_paths", {})
    if set(paths) != {"forward", "return"}:
        return [model.gap("tgw_nacl_path_unproven", "Both Transit Gateway directions must be proven before attachment-subnet NACL stages can be evaluated")]
    checks = []
    for flow, endpoint, peer, port, attachment_subnets in (
        ("forward", src, dst, query["destination_port"], paths["forward"]),
        ("return", dst, src, query["source_port"], paths["return"]),
    ):
        source_subnet, target_subnet = attachment_subnets
        source_attachment = {**endpoint, "subnet": source_subnet}
        target_attachment = {**peer, "subnet": target_subnet}
        checks.append(_aws_acl(model, endpoint, peer, True, port, query["protocol"], flow))
        checks.append(_aws_acl(model, source_attachment, endpoint, False, port, query["protocol"], f"attachment_{flow}"))
        if target_subnet["id"] != peer["subnet"]["id"]:
            checks.append(_aws_acl(model, target_attachment, peer, True, port, query["protocol"], f"attachment_{flow}"))
            checks.append(_aws_acl(model, peer, endpoint, False, port, query["protocol"], flow))
        else:
            model.step("policy", "allowed", "Transit Gateway to instance traffic in the attachment subnet bypasses that subnet's NACL",
                [model.ref(target_subnet, "SubnetId")], control="aws.network_acl", flow=flow)
    return checks


def _aws_tgw_sg_reference(model, src, dst):
    directions = getattr(model, "_aws_cross_vpc_group_only_allow", set())
    if not directions:
        return "allowed"
    if "egress" in directions:
        return model.gap("tgw_sg_egress_reference_unsupported",
            "Transit Gateway security-group referencing is supported only in inbound rules")
    context = getattr(model, "_aws_tgw_forward_sg_context", None)
    if context is None or set(getattr(model, "_aws_tgw_paths", {})) != {"forward", "return"}:
        return model.gap("tgw_sg_reference_unproven",
            "Both selected Transit Gateway routes and their VPC attachments must be proven")
    gateway, source_attachment, target_attachment = context
    refs = [model.ref(item, "Options.SecurityGroupReferencingSupport")
        for item in (gateway, source_attachment, target_attachment)]
    if any(not isinstance(item["data"].get("Options"), dict) or
        item["data"]["Options"].get("SecurityGroupReferencingSupport") != "enable"
        for item in (gateway, source_attachment, target_attachment)):
        return model.gap("tgw_sg_reference_unproven",
            "The Transit Gateway and both VPC attachments must explicitly enable security-group referencing", refs)
    forward_subnets = model._aws_tgw_paths["forward"]
    for subnet in (src["subnet"], dst["subnet"], *forward_subnets):
        zone = subnet["data"].get("AvailabilityZoneId") if subnet else None
        if (not isinstance(zone, str) or not re.fullmatch(r"[a-z]{3,4}\d+-az\d+", zone) or
            zone == "use1-az3" or subnet["data"].get("OutpostArn")):
            return model.gap("tgw_sg_reference_zone_unproven",
                "Security-group referencing is unavailable or unproven for a selected attachment zone or Outpost",
                refs + ([model.ref(subnet, "AvailabilityZoneId/OutpostArn")] if subnet else []))
    return model.step("policy", "allowed", "Native Transit Gateway and attachment options enable inbound cross-VPC security-group referencing",
        refs, control="aws.security_group", direction="ingress")


def _aws(model, source, destination, query):
    endpoints = [_aws_endpoint(model, r, query["address_family"]) for r in (source, destination)]
    if not all(e and e["address"] for e in endpoints):
        return []
    src, dst = endpoints
    model.result["endpoints"] = _endpoint_details(src, dst)
    if src["resource"]["id"] == dst["resource"]["id"]:
        return [model.gap("self_traffic_semantics_unproven",
            "Traffic to this EC2 interface's own private IP may stay inside the host; SG and NACL boundary rules do not prove a drop",
            [model.ref(src["resource"], "PrivateIpAddress/Ipv6Addresses")])]
    checks = [_aws_sg(model, src, dst, "egress", query), _aws_sg(model, dst, src, "ingress", query)]
    if src["vpc"] and dst["vpc"] and src["vpc"]["id"] != dst["vpc"]["id"]:
        ranges = [[ipaddress.ip_network(v, strict=False) for v in _aws_vpc_ranges(e["vpc"]["data"]) if _cidr(v, e["address"]) is not None] for e in (src, dst)]
        if any(a.version == b.version and a.overlaps(b) for a in ranges[0] for b in ranges[1]):
            checks.append(model.gap("overlapping_address_domains", "Cross-VPC overlap cannot be resolved into the selected resource path by address alone"))
    if src["subnet"] and dst["subnet"] and src["subnet"]["id"] == dst["subnet"]["id"]:
        refs = [model.ref(src["subnet"], "SubnetId/CidrBlock/Ipv6CidrBlockAssociationSet")]
        checks.append(model.step("route", "allowed", "Selected hosts share one native subnet; same-subnet traffic uses its direct path", refs,
            direction="forward_and_return"))
        model.step("policy", "allowed", "NACLs do not filter traffic within the same subnet", refs, control="aws.network_acl")
    else:
        checks += [_aws_route(model, src, dst, "forward"), _aws_route(model, dst, src, "return")]
        if getattr(model, "_aws_tgw_selected", False):
            checks += _aws_tgw_acls(model, src, dst, query)
            checks.append(_aws_tgw_sg_reference(model, src, dst))
        else:
            checks += [_aws_acl(model, src, dst, True, query["destination_port"], query["protocol"], "forward"),
                _aws_acl(model, dst, src, False, query["destination_port"], query["protocol"], "forward"),
                _aws_acl(model, dst, src, True, query["source_port"], query["protocol"], "return"),
                _aws_acl(model, src, dst, False, query["source_port"], query["protocol"], "return")]
    return checks


def _aws_vpc_ranges(data):
    return ([data["CidrBlock"]] if data.get("CidrBlock") else []) + [
        a["CidrBlock"] for a in data.get("CidrBlockAssociationSet", [])
        if a.get("CidrBlock") and a.get("CidrBlockState", {}).get("State") == "associated"
    ] + [
        a["Ipv6CidrBlock"] for a in data.get("Ipv6CidrBlockAssociationSet", [])
        if a.get("Ipv6CidrBlock") and a.get("Ipv6CidrBlockState", {}).get("State") == "associated"
    ]


def _endpoint_details(source, destination):
    return {key: {"resource_id": endpoint["selected"]["id"], "native_id": endpoint["selected"]["native_id"],
                  "scope": endpoint["scope"], "address": str(endpoint["address"]),
                  "interface_resource_id": endpoint["resource"]["id"],
                  **({"interface_index": endpoint["interface_index"]} if "interface_index" in endpoint else {})}
            for key, endpoint in (("source", source), ("destination", destination))}


def _azure_endpoint(model, resource, family):
    selected = resource
    if resource["type"] == "vm":
        interfaces = resource["data"].get("properties", {}).get("networkProfile", {}).get("networkInterfaces")
        if (not isinstance(interfaces, list) or len(interfaces) != 1 or
            not isinstance(interfaces[0], dict) or not isinstance(interfaces[0].get("id"), str)):
            model.gap("endpoint_interface_ambiguous", "Azure VM needs exactly one collected selected network interface", [model.ref(resource, "properties.networkProfile.networkInterfaces")])
            return None
        vm = resource
        if not model.complete("vm", vm["scope"]):
            model.gap("endpoint_association_incomplete", "Selected Azure VM collection is incomplete", [model.ref(vm, "properties.networkProfile.networkInterfaces")])
        provenance = vm["data"].get("_provenance")
        if not isinstance(provenance, dict) or provenance.get("representation") != "full":
            model.gap("endpoint_detail_missing", "The selected Azure VM needs authoritative full GET detail", [model.ref(vm, "_provenance")])
        if vm["data"].get("properties", {}).get("provisioningState") != "Succeeded":
            model.gap("endpoint_not_ready", "The selected Azure VM is not proven provisioned", [model.ref(vm, "properties.provisioningState")])
        resource = model.find("nic", interfaces[0].get("id"))
        if resource is None:
            model.gap("interface_inventory_missing", "The declared VM NIC was not collected")
            return None
        attached_vm = resource["data"].get("properties", {}).get("virtualMachine")
        if (not isinstance(attached_vm, dict) or
            not isinstance(attached_vm.get("id"), str) or attached_vm["id"].lower() != vm["native_id"].lower()):
            model.gap("endpoint_association_mismatch", "The NIC's native VM attachment disagrees with the selected VM",
                [model.ref(vm, "properties.networkProfile.networkInterfaces"), model.ref(resource, "properties.virtualMachine")])
            return None
    elif resource["type"] != "nic":
        model.gap("unsupported_endpoint_type", "Azure selected endpoints must be a VM or NIC", [model.ref(resource, "data")])
        return None
    attached_ref = resource["data"].get("properties", {}).get("virtualMachine")
    vm = model.find("vm", attached_ref["id"]) if isinstance(attached_ref, dict) and isinstance(attached_ref.get("id"), str) else None
    if vm is None or vm["scope"] != resource["scope"]:
        model.gap("endpoint_vm_attachment_missing", "The selected NIC needs an exact collected VM attachment",
            [model.ref(resource, "properties.virtualMachine")])
    else:
        vm_props = vm["data"].get("properties", {})
        vm_profile = vm_props.get("networkProfile") if isinstance(vm_props, dict) else None
        vm_interfaces = vm_profile.get("networkInterfaces") if isinstance(vm_profile, dict) else None
        matches = ([item for item in vm_interfaces if isinstance(item, dict) and
            isinstance(item.get("id"), str) and item["id"].lower() == resource["native_id"].lower()]
            if isinstance(vm_interfaces, list) else [])
        if len(matches) != 1:
            model.gap("endpoint_association_mismatch", "The attached VM must identify this NIC exactly once",
                [model.ref(vm, "properties.networkProfile.networkInterfaces"), model.ref(resource, "properties.virtualMachine")])
        if not model.complete("vm", vm["scope"]):
            model.gap("endpoint_association_incomplete", "Attached Azure VM collection is incomplete",
                [model.ref(vm, "properties.networkProfile.networkInterfaces")])
        vm_provenance = vm["data"].get("_provenance")
        if (not isinstance(vm_provenance, dict) or vm_provenance.get("representation") != "full" or
            vm_provenance.get("expand") != "instanceView" or not isinstance(vm_props, dict) or
            vm_props.get("provisioningState") != "Succeeded"):
            model.gap("endpoint_vm_detail_missing", "The attached VM needs full provisioned GET detail with instance view",
                [model.ref(vm, "_provenance/properties.provisioningState")])
        instance_view = vm_props.get("instanceView") if isinstance(vm_props, dict) else None
        statuses = instance_view.get("statuses") if isinstance(instance_view, dict) else None
        power_codes = ([item.get("code") for item in statuses if isinstance(item, dict) and
            isinstance(item.get("code"), str) and item["code"].startswith("PowerState/")]
            if isinstance(statuses, list) else [])
        if (not isinstance(statuses, list) or
            any(not isinstance(item, dict) or not isinstance(item.get("code"), str) for item in statuses) or
            power_codes != ["PowerState/running"]):
            model.gap("endpoint_power_state_unproven", "The attached VM is not proven PowerState/running by its instance view",
                [model.ref(vm, "properties.instanceView.statuses")])
    props = resource["data"].get("properties", {})
    configs = props.get("ipConfigurations")
    if not isinstance(configs, list):
        model.gap("endpoint_ip_configuration_missing", "Native NIC IP configurations are missing", [model.ref(resource, "properties.ipConfigurations")])
        return None
    address = _address(model, [c.get("properties", {}).get("privateIPAddress") for c in configs], family, resource)
    if address is None:
        return None
    matching = [c for c in configs if _cidr(c.get("properties", {}).get("privateIPAddress"), address) is True]
    if len(matching) != 1:
        model.gap("endpoint_ip_configuration_ambiguous", "Exactly one native NIC IP configuration must own the selected address",
            [model.ref(resource, "properties.ipConfigurations")])
        return None
    subnets = {c.get("properties", {}).get("subnet", {}).get("id") for c in matching}
    associations = matching[0].get("properties", {}).get("applicationSecurityGroups", [])
    asg_ids = ({str(group["id"]).lower() for group in associations if isinstance(group, dict) and isinstance(group.get("id"), str)}
        if isinstance(associations, list) and all(isinstance(group, dict) and isinstance(group.get("id"), str) for group in associations) else None)
    subnet = model.find("subnet", next(iter(subnets))) if len(subnets) == 1 else None
    vnet = model.find("vnet", subnet["native_id"].rsplit("/subnets/", 1)[0]) if subnet else None
    if subnet is None or vnet is None:
        model.gap("network_domain_missing", "NIC address needs exact native subnet/VNet identity, not a same-name network", [model.ref(resource, "properties.ipConfigurations")])
    else:
        prefixes = subnet["data"].get("properties", {}).get("addressPrefixes", [])
        prefix = subnet["data"].get("properties", {}).get("addressPrefix")
        if prefix:
            prefixes = prefixes + [prefix]
        if not any(_cidr(p, address) is True for p in prefixes):
            model.gap("endpoint_outside_subnet", "Private NIC address is not proven inside its selected native subnet", [model.ref(subnet, "properties.addressPrefix/addressPrefixes")])
        vnet_prefixes = vnet["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", [])
        if not any(_cidr(p, address) is True for p in vnet_prefixes):
            model.gap("endpoint_outside_vnet", "Private NIC address is not proven inside its selected native VNet", [model.ref(vnet, "properties.addressSpace.addressPrefixes")])
    for dependency in (resource, subnet, vnet):
        if dependency and not model.complete(dependency["type"], dependency["scope"]):
            model.gap("endpoint_association_incomplete", "Native endpoint/subnet/VNet association collection is incomplete", [model.ref(dependency, "properties")])
    for dependency in (resource, subnet, vnet):
        if dependency is None:
            continue
        provenance = dependency["data"].get("_provenance")
        if not isinstance(provenance, dict) or provenance.get("representation") != "full":
            model.gap("endpoint_detail_missing", "The selected NIC, subnet, and VNet need authoritative full GET detail", [model.ref(dependency, "_provenance")])
        if dependency["data"].get("properties", {}).get("provisioningState") != "Succeeded":
            model.gap("endpoint_not_ready", "The selected NIC, subnet, or VNet is not proven provisioned", [model.ref(dependency, "properties.provisioningState")])
    return {"resource": resource, "selected": selected, "address": address, "scope": resource["scope"], "subnet": subnet, "vnet": vnet,
        "asg_ids": asg_ids}


def _azure_peering_subnets(peering, endpoint, peer):
    props = peering["data"].get("properties", {})
    complete = props.get("peerCompleteVnets", True)
    if complete is True:
        return True
    if complete is not False or not endpoint.get("subnet") or not peer.get("subnet"):
        return None
    local_names, remote_names = props.get("localSubnetNames"), props.get("remoteSubnetNames")
    if (not isinstance(local_names, list) or not isinstance(remote_names, list) or
        any(not isinstance(name, str) or not name for name in local_names + remote_names)):
        return None
    local = endpoint["subnet"]["native_id"].lower().rsplit("/subnets/", 1)[-1]
    remote = peer["subnet"]["native_id"].lower().rsplit("/subnets/", 1)[-1]
    return local in {name.lower() for name in local_names} and remote in {name.lower() for name in remote_names}


def _azure_peering_ready(model, peering):
    provenance = peering["data"].get("_provenance")
    if not isinstance(provenance, dict) or provenance.get("representation") != "full":
        return model.gap("peering_detail_missing", "The selected Azure peering needs authoritative full GET detail", [model.ref(peering, "_provenance")])
    if peering["data"].get("properties", {}).get("provisioningState") != "Succeeded":
        return model.gap("peering_not_ready", "The selected Azure peering is not proven provisioned", [model.ref(peering, "properties.provisioningState")])
    return True


def _azure_address_selector(model, value, subject, endpoint):
    address = subject["address"]
    if value == "*":
        return True
    direct = _cidr(value, address)
    if direct is not None:
        return direct
    if value == "VirtualNetwork" and endpoint["vnet"]:
        prefixes = endpoint["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", [])
        if any(_cidr(p, address) is True for p in prefixes):
            return True
        # Azure's VirtualNetwork tag also includes access-enabled peered
        # VNets. Only prove positive membership from synchronized native
        # peering and the collected remote address space; other tag members
        # (BGP/UDR/gateway prefixes) still need effective tag evidence.
        local_id = endpoint["vnet"]["native_id"].lower()
        for peering in model.kinds["vnet_peering"]:
            if not peering["native_id"].lower().startswith(local_id + "/virtualnetworkpeerings/"):
                continue
            props = peering["data"].get("properties", {})
            remote_ref = props.get("remoteVirtualNetwork", {}).get("id")
            if not subject.get("vnet") or not isinstance(remote_ref, str) or remote_ref.lower() != subject["vnet"]["native_id"].lower():
                continue
            if (_azure_peering_ready(model, peering) is not True or
                props.get("peeringState") != "Connected" or props.get("allowVirtualNetworkAccess") is not True or
                props.get("peeringSyncLevel") != "FullyInSync" or
                (address.version == 4 and props.get("enableOnlyIPv6Peering") is True) or
                not model.complete("vnet_peering", peering["scope"])):
                continue
            remote = model.find("vnet", remote_ref)
            if (remote is None or not model.complete("vnet", remote["scope"]) or
                not subject.get("vnet") or subject["vnet"]["id"] != remote["id"] or
                _azure_peering_subnets(peering, endpoint, subject) is not True):
                continue
            declared = props.get("remoteAddressSpace", {}).get("addressPrefixes")
            observed = remote["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", [])
            if (isinstance(declared, list) and any(_cidr(p, address) is True for p in declared) and
                any(_cidr(p, address) is True for p in observed)):
                model.ref(peering, "properties.remoteAddressSpace/allowVirtualNetworkAccess/peeringState")
                model.ref(remote, "properties.addressSpace.addressPrefixes")
                return True
    if value == "VirtualNetwork":
        # This tag also contains gateway, BGP, and UDR-learned ranges. The
        # subscription service-tag list is not an effective per-VNet expansion
        # and cannot prove negative membership for a selected NIC.
        return None
    # Tags may contain BGP, peering, or dynamically maintained service ranges.
    # Never decide membership by a public/private-address naming heuristic.
    tags = [r for r in model.kinds["service_tag"] if r["scope"] == endpoint["scope"] and r["data"].get("name") == value]
    if len(tags) == 1 and model.complete("service_tag", tags[0]["scope"]):
        prefixes = tags[0]["data"].get("properties", {}).get("addressPrefixes")
        if isinstance(prefixes, list):
            model.ref(tags[0], "properties.addressPrefixes")
            return _any(_cidr(p, address) for p in prefixes)
    return None


def _azure_defaults():
    def rule(name, direction, priority, source, destination, access):
        return {"name": name, "properties": {"direction": direction, "priority": priority,
            "sourceAddressPrefix": source, "destinationAddressPrefix": destination,
            "sourcePortRange": "*", "destinationPortRange": "*", "protocol": "*", "access": access}}
    return [rule("AllowVNetInBound", "Inbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow"),
        rule("AllowAzureLoadBalancerInBound", "Inbound", 65001, "AzureLoadBalancer", "*", "Allow"),
        rule("DenyAllInBound", "Inbound", 65500, "*", "*", "Deny"),
        rule("AllowVNetOutBound", "Outbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow"),
        rule("AllowInternetOutBound", "Outbound", 65001, "*", "Internet", "Allow"),
        rule("DenyAllOutBound", "Outbound", 65500, "*", "*", "Deny")]


def _azure_nsg(model, nsg, endpoint, source, destination, direction, query, admin_complete):
    if not model.complete("nsg", nsg["scope"]):
        return model.gap("nsg_rules_incomplete", "The attached NSG rule collection is unavailable or incomplete", [model.ref(nsg, "properties")])
    provenance = nsg["data"].get("_provenance")
    if not isinstance(provenance, dict) or provenance.get("representation") != "full":
        return model.gap("nsg_detail_missing", "The attached Azure NSG needs authoritative full GET detail", [model.ref(nsg, "_provenance")])
    props = nsg["data"].get("properties", {})
    if not isinstance(props, dict) or not isinstance(props.get("securityRules"), list):
        return model.gap("nsg_rules_missing", "Custom NSG rules must be explicitly collected, including an empty list", [model.ref(nsg, "properties.securityRules")])
    if props.get("provisioningState") != "Succeeded":
        return model.gap("nsg_not_ready", "The attached Azure NSG is not proven provisioned", [model.ref(nsg, "properties.provisioningState")])
    defaults = props.get("defaultSecurityRules", _azure_defaults())
    if (not isinstance(defaults, list) or
        any(not isinstance(rule, dict) or not isinstance(rule.get("properties"), dict)
            for rule in props["securityRules"] + defaults)):
        return model.gap("nsg_rule_malformed", "Custom and default NSG rules must contain native rule objects and properties",
            [model.ref(nsg, "properties.securityRules/defaultSecurityRules")])
    if any(rule["properties"].get("provisioningState") != "Succeeded"
        for rule in props["securityRules"] + (defaults if "defaultSecurityRules" in props else [])):
        return model.gap("nsg_rule_not_ready", "An Azure NSG rule is not proven provisioned", [model.ref(nsg, "properties.securityRules/defaultSecurityRules")])
    rules = [(r["properties"].get("priority"), i, r, "securityRules") for i, r in enumerate(props["securityRules"])]
    rules += [(r["properties"].get("priority"), i, r, "defaultSecurityRules") for i, r in enumerate(defaults)]
    rules = [r for r in rules if r[2].get("properties", {}).get("direction") == direction or
        r[2].get("properties", {}).get("direction") not in {"Inbound", "Outbound"}]
    if any(isinstance(priority, bool) or not isinstance(priority, int) for priority, _, _, _ in rules) or len({r[0] for r in rules}) != len(rules):
        return model.gap("nsg_order_ambiguous", "NSG rules require unique native priorities per direction", [model.ref(nsg, "properties.securityRules")])
    if any(not (100 <= priority <= 4096 if origin == "securityRules" else 65000 <= priority <= 65535) for priority, _, _, origin in rules):
        return model.gap("nsg_order_malformed", "NSG custom/default priorities are outside their native supported ranges", [model.ref(nsg, "properties.securityRules/defaultSecurityRules")])
    for _, i, rule, origin in sorted(rules):
        p = rule["properties"]
        if p.get("direction") not in {"Inbound", "Outbound"}:
            return model.gap("nsg_direction_unknown", "An earlier NSG rule has an unrecognized native direction",
                [model.ref(nsg, f"properties.{origin}[{i}].direction")])
        def addresses(singular, plural, subject, asg_field):
            if (plural in p and (not isinstance(p[plural], list) or any(not isinstance(value, str) for value in p[plural])) or
                singular in p and not isinstance(p[singular], str)):
                return None
            asg_refs = p.get(asg_field)
            if asg_field in p and (not isinstance(asg_refs, list) or
                any(not isinstance(ref, dict) or not isinstance(ref.get("id"), str) for ref in asg_refs)):
                return None
            if asg_refs:
                if p.get(plural) or p.get(singular):
                    return None
                if endpoint["vnet"] is None or subject["vnet"] is None or subject["asg_ids"] is None:
                    return None
                if endpoint["vnet"]["id"] != subject["vnet"]["id"]:
                    return False
                model.ref(subject["resource"], "properties.ipConfigurations[].properties.applicationSecurityGroups")
                return any(ref["id"].lower() in subject["asg_ids"] for ref in asg_refs)
            if p.get(plural) and p.get(singular):
                return None
            values = p.get(plural) or ([p[singular]] if p.get(singular) else [])
            return _any(_azure_address_selector(model, v, subject, endpoint) for v in values) if values else None
        def ports(singular, plural, port):
            if (plural in p and (not isinstance(p[plural], list) or any(not isinstance(value, str) for value in p[plural])) or
                singular in p and not isinstance(p[singular], str)):
                return None
            if p.get(plural) and p.get(singular):
                return None
            values = p.get(plural) or ([p[singular]] if p.get(singular) else [])
            # Azure augmented ranges can use commas; other native provider
            # port fields cannot silently acquire this syntax.
            return _any(_ports(part.strip(), port) for v in values for part in v.split(",")) if values else None
        matched = _all([_azure_protocol(p.get("protocol"), query["protocol"]),
            addresses("sourceAddressPrefix", "sourceAddressPrefixes", source, "sourceApplicationSecurityGroups"),
            addresses("destinationAddressPrefix", "destinationAddressPrefixes", destination, "destinationApplicationSecurityGroups"),
            ports("sourcePortRange", "sourcePortRanges", query["source_port"]),
            ports("destinationPortRange", "destinationPortRanges", query["destination_port"])])
        refs = [model.ref(nsg, f"properties.{origin}[{i}]")]
        if matched is None:
            return model.gap("nsg_selector_unresolved", "An earlier NSG source port, service tag, ASG, or selector could change the ordered decision", refs)
        if matched:
            action = p.get("access")
            if action not in {"Allow", "Deny"}:
                return model.gap("nsg_action_unknown", "Native matching NSG action is unrecognized", refs)
            decision = "allowed" if action == "Allow" else "blocked"
            return model.step("policy", decision if admin_complete else "unknown",
                "First ordered matching NSG rule" if admin_complete else "NSG candidate cannot decide before missing overriding security-admin policy context",
                refs, control="azure.nsg", direction=direction, candidate_decision=decision,
                pre_route=direction == "Outbound",
                return_behavior="stateful: established response does not require a reverse NSG allow",
                **({"derived_default": True} if origin == "defaultSecurityRules" and "defaultSecurityRules" not in props else {}))
    return model.gap("nsg_default_rules_unresolved", "No native/default NSG decision is proven", [model.ref(nsg, "properties")])


def _azure_policy(model, endpoint, source, destination, direction, query, admin_complete):
    holders = [endpoint["resource"], endpoint["subnet"]] if direction == "Outbound" else [endpoint["subnet"], endpoint["resource"]]
    decisions = []
    for holder in holders:
        if holder is None or not model.complete(holder["type"], holder["scope"]):
            decisions.append(model.gap("nsg_association_incomplete", "Both NIC and subnet NSG association states must be collected"))
            continue
        reference = holder["data"].get("properties", {}).get("networkSecurityGroup")
        if reference is None:
            decisions.append(model.step("policy", "allowed" if admin_complete else "unknown",
                "Native NIC/subnet has no attached NSG; higher policy context is assessed separately", [model.ref(holder, "properties.networkSecurityGroup")],
                control="azure.nsg", direction=direction))
            continue
        if not isinstance(reference, dict) or not isinstance(reference.get("id"), str) or not reference["id"]:
            decisions.append(model.gap("nsg_association_malformed", "The selected NIC or subnet has an invalid NSG association",
                [model.ref(holder, "properties.networkSecurityGroup")]))
            continue
        nsg = model.find("nsg", reference.get("id"))
        if nsg is None:
            decisions.append(model.gap("nsg_inventory_missing", "A declared NSG was not collected", [model.ref(holder, "properties.networkSecurityGroup")]))
        else:
            decisions.append(_azure_nsg(model, nsg, endpoint, source, destination, direction, query, admin_complete))
    return decisions


def _azure_effective_route(model, endpoint, peer, direction):
    collections = [c for c in model.snapshot["collections"] if c["type"] == "effective_route" and c["scope"] == endpoint["scope"]]
    if len(collections) != 1 or collections[0]["status"] not in {"collected", "empty"}:
        return model.gap("effective_route_inventory_incomplete", "The selected NIC needs a complete effective-route inventory")
    nic_id = endpoint["resource"]["native_id"].lower()
    evidence = collections[0].get("source_evidence")
    proof = [p for p in evidence if isinstance(p, dict) and
        str(p.get("resource_id", "")).lower() == nic_id] if isinstance(evidence, list) else []
    if not proof or any(p.get("source_operation") != "effectiveRouteTable" or
        not _sha256(p.get("response_sha256")) for p in proof):
        return model.gap("effective_route_proof_missing", "Every selected NIC effective-route response page needs valid native query evidence")
    raw_ids = [row.get("id") for row in collections[0]["items"]]
    if (any(not isinstance(row_id, str) or not row_id for row_id in raw_ids) or
        len({row_id.lower() for row_id in raw_ids}) != len(raw_ids)):
        return model.gap("effective_route_identity_ambiguous", "Native effective-route response rows need distinct nonempty IDs")
    rows = [r for r in model.kinds["effective_route"] if r["scope"] == endpoint["scope"]
        and str(r["data"].get("nic_id", "")).lower() == nic_id]
    if any(not isinstance(r["data"].get("nic_id"), str) or not r["data"]["nic_id"]
        for r in model.kinds["effective_route"] if r["scope"] == endpoint["scope"]):
        return model.gap("effective_route_identity_ambiguous",
            "An effective-route row in the selected scope lacks its owning NIC identity")
    if not rows:
        return model.gap("effective_route_nic_missing", "No effective-route response was captured for the selected NIC")
    if any(not isinstance(p := row["data"].get("_provenance"), dict) or
        p.get("source_operation") != "effectiveRouteTable" or p.get("read_only") is not True or
        str(p.get("nic_id", "")).lower() != nic_id or
        not isinstance(row["data"].get("id"), str) or
        not row["data"]["id"].lower().startswith(nic_id + "/effectiveroutes/")
        for row in rows):
        return model.gap("effective_route_row_proof_missing",
            "Selected NIC effective-route rows must carry the native query operation and NIC identity",
            [model.ref(row, "_provenance/nic_id/id") for row in rows])
    choices = []
    for row in rows:
        route = row["data"].get("route")
        if not isinstance(route, dict) or route.get("state") not in {"Active", "Invalid"}:
            return model.gap("effective_route_state_unknown", "Effective-route state is missing or unrecognized", [model.ref(row, "route")])
        if route["state"] == "Invalid":
            continue
        prefixes = route.get("addressPrefix")
        if not isinstance(prefixes, list) or not prefixes:
            return model.gap("effective_route_prefix_missing", "Active effective route lacks native destination prefixes", [model.ref(row, "route.addressPrefix")])
        for prefix in prefixes:
            match = _cidr(prefix, peer["address"])
            if match is None:
                return model.gap("effective_route_prefix_malformed", "An effective-route prefix cannot be evaluated", [model.ref(row, "route.addressPrefix")])
            if match:
                source = route.get("source")
                if source not in {"User", "VirtualNetworkGateway", "Default"}:
                    return model.gap("effective_route_source_unknown", "An active matching effective route has unknown precedence", [model.ref(row, "route.source")])
                choices.append((ipaddress.ip_network(prefix, strict=False).prefixlen, source, route, row))
    if not choices:
        return model.gap("effective_route_selection_unresolved",
            "No captured active route covers the selected address despite Azure system routing; an incomplete effective table cannot prove a drop",
            [model.ref(r, "route") for r in rows])
    service_endpoints = [c for c in choices if c[1] == "Default" and
        c[2].get("nextHopType") == "VirtualNetworkServiceEndpoint"]
    if service_endpoints:
        refs = [model.ref(c[3], "route") for c in service_endpoints]
        model.result["translations"].append({"decision": "unknown", "component": "VirtualNetworkServiceEndpoint", "evidence_refs": refs})
        return model.gap("unsupported_route_component",
            "A matching service-endpoint system route takes precedence over UDRs and does not prove a direct path to the selected NIC", refs)
    # Azure gives local/peering system paths precedence over BGP paths, even
    # when the BGP prefix is more specific. User routes remain candidates.
    preferred = [c for c in choices if c[1] == "Default" and c[2].get("nextHopType") in {"VnetLocal", "VnetPeering"}]
    if preferred:
        choices = [c for c in choices if c[1] != "VirtualNetworkGateway"]
    longest = max(c[0] for c in choices)
    choices = [c for c in choices if c[0] == longest]
    rank = {"User": 3, "VirtualNetworkGateway": 2, "Default": 1}
    best = max(rank[c[1]] for c in choices)
    choices = [c for c in choices if rank[c[1]] == best]
    if len(choices) != 1:
        return model.gap("effective_route_ambiguous", "Equal-priority effective routes cannot establish one next hop", [model.ref(c[3], "route") for c in choices])
    _, source, route, row = choices[0]
    refs = [model.ref(row, "route")]
    hop = route.get("nextHopType")
    if source == "User" and hop not in {"None", "VnetLocal", "Internet", "VirtualAppliance", "VirtualApplianceEcmp", "VirtualNetworkGateway"}:
        return model.gap("effective_route_next_hop_invalid", "An effective user route names a next hop type Azure does not permit for UDRs", refs)
    if hop == "None":
        return model.step("route", "blocked", "Selected active effective route drops traffic", refs, direction=direction, source=source)
    if hop == "VnetLocal":
        if endpoint["vnet"] and peer["vnet"] and endpoint["vnet"]["id"] == peer["vnet"]["id"]:
            return model.step("route", "allowed", "Selected active effective route stays inside the exact VNet", refs, direction=direction, source=source)
        return model.gap("effective_route_domain_mismatch", "A VnetLocal hop cannot prove another native VNet destination", refs)
    if hop == "VnetPeering":
        if source != "Default":
            return model.gap("effective_route_source_unknown", "A peering next hop must be an Azure system route", refs)
        if not endpoint["vnet"] or not peer["vnet"] or endpoint["vnet"]["id"] == peer["vnet"]["id"]:
            return model.gap("effective_route_domain_mismatch", "A peering hop needs two distinct native VNets", refs)
        peers = [r for r in model.kinds["vnet_peering"] if r["native_id"].lower().startswith(endpoint["vnet"]["native_id"].lower() + "/virtualnetworkpeerings/")
            and r["data"].get("properties", {}).get("remoteVirtualNetwork", {}).get("id", "").lower() == peer["vnet"]["native_id"].lower()]
        if len(peers) != 1 or not model.complete("vnet_peering", peers[0]["scope"]):
            return model.gap("peering_context_missing", "The effective peering hop lacks exact scoped peering facts", refs)
        if _azure_peering_ready(model, peers[0]) is not True:
            return "unknown"
        props = peers[0]["data"].get("properties", {})
        refs.append(model.ref(peers[0], "properties"))
        if props.get("peeringState") != "Connected" or props.get("allowVirtualNetworkAccess") is not True or props.get("peeringSyncLevel") != "FullyInSync":
            return model.gap("peering_context_missing", "The referenced peering is not connected, access-enabled, and synchronized", refs)
        if _azure_peering_subnets(peers[0], endpoint, peer) is not True:
            return model.gap("subnet_peering_unmodeled", "Selected local and remote subnets are not both proven members of the peering", refs)
        if peer["address"].version == 4 and props.get("enableOnlyIPv6Peering") is True:
            return model.gap("peering_address_family_unavailable", "IPv6-only peering does not prove an IPv4 path", refs)
        remote_space = props.get("remoteAddressSpace")
        declared = remote_space.get("addressPrefixes") if isinstance(remote_space, dict) else None
        peer_space = peer["vnet"]["data"].get("properties", {}).get("addressSpace")
        observed = peer_space.get("addressPrefixes") if isinstance(peer_space, dict) else None
        if (not isinstance(declared, list) or not isinstance(observed, list) or
            not any(_cidr(prefix, peer["address"]) is True for prefix in declared) or
            not any(_cidr(prefix, peer["address"]) is True for prefix in observed)):
            return model.gap("effective_peering_address_space_unproven",
                "The selected effective peering route conflicts with the peering's synchronized remote address space",
                refs + [model.ref(peers[0], "properties.remoteAddressSpace.addressPrefixes"),
                    model.ref(peer["vnet"], "properties.addressSpace.addressPrefixes")])
        table_ref = endpoint["subnet"]["data"].get("properties", {}).get("routeTable") if endpoint.get("subnet") else None
        table = model.find("route_table", table_ref["id"]) if isinstance(table_ref, dict) and isinstance(table_ref.get("id"), str) else None
        if table and model.complete("route_table", table["scope"]):
            table_props = table["data"].get("properties", {})
            provenance = table["data"].get("_provenance", {})
            if (isinstance(table_props, dict) and isinstance(provenance, dict) and
                provenance.get("representation") == "full" and
                isinstance(provenance.get("api_version"), str) and
                re.fullmatch(r"\d{4}-\d{2}-\d{2}", provenance["api_version"]) and
                provenance["api_version"] >= "2025-07-01" and
                table_props.get("provisioningState") == "Succeeded" and table_props.get("disablePeeringRoute") == "All"):
                return model.gap("effective_peering_route_conflict",
                    "The active NIC peering route conflicts with an associated table that disables peering routes",
                    refs + [model.ref(endpoint["subnet"], "properties.routeTable"), model.ref(table, "properties.disablePeeringRoute")])
        return model.step("route", "allowed", "Selected effective route and native peering reach the exact remote subnet", refs, direction=direction, source=source)
    model.result["translations"].append({"decision": "unknown", "component": hop or "unknown_next_hop", "evidence_refs": refs})
    return model.gap("unsupported_route_component", "The selected effective route uses an unmodeled gateway, appliance, Internet, or service path", refs)


def _azure_route(model, endpoint, peer, direction):
    if not endpoint["subnet"] or not endpoint["vnet"] or not peer["vnet"]:
        return model.gap("route_domain_missing", "Native Azure subnet/VNet context is missing")
    if any(c["type"] == "effective_route" for c in model.snapshot["collections"]):
        return _azure_effective_route(model, endpoint, peer, direction)
    if not model.context_complete("routing") or model.context("routing").get("bgp") != "none":
        return model.gap("azure_route_context_missing", "User routes do not establish effective routing without complete system/BGP context")
    same = endpoint["vnet"]["id"] == peer["vnet"]["id"]
    custom = []
    peering_routes_enabled = True
    table_ref = endpoint["subnet"]["data"].get("properties", {}).get("routeTable")
    if table_ref is not None:
        if not isinstance(table_ref, dict) or not isinstance(table_ref.get("id"), str) or not table_ref["id"]:
            return model.gap("route_table_association_malformed", "The selected subnet has a malformed UDR table association",
                [model.ref(endpoint["subnet"], "properties.routeTable")])
        table = model.find("route_table", table_ref["id"])
        if table is None or not model.complete("route_table", table["scope"]) or not isinstance(table["data"].get("properties", {}).get("routes"), list):
            return model.gap("route_table_incomplete", "The explicitly associated Azure route table is missing or incomplete", [model.ref(endpoint["subnet"], "properties.routeTable")])
        provenance = table["data"].get("_provenance")
        if not isinstance(provenance, dict) or provenance.get("representation") != "full":
            return model.gap("route_table_detail_missing", "The associated Azure route table needs authoritative full GET detail", [model.ref(table, "_provenance")])
        if not same and (not isinstance(provenance.get("api_version"), str) or
            not re.fullmatch(r"\d{4}-\d{2}-\d{2}", provenance["api_version"]) or
            provenance["api_version"] < "2025-07-01"):
            return model.gap("peering_route_api_version_old", "The route-table API version cannot expose disabled peering routes", [model.ref(table, "_provenance.api_version")])
        table_props = table["data"]["properties"]
        if table_props.get("provisioningState") != "Succeeded":
            return model.gap("route_table_not_ready", "The associated Azure route table is not proven provisioned", [model.ref(table, "properties.provisioningState")])
        if not same:
            peering_mode = table_props.get("disablePeeringRoute")
            if not isinstance(peering_mode, str) or peering_mode not in {"None", "All"}:
                return model.gap("peering_route_setting_unknown", "The associated route table does not prove whether peering routes are enabled", [model.ref(table, "properties.disablePeeringRoute")])
            peering_routes_enabled = peering_mode == "None"
        for i, r in enumerate(table["data"]["properties"]["routes"]):
            if not isinstance(r, dict) or not isinstance(r.get("properties"), dict):
                return model.gap("route_entry_malformed", "An Azure user-defined route is malformed", [model.ref(table, f"properties.routes[{i}]")])
            p = r.get("properties", {})
            if p.get("provisioningState") != "Succeeded":
                return model.gap("route_not_ready", "An Azure user-defined route is not proven provisioned", [model.ref(table, f"properties.routes[{i}].properties.provisioningState")])
            match = _cidr(p.get("addressPrefix"), peer["address"])
            if match is None:
                return model.gap("route_selector_unresolved", "Azure UDR address tags/prefixes are not resolved", [model.ref(table, f"properties.routes[{i}]")])
            if match:
                custom.append((ipaddress.ip_network(p["addressPrefix"], strict=False).prefixlen, p.get("nextHopType"), model.ref(table, f"properties.routes[{i}]")))
    system = []
    if same:
        for prefix in endpoint["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", []):
            if _cidr(prefix, peer["address"]) is True:
                system.append((ipaddress.ip_network(prefix, strict=False).prefixlen, "VnetLocal", model.ref(endpoint["vnet"], "properties.addressSpace.addressPrefixes")))
    elif peering_routes_enabled:
        peerings = [r for r in model.kinds["vnet_peering"] if r["data"].get("properties", {}).get("remoteVirtualNetwork", {}).get("id", "").lower() == peer["vnet"]["native_id"].lower()
            and r["native_id"].lower().startswith(endpoint["vnet"]["native_id"].lower() + "/virtualnetworkpeerings/")]
        if len(peerings) == 1:
            if not model.complete("vnet_peering", peerings[0]["scope"]):
                return model.gap("peering_collection_incomplete", "Native peering collection is unavailable or partial", [model.ref(peerings[0], "properties")])
            if _azure_peering_ready(model, peerings[0]) is not True:
                return "unknown"
            p = peerings[0]["data"].get("properties", {})
            refs = model.ref(peerings[0], "properties")
            if p.get("peeringState") != "Connected" or p.get("allowVirtualNetworkAccess") is not True:
                return model.gap("peering_context_missing", "Declared peering is disconnected or access-disabled; unsupported alternate gateway/appliance routes are not ruled out", [refs])
            if p.get("peeringSyncLevel") != "FullyInSync":
                return model.gap("peering_context_missing", "Peering address-space synchronization is not complete", [refs])
            if _azure_peering_subnets(peerings[0], endpoint, peer) is not True:
                return model.gap("subnet_peering_unmodeled", "Selected local and remote subnets are not both proven members of the peering", [refs])
            if peer["address"].version == 4 and p.get("enableOnlyIPv6Peering") is True:
                return model.gap("peering_address_family_unavailable", "IPv6-only peering does not prove an IPv4 path", [refs])
            remote_space = p.get("remoteAddressSpace")
            declared = remote_space.get("addressPrefixes") if isinstance(remote_space, dict) else None
            peer_space = peer["vnet"]["data"].get("properties", {}).get("addressSpace")
            observed = peer_space.get("addressPrefixes") if isinstance(peer_space, dict) else None
            if (not isinstance(declared, list) or not isinstance(observed, list) or
                not any(_cidr(prefix, peer["address"]) is True for prefix in declared) or
                not any(_cidr(prefix, peer["address"]) is True for prefix in observed)):
                return model.gap("peering_address_space_unproven",
                    "The declared peering route needs matching synchronized remote and collected VNet address spaces",
                    [refs, model.ref(peerings[0], "properties.remoteAddressSpace.addressPrefixes"),
                        model.ref(peer["vnet"], "properties.addressSpace.addressPrefixes")])
            for prefix in declared:
                if _cidr(prefix, peer["address"]) is True:
                    system.append((ipaddress.ip_network(prefix, strict=False).prefixlen, "VnetPeering", refs))
        else:
            return model.gap("peering_context_missing", "Cross-VNet routing requires native connected access-enabled peering in each direction")
    choices = [(prefix, 1, hop, ref) for prefix, hop, ref in custom] + [(prefix, 0, hop, ref) for prefix, hop, ref in system]
    if not choices:
        return model.gap("route_not_proven", "No supported local/peered system route reaches the selected private endpoint")
    best = max((c[0], c[1]) for c in choices)
    choices = [c for c in choices if c[:2] == best]
    if len(choices) != 1:
        return model.gap("route_priority_ambiguous", "Azure equal-prefix route alternatives need effective-route evidence")
    _, source, hop, ref = choices[0]
    if source == 1 and hop not in {"None", "VnetLocal", "Internet", "VirtualAppliance", "VirtualApplianceEcmp", "VirtualNetworkGateway"}:
        return model.gap("route_next_hop_invalid", "A user-defined route has a next hop type that Azure does not permit",
            [ref])
    if hop == "None":
        return model.step("route", "blocked", "Selected longest-prefix UDR has the None drop next hop", [ref], direction=direction)
    if hop == "VnetLocal" and not same:
        return model.gap("route_domain_mismatch", "A VnetLocal next hop cannot prove traffic to a different native VNet", [ref])
    if hop in {"VnetLocal", "VnetPeering"}:
        return model.step("route", "allowed", "Selected native/system private-network route", [ref], direction=direction, next_hop=hop)
    model.result["translations"].append({"decision": "unknown", "component": hop, "evidence_refs": [ref]})
    return model.gap("unsupported_route_component", "Azure Internet, NAT, VPN gateway, and virtual-appliance routing are not modeled", [ref])


def _azure(model, source, destination, query):
    endpoints = [_azure_endpoint(model, r, query["address_family"]) for r in (source, destination)]
    if not all(e and e["address"] for e in endpoints):
        return []
    src, dst = endpoints
    model.result["endpoints"] = _endpoint_details(src, dst)
    if src["resource"]["id"] == dst["resource"]["id"]:
        return [model.gap("self_traffic_semantics_unproven",
            "Traffic to this VM NIC's own private IP may stay inside the host; NSG and VNet routing rules do not prove a drop",
            [model.ref(src["resource"], "properties.ipConfigurations")])]
    admin_context = model.context("security_admin")
    admin_complete = model.context_complete("security_admin")
    declared_admin = admin_context.get("policies")
    admin_collections = [c for c in model.snapshot["collections"] if c["type"] == "security_admin_rule"]
    observed_admin = [item for c in admin_collections for item in c["items"]]
    inventory_complete = all(c["status"] in {"collected", "empty"} for c in admin_collections)
    inventory_matches = (isinstance(declared_admin, list) and
        all(isinstance(value, str) for value in declared_admin) and
        all(isinstance(item.get("id"), str) for item in observed_admin) and
        sorted(declared_admin) == sorted(item.get("id") for item in observed_admin))
    selected_vnets = {e["vnet"]["native_id"].lower(): e["scope"] for e in (src, dst) if e["vnet"]}
    selected_queries_proven = bool(selected_vnets) and all(
        len(rows := [c for c in admin_collections if c["scope"] == scope]) == 1 and
        rows[0]["status"] in {"collected", "empty"} and
        any(isinstance(proof, dict) and proof.get("source_operation") == "listNetworkManagerEffectiveSecurityAdminRules"
            and str(proof.get("resource_id", "")).lower() == vnet_id and
            _sha256(proof.get("response_sha256"))
            for proof in rows[0].get("source_evidence", []))
        for vnet_id, scope in selected_vnets.items())
    admin_empty = admin_complete and declared_admin == [] and inventory_complete and not observed_admin and selected_queries_proven
    admin_allow_only = (admin_complete and inventory_complete and inventory_matches and
        selected_queries_proven and bool(observed_admin) and
        all(isinstance(item.get("rule"), dict) and isinstance(item["rule"].get("properties"), dict) and
            item["rule"]["properties"].get("access") == "Allow"
            for item in observed_admin))
    admin = admin_empty or admin_allow_only
    if admin_allow_only:
        model.step("policy", "allowed", "Complete effective security-admin rules contain only Allow actions, which continue to NSGs",
            [model.ref(resource, "rule.properties.access") for resource in model.kinds["security_admin_rule"]],
            control="azure.security_admin", candidate_decision="allowed")
    if (not inventory_complete or
        (declared_admin == [] and observed_admin) or
        (isinstance(declared_admin, list) and observed_admin and not inventory_matches)):
        model.gap("azure_security_admin_inventory_conflict", "Observed or incomplete security-admin rules contradict the effective-policy context")
    if not admin:
        model.gap("azure_security_admin_context_missing", "Higher-priority security-admin AlwaysAllow/Deny policies can bypass NSGs; absence is not assumed")
    checks = _azure_policy(model, src, src, dst, "Outbound", query, admin) + _azure_policy(model, dst, src, dst, "Inbound", query, admin)
    if src["vnet"] and dst["vnet"] and src["vnet"]["id"] != dst["vnet"]["id"]:
        a = src["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", [])
        b = dst["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", [])
        if any(ipaddress.ip_network(x, strict=False).version == ipaddress.ip_network(y, strict=False).version and
               ipaddress.ip_network(x, strict=False).overlaps(ipaddress.ip_network(y, strict=False)) for x in a for y in b):
            checks.append(model.gap("overlapping_address_domains", "Peering does not establish an unambiguous path across overlapping VNet address domains"))
    checks += [_azure_route(model, src, dst, "forward"), _azure_route(model, dst, src, "return")]
    return checks


def _gcp_endpoint(model, resource, family):
    selected = resource
    if resource["type"] == "instance_interface":
        parent = model.by_id.get(resource["data"].get("instance_resource_id"))
        index = resource["data"].get("interface_index")
        if (parent is None or parent["type"] != "instance" or
            not isinstance(index, int) or isinstance(index, bool)):
            model.gap("endpoint_interface_ambiguous", "The selected GCP interface has no exact collected VM parent")
            return None
        resource = parent
    elif resource["type"] == "instance":
        index = 0
    else:
        model.gap("unsupported_endpoint_type", "GCP selected endpoints must be collected VM instances or their interfaces", [model.ref(resource, "data")])
        return None
    if resource["data"].get("status") != "RUNNING":
        model.gap("endpoint_not_running", "The selected GCP VM is not proven RUNNING; a configured network path cannot prove a live endpoint",
            [model.ref(resource, "status")])
    interfaces = resource["data"].get("networkInterfaces")
    if (not isinstance(interfaces, list) or
        (selected["type"] == "instance" and len(interfaces) != 1) or
        not 0 <= index < len(interfaces) or not isinstance(interfaces[index], dict)):
        model.gap("endpoint_interface_ambiguous", "Select a collected GCP interface when a VM has multiple native interfaces", [model.ref(resource, "networkInterfaces")])
        return None
    interface = interfaces[index]
    interface_path = f"networkInterfaces[{index}]"
    if family == "ipv6" and interface.get("ipv6AccessType") != "INTERNAL":
        model.gap("unsupported_external_ipv6", "GCP IPv6 modeling requires an observed internal IPv6 interface; external addressing is not a private-route assumption", [model.ref(resource, f"{interface_path}.ipv6AccessType")])
        return None
    address = _address(model, [interface.get("networkIP"), interface.get("ipv6Address")], family, resource)
    network_id = _gcp_scoped_ref(interface.get("network"), "network", resource["scope"])
    subnet_id = _gcp_scoped_ref(interface.get("subnetwork"), "subnetwork", resource["scope"])
    network = model.find("network", network_id) if network_id else None
    subnet = model.find("subnetwork", subnet_id) if subnet_id else None
    if network is None or subnet is None:
        model.gap("network_domain_missing", "Full host-project global network and regional subnetwork facts must be collected", [model.ref(resource, interface_path)])
    elif _gcp_scoped_ref(subnet["data"].get("network"), "network", subnet["scope"]) != _gcp_network_id(network):
        model.gap("network_domain_mismatch", "Interface and subnet network references disagree", [model.ref(subnet, "network")])
        subnet = None
    elif "subnetworks" in network["data"]:
        listed = network["data"]["subnetworks"]
        if (not isinstance(listed, list) or
            any(_gcp_scoped_ref(value, "subnetwork", network["scope"]) is None for value in listed) or
            _gcp_id(subnet["native_id"]) not in {
                _gcp_scoped_ref(value, "subnetwork", network["scope"]) for value in listed}):
            model.gap("network_domain_subnet_membership_mismatch",
                "The selected subnet is missing from the network's native subnet inventory",
                [model.ref(network, "subnetworks"), model.ref(subnet, "network")])
            subnet = None
    if family == "ipv6" and address and subnet and (
        interface.get("stackType") not in {"IPV4_IPV6", "IPV6_ONLY"} or
        subnet["data"].get("stackType") not in {"IPV4_IPV6", "IPV6_ONLY"} or
        subnet["data"].get("ipv6AccessType") != "INTERNAL"):
        model.gap("endpoint_ipv6_capability_conflict",
            "The VM interface and its subnet must both declare IPv6-capable stacks and internal IPv6 access",
            [model.ref(resource, f"{interface_path}.stackType/ipv6AccessType"),
             model.ref(subnet, "stackType/ipv6AccessType/internalIpv6Prefix")])
    if family == "ipv4" and address and subnet and (
        interface.get("stackType", "IPV4_ONLY") not in {"IPV4_ONLY", "IPV4_IPV6"} or
        subnet["data"].get("stackType", "IPV4_ONLY") not in {"IPV4_ONLY", "IPV4_IPV6"}):
        model.gap("endpoint_ipv4_capability_conflict",
            "The VM interface and its subnet must both permit IPv4 addresses",
            [model.ref(resource, f"{interface_path}.stackType"), model.ref(subnet, "stackType")])
    if address and subnet:
        prefixes = [subnet["data"].get("ipCidrRange"), subnet["data"].get("internalIpv6Prefix")]
        if not any(_cidr(p, address) is True for p in prefixes if p):
            model.gap("endpoint_outside_subnet", "The selected primary address is not proven inside its native subnet family", [model.ref(subnet, "ipCidrRange/internalIpv6Prefix")])
    for dependency in (resource, network, subnet):
        if dependency and not model.complete(dependency["type"], dependency["scope"]):
            model.gap("endpoint_association_incomplete", "VM/global-network/subnetwork collection visibility is incomplete", [model.ref(dependency, "data")])
    tags = resource["data"].get("tags", {}).get("items", [])
    accounts = resource["data"].get("serviceAccounts", [])
    if (not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags) or
        not isinstance(accounts, list) or any(not isinstance(account, dict) or
            not isinstance(account.get("email"), str) for account in accounts)):
        model.gap("endpoint_firewall_identity_malformed", "Native VM tags or service-account identities cannot be matched safely",
            [model.ref(resource, "tags.items/serviceAccounts")])
        return None
    return {"resource": resource, "selected": selected, "address": address, "scope": resource["scope"],
            "network": network, "subnet": subnet, "interface": interface, "interface_index": index,
            "tags": tags, "service_accounts": [account["email"] for account in accounts]}


def _gcp_sa_match(model, values, endpoint):
    matched = set(values).intersection(endpoint["service_accounts"])
    if not matched:
        return False
    network_project = _gcp_network_id(endpoint["network"]).split("/")[1]
    vm_project = endpoint["scope"].split("/")[-1]
    # Native shared-VPC interface evidence establishes the selected VM's service
    # project. Arbitrary third-project service-account criteria stay unresolved.
    for email in matched:
        if email and "@" in email and email.endswith(".iam.gserviceaccount.com"):
            project = email.split("@", 1)[1].removesuffix(".iam.gserviceaccount.com")
            if project in {network_project, vm_project}:
                return True
    return None


def _gcp_protocol(native, requested):
    if not isinstance(native, str):
        return None
    if native == "all":
        return True
    if native in {"tcp", "udp", "icmp", "esp", "ah", "ipip", "sctp"}:
        return native == requested
    if native.isascii() and native.isdecimal() and 0 <= int(native) <= 255:
        return int(native) == (6 if requested == "tcp" else 17)
    return None


def _gcp_rule_match(model, rule, endpoint, peer, direction, query, owner_scope):
    network = rule.get("network")
    project_scope = owner_scope if owner_scope.startswith("projects/") else f"projects/{owner_scope}"
    if network is None:
        network = f"{project_scope}/global/networks/default"
    elif isinstance(network, str) and network.startswith("global/networks/"):
        network = f"{project_scope}/{network}"
    if not isinstance(network, str) or not _gcp_id(network).startswith("projects/"):
        return None
    if _gcp_id(network) != _gcp_network_id(endpoint["network"]):
        return False
    native_direction = rule.get("direction", "INGRESS")
    if native_direction in {"INGRESS", "EGRESS"} and native_direction != direction:
        return False
    disabled = rule.get("disabled", False)
    if disabled is True:
        return False
    if not isinstance(disabled, bool) or native_direction not in {"INGRESS", "EGRESS"}:
        return None
    selector_fields = ("targetTags", "targetServiceAccounts", "sourceTags", "sourceServiceAccounts",
        "sourceRanges", "destinationRanges")
    if any(field in rule and (not isinstance(rule[field], list) or
        any(not isinstance(value, str) for value in rule[field])) for field in selector_fields):
        return None
    if (rule.get("targetTags") and rule.get("targetServiceAccounts")) or (rule.get("sourceTags") and rule.get("sourceServiceAccounts")) or (rule.get("targetTags") and rule.get("sourceServiceAccounts")) or (rule.get("targetServiceAccounts") and rule.get("sourceTags")):
        return None
    if direction == "EGRESS" and (rule.get("sourceTags") or rule.get("sourceServiceAccounts")):
        return None
    target = bool(set(rule["targetTags"]).intersection(endpoint["tags"])) if rule.get("targetTags") else _gcp_sa_match(model, rule["targetServiceAccounts"], endpoint) if rule.get("targetServiceAccounts") else True
    actions = rule.get("denied", rule.get("allowed"))
    if (not isinstance(actions, list) or not actions or ("allowed" in rule and "denied" in rule) or
        any(not isinstance(action, dict) or ("ports" in action and
            (not isinstance(action["ports"], list) or any(not isinstance(port, str) for port in action["ports"]) or
             any(port in {"*", "Any", "any"} for port in action["ports"]) or
             (action["ports"] and str(action.get("IPProtocol", "")).lower() not in {"tcp", "udp", "6", "17"})))
            for action in actions)):
        return None
    ports = _any(_all([_gcp_protocol(a.get("IPProtocol"), query["protocol"]),
        _any(_ports(p, query["destination_port"]) for p in a["ports"]) if a.get("ports") else True]) for a in actions)
    if direction == "INGRESS":
        source = []
        if rule.get("sourceRanges"):
            source += [_cidr(p, peer["address"]) for p in rule["sourceRanges"]]
        same_network = peer["network"] and peer["network"]["id"] == endpoint["network"]["id"]
        if rule.get("sourceTags"):
            source.append(same_network and bool(set(rule["sourceTags"]).intersection(peer["tags"])))
        if rule.get("sourceServiceAccounts"):
            source.append(_gcp_sa_match(model, rule["sourceServiceAccounts"], peer) if same_network else False)
        if not any(rule.get(k) for k in ("sourceRanges", "sourceTags", "sourceServiceAccounts")):
            source = [_cidr("0.0.0.0/0", peer["address"])]
        destination = _any(_cidr(p, endpoint["address"]) for p in rule["destinationRanges"]) if rule.get("destinationRanges") else True
        return _all([target, ports, _any(source), destination])
    destination = _any(_cidr(p, peer["address"]) for p in (rule.get("destinationRanges") or ["0.0.0.0/0"]))
    source = _any(_cidr(p, endpoint["address"]) for p in rule["sourceRanges"]) if rule.get("sourceRanges") else True
    return _all([target, ports, source, destination])


def _gcp_firewall(model, endpoint, peer, direction, query, hierarchy_complete):
    owner_scope = _gcp_owner_scope(model, "firewall", endpoint["network"]) if endpoint["network"] else None
    if owner_scope is None or not model.complete("firewall", owner_scope):
        return model.gap("firewall_collection_incomplete", "Host-project network firewall collection is missing, denied, or partial")
    candidates = []
    for resource in model.kinds["firewall"]:
        if resource["scope"] != owner_scope:
            continue
        rule = resource["data"]
        match = _gcp_rule_match(model, rule, endpoint, peer, direction, query, owner_scope)
        if match is False:
            continue
        priority = rule.get("priority", 1000)
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 65535:
            return model.gap("firewall_order_malformed", "A potentially matching firewall priority is invalid", [model.ref(resource, "priority")])
        action = "blocked" if "denied" in rule else "allowed"
        candidates.append((priority, resource, match, action))
    for priority in sorted({c[0] for c in candidates}):
        peers = [c for c in candidates if c[0] == priority]
        denied = [c for c in peers if c[2] is True and c[3] == "blocked"]
        allowed = [c for c in peers if c[2] is True and c[3] == "allowed"]
        uncertain = [c for c in peers if c[2] is None]
        refs = [model.ref(c[1], "data") for c in peers]
        decision = "blocked" if denied else "allowed" if allowed and not any(c[3] == "blocked" for c in uncertain) else None
        if decision is None:
            return model.gap("firewall_selector_unresolved", "A higher/equal-priority tag, service-account, or rule selector could alter the ordered result", refs)
        return model.step("policy", decision if hierarchy_complete else "unknown",
            "Highest-priority matching VPC firewall rule; deny wins an equal-priority tie" if hierarchy_complete else
            "VPC firewall candidate cannot decide before missing hierarchy/network-firewall policy context", refs,
            control="gcp.firewall", direction=direction, priority=priority, candidate_decision=decision,
            pre_route=direction == "EGRESS",
            return_behavior="stateful: matching response traffic does not require reverse firewall allowance")
    decision = "blocked" if direction == "INGRESS" else "allowed"
    return model.step("policy", decision if hierarchy_complete else "unknown", "Native implied ingress deny / egress allow after complete VPC rule evaluation",
        [model.ref(endpoint["network"], "network")], control="gcp.firewall", direction=direction, candidate_decision=decision, implied_default=True,
        pre_route=direction == "EGRESS")


def _gcp_regional_policies_absent(model, endpoint):
    network = endpoint["network"]
    subnet = endpoint["subnet"]
    if not network or not subnet:
        return False
    link = _gcp_id(subnet["data"].get("selfLink", subnet["native_id"]))
    match = re.fullmatch(r"projects/[^/]+/regions/([a-z0-9-]+)/subnetworks/[^/]+", link)
    owner_scope = _gcp_owner_scope(model, "effective_firewall", network)
    if not match:
        model.gap("gcp_effective_firewall_identity_missing", "Selected subnet region and host-project VPC identity are required for regional firewall policy proof")
        return False
    if owner_scope is None:
        model.gap("gcp_regional_firewall_inventory_incomplete", "The selected host project has no regional effective-firewall inventory")
        return False
    collections = model.collections.get(("effective_firewall", owner_scope), [])
    if (len(collections) != 1 or collections[0]["status"] not in {"collected", "empty"} or
        not isinstance(collections[0].get("source_requests"), list) or
        not collections[0]["source_requests"]):
        model.gap("gcp_regional_firewall_inventory_incomplete", "A native regional effective-firewall read is required for the selected VPC and subnet region")
        return False
    rows = [resource for resource in model.kinds["effective_firewall"] if resource["scope"] == owner_scope and
        _gcp_id(resource["data"].get("network", "")) == _gcp_network_id(network) and
        resource["data"].get("region") == match.group(1)]
    if len(rows) != 1:
        model.gap("gcp_regional_firewall_read_missing", "Exactly one native regional effective-firewall response must match the selected VPC and region")
        return False
    row = rows[0]
    provenance = row["data"].get("_provenance")
    policies = row["data"].get("firewallPolicys")
    collection_requests = collections[0]["source_requests"]
    row_requests = provenance.get("source_requests") if isinstance(provenance, dict) else None
    refs = [model.ref(row, "firewallPolicys/_provenance")]
    if (not isinstance(provenance, dict) or
        not isinstance(row_requests, list) or not row_requests or
        any(not isinstance(request, str) or not request for request in collection_requests + row_requests) or
        not set(row_requests).issubset(collection_requests) or
        row["data"].get("effective_source_operation") != "regionNetworkFirewallPolicies.getEffectiveFirewalls" or
        not isinstance(policies, list) or any(not isinstance(policy, dict) for policy in policies)):
        model.gap("gcp_regional_firewall_read_malformed", "The selected regional effective-firewall response lacks native policy detail", refs)
        return False
    if policies:
        model.gap("gcp_regional_firewall_policy_present", "Effective regional or system firewall policies may override classic VPC firewall rules", refs)
        return False
    return True


def _gcp_peering_ranges(model, network, scope):
    """Collect native subnet routes that must not overlap a peered VPC."""
    owner_id = _gcp_network_id(network)
    ranges = []
    for subnet in model.kinds["subnetwork"]:
        if subnet["scope"] != scope:
            continue
        observed_owner = _gcp_scoped_ref(subnet["data"].get("network"), "network", scope)
        if observed_owner is None:
            model.gap("peering_subnet_inventory_malformed", "A host-project subnet has no usable native network owner",
                [model.ref(subnet, "network")])
            return None
        if observed_owner != owner_id:
            continue
        secondary = subnet["data"].get("secondaryIpRanges", [])
        if not isinstance(secondary, list) or any(not isinstance(value, dict) or
            not isinstance(value.get("ipCidrRange"), str) for value in secondary):
            model.gap("peering_subnet_inventory_malformed", "Local secondary subnet ranges are malformed",
                [model.ref(subnet, "secondaryIpRanges")])
            return None
        prefixes = [("ipCidrRange", subnet["data"].get("ipCidrRange")),
            ("internalIpv6Prefix", subnet["data"].get("internalIpv6Prefix")),
            ("externalIpv6Prefix", subnet["data"].get("externalIpv6Prefix"))]
        prefixes += [("secondaryIpRanges", value["ipCidrRange"]) for value in secondary]
        for field, prefix in prefixes:
            if prefix is None:
                continue
            try:
                parsed = ipaddress.ip_network(prefix, strict=False)
            except (ValueError, TypeError):
                model.gap("peering_subnet_inventory_malformed", "A peered subnet route range is malformed",
                    [model.ref(subnet, field)])
                return None
            ranges.append((parsed, subnet, field))
    return ranges


def _gcp_route(model, endpoint, peer, direction):
    if not endpoint["network"] or not peer["network"] or not endpoint["subnet"] or not peer["subnet"]:
        return model.gap("route_domain_missing", "Native host-project network/subnet context is missing")
    context = model.context("routing")
    route_scope = _gcp_owner_scope(model, "route", endpoint["network"])
    if route_scope is None or not model.complete("route", route_scope):
        return model.gap("route_collection_incomplete", "Native selected-network route visibility is incomplete")
    if model.context_complete("routing") and context.get("policy_based_routes") != "none":
        return model.gap("gcp_route_context_missing", "Effective policy-based routing context is not proven absent")
    explicit_context = model.context_complete("routing") and context.get("policy_based_routes") == "none"
    # Regular local and peering subnet routes precede custom static and
    # dynamic routes. Policy-based routes precede subnet routes, so their
    # absence must still be proven for the selected network.
    native_policy_routes = model.collections.get(("policy_based_route", route_scope), [])
    native_context = (len(native_policy_routes) == 1 and native_policy_routes[0]["status"] == "empty" and
        native_policy_routes[0]["items"] == [] and
        isinstance(native_policy_routes[0].get("source_requests"), list) and
        bool(native_policy_routes[0]["source_requests"]) and
        all(isinstance(request, str) and request for request in native_policy_routes[0]["source_requests"]))
    route_overrides = [c for c in model.snapshot["collections"] if c["type"] == "policy_based_route"]
    if any(c["status"] not in {"collected", "empty"} or c["items"] for c in route_overrides if c["scope"] == route_scope):
        return model.gap("gcp_policy_route_inventory_conflict", "Observed or incomplete policy-based routes contradict an empty policy-route context")
    if not explicit_context and not native_context:
        return model.gap("gcp_route_context_missing", "Policy-based route absence is not proven for the selected network")
    if model.context_complete("routing") and context.get("dynamic_routes") == "none":
        routers = [c for c in model.snapshot["collections"] if c["type"] == "router"]
        if any(c["status"] not in {"collected", "empty"} or any(r.get("bgpPeers") for r in c["items"]) for c in routers if c["scope"] == route_scope):
            return model.gap("gcp_dynamic_route_inventory_conflict", "Observed or incomplete Cloud Router BGP context contradicts an empty dynamic-route context")
    if peer["subnet"]["data"].get("purpose", "PRIVATE") != "PRIVATE":
        return model.gap("unsupported_subnet_purpose", "Proxy, hybrid, private-service-connect, and special-purpose subnet routing is not modeled", [model.ref(peer["subnet"], "purpose")])
    hybrid = peer["subnet"]["data"].get("allowSubnetCidrRoutesOverlap", False)
    if not isinstance(hybrid, bool):
        return model.gap("hybrid_subnet_state_unknown", "Native hybrid subnet routing state is malformed", [model.ref(peer["subnet"], "allowSubnetCidrRoutesOverlap")])
    if hybrid:
        return model.gap("hybrid_subnet_route_unknown", "Hybrid subnet routing allows overlapping custom routes; the regular subnet route alone cannot decide this destination", [model.ref(peer["subnet"], "allowSubnetCidrRoutesOverlap")])
    if endpoint["network"]["id"] == peer["network"]["id"]:
        return model.step("route", "allowed", "Native regular subnet route within one global host-project VPC takes precedence over custom static routes",
            [model.ref(peer["subnet"], "ipCidrRange/internalIpv6Prefix"), model.ref(endpoint["network"], "selfLink")], direction=direction)
    peerings = endpoint["network"]["data"].get("peerings")
    if not isinstance(peerings, list) or any(not isinstance(p, dict) for p in peerings):
        return model.gap("peering_inventory_malformed", "Native network peerings must be a list of peering objects",
            [model.ref(endpoint["network"], "peerings")])
    peers = [p for p in peerings
        if _gcp_peering_network_id(p.get("network"), endpoint["network"]) == _gcp_network_id(peer["network"])]
    if len(peers) != 1:
        return model.gap("peering_context_missing", "Cross-network subnet routing needs native peering to the exact host-project network in each direction")
    peering = peers[0]
    refs = [model.ref(endpoint["network"], "peerings")]
    if peering.get("state") != "ACTIVE":
        return model.gap("peering_context_missing", "Native peering is not proven active; unsupported static next-hop alternatives are not modeled", refs)
    local_ranges = _gcp_peering_ranges(model, endpoint["network"], endpoint["subnet"]["scope"])
    peer_ranges = _gcp_peering_ranges(model, peer["network"], peer["subnet"]["scope"])
    if local_ranges is None or peer_ranges is None:
        return "unknown"
    for family in (4, 6):
        left = sorted((row for row in local_ranges if row[0].version == family), key=lambda row: int(row[0].network_address))
        right = sorted((row for row in peer_ranges if row[0].version == family), key=lambda row: int(row[0].network_address))
        i = j = 0
        while i < len(left) and j < len(right):
            local_prefix, local_subnet, local_field = left[i]
            peer_prefix, peer_subnet, peer_field = right[j]
            if local_prefix.overlaps(peer_prefix):
                return model.gap("overlapping_address_domains", "Collected subnet route ranges overlap across supposedly active peered VPCs",
                    refs + [model.ref(local_subnet, local_field), model.ref(peer_subnet, peer_field)])
            if int(local_prefix.broadcast_address) < int(peer_prefix.broadcast_address):
                i += 1
            else:
                j += 1
    if peering.get("exchangeSubnetRoutes") is False:
        return model.gap("peering_subnet_exchange_unknown", "Native peering does not prove subnet-route exchange", refs)
    connection = peering.get("connectionStatus", {})
    if not isinstance(connection, dict):
        return model.gap("peering_status_malformed", "Native effective peering status must be an object", refs)
    traffic = connection.get("trafficConfiguration", {})
    consensus = connection.get("consensusState", {})
    if not isinstance(traffic, dict) or not isinstance(consensus, dict):
        return model.gap("peering_status_malformed", "Native effective peering traffic and consensus status must be objects", refs)
    if peer["address"].version == 6:
        effective_stack = traffic.get("stackType")
        if effective_stack != "IPV4_IPV6":
            return model.gap("peering_ipv6_context_missing", "Peering does not prove effective IPv6 subnet route exchange", refs)
    if peer["address"].version == 4:
        prefix = peer["subnet"]["data"].get("ipCidrRange")
        if not isinstance(prefix, str):
            return model.gap("peering_subnet_prefix_missing", "The peer IPv4 subnet route has no native prefix", [model.ref(peer["subnet"], "ipCidrRange")])
        subnet_route = ipaddress.ip_network(prefix, strict=False)
        always_exchanged = tuple(ipaddress.ip_network(value) for value in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
            "198.51.100.0/24", "203.0.113.0/24", "192.88.99.0/24",
            "198.18.0.0/15", "240.0.0.0/4"))
        if not any(subnet_route.subnet_of(private) for private in always_exchanged):
            reverse_peerings = peer["network"]["data"].get("peerings")
            if not isinstance(reverse_peerings, list) or any(not isinstance(p, dict) for p in reverse_peerings):
                return model.gap("peering_inventory_malformed", "Native reverse-network peerings must be a list of peering objects",
                    [model.ref(peer["network"], "peerings")])
            reverse = [p for p in reverse_peerings
                if _gcp_peering_network_id(p.get("network"), peer["network"]) == _gcp_network_id(endpoint["network"])]
            refs.append(model.ref(peer["network"], "peerings"))
            def effective_flag(value, active_name):
                status = value.get("connectionStatus", {})
                if not isinstance(status, dict):
                    return None
                active = status.get("trafficConfiguration", {})
                if not isinstance(active, dict):
                    return None
                return active.get(active_name)
            if (len(reverse) != 1 or reverse[0].get("state") != "ACTIVE" or
                effective_flag(peering, "importSubnetRoutesWithPublicIpFromPeer") is not True or
                effective_flag(reverse[0], "exportSubnetRoutesWithPublicIpToPeer") is not True):
                return model.gap("peering_public_subnet_exchange_unknown",
                    "A privately used public IPv4 subnet route needs effective import and peer export enabled", refs)
    prefix_field = "internalIpv6Prefix" if peer["address"].version == 6 else "ipCidrRange"
    peer_prefix = peer["subnet"]["data"].get(prefix_field)
    local_prefix = endpoint["subnet"]["data"].get(prefix_field)
    if not isinstance(peer_prefix, str) or not isinstance(local_prefix, str):
        return model.gap("peering_subnet_prefix_missing", "Both selected peered subnets need native prefixes for the requested address family",
            refs + [model.ref(peer["subnet"], prefix_field), model.ref(endpoint["subnet"], prefix_field)])
    try:
        overlap = ipaddress.ip_network(peer_prefix, strict=False).overlaps(ipaddress.ip_network(local_prefix, strict=False))
    except ValueError:
        return model.gap("peering_subnet_prefix_malformed", "A selected peered subnet prefix is malformed",
            refs + [model.ref(peer["subnet"], prefix_field), model.ref(endpoint["subnet"], prefix_field)])
    if overlap:
        return model.gap("overlapping_address_domains", "Overlapping cross-project subnet domains cannot establish the selected peer resource path", refs)
    return model.step("route", "allowed", "Active native peering exchanges the selected regular private subnet route", refs, direction=direction)


def _gcp(model, source, destination, query):
    endpoints = [_gcp_endpoint(model, r, query["address_family"]) for r in (source, destination)]
    if not all(e and e["address"] for e in endpoints):
        return []
    src, dst = endpoints
    model.result["endpoints"] = _endpoint_details(src, dst)
    if src["resource"]["id"] == dst["resource"]["id"]:
        if src["interface_index"] != dst["interface_index"]:
            return [model.gap("self_traffic_semantics_unproven",
                "Traffic between two interfaces of one VM may remain inside the guest; VPC controls cannot prove its path",
                [model.ref(src["resource"], "networkInterfaces")])]
        refs = [model.ref(src["resource"], f"networkInterfaces[{src['interface_index']}].networkIP/ipv6Address")]
        return [
            model.step("policy", "allowed", "Traffic to the VM's own primary interface address stays inside the VM; VPC firewall policies do not apply",
                refs, control="gcp.firewall", direction="self"),
            model.step("route", "allowed", "Traffic to the VM's own primary interface address stays inside the VM",
                refs, direction="forward_and_return"),
        ]
    hierarchy_context = model.context("firewall_hierarchy")
    hierarchy = model.context_complete("firewall_hierarchy") and hierarchy_context.get("policies") == []
    host_scopes = {_gcp_owner_scope(model, "firewall", endpoint["network"]) for endpoint in (src, dst)}
    # The Network resource independently exposes an attached global network
    # firewall policy. A stale or contradictory empty-policy proof cannot
    # override that native attachment, even if a policy LIST missed it.
    attached_network_policies = [endpoint["network"] for endpoint in (src, dst)
        if endpoint["network"] and endpoint["network"]["data"].get("firewallPolicy") not in (None, "")]
    if attached_network_policies:
        hierarchy = False
        model.gap("gcp_network_firewall_policy_attachment_conflict",
            "A selected VPC names an attached network firewall policy despite an empty-policy assertion",
            [model.ref(network, "firewallPolicy") for network in {r["id"]: r for r in attached_network_policies}.values()])
    scoped = "unaffected_projects" in hierarchy_context
    if scoped:
        unaffected = hierarchy_context.get("unaffected_projects")
        ancestors = hierarchy_context.get("project_ancestors")
        hierarchy = (hierarchy and isinstance(unaffected, list) and isinstance(ancestors, dict)
            and None not in host_scopes and host_scopes <= set(unaffected))
        if hierarchy:
            for scope in host_scopes:
                policies = model.collections.get(("firewall_policy", scope), [])
                chain = ancestors.get(scope)
                if (len(policies) != 1 or policies[0]["status"] not in {"collected", "empty"} or
                    not policies[0].get("source_requests") or
                    not isinstance(chain, list) or any(not isinstance(parent, str) or
                        not parent.startswith(("folders/", "organizations/")) for parent in chain)):
                    hierarchy = False
                    break
                if any(item.get("_provenance", {}).get("representation") != "full" or
                    not isinstance(item.get("associations", []), list) or item.get("associations")
                    for item in policies[0]["items"]):
                    hierarchy = False
                    break
                if any(len(rows := model.collections.get(("firewall_policy_association", parent), [])) != 1 or
                    rows[0]["status"] != "empty" or rows[0]["items"] or
                    not rows[0].get("source_requests") for parent in chain):
                    hierarchy = False
                    break
        # Imported snapshots can carry the older split policy types beside a
        # native, project-scoped absence proof. They must not disappear from
        # that proof merely because the native collector uses firewall_policy.
        related_scopes = set(host_scopes)
        if isinstance(ancestors, dict):
            for scope in host_scopes:
                if isinstance(ancestors.get(scope), list):
                    related_scopes.update(ancestors[scope])
        if any(c["scope"] in related_scopes and
               c["type"] in {"hierarchical_firewall_policy", "network_firewall_policy"} and
               (c["status"] not in {"collected", "empty"} or c["items"])
               for c in model.snapshot["collections"]):
            hierarchy = False
        if not hierarchy:
            model.gap("gcp_firewall_hierarchy_inventory_conflict", "Selected host-project policy or ancestor-association evidence is incomplete or active")
    else:
        # An unscoped assertion cannot rule out policies attached to the
        # selected host project or an ancestor that was never queried.
        hierarchy = False
        policy_types = {"firewall_policy", "hierarchical_firewall_policy", "network_firewall_policy", "firewall_policy_association"}
        policy_collections = [c for c in model.snapshot["collections"] if c["type"] in policy_types and
            (c["type"] != "firewall_policy_association" or c["scope"].startswith(("folders/", "organizations/")))]
        if any(c["status"] not in {"collected", "empty"} or c["items"] for c in policy_collections):
            hierarchy = False
            model.gap("gcp_firewall_hierarchy_inventory_conflict", "Observed or incomplete firewall policies contradict an empty effective-policy context")
    regional_clear = [_gcp_regional_policies_absent(model, endpoint) for endpoint in (src, dst)]
    hierarchy = hierarchy and all(regional_clear)
    if not hierarchy:
        model.gap("gcp_firewall_hierarchy_missing", "Hierarchical/global/regional firewall policy precedence or absence is not verified")
    checks = [_gcp_firewall(model, src, dst, "EGRESS", query, hierarchy), _gcp_firewall(model, dst, src, "INGRESS", query, hierarchy)]
    checks += [_gcp_route(model, src, dst, "forward"), _gcp_route(model, dst, src, "return")]
    return checks


def _selector(selector, labels):
    if not isinstance(selector, dict):
        return None
    if set(selector) - {"matchLabels", "matchExpressions"}:
        return None
    match_labels = selector.get("matchLabels", {})
    expressions = selector.get("matchExpressions", [])
    if (not isinstance(match_labels, dict) or not isinstance(expressions, list) or
        any(not isinstance(key, str) or not key or not isinstance(value, str)
            for key, value in match_labels.items()) or
        any(not isinstance(expression, dict) or set(expression) - {"key", "operator", "values"}
            for expression in expressions)):
        return None
    if not match_labels and not expressions:
        return True
    if not isinstance(labels, dict) or any(not isinstance(key, str) or not isinstance(value, str)
        for key, value in labels.items()):
        return None
    decisions = [labels.get(key) == value for key, value in match_labels.items()]
    for expression in expressions:
        key, operation, values = expression.get("key"), expression.get("operator"), expression.get("values", [])
        if (not isinstance(key, str) or not key or not isinstance(values, list) or
            any(not isinstance(value, str) for value in values)):
            decisions.append(None)
        elif operation == "In":
            decisions.append(key in labels and labels[key] in values if values else None)
        elif operation == "NotIn":
            decisions.append(key not in labels or labels[key] not in values if values else None)
        elif operation == "Exists":
            decisions.append(key in labels if not values else None)
        elif operation == "DoesNotExist":
            decisions.append(key not in labels if not values else None)
        else:
            decisions.append(None)
    return _all(decisions)


def _k8s_endpoint(model, resource, family):
    if resource["type"] != "pod":
        model.gap("unsupported_endpoint_type", "Kubernetes selected endpoints must be direct pods; Service/LB address translations are not inferred", [model.ref(resource, "data")])
        return None
    if not model.complete("pod", resource["scope"]):
        model.gap("endpoint_association_incomplete", "Selected pod inventory is missing or partial", [model.ref(resource, "metadata.namespace/status.podIPs")])
    data = resource["data"]
    metadata, status, provenance = data.get("metadata"), data.get("status"), data.get("provenance")
    if not isinstance(metadata, dict) or not isinstance(status, dict) or not isinstance(provenance, dict):
        model.gap("pod_endpoint_facts_malformed", "Pod metadata, status, and cluster provenance must be native objects",
            [model.ref(resource, "metadata/status/provenance")])
        return None
    spec = data.get("spec")
    if (not isinstance(spec, dict) or not isinstance(spec.get("containers"), list) or not spec["containers"] or
        any(not isinstance(container, dict) or not isinstance(container.get("name"), str) or
            not container["name"] for container in spec["containers"]) or
        ("hostNetwork" in spec and not isinstance(spec["hostNetwork"], bool))):
        model.gap("pod_network_spec_unresolved", "A complete PodSpec is needed to rule out host networking and identify a pod endpoint",
            [model.ref(resource, "spec.containers/spec.hostNetwork")])
        return None
    if spec.get("hostNetwork") is True:
        model.gap("host_network_semantics_unknown", "Host-network pod policy and node-source exceptions depend on the enforcing CNI", [model.ref(resource, "spec.hostNetwork")])
        return None
    if status.get("phase") != "Running" or metadata.get("deletionTimestamp"):
        model.gap("pod_endpoint_not_active", "A pod must be observed Running and not terminating before its recorded IP can represent an active network endpoint",
            [model.ref(resource, "status.phase/metadata.deletionTimestamp")])
        return None
    pod_ips = status.get("podIPs", [])
    if not isinstance(pod_ips, list) or any(not isinstance(item, dict) or
        not isinstance(item.get("ip"), str) for item in pod_ips):
        model.gap("pod_endpoint_ips_malformed", "The native PodStatus podIPs list must contain IP objects",
            [model.ref(resource, "status.podIPs")])
        return None
    address = _address(model, [status.get("podIP")] + [item["ip"] for item in pod_ips], family, resource)
    namespace = metadata.get("namespace")
    cluster = model.snapshot.get("metadata", {}).get("cluster_id")
    observed_cluster = provenance.get("cluster_id")
    if (not isinstance(cluster, str) or not cluster or observed_cluster != cluster or
        not isinstance(namespace, str) or not namespace):
        model.gap("cluster_namespace_context_missing", "Native cluster identity and namespace must be explicit; namespace is not a subnet", [model.ref(resource, "metadata.namespace/provenance.cluster_id")])
    namespace_resources = [r for r in model.kinds["namespace"] if r["data"].get("metadata", {}).get("name") == namespace]
    namespace_resource = namespace_resources[0] if len(namespace_resources) == 1 else None
    if len(namespace_resources) > 1:
        model.gap("namespace_identity_ambiguous", "Multiple native Namespace records claim the selected pod namespace")
    if namespace_resource:
        namespace_provenance = namespace_resource["data"].get("provenance")
        if (not isinstance(namespace_provenance, dict) or
            namespace_provenance.get("cluster_id") != cluster or
            namespace_provenance.get("namespace") != "_cluster"):
            model.gap("namespace_provenance_mismatch", "The Namespace record is not proven to belong to the selected pod cluster",
                [model.ref(namespace_resource, "provenance.cluster_id/namespace")])
            namespace_resource = None
        else:
            namespace_labels = namespace_resource["data"].get("metadata", {}).get("labels")
            if (isinstance(namespace_labels, dict) and
                "kubernetes.io/metadata.name" in namespace_labels and
                namespace_labels["kubernetes.io/metadata.name"] != namespace):
                model.gap("cluster_namespace_context_missing",
                    "The Namespace's immutable name label disagrees with its native identity",
                    [model.ref(namespace_resource, "metadata.name/labels")])
                namespace_resource = None
    return {"resource": resource, "selected": resource, "address": address, "scope": resource["scope"],
        "namespace": namespace, "cluster": cluster, "namespace_resource": namespace_resource,
        "labels": data.get("metadata", {}).get("labels", {})}


def _k8s_peer(model, policy_namespace, peer, other):
    if not isinstance(peer, dict) or set(peer) - {"podSelector", "namespaceSelector", "ipBlock"}:
        return None
    if not peer:
        return True
    if "ipBlock" in peer:
        if len(peer) != 1:
            return None
        block = peer["ipBlock"]
        if not isinstance(block, dict) or set(block) - {"cidr", "except"}:
            return None
        if model.context("cni").get("ipblock_semantics") != "pod_ips_preserved":
            return None
        exceptions = block.get("except", [])
        if not isinstance(exceptions, list) or any(not isinstance(cidr, str) for cidr in exceptions):
            return None
        try:
            network = ipaddress.ip_network(block.get("cidr"), strict=False)
            if any(not ipaddress.ip_network(cidr, strict=False).subnet_of(network) for cidr in exceptions):
                return None
        except (ValueError, TypeError):
            return None
        base = _cidr(block.get("cidr"), other["address"])
        excluded = _any(_cidr(cidr, other["address"]) for cidr in exceptions)
        return _all([base, None if excluded is None else not excluded])
    namespace = other["namespace_resource"]
    labels = namespace["data"].get("metadata", {}).get("labels", {}) if namespace and model.complete("namespace", namespace["scope"]) else None
    if "namespaceSelector" in peer and isinstance(peer["namespaceSelector"], dict):
        selector = peer["namespaceSelector"]
        name_label = "kubernetes.io/metadata.name"
        named = (name_label in selector.get("matchLabels", {})
            if isinstance(selector.get("matchLabels", {}), dict) else False)
        expressions = selector.get("matchExpressions", [])
        named = named or (isinstance(expressions, list) and any(
            isinstance(expression, dict) and expression.get("key") == name_label for expression in expressions))
        if named and (not isinstance(labels, dict) or labels.get(name_label) != other["namespace"]):
            return None
    matches = [_selector(peer["namespaceSelector"], labels)] if "namespaceSelector" in peer else [other["namespace"] == policy_namespace]
    if "podSelector" in peer:
        matches.append(_selector(peer["podSelector"], other["labels"]))
    if namespace:
        model.ref(namespace, "metadata.labels")
    return _all(matches)


def _k8s_ports(model, rule, destination, query):
    ports = rule.get("ports")
    if "ports" in rule and (not isinstance(ports, list) or any(not isinstance(port, dict) for port in ports)):
        return None
    if not ports:
        return True
    matches = []
    for port in ports:
        if set(port) - {"port", "protocol", "endPort"}:
            matches.append(None)
            continue
        value = port.get("port")
        if (("protocol" in port and (not isinstance(port["protocol"], str) or
            port["protocol"] not in {"TCP", "UDP", "SCTP"})) or
            ("port" in port and value is None) or
            (isinstance(value, int) and (isinstance(value, bool) or not 1 <= value <= 65535)) or
            (isinstance(value, str) and not value) or
            ("endPort" in port and (not isinstance(value, int) or isinstance(value, bool) or
                not isinstance(port["endPort"], int) or isinstance(port["endPort"], bool) or
                not value <= port["endPort"] <= 65535))):
            matches.append(None)
            continue
        proto = _protocol(port.get("protocol", "TCP"), query["protocol"])
        if value is None:
            matches.append(proto)
        elif isinstance(value, int) and not isinstance(value, bool):
            end = port.get("endPort", value)
            # If endPort is unsupported or unverified, even the first port in
            # the range cannot prove how the CNI applies this entire rule.
            match = (None if "endPort" in port and model.context("cni").get("supports_end_port") is not True
                else _ports(f"{value}-{end}", query["destination_port"]))
            matches.append(_all([proto, match]))
        elif isinstance(value, str) and "endPort" not in port:
            spec = destination["resource"]["data"].get("spec")
            if not isinstance(spec, dict) or not isinstance(spec.get("containers"), list) or not spec["containers"]:
                matches.append(None)
                continue
            ephemeral = spec.get("ephemeralContainers", [])
            if (not isinstance(ephemeral, list) or any(not isinstance(container, dict) or
                "ports" in container for container in ephemeral)):
                matches.append(None)
                continue
            groups = [spec["containers"], spec.get("initContainers", [])]
            if (any(not isinstance(group, list) for group in groups) or
                any(not isinstance(container, dict) or not isinstance(container.get("ports", []), list)
                    for group in groups for container in group) or
                any(not isinstance(p, dict) or not isinstance(p.get("containerPort"), int) or
                    isinstance(p.get("containerPort"), bool) or not 1 <= p["containerPort"] <= 65535 or
                    ("name" in p and not isinstance(p["name"], str)) or
                    ("protocol" in p and (not isinstance(p["protocol"], str) or
                        p["protocol"] not in {"TCP", "UDP", "SCTP"}))
                    for group in groups for container in group for p in container.get("ports", []))):
                matches.append(None)
                continue
            regular_ports = {p.get("containerPort") for container in spec["containers"] for p in container.get("ports", [])
                if p.get("name") == value and str(p.get("protocol", "TCP")).lower() == query["protocol"]}
            init_ports = {p.get("containerPort") for container in spec.get("initContainers", []) for p in container.get("ports", [])
                if p.get("name") == value and str(p.get("protocol", "TCP")).lower() == query["protocol"]}
            # Ordinary init containers have finished once the pod is Running;
            # sidecar init containers can persist. The imported CNI proof does
            # not establish which init-container names it resolves.
            match = (None if init_ports and init_ports != regular_ports else
                query["destination_port"] in regular_ports if len(regular_ports) <= 1 else None)
            matches.append(_all([proto, match]))
            model.ref(destination["resource"], "spec.containers[*].ports")
        else:
            matches.append(None)
    return _any(matches)


def _k8s_policy(model, endpoint, other, destination, direction, query, enforced):
    if not model.complete("networkpolicy", endpoint["scope"]):
        return model.gap("network_policy_collection_incomplete", "Additive policy union needs complete policy inventory for the selected namespace scope")
    selectors_unknown, namespace_unknown, selected = [], [], []
    for policy in model.kinds["networkpolicy"]:
        data = policy["data"]
        namespace = data.get("metadata", {}).get("namespace")
        if isinstance(namespace, str) and namespace and namespace != endpoint["namespace"]:
            continue
        spec = data.get("spec")
        if not isinstance(spec, dict) or set(spec) - {"podSelector", "policyTypes", "ingress", "egress"}:
            selectors_unknown.append(policy)
            continue
        match = _selector(spec.get("podSelector", {}), endpoint["labels"])
        if match is False:
            continue
        provenance = data.get("provenance")
        if isinstance(namespace, str) and namespace and (not isinstance(provenance, dict) or
            provenance.get("cluster_id") != endpoint["cluster"] or
            provenance.get("namespace") != namespace):
            return model.gap("network_policy_provenance_mismatch",
                "A potentially selected NetworkPolicy lacks matching native cluster and namespace provenance",
                [model.ref(policy, "metadata.namespace/provenance.cluster_id/namespace")])
        if not isinstance(namespace, str) or not namespace:
            namespace_unknown.append(policy)
            continue
        # Kubernetes defaults Egress only when there is at least one egress
        # rule. An explicit empty egress list still defaults to Ingress only.
        types = spec.get("policyTypes")
        if "policyTypes" not in spec or types == []:
            egress = spec.get("egress", [])
            if not isinstance(egress, list):
                selectors_unknown.append(policy)
                continue
            types = ["Ingress"] + (["Egress"] if egress else [])
        if (not isinstance(types, list) or not types or
            any(not isinstance(value, str) or value not in {"Ingress", "Egress"} for value in types) or
            len(set(types)) != len(types)):
            selectors_unknown.append(policy)
            continue
        if direction not in types:
            continue
        if match is None:
            selectors_unknown.append(policy)
        elif match:
            selected.append(policy)
    key, peers_key = ("ingress", "from") if direction == "Ingress" else ("egress", "to")
    allow_refs, uncertain, selected_refs = [], bool(selectors_unknown or namespace_unknown), []
    for policy in selected:
        selected_refs.append(model.ref(policy, "spec.podSelector/policyTypes"))
        rules = policy["data"]["spec"].get(key, [])
        if not isinstance(rules, list):
            uncertain = True
            continue
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict) or set(rule) - {peers_key, "ports"}:
                uncertain = True
                continue
            peers = rule.get(peers_key)
            if peers_key in rule and (not isinstance(peers, list) or any(not isinstance(peer, dict) for peer in peers)):
                uncertain = True
                continue
            peer_match = _any(_k8s_peer(model, endpoint["namespace"], peer, other) for peer in peers) if peers else True
            port_match = _k8s_ports(model, rule, destination, query)
            match = _all([peer_match, port_match])
            if match:
                allow_refs.append(model.ref(policy, f"spec.{key}[{i}]"))
            elif match is None:
                uncertain = True
    if source_same := endpoint["resource"]["id"] == other["resource"]["id"]:
        decision, reason = "allowed", "A standard pod policy cannot block the pod's own loopback traffic"
    elif allow_refs:
        decision, reason = "allowed", "An allow in the additive union admits this flow; another standard policy cannot subtract it"
    elif uncertain:
        return model.gap("network_policy_selector_unresolved", "Policy namespace, labels, types, CNI IP-block/port behavior, or a selector could alter the additive union",
            selected_refs + [model.ref(p, "metadata.namespace/spec") for p in selectors_unknown + namespace_unknown])
    elif not selected:
        decision, reason = "allowed", "No standard NetworkPolicy isolates this pod in this direction after complete enumeration"
    else:
        decision, reason = "blocked", "The complete additive policy union isolates this direction and contains no matching allow"
    return model.step("policy", decision if enforced else "unknown", reason if enforced else "Policy intent is modeled but enforcing CNI evidence is missing",
        allow_refs or selected_refs or [model.ref(endpoint["resource"], "metadata.namespace/labels")],
        control="k8s.networkpolicy", direction=direction, candidate_decision=decision,
        pre_route=direction == "Egress",
        return_behavior="Responses to admitted TCP/UDP connections are implicitly admitted", self_traffic=source_same)


def _k8s(model, source, destination, query):
    endpoints = [_k8s_endpoint(model, r, query["address_family"]) for r in (source, destination)]
    if not all(e and e["address"] for e in endpoints):
        return []
    src, dst = endpoints
    model.result["endpoints"] = _endpoint_details(src, dst)
    selected_ids = {src["resource"]["id"], dst["resource"]["id"]}
    for pod in model.kinds["pod"]:
        if pod["id"] in selected_ids or pod["data"].get("provenance", {}).get("cluster_id") != src["cluster"]:
            continue
        metadata = pod["data"].get("metadata")
        status = pod["data"].get("status")
        if not isinstance(metadata, dict) or not isinstance(status, dict) or status.get("phase") != "Running" or metadata.get("deletionTimestamp"):
            continue
        addresses = [status.get("podIP")]
        pod_ips = status.get("podIPs", [])
        if isinstance(pod_ips, list):
            addresses += [item.get("ip") for item in pod_ips if isinstance(item, dict)]
        for value in addresses:
            if not isinstance(value, str):
                continue
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address in {src["address"], dst["address"]}:
                model.gap("pod_endpoint_address_collision",
                    "Another active pod in this cluster claims a selected pod IP; its destination identity is ambiguous",
                    [model.ref(pod, "status.podIP/status.podIPs")])
                break
    cni = model.context("cni")
    enforced = (model.context_complete("cni") and cni.get("enforces_network_policy") is True
        and cni.get("policy_sources") == "standard_networkpolicy_only")
    if not enforced:
        model.gap("cni_enforcement_unknown", "An enforcing CNI and complete standard-only policy sources must be observed before NetworkPolicy can decide")
    namespaced_custom = {"cilium_networkpolicy", "calico_networkpolicy"}
    cluster_custom = {"cilium_clusterwide_networkpolicy", "calico_global_networkpolicy",
        "admin_networkpolicy", "baseline_admin_networkpolicy", "cluster_networkpolicy"}
    custom = [c for c in model.snapshot["collections"] if c["type"] in namespaced_custom | cluster_custom]
    discoveries = [c for c in model.snapshot["collections"] if c["type"] == "api_discovery"]
    discovery_complete = (len(discoveries) == 1 and discoveries[0]["status"] == "collected"
        and len(discoveries[0]["items"]) == 1 and isinstance(discoveries[0]["items"][0].get("groups"), list)
        and discoveries[0]["items"][0].get("provenance", {}).get("cluster_id") == src["cluster"]
        and discoveries[0]["items"][0].get("provenance", {}).get("source") == "GET /apis"
        and any(isinstance(group, dict) and group.get("name") == "networking.k8s.io" and
            isinstance(group.get("versions"), list) and
            any(isinstance(version, dict) and version.get("version") == "v1" for version in group["versions"])
            for group in discoveries[0]["items"][0]["groups"]))
    if discovery_complete:
        for item in model.kinds["api_discovery"]:
            model.ref(item, "groups")
    namespaced_empty = all(
        len(matches := [c for c in custom if c["type"] == kind and c["scope"] == scope]) == 1
        and matches[0]["status"] == "empty"
        for scope in {src["scope"], dst["scope"]}
        for kind in namespaced_custom
    )
    cluster_empty = all(
        len(matches := [c for c in custom if c["type"] == kind]) == 1 and matches[0]["status"] == "empty"
        for kind in cluster_custom
    )
    if not discovery_complete or not namespaced_empty or not cluster_empty:
        enforced = False
        model.gap("cni_custom_policy_context_unknown", "API discovery and nonstandard CNI policy inventories must be explicitly collected and empty before the standard additive union can decide")
    if src["cluster"] != dst["cluster"]:
        return [model.gap("cluster_domain_mismatch", "Native pod IPs from distinct cluster address domains cannot be joined by namespace or CIDR")]
    routing = model.context_complete("routing") and model.context("routing").get("pod_network_connected") is True
    if not routing:
        model.gap("pod_routing_context_missing", "Direct pod network routing is not proven by namespace/policy inventory")
    checks = [_k8s_policy(model, src, dst, dst, "Egress", query, enforced),
              _k8s_policy(model, dst, src, dst, "Ingress", query, enforced)]
    checks.append(model.step("route", "allowed" if routing else "unknown", "Observed enforcing pod-network routing context" if routing else "No route proof for direct pod-network traffic",
        [model.ref(src["resource"], "status.podIPs"), model.ref(dst["resource"], "status.podIPs")], direction="forward_and_return"))
    return checks


def _flow_query(source_resource_id, destination_resource_id, protocol, destination_port, source_port, address_family):
    if not isinstance(source_resource_id, str) or not isinstance(destination_resource_id, str):
        raise ValueError("source and destination resource IDs must be strings")
    protocol = protocol.lower() if isinstance(protocol, str) else ""
    if protocol not in {"tcp", "udp"}:
        raise ValueError("only tcp and udp new-flow modeling is supported")
    for name, value in (("destination_port", destination_port), ("source_port", source_port)):
        if name == "source_port" and value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError(f"{name} must be an integer from 1 to 65535")
    if address_family not in {"ipv4", "ipv6"}:
        raise ValueError("address_family must be ipv4 or ipv6")
    return {"source_resource_id": source_resource_id, "destination_resource_id": destination_resource_id,
            "protocol": protocol, "destination_port": destination_port, "source_port": source_port,
            "address_family": address_family}


def _observed_private_ip_collisions(model):
    """Reject a selected endpoint IP also claimed by another collected interface."""
    def same_ip(value, selected):
        if not isinstance(value, str):
            return False
        try:
            return ipaddress.ip_address(value) == selected
        except ValueError:
            return False

    for endpoint in model.result["endpoints"].values():
        interface = model.by_id.get(endpoint.get("interface_resource_id"))
        if interface is None:
            continue
        try:
            selected = ipaddress.ip_address(endpoint["address"])
        except (KeyError, ValueError):
            continue
        key = (interface["id"], str(selected), endpoint.get("interface_index") if model.provider == "gcp" else None)
        conflicts = model.private_ip_collision_cache.get(key)
        if conflicts is None:
            conflicts = []
        if key not in model.private_ip_collision_cache and model.provider == "aws" and interface["type"] == "network_interface":
            vpc_id = interface["data"].get("VpcId")
            for other in model.kinds["network_interface"]:
                if (other["id"] == interface["id"] or other["data"].get("VpcId") != vpc_id or
                    other["scope"].rsplit("/", 1)[-1] != interface["scope"].rsplit("/", 1)[-1]):
                    continue
                facts = other["data"]
                addresses = [facts.get("PrivateIpAddress")]
                addresses += [row.get("PrivateIpAddress") for row in facts.get("PrivateIpAddresses", []) if isinstance(row, dict)]
                addresses += [row.get("Ipv6Address") for row in facts.get("Ipv6Addresses", []) if isinstance(row, dict)]
                if any(same_ip(value, selected) for value in addresses):
                    conflicts.append((other, "PrivateIpAddress/PrivateIpAddresses/Ipv6Addresses"))
        elif key not in model.private_ip_collision_cache and model.provider == "azure" and interface["type"] == "nic":
            configs = interface["data"].get("properties", {}).get("ipConfigurations", [])
            selected_subnets = [config.get("properties", {}).get("subnet", {}).get("id") for config in configs
                if isinstance(config, dict) and same_ip(config.get("properties", {}).get("privateIPAddress"), selected)]
            vnet_id = selected_subnets[0].lower().rsplit("/subnets/", 1)[0] if len(selected_subnets) == 1 and isinstance(selected_subnets[0], str) else None
            if vnet_id:
                for other in model.kinds["nic"]:
                    if other["id"] == interface["id"]:
                        continue
                    for config in other["data"].get("properties", {}).get("ipConfigurations", []):
                        if not isinstance(config, dict):
                            continue
                        props = config.get("properties", {})
                        subnet_id = props.get("subnet", {}).get("id")
                        if (isinstance(subnet_id, str) and subnet_id.lower().rsplit("/subnets/", 1)[0] == vnet_id and
                            same_ip(props.get("privateIPAddress"), selected)):
                            conflicts.append((other, "properties.ipConfigurations"))
                            break
        elif key not in model.private_ip_collision_cache and model.provider == "gcp" and interface["type"] == "instance":
            selected_interfaces = interface["data"].get("networkInterfaces", [])
            selected_index = endpoint.get("interface_index", 0)
            selected_nic = selected_interfaces[selected_index] if isinstance(selected_interfaces, list) and isinstance(selected_index, int) and 0 <= selected_index < len(selected_interfaces) else None
            network = _gcp_scoped_ref(selected_nic.get("network"), "network", interface["scope"]) if isinstance(selected_nic, dict) else None
            if network:
                for other in model.kinds["instance"]:
                    for i, nic in enumerate(other["data"].get("networkInterfaces", [])):
                        if other["id"] == interface["id"] and i == selected_index:
                            continue
                        if (isinstance(nic, dict) and _gcp_scoped_ref(nic.get("network"), "network", other["scope"]) == network and
                            any(same_ip(nic.get(field), selected) for field in ("networkIP", "ipv6Address"))):
                            conflicts.append((other, f"networkInterfaces[{i}]"))
                            break
        model.private_ip_collision_cache[key] = conflicts
        if conflicts:
            model.gap("endpoint_address_collision", "Another collected interface in this network claims the selected private IP",
                [model.ref(interface, "addresses"), *(model.ref(resource, path) for resource, path in conflicts)])


def _evaluate_model(model):
    query = model.result["query"]
    if model.identity_collisions:
        model.gap("network_inventory_identity_collision",
            "Native network records share an identity, so deduplicating them could hide conflicting route or policy facts")
    source_resource_id, destination_resource_id = query["source_resource_id"], query["destination_resource_id"]
    source, destination = model.by_id.get(source_resource_id), model.by_id.get(destination_resource_id)
    if source is None or destination is None:
        model.gap("endpoint_inventory_missing", "Both selected globally scoped IDs must exist in this immutable network inventory")
        return model.result
    try:
        evaluators = {"aws": _aws, "azure": _azure, "gcp": _gcp, "k8s": _k8s}
        evaluator = evaluators.get(model.provider)
        checks = evaluator(model, source, destination, query) if evaluator else [model.gap("provider_model_pending", "Provider selected-flow model is not yet available")]
        endpoints = model.result["endpoints"]
        _observed_private_ip_collisions(model)
        if source_resource_id != destination_resource_id and endpoints.get("source", {}).get("address") == endpoints.get("destination", {}).get("address") and endpoints.get("source"):
            model.gap("endpoint_address_collision", "Distinct selected resources share an address; overlapping scoped identities must not be merged")
        critical = {"overlapping_address_domains", "cluster_namespace_context_missing", "cluster_domain_mismatch",
            "network_inventory_identity_collision"}
        domain_valid = not any(g["code"] in critical or g["code"].startswith(("endpoint_", "pod_endpoint_", "network_domain_"))
            for g in model.result["unresolved_dependencies"])
        forward = [r for r in model.result["routes"] if r.get("direction") in {"forward", "forward_and_return"}]
        direct = bool(forward) and all(r["decision"] == "allowed" for r in forward)
        return_routes = [r for r in model.result["routes"] if r.get("direction") in {"return", "forward_and_return"}]
        return_proven = bool(return_routes) and all(r["decision"] == "allowed" for r in return_routes)
        decisive = domain_valid and (any(r["decision"] == "blocked" and r.get("direction") == "forward" for r in model.result["routes"]) or
            any(p["decision"] == "blocked" and (p.get("pre_route") or p.get("address_translation_invariant") or
                direct and (not p.get("requires_return_route") or return_proven)) for p in model.result["policy_decisions"]) or
            direct and any(r["decision"] == "blocked" for r in model.result["routes"]))
        if "blocked" in checks and not decisive:
            model.gap("blocked_candidate_not_proven", "A downstream denial cannot be decisive before its scoped path/translation assumptions are proven")
        model.result["decision"] = "blocked" if decisive else "unknown" if not checks or any(c != "allowed" for c in checks) or model.result["unresolved_dependencies"] else "allowed"
    except (TypeError, ValueError, KeyError, AttributeError, IndexError):
        model.gap("malformed_native_facts", "Malformed native relationships or rules cannot establish a selected configuration path")
        model.result["decision"] = "unknown"
    return model.result


def evaluate_reachability(snapshot, source_resource_id, destination_resource_id, protocol,
                          destination_port, source_port=None, address_family="ipv4"):
    """Evaluate one new selected private TCP/UDP flow, offline and bounded by facts."""
    query = _flow_query(source_resource_id, destination_resource_id, protocol, destination_port, source_port, address_family)
    snapshot = validate(snapshot, read_only=True)
    return _evaluate_model(_Model(snapshot, query))


def evaluate_reachability_batch(snapshot, source_resource_id, destination_resource_ids, protocol,
                                destination_port, source_port=None, address_family="ipv4"):
    """Evaluate up to 24 independent flows with one validated snapshot index."""
    if (not isinstance(destination_resource_ids, list) or not 1 <= len(destination_resource_ids) <= 24 or
        any(not isinstance(value, str) or not value for value in destination_resource_ids) or
        len(set(destination_resource_ids)) != len(destination_resource_ids)):
        raise ValueError("destination_resource_ids must contain 1 to 24 unique resource IDs")
    queries = [_flow_query(source_resource_id, destination, protocol, destination_port, source_port, address_family)
        for destination in destination_resource_ids]
    snapshot = validate(snapshot, read_only=True)
    results, index = [], None
    for query in queries:
        model = _Model(snapshot, query, index)
        index = model.index
        results.append(_evaluate_model(model))
    return results


def evaluate_reachability_matrix(snapshot, endpoint_resource_ids, protocol,
                                 destination_port, source_port=None, address_family="ipv4"):
    """Assess every ordered pair in a bounded endpoint set using one snapshot index."""
    if (not isinstance(endpoint_resource_ids, list) or not 2 <= len(endpoint_resource_ids) <= 12 or
        any(not isinstance(value, str) or not value for value in endpoint_resource_ids) or
        len(set(endpoint_resource_ids)) != len(endpoint_resource_ids)):
        raise ValueError("endpoint_resource_ids must contain 2 to 12 unique resource IDs")
    queries = [_flow_query(source, destination, protocol, destination_port, source_port, address_family)
        for source in endpoint_resource_ids for destination in endpoint_resource_ids if source != destination]
    snapshot = validate(snapshot, read_only=True)
    results, index = [], None
    for query in queries:
        model = _Model(snapshot, query, index)
        index = model.index
        results.append(_evaluate_model(model))
    return results


def evaluate_reachability_grid(snapshot, first_endpoint_resource_ids, second_endpoint_resource_ids,
                               protocol, destination_port, source_port=None, address_family="ipv4"):
    """Assess both directions across two bounded endpoint windows."""
    for name, ids in (("first", first_endpoint_resource_ids), ("second", second_endpoint_resource_ids)):
        if (not isinstance(ids, list) or not 1 <= len(ids) <= 12 or
            any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != len(ids)):
            raise ValueError(f"{name} endpoint IDs must contain 1 to 12 unique resource IDs")
    pairs = dict.fromkeys(
        [(source, destination) for source in first_endpoint_resource_ids for destination in second_endpoint_resource_ids if source != destination] +
        [(source, destination) for source in second_endpoint_resource_ids for destination in first_endpoint_resource_ids if source != destination]
    )
    if not pairs:
        raise ValueError("At least two distinct endpoint IDs are required across the windows")
    queries = [_flow_query(source, destination, protocol, destination_port, source_port, address_family)
        for source, destination in pairs]
    snapshot = validate(snapshot, read_only=True)
    results, index = [], None
    for query in queries:
        model = _Model(snapshot, query, index)
        index = model.index
        results.append(_evaluate_model(model))
    return results
