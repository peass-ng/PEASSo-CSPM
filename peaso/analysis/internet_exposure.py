"""Offline internet-to-asset exposure (0.0.0.0/0 -> asset) from collected native facts.

For every asset with a public address or endpoint the declared path layers are
evaluated in provider order (AWS: IGW route, NACL, security group, listener;
GCP: external IP, VPC firewall/firewall policies, forwarding rule/Cloud Armor;
Azure: public IP, subnet+NIC NSGs, LB/AppGW rules; K8s: Service/Ingress source
ranges). The result is one ``analysis.internet_exposure`` finding per asset:

* FAIL    every collected layer admits internet traffic on at least one port
          (layers that could not be resolved are listed in ``unresolved``);
* PASS    every relevant layer is collected and blocks internet traffic;
* UNKNOWN a required layer is missing, denied or uncollected.

This is a declared-configuration model; it sends no traffic and never calls a
provider. Port sets are evaluated as exact interval arithmetic per protocol.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
import json
import re
from urllib.parse import urlsplit
from peaso.snapshot import freeze

from .common import RANK, _CONTEXT, as_list, finding, native_id, node, node_id, relationship, source, stable_id

CHECK = "analysis.internet_exposure"
TITLE = "Asset reachable from the internet"
PROTOCOLS = ("tcp", "udp", "icmp")
FULL = {"tcp": ((0, 65535),), "udp": ((0, 65535),), "icmp": ((0, 0),)}
EMPTY = {}
ADMIN_PORTS = {22, 23, 3389, 5985, 5986, 2375, 2376, 6443, 10250, 2379, 5900}
DATA_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 9300, 11211, 27017, 5984, 8086, 9042, 7000, 50070, 5601, 9092, 2181, 8020, 8888}
AVAILABLE = ("collected", "empty", "partial")
# Facts the collectors would need for a complete model (routed to collector owners).
STATIC_GAPS = {
    "aws": [],
    "gcp": [
        {"fact": "Cloud Armor request-dependent match attributes and external threat intelligence", "for": "backend_service.securityPolicy"},
        {"fact": "compute instanceGroups.listInstances / NEG endpoints", "for": "passthrough forwarding_rule backends"},
    ],
    "azure": [
        {"fact": "Azure Firewall DNAT translated backend route and effective NSG", "for": "Azure Firewall DNAT"},
        {"fact": "Microsoft.Network/applicationSecurityGroups membership", "for": "NSG ASG rules"},
        {"fact": "Microsoft.Web/sites/config/authsettingsV2", "for": "App Service authentication"},
    ],
    "k8s": [{"fact": "cloud LB/node security groups or firewall for node addresses", "for": "NodePort services and host-bound Pods"}],
}


# ------------------------------------------------------------ port arithmetic

def _merge(intervals):
    output = []
    for low, high in sorted(intervals):
        if output and low <= output[-1][1] + 1:
            output[-1] = (output[-1][0], max(output[-1][1], high))
        else:
            output.append((low, high))
    return tuple(output)


def pset(protocol, low=0, high=65535):
    protocol = _proto(protocol)
    if protocol is None:
        return None
    if protocol == "all":
        return dict(FULL)
    if protocol == "icmp":
        return {"icmp": ((0, 0),)}
    low, high = int(low), int(high)
    if low < 0 or high < low:
        return {}
    return {protocol: ((max(low, 0), min(high, 65535)),)}


def union(a, b):
    return {p: _merge(a.get(p, ()) + b.get(p, ())) for p in PROTOCOLS if a.get(p) or b.get(p)}


def intersect(a, b):
    output = {}
    for p in PROTOCOLS:
        merged = [(max(l1, l2), min(h1, h2)) for l1, h1 in a.get(p, ()) for l2, h2 in b.get(p, ()) if max(l1, l2) <= min(h1, h2)]
        if merged:
            output[p] = _merge(merged)
    return output


def subtract(a, b):
    output = {}
    for p in PROTOCOLS:
        current = list(a.get(p, ()))
        for low, high in b.get(p, ()):
            following = []
            for l1, h1 in current:
                if high < l1 or low > h1:
                    following.append((l1, h1))
                    continue
                if l1 < low:
                    following.append((l1, low - 1))
                if h1 > high:
                    following.append((high + 1, h1))
            current = following
        if current:
            output[p] = _merge(current)
    return output


def empty(a):
    return not any(a.get(p) for p in (*PROTOCOLS, "esp"))


def describe(a):
    output = []
    for p in PROTOCOLS:
        for low, high in a.get(p, ()):
            if p == "icmp":
                output.append("icmp")
            elif (low, high) == (0, 65535):
                output.append(f"{p}/all")
            else:
                output.append(f"{p}/{low}" if low == high else f"{p}/{low}-{high}")
    if a.get("esp"):
        output.append("esp")
    return output


def ports_of(a):
    return {(p, port) for p in ("tcp", "udp") for low, high in a.get(p, ()) for port in (range(low, high + 1) if high - low < 4096 else ())}


def _proto(value):
    text = str(value).strip().lower()
    return {"-1": "all", "all": "all", "*": "all", "any": "all", "6": "tcp", "tcp": "tcp", "17": "udp", "udp": "udp",
            "1": "icmp", "icmp": "icmp", "58": "icmp", "icmpv6": "icmp", "icmp6": "icmp", "ipv6-icmp": "icmp",
            "http": "tcp", "https": "tcp", "tls": "tcp", "ssl": "tcp", "tcp_udp": "all", "sctp": None, "esp": None,
            "ah": None, "gre": None}.get(text)


def _port_spec(protocol, spec):
    """'22', '80-443', '*' (or None) -> port set."""
    if spec in (None, "", "*", "all", "0-65535"):
        return pset(protocol)
    text = str(spec).strip()
    if "-" in text:
        low, high = text.split("-", 1)
        return pset(protocol, int(low), int(high))
    return pset(protocol, int(text), int(text))


def _cidr(value):
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def _internet(value):
    """True when the declared source covers the whole IPv4 or IPv6 internet."""
    if value in ("*", "Internet", "internet", "Any", "any", "0.0.0.0/0", "::/0", "0.0.0.0", "<nw>/0"):
        return True
    if type(value) is str:
        return _internet_text(value)
    network = _cidr(value)
    return network is not None and network.prefixlen == 0


@lru_cache(maxsize=65536)
def _internet_text(value):
    # The same few source ranges repeat across every rule and interface.
    network = _cidr(value)
    return network is not None and network.prefixlen == 0


def _public_ip(value):
    try:
        address = ipaddress.ip_address(str(value).split("/", 1)[0])
    except ValueError:
        return False
    return address.is_global


def _public_source(value):
    """A source range containing a globally routable internet address."""
    if _internet(value):
        return True
    network = _cidr(value)
    return network is not None and network.network_address.is_global


# ---------------------------------------------------------------- inventory

class Inventory:
    """Snapshot-wide lookup across scopes (native ids are globally unique per provider)."""

    def __init__(self, snapshot, resources):
        self.snapshot = snapshot
        self.provider = snapshot["provider"]
        self.by_type, self.by_id, self.status = {}, {}, {}
        self.network_cache = {}
        # Identifier keys are indexed per kind on first lookup, in the same
        # inventory order, so unqueried kinds (metrics, activity) cost nothing.
        self._indexed = set()
        for resource in resources:
            self.by_type.setdefault(resource["type"], []).append(resource)
        for collection in snapshot.get("collections", []):
            self.status.setdefault(collection["type"], {})[collection["scope"]] = collection.get("status", "unknown")

    def _keys(self, resource):
        data = resource["data"]
        keys = {str(native_id(resource))}
        for field in ("id", "selfLink", "name", "GroupId", "SubnetId", "VpcId", "InternetGatewayId", "PrefixListId", "NetworkAclId", "RouteTableId", "InstanceId",
                      "NetworkInterfaceId", "LoadBalancerArn", "LoadBalancerName"):
            value = data.get(field) if isinstance(data, dict) else None
            if isinstance(value, str):
                keys.add(value)
                keys.add(value.lower())
        meta = data.get("metadata") if isinstance(data, dict) else None
        if isinstance(meta, dict) and meta.get("name"):
            keys.add(f"{meta.get('namespace', '')}/{meta['name']}")
        return keys

    def items(self, kind):
        return self.by_type.get(kind, [])

    def get(self, kind, key):
        if key is None:
            return None
        if kind not in self._indexed:
            self._indexed.add(kind)
            for resource in self.by_type.get(kind, ()):
                for native in self._keys(resource):
                    self.by_id.setdefault((kind, native), resource)
        return self.by_id.get((kind, str(key))) or self.by_id.get((kind, str(key).lower()))

    def state(self, kind, scope=None):
        """collected | empty | partial | missing (not collected/denied/unknown)."""
        statuses = self.status.get(kind, {})
        if scope is not None and scope in statuses:
            value = statuses[scope]
        elif statuses:
            values = set(statuses.values())
            value = "collected" if values <= {"collected", "empty"} and "collected" in values else \
                "empty" if values == {"empty"} else "partial" if values & {"collected", "partial"} else next(iter(values))
        else:
            value = "not_collected"
        return value if value in AVAILABLE else "missing:" + value

    def aws_associations(self, kind):
        """First native association/default in inventory order, as in the path readers."""
        key = ("aws_associations", kind)
        if key not in self.network_cache:
            subnets, defaults = {}, {}
            for resource in self.items(kind):
                data = resource["data"]
                associations = [a for a in as_list(data.get("Associations")) if isinstance(a, dict)]
                for association in associations:
                    subnet = association.get("SubnetId")
                    if isinstance(subnet, str):
                        subnets.setdefault(subnet, resource)
                default = data.get("IsDefault") if kind == "network_acl" else any(a.get("Main") for a in associations)
                if default and isinstance(data.get("VpcId"), str):
                    defaults.setdefault(data["VpcId"], resource)
            self.network_cache[key] = subnets, defaults
        return self.network_cache[key]


class Assessment:
    def __init__(self, resource, kind):
        self.resource, self.kind, self.origin = resource, kind, resource
        self.ports = None
        self.path, self.unresolved, self.addresses, self.notes = [], [], [], []
        self.blocked_by = None
        self.authenticated = False
        self.data_exposure = False
        self.external_ids = []
        self.endpoint = None
        self.explicit = None
        self.dormant = False

    def step(self, layer, decision, **evidence):
        self.path.append({"layer": layer, "decision": decision, **evidence})
        if decision == "block" and self.blocked_by is None:
            self.blocked_by = layer

    def gap(self, layer, reason, fact=None):
        self.unresolved.append({"layer": layer, "reason": reason, **({"collector_fact": fact} if fact else {})})

    def verdict(self):
        """FAIL: the primary filtering layers are known and admit traffic (secondary gaps listed);
        PASS: a fully collected layer blocks; UNKNOWN: a primary layer is unresolved."""
        if self.explicit:
            return self.explicit
        hard = [g for g in self.unresolved if g.get("decisive", True) and g["layer"] in self.decisive_layers()]
        if self.data_exposure or (self.ports is not None and not empty(self.ports)):
            return "UNKNOWN" if hard else "FAIL"
        if self.blocked_by is not None:
            # A blocking layer that is itself collected is decisive even when others are unknown.
            return "PASS"
        return "UNKNOWN" if hard or self.ports is None else "PASS"

    @staticmethod
    def decisive_layers():
        # Route/NACL/public-IP gaps are reported but do not downgrade an otherwise open path.
        return {"security_group", "nsg", "firewall", "listener", "policy", "inventory", "invoker",
                "cloud_armor", "backend", "access_restrictions", "authorization", "attributes"}

    def severity(self):
        if self.verdict() != "FAIL":
            return "info"
        if self.data_exposure:
            return "critical"
        full = any((low, high) == (0, 65535) for p in ("tcp", "udp") for low, high in (self.ports or {}).get(p, ()))
        contains = lambda ports: any(low <= port <= high for p in ("tcp", "udp")
                                    for low, high in (self.ports or {}).get(p, ()) for port in ports)
        if full or contains(DATA_PORTS):
            return "critical"
        if contains(ADMIN_PORTS) or self.kind in ("control_plane", "database"):
            return "high"
        # A web listener is an exposure to review, not by itself a critical flaw.
        web_only = bool(self.ports) and all(p == "tcp" and all(low == high and low in (80, 443)
                                        for low, high in intervals) for p, intervals in self.ports.items())
        return "medium" if web_only or self.authenticated else "high"

    def adjusted_severity(self):
        """Stopped/deallocated compute keeps its exposed configuration but is not reachable right now."""
        severity = self.severity()
        if self.dormant and severity in ("critical", "high"):
            return {"critical": "high", "high": "medium"}[severity]
        return severity


def _status(snapshot, inventory, resource, path):
    return source(snapshot, resource, path)


# ---------------------------------------------------------------------- AWS

def _aws_sg_ports(inventory, group_ids, assessment, where, family=4):
    """Union of 0.0.0.0/0 and ::/0 ingress over the attached security groups."""
    if not group_ids:
        assessment.step("security_group", "block", reason="no security groups attached", at=where)
        return {}
    allowed, seen = {}, []
    for group_id in group_ids:
        group = inventory.get("security_group", group_id)
        if group is None:
            assessment.gap("security_group", f"{group_id} not in inventory ({inventory.state('security_group')})", "ec2 describe_security_groups")
            continue
        cache_key = ("aws_sg_ports", group["id"], family)
        if cache_key not in inventory.network_cache:
            inventory.network_cache[cache_key] = _aws_group_rules(group, family)
        ports, direct_rules, prefix_lists = inventory.network_cache[cache_key]
        rules = list(direct_rules)
        allowed = union(allowed, ports)
        for prefix_id, prefix_ports in prefix_lists:
            prefix = inventory.get("managed_prefix_list", prefix_id)
            entries = prefix["data"].get("Entries") if prefix else None
            if not isinstance(entries, dict) or entries.get("collection_status") not in ("collected", "empty") or not isinstance(entries.get("items"), list):
                assessment.gap("security_group", f"prefix list {prefix_id} entries not completely collected",
                               "ec2:GetManagedPrefixListEntries")
                continue
            cidrs = [e.get("Cidr") for e in entries["items"] if isinstance(e, dict) and
                     _internet(e.get("Cidr")) and (":" in e.get("Cidr", "")) == (family == 6)]
            if cidrs:
                allowed = union(allowed, prefix_ports)
                rules.append({"ports": describe(prefix_ports), "cidrs": cidrs, "prefix_list_id": prefix_id})
        seen.append({"group_id": group_id, "internet_rules": rules})
    assessment.step("security_group", "allow" if not empty(allowed) else "block" if not any(g["layer"] == "security_group" for g in assessment.unresolved) else "unknown",
                    groups=seen, allowed=describe(allowed), address_family=family, at=where)
    return allowed


def _aws_group_rules(group, family=4):
    allowed, rules, prefix_lists = {}, [], []
    for permission in as_list(group["data"].get("IpPermissions")):
        if not isinstance(permission, dict):
            continue
        protocol = _proto(permission.get("IpProtocol"))
        ports = pset(permission.get("IpProtocol"), permission.get("FromPort", 0) if protocol in ("tcp", "udp") else 0,
                     permission.get("ToPort", 65535) if protocol in ("tcp", "udp") else 65535) if protocol else None
        if protocol in ("tcp", "udp") and permission.get("FromPort") in (None, -1):
            ports = pset(protocol)
        if ports is None:
            continue
        cidrs = [r.get("CidrIp") for r in as_list(permission.get("IpRanges")) if isinstance(r, dict)] + \
                [r.get("CidrIpv6") for r in as_list(permission.get("Ipv6Ranges")) if isinstance(r, dict)]
        internet_cidrs = [c for c in cidrs if _internet(c) and (":" in c) == (family == 6)]
        if internet_cidrs:
            allowed = union(allowed, ports)
            rules.append({"ports": describe(ports), "cidrs": internet_cidrs})
        if as_list(permission.get("PrefixListIds")):
            prefix_lists.extend((p.get("PrefixListId"), ports) for p in permission["PrefixListIds"]
                                if isinstance(p, dict) and isinstance(p.get("PrefixListId"), str))
    return allowed, freeze(rules), prefix_lists


def _aws_nacl(inventory, subnet_id, ports, assessment, where, family=4):
    if not subnet_id:
        assessment.gap("network_acl", "subnet unknown")
        return ports
    associations, defaults = inventory.aws_associations("network_acl")
    if isinstance(subnet_id, str):
        acl = associations.get(subnet_id)
    else:
        acl = next((a for a in inventory.items("network_acl") if any(
            isinstance(x, dict) and x.get("SubnetId") == subnet_id for x in as_list(a["data"].get("Associations")))), None)
    if acl is None:
        subnet = inventory.get("subnet", subnet_id)
        vpc = subnet["data"].get("VpcId") if subnet else None
        if isinstance(vpc, str):
            acl = defaults.get(vpc)
        elif vpc:
            acl = next((a for a in inventory.items("network_acl")
                        if a["data"].get("IsDefault") and a["data"].get("VpcId") == vpc), None)
    if acl is None:
        assessment.gap("network_acl", f"no NACL association for {subnet_id} ({inventory.state('network_acl')})", "ec2 describe_network_acls")
        return ports

    def evaluate(egress):
        allowed, decided = {}, {}
        entries = sorted((e for e in as_list(acl["data"].get("Entries")) if isinstance(e, dict) and bool(e.get("Egress")) is egress),
                         key=lambda e: int(e.get("RuleNumber", 32767)))
        for entry in entries:
            cidr = entry.get("Ipv6CidrBlock") if family == 6 else entry.get("CidrBlock")
            if not _internet(cidr):
                continue
            protocol = _proto(entry.get("Protocol"))
            if protocol is None:
                continue
            port_range = entry.get("PortRange") if isinstance(entry.get("PortRange"), dict) else {}
            rule = pset(protocol, port_range.get("From", 0), port_range.get("To", 65535)) if protocol in ("tcp", "udp") and port_range else pset(protocol)
            fresh = subtract(rule, decided)
            if entry.get("RuleAction") == "allow":
                allowed = union(allowed, fresh)
            decided = union(decided, rule)
        return allowed
    cache_key = ("aws_acl_ports", acl["id"], family)
    if cache_key not in inventory.network_cache:
        inventory.network_cache[cache_key] = evaluate(False), evaluate(True)
    inbound, outbound = inventory.network_cache[cache_key]
    result = intersect(ports, inbound)
    if not empty(result) and empty(intersect(outbound, pset("tcp", 1024, 65535))) and result.get("tcp"):
        assessment.notes.append(f"NACL {native_id(acl)} egress to 0.0.0.0/0 does not allow TCP ephemeral ports; stateless return traffic may be dropped")
    assessment.step("network_acl", "allow" if not empty(result) else "block", acl=native_id(acl), subnet=subnet_id,
                    inbound_allowed=describe(inbound), address_family=family, at=where)
    return result


def _aws_route(inventory, subnet_id, vpc_id, assessment, where, ipv6=False):
    if not subnet_id:
        assessment.gap("route", "subnet unknown")
        return None
    tables = inventory.items("route_table")
    associations, defaults = inventory.aws_associations("route_table")
    if isinstance(subnet_id, str):
        table = associations.get(subnet_id)
    else:
        table = next((t for t in tables if any(isinstance(a, dict) and a.get("SubnetId") == subnet_id
                     for a in as_list(t["data"].get("Associations")))), None)
    if table is None and vpc_id:
        if isinstance(vpc_id, str):
            table = defaults.get(vpc_id)
        else:
            table = next((t for t in tables if t["data"].get("VpcId") == vpc_id and any(
                isinstance(a, dict) and a.get("Main") for a in as_list(t["data"].get("Associations")))), None)
    if table is None:
        assessment.gap("route", f"no route table for {subnet_id} ({inventory.state('route_table')})", "ec2 describe_route_tables")
        return None
    cache_key = ("aws_internet_routes", table["id"])
    if cache_key not in inventory.network_cache:
        inventory.network_cache[cache_key] = [r for r in as_list(table["data"].get("Routes")) if isinstance(r, dict) and str(r.get("GatewayId", "")).startswith("igw-")
            and r.get("State", "active") == "active" and (r.get("DestinationCidrBlock") == "0.0.0.0/0" or r.get("DestinationIpv6CidrBlock") == "::/0")]
    routes = [r for r in inventory.network_cache[cache_key] if
              (r.get("DestinationIpv6CidrBlock") == "::/0") == bool(ipv6)]
    if routes:
        gateway_id = routes[0]["GatewayId"]
        gateway = inventory.get("internet_gateway", gateway_id)
        if gateway is not None:
            attachments = as_list(gateway["data"].get("Attachments"))
            if not any(isinstance(x, dict) and x.get("VpcId") == vpc_id and x.get("State") in (None, "available") for x in attachments):
                assessment.step("internet_gateway", "block", reason="route target is not attached to the VPC", at=where)
                return False
        else:
            assessment.gap("route", "internet gateway attachment not collected", "ec2:DescribeInternetGateways")
        assessment.step("route", "allow", route_table=native_id(table), internet_gateway=routes[0]["GatewayId"], subnet=subnet_id, address_family=6 if ipv6 else 4, at=where)
        return True
    assessment.step("route", "block", route_table=native_id(table), subnet=subnet_id, address_family=6 if ipv6 else 4, reason="no active default route to an internet gateway", at=where)
    return False


def _aws_vpc_bpa(inventory, subnet_id, vpc_id, assessment, where):
    """Return False only for a proven effective regional VPC BPA ingress block."""
    scope = assessment.resource["scope"]
    options = [r for r in inventory.items("vpc_block_public_access_options") if r["scope"] == scope]
    if len(options) != 1:
        assessment.gap("route", "VPC Block Public Access options not collected", "ec2:DescribeVpcBlockPublicAccessOptions")
        return None
    data = options[0]["data"].get("VpcBlockPublicAccessOptions")
    if not isinstance(data, dict) or data.get("State") not in ("default-state", "update-complete"):
        assessment.gap("route", "VPC Block Public Access state unresolved", "ec2:DescribeVpcBlockPublicAccessOptions")
        return None
    mode = data.get("InternetGatewayBlockMode")
    if mode == "off":
        return True
    if mode not in ("block-ingress", "block-bidirectional"):
        assessment.gap("route", "VPC Block Public Access mode unknown", "ec2:DescribeVpcBlockPublicAccessOptions")
        return None
    if inventory.state("vpc_block_public_access_exclusion", scope) not in ("collected", "empty"):
        assessment.gap("route", "VPC Block Public Access exclusions not completely collected", "ec2:DescribeVpcBlockPublicAccessExclusions")
        return None
    exclusions = [r["data"] for r in inventory.items("vpc_block_public_access_exclusion") if r["scope"] == scope
                  and (r["data"].get("VpcId") == vpc_id or r["data"].get("SubnetId") == subnet_id)
                  and r["data"].get("State") in ("create-complete", "update-complete")]
    if any(x.get("InternetGatewayExclusionMode") == "allow-bidirectional" for x in exclusions):
        assessment.step("vpc_public_access_block", "allow", mode=mode, exclusion="allow-bidirectional", at=where)
        return True
    assessment.step("vpc_public_access_block", "block", mode=mode, at=where)
    return False


def _aws_vpc_path(inventory, assessment, subnet_ids, group_ids, ports, where, route=True, vpc_id=None, family=4):
    """route -> NACL -> SG for a set of candidate subnets; returns the reachable port set."""
    if group_ids is not None:
        ports = intersect(ports, _aws_sg_ports(inventory, group_ids, assessment, where, family))
    if empty(ports):
        return ports
    if not subnet_ids:
        assessment.gap("network_acl", "subnets not collected for this asset")
        return ports
    reachable = {}
    for subnet_id in subnet_ids:
        subnet = inventory.get("subnet", subnet_id)
        vpc = vpc_id or (subnet["data"].get("VpcId") if subnet else None)
        if route and _aws_vpc_bpa(inventory, subnet_id, vpc, assessment, where) is False:
            continue
        if route and _aws_route(inventory, subnet_id, vpc, assessment, where, ipv6=family == 6) is False:
            continue
        reachable = union(reachable, _aws_nacl(inventory, subnet_id, ports, assessment, where, family))
    if empty(reachable) and assessment.blocked_by is None:
        assessment.step("subnets", "block", reason="no candidate subnet admits internet traffic")
    elif not empty(reachable):
        # An earlier subnet may have recorded a block; any reachable subnet makes the asset reachable.
        assessment.blocked_by = None
    return reachable


def _aws_eip_addresses(inventory, scope, eni_id):
    """Use all already collected EIP associations for an exact interface match."""
    if not isinstance(eni_id, str) or not eni_id:
        return []
    key = ("aws_eip_by_eni",)
    if key not in inventory.network_cache:
        addresses = {}
        for eip in (*inventory.items("elastic_ip"), *inventory.items("ec2_eip")):
            data = eip["data"]
            interface = data.get("NetworkInterfaceId")
            public = data.get("PublicIp")
            if data.get("AssociationId") and isinstance(interface, str) and _public_ip(public):
                addresses.setdefault((eip["scope"], interface), set()).add(public)
        inventory.network_cache[key] = addresses
    return sorted(inventory.network_cache[key].get((scope, eni_id), set()))


def _aws_instance(snapshot, inventory, resource):
    data = resource["data"]
    a = Assessment(resource, "public_ip")
    interfaces = [n for n in as_list(data.get("NetworkInterfaces")) if isinstance(n, dict)]
    addresses = []
    for interface in interfaces:
        declared = (interface.get("Association") or {}).get("PublicIp")
        private_public = [(x.get("Association") or {}).get("PublicIp") for x in as_list(interface.get("PrivateIpAddresses"))
                          if isinstance(x, dict)]
        public = sorted(set(([declared] if declared else []) + [x for x in private_public if isinstance(x, str) and x] +
                            _aws_eip_addresses(inventory, resource["scope"], interface.get("NetworkInterfaceId"))))
        v6 = [x.get("Ipv6Address") for x in as_list(interface.get("Ipv6Addresses")) if isinstance(x, dict) and x.get("Ipv6Address")]
        if public or v6:
            addresses.append((interface, public, v6))
    if not interfaces and data.get("PublicIpAddress"):
        addresses.append(({"SubnetId": data.get("SubnetId"), "Groups": data.get("SecurityGroups", [])}, [data["PublicIpAddress"]], []))
    if not addresses:
        return None
    a.addresses = [ip for _, v4, v6 in addresses for ip in v4 + v6]
    state = (data.get("State") or {}).get("Name")
    total = {}
    for interface, v4, v6 in addresses:
        groups = [g.get("GroupId") for g in as_list(interface.get("Groups")) if isinstance(g, dict)]
        where = interface.get("NetworkInterfaceId", "primary")
        for family, addresses in ((4, v4), (6, v6)):
            if addresses:
                total = union(total, _aws_vpc_path(inventory, a, [interface.get("SubnetId") or data.get("SubnetId")], groups,
                                                   dict(FULL), where, vpc_id=interface.get("VpcId") or data.get("VpcId"), family=family))
    a.ports = total
    if not empty(total):
        a.blocked_by = None
    elif (projected := inventory.get("ec2_effective_ingress", data.get("InstanceId"))) is not None and projected["scope"] == resource["scope"]:
        proof = projected["data"].get("configured_path_witness")
        if isinstance(proof, dict):
            from .aws_public_ingress import MODEL, prepare, witness
            cache_key = ("aws_public_ingress_prepared", resource["scope"])
            if cache_key not in inventory.network_cache:
                inventory.network_cache[cache_key] = prepare(snapshot, resource["scope"])
            prepared = inventory.network_cache[cache_key]
            verified = witness(snapshot, resource["scope"], data.get("InstanceId"), prepared=prepared) if prepared is not None else None
            if projected["data"].get("proof_model") == MODEL and verified == proof:
                a.addresses = sorted(set(a.addresses + [proof["public_address"]]))
                a.ports = pset(proof["protocol"], proof["destination_port"], proof["destination_port"])
                a.blocked_by = None
                a.step("configured_path_witness", "allow", source_address=proof["source_address"],
                       network_interface_id=proof["network_interface_id"], destination_port=proof["destination_port"],
                       protocol=proof["protocol"], semantics="Positive direct IPv4 configuration witness; application listening unknown")
            else:
                a.gap("inventory", "cached direct-ingress witness does not match independently recomputed snapshot facts",
                      "ec2_effective_ingress")
                a.blocked_by = None
                a.ports = None
    if state and state != "running":
        a.dormant = True
        a.notes.append(f"instance state is {state}; exposure applies when it runs (public address retained)")
    return a


def _aws_eni(snapshot, inventory, resource):
    data = resource["data"]
    attachment = data.get("Attachment") if isinstance(data.get("Attachment"), dict) else {}
    if attachment.get("InstanceId") or str(data.get("Description", "")).startswith("ELB ") or data.get("InterfaceType") in (
            "nat_gateway", "network_load_balancer", "gateway_load_balancer", "gateway_load_balancer_endpoint", "vpc_endpoint", "load_balancer"):
        return None
    declared = (data.get("Association") or {}).get("PublicIp")
    private_public = [(x.get("Association") or {}).get("PublicIp") for x in as_list(data.get("PrivateIpAddresses"))
                      if isinstance(x, dict)]
    public = sorted(set(([declared] if declared else []) + [x for x in private_public if isinstance(x, str) and x] +
                        _aws_eip_addresses(inventory, resource["scope"], data.get("NetworkInterfaceId"))))
    v6 = [x.get("Ipv6Address") for x in as_list(data.get("Ipv6Addresses")) if isinstance(x, dict) and x.get("Ipv6Address")]
    if not public and not v6:
        return None
    a = Assessment(resource, "public_ip")
    a.addresses = public + v6
    groups = [g.get("GroupId") for g in as_list(data.get("Groups")) if isinstance(g, dict)]
    a.ports = {}
    for family, addresses in ((4, public), (6, v6)):
        if addresses:
            a.ports = union(a.ports, _aws_vpc_path(inventory, a, [data.get("SubnetId")], groups,
                                                  dict(FULL), native_id(resource), vpc_id=data.get("VpcId"), family=family))
    if not empty(a.ports):
        a.blocked_by = None
    if data.get("Description"):
        a.notes.append(f"interface description: {data['Description']}")
    return a


def _listener_ports(protocol, port):
    proto = str(protocol or "TCP").upper()
    kind = "udp" if proto == "UDP" else "all" if proto == "TCP_UDP" else "tcp"
    if kind == "all":
        return union(pset("tcp", port, port), pset("udp", port, port))
    return pset(kind, port, port)


def _aws_elbv2(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("Scheme") != "internet-facing":
        return None
    a = Assessment(resource, "load_balancer")
    a.endpoint = data.get("DNSName")
    a.addresses = [data.get("DNSName")] if data.get("DNSName") else []
    listeners = data.get("Listeners") if isinstance(data.get("Listeners"), dict) else {}
    ports = {}
    if listeners.get("collection_status") in ("collected", "empty"):
        auth = []
        for listener in as_list(listeners.get("items")):
            if isinstance(listener, dict) and isinstance(listener.get("Port"), int):
                ports = union(ports, _listener_ports(listener.get("Protocol"), listener["Port"]))
                if any(isinstance(x, dict) and str(x.get("Type", "")).startswith("authenticate-") for x in as_list(listener.get("DefaultActions"))):
                    auth.append(listener["Port"])
        a.step("listener", "allow" if not empty(ports) else "block", listeners=describe(ports), authenticated_default_actions=auth)
        a.authenticated = bool(auth) and set(auth) >= {p for _, p in ports_of(ports)}
    else:
        a.gap("listener", f"listeners {listeners.get('collection_status', 'not collected')}", "elbv2 describe_listeners")
        ports = dict(FULL)
    groups = data.get("SecurityGroups")
    subnets = [z.get("SubnetId") for z in as_list(data.get("AvailabilityZones")) if isinstance(z, dict) and z.get("SubnetId")]
    a.ports = _aws_vpc_path(inventory, a, subnets, groups if data.get("Type") == "application" or groups else None, ports,
                            native_id(resource), route=False, vpc_id=data.get("VpcId"))
    if data.get("Type") == "network" and not groups:
        a.notes.append("NLB without security groups: target security groups govern client traffic (client IP preserved)")
    if any(g["layer"] == "listener" for g in a.unresolved) and not empty(a.ports):
        a.ports = None
    return a


def _aws_classic(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("Scheme") != "internet-facing":
        return None
    a = Assessment(resource, "load_balancer")
    a.addresses = [data.get("DNSName")] if data.get("DNSName") else []
    ports = {}
    for item in as_list(data.get("ListenerDescriptions")):
        listener = item.get("Listener") if isinstance(item, dict) else None
        if isinstance(listener, dict) and isinstance(listener.get("LoadBalancerPort"), int):
            ports = union(ports, pset("tcp", listener["LoadBalancerPort"], listener["LoadBalancerPort"]))
    a.step("listener", "allow" if not empty(ports) else "block", listeners=describe(ports))
    a.ports = _aws_vpc_path(inventory, a, as_list(data.get("Subnets")), as_list(data.get("SecurityGroups")) if data.get("VPCId") else None,
                            ports, native_id(resource), route=False, vpc_id=data.get("VPCId"))
    return a


def _aws_rds(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("PubliclyAccessible") is not True:
        return None
    a = Assessment(resource, "database")
    endpoint = data.get("Endpoint") if isinstance(data.get("Endpoint"), dict) else {}
    a.addresses = [endpoint.get("Address")] if endpoint.get("Address") else []
    port = endpoint.get("Port", data.get("DbInstancePort"))
    ports = pset("tcp", port, port) if isinstance(port, int) else None
    if ports is None:
        a.gap("listener", "database endpoint port not collected")
        ports = dict(FULL)
    a.step("listener", "allow", port=port, engine=data.get("Engine"))
    groups = [g.get("VpcSecurityGroupId") for g in as_list(data.get("VpcSecurityGroups")) if isinstance(g, dict) and g.get("Status", "active") == "active"]
    group = data.get("DBSubnetGroup") if isinstance(data.get("DBSubnetGroup"), dict) else {}
    subnets = [s.get("SubnetIdentifier") for s in as_list(group.get("Subnets")) if isinstance(s, dict)]
    a.ports = _aws_vpc_path(inventory, a, subnets, groups, ports, native_id(resource), vpc_id=group.get("VpcId"))
    if data.get("DBInstanceStatus") not in (None, "available"):
        a.notes.append(f"DB instance status {data.get('DBInstanceStatus')}")
    return a


def _aws_redshift(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("PubliclyAccessible") is not True:
        return None
    a = Assessment(resource, "database")
    endpoint = data.get("Endpoint") if isinstance(data.get("Endpoint"), dict) else {}
    a.addresses = [endpoint.get("Address")] if endpoint.get("Address") else []
    port = endpoint.get("Port", 5439)
    a.step("listener", "allow", port=port)
    groups = [g.get("VpcSecurityGroupId") for g in as_list(data.get("VpcSecurityGroups")) if isinstance(g, dict)]
    name = data.get("ClusterSubnetGroupName")
    group = next((r["data"] for r in inventory.items("redshift_subnet_group") if r["scope"] == resource["scope"]
                  and r["data"].get("ClusterSubnetGroupName") == name), None)
    if not isinstance(group, dict):
        a.gap("inventory", "Redshift subnet group not collected", "redshift:DescribeClusterSubnetGroups")
        return a
    subnets = [s.get("SubnetIdentifier") for s in as_list(group.get("Subnets"))
               if isinstance(s, dict) and s.get("SubnetIdentifier")]
    if not subnets:
        a.gap("inventory", "Redshift subnet group has no collected subnets", "redshift:DescribeClusterSubnetGroups")
        return a
    a.ports = _aws_vpc_path(inventory, a, subnets, groups, pset("tcp", port, port), native_id(resource), vpc_id=group.get("VpcId"))
    return a


def _public_policy(document_value):
    """(public, restrictive_conditions) for an AWS resource policy document."""
    from .iam import document
    from .trust import restrictive_conditions
    doc = document(document_value)
    if doc is None:
        return None, []
    public, restricted = False, []
    for statement in as_list(doc.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        values = [principal] if isinstance(principal, str) else [v for x in principal.values() for v in as_list(x)] if isinstance(principal, dict) else []
        if "*" not in values:
            continue
        conditions = restrictive_conditions(statement.get("Condition"))
        if conditions:
            restricted.extend(conditions)
        else:
            public = True
    return public, restricted


def _aws_opensearch(snapshot, inventory, resource):
    domain = resource["data"].get("Domain")
    status = domain.get("DomainStatus") if isinstance(domain, dict) else None
    if not isinstance(status, dict):
        return None
    a = Assessment(resource, "managed_endpoint")
    if status.get("VPCOptions") and status["VPCOptions"].get("VPCId"):
        return None
    a.addresses = [status.get("Endpoint")] if status.get("Endpoint") else []
    a.step("route", "allow", reason="public (non-VPC) domain endpoint")
    public, restricted = _public_policy(status.get("AccessPolicies"))
    ports = pset("tcp", 443, 443)
    if status.get("DomainEndpointOptions", {}).get("EnforceHTTPS") is False:
        ports = union(ports, pset("tcp", 80, 80))
    if public is None:
        a.step("policy", "allow", reason="no access policy document; IAM identity policies govern", note="authenticated")
        a.authenticated = True
    elif public:
        a.step("policy", "allow", reason="access policy grants Principal * without restrictive conditions")
    else:
        a.step("policy", "allow", reason="access policy requires signed or condition-restricted access", restrictive_conditions=restricted)
        a.authenticated = True
    fine = status.get("AdvancedSecurityOptions", {})
    if isinstance(fine, dict) and fine.get("Enabled"):
        a.authenticated = True
        a.notes.append("fine-grained access control enabled")
    a.ports = ports
    return a


def _aws_eks(snapshot, inventory, resource):
    cluster = resource["data"].get("Cluster")
    config = cluster.get("cluster", {}).get("resourcesVpcConfig") if isinstance(cluster, dict) else None
    if not isinstance(config, dict):
        return None
    a = Assessment(resource, "control_plane")
    a.authenticated = True
    if config.get("endpointPublicAccess") is not True:
        return None
    a.addresses = [cluster["cluster"].get("endpoint")] if cluster["cluster"].get("endpoint") else []
    cidrs = as_list(config.get("publicAccessCidrs")) or ["0.0.0.0/0"]
    public = [c for c in cidrs if _public_source(c)]
    if public:
        a.step("source_ranges", "allow", public_access_cidrs=public,
               semantics="Declared public client CIDR; EKS authentication still applies")
        a.ports = pset("tcp", 443, 443)
    else:
        a.step("source_ranges", "block", public_access_cidrs=cidrs)
        a.ports = {}
    return a


def _aws_lambda_url(snapshot, inventory, resource):
    data = resource["data"]
    url = data.get("FunctionUrl")
    if not isinstance(url, dict) or url.get("absent") or url.get("AuthType") is None:
        if isinstance(url, dict) and url.get("collection_status") not in (None, "collected", "empty"):
            a = Assessment(resource, "function_url")
            a.gap("inventory", f"function URL config {url.get('collection_status')}", "lambda get_function_url_config")
            return a
        return None
    a = Assessment(resource, "function_url")
    a.addresses = [url.get("FunctionUrl")] if url.get("FunctionUrl") else []
    a.ports = pset("tcp", 443, 443)
    if url.get("AuthType") != "NONE":
        a.step("authorization", "allow", auth_type=url.get("AuthType"))
        a.authenticated = True
        a.explicit = "PASS"
        a.notes.append("Function URL requires SigV4 (AWS_IAM); not anonymously invocable")
        return a
    a.step("authorization", "allow", auth_type="NONE")
    policy = data.get("Policy") if isinstance(data.get("Policy"), dict) else {}
    if policy.get("absent"):
        a.step("policy", "block", reason="AuthType NONE but no resource policy grants public InvokeFunctionUrl")
        a.ports = {}
        return a
    if "Policy" not in policy:
        a.gap("policy", f"function policy {policy.get('collection_status', 'not collected')}", "lambda get_policy")
        return a
    from .iam import document
    doc = document(policy["Policy"]) or {}
    required = {"lambda:invokefunctionurl", "lambda:invokefunction"}
    public, denied, uncertain = set(), set(), set()
    function_arn = url.get("FunctionArn") or data.get("FunctionArn")
    from fnmatch import fnmatchcase
    for statement in as_list(doc.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny"):
            continue
        if any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain.update(required)
            continue
        principal = statement.get("Principal")
        values = [principal] if isinstance(principal, str) else as_list(principal.get("AWS")) if isinstance(principal, dict) else []
        if "*" not in values:
            continue
        actions = [str(x).lower() for x in as_list(statement.get("Action"))]
        matched = {action for action in required if any(fnmatchcase(action, pattern) for pattern in actions)}
        if not matched:
            continue
        resources = as_list(statement.get("Resource"))
        if not resources or not isinstance(function_arn, str):
            uncertain.update(matched)
            continue
        if not any(isinstance(value, str) and fnmatchcase(function_arn, value) for value in resources):
            continue
        condition = statement.get("Condition") or {}
        if not isinstance(condition, dict):
            uncertain.update(matched)
            continue
        applicable = True
        for operator, terms in condition.items():
            if not isinstance(terms, dict) or operator not in ("StringEquals", "Bool"):
                applicable = None
                break
            for key, value in terms.items():
                if isinstance(value, list):
                    value = value[0] if len(value) == 1 else None
                if value is None:
                    applicable = None
                    break
                normalized = str(value).lower()
                if operator == "StringEquals" and key.lower() == "lambda:functionurlauthtype":
                    if normalized != "none":
                        applicable = False
                elif operator == "Bool" and key.lower() == "lambda:invokedviafunctionurl":
                    if normalized != "true":
                        applicable = False
                else:
                    applicable = None
                    break
            if applicable is None:
                break
        if applicable is None:
            uncertain.update(matched)
        elif applicable:
            (public if statement["Effect"] == "Allow" else denied).update(matched)
    if denied:
        a.step("policy", "block", reason="public URL invocation is explicitly denied", denied_actions=sorted(denied))
        a.ports = {}
    elif uncertain:
        a.gap("policy", "public URL policy condition or resource is not fully resolved", "lambda:GetPolicy")
    elif public == required:
        a.step("policy", "allow", public_actions=sorted(public))
    else:
        created = url.get("CreationTime")
        try:
            from datetime import date
            created_date = date.fromisoformat(created[:10]) if isinstance(created, str) else None
        except ValueError:
            created_date = None
        if created_date is None or created_date < date(2025, 10, 1):
            if public:
                a.gap("policy", "legacy Function URL may use the pre-October-2025 permission model", "lambda:GetFunctionUrlConfig")
            else:
                a.step("policy", "block", reason="no public URL invocation grant")
                a.ports = {}
        else:
            a.step("policy", "block", reason="new Function URL requires both public invocation grants", public_actions=sorted(public))
            a.ports = {}
    return a


def _aws_api_stage(snapshot_data, assessment, service):
    """Check a cached API Gateway stage read without fetching during analysis."""
    stages = snapshot_data.get("Stages")
    operation = "apigateway:GetStages" if service == "rest" else "apigatewayv2:GetStages"
    if not isinstance(stages, dict) or stages.get("collection_status") not in ("collected", "empty"):
        assessment.gap("inventory", "API Gateway stage read unavailable", operation)
        return None
    rows = stages.get("items")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        assessment.gap("inventory", "API Gateway stage list malformed", operation)
        return None
    active = []
    for row in rows:
        name = row.get("stageName") if service == "rest" else row.get("StageName")
        deployment = row.get("deploymentId") if service == "rest" else row.get("DeploymentId")
        auto = row.get("AutoDeploy") is True if service == "http" else False
        if not isinstance(name, str) or not name:
            assessment.gap("inventory", "API Gateway stage name missing", operation)
            return None
        if isinstance(deployment, str) and deployment or auto:
            active.append(name)
    assessment.step("deployment", "allow" if active else "block", stage_names=active,
                    reason="no associated deployment or automatic deployment" if not active else "deployed stages collected")
    return bool(active)


def _aws_rest_api(snapshot, inventory, resource):
    data = resource["data"]
    a = Assessment(resource, "api")
    types = as_list((data.get("endpointConfiguration") or {}).get("types"))
    if "PRIVATE" in types:
        a.step("route", "block", endpoint_types=types, disable_execute_api_endpoint=data.get("disableExecuteApiEndpoint"))
        a.ports = {}
        return a
    domains, unresolved_domains, routing_domains = [], [], []
    for domain in inventory.items("apigateway_domain_name"):
        if domain["scope"] != resource["scope"]:
            continue
        domain_types = as_list((domain["data"].get("endpointConfiguration") or {}).get("types"))
        if not domain_types:
            unresolved_domains.append(domain["data"].get("domainName") or native_id(domain))
            continue
        if "PRIVATE" in domain_types:
            continue
        routing_mode = str(domain["data"].get("routingMode", ""))
        if "ROUTING_RULE" in routing_mode:
            rules = domain["data"].get("RoutingRules")
            if not isinstance(rules, dict) or rules.get("collection_status") not in ("collected", "empty") or not isinstance(rules.get("items"), list):
                routing_domains.append(domain["data"].get("domainName") or native_id(domain))
            else:
                stages = data.get("Stages") if isinstance(data.get("Stages"), dict) else {}
                active_stages = {s.get("stageName") for s in as_list(stages.get("items")) if isinstance(s, dict)
                                 and isinstance(s.get("deploymentId"), str) and s.get("deploymentId")}
                for rule in rules["items"]:
                    if not isinstance(rule, dict):
                        continue
                    for action in as_list(rule.get("Actions")):
                        invoke = action.get("InvokeApi") if isinstance(action, dict) else None
                        if isinstance(invoke, dict) and invoke.get("ApiId") == native_id(resource):
                            if invoke.get("Stage") in active_stages:
                                domains.append(str(domain["data"].get("domainName") or native_id(domain)))
                            else:
                                routing_domains.append(domain["data"].get("domainName") or native_id(domain))
            if "ONLY" in routing_mode:
                continue
        mappings = domain["data"].get("BasePathMappings") or {}
        if mappings.get("collection_status") != "collected":
            unresolved_domains.append(domain["data"].get("domainName") or native_id(domain))
            continue
        if any(isinstance(mapping, dict) and mapping.get("restApiId") == native_id(resource)
               for mapping in as_list(mappings.get("items"))):
            domains.append(str(domain["data"].get("domainName") or native_id(domain)))
    if data.get("disableExecuteApiEndpoint") is True and not domains:
        a.step("route", "block", endpoint_types=types, disable_execute_api_endpoint=True)
        if unresolved_domains or routing_domains or inventory.state("apigateway_domain_name", resource["scope"]) not in {"collected", "empty"}:
            a.gap("inventory", "custom-domain routing rules are not collected" if routing_domains and not unresolved_domains
                  else "custom-domain mappings are not fully collected",
                  "API Gateway domain routing and base-path mappings")
            a.explicit = "UNKNOWN"
        a.ports = {}
        return a
    if data.get("disableExecuteApiEndpoint") is not True:
        a.addresses.append(f"https://{native_id(resource)}.execute-api.{resource['scope'].split('/')[-1]}.amazonaws.com")
    a.addresses.extend(f"https://{name}" for name in sorted(set(domains)))
    a.step("route", "allow", endpoint_types=types, custom_domains=sorted(set(domains)),
           disable_execute_api_endpoint=data.get("disableExecuteApiEndpoint"),
           semantics="Configured API Gateway route; custom-domain DNS and requests were not tested")
    stage = _aws_api_stage(data, a, "rest")
    if stage is not True:
        a.ports = {} if stage is False else None
        return a
    if unresolved_domains:
        a.notes.append("Other custom-domain base-path mappings were not fully collected")
    if routing_domains:
        a.notes.append("Custom domains using routing rules require separate route resolution")
    policy = data.get("policy")
    if policy:
        from peaso.checks.aws_ip_policy_boundary import normalize
        from peaso.checks.facts import Unavailable
        try:
            normalized, bounded = normalize(policy)
        except (Unavailable, ValueError, TypeError):
            bounded = False
        if bounded:
            from peaso.checks.aws_resource_policy_scope import review_document
            violations, uncertain = review_document(normalized, minimum_ipv6_prefix=1)
            if not violations and not uncertain:
                a.step("policy", "block", reason="Unrestricted Internet sources are denied; allowlisted clients may still connect.")
                a.ports = {}
                return a
    public, restricted = _public_policy(policy)
    if public is False and restricted:
        a.step("policy", "allow", restrictive_conditions=restricted)
        a.notes.append("resource policy restricts callers by condition")
    from .iam import document
    policy = document(data.get("policy")) or {}
    conditional_denies = [statement.get("Condition") for statement in as_list(policy.get("Statement"))
        if isinstance(statement, dict) and statement.get("Effect") == "Deny" and statement.get("Condition")]
    if conditional_denies:
        a.step("policy", "allow", conditional_denies=conditional_denies,
               semantics="Caller source restrictions apply; configured custom domain may still have a public edge")
        a.authenticated = True
    a.ports = pset("tcp", 443, 443)
    methods = data.get("Methods", data.get("resources"))
    if isinstance(methods, list):
        if not methods:
            a.step("authorization", "block", reason="no methods configured")
            a.ports = {}
            return a
        if not all(isinstance(m, dict) and isinstance(m.get("authorizationType"), str)
                   and type(m.get("apiKeyRequired")) is bool for m in methods):
            a.gap("authorization", "method authorization or API-key fields malformed", "apigateway:GetResources")
            return a
        open_methods = [m.get("httpMethod") for m in methods if m["authorizationType"] == "NONE" and not m["apiKeyRequired"]]
        a.step("authorization", "allow" if open_methods else "block", unauthenticated_methods=open_methods,
               authentication_required=not bool(open_methods))
        if not open_methods:
            a.authenticated = True
            a.ports = {}
    else:
        a.gap("authorization", "method authorizationType/apiKeyRequired not collected", "apigateway:GetResources")
    return a


def _aws_http_api(snapshot, inventory, resource):
    data = resource["data"]
    a = Assessment(resource, "api")
    domains, unresolved_domains = [], []
    for domain in inventory.items("apigatewayv2_domain_name"):
        if domain["scope"] != resource["scope"]:
            continue
        domain_data = domain["data"]
        configs = as_list(domain_data.get("DomainNameConfigurations"))
        if not configs or any(not isinstance(config, dict) or config.get("EndpointType") not in {"REGIONAL", "EDGE", "PRIVATE"}
                              for config in configs):
            unresolved_domains.append(domain_data.get("DomainName"))
            continue
        if configs and all(isinstance(config, dict) and config.get("EndpointType") == "PRIVATE" for config in configs):
            continue
        if "ROUTING_RULE" in str(domain_data.get("RoutingMode", "")):
            unresolved_domains.append(domain_data.get("DomainName"))
            continue
        mappings = domain_data.get("ApiMappings") or {}
        if mappings.get("collection_status") != "collected":
            unresolved_domains.append(domain_data.get("DomainName"))
            continue
        if any(isinstance(mapping, dict) and mapping.get("ApiId") == data.get("ApiId")
               for mapping in as_list(mappings.get("items"))):
            name = domain_data.get("DomainName")
            if isinstance(name, str) and name:
                domains.append(name)
            else:
                unresolved_domains.append(native_id(domain))
    if data.get("DisableExecuteApiEndpoint") is True and not domains:
        a.step("route", "block", disable_execute_api_endpoint=True)
        if unresolved_domains or inventory.state("apigatewayv2_domain_name", resource["scope"]) not in {"collected", "empty"}:
            a.gap("inventory", "HTTP API custom-domain mappings or routing rules are not fully collected",
                  "apigatewayv2 get_domain_names + get_api_mappings")
            a.explicit = "UNKNOWN"
        a.ports = {}
        return a
    if data.get("DisableExecuteApiEndpoint") is not True and data.get("ApiEndpoint"):
        a.addresses.append(data["ApiEndpoint"])
    a.addresses.extend(f"https://{name}" for name in sorted(set(domains)) if name)
    a.step("route", "allow", protocol=data.get("ProtocolType"), custom_domains=sorted(set(domains)),
           disable_execute_api_endpoint=data.get("DisableExecuteApiEndpoint"))
    stage = _aws_api_stage(data, a, "http")
    if stage is not True:
        a.ports = {} if stage is False else None
        return a
    a.ports = pset("tcp", 443, 443)
    routes = data.get("Routes")
    if isinstance(routes, dict) and routes.get("collection_status") == "collected":
        routes = routes.get("items")
    if isinstance(routes, list):
        if not routes:
            a.step("authorization", "block", reason="no routes configured")
            a.ports = {}
            return a
        open_routes = [r.get("RouteKey") for r in routes if isinstance(r, dict) and r.get("AuthorizationType", "NONE") == "NONE" and not r.get("ApiKeyRequired")]
        a.step("authorization", "allow" if open_routes else "block", unauthenticated_routes=open_routes,
               authentication_required=not bool(open_routes))
        if not open_routes:
            a.authenticated = True
            a.ports = {}
    else:
        a.gap("authorization", "route AuthorizationType not collected", "apigatewayv2:GetRoutes")
    return a


def _aws_snapshot_share(snapshot, inventory, resource, attribute_path, name):
    from .trust import trusted_scopes
    data = resource["data"]
    a = Assessment(resource, "data_share")
    attributes = data.get("Attributes")
    if not isinstance(attributes, dict) or attributes.get("collection_status") not in (None, "collected"):
        if data.get("SnapshotType") in ("automated", "awsbackup"):
            return None
        a.gap("attributes", f"{name} sharing attributes {'not collected' if not isinstance(attributes, dict) else attributes.get('collection_status')}",
              "rds describe_db_cluster_snapshot_attributes" if name == "cluster snapshot" else "rds describe_db_snapshot_attributes")
        return a
    result = attributes
    for key in attribute_path:
        result = result.get(key, {}) if isinstance(result, dict) else {}
    values = [v for x in as_list(result) if isinstance(x, dict) and x.get("AttributeName") == "restore" for v in as_list(x.get("AttributeValues"))]
    trusted = trusted_scopes(snapshot)["ids"]
    if "all" in values:
        a.step("attributes", "allow", restore=["all"])
        a.data_exposure = True
        a.ports = {}
        return a
    foreign = [v for v in values if trusted and v not in trusted]
    if foreign:
        a.step("attributes", "allow", restore=values, external_accounts=foreign)
        a.external_ids = foreign
        a.kind = "external_share"
        a.explicit = "FAIL"
        return a
    a.step("attributes", "block", restore=values)
    a.ports = {}
    return a


def _aws_ec2_share(snapshot, inventory, resource, field, coverage_field, permission_key):
    """Report only observed EC2 snapshot/image launch grants; missing reads stay unknown."""
    from .trust import trusted_scopes
    data = resource["data"]
    a = Assessment(resource, "data_share")
    coverage = (data.get("_coverage") or {}).get(coverage_field, {})
    permissions = data.get(field)
    if coverage.get("status") not in ("collected", "empty") or not isinstance(permissions, list):
        a.gap("attributes", f"{coverage_field} not completely collected", f"ec2:{permission_key}")
        return a
    if not all(isinstance(p, dict) for p in permissions):
        a.gap("attributes", f"{coverage_field} malformed", f"ec2:{permission_key}")
        return a
    public = any(p.get("Group") == "all" for p in permissions)
    external = sorted({p["UserId"] for p in permissions if isinstance(p.get("UserId"), str)
                       and p["UserId"] not in trusted_scopes(snapshot)["ids"]})
    if resource["type"] == "ebs_snapshot" and public:
        settings = [r for r in inventory.items("ec2_regional_settings") if r["scope"] == resource["scope"]]
        state = settings[0]["data"].get("SnapshotBlockPublicAccessState") if len(settings) == 1 else None
        if state == "block-all-sharing":
            a.step("public_access_block", "block", state=state)
            public = False
        elif state not in ("block-new-sharing", "unblocked"):
            a.gap("attributes", "EBS snapshot Block Public Access state not collected", "ec2:GetSnapshotBlockPublicAccessState")
            return a
        else:
            a.step("public_access_block", "allow", state=state)
    if public:
        a.step("attributes", "allow", public_group="all")
        a.data_exposure = True
        a.ports = {}
    elif external:
        a.step("attributes", "allow", external_accounts=external)
        a.kind = "external_share"
        a.external_ids = external
        a.explicit = "FAIL"
    else:
        a.step("attributes", "block", permission_count=len(permissions))
        a.ports = {}
    return a


def _aws_cloudfront(snapshot, inventory, resource):
    data = resource["data"]
    config = data.get("Config")
    if not isinstance(config, dict) or config.get("collection_status") != "collected":
        a = Assessment(resource, "cdn_endpoint")
        a.gap("inventory", "CloudFront distribution config not collected", "cloudfront:GetDistributionConfig")
        return a
    distribution = config.get("DistributionConfig")
    if not isinstance(distribution, dict):
        a = Assessment(resource, "cdn_endpoint")
        a.gap("inventory", "CloudFront distribution config malformed", "cloudfront:GetDistributionConfig")
        return a
    if distribution.get("Enabled") is not True:
        return None
    a = Assessment(resource, "cdn_endpoint")
    domain = data.get("DomainName")
    if isinstance(domain, str) and domain:
        a.addresses = [domain]
    else:
        a.gap("inventory", "CloudFront domain name missing", "cloudfront:ListDistributions")
    behaviors = [distribution.get("DefaultCacheBehavior")]
    behaviors.extend((distribution.get("CacheBehaviors") or {}).get("Items") or [])
    if not all(isinstance(b, dict) for b in behaviors):
        a.gap("listener", "CloudFront cache behavior missing")
        return a
    ports = {}
    for behavior in behaviors:
        policy = behavior.get("ViewerProtocolPolicy")
        if policy in ("allow-all", "redirect-to-https", "https-only"):
            ports = union(ports, pset("tcp", 443, 443))
        if policy in ("allow-all", "redirect-to-https"):
            ports = union(ports, pset("tcp", 80, 80))
        if policy not in ("allow-all", "redirect-to-https", "https-only"):
            a.gap("listener", "CloudFront viewer protocol policy unresolved")
    a.ports = ports
    a.step("listener", "allow" if ports else "block", viewer_protocol_policies=sorted({b.get("ViewerProtocolPolicy") for b in behaviors if isinstance(b.get("ViewerProtocolPolicy"), str)}))
    a.notes.append("CloudFront viewer reachability does not establish origin reachability or authorization")
    return a


def _aws_app_runner(snapshot, inventory, resource):
    data = resource["data"]
    details = data.get("NetworkDetails")
    a = Assessment(resource, "managed_endpoint")
    if not isinstance(details, dict) or not isinstance(details.get("NetworkConfiguration"), dict):
        a.gap("inventory", "App Runner DescribeService network configuration missing", "apprunner:DescribeService")
        return a
    ingress = details["NetworkConfiguration"].get("IngressConfiguration")
    if not isinstance(ingress, dict):
        a.gap("inventory", "App Runner ingress configuration malformed", "apprunner:DescribeService")
        return a
    public = ingress.get("IsPubliclyAccessible", True)  # AWS default when omitted.
    if type(public) is not bool:
        a.gap("inventory", "App Runner public ingress setting malformed", "apprunner:DescribeService")
        return a
    url = details.get("ServiceUrl") or data.get("ServiceUrl")
    if public is False:
        a.step("private_endpoint", "block", is_publicly_accessible=False)
        a.ports = {}
        return a
    if not isinstance(url, str) or not url:
        a.gap("inventory", "App Runner service URL missing", "apprunner:DescribeService")
        return a
    a.addresses = [url]
    a.ports = pset("tcp", 443, 443)
    a.step("ingress", "allow", is_publicly_accessible=True,
           source="default" if "IsPubliclyAccessible" not in ingress else "declared")
    a.dormant = details.get("Status", data.get("Status")) != "RUNNING"
    return a


def _aws_amplify(snapshot, inventory, resource):
    data = resource["data"]
    branches = data.get("Branches")
    a = Assessment(resource, "managed_endpoint")
    if not isinstance(branches, dict) or branches.get("collection_status") not in ("collected", "empty"):
        a.gap("inventory", "Amplify branch inventory missing", "amplify:ListBranches")
        return a
    items = branches.get("items")
    if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
        a.gap("inventory", "Amplify branch inventory malformed", "amplify:ListBranches")
        return a
    if not items:
        return None
    domain = data.get("defaultDomain")
    if not isinstance(domain, str) or not domain:
        a.gap("inventory", "Amplify default domain missing", "amplify:ListApps")
        return a
    names = [x.get("displayName") or x.get("branchName") for x in items]
    if any(not isinstance(name, str) or not name for name in names):
        a.gap("inventory", "Amplify branch domain prefix missing", "amplify:ListBranches")
        return a
    a.addresses = [f"{name}.{domain}" for name in names]
    domains = data.get("DomainAssociations")
    if isinstance(domains, dict) and domains.get("collection_status") in ("collected", "empty") and isinstance(domains.get("items"), list):
        custom = []
        for association in domains["items"]:
            if not isinstance(association, dict) or association.get("domainStatus") != "AVAILABLE":
                continue
            suffix = association.get("domainName")
            if not isinstance(suffix, str) or not suffix:
                continue
            for subdomain in as_list(association.get("subDomains")):
                if not isinstance(subdomain, dict) or subdomain.get("verified") is not True:
                    continue
                setting = subdomain.get("subDomainSetting")
                if not isinstance(setting, dict) or setting.get("branchName") not in [x.get("branchName") for x in items]:
                    continue
                prefix = setting.get("prefix")
                if isinstance(prefix, str):
                    custom.append(f"{prefix}.{suffix}" if prefix else suffix)
        a.addresses.extend(custom)
        a.step("custom_domain", "allow" if custom else "block", domains=custom)
    else:
        a.notes.append("Custom-domain associations were not collected; default branch domains remain known")
    a.ports = pset("tcp", 443, 443)
    a.step("hosting", "allow", branch_count=len(items), default_domains=a.addresses[:len(items)])
    a.notes.append("Deployment health is not collected; configured endpoint availability may differ")
    a.authenticated = all(x.get("enableBasicAuth") is True or data.get("enableBasicAuth") is True for x in items)
    return a


def _aws_bucket(snapshot, inventory, resource):
    data = resource["data"]
    a = Assessment(resource, "data_share")
    policy_status = (data.get("PolicyStatus") or {}).get("PolicyStatus", {}) if isinstance(data.get("PolicyStatus"), dict) else {}
    public_policy = policy_status.get("IsPublic") if isinstance(policy_status, dict) else None
    restricted = []
    if public_policy is None:
        policy = data.get("Policy") if isinstance(data.get("Policy"), dict) else {}
        if policy.get("absent"):
            public_policy = False
        elif "Policy" in policy:
            public_policy, restricted = _public_policy(policy["Policy"])
    acl = data.get("Acl") if isinstance(data.get("Acl"), dict) else {}
    grants = [g for g in as_list(acl.get("Grants")) if isinstance(g, dict) and str((g.get("Grantee") or {}).get("URI", "")).endswith(("/AllUsers", "/AuthenticatedUsers"))]
    public_acl = bool(grants) if acl.get("collection_status") in (None, "collected") and "Grants" in acl else None
    if public_policy is False and public_acl is False:
        return None
    if public_policy is None and public_acl is None:
        a.gap("policy", "bucket policy status and ACL not collected", "s3 get_bucket_policy_status / get_bucket_acl")
        return a
    settings, sources = effective_bucket_bpa(snapshot, inventory, resource)
    a.step("policy", "allow" if public_policy else "not_public", public_policy=public_policy, restrictive_conditions=restricted)
    a.step("acl", "allow" if public_acl else "not_public", public_grants=[g.get("Permission") for g in grants])
    if settings is None:
        a.gap("public_access_block", "account-level S3 Block Public Access not collected", "s3control get_public_access_block")
        a.unresolved[-1]["layer"] = "policy"
        a.data_exposure = True
        return a
    exposed_policy = bool(public_policy) and not settings.get("RestrictPublicBuckets")
    exposed_acl = bool(public_acl) and not settings.get("IgnorePublicAcls")
    a.step("public_access_block", "allow" if exposed_policy or exposed_acl else "block", effective=settings, sources=sources)
    if exposed_policy or exposed_acl:
        a.data_exposure = True
        a.addresses = [f"https://{native_id(resource)}.s3.amazonaws.com"]
        a.blocked_by = None
    else:
        a.ports = {}
    return a


def effective_bucket_bpa(snapshot, inventory, resource):
    """(settings or None, sources) combining bucket and account S3 Block Public Access (logical OR)."""
    names = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    bucket = resource["data"].get("PublicAccessBlock") if isinstance(resource["data"].get("PublicAccessBlock"), dict) else {}
    bucket_config = bucket.get("PublicAccessBlockConfiguration") if isinstance(bucket.get("PublicAccessBlockConfiguration"), dict) else {}
    if not bucket.get("absent") and not bucket_config:
        return None, {"bucket": bucket.get("collection_status", "not_collected")}
    account = resource["scope"].split("/", 1)[0]
    state = inventory.state("s3_account_public_access_block", resource["scope"])
    if state.startswith("missing"):
        return None, {"bucket": "collected", "account": state}
    account_items = [r for r in inventory.items("s3_account_public_access_block") if r["scope"].split("/", 1)[0] == account]
    account_config = {}
    for item in account_items:
        config = item["data"].get("PublicAccessBlockConfiguration", item["data"])
        if isinstance(config, dict):
            account_config = config
    settings = {k: bool(bucket_config.get(k)) or bool(account_config.get(k)) for k in names}
    return settings, {"bucket": dict(bucket_config) if bucket_config else "absent", "account": dict(account_config) if account_config else "absent"}


# ---------------------------------------------------------------------- GCP

def _gcp_rule_ports(entries):
    ports = {}
    for entry in as_list(entries):
        if not isinstance(entry, dict):
            continue
        protocol = entry.get("IPProtocol", entry.get("ipProtocol"))
        if _proto(protocol) is None:
            continue
        specs = as_list(entry.get("ports")) or [None]
        for spec in specs:
            current = _port_spec(protocol, spec)
            if current:
                ports = union(ports, current)
    return ports


def _gcp_network_internet_rules(inventory, network):
    """VPC firewall rules of one network that admit internet ingress, in inventory order.

    The network/direction/source filters do not depend on the instance, so the
    rules are grouped by network once instead of rescanning every rule for each
    exposed interface. Target tag/service-account filters stay per interface.
    """
    def eligible(rule):
        r = rule["data"]
        if r.get("direction", "INGRESS") != "INGRESS" or r.get("disabled"):
            return False
        sources = as_list(r.get("sourceRanges"))
        if not sources and (r.get("sourceTags") or r.get("sourceServiceAccounts")):
            return False
        return not sources or any(_public_source(x) for x in sources)
    try:
        hash(network)
    except TypeError:
        return [rule for rule in inventory.items("firewall")
                if rule["data"].get("network") == network and eligible(rule)]
    index = inventory.network_cache.get("gcp_network_internet_rules")
    if index is None:
        grouped, unhashable = {}, []
        for rule in inventory.items("firewall"):
            value = rule["data"].get("network")
            try:
                grouped.setdefault(value, []).append(rule)
            except TypeError:
                unhashable.append(rule)
        index = inventory.network_cache["gcp_network_internet_rules"] = ({}, grouped, unhashable)
    resolved, grouped, unhashable = index
    if network not in resolved:
        if unhashable:
            # Rare non-string network values keep the exact equality scan.
            rules = [rule for rule in inventory.items("firewall")
                     if rule["data"].get("network") == network and eligible(rule)]
        else:
            rules = [rule for rule in grouped.get(network, ()) if eligible(rule)]
        resolved[network] = rules
    return resolved[network]


def _gcp_firewall(inventory, instance, interface, assessment):
    data = instance["data"]
    network = interface.get("network")
    tags = set(as_list((data.get("tags") or {}).get("items")))
    accounts = {s.get("email") for s in as_list(data.get("serviceAccounts")) if isinstance(s, dict)}
    allowed, decided = {}, {}
    policies = inventory.items("firewall_policy")
    hierarchy = (((inventory.snapshot.get("metadata") or {}).get("network_context") or {}).get("gcp") or {}).get("firewall_hierarchy") or {}
    unaffected = (hierarchy.get("complete") is True and instance.get("scope") in as_list(hierarchy.get("unaffected_projects")))
    network_resource = inventory.get("network", network)
    if ((policies and not unaffected) or
        (network_resource is not None and network_resource["data"].get("firewallPolicy")) or
        any(as_list(row["data"].get("firewallPolicys")) for row in inventory.items("effective_firewall")
            if row.get("scope") == instance.get("scope") and row["data"].get("network") == network)):
        assessment.gap("firewall", "attached hierarchical, network, or regional policy precedence needs an effective per-instance rule decision")
        return None
    if inventory.state("firewall_policy").startswith("missing"):
        assessment.gap("firewall_policy", "hierarchical/network firewall policies not collected", "compute firewallPolicies")
        assessment.unresolved[-1]["decisive"] = False
    candidates = []
    for rule in _gcp_network_internet_rules(inventory, network):
        r = rule["data"]
        if r.get("targetTags") and not tags & set(r["targetTags"]):
            continue
        if r.get("targetServiceAccounts") and not accounts & set(r["targetServiceAccounts"]):
            continue
        candidates.append(rule)
    if inventory.state("firewall").startswith("missing"):
        assessment.gap("firewall", f"VPC firewall rules {inventory.state('firewall')}", "compute firewalls.list")
        return None
    matched = []
    for rule in sorted(candidates, key=lambda x: (int(x["data"].get("priority", 1000)), 0 if x["data"].get("denied") else 1)):
        r = rule["data"]
        ports = _gcp_rule_ports(r.get("denied") or r.get("allowed"))
        fresh = subtract(ports, decided)
        if r.get("allowed") and not empty(fresh):
            allowed = union(allowed, fresh)
            matched.append({"rule": r.get("name"), "priority": r.get("priority", 1000), "action": "allow", "ports": describe(fresh)})
        elif r.get("denied") and not empty(fresh):
            matched.append({"rule": r.get("name"), "priority": r.get("priority", 1000), "action": "deny", "ports": describe(fresh)})
        decided = union(decided, ports)
    assessment.step("firewall", "allow" if not empty(allowed) else "block", network=network, matched_rules=matched,
                    implied="deny ingress", allowed=describe(allowed))
    return allowed


def _gcp_instance(snapshot, inventory, resource):
    data = resource["data"]
    interfaces = [n for n in as_list(data.get("networkInterfaces")) if isinstance(n, dict)]
    exposed = [(n, [c.get("natIP") for c in as_list(n.get("accessConfigs")) if isinstance(c, dict) and c.get("natIP")]
                + [c.get("externalIpv6") for c in as_list(n.get("ipv6AccessConfigs")) if isinstance(c, dict) and c.get("externalIpv6")]) for n in interfaces]
    exposed = [(n, ips) for n, ips in exposed if ips]
    if not exposed:
        return None
    a = Assessment(resource, "public_ip")
    total = {}
    unknown = False
    for interface, ips in exposed:
        a.addresses.extend(ips)
        a.step("external_ip", "allow", interface=interface.get("name"), addresses=ips)
        allowed = _gcp_firewall(inventory, resource, interface, a)
        if allowed is None:
            unknown = True
        else:
            total = union(total, allowed)
    a.ports = None if unknown and empty(total) else total
    if not empty(total):
        a.blocked_by = None
    if data.get("status") not in (None, "RUNNING"):
        a.dormant = True
        a.notes.append(f"instance status {data.get('status')}")
    return a


def _gcp_forwarding_rule(snapshot, inventory, resource):
    data = resource["data"]
    if str(data.get("loadBalancingScheme", "EXTERNAL")) not in ("EXTERNAL", "EXTERNAL_MANAGED"):
        return None
    a = Assessment(resource, "load_balancer")
    a.addresses = [data.get("IPAddress")] if data.get("IPAddress") else []
    if not a.addresses or not _public_ip(a.addresses[0]):
        a.explicit = "UNKNOWN"
        a.gap("public_ip", "external forwarding rule has no observed public IP address")
    protocol = data.get("IPProtocol", "TCP")
    if str(protocol).upper() == "ESP":
        ports = {"esp": ((0, 0),)}
    elif data.get("allPorts"):
        ports = pset(protocol)
    elif data.get("ports"):
        ports = {}
        for spec in as_list(data["ports"]):
            ports = union(ports, _port_spec(protocol, spec) or {})
    else:
        ports = _port_spec(protocol, data.get("portRange")) or {}
    a.step("forwarding_rule", "allow", scheme=data.get("loadBalancingScheme"), ports=describe(ports), target=data.get("target") or data.get("backendService"))
    a.ports = ports
    target = data.get("target")
    if isinstance(target, str) and "/targetVpnGateways/" in target:
        a.kind = "vpn_gateway"
        a.notes.append("Classic Cloud VPN accepts ESP and IKE; the configured forwarding rule selects this protocol")
        return a
    if isinstance(target, str) and ("/targetPools/" in target or "/targetInstances/" in target):
        target_kind = "target_pool" if "/targetPools/" in target else "target_instance"
        destination = inventory.get(target_kind, target)
        if destination is None:
            a.gap("backend", f"{target_kind} {target} not collected", "compute aggregated targetPools/targetInstances")
            return a
        detail = destination["data"]
        refs = as_list(detail.get("instances")) if target_kind == "target_pool" else [detail.get("instance")]
        allowed, inspected, unresolved = {}, 0, False
        for ref in refs:
            vm = inventory.get("instance", ref)
            if vm is None:
                unresolved = True
                continue
            interfaces = [row for row in as_list(vm["data"].get("networkInterfaces")) if isinstance(row, dict)]
            if not interfaces:
                unresolved = True
            for interface in interfaces:
                open_ports = _gcp_firewall(inventory, vm, interface, a)
                if open_ports is None:
                    unresolved = True
                else:
                    inspected += 1
                    allowed = union(allowed, intersect(ports, open_ports))
        if inspected and not unresolved:
            a.ports = allowed
            a.step("backend", "allow" if not empty(allowed) else "block", target_kind=target_kind,
                   instances=refs, allowed=describe(allowed))
        else:
            a.gap("backend", "target VM inventory or effective firewall is incomplete")
        if target_kind == "target_pool":
            a.notes.append("Target pool backend health and application listener state are not proven by this declaration")
        if detail.get("securityPolicy"):
            decision = _gcp_armor_decision(inventory, detail["securityPolicy"])
            if decision == "block":
                a.ports = {}
                a.step("cloud_armor", "block", security_policy=detail["securityPolicy"])
            elif decision == "unknown":
                a.gap("cloud_armor", "target instance security policy decision is request dependent or unavailable")
        return a
    if target and "/target" in target and "Pools" not in target and "Instances" not in target:
        proxy = inventory.get("target_proxy", target)
        if proxy is None:
            a.gap("backend", f"target proxy {target} not collected", "compute targetHttp(s)Proxies")
            return a
        services = []
        url_map = proxy["data"].get("urlMap")
        if url_map:
            mapping = inventory.get("url_map", url_map)
            if mapping is None:
                a.gap("backend", f"url map {url_map} not collected", "compute urlMaps")
                return a
            m = mapping["data"]
            def route_backends(route, action_key):
                if not isinstance(route, dict):
                    return []
                found = [route.get("defaultService") or route.get("service")]
                action = route.get(action_key)
                if isinstance(action, dict):
                    for weighted in as_list(action.get("weightedBackendServices")):
                        if isinstance(weighted, dict) and isinstance(weighted.get("weight"), int) and weighted["weight"] > 0:
                            found.append(weighted.get("backendService"))
                return [ref for ref in found if isinstance(ref, str) and ref]
            services = route_backends(m, "defaultRouteAction")
            for matcher in as_list(m.get("pathMatchers")):
                services.extend(route_backends(matcher, "defaultRouteAction"))
                if not isinstance(matcher, dict):
                    continue
                for rule in as_list(matcher.get("pathRules")) + as_list(matcher.get("routeRules")):
                    services.extend(route_backends(rule, "routeAction"))
        elif proxy["data"].get("service"):
            services = [proxy["data"]["service"]]
        services = [s for s in dict.fromkeys(services) if s]
        armor, unprotected, buckets = [], [], []
        unresolved_backend = not services
        if not services:
            a.gap("backend", "target proxy has no collected URL-map backend route")
        for service in services:
            if "/backendBuckets/" in service:
                bucket = inventory.get("backend_bucket", service)
                if bucket is None:
                    unresolved_backend = True
                    a.gap("backend", f"backend bucket {service} not collected", "compute backendBuckets")
                    continue
                detail = bucket["data"]
                origin = {"backend_bucket": service, "bucket_name": detail.get("bucketName"),
                          "cdn_enabled": detail.get("enableCdn"),
                          "signed_url_keys_present": bool(as_list((detail.get("cdnPolicy") or {}).get("signedUrlKeyNames")))}
                buckets.append(origin)
                policy = detail.get("edgeSecurityPolicy")
                (armor if policy else unprotected).append({**origin, "security_policy": policy})
                continue
            backend = inventory.get("backend_service", service)
            if backend is None:
                unresolved_backend = True
                a.gap("backend", f"backend service {service} not collected", "compute backendServices")
                continue
            policy = backend["data"].get("securityPolicy")
            (armor if policy else unprotected).append({"backend_service": service, "security_policy": policy})
            if backend["data"].get("iap", {}).get("enabled"):
                a.authenticated = True
                a.notes.append(f"IAP enabled on {service}")
        a.step("cloud_armor", "allow" if unprotected else "unknown", unprotected=unprotected, protected=armor, backend_buckets=buckets)
        if armor and not unprotected and not unresolved_backend:
            decisions = [_gcp_armor_decision(inventory, entry["security_policy"]) for entry in armor]
            if all(decision == "block" for decision in decisions):
                a.step("cloud_armor_rules", "block", decisions=decisions)
                a.ports = {}
            elif any(decision == "allow" for decision in decisions):
                a.step("cloud_armor_rules", "allow", decisions=decisions)
            else:
                a.gap("cloud_armor", "Cloud Armor policy rules or request-dependent matches cannot establish a public path", STATIC_GAPS["gcp"][0]["fact"])
    else:
        backend_ref = data.get("backendService")
        backend = inventory.get("backend_service", backend_ref)
        health = backend["data"].get("BackendHealth") if backend is not None else None
        if not isinstance(health, dict):
            separate = inventory.get("backend_service_health", backend_ref)
            health = separate["data"] if separate is not None else None
        if backend is None or not isinstance(health, dict) or health.get("collection_status") != "collected":
            a.gap("backend", "passthrough load balancer backend service or health is unavailable",
                  "backend_service.BackendHealth")
            return a
        allowed, inspected, unresolved = {}, 0, False
        for group in as_list(health.get("groups")):
            if not isinstance(group, dict) or group.get("collection_status") != "collected":
                unresolved = True
                continue
            for endpoint in as_list(group.get("healthStatus")):
                if not isinstance(endpoint, dict) or endpoint.get("healthState") != "HEALTHY":
                    continue
                vm = inventory.get("instance", endpoint.get("instance"))
                if vm is None:
                    unresolved = True
                    continue
                interfaces = [row for row in as_list(vm["data"].get("networkInterfaces")) if isinstance(row, dict)]
                if not interfaces:
                    unresolved = True
                    continue
                for interface in interfaces:
                    open_ports = _gcp_firewall(inventory, vm, interface, a)
                    if open_ports is None:
                        unresolved = True
                    else:
                        inspected += 1
                        allowed = union(allowed, intersect(ports, open_ports))
        if not empty(allowed):
            a.ports = allowed
            a.step("passthrough_backend", "allow", healthy_interfaces_inspected=inspected,
                   allowed=describe(allowed))
        elif inspected and not unresolved:
            a.ports = {}
            a.step("passthrough_backend", "block", healthy_interfaces_inspected=inspected)
        else:
            a.gap("backend", "no complete healthy backend VM and firewall path was established",
                  STATIC_GAPS["gcp"][1]["fact"])
    return a


def _gcp_armor_decision(inventory, policy_ref):
    """Resolve only a first universal Cloud Armor rule; retain all other matches as unknown."""
    policy = inventory.get("security_policy", policy_ref)
    if policy is None or inventory.state("security_policy", policy["scope"]) not in AVAILABLE:
        return "unknown"
    rules = policy["data"].get("rules")
    if not isinstance(rules, list) or not rules:
        return "unknown"
    try:
        ordered = sorted(rules, key=lambda row: int(row["priority"]))
    except (TypeError, ValueError, KeyError):
        return "unknown"
    for rule in ordered:
        if not isinstance(rule, dict) or rule.get("preview") is True:
            continue
        match = rule.get("match")
        if not isinstance(match, dict) or match.get("expr") or rule.get("networkMatch"):
            return "unknown"
        config = match.get("config")
        if not isinstance(config, dict) or set(config) != {"srcIpRanges"}:
            return "unknown"
        ranges = as_list(config.get("srcIpRanges"))
        if not ranges or not all(value == "*" or _cidr(value) is not None for value in ranges):
            return "unknown"
        if not any(_public_source(value) for value in ranges):
            # A preceding private-source rule does not establish a public path.
            continue
        action = rule.get("action")
        if action == "allow":
            return "allow"
        return "block" if (isinstance(action, str) and action.startswith("deny(")
                           and any(value == "*" or _internet(value) for value in ranges)) else "unknown"
    return "unknown"


def _gcp_invoker(policy, roles):
    if not isinstance(policy, dict):
        return None, None
    public, conditional = [], []
    for binding in as_list(policy.get("bindings")):
        if isinstance(binding, dict) and binding.get("role") in roles:
            members = [m for m in as_list(binding.get("members")) if m in ("allUsers", "allAuthenticatedUsers")]
            if binding.get("condition"):
                conditional.extend(members)
            else:
                public.extend(members)
    return public, conditional


def _gcp_serverless(snapshot, inventory, resource):
    data = resource["data"]
    a = Assessment(resource, "serverless")
    backing = None
    if resource["type"] == "cloudrun_service":
        ingress = data.get("ingress", "INGRESS_TRAFFIC_ALL")
        open_ingress = ingress == "INGRESS_TRAFFIC_ALL"
        a.addresses = as_list(data.get("urls")) or ([data.get("uri")] if data.get("uri") else [])
        roles = {"roles/run.invoker", "roles/run.servicesInvoker"}
        disabled = data.get("invokerIamDisabled") is True
    else:
        config = data.get("serviceConfig") if isinstance(data.get("serviceConfig"), dict) else data
        ingress = config.get("ingressSettings", "ALLOW_ALL")
        open_ingress = ingress == "ALLOW_ALL"
        a.addresses = [config.get("uri") or (data.get("httpsTrigger") or {}).get("url")] if (config.get("uri") or (data.get("httpsTrigger") or {}).get("url")) else []
        roles = {"roles/cloudfunctions.invoker", "roles/run.invoker", "roles/run.servicesInvoker"}
        disabled = False
        service_ref = config.get("service")
        if isinstance(service_ref, str) and service_ref:
            backing = inventory.get("cloudrun_service", service_ref)
    a.step("ingress", "allow" if open_ingress else "block", ingress=ingress)
    a.ports = pset("tcp", 443, 443) if open_ingress else {}
    if not open_ingress:
        return a
    if backing is not None:
        backing_ingress = backing["data"].get("ingress", "INGRESS_TRAFFIC_ALL")
        a.step("backing_service_ingress", "allow" if backing_ingress == "INGRESS_TRAFFIC_ALL" else "block",
               service=service_ref, ingress=backing_ingress)
        if backing_ingress != "INGRESS_TRAFFIC_ALL":
            a.ports = {}
            return a
        if backing["data"].get("invokerIamDisabled") is True:
            a.step("backing_service_invoker", "allow", service=service_ref, invoker_iam_disabled=True)
            return a
    if disabled:
        a.step("invoker", "allow", invoker_iam_disabled=True)
        return a
    policy = data.get("iamPolicy")
    if isinstance(policy, dict) and policy.get("collection_status") not in (None, "collected"):
        policy = None
    public, conditional = _gcp_invoker(policy, roles)
    if backing is not None:
        backing_policy = backing["data"].get("iamPolicy")
        if isinstance(backing_policy, dict) and backing_policy.get("collection_status") not in (None, "collected"):
            backing_policy = None
        backing_public, backing_conditional = _gcp_invoker(backing_policy,
            {"roles/run.invoker", "roles/run.servicesInvoker"})
        if backing_public:
            public = list(dict.fromkeys((public or []) + backing_public))
        if backing_conditional:
            conditional = list(dict.fromkeys((conditional or []) + backing_conditional))
        if not public and backing_public is None:
            a.gap("invoker", "backing Cloud Run service IAM policy not collected", "run services.getIamPolicy")
            a.ports = None
            return a
    elif resource["type"] == "function" and isinstance(service_ref, str) and service_ref and not public:
        a.gap("invoker", "Cloud Functions v2 backing Cloud Run service not collected", "run services.list")
        a.ports = None
        return a
    if public is None:
        a.gap("invoker", "invoker IAM policy not collected", "getIamPolicy")
    elif public:
        a.step("invoker", "allow", public_members=public)
        if "allUsers" not in public:
            a.authenticated = True
    elif conditional:
        a.step("invoker", "unknown", conditional_public_members=conditional)
        a.gap("invoker", "public invoker grant has a request-dependent IAM condition")
        a.ports = None
    else:
        a.step("invoker", "block", reason="no allUsers/allAuthenticatedUsers invoker; IAM authentication required")
        a.ports = {}
    return a


def _gcp_sql(snapshot, inventory, resource):
    settings = resource["data"].get("settings") if isinstance(resource["data"].get("settings"), dict) else {}
    ip = settings.get("ipConfiguration") if isinstance(settings.get("ipConfiguration"), dict) else {}
    if ip.get("ipv4Enabled") is not True:
        return None
    a = Assessment(resource, "database")
    a.addresses = [x.get("ipAddress") for x in as_list(resource["data"].get("ipAddresses")) if isinstance(x, dict) and x.get("type") == "PRIMARY"]
    version = str(resource["data"].get("databaseVersion", ""))
    port = 5432 if "POSTGRES" in version else 1433 if "SQLSERVER" in version else 3306
    networks = [n.get("value") for n in as_list(ip.get("authorizedNetworks")) if isinstance(n, dict)]
    a.authenticated = True
    if any(_public_source(n) for n in networks):
        a.step("authorized_networks", "allow", authorized_networks=networks, require_ssl=ip.get("requireSsl"), ssl_mode=ip.get("sslMode"))
        a.ports = union(pset("tcp", port, port), pset("tcp", 3307, 3307))
    else:
        a.step("authorized_networks", "block", authorized_networks=networks, applies_to="direct connections")
        a.notes.append("Cloud SQL Auth Proxy and connectors can use the public IP without an authorized network, with IAM and database authentication")
        a.ports = pset("tcp", 3307, 3307)
    return a


def _gcp_alloydb(snapshot, inventory, resource):
    data = resource["data"]
    config = data.get("networkConfig")
    public_ip = isinstance(config, dict) and config.get("enablePublicIp") is True
    data_api = data.get("dataApiAccess") == "ENABLED"
    if not public_ip and not data_api:
        return None
    a = Assessment(resource, "database")
    a.authenticated = True
    if data_api:
        a.endpoint = "alloydb.googleapis.com"
        a.step("data_api", "allow", access="ENABLED", method="instances.executeSql",
               private_ip_supported=True)
        a.ports = pset("tcp", 443, 443)
    if not public_ip:
        if data.get("state") not in (None, "READY"):
            a.dormant = True
            a.notes.append(f"instance state {data.get('state')}")
        return a
    address = data.get("publicIpAddress")
    if isinstance(address, str) and _public_ip(address):
        a.addresses = [address]
    networks = [row.get("cidrRange") for row in as_list(config.get("authorizedExternalNetworks")) if isinstance(row, dict)]
    a.step("public_ip", "allow", enabled=True, observed_address=a.addresses,
           authorized_external_networks=networks)
    a.ports = union(a.ports or {}, pset("tcp", 5433, 5433))
    connectors_required = (data.get("clientConnectionConfig") or {}).get("requireConnectors") is True
    if any(_public_source(network) for network in networks) and not connectors_required:
        a.ports = union(a.ports, pset("tcp", 5432, 5432))
    else:
        a.notes.append("Direct connections are source restricted or connectors are required; AlloyDB Auth Proxy and connectors can use the public IP with IAM authentication")
    if data.get("state") not in (None, "READY"):
        a.dormant = True
        a.notes.append(f"instance state {data.get('state')}")
    return a


def _gcp_gke(snapshot, inventory, resource):
    from ..checks.exposure_endpoints import gke_control_plane
    from ..checks.facts import Unavailable
    data = resource["data"]
    a = Assessment(resource, "control_plane")
    a.authenticated = True
    try:
        status, evidence = gke_control_plane(data, {})
    except (Unavailable, ValueError, TypeError, AttributeError, KeyError):
        status, evidence = "UNKNOWN", {"reason": "GKE endpoint configuration is unavailable or malformed"}
    control = data.get("controlPlaneEndpointsConfig")
    control = control if isinstance(control, dict) else {}
    endpoints = control.get("ipEndpointsConfig")
    endpoints = endpoints if isinstance(endpoints, dict) else {}
    if status == "NOT_APPLICABLE":
        dns = control.get("dnsEndpointConfig")
        dns = dns if isinstance(dns, dict) else {}
        a.addresses = [dns["endpoint"]] if isinstance(dns.get("endpoint"), str) else []
        if dns.get("allowExternalTraffic") is False:
            a.step("dns_user_traffic", "block", google_managed_service_access="not_assessed")
            a.ports = {}
        else:
            a.ports = pset("tcp", 443, 443)
            a.explicit = "UNKNOWN"
            a.gap("dns_authorization", "IP endpoints are disabled. DNS endpoint IAM/VPC Service Controls need separate context; no IP exposure is inferred.")
        return a
    if status == "PASS" and evidence.get("private_endpoint"):
        return None
    if status == "PASS" and any(_public_source(value) for value in as_list(evidence.get("authorized_networks"))):
        status = "FAIL"
        evidence = {**evidence, "public_source_subset": True}
    address = endpoints.get("publicEndpoint") or data.get("endpoint")
    a.addresses = [address] if address else []
    if status == "PASS":
        a.step("source_ranges", "block", **evidence)
        a.ports = {}
    elif status == "FAIL":
        a.step("source_ranges", "allow", **evidence)
        a.ports = pset("tcp", 443, 443)
    else:
        a.ports = pset("tcp", 443, 443)
        a.explicit = "UNKNOWN"
        a.gap("source_ranges", evidence.get("reason", "Control-plane source range decision needs review"))
    return a


def _gcp_bucket(snapshot, inventory, resource):
    data = resource["data"]
    policy = data.get("iamPolicy")
    public = []
    conditional = []
    coverage = (data.get("_coverage") or {}).get("iamPolicy", {})
    policy_ok = (isinstance(policy, dict) and policy.get("collection_status") in (None, "collected")
                 and isinstance(coverage, dict) and coverage.get("status") in (None, "collected"))
    if policy_ok:
        for binding in as_list(policy.get("bindings")):
            if not isinstance(binding, dict):
                continue
            grants = [(binding.get("role"), m) for m in as_list(binding.get("members"))
                      if m in ("allUsers", "allAuthenticatedUsers")]
            (conditional if binding.get("condition") else public).extend(grants)
    # The collector attaches these only after complete native ACL reads and
    # verifies that uniform bucket-level access is disabled.
    acl = []
    if (data.get("iamConfiguration") or {}).get("uniformBucketLevelAccess", {}).get("enabled") is False:
        for field in ("bucketAccessControls", "objectAccessControls"):
            envelope = data.get(field)
            if not isinstance(envelope, dict) or envelope.get("status") != "collected" or envelope.get("all_pages") is not True:
                continue
            if field == "objectAccessControls" and (envelope.get("all_objects") is not True or envelope.get("all_versions") is not True):
                continue
            for row in as_list(envelope.get("items")):
                roles = ("READER", "OWNER", "WRITER") if field == "bucketAccessControls" else ("READER", "OWNER")
                if isinstance(row, dict) and row.get("entity") in ("allUsers", "allAuthenticatedUsers") and row.get("role") in roles:
                    acl.append({"source": field, "entity": row["entity"], "role": row["role"],
                                **({"object_ref": row["objectRef"]} if field == "objectAccessControls" and row.get("objectRef") else {})})
    effective_rows = [row for row in inventory.items("bucket_effective_iam")
                      if row.get("scope") == resource.get("scope") and row["data"].get("name") == data.get("name")]
    effective_public = (len(effective_rows) == 1 and effective_rows[0]["data"].get("resolutionComplete") is True
                        and effective_rows[0]["data"].get("publicAccess") is True)
    if not public and not acl and not conditional and not effective_public:
        return None
    a = Assessment(resource, "data_share")
    prevention = (data.get("iamConfiguration") or {}).get("publicAccessPrevention")
    if prevention == "inherited":
        scope = resource["scope"]
        matches = [row["data"] for row in inventory.items("org_policy_effective")
                   if row.get("scope") == scope and row["data"].get("name") ==
                   scope + "/policies/storage.publicAccessPrevention" and
                   row["data"].get("constraint") == "storage.publicAccessPrevention"]
        if inventory.state("org_policy_effective", scope) == "collected" and len(matches) == 1:
            rules = (matches[0].get("spec") or {}).get("rules", [])
            if (isinstance(rules, list) and all(isinstance(rule, dict) and
                    set(rule) == {"enforce"} and type(rule.get("enforce")) is bool for rule in rules)
                    and len({rule["enforce"] for rule in rules}) <= 1):
                prevention = "enforced" if rules and rules[0]["enforce"] else "not_enforced"
    if prevention == "enforced":
        a.step("public_access_prevention", "block", bindings=public, acl=acl, conditional=conditional,
               effective_public=effective_public)
        a.ports = {}
        return a
    a.step("policy", "allow" if public or acl or effective_public else "unknown", bindings=public, acl=acl,
           conditional=conditional, effective_public=effective_public, public_access_prevention=prevention)
    if (not public and not acl and not effective_public) or prevention == "inherited":
        a.explicit = "UNKNOWN"
        a.gap("policy", "conditional public grant or inherited public access prevention requires effective-policy evaluation")
    a.data_exposure = True
    a.addresses = [f"https://storage.googleapis.com/{data.get('name', native_id(resource))}"]
    return a


def _gcp_bigquery_dataset(snapshot, inventory, resource):
    """Legacy dataset ACLs can expose data without a separate IAM binding."""
    data = resource["data"]
    access = data.get("access")
    if not isinstance(access, list):
        return None
    public = []
    delegated = []
    for entry in access:
        if not isinstance(entry, dict):
            continue
        member = entry.get("iamMember") or entry.get("specialGroup")
        if member in ("allUsers", "allAuthenticatedUsers"):
            public.append({"member": member, "role": entry.get("role")})
        for kind in ("view", "routine", "dataset"):
            ref = entry.get(kind)
            if isinstance(ref, dict):
                delegated.append({"kind": kind, "reference": ref})
    if not public and not delegated:
        return None
    a = Assessment(resource, "data_share")
    source_project = resource["scope"].removeprefix("projects/")
    def destination_project(row):
        ref = row["reference"]
        if row["kind"] == "dataset" and isinstance(ref.get("dataset"), dict):
            ref = ref["dataset"]
        return ref.get("projectId") or ref.get("project_id")
    external_projects = sorted({project for row in delegated
                                if isinstance(project := destination_project(row), str)
                                and project and project != source_project})
    public_views = []
    for row in delegated:
        if row["kind"] != "view":
            continue
        ref = row["reference"]
        if destination_project(row) != source_project or not all(isinstance(ref.get(key), str) and ref[key]
                for key in ("datasetId", "tableId")):
            continue
        view_name = f"{resource['scope']}/datasets/{ref['datasetId']}/tables/{ref['tableId']}"
        view = inventory.get("bigquery_table", view_name)
        if view is None or view["data"].get("type") != "VIEW":
            continue
        dataset_name = f"{resource['scope']}/datasets/{ref['datasetId']}"
        target = inventory.get("bigquery_dataset", dataset_name)
        dataset_public = (target is not None and isinstance(target["data"].get("access"), list) and
            any(isinstance(entry, dict) and (entry.get("iamMember") or entry.get("specialGroup")) in
                ("allUsers", "allAuthenticatedUsers") and entry.get("role") in ("READER", "OWNER", "WRITER")
                for entry in target["data"]["access"]))
        policy = view["data"].get("iamPolicy")
        table_public = (isinstance(policy, dict) and policy.get("collection_status") in (None, "collected") and
            any(isinstance(binding, dict) and not binding.get("condition") and
                binding.get("role") in ("roles/bigquery.dataViewer", "roles/bigquery.dataOwner", "roles/bigquery.admin") and
                any(member in ("allUsers", "allAuthenticatedUsers") for member in as_list(binding.get("members")))
                for binding in as_list(policy.get("bindings"))))
        if dataset_public or table_public:
            public_views.append({"view": view_name, "dataset_public": bool(dataset_public),
                                 "table_public": bool(table_public)})
    a.external_ids = external_projects
    if public:
        a.data_exposure = True
        a.authenticated = not any(row["member"] == "allUsers" for row in public)
        a.step("dataset_acl", "allow", public=public, delegated=delegated)
    elif external_projects:
        # The dataset ACL itself grants an authorized resource in another
        # project access to source data. Its downstream readers are separate.
        a.data_exposure = True
        a.step("dataset_acl", "allow", delegated=delegated, external_projects=external_projects)
        a.notes.append("Destination readers and project ownership are not established by this grant")
    elif public_views:
        a.data_exposure = True
        a.step("authorized_view", "allow", public_views=public_views,
               semantics="Public query access to an authorized view; returned columns depend on view SQL")
    else:
        # An authorized view/routine/dataset receives source-data privileges,
        # but the destination's readers and project ownership need a join.
        a.explicit = "UNKNOWN"
        a.step("dataset_acl", "unknown", delegated=delegated)
        a.gap("policy", "authorized BigQuery resource can read this dataset; destination access and ownership are unresolved")
    return a


def _gcp_firebase_rules(snapshot, inventory, resource):
    data = resource["data"]
    a = Assessment(resource, "data_share")
    if resource["type"] == "firebase_database_rules":
        a.addresses = [data["databaseUrl"]] if isinstance(data.get("databaseUrl"), str) else []
        a.dormant = data.get("state") not in (None, "ACTIVE")
    if data.get("source_inspected") is not True:
        a.gap("inventory", "active Firebase ruleset source was not completely inspected")
        return a
    public = data.get("public_read") is True or data.get("public_write") is True
    authenticated = data.get("authenticated_read") is True
    conditional = data.get("conditional_read") is True or data.get("conditional_write") is True
    a.step("firebase_rules", "allow" if public or authenticated else "unknown" if conditional else "block",
           services=data.get("services"), ruleset=data.get("rulesetName"),
           public_read=data.get("public_read"), public_write=data.get("public_write"),
             authenticated_read=authenticated, conditional_read=data.get("conditional_read"),
             conditional_write=data.get("conditional_write"))
    if public:
        a.data_exposure = True
        if conditional:
            a.notes.append("Other conditional rules may expose additional paths")
    elif authenticated:
        a.authenticated = True
        a.explicit = "UNKNOWN"
        a.gap("authorization", "rules allow authenticated users, but public identity enrollment and downstream claim restrictions are not established")
    elif conditional:
        a.gap("policy", "request-dependent Firebase rule conditions need runtime path and authentication context")
    else:
        a.ports = {}
    return a


def _gcp_vpn_gateway(snapshot, inventory, resource):
    interfaces = [row for row in as_list(resource["data"].get("vpnInterfaces")) if isinstance(row, dict)]
    public = [ip for row in interfaces if not row.get("interconnectAttachment")
              for ip in (row.get("ipAddress"), row.get("ipv6Address"))
              if isinstance(ip, str) and _public_ip(ip)]
    if not public:
        return None
    a = Assessment(resource, "vpn_gateway")
    a.addresses = public
    a.ports = union(pset("udp", 500, 500), pset("udp", 4500, 4500))
    a.ports["esp"] = ((0, 0),)
    a.authenticated = True
    a.step("public_vpn_interfaces", "allow", addresses=public, protocols=["udp/500", "udp/4500", "esp"])
    a.notes.append("Only authenticated IPsec peers can establish a tunnel; VPC routes and firewall rules control traffic after decapsulation")
    return a


def _gcp_ftp(snapshot, inventory, resource):
    data = resource["data"]
    config = data.get("externalConfig")
    if not isinstance(config, dict):
        return None
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True  # SFTP user authentication is a separate layer.
    address = config.get("ipAddress")
    if isinstance(address, str) and _public_ip(address):
        a.addresses = [address]
    else:
        a.explicit = "UNKNOWN"
        a.gap("public_ip", "external SFTP server has no observed public address")
    ranges = config.get("allowedCidrBlocks")
    if not isinstance(ranges, list) or not ranges:
        a.explicit = "UNKNOWN"
        a.gap("source_ranges", "external SFTP source ranges are unavailable")
    elif any(_public_source(value) for value in ranges):
        a.step("source_ranges", "allow", allowed_cidrs=ranges)
        a.ports = pset("tcp", 22, 22)
    else:
        a.step("source_ranges", "block", allowed_cidrs=ranges)
        a.ports = {}
    return a


def _gcp_looker(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("publicIpEnabled") is not True:
        return None
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True
    address = data.get("ingressPublicIp")
    if isinstance(address, str) and _public_ip(address):
        a.addresses = [address]
    else:
        a.explicit = "UNKNOWN"
        a.gap("public_ip", "Looker public ingress is enabled but its address is unavailable")
    allowlist = data.get("ingressIpAllowlistConfig")
    if not isinstance(allowlist, dict) or allowlist.get("enabled") is False:
        a.step("ip_allowlist", "allow", enabled=False)
        a.ports = pset("tcp", 443, 443)
    elif allowlist.get("enabled") is True and isinstance(allowlist.get("allowlistRules"), list):
        ranges = [row.get("ipRange") for row in allowlist["allowlistRules"] if isinstance(row, dict)]
        open_to_internet = any(_public_source(value) for value in ranges)
        a.step("ip_allowlist", "allow" if open_to_internet else "block", ranges=ranges)
        a.ports = pset("tcp", 443, 443) if open_to_internet else {}
    else:
        a.explicit = "UNKNOWN"
        a.gap("ip_allowlist", "Looker ingress allowlist state is unavailable")
    return a


def _gcp_blockchain_node(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("privateServiceConnectEnabled") is True:
        return None
    info = data.get("connectionInfo") if isinstance(data.get("connectionInfo"), dict) else {}
    endpoints = info.get("endpointInfo") if isinstance(info.get("endpointInfo"), dict) else {}
    urls = [endpoints.get(field) for field in ("jsonRpcApiEndpoint", "websocketsApiEndpoint")]
    urls = [value for value in urls if isinstance(value, str) and value.startswith(("https://", "wss://"))]
    if not urls:
        return None
    a = Assessment(resource, "managed_endpoint")
    a.addresses = urls
    a.authenticated = True
    a.step("public_endpoint", "allow", private_service_connect=False, endpoints=urls)
    a.ports = pset("tcp", 443, 443)
    return a


def _gcp_data_fusion(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("privateInstance") is not False:
        return None
    endpoints = [data.get(field) for field in ("serviceEndpoint", "apiEndpoint")]
    endpoints = [value for value in endpoints if isinstance(value, str) and value.startswith("https://")]
    if not endpoints:
        return None
    a = Assessment(resource, "managed_endpoint")
    a.addresses = endpoints
    a.authenticated = True
    a.step("public_instance", "allow", private_instance=False)
    a.ports = pset("tcp", 443, 443)
    return a


def _gcp_vertex_index(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("publicEndpointEnabled") is not True:
        return None
    a = Assessment(resource, "managed_endpoint")
    domain = data.get("publicEndpointDomainName")
    if isinstance(domain, str) and domain:
        a.addresses = [domain]
        a.step("public_endpoint", "allow", enabled=True, domain=domain)
        a.ports = pset("tcp", 443, 443)
        a.authenticated = True
    else:
        a.explicit = "UNKNOWN"
        a.gap("public_endpoint", "Vertex AI public index endpoint is enabled but has no observed domain")
    return a


def _gcp_vertex_feature_store(snapshot, inventory, resource):
    data = resource["data"]
    endpoint = data.get("dedicatedServingEndpoint")
    if not isinstance(endpoint, dict) or not isinstance(endpoint.get("publicEndpointDomainName"), str):
        return None
    a = Assessment(resource, "managed_endpoint")
    a.addresses = [endpoint["publicEndpointDomainName"]]
    a.authenticated = True
    a.step("public_endpoint", "allow", domain=endpoint["publicEndpointDomainName"])
    a.ports = pset("tcp", 443, 443)
    return a


def _gcp_app_engine(snapshot, inventory, resource):
    data = resource["data"]
    hostname = data.get("defaultHostname")
    if not isinstance(hostname, str) or not hostname:
        return None
    a = Assessment(resource, "managed_endpoint")
    a.addresses = [hostname]
    a.authenticated = (data.get("iap") or {}).get("enabled") is True
    if data.get("servingStatus") in {"USER_DISABLED", "SYSTEM_DISABLED"}:
        a.step("serving_status", "block", status=data["servingStatus"])
        a.ports = {}
    else:
        a.step("default_hostname", "allow", hostname=hostname, iap_enabled=a.authenticated)
        a.ports = pset("tcp", 443, 443)
    return a


def _gcp_api_gateway(snapshot, inventory, resource):
    data = resource["data"]
    hostname = data.get("defaultHostname")
    if not isinstance(hostname, str) or not hostname:
        return None
    a = Assessment(resource, "managed_endpoint")
    a.addresses = [hostname]
    if data.get("state") in {"FAILED", "DELETING"}:
        a.step("gateway_state", "block", state=data["state"])
        a.ports = {}
    elif data.get("state") == "ACTIVE":
        a.step("gateway_hostname", "allow", hostname=hostname, api_config=data.get("apiConfig"))
        a.ports = pset("tcp", 443, 443)
        a.notes.append("API Config request authentication was not evaluated")
    else:
        a.explicit = "UNKNOWN"
        a.gap("gateway_state", "Gateway has a hostname but is not confirmed ACTIVE")
    return a


def _gcp_firebase_apphosting(snapshot, inventory, resource):
    data = resource["data"]
    uri = data.get("uri")
    if not isinstance(uri, str) or not uri.startswith("https://"):
        return None
    a = Assessment(resource, "managed_endpoint")
    a.addresses = [uri]
    if data.get("deleteTime"):
        a.step("backend_state", "block", deleted=True)
        a.ports = {}
    else:
        a.step("backend_uri", "allow", uri=uri)
        a.ports = pset("tcp", 443, 443)
    return a


def _gcp_media_cdn(snapshot, inventory, resource):
    data = resource["data"]
    addresses = [ip for field in ("ipv4Addresses", "ipv6Addresses") for ip in as_list(data.get(field))
                 if isinstance(ip, str) and _public_ip(ip)]
    if not addresses:
        return None
    a = Assessment(resource, "managed_endpoint")
    hosts = [host for rule in as_list((data.get("routing") or {}).get("hostRules")) if isinstance(rule, dict)
             for host in as_list(rule.get("hosts")) if isinstance(host, str)]
    a.addresses = addresses + hosts
    a.step("edge_addresses", "allow", addresses=addresses, hosts=hosts)
    a.ports = pset("tcp", 443, 443) if data.get("requireTls") is True else union(pset("tcp", 80, 80), pset("tcp", 443, 443))
    armor = data.get("edgeSecurityPolicy")
    if armor:
        decision = _gcp_armor_decision(inventory, armor)
        if decision == "block":
            a.step("cloud_armor", "block", policy=armor)
            a.ports = {}
        elif decision == "allow":
            a.step("cloud_armor", "allow", policy=armor)
        else:
            a.gap("cloud_armor", "Media CDN edge security policy cannot establish an unconditional public path",
                  "securityPolicies.get")
    return a


def _gcp_workstation(snapshot, inventory, resource):
    data = resource["data"]
    host = data.get("host")
    if not isinstance(host, str) or not host:
        return None
    cluster_ref = data.get("name", "").split("/workstationConfigs/", 1)[0]
    cluster = inventory.get("workstation_cluster", cluster_ref)
    a = Assessment(resource, "managed_endpoint")
    a.addresses = [host]
    a.authenticated = True
    if cluster is None:
        a.explicit = "UNKNOWN"
        a.gap("cluster", "Cloud Workstations cluster configuration was not collected", "workstationClusters.list")
    elif (cluster["data"].get("privateClusterConfig") or {}).get("enablePrivateEndpoint") is True:
        a.step("private_cluster", "block", cluster=cluster_ref)
        a.ports = {}
    elif data.get("state") == "STATE_RUNNING":
        a.step("public_gateway", "allow", cluster=cluster_ref, host=host)
        a.ports = pset("tcp", 443, 443)
    elif data.get("state") in {"STATE_STOPPED", "STATE_STOPPING", "STATE_DELETED"}:
        a.step("workstation_state", "block", state=data["state"])
        a.ports = {}
    else:
        a.explicit = "UNKNOWN"
        a.gap("workstation_state", "Workstation has a host but is not confirmed running")
    return a


def _gcp_beyondcorp_connection(snapshot, inventory, resource):
    data = resource["data"]
    gateway = data.get("gateway")
    if not isinstance(gateway, dict) or not gateway.get("uri"):
        return None
    a = Assessment(resource, "application_gateway")
    a.addresses = [gateway["uri"]]
    a.authenticated = True
    a.ports = pset("tcp", gateway.get("ingressPort") or 19443, gateway.get("ingressPort") or 19443)
    a.step("gateway", "allow", uri=gateway["uri"], ingress_port=gateway.get("ingressPort") or 19443,
           application_endpoint=data.get("applicationEndpoint"), private_service_connection=gateway.get("l7psc"))
    if data.get("state") != "CREATED":
        a.dormant = True
        a.notes.append(f"AppConnection state {data.get('state') or 'unknown'}")
    a.notes.append("BeyondCorp access policy and target application authorization are separate from gateway reachability")
    return a


def _gcp_contact_center(snapshot, inventory, resource):
    data = resource["data"]
    detail_status = (data.get("_coverage") or {}).get("network_detail", {}).get("status")
    if detail_status not in (None, "collected"):
        a = Assessment(resource, "application_gateway")
        a.gap("inventory", f"contact center detail {detail_status}; private ingress is unknown")
        return a
    ingress = as_list((data.get("privateAccess") or {}).get("ingressSettings"))
    private_agent = any(isinstance(row, dict) and row.get("name") == "AGENT" for row in ingress)
    a = Assessment(resource, "application_gateway")
    a.authenticated = True
    if private_agent:
        a.step("private_ingress", "block", component="AGENT", settings=ingress)
        a.ports = {}
    else:
        a.step("private_ingress", "allow", component="AGENT", settings=ingress,
               reason="no private agent ingress setting")
        a.ports = pset("tcp", 443, 443)
        a.notes.append("The agent portal uses application authentication; end-user contact channels are separate")
    if data.get("state") in ("DELETING", "DOWN", "STATE_DELETING", "STATE_DOWN"):
        a.dormant = True
        a.notes.append(f"contact center state {data.get('state')}")
    return a


def _gcp_oracle_goldengate(snapshot, inventory, resource):
    properties = resource["data"].get("properties")
    if not isinstance(properties, dict) or properties.get("isPublic") is not True:
        return None
    a = Assessment(resource, "application_gateway")
    a.authenticated = True
    addresses = [properties.get("publicIpAddress"), properties.get("deploymentUrl")]
    addresses.extend(row.get("ingressIpAddress") for row in as_list(properties.get("ingressIps")) if isinstance(row, dict))
    a.addresses = [value for value in addresses if isinstance(value, str) and value]
    a.ports = pset("tcp", 443, 443)
    a.step("public_deployment", "allow", is_public=True, addresses=a.addresses,
           network_security_groups=as_list(properties.get("nsgIds")))
    a.gap("firewall", "Google Cloud Oracle Database API exposes OCI NSG IDs but has no read endpoint for OCI NSG ingress or subnet security-list rules; effective ingress requires OCI-side data")
    if properties.get("lifecycleState") not in (None, "ACTIVE"):
        a.dormant = True
    return a


def _gcp_vertex_sandbox(snapshot, inventory, resource):
    data = resource["data"]
    connection = data.get("connectionInfo")
    if not isinstance(connection, dict):
        return None
    address = connection.get("loadBalancerIp")
    host = connection.get("loadBalancerHostname")
    if not (isinstance(address, str) and _public_ip(address)) and not host:
        return None
    a = Assessment(resource, "application_gateway")
    a.addresses = [value for value in (address, host) if isinstance(value, str) and value]
    a.explicit = "UNKNOWN"
    a.step("load_balancer", "unknown", addresses=a.addresses,
           private_service_attachment=connection.get("serviceAttachment"))
    a.gap("backend", "Vertex SandboxEnvironment.connectionInfo publishes the managed load balancer IP/hostname but no listener port or effective ingress controls; the public endpoint cannot be resolved to an open port from this API")
    if data.get("state") != "STATE_RUNNING":
        a.dormant = True
    return a


def _gcp_tpu_node(snapshot, inventory, resource):
    data = resource["data"]
    endpoints = [row for row in as_list(data.get("networkEndpoints")) if isinstance(row, dict)]
    addresses = [row.get("accessConfig", {}).get("externalIp") for row in endpoints
                 if isinstance(row.get("accessConfig"), dict)]
    addresses = [ip for ip in addresses if isinstance(ip, str) and _public_ip(ip)]
    if not addresses:
        return None
    a = Assessment(resource, "public_ip")
    a.addresses = addresses
    a.step("external_ip", "allow", addresses=addresses)
    configs = as_list(data.get("networkConfigs")) or ([data["networkConfig"]] if isinstance(data.get("networkConfig"), dict) else [])
    if len(configs) != 1 or not isinstance(configs[0], dict):
        a.explicit = "UNKNOWN"
        a.gap("firewall", "TPU external IP cannot be bound to exactly one VPC network configuration")
        return a
    network = configs[0].get("network") or "default"
    if not isinstance(network, str) or not network:
        a.explicit = "UNKNOWN"
        a.gap("firewall", "TPU network identity is unavailable")
        return a
    if "/networks/" not in network:
        matches = [row for row in inventory.items("network") if row["scope"] == resource["scope"] and
                   row["data"].get("name") == network and isinstance(row["data"].get("selfLink"), str)]
        if len(matches) != 1:
            a.explicit = "UNKNOWN"
            a.gap("firewall", "TPU network name cannot be bound to one collected VPC")
            return a
        network = matches[0]["data"]["selfLink"]
    tags = data.get("tags")
    account = data.get("serviceAccount")
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags) or not isinstance(account, dict):
        a.explicit = "UNKNOWN"
        a.gap("firewall", "TPU firewall target tags or service account metadata is incomplete")
        return a
    email = account.get("email")
    if email is not None and not isinstance(email, str):
        a.explicit = "UNKNOWN"
        a.gap("firewall", "TPU service account identity is malformed")
        return a
    if inventory.state("firewall") not in ("collected", "empty") or inventory.state("firewall_policy") not in ("collected", "empty"):
        a.explicit = "UNKNOWN"
        a.gap("firewall", "TPU VPC firewall or hierarchy inventory is incomplete")
        return a
    target = {**resource, "data": {"tags": {"items": tags},
                                   "serviceAccounts": [{"email": email}] if email else []}}
    allowed = _gcp_firewall(inventory, target, {"network": network}, a)
    if allowed is None or empty(allowed):
        a.explicit = "UNKNOWN"
        a.gap("firewall", "TPU public address has no proven allowed port under the collected VPC policy")
        return a
    a.ports = allowed
    a.step("tpu_endpoint", "allow", declared_ports=[row.get("port") for row in endpoints
           if isinstance(row.get("accessConfig"), dict) and row["accessConfig"].get("externalIp") in addresses],
           firewall_allowed=describe(allowed))
    if data.get("state") != "READY":
        a.dormant = True
    return a


def _gcp_vmware_address(snapshot, inventory, resource):
    data = resource["data"]
    ip = data.get("externalIp")
    if not isinstance(ip, str) or not _public_ip(ip):
        return None
    a = Assessment(resource, "public_ip")
    a.addresses = [ip]
    a.step("external_ip", "allow", address=ip, state=data.get("state"))
    if data.get("state") != "ACTIVE":
        a.explicit = "UNKNOWN"
        a.gap("external_ip", "VMware Engine external address is not confirmed ACTIVE")
        return a
    cloud_ref = data.get("name", "").split("/externalAddresses/", 1)[0]
    cloud = inventory.get("vmware_private_cloud", cloud_ref)
    network = ((cloud or {}).get("data", {}).get("networkConfig") or {}).get("vmwareEngineNetworkCanonical")
    if not isinstance(network, str):
        a.explicit = "UNKNOWN"
        a.gap("network_policy", "VMware Engine private cloud network is unavailable", "privateClouds.list")
        return a
    location = data.get("name", "").split("/locations/", 1)[-1].split("/", 1)[0]
    region = location.rsplit("-", 1)[0] if location.rsplit("-", 1)[-1] in "abcdef" else location
    policies = [row for row in inventory.items("vmware_network_policy")
                if row["data"].get("vmwareEngineNetworkCanonical") == network and
                row["data"].get("name", "").split("/locations/", 1)[-1].split("/", 1)[0] in {region, "global"}]
    if len(policies) != 1:
        a.explicit = "UNKNOWN"
        a.gap("network_policy", "Exactly one applicable VMware Engine network policy was not collected",
              "networkPolicies.list")
        return a
    policy = policies[0]["data"]
    external = policy.get("externalIp")
    if isinstance(external, dict) and external.get("enabled") is False:
        a.step("network_policy", "block", policy=policy.get("name"), external_ip_enabled=False)
        a.ports = {}
        return a
    if not isinstance(external, dict) or external.get("state") != "ACTIVE":
        a.explicit = "UNKNOWN"
        a.gap("network_policy", "VMware Engine external IP service is not confirmed ACTIVE")
        return a
    if external.get("enabled") is not True or inventory.state("vmware_external_access_rule").startswith("missing"):
        a.explicit = "UNKNOWN"
        a.gap("external_access_rule", "VMware Engine external access policy or rules are unavailable",
              "externalAccessRules.list")
        return a
    rules = [row["data"] for row in inventory.items("vmware_external_access_rule")
             if row["data"].get("name", "").startswith(policy["name"] + "/externalAccessRules/")]
    if any(row.get("state") != "ACTIVE" for row in rules):
        a.explicit = "UNKNOWN"
        a.gap("external_access_rule", "VMware Engine access rules are changing or have unknown state")
        return a
    try:
        rules.sort(key=lambda row: int(row["priority"]))
    except (KeyError, TypeError, ValueError):
        a.explicit = "UNKNOWN"
        a.gap("external_access_rule", "VMware Engine access rule priority is malformed")
        return a
    if len({row["priority"] for row in rules}) != len(rules):
        a.explicit = "UNKNOWN"
        a.gap("external_access_rule", "Equal-priority VMware Engine access rules have nondeterministic ordering")
        return a
    allowed, decided = {}, {}
    def public_source(entry):
        value = entry.get("ipAddressRange", entry.get("ipAddress"))
        network = _cidr(value)
        return _public_source(value)

    def destination(entry):
        if entry.get("externalAddress") == data.get("name") or entry.get("ipAddress") == ip:
            return True
        network = _cidr(entry.get("ipAddressRange"))
        return network is not None and ipaddress.ip_address(ip) in network

    for rule in rules:
        sources = as_list(rule.get("sourceIpRanges"))
        if sources and not any(isinstance(entry, dict) and public_source(entry) for entry in sources):
            continue
        destinations = as_list(rule.get("destinationIpRanges"))
        if destinations and not any(isinstance(entry, dict) and destination(entry) for entry in destinations):
            continue
        ports = {}
        for spec in as_list(rule.get("destinationPorts")) or [None]:
            ports = union(ports, _port_spec(rule.get("ipProtocol"), spec) or {})
        fresh = subtract(ports, decided)
        if rule.get("action") in {"ALLOW", "ACTION_UNSPECIFIED"}:
            allowed = union(allowed, fresh)
        elif rule.get("action") != "DENY":
            a.explicit = "UNKNOWN"
            a.gap("external_access_rule", "VMware Engine access rule action is unknown")
            return a
        decided = union(decided, ports)
    a.ports = allowed
    a.step("external_access_rule", "allow" if not empty(allowed) else "block",
           policy=policy.get("name"), allowed=describe(allowed))
    a.notes.append("Google Cloud VMware Engine API reports external access rules; NSX gateway and distributed firewall rules are not visible through that API")
    return a


def gcp_public_policy_findings(snapshot, resources):
    """Report public resource IAM declarations already present in the snapshot.

    These are permission grants, not proof that an unauthenticated request can
    read data. Conditional grants remain unresolved. A denied IAM read cannot
    justify a negative finding.
    """
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        # Buckets and invokable endpoints have path-specific evaluations above.
        if resource["type"] in {"bucket", "cloudrun_service", "function"} or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        coverage = data.get("_coverage", {}).get("iamPolicy") if isinstance(data.get("_coverage"), dict) else None
        policy = data if resource["type"] == "iam_policy" else data.get("iamPolicy")
        if (isinstance(coverage, dict) and coverage.get("status") not in (None, "collected")
                or not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected")):
            continue
        declarations = []
        for binding in as_list(policy.get("bindings")):
            if not isinstance(binding, dict):
                continue
            role = binding.get("role")
            for member in as_list(binding.get("members")):
                if member in ("allUsers", "allAuthenticatedUsers") and isinstance(role, str):
                    declarations.append({"role": role, "member": member,
                                         "condition": binding.get("condition")})
        if not declarations:
            continue
        unconditional = [row for row in declarations if not row["condition"]]
        status = "FAIL" if unconditional else "UNKNOWN"
        evidence = {
            "observed": ("The collected resource IAM policy grants a role to a public principal."
                         if unconditional else "The collected resource IAM policy has conditional public grants; effective access is unresolved."),
            "public_bindings": declarations, "risk_state": "observed" if unconditional else "unknown",
            "source": source(snapshot, resource, "bindings" if resource["type"] == "iam_policy" else "iamPolicy.bindings"),
            "semantics": "Declared resource IAM grants; conditions, denies and provider guardrails are not evaluated.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_public_iam",
                              "Public resource IAM grant", "high" if status == "FAIL" else "info", evidence, status=status))
    return output


# -------------------------------------------------------------------- Azure

def _props(resource):
    data = resource["data"]
    return data.get("properties") if isinstance(data.get("properties"), dict) else {}


def _nsg_allowed(nsg, address=None, groups=()):
    props = _props(nsg)
    rules = [r for r in as_list(props.get("securityRules")) + as_list(props.get("defaultSecurityRules")) if isinstance(r, dict)]
    if not any((r.get("properties") or {}).get("priority", 0) >= 65000 for r in rules):
        rules.append({"name": "DenyAllInBound(default)", "properties": {"priority": 65500, "direction": "Inbound", "access": "Deny",
                      "protocol": "*", "sourceAddressPrefix": "*", "destinationAddressPrefix": "*", "destinationPortRange": "*"}})
    ordered = sorted(rules, key=lambda r: int((r.get("properties") or {}).get("priority", 4096)))
    candidates = {ipaddress.ip_address(value) for value in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")}
    source_nets, unresolved_sources = {}, set()
    for rule in ordered:
        p = rule.get("properties") or {}
        sources = as_list(p.get("sourceAddressPrefixes")) + as_list(p.get("sourceAddressPrefix"))
        networks = [net for value in sources for net in _azure_restriction_sources(value)]
        source_nets[id(rule)] = networks
        if (p.get("direction", "Inbound") == "Inbound" and p.get("access") == "Allow"
                and not p.get("sourceApplicationSecurityGroups")
                and (not sources or any(not _azure_restriction_sources(value) and value != "VirtualNetwork"
                                        for value in sources))):
            unresolved_sources.add(id(rule))
        for net in networks:
            maximum = (1 << net.max_prefixlen) - 1
            low, high = int(net.network_address), int(net.broadcast_address)
            for number in (low - 1, low, low + 1, high - 1, high, high + 1):
                if 0 <= number <= maximum:
                    candidate = ipaddress.ip_address(number) if net.version == 4 else ipaddress.IPv6Address(number)
                    if candidate.is_global:
                        candidates.add(candidate)
    allowed, matched, seen = {}, [], set()
    for rule in ordered:
        if id(rule) in unresolved_sources:
            matched.append({"rule": rule.get("name"), "priority": (rule.get("properties") or {}).get("priority"),
                            "unresolved_public_source": True})
    for candidate in sorted(candidates, key=lambda ip: (ip.version, int(ip))):
        decided = {}
        for rule in ordered:
            p = rule.get("properties") or {}
            if p.get("direction", "Inbound") != "Inbound":
                continue
            if p.get("sourceApplicationSecurityGroups") or not any(candidate in net for net in source_nets[id(rule)]):
                continue
            destinations = as_list(p.get("destinationAddressPrefixes")) + as_list(p.get("destinationAddressPrefix"))
            asgs = {str(x.get("id", "")).lower() for x in as_list(p.get("destinationApplicationSecurityGroups")) if isinstance(x, dict)}
            if asgs:
                if not asgs & {str(g).lower() for g in groups}:
                    continue
            elif destinations and not any(d in ("*", "Any", "VirtualNetwork", "Internet") or _internet(d) or
                                          (address and _cidr(d) is not None and _cidr(address) is not None and
                                           _cidr(address).subnet_of(_cidr(d)) if _cidr(d) and _cidr(address) and
                                           _cidr(d).version == _cidr(address).version else False)
                                          for d in destinations):
                continue
            ports = {}
            for spec in as_list(p.get("destinationPortRanges")) + as_list(p.get("destinationPortRange")) or ["*"]:
                ports = union(ports, _port_spec(p.get("protocol", "*"), spec) or {})
            fresh = subtract(ports, decided)
            if empty(fresh):
                continue
            if p.get("access") == "Allow":
                allowed = union(allowed, fresh)
            key = (rule.get("name"), p.get("priority"), p.get("access"), tuple(describe(fresh)))
            if key not in seen:
                seen.add(key)
                matched.append({"rule": rule.get("name"), "priority": p.get("priority"), "access": p.get("access"), "ports": describe(fresh)})
            decided = union(decided, ports)
    return allowed, matched


def _azure_subnet(inventory, subnet_id):
    if not subnet_id:
        return None, "unknown subnet"
    subnet = inventory.get("subnet", subnet_id)
    if subnet is not None:
        return subnet, None
    vnet_id = subnet_id.lower().split("/subnets/")[0]
    vnet = inventory.get("vnet", vnet_id)
    if vnet is not None:
        for item in as_list(_props(vnet).get("subnets")):
            if isinstance(item, dict) and str(item.get("id", "")).lower() == subnet_id.lower():
                return {"data": item, "type": "subnet", "scope": vnet["scope"], "provider": "azure", "id": item.get("id")}, None
    return None, f"subnet {subnet_id} not collected"


def _azure_nsg_path(inventory, a, nic_nsg_id, subnet_id, ports, address=None, groups=(), sku=None, where=None):
    """Subnet NSG AND NIC NSG must both allow; a missing NSG level is open (Standard public IPs are closed with no NSG)."""
    levels, present = [], 0
    subnet, problem = _azure_subnet(inventory, subnet_id)
    subnet_nsg = None
    if subnet is None:
        a.gap("nsg", problem, "Microsoft.Network/virtualNetworks subnets")
    else:
        subnet_nsg = ((subnet["data"].get("properties") or {}).get("networkSecurityGroup") or {}).get("id")
    result = ports
    unresolved_source = known_block = False
    for level, nsg_id in (("subnet", subnet_nsg if subnet is not None else False), ("nic", nic_nsg_id)):
        if nsg_id is False:
            continue
        if not nsg_id:
            levels.append({"level": level, "nsg": None})
            continue
        nsg = inventory.get("nsg", nsg_id)
        if nsg is None:
            a.gap("nsg", f"{level} NSG {nsg_id} not collected", "Microsoft.Network/networkSecurityGroups")
            continue
        present += 1
        allowed, matched = _nsg_allowed(nsg, address, groups)
        unknown_here = any(row.get("unresolved_public_source") for row in matched)
        if unknown_here:
            a.gap("nsg", f"{level} NSG has an allow rule with an unresolved source service tag or prefix")
            unresolved_source = True
        result = intersect(result, allowed)
        if empty(result) and not unknown_here:
            known_block = True
        levels.append({"level": level, "nsg": native_id(nsg), "matched_rules": matched, "allowed": describe(allowed)})
    if present == 0 and not any(g["layer"] == "nsg" for g in a.unresolved) and str(sku or "").lower() == "standard":
        a.step("nsg", "block", reason="Standard SKU public IP without NSG is closed to inbound by default", levels=levels, at=where)
        return {}
    a.step("nsg", "allow" if not empty(result) else "unknown" if unresolved_source and not known_block else "block",
           levels=levels, allowed=describe(result), at=where)
    return result


def _azure_public_ips(inventory):
    output = {}
    for item in inventory.items("public_ip"):
        config = (_props(item).get("ipConfiguration") or {}).get("id")
        if config:
            output[str(config).lower()] = item
    return output


def _azure_nic(snapshot, inventory, resource, public_ips):
    props = _props(resource)
    a = Assessment(resource, "public_ip")
    total, found = {}, False
    for config in as_list(props.get("ipConfigurations")):
        if not isinstance(config, dict):
            continue
        cp = config.get("properties") or {}
        public_ref = (cp.get("publicIPAddress") or {}).get("id")
        if not public_ref:
            continue
        found = True
        public = inventory.get("public_ip", public_ref) or public_ips.get(str(config.get("id", "")).lower())
        sku = None
        if public is None:
            a.gap("public_ip", f"public IP {public_ref} not collected", "Microsoft.Network/publicIPAddresses")
        else:
            sku = (public["data"].get("sku") or {}).get("name")
            if _props(public).get("ipAddress"):
                a.addresses.append(_props(public)["ipAddress"])
            a.step("public_ip", "allow", public_ip=native_id(public), sku=sku, address=_props(public).get("ipAddress"))
        groups = [g.get("id") for g in as_list(cp.get("applicationSecurityGroups")) if isinstance(g, dict)]
        total = union(total, _azure_nsg_path(inventory, a, (props.get("networkSecurityGroup") or {}).get("id"), (cp.get("subnet") or {}).get("id"),
                                             dict(FULL), cp.get("privateIPAddress"), groups, sku, config.get("name")))
    if not found:
        return None
    a.ports = total
    if not empty(total):
        a.blocked_by = None
    vm = (props.get("virtualMachine") or {}).get("id")
    target = inventory.get("vm", vm) if vm else None
    if target is not None:
        a.resource = target
        a.notes.append(f"via network interface {native_id(resource)}")
    return a


def _azure_nic_config_index(inventory):
    """NIC IP configurations indexed by backend pool id and by configuration id.

    Built once per inventory instead of rescanning every NIC for each load
    balancer rule; positions keep the original inventory order.
    """
    index = inventory.network_cache.get("azure_nic_configs")
    if index is None:
        try:
            index = _azure_nic_config_entries(inventory)
        except (AttributeError, TypeError):
            # Malformed native records keep the original per-rule scans and errors.
            index = False
        inventory.network_cache["azure_nic_configs"] = index
    return index or None


def _azure_nic_config_entries(inventory):
    by_pool, by_config = {}, {}
    position = 0
    for nic in inventory.items("nic"):
        for config in as_list(_props(nic).get("ipConfigurations")):
            cp = (config or {}).get("properties") or {}
            refs = {str(x.get("id", "")).lower() for x in as_list(cp.get("loadBalancerBackendAddressPools")) + as_list(cp.get("applicationGatewayBackendAddressPools")) if isinstance(x, dict)}
            for ref in refs:
                by_pool.setdefault(ref, []).append((position, nic, config))
            by_config.setdefault(str((config or {}).get("id", "")).lower(), []).append((nic, config))
            position += 1
    return by_pool, by_config


def _azure_backend_nics(inventory, pool_ids):
    pools = {str(p).lower() for p in pool_ids}
    index = _azure_nic_config_index(inventory)
    if index is None:
        for nic in inventory.items("nic"):
            for config in as_list(_props(nic).get("ipConfigurations")):
                cp = (config or {}).get("properties") or {}
                refs = {str(x.get("id", "")).lower() for x in as_list(cp.get("loadBalancerBackendAddressPools")) + as_list(cp.get("applicationGatewayBackendAddressPools")) if isinstance(x, dict)}
                if refs & pools:
                    yield nic, config
        return
    by_pool = index[0]
    matched = {}
    for pool in pools:
        for position, nic, config in by_pool.get(pool, ()):
            matched[position] = (nic, config)
    for position in sorted(matched):
        yield matched[position]


def _azure_lb(snapshot, inventory, resource):
    props = _props(resource)
    fronts = {str(f.get("id", "")).lower(): f for f in as_list(props.get("frontendIPConfigurations")) if isinstance(f, dict)
              and ((f.get("properties") or {}).get("publicIPAddress") or {}).get("id")}
    if not fronts:
        return None
    a = Assessment(resource, "load_balancer")
    public_fronts = {}
    for front_id, front in fronts.items():
        public = inventory.get("public_ip", front["properties"]["publicIPAddress"]["id"])
        if public is not None and _props(public).get("ipAddress"):
            public_fronts[front_id] = _props(public)["ipAddress"]
    total = {}
    allowed_backend_nics = set()
    backend_routes = []
    rules = [("loadBalancingRules", r) for r in as_list(props.get("loadBalancingRules"))] + [("inboundNatRules", r) for r in as_list(props.get("inboundNatRules"))]
    for kind, rule in rules:
        rp = (rule or {}).get("properties") or {}
        front_id = str((rp.get("frontendIPConfiguration") or {}).get("id", "")).lower()
        if front_id not in fronts:
            continue
        protocol = rp.get("protocol", "Tcp")
        frontend, backend = rp.get("frontendPort"), rp.get("backendPort", rp.get("frontendPort"))
        if frontend == 0:  # HA ports
            frontend_ports, backend_ports = pset(protocol), pset(protocol)
        else:
            frontend_ports, backend_ports = pset(protocol, frontend, frontend), pset(protocol, backend, backend)
        pools = [x.get("id") for x in as_list(rp.get("backendAddressPools")) + as_list(rp.get("backendAddressPool")) if isinstance(x, dict)]
        nics = list(_azure_backend_nics(inventory, pools)) if pools else []
        if kind == "inboundNatRules":
            target = (rp.get("backendIPConfiguration") or {}).get("id")
            index = _azure_nic_config_index(inventory) if target else None
            nics = (list(index[1].get(str(target).lower(), ())) if index is not None else
                    [(n, c) for n in inventory.items("nic") for c in as_list(_props(n).get("ipConfigurations"))
                     if target and str((c or {}).get("id", "")).lower() == str(target).lower()])
        if not nics:
            a.gap("backend", f"{kind} {rule.get('name')}: backend NICs not resolved", "Microsoft.Network/networkInterfaces")
            continue
        for nic, config in nics:
            cp = config.get("properties") or {}
            allowed = _azure_nsg_path(inventory, a, (_props(nic).get("networkSecurityGroup") or {}).get("id"), (cp.get("subnet") or {}).get("id"),
                                      backend_ports, cp.get("privateIPAddress"), [g.get("id") for g in as_list(cp.get("applicationSecurityGroups")) if isinstance(g, dict)],
                                      "standard" if (resource["data"].get("sku") or {}).get("name", "").lower() == "standard" else "basic", rule.get("name"))
            if not empty(allowed):
                if front_id not in public_fronts:
                    a.gap("inventory", f"{kind} {rule.get('name')}: public frontend address not collected",
                          "Microsoft.Network/publicIPAddresses")
                    continue
                total = union(total, frontend_ports)
                allowed_backend_nics.add(nic["id"])
                address = public_fronts[front_id]
                backend_routes.append({"nic_id": nic["id"], "public_ip": address,
                    "frontend_ports": describe(frontend_ports), "backend_ports": describe(backend_ports),
                    "rule_name": rule.get("name")})
                if address not in a.addresses:
                    a.addresses.append(address)
    if allowed_backend_nics:
        a.step("backend", "allow", nic_ids=sorted(allowed_backend_nics), routes=backend_routes)
    a.step("listener", "allow" if not empty(total) else "block", frontend_ports=describe(total))
    a.ports = total if rules else {}
    if not empty(total):
        a.blocked_by = None
    return a


def _azure_appgw(snapshot, inventory, resource):
    props = _props(resource)
    fronts = {str(f.get("id", "")).lower() for f in as_list(props.get("frontendIPConfigurations")) if isinstance(f, dict)
              and ((f.get("properties") or {}).get("publicIPAddress") or {}).get("id")}
    if not fronts:
        return None
    a = Assessment(resource, "load_balancer")
    port_map = {str(p.get("id", "")).lower(): (p.get("properties") or {}).get("port") for p in as_list(props.get("frontendPorts")) if isinstance(p, dict)}
    ports = {}
    for listener in as_list(props.get("httpListeners")) + as_list(props.get("listeners")):
        lp = (listener or {}).get("properties") or {}
        if str((lp.get("frontendIPConfiguration") or {}).get("id", "")).lower() in fronts:
            port = port_map.get(str((lp.get("frontendPort") or {}).get("id", "")).lower())
            if isinstance(port, int):
                ports = union(ports, pset("tcp", port, port))
    a.step("listener", "allow" if not empty(ports) else "block", listener_ports=describe(ports))
    subnet = next((((c.get("properties") or {}).get("subnet") or {}).get("id") for c in as_list(props.get("gatewayIPConfigurations")) if isinstance(c, dict)), None)
    a.ports = _azure_nsg_path(inventory, a, None, subnet, ports, sku="basic", where="gateway subnet")
    waf = props.get("webApplicationFirewallConfiguration") or props.get("firewallPolicy")
    a.notes.append("WAF configured" if waf else "no WAF configuration on the gateway")
    return a


def _azure_restriction_sources(value):
    if value in ("Any", "*", "Internet"):
        return [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")]
    network = _cidr(value)
    return [network] if network is not None else []


def _azure_public_remainder(sources, prior):
    """Whether a first-match App Service rule still reaches any global IP."""
    for source_net in sources:
        remaining = [source_net]
        for earlier in prior:
            next_remaining = []
            for current in remaining:
                if earlier.version != current.version or not current.overlaps(earlier):
                    next_remaining.append(current)
                elif current.subnet_of(earlier):
                    continue
                elif earlier.subnet_of(current):
                    next_remaining.extend(current.address_exclude(earlier))
            remaining = next_remaining
            if not remaining:
                break
        if any(net.prefixlen == 0 or _public_ip(net.network_address) or
               _public_ip(net.broadcast_address) for net in remaining):
            return True
    return False


def _azure_app_service(snapshot, inventory, resource, configs):
    props = _props(resource)
    a = Assessment(resource, "web_app")
    a.addresses = [h for h in as_list(props.get("defaultHostName")) if h]
    if str(props.get("publicNetworkAccess", "")).lower() == "disabled":
        a.step("public_network_access", "block", public_network_access="Disabled")
        a.ports = {}
        return a
    if props.get("publicNetworkAccess") is None and as_list(props.get("privateEndpointConnections")):
        a.gap("inventory", "publicNetworkAccess is unset while private endpoint connections are present; public default is unresolved")
    ports = pset("tcp", 443, 443) if props.get("httpsOnly") else union(pset("tcp", 80, 80), pset("tcp", 443, 443))
    a.step("public_network_access", "allow", public_network_access=props.get("publicNetworkAccess", "default(Enabled)"))
    config = configs.get(str(resource["data"].get("id", "")).lower())
    if config is None:
        a.gap("access_restrictions", "site config (ipSecurityRestrictions) not collected", "Microsoft.Web/sites/config/web")
        a.ports = ports
        return a
    cp = _props(config)
    restrictions = [r for r in as_list(cp.get("ipSecurityRestrictions")) if isinstance(r, dict)]
    default = cp.get("ipSecurityRestrictionsDefaultAction") or ("Deny" if restrictions and not any(r.get("ipAddress") == "Any" for r in restrictions) else "Allow")
    prior, open_rules, unsupported = [], [], []
    for restriction in sorted(restrictions, key=lambda r: int(r.get("priority", 65000))):
        sources = _azure_restriction_sources(restriction.get("ipAddress"))
        if not sources:
            unsupported.append(restriction.get("name"))
            continue
        if restriction.get("action", "Allow") == "Allow" and _azure_public_remainder(sources, prior):
            open_rules.append(restriction.get("name"))
        prior.extend(sources)
    reachable = bool(open_rules) or (default == "Allow" and _azure_public_remainder(
        _azure_restriction_sources("Any"), prior))
    if unsupported:
        a.gap("access_restrictions", "App Service source rule uses an unresolved service tag or VNet source")
    a.step("access_restrictions", "allow" if reachable else "unknown" if unsupported else "block",
           restriction_count=len(restrictions), default_action=default, open_rules=open_rules)
    a.ports = ports if reachable else {}
    a.notes.append("App Service authentication (Easy Auth) settings are not collected")
    return a


def _azure_aks(snapshot, inventory, resource):
    from ..checks.exposure_endpoints import aks_api_server
    from ..checks.facts import Unavailable
    a = Assessment(resource, "control_plane")
    a.authenticated = True
    a.addresses = [_props(resource).get("fqdn")] if _props(resource).get("fqdn") else []
    try:
        status, evidence = aks_api_server(resource["data"], {})
    except (Unavailable, ValueError, TypeError, AttributeError, KeyError):
        status, evidence = "UNKNOWN", {"reason": "AKS endpoint configuration is unavailable or malformed"}
    if status == "PASS" and evidence.get("private_cluster"):
        return None
    if status == "PASS":
        a.step("source_ranges", "block", **evidence)
        a.ports = {}
    elif status == "FAIL":
        a.step("source_ranges", "allow", **evidence)
        a.ports = pset("tcp", 443, 443)
    else:
        a.ports = pset("tcp", 443, 443)
        a.explicit = "UNKNOWN"
        a.gap("source_ranges", evidence.get("reason", "Control-plane source range decision needs review"))
    return a


def _azure_storage(snapshot, inventory, resource):
    props = _props(resource)
    a = Assessment(resource, "data_share")
    if str(props.get("publicNetworkAccess", "")).lower() == "disabled":
        return None
    acls = props.get("networkAcls") or {}
    if acls.get("defaultAction", "Allow") != "Allow":
        a.step("network_rules", "block", default_action=acls.get("defaultAction"), ip_rules=len(as_list(acls.get("ipRules"))))
        a.ports = {}
        return a
    a.addresses = sorted(v for v in (props.get("primaryEndpoints") or {}).values() if isinstance(v, str))[:4]
    a.step("network_rules", "allow", default_action="Allow")
    a.ports = pset("tcp", 443, 443) if props.get("supportsHttpsTrafficOnly", True) else union(pset("tcp", 80, 80), pset("tcp", 443, 443))
    if props.get("allowBlobPublicAccess") is True:
        a.step("anonymous_access", "allow", allow_blob_public_access=True)
        a.notes.append("anonymous blob access allowed at account level; container access levels decide actual anonymous reads")
    else:
        a.authenticated = True
        a.step("anonymous_access", "authenticated_only", allow_blob_public_access=props.get("allowBlobPublicAccess"),
               shared_key_access=props.get("allowSharedKeyAccess"))
    return a


def _azure_storage_container(snapshot, inventory, resource):
    """An anonymous container requires both its own ACL and account gates."""
    level = _props(resource).get("publicAccess")
    if level not in ("Blob", "Container"):
        return None
    a = Assessment(resource, "data_share")
    a.authenticated = False
    parent_id = resource["data"].get("parent_id") or str(resource["data"].get("id", "")).split("/blobServices/")[0]
    account = inventory.get("storage_account", parent_id)
    if account is None:
        a.gap("inventory", "parent storage account is not collected", "Microsoft.Storage/storageAccounts")
        return a
    props = _props(account)
    a.step("container_acl", "allow", public_access=level)
    if props.get("allowBlobPublicAccess") is False or str(props.get("publicNetworkAccess", "")).lower() == "disabled":
        a.step("account_gate", "block", allow_blob_public_access=props.get("allowBlobPublicAccess"),
               public_network_access=props.get("publicNetworkAccess"))
        a.ports = {}
        return a
    if props.get("allowBlobPublicAccess") is not True:
        a.gap("inventory", "account allowBlobPublicAccess setting is unavailable")
    if props.get("publicNetworkAccess") is None:
        a.gap("inventory", "account publicNetworkAccess setting is unavailable")
    acls = props.get("networkAcls")
    if not isinstance(acls, dict) or acls.get("defaultAction") not in ("Allow", "Deny"):
        a.gap("firewall", "account network ACL default action is unavailable")
    elif acls["defaultAction"] == "Deny":
        a.step("firewall", "block", default_action="Deny")
        a.ports = {}
        return a
    else:
        a.step("firewall", "allow", default_action="Allow")
    a.addresses = [v for v in (props.get("primaryEndpoints") or {}).values() if isinstance(v, str) and "blob" in v][:1]
    if not a.addresses:
        a.gap("inventory", "public blob endpoint is not collected")
    a.data_exposure = True
    a.ports = pset("tcp", 443, 443)
    return a


def _azure_sql(snapshot, inventory, resource, rules):
    props = _props(resource)
    if str(props.get("publicNetworkAccess", "")).lower() == "disabled":
        return None
    a = Assessment(resource, "database")
    a.addresses = [props.get("fullyQualifiedDomainName")] if props.get("fullyQualifiedDomainName") else []
    rid = str(resource["data"].get("id", "")).lower()
    state = inventory.state("sql_firewall_rule", resource["data"].get("id"))
    if state.startswith("missing") and rid not in rules:
        a.gap("firewall", f"SQL firewall rules {state}", "Microsoft.Sql/servers/firewallRules")
        return a
    open_rules, azure = [], False
    for rule in rules.get(rid, []):
        rp = _props(rule)
        start, end = rp.get("startIpAddress"), rp.get("endIpAddress")
        if start == "0.0.0.0" and end == "0.0.0.0":
            azure = True
        else:
            try:
                first, last = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
            except (ipaddress.AddressValueError, TypeError):
                a.gap("firewall", "SQL firewall rule has an invalid IP range")
                continue
            if first > last:
                a.gap("firewall", "SQL firewall rule start exceeds end")
                continue
            ranges = list(ipaddress.summarize_address_range(first, last))
            if any(network.prefixlen == 0 or _public_ip(network.network_address) or
                   _public_ip(network.broadcast_address) for network in ranges):
                open_rules.append({"rule": rule["data"].get("name"), "start_ip": start, "end_ip": end})
    if azure:
        a.notes.append("'Allow Azure services' rule (0.0.0.0-0.0.0.0) admits any Azure tenant's resources")
    a.step("firewall", "allow" if open_rules else "block", open_rules=open_rules)
    a.ports = pset("tcp", 1433, 1433) if open_rules else {}
    if open_rules and not a.addresses:
        a.gap("inventory", "SQL public endpoint FQDN is not collected")
    return a


def _azure_container_group(snapshot, inventory, resource):
    """Container Instances expose only declared ports on a public IP group."""
    props = _props(resource)
    ip = props.get("ipAddress") or {}
    if str(ip.get("type", "")).lower() != "public":
        return None
    a = Assessment(resource, "container")
    address = ip.get("ip") or props.get("fqdn")
    if address:
        a.addresses.append(address)
    ports = {}
    for port in as_list(ip.get("ports")):
        if not isinstance(port, dict):
            continue
        number = port.get("port")
        if isinstance(number, int) and 1 <= number <= 65535:
            ports = union(ports, pset(port.get("protocol", "tcp"), number, number) or {})
    if not ports:
        a.gap("listener", "public Container Instance has no collected valid port declaration")
    a.step("public_ip", "allow", ip_type="Public", address=address)
    a.step("listener", "allow" if ports else "unknown", ports=describe(ports))
    a.ports = ports
    if not address:
        a.gap("inventory", "public Container Instance address is not collected")
    return a


def _azure_container_app(snapshot, inventory, resource):
    props = _props(resource)
    ingress = (props.get("configuration") or {}).get("ingress") or {}
    if ingress.get("external") is not True:
        return None
    a = Assessment(resource, "container")
    env_id = props.get("environmentId") or props.get("managedEnvironmentId")
    environment = inventory.get("container_app_environment", env_id)
    if environment is None:
        a.gap("inventory", "Container Apps environment is not collected", "Microsoft.App/managedEnvironments")
    else:
        ep = _props(environment)
        if (str(ep.get("publicNetworkAccess", "")).lower() == "disabled" or
                (ep.get("vnetConfiguration") or {}).get("internal") is True):
            a.step("environment", "block", public_network_access=ep.get("publicNetworkAccess"),
                   internal=(ep.get("vnetConfiguration") or {}).get("internal"))
            a.ports = {}
            return a
        if str(ep.get("publicNetworkAccess", "")).lower() != "enabled":
            a.gap("inventory", "Container Apps environment publicNetworkAccess is not explicit")
        a.step("environment", "allow", public_network_access=ep.get("publicNetworkAccess"))
    transport = str(ingress.get("transport") or "auto").lower()
    if transport == "tcp":
        port = ingress.get("exposedPort")
        if isinstance(port, int) and 1 <= port <= 65535:
            a.ports = pset("tcp", port, port)
        else:
            a.gap("listener", "Container App TCP exposedPort is unavailable")
    elif transport in ("auto", "http", "http2"):
        a.ports = pset("tcp", 443, 443)
        if ingress.get("allowInsecure") is True:
            a.ports = union(a.ports, pset("tcp", 80, 80))
    else:
        a.gap("listener", "Container App ingress transport is unrecognized")
    for mapping in as_list(ingress.get("additionalPortMappings")):
        if isinstance(mapping, dict) and mapping.get("external") is True:
            port = mapping.get("exposedPort") or mapping.get("targetPort")
            if isinstance(port, int) and 1 <= port <= 65535:
                a.ports = union(a.ports or {}, pset("tcp", port, port))
            else:
                a.gap("listener", "Container App external additional port is unavailable")
    rules = as_list(ingress.get("ipSecurityRestrictions"))
    if rules:
        actions = {r.get("action") for r in rules if isinstance(r, dict)}
        networks = [_cidr(r.get("ipAddressRange")) for r in rules if isinstance(r, dict)]
        if len(actions) != 1 or None in networks or len(networks) != len(rules):
            a.gap("access_restrictions", "Container App IP restriction rules are malformed or mixed")
        elif actions == {"Allow"}:
            if not _azure_public_remainder(networks, []):
                a.step("access_restrictions", "block", action="Allow", rule_count=len(rules))
                a.ports = {}
                return a
            a.step("access_restrictions", "allow", action="Allow", rule_count=len(rules))
        elif actions == {"Deny"}:
            if not _azure_public_remainder(_azure_restriction_sources("Any"), networks):
                a.step("access_restrictions", "block", action="Deny", rule_count=len(rules))
                a.ports = {}
                return a
            a.step("access_restrictions", "allow", action="Deny", rule_count=len(rules))
        else:
            a.gap("access_restrictions", "Container App IP restriction action is unrecognized")
    else:
        a.step("access_restrictions", "allow", rule_count=0)
    if ingress.get("clientCertificateMode") == "Require":
        a.authenticated = True
    fqdn = ingress.get("fqdn")
    if isinstance(fqdn, str) and fqdn:
        a.addresses.append(fqdn)
    else:
        a.gap("inventory", "Container App public ingress FQDN is not collected")
    if props.get("provisioningState") not in (None, "Succeeded"):
        a.gap("inventory", "Container App provisioning is not confirmed successful")
    a.step("listener", "allow" if a.ports else "unknown", transport=transport, ports=describe(a.ports or {}))
    return a


def _azure_firewall(snapshot, inventory, resource):
    """Classic Firewall DNAT frontends; backend reachability remains explicit."""
    props = _props(resource)
    frontends = []
    for config in as_list(props.get("ipConfigurations")):
        if not isinstance(config, dict):
            continue
        public_id = ((config.get("properties") or {}).get("publicIPAddress") or {}).get("id")
        public = inventory.get("public_ip", public_id)
        address = _props(public).get("ipAddress") if public is not None else None
        if address and _public_ip(address):
            frontends.append(address)
    if not frontends and not as_list(props.get("natRuleCollections")) and not props.get("firewallPolicy"):
        return None
    a = Assessment(resource, "firewall_dnat")
    a.addresses = frontends
    collections = list(as_list(props.get("natRuleCollections")))
    if props.get("firewallPolicy"):
        policy_id = (props.get("firewallPolicy") or {}).get("id")
        policy = inventory.get("firewall_policy", policy_id)
        if policy is None:
            a.gap("policy", "referenced Firewall Policy is not collected", "Microsoft.Network/firewallPolicies")
        else:
            policy_data = policy["data"]
            coverage = ((policy_data.get("_coverage") or {}).get("ruleCollectionGroups") or {}).get("status")
            if coverage not in ("collected", "empty"):
                a.gap("policy", "Firewall Policy rule collection group pages are incomplete",
                      "Microsoft.Network/firewallPolicies/ruleCollectionGroups")
            else:
                for group in as_list(policy_data.get("ruleCollectionGroups")):
                    provenance = (group or {}).get("_provenance") or {}
                    if (provenance.get("representation") != "full" or
                            provenance.get("source_operation") != "get_rule_collection_group"):
                        a.gap("policy", "Firewall Policy group lacks full GET provenance")
                        continue
                    for collection in as_list(((group or {}).get("properties") or {}).get("ruleCollections")):
                        if ((collection or {}).get("ruleCollectionType") == "FirewallPolicyNatRuleCollection" and
                                str((((collection or {}).get("action") or {}).get("type", "")).lower()) == "dnat"):
                            collections.append(collection)
            if ((policy_data.get("properties") or {}).get("basePolicy") or {}).get("id"):
                a.gap("policy", "Firewall Policy base-policy inheritance is not resolved")
    ports, matched = {}, []
    for collection in collections:
        cp = (collection or {}).get("properties") or collection or {}
        if str((cp.get("action") or {}).get("type", "")).lower() != "dnat":
            continue
        for rule in as_list(cp.get("rules")):
            if not isinstance(rule, dict):
                continue
            sources = [_cidr(value) for value in as_list(rule.get("sourceAddresses"))]
            if rule.get("sourceIpGroups"):
                a.gap("policy", "DNAT source IP group membership is not resolved")
            if None in sources:
                a.gap("policy", "DNAT source address syntax is not resolved")
            if not sources or None in sources or not _azure_public_remainder(sources, []):
                continue
            destinations = [_cidr(value) for value in as_list(rule.get("destinationAddresses"))]
            if None in destinations:
                a.gap("policy", "DNAT destination address syntax is not resolved")
            if not frontends or not any(net and ipaddress.ip_address(front) in net
                                        for net in destinations for front in frontends):
                continue
            exposed = {}
            for protocol in as_list(rule.get("protocols")) + as_list(rule.get("ipProtocols")):
                for spec in as_list(rule.get("destinationPorts")):
                    exposed = union(exposed, _port_spec(protocol, spec) or {})
            if exposed:
                ports = union(ports, exposed)
                matched.append({"collection": collection.get("name"), "rule": rule.get("name"),
                                "frontend_ports": describe(exposed), "translated_address": rule.get("translatedAddress"),
                                "translated_port": rule.get("translatedPort")})
    if matched:
        a.step("dnat", "allow", rules=matched)
        a.gap("backend", "translated backend route and effective NSG are not resolved")
    elif frontends and not a.unresolved:
        a.step("dnat", "block", reason="no collected public-source classic DNAT rule")
    else:
        a.gap("inventory", "Firewall public frontend or policy DNAT rule inventory is unavailable")
    a.ports = ports
    return a


_AZURE_MANAGED_ENDPOINTS = {
    "vault": (443, "networkAcls"),
    "managed_hsm": (443, "networkAcls"),
    "cosmos_account": (443, "ipRules"),
    "container_registry": (443, "networkRuleSet"),
    "cognitive_account": (443, "networkAcls"),
    "search_service": (443, "networkRuleSet"),
    "app_configuration": (443, "networkRuleSet"),
    "servicebus_namespace": (443, "networkRuleSet"),
    "eventhub_namespace": (443, "networkRuleSet"),
    "mysql_flexible_server": (3306, "firewallRules"),
    "postgresql_flexible_server": (5432, "firewallRules"),
}


def _azure_managed_endpoint(snapshot, inventory, resource):
    """Surface explicit public endpoint settings without inventing firewall joins."""
    props = _props(resource)
    kind = resource["type"]
    port, rules_name = _AZURE_MANAGED_ENDPOINTS[kind]
    a = Assessment(resource, "database" if port != 443 else "managed_endpoint")
    a.authenticated = True
    endpoint = next((props.get(field) for field in ("vaultUri", "hsmUri", "loginServer", "endpoint", "documentEndpoint", "fullyQualifiedDomainName")
                     if isinstance(props.get(field), str) and props.get(field)), None)
    if endpoint:
        a.addresses.append(endpoint)
    public = props.get("publicNetworkAccess")
    if isinstance(public, str) and public.lower() == "disabled":
        a.step("public_network_access", "block", public_network_access=public)
        a.ports = {}
        return a
    if not isinstance(public, str) or public.lower() != "enabled":
        a.gap("inventory", "publicNetworkAccess is not explicitly collected as Enabled or Disabled")
        return a
    a.step("public_network_access", "allow", public_network_access=public)
    # A private endpoint does not close an explicitly enabled public endpoint.
    rules = props.get(rules_name)
    if isinstance(rules, dict) and rules_name != "firewallRules":
        action = rules.get("defaultAction")
        if action == "Deny":
            if as_list(rules.get("ipRules")) or as_list(rules.get("virtualNetworkRules")):
                a.gap("firewall", f"{rules_name} allow rules require effective source evaluation")
                a.ports = pset("tcp", port, port)
                return a
            a.step("firewall", "block", default_action=action)
            a.ports = {}
            return a
        if action == "Allow":
            a.step("firewall", "allow", default_action=action)
            a.ports = pset("tcp", port, port)
            if not endpoint:
                a.gap("inventory", "managed public endpoint address is not collected")
            return a
    a.gap("firewall", f"{rules_name} public ingress rules are not resolved", f"{kind} {rules_name}")
    a.ports = pset("tcp", port, port)
    return a


def _azure_public_edge(snapshot, inventory, resource):
    """Assess the public listener from the collector's bounded route projection."""
    data = resource["data"]
    a = Assessment(resource, "public_edge")
    coverage = (data.get("_coverage") or {}).get("effectiveRoutes") or {}
    if coverage.get("status") not in ("collected", "empty"):
        a.gap("inventory", "effective Front Door/CDN routes are not resolved")
        return a
    routes = data.get("effectiveRoutes")
    if not isinstance(routes, list):
        a.gap("inventory", "effective Front Door/CDN routes are malformed")
        return a
    enabled = [r for r in routes if isinstance(r, dict) and r.get("enabledState") == "Enabled"]
    if not enabled:
        a.step("listener", "block", reason="no enabled effective route")
        a.ports = {}
        return a
    a.step("listener", "allow", route_ids=[r.get("id") for r in enabled])
    endpoints = data.get("endpoints") or []
    domains = data.get("domains") or []
    hosts = [entry.get("properties", {}).get("hostName") for entry in endpoints + domains
             if isinstance(entry, dict) and isinstance(entry.get("properties"), dict)]
    a.addresses = sorted({host for host in hosts if isinstance(host, str) and host})
    if not a.addresses:
        a.gap("inventory", "public edge hostname was not collected")
    ports = {}
    for route in enabled:
        paths = route.get("paths")
        if not isinstance(paths, list) or not paths:
            a.gap("listener", "effective edge protocol paths are unavailable")
            continue
        for path in paths:
            protocols = path.get("acceptedProtocols") if isinstance(path, dict) else None
            if not isinstance(protocols, list) or any(p not in ("Http", "Https") for p in protocols):
                a.gap("listener", "edge listener protocols are unresolved")
                continue
            for protocol in protocols:
                port = 80 if protocol == "Http" else 443
                ports = union(ports, pset("tcp", port, port))
            if path.get("action") == "Forward":
                a.gap("backend", "origin health and effective backend access are not observed")
            elif path.get("action") != "Redirect":
                a.gap("listener", "edge route action is unresolved")
    a.ports = ports
    if data.get("sku", {}).get("name") in ("Standard_AzureFrontDoor", "Premium_AzureFrontDoor"):
        policies = data.get("securityPolicies")
        if policies:
            a.gap("policy", "edge security policy may filter the listener")
    if (data.get("properties") or {}).get("webApplicationFirewallPolicyLink"):
        a.gap("policy", "classic Front Door WAF policy may filter the listener")
    return a


def _azure_api_management(snapshot, inventory, resource):
    """Assess the managed gateway listener, independently of API authorization."""
    props = resource["data"].get("properties") or {}
    a = Assessment(resource, "api_gateway")
    access = props.get("publicNetworkAccess")
    network = props.get("virtualNetworkType")
    if access == "Disabled":
        a.step("public_network_access", "block", value=access)
        a.ports = {}
        return a
    if network == "Internal":
        a.step("network", "block", virtual_network_type=network)
        a.ports = {}
        return a
    if props.get("disableGateway") is True:
        a.step("listener", "block", reason="managed gateway disabled")
        a.ports = {}
        return a
    if access not in (None, "Enabled") or network not in (None, "None", "External"):
        a.gap("inventory", "API Management public access or virtual network mode is unresolved")
        return a
    if props.get("disableGateway") is not False:
        a.gap("listener", "managed gateway enable state was not collected")
    endpoint = props.get("gatewayUrl")
    if isinstance(endpoint, str) and endpoint.startswith("https://"):
        a.addresses.append(endpoint)
    else:
        a.gap("inventory", "API Management gateway URL was not collected")
    a.step("public_network_access", "allow", value=access or "Enabled (service default)",
           virtual_network_type=network or "None (service default)")
    if network == "External":
        a.gap("nsg", "external VNet gateway subnet NSG and route path are not resolved")
    a.ports = pset("tcp", 443, 443)
    a.notes.append("Gateway listener exposure does not establish anonymous API access or a healthy backend")
    return a


def _azure_redis(snapshot, inventory, resource):
    props = resource["data"].get("properties") or {}
    a = Assessment(resource, "database")
    access = props.get("publicNetworkAccess")
    if access == "Disabled":
        a.step("public_network_access", "block", value=access)
        a.ports = {}
        return a
    if access != "Enabled":
        a.gap("inventory", "Redis public network access state is not explicit")
        return a
    if props.get("subnetId"):
        a.gap("nsg", "VNet-injected Redis subnet path is not resolved")
    hostname = props.get("hostName")
    if isinstance(hostname, str) and hostname:
        a.addresses.append(hostname)
    else:
        a.gap("inventory", "Redis public hostname is not observed")
    ports = {}
    ssl_port = props.get("sslPort")
    if type(ssl_port) is int and 1 <= ssl_port <= 65535:
        ports = pset("tcp", ssl_port, ssl_port)
    else:
        a.gap("listener", "Redis TLS listener port is not observed")
    if props.get("enableNonSslPort") is True:
        clear_port = props.get("port")
        if type(clear_port) is int and 1 <= clear_port <= 65535:
            ports = union(ports, pset("tcp", clear_port, clear_port))
        else:
            a.gap("listener", "enabled Redis non-TLS port is not observed")
    elif props.get("enableNonSslPort") is not False:
        a.gap("listener", "Redis non-TLS listener state is not observed")
    a.step("public_network_access", "allow", value=access)
    coverage = (resource["data"].get("_coverage") or {}).get("firewallRules") or {}
    rules = resource["data"].get("firewallRules")
    if coverage.get("status") not in ("collected", "empty") or not isinstance(rules, list):
        a.gap("firewall", "Redis firewall IP rules are not fully collected")
    elif not rules:
        a.step("firewall", "allow", reason="no configured IP rules")
    else:
        public = False
        for rule in rules:
            fields = rule.get("properties") if isinstance(rule, dict) else None
            try:
                start = ipaddress.IPv4Address(fields["startIP"])
                end = ipaddress.IPv4Address(fields["endIP"])
                if start > end:
                    raise ValueError("reversed range")
                public |= _azure_public_remainder(ipaddress.summarize_address_range(start, end), [])
            except (TypeError, KeyError, ValueError):
                a.gap("firewall", "Redis firewall rule has an unresolved IP range")
        if public:
            a.step("firewall", "allow", reason="rule admits a public IPv4 source")
        elif not any(gap["layer"] == "firewall" for gap in a.unresolved):
            a.step("firewall", "block", reason="no rule admits a public IPv4 source")
            ports = {}
    a.ports = ports
    return a


# ---------------------------------------------------------------------- K8s

INTERNAL = {"service.beta.kubernetes.io/aws-load-balancer-internal": {"true", "0.0.0.0/0"},
            "service.beta.kubernetes.io/aws-load-balancer-scheme": {"internal"},
            "service.beta.kubernetes.io/azure-load-balancer-internal": {"true"},
            "networking.gke.io/load-balancer-type": {"internal"},
            "cloud.google.com/load-balancer-type": {"internal"},
            "service.beta.kubernetes.io/oci-load-balancer-internal": {"true"},
            "alb.ingress.kubernetes.io/scheme": {"internal"},
            "service.beta.kubernetes.io/openstack-internal-load-balancer": {"true"}}
SOURCE_ANNOTATIONS = ("service.beta.kubernetes.io/load-balancer-source-ranges", "alb.ingress.kubernetes.io/inbound-cidrs",
                      "nginx.ingress.kubernetes.io/whitelist-source-range", "nginx.ingress.kubernetes.io/allowlist-source-range",
                      "service.beta.kubernetes.io/azure-allowed-ip-ranges")


def k8s_internal(meta):
    annotations = meta.get("annotations") if isinstance(meta.get("annotations"), dict) else {}
    return [k for k, values in INTERNAL.items() if str(annotations.get(k, "")).strip().lower() in values]


def k8s_source_ranges(spec, meta):
    annotations = meta.get("annotations") if isinstance(meta.get("annotations"), dict) else {}
    ranges = [str(x) for x in as_list(spec.get("loadBalancerSourceRanges"))]
    for key in SOURCE_ANNOTATIONS:
        if annotations.get(key):
            ranges += [x.strip() for x in str(annotations[key]).split(",") if x.strip()]
    return ranges


def _k8s_public_source(value):
    if _internet(value):
        return True
    network = _cidr(value)
    return network is not None and network.is_global


def _k8s_ports(spec, field="port"):
    ports = {}
    for port in as_list(spec.get("ports")):
        if isinstance(port, dict) and isinstance(port.get(field), int):
            ports = union(ports, pset(port.get("protocol", "TCP"), port[field], port[field]) or {})
    return ports


def _k8s_nodes(inventory, resource):
    data = resource["data"]
    cluster = (data.get("provenance") or {}).get("cluster_id") or (data.get("metadata") or {}).get("cluster_id") or resource["scope"].split("/", 1)[0]
    return [n for n in inventory.items("node") if n["scope"] == resource["scope"] and
            ((n["data"].get("provenance") or {}).get("cluster_id") or
             (n["data"].get("metadata") or {}).get("cluster_id") or n["scope"].split("/", 1)[0]) == cluster]


def _k8s_public_nodes(inventory, resource):
    return [n for n in _k8s_nodes(inventory, resource) if
            any(isinstance(x, dict) and x.get("type") == "ExternalIP" and _public_ip(x.get("address"))
                for x in as_list((n["data"].get("status") or {}).get("addresses")))]


def _k8s_external_dns(inventory, resource):
    return [x.get("address") for n in _k8s_nodes(inventory, resource)
            for x in as_list((n["data"].get("status") or {}).get("addresses"))
            if isinstance(x, dict) and x.get("type") == "ExternalDNS" and isinstance(x.get("address"), str) and x["address"]]


def _k8s_service(snapshot, inventory, resource):
    data = resource["data"]
    spec, meta = data.get("spec") or {}, data.get("metadata") or {}
    kind = spec.get("type", "ClusterIP")
    external = [ip for ip in as_list(spec.get("externalIPs")) if _public_ip(ip)]
    if kind == "ExternalName":
        name = str(spec.get("externalName") or "").strip().rstrip(".")
        if not name or name.endswith((".svc", ".svc.cluster.local", ".cluster.local")):
            return None
        a = Assessment(resource, "external_destination")
        a.step("service_alias", "allow", external_name=name)
        a.gap("inventory", "ExternalName target DNS, ownership and actual client traffic are not observed")
        return a
    if kind not in ("LoadBalancer", "NodePort") and not external:
        return None
    a = Assessment(resource, "service")
    a.step("service_type", "allow", type=kind, external_ips=external)
    def external_path():
        health_port = spec.get("healthCheckNodePort") if kind == "LoadBalancer" else None
        if isinstance(health_port, int) and not isinstance(health_port, bool) and 0 < health_port <= 65535:
            nodes = _k8s_public_nodes(inventory, resource)
            if nodes:
                gap_layer = "security_group" if a.blocked_by or not a.ports else "node_firewall"
                if a.blocked_by:
                    a.addresses = []
                a.addresses = list(dict.fromkeys([*a.addresses, *(x.get("address") for n in nodes for x in
                    as_list((n["data"].get("status") or {}).get("addresses")) if isinstance(x, dict) and
                    x.get("type") == "ExternalIP" and _public_ip(x.get("address")))]))
                a.ports = union(a.ports or {}, pset("tcp", health_port, health_port))
                a.blocked_by = None
                a.step("health_check_node_port", "allow", port=health_port, public_nodes=[native_id(n) for n in nodes])
                a.gap(gap_layer, "cloud firewall for public Node health-check port is not observed")
        if external:
            # externalIPs is a requested address, not an observed address
            # assignment or route. A separately observed public LB path can
            # still decide this resource's verdict on its own evidence.
            observed_lb_path = kind == "LoadBalancer" and a.verdict() == "FAIL"
            if not observed_lb_path:
                a.addresses = list(dict.fromkeys([*([] if a.blocked_by else a.addresses), *external]))
            a.ports = union(a.ports or {}, _k8s_ports(spec))
            a.blocked_by = None
            a.unresolved = [gap for gap in a.unresolved if gap["layer"] != "inventory"]
            a.step("external_ip", "unknown", declared_public_addresses=external)
            a.gap("inventory", "externalIPs address ownership and routing to a cluster node are not observed")
            a.unresolved[-1]["decisive"] = not observed_lb_path
            a.gap("firewall", "cloud firewall admission for the declared externalIPs address is not observed")
            a.unresolved[-1]["decisive"] = not observed_lb_path
        return a
    if kind == "LoadBalancer":
        internal = k8s_internal(meta)
        ingress = [x.get("ip") or x.get("hostname") for x in as_list(((data.get("status") or {}).get("loadBalancer") or {}).get("ingress")) if isinstance(x, dict)]
        a.addresses = [x for x in ingress if x]
        if internal:
            a.step("scheme", "block", internal_annotations=internal)
            a.ports = {}
            return external_path()
        if a.addresses and all(not _public_ip(x) for x in a.addresses if re.match(r"^[0-9a-fA-F:.]+$", str(x))) and \
                all(re.match(r"^[0-9a-fA-F:.]+$", str(x)) for x in a.addresses):
            a.step("scheme", "block", reason="load balancer address is private", addresses=a.addresses)
            a.ports = {}
            return external_path()
        ranges = k8s_source_ranges(spec, meta)
        if ranges and not any(_k8s_public_source(r) for r in ranges):
            a.step("source_ranges", "block", load_balancer_source_ranges=ranges)
            a.ports = {}
            return external_path()
        a.step("source_ranges", "allow", load_balancer_source_ranges=ranges or ["0.0.0.0/0 (default)"])
        a.ports = _k8s_ports(spec)
        if not a.addresses:
            a.notes.append("no load balancer address observed in status; provisioning not confirmed")
            a.gap("inventory", "no load balancer address observed in status")
        return external_path()
    if kind == "NodePort":
        public_nodes = [native_id(n) for n in _k8s_public_nodes(inventory, resource)]
        a.ports = _k8s_ports(spec, "nodePort")
        if inventory.state("node").startswith("missing"):
            a.gap("inventory", "nodes not collected", "k8s nodes list")
        elif not public_nodes:
            external_dns = _k8s_external_dns(inventory, resource)
            if external_dns:
                a.addresses = external_dns
                a.gap("inventory", "Node ExternalDNS resolution and public routing are not observed")
            else:
                a.step("node_address", "block", reason="no node has a public ExternalIP or ExternalDNS")
                a.ports = {} if not external else _k8s_ports(spec)
        else:
            a.step("node_address", "allow", public_nodes=public_nodes)
            a.gap("security_group", "node cloud firewall/security groups are outside the cluster inventory", STATIC_GAPS["k8s"][0]["fact"])
    return external_path()


def _k8s_ingress(snapshot, inventory, resource):
    data = resource["data"]
    spec, meta = data.get("spec") or {}, data.get("metadata") or {}
    a = Assessment(resource, "ingress")
    addresses = [x.get("ip") or x.get("hostname") for x in as_list(((data.get("status") or {}).get("loadBalancer") or {}).get("ingress")) if isinstance(x, dict)]
    a.addresses = [x for x in addresses if x]
    internal = k8s_internal(meta)
    klass = spec.get("ingressClassName") or (meta.get("annotations") or {}).get("kubernetes.io/ingress.class")
    if internal or (klass and "internal" in str(klass).lower()):
        a.step("scheme", "block", internal_annotations=internal, ingress_class=klass)
        a.ports = {}
        return a
    ranges = k8s_source_ranges(spec, meta)
    ports = pset("tcp", 80, 80)
    if spec.get("tls"):
        ports = union(ports, pset("tcp", 443, 443))
    if ranges and not any(_k8s_public_source(r) for r in ranges):
        a.step("source_ranges", "block", source_ranges=ranges)
        a.ports = {}
        return a
    if not a.addresses:
        a.gap("inventory", "no load balancer address in ingress status; controller exposure not observed", None)
        a.ports = ports
        return a
    if all(re.match(r"^[0-9a-fA-F:.]+$", str(x)) and not _public_ip(x) for x in a.addresses):
        a.step("scheme", "block", reason="ingress address is private", addresses=a.addresses)
        a.ports = {}
        return a
    a.step("source_ranges", "allow", source_ranges=ranges or ["0.0.0.0/0 (default)"], ingress_class=klass,
           hosts=[r.get("host") for r in as_list(spec.get("rules")) if isinstance(r, dict) and r.get("host")])
    a.ports = ports
    return a


def _k8s_pod(snapshot, inventory, resource):
    """Assess host-bound Pod ports against collected node addresses conservatively."""
    data = resource["data"]
    spec, meta = data.get("spec") or {}, data.get("metadata") or {}
    if meta.get("deletionTimestamp") or (data.get("status") or {}).get("phase") in {"Succeeded", "Failed"}:
        return None
    host_network = spec.get("hostNetwork") is True
    status = data.get("status") or {}
    host_addresses = [ip for ip in [status.get("hostIP"), *(x.get("ip") for x in as_list(status.get("hostIPs")) if isinstance(x, dict))]
                      if _public_ip(ip)]
    pod_addresses = [ip for ip in [status.get("podIP"), *(x.get("ip") for x in as_list(status.get("podIPs")) if isinstance(x, dict))]
                     if _public_ip(ip)]
    annotations = meta.get("annotations") or {}
    multus = annotations.get("k8s.v1.cni.cncf.io/network-status") if isinstance(annotations, dict) else None
    if isinstance(multus, str):
        try:
            for attachment in as_list(json.loads(multus)):
                if isinstance(attachment, dict):
                    pod_addresses.extend(ip for ip in as_list(attachment.get("ips")) if _public_ip(ip))
        except (ValueError, TypeError):
            pass
    ports = {}
    bindings = []
    for container in as_list(spec.get("containers")) + as_list(spec.get("initContainers")) + as_list(spec.get("ephemeralContainers")):
        if not isinstance(container, dict):
            continue
        for port in as_list(container.get("ports")):
            if not isinstance(port, dict):
                continue
            value = port.get("hostPort") or (port.get("containerPort") if host_network or pod_addresses else None)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= 65535:
                continue
            host_ip = port.get("hostIP")
            if host_ip:
                try:
                    address = ipaddress.ip_address(host_ip)
                except ValueError:
                    address = None
                if address is not None and (address.is_loopback or address.is_private):
                    continue
                if _public_ip(host_ip):
                    host_addresses.append(host_ip)
            ports = union(ports, pset(port.get("protocol", "TCP"), value, value) or {})
            bindings.append({"port": value, "protocol": port.get("protocol", "TCP"), "host_ip": host_ip})
    if not host_network and not bindings and not pod_addresses:
        return None
    a = Assessment(resource, "host_port")
    a.step("host_binding", "allow", host_network=host_network, bindings=bindings)
    a.ports = ports if ports else None
    if not bindings:
        a.gap("inventory", "Pod has a public address or host network but no collected listener port declaration")
    if pod_addresses:
        a.addresses = list(dict.fromkeys(pod_addresses))
        a.step("pod_address", "allow", public_addresses=a.addresses)
        a.gap("firewall", "public Pod IP routing and network policy enforcement are not established by Pod status")
        return a
    if host_addresses:
        a.addresses = list(dict.fromkeys(host_addresses))
        a.step("host_address", "allow", public_addresses=a.addresses)
        a.gap("security_group", "host-bound public address firewall and routing are not established")
        return a
    node_name = spec.get("nodeName")
    if not node_name:
        a.gap("inventory", "Pod is not scheduled to an observed node")
        return a
    def cluster(row):
        data = row["data"]
        return str((data.get("provenance") or {}).get("cluster_id") or
                   (data.get("metadata") or {}).get("cluster_id") or row["scope"].split("/", 1)[0])

    node_index = inventory.network_cache.get("k8s_nodes_by_scope_name")
    if node_index is None:
        node_index = {(n["scope"], cluster(n), (n["data"].get("metadata") or {}).get("name")): n
                      for n in inventory.items("node") if isinstance(n.get("data"), dict)}
        inventory.network_cache["k8s_nodes_by_scope_name"] = node_index
    node = node_index.get((resource["scope"], cluster(resource), node_name))
    if node is None:
        a.gap("inventory", "scheduled node is not in the collected inventory")
        return a
    addresses = [item.get("address") for item in as_list((node["data"].get("status") or {}).get("addresses"))
                 if isinstance(item, dict) and item.get("type") == "ExternalIP" and _public_ip(item.get("address"))]
    if not addresses:
        external_dns = [item.get("address") for item in as_list((node["data"].get("status") or {}).get("addresses"))
                        if isinstance(item, dict) and item.get("type") == "ExternalDNS" and isinstance(item.get("address"), str)]
        if external_dns:
            a.addresses = external_dns
            a.gap("inventory", "scheduled Node ExternalDNS resolution and public routing are not observed")
            return a
        a.step("node_address", "block", reason="scheduled node has no public ExternalIP or ExternalDNS")
        a.ports = {}
        return a
    a.addresses = addresses
    a.step("node_address", "allow", node=node_name, public_addresses=addresses)
    a.gap("security_group", "node cloud firewall is not available in Kubernetes inventory",
          STATIC_GAPS["k8s"][0]["fact"])
    return a


def _k8s_node(snapshot, inventory, resource):
    status = resource["data"].get("status") or {}
    addresses = [x.get("address") for x in as_list(status.get("addresses")) if isinstance(x, dict)
                 and x.get("type") == "ExternalIP" and _public_ip(x.get("address"))]
    endpoint = (status.get("daemonEndpoints") or {}).get("kubeletEndpoint") or {}
    port = endpoint.get("Port", endpoint.get("port")) if isinstance(endpoint, dict) else None
    external_dns = [x.get("address") for x in as_list(status.get("addresses")) if isinstance(x, dict)
                    and x.get("type") == "ExternalDNS" and isinstance(x.get("address"), str) and x["address"]]
    if not (addresses or external_dns) or not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535:
        return None
    a = Assessment(resource, "kubelet")
    a.addresses, a.ports = addresses or external_dns, pset("tcp", port, port)
    a.step("kubelet_endpoint", "allow", port=port, public_addresses=addresses, external_dns=external_dns)
    if not addresses:
        a.gap("inventory", "Node ExternalDNS resolution and public routing are not observed")
    a.gap("security_group", "node cloud firewall is not available in Kubernetes inventory")
    return a


def _k8s_external_backend(snapshot, inventory, resource):
    """Identify declared public backends that may receive workload data."""
    kind, data = resource["type"], resource["data"]
    addresses, destinations, ports = [], [], {}
    if kind == "endpointslice":
        for endpoint in as_list(data.get("endpoints")):
            if isinstance(endpoint, dict):
                addresses.extend(x for x in as_list(endpoint.get("addresses")) if _public_ip(x))
        entries = data.get("ports")
    elif kind in {"endpoint", "endpoints"}:
        entries = []
        for subset in as_list(data.get("subsets")):
            if isinstance(subset, dict):
                addresses.extend(x.get("ip") for key in ("addresses", "notReadyAddresses")
                                 for x in as_list(subset.get(key)) if isinstance(x, dict) and _public_ip(x.get("ip")))
                entries += as_list(subset.get("ports"))
    else:
        spec = data.get("spec") or {}
        if kind == "istio_service_entry" and spec.get("location") == "MESH_EXTERNAL":
            destinations.extend(x for x in as_list(spec.get("hosts")) if isinstance(x, str) and x)
        addresses.extend(x for x in as_list(spec.get("addresses")) if _public_ip(x))
        if kind == "istio_workload_entry" and _public_ip(spec.get("address")):
            addresses.append(spec["address"])
        elif kind == "istio_workload_entry" and isinstance(spec.get("address"), str) and "." in spec["address"]:
            destinations.append(spec["address"])
        for endpoint in as_list(spec.get("endpoints")):
            if isinstance(endpoint, dict) and _public_ip(endpoint.get("address")):
                addresses.append(endpoint["address"])
        entries = spec.get("ports")
    if not addresses and not destinations:
        return None
    for entry in as_list(entries):
        if isinstance(entry, dict):
            number = entry.get("port", entry.get("number"))
            if isinstance(number, int) and not isinstance(number, bool):
                ports = union(ports, pset(entry.get("protocol", "TCP"), number, number) or {})
    a = Assessment(resource, "external_backend")
    a.addresses, a.ports = list(dict.fromkeys(addresses)), ports or None
    a.step("external_backend", "allow", public_addresses=a.addresses, destinations=list(dict.fromkeys(destinations)))
    if not a.addresses:
        a.gap("inventory", "external destination hostname has no observed public DNS address")
    a.gap("backend", "reference by a workload and actual data transfer to this public address are not established")
    return a


def _k8s_third_party_data(snapshot, inventory, resource):
    """Find API-declared external receivers or configuration sources, without reading content."""
    kind, data = resource["type"], resource["data"]
    targets = []
    if kind == "admission_configuration":
        for webhook in as_list(data.get("webhooks")):
            if not isinstance(webhook, dict):
                continue
            url = (webhook.get("clientConfig") or {}).get("url")
            if isinstance(url, str):
                host = urlsplit(url).hostname
                if host and not host.endswith((".svc", ".svc.cluster.local", ".cluster.local")):
                    targets.append(host)
    elif kind == "configsync_rootsync":
        spec = data.get("spec") or {}
        for source_type in ("git", "oci", "helm"):
            source_data = spec.get(source_type) or {}
            if not isinstance(source_data, dict):
                continue
            for key in ("repo", "image"):
                url = source_data.get(key)
                if isinstance(url, str):
                    host = urlsplit(url).hostname or url.split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
                    if host and "." in host and not host.endswith((".svc", ".svc.cluster.local", ".cluster.local")):
                        targets.append(host)
    elif kind == "persistentvolume":
        spec = data.get("spec") or {}
        for storage, key in (("nfs", "server"), ("iscsi", "targetPortal")):
            host = (spec.get(storage) or {}).get(key)
            if isinstance(host, str):
                address = host.split("]", 1)[0].removeprefix("[") if host.startswith("[") else \
                    host if _public_ip(host) else host.split(":", 1)[0]
                if _public_ip(address):
                    targets.append(address)
    if not targets:
        return None
    a = Assessment(resource, "third_party_data")
    a.addresses = list(dict.fromkeys(x for x in targets if _public_ip(x)))
    a.step("external_receiver", "allow", hosts=list(dict.fromkeys(targets)))
    a.gap("backend", "third-party ownership, successful delivery and data contents are not observed")
    return a


def _k8s_gateway(snapshot, inventory, resource):
    """Surface public Gateway API listeners without claiming backend reachability."""
    data = resource["data"]
    spec = data.get("spec") or {}
    listeners = [x for x in as_list(spec.get("listeners")) if isinstance(x, dict)
                 and isinstance(x.get("port"), int) and not isinstance(x.get("port"), bool)]
    if not listeners:
        return None
    a = Assessment(resource, "gateway")
    a.addresses = [x.get("value") for x in as_list((data.get("status") or {}).get("addresses"))
                   if isinstance(x, dict) and _public_ip(x.get("value"))]
    for listener in listeners:
        a.ports = union(a.ports or {}, pset(listener.get("protocol", "TCP"), listener["port"], listener["port"]) or {})
    a.step("gateway_listeners", "allow", listeners=[{"name": x.get("name"), "port": x["port"], "protocol": x.get("protocol")} for x in listeners])
    if not a.addresses:
        a.gap("inventory", "no public Gateway address observed in status")
        return a
    a.gap("backend", "Gateway route acceptance, backend health and controller routing are not established")
    return a


K8S_ROUTE_TYPES = frozenset({
    "httproute", "grpcroute", "tlsroute", "tcproute", "udproute", "linkerd_http_route",
    "contour_http_proxy", "istio_gateway", "istio_virtual_service", "nginx_virtual_server",
    "nginx_virtual_server_route", "nginx_transport_server", "openshift_route",
    "traefik_ingress_route", "traefik_ingress_route_tcp", "traefik_ingress_route_udp",
})


def _k8s_custom_route(snapshot, inventory, resource):
    """Report collected controller route declarations, retaining data-plane uncertainty."""
    kind, data = resource["type"], resource["data"]
    spec = data.get("spec") or {}
    if kind == "istio_virtual_service" and not any(g != "mesh" for g in as_list(spec.get("gateways"))):
        return None
    if kind in {"httproute", "grpcroute", "tlsroute", "tcproute", "udproute", "linkerd_http_route"}:
        parents = [p for p in as_list(spec.get("parentRefs")) if isinstance(p, dict) and p.get("kind", "Gateway") == "Gateway"]
        if not parents:
            return None
    elif kind == "istio_gateway":
        if not as_list(spec.get("servers")):
            return None
    elif not any(spec.get(key) for key in ("routes", "rules", "virtualhost", "host", "hosts", "listener", "to", "upstreams", "subroutes")):
        return None
    a = Assessment(resource, "controller_route")
    a.step("route_declaration", "allow", route_kind=kind)
    status = data.get("status") or {}
    for item in as_list((status.get("loadBalancer") or {}).get("ingress")) + as_list(status.get("ingress")):
        if isinstance(item, dict):
            candidate = item.get("ip") or item.get("address")
            if _public_ip(candidate):
                a.addresses.append(candidate)
    for key in ("ip", "address"):
        if _public_ip(status.get(key)):
            a.addresses.append(status[key])
    if kind in {"httproute", "grpcroute", "tlsroute", "tcproute", "udproute", "linkerd_http_route"}:
        meta = data.get("metadata") or {}
        namespace = meta.get("namespace", "default")
        cluster = (data.get("provenance") or {}).get("cluster_id") or meta.get("cluster_id") or resource["scope"].split("/", 1)[0]
        if "k8s_public_gateways" not in inventory.network_cache:
            inventory.network_cache["k8s_public_gateways"] = {
                ((g["data"].get("provenance") or {}).get("cluster_id") or
                 (g["data"].get("metadata") or {}).get("cluster_id") or g["scope"].split("/", 1)[0],
                 (g["data"].get("metadata") or {}).get("namespace", "default"),
                 (g["data"].get("metadata") or {}).get("name")): g
                for g in inventory.items("gateway") if isinstance(g.get("data"), dict)}
        for parent in parents:
            gateway = inventory.network_cache["k8s_public_gateways"].get((cluster, parent.get("namespace") or namespace, parent.get("name")))
            if gateway is None:
                continue
            gateway_status = gateway["data"].get("status") or {}
            a.addresses.extend(x.get("value") for x in as_list(gateway_status.get("addresses"))
                               if isinstance(x, dict) and _public_ip(x.get("value")))
            for listener in as_list((gateway["data"].get("spec") or {}).get("listeners")):
                if not isinstance(listener, dict) or parent.get("sectionName") and listener.get("name") != parent["sectionName"]:
                    continue
                port = listener.get("port")
                if isinstance(port, int) and not isinstance(port, bool):
                    a.ports = union(a.ports or {}, pset(listener.get("protocol", "TCP"), port, port) or {})
    elif kind == "istio_gateway":
        for server in as_list(spec.get("servers")):
            port = (server.get("port") or {}) if isinstance(server, dict) else {}
            if isinstance(port, dict) and isinstance(port.get("number"), int):
                a.ports = union(a.ports or {}, pset(port.get("protocol", "TCP"), port["number"], port["number"]) or {})
    elif kind == "nginx_transport_server":
        a.gap("listener", "named NGINX listener port is configured outside this route object")
    else:
        default_ports = pset("tcp", 80, 80)
        if spec.get("tls"):
            default_ports = union(default_ports, pset("tcp", 443, 443))
        if kind not in {"traefik_ingress_route_tcp", "traefik_ingress_route_udp"}:
            a.ports = default_ports
    a.addresses = list(dict.fromkeys(a.addresses))
    if not a.addresses:
        a.gap("inventory", "public controller address or attached public Gateway is not observed")
    a.gap("backend", "controller route acceptance, listener mapping and backend reachability are not established")
    return a


# --------------------------------------------------------------- dispatcher

AWS_TYPES = ["vpc", "subnet", "route_table", "network_acl", "security_group", "network_interface", "instance", "internet_gateway",
             "load_balancer", "classic_load_balancer", "rds_instance", "rds_snapshot", "rds_cluster_snapshot", "redshift_cluster",
             "opensearch_domain", "eks_cluster", "lambda_function", "rest_api", "apigateway_domain_name", "http_api", "apigatewayv2_domain_name", "bucket", "s3_account_public_access_block",
             "organization_account", "ec2_image", "ebs_snapshot", "cloudfront_distribution", "app_runner_service", "amplify_app"]
GCP_TYPES = ["network", "firewall", "firewall_policy", "instance", "forwarding_rule", "target_proxy", "url_map", "backend_service", "backend_bucket", "security_policy",
             "cloudrun_service", "function", "sql_instance", "alloydb_instance", "gke_cluster", "bucket", "bucket_effective_iam", "org_policy_effective", "bigquery_dataset", "firebase_rules_release", "firebase_database_rules", "vpn_gateway",
             "project", "workload_identity_provider",
             "cloud_ftp_server", "looker_instance", "blockchain_node", "data_fusion_instance", "vertex_index_endpoint",
             "vertex_feature_online_store", "app_engine_application", "api_gateway", "firebase_apphosting_endpoint",
             "media_cdn_service", "target_pool", "target_instance",
             "workstation", "workstation_cluster", "beyondcorp_connection", "contact_center", "oracle_goldengate_deployment", "vertex_agent_sandbox", "tpu_node",
             "vmware_external_address", "vmware_external_access_rule", "vmware_network_policy", "vmware_private_cloud"]
AZURE_TYPES = ["vnet", "subnet", "nsg", "nic", "vm", "public_ip", "load_balancer", "application_gateway", "app_service",
               "app_service_config", "aks_cluster", "storage_account", "storage_container", "sql_server", "sql_firewall_rule", "managed_identity_federated_credential",
               "container_group", "container_app", "container_app_environment", "azure_firewall", "firewall_policy", "frontdoor_and_cdn_endpoint", "api_management", "redis_cache", *_AZURE_MANAGED_ENDPOINTS]
K8S_TYPES = ["service", "ingress", "node", "pod", "gateway", "endpoint", "endpoints", "endpointslice",
             "istio_service_entry", "istio_workload_entry", "admission_configuration", "configsync_rootsync",
             "persistentvolume", "kcc_iampolicy", "kcc_iampartialpolicy", "securitycontextconstraint",
             "component_configuration", *sorted(K8S_ROUTE_TYPES)]
EXPOSURE_TYPES = {"aws": AWS_TYPES, "gcp": GCP_TYPES, "azure": AZURE_TYPES, "k8s": K8S_TYPES}
EVALUATED = {"aws": {"instance", "network_interface", "load_balancer", "classic_load_balancer", "rds_instance", "redshift_cluster",
                     "opensearch_domain", "eks_cluster", "lambda_function", "rest_api", "http_api", "rds_snapshot", "rds_cluster_snapshot", "bucket",
                     "ec2_image", "ebs_snapshot", "cloudfront_distribution", "app_runner_service", "amplify_app"},
             "gcp": {"instance", "forwarding_rule", "cloudrun_service", "function", "sql_instance", "alloydb_instance", "gke_cluster", "bucket", "bigquery_dataset", "firebase_rules_release", "firebase_database_rules", "vpn_gateway",
                     "cloud_ftp_server", "looker_instance", "blockchain_node", "data_fusion_instance", "vertex_index_endpoint",
                     "vertex_feature_online_store", "app_engine_application", "api_gateway", "firebase_apphosting_endpoint",
                     "media_cdn_service",
                     "workstation", "beyondcorp_connection", "contact_center", "oracle_goldengate_deployment", "vertex_agent_sandbox", "tpu_node",
                     "vmware_external_address"},
             "azure": {"nic", "load_balancer", "application_gateway", "app_service", "aks_cluster", "storage_account", "storage_container", "sql_server",
                       "container_group", "container_app", "azure_firewall", "frontdoor_and_cdn_endpoint", "api_management", "redis_cache", *_AZURE_MANAGED_ENDPOINTS},
             "k8s": {"service", "ingress", "pod", "node", "gateway", "endpoint", "endpoints", "endpointslice",
                     "istio_service_entry", "istio_workload_entry", "admission_configuration", "configsync_rootsync",
                     "persistentvolume", *K8S_ROUTE_TYPES}}


def assess(snapshot, resources):
    """Return [Assessment] for every asset with a public address/endpoint (cached per snapshot)."""
    context = _CONTEXT.get()
    key = ("snapshot", "internet_exposure")
    if context is not None and context["snapshot"] is snapshot and key in context["derivations"]:
        return context["derivations"][key]
    inventory = Inventory(snapshot, resources)
    provider = snapshot["provider"]
    output = []
    extra = {}
    if provider == "azure":
        extra["public_ips"] = _azure_public_ips(inventory)
        extra["configs"] = {str(c["data"].get("parent_id", "")).lower() or str(c["data"].get("id", "")).lower().split("/config/")[0]: c
                            for c in inventory.items("app_service_config")}
        rules = {}
        for rule in inventory.items("sql_firewall_rule"):
            parent = str(rule["data"].get("id", "")).lower().split("/firewallrules/")[0]
            rules.setdefault(parent, []).append(rule)
        extra["rules"] = rules
    handlers = {
        "aws": {"instance": _aws_instance, "network_interface": _aws_eni, "load_balancer": _aws_elbv2, "classic_load_balancer": _aws_classic,
                "rds_instance": _aws_rds, "redshift_cluster": _aws_redshift, "opensearch_domain": _aws_opensearch, "eks_cluster": _aws_eks,
                "lambda_function": _aws_lambda_url, "rest_api": _aws_rest_api, "http_api": _aws_http_api, "bucket": _aws_bucket,
                "rds_snapshot": lambda s, i, r: _aws_snapshot_share(s, i, r, ("DBSnapshotAttributesResult", "DBSnapshotAttributes"), "snapshot"),
                "rds_cluster_snapshot": lambda s, i, r: _aws_snapshot_share(s, i, r, ("DBClusterSnapshotAttributesResult", "DBClusterSnapshotAttributes"), "cluster snapshot"),
                "ec2_image": lambda s, i, r: _aws_ec2_share(s, i, r, "LaunchPermissions", "LaunchPermissions", "DescribeImageAttribute"),
                "ebs_snapshot": lambda s, i, r: _aws_ec2_share(s, i, r, "CreateVolumePermissions", "CreateVolumePermissions", "DescribeSnapshotAttribute"),
                "cloudfront_distribution": _aws_cloudfront, "app_runner_service": _aws_app_runner, "amplify_app": _aws_amplify},
        "gcp": {"instance": _gcp_instance, "forwarding_rule": _gcp_forwarding_rule, "cloudrun_service": _gcp_serverless, "function": _gcp_serverless,
                "sql_instance": _gcp_sql, "alloydb_instance": _gcp_alloydb, "gke_cluster": _gcp_gke, "bucket": _gcp_bucket,
                "bigquery_dataset": _gcp_bigquery_dataset, "firebase_rules_release": _gcp_firebase_rules,
                "firebase_database_rules": _gcp_firebase_rules,
                "vpn_gateway": _gcp_vpn_gateway,
                "cloud_ftp_server": _gcp_ftp, "looker_instance": _gcp_looker, "blockchain_node": _gcp_blockchain_node,
                "data_fusion_instance": _gcp_data_fusion, "vertex_index_endpoint": _gcp_vertex_index,
                "vertex_feature_online_store": _gcp_vertex_feature_store, "app_engine_application": _gcp_app_engine,
                "api_gateway": _gcp_api_gateway, "firebase_apphosting_endpoint": _gcp_firebase_apphosting,
                "media_cdn_service": _gcp_media_cdn,
                "workstation": _gcp_workstation, "beyondcorp_connection": _gcp_beyondcorp_connection,
                "contact_center": _gcp_contact_center, "oracle_goldengate_deployment": _gcp_oracle_goldengate,
                "vertex_agent_sandbox": _gcp_vertex_sandbox,
                "tpu_node": _gcp_tpu_node,
                "vmware_external_address": _gcp_vmware_address},
        "azure": {"nic": lambda s, i, r: _azure_nic(s, i, r, extra["public_ips"]), "load_balancer": _azure_lb, "application_gateway": _azure_appgw,
                  "app_service": lambda s, i, r: _azure_app_service(s, i, r, extra["configs"]), "aks_cluster": _azure_aks,
                  "storage_account": _azure_storage, "storage_container": _azure_storage_container,
                  "sql_server": lambda s, i, r: _azure_sql(s, i, r, extra["rules"]),
                  "container_group": _azure_container_group,
                  "container_app": _azure_container_app,
                  "azure_firewall": _azure_firewall,
                  "frontdoor_and_cdn_endpoint": _azure_public_edge,
                  "api_management": _azure_api_management,
                  "redis_cache": _azure_redis,
                  **{kind: _azure_managed_endpoint for kind in _AZURE_MANAGED_ENDPOINTS}},
        "k8s": {"service": _k8s_service, "ingress": _k8s_ingress, "pod": _k8s_pod, "node": _k8s_node,
                "gateway": _k8s_gateway,
                **dict.fromkeys(("endpoint", "endpoints", "endpointslice", "istio_service_entry", "istio_workload_entry"), _k8s_external_backend),
                **dict.fromkeys(("admission_configuration", "configsync_rootsync", "persistentvolume"), _k8s_third_party_data),
                **dict.fromkeys(K8S_ROUTE_TYPES, _k8s_custom_route)},
    }.get(provider, {})
    for resource in resources:
        handler = handlers.get(resource["type"])
        if handler is None or not isinstance(resource.get("data"), dict):
            continue
        try:
            current = handler(snapshot, inventory, resource)
        except (TypeError, AttributeError, KeyError, ValueError, IndexError) as exc:
            current = Assessment(resource, "malformed")
            current.gap("inventory", f"malformed native fact: {type(exc).__name__}")
        if current is not None:
            output.append(current)
    if context is not None and context["snapshot"] is snapshot:
        context["derivations"][key] = output
    return output


def _title(assessment, status):
    if status == "FAIL":
        if assessment.kind == "external_share":
            return "Data shared with external account"
        if assessment.data_exposure:
            return "Data publicly accessible from the internet"
        ports = describe(assessment.ports or {})
        addresses = sorted(x for x in assessment.addresses if x)
        target = f" at {', '.join(addresses[:2])}" if addresses else ""
        if ports:
            return f"Internet access to {', '.join(ports[:4])}{target}"
        return f"Asset reachable from the internet{target}"
    if status == "PASS":
        return "Public endpoint blocked from the internet"
    return "Internet exposure could not be fully resolved"


def _observed(assessment, status):
    """A short observation, with uncertainty retained when a path is incomplete."""
    if status == "UNKNOWN":
        return "Internet access could not be determined because required configuration is missing."
    if status == "PASS":
        if assessment.blocked_by:
            return f"Public access is blocked by {assessment.blocked_by.replace('_', ' ')}."
        return "The collected configuration does not allow public access."
    if assessment.kind == "external_share":
        accounts = ", ".join(assessment.external_ids)
        noun = "AMI launch" if assessment.resource["type"] == "ec2_image" else "Snapshot restore"
        return f"{noun} access is granted to external accounts: {accounts}."
    if assessment.data_exposure:
        if assessment.resource["type"] == "ec2_image":
            return "AMI launch access is granted to everyone."
        if assessment.resource["type"] in ("rds_snapshot", "rds_cluster_snapshot", "ebs_snapshot"):
            return "Snapshot restore access is granted to everyone."
        return "Public access to the stored data is allowed."
    sentence = f"{_title(assessment, status)} is allowed."
    if assessment.dormant:
        return sentence.replace("Internet access", "Configured internet access", 1) + " The instance is stopped or deallocated."
    if assessment.unresolved:
        return sentence + " Some path layers remain unresolved."
    return sentence


def internet_findings(snapshot, resources):
    from ..remediation import exposure_action
    output = []
    for assessment in assess(snapshot, resources):
        status = assessment.verdict()
        exposed = describe(assessment.ports or {})
        evidence = {"observed": _observed(assessment, status),
                    "exposure_kind": assessment.kind, "exposed_ports": exposed if status != "PASS" else [],
                    "public_addresses": sorted(x for x in assessment.addresses if x), "path": assessment.path,
                    "blocked_by": assessment.blocked_by if status == "PASS" else None,
                    "unresolved": assessment.unresolved, "notes": assessment.notes,
                    "authenticated_endpoint": assessment.authenticated, "data_exposure": assessment.data_exposure,
                    "external_scope_ids": assessment.external_ids,
                    "collector_facts_needed": sorted({g["collector_fact"] for g in assessment.unresolved if g.get("collector_fact")}),
                    "source": source(snapshot, assessment.resource, "data"),
                    "risk_state": "observed" if status == "FAIL" else "reviewed" if status == "PASS" else "unknown",
                    "semantics": "Declared-configuration path model from 0.0.0.0/0; no traffic was sent."}
        severity = "high" if assessment.kind == "external_share" and status == "FAIL" else assessment.adjusted_severity()
        current = finding(snapshot, assessment.resource, "exposure", CHECK, _title(assessment, status), severity, evidence, status=status)
        current["remediation"] = exposure_action(evidence, status)
        current["id"] = stable_id("exposure", CHECK, node_id(assessment.resource), node_id(assessment.origin), assessment.kind)
        output.append(current)
    output.extend(coverage_findings(snapshot, resources))
    output.extend(gcp_public_policy_findings(snapshot, resources))
    return output


def coverage_findings(snapshot, resources):
    """One UNKNOWN per scope listing exposure inventory that is missing or never collected."""
    provider = snapshot["provider"]
    collected = {(c["scope"], c["type"]): c.get("status") for c in snapshot.get("collections", [])}
    output = []
    for scope in snapshot.get("scopes", []):
        gaps = []
        for kind in sorted(EVALUATED.get(provider, ())):
            status = collected.get((scope, kind))
            if status is None and provider == "aws":
                # Account-global inventories (bucket) live under <account>/global.
                status = collected.get((scope.split("/", 1)[0] + "/global", kind))
            if status is not None and status not in AVAILABLE:
                gaps.append({"type": kind, "status": status})
        if not gaps:
            continue
        placeholder = {"id": "inventory:internet_exposure", "type": "inventory", "scope": scope, "provider": provider, "service": "exposure", "data": {}}
        output.append(finding(snapshot, placeholder, "exposure", CHECK, "Internet exposure inventory incomplete", "info",
            {"gaps": gaps, "collector_facts_needed": STATIC_GAPS.get(provider, []), "risk_state": "unknown"}, status="UNKNOWN"))
    return output


def annotate_network(graph, snapshot, resources):
    """Add an Internet node and ``internet_exposure`` edges to every exposed or unresolved asset."""
    assessments = [a for a in assess(snapshot, resources) if a.verdict() in ("FAIL", "UNKNOWN") and a.kind != "external_share"]
    if not assessments:
        return graph
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    internet_id = stable_id(snapshot["provider"], "internet")
    if internet_id not in nodes:
        nodes[internet_id] = {"id": internet_id, "resource_id": "internet", "native_id": "0.0.0.0/0", "label": "Internet (0.0.0.0/0, ::/0)",
            "type": "internet", "native_kind": "internet", "provider_specific": {"native_kind": "internet"}, "provider": snapshot["provider"],
            "scope": "internet", "evidence": {"synthetic": True, "inventory_status": "reference_only"}, "risk_annotations": []}
    edges = {e["id"]: e for e in graph.get("edges", [])}
    for assessment in assessments:
        status = assessment.verdict()
        target = node_id(assessment.resource)
        if target not in nodes:
            nodes[target] = node(assessment.resource)
        current = nodes[target]
        exposed = describe(assessment.ports or {})
        current["exposure"] = {"status": status, "exposed_ports": exposed, "kind": assessment.kind,
                               "public_addresses": sorted(x for x in assessment.addresses if x)}
        annotations = [x for x in current.get("risk_annotations", []) if not (isinstance(x, dict) and x.get("kind") == "internet_exposed")]
        annotations.append({"kind": "internet_exposed", "status": status, "severity": assessment.severity(), "ports": exposed})
        current["risk_annotations"] = annotations
        edge = relationship(internet_id, target, "internet_exposure",
            {"source": {"path": f"internet_exposure:{assessment.kind}"}, "status": status, "exposed_ports": exposed,
             "path": [{"layer": s["layer"], "decision": s["decision"]} for s in assessment.path],
             "unresolved": [g["layer"] for g in assessment.unresolved]},
            layer="exposure", confidence="high" if status == "FAIL" else "low")
        edges[edge["id"]] = edge
    graph = dict(graph)
    graph["nodes"] = sorted(nodes.values(), key=lambda row: row["id"])
    graph["edges"] = sorted(edges.values(), key=lambda row: row["id"])
    return graph


def federated_findings(snapshot, resources):
    from .trust import aws_federated_trust, azure_federated_credential, gcp_wif_provider
    handlers = {("aws", "iam_role"): aws_federated_trust, ("gcp", "workload_identity_provider"): gcp_wif_provider,
                ("azure", "managed_identity_federated_credential"): azure_federated_credential,
                ("azure", "directory_application_federated_credential"): azure_federated_credential}
    output = []
    for resource in resources:
        handler = handlers.get((snapshot["provider"], resource["type"]))
        if handler is None or not isinstance(resource.get("data"), dict):
            continue
        try:
            verdict = handler(snapshot, resource)
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            verdict = ("UNKNOWN", "info", {"reason": "malformed_native_fact"})
        if verdict is None:
            continue
        status, severity, evidence = verdict
        evidence["source"] = source(snapshot, resource, "data")
        output.append(finding(snapshot, resource, "exposure", "analysis.federated_trust",
            "Federated (OIDC) trust is not pinned to a subject" if status == "FAIL" else "Federated (OIDC) trust review",
            severity if status != "PASS" else "info", evidence, status=status))
    return output


__all__ = ["EXPOSURE_TYPES", "annotate_network", "assess", "effective_bucket_bpa", "federated_findings", "internet_findings",
           "k8s_internal", "k8s_source_ranges", "pset", "union", "intersect", "subtract", "describe"]
