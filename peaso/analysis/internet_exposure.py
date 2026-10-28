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
from collections import Counter
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
IPV6_GUA = ipaddress.IPv6Network("2000::/3")
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


def _dns_hostname(value):
    return (isinstance(value, str) and len(value) <= 255 and
            re.fullmatch(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value) is not None)


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
    if network is None:
        return False
    # A CIDR can start at a reserved address yet contain global clients.
    # IANA currently assigns IPv6 global unicast from 2000::/3.
    return (network.is_global if network.version == 4 else
            network.is_global and network.overlaps(IPV6_GUA))


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
        for field in ("id", "selfLink", "name", "GroupId", "SubnetId", "VpcId", "InternetGatewayId", "PrefixListId", "NetworkAclId", "RouteTableId", "TransitGatewayRouteTableId", "InstanceId", "KeyArn",
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

def _aws_sg_ports(inventory, group_ids, assessment, where, family=4, narrow_public=False):
    """Union of 0.0.0.0/0 and ::/0 ingress over the attached security groups."""
    if not group_ids:
        fact = {"instance": "ec2:DescribeInstances", "network_interface": "ec2:DescribeNetworkInterfaces",
                "rds_instance": "rds:DescribeDBInstances", "redshift_cluster": "redshift:DescribeClusters",
                "load_balancer": "elasticloadbalancing:DescribeLoadBalancers",
                "classic_load_balancer": "elasticloadbalancing:DescribeLoadBalancers"}.get(assessment.resource["type"])
        assessment.gap("security_group", "attached security group IDs not collected for VPC asset",
                       fact)
        return dict(FULL)
    allowed, seen = {}, []
    for group_id in group_ids:
        group = inventory.get("security_group", group_id)
        if group is None:
            assessment.gap("security_group", f"{group_id} not in inventory ({inventory.state('security_group')})", "ec2 describe_security_groups")
            continue
        permissions = group["data"].get("IpPermissions")
        if not isinstance(permissions, list) or not all(isinstance(rule, dict) for rule in permissions):
            assessment.gap("security_group", f"{group_id} inbound permission list not collected or malformed",
                           "ec2:DescribeSecurityGroups.SecurityGroups[].IpPermissions")
            continue
        malformed_field = None
        for rule in permissions:
            protocol = rule.get("IpProtocol")
            if (not isinstance(protocol, (str, int)) or
                    (str(protocol) != "-1" and not (str(protocol).isdigit() and 0 <= int(protocol) <= 255)
                     and str(protocol).lower() not in ("tcp", "udp", "icmp", "icmpv6"))):
                malformed_field = "IpProtocol"
                break
            if _proto(protocol) in ("tcp", "udp") and (
                    type(rule.get("FromPort")) is not int or type(rule.get("ToPort")) is not int or
                    not 0 <= rule["FromPort"] <= rule["ToPort"] <= 65535):
                malformed_field = "FromPort|ToPort"
                break
            for field, cidr_key, version in (("IpRanges", "CidrIp", 4), ("Ipv6Ranges", "CidrIpv6", 6)):
                ranges = rule.get(field)
                if ranges is not None and (not isinstance(ranges, list) or any(
                        not isinstance(item, dict) or (network := _cidr(item.get(cidr_key))) is None or network.version != version
                        for item in ranges)):
                    malformed_field = f"{field}[].{cidr_key}"
                    break
            if malformed_field:
                break
            prefixes = rule.get("PrefixListIds")
            if prefixes is not None and (not isinstance(prefixes, list) or any(
                    not isinstance(item, dict) or not isinstance(item.get("PrefixListId"), str)
                    or not item["PrefixListId"] for item in prefixes)):
                malformed_field = "PrefixListIds[].PrefixListId"
                break
            if not any(field in rule for field in ("IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs")):
                malformed_field = "IpRanges|Ipv6Ranges|PrefixListIds|UserIdGroupPairs"
                break
        if malformed_field:
            assessment.gap("security_group", f"{group_id} inbound permission match field not collected or malformed",
                           f"ec2:DescribeSecurityGroups.SecurityGroups[].IpPermissions[].{malformed_field}")
            continue
        cache_key = ("aws_sg_ports", group["id"], family, narrow_public)
        if cache_key not in inventory.network_cache:
            inventory.network_cache[cache_key] = _aws_group_rules(group, family, narrow_public)
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
            version = prefix["data"].get("Version")
            if version is not None and (type(version) is not int or version <= 0 or prefix["data"].get("EntriesVersion") != version):
                assessment.gap("security_group", f"prefix list {prefix_id} entries are not tied to its observed version",
                               "ec2:DescribeManagedPrefixLists.Version,ec2:GetManagedPrefixListEntries.TargetVersion")
                continue
            if any(not isinstance(entry, dict) or _cidr(entry.get("Cidr")) is None for entry in entries["items"]):
                assessment.gap("security_group", f"prefix list {prefix_id} entry CIDR missing or malformed",
                               "ec2:GetManagedPrefixListEntries.Entries[].Cidr")
                continue
            cidrs = [e.get("Cidr") for e in entries["items"] if isinstance(e, dict) and
                     (_public_source(e.get("Cidr")) if narrow_public else _internet(e.get("Cidr")))
                     and (":" in e.get("Cidr", "")) == (family == 6)]
            if cidrs:
                allowed = union(allowed, prefix_ports)
                rules.append({"ports": describe(prefix_ports), "cidrs": cidrs, "prefix_list_id": prefix_id})
        seen.append({"group_id": group_id, "internet_rules": rules})
    assessment.step("security_group", "allow" if not empty(allowed) else "block" if not any(g["layer"] == "security_group" for g in assessment.unresolved) else "unknown",
                    groups=seen, allowed=describe(allowed), address_family=family, at=where)
    return allowed


def _aws_group_rules(group, family=4, narrow_public=False):
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
        internet_cidrs = [c for c in cidrs if (_public_source(c) if narrow_public else _internet(c))
                          and (":" in c) == (family == 6)]
        if internet_cidrs:
            allowed = union(allowed, ports)
            rules.append({"ports": describe(ports), "cidrs": internet_cidrs})
        if as_list(permission.get("PrefixListIds")):
            prefix_lists.extend((p.get("PrefixListId"), ports) for p in permission["PrefixListIds"]
                                if isinstance(p, dict) and isinstance(p.get("PrefixListId"), str))
    return allowed, freeze(rules), prefix_lists


def _aws_sg_source_rules(inventory, group_ids, family):
    """Keep the source CIDR attached to each allowed ingress port set."""
    key = ("aws_sg_source_rules", tuple(sorted(group_ids)), family)
    if key not in inventory.network_cache:
        rules = []
        for group_id in group_ids:
            group = inventory.get("security_group", group_id)
            if group is None:
                continue
            for permission in as_list(group["data"].get("IpPermissions")):
                if not isinstance(permission, dict):
                    continue
                protocol = _proto(permission.get("IpProtocol"))
                if protocol is None:
                    continue
                ports = (pset(protocol, permission.get("FromPort", 0), permission.get("ToPort", 65535))
                         if protocol in ("tcp", "udp") and permission.get("FromPort") not in (None, -1)
                         else pset(protocol))
                for field, key_name in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
                    for item in as_list(permission.get(field)):
                        network = _cidr(item.get(key_name)) if isinstance(item, dict) else None
                        if network is not None and network.version == family and _public_source(network):
                            rules.append((network, ports))
                for item in as_list(permission.get("PrefixListIds")):
                    prefix_id = item.get("PrefixListId") if isinstance(item, dict) else None
                    prefix = inventory.get("managed_prefix_list", prefix_id) if prefix_id else None
                    entries = prefix["data"].get("Entries") if prefix else None
                    if not isinstance(entries, dict) or entries.get("collection_status") not in ("collected", "empty"):
                        continue
                    for entry in as_list(entries.get("items")):
                        network = _cidr(entry.get("Cidr")) if isinstance(entry, dict) else None
                        if network is not None and network.version == family and _public_source(network):
                            rules.append((network, ports))
        inventory.network_cache[key] = rules
    return inventory.network_cache[key]


def _aws_nacl(inventory, subnet_id, ports, assessment, where, family=4, public_host_ports=None, source_rules=None):
    if not subnet_id:
        assessment.gap("network_acl", "subnet unknown")
        return ports
    associations, _ = inventory.aws_associations("network_acl")
    if isinstance(subnet_id, str):
        acl = associations.get(subnet_id)
    else:
        acl = next((a for a in inventory.items("network_acl") if any(
            isinstance(x, dict) and x.get("SubnetId") == subnet_id for x in as_list(a["data"].get("Associations")))), None)
    if acl is None:
        assessment.gap("inventory", f"no collected NACL association for {subnet_id} ({inventory.state('network_acl')})",
                       "ec2:DescribeNetworkAcls.NetworkAcls[].Associations[].SubnetId")
        return ports
    subnet = inventory.get("subnet", subnet_id)
    subnet_vpc = subnet["data"].get("VpcId") if subnet else None
    if not isinstance(subnet_vpc, str) or not subnet_vpc or acl["data"].get("VpcId") != subnet_vpc:
        assessment.gap("inventory", "subnet NACL VPC identity not collected or mismatched",
                       "ec2:DescribeNetworkAcls.NetworkAcls[].VpcId")
        return ports
    if not isinstance(acl["data"].get("Entries"), list):
        assessment.gap("inventory", f"NACL entries not collected for {subnet_id}", "ec2:DescribeNetworkAcls")
        return ports
    cidr_field = "Ipv6CidrBlock" if family == 6 else "CidrBlock"
    for entry in acl["data"]["Entries"]:
        if not isinstance(entry, dict):
            assessment.gap("inventory", "NACL entry not collected as a rule object",
                           "ec2:DescribeNetworkAcls.NetworkAcls[].Entries")
            return ports
        for field in ("CidrBlock", "Ipv6CidrBlock"):
            if entry.get(field) is not None and _cidr(entry[field]) is None:
                assessment.gap("inventory", "NACL rule CIDR malformed",
                               f"ec2:DescribeNetworkAcls.NetworkAcls[].Entries[].{field}")
                return ports
        if entry.get("CidrBlock") is None and entry.get("Ipv6CidrBlock") is None:
            assessment.gap("inventory", "NACL rule CIDR not collected",
                           "ec2:DescribeNetworkAcls.NetworkAcls[].Entries[].CidrBlock|Ipv6CidrBlock")
            return ports
        if not _public_source(entry.get(cidr_field)):
            continue
        protocol = entry.get("Protocol")
        if str(protocol) != "-1" and (not str(protocol).isdigit() or not 0 <= int(protocol) <= 255):
            assessment.gap("inventory", "public-source NACL rule protocol not collected or malformed",
                           "ec2:DescribeNetworkAcls.NetworkAcls[].Entries[].Protocol")
            return ports
        if str(protocol) in ("6", "17"):
            port_range = entry.get("PortRange")
            if (not isinstance(port_range, dict) or type(port_range.get("From")) is not int or
                    type(port_range.get("To")) is not int or not 0 <= port_range["From"] <= port_range["To"] <= 65535):
                assessment.gap("inventory", "public-source NACL TCP/UDP port range not collected or malformed",
                               "ec2:DescribeNetworkAcls.NetworkAcls[].Entries[].PortRange")
                return ports
        if entry.get("RuleAction") not in ("allow", "deny"):
            assessment.gap("inventory", "public-source NACL rule action not collected or malformed",
                           "ec2:DescribeNetworkAcls.NetworkAcls[].Entries[].RuleAction")
            return ports
        if type(entry.get("RuleNumber")) is not int or not 1 <= entry["RuleNumber"] <= 32767:
            assessment.gap("inventory", "public-source NACL rule order not collected or malformed",
                           "ec2:DescribeNetworkAcls.NetworkAcls[].Entries[].RuleNumber")
            return ports
        if type(entry.get("Egress")) is not bool:
            assessment.gap("inventory", "public-source NACL rule direction not collected or malformed",
                           "ec2:DescribeNetworkAcls.NetworkAcls[].Entries[].Egress")
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
    inbound_ports = intersect(ports, inbound)
    result = {protocol: intervals for protocol, intervals in inbound_ports.items()
              if not empty(intersect(outbound, pset(protocol, 1024, 65535)
                                     if protocol in ("tcp", "udp") else pset(protocol)))}
    if public_host_ports and not empty(public_host_ports):
        entries = sorted((e for e in as_list(acl["data"].get("Entries")) if isinstance(e, dict)),
                         key=lambda e: int(e.get("RuleNumber", 32767)))
        field = "Ipv6CidrBlock" if family == 6 else "CidrBlock"
        host_key = ("aws_acl_host_candidates", acl["id"], family,
                    tuple(sorted({str(network) for network, _ in source_rules or ()})))
        if host_key not in inventory.network_cache:
            networks = [_cidr(entry.get(field)) for entry in entries]
            networks += [network for network, _ in source_rules or ()]
            hosts = set()
            maximum = (1 << (32 if family == 4 else 128)) - 1
            boundaries = {0, maximum + 1}
            for network in networks:
                if network is None or network.version != family:
                    continue
                low, high = int(network.network_address), int(network.broadcast_address)
                boundaries.update((low, high + 1))
            ordered = sorted(boundaries)
            for low, end in zip(ordered, ordered[1:]):
                high = end - 1
                # Every CIDR membership is constant inside this interval. Sampling
                # its edges and middle covers a segment left by an earlier Deny.
                for value in {low if low == high else low + 1, (low + high) // 2, high}:
                    address = ipaddress.IPv4Address(value) if family == 4 else ipaddress.IPv6Address(value)
                    if address.is_global:
                        hosts.add(str(address))
            inventory.network_cache[host_key] = tuple(sorted(hosts, key=ipaddress.ip_address))

        def host_rules(host, egress):
            address = ipaddress.ip_address(host)
            allowed, decided = {}, {}
            for entry in entries:
                network = _cidr(entry.get(field))
                if bool(entry.get("Egress")) is not egress or network is None or address not in network:
                    continue
                protocol = _proto(entry.get("Protocol"))
                if protocol not in ("tcp", "udp", "all"):
                    continue
                port_range = entry.get("PortRange") if isinstance(entry.get("PortRange"), dict) else {}
                rule = (pset(protocol, port_range.get("From", 0), port_range.get("To", 65535))
                        if protocol in ("tcp", "udp") and port_range else pset(protocol))
                fresh = subtract(rule, decided)
                if entry.get("RuleAction") == "allow":
                    allowed = union(allowed, fresh)
                decided = union(decided, rule)
            return allowed

        witnesses = []
        for host in inventory.network_cache[host_key]:
            admitted = intersect(public_host_ports, host_rules(host, False))
            if source_rules is not None:
                address = ipaddress.ip_address(host)
                sg_ports = {}
                for network, rule_ports in source_rules:
                    if address in network:
                        sg_ports = union(sg_ports, rule_ports)
                admitted = intersect(admitted, sg_ports)
            return_ports = host_rules(host, True)
            admitted = {protocol: intervals for protocol, intervals in admitted.items()
                        if protocol in ("tcp", "udp") and not empty(intersect(return_ports, pset(protocol, 1024, 65535)))}
            if not empty(admitted):
                result = union(result, admitted)
                witnesses.append({"source_ip": host, "ports": describe(admitted)})
        if witnesses:
            assessment.step("network_acl_host", "allow", acl=native_id(acl), subnet=subnet_id,
                            public_host_witnesses=witnesses, address_family=family, at=where)
    assessment.step("network_acl", "allow" if not empty(result) else "block", acl=native_id(acl), subnet=subnet_id,
                    inbound_allowed=describe(inbound), return_allowed=describe(outbound),
                    address_family=family, at=where)
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
        if any(not isinstance(t["data"].get("Associations"), list) or
               not all(isinstance(a, dict) for a in t["data"]["Associations"])
               for t in tables if t["data"].get("VpcId") == vpc_id):
            assessment.gap("inventory", "route-table association lists incomplete; implicit main association unresolved",
                           "ec2:DescribeRouteTables.RouteTables[].Associations")
            assessment.step("route", "unknown", subnet=subnet_id, address_family=6 if ipv6 else 4, at=where)
            return None
        if isinstance(vpc_id, str):
            table = defaults.get(vpc_id)
        else:
            table = next((t for t in tables if t["data"].get("VpcId") == vpc_id and any(
                isinstance(a, dict) and a.get("Main") for a in as_list(t["data"].get("Associations")))), None)
    if table is None:
        assessment.gap("inventory", f"no route table for {subnet_id} ({inventory.state('route_table')})", "ec2:DescribeRouteTables")
        return None
    if not isinstance(vpc_id, str) or not vpc_id or table["data"].get("VpcId") != vpc_id:
        assessment.gap("inventory", "subnet route table VPC identity not collected or mismatched",
                       "ec2:DescribeRouteTables.RouteTables[].VpcId")
        assessment.step("route", "unknown", route_table=native_id(table), subnet=subnet_id,
                        address_family=6 if ipv6 else 4, at=where)
        return None
    table_associations = table["data"].get("Associations")
    association = next((row for row in table_associations if isinstance(row, dict) and row.get("SubnetId") == subnet_id), None) if isinstance(table_associations, list) else None
    if association is None and isinstance(table_associations, list):
        association = next((row for row in table_associations if isinstance(row, dict) and row.get("Main") is True), None)
    state = association.get("AssociationState") if isinstance(association, dict) else None
    if not isinstance(state, dict) or state.get("State") != "associated":
        assessment.gap("inventory", "subnet route-table association state not confirmed associated",
                       "ec2:DescribeRouteTables.RouteTables[].Associations[].AssociationState.State")
        assessment.step("route", "unknown", route_table=native_id(table), subnet=subnet_id,
                        address_family=6 if ipv6 else 4, at=where)
        return None
    route_rows = table["data"].get("Routes")
    if not isinstance(route_rows, list) or not all(isinstance(row, dict) for row in route_rows):
        assessment.gap("inventory", "subnet route table route list not collected or malformed",
                       "ec2:DescribeRouteTables.RouteTables[].Routes")
        assessment.step("route", "unknown", route_table=native_id(table), subnet=subnet_id,
                        address_family=6 if ipv6 else 4, at=where)
        return None
    cache_key = ("aws_internet_routes", table["id"])
    if cache_key not in inventory.network_cache:
        inventory.network_cache[cache_key] = [r for r in route_rows if str(r.get("GatewayId", "")).startswith("igw-")
            and (r.get("DestinationCidrBlock") == "0.0.0.0/0" or r.get("DestinationIpv6CidrBlock") == "::/0")]
    routes = [r for r in inventory.network_cache[cache_key] if
              (r.get("DestinationIpv6CidrBlock") == "::/0") == bool(ipv6)]
    active_routes = [r for r in routes if r.get("State") == "active"]
    if not active_routes and any(r.get("State") not in ("active", "blackhole") for r in routes):
        assessment.gap("inventory", "internet gateway default route state not collected or malformed",
                       "ec2:DescribeRouteTables.Routes[].State")
        assessment.step("route", "unknown", route_table=native_id(table), subnet=subnet_id,
                        address_family=6 if ipv6 else 4, at=where)
        return None
    routes = active_routes
    if routes:
        gateway_id = routes[0]["GatewayId"]
        gateway = inventory.get("internet_gateway", gateway_id)
        attachment_unresolved = False
        if gateway is not None:
            attachments = gateway["data"].get("Attachments")
            if not isinstance(attachments, list):
                assessment.gap("inventory", "internet gateway attachments not collected", "ec2:DescribeInternetGateways")
                attachment_unresolved = True
            elif any(isinstance(x, dict) and x.get("VpcId") == vpc_id and x.get("State") == "available" for x in attachments):
                pass
            elif any(isinstance(x, dict) and x.get("VpcId") == vpc_id and x.get("State") != "available" for x in attachments):
                assessment.gap("inventory", "internet gateway attachment state not available", "ec2:DescribeInternetGateways")
                attachment_unresolved = True
            else:
                assessment.step("internet_gateway", "block", reason="route target is not attached to the VPC", at=where)
                return False
        else:
            assessment.gap("inventory", "internet gateway attachment not collected", "ec2:DescribeInternetGateways")
            attachment_unresolved = True
        assessment.step("route", "unknown" if attachment_unresolved else "allow",
                        route_table=native_id(table), internet_gateway=routes[0]["GatewayId"],
                        subnet=subnet_id, address_family=6 if ipv6 else 4, at=where)
        return True
    assessment.step("route", "block", route_table=native_id(table), subnet=subnet_id, address_family=6 if ipv6 else 4, reason="no active default route to an internet gateway", at=where)
    return False


def _aws_vpc_bpa(inventory, subnet_id, vpc_id, assessment, where):
    """Return False only for a proven effective regional VPC BPA ingress block."""
    scope = assessment.resource["scope"]
    options = [r for r in inventory.items("vpc_block_public_access_options") if r["scope"] == scope]
    if len(options) != 1:
        assessment.gap("inventory", "VPC Block Public Access options not collected", "ec2:DescribeVpcBlockPublicAccessOptions")
        return None
    data = options[0]["data"].get("VpcBlockPublicAccessOptions")
    if not isinstance(data, dict) or data.get("State") not in ("default-state", "update-complete"):
        assessment.gap("inventory", "VPC Block Public Access state unresolved", "ec2:DescribeVpcBlockPublicAccessOptions")
        return None
    mode = data.get("InternetGatewayBlockMode")
    if mode == "off":
        return True
    if mode not in ("block-ingress", "block-bidirectional"):
        assessment.gap("inventory", "VPC Block Public Access mode unknown", "ec2:DescribeVpcBlockPublicAccessOptions")
        return None
    if inventory.state("vpc_block_public_access_exclusion", scope) not in ("collected", "empty"):
        assessment.gap("inventory", "VPC Block Public Access exclusions not completely collected", "ec2:DescribeVpcBlockPublicAccessExclusions")
        return None
    exclusions = [r["data"] for r in inventory.items("vpc_block_public_access_exclusion") if r["scope"] == scope
                  and (r["data"].get("VpcId") == vpc_id or r["data"].get("SubnetId") == subnet_id)
                  and r["data"].get("State") in ("create-complete", "update-complete")]
    if any(x.get("InternetGatewayExclusionMode") == "allow-bidirectional" for x in exclusions):
        assessment.step("vpc_public_access_block", "allow", mode=mode, exclusion="allow-bidirectional", at=where)
        return True
    assessment.step("vpc_public_access_block", "block", mode=mode, at=where)
    return False


def _aws_vpc_path(inventory, assessment, subnet_ids, group_ids, ports, where, route=True, vpc_id=None, family=4, narrow_public=False, public_host_witness=False):
    """route -> NACL -> SG for a set of candidate subnets; returns the reachable port set."""
    source_rules = None
    if group_ids is not None:
        if public_host_witness:
            source_rules = _aws_sg_source_rules(inventory, group_ids, family)
        ports = intersect(ports, _aws_sg_ports(inventory, group_ids, assessment, where, family, narrow_public))
    if empty(ports):
        return ports
    subnet_ids = [subnet_id for subnet_id in (subnet_ids or []) if isinstance(subnet_id, str) and subnet_id]
    if not subnet_ids:
        fact = {"instance": "ec2:DescribeInstances", "network_interface": "ec2:DescribeNetworkInterfaces",
                "rds_instance": "rds:DescribeDBInstances", "redshift_cluster": "redshift:DescribeClusterSubnetGroups",
                "load_balancer": "elasticloadbalancing:DescribeLoadBalancers",
                "classic_load_balancer": "elasticloadbalancing:DescribeLoadBalancers"}.get(assessment.resource["type"])
        assessment.gap("inventory", "asset subnet IDs not collected; route and NACL association unresolved", fact)
        return ports
    reachable = {}
    subnet_identity_unresolved = False
    for subnet_id in subnet_ids:
        subnet = inventory.get("subnet", subnet_id)
        if subnet is None or not isinstance(subnet["data"].get("VpcId"), str) or not subnet["data"]["VpcId"]:
            assessment.gap("inventory", "candidate subnet VPC identity not collected",
                           "ec2:DescribeSubnets.Subnets[].VpcId")
            subnet_identity_unresolved = True
            continue
        if vpc_id and subnet["data"]["VpcId"] != vpc_id:
            assessment.gap("inventory", "candidate subnet VPC differs from asset VPC",
                           "ec2:DescribeSubnets.Subnets[].VpcId")
            subnet_identity_unresolved = True
            continue
        vpc = subnet["data"]["VpcId"]
        if route and _aws_vpc_bpa(inventory, subnet_id, vpc, assessment, where) is False:
            continue
        if route and _aws_route(inventory, subnet_id, vpc, assessment, where, ipv6=family == 6) is False:
            continue
        reachable = union(reachable, _aws_nacl(inventory, subnet_id, ports, assessment, where, family,
                                              ports if public_host_witness else None, source_rules))
    if empty(reachable) and assessment.blocked_by is None and not subnet_identity_unresolved:
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
            if (data.get("AssociationId") and not data.get("ServiceManaged")
                    and isinstance(interface, str) and _public_ip(public)):
                addresses.setdefault((eip["scope"], interface), set()).add(public)
        inventory.network_cache[key] = addresses
    return sorted(inventory.network_cache[key].get((scope, eni_id), set()))


def _aws_public_ipv6_in_subnet(inventory, subnet_id, address, assessment):
    """Use the subnet CIDR's observed AWS advertisement attribute for an ENI IPv6 address."""
    if not _public_ip(address):
        return False
    subnet = inventory.get("subnet", subnet_id) if isinstance(subnet_id, str) else None
    associations = subnet["data"].get("Ipv6CidrBlockAssociationSet") if subnet else None
    if not isinstance(associations, list):
        assessment.gap("inventory", "subnet IPv6 CIDR advertisement attribute not collected", "ec2:DescribeSubnets")
        return None
    address_ip = ipaddress.ip_address(address)
    matches = [row for row in associations if isinstance(row, dict) and
               (network := _cidr(row.get("Ipv6CidrBlock"))) is not None and address_ip in network]
    if len(matches) != 1:
        assessment.gap("inventory", "ENI IPv6 address has no unique collected subnet CIDR", "ec2:DescribeSubnets")
        return None
    row = matches[0]
    state = row.get("Ipv6CidrBlockState")
    if not isinstance(state, dict) or state.get("State") != "associated":
        assessment.gap("inventory", "subnet IPv6 CIDR association state unresolved", "ec2:DescribeSubnets")
        return None
    attribute = row.get("Ipv6AddressAttribute")
    if attribute == "public":
        return True
    if attribute == "private":
        return False
    source = row.get("IpSource")
    if source in ("amazon", "byoip"):
        return True
    if source == "none":
        return False
    assessment.gap("inventory", "subnet IPv6 public/private address attribute unresolved", "ec2:DescribeSubnets")
    return None


def _aws_ipv6_igw_allowed(inventory, scope, eni_id, assessment, detail=None):
    """Use the ENI-only IGW denial flag; DescribeInstances omits it."""
    if detail is None:
        row = inventory.get("network_interface", eni_id) if isinstance(eni_id, str) else None
        detail = row["data"] if row and row["scope"] == scope else None
    if not isinstance(detail, dict) or detail.get("NetworkInterfaceId") != eni_id:
        assessment.gap("inventory", "ENI IPv6 internet-gateway denial flag not collected", "ec2:DescribeNetworkInterfaces")
        return None
    denied = detail.get("DenyAllIgwTraffic")
    if denied is True:
        return False
    if denied is False:
        return True
    assessment.gap("inventory", "ENI IPv6 internet-gateway denial flag unresolved", "ec2:DescribeNetworkInterfaces")
    return None


def _aws_instance(snapshot, inventory, resource):
    data = resource["data"]
    a = Assessment(resource, "public_ip")
    interfaces = [n for n in as_list(data.get("NetworkInterfaces")) if isinstance(n, dict)]
    addresses = []
    for interface in interfaces:
        declared = (interface.get("Association") or {}).get("PublicIp")
        private_public = [(x.get("Association") or {}).get("PublicIp") for x in as_list(interface.get("PrivateIpAddresses"))
                          if isinstance(x, dict)]
        public = sorted({x for x in ([declared] + private_public +
                         _aws_eip_addresses(inventory, resource["scope"], interface.get("NetworkInterfaceId")))
                         if isinstance(x, str) and _public_ip(x)})
        subnet_id = interface.get("SubnetId") or data.get("SubnetId")
        v6 = [x["Ipv6Address"] for x in as_list(interface.get("Ipv6Addresses")) if isinstance(x, dict)
              and isinstance(x.get("Ipv6Address"), str) and _public_ip(x["Ipv6Address"])
              and _aws_ipv6_igw_allowed(inventory, resource["scope"], interface.get("NetworkInterfaceId"), a) is True
              and _aws_public_ipv6_in_subnet(inventory, subnet_id, x["Ipv6Address"], a) is True]
        if public or v6:
            addresses.append((interface, public, v6))
    if not interfaces and _public_ip(data.get("PublicIpAddress")):
        addresses.append(({"SubnetId": data.get("SubnetId"), "Groups": data.get("SecurityGroups", [])}, [data["PublicIpAddress"]], []))
    if not addresses:
        return a if a.unresolved else None
    a.addresses = [ip for _, v4, v6 in addresses for ip in v4 + v6]
    state_data = data.get("State") if isinstance(data.get("State"), dict) else {}
    state = state_data.get("Name")
    if state not in ("pending", "running", "shutting-down", "terminated", "stopping", "stopped"):
        a.gap("inventory", "EC2 instance state not collected or malformed", "ec2:DescribeInstances.State.Name")
        return a
    total = {}
    for interface, v4, v6 in addresses:
        groups = [g.get("GroupId") for g in as_list(interface.get("Groups")) if isinstance(g, dict)]
        where = interface.get("NetworkInterfaceId", "primary")
        for family, addresses in ((4, v4), (6, v6)):
            if addresses:
                total = union(total, _aws_vpc_path(inventory, a, [interface.get("SubnetId") or data.get("SubnetId")], groups,
                                                   dict(FULL), where, vpc_id=interface.get("VpcId") or data.get("VpcId"),
                                                   family=family, narrow_public=True, public_host_witness=True))
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
    service_types = {"api_gateway_managed", "aws_codestar_connections_managed", "ec2_instance_connect_endpoint",
                     "efs", "evs", "gateway_load_balancer", "gateway_load_balancer_endpoint",
                     "global_accelerator_managed", "iot_rules_managed", "lambda", "load_balancer",
                     "nat_gateway", "network_load_balancer", "quicksight", "transit_gateway", "vpc_endpoint"}
    operator = data.get("Operator") if isinstance(data.get("Operator"), dict) else {}
    if (attachment.get("InstanceId") or data.get("RequesterManaged") is True or operator.get("Managed") is True
            or str(data.get("Description", "")).startswith("ELB ") or data.get("InterfaceType") in service_types):
        return None
    declared = (data.get("Association") or {}).get("PublicIp")
    private_public = [(x.get("Association") or {}).get("PublicIp") for x in as_list(data.get("PrivateIpAddresses"))
                      if isinstance(x, dict)]
    public = sorted({x for x in ([declared] + private_public +
                     _aws_eip_addresses(inventory, resource["scope"], data.get("NetworkInterfaceId")))
                     if isinstance(x, str) and _public_ip(x)})
    a = Assessment(resource, "public_ip")
    v6 = [x["Ipv6Address"] for x in as_list(data.get("Ipv6Addresses")) if isinstance(x, dict)
          and isinstance(x.get("Ipv6Address"), str) and _public_ip(x["Ipv6Address"])
          and _aws_ipv6_igw_allowed(inventory, resource["scope"], data.get("NetworkInterfaceId"), a, data) is True
          and _aws_public_ipv6_in_subnet(inventory, data.get("SubnetId"), x["Ipv6Address"], a) is True]
    if not public and not v6:
        return a if a.unresolved else None
    a.addresses = public + v6
    status = data.get("Status")
    if status == "available":
        a.step("attachment", "block", status=status, reason="network interface is not attached")
        a.ports = {}
        return a
    if status != "in-use":
        a.gap("inventory", "network interface attachment status not in-use or not collected",
              "ec2:DescribeNetworkInterfaces.Status")
        return a
    a.step("attachment", "allow", status=status)
    groups = [g.get("GroupId") for g in as_list(data.get("Groups")) if isinstance(g, dict)]
    a.ports = {}
    for family, addresses in ((4, public), (6, v6)):
        if addresses:
            a.ports = union(a.ports, _aws_vpc_path(inventory, a, [data.get("SubnetId")], groups,
                                                  dict(FULL), native_id(resource), vpc_id=data.get("VpcId"),
                                                  family=family, narrow_public=True, public_host_witness=True))
    if not empty(a.ports):
        a.blocked_by = None
    if data.get("Description"):
        a.notes.append(f"interface description: {data['Description']}")
    return a


def _listener_ports(protocol, port):
    proto = str(protocol or "TCP").upper()
    kind = "udp" if proto in ("UDP", "QUIC") else "all" if proto in ("TCP_UDP", "TCP_QUIC") else "tcp"
    if kind == "all":
        return union(pset("tcp", port, port), pset("udp", port, port))
    return pset(kind, port, port)


def _alb_listener_authentication(listener):
    """Whether every collected ALB rule blocks unauthenticated target forwarding."""
    rules = listener.get("Rules")
    rows = rules.get("items") if isinstance(rules, dict) and rules.get("collection_status") == "collected" else None
    if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
        return None
    defaults = [row for row in rows if row.get("IsDefault") is True]
    if len(defaults) != 1:
        return None
    listener_actions = listener.get("DefaultActions")
    if (not isinstance(listener_actions, list) or not all(isinstance(a, dict) for a in listener_actions) or
            [a.get("Type") for a in listener_actions] != [
            a.get("Type") for a in as_list(defaults[0].get("Actions")) if isinstance(a, dict)]):
        return None
    protected = True
    for row in rows:
        actions = row.get("Actions")
        if not isinstance(actions, list) or not actions or not all(isinstance(action, dict) for action in actions):
            return None
        if actions[-1].get("Type") not in ("forward", "redirect", "fixed-response"):
            return None
        auth = [action for action in actions[:-1] if action.get("Type") in ("authenticate-oidc", "authenticate-cognito")]
        if not auth:
            protected = False
            continue
        if len(auth) != 1 or any(action.get("Type") not in ("authenticate-oidc", "authenticate-cognito") for action in actions[:-1]):
            return None
        mode = auth[0].get("UnauthenticatedRequestMode")
        if mode == "allow":
            protected = False
        elif mode not in ("authenticate", "deny"):
            return None
    return protected


def _aws_elbv2(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("Scheme") == "internal":
        return None
    a = Assessment(resource, "load_balancer")
    if data.get("Scheme") != "internet-facing":
        a.gap("inventory", "ELBv2 load balancer scheme not collected or unsupported",
              "elbv2:DescribeLoadBalancers.Scheme")
        return a
    a.endpoint = data.get("DNSName")
    a.addresses = [data.get("DNSName")] if data.get("DNSName") else []
    state = data.get("State") if isinstance(data.get("State"), dict) else {}
    code = state.get("Code")
    if code == "failed":
        a.step("load_balancer_state", "block", code=code)
        a.ports = {}
        return a
    if code not in ("active", "active_impaired"):
        a.gap("inventory", f"ELBv2 load balancer state {code or 'not collected'}",
              "elbv2:DescribeLoadBalancers.State.Code")
        return a
    a.step("load_balancer_state", "allow", code=code)
    if code == "active_impaired":
        a.notes.append("Load balancer routes traffic but has impaired scaling capacity")
    static_ipv6 = []
    if data.get("Type") == "network":
        static = []
        for zone in as_list(data.get("AvailabilityZones")):
            if not isinstance(zone, dict):
                continue
            for address in as_list(zone.get("LoadBalancerAddresses")):
                if isinstance(address, dict) and _public_ip(address.get("IpAddress")):
                    static.append({"ip": address["IpAddress"], "allocation_id": address.get("AllocationId")})
                if isinstance(address, dict) and _public_ip(address.get("IPv6Address")):
                    static_ipv6.append(address["IPv6Address"])
        if static:
            a.addresses.extend(x["ip"] for x in static)
            a.step("public_address", "allow", static_ipv4=static)
        if static_ipv6:
            a.addresses.extend(sorted(set(static_ipv6)))
            a.step("public_address", "allow", static_ipv6=sorted(set(static_ipv6)))
    if not a.addresses:
        a.gap("inventory", "ELBv2 public DNS name or static NLB address not collected",
              "elbv2:DescribeLoadBalancers.DNSName")
        return a
    address_type = data.get("IpAddressType")
    valid_address_types = ({"ipv4", "dualstack", "dualstack-without-public-ipv4"}
                           if data.get("Type") == "application" else {"ipv4", "dualstack"})
    if address_type not in valid_address_types:
        a.gap("inventory", "ELBv2 public address family not collected or unsupported",
              "elbv2:DescribeLoadBalancers.IpAddressType")
        return a
    listeners = data.get("Listeners") if isinstance(data.get("Listeners"), dict) else {}
    ports = {}
    if listeners.get("collection_status") in ("collected", "empty"):
        rows = listeners.get("items")
        protocols = ({"HTTP", "HTTPS"} if data.get("Type") == "application" else
                     {"TCP", "TLS", "UDP", "TCP_UDP", "QUIC", "TCP_QUIC"} if data.get("Type") == "network" else None)
        if not isinstance(rows, list) or protocols is None:
            a.gap("listener", "ELBv2 listener list or load balancer type unresolved", "elbv2:DescribeListeners")
            return a
        auth = []
        malformed = False
        for listener in rows:
            if (not isinstance(listener, dict) or type(listener.get("Port")) is not int
                    or not 1 <= listener["Port"] <= 65535 or listener.get("Protocol") not in protocols):
                malformed = True
                continue
            ports = union(ports, _listener_ports(listener["Protocol"], listener["Port"]))
            if any(isinstance(x, dict) and str(x.get("Type", "")).startswith("authenticate-") for x in as_list(listener.get("DefaultActions"))):
                auth.append(listener["Port"])
        if malformed and empty(ports):
            a.gap("listener", "ELBv2 listener protocol or port malformed", "elbv2:DescribeListeners")
            return a
        if malformed:
            a.notes.append("Other ELBv2 listener protocol or port records were malformed")
        a.step("listener", "allow" if not empty(ports) else "block", listeners=describe(ports), authenticated_default_actions=auth)
        if auth:
            authentication = [_alb_listener_authentication(listener) for listener in rows if isinstance(listener, dict)]
            if authentication and all(result is True for result in authentication):
                a.authenticated = True
                a.step("authentication", "requires_auth", source="elbv2:DescribeRules",
                       semantics="Every collected ALB listener rule requires authentication or denies unauthenticated requests before its routing action; no request was observed")
            elif any(result is False for result in authentication):
                a.step("authentication", "not_universal", source="elbv2:DescribeRules",
                       semantics="At least one collected listener rule lacks an authentication action or permits unauthenticated forwarding; this does not establish a matching client request")
            else:
                a.gap("authentication", "ALB authentication action modes or complete listener rules unresolved",
                      "elbv2:DescribeRules.Actions.Authenticate*Config.OnUnauthenticatedRequest")
    else:
        a.gap("listener", f"listeners {listeners.get('collection_status', 'not collected')}", "elbv2 describe_listeners")
        ports = dict(FULL)
    groups = data.get("SecurityGroups")
    subnets = [z.get("SubnetId") for z in as_list(data.get("AvailabilityZones")) if isinstance(z, dict) and z.get("SubnetId")]
    a.ports = ({} if address_type == "dualstack-without-public-ipv4" else
               _aws_vpc_path(inventory, a, subnets, groups if data.get("Type") == "application" or groups else None, ports,
                             native_id(resource), route=data.get("Type") in ("application", "network"), vpc_id=data.get("VpcId"), narrow_public=True,
                             public_host_witness=data.get("Type") in ("application", "network")))
    if address_type in ("dualstack", "dualstack-without-public-ipv4"):
        a.ports = union(a.ports, _aws_vpc_path(inventory, a, subnets, groups if groups else None, ports,
                                             native_id(resource), route=data.get("Type") in ("application", "network"), vpc_id=data.get("VpcId"),
                                             family=6, narrow_public=True, public_host_witness=True))
    if data.get("Type") == "network" and not groups:
        a.notes.append("NLB without security groups: target security groups govern client traffic (client IP preserved)")
    if any(g["layer"] == "listener" for g in a.unresolved) and not empty(a.ports):
        a.ports = None
    return a


def _aws_classic(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("Scheme") == "internal":
        return None
    a = Assessment(resource, "load_balancer")
    if data.get("Scheme") != "internet-facing":
        a.gap("inventory", "Classic ELB scheme not collected or unsupported",
              "elasticloadbalancing:DescribeLoadBalancers.Scheme")
        return a
    a.addresses = [data.get("DNSName")] if data.get("DNSName") else []
    if not a.addresses:
        a.gap("inventory", "Classic ELB public DNS name not collected",
              "elasticloadbalancing:DescribeLoadBalancers.DNSName")
        return a
    descriptions = data.get("ListenerDescriptions")
    if not isinstance(descriptions, list):
        a.gap("listener", "Classic ELB listener descriptions not collected", "elasticloadbalancing:DescribeLoadBalancers")
        return a
    ports = {}
    malformed = False
    for item in descriptions:
        listener = item.get("Listener") if isinstance(item, dict) else None
        if (isinstance(listener, dict) and type(listener.get("LoadBalancerPort")) is int
                and 1 <= listener["LoadBalancerPort"] <= 65535
                and listener.get("Protocol") in ("HTTP", "HTTPS", "TCP", "SSL")):
            ports = union(ports, pset("tcp", listener["LoadBalancerPort"], listener["LoadBalancerPort"]))
        else:
            malformed = True
    if malformed and empty(ports):
        a.gap("listener", "Classic ELB listener details malformed", "elasticloadbalancing:DescribeLoadBalancers")
        return a
    if malformed:
        a.notes.append("Other Classic ELB listener details were malformed")
    a.step("listener", "allow" if not empty(ports) else "block", listeners=describe(ports))
    a.ports = _aws_vpc_path(inventory, a, as_list(data.get("Subnets")), as_list(data.get("SecurityGroups")) if data.get("VPCId") else None,
                            ports, native_id(resource), route=bool(data.get("VPCId")), vpc_id=data.get("VPCId"), narrow_public=True,
                            public_host_witness=bool(data.get("VPCId")))
    return a


def _aws_rds(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("PubliclyAccessible") is False:
        return None
    a = Assessment(resource, "database")
    if data.get("PubliclyAccessible") is not True:
        a.gap("inventory", "RDS PubliclyAccessible flag not collected", "rds:DescribeDBInstances.PubliclyAccessible")
        return a
    endpoint = data.get("Endpoint") if isinstance(data.get("Endpoint"), dict) else {}
    a.addresses = [endpoint["Address"]] if _dns_hostname(endpoint.get("Address")) else []
    if not isinstance(data.get("DBInstanceStatus"), str) or not data["DBInstanceStatus"]:
        a.gap("inventory", "RDS instance status not collected", "rds:DescribeDBInstances.DBInstanceStatus")
        return a
    if data["DBInstanceStatus"] not in ("available", "stopped"):
        a.gap("inventory", "RDS instance status does not establish a currently serving database endpoint",
              "rds:DescribeDBInstances.DBInstanceStatus")
        return a
    if not a.addresses:
        a.gap("inventory", "RDS public endpoint DNS address not collected or malformed", "rds:DescribeDBInstances.Endpoint.Address")
        return a
    port = endpoint.get("Port")
    if type(port) is not int or not 1 <= port <= 65535:
        a.gap("listener", "RDS endpoint listener port not collected or malformed", "rds:DescribeDBInstances.Endpoint.Port")
        return a
    ports = pset("tcp", port, port)
    a.step("listener", "allow", port=port, engine=data.get("Engine"))
    groups = [g.get("VpcSecurityGroupId") for g in as_list(data.get("VpcSecurityGroups")) if isinstance(g, dict) and g.get("Status", "active") == "active"]
    group = data.get("DBSubnetGroup") if isinstance(data.get("DBSubnetGroup"), dict) else {}
    subnets = [s.get("SubnetIdentifier") for s in as_list(group.get("Subnets")) if isinstance(s, dict)]
    a.ports = _aws_vpc_path(inventory, a, subnets, groups, ports, native_id(resource), vpc_id=group.get("VpcId"),
                            narrow_public=True, public_host_witness=True)
    state = data.get("DBInstanceStatus")
    if state == "stopped":
        a.dormant = True
        a.notes.append("DB instance is stopped; retained endpoint configuration applies after restart")
    elif state not in (None, "available"):
        a.notes.append(f"DB instance status {state}")
    return a


def _aws_redshift(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("PubliclyAccessible") is False:
        return None
    a = Assessment(resource, "database")
    if data.get("PubliclyAccessible") is not True:
        a.gap("inventory", "Redshift PubliclyAccessible flag not collected", "redshift:DescribeClusters.PubliclyAccessible")
        return a
    endpoint = data.get("Endpoint") if isinstance(data.get("Endpoint"), dict) else {}
    a.addresses = [endpoint["Address"]] if _dns_hostname(endpoint.get("Address")) else []
    if not isinstance(data.get("ClusterStatus"), str) or not data["ClusterStatus"]:
        a.gap("inventory", "Redshift cluster status not collected", "redshift:DescribeClusters.ClusterStatus")
        return a
    if data["ClusterStatus"] not in ("available", "available, prep-for-resize", "available, resize-cleanup", "paused"):
        a.gap("inventory", "Redshift cluster status does not establish a currently serving database endpoint",
              "redshift:DescribeClusters.ClusterStatus")
        return a
    if not a.addresses:
        a.gap("inventory", "Redshift public endpoint DNS address not collected or malformed", "redshift:DescribeClusters.Endpoint.Address")
        return a
    port = endpoint.get("Port")
    if type(port) is not int or not 1 <= port <= 65535:
        a.gap("listener", "Redshift endpoint port not collected", "redshift:DescribeClusters")
        return a
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
    a.ports = _aws_vpc_path(inventory, a, subnets, groups, pset("tcp", port, port), native_id(resource),
                            vpc_id=group.get("VpcId"), narrow_public=True, public_host_witness=True)
    if data.get("ClusterStatus") == "paused":
        a.dormant = True
        a.notes.append("Redshift cluster is paused; retained endpoint configuration applies after resume")
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


def _opensearch_http_policy(document_value, domain_arn):
    """Resolve broad anonymous HTTP grants to this domain from its cached policy."""
    from fnmatch import fnmatchcase
    from .iam import document
    from .trust import restrictive_conditions
    doc = document(document_value)
    if doc is None or not isinstance(domain_arn, str):
        return None, [], True, []
    methods = {f"es:eshttp{method}" for method in ("get", "head", "post", "put", "patch", "delete")}
    scope = f"{domain_arn}/*"
    allowed, denied, restricted, uncertain, narrow = set(), set(), [], False, []
    statements = as_list(doc.get("Statement"))
    any_deny = any(isinstance(row, dict) and row.get("Effect") == "Deny" for row in statements)
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny"):
            uncertain = True
            continue
        principal = statement.get("Principal")
        values = [principal] if isinstance(principal, str) else [v for x in principal.values() for v in as_list(x)] if isinstance(principal, dict) else []
        if "*" not in values:
            continue
        if any(key in statement for key in ("NotAction", "NotResource", "NotPrincipal")):
            uncertain = True
            continue
        actions = [x.casefold() for x in as_list(statement.get("Action")) if isinstance(x, str)]
        matched = {action for action in methods if any(fnmatchcase(action, pattern) for pattern in actions)}
        if not matched:
            continue
        resources = as_list(statement.get("Resource"))
        if scope not in resources and "*" not in resources:
            path_resources = [x for x in resources if isinstance(x, str) and x.startswith(f"{domain_arn}/")
                              and len(x) > len(domain_arn) + 1]
            if path_resources:
                if statement["Effect"] == "Allow" and not statement.get("Condition") and not any_deny:
                    narrow.extend((action, resource) for action in sorted(matched) for resource in path_resources)
                else:
                    uncertain = True
            continue
        condition = statement.get("Condition") or {}
        if condition:
            if statement["Effect"] == "Allow":
                restricted.extend(restrictive_conditions(condition))
            uncertain = True
            continue
        (allowed if statement["Effect"] == "Allow" else denied).update(matched)
    return bool(allowed - denied or narrow), restricted, uncertain, narrow


def _aws_opensearch(snapshot, inventory, resource):
    domain = resource["data"].get("Domain")
    status = domain.get("DomainStatus") if isinstance(domain, dict) else None
    a = Assessment(resource, "managed_endpoint")
    if not isinstance(status, dict):
        a.gap("inventory", "OpenSearch domain status not collected", "opensearch:DescribeDomain.DomainStatus")
        return a
    if isinstance(status.get("VPCOptions"), dict):
        return None
    processing = status.get("DomainProcessingStatus")
    if processing == "Isolated" or status.get("Deleted") is True:
        a.step("domain_state", "block", domain_processing_status=processing,
               deleted=status.get("Deleted") is True, reason="OpenSearch domain is suspended or deleted")
        a.ports = {}
        return a
    if processing in ("Creating", "Deleting") or status.get("Created") is False:
        a.gap("inventory", "OpenSearch domain creation or deletion is not complete",
              "opensearch:DescribeDomain.DomainProcessingStatus")
        return a
    if processing != "Active":
        a.gap("inventory", "OpenSearch domain serving state not established by current configuration",
              "opensearch:DescribeDomain.DomainProcessingStatus")
        return a
    service_hosts = []
    malformed_hosts = []
    for field, host in (("Endpoint", status.get("Endpoint")),
                        ("EndpointV2", status.get("EndpointV2") if status.get("IPAddressType") == "dualstack" else None)):
        if host is None:
            continue
        if _dns_hostname(host):
            service_hosts.append(host)
        else:
            malformed_hosts.append(field)
    a.addresses = service_hosts
    for field in malformed_hosts:
        a.unresolved.append({"layer": "inventory", "reason": "OpenSearch service endpoint hostname malformed",
                             "collector_fact": f"opensearch:DescribeDomain.DomainStatus.{field}",
                             "decisive": not bool(service_hosts)})
    endpoint_options = status.get("DomainEndpointOptions")
    custom_declared = False
    if isinstance(endpoint_options, dict) and endpoint_options.get("CustomEndpointEnabled") is True:
        custom_host = endpoint_options.get("CustomEndpoint")
        if _dns_hostname(custom_host):
            custom_declared = True
            a.step("alternate_endpoint", "allow_declaration", custom_endpoint=custom_host,
                   source="opensearch:DescribeDomain.DomainEndpointOptions",
                   semantics="Enabled custom hostname is configured; public DNS CNAME or alias routing is not collected")
            a.notes.append("OpenSearch custom hostname needs a public DNS CNAME or alias to the service endpoint")
        else:
            a.gap("inventory", "enabled OpenSearch custom endpoint host missing or malformed",
                  "opensearch:DescribeDomain.DomainEndpointOptions.CustomEndpoint")
    if not a.addresses:
        a.gap("inventory", "OpenSearch public domain endpoint host not collected", "opensearch:DescribeDomain")
        if custom_declared:
            a.gap("dns", "OpenSearch custom hostname DNS routing not collected",
                  "route53:ListResourceRecordSets or external DNS")
        return a
    a.step("route", "allow", reason="public (non-VPC) domain endpoint")
    public, restricted, uncertain, narrow = _opensearch_http_policy(status.get("AccessPolicies"), status.get("ARN"))
    ports = pset("tcp", 443, 443)
    if isinstance(endpoint_options, dict) and endpoint_options.get("EnforceHTTPS") is False:
        ports = union(ports, pset("tcp", 80, 80))
    if public:
        a.step("policy", "allow", reason="access policy grants Principal * an HTTP action on this domain without restrictive conditions",
               narrow_resource_declarations=[{"action": action, "resource": resource} for action, resource in narrow],
               semantics="A granted domain path is a policy declaration; index existence and HTTP response are not established")
    elif uncertain:
        a.gap("policy", "domain HTTP action, resource or condition join is unresolved", "opensearch:DescribeDomain")
        a.authenticated = True
    elif public is None:
        a.step("policy", "allow", reason="no access policy document; IAM identity policies govern", note="authenticated")
        a.authenticated = True
    else:
        a.step("policy", "allow", reason="access policy requires signed or condition-restricted access", restrictive_conditions=restricted)
        a.authenticated = True
    fine = status.get("AdvancedSecurityOptions", {})
    if isinstance(fine, dict) and fine.get("Enabled") is True:
        migration = fine.get("AnonymousAuthEnabled")
        a.step("fine_grained_access", "requires_auth" if migration is False else "anonymous_migration" if migration is True else "unresolved",
               enabled=True, anonymous_auth_enabled=migration,
               semantics="OpenSearch migration can admit unsigned requests despite fine-grained access control")
        if migration is False:
            a.authenticated = True
        elif type(migration) is not bool:
            a.gap("fine_grained_access", "anonymous-auth migration setting not collected", "opensearch:DescribeDomain")
    a.ports = ports
    return a


def _aws_eks(snapshot, inventory, resource):
    cluster = resource["data"].get("Cluster")
    config = cluster.get("cluster", {}).get("resourcesVpcConfig") if isinstance(cluster, dict) else None
    a = Assessment(resource, "control_plane")
    if not isinstance(config, dict):
        a.gap("inventory", "EKS cluster VPC endpoint configuration not collected",
              "eks:DescribeCluster.resourcesVpcConfig")
        return a
    a.notes.append("Kubernetes may authorize anonymous API paths; effective anonymous RBAC bindings are not collected by AWS DescribeCluster")
    if config.get("endpointPublicAccess") is False:
        return None
    if config.get("endpointPublicAccess") is not True:
        a.gap("inventory", "EKS public endpoint flag not collected",
              "eks:DescribeCluster.resourcesVpcConfig.endpointPublicAccess")
        return a
    cluster_status = cluster["cluster"].get("status")
    if cluster_status != "ACTIVE":
        a.gap("inventory", "EKS cluster API serving state not established",
              "eks:DescribeCluster.cluster.status")
        return a
    a.step("cluster_state", "allow", status=cluster_status,
           semantics="Observed ACTIVE cluster status; no request was observed")
    endpoint = cluster["cluster"].get("endpoint")
    try:
        parsed_endpoint = urlsplit(endpoint) if isinstance(endpoint, str) else None
        valid_endpoint = (parsed_endpoint is not None and parsed_endpoint.scheme == "https"
                          and isinstance(parsed_endpoint.hostname, str) and "." in parsed_endpoint.hostname
                          and parsed_endpoint.port in (None, 443) and parsed_endpoint.username is None
                          and parsed_endpoint.password is None and parsed_endpoint.path in ("", "/")
                          and not parsed_endpoint.query and not parsed_endpoint.fragment)
    except ValueError:
        valid_endpoint = False
    if not valid_endpoint:
        a.gap("inventory", "EKS public API server HTTPS endpoint host not collected or malformed",
              "eks:DescribeCluster.cluster.endpoint")
        return a
    a.addresses = [endpoint]
    observed_cidrs = config.get("publicAccessCidrs")
    if observed_cidrs is not None and (not isinstance(observed_cidrs, list) or any(
            not isinstance(value, str) or _cidr(value) is None for value in observed_cidrs)):
        a.gap("source_ranges", "EKS public API CIDR list malformed",
              "eks:DescribeCluster.resourcesVpcConfig.publicAccessCidrs")
        return a
    cidrs = observed_cidrs or []
    defaulted = not cidrs
    if defaulted:
        cidrs = ["0.0.0.0/0"]
        network_config = cluster["cluster"].get("kubernetesNetworkConfig")
        hostname = parsed_endpoint.hostname
        if (isinstance(network_config, dict) and network_config.get("ipFamily") == "ipv6"
                and isinstance(hostname, str) and hostname.endswith(".api.aws")):
            cidrs.append("::/0")
    public = [c for c in cidrs if _public_source(c)]
    if public:
        a.step("source_ranges", "allow", public_access_cidrs=public,
               source="documented_default" if defaulted else "DescribeCluster",
               semantics="Observed or documented-default public client CIDR; EKS authentication still applies")
        a.ports = pset("tcp", 443, 443)
    else:
        a.step("source_ranges", "block", public_access_cidrs=cidrs)
        a.ports = {}
    return a


def _aws_lambda_url(snapshot, inventory, resource):
    data = resource["data"]
    url = data.get("FunctionUrl")
    if not isinstance(url, dict):
        a = Assessment(resource, "function_url")
        a.gap("inventory", "function URL configuration read missing", "lambda:GetFunctionUrlConfig")
        return a
    if url.get("collection_status") == "empty" and url.get("absent") is True:
        return None
    if url.get("collection_status") != "collected" or url.get("AuthType") not in ("NONE", "AWS_IAM"):
        a = Assessment(resource, "function_url")
        a.gap("inventory", f"function URL config {url.get('collection_status', 'not collected')} or auth type unresolved",
              "lambda:GetFunctionUrlConfig")
        return a
    url_arn = url.get("FunctionArn")
    expected_arn = data.get("AliasArn") if resource["type"] == "lambda_alias" else data.get("FunctionArn")
    accepted_arns = {expected_arn} if resource["type"] == "lambda_alias" else {expected_arn, f"{expected_arn}:$LATEST"}
    if (not isinstance(expected_arn, str) or not expected_arn or
            not isinstance(url_arn, str) or url_arn not in accepted_arns):
        a = Assessment(resource, "function_url")
        a.gap("inventory", "function URL target ARN not collected or mismatched",
              "lambda:GetFunctionUrlConfig.FunctionArn")
        return a
    endpoint = url.get("FunctionUrl")
    try:
        parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
        region = url_arn.split(":")[3]
        valid_endpoint = (parsed is not None and parsed.scheme == "https"
                          and isinstance(parsed.hostname, str)
                          and re.fullmatch(r"[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws", parsed.hostname)
                          and parsed.hostname.endswith(f".lambda-url.{region}.on.aws")
                          and parsed.port is None and parsed.username is None and parsed.password is None
                          and parsed.path in ("", "/") and not parsed.query and not parsed.fragment)
    except (IndexError, ValueError):
        valid_endpoint = False
    if not valid_endpoint:
        a = Assessment(resource, "function_url")
        a.gap("inventory", "function URL endpoint or alias identity unresolved", "lambda:GetFunctionUrlConfig.FunctionUrl")
        return a
    a = Assessment(resource, "function_url")
    a.addresses = [endpoint]
    a.ports = pset("tcp", 443, 443)
    if url.get("AuthType") == "AWS_IAM":
        a.step("authorization", "allow", auth_type=url.get("AuthType"))
        a.authenticated = True
        policy = data.get("Policy")
        if not isinstance(policy, dict) or not (policy.get("absent") is True or policy.get("collection_status") == "collected" and "Policy" in policy):
            a.gap("policy", "AWS_IAM Function URL resource policy not collected", "lambda:GetPolicy")
            a.explicit = "UNKNOWN"
            return a
        if policy.get("collection_status") == "collected":
            from .iam import document
            from fnmatch import fnmatchcase
            statements = as_list((document(policy["Policy"]) or {}).get("Statement"))
            function_arn = url.get("FunctionArn") or data.get("FunctionArn") or data.get("AliasArn")
            account = resource["scope"].split("/", 1)[0]
            grants = {}
            if not any(isinstance(statement, dict) and statement.get("Effect") == "Deny" for statement in statements):
                for statement in statements:
                    if (not isinstance(statement, dict) or statement.get("Effect") != "Allow"
                            or any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource"))
                            or not isinstance(function_arn, str) or function_arn not in as_list(statement.get("Resource"))):
                        continue
                    conditions = statement.get("Condition") or {}
                    if not isinstance(conditions, dict):
                        continue
                    applicable = True
                    for operator, terms in conditions.items():
                        if not isinstance(terms, dict) or operator not in ("StringEquals", "Bool"):
                            applicable = False
                            break
                        for key, value in terms.items():
                            if isinstance(value, list):
                                value = value[0] if len(value) == 1 else None
                            expected = ("AWS_IAM" if operator == "StringEquals" and isinstance(key, str)
                                        and key.casefold() == "lambda:functionurlauthtype" else
                                        "true" if operator == "Bool" and isinstance(key, str)
                                        and key.casefold() == "lambda:invokedviafunctionurl" else None)
                            if expected is None or not isinstance(value, (str, bool)) or str(value).casefold() != expected.casefold():
                                applicable = False
                                break
                        if not applicable:
                            break
                    if not applicable:
                        continue
                    principal = statement.get("Principal")
                    principals = [principal] if isinstance(principal, str) else as_list(principal.get("AWS")) if isinstance(principal, dict) else []
                    actions = [value.casefold() for value in as_list(statement.get("Action")) if isinstance(value, str)]
                    matched = {action for action in ("lambda:invokefunctionurl", "lambda:invokefunction")
                               if any(fnmatchcase(action, pattern) for pattern in actions)}
                    for value in principals:
                        identity = re.fullmatch(r"arn:[^:]+:iam::([0-9]{12}):(?:root|role/.+|user/.+)", value) if isinstance(value, str) else None
                        if value == "*" or identity and identity.group(1) != account:
                            grants.setdefault(value, set()).update(matched)
            for principal, actions in sorted(grants.items()):
                if {"lambda:invokefunctionurl", "lambda:invokefunction"} <= actions:
                    a.step("policy", "allow_declaration", principal=principal, actions=sorted(actions),
                           function_arn=function_arn,
                           semantics="Collected resource policy grants URL invocation to an external AWS principal; SigV4 and caller identity policy are still required, and no invocation was observed")
                    a.explicit = "UNKNOWN"
        a.notes.append("Function URL requires SigV4 (AWS_IAM); external caller identity permissions are not collected")
        if a.explicit is None:
            a.explicit = "PASS"
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
        if created_date is None or created_date < date(2025, 11, 1):
            if public:
                a.gap("policy", "Function URL creation falls before or within the undocumented October 2025 permission cutover", "lambda:GetFunctionUrlConfig")
            else:
                a.step("policy", "block", reason="no public URL invocation grant")
                a.ports = {}
        else:
            a.step("policy", "block", reason="new Function URL requires both public invocation grants", public_actions=sorted(public))
            a.ports = {}
    return a


def _aws_lambda_direct_invoke(snapshot, inventory, resource):
    """Find an owned function or alias policy granting foreign direct invocation."""
    from .trust import trusted_scopes
    from .iam import document
    from fnmatch import fnmatchcase

    data = resource["data"]
    read = data.get("Policy")
    if isinstance(read, dict) and read.get("absent") is True:
        return None
    a = Assessment(resource, "external_lambda_invoke")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    kind = resource["type"]
    arn = data.get("AliasArn") if kind == "lambda_alias" else data.get("FunctionArn")
    if not isinstance(arn, str) or not re.fullmatch(
            r"arn:" + partition + r":lambda:" + re.escape(region) + ":" +
            re.escape(account) + r":function:[A-Za-z0-9_.-]+" +
            (r":[A-Za-z0-9_-]+" if kind == "lambda_alias" else r":[0-9]+" if kind == "lambda_version" else ""), arn):
        a.gap("inventory", "Lambda policy resource is not attributable to the scoped function")
        return a
    if kind == "lambda_version" and (data.get("BaseFunctionArn") != arn.rsplit(":", 1)[0] or data.get("Version") != arn.rsplit(":", 1)[1]):
        a.gap("inventory", "Lambda version policy identity is inconsistent with the published function version")
        return a
    if not isinstance(read, dict) or read.get("collection_status") != "collected":
        a.gap("inventory", "Lambda function policy read is incomplete", "lambda:GetPolicy")
        return a
    doc = document(read.get("Policy"))
    statements = doc.get("Statement") if isinstance(doc, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "Lambda function policy statements are malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, uncertain = set(), False
    for statement in statements:
        actions = as_list(statement.get("Action"))
        if not all(isinstance(x, str) for x in actions):
            uncertain = True
            continue
        if not any(fnmatchcase("lambda:invokefunction", x.casefold()) for x in actions):
            continue
        resources = as_list(statement.get("Resource"))
        if not all(isinstance(x, str) for x in resources):
            uncertain = True
            continue
        if not any(fnmatchcase(arn, x) for x in resources):
            continue
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if statement.get("Effect") != "Allow" or statement.get("Condition") or any(
                key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain = True
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, dict) else principal
        principals = [principal] if isinstance(principal, str) else principal
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            uncertain = True
            continue
        for value in principals:
            if value == "*":
                foreign.add("*")
                continue
            match = re.fullmatch(r"arn:" + partition + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
            owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner not in trusted:
                foreign.add(owner)
    if foreign and not uncertain:
        a.external_ids = sorted(foreign)
        a.authenticated = True
        a.explicit = "FAIL"
        a.step("resource_policy", "allow", function_arn=arn, external_principals=sorted(foreign), action="lambda:InvokeFunction")
        a.gap("caller", "The foreign caller's identity policy and any invocation were not observed")
        return a
    if foreign or uncertain:
        a.gap("policy", "Lambda policy conditions or Deny applicability are unresolved")
        return a
    return None


def _aws_lambda_layer_share(snapshot, inventory, resource):
    """A version-scoped Lambda layer policy granting cross-account code access."""
    from .trust import trusted_scopes
    from .iam import document
    from fnmatch import fnmatchcase

    data = resource["data"]
    read = data.get("Policy")
    if isinstance(read, dict) and read.get("absent") is True:
        return None
    a = Assessment(resource, "external_layer_share")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    name, number = data.get("LayerName"), data.get("Version")
    base, arn = data.get("LayerArn"), data.get("LayerVersionArn")
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9-_]+", name) or
            not isinstance(number, int) or isinstance(number, bool) or number < 1 or
            base != f"arn:{partition}:lambda:{region}:{account}:layer:{name}" or
            arn != f"{base}:{number}"):
        a.gap("inventory", "Lambda layer version ARN is not attributable to the scoped layer")
        return a
    if not isinstance(read, dict) or read.get("collection_status") != "collected":
        a.gap("inventory", "Lambda layer policy read is incomplete", "lambda:GetLayerVersionPolicy")
        return a
    doc = document(read.get("Policy"))
    statements = doc.get("Statement") if isinstance(doc, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "Lambda layer policy statements are malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, uncertain = set(), False
    for statement in statements:
        actions = as_list(statement.get("Action"))
        if not all(isinstance(x, str) for x in actions):
            uncertain = True
            continue
        if not any(fnmatchcase("lambda:getlayerversion", x.casefold()) for x in actions):
            continue
        resources = as_list(statement.get("Resource"))
        if not all(isinstance(x, str) for x in resources):
            uncertain = True
            continue
        if not any(fnmatchcase(arn, x) for x in resources):
            continue
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if statement.get("Effect") != "Allow" or statement.get("Condition") or any(
                key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain = True
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, dict) else principal
        principals = [principal] if isinstance(principal, str) else principal
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            uncertain = True
            continue
        for value in principals:
            if value == "*":
                foreign.add("*")
                continue
            match = re.fullmatch(r"arn:" + partition + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
            owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner not in trusted:
                foreign.add(owner)
    if foreign and not uncertain:
        a.external_ids = sorted(foreign)
        a.authenticated = True
        a.explicit = "FAIL"
        a.step("resource_policy", "allow", layer_version_arn=arn, external_principals=sorted(foreign), action="lambda:GetLayerVersion")
        a.gap("caller", "The foreign caller's identity policy and any layer download were not observed")
        return a
    if foreign or uncertain:
        a.gap("policy", "Lambda layer policy conditions or Deny applicability are unresolved")
        return a
    return None


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
    stage_read = data.get("Stages")
    active_stage_names = ({s.get("stageName") for s in as_list(stage_read.get("items")) if isinstance(s, dict)
                           and isinstance(s.get("deploymentId"), str) and s.get("deploymentId")}
                          if isinstance(stage_read, dict) and stage_read.get("collection_status") in ("collected", "empty") else None)
    reachable_stage_names = set(active_stage_names or ()) if data.get("disableExecuteApiEndpoint") is not True else set()
    endpoint_config = data.get("endpointConfiguration")
    types = endpoint_config.get("types") if isinstance(endpoint_config, dict) else None
    if (not isinstance(types, list) or not types or any(value not in ("EDGE", "REGIONAL", "PRIVATE") for value in types)
            or "PRIVATE" in types and len(types) != 1):
        a.gap("inventory", "REST API endpoint type not collected or malformed",
              "apigateway:GetRestApi.endpointConfiguration.types")
        return a
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
                continue
            else:
                ordered = rules["items"]
                valid = all(isinstance(rule, dict) and type(rule.get("Priority")) is int
                            and 1 <= rule["Priority"] <= 1000000
                            and type(rule.get("ConditionCount")) is int and 0 <= rule["ConditionCount"] <= 3
                            and isinstance(rule.get("Actions"), list) and len(rule["Actions"]) == 1
                            and isinstance(rule["Actions"][0], dict)
                            and isinstance(rule["Actions"][0].get("InvokeApi"), dict)
                            and isinstance(rule["Actions"][0]["InvokeApi"].get("ApiId"), str)
                            and isinstance(rule["Actions"][0]["InvokeApi"].get("Stage"), str)
                            for rule in ordered)
                valid = valid and len({rule["Priority"] for rule in ordered}) == len(ordered)
                if not valid:
                    routing_domains.append(domain["data"].get("domainName") or native_id(domain))
                    continue
                catch_all = False
                for index, rule in enumerate(sorted(ordered, key=lambda item: item["Priority"])):
                    invoke = rule["Actions"][0]["InvokeApi"]
                    if invoke["ApiId"] == native_id(resource):
                        if active_stage_names is None:
                            routing_domains.append(domain["data"].get("domainName") or native_id(domain))
                        elif index == 0 and rule["ConditionCount"] == 0:
                            if invoke["Stage"] in active_stage_names:
                                domains.append(str(domain["data"].get("domainName") or native_id(domain)))
                                reachable_stage_names.add(invoke["Stage"])
                        elif index == 0 and rule["ConditionCount"] == 1 and rule.get("SingleHeaderCondition") is True:
                            if invoke["Stage"] in active_stage_names:
                                domains.append(str(domain["data"].get("domainName") or native_id(domain)))
                                reachable_stage_names.add(invoke["Stage"])
                                a.step("routing_condition", "allow", domain=domain["data"].get("domainName"),
                                       condition_kind="single_header", condition_count=1,
                                       semantics="A client-supplied header can select this first-priority rule; no request was made")
                        elif (index == 0 and invoke.get("StripBasePath") is True
                              and ((rule["ConditionCount"] == 1 and rule.get("SingleBasePathCondition") is True)
                                   or (rule["ConditionCount"] == 2 and rule.get("HeaderAndBasePathConditions") is True))):
                            if invoke["Stage"] in active_stage_names:
                                domains.append(str(domain["data"].get("domainName") or native_id(domain)))
                                reachable_stage_names.add(invoke["Stage"])
                                a.step("routing_condition", "allow", domain=domain["data"].get("domainName"),
                                       condition_kind="header_and_base_path_strip" if rule["ConditionCount"] == 2 else "single_base_path_strip",
                                       condition_count=rule["ConditionCount"],
                                       semantics="Client-supplied base path and optional header select this first-priority rule; the base path is stripped before the deployed method; no request was made")
                        elif invoke["Stage"] in active_stage_names:
                            # Header/path conditions and earlier rules require a
                            # request witness before this target can be claimed.
                            routing_domains.append(domain["data"].get("domainName") or native_id(domain))
                    if rule["ConditionCount"] == 0:
                        catch_all = True
                        break
            if "ONLY" in routing_mode or catch_all:
                continue
        mappings = domain["data"].get("BasePathMappings") or {}
        if mappings.get("collection_status") not in ("collected", "empty"):
            unresolved_domains.append(domain["data"].get("domainName") or native_id(domain))
            continue
        for mapping in as_list(mappings.get("items")):
            if not isinstance(mapping, dict) or mapping.get("restApiId") != native_id(resource):
                continue
            if active_stage_names is not None and mapping.get("stage") in active_stage_names:
                domains.append(str(domain["data"].get("domainName") or native_id(domain)))
                reachable_stage_names.add(mapping["stage"])
            elif active_stage_names is None or not isinstance(mapping.get("stage"), str):
                unresolved_domains.append(domain["data"].get("domainName") or native_id(domain))
    if data.get("disableExecuteApiEndpoint") is True and not domains:
        a.step("route", "unresolved", endpoint_types=types, disable_execute_api_endpoint=True,
               semantics="Live REST API flag requires a stage update before it blocks the default endpoint")
        a.gap("inventory", "stage-applied default execute-api endpoint state not observable from collected API/stage reads",
              "apigateway:GetStage stage-applied disableExecuteApiEndpoint (not exposed)")
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
    if data.get("disableExecuteApiEndpoint") is True:
        a.gap("default_route", "stage-applied default execute-api endpoint block is not observed",
              "apigateway:GetStage stage-applied disableExecuteApiEndpoint (not exposed)")
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
    from .iam import document
    policy_document = document(policy) or {}
    account, region = resource["scope"].split("/", 1)
    api_id = native_id(resource)
    broad_arn = re.compile(r"arn:[^:]+:execute-api:" + re.escape(region) + ":" + re.escape(account) + ":" +
                           re.escape(api_id) + r"/\*(?:/\*/\*)?")
    for statement in as_list(policy_document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Deny" or statement.get("Condition") or any(
                key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            continue
        principal = statement.get("Principal")
        principals = [principal] if isinstance(principal, str) else as_list(principal.get("AWS")) if isinstance(principal, dict) else []
        actions = [action.casefold() for action in as_list(statement.get("Action")) if isinstance(action, str)]
        resources = as_list(statement.get("Resource"))
        if ("*" in principals and any(action in ("*", "execute-api:*", "execute-api:invoke") for action in actions)
                and any(isinstance(value, str) and (value in ("*", "execute-api:/*") or broad_arn.fullmatch(value))
                        for value in resources)):
            a.step("policy", "block", reason="unconditional wildcard-principal Invoke Deny covers all API stages, methods and paths",
                   denied_action="execute-api:Invoke", denied_resource_scope="all_api_routes")
            a.ports = {}
            return a
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
    policy = policy_document
    conditional_denies = [statement.get("Condition") for statement in as_list(policy.get("Statement"))
        if isinstance(statement, dict) and statement.get("Effect") == "Deny" and statement.get("Condition")]
    if conditional_denies:
        a.step("policy", "allow", conditional_denies=conditional_denies,
               semantics="Caller source restrictions apply; configured custom domain may still have a public edge")
        a.authenticated = True
    a.ports = pset("tcp", 443, 443)
    method_state = inventory.state("rest_api_method", resource["scope"])
    stages = {s.get("stageName"): s.get("deploymentId") for s in as_list(stage_read.get("items"))
              if isinstance(s, dict) and s.get("stageName") in reachable_stage_names}
    methods, seen = [], set()
    for item in inventory.items("rest_api_method"):
        if item["scope"] != resource["scope"] or item["data"].get("restApiId") != native_id(resource):
            continue
        row = item["data"]
        stage_arn = row.get("stageArn")
        match = re.fullmatch(r"arn:[^:]+:apigateway:([^:]+)::/restapis/([^/]+)/stages/([^/]+)", stage_arn) if isinstance(stage_arn, str) else None
        if not match or match.group(1) != resource["scope"].rsplit("/", 1)[-1] or match.group(2) != native_id(resource):
            a.gap("authorization", "deployed method stage identity malformed", "apigateway:GetDeployment")
            return a
        stage_name = match.group(3)
        if stage_name not in reachable_stage_names:
            continue
        identity = (stage_name, row.get("resourcePath"), row.get("httpMethod"))
        if (row.get("deploymentId") != stages.get(stage_name)
                or (row.get("_provenance") or {}).get("stage_deployment_join_verified") is not True
                or not isinstance(row.get("resourcePath"), str) or not row["resourcePath"].startswith("/")
                or row.get("httpMethod") not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "ANY")
                or row.get("authorizationType") not in ("NONE", "AWS_IAM", "CUSTOM", "COGNITO_USER_POOLS")
                or type(row.get("apiKeyRequired")) is not bool or identity in seen):
            a.gap("authorization", "deployed method authorization, API key or stage join unresolved", "apigateway:GetDeployment")
            return a
        seen.add(identity)
        methods.append(row)
    open_methods = [f"{m['httpMethod']} {m['resourcePath']}@{m['stageArn'].rsplit('/', 1)[-1]}"
                    for m in methods if m["authorizationType"] == "NONE" and not m["apiKeyRequired"]]
    if open_methods:
        a.step("authorization", "allow", unauthenticated_methods=sorted(open_methods), source="deployed MethodSnapshot")
    elif method_state not in ("collected", "empty") or not methods:
        a.gap("authorization", "deployed REST method snapshot unavailable or incomplete", "apigateway:GetDeployment")
    else:
        a.step("authorization", "block", authentication_required=True, source="deployed MethodSnapshot")
        a.authenticated = True
        a.ports = {}
        if data.get("disableExecuteApiEndpoint") is True:
            a.explicit = "UNKNOWN"
    return a


def _aws_http_api(snapshot, inventory, resource):
    data = resource["data"]
    a = Assessment(resource, "api")
    stage_read = data.get("Stages")
    active_stage_names = ({s.get("StageName") for s in as_list(stage_read.get("items")) if isinstance(s, dict)
                           and (s.get("AutoDeploy") is True or isinstance(s.get("DeploymentId"), str) and s.get("DeploymentId"))}
                          if isinstance(stage_read, dict) and stage_read.get("collection_status") in ("collected", "empty") else None)
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
        if mappings.get("collection_status") not in ("collected", "empty"):
            unresolved_domains.append(domain_data.get("DomainName"))
            continue
        for mapping in as_list(mappings.get("items")):
            if not isinstance(mapping, dict) or mapping.get("ApiId") != data.get("ApiId"):
                continue
            name = domain_data.get("DomainName")
            if active_stage_names is not None and mapping.get("Stage") in active_stage_names and isinstance(name, str) and name:
                domains.append(name)
            elif active_stage_names is None or not isinstance(mapping.get("Stage"), str) or not isinstance(name, str):
                unresolved_domains.append(name or native_id(domain))
    if data.get("DisableExecuteApiEndpoint") is True and not domains:
        a.step("route", "unresolved", disable_execute_api_endpoint=True,
               semantics="Manual HTTP API stages require redeployment before the live disable flag blocks the default endpoint")
        a.gap("inventory", "stage-applied HTTP API default execute-api endpoint state not observed",
              "apigatewayv2:GetStage stage-applied DisableExecuteApiEndpoint (not exposed)")
        if unresolved_domains or inventory.state("apigatewayv2_domain_name", resource["scope"]) not in {"collected", "empty"}:
            a.gap("inventory", "HTTP API custom-domain mappings or routing rules are not fully collected",
                  "apigatewayv2 get_domain_names + get_api_mappings")
        a.explicit = "UNKNOWN"
        a.ports = {}
        return a
    if data.get("DisableExecuteApiEndpoint") is not True and data.get("ApiEndpoint"):
        a.addresses.append(data["ApiEndpoint"])
    a.addresses.extend(f"https://{name}" for name in sorted(set(domains)) if name)
    if data.get("DisableExecuteApiEndpoint") is True:
        a.gap("default_route", "stage-applied HTTP API default endpoint block not observed",
              "apigatewayv2:GetStage stage-applied DisableExecuteApiEndpoint (not exposed)")
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
    a.step("authorization", "unknown", live_route_count=len(routes) if isinstance(routes, list) else None,
           semantics="GetRoutes describes current API configuration, not the route snapshot deployed to an active stage")
    a.gap("authorization", "stage-bound HTTP API route authorization not collected", "apigatewayv2:ExportApi")
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


def _aws_redshift_snapshot_share(snapshot, inventory, resource):
    """Owner-visible Redshift manual snapshot restore authorizations."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_redshift_snapshot_share")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    cluster, name, arn = data.get("ClusterIdentifier"), data.get("SnapshotIdentifier"), data.get("SnapshotArn")
    if (not isinstance(cluster, str) or not cluster or not isinstance(name, str) or not name or
            arn != f"arn:{partition}:redshift:{region}:{account}:snapshot:{cluster}/{name}" or
            data.get("OwnerAccount") != account):
        a.gap("inventory", "Redshift snapshot identity or owner does not match the scoped account")
        return a
    if data.get("SnapshotType") != "manual":
        if data.get("SnapshotType") == "automated":
            return None
        a.gap("inventory", "Redshift snapshot type is unresolved")
        return a
    accounts = data.get("AccountsWithRestoreAccess", [])
    if accounts is None:
        accounts = []
    if not isinstance(accounts, list):
        a.gap("inventory", "Redshift restore authorization list is malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, uncertain = set(), False
    for row in accounts:
        if not isinstance(row, dict):
            uncertain = True
            continue
        account_id, alias = row.get("AccountId"), row.get("AccountAlias")
        if isinstance(account_id, str) and re.fullmatch(r"[0-9]{12}", account_id) and not alias:
            if account_id not in trusted:
                foreign.add(account_id)
        elif alias == "amazon-redshift-support" and not account_id:
            foreign.add(alias)
        else:
            uncertain = True
    if foreign:
        a.external_ids = sorted(foreign)
        if data.get("Status") == "available" and not uncertain:
            a.explicit = "FAIL"
            a.step("restore_authorization", "allow", snapshot_arn=arn, external_accounts=sorted(foreign))
            a.gap("restore", "Foreign caller IAM permission, any KMS access and actual restore were not observed")
        else:
            a.gap("inventory", "Redshift snapshot status or restore authorization is unresolved")
        return a
    if uncertain:
        a.gap("inventory", "Redshift restore authorization owner is unresolved")
        return a
    return None


def _aws_redshift_serverless_snapshot_share(snapshot, inventory, resource):
    """Owner-visible Redshift Serverless restore grants to either restore target."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_redshift_serverless_snapshot_share")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    arn = data.get("snapshotArn")
    if (not isinstance(arn, str) or not re.fullmatch(r"arn:" + partition + r":redshift-serverless:" +
            re.escape(region) + ":" + re.escape(account) + r":snapshot/[A-Za-z0-9-]+", arn) or
            data.get("ownerAccount") != account or data.get("id", arn) != arn):
        a.gap("inventory", "Redshift Serverless snapshot ARN or owner does not match the scoped account")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, uncertain = {}, False
    for field, target in (("accountsWithRestoreAccess", "namespace"),
                          ("accountsWithProvisionedRestoreAccess", "provisioned_cluster")):
        values = data.get(field, [])
        if values is None:
            values = []
        if not isinstance(values, list):
            uncertain = True
            continue
        for value in values:
            if not isinstance(value, str) or not re.fullmatch(r"[0-9]{12}", value):
                uncertain = True
            elif value not in trusted:
                foreign.setdefault(target, set()).add(value)
    if foreign:
        a.external_ids = sorted({value for accounts in foreign.values() for value in accounts})
        if data.get("status") == "AVAILABLE" and not uncertain:
            a.explicit = "FAIL"
            a.step("restore_authorization", "allow", snapshot_arn=arn,
                   external_targets={target: sorted(accounts) for target, accounts in sorted(foreign.items())})
            a.gap("restore", "Foreign caller IAM permission, any KMS access and actual restore were not observed")
        else:
            a.gap("inventory", "Redshift Serverless snapshot status or restore authorization is unresolved")
        return a
    if uncertain:
        a.gap("inventory", "Redshift Serverless restore authorization list is malformed")
        return a
    return None


def _aws_cluster_snapshot_share(snapshot, inventory, resource):
    """DocumentDB or Neptune manual snapshot restore authorization."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_cluster_snapshot_share")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    name, arn = data.get("DBClusterSnapshotIdentifier"), data.get("DBClusterSnapshotArn")
    if (not isinstance(name, str) or not name or
            arn != f"arn:{partition}:rds:{region}:{account}:cluster-snapshot:{name}" or
            data.get("id", arn) != arn):
        a.gap("inventory", "Cluster snapshot ARN is not attributable to the scoped account")
        return a
    if data.get("SnapshotType") in ("automated", "awsbackup"):
        return None
    if data.get("SnapshotType") != "manual":
        a.gap("inventory", "Cluster snapshot type is unresolved")
        return a
    read = data.get("Attributes")
    service = "docdb" if resource["type"] == "docdb_cluster_snapshot" else "neptune"
    if data.get("Engine") not in (None, service):
        a.gap("inventory", "Cluster snapshot engine does not match the source service")
        return a
    if not isinstance(read, dict) or read.get("collection_status") != "collected":
        a.gap("inventory", "Cluster snapshot restore attributes are incomplete", f"{service}:DescribeDBClusterSnapshotAttributes")
        return a
    result = read.get("DBClusterSnapshotAttributesResult")
    if not isinstance(result, dict) or result.get("DBClusterSnapshotIdentifier") != name:
        a.gap("inventory", "Cluster snapshot attribute result does not match the snapshot")
        return a
    attributes = result.get("DBClusterSnapshotAttributes")
    if not isinstance(attributes, list) or any(not isinstance(row, dict) for row in attributes):
        a.gap("inventory", "Cluster snapshot restore attributes are malformed")
        return a
    restore = [row for row in attributes if row.get("AttributeName") == "restore"]
    if len(restore) != 1 or not isinstance(restore[0].get("AttributeValues"), list):
        a.gap("inventory", "Cluster snapshot restore values are missing or malformed")
        return a
    values = restore[0]["AttributeValues"]
    if any(not isinstance(value, str) or not value for value in values):
        a.gap("inventory", "Cluster snapshot restore recipient is malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign = sorted({value for value in values if re.fullmatch(r"[0-9]{12}", value) and value not in trusted})
    invalid = [value for value in values if value != "all" and not re.fullmatch(r"[0-9]{12}", value)]
    public = "all" in values
    if invalid:
        a.gap("inventory", "Cluster snapshot restore recipient is not an account ID")
        return a
    if public and data.get("StorageEncrypted") is not False:
        a.gap("inventory", "Public snapshot grant conflicts with encrypted or unknown storage state")
        return a
    if (public or foreign) and data.get("Status") != "available":
        a.gap("inventory", "Cluster snapshot availability is unresolved")
        return a
    if public or foreign:
        a.external_ids = ["*"] if public else foreign
        a.data_exposure = public
        a.explicit = "FAIL"
        a.step("restore_authorization", "allow", snapshot_arn=arn, external_recipients=a.external_ids,
               semantics="Public or foreign copy/restore authorization; KMS and actual copy/restore unverified")
        if data.get("StorageEncrypted") is True:
            a.gap("kms", "Foreign KMS access and encrypted snapshot copy were not observed")
        return a
    return None


def _aws_ec2_share(snapshot, inventory, resource, field, coverage_field, permission_key):
    """Report only observed EC2 snapshot/image launch grants; missing reads stay unknown."""
    from .trust import trusted_scopes
    data = resource["data"]
    a = Assessment(resource, "data_share")
    coverage = (data.get("_coverage") or {}).get(coverage_field, {})
    permissions = data.get(field)
    if resource["type"] == "ec2_image" and data.get("Public") is True:
        account = str(resource.get("scope", "")).split("/", 1)[0]
        if data.get("OwnerId") not in (None, account):
            a.gap("inventory", "Public AMI owner does not match the scanned account")
            return a
        a.step("image_public_flag", "allow", image_id=data.get("ImageId"), public=True,
               image_state=data.get("State"))
        if coverage.get("status") not in ("collected", "empty") or not isinstance(permissions, list):
            a.gap("attributes", "Launch permission detail is incomplete; DescribeImages.Public proves the public grant",
                  "ec2:DescribeImageAttribute")
        a.data_exposure = True
        a.ports = {}
        a.explicit = "FAIL"
        return a
    if coverage.get("status") not in ("collected", "empty") or not isinstance(permissions, list):
        a.gap("attributes", f"{coverage_field} not completely collected", f"ec2:{permission_key}")
        return a
    public = any(p == {"Group": "all"} for p in permissions)
    selectors = {"UserId", "Group"} | ({"OrganizationArn", "OrganizationalUnitArn"} if resource["type"] == "ec2_image" else set())
    if not all(isinstance(p, dict) and len(p) == 1 and next(iter(p)) in selectors and
               isinstance(next(iter(p.values())), str) and next(iter(p.values())) for p in permissions):
        if not public:
            a.gap("attributes", f"{coverage_field} malformed", f"ec2:{permission_key}")
            return a
        a.gap("attributes", f"Additional {coverage_field} entries malformed", f"ec2:{permission_key}")
        permissions = [{"Group": "all"}]
    if any(("UserId" in p and not re.fullmatch(r"[0-9]{12}", p["UserId"])) or
           ("Group" in p and p["Group"] != "all") for p in permissions):
        if not public:
            a.gap("attributes", f"{coverage_field} selector is unresolved", f"ec2:{permission_key}")
            return a
        a.gap("attributes", f"Additional {coverage_field} selectors unresolved", f"ec2:{permission_key}")
        permissions = [{"Group": "all"}]
    trusted = trusted_scopes(snapshot)["ids"]
    external = {p["UserId"] for p in permissions if "UserId" in p and p["UserId"] not in trusted}
    unresolved = False
    if resource["type"] == "ec2_image":
        account = str(resource.get("scope", "")).split("/", 1)[0]
        key = ("aws_organization_id", account)
        if key not in inventory.network_cache:
            configs = [r["data"].get("Organization") for r in inventory.items("aws_account_configuration")
                       if r["scope"].split("/", 1)[0] == account]
            valid = [(c["OrganizationId"], c["MasterAccountId"]) for c in configs if isinstance(c, dict)
                     and c.get("collection_status") == "collected" and
                     re.fullmatch(r"o-[a-z0-9]{10,32}", str(c.get("OrganizationId", ""))) and
                     re.fullmatch(r"[0-9]{12}", str(c.get("MasterAccountId", "")))]
            inventory.network_cache[key] = valid[0] if len(configs) == len(valid) == 1 else None
        own_organization = inventory.network_cache[key]
        for permission in permissions:
            field_name = next(iter(permission))
            if field_name not in ("OrganizationArn", "OrganizationalUnitArn"):
                continue
            arn = permission[field_name]
            pattern = (r"arn:[^:]+:organizations::([0-9]{12}):organization/(o-[a-z0-9]{10,32})" if field_name == "OrganizationArn" else
                       r"arn:[^:]+:organizations::([0-9]{12}):ou/(o-[a-z0-9]{10,32})/ou-[a-z0-9-]+")
            match = re.fullmatch(pattern, arn)
            if match is None or own_organization is None:
                unresolved = True
            elif match.group(2) != own_organization[0]:
                external.add(arn)
            elif match.group(1) != own_organization[1]:
                unresolved = True
    external = sorted(external)
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
        a.step("attributes", "allow", external_principals=external)
        a.kind = "external_share"
        a.external_ids = external
        a.explicit = "FAIL"
        if unresolved:
            a.gap("attributes", "Additional AMI organization or OU scope is unresolved")
    elif unresolved:
        a.gap("attributes", "AMI organization or OU sharing scope is unresolved", "organizations:DescribeOrganization")
    else:
        a.step("attributes", "block", permission_count=len(permissions))
        a.ports = {}
    return a


def _aws_ram_share(snapshot, inventory, resource):
    """Assess effective RAM associations, not the allowExternalPrincipals capability flag."""
    from .trust import trusted_scopes

    data = resource["data"]
    if data.get("status") in ("DELETING", "DELETED", "FAILED"):
        return None
    a = Assessment(resource, "external_share")
    if data.get("status") != "ACTIVE":
        a.gap("share", "RAM share status unresolved", "ram:GetResourceShares")
        return a
    associations = {}
    for field in ("ResourceAssociations", "PrincipalAssociations"):
        part = data.get(field)
        if not isinstance(part, dict) or part.get("collection_status") != "collected":
            a.gap("associations", f"RAM {field} not completely collected", "ram:GetResourceShareAssociations")
            return a
        rows = part.get("resourceShareAssociations")
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            a.gap("associations", f"RAM {field} malformed", "ram:GetResourceShareAssociations")
            return a
        if any(row.get("status") not in ("ASSOCIATED", "FAILED", "DISASSOCIATED") for row in rows):
            a.gap("associations", f"RAM {field} has a pending association", "ram:GetResourceShareAssociations")
            return a
        associations[field] = sorted({row["associatedEntity"] for row in rows
                                      if row.get("status") == "ASSOCIATED" and isinstance(row.get("associatedEntity"), str)})
        if any(row.get("status") == "ASSOCIATED" and not isinstance(row.get("associatedEntity"), str) for row in rows):
            a.gap("associations", f"RAM {field} identity missing", "ram:GetResourceShareAssociations")
            return a
    resources = associations["ResourceAssociations"]
    if not resources:
        a.step("associations", "block", reason="no associated resources")
        a.ports = {}
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    principals = data["PrincipalAssociations"]["resourceShareAssociations"]
    foreign = []
    unresolved = []
    for row in principals:
        if row.get("status") != "ASSOCIATED":
            continue
        principal = row["associatedEntity"]
        if row.get("external") is True:
            foreign.append(principal)
            continue
        if row.get("external") is False:
            continue
        if principal in trusted:
            continue
        if re.fullmatch(r"[0-9]{12}", principal):
            foreign.append(principal)
            continue
        match = re.fullmatch(r"arn:[^:]+:iam::([0-9]{12}):(?:role|user)/.+", principal)
        if match:
            if match.group(1) not in trusted:
                foreign.append(principal)
            continue
        unresolved.append(principal)
    if foreign:
        a.step("associations", "allow", resources=resources, external_principals=sorted(set(foreign)))
        a.external_ids = sorted(set(foreign))
        a.explicit = "FAIL"
    elif unresolved:
        a.gap("associations", "RAM principal scope unresolved", "ram:GetResourceShareAssociations")
    else:
        a.step("associations", "block", resources=resources, principal_count=len(associations["PrincipalAssociations"]))
        a.ports = {}
    return a


def _aws_vpc_peering(snapshot, inventory, resource):
    """Identify an active foreign peer with a local route into the connection."""
    from .trust import trusted_scopes

    data = resource["data"]
    status = data.get("Status")
    state = status.get("Code") if isinstance(status, dict) else None
    if state in ("deleted", "deleting", "rejected", "expired", "failed", "pending-acceptance", "initiating-request", "provisioning"):
        return None
    a = Assessment(resource, "external_network")
    if state != "active":
        a.gap("connection", "VPC peering state is not active or is unresolved")
        return a
    account = str(resource.get("scope", "")).split("/", 1)[0]
    requester, accepter = data.get("RequesterVpcInfo"), data.get("AccepterVpcInfo")
    if not isinstance(requester, dict) or not isinstance(accepter, dict):
        a.gap("inventory", "VPC peering owners or VPC IDs are not collected")
        return a
    sides = [(requester, accepter), (accepter, requester)]
    local = next((side for side in sides if side[0].get("OwnerId") == account), None)
    if local is None or not all(isinstance(value, str) and value for value in
                                (local[0].get("VpcId"), local[1].get("VpcId"))) or not re.fullmatch(r"[0-9]{12}", str(local[1].get("OwnerId", ""))):
        a.gap("inventory", "Local and peer VPC ownership could not be resolved")
        return a
    peer = local[1]["OwnerId"]
    if peer in trusted_scopes(snapshot)["ids"]:
        return None
    peer_id = data.get("VpcPeeringConnectionId")
    if not isinstance(peer_id, str) or not peer_id:
        a.gap("inventory", "VPC peering connection ID is missing")
        return a
    routes = []
    malformed = False
    for table in inventory.items("route_table"):
        if table["scope"].split("/", 1)[0] != account or table["data"].get("VpcId") != local[0]["VpcId"]:
            continue
        entries = table["data"].get("Routes")
        if not isinstance(entries, list):
            malformed = True
            continue
        if any(not isinstance(route, dict) for route in entries):
            malformed = True
        routes.extend({"route_table": table["data"].get("RouteTableId"),
                       "destination": route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")}
                      for route in entries if isinstance(route, dict) and route.get("VpcPeeringConnectionId") == peer_id
                      and route.get("State") == "active")
    if routes:
        a.step("peering_route", "allow", local_vpc=local[0]["VpcId"], peer_vpc=local[1]["VpcId"],
               peer_account=peer, routes=routes)
        a.external_ids = [peer]
        a.explicit = "FAIL"
        a.gap("backend", "Peer-side route, subnet ACL, security group and application access are not established")
    elif inventory.state("route_table", resource["scope"]) in ("collected", "empty") and not malformed:
        a.step("peering_route", "block", local_vpc=local[0]["VpcId"], peer_account=peer,
               reason="no active local route to this peer")
        a.ports = {}
    else:
        a.gap("peering_route", "Local route-table inventory is incomplete", "ec2:DescribeRouteTables")
    return a


def _aws_tgw_foreign_attachment(snapshot, inventory, resource):
    """Join a local VPC route and TGW route to an available foreign VPC attachment."""
    from .trust import trusted_scopes

    data = resource["data"]
    if data.get("ResourceType") != "vpc" or data.get("State") in ("deleted", "deleting", "failed", "rejected"):
        return None
    account = str(resource.get("scope", "")).split("/", 1)[0]
    owner = str(data.get("ResourceOwnerId", ""))
    gateway = data.get("TransitGatewayId")
    attachment = data.get("TransitGatewayAttachmentId")
    if owner in trusted_scopes(snapshot)["ids"]:
        return None
    a = Assessment(resource, "external_network")
    if (data.get("State") != "available" or data.get("TransitGatewayOwnerId") != account or
            not re.fullmatch(r"[0-9]{12}", owner) or not all(isinstance(value, str) and value for value in (gateway, attachment))):
        a.gap("inventory", "Foreign VPC attachment state or owner is unresolved")
        return a
    local = [row for row in inventory.items("transit_gateway_attachment")
             if row["scope"] == resource["scope"] and row["data"].get("TransitGatewayId") == gateway
             and row["data"].get("TransitGatewayOwnerId") == account
             and row["data"].get("ResourceOwnerId") == account and row["data"].get("ResourceType") == "vpc"
             and row["data"].get("State") == "available"]
    for near in local:
        info = near["data"]
        assoc = info.get("Association")
        table_id = assoc.get("TransitGatewayRouteTableId") if isinstance(assoc, dict) and assoc.get("State") == "associated" else None
        table = inventory.get("transit_gateway_route_table", table_id)
        if table is None or table["scope"] != resource["scope"] or table["data"].get("TransitGatewayId") != gateway or table["data"].get("State") != "available":
            continue
        route_inventory = table["data"].get("RouteInventory")
        associations = table["data"].get("AssociationInventory")
        if (not isinstance(route_inventory, dict) or route_inventory.get("collection_status") not in ("collected", "empty") or
                route_inventory.get("queries") != ["type=static", "type=propagated"] or not isinstance(route_inventory.get("items"), list) or
                not isinstance(associations, dict) or associations.get("collection_status") not in ("collected", "empty") or
                not isinstance(associations.get("items"), list) or not any(isinstance(row, dict) and
                row.get("TransitGatewayAttachmentId") == info.get("TransitGatewayAttachmentId") and row.get("State") == "associated"
                for row in associations["items"])):
            continue
        target_routes = []
        for route in route_inventory["items"]:
            if not isinstance(route, dict) or route.get("State") != "active" or route.get("Type") not in ("static", "propagated"):
                continue
            targets = route.get("TransitGatewayAttachments")
            if (not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], dict) or
                    targets[0].get("TransitGatewayAttachmentId") != attachment or
                    targets[0].get("ResourceType") != "vpc" or targets[0].get("ResourceId") != data.get("ResourceId")):
                continue
            destination = _cidr(route.get("DestinationCidrBlock"))
            if destination is not None:
                target_routes.append(destination)
        for vpc_table in inventory.items("route_table"):
            if vpc_table["scope"] != resource["scope"] or vpc_table["data"].get("VpcId") != info.get("ResourceId"):
                continue
            vpc_routes = vpc_table["data"].get("Routes")
            if not isinstance(vpc_routes, list):
                continue
            for vpc_route in vpc_routes:
                if not isinstance(vpc_route, dict) or vpc_route.get("TransitGatewayId") != gateway or vpc_route.get("State") != "active":
                    continue
                local_destination = _cidr(vpc_route.get("DestinationCidrBlock") or vpc_route.get("DestinationIpv6CidrBlock"))
                for foreign_destination in target_routes:
                    if local_destination is None or not local_destination.overlaps(foreign_destination):
                        continue
                    a.step("transit_route", "allow", local_vpc=info.get("ResourceId"), foreign_attachment=attachment,
                           foreign_account=owner, vpc_route_table=vpc_table["data"].get("RouteTableId"),
                           gateway_route_table=table_id, destination=str(foreign_destination))
                    a.external_ids = [owner]
                    a.explicit = "FAIL"
                    a.gap("backend", "Foreign return route, subnet ACL, security group and application access are not established")
                    return a
    a.gap("transit_route", "A complete route from a local VPC through this gateway to the foreign attachment was not established")
    return a


def _aws_vpn_connection(snapshot, inventory, resource):
    """Report the public IPsec frontend, separately from routed tunnel traffic."""
    data = resource["data"]
    if data.get("State") in ("deleted", "deleting"):
        return None
    a = Assessment(resource, "vpn_gateway")
    options = data.get("Options")
    if not isinstance(options, dict) or data.get("State") != "available":
        a.gap("inventory", "VPN connection state or outside address mode is unresolved")
        return a
    mode = options.get("OutsideIpAddressType", "PublicIpv4")
    if mode == "PrivateIpv4":
        a.ports = {}
        a.step("vpn_transport", "block", outside_address_type=mode)
        return a
    if mode not in ("PublicIpv4", "Ipv6"):
        a.gap("inventory", "VPN outside address mode is unsupported or malformed")
        return a
    telemetry = data.get("VgwTelemetry")
    tunnels = options.get("TunnelOptions")
    if not isinstance(telemetry, list) or not isinstance(tunnels, list):
        a.gap("inventory", "VPN tunnel outside addresses are not completely collected")
        return a
    rows = telemetry + tunnels
    if not rows or any(not isinstance(row, dict) for row in rows):
        a.gap("inventory", "VPN tunnel outside address records are missing or malformed")
        return a
    addresses = sorted({row["OutsideIpAddress"] for row in rows
                        if isinstance(row.get("OutsideIpAddress"), str) and _public_ip(row["OutsideIpAddress"])})
    if not addresses:
        a.gap("inventory", "Public VPN tunnel outside address is absent or malformed")
        return a
    a.addresses = addresses
    a.ports = union(pset("udp", 500, 500), pset("udp", 4500, 4500))
    a.ports["esp"] = ((0, 0),)
    a.authenticated = True
    a.step("vpn_transport", "allow", addresses=addresses, protocols=["udp/500", "udp/4500", "esp"])
    a.notes.append("Public IPsec tunnel endpoints require peer authentication; tunnel routes and downstream controls are separate")
    return a


def _aws_client_vpn_endpoint(snapshot, inventory, resource):
    """Assess the managed OpenVPN listener, not post-login destination access."""
    data = resource["data"]
    status = data.get("Status")
    state = status.get("Code") if isinstance(status, dict) else None
    a = Assessment(resource, "vpn_gateway")
    if state in ("pending-associate", "pending", "deleting", "deleted"):
        a.ports = {}
        a.step("endpoint_state", "block", state=state)
        return a
    if state != "available":
        a.gap("inventory", "Client VPN endpoint state is unresolved")
        return a
    dns = data.get("DnsName")
    if not isinstance(dns, str) or not dns.strip():
        a.gap("inventory", "Available Client VPN endpoint has no collected DNS name")
        return a
    protocol = data.get("TransportProtocol", "udp")
    port = data.get("VpnPort", 443)
    if protocol not in ("tcp", "udp") or port not in (443, 1194):
        a.gap("inventory", "Client VPN transport protocol or port is malformed")
        return a
    a.endpoint = dns
    a.ports = pset(protocol, port, port)
    a.authenticated = True
    a.step("managed_vpn_listener", "allow", dns_name=a.endpoint, protocol=protocol, port=port)
    a.notes.append("Client VPN requires authentication; authorization rules and routes control post-login destinations")
    return a


def _aws_client_vpn_all_clients_authorization(snapshot, inventory, resource):
    """An active Client VPN rule admitting every authenticated client to a CIDR."""
    data = resource["data"]
    read = data.get("AuthorizationRules")
    if read is None:
        return None
    a = Assessment(resource, "vpn_client_authorization")
    endpoint = data.get("ClientVpnEndpointId")
    if (not isinstance(endpoint, str) or not re.fullmatch(r"cvpn-endpoint-[a-z0-9]+", endpoint) or
            not isinstance(read, dict) or read.get("ClientVpnEndpointId") != endpoint):
        a.gap("inventory", "Client VPN authorization rules are not bound to the scoped endpoint")
        return a
    state = (data.get("Status") or {}).get("Code") if isinstance(data.get("Status"), dict) else None
    if state in {"pending-associate", "pending", "deleting", "deleted"}:
        return None
    if state != "available":
        a.gap("inventory", "Client VPN endpoint state is unresolved")
        return a
    status = read.get("collection_status")
    rules = read.get("items")
    if status not in {"collected", "empty", "partial"} or not isinstance(rules, list):
        a.gap("inventory", "Client VPN authorization rule read is incomplete")
        return a
    destinations, uncertain = [], status == "partial"
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("Status"), dict):
            uncertain = True
            continue
        rule_state = rule["Status"].get("Code")
        if rule_state != "active":
            if rule_state not in {"authorizing", "revoking", "failed"}:
                uncertain = True
            continue
        all_groups = rule.get("AuthorizeAllGroups")
        if type(all_groups) is not bool:
            uncertain = True
            continue
        if not all_groups:
            continue
        cidr = rule.get("DestinationCidr")
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except (TypeError, ValueError):
            uncertain = True
            continue
        destinations.append(str(network))
    if destinations and not uncertain:
        a.authenticated = True
        a.explicit = "FAIL"
        a.step("client_authorization", "allow", endpoint_id=endpoint,
               destination_cidrs=sorted(set(destinations)))
        routing = inventory.get("client_vpn_routing", endpoint)
        detail = routing["data"] if routing is not None and routing["scope"] == resource["scope"] else {}
        routes, targets = detail.get("Routes"), detail.get("TargetNetworks")
        if (isinstance(routes, dict) and routes.get("ClientVpnEndpointId") == endpoint and
                routes.get("collection_status") in {"collected", "empty"} and
                isinstance(routes.get("items"), list) and
                isinstance(targets, dict) and targets.get("ClientVpnEndpointId") == endpoint and
                targets.get("collection_status") in {"collected", "empty"} and
                isinstance(targets.get("items"), list)):
            associated, malformed = {}, False
            for target in targets["items"]:
                if not isinstance(target, dict) or target.get("ClientVpnEndpointId") != endpoint:
                    malformed = True
                    continue
                if (isinstance(target.get("Status"), dict) and target["Status"].get("Code") == "associated" and
                        isinstance(target.get("TargetNetworkId"), str) and
                        re.fullmatch(r"subnet-[a-z0-9]+", target["TargetNetworkId"]) and
                        isinstance(target.get("AssociationId"), str) and
                        re.fullmatch(r"cvpn-assoc-[a-z0-9]+", target["AssociationId"]) and
                        isinstance(target.get("VpcId"), str) and re.fullmatch(r"vpc-[a-z0-9]+", target["VpcId"])):
                    if target["TargetNetworkId"] in associated:
                        malformed = True
                    associated[target["TargetNetworkId"]] = target
                elif isinstance(target.get("Status"), dict) and target["Status"].get("Code") == "associated":
                    malformed = True
            matched = []
            for route in routes["items"]:
                if not isinstance(route, dict) or route.get("ClientVpnEndpointId") != endpoint or not isinstance(route.get("Status"), dict):
                    malformed = True
                    continue
                if route["Status"].get("Code") != "active":
                    continue
                try:
                    route_network = ipaddress.ip_network(route.get("DestinationCidr"), strict=True)
                except (TypeError, ValueError):
                    malformed = True
                    continue
                subnet = route.get("TargetSubnet")
                if not isinstance(subnet, str):
                    malformed = True
                    continue
                target = associated.get(subnet)
                if target and any(route_network.version == (network := ipaddress.ip_network(cidr)).version and
                                  route_network.overlaps(network) for cidr in destinations):
                    matched.append({"route_cidr": str(route_network), "target_subnet": route["TargetSubnet"],
                                    "vpc_id": target["VpcId"], "association_id": target.get("AssociationId"),
                                    "security_groups": target.get("SecurityGroups", [])})
            if matched and not malformed:
                a.step("client_route", "allow", routes=matched)
                a.gap("destination", "Destination security groups, NACLs, device policy and actual traffic were not verified")
            else:
                a.gap("route", "No validated active Client VPN route and associated target subnet joins this authorization rule")
        else:
            a.gap("route", "Client VPN route or target-network association read is incomplete")
        a.gap("caller", "Client authentication, device policy and actual traffic were not observed")
        return a
    if destinations or uncertain:
        a.gap("authorization", "Client VPN all-client authorization status or destination is unresolved")
        return a
    return None


def _aws_vpc_endpoint_service(snapshot, inventory, resource):
    """Classify PrivateLink invitations and accepted cross-account connections."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_share")
    state = data.get("ServiceState")
    if state in ("Deleted", "Deleting", "Failed"):
        return None
    if state != "Available":
        a.gap("inventory", "VPC endpoint service state is unresolved")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    connections = data.get("EndpointConnections")
    active_foreign = []
    connections_complete = isinstance(connections, list)
    if connections_complete:
        for row in connections:
            if not isinstance(row, dict) or row.get("ServiceId") != data.get("ServiceId"):
                connections_complete = False
                break
            connection_state = row.get("VpcEndpointState")
            if connection_state == "Available":
                owner = row.get("VpcEndpointOwner")
                endpoint_id = row.get("VpcEndpointId")
                if not isinstance(owner, str) or not re.fullmatch(r"[0-9]{12}", owner) or not isinstance(endpoint_id, str):
                    connections_complete = False
                    break
                if owner not in trusted:
                    active_foreign.append({"account": owner, "endpoint": endpoint_id})
            elif connection_state not in ("PendingAcceptance", "Pending", "Deleting", "Deleted", "Rejected", "Failed", "Expired"):
                connections_complete = False
                break
    if not connections_complete:
        a.gap("inventory", "VPC endpoint service connections are not completely collected",
              "ec2:DescribeVpcEndpointConnections")
    principals = data.get("AllowedPrincipals")
    principals_complete = isinstance(principals, list) and all(isinstance(p, str) for p in principals)
    if not principals_complete:
        a.gap("inventory", "VPC endpoint service allowed principals are not completely collected",
              "ec2:DescribeVpcEndpointServicePermissions")
        principals = []
    external = []
    unknown = []
    for principal in principals:
        if principal == "*":
            external.append(principal)
            continue
        match = re.fullmatch(r"arn:[^:]+:iam::([0-9]{12}):(?:root|role/.+|user/.+)", principal)
        if match:
            if match.group(1) not in trusted:
                external.append(principal)
        else:
            unknown.append(principal)
    if external or active_foreign:
        a.external_ids = sorted(set(external) | {row["account"] for row in active_foreign})
        a.explicit = "FAIL"
        if external:
            a.step("allowed_principals", "allow", external_principals=sorted(set(external)),
                   acceptance_required=data.get("AcceptanceRequired"))
            a.notes.append("Allowed principals can request PrivateLink connections; manual acceptance and backend access are separate")
        if active_foreign:
            a.step("endpoint_connections", "allow", active_external_connections=active_foreign)
            a.notes.append("Available external endpoints remain connected even if their principals were removed from the allowlist")
    elif unknown:
        a.gap("inventory", "VPC endpoint service principal scope is unresolved")
    elif principals_complete and connections_complete:
        a.ports = {}
        a.step("external_access", "block", principal_count=len(principals), connection_count=len(connections))
    return a


def _aws_ecr_registry_replication(snapshot, inventory, resource):
    """Identify configured ECR image replication to a foreign registry."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_share")
    replication = data.get("Replication")
    if not isinstance(replication, dict) or replication.get("collection_status") != "collected":
        a.gap("inventory", "ECR registry replication configuration is not completely collected", "ecr:DescribeRegistry")
        return a
    rules = replication.get("rules")
    if not isinstance(rules, list):
        a.gap("inventory", "ECR registry replication rules are malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    external = []
    malformed = False
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("destinations"), list):
            malformed = True
            continue
        filters = rule.get("repositoryFilters", [])
        if not isinstance(filters, list) or any(not isinstance(f, dict) or f.get("filterType") != "PREFIX_MATCH"
                                                or not isinstance(f.get("filter"), str) for f in filters):
            malformed = True
            continue
        for destination in rule["destinations"]:
            if not isinstance(destination, dict):
                malformed = True
                continue
            account = destination.get("registryId")
            region = destination.get("region")
            if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account) or not isinstance(region, str) or not region:
                malformed = True
                continue
            if account not in trusted:
                external.append({"account": account, "region": region,
                                 "repository_prefixes": sorted(f["filter"] for f in filters)})
    if malformed:
        a.gap("inventory", "Some ECR replication destinations or filters are malformed")
    if external:
        a.external_ids = sorted({row["account"] for row in external})
        a.explicit = "FAIL"
        a.step("replication", "allow", external_destinations=external)
        a.notes.append("Destination registry permission is required; the source account cannot prove completed replication")
    elif not malformed:
        a.ports = {}
        a.step("replication", "block", rule_count=len(rules))
    return a


def _aws_ecr_registry_policy_pull(snapshot, inventory, resource):
    """A private-registry policy granting foreign image-pull actions."""
    from .trust import trusted_scopes
    from fnmatch import fnmatchcase

    data = resource["data"]
    read = data.get("RegistryPolicy")
    if isinstance(read, dict) and read.get("absent") is True:
        return None
    a = Assessment(resource, "external_registry_policy_pull")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    if not re.fullmatch(r"[0-9]{12}", account) or data.get("registryId") != account:
        a.gap("inventory", "ECR registry identity does not match the scoped account")
        return a
    if not isinstance(read, dict) or read.get("collection_status") != "collected":
        a.gap("inventory", "ECR registry policy read is incomplete", "ecr:GetRegistryPolicy")
        return a
    policy = read.get("policyText")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = None
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "ECR registry policy statements are malformed")
        return a
    prefix = f"arn:{partition}:ecr:{region}:{account}:repository/"
    required = ("ecr:batchgetimage", "ecr:getdownloadurlforlayer")
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, patterns, uncertain = set(), set(), False
    for statement in statements:
        if statement.get("Effect") == "Deny" and any(key in statement for key in ("NotAction", "NotResource", "NotPrincipal")):
            uncertain = True
            continue
        actions = as_list(statement.get("Action"))
        if not all(isinstance(x, str) for x in actions):
            uncertain = True
            continue
        matched = {action for action in required if any(fnmatchcase(action, value.casefold()) for value in actions)}
        if not matched:
            continue
        resources = as_list(statement.get("Resource"))
        if not all(isinstance(x, str) for x in resources):
            uncertain = True
            continue
        owned = [value for value in resources if value == "*" or value.startswith(prefix) and len(value) > len(prefix)]
        if not owned:
            continue
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if len(matched) != len(required):
            continue
        if statement.get("Effect") != "Allow" or statement.get("Condition") or any(
                key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain = True
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, dict) else principal
        principals = [principal] if isinstance(principal, str) else principal
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            uncertain = True
            continue
        for value in principals:
            if value == "*":
                foreign.add("*")
                patterns.update(owned)
                continue
            match = re.fullmatch(r"arn:" + partition + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
            owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner not in trusted:
                foreign.add(owner)
                patterns.update(owned)
    if foreign and not uncertain:
        a.external_ids = sorted(foreign)
        a.authenticated = True
        a.explicit = "FAIL"
        a.step("registry_policy", "allow", resource_patterns=sorted(patterns), external_principals=sorted(foreign),
               actions=["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"])
        a.gap("caller", "Authorization token, identity permissions, matching repositories and image pulls were not observed")
        return a
    if foreign or uncertain:
        a.gap("policy", "ECR registry pull grant, conditions or Deny applicability are unresolved")
        return a
    return None


def _aws_ecr_template_pull(snapshot, inventory, resource):
    """A creation template that would attach a foreign pull policy to future repositories."""
    from .trust import trusted_scopes
    from fnmatch import fnmatchcase

    data = resource["data"]
    a = Assessment(resource, "external_registry_template_pull")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    if not re.fullmatch(r"[0-9]{12}", account) or data.get("registryId") != account:
        a.gap("inventory", "ECR registry identity does not match the scoped account")
        return a
    read = data.get("RepositoryCreationTemplates")
    if not isinstance(read, dict) or read.get("collection_status") not in ("collected", "empty"):
        a.gap("inventory", "ECR repository creation templates are incompletely collected", "ecr:DescribeRepositoryCreationTemplates")
        return a
    templates = read.get("items")
    if not isinstance(templates, list):
        a.gap("inventory", "ECR repository creation template list is malformed")
        return a
    if not templates and read.get("collection_status") == "empty":
        return None
    trusted = trusted_scopes(snapshot)["ids"]
    required = ("ecr:batchgetimage", "ecr:getdownloadurlforlayer")
    grants, uncertain = [], False
    for template in templates:
        if not isinstance(template, dict):
            uncertain = True
            continue
        prefix, workflows = template.get("prefix"), template.get("appliedFor")
        if (not isinstance(prefix, str) or not prefix or
                not isinstance(workflows, list) or not workflows or
                any(value not in ("PULL_THROUGH_CACHE", "CREATE_ON_PUSH", "REPLICATION") for value in workflows)):
            uncertain = True
            continue
        policy = template.get("repositoryPolicy")
        if policy is None:
            continue
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except ValueError:
                policy = None
        statements = policy.get("Statement") if isinstance(policy, dict) else None
        statements = [statements] if isinstance(statements, dict) else statements
        if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
            uncertain = True
            continue
        for statement in statements:
            if statement.get("Effect") == "Deny" and any(key in statement for key in ("NotAction", "NotResource", "NotPrincipal")):
                uncertain = True
                continue
            actions = as_list(statement.get("Action"))
            if not all(isinstance(x, str) for x in actions):
                uncertain = True
                continue
            matched = {action for action in required if any(fnmatchcase(action, value.casefold()) for value in actions)}
            if not matched:
                continue
            resources = as_list(statement.get("Resource", "*"))
            if resources != ["*"]:
                uncertain = True
                continue
            if statement.get("Effect") == "Deny":
                uncertain = True
                continue
            if len(matched) != len(required):
                continue
            if statement.get("Effect") != "Allow" or statement.get("Condition") or any(
                    key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
                uncertain = True
                continue
            principal = statement.get("Principal")
            principal = principal.get("AWS") if isinstance(principal, dict) else principal
            principals = [principal] if isinstance(principal, str) else principal
            if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
                uncertain = True
                continue
            for value in principals:
                if value == "*":
                    grants.append({"principal": "*", "prefix": prefix, "workflows": sorted(set(workflows))})
                    continue
                match = re.fullmatch(r"arn:" + partition + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
                owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
                if owner is None:
                    uncertain = True
                elif owner not in trusted:
                    grants.append({"principal": owner, "prefix": prefix, "workflows": sorted(set(workflows))})
    if grants and not uncertain:
        a.external_ids = sorted({row["principal"] for row in grants})
        a.authenticated = True
        a.dormant = True
        a.explicit = "FAIL"
        a.step("repository_creation_template", "allow", future_grants=grants)
        a.gap("creation", "Templates affect only future ECR-created repositories; matching repository creation and image pulls were not observed")
        return a
    if grants or uncertain:
        a.gap("policy", "ECR template policy, conditions or Deny applicability are unresolved")
        return a
    return None


def _aws_generic_resource_policy_grant(snapshot, inventory, resource):
    """A source-attributed resource policy declaring access for a foreign AWS principal."""
    from .trust import trusted_scopes
    from fnmatch import fnmatchcase

    data = resource["data"]
    provenance = data.get("_provenance")
    a = Assessment(resource, "external_generic_policy_grant")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    arn = data.get("ResourceArn")
    if (not isinstance(provenance, dict) or provenance.get("read_only") is not True or
            provenance.get("owner_account") != account or not isinstance(provenance.get("families"), list) or
            not provenance["families"] or any(not isinstance(x, str) for x in provenance["families"]) or
            not isinstance(arn, str)):
        a.gap("inventory", "Resource policy source or owner is not attributable to the scanned account")
        return a
    parts = arn.split(":", 5)
    if (len(parts) != 6 or parts[0] != "arn" or parts[1] != partition or
            parts[3] not in (region, "") or parts[4] not in (account, "") or not parts[5] or
            (parts[4] == "" and not all(str(family).startswith("s3-") for family in provenance["families"]))):
        a.gap("inventory", "Resource policy ARN is outside the owned partition, account or Region")
        return a
    policy = data.get("Policy")
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "Resource policy statements are malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    # The base families have separate, more precise checks for these actions.
    dedicated = {"sns": {"sns:subscribe"}, "sqs": {"sqs:receivemessage"},
                 "lambda": {"lambda:invokefunction", "lambda:invokefunctionurl"},
                 "ecr": {"ecr:batchgetimage", "ecr:getdownloadurlforlayer"}}
    excluded_actions = dedicated.get(parts[2], set()) if "covered_services" in provenance else set()
    grants, uncertain, candidate = [], False, False
    for statement in statements:
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if statement.get("Effect") != "Allow":
            uncertain = True
            continue
        actions = as_list(statement.get("Action"))
        if not actions or any(not isinstance(value, str) or not value for value in actions):
            uncertain = True
            continue
        actions = [value for value in actions if value.lower() not in excluded_actions]
        if not actions:
            continue
        resources = as_list(statement.get("Resource", arn))
        if not resources or any(not isinstance(value, str) or not value for value in resources):
            uncertain = True
            continue
        if not any(value == "*" or fnmatchcase(arn, value) or
                   value.startswith(arn + "/") or value.startswith(arn + ":") for value in resources):
            continue
        principal = statement.get("Principal")
        if principal == "*":
            principals = ["*"]
        elif isinstance(principal, dict) and "AWS" in principal:
            principals = as_list(principal["AWS"])
        elif isinstance(principal, dict) and "AWS" not in principal:
            continue  # Service/federated principals require service-specific semantics.
        else:
            uncertain = True
            continue
        if not principals or any(not isinstance(value, str) for value in principals):
            uncertain = True
            continue
        for value in principals:
            if value == "*":
                owner = "*"
            else:
                match = re.fullmatch(r"arn:" + partition + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
                owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner == "*" or owner not in trusted:
                candidate = True
                if statement.get("Condition") or any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
                    uncertain = True
                else:
                    grants.append({"account": owner, "actions": sorted(set(actions))})
    if grants and not uncertain:
        a.external_ids = sorted({grant["account"] for grant in grants})
        a.authenticated = True
        a.explicit = "FAIL"
        a.step("resource_policy", "allow", resource_arn=arn, source_families=provenance["families"],
               external_grants=grants)
        a.gap("caller", "Caller identity permissions, service-specific prerequisites and actual use were not observed")
        return a
    if grants or candidate:
        a.gap("policy", "Resource policy conditions, Deny or foreign principal applicability are unresolved")
        return a
    return None


def _aws_role_foreign_assumption(snapshot, inventory, resource):
    """An owned role trust policy declaring AssumeRole to a foreign AWS principal."""
    from .iam import assume_role_document
    from fnmatch import fnmatchcase

    data = resource["data"]
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    arn, name = data.get("Arn"), data.get("RoleName")
    if (not isinstance(name, str) or not name or not isinstance(arn, str) or
            not re.fullmatch(r"arn:" + re.escape(partition) + r":iam::" + re.escape(account) +
                             r":role/(?:[^/]+/)*" + re.escape(name), arn)):
        a = Assessment(resource, "external_generic_policy_grant")
        a.gap("inventory", "IAM role trust policy is not attributable to the scoped role")
        return a
    policy = assume_role_document(resource)
    if policy is None:
        a = Assessment(resource, "external_generic_policy_grant")
        a.gap("inventory", "IAM role trust policy is missing or malformed")
        return a
    statements = as_list(policy.get("Statement"))
    relevant = []
    for statement in statements:
        if not isinstance(statement, dict):
            relevant.append(statement)
            continue
        if statement.get("Effect") == "Deny" and "NotAction" in statement:
            relevant.append(statement)  # Could deny AssumeRole even without an Action field.
            continue
        actions = as_list(statement.get("Action"))
        matched = [action for action in actions if isinstance(action, str) and
                   fnmatchcase("sts:assumerole", action.lower())]
        if matched:
            relevant.append({**statement, "Action": matched})
    if not relevant:
        return None
    attributed = {**resource, "data": {"ResourceArn": arn, "Policy": {"Statement": relevant},
        "_provenance": {"read_only": True, "owner_account": account,
                        "source_region": region, "families": ["iam-role-trust"],
                        "source_operations": ["iam:GetRole"]}}}
    return _aws_generic_resource_policy_grant(snapshot, inventory, attributed)


def _aws_ecr_repository_share(snapshot, inventory, resource):
    """Identify a declared private-image pull grant to a named foreign principal."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_registry_share")
    account, _, region = str(resource.get("scope", "")).partition("/")
    arn = data.get("repositoryArn")
    name = data.get("repositoryName")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    if (not isinstance(name, str) or not name or
            arn != f"arn:{partition}:ecr:{region}:{account}:repository/{name}" or
            data.get("registryId", account) != account):
        a.gap("inventory", "ECR repository identity is not attributable to the scoped account")
        return a
    read = data.get("Policy")
    if not isinstance(read, dict):
        a.gap("inventory", "ECR repository policy read is missing", "ecr:GetRepositoryPolicy")
        return a
    if read.get("collection_status") == "empty" and read.get("absent") is True:
        return None
    if read.get("collection_status") != "collected" or read.get("registryId", account) != account or read.get("repositoryName", name) != name:
        a.gap("inventory", "ECR repository policy read is incomplete or mismatched", "ecr:GetRepositoryPolicy")
        return a
    policy = read.get("policyText")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = None
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "ECR repository policy statements are malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, uncertain = set(), False
    for statement in statements:
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if statement.get("Effect") != "Allow":
            uncertain = True
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or any(not isinstance(x, str) for x in actions):
            uncertain = True
            continue
        actions = {x.casefold() for x in actions}
        if not ({"*", "ecr:*"} & actions or {"ecr:batchgetimage", "ecr:getdownloadurlforlayer"} <= actions):
            continue
        resources = statement.get("Resource", arn)
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or any(not isinstance(x, str) for x in resources):
            uncertain = True
            continue
        if "*" not in resources and arn not in resources:
            continue
        if statement.get("Condition") or "NotPrincipal" in statement or "NotAction" in statement or "NotResource" in statement:
            uncertain = True
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, dict) else principal
        principals = [principal] if isinstance(principal, str) else principal
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            uncertain = True
            continue
        for value in principals:
            match = re.fullmatch(r"arn:" + re.escape(partition) + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
            owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner not in trusted:
                foreign.add(owner)
    if foreign and not uncertain:
        a.external_ids = sorted(foreign)
        a.explicit = "FAIL"
        a.step("repository_policy", "allow", repository_arn=arn, external_accounts=sorted(foreign),
               actions=["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"])
        a.gap("caller", "Foreign principal authentication, authorization token and identity-side permissions were not observed")
        return a
    if foreign or uncertain:
        a.gap("policy", "ECR repository grant or Deny applicability is unresolved")
        return a
    return None


def _aws_secret_foreign_read(snapshot, inventory, resource):
    """A named foreign GetSecretValue grant with a potentially shareable key."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_secret_grant")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    arn, name = data.get("ARN"), data.get("Name")
    if (not isinstance(name, str) or not name or not isinstance(arn, str) or
            not re.fullmatch(r"arn:" + re.escape(partition) + r":secretsmanager:" + re.escape(region) +
                             r":" + re.escape(account) + r":secret:[^:]+", arn)):
        a.gap("inventory", "Secret identity is not attributable to the scoped account")
        return a
    read = data.get("Policy")
    if not isinstance(read, dict) or read.get("collection_status") != "collected":
        a.gap("inventory", "Secret resource policy read is incomplete", "secretsmanager:GetResourcePolicy")
        return a
    if "ResourcePolicy" not in read:
        return None
    if read.get("ARN") != arn or read.get("Name") != name:
        a.gap("inventory", "Secret resource policy is not bound to this secret")
        return a
    policy = read["ResourcePolicy"]
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = None
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "Secret resource policy statements are malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, uncertain = set(), False
    for statement in statements:
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if statement.get("Effect") != "Allow":
            uncertain = True
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or any(not isinstance(x, str) for x in actions):
            uncertain = True
            continue
        if not {x.casefold() for x in actions} & {"*", "secretsmanager:*", "secretsmanager:getsecretvalue"}:
            continue
        resources = statement.get("Resource", arn)
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or any(not isinstance(x, str) for x in resources):
            uncertain = True
            continue
        if "*" not in resources and arn not in resources:
            continue
        if statement.get("Condition") or any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain = True
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, dict) else principal
        principals = [principal] if isinstance(principal, str) else principal
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            uncertain = True
            continue
        for value in principals:
            match = re.fullmatch(r"arn:" + re.escape(partition) + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
            owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner not in trusted:
                foreign.add(owner)
    if not foreign and not uncertain:
        return None
    coverage = data.get("_coverage", {}).get("KmsKeyId") if isinstance(data.get("_coverage"), dict) else None
    if isinstance(coverage, dict) and coverage.get("status") == "empty" and coverage.get("documented_default") == "aws/secretsmanager":
        a.step("kms_key", "block", reason="AWS managed default key cannot be used for cross-account secret reads")
        a.ports = {}
        return a
    if (not isinstance(coverage, dict) or coverage.get("status") != "collected" or
            not isinstance(data.get("KmsKeyId"), str) or not data["KmsKeyId"] or
            data["KmsKeyId"] in ("alias/aws/secretsmanager", "aws/secretsmanager")):
        a.gap("kms_key", "Secret KMS key identity is missing or does not prove a shareable customer key", "secretsmanager:DescribeSecret")
        return a
    if foreign and not uncertain:
        a.external_ids = sorted(foreign)
        a.explicit = "FAIL"
        a.step("secret_policy", "allow", secret_arn=arn, external_accounts=sorted(foreign),
               action="secretsmanager:GetSecretValue")
        a.gap("caller", "Foreign caller identity permission and KMS Decrypt authorization were not observed")
        return a
    a.gap("policy", "Secret policy conditions or Deny applicability are unresolved")
    return a


def _aws_sqs_foreign_receive(snapshot, inventory, resource):
    """A named foreign ReceiveMessage grant on an owned SQS queue."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_queue_receive")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    url = data.get("QueueUrl")
    parsed = urlsplit(url) if isinstance(url, str) else None
    if (parsed is None or parsed.scheme != "https" or parsed.netloc != f"sqs.{region}.{suffix}" or
            parsed.query or parsed.fragment or
            not re.fullmatch(r"/" + re.escape(account) + r"/[A-Za-z0-9_-]{1,80}(?:\.fifo)?", parsed.path)):
        a.gap("inventory", "SQS queue URL is not attributable to the scoped account")
        return a
    name = parsed.path.rsplit("/", 1)[-1]
    arn = f"arn:{partition}:sqs:{region}:{account}:{name}"
    read = data.get("Attributes")
    if not isinstance(read, dict) or read.get("collection_status") != "collected":
        a.gap("inventory", "SQS queue attributes are incomplete", "sqs:GetQueueAttributes")
        return a
    attributes = read.get("Attributes")
    if not isinstance(attributes, dict) or attributes.get("QueueArn") != arn:
        a.gap("inventory", "SQS queue attributes are not bound to this queue")
        return a
    if "Policy" not in attributes:
        return None
    policy = attributes["Policy"]
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = None
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "SQS queue policy statements are malformed")
        return a
    foreign, uncertain = set(), False
    trusted = trusted_scopes(snapshot)["ids"]
    for statement in statements:
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if statement.get("Effect") != "Allow":
            uncertain = True
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or any(not isinstance(x, str) for x in actions):
            uncertain = True
            continue
        if not {x.casefold() for x in actions} & {"*", "sqs:*", "sqs:receivemessage"}:
            continue
        resources = statement.get("Resource", arn)
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or any(not isinstance(x, str) for x in resources):
            uncertain = True
            continue
        if "*" not in resources and arn not in resources:
            continue
        if statement.get("Condition") or any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain = True
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, dict) else principal
        principals = [principal] if isinstance(principal, str) else principal
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            uncertain = True
            continue
        for value in principals:
            match = re.fullmatch(r"arn:" + re.escape(partition) + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
            owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner not in trusted:
                foreign.add(owner)
    if not foreign and not uncertain:
        return None
    key = attributes.get("KmsMasterKeyId")
    key_coverage = attributes.get("_coverage", {}).get("KmsMasterKeyId") if isinstance(attributes.get("_coverage"), dict) else None
    if key == "" and isinstance(key_coverage, dict) and key_coverage.get("status") == "empty":
        key = None
    if key in ("alias/aws/sqs", "aws/sqs"):
        a.step("kms_key", "block", reason="AWS managed SQS KMS key cannot grant foreign decrypt")
        a.ports = {}
        return a
    if key is not None and (not isinstance(key, str) or not key):
        a.gap("kms_key", "SQS KMS key identity is malformed")
        return a
    if foreign and not uncertain:
        a.external_ids = sorted(foreign)
        a.explicit = "FAIL"
        a.step("queue_policy", "allow", queue_arn=arn, external_accounts=sorted(foreign), action="sqs:ReceiveMessage")
        a.gap("caller", "Foreign caller identity permission and any customer KMS Decrypt authorization were not observed")
        return a
    a.gap("policy", "SQS policy conditions or Deny applicability are unresolved")
    return a


def _aws_sns_foreign_subscription(snapshot, inventory, resource):
    """A confirmed subscription to an owned topic by a foreign account."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_topic_subscription")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    topic, subscription, owner, protocol = (data.get(key) for key in ("TopicArn", "SubscriptionArn", "Owner", "Protocol"))
    topic_match = re.fullmatch(r"arn:" + partition + r":sns:" + re.escape(region) + ":" + re.escape(account) +
                               r":([A-Za-z0-9_-]{1,256}(?:\.fifo)?)", topic) if isinstance(topic, str) else None
    if (topic_match is None or not isinstance(owner, str) or not re.fullmatch(r"[0-9]{12}", owner) or
            not isinstance(protocol, str) or not protocol):
        a.gap("inventory", "SNS topic subscription identity is not attributable to the scoped topic")
        return a
    if owner in trusted_scopes(snapshot)["ids"]:
        return None
    if subscription == "PendingConfirmation":
        a.gap("confirmation", "Foreign-owned SNS subscription has not been confirmed")
        return a
    if (not isinstance(subscription, str) or not re.fullmatch(r"arn:" + partition + r":sns:" +
            re.escape(region) + ":" + owner + ":" + re.escape(topic_match.group(1)) + r":[0-9a-fA-F-]{36}", subscription)):
        a.gap("inventory", "SNS subscription ARN does not match its foreign owner and topic")
        return a
    a.external_ids = [owner]
    a.explicit = "FAIL"
    a.step("subscription", "allow", topic_arn=topic, subscription_arn=subscription,
           subscriber_account=owner, protocol=protocol)
    a.gap("delivery", "Endpoint ownership and successful message delivery were not observed")
    return a


def _aws_sns_subscribe_grant(snapshot, inventory, resource):
    """A topic policy permitting a foreign principal to request subscription."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_topic_subscribe_grant")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    arn = data.get("TopicArn")
    if (not isinstance(arn, str) or not re.fullmatch(r"arn:" + partition + r":sns:" +
            re.escape(region) + ":" + re.escape(account) + r":[A-Za-z0-9_-]{1,256}(?:\.fifo)?", arn)):
        a.gap("inventory", "SNS topic ARN is not attributable to the scoped account")
        return a
    read = data.get("Attributes")
    if not isinstance(read, dict) or read.get("collection_status") != "collected":
        a.gap("inventory", "SNS topic attributes are incomplete", "sns:GetTopicAttributes")
        return a
    attrs = read.get("Attributes")
    if not isinstance(attrs, dict) or attrs.get("TopicArn") != arn or attrs.get("Owner") != account:
        a.gap("inventory", "SNS topic attributes are not bound to this owned topic")
        return a
    policy = attrs.get("Policy")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = None
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "SNS topic policy statements are malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, uncertain = set(), False
    for statement in statements:
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if statement.get("Effect") != "Allow":
            uncertain = True
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or any(not isinstance(x, str) for x in actions):
            uncertain = True
            continue
        if not {x.casefold() for x in actions} & {"*", "sns:*", "sns:subscribe"}:
            continue
        resources = statement.get("Resource", arn)
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or any(not isinstance(x, str) for x in resources):
            uncertain = True
            continue
        if "*" not in resources and arn not in resources:
            continue
        if statement.get("Condition") or any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain = True
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, dict) else principal
        principals = [principal] if isinstance(principal, str) else principal
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            uncertain = True
            continue
        for value in principals:
            if value == "*":
                foreign.add("*")
                continue
            match = re.fullmatch(r"arn:" + re.escape(partition) + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
            owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner not in trusted:
                foreign.add(owner)
    if foreign and not uncertain:
        a.external_ids = sorted(foreign)
        a.explicit = "FAIL"
        a.step("topic_policy", "allow", topic_arn=arn, external_principals=sorted(foreign), action="sns:Subscribe")
        a.gap("confirmation", "A subscription request, endpoint confirmation and successful delivery were not observed")
        return a
    if foreign or uncertain:
        a.gap("policy", "SNS topic policy conditions or Deny applicability are unresolved")
        return a
    return None


def _aws_kms_foreign_decrypt(snapshot, inventory, resource):
    """A key policy permitting foreign use of an enabled decrypt-capable key."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_kms_decrypt_grant")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    key_id = data.get("KeyId")
    metadata = data.get("Metadata")
    if (not isinstance(key_id, str) or not key_id or not isinstance(metadata, dict) or
            metadata.get("collection_status") != "collected"):
        a.gap("inventory", "KMS key metadata is incomplete", "kms:DescribeKey")
        return a
    native = metadata.get("KeyMetadata")
    arn = native.get("Arn") if isinstance(native, dict) else None
    if (not isinstance(native, dict) or native.get("KeyId") != key_id or
            not isinstance(arn, str) or not re.fullmatch(r"arn:" + partition + r":kms:" +
                re.escape(region) + ":" + re.escape(account) + r":key/[A-Za-z0-9-]+", arn) or
            data.get("KeyArn", arn) != arn):
        a.gap("inventory", "KMS key ARN is not attributable to the scoped key")
        return a
    if native.get("KeyManager") == "AWS" or native.get("KeyUsage") in ("SIGN_VERIFY", "GENERATE_VERIFY_MAC", "KEY_AGREEMENT"):
        return None
    if native.get("KeyManager") != "CUSTOMER" or native.get("KeyUsage") != "ENCRYPT_DECRYPT":
        a.gap("inventory", "KMS key manager or cryptographic usage is unresolved", "kms:DescribeKey")
        return a
    if native.get("KeyState") in ("Disabled", "PendingDeletion", "PendingImport") or native.get("Enabled") is False:
        a.step("key_state", "block", reason="KMS key cannot currently decrypt")
        a.ports = {}
        return a
    if native.get("KeyState") != "Enabled" or native.get("Enabled") is not True:
        a.gap("key_state", "KMS key enabled state is unresolved", "kms:DescribeKey")
        return a
    read = data.get("Policy")
    if not isinstance(read, dict) or read.get("collection_status") != "collected":
        a.gap("inventory", "KMS key policy read is incomplete", "kms:GetKeyPolicy")
        return a
    policy = read.get("Policy")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = None
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "KMS key policy statements are malformed")
        return a
    trusted = trusted_scopes(snapshot)["ids"]
    foreign, uncertain = set(), False
    for statement in statements:
        if statement.get("Effect") == "Deny":
            uncertain = True
            continue
        if statement.get("Effect") != "Allow":
            uncertain = True
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or any(not isinstance(x, str) for x in actions):
            uncertain = True
            continue
        if not {x.casefold() for x in actions} & {"*", "kms:*", "kms:decrypt"}:
            continue
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or "*" not in resources:
            uncertain = True
            continue
        if statement.get("Condition") or any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
            uncertain = True
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, dict) else principal
        principals = [principal] if isinstance(principal, str) else principal
        if not isinstance(principals, list) or any(not isinstance(x, str) for x in principals):
            uncertain = True
            continue
        for value in principals:
            if value == "*":
                foreign.add("*")
                continue
            match = re.fullmatch(r"arn:" + re.escape(partition) + r":iam::([0-9]{12}):(?:root|(?:role|user)/.+)", value)
            owner = value if re.fullmatch(r"[0-9]{12}", value) else match.group(1) if match else None
            if owner is None:
                uncertain = True
            elif owner not in trusted:
                foreign.add(owner)
    if foreign and not uncertain:
        a.external_ids = sorted(foreign)
        a.explicit = "FAIL"
        a.step("key_policy", "allow", key_arn=arn, external_principals=sorted(foreign), action="kms:Decrypt")
        a.gap("caller", "Foreign caller IAM permission and possession of decryptable ciphertext were not observed")
        return a
    if foreign or uncertain:
        a.gap("policy", "KMS key policy conditions or Deny applicability are unresolved")
        return a
    return None


def _aws_kms_foreign_grant(snapshot, inventory, resource):
    """A foreign Decrypt grantee on an enabled customer KMS key."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_kms_grant")
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    key_id, key_arn, grant_id = (data.get(key) for key in ("KeyId", "KeyArn", "GrantId"))
    if (not isinstance(key_id, str) or not key_id or not isinstance(grant_id, str) or not grant_id or
            not isinstance(key_arn, str) or key_arn != f"arn:{partition}:kms:{region}:{account}:key/{key_id}"):
        a.gap("inventory", "KMS grant key identity is incomplete or foreign")
        return a
    operations = data.get("Operations")
    if not isinstance(operations, list) or any(not isinstance(operation, str) for operation in operations):
        a.gap("inventory", "KMS grant operations are malformed")
        return a
    if "Decrypt" not in operations:
        return None
    grantee = data.get("GranteePrincipal")
    match = re.fullmatch(r"arn:" + re.escape(partition) + r":(?:iam|sts)::([0-9]{12}):(?:root|(?:role|user)/.+|assumed-role/.+)", grantee) if isinstance(grantee, str) else None
    owner = grantee if isinstance(grantee, str) and re.fullmatch(r"[0-9]{12}", grantee) else match.group(1) if match else None
    if owner is None:
        a.gap("grantee", "KMS grant grantee cannot be attributed to an AWS account")
        return a
    if owner in trusted_scopes(snapshot)["ids"]:
        return None
    if data.get("ConstraintKeys"):
        a.gap("constraint", "KMS grant encryption context or source constraint is not resolved")
        return a
    key = inventory.get("kms_key", key_arn)
    if key is None or key.get("scope") != resource.get("scope"):
        a.gap("inventory", "KMS grant has no matching collected key metadata", "kms:DescribeKey")
        return a
    detail = key["data"]
    metadata = detail.get("Metadata")
    native = metadata.get("KeyMetadata") if isinstance(metadata, dict) and metadata.get("collection_status") == "collected" else None
    if (not isinstance(native, dict) or native.get("Arn") != key_arn or native.get("KeyId") != key_id):
        a.gap("inventory", "KMS grant key metadata is incomplete or mismatched", "kms:DescribeKey")
        return a
    if native.get("KeyManager") == "AWS" or native.get("KeyUsage") in ("SIGN_VERIFY", "GENERATE_VERIFY_MAC", "KEY_AGREEMENT"):
        return None
    if native.get("KeyManager") != "CUSTOMER" or native.get("KeyUsage") != "ENCRYPT_DECRYPT":
        a.gap("inventory", "KMS grant key manager or usage is unresolved", "kms:DescribeKey")
        return a
    if native.get("KeyState") in ("Disabled", "PendingDeletion", "PendingImport") or native.get("Enabled") is False:
        a.step("key_state", "block", reason="KMS key cannot currently decrypt")
        a.ports = {}
        return a
    if native.get("KeyState") != "Enabled" or native.get("Enabled") is not True:
        a.gap("key_state", "KMS grant key enabled state is unresolved", "kms:DescribeKey")
        return a
    policy_read = detail.get("Policy")
    if not isinstance(policy_read, dict) or policy_read.get("collection_status") != "collected":
        a.gap("inventory", "KMS key policy read is needed to evaluate explicit Deny", "kms:GetKeyPolicy")
        return a
    policy = policy_read.get("Policy")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = None
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        a.gap("inventory", "KMS key policy statements are malformed")
        return a
    if any(statement.get("Effect") == "Deny" for statement in statements):
        a.gap("policy", "KMS key policy Deny applicability to the grantee is unresolved")
        return a
    a.external_ids = [owner]
    a.explicit = "FAIL"
    a.step("grant", "allow", key_arn=key_arn, grant_id=grant_id, grantee=grantee, action="kms:Decrypt")
    a.gap("caller", "Grantee identity controls, other denies and possession of decryptable ciphertext were not observed")
    return a


def _aws_ecr_public_repository(snapshot, inventory, resource):
    """An ECR Public repository is readable without a repository policy grant."""
    data = resource["data"]
    a = Assessment(resource, "public_registry")
    account = str(resource.get("scope", "")).split("/", 1)[0]
    name, arn, registry = data.get("repositoryName"), data.get("repositoryArn"), data.get("registryId")
    if (resource.get("scope", "").split("/")[-1] != "us-east-1" or
            not isinstance(name, str) or not re.fullmatch(r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*", name) or
            not isinstance(arn, str) or arn != f"arn:aws:ecr-public::{account}:repository/{name}" or
            registry != account):
        a.gap("inventory", "ECR Public repository identity or regional scope is incomplete")
        return a
    a.step("public_repository", "allow", repository_arn=arn, repository_name=name,
           repository_uri=data.get("repositoryUri") if isinstance(data.get("repositoryUri"), str) else None)
    a.explicit = "FAIL"
    a.gap("content", "Published image inventory and successful pull were not tested")
    return a


def _aws_log_subscription_export(snapshot, inventory, resource):
    """A log-group or account subscription aimed at a foreign logical destination."""
    from .trust import trusted_scopes

    data = resource["data"]
    a = Assessment(resource, "external_log_stream")
    scope = str(resource.get("scope", ""))
    account, _, region = scope.partition("/")
    destination = data.get("DestinationArn", data.get("destinationArn"))
    account_policy = resource["type"] == "log_account_subscription_policy"
    source = data.get("LogGroupArn")
    name = data.get("policyName") if account_policy else data.get("filterName")
    group = "account policy " + name if account_policy and isinstance(name, str) else data.get("logGroupName")
    if not all(isinstance(value, str) and value for value in (destination, name, group)):
        a.gap("inventory", "Log subscription source or destination identity is incomplete")
        return a
    if account_policy:
        if data.get("accountId") != account or data.get("policyType") != "SUBSCRIPTION_FILTER_POLICY":
            a.gap("inventory", "Log account policy is not attributable to the scoped account")
            return a
        partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    else:
        source_match = re.fullmatch(r"arn:([^:]+):logs:" + re.escape(region) + ":" + re.escape(account) +
                                    r":log-group:(.+)", source) if isinstance(source, str) else None
        if source_match is None or source_match.group(2) != group:
            a.gap("inventory", "Log subscription source is not the scoped log group")
            return a
        partition = source_match.group(1)
    target = re.fullmatch(r"arn:" + re.escape(partition) + r":logs:" + re.escape(region) +
                          r":([0-9]{12}):destination:([^:]+)", destination)
    if target is None:
        a.gap("inventory", "Log subscription destination is not an attributable logical destination")
        return a
    recipient = target.group(1)
    if recipient in trusted_scopes(snapshot)["ids"]:
        return None
    a.step("subscription", "allow", log_group=group, filter_name=name,
           destination_arn=destination, recipient_account=recipient)
    a.external_ids = [recipient]
    a.explicit = "FAIL"
    a.gap("delivery", "Recipient acceptance and successful log-event delivery were not observed")
    return a


def _aws_log_destination_policy_grant(snapshot, inventory, resource):
    """Assess the access policy returned with an owned logical log destination."""
    data = resource["data"]
    account, _, region = str(resource.get("scope", "")).partition("/")
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    arn, name = data.get("arn"), data.get("destinationName")
    if (not isinstance(arn, str) or not isinstance(name, str) or not name or ":" in name or
            arn != f"arn:{partition}:logs:{region}:{account}:destination:{name}"):
        a = Assessment(resource, "external_generic_policy_grant")
        a.gap("inventory", "CloudWatch Logs destination identity is not attributable to the scanned account")
        return a
    raw = data.get("accessPolicy")
    if raw is None or raw == "":
        return None
    try:
        policy = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        policy = None
    # DescribeDestinations returns the attached policy with the destination;
    # reuse the source/owner checks and conservative Allow/Deny logic.
    attributed = {**resource, "data": {"ResourceArn": arn, "Policy": policy,
        "_provenance": {"read_only": True, "owner_account": account,
                        "source_region": region, "families": ["logs-destinations"],
                        "source_operations": ["logs:DescribeDestinations"]}}}
    return _aws_generic_resource_policy_grant(snapshot, inventory, attributed)
def _cloudfront_staging_primary(inventory, staging):
    """Observed active primary policy that can route a viewer request to this staging DNS name."""
    domain = staging.get("DomainName")
    arn = staging.get("ARN")
    if not isinstance(domain, str) or not domain or not isinstance(arn, str):
        return None
    account = arn.split(":")[4] if len(arn.split(":")) > 4 else None
    matches = []
    for primary in inventory.items("cloudfront_distribution"):
        data = primary["data"]
        primary_arn = data.get("ARN")
        if (not isinstance(primary_arn, str) or len(primary_arn.split(":")) <= 4
                or primary_arn.split(":")[4] != account or data.get("Status") != "Deployed"):
            continue
        config = data.get("Config")
        settings = config.get("DistributionConfig") if isinstance(config, dict) and config.get("collection_status") == "collected" else None
        if (not isinstance(settings, dict) or settings.get("Staging") is True or data.get("Staging") is True
                or settings.get("Enabled") is not True or settings.get("ConnectionMode") not in (None, "direct")
                or not isinstance(settings.get("ContinuousDeploymentPolicyId"), str)):
            continue
        policy = data.get("ContinuousDeploymentPolicy")
        if (not isinstance(policy, dict) or policy.get("collection_status") != "collected"
                or policy.get("Id") != settings["ContinuousDeploymentPolicyId"] or policy.get("Enabled") is not True):
            continue
        names = policy.get("StagingDistributionDnsNames")
        if (not isinstance(names, dict) or names.get("Quantity") != 1
                or names.get("Items") != [domain]):
            continue
        mode = policy.get("TrafficType")
        weight = policy.get("Weight")
        routed = ((mode == "SingleWeight" and type(weight) in (int, float) and 0 < weight <= 1)
                  or (mode == "SingleHeader" and policy.get("HeaderConditionPresent") is True))
        host = data.get("DomainName")
        if routed and isinstance(host, str) and host:
            matches.append((host, mode, policy["Id"], primary_arn))
    return sorted(matches)[0] if matches else None


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
    if data.get("Status") != "Deployed":
        a = Assessment(resource, "cdn_endpoint")
        if isinstance(data.get("DomainName"), str) and data["DomainName"]:
            a.addresses = [data["DomainName"]]
        a.gap("inventory", "CloudFront distribution configuration is not observed fully deployed",
              "cloudfront:ListDistributions")
        return a
    if distribution.get("ConnectionMode") == "tenant-only":
        a = Assessment(resource, "cdn_endpoint")
        a.step("viewer_routing", "allow_declaration", connection_mode="tenant-only",
               semantics="Multi-tenant distribution cannot serve viewers directly; tenant and connection-group routing are not collected")
        a.gap("inventory", "CloudFront distribution tenant and connection-group routing not collected",
              "cloudfront:ListDistributionTenants,cloudfront:GetConnectionGroup")
        return a
    if distribution.get("ConnectionMode") not in (None, "direct"):
        a = Assessment(resource, "cdn_endpoint")
        a.gap("inventory", "CloudFront distribution connection mode unresolved",
              "cloudfront:GetDistributionConfig.ConnectionMode")
        return a
    staging = distribution.get("Staging") is True or data.get("Staging") is True
    staging_route = _cloudfront_staging_primary(inventory, data) if staging else None
    if staging and not staging_route:
        a = Assessment(resource, "cdn_endpoint")
        a.gap("inventory", "CloudFront staging distribution is not directly viewer-addressable; primary traffic policy unresolved",
              "cloudfront:GetContinuousDeploymentPolicy")
        return a
    if distribution.get("Enabled") is False:
        return None
    a = Assessment(resource, "cdn_endpoint")
    if distribution.get("Enabled") is not True:
        a.gap("inventory", "CloudFront distribution enabled state missing", "cloudfront:GetDistributionConfig")
        return a
    domain = staging_route[0] if staging_route else data.get("DomainName")
    if isinstance(domain, str) and domain:
        a.addresses = [domain]
    else:
        a.gap("inventory", "CloudFront domain name missing", "cloudfront:ListDistributions")
    if staging_route:
        a.step("viewer_routing", "allow_declaration", primary_distribution_arn=staging_route[3],
               policy_id=staging_route[2], traffic_type=staging_route[1],
               semantics="Viewer reaches the primary host; an enabled policy can route a selected request to staging")
    behaviors = [distribution.get("DefaultCacheBehavior")]
    extra_behaviors = distribution.get("CacheBehaviors")
    if extra_behaviors is not None:
        items = extra_behaviors.get("Items", []) if isinstance(extra_behaviors, dict) else None
        count = extra_behaviors.get("Quantity") if isinstance(extra_behaviors, dict) else None
        if (type(count) is not int or count < 0 or not isinstance(items, list)
                or len(items) != count or not all(isinstance(item, dict) for item in items)):
            a.gap("authorization", "CloudFront cache behavior inventory/count incomplete",
                  "cloudfront:GetDistributionConfig.CacheBehaviors")
        else:
            behaviors.extend(items)
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
    signed_behaviors, unsigned_behaviors, unresolved_behaviors = [], [], []
    for behavior in behaviors:
        path = behavior.get("PathPattern", "<default>")
        signed = False
        signing_unresolved = False
        for field in ("TrustedKeyGroups", "TrustedSigners"):
            setting = behavior.get(field)
            if setting is None:
                continue
            if not isinstance(setting, dict) or type(setting.get("Enabled")) is not bool:
                signing_unresolved = True
                continue
            count, items = setting.get("Quantity"), setting.get("Items")
            if setting["Enabled"] is False and type(count) is int and count == 0:
                continue
            if (setting["Enabled"] is True and type(count) is int and count > 0
                    and isinstance(items, list) and len(items) == count
                    and all(isinstance(item, str) and item for item in items)):
                signed = True
            else:
                signing_unresolved = True
        methods = behavior.get("AllowedMethods")
        allowed = methods.get("Items") if isinstance(methods, dict) else None
        if not isinstance(allowed, list) or not all(isinstance(method, str) for method in allowed):
            unresolved_behaviors.append(path)
        if signing_unresolved:
            unresolved_behaviors.append(path)
            a.gap("authorization", "CloudFront signed-viewer configuration malformed for cache behavior",
                  "cloudfront:GetDistributionConfig.TrustedKeyGroups/TrustedSigners")
            continue
        if not isinstance(allowed, list) or not all(isinstance(method, str) for method in allowed):
            continue
        if signed and "OPTIONS" not in allowed:
            signed_behaviors.append(path)
        else:
            unsigned_behaviors.append(path)
    a.step("viewer_access", "allow", signed_request_paths=signed_behaviors,
           unsigned_or_options_paths=unsigned_behaviors,
           unresolved_paths=sorted(set(unresolved_behaviors)),
           semantics="Signed URL/cookie settings apply per cache behavior; CloudFront can forward OPTIONS without a signature")
    a.authenticated = bool(signed_behaviors) and not unsigned_behaviors and not unresolved_behaviors
    origin_config = distribution.get("Origins")
    origins = origin_config.get("Items") if isinstance(origin_config, dict) else None
    targets = {behavior.get("TargetOriginId") for behavior in behaviors if isinstance(behavior.get("TargetOriginId"), str)}
    if not isinstance(origins, list) or not origins:
        a.gap("origin", "CloudFront distribution origin inventory not collected", "cloudfront:GetDistributionConfig.Origins")
    elif type(origin_config.get("Quantity")) is not int or origin_config["Quantity"] != len(origins):
        a.gap("origin", "CloudFront origin quantity and items disagree", "cloudfront:GetDistributionConfig.Origins")
    if not targets:
        a.gap("origin", "CloudFront cache behavior target origin ID not collected", "cloudfront:GetDistributionConfig.TargetOriginId")
    if isinstance(origins, list) and targets:
        origin_ids = [origin.get("Id") for origin in origins if isinstance(origin, dict) and isinstance(origin.get("Id"), str)]
        missing_targets = sorted(targets - set(origin_ids))
        if missing_targets:
            a.gap("origin", "CloudFront cache behavior target origin ID has no matching origin", "cloudfront:GetDistributionConfig.Origins")
        seen_ids, duplicate_ids = set(), set()
        for origin_id in origin_ids:
            if origin_id in seen_ids:
                duplicate_ids.add(origin_id)
            seen_ids.add(origin_id)
        if duplicate_ids:
            a.gap("origin", "CloudFront origin IDs are not unique", "cloudfront:GetDistributionConfig.Origins")
    if isinstance(origins, list) and targets:
        from .iam import document
        from fnmatch import fnmatchcase
        distribution_arn = data.get("ARN")
        partition = distribution_arn.split(":", 2)[1] if isinstance(distribution_arn, str) and distribution_arn.startswith("arn:") else None
        def exact_source_arn(statement):
            condition = statement.get("Condition")
            if not isinstance(condition, dict) or len(condition) != 1:
                return False
            operator, terms = next(iter(condition.items()))
            if operator not in ("StringEquals", "ArnEquals", "ArnLike") or not isinstance(terms, dict) or len(terms) != 1:
                return False
            key, value = next(iter(terms.items()))
            return isinstance(key, str) and key.casefold() == "aws:sourcearn" and value == distribution_arn
        for origin in origins:
            if not isinstance(origin, dict) or origin.get("Id") not in targets or origin.get("Id") in duplicate_ids:
                continue
            vpc_config = origin.get("VpcOriginConfig")
            if isinstance(vpc_config, dict):
                vpc_id = vpc_config.get("VpcOriginId")
                account = resource["scope"].split("/", 1)[0]
                cache_key = ("cloudfront_vpc_origins", account)
                if cache_key not in inventory.network_cache:
                    inventory.network_cache[cache_key] = {item["data"]["Id"]: item["data"]
                        for item in inventory.items("cloudfront_vpc_origin")
                        if item["scope"].split("/", 1)[0] == account
                        and isinstance(item["data"].get("Id"), str)}
                listed = inventory.network_cache[cache_key].get(vpc_id) if isinstance(vpc_id, str) else None
                detail = listed.get("VpcOrigin") if isinstance(listed, dict) else None
                endpoint = detail.get("VpcOriginEndpointConfig") if isinstance(detail, dict) else None
                endpoint_arn = endpoint.get("Arn") if isinstance(endpoint, dict) else None
                if (isinstance(listed, dict) and listed.get("Id") == vpc_id and listed.get("Status") == "Deployed"
                        and isinstance(detail, dict) and detail.get("Id") == vpc_id and detail.get("Status") == "Deployed"
                        and isinstance(endpoint_arn, str) and endpoint_arn.startswith("arn:")):
                    a.step("origin", "allow_declaration", origin_id=origin["Id"], vpc_origin_id=vpc_id,
                           origin_endpoint_arn=endpoint_arn, vpc_origin_status="Deployed",
                           semantics="Collected distribution names this deployed VPC origin and endpoint; backend security group, return NACL, listener, target and response are not established")
                elif not isinstance(vpc_id, str) or not vpc_id:
                    a.gap("origin", "CloudFront VPC origin ID missing", "cloudfront:GetDistributionConfig")
                elif not isinstance(listed, dict):
                    a.gap("origin", "Referenced CloudFront VPC origin not present in inventory", "cloudfront:ListVpcOrigins")
                elif listed.get("Status") != "Deployed":
                    a.gap("origin", "CloudFront VPC origin is not observed deployed", "cloudfront:ListVpcOrigins")
                else:
                    a.gap("origin", "CloudFront VPC origin detail or endpoint unresolved", "cloudfront:GetVpcOrigin")
                continue
            s3_config = origin.get("S3OriginConfig")
            identity = s3_config.get("OriginAccessIdentity") if isinstance(s3_config, dict) else None
            match = re.fullmatch(r"origin-access-identity/cloudfront/([A-Z0-9]+)", identity) if isinstance(identity, str) else None
            oac_id = origin.get("OriginAccessControlId")
            oac = data.get("OriginAccessControls", {}).get(oac_id) if isinstance(data.get("OriginAccessControls"), dict) and isinstance(oac_id, str) and oac_id else None
            if oac_id and (not isinstance(oac, dict) or oac.get("collection_status") != "collected"):
                a.gap("origin_auth", "CloudFront OAC configuration unavailable", "cloudfront:GetOriginAccessControl")
            if isinstance(oac, dict) and oac.get("collection_status") == "collected":
                behavior = oac.get("SigningBehavior")
                if oac.get("Id") == oac_id and behavior in ("always", "never", "no-override"):
                    a.step("origin_auth", "allow_declaration" if behavior in ("always", "no-override") else "unresolved",
                           origin_id=origin["Id"], origin_access_control_id=oac_id,
                           signing_behavior=behavior, signing_protocol=oac.get("SigningProtocol"),
                           origin_type=oac.get("OriginAccessControlOriginType"),
                           semantics="Observed OAC signing configuration; no-override signs requests without a viewer Authorization header; origin response requires separate evidence")
                else:
                    a.gap("origin_auth", "CloudFront OAC signing configuration malformed", "cloudfront:GetOriginAccessControl")
            hostname = origin.get("DomainName")
            if (isinstance(oac, dict) and oac.get("collection_status") == "collected"
                    and oac.get("Id") == oac_id and oac.get("SigningBehavior") in ("always", "no-override")
                    and oac.get("SigningProtocol") == "sigv4" and oac.get("OriginAccessControlOriginType") == "lambda"
                    and isinstance(origin.get("CustomOriginConfig"), dict) and isinstance(hostname, str)
                    and re.fullmatch(r"[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws", hostname)
                    and isinstance(distribution_arn, str)):
                for kind in ("lambda_function", "lambda_alias"):
                    for function in inventory.items(kind):
                        if function["scope"].split("/", 1)[0] != resource["scope"].split("/", 1)[0]:
                            continue
                        function_data = function["data"]
                        url = function_data.get("FunctionUrl")
                        function_arn = function_data.get("AliasArn") if kind == "lambda_alias" else function_data.get("FunctionArn")
                        if (not isinstance(function_arn, str) or not isinstance(url, dict) or url.get("collection_status") != "collected"
                                or url.get("AuthType") != "AWS_IAM" or url.get("FunctionArn") != function_arn
                                or not isinstance(url.get("FunctionUrl"), str)
                                or urlsplit(url["FunctionUrl"]).hostname != hostname):
                            continue
                        policy_read = function_data.get("Policy")
                        if not isinstance(policy_read, dict) or policy_read.get("collection_status") != "collected":
                            continue
                        statements = as_list((document(policy_read.get("Policy")) or {}).get("Statement"))
                        if any(isinstance(row, dict) and row.get("Effect") == "Deny" for row in statements):
                            continue
                        actions = set()
                        for statement in statements:
                            if (not isinstance(statement, dict) or statement.get("Effect") != "Allow"
                                    or any(key in statement for key in ("NotPrincipal", "NotAction", "NotResource"))
                                    or statement.get("Principal") != {"Service": "cloudfront.amazonaws.com"}
                                    or function_arn not in as_list(statement.get("Resource"))
                                    or not exact_source_arn(statement)):
                                continue
                            actions.update(action.casefold() for action in as_list(statement.get("Action"))
                                           if isinstance(action, str) and action.casefold() in
                                           ("lambda:invokefunctionurl", "lambda:invokefunction"))
                        if {"lambda:invokefunctionurl", "lambda:invokefunction"} <= actions:
                            a.step("origin_policy", "allow_declaration", origin_id=origin["Id"],
                                   origin_type="lambda_function_url", function_arn=function_arn,
                                   principal="cloudfront.amazonaws.com", source_arn=distribution_arn,
                                   actions=sorted(actions),
                                   semantics="Collected qualified Lambda policy grants both URL invocation actions to this distribution; no-override requires a viewer request without Authorization; function response is not established")
            bucket_host = (re.fullmatch(r"(.+)\.s3(?:[.-][a-z]{2}(?:-[a-z]+)+-\d+)?\.amazonaws\.com", hostname)
                           if isinstance(hostname, str) else None)
            bucket_name = bucket_host.group(1) if bucket_host else None
            if not bucket_name or not partition:
                continue
            bucket = next((item for item in inventory.items("bucket") if item["scope"].split("/", 1)[0] == resource["scope"].split("/", 1)[0]
                           and item["data"].get("Name") == bucket_name), None)
            policy = bucket["data"].get("Policy") if bucket else None
            if not isinstance(policy, dict) or policy.get("collection_status") != "collected" or "Policy" not in policy:
                continue
            statements = as_list((document(policy["Policy"]) or {}).get("Statement"))
            if any(isinstance(statement, dict) and statement.get("Effect") == "Deny" for statement in statements):
                continue
            if (isinstance(oac, dict) and oac.get("collection_status") == "collected"
                    and oac.get("Id") == oac_id and oac.get("SigningBehavior") in ("always", "no-override")
                    and oac.get("SigningProtocol") == "sigv4" and oac.get("OriginAccessControlOriginType") == "s3"
                    and isinstance(s3_config, dict) and not identity and isinstance(distribution_arn, str)):
                object_arn = f"arn:{partition}:s3:::{bucket_name}/*"
                for statement in statements:
                    if not isinstance(statement, dict) or statement.get("Effect") != "Allow" or any(
                            key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
                        continue
                    principal = statement.get("Principal")
                    if not isinstance(principal, dict) or principal.get("Service") != "cloudfront.amazonaws.com":
                        continue
                    if not any(isinstance(action, str) and fnmatchcase("s3:GetObject", action) for action in as_list(statement.get("Action"))):
                        continue
                    if object_arn not in as_list(statement.get("Resource")):
                        continue
                    if not exact_source_arn(statement):
                        continue
                    a.step("origin_policy", "allow_declaration", origin_id=origin["Id"], bucket=bucket_name,
                           principal="cloudfront.amazonaws.com", source_arn=distribution_arn,
                           action="s3:GetObject", resource=object_arn,
                           semantics="Collected bucket policy grants a request signed by this distribution's S3 OAC; no-override requires a viewer request without Authorization; object existence, ACL, KMS and response are not established")
                    break
            if not match or oac_id:
                continue
            principal = f"arn:{partition}:iam::cloudfront:user/CloudFront Origin Access Identity {match.group(1)}"
            oai = data.get("OriginAccessIdentities", {}).get(match.group(1)) if isinstance(data.get("OriginAccessIdentities"), dict) else None
            canonical = oai.get("S3CanonicalUserId") if isinstance(oai, dict) and oai.get("collection_status") == "collected" and oai.get("Id") == match.group(1) else None
            object_arn = f"arn:{partition}:s3:::{bucket_name}/*"
            for statement in statements:
                if not isinstance(statement, dict) or statement.get("Effect") != "Allow" or statement.get("Condition") or any(
                        key in statement for key in ("NotPrincipal", "NotAction", "NotResource")):
                    continue
                aws_principal = statement.get("Principal", {}).get("AWS") if isinstance(statement.get("Principal"), dict) else None
                canonical_principal = statement.get("Principal", {}).get("CanonicalUser") if isinstance(statement.get("Principal"), dict) else None
                matched_principal = (principal if principal in as_list(aws_principal)
                                     else canonical if isinstance(canonical, str) and canonical in as_list(canonical_principal) else None)
                if matched_principal is None:
                    continue
                if not any(isinstance(action, str) and fnmatchcase("s3:GetObject", action) for action in as_list(statement.get("Action"))):
                    continue
                if object_arn not in as_list(statement.get("Resource")):
                    continue
                a.step("origin_policy", "allow_declaration", origin_id=origin["Id"], bucket=bucket_name,
                       principal=matched_principal, action="s3:GetObject", resource=object_arn,
                       semantics="Collected bucket policy grants the configured OAI object read; object existence, ACL, KMS and response are not established")
                break
    a.notes.append("CloudFront viewer reachability does not establish origin reachability or authorization")
    return a


def _aws_global_accelerator(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("Enabled") is False:
        return None
    a = Assessment(resource, "managed_endpoint")
    if data.get("Enabled") is not True or data.get("Status") != "DEPLOYED":
        a.gap("inventory", "Global Accelerator enabled/deployed state unresolved", "globalaccelerator:ListAccelerators")
        return a
    ip_sets = data.get("IpSets")
    if not isinstance(ip_sets, list) or not ip_sets:
        a.gap("inventory", "Global Accelerator static IP sets missing", "globalaccelerator:ListAccelerators")
        return a
    addresses = []
    for ip_set in ip_sets:
        if not isinstance(ip_set, dict) or ip_set.get("IpFamily") not in ("IPv4", "IPv6") or not isinstance(ip_set.get("IpAddresses"), list):
            a.gap("inventory", "Global Accelerator IP set malformed", "globalaccelerator:ListAccelerators")
            return a
        for address in ip_set["IpAddresses"]:
            if not isinstance(address, str) or not _public_ip(address) or ipaddress.ip_address(address).version != (4 if ip_set["IpFamily"] == "IPv4" else 6):
                a.gap("inventory", "Global Accelerator static IP not globally routable or family mismatched", "globalaccelerator:ListAccelerators")
                return a
            addresses.append(address)
    if not addresses:
        a.gap("inventory", "Global Accelerator static IP list empty", "globalaccelerator:ListAccelerators")
        return a
    a.addresses = sorted(set(addresses))
    arn = data.get("AcceleratorArn")
    if not isinstance(arn, str) or not arn:
        a.gap("inventory", "Global Accelerator ARN missing", "globalaccelerator:ListAccelerators")
        return a
    listeners = [r["data"] for r in inventory.items("globalaccelerator_listener")
                 if r["data"].get("AcceleratorArn") == arn]
    if not listeners and inventory.state("globalaccelerator_listener") not in ("collected", "empty"):
        a.gap("listener", "Global Accelerator listeners unavailable", "globalaccelerator:ListListeners")
        return a
    ports = {}
    for listener in listeners:
        protocol = listener.get("Protocol")
        ranges = listener.get("PortRanges")
        if protocol not in ("TCP", "UDP") or not isinstance(ranges, list) or not ranges:
            a.gap("listener", "Global Accelerator listener protocol or port ranges malformed", "globalaccelerator:ListListeners")
            continue
        for port_range in ranges:
            if not isinstance(port_range, dict) or type(port_range.get("FromPort")) is not int or type(port_range.get("ToPort")) is not int or not 1 <= port_range["FromPort"] <= port_range["ToPort"] <= 65535:
                a.gap("listener", "Global Accelerator listener port range malformed", "globalaccelerator:ListListeners")
                continue
            ports = union(ports, pset(protocol.lower(), port_range["FromPort"], port_range["ToPort"]))
    a.ports = ports
    if not a.unresolved:
        a.step("listener", "allow" if ports else "block", accelerator_arn=arn, static_ips=a.addresses, ports=describe(ports))
    a.notes.append("Static IP and listener configuration proves a public frontend, not endpoint health or backend delivery")
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


def _gcp_order_hierarchy_policies(inventory, instance, policies):
    known_types = {"HIERARCHY", "NETWORK", "NETWORK_REGIONAL", "SYSTEM_GLOBAL", "SYSTEM_REGIONAL"}
    if any(not isinstance(policy, dict) or policy.get("type") not in known_types for policy in policies):
        return None
    hierarchy = [policy for policy in policies if policy.get("type") == "HIERARCHY"]
    if len(hierarchy) <= 1:
        return hierarchy
    projects = [row for row in inventory.items("project") if row.get("scope") == instance.get("scope")]
    if len(projects) != 1:
        return None
    ancestry = projects[0]["data"].get("_ancestry")
    project_ids = {instance["scope"].split("/", 1)[-1], str(projects[0]["data"].get("projectNumber"))}
    if (not isinstance(ancestry, list) or len(ancestry) < 2 or
            not isinstance(ancestry[0], dict) or
            (ancestry[0].get("resourceId") or {}).get("type") != "project" or
            str((ancestry[0].get("resourceId") or {}).get("id")) not in project_ids):
        return None
    scopes = []
    for ancestor in ancestry[1:]:
        resource_id = ancestor.get("resourceId") if isinstance(ancestor, dict) else None
        if not isinstance(resource_id, dict) or resource_id.get("type") not in ("folder", "organization"):
            return None
        identifier = resource_id.get("id")
        if not isinstance(identifier, str) or not identifier.isdigit():
            return None
        scopes.append(f"{resource_id['type']}s/{identifier}")
    if len(scopes) != len(set(scopes)) or not scopes[-1].startswith("organizations/") or any(
            scope.startswith("organizations/") for scope in scopes[:-1]):
        return None
    ordered = []
    for scope in reversed(scopes):
        if inventory.state("firewall_policy_association", scope) not in ("collected", "empty"):
            return None
        associations = [row["data"] for row in inventory.items("firewall_policy_association")
                        if row.get("scope") == scope]
        if any(not isinstance(row, dict) or row.get("attachmentTarget") != scope or
               not isinstance(row.get("name"), str) or
               type(row.get("priority", 1000)) is not int or
               not 1 <= row.get("priority", 1000) <= 2147483647 or
               not isinstance(row.get("firewallPolicyId"), str) or
               not row["firewallPolicyId"].isdigit() for row in associations):
            return None
        ordered.extend(sorted(associations, key=lambda row: (row.get("priority", 1000), row["name"])))
    ids = [row["firewallPolicyId"] for row in ordered]
    effective = {}
    for policy in hierarchy:
        name = policy.get("name")
        identifier = name.rsplit("/", 1)[-1] if isinstance(name, str) else None
        if not isinstance(identifier, str) or not identifier.isdigit() or identifier in effective:
            return None
        effective[identifier] = policy
    if len(ids) != len(set(ids)) or set(ids) != set(effective):
        return None
    return [effective[identifier] for identifier in ids]


def _gcp_terminal_hierarchy_rule(policies, interface, policy_type="HIERARCHY"):
    """Resolve terminal policy allow ports after private-only or port-deny rules.

    getEffectiveFirewalls has already selected rules for this VM interface. Other
    policy matches and inter-policy precedence still require full evaluation.
    """
    known_types = {"HIERARCHY", "NETWORK", "NETWORK_REGIONAL", "SYSTEM_GLOBAL", "SYSTEM_REGIONAL"}
    if (not isinstance(policies, list) or any(not isinstance(policy, dict) or
            policy.get("type") not in known_types for policy in policies)):
        return None
    selected = [policy for policy in policies if policy.get("type") == policy_type]
    if len(selected) != 1:
        return None
    policy = selected[0]
    rules = policy.get("rules")
    if not isinstance(rules, list):
        return None
    ingress = []
    for rule in rules:
        if not isinstance(rule, dict) or (rule.get("disabled") is not None and type(rule["disabled"]) is not bool):
            return None
        if rule.get("disabled") is True or rule.get("direction") == "EGRESS":
            continue
        if rule.get("direction") != "INGRESS":
            return None
        priority = rule.get("priority")
        if isinstance(priority, bool) or not isinstance(priority, (int, str)) or not str(priority).isdigit():
            return None
        ingress.append((int(priority), rule))
    ingress.sort(key=lambda row: row[0])
    if len({priority for priority, _ in ingress}) != len(ingress):
        return None
    families = set()
    if any(isinstance(row, dict) and row.get("natIP") for row in as_list(interface.get("accessConfigs"))):
        families.add("0.0.0.0/0")
    if any(isinstance(row, dict) and row.get("externalIpv6") for row in as_list(interface.get("ipv6AccessConfigs"))):
        families.add("::/0")
    if not families:
        return None
    private_ranges = tuple(ipaddress.ip_network(value) for value in
                           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
    earlier_denied = {}
    for _, rule in ingress:
        if rule.get("targetType", "INSTANCES") != "INSTANCES":
            return None
        match = rule.get("match")
        if not isinstance(match, dict) or set(match) - {"srcIpRanges", "layer4Configs"}:
            return None
        sources = match.get("srcIpRanges")
        if not isinstance(sources, list) or not sources or any(not isinstance(value, str) for value in sources):
            return None
        networks = [_cidr(value) for value in sources]
        if any(network is None for network in networks):
            return None
        if all(any(network.subnet_of(private) for private in private_ranges
                   if private.version == network.version) for network in networks):
            # These sources have no direct route from public-internet clients.
            continue
        if rule.get("action") not in ("allow", "deny", "goto_next") or not families.issubset(set(sources)):
            return None
        configs = match.get("layer4Configs")
        if configs in (None, []):
            ports = dict(FULL)
        elif not isinstance(configs, list):
            return None
        else:
            ports = {}
            for config in configs:
                if not isinstance(config, dict) or set(config) - {"ipProtocol", "ports"}:
                    return None
                protocol = _proto(config.get("ipProtocol"))
                if protocol not in ("tcp", "udp"):
                    return None
                specs = config.get("ports")
                if specs is not None and (not isinstance(specs, list) or not specs):
                    return None
                for spec in specs if specs is not None else [None]:
                    if spec is None:
                        ports = union(ports, pset(protocol))
                        continue
                    if not isinstance(spec, str) or not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", spec):
                        return None
                    bounds = [int(value) for value in spec.split("-", 1)]
                    low, high = (bounds[0], bounds[-1])
                    if not 1 <= low <= high <= 65535:
                        return None
                    ports = union(ports, pset(protocol, low, high))
        if rule["action"] == "deny":
            if ports == FULL:
                return policy, rule, {}
            earlier_denied = union(earlier_denied, ports)
            continue
        if rule["action"] == "goto_next":
            if not empty(earlier_denied):
                return None
            return (policy, rule, None) if ports == FULL else (policy, rule, None, ports)
        allowed = subtract(ports, earlier_denied)
        if not empty(allowed):
            return policy, rule, allowed
    return (policy, {"action": "goto_next", "ruleName": "implied"}, None) if empty(earlier_denied) else None


def _gcp_effective_vpc_public_allow(rules, tags, accounts, address_families):
    if not isinstance(rules, list) or not address_families:
        return None
    candidates = []
    for rule in rules:
        if not isinstance(rule, dict) or type(rule.get("priority", 1000)) is not int:
            return None
        if rule.get("direction", "INGRESS") != "INGRESS" or rule.get("disabled") is True:
            continue
        if rule.get("destinationRanges"):
            return None
        sources = as_list(rule.get("sourceRanges"))
        if sources and (rule.get("sourceTags") or rule.get("sourceServiceAccounts")):
            return None
        if (not sources and (rule.get("sourceTags") or rule.get("sourceServiceAccounts"))) or (
                not sources and 4 not in address_families) or (
                sources and not any(_public_source(value) and _cidr(value).version in address_families
                                    for value in sources)):
            continue
        if rule.get("targetTags") and not tags & set(as_list(rule["targetTags"])):
            continue
        if rule.get("targetServiceAccounts") and not accounts & set(as_list(rule["targetServiceAccounts"])):
            continue
        if bool(rule.get("allowed")) == bool(rule.get("denied")):
            return None
        candidates.append(rule)
    allowed, decided, matched = {}, {}, []
    for rule in sorted(candidates, key=lambda row: (row.get("priority", 1000), 0 if row.get("denied") else 1)):
        ports = _gcp_rule_ports(rule.get("denied") or rule.get("allowed"))
        if empty(ports):
            return None
        fresh = subtract(ports, decided)
        if rule.get("allowed") and not empty(fresh):
            allowed = union(allowed, fresh)
            matched.append({"rule": rule.get("name"), "priority": rule.get("priority", 1000),
                            "source_ranges": as_list(rule.get("sourceRanges")), "ports": describe(fresh)})
        decided = union(decided, ports)
    return allowed, matched


def _gcp_effective_vpc_no_public_match(rules, tags, accounts, address_families):
    if not isinstance(rules, list) or not address_families:
        return False
    for rule in rules:
        if not isinstance(rule, dict):
            return False
        if rule.get("disabled") is True or rule.get("direction", "INGRESS") == "EGRESS":
            continue
        if rule.get("disabled") not in (None, False) or rule.get("direction", "INGRESS") != "INGRESS":
            return False
        target_tags = rule.get("targetTags")
        target_accounts = rule.get("targetServiceAccounts")
        if target_tags is not None and (not isinstance(target_tags, list) or
                                        any(not isinstance(tag, str) for tag in target_tags)):
            return False
        if target_accounts is not None and (not isinstance(target_accounts, list) or
                                            any(not isinstance(account, str) for account in target_accounts)):
            return False
        if target_tags and not tags.intersection(target_tags):
            continue
        if target_accounts and not accounts.intersection(target_accounts):
            continue
        sources = rule.get("sourceRanges")
        if sources is not None and (not isinstance(sources, list) or
                                    any(not isinstance(source, str) or _cidr(source) is None for source in sources)):
            return False
        if not sources:
            if rule.get("sourceTags") or rule.get("sourceServiceAccounts") or 4 not in address_families:
                continue
            return False
        if any(_public_source(source) and _cidr(source).version in address_families for source in sources):
            return False
    return True


def _gcp_firewall(inventory, instance, interface, assessment):
    data = instance["data"]
    network = interface.get("network")
    tags = set(as_list((data.get("tags") or {}).get("items")))
    accounts = {s.get("email") for s in as_list(data.get("serviceAccounts")) if isinstance(s, dict)}
    address_families = ({4} if any(c.get("natIP") for c in as_list(interface.get("accessConfigs"))
                                   if isinstance(c, dict)) else set())
    if any(c.get("externalIpv6") for c in as_list(interface.get("ipv6AccessConfigs"))
           if isinstance(c, dict)):
        address_families.add(6)
    allowed, decided = {}, {}
    policies = inventory.items("firewall_policy")
    instance_link = data.get("selfLink")
    instance_id = ("projects/" + instance_link.split("/projects/", 1)[1]
                   if isinstance(instance_link, str) and "/projects/" in instance_link else instance_link)
    effective = [row for row in inventory.items("instance_effective_firewall")
                 if row.get("scope") == instance.get("scope") and row["data"].get("instance") == instance_id
                 and row["data"].get("networkInterface") == interface.get("name")]
    effective_rules = None
    if effective:
        if (len(effective) != 1 or effective[0]["data"].get("effective_source_operation") != "instances.getEffectiveFirewalls"
                or not isinstance(effective[0]["data"].get("firewallPolicys"), list)
                or not isinstance(effective[0]["data"].get("firewalls"), list)):
            assessment.gap("firewall", "per-interface effective firewall response is ambiguous or malformed")
            return None
        attached = effective[0]["data"]["firewallPolicys"]
        if attached:
            if any(not isinstance(policy, dict) or policy.get("type") not in (
                    "HIERARCHY", "SYSTEM_REGIONAL", "NETWORK", "NETWORK_REGIONAL") for policy in attached):
                assessment.gap("firewall", "per-interface effective firewall response has an unrecognized policy type")
                return None
            ordered = _gcp_order_hierarchy_policies(inventory, instance, attached)
            resolved = None
            policy_kind = "hierarchical"
            transition_ports = dict(FULL)
            hierarchy_exhausted = ordered == []
            system_exhausted = False
            if ordered:
                hierarchy_exhausted = True
                for hierarchy_policy in ordered:
                    candidate = _gcp_terminal_hierarchy_rule([hierarchy_policy], interface)
                    if candidate is None:
                        hierarchy_exhausted = False
                        break
                    if candidate[2] is None:
                        if len(candidate) == 4:
                            transition_ports = intersect(transition_ports, candidate[3])
                            if empty(transition_ports):
                                hierarchy_exhausted = False
                                break
                        assessment.step("hierarchy_transition", "goto_next", policy=hierarchy_policy.get("name"),
                                        rule=candidate[1].get("ruleName"), ports=describe(transition_ports))
                        continue
                    resolved = candidate
                    break
            if (resolved is None and hierarchy_exhausted and
                    not any(policy.get("type") == "SYSTEM_GLOBAL" for policy in attached)):
                system_policies = [policy for policy in attached if policy.get("type") == "SYSTEM_REGIONAL"]
                if not system_policies:
                    system_exhausted = True
                elif len(system_policies) == 1:
                    candidate = _gcp_terminal_hierarchy_rule([system_policies[0]], interface, "SYSTEM_REGIONAL")
                    if candidate is not None and candidate[2] is not None:
                        resolved = candidate
                        policy_kind = "regional system"
                    elif candidate is not None and candidate[2] is None:
                        next_ports = (intersect(transition_ports, candidate[3]) if len(candidate) == 4
                                      else transition_ports)
                        if not empty(next_ports):
                            assessment.step("system_transition", "goto_next", policy=system_policies[0].get("name"),
                                            rule=candidate[1].get("ruleName"), ports=describe(next_ports))
                            transition_ports = next_ports
                            system_exhausted = True
            if resolved is None and hierarchy_exhausted and system_exhausted:
                network_resource = inventory.get("network", network)
                global_policies = [policy for policy in attached if policy.get("type") == "NETWORK"]
                regional_policies = [policy for policy in attached if policy.get("type") == "NETWORK_REGIONAL"]
                enforcement_order = (network_resource["data"].get("networkFirewallPolicyEnforcementOrder")
                                     if network_resource is not None else None)
                classic_ignored_for_public = (network_resource is not None and
                                              enforcement_order in (None, "AFTER_CLASSIC_FIREWALL") and
                                              _gcp_effective_vpc_no_public_match(effective[0]["data"]["firewalls"],
                                                                                 tags, accounts, address_families))
                if network_resource is not None and (enforcement_order == "BEFORE_CLASSIC_FIREWALL" or
                                                     classic_ignored_for_public):
                    if classic_ignored_for_public:
                        assessment.step("classic_transition", "goto_next", network=network,
                                        enforcement_order="AFTER_CLASSIC_FIREWALL",
                                        vpc_rule_count=len(effective[0]["data"]["firewalls"]))
                    if len(global_policies) == 1:
                        candidate = _gcp_terminal_hierarchy_rule([global_policies[0]], interface, "NETWORK")
                        if candidate is not None and candidate[2] is not None:
                            resolved = candidate
                            policy_kind = "global network"
                        elif candidate is not None and candidate[2] is None and len(regional_policies) == 1:
                            next_ports = (intersect(transition_ports, candidate[3]) if len(candidate) == 4
                                          else transition_ports)
                            if not empty(next_ports):
                                assessment.step("network_transition", "goto_next", policy=global_policies[0].get("name"),
                                                rule=candidate[1].get("ruleName"), ports=describe(next_ports))
                                regional = _gcp_terminal_hierarchy_rule([regional_policies[0]], interface,
                                                                         "NETWORK_REGIONAL")
                                if regional is not None and regional[2] is not None:
                                    resolved = regional
                                    transition_ports = next_ports
                                    policy_kind = "regional network"
                    elif not global_policies and len(regional_policies) == 1:
                        candidate = _gcp_terminal_hierarchy_rule([regional_policies[0]], interface, "NETWORK_REGIONAL")
                        if candidate is not None and candidate[2] is not None:
                            resolved = candidate
                            policy_kind = "regional network"
            if resolved is None:
                network_resource = inventory.get("network", network)
                if (hierarchy_exhausted and system_exhausted and network_resource is not None and
                        network_resource["data"].get("networkFirewallPolicyEnforcementOrder", "AFTER_CLASSIC_FIREWALL")
                        == "AFTER_CLASSIC_FIREWALL"):
                    classic = _gcp_effective_vpc_public_allow(effective[0]["data"]["firewalls"], tags,
                                                               accounts, address_families)
                    if classic is not None:
                        classic_ports = intersect(classic[0], transition_ports)
                        if not empty(classic_ports):
                            assessment.step("classic_precedence", "allow", network=network,
                                            enforcement_order="AFTER_CLASSIC_FIREWALL",
                                            matched_rules=classic[1], allowed=describe(classic_ports))
                            return classic_ports
                assessment.gap("firewall", "per-interface hierarchical/network firewall policy rules need ordered evaluation")
                return None
            hierarchy_policy, terminal, terminal_ports = resolved
            action = terminal["action"]
            if action == "allow":
                terminal_ports = intersect(terminal_ports, transition_ports)
                if empty(terminal_ports):
                    assessment.gap("firewall", "hierarchical transition and later allow have no shared Layer 4 ports")
                    return None
            elif transition_ports != FULL:
                assessment.gap("firewall", "hierarchical deny after a port-specific transition leaves other ports unresolved")
                return None
            assessment.step("effective_firewall", "allow" if action == "allow" else "block", instance=instance_id,
                            network_interface=interface.get("name"), policy=hierarchy_policy.get("name"),
                            rule=terminal.get("ruleName"), priority=terminal["priority"], action=action,
                            source_ranges=terminal["match"]["srcIpRanges"],
                            allowed_ports=describe(terminal_ports) if action == "allow" else [],
                            basis=f"terminal {policy_kind} ingress rule")
            if action == "allow" and terminal_ports != FULL:
                assessment.gap("firewall", f"{policy_kind} allow covers only recorded Layer 4 ports; other traffic needs ordered policy evaluation")
                assessment.unresolved[-1]["decisive"] = False
            return terminal_ports if action == "allow" else {}
        effective_rules = effective[0]["data"]["firewalls"]
        assessment.step("effective_firewall", "allow", instance=instance_id,
                        network_interface=interface.get("name"), policy_count=0,
                        vpc_rule_count=len(effective_rules))
    hierarchy = (((inventory.snapshot.get("metadata") or {}).get("network_context") or {}).get("gcp") or {}).get("firewall_hierarchy") or {}
    unaffected = (hierarchy.get("complete") is True and instance.get("scope") in as_list(hierarchy.get("unaffected_projects")))
    network_resource = inventory.get("network", network)
    if (effective_rules is None and ((policies and not unaffected) or
        (network_resource is not None and network_resource["data"].get("firewallPolicy")) or
        any(as_list(row["data"].get("firewallPolicys")) for row in inventory.items("effective_firewall")
            if row.get("scope") == instance.get("scope") and row["data"].get("network") == network))):
        assessment.gap("firewall", "attached hierarchical, network, or regional policy precedence needs an effective per-instance rule decision")
        return None
    if inventory.state("firewall_policy").startswith("missing"):
        assessment.gap("firewall_policy", "hierarchical/network firewall policies not collected", "compute firewallPolicies")
        assessment.unresolved[-1]["decisive"] = False
    candidates = []
    source_rules = ([{"data": row} for row in effective_rules]
                    if effective_rules is not None else _gcp_network_internet_rules(inventory, network))
    for rule in source_rules:
        r = rule["data"]
        if effective_rules is not None:
            if r.get("direction", "INGRESS") != "INGRESS" or r.get("disabled"):
                continue
            sources = as_list(r.get("sourceRanges"))
            if (not sources and (r.get("sourceTags") or r.get("sourceServiceAccounts"))) or (
                    sources and not any(_public_source(value) for value in sources)):
                continue
        if r.get("targetTags") and not tags & set(r["targetTags"]):
            continue
        if r.get("targetServiceAccounts") and not accounts & set(r["targetServiceAccounts"]):
            continue
        candidates.append(rule)
    if effective_rules is None and inventory.state("firewall").startswith("missing"):
        assessment.gap("firewall", f"VPC firewall rules {inventory.state('firewall')}", "compute firewalls.list")
        return None
    matched = []
    for rule in sorted(candidates, key=lambda x: (int(x["data"].get("priority", 1000)), 0 if x["data"].get("denied") else 1)):
        r = rule["data"]
        ports = _gcp_rule_ports(r.get("denied") or r.get("allowed"))
        fresh = subtract(ports, decided)
        if r.get("allowed") and not empty(fresh):
            allowed = union(allowed, fresh)
            matched.append({"rule": r.get("name"), "priority": r.get("priority", 1000), "action": "allow",
                            "ports": describe(fresh), "source_ranges": as_list(r.get("sourceRanges"))})
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
    elif unknown:
        # A block on one public interface cannot clear an unresolved second path.
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
        ports = pset("all" if protocol == "L3_DEFAULT" else protocol)
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
        services, redirects = [], []
        path_route_witnesses = {}
        partial_route_witness = False
        url_map = proxy["data"].get("urlMap")
        if url_map:
            mapping = inventory.get("url_map", url_map)
            if mapping is None:
                a.gap("backend", f"url map {url_map} not collected", "compute urlMaps")
                return a
            m = mapping["data"]
            def redirect_action(action, route):
                if not isinstance(action, dict) or not any(
                        kind in target for kind in ("/targetHttpProxies/", "/targetHttpsProxies/")):
                    return None
                code = action.get("redirectResponseCode", "MOVED_PERMANENTLY_DEFAULT")
                if code not in ("MOVED_PERMANENTLY_DEFAULT", "FOUND", "SEE_OTHER",
                                "TEMPORARY_REDIRECT", "PERMANENT_REDIRECT"):
                    return None
                host = action.get("hostRedirect")
                if host is not None and (not isinstance(host, str) or not host or
                                         any(char in host for char in "/?#@ ")):
                    return None
                strip_query = action.get("stripQuery", False)
                https_redirect = action.get("httpsRedirect", False)
                if type(strip_query) is not bool or type(https_redirect) is not bool:
                    return None
                if https_redirect and "/targetHttpProxies/" not in target:
                    return None
                return {"route": route, "response_code": code, "host_redirect": host,
                        "strip_query": strip_query, "https_redirect": https_redirect}
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
            host_rules = m.get("hostRules")
            unmatched_host = None
            if ("/targetHttpProxies/" in target and isinstance(host_rules, list) and host_rules and
                    all(isinstance(rule, dict) and isinstance(rule.get("hosts"), list) and rule["hosts"] and
                        all(isinstance(host, str) and host and "*" not in host for host in rule["hosts"])
                        for rule in host_rules)):
                witness = "peaso-unmatched.invalid"
                if all(witness.casefold() != host.casefold() for rule in host_rules for host in rule["hosts"]):
                    unmatched_host = witness
            services = (route_backends(m, "defaultRouteAction")
                        if not as_list(host_rules) or unmatched_host is not None else [])
            if ((not as_list(host_rules) or unmatched_host is not None) and not m.get("defaultService") and
                    not as_list((m.get("defaultRouteAction") or {}).get("weightedBackendServices"))):
                redirect = redirect_action(m.get("defaultUrlRedirect"),
                                           "unmatched_host_default" if unmatched_host else "url_map_default")
                if redirect:
                    if unmatched_host:
                        redirect["host_witness"] = unmatched_host
                    redirects.append(redirect)
            host_matchers = {rule["pathMatcher"] for rule in as_list(m.get("hostRules"))
                             if isinstance(rule, dict) and isinstance(rule.get("pathMatcher"), str)
                             and isinstance(rule.get("hosts"), list)
                             and rule["hosts"] and all(isinstance(host, str) and host for host in rule["hosts"])}
            for matcher in as_list(m.get("pathMatchers")):
                if not isinstance(matcher, dict):
                    continue
                if matcher.get("name") in host_matchers:
                    route_rules = matcher.get("routeRules")
                    def matches_all_paths(rule):
                        matches = rule.get("matchRules") if isinstance(rule, dict) else None
                        return isinstance(matches, list) and any(
                            isinstance(match, dict) and set(match) <= {"prefixMatch", "ignoreCase"} and
                            match.get("prefixMatch") == "/" and type(match.get("ignoreCase", False)) is bool
                            for match in matches)
                    route_intercepts_default = (isinstance(route_rules, list) and
                                                any(matches_all_paths(rule) for rule in route_rules))
                    path_rules = matcher.get("pathRules")
                    path_intercepts_default = (isinstance(path_rules, list) and any(
                        isinstance(rule, dict) and "/*" in as_list(rule.get("paths"))
                        for rule in path_rules))
                    universal_rule = None
                    if (isinstance(host_rules, list) and len(host_rules) == 1 and
                            host_rules[0].get("hosts") == ["*"] and
                            host_rules[0].get("pathMatcher") == matcher.get("name") and
                            isinstance(route_rules, list) and route_rules and
                            not as_list(matcher.get("pathRules"))):
                        priorities = [rule.get("priority") for rule in route_rules if isinstance(rule, dict)]
                        valid_order = (len(priorities) == len(route_rules) and
                                       all(type(value) is int and 0 <= value <= 2147483647 for value in priorities) and
                                       len(set(priorities)) == len(priorities))
                        rule = min(route_rules, key=lambda row: row["priority"]) if valid_order else None
                        matches = rule.get("matchRules") if isinstance(rule, dict) else None
                        if (isinstance(rule, dict) and type(rule.get("priority")) is int and
                                0 <= rule["priority"] <= 2147483647 and
                                isinstance(matches, list) and len(matches) == 1 and matches_all_paths(rule) and
                                not rule.get("urlRedirect") and route_backends(rule, "routeAction")):
                            universal_rule = rule
                    if universal_rule is not None:
                        services.extend(route_backends(universal_rule, "routeAction"))
                        a.step("url_route_rule", "allow", host="*", prefix="/",
                               priority=universal_rule["priority"],
                               backends=route_backends(universal_rule, "routeAction"))
                    elif not route_intercepts_default and not path_intercepts_default:
                        services.extend(route_backends(matcher, "defaultRouteAction"))
                    def earlier_excludes(rule, path):
                        matches = rule.get("matchRules")
                        if not isinstance(matches, list) or not matches:
                            return False
                        for match in matches:
                            if not isinstance(match, dict):
                                return False
                            path_keys = [key for key in ("prefixMatch", "fullPathMatch") if key in match]
                            if len(path_keys) != 1:
                                return False
                            prefix, exact = match.get("prefixMatch"), match.get("fullPathMatch")
                            if isinstance(prefix, str) and (prefix == "" or prefix.startswith("/")) and (
                                    not path.casefold().startswith(prefix.casefold())):
                                continue
                            if isinstance(exact, str) and exact.startswith("/") and path.casefold() != exact.casefold():
                                continue
                            return False
                        return True
                    if (universal_rule is None and isinstance(host_rules, list) and
                            isinstance(route_rules, list) and route_rules and not as_list(matcher.get("pathRules"))):
                        priorities = [rule.get("priority") for rule in route_rules if isinstance(rule, dict)]
                        if (len(priorities) == len(route_rules) and
                                all(type(value) is int and 0 <= value <= 2147483647 for value in priorities) and
                                len(set(priorities)) == len(priorities)):
                            ordered_rules = sorted(route_rules, key=lambda rule: rule["priority"])
                            for position, selected_rule in enumerate(ordered_rules):
                                matches = selected_rule.get("matchRules")
                                if not (isinstance(matches, list) and len(matches) == 1 and isinstance(matches[0], dict) and
                                    set(matches[0]) <= {"prefixMatch", "fullPathMatch", "ignoreCase"} and
                                    type(matches[0].get("ignoreCase", False)) is bool and
                                    not selected_rule.get("urlRedirect") and route_backends(selected_rule, "routeAction")):
                                    continue
                                match = matches[0]
                                keys = [key for key in ("prefixMatch", "fullPathMatch") if key in match]
                                path = match.get(keys[0]) if len(keys) == 1 else None
                                host = next((value for rule in host_rules if isinstance(rule, dict) and
                                             rule.get("pathMatcher") == matcher.get("name") and
                                             isinstance(rule.get("hosts"), list)
                                             for value in rule["hosts"] if isinstance(value, str) and
                                             value and "*" not in value), None)
                                if host is None and len(host_rules) == 1 and host_rules[0].get("hosts") == ["*"]:
                                    host = "peaso-route.invalid"
                                if (isinstance(path, str) and path.startswith("/") and
                                        not any(char in path for char in "?#\r\n") and host and
                                        (position == 0 or all(earlier_excludes(earlier, path)
                                                              for earlier in ordered_rules[:position]))):
                                    services.extend(route_backends(selected_rule, "routeAction"))
                                    partial_route_witness = True
                                    a.step("url_route_rule", "allow", host=host, match_type=keys[0], path=path,
                                           priority=selected_rule["priority"],
                                           backends=route_backends(selected_rule, "routeAction"))
                                    break
                    if (not as_list(matcher.get("pathRules")) and not as_list(matcher.get("routeRules"))
                            and not matcher.get("defaultService") and not as_list(
                                (matcher.get("defaultRouteAction") or {}).get("weightedBackendServices"))):
                        redirect = redirect_action(matcher.get("defaultUrlRedirect"), "path_matcher_default")
                        if redirect:
                            redirects.append(redirect)
                    if isinstance(path_rules, list) and path_rules and not as_list(route_rules):
                        patterns = []
                        for rule in path_rules:
                            paths = rule.get("paths") if isinstance(rule, dict) else None
                            if not isinstance(paths, list) or not paths:
                                patterns = []
                                break
                            for pattern in paths:
                                if (not isinstance(pattern, str) or not pattern.startswith("/") or
                                        any(char in pattern for char in "?#\r\n") or
                                        ("*" in pattern and not pattern.endswith("/*")) or pattern.count("*") > 1):
                                    patterns = []
                                    break
                                patterns.append((pattern, rule))
                            if not patterns:
                                break
                        host = next((value for rule in host_rules if isinstance(rule, dict) and
                                     rule.get("pathMatcher") == matcher.get("name") and
                                     isinstance(rule.get("hosts"), list)
                                     for value in rule["hosts"] if isinstance(value, str) and value and
                                     "*" not in value), None)
                        if host is None and len(host_rules) == 1 and host_rules[0].get("hosts") == ["*"]:
                            host = "peaso-path.invalid"
                        if patterns and host:
                            for pattern, selected_rule in patterns:
                                witness = pattern[:-1] + "peaso-witness" if pattern.endswith("/*") else pattern
                                exact = [rule for other, rule in patterns if other == witness]
                                prefixes = [(len(other), rule) for other, rule in patterns
                                            if other.endswith("/*") and witness.startswith(other[:-1])]
                                winner = (exact[0] if len(exact) == 1 else None) if exact else (
                                    max(prefixes, key=lambda row: row[0])[1] if prefixes and
                                    len([row for row in prefixes if row[0] == max(item[0] for item in prefixes)]) == 1
                                    else None)
                                if winner is not selected_rule:
                                    continue
                                backend_refs = route_backends(selected_rule, "routeAction")
                                if backend_refs and not selected_rule.get("urlRedirect"):
                                    services.extend(backend_refs)
                                    universal_path_rule = (
                                        len(host_rules) == 1 and host_rules[0].get("hosts") == ["*"] and
                                        len(patterns) == 1 and pattern == "/*" and
                                        len(path_rules) == 1 and len(backend_refs) == 1)
                                    partial_route_witness = partial_route_witness or not universal_path_rule
                                    for ref in backend_refs:
                                        path_route_witnesses[ref] = {"host": host, "path": witness,
                                                                     "pattern": pattern}
                                    a.step("url_path_rule", "allow", host=host, path=witness,
                                           pattern=pattern, backends=backend_refs)
                                    continue
                                if not backend_refs:
                                    redirect = redirect_action(selected_rule.get("urlRedirect"), "path_rule")
                                    if redirect:
                                        redirect["match_path_type"] = ("prefixMatch" if pattern.endswith("/*")
                                                                        else "fullPathMatch")
                                        redirect["match_path"] = witness
                                        redirects.append(redirect)
                                        break
                    if isinstance(route_rules, list) and route_rules and not as_list(matcher.get("pathRules")):
                        priorities = [rule.get("priority") for rule in route_rules if isinstance(rule, dict)]
                        if (len(priorities) == len(route_rules) and
                                all(type(value) is int and 0 <= value <= 2147483647 for value in priorities) and
                                len(set(priorities)) == len(priorities)):
                            def redirect_paths(rule):
                                matches = rule.get("matchRules")
                                return ([(key, match[key]) for match in matches if isinstance(match, dict)
                                         for key in ("prefixMatch", "fullPathMatch")
                                         if set(match) <= {key, "ignoreCase"} and isinstance(match.get(key), str)
                                         and (key != "prefixMatch" or match[key] == "" or match[key].startswith("/"))
                                         and (key != "fullPathMatch" or match[key].startswith("/"))
                                         and not any(char in match[key] for char in "?#\r\n")
                                         and type(match.get("ignoreCase", False)) is bool]
                                        if isinstance(matches, list) else [])
                            prior = []
                            found_route_redirect = False
                            for rule in sorted(route_rules, key=lambda row: row["priority"]):
                                if not rule.get("service") and not rule.get("routeAction"):
                                    for kind, path in redirect_paths(rule):
                                        if prior and (kind != "fullPathMatch" or
                                                not all(earlier_excludes(earlier, path) for earlier in prior)):
                                            continue
                                        redirect = redirect_action(rule.get("urlRedirect"),
                                                                   "first_route_rule" if not prior else "disjoint_route_rule")
                                        if redirect:
                                            redirect["match_path_type"], redirect["match_path"] = kind, path
                                            redirects.append(redirect)
                                            found_route_redirect = True
                                            break
                                if found_route_redirect:
                                    break
                                prior.append(rule)
        elif proxy["data"].get("service"):
            services = [proxy["data"]["service"]]
        services = [s for s in dict.fromkeys(services) if s]
        routes, buckets = [], []
        unresolved_backend = not services and not redirects
        if not services and not redirects:
            a.gap("backend", "target proxy has no provably reachable collected URL-map backend route")
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
                if service in path_route_witnesses:
                    origin["host_witness"] = path_route_witnesses[service]["host"]
                    origin["path_witness"] = path_route_witnesses[service]["path"]
                    origin["path_pattern"] = path_route_witnesses[service]["pattern"]
                storage = inventory.get("bucket", detail.get("bucketName"))
                projects = [row["data"] for row in inventory.items("project")
                            if row.get("scope") == resource.get("scope")]
                project_number = (str(projects[0]["projectNumber"])
                                  if len(projects) == 1 and projects[0].get("projectNumber") is not None else None)
                service_agent = (f"service-{project_number}@https-lb.iam.gserviceaccount.com"
                                 if project_number and project_number.isdecimal() else None)
                policy = storage["data"].get("iamPolicy") if storage else None
                grants = []
                if service_agent and isinstance(policy, dict) and policy.get("collection_status") in (None, "collected"):
                    grants = [binding for binding in as_list(policy.get("bindings"))
                              if isinstance(binding, dict) and binding.get("role") == "roles/storage.objectViewer"
                              and not binding.get("condition") and
                              f"serviceAccount:{service_agent}" in as_list(binding.get("members"))]
                inherited_grants = []
                root = inventory.get("iam_policy", storage["scope"]) if storage else None
                root_policy = root["data"] if root else None
                if service_agent and isinstance(root_policy, dict) and root_policy.get("collection_status") in (None, "collected"):
                    for binding in as_list(root_policy.get("bindings")):
                        if not isinstance(binding, dict) or binding.get("condition") or f"serviceAccount:{service_agent}" not in as_list(binding.get("members")):
                            continue
                        role = binding.get("role")
                        role_row = inventory.get("iam_role", role) if isinstance(role, str) else None
                        permissions = role_row["data"].get("includedPermissions") if role_row else None
                        if isinstance(permissions, list) and "storage.objects.get" in permissions:
                            inherited_grants.append({"scope": storage["scope"], "role": role,
                                                     "permission": "storage.objects.get"})
                public_grants = []
                public_object_acl = []
                public_folder_grants = []
                if storage and isinstance(policy, dict) and policy.get("collection_status") in (None, "collected"):
                    bucket_data = storage["data"]
                    coverage = bucket_data.get("_coverage")
                    iam_coverage = coverage.get("iamPolicy") if isinstance(coverage, dict) else None
                    config = bucket_data.get("iamConfiguration")
                    prevention = config.get("publicAccessPrevention") if isinstance(config, dict) else None
                    ip_filter = bucket_data.get("ipFilter")
                    def public_object_get_role(role):
                        if role == "roles/storage.objectViewer":
                            return True
                        role_row = inventory.get("iam_role", role) if isinstance(role, str) else None
                        detail = role_row["data"] if role_row else None
                        return (isinstance(detail, dict) and detail.get("stage") != "DISABLED" and
                                isinstance(detail.get("includedPermissions"), list) and
                                "storage.objects.get" in detail["includedPermissions"])
                    if (not isinstance(iam_coverage, dict) or iam_coverage.get("status") in (None, "collected")) and (
                            prevention == "not_enforced" and (ip_filter is None or
                            isinstance(ip_filter, dict) and ip_filter.get("mode") == "Disabled")):
                        public_grants = [{"role": binding["role"], "member": member,
                                          **({"permission": "storage.objects.get"} if binding["role"] != "roles/storage.objectViewer" else {})}
                                         for binding in as_list(policy.get("bindings"))
                                         if isinstance(binding, dict) and public_object_get_role(binding.get("role"))
                                         and not binding.get("condition")
                                         for member in as_list(binding.get("members"))
                                         if member in ("allUsers", "allAuthenticatedUsers")]
                        if isinstance(root_policy, dict) and root_policy.get("collection_status") in (None, "collected"):
                            public_grants.extend({"role": binding["role"], "member": member,
                                                  "scope": storage["scope"],
                                                  **({"permission": "storage.objects.get"} if binding["role"] != "roles/storage.objectViewer" else {})}
                                                 for binding in as_list(root_policy.get("bindings"))
                                                 if isinstance(binding, dict) and public_object_get_role(binding.get("role"))
                                                 and not binding.get("condition")
                                                 for member in as_list(binding.get("members"))
                                                 if member in ("allUsers", "allAuthenticatedUsers"))
                if storage:
                    bucket_data = storage["data"]
                    config = bucket_data.get("iamConfiguration")
                    prevention = config.get("publicAccessPrevention") if isinstance(config, dict) else None
                    uniform = config.get("uniformBucketLevelAccess") if isinstance(config, dict) else None
                    ip_filter = bucket_data.get("ipFilter")
                    envelope = bucket_data.get("objectAccessControls")
                    top_level_default = (url_map and isinstance(m, dict) and m.get("defaultService") == service
                                         and (not as_list(m.get("hostRules")) or unmatched_host is not None))
                    matcher_default = (url_map and isinstance(m, dict) and any(
                        isinstance(matcher, dict) and matcher.get("name") in host_matchers
                        and matcher.get("defaultService") == service
                        and matcher.get("pathRules") in (None, []) and matcher.get("routeRules") in (None, [])
                        for matcher in as_list(m.get("pathMatchers"))))
                    default_route = top_level_default or matcher_default
                    if top_level_default and unmatched_host:
                        origin["host_witness"] = unmatched_host
                    if (default_route and isinstance(uniform, dict) and uniform.get("enabled") is False
                            and prevention == "not_enforced" and
                            (ip_filter is None or isinstance(ip_filter, dict) and ip_filter.get("mode") == "Disabled")
                            and isinstance(envelope, dict) and envelope.get("status") == "collected"
                            and envelope.get("all_pages") is True and envelope.get("all_objects") is True
                            and envelope.get("all_versions") is True and envelope.get("projection") == "full"
                            and envelope.get("source_inventory") == "object_acl"
                            and isinstance(envelope.get("source_requests"), list)
                            and bool(envelope["source_requests"])):
                        public_object_acl = [{"role": f"object ACL {row['role']}", "member": row["entity"],
                                              "source": "objectAccessControls"}
                                             for row in as_list(envelope.get("items"))
                                             if isinstance(row, dict) and row.get("entity") in ("allUsers", "allAuthenticatedUsers")
                                             and row.get("role") in ("READER", "OWNER")]
                        public_grants.extend(public_object_acl)
                    if (default_route and isinstance(uniform, dict) and uniform.get("enabled") is True
                            and prevention == "not_enforced" and
                            (ip_filter is None or isinstance(ip_filter, dict) and ip_filter.get("mode") == "Disabled")):
                        for folder_row in inventory.items("managed_folder"):
                            folder = folder_row["data"]
                            if (not isinstance(folder, dict) or folder_row.get("scope") != storage.get("scope") or
                                    folder.get("bucket") != bucket_data.get("name") or
                                    not isinstance(folder.get("name"), str) or not folder["name"].endswith("/")):
                                continue
                            folder_policy = folder.get("iamPolicy")
                            if not isinstance(folder_policy, dict) or folder_policy.get("collection_status") not in (None, "collected"):
                                continue
                            for binding in as_list(folder_policy.get("bindings")):
                                if not isinstance(binding, dict) or binding.get("condition"):
                                    continue
                                role = binding.get("role")
                                role_row = inventory.get("iam_role", role) if isinstance(role, str) else None
                                role_data = role_row["data"] if role_row else None
                                object_read = (role == "roles/storage.objectViewer" or
                                               isinstance(role_data, dict) and role_data.get("stage") != "DISABLED"
                                               and isinstance(role_data.get("includedPermissions"), list)
                                               and "storage.objects.get" in role_data["includedPermissions"])
                                if object_read:
                                    public_folder_grants.extend({"role": role, "member": member,
                                                                 "folder": folder["name"], "source": "managed_folder"}
                                                                for member in as_list(binding.get("members"))
                                                                if member in ("allUsers", "allAuthenticatedUsers"))
                        public_grants.extend(public_folder_grants)
                origin["cdn_service_agent_read_grant"] = bool(grants or inherited_grants)
                origin["cdn_service_agent_inherited_grants"] = inherited_grants
                origin["public_origin_read_grants"] = public_grants
                origin["public_object_acl_grants"] = public_object_acl
                origin["public_managed_folder_grants"] = public_folder_grants
                origin["origin_bucket_collected"] = storage is not None
                a.step("cdn_origin", "allow" if grants or inherited_grants or public_grants else "unknown", **origin,
                       service_agent=service_agent, object_content_observed=False)
                if not grants and not inherited_grants and not public_grants:
                    a.gap("origin", "origin object-read authorization or cached object state is not established by the backend bucket")
                buckets.append(origin)
                routes.append({**origin, "edge_security_policy": detail.get("edgeSecurityPolicy"),
                               "backend_security_policy": None})
                continue
            backend = inventory.get("backend_service", service)
            if backend is None:
                unresolved_backend = True
                a.gap("backend", f"backend service {service} not collected", "compute backendServices")
                continue
            routes.append({"backend_service": service,
                           "edge_security_policy": backend["data"].get("edgeSecurityPolicy"),
                           "backend_security_policy": backend["data"].get("securityPolicy"),
                           "cdn_enabled": backend["data"].get("enableCDN") is True})
            if backend["data"].get("iap", {}).get("enabled"):
                a.authenticated = True
                a.notes.append(f"IAP enabled on {service}")
        decisions = []
        for route in routes:
            edge_ref, backend_ref = route["edge_security_policy"], route["backend_security_policy"]
            edge = _gcp_armor_decision(inventory, edge_ref) if edge_ref else "allow"
            backend = _gcp_armor_decision(inventory, backend_ref) if backend_ref else "allow"
            if edge == "block":
                outcome = "block"
            elif backend == "block" and not route.get("cdn_enabled"):
                outcome = "block"
            elif edge == "allow" and backend == "allow":
                outcome = "allow"
            else:
                outcome = "unknown"
            decisions.append({**route, "edge_decision": edge, "backend_decision": backend,
                              "decision": outcome})
        if any(row["decision"] == "allow" for row in decisions):
            a.step("cloud_armor", "allow", routes=decisions, backend_buckets=buckets)
            if partial_route_witness or any(row["decision"] == "allow" and row.get("host_witness") and
                   row.get("public_origin_read_grants") for row in decisions):
                for gap in a.unresolved:
                    if gap["layer"] == "backend":
                        gap["decisive"] = False
        elif decisions and not unresolved_backend and not partial_route_witness and all(row["decision"] == "block" for row in decisions):
            a.step("cloud_armor", "block", routes=decisions, backend_buckets=buckets)
            a.ports = {}
        elif not redirects:
            a.step("cloud_armor", "unknown", routes=decisions, backend_buckets=buckets)
            if partial_route_witness and decisions and all(row["decision"] == "block" for row in decisions):
                a.gap("backend", "selected path or route-rule backend is blocked; other host and path routes remain unresolved")
            else:
                a.gap("cloud_armor", "edge/backend policy decision or CDN cache-hit path is request dependent or unavailable",
                      STATIC_GAPS["gcp"][0]["fact"])
        if redirects:
            a.step("url_redirect", "allow", routes=redirects, url_map=url_map)
            a.ports = ports
            a.blocked_by = None
            for gap in a.unresolved:
                if gap["layer"] in ("backend", "cloud_armor"):
                    gap["decisive"] = False
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


def _gcp_cloudrun_instance(snapshot, inventory, resource):
    data = resource["data"]
    ingress = data.get("ingress")
    if ingress in ("INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"):
        return None
    if ingress != "INGRESS_TRAFFIC_ALL" and not data.get("urls"):
        return None
    a = Assessment(resource, "serverless")
    raw_urls = data.get("urls")
    if not isinstance(raw_urls, list) or not raw_urls:
        a.gap("public_endpoint", "Cloud Run instance has public ingress but no recorded serving URLs")
        return a
    origins = []
    for url in raw_urls:
        try:
            parsed = urlsplit(url) if isinstance(url, str) else None
            valid = (parsed is not None and parsed.scheme == "https" and bool(parsed.hostname) and
                     not parsed.username and not parsed.password and parsed.port in (None, 443))
        except ValueError:
            valid = False
        if not valid:
            a.gap("public_endpoint", "Cloud Run instance serving URL is malformed or not HTTPS")
            return a
        origins.append(f"https://{parsed.hostname}")
    a.addresses = sorted(set(origins))
    if ingress != "INGRESS_TRAFFIC_ALL":
        a.gap("ingress", "Cloud Run instance has serving URLs but public ingress is not confirmed")
        return a
    condition = data.get("terminalCondition")
    condition_state = condition.get("state") if isinstance(condition, dict) else None
    if (data.get("deleteTime") or data.get("reconciling") is True or
            condition_state not in (None, "CONDITION_SUCCEEDED")):
        a.gap("instance_state", "Cloud Run instance is deleted, reconciling, or has no successful serving condition")
        return a
    if data.get("defaultUriDisabled") is True:
        a.gap("public_endpoint", "Cloud Run instance default URI is disabled; alternate URL resolution is unresolved")
        return a
    if data.get("iapEnabled") is True:
        a.gap("authorization", "Cloud Run instance IAP is enabled; IAP user grants are unresolved")
        return a
    if data.get("invokerIamDisabled") is True:
        a.step("invoker", "allow", invoker_iam_disabled=True)
    else:
        policy = data.get("iamPolicy")
        if isinstance(policy, dict) and policy.get("collection_status") not in (None, "collected"):
            policy = None
        public, conditional = _gcp_invoker(policy, {"roles/run.invoker", "roles/run.servicesInvoker"})
        if public is None:
            a.gap("invoker", "Cloud Run instance IAM policy is unavailable")
            return a
        if public:
            a.step("invoker", "allow", public_members=public)
            a.authenticated = "allUsers" not in public
        elif conditional:
            a.gap("invoker", "Cloud Run instance public invoker grant has an IAM condition")
            return a
        else:
            a.gap("invoker", "Cloud Run instance has no direct public invoker grant; inherited and named-principal access remain unresolved")
            return a
    a.step("instance_url", "allow", ingress="INGRESS_TRAFFIC_ALL", origins=a.addresses,
           default_uri_disabled=False)
    a.ports = pset("tcp", 443, 443)
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


def _gcp_gke_exposure_service(snapshot, inventory, resource):
    """Preserve a live Service exposure candidate until the cloud path is joined."""
    data = resource["data"]
    state = data.get("inventoryStatus")
    if state == "collected":
        return None
    if state is not None:
        a = Assessment(resource, "gke_workload")
        a.explicit = "UNKNOWN"
        a.step("kubernetes_inventory", "unknown", cluster=data.get("cluster"), status=state,
               reason=data.get("reason"))
        a.gap("inventory", "GKE Kubernetes Service inventory was not completely read")
        return a
    spec = data.get("spec") if isinstance(data.get("spec"), dict) else {}
    kind = spec.get("type")
    external = [value for value in as_list(spec.get("externalIPs")) if _public_ip(value)]
    if kind not in ("LoadBalancer", "NodePort") and not external and not data.get("negConfigured") and not data.get("negStatus"):
        return None
    a = Assessment(resource, "gke_workload")
    a.explicit = "UNKNOWN"
    ingress = ((data.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []
    a.addresses = list(dict.fromkeys(external + [item["ip"] for item in ingress
        if isinstance(item, dict) and _public_ip(item.get("ip"))]))
    ports = {}
    for item in as_list(spec.get("ports")):
        if not isinstance(item, dict):
            continue
        port = item.get("nodePort") if kind == "NodePort" else item.get("port")
        if isinstance(port, int) and 1 <= port <= 65535:
            ports = union(ports, pset(item.get("protocol", "TCP"), port, port) or {})
    a.ports = ports
    a.step("kubernetes_service", "unknown", cluster=data.get("cluster"), service_type=kind,
           addresses=a.addresses, ports=describe(ports), source_ranges=spec.get("loadBalancerSourceRanges"),
           annotations=data.get("annotations"), neg_status=data.get("negStatus"),
           neg_status_unresolved=data.get("negStatusUnresolved"))
    opened = {}
    if kind in ("NodePort", "LoadBalancer"):
        opened = _gcp_gke_nodeport_direct_node(inventory, resource, a) or {}
    if kind == "LoadBalancer":
        cloud_opened = _gcp_gke_service_cloud_edge(snapshot, inventory, resource, a)
        if cloud_opened:
            opened = union(opened, cloud_opened)
            a.notes.append("Public Service cloud-edge listener is proven; Kubernetes application backend health is not established by this join")
    if data.get("negStatus"):
        neg_opened = _gcp_gke_standalone_neg_edge(snapshot, inventory, resource, a)
        if neg_opened:
            opened = union(opened, neg_opened)
            a.notes.append("Public standalone NEG cloud-edge listener is proven; application Pod health is not established")
    if opened:
        a.explicit = "FAIL"
        a.ports = opened
        return a
    a.gap("firewall", "GKE Service listener, cloud forwarding rule, node firewall and backend path need an effective join")
    return a


def _gcp_gke_standalone_neg_edge(snapshot, inventory, resource, assessment):
    data = resource["data"]
    cluster = data.get("cluster")
    markers = [row["data"] for row in inventory.items("gke_exposure_service")
               if row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") is not None]
    status = data.get("negStatus")
    if (len(markers) != 1 or markers[0].get("inventoryStatus") != "collected"
            or not isinstance(status, dict) or inventory.state("network_endpoint_group", resource.get("scope")) != "collected"):
        return None
    groups = status.get("networkEndpointGroups")
    zones = status.get("zones")
    ports = {str(port.get("port")) for port in as_list((data.get("spec") or {}).get("ports"))
             if isinstance(port, dict) and type(port.get("port")) is int}
    if (not isinstance(groups, dict) or not isinstance(zones, list)
            or not set(groups).intersection(ports)):
        return None
    neg_refs = set()
    for name in {group for port, group in groups.items() if port in ports and isinstance(group, str)}:
        for zone in zones:
            matches = [row for row in inventory.items("network_endpoint_group")
                       if row.get("scope") == resource.get("scope") and row["data"].get("name") == name
                       and isinstance(row["data"].get("selfLink"), str)
                       and row["data"]["selfLink"].endswith("/zones/" + str(zone) + "/networkEndpointGroups/" + name)
                       and row["data"].get("networkEndpointType") == "GCE_VM_IP_PORT"]
            if len(matches) == 1:
                neg_refs.add(matches[0]["data"]["selfLink"])
    if not neg_refs:
        return None
    backend_refs = set()
    for backend in inventory.items("backend_service"):
        detail = backend["data"]
        ref = detail.get("selfLink")
        if (backend.get("scope") == resource.get("scope") and isinstance(ref, str)
                and any(isinstance(row, dict) and row.get("group") in neg_refs
                        for row in as_list(detail.get("backends")))):
            backend_refs.add(ref)
    if not backend_refs:
        return None
    opened = {}
    for rule in inventory.items("forwarding_rule"):
        detail = rule["data"]
        if (rule.get("scope") != resource.get("scope") or not _public_ip(detail.get("IPAddress"))
                or detail.get("loadBalancingScheme") not in ("EXTERNAL", "EXTERNAL_MANAGED")):
            continue
        direct = detail.get("backendService") in backend_refs
        if not direct and not isinstance(detail.get("target"), str):
            continue
        edge = _gcp_forwarding_rule(snapshot, inventory, rule)
        if edge is None or edge.verdict() != "FAIL" or empty(edge.ports or {}):
            continue
        routes = [route for step in edge.path if step.get("layer") == "cloud_armor"
                  for route in as_list(step.get("routes")) if isinstance(route, dict)
                  and route.get("backend_service") in backend_refs and route.get("decision") == "allow"]
        if not direct and not routes:
            continue
        opened = union(opened, edge.ports)
        assessment.addresses = list(dict.fromkeys(assessment.addresses + [detail["IPAddress"]]))
        assessment.step("gke_standalone_neg_edge", "allow", neg_refs=sorted(neg_refs),
                        backend_services=sorted(backend_refs), forwarding_rule=detail.get("name"),
                        public_ip=detail["IPAddress"], ports=describe(edge.ports), cloud_path=edge.path)
    return opened or None


def _gcp_gke_service_cloud_edge(snapshot, inventory, resource, assessment):
    data = resource["data"]
    spec = data.get("spec") if isinstance(data.get("spec"), dict) else {}
    source_ranges = spec.get("loadBalancerSourceRanges")
    if source_ranges is not None and (not isinstance(source_ranges, list) or not source_ranges
            or any(not isinstance(value, str) or _cidr(value) is None for value in source_ranges)):
        assessment.gap("source_ranges", "LoadBalancer Service source ranges are malformed or unavailable")
        return None
    cluster = data.get("cluster")
    markers = [row["data"] for row in inventory.items("gke_exposure_service")
               if row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") is not None]
    if len(markers) != 1 or markers[0].get("inventoryStatus") != "collected":
        return None
    annotations = data.get("annotations")
    if not isinstance(annotations, dict):
        return None
    backend_name = annotations.get("service.kubernetes.io/backend-service")
    if backend_name is not None and (not isinstance(backend_name, str)
                                     or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", backend_name)):
        return None
    ingress = ((data.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []
    public_ips = {item.get("ip") for item in ingress if isinstance(item, dict) and _public_ip(item.get("ip"))}
    if not public_ips:
        return None
    opened = {}
    for protocol, annotation_key in (("TCP", "tcp-forwarding-rule"), ("UDP", "udp-forwarding-rule"),
                                      ("L3_DEFAULT", "l3-forwarding-rule"),
                                      ("L3_DEFAULT", "l3-forwarding-rule-ipv6")):
        rule_name = annotations.get("service.kubernetes.io/" + annotation_key)
        if not isinstance(rule_name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", rule_name):
            continue
        candidates = [row for row in inventory.items("forwarding_rule")
                      if row.get("scope") == resource.get("scope")
                      and row["data"].get("name") == rule_name
                      and row["data"].get("IPAddress") in public_ips
                      and row["data"].get("loadBalancingScheme") in ("EXTERNAL", "EXTERNAL_MANAGED")
                      and row["data"].get("IPProtocol") == protocol
                      and (protocol != "L3_DEFAULT" or row["data"].get("allPorts") is True)
                      and (isinstance(backend_name, str)
                           and isinstance(row["data"].get("backendService"), str)
                           and row["data"]["backendService"].endswith("/backendServices/" + backend_name)
                           or backend_name is None and isinstance(row["data"].get("target"), str)
                           and "/targetPools/" in row["data"]["target"])]
        if len(candidates) != 1:
            continue
        rule = candidates[0]
        destination_kind = "backend_service" if backend_name is not None else "target_pool"
        destination_ref = rule["data"].get("backendService" if backend_name is not None else "target")
        destination = inventory.get(destination_kind, destination_ref)
        if destination is None or destination.get("scope") != resource.get("scope"):
            continue
        edge = _gcp_forwarding_rule(snapshot, inventory, rule)
        if edge is None or edge.verdict() != "FAIL":
            continue
        service_ports = {}
        for port in as_list((data.get("spec") or {}).get("ports")):
            if isinstance(port, dict) and (protocol == "L3_DEFAULT" or port.get("protocol", "TCP") == protocol) and type(port.get("port")) is int:
                service_ports = union(service_ports, pset(port.get("protocol", "TCP"), port["port"], port["port"]) or {})
        exposed = intersect(edge.ports or {}, service_ports)
        if empty(exposed):
            continue
        if source_ranges is not None:
            ip = ipaddress.ip_address(rule["data"]["IPAddress"])
            family = "0.0.0.0/0" if ip.version == 4 else "::/0"
            family_ranges = [value for value in source_ranges if _cidr(value).version == ip.version]
            if not any(_cidr(value).prefixlen == 0 for value in family_ranges):
                def public_overlap(firewall_ranges):
                    for service_value in family_ranges:
                        service_network = _cidr(service_value)
                        for firewall_value in as_list(firewall_ranges):
                            firewall_network = _cidr(firewall_value)
                            if firewall_network is None or firewall_network.version != ip.version:
                                continue
                            if service_network.overlaps(firewall_network):
                                overlap = (service_network if service_network.prefixlen >= firewall_network.prefixlen
                                           else firewall_network)
                                address_type = ipaddress.IPv4Address if overlap.version == 4 else ipaddress.IPv6Address
                                last = overlap.num_addresses - 1
                                if any(address_type(int(overlap.network_address) + offset).is_global
                                       for offset in (0, last // 4, last // 2, last * 3 // 4, last)):
                                    return True
                    return False
                terminal_allow = any(step.get("layer") == "effective_firewall"
                    and step.get("decision") == "allow"
                    and step.get("basis") == "terminal hierarchical ingress rule"
                    and family in as_list(step.get("source_ranges"))
                    and public_overlap(step.get("source_ranges")) for step in edge.path)
                def matched_ports(row):
                    allowed = {}
                    for label in as_list(row.get("ports")):
                        match = re.fullmatch(r"(tcp|udp)/(all|[0-9]{1,5}(?:-[0-9]{1,5})?)", label) if isinstance(label, str) else None
                        if match:
                            allowed = union(allowed, _port_spec(match.group(1), match.group(2)) or {})
                    return allowed
                vpc_allow = any(step.get("layer") == "firewall" and step.get("decision") == "allow"
                    and any(isinstance(matched, dict) and matched.get("action") == "allow"
                            and public_overlap(matched.get("source_ranges"))
                            and not empty(intersect(matched_ports(matched), exposed))
                            for matched in as_list(step.get("matched_rules"))) for step in edge.path)
                if not (terminal_allow or vpc_allow):
                    assessment.gap("source_ranges", "narrowed LoadBalancer source ranges need an exact intersection with effective backend firewall sources")
                    continue
        opened = union(opened, exposed)
        assessment.step("gke_cloud_edge", "allow", forwarding_rule=rule_name,
                        backend_service=backend_name, target_pool=destination_ref if backend_name is None else None,
                        public_ip=rule["data"]["IPAddress"], ports=describe(exposed), cloud_path=edge.path)
    return opened or None


def _gcp_gke_nodeport_direct_node(inventory, resource, assessment):
    data = resource["data"]
    cluster, namespace, service = data.get("cluster"), data.get("namespace"), data.get("kubernetesName")
    if not all(isinstance(value, str) and value for value in (cluster, namespace, service)):
        return None
    for kind in ("gke_exposure_service", "gke_exposure_endpointslice", "gke_exposure_node"):
        markers = [row["data"] for row in inventory.items(kind)
                   if row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") is not None]
        if len(markers) != 1 or markers[0].get("inventoryStatus") != "collected":
            return None
    slices = [row["data"] for row in inventory.items("gke_exposure_endpointslice")
              if row["data"].get("cluster") == cluster and row["data"].get("namespace") == namespace
              and row["data"].get("serviceName") == service and row["data"].get("inventoryStatus") is None
              and row["data"].get("addressType") in ("IPv4", "IPv6")]
    spec = data.get("spec") or {}
    if spec.get("externalTrafficPolicy", "Cluster") not in ("Cluster", "Local"):
        return None
    local = spec.get("externalTrafficPolicy", "Cluster") == "Local"
    nodes = [row["data"] for row in inventory.items("gke_exposure_node")
             if row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") is None
             and isinstance(row["data"].get("kubernetesName"), str)]
    opened = {}
    for service_port in as_list(spec.get("ports")):
        if not isinstance(service_port, dict) or type(service_port.get("nodePort")) is not int:
            continue
        protocol = service_port.get("protocol", "TCP")
        if protocol not in ("TCP", "UDP"):
            continue
        port_name = service_port.get("name", "")
        target = service_port.get("targetPort", service_port.get("port"))
        if not isinstance(port_name, str) or not (type(target) is int and 1 <= target <= 65535
                                                 or isinstance(target, str) and target):
            continue
        ready_nodes = []
        for endpoint_slice in slices:
            if not any(isinstance(port, dict) and port.get("name", "") == port_name
                       and port.get("protocol") == protocol and type(port.get("port")) is int
                       and (type(target) is not int or port["port"] == target)
                       for port in as_list(endpoint_slice.get("ports"))):
                continue
            if type(endpoint_slice.get("readyEndpointCount")) is not int or endpoint_slice["readyEndpointCount"] <= 0:
                continue
            ready_nodes.extend(as_list(endpoint_slice.get("readyNodeNames")))
        if not ready_nodes:
            continue
        candidate_nodes = [node for node in nodes if not local or node["kubernetesName"] in ready_nodes]
        exposed_port = service_port["nodePort"]
        ports = pset(protocol, exposed_port, exposed_port) or {}
        for node in candidate_nodes:
            reached = _gcp_gke_direct_node(inventory, resource, assessment, ports,
                                                node_name=node["kubernetesName"], require_host_ip=False)
            if reached:
                opened = union(opened, reached)
                assessment.step("kubernetes_backend", "allow", service=service,
                                namespace=namespace, ready_endpoints=len(ready_nodes),
                                traffic_policy=spec.get("externalTrafficPolicy", "Cluster"),
                                node=node["kubernetesName"],
                                exposed_ports=describe(reached))
    return opened or None


def _gcp_gke_exposure_ingress(snapshot, inventory, resource):
    """Preserve declared Ingress reachability until its controller path is proven."""
    data = resource["data"]
    state = data.get("inventoryStatus")
    if state == "collected":
        return None
    a = Assessment(resource, "gke_workload")
    a.explicit = "UNKNOWN"
    if state is not None:
        a.step("kubernetes_inventory", "unknown", cluster=data.get("cluster"), status=state,
               reason=data.get("reason"))
        a.gap("inventory", "GKE Kubernetes Ingress inventory was not completely read")
        return a
    addresses = ((data.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []
    a.addresses = list(dict.fromkeys(item["ip"] for item in addresses
        if isinstance(item, dict) and _public_ip(item.get("ip"))))
    a.step("kubernetes_ingress", "unknown", cluster=data.get("cluster"),
           ingress_class=data.get("ingressClassName"), hosts=data.get("hosts"),
           default_backend=data.get("hasDefaultBackend"), addresses=a.addresses,
           controller_annotations=data.get("annotations"))
    opened = _gcp_gke_ingress_cloud_edge(snapshot, inventory, resource, a)
    if opened:
        a.explicit = "FAIL"
        a.ports = opened
        a.notes.append("Public Ingress cloud-edge listener is proven; Kubernetes application backend health is not established by this join")
        return a
    a.gap("controller", "GKE Ingress controller, cloud forwarding rule, firewall and backend path need an effective join")
    return a


def _gcp_gke_ingress_cloud_edge(snapshot, inventory, resource, assessment):
    data = resource["data"]
    annotations = data.get("annotations")
    if (not isinstance(annotations, dict) or not assessment.addresses
            or not data.get("hasDefaultBackend") and not as_list(data.get("hosts"))):
        return None
    ingress_class = annotations.get("kubernetes.io/ingress.class")
    if ingress_class not in (None, "gce") or ingress_class is None and data.get("ingressClassName") is not None:
        return None
    cluster = data.get("cluster")
    markers = [row["data"] for row in inventory.items("gke_exposure_ingress")
               if row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") is not None]
    if len(markers) != 1 or markers[0].get("inventoryStatus") != "collected":
        return None
    index = inventory.network_cache.get("gcp_ingress_forwarding_rules")
    if index is None:
        index = {}
        for row in inventory.items("forwarding_rule"):
            detail = row["data"]
            if isinstance(detail.get("name"), str) and isinstance(detail.get("IPAddress"), str):
                index.setdefault((row.get("scope"), detail["name"], detail["IPAddress"]), []).append(row)
        inventory.network_cache["gcp_ingress_forwarding_rules"] = index
    opened = {}
    for fr_key, proxy_key, target_kind, port in (
            ("ingress.kubernetes.io/forwarding-rule", "ingress.kubernetes.io/target-proxy", "targetHttpProxies", 80),
            ("ingress.kubernetes.io/https-forwarding-rule", "ingress.kubernetes.io/https-target-proxy", "targetHttpsProxies", 443)):
        fr_name, proxy_name, map_name = (annotations.get(fr_key), annotations.get(proxy_key),
                                        annotations.get("ingress.kubernetes.io/url-map"))
        if not all(isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value)
                   for value in (fr_name, proxy_name, map_name)):
            continue
        rules = [row for address in assessment.addresses
                 for row in index.get((resource.get("scope"), fr_name, address), ())
                 if row["data"].get("loadBalancingScheme") in ("EXTERNAL", "EXTERNAL_MANAGED")
                 and row["data"].get("IPProtocol", "TCP") == "TCP"
                 and isinstance(row["data"].get("target"), str)
                 and row["data"]["target"].endswith("/" + target_kind + "/" + proxy_name)]
        if len(rules) != 1:
            continue
        rule = rules[0]
        proxy = inventory.get("target_proxy", rule["data"]["target"])
        url_map = proxy["data"].get("urlMap") if proxy else None
        if not isinstance(url_map, str) or not url_map.endswith("/urlMaps/" + map_name):
            continue
        edge = _gcp_forwarding_rule(snapshot, inventory, rule)
        if edge.verdict() != "FAIL":
            continue
        exposed = intersect(edge.ports or {}, pset("tcp", port, port) or {})
        if empty(exposed):
            continue
        opened = union(opened, exposed)
        assessment.step("gke_cloud_edge", "allow", forwarding_rule=fr_name, target_proxy=proxy_name,
                        url_map=map_name, public_ip=rule["data"]["IPAddress"], ports=describe(exposed),
                        cloud_path=edge.path)
    return opened or None


def _gcp_gke_exposure_pod(snapshot, inventory, resource):
    """Preserve host-bound Pod candidates until node exposure is proven."""
    data = resource["data"]
    state = data.get("inventoryStatus")
    if state == "collected":
        return None
    if state is None and (data.get("phase") in ("Succeeded", "Failed")
                          or not data.get("hostNetwork") and not data.get("hostPorts")):
        return None
    a = Assessment(resource, "gke_workload")
    a.explicit = "UNKNOWN"
    if state is not None:
        a.step("kubernetes_inventory", "unknown", cluster=data.get("cluster"), status=state,
               reason=data.get("reason"))
        a.gap("inventory", "GKE Kubernetes Pod inventory was not completely read")
        return a
    host_ip = data.get("hostIP")
    a.addresses = [host_ip] if _public_ip(host_ip) else []
    ports = {}
    wildcard_ports = {4: {}, 6: {}}
    private_bind_ports = {}
    public_bind_ports = {}
    for item in as_list(data.get("hostPorts")):
        if not isinstance(item, dict):
            continue
        port = item.get("hostPort")
        if type(port) is int and 1 <= port <= 65535:
            declared = pset(item.get("protocol", "TCP"), port, port) or {}
            ports = union(ports, declared)
            bind_ip = item.get("bindIP", "0.0.0.0")
            if bind_ip in ("0.0.0.0", "::"):
                version = 4 if bind_ip == "0.0.0.0" else 6
                wildcard_ports[version] = union(wildcard_ports[version], declared)
            elif isinstance(bind_ip, str):
                try:
                    address = ipaddress.ip_address(bind_ip)
                except ValueError:
                    continue
                if address.version == 4 and not address.is_global:
                    private_bind_ports[bind_ip] = union(private_bind_ports.get(bind_ip, {}), declared)
                elif address.version == 6 and address.is_global:
                    public_bind_ports[bind_ip] = union(public_bind_ports.get(bind_ip, {}), declared)
    a.ports = ports
    a.step("kubernetes_pod", "unknown", cluster=data.get("cluster"), node=data.get("nodeName"),
           host_network=data.get("hostNetwork"), host_ip=host_ip, host_ports=describe(ports),
           phase=data.get("phase"))
    if data.get("hostNetwork") is True and empty(ports):
        a.gap("runtime_socket", "Kubernetes Pod API does not enumerate listening sockets; a hostNetwork process can listen without declaring container ports")
        return a
    if data.get("phase") == "Running":
        opened = {}
        for version, bound_ports in wildcard_ports.items():
            if not empty(bound_ports):
                opened = union(opened, _gcp_gke_direct_node(inventory, resource, a, bound_ports,
                                                             allowed_ip_version=version) or {})
        for bind_ip, bound_ports in private_bind_ports.items():
            opened = union(opened, _gcp_gke_direct_node(inventory, resource, a, bound_ports,
                                                         required_private_ip=bind_ip) or {})
        for bind_ip, bound_ports in public_bind_ports.items():
            opened = union(opened, _gcp_gke_direct_node(inventory, resource, a, bound_ports,
                                                         required_public_ip=bind_ip) or {})
        if opened:
            a.explicit = "FAIL"
            a.ports = opened
            return a
    a.gap("node_firewall", "GKE Pod host-bound port, bind address, node address and effective firewall path need a join")
    return a


def _gcp_gke_direct_node(inventory, resource, assessment, ports, *, node_name=None, require_host_ip=True,
                         required_private_ip=None, required_public_ip=None, allowed_ip_version=None):
    """Prove a node listener through one exact Node, VM and effective rule set."""
    data = resource["data"]
    cluster, host_ip = data.get("cluster"), data.get("hostIP")
    node_name = node_name or data.get("nodeName")
    if not all(isinstance(value, str) and value for value in (cluster, node_name)) or (require_host_ip and not isinstance(host_ip, str)):
        return None
    if any(row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") != "collected"
           for row in inventory.items("gke_exposure_node") if row["data"].get("inventoryStatus") is not None):
        return None
    nodes = [row["data"] for row in inventory.items("gke_exposure_node")
             if row["data"].get("cluster") == cluster and row["data"].get("kubernetesName") == node_name
             and row["data"].get("inventoryStatus") is None]
    if len(nodes) != 1:
        return None
    node = nodes[0]
    addresses = node.get("addresses")
    if not isinstance(addresses, list) or (require_host_ip and host_ip not in [entry.get("address") for entry in addresses
        if isinstance(entry, dict) and entry.get("type") in ("InternalIP", "ExternalIP")]):
        return None
    if required_private_ip is not None and required_private_ip not in [entry.get("address") for entry in addresses
        if isinstance(entry, dict) and entry.get("type") == "InternalIP"]:
        return None
    provider = node.get("providerID")
    match = re.fullmatch(r"gce://([a-z][a-z0-9-]{0,62})/([a-z][a-z0-9-]{0,62})/([a-z][a-z0-9-]{0,62})",
                         provider) if isinstance(provider, str) else None
    if not match or resource.get("scope") != "projects/" + match[1]:
        return None
    identity = f"projects/{match[1]}/zones/{match[2]}/instances/{match[3]}"
    instances = [row for row in inventory.items("instance") if row.get("scope") == resource.get("scope")
                 and isinstance(row["data"].get("selfLink"), str)
                 and row["data"]["selfLink"].endswith("/" + identity)]
    if len(instances) != 1 or instances[0]["data"].get("status") != "RUNNING":
        return None
    instance = instances[0]
    public_addresses = {entry.get("address") for entry in addresses if isinstance(entry, dict)
                        and entry.get("type") == "ExternalIP" and _public_ip(entry.get("address"))}
    opened = {}
    for interface in as_list(instance["data"].get("networkInterfaces")):
        if not isinstance(interface, dict) or not isinstance(interface.get("name"), str):
            continue
        if required_private_ip is not None and interface.get("networkIP") != required_private_ip:
            continue
        ips = {entry.get("natIP") for entry in as_list(interface.get("accessConfigs"))
               if isinstance(entry, dict) and _public_ip(entry.get("natIP"))}
        ips.update(entry.get("externalIpv6") for entry in as_list(interface.get("ipv6AccessConfigs"))
                   if isinstance(entry, dict) and _public_ip(entry.get("externalIpv6")))
        matched_ips = ips & public_addresses
        if allowed_ip_version is not None:
            matched_ips = {ip for ip in matched_ips if ipaddress.ip_address(ip).version == allowed_ip_version}
        if required_public_ip is not None:
            matched_ips &= {required_public_ip}
        if not matched_ips:
            continue
        effective = [row["data"] for row in inventory.items("instance_effective_firewall")
                     if row.get("scope") == resource.get("scope") and row["data"].get("instance") == identity
                     and row["data"].get("networkInterface") == interface["name"]]
        if (len(effective) != 1 or effective[0].get("effective_source_operation") != "instances.getEffectiveFirewalls"
                or not isinstance(effective[0].get("firewallPolicys"), list)
                or not isinstance(effective[0].get("firewalls"), list)):
            continue
        allowed = _gcp_firewall(inventory, instance, interface, assessment)
        if allowed is None:
            continue
        overlap = intersect(ports, allowed)
        if not empty(overlap):
            opened = union(opened, overlap)
            assessment.addresses.extend(sorted(matched_ips))
            assessment.step("gke_node_compute", "allow", node=node_name, provider_id=provider,
                            vm=identity, interface=interface["name"], public_ips=sorted(matched_ips),
                            exposed_ports=describe(overlap))
    return opened or None


def _gcp_gke_exposure_node(snapshot, inventory, resource):
    data = resource["data"]
    state = data.get("inventoryStatus")
    if state is None or state == "collected":
        return None
    a = Assessment(resource, "gke_workload")
    a.explicit = "UNKNOWN"
    a.step("kubernetes_inventory", "unknown", cluster=data.get("cluster"), status=state,
           reason=data.get("reason"))
    a.gap("inventory", "GKE Kubernetes Node inventory was not completely read")
    return a


def _gcp_gke_exposure_endpointslice(snapshot, inventory, resource):
    data = resource["data"]
    state = data.get("inventoryStatus")
    if state is None or state == "collected":
        return None
    a = Assessment(resource, "gke_workload")
    a.explicit = "UNKNOWN"
    a.step("kubernetes_inventory", "unknown", cluster=data.get("cluster"), status=state,
           reason=data.get("reason"))
    a.gap("inventory", "GKE Kubernetes EndpointSlice inventory was not completely read")
    return a


def _gcp_gke_exposure_multiclusteringress(snapshot, inventory, resource):
    data = resource["data"]
    state = data.get("inventoryStatus")
    if state == "collected":
        return None
    a = Assessment(resource, "gke_workload")
    a.explicit = "UNKNOWN"
    if state is not None:
        a.step("kubernetes_inventory", "unknown", cluster=data.get("cluster"), status=state,
               reason=data.get("reason"))
        a.gap("inventory", "GKE Kubernetes MultiClusterIngress inventory was not completely read")
        return a
    a.addresses = [data["VIP"]] if _public_ip(data.get("VIP")) else []
    a.step("kubernetes_multiclusteringress", "unknown", cluster=data.get("cluster"),
           vip=data.get("VIP"), cloud_resources=data.get("cloudResources"))
    cloud = data.get("cloudResources")
    markers = [row["data"] for row in inventory.items("gke_exposure_multiclusteringress")
               if row["data"].get("cluster") == data.get("cluster")
               and row["data"].get("inventoryStatus") is not None]
    if (len(markers) == 1 and markers[0].get("inventoryStatus") == "collected"
            and len(a.addresses) == 1 and isinstance(cloud, dict)):
        def names(key):
            values = cloud.get(key)
            return set(values) if isinstance(values, list) and 0 < len(values) <= 32 and all(
                isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value)
                for value in values) else set()
        forwarding_names, proxy_names, map_names = (names("forwardingRules"),
                                                     names("targetProxies"), names("urlMap"))
        if forwarding_names and proxy_names and map_names:
            rules = [row for row in inventory.items("forwarding_rule")
                     if row.get("scope") == resource.get("scope")
                     and row["data"].get("name") in forwarding_names
                     and row["data"].get("IPAddress") == data["VIP"]]
            opened = {}
            for rule in rules:
                detail = rule["data"]
                if (sum(candidate["data"].get("name") == detail.get("name") and
                        candidate["data"].get("IPAddress") == data["VIP"] for candidate in rules) != 1
                        or detail.get("loadBalancingScheme") not in ("EXTERNAL", "EXTERNAL_MANAGED")
                        or detail.get("IPProtocol", "TCP") != "TCP"
                        or not isinstance(detail.get("target"), str)
                        or not any(detail["target"].endswith("/" + kind + "/" + name)
                                   for kind in ("targetHttpProxies", "targetHttpsProxies") for name in proxy_names)):
                    continue
                proxies = [row for row in inventory.items("target_proxy") if row.get("scope") == resource.get("scope")
                           and detail["target"] in {row["data"].get("name"), row["data"].get("selfLink")}]
                if len(proxies) != 1:
                    continue
                map_ref = proxies[0]["data"].get("urlMap")
                maps = [row for row in inventory.items("url_map") if row.get("scope") == resource.get("scope")
                        and isinstance(map_ref, str) and map_ref in {row["data"].get("name"), row["data"].get("selfLink")}
                        and any(map_ref.endswith("/urlMaps/" + name) for name in map_names)]
                if len(maps) != 1:
                    continue
                edge = _gcp_forwarding_rule(snapshot, inventory, rule)
                if edge is None or edge.verdict() != "FAIL" or empty(edge.ports or {}):
                    continue
                opened = union(opened, edge.ports)
                a.step("gke_multicluster_cloud_edge", "allow", forwarding_rule=detail["name"],
                       target_proxy=detail["target"], url_map=map_ref, public_ip=data["VIP"],
                       ports=describe(edge.ports), cloud_path=edge.path)
            if opened:
                a.explicit = "FAIL"
                a.ports = opened
                a.notes.append("Public MultiClusterIngress cloud-edge listener is proven; application Pod health is not established")
                return a
    a.gap("controller", "MultiClusterIngress status and exact Compute forwarding rule, proxy, URL map and backend path need a join")
    return a


def _gcp_gke_exposure_gateway(snapshot, inventory, resource):
    data = resource["data"]
    state = data.get("inventoryStatus")
    if state == "collected":
        return None
    a = Assessment(resource, "gke_workload")
    a.explicit = "UNKNOWN"
    if state is not None:
        a.step("kubernetes_inventory", "unknown", cluster=data.get("cluster"), status=state,
               reason=data.get("reason"))
        a.gap("inventory", "GKE Kubernetes Gateway inventory was not completely read")
        return a
    listeners = as_list(data.get("listeners"))
    if not listeners:
        return None
    a.addresses = [entry["value"] for entry in as_list(data.get("addresses"))
                   if isinstance(entry, dict) and entry.get("type") == "IPAddress"
                   and _public_ip(entry.get("value"))]
    ports = {}
    for listener in listeners:
        if isinstance(listener, dict) and type(listener.get("port")) is int:
            protocol = "udp" if listener.get("protocol") == "UDP" else "tcp"
            ports = union(ports, pset(protocol, listener["port"], listener["port"]) or {})
    a.ports = ports
    a.step("kubernetes_gateway", "unknown", cluster=data.get("cluster"),
           gateway_class=data.get("gatewayClassName"), listeners=listeners, addresses=a.addresses)
    opened = _gcp_gke_gateway_cloud_edge(snapshot, inventory, resource, a)
    if opened:
        a.explicit = "FAIL"
        a.ports = opened
        a.notes.append("Public Gateway cloud-edge listener is proven; Kubernetes application backend health is not established by this join")
        return a
    a.gap("controller", "GKE Gateway class, route acceptance, forwarding rule and backend path need an effective join")
    return a


def _gcp_gke_gateway_cloud_edge(snapshot, inventory, resource, assessment):
    data = resource["data"]
    if data.get("gatewayClassName") not in {
            "gke-l7-global-external-managed", "gke-l7-regional-external-managed", "gke-l7-gxlb",
            "gke-l7-global-external-managed-mc", "gke-l7-regional-external-managed-mc", "gke-l7-gxlb-mc"}:
        return None
    cluster = data.get("cluster")
    markers = [row["data"] for row in inventory.items("gke_exposure_gateway")
               if row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") is not None]
    if len(markers) != 1 or markers[0].get("inventoryStatus") != "collected" or not assessment.addresses:
        return None
    class_markers = [row["data"] for row in inventory.items("gke_exposure_gatewayclass")
                     if row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") is not None]
    classes = [row["data"] for row in inventory.items("gke_exposure_gatewayclass")
               if row["data"].get("cluster") == cluster
               and row["data"].get("kubernetesName") == data.get("gatewayClassName")
               and row["data"].get("inventoryStatus") is None]
    if (len(class_markers) != 1 or class_markers[0].get("inventoryStatus") != "collected"
            or len(classes) != 1 or classes[0].get("controllerName") != "networking.gke.io/gateway"):
        return None
    annotations = data.get("annotations")
    if not isinstance(annotations, dict):
        return None
    def names(key):
        value = annotations.get("networking.gke.io/" + key)
        if not isinstance(value, str) or len(value) > 4096:
            return set()
        parts = [part.strip() for part in value.split(",")]
        return set(parts) if 0 < len(parts) <= 32 and all(
            re.fullmatch(r"[a-z][a-z0-9-]{0,62}", part) for part in parts) else set()
    forwarding_names, proxy_names, map_names = (names("forwarding-rules"), names("target-proxies"), names("url-maps"))
    if not forwarding_names or not proxy_names or not map_names:
        return None
    opened = {}
    forwarding_rows = list(inventory.items("forwarding_rule"))
    forwarding_counts = Counter((row.get("scope"), row["data"].get("name"), row["data"].get("IPAddress"))
                                for row in forwarding_rows)
    for listener in as_list(data.get("listeners")):
        if not isinstance(listener, dict) or listener.get("protocol") not in ("HTTP", "HTTPS"):
            continue
        port = listener.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            continue
        proxy_type = "targetHttpProxies" if listener["protocol"] == "HTTP" else "targetHttpsProxies"
        for rule in forwarding_rows:
            detail = rule["data"]
            if (rule.get("scope") != resource.get("scope") or detail.get("name") not in forwarding_names
                    or detail.get("IPAddress") not in assessment.addresses
                    or forwarding_counts[(rule.get("scope"), detail.get("name"), detail.get("IPAddress"))] != 1
                    or detail.get("loadBalancingScheme") not in ("EXTERNAL", "EXTERNAL_MANAGED")
                    or detail.get("IPProtocol", "TCP") != "TCP"
                    or not isinstance(detail.get("target"), str)
                    or not any(detail["target"].endswith("/" + proxy_type + "/" + name)
                               for name in proxy_names)):
                continue
            proxy = inventory.get("target_proxy", detail["target"])
            if proxy is None or proxy.get("scope") != resource.get("scope"):
                continue
            url_map_ref = proxy["data"].get("urlMap")
            url_map = inventory.get("url_map", url_map_ref) if isinstance(url_map_ref, str) else None
            if (url_map is None or url_map.get("scope") != resource.get("scope")
                    or not any(url_map_ref.endswith("/urlMaps/" + name) for name in map_names)):
                continue
            edge = _gcp_forwarding_rule(snapshot, inventory, rule)
            if edge is None or edge.verdict() != "FAIL":
                continue
            exposed = intersect(edge.ports or {}, pset("tcp", port, port) or {})
            if empty(exposed):
                continue
            opened = union(opened, exposed)
            assessment.step("gke_cloud_edge", "allow", forwarding_rule=detail["name"],
                            target_proxy=detail["target"], url_map=url_map_ref,
                            public_ip=detail["IPAddress"], ports=describe(exposed), cloud_path=edge.path)
    return opened or None


def _gcp_gke_exposure_httproute(snapshot, inventory, resource):
    data = resource["data"]
    state = data.get("inventoryStatus")
    if state == "collected":
        return None
    a = Assessment(resource, "gke_workload")
    a.explicit = "UNKNOWN"
    if state is not None:
        a.step("kubernetes_inventory", "unknown", cluster=data.get("cluster"), status=state,
               reason=data.get("reason"))
        a.gap("inventory", "GKE Kubernetes HTTPRoute inventory was not completely read")
        return a
    if not data.get("parentRefs") or not data.get("backendRefs"):
        return None
    a.step("kubernetes_httproute", "unknown", cluster=data.get("cluster"),
           hostnames=data.get("hostnames"), parents=data.get("parentRefs"),
           backends=data.get("backendRefs"))
    opened = _gcp_gke_httproute_cloud_edge(snapshot, inventory, resource, a)
    if opened:
        a.explicit = "FAIL"
        a.ports = opened
        a.notes.append("Accepted HTTPRoute on a public Gateway cloud-edge listener is proven; application backend health is not established")
        return a
    a.gap("controller", "GKE HTTPRoute acceptance, Gateway listener and cloud backend path need an effective join")
    return a


def _gcp_gke_httproute_cloud_edge(snapshot, inventory, resource, assessment):
    data = resource["data"]
    cluster, namespace, generation = data.get("cluster"), data.get("namespace"), data.get("generation")
    if not isinstance(cluster, str) or not isinstance(namespace, str) or type(generation) is not int:
        return None
    for kind in ("gke_exposure_httproute", "gke_exposure_gateway"):
        markers = [row["data"] for row in inventory.items(kind)
                   if row["data"].get("cluster") == cluster and row["data"].get("inventoryStatus") is not None]
        if len(markers) != 1 or markers[0].get("inventoryStatus") != "collected":
            return None
    def parent_key(ref):
        if not isinstance(ref, dict) or not isinstance(ref.get("name"), str):
            return None
        return (ref.get("group", "gateway.networking.k8s.io"), ref.get("kind", "Gateway"),
                ref.get("namespace", namespace), ref["name"], ref.get("sectionName"), ref.get("port"))
    specified = {key for ref in as_list(data.get("parentRefs")) if (key := parent_key(ref)) is not None}
    opened = {}
    for parent in as_list(data.get("parentStatus")):
        if not isinstance(parent, dict) or parent.get("controllerName") != "networking.gke.io/gateway":
            continue
        key = parent_key(parent.get("parentRef"))
        if (key not in specified or key[0] != "gateway.networking.k8s.io" or key[1] != "Gateway"
                or key[4] is not None and (not isinstance(key[4], str) or not key[4])):
            continue
        conditions = as_list(parent.get("conditions"))
        if any(not isinstance(condition, dict) for condition in conditions):
            continue
        accepted = [condition for condition in conditions if condition.get("type") == "Accepted"]
        reconciled = [condition for condition in conditions if condition.get("type") == "Reconciled"]
        refs = [condition for condition in conditions if condition.get("type") == "ResolvedRefs"]
        if (len(accepted) != 1 or len(reconciled) != 1 or len(refs) > 1
                or any(condition.get("status") != "True" or condition.get("observedGeneration") != generation
                       for condition in accepted + reconciled + refs)):
            continue
        gateways = [row for row in inventory.items("gke_exposure_gateway")
                    if row["data"].get("cluster") == cluster and row["data"].get("namespace") == key[2]
                    and row["data"].get("kubernetesName") == key[3]
                    and row["data"].get("inventoryStatus") is None]
        if len(gateways) != 1:
            continue
        gateway = gateways[0]
        listeners = as_list(gateway["data"].get("listeners"))
        matching_listeners = [listener for listener in listeners if isinstance(listener, dict)
                              and (key[4] is None or listener.get("name") == key[4])
                              and (key[5] is None or listener.get("port") == key[5])
                              and listener.get("protocol") in ("HTTP", "HTTPS")
                              and type(listener.get("port")) is int]
        if len(matching_listeners) != 1:
            continue
        listener = matching_listeners[0]
        listener_name = listener.get("name")
        listener_ports = pset("tcp", listener["port"], listener["port"]) or {}
        if empty(listener_ports):
            continue
        edge = _gcp_gke_exposure_gateway(snapshot, inventory, gateway)
        if edge is None or edge.verdict() != "FAIL":
            continue
        exposed = intersect(edge.ports or {}, listener_ports)
        if empty(exposed):
            continue
        opened = union(opened, exposed)
        assessment.addresses.extend(edge.addresses)
        assessment.step("gke_route_cloud_edge", "allow", gateway=gateway["data"].get("name"),
                        listener=listener_name, ports=describe(exposed), cloud_path=edge.path)
    return opened or None


def _gcp_bucket(snapshot, inventory, resource):
    data = resource["data"]
    def grant_unconditional(binding):
        condition = binding.get("condition")
        return condition is None or (isinstance(condition, dict)
                                     and isinstance(condition.get("expression"), str)
                                     and condition["expression"].strip() == "true")
    policy = data.get("iamPolicy")
    public = []
    conditional = []
    unresolved_roles = []
    known_storage_roles = {"roles/storage.objectViewer", "roles/storage.objectUser",
                           "roles/storage.objectCreator", "roles/storage.objectAdmin", "roles/storage.admin",
                           "roles/storage.legacyObjectReader", "roles/storage.legacyObjectOwner",
                           "roles/storage.legacyBucketReader", "roles/storage.legacyBucketWriter", "roles/storage.legacyBucketOwner",
                           "roles/viewer", "roles/editor", "roles/owner"}
    object_permissions = {"storage.objects.get", "storage.objects.list", "storage.objects.create",
                          "storage.objects.update", "storage.objects.delete", "storage.objects.getIamPolicy",
                          "storage.objects.setIamPolicy", "storage.buckets.setIamPolicy"}
    coverage = (data.get("_coverage") or {}).get("iamPolicy", {})
    policy_ok = (isinstance(policy, dict) and policy.get("collection_status") in (None, "collected")
                 and isinstance(coverage, dict) and coverage.get("status") in (None, "collected"))
    if policy_ok:
        for binding in as_list(policy.get("bindings")):
            if not isinstance(binding, dict):
                continue
            grants = [(binding.get("role"), m) for m in as_list(binding.get("members"))
                      if m in ("allUsers", "allAuthenticatedUsers")]
            if not grants:
                continue
            role = binding.get("role")
            role_row = inventory.get("iam_role", role) if isinstance(role, str) else None
            permissions = role_row["data"].get("includedPermissions") if role_row else None
            if isinstance(permissions, list):
                if any(permission in object_permissions for permission in permissions):
                    (public if grant_unconditional(binding) else conditional).extend(grants)
            elif role in known_storage_roles:
                (public if grant_unconditional(binding) else conditional).extend(grants)
            else:
                unresolved_roles.extend(grants)
    # The collector attaches these only after complete native ACL reads and
    # verifies that uniform bucket-level access is disabled.
    acl = []
    acl_unresolved = []
    if (data.get("iamConfiguration") or {}).get("uniformBucketLevelAccess", {}).get("enabled") is False:
        for field in ("bucketAccessControls", "objectAccessControls"):
            envelope = data.get(field)
            if not isinstance(envelope, dict) or envelope.get("status") != "collected" or envelope.get("all_pages") is not True:
                acl_unresolved.append(field + " inventory incomplete")
                continue
            if field == "objectAccessControls" and (envelope.get("all_objects") is not True or envelope.get("all_versions") is not True):
                acl_unresolved.append("objectAccessControls object or version inventory incomplete")
                continue
            if (field == "objectAccessControls" and envelope.get("source_inventory") == "object_acl"
                    and inventory.state("object_acl", resource.get("scope")) == "collected"):
                expected = [(row.get("entity"), row.get("role")) for row in as_list(envelope.get("items"))
                            if isinstance(row, dict) and row.get("entity") in ("allUsers", "allAuthenticatedUsers")
                            and row.get("role") in ("READER", "OWNER")]
                native = [row["data"] for row in inventory.items("object_acl")
                          if row.get("scope") == resource.get("scope") and row["data"].get("bucket") == data.get("name")
                          and row["data"].get("entity") in ("allUsers", "allAuthenticatedUsers")
                          and row["data"].get("role") in ("READER", "OWNER")]
                source_requests = envelope.get("source_requests")
                if (isinstance(source_requests, list) and source_requests
                        and Counter(expected) == Counter((row["entity"], row["role"]) for row in native)
                        and all(isinstance(row.get("objectRef"), str)
                                and re.fullmatch(r"[0-9a-f]{64}", row["objectRef"])
                                and isinstance(row.get("generation"), str)
                                and re.fullmatch(r"[0-9]{1,20}", row["generation"])
                                and isinstance(row.get("_provenance"), dict)
                                and isinstance(row["_provenance"].get("source_requests"), list)
                                and row["_provenance"]["source_requests"]
                                and set(row["_provenance"]["source_requests"]) <= set(source_requests)
                                for row in native)):
                    acl.extend({"source": field, "entity": row["entity"], "role": row["role"],
                                "object_ref": row["objectRef"], "generation": row["generation"]}
                               for row in native)
                    continue
            for row in as_list(envelope.get("items")):
                roles = ("READER", "OWNER", "WRITER") if field == "bucketAccessControls" else ("READER", "OWNER")
                if isinstance(row, dict) and row.get("entity") in ("allUsers", "allAuthenticatedUsers") and row.get("role") in roles:
                    acl.append({"source": field, "entity": row["entity"], "role": row["role"],
                                **({"object_ref": row["objectRef"]} if field == "objectAccessControls" and row.get("objectRef") else {})})
    effective_rows = [row for row in inventory.items("bucket_effective_iam")
                      if row.get("scope") == resource.get("scope") and row["data"].get("name") == data.get("name")]
    effective_proven = (inventory.state("bucket_effective_iam", resource.get("scope")) == "collected"
                        and len(effective_rows) == 1 and effective_rows[0]["data"].get("resolutionComplete") is True
                        and type(effective_rows[0]["data"].get("publicAccess")) is bool)
    effective_public = effective_proven and effective_rows[0]["data"]["publicAccess"] is True
    effective_unresolved = not effective_proven
    folder_public = []
    folder_unresolved = []
    if (data.get("iamConfiguration") or {}).get("uniformBucketLevelAccess", {}).get("enabled") is True:
        if inventory.state("managed_folder", resource.get("scope")) not in ("collected", "empty"):
            folder_unresolved.append({"reason": "managed folder inventory incomplete"})
        for folder in inventory.items("managed_folder"):
            detail = folder["data"]
            if folder.get("scope") != resource.get("scope") or detail.get("bucket") != data.get("name"):
                continue
            name = detail.get("name")
            folder_policy = detail.get("iamPolicy")
            if not isinstance(name, str) or not isinstance(folder_policy, dict) or folder_policy.get("collection_status") not in (None, "collected"):
                folder_unresolved.append({"folder": name, "reason": "managed folder IAM unavailable"})
                continue
            for binding in as_list(folder_policy.get("bindings")):
                if not isinstance(binding, dict):
                    continue
                members = [m for m in as_list(binding.get("members")) if m in ("allUsers", "allAuthenticatedUsers")]
                if not members:
                    continue
                role = binding.get("role")
                role_row = inventory.get("iam_role", role) if isinstance(role, str) else None
                permissions = role_row["data"].get("includedPermissions") if role_row else None
                grant = {"folder": name, "role": role, "members": members}
                if not grant_unconditional(binding):
                    folder_unresolved.append({**grant, "reason": "conditional managed folder IAM"})
                elif isinstance(permissions, list) and any(p in object_permissions for p in permissions):
                    folder_public.append(grant)
                elif permissions is None and role in (known_storage_roles -
                        {"roles/storage.legacyBucketReader", "roles/storage.legacyBucketWriter"}):
                    folder_public.append(grant)
                elif permissions is None:
                    folder_unresolved.append({**grant, "reason": "managed folder role permissions unavailable"})
    if not public and not acl and not conditional and not effective_public and not effective_unresolved and not unresolved_roles and not folder_public and not folder_unresolved and not acl_unresolved:
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
    ip_filter = data.get("ipFilter")
    if isinstance(ip_filter, dict) and ip_filter.get("mode") == "Enabled":
        source = ip_filter.get("publicNetworkSource")
        ranges = source.get("allowedIpCidrRanges", []) if isinstance(source, dict) else [] if source is None else None
        if not isinstance(ranges, list) or any(not isinstance(value, str) or _cidr(value) is None for value in ranges):
            a.gap("policy", "enabled bucket IP filter has malformed or unavailable public CIDR ranges")
            a.explicit = "UNKNOWN"
        elif not any(_public_source(value) for value in ranges):
            a.step("bucket_ip_filter", "block", public_cidrs=ranges,
                   semantics="direct public-network requests; VPC and service-agent paths assessed separately")
            a.ports = {}
            return a
        else:
            a.step("bucket_ip_filter", "allow", public_cidrs=ranges)
    elif ip_filter is not None and (not isinstance(ip_filter, dict) or ip_filter.get("mode") != "Disabled"):
        a.gap("policy", "bucket IP filter mode is not recognized")
        a.explicit = "UNKNOWN"
    a.step("policy", "allow" if public or acl or effective_public or folder_public else "unknown", bindings=public, acl=acl,
           acl_unresolved=acl_unresolved, conditional=conditional, unresolved_roles=unresolved_roles,
           effective_public=effective_public, effective_iam_unresolved=effective_unresolved,
           managed_folder_grants=folder_public,
           managed_folder_unresolved=folder_unresolved, public_access_prevention=prevention)
    if (not public and not acl and not effective_public and not folder_public) or prevention == "inherited":
        a.explicit = "UNKNOWN"
        a.gap("policy", "conditional or unresolved public IAM/ACL evidence, inherited IAM or public access prevention requires effective-policy evaluation")
    a.data_exposure = True
    a.addresses = [f"https://storage.googleapis.com/{data.get('name', native_id(resource))}"]
    return a


def _gcp_bigquery_dataset(snapshot, inventory, resource):
    """Legacy dataset ACLs can expose data without a separate IAM binding."""
    data = resource["data"]
    def grant_unconditional(row):
        condition = row.get("condition")
        return condition is None or (isinstance(condition, dict)
                                     and isinstance(condition.get("expression"), str)
                                     and condition["expression"].strip() == "true")
    access = data.get("access")
    if not isinstance(access, list):
        return None
    public = []
    conditional_public = []
    delegated = []
    conditional_delegated = []
    project_groups = []
    for entry in access:
        if not isinstance(entry, dict):
            continue
        member = entry.get("iamMember") or entry.get("specialGroup")
        if member in ("allUsers", "allAuthenticatedUsers"):
            (conditional_public if not grant_unconditional(entry) or entry.get("role") not in ("READER", "WRITER", "OWNER") else public).append(
                {"member": member, "role": entry.get("role")})
        if entry.get("specialGroup") in ("projectReaders", "projectWriters", "projectOwners"):
            project_groups.append({"group": entry["specialGroup"], "role": entry.get("role"),
                                   "conditional": not grant_unconditional(entry)})
        for kind in ("view", "routine", "dataset"):
            ref = entry.get(kind)
            if isinstance(ref, dict):
                (conditional_delegated if entry.get("condition") is not None else delegated).append(
                    {"kind": kind, "reference": ref,
                     **({"role": entry.get("role")} if kind == "routine" and "role" in entry else {})})
    if not public and not delegated and not conditional_public and not conditional_delegated and not project_groups:
        return None
    a = Assessment(resource, "data_share")
    def destination_project(row):
        ref = row["reference"]
        if row["kind"] == "dataset" and isinstance(ref.get("dataset"), dict):
            ref = ref["dataset"]
        return ref.get("projectId") or ref.get("project_id")
    from .trust import trusted_scopes
    trusted_project_ids = trusted_scopes(snapshot)["ids"]
    def destination_scope(row):
        project = destination_project(row)
        if not isinstance(project, str) or not project:
            return None
        matches = {scope for scope in snapshot.get("scopes", []) if scope == f"projects/{project}"}
        for candidate in inventory.items("project"):
            detail = candidate["data"]
            if project in {str(detail.get("projectId")), str(detail.get("projectNumber")),
                           str(detail.get("name", "")).removeprefix("projects/")}:
                matches.add(candidate["scope"])
        return next(iter(matches)) if len(matches) == 1 else None
    external_projects = sorted({project for row in delegated
                                if isinstance(project := destination_project(row), str)
                                and project and project not in trusted_project_ids
                                and (row["kind"] != "routine" or row.get("role") in
                                     (None, "roles/bigquery.routineDataViewer",
                                      "roles/bigquery.routineDataEditor", "roles/bigquery.routineAdmin"))})
    reader_cache = {}
    def project_for_scope(scope):
        alias = scope.removeprefix("projects/") if isinstance(scope, str) and scope.startswith("projects/") else None
        rows = [row for row in inventory.items("project") if row.get("scope") == scope and alias in {
            str(row["data"].get("projectId")), str(row["data"].get("projectNumber")),
            str(row["data"].get("name", "")).removeprefix("projects/")}]
        return rows[0] if len(rows) == 1 else None
    def inherited_public(permission, target_scope):
        key = (permission, target_scope)
        if key in reader_cache:
            return reader_cache[key]
        project_policy_row = inventory.get("iam_policy", target_scope)
        project_policy = project_policy_row["data"] if project_policy_row else None
        project_row = project_for_scope(target_scope)
        project_data = project_row["data"] if project_row else {}
        inherited_policies = project_data.get("_inherited_iam_policies")
        inherited_coverage = (project_data.get("_coverage") or {}).get("_inherited_iam_policies") or {}
        if not (isinstance(inherited_policies, list) and inherited_coverage.get("status") == "collected"):
            inherited_policies = []
        grants = []
        policies = [(target_scope, project_policy), *[
            (policy.get("ancestor"), policy) for policy in inherited_policies
            if isinstance(policy, dict) and policy.get("name") == policy.get("ancestor")]]
        builtins = {"bigquery.tables.getData": {
            "roles/bigquery.dataViewer", "roles/bigquery.dataEditor",
            "roles/bigquery.dataOwner", "roles/bigquery.admin"},
            "bigquery.routines.get": {
                "roles/bigquery.metadataViewer", "roles/bigquery.dataViewer",
                "roles/bigquery.dataEditor", "roles/bigquery.dataOwner", "roles/bigquery.admin"}}
        for scope, policy in policies:
            if (not isinstance(policy, dict) or policy.get("name") != scope
                    or policy.get("collection_status", "collected") != "collected"):
                continue
            for binding in as_list(policy.get("bindings")):
                if not isinstance(binding, dict) or not grant_unconditional(binding):
                    continue
                members = [member for member in as_list(binding.get("members"))
                           if member in ("allUsers", "allAuthenticatedUsers")]
                role = binding.get("role")
                role_row = inventory.get("iam_role", role) if isinstance(role, str) else None
                permissions = role_row["data"].get("includedPermissions") if role_row else None
                has_permission = (permission in permissions if isinstance(permissions, list)
                                  else role in builtins.get(permission, ()) if role_row is None else False)
                if members and has_permission:
                    grants.append({"role": role, "members": members, "scope": scope,
                                   "permission": permission})
        reader_cache[key] = grants
        return grants
    def project_basic_grants(groups, project_scope):
        grants = []
        unresolved = []
        if not groups:
            return grants, unresolved
        from .common import externality, principal_scope
        project_policy_row = inventory.get("iam_policy", project_scope)
        project_policy = project_policy_row["data"] if project_policy_row else None
        project_row = project_for_scope(project_scope)
        project_data = project_row["data"] if project_row else {}
        ancestor_coverage = (project_data.get("_coverage") or {}).get("_inherited_iam_policies") or {}
        policies = [(project_scope, project_policy)]
        if inventory.state("iam_policy", project_scope) != "collected":
            unresolved.append("project IAM inventory incomplete")
        if ancestor_coverage.get("status") == "collected" and isinstance(project_data.get("_inherited_iam_policies"), list):
            policies.extend((policy.get("ancestor"), policy) for policy in project_data["_inherited_iam_policies"]
                            if isinstance(policy, dict) and policy.get("name") == policy.get("ancestor"))
        else:
            unresolved.append("project ancestor IAM incomplete")
        roles = {"projectReaders": "roles/viewer", "projectWriters": "roles/editor", "projectOwners": "roles/owner"}
        for scope, policy in policies:
            if (not isinstance(policy, dict) or policy.get("name") != scope
                    or policy.get("collection_status", "collected") != "collected"
                    or not isinstance(policy.get("bindings"), list)):
                unresolved.append(f"project role IAM unavailable: {scope}")
                continue
            for group in groups:
                if group["role"] not in ("READER", "WRITER", "OWNER") or group["conditional"]:
                    unresolved.append(f"conditional or unrecognized dataset role: {group['group']}")
                    continue
                for binding in as_list(policy.get("bindings")):
                    if not isinstance(binding, dict) or binding.get("role") != roles[group["group"]]:
                        continue
                    for member in as_list(binding.get("members")):
                        if not isinstance(member, str):
                            unresolved.append(f"project role principal malformed: {scope}")
                            continue
                        classification = externality(snapshot, member)
                        if not grant_unconditional(binding) or classification == "unknown":
                            unresolved.append(f"conditional or unattributed project role: {scope}")
                        elif classification in ("public", "everyone_authenticated", "external"):
                            grants.append({"group": group["group"], "dataset_role": group["role"],
                                "iam_role": binding["role"], "scope": scope, "principal": member,
                                "classification": classification,
                                **({"external_scope_id": principal_scope("gcp", member)} if classification == "external" else {})})
        return grants, unresolved
    project_group_grants, project_group_unresolved = project_basic_grants(project_groups, resource.get("scope"))
    destination_group_cache = {}
    def destination_project_grants(target, dataset_name):
        if target is None or not isinstance(target["data"].get("access"), list):
            return []
        if dataset_name not in destination_group_cache:
            groups = [{"group": entry["specialGroup"], "role": entry.get("role"),
                       "conditional": not grant_unconditional(entry)}
                      for entry in target["data"]["access"] if isinstance(entry, dict) and
                      entry.get("specialGroup") in ("projectReaders", "projectWriters", "projectOwners")]
            destination_group_cache[dataset_name] = project_basic_grants(groups, target.get("scope"))[0]
        return destination_group_cache[dataset_name]
    def direct_public(policy, permission, known_roles):
        if not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected"):
            return False
        for binding in as_list(policy.get("bindings")):
            if not isinstance(binding, dict) or not grant_unconditional(binding) or not any(
                    member in ("allUsers", "allAuthenticatedUsers") for member in as_list(binding.get("members"))):
                continue
            role = binding.get("role")
            role_row = inventory.get("iam_role", role) if isinstance(role, str) else None
            permissions = role_row["data"].get("includedPermissions") if role_row else None
            if isinstance(permissions, list):
                if permission in permissions:
                    return True
            elif role in known_roles:
                return True
        return False
    public_views = []
    view_refs = []
    for row in delegated:
        ref = row["reference"]
        target_scope = destination_scope(row)
        if row["kind"] == "view" and target_scope and all(
                isinstance(ref.get(key), str) and ref[key] for key in ("datasetId", "tableId")):
            view_refs.append((f"{target_scope}/datasets/{ref['datasetId']}/tables/{ref['tableId']}", "view"))
        elif row["kind"] == "dataset" and target_scope:
            target_types = ref.get("targetTypes", ref.get("target_types"))
            dataset_ref = ref.get("dataset")
            dataset_id = (dataset_ref.get("datasetId") or dataset_ref.get("dataset_id")) if isinstance(dataset_ref, dict) else None
            views_authorized = target_types == "VIEWS" or isinstance(target_types, list) and "VIEWS" in target_types
            if not views_authorized or not isinstance(dataset_id, str) or not dataset_id:
                continue
            if "gcp_bigquery_views_by_dataset" not in inventory.network_cache:
                grouped = {}
                for table in inventory.items("bigquery_table"):
                    name = table["data"].get("name")
                    if isinstance(name, str) and "/tables/" in name:
                        grouped.setdefault(name.rsplit("/tables/", 1)[0], []).append(table)
                inventory.network_cache["gcp_bigquery_views_by_dataset"] = grouped
            dataset_name = f"{target_scope}/datasets/{dataset_id}"
            view_refs.extend((table["data"]["name"], "authorized_dataset")
                             for table in inventory.network_cache["gcp_bigquery_views_by_dataset"].get(dataset_name, ())
                             if table["data"].get("type") in ("VIEW", "MATERIALIZED_VIEW"))
    for view_name, authorization in dict.fromkeys(view_refs):
        view = inventory.get("bigquery_table", view_name)
        if view is None or view["data"].get("type") not in ("VIEW", "MATERIALIZED_VIEW"):
            continue
        dataset_name = view_name.rsplit("/tables/", 1)[0]
        target = inventory.get("bigquery_dataset", dataset_name)
        dataset_public = (target is not None and isinstance(target["data"].get("access"), list) and
            any(isinstance(entry, dict) and grant_unconditional(entry) and (entry.get("iamMember") or entry.get("specialGroup")) in
                ("allUsers", "allAuthenticatedUsers") and entry.get("role") in ("READER", "OWNER", "WRITER")
                for entry in target["data"]["access"]))
        dataset_project_grants = destination_project_grants(target, dataset_name)
        policy = view["data"].get("iamPolicy")
        table_public = direct_public(policy, "bigquery.tables.getData",
                                     {"roles/bigquery.dataViewer", "roles/bigquery.dataEditor",
                                      "roles/bigquery.dataOwner", "roles/bigquery.admin"})
        readers = inherited_public("bigquery.tables.getData", view_name.split("/datasets/", 1)[0])
        if dataset_public or dataset_project_grants or table_public or readers:
            public_views.append({"view": view_name, "authorization": authorization,
                                 "dataset_public": bool(dataset_public),
                                 "dataset_project_grants": dataset_project_grants,
                                 "table_public": bool(table_public),
                                 "inherited_public": readers})
    public_routines = []
    routine_role_unresolved = []
    for row in delegated:
        if row["kind"] != "routine" or not (target_scope := destination_scope(row)):
            continue
        ref = row["reference"]
        if not all(isinstance(ref.get(key), str) and ref[key] for key in ("datasetId", "routineId")):
            continue
        routine_name = f"{target_scope}/datasets/{ref['datasetId']}/routines/{ref['routineId']}"
        routine = inventory.get("bigquery_routine_metadata", routine_name)
        if routine is None:
            continue
        routine_type, authorization_role = routine["data"].get("routineType"), row.get("role")
        if routine_type == "PROCEDURE":
            if authorization_role not in (None, "roles/bigquery.routineDataViewer",
                                          "roles/bigquery.routineDataEditor", "roles/bigquery.routineAdmin"):
                routine_role_unresolved.append({"routine": routine_name, "role": authorization_role})
                continue
        elif routine_type not in ("SCALAR_FUNCTION", "TABLE_VALUED_FUNCTION") or authorization_role is not None:
            routine_role_unresolved.append({"routine": routine_name, "role": authorization_role})
            continue
        target = inventory.get("bigquery_dataset", f"{target_scope}/datasets/{ref['datasetId']}")
        dataset_public = (target is not None and isinstance(target["data"].get("access"), list) and
            any(isinstance(entry, dict) and grant_unconditional(entry) and (entry.get("iamMember") or entry.get("specialGroup")) in
                ("allUsers", "allAuthenticatedUsers") and entry.get("role") in ("READER", "OWNER", "WRITER")
                for entry in target["data"]["access"]))
        dataset_project_grants = destination_project_grants(target, f"{target_scope}/datasets/{ref['datasetId']}")
        policy = routine["data"].get("iamPolicy")
        routine_public = direct_public(policy, "bigquery.routines.get",
                                       {"roles/bigquery.metadataViewer", "roles/bigquery.dataViewer",
                                        "roles/bigquery.dataEditor", "roles/bigquery.dataOwner", "roles/bigquery.admin",
                                        "roles/bigquery.routineDataViewer", "roles/bigquery.routineDataEditor"})
        readers = inherited_public("bigquery.routines.get", target_scope)
        if dataset_public or dataset_project_grants or routine_public or readers:
            public_routines.append({"routine": routine_name, "routine_type": routine["data"].get("routineType"),
                                    "authorization_role": authorization_role,
                                    "mutation_possible": routine_type == "PROCEDURE" and authorization_role in
                                        (None, "roles/bigquery.routineDataEditor", "roles/bigquery.routineAdmin"),
                                    "dataset_public": bool(dataset_public), "dataset_project_grants": dataset_project_grants,
                                    "routine_public": bool(routine_public),
                                    "inherited_public": readers})
    a.external_ids = sorted(set(external_projects) | {grant["external_scope_id"] for grant in project_group_grants
                                                       if grant.get("external_scope_id")} |
                            {grant["external_scope_id"] for row in public_views + public_routines
                             for grant in row.get("dataset_project_grants", []) if grant.get("external_scope_id")})
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
    elif project_group_grants:
        a.data_exposure = True
        a.authenticated = not any(grant["classification"] == "public" for grant in project_group_grants)
        a.step("dataset_project_group", "allow", grants=project_group_grants)
    elif public_views or public_routines:
        a.data_exposure = True
        layer = "authorized_view" if public_views and not public_routines else "authorized_routine" if public_routines and not public_views else "authorized_resource"
        a.step(layer, "allow", public_views=public_views, public_routines=public_routines,
               semantics="Public invocation of an authorized view or routine; returned data and writes depend on SQL")
    elif delegated or conditional_public or conditional_delegated or project_group_unresolved:
        # An authorized view/routine/dataset receives source-data privileges,
        # but the destination's readers and project ownership need a join.
        a.explicit = "UNKNOWN"
        a.step("dataset_acl", "unknown", delegated=delegated, conditional_public=conditional_public,
               conditional_delegated=conditional_delegated, project_groups=project_groups,
               project_group_unresolved=project_group_unresolved,
               routine_role_unresolved=routine_role_unresolved)
        a.gap("policy", "conditional dataset ACL, project role, or authorized BigQuery resource requires effective access review")
    else:
        return None
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
    authenticated = data.get("authenticated_read") is True or data.get("authenticated_write") is True
    conditional = data.get("conditional_read") is True or data.get("conditional_write") is True
    a.step("firebase_rules", "allow" if public or authenticated else "unknown" if conditional else "block",
           services=data.get("services"), ruleset=data.get("rulesetName"),
           public_read=data.get("public_read"), public_write=data.get("public_write"),
             authenticated_read=data.get("authenticated_read"), authenticated_write=data.get("authenticated_write"),
             conditional_read=data.get("conditional_read"),
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


def _gcp_network_peering(snapshot, inventory, resource):
    data = resource["data"]
    peerings = data.get("peerings")
    if not isinstance(peerings, list):
        return None
    scope = resource.get("scope", "")
    if not scope.startswith("projects/"):
        return None
    project = scope.removeprefix("projects/")
    if not project or project.isdigit():
        return None
    candidates = []
    for peering in peerings:
        if not isinstance(peering, dict) or peering.get("state") != "ACTIVE":
            continue
        peer_ref = peering.get("network")
        if not isinstance(peer_ref, str):
            continue
        if "://" in peer_ref:
            try:
                parsed = urlsplit(peer_ref)
                if (parsed.scheme != "https" or parsed.hostname not in
                        ("compute.googleapis.com", "www.googleapis.com") or parsed.port is not None or
                        parsed.username or parsed.password or parsed.query or parsed.fragment):
                    continue
            except ValueError:
                continue
            peer_path = parsed.path.removeprefix("/compute/v1/")
        else:
            peer_path = peer_ref.removeprefix("/")
        match = re.fullmatch(r"projects/([^/]+)/global/networks/[^/]+", peer_path)
        if match and match.group(1) != project and not match.group(1).isdigit():
            candidates.append({"name": peering.get("name"), "peer_network": peer_ref,
                               "peer_project": match.group(1), "state": "ACTIVE",
                               "import_custom_routes": peering.get("importCustomRoutes"),
                               "export_custom_routes": peering.get("exportCustomRoutes")})
    if not candidates:
        return None
    a = Assessment(resource, "cross_project_peering")
    for candidate in candidates:
        a.step("vpc_peering", "allow", **candidate)
    a.gap("route", "effective exchanged routes, destination firewall and peer ownership are unresolved",
          "compute networks.listPeeringRoutes and network effective routes")
    return a


def _gcp_vpn_tunnel(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("status") != "ESTABLISHED":
        return None
    peer_ref = data.get("peerExternalGateway")
    external_peer = isinstance(peer_ref, str) and "/externalVpnGateways/" in peer_ref
    gcp_peer_ref = data.get("peerGcpGateway")
    peer_project = None
    if isinstance(gcp_peer_ref, str):
        try:
            parsed_peer = urlsplit(gcp_peer_ref)
            peer_match = re.fullmatch(r"/compute/v1/projects/([^/]+)/regions/[^/]+/vpnGateways/[^/]+",
                                      parsed_peer.path)
            if (parsed_peer.scheme == "https" and parsed_peer.hostname in
                    ("compute.googleapis.com", "www.googleapis.com") and not parsed_peer.query and
                    not parsed_peer.fragment and not parsed_peer.username and not parsed_peer.password and
                    parsed_peer.port is None and peer_match):
                peer_project = peer_match.group(1)
        except ValueError:
            pass
    cross_project_peer = (peer_project is not None and
                          resource.get("scope") != f"projects/{peer_project}")
    if external_peer and gcp_peer_ref:
        return None
    ha = external_peer or cross_project_peer
    classic = not ha and isinstance(data.get("peerIp"), str) and _public_ip(data["peerIp"])
    if not ha and not classic:
        return None
    gateway_ref = data.get("vpnGateway" if ha else "targetVpnGateway")
    if not isinstance(gateway_ref, str) or ("/vpnGateways/" if ha else "/targetVpnGateways/") not in gateway_ref:
        return None
    a = Assessment(resource, "vpn_peer")
    a.authenticated = True
    gateway = inventory.get("vpn_gateway", gateway_ref)
    if gateway is None or gateway.get("scope") != resource.get("scope"):
        a.gap("inventory", "VPN tunnel local gateway is not in the collected inventory",
              "compute vpnGateways/targetVpnGateways.aggregatedList")
        return a
    if ha:
        interface_id = data.get("vpnGatewayInterface")
        if type(interface_id) is not int or interface_id not in (0, 1):
            a.gap("inventory", "HA VPN tunnel local interface ID is unavailable")
            return a
        interfaces = [row for row in as_list(gateway["data"].get("vpnInterfaces"))
                      if isinstance(row, dict) and row.get("id") == interface_id]
        if len(interfaces) != 1 or interfaces[0].get("interconnectAttachment"):
            a.gap("inventory", "HA VPN tunnel local public interface is unavailable or ambiguous")
            return a
        public_ip = interfaces[0].get("ipAddress")
        if not isinstance(public_ip, str) or not _public_ip(public_ip):
            a.gap("public_ip", "HA VPN tunnel local interface has no recorded public IP")
            return a
    else:
        def udp_ports(rule):
            specs = rule.get("ports") if isinstance(rule.get("ports"), list) else [rule.get("portRange")]
            found = set()
            for spec in specs:
                if not isinstance(spec, str) or not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", spec):
                    continue
                low, high = (int(part) for part in spec.split("-")) if "-" in spec else (int(spec), int(spec))
                if 1 <= low <= high <= 65535:
                    found.update(port for port in (500, 4500) if low <= port <= high)
            return found
        by_ip = {}
        for row in inventory.items("forwarding_rule"):
            rule = row["data"]
            address = rule.get("IPAddress")
            if (row.get("scope") != resource.get("scope") or rule.get("target") != gateway_ref or
                    rule.get("loadBalancingScheme", "EXTERNAL") != "EXTERNAL" or
                    not isinstance(address, str) or not _public_ip(address)):
                continue
            protocols = by_ip.setdefault(address, set())
            if rule.get("IPProtocol") == "ESP":
                protocols.add("esp")
            elif rule.get("IPProtocol") == "UDP":
                protocols.update(udp_ports(rule))
        public_ip = next((address for address, protocols in sorted(by_ip.items())
                          if {"esp", 500, 4500} <= protocols), None)
        if public_ip is None:
            a.gap("inventory", "Classic VPN tunnel lacks one collected public IP with ESP, UDP 500 and UDP 4500 forwarding rules",
                  "compute forwardingRules.aggregatedList")
            return a
    a.addresses = [public_ip]
    a.ports = union(pset("udp", 500, 500), pset("udp", 4500, 4500))
    a.ports["esp"] = ((0, 0),)
    a.step("vpn_peer", "allow", tunnel_status="ESTABLISHED", local_gateway=gateway_ref,
           tunnel_type="HA" if ha else "Classic", public_ip=public_ip,
           peer=(peer_ref if external_peer else gcp_peer_ref if cross_project_peer else data["peerIp"]),
           **({"peer_project": peer_project} if cross_project_peer else {}),
           **({"interface_id": interface_id} if ha else {}))
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
    status = data.get("servingStatus")
    if status in {"USER_DISABLED", "SYSTEM_DISABLED"}:
        a.step("serving_status", "block", status=data["servingStatus"])
        a.ports = {}
        return a
    if status != "SERVING":
        a.gap("serving_status", "App Engine application serving status is unavailable or unspecified")
        return a
    a.step("default_hostname", "allow", hostname=hostname, iap_enabled=a.authenticated)
    if inventory.state("app_engine_firewall_rule", resource["scope"]) != "collected":
        a.gap("app_engine_firewall", "App Engine ingress firewall rules are not completely collected",
              "apps.firewall.ingressRules.list")
        return a
    rules = [row["data"] for row in inventory.items("app_engine_firewall_rule")
             if row.get("scope") == resource["scope"]]
    if not rules or any(type(rule.get("priority")) is not int or not 1 <= rule["priority"] <= 2147483647
                        for rule in rules) or len({rule["priority"] for rule in rules}) != len(rules):
        a.gap("app_engine_firewall", "App Engine ingress firewall priorities or default rule are unavailable")
        return a
    private_ranges = tuple(ipaddress.ip_network(value) for value in
                           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
    for rule in sorted(rules, key=lambda row: row["priority"]):
        source = rule.get("sourceRange")
        network = _cidr(source) if isinstance(source, str) and source != "*" else None
        if source != "*" and network is None:
            break
        if network is not None and any(network.subnet_of(private) for private in private_ranges
                                       if network.version == private.version):
            continue
        action = rule.get("action")
        if action == "ALLOW" and (source == "*" or _public_source(source)):
            a.step("app_engine_firewall", "allow", priority=rule["priority"], source_range=source, action=action)
            a.ports = pset("tcp", 443, 443)
            return a
        if action == "DENY" and source == "*":
            a.step("app_engine_firewall", "block", priority=rule["priority"], source_range=source, action=action)
            a.ports = {}
            return a
        break
    a.gap("app_engine_firewall", "App Engine ingress firewall has no provable public allow or universal deny")
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


def _gcp_dataproc_cluster(snapshot, inventory, resource):
    data = resource["data"]
    config = data.get("config")
    endpoint = config.get("endpointConfig") if isinstance(config, dict) else None
    if not isinstance(endpoint, dict) or endpoint.get("enableHttpPortAccess") is not True:
        return None
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True
    ports = endpoint.get("httpPorts")
    if not isinstance(ports, dict) or not ports:
        a.gap("public_endpoint", "Component Gateway is enabled but has no recorded HTTP port URLs")
        return a
    origins = []
    for label, url in ports.items():
        if not isinstance(label, str) or not isinstance(url, str):
            a.gap("public_endpoint", "Component Gateway HTTP port mapping is malformed")
            return a
        try:
            parsed = urlsplit(url)
            valid = (parsed.scheme == "https" and bool(parsed.hostname) and
                     not parsed.username and not parsed.password and parsed.port in (None, 443))
        except ValueError:
            valid = False
        if not valid:
            a.gap("public_endpoint", "Component Gateway HTTP port URL is not a valid HTTPS gateway URL")
            return a
        origins.append(f"https://{parsed.hostname}")
    a.addresses = sorted(set(origins))
    state = (data.get("status") or {}).get("state") if isinstance(data.get("status"), dict) else None
    if state != "RUNNING":
        a.gap("cluster_state", "Component Gateway cluster is not confirmed RUNNING")
        return a
    a.step("component_gateway", "allow", enabled=True, origins=a.addresses,
           interfaces=sorted(ports))
    a.ports = pset("tcp", 443, 443)
    a.notes.append("Component Gateway user IAM and UI response are separate from the declared HTTPS endpoint")
    return a


def _gcp_workbench_instance(snapshot, inventory, resource):
    data = resource["data"]
    if data.get("disableProxyAccess") is True:
        return None
    if not isinstance(data.get("proxyUri"), str) and data.get("state") != "ACTIVE":
        return None
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True
    uri = data.get("proxyUri")
    try:
        parsed = urlsplit(uri) if isinstance(uri, str) else None
        valid = (parsed is not None and parsed.scheme == "https" and bool(parsed.hostname) and
                 not parsed.username and not parsed.password and parsed.port in (None, 443))
    except ValueError:
        valid = False
    if not valid:
        a.gap("public_endpoint", "Workbench proxy is enabled but has no valid recorded HTTPS proxy URI")
        return a
    a.addresses = [f"https://{parsed.hostname}"]
    if data.get("state") != "ACTIVE":
        a.gap("instance_state", "Workbench instance is not confirmed ACTIVE")
        return a
    a.step("notebook_proxy", "allow", proxy_access_disabled=False, origin=a.addresses[0], state="ACTIVE")
    a.ports = pset("tcp", 443, 443)
    a.notes.append("Workbench owner or service-account-user authorization and Jupyter response remain unresolved")
    return a


def _gcp_composer_environment(snapshot, inventory, resource):
    data = resource["data"]
    config = data.get("config")
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True
    if not isinstance(config, dict):
        a.gap("inventory", "Composer environment config is unavailable")
        return a
    uri = config.get("airflowUri")
    if not isinstance(uri, str) or not uri.startswith("https://"):
        a.gap("public_endpoint", "Composer Airflow web UI URI is unavailable", "environments.list")
        return a
    a.addresses = [uri]
    if data.get("state") != "RUNNING":
        a.gap("environment_state", "Composer environment is not confirmed RUNNING")
        return a
    control = config.get("webServerNetworkAccessControl")
    if control is None:
        a.step("web_server_ip_allowlist", "allow", mode="unrestricted", uri=uri)
        a.ports = pset("tcp", 443, 443)
    elif not isinstance(control, dict) or not isinstance(control.get("allowedIpRanges"), list):
        a.gap("web_server_ip_allowlist", "Composer web server allowed IP ranges are unavailable or malformed")
    else:
        ranges = control["allowedIpRanges"]
        values = [entry.get("value") for entry in ranges if isinstance(entry, dict)]
        if len(values) != len(ranges) or any(not isinstance(value, str) or _cidr(value) is None for value in values):
            a.gap("web_server_ip_allowlist", "Composer web server allowed IP ranges are unavailable or malformed")
        elif any(_public_source(value) for value in values):
            a.step("web_server_ip_allowlist", "allow", allowed_ip_ranges=values, uri=uri)
            a.ports = pset("tcp", 443, 443)
        else:
            a.step("web_server_ip_allowlist", "block", allowed_ip_ranges=values, uri=uri)
            a.ports = {}
    a.notes.append("Airflow UI and API still require IAM authentication; no user grant or application response was evaluated")
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
    if not configs or any(not isinstance(config, dict) for config in configs):
        a.explicit = "UNKNOWN"
        a.gap("firewall", "TPU external IP has no complete VPC network configuration")
        return a
    configured_networks = [("default" if config.get("network") in (None, "") else config.get("network"))
                           for config in configs]
    if any(not isinstance(value, str) or not value for value in configured_networks):
        a.explicit = "UNKNOWN"
        a.gap("firewall", "TPU network identity is unavailable")
        return a
    selected_by_external_flag = False
    if len(set(configured_networks)) != 1:
        explicit_flags = all(type(config.get("enableExternalIps")) is bool for config in configs)
        public_networks = {configured_networks[index] for index, config in enumerate(configs)
                           if config.get("enableExternalIps") is True} if explicit_flags else set()
        if len(public_networks) != 1:
            a.explicit = "UNKNOWN"
            a.gap("firewall", "TPU public endpoints cannot be mapped to distinct VPC network configurations from the Node API")
            return a
        network = public_networks.pop()
        selected_by_external_flag = True
    else:
        network = configured_networks[0]
    if "/networks/" not in network:
        matches = [row for row in inventory.items("network") if row["scope"] == resource["scope"] and
                   row["data"].get("name") == network and isinstance(row["data"].get("selfLink"), str)]
        if len(matches) != 1:
            a.explicit = "UNKNOWN"
            a.gap("firewall", "TPU network name cannot be bound to one collected VPC")
            return a
        network = matches[0]["data"]["selfLink"]
    if selected_by_external_flag:
        a.step("tpu_network_config", "allow", network=network,
               public_enabled_configs=sum(config["enableExternalIps"] for config in configs),
               private_only_configs=sum(not config["enableExternalIps"] for config in configs))
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
    public_endpoints = [row for row in endpoints if isinstance(row.get("accessConfig"), dict)
                        and row["accessConfig"].get("externalIp") in addresses]
    declared_ports = [row.get("port") for row in public_endpoints]
    if any(type(port) is not int or not 1 <= port <= 65535 for port in declared_ports):
        a.explicit = "UNKNOWN"
        a.gap("endpoint_port", "TPU public network endpoint port is missing or malformed")
        return a
    endpoint_ports = {}
    for port in declared_ports:
        endpoint_ports = union(endpoint_ports, pset("tcp", port, port))
    permitted = intersect(allowed, endpoint_ports)
    if empty(permitted):
        a.explicit = "UNKNOWN"
        a.gap("endpoint_port", "TPU declared public endpoint port has no matching TCP firewall allowance")
        return a
    a.ports = permitted
    a.step("tpu_endpoint", "allow", declared_ports=declared_ports,
           firewall_allowed=describe(allowed), matched_ports=describe(permitted))
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


def gcp_service_account_impersonation_findings(snapshot, resources):
    """Identify direct and verified inherited third-party SA credential grants."""
    if snapshot["provider"] != "gcp":
        return []
    from .common import externality
    credential_permissions = {"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken",
                              "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt",
                              "iam.serviceAccountKeys.create"}
    known = {
        "roles/iam.serviceAccountTokenCreator": credential_permissions - {"iam.serviceAccountKeys.create"},
        "roles/iam.workloadIdentityUser": {"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken"},
        "roles/iam.serviceAccountOpenIdTokenCreator": {"iam.serviceAccounts.getOpenIdToken"},
        "roles/iam.serviceAccountKeyAdmin": {"iam.serviceAccountKeys.create"},
        "roles/iam.serviceAccountUser": {"iam.serviceAccounts.actAs"},
    }
    key_creator_roles = {"roles/owner", "roles/editor", "roles/iam.admin", "roles/iam.editor",
                         "roles/admin", "roles/writer", "roles/assuredoss.admin", "roles/securitycenter.admin"}
    known.update({role: {"iam.serviceAccountKeys.create"} for role in key_creator_roles})
    known_run_deploy = {
        "roles/run.admin": {"run.services.create", "run.jobs.create", "run.jobs.run", "run.workerpools.create"},
        "roles/run.developer": {"run.services.create", "run.jobs.create", "run.jobs.run", "run.workerpools.create"},
        "roles/run.editor": {"run.services.create", "run.jobs.create", "run.workerpools.create"},
        "roles/owner": {"run.services.create", "run.jobs.create", "run.jobs.run", "run.workerpools.create"},
        "roles/editor": {"run.services.create", "run.jobs.create", "run.jobs.run", "run.workerpools.create"},
        "roles/run.jobsExecutor": {"run.jobs.run"},
        "roles/run.jobsExecutorWithOverrides": {"run.jobs.run"},
        "roles/run.invoker": {"run.jobs.run"},
    }
    roles = {}
    project_policies = {}
    projects = {}
    run_enabled = set()
    complete_services = {collection.get("scope") for collection in snapshot.get("collections", [])
                         if collection.get("type") == "service_usage" and collection.get("status") == "collected"}
    for resource in resources:
        if resource["type"] == "iam_role" and isinstance(resource.get("data"), dict):
            roles.setdefault(resource["data"].get("name"), []).append(resource["data"])
        if resource["type"] == "iam_policy" and resource["data"].get("name") == resource.get("scope"):
            project_policies.setdefault(resource["scope"], []).append(resource)
        if resource["type"] == "project" and resource.get("scope"):
            projects.setdefault(resource["scope"], []).append(resource)
        if (resource["type"] == "service_usage" and resource.get("scope") in complete_services
                and isinstance(resource.get("data"), dict)
                and isinstance(resource["data"].get("name"), str)
                and resource["data"]["name"].endswith("/services/run.googleapis.com")
                and resource["data"].get("state") == "ENABLED"):
            run_enabled.add(resource["scope"])
    output = []
    for resource in resources:
        if resource["type"] != "service_account" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        coverage = (data.get("_coverage") or {}).get("iamPolicy")
        policy = data.get("iamPolicy")
        policy_sources = []
        if (isinstance(policy, dict) and policy.get("collection_status") in (None, "collected")
                and (not isinstance(coverage, dict) or coverage.get("status") == "collected")):
            policy_sources.append(("direct", policy, resource))
        project_scope = resource.get("scope")
        if len(project_policies.get(project_scope, [])) == 1:
            project_policy = project_policies[project_scope][0]
            if project_policy["data"].get("collection_status") in (None, "collected"):
                policy_sources.append((project_scope, project_policy["data"], project_policy))
        if len(projects.get(project_scope, [])) == 1:
            project = projects[project_scope][0]
            project_data = project["data"]
            suffix = project_scope.removeprefix("projects/") if isinstance(project_scope, str) else ""
            project_identity_ok = suffix and suffix in {
                str(project_data.get("projectId")), str(project_data.get("projectNumber")),
                str(project_data.get("name", "")).removeprefix("projects/")}
            inherited = project_data.get("_inherited_iam_policies")
            inherited_coverage = (project_data.get("_coverage") or {}).get("_inherited_iam_policies")
            if (project_identity_ok and isinstance(inherited_coverage, dict) and inherited_coverage.get("status") == "collected"
                    and isinstance(inherited, list)):
                for ancestor in inherited:
                    if (isinstance(ancestor, dict) and isinstance(ancestor.get("name"), str)
                            and re.fullmatch(r"(?:folders|organizations)/[0-9]+", ancestor["name"])
                            and ancestor.get("ancestor") == ancestor["name"]
                            and ancestor.get("collection_status") == "collected"):
                        policy_sources.append((ancestor["name"], ancestor, project))
        grants = []
        for policy_scope, current_policy, policy_resource in policy_sources:
            for binding in as_list(current_policy.get("bindings")):
                if not isinstance(binding, dict) or not isinstance(binding.get("role"), str):
                    continue
                role = binding["role"]
                role_rows = roles.get(role, [])
                resolved = role_rows[0].get("includedPermissions") if len(role_rows) == 1 else None
                permissions = set(resolved) if isinstance(resolved, list) and all(
                    isinstance(permission, str) for permission in resolved) else known.get(role)
                for member in as_list(binding.get("members")):
                    if not isinstance(member, str):
                        continue
                    classification = externality(snapshot, member)
                    if classification not in ("public", "external"):
                        continue
                    credential = sorted((permissions or set()) & credential_permissions)
                    act_as = bool(permissions and "iam.serviceAccounts.actAs" in permissions)
                    if not credential and not act_as and permissions is not None:
                        continue
                    grants.append({"member": member, "classification": classification, "role": role,
                                   "policy_scope": policy_scope,
                                   "policy_source": source(snapshot, policy_resource,
                                       "iamPolicy.bindings" if policy_resource is resource else
                                       "_inherited_iam_policies" if policy_resource["type"] == "project" else "bindings"),
                                   "credential_permissions": credential, "act_as": act_as,
                                   "conditional": (binding.get("condition") is not None and not (
                                       isinstance(binding.get("condition"), dict)
                                       and isinstance(binding["condition"].get("expression"), str)
                                       and binding["condition"]["expression"].strip() == "true")),
                                   "role_permissions_resolved": permissions is not None})
        if not grants:
            continue
        deployment_paths = []
        account_name = data.get("name")
        if (isinstance(project_scope, str) and project_scope in run_enabled and isinstance(account_name, str)
                and account_name.startswith(project_scope + "/serviceAccounts/")):
            act_as_grants = [grant for grant in grants if grant["act_as"] and not grant["conditional"]]
            deploy_permissions = {}
            for policy_scope, current_policy, policy_resource in policy_sources:
                if policy_scope == "direct":
                    continue
                for binding in as_list(current_policy.get("bindings")):
                    if not isinstance(binding, dict) or not isinstance(binding.get("role"), str):
                        continue
                    condition = binding.get("condition")
                    if condition is not None and not (isinstance(condition, dict)
                            and isinstance(condition.get("expression"), str)
                            and condition["expression"].strip() == "true"):
                        continue
                    role = binding["role"]
                    matches = roles.get(role, [])
                    permissions = matches[0].get("includedPermissions") if len(matches) == 1 else None
                    if not isinstance(permissions, list):
                        if matches:
                            continue
                        permissions = known_run_deploy.get(role, set())
                    members = {member for member in as_list(binding.get("members")) if isinstance(member, str)}
                    for act_as in act_as_grants:
                        if act_as["member"] in members:
                            for permission in ("run.services.create", "run.jobs.create", "run.jobs.run",
                                               "run.workerpools.create"):
                                if permission in permissions:
                                    deploy_permissions.setdefault(act_as["member"], {}).setdefault(permission, {
                                        "scope": policy_scope, "role": role,
                                        "source": source(snapshot, policy_resource,
                                            "_inherited_iam_policies" if policy_resource["type"] == "project" else "bindings")})
            for act_as in act_as_grants:
                available = deploy_permissions.get(act_as["member"], {})
                for path_type, required in (("cloud_run_service", ("run.services.create",)),
                                            ("cloud_run_job", ("run.jobs.create", "run.jobs.run")),
                                            ("cloud_run_worker_pool", ("run.workerpools.create",))):
                    if all(permission in available for permission in required):
                        deployment_paths.append({"member": act_as["member"],
                            "act_as_scope": act_as["policy_scope"], "path_type": path_type,
                            "permissions": list(required), "deploy_grants": [available[permission] for permission in required],
                            "service": "run.googleapis.com"})
        definite = [grant for grant in grants if grant["credential_permissions"] and not grant["conditional"]]
        definite_path = bool(deployment_paths)
        status = "FAIL" if definite or definite_path else "UNKNOWN"
        evidence = {"observed": "A public or third-party principal has a service-account credential grant."
                    if definite else "A public or third-party principal can run a Cloud Run workload as this service account."
                    if definite_path else "A public or third-party service-account grant has unresolved credential use.",
                    "service_account": data.get("name") or data.get("email"), "grants": grants,
                    "deployment_paths": deployment_paths,
                    "source": source(snapshot, resource, "data"),
                    "risk_state": "observed" if definite or definite_path else "unknown",
                    "semantics": "Collected direct or verified ancestor allow-policy permissions only; IAM denies, conditions, org policy key guardrails, and actual credential use are not proven. Cloud Run path uses a same-project service account, an enabled API, exact principal match, actAs and service or worker-pool creation, or job creation plus execution; public container images are supported."}
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_service_account_impersonation",
                              "Third-party service-account credential grant", "critical" if definite or definite_path else "info",
                              evidence, status=status))
    return output


def gcp_default_object_acl_findings(snapshot, resources):
    """Report a public template ACL that applies to future nonuniform uploads."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        if resource["type"] != "default_object_acl" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        if data.get("entity") not in ("allUsers", "allAuthenticatedUsers") or data.get("role") not in ("READER", "OWNER"):
            continue
        evidence = {"observed": "The bucket's default object ACL grants public read access to future uploads.",
                    "bucket": data.get("bucket"), "principal": data["entity"], "role": data["role"],
                    "source": source(snapshot, resource, "entity"), "risk_state": "observed_configuration",
                    "semantics": "Future object ACL template only; existing object access and effective public access prevention are assessed separately."}
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_public_default_object_acl",
                              "Public default object ACL", "high", evidence, status="FAIL"))
    return output


def gcp_authorized_dataset_future_view_findings(snapshot, resources):
    """Report a public authorized-dataset grant as future-view configuration."""
    if snapshot["provider"] != "gcp":
        return []
    from .common import externality, principal_scope
    complete_scopes = {collection.get("scope") for collection in snapshot.get("collections", [])
                       if collection.get("type") == "bigquery_dataset" and collection.get("status") == "collected"}
    project_aliases = {}
    for resource in resources:
        if resource["type"] != "project" or not isinstance(resource.get("data"), dict):
            continue
        scope = resource.get("scope")
        if not isinstance(scope, str) or scope not in complete_scopes or not scope.startswith("projects/"):
            continue
        data = resource["data"]
        aliases = {str(data.get("projectId")), str(data.get("projectNumber")),
                   str(data.get("name", "")).removeprefix("projects/")}
        if scope.removeprefix("projects/") in {str(data.get("projectId")), str(data.get("projectNumber"))}:
            for alias in aliases:
                if alias not in ("None", ""):
                    project_aliases.setdefault(alias, set()).add(scope)
    datasets = {}
    for resource in resources:
        if (resource["type"] == "bigquery_dataset" and resource.get("scope") in complete_scopes
                and isinstance(resource.get("data"), dict)
                and resource["data"].get("_representation", "full") == "full"
                and isinstance(resource["data"].get("access"), list)):
            datasets.setdefault(resource["data"].get("name"), []).append(resource)
    roles = {}
    policies = {}
    projects = {}
    complete_iam_scopes = {collection.get("scope") for collection in snapshot.get("collections", [])
                           if collection.get("type") == "iam_policy" and collection.get("status") == "collected"}
    for resource in resources:
        data = resource.get("data")
        if not isinstance(data, dict):
            continue
        if resource["type"] == "iam_role" and isinstance(data.get("name"), str):
            roles.setdefault(data["name"], []).append(data)
        elif (resource["type"] == "iam_policy" and resource.get("scope") in complete_iam_scopes
              and data.get("name") == resource.get("scope") and data.get("collection_status", "collected") == "collected"):
            policies.setdefault(resource["scope"], []).append(data)
        elif resource["type"] == "project" and isinstance(resource.get("scope"), str):
            projects.setdefault(resource["scope"], []).append(data)
    reader_cache = {}
    def project_readers(scope, legacy_groups=()):
        legacy_groups = frozenset(legacy_groups)
        cache_key = (scope, legacy_groups)
        if cache_key in reader_cache:
            return reader_cache[cache_key]
        candidates = [(scope, policy) for policy in policies.get(scope, ()) if len(policies[scope]) == 1]
        project_rows = projects.get(scope, ())
        if len(project_rows) == 1:
            project = project_rows[0]
            suffix = scope.removeprefix("projects/")
            coverage_data = project.get("_coverage") if isinstance(project.get("_coverage"), dict) else {}
            coverage = coverage_data.get("_inherited_iam_policies") or {}
            if (suffix in {str(project.get("projectId")), str(project.get("projectNumber"))}
                    and isinstance(coverage, dict) and coverage.get("status") == "collected"
                    and isinstance(project.get("_inherited_iam_policies"), list)):
                candidates.extend((ancestor["name"], ancestor) for ancestor in project["_inherited_iam_policies"]
                                  if isinstance(ancestor, dict)
                                  and isinstance(ancestor.get("name"), str)
                                  and re.fullmatch(r"(?:folders|organizations)/[0-9]+", ancestor["name"])
                                  and ancestor.get("ancestor") == ancestor["name"]
                                  and ancestor.get("collection_status") == "collected")
        grants = []
        foreign_grants = []
        for policy_scope, policy in candidates:
            for binding in as_list(policy.get("bindings")):
                if not isinstance(binding, dict):
                    continue
                condition = binding.get("condition")
                if condition is not None and not (isinstance(condition, dict)
                        and condition.get("expression") == "true"):
                    continue
                members = [member for member in as_list(binding.get("members"))
                           if member in ("allUsers", "allAuthenticatedUsers")]
                foreign_members = [member for member in as_list(binding.get("members"))
                                   if isinstance(member, str) and externality(snapshot, member) == "external"]
                role = binding.get("role")
                matches = roles.get(role, []) if isinstance(role, str) else []
                permissions = matches[0].get("includedPermissions") if len(matches) == 1 else None
                builtin_reader = role in {"roles/bigquery.dataViewer", "roles/bigquery.dataEditor",
                                          "roles/bigquery.dataOwner", "roles/bigquery.admin"}
                can_read = ("bigquery.tables.getData" in permissions if isinstance(permissions, list)
                            else builtin_reader if not matches else False)
                group_roles = {"projectReaders": "roles/viewer", "projectWriters": "roles/editor",
                               "projectOwners": "roles/owner"}
                via_groups = sorted(group for group in legacy_groups if group_roles.get(group) == role)
                if members and (can_read or via_groups):
                    grants.append({"scope": policy_scope, "role": role, "members": members,
                                   **({"via_special_groups": via_groups} if via_groups else {})})
                if foreign_members and (can_read or via_groups):
                    foreign_grants.extend({"scope": policy_scope, "role": role,
                                           "principal_kind": member.partition(":")[0],
                                           "external_scope_id": principal_scope("gcp", member),
                                           **({"via_special_groups": via_groups} if via_groups else {})}
                                          for member in foreign_members)
        reader_cache[cache_key] = (grants, foreign_grants)
        return reader_cache[cache_key]
    output = []
    for name, sources in datasets.items():
        if len(sources) != 1 or not isinstance(name, str):
            continue
        current = sources[0]
        scope = current.get("scope")
        if not isinstance(scope, str) or not name.startswith(scope + "/datasets/"):
            continue
        configurations = []
        external_configurations = []
        for entry in current["data"]["access"]:
            if not isinstance(entry, dict) or entry.get("condition") is not None:
                continue
            authorization = entry.get("dataset")
            if not isinstance(authorization, dict):
                continue
            target_types = authorization.get("targetTypes", authorization.get("target_types"))
            if not (target_types == "VIEWS" or isinstance(target_types, list) and "VIEWS" in target_types):
                continue
            ref = authorization.get("dataset")
            if not isinstance(ref, dict):
                continue
            project = ref.get("projectId", ref.get("project_id"))
            dataset_id = ref.get("datasetId", ref.get("dataset_id"))
            if not isinstance(project, str) or not isinstance(dataset_id, str) or not dataset_id:
                continue
            candidate_scopes = set(project_aliases.get(project, ()))
            direct_scope = f"projects/{project}"
            if direct_scope in complete_scopes:
                candidate_scopes.add(direct_scope)
            if len(candidate_scopes) != 1:
                continue
            target_name = f"{next(iter(candidate_scopes))}/datasets/{dataset_id}"
            targets = datasets.get(target_name, [])
            if len(targets) != 1:
                continue
            target = targets[0]
            readers = [row.get("iamMember") or row.get("specialGroup") for row in target["data"]["access"]
                       if isinstance(row, dict) and (row.get("condition") is None or
                           isinstance(row.get("condition"), dict) and row["condition"].get("expression") == "true")
                       and (row.get("iamMember") or row.get("specialGroup")) in ("allUsers", "allAuthenticatedUsers")
                       and row.get("role") in ("READER", "WRITER", "OWNER")]
            legacy_groups = [row.get("specialGroup") for row in target["data"]["access"]
                             if isinstance(row, dict) and row.get("specialGroup") in
                             ("projectReaders", "projectWriters", "projectOwners")
                             and row.get("role") in ("READER", "WRITER", "OWNER")
                             and (row.get("condition") is None or isinstance(row.get("condition"), dict)
                                  and row["condition"].get("expression") == "true")]
            inherited_readers, foreign_iam_readers = project_readers(target["scope"], legacy_groups)
            foreign_readers = []
            for row in target["data"]["access"]:
                if not isinstance(row, dict) or row.get("role") not in ("READER", "WRITER", "OWNER"):
                    continue
                condition = row.get("condition")
                if condition is not None and not (isinstance(condition, dict)
                        and condition.get("expression") == "true"):
                    continue
                for field, prefix in (("iamMember", ""), ("userByEmail", "user:"),
                                      ("groupByEmail", "group:"), ("domain", "domain:")):
                    value = row.get(field)
                    if not isinstance(value, str) or not value:
                        continue
                    member = prefix + value
                    if externality(snapshot, member) == "external":
                        foreign_readers.append({"principal_kind": field, "role": row["role"],
                                                "external_scope_id": principal_scope("gcp", member)})
            if foreign_readers or foreign_iam_readers:
                external_configurations.append({"authorized_dataset": target_name,
                                                "foreign_readers": foreign_readers,
                                                "foreign_project_iam": foreign_iam_readers})
            if not readers and not inherited_readers:
                continue
            configurations.append({"authorized_dataset": target_name, "public_readers": sorted(set(readers)),
                                   "public_project_iam": inherited_readers})
        if configurations:
            evidence = {"observed": "An authorized dataset with public readers grants its current and future views access to this source dataset.",
                        "source_dataset": name, "authorized_datasets": list({
                            (row["authorized_dataset"], tuple(row["public_readers"])): row
                            for row in configurations}.values()),
                        "source": source(snapshot, current, "access"),
                        "risk_state": "observed_configuration",
                        "semantics": "Future-view authorization only; a view must be created by an actor with required source permissions. Current view definitions, SQL results, and actual data access are assessed separately."}
            output.append(finding(snapshot, current, "exposure", "analysis.gcp_authorized_dataset_future_views",
                                  "Public authorized-dataset future-view grant", "high", evidence, status="FAIL"))
        if external_configurations:
            evidence = {"observed": "An authorized dataset with attributable foreign readers grants its current and future views access to this source dataset.",
                        "source_dataset": name, "authorized_datasets": external_configurations,
                        "source": source(snapshot, current, "access"),
                        "risk_state": "observed_configuration",
                        "semantics": "Future-view authorization only; view creation, SQL results and actual data access are not established. Only attributable foreign destination ACL and verified project or ancestor IAM readers are included."}
            output.append(finding(snapshot, current, "exposure", "analysis.gcp_authorized_dataset_future_views_external",
                                  "Third-party authorized-dataset future-view grant", "high", evidence, status="FAIL"))
    return output


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
        if resource["type"] == "artifact_repository":
            # The permission-specific finding below owns these exact grants.
            declarations = [row for row in declarations if row["role"] != "roles/artifactregistry.reader"]
        if resource["type"] in {"pubsub_topic", "pubsub_subscription"}:
            exact_role = ("roles/pubsub.publisher" if resource["type"] == "pubsub_topic"
                          else "roles/pubsub.subscriber")
            declarations = [row for row in declarations if row["role"] != exact_role]
        if not declarations:
            continue
        unconditional = [row for row in declarations if row["condition"] is None or
                         (isinstance(row["condition"], dict)
                          and isinstance(row["condition"].get("expression"), str)
                          and row["condition"]["expression"].strip() == "true")]
        status = "FAIL" if unconditional else "UNKNOWN"
        evidence = {
            "observed": ("The collected resource IAM policy grants a role to a public principal."
                         if unconditional else "The collected resource IAM policy has conditional public grants; effective access is unresolved."),
            "public_bindings": declarations, "risk_state": "observed" if unconditional else "unknown",
            "source": source(snapshot, resource, "bindings" if resource["type"] == "iam_policy" else "iamPolicy.bindings"),
            "semantics": "Declared resource IAM grants; only exact constant-true conditions are resolved. Denies and provider guardrails are not evaluated.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_public_iam",
                              "Public resource IAM grant", "high" if status == "FAIL" else "info", evidence, status=status))
    return output


def _gcp_cross_project_sa_grants(policy, project, role):
    grants = []
    for binding in as_list(policy.get("bindings")):
        if not isinstance(binding, dict) or binding.get("role") != role:
            continue
        for member in as_list(binding.get("members")):
            if not isinstance(member, str) or not member.startswith("serviceAccount:"):
                continue
            match = re.fullmatch(r"[^@]+@([a-z][a-z0-9-]*)\.iam\.gserviceaccount\.com",
                                 member.removeprefix("serviceAccount:"))
            if match and match.group(1) != project:
                grants.append({"member": member, "service_account_project": match.group(1),
                               "role": role, "condition": binding.get("condition")})
    return grants


def _gcp_grant_is_unconditional(grant):
    condition = grant.get("condition")
    return condition is None or (isinstance(condition, dict)
                                 and isinstance(condition.get("expression"), str)
                                 and condition["expression"].strip() == "true")


def gcp_bigtable_external_reader_findings(snapshot, resources):
    """Report exact direct table-reader grants to another GCP project's SA."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        if resource["type"] != "bigtable_table" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        envelope = data.get("_coverage")
        coverage = envelope.get("iamPolicy") if isinstance(envelope, dict) else None
        policy = data.get("iamPolicy")
        if (not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected")
                or isinstance(coverage, dict) and coverage.get("status") not in (None, "collected")):
            continue
        project = resource["scope"].removeprefix("projects/")
        if not project or project == resource["scope"]:
            continue
        grants = _gcp_cross_project_sa_grants(policy, project, "roles/bigtable.reader")
        if not grants:
            continue
        unconditional = [grant for grant in grants if _gcp_grant_is_unconditional(grant)]
        status = "FAIL" if unconditional else "UNKNOWN"
        named_grant = (unconditional or grants)[0]
        name = data.get("name", native_id(resource))
        if unconditional:
            observed = (
                f"The Bigtable table {name} has an IAM grant of roles/bigtable.reader to {named_grant['member']}.\n"
                "That grant may let the service account read rows in this table.\n"
                "Those rows could contain data intended to stay within this project."
            )
        else:
            observed = (
                f"The Bigtable table {name} has a conditional IAM grant of roles/bigtable.reader to {named_grant['member']}.\n"
                "The recorded condition does not tell whether this account can read these rows.\n"
                "If it allows access, the account could read data intended to stay within this project."
            )
        evidence = {
            "observed": observed,
            "direct_reader_grants": grants,
            "permission": "bigtable.tables.readRows",
            "source": source(snapshot, resource, "iamPolicy.bindings"),
            "risk_state": "observed" if unconditional else "unknown",
            "semantics": "Direct IAM grant declaration only; project ownership, IAM denies, table contents, and successful reads are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_bigtable_external_reader",
                              "Cross-project Bigtable table reader grant", "high" if unconditional else "info",
                              evidence, status=status))
    return output


def gcp_source_repository_external_reader_findings(snapshot, resources):
    """Report direct source clone/fetch grants to a cross-project service account."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        if resource["type"] != "source_repository" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        envelope = data.get("_coverage")
        coverage = envelope.get("iamPolicy") if isinstance(envelope, dict) else None
        policy = data.get("iamPolicy")
        if (not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected")
                or isinstance(coverage, dict) and coverage.get("status") not in (None, "collected")):
            continue
        project = resource["scope"].removeprefix("projects/")
        if not project or project == resource["scope"]:
            continue
        grants = _gcp_cross_project_sa_grants(policy, project, "roles/source.reader")
        if not grants:
            continue
        unconditional = [grant for grant in grants if _gcp_grant_is_unconditional(grant)]
        named_grant = (unconditional or grants)[0]
        name = data.get("name", native_id(resource))
        if unconditional:
            observed = (
                f"The source repository {name} has an IAM grant of roles/source.reader to {named_grant['member']}.\n"
                "That grant may let the service account fetch source files.\n"
                "Those files could contain code or data intended to stay within this project."
            )
        else:
            observed = (
                f"The source repository {name} has a conditional IAM grant of roles/source.reader to {named_grant['member']}.\n"
                "The recorded condition leaves this account's source access unclear.\n"
                "If it allows access, the account could fetch code or data from this project."
            )
        evidence = {
            "observed": observed,
            "direct_reader_grants": grants,
            "permission": "source.repos.get",
            "source": source(snapshot, resource, "iamPolicy.bindings"),
            "risk_state": "observed" if unconditional else "unknown",
            "semantics": "Direct IAM grant to clone, fetch and browse only; project ownership, inherited IAM, denies and successful reads are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_source_repository_external_reader",
                              "Cross-project source repository reader grant", "high" if unconditional else "info",
                              evidence, status="FAIL" if unconditional else "UNKNOWN"))
    return output


def gcp_cloud_tasks_external_enqueuer_findings(snapshot, resources):
    """Report direct queue Enqueuer grants to a cross-project service account."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        if resource["type"] != "cloudtasks_queue" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        envelope = data.get("_coverage")
        coverage = envelope.get("iamPolicy") if isinstance(envelope, dict) else None
        policy = data.get("iamPolicy")
        if (not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected")
                or isinstance(coverage, dict) and coverage.get("status") not in (None, "collected")):
            continue
        project = resource["scope"].removeprefix("projects/")
        if not project or project == resource["scope"]:
            continue
        grants = _gcp_cross_project_sa_grants(policy, project, "roles/cloudtasks.enqueuer")
        if not grants:
            continue
        unconditional = [grant for grant in grants if _gcp_grant_is_unconditional(grant)]
        grant = (unconditional or grants)[0]
        name = data.get("name", native_id(resource))
        first = (f"The Cloud Tasks queue {name} has roles/cloudtasks.enqueuer for {grant['member']} in its direct IAM policy."
                 if unconditional else
                 f"The Cloud Tasks queue {name} has a conditional roles/cloudtasks.enqueuer binding for {grant['member']}.")
        evidence = {
            "observed": "\n".join((first,
                "That role includes cloudtasks.tasks.create on the queue." if unconditional else
                "The condition has no recorded request evaluation.",
                "A service account from another GCP project may create tasks in this queue if other controls allow it." if unconditional else
                "If the condition is satisfied, that service account may create tasks in this queue.",
                "Those tasks could trigger actions or send data if the queue's target accepts them.")),
            "direct_enqueuer_grants": grants,
            "permission": "cloudtasks.tasks.create",
            "queue_state": data.get("state"),
            "source": source(snapshot, resource, "iamPolicy.bindings"),
            "risk_state": "observed" if unconditional else "unknown",
            "semantics": "Direct queue permission declaration only; task creation, target routing, dispatch and recipient ownership are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_cloud_tasks_external_enqueuer",
                              "Cross-project Cloud Tasks Enqueuer grant", "high" if unconditional else "info",
                              evidence, status="FAIL" if unconditional else "UNKNOWN"))
    return output


def gcp_scheduler_oidc_target_findings(snapshot, resources):
    """Surface configured token delivery to an HTTP target, not execution."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        if resource["type"] != "scheduler_job" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        target = data.get("httpTarget")
        if data.get("state") != "ENABLED" or not isinstance(target, dict):
            continue
        uri = target.get("uri")
        token = target.get("oidcToken")
        if not isinstance(uri, str) or not isinstance(token, dict) or not isinstance(token.get("serviceAccountEmail"), str):
            continue
        try:
            parsed = urlsplit(uri)
            host, port = parsed.hostname, parsed.port
        except ValueError:
            continue
        if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
            continue
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.lower() == "localhost":
                continue
        else:
            if not address.is_global:
                continue
        if port is not None and not 1 <= port <= 65535:
            continue
        # The collector strips query strings. Keep only the origin here because
        # even a path may be a bearer capability or customer data.
        origin_host = f"[{host.lower()}]" if ":" in host else host.lower()
        origin = f"{parsed.scheme}://{origin_host}" + (f":{port}" if port else "")
        name = data.get("name", native_id(resource))
        evidence = {
            "observed": (
                f"The Cloud Scheduler job {name} is enabled and configured to send an OIDC token for {token['serviceAccountEmail']} to {origin}.\n"
                "When the job runs, that target may receive the service account's identity token.\n"
                "If the target is outside trusted control, the token could expose access tied to that identity."
            ),
            "target_origin": origin,
            "service_account": token["serviceAccountEmail"],
            "http_method": target.get("httpMethod"),
            "source": source(snapshot, resource, "httpTarget"),
            "risk_state": "observed",
            "semantics": "Configured token-bearing outbound call only; target ownership, audience, job execution, delivery and token use are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_scheduler_oidc_target",
                              "Cloud Scheduler token-bearing HTTP target", "high", evidence, status="FAIL"))
    return output


def gcp_pubsub_oidc_push_findings(snapshot, resources):
    """Surface token-bearing push configuration without asserting delivery."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        if resource["type"] != "pubsub_subscription" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        push = data.get("pushConfig")
        if not isinstance(push, dict):
            continue
        endpoint = push.get("pushEndpoint")
        token = push.get("oidcToken")
        if not isinstance(endpoint, str) or not isinstance(token, dict):
            continue
        account = token.get("serviceAccountEmail")
        if not isinstance(account, str) or not account:
            continue
        try:
            parsed = urlsplit(endpoint)
            host, port = parsed.hostname, parsed.port
        except ValueError:
            continue
        if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
            continue
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.lower() == "localhost":
                continue
        else:
            if not address.is_global:
                continue
        if port is not None and not 1 <= port <= 65535:
            continue
        origin_host = f"[{host.lower()}]" if ":" in host else host.lower()
        origin = f"{parsed.scheme}://{origin_host}" + (f":{port}" if port else "")
        name = data.get("name", native_id(resource))
        state = data.get("state")
        evidence = {
            "observed": "\n".join((
                f"The Pub/Sub subscription {name} has push endpoint origin {origin} and state {state or 'unrecorded'}.",
                f"Its pushConfig.oidcToken.serviceAccountEmail is {account}.",
                "Pub/Sub may attach an OIDC token for that account when pushing subscription messages.",
                "If the recipient is outside the owner's control, its operators could receive message data and the token; ownership and delivery remain unresolved.")),
            "target_origin": origin,
            "service_account": account,
            "subscription_state": state,
            "source": source(snapshot, resource, "pushConfig"),
            "risk_state": "observed",
            "semantics": "Configured token-bearing push only; endpoint ownership, generated token, message contents, delivery and recipient use are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_pubsub_oidc_push",
                              "Pub/Sub token-bearing push endpoint", "high", evidence, status="FAIL"))
    return output


def gcp_artifact_public_reader_findings(snapshot, resources):
    """Report direct public Artifact Registry Reader grants, not artifact access."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        if resource["type"] != "artifact_repository" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        envelope = data.get("_coverage")
        coverage = envelope.get("iamPolicy") if isinstance(envelope, dict) else None
        policy = data.get("iamPolicy")
        if (not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected")
                or isinstance(coverage, dict) and coverage.get("status") not in (None, "collected")):
            continue
        grants = []
        for binding in as_list(policy.get("bindings")):
            if not isinstance(binding, dict) or binding.get("role") != "roles/artifactregistry.reader":
                continue
            for member in as_list(binding.get("members")):
                if member in ("allUsers", "allAuthenticatedUsers"):
                    grants.append({"member": member, "role": binding["role"],
                                   "condition": binding.get("condition")})
        if not grants:
            continue
        unconditional = [grant for grant in grants if _gcp_grant_is_unconditional(grant)]
        named_grant = (unconditional or grants)[0]
        name = data.get("name", native_id(resource))
        if unconditional:
            observed = (
                f"The Artifact Registry repository {name} has an IAM grant of roles/artifactregistry.reader to {named_grant['member']}.\n"
                "That grant may let the public principal download artifacts from this repository.\n"
                "Those artifacts could contain software or data intended for a smaller audience."
            )
        else:
            observed = (
                f"The Artifact Registry repository {name} has a conditional IAM grant of roles/artifactregistry.reader to {named_grant['member']}.\n"
                "The recorded condition leaves public artifact access unclear.\n"
                "If it allows access, artifacts could reach people outside the intended audience."
            )
        evidence = {
            "observed": observed,
            "direct_reader_grants": grants,
            "permission": "artifactregistry.repositories.downloadArtifacts",
            "repository_format": data.get("format"),
            "source": source(snapshot, resource, "iamPolicy.bindings"),
            "risk_state": "observed" if unconditional else "unknown",
            "semantics": "Direct public read-permission declaration only; IAM denies, repository contents, endpoint requests and successful downloads are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_artifact_public_reader",
                              "Public Artifact Registry Reader grant", "high" if unconditional else "info",
                              evidence, status="FAIL" if unconditional else "UNKNOWN"))
    return output


def gcp_pubsub_public_grant_findings(snapshot, resources):
    """Report direct public publish or consume grants without asserting API access."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        kind = resource["type"]
        if kind not in {"pubsub_topic", "pubsub_subscription"} or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        coverage = data.get("_coverage", {}).get("iamPolicy") if isinstance(data.get("_coverage"), dict) else None
        policy = data.get("iamPolicy")
        if (not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected")
                or isinstance(coverage, dict) and coverage.get("status") not in (None, "collected")):
            continue
        topic = kind == "pubsub_topic"
        role = "roles/pubsub.publisher" if topic else "roles/pubsub.subscriber"
        permission = "pubsub.topics.publish" if topic else "pubsub.subscriptions.consume"
        grants = []
        for binding in as_list(policy.get("bindings")):
            if not isinstance(binding, dict) or binding.get("role") != role:
                continue
            for member in as_list(binding.get("members")):
                if member in {"allUsers", "allAuthenticatedUsers"}:
                    grants.append({"member": member, "role": role, "condition": binding.get("condition")})
        if not grants:
            continue
        unconditional = [grant for grant in grants if _gcp_grant_is_unconditional(grant)]
        grant = (unconditional or grants)[0]
        name = data.get("name", native_id(resource))
        resource_label = "topic" if topic else "subscription"
        action = "publish messages to the topic" if topic else "consume messages from the subscription"
        impact = ("Those messages could affect people or services that rely on the topic."
                  if topic else "Those messages could contain data intended for a smaller audience.")
        first = (f"The Pub/Sub {resource_label} {name} has {role} for {grant['member']} in its direct IAM policy."
                 if unconditional else
                 f"The Pub/Sub {resource_label} {name} has a conditional {role} binding for {grant['member']}.")
        evidence = {
            "observed": "\n".join((first,
                f"That role includes {permission}." if unconditional else
                "The condition has no recorded request evaluation.",
                f"Internet principals may {action} if other controls allow it." if unconditional else
                f"If the condition is satisfied, that principal may {action}.",
                impact)),
            "direct_public_grants": grants,
            "permission": permission,
            "source": source(snapshot, resource, "iamPolicy.bindings"),
            "risk_state": "observed" if unconditional else "unknown",
            "semantics": "Direct resource permission declaration only; inherited policy, IAM denies, API authentication and successful requests are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_pubsub_public_grant",
                              "Public Pub/Sub publish or consume grant", "high" if unconditional else "info",
                              evidence, status="FAIL" if unconditional else "UNKNOWN"))
    return output


def gcp_secret_external_accessor_findings(snapshot, resources):
    """Report direct cross-project Secret Accessor grants, not secret reads."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    for resource in resources:
        if resource["type"] != "secret" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        coverage = data.get("_coverage", {}).get("iamPolicy") if isinstance(data.get("_coverage"), dict) else None
        policy = data.get("iamPolicy")
        if (not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected")
                or isinstance(coverage, dict) and coverage.get("status") not in (None, "collected")):
            continue
        project = resource["scope"].removeprefix("projects/")
        if not project or project == resource["scope"]:
            continue
        grants = _gcp_cross_project_sa_grants(policy, project, "roles/secretmanager.secretAccessor")
        if not grants:
            continue
        unconditional = [grant for grant in grants if _gcp_grant_is_unconditional(grant)]
        grant = (unconditional or grants)[0]
        name = data.get("name", native_id(resource))
        first = (f"The Secret Manager secret {name} has roles/secretmanager.secretAccessor for {grant['member']} in its direct IAM policy."
                 if unconditional else
                 f"The Secret Manager secret {name} has a conditional roles/secretmanager.secretAccessor binding for {grant['member']}.")
        evidence = {
            "observed": "\n".join((first,
                "That role includes secretmanager.versions.access on the secret." if unconditional else
                "The condition has no recorded request evaluation.",
                "A service account from another GCP project may access secret-version payloads if other controls allow it." if unconditional else
                "If the condition is satisfied, that service account may access secret-version payloads.",
                "Those payloads could contain credentials or data meant to stay within this project.")),
            "direct_accessor_grants": grants,
            "permission": "secretmanager.versions.access",
            "source": source(snapshot, resource, "iamPolicy.bindings"),
            "risk_state": "observed" if unconditional else "unknown",
            "semantics": "Direct secret payload permission declaration only; account ownership, IAM denies, version state and successful reads are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_secret_external_accessor",
                              "Cross-project Secret Manager Accessor grant", "high" if unconditional else "info",
                              evidence, status="FAIL" if unconditional else "UNKNOWN"))
    return output


def gcp_kms_external_decrypter_findings(snapshot, resources):
    """Report direct cross-project key decrypt grants, not decrypted data."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    roles = ("roles/cloudkms.cryptoKeyDecrypter", "roles/cloudkms.cryptoKeyEncrypterDecrypter")
    for resource in resources:
        if resource["type"] != "kms_key" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        coverage = data.get("_coverage", {}).get("iamPolicy") if isinstance(data.get("_coverage"), dict) else None
        policy = data.get("iamPolicy")
        if (not isinstance(policy, dict) or policy.get("collection_status") not in (None, "collected")
                or isinstance(coverage, dict) and coverage.get("status") not in (None, "collected")):
            continue
        project = resource["scope"].removeprefix("projects/")
        if not project or project == resource["scope"]:
            continue
        grants = [grant for role in roles for grant in _gcp_cross_project_sa_grants(policy, project, role)]
        if not grants:
            continue
        unconditional = [grant for grant in grants if _gcp_grant_is_unconditional(grant)]
        grant = (unconditional or grants)[0]
        name = data.get("name", native_id(resource))
        first = (f"The Cloud KMS key {name} has {grant['role']} for {grant['member']} in its direct IAM policy."
                 if unconditional else
                 f"The Cloud KMS key {name} has a conditional {grant['role']} binding for {grant['member']}.")
        evidence = {
            "observed": "\n".join((first,
                "That role includes cloudkms.cryptoKeyVersions.useToDecrypt on the key." if unconditional else
                "The condition has no recorded request evaluation.",
                "A service account from another GCP project may use this key to decrypt ciphertext if other controls allow it." if unconditional else
                "If the condition is satisfied, that service account may use this key to decrypt ciphertext.",
                "If that account also has encrypted data, its contents could become visible outside this project.")),
            "direct_decrypter_grants": grants,
            "permission": "cloudkms.cryptoKeyVersions.useToDecrypt",
            "key_purpose": data.get("purpose"),
            "source": source(snapshot, resource, "iamPolicy.bindings"),
            "risk_state": "observed" if unconditional else "unknown",
            "semantics": "Direct key decrypt-permission declaration only; key version state, IAM denies, ciphertext possession and successful decryption are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_kms_external_decrypter",
                              "Cross-project Cloud KMS Decrypter grant", "high" if unconditional else "info",
                              evidence, status="FAIL" if unconditional else "UNKNOWN"))
    return output


def gcp_logging_cross_project_sink_findings(snapshot, resources):
    """Report active sinks naming a different GCP project as their destination."""
    if snapshot["provider"] != "gcp":
        return []
    output = []
    destination_patterns = {
        "logging": r"logging\.googleapis\.com/projects/([^/]+)(?:/locations/[^/]+/buckets/[^/]+)?",
        "bigquery": r"bigquery\.googleapis\.com/projects/([^/]+)/datasets/[^/]+",
        "pubsub": r"pubsub\.googleapis\.com/projects/([^/]+)/topics/[^/]+",
    }
    for resource in resources:
        if resource["type"] != "log_sink" or not isinstance(resource.get("data"), dict):
            continue
        data = resource["data"]
        if data.get("disabled") not in (None, False):
            continue
        destination_ref = data.get("destination")
        if not isinstance(destination_ref, str):
            continue
        matches = [(kind, re.fullmatch(pattern, destination_ref))
                   for kind, pattern in destination_patterns.items()]
        match = next(((kind, matched) for kind, matched in matches if matched), None)
        if match is None:
            continue
        kind, matched = match
        destination_project = matched.group(1)
        source_project = resource["scope"].removeprefix("projects/")
        if (not re.fullmatch(r"[a-z][a-z0-9-]*", destination_project)
                or not re.fullmatch(r"[a-z][a-z0-9-]*", source_project)
                or source_project == destination_project):
            continue
        name = data.get("name", native_id(resource))
        evidence = {
            "observed": "\n".join((
                f"The Cloud Logging sink {name} has destination {destination_ref}.",
                f"Its disabled setting is {str(data.get('disabled', False)).lower()}, and the destination names project {destination_project}.",
                "Matching log entries may be routed to that project if writer permissions and destination controls allow it.",
                "If another owner controls the destination, its operators could access sensitive log data; ownership, filters, writer rights, and delivery remain unresolved.")),
            "destination": destination_ref,
            "destination_kind": kind,
            "destination_project": destination_project,
            "source_project": source_project,
            "source": source(snapshot, resource, "destination"),
            "risk_state": "observed",
            "semantics": "Configured cross-project log routing only; destination ownership, filters, exclusions, writer authorization, matching entries and delivery are not established.",
        }
        output.append(finding(snapshot, resource, "exposure", "analysis.gcp_logging_cross_project_sink",
                              "Cross-project Cloud Logging sink destination", "high", evidence, status="FAIL"))
    return output


# -------------------------------------------------------------------- Azure

def _props(resource):
    data = resource["data"]
    return data.get("properties") if isinstance(data.get("properties"), dict) else {}


def _azure_service_tag_ranges(inventory, scope):
    """Resolve the subscription's already collected service-tag page once per scan."""
    key = ("azure_service_tags", scope)
    if key not in inventory.network_cache:
        tags = {}
        if inventory.state("service_tag", scope) in ("collected", "empty"):
            for item in inventory.items("service_tag"):
                if item["scope"] != scope:
                    continue
                name = item["data"].get("name")
                prefixes = _props(item).get("addressPrefixes")
                if not isinstance(name, str) or not isinstance(prefixes, list):
                    continue
                networks = [_cidr(prefix) for prefix in prefixes]
                tags[name.casefold()] = networks if all(networks) else None
        inventory.network_cache[key] = tags
    return inventory.network_cache[key]


def _nsg_allowed(nsg, address=None, groups=(), service_tags=None):
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
        networks = []
        unresolved = not sources
        for value in sources:
            direct = _azure_restriction_sources(value)
            if direct:
                networks.extend(direct)
            elif isinstance(value, str) and value.casefold() == "azureloadbalancer":
                # This tag is Azure's health-probe source, not client ingress.
                continue
            elif isinstance(value, str) and service_tags is not None and service_tags.get(value.casefold()):
                networks.extend(service_tags[value.casefold()])
            else:
                unresolved = True
        source_nets[id(rule)] = networks
        if (p.get("direction", "Inbound") == "Inbound" and not p.get("sourceApplicationSecurityGroups")
                and unresolved):
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
            elif destinations and not any(d in ("*", "Any", "VirtualNetwork") or
                                          (isinstance(d, str) and d.casefold() == "internet" and address and _public_ip(address)) or
                                          (_internet(d) and not (isinstance(d, str) and d.casefold() == "internet")) or
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
    first_allow = min((int(row["priority"]) for row in matched if row.get("access") == "Allow"), default=None)
    for rule in ordered:
        if id(rule) in unresolved_sources:
            priority = int((rule.get("properties") or {}).get("priority", 4096))
            if first_allow is None or priority <= first_allow:
                matched.append({"rule": rule.get("name"), "priority": priority,
                                "unresolved_public_source": True})
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
        allowed, matched = _nsg_allowed(nsg, address, groups,
                                        _azure_service_tag_ranges(inventory, nsg["scope"]))
        unknown_here = any(row.get("unresolved_public_source") for row in matched)
        if unknown_here:
            a.gap("nsg", f"{level} NSG has a rule with an unresolved source service tag or prefix")
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


def _azure_nic_public_return_route(inventory, nic, public_address):
    """Prove a dropped public return route only from complete NIC effective routes."""
    if "effective_route" not in inventory.status:
        return None
    if inventory.state("effective_route", nic["scope"]) != "collected":
        return "unknown"
    try:
        family = ipaddress.ip_address(public_address).version
    except (TypeError, ValueError):
        return "unknown"
    nic_id = str(nic["data"].get("id", ""))
    rows = [row["data"] for row in inventory.items("effective_route")
            if row["scope"] == nic["scope"] and
            str(row["data"].get("nic_id", "")).casefold() == nic_id.casefold()]
    if not rows:
        return "unknown"
    default_drop = False
    public_override = False
    forced_tunnel = False
    seen = set()
    for row in rows:
        rid = row.get("id")
        proof = row.get("_provenance")
        route = row.get("route")
        if (not isinstance(rid, str) or not rid.casefold().startswith(
                (nic_id + "/effectiveRoutes/").casefold()) or rid.casefold() in seen
                or not isinstance(proof, dict) or proof.get("source_operation") != "effectiveRouteTable"
                or proof.get("read_only") is not True or
                str(proof.get("nic_id", "")).casefold() != nic_id.casefold()
                or not isinstance(route, dict) or route.get("state") not in ("Active", "Invalid")):
            return "unknown"
        seen.add(rid.casefold())
        if route["state"] == "Invalid":
            continue
        prefixes = route.get("addressPrefix")
        if not isinstance(prefixes, list) or not prefixes:
            return "unknown"
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except (TypeError, ValueError):
                return "unknown"
            if network.version != family:
                continue
            hop = route.get("nextHopType")
            source = route.get("source")
            if source not in ("User", "VirtualNetworkGateway", "Default") or hop not in (
                    "Internet", "None", "VnetLocal", "VnetPeering", "VirtualAppliance",
                    "VirtualApplianceEcmp", "VirtualNetworkGateway", "VirtualNetworkServiceEndpoint"):
                return "unknown"
            if network.prefixlen == 0 and source == "User":
                if hop == "None":
                    default_drop = True
                elif hop in ("VirtualAppliance", "VirtualApplianceEcmp", "VirtualNetworkGateway"):
                    forced_tunnel = True
                else:
                    public_override = True
            elif network.is_global and network.prefixlen > 0 and hop != "None":
                public_override = True
    if default_drop:
        return "unknown" if public_override or forced_tunnel else "block"
    if forced_tunnel:
        return "unknown"
    return None


def _azure_nic_declared_route_uncertainty(inventory, subnet_id, public_address):
    """A subnet UDR can change public return routing when effective routes are absent."""
    subnet, _ = _azure_subnet(inventory, subnet_id)
    if subnet is None:
        return None
    association = (subnet["data"].get("properties") or {}).get("routeTable")
    if association is None:
        return None
    table_id = association.get("id") if isinstance(association, dict) else None
    if not isinstance(table_id, str) or not table_id:
        return "unknown"
    table = inventory.get("route_table", table_id)
    if table is None or inventory.state("route_table", table["scope"]) != "collected":
        return "unknown"
    routes = _props(table).get("routes")
    if not isinstance(routes, list):
        return "unknown"
    try:
        family = ipaddress.ip_address(public_address).version
    except (TypeError, ValueError):
        return "unknown"
    for row in routes:
        props = row.get("properties") if isinstance(row, dict) else None
        if not isinstance(props, dict):
            return "unknown"
        try:
            network = ipaddress.ip_network(props.get("addressPrefix"), strict=False)
        except (TypeError, ValueError):
            return "unknown"
        if network.version == family and network.prefixlen == 0 and props.get("nextHopType") != "Internet":
            return "unknown"
    return None


def _azure_nic(snapshot, inventory, resource, public_ips):
    props = _props(resource)
    a = Assessment(resource, "public_ip")
    total, found, unresolved_route, unresolved_public = {}, False, False, False
    public_gaps = []
    for config in as_list(props.get("ipConfigurations")):
        if not isinstance(config, dict):
            continue
        cp = config.get("properties") or {}
        public_ref = (cp.get("publicIPAddress") or {}).get("id")
        if not public_ref:
            continue
        found = True
        public = inventory.get("public_ip", public_ref) or public_ips.get(str(config.get("id", "")).lower())
        if public is None:
            a.gap("inventory", f"referenced public IP {public_ref} is not collected",
                  "Microsoft.Network/publicIPAddresses")
            public_gaps.append(a.unresolved[-1])
            unresolved_public = True
            continue
        address = _props(public).get("ipAddress")
        if not address or not _public_ip(address):
            a.gap("inventory", f"referenced public IP {public_ref} has no assigned global address",
                  "Microsoft.Network/publicIPAddresses")
            public_gaps.append(a.unresolved[-1])
            unresolved_public = True
            continue
        sku = (public["data"].get("sku") or {}).get("name")
        a.addresses.append(address)
        a.step("public_ip", "allow", public_ip=native_id(public), sku=sku, address=address)
        groups = [g.get("id") for g in as_list(cp.get("applicationSecurityGroups")) if isinstance(g, dict)]
        allowed = _azure_nsg_path(inventory, a, (props.get("networkSecurityGroup") or {}).get("id"), (cp.get("subnet") or {}).get("id"),
                                  dict(FULL), cp.get("privateIPAddress"), groups, sku, config.get("name"))
        if not empty(allowed):
            route = _azure_nic_public_return_route(inventory, resource, address)
            if route is None:
                route = _azure_nic_declared_route_uncertainty(
                    inventory, (cp.get("subnet") or {}).get("id"), address)
            if route == "block":
                a.step("return_route", "block", reason="complete NIC effective routes drop public return traffic",
                       nic=native_id(resource), at=config.get("name"))
                allowed = {}
            elif route == "unknown":
                a.step("return_route", "unknown", reason="public return traffic uses an unresolved effective or declared route",
                       nic=native_id(resource), at=config.get("name"))
                unresolved_route = True
                allowed = {}
        total = union(total, allowed)
    if not found:
        return None
    a.ports = total
    if not empty(total):
        a.blocked_by = None
        for gap in public_gaps:
            gap["decisive"] = False
    elif unresolved_route or unresolved_public:
        a.explicit = "UNKNOWN"
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
    by_pool, by_config, by_address = {}, {}, {}
    position = 0
    for nic in inventory.items("nic"):
        for config in as_list(_props(nic).get("ipConfigurations")):
            cp = (config or {}).get("properties") or {}
            refs = {str(x.get("id", "")).lower() for x in as_list(cp.get("loadBalancerBackendAddressPools")) + as_list(cp.get("applicationGatewayBackendAddressPools")) if isinstance(x, dict)}
            for ref in refs:
                by_pool.setdefault(ref, []).append((position, nic, config))
            by_config.setdefault(str((config or {}).get("id", "")).lower(), []).append((nic, config))
            address = cp.get("privateIPAddress")
            subnet_ref = cp.get("subnet")
            subnet_id = subnet_ref.get("id") if isinstance(subnet_ref, dict) else None
            if isinstance(address, str) and isinstance(subnet_id, str):
                by_address.setdefault((subnet_id.casefold(), address.casefold()), []).append((nic, config))
            position += 1
    return by_pool, by_config, by_address


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


def _azure_lb_probed_backends_admin_down(backend_pools, pool_ids):
    """Prove every address in the rule's IP-based pools excludes new flows."""
    if not pool_ids:
        return False
    for pool_id in pool_ids:
        pool = backend_pools.get(str(pool_id).lower())
        props = pool.get("properties") if isinstance(pool, dict) else None
        if not isinstance(props, dict) or as_list(props.get("backendIPConfigurations")):
            return False
        addresses = props.get("loadBalancerBackendAddresses")
        if not isinstance(addresses, list) or not addresses:
            return False
        for entry in addresses:
            ep = entry.get("properties") if isinstance(entry, dict) else None
            if (not isinstance(ep, dict) or not isinstance(ep.get("ipAddress"), str)
                    or not ep["ipAddress"] or ep.get("networkInterfaceIPConfiguration")
                    or ep.get("adminState") != "Down"):
                return False
    return True


def _azure_lb(snapshot, inventory, resource):
    props = _props(resource)
    probe_ids = {str(probe.get("id")).casefold() for probe in as_list(props.get("probes"))
                 if isinstance(probe, dict) and probe.get("id")}
    backend_pools = {str(p.get("id", "")).lower(): p for p in as_list(props.get("backendAddressPools"))
                     if isinstance(p, dict) and p.get("id")}
    fronts = {str(f.get("id", "")).lower(): f for f in as_list(props.get("frontendIPConfigurations")) if isinstance(f, dict)
              and ((f.get("properties") or {}).get("publicIPAddress") or {}).get("id")}
    if not fronts:
        return None
    a = Assessment(resource, "load_balancer")
    public_fronts = {}
    for front_id, front in fronts.items():
        public = inventory.get("public_ip", front["properties"]["publicIPAddress"]["id"])
        address = _props(public).get("ipAddress") if public is not None else None
        if address and _public_ip(address):
            public_fronts[front_id] = address
    total = {}
    allowed_backend_nics = set()
    backend_routes = []
    unresolved_backends = []
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
        probe_ref = rp.get("probe")
        probed = (kind == "loadBalancingRules" and isinstance(probe_ref, dict)
                  and str(probe_ref.get("id", "")).casefold() in probe_ids)
        nics = list(_azure_backend_nics(inventory, pools)) if pools else []
        raw_backends = []
        if pools and kind == "loadBalancingRules":
            config_index = _azure_nic_config_index(inventory)
            known_configs = {str(config.get("id", "")).lower() for _, config in nics}
            for pool_id in pools:
                pool = backend_pools.get(str(pool_id).lower())
                if pool is None:
                    unresolved_backends.append(f"{kind} {rule.get('name')}: backend pool {pool_id} not collected")
                    continue
                pool_props = pool.get("properties") or {}
                entries = [(entry, None) for entry in as_list(pool_props.get("backendIPConfigurations"))]
                entries += [((entry.get("properties") or {}).get("networkInterfaceIPConfiguration"), entry)
                            for entry in as_list(pool_props.get("loadBalancerBackendAddresses")) if isinstance(entry, dict)
                            and (entry.get("properties") or {}).get("adminState") != "Down"]
                for ref, address_entry in entries:
                    config_id = ref.get("id") if isinstance(ref, dict) else None
                    if not config_id:
                        if address_entry is not None:
                            raw_backends.append(address_entry)
                        continue
                    matches = config_index[1].get(str(config_id).lower(), ()) if config_index is not None else ()
                    if not matches:
                        unresolved_backends.append(f"{kind} {rule.get('name')}: backend NIC configuration {config_id} not collected")
                    for nic, config in matches:
                        key = str(config.get("id", "")).lower()
                        if key not in known_configs:
                            nics.append((nic, config))
                            known_configs.add(key)
        if kind == "inboundNatRules":
            target = (rp.get("backendIPConfiguration") or {}).get("id")
            index = _azure_nic_config_index(inventory) if target else None
            nics = (list(index[1].get(str(target).lower(), ())) if index is not None else
                    [(n, c) for n in inventory.items("nic") for c in as_list(_props(n).get("ipConfigurations"))
                     if target and str((c or {}).get("id", "")).lower() == str(target).lower()])
        if not nics:
            if probed and _azure_lb_probed_backends_admin_down(backend_pools, pools):
                a.step("backend", "block", reason="all probed IP-based backend addresses have adminState Down",
                       rule_name=rule.get("name"))
                continue
            if not raw_backends:
                unresolved_backends.append(f"{kind} {rule.get('name')}: backend NICs not resolved")
                continue
        for nic, config in nics:
            cp = config.get("properties") or {}
            allowed = _azure_nsg_path(inventory, a, (_props(nic).get("networkSecurityGroup") or {}).get("id"), (cp.get("subnet") or {}).get("id"),
                                      backend_ports, cp.get("privateIPAddress"), [g.get("id") for g in as_list(cp.get("applicationSecurityGroups")) if isinstance(g, dict)],
                                      "standard" if (resource["data"].get("sku") or {}).get("name", "").lower() == "standard" else "basic", rule.get("name"))
            if not empty(allowed):
                if front_id not in public_fronts:
                    a.gap("inventory", f"{kind} {rule.get('name')}: assigned global public frontend address not collected",
                          "Microsoft.Network/publicIPAddresses")
                    continue
                address = public_fronts[front_id]
                route = _azure_nic_public_return_route(inventory, nic, address)
                if route is None:
                    route = _azure_nic_declared_route_uncertainty(inventory, (cp.get("subnet") or {}).get("id"), address)
                if route == "unknown":
                    a.gap("return_route", f"{kind} {rule.get('name')}: backend NIC return route unresolved")
                    continue
                if route == "block":
                    a.step("return_route", "block", reason="complete NIC effective routes drop public return traffic",
                           nic=native_id(nic), at=rule.get("name"))
                    continue
                total = union(total, frontend_ports)
                allowed_backend_nics.add(nic["id"])
                backend_routes.append({"nic_id": nic["id"], "public_ip": address,
                    "frontend_ports": describe(frontend_ports), "backend_ports": describe(backend_ports),
                    "rule_name": rule.get("name")})
                if address not in a.addresses:
                    a.addresses.append(address)
        for entry in raw_backends:
            ep = entry.get("properties")
            if not isinstance(ep, dict):
                unresolved_backends.append(f"{kind} {rule.get('name')}: raw backend properties not collected")
                continue
            if probed and ep.get("adminState") == "Down":
                continue
            backend_ip = ep.get("ipAddress")
            subnet_ref = ep.get("subnet")
            subnet_id = subnet_ref.get("id") if isinstance(subnet_ref, dict) else None
            try:
                ipaddress.ip_address(backend_ip)
            except (TypeError, ValueError):
                backend_ip = None
            if not backend_ip or not subnet_id:
                unresolved_backends.append(f"{kind} {rule.get('name')}: raw backend IP or subnet reference not collected")
                continue
            index = _azure_nic_config_index(inventory)
            matches = index[2].get((str(subnet_id).casefold(), backend_ip.casefold()), ()) if index else ()
            if not matches:
                unresolved_backends.append(f"{kind} {rule.get('name')}: raw backend {backend_ip} has no collected NIC configuration")
                continue
            for nic, config in matches:
                cp = config.get("properties") or {}
                allowed = _azure_nsg_path(inventory, a, (_props(nic).get("networkSecurityGroup") or {}).get("id"),
                                          subnet_id, backend_ports, backend_ip,
                                          [g.get("id") for g in as_list(cp.get("applicationSecurityGroups")) if isinstance(g, dict)],
                                          "standard" if (resource["data"].get("sku") or {}).get("name", "").lower() == "standard" else "basic",
                                          f"{rule.get('name')} backend {backend_ip}")
                if empty(allowed):
                    continue
                if front_id not in public_fronts:
                    a.gap("inventory", f"{kind} {rule.get('name')}: assigned global public frontend address not collected",
                          "Microsoft.Network/publicIPAddresses")
                    continue
                address = public_fronts[front_id]
                route = _azure_nic_public_return_route(inventory, nic, address)
                if route is None:
                    route = _azure_nic_declared_route_uncertainty(inventory, subnet_id, address)
                if route == "unknown":
                    a.gap("return_route", f"{kind} {rule.get('name')}: raw backend return route unresolved")
                    continue
                if route == "block":
                    a.step("return_route", "block", reason="complete NIC effective routes drop public return traffic",
                           nic=native_id(nic), at=rule.get("name"))
                    continue
                total = union(total, frontend_ports)
                allowed_backend_nics.add(nic["id"])
                backend_routes.append({"nic_id": nic["id"], "backend_ip": backend_ip, "public_ip": address,
                    "frontend_ports": describe(frontend_ports), "backend_ports": describe(backend_ports),
                    "rule_name": rule.get("name")})
                if address not in a.addresses:
                    a.addresses.append(address)
    if backend_routes:
        a.step("backend", "allow", nic_ids=sorted(allowed_backend_nics), routes=backend_routes)
    if unresolved_backends:
        if not empty(total):
            a.notes.append("Other load-balancer backend paths unresolved: " + "; ".join(unresolved_backends))
        else:
            a.gap("backend", "; ".join(unresolved_backends), "Microsoft.Network/loadBalancers/backendAddressPools")
            a.explicit = "UNKNOWN"
    unresolved_frontend = any(gap["layer"] == "inventory" and
                              "assigned global public frontend address" in gap["reason"]
                              for gap in a.unresolved)
    a.step("listener", "allow" if not empty(total) else "unknown" if unresolved_frontend else "block",
           frontend_ports=describe(total))
    a.ports = total if rules else {}
    if not empty(total):
        a.blocked_by = None
        for gap in a.unresolved:
            if gap["layer"] == "inventory" and "assigned global public frontend address" in gap["reason"]:
                gap["decisive"] = False
    elif unresolved_frontend:
        a.explicit = "UNKNOWN"
    return a


def _azure_appgw(snapshot, inventory, resource):
    props = _props(resource)
    fronts = {str(f.get("id", "")).lower(): ((f.get("properties") or {}).get("publicIPAddress") or {}).get("id")
              for f in as_list(props.get("frontendIPConfigurations")) if isinstance(f, dict)
              and ((f.get("properties") or {}).get("publicIPAddress") or {}).get("id")}
    if not fronts:
        return None
    a = Assessment(resource, "load_balancer")
    port_map = {str(p.get("id", "")).lower(): (p.get("properties") or {}).get("port") for p in as_list(props.get("frontendPorts")) if isinstance(p, dict)}
    ports, address_ports = {}, {}
    unresolved_fronts = []
    for listener in as_list(props.get("httpListeners")) + as_list(props.get("listeners")):
        lp = (listener or {}).get("properties") or {}
        front_id = str((lp.get("frontendIPConfiguration") or {}).get("id", "")).lower()
        if front_id in fronts:
            port = port_map.get(str((lp.get("frontendPort") or {}).get("id", "")).lower())
            if isinstance(port, int):
                public = inventory.get("public_ip", fronts[front_id])
                address = _props(public).get("ipAddress") if public is not None else None
                if address and _public_ip(address):
                    ports = union(ports, pset("tcp", port, port))
                    address_ports[address] = union(address_ports.get(address, {}), pset("tcp", port, port))
                    if address not in a.addresses:
                        a.addresses.append(address)
                else:
                    unresolved_fronts.append(fronts[front_id])
    if unresolved_fronts:
        if empty(ports):
            a.gap("inventory", "Application Gateway public frontend address is not collected",
                  "Microsoft.Network/publicIPAddresses")
            return a
        a.notes.append("Other Application Gateway public frontend addresses are not collected")
    a.step("listener", "allow" if not empty(ports) else "block", listener_ports=describe(ports))
    subnet = next((((c.get("properties") or {}).get("subnet") or {}).get("id") for c in as_list(props.get("gatewayIPConfigurations")) if isinstance(c, dict)), None)
    allowed, unresolved_nsg, paths = {}, [], []
    for address, listener_ports in address_ports.items():
        path = Assessment(resource, "application_gateway")
        open_ports = _azure_nsg_path(inventory, path, None, subnet, listener_ports,
                                     address=address, sku="basic", where="gateway subnet")
        known_ports = {} if path.unresolved else open_ports
        paths.append({"address": address, "listener_ports": describe(listener_ports),
                      "allowed_ports": describe(known_ports), "nsg": path.path})
        if path.unresolved:
            unresolved_nsg.extend({**gap, "reason": f"{address}: {gap['reason']}"}
                                  for gap in path.unresolved)
        else:
            allowed = union(allowed, known_ports)
    if not empty(allowed):
        if unresolved_nsg:
            a.notes.append("Other public frontend subnet NSG paths are unresolved")
        a.step("nsg", "allow", frontends=paths, allowed=describe(allowed))
    elif unresolved_nsg or unresolved_fronts:
        a.unresolved.extend(unresolved_nsg)
        if unresolved_fronts:
            a.gap("inventory", "Other Application Gateway public frontend addresses are not collected",
                  "Microsoft.Network/publicIPAddresses")
        a.step("nsg", "unknown", frontends=paths)
    else:
        a.step("nsg", "block", frontends=paths)
    a.ports = allowed
    waf = props.get("webApplicationFirewallConfiguration") or props.get("firewallPolicy")
    a.notes.append("WAF configured" if waf else "no WAF configuration on the gateway")
    return a


def _azure_restriction_sources(value):
    if isinstance(value, str) and "," in value:
        parts = [part.strip() for part in value.split(",")]
        if not all(parts):
            return []
        networks = [_azure_restriction_sources(part) for part in parts]
        return [net for group in networks for net in group] if all(networks) else []
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


def _azure_app_restriction_decision(cp, prefix, service_tags=None):
    """Resolve one App Service site surface from its recorded ARM restriction fields."""
    stem = prefix + "IpSecurityRestrictions" if prefix else "ipSecurityRestrictions"
    raw_restrictions = as_list(cp.get(stem))
    restrictions = [r for r in raw_restrictions if isinstance(r, dict)]
    unresolved = len(restrictions) != len(raw_restrictions)
    default = cp.get(stem + "DefaultAction") or ("Deny" if raw_restrictions else "Allow")
    unresolved |= default not in ("Allow", "Deny")
    prior, open_rules, unsupported = [], [], []
    try:
        ordered = sorted(restrictions, key=lambda r: int(r.get("priority", 65000)))
    except (TypeError, ValueError):
        return "unknown", {"default_action": default, "restriction_count": len(raw_restrictions),
                           "open_rules": [], "reason": "invalid restriction priority"}
    for restriction in ordered:
        source_value = restriction.get("ipAddress")
        subnet_ref = restriction.get("vnetSubnetResourceId")
        source_parts = [part.strip() for part in source_value.split(",")] if isinstance(source_value, str) else []
        sources = []
        supported = bool(source_parts) or isinstance(subnet_ref, str) and bool(subnet_ref)
        for part in source_parts:
            if part == "AnyVnets":
                continue  # Service-endpoint source, not an arbitrary internet IP.
            direct = _azure_restriction_sources(part)
            tag = service_tags.get(part.casefold()) if service_tags is not None else None
            if direct:
                sources.extend(direct)
            elif tag:
                sources.extend(tag)
            else:
                supported = False
        if not supported:
            unsupported.append(restriction.get("name"))
            continue
        action = restriction.get("action", "Allow")
        if action not in ("Allow", "Deny"):
            unsupported.append(restriction.get("name"))
            continue
        if action == "Allow" and _azure_public_remainder(sources, prior):
            open_rules.append(restriction.get("name"))
        # Header filters further narrow the matching request. A conditional deny
        # cannot shadow every request from its IP range.
        if not restriction.get("headers"):
            prior.extend(sources)
    reachable = bool(open_rules) or (default == "Allow" and _azure_public_remainder(
        _azure_restriction_sources("Any"), prior))
    unresolved |= bool(unsupported)
    detail = {"restriction_count": len(raw_restrictions), "default_action": default, "open_rules": open_rules}
    if unresolved:
        detail["reason"] = "malformed or unsupported App Service restriction or unmatched action"
    return ("unknown" if unresolved else "allow" if reachable else "block"), detail


def _azure_app_ase_mode(inventory, props):
    profile = props.get("hostingEnvironmentProfile")
    ase_id = profile.get("id") if isinstance(profile, dict) else None
    if not ase_id and props.get("serverFarmId"):
        plan = inventory.get("app_service_plan", props["serverFarmId"])
        profile = _props(plan).get("hostingEnvironmentProfile") if plan else None
        ase_id = profile.get("id") if isinstance(profile, dict) else None
    if not ase_id:
        return None, None
    ase = inventory.get("app_service_environment", ase_id)
    if ase is None:
        return "unknown", ase_id
    mode = _props(ase).get("internalLoadBalancingMode")
    if mode not in ("None", "Web", "Publishing", "Web, Publishing"):
        return "unknown", ase_id
    return mode, ase_id


def _azure_app_authentication(assessment, resource, main, scm):
    """Record the built-in auth gate without treating it as a network block."""
    site = resource["data"]
    coverage = (site.get("_coverage") or {}).get("authSettingsV2") or {}
    auth = site.get("authSettingsV2")
    expected = str(site.get("id", "")) + "/config/authsettingsV2"
    if (coverage.get("status") != "collected" or not isinstance(auth, dict)
            or str(auth.get("id", "")).casefold() != expected.casefold()
            or not isinstance(auth.get("properties"), dict)):
        assessment.step("app_authentication", "unknown", reason="site or slot authsettingsV2 not fully collected")
        return
    props = auth["properties"]
    platform = props.get("platform")
    validation = props.get("globalValidation")
    enabled = platform.get("enabled") if isinstance(platform, dict) else None
    required = validation.get("requireAuthentication") if isinstance(validation, dict) else None
    action = validation.get("unauthenticatedClientAction") if isinstance(validation, dict) else None
    excluded = validation.get("excludedPaths") if isinstance(validation, dict) else None
    no_exceptions = isinstance(excluded, list) and not excluded
    restrictive = action in ("RedirectToLoginPage", "Return401", "Return403")
    if enabled is True and required is True and restrictive and no_exceptions:
        assessment.step("app_authentication", "require", platform_enabled=True,
                        require_authentication=True, unauthenticated_action=action, excluded_paths=[])
        if main == "allow" and scm == "block":
            assessment.authenticated = True
    elif enabled is False or required is False or action == "AllowAnonymous":
        assessment.step("app_authentication", "not_required", platform_enabled=enabled,
                        require_authentication=required, unauthenticated_action=action,
                        excluded_paths=excluded if isinstance(excluded, list) else None)
    else:
        assessment.step("app_authentication", "unknown", platform_enabled=enabled,
                        require_authentication=required, unauthenticated_action=action,
                        excluded_paths=excluded if isinstance(excluded, list) else None)


def _azure_app_client_certificate(assessment, props, main):
    """Describe the main-site certificate presentation gate, not app validation."""
    if main == "block":
        return
    enabled = props.get("clientCertEnabled")
    mode = props.get("clientCertMode")
    excluded = props.get("clientCertExclusionPaths")
    if enabled is None or enabled is False:
        assessment.step("client_certificate", "not_required", client_cert_enabled=enabled)
        return
    if enabled is not True or (excluded is not None and not isinstance(excluded, str)):
        assessment.step("client_certificate", "unknown", client_cert_enabled=enabled,
                        client_cert_mode=mode)
        return
    exclusions = [path.strip() for path in re.split(r"[,;]", excluded) if path.strip()] if excluded else []
    if mode == "Required" and props.get("httpsOnly") is True and not exclusions:
        decision = "certificate_required"
    elif mode == "Required":
        decision = "partial"
    elif mode in ("Optional", "OptionalInteractiveUser"):
        decision = "optional"
    else:
        decision = "unknown"
    assessment.step("client_certificate", decision, client_cert_enabled=True,
                    client_cert_mode=mode, https_only=props.get("httpsOnly") is True,
                    excluded_paths=exclusions,
                    validation="application code must validate the forwarded certificate")


def _azure_function_triggers(assessment, inventory, resource):
    site = resource["data"]
    kind = site.get("kind")
    if resource["type"] == "app_service_slot" and site.get("parent_id"):
        parent = inventory.get("app_service", site["parent_id"])
        kind = parent["data"].get("kind") if parent is not None else kind
    kinds = {part.strip().casefold() for part in kind.split(",")} if isinstance(kind, str) else set()
    if "functionapp" not in kinds and "functions" not in (site.get("_coverage") or {}):
        return
    coverage = (site.get("_coverage") or {}).get("functions") or {}
    functions = site.get("functions")
    if coverage.get("status") not in ("collected", "empty") or not isinstance(functions, list):
        assessment.step("function_triggers", "unknown", reason="Function LIST not complete")
        return
    anonymous, keyed, unresolved = [], [], []
    site_id = str(site.get("id", ""))
    for function in functions:
        if not isinstance(function, dict) or not re.fullmatch(
                re.escape(site_id + "/functions/") + r"[^/?#%\\\s]+", str(function.get("id", "")), re.I):
            unresolved.append("malformed function identity")
            continue
        name = function["id"].rsplit("/", 1)[-1]
        props = function.get("properties")
        if not isinstance(props, dict) or props.get("triggerConfigComplete") is not True:
            unresolved.append(name)
            continue
        triggers = props.get("httpTriggers")
        if not isinstance(triggers, list):
            unresolved.append(name)
            continue
        for trigger in triggers:
            if not isinstance(trigger, dict) or props.get("isDisabled") is None:
                unresolved.append(name)
            elif props["isDisabled"] is True:
                continue
            elif str(trigger.get("authLevel", "")).casefold() == "anonymous":
                anonymous.append(name)
            elif str(trigger.get("authLevel", "")).casefold() in ("function", "admin"):
                keyed.append(name)
            else:
                unresolved.append(name)
    decision = ("anonymous" if anonymous else "unknown" if unresolved else
                "key_required" if keyed else "none")
    assessment.step("function_triggers", decision, anonymous_functions=sorted(set(anonymous)),
                    keyed_functions=sorted(set(keyed)), unresolved_functions=sorted(set(unresolved)),
                    listed_functions=len(functions))


def _azure_app_service(snapshot, inventory, resource, configs):
    props = _props(resource)
    a = Assessment(resource, "web_app")
    a.addresses = [h for h in as_list(props.get("defaultHostName")) if h]
    public_access = props.get("publicNetworkAccess")
    if str(public_access).lower() == "disabled":
        a.step("public_network_access", "block", public_network_access="Disabled")
        a.ports = {}
        return a
    if public_access is None:
        connections = as_list(props.get("privateEndpointConnections"))
        site_id = str(resource["data"].get("id", ""))
        has_endpoint = bool(site_id) and any(isinstance(row, dict) and isinstance(row.get("id"), str) and
                           re.fullmatch(re.escape(site_id) + r"/privateEndpointConnections/[^/]+",
                                        row["id"], re.I) for row in connections)
        if has_endpoint:
            a.step("public_network_access", "block", public_network_access="default(Disabled)",
                   reason="unset access with a recorded private endpoint")
            a.ports = {}
            return a
        if connections:
            a.gap("inventory", "privateEndpointConnections contain no valid site child identity")
    if public_access is not None and str(public_access).lower() != "enabled":
        a.gap("inventory", "App Service publicNetworkAccess value is unrecognized")
    ports = pset("tcp", 443, 443) if props.get("httpsOnly") else union(pset("tcp", 80, 80), pset("tcp", 443, 443))
    a.step("public_network_access", "allow", public_network_access=props.get("publicNetworkAccess", "default(Enabled)"))
    if props.get("enabled") is False and props.get("scmSiteAlsoStopped") is True:
        a.step("site_state", "block", enabled=False, scm_site_also_stopped=True)
        a.addresses = []
        a.ports = {}
        return a
    ase_mode, ase_id = _azure_app_ase_mode(inventory, props)
    if ase_mode == "Web, Publishing":
        a.step("hosting_environment", "block", ase_id=ase_id, internal_load_balancing_mode=ase_mode)
        a.ports = {}
        return a
    if ase_mode == "unknown":
        a.gap("inventory", "App Service Environment ingress mode is not collected or recognized")
    config = configs.get(str(resource["data"].get("id", "")).lower())
    if config is None:
        a.gap("access_restrictions", "site config (main and SCM restrictions) not collected", "Microsoft.Web/sites/config/web")
        a.ports = ports
        _azure_function_triggers(a, inventory, resource)
        return a
    cp = _props(config)
    service_tags = _azure_service_tag_ranges(inventory, resource["scope"])
    main, main_detail = _azure_app_restriction_decision(cp, "", service_tags)
    if main == "block":
        a.addresses = []
    use_main = cp.get("scmIpSecurityRestrictionsUseMain")
    if use_main is True:
        scm, scm_detail = main, {**main_detail, "uses_main_rules": True}
    elif use_main is False:
        scm, scm_detail = _azure_app_restriction_decision(cp, "scm", service_tags)
        scm_detail["uses_main_rules"] = False
    else:
        scm, scm_detail = "unknown", {"reason": "scmIpSecurityRestrictionsUseMain is not recorded as a boolean"}
    if ase_mode == "Web":
        main, main_detail = "block", {**main_detail, "internal_ase": ase_id}
    elif ase_mode == "Publishing":
        scm, scm_detail = "block", {**scm_detail, "internal_ase": ase_id}
    if props.get("enabled") is False:
        main, main_detail = "block", {**main_detail, "site_stopped": True}
    if props.get("hostNamesDisabled") is True:
        main, main_detail = "block", {**main_detail, "public_hostnames_disabled": True}
        if scm == "allow":
            scm, scm_detail = "unknown", {**scm_detail,
                "reason": "SCM listener under disabled public hostnames is not documented by the site flag"}
    if ase_id:
        a.step("hosting_environment", "unknown" if ase_mode == "unknown" else "allow",
               ase_id=ase_id, internal_load_balancing_mode=ase_mode)
    if main == "block":
        a.addresses = []
    scm_hosts = [h for h in as_list(props.get("enabledHostNames"))
                 if isinstance(h, str) and ".scm." in h.lower()]
    if scm == "allow" and not scm_hosts:
        scm, scm_detail = "unknown", {**scm_detail, "reason": "SCM hostname is not recorded in enabledHostNames"}
    if scm == "allow":
        a.addresses.extend(scm_hosts)
    decision = ("allow" if "allow" in (main, scm) else
                "block" if main == scm == "block" else "unknown")
    _azure_app_authentication(a, resource, main, scm)
    _azure_app_client_certificate(a, props, main)
    a.step("access_restrictions", decision, main={"decision": main, **main_detail},
           scm={"decision": scm, **scm_detail}, scm_hosts=scm_hosts)
    if decision == "unknown":
        a.gap("access_restrictions", "main or SCM public-site restriction decision is unresolved")
    a.ports = ports if decision == "allow" else {}
    _azure_function_triggers(a, inventory, resource)
    return a


def _azure_app_service_slot(snapshot, inventory, resource):
    slot = resource["data"]
    coverage = (slot.get("_coverage") or {}).get("configuration") or {}
    config = slot.get("configuration")
    if (coverage.get("status") == "collected" and isinstance(config, dict)
            and str(config.get("id", "")).casefold() ==
            (str(slot.get("id", "")) + "/config/web").casefold()
            and isinstance(config.get("properties"), dict)):
        configs = {str(slot["id"]).casefold(): {"data": config}}
    else:
        configs = {}
    assessment = _azure_app_service(snapshot, inventory, resource, configs)
    assessment.notes.append("Deployment slot has independent public-access and main/SCM restriction settings")
    return assessment


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


def _azure_storage_public_ip_rules(acls):
    """Classify public source ranges in the account's collected firewall rules."""
    public, unresolved = [], False
    for field, family in (("ipRules", 4), ("ipv6Rules", 6)):
        rules = acls.get(field, [])
        if not isinstance(rules, list):
            unresolved = True
            continue
        for rule in rules:
            value = rule.get("value") if isinstance(rule, dict) else None
            network = _cidr(value) if value else None
            if (network is None or network.version != family or
                    (isinstance(rule, dict) and rule.get("action", "Allow") != "Allow")):
                unresolved = True
            elif _azure_public_remainder([network], []):
                public.append(value)
    return public, unresolved


def _azure_storage_published_public_ip_rules(props, public, service=None):
    """IPv6 network rules require a recorded published IPv6 endpoint."""
    ipv4, ipv6 = [], []
    for value in public:
        (ipv6 if _cidr(value).version == 6 else ipv4).append(value)
    if not ipv6:
        return public, False
    endpoints = props.get("primaryEndpoints")
    ipv6_endpoints = endpoints.get("ipv6Endpoints") if isinstance(endpoints, dict) else None
    preference = props.get("dualStackEndpointPreference")
    if (isinstance(preference, dict) and preference.get("publishIpv6Endpoint") is True
            and isinstance(ipv6_endpoints, dict) and any(
                isinstance(url, str) and url.startswith("https://")
                for url in ([ipv6_endpoints.get(service)] if service else ipv6_endpoints.values()))):
        return public, False
    return ipv4, True


def _azure_storage_resource_instance_rules(acls):
    """Recorded resource-instance grants admit named Azure sources to the public endpoint."""
    rules = acls.get("resourceAccessRules", [])
    if not isinstance(rules, list):
        return [], True
    allowed = []
    unresolved = False
    for rule in rules:
        if (not isinstance(rule, dict) or not isinstance(rule.get("resourceId"), str)
                or not rule["resourceId"].startswith("/subscriptions/")
                or not isinstance(rule.get("tenantId"), str) or not rule["tenantId"]):
            unresolved = True
            continue
        allowed.append({"resource_id": rule["resourceId"], "tenant_id": rule["tenantId"]})
    return allowed, unresolved


def _azure_storage_virtual_network_rules(acls):
    """A succeeded subnet ACL can admit an Azure subnet from another tenant."""
    rules = acls.get("virtualNetworkRules", [])
    if not isinstance(rules, list):
        return [], True
    allowed = []
    unresolved = False
    for rule in rules:
        subnet_id = rule.get("id") if isinstance(rule, dict) else None
        if (not isinstance(subnet_id, str) or
                not re.fullmatch(r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/virtualNetworks/[^/]+/subnets/[^/]+", subnet_id, re.I) or
                rule.get("action", "Allow") != "Allow" or rule.get("state") != "Succeeded"):
            unresolved = True
            continue
        allowed.append(subnet_id)
    return allowed, unresolved


def _azure_storage_bypass(acls):
    """ARM NetworkRuleSet defaults the trusted-service exception to AzureServices."""
    value = acls.get("bypass", "AzureServices")
    if not isinstance(value, str):
        return None
    if value == "None":
        return set()
    entries = {part.strip() for part in value.split(",")}
    return entries if entries and entries <= {"AzureServices", "Logging", "Metrics"} else None


def _azure_storage_endpoint_urls(props, service=None):
    """Use only ARM-returned primary/secondary and published routing endpoints."""
    urls = []
    routing = props.get("routingPreference")
    routing = routing if isinstance(routing, dict) else {}
    for location in ("primaryEndpoints", "secondaryEndpoints"):
        endpoints = props.get(location)
        if not isinstance(endpoints, dict):
            continue
        for name, value in endpoints.items():
            if isinstance(value, str) and (service is None or name == service) and value.startswith("https://"):
                urls.append(value)
        for kind, publish in (("internetEndpoints", "publishInternetEndpoints"),
                              ("microsoftEndpoints", "publishMicrosoftEndpoints")):
            variant = endpoints.get(kind)
            if routing.get(publish) is True and isinstance(variant, dict):
                urls.extend(value for name, value in variant.items()
                            if (service is None or name == service) and isinstance(value, str)
                            and value.startswith("https://"))
    return sorted(set(urls))


def _azure_storage(snapshot, inventory, resource):
    props = _props(resource)
    a = Assessment(resource, "data_share")
    if str(props.get("publicNetworkAccess", "")).lower() == "disabled":
        return None
    if props.get("publicNetworkAccess") == "SecuredByPerimeter":
        a.gap("firewall", "storage network security perimeter rules are not collected")
        a.explicit = "UNKNOWN"
    acls = props.get("networkAcls") or {}
    if acls.get("defaultAction", "Allow") not in ("Allow", "Deny"):
        a.gap("firewall", "storage account network ACL default action is unresolved")
        return a
    public = []
    if acls.get("defaultAction", "Allow") == "Deny":
        public, unresolved = _azure_storage_public_ip_rules(acls)
        public, ipv6_unknown = _azure_storage_published_public_ip_rules(props, public)
        instances, unresolved_instances = _azure_storage_resource_instance_rules(acls)
        subnets, unresolved_subnets = _azure_storage_virtual_network_rules(acls)
        bypass = _azure_storage_bypass(acls)
        if public or instances or subnets:
            a.step("network_rules", "allow", default_action="Deny", public_ip_rules=public,
                   resource_instance_rules=instances, virtual_network_rules=subnets)
            if unresolved or ipv6_unknown or unresolved_instances or unresolved_subnets:
                a.notes.append("Other storage account network rule entries are malformed or incomplete")
        elif unresolved or ipv6_unknown or unresolved_instances or unresolved_subnets or bypass is None:
            a.gap("firewall", "storage account IP, resource-instance, subnet or trusted-service bypass rules are malformed or incomplete")
            a.ports = None
            return a
        elif bypass:
            a.step("trusted_service_exception", "allow", bypass=sorted(bypass), default_action="Deny")
            a.gap("authorization", "trusted Azure service exception requires service identity and data authorization")
            a.ports = None
            return a
        else:
            a.step("network_rules", "block", default_action=acls.get("defaultAction"),
                   ip_rules=len(as_list(acls.get("ipRules"))))
            a.ports = {}
            return a
    endpoint_set = props.get("primaryEndpoints") or {}
    a.addresses = _azure_storage_endpoint_urls(props)
    secondary = props.get("secondaryEndpoints")
    secondary_blob = secondary.get("blob") if isinstance(secondary, dict) else None
    if secondary_blob in a.addresses:
        a.step("secondary_endpoint", "allow", blob_url=secondary_blob,
               secondary_status=props.get("statusOfSecondary"))
    if any(_cidr(value).version == 6 for value in public):
        a.addresses.extend(sorted(v for v in endpoint_set["ipv6Endpoints"].values()
                                  if isinstance(v, str) and v.startswith("https://"))[:4])
    if not a.path:
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
    if props.get("publicNetworkAccess") == "SecuredByPerimeter":
        a.gap("firewall", "storage network security perimeter rules are not collected")
        a.explicit = "UNKNOWN"
    if props.get("publicNetworkAccess") is None:
        a.gap("inventory", "account publicNetworkAccess setting is unavailable")
    acls = props.get("networkAcls")
    if not isinstance(acls, dict) or acls.get("defaultAction") not in ("Allow", "Deny"):
        a.gap("firewall", "account network ACL default action is unavailable")
    elif acls["defaultAction"] == "Deny":
        public, unresolved = _azure_storage_public_ip_rules(acls)
        public, ipv6_unknown = _azure_storage_published_public_ip_rules(props, public, service="blob")
        instances, unresolved_instances = _azure_storage_resource_instance_rules(acls)
        subnets, unresolved_subnets = _azure_storage_virtual_network_rules(acls)
        bypass = _azure_storage_bypass(acls)
        if public or instances or subnets:
            a.step("firewall", "allow", default_action="Deny", public_ip_rules=public,
                   resource_instance_rules=instances, virtual_network_rules=subnets)
            if unresolved or ipv6_unknown or unresolved_instances or unresolved_subnets:
                a.notes.append("Other storage account network rule entries are malformed or incomplete")
        elif unresolved or ipv6_unknown or unresolved_instances or unresolved_subnets or bypass is None:
            a.gap("firewall", "storage account IP, resource-instance, subnet or trusted-service bypass rules are malformed or incomplete")
        else:
            if bypass:
                a.step("trusted_service_exception", "authenticated_only", bypass=sorted(bypass))
            a.step("firewall", "block", default_action="Deny")
            a.ports = {}
            return a
    else:
        a.step("firewall", "allow", default_action="Allow")
    endpoint_set = props.get("primaryEndpoints") or {}
    a.addresses = _azure_storage_endpoint_urls(props, service="blob")
    secondary = props.get("secondaryEndpoints")
    secondary_blob = secondary.get("blob") if isinstance(secondary, dict) else None
    if secondary_blob in a.addresses:
        a.step("secondary_endpoint", "allow", blob_url=secondary_blob,
               secondary_status=props.get("statusOfSecondary"))
    if acls.get("defaultAction") == "Deny" and any(_cidr(value).version == 6 for value in public):
        ipv6_blob = endpoint_set["ipv6Endpoints"].get("blob")
        if isinstance(ipv6_blob, str) and ipv6_blob.startswith("https://"):
            a.addresses.append(ipv6_blob)
    if not a.addresses:
        a.gap("inventory", "public blob endpoint is not collected")
    a.data_exposure = True
    a.ports = pset("tcp", 443, 443)
    return a


def _azure_sql(snapshot, inventory, resource, rules):
    props = _props(resource)
    public_access = props.get("publicNetworkAccess")
    if str(public_access).lower() == "disabled":
        return None
    a = Assessment(resource, "database")
    a.addresses = [props.get("fullyQualifiedDomainName")] if props.get("fullyQualifiedDomainName") else []
    if str(public_access).lower() != "enabled":
        a.gap("inventory", "SQL publicNetworkAccess is not explicitly Enabled or Disabled")
    rid = str(resource["data"].get("id", "")).lower()
    state = inventory.state("sql_firewall_rule", resource["data"].get("id"))
    open_rules, azure = [], False
    for rule in rules.get(rid, []):
        rp = _props(rule)
        start, end = rp.get("startIpAddress"), rp.get("endIpAddress")
        if start == "0.0.0.0" and end == "0.0.0.0":
            azure = True
            open_rules.append({"rule": rule["data"].get("name"), "source": "any Azure tenant",
                               "start_ip": start, "end_ip": end})
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
        a.notes.append("'Allow Azure services' admits resources in other Azure tenants; database authentication is separate")
    if state not in ("collected", "empty") and not open_rules:
        a.gap("firewall", f"SQL firewall rules {state}", "Microsoft.Sql/servers/firewallRules")
    if not open_rules:
        a.gap("firewall", "database-level firewall rules are not in ARM server firewall LIST",
              "SQL data-plane sys.database_firewall_rules for each database")
    unresolved_rules = any(gap["layer"] == "firewall" for gap in a.unresolved)
    a.step("firewall", "allow" if open_rules else "unknown" if unresolved_rules else "block",
           open_rules=open_rules)
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
    env_id = props.get("environmentId") or props.get("managedEnvironmentId")
    environment = inventory.get("container_app_environment", env_id)
    route_hosts = []
    route_state = None
    if ingress.get("external") is not True:
        if environment is not None:
            route_state = (environment["data"].get("_coverage") or {}).get("httpRouteConfigs", {}).get("status")
            app_name = str(resource["data"].get("id", "")).rsplit("/", 1)[-1].casefold()
            for route in as_list(environment["data"].get("httpRouteConfigs")):
                route_props = route.get("properties") if isinstance(route, dict) else None
                if not isinstance(route_props, dict) or route_props.get("provisioningState") != "Succeeded":
                    continue
                if not any(isinstance(rule, dict) and any(
                        isinstance(target, dict) and str(target.get("containerApp", "")).casefold() == app_name
                        for target in as_list(rule.get("targets")))
                        for rule in as_list(route_props.get("rules"))):
                    continue
                fqdn = route_props.get("fqdn")
                if isinstance(fqdn, str) and fqdn:
                    route_hosts.append(fqdn)
        if ingress.get("external") is False and not route_hosts and route_state in ("collected", "empty"):
            return None
    a = Assessment(resource, "container")
    if ingress.get("external") is not True:
        if not route_hosts:
            a.gap("inventory", "Container App ingress external setting is unavailable" if
                  ingress.get("external") is not False else
                  "Container Apps environment HTTP route inventory is incomplete")
            return a
        a.addresses = sorted(set(route_hosts))
        a.step("environment_http_route", "allow", route_fqdns=a.addresses,
               app_ingress_external=ingress.get("external"))
    runtime = inventory.get("container_app_runtime", resource["data"].get("id"))
    runtime_status = _props(runtime).get("runningStatus") if runtime is not None else props.get("runningStatus")
    if runtime_status == "Stopped":
        a.step("app_state", "block", running_status="Stopped")
        a.ports = {}
        return a
    if runtime_status in ("Progressing", "Suspended"):
        a.gap("inventory", "Container App running status is transitional or suspended")
        a.step("app_state", "unknown", running_status=runtime_status)
    if (runtime is not None and runtime_status == "Running"
            and _props(runtime).get("provisioningState") == "Succeeded"
            and inventory.state("container_app_runtime", resource["scope"]) == "collected"
            and (runtime["data"].get("_provenance") or {}).get("method") == "GET+LIST"
            and (runtime["data"].get("_provenance") or {}).get("read_only") is True):
        revisions = runtime["data"].get("revisions")
        if (isinstance(revisions, list) and revisions and all(
                isinstance(revision, dict) and
                str(revision.get("id", "")).casefold().startswith(
                    str(resource["data"].get("id", "")).casefold() + "/revisions/") and
                isinstance(revision.get("properties"), dict) and
                revision["properties"].get("active") is False
                for revision in revisions)):
            a.step("revisions", "block", inactive_revision_count=len(revisions),
                   running_status=runtime_status)
            a.ports = {}
            return a
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
    transport = "http" if route_hosts and ingress.get("external") is not True else str(ingress.get("transport") or "auto").lower()
    if transport == "tcp":
        port = ingress.get("exposedPort")
        if isinstance(port, int) and 1 <= port <= 65535:
            a.ports = pset("tcp", port, port)
        else:
            a.gap("listener", "Container App TCP exposedPort is unavailable")
    elif transport in ("auto", "http", "http2"):
        a.ports = union(pset("tcp", 80, 80), pset("tcp", 443, 443))
        insecure = ingress.get("allowInsecure")
        if insecure is not None and type(insecure) is not bool:
            a.gap("listener", "Container App allowInsecure HTTP redirect mode is unresolved")
        else:
            a.step("http_port_80", "allow" if insecure is True else "redirect",
                   allow_insecure=insecure if insecure is not None else False)
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
    if route_hosts and ingress.get("external") is not True and rules:
        a.gap("access_restrictions", "app IP restriction behavior through environment HTTP route is unresolved")
        rules = []
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
    if not route_hosts:
        fqdn = ingress.get("fqdn")
        if isinstance(fqdn, str) and fqdn:
            a.addresses.append(fqdn)
        else:
            a.gap("inventory", "Container App public ingress FQDN is not collected")
    if (ingress.get("external") is True and transport in ("auto", "http", "http2") and environment is not None
            and runtime is not None and inventory.state("container_app_runtime", resource["scope"]) == "collected"
            and (runtime["data"].get("_provenance") or {}).get("method") == "GET+LIST"
            and (runtime["data"].get("_provenance") or {}).get("read_only") is True):
        domain = _props(environment).get("defaultDomain")
        traffic = ingress.get("traffic")
        revisions = runtime["data"].get("revisions")
        if isinstance(domain, str) and domain and isinstance(traffic, list) and isinstance(revisions, list):
            active = {str(rev.get("id", "")).rsplit("/", 1)[-1].casefold()
                      for rev in revisions if isinstance(rev, dict)
                      and isinstance(rev.get("properties"), dict)
                      and rev["properties"].get("active") is True}
            labels = sorted({entry["label"] for entry in traffic if isinstance(entry, dict)
                             and isinstance(entry.get("label"), str)
                             and re.fullmatch(r"[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?", entry["label"])
                             and "--" not in entry["label"]
                             and str(entry.get("revisionName", "")).casefold() in active})
            if labels:
                name = str(resource["data"].get("id", "")).rsplit("/", 1)[-1]
                label_hosts = [f"{name}---{label}.{domain}" for label in labels]
                a.addresses.extend(host for host in label_hosts if host not in a.addresses)
                a.step("revision_labels", "allow", active_label_fqdns=label_hosts,
                       source="ARM ingress traffic, environment defaultDomain and complete revisions LIST")
    if props.get("provisioningState") not in (None, "Succeeded"):
        a.gap("inventory", "Container App provisioning is not confirmed successful")
    a.step("listener", "allow" if a.ports else "unknown", transport=transport, ports=describe(a.ports or {}))
    return a


def _azure_firewall_stopped_vm_backend(inventory, translated_address):
    """A unique NIC-owned translated IP can prove an off VM cannot serve DNAT."""
    try:
        target = ipaddress.ip_address(translated_address)
    except (TypeError, ValueError):
        return None
    matches = []
    for nic in inventory.items("nic"):
        for config in as_list(_props(nic).get("ipConfigurations")):
            address = (config.get("properties") or {}).get("privateIPAddress") if isinstance(config, dict) else None
            if address == str(target):
                matches.append(nic)
    if len(matches) != 1:
        return None
    nic = matches[0]
    vm_id = (_props(nic).get("virtualMachine") or {}).get("id")
    vm = inventory.get("vm", vm_id) if vm_id else None
    view = _props(vm).get("instanceView") if vm is not None else None
    statuses = view.get("statuses") if isinstance(view, dict) else None
    if not isinstance(statuses, list):
        return None
    power = [row.get("code") for row in statuses if isinstance(row, dict)
             and str(row.get("code", "")).startswith("PowerState/")]
    if len(power) != 1 or power[0] not in ("PowerState/stopped", "PowerState/deallocated"):
        return None
    return {"nic": native_id(nic), "vm": native_id(vm), "power_state": power[0],
            "translated_address": str(target)}


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
            # Azure Firewall does not inherit NAT collections from base policies.
            # Network/application inheritance can filter other paths, but not
            # create an inbound DNAT rule for this policy.
    ports, matched = {}, []
    for collection in collections:
        cp = (collection or {}).get("properties") or collection or {}
        if str((cp.get("action") or {}).get("type", "")).lower() != "dnat":
            continue
        for rule in as_list(cp.get("rules")):
            if not isinstance(rule, dict):
                continue
            sources = []
            for value in as_list(rule.get("sourceAddresses")):
                parsed = _azure_restriction_sources(value)
                sources.extend(parsed if parsed else [None])
            group_refs = rule.get("sourceIpGroups")
            if group_refs is None:
                group_refs = []
            if not isinstance(group_refs, list):
                a.gap("policy", "DNAT source IP group references are malformed")
                group_refs = []
            for group_id in group_refs:
                if not isinstance(group_id, str) or not group_id:
                    a.gap("policy", "DNAT source IP group reference is malformed")
                    continue
                group = inventory.get("ip_group", group_id)
                if group is None:
                    a.gap("policy", "referenced DNAT source IP group is not collected", "Microsoft.Network/ipGroups")
                    continue
                group_props = _props(group)
                addresses = group_props.get("ipAddresses")
                if (not isinstance(addresses, list) or
                        group_props.get("provisioningState") not in (None, "Succeeded")):
                    a.gap("policy", "DNAT source IP group membership is incomplete or not provisioned")
                    continue
                sources.extend(_cidr(value) for value in addresses)
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
        stopped = ([_azure_firewall_stopped_vm_backend(inventory, rule["translated_address"])
                    for rule in matched] if not a.unresolved else [])
        if stopped and all(stopped):
            a.step("backend", "block", stopped_vm_backends=stopped)
            a.ports = {}
            return a
        a.gap("backend", "translated backend route, runtime and effective NSG are not resolved")
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
    if kind in ("servicebus_namespace", "eventhub_namespace"):
        local_auth = props.get("disableLocalAuth")
        coverage = (resource["data"].get("_coverage") or {}).get("authorizationRules") or {}
        rules = resource["data"].get("authorizationRules")
        if local_auth is True:
            a.step("sas_authorization", "disabled", disable_local_auth=True)
        elif local_auth is False and coverage.get("status") in ("collected", "empty") and isinstance(rules, list):
            a.step("sas_authorization", "conditional", disable_local_auth=False,
                   namespace_rules=[{"name": row["name"], "rights": row["properties"]["rights"]}
                                    for row in rules])
            if rules:
                a.notes.append("Namespace SAS rules grant capabilities to key holders; issued tokens and recipients are not inventoried.")
        else:
            a.notes.append("Namespace SAS authentication or authorization-rule inventory is incomplete.")
        if local_auth is False:
            entity_rules = []
            complete = True
            for field in (("queues", "topics") if kind == "servicebus_namespace" else ("eventHubs",)):
                entities = resource["data"].get(field)
                list_status = (resource["data"].get("_coverage") or {}).get(field, {}).get("status")
                if list_status not in ("collected", "empty") or not isinstance(entities, list):
                    complete = False
                    continue
                for entity in entities:
                    rule_status = (entity.get("_coverage") or {}).get("authorizationRules", {}).get("status")
                    if rule_status not in ("collected", "empty") or not isinstance(entity.get("authorizationRules"), list):
                        complete = False
                        continue
                    for rule in entity["authorizationRules"]:
                        entity_rules.append({"entity": entity["id"], "name": rule["name"],
                                             "rights": rule["properties"]["rights"]})
            if entity_rules:
                a.step("sas_entity_authorization", "conditional", rules=entity_rules,
                       inventory_complete=complete)
            if not complete:
                a.notes.append("Queue or topic SAS rule inventory is incomplete."
                               if kind == "servicebus_namespace"
                               else "Event Hub entity SAS rule inventory is incomplete.")
    if kind == "container_registry":
        if props.get("adminUserEnabled") is True:
            a.step("registry_admin_credentials", "conditional", admin_user_enabled=True)
            a.notes.append("Registry admin credentials are enabled; their holders are not inventoried.")
        token_coverage = (resource["data"].get("_coverage") or {}).get("tokens") or {}
        map_coverage = (resource["data"].get("_coverage") or {}).get("scopeMaps") or {}
        tokens, maps = resource["data"].get("tokens"), resource["data"].get("scopeMaps")
        if (token_coverage.get("status") in ("collected", "empty") and isinstance(tokens, list)
                and map_coverage.get("status") in ("collected", "empty") and isinstance(maps, list)):
            scope_maps = {row["id"].casefold(): row for row in maps
                          if isinstance(row, dict) and isinstance(row.get("id"), str)}
            active_tokens, unresolved = [], False
            for token in tokens:
                token_props = token.get("properties") if isinstance(token, dict) else None
                if not isinstance(token_props, dict):
                    unresolved = True
                    continue
                if str(token_props.get("status", "")).casefold() == "disabled":
                    continue
                if str(token_props.get("status", "")).casefold() != "enabled":
                    unresolved = True
                    continue
                map_id = token_props.get("scopeMapId")
                scope_map = scope_maps.get(map_id.casefold()) if isinstance(map_id, str) else None
                actions = (scope_map.get("properties") or {}).get("actions") if scope_map else None
                if not isinstance(actions, list) or any(not isinstance(action, str) for action in actions):
                    unresolved = True
                    continue
                active_tokens.append({"name": token.get("name"), "scope_map": map_id,
                                      "actions": actions})
            if active_tokens:
                a.step("registry_tokens", "conditional", enabled_tokens=active_tokens)
                a.notes.append("Enabled registry tokens grant their scope-map actions to valid password holders; holders and password state are not inventoried.")
            if unresolved:
                a.notes.append("Some registry token scope-map rights are unresolved.")
        else:
            a.notes.append("Registry token or scope-map inventory is incomplete.")
        anonymous = props.get("anonymousPullEnabled")
        if anonymous is True:
            a.authenticated = False
            a.step("anonymous_pull", "allow", anonymous_pull_enabled=True)
            a.notes.append("Anonymous pull permits unauthenticated read of every repository; registry content was not inventoried.")
        elif anonymous is False:
            a.step("anonymous_pull", "authenticated_only", anonymous_pull_enabled=False)
        else:
            a.notes.append("ACR anonymous-pull setting is unavailable; authentication cannot be established from this snapshot.")
    endpoint = next((props.get(field) for field in ("vaultUri", "hsmUri", "loginServer", "endpoint", "documentEndpoint", "serviceBusEndpoint", "fullyQualifiedDomainName")
                     if isinstance(props.get(field), str) and props.get(field)), None)
    if endpoint:
        a.addresses.append(endpoint)
    flexible = kind in ("mysql_flexible_server", "postgresql_flexible_server")
    network = props.get("network") if isinstance(props.get("network"), dict) else {}
    public = network.get("publicNetworkAccess") if flexible else props.get("publicNetworkAccess")
    namespace_rules = None
    if kind in ("servicebus_namespace", "eventhub_namespace"):
        coverage = (resource["data"].get("_coverage") or {}).get("networkRuleSet") or {}
        child = resource["data"].get("networkRuleSet")
        if coverage.get("status") == "collected" and isinstance(child, dict) and isinstance(child.get("properties"), dict):
            namespace_rules = child["properties"]
            if public is None:
                public = namespace_rules.get("publicNetworkAccess")
    if isinstance(public, str) and public.lower() == "disabled":
        a.step("public_network_access", "block", public_network_access=public)
        a.ports = {}
        if kind in ("vault", "managed_hsm"):
            acls = props.get("networkAcls")
            bypass = acls.get("bypass", "AzureServices") if isinstance(acls, dict) else None
            if bypass != "None":
                a.gap("authorization", "trusted-service firewall bypass may admit external service identities")
                a.explicit = "UNKNOWN"
        return a
    if not isinstance(public, str) or public.lower() != "enabled":
        a.gap("inventory", "publicNetworkAccess is not explicitly collected as Enabled or Disabled")
        return a
    a.step("public_network_access", "allow", public_network_access=public)
    if flexible:
        if network.get("delegatedSubnetResourceId"):
            a.gap("nsg", "delegated database subnet route and NSG are not resolved")
            a.explicit = "UNKNOWN"
        coverage = (resource["data"].get("_coverage") or {}).get("firewallRules") or {}
        rows = resource["data"].get("firewallRules")
        if coverage.get("status") not in ("collected", "empty") or not isinstance(rows, list):
            a.gap("firewall", "flexible server firewall child rules are not fully collected")
            return a
        public_rules, malformed = [], False
        for row in rows:
            fields = row.get("properties") if isinstance(row, dict) else None
            try:
                start = ipaddress.IPv4Address(fields["startIpAddress"])
                end = ipaddress.IPv4Address(fields["endIpAddress"])
                if start > end:
                    raise ValueError("reversed range")
                if start == end == ipaddress.IPv4Address("0.0.0.0"):
                    public_rules.append({"name": row.get("name"), "source": "any Azure tenant"})
                elif _azure_public_remainder(ipaddress.summarize_address_range(start, end), []):
                    public_rules.append({"name": row.get("name"), "source": str(start) + "-" + str(end)})
            except (TypeError, KeyError, ValueError):
                malformed = True
        if public_rules:
            a.step("firewall", "allow", public_rules=public_rules)
            a.ports = pset("tcp", port, port)
            a.explicit = None
            if not endpoint:
                a.gap("inventory", "flexible server public hostname is not collected")
        elif malformed:
            a.gap("firewall", "flexible server firewall IP range is unresolved")
        else:
            a.step("firewall", "block", reason="no public-source firewall rule")
            a.ports = {}
        return a
    if kind == "cosmos_account":
        ip_rules = props.get("ipRules")
        if not isinstance(ip_rules, list):
            a.gap("firewall", "Cosmos IP firewall rules are not collected")
        elif not ip_rules and props.get("isVirtualNetworkFilterEnabled") is False:
            a.step("firewall", "allow", reason="no IP or VNet access list")
        elif not ip_rules:
            vnet_rules = props.get("virtualNetworkRules")
            bypass_ids = props.get("networkAclBypassResourceIds")
            if (props.get("isVirtualNetworkFilterEnabled") is True and isinstance(vnet_rules, list)
                    and props.get("networkAclBypass") == "None" and bypass_ids == []):
                subnet_ids = []
                for rule in vnet_rules:
                    subnet_id = rule.get("id") if isinstance(rule, dict) else None
                    if (not isinstance(subnet_id, str) or not re.fullmatch(
                            r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/"
                            r"virtualNetworks/[^/]+/subnets/[^/]+", subnet_id, re.IGNORECASE)):
                        break
                    subnet_ids.append(subnet_id)
                if len(subnet_ids) == len(vnet_rules):
                    a.step("firewall", "block", reason="only subnet service-endpoint sources are allowed")
                    outside = [sid for sid in subnet_ids
                               if sid.split("/", 3)[2].casefold() != resource["scope"].split("/", 3)[2].casefold()]
                    if outside:
                        a.step("vnet_acl", "conditional", cross_subscription_subnet_ids=outside)
                        a.gap("authorization", "cross-subscription Cosmos subnet ownership and effective access are unresolved")
                        a.explicit = "UNKNOWN"
                else:
                    a.gap("firewall", "Cosmos VNet subnet rule is malformed")
            else:
                a.gap("firewall", "Cosmos VNet access list or network ACL bypass is unresolved")
        else:
            public_ips, azure_tenants, malformed = [], False, False
            for rule in ip_rules:
                value = rule.get("ipAddressOrRange") if isinstance(rule, dict) else None
                if value == "0.0.0.0":
                    azure_tenants = True
                    continue
                network = _cidr(value) if value else None
                if network is None:
                    malformed = True
                elif _azure_public_remainder([network], []):
                    public_ips.append(value)
            if public_ips or azure_tenants:
                a.step("firewall", "allow", public_ip_rules=public_ips,
                       cross_tenant_azure_services=azure_tenants)
            else:
                a.gap("firewall", "Cosmos IP rule or network ACL bypass is unresolved"
                      if malformed or props.get("networkAclBypass") not in (None, "None")
                      else "Cosmos nonpublic IP rule requires source validation")
        a.ports = {} if a.blocked_by == "firewall" else pset("tcp", port, port)
        if not endpoint:
            a.gap("inventory", "Cosmos public endpoint address is not collected")
        return a
    if kind == "app_configuration":
        a.step("listener", "allow", reason="App Configuration public endpoint has no ARM IP firewall")
        a.ports = pset("tcp", 443, 443)
        if not endpoint:
            a.gap("inventory", "App Configuration public endpoint address is not collected")
        return a
    if kind == "search_service":
        rules = props.get("networkRuleSet")
        ip_rules = rules.get("ipRules") if isinstance(rules, dict) else None
        if not isinstance(ip_rules, list):
            a.gap("firewall", "Search IP restriction list is not collected")
            return a
        public_ips, malformed = [], False
        for rule in ip_rules:
            value = rule.get("value") if isinstance(rule, dict) else None
            network = _cidr(value) if isinstance(value, str) else None
            if network is None:
                malformed = True
            elif _azure_public_remainder([network], []):
                public_ips.append(value)
        if public_ips or not ip_rules:
            a.step("firewall", "allow", public_ip_rules=public_ips,
                   reason="no IP restriction rules" if not ip_rules else "public source allowed")
            a.ports = pset("tcp", 443, 443)
        elif malformed or rules.get("bypass") not in (None, "None"):
            a.gap("firewall", "Search IP rule or bypass needs effective source evaluation")
        else:
            a.step("firewall", "block", reason="no public-source IP rule")
            a.ports = {}
        return a
    # A private endpoint does not close an explicitly enabled public endpoint.
    rules = namespace_rules if kind in ("servicebus_namespace", "eventhub_namespace") else props.get(rules_name)
    if isinstance(rules, dict) and rules_name != "firewallRules":
        action = rules.get("defaultAction")
        if action == "Deny":
            if kind in ("vault", "managed_hsm"):
                public_ips, malformed = _azure_storage_public_ip_rules(rules)
                if public_ips:
                    a.step("firewall", "allow", default_action=action, public_ip_rules=public_ips)
                    a.ports = pset("tcp", port, port)
                    if not endpoint:
                        a.gap("inventory", "managed public endpoint address is not collected")
                    return a
                if malformed or rules.get("bypass", "AzureServices") != "None":
                    a.gap("firewall", "vault IP rules or trusted-service bypass need effective authorization")
                    a.ports = pset("tcp", port, port)
                    return a
            if kind in ("container_registry", "cognitive_account",
                        "servicebus_namespace", "eventhub_namespace"):
                ip_field = "ipMask" if kind in ("servicebus_namespace", "eventhub_namespace") else "value"
                public_ips, malformed = [], False
                ip_rules = rules.get("ipRules", [])
                if not isinstance(ip_rules, list):
                    malformed = True
                else:
                    for rule in ip_rules:
                        value = rule.get(ip_field) if isinstance(rule, dict) else None
                        network = _cidr(value) if isinstance(value, str) else None
                        if network is None or rule.get("action", "Allow") != "Allow":
                            malformed = True
                        elif _azure_public_remainder([network], []):
                            public_ips.append(value)
                if public_ips:
                    a.step("firewall", "allow", default_action=action, public_ip_rules=public_ips)
                    a.ports = pset("tcp", port, port)
                    if malformed:
                        a.notes.append("Additional IP rules remain unresolved")
                    return a
                bypass = (rules.get("trustedServiceAccessEnabled") is True or
                          rules.get("bypass") not in (None, "None") or
                          kind == "container_registry" and props.get("networkRuleBypassOptions") not in (None, "None"))
                if malformed or bypass:
                    a.gap("firewall", "managed endpoint IP rule or trusted-service bypass unresolved")
                    a.ports = pset("tcp", port, port)
                    return a
                a.step("firewall", "block", reason="no public-source IP rule", default_action=action)
                a.ports = {}
                return a
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


def _azure_realtime_endpoint(snapshot, inventory, resource):
    """SignalR/Web PubSub public listener from recorded request and IP ACLs."""
    props = _props(resource)
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True
    access = props.get("publicNetworkAccess")
    if access == "Disabled":
        a.step("public_network_access", "block", value=access)
        a.ports = {}
        return a
    if access != "Enabled":
        a.gap("inventory", "realtime service publicNetworkAccess is unavailable")
        return a
    a.step("public_network_access", "allow", value=access)
    hostname = props.get("hostName")
    port = props.get("publicPort")
    if isinstance(hostname, str) and hostname:
        a.addresses.append(hostname)
    else:
        a.gap("inventory", "realtime service hostname is unavailable")
    if type(port) is not int or not 1 <= port <= 65535:
        a.gap("listener", "realtime service public port is unavailable")
        return a
    a.ports = pset("tcp", port, port)
    acl = props.get("networkACLs")
    if not isinstance(acl, dict) or acl.get("defaultAction") not in ("Allow", "Deny"):
        a.gap("firewall", "realtime service network ACL default is unavailable")
        return a
    default = acl["defaultAction"]
    public = acl.get("publicNetwork")
    if public is not None and not isinstance(public, dict):
        a.gap("policy", "realtime public request ACL is malformed")
        return a
    public = public or {}
    allow_types, deny_types = public.get("allow", []), public.get("deny", [])
    if not isinstance(allow_types, list) or not isinstance(deny_types, list):
        a.gap("policy", "realtime public request types are malformed")
        return a
    request_types = {"ClientConnection", "ServerConnection", "RESTAPI", "Trace"}
    if any(t not in request_types for t in allow_types + deny_types) or set(allow_types) & set(deny_types):
        a.gap("policy", "realtime public request type precedence is unresolved")
        return a
    permitted_types = (request_types if default == "Allow" else set()) | set(allow_types)
    permitted_types -= set(deny_types)
    rules = acl.get("ipRules", [])
    if not isinstance(rules, list):
        a.gap("firewall", "realtime service IP rules are malformed")
        return a
    denied, public_source, malformed = [], False, False
    for rule in rules:
        value = rule.get("value") if isinstance(rule, dict) else None
        action = rule.get("action") if isinstance(rule, dict) else None
        network = _cidr(value) if value else None
        if network is None or action not in ("Allow", "Deny"):
            malformed = True
            continue
        if action == "Allow" and _azure_public_remainder([network], denied):
            public_source = True
        elif action == "Deny":
            denied.append(network)
    if default == "Allow" and _azure_public_remainder(
            [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")], denied):
        public_source = True
    if not rules and permitted_types:
        public_source = True
    if malformed:
        a.gap("firewall", "realtime service IP rule syntax is unresolved")
    if not permitted_types and not rules:
        a.step("policy", "block", reason="no public request type admitted")
        a.ports = {}
    elif not public_source and not malformed and default == "Allow":
        a.step("firewall", "block", reason="no public source admitted")
        a.ports = {}
    elif public_source and permitted_types:
        a.step("listener", "allow", public_request_types=sorted(permitted_types))
    else:
        a.gap("policy", "realtime listener public request path is unresolved")
    a.notes.append("Public listener does not establish a valid client or server authorization token")
    return a


def _azure_synapse_workspace(snapshot, inventory, resource):
    """Workspace public SQL/development listeners and complete ARM IP rules."""
    props = _props(resource)
    a = Assessment(resource, "database")
    a.authenticated = True
    access = props.get("publicNetworkAccess")
    if access == "Disabled":
        a.step("public_network_access", "block", value=access)
        a.ports = {}
        return a
    if access != "Enabled":
        a.gap("inventory", "Synapse public network access is not explicit")
        return a
    a.step("public_network_access", "allow", value=access)
    endpoints = props.get("connectivityEndpoints")
    ports = {}
    if isinstance(endpoints, dict):
        for name, port in (("sql", 1433), ("sqlOnDemand", 1433), ("dev", 443)):
            host = endpoints.get(name)
            if isinstance(host, str) and host:
                a.addresses.append(host)
                ports = union(ports, pset("tcp", port, port))
    if not ports:
        a.gap("inventory", "Synapse SQL/development endpoint hostnames are unavailable")
    coverage = (resource["data"].get("_coverage") or {}).get("firewallRules") or {}
    rules = resource["data"].get("firewallRules")
    if coverage.get("status") not in ("collected", "empty") or not isinstance(rules, list):
        a.gap("firewall", "Synapse workspace firewall rules are not fully collected")
        a.ports = ports or None
        return a
    public_rules, malformed = [], False
    for rule in rules:
        fields = rule.get("properties") if isinstance(rule, dict) else None
        try:
            start = ipaddress.IPv4Address(fields["startIpAddress"])
            end = ipaddress.IPv4Address(fields["endIpAddress"])
            if start > end:
                raise ValueError("reversed range")
            if start == end == ipaddress.IPv4Address("0.0.0.0"):
                public_rules.append({"name": rule.get("name"), "source": "any Azure tenant"})
            elif _azure_public_remainder(ipaddress.summarize_address_range(start, end), []):
                public_rules.append({"name": rule.get("name"), "source": str(start) + "-" + str(end)})
        except (TypeError, KeyError, ValueError):
            malformed = True
    if public_rules:
        a.step("firewall", "allow", public_rules=public_rules)
        a.ports = ports or None
    elif malformed:
        a.gap("firewall", "Synapse firewall IP range is unresolved")
        a.ports = ports or None
    else:
        a.step("firewall", "block", reason="no public-source workspace firewall rule")
        a.ports = {}
    a.notes.append("Workspace listener exposure does not establish SQL or Synapse authorization")
    return a


def _azure_disk_public_export(snapshot, inventory, resource):
    """Assess the public SAS export capability recorded by Compute GET/LIST."""
    props = _props(resource)
    a = Assessment(resource, "disk_export")
    a.authenticated = True
    public = props.get("publicNetworkAccess")
    policy = props.get("networkAccessPolicy")
    if policy == "DenyAll":
        a.step("export_policy", "block", network_access_policy=policy)
        a.ports = {}
    elif policy == "AllowPrivate":
        a.step("export_policy", "block", network_access_policy=policy,
               disk_access_id=props.get("diskAccessId"))
        a.ports = {}
    elif public == "Disabled":
        a.step("public_network_access", "block", public_network_access=public,
               network_access_policy=policy)
        a.ports = {}
    elif policy == "AllowAll" and public == "Enabled":
        a.step("export_policy", "allow", network_access_policy=policy,
               public_network_access=public)
        a.ports = pset("tcp", 443, 443)
        a.notes.append("Public SAS export is permitted; an issued SAS URI or recipient is not observable in Compute GET/LIST.")
    else:
        a.gap("policy", "Compute publicNetworkAccess/networkAccessPolicy is absent or unrecognized")
    return a


def _azure_kusto_cluster(snapshot, inventory, resource):
    """Assess the Data Explorer public endpoint and its recorded IP allow list."""
    props = _props(resource)
    a = Assessment(resource, "database")
    a.authenticated = True
    for field in ("uri", "dataIngestionUri"):
        if isinstance(props.get(field), str) and props[field]:
            a.addresses.append(props[field])
    public = props.get("publicNetworkAccess")
    if public == "Disabled":
        a.step("public_network_access", "block", public_network_access=public)
        a.ports = {}
        return a
    if public != "Enabled":
        a.gap("inventory", "Kusto publicNetworkAccess is absent or unrecognized")
        return a
    a.step("public_network_access", "allow", public_network_access=public)
    rules = props.get("allowedIpRangeList")
    if not isinstance(rules, list):
        a.gap("firewall", "Kusto allowedIpRangeList is not collected")
        return a
    if not rules:
        a.step("firewall", "allow", reason="empty allow list permits all public networks")
        a.ports = pset("tcp", 443, 443)
    else:
        public_rules, unresolved = [], []
        for value in rules:
            network = _cidr(value) if isinstance(value, str) else None
            if network is None:
                unresolved.append(value if isinstance(value, str) else "malformed entry")
            elif _azure_public_remainder([network], []):
                public_rules.append(value)
        if public_rules:
            a.step("firewall", "allow", public_ip_rules=public_rules)
            a.ports = pset("tcp", 443, 443)
            if unresolved:
                a.notes.append("Additional Kusto service-tag or malformed allow rules remain unresolved.")
        elif unresolved:
            a.gap("firewall", "Kusto service tag or malformed IP rule needs its effective public address set")
        else:
            a.step("firewall", "block", reason="no public-source IP rule")
            a.ports = {}
    if a.ports and not a.addresses:
        a.gap("inventory", "Kusto public URI is not collected")
    return a


def _azure_batch_account(snapshot, inventory, resource):
    """Assess both Batch account and node-management public endpoints."""
    props = _props(resource)
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True
    public = props.get("publicNetworkAccess")
    if public == "Disabled":
        a.step("public_network_access", "block", public_network_access=public)
        a.ports = {}
        return a
    if public != "Enabled":
        a.gap("inventory", "Batch publicNetworkAccess is absent, perimeter-secured, or unrecognized")
        return a
    a.step("public_network_access", "allow", public_network_access=public)
    profile = props.get("networkProfile")
    if profile is not None and not isinstance(profile, dict):
        a.gap("firewall", "Batch networkProfile is malformed")
        return a
    profile = profile or {}
    open_endpoints, unknown_endpoints, closed_endpoints = [], [], []
    for endpoint_field, access_field in (("accountEndpoint", "accountAccess"),
                                         ("nodeManagementEndpoint", "nodeManagementAccess")):
        endpoint = props.get(endpoint_field)
        if not isinstance(endpoint, str) or not endpoint:
            if endpoint_field == "accountEndpoint":
                unknown_endpoints.append(endpoint_field + " address absent")
            continue
        a.addresses.append(endpoint)
        access = profile.get(access_field)
        if access is None:
            # Batch defaults to all public networks when no endpoint rules are configured.
            open_endpoints.append({"endpoint": endpoint_field, "source": "all public networks"})
            continue
        if not isinstance(access, dict):
            unknown_endpoints.append(access_field + " malformed")
            continue
        action = access.get("defaultAction")
        if action == "Allow":
            open_endpoints.append({"endpoint": endpoint_field, "source": "all public networks"})
            continue
        if action != "Deny" or not isinstance(access.get("ipRules", []), list):
            unknown_endpoints.append(access_field + " action/rules unresolved")
            continue
        public_rules, malformed = [], False
        for rule in access.get("ipRules", []):
            value = rule.get("value") if isinstance(rule, dict) else None
            network = _cidr(value) if isinstance(value, str) else None
            if network is None or rule.get("action") != "Allow":
                malformed = True
            elif _azure_public_remainder([network], []):
                public_rules.append(value)
        if public_rules:
            open_endpoints.append({"endpoint": endpoint_field, "public_ip_rules": public_rules})
        elif malformed:
            unknown_endpoints.append(access_field + " IP rule unresolved")
        else:
            closed_endpoints.append(endpoint_field)
    if open_endpoints:
        a.step("firewall", "allow", open_endpoints=open_endpoints)
        a.ports = pset("tcp", 443, 443)
        if unknown_endpoints:
            a.notes.append("Other Batch endpoint paths unresolved: " + ", ".join(unknown_endpoints))
    elif unknown_endpoints or not closed_endpoints:
        a.gap("firewall", "Batch endpoint access unresolved: " + ", ".join(unknown_endpoints or ["no observed endpoint"]))
    else:
        a.step("firewall", "block", closed_endpoints=closed_endpoints)
        a.ports = {}
    return a


def _azure_ml_workspace(snapshot, inventory, resource):
    """Join the workspace gate, optional ACL and cached online scoring endpoints."""
    props = _props(resource)
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True
    def record_scoring_auth(endpoint):
        fields = endpoint.get("properties") if isinstance(endpoint, dict) else None
        mode = fields.get("authMode") if isinstance(fields, dict) else None
        if mode in ("Key", "AMLToken", "AADToken"):
            a.step("scoring_authentication", "conditional", online_endpoint=endpoint.get("id"),
                   auth_mode=mode, access_requirement={"Key": "endpoint key",
                                                  "AMLToken": "Azure ML token",
                                                  "AADToken": "Entra identity with score/action RBAC"}[mode])
            if mode != "AADToken":
                a.notes.append("Scoring credential or token recipients are not inventoried.")
        else:
            a.notes.append("Online endpoint scoring authentication mode is unavailable or unrecognized.")
    access = props.get("publicNetworkAccess")
    if access == "Disabled":
        a.step("public_network_access", "block", public_network_access=access)
        a.ports = {}
        coverage = (resource["data"].get("_coverage") or {}).get("onlineEndpoints") or {}
        endpoints = resource["data"].get("onlineEndpoints")
        if coverage.get("status") not in ("collected", "empty") or not isinstance(endpoints, list):
            a.gap("online_endpoint", "ML endpoint list incomplete despite disabled workspace gate")
            a.explicit = "UNKNOWN"
        elif any(not isinstance(row, dict) or not isinstance(row.get("properties"), dict)
                 or row["properties"].get("publicNetworkAccess") != "Disabled" for row in endpoints):
            a.gap("online_endpoint", "ML endpoint public gate could differ from disabled workspace gate")
            a.explicit = "UNKNOWN"
            for row in endpoints:
                if isinstance(row, dict) and isinstance(row.get("properties"), dict) and row["properties"].get("publicNetworkAccess") == "Enabled":
                    record_scoring_auth(row)
            acls = props.get("networkAcls")
            if isinstance(acls, dict) and acls.get("defaultAction") == "Deny":
                public_ips, _ = _azure_storage_public_ip_rules(acls)
                exposed = [row for row in endpoints if isinstance(row, dict)
                           and isinstance(row.get("properties"), dict)
                           and row["properties"].get("publicNetworkAccess") == "Enabled"]
                if public_ips and exposed:
                    for row in exposed:
                        uri = row["properties"].get("scoringUri")
                        if isinstance(uri, str) and uri:
                            a.addresses.append(uri)
                    a.step("online_endpoint_acl", "allow", online_endpoints=[row.get("id") for row in exposed],
                           public_ip_rules=public_ips)
                    a.notes.append("Azure ML selected-IP rules can continue to apply to online endpoints after workspace public access is disabled.")
                    a.ports = pset("tcp", 443, 443)
                    a.explicit = "FAIL"
        return a
    if access != "Enabled":
        a.gap("inventory", "ML workspace publicNetworkAccess is absent or unrecognized")
        return a
    a.step("public_network_access", "allow", public_network_access=access)
    coverage = (resource["data"].get("_coverage") or {}).get("onlineEndpoints") or {}
    endpoints = resource["data"].get("onlineEndpoints")
    if coverage.get("status") not in ("collected", "empty") or not isinstance(endpoints, list):
        a.gap("online_endpoint", "ML online endpoint child list is incomplete")
    else:
        for endpoint in endpoints:
            fields = endpoint.get("properties") if isinstance(endpoint, dict) else None
            if not isinstance(fields, dict):
                a.gap("online_endpoint", "ML online endpoint properties are malformed")
                continue
            if fields.get("publicNetworkAccess") == "Enabled":
                record_scoring_auth(endpoint)
                uri = fields.get("scoringUri")
                if isinstance(uri, str) and uri:
                    a.addresses.append(uri)
                else:
                    a.gap("online_endpoint", "public ML online endpoint scoring URI is unavailable")
                a.step("listener", "allow", online_endpoint=endpoint.get("id"), scoring_uri=uri)
            elif fields.get("publicNetworkAccess") != "Disabled":
                a.gap("online_endpoint", "ML online endpoint public access gate is unresolved")
    acls = props.get("networkAcls")
    if not isinstance(acls, dict):
        a.gap("firewall", "ML workspace selected-IP networkAcls are absent from the collected response")
        return a
    action = acls.get("defaultAction")
    if action == "Allow":
        a.step("firewall", "allow", default_action=action)
        a.ports = pset("tcp", 443, 443)
    elif action == "Deny":
        public_ips, malformed = _azure_storage_public_ip_rules(acls)
        if public_ips:
            a.step("firewall", "allow", public_ip_rules=public_ips)
            a.ports = pset("tcp", 443, 443)
        elif malformed:
            a.gap("firewall", "ML workspace selected-IP rule is malformed")
        else:
            a.step("firewall", "block", reason="no public-source IP rule")
            a.ports = {}
    else:
        a.gap("firewall", "ML workspace selected-IP default action is unresolved")
    return a


def _databricks_public_witness(rules, enabled, lists, denies=()):
    """Return a concrete global IPv4 source allowed by both collected layers."""
    try:
        allow = [ipaddress.ip_network(cidr) for item in lists
                 if enabled and item.get('enabled') is True and item.get('list_type') == 'ALLOW'
                 for cidr in item.get('ip_addresses', [])]
        block = [ipaddress.ip_network(cidr) for item in lists
                 if enabled and item.get('enabled') is True and item.get('list_type') == 'BLOCK'
                 for cidr in item.get('ip_addresses', [])]
        contexts = [(rule['origin'], [ipaddress.ip_network(cidr) for cidr in rule['ranges']]) for rule in rules]
        denied = [(rule['origin'], [ipaddress.ip_network(cidr) for cidr in rule['ranges']]) for rule in denies]
    except (TypeError, ValueError, KeyError, AttributeError):
        return None
    if any(network.version != 4 for network in
           (*allow, *block, *(n for _, nets in (*contexts, *denied) for n in nets))):
        return None
    # Every access decision is constant between the endpoints of its CIDRs.
    # Include Python's special-use IPv4 boundaries so is_global is constant
    # within each interval too (including its narrow public exceptions).
    boundaries = {0, 1 << 32}
    special = getattr(ipaddress._IPv4Constants, '_private_networks', ())
    special = (*special, getattr(ipaddress._IPv4Constants, '_public_network',
                                ipaddress.ip_network('100.64.0.0/10')),
               *getattr(ipaddress._IPv4Constants, '_private_networks_exceptions', ()))
    for network in (*allow, *block, *(n for _, nets in (*contexts, *denied) for n in nets), *special):
        boundaries.add(int(network.network_address))
        boundaries.add(int(network.broadcast_address) + 1)
    for value in sorted(boundaries):
        if value == 1 << 32:
            continue
        address = ipaddress.IPv4Address(value)
        if not address.is_global:
            continue
        if enabled and (any(address in network for network in block)
                        or allow and not any(address in network for network in allow)):
            continue
        if any(mode == 'all' or mode == 'include' and any(address in network for network in networks)
               or mode == 'exclude' and not any(address in network for network in networks)
               for mode, networks in denied):
            continue
        if any(mode == 'all' or mode == 'include' and any(address in network for network in networks)
               or mode == 'exclude' and not any(address in network for network in networks)
               for mode, networks in contexts):
            return str(address)
    return None


def _azure_databricks_workspace(snapshot, inventory, resource):
    """Use the ARM workspace public gate without guessing Databricks ingress policies."""
    props = _props(resource)
    a = Assessment(resource, "managed_endpoint")
    a.authenticated = True
    host = props.get("workspaceUrl")
    if isinstance(host, str) and host:
        a.addresses.append(host)
    access = props.get("publicNetworkAccess")
    if access == "Disabled":
        a.step("public_network_access", "block", public_network_access=access)
        a.ports = {}
    elif access == "Enabled":
        a.step("public_network_access", "allow", public_network_access=access)
        a.ports = pset("tcp", 443, 443)
        ingress = [row['data'] for row in inventory.items('databricks_workspace_ingress_policy')
                   if str(native_id(row)).casefold() == str(native_id(resource)).casefold()]
        restricted_rules = None
        if len(ingress) != 1 or ingress[0].get('policyStatus') != 'collected':
            a.gap('policy', 'Databricks workspace context-based ingress policy unavailable')
        elif (ingress[0].get('restriction_mode') == 'RESTRICTED_ACCESS'
              and ingress[0].get('allow_rule_count') == 0):
            a.step('workspace_context_ingress', 'block', restriction_mode='RESTRICTED_ACCESS', allow_rule_count=0)
            a.ports = {}
        elif ingress[0].get('restriction_mode') == 'FULL_ACCESS':
            a.step('workspace_context_ingress', 'allow', restriction_mode='FULL_ACCESS')
        elif ingress[0].get('restriction_mode') == 'RESTRICTED_ACCESS':
            restricted_rules = ingress[0]
        else:
            a.gap('policy', 'Databricks context ingress rules require identity, source and destination matching')
        policies = [row for row in inventory.items('databricks_workspace_ip_policy')
                    if str(native_id(row)).casefold() == str(native_id(resource)).casefold()]
        ip_policy = None
        if len(policies) != 1 or policies[0]['data'].get('policyStatus') != 'collected':
            a.gap('policy', 'Databricks workspace IP access lists unavailable or uncollected')
        else:
            policy = policies[0]['data']
            enabled = policy.get('ipAccessListsEnabled')
            lists = policy.get('ipAccessLists')
            if (type(enabled) is not bool or not isinstance(lists, list)
                    or any(not isinstance(item, dict) or type(item.get('enabled')) is not bool
                           or item.get('list_type') not in ('ALLOW', 'BLOCK')
                           or not isinstance(item.get('ip_addresses'), list)
                           or any((network := _cidr(cidr)) is None or network.version != 4
                                  for cidr in item['ip_addresses']) for item in lists)):
                a.gap('policy', 'Databricks workspace IP access lists malformed')
            else:
                active = [item for item in lists if isinstance(item, dict) and item.get('enabled') is True]
                ip_policy = (enabled, active)
                allow = [item for item in active if item.get('list_type') == 'ALLOW']
                block = [item for item in active if item.get('list_type') == 'BLOCK']
                if enabled and any('0.0.0.0/0' in item.get('ip_addresses', []) for item in block):
                    a.step('workspace_ip_access_lists', 'block', active_allow_lists=len(allow), active_block_lists=len(block))
                    a.ports = {}
                elif enabled and allow and all(
                        isinstance(item.get('ip_addresses'), list) and all(
                            (network := _cidr(cidr)) is not None and network.version == 4 and any(
                                network.subnet_of(ipaddress.ip_network(private)) for private in
                                ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
                            for cidr in item['ip_addresses']) for item in allow):
                    a.step('workspace_ip_access_lists', 'block', active_allow_lists=len(allow), active_block_lists=len(block))
                    a.ports = {}
                else:
                    witness = _databricks_public_witness([{'origin': 'all', 'ranges': []}], enabled, active)
                    if witness:
                        a.step('workspace_ip_access_lists', 'allow', enabled=enabled,
                               active_allow_lists=len(allow), active_block_lists=len(block), public_source_ip=witness)
                    else:
                        a.gap('policy', 'Databricks IP lists do not establish a surviving public source')
        if restricted_rules is not None:
            found = False
            for target, rule_key, deny_key, ignored_key in (
                    ('workspace_ui', 'public_ui_rules', 'public_ui_denies', 'ui_ignored_deny_count'),
                    ('workspace_api', 'public_api_rules', 'public_api_denies', 'api_ignored_deny_count')):
                rules = restricted_rules.get(rule_key)
                denies = restricted_rules.get(deny_key)
                ignored = restricted_rules.get(ignored_key)
                if (ip_policy is None or not isinstance(rules, list) or not isinstance(denies, list)
                        or type(ignored) is not int
                        or restricted_rules.get('deny_rule_count') != len(denies) + ignored):
                    continue
                for rule in rules:
                    for principal in (('users', 'service_principals') if target == 'workspace_api' else ('users',)):
                        if rule.get('identity') not in ('both', principal):
                            continue
                        applicable = [deny for deny in denies if deny.get('identity') in ('both', principal)]
                        witness = _databricks_public_witness([rule], *ip_policy, applicable)
                        if witness:
                            detail = {'api_scope': rule['scope']} if target == 'workspace_api' else {}
                            a.step('workspace_context_ingress', 'allow', restriction_mode='RESTRICTED_ACCESS',
                                   destination=target, public_source_ip=witness, principal_type=principal, **detail)
                            found = True
                            break
                    if found:
                        break
                if found:
                    break
            if not found:
                a.gap('policy', 'Databricks context ingress rules require identity, source and destination matching')
        if not a.addresses:
            a.gap("inventory", "Databricks workspaceUrl is unavailable")
    else:
        a.gap("inventory", "Databricks publicNetworkAccess is absent or unrecognized")
    return a


def _azure_compute_gallery(snapshot, inventory, resource):
    """Assess the collected gallery-wide community/direct-sharing policy."""
    props = _props(resource)
    a = Assessment(resource, "gallery_share")
    profile = props.get("sharingProfile")
    if not isinstance(profile, dict):
        a.gap("policy", "Compute Gallery sharingProfile is not collected")
        return a
    permission = profile.get("permissions")
    if permission == "Private":
        a.step("sharing_policy", "block", permission=permission)
        a.ports = {}
    elif permission == "Community":
        status = props.get("sharingStatus") if isinstance(props.get("sharingStatus"), dict) else {}
        a.step("sharing_policy", "allow", permission=permission,
               sharing_state=status.get("aggregatedState"))
        a.explicit = "FAIL"
        a.notes.append("Gallery policy permits community sharing; published image versions are assessed from child inventory when available.")
    elif permission == "Groups":
        groups = profile.get("groups")
        owner = str(resource.get("scope", "")).lower().removeprefix("/subscriptions/")
        if not owner or not isinstance(groups, list):
            a.gap("authorization", "gallery direct-sharing recipient list or owner subscription is unavailable")
            return a
        other_subscriptions, tenant_recipients, malformed = [], [], False
        for group in groups:
            ids = group.get("ids") if isinstance(group, dict) else None
            group_type = group.get("type") if isinstance(group, dict) else None
            if group_type not in ("Subscriptions", "AADTenants") or not isinstance(ids, list) or any(
                    not isinstance(value, str) or not value.strip() for value in ids):
                malformed = True
                continue
            if group_type == "Subscriptions":
                other_subscriptions.extend(value for value in ids if value.lower() != owner)
            else:
                tenant_recipients.extend(ids)
        provenance = resource["data"].get("_provenance") or {}
        metadata = snapshot.get("metadata") or {}
        owner_tenant = (provenance.get("tenant_id") if provenance.get("tenant_verified") is True
                        else metadata.get("tenant_id") if metadata.get("tenant_verified") is True else None)
        other_tenants = ([value for value in tenant_recipients if value.lower() != owner_tenant.lower()]
                         if isinstance(owner_tenant, str) and owner_tenant else [])
        a.external_ids = sorted(set(other_subscriptions + other_tenants))
        if other_subscriptions or other_tenants:
            a.step("sharing_policy", "allow", permission=permission,
                   recipient_subscriptions=sorted(set(other_subscriptions)),
                   recipient_tenants=sorted(set(other_tenants)))
            a.explicit = "FAIL"
            a.notes.append("Direct sharing targets other subscriptions or tenants; published image versions are assessed from child inventory when available.")
        elif (tenant_recipients and not owner_tenant) or malformed:
            a.gap("authorization", "gallery tenant recipient ownership or malformed sharing group is unresolved")
        else:
            a.step("sharing_policy", "block", reason="no other subscription or tenant recipient")
            a.ports = {}
    else:
        a.gap("policy", "Compute Gallery sharing permission is absent or unrecognized")
    if permission in ("Community", "Groups"):
        coverage = (resource["data"].get("_coverage") or {}).get("images") or {}
        images = resource["data"].get("images")
        if coverage.get("status") not in ("collected", "empty") or not isinstance(images, list):
            a.notes.append("Gallery image-definition inventory is incomplete; publication is unresolved.")
        else:
            versions, complete = [], True
            for image in images:
                image_coverage = ((image.get("_coverage") or {}).get("versions") or {}) if isinstance(image, dict) else {}
                rows = image.get("versions") if isinstance(image, dict) else None
                if image_coverage.get("status") not in ("collected", "empty") or not isinstance(rows, list):
                    complete = False
                elif any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows):
                    complete = False
                else:
                    versions.extend(row["id"] for row in rows)
            if versions:
                a.notes.append("Observed gallery image versions: " + ", ".join(sorted(versions)))
            if not complete:
                a.notes.append("Some gallery image-version inventories are incomplete; publication is unresolved.")
            elif not versions:
                a.notes.append("No gallery image versions were observed in the complete child inventory.")
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
    if access not in (None, "Enabled") or network not in (None, "None", "External"):
        a.gap("inventory", "API Management public access or virtual network mode is unresolved")
        return a
    primary_enabled = props.get("disableGateway") is not True
    locations = props.get("additionalLocations") or []
    if not isinstance(locations, list):
        a.gap("inventory", "API Management additional locations are malformed")
        locations = []
    regional = []
    for location in locations:
        if not isinstance(location, dict) or location.get("disableGateway") not in (None, False, True):
            a.gap("listener", "API Management regional gateway state is malformed")
            continue
        if location.get("disableGateway") is not True:
            regional.append(location)
    if not primary_enabled and not regional and not a.unresolved:
        a.step("listener", "block", reason="primary and regional managed gateways disabled")
        a.ports = {}
        return a
    if primary_enabled and props.get("disableGateway") is not False:
        a.gap("listener", "managed gateway enable state was not collected")
    if primary_enabled:
        endpoint = props.get("gatewayUrl")
        if isinstance(endpoint, str) and endpoint.startswith("https://"):
            a.addresses.append(endpoint)
        else:
            a.gap("inventory", "API Management gateway URL was not collected")
    for location in regional:
        endpoint = location.get("gatewayRegionalUrl")
        if isinstance(endpoint, str) and endpoint.startswith("https://"):
            a.addresses.append(endpoint)
        else:
            a.gap("inventory", "API Management enabled regional gateway URL was not collected")
    a.step("public_network_access", "allow", value=access or "Enabled (service default)",
           virtual_network_type=network or "None (service default)")
    ports = pset("tcp", 443, 443)
    if network == "External":
        regional_only = not primary_enabled and len(regional) == 1
        if regional and not regional_only:
            a.gap("nsg", "External VNet regional gateway subnet NSG paths are not resolved")
        if not primary_enabled and not regional_only:
            return a
        gateway_location = regional[0] if regional_only else props
        sku = ((gateway_location.get("sku") or resource["data"].get("sku") or {}).get("name"))
        if sku not in ("Developer", "Premium"):
            a.gap("nsg", "External VNet NSG semantics require a recorded classic Developer or Premium SKU")
        network_config = gateway_location.get("virtualNetworkConfiguration")
        subnet_id = network_config.get("subnetResourceId") if isinstance(network_config, dict) else None
        subnet, _ = _azure_subnet(inventory, subnet_id)
        if subnet is None:
            a.gap("nsg", "External VNet gateway subnet is not collected", "Microsoft.Network/virtualNetworks/subnets")
        elif sku in ("Developer", "Premium"):
            nsg_id = ((_props(subnet).get("networkSecurityGroup") or {}).get("id"))
            nsg = inventory.get("nsg", nsg_id) if nsg_id else None
            # The API does not expose the gateway's private DIP. A rule aimed
            # at a specific destination IP cannot be resolved from the subnet.
            specific_destination = bool(nsg and any(
                (rule.get("properties") or {}).get("access") == "Allow" and (
                    bool((rule.get("properties") or {}).get("destinationApplicationSecurityGroups")) or any(
                    value not in ("*", "Any", "VirtualNetwork", "0.0.0.0/0", "::/0")
                    for value in as_list((rule.get("properties") or {}).get("destinationAddressPrefixes")) +
                                 as_list((rule.get("properties") or {}).get("destinationAddressPrefix"))))
                for rule in as_list(_props(nsg).get("securityRules")) if isinstance(rule, dict)))
            ports = _azure_nsg_path(inventory, a, None, subnet_id, ports,
                                    sku="standard", where="API Management gateway subnet")
            if specific_destination:
                a.blocked_by = None
                a.gap("nsg", "destination-specific NSG allow needs the gateway's private DIP")
            if not empty(ports) and (_props(subnet).get("routeTable") or {}).get("id"):
                a.gap("inventory", "External VNet gateway return route through the associated route table is unresolved")
        if regional and not regional_only and empty(ports):
            a.blocked_by = None
    a.ports = ports
    a.notes.append("Gateway listener exposure does not establish anonymous API access or a healthy backend")
    return a


def _azure_redis(snapshot, inventory, resource):
    props = resource["data"].get("properties") or {}
    a = Assessment(resource, "database")
    subnet_id = props.get("subnetId")
    if isinstance(subnet_id, str) and re.search(r"/subnets/[^/]+$", subnet_id, re.IGNORECASE):
        # Premium VNet injection assigns a private address to the cache. The
        # publicNetworkAccess flag describes the separate Private Link mode;
        # it cannot make an injected cache directly internet addressable.
        a.step("network", "block", reason="VNet-injected Redis has no public listener",
               subnet_id=subnet_id)
        a.ports = {}
        return a
    if subnet_id is not None:
        a.gap("inventory", "Redis subnetId is malformed; VNet injection cannot be established")
        return a
    access = props.get("publicNetworkAccess")
    if access == "Disabled":
        a.step("public_network_access", "block", value=access)
        a.ports = {}
        return a
    if access != "Enabled":
        a.gap("inventory", "Redis public network access state is not explicit")
        return a
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


def _azure_redis_enterprise(snapshot, inventory, resource):
    """Assess Redis Enterprise / Azure Managed Redis database listeners."""
    props = _props(resource)
    a = Assessment(resource, "database")
    a.authenticated = True
    access = props.get("publicNetworkAccess")
    if access == "Disabled":
        a.step("public_network_access", "block", value=access)
        a.ports = {}
        return a
    if access != "Enabled":
        a.gap("inventory", "Redis Enterprise publicNetworkAccess is absent or unrecognized")
        return a
    a.step("public_network_access", "allow", value=access)
    firewall = props.get("firewallRules")
    if not isinstance(firewall, list):
        a.gap("firewall", "Redis Enterprise cluster firewall rules are not observed")
    elif not firewall:
        a.step("firewall", "allow", reason="no configured cluster firewall rules")
    else:
        public, malformed = False, False
        for rule in firewall:
            prefix = rule.get("sourceAddressPrefix") if isinstance(rule, dict) else None
            network = _cidr(prefix) if isinstance(prefix, str) else None
            if network is None:
                malformed = True
            else:
                public |= _azure_public_remainder([network], [])
        if public:
            a.step("firewall", "allow", reason="rule admits a public source")
        elif malformed:
            a.gap("firewall", "Redis Enterprise cluster firewall rule has an unresolved source")
        else:
            a.step("firewall", "block", reason="no rule admits a public source")
            a.ports = {}
            return a
    hostname = props.get("hostName")
    if isinstance(hostname, str) and hostname:
        a.addresses.append(hostname)
    else:
        a.gap("inventory", "Redis Enterprise public hostname is unavailable")
    cluster_id = str(native_id(resource)).casefold()
    status = inventory.state("redis_enterprise_database", resource["scope"])
    rows = [row for row in inventory.items("redis_enterprise_database")
            if str(native_id(row)).casefold().startswith(cluster_id + "/databases/")]
    ports, malformed = {}, False
    for row in rows:
        fields = _props(row)
        port = fields.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            malformed = True
            continue
        ports = union(ports, pset("tcp", port, port))
        a.step("listener", "allow", database_id=native_id(row), port=port,
               client_protocol=fields.get("clientProtocol"))
    if status not in ("collected", "empty") or malformed:
        a.gap("inventory", "Redis Enterprise database child inventory or listener port is incomplete")
    if ports:
        a.ports = ports
        if not any(gap["layer"] == "firewall" for gap in a.unresolved):
            a.explicit = "FAIL"
    elif status in ("collected", "empty") and not malformed:
        a.step("listener", "block", reason="no database listener in complete child inventory")
        a.ports = {}
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


def _k8s_source_range_decision(ranges):
    """Do not treat an unparseable controller annotation as a private range."""
    if any(_cidr(value) is None and not _internet(value) for value in ranges):
        return "unknown"
    return "public" if any(_k8s_public_source(value) for value in ranges) else "private"


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
        range_decision = _k8s_source_range_decision(ranges) if ranges else "public"
        if range_decision == "unknown":
            a.step("source_ranges", "unknown", invalid_source_ranges=[r for r in ranges if _cidr(r) is None and not _internet(r)])
            a.ports = _k8s_ports(spec)
            a.gap("inventory", "controller treatment of invalid source range is not observed")
            return external_path()
        if range_decision == "private":
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
    range_decision = _k8s_source_range_decision(ranges) if ranges else "public"
    if range_decision == "unknown":
        a.step("source_ranges", "unknown", invalid_source_ranges=[r for r in ranges if _cidr(r) is None and not _internet(r)])
        a.ports = ports
        a.gap("inventory", "controller treatment of invalid source range is not observed")
        return a
    if range_decision == "private":
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

AWS_TYPES = ["iam_role", "vpc", "subnet", "route_table", "network_acl", "security_group", "network_interface", "instance", "internet_gateway", "vpc_peering", "transit_gateway_attachment", "transit_gateway_route_table", "vpn_connection", "client_vpn_endpoint", "client_vpn_routing", "vpc_endpoint_service",
             "load_balancer", "classic_load_balancer", "rds_instance", "rds_snapshot", "rds_cluster_snapshot", "redshift_cluster",
             "opensearch_domain", "eks_cluster", "lambda_function", "lambda_alias", "lambda_version", "rest_api", "apigateway_domain_name", "http_api", "apigatewayv2_domain_name", "bucket", "s3_account_public_access_block",
             "organization_account", "aws_account_configuration", "ec2_image", "ebs_snapshot", "ram_resource_share", "kms_key", "kms_grant", "secret", "sqs_queue", "sns_topic", "sns_topic_subscription", "ecr_registry", "ecr_repository", "ecr_public_repository", "log_subscription_filter", "log_account_subscription_policy", "log_destination", "cloudfront_distribution", "globalaccelerator_accelerator", "globalaccelerator_listener", "app_runner_service", "amplify_app"]
GCP_TYPES = ["network", "firewall", "firewall_policy", "instance", "instance_effective_firewall", "forwarding_rule", "target_proxy", "url_map", "backend_service", "backend_bucket", "security_policy",
             "cloudrun_service", "cloudrun_instance", "function", "sql_instance", "alloydb_instance", "gke_cluster", "gke_exposure_service", "gke_exposure_ingress", "gke_exposure_pod", "gke_exposure_node", "gke_exposure_gateway", "gke_exposure_gatewayclass", "gke_exposure_httproute", "gke_exposure_endpointslice", "gke_exposure_multiclusteringress", "network_endpoint_group", "bucket", "bucket_acl", "object_acl", "managed_folder", "bucket_effective_iam", "org_policy_effective", "bigquery_dataset", "bigquery_table", "bigquery_routine_metadata", "firebase_rules_release", "firebase_database_rules", "vpn_gateway", "vpn_tunnel",
             "project", "iam_policy", "iam_role", "service_account", "service_usage", "group", "group_membership", "default_object_acl", "workload_identity_provider",
             "cloud_ftp_server", "looker_instance", "blockchain_node", "data_fusion_instance", "dataproc_cluster", "workbench_instance", "vertex_index_endpoint",
             "vertex_feature_online_store", "app_engine_application", "api_gateway", "composer_environment", "firebase_apphosting_endpoint",
             "media_cdn_service", "target_pool", "target_instance",
             "workstation", "workstation_cluster", "beyondcorp_connection", "contact_center", "oracle_goldengate_deployment", "vertex_agent_sandbox", "tpu_node",
             "vmware_external_address", "vmware_external_access_rule", "vmware_network_policy", "vmware_private_cloud"]
AZURE_TYPES = ["vnet", "subnet", "nsg", "service_tag", "nic", "vm", "public_ip", "load_balancer", "application_gateway", "app_service", "app_service_slot", "app_service_plan", "app_service_environment",
               "app_service_config", "aks_cluster", "storage_account", "storage_container", "sql_server", "sql_firewall_rule", "managed_identity_federated_credential",
               "container_group", "container_app", "container_app_environment", "container_app_runtime", "azure_firewall", "firewall_policy", "ip_group", "frontdoor_and_cdn_endpoint", "api_management", "redis_cache", "redis_enterprise_cluster", "redis_enterprise_database", "signalr_service", "web_pubsub", "synapse_workspace", "disk", "snapshot", "kusto_cluster", "batch_account", "ml_workspace", "databricks_workspace", "compute_gallery", *_AZURE_MANAGED_ENDPOINTS]
K8S_TYPES = ["service", "ingress", "node", "pod", "gateway", "endpoint", "endpoints", "endpointslice",
             "istio_service_entry", "istio_workload_entry", "admission_configuration", "configsync_rootsync",
             "persistentvolume", "kcc_iampolicy", "kcc_iampartialpolicy", "securitycontextconstraint",
             "component_configuration", *sorted(K8S_ROUTE_TYPES)]
EXPOSURE_TYPES = {"aws": AWS_TYPES, "gcp": GCP_TYPES, "azure": AZURE_TYPES, "k8s": K8S_TYPES}
EVALUATED = {"aws": {"iam_role", "instance", "network_interface", "load_balancer", "classic_load_balancer", "rds_instance", "redshift_cluster",
                     "opensearch_domain", "eks_cluster", "lambda_function", "lambda_alias", "lambda_version", "rest_api", "http_api", "rds_snapshot", "rds_cluster_snapshot", "bucket",
                     "ec2_image", "ebs_snapshot", "ram_resource_share", "kms_key", "kms_grant", "secret", "sqs_queue", "sns_topic", "sns_topic_subscription", "ecr_registry", "ecr_repository", "ecr_public_repository", "log_subscription_filter", "log_account_subscription_policy", "log_destination", "vpc_peering", "transit_gateway_attachment", "vpn_connection", "client_vpn_endpoint", "vpc_endpoint_service", "cloudfront_distribution", "globalaccelerator_accelerator", "app_runner_service", "amplify_app"},
             "gcp": {"network", "instance", "forwarding_rule", "cloudrun_service", "cloudrun_instance", "function", "sql_instance", "alloydb_instance", "gke_cluster", "gke_exposure_service", "gke_exposure_ingress", "gke_exposure_pod", "gke_exposure_node", "gke_exposure_gateway", "gke_exposure_httproute", "gke_exposure_endpointslice", "gke_exposure_multiclusteringress", "bucket", "bigquery_dataset", "firebase_rules_release", "firebase_database_rules", "vpn_gateway", "vpn_tunnel",
                     "cloud_ftp_server", "looker_instance", "blockchain_node", "data_fusion_instance", "dataproc_cluster", "workbench_instance", "vertex_index_endpoint",
                     "vertex_feature_online_store", "app_engine_application", "api_gateway", "composer_environment", "firebase_apphosting_endpoint",
                     "media_cdn_service",
                     "workstation", "beyondcorp_connection", "contact_center", "oracle_goldengate_deployment", "vertex_agent_sandbox", "tpu_node",
                     "vmware_external_address"},
             "azure": {"nic", "load_balancer", "application_gateway", "app_service", "app_service_slot", "aks_cluster", "storage_account", "storage_container", "sql_server",
                       "container_group", "container_app", "azure_firewall", "frontdoor_and_cdn_endpoint", "api_management", "redis_cache", "redis_enterprise_cluster", "signalr_service", "web_pubsub", "synapse_workspace", "disk", "snapshot", "kusto_cluster", "batch_account", "ml_workspace", "databricks_workspace", "compute_gallery", *_AZURE_MANAGED_ENDPOINTS},
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
        "aws": {"iam_role": _aws_role_foreign_assumption, "instance": _aws_instance, "network_interface": _aws_eni, "load_balancer": _aws_elbv2, "classic_load_balancer": _aws_classic,
                "rds_instance": _aws_rds, "redshift_cluster": _aws_redshift, "opensearch_domain": _aws_opensearch, "eks_cluster": _aws_eks,
                "lambda_function": _aws_lambda_url, "lambda_alias": _aws_lambda_url,
                "lambda_version": _aws_lambda_direct_invoke,
                "lambda_layer_version": _aws_lambda_layer_share,
                "rest_api": _aws_rest_api, "http_api": _aws_http_api, "bucket": _aws_bucket,
                "rds_snapshot": lambda s, i, r: _aws_snapshot_share(s, i, r, ("DBSnapshotAttributesResult", "DBSnapshotAttributes"), "snapshot"),
                "rds_cluster_snapshot": lambda s, i, r: _aws_snapshot_share(s, i, r, ("DBClusterSnapshotAttributesResult", "DBClusterSnapshotAttributes"), "cluster snapshot"),
                "redshift_snapshot": _aws_redshift_snapshot_share,
                "redshiftserverless_snapshot": _aws_redshift_serverless_snapshot_share,
                "docdb_cluster_snapshot": _aws_cluster_snapshot_share,
                "neptune_cluster_snapshot": _aws_cluster_snapshot_share,
                "ec2_image": lambda s, i, r: _aws_ec2_share(s, i, r, "LaunchPermissions", "LaunchPermissions", "DescribeImageAttribute"),
                "ebs_snapshot": lambda s, i, r: _aws_ec2_share(s, i, r, "CreateVolumePermissions", "CreateVolumePermissions", "DescribeSnapshotAttribute"),
                "ram_resource_share": _aws_ram_share, "vpc_peering": _aws_vpc_peering,
                "transit_gateway_attachment": _aws_tgw_foreign_attachment, "vpn_connection": _aws_vpn_connection,
                "client_vpn_endpoint": _aws_client_vpn_endpoint,
                "vpc_endpoint_service": _aws_vpc_endpoint_service,
                "ecr_registry": _aws_ecr_registry_replication,
                "aws_resource_policy": _aws_generic_resource_policy_grant,
                "ecr_repository": _aws_ecr_repository_share,
                "secret": _aws_secret_foreign_read,
                "sqs_queue": _aws_sqs_foreign_receive,
                "sns_topic_subscription": _aws_sns_foreign_subscription,
                "sns_topic": _aws_sns_subscribe_grant,
                "kms_key": _aws_kms_foreign_decrypt,
                "kms_grant": _aws_kms_foreign_grant,
                "ecr_public_repository": _aws_ecr_public_repository,
                "log_subscription_filter": _aws_log_subscription_export,
                "log_account_subscription_policy": _aws_log_subscription_export,
                "log_destination": _aws_log_destination_policy_grant,
                "cloudfront_distribution": _aws_cloudfront, "globalaccelerator_accelerator": _aws_global_accelerator,
                "app_runner_service": _aws_app_runner, "amplify_app": _aws_amplify},
        "gcp": {"network": _gcp_network_peering, "instance": _gcp_instance, "forwarding_rule": _gcp_forwarding_rule, "cloudrun_service": _gcp_serverless, "cloudrun_instance": _gcp_cloudrun_instance, "function": _gcp_serverless,
                "sql_instance": _gcp_sql, "alloydb_instance": _gcp_alloydb, "gke_cluster": _gcp_gke,
                "gke_exposure_service": _gcp_gke_exposure_service,
                "gke_exposure_ingress": _gcp_gke_exposure_ingress,
                "gke_exposure_pod": _gcp_gke_exposure_pod,
                "gke_exposure_node": _gcp_gke_exposure_node,
                "gke_exposure_gateway": _gcp_gke_exposure_gateway,
                "gke_exposure_httproute": _gcp_gke_exposure_httproute, "gke_exposure_endpointslice": _gcp_gke_exposure_endpointslice, "gke_exposure_multiclusteringress": _gcp_gke_exposure_multiclusteringress, "bucket": _gcp_bucket,
                "bigquery_dataset": _gcp_bigquery_dataset, "firebase_rules_release": _gcp_firebase_rules,
                "firebase_database_rules": _gcp_firebase_rules,
                "vpn_gateway": _gcp_vpn_gateway, "vpn_tunnel": _gcp_vpn_tunnel,
                "cloud_ftp_server": _gcp_ftp, "looker_instance": _gcp_looker, "blockchain_node": _gcp_blockchain_node,
                "data_fusion_instance": _gcp_data_fusion, "dataproc_cluster": _gcp_dataproc_cluster,
                "workbench_instance": _gcp_workbench_instance,
                "vertex_index_endpoint": _gcp_vertex_index,
                "vertex_feature_online_store": _gcp_vertex_feature_store, "app_engine_application": _gcp_app_engine,
                "api_gateway": _gcp_api_gateway, "composer_environment": _gcp_composer_environment,
                "firebase_apphosting_endpoint": _gcp_firebase_apphosting,
                "media_cdn_service": _gcp_media_cdn,
                "workstation": _gcp_workstation, "beyondcorp_connection": _gcp_beyondcorp_connection,
                "contact_center": _gcp_contact_center, "oracle_goldengate_deployment": _gcp_oracle_goldengate,
                "vertex_agent_sandbox": _gcp_vertex_sandbox,
                "tpu_node": _gcp_tpu_node,
                "vmware_external_address": _gcp_vmware_address},
        "azure": {"nic": lambda s, i, r: _azure_nic(s, i, r, extra["public_ips"]), "load_balancer": _azure_lb, "application_gateway": _azure_appgw,
                  "app_service": lambda s, i, r: _azure_app_service(s, i, r, extra["configs"]), "aks_cluster": _azure_aks,
                  "app_service_slot": _azure_app_service_slot,
                  "storage_account": _azure_storage, "storage_container": _azure_storage_container,
                  "sql_server": lambda s, i, r: _azure_sql(s, i, r, extra["rules"]),
                  "container_group": _azure_container_group,
                  "container_app": _azure_container_app,
                  "azure_firewall": _azure_firewall,
                  "frontdoor_and_cdn_endpoint": _azure_public_edge,
                  "api_management": _azure_api_management,
                  "redis_cache": _azure_redis,
                  "redis_enterprise_cluster": _azure_redis_enterprise,
                  "signalr_service": _azure_realtime_endpoint,
                  "web_pubsub": _azure_realtime_endpoint,
                  "synapse_workspace": _azure_synapse_workspace,
                  "disk": _azure_disk_public_export,
                  "snapshot": _azure_disk_public_export,
                  "kusto_cluster": _azure_kusto_cluster,
                  "batch_account": _azure_batch_account,
                  "ml_workspace": _azure_ml_workspace,
                  "databricks_workspace": _azure_databricks_workspace,
                  "compute_gallery": _azure_compute_gallery,
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
        if provider == "aws" and resource["type"] in ("lambda_function", "lambda_alias"):
            direct = _aws_lambda_direct_invoke(snapshot, inventory, resource)
            if direct is not None:
                output.append(direct)
        if provider == "aws" and resource["type"] == "client_vpn_endpoint":
            authorization = _aws_client_vpn_all_clients_authorization(snapshot, inventory, resource)
            if authorization is not None:
                output.append(authorization)
        if provider == "aws" and resource["type"] == "ecr_registry":
            pull = _aws_ecr_registry_policy_pull(snapshot, inventory, resource)
            if pull is not None:
                output.append(pull)
            template = _aws_ecr_template_pull(snapshot, inventory, resource)
            if template is not None:
                output.append(template)
    if context is not None and context["snapshot"] is snapshot:
        context["derivations"][key] = output
    return output


def _title(assessment, status):
    if assessment.kind == "vpn_client_authorization":
        return "Client VPN authorizes all clients to destination network" if status == "FAIL" else "Client VPN authorization unresolved"
    if assessment.kind == "external_generic_policy_grant":
        return "Resource policy grants foreign account access" if status == "FAIL" else "Foreign resource-policy grant unresolved"
    if assessment.kind == "external_cluster_snapshot_share":
        service = "DocumentDB" if assessment.resource["type"] == "docdb_cluster_snapshot" else "Neptune"
        return (service + " snapshot grants public restore access" if "*" in assessment.external_ids else
                service + " snapshot grants foreign restore access") if status == "FAIL" else service + " snapshot sharing unresolved"
    if assessment.kind == "external_redshift_serverless_snapshot_share":
        return "Redshift Serverless snapshot grants foreign restore access" if status == "FAIL" else "Redshift Serverless snapshot sharing unresolved"
    if assessment.kind == "external_redshift_snapshot_share":
        return "Redshift snapshot grants foreign restore access" if status == "FAIL" else "Redshift snapshot sharing unresolved"
    if assessment.kind == "external_registry_template_pull":
        return "ECR creation template grants future foreign image pulls" if status == "FAIL" else "ECR creation template pull grant unresolved"
    if assessment.kind == "external_registry_policy_pull":
        return "ECR registry policy permits foreign image pulls" if status == "FAIL" else "ECR registry pull grant unresolved"
    if assessment.kind == "external_layer_share":
        return "Lambda layer version shared with foreign principals" if status == "FAIL" else "Lambda layer sharing unresolved"
    if assessment.kind == "external_lambda_invoke":
        return "Lambda policy permits foreign direct invocation" if status == "FAIL" else "Foreign Lambda invocation unresolved"
    if assessment.kind == "external_kms_grant":
        return "KMS grant permits foreign Decrypt" if status == "FAIL" else "Foreign KMS grant unresolved" if status == "UNKNOWN" else "KMS grant key cannot currently decrypt"
    if assessment.kind == "external_kms_decrypt_grant":
        return "KMS key policy permits foreign decrypt" if status == "FAIL" else "Foreign KMS decrypt unresolved" if status == "UNKNOWN" else "KMS key cannot currently decrypt"
    if assessment.kind == "external_topic_subscribe_grant":
        if status == "FAIL" and "*" in assessment.external_ids:
            return "SNS topic permits public subscription requests"
        return "SNS topic permits foreign subscription requests" if status == "FAIL" else "SNS subscribe grant unresolved"
    if assessment.kind == "external_topic_subscription":
        return "SNS topic has a foreign-owned subscription" if status == "FAIL" else "Foreign SNS subscription unresolved"
    if assessment.kind == "external_queue_receive":
        return "SQS queue grants foreign message receive" if status == "FAIL" else "Foreign SQS receive unresolved" if status == "UNKNOWN" else "Managed key blocks foreign SQS receive"
    if assessment.kind == "external_secret_grant":
        return "Secret policy grants foreign read" if status == "FAIL" else "Foreign secret read unresolved" if status == "UNKNOWN" else "Default key blocks foreign secret read"
    if assessment.kind == "external_registry_share":
        return "ECR repository grants foreign image pull" if status == "FAIL" else "ECR repository sharing unresolved"
    if assessment.kind == "external_log_stream":
        return "Log subscription targets external account" if status == "FAIL" else "Log subscription destination unresolved"
    if assessment.kind == "public_registry":
        return "ECR Public repository is publicly readable" if status == "FAIL" else "ECR Public repository identity unresolved"
    if assessment.kind == "external_network":
        if assessment.resource["type"] == "transit_gateway_attachment":
            return ("Local route to foreign Transit Gateway attachment" if status == "FAIL" else
                    "Foreign Transit Gateway attachment route unresolved")
        return ("Active route to external VPC peer" if status == "FAIL" else
                "No active route to external VPC peer" if status == "PASS" else
                "External VPC peering route unresolved")
    if assessment.kind == "cross_project_peering":
        return "Cross-project VPC peering path unresolved"
    if assessment.kind == "vpn_peer":
        cross_project = any(step.get("peer_project") for step in assessment.path if step.get("layer") == "vpn_peer")
        return (("Established Cloud VPN tunnel to another GCP project" if cross_project else
                 "Established Cloud VPN tunnel to configured external peer") if status == "FAIL" else
                "Cloud VPN peer path unresolved")
    if assessment.kind == "gallery_share":
        return ("Compute Gallery community sharing permitted" if status == "FAIL" else
                "Compute Gallery community sharing blocked" if status == "PASS" else
                "Compute Gallery sharing recipients unresolved")
    if assessment.kind == "disk_export":
        return ("Public disk or snapshot SAS export permitted" if status == "FAIL" else
                "Public disk or snapshot SAS export blocked" if status == "PASS" else
                "Disk or snapshot SAS export policy unresolved")
    if status == "FAIL":
        if assessment.kind == "external_share":
            return "Data shared with external principal" if assessment.resource["type"] == "ec2_image" else "Data shared with external account"
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
    invalid_ranges = next((step.get("invalid_source_ranges") for step in assessment.path
                           if step.get("layer") == "source_ranges" and step.get("decision") == "unknown"), None)
    if assessment.resource["provider"] == "k8s" and assessment.kind in {"service", "ingress"} and invalid_ranges:
        noun = "Service" if assessment.kind == "service" else "Ingress"
        value = ", ".join(str(item) for item in invalid_ranges[:2])
        return (f"The {noun} has source range {value}, which is not a valid IP range.\n"
                "The controller's treatment of that value is not recorded, so its public source rule is unclear.\n"
                "The source rule may admit public requests if the controller ignores that range.\n"
                f"That could expose data served through this {noun}.")
    if assessment.kind == "vpn_client_authorization":
        if status == "FAIL":
            return ("The active Client VPN rule allows every authenticated client for its destination CIDR.\n"
                    "A client may reach that network if its route and filters also allow traffic.\n"
                    "That could expose data served by resources on the destination network.")
        return ("The Client VPN all-client rule read is incomplete.\n"
                "Authorization for its destination CIDR remains unclear.\n"
                "Clients may reach data on that network if the missing rule allows them.")
    if assessment.kind == "external_generic_policy_grant":
        if status == "FAIL":
            return ("The owned resource policy allows a foreign or wildcard AWS principal.\n"
                    "That principal may use the permitted action if other service rules allow it.\n"
                    "The action could expose data held by this resource.")
        return ("The owned resource policy or foreign grant is incomplete.\n"
                "A foreign principal may use its action if the missing terms allow it.\n"
                "That could expose data held by this resource.")
    if assessment.kind == "external_cluster_snapshot_share":
        if status == "FAIL":
            recipient = "all AWS accounts" if "*" in assessment.external_ids else "foreign accounts"
            return (f"The manual cluster snapshot grants copy or restore access to {recipient}.\n"
                    "Those accounts may copy or restore it if their IAM and KMS permissions allow it.\n"
                    "A copy could expose data stored in the cluster snapshot.")
        return ("The cluster snapshot ownership or restore attributes are incomplete.\n"
                "A foreign account may copy it if the missing grant allows restoration.\n"
                "That could expose data stored in the snapshot.")
    if assessment.kind == "external_redshift_serverless_snapshot_share":
        if status == "FAIL":
            return ("The Redshift Serverless snapshot permits a foreign namespace or cluster restore.\n"
                    "A foreign account may restore it if its IAM and KMS permissions allow it.\n"
                    "That could expose data stored in the snapshot.")
        return ("The Redshift Serverless snapshot owner or restore recipients are incomplete.\n"
                "A foreign account may restore it if the missing grant allows that action.\n"
                "That could expose data stored in the snapshot.")
    if assessment.kind == "external_redshift_snapshot_share":
        if status == "FAIL":
            return ("The manual Redshift snapshot allows a foreign account or AWS Support to restore it.\n"
                    "That principal may restore it if its IAM and KMS permissions allow it.\n"
                    "That could expose data stored in the snapshot.")
        return ("The Redshift snapshot owner or restore authorizations are incomplete.\n"
                "A foreign principal may restore it if the missing grant allows that action.\n"
                "That could expose data stored in the snapshot.")
    if assessment.kind == "external_registry_template_pull":
        if status == "FAIL":
            return ("The ECR creation template attaches a foreign image-pull policy to future matching repositories.\n"
                    "A foreign principal may pull future images if other permissions allow it.\n"
                    "Those images could expose data used by people or services.")
        return ("The ECR creation template or its future pull grant is incomplete.\n"
                "A foreign principal may pull future images if the missing terms allow it.\n"
                "Those images could expose data used by people or services.")
    if assessment.kind == "external_registry_policy_pull":
        if status == "FAIL":
            return ("The private ECR registry policy grants both image-pull actions to a foreign principal.\n"
                    "That principal may pull images if token access and other permissions allow it.\n"
                    "Those images could expose data used by people or services.")
        return ("The private ECR registry policy or foreign pull grant is incomplete.\n"
                "A foreign principal may pull images if the missing terms allow it.\n"
                "Those images could expose data used by people or services.")
    if assessment.kind == "external_layer_share":
        if status == "FAIL":
            return ("The Lambda layer version policy grants GetLayerVersion to a foreign principal.\n"
                    "That principal may download the layer if its caller permissions allow it.\n"
                    "Layer contents could expose data used by services.")
        return ("The Lambda layer version policy or foreign GetLayerVersion grant is incomplete.\n"
                "A foreign principal may download the layer if the missing terms allow it.\n"
                "Layer contents could expose data used by services.")
    if assessment.kind == "external_lambda_invoke":
        if status == "FAIL":
            return ("The Lambda function or alias policy grants InvokeFunction to a foreign principal.\n"
                    "That principal may invoke it if caller permissions also allow the action.\n"
                    "An invocation could affect data handled by the function.")
        return ("The Lambda function or alias policy has incomplete invoke terms.\n"
                "A foreign principal may invoke it if the missing terms allow the action.\n"
                "That could affect data handled by the function.")
    if assessment.kind == "external_kms_grant":
        if status == "FAIL":
            return ("The KMS grant permits a foreign principal to request Decrypt with this key.\n"
                    "The principal may decrypt ciphertext if other authorization and ciphertext access allow it.\n"
                    "That could expose data protected by the key.")
        if status == "PASS":
            return ("The KMS grant refers to a key that cannot currently decrypt.\n"
                    "This grant cannot use that key to read ciphertext in its recorded state.\n"
                    "Data protected by the key is outside this grant's current decrypt path.")
        return ("The KMS grant, key state, or constraints are incomplete.\n"
                "A foreign principal may decrypt if the missing terms permit it.\n"
                "That could expose data protected by the key.")
    if assessment.kind == "external_kms_decrypt_grant":
        if status == "FAIL":
            return ("The enabled customer KMS key policy grants Decrypt to a foreign principal.\n"
                    "That principal may decrypt if caller permission and ciphertext access allow it.\n"
                    "That could expose data protected by this key.")
        if status == "PASS":
            return ("The KMS key is disabled or otherwise unable to decrypt in its recorded state.\n"
                    "Its policy cannot currently decrypt ciphertext through this path.\n"
                    "Data protected by this key remains outside that decrypt path.")
        return ("The KMS key state or Decrypt policy grant is incomplete.\n"
                "A foreign principal may decrypt if the missing terms allow it.\n"
                "That could expose data protected by this key.")
    if assessment.kind == "external_topic_subscribe_grant":
        if status == "FAIL":
            return ("The SNS topic policy permits a foreign principal to request a subscription.\n"
                    "That principal may receive messages if a subscription is confirmed.\n"
                    "Those messages could contain data about people or services.")
        return ("The SNS topic policy or foreign Subscribe grant is incomplete.\n"
                "A foreign principal may subscribe if the missing terms allow it.\n"
                "Topic messages could contain data about people or services.")
    if assessment.kind == "external_topic_subscription":
        if status == "FAIL":
            return ("A foreign account owns a confirmed subscription to this SNS topic.\n"
                    "The endpoint may receive topic messages if delivery succeeds.\n"
                    "Those messages could contain data about people or services.")
        return ("The SNS subscription confirmation or owner account is incomplete.\n"
                "A foreign endpoint may receive messages if confirmation and delivery succeed.\n"
                "Those messages could contain data about people or services.")
    if assessment.kind == "external_queue_receive":
        if status == "FAIL":
            return ("The SQS queue policy grants ReceiveMessage to foreign account " + ", ".join(assessment.external_ids) + ".\n"
                    "That account may read messages if caller and KMS permissions allow it.\n"
                    "Those messages could contain data about people or services.")
        if status == "PASS":
            return ("The queue uses the AWS managed SQS KMS key.\n"
                    "That key blocks the cross-account decrypt path for this queue.\n"
                    "Message data remains outside this foreign read path.")
        return ("The queue policy or foreign ReceiveMessage grant is incomplete.\n"
                "A foreign account may read messages if the missing terms allow it.\n"
                "Those messages could contain data about people or services.")
    if assessment.kind == "external_secret_grant":
        if status == "FAIL":
            return ("The secret policy grants GetSecretValue to foreign account " + ", ".join(assessment.external_ids) + ".\n"
                    "That account may read the secret if caller and KMS permissions allow it.\n"
                    "The value could expose data used by people or services.")
        if status == "PASS":
            return ("The secret uses the AWS managed default KMS key.\n"
                    "That key blocks the cross-account decrypt path for this secret.\n"
                    "The secret value remains outside this foreign read path.")
        return ("The secret policy or KMS key terms are incomplete.\n"
                "A foreign account may read the value if the missing terms allow it.\n"
                "That could expose data used by people or services.")
    if assessment.kind == "external_registry_share":
        if status == "FAIL":
            return ("The ECR repository policy grants image-pull actions to foreign account " + ", ".join(assessment.external_ids) + ".\n"
                    "That account may pull images if caller authentication also allows it.\n"
                    "Those images could expose data used by people or services.")
        return ("The ECR repository policy or foreign image-pull grant is incomplete.\n"
                "A foreign account may pull images if the missing terms allow it.\n"
                "Those images could expose data used by people or services.")
    if assessment.kind == "external_log_stream":
        if status == "FAIL":
            return ("A CloudWatch Logs subscription targets a destination owned by account "
                    + assessment.external_ids[0] + ".\n"
                    "Delivery to that destination was not observed.\n"
                    "The external account may receive log events if delivery succeeds.\n"
                    "Those events could expose data recorded about people or services.")
        return ("The CloudWatch Logs subscription source or destination account is missing.\n"
                "That leaves the recipient of log events unresolved.\n"
                "The destination may receive events if delivery is configured and succeeds.\n"
                "Those events could expose recorded data outside the account.")
    if assessment.kind == "public_registry":
        if status == "FAIL":
            return ("The ECR Public repository permits public image pulls.\n"
                    "Its published image inventory was not recorded.\n"
                    "People outside the account may download any images that are present.\n"
                    "Those images could expose data used by people and services.")
        return ("The ECR Public repository identity or regional scope is missing.\n"
                "Its public pull setting cannot be resolved from those fields.\n"
                "Images may be downloadable if public access is enabled.\n"
                "Their contents could expose data outside the account.")
    if assessment.kind == "external_network":
        if assessment.resource["type"] == "transit_gateway_attachment":
            if status == "FAIL":
                return ("A local VPC route and associated Transit Gateway route select a foreign VPC attachment owned by "
                        + assessment.external_ids[0] + ".\n"
                        "Those routes may carry traffic to that VPC if its return route and filters allow it.\n"
                        "The return route and endpoint rules are not recorded for this attachment.\n"
                        "Traffic across the connection could expose data in connected resources.")
            return ("The local VPC or Transit Gateway route to the foreign attachment is incomplete.\n"
                    "A usable path to the attached VPC cannot be resolved from those records.\n"
                    "Traffic may cross the connection if the missing routes and endpoint rules allow it.\n"
                    "That could expose data in connected resources.")
        if status == "FAIL":
            return ("An active VPC peering connection has a local route to account "
                    + assessment.external_ids[0] + ".\n"
                    "That route may carry traffic to the peer if its routes and filters also allow it.\n"
                    "Peer routing and endpoint rules are not recorded for this connection.\n"
                    "Traffic across that path could expose data in connected resources.")
        if status == "PASS":
            return ("The external VPC peering connection has no active local route in the recorded route tables.\n"
                    "This VPC has no recorded path through that connection.\n"
                    "That may limit traffic to resources in the peer network.\n"
                    "Data on those resources could remain out of reach through this route.")
        return ("The external VPC peering state or local route inventory is incomplete.\n"
                "A route toward the peer account cannot be resolved from those records.\n"
                "Traffic may cross this connection if active routes and peer rules allow it.\n"
                "That could expose data in connected resources.")
    if assessment.resource["type"] == "load_balancer" and status == "UNKNOWN":
        missing_frontend = next((gap["reason"] for gap in assessment.unresolved
                                 if "assigned global public frontend address" in gap["reason"]), None)
        if missing_frontend:
            name = assessment.resource["data"].get("name", native_id(assessment.resource))
            return (f"The Load Balancer {name} has an inbound rule referencing a public-IP frontend.\n"
                    "The rule has no recorded assigned global public frontend address.\n"
                    "The listener's public address is unclear until that assignment is recorded.\n"
                    "If assigned, public traffic could reach data served through this load balancer.")
    if assessment.kind == "public_ip" and status == "UNKNOWN":
        missing = next((gap["reason"] for gap in assessment.unresolved
                        if gap["layer"] == "inventory" and gap["reason"].startswith("referenced public IP ")), None)
        if missing:
            name = assessment.resource["data"].get("name", native_id(assessment.resource))
            return (f"The Azure network interface or VM {name} has a public-IP association.\n"
                    f"The {missing}.\n"
                    "A public path to the interface is unclear without that address.\n"
                    "If assigned, requests could reach software or data on the VM.")
    if assessment.resource["type"] == "azure_firewall" and status == "PASS":
        backend = next((step for step in assessment.path
                        if step["layer"] == "backend" and step["decision"] == "block"), None)
        if backend is not None:
            item = backend["stopped_vm_backends"][0]
            name = assessment.resource["data"].get("name", native_id(assessment.resource))
            return (f"The Azure Firewall {name} has a public-source DNAT rule to private address "
                    f"{item['translated_address']}.\n"
                    f"That address uniquely matches NIC {item['nic']} on VM {item['vm']} with "
                    f"recorded {item['power_state']}.\n"
                    "The stopped VM cannot serve the current translated path.\n"
                    "Starting it could reopen a route to software or data on that VM.")
    if assessment.resource["type"] == "application_gateway":
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        if status == "UNKNOWN" and any("public frontend address" in gap["reason"]
                                       for gap in assessment.unresolved):
            return (f"The Application Gateway {name} has a listener referencing a public frontend.\n"
                    "The referenced public IP resource has no collected assigned public address.\n"
                    "A public path through this listener is unclear without that address.\n"
                    "If assigned, the listener could expose data served by its backend.")
        if status == "FAIL" and assessment.addresses:
            nsg = next((step for step in assessment.path if step["layer"] == "nsg"), {})
            open_frontend = next((front["address"] for front in nsg.get("frontends", [])
                                  if front.get("allowed_ports")), assessment.addresses[0])
            return (f"The Application Gateway {name} has a listener on assigned public address "
                    f"{open_frontend}.\n"
                    "The recorded gateway subnet rules allow the listener port from a public source.\n"
                    "Requests may reach a backend if its routing and access rules also allow them.\n"
                    "That could expose data served through this gateway.")
    if assessment.kind == "cross_project_peering" and status == "UNKNOWN":
        data = assessment.resource["data"]
        name = data.get("name", native_id(assessment.resource))
        peering = next(step for step in assessment.path if step.get("layer") == "vpc_peering")
        return "\n".join((
            f"The VPC network {name} has ACTIVE peering {peering.get('name') or 'unnamed'} to {peering['peer_network']} in project {peering['peer_project']}.",
            f"Its importCustomRoutes value is {peering['import_custom_routes']} and exportCustomRoutes value is {peering['export_custom_routes']}.",
            "Peer network clients may reach local subnet addresses if exchanged routes and local firewall rules admit them.",
            "That could expose workload services or data to users in the peer project if those paths exist."))
    if assessment.resource["type"] == "vpn_tunnel" and status in ("FAIL", "UNKNOWN"):
        data = assessment.resource["data"]
        name = data.get("name", native_id(assessment.resource))
        classic = bool(data.get("targetVpnGateway"))
        peer = data.get("peerIp") if classic else data.get("peerExternalGateway") or data.get("peerGcpGateway")
        gateway = data.get("targetVpnGateway") if classic else data.get("vpnGateway")
        peer_project = next((step.get("peer_project") for step in assessment.path
                             if step.get("layer") == "vpn_peer" and step.get("peer_project")), None)
        peer_label = "peer" if classic else "peer GCP gateway" if data.get("peerGcpGateway") else "peer gateway"
        project_detail = f" in project {peer_project}" if peer_project else ""
        public_ip = assessment.addresses[0] if assessment.addresses else "no recorded public interface address"
        local = (f"Its local gateway {gateway} has {public_ip} across ESP, UDP 500 and UDP 4500 forwarding rules."
                 if classic and assessment.addresses else
                 f"Its local gateway {gateway} lacks a recorded public IP with all three forwarding rules."
                 if classic else
                 f"Its local gateway {gateway} uses interface {data.get('vpnGatewayInterface')} with {public_ip}.")
        return "\n".join((
            f"The {'Classic' if classic else 'HA'} VPN tunnel {name} has status {data.get('status') or 'unavailable'} and {peer_label} {peer}{project_detail}.",
            local,
            "An authenticated peer may exchange IPsec traffic with that gateway when the tunnel remains established.",
            "That could allow the peer to reach VPC services or data if routes and firewalls admit the traffic."))
    if assessment.resource["type"] == "app_engine_application" and status in ("FAIL", "UNKNOWN"):
        data = assessment.resource["data"]
        name = data.get("name", native_id(assessment.resource))
        hostname = data.get("defaultHostname") or "no recorded default hostname"
        serving = data.get("servingStatus") or "unavailable"
        firewall = next((step for step in assessment.path if step.get("layer") == "app_engine_firewall"), None)
        first = f"The App Engine application {name} has default hostname {hostname} and serving status {serving}."
        if firewall and firewall.get("decision") == "allow":
            second = (f"Its priority {firewall['priority']} ingress rule allows source {firewall['source_range']}"
                      f" and application IAP is {'enabled' if assessment.authenticated else 'disabled or unrecorded'}.")
        else:
            second = "Its ordered ingress firewall decision or serving status is unresolved."
        return "\n".join((first, second,
            "Internet clients may reach its HTTPS endpoint if routing and identity controls admit requests.",
            "That could expose application behavior or data to outside users if the service responds."))
    if assessment.kind == "vpn_gateway" and status in ("FAIL", "UNKNOWN"):
        data = assessment.resource["data"]
        name = data.get("name", native_id(assessment.resource))
        addresses = ", ".join(str(value) for value in assessment.addresses[:2]) or "no recorded public address"
        if assessment.resource["type"] == "vpn_gateway":
            return "\n".join((
                f"The HA VPN gateway {name} has public interface address {addresses}.",
                "Its public interfaces permit UDP 500, UDP 4500, and ESP for IPsec peer traffic.",
                "An internet peer may send those protocols to the gateway, subject to tunnel authentication.",
                "An authenticated peer could reach VPC services or data if tunnel, route, and firewall controls allow it."))
        target = data.get("target") or "no recorded target VPN gateway"
        ports = ", ".join(describe(assessment.ports or {})) or "no recorded protocol port"
        return "\n".join((
            f"The Classic VPN forwarding rule {name} has address {addresses} and target {target}.",
            f"Its recorded IP protocol and port selection is {ports}.",
            "An internet peer may send that traffic to the gateway if the public listener responds.",
            "An authenticated peer could reach VPC services or data if tunnel, route, and firewall controls allow it."))
    redirect = next((step for step in assessment.path if step.get("layer") == "url_redirect"), None)
    if assessment.resource["type"] == "forwarding_rule" and redirect and status in ("FAIL", "UNKNOWN"):
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        address = ", ".join(str(value) for value in assessment.addresses[:2]) or "no recorded public address"
        route = redirect["routes"][0]
        target = route.get("host_redirect") or "the requested host"
        first = f"The forwarding rule {name} has address {address} and a URL-map redirect route."
        match_path = route.get("match_path")
        match_type = "prefix" if route.get("match_path_type") == "prefixMatch" else "exact"
        path_detail = f" for request path {match_type} {match_path or '/'}" if match_path is not None else ""
        host_detail = f" for unmatched host {route['host_witness']}" if route.get("host_witness") else ""
        second = (f"That route{host_detail}{path_detail} has response code {route['response_code']}, destination {target}, "
                  f"and stripQuery set to {str(route['strip_query']).lower()}.")
        impact = ("Visitors could be sent to the configured destination after their query string is removed."
                  if route["strip_query"] else
                  "Visitors could send URL query data to the configured destination if their client follows the redirect.")
        return "\n".join((first, second,
            "An internet client may receive the redirect if the public listener responds.",
            impact))
    route_rule = next((step for step in assessment.path if step.get("layer") == "url_route_rule"), None)
    if assessment.resource["type"] == "forwarding_rule" and route_rule and status in ("FAIL", "UNKNOWN"):
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        address = ", ".join(str(value) for value in assessment.addresses[:2]) or "no recorded public address"
        backends = ", ".join(route_rule.get("backends", []))
        match_type = "exact" if route_rule.get("match_type") == "fullPathMatch" else "prefix"
        path = route_rule.get("path", route_rule.get("prefix", "/"))
        host = route_rule.get("host", "unrecorded")
        return "\n".join((
            f"The forwarding rule {name} has public address {address} and URL-map Host {host}.",
            f"Its priority {route_rule.get('priority')} rule matches path {match_type} {path} and selects backend {backends}.",
            "Internet clients may reach that backend if edge policy and backend routing admit requests.",
            "That could expose application behavior or data; backend health and responses remain unresolved."))
    if assessment.resource["type"] == "cloudrun_instance" and status in ("FAIL", "UNKNOWN"):
        data = assessment.resource["data"]
        name = data.get("name", native_id(assessment.resource))
        origins = ", ".join(assessment.addresses[:2]) or "no recorded serving URL"
        first = f"The Cloud Run instance {name} has ingress {data.get('ingress') or 'unavailable'} and {origins}."
        if status == "FAIL":
            grant = next((step for step in assessment.path if step.get("layer") == "invoker"), {})
            access = ("its invoker IAM check disabled" if grant.get("invoker_iam_disabled") else
                      f"a direct public invoker grant to {', '.join(grant.get('public_members', []))}")
            return "\n".join((first,
                f"It has {access} and a declared HTTPS route on port 443.",
                "Internet clients may call that route if DNS and the instance respond.",
                "That could expose application behavior or data to outside users."))
        return "\n".join((first,
            "Its serving URL, active state, IAP setting, or invoker grant is unresolved.",
            "Internet clients may call that route if those controls admit them.",
            "That could expose application behavior or data to outside users."))
    if assessment.resource["type"] == "workbench_instance" and status in ("FAIL", "UNKNOWN"):
        data = assessment.resource["data"]
        name = data.get("name", native_id(assessment.resource))
        origin = assessment.addresses[0] if assessment.addresses else "no recorded HTTPS URI"
        first = (f"The Workbench instance {name} has proxy access enabled at {origin}."
                 if assessment.addresses else
                 f"The Workbench instance {name} has proxy access enabled with no recorded HTTPS URI.")
        if status == "FAIL":
            return "\n".join((first,
                "Its state is ACTIVE and the Jupyter proxy route is declared on HTTPS port 443.",
                "An internet client may reach that proxy if the service responds and identity grants allow the user.",
                "That could expose notebook code or data to an authorized outside user."))
        return "\n".join((first,
            f"Its recorded state is {data.get('state') or 'unavailable'}, and the proxy URL or active state is unresolved.",
            "An internet client may reach the proxy if it becomes available and identity grants allow the user.",
            "That could expose notebook code or data to an authorized outside user."))
    if assessment.resource["type"] == "dataproc_cluster" and status in ("FAIL", "UNKNOWN"):
        data = assessment.resource["data"]
        name = data.get("clusterName", native_id(assessment.resource))
        endpoint = (data.get("config") or {}).get("endpointConfig") or {}
        labels = sorted((endpoint.get("httpPorts") or {}).keys()) if isinstance(endpoint.get("httpPorts"), dict) else []
        origins = ", ".join(assessment.addresses[:2]) or "no recorded URL"
        first = (f"The Dataproc cluster {name} has Component Gateway enabled with HTTPS origin {origins}."
                 if assessment.addresses else
                 f"The Dataproc cluster {name} has Component Gateway enabled with no recorded HTTPS URL.")
        if status == "FAIL":
            return "\n".join((first,
                f"Its RUNNING cluster advertises {', '.join(labels[:3])} through the gateway.",
                "An internet client may reach those gateway URLs if the service responds and IAM permits the user.",
                "That could expose cluster interface details or workload data to an authorized outside user."))
        state = (data.get("status") or {}).get("state") if isinstance(data.get("status"), dict) else None
        return "\n".join((first,
            f"Its recorded state is {state or 'unavailable'}, and its gateway URL or active status is unresolved.",
            "An internet client may reach a gateway interface if it becomes available and IAM permits the user.",
            "That could expose cluster interface details or workload data to an authorized outside user."))
    public_origin = next((step for step in assessment.path if step.get("layer") == "cdn_origin"
                          and step.get("public_origin_read_grants")), None)
    if assessment.resource["type"] == "forwarding_rule" and public_origin and status in ("FAIL", "UNKNOWN"):
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        address = ", ".join(str(value) for value in assessment.addresses[:2])
        grant = public_origin["public_origin_read_grants"][0]
        grant_scope = (f" on project {grant['scope']}" if grant.get("scope") else "")
        permission = (f" including {grant['permission']}" if grant.get("permission") else "")
        if grant.get("source") == "objectAccessControls":
            host_detail = f" for unmatched Host {public_origin['host_witness']}" if public_origin.get("host_witness") else ""
            return "\n".join((
                f"The forwarding rule {name} has public address {address} and default backend bucket {public_origin.get('bucket_name')}{host_detail}.",
                f"At least one origin object has {grant['role']} for {grant['member']} with public access prevention not enforced.",
                "An internet client may request that object through the backend bucket route if edge policy admits it.",
                "An outside viewer could receive object data; current edge delivery and object response remain unresolved."))
        if grant.get("source") == "managed_folder":
            host_detail = f" for unmatched Host {public_origin['host_witness']}" if public_origin.get("host_witness") else ""
            return "\n".join((
                f"The forwarding rule {name} has public address {address} and default backend bucket {public_origin.get('bucket_name')}{host_detail}.",
                f"Its managed folder {grant['folder']} grants {grant['role']} to {grant['member']} with public access prevention not enforced.",
                "An internet client may request objects under that folder prefix if edge policy admits the route.",
                "An outside viewer could receive object data if matching objects exist; delivery remains unresolved."))
        host_detail = (f" for Host {public_origin['host_witness']} path {public_origin['path_witness']}"
                       if public_origin.get("path_witness") else
                       f" for unmatched Host {public_origin['host_witness']}"
                       if public_origin.get("host_witness") else "")
        return "\n".join((
            f"The forwarding rule {name} has public address {address} and backend bucket {public_origin.get('bucket_name')}{host_detail}.",
            f"Its origin has {grant['role']}{permission} for {grant['member']}{grant_scope} with public access prevention not enforced.",
            "Internet clients may reach the bucket route if edge policy and origin delivery allow it.",
            "An outside viewer could receive object data if objects exist; edge cache contents and responses remain unresolved."))
    path_rule = next((step for step in assessment.path if step.get("layer") == "url_path_rule"), None)
    if assessment.resource["type"] == "forwarding_rule" and path_rule and status in ("FAIL", "UNKNOWN"):
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        address = ", ".join(str(value) for value in assessment.addresses[:2]) or "no recorded public address"
        backends = ", ".join(path_rule.get("backends", []))
        return "\n".join((
            f"The forwarding rule {name} has public address {address} and URL-map Host {path_rule['host']}.",
            f"Its path rule {path_rule['pattern']} matches request path {path_rule['path']} and selects backend {backends}.",
            "Internet clients may reach that backend if edge policy and backend routing admit requests.",
            "That could expose application behavior or data; backend health and responses remain unresolved."))
    if assessment.resource["type"] == "tpu_node" and status in ("FAIL", "UNKNOWN"):
        data = assessment.resource["data"]
        name = data.get("name", native_id(assessment.resource))
        public = [row for row in as_list(data.get("networkEndpoints"))
                  if isinstance(row, dict) and isinstance(row.get("accessConfig"), dict)
                  and row["accessConfig"].get("externalIp") in assessment.addresses]
        endpoint = public[0] if public else {}
        address = (endpoint.get("accessConfig") or {}).get("externalIp", "unrecorded")
        port = endpoint.get("port", "unrecorded")
        first = f"The TPU node {name} has public network endpoint {address} with port {port}."
        if status == "FAIL":
            matched = ", ".join(describe(assessment.ports or {}))
            selected = next((step for step in assessment.path if step.get("layer") == "tpu_network_config"), None)
            network_detail = f" on selected VPC {selected['network']}" if selected else ""
            return "\n".join((first,
                f"Its joined VPC firewall{network_detail} allows {matched} at the declared endpoint port.",
                "Internet clients may reach that port if the TPU workload accepts connections.",
                "That could expose TPU workload services or data; guest listener state and responses remain unresolved."))
        distinct_networks = any("distinct VPC network configurations" in gap.get("reason", "")
                                for gap in assessment.unresolved)
        detail = ("Its networkConfigs name distinct VPC networks without a networkEndpoint-to-networkConfig association."
                  if distinct_networks else "Its network, firewall, or endpoint-port decision remains unresolved.")
        return "\n".join((first,
            detail,
            "Internet clients may reach a TPU workload port if those controls admit traffic.",
            "That could expose TPU workload services or data; guest listener state and responses remain unresolved."))
    classic = next((step for step in assessment.path if step.get("layer") == "classic_precedence"), None)
    if assessment.resource["type"] == "instance" and classic and status == "FAIL":
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        addresses = ", ".join(str(value) for value in assessment.addresses[:2])
        matched = classic.get("matched_rules") or [{}]
        return "\n".join((
            f"The Compute instance {name} has external address {addresses} on VPC {classic.get('network')}.",
            f"Its VPC enforcement order is AFTER_CLASSIC_FIREWALL, and classic rule {matched[0].get('rule')} allows {', '.join(classic.get('allowed') or [])}.",
            "Internet clients may reach an allowed port if a guest listener accepts traffic.",
            "That could expose software or data served by this instance."))
    terminal = next((step for step in assessment.path
                     if step.get("layer") == "effective_firewall"
                     and step.get("basis") in ("terminal hierarchical ingress rule",
                                               "terminal global network ingress rule",
                                               "terminal regional network ingress rule",
                                               "terminal regional system ingress rule")), None)
    transition = next((step for step in assessment.path if step.get("layer") == "hierarchy_transition"), None)
    system_transition = next((step for step in assessment.path if step.get("layer") == "system_transition"), None)
    network_transition = next((step for step in assessment.path if step.get("layer") == "network_transition"), None)
    if (assessment.resource["type"] == "instance" and status == "UNKNOWN" and terminal is None and
            (transition or system_transition or network_transition or any(gap.get("layer") == "firewall" and "per-interface" in gap.get("reason", "")
                               for gap in assessment.unresolved))):
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        addresses = ", ".join(str(value) for value in assessment.addresses[:2])
        transition_ports = transition.get("ports") if transition else None
        port_detail = f" for {', '.join(transition_ports)}" if transition_ports and transition_ports != describe(FULL) else ""
        if transition:
            second = f"Its hierarchical policy {transition.get('policy')} has goto_next at rule {transition.get('rule')}{port_detail}."
        elif system_transition:
            ports = system_transition.get("ports")
            port_detail = f" for {', '.join(ports)}" if ports and ports != describe(FULL) else ""
            second = (f"Its regional system policy {system_transition.get('policy')} has goto_next at rule "
                      f"{system_transition.get('rule')}{port_detail}.")
        elif network_transition:
            ports = network_transition.get("ports")
            port_detail = f" for {', '.join(ports)}" if ports and ports != describe(FULL) else ""
            second = (f"Its global network policy {network_transition.get('policy')} has goto_next at rule "
                      f"{network_transition.get('rule')}{port_detail}.")
        else:
            second = "Its per-interface firewall policy decision is unresolved."
        return "\n".join((
            f"The Compute instance {name} has external address {addresses}.",
            second,
            "A later firewall decision may allow an internet client to reach a workload port.",
            "That could expose software or data served by this instance if a later policy admits traffic."))
    if terminal is not None and assessment.resource["type"] == "instance":
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        addresses = ", ".join(str(value) for value in assessment.addresses[:2])
        first = f"The Compute instance {name} has external address {addresses}."
        port_note = (f" and allows {', '.join(terminal['allowed_ports'])}"
                     if terminal.get("action") == "allow" and terminal.get("allowed_ports") else "")
        policy_kind = terminal.get("basis", "terminal hierarchical ingress rule").removeprefix("terminal ").removesuffix(" ingress rule")
        second = (f"Its effective {policy_kind} rule {terminal.get('rule')} has action "
                  f"{terminal.get('action')} at priority {terminal.get('priority')}{port_note}.")
        if status == "FAIL":
            return "\n".join((first, second,
                "Internet clients may reach an allowed port if a guest listener accepts traffic.",
                "That could expose software or data served by this instance."))
        if status == "PASS":
            return "\n".join((first, second,
                "This rule may block internet requests to the instance on its public interface.",
                "That limits a route to software or data served by this instance."))
        return "\n".join((first, second,
            "Another public interface may admit traffic if its firewall allows it.",
            "That could expose software or data served by this instance."))
    if assessment.resource["type"] == "composer_environment":
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        allowlist = next((step for step in assessment.path
                          if step["layer"] == "web_server_ip_allowlist"), {})
        if status == "FAIL":
            setting = ("has no webServerNetworkAccessControl setting"
                       if allowlist.get("mode") == "unrestricted" else
                       "has a webServerNetworkAccessControl range that allows a public source")
            return (f"The Composer environment {name} is RUNNING and {setting} for its Airflow web UI.\n"
                    "A public source may reach that UI if the service responds.\n"
                    "If IAM also grants access, workflow settings or data could become visible.")
        if status == "PASS":
            return (f"The Composer environment {name} has webServerNetworkAccessControl with no public source range.\n"
                    "That setting may block internet clients from its Airflow web UI.\n"
                    "This limits a route to workflow settings and data.")
        reason = assessment.unresolved[0]["reason"] if assessment.unresolved else ""
        if "config" in reason:
            missing = "config"
        elif "URI" in reason:
            missing = "config.airflowUri"
        elif "RUNNING" in reason:
            missing = "RUNNING state"
        else:
            missing = "webServerNetworkAccessControl.allowedIpRanges"
        return (f"The Composer environment {name} has no complete recorded {missing} for its Airflow web UI.\n"
                "Its public access setting remains unclear.\n"
                "An open path could expose workflow settings or data if IAM also grants access.")
    if assessment.resource["type"] == "container_app":
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        route = next((step for step in assessment.path if step["layer"] == "environment_http_route"), None)
        if route is not None and status in ("FAIL", "UNKNOWN"):
            return (f"The Container App {name} has internal ingress but an environment HTTP route "
                    f"targets it at {route['route_fqdns'][0]}.\n"
                    "The recorded route is provisioned and the environment public network gate is evaluated.\n" +
                    ("A public request may reach the app; successful backend response was not tested."
                     if status == "FAIL" else "App restrictions or other path facts still leave public reachability unresolved."))
        labels = next((step for step in assessment.path
                       if step["layer"] == "revision_labels"), None)
        if status == "FAIL" and labels is not None:
            return (f"The Container App {name} has external HTTP ingress and an active revision label "
                    f"FQDN {labels['active_label_fqdns'][0]}.\n"
                    "Recorded ingress traffic, environment domain and complete revision list establish a "
                    "label route independent of the app URL traffic weight.\n"
                    "The public network gates admit a source; a successful request was not tested.")
        http_port = next((step for step in assessment.path if step["layer"] == "http_port_80"), None)
        if status == "FAIL" and http_port is not None:
            fqdn = assessment.addresses[0] if assessment.addresses else "an unobserved FQDN"
            mode = "permits insecure HTTP" if http_port["decision"] == "allow" else "redirects HTTP to HTTPS"
            return (f"The Container App {name} records external HTTP ingress at {fqdn} on ports 80 and 443.\n"
                    f"Port 80 {mode} under its recorded allowInsecure setting.\n"
                    "A public source is admitted by the recorded restrictions; backend response was not tested.")
        inactive = next((step for step in assessment.path
                         if step["layer"] == "revisions" and step["decision"] == "block"), None)
        if status == "PASS" and inactive is not None:
            return (f"The Container App {name} has external ingress declared and a complete runtime "
                    f"revision list of {inactive['inactive_revision_count']} inactive revisions.\n"
                    "The snapshot has no active revision to serve that ingress path.\n"
                    "Activating a revision could reopen the declared public endpoint.")
        state = next((step.get("running_status") for step in assessment.path
                      if step.get("layer") == "app_state"), None)
        if status == "PASS" and state == "Stopped":
            return (f"The Container App {name} has external ingress configured and recorded runningStatus Stopped.\n"
                    "That stopped state blocks current requests through its public endpoint.\n"
                    "Starting the app could reopen the declared ingress path.")
        if status == "UNKNOWN" and state is not None:
            return (f"The Container App {name} has external ingress configured and recorded runningStatus {state}.\n"
                    "Its current public request path is unresolved while this state changes.\n"
                    "The endpoint could expose app responses if an active revision serves requests.")
    if assessment.resource["type"] == "api_management" and status in ("FAIL", "UNKNOWN"):
        props = _props(assessment.resource)
        if props.get("disableGateway") is True and assessment.addresses:
            name = assessment.resource["data"].get("name", native_id(assessment.resource))
            return (f"The API Management service {name} has its primary gateway disabled and an enabled "
                    f"regional gateway at {assessment.addresses[0]}.\n" +
                    ("That recorded regional listener may accept public HTTPS requests if the service responds.\n"
                     if status == "FAIL" else
                     "The regional public request path is unresolved by its VNet or inventory settings.\n")
                    + "API authorization, backend health, and successful requests were not tested.")
    if assessment.resource["type"] == "sql_server" and status == "UNKNOWN" and any(
            "database-level firewall rules" in gap["reason"] for gap in assessment.unresolved):
        name = assessment.resource["data"].get("name", native_id(assessment.resource))
        return (f"The Azure SQL server {name} has public network access enabled but no recorded "
                "public-source server firewall rule.\n"
                "Database-level firewall rules are not present in the ARM server rule inventory.\n"
                "A database could still admit a public source; its SQL data-plane rules were not read.")
    if assessment.kind == "web_app":
        restriction = next((step for step in assessment.path if step["layer"] == "access_restrictions"), {})
        network = next((step for step in assessment.path if step["layer"] == "public_network_access"), {})
        main = (restriction.get("main") or {}).get("decision")
        scm = (restriction.get("scm") or {}).get("decision")
        if status == "FAIL":
            surface = "SCM" if scm == "allow" and main != "allow" else "main site"
            impact = ("deployment controls or app data" if surface == "SCM" else "app data")
            return (f"The App Service allows public network access, and its {surface} IP rules allow a public source.\n"
                    f"A request may reach the {surface} endpoint if its hostname and service are active.\n"
                    f"If authentication also allows it, that could expose {impact}.")
        if status == "PASS":
            if network.get("decision") == "block":
                return ("The App Service has publicNetworkAccess set to Disabled.\n"
                        "That setting blocks public requests to its main and SCM endpoints.\n"
                        "This limits a route to app data and deployment controls.")
            return ("The App Service's main and SCM IP rules deny public sources.\n"
                    "Those rules may block internet requests to both endpoints.\n"
                    "This limits a route to app data and deployment controls.")
        if not restriction:
            missing = "main and SCM IP restriction settings"
        elif main == "unknown":
            missing = "main IP restriction decision"
        else:
            missing = "SCM IP restriction decision or SCM hostname"
        return (f"The App Service has no complete recorded {missing}.\n"
                "Its public request path therefore remains unclear.\n"
                "An open path could expose app data or deployment controls if authentication also allows access.")
    if assessment.kind == "gallery_share":
        profile = _props(assessment.resource).get("sharingProfile")
        permission = profile.get("permissions") if isinstance(profile, dict) else None
        if status == "FAIL":
            if permission == "Groups":
                return ("The gallery has sharingProfile.permissions Groups with recipients outside its owning subscription or tenant.\n"
                        "This setting permits direct sharing of gallery images with those recipients.\n"
                        "Published image versions may become available to those recipients.\n"
                        "That could expose files or data stored in those images.")
            return ("The gallery has sharingProfile.permissions Community.\n"
                    "This setting permits community sharing of its images.\n"
                    "Published image versions may become available outside the tenant.\n"
                    "That could expose files or data stored in those images.")
        if status == "PASS":
            if permission == "Groups":
                return ("The gallery has sharingProfile.permissions Groups with only its owning subscription or tenant recorded.\n"
                        "No external recipient is present in the recorded direct-sharing policy.\n"
                        "This gallery policy does not grant outside access to image contents.")
            return ("The gallery has sharingProfile.permissions Private.\n"
                    "This setting blocks community sharing of its images.\n"
                    "Image contents are protected from this public sharing path.")
        if permission == "Groups":
            return ("The gallery has sharingProfile.permissions Groups.\n"
                    "The recipients' ownership and published image versions are not recorded.\n"
                    "A recipient outside the tenant could access shared image contents.")
        first = ("The gallery has no recorded sharingProfile.permissions value." if permission is None
                 else f"The gallery has sharingProfile.permissions {permission}.")
        return (first + "\n"
                "Its community sharing setting is unclear from that value.\n"
                "Published images could be available outside the tenant if sharing is enabled.")
    if assessment.kind == "disk_export":
        props = _props(assessment.resource)
        policy = props.get("networkAccessPolicy")
        public = props.get("publicNetworkAccess")
        noun = "snapshot" if assessment.resource["type"] == "snapshot" else "disk"
        if status == "FAIL":
            return (f"The {noun} has networkAccessPolicy AllowAll and publicNetworkAccess Enabled.\n"
                    "An authorized user may create a SAS URL for public export.\n"
                    "A person with a valid URL could read the exported data.\n"
                    "That could expose files or personal data stored in the disk image.")
        if status == "PASS":
            setting = (f"networkAccessPolicy {policy}" if policy in ("DenyAll", "AllowPrivate")
                       else f"publicNetworkAccess {public}")
            return (f"The {noun} has {setting}.\n"
                    "This setting blocks the public SAS export path.\n"
                    "A SAS URL could not use that public path to reach the stored data.")
        missing = [name for name, value in (("networkAccessPolicy", policy),
                                           ("publicNetworkAccess", public)) if value is None]
        first = (f"The {noun} has no recorded {' or '.join(missing)} value." if missing else
                 f"The {noun} has networkAccessPolicy {policy} and publicNetworkAccess {public}.")
        return (first + "\n"
                "The public SAS export path is unclear from these settings.\n"
                "If public export is allowed, a valid SAS URL could expose stored data.")
    if assessment.resource["type"] in ("storage_account", "storage_container") and status == "FAIL":
        ipv6_step = next((step for step in assessment.path if any(
            _cidr(value).version == 6 for value in step.get("public_ip_rules", []))), None)
        if ipv6_step is not None:
            source = next(value for value in ipv6_step["public_ip_rules"] if _cidr(value).version == 6)
            name = assessment.resource["data"].get("name", native_id(assessment.resource))
            if assessment.resource["type"] == "storage_container":
                return (f"The blob container {name} allows anonymous access, and its account publishes "
                        f"an IPv6 blob endpoint with firewall source {source}.\n"
                        "A request from that IPv6 source may reach the blob endpoint if the service responds.\n"
                        "Anonymous blob reads could expose stored data; no request or contents were tested.")
            return (f"The storage account {name} publishes an IPv6 endpoint and permits firewall source {source}.\n"
                    "A request from that IPv6 source may reach the storage endpoint if the service responds.\n"
                    "Data authorization and successful access were not tested.")
        instance_step = next((step for step in assessment.path
                              if step.get("resource_instance_rules") and not step.get("public_ip_rules")), None)
        if instance_step is not None:
            instance = instance_step["resource_instance_rules"][0]
            if assessment.resource["type"] == "storage_container":
                return (f"The blob container {assessment.resource['data'].get('name', native_id(assessment.resource))} "
                        f"allows anonymous access, and its account permits resource instance {instance['resource_id']} "
                        f"in tenant {instance['tenant_id']} through the public endpoint.\n"
                        "Requests from that instance may reach the blob endpoint if the service responds.\n"
                        "Anonymous blob reads could expose stored data; no request or blob contents were tested.")
            return (f"The storage account {assessment.resource['data'].get('name', native_id(assessment.resource))} "
                    f"permits resource instance {instance['resource_id']} in tenant {instance['tenant_id']} "
                    "through its public endpoint.\n"
                    "Requests from that instance may reach the storage endpoint if the service responds.\n"
                    "Reading data still requires separate authorization or a public container ACL; neither was tested.")
        subnet_step = next((step for step in assessment.path
                            if step.get("virtual_network_rules") and not step.get("public_ip_rules")), None)
        if subnet_step is not None:
            subnet_id = subnet_step["virtual_network_rules"][0]
            if assessment.resource["type"] == "storage_container":
                return (f"The blob container {assessment.resource['data'].get('name', native_id(assessment.resource))} "
                        f"allows anonymous access, and its account permits subnet {subnet_id} "
                        "through the public endpoint.\n"
                        "Requests from that subnet may reach the blob endpoint if its service endpoint and service respond.\n"
                        "Anonymous blob reads could expose stored data; subnet ownership and successful access were not tested.")
            return (f"The storage account {assessment.resource['data'].get('name', native_id(assessment.resource))} "
                    f"permits subnet {subnet_id} through its public endpoint.\n"
                    "Requests from that subnet may reach storage if its service endpoint and the service respond.\n"
                    "Subnet ownership, data authorization, and successful access were not tested.")
    if assessment.resource["type"] in ("storage_account", "storage_container") and status == "FAIL":
        account = assessment.resource["data"]
        secondary = next((step.get("blob_url") for step in assessment.path
                          if step["layer"] == "secondary_endpoint"), None)
        if assessment.resource["type"] == "storage_container":
            if secondary:
                name = account.get("name", native_id(assessment.resource))
                return (f"The blob container {name} allows anonymous reads and its account records "
                        f"read-access secondary blob endpoint {secondary}.\n"
                        "The account network rules permit a public source to that endpoint if it responds.\n"
                        "No blob request or contents were tested.")
        else:
            if secondary:
                name = account.get("name", native_id(assessment.resource))
                return (f"The storage account {name} records read-access secondary blob endpoint {secondary}.\n"
                        "Its network rules permit a public source to that endpoint if it responds.\n"
                        "Data authorization and a successful request were not tested.")
    if assessment.resource["type"] == "storage_account" and status == "UNKNOWN":
        exception = next((step for step in assessment.path
                          if step["layer"] == "trusted_service_exception"), None)
        if exception is not None:
            name = assessment.resource["data"].get("name", native_id(assessment.resource))
            return (f"The storage account {name} denies unmatched network sources but records "
                    f"trusted-service bypass {', '.join(exception['bypass'])}.\n"
                    "Those Azure services may use its public endpoint from outside the account network boundary.\n"
                    "Service identity, data authorization, and a successful request were not observed.")
    if assessment.resource["type"] == "container_registry" and _props(assessment.resource).get("anonymousPullEnabled") is True:
        if status == "FAIL":
            return ("The registry has anonymousPullEnabled true and a recorded public network path.\n"
                    "Public clients may pull images without a registry identity if the service responds.\n"
                    "Images in this registry could expose data used by people or services.")
        if status == "PASS":
            return ("The registry has anonymousPullEnabled true, but its recorded network gate blocks direct public access.\n"
                    "Clients on another permitted network path may still pull images anonymously.\n"
                    "Those images could contain data used by people or services.")
        return ("The registry has anonymousPullEnabled true.\n"
                "Its public network path is unresolved because the network gate is incomplete.\n"
                "If public access is allowed, people may pull any images present.\n"
                "Those images could expose data used by people or services.")
    if status == "UNKNOWN":
        return "Internet access could not be determined because required configuration is missing."
    if status == "PASS":
        if assessment.blocked_by:
            return f"Public access is blocked by {assessment.blocked_by.replace('_', ' ')}."
        return "The collected configuration does not allow public access."
    if assessment.kind == "external_share":
        principals = ", ".join(assessment.external_ids)
        if assessment.resource["type"] == "ec2_image":
            return (f"The AMI launch permission names external principals: {principals}.\n"
                    "Those principals may launch an instance from this image if their other permissions allow it.\n"
                    "A launched image could expose files or data stored in the AMI.")
        return (f"The snapshot restore permission names external accounts: {principals}.\n"
                "Those accounts may restore the snapshot if their other permissions allow it.\n"
                "A restored snapshot could expose files or data stored in the image.")
    if assessment.data_exposure:
        if assessment.resource["type"] == "ec2_image":
            return "AMI launch access is granted to everyone."
        if assessment.resource["type"] in ("rds_snapshot", "rds_cluster_snapshot", "ebs_snapshot"):
            return "Snapshot restore access is granted to everyone."
        return "Public access to the stored data is allowed."
    sentence = f"{_title(assessment, status)} is allowed."
    if assessment.dormant:
        inactive = {"rds_instance": "The DB instance is stopped.",
                    "redshift_cluster": "The Redshift cluster is paused."}.get(
                        assessment.resource["type"], "The instance is stopped or deallocated.")
        return sentence.replace("Internet access", "Configured internet access", 1) + " " + inactive
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
                    "semantics": ("Configured CloudWatch Logs subscription to a foreign logical destination; delivery was not observed."
                                  if assessment.kind == "external_log_stream" else
                                  "Declared ECR repository policy grant to a foreign principal; caller authentication, identity-side permissions and image pulls were not observed."
                                  if assessment.kind == "external_registry_share" else
                                  "Declared ECR registry policy grant for image-pull actions; caller token, matching repositories and pulls were not observed."
                                  if assessment.kind == "external_registry_policy_pull" else
                                  "Configured ECR creation template would grant foreign pull actions to future matching repositories; no existing repository or pull is implied."
                                  if assessment.kind == "external_registry_template_pull" else
                                  "Observed Redshift manual snapshot restore authorization for a foreign account or AWS Support; caller IAM, KMS and actual restore were not observed."
                                  if assessment.kind == "external_redshift_snapshot_share" else
                                  "Observed Redshift Serverless snapshot restore authorization for foreign namespace or provisioned-cluster targets; caller IAM, KMS and actual restore were not observed."
                                  if assessment.kind == "external_redshift_serverless_snapshot_share" else
                                  "Observed DocumentDB or Neptune manual snapshot copy/restore authorization; caller, KMS and actual use were not observed."
                                  if assessment.kind == "external_cluster_snapshot_share" else
                                  "Declared foreign AWS principal grant in a source-attributed resource policy; caller, service prerequisites and actual use were not observed."
                                  if assessment.kind == "external_generic_policy_grant" else
                                  "Declared cross-account secret read grant with a customer KMS key; caller and KMS permissions were not observed."
                                  if assessment.kind == "external_secret_grant" else
                                  "Declared SQS queue ReceiveMessage grant to a foreign principal; caller and any KMS permissions were not observed."
                                  if assessment.kind == "external_queue_receive" else
                                  "Confirmed foreign-owned SNS subscription to an owned topic; endpoint ownership and message delivery were not observed."
                                  if assessment.kind == "external_topic_subscription" else
                                  "Declared SNS topic Subscribe grant to a foreign or wildcard principal; confirmation and message delivery were not observed."
                                  if assessment.kind == "external_topic_subscribe_grant" else
                                  "Declared foreign KMS Decrypt grant on an enabled customer key; caller permissions and ciphertext access were not observed."
                                  if assessment.kind == "external_kms_decrypt_grant" else
                                  "Declared foreign KMS Decrypt grant on an enabled customer key; other authorization controls and ciphertext access were not observed."
                                  if assessment.kind == "external_kms_grant" else
                                  "Declared Lambda InvokeFunction grant to a foreign or wildcard principal; caller permissions and invocation were not observed."
                                  if assessment.kind == "external_lambda_invoke" else
                                  "Declared Lambda layer GetLayerVersion grant to a foreign or wildcard principal; caller permissions and download were not observed."
                                  if assessment.kind == "external_layer_share" else
                                  "ECR Public repository configuration permits anonymous image pulls; published images were not enumerated."
                                  if assessment.kind == "public_registry" else
                                  "Declared cross-account network connection and local route; return route and endpoint access are unverified."
                                  if assessment.kind == "external_network" else
                                  "Declared-configuration path model from 0.0.0.0/0; no traffic was sent.")}
        severity = ("critical" if assessment.kind == "external_cluster_snapshot_share" and assessment.data_exposure and status == "FAIL" else
                    "high" if assessment.kind in ("external_share", "external_cluster_snapshot_share", "external_network", "public_registry", "external_log_stream", "external_registry_share", "external_registry_policy_pull", "external_redshift_snapshot_share", "external_redshift_serverless_snapshot_share", "external_secret_grant", "external_queue_receive", "external_topic_subscription", "external_topic_subscribe_grant", "external_kms_decrypt_grant", "external_kms_grant", "external_lambda_invoke", "external_layer_share") and status == "FAIL" else assessment.adjusted_severity())
        current = finding(snapshot, assessment.resource, "exposure", CHECK, _title(assessment, status), severity, evidence, status=status)
        current["remediation"] = exposure_action(evidence, status)
        current["id"] = stable_id("exposure", CHECK, node_id(assessment.resource), node_id(assessment.origin), assessment.kind)
        output.append(current)
    output.extend(coverage_findings(snapshot, resources))
    output.extend(gcp_public_policy_findings(snapshot, resources))
    output.extend(gcp_service_account_impersonation_findings(snapshot, resources))
    output.extend(gcp_default_object_acl_findings(snapshot, resources))
    output.extend(gcp_authorized_dataset_future_view_findings(snapshot, resources))
    output.extend(gcp_bigtable_external_reader_findings(snapshot, resources))
    output.extend(gcp_source_repository_external_reader_findings(snapshot, resources))
    output.extend(gcp_cloud_tasks_external_enqueuer_findings(snapshot, resources))
    output.extend(gcp_scheduler_oidc_target_findings(snapshot, resources))
    output.extend(gcp_pubsub_oidc_push_findings(snapshot, resources))
    output.extend(gcp_artifact_public_reader_findings(snapshot, resources))
    output.extend(gcp_pubsub_public_grant_findings(snapshot, resources))
    output.extend(gcp_secret_external_accessor_findings(snapshot, resources))
    output.extend(gcp_kms_external_decrypter_findings(snapshot, resources))
    output.extend(gcp_logging_cross_project_sink_findings(snapshot, resources))
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
    assessments = [a for a in assess(snapshot, resources) if a.verdict() in ("FAIL", "UNKNOWN")
                   and a.kind not in ("external_share", "cross_project_peering")]
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
                ("azure", "directory_federated_credential"): azure_federated_credential,
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
