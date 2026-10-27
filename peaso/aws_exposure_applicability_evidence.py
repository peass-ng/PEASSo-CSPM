"""Attach bounded recorded applicability witnesses to AWS Exposure findings.

The underlying checks own the verdict. This module only makes the facts used
by those checks explicit in the finding sent to a reviewer.
"""
from __future__ import annotations

from ipaddress import ip_network


SUBNET = "aws.claude_a.vpc.in_use_subnet_no_auto_public_ip"
CUSTOMER_SG = "aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis"
PUBLIC_RANGE_SG = "aws.claude_a.vpc.sg_no_public_ip_any_port"
SSM = "aws.cb.ssm.block_public_document_sharing"
SETTING_ID = "/ssm/documents/console/public-sharing-permission"


def _complete(index, kind):
    rows = index.get("collections", {}).get(kind, ())
    return bool(rows) and all(row.get("status") in ("collected", "empty") for row in rows)


def _rows(index, kind):
    return [row.get("data", {}) for row in index.get(kind, ())]


def _specific_public_rule(item):
    from peaso.checks.claude_aws_a_common import prowler_sg_open
    for rule in item.get("IpPermissions", ()):
        if not isinstance(rule, dict) or not prowler_sg_open(rule, "-1", any_address=False, all_ports=True):
            continue
        for family, field in ((4, "IpRanges"), (6, "Ipv6Ranges")):
            key = "CidrIp" if family == 4 else "CidrIpv6"
            for source in rule.get(field, ()):
                cidr = source.get(key) if isinstance(source, dict) else None
                try:
                    network = ip_network(cidr, strict=False)
                except (ValueError, TypeError):
                    continue
                if network.version == family and network.is_global and network.prefixlen > 0:
                    return {"protocol": rule.get("IpProtocol"), "from_port": rule.get("FromPort"),
                            "to_port": rule.get("ToPort"), "source_kind": "specific_public_cidr"}
    return None


def augment(check_id, status, evidence, item, index):
    """Return a copy with verified witnesses; leave inconclusive rows alone."""
    if status != "FAIL" or not isinstance(evidence, dict):
        return evidence
    extra = {}
    if check_id == SUBNET and evidence.get("map_public_ip_on_launch") is True and _complete(index, "network_interface"):
        subnet_id = item.get("SubnetId")
        count = sum(eni.get("SubnetId") == subnet_id for eni in _rows(index, "network_interface"))
        if count > 0:
            extra = {"matching_network_interface_count": count, "in_use_from_collected_eni": True}
    elif check_id == CUSTOMER_SG and evidence.get("world_ingress_rule_found") is True:
        enis = evidence.get("customer_enis")
        if isinstance(enis, list) and enis:
            extra = {"customer_network_interface_count": len(enis), "any_port_control": True}
    elif check_id == PUBLIC_RANGE_SG and evidence.get("specific_public_range_match") is True:
        matched = _specific_public_rule(item)
        if matched:
            extra = {"matched_public_range_rule": matched, "any_port_control": True}
    elif check_id == SSM and evidence.get("setting_value") == "Enable" and _complete(index, "ssm_service_settings"):
        matches = [row.get("ServiceSetting") for row in _rows(index, "ssm_service_settings")
                   if isinstance(row.get("ServiceSetting"), dict) and row["ServiceSetting"].get("SettingId") == SETTING_ID]
        if len(matches) == 1 and matches[0].get("SettingValue") == "Enable":
            extra = {"setting_id": SETTING_ID, "public_document_sharing_enabled": True}
    return {**evidence, **extra} if extra else evidence


def observed(finding):
    """Short source-bound explanation for the four historical prompt gaps."""
    if not isinstance(finding, dict) or finding.get("status") != "FAIL":
        return None
    cid, evidence = finding.get("check_id"), finding.get("evidence")
    if not isinstance(evidence, dict):
        return None
    if cid == SUBNET and evidence.get("map_public_ip_on_launch") is True:
        count = evidence.get("matching_network_interface_count")
        if type(count) is int and count > 0 and evidence.get("in_use_from_collected_eni") is True:
            return ("MapPublicIpOnLaunch is true for this subnet.\n"
                    f"{count} collected network interface{'s' if count != 1 else ''} reference this subnet.\n"
                    "New instances launched here may receive public IPv4 addresses.\n"
                    "Their services could accept internet traffic if routes and network rules also allow it.")
    if cid == CUSTOMER_SG and evidence.get("world_ingress_rule_found") is True:
        enis = evidence.get("customer_enis")
        count = evidence.get("customer_network_interface_count")
        if type(count) is not int and isinstance(enis, list) and enis:
            count = len(enis)
        if type(count) is int and count > 0:
            return ("A world-source ingress rule opens at least one port.\n"
                    f"{count} attached network interface{'s' if count != 1 else ''} are customer-managed.\n"
                    "Services on those interfaces could accept outside connections if routes also allow traffic.\n"
                    "People using those services may encounter unsolicited requests.")
    if cid == PUBLIC_RANGE_SG and evidence.get("specific_public_range_match") is True:
        rule = evidence.get("matched_public_range_rule")
        if isinstance(rule, dict) and rule.get("source_kind") == "specific_public_cidr":
            protocol, low, high = rule.get("protocol"), rule.get("from_port"), rule.get("to_port")
            port = (f"{protocol} port {low}" if type(low) is int and low == high else
                    f"{protocol} ports {low}–{high}" if type(low) is int and type(high) is int else
                    "all ports")
            return (f"A security group ingress rule allows {port} from a specific public CIDR.\n"
                    "Services attached to this group could accept connections from that range.\n"
                    "People outside the account may reach those services if public addressing and routes also allow traffic.")
        return ("A security group ingress rule allows at least one port from a specific public CIDR.\n"
                "Services attached to this group could accept connections from that range.\n"
                "People outside the account may reach those services if public addressing and routes also allow traffic.")
    if cid == SSM and evidence.get("setting_value") == "Enable" and evidence.get("setting_id", SETTING_ID) == SETTING_ID:
        return ("The /ssm/documents/console/public-sharing-permission setting is Enable.\n"
                "Public SSM document sharing is allowed in this scope.\n"
                "Documents shared this way could be read by people outside the account.")
    return None
