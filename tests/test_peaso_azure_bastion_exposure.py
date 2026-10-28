"""Azure Bastion client and shareable-link exposure from native ARM facts."""

import json
from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport


HOST = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/bastionHosts/host"
PIP = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip"
VNET = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
SUBNET = VNET + "/subnets/AzureBastionSubnet"
VM = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def result(properties, sku="Standard", extra=()):
    host = {"id": HOST, "name": "host", "type": "Microsoft.Network/bastionHosts",
            "sku": {"name": sku}, "properties": {"provisioningState": "Succeeded", **properties}}
    collections = [{"type": "bastion_host", "scope": SCOPE, "service": "Microsoft.Network",
                    "status": "collected", "items": [host]}, *extra]
    snapshot = make_snapshot("azure", [SCOPE], collections)
    return next(row for row in assess(snapshot, resources(snapshot)) if row.resource["type"] == "bastion_host")


def dedicated(**overrides):
    return {"enablePrivateOnlyBastion": False,
            "ipConfigurations": [{"properties": {"publicIPAddress": {"id": PIP},
                                               "subnet": {"id": SUBNET}, "provisioningState": "Succeeded"}}],
            **overrides}


def network():
    return ({"type": "public_ip", "scope": SCOPE, "service": "Microsoft.Network", "status": "collected",
             "items": [{"id": PIP, "properties": {"ipAddress": "8.8.8.8"}}]},
            {"type": "subnet", "scope": SCOPE, "service": "Microsoft.Network", "status": "collected",
             "items": [{"id": SUBNET, "properties": {}}]})


def test_dedicated_public_and_private_only_bastion():
    public = result(dedicated(), extra=network())
    assert public.verdict() == "FAIL" and public.ports == {"tcp": ((443, 443),)}
    assert public.addresses == ["8.8.8.8"]
    private = result(dedicated(enablePrivateOnlyBastion=True), sku="Premium", extra=network())
    assert private.verdict() == "PASS" and private.ports == {}
    assert result(dedicated(), extra=()).verdict() == "UNKNOWN"


def test_developer_shared_endpoint_ip_rules():
    public = result({"dnsName": "shared.bastionglobal.azure.com", "ipConfigurations": [],
                     "networkAcls": {"ipRules": [{"addressPrefix": "0.0.0.0/0"}]}}, sku="Developer")
    assert public.verdict() == "FAIL" and public.ports == {"tcp": ((443, 443),)}
    restricted = result({"dnsName": "shared.bastionglobal.azure.com", "ipConfigurations": [],
                         "networkAcls": {"ipRules": [{"addressPrefix": "10.0.0.0/8"}]}}, sku="Developer")
    assert restricted.verdict() == "PASS"
    malformed = result({"dnsName": "shared.bastionglobal.azure.com", "ipConfigurations": [],
                        "networkAcls": {"ipRules": [{"addressPrefix": "garbled"}]}}, sku="Developer")
    assert malformed.verdict() == "UNKNOWN"


def test_dedicated_bastion_subnet_nsg_can_close_client_port():
    nsg = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/bastion"
    pip, subnet = network()
    subnet["items"][0]["properties"]["networkSecurityGroup"] = {"id": nsg}
    rules = {"type": "nsg", "scope": SCOPE, "service": "Microsoft.Network", "status": "collected",
             "items": [{"id": nsg, "properties": {"securityRules": [{"name": "deny",
             "properties": {"priority": 100, "direction": "Inbound", "access": "Deny", "protocol": "Tcp",
                            "sourceAddressPrefix": "*", "destinationAddressPrefix": "*",
                            "destinationPortRange": "443"}}]}}]}
    finding = result(dedicated(), extra=(pip, subnet, rules))
    assert finding.verdict() == "PASS" and finding.ports == {}


def test_shareable_link_presence_is_detected_without_retaining_url_token():
    host = {"id": HOST, "name": "host", "type": "Microsoft.Network/bastionHosts",
            "sku": {"name": "Standard"}, "properties": {"provisioningState": "Succeeded",
            "enablePrivateOnlyBastion": False, "enableShareableLink": True,
            "ipConfigurations": [{"properties": {"publicIPAddress": {"id": PIP}, "subnet": {"id": SUBNET}}}],
            "sessionRecordingConfiguration": {"secret": "sensitive-marker"}}}
    api = Transport({SCOPE + "/providers/Microsoft.Network/bastionHosts": {"value": [host]},
                     HOST: host, HOST + "/getShareableLinks": {"value": [{"vm": {"id": VM},
                         "bsl": "https://shared.example.test/api/sensitive-marker"}]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["bastion_host"], transport=api)
    calls = [urlsplit(url).path for url in api.calls]
    assert calls.count(HOST) == 1 and calls.count(HOST + "/getShareableLinks") == 1
    assert "sensitive-marker" not in json.dumps(snapshot)
    finding = next(row for row in assess(snapshot, resources(snapshot)) if row.resource["type"] == "bastion_host")
    assert finding.verdict() == "FAIL" and finding.external_ids == [VM]
    assert finding.unresolved  # Synthetic scan omitted the public IP and subnet resources.


def test_enabled_shareable_link_with_failed_read_is_unknown():
    row = result({"enablePrivateOnlyBastion": True, "enableShareableLink": True,
                  "ipConfigurations": []}, sku="Premium")
    assert row.verdict() == "UNKNOWN"
