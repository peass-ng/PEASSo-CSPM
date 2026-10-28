"""Oracle SCAN ingress and Palo Alto Cloud NGFW public IP metadata."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors.azure_partner_network_native import ORACLE, PALO, NEXUS, _safe
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"


def _finding(kind, raw):
    item = _safe(raw, SCOPE, kind)
    snap = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SCOPE,
        "service": "Oracle.Database" if kind == ORACLE else "PaloAltoNetworks.Cloudngfw",
        "status": "collected", "items": [item]}])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == kind)


def test_oracle_cluster_public_source_cidr_is_surfaced():
    raw = {"id": SCOPE + "/resourceGroups/rg/providers/Oracle.Database/cloudVmClusters/c",
           "properties": {"nsgCidrs": [{"source": "0.0.0.0/0", "destinationPortRange": {"min": 1521, "max": 1521}}]}}
    result = _finding(ORACLE, raw)
    assert result.verdict() == "UNKNOWN"
    assert result.ports == {"tcp": ((1521, 1521),)}
    assert any(step["layer"] == "oracle_nsg" for step in result.path)


def test_palo_alto_public_ip_is_surfaced():
    raw = {"id": SCOPE + "/resourceGroups/rg/providers/PaloAltoNetworks.Cloudngfw/firewalls/f",
           "properties": {"networkProfile": {"networkType": "VNET", "publicIps": [
               {"address": "20.22.92.11", "resourceId": SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/p"}]}}}
    result = _finding(PALO, raw)
    assert result.verdict() == "UNKNOWN"
    assert result.addresses == ["20.22.92.11"]


def test_operator_nexus_vm_public_attachment_is_surfaced():
    raw = {"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.NetworkCloud/virtualMachines/v",
           "properties": {"networkAttachments": [{"attachedNetworkId": "network-id",
                                                  "ipv4Address": "20.22.92.12"}]}}
    result = _finding(NEXUS, raw)
    assert result.verdict() == "UNKNOWN"
    assert result.addresses == ["20.22.92.12"]
