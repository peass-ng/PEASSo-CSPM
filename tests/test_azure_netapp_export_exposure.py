"""NetApp volume export policy and foreign peering evidence."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors.azure_storage_backup_native import _project
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
VNET = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.NetApp/netAppAccounts/a/capacityPools/p/volumes/v"
REMOTE = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/other/providers/Microsoft.Network/virtualNetworks/foreign"


def _volume(rules, protocols=("NFSv4.1",)):
    raw = {"id": RID, "name": "a/p/v", "type": "Microsoft.NetApp/netAppAccounts/capacityPools/volumes",
           "properties": {"protocolTypes": list(protocols), "subnetId": VNET + "/subnets/netapp",
                          "exportPolicy": {"rules": rules},
                          "mountTargets": [{"ipAddress": "10.0.0.4"}]}}
    return _project(raw, RID, "Volumes_List", "2026-01-01")


def _decision(rules, protocols=("NFSv4.1",), foreign=True):
    peerings = [{"id": VNET + "/virtualNetworkPeerings/foreign", "properties": {
        "remoteVirtualNetwork": {"id": REMOTE}, "peeringState": "Connected",
        "allowVirtualNetworkAccess": True}}] if foreign else []
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "netapp_volume", "scope": SCOPE, "service": "Microsoft.NetApp",
         "status": "collected", "items": [_volume(rules, protocols)]},
        {"type": "vnet_peering", "scope": SCOPE, "service": "Microsoft.Network",
         "status": "collected", "items": peerings},
    ])
    return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "netapp_volume")


def test_foreign_peered_vnet_and_broad_nfs_export():
    rule = {"ruleIndex": 1, "allowedClients": "0.0.0.0/0", "nfsv41": True, "unixReadWrite": True}
    row = _decision([rule])
    assert row.verdict() == "FAIL" and row.external_ids == [REMOTE]
    assert row.ports == {"tcp": ((2049, 2049),)}
    assert _decision([rule], foreign=False).verdict() == "UNKNOWN"


def test_netapp_export_order_and_smb_acl_limit():
    deny = {"ruleIndex": 1, "allowedClients": "10.0.0.0/8", "nfsv41": True,
            "unixReadOnly": False, "unixReadWrite": False}
    broad = {"ruleIndex": 2, "allowedClients": "0.0.0.0/0", "nfsv41": True,
             "unixReadOnly": True}
    assert _decision([deny, broad]).verdict() == "UNKNOWN"
    assert _decision([], protocols=("NFSv4.1",)).verdict() == "PASS"
    assert _decision([], protocols=("CIFS",)).verdict() == "UNKNOWN"
