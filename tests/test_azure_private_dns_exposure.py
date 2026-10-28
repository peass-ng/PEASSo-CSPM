"""Private DNS links expose zone records to linked virtual networks."""
from peaso.analysis.internet_exposure import _azure_private_dns_link, assess
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
ZONE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/internal.example"
LINK = ZONE + "/virtualNetworkLinks/peer"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/peer/providers/Microsoft.Network/virtualNetworks/peer"
LOCAL = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/own"


def _item(remote, *, state="Completed", provisioning="Succeeded", registration=False):
    return {"id": LINK, "name": "peer", "type": "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
            "properties": {"virtualNetworkLinkState": state, "provisioningState": provisioning,
                           "virtualNetwork": {"id": remote}, "registrationEnabled": registration}}


def _verdict(item):
    return _azure_private_dns_link(None, None, {"type": "private_dns_link", "data": item})


def test_foreign_resolution_and_registration_are_detected():
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "private_dns_link", "scope": SCOPE,
        "service": "Microsoft.Network", "status": "collected", "items": [_item(FOREIGN, registration=True)]}])
    result = assess(snapshot, resources(snapshot))
    assert len(result) == 1
    assert result[0].verdict() == "FAIL"
    assert result[0].external_ids == [FOREIGN]
    assert result[0].path[0]["registration_enabled"] is True


def test_same_subscription_and_inactive_links_do_not_claim_external_share():
    assert _verdict(_item(LOCAL)).verdict() == "PASS"
    assert _verdict(_item(FOREIGN, state="Done")).verdict() == "FAIL"
    assert _verdict(_item(FOREIGN, state="Disconnected")).verdict() == "PASS"
    assert _verdict(_item(FOREIGN, provisioning="Failed")).verdict() == "PASS"
    assert _verdict(_item(FOREIGN, state="InProgress")).verdict() == "UNKNOWN"
    assert _verdict(_item(None)).verdict() == "UNKNOWN"
