"""Azure AI Search private endpoints can share an otherwise private service."""
from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Search/searchServices/index"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/peer/providers/Microsoft.Network/privateEndpoints/index"
LOCAL = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/index"


def _assessment(public="Disabled", remote=None, state="Approved", provisioning="Succeeded", malformed=False):
    connections = [] if remote is None else [{"id": RID + "/privateEndpointConnections/link",
        "properties": {"privateEndpoint": {"id": remote},
                       "privateLinkServiceConnectionState": {"status": state},
                       "provisioningState": provisioning}}]
    props = {"publicNetworkAccess": public, "endpoint": "https://index.search.windows.net",
             "networkRuleSet": {"ipRules": []}, "privateEndpointConnections": connections}
    if malformed:
        props["_coverage"] = {"privateEndpointConnections": {"status": "malformed"}}
        props.pop("privateEndpointConnections")
    row = {"id": RID, "name": "index", "type": "Microsoft.Search/searchServices", "properties": props}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "search_service", "scope": SCOPE,
        "service": "Microsoft.Search", "status": "collected", "items": [row]}])
    return next(a for a in assess(snapshot, resources(snapshot)) if a.resource["type"] == "search_service")


def test_private_search_service_linked_to_foreign_subscription_is_shared():
    a = _assessment(remote=FOREIGN)
    assert a.verdict() == "FAIL" and a.external_ids == [FOREIGN]
    assert a.ports == {"tcp": ((443, 443),)}
    assert any(step["layer"] == "private_link_share" for step in a.path)
    assert _assessment(remote=LOCAL).verdict() == "PASS"
    assert _assessment(remote=FOREIGN, state="Pending").verdict() == "PASS"


def test_incomplete_private_link_only_blocks_claim_of_isolation():
    assert _assessment(remote=FOREIGN, provisioning="Updating").verdict() == "UNKNOWN"
    assert _assessment(malformed=True).verdict() == "UNKNOWN"
    assert _assessment(public="Enabled", malformed=True).verdict() == "FAIL"
