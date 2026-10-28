"""Service Bus AMQP and private-link shares use collected namespace metadata."""
from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/bus"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"


def _assess(public="Enabled", action="Allow", remote=None, state="Approved", provisioning="Succeeded"):
    connections = [] if remote is None else [{"properties": {"privateEndpoint": {"id": remote},
        "privateLinkServiceConnectionState": {"status": state}, "provisioningState": provisioning}}]
    item = {"id": RID, "name": "bus", "type": "Microsoft.ServiceBus/namespaces",
        "properties": {"publicNetworkAccess": public, "serviceBusEndpoint": "https://bus.servicebus.windows.net",
                       "disableLocalAuth": True, "privateEndpointConnections": connections},
        "_coverage": {"networkRuleSet": {"status": "collected"}},
        "networkRuleSet": {"properties": {"publicNetworkAccess": public, "defaultAction": action,
                                           "ipRules": [], "trustedServiceAccessEnabled": False}}}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "servicebus_namespace", "scope": SCOPE,
        "service": "Microsoft.ServiceBus", "status": "collected", "items": [item]}])
    return next(a for a in assess(snapshot, resources(snapshot)) if a.resource["type"] == "servicebus_namespace")


def test_public_service_bus_reports_https_and_amqp_tls():
    a = _assess()
    assert a.verdict() == "FAIL"
    assert a.ports == {"tcp": ((443, 443), (5671, 5671))}
    assert _assess(action="Deny").verdict() == "PASS"


def test_foreign_private_endpoint_is_a_share_even_when_public_access_disabled():
    a = _assess(public="Disabled", remote=FOREIGN)
    assert a.verdict() == "FAIL" and a.external_ids == [FOREIGN]
    assert a.ports == {"tcp": ((443, 443), (5671, 5671))}
    assert _assess(public="Disabled", remote=FOREIGN, state="Pending").verdict() == "PASS"
    assert _assess(public="Disabled").verdict() == "PASS"


def test_unresolved_private_endpoint_prevents_false_isolation_verdict():
    assert _assess(action="Deny", remote=FOREIGN, provisioning="Updating").verdict() == "UNKNOWN"
    assert _assess(action="Deny", remote=FOREIGN, state="Pending").verdict() == "PASS"
