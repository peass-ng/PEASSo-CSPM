"""SignalR foreign private endpoint request ACLs remain visible with public access off."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
SERVICE = SCOPE + "/resourceGroups/rg/providers/Microsoft.SignalRService/signalR/signal"
CONNECTION = SERVICE + "/privateEndpointConnections/signal.foreign"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"
LOCAL = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"
BASE = "https://management.azure.com"


def _scan(remote=FOREIGN, allowed=True, acl_present=True, public="Disabled", connections_present=True, connections_empty=False):
    acl = {"defaultAction": "Deny", "publicNetwork": {"allow": ["ClientConnection"] if public == "Enabled" else []}, "ipRules": [],
           "privateEndpoints": [{"name": "signal.foreign", "allow": ["ClientConnection"] if allowed else []}]}
    props = {"publicNetworkAccess": public, "hostName": "signal.service.signalr.net", "publicPort": 443,
             "serverPort": 8443,
             "privateEndpointConnections": [{"id": CONNECTION, "name": "signal.foreign",
                 "type": "Microsoft.SignalRService/signalR/privateEndpointConnections",
                 "properties": {"provisioningState": "Succeeded", "privateEndpoint": {"id": remote},
                                "privateLinkServiceConnectionState": {"status": "Approved"}}}]}
    if acl_present:
        props["networkACLs"] = acl
    if not connections_present:
        props.pop("privateEndpointConnections")
    elif connections_empty:
        props["privateEndpointConnections"] = []
    detail = {"id": SERVICE, "name": "signal", "type": "Microsoft.SignalRService/signalR",
              "properties": props}

    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            assert body is None and url.startswith(BASE)
            path = url[len(BASE):].split("?", 1)[0]
            if path == SERVICE:
                return detail
            if path == SCOPE + "/providers/Microsoft.SignalRService/signalR":
                return {"value": [{"id": SERVICE, "name": "signal", "type": detail["type"]}]}
            return {"value": []}

    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["signalr_service"], transport=transport)
    # Serverless upstream delivery is a separate ``external_event_delivery`` assessment.
    findings = [a for a in assess(snapshot, resources(snapshot)) if a.kind != "external_event_delivery"]
    return snapshot, findings, transport


def test_private_only_foreign_approved_connection_with_request_rights():
    snapshot, findings, transport = _scan()
    assert len(findings) == 1 and findings[0].verdict() == "FAIL"
    assert findings[0].external_ids == [FOREIGN]
    assert findings[0].ports == {"tcp": ((443, 443), (8443, 8443))}
    assert any(step["layer"] == "private_link_share" for step in findings[0].path)
    assert len(transport.calls) == len(set(transport.calls))
    assert sum(url.startswith(BASE + SERVICE + "?") for url in transport.calls) == 1


def test_private_acl_denies_or_connection_is_local():
    _, findings, _ = _scan(allowed=False)
    assert findings[0].verdict() == "PASS"
    _, findings, _ = _scan(remote=LOCAL)
    assert findings[0].verdict() == "PASS"
    _, findings, _ = _scan(acl_present=False, connections_empty=True)
    assert findings[0].verdict() == "PASS"


def test_missing_private_acl_is_unknown_when_public_disabled():
    _, findings, _ = _scan(acl_present=False)
    assert findings[0].verdict() == "UNKNOWN"


def test_public_path_remains_fail_when_private_acl_is_missing():
    _, findings, _ = _scan(connections_present=False, public="Enabled")
    assert findings[0].verdict() == "FAIL"
