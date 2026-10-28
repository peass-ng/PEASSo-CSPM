"""Web PubSub foreign private links use the collected child list and named ACL."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
SERVICE = SCOPE + "/resourceGroups/rg/providers/Microsoft.SignalRService/webPubSub/pubsub"
CONNECTION = SERVICE + "/privateEndpointConnections/pubsub.foreign"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"
BASE = "https://management.azure.com"


def _scan(allowed=True, status="Approved", child_present=True, acl_present=True,
          hubs=None, shared_links=None, hubs_present=True, public="Disabled"):
    props = {"publicNetworkAccess": public, "hostName": "pubsub.webpubsub.azure.com",
             "publicPort": 443, "serverPort": 8443}
    if acl_present:
        props["networkACLs"] = {"defaultAction": "Deny", "publicNetwork": {"allow": ["ClientConnection"] if public == "Enabled" else []},
                                "privateEndpoints": [{"name": "pubsub.foreign",
                                                      "allow": ["RESTAPI"] if allowed else []}]}
    detail = {"id": SERVICE, "name": "pubsub", "type": "Microsoft.SignalRService/webPubSub",
              "properties": props}
    connection = {"id": CONNECTION, "name": "pubsub.foreign",
                  "type": "Microsoft.SignalRService/webPubSub/privateEndpointConnections",
                  "properties": {"provisioningState": "Succeeded", "privateEndpoint": {"id": FOREIGN},
                                 "privateLinkServiceConnectionState": {"status": status}}}

    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            assert body is None and url.startswith(BASE)
            path = url[len(BASE):].split("?", 1)[0]
            if path == SERVICE:
                return detail
            if path == SCOPE + "/providers/Microsoft.SignalRService/webPubSub":
                return {"value": [{"id": SERVICE, "name": "pubsub", "type": detail["type"]}]}
            if path == SERVICE + "/privateEndpointConnections":
                if not child_present:
                    raise RuntimeError("child unavailable")
                return {"value": [connection]}
            if path == SERVICE + "/hubs":
                if not hubs_present:
                    raise RuntimeError("hub LIST unavailable")
                return {"value": hubs or []}
            if path == SERVICE + "/sharedPrivateLinkResources":
                return {"value": shared_links or []}
            return {"value": []}

    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["web_pubsub"], transport=transport)
    findings = assess(snapshot, resources(snapshot))
    return snapshot, findings, transport


def test_private_only_foreign_connection_with_request_rights():
    snapshot, findings, transport = _scan()
    assert len(findings) == 1 and findings[0].verdict() == "FAIL"
    assert findings[0].external_ids == [FOREIGN]
    assert findings[0].ports == {"tcp": ((443, 443), (8443, 8443))}
    row, = [item for c in snapshot["collections"] if c["type"] == "web_pubsub" for item in c["items"]]
    assert row["_coverage"]["privateEndpointConnections"]["status"] == "collected"
    assert len(transport.calls) == len(set(transport.calls))


def test_denied_or_rejected_connection_is_not_a_share():
    _, findings, _ = _scan(allowed=False)
    assert findings[0].verdict() == "PASS"
    _, findings, _ = _scan(status="Rejected")
    assert findings[0].verdict() == "PASS"


def test_missing_child_or_acl_is_unknown():
    _, findings, _ = _scan(child_present=False)
    assert findings[0].verdict() == "UNKNOWN"
    _, findings, _ = _scan(acl_present=False)
    assert findings[0].verdict() == "UNKNOWN"


def test_hub_anonymous_and_outbound_targets_do_not_save_url_secrets():
    secret = "secret-token"
    hub = {"id": SERVICE + "/hubs/chat", "name": "chat", "type": "Microsoft.SignalRService/webPubSub/hubs",
           "properties": {"anonymousConnectPolicy": "allow",
                          "eventHandlers": [{"urlTemplate": "https://partner.example/" + secret + "?sig=" + secret,
                                             "systemEvents": ["connected"]}],
                          "eventListeners": [{"endpoint": {"type": "EventHub",
                                                              "fullyQualifiedNamespace": "partner.servicebus.windows.net",
                                                              "eventHubName": "events"}}]}}
    link = {"id": SERVICE + "/sharedPrivateLinkResources/partner", "name": "partner",
            "type": "Microsoft.SignalRService/webPubSub/sharedPrivateLinkResources",
            "properties": {"status": "Approved", "provisioningState": "Succeeded",
                           "privateLinkResourceId": "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/Microsoft.Web/sites/partner",
                           "requestMessage": secret}}
    snapshot, findings, transport = _scan(allowed=False, status="Rejected", hubs=[hub], shared_links=[link])
    assert len(findings) == 1 and findings[0].verdict() == "UNKNOWN"
    assert any(step["layer"] == "external_integrations" for step in findings[0].path)
    assert secret not in repr(snapshot)
    assert len(transport.calls) == len(set(transport.calls))


def test_missing_hub_list_is_unknown_when_no_private_share():
    _, findings, _ = _scan(status="Rejected", hubs_present=False)
    assert findings[0].verdict() == "UNKNOWN"


def test_anonymous_hub_on_public_client_listener():
    hub = {"id": SERVICE + "/hubs/chat", "name": "chat", "type": "Microsoft.SignalRService/webPubSub/hubs",
           "properties": {"anonymousConnectPolicy": "allow", "eventHandlers": [], "eventListeners": []}}
    _, findings, _ = _scan(status="Rejected", public="Enabled", hubs=[hub])
    assert findings[0].verdict() == "FAIL" and findings[0].authenticated is False
