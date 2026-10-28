"""Notification Hubs exposure inventory contains rights but no credentials."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors.azure_notification_hubs_native import KIND, collect
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/test"
NS = SCOPE + "/resourceGroups/rg/providers/Microsoft.NotificationHubs/namespaces/ns"
HUB = NS + "/notificationHubs/hub"


def test_cached_lists_project_credentials_out_and_detect_public_rights():
    namespace = {"id": NS, "name": "ns", "type": "Microsoft.NotificationHubs/namespaces",
        "properties": {"publicNetworkAccess": "Enabled", "serviceBusEndpoint": "https://ns.servicebus.windows.net/",
            "networkAcls": {"publicNetworkRule": {"rights": ["Listen"]}, "ipRules": []},
            "privateEndpointConnections": [],
            "pnsCredentials": {"gcmCredential": {"googleApiKey": "secret-do-not-copy"}}}}
    hub = {"id": HUB, "name": "hub", "type": "Microsoft.NotificationHubs/namespaces/notificationHubs",
        "properties": {"apnsCredential": {"token": "secret-do-not-copy"},
            "authorizationRules": [{"primaryKey": "secret-do-not-copy"}]}}
    ns_rule = {"id": NS + "/authorizationRules/root", "name": "root",
        "type": "Microsoft.NotificationHubs/namespaces/authorizationRules",
        "properties": {"rights": ["Manage", "Send"], "primaryKey": "secret-do-not-copy"}}
    hub_rule = {"id": HUB + "/authorizationRules/client", "name": "client",
        "type": "Microsoft.NotificationHubs/namespaces/notificationHubs/authorizationRules",
        "properties": {"rights": ["Listen"], "secondaryKey": "secret-do-not-copy"}}
    pages = {SCOPE + "/providers/Microsoft.NotificationHubs/namespaces": [[namespace]],
             NS + "/authorizationRules": [[ns_rule]], NS + "/notificationHubs": [[hub]],
             HUB + "/authorizationRules": [[hub_rule]]}

    class Reader:
        def __init__(self):
            self.collections = []
            self.urls = []

        def pages(self, request, url):
            self.urls.append(url)
            path = url.removeprefix("https://management.azure.com").split("?", 1)[0]
            yield from pages[path]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                items = [item for page in fetch() for item in page]
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": items})

    reader = Reader()
    collect(reader, None, [SCOPE], {KIND})
    assert len(reader.urls) == len(set(reader.urls)) == 4
    assert "secret-do-not-copy" not in repr(reader.collections)
    item = reader.collections[0]["items"][0]
    assert item["authorizationRules"][0]["rights"] == ["Manage", "Send"]
    assert item["hubs"][0]["authorizationRules"][0]["rights"] == ["Listen"]
    assert item["properties"]["pushProviders"] == ["gcmCredential"]
    assert item["hubs"][0]["pushProviders"] == ["apnsCredential"]
    snapshot = make_snapshot("azure", [SCOPE], reader.collections)
    result = assess(snapshot, resources(snapshot))
    assert len(result) == 1 and result[0].verdict() == "FAIL"
    assert result[0].addresses == ["https://ns.servicebus.windows.net/"]
    assert result[0].ports == {"tcp": ((443, 443),)}
    assert any(step["layer"] == "third_party_push_provider" for step in result[0].path)


def test_private_only_and_incomplete_acl_do_not_claim_public_path():
    from peaso.analysis.internet_exposure import _azure_notification_hub
    def outcome(props):
        return _azure_notification_hub(None, None, {"type": KIND, "data": {"properties": props,
            "authorizationRules": [], "hubs": []}}).verdict()
    base = {"publicNetworkAccess": "Enabled", "serviceBusEndpoint": "https://ns.servicebus.windows.net/",
            "privateEndpointConnections": []}
    assert outcome({**base, "networkAcls": {"publicNetworkRule": {"rights": []},
                    "ipRules": [{"ipMask": "10.0.0.0/8", "rights": ["Send"]}]}}) == "PASS"
    assert outcome({**base, "networkAcls": {"publicNetworkRule": {"rights": []},
                    "ipRules": [{"ipMask": "8.8.8.8/32", "rights": ["Send"]}]}}) == "FAIL"
    assert outcome({**base, "networkAcls": None}) == "UNKNOWN"
    assert outcome({**base, "publicNetworkAccess": "Disabled"}) == "PASS"
    assert outcome({**base, "enabled": False, "networkAcls": {"publicNetworkRule": {"rights": ["Send"]},
                    "ipRules": []}}) == "PASS"


def test_approved_cross_subscription_private_endpoint_is_exposure():
    from peaso.analysis.internet_exposure import _azure_notification_hub
    foreign = "/subscriptions/other/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"
    same = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"
    def outcome(remote, state="Approved", provisioning="Succeeded"):
        return _azure_notification_hub(None, None, {"type": KIND, "data": {"id": NS,
            "properties": {"publicNetworkAccess": "Disabled", "privateEndpointConnections": [
                {"privateEndpointId": remote, "status": state, "provisioningState": provisioning}]},
            "authorizationRules": [], "hubs": []}})
    outside = outcome(foreign)
    assert outside.verdict() == "FAIL" and outside.external_ids == [foreign]
    assert outcome(same).verdict() == "PASS"
    assert outcome(foreign, state="Pending").verdict() == "PASS"
    assert outcome(foreign, provisioning=None).verdict() == "UNKNOWN"


def test_selected_collector_uses_only_three_cached_read_paths():
    from peaso.collectors import azure
    foreign = "/subscriptions/other/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"
    ns = {"id": NS, "name": "ns", "type": "Microsoft.NotificationHubs/namespaces",
          "properties": {"publicNetworkAccess": "Disabled", "serviceBusEndpoint": "https://ns.servicebus.windows.net/",
              "networkAcls": {"publicNetworkRule": {"rights": ["Listen"]}, "ipRules": []},
              "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": foreign},
                  "privateLinkServiceConnectionState": {"status": "Approved"}, "provisioningState": "Succeeded"}}],
              "pnsCredentials": {"googleApiKey": "secret-do-not-copy"}}}
    base = "https://management.azure.com"
    urls = {base + SCOPE + "/providers/Microsoft.NotificationHubs/namespaces?api-version=2023-09-01": {"value": [ns]},
            base + NS + "/authorizationRules?api-version=2023-09-01": {"value": []},
            base + NS + "/notificationHubs?api-version=2023-09-01": {"value": []}}

    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=None):
            assert body is None and url in urls
            self.calls.append(url)
            return urls[url]

    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=[KIND], transport=transport)
    selected = [row for row in snapshot["collections"] if row["type"] == KIND]
    assert len(selected) == 1 and selected[0]["status"] == "collected"
    assert len(transport.calls) == len(set(transport.calls)) == snapshot["metadata"]["calls"] == 3
    assert "secret-do-not-copy" not in repr(snapshot)
    found = assess(snapshot, resources(snapshot))
    assert len(found) == 1 and found[0].verdict() == "FAIL" and found[0].external_ids == [foreign]
