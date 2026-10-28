"""Relay native collection and exposure use only credential-free LIST data."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.collectors.azure_relay_native import KIND
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
NS = SCOPE + "/resourceGroups/rg/providers/Microsoft.Relay/namespaces/relayns"
HYBRID = NS + "/hybridConnections/hybrid"
WCF = NS + "/wcfRelays/wcf"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/peer/providers/Microsoft.Network/privateEndpoints/relay"
BASE = "https://management.azure.com"
VERSION = "?api-version=2024-01-01"


def _namespace(public="Enabled", private=False):
    return {"id": NS, "name": "relayns", "type": "Microsoft.Relay/namespaces",
            "properties": {"provisioningState": "Succeeded", "publicNetworkAccess": public,
                           "serviceBusEndpoint": "https://relayns.servicebus.windows.net:443/",
                           "privateEndpointConnections": [] if not private else [{"properties": {
                               "privateEndpoint": {"id": FOREIGN},
                               "privateLinkServiceConnectionState": {"status": "Approved"},
                               "provisioningState": "Succeeded"}}],
                           }}


def _scan(public="Enabled", private=False, fail_children=False):
    rule = {"id": NS + "/authorizationRules/root", "name": "root",
            "type": "Microsoft.Relay/namespaces/authorizationRules",
            "properties": {"rights": ["Manage", "Send"], "primaryKey": "secret-do-not-copy"}}
    hybrid = {"id": HYBRID, "name": "hybrid", "type": "Microsoft.Relay/namespaces/hybridConnections",
              "properties": {"listenerCount": 1, "requiresClientAuthorization": False,
                             "userMetadata": "secret-do-not-copy"}}
    wcf = {"id": WCF, "name": "wcf", "type": "Microsoft.Relay/namespaces/wcfRelays",
           "properties": {"listenerCount": 1, "relayType": "NetTcp",
                          "requiresClientAuthorization": True, "requiresTransportSecurity": True}}
    pages = {SCOPE + "/providers/Microsoft.Relay/namespaces": [_namespace(public, private)],
             NS + "/authorizationRules": [rule], NS + "/hybridConnections": [hybrid],
             HYBRID + "/authorizationRules": [], NS + "/wcfRelays": [wcf],
             WCF + "/authorizationRules": []}
    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            if body is not None:
                return {"data": []}
            assert url.startswith(BASE)
            if url.endswith("?api-version=2026-01-01"):
                path = url[len(BASE):].split("?", 1)[0]
                return {"value": pages[path]} if path in pages else _namespace(public, private)
            assert url.endswith(VERSION)
            if fail_children:
                raise RuntimeError("child LIST unavailable")
            return {"value": pages[url[len(BASE):-len(VERSION)]]}
    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=[KIND], transport=transport)
    selected, = [row for row in snapshot["collections"] if row["type"] == KIND]
    return snapshot, selected, transport


def test_public_relay_listener_ports_anonymous_clients_and_sas_rights():
    snapshot, selected, transport = _scan()
    assert selected["status"] == "collected"
    assert len(transport.calls) == len(set(transport.calls)) == snapshot["metadata"]["calls"]
    assert "secret-do-not-copy" not in repr(snapshot)
    result = assess(snapshot, resources(snapshot))
    assert len(result) == 1 and result[0].verdict() == "FAIL"
    assert result[0].ports == {"tcp": ((443, 443), (5671, 5671), (9352, 9353))}
    assert result[0].authenticated is False
    assert any(step["layer"] == "sas_authorization" for step in result[0].path)


def test_private_only_relay_reports_foreign_approved_endpoint():
    snapshot, _, _ = _scan(public="Disabled", private=True)
    result = assess(snapshot, resources(snapshot))
    assert result[0].verdict() == "FAIL" and result[0].external_ids == [FOREIGN]
    snapshot, _, _ = _scan(public="Disabled", private=False)
    assert assess(snapshot, resources(snapshot))[0].verdict() == "PASS"


def test_child_inventory_failure_is_unknown_without_duplicate_namespace_collection():
    snapshot, selected, _ = _scan(fail_children=True)
    assert selected["items"][0]["_coverage"]["relayExposure"]["status"] == "unknown"
    assert assess(snapshot, resources(snapshot))[0].verdict() == "UNKNOWN"
