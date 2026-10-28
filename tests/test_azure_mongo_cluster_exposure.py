"""Mongo vCore public, Data API, private link, and Entra grant paths."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CLUSTER = SCOPE + "/resourceGroups/rg/providers/Microsoft.DocumentDB/mongoClusters/mongocluster"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/peer/providers/Microsoft.Network/privateEndpoints/mongo"
ARM = "https://management.azure.com"


def _scan(*, public="Enabled", data_api="Enabled", firewall=True, foreign=True, embedded=False,
          deny_firewall=False, bypass="None"):
    cluster = {"id": CLUSTER, "name": "mongocluster", "type": "Microsoft.DocumentDB/mongoClusters",
               "properties": {"provisioningState": "Succeeded", "publicNetworkAccess": public,
                              "networkBypassMode": bypass, "dataApi": {"mode": data_api},
                              "authConfig": {"allowedModes": ["MicrosoftEntraID"]},
                              "administrator": {"password": "secret-do-not-copy"}}}
    connection = {"id": CLUSTER + "/privateEndpointConnections/link", "name": "link",
                  "type": "Microsoft.DocumentDB/mongoClusters/privateEndpointConnections",
                  "properties": {"privateEndpoint": {"id": FOREIGN},
                                 "privateLinkServiceConnectionState": {"status": "Approved", "description": "secret-do-not-copy"}}}
    if embedded:
        cluster["properties"]["privateEndpointConnections"] = [connection]
    rule = {"id": CLUSTER + "/firewallRules/open", "name": "open",
            "type": "Microsoft.DocumentDB/mongoClusters/firewallRules",
            "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}
    user = {"id": CLUSTER + "/users/33333333-3333-3333-3333-333333333333", "name": "33333333-3333-3333-3333-333333333333",
            "type": "Microsoft.DocumentDB/mongoClusters/users",
            "properties": {"identityProvider": {"type": "MicrosoftEntraID", "properties": {"principalType": "servicePrincipal"}},
                           "roles": [{"db": "admin", "role": "root"}], "credential": "secret-do-not-copy"}}
    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            if body is not None:
                return {"data": []}
            assert url.startswith(ARM)
            path = url[len(ARM):].split("?", 1)[0]
            if path == SCOPE + "/providers/Microsoft.DocumentDB/mongoClusters":
                assert "api-version=2026-06-01" in url
                return {"value": [cluster]}
            if path == CLUSTER:
                assert "api-version=2026-06-01" in url
                return cluster
            if path == CLUSTER + "/firewallRules":
                if deny_firewall:
                    raise RuntimeError("firewall LIST unavailable")
                return {"value": [rule] if firewall else []}
            if path == CLUSTER + "/privateEndpointConnections":
                return {"value": [connection] if foreign else []}
            if path == CLUSTER + "/users":
                return {"value": [user]}
            raise AssertionError(url)
    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["mongo_cluster"], transport=transport)
    return snapshot, transport


def test_public_mongo_and_data_api_ports_with_grants():
    snapshot, transport = _scan()
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "FAIL"
    assert result.ports == {"tcp": ((443, 443), (10260, 10260))}
    assert any(step["layer"] == "entra_data_grants" for step in result.path)
    assert len(transport.calls) == len(set(transport.calls)) == snapshot["metadata"]["calls"]
    assert "secret-do-not-copy" not in repr(snapshot)


def test_private_only_foreign_link_and_embedded_reuse():
    snapshot, transport = _scan(public="Disabled", embedded=True)
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "FAIL" and result.external_ids == [FOREIGN]
    assert not any("/privateEndpointConnections?" in url for url in transport.calls)
    snapshot, _ = _scan(public="Disabled", foreign=False, data_api="Disabled")
    assert assess(snapshot, resources(snapshot))[0].verdict() == "PASS"


def test_public_rule_absent_and_denied_rule_stay_distinct():
    snapshot, _ = _scan(firewall=False, foreign=False)
    assert assess(snapshot, resources(snapshot))[0].verdict() == "PASS"
    snapshot, _ = _scan(deny_firewall=True, foreign=False)
    assert assess(snapshot, resources(snapshot))[0].verdict() == "UNKNOWN"


def test_cosmos_service_bypass_is_not_treated_as_closed_private_cluster():
    snapshot, _ = _scan(public="Disabled", foreign=False, bypass="AzureCosmosDB")
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "UNKNOWN"
    assert any(step["layer"] == "network_bypass" for step in result.path)
