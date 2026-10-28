"""MySQL Flexible Server custom listener ports and foreign private links."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
SERVER = SCOPE + "/resourceGroups/rg/providers/Microsoft.DBforMySQL/flexibleServers/db"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/peer/providers/Microsoft.Network/privateEndpoints/db"
ARM = "https://management.azure.com"


def _scan(*, public="Disabled", port=8888, foreign=True, allow_public=False, deny_private=False, embedded=False):
    server = {"id": SERVER, "name": "db", "type": "Microsoft.DBforMySQL/flexibleServers",
              "properties": {"databasePort": port, "fullyQualifiedDomainName": "db.mysql.database.azure.com",
                             "network": {"publicNetworkAccess": public}}}
    connection = {"id": SERVER + "/privateEndpointConnections/link", "name": "link",
                  "type": "Microsoft.DBforMySQL/flexibleServers/privateEndpointConnections",
                  "properties": {"privateEndpoint": {"id": FOREIGN if foreign else SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/db"},
                                 "privateLinkServiceConnectionState": {"status": "Approved"},
                                 "provisioningState": "Succeeded", "description": "secret-do-not-copy"}}
    if embedded:
        server["properties"]["privateEndpointConnections"] = [connection]
    firewall = {"id": SERVER + "/firewallRules/allow", "name": "allow",
                "type": "Microsoft.DBforMySQL/flexibleServers/firewallRules",
                "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}
    class Transport:
        tenant = verified_tenant = None
        def __init__(self): self.calls = []
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            if body is not None:
                return {"data": []}
            assert url.startswith(ARM)
            path = url[len(ARM):].split("?", 1)[0]
            if path == SCOPE + "/providers/Microsoft.DBforMySQL/flexibleServers":
                assert "api-version=2024-12-30" in url
                return {"value": [server]}
            if path == SERVER + "/privateEndpointConnections":
                assert "api-version=2024-12-30" in url
                if deny_private:
                    raise RuntimeError("private endpoint LIST unavailable")
                return {"value": [connection] if foreign else []}
            if path == SERVER + "/firewallRules":
                return {"value": [firewall] if allow_public else []}
            if path.startswith(SERVER + "/"):
                return {"value": []}
            if path == SERVER:
                return server
            raise AssertionError(url)
    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["mysql_flexible_server"], transport=transport)
    return snapshot, transport


def test_foreign_private_link_uses_configured_port_even_when_public_firewall_blocks():
    for public in ("Disabled", "Enabled"):
        snapshot, transport = _scan(public=public)
        result, = assess(snapshot, resources(snapshot))
        assert result.verdict() == "FAIL"
        assert result.external_ids == [FOREIGN]
        assert result.ports == {"tcp": ((8888, 8888),)}
        assert len(transport.calls) == len(set(transport.calls)) == snapshot["metadata"]["calls"]
        assert "secret-do-not-copy" not in repr(snapshot)


def test_public_custom_port_and_incomplete_private_inventory():
    snapshot, _ = _scan(public="Enabled", foreign=False, allow_public=True)
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "FAIL" and result.ports == {"tcp": ((8888, 8888),)}
    snapshot, _ = _scan(deny_private=True)
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "UNKNOWN"


def test_invalid_port_does_not_report_default_listener():
    snapshot, _ = _scan(public="Enabled", foreign=False, allow_public=True, port=70000)
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "UNKNOWN" and result.ports == {}


def test_embedded_private_link_reuses_parent_without_child_list():
    snapshot, transport = _scan(embedded=True)
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "FAIL" and result.external_ids == [FOREIGN]
    assert not any("/privateEndpointConnections?" in url for url in transport.calls)
    assert "secret-do-not-copy" not in repr(snapshot)
