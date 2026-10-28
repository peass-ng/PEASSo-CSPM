"""PostgreSQL Flexible Server PgBouncer and foreign private endpoint paths."""
from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
SERVER = SCOPE + "/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/dbserver"
FOREIGN = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/peer/providers/Microsoft.Network/privateEndpoints/db"
ARM = "https://management.azure.com"


def _scan(*, public="Disabled", pgbouncer="true", foreign=True, embedded=False, deny_private=False, cluster=False):
    server = {"id": SERVER, "name": "dbserver", "type": "Microsoft.DBforPostgreSQL/flexibleServers",
              "properties": {"fullyQualifiedDomainName": "dbserver.postgres.database.azure.com",
                             "network": {"publicNetworkAccess": public}}}
    if cluster:
        server["properties"]["cluster"] = {"clusterSize": 2}
    connection = {"id": SERVER + "/privateEndpointConnections/link.123", "name": "link.123",
                  "type": "Microsoft.DBforPostgreSQL/flexibleServers/privateEndpointConnections",
                  "properties": {"privateEndpoint": {"id": FOREIGN},
                                 "privateLinkServiceConnectionState": {"status": "Approved"},
                                 "provisioningState": "Ready", "description": "secret-do-not-copy"}}
    if embedded:
        server["properties"]["privateEndpointConnections"] = [connection]
    configuration = {"id": SERVER + "/configurations/pgbouncer.enabled", "name": "pgbouncer.enabled",
                     "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
                     "properties": {"value": pgbouncer}}
    firewall = {"id": SERVER + "/firewallRules/allow", "name": "allow",
                "type": "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
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
            if path == SCOPE + "/providers/Microsoft.DBforPostgreSQL/flexibleServers":
                assert "api-version=2025-08-01" in url
                return {"value": [server]}
            if path == SERVER + "/privateEndpointConnections":
                if deny_private:
                    raise RuntimeError("private endpoint LIST unavailable")
                return {"value": [connection] if foreign else []}
            if path == SERVER + "/configurations":
                return {"value": [configuration]}
            if path == SERVER + "/firewallRules":
                return {"value": [firewall] if public == "Enabled" else []}
            if path.startswith(SERVER + "/"):
                return {"value": []}
            if path == SERVER:
                return server
            raise AssertionError(url)
    transport = Transport()
    snapshot = azure.collect({"scopes": [SCOPE], "auth": {}, "options": {"concurrency": 1, "retries": 0}},
                             requirements=["postgresql_flexible_server"], transport=transport)
    return snapshot, transport


def test_private_link_and_pgbouncer_ports_with_embedded_and_child_inventory():
    for embedded in (False, True):
        snapshot, transport = _scan(embedded=embedded)
        result, = assess(snapshot, resources(snapshot))
        assert result.verdict() == "FAIL" and result.external_ids == [FOREIGN]
        assert result.ports == {"tcp": ((5432, 5432), (6432, 6432))}
        assert len(transport.calls) == len(set(transport.calls)) == snapshot["metadata"]["calls"]
        assert ("/privateEndpointConnections?" in repr(transport.calls)) is not embedded
        assert "secret-do-not-copy" not in repr(snapshot)


def test_public_firewall_and_disabled_pgbouncer():
    snapshot, _ = _scan(public="Enabled", pgbouncer="false", foreign=False)
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "FAIL" and result.ports == {"tcp": ((5432, 5432),)}


def test_denied_private_endpoint_list_does_not_become_empty():
    snapshot, _ = _scan(deny_private=True)
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "UNKNOWN"


def test_elastic_cluster_worker_pgbouncer_port():
    snapshot, _ = _scan(cluster=True)
    result, = assess(snapshot, resources(snapshot))
    assert result.verdict() == "FAIL"
    assert result.ports == {"tcp": ((5432, 5432), (6432, 6432), (8432, 8432))}
