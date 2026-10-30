"""Azure Managed Redis database child inventory uses one cached ARM list."""

from urllib.parse import urlsplit, parse_qs

from peaso.collectors import azure
from peaso.analysis.internet_exposure import assess
from peaso.snapshot import resources

SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB
CLUSTER = SCOPE + "/resourceGroups/rg/providers/Microsoft.Cache/redisEnterprise/cache"
DATABASE = CLUSTER + "/databases/default"


class Transport:
    tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

    def __init__(self, private_connections=()):
        self.calls = []
        self.private_connections = private_connections

    def request(self, url, *, body=None, audience=azure.ARM):
        assert body is None and audience == azure.ARM
        self.calls.append(url)
        path = urlsplit(url).path
        if path == SCOPE + "/providers/Microsoft.Cache/redisEnterprise":
            return {"value": [{"id": CLUSTER, "name": "cache",
                "type": "Microsoft.Cache/redisEnterprise", "properties": {
                    "publicNetworkAccess": "Enabled", "hostName": "cache.redis.azure.net"}}]}
        if path == CLUSTER:
            return {"id": CLUSTER, "name": "cache", "type": "Microsoft.Cache/redisEnterprise",
                    "properties": {"publicNetworkAccess": "Enabled", "hostName": "cache.redis.azure.net"}}
        if path == CLUSTER + "/databases":
            return {"value": [{"id": DATABASE, "name": "default",
                "type": "Microsoft.Cache/redisEnterprise/databases",
                "properties": {"port": 10000, "clientProtocol": "Encrypted"}}]}
        if path == CLUSTER + "/privateEndpointConnections":
            return {"value": list(self.private_connections)}
        return {"value": []}


def test_redis_enterprise_parent_and_database_are_read_once():
    transport = Transport()
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["redis_enterprise_cluster", "redis_enterprise_database"], transport=transport)
    parent = next(c for c in snapshot["collections"] if c["type"] == "redis_enterprise_cluster")
    child = next(c for c in snapshot["collections"] if c["type"] == "redis_enterprise_database")
    assert parent["status"] == "collected"
    assert child["status"] == "collected" and child["items"][0]["properties"]["port"] == 10000
    assert sum(urlsplit(url).path == CLUSTER + "/databases" for url in transport.calls) == 1
    assert sum(urlsplit(url).path == CLUSTER + "/privateEndpointConnections" for url in transport.calls) == 1
    # The parent LIST/GET use the first version with cluster firewallRules;
    # the database and private endpoint children keep the stable version.
    redis = [url for url in transport.calls if "redisEnterprise" in urlsplit(url).path
             and "diagnosticSettings" not in urlsplit(url).path]
    parents = [url for url in redis if urlsplit(url).path.endswith(("/redisEnterprise", CLUSTER))]
    assert sum(urlsplit(url).path == CLUSTER for url in transport.calls) == 1
    assert parents and all(parse_qs(urlsplit(url).query).get("api-version") == ["2026-10-01-preview"]
                           for url in parents)
    assert all(parse_qs(urlsplit(url).query).get("api-version") == ["2025-07-01"]
               for url in redis if url not in parents)


def _private(remote, status="Approved", provisioning="Succeeded"):
    return {"id": CLUSTER + "/privateEndpointConnections/pec", "name": "pec",
            "type": "Microsoft.Cache/redisEnterprise/privateEndpointConnections",
            "properties": {"privateEndpoint": {"id": remote},
                           "privateLinkServiceConnectionState": {"status": status},
                           "provisioningState": provisioning}}


def test_managed_redis_private_connection_exposure_with_public_access_disabled():
    foreign = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/other/providers/Microsoft.Network/privateEndpoints/pe"
    local = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe"
    for connections, expected in (([_private(foreign)], "FAIL"), ([_private(local)], "PASS"),
                                  ([_private(foreign, status="Pending")], "PASS"),
                                  ([_private(foreign, provisioning="Creating")], "UNKNOWN"),
                                  ([], "PASS")):
        transport = Transport(connections)
        snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                                 ["redis_enterprise_cluster", "redis_enterprise_database"], transport=transport)
        cluster = next(c for c in snapshot["collections"] if c["type"] == "redis_enterprise_cluster")
        cluster["items"][0]["properties"]["publicNetworkAccess"] = "Disabled"
        result = next(row for row in assess(snapshot, resources(snapshot))
                      if row.resource["type"] == "redis_enterprise_cluster")
        assert result.verdict() == expected
        if expected == "FAIL":
            assert result.external_ids == [foreign]
