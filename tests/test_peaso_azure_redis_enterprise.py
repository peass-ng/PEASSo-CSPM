"""Azure Managed Redis database child inventory uses one cached ARM list."""

from urllib.parse import urlsplit, parse_qs

from peaso.collectors import azure

SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB
CLUSTER = SCOPE + "/resourceGroups/rg/providers/Microsoft.Cache/redisEnterprise/cache"
DATABASE = CLUSTER + "/databases/default"


class Transport:
    tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

    def __init__(self):
        self.calls = []

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
                    "properties": {"publicNetworkAccess": "Enabled", "hostName": "cache.redis.azure.net",
                                   "firewallRules": []}}
        if path == CLUSTER + "/databases":
            return {"value": [{"id": DATABASE, "name": "default",
                "type": "Microsoft.Cache/redisEnterprise/databases",
                "properties": {"port": 10000, "clientProtocol": "Encrypted"}}]}
        return {"value": []}


def test_redis_enterprise_parent_and_database_are_read_once():
    transport = Transport()
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["redis_enterprise_cluster", "redis_enterprise_database"], transport=transport)
    parent = next(c for c in snapshot["collections"] if c["type"] == "redis_enterprise_cluster")
    child = next(c for c in snapshot["collections"] if c["type"] == "redis_enterprise_database")
    assert parent["status"] == "collected"
    assert parent["items"][0]["properties"]["firewallRules"] == []
    assert child["status"] == "collected" and child["items"][0]["properties"]["port"] == 10000
    assert sum(urlsplit(url).path == CLUSTER for url in transport.calls) == 1
    assert sum(urlsplit(url).path == CLUSTER + "/databases" for url in transport.calls) == 1
    assert all(parse_qs(urlsplit(url).query).get("api-version") ==
               (["2025-07-01"] if urlsplit(url).path.endswith("/databases") else ["2026-10-01-preview"])
               for url in transport.calls if "redisEnterprise" in urlsplit(url).path
               and "diagnosticSettings" not in urlsplit(url).path)
