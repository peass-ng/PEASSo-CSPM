"""Redis private endpoint shares survive public listener and firewall blocks."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Cache/redis/cache"
REMOTE = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/other/providers/Microsoft.Network/privateEndpoints/pe"


def _connection(remote=REMOTE, status="Approved", provisioning="Succeeded"):
    return {"id": RID + "/privateEndpointConnections/pec", "name": "pec",
            "type": "Microsoft.Cache/redis/privateEndpointConnections", "properties": {
                "privateEndpoint": {"id": remote},
                "privateLinkServiceConnectionState": {"status": status},
                "provisioningState": provisioning}}


def _assess(response):
    parent = {"id": RID, "type": "Microsoft.Cache/redis", "properties": {
        "publicNetworkAccess": "Disabled", "hostName": "cache.redis.cache.windows.net",
        "sslPort": 6380, "enableNonSslPort": False}}
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return {"value": []} if "/firewallRules?" in url else response

    azure._embed(azure._Reader({}), request, [("redis_cache", parent)], skip=("diagnosticSettings",))
    snap = make_snapshot("azure", [SCOPE], [{"type": "redis_cache", "scope": SCOPE,
        "service": "Microsoft.Cache", "status": "collected", "items": [parent]}])
    result = next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "redis_cache")
    return result, calls


def test_redis_foreign_private_endpoint_with_public_access_disabled():
    result, calls = _assess({"value": [_connection()]})
    assert result.verdict() == "FAIL"
    assert result.external_ids == [REMOTE]
    assert calls.count("https://management.azure.com" + RID +
                       "/privateEndpointConnections?api-version=2024-11-01") == 1


def test_redis_private_endpoint_absence_and_uncertainty():
    assert _assess({"value": []})[0].verdict() == "PASS"
    same = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe"
    assert _assess({"value": [_connection(remote=same)]})[0].verdict() == "PASS"
    assert _assess({"value": [_connection(status="Pending")]})[0].verdict() == "PASS"
    assert _assess({"value": [_connection(provisioning="Creating")]})[0].verdict() == "UNKNOWN"
    assert _assess({"bad": []})[0].verdict() == "UNKNOWN"
