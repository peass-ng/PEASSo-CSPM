"""Redis firewall child LIST is a bounded read on the existing per-scan reader."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Cache/redis/cache"


def _result(response):
    reader = azure._Reader({})
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return response

    parent = {"id": RID, "type": "Microsoft.Cache/redis", "properties": {
        "publicNetworkAccess": "Enabled", "hostName": "cache.redis.cache.windows.net",
        "sslPort": 6380, "enableNonSslPort": False}}
    azure._embed(reader, request, [("redis_cache", parent)], skip=("diagnosticSettings",))
    return parent, calls


def _decision(parent):
    snap = make_snapshot("azure", [SCOPE], [{"type": "redis_cache", "scope": SCOPE,
        "service": "Microsoft.Cache", "status": "collected", "items": [parent]}])
    return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "redis_cache")


def test_redis_firewall_list_once_and_assess_public_rule():
    rule = {"id": RID + "/firewallRules/public", "name": "public", "type": "Microsoft.Cache/redis/firewallRules",
            "properties": {"startIP": "8.8.8.8", "endIP": "8.8.8.8"}}
    parent, calls = _result({"value": [rule]})
    assert calls == ["https://management.azure.com" + RID + "/firewallRules?api-version=2024-11-01"]
    assert parent["_coverage"]["firewallRules"]["status"] == "collected"
    assert len(parent["firewallRules"]) == 1
    assert _decision(parent).verdict() == "FAIL"


def test_redis_empty_firewall_list_and_malformed_response():
    parent, calls = _result({"value": []})
    assert len(calls) == 1 and parent["_coverage"]["firewallRules"]["status"] == "empty"
    assert _decision(parent).verdict() == "FAIL"
    malformed, calls = _result({"not_value": []})
    assert len(calls) == 1 and malformed["_coverage"]["firewallRules"]["status"] not in ("collected", "empty")
    assert _decision(malformed).verdict() == "UNKNOWN"
