"""Managed Prometheus public query and private endpoint exposure."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SUB = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"
SCOPE = "/subscriptions/" + SUB
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Monitor/accounts/metrics"
URL = "https://management.azure.com" + SCOPE + "/providers/Microsoft.Monitor/accounts?api-version=2025-10-03"


def _scan(*, access="Enabled", connections=None, state="Succeeded"):
    row = {"id": RID, "type": "Microsoft.Monitor/accounts", "name": "metrics", "location": "eastus",
           "properties": {"provisioningState": state, "publicNetworkAccess": access,
                          "metrics": {"prometheusQueryEndpoint":
                                      "https://metrics.eastus.prometheus.monitor.azure.com/path?sig=PRIVATE"},
                          "privateEndpointConnections": [] if connections is None else connections}}

    class Transport:
        tenant = SUB
        verified_tenant = True

        def __init__(self):
            self.calls = []

        def request(self, url, *, body=None, audience=None):
            self.calls.append(url)
            if url == URL:
                return {"value": [row]}
            if "/Microsoft.ResourceGraph/resources" in url:
                return {"data": []}
            if "/diagnosticSettings?" in url:
                return {"value": []}
            raise AssertionError(url)

    transport = Transport()
    snap = azure.collect({"scopes": [SCOPE], "options": {"inventories": ["monitor_workspace"],
                          "concurrency": 1, "retries": 0}, "auth": {}},
                         requirements=["monitor_workspace"], transport=transport)
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "monitor_workspace")
    return result, snap, transport


def test_public_query_endpoint_is_detected_without_url_token():
    result, snap, transport = _scan()
    assert result.verdict() == "FAIL"
    assert result.addresses == ["metrics.eastus.prometheus.monitor.azure.com"]
    assert "PRIVATE" not in str(snap)
    assert transport.calls.count(URL) == 1


def test_disabled_public_query_and_foreign_private_endpoint():
    result, _, _ = _scan(access="Disabled")
    assert result.verdict() == "PASS"
    foreign = [{"properties": {"provisioningState": "Succeeded", "groupIds": ["prometheusMetrics"],
                               "privateEndpoint": {"id": "/subscriptions/" + OTHER +
                                                       "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"},
                               "privateLinkServiceConnectionState": {"status": "Approved"}}}]
    result, _, _ = _scan(access="Disabled", connections=foreign)
    assert result.verdict() == "FAIL"
    assert result.external_ids[0].startswith("/subscriptions/" + OTHER)
    assert _scan(access=None)[0].verdict() == "UNKNOWN"
    assert _scan(state="Failed")[0].verdict() == "UNKNOWN"
