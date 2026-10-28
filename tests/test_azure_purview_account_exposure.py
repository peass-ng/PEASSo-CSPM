"""Purview account public endpoint and private sharing evidence."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SUB = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"
SCOPE = "/subscriptions/" + SUB
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Purview/accounts/catalog"
URL = "https://management.azure.com" + SCOPE + "/providers/Microsoft.Purview/accounts?api-version=2021-12-01"


def _scan(*, access="Enabled", connections=None, managed_access="Disabled"):
    row = {"id": RID, "type": "Microsoft.Purview/accounts", "name": "catalog",
           "properties": {"provisioningState": "Succeeded", "publicNetworkAccess": access,
                          "managedResourcesPublicNetworkAccess": managed_access,
                          "cloudConnectors": {"awsExternalId": "PRIVATE_EXTERNAL_ID"},
                          "endpoints": {"catalog": "https://catalog.purview.azure.com/path?sig=SECRET",
                                        "scan": "https://scan.purview.azure.com/path?token=SECRET"},
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
            if url.startswith("https://management.azure.com" + RID + "?"):
                return row
            if "/Microsoft.ResourceGraph/resources" in url:
                return {"data": []}
            if "/diagnosticSettings?" in url:
                return {"value": []}
            raise AssertionError(url)

    transport = Transport()
    snap = azure.collect({"scopes": [SCOPE], "options": {"inventories": ["purview_account"],
                          "concurrency": 1, "retries": 0}, "auth": {}},
                         requirements=["purview_account"], transport=transport)
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "purview_account")
    return result, snap, transport


def test_public_catalog_scan_hosts_and_secret_free_projection():
    result, snap, transport = _scan()
    assert result.verdict() == "FAIL"
    assert result.addresses == ["catalog.purview.azure.com", "scan.purview.azure.com"]
    assert "SECRET" not in str(snap) and "PRIVATE_EXTERNAL_ID" not in str(snap)
    assert transport.calls.count(URL) == 1


def test_disabled_public_access_and_cross_subscription_private_connection():
    assert _scan(access="Disabled")[0].verdict() == "PASS"
    foreign = [{"properties": {"provisioningState": "Succeeded",
                               "privateEndpoint": {"id": "/subscriptions/" + OTHER +
                                                       "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/peer"},
                               "privateLinkServiceConnectionState": {"status": "Approved"}}}]
    result, _, _ = _scan(access="Disabled", connections=foreign)
    assert result.verdict() == "FAIL"
    assert result.external_ids[0].startswith("/subscriptions/" + OTHER)
    assert _scan(access=None)[0].verdict() == "UNKNOWN"
    assert _scan(access="Disabled", managed_access="Enabled")[0].verdict() == "UNKNOWN"
