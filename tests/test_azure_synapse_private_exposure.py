"""Synapse foreign private endpoints survive the public network gate."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Synapse/workspaces/ws"
REMOTE = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/other/providers/Microsoft.Network/privateEndpoints/pe"


def _connection(remote=REMOTE, status="Approved", provisioning="Succeeded"):
    return {"id": RID + "/privateEndpointConnections/pec", "name": "sql",
            "type": "Microsoft.Synapse/workspaces/privateEndpointConnections", "properties": {
                "privateEndpoint": {"id": remote},
                "privateLinkServiceConnectionState": {"status": status},
                "provisioningState": provisioning}}


def _decision(response):
    parent = {"id": RID, "type": "Microsoft.Synapse/workspaces", "properties": {
        "publicNetworkAccess": "Disabled"}}
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return response if "/privateEndpointConnections?" in url else {"value": []}

    azure._embed(azure._Reader({}), request, [("synapse_workspace", parent)],
                 skip=("diagnosticSettings", "sqlPools", "firewallRules", "managedPrivateEndpoints"))
    snap = make_snapshot("azure", [SCOPE], [{"type": "synapse_workspace", "scope": SCOPE,
        "service": "Microsoft.Synapse", "status": "collected", "items": [parent]}])
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "synapse_workspace")
    return row, calls


def test_synapse_foreign_private_endpoint_when_public_access_disabled():
    row, calls = _decision({"value": [_connection()]})
    assert row.verdict() == "FAIL" and row.external_ids == [REMOTE]
    assert row.ports == {"tcp": ((443, 443), (1433, 1433))}
    assert calls.count("https://management.azure.com" + RID +
                       "/privateEndpointConnections?api-version=2021-06-01") == 1


def test_synapse_private_endpoint_absence_and_uncertainty():
    local = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe"
    assert _decision({"value": []})[0].verdict() == "PASS"
    assert _decision({"value": [_connection(remote=local)]})[0].verdict() == "PASS"
    assert _decision({"value": [_connection(status="Pending")]})[0].verdict() == "PASS"
    assert _decision({"value": [_connection(provisioning="Creating")]})[0].verdict() == "UNKNOWN"
    assert _decision({"bad": []})[0].verdict() == "UNKNOWN"
