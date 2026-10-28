"""SQL logical server foreign private routes are independent of public access."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Sql/servers/sql"
REMOTE = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/other/providers/Microsoft.Network/privateEndpoints/pe"


def _connection(remote=REMOTE, status="Approved", state="Ready"):
    return {"id": RID + "/privateEndpointConnections/pec", "name": "pec",
            "type": "Microsoft.Sql/servers/privateEndpointConnections", "properties": {
                "privateEndpoint": {"id": remote},
                "privateLinkServiceConnectionState": {"status": status},
                "provisioningState": state}}


def _decision(response):
    parent = {"id": RID, "type": "Microsoft.Sql/servers", "properties": {
        "publicNetworkAccess": "Disabled", "fullyQualifiedDomainName": "sql.database.windows.net"}}
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return response if "/privateEndpointConnections?" in url else {"value": []}

    azure._embed(azure._Reader({}), request, [("sql_server", parent)],
                 skip=("diagnosticSettings", "serverAdministrators", "azureADOnlyAuthentications",
                       "virtualNetworkRules", "firewallRules", "securityAlertPolicies",
                       "vulnerabilityAssessment", "expressVulnerabilityAssessment", "encryptionProtector"))
    snap = make_snapshot("azure", [SCOPE], [{"type": "sql_server", "scope": SCOPE,
        "service": "Microsoft.Sql", "status": "collected", "items": [parent]}])
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "sql_server")
    return row, calls


def test_sql_foreign_private_endpoint_when_public_access_disabled():
    row, calls = _decision({"value": [_connection()]})
    assert row.verdict() == "FAIL" and row.external_ids == [REMOTE]
    assert row.ports == {"tcp": ((1433, 1433),)}
    assert calls.count("https://management.azure.com" + RID +
                       "/privateEndpointConnections?api-version=2023-08-01") == 1


def test_sql_private_endpoint_absence_and_uncertainty():
    local = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe"
    assert _decision({"value": []})[0].verdict() == "PASS"
    assert _decision({"value": [_connection(remote=local)]})[0].verdict() == "PASS"
    assert _decision({"value": [_connection(status="Pending")]})[0].verdict() == "PASS"
    assert _decision({"value": [_connection(state="Approving")]})[0].verdict() == "UNKNOWN"
    assert _decision({"not_value": []})[0].verdict() == "UNKNOWN"
