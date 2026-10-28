"""EASM data-plane export inventory and conservative exposure assessment."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Easm/workspaces/easm1"
ARM_LIST = "https://management.azure.com" + SCOPE + "/providers/Microsoft.Easm/workspaces?api-version=2023-04-01-preview"
DATA_LIST = ("https://eastus.easm.defender.microsoft.com/subscriptions/00000000-0000-0000-0000-000000000001"
             "/resourceGroups/rg/workspaces/easm1/dataConnections?api-version=2024-10-01-preview")


class FakeTransport:
    tenant = "00000000-0000-0000-0000-000000000002"
    verified_tenant = True

    def __init__(self, data):
        self.data = data
        self.calls = []

    def request(self, url, *, body=None, audience=None):
        self.calls.append((url, audience))
        result = self.data[url]
        if isinstance(result, Exception):
            raise result
        return result


def _scan(connection, *, continuation=None):
    data = {ARM_LIST: {"value": [{"id": RID, "type": "Microsoft.Easm/workspaces", "location": "eastus",
                                  "properties": {"provisioningState": "Succeeded"}}]},
            DATA_LIST: {"value": [connection], **({"nextLink": continuation} if continuation else {})}}
    transport = FakeTransport(data)
    snap = azure.collect({"scopes": [SCOPE], "options": {"inventories": ["easm_data_connection"],
                          "concurrency": 1, "retries": 0}, "auth": {}},
                         requirements=["easm_data_connection"], transport=transport)
    return snap, transport


def test_data_connection_drops_api_key_and_reports_conditional_export():
    raw = {"name": "export", "kind": "logAnalytics", "active": True,
           "content": "assets", "frequency": "daily",
           "properties": {"workspaceId": "workspace-guid", "apiKey": "EXAMPLE_SECRET_VALUE"}}
    snap, transport = _scan(raw)
    collection = next(c for c in snap["collections"] if c["type"] == "easm_data_connection")
    assert collection["status"] == "collected"
    assert collection["items"][0]["workspaceId"] == "workspace-guid"
    assert "EXAMPLE_SECRET_VALUE" not in str(snap)
    assert transport.calls.count((DATA_LIST, "https://easm.defender.microsoft.com")) == 1
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "easm_data_connection")
    assert result.verdict() == "UNKNOWN"
    assert result.path[-1]["destination_id"] == "workspace-guid"
    workspace = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "easm_workspace")
    assert workspace.verdict() == "FAIL"
    assert workspace.addresses == ["eastus.easm.defender.microsoft.com"]


def test_inactive_and_denied_connections():
    raw = {"name": "export", "kind": "azureDataExplorer", "active": False,
           "properties": {"clusterName": "adx", "databaseName": "db", "region": "eastus"}}
    snap, _ = _scan(raw)
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "easm_data_connection")
    assert result.verdict() == "PASS"
    snap, _ = _scan(raw, continuation="https://evil.example/dataConnections")
    assert next(c for c in snap["collections"] if c["type"] == "easm_data_connection")["status"] not in ("collected", "empty")


def test_selected_connection_adds_workspace_parent():
    assert "easm_workspace" in azure._selected({"inventories": ["easm_data_connection"]}, None)
