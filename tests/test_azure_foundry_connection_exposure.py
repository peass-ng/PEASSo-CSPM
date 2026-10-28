"""Foundry connection inventory retains destination facts without secrets."""

from types import SimpleNamespace

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_foundry_agent_native as agent, azure_foundry_connection_native as connection
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
ACCOUNT = SCOPE + "/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai"
PROJECT = ACCOUNT + "/projects/test"
HOST = "ai.services.ai.azure.com"


def test_connection_list_projection_and_conditional_finding():
    class Reader:
        def __init__(self):
            self.collections = [{"type": "foundry_project", "scope": ACCOUNT, "status": "collected",
                                 "items": [{"id": PROJECT, "name": "test", "parent_id": ACCOUNT}]}]
            self.urls = []

        def pages(self, request, url, *, audience):
            self.urls.append((url, audience))
            yield [{"id": "conn_1", "name": "remote", "type": "RemoteTool_Preview",
                    "target": "https://partner.example/tool?secret=drop", "credentials": {
                        "type": "ApiKey", "key": "must-not-persist"}}]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    reader = Reader()
    transport = SimpleNamespace(foundry_hosts=set())
    connection.collect(reader, lambda _: None, transport, {connection.KIND})
    assert transport.foundry_hosts == {HOST}
    assert reader.urls[0][1] == agent.AUDIENCE
    assert agent.allowed_route(reader.urls[0][0], {HOST})
    assert not agent.allowed_route("https://" + HOST + "/api/projects/test/connections/conn_1?api-version=v1", {HOST})
    row = reader.collections[-1]["items"][0]
    assert row["target_host"] == "partner.example" and row["credential_type"] == "ApiKey"
    assert "must-not-persist" not in str(row) and "secret=drop" not in str(row)
    snap = make_snapshot("azure", [SCOPE], [reader.collections[-1]])
    finding = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == connection.KIND)
    assert finding.verdict() == "UNKNOWN" and finding.addresses == ["partner.example"]
    assert azure._selected({}, [connection.KIND]) >= {connection.KIND, "foundry_project", "cognitive_account"}
