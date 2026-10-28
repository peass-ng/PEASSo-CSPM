"""Foundry agent route binding and public Microsoft 365 Activity detection."""

from types import SimpleNamespace

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_foundry_agent_native as agent
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
ACCOUNT = SCOPE + "/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai"
PROJECT = ACCOUNT + "/projects/test"
HOST = "ai.services.ai.azure.com"


def _assessment(status="Enabled", public=True, schemes=None):
    raw = {"id": PROJECT + "/agents/bot", "parent_id": PROJECT, "name": "bot",
           "status": status, "endpoint_host": HOST, "protocols": ["activity", "responses"],
           "m365_public": public, "authorization_schemes": schemes or [{"type": "BotService"}]}
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "foundry_agent", "scope": PROJECT, "service": "Microsoft Foundry",
         "status": "collected", "items": [raw]},
    ])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "foundry_agent")


def test_public_activity_route_and_disabled_agent():
    row = _assessment()
    assert row.verdict() == "FAIL" and row.addresses == [HOST]
    assert row.authenticated is True
    assert _assessment(status="Disabled").verdict() == "PASS"
    assert _assessment(public=False).verdict() == "UNKNOWN"


def test_agent_list_get_and_safe_projection():
    class Reader:
        def __init__(self):
            self.collections = [{"type": "foundry_project", "scope": ACCOUNT, "status": "collected",
                                 "items": [{"id": PROJECT, "name": "test", "parent_id": ACCOUNT,
                                            "properties": {"endpointHosts": [HOST]}}]}]
            self.budget = SimpleNamespace(max_pages=4)
            self.urls = []

        def call(self, request, url, audience=None):
            self.urls.append((url, audience))
            if url.endswith("/agents?api-version=v1&limit=100"):
                return {"data": [{"id": "ag_1", "name": "bot"}], "has_more": False}
            return {"name": "bot", "status": "Enabled", "instructions": "must-not-persist",
                    "agent_endpoint": {"authorization_schemes": [{"type": "BotService"}],
                                       "protocol_configuration": {
                                           "activity": {"enable_m365_public_endpoint": True},
                                           "responses": {}}}}

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                items = [item for page in fetch() for item in page]
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": items})

    reader = Reader()
    transport = SimpleNamespace(foundry_hosts=set())
    agent.collect(reader, lambda _: None, transport, {agent.KIND})
    assert transport.foundry_hosts == {HOST}
    assert len(reader.urls) == 2 and all(audience == agent.AUDIENCE for _, audience in reader.urls)
    assert all(agent.allowed_route(url, {HOST}) for url, _ in reader.urls)
    assert not agent.allowed_route("https://evil.example/api/projects/test/agents?api-version=v1&limit=100", {HOST})
    item = reader.collections[-1]["items"][0]
    assert item["m365_public"] is True and item["authorization_schemes"] == [{
        "type": "BotService", "allowed_tenants": None, "allowed_clients": None}]
    assert "must-not-persist" not in str(item)
    assert azure._selected({}, [agent.KIND]) >= {agent.KIND, "foundry_project", "cognitive_account"}
