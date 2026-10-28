"""Foundry project collection and inherited account network exposure."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_foundry_project_native as foundry
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
ACCOUNT = SCOPE + "/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai"
PROJECT = ACCOUNT + "/projects/test"


def _assessment(access="Enabled", action="Allow", endpoints=None, connections=None):
    parent = {"id": ACCOUNT, "kind": "AIServices", "type": "Microsoft.CognitiveServices/accounts",
              "properties": {"provisioningState": "Succeeded", "publicNetworkAccess": access,
                             "networkAcls": {"defaultAction": action, "ipRules": [], "bypass": "None"},
                             "privateEndpointConnections": [] if connections is None else connections}}
    child = {"id": PROJECT, "parent_id": ACCOUNT, "type": "Microsoft.CognitiveServices/accounts/projects",
             "properties": {"provisioningState": "Succeeded", "endpointHosts":
                            ["ai.services.ai.azure.com"] if endpoints is None else endpoints}}
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "cognitive_account", "scope": SCOPE, "service": "Microsoft.CognitiveServices",
         "status": "collected", "items": [parent]},
        {"type": "foundry_project", "scope": ACCOUNT, "service": "Microsoft.CognitiveServices",
         "status": "collected", "items": [child]},
    ])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "foundry_project")


def test_project_public_endpoint_inherits_account_policy():
    row = _assessment()
    assert row.verdict() == "FAIL" and row.addresses == ["ai.services.ai.azure.com"]
    assert _assessment(access="Disabled").verdict() == "PASS"
    assert _assessment(action="Deny").verdict() == "PASS"
    assert _assessment(endpoints=[]).verdict() == "UNKNOWN"


def test_private_project_share_even_when_public_network_disabled():
    foreign = SCOPE.replace("00000000-0000-0000-0000-000000000001",
                            "00000000-0000-0000-0000-000000000002")
    endpoint = foreign + "/resourceGroups/other/providers/Microsoft.Network/privateEndpoints/link"
    link = {"properties": {"privateEndpoint": {"id": endpoint},
                           "privateLinkServiceConnectionState": {"status": "Approved"},
                           "provisioningState": "Succeeded"}}
    row = _assessment(access="Disabled", connections=[link])
    assert row.verdict() == "FAIL" and row.external_ids == [endpoint]


def test_project_list_is_bound_to_parent_and_drops_unknown_fields():
    class Reader:
        def __init__(self):
            self.collections = [{"type": "cognitive_account", "scope": SCOPE, "status": "collected",
                                 "items": [{"id": ACCOUNT, "kind": "AIServices"}]}]
            self.urls = []

        def pages(self, request, url):
            self.urls.append(url)
            yield [{"id": PROJECT, "name": "test", "type": "Microsoft.CognitiveServices/accounts/projects",
                    "properties": {"provisioningState": "Succeeded", "endpoints": {
                        "service": "https://ai.services.ai.azure.com/api/projects/test?secret=drop",
                        "bad": "http://invalid.example/"}, "secret": "must-not-persist"}}]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                items = [item for page in fetch() for item in page]
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": items})

    reader = Reader()
    foundry.collect(reader, lambda _: None, {foundry.KIND}, azure.ARM)
    assert reader.urls == [azure.ARM + ACCOUNT + "/projects?api-version=2025-06-01"]
    child = reader.collections[-1]["items"][0]
    assert child["properties"]["endpointHosts"] == ["ai.services.ai.azure.com"]
    assert "must-not-persist" not in str(child) and "secret=drop" not in str(child)
    assert azure._selected({}, [foundry.KIND]) >= {foundry.KIND, "cognitive_account"}
