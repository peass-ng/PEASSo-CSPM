"""SignalR Serverless upstream recipient detection and URL privacy."""

import json
from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport


RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.SignalRService/signalR/service"


def upstream_decision(properties):
    item = {"id": RID, "type": "Microsoft.SignalRService/signalR", "name": "service",
            "_provenance": {"representation": "full", "source_operation": "get"},
            "properties": properties}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "signalr_service", "scope": SCOPE,
        "service": "Microsoft.SignalRService", "status": "collected", "items": [item]}])
    return next(row for row in assess(snapshot, resources(snapshot))
                if row.resource["type"] == "signalr_service" and row.kind == "external_event_delivery")


def test_serverless_upstream_and_disabled_modes():
    props = {"features": [{"flag": "ServiceMode", "value": "Serverless"}],
             "upstreamHosts": ["partner.example.test"], "upstreamComplete": True}
    finding = upstream_decision(props)
    assert finding.verdict() == "FAIL" and finding.external_ids == ["partner.example.test"]
    assert upstream_decision({**props, "features": [{"flag": "ServiceMode", "value": "Default"}]}).verdict() == "PASS"
    assert upstream_decision({**props, "features": [{"flag": "ServiceMode", "value": "Classic"}]}).verdict() == "PASS"
    assert upstream_decision({**props, "upstreamHosts": []}).verdict() == "PASS"


def test_missing_mode_or_malformed_template_is_unknown():
    assert upstream_decision({"features": [], "upstreamHosts": ["partner.example.test"],
                              "upstreamComplete": True}).verdict() == "UNKNOWN"
    assert upstream_decision({"features": [{"flag": "ServiceMode", "value": "Serverless"}],
                              "upstreamHosts": [], "upstreamComplete": False}).verdict() == "UNKNOWN"


def test_collector_projects_only_upstream_hostname_from_full_get():
    item = {"id": RID, "name": "service", "type": "Microsoft.SignalRService/signalR",
            "properties": {"publicNetworkAccess": "Disabled", "features": [{"flag": "ServiceMode", "value": "Serverless"}],
                           "upstream": {"templates": [{"urlTemplate":
                               "https://partner.example.test/sensitive-marker?sig=sensitive-marker"}]}}}
    api = Transport({SCOPE + "/providers/Microsoft.SignalRService/signalR": {"value": [item]}, RID: item})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["signalr_service"], transport=api)
    assert [urlsplit(url).path for url in api.calls].count(RID) == 1
    assert "sensitive-marker" not in json.dumps(snapshot)
    finding = next(row for row in assess(snapshot, resources(snapshot))
                   if row.resource["type"] == "signalr_service" and row.kind == "external_event_delivery")
    assert finding.verdict() == "FAIL" and finding.external_ids == ["partner.example.test"]
