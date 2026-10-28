"""Analysis Services public endpoint and firewall collection from full ARM detail."""

import json
from urllib.parse import urlsplit

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport, parent

SERVER = SCOPE + "/resourceGroups/rg/providers/Microsoft.AnalysisServices/servers/model"
LIST = SCOPE + "/providers/Microsoft.AnalysisServices/servers"
KIND = "Microsoft.AnalysisServices/servers"


def server(firewall=None, state="Succeeded"):
    props = {"state": state, "provisioningState": "Succeeded",
             "serverFullName": "asazure://westus.asazure.windows.net/model",
             "asAdministrators": {"members": ["owner@example.com"]},
             "backupBlobContainerUri": "https://backup.example/container?sig=sensitive-marker"}
    if firewall is not None:
        props["ipV4FirewallSettings"] = firewall
    return parent(SERVER, KIND, props)


def decision(row):
    snap = make_snapshot("azure", [SCOPE], [{"type": "analysis_server", "scope": SCOPE,
        "service": "Microsoft.AnalysisServices", "status": "collected", "items": [row]}])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "analysis_server")


def test_full_get_is_cached_and_backup_sas_is_not_retained():
    api = Transport({LIST: {"value": [server()]}, SERVER: server()})
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["analysis_server"], transport=api)
    rows = [c for c in snap["collections"] if c["type"] == "analysis_server"]
    assert rows[0]["status"] == "collected"
    assert sum(urlsplit(url).path == SERVER for url in api.calls) == 1
    assert "sensitive-marker" not in json.dumps(snap)
    assert decision(rows[0]["items"][0]).verdict() == "FAIL"


@pytest.mark.parametrize("settings,expected", [
    ({"enablePowerBIService": False, "firewallRules": []}, "PASS"),
    ({"enablePowerBIService": True, "firewallRules": []}, "FAIL"),
    ({"enablePowerBIService": False, "firewallRules": [
        {"rangeStart": "8.8.8.8", "rangeEnd": "8.8.8.8"}]}, "FAIL"),
    ({"enablePowerBIService": False, "firewallRules": [
        {"rangeStart": "10.0.0.1", "rangeEnd": "10.0.0.8"}]}, "PASS"),
    ({"enablePowerBIService": False, "firewallRules": [
        {"rangeStart": "bad", "rangeEnd": "bad"}]}, "UNKNOWN"),
])
def test_firewall_decisions(settings, expected):
    row = server(settings)
    row["_provenance"] = {"source_operation": "Servers_GetDetails"}
    assert decision(row).verdict() == expected


def test_paused_server_is_not_listening_and_unproven_detail_stays_unknown():
    paused = server(state="Paused")
    assert decision(paused).verdict() == "PASS"
    assert decision(server()).verdict() == "UNKNOWN"


def test_eastus2_client_protocol_is_accepted():
    row = server()
    row["properties"]["serverFullName"] = "aspaaseastus2://eastus2.asazure.windows.net/model"
    row["_provenance"] = {"source_operation": "Servers_GetDetails"}
    assert decision(row).verdict() == "FAIL"


def test_malformed_firewall_rejected_without_retaining_sensitive_detail():
    malformed = server({"firewallRules": [{"rangeStart": "sensitive-marker"}]})
    api = Transport({LIST: {"value": [malformed]}, SERVER: malformed})
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["analysis_server"], transport=api)
    row = next(c for c in snap["collections"] if c["type"] == "analysis_server")
    assert row["status"] not in ("collected", "empty")
    assert "sensitive-marker" not in json.dumps(snap)


def test_endpoint_query_is_rejected_before_snapshot_storage():
    malformed = server()
    malformed["properties"]["serverFullName"] += "?sig=sensitive-marker"
    api = Transport({LIST: {"value": [malformed]}, SERVER: malformed})
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["analysis_server"], transport=api)
    row = next(c for c in snap["collections"] if c["type"] == "analysis_server")
    assert row["status"] not in ("collected", "empty")
    assert "sensitive-marker" not in json.dumps(snap)
