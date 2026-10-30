"""Azure Managed Grafana native workspace and snapshot exposure evidence."""

import json
from urllib.parse import urlsplit
import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport, parent

WORKSPACE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Dashboard/grafana/workspace"
LIST = SCOPE + "/providers/Microsoft.Dashboard/grafana"
URL = "https://workspace.grafana.azure.com"


def grafana(*, public="Enabled", external=False):
    return parent(WORKSPACE, "Microsoft.Dashboard/grafana", {
        "provisioningState": "Succeeded", "publicNetworkAccess": public, "endpoint": URL,
        "grafanaConfigurations": {"snapshots": {"externalEnabled": external},
                                  "smtp": {"password": "sensitive-marker", "host": "smtp.example"}},
    })


def decision(item, snapshot_items=None, snapshot_status="empty"):
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "managed_grafana",
        "scope": SCOPE, "service": "Microsoft.Dashboard", "status": "collected", "items": [item]},
        {"type": "managed_grafana_snapshot", "scope": WORKSPACE, "service": "Microsoft.Dashboard",
         "status": snapshot_status, "items": [] if snapshot_items is None else snapshot_items}])
    rows = assess(snapshot, resources(snapshot))
    assert len(rows) == 1
    return rows[0]


def test_collects_grafana_list_without_smtp_secret():
    paths = {LIST: {"value": [grafana()]}, "/api/dashboard/snapshots": []}
    api = Transport(paths)
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["managed_grafana"], transport=api)
    rows = [row for row in snapshot["collections"] if row["type"] == "managed_grafana"]
    assert len(rows) == 1 and rows[0]["status"] == "collected"
    assert rows[0]["items"][0]["_provenance"]["source_operation"] == "Grafana_List"
    assert "sensitive-marker" not in json.dumps(snapshot)
    expected = {LIST, "/providers/Microsoft.ResourceGraph/resources",
                WORKSPACE + "/providers/Microsoft.Insights/diagnosticSettings",
                "/api/dashboard/snapshots"}
    assert {urlsplit(url).path for url in api.calls} == expected
    assert len(api.calls) == len(expected)
    assert assess(snapshot, resources(snapshot))[0].verdict() == "FAIL"


def test_public_url_and_external_snapshot_decisions():
    assert decision(grafana()).verdict() == "FAIL"
    assert decision(grafana(public="Disabled", external=False)).verdict() == "PASS"
    assert decision(grafana(public="Disabled", external=True)).verdict() == "PASS"
    assert decision(grafana(public="Disabled", external=True), snapshot_status="denied").verdict() == "UNKNOWN"
    shared = {"id": WORKSPACE + "/snapshots/7", "type": "Microsoft.Dashboard/grafana/snapshots",
              "properties": {"external": True, "expires": "2099-01-01T00:00:00Z"}}
    assert decision(grafana(public="Disabled", external=False), [shared], "collected").verdict() == "FAIL"
    missing = grafana(public="Disabled")
    del missing["properties"]["grafanaConfigurations"]
    assert decision(missing).verdict() == "PASS"
    no_url = grafana()
    del no_url["properties"]["endpoint"]
    assert decision(no_url).verdict() == "UNKNOWN"


def test_malformed_snapshot_setting_is_not_retained():
    malformed = grafana()
    malformed["properties"]["grafanaConfigurations"]["snapshots"] = {"externalEnabled": "sensitive-marker"}
    api = Transport({LIST: {"value": [malformed]}, "/api/dashboard/snapshots": []})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["managed_grafana"], transport=api)
    row = next(row for row in snapshot["collections"] if row["type"] == "managed_grafana")
    assert row["status"] not in ("collected", "empty")
    assert "sensitive-marker" not in json.dumps(snapshot)


def test_external_snapshot_list_proves_sharing_without_storing_capability_url():
    shared = {"id": 7, "name": "Operations", "external": True,
              "externalUrl": "https://snapshots.raintank.io/sensitive-marker",
              "key": "sensitive-marker", "expires": "2099-01-01T00:00:00Z"}
    api = Transport({LIST: {"value": [grafana(public="Disabled", external=False)]},
                     "/api/dashboard/snapshots": [shared]})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["managed_grafana"], transport=api)
    rows = [row for row in snapshot["collections"] if row["type"] == "managed_grafana_snapshot"]
    assert len(rows) == 1 and rows[0]["status"] == "collected"
    assert rows[0]["items"][0]["properties"]["external"] is True
    assert "sensitive-marker" not in json.dumps(snapshot)
    assert assess(snapshot, resources(snapshot))[0].verdict() == "FAIL"


def test_data_plane_host_binding_rejects_foreign_origin():
    transport = azure.AzureTransportExposure({"method": "token", "arm_token": "unused"})
    transport.allow_grafana("https://workspace.eus.grafana.azure.com")
    assert "workspace.eus.grafana.azure.com" in transport.grafana_hosts
    with pytest.raises(azure.AzureReadError):
        transport.allow_grafana("https://workspace.eus.grafana.azure.com.evil.example")
