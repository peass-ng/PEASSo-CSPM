"""Provider-side Azure Private Link Service subscription sharing."""

import json
from urllib.parse import urlsplit

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport, parent

SERVICE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/privateLinkServices/provider"
LIST = SCOPE + "/providers/Microsoft.Network/privateLinkServices"
KIND = "Microsoft.Network/privateLinkServices"
OTHER = "22222222-2222-2222-2222-222222222222"


def service(*, mode="Restricted", visible=None, automatic=None, connections=None):
    return parent(SERVICE, KIND, {
        "provisioningState": "Succeeded", "accessMode": mode,
        "alias": "sensitive-marker.azure.privatelinkservice",
        "visibility": {"subscriptions": [SUB] if visible is None else visible},
        "autoApproval": {"subscriptions": [] if automatic is None else automatic},
        "privateEndpointConnections": [] if connections is None else connections,
    })


def connection(subscription=OTHER, status="Approved"):
    return {"id": SERVICE + "/privateEndpointConnections/c", "properties": {
        "privateEndpoint": {"id": "/subscriptions/" + subscription +
                            "/resourceGroups/consumer/providers/Microsoft.Network/privateEndpoints/pe"},
        "privateLinkServiceConnectionState": {"status": status, "description": "sensitive-marker"},
    }}


def decision(row):
    snap = make_snapshot("azure", [SCOPE], [{"type": "private_link_service", "scope": SCOPE,
        "service": "Microsoft.Network", "status": "collected", "items": [row]}])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "private_link_service")


def projected(row):
    return azure._private_link_service_metadata(row)


def test_full_get_collects_once_and_drops_alias_and_approval_message():
    row = service(connections=[connection()])
    api = Transport({LIST: {"value": [row]}, SERVICE: row})
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                         ["private_link_service"], transport=api)
    collection = next(c for c in snap["collections"] if c["type"] == "private_link_service")
    assert collection["status"] == "collected"
    assert sum(urlsplit(url).path == SERVICE for url in api.calls) == 1
    assert "api-version=2025-05-01" in next(url for url in api.calls if urlsplit(url).path == SERVICE)
    assert "sensitive-marker" not in json.dumps(snap)
    assert decision(collection["items"][0]).verdict() == "FAIL"


@pytest.mark.parametrize("row,verdict", [
    (service(automatic=[OTHER], visible=[OTHER]), "FAIL"),
    (service(connections=[connection()]), "FAIL"),
    (service(connections=[connection(status="Pending")]), "PASS"),
    (service(connections=[connection(subscription=SUB)]), "PASS"),
    (service(), "PASS"),
    (service(mode="Default"), "UNKNOWN"),
    (service(visible=[OTHER]), "UNKNOWN"),
])
def test_subscription_access_decisions(row, verdict):
    a = decision(projected(row))
    assert a.verdict() == verdict
    if verdict == "FAIL":
        assert OTHER in a.external_ids


def test_missing_get_proof_or_access_mode_remains_unknown():
    assert decision(service()).verdict() == "UNKNOWN"
    row = service()
    del row["properties"]["accessMode"]
    assert decision(projected(row)).verdict() == "UNKNOWN"


def test_malformed_connection_stops_collection_without_retaining_message():
    row = service(connections=[{"properties": {"description": "sensitive-marker"}}])
    api = Transport({LIST: {"value": [row]}, SERVICE: row})
    snap = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                         ["private_link_service"], transport=api)
    collection = next(c for c in snap["collections"] if c["type"] == "private_link_service")
    assert collection["status"] not in ("collected", "empty")
    assert "sensitive-marker" not in json.dumps(snap)
