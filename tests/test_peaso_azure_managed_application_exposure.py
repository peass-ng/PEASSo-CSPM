"""Azure Managed Applications publisher delegation from safe native LIST metadata."""

import json
from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport, parent

OWNER = "22222222-2222-2222-2222-222222222222"
PUBLISHER = "33333333-3333-3333-3333-333333333333"
APP = SCOPE + "/resourceGroups/rg/providers/Microsoft.Solutions/applications/app"
LIST = SCOPE + "/providers/Microsoft.Solutions/applications"


def application(*, publisher=PUBLISHER, mode="Managed", grants=None, jit=False):
    return parent(APP, "Microsoft.Solutions/applications", {
        "provisioningState": "Succeeded", "publisherTenantId": publisher,
        "managementMode": mode, "managedResourceGroupId": SCOPE + "/resourceGroups/managed",
        "authorizations": ([{"principalId": "publisher-user", "roleDefinitionId": "reader"}]
                           if grants is None else grants),
        "jitAccessPolicy": {"jitAccessEnabled": jit},
        "parameters": {"credential": {"value": "sensitive-marker"}},
        "outputs": {"token": {"value": "sensitive-marker"}},
    })


def decision(item, metadata=None):
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "managed_application",
        "scope": SCOPE, "service": "Microsoft.Solutions", "status": "collected", "items": [item]}],
        metadata={"subscription_tenants": {SCOPE: OWNER}} if metadata is None else metadata)
    rows = assess(snapshot, resources(snapshot))
    assert len(rows) == 1
    return rows[0]


def test_managed_application_collects_safe_subscription_list_once():
    paths = {SCOPE: {"id": SCOPE, "subscriptionId": SUB, "tenantId": OWNER},
             LIST: {"value": [application()]}}
    api = Transport(paths)
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["managed_application"], transport=api)
    rows = [row for row in snapshot["collections"] if row["type"] == "managed_application"]
    assert len(rows) == 1 and rows[0]["status"] == "collected"
    assert len(rows[0]["items"]) == 1
    assert rows[0]["items"][0]["_provenance"]["source_operation"] == "Applications_ListBySubscription"
    assert "sensitive-marker" not in json.dumps(snapshot)
    expected = {SCOPE, LIST, "/providers/Microsoft.ResourceGraph/resources",
                APP + "/providers/Microsoft.Insights/diagnosticSettings"}
    assert {urlsplit(url).path for url in api.calls} == expected
    assert len(api.calls) == len(expected)


def test_foreign_publisher_grant_and_jit_decisions():
    assert decision(application()).verdict() == "FAIL"
    assert decision(application()).external_ids == [PUBLISHER]
    assert decision(application(mode="Unmanaged")).verdict() == "PASS"
    assert decision(application(grants=[])).verdict() == "PASS"
    assert decision(application(publisher=OWNER)).verdict() == "PASS"
    assert decision(application(jit=True)).verdict() == "UNKNOWN"
    assert decision(application(), metadata={}).verdict() == "UNKNOWN"


def test_missing_jit_policy_and_authorizations_are_unknown():
    without_policy = application()
    del without_policy["properties"]["jitAccessPolicy"]
    assert decision(without_policy).verdict() == "UNKNOWN"
    without_grants = application()
    del without_grants["properties"]["authorizations"]
    assert decision(without_grants).verdict() == "UNKNOWN"


def test_malformed_authorization_never_enters_snapshot():
    malformed = application()
    malformed["properties"]["authorizations"] = {"credential": "sensitive-marker"}
    api = Transport({SCOPE: {"id": SCOPE, "subscriptionId": SUB, "tenantId": OWNER},
                     LIST: {"value": [malformed]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["managed_application"], transport=api)
    row = next(row for row in snapshot["collections"] if row["type"] == "managed_application")
    assert row["status"] not in ("collected", "empty")
    assert "sensitive-marker" not in json.dumps(snapshot)
