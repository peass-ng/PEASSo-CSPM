"""Cost Management export destinations from read-only LIST metadata."""

import json
from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import resources
from tests.test_peaso_azure_bulk_native import SUB, SCOPE, Transport

EXPORTS = SCOPE + "/providers/Microsoft.CostManagement/exports"
OTHER = "33333333-3333-3333-3333-333333333333"


def export(destination):
    return {"id": EXPORTS + "/daily", "type": "Microsoft.CostManagement/exports",
            "properties": {"deliveryInfo": {"destination": destination},
                           "schedule": {"status": "Active"}, "secret": "sensitive-marker"}}


def collected(destination):
    api = Transport({EXPORTS: {"value": [export(destination)]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["cost_export"], transport=api)
    decision = next(row for row in assess(snapshot, resources(snapshot))
                    if row.resource["type"] == "cost_export")
    return api, snapshot, decision


def test_cross_subscription_export_is_detected_from_one_list():
    target = f"/subscriptions/{OTHER}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/target"
    api, snapshot, decision = collected({"resourceId": target, "type": "AzureBlob"})
    assert decision.verdict() == "FAIL"
    assert decision.external_ids == [OTHER]
    assert [urlsplit(url).path for url in api.calls].count(EXPORTS) == 1
    assert "sensitive-marker" not in json.dumps(snapshot)


def test_same_subscription_destination_is_not_external():
    target = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/target"
    _, _, decision = collected({"resourceId": target, "type": "AzureBlob"})
    assert decision.verdict() == "PASS"


def test_partner_sas_destination_owner_is_unknown_and_secret_removed():
    _, snapshot, decision = collected({"storageAccount": "partner", "sasToken": "sensitive-marker",
                                       "type": "AzureBlob"})
    assert decision.verdict() == "UNKNOWN"
    assert "sensitive-marker" not in json.dumps(snapshot)
    assert "sasToken" not in json.dumps(snapshot)


def test_missing_destination_is_unknown_without_losing_the_export():
    _, snapshot, decision = collected({})
    assert decision.verdict() == "UNKNOWN"
    assert next(c for c in snapshot["collections"] if c["type"] == "cost_export")["status"] == "collected"


def test_malformed_destination_fails_closed_without_retaining_raw_row():
    api = Transport({EXPORTS: {"value": [export({"resourceId": None, "sasToken": "sensitive-marker"})]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["cost_export"], transport=api)
    assert "sensitive-marker" not in json.dumps(snapshot)
    assert next(c for c in snapshot["collections"] if c["type"] == "cost_export")["status"] == "collected"


def test_subscription_resource_group_management_group_and_billing_scopes_are_listed():
    group = SCOPE + "/resourceGroups/rg"
    management = "/providers/Microsoft.Management/managementGroups/root"
    account = "/providers/Microsoft.Billing/billingAccounts/100"
    profile = account + "/billingProfiles/200"
    section = profile + "/invoiceSections/300"
    api = Transport({
        SCOPE + "/resourcegroups": {"value": [{"id": group, "type": "Microsoft.Resources/resourceGroups",
                                                "properties": {}}]},
        "/providers/Microsoft.Management/managementGroups": {"value": [{"id": management}]},
        management: {"id": management, "properties": {}},
        "/providers/Microsoft.Billing/billingAccounts": {"value": [
            {"id": account, "properties": {"agreementType": "MicrosoftCustomerAgreement",
                                           "displayName": "sensitive-marker"}}]},
        account + "/billingProfiles": {"value": [{"id": profile}]},
        profile + "/invoiceSections": {"value": [{"id": section}]},
    })
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["cost_export"], transport=api)
    calls = [urlsplit(url).path for url in api.calls]
    for scope in (SCOPE, group, management, account, profile, section):
        assert calls.count(scope + "/providers/Microsoft.CostManagement/exports") == 1
    assert "sensitive-marker" not in json.dumps(snapshot)
