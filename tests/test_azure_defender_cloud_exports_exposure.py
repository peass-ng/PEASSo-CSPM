"""Defender notification and automation data routes are assessed natively."""

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.collectors import azure_defender_automations_native as automations
from peaso.snapshot import make_snapshot, resources


SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
RID = SUB + "/resourceGroups/rg/providers/Microsoft.Security/automations/export"
TARGET = OTHER + "/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/eventhubs/alerts"


def _raw(target=TARGET, enabled=True):
    return {"id": RID, "name": "export", "type": "Microsoft.Security/automations",
            "properties": {"isEnabled": enabled, "actions": [{"actionType": "EventHub",
                "eventHubResourceId": target, "connectionString": "must-not-persist",
                "sasPolicyName": "send", "uri": "https://secret.example/?sig=must-not-persist"}],
                "sources": [{"eventSource": "Alerts", "ruleSets": [{"rules": [{
                    "expectedValue": "must-not-persist"}]}]}]}}


def _results(*, automation=None, contact=None, domains=True):
    collections = [{"type": "directory_domain", "scope": SUB, "service": "Microsoft.Graph",
                    "status": "collected" if domains else "denied", "items":
                    [{"id": "owner.example", "isVerified": True}] if domains else []}]
    if automation is not None:
        collections.append({"type": automations.KIND, "scope": SUB, "service": "Microsoft.Security",
                            "status": "collected", "items": [automation]})
    if contact is not None:
        collections.append({"type": "security_contact", "scope": SUB, "service": "Microsoft.Security",
                            "status": "collected", "items": [contact]})
    snap = make_snapshot("azure", [SUB], collections)
    return {row.resource["type"]: row for row in assess(snap, resources(snap))}


def test_cross_subscription_export_and_safe_projection():
    row = automations.project(_raw(), SUB)
    assert "must-not-persist" not in str(row)
    result = _results(automation=row)[automations.KIND]
    assert result.verdict() == "FAIL"
    assert result.external_ids == [TARGET]


def test_disabled_or_same_subscription_automation():
    assert _results(automation=automations.project(_raw(enabled=False), SUB))[automations.KIND].verdict() == "PASS"
    same = SUB + TARGET[len(OTHER):]
    assert _results(automation=automations.project(_raw(target=same), SUB))[automations.KIND].verdict() == "UNKNOWN"


def _collected_contact(contact):
    class Transport:
        tenant = verified_tenant = "00000000-0000-0000-0000-0000000000aa"

        def request(self, url, body=None, audience=azure.ARM):
            path = url.split("?", 1)[0]
            if audience == azure.ARM and path == azure.ARM + SUB:
                return {"id": SUB, "subscriptionId": SUB.rsplit("/", 1)[-1], "tenantId": self.tenant}
            if path == azure.ARM + SUB + "/providers/Microsoft.Security/securityContacts":
                return {"value": [contact]}
            if path == azure.ARM + contact["id"]:
                return contact
            return {"value": []}

    snapshot = azure.collect({"scopes": [SUB]}, ["security_contact"], transport=Transport())
    rows = [c for c in snapshot["collections"] if c["type"] == "security_contact"]
    assert len(rows) == 1 and rows[0]["status"] == "collected", rows
    return rows[0]["items"][0]


def test_foreign_security_contact_and_missing_domain_inventory():
    contact = {"id": SUB + "/providers/Microsoft.Security/securityContacts/default",
               "type": "Microsoft.Security/securityContacts", "properties": {
                   "isEnabled": True, "emails": "oncall@owner.example;alerts@partner.example",
                   "notificationsSources": [{"sourceType": "Alert", "minimalSeverity": "High"}]}}
    result = _results(contact=contact)["security_contact"]
    assert result.verdict() == "FAIL" and result.external_ids == ["alerts@partner.example"]
    assert _results(contact=contact, domains=False)["security_contact"].verdict() == "UNKNOWN"
    # The official LIST example returns the singular type; the collector call
    # sites admit it for security contacts while the shared helper stays strict.
    singular = {**contact, "type": "Microsoft.Security/securityContact"}
    with pytest.raises(ValueError):
        azure._arm_parent_native_type(singular, "security_contact")
    assert _collected_contact(singular)["type"] == "Microsoft.Security/securityContact"
    role_only = {**contact, "properties": {**contact["properties"], "emails": "",
                 "notificationsByRole": {"state": "On", "roles": ["Owner"]}}}
    assert _results(contact=role_only)["security_contact"].verdict() == "UNKNOWN"


def test_foreign_automation_rejected_and_one_list_per_subscription():
    with pytest.raises(ValueError):
        automations.project({**_raw(), "id": OTHER + RID}, SUB)
    reader = azure._Reader({})
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return {"value": [_raw()]}

    automations.collect(reader, request, [SUB], {automations.KIND})
    assert len(calls) == 1
    assert calls[0].endswith("/providers/Microsoft.Security/automations?api-version=2023-12-01-preview")
    assert reader.collections[0]["status"] == "collected"
