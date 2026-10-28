"""Read-only App Compliance Automation report and webhook exposure."""

import json
from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SUB, SCOPE, Transport

REPORTS = "/providers/Microsoft.AppComplianceAutomation/reports"
REPORT = REPORTS + "/review"
WEBHOOKS = REPORT + "/webhooks"
WEBHOOK = WEBHOOKS + "/notify"
OTHER = "33333333-3333-3333-3333-333333333333"


def report(storage=SUB):
    return {"name": "review", "id": REPORT, "type": "Microsoft.AppComplianceAutomation/reports",
            "properties": {"status": "Active", "tenantId": Transport.tenant,
                           "subscriptions": [SUB],
                           "storageInfo": {"subscriptionId": storage, "accountName": "account"},
                           "resources": [{"secret": "sensitive-marker"}]}}


def webhook(status="Enabled", *, events=None, url="https://outside.example.net/hook?key=sensitive-marker"):
    return {"name": "notify", "id": WEBHOOK,
            "type": "Microsoft.AppComplianceAutomation/reports/webhooks",
            "properties": {"status": status, "provisioningState": "Succeeded",
                           "deliveryStatus": "Succeeded", "sendAllEvents": "false",
                           "events": ["generate_snapshot_success"] if events is None else events,
                           "payloadUrl": url, "webhookKey": "sensitive-marker"}}


def decision(snapshot, kind):
    return next(row for row in assess(snapshot, resources(snapshot)) if row.resource["type"] == kind)


def test_collect_paged_report_and_webhook_once_without_secret_url_or_key():
    api = Transport({REPORTS: {"value": [report()]}, WEBHOOKS: {"value": [webhook()]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["acat_report"], transport=api)
    assert [c["status"] for c in snapshot["collections"] if c["type"] in ("acat_report", "acat_webhook")] == ["collected", "collected"]
    assert [urlsplit(url).path for url in api.calls].count(REPORTS) == 1
    assert [urlsplit(url).path for url in api.calls].count(WEBHOOKS) == 1
    assert "api-version=2024-06-27" in api.calls[0]
    serialized = json.dumps(snapshot)
    assert "sensitive-marker" not in serialized
    assert "/hook" not in serialized
    assert "webhookKey" not in serialized
    assert decision(snapshot, "acat_report").verdict() == "PASS"
    hook = decision(snapshot, "acat_webhook")
    assert hook.verdict() == "FAIL" and hook.external_ids == ["outside.example.net"]


def test_cross_subscription_storage_and_disabled_webhook():
    api = Transport({REPORTS: {"value": [report(OTHER)]},
                     WEBHOOKS: {"value": [webhook("Disabled")]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["acat_webhook"], transport=api)
    parent = decision(snapshot, "acat_report")
    assert parent.verdict() == "FAIL" and parent.external_ids == [OTHER]
    assert decision(snapshot, "acat_webhook").verdict() == "PASS"


def test_incomplete_webhook_list_keeps_report_unknown():
    api = Transport({REPORTS: {"value": [report()]}, WEBHOOKS: ValueError("sensitive-marker")})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["acat_report"], transport=api)
    assert decision(snapshot, "acat_report").verdict() == "UNKNOWN"
    assert "sensitive-marker" not in json.dumps(snapshot)


def test_missing_event_selection_does_not_claim_webhook_delivery():
    item = {"id": WEBHOOK, "properties": {"status": "Enabled", "provisioningState": "Succeeded",
                                       "payloadHost": "outside.example.net", "payloadScheme": "https"}}
    snap = make_snapshot("azure", [SCOPE], [{"type": "acat_webhook", "scope": REPORT,
        "service": "Microsoft.AppComplianceAutomation", "status": "collected", "items": [item]}])
    assert decision(snap, "acat_webhook").verdict() == "UNKNOWN"


def test_empty_event_selection_blocks_webhook_delivery():
    api = Transport({REPORTS: {"value": [report()]},
                     WEBHOOKS: {"value": [webhook(events=[])]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["acat_report"], transport=api)
    assert decision(snapshot, "acat_webhook").verdict() == "PASS"


def test_malformed_destination_does_not_enter_snapshot():
    api = Transport({REPORTS: {"value": [report()]},
                     WEBHOOKS: {"value": [webhook(url="https://user:sensitive-marker@example.net/hook")]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["acat_report"], transport=api)
    assert decision(snapshot, "acat_report").verdict() == "UNKNOWN"
    assert "sensitive-marker" not in json.dumps(snapshot)
