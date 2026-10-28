"""App Configuration Event Grid recipient exposure from secret-safe LIST facts."""

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SUB, SCOPE, Transport

STORE = SCOPE + "/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/store"
EVENTS = STORE + "/providers/Microsoft.EventGrid/eventSubscriptions"
OTHER = "33333333-3333-3333-3333-333333333333"


def subscription(destination, **extra):
    return {"id": EVENTS + "/changes", "properties": {"provisioningState": "Succeeded",
            "destination": destination, "secret": "sensitive-marker", **extra}}


def decision(item, *collections):
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "app_configuration_event_subscription",
        "scope": STORE, "service": "Microsoft.EventGrid", "status": "collected", "items": [item]}, *collections])
    return next(row for row in assess(snapshot, resources(snapshot))
                if row.resource["type"] == "app_configuration_event_subscription")


def test_webhook_projection_drops_url_path_query_and_delivery_attributes():
    store = {"id": STORE, "name": "store", "type": "Microsoft.AppConfiguration/configurationStores",
             "properties": {"publicNetworkAccess": "Disabled", "endpoint": "https://store.azconfig.io",
                            "privateEndpointConnections": []}}
    event = subscription({"endpointType": "WebHook", "properties": {
        "endpointBaseUrl": "https://partner.example.test/sensitive-marker?sig=sensitive-marker",
        "deliveryAttributeMappings": [{"name": "secret", "value": "sensitive-marker"}]}})
    api = Transport({SCOPE + "/providers/Microsoft.AppConfiguration/configurationStores": {"value": [store]},
                     STORE: store, EVENTS: {"value": [event]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["app_configuration"], transport=api)
    assert [urlsplit(url).path for url in api.calls].count(EVENTS) == 1
    assert "sensitive-marker" not in json.dumps(snapshot)
    finding = next(row for row in assess(snapshot, resources(snapshot))
                   if row.resource["type"] == "app_configuration_event_subscription")
    assert finding.verdict() == "FAIL" and finding.external_ids == ["partner.example.test"]


def test_cross_subscription_resource_and_dead_letter_are_detected():
    event = subscription({"endpointType": "EventHub", "properties": {
        "resourceId": f"/subscriptions/{OTHER}/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/eventhubs/hub"}},
        deadLetterDestination={"endpointType": "StorageBlob", "properties": {
            "resourceId": f"/subscriptions/{OTHER}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/archive"}})
    props = {"provisioningState": "Succeeded", "endpointType": "EventHub",
             "destinationResourceId": event["properties"]["destination"]["properties"]["resourceId"],
             "deadLetterResourceId": event["properties"]["deadLetterDestination"]["properties"]["resourceId"]}
    finding = decision({"id": event["id"], "properties": props})
    assert finding.verdict() == "FAIL" and finding.external_ids == [OTHER]


def test_same_subscription_destination_and_expired_subscription():
    same = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/eventhubs/hub"
    props = {"provisioningState": "Succeeded", "endpointType": "EventHub", "destinationResourceId": same}
    assert decision({"id": EVENTS + "/changes", "properties": props}).verdict() == "PASS"
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert decision({"id": EVENTS + "/changes", "properties": {**props, "expirationTimeUtc": yesterday}}).verdict() == "PASS"


def test_same_subscription_monitor_action_group_needs_recipient_assessment():
    group = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/notify"
    finding = decision({"id": EVENTS + "/changes", "properties": {
        "provisioningState": "Succeeded", "endpointType": "MonitorAlert", "actionGroupIds": [group]}})
    assert finding.verdict() == "UNKNOWN"
    assert finding.unresolved


def test_monitor_action_group_email_receiver_and_secret_webhook_projection():
    group = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/notify"
    store = {"id": STORE, "name": "store", "type": "Microsoft.AppConfiguration/configurationStores",
             "properties": {"publicNetworkAccess": "Disabled", "endpoint": "https://store.azconfig.io",
                            "privateEndpointConnections": []}}
    event = subscription({"endpointType": "MonitorAlert", "properties": {"actionGroups": [group]}})
    api = Transport({SCOPE + "/providers/Microsoft.AppConfiguration/configurationStores": {"value": [store]},
                     STORE: store, EVENTS: {"value": [event]}, group: {"id": group, "properties": {
                         "enabled": True, "emailReceivers": [{"emailAddress": "sensitive-marker@example.test", "status": "Enabled"}],
                         "webhookReceivers": [{"serviceUri": "https://hook.example.test/sensitive-marker?sig=sensitive-marker"}]}}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["app_configuration"], transport=api)
    assert [urlsplit(url).path for url in api.calls].count(group) == 1
    assert "sensitive-marker" not in json.dumps(snapshot)
    finding = next(row for row in assess(snapshot, resources(snapshot))
                   if row.resource["type"] == "app_configuration_event_subscription")
    assert finding.verdict() == "FAIL"
    assert "hook.example.test" in finding.external_ids


def test_monitor_action_group_disabled_and_missing_are_distinct():
    group = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/notify"
    item = {"id": EVENTS + "/changes", "properties": {
        "provisioningState": "Succeeded", "endpointType": "MonitorAlert", "actionGroupIds": [group]}}
    collection = {"type": "app_configuration_event_action_group", "scope": group, "service": "Microsoft.Insights",
                  "status": "collected", "items": [{"id": group, "properties": {"enabled": False,
                  "channels": ["email"], "webhookHosts": [], "resourceSubscriptions": [], "unresolvedReceivers": False}}]}
    assert decision(item, collection).verdict() == "PASS"
    assert decision(item).verdict() == "UNKNOWN"
