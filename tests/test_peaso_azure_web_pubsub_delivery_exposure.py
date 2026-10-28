"""Web PubSub hub delivery and anonymous connection exposure."""

import json
from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SCOPE, SUB, Transport


SERVICE = SCOPE + "/resourceGroups/rg/providers/Microsoft.SignalRService/webPubSub/service"
HUB = SERVICE + "/hubs/chat"
OTHER = "33333333-3333-3333-3333-333333333333"


def decisions(hub, namespaces=(), hub_status="collected"):
    service = {"id": SERVICE, "properties": {"publicNetworkAccess": "Disabled"}}
    snapshot = make_snapshot("azure", [SCOPE], [
        {"type": "web_pubsub", "scope": SCOPE, "service": "Microsoft.SignalRService",
         "status": "collected", "items": [service]},
        {"type": "web_pubsub_hub", "scope": SERVICE, "service": "Microsoft.SignalRService",
         "status": hub_status, "items": [hub] if hub else []},
        {"type": "eventhub_namespace", "scope": SCOPE, "service": "Microsoft.EventHub",
         "status": "collected", "items": list(namespaces)}])
    return next(row for row in assess(snapshot, resources(snapshot))
                if row.resource["type"] == "web_pubsub" and row.kind == "external_event_delivery")


def test_http_handler_is_detected_when_public_client_ingress_disabled():
    hub = {"id": HUB, "properties": {"handlerHosts": ["partner.example.test"],
           "eventHubNamespaces": [], "anonymousConnectPolicy": "deny"}}
    finding = decisions(hub)
    assert finding.verdict() == "FAIL" and finding.external_ids == ["partner.example.test"]


def test_event_hub_listener_owner_and_missing_inventory():
    hub = {"id": HUB, "properties": {"handlerHosts": [],
           "eventHubNamespaces": ["events.servicebus.windows.net"], "anonymousConnectPolicy": "deny"}}
    foreign = {"id": f"/subscriptions/{OTHER}/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/events",
               "properties": {"serviceBusEndpoint": "https://events.servicebus.windows.net:443/"}}
    assert decisions(hub, [foreign]).verdict() == "FAIL"
    assert decisions(hub, [{**foreign, "id": foreign["id"].replace(OTHER, SUB)}]).verdict() == "PASS"
    assert decisions(hub).verdict() == "UNKNOWN"
    assert decisions(hub, [foreign], hub_status="partial").verdict() == "FAIL"


def test_collector_projects_http_host_and_event_hub_without_callback_secret():
    service = {"id": SERVICE, "name": "service", "type": "Microsoft.SignalRService/webPubSub",
               "properties": {"publicNetworkAccess": "Disabled"}}
    hub = {"id": HUB, "name": "chat", "type": "Microsoft.SignalRService/WebPubSub/hubs",
           "properties": {"anonymousConnectPolicy": "allow", "eventHandlers": [{
               "urlTemplate": "https://partner.example.test/sensitive-marker?sig=sensitive-marker",
               "userEventPattern": "*", "auth": {"secret": "sensitive-marker"}}],
               "eventListeners": [{"filter": {"type": "EventName", "systemEvents": ["connected"]},
                                   "endpoint": {"type": "EventHub", "fullyQualifiedNamespace":
                                                "events.servicebus.windows.net", "eventHubName": "incoming"}}]}}
    api = Transport({SCOPE + "/providers/Microsoft.SignalRService/webPubSub": {"value": [service]},
                     SERVICE + "/hubs": {"value": [hub]}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["web_pubsub"], transport=api)
    assert [urlsplit(url).path for url in api.calls].count(SERVICE + "/hubs") == 1
    assert "sensitive-marker" not in json.dumps(snapshot)
    projected = next(row for c in snapshot["collections"] if c["type"] == "web_pubsub_hub"
                     for row in c["items"])
    assert projected["properties"]["handlerHosts"] == ["partner.example.test"]
    assert projected["properties"]["anonymousConnectPolicy"] == "allow"
    finding = next(row for row in assess(snapshot, resources(snapshot))
                   if row.resource["type"] == "web_pubsub" and row.kind == "external_event_delivery")
    assert finding.verdict() == "FAIL"


def test_empty_hubs_and_partial_hub_list_are_distinct():
    assert decisions(None, hub_status="empty").verdict() == "PASS"
    assert decisions(None, hub_status="partial").verdict() == "UNKNOWN"


def test_anonymous_hub_is_recorded_on_public_client_listener():
    service = {"id": SERVICE, "properties": {"publicNetworkAccess": "Enabled",
               "hostName": "service.webpubsub.azure.com", "publicPort": 443,
               "networkACLs": {"defaultAction": "Allow", "publicNetwork": {"allow": ["ClientConnection"]},
                               "ipRules": []}}}
    hub = {"id": HUB, "properties": {"handlerHosts": [], "eventHubNamespaces": [],
           "anonymousConnectPolicy": "allow"}}
    snapshot = make_snapshot("azure", [SCOPE], [
        {"type": "web_pubsub", "scope": SCOPE, "service": "Microsoft.SignalRService",
         "status": "collected", "items": [service]},
        {"type": "web_pubsub_hub", "scope": SERVICE, "service": "Microsoft.SignalRService",
         "status": "collected", "items": [hub]}])
    finding = next(row for row in assess(snapshot, resources(snapshot))
                   if row.resource["type"] == "web_pubsub" and row.kind == "managed_endpoint")
    assert finding.verdict() == "FAIL" and finding.authenticated is False
    assert any(step["layer"] == "anonymous_connect" for step in finding.path)
