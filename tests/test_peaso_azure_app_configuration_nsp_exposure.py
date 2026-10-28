"""App Configuration NSP mode overrides the store's public access setting."""

import json
from urllib.parse import urlsplit

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_azure_bulk_native import SUB, SCOPE, Transport

STORE = SCOPE + "/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/store"
NSP = STORE + "/networkSecurityPerimeterConfigurations"
CONFIG = NSP + "/perimeter.association"
PERIMETER = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityPerimeters/zone"


def decision(public, rows, status="collected", members=(), member_status="empty", connections=None,
             connection_status="empty"):
    store_props = {"publicNetworkAccess": public, "endpoint": "https://store.azconfig.io"}
    if connections is not None:
        store_props["privateEndpointConnections"] = connections
    collections = [{"type": "app_configuration", "scope": SCOPE, "service": "Microsoft.AppConfiguration",
                    "status": "collected", "items": [{"id": STORE, "properties": store_props}]},
                   {"type": "app_configuration_nsp", "scope": STORE, "service": "Microsoft.AppConfiguration",
                    "status": status, "items": rows},
                   {"type": "app_configuration_nsp_membership", "scope": PERIMETER, "service": "Microsoft.Network",
                    "status": member_status, "items": list(members)},
                   {"type": "app_configuration_private_connection", "scope": STORE,
                    "service": "Microsoft.AppConfiguration", "status": connection_status, "items": []}]
    snapshot = make_snapshot("azure", [SCOPE], collections)
    return next(row for row in assess(snapshot, resources(snapshot)) if row.resource["type"] == "app_configuration")


def config(prefixes=(), mode="Enforced", subscriptions=(), perimeters=()):
    return {"id": CONFIG, "properties": {"provisioningState": "Accepted", "hasProvisioningIssues": False,
            "perimeterId": PERIMETER,
            "accessMode": mode, "inboundRules": [{"addressPrefixes": list(prefixes),
              "subscriptions": list(subscriptions), "perimeterIds": list(perimeters)}]}}


def test_enforced_perimeter_overrides_both_store_public_settings():
    assert decision("Disabled", [config(["8.8.8.0/24"])]).verdict() == "FAIL"
    assert decision("Enabled", [config()]).verdict() == "PASS"
    assert decision("Enabled", [config(["10.0.0.0/8"])]).verdict() == "PASS"
    assert decision("Enabled", [config(perimeters=[PERIMETER])]).verdict() == "PASS"
    assert decision("Enabled", [config()], member_status="denied").verdict() == "UNKNOWN"


def test_absent_or_transition_configuration_does_not_claim_a_perimeter_block():
    assert decision("Enabled", [], "empty").verdict() == "FAIL"
    assert decision("Disabled", [], "empty").verdict() == "PASS"
    assert decision("Enabled", [], "denied").verdict() == "UNKNOWN"
    assert decision("Disabled", [], "empty", connection_status="denied").verdict() == "UNKNOWN"
    assert decision("Disabled", [config(mode="Learning")]).verdict() == "PASS"
    assert decision("Disabled", [config(["8.8.8.0/24"], mode="Learning")]).verdict() == "FAIL"
    assert decision("Enabled", [config(mode="Learning")]).verdict() == "FAIL"


def test_automatic_public_access_uses_private_endpoint_state():
    approved = {"properties": {"provisioningState": "Succeeded",
                               "privateLinkServiceConnectionState": {"status": "Approved"}}}
    assert decision("Automatic", [], "empty", connections=[]).verdict() == "FAIL"
    assert decision("Automatic", [], "empty", connections=[approved]).verdict() == "PASS"
    assert decision("Automatic", [], "empty", connections=[{}]).verdict() == "UNKNOWN"


def test_foreign_subscription_rule_is_exposed_without_claiming_anonymous_access():
    other = "33333333-3333-3333-3333-333333333333"
    finding = decision("Disabled", [config(subscriptions=[other])])
    assert finding.verdict() == "UNKNOWN"  # malformed rule cannot become a positive grant
    finding = decision("Disabled", [config(subscriptions=["/subscriptions/" + other])])
    assert finding.verdict() == "FAIL" and finding.external_ids == [other]


def test_foreign_member_of_same_perimeter_is_detected():
    other = "33333333-3333-3333-3333-333333333333"
    member = {"id": PERIMETER + "/resourceAssociations/partner",
              "properties": {"protectedResourceId": f"/subscriptions/{other}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/partner",
                             "accessMode": "Enforced", "provisioningState": "Succeeded",
                             "hasProvisioningIssues": "no"}}
    finding = decision("Enabled", [config()], members=[member], member_status="collected")
    assert finding.verdict() == "FAIL" and finding.external_ids == [other]


def test_collector_projects_only_inbound_rule_metadata_once():
    other = "33333333-3333-3333-3333-333333333333"
    connection = {"id": STORE + "/privateEndpointConnections/partner", "name": "partner",
                  "type": "Microsoft.AppConfiguration/configurationStores/privateEndpointConnections",
                  "properties": {"privateEndpoint": {"id": f"/subscriptions/{other}/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/partner"},
                                 "privateLinkServiceConnectionState": {"status": "Approved", "description": "sensitive-marker"},
                                 "provisioningState": "Succeeded"}}
    raw = {"id": CONFIG, "type": "Microsoft.AppConfiguration/configurationStores/networkSecurityPerimeterConfigurations",
           "properties": {"provisioningState": "Accepted", "provisioningIssues": [],
                          "networkSecurityPerimeter": {"id": PERIMETER},
                          "resourceAssociation": {"accessMode": "Enforced"},
                          "profile": {"accessRules": [{"name": "r1", "properties": {
                              "direction": "Inbound", "addressPrefixes": ["8.8.8.0/24"],
                              "subscriptions": [], "networkSecurityPerimeters": [],
                              "secret": "sensitive-marker"}}]}}}
    store = {"id": STORE, "name": "store", "type": "Microsoft.AppConfiguration/configurationStores",
             "properties": {"publicNetworkAccess": "Disabled", "endpoint": "https://store.azconfig.io",
                            "privateEndpointConnections": [connection]}}
    api = Transport({SCOPE + "/providers/Microsoft.AppConfiguration/configurationStores": {"value": [store]},
                     STORE: store, NSP: {"value": [raw]},
                     PERIMETER + "/resourceAssociations": {"value": []}})
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}},
                             ["app_configuration"], transport=api)
    assert [urlsplit(url).path for url in api.calls].count(NSP) == 1
    assert [urlsplit(url).path for url in api.calls].count(PERIMETER + "/resourceAssociations") == 1
    assert "sensitive-marker" not in json.dumps(snapshot)
    findings = {row.resource["type"]: row for row in assess(snapshot, resources(snapshot))}
    assert findings["app_configuration"].verdict() == "FAIL"
    assert findings["app_configuration_private_connection"].verdict() == "FAIL"
    assert findings["app_configuration_private_connection"].external_ids == [other]
