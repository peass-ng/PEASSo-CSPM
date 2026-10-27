"""Native Azure exposure additions use only collected configuration."""

import pytest

from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources

SCOPE = "/subscriptions/test"


def decision(kind, properties):
    item = {"id": f"{SCOPE}/resourceGroups/rg/providers/test/{kind}/asset", "properties": properties}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SCOPE, "service": "test",
        "status": "collected", "items": [item]}])
    before = repr(snapshot)
    rows = assess(snapshot, resources(snapshot))
    assert repr(snapshot) == before and len(rows) == 1
    return rows[0]


def test_container_instance_public_ports_and_private_group():
    exposed = decision("container_group", {"ipAddress": {"type": "Public", "ip": "8.8.8.8",
        "ports": [{"protocol": "TCP", "port": 8080}]}})
    assert exposed.verdict() == "FAIL" and exposed.addresses == ["8.8.8.8"]
    assert exposed.ports == {"tcp": ((8080, 8080),)}
    assert decision("container_group", {"ipAddress": {"type": "Public"}}).verdict() == "UNKNOWN"


def test_app_service_unset_public_access_with_private_endpoint_is_uncertain():
    site_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "app_service", "scope": SCOPE, "service": "web", "status": "collected", "items": [
            {"id": site_id, "properties": {"defaultHostName": "app.azurewebsites.net",
             "privateEndpointConnections": [{"id": "endpoint"}]}}]},
        {"type": "app_service_config", "scope": SCOPE, "service": "web", "status": "collected", "items": [
            {"id": site_id + "/config/web", "parent_id": site_id,
             "properties": {"ipSecurityRestrictions": [], "ipSecurityRestrictionsDefaultAction": "Allow"}}]}])
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "app_service")
    assert row.verdict() == "UNKNOWN"


def test_anonymous_blob_requires_container_and_account_gates():
    account_id = f"{SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a"
    container = {"id": account_id + "/blobServices/default/containers/public",
        "parent_id": account_id, "properties": {"publicAccess": "Blob"}}

    def assess_container(account_properties):
        snap = make_snapshot("azure", [SCOPE], [
            {"type": "storage_account", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [{"id": account_id, "properties": account_properties}]},
            {"type": "storage_container", "scope": SCOPE, "service": "storage", "status": "collected",
             "items": [container]}])
        return next(row for row in assess(snap, resources(snap)) if row.resource["type"] == "storage_container")

    open_account = {"allowBlobPublicAccess": True, "publicNetworkAccess": "Enabled",
        "networkAcls": {"defaultAction": "Allow"},
        "primaryEndpoints": {"blob": "https://a.blob.core.windows.net/"}}
    assert assess_container(open_account).verdict() == "FAIL"
    assert assess_container({**open_account, "allowBlobPublicAccess": False}).verdict() == "PASS"
    assert assess_container({**open_account, "networkAcls": {"defaultAction": "Deny"}}).verdict() == "PASS"
    assert assess_container({**open_account, "networkAcls": {}}).verdict() == "UNKNOWN"


@pytest.mark.parametrize("kind", ["vault", "container_registry", "search_service", "servicebus_namespace"])
def test_managed_endpoint_explicit_network_gate(kind):
    rule = {"vault": "networkAcls", "container_registry": "networkRuleSet",
            "search_service": "networkRuleSet", "servicebus_namespace": "networkRuleSet"}[kind]
    assert decision(kind, {"publicNetworkAccess": "Enabled", "endpoint": "https://public.example.test",
                           rule: {"defaultAction": "Allow"}}).verdict() == "FAIL"
    assert decision(kind, {"publicNetworkAccess": "Enabled", rule: {"defaultAction": "Deny"}}).verdict() == "PASS"
    assert decision(kind, {"publicNetworkAccess": "Enabled"}).verdict() == "UNKNOWN"
    assert decision(kind, {"publicNetworkAccess": "Disabled", rule: {"defaultAction": "Allow"}}).verdict() == "PASS"
