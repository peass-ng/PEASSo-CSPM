"""Credential-free Azure Monitor receiver projection and external export assessment."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_swc
from peaso.snapshot import make_snapshot, resources


OWNER = "00000000-0000-0000-0000-000000000001"
FOREIGN = "00000000-0000-0000-0000-000000000002"
SCOPE = "/subscriptions/" + OWNER
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/alerts"


def _row(*, enabled=True, tenant=FOREIGN):
    raw = {"id": RID, "type": "Microsoft.Insights/actionGroups", "properties": {
        "enabled": enabled,
        "webhookReceivers": [{"serviceUri": "https://receiver.example/path/PRIVATE?sig=SECRET"}],
        "logicAppReceivers": [{"callbackUrl": "https://logic.example/workflows/PRIVATE?sig=SECRET"}],
        "azureFunctionReceivers": [{"httpTriggerUrl": "https://function.example/api/PRIVATE?code=SECRET"}],
        "emailReceivers": [{"emailAddress": "person@example.org", "status": "Enabled"}],
        "eventHubReceivers": [{"tenantId": tenant, "subscriptionId": FOREIGN,
                               "eventHubNameSpace": "namespace", "eventHubName": "events"}]}}
    return azure_swc.list_detail(raw, "action_group")


def _assess(row):
    snap = make_snapshot("azure", [SCOPE], [{"type": "action_group", "scope": SCOPE,
                                             "status": "collected", "items": [row]}],
                         metadata={"tenant_id": OWNER, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "action_group")


def test_foreign_event_hub_and_secret_safe_receivers():
    row = _row()
    assert "SECRET" not in str(row) and "PRIVATE" not in str(row)
    assert "person@" not in str(row)
    assert {r["host"] for r in row["_exposureReceivers"] if "host" in r} == {
        "receiver.example", "logic.example", "function.example"}
    result = _assess(row)
    assert result.verdict() == "FAIL"
    assert result.external_ids == [FOREIGN]


def test_disabled_and_unknown_receiver_ownership():
    assert _assess(_row(enabled=False)).verdict() == "PASS"
    assert _assess(_row(tenant=OWNER)).verdict() == "FAIL"  # foreign subscription
    row = _row(tenant=OWNER)
    row["_exposureReceivers"] = [r for r in row["_exposureReceivers"] if r["kind"] != "eventHub"]
    assert _assess(row).verdict() == "UNKNOWN"


def _export(kind, props):
    row = {"id": RID + "/diagnosticSettings/export", "properties": props}
    snap = make_snapshot("azure", [SCOPE], [{"type": kind, "scope": SCOPE,
                                             "status": "collected", "items": [row]}])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == kind)


def test_diagnostic_and_log_profile_foreign_export():
    partner = "/subscriptions/" + OWNER + "/resourceGroups/rg/providers/Microsoft.Datadog/monitors/partner"
    props = {"logs": [{"category": "Administrative", "enabled": True}], "metrics": [],
             "marketplacePartnerId": partner}
    result = _export("subscription_diagnostic_setting", props)
    assert result.verdict() == "FAIL" and partner in result.external_ids
    foreign_storage = "/subscriptions/" + FOREIGN + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs"
    assert _export("diagnostic_setting", {"logs": [{"enabled": True}], "storageAccountId": foreign_storage}).verdict() == "FAIL"
    assert _export("monitor_log_profile", {"categories": ["Write"], "locations": ["global"],
                                           "storageAccountId": foreign_storage}).verdict() == "FAIL"
    assert _export("diagnostic_setting", {"logs": [{"enabled": False}], "storageAccountId": foreign_storage}).verdict() == "PASS"


def test_action_group_collector_reuses_list_and_never_stores_receiver_secrets():
    class Transport:
        tenant = OWNER
        verified_tenant = True

        def __init__(self):
            self.calls = []

        def request(self, url, *, body=None, audience=None):
            self.calls.append(url)
            row = {"id": RID, "type": "Microsoft.Insights/actionGroups", "properties": {
                "enabled": True,
                "webhookReceivers": [{"serviceUri": "https://receiver.example/path/PRIVATE?sig=SECRET"}],
                "eventHubReceivers": [{"tenantId": FOREIGN, "subscriptionId": FOREIGN}]}}
            if "/Microsoft.ResourceGraph/resources" in url:
                return {"data": []}
            if url.endswith("/actionGroups?api-version=2023-01-01"):
                return {"value": [row]}
            if "/diagnosticSettings?" in url:
                return {"value": []}
            return row

    transport = Transport()
    snap = azure.collect({"scopes": [SCOPE], "options": {"inventories": ["action_group"],
                          "concurrency": 1, "retries": 0}, "auth": {}},
                         requirements=["action_group"], transport=transport)
    assert len(transport.calls) == len(set(transport.calls)) == 4
    assert "SECRET" not in str(snap) and "PRIVATE" not in str(snap)
    result = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "action_group")
    assert result.verdict() == "FAIL"
