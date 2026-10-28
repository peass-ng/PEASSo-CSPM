"""Sentinel automation playbook destinations expose incident or alert data."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_sentinel_automation_exposure as native
from peaso.snapshot import make_snapshot, resources

SUB = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"
TENANT = "00000000-0000-0000-0000-000000000003"
FOREIGN_TENANT = "00000000-0000-0000-0000-000000000004"
WORKSPACE = "/subscriptions/" + SUB + "/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/soc"
RULE = WORKSPACE + "/providers/Microsoft.SecurityInsights/automationRules/rule"


def _scan(*, target_sub=OTHER, tenant=None, enabled=True, expiration=None, action="RunPlaybook"):
    playbook = "/subscriptions/" + target_sub + "/resourceGroups/playbooks/providers/Microsoft.Logic/workflows/send"
    raw = {"id": RULE, "type": "Microsoft.SecurityInsights/automationRules",
           "properties": {"displayName": "PRIVATE_NAME", "triggeringLogic": {"isEnabled": enabled,
           "expirationTimeUtc": expiration, "conditions": [{"private": "SECRET"}]},
           "actions": [{"actionType": action, "actionConfiguration": {
               "logicAppResourceId": playbook, "tenantId": tenant,
               "connectionString": "PRIVATE_CONNECTION_STRING"}}]}}

    class Reader:
        collections = [{"type": "sentinel_workspace", "scope": "/subscriptions/" + SUB,
                        "status": "collected", "items": [{"id": WORKSPACE}]}]

        def pages(self, request, url):
            yield request(url)["value"]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": "collected", "items": [item for page in fetch() for item in page]})

    calls = []

    def request(url):
        calls.append(url)
        assert url == "https://management.azure.com" + WORKSPACE + "/providers/Microsoft.SecurityInsights/automationRules?api-version=2025-09-01"
        return {"value": [raw]}

    reader = Reader()
    native.collect(reader, request, {native.KIND})
    assert len(calls) == 1
    assert "PRIVATE" not in str(reader.collections[-1]) and "SECRET" not in str(reader.collections[-1])
    snap = make_snapshot("azure", ["/subscriptions/" + SUB], reader.collections,
                         created_at="2026-10-28T00:00:00+00:00",
                         metadata={"tenant_id": TENANT, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == native.KIND)


def test_enabled_foreign_subscription_or_tenant_playbook():
    first = _scan()
    assert first.verdict() == "FAIL"
    assert first.external_ids[0].startswith("/subscriptions/" + OTHER)
    assert first.data_exposure is True
    assert _scan(target_sub=SUB, tenant=FOREIGN_TENANT).verdict() == "FAIL"


def test_disabled_expired_and_local_routes():
    assert _scan(enabled=False).verdict() == "PASS"
    assert _scan(expiration="2026-10-27T23:00:00Z").verdict() == "PASS"
    assert _scan(target_sub=SUB, tenant=TENANT).verdict() == "UNKNOWN"
    assert _scan(target_sub=SUB, action="AddIncidentTask").verdict() == "PASS"


def test_selected_automation_includes_workspace_without_incident_inventory():
    selected = azure._selected({"inventories": [native.KIND]}, None)
    assert "log_analytics_workspace" in selected
    assert "sentinel_workspace" not in selected
