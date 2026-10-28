"""Cost Management export destinations are cached and credential-free."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_cost_exports_native
from peaso.snapshot import make_snapshot, resources


SOURCE = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
GROUP = SOURCE + "/resourceGroups/rg"
MG = "/providers/Microsoft.Management/managementGroups/root"
TARGET = OTHER + "/resourceGroups/other/providers/Microsoft.Storage/storageAccounts/costs"


def _raw(scope=SOURCE, target=TARGET, sas=False):
    destination = {"container": "costs", "storageAccount": "costs",
                   "sasToken": "must-never-persist"}
    if not sas:
        destination["resourceId"] = target
    return {"id": scope + "/providers/Microsoft.CostManagement/exports/monthly",
            "name": "monthly", "type": "Microsoft.CostManagement/exports",
            "properties": {"deliveryInfo": {"destination": destination},
                           "schedule": {"status": "Active"},
                           "definition": {"type": "ActualCost"},
                           "secret": "must-never-persist"}}


def _decision(scope=SOURCE, target=TARGET, sas=False):
    item = azure_cost_exports_native.project(_raw(scope, target, sas), scope)
    snap = make_snapshot("azure", [SOURCE], [
        {"type": "cost_export", "scope": scope, "service": "Microsoft.CostManagement",
         "status": "collected", "items": [item]}])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "cost_export"), item


def test_foreign_subscription_export_and_sas_owner_uncertainty():
    row, item = _decision()
    assert row.verdict() == "FAIL" and row.external_ids == [TARGET]
    assert "must-never-persist" not in str(item)
    assert _decision(target=SOURCE + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/costs")[0].verdict() == "PASS"
    assert _decision(sas=True)[0].verdict() == "UNKNOWN"


def test_export_list_once_for_each_selected_scope():
    reader = azure._Reader({})
    reader.collections = [
        {"type": "resource_group", "scope": SOURCE, "status": "collected",
         "items": [{"id": GROUP}]},
        {"type": "management_group", "scope": "/tenants/tenant", "status": "collected",
         "items": [{"id": MG}]},
    ]
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        scope = url.split("/providers/Microsoft.CostManagement/exports?", 1)[0].removeprefix(
            "https://management.azure.com")
        return {"value": [_raw(scope)]}

    azure_cost_exports_native.collect(reader, request, [SOURCE, SOURCE], {"cost_export"})
    assert len(calls) == 3
    assert len(set(calls)) == 3
    assert {row["scope"] for row in reader.collections if row["type"] == "cost_export"} == {SOURCE, GROUP, MG}
    assert all("must-never-persist" not in str(row) for row in reader.collections)


def test_selected_export_requests_scope_parents():
    assert {"resource_group", "management_group"} <= azure._selected({}, ["cost_export"])


def test_management_group_export_to_known_foreign_tenant():
    item = azure_cost_exports_native.project(_raw(MG), MG)
    snap = make_snapshot("azure", [SOURCE], [
        {"type": "cost_export", "scope": MG, "service": "Microsoft.CostManagement",
         "status": "collected", "items": [item]},
        {"type": "management_group", "scope": "/tenants/owner", "service": "Microsoft.Management",
         "status": "collected", "items": [{"id": MG, "properties": {"tenantId": "owner"}}]},
    ], metadata={"subscription_tenants": {OTHER: "foreign"}})
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "cost_export")
    assert row.verdict() == "FAIL" and row.external_ids == [TARGET]
