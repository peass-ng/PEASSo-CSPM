"""Subscription managing tenants and direct external RBAC are exposure paths."""

from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
OWNER = "00000000-0000-0000-0000-000000000010"
FOREIGN = "00000000-0000-0000-0000-000000000020"
ROLE = "/providers/Microsoft.Authorization/roleDefinitions/reader"


def _decision(managers=(), *, role=False, include_managers=True, assignments="collected"):
    sub = {"id": SCOPE, "subscriptionId": SCOPE.rsplit("/", 1)[-1],
           "tenantId": OWNER, "state": "Enabled"}
    if include_managers:
        sub["managedByTenants"] = [{"tenantId": tenant} for tenant in managers]
    collections = [
        {"type": "subscription", "scope": SCOPE, "service": "Microsoft.Resources",
         "status": "collected", "items": [sub]},
        {"type": "role_assignment", "scope": SCOPE, "service": "Microsoft.Authorization",
         "status": assignments, "items": [{"id": SCOPE + "/providers/Microsoft.Authorization/roleAssignments/a",
             "properties": {"scope": SCOPE, "principalId": FOREIGN, "principalType": "ServicePrincipal",
                            "roleDefinitionId": ROLE}}] if role else []},
        {"type": "role_assignment", "scope": "/", "service": "Microsoft.Authorization",
         "status": "empty", "items": []},
        {"type": "role_definition", "scope": "/", "service": "Microsoft.Authorization",
         "status": "collected", "items": [{"id": ROLE, "properties": {"permissions": [
             {"actions": ["*/read"], "notActions": []}]}}]},
        {"type": "directory_service_principal", "scope": "/tenants/" + OWNER,
         "service": "Microsoft.Graph", "status": "collected",
         "items": [{"id": FOREIGN, "appOwnerOrganizationId": FOREIGN}]},
    ]
    snap = make_snapshot("azure", [SCOPE], collections,
                         metadata={"tenant_id": OWNER, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "subscription")


def test_foreign_managing_tenant_and_external_subscription_role():
    row = _decision([FOREIGN])
    assert row.verdict() == "FAIL" and row.external_ids == [FOREIGN]
    assert row.path[-1]["managing_tenant_ids"] == [FOREIGN]
    assert _decision([], role=True).verdict() == "FAIL"


def test_same_tenant_no_manager_and_missing_inventory():
    assert _decision([]).verdict() == "PASS"
    assert _decision([OWNER]).verdict() == "PASS"
    assert _decision([], include_managers=False).verdict() == "UNKNOWN"
    assert _decision([], assignments="partial").verdict() == "UNKNOWN"
