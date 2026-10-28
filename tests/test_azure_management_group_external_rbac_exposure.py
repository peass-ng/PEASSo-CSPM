"""Management-group role grants can share all descendant subscriptions."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources


TENANT = "00000000-0000-0000-0000-000000000010"
SCOPE = "/tenants/" + TENANT
GROUP = "/providers/Microsoft.Management/managementGroups/root"
ASSIGNMENT = GROUP + "/providers/Microsoft.Authorization/roleAssignments/a"
DEFINITION = "/providers/Microsoft.Authorization/roleDefinitions/reader"
PRINCIPAL = "00000000-0000-0000-0000-000000000020"


def _assess(*, owner="external", role=True, assignment=True, root=False, status="collected", condition=None):
    collections = [
        {"type": "management_group", "scope": SCOPE, "service": "Microsoft.Management",
         "status": "collected", "items": [{"id": GROUP, "type": "Microsoft.Management/managementGroups",
             "properties": {"tenantId": TENANT, "children": [{"id": "/subscriptions/00000000-0000-0000-0000-000000000001",
                                                     "type": "/subscriptions"}]}}]},
        {"type": "role_assignment", "scope": GROUP, "service": "Microsoft.Authorization",
         "status": status, "items": [{"id": ASSIGNMENT, "properties": {"scope": GROUP,
             "principalId": PRINCIPAL, "principalType": "ServicePrincipal", "roleDefinitionId": DEFINITION,
             **({"condition": condition} if condition else {})}}] if assignment else []},
        {"type": "role_assignment", "scope": "/", "service": "Microsoft.Authorization",
         "status": "collected" if root else "empty", "items": [{"id": "/providers/Microsoft.Authorization/roleAssignments/root",
             "properties": {"scope": "/", "principalId": PRINCIPAL,
                            "principalType": "ServicePrincipal", "roleDefinitionId": DEFINITION}}] if root else []},
        {"type": "role_definition", "scope": "/", "service": "Microsoft.Authorization",
         "status": "collected", "items": [{"id": DEFINITION, "properties": {"permissions": [
             {"actions": ["*/read"], "notActions": [], "dataActions": []}]}}] if role else []},
        {"type": "directory_service_principal", "scope": SCOPE, "service": "Microsoft.Graph",
         "status": "collected", "items": [{"id": PRINCIPAL, "appOwnerOrganizationId":
             "00000000-0000-0000-0000-000000000020" if owner == "external" else TENANT}]},
    ]
    snap = make_snapshot("azure", ["/subscriptions/00000000-0000-0000-0000-000000000001"],
                         collections, metadata={"tenant_id": TENANT, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "management_group")


def test_external_management_group_role_grant():
    row = _assess()
    assert row.verdict() == "FAIL"
    assert row.external_ids == [PRINCIPAL]
    assert row.path[-1]["grants"][0]["role_definition_id"] == DEFINITION


def test_owned_or_absent_grant_and_incomplete_inventory():
    assert _assess(owner="owned").verdict() == "PASS"
    assert _assess(assignment=False).verdict() == "PASS"
    assert _assess(status="partial").verdict() == "UNKNOWN"
    assert _assess(role=False).verdict() == "UNKNOWN"
    assert _assess(condition="@Resource[Microsoft.Storage/storageAccounts:name] StringEquals 'x'").verdict() == "UNKNOWN"
    assert _assess(assignment=False, root=True).verdict() == "FAIL"


def test_selected_management_group_includes_role_and_directory_evidence():
    selected = azure._selected({}, ["management_group"])
    assert {"role_assignment", "role_definition", "directory_user", "directory_group",
            "directory_service_principal", "directory_membership"} <= selected


def test_guest_member_of_assigned_group_is_external():
    assigned_group = "00000000-0000-0000-0000-000000000030"
    guest = "00000000-0000-0000-0000-000000000040"
    collections = [
        {"type": "management_group", "scope": SCOPE, "service": "Microsoft.Management",
         "status": "collected", "items": [{"id": GROUP, "properties": {"tenantId": TENANT}}]},
        {"type": "role_assignment", "scope": GROUP, "service": "Microsoft.Authorization",
         "status": "collected", "items": [{"id": ASSIGNMENT, "properties": {"scope": GROUP,
             "principalId": assigned_group, "principalType": "Group", "roleDefinitionId": DEFINITION}}]},
        {"type": "role_assignment", "scope": "/", "service": "Microsoft.Authorization",
         "status": "empty", "items": []},
        {"type": "role_definition", "scope": "/", "service": "Microsoft.Authorization",
         "status": "collected", "items": [{"id": DEFINITION, "properties": {"permissions": [
             {"actions": ["*/read"], "notActions": []}]}}]},
        {"type": "directory_group", "scope": SCOPE, "service": "Microsoft.Graph",
         "status": "collected", "items": [{"id": assigned_group}]},
        {"type": "directory_membership", "scope": SCOPE + "/groups/" + assigned_group,
         "service": "Microsoft.Graph", "status": "collected", "items": [{"id": guest}]},
        {"type": "directory_user", "scope": SCOPE, "service": "Microsoft.Graph",
         "status": "collected", "items": [{"id": guest, "userType": "Guest"}]},
    ]
    snap = make_snapshot("azure", ["/subscriptions/00000000-0000-0000-0000-000000000001"],
                         collections, metadata={"tenant_id": TENANT, "tenant_verified": True})
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "management_group")
    assert row.verdict() == "FAIL" and row.external_ids == [guest]
