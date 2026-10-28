"""Graph grants to foreign-owned applications are native exposure evidence."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources


OWNER = "00000000-0000-0000-0000-000000000001"
FOREIGN = "00000000-0000-0000-0000-000000000002"
CLIENT = "00000000-0000-0000-0000-000000000003"
RESOURCE = "00000000-0000-0000-0000-000000000004"
SCOPE = "/tenants/" + OWNER


def _assess(*, owner=FOREIGN, principal_inventory="collected", grant_type="directory_oauth2_permission_grant",
            default_role=False, role_enabled=True, client_enabled=True):
    if grant_type == "directory_oauth2_permission_grant":
        grant = {"id": "grant-1", "clientId": CLIENT, "resourceId": RESOURCE,
                 "consentType": "AllPrincipals", "scope": "User.Read Mail.Read"}
    else:
        grant = {"id": "assignment-1", "principalId": CLIENT, "resourceId": RESOURCE,
                 "appRoleId": "00000000-0000-0000-0000-000000000005",
                 "appRoleValue": "Mail.Read", "appRoleEnabled": role_enabled,
                 "defaultAppRole": default_role}
    collections = [{"type": grant_type, "scope": SCOPE, "status": "collected", "items": [grant]},
                   {"type": "directory_service_principal", "scope": SCOPE,
                    "status": principal_inventory, "items": [{"id": CLIENT,
                    "appOwnerOrganizationId": owner, "accountEnabled": client_enabled}] if principal_inventory == "collected" else []}]
    snap = make_snapshot("azure", [SCOPE], collections,
                         metadata={"tenant_id": OWNER, "tenant_verified": True})
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == grant_type)


def test_foreign_delegated_consent_all_users():
    result = _assess()
    assert result.verdict() == "FAIL"
    assert result.external_ids == [CLIENT]
    assert result.path[-1]["consent_type"] == "AllPrincipals"


def test_foreign_application_role_and_uncertain_rights():
    assert _assess(grant_type="directory_app_role_assignment").verdict() == "FAIL"
    assert _assess(grant_type="directory_app_role_assignment", default_role=True).verdict() == "UNKNOWN"
    assert _assess(grant_type="directory_app_role_assignment", role_enabled=None).verdict() == "UNKNOWN"
    assert _assess(principal_inventory="denied").verdict() == "UNKNOWN"
    assert _assess(client_enabled=False).verdict() == "UNKNOWN"
    assert _assess(owner=OWNER).verdict() == "UNKNOWN"


def test_selected_grants_include_client_ownership_inventory():
    selected = azure._selected({"inventories": ["directory_oauth2_permission_grant"]}, None)
    assert "directory_service_principal" in selected
