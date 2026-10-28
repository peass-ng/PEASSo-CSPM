"""Legacy Key Vault data-plane access policies reach observed outside identities."""

from peaso.analysis.iam import review_findings
from peaso.snapshot import make_snapshot, resources

TENANT = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"
GUEST = "33333333-3333-3333-3333-333333333333"
GROUP = "44444444-4444-4444-4444-444444444444"
INNER = "55555555-5555-5555-5555-555555555555"
FOREIGN_SP = "66666666-6666-6666-6666-666666666666"
SCOPE = "/subscriptions/77777777-7777-7777-7777-777777777777"
VAULT = SCOPE + "/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/secretstore"


def collection(kind, scope, items):
    return {"type": kind, "scope": scope, "service": "Microsoft.Graph" if kind.startswith("directory_") else "Microsoft.KeyVault",
            "status": "collected", "items": items}


def findings(policy, *, rbac=None, groups=False):
    props = {"tenantId": TENANT, "enableRbacAuthorization": rbac, "accessPolicies": [policy]}
    rows = [collection("vault", SCOPE, [{"id": VAULT, "properties": props}]),
            collection("directory_user", "/tenants/" + TENANT, [{"id": GUEST, "userType": "Guest"}])]
    if groups:
        rows.extend((
            collection("directory_group", "/tenants/" + TENANT, [{"id": GROUP}, {"id": INNER}]),
            collection("directory_membership", "/tenants/" + TENANT + "/groups/" + GROUP, [{"id": INNER}]),
            collection("directory_membership", "/tenants/" + TENANT + "/groups/" + INNER, [{"id": FOREIGN_SP}]),
            collection("directory_service_principal", "/tenants/" + TENANT,
                       [{"id": FOREIGN_SP, "appOwnerOrganizationId": OTHER}]),
        ))
    snapshot = make_snapshot("azure", [SCOPE], rows, metadata={"tenant_id": TENANT})
    return [row for row in review_findings(snapshot, resources(snapshot))
            if row["check_id"] == "analysis.principal_exposure"]


def policy(principal=GUEST, **changes):
    return {"tenantId": TENANT, "objectId": principal,
            "permissions": {"keys": ["get"], "secrets": ["get"]}, **changes}


def test_guest_vault_access_policy_is_external_data_grant():
    found = findings(policy())
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    grant = found[0]["evidence"]["principals"][0]["native_grant"]
    assert grant["keyVaultAccessPolicy"] is True
    assert grant["permissions"]["secrets"] == ["get"]


def test_rbac_mode_and_non_grants_do_not_activate_legacy_policy():
    assert findings(policy(), rbac=True) == []
    assert findings(policy(), rbac=0) == []
    assert findings(policy(permissions={"secrets": []})) == []
    assert findings(policy(tenantId=OTHER)) == []


def test_vault_group_policy_reaches_nested_foreign_service_principal():
    found = findings(policy(GROUP), groups=True)
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    entry = found[0]["evidence"]["principals"][0]
    assert entry["principal"] == FOREIGN_SP
    grant = entry["native_grant"]
    assert grant["viaGroup"] == GROUP and grant["groupPath"] == [GROUP, INNER]
    assert grant["membershipSource"]


def test_application_bound_access_policy_needs_joint_authorization():
    found = findings(policy(applicationId="88888888-8888-8888-8888-888888888888"))
    assert len(found) == 1 and found[0]["status"] == "MANUAL"
