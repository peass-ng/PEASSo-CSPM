"""Managed HSM local RBAC uses its own bound data-plane LIST."""

from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure
from peaso.analysis.iam import review_findings
from peaso.snapshot import make_snapshot, resources

SUB = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"
GUEST = "33333333-3333-3333-3333-333333333333"
SCOPE = "/subscriptions/" + SUB
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.KeyVault/managedHSMs/hsm"
URI = "https://westus.hsm.managedhsm.azure.net"
ASSIGNMENT = {"id": "/keys/providers/Microsoft.Authorization/roleAssignments/44444444-4444-4444-4444-444444444444",
              "type": "Microsoft.Authorization/roleAssignments",
              "name": "44444444-4444-4444-4444-444444444444",
              "properties": {"scope": "/keys", "principalId": GUEST,
                             "roleDefinitionId": "/keys/providers/Microsoft.Authorization/roleDefinitions/55555555-5555-5555-5555-555555555555"}}
DEFINITION = {"id": ASSIGNMENT["properties"]["roleDefinitionId"],
              "type": "Microsoft.Authorization/roleDefinitions", "name": "55555555-5555-5555-5555-555555555555",
              "properties": {"roleName": "Key Reader", "permissions": [{"dataActions": ["Microsoft.KeyVault/managedHsm/keys/read/action"],
                                                                       "notDataActions": []}]}}


class Transport:
    tenant = verified_tenant = TENANT

    def __init__(self):
        self.calls = []
        self.allowed = []

    def allow_hsm(self, uri, name):
        self.allowed.append((uri, name))

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, audience))
        path = urlsplit(url).path
        if path == SCOPE + "/providers/Microsoft.KeyVault/managedHSMs":
            return {"value": [{"id": RID, "name": "hsm", "type": "Microsoft.KeyVault/managedHSMs",
                "properties": {"hsmUri": URI, "publicNetworkAccess": "Enabled"}}]}
        if path.endswith("//keys/providers/Microsoft.Authorization/roleAssignments"):
            assert audience == azure.VAULT
            return {"value": [ASSIGNMENT]}
        if path.endswith("//keys/providers/Microsoft.Authorization/roleDefinitions"):
            assert audience == azure.VAULT
            return {"value": [DEFINITION]}
        if path.endswith("//providers/Microsoft.Authorization/roleAssignments"):
            assert audience == azure.VAULT
            return {"value": []}
        return {"value": []}


def test_hsm_local_assignments_read_once_per_top_level_scope():
    transport = Transport()
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["managed_hsm"], transport=transport)
    hsm = next(c for c in snapshot["collections"] if c["type"] == "managed_hsm")["items"][0]
    assert transport.allowed == [(URI, "hsm")]
    assert hsm["_coverage"]["localRoleAssignments"]["status"] == "collected"
    assert hsm["localRoleAssignments"][0]["properties"]["principalId"] == GUEST
    assert hsm["_coverage"]["localRoleDefinitions"]["status"] == "collected"
    assert hsm["localRoleDefinitions"][0]["properties"]["permissions"][0]["dataActions"] == ["Microsoft.KeyVault/managedHsm/keys/read/action"]
    assert sum("/roleAssignments" in urlsplit(url).path for url, _ in transport.calls) == 2


def test_hsm_local_assignments_include_individual_key_scope():
    class KeyTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            if path == "/keys":
                self.calls.append((url, audience))
                return {"value": [{"kid": URI + "/keys/one"}]}
            if path.endswith("//keys/one/providers/Microsoft.Authorization/roleAssignments"):
                self.calls.append((url, audience))
                return {"value": [{**ASSIGNMENT,
                    "id": "/keys/one/providers/Microsoft.Authorization/roleAssignments/44444444-4444-4444-4444-444444444444",
                    "properties": {**ASSIGNMENT["properties"], "scope": "/keys/one"}}]}
            return super().request(url, body=body, audience=audience)
    transport = KeyTransport()
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["managed_hsm"], transport=transport)
    hsm = next(c for c in snapshot["collections"] if c["type"] == "managed_hsm")["items"][0]
    assert hsm["_coverage"]["localRoleAssignmentKeys"]["status"] == "collected"
    assert hsm["_coverage"]["localRoleAssignments"]["status"] == "collected"
    assert {row["properties"]["scope"] for row in hsm["localRoleAssignments"]} == {"/keys", "/keys/one"}
    assert sum("/roleAssignments" in urlsplit(url).path for url, _ in transport.calls) == 3


def test_hsm_key_inventory_denial_keeps_local_rbac_partial():
    class DeniedKeyTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            if urlsplit(url).path == "/keys":
                raise azure.AzureReadError("key list denied", status_code=403)
            return super().request(url, body=body, audience=audience)
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["managed_hsm"], transport=DeniedKeyTransport())
    hsm = next(c for c in snapshot["collections"] if c["type"] == "managed_hsm")["items"][0]
    assert hsm["_coverage"]["localRoleAssignmentKeys"]["status"] != "collected"
    assert hsm["_coverage"]["localRoleAssignments"]["status"] == "partial"
    assert hsm["localRoleAssignments"][0]["properties"]["scope"] == "/keys"


def test_hsm_role_definition_denial_is_visible():
    class DeniedDefinitionTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            if urlsplit(url).path.endswith("//keys/providers/Microsoft.Authorization/roleDefinitions"):
                raise azure.AzureReadError("role definition list denied", status_code=403)
            return super().request(url, body=body, audience=audience)
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0}}, ["managed_hsm"], transport=DeniedDefinitionTransport())
    hsm = next(c for c in snapshot["collections"] if c["type"] == "managed_hsm")["items"][0]
    assert hsm["_coverage"]["localRoleDefinitions"]["status"] != "collected"
    assert hsm["localRoleDefinitions"] == []


def test_hsm_data_plane_origin_is_bound_to_arm_name():
    transport = azure.AzureTransport({"method": "token", "vault_token": "fixture"})
    transport.allow_hsm(URI, "hsm")
    assert "westus.hsm.managedhsm.azure.net" in transport.vault_hosts
    with pytest.raises(azure.AzureReadError):
        transport.allow_hsm("https://westus.other.managedhsm.azure.net", "hsm")


def test_hsm_local_assignment_to_observed_guest_is_external_principal():
    hsm = {"id": RID, "properties": {"hsmUri": URI},
           "_coverage": {"localRoleAssignments": {"status": "collected"},
                         "localRoleDefinitions": {"status": "collected"}},
           "localRoleAssignments": [ASSIGNMENT], "localRoleDefinitions": [DEFINITION]}
    snapshot = make_snapshot("azure", [SCOPE], [
        {"type": "managed_hsm", "scope": SCOPE, "service": "Microsoft.KeyVault", "status": "collected", "items": [hsm]},
        {"type": "directory_user", "scope": "/tenants/" + TENANT, "service": "Microsoft.Graph", "status": "collected",
         "items": [{"id": GUEST, "userType": "Guest"}]},
    ], metadata={"tenant_id": TENANT})
    found = [row for row in review_findings(snapshot, resources(snapshot))
             if row["check_id"] == "analysis.principal_exposure"]
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    grant = found[0]["evidence"]["principals"][0]["native_grant"]
    assert grant["hsmLocalRbac"] is True and grant["scope"] == "/keys"
    assert grant["roleDefinition"]["permissions"][0]["dataActions"] == ["Microsoft.KeyVault/managedHsm/keys/read/action"]


def test_hsm_local_group_assignment_reaches_nested_outside_members():
    outer = "66666666-6666-6666-6666-666666666666"
    inner = "77777777-7777-7777-7777-777777777777"
    foreign_sp = "88888888-8888-8888-8888-888888888888"
    assignment = {**ASSIGNMENT, "properties": {**ASSIGNMENT["properties"], "principalId": outer}}
    snapshot = make_snapshot("azure", [SCOPE], [
        {"type": "managed_hsm", "scope": SCOPE, "service": "Microsoft.KeyVault", "status": "collected",
         "items": [{"id": RID, "localRoleAssignments": [assignment], "localRoleDefinitions": [DEFINITION],
                    "_coverage": {"localRoleAssignments": {"status": "collected"}}}]},
        {"type": "directory_group", "scope": "/tenants/" + TENANT, "service": "Microsoft.Graph", "status": "collected",
         "items": [{"id": outer}, {"id": inner}]},
        {"type": "directory_membership", "scope": "/tenants/" + TENANT + "/groups/" + outer,
         "service": "Microsoft.Graph", "status": "collected", "items": [{"id": inner}]},
        {"type": "directory_membership", "scope": "/tenants/" + TENANT + "/groups/" + inner,
         "service": "Microsoft.Graph", "status": "collected", "items": [{"id": GUEST}, {"id": foreign_sp}]},
        {"type": "directory_user", "scope": "/tenants/" + TENANT, "service": "Microsoft.Graph", "status": "collected",
         "items": [{"id": GUEST, "userType": "Guest"}]},
        {"type": "directory_service_principal", "scope": "/tenants/" + TENANT,
         "service": "Microsoft.Graph", "status": "collected",
         "items": [{"id": foreign_sp, "appOwnerOrganizationId": "99999999-9999-9999-9999-999999999999"}]},
    ], metadata={"tenant_id": TENANT})
    found = [row for row in review_findings(snapshot, resources(snapshot))
             if row["check_id"] == "analysis.principal_exposure" and row["status"] == "FAIL"]
    assert len(found) == 1
    grants = {row["principal"]: row["native_grant"] for row in found[0]["evidence"]["principals"]}
    assert set(grants) == {GUEST, foreign_sp}
    assert all(grant["viaGroup"] == outer and grant["groupPath"] == [outer, inner]
               and grant["membershipSource"] and grant["scope"] == "/keys"
               for grant in grants.values())
