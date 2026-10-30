"""Behaviour of the claude_azure IDENTITY group predicates."""
import copy

import pytest

import peaso.checks.claude_azure_identity as identity
from peaso.checks import CHECK_ALIASES, CHECKS, evaluate_check
from peaso.checks.claude_azure_common import scope_index
from peaso.checks.fixtures import CASES
from tests.azure_native_successor_inputs_20261020 import current_cases

REGISTRY = {check.id: check for check in CHECKS}
IDS = list(identity.IDENTITY_CHECK_IDS)


def run(check_id, item, index=None):
    return REGISTRY[check_id].evaluate(item, {} if index is None else index)[0]


def cid(slug):
    return "azure.claude." + slug


def test_group_registers_unique_prefixed_ids():
    # aks_authorized_ip_ranges is retired as an alias of azure.aks.api_server_restricted.
    assert len(IDS) == len(set(IDS)) == 86
    assert CHECK_ALIASES[cid("aks_authorized_ip_ranges")] == "azure.aks.api_server_restricted"
    assert all(check_id.startswith("azure.claude.") for check_id in IDS)


@pytest.mark.parametrize("check_id", IDS)
def test_fixtures(check_id):
    cases = current_cases(check_id, CASES[check_id])
    assert "index" not in cases or REGISTRY[check_id].target != "scope"
    expected_cases = (("pass", "PASS"), ("fail", "FAIL"))
    if check_id == cid("iam_root_custom_role_no_wildcard"):
        # Azure RBAC no longer permits root-scoped CustomRole definitions.
        # There is no valid supported PASS/FAIL fixture for this obsolete
        # root-scope criterion. Preserve the historical UNKNOWN and ordinary
        # non-root NOT_APPLICABLE evidence under truthful CASES keys.
        expected_cases = (("not_applicable", "NOT_APPLICABLE"), ("unknown", "UNKNOWN"))
    if check_id == cid('managed_hsm_audit_logging'):
        # The obsolete retention field cannot prove current retention; the
        # separate declared-audit replacement is reviewed independently.
        expected_cases = (('unknown', 'UNKNOWN'), ('fail', 'FAIL'))
    for name, expected in expected_cases:
        data = copy.deepcopy(cases[name])
        index = copy.deepcopy(cases.get(name + "_index", {}))
        assert REGISTRY[check_id].evaluate(data, index)[0] == expected, name
        assert data == cases[name] and index == cases.get(name + "_index", {})
    for missing in ({}, None, {"collection_status": "denied"}):
        assert run(check_id, missing) == "UNKNOWN"


def test_scope_checks_need_inventory():
    scope_ids = [check_id for check_id in IDS if REGISTRY[check_id].target == "scope"]
    assert scope_ids
    for check_id in scope_ids:
        assert "pass_index" in CASES[check_id] and "fail_index" in CASES[check_id]
        assert run(check_id, {"scope": "/subscriptions/s"}, {}) == "UNKNOWN"


# --- Entra -----------------------------------------------------------------------------------------------

def tenant_index(kind, items, scope="/tenants/t"):
    index = scope_index({kind: items})
    index["context"] = {"scope": scope}
    return index


def test_tenant_aggregate_scope_gating():
    policy = CASES[cid("entra_ca_mfa_admin_portals")]["pass_index"]
    assert run(cid("entra_ca_mfa_admin_portals"), {"tenantId": "other"}, policy) == "NOT_APPLICABLE"
    selected = copy.deepcopy(policy)
    selected["context"]["scope"] = "/tenants/selected"
    assert run(cid("entra_ca_mfa_admin_portals"), {"tenantId": "t"}, selected) == "UNKNOWN"
    assert run(cid("entra_ca_mfa_admin_portals"), {"tenantId": "t"}, {"context": {"scope": "/tenants/t"}}) == "UNKNOWN"


def test_ca_mfa_requires_all_users_and_target():
    base = {"id": "p", "state": "enabled", "conditions": {"users": {"includeUsers": ["group-a"]},
            "applications": {"includeApplications": ["MicrosoftAdminPortals"]}}, "grantControls": {"builtInControls": ["mfa"]}}
    assert run(cid("entra_ca_mfa_admin_portals"), {"tenantId": "t"}, tenant_index("conditional_access_policy", [base])) == "FAIL"
    assert run(cid("entra_ca_mfa_management_api"), {"tenantId": "t"}, tenant_index("conditional_access_policy", [])) == "FAIL"
    session_only = dict(base, conditions={"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["MicrosoftAdminPortals"]}}, grantControls=None)
    assert run(cid("entra_ca_mfa_admin_portals"), {"tenantId": "t"}, tenant_index("conditional_access_policy", [session_only])) == "FAIL"
    assert run(cid("entra_ca_mfa_admin_portals"), {"tenantId": "t"}, tenant_index("conditional_access_policy", [dict(base, state="weird")])) == "UNKNOWN"


def test_global_admin_counts_distinct_root_principals():
    rows = [{"principalId": "p1", "roleDefinitionId": identity.GLOBAL_ADMINISTRATOR, "directoryScopeId": "/"}] * 6
    assert run(cid("entra_global_admin_fewer_than_five"), {"tenantId": "t"}, tenant_index("directory_role_assignment", rows)) == "PASS"


def test_m365_group_setting_value_must_be_present():
    unified = {"displayName": "Group.Unified", "values": [{"name": "UsageGuidelinesUrl", "value": ""}]}
    assert run(cid("entra_m365_group_creation_restricted"), {"tenantId": "t"}, tenant_index("directory_setting", [unified])) == "UNKNOWN"
    unified["values"].append({"name": "EnableGroupCreation", "value": "true"})
    assert run(cid("entra_m365_group_creation_restricted"), {"tenantId": "t"}, tenant_index("directory_setting", [unified])) == "FAIL"


def test_user_consent_predicates_are_distinct():
    low = {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]}}
    assert run(cid("entra_user_consent_disabled"), low) == "FAIL"
    assert run(cid("entra_user_consent_not_legacy"), low) == "PASS"
    assert run(cid("entra_user_consent_disabled"), {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": [3]}}) == "UNKNOWN"


def test_guest_role_unknown_value():
    assert run(cid("entra_guest_access_restricted"), {"guestUserRoleId": "00000000-0000-0000-0000-000000000000"}) == "UNKNOWN"


def test_strong_auth_requires_campaign_and_method():
    policy = copy.deepcopy(CASES[cid("entra_auth_methods_strong_registration")]["pass"])
    policy["authenticationMethodConfigurations"][0]["state"] = "disabled"
    assert run(cid("entra_auth_methods_strong_registration"), policy) == "FAIL"
    policy["authenticationMethodConfigurations"] = [{"id": "Sms", "state": "enabled"}]
    assert run(cid("entra_auth_methods_strong_registration"), policy) == "FAIL"


def test_named_location_types():
    assert run(cid("entra_named_location_trusted"), {"@odata.type": "#microsoft.graph.countryNamedLocation"}) == "NOT_APPLICABLE"
    assert run(cid("entra_named_location_trusted"), {"@odata.type": "#microsoft.graph.other"}) == "UNKNOWN"


def test_time_based_rules_need_snapshot_time():
    app = CASES[cid("entra_app_credential_not_expiring")]["pass"]
    assert run(cid("entra_app_credential_not_expiring"), app, {}) == "UNKNOWN"
    assert run(cid("entra_app_credential_not_expiring"), {"passwordCredentials": [], "keyCredentials": []}, {}) == "NOT_APPLICABLE"
    never = {"passwordCredentials": [{"keyId": "k", "endDateTime": None}], "keyCredentials": []}
    assert run(cid("entra_app_credential_not_expiring"), never, {"context": {"created_at": "2026-01-01T00:00:00Z"}}) == "FAIL"
    expired = {"passwordCredentials": [{"keyId": "k", "endDateTime": "2025-01-01T00:00:00Z"}], "keyCredentials": []}
    assert run(cid("entra_app_credential_not_expiring"), expired, {"context": {"created_at": "2026-01-01T00:00:00Z"}}) == "FAIL"
    user = {"id": "u", "accountEnabled": True, "signInActivity": {"lastSignInDateTime": None}}
    assert run(cid("entra_user_recent_sign_in"), user, {"context": {"created_at": "2026-01-01T00:00:00Z"}}) == "UNKNOWN"
    # Without verified directory capture authority even a disabled user fails closed;
    # the bound NOT_APPLICABLE path is covered in test_unused_iam_azure_user_completion.
    assert run(cid("entra_user_recent_sign_in"), dict(user, accountEnabled=False), {}) == "UNKNOWN"
    assert run(cid("entra_user_recent_sign_in"), {"id": "u", "accountEnabled": True}, {"context": {"created_at": "2026-01-01T00:00:00Z"}}) == "UNKNOWN"


def test_user_mfa_privilege_split():
    privileged = CASES[cid("entra_privileged_user_mfa")]["fail_index"]
    plain = CASES[cid("entra_non_privileged_user_mfa")]["fail_index"]
    user = {"id": "u1", "accountEnabled": True}
    assert run(cid("entra_non_privileged_user_mfa"), user, privileged) == "NOT_APPLICABLE"
    assert run(cid("entra_privileged_user_mfa"), user, plain) == "NOT_APPLICABLE"
    assert run(cid("entra_non_privileged_user_mfa"), dict(user, accountEnabled=False), plain) == "NOT_APPLICABLE"
    no_detail = scope_index({"directory_role_assignment": [], "user_registration_detail": []})
    assert run(cid("entra_non_privileged_user_mfa"), user, no_detail) == "UNKNOWN"


def test_vm_access_mfa_is_unknown_without_registration_inventory():
    owner = CASES[cid("entra_vm_access_user_mfa")]["pass"]
    assert run(cid("entra_vm_access_user_mfa"), owner, {}) == "UNKNOWN"
    reader = identity._assignment(identity.READER)
    assert run(cid("entra_vm_access_user_mfa"), reader, {}) == "NOT_APPLICABLE"


# --- Azure RBAC --------------------------------------------------------------------------------------------

def test_owner_count_ignores_resource_group_scope_and_duplicates():
    rows = [identity._assignment(identity.OWNER, "o1"), identity._assignment(identity.OWNER, "o1"),
            identity._assignment(identity.OWNER, "o2", scope="/subscriptions/s/resourceGroups/rg"),
            identity._assignment(identity.OWNER, "o3", scope="/providers/Microsoft.Management/managementGroups/mg")]
    index = scope_index({"role_assignment": rows})
    assert run(cid("iam_subscription_owner_between_2_and_3"), {"scope": "/subscriptions/s"}, index) == "PASS"
    assert run(cid("iam_subscription_owner_more_than_1"), {"scope": "/subscriptions/s"}, scope_index({"role_assignment": []})) == "FAIL"
    assert run(cid("iam_subscription_owner_max_3"), {"scope": "/subscriptions/s"}, scope_index({"role_assignment": []})) == "PASS"


def test_user_join_failures_are_unknown():
    index = scope_index({"role_assignment": [identity._assignment(identity.OWNER, "ghost")], "directory_user": [identity._user()]})
    assert run(cid("iam_external_user_no_owner"), {"scope": "/subscriptions/s"}, index) == "UNKNOWN"
    only_rbac = scope_index({"role_assignment": [identity._assignment(identity.OWNER)]})
    assert run(cid("iam_disabled_user_no_owner"), {"scope": "/subscriptions/s"}, only_rbac) == "UNKNOWN"


def test_external_detection_by_upn_marker():
    member_ext = identity._user(upn="carol_fabrikam.com#EXT#@contoso.onmicrosoft.com", user_type="Member")
    index = scope_index({"role_assignment": [identity._assignment(identity.CONTRIBUTOR)], "directory_user": [member_ext]})
    assert run(cid("iam_external_user_no_write"), {"scope": "/subscriptions/s"}, index) == "FAIL"
    assert run(cid("iam_external_user_no_reader"), {"scope": "/subscriptions/s"}, index) == "PASS"


def test_role_assignment_and_definition_edges():
    group = identity._assignment(identity.CONTRIBUTOR, principal_type="Group")
    assert run(cid("iam_user_no_contributor_assignment"), group) == "NOT_APPLICABLE"
    assert run(cid("iam_custom_role_no_wildcard_actions"), identity._definition("BuiltInRole", actions=("*",))) == "NOT_APPLICABLE"
    assert run(cid("iam_custom_role_no_wildcard_actions"), identity._definition(actions=("*:*",))) == "FAIL"
    assert run(cid("iam_root_custom_role_no_wildcard"), identity._definition(actions=("Microsoft.Compute/*",), scopes=("/",))) == "UNKNOWN"
    assert run(cid("iam_custom_role_no_wildcard_actions"), {"properties": {"type": "Odd", "permissions": []}}) == "UNKNOWN"


def test_tenant_transfer_requires_both_blocks():
    assert run(cid("iam_subscription_tenant_transfer_restricted"), {"properties": {"blockSubscriptionsIntoTenant": False, "blockSubscriptionsLeavingTenant": True}}) == "FAIL"
    assert run(cid("iam_subscription_tenant_transfer_restricted"), {"properties": {"blockSubscriptionsIntoTenant": "true", "blockSubscriptionsLeavingTenant": True}}) == "UNKNOWN"


# --- PaaS ------------------------------------------------------------------------------------------------

def test_private_link_states_and_basic_tier():
    pending = {"sku": {"tier": "Standard"}, "properties": {"privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Pending"}}}]}}
    assert run(cid("iot_hub_private_link"), pending) == "FAIL"
    assert run(cid("eventhub_namespace_private_link"), dict(pending, sku={"tier": "Basic"})) == "NOT_APPLICABLE"
    odd = copy.deepcopy(pending)
    odd["properties"]["privateEndpointConnections"][0]["properties"]["privateLinkServiceConnectionState"]["status"] = "Strange"
    assert run(cid("fhir_private_link"), odd) == "UNKNOWN"
    disabled_no_pe = {"properties": {"publicNetworkAccess": "Disabled", "privateEndpointConnections": []}}
    assert run(cid("eventgrid_topic_private_link"), disabled_no_pe) == "FAIL"


def test_hdinsight_skips_unprovisioned():
    assert run(cid("hdinsight_cmk"), {"properties": {"provisioningState": "Deleting"}}) == "NOT_APPLICABLE"


def test_logging_rules_without_diagnostics_are_unknown_or_fail():
    assert run(cid("eventhub_namespace_logging"), {"name": "ns"}) == "UNKNOWN"
    assert run(cid("iot_hub_logging"), {"diagnosticSettings": []}) == "FAIL"
    retention_without_days = {"diagnosticSettings": [{"properties": {"logs": [{"enabled": True, "category": "Connections", "retentionPolicy": {"enabled": True}}]}}]}
    assert run(cid("iot_hub_logging"), retention_without_days) == "FAIL"


# --- Key Vault --------------------------------------------------------------------------------------------

def test_keyvault_logging_variants():
    groups = {"diagnosticSettings": [{"properties": {"logs": [{"enabled": True, "categoryGroup": "audit"}, {"enabled": True, "categoryGroup": "allLogs"}]}}]}
    assert run(cid("keyvault_audit_logging"), groups) == "PASS"
    audit_event = CASES[cid("keyvault_audit_logging")]["pass"]
    assert run(cid("keyvault_audit_and_alllogs_groups"), audit_event) == "FAIL"


def test_rbac_split_expiration():
    secret = {"vaultProperties": {"enableRbacAuthorization": False}, "properties": {"attributes": {"enabled": True, "exp": None}}}
    assert run(cid("keyvault_rbac_secret_expiration_set"), secret) == "NOT_APPLICABLE"
    assert run(cid("keyvault_non_rbac_secret_expiration_set"), secret) == "FAIL"
    assert run(cid("keyvault_non_rbac_secret_expiration_set"), {"properties": {"attributes": {"enabled": True, "exp": None}}}) == "UNKNOWN"
    disabled = {"properties": {"attributes": {"enabled": False, "exp": None}}}
    assert run(cid("keyvault_key_expiration_set"), disabled) == "NOT_APPLICABLE"


def test_key_rotation_variants():
    expiry_rotate = CASES[cid("keyvault_key_automatic_rotation_after_create")]["fail"]
    assert run(cid("keyvault_key_rotation_policy"), expiry_rotate) == "PASS"
    assert run(cid("keyvault_key_rotation_policy"), {"properties": {"rotationPolicy": None}}) == "FAIL"


def test_vault_private_endpoint_rules():
    assert run(cid("keyvault_private_endpoint_only_access"), {"properties": {"privateEndpointConnections": []}}) == "NOT_APPLICABLE"
    assert run(cid("keyvault_vnet_service_endpoint"), {"properties": {"networkAcls": {"defaultAction": "Deny"}}}) == "FAIL"


# --- AKS / Kusto -------------------------------------------------------------------------------------------

def test_aks_edges():
    assert run(cid("aks_azure_policy_addon"), {"properties": {"addonProfiles": {"azurePolicy": {"enabled": True}}}}) == "PASS"
    assert run(cid("aks_azure_policy_addon"), {"properties": {"addonProfiles": {"azurepolicy": {"enabled": True}, "azurePolicy": {"enabled": False}}}}) == "UNKNOWN"
    # The retired alias resolves to the exposure survivor, which passes a private API server.
    assert evaluate_check(cid("aks_authorized_ip_ranges"), {"properties": {"apiServerAccessProfile": {"enablePrivateCluster": True}}})[0] == "PASS"
    assert run(cid("aks_max_pods_at_least_50"), {"properties": {"agentPoolProfiles": []}}) == "UNKNOWN"
    assert run(cid("aks_network_policy_configured"), {"properties": {"networkProfile": {"networkPolicy": "none"}}}) == "FAIL"
    assert run(cid("aks_secret_store_rotation"), {"properties": {"addonProfiles": {}}}) == "FAIL"


@pytest.mark.parametrize("version,expected", [("1.10.9", "FAIL"), ("1.11.8", "FAIL"), ("1.11.9", "PASS"), ("1.12.7", "PASS"),
                                              ("1.13.4", "FAIL"), ("1.29.12", "PASS"), ("1.13", "UNKNOWN"), ("latest", "UNKNOWN")])
def test_aks_version(version, expected):
    assert run(cid("aks_version_not_cve_2019_9946"), {"properties": {"kubernetesVersion": version}}) == expected


def test_kusto_cmk_requires_name_and_uri():
    assert run(cid("kusto_cmk"), {"properties": {}}) == "FAIL"
    assert run(cid("kusto_cmk"), {"properties": {"keyVaultProperties": {"keyName": "k"}}}) == "FAIL"
    assert run(cid("kusto_cmk"), {"properties": {"keyVaultProperties": {"keyName": 4, "keyVaultUri": "u"}}}) == "UNKNOWN"
