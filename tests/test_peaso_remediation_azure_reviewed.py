"""Source-bound Azure remediation shard checks."""

import json
from pathlib import Path

from peaso.checks import CHECKS
from peaso.checks.claude_azure_network import LOOSE_ALERTS, STRICT_ALERTS
from peaso.remediation import template
from tests.reviewed_guidance_presentation import assert_approved_presentation


PATH = Path(__file__).resolve().parents[1] / "peaso/rulepacks/remediation_azure_reviewed.json"


def reviewed():
    return json.loads(PATH.read_text())




def test_entra_authorization_policy_guidance_uses_exact_tenant_fields():
    entries = reviewed()
    invites = entries["azure.claude.entra_guest_invites_admins_only"]
    assert invites["field_binding"]["path"] == "authorizationPolicy.allowInvitesFrom"
    assert "adminsAndGuestInviters" in " ".join(invites["steps"])
    assert "allowInvitesFrom" in invites["cli"][1]["code"]
    guest = entries["azure.claude.entra_guest_access_restricted"]
    assert guest["field_binding"]["path"] == "authorizationPolicy.guestUserRoleId"
    assert "2af84b1e-32c8-42b7-82bc-daa82404023b" in guest["cli"][1]["code"]


def test_entra_admin_portal_and_management_api_policies_are_distinct():
    entries = reviewed()
    for suffix, app in (("admin_portals", "MicrosoftAdminPortals"),
                        ("management_api", "797f4846-ba00-4fd7-ba43-dac1f8f63013")):
        entry = entries[f"azure.claude.entra_ca_mfa_{suffix}"]
        assert app in entry["field_binding"]["path"]
        assert app in " ".join(entry["steps"])
        assert "report-only" in " ".join(entry["steps"])
        assert "exclusions" in " ".join(entry["caveats"])
        assert "does not establish tenant-wide MFA coverage" in " ".join(entry["caveats"])
        assert "@<REVIEWED_CA_" in entry["cli"][1]["code"]


def test_named_location_and_group_creation_guidance_keeps_tenant_scope():
    entries = reviewed()
    aggregate = entries["azure.claude.entra_trusted_named_location_exists"]
    assert "ipRanges[] nonempty" in aggregate["field_binding"]["path"]
    assert "country location does not satisfy" in " ".join(aggregate["steps"])
    location = entries["azure.claude.entra_named_location_trusted"]
    assert "@odata.type" in " ".join(location["steps"])
    assert "preserve existing IP ranges" in " ".join(location["steps"])
    groups = entries["azure.claude.entra_m365_group_creation_restricted"]
    assert "Group.Unified" in groups["field_binding"]["path"]
    assert "templateId" in " ".join(groups["caveats"])
    assert any("groupSettings/<GROUP_SETTING_ID>" in c["code"] for c in groups["cli"])


def test_nsg_web_and_outbound_guidance_tracks_priority_and_default_rules():
    entries = reviewed()
    for suffix, ports in (("nsg_internet_http", "TCP 80"),
                          ("nsg_internet_http_https", "TCP 80 or 443")):
        entry = entries[f"azure.claude.{suffix}"]
        assert ports in entry["field_binding"]["path"]
        assert "exposed_rules" in entry["field_binding"]["path"]
        assert "higher-priority Deny" in " ".join(entry["steps"])
        assert "public web service" in " ".join(entry["caveats"])
    outbound = entries["azure.claude.nsg_outbound_restricted"]
    assert "Outbound" in outbound["field_binding"]["path"]
    assert "65001" in " ".join(outbound["steps"])
    assert "default AllowInternetOutBound" in " ".join(outbound["caveats"])
    assert "--direction Outbound --access Deny" in outbound["cli"][1]["code"]


def test_activity_alerts_keep_strict_and_loose_evaluator_contracts_distinct():
    entries = reviewed()
    for slug, _what, category, operations, resource_type in STRICT_ALERTS:
        entry = entries[f"azure.claude.{slug}"]
        binding = entry["field_binding"]
        assert binding["target"] == "scope"
        assert "location=Global" in binding["path"]
        assert f"category={category}" in binding["path"]
        assert (f"operationName={operations[0]}" if operations
                else f"resourceType={resource_type}") in binding["path"]
        assert "--method put" in entry["cli"][1]["code"]
        assert "action group" in " ".join(entry["steps"])
    for slug, _what, operations, _severity in LOOSE_ALERTS:
        entry = entries[f"azure.claude.{slug}"]
        binding = entry["field_binding"]
        assert binding["target"] == "scope"
        assert operations[0] in binding["path"]
        assert "does not bind location, category or scope" in binding["path"]
        assert "does not verify category, scope" in " ".join(entry["caveats"])


def test_subscription_diagnostic_checks_separate_existence_from_coverage():
    entries = reviewed()
    exists = entries["azure.claude.subscription_diagnostic_setting_exists"]
    assert exists["field_binding"]["target"] == "scope"
    assert "list is empty" in " ".join(exists["steps"])
    assert "could pass without exporting" in " ".join(exists["caveats"])
    resource = entries["azure.claude.subscription_diagnostic_setting_categories"]
    assert resource["field_binding"]["target"] == "resource"
    assert "missing_categories" in resource["field_binding"]["observed_fail_evidence"]
    aggregate = entries["azure.claude.subscription_diagnostic_setting_any_categories"]
    assert aggregate["field_binding"]["target"] == "scope"
    assert "spread across different settings do not pass" in " ".join(aggregate["steps"])


def test_azure_iam_guidance_uses_exact_assignment_and_definition_ids():
    entries = reviewed()
    uaa = entries["azure.claude.iam_no_user_access_administrator_assignment"]
    assert "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" in uaa["field_binding"]["path"]
    assert "--ids <REVIEWED_ROLE_ASSIGNMENT_ID>" in uaa["cli"][1]["code"]
    assert "never delete by role" in " ".join(uaa["caveats"])
    contributor = entries["azure.claude.iam_user_no_contributor_assignment"]
    assert "principalType=User" in contributor["field_binding"]["path"]
    assert "b24988ac-6180-42a0-ab88-20f7382dd24c" in contributor["field_binding"]["path"]
    definition = entries["azure.claude.iam_custom_role_no_wildcard_actions"]
    assert "permissions[].actions" in definition["field_binding"]["path"]
    assert "DataActions" in " ".join(definition["caveats"])
    assert "--role-definition '@<REVIEWED_CUSTOM_ROLE_JSON>'" in definition["cli"][1]["code"]


def test_global_administrator_count_preserves_emergency_access():
    entry = reviewed()["azure.claude.entra_global_admin_fewer_than_five"]
    assert "directoryScopeId=/" in entry["field_binding"]["path"]
    assert "distinct principalId count >=5" in entry["field_binding"]["path"]
    assert "PIM eligibility and group expansion" in " ".join(entry["steps"])
    assert "emergency accounts" in " ".join(entry["steps"])
    assert "<REVIEWED_ASSIGNMENT_ID>" in entry["cli"][1]["code"]


def test_application_credential_rotation_keeps_generated_secrets_out_of_cli():
    entry = reviewed()["azure.claude.entra_app_credential_not_expiring"]
    assert "passwordCredentials[] and keyCredentials[]" in entry["field_binding"]["path"]
    assert "keyId" in entry["field_binding"]["path"]
    assert "secretText" in " ".join(entry["steps"])
    assert all("addPassword" not in command["code"] for command in entry["cli"])
    assert all("secretText" not in command["code"] for command in entry["cli"])


def test_recent_user_sign_in_guidance_uses_successful_activity_only():
    entry = reviewed()["azure.claude.entra_user_recent_sign_in"]
    binding = entry["field_binding"]
    assert binding["kind"] == "directory_user"
    assert binding["target"] == "resource"
    assert "signInActivity.lastSuccessfulSignInDateTime" in binding["path"]
    assert "context.created_at" in binding["path"]
    assert "days_since_successful_sign_in" in binding["observed_fail_evidence"]
    text = " ".join(entry["steps"] + entry["caveats"])
    assert "2023-12-01" in text and "not backfilled" in text
    assert "attempt" in text and "UNKNOWN" in text
    assert "do not disable" in text
    assert len(entry["cli"]) == 1
    assert "--method get" in entry["cli"][0]["code"]
    assert "--method patch" not in entry["cli"][0]["code"]


def test_mysql_postgresql_flexible_server_guidance_tracks_native_fields_and_supported_changes():
    entries = reviewed()
    parameters = {
        "mysql_flexible_audit_log_enabled": "audit_log_enabled",
        "mysql_flexible_secure_transport": "require_secure_transport",
        "mysql_flexible_audit_log_connection": "audit_log_events",
        "mysql_flexible_min_tls_12": "tls_version",
        "postgresql_flexible_secure_transport": "require_secure_transport",
        "postgresql_flexible_connection_throttling": "connection_throttle.enable",
        "postgresql_flexible_log_checkpoints": "log_checkpoints",
        "postgresql_flexible_log_connections": "log_connections",
        "postgresql_flexible_log_disconnections": "log_disconnections",
        "postgresql_flexible_log_retention_over_3_days": "logfiles.retention_days",
    }
    for slug, parameter in parameters.items():
        entry = entries[f"azure.claude.{slug}"]
        assert parameter in entry["field_binding"]["path"]
        assert entry["field_binding"]["target"] == "resource"
        assert all("<RESOURCE_GROUP>" in command["code"] for command in entry["cli"])
        assert any("parameter show" in command["code"] for command in entry["cli"])
        assert all(reference["url"].startswith("https://learn.microsoft.com/") for reference in entry["references"])
    assert len(entries["azure.claude.mysql_flexible_audit_log_connection"]["cli"]) == 1
    assert "CONNECTION_V2" in " ".join(entries["azure.claude.mysql_flexible_audit_log_connection"]["caveats"])
    assert "NOT_APPLICABLE" in " ".join(entries["azure.claude.postgresql_flexible_connection_throttling"]["caveats"])
    assert "restart" in " ".join(entries["azure.claude.mysql_flexible_min_tls_12"]["steps"])


def test_flexible_server_ha_firewall_and_entra_guidance_keep_applicability():
    entries = reviewed()
    mysql_ha = entries["azure.claude.mysql_flexible_high_availability"]
    pg_ha = entries["azure.claude.postgresql_flexible_high_availability"]
    assert "Burstable" in mysql_ha["field_binding"]["path"]
    assert "creation-time only" in " ".join(mysql_ha["caveats"])
    assert all("update" not in command["code"] for command in mysql_ha["cli"])
    assert "--high-availability ZoneRedundant" in pg_ha["cli"][1]["code"]
    for slug, join in (("postgresql_flexible_no_azure_services_rule", "AND"),
                       ("postgresql_flexible_no_zero_address_rule", "OR")):
        entry = entries[f"azure.claude.{slug}"]
        assert join in entry["field_binding"]["path"]
        assert "publicNetworkAccess=Disabled" in entry["field_binding"]["path"]
        assert "can break database connections" in " ".join(entry["caveats"])
        assert all("delete" not in command["code"] for command in entry["cli"])
    entra = entries["azure.claude.postgresql_flexible_entra_authentication"]
    assert "authConfig.activeDirectoryAuth=Enabled" in entra["field_binding"]["path"]
    assert "administrators[] nonempty" in entra["field_binding"]["path"]
    assert "--microsoft-entra-auth Enabled" in entra["cli"][2]["code"]
    assert "--object-id <REVIEWED_ADMIN_OBJECT_ID>" in entra["cli"][3]["code"]


def test_app_service_api_and_web_guidance_uses_kind_selection_and_exact_settings():
    entries = reviewed()
    api = {
        "api_app_client_certificates": "clientCertEnabled",
        "api_app_cors_no_wildcard": "cors.allowedOrigins",
        "api_app_ftps_required": "ftpsState",
        "api_app_min_tls_12": "minTlsVersion",
        "api_app_remote_debugging_disabled": "remoteDebuggingEnabled",
        "api_app_https_only": "httpsOnly",
        "api_app_managed_identity": "identity.type",
    }
    web = {
        "web_app_remote_debugging_disabled": "remoteDebuggingEnabled",
        "web_app_client_certificates": "clientCertEnabled",
        "web_app_incoming_client_cert": "clientCertEnabled",
        "web_app_ftps_required": "ftpsState",
        "web_app_managed_identity": "identity.type",
        "web_app_register_with_entra": "identity.type",
        "web_app_authentication_enabled": "authSettingsV2.properties",
        "web_app_always_on": "alwaysOn",
    }
    for slug, field in {**api, **web}.items():
        entry = entries[f"azure.claude2.{slug}"]
        binding = entry["field_binding"]
        assert binding["evaluator_family"] == "peaso.checks.claude2_azure_app"
        assert binding["kind"] == "app_service" and binding["target"] == "resource"
        assert field in binding["path"]
        assert entry["steps"] and entry["references"]
    assert "exactly api" in entries["azure.claude2.api_app_remote_debugging_disabled"]["field_binding"]["path"]
    assert "not exactly api" in entries["azure.claude2.web_app_remote_debugging_disabled"]["field_binding"]["path"]
    assert "kind has no functionapp element" in entries["azure.claude2.web_app_incoming_client_cert"]["field_binding"]["path"]
    assert "clientCertMode" in " ".join(entries["azure.claude2.web_app_client_certificates"]["caveats"])
    assert "not API authentication" in " ".join(entries["azure.claude2.api_app_cors_no_wildcard"]["caveats"])
    assert "clientCertEnabled" in entries["azure.claude2.api_app_client_certificates"]["field_binding"]["path"]
    assert "--min-tls-version 1.2" in entries["azure.claude2.api_app_min_tls_12"]["cli"][1]["code"]
    assert "--https-only true" in entries["azure.claude2.api_app_https_only"]["cli"][1]["code"]
    assert "anonymous requests" in " ".join(entries["azure.claude2.web_app_authentication_enabled"]["caveats"])
    assert "missing authSettingsV2 => UNKNOWN" in entries["azure.claude2.web_app_authentication_enabled"]["field_binding"]["path"]
    assert "root GET" in " ".join(entries["azure.claude2.web_app_always_on"]["caveats"])


def test_azure_reviewed_shard_rejects_approved_central_collision(monkeypatch, tmp_path):
    import peaso.remediation as remediation

    check_id = "azure.port.storage_account_soft_delete_enabled"
    candidate = dict(remediation.template(check_id), summary="Conflicting approved edit")
    shard = tmp_path / "azure-reviewed.json"
    shard.write_text(json.dumps({check_id: candidate}))
    monkeypatch.setattr(remediation, "AZURE_REVIEWED", shard)
    remediation.rules.cache_clear()
    try:
        try:
            remediation.rules()
        except ValueError as exc:
            assert "conflicts with approved IDs" in str(exc)
        else:
            assert False, "approved Azure shard collision was accepted"
    finally:
        remediation.rules.cache_clear()


def test_app_service_health_diagnostic_and_function_predicates_keep_their_exact_fields():
    entries = reviewed()
    checks = {
        'web_app_health_check': ('healthCheckPath', 'health_check_path'),
        'web_app_diagnostic_http_log_category': ('AppServiceHTTPLogs', 'settings'),
        'function_app_client_certificates': ('clientCertEnabled', 'configured=false'),
        'function_app_ftps_required': ('ftpsState=AllAllowed', 'ftps_state'),
        'function_app_linux_http2': ('http20Enabled=false', 'http20_enabled'),
        'function_app_managed_identity': ('identity.type', 'identity_type'),
        'function_app_authentication_enabled': ('authSettingsV2.properties', 'authentication_enabled'),
        'function_app_restrict_public_access': ('ipAddress=Any and action=Allow', 'allow_any_rules'),
        'prowler_app_client_certificates_required': ('clientCertMode=Required', 'client_cert_mode'),
        'prowler_app_http_logs': ('categoryGroup=allLogs', 'settings'),
        'prowler_app_authentication': ('authSettingsV2.properties', 'authentication_enabled'),
        'prowler_app_identity': ('identity.type', 'identity_type'),
        'prowler_function_identity': ('identity.type', 'identity_type'),
        'prowler_function_ftp_ftps_disabled': ('ftpsState != Disabled', 'ftps_state'),
        'prowler_function_not_public': ('publicNetworkAccess=Enabled', 'public_network_access'),
    }
    for slug, (field, evidence) in checks.items():
        entry = entries[f'azure.claude2.{slug}']
        assert field in entry['field_binding']['path']
        assert evidence in entry['field_binding']['observed_fail_evidence']
        assert entry['field_binding']['target'] == 'resource'
        assert entry['steps'] and entry['references']
    assert 'allLogs group alone does not satisfy' in ' '.join(entries['azure.claude2.web_app_diagnostic_http_log_category']['steps'])
    assert 'enabled allLogs categoryGroup' in ' '.join(entries['azure.claude2.prowler_app_http_logs']['steps'])
    assert 'FtpsOnly passes' in ' '.join(entries['azure.claude2.function_app_ftps_required']['caveats'])
    assert 'FtpsOnly' in ' '.join(entries['azure.claude2.prowler_function_ftp_ftps_disabled']['caveats'])
    assert 'missing rules may still leave' in ' '.join(entries['azure.claude2.function_app_restrict_public_access']['caveats'])
    assert 'private endpoints are unsupported' in ' '.join(entries['azure.claude2.prowler_function_not_public']['caveats'])
    assert 'empty string passes' in ' '.join(entries['azure.claude2.web_app_health_check']['caveats'])


def test_network_watcher_and_flow_log_guidance_tracks_current_resources():
    entries = reviewed()
    watcher = entries["azure.claude.network_watcher_in_vnet_region"]
    assert watcher["field_binding"]["kind"] == "vnet"
    assert "scoped network_watcher[].location" in watcher["field_binding"]["path"]
    assert "--locations <VNET_REGION>" in watcher["cli"][1]["code"]
    enabled = entries["azure.claude.flow_log_enabled"]
    assert enabled["field_binding"]["path"] == "properties.enabled=false"
    assert "--enabled true" in enabled["cli"][1]["code"]
    assert "New NSG flow logs are no longer supported" in " ".join(enabled["caveats"])
    analytics = entries["azure.claude.flow_log_traffic_analytics"]
    assert "trafficAnalyticsInterval" in analytics["field_binding"]["path"]
    assert "--traffic-analytics true" in analytics["cli"][1]["code"]
    retention = entries["azure.claude.network_watcher_flow_logs_retention_90"]
    assert retention["field_binding"]["kind"] == "network_watcher"
    assert "0<properties.retentionPolicy.days<90" in retention["field_binding"]["path"]
    assert "--retention 90" in retention["cli"][1]["code"]
    assert "--location <WATCHER_REGION>" in retention["cli"][0]["code"]
    aggregate = entries["azure.claude.network_watcher_flow_logs_traffic_analytics"]
    assert aggregate["field_binding"]["kind"] == "network_watcher"
    assert "flowLogs[] nonempty" in aggregate["field_binding"]["path"]
    assert "--vnet <REVIEWED_VNET_ID>" in aggregate["cli"][1]["code"]
    assert "New NSG flow logs are unsupported" in " ".join(aggregate["caveats"])


def test_recovery_vault_guidance_separates_identity_from_protection():
    entries = reviewed()
    identity = entries["azure.claude.recovery_vault_managed_identity"]
    assert identity["field_binding"]["path"].startswith("identity.type")
    assert "--system-assigned" in identity["cli"][1]["code"]
    assert "does not grant" in " ".join(identity["caveats"])
    items = entries["azure.claude.recovery_vault_has_protected_items"]
    assert items["field_binding"]["path"] == "backupProtectedItems[] empty"
    assert "<REVIEWED_VM_ARM_ID>" in items["cli"][1]["code"]
    assert "intentionally empty" in " ".join(items["steps"])
    assert "pageable" in " ".join(items["caveats"])
    assert "azure.claude.recovery_vault_private_endpoint_backup" not in entries
    assert "azure.claude.recovery_vault_backup_retention_30_days" not in entries


def test_vpn_gateway_entra_only_guidance_requires_client_migration():
    entry = reviewed()["azure.claude.vnet_gateway_entra_only"]
    assert "vpnAuthenticationTypes nonempty and not exactly [AAD]" in entry["field_binding"]["path"]
    assert "Certificate or RADIUS" in " ".join(entry["steps"])
    assert "OpenVPN" in " ".join(entry["caveats"])
    assert "can disconnect" in " ".join(entry["caveats"])


def test_sql_firewall_rules_keep_azure_services_and_full_range_distinct():
    entries = reviewed()
    both = entries["azure.claude.sql_firewall_no_internet_or_azure_services"]
    full = entries["azure.claude.sql_firewall_no_full_range"]
    assert "{0.0.0.0,255.255.255.255}" in both["field_binding"]["path"]
    assert "endIpAddress=255.255.255.255" in full["field_binding"]["path"]
    assert "Azure-services exception" in " ".join(both["steps"])
    assert "outside this exact full-range predicate" in " ".join(full["steps"])
    for entry in (both, full):
        assert "--name <FLAGGED_RULE_NAME>" in entry["cli"][1]["code"]
        assert "--start-ip-address <APPROVED_START_IPV4>" in entry["cli"][1]["code"]
        assert "can break application connectivity" in " ".join(entry["caveats"])


def test_blob_container_public_acl_guidance_uses_arm_resource_without_keys():
    entry = reviewed()["azure.claude.storage_container_no_public_access"]
    assert "properties.publicAccess in {Blob,Container}" in entry["field_binding"]["path"]
    assert "--ids <EXACT_CONTAINER_ARM_ID> --public-access off" in entry["cli"][1]["code"]
    assert all("account-key" not in command["code"] for command in entry["cli"])
    assert "account-level allowBlobPublicAccess" in " ".join(entry["caveats"])


def test_security_contact_guidance_preserves_full_resource_and_threshold():
    entries = reviewed()
    email = entries["azure.claude.defender_contact_has_email"]
    assert "properties.emails" in email["field_binding"]["path"]
    assert "semicolon" in email["field_binding"]["path"]
    attack = entries["azure.claude.defender_attack_path_notifications"]
    assert "AttackPath.minimalRiskLevel" in attack["field_binding"]["path"]
    assert "minimalRiskLevel=High" in " ".join(attack["steps"])
    for entry in (email, attack):
        assert "--method put" in entry["cli"][1]["code"]
        assert "@<REVIEWED_SECURITY_CONTACT_JSON>" in entry["cli"][1]["code"]
        assert "A PUT replaces the full contact resource" in " ".join(entry["caveats"])


def test_servicebus_guidance_keeps_sas_migration_and_vnet_rule_scope():
    entries = reviewed()
    auth = entries["azure.claude.servicebus_namespace_local_auth_disabled"]
    assert auth["field_binding"]["path"] == "properties.status=Active and properties.disableLocalAuth=false"
    assert "--disable-local-auth true" in auth["cli"][1]["code"]
    assert "SAS" in " ".join(auth["caveats"])
    vnet = entries["azure.claude.servicebus_premium_namespace_vnet_rules"]
    assert "sku.tier=Premium" in vnet["field_binding"]["path"]
    assert "any subnet.id missing/blank" in vnet["field_binding"]["path"]
    assert "id=<REVIEWED_SUBNET_ARM_ID>" in vnet["cli"][1]["code"]
    assert "does not make the namespace private" in " ".join(vnet["caveats"])
    assert "azure.claude.servicebus_namespace_network_restricted" not in entries
    private = entries["azure.claude.servicebus_namespace_private_link"]
    assert "sku.tier=Premium" in private["field_binding"]["path"]
    assert "null collection is manual" in private["field_binding"]["path"]
    assert "--group-id namespace" in private["cli"][1]["code"]
    assert "--id <PENDING_NAMESPACE_CONNECTION_ARM_ID>" in private["cli"][2]["code"]
    assert "does not automatically disable" in " ".join(private["caveats"])


def test_sql_ltr_guidance_requires_nonzero_declared_interval_without_reset():
    entry = reviewed()["azure.claude.sql_database_long_term_retention"]
    path = entry["field_binding"]["path"]
    assert "weeklyRetention=PT0S" in path
    assert "monthlyRetention=PT0S" in path
    assert "yearlyRetention=PT0S" in path
    assert "--weekly-retention P4W" in entry["cli"][1]["code"]
    assert "Do not reset other intervals" in " ".join(entry["caveats"])


def test_sql_entra_admin_guidance_uses_reviewed_principal():
    entry = reviewed()["azure.claude.sql_server_entra_admin"]
    assert "administratorType lacks ActiveDirectory" in entry["field_binding"]["path"]
    assert "--object-id <REVIEWED_ENTRA_OBJECT_ID>" in entry["cli"][1]["code"]
    assert "grants SQL administrative authority" in " ".join(entry["caveats"])


def test_sql_vnet_rule_guidance_requires_real_service_endpoint():
    entry = reviewed()["azure.claude.sql_server_vnet_rules"]
    assert entry["field_binding"]["path"] == "virtualNetworkRules[].properties.virtualNetworkSubnetId list empty"
    assert "Microsoft.Sql service endpoint" in " ".join(entry["steps"])
    assert "--subnet <REVIEWED_SUBNET_ARM_ID> --ignore-missing-endpoint false" in entry["cli"][1]["code"]
    assert "still uses the SQL public service endpoint" in " ".join(entry["caveats"])


def test_sql_private_link_guidance_checks_approved_connection_and_client_dns():
    entry = reviewed()["azure.claude.sql_server_private_link"]
    assert "privateEndpointConnections[]" in entry["field_binding"]["path"]
    assert "lacks Approved" in entry["field_binding"]["path"]
    assert "--group-id sqlServer" in entry["cli"][1]["code"]
    assert "--id <PENDING_SQL_CONNECTION_ARM_ID>" in entry["cli"][2]["code"]
    assert "privatelink.database.windows.net" in " ".join(entry["steps"])
    assert "does not block public routing" in " ".join(entry["caveats"])


def test_storage_key_policy_guidance_separates_reminder_from_rotation():
    entries = reviewed()
    for suffix, expected in (("storage_key_expiration_policy_90", "!= 90"),
                             ("storage_key_expiration_policy_max_90", ">90")):
        entry = entries[f"azure.claude.{suffix}"]
        assert expected in entry["field_binding"]["path"]
        assert "--key-exp-days 90" in entry["cli"][1]["code"]
        assert "keyCreationTime" in entry["cli"][0]["code"]
        assert "not automatic rotation" in " ".join(entry["caveats"])
        assert "SAS tokens" in " ".join(entry["caveats"])


def test_storage_vnet_guidance_stages_rules_before_default_deny():
    entry = reviewed()["azure.claude.storage_vnet_service_endpoint_rules"]
    assert "defaultAction != Deny" in entry["field_binding"]["path"]
    assert "virtualNetworkRules[] empty" in entry["field_binding"]["path"]
    assert "--subnet <REVIEWED_SUBNET_ARM_ID>" in entry["cli"][1]["code"]
    assert "--default-action Deny" in entry["cli"][2]["code"]
    assert "can immediately block applications" in " ".join(entry["caveats"])


def test_base_storage_transport_guidance_uses_native_account_fields():
    entries = reviewed()
    https = entries["azure.storage.https_only"]
    assert https["field_binding"]["evaluator_family"] == "peaso.checks"
    assert https["field_binding"]["path"] == "properties.supportsHttpsTrafficOnly=false"
    assert "--https-only true" in https["cli"][1]["code"]
    assert "SMB" in " ".join(https["caveats"])
    tls = entries["azure.storage.minimum_tls"]
    assert tls["field_binding"]["evaluator_family"] == "peaso.checks"
    assert "TLS1_0,TLS1_1" in tls["field_binding"]["path"]
    assert "--min-tls-version TLS1_2" in tls["cli"][1]["code"]
    assert "Clients unable to negotiate TLS 1.2" in " ".join(tls["caveats"])


def test_entra_consent_guidance_preserves_assignments_and_exact_thresholds():
    entries = reviewed()
    disabled = entries["azure.claude.entra_user_consent_disabled"]
    legacy = entries["azure.claude.entra_user_consent_not_legacy"]
    assert "nonempty casefolded managePermissionGrantsForSelf" in disabled["field_binding"]["path"]
    assert "malformed self-grant is UNKNOWN" in disabled["field_binding"]["path"]
    assert "exact casefolded managePermissionGrantsForSelf.microsoft-user-default-legacy" in legacy["field_binding"]["path"]
    assert "custom-only self-grant is UNKNOWN" in legacy["field_binding"]["path"]
    assert "managePermissionGrantsForSelf.microsoft-user-default-low" in " ".join(legacy["steps"])
    for entry in (disabled, legacy):
        assert "permissionGrantPoliciesAssigned" in entry["cli"][0]["code"]
        assert "@<REVIEWED_CONSENT_POLICY_PATCH_JSON>" in entry["cli"][1]["code"]
        assert "replaces that complete assignment array" in " ".join(entry["caveats"])
        assert "existing app consent grants remain" in " ".join(entry["caveats"])


def test_base_azure_iam_and_nsg_guidance_uses_declared_predicates():
    entries = reviewed()
    role = entries["azure.iam.no_full_custom_role"]
    assert role["field_binding"]["evaluator_family"] == "peaso.checks"
    assert "actions or dataActions contains literal *" in role["field_binding"]["path"]
    assert "otherwise MANUAL" in role["field_binding"]["path"]
    assert "any such exclusion makes the whole evaluation MANUAL" in " ".join(role["steps"])
    assert "--role-definition '@<REVIEWED_CUSTOM_ROLE_JSON>'" in role["cli"][1]["code"]
    assert "notActions or notDataActions as explicit denies" in " ".join(role["caveats"])
    ingress = entries["azure.network.restrict_internet_ingress"]
    assert ingress["field_binding"]["evaluator_family"] == "peaso.checks"
    assert "sourceAddressPrefix/sourceAddressPrefixes" in ingress["field_binding"]["path"]
    assert "broad_ingress_rules" == ingress["field_binding"]["observed_fail_evidence"]
    assert "--name <FLAGGED_RULE_NAME> --source-address-prefixes <APPROVED_CLIENT_CIDR>" in ingress["cli"][1]["code"]
    assert "does not calculate effective NSG priority" in " ".join(ingress["caveats"])


def test_base_owner_assignment_guidance_removes_exact_grant_after_replacement():
    entry = reviewed()["azure.iam.review_owner_assignment"]
    assert entry["field_binding"]["evaluator_family"] == "peaso.checks"
    assert "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" in entry["field_binding"]["path"]
    assert "role_assignment" == entry["field_binding"]["kind"]
    assert "--ids <EXACT_OWNER_ASSIGNMENT_ID>" in entry["cli"][1]["code"]
    assert "test the replacement before revoking standing Owner" in " ".join(entry["steps"])
    assert "break-glass" in " ".join(entry["caveats"])


def test_storage_key_rotation_guidance_uses_age_and_hides_secret_output():
    entry = reviewed()["azure.claude.storage_access_keys_rotated_90"]
    assert "keyCreationTime{} nonempty and any key age >90 days" in entry["field_binding"]["path"]
    assert entry["field_binding"]["observed_fail_evidence"] == "key_age_days"
    assert "--query \"keyCreationTime\"" in entry["cli"][0]["code"]
    assert "--key <REVIEWED_PRIMARY_OR_SECONDARY> --output none" in entry["cli"][1]["code"]
    assert "Do not rotate both keys together" in " ".join(entry["caveats"])
    assert "account or service SAS tokens" in " ".join(entry["caveats"])


def test_storage_private_endpoint_presence_guidance_does_not_claim_approval():
    entry = reviewed()["azure.claude.storage_private_endpoint_present"]
    assert "privateEndpointConnections[] empty" in entry["field_binding"]["path"]
    assert "any status passes declaration predicate" in entry["field_binding"]["path"]
    assert "--group-id <REVIEWED_STORAGE_SUBRESOURCE>" in entry["cli"][1]["code"]
    assert "--id <PENDING_STORAGE_CONNECTION_ARM_ID>" in entry["cli"][2]["code"]
    assert "Blob and DFS endpoints are distinct" in " ".join(entry["caveats"])
    assert "Pending, Rejected or Disconnected" in " ".join(entry["caveats"])
    assert "marked Preview" in " ".join(entry["caveats"])


def test_storage_private_endpoint_all_approved_guidance_reviews_every_record():
    entry = reviewed()["azure.claude.storage_private_link_all_approved"]
    assert "empty OR any" in entry["field_binding"]["path"]
    assert "status != Approved" in entry["field_binding"]["path"]
    assert "every connection record" in " ".join(entry["caveats"])
    assert "Do not delete a record merely to satisfy the check" in " ".join(entry["caveats"])
    assert "--id <VERIFIED_PENDING_STORAGE_CONNECTION_ARM_ID>" in entry["cli"][1]["code"]
    assert "marked Preview" in " ".join(entry["caveats"])


def test_storage_service_soft_delete_guidance_preserves_distinct_policies():
    entries = reviewed()
    both = entries["azure.claude.storage_blob_and_container_soft_delete_7_365"]
    assert "deleteRetentionPolicy" in both["field_binding"]["path"]
    assert "containerDeleteRetentionPolicy" in both["field_binding"]["path"]
    assert "--enable-delete-retention true" in both["cli"][1]["code"]
    assert "--enable-container-delete-retention true" in both["cli"][2]["code"]
    assert "Preserve an already compliant period" in " ".join(both["steps"])
    blob = entries["azure.claude.storage_blob_soft_delete_enabled"]
    assert blob["field_binding"]["path"] == "type=blobServices and properties.deleteRetentionPolicy.enabled=false"
    assert "container soft deletion and an adequate retention period are separate controls" in " ".join(blob["caveats"])
    flag = entries["azure.claude.storage_file_share_soft_delete_enabled"]
    assert "even if the account has no shares" in " ".join(flag["steps"])
    period = entries["azure.claude.storage_file_share_soft_delete_1_365"]
    assert "shares[] nonempty" in period["field_binding"]["path"]
    assert "empty shares NOT_APPLICABLE" in period["field_binding"]["path"]
    assert "--delete-retention-days <REVIEWED_SHARE_RETENTION_DAYS_1_365>" in period["cli"][1]["code"]
    for entry in (flag, period):
        assert "Microsoft.FileShares resource provider does not currently support" in " ".join(entry["caveats"])


def test_storage_smb_guidance_binds_exact_configured_set_and_client_impact():
    entries = reviewed()
    for suffix, field, wanted, command in (
        ("storage_smb_channel_encryption_aes_256_gcm", "channelEncryption", "AES-256-GCM", "--channel-encryption AES-256-GCM"),
        ("storage_smb_version_3_1_1", "versions", "SMB3.1.1", "--versions SMB3.1.1"),
    ):
        entry = entries[f"azure.claude.{suffix}"]
        assert entry["review_status"] == "approved"
        assert f"properties.protocolSettings.smb.{field}" in entry["field_binding"]["path"]
        assert wanted in entry["field_binding"]["path"]
        assert entry["field_binding"]["observed_fail_evidence"] == "configured"
        assert command in entry["cli"][1]["code"]
        assert "client" in " ".join(entry["caveats"]).lower()
        assert "service default" in " ".join(entry["steps"])


def test_file_sync_private_endpoint_guidance_requires_working_paths_first():
    entry = reviewed()["azure.claude.storage_sync_private_link"]
    assert entry["review_status"] == "approved"
    assert "incomingTrafficPolicy=AllowAllTraffic OR no Approved" in entry["field_binding"]["path"]
    assert entry["field_binding"]["observed_fail_evidence"] == "incoming_traffic_policy, connection_states"
    assert "both the Storage Sync Service and its storage account" in " ".join(entry["steps"])
    assert "before changing public access" in " ".join(entry["steps"])
    assert "Set-AzStorageSyncService" in entry["cli"][1]["code"]
    assert entry["cli"][1]["shell"] == "powershell"
    assert "Azure CLI does not support" in " ".join(entry["caveats"])


def test_synapse_exfiltration_guidance_respects_creation_time_immutability():
    entry = reviewed()["azure.claude.synapse_workspace_exfiltration_protection"]
    assert entry["review_status"] == "approved"
    assert "managedVirtualNetworkSettings.preventDataExfiltration" in entry["field_binding"]["path"]
    assert entry["field_binding"]["observed_fail_evidence"] == "prevent_data_exfiltration"
    assert entry["cli"] == []
    assert "enabled at creation" in " ".join(entry["steps"])
    assert "cutover and rollback" in " ".join(entry["steps"])
    assert "cannot be changed after" in " ".join(entry["caveats"])


def test_synapse_cmk_guidance_requires_migration_and_key_continuity():
    entry = reviewed()["azure.claude.synapse_workspace_cmk"]
    assert entry["review_status"] == "approved"
    assert entry["field_binding"]["path"] == "properties.encryption.cmk.key.name absent or empty"
    assert entry["field_binding"]["observed_fail_evidence"] == "cmk_key_name"
    assert entry["cli"] == []
    assert "during creation" in " ".join(entry["steps"])
    assert "cannot be changed after workspace creation" in " ".join(entry["caveats"])
    assert "old key versions" in " ".join(entry["caveats"])


def test_synapse_inbound_private_link_does_not_claim_outbound_or_all_paths():
    entry = reviewed()["azure.claude.synapse_workspace_private_link"]
    assert entry["review_status"] == "approved"
    assert "privateEndpointConnections[]" in entry["field_binding"]["path"]
    assert entry["field_binding"]["observed_fail_evidence"] == "connection_states"
    assert "Sql, SqlOnDemand or Dev" in " ".join(entry["steps"])
    assert "not Synapse managed private endpoints" in " ".join(entry["caveats"])
    assert "public network access is disabled" in " ".join(entry["caveats"])


def test_encryption_scope_guidance_updates_only_flagged_scope_after_key_review():
    entry = reviewed()["azure.claude.storage_encryption_scope_cmk"]
    assert entry["review_status"] == "approved"
    assert "properties.source=Microsoft.Storage" in entry["field_binding"]["path"]
    assert entry["field_binding"]["observed_fail_evidence"] == "source"
    assert "--name <ENCRYPTION_SCOPE_NAME>" in entry["cli"][1]["code"]
    assert "--key-source Microsoft.KeyVault --key-uri <REVIEWED_KEY_URI>" in entry["cli"][1]["code"]
    assert "purge protection" in " ".join(entry["steps"])
    assert "data unavailable" in " ".join(entry["caveats"])
