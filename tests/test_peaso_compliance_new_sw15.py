"""Signed sw15 predicates, captured evidence and strict scope boundaries."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS
_before = {id(check) for check in CHECKS}
from peaso.checks import compliance_new_sw15 as sw
# These tests retain safe Check objects locally and remove only registrations
# introduced by our direct import. Existing central registrations are untouched.
CHECKS[:] = [check for check in CHECKS if id(check) in _before or check.id not in sw.IDS]

SUB = "/subscriptions/sub"
BASE = SUB + "/resourceGroups/rg/providers/"
NOW = "2026-10-12T00:00:00Z"
RECENT = 1791676800  # 2026-10-11 UTC
OLD = 1735689600  # 2025-01-01 UTC
PRINCIPAL = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"
VAULT = BASE + "Microsoft.KeyVault/vaults/vault"
SECRET_URI = "https://vault.vault.azure.net/secrets/password"
WORKSPACE = BASE + "Microsoft.OperationalInsights/workspaces/logs"
STORAGE = BASE + "Microsoft.Storage/storageAccounts/logs"
POLICY = {"status": "collected", "scope": SUB,
          "observationStart": "2026-10-11T00:00:00Z", "observationEnd": NOW,
          "approvedSinkIds": [WORKSPACE, STORAGE], "resolvedSinkIds": [WORKSPACE, STORAGE],
          "requireServiceBusDataPlaneAudit": True, "unusedForDays": 30,
          "maxDaysSinceRotation": 90, "approvedRotationDays": 90,
          "approvedVaultUris": ["https://vault.vault.azure.net"], "approvedResponders": [PRINCIPAL],
          "approvedBuildSourceIds": ["corporate"], "requiredRetentionDays": 365,
          "maxCalls": 2, "maxRenewalPeriodSeconds": 60,
          "stableCounterKeys": ["@(context.Subscription.Id)"], "allowAzureServices": False}


def resource(path, **fields):
    return {"id": BASE + path, "_provenance": {"representation": "full"}, **fields}


def evidence(row, **fields):
    return {"status": "collected", "resource_id": row["id"], "observed_at": NOW, **fields}


def child(row, suffix, **fields):
    return {"id": row["id"] + "/" + suffix, "parent_id": row["id"], **fields}


def embedded(row, field, rows):
    row[field] = rows
    row.setdefault("_coverage", {})[field] = {"status": "collected" if rows else "empty"}


def scoped(collections):
    index = {"context": {"provider": "azure", "scope": SUB, "created_at": NOW,
                         "metadata": {"sw15": copy.deepcopy(POLICY)}}, "collections": {}}
    for kind, rows in collections.items():
        index["collections"][kind] = [{"type": kind, "scope": SUB,
            "status": "collected" if rows else "empty", "items": rows}]
        index[kind] = [{"type": kind, "scope": SUB, "data": row} for row in rows]
    return index


def logging(row, category):
    embedded(row, "diagnosticSettings", [child(row, "providers/Microsoft.Insights/diagnosticSettings/logs",
        properties={"workspaceId": WORKSPACE, "storageAccountId": None, "logs": [{"category": category, "enabled": True}]})])
    row["diagnosticCategories"] = evidence(row, categories=[category, "RuntimeAuditLogs"])


def secret(kind):
    row = {"id": VAULT + "/secrets/password", "parent_id": VAULT, "data_plane_id": SECRET_URI,
           "properties": {"attributes": {"enabled": True}}}
    current = {"id": SECRET_URI + "/current", "attributes": {"created": RECENT, "enabled": True},
               "_provenance": {"endpoint": "secrets/get", "read_only": True, "request_uri": SECRET_URI}}
    row["currentVersion"] = current
    row["versions"] = [{"id": current["id"], "attributes": copy.deepcopy(current["attributes"])}]
    row["_coverage"] = {"versions": {"status": "collected"}, "currentVersion": {"status": "collected"}}
    vault = {"id": VAULT, "properties": {"vaultUri": "https://vault.vault.azure.net"}}
    return row, {kind: [row], "vault": [vault]}


def fixture(check_id, fail=False):
    number = sw.IDS.index(check_id)
    if number == 0:
        row = resource("Microsoft.DBforMySQL/flexibleServers/mysql")
        embedded(row, "configurations", [child(row, "configurations/audit_log_enabled", name="audit_log_enabled",
            properties={"value": "OFF" if fail else "ON"})])
        logging(row, "MySqlAuditLogs")
        return row, {"mysql_flexible_server": [row]}
    if number in (1, 2, 9):
        kind = "vault_secret" if number == 9 else "key_vault_secret"
        row, collections = secret(kind)
        if number == 1:
            row["auditHistory"] = evidence(row, window_start="2026-09-01T00:00:00Z", window_end=NOW,
                retention_start="2026-09-01T00:00:00Z", route_enabled=True, identifiers_comparable=True,
                success_values=["Success"], failure_values=["Failure"], events=[] if fail else [{"OperationName": "SecretGet", "ResultType": "Success",
                  "TimeGenerated": "2026-10-11T00:00:00Z", "SecretUri": SECRET_URI + "/old-version"}])
        elif number == 2 and fail:
            row["currentVersion"]["attributes"]["created"] = OLD
            row["versions"][0]["attributes"]["created"] = OLD
        elif number == 9:
            row["versions"].append({"id": SECRET_URI + "/old", "attributes": {"created": OLD, "enabled": False},
                "accessEvidence": {"status": "collected", "version_id": SECRET_URI + "/old", "observed_at": NOW,
                    "method": "authorized_read_test", "authorized": True, "outcome": "readable" if fail else "denied"}})
        return row, collections
    if number == 3:
        row = resource("Microsoft.Web/sites/app", kind="app,linux",
                       identity={"type": "None"} if fail else {"type": "SystemAssigned", "principalId": PRINCIPAL})
        return row, {"web_app": [row]}
    if number == 4:
        row = resource("Microsoft.Web/sites/app")
        row["workloadSecrets"] = evidence(row, inventory_complete=True, classification_complete=True,
            sites_slots_complete=True, locations_complete=True, secrets=[{"secret_id": "database-password",
                "required": True, "present": True, "storage": "literal_outside_key_vault" if fail else "key_vault",
                "secret_uri": SECRET_URI, "app_service_setting": True, "site_id": row["id"],
                "reference": "@Microsoft.KeyVault(SecretUri=" + SECRET_URI + ")", "resolution_status": "Resolved"}])
        return row, {"web_app": [row]}
    if number in (5, 6):
        row = {"id": SUB}
        profile = {"id": SUB + "/providers/Microsoft.Insights/logProfiles/default", "properties": {
            "categories": ["Write"] if fail and number == 5 else ["Write", "Delete", "Action"],
            "storageAccountId": STORAGE, "serviceBusRuleId": None, "retentionPolicy": {"enabled": True, "days": 30 if fail else 365}}}
        return row, {"subscription": [row], "monitor_log_profile": [profile]}
    if number == 7:
        row = resource("Microsoft.Storage/storageAccounts/logs/blobServices/default")
        cid = row["id"] + "/containers/audit"
        container = {"id": cid, "default_retention_measured": True, "inheritance_resolved": True,
            "object_overrides_resolved": True, "default_retention_active": True, "retention_days": 365,
            "protection": "Unlocked" if fail else "Locked", "all_objects_evaluated": True, "object_ids": ["audit-object"],
            "enforcement": [{"observed_at": NOW, "authorized": True, "premature": True,
                "operation": action, "object_id": "audit-object", "container_id": cid, "outcome": "denied"}
                for action in ("delete", "modify")]}
        row["immutabilityEvidence"] = evidence(row, container_inventory_complete=True, containers=[container])
        return row, {"storage_service": [row]}
    if number == 8:
        row = resource("Microsoft.Insights/actionGroups/responders")
        row["ackAuthorization"] = evidence(row, workflow_inventory_complete=True, workflows=[{
            "workflow_id": "incident", "coverage": {key: True for key in
               ("action_mapping", "scopes", "ancestors", "groups", "pim", "conditions", "external_systems")},
            "effective_grants": [{"principal_id": OTHER if fail else PRINCIPAL,
                "action": "Microsoft.AlertsManagement/alerts/changeState/action", "scope": SUB, "effective": True}]}])
        return row, {"action_group": [row]}
    if number == 10:
        row = resource("Microsoft.DevOpsInfrastructure/pools/build")
        row["externalAccess"] = evidence(row, endpoints_complete=True, hosts_complete=True, nics_complete=True,
            firewalls_complete=True, effective_routes_complete=True, endpoint_ids=["agent:443"], probes=[{
                "endpoint_id": "agent:443", "observed_at": NOW, "authorized_test": True,
                "external_source": True, "source_id": "internet", "outcome": "allowed" if fail else "denied"}])
        return row, {"build_agent": [row]}
    if number == 11:
        row = resource("Microsoft.Web/sites/function", kind="functionapp")
        oid = BASE + "Microsoft.ApiManagement/service/gateway/apis/function/operations/invoke"
        operation = {"operation_id": oid, "function_id": row["id"] + "/functions/invoke", "exposed": True,
            "expressions_resolved": True, "effective_policy_xml": '<policies><inbound><rate-limit-by-key calls="2" renewal-period="60" counter-key="@(context.Subscription.Id)" /></inbound></policies>',
            "probe": {"observed_at": NOW, "authorized": True, "operation_id": oid,
                "counter_key": "@(context.Subscription.Id)", "fresh_counter": True, "caller_id": "caller",
                "attempts": [{"sequence": n, "caller_id": "caller", "observed_at": NOW,
                    "status_code": 200 if n < 3 or fail else 429, "policy_denial": n == 3 and not fail} for n in (1, 2, 3)]}}
        row["invocationEvidence"] = evidence(row, operations_complete=True, function_mapping_complete=True,
            policy_tree_complete=True, inheritance_resolved=True, operations=[operation])
        return row, {"function_app": [row]}
    if number == 12:
        row = {"scope": SUB}
        server = resource("Microsoft.Sql/servers/sql", properties={"publicNetworkAccess": "Enabled"})
        embedded(server, "firewallRules", [child(server, "firewallRules/custom", classification="Custom",
            properties={"startIpAddress": "0.0.0.0" if fail else "10.0.0.1", "endIpAddress": "255.255.255.255" if fail else "10.0.0.1"})])
        return row, {"sql_server": [server], "mysql_flexible_server": [], "postgresql_flexible_server": []}
    if number == 13:
        row = {"scope": SUB}
        nic = resource("Microsoft.Network/networkInterfaces/nic", properties={"ipConfigurations": [{"properties": {}}]})
        if fail:
            nic["properties"]["ipConfigurations"][0]["properties"]["publicIPAddress"] = {"id": BASE + "Microsoft.Network/publicIPAddresses/public"}
        vm = resource("Microsoft.Compute/virtualMachines/vm", properties={"networkProfile": {"networkInterfaces": [{"id": nic["id"]}]}})
        return row, {"vm": [vm], "nic": [nic], "vm_scale_set": []}
    row = resource("Microsoft.ServiceBus/namespaces/messages", sku={"name": "Standard"})
    logging(row, "OperationalLogs")
    if fail:
        row["diagnosticSettings"][0]["properties"]["logs"][0]["enabled"] = False
    return row, {"servicebus_namespace": [row]}


def evaluate(check_id, row, collections, policy=None):
    index = scoped(collections)
    if policy:
        index["context"]["metadata"]["sw15"].update(policy)
    return sw.CHECK_BY_ID[check_id].evaluate(row, index)


@pytest.mark.parametrize("check_id", sw.IDS)
def test_signed_pass_fail(check_id):
    row, collections = fixture(check_id)
    assert evaluate(check_id, row, collections)[0] == "PASS"
    row, collections = fixture(check_id, fail=True)
    assert evaluate(check_id, row, collections)[0] == "FAIL"


@pytest.mark.parametrize("check_id", sw.IDS)
def test_missing_incomplete_malformed_and_foreign_facts(check_id):
    row, collections = fixture(check_id)
    check = sw.CHECK_BY_ID[check_id]
    assert check.evaluate(row, {})[0] == "UNKNOWN"
    index = scoped(collections)
    index["collections"][check.dependencies[0]][0]["status"] = "partial"
    assert check.evaluate(row, index)[0] == "UNKNOWN"
    index = scoped(collections)
    index["collections"][check.dependencies[0]][0]["scope"] = "/subscriptions/foreign"
    assert check.evaluate(row, index)[0] == "UNKNOWN"
    index = scoped(collections)
    index["context"]["provider"] = "aws"
    assert check.evaluate(row, index)[0] == "UNKNOWN"
    key = "scope" if check.target == "scope" else "id"
    bad = copy.deepcopy(row)
    bad[key] = {"malformed": True}
    assert evaluate(check_id, bad, collections)[0] == "UNKNOWN"
    missing = copy.deepcopy(row)
    missing.pop(key)
    assert evaluate(check_id, missing, collections)[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", sw.IDS)
def test_missing_and_malformed_required_detail(check_id):
    row, collections = fixture(check_id)
    number = sw.IDS.index(check_id)
    fields = {0: "configurations", 1: "auditHistory", 2: "currentVersion", 3: "kind", 4: "workloadSecrets",
              7: "immutabilityEvidence", 8: "ackAuthorization", 9: "versions", 10: "externalAccess",
              11: "invocationEvidence", 14: "diagnosticSettings"}
    target = row
    if number in (5, 6):
        target = collections["monitor_log_profile"][0]
        field = "properties"
    elif number == 12:
        target = collections["sql_server"][0]
        field = "firewallRules"
    elif number == 13:
        target = collections["nic"][0]
        field = "properties"
    else:
        field = fields[number]
    value = target.pop(field)
    assert evaluate(check_id, row, collections)[0] == "UNKNOWN"
    target[field] = "malformed" if not isinstance(value, str) else 123
    assert evaluate(check_id, row, collections)[0] == "UNKNOWN"


def test_not_applicable_for_disabled_current_and_base_secrets_empty_profiles_and_servers():
    row, collections = fixture(sw.IDS[1])
    row["properties"]["attributes"]["enabled"] = False
    assert evaluate(sw.IDS[1], row, collections)[0] == "NOT_APPLICABLE"
    row, collections = fixture(sw.IDS[2])
    row["currentVersion"]["attributes"]["enabled"] = False
    row["versions"][0]["attributes"]["enabled"] = False
    assert evaluate(sw.IDS[2], row, collections)[0] == "NOT_APPLICABLE"
    row, collections = fixture(sw.IDS[6])
    collections["monitor_log_profile"] = []
    assert evaluate(sw.IDS[6], row, collections)[0] == "NOT_APPLICABLE"
    assert evaluate(sw.IDS[5], row, collections)[0] == "FAIL"
    row, collections = fixture(sw.IDS[12])
    collections["sql_server"] = []
    assert evaluate(sw.IDS[12], row, collections)[0] == "NOT_APPLICABLE"
    for number, key, rows_key in [(4, "workloadSecrets", "secrets"), (7, "immutabilityEvidence", "containers"),
                                  (8, "ackAuthorization", "workflows"), (11, "invocationEvidence", "operations")]:
        row, collections = fixture(sw.IDS[number])
        row[key][rows_key] = []
        assert evaluate(sw.IDS[number], row, collections)[0] == "NOT_APPLICABLE"
    row, collections = fixture(sw.IDS[9])
    row["versions"] = row["versions"][:1]
    assert evaluate(sw.IDS[9], row, collections)[0] == "NOT_APPLICABLE"


def test_audit_use_matches_old_version_and_requires_entire_retention_window():
    row, collections = fixture(sw.IDS[1])
    assert evaluate(sw.IDS[1], row, collections)[0] == "PASS"
    row["auditHistory"]["retention_start"] = "2026-10-11T00:00:00Z"
    assert evaluate(sw.IDS[1], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[1])
    row["auditHistory"]["events"][0]["SecretUri"] = "https://other.vault.azure.net/secrets/password/version"
    assert evaluate(sw.IDS[1], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[1])
    row["auditHistory"]["events"][0]["ResultType"] = "Failure"
    assert evaluate(sw.IDS[1], row, collections)[0] == "FAIL"
    row["auditHistory"]["events"][0].pop("TimeGenerated")
    assert evaluate(sw.IDS[1], row, collections)[0] == "UNKNOWN"


def test_rotation_current_version_boundary_and_newer_disabled_version_does_not_refresh():
    row, collections = fixture(sw.IDS[2], fail=True)
    row["versions"].append({"id": SECRET_URI + "/disabled-newer", "attributes": {"created": RECENT, "enabled": False}})
    assert evaluate(sw.IDS[2], row, collections)[0] == "FAIL"
    boundary = int(sw._time(NOW).timestamp()) - 90 * 86400
    for entry in (row["currentVersion"], row["versions"][0]):
        entry["attributes"]["created"] = boundary
    assert evaluate(sw.IDS[2], row, collections)[0] == "PASS"
    row["currentVersion"]["id"] = SECRET_URI + "/unlisted"
    assert evaluate(sw.IDS[2], row, collections)[0] == "UNKNOWN"


def test_disabled_old_secret_configuration_alone_cannot_prove_effective_denial():
    row, collections = fixture(sw.IDS[9])
    row["versions"][1].pop("accessEvidence")
    assert evaluate(sw.IDS[9], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[9], fail=True)
    row["versions"].append({"id": SECRET_URI + "/unmeasured", "attributes": {"created": OLD, "enabled": False}})
    assert evaluate(sw.IDS[9], row, collections)[0] == "FAIL"


def test_managed_identity_user_attachment_without_inbound_auth_and_missing_full_get():
    row, collections = fixture(sw.IDS[3])
    row["identity"] = {"type": "UserAssigned", "userAssignedIdentities": {
        BASE + "Microsoft.ManagedIdentity/userAssignedIdentities/app": {}}}
    assert evaluate(sw.IDS[3], row, collections)[0] == "PASS"
    row["identity"]["userAssignedIdentities"] = {"foreign": {}}
    assert evaluate(sw.IDS[3], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[3])
    row.pop("identity")
    assert evaluate(sw.IDS[3], row, collections)[0] == "FAIL"
    row.pop("_provenance")
    assert evaluate(sw.IDS[3], row, collections)[0] == "UNKNOWN"


def test_workload_inventory_and_current_resolution_required_even_with_valid_reference():
    row, collections = fixture(sw.IDS[4])
    row["workloadSecrets"]["secrets"][0]["resolution_status"] = "AccessToKeyVaultDenied"
    assert evaluate(sw.IDS[4], row, collections)[0] == "FAIL"
    row, collections = fixture(sw.IDS[4])
    row["workloadSecrets"]["secrets"][0].pop("resolution_status")
    assert evaluate(sw.IDS[4], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[4])
    row["workloadSecrets"]["locations_complete"] = False
    assert evaluate(sw.IDS[4], row, collections)[0] == "UNKNOWN"


def test_profile_split_coverage_and_destinations_and_verified_unlimited_retention():
    row, collections = fixture(sw.IDS[5])
    first = collections["monitor_log_profile"][0]
    first["properties"]["categories"] = ["Write"]
    second = copy.deepcopy(first)
    second["id"] = second["id"].replace("default", "other")
    second["properties"]["categories"] = ["Delete", "Action"]
    collections["monitor_log_profile"].append(second)
    assert evaluate(sw.IDS[5], row, collections)[0] == "PASS"
    second["properties"]["storageAccountId"] = None
    assert evaluate(sw.IDS[5], row, collections)[0] == "FAIL"
    second["properties"].pop("serviceBusRuleId")
    assert evaluate(sw.IDS[5], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[6])
    profile = collections["monitor_log_profile"][0]
    profile["properties"]["retentionPolicy"] = {"enabled": False, "days": 0}
    assert evaluate(sw.IDS[6], row, collections)[0] == "UNKNOWN"
    profile["destinationRetention"] = evidence(profile, sink_id=STORAGE, unlimited=True)
    assert evaluate(sw.IDS[6], row, collections)[0] == "PASS"
    profile["destinationRetention"]["sink_id"] = WORKSPACE
    assert evaluate(sw.IDS[6], row, collections)[0] == "UNKNOWN"


def test_diagnostic_setting_parent_sink_support_and_premium_runtime_audit():
    row, collections = fixture(sw.IDS[0])
    row["diagnosticSettings"][0]["parent_id"] = BASE + "Microsoft.DBforMySQL/flexibleServers/other"
    assert evaluate(sw.IDS[0], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[0])
    row["diagnosticSettings"][0]["properties"]["workspaceId"] = None
    assert evaluate(sw.IDS[0], row, collections)[0] == "FAIL"
    row, collections = fixture(sw.IDS[14])
    row["sku"]["name"] = "Premium"
    assert evaluate(sw.IDS[14], row, collections)[0] == "FAIL"
    row["diagnosticSettings"][0]["properties"]["logs"].append({"category": "RuntimeAuditLogs", "enabled": True})
    assert evaluate(sw.IDS[14], row, collections)[0] == "PASS"
    assert evaluate(sw.IDS[14], row, collections, {"resolvedSinkIds": []})[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[14])
    props = row["diagnosticSettings"][0]["properties"]
    props["workspaceId"] = None
    props["eventHubAuthorizationRuleId"] = BASE + "Microsoft.EventHub/namespaces/events/authorizationRules/logs"
    assert evaluate(sw.IDS[14], row, collections)[0] == "FAIL"


def test_locked_storage_policy_alone_and_generic_alert_write_cannot_pass():
    row, collections = fixture(sw.IDS[7])
    row["immutabilityEvidence"]["containers"][0]["enforcement"] = []
    assert evaluate(sw.IDS[7], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[7])
    row["immutabilityEvidence"]["containers"][0]["enforcement"][0]["outcome"] = "allowed"
    assert evaluate(sw.IDS[7], row, collections)[0] == "FAIL"
    row, collections = fixture(sw.IDS[8])
    row["ackAuthorization"]["workflows"][0]["effective_grants"][0]["action"] = "Microsoft.Insights/metricAlerts/write"
    assert evaluate(sw.IDS[8], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[8])
    row["ackAuthorization"]["workflows"][0]["coverage"]["external_systems"] = False
    assert evaluate(sw.IDS[8], row, collections)[0] == "UNKNOWN"


def test_build_requires_current_probe_for_each_endpoint():
    row, collections = fixture(sw.IDS[10])
    row["externalAccess"]["endpoint_ids"].append("self-hosted:443")
    assert evaluate(sw.IDS[10], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[10])
    row["externalAccess"]["probes"][0]["observed_at"] = "2026-01-01T00:00:00Z"
    assert evaluate(sw.IDS[10], row, collections)[0] == "UNKNOWN"


def test_function_complete_no_limit_fails_and_configuration_without_probe_is_unknown():
    row, collections = fixture(sw.IDS[11])
    operation = row["invocationEvidence"]["operations"][0]
    operation["effective_policy_xml"] = "<policies><inbound /></policies>"
    operation.pop("probe")
    assert evaluate(sw.IDS[11], row, collections)[0] == "FAIL"
    row, collections = fixture(sw.IDS[11])
    operation = row["invocationEvidence"]["operations"][0]
    operation.pop("probe")
    assert evaluate(sw.IDS[11], row, collections)[0] == "UNKNOWN"
    operation["effective_policy_xml"] = "<policies><inbound><base /></inbound></policies>"
    assert evaluate(sw.IDS[11], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[11])
    operation = row["invocationEvidence"]["operations"][0]
    operation["probe"]["attempts"][2]["caller_id"] = "other-caller"
    assert evaluate(sw.IDS[11], row, collections)[0] == "UNKNOWN"


def test_firewall_custom_classification_azure_services_sentinel_and_public_access():
    row, collections = fixture(sw.IDS[12])
    rule = collections["sql_server"][0]["firewallRules"][0]
    rule["properties"] = {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}
    assert evaluate(sw.IDS[12], row, collections)[0] == "FAIL"
    assert evaluate(sw.IDS[12], row, collections, {"allowAzureServices": True})[0] == "PASS"
    rule.pop("classification")
    assert evaluate(sw.IDS[12], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[12])
    collections["sql_server"][0]["properties"].pop("publicNetworkAccess")
    assert evaluate(sw.IDS[12], row, collections)[0] == "UNKNOWN"


def test_vmss_templates_and_unresolved_vm_nic_are_separate_from_instance_drift():
    row, collections = fixture(sw.IDS[13])
    scale = resource("Microsoft.Compute/virtualMachineScaleSets/scale", properties={"virtualMachineProfile": {
        "networkProfile": {"networkInterfaceConfigurations": [{"properties": {"ipConfigurations": [{"properties": {}}]}}]}}})
    collections["vm_scale_set"] = [scale]
    assert evaluate(sw.IDS[13], row, collections)[0] == "PASS"
    configs = scale["properties"]["virtualMachineProfile"]["networkProfile"]["networkInterfaceConfigurations"]
    configs[0]["properties"]["ipConfigurations"][0]["properties"]["publicIPAddressConfiguration"] = {"name": "public", "properties": {}}
    assert evaluate(sw.IDS[13], row, collections)[0] == "FAIL"
    row, collections = fixture(sw.IDS[13])
    collections["vm"][0]["properties"]["networkProfile"]["networkInterfaces"][0]["id"] = BASE + "Microsoft.Network/networkInterfaces/missing"
    assert evaluate(sw.IDS[13], row, collections)[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", sw.IDS)
def test_repeat_evaluation_is_immutable_and_duplicate_projection_is_unknown(check_id):
    row, collections = fixture(check_id)
    index = scoped(collections)
    original = copy.deepcopy((row, index))
    check = sw.CHECK_BY_ID[check_id]
    assert check.evaluate(row, index)[0] == "PASS"
    assert check.evaluate(row, index)[0] == "PASS"
    assert (row, index) == original
    dependency = check.dependencies[0]
    if collections[dependency]:
        index[dependency].append(copy.deepcopy(index[dependency][0]))
        index["collections"][dependency][0]["items"].append(copy.deepcopy(collections[dependency][0]))
        assert check.evaluate(row, index)[0] == "UNKNOWN"


def test_unknown_audit_result_and_versioned_get_cannot_prove_use_or_current_rotation():
    row, collections = fixture(sw.IDS[1])
    row["auditHistory"]["events"][0]["ResultType"] = "FutureResult"
    assert evaluate(sw.IDS[1], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[2])
    row["currentVersion"]["_provenance"]["request_uri"] = SECRET_URI + "/current"
    assert evaluate(sw.IDS[2], row, collections)[0] == "UNKNOWN"


def test_every_object_needs_both_denials_and_429_requires_policy_denial_evidence():
    row, collections = fixture(sw.IDS[7])
    row["immutabilityEvidence"]["containers"][0]["object_ids"].append("unmeasured-object")
    assert evaluate(sw.IDS[7], row, collections)[0] == "UNKNOWN"
    row, collections = fixture(sw.IDS[11])
    row["invocationEvidence"]["operations"][0]["probe"]["attempts"][-1]["policy_denial"] = False
    assert evaluate(sw.IDS[11], row, collections)[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", sw.IDS)
def test_foreign_native_type_and_unreadable_identity_coverage_stay_unknown(check_id):
    row, collections = fixture(check_id)
    target = next((value for values in collections.values() for value in values), None)
    assert target is not None
    target["id"] = BASE + "Microsoft.Unrelated/examples/foreign"
    assert evaluate(check_id, row, collections)[0] == "UNKNOWN"
    row, collections = fixture(check_id)
    target = next(value for values in collections.values() for value in values)
    target.setdefault("_coverage", {})["id"] = {"status": "denied"}
    assert evaluate(check_id, row, collections)[0] == "UNKNOWN"


def test_alert_uuid_identity_is_case_insensitive_and_policy_scope_is_required():
    row, collections = fixture(sw.IDS[8])
    principal = "abcdefab-abcd-abcd-abcd-abcdefabcdef"
    row["ackAuthorization"]["workflows"][0]["effective_grants"][0]["principal_id"] = principal.upper()
    assert evaluate(sw.IDS[8], row, collections, {"approvedResponders": [principal]})[0] == "PASS"
    assert evaluate(sw.IDS[8], row, collections, {"scope": "/subscriptions/other"})[0] == "UNKNOWN"


def test_unknown_enabled_diagnostic_category_cannot_hide_a_supported_export():
    row, collections = fixture(sw.IDS[14])
    row["diagnosticSettings"][0]["properties"]["logs"].append({"category": "FutureCategory", "enabled": True})
    assert evaluate(sw.IDS[14], row, collections)[0] == "UNKNOWN"


def test_sw15_conflicting_policy_roots_cannot_prove_build_is_private():
    row, collections = fixture(sw.IDS[10])
    index = scoped(collections)
    modern = copy.deepcopy(POLICY)
    modern["approvedBuildSourceIds"] = ["internet"]
    index["context"]["metadata"]["compliance_policy"] = {"sw15": modern}
    assert sw.CHECK_BY_ID[sw.IDS[10]].evaluate(row, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("namespace, expected", [
    ("equal_copies", "PASS"), ("modern_only", "PASS"), ("legacy_only", "PASS"),
    ("unreadable_legacy", "UNKNOWN"), ("unreadable_modern", "UNKNOWN"),
    ("malformed_legacy", "UNKNOWN"), ("malformed_modern", "UNKNOWN"),
    ("unrelated_modern_root", "PASS"), ("foreign_modern_scope", "UNKNOWN"),
    ("both_missing", "UNKNOWN"),
])
def test_sw15_policy_namespace_resolution_for_registered_build_control(namespace, expected):
    row, collections = fixture(sw.IDS[10])
    index = scoped(collections)
    metadata = index["context"]["metadata"]
    if namespace in ("equal_copies", "unreadable_legacy", "unreadable_modern",
                     "malformed_legacy", "foreign_modern_scope"):
        metadata["compliance_policy"] = {"sw15": copy.deepcopy(POLICY)}
    if namespace == "modern_only":
        metadata.pop("sw15")
        metadata["compliance_policy"] = {"sw15": copy.deepcopy(POLICY)}
    elif namespace == "unreadable_legacy":
        metadata["_coverage"] = {"sw15": {"status": "partial"}}
    elif namespace == "unreadable_modern":
        metadata["compliance_policy"] = {"sw15": copy.deepcopy(POLICY),
                                         "_coverage": {"sw15": {"status": "partial"}}}
    elif namespace == "malformed_legacy":
        metadata["sw15"] = None
    elif namespace == "malformed_modern":
        metadata["compliance_policy"] = None
    elif namespace == "unrelated_modern_root":
        metadata["compliance_policy"] = {"sw14": {"status": "collected"}}
    elif namespace == "foreign_modern_scope":
        metadata["compliance_policy"]["sw15"]["scope"] = "/subscriptions/foreign"
    elif namespace == "both_missing":
        metadata.clear()
    assert sw.CHECK_BY_ID[sw.IDS[10]].evaluate(row, index)[0] == expected


def test_sw15_policy_namespace_empty_coverage_conflicts_with_present_copy():
    row, collections = fixture(sw.IDS[10])
    for root in ("legacy", "modern"):
        index = scoped(collections)
        metadata = index["context"]["metadata"]
        if root == "legacy":
            metadata["_coverage"] = {"sw15": {"status": "empty"}}
        else:
            metadata["compliance_policy"] = {"sw15": copy.deepcopy(POLICY),
                "_coverage": {"sw15": {"status": "empty"}}}
        assert sw.CHECK_BY_ID[sw.IDS[10]].evaluate(row, index)[0] == "UNKNOWN"
