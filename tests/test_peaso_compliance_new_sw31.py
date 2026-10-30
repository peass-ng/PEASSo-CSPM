"""Isolated, signed Azure sw31 predicates and missing-fact boundaries."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw31 as sw31  # noqa: F401  (registration side effect)

S = "/subscriptions/sub"
R = S + "/resourceGroups/rg/providers/"
SQL = R + "Microsoft.Sql/servers/s/databases/db"
MYSQL = R + "Microsoft.DBforMySQL/servers/m"
NSG = R + "Microsoft.Network/networkSecurityGroups/n"
BACKUP = R + "Microsoft.RecoveryServices/vaults/v/backupProtectedItems/i"
VM = R + "Microsoft.Compute/virtualMachines/v"


def index(collections, policy=None):
    result = {"context": {"provider": "azure", "scope": S, "created_at": "2026-10-12T00:00:00Z",
                        "metadata": {"compliance_policy": {"sw31": policy or {}}}},
            "collections": {kind: [{"scope": scope, "status": "collected" if rows else "empty", "items": copy.deepcopy(rows)}
                                   for scope, rows in batches]
                            for kind, batches in collections.items()},
            **{kind: [{"scope": scope, "data": copy.deepcopy(row)} for scope, rows in batches for row in rows]
               for kind, batches in collections.items()}}
    if policy and '_synthetic_backup_fixture_capture' in policy:
        capture = policy['_synthetic_backup_fixture_capture']
        result['context']['metadata'].update(copy.deepcopy(capture))
        for kind in ('recovery_vault', 'backup_job', 'backup_protected_item'):
            for envelope in result['collections'].get(kind, []):
                envelope.update(type=kind, service='Microsoft.RecoveryServices' if kind == 'recovery_vault' else 'azure',
                    _provenance={key: capture[key] for key in ('credential_context_id', 'customer_context_id')})
            for wrapper in result.get(kind, []):
                wrapper.update(type=kind, provider='azure')
    return result



def one(**kinds):
    return {kind: [(S, rows)] for kind, rows in kinds.items()}


def sql():
    return {"id": SQL, "properties": {"status": "Online"}}


def mysql():
    return {"id": MYSQL, "properties": {"sslEnforcement": "Enabled"}}


def nsg():
    return {"id": NSG, "properties": {"securityRules": [], "defaultSecurityRules": []}}


def backup():
    return {"id": BACKUP, "properties": {"lastRecoveryPoint": "2026-10-10T00:00:00Z",
             "lastBackupStatus": "Completed", "protectionState": "Protected"}}


def path():
    return {"id": NSG + "/effectiveInternetPaths/tcp443", "parent_id": NSG,
            "properties": {"protocol": "Tcp", "destinationPort": 443, "worldSource": True, "allowed": True}}


def case(cid):
    if cid == "azure_recovery_vault_10_3_3_1_1f42f66":
        p = {"id": SQL + "/backupShortTermRetentionPolicies/default", "properties": {"retentionDays": 7}}
        c = one(sql_database=[sql()], sql_backup_short_term_policy=[p])
        bad = copy.deepcopy(c); bad["sql_backup_short_term_policy"][0][1][0]["properties"]["retentionDays"] = 0
        return c, bad, {}, "sql_database", True
    if cid == "azure_recovery_vault_10_3_3_8_26e08d7":
        p = {"id": SQL + "/backupShortTermRetentionPolicies/default", "properties": {"retentionDays": 7}}
        point = {"id": SQL + "/restorePoints/p", "parent_id": SQL,
                 "properties": {"restorePointCreationDate": "2026-10-10T00:00:00Z"}}
        c = one(sql_database=[sql()], sql_backup_short_term_policy=[p], sql_restore_point=[point])
        bad = copy.deepcopy(c); bad["sql_backup_short_term_policy"][0][1][0]["properties"]["retentionDays"] = 0
        return c, bad, {}, "sql_database", True
    if cid == "azure.gap.sql_database_long_term_geo_redundant_backup_enabled":
        p = {"id": SQL + "/backupLongTermRetentionPolicies/default", "properties":
             {"weeklyRetention": "P1W", "monthlyRetention": "P0M", "yearlyRetention": "P0Y"}}
        copyrow = {"id": SQL + "/longTermRetentionBackups/b", "parent_id": SQL,
                   "properties": {"backupStorageRedundancy": "Geo"}}
        c = one(sql_database=[sql()], sql_database_ltr_policy=[p], sql_ltr_backup=[copyrow])
        bad = copy.deepcopy(c); bad["sql_ltr_backup"][0][1][0]["properties"]["backupStorageRedundancy"] = "Local"
        return c, bad, {}, "sql_database", True
    if cid == "azure.cis.enforce_ssl_connection_mysql_server":
        c = one(mysql_single_server=[mysql()]); bad = copy.deepcopy(c)
        bad["mysql_single_server"][0][1][0]["properties"]["sslEnforcement"] = "Disabled"
        return c, bad, {}, "mysql_single_server", True
    if cid == "azure.cis.mysql_single_audit_log_enabled":
        config = {"id": MYSQL + "/configurations/audit_log_enabled", "parent_id": MYSQL,
                  "name": "audit_log_enabled", "properties": {"value": "ON"}}
        c = one(mysql_single_server=[mysql()], mysql_single_configuration=[config]); bad = copy.deepcopy(c)
        bad["mysql_single_configuration"][0][1][0]["properties"]["value"] = "OFF"
        return c, bad, {}, "mysql_single_server", True
    if cid == "azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5":
        tde = {"id": SQL + "/transparentDataEncryption/current", "parent_id": SQL,
               "properties": {"state": "Enabled"}}
        c = one(sql_database=[sql()], sql_tde=[tde], managed_instance_database=[], managed_instance_tde=[])
        bad = copy.deepcopy(c); bad["sql_tde"][0][1][0]["properties"]["state"] = "Disabled"
        return c, bad, {}, "sql_database", True
    if cid in ("azure.gap.audit_diagnostic_setting", "azure_sql_database_sqlserver_auditing_enabled_77d6841"):
        rid = VM if cid.startswith("azure.gap") else SQL
        resource = {"id": rid, "type": "Microsoft.Compute/virtualMachines"} if rid == VM else sql()
        setting = {"id": rid + "/providers/Microsoft.Insights/diagnosticSettings/d", "parent_id": rid,
                   "properties": {"workspaceId": S + "/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w",
                                  "logs": [{"category": "Audit", "enabled": True}]}}
        category = {"id": rid + "/providers/Microsoft.Insights/diagnosticSettingsCategories/Audit",
                    "parent_id": rid, "name": "Audit"}
        kind = "resource" if rid == VM else "sql_database"
        c = one(**{kind: [resource]}, diagnostic_setting=[setting], diagnostic_category=[category]); bad = copy.deepcopy(c)
        bad["diagnostic_setting"][0][1][0]["properties"]["logs"][0]["enabled"] = False
        policy = {"requiredCategories": ["Audit"], "approvedSinkIds": [setting["properties"]["workspaceId"]]}
        if rid == VM: policy["selectedResourceTypes"] = ["Microsoft.Compute/virtualMachines"]
        return c, bad, policy, kind, True
    if cid == "azure.gap.asset_inventory_required_metadata":
        c = one(resource_graph=[{"id": VM, "subscriptionId": "sub", "type": "Microsoft.Compute/virtualMachines", "location": "westeurope", "tags": {"owner": "team"}}]); bad = copy.deepcopy(c)
        bad["resource_graph"][0][1][0]["tags"] = {}
        return c, bad, {"requiredTagKeys": ["owner"], "inScopeResourceTypes": ["Microsoft.Compute/virtualMachines"]}, "resource_graph", True
    if cid == "azure.other.region_allowlist":
        e = {"id": S + "/regionalControlEvidence/e", "properties": {"disallowedDeploymentDenied": True,
             "unauthorizedRegionSecretDenied": True, "euOperationsVerified": True}}
        c = one(resource=[{"id": VM, "type": "Microsoft.Compute/virtualMachines", "location": "westeurope", "zones": ["1"]}], regional_control_evidence=[e]); bad = copy.deepcopy(c)
        bad["resource"][0][1][0]["location"] = "eastus"
        return c, bad, {"approvedRegions": ["westeurope"], "globalResourceTypes": ["Microsoft.Resources/subscriptions"], "approvedZones": {"microsoft.compute/virtualmachines": ["1"]}}, "resource", False
    if cid in ("azure.other.backup_freshness_14_days", "azure.other.backup_freshness_30_days"):
        c = one(backup_protected_item=[backup()]); bad = copy.deepcopy(c)
        bad["backup_protected_item"][0][1][0]["properties"]["lastRecoveryPoint"] = "2026-08-01T00:00:00Z"
        return c, bad, {"requiredBackupItemIds": [BACKUP]}, "backup_protected_item", False
    if cid == "azure_c5_ops_07_01b":
        from tests.backup_c5_fixture_data import fixture_index
        prepared = fixture_index(cid, S, "2026-10-12T00:00:00Z")
        c = {kind: [(S, copy.deepcopy(envs[0]['items']))] for kind, envs in prepared['collections'].items()}
        bad = copy.deepcopy(c)
        bad['backup_protected_item'][0][1][0]['properties']['lastBackupStatus'] = 'Failed'
        policy = prepared['context']['metadata']['compliance_policy']['sw31']
        policy['_synthetic_backup_fixture_capture'] = {key: prepared['context']['metadata'][key]
            for key in ('tenant_id', 'tenant_verified', 'credential_context_id', 'customer_context_id')}
        return c, bad, policy, 'backup_protected_item', False
    if cid == "azure_nsg_world_ingress_approved_ports":
        c = one(nsg=[nsg()], nsg_effective_internet_path=[path()]); bad = copy.deepcopy(c)
        bad["nsg_effective_internet_path"][0][1][0]["properties"]["destinationPort"] = 22
        return c, bad, {"approvedInternetPorts": [443]}, "nsg", True
    if cid == "azure.other.nsg_port_protocol_assignment":
        from tests.nsg_service_observation_fixture import fixture, digest
        c, policy = fixture()
        bad, _ = fixture(actual='ssh')
        policy['serviceObservationAuthority']['approvedObservationSha256s'].append(
            digest(bad['nsg_service_measurement'][0][1][0]['properties']['observation']))
        return c, bad, policy, "nsg", False
    raise AssertionError(cid)


IDS = ("azure.other.nsg_port_protocol_assignment", "azure_nsg_world_ingress_approved_ports",
 "azure.gap.sql_database_long_term_geo_redundant_backup_enabled", "azure_recovery_vault_10_3_3_1_1f42f66",
 "azure_recovery_vault_10_3_3_8_26e08d7", "azure_sql_database_sqlserver_auditing_enabled_77d6841",
 "azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5", "azure.gap.asset_inventory_required_metadata",
 "azure.gap.audit_diagnostic_setting", "azure.other.region_allowlist", "azure.other.backup_freshness_14_days",
 "azure.other.backup_freshness_30_days", "azure_c5_ops_07_01b", "azure.cis.enforce_ssl_connection_mysql_server",
 "azure.cis.mysql_single_audit_log_enabled")


@pytest.fixture(scope="module", autouse=True)
def cleanup_draft_registration():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in IDS]


@pytest.mark.parametrize("cid", IDS)
def test_pass_fail_unknown_boundaries(cid):
    good, bad, policy, primary, applicable_empty = case(cid)
    assert evaluate_check(cid, {"scope": S}, index(good, policy))[0] == "PASS"
    assert evaluate_check(cid, {"scope": S}, index(bad, policy))[0] == "FAIL"
    partial = index(good, policy); partial["collections"][primary][0]["status"] = "partial"
    assert evaluate_check(cid, {"scope": S}, partial)[0] == "UNKNOWN"
    missing = index(good, policy); missing["collections"].pop(primary)
    assert evaluate_check(cid, {"scope": S}, missing)[0] == "UNKNOWN"
    malformed = copy.deepcopy(good); malformed[primary][0][1][0]["id"] = 42
    assert evaluate_check(cid, {"scope": S}, index(malformed, policy))[0] == "UNKNOWN"
    foreign = index(good, policy); foreign["context"]["scope"] = "/subscriptions/other"
    assert evaluate_check(cid, {"scope": S}, foreign)[0] == "UNKNOWN"
    if applicable_empty:
        empty = copy.deepcopy(good); empty[primary][0] = (S, [])
        assert evaluate_check(cid, {"scope": S}, index(empty, policy))[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("cid", ["azure_nsg_world_ingress_approved_ports",
    "azure.gap.asset_inventory_required_metadata", "azure.gap.audit_diagnostic_setting", "azure.other.region_allowlist",
    "azure.other.backup_freshness_14_days", "azure.other.backup_freshness_30_days", "azure_c5_ops_07_01b"])
def test_missing_operator_policy_is_unknown(cid):
    good, _, policy, _, _ = case(cid)
    facts = index(good, policy)
    facts["context"]["metadata"].pop("compliance_policy")
    assert evaluate_check(cid, {"scope": S}, facts)[0] == "UNKNOWN"


def test_definite_fail_precedes_other_unknown_facts():
    cid = "azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5"
    _, bad, policy, _, _ = case(cid)
    missing_mi = index(bad, policy)
    missing_mi["collections"].pop("managed_instance_database")
    assert evaluate_check(cid, {"scope": S}, missing_mi)[0] == "FAIL"

    cid = "azure.gap.sql_database_long_term_geo_redundant_backup_enabled"
    _, bad, policy, _, _ = case(cid)
    missing_policy = index(bad, policy)
    missing_policy["collections"].pop("sql_database_ltr_policy")
    assert evaluate_check(cid, {"scope": S}, missing_policy)[0] == "FAIL"

    cid = "azure_c5_ops_07_01b"
    _, bad, policy, _, _ = case(cid)
    missing_jobs = index(bad, policy)
    missing_jobs["collections"].pop("backup_job")
    assert evaluate_check(cid, {"scope": S}, missing_jobs)[0] == "FAIL"


def test_nsg_service_empty_exposure_and_measurement_binding():
    cid = "azure.other.nsg_port_protocol_assignment"
    good, _, policy, _, _ = case(cid)
    no_paths = copy.deepcopy(good)
    no_paths["nsg_effective_internet_path"][0] = (S, [])
    no_paths["nsg_service_measurement"][0] = (S, [])
    assert evaluate_check(cid, {"scope": S}, index(no_paths, policy))[0] == "PASS"
    mismatch = copy.deepcopy(good)
    mismatch["nsg_service_measurement"][0][1][0]["properties"]["port"] = 22
    assert evaluate_check(cid, {"scope": S}, index(mismatch, policy))[0] == "UNKNOWN"


def test_sql_logging_requires_log_analytics_workspace():
    cid = "azure_sql_database_sqlserver_auditing_enabled_77d6841"
    good, _, policy, _, _ = case(cid)
    storage = copy.deepcopy(good)
    props = storage["diagnostic_setting"][0][1][0]["properties"]
    props["storageAccountId"] = props.pop("workspaceId")
    assert evaluate_check(cid, {"scope": S}, index(storage, policy))[0] == "FAIL"


@pytest.mark.parametrize("cid", ["azure.other.backup_freshness_14_days", "azure.other.backup_freshness_30_days"])
def test_backup_operation_time_does_not_replace_recovery_point(cid):
    good, _, policy, _, _ = case(cid)
    no_point = copy.deepcopy(good)
    props = no_point["backup_protected_item"][0][1][0]["properties"]
    props.pop("lastRecoveryPoint")
    props["lastBackupTime"] = "2026-10-11T00:00:00Z"
    assert evaluate_check(cid, {"scope": S}, index(no_point, policy))[0] == "UNKNOWN"
    stale = copy.deepcopy(good)
    stale_props = stale["backup_protected_item"][0][1][0]["properties"]
    stale_props.pop("lastBackupStatus")
    stale_props["lastRecoveryPoint"] = "2026-08-01T00:00:00Z"
    assert evaluate_check(cid, {"scope": S}, index(stale, policy))[0] == "FAIL"


@pytest.mark.parametrize("cid,primary", [
    ("azure_recovery_vault_10_3_3_1_1f42f66", "sql_database"),
    ("azure_recovery_vault_10_3_3_8_26e08d7", "sql_database"),
    ("azure.cis.mysql_single_audit_log_enabled", "mysql_single_server"),
    ("azure_nsg_world_ingress_approved_ports", "nsg")])
def test_empty_primary_inventory_is_not_applicable_before_child_reads(cid, primary):
    facts = index(one(**{primary: []}))
    assert evaluate_check(cid, {"scope": S}, facts)[0] == "NOT_APPLICABLE"
