"""Source-bound tests for the fifteen sw33 signed Azure predicates."""
import copy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw33 as sw33

S = "/subscriptions/11111111-1111-1111-1111-111111111111"
R = S + "/resourceGroups/rg/providers"
A = R + "/Microsoft.Storage/storageAccounts/acct"
SH = A + "/fileServices/default/shares/share"
K = "https://vault.vault.azure.net/keys/data/v1"
G = R + "/Microsoft.Network/virtualNetworkGateways/gw"
C = R + "/Microsoft.Network/connections/vpn"
SQL = R + "/Microsoft.Sql/servers/sql"
MI = R + "/Microsoft.Sql/managedInstances/mi"
GW = R + "/Microsoft.Network/applicationGateways/gw"
LA = R + "/Microsoft.OperationalInsights/workspaces/ws"
EH = R + "/Microsoft.EventHub/namespaces/eh"

def index(kinds, policy=None):
    value = {"context": {"provider": "azure", "scope": S, "metadata": {"compliance_policy": {"sw33": {"status": "collected", "scope": S, **(policy or {})}}}},
             "collections": {}}
    for kind, rows in kinds.items():
        value["collections"][kind] = [{"type": kind, "scope": S, "status": "collected", "items": rows}]
        value[kind] = [{"type": kind, "scope": S, "data": row} for row in rows]
    return value

def fixture(check_id):
    """A complete safe declaration, one proven adverse field, and no implicit collector defaults."""
    if check_id == "azure_route_table_network_http_internet_access_restricted_5cd2484":
        rid = R + "/Microsoft.Network/routeTables/rt"
        route = {"id": rid + "/routes/a", "properties": {"addressPrefix": "10.0.0.0/24"}}
        row = {"id": rid, "properties": {"routes": [route]}}
        return row, index({"route_table": [row]}, {"routeDestinations": {"routeTableIds": [rid], "allowedDestinationCidrs": ["10.0.0.0/8"]}}), lambda x: x["route_table"][0]["data"]["properties"]["routes"][0]["properties"].update(addressPrefix="0.0.0.0/0")
    if check_id == "azure_storage_file_share_3_5_1_15_17dc7f4":
        row = {"id": A, "properties": {"encryption": {"keySource": "Microsoft.Keyvault", "services": {"file": {"enabled": True}}, "keyVaultProperties": {"currentVersionedKeyIdentifier": K, "keyVaultUri": "https://vault.vault.azure.net", "keyName": "data", "keyVersion": "v1"}}}}
        return row, index({"storage_account": [row]}, {"azureFilesKeys": {"approvedKeyIds": [K]}}), lambda x: x["storage_account"][0]["data"]["properties"]["encryption"].update(keySource="Microsoft.Storage")
    if check_id == "azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb":
        pod = {"id": R + "/Microsoft.ContainerService/managedClusters/aks/pods/p", "spec": {"containers": [{"name": "app", "securityContext": {"readOnlyRootFilesystem": True}}], "initContainers": [], "ephemeralContainers": []}}
        kinds = {k: [] for k in ("aks_pod", "aks_deployment", "aks_statefulset", "aks_daemonset", "aks_job", "aks_cronjob")}; kinds["aks_pod"] = [pod]
        return {}, index(kinds), lambda x: x["aks_pod"][0]["data"]["spec"]["containers"][0]["securityContext"].update(readOnlyRootFilesystem=False)
    if check_id == "azure_directory_user_10_6_3_21_d013932":
        uid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        kinds = {"directory_user": [{"id": uid, "accountEnabled": False}], "directory_user_group_membership": [{"id": uid, "userId": uid, "groups": [{"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}]}]}
        return {}, index(kinds), lambda x: x["directory_user_group_membership"][0]["data"].update(groups=[])
    if check_id == "azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9":
        admin = {"id": SQL + "/administrators/ActiveDirectory", "properties": {"administratorType": "ActiveDirectory", "sid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}}
        kinds = {"sql_database": [{"id": SQL + "/databases/db"}], "sql_server": [{"id": SQL, "serverAdministrators": [admin]}], "mssql_managed_instance": [], "sql_managed_instance_administrator": []}
        return {}, index(kinds), lambda x: x["sql_server"][0]["data"].update(serverAdministrators=[])
    if check_id == "azure_storage_file_share_10_3_3_18_d67ab34":
        policy_id = R + "/Microsoft.RecoveryServices/vaults/v/backupPolicies/p"
        kinds = {"storage_file_share": [{"id": SH}], "netapp_volume": [], "backup_protected_item": [{"id": R + "/Microsoft.RecoveryServices/vaults/v/backupProtectedItems/i", "properties": {"sourceResourceId": A, "friendlyName": "share", "protectedItemType": "AzureFileShareProtectedItem", "protectionState": "Protected", "policyId": policy_id}}], "backup_policy": [{"id": policy_id}], "recovery_vault": [{"id": R + "/Microsoft.RecoveryServices/vaults/v"}], "netapp_backup_policy": [], "netapp_backup_vault": []}
        return {}, index(kinds), lambda x: x["backup_protected_item"][0]["data"]["properties"].update(protectionState="NotProtected")
    if check_id == "azure_azure_resource_1_3_1_46_b70e2c8":
        conn = {"id": C, "properties": {"virtualNetworkGateway1": {"id": G}, "tunnelConnectionStatus": [{"tunnel": "a", "connectionStatus": "Connected"}, {"tunnel": "b", "connectionStatus": "Connected"}]}}
        kinds = {"virtual_network_gateway": [{"id": G}], "virtual_network_gateway_connection": [conn]}
        policy = {"vpnTunnels": {"gatewayId": G, "expectedTunnels": [{"connectionId": C, "tunnel": "a"}, {"connectionId": C, "tunnel": "b"}]}}
        return {}, index(kinds, policy), lambda x: x["virtual_network_gateway_connection"][0]["data"]["properties"]["tunnelConnectionStatus"][0].update(connectionStatus="Disconnected")
    if check_id == "azure_application_gateway_app_http_logs_enabled_2de0361":
        setting = {"id": GW + "/providers/Microsoft.Insights/diagnosticSettings/d", "properties": {"workspaceId": LA, "logs": [{"category": "ApplicationGatewayAccessLog", "enabled": True}]}}
        kinds = {"application_gateway": [{"id": GW}], "load_balancer": [], "diagnostic_setting": [setting], "diagnostic_category": [{"id": GW + "/providers/Microsoft.Insights/diagnosticSettingsCategories/ApplicationGatewayAccessLog", "resourceId": GW, "name": "ApplicationGatewayAccessLog", "categoryType": "Logs"}], "log_analytics_workspace": [{"id": LA}], "storage_account": []}
        return {}, index(kinds), lambda x: x["diagnostic_setting"][0]["data"]["properties"]["logs"][0].update(enabled=False)
    if check_id == "azure_c5_am_09_01b":
        row = {"id": A, "type": "Microsoft.Storage/storageAccounts", "tags": {"data-class": "restricted"}}
        policy = {"classification": {"tagKey": "data-class", "assets": [{"id": A, "applicable": True, "tagSuitable": True, "approvedLabel": "restricted"}]}}
        return {}, index({"resource_graph": [row]}, policy), lambda x: x["resource_graph"][0]["data"].update(tags={})
    if check_id == "azure_c5_cry_08_01b":
        cert = {"id": R + "/Microsoft.KeyVault/vaults/v/certificates/c", "isCurrentVersion": True, "policy": {"issuer": {"name": "ApprovedCA"}, "key_props": {"kty": "RSA", "key_size": 3072}}}
        process = {"id": S, "procedureCurrent": True, "identityVerified": True, "secureIssuance": True, "trustedCaVerified": True, "periodStart": "2026-01-01T00:00:00Z", "periodEnd": "2026-12-31T00:00:00Z"}
        policy = {"certificateIssuance": {"approvedIssuers": ["ApprovedCA"], "approvedKeyTypes": ["RSA"], "approvedEcCurves": ["P-256"], "minimumRsaBits": 2048, "assessedAt": "2026-10-12T00:00:00Z"}}
        return {}, index({"key_vault_certificate_current": [cert], "certificate_issuance_evidence": [process]}, policy), lambda x: x["key_vault_certificate_current"][0]["data"]["policy"]["issuer"].update(name="BadCA")
    if check_id == "azure.cis.auto_provision_vulnerability_assessment_machines":
        setting = {"id": S + "/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/azureServersSetting", "kind": "AzureServersSetting", "properties": {"selectedProvider": "MdeTvm"}}
        pricing = {"id": S + "/providers/Microsoft.Security/pricings/VirtualMachines", "name": "VirtualMachines", "properties": {"pricingTier": "Standard"}}
        kinds = {"security_pricing": [pricing], "server_vulnerability_assessment_setting": [setting], "arc_machine": [], "arc_vulnerability_assessment_evidence": []}
        return {}, index(kinds), lambda x: x["security_pricing"][0]["data"]["properties"].update(pricingTier="Free")
    if check_id == "azure.cis.unity_catalog_configured_databricks":
        row = {"id": R + "/Microsoft.Databricks/workspaces/w", "accountId": "acct", "workspaceId": 12, "state": "ACTIVE", "metastore": {"httpStatus": 200, "metastore_assignment": {"workspace_id": 12, "metastore_id": "meta"}}}
        return {}, index({"databricks_account_workspace": [row]}, {"databricksAccount": {"accountId": "acct"}}), lambda x: x["databricks_account_workspace"][0]["data"]["metastore"].clear() or x["databricks_account_workspace"][0]["data"]["metastore"].update(httpStatus=404, documentedNoAssignment=True)
    if check_id == "azure.other.database_backup_alert":
        from tests.test_peaso_azure_database_alert_delivery_binding import observed
        return {}, observed(), lambda x: x["database_backup_alert_evidence"][0]["data"]["signals"]["paused"].update(testStatus="failed")
    if check_id == "azure.other.message_namespace_cmk":
        row = {"id": EH, "sku": {"tier": "Premium"}, "properties": {"encryption": {"keySource": "Microsoft.KeyVault", "keyVaultProperties": [{"keyVaultKeyUrl": K}]}}}
        kinds = {"eventhub_namespace": [row], "servicebus_namespace": [], "message_cmk_negative_test": [{"id": EH + "/negativeTest", "namespaceId": EH, "keyUsable": True, "withoutCmkRejected": True}]}
        return {}, index(kinds, {"messagingCmk": {"approvedKeys": [{"id": K}]}}), lambda x: x["message_cmk_negative_test"][0]["data"].update(withoutCmkRejected=False)
    if check_id == "azure.other.change_approval_trace":
        rid = R + "/Microsoft.Storage/storageAccounts/acct"
        event = {"id": S + "/providers/Microsoft.Insights/eventtypes/management/values/e", "eventTimestamp": "2026-10-10T12:00:00Z", "operationName": {"value": "Microsoft.Storage/storageAccounts/write"}, "status": {"value": "Succeeded"}, "resourceId": rid, "correlationId": "cor", "caller": "user"}
        approval = {"id": S + "/approvalRecords/t", "correlationId": "cor", "resourceId": rid, "ticketId": "T-1", "approver": "owner", "status": "Approved", "approvedAt": "2026-10-09T12:00:00Z"}
        coverage = {"id": S, "retainedFrom": "2026-10-01T00:00:00Z", "collectedThrough": "2026-10-12T00:00:00Z"}
        policy = {"changeApproval": {"windowStart": "2026-10-01T00:00:00Z", "windowEnd": "2026-10-12T00:00:00Z"}}
        return {}, index({"activity_log": [event], "activity_log_coverage": [coverage], "change_approval_record": [approval]}, policy), lambda x: x["change_approval_record"][0]["data"].update(approvedAt="2026-10-11T12:00:00Z")
    raise AssertionError(check_id)


def refreshed(facts):
    """Keep wrapper and envelope representations consistent after a fixture mutation."""
    for kind, resources in ((k, v) for k, v in facts.items() if isinstance(v, list) and k in facts.get("collections", {})):
        facts["collections"][kind][0]["items"] = [r["data"] for r in resources]
    return facts

@pytest.mark.parametrize("check_id", sw33.IDS)
def test_pass_fail_missing_incomplete_malformed_and_foreign_scope(check_id):
    item, facts, make_bad = fixture(check_id)
    assert evaluate_check(check_id, item, facts)[0] == "PASS", check_id
    bad = copy.deepcopy(facts)
    make_bad(bad)
    refreshed(bad)
    bad_item = bad[next(iter(facts["collections"]))][0]["data"] if item else {}
    assert evaluate_check(check_id, bad_item, bad)[0] == "FAIL", check_id
    primary = next(iter(facts["collections"]))
    missing = copy.deepcopy(facts)
    del missing["collections"][primary]
    assert evaluate_check(check_id, item, missing)[0] == "UNKNOWN"
    incomplete = copy.deepcopy(facts)
    incomplete["collections"][primary][0]["status"] = "partial"
    assert evaluate_check(check_id, item, incomplete)[0] == "UNKNOWN"
    malformed = copy.deepcopy(facts)
    malformed["collections"][primary][0]["items"] = "bad"
    assert evaluate_check(check_id, item, malformed)[0] == "UNKNOWN"
    foreign = copy.deepcopy(facts)
    foreign["collections"][primary][0]["scope"] = "/subscriptions/22222222-2222-2222-2222-222222222222"
    assert evaluate_check(check_id, item, foreign)[0] == "UNKNOWN"
    missing_field = copy.deepcopy(facts)
    del missing_field[primary][0]["data"]["id"]
    assert evaluate_check(check_id, item, refreshed(missing_field))[0] == "UNKNOWN"
    malformed_field = copy.deepcopy(facts)
    malformed_field[primary][0]["data"]["id"] = 42
    assert evaluate_check(check_id, item, refreshed(malformed_field))[0] == "UNKNOWN"


def test_not_applicable_unscoped_route_table():
    cid = "azure_route_table_network_http_internet_access_restricted_5cd2484"
    item, facts, _ = fixture(cid)
    facts["context"]["metadata"]["compliance_policy"]["sw33"]["routeDestinations"]["routeTableIds"] = []
    assert evaluate_check(cid, item, facts)[0] == "NOT_APPLICABLE"


def test_disabled_directory_user_is_included_and_missing_membership_cannot_pass():
    cid = "azure_directory_user_10_6_3_21_d013932"
    item, facts, _ = fixture(cid)
    facts["directory_user_group_membership"][0]["data"]["groups"] = []
    assert evaluate_check(cid, item, refreshed(facts))[0] == "FAIL"
    facts["directory_user_group_membership"] = []
    facts["collections"]["directory_user_group_membership"][0]["items"] = []
    assert evaluate_check(cid, item, facts)[0] == "UNKNOWN"


def test_vpn_parent_connected_and_wrong_gateway_do_not_pass():
    cid = "azure_azure_resource_1_3_1_46_b70e2c8"
    item, facts, _ = fixture(cid)
    connection = facts["virtual_network_gateway_connection"][0]["data"]
    connection["properties"]["connectionStatus"] = "Connected"
    connection["properties"]["tunnelConnectionStatus"] = []
    assert evaluate_check(cid, item, refreshed(facts))[0] == "FAIL"
    connection["properties"]["virtualNetworkGateway1"]["id"] = R + "/Microsoft.Network/virtualNetworkGateways/other"
    assert evaluate_check(cid, item, refreshed(facts))[0] == "UNKNOWN"
    connection["properties"]["virtualNetworkGateway1"]["id"] = G
    connection["properties"]["tunnelConnectionStatus"] = [
        {"tunnel": "a", "connectionStatus": "Connected"},
        {"tunnel": "b", "connectionStatus": "Connected"},
        {"tunnel": "unselected", "connectionStatus": "Connected"}]
    assert evaluate_check(cid, item, refreshed(facts))[0] == "UNKNOWN"


def test_sql_managed_instance_requires_its_own_administrator():
    cid = "azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9"
    item, facts, _ = fixture(cid)
    facts["mssql_managed_instance"].append({"type": "mssql_managed_instance", "scope": S, "data": {"id": MI}})
    facts["sql_managed_instance_administrator"].append({"type": "sql_managed_instance_administrator", "scope": S, "data": {"id": MI, "administrators": []}})
    assert evaluate_check(cid, item, refreshed(facts))[0] == "FAIL"
    facts["sql_managed_instance_administrator"] = []
    assert evaluate_check(cid, item, refreshed(facts))[0] == "UNKNOWN"


def test_certificate_metadata_without_process_evidence_is_unknown():
    cid = "azure_c5_cry_08_01b"
    item, facts, _ = fixture(cid)
    facts["certificate_issuance_evidence"] = []
    assert evaluate_check(cid, item, refreshed(facts))[0] == "UNKNOWN"


def test_databricks_other_metastore_error_is_unknown():
    cid = "azure.cis.unity_catalog_configured_databricks"
    item, facts, _ = fixture(cid)
    facts["databricks_account_workspace"][0]["data"]["metastore"] = {"httpStatus": 403}
    assert evaluate_check(cid, item, refreshed(facts))[0] == "UNKNOWN"


def test_measured_disabled_defender_setting_survives_missing_arc_proof():
    cid = "azure.cis.auto_provision_vulnerability_assessment_machines"
    item, facts, _ = fixture(cid)
    facts["security_pricing"][0]["data"]["properties"]["pricingTier"] = "Free"
    del facts["collections"]["arc_machine"]
    assert evaluate_check(cid, item, refreshed(facts))[0] == "FAIL"


def test_service_managed_messaging_key_is_conclusive_without_publish_test():
    cid = "azure.other.message_namespace_cmk"
    item, facts, _ = fixture(cid)
    facts["eventhub_namespace"][0]["data"]["properties"]["encryption"]["keySource"] = "ServiceManaged"
    del facts["collections"]["message_cmk_negative_test"]
    assert evaluate_check(cid, item, refreshed(facts))[0] == "FAIL"


