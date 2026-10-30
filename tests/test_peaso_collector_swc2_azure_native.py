"""Azure wave 2 native read coverage with provider-owned mocked responses."""
import copy
from urllib.parse import parse_qs, urlsplit

import pytest

from peaso.collectors import azure, azure_sql_ltr_native
from peaso.snapshot import validate


SCOPE = "/subscriptions/sub-a"
ROOT = SCOPE + "/resourceGroups/rg/providers/"


class ReadError(RuntimeError):
    def __init__(self, status):
        super().__init__("SENSITIVE_EXCEPTION_BODY")
        self.status = status


class Fixture:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []
        self.tenant = "tenant-a"
        self.verified_tenant = "tenant-a"

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        if body is not None:
            return {"data": []}
        path = urlsplit(url).path
        value = self.routes.get(path, {"value": []})
        if callable(value):
            value = value(parse_qs(urlsplit(url).query))
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


def collect(kinds, routes, **options):
    fixture = Fixture(routes)
    snapshot = azure.collect({"scopes": ["sub-a"], "options": {"retries": 0, **options}}, kinds, transport=fixture)
    assert validate(snapshot) == snapshot
    assert "SENSITIVE_EXCEPTION_BODY" not in str(snapshot)
    return snapshot, fixture


def rows(snapshot, kind):
    return next(c for c in snapshot["collections"] if c["scope"] == SCOPE and c["type"] == kind)


def endpoint(kind):
    return SCOPE + "/providers/" + azure.ENDPOINTS[kind][0]


@pytest.mark.parametrize("mode,status,count", [
    ("complete", "collected", 1), ("empty", "empty", 0),
    ("paginated", "collected", 2), ("error", "denied", 0),
    ("partial", "partial", 1),
])
def test_action_group_native_inventory(mode, status, count):
    path = endpoint("action_group")
    ids = [ROOT + "Microsoft.Insights/actionGroups/" + name for name in ("one", "two")]
    values = [{"id": rid, "type": "Microsoft.Insights/actionGroups", "properties": {
        "enabled": True, "webhookReceivers": [{"serviceUri": "https://example.test/?secret=SENSITIVE_EXCEPTION_BODY"}]}}
              for rid in ids]
    def list_response(query):
        if mode == "error":
            return ReadError(403)
        if mode == "empty":
            return {"value": []}
        if "page" in query:
            return ReadError(403) if mode == "partial" else {"value": [values[1]]}
        return {"value": [values[0]], "nextLink": azure.ARM + path + "?page=2"} if mode in ("partial", "paginated") else {"value": [values[0]]}
    routes = {path: list_response, **{row["id"]: row for row in values}}
    snapshot, fixture = collect(["action_group"], routes)
    group = rows(snapshot, "action_group")
    assert (group["status"], len(group["items"])) == (status, count)
    if count:
        assert group["items"][0]["_provenance"]["source_operation"] == "action_groups_list_by_subscription"
        assert group["items"][0]["_provenance"]["native_response_complete"] is False
        assert group["items"][0]["properties"]["enabled"] is True
        assert group["items"][0]["_coverage"]["receivers"]["status"] == "not_collected"
    if mode == "paginated":
        assert any("page=2" in call[0] for call in fixture.calls)


def test_scheduled_rule_list_provenance_preserves_native_shape():
    rid = ROOT + "Microsoft.Insights/scheduledQueryRules/rule"
    snapshot, _ = collect(["scheduled_query_rule"], {endpoint("scheduled_query_rule"): {"value": [
        {"id": rid, "kind": "LogAlert", "properties": {"criteria": {"allOf": []}, "enabled": True}}
    ]}})
    rule = rows(snapshot, "scheduled_query_rule")["items"][0]
    assert rule["_provenance"]["representation"] == "full"
    assert rule["_provenance"]["source_operation"] == "scheduled_query_rules_list_by_subscription"
    assert rule["properties"]["criteria"]["allOf"] == []


@pytest.mark.parametrize("mode,status,children", [
    ("complete", "collected", 2), ("empty", "empty", 0),
    ("paginated", "collected", 2), ("error", "denied", 0),
    ("partial", "partial", 1),
])
def test_mysql_configurations_shared_and_subscription_scoped(mode, status, children):
    server_id = ROOT + "Microsoft.DBforMySQL/servers/mysql"
    server = {"id": server_id, "type": "Microsoft.DBforMySQL/servers", "properties": {"sslEnforcement": "Enabled"}}
    configs = [{"id": server_id + "/configurations/" + name, "type": "Microsoft.DBforMySQL/servers/configurations", "name": name,
                "properties": {"value": value}} for name, value in
               (("audit_log_enabled", "ON"), ("audit_log_events", "CONNECTION"))]
    def response(query):
        if mode == "error":
            return ReadError(403)
        if mode == "empty":
            return {"value": []}
        if "page" in query:
            return ReadError(403) if mode == "partial" else {"value": [configs[1]]}
        return {"value": [configs[0]], "nextLink": azure.ARM + server_id + "/configurations?page=2"} if mode in ("paginated", "partial") else {"value": configs}
    snapshot, _ = collect(["mysql_single_configuration"], {
        endpoint("mysql_single_server"): {"value": [server]}, server_id: server,
        server_id + "/configurations": response,
    })
    parent = rows(snapshot, "mysql_single_server")["items"][0]
    result = rows(snapshot, "mysql_single_configuration")
    assert parent["_coverage"]["configurations"]["status"] == status
    assert len(result["items"]) == children
    assert result["status"] == ("partial" if status == "partial" else "denied" if status == "denied" else "collected" if children else "empty")
    assert all(row["parent_id"] == server_id for row in result["items"])


def test_bot_full_get_omission_and_unresolved_key_collection():
    rid = ROOT + "Microsoft.BotService/botServices/bot"
    bot = {"id": rid, "sku": {"name": "S1"}, "properties": {"isCmekEnabled": False}}
    snapshot, _ = collect(["bot_service", "bot_cmk_key"], {
        endpoint("bot_service"): {"value": [{"id": rid}]}, rid: bot,
    })
    row = rows(snapshot, "bot_service")["items"][0]
    assert row["_provenance"]["source_operation"] == "botServices/get"
    assert row["properties"]["_coverage"]["cmekKeyVaultUrl"] == {"status": "empty"}
    assert rows(snapshot, "bot_cmk_key")["status"] == "not_collected"


@pytest.mark.parametrize("kind", ["mongo_cluster", "azure_firewall"])
def test_simple_arm_inventory_pages_and_partial(kind):
    path = endpoint(kind)
    resource_type = azure.ENDPOINTS[kind][0]
    first = {"id": ROOT + resource_type + "/first", "properties": {}}
    second = {"id": ROOT + resource_type + "/second", "properties": {}}
    def pages(query):
        return {"value": [second]} if "page" in query else {"value": [first], "nextLink": azure.ARM + path + "?page=2"}
    # Full-GET kinds read each listed resource natively after the list page.
    details = {row["id"]: row for row in (first, second)} if kind in azure.FULL_GET_KINDS else {}
    snapshot, _ = collect([kind], {path: pages, **details})
    assert rows(snapshot, kind)["status"] == "collected"
    assert len(rows(snapshot, kind)["items"]) == 2
    snapshot, _ = collect([kind], {path: lambda query: ReadError(403) if "page" in query else pages(query), **details})
    assert rows(snapshot, kind)["status"] == "partial"


@pytest.mark.parametrize("mode,status,count", [
    ("complete", "collected", 1), ("empty", "empty", 0),
    ("paginated", "collected", 2), ("error", "denied", 0),
    ("partial", "partial", 1),
])
def test_aks_defender_pricing_complete_pair_and_parent_pages(mode, status, count):
    path = endpoint("aks_cluster")
    clusters = [{"id": ROOT + "Microsoft.ContainerService/managedClusters/" + name, "type": "Microsoft.ContainerService/managedClusters",
                 "properties": {"kubernetesVersion": "1.30.1"}} for name in ("one", "two")]
    def list_response(query):
        if mode == "error":
            return ReadError(403)
        if mode == "empty":
            return {"value": []}
        if "page" in query:
            return ReadError(403) if mode == "partial" else {"value": [clusters[1]]}
        return {"value": [clusters[0]], "nextLink": azure.ARM + path + "?page=2"} if mode in ("partial", "paginated") else {"value": [clusters[0]]}
    routes = {path: list_response, **{row["id"]: row for row in clusters}}
    for cluster in clusters:
        for name in ("Containers", "CloudPosture"):
            pid = cluster["id"] + "/providers/Microsoft.Security/pricings/" + name
            routes[pid] = {"id": pid, "name": name, "properties": {"pricingTier": "Standard", "inherited": "False", "extensions": []}}
    snapshot, _ = collect(["defender_pricing"], routes)
    pricing = rows(snapshot, "defender_pricing")
    assert pricing["status"] == status
    assert len(pricing["items"]) == count
    for row in pricing["items"]:
        assert len(row["plans"]) == 2
        assert row["_provenance"]["effective_scope"] == row["id"]


def test_vm_instance_view_current_patch_summary_and_denial():
    rid = ROOT + "Microsoft.Compute/virtualMachines/vm"
    vm = {"id": rid, "type": "Microsoft.Compute/virtualMachines", "properties": {"storageProfile": {}}}
    routes = {endpoint("vm"): {"value": [vm]}, rid: vm,
              rid + "/instanceView": {"patchStatus": {"availablePatchSummary": {
                  "status": "Succeeded", "criticalAndSecurityPatchCount": 0}}}}
    snapshot, _ = collect(["vm"], routes)
    row = rows(snapshot, "vm")["items"][0]
    assert row["_coverage"]["instanceView"]["status"] == "collected"
    assert row["instanceView"]["patchStatus"]["availablePatchSummary"]["status"] == "Succeeded"
    routes[rid + "/instanceView"] = ReadError(403)
    snapshot, _ = collect(["vm"], routes)
    row = rows(snapshot, "vm")["items"][0]
    assert row["_coverage"]["instanceView"]["status"] == "denied"
    assert "instanceView" not in row


@pytest.mark.parametrize("mode,status,count", [
    ("complete", "collected", 1), ("empty", "empty", 0),
    ("paginated", "collected", 2), ("error", "denied", 0),
    ("partial", "partial", 1),
])
def test_diagnostic_category_child_and_consolidated_coverage(mode, status, count):
    gateway_id = ROOT + "Microsoft.Network/applicationGateways/gateway"
    base = gateway_id + "/providers/Microsoft.Insights/diagnosticSettingsCategories"
    values = [{"id": base + "/" + name, "name": name,
               "properties": {"categoryType": "Logs", "categoryGroups": ["allLogs"]}}
              for name in ("ApplicationGatewayAccessLog", "ApplicationGatewayFirewallLog")]
    def category_pages(query):
        if mode == "error":
            return ReadError(403)
        if mode == "empty":
            return {"value": []}
        if "page" in query:
            return ReadError(403) if mode == "partial" else {"value": [values[1]]}
        return {"value": [values[0]], "nextLink": azure.ARM + base + "?page=2"} if mode in ("paginated", "partial") else {"value": [values[0]]}
    snapshot, _ = collect(["diagnostic_category"], {
        endpoint("application_gateway"): {"value": [{"id": gateway_id, "type": "Microsoft.Network/applicationGateways", "properties": {}}]},
        base: category_pages,
    })
    parent = rows(snapshot, "application_gateway")["items"][0]
    assert parent["_coverage"]["diagnosticCategories"]["status"] == status
    categories = rows(snapshot, "diagnostic_category")
    assert categories["status"] == ("partial" if status == "partial" else "denied" if status == "denied" else "collected" if count else "empty")
    assert len(categories["items"]) == count
    assert all(row["parent_id"] == gateway_id and row["resourceId"] == gateway_id for row in categories["items"])
    assert all(row["categoryType"] == "Logs" and row["categoryGroups"] == ["allLogs"] for row in categories["items"])


def test_storage_event_subscriptions_and_mysql_flexible_admins_reuse_embedded_reader():
    account_id = ROOT + "Microsoft.Storage/storageAccounts/store"
    mysql_id = ROOT + "Microsoft.DBforMySQL/flexibleServers/mysql"
    event_id = account_id + "/providers/Microsoft.EventGrid/eventSubscriptions/sub"
    admin_id = mysql_id + "/administrators/admin"
    snapshot, _ = collect(["storage_account", "mysql_flexible_server"], {
        endpoint("storage_account"): {"value": [{"id": account_id, "type": "Microsoft.Storage/storageAccounts", "properties": {}}]},
        account_id: {"id": account_id, "type": "Microsoft.Storage/storageAccounts", "properties": {}},
        account_id + "/providers/Microsoft.EventGrid/eventSubscriptions": {"value": [
            {"id": event_id, "properties": {"provisioningState": "Succeeded"}}]},
        endpoint("mysql_flexible_server"): {"value": [{"id": mysql_id, "type": "Microsoft.DBforMySQL/flexibleServers", "properties": {"authConfig": {"activeDirectoryAuth": "Enabled"}}}]},
        mysql_id + "/administrators": {"value": [{"id": admin_id, "type": "Microsoft.DBforMySQL/flexibleServers/administrators", "name": "admin", "properties": {"principalId": "user-a"}}]},
    })
    storage = rows(snapshot, "storage_account")["items"][0]
    mysql = rows(snapshot, "mysql_flexible_server")["items"][0]
    assert storage["_coverage"]["eventSubscriptions"]["status"] == "collected"
    assert storage["eventSubscriptions"][0]["properties"]["provisioningState"] == "Succeeded"
    assert mysql["_coverage"]["administrators"]["status"] == "collected"
    assert mysql["administrators"][0]["properties"]["principalId"] == "user-a"


def test_cosmos_supported_categories_and_group_resolution_from_same_read():
    rid = ROOT + "Microsoft.DocumentDB/databaseAccounts/cosmos"
    base = rid + "/providers/Microsoft.Insights/diagnosticSettingsCategories"
    setting = rid + "/providers/Microsoft.Insights/diagnosticSettings/export"
    snapshot, _ = collect(["cosmos_account", "diagnostic_setting", "diagnostic_category"], {
        SCOPE + "/resources": {"value": [{"id": rid, "type": "Microsoft.DocumentDB/databaseAccounts"}]},
        endpoint("cosmos_account"): {"value": [{"id": rid, "type": "Microsoft.DocumentDB/databaseAccounts", "properties": {"capabilities": [{"name": "EnableMongo"}]}}]},
        base: {"value": [{"id": base + "/MongoRequests", "name": "MongoRequests",
                          "properties": {"categoryType": "Logs", "categoryGroups": ["allLogs"]}}]},
        rid + "/providers/Microsoft.Insights/diagnosticSettings": {"value": [{"id": setting,
            "properties": {"logs": [{"categoryGroup": "allLogs", "enabled": True}],
                           "workspaceId": ROOT + "Microsoft.OperationalInsights/workspaces/ws"}}]},
    })
    cosmos = rows(snapshot, "cosmos_account")["items"][0]
    assert cosmos["supported_log_categories"] == ["MongoRequests"]
    assert cosmos["diagnosticSettings"][0]["properties"]["logs"][0]["resolvedCategories"] == ["MongoRequests"]


def test_databox_expanded_get_purview_region_and_metric_alert_inventory():
    job_id = ROOT + "Microsoft.DataBox/jobs/job"
    purview_id = ROOT + "Microsoft.Purview/accounts/purview"
    metric_id = ROOT + "Microsoft.Insights/metricAlerts/alert"
    job = {"id": job_id, "sku": {"name": "DataBox"}, "properties": {"details": {"preferences": {"encryptionPreferences": {"doubleEncryption": "Enabled"}}}}}
    purview = {"id": purview_id, "location": "WestEurope", "properties": {"provisioningState": "Succeeded"}}
    metric = {"id": metric_id, "properties": {"enabled": True, "scopes": [job_id], "actions": []}}
    snapshot, fixture = collect(["databox_job", "purview_account", "metric_alert"], {
        endpoint("databox_job"): {"value": [{"id": job_id}]}, job_id: job,
        endpoint("purview_account"): {"value": [{"id": purview_id}]}, purview_id: purview,
        endpoint("metric_alert"): {"value": [metric]},
    })
    collected_job = rows(snapshot, "databox_job")["items"][0]
    assert collected_job["_provenance"]["expand"] == "details"
    assert collected_job["_provenance"]["representation"] == "full"
    assert any("$expand=details" in call[0] for call in fixture.calls)
    assert rows(snapshot, "purview_account")["items"][0]["location"] == "westeurope"
    assert rows(snapshot, "metric_alert")["items"][0]["properties"]["actions"] == []


@pytest.mark.parametrize("mode,status,count", [
    ("complete", "collected", 1), ("empty", "empty", 0),
    ("paginated", "collected", 2), ("error", "denied", 0),
    ("partial", "partial", 1),
])
def test_shared_arm_resource_inventory(mode, status, count):
    path = SCOPE + "/resources"
    values = [{"id": ROOT + "Microsoft.Storage/storageAccounts/" + name,
               "type": "Microsoft.Storage/storageAccounts", "location": "westeurope",
               "tags": {"classification": "internal"}} for name in ("one", "two")]
    def pages(query):
        if mode == "error":
            return ReadError(403)
        if mode == "empty":
            return {"value": []}
        if "page" in query:
            return ReadError(403) if mode == "partial" else {"value": [values[1]]}
        return {"value": [values[0]], "nextLink": azure.ARM + path + "?page=2"} if mode in ("paginated", "partial") else {"value": [values[0]]}
    snapshot, fixture = collect(["azure_resource", "resource"], {path: pages})
    for kind in ("azure_resource", "resource"):
        assert (rows(snapshot, kind)["status"], len(rows(snapshot, kind)["items"])) == (status, count)
    assert sum(call[0].startswith(azure.ARM + path) for call in fixture.calls) == (2 if mode in ("paginated", "partial") else 1)


def test_backup_jobs_and_sql_restore_points_reuse_paged_embedded_children():
    vault_id = ROOT + "Microsoft.RecoveryServices/vaults/vault"
    sql_id = ROOT + "Microsoft.Sql/servers/server"
    db_id = sql_id + "/databases/db"
    job_id = vault_id + "/backupJobs/job"
    restore_id = db_id + "/restorePoints/point"
    ltr_path = SCOPE + "/providers/Microsoft.Sql/locations/eastus/longTermRetentionServers/server/longTermRetentionDatabases/db/longTermRetentionBackups"
    ltr_id = ltr_path + "/backup"
    snapshot, _ = collect(["backup_job", "sql_restore_point", "sql_ltr_backup"], {
        endpoint("recovery_vault"): {"value": [{"id": vault_id, "type": "Microsoft.RecoveryServices/vaults", "properties": {}}]},
        vault_id: {"id": vault_id, "type": "Microsoft.RecoveryServices/vaults", "properties": {}},
        endpoint("sql_server"): {"value": [{"id": sql_id, "type": "Microsoft.Sql/servers", "properties": {}}]},
        sql_id + "/databases": {"value": [{"id": db_id, "location": "eastus", "properties": {"status": "Online"}}]},
        vault_id + "/backupJobs": {"value": [{"id": job_id, "properties": {"status": "Completed", "protectedItemId": "item"}}]},
        db_id + "/restorePoints": {"value": [{"id": restore_id, "properties": {"restorePointCreationDate": "2026-01-01T00:00:00Z"}}]},
        ltr_path: {"value": [{"id": ltr_id, "type": azure_sql_ltr_native.NATIVE_TYPE,
                             "properties": {"serverName": "server", "databaseName": "db",
                                            "databaseDeletionTime": None, "backupStorageRedundancy": "Geo"}}]},
    })
    assert rows(snapshot, "backup_job")["items"][0]["parent_id"] == vault_id
    assert rows(snapshot, "sql_restore_point")["items"][0]["parent_id"] == db_id
    assert rows(snapshot, "sql_ltr_backup")["items"][0]["properties"]["backupStorageRedundancy"] == "Geo"


def test_managed_instance_databases_and_exact_tde_get_with_partial_coverage():
    mi_id = ROOT + "Microsoft.Sql/managedInstances/mi"
    db_id = mi_id + "/databases/db"
    tid = db_id + "/transparentDataEncryption/current"
    routes = {
        endpoint("mssql_managed_instance"): {"value": [{"id": mi_id, "properties": {}}]},
        mi_id + "/databases": {"value": [{"id": db_id, "properties": {"status": "Online"}}]},
        tid: {"id": tid, "properties": {"state": "Enabled"}},
    }
    snapshot, _ = collect(["managed_instance_tde"], routes)
    db = rows(snapshot, "managed_instance_database")["items"][0]
    assert db["parent_id"] == mi_id
    assert db["_coverage"]["transparentDataEncryption"]["status"] == "collected"
    assert rows(snapshot, "managed_instance_tde")["items"][0]["properties"]["state"] == "Enabled"
    routes[tid] = ReadError(403)
    snapshot, _ = collect(["managed_instance_tde"], routes)
    assert rows(snapshot, "managed_instance_tde")["status"] == "denied"
    assert rows(snapshot, "managed_instance_tde")["items"] == []


# Native current certificate metadata and service-specific token audiences.
from peaso.collectors import azure_swc as cert_inventory
"""Private native-reader to published-engine acceptance for the next batch."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from peaso.collectors.azure import _Reader, AzureReadError
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
CERT_SCOPE = '/subscriptions/sub-fixture'
CERT_VAULT_ID = CERT_SCOPE + '/resourceGroups/test/providers/Microsoft.KeyVault/vaults/vaultfixture'
CERT_ORIGIN = 'https://vaultfixture.vault.azure.net'
CERT_RSA_CHECK = 'azure_vault_3_7_1_2_532ecd2'
CERT_EXPIRY_CHECK = 'azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3'
CERT_NOW = datetime.now(timezone.utc)

def _cert_fixture_public(bits=2048, days=90, enabled=True):
    key = ec.generate_private_key(ec.SECP256R1()) if bits == 'EC' else rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture.invalid')])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(CERT_NOW - timedelta(days=1)).not_valid_after(CERT_NOW + timedelta(days=days)).sign(key, hashes.SHA256())
    return {'id': CERT_ORIGIN + '/certificates/cert/v1', 'cer': base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(), 'attributes': {'enabled': enabled, 'exp': int((CERT_NOW + timedelta(days=days)).timestamp())}, 'sid': 'discard', 'kid': 'discard', 'value': 'never-retain', 'tags': {'secret': 'never-retain'}}

def _cert_fixture_evaluate(*, current=None, mutate=None, options=None, parent_status='collected', empty=False):
    current = current if current is not None else _cert_fixture_public()
    reader = _Reader({'concurrency': 1, 'retries': 0, **(options or {})})
    reader.collections.append({'type': 'vault', 'scope': CERT_SCOPE, 'service': 'Microsoft.KeyVault', 'status': parent_status, 'items': [] if parent_status in ('empty', 'denied') else [{'id': CERT_VAULT_ID, 'properties': {'vaultUri': CERT_ORIGIN}}]})
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        if mutate:
            response = mutate(url)
            if response is not None:
                return response
        if url == CERT_ORIGIN + '/certificates?api-version=' + '2025-07-01':
            return {'value': [] if empty else [{'id': CERT_ORIGIN + '/certificates/cert'}]}
        assert url == CERT_ORIGIN + '/certificates/cert?api-version=' + '2025-07-01'
        return deepcopy(current)
    cert_inventory.collect_current_certificates(reader, request, [CERT_SCOPE])
    snapshot = make_snapshot('azure', [CERT_SCOPE], reader.collections, created_at=CERT_NOW.isoformat(), metadata={'compliance_policy': {'status': 'collected', 'scope': CERT_SCOPE, 'observed_at': CERT_NOW.isoformat(), 'max_age_seconds': 86400, 'parameters': {'expirationWithinDays': 30}}})
    report = evaluate_snapshot(snapshot, checks=[CERT_RSA_CHECK, CERT_EXPIRY_CHECK])
    statuses = {row['check_id']: row['status'] for row in report['findings']}
    return (statuses, reader, snapshot, calls)

@pytest.mark.parametrize('bits,days,enabled,rsa_status,expiry_status', [(2048, 90, True, 'PASS', 'PASS'), (1024, 90, True, 'FAIL', 'PASS'), (2048, 7, True, 'PASS', 'FAIL'), ('EC', 90, True, 'NOT_APPLICABLE', 'PASS'), (2048, 7, False, 'PASS', 'NOT_APPLICABLE')])
def test_native_current_certificate_to_engine(bits, days, enabled, rsa_status, expiry_status):
    statuses, reader, snapshot, calls = _cert_fixture_evaluate(current=_cert_fixture_public(bits, days, enabled))
    assert statuses == {CERT_RSA_CHECK: rsa_status, CERT_EXPIRY_CHECK: expiry_status}
    assert len(calls) == 2
    import json
    assert 'never-retain' not in json.dumps(snapshot)

@pytest.mark.parametrize('mode', ['denied', 'foreign', 'paging', 'parent_denied', 'call_limit', 'empty', 'duplicate'])
def test_incomplete_native_inventory_stays_unknown(mode):

    def mutate(url):
        if mode == 'denied':
            raise AzureReadError('denied', 403)
        if mode == 'foreign':
            return {'value': [{'id': 'https://foreign.vault.azure.net/certificates/cert'}]}
        if mode == 'paging' and '/certificates?' in url:
            return {'value': [], 'nextLink': url + '&page=2'}
        if mode == 'duplicate' and '/certificates?' in url:
            return {'value': [{'id': CERT_ORIGIN + '/certificates/cert'}] * 2}
    statuses, reader, _, _ = _cert_fixture_evaluate(mutate=mutate, options={'max_pages': 1} if mode == 'paging' else {'max_calls': 1} if mode == 'call_limit' else {}, parent_status='denied' if mode == 'parent_denied' else 'collected', empty=mode == 'empty')
    expected = 'NOT_APPLICABLE' if mode == 'empty' else 'DENIED' if mode == 'denied' else 'UNKNOWN'
    assert statuses == {CERT_RSA_CHECK: expected, CERT_EXPIRY_CHECK: expected}

@pytest.mark.parametrize('days,expected_expiry', [(90, 'PASS'), (7, 'FAIL')])
def test_actual_provider_and_bulk_policy_intake(days, expected_expiry):
    from peaso.collectors import azure
    from peaso.collectors.bulk_evidence import collect
    from types import SimpleNamespace
    from urllib.parse import urlsplit
    current = _cert_fixture_public(days=days)

    class Fixture:
        tenant = 'tenant-fixture'
        verified_tenant = 'tenant-fixture'

        def __init__(self):
            self.allowed = []

        def allow_vault(self, uri):
            self.allowed.append(uri)

        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            if body is not None:
                return {'data': []}
            if path == CERT_SCOPE + '/providers/Microsoft.KeyVault/vaults':
                return {'value': [{'id': CERT_VAULT_ID, 'type': 'Microsoft.KeyVault/vaults', 'properties': {'vaultUri': CERT_ORIGIN}}]}
            if path == '/certificates':
                return {'value': [{'id': CERT_ORIGIN + '/certificates/cert'}]}
            if path == '/certificates/cert':
                return deepcopy(current)
            return {'value': []}
    fixture = Fixture()
    module = SimpleNamespace(TYPES=azure.TYPES, collect=lambda connector, requirements: azure.collect(connector, requirements, transport=fixture))
    now = datetime.now(timezone.utc).isoformat()
    connector = {'provider': 'azure', 'scopes': ['sub-fixture'], 'auth': {'tenant_id': 'tenant-fixture'}, 'options': {'concurrency': 1, 'retries': 0, 'compliance_policy': {'status': 'collected', 'scope': CERT_SCOPE, 'observed_at': now, 'max_age_seconds': 3600, 'parameters': {'expirationWithinDays': 30}}}}
    snapshot = collect(module, connector, ['key_vault_certificate'])
    report = evaluate_snapshot(snapshot, checks=[CERT_RSA_CHECK, CERT_EXPIRY_CHECK])
    assert {r['check_id']: r['status'] for r in report['findings']} == {CERT_RSA_CHECK: 'PASS', CERT_EXPIRY_CHECK: expected_expiry}
    assert fixture.allowed == [CERT_ORIGIN]
    assert snapshot['metadata']['bulk_evidence']['unavailable_projections'] == []

"""Service-specific token audiences stay isolated in the private candidate."""
import base64
import json
from types import SimpleNamespace
import time
import pytest
from peaso.collectors.azure import AzureTransport, AzureReadError, ARM, GRAPH, VAULT, STORAGE
CERT_TENANT = 'tenant-fixture'
CERT_VAULT_AUDIENCE = 'cfa8b339-82a2-471a-a3c9-0fc0be7a4093'
CERT_GRAPH_AUDIENCE = '00000003-0000-0000-c000-000000000000'

def _cert_audience_client(audience, tenant=CERT_TENANT):
    claims = {'aud': audience, 'tid': tenant}
    token = 'e30.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.signature'

    class Credential:

        def get_token(self, scope):
            return SimpleNamespace(token=token, expires_on=time.time() + 3600)
    return AzureTransport({'method': 'client-secret', 'tenant_id': CERT_TENANT}, credential=Credential())

@pytest.mark.parametrize('requested', [ARM, GRAPH, VAULT, STORAGE])
@pytest.mark.parametrize('actual', [ARM, GRAPH, VAULT, STORAGE, CERT_VAULT_AUDIENCE, CERT_GRAPH_AUDIENCE, 'https://foreign.invalid'])
def test_exact_service_audience_matrix(requested, actual):
    client = _cert_audience_client(actual)
    accepted = actual == requested or (requested == VAULT and actual == CERT_VAULT_AUDIENCE) or (requested == GRAPH and actual == CERT_GRAPH_AUDIENCE)
    if accepted:
        assert client.token(requested)
    else:
        with pytest.raises(AzureReadError, match='token_audience_mismatch'):
            client.token(requested)

def test_native_guid_does_not_bypass_tenant():
    with pytest.raises(AzureReadError, match='tenant_mismatch'):
        _cert_audience_client(CERT_VAULT_AUDIENCE, 'foreign-tenant').token(VAULT)
