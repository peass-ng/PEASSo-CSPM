"""Real collector-shaped Logs evidence, strict failure and authority boundaries."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure
from peaso.collectors import azure_detection_telemetry as native
from peaso.snapshot import validate

SCOPE = "/subscriptions/00000000-1111-2222-3333-444444444444"
ROOT = SCOPE + "/resourceGroups/rg/providers/"
WORKSPACE = ROOT + "Microsoft.OperationalInsights/workspaces/security"
SOURCE = SCOPE
CUSTOMER = "11111111-2222-3333-4444-555555555555"
CID = "azure.other.attack_t1049"


def policy(*, dialect="sw11-v1", source=SOURCE, table="AzureActivity", cid=CID):
    req = {"workspace_id": WORKSPACE, "pattern_id": "primary"}
    if dialect == "sw11-v1":
        req["sources"] = [{"resource_id": source, "table": table, "lookback_seconds": 600}]
        return {"azure_attack_detection": {"status": "collected", "subscription_scope": SCOPE,
            "checks": {cid: {"requirements": [req]}}}}
    req.update(source_id=source, table=table, max_window_seconds=600)
    return {"sw12": {"status": "collected", "scope": SCOPE,
        "checks": {cid: {"requirements": [req]}}}}


class Failure(RuntimeError):
    status = 403


class Transport:
    tenant = "tenant"
    verified_tenant = "tenant"

    def __init__(self, *, mode="ok", source=SOURCE, table="AzureActivity"):
        self.mode, self.source, self.table, self.calls = mode, source, table, []
        self.operation = 'GetBlob' if table.startswith('Storage') else 'SecretGet' if table in ('AZKVAuditLogs', 'AzureDiagnostics') else 'Sign-in activity' if table == 'SigninLogs' else 'Microsoft.Compute/virtualMachines/read'

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        path = urlsplit(url).path
        if audience == azure.LOGS:
            if self.mode == "denied":
                raise Failure("SECRET_LOG_OR_TOKEN")
            start, end = map(datetime.fromisoformat, body["timespan"].split("/"))
            latest = (end - timedelta(seconds=30)).isoformat()
            response = {"tables": [{"name": "PrimaryResult", "columns": [
                {"name": name, "type": kind} for name, kind in
                [("event_count", "long"), ("last_ingested_at", "datetime"),
                 ("last_event_at", "datetime"), ("operations", "dynamic")]],
                "rows": [[1, latest, latest, [self.operation]]]}]}
            row = response["tables"][0]["rows"][0]
            if self.mode == "empty":
                row[:] = [0, None, None, []]
            elif self.mode == "partial":
                response["error"] = {"code": "PartialError", "message": "SECRET_LOG_OR_TOKEN"}
            elif self.mode == "boolean_count":
                row[0] = True
            elif self.mode == "future":
                row[1] = (end + timedelta(seconds=1)).isoformat()
            elif self.mode == "old":
                row[2] = (start - timedelta(seconds=1)).isoformat()
            elif self.mode == "extra_table":
                response["tables"].append(copy.deepcopy(response["tables"][0]))
            elif self.mode == "extra_row":
                response["tables"][0]["rows"].append(copy.deepcopy(row))
            elif self.mode == "missing_column":
                response["tables"][0]["columns"].pop()
            elif self.mode == "invalid_operations":
                row[-1] = [None]
            elif self.mode == "sensitive_operation":
                row[-1] = ["Bearer SECRET_LOG_OR_TOKEN", "valid.read"]
            return response
        if path.casefold() == WORKSPACE.casefold():
            return {"id": WORKSPACE if self.mode != "foreign_workspace" else WORKSPACE.replace("security", "foreign"),
                    "properties": {"customerId": CUSTOMER if self.mode != "bad_customer" else "../foreign"}}
        if "diagnosticsettings" in path.casefold():
            if self.mode == "diagnostics_denied":
                raise Failure("SECRET_LOG_OR_TOKEN")
            if self.mode == "disabled":
                return {"value": []}
            setting = {"id": path + "/logs",
                "properties": {"workspaceId": WORKSPACE, "logAnalyticsDestinationType": "Dedicated",
                    "logs": [{"enabled": True, "categoryGroup": "allLogs"}]}}
            if path.casefold().startswith('/providers/microsoft.aadiam/'):
                setting['properties']['logs'] = [{'enabled': True, 'category': 'SignInLogs' if self.table == 'SigninLogs' else 'AuditLogs'}]
            if self.table == 'AzureDiagnostics':
                setting['properties'].pop('logAnalyticsDestinationType')
            if self.mode == "foreign_diagnostic":
                setting["id"] = WORKSPACE + "/providers/Microsoft.Insights/diagnosticSettings/logs"
            if self.mode == "foreign_destination":
                setting["properties"]["workspaceId"] = WORKSPACE + "foreign"
            if self.mode == "partial_diagnostics":
                return {"value": [setting], "nextLink": url + "&page=2"} if "page=2" not in url else (_ for _ in ()).throw(Failure("SECRET_LOG_OR_TOKEN"))
            return {"value": [setting]}
        return {"value": []}


def collect(review=None, **kwargs):
    transport = Transport(**kwargs)
    snapshot = azure.collect({"scopes": [SCOPE], "options": {"retries": 0,
        "compliance_policy": policy() if review is None else review}}, [native.KIND], transport=transport)
    validate(snapshot)
    assert "SECRET_LOG_OR_TOKEN" not in json.dumps(snapshot)
    envelope = next(c for c in snapshot["collections"] if c["type"] == native.KIND)
    return envelope, transport, snapshot


def test_source_filtered_native_logs_and_separate_audience():
    envelope, transport, _ = collect()
    assert envelope["status"] == "collected"
    row, = envelope["items"]
    assert row["row_count"] == 1 and row["export_enabled"] and row["routing_verified"]
    assert row["id"] == "|".join((WORKSPACE.casefold(), SOURCE.casefold(), "AzureActivity"))
    calls = [c for c in transport.calls if c[2] == azure.LOGS]
    assert len(calls) == 1
    url, body, _ = calls[0]
    assert url == native.API + CUSTOMER + "/query"
    assert '_SubscriptionId =~ ' + json.dumps(SCOPE.rsplit('/', 1)[-1]) in body["query"]
    assert "summarize event_count=count()" in body["query"]
    assert "workspaces" not in body


@pytest.mark.parametrize("mode", ["partial", "boolean_count", "future", "old", "extra_table", "extra_row",
    "missing_column", "invalid_operations", "foreign_workspace", "bad_customer", "foreign_diagnostic"])
def test_malformed_or_partial_native_results_never_complete(mode):
    envelope, _, _ = collect(mode=mode)
    assert envelope["status"] not in ("collected", "empty")
    assert envelope["items"] == []


@pytest.mark.parametrize("mode", ["denied", "diagnostics_denied", "partial_diagnostics"])
def test_permission_failures_are_unavailable(mode):
    envelope, _, _ = collect(mode=mode)
    assert envelope["status"] == "denied" and envelope["items"] == []


def test_empty_success_is_a_measured_zero_not_missing_inventory():
    envelope, _, _ = collect(mode="empty")
    assert envelope["status"] == "collected"
    assert envelope["items"][0]["row_count"] == 0
    assert envelope["items"][0]["last_ingested_at"] is None


def test_no_policy_is_not_an_empty_or_complete_collection():
    envelope, transport, _ = collect({})
    assert envelope["status"] not in ("collected", "empty")
    assert not any(call[2] == azure.LOGS for call in transport.calls)


@pytest.mark.parametrize("bad", ["AzureActivity | take 1", "AzureActivity;print secret", "x()"])
def test_table_injection_rejected_before_logs_call(bad):
    envelope, transport, _ = collect(policy(table=bad))
    assert envelope["status"] not in ("collected", "empty")
    assert not any(call[2] == azure.LOGS for call in transport.calls)


@pytest.mark.parametrize("source", ["/subscriptions/other", SOURCE + "/../other", SOURCE + "/x?secret=1"])
def test_foreign_or_path_escape_sources_rejected(source):
    envelope, transport, _ = collect(policy(source=source))
    assert envelope["status"] not in ("collected", "empty")
    assert not any(call[2] == azure.LOGS for call in transport.calls)


def test_shared_queries_are_deduplicated_across_checks_and_dialects():
    review = policy()
    other = policy(cid="azure.other.attack_t1136")
    review["azure_attack_detection"]["checks"].update(other["azure_attack_detection"]["checks"])
    review.update(policy(dialect="sw12-v1", cid="azure.other.attack_t1546"))
    envelope, transport, _ = collect(review)
    assert envelope["status"] == "collected"
    assert len(envelope["items"]) == 2
    assert len([c for c in transport.calls if c[2] == azure.LOGS]) == 1
    assert {r["_provenance"]["contract"] for r in envelope["items"]} == native.CONTRACTS


def test_sensitive_operation_payload_is_dropped():
    envelope, _, _ = collect(policy(dialect="sw12-v1", cid="azure.other.attack_t1546"), mode="sensitive_operation")
    assert envelope["items"][0]["supported_operations"] == ["valid.read"]


def token(audience):
    payload = base64.urlsafe_b64encode(json.dumps({"aud": audience, "tid": "tenant"}).encode()).rstrip(b"=").decode()
    return "header." + payload + ".signature"


def test_direct_logs_token_must_have_the_logs_audience():
    good = azure.AzureTransport({"method": "token", "tenant_id": "tenant", "logs_token": token(azure.LOGS)})
    assert good.token(azure.LOGS) == good.auth["logs_token"]
    bad = azure.AzureTransport({"method": "token", "tenant_id": "tenant", "logs_token": token(azure.ARM)})
    with pytest.raises(azure.AzureReadError, match="token_audience_mismatch"):
        bad.token(azure.LOGS)


@pytest.mark.parametrize("url", ["https://evil.test/query", "http://api.loganalytics.azure.com/query",
    "https://api.loganalytics.azure.com:444/query", "https://user@api.loganalytics.azure.com/query",
    "https://api.loganalytics.azure.com/query#fragment"])
def test_logs_transport_rejects_other_origins_before_reading_credentials(url):
    transport = azure.AzureTransport({"method": "token", "logs_token": token(azure.LOGS)})
    with pytest.raises(azure.AzureReadError, match="untrusted_continuation"):
        transport.request(url, audience=azure.LOGS)


def engine_case(monkeypatch, cid, *, mode="ok", disabled_rule=False, dialect="sw11-v1", include_both=False,
                source_override=None, table="AzureActivity", verified_tenant=None, unrelated_unresolved=False):
    from peaso.collectors import collect_live
    from tests.archived_check_contract import evaluate_snapshot
    group = ROOT + "Microsoft.Insights/actionGroups/response"
    rule = ROOT + "Microsoft.Insights/scheduledQueryRules/detection"
    source = source_override or (ROOT + "Microsoft.Compute/virtualMachines/host" if dialect == "sw12-v1" else SOURCE)
    operation = Transport(table=table).operation
    query = table + ' | where OperationName == ' + json.dumps(operation)
    condition = {"query": query, "timeAggregation": "Count", "operator": "GreaterThan", "threshold": 0,
        "failingPeriods": {"numberOfEvaluationPeriods": 1, "minFailingPeriodsToAlert": 1}, "dimensions": []}
    signature = {key: value for key, value in condition.items() if key != "query"}
    signature.update(metricMeasureColumn=None, resourceIdColumn=None)
    digest = hashlib.sha256(query.encode()).hexdigest()
    review = policy(dialect=dialect, source=source, table=table, cid=cid)
    if dialect == "sw11-v1":
        req = review["azure_attack_detection"]["checks"][cid]["requirements"][0]
        req.update(scope_ids=[WORKSPACE], approved_action_group_ids=[group], required_fragments=[query],
            max_notification_delay_seconds=600, queries=[{"sha256": digest,
                "normalization": "sha256-kql-text-v1", "semantics_reviewed": True, "fully_resolved": True,
                "effective_workspace_ids": [WORKSPACE], "source_tables": [table],
                "evaluationFrequency": "PT5M", "windowSize": "PT5M", "max_lookback_seconds": 600,
                "trigger_semantics_reviewed": True, "trigger": signature, "max_trigger_delay_seconds": 300}])
    else:
        root = review["sw12"]
        root.update(observed_at=datetime.now(timezone.utc).isoformat(), max_age_seconds=3600)
        check = root["checks"][cid]
        check.update(queryNormalization="kql-lf-trim-v1", requiredWorkspaceIds=[WORKSPACE], requiredActionGroupIds=[group])
        check["requirements"][0].update(semantics_reviewed=True, trigger_semantics_reviewed=True,
            requiredQueryFragments=[query], approvedCriteria=[[{**signature, "query_sha256": digest}]],
            min_window_seconds=300, max_frequency_seconds=300, max_notification_delay_seconds=600,
            required_operations=[operation])
        if cid.endswith(('attack_t1537', 'attack_t1619')):
            check['requirements'][0]['max_ingestion_age_seconds'] = 600
    if include_both:
        foreign = policy(dialect="sw12-v1" if dialect == "sw11-v1" else "sw11-v1", cid="azure.other.attack_t1546")
        review.update(foreign)
    if unrelated_unresolved:
        extra = copy.deepcopy(review['azure_attack_detection']['checks'][cid])
        extra['requirements'][0]['sources'][0]['table'] = 'CustomUnresolved_CL'
        extra['requirements'][0]['queries'][0]['source_tables'] = ['CustomUnresolved_CL']
        review['azure_attack_detection']['checks']['azure.other.attack_t1199'] = extra
    class EngineTransport(Transport):
        def close(self):
            self.closed = True

        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            self.closed = getattr(self, "closed", False)
            assert not self.closed, "Logs must run before credentials close"
            if path.casefold() == SCOPE.casefold():
                return {'id': SCOPE, 'tenantId': verified_tenant}
            if path == SCOPE + "/providers/Microsoft.Insights/scheduledQueryRules":
                return {"value": [{"id": rule, "kind": "LogAlert", "type": "Microsoft.Insights/scheduledQueryRules",
                    "properties": {"enabled": not disabled_rule, "scopes": [WORKSPACE],
                        "criteria": {"allOf": [condition]}, "evaluationFrequency": "PT5M", "windowSize": "PT5M",
                        "overrideQueryTimeRange": None, "muteActionsDuration": "PT0S", "actions": {"actionGroups": [group]}}}]}
            if path == SCOPE + "/providers/Microsoft.Insights/actionGroups" or path == group:
                row = {"id": group, "type": "Microsoft.Insights/actionGroups", "properties": {"enabled": True,
                    "webhookReceivers": [{"serviceUri": "https://secret.test/?credential=SECRET_LOG_OR_TOKEN"}]}}
                return {"value": [row]} if path.endswith("/actionGroups") else row
            if path == SCOPE + "/providers/Microsoft.OperationalInsights/workspaces":
                return {"value": [{"id": WORKSPACE, "type": "Microsoft.OperationalInsights/workspaces", "properties": {"customerId": CUSTOMER}}]}
            return super().request(url, body=body, audience=audience)
    transport = EngineTransport(mode=mode, table=table)
    if verified_tenant is not None:
        transport.tenant = transport.verified_tenant = verified_tenant
    monkeypatch.setattr(azure, "AzureTransportExposure", lambda auth: transport)
    snapshot = collect_live({"provider": "azure", "scopes": [SCOPE], "options": {"retries": 0,
        "compliance_policy": review}}, [native.KIND])
    assert transport.closed
    assert "SECRET_LOG_OR_TOKEN" not in json.dumps(snapshot)
    findings = evaluate_snapshot(snapshot, checks=[cid])["findings"]
    assert len(findings) == 1
    return findings[0]["status"]


@pytest.mark.parametrize("cid", ["azure.other.attack_t1049", "azure.other.attack_t1082", "azure.other.attack_t1087",
    "azure.other.attack_t1199", "azure.other.attack_t1491"])
def test_real_collector_and_engine_sw11_pass(monkeypatch, cid):
    assert engine_case(monkeypatch, cid) == "PASS"


@pytest.mark.parametrize("mode,disabled,expected", [("ok", True, "FAIL"), ("denied", False, "DENIED"),
    ("empty", False, "FAIL"), ("partial", False, "UNKNOWN")])
def test_real_collector_and_engine_failure_boundaries(monkeypatch, mode, disabled, expected):
    assert engine_case(monkeypatch, CID, mode=mode, disabled_rule=disabled) == expected


def test_real_collector_sw12_accepts_individually_attested_enabled_without_receiver_secrets(monkeypatch):
    assert engine_case(monkeypatch, "azure.other.attack_t1546", dialect="sw12-v1") == "PASS"


def test_receiver_enabled_does_not_manufacture_delivery_acknowledgement(monkeypatch):
    assert engine_case(monkeypatch, "azure.other.attack_t1136") == "UNKNOWN"


def test_two_typed_contracts_coexist_in_the_same_complete_inventory(monkeypatch):
    assert engine_case(monkeypatch, CID, include_both=True) == "PASS"


@pytest.mark.parametrize('cid,table', [('azure.other.attack_t1069', 'AuditLogs'),
    ('azure.other.attack_t1201', 'AuditLogs'), ('azure.other.attack_t1110', 'SigninLogs')])
def test_native_tenant_feed_requires_real_subscription_authority_join(monkeypatch, cid, table):
    tenant = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    assert engine_case(monkeypatch, cid, table=table, source_override='/tenants/' + tenant,
                       verified_tenant=tenant) == 'PASS'


@pytest.mark.parametrize('cid', ['azure.other.attack_t1606', 'azure.other.attack_t1621'])
def test_native_sw12_tenant_signin_feed_is_bound_to_same_capture(monkeypatch, cid):
    tenant = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    assert engine_case(monkeypatch, cid, dialect='sw12-v1', table='SigninLogs',
                       source_override='/tenants/' + tenant, verified_tenant=tenant) == 'PASS'


@pytest.mark.parametrize('cid', ['azure.other.attack_t1562', 'azure.other.attack_t1578'])
def test_native_sw12_activity_feed_has_true_resource_to_subscription_export_join(monkeypatch, cid):
    assert engine_case(monkeypatch, cid, dialect='sw12-v1') == 'PASS'


@pytest.mark.parametrize('cid,dialect', [('azure.other.attack_t1119', 'sw11-v1'),
    ('azure.other.attack_t1213', 'sw11-v1'), ('azure.other.attack_t1537', 'sw12-v1')])
def test_native_storage_parent_to_blob_service_join(monkeypatch, cid, dialect):
    assert engine_case(monkeypatch, cid, dialect=dialect, table='StorageBlobLogs',
        source_override=ROOT + 'Microsoft.Storage/storageAccounts/sensitive') == 'PASS'


def test_native_keyvault_legacy_diagnostic_route(monkeypatch):
    assert engine_case(monkeypatch, 'azure.other.attack_t1651', dialect='sw12-v1', table='AzureDiagnostics',
        source_override=ROOT + 'Microsoft.KeyVault/vaults/sensitive') == 'PASS'


def test_current_disabled_export_is_measured_instead_of_inferred_from_no_events(monkeypatch):
    assert engine_case(monkeypatch, 'azure.other.attack_t1213', table='StorageBlobLogs', mode='disabled',
        source_override=ROOT + 'Microsoft.Storage/storageAccounts/sensitive') == 'FAIL'


def test_unrelated_unresolved_source_cannot_poison_an_independently_measured_detection(monkeypatch):
    assert engine_case(monkeypatch, CID, unrelated_unresolved=True) == 'PASS'


def test_tenant_source_without_verified_credential_cannot_make_a_query():
    envelope, transport, _ = collect(policy(source='/tenants/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', table='AuditLogs'))
    assert envelope['status'] not in ('collected', 'empty')
    assert not any(c[2] == azure.LOGS for c in transport.calls)


@pytest.mark.parametrize('table', ['StorageBlobLogs', 'AZKVAuditLogs', 'FunctionAppLogs'])
def test_cannot_route_resource_events_through_a_tenant_diagnostic_setting(table):
    assert native._route([], '/providers/microsoft.aadiam', WORKSPACE.casefold(), table) == (None, [])
