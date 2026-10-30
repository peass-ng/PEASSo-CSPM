"""Explicitly unreadable logging facts cannot prove a logging absence."""
from copy import deepcopy
import pytest
from peaso.collectors import azure, collect_live
from peaso.engine import collect_snapshot
from tests.test_peaso_azure_audit_storage_history import requirements as historical_requirements, evaluate as historical_evaluate
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_audit_storage_native import API, SCOPE, SERVICE, options, native


def assessed(monkeypatch, mutate):
    api=API("absent")
    monkeypatch.setattr(azure,"AzureTransport",lambda auth:api)
    # collect() builds AzureTransportExposure for owned native reads.
    monkeypatch.setattr(azure,"AzureTransportExposure",lambda auth:api)
    connector={"provider":"azure","scopes":[SCOPE],"auth":{"method":"token","arm_token":"inert","storage_token":"inert"},"options":options("absent")}
    captured=collect_live(connector,historical_requirements())
    account=next(c for c in captured["collections"] if c["type"]=="storage_account")["items"][0]
    account["serviceAnalyticsLogging"]["blob"].update(dict.fromkeys(native.OPERATIONS,True))
    mutate(account)
    evidence=next(c for c in captured["collections"] if c["type"]==native.KIND)["items"][0]
    evidence["payload"]["account_configuration_sha256"]=native.digest(native.projection(account))
    snapshot=make_snapshot("azure",[SCOPE],captured["collections"],created_at=captured["created_at"],metadata=captured["metadata"])
    before=deepcopy(snapshot)
    imported=collect_snapshot({"connector":{"provider":"azure","scopes":[SCOPE],"options":{"snapshot":snapshot}}})
    rows=[f for f in historical_evaluate(imported) if f["check_id"]==native.CID]
    assert len(rows)==1 and snapshot==before and imported==before
    assert api.closed
    return rows[0]


@pytest.mark.parametrize("operation",native.OPERATIONS)
def test_denied_legacy_operation_does_not_prove_logging_absence(monkeypatch,operation):
    def mutate(account):
        state=account["serviceAnalyticsLogging"]["blob"]
        state[operation]=False
        state["_coverage"]={operation:{"status":"denied"}}
    assert assessed(monkeypatch,mutate)["status"]=="UNKNOWN"


def test_known_logging_absence_survives_unreadable_other_legacy_operation(monkeypatch):
    def mutate(account):
        state=account["serviceAnalyticsLogging"]["blob"]
        state["read"]=False
        state["_coverage"]={"write":{"status":"denied"}}
    row=assessed(monkeypatch,mutate)
    assert row["status"]=="FAIL" and row["evidence"]["missing_blob_access_log_operations"]==["read"]


def test_all_configured_legacy_operations_still_do_not_prove_delivery(monkeypatch):
    assert assessed(monkeypatch,lambda account:None)["status"]=="UNKNOWN"


@pytest.mark.parametrize("field",["enabled","category","categoryGroup","logs","id"])
def test_unreadable_diagnostic_selector_cannot_prove_missing_read_logging(monkeypatch,field):
    def mutate(account):
        account["serviceAnalyticsLogging"]["blob"]["read"]=False
        entry={"category":"StorageRead","enabled":False}
        setting={"id":SERVICE+"/providers/Microsoft.Insights/diagnosticSettings/logs","properties":{"logs":[entry]}}
        if field=="categoryGroup":
            entry.pop("category")
            entry["categoryGroup"]="allLogs"
        target=setting if field=="id" else setting["properties"] if field=="logs" else entry
        target["_coverage"]={field:{"status":"denied"}}
        diagnostics=account["serviceDiagnosticSettings"]
        diagnostics["blob"]=[setting]
        diagnostics["_coverage"]["blob"]["status"]="collected"
    assert assessed(monkeypatch,mutate)["status"]=="UNKNOWN"
