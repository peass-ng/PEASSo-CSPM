"""Unavailable audit proof facts cannot establish missing Blob access logging."""
from copy import deepcopy
import pytest

from peaso.collectors import azure, collect_live
from peaso.engine import collect_snapshot
from tests.test_peaso_azure_audit_storage_history import requirements as historical_requirements, evaluate as historical_evaluate
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_audit_storage_native import API, SCOPE, SERVICE, options, native


def _assess(monkeypatch, field):
    api = API("absent")
    monkeypatch.setattr(azure, "AzureTransport", lambda auth: api)
    monkeypatch.setattr(azure, "AzureTransportExposure", lambda auth: api)
    connector = {"provider": "azure", "scopes": [SCOPE], "auth": {
        "method": "token", "arm_token": "inert", "storage_token": "inert"}, "options": options("absent")}
    captured = collect_live(connector, historical_requirements())
    account = next(c for c in captured["collections"] if c["type"] == "storage_account")["items"][0]
    row = next(c for c in captured["collections"] if c["type"] == native.KIND)["items"][0]
    if field == "parent_diagnostics":
        account.setdefault("_coverage", {})["serviceDiagnosticSettings"] = {"status": "denied"}
    elif field == "parent_analytics":
        account.setdefault("_coverage", {})["serviceAnalyticsLogging"] = {"status": "denied"}
    elif field == "parent_provenance":
        account.setdefault("_coverage", {})["_provenance"] = {"status": "denied"}
    elif field == "account_id":
        account.setdefault("_coverage", {})["id"] = {"status": "denied"}
    elif field == "native_api_version":
        account["_provenance"].setdefault("_coverage", {})["api_version"] = {"status": "denied"}
    elif field == "row_payload":
        row.setdefault("_coverage", {})["payload"] = {"status": "denied"}
    elif field == "payload_hash":
        row["payload"].setdefault("_coverage", {})["account_configuration_sha256"] = {"status": "denied"}
    elif field == "category_list":
        row["payload"].setdefault("_coverage", {})["categories"] = {"status": "denied"}
    elif field == "row_provenance":
        row.setdefault("_coverage", {})["_provenance"] = {"status": "denied"}
    elif field == "classification":
        row["_provenance"].setdefault("_coverage", {})["operator_classification"] = {"status": "denied"}
    elif field == "proof_complete":
        row["_provenance"].setdefault("_coverage", {})["category_pages_complete"] = {"status": "denied"}
    elif field == "category_type":
        row["payload"]["categories"][0].setdefault("_coverage", {})["categoryType"] = {"status": "denied"}
    elif field == "category_name":
        row["payload"]["categories"][0].setdefault("_coverage", {})["name"] = {"status": "denied"}
    elif field == "category_groups":
        categories = row["payload"]["categories"]
        for category in categories:
            category["categoryGroups"] = ["audit"] if category["name"] == "StorageRead" else []
        categories[1].setdefault("_coverage", {})["categoryGroups"] = {"status": "denied"}
        account["serviceDiagnosticSettings"]["blob"] = [{"id": SERVICE + "/providers/Microsoft.Insights/diagnosticSettings/logs",
            "properties": {"logs": [{"categoryGroup": "audit", "enabled": True}]}}]
        account["serviceDiagnosticSettings"]["_coverage"]["blob"]["status"] = "collected"
    else:
        raise AssertionError(field)
    row["payload"]["account_configuration_sha256"] = native.digest(native.projection(account))
    snapshot = make_snapshot("azure", [SCOPE], captured["collections"], created_at=captured["created_at"], metadata=captured["metadata"])
    before = deepcopy(snapshot)
    imported = collect_snapshot({"connector": {"provider": "azure", "scopes": [SCOPE], "options": {"snapshot": snapshot}}})
    findings = [f for f in historical_evaluate(imported) if f["check_id"] == native.CID]
    assert len(findings) == 1 and snapshot == before and imported == before and api.closed
    return findings[0]


@pytest.mark.parametrize("field", ["parent_diagnostics", "parent_analytics", "parent_provenance",
    "account_id", "native_api_version", "row_payload", "payload_hash", "category_list",
    "row_provenance", "classification", "proof_complete", "category_type", "category_name", "category_groups"])
def test_unreadable_proof_cannot_establish_absence(monkeypatch, field):
    assert _assess(monkeypatch, field)["status"] == "UNKNOWN"
