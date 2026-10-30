"""Public collect/evaluate path with stubbed APIM service diagnostics."""

from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, collect_live
from peaso.engine import plan_collection
from peaso.server.validation import validate_connector
from peaso.collectors import azure_apim_diagnostic_evidence_native as native
from peaso.collectors.azure_apim_diagnostic_evidence_native import CID, KIND

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
SERVICE = SCOPE + "/resourceGroups/rg/providers/Microsoft.ApiManagement/service/s"
API = SERVICE + "/apis/orders"
AI = SERVICE + "/loggers/ai"
MONITOR = SERVICE + "/loggers/monitor"


@pytest.mark.parametrize("service_kind,expected", [
    ("none", "FAIL"), ("ai", "UNKNOWN"),
    ("monitor", "FAIL"), ("zero_ai", "FAIL"),
    ("errors_ai", "UNKNOWN"), ("denied", "UNKNOWN"),
])
def test_service_diagnostic_effective_route(monkeypatch, service_kind, expected):
    parent = {"id": SERVICE, "type": "Microsoft.ApiManagement/service", "properties": {}}
    api = {"id": API, "properties": {"type": "http", "protocols": ["https"],
        "isCurrent": True, "apiRevision": "1"}}
    loggers = [{"id": AI, "properties": {"loggerType": "applicationInsights"}},
               {"id": MONITOR, "properties": {"loggerType": "azureMonitor"}}]
    logger = MONITOR if service_kind == "monitor" else AI
    sample = 0 if service_kind in ("zero_ai", "errors_ai") else 100
    always = "allErrors" if service_kind == "errors_ai" else None
    diagnostics = [] if service_kind in ("none", "denied") else [{
        "id": SERVICE + "/diagnostics/trace", "properties": {
            "loggerId": logger, "sampling": {"samplingType": "fixed", "percentage": sample},
            "alwaysLog": always}}]
    calls = []

    class Transport:
        tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

        def close(self):
            pass

        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            calls.append(path)
            assert audience == azure.ARM
            if path == "/providers/Microsoft.ResourceGraph/resources":
                return {"data": [], "resultTruncated": False}
            assert body is None
            if path == "/subscriptions":
                return {"value": [{"id": SCOPE, "subscriptionId": SCOPE.rsplit("/", 1)[1],
                    "tenantId": self.tenant, "state": "Enabled"}]}
            if path == SCOPE:
                return {"id": SCOPE, "subscriptionId": SCOPE.rsplit("/", 1)[1],
                    "tenantId": self.tenant, "state": "Enabled"}
            if path == SCOPE + "/providers/Microsoft.ApiManagement/service":
                return {"value": [deepcopy(parent)]}
            if path == SERVICE:
                return deepcopy(parent)
            if path == SERVICE + "/providers/Microsoft.Insights/diagnosticSettings":
                return {"value": []}
            if path == SERVICE + "/apis":
                return {"value": [deepcopy(api)]}
            if path == SERVICE + "/loggers":
                return {"value": deepcopy(loggers)}
            if path == SERVICE + "/diagnostics":
                if service_kind == "denied":
                    raise azure.AzureReadError("fixture_denied", 403)
                return {"value": deepcopy(diagnostics)}
            if path == API + "/revisions":
                return {"value": [{"apiId": API, "isOnline": True, "isCurrent": True}]}
            if path == API + "/diagnostics":
                return {"value": []}
            raise AssertionError("unexpected endpoint: " + path)

    monkeypatch.setattr(azure, "AzureTransport", lambda auth: Transport());monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: Transport())
    auth = {"method": "token", "arm_token": "inert-fixture"}
    options = {"concurrency": 1, "retries": 1}
    validate_connector("azure", auth, options, SimpleNamespace(auth_mode="cognito"))
    connector = {"provider": "azure", "scopes": [SCOPE], "auth": auth, "options": options}
    with pytest.raises(ValueError, match="requires external policy or manual evidence"):
        plan_collection({"connector": connector, "checks": [CID]})
    required = {"api_management", KIND}
    snapshot = collect_live(connector, required)
    inventories = {kind: {row["id"].casefold(): row for collection in snapshot["collections"]
                   if collection["type"] == kind for row in collection["items"]}
                   for kind in ("api_management", native.SOURCE, KIND)}
    status, _ = native.assess(SERVICE.casefold(), snapshot, inventories[KIND],
                              inventories[native.SOURCE], inventories["api_management"])
    assert status == expected
    assert calls.count(SERVICE + "/diagnostics") == 1
    evidence = next(c for c in snapshot["collections"] if c["type"] == KIND)
    for row in evidence["items"]:
        assert row["_coverage"]["loggerCredentialUsability"]["status"] == "not_collected"
