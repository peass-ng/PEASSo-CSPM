"""Playwright workspace LIST projection and public data-plane assessment."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure, azure_swc
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.LoadTestService/playwrightWorkspaces/pw"


def _row(properties):
    raw = {"id": RID, "name": "pw", "type": "Microsoft.LoadTestService/playwrightWorkspaces",
           "properties": {**properties, "accessToken": "must-not-persist", "unknown": "must-not-persist"}}
    projected = azure_swc.list_detail(raw, "playwright_workspace")
    snap = make_snapshot("azure", [SCOPE], [
        {"type": "playwright_workspace", "scope": SCOPE,
         "service": "Microsoft.LoadTestService", "status": "collected", "items": [projected]},
    ])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "playwright_workspace"), projected


def test_public_workspace_and_token_mode_from_native_list():
    row, item = _row({"dataplaneUri": "https://pw.example.com/api", "localAuth": "Enabled",
                      "provisioningState": "Succeeded"})
    assert row.verdict() == "FAIL"
    assert row.addresses == ["pw.example.com"]
    assert item["properties"]["localAuth"] == "Enabled"
    assert "must-not-persist" not in str(item)
    assert azure.ENDPOINTS["playwright_workspace"] == (
        "Microsoft.LoadTestService/playwrightWorkspaces", "2025-09-01")


def test_missing_or_unready_endpoint_is_unknown():
    assert _row({"dataplaneUri": "https://pw.example.com", "localAuth": "Disabled",
                 "provisioningState": "Creating"})[0].verdict() == "UNKNOWN"
    assert _row({"dataplaneUri": "http://pw.example.com", "localAuth": "Disabled",
                 "provisioningState": "Succeeded"})[0].verdict() == "UNKNOWN"
