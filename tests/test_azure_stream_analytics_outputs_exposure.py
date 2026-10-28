"""Configured Stream Analytics sinks and credential-free collector evidence."""

from peaso.analysis.internet_exposure import assess
from peaso.collectors import azure
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.StreamAnalytics/streamingjobs/job"
OWNER = "00000000-0000-0000-0000-000000000010"
FOREIGN = "00000000-0000-0000-0000-000000000020"


def _output(tenant=FOREIGN):
    return {"id": RID + "/outputs/lake", "type": "Microsoft.StreamAnalytics/streamingjobs/outputs",
            "properties": {"datasource": {"type": "Microsoft.DataLake/Accounts",
                                          "properties": {"tenantId": tenant, "accountName": "lake",
                                                         "apiKey": "must-never-persist", "password": "secret"}}}}


def _evaluate(response, owner=OWNER):
    parent = {"id": RID, "type": "Microsoft.StreamAnalytics/streamingjobs",
              "properties": {"jobState": "Running"}}
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return response

    azure._embed(azure._Reader({}), request, [("stream_analytics_job", parent)],
                 skip=("diagnosticSettings",))
    snap = make_snapshot("azure", [SCOPE], [{"type": "stream_analytics_job", "scope": SCOPE,
        "service": "Microsoft.StreamAnalytics", "status": "collected", "items": [parent]}],
        metadata={"tenant_id": owner, "tenant_verified": True})
    row = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "stream_analytics_job")
    return row, parent, calls


def test_foreign_tenant_output_detected_without_credentials():
    row, parent, calls = _evaluate({"value": [_output()]})
    assert row.verdict() == "FAIL"
    assert row.external_ids == [RID + "/outputs/lake"]
    assert calls == ["https://management.azure.com" + RID + "/outputs?api-version=2020-03-01"]
    assert "must-never-persist" not in str(parent) and "secret" not in str(parent)


def test_output_absence_same_tenant_and_incomplete_list():
    assert _evaluate({"value": []})[0].verdict() == "PASS"
    assert _evaluate({"value": [_output(OWNER)]})[0].verdict() == "UNKNOWN"
    assert _evaluate({"bad": []})[0].verdict() == "UNKNOWN"


def test_foreign_child_identity_rejected():
    row = _output()
    row["id"] = RID + "/inputs/foreign"
    assert _evaluate({"value": [row]})[0].verdict() == "UNKNOWN"
