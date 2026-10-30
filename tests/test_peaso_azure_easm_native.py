"""Source-bound private main planner, snapshot, and real engine fixtures."""
from pathlib import Path

import pytest

from peaso.engine import evaluate_snapshot

HERE = Path(__file__).resolve().parent
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RID = SCOPE + "/resourceGroups/rg/providers/Microsoft.Easm/workspaces/easm1"
URL = "https://management.azure.com" + SCOPE + "/providers/Microsoft.Easm/workspaces?api-version=2023-04-01-preview"
ARG = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
DIAG = "https://management.azure.com" + RID + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"


from peaso.checks import azure_easm_native as CHECK
from peaso.collectors import azure as COLLECT
from peaso.checks import next_group_easm_fixtures as FRAGMENT


class FakeTransport:
    tenant = "00000000-0000-0000-0000-000000000002"
    verified_tenant = True

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def request(self, url, *, body=None, audience=None):
        self.calls.append(url)
        if url == ARG:
            return {"data": []}
        if url == DIAG:
            return {"value": []}
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


def workspace(state="Succeeded", rid=RID):
    return {"id": rid, "type": "Microsoft.Easm/workspaces", "properties": {"provisioningState": state}}


def report(responses, *, options=None):
    transport = FakeTransport(responses)
    snapshot = COLLECT.collect({"scopes": [SCOPE], "options": {"inventories": ["easm_workspace"],
                              "concurrency": 1, "retries": 0, **(options or {})}, "auth": {}},
                             requirements=["easm_workspace"], transport=transport)
    outcome = evaluate_snapshot(snapshot, checks=[CHECK.EASM])
    findings = [f for f in outcome["findings"] if f["check_id"] == CHECK.EASM]
    coverage = [c for c in outcome["coverage"] if c.get("check_id") == CHECK.EASM]
    assert len(findings) == len(coverage) == 1
    return findings[0]["status"], coverage[0], transport.calls, snapshot


@pytest.mark.parametrize("rows,expected", [
    ([workspace()], "PASS"),
    ([workspace("Failed")], "FAIL"),
    ([], "FAIL"),
    ([workspace(None)], "UNKNOWN"),
    ([workspace("Unexpected")], "UNKNOWN"),
    ([workspace("Succeeded", SCOPE.replace("000000000001", "000000000099") + RID[len(SCOPE):])], "UNKNOWN"),
])
def test_main_planner_to_snapshot_to_engine(rows, expected):
    actual, coverage, calls, snapshot = report({URL: {"value": rows}})
    assert actual == expected
    assert calls.count(ARG) == calls.count(URL) == 1
    assert set(calls) <= {ARG, URL, DIAG}
    assert coverage["by_status"] == {expected: 1}
    assert "secretText" not in str(snapshot)


def test_pagination_and_limits():
    next_url = URL + "&$skiptoken=2"
    actual, _, calls, _ = report({URL: {"value": [], "nextLink": next_url}, next_url: {"value": [workspace()]}})
    assert actual == "PASS" and calls.count(ARG) == calls.count(URL) == calls.count(next_url) == 1
    assert set(calls) <= {ARG, URL, next_url, DIAG}
    actual, _, _, _ = report({URL: {"value": [], "nextLink": next_url}, next_url: {"value": [workspace()]}}, options={"max_pages": 1})
    assert actual == "UNKNOWN"


@pytest.mark.parametrize("response", [PermissionError("denied"), {"value": "bad"}, {"value": [workspace()], "nextLink": "https://evil.example/steal"}, {"value": [workspace(), workspace()]}])
def test_denied_malformed_untrusted_and_duplicate(response):
    actual, _, _, _ = report({URL: response})
    assert actual == "UNKNOWN"


def test_graph_projection_is_metadata_only_and_held_evaluator_conservative():
    raw = {"id": "11111111-1111-1111-1111-111111111111", "passwordCredentials": [{"keyId": "22222222-2222-2222-2222-222222222222",
           "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2027-01-01T00:00:00Z", "secretText": "SECRET"}]}
    projected = COLLECT._metadata_only(raw)
    assert projected["passwordCredentials"] == [{"keyId": raw["passwordCredentials"][0]["keyId"],
        "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2027-01-01T00:00:00Z"}]
    assert "SECRET" not in str(projected)
    from peaso.checks import CHECKS
    admitted = [check for check in CHECKS if check.id == "azure.other.entra_app_secret_age_90"]
    assert len(admitted) == 1
    from peaso.checks import evaluate_check
    assert evaluate_check(admitted[0].id, {}, {})[0] == "UNKNOWN"


def test_private_central_fixture_contract_and_immutability():
    from copy import deepcopy
    from peaso.checks import evaluate_check
    cases = FRAGMENT.CASES_FRAGMENT[CHECK.EASM]
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN")):
        item, index = deepcopy(cases[name]), deepcopy(cases[name + "_index"])
        prior_item, prior_index = deepcopy(item), deepcopy(index)
        assert evaluate_check(CHECK.EASM, item, index)[0] == expected
        assert item == prior_item and index == prior_index
    assert evaluate_check(CHECK.EASM, cases["missing"], {})[0] == "UNKNOWN"
    assert evaluate_check(CHECK.EASM, cases["malformed"], {})[0] == "UNKNOWN"
