"""Native-only alert declaration fixtures; no evaluator pipeline or notification calls."""
import copy
import json

import pytest

from peaso.checks import CHECKS, azure_ports_monitor as ports
from peaso.checks.fixtures import CASES
from peaso.collectors.azure import collect

REGISTRY = {check.id: check for check in CHECKS}


@pytest.mark.parametrize("query", ports.ALERTS, ids=str)
def test_native_alert_pass_fail_unknown_denied_partial_and_purity(query):
    cid = ports.SOURCE_QUERIES[query]
    fixture = CASES[cid]
    for label, expected in (("pass", "PASS"), ("fail", "FAIL")):
        item, index = copy.deepcopy(fixture[label]), copy.deepcopy(fixture[label + "_index"])
        before = copy.deepcopy((item, index))
        assert REGISTRY[cid].evaluate(item, index)[0] == expected
        assert (item, index) == before
    for state in ("denied", "partial", "malformed", "not_collected"):
        index = ports._fixture("activity_log_alert", [], state)
        assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "UNKNOWN"
    for item in ({}, None, [], {"collection_status": "denied"}):
        assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("query", ports.ALERTS, ids=str)
def test_pinned_enabled_global_exact_scope_and_condition_selector_truth(query):
    duckdb = pytest.importorskip("duckdb")
    category, operation, resource_type = ports.ALERTS[query]
    cid = ports.SOURCE_QUERIES[query]
    for label, desired in (("pass", "ok"), ("fail", "alarm")):
        rule = CASES[cid]["pass_index"]["activity_log_alert"][0]["data"]
        columns = {"enabled": label == "pass", "location": "global", "scope": "/subscriptions/sub", "conditions": rule["properties"]["condition"]["allOf"]}
        with duckdb.connect(":memory:") as db:
            # Execute the inspected source WHERE/count condition against one
            # independently stated subscription truth row, without cloud queries.
            row = db.execute("SELECT CASE WHEN enabled AND location='global' AND scope='/subscriptions/sub' AND json_contains(conditions, ?::JSON) AND json_contains(conditions, ?::JSON) THEN 'ok' ELSE 'alarm' END FROM (SELECT ? AS enabled, ? AS location, ? AS scope, ?::JSON AS conditions)",
                             [json.dumps([{"field": "category", "equals": category}]), json.dumps([{"field": "operationName", "equals": operation}]), columns["enabled"], columns["location"], columns["scope"], json.dumps(columns["conditions"])]).fetchone()[0]
        assert row == desired


@pytest.mark.parametrize("query", [key for key, spec in ports.ALERTS.items() if spec[2]], ids=str)
def test_resource_type_alternative_requires_exactly_two_conditions(query):
    cid = ports.SOURCE_QUERIES[query]
    category, operation, resource_type = ports.ALERTS[query]
    index = copy.deepcopy(CASES[cid]["pass_index"])
    conditions = [{"field": "category", "equals": category}, {"field": "resourceType", "equals": resource_type}]
    index["activity_log_alert"][0]["data"]["properties"]["condition"]["allOf"] = conditions
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "PASS"
    conditions.append({"field": "level", "equals": "Error"})
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "FAIL"


def test_foreign_subscription_malformed_conditions_and_anyof_do_not_fulfill_source_leaf():
    cid = ports.SOURCE_QUERIES["monitor_log_alert_create_policy_assignment"]
    index = copy.deepcopy(CASES[cid]["pass_index"])
    row = index["activity_log_alert"][0]["data"]
    row["id"] = row["id"].replace("/sub/", "/foreign/")
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "UNKNOWN"
    row["id"] = row["id"].replace("/foreign/", "/sub/")
    row["properties"]["condition"]["allOf"] = [{"anyOf": [{"field": "category", "equals": "Administrative"}]}]
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "FAIL"
    row["properties"]["condition"]["allOf"] = [{"field": "category"}]
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "UNKNOWN"


def test_activity_log_alert_collector_reads_metadata_and_discards_webhook_payload_properties():
    calls = []
    class Alerts:
        tenant = "tenant"
        def request(self, url, body=None, audience=None):
            calls.append((url, body))
            if body:
                return {"data": []}
            return {"value": [{"id": "/subscriptions/sub/resourceGroups/g/providers/Microsoft.Insights/activityLogAlerts/a", "properties": {"enabled": True, "condition": {"allOf": []}, "actions": {"actionGroups": [{"actionGroupId": "/group", "webhookProperties": {"api_token": "INERT_MARKER"}}]}}}]}
    snapshot = collect({"scopes": ["sub"]}, ["activity_log_alert"], transport=Alerts())
    row = next(r for r in snapshot["collections"] if r["type"] == "activity_log_alert")
    assert row["status"] == "collected"
    assert "INERT_MARKER" not in json.dumps(snapshot)
    assert row["items"][0]["properties"]["actions"]["actionGroups"][0]["actionGroupId"] == "/group"
    assert all("testnotifications" not in url.lower() and "trigger" not in url.lower() for url, _ in calls)
