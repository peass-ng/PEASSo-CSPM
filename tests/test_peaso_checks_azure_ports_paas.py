"""Exact post-transfer PaaS predicates and pinned source truth fixtures."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_paas as ports
from peaso.checks.fixtures import CASES
from peaso.collectors.azure import collect, ENDPOINTS

REGISTRY = {check.id: check for check in CHECKS}
ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / "peaso/rulepacks/reviewed_azure_ports_paas.json").read_text())
SQL = {review["source_review"]["query_id"]: review["source_review"]["status_case_sql"] for review in REVIEWS.values()}


@pytest.mark.parametrize("query", ports.SOURCE_QUERIES, ids=str)
def test_native_and_pinned_cases_agree_on_independent_truth_rows(query):
    duckdb = pytest.importorskip("duckdb")
    cid = ports.SOURCE_QUERIES[query]
    case = re.sub(r"\b\w+\.(\w+)\b", r"\1", SQL[query])
    case = case.replace("c.id", "source_join_id")
    if "when id is null" in case:
        case = case.replace("when id is null", "when source_join_id is null")
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s+(is\s+not\s+null|=)", r"(\1) \2", case, flags=re.I)
    if "::bool" in case:
        case = case.replace("(parameters -> 'enableNoPublicIp' -> 'value')::bool", "CAST(parameters -> 'enableNoPublicIp' -> 'value' AS BOOLEAN)")
    for label, expected_source, expected_native in (("pass", "ok", "PASS"), ("fail", "alarm", "FAIL")):
        if query == "databricks_workspace_no_public_ip_enabled":
            sql = "SELECT " + case + " FROM (SELECT ?::JSON AS parameters)"
            values = [json.dumps({"enableNoPublicIp": {"value": label == "pass"}})]
        elif query == "databricks_workspace_deployed_in_custom_vnet":
            sql = "SELECT " + case + " FROM (SELECT ?::JSON AS parameters)"
            values = [json.dumps({"customVirtualNetworkId": {"value": "/network"}} if label == "pass" else {})]
        elif "private" in query:
            sql = "SELECT " + case + " FROM (SELECT ? AS source_join_id)"
            values = ["approved-resource-id" if label == "pass" else None]
        elif query == "cosmosdb_account_virtual_network_filter_enabled":
            sql = "SELECT " + case + " FROM (SELECT 'Enabled' AS public_network_access, ? AS is_virtual_network_filter_enabled)"
            values = ["true" if label == "pass" else "false"]
        else:
            sql = "SELECT " + case + " FROM (SELECT ? AS public_network_access)"
            values = ["Disabled" if label == "pass" else "Enabled"]
        with duckdb.connect(":memory:") as database:
            assert database.execute(sql, values).fetchone()[0] == expected_source
        item = copy.deepcopy(CASES[cid][label])
        original = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == expected_native
        assert item == original


@pytest.mark.parametrize("cid", ports.CHECK_IDS, ids=str)
def test_unavailable_or_malformed_fields_never_pass(cid):
    check = REGISTRY[cid]
    for item in ({}, None, [], {"collection_status": "denied"}, {"collection_status": "partial"}):
        assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_public_disabled_branch_does_not_need_unrelated_vnet_filter_and_missing_branch_is_unknown():
    check = REGISTRY[ports.SOURCE_QUERIES["cosmosdb_account_virtual_network_filter_enabled"]]
    assert check.evaluate({"properties": {"publicNetworkAccess": "Disabled"}}, {})[0] == "PASS"
    assert check.evaluate({"properties": {"publicNetworkAccess": "Enabled"}}, {})[0] == "UNKNOWN"


def test_private_endpoint_pending_and_malformed_states_do_not_pass():
    check = REGISTRY[ports.SOURCE_QUERIES["cosmosdb_account_uses_private_link"]]
    pending = {"properties": {"privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Pending"}}}]}}
    assert check.evaluate(pending, {})[0] == "FAIL"
    pending["properties"]["privateEndpointConnections"][0]["properties"]["privateLinkServiceConnectionState"]["status"] = "FutureState"
    assert check.evaluate(pending, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("kind", ["container_registry", "cosmos_account", "databricks_workspace", "kusto_cluster"])
def test_shared_new_paas_collection_is_authoritative_and_read_only(kind):
    calls = []
    class Metadata:
        tenant = "tenant"
        def request(self, url, body=None, audience=None):
            calls.append((url, body))
            if body:
                return {"data": []}
            rid = "/subscriptions/sub/resourceGroups/g/providers/" + ENDPOINTS[kind][0] + "/resource"
            if "/providers/Microsoft.Insights/diagnosticSettings?" in url:
                return {"value": []}
            item = {"id": rid, "type": ENDPOINTS[kind][0],
                    "properties": {"publicNetworkAccess": "Disabled"}}
            if url.split("?", 1)[0].endswith(rid):
                return item
            return {"value": [item]}
    snapshot = collect({"scopes": ["sub"]}, [kind], transport=Metadata())
    record = next(row for row in snapshot["collections"] if row["type"] == kind)
    assert record["status"] == "collected"
    # Discovery/list, per-resource diagnostics, registry child metadata and
    # registry network-rule metadata are distinct reads.
    assert len(calls) == (7 if kind == "container_registry" else 3)
    if kind == "container_registry":
        assert {url.split("?", 1)[0].rsplit("/", 1)[-1] for url, _ in calls if "/resource/" in url and "diagnosticSettings" not in url} == {"tokens", "scopeMaps", "cacheRules"}
        assert sum("/resource?api-version=2023-11-01-preview" in url for url, _ in calls) == 1
    assert sum("/providers/Microsoft.Insights/diagnosticSettings?" in url for url, _ in calls) == 1
    assert len({(url, repr(body)) for url, body in calls}) == len(calls)
    assert all(not any(operation in url.lower() for operation in ("listkeys", "getpassword", "regenerate", "create")) for url, _ in calls)
