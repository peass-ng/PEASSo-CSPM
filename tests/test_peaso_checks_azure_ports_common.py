"""Differential source checks for exact common-predicate reuse and conjunctions."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_common
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / "peaso/rulepacks/reviewed_azure_ports_common.json").read_text())
REGISTRY = {check.id: check for check in CHECKS}
QUERIES = {}
for row in REVIEWS.values():
    QUERIES[row["source_review"]["query_id"]] = row

TRUTH = {
    "keyvault_vault_recoverable": ({"soft_delete_enabled": True, "purge_protection_enabled": True}, {"soft_delete_enabled": True, "purge_protection_enabled": False}),
    "storage_account_trusted_microsoft_services_enabled": ({"network_rule_bypass": "Logging,AzureServices"}, {"network_rule_bypass": "Logging,Metrics"}),
    "storage_account_secure_transfer_required_enabled": ({"enable_https_traffic_only": True}, {"enable_https_traffic_only": False}),
    "storage_account_default_network_access_rule_denied": ({"network_rule_default_action": "Deny"}, {"network_rule_default_action": "Allow"}),
    "sql_server_auditing_on": ({"audit": {"properties": {"state": "Enabled"}}}, {"audit": {"properties": {"state": "Disabled"}}}),
    "sql_database_transparent_data_encryption_enabled": ({"transparent_data_encryption": {"state": "Enabled"}}, {"transparent_data_encryption": {"state": "Disabled"}}),
    "sql_server_auditing_retention_period_90": ({"audit": {"properties": {"retentionDays": 0}}}, {"audit": {"properties": {"retentionDays": 30}}}),
    "appservice_web_app_use_https": ({"https_only": True}, {"https_only": False}),
    "appservice_web_app_latest_http_version": ({"configuration": {"properties": {"http20Enabled": True}}}, {"configuration": {"properties": {"http20Enabled": False}}}),
    "appservice_web_app_latest_tls_version": ({"configuration": {"properties": {"minTlsVersion": "1.3"}}}, {"configuration": {"properties": {"minTlsVersion": "1.0"}}}),
}


@pytest.mark.parametrize("query", QUERIES, ids=str)
def test_exact_source_case_matches_reused_native_predicate(query):
    duckdb = pytest.importorskip("duckdb")
    review = QUERIES[query]
    check = REGISTRY[review["native_checks"][0]]
    case = re.sub(r"\b[a-z_]+\.(\w+)\b", r"\1", review["source_review"]["status_case_sql"])
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*(?:::integer|::boolean|::bool)", r"CAST(\1 AS VARCHAR)", case)
    # Match PostgreSQL text-extraction casts without altering the comparison.
    case = re.sub(r"CAST\(([^\n]+?) AS VARCHAR\)\s*=\s*0", r"CAST(\1 AS INTEGER) = 0", case)
    case = re.sub(r"CAST\(([^\n]+?) AS VARCHAR\)\s*>=\s*90", r"CAST(\1 AS INTEGER) >= 90", case)
    case = case.replace("not (configuration -> 'properties' ->> 'http20Enabled') :: boolean", "NOT CAST(configuration -> 'properties' ->> 'http20Enabled' AS BOOLEAN)")
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*(is\s+not\s+null|=|<|>=)", r"(\1) \2", case, flags=re.I)
    for index, (label, source_status, native_status) in enumerate((("pass", "ok", "PASS"), ("fail", "alarm", "FAIL"))):
        columns = TRUTH[query][index]
        definitions, values = [], []
        for name, value in columns.items():
            definitions.append("?" + ("::JSON" if isinstance(value, dict) else "") + " AS " + name)
            values.append(json.dumps(value) if isinstance(value, dict) else value)
        with duckdb.connect(":memory:") as database:
            assert database.execute("SELECT " + case + " FROM (SELECT " + ",".join(definitions) + ")", values).fetchone()[0] == source_status
        fixtures = CASES.get(check.id, {"pass": {"properties": {"supportsHttpsTrafficOnly": True}}, "fail": {"properties": {"supportsHttpsTrafficOnly": False}}})
        item = copy.deepcopy(fixtures[label])
        assert check.evaluate(item, {})[0] == native_status


@pytest.mark.parametrize("cid", azure_ports_common.CHECK_IDS, ids=str)
def test_new_common_rules_preserve_missing_denied_and_malformed_unknown(cid):
    for data in ({}, None, [], {"collection_status": "denied"}, {"collection_status": "partial"}):
        assert REGISTRY[cid].evaluate(data, {})[0] == "UNKNOWN"


def test_vault_recovery_conjunction_requires_both_settings():
    check = REGISTRY["azure.port.keyvault_vault_recoverable"]
    for soft, purge, want in ((True, True, "PASS"), (True, False, "FAIL"), (False, True, "FAIL"), (False, False, "FAIL")):
        assert check.evaluate({"properties": {"enableSoftDelete": soft, "enablePurgeProtection": purge}}, {})[0] == want
    assert check.evaluate({"properties": {"enableSoftDelete": True}}, {})[0] == "UNKNOWN"
