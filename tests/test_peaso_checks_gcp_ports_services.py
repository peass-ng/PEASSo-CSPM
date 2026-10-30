"""Service predicates have available-fact truths and explicit data gaps."""
import copy
import pytest
from peaso.checks import CHECKS, gcp_ports_services as ports
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_each_service_predicate_available_and_unavailable_truth(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    if cid == "gcp.ports.sql_instance_mysql_binary_log_enabled" and case in ("pass", "fail"):
        item["databaseVersion"] = "MYSQL_8_0"  # Required native engine applicability.
    original = copy.deepcopy(item)
    actual, evidence = REGISTRY[cid].evaluate(item, {})
    assert actual == wanted, evidence
    assert item == original


@pytest.mark.parametrize("cid", ports.SQL_SPECS)
def test_sql_engine_exclusion_and_complete_flag_absence(cid):
    description = ports.SQL_SPECS[cid]
    different = "MYSQL_8" if description["engine"] != "MYSQL" else "POSTGRES_16"
    assert REGISTRY[cid].evaluate({"databaseVersion": different}, {})[0] == "NOT_APPLICABLE"
    item = {"databaseVersion": description["engine"] + "_16", "settings": {"databaseFlags": []}}
    assert REGISTRY[cid].evaluate(item, {})[0] == ("PASS" if description["forbidden"] else "FAIL")


def test_distinct_trace_and_verbosity_source_conditions_not_hash_merged():
    on = REGISTRY["gcp.ports.sql_instance_sql_3625_trace_database_flag_on"]
    item = {"databaseVersion": "SQLSERVER_2022_STANDARD", "settings": {"databaseFlags": [{"name": "3625", "value": "on"}]}}
    assert on.evaluate(item, {})[0] == "PASS"
    assert item["settings"]["databaseFlags"][0]["value"] != "off"  # Exact rejected source condition is false.
    assert "gcp.ports.sql_instance_sql_3625_trace_database_flag_off" not in REGISTRY
    verbose = REGISTRY["gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter"]
    item = {"databaseVersion": "POSTGRES_16", "settings": {"databaseFlags": [{"name": "log_error_verbosity", "value": "verbose"}]}}
    assert verbose.evaluate(item, {})[0] == "PASS"


def test_explicit_denied_setting_is_not_assessed_as_false():
    check = REGISTRY["gcp.ports.kubernetes_cluster_use_ip_aliases"]
    item = {"ipAllocationPolicy": {"useIpAliases": True, "_coverage": {"useIpAliases": {"status": "denied"}}}}
    assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_node_pools_do_not_invent_autopilot_or_missing_management_settings():
    check = REGISTRY["gcp.ports.kubernetes_cluster_auto_repair_enabled"]
    assert check.evaluate({"nodePools": []}, {})[0] == "UNKNOWN"
    assert check.evaluate({"nodePools": [{"name": "p"}]}, {})[0] == "UNKNOWN"
