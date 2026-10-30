"""Semantic fixture for signed Cloud SQL deletion protection."""
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_gcp_sql  # noqa: F401  (registration side effect)
from peaso.checks import CHECKS, evaluate_check


CHECK_ID = "gcp.sql.deletion_protection"


def instance(value):
    return {"name": "inert-sql", "settings": {"deletionProtectionEnabled": value}}


def evaluate(item, status="collected"):
    index = {"collections": {"sql_instance": [{"scope": "projects/inert", "status": status}]},
             "sql_instance": [{"data": item}]}
    return evaluate_check(CHECK_ID, item, index)


def test_sql_deletion_protection_requires_observed_typed_nested_boolean_and_complete_inventory():
    assert evaluate(instance(True))[0] == "PASS"
    assert evaluate(instance(False))[0] == "FAIL"
    assert evaluate(instance(False), "partial")[0] == "UNKNOWN"
    assert evaluate(instance(True), "denied")[0] == "UNKNOWN"
    assert evaluate({"name": "inert-sql", "settings": {}})[0] == "UNKNOWN"
    assert evaluate({"name": "inert-sql", "deletionProtectionEnabled": True})[0] == "UNKNOWN"
    assert evaluate(instance("false"))[0] == "UNKNOWN"
    assert evaluate(instance(None))[0] == "UNKNOWN"
    assert evaluate(instance(False) | {"_coverage": {"settings": {"status": "denied"}}})[0] == "UNKNOWN"
    assert evaluate({"name": "inert-sql", "settings": {"_coverage": {"deletionProtectionEnabled": {"status": "denied"}}}})[0] == "UNKNOWN"
