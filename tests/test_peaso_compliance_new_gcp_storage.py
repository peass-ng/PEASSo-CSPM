"""Semantic fixture for the signed Cloud Storage usage-log destination check."""
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_gcp_storage  # noqa: F401  (registration side effect)
from peaso.checks import CHECKS, evaluate_check


CHECK_ID = "gcp_bucket_logging_enabled_fb7cc594582a"


def evaluate(item):
    return evaluate_check(CHECK_ID, item, {})


def bucket(**fields):
    return {"name": "pci-inert-bucket", "_provenance": {"representation": "full"}, **fields}


def test_usage_log_destination_requires_complete_full_bucket_metadata():
    assert evaluate(bucket(logging={"logBucket": "pci-inert-log-bucket"}))[0] == "PASS"
    assert evaluate(bucket())[0] == "FAIL"
    assert evaluate(bucket(logging={}))[0] == "FAIL"
    assert evaluate(bucket(logging={"logBucket": ""}))[0] == "FAIL"
    assert evaluate({"name": "pci-inert-bucket", "logging": {"logBucket": "pci-inert-log-bucket"},
                     "_provenance": {"representation": "partial"}})[0] == "UNKNOWN"
    assert evaluate(bucket(_coverage={"logging": {"status": "denied"}}))[0] == "UNKNOWN"
    assert evaluate(bucket(collection_status="denied"))[0] == "UNKNOWN"
    assert evaluate(bucket(logging={"logBucket": None}))[0] == "UNKNOWN"
    assert evaluate(bucket(logging={"_coverage": {"logBucket": {"status": "denied"}}}))[0] == "UNKNOWN"
    assert evaluate({})[0] == "UNKNOWN"
