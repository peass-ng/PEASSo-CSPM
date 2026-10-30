"""Signed BigQuery allUsers READER fixtures, including narrower-scope contrasts."""
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_gcp_bigquery  # noqa: F401  (registration side effect)
from peaso.checks import CHECKS, evaluate_check


CHECK_ID = "gcp_pci_bigquery_dataset_a4e25dbf9640"


def dataset(**fields):
    return {"name": "projects/pci-inert/datasets/sample", "_provenance": {"representation": "full"}, **fields}


def evaluate(item):
    return evaluate_check(CHECK_ID, item, {})


def test_only_exact_all_users_reader_pair_fails():
    assert evaluate(dataset(access=[{"specialGroup": "allUsers", "role": "READER"}]))[0] == "FAIL"
    assert evaluate(dataset(access=[{"specialGroup": "allUsers", "role": "WRITER"}]))[0] == "PASS"
    assert evaluate(dataset(access=[{"specialGroup": "allAuthenticatedUsers", "role": "READER"}]))[0] == "PASS"
    assert evaluate(dataset(access=[{"iamMember": "allUsers", "role": "READER"}]))[0] == "FAIL"
    assert evaluate(dataset(access=[{"userByEmail": "owner@example.invalid", "role": "OWNER"}]))[0] == "PASS"
    assert evaluate(dataset())[0] == "PASS"
    assert evaluate(dataset(access=[{"view": {"projectId": "pci-inert", "datasetId": "views", "tableId": "v1"}},
                                    {"specialGroup": "allUsers", "role": "READER"}]))[0] == "FAIL"


def test_partial_denied_and_malformed_acl_cannot_be_clean_pass():
    assert evaluate({"name": "projects/pci-inert/datasets/sample", "access": [],
                     "_provenance": {"representation": "partial"}})[0] == "UNKNOWN"
    assert evaluate(dataset(collection_status="denied"))[0] == "UNKNOWN"
    assert evaluate(dataset(_coverage={"access": {"status": "denied"}}))[0] == "UNKNOWN"
    assert evaluate(dataset(access="bad-list"))[0] == "UNKNOWN"
    assert evaluate(dataset(access=[{"specialGroup": "allUsers"}]))[0] == "UNKNOWN"
    assert evaluate(dataset(access=[{"specialGroup": 12, "role": "READER"}]))[0] == "UNKNOWN"
    assert evaluate(dataset(access=[{"specialGroup": "allUsers", "role": "new-role"}]))[0] == "UNKNOWN"
    assert evaluate({})[0] == "UNKNOWN"
