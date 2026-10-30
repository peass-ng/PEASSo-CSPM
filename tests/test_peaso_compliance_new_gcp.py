"""Semantic fixtures for signed, source-bound GCP compliance additions."""
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_gcp  # noqa: F401  (registration side effect)


def evaluate(check_id, item):
    return evaluate_check(check_id, item, {})


def bucket(**fields):
    return {"_provenance": {"representation": "full"}, **fields}


def test_versioned_bucket_lifecycle_requires_supported_action_and_condition():
    check_id = "gcp_pci_bucket_0742bd5dc32c"
    item = bucket(versioning={"enabled": True}, lifecycle={"rule": [{"action": {"type": "Delete"}, "condition": {"age": 90}}]})
    assert evaluate(check_id, item)[0] == "PASS"
    assert evaluate(check_id, bucket(versioning={"enabled": True}, lifecycle={"rule": []}))[0] == "FAIL"
    assert evaluate(check_id, bucket(versioning={"enabled": False}))[0] == "PASS"
    assert evaluate(check_id, bucket(versioning={"enabled": True}))[0] == "FAIL"
    assert evaluate(check_id, bucket(versioning={"enabled": True}, lifecycle={"rule": [{"action": {"type": "Unknown"}, "condition": {"age": 90}}]}))[0] == "UNKNOWN"
    assert evaluate(check_id, bucket(versioning={"enabled": True}, _coverage={"lifecycle": {"status": "denied"}}))[0] == "UNKNOWN"
    assert evaluate(check_id, {})[0] == "UNKNOWN"


def test_versioned_bucket_retention_requires_positive_period():
    check_id = "gcp_pci_bucket_3d76b0b0701e"
    assert evaluate(check_id, bucket(versioning={"enabled": True}, retentionPolicy={"retentionPeriod": "86400"}))[0] == "PASS"
    assert evaluate(check_id, bucket(versioning={"enabled": True}))[0] == "FAIL"
    assert evaluate(check_id, bucket(versioning={"enabled": False}))[0] == "PASS"
    assert evaluate(check_id, bucket(versioning={"enabled": True}, retentionPolicy={"retentionPeriod": "0"}))[0] == "FAIL"
    assert evaluate(check_id, bucket(versioning={"enabled": True}, _coverage={"retentionPolicy": {"status": "denied"}}))[0] == "UNKNOWN"
    assert evaluate(check_id, bucket(versioning={"enabled": True}, retentionPolicy={"retentionPeriod": "broken"}))[0] == "UNKNOWN"


def test_instance_template_external_ip_requires_complete_interfaces():
    check_id = "gcp_pci_instance_template_2e26bed500fc"
    assert evaluate(check_id, {"_provenance": {"representation": "full"}, "properties": {"networkInterfaces": [{"network": "global/networks/private"}]}})[0] == "PASS"
    assert evaluate(check_id, {"properties": {"networkInterfaces": [{"network": "global/networks/private"}]}})[0] == "UNKNOWN"
    assert evaluate(check_id, {"properties": {"networkInterfaces": [{"accessConfigs": [{"type": "ONE_TO_ONE_NAT"}]}]}})[0] == "FAIL"
    assert evaluate(check_id, {"properties": {"networkInterfaces": []}})[0] == "UNKNOWN"
    assert evaluate(check_id, {"properties": {"networkInterfaces": [{"accessConfigs": "not-a-list"}]}})[0] == "UNKNOWN"
    assert evaluate(check_id, {})[0] == "UNKNOWN"


def test_pubsub_cmek_distinguishes_default_encryption_and_unknown_coverage():
    check_id = "gcp_pubsub_topic_cmek"
    assert evaluate(check_id, {"name": "projects/p/topics/t", "kmsKeyName": "projects/p/locations/europe/keyRings/r/cryptoKeys/k"})[0] == "PASS"
    assert evaluate(check_id, {"name": "projects/p/topics/t", "_provenance": {"representation": "full"}})[0] == "FAIL"
    assert evaluate(check_id, {"name": "projects/p/topics/t"})[0] == "UNKNOWN"
    assert evaluate(check_id, {"name": "projects/p/topics/t", "kmsKeyName": None})[0] == "UNKNOWN"
    assert evaluate(check_id, {"name": "projects/p/topics/t", "_coverage": {"kmsKeyName": {"status": "denied"}}})[0] == "UNKNOWN"
    assert evaluate(check_id, {})[0] == "UNKNOWN"


def test_bigquery_public_acl_checks_keep_roles_and_principals_distinct():
    read_write = "gcp_pci_bigquery_dataset_6017267cdf32"
    all_users = "gcp_pci_bigquery_dataset_fb9fcc01d5b7"
    base = {"_provenance": {"representation": "full"}, "access": []}
    assert evaluate(read_write, base)[0] == "PASS"
    assert evaluate(all_users, base)[0] == "PASS"
    authenticated_reader = {**base, "access": [{"role": "READER", "specialGroup": "allAuthenticatedUsers"}]}
    assert evaluate(read_write, authenticated_reader)[0] == "FAIL"
    assert evaluate(all_users, authenticated_reader)[0] == "PASS"
    public_owner = {**base, "access": [{"role": "OWNER", "iamMember": "allUsers"}]}
    assert evaluate(read_write, public_owner)[0] == "PASS"
    assert evaluate(all_users, public_owner)[0] == "FAIL"
    public_writer = {**base, "access": [{"role": "WRITER", "iamMember": "allUsers"}]}
    assert evaluate(read_write, public_writer)[0] == "FAIL"
    assert evaluate(all_users, public_writer)[0] == "FAIL"
    authorized_view_first = {**base, "access": [{"view": {"projectId": "p", "datasetId": "d", "tableId": "v"}}, public_writer["access"][0]]}
    assert evaluate(read_write, authorized_view_first)[0] == "FAIL"
    assert evaluate(read_write, {**base, "access": authorized_view_first["access"][:1]})[0] == "PASS"
    assert evaluate(read_write, {"_provenance": {"representation": "partial"}, "access": []})[0] == "UNKNOWN"
    assert evaluate(all_users, {"_provenance": {"representation": "full"}, "_coverage": {"access": {"status": "denied"}}})[0] == "UNKNOWN"
    assert evaluate(all_users, {"_provenance": {"representation": "full"}, "_coverage": "malformed"})[0] == "UNKNOWN"
