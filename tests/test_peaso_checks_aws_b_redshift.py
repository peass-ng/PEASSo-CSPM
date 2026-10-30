"""Redshift predicates preserve exact flags/thresholds and unknown dependencies."""
from peaso.checks.hacktricks_scope import includes
import copy
import pytest
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks import aws_b_redshift as module
from peaso.checks.fixtures import CASES
from peaso.collectors import aws_b_services as plugin


def check(cid):
    return next(c for c in CHECKS if c.id == cid)


@pytest.mark.parametrize("cid", module.IDS)
def test_native_settings_pass_fail_missing_denied_malformed(cid):
    c = check(cid)
    for label, expected in (("pass", "PASS"), ("fail", "FAIL")):
        data = copy.deepcopy(CASES[cid][label]);before = copy.deepcopy(data)
        assert c.evaluate(data, {})[0] == expected
        assert data == before
    for data in ({}, None, {"collection_status": "denied"}, {"_coverage": []}):
        assert c.evaluate(data, {})[0] == "UNKNOWN"
    assert (HACKTRICKS in c.frameworks) == includes(c.id)


def test_kms_reference_is_not_customer_managed_classification_and_absence_needs_complete_identity():
    c = check("aws.b.redshift.kms_key_declared")
    data = {"ClusterIdentifier": "fixture", "Encrypted": True}
    assert c.evaluate(data, {})[0] == "UNKNOWN"
    index = {"collections": {"redshift_cluster": [{"status": "collected"}]}, "redshift_cluster": [{"data": data}]}
    assert c.evaluate(data, index)[0] == "FAIL"
    index["collections"]["redshift_cluster"][0]["status"] = "partial"
    assert c.evaluate(data, index)[0] == "UNKNOWN"
    assert c.evaluate({"Encrypted": True, "KmsKeyId": ""}, {})[0] == "UNKNOWN"
    assert c.evaluate({"Encrypted": True, "_coverage": {"KmsKeyId": {"status": "denied"}}}, {})[0] == "UNKNOWN"


def test_redshift_name_policy_keeps_case_sensitive_source_semantics():
    c = check("aws.b.redshift.nondefault_admin")
    assert c.evaluate({"MasterUsername": "awsuser"}, {})[0] == "FAIL"
    assert c.evaluate({"MasterUsername": "AWSUSER"}, {})[0] == "PASS"


def test_retention_boundary_and_malformed_boolean():
    c = check("aws.b.redshift.snapshots_seven_days")
    for days, expected in ((0, "FAIL"), (6, "FAIL"), (7, "PASS"), (-1, "UNKNOWN"), (True, "UNKNOWN")):
        assert c.evaluate({"AutomatedSnapshotRetentionPeriod": days}, {})[0] == expected


def test_logging_metadata_uses_shared_read_and_keeps_denial_explicit():
    class Reads:
        calls = []
        def detail(self, session, service, region, operation, **arguments):
            self.calls.append((service, region, operation, arguments))
            return {"collection_status": "denied"}
    reads = Reads()
    data = plugin.ENRICHERS["redshift_cluster"](reads, object(), "us-east-1", [{"ClusterIdentifier": "fixture"}])[0]
    assert data["Logging"]["collection_status"] == "denied"
    assert check("aws.b.redshift.audit_logging").evaluate(data, {})[0] == "UNKNOWN"
    assert reads.calls == [("redshift", "us-east-1", "describe_logging_status", {"ClusterIdentifier": "fixture"})]
