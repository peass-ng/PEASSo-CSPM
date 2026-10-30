"""Database/FSx pinned policies: native settings, applicability and purity."""
from peaso.checks.hacktricks_scope import includes
import copy
import pytest
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks import aws_b_databases
from peaso.checks.fixtures import CASES
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def check(cid):
    return next(c for c in CHECKS if c.id == cid)


@pytest.mark.parametrize("cid", aws_b_databases.IDS)
def test_native_pass_fail_unknown_denied_malformed_and_input_purity(cid):
    c = check(cid)
    cases = CASES[cid]
    for label, status in (("pass", "PASS"), ("fail", "FAIL"), ("not_applicable", "NOT_APPLICABLE")):
        if label not in cases:
            continue
        data = copy.deepcopy(cases[label])
        before = copy.deepcopy(data)
        assert c.evaluate(data, {})[0] == status
        assert data == before
    for data in ({}, None, {"collection_status": "denied"}, {"_coverage": []}):
        assert c.evaluate(data, {})[0] == "UNKNOWN"
    assert (HACKTRICKS in c.frameworks) == includes(c.id)


def test_rds_aurora_eligibility_precedes_instance_multiaz_setting():
    c = check("aws.b.rds_instance.multiple_az")
    for engine in ("aurora-mysql", "AURORA-POSTGRESQL", "custom-aurora-postgresql-variant"):
        assert c.evaluate({"Engine": engine}, {})[0] == "NOT_APPLICABLE"
    assert c.evaluate({"Engine": "mysql"}, {})[0] == "UNKNOWN"
    assert c.evaluate({"Engine": "postgres", "MultiAZ": "true"}, {})[0] == "UNKNOWN"


def test_neptune_logging_requires_audit_and_preserves_unknown_categories():
    c = check("aws.b.neptune.audit_logging")
    assert c.evaluate({"EnabledCloudwatchLogsExports": ["slowquery", "audit"]}, {})[0] == "PASS"
    assert c.evaluate({"EnabledCloudwatchLogsExports": []}, {})[0] == "FAIL"
    assert c.evaluate({"EnabledCloudwatchLogsExports": [True]}, {})[0] == "UNKNOWN"


def test_neptune_backup_exact_threshold_does_not_accept_boolean_or_negative():
    c = check("aws.b.neptune.backup_retention_seven_days")
    for days, expected in ((0, "FAIL"), (6, "FAIL"), (7, "PASS"), (35, "PASS"), (-1, "UNKNOWN"), (True, "UNKNOWN")):
        assert c.evaluate({"BackupRetentionPeriod": days}, {})[0] == expected


def test_fsx_ontap_second_generation_multiaz_and_unknown_enum():
    c = check("aws.b.fsx.netapp_ontap_multi_az")
    assert c.evaluate({"FileSystemType": "ONTAP", "OntapConfiguration": {"DeploymentType": "MULTI_AZ_2"}}, {})[0] == "PASS"
    assert c.evaluate({"FileSystemType": "ONTAP", "OntapConfiguration": {"DeploymentType": "new-version"}}, {})[0] == "UNKNOWN"
    assert c.evaluate({"FileSystemType": "new-service"}, {})[0] == "UNKNOWN"


def test_fsx_openzfs_requires_both_tag_settings_and_missing_detail_is_unknown():
    c = check("aws.b.fsx.openzfs_copy_backup_and_volume_tags")
    for backups, volumes in ((False, False), (False, True), (True, False)):
        assert c.evaluate({"FileSystemType": "OPENZFS", "OpenZFSConfiguration": {"CopyTagsToBackups": backups, "CopyTagsToVolumes": volumes}}, {})[0] == "FAIL"
    assert c.evaluate({"FileSystemType": "OPENZFS", "OpenZFSConfiguration": {"CopyTagsToBackups": True}}, {})[0] == "UNKNOWN"
    assert c.evaluate({"FileSystemType": "LUSTRE"}, {})[0] == "NOT_APPLICABLE"


def test_service_inventory_denied_and_known_empty_are_distinct():
    cid = "aws.b.neptune_cluster.storage_encryption"
    for status, expected in (("denied", "DENIED"), ("unknown", "UNKNOWN"), ("empty", "EMPTY")):
        snapshot = make_snapshot("aws", ["111111111111/us-east-1"], [{"type": "neptune_cluster", "scope": "111111111111/us-east-1", "status": status, "items": []}])
        report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[cid])
        assert report["findings"][0]["status"] == expected


