"""Evaluator boundaries and priority review for AWS copy corrections."""
from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.aws_finding_clarity_reviewed import ROWS, SEVERITY_REVIEW

REGISTRY = {check.id: check for check in CHECKS}


def predicate_cases():
    output = []
    statuses = {"pass": "PASS", "fail": "FAIL", "missing": "UNKNOWN", "malformed": "UNKNOWN",
                "unknown": "UNKNOWN", "manual": "MANUAL", "not_applicable": "NOT_APPLICABLE"}
    for cid in sorted(ROWS):
        fixture = CASES.get(cid, {})
        for case, status in statuses.items():
            if case in fixture:
                output.append(pytest.param(cid, fixture[case], fixture.get(case + "_index", fixture.get("index", {})),
                                           fixture.get(case + "_expect", status), id=cid + ":" + case))
    return output


@pytest.mark.parametrize("cid,item,index,status", predicate_cases())
def test_existing_predicate_fixture_outcomes_are_preserved(cid, item, index, status):
    assert REGISTRY[cid].evaluate(deepcopy(item), deepcopy(index))[0] == status


def test_default_s3_encryption_absence_does_not_become_failure():
    check = REGISTRY["aws.s3.default_encryption"]
    assert check.evaluate({"Encryption": {"absent": True}}, {})[0] == "UNKNOWN"
    good = {"Encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}}
    status, evidence = check.evaluate(good, {})
    assert status == "PASS" and evidence["algorithms"] == ["AES256"]
    assert "existing object encryption was not collected" in evidence["semantics"]


def test_priority_review_keeps_administrative_ports_and_public_data_serious():
    assert SEVERITY_REVIEW["aws.claude_a.vpc.sg_no_world_ssh"]["recommended"] == "high"
    assert SEVERITY_REVIEW["aws.claude_a.vpc.sg_no_world_rdp"]["recommended"] == "high"
    assert SEVERITY_REVIEW["aws.c2b.elbv2.internet_facing_open_sg"]["recommended"] == "medium"
    assert SEVERITY_REVIEW["aws.gap.s3.no_public_write_acl_or_policy"]["recommended"] == "critical"
    assert SEVERITY_REVIEW["aws.claude_a.s3.restrict_public_read"]["recommended"] == "critical"
    assert SEVERITY_REVIEW["aws.c2b.cloudfront.custom_ssl_certificate"]["recommended"] == "info"
    assert SEVERITY_REVIEW["aws.c2b.dms.public_instance_open_sg"]["recommended"] == "high"
