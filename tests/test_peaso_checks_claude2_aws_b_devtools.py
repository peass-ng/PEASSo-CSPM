"""Behaviour tests for the claude2_aws_b devtools group, runnable without the other group modules."""
import copy
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks import claude2_aws_b_devtools as devtools
from peaso.checks.claude2_aws_b_common import IDS, ROWS, DOCS, CONTEXT

REGISTRY = {check.id: check for check in CHECKS}
EXTRA_EXPECT = {"absent": "PASS", "never": "FAIL"}
STANDARD = {"pass", "fail", "manual", "unknown", "not_applicable", "missing", "malformed", "index", "case_indices"}
OWN = [cid for cid in IDS if cid.split(".")[2] in {"codebuild", "cloudformation", "codedeploy", "ecr", "eventbridge", "codeartifact"}]


def _evaluate(cid, name):
    cases = CASES[cid]
    index = cases.get(name + "_index", cases.get("index", {}))
    data, scoped = copy.deepcopy(cases[name]), copy.deepcopy(index)
    before, before_index = copy.deepcopy(data), copy.deepcopy(scoped)
    status = REGISTRY[cid].evaluate(data, scoped)[0]
    assert data == before and scoped == before_index
    return status


@pytest.mark.parametrize("cid", OWN)
def test_pass_fail_unknown(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    assert _evaluate(cid, "pass") == "PASS"
    assert _evaluate(cid, "fail") == "FAIL"
    assert _evaluate(cid, "unknown") == "UNKNOWN"
    for bad in ({}, None, {"collection_status": "denied"}):
        assert check.evaluate(bad, cases.get("index", {}))[0] == "UNKNOWN"
    if "not_applicable" in cases:
        assert _evaluate(cid, "not_applicable") == "NOT_APPLICABLE"
    if "pass_index" in cases:
        assert check.evaluate(copy.deepcopy(cases["pass"]), {"context": dict(CONTEXT)})[0] in ("UNKNOWN", "NOT_APPLICABLE")
    assert ROWS[cid] and DOCS[cid] and check.severity and check.remediation


@pytest.mark.parametrize("cid,key", [(c, k) for c in OWN for k in CASES[c] if k not in STANDARD and not k.endswith(("_index", "_expect"))])
def test_named_fixtures(cid, key):
    expected = CASES[cid].get(key + "_expect") or ("PASS" if key.endswith("_pass") else EXTRA_EXPECT[key])
    assert _evaluate(cid, key) == expected


def test_anchored_patterns():
    assert devtools._anchored("") and devtools._anchored("^a$|^b$") and devtools._anchored("^a$| ^b$ ")
    assert not devtools._anchored("^a$|b") and not devtools._anchored("main")


def test_bitbucket_url_credentials_never_in_evidence():
    status, evidence = REGISTRY["aws.c2b.codebuild.source_url_no_credentials"].evaluate(copy.deepcopy(CASES["aws.c2b.codebuild.source_url_no_credentials"]["fail"]), {})[:2]
    assert status == "FAIL" and "abc@" not in json.dumps(evidence)


def test_signature_images_are_not_scannable():
    assert not devtools._scannable({"artifactMediaType": "application/vnd.oci.image.config.v1+json", "imageTags": ["sha256-abc.sig"]})
    assert not devtools._scannable({"artifactMediaType": "application/vnd.cncf.notary.signature", "imageTags": ["v1"]})
    assert devtools._scannable({"artifactMediaType": "application/vnd.oci.image.config.v1+json", "imageTags": ["v1"]})

@pytest.mark.parametrize("cid", ["aws.c2b.ecr.repository_policy_no_wildcard_principal", "aws.c2b.ecr.repository_not_public",
                                 "aws.c2b.ecr.repository_policy_prohibit_public_perimeter"])
def test_ecr_policy_accepts_collector_parsed_document(cid):
    # the live AWS collector stores policyText already parsed into a dict
    for name in ("pass", "fail"):
        data = copy.deepcopy(CASES[cid][name])
        policy = data.get("Policy")
        if isinstance(policy, dict) and isinstance(policy.get("policyText"), str):
            policy["policyText"] = json.loads(policy["policyText"])
        assert REGISTRY[cid].evaluate(data, copy.deepcopy(CASES[cid].get("index", {})))[0] == _evaluate(cid, name)
