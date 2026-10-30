"""Behaviour tests for the claude2_aws_a native ports and partition dispositions."""
from peaso.checks.hacktricks_scope import includes
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.claude2_aws_a_common import CONTEXT, IDS, ROWS, idx, policy_document, principal_aws_values, report_time
from peaso.checks import claude2_aws_a  # noqa: F401  (registration side effect)

REGISTRY = {check.id: check for check in CHECKS}
HACKTRICKS = "HackTricks Cloud Best Practices"


def _evaluate(cid, name):
    cases = CASES[cid]
    index = cases.get(name + "_index", cases.get("case_indices", {}).get(name, cases.get("index", {})))
    data, scoped = copy.deepcopy(cases[name]), copy.deepcopy(index)
    before, before_index = copy.deepcopy(data), copy.deepcopy(scoped)
    status = REGISTRY[cid].evaluate(data, scoped)[0]
    assert data == before and scoped == before_index
    return status


@pytest.mark.parametrize("cid", IDS)
def test_pass_fail_unknown(cid):
    check = REGISTRY[cid]
    cases = CASES[cid]
    assert _evaluate(cid, "pass") == "PASS"
    if "fail" in cases:
        assert _evaluate(cid, "fail") == "FAIL"
    else:
        assert _evaluate(cid, "manual") == "MANUAL"
    assert _evaluate(cid, "unknown") == "UNKNOWN"
    assert check.evaluate({}, cases.get("index", {}))[0] == "UNKNOWN"
    assert check.evaluate(None, cases.get("index", {}))[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, cases.get("index", {}))[0] == "UNKNOWN"
    if "not_applicable" in cases:
        assert _evaluate(cid, "not_applicable") == "NOT_APPLICABLE"
    assert (HACKTRICKS in check.frameworks) == includes(check.id)
    assert ROWS[cid]


@pytest.mark.parametrize("cid", [c for c in IDS if len(REGISTRY[c].dependencies or []) > 1 or "pass_index" in CASES[c]])
def test_dependency_missing_is_unknown(cid):
    """A predicate that needs another inventory never guesses without it."""
    check = REGISTRY[cid]
    assert check.evaluate(copy.deepcopy(CASES[cid]["pass"]), {"context": dict(CONTEXT)})[0] in ("UNKNOWN", "NOT_APPLICABLE")


STANDARD = {"pass", "fail", "manual", "unknown", "not_applicable", "missing", "malformed", "index", "case_indices"}
EXTRAS = [(cid, key) for cid in IDS for key in CASES[cid] if key not in STANDARD and not key.endswith(("_index", "_expect"))]


@pytest.mark.parametrize("cid,key", EXTRAS)
def test_named_fixtures(cid, key):
    assert _evaluate(cid, key) == CASES[cid][key + "_expect"]


def test_threat_ratio_counts_distinct_names_over_pinned_list():
    cid = "aws.claude2_a.cloudtrail.threat_detection_llm_jacking"
    check = REGISTRY[cid]
    actor = "arn:aws:iam::123456789012:user/x"
    names = ["InvokeModel"] * 20 + ["ListFoundationModels"]
    events = [{"ActorArn": actor, "ActorType": "IAMUser", "EventName": n, "EventTime": "2026-10-10T10:00:00+00:00", "EventId": str(i)}
              for i, n in enumerate(names)]
    # 2 distinct of 14 pinned names = 0.14 <= 0.4: repeated calls of one API never trip the ratio.
    assert check.evaluate({"scope": "123456789012/us-east-1"}, idx(aws_cloudtrail_activity=events))[0] == "PASS"
    other = [dict(e, ActorArn="arn:aws:iam::123456789012:user/y", EventName="Unrelated") for e in events]
    assert check.evaluate({"scope": "123456789012/us-east-1"}, idx(aws_cloudtrail_activity=other))[0] == "PASS"


def test_helpers():
    assert principal_aws_values({"Principal": "*"}) == ["*"]
    assert principal_aws_values({"Principal": {"AWS": "arn:aws:iam::1:root"}}) == ["arn:aws:iam::1:root"]
    assert principal_aws_values({"Principal": {"Service": "logs.amazonaws.com"}}) == []
    assert report_time({"x": "N/A"}, "x") is None and report_time({"x": "no_information"}, "x") is None
    assert policy_document('{"Statement":{"Effect":"Allow","Principal":"*","Action":"*"}}')
