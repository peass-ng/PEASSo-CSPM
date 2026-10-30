"""Behaviour tests for the claude2_aws_b native ports (AWS-B rows taken over from stalled Codex workers)."""
from peaso.checks.hacktricks_scope import includes
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.claude2_aws_b_common import IDS, ROWS, CONTEXT, resource_policy_public, policy_document, days_between, detail, detail_list, ABSENT, Unavailable
from peaso.checks import claude2_aws_b as claude_aws_b  # noqa: F401  (registration side effect)

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
        assert _evaluate(cid, "fail") == cases.get("fail_expect", "FAIL")
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


@pytest.mark.parametrize("cid", [c for c in IDS if "pass_index" in CASES[c]])
def test_dependency_missing_is_unknown(cid):
    """A predicate that needs another inventory never guesses without it."""
    check = REGISTRY[cid]
    assert check.evaluate(copy.deepcopy(CASES[cid]["pass"]), {"context": dict(CONTEXT)})[0] in ("UNKNOWN", "NOT_APPLICABLE")


# Additional named fixtures and the status each one must produce.
EXTRA_EXPECT = {"absent": "PASS", "no_policy": "PASS", "no_config": "PASS", "unlisted": "UNKNOWN", "bundle": "FAIL", "default_key": "FAIL",
                "never": "FAIL", "no_rules": "FAIL", "other_account": "FAIL", "no_set": "FAIL"}
STANDARD = {"pass", "fail", "manual", "unknown", "not_applicable", "missing", "malformed", "index", "case_indices"}
EXTRAS = [(cid, key) for cid in IDS for key in CASES[cid] if key not in STANDARD and not key.endswith(("_index", "_expect"))]


@pytest.mark.parametrize("cid,key", EXTRAS)
def test_named_fixtures(cid, key):
    expected = CASES[cid].get(key + "_expect") or ("PASS" if key.endswith("_pass") else EXTRA_EXPECT[key])
    assert _evaluate(cid, key) == expected


def test_resource_policy_public():
    public = policy_document('{"Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:BatchGetImage"}]}')
    assert resource_policy_public(public)
    deny = policy_document('{"Statement":[{"Effect":"Deny","Principal":"*","Action":"*"}]}')
    assert not resource_policy_public(deny)

def test_detail_helpers():
    assert detail({"D": ABSENT}, "D") is None
    assert detail({"D": {"collection_status": "collected", "A": 1}}, "D")["A"] == 1
    with pytest.raises(Unavailable):
        detail({"D": {"collection_status": "denied"}}, "D")
    with pytest.raises(Unavailable):
        detail({}, "D")
    assert detail_list({"L": {"collection_status": "empty", "items": []}}, "L") == []
    with pytest.raises(Unavailable):
        detail_list({"L": {"collection_status": "partial", "items": [{}]}}, "L")

def test_days_between_is_calendar_days():
    from datetime import datetime, timezone
    assert days_between(datetime(2026, 1, 2, 0, 1, tzinfo=timezone.utc), datetime(2026, 1, 1, 23, 59, tzinfo=timezone.utc)) == 1
