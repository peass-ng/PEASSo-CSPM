"""Source-bound API Keys restriction fixtures; no Google Cloud calls."""
from __future__ import annotations

import copy

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_gcp_api_keys as rule
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import CHECKS, evaluate_check


SCOPE = "projects/fixture-project"
NAME = "projects/123456789012/locations/global/keys/key-1"


def key(**fields):
    return {"name": NAME, "_provenance": {"scope": SCOPE,
            "source_requests": ["request-1"]}, **fields}


def scoped(rows, *, status="collected", scope=SCOPE):
    return {"context": {"provider": "gcp", "scope": scope},
            "collections": {"api_key": [{"type": "api_key", "scope": scope,
                                          "status": status, "items": rows}]},
            "api_key": [{"type": "api_key", "scope": scope, "data": row} for row in rows]}


def verdict(row, *, rows=None, **kwargs):
    return evaluate_check(rule.CHECK_ID, row, scoped([row] if rows is None else rows, **kwargs))


def test_active_restricted_unrestricted_and_deleted_keys():
    good = key(restrictions={"apiTargets": [{"service": "storage.googleapis.com"}]})
    assert verdict(good)[0] == "PASS"
    assert verdict(key(restrictions={"apiTargets": []}))[0] == "FAIL"
    assert verdict(key())[0] == "FAIL"
    assert verdict(key(restrictions={"serverKeyRestrictions": {"allowedIps": ["192.0.2.1"]}}))[0] == "FAIL"
    assert verdict(key(deleteTime="2026-10-11T00:00:00Z"))[0] == "NOT_APPLICABLE"
    assert verdict(key(restrictions={"apiTargets": [{"service": "cloudapis.googleapis.com"}]}))[0] == "UNKNOWN"


def test_denied_partial_malformed_or_detached_facts_are_unknown():
    good = key(restrictions={"apiTargets": [{"service": "storage.googleapis.com"}]})
    assert verdict(good, status="partial")[0] == "UNKNOWN"
    assert verdict(good, status="denied")[0] == "UNKNOWN"
    assert verdict(key(_coverage={"restrictions": {"status": "denied"}}))[0] == "UNKNOWN"
    assert verdict(key(restrictions={"_coverage": {"apiTargets": {"status": "denied"}}}))[0] == "UNKNOWN"
    assert verdict(key(restrictions={"apiTargets": [{"service": 7}]}))[0] == "UNKNOWN"
    assert verdict(key(restrictions={"apiTargets": "storage.googleapis.com"}))[0] == "UNKNOWN"
    assert verdict(key(deleteTime="not-a-time"))[0] == "UNKNOWN"
    assert verdict(good, rows=[good, copy.deepcopy(good)])[0] == "UNKNOWN"
    assert verdict(key(_provenance={"scope": "projects/other", "source_requests": ["request-1"]}))[0] == "UNKNOWN"
    assert verdict(good, scope="projects/other")[0] == "UNKNOWN"


def test_immutable_evaluation_and_production_scoped_snapshot():
    row = key(restrictions={"apiTargets": [{"service": "storage.googleapis.com"}]})
    index = scoped([row])
    original = copy.deepcopy(index)
    assert evaluate_check(rule.CHECK_ID, row, index)[0] == "PASS"
    assert evaluate_check(rule.CHECK_ID, row, index)[0] == "PASS"
    assert index == original
    snapshot = make_snapshot("gcp", [SCOPE], [
        {"type": "api_key", "scope": SCOPE, "service": "apikeys",
         "status": "collected", "items": [key(restrictions={"apiTargets": []})]},
    ], created_at="2026-10-12T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[rule.CHECK_ID])
    assert [f["status"] for f in report["findings"] if f["check_id"] == rule.CHECK_ID] == ["FAIL"]
