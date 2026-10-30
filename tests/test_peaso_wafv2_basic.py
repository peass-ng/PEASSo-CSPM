"""Signed WAFv2 basic admission through the real registry and snapshot engine."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, wafv2_basic
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

from tests.release_successor_history import (ancestor_json, ancestor_bytes, ancestor_sha, registered_before_bulk, registry_source_before_bulk)

CHECKS = registered_before_bulk(CHECKS)

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
SCOPE = ACCOUNT + "/us-east-1"
ARN = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:regional/rulegroup/example/1234"
METRICS = "aws.pci.wafv2.rule_group_metrics"
NONEMPTY = "aws.pci.wafv2.rule_group_nonempty"
EXISTING = "aws.cb.wafv2.rule_group_metrics"
SIGNED_REQUIREMENTS = {
    METRICS: {"10.2.1.1.36", "10.4.1.1.7", "10.4.1.6", "10.4.2.7", "10.6.3.41",
              "10.7.1.8", "10.7.2.8", "A3.3.1.11", "A3.5.1.11"},
    NONEMPTY: {"6.4.1.7", "6.4.2.7"},
}
SIGNED_SHA = {METRICS: "68c0870a052157b9277dc9889347264ae416c566e9b89feb341689648447876b",
              NONEMPTY: "0c3e8decee40fc7c33a486fc596b80795e8fc95f0894c2817160622b9b5e705e"}


def group(enabled=True, rules=None):
    return {"ARN": ARN, "Scope": "REGIONAL", "RuleGroup": {"ARN": ARN,
        "VisibilityConfig": {"CloudWatchMetricsEnabled": enabled},
        "Rules": [{"Name": "block"}] if rules is None else rules}}


def report(rows, checks, *, status="collected", scope=SCOPE):
    collection = {"type": "wafv2_rule_group", "scope": scope, "service": "wafv2",
                  "status": status, "items": copy.deepcopy(rows) if status in {"collected", "partial"} else []}
    if status in {"partial", "denied"}:
        collection["error"] = {"code": "AccessDenied" if status == "denied" else "Incomplete"}
    snapshot = make_snapshot("aws", [scope], [collection])
    return evaluate_snapshot(snapshot, checks=list(checks), categories=["hardening"],
                             include_not_applicable=True)


def resource_finding(out, cid):
    rows = [row for row in out["findings"] if row["check_id"] == cid and
            not row["resource_id"].startswith("inventory:")]
    assert len(rows) == 1
    return rows[0]


def coverage(out, cid):
    rows = [row for row in out["coverage"] if row["level"] == "check" and row["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]




@pytest.mark.parametrize("row,metrics,nonempty", [
    (group(), "PASS", "PASS"),
    (group(enabled=False), "FAIL", "PASS"),
    (group(rules=[]), "PASS", "FAIL"),
    (group(enabled="true"), "UNKNOWN", "PASS"),
    (group(rules="bad"), "PASS", "UNKNOWN"),
    ({"ARN": ARN, "Scope": "REGIONAL"}, "UNKNOWN", "UNKNOWN"),
    ({**group(), "RuleGroup": {"collection_status": "denied"}}, "UNKNOWN", "UNKNOWN"),
    ({**group(), "ARN": ARN.replace(ACCOUNT, "999999999999")}, "UNKNOWN", "UNKNOWN"),
])
def test_resource_outcomes(row, metrics, nonempty):
    out = report([row], [METRICS, NONEMPTY])
    assert resource_finding(out, METRICS)["status"] == metrics
    assert resource_finding(out, NONEMPTY)["status"] == nonempty
    assert coverage(out, METRICS)["by_status"] == {metrics: 1}


@pytest.mark.parametrize("status", ["partial", "denied", "empty"])
def test_incomplete_collection_coverage(status):
    out = report([], [METRICS, NONEMPTY], status=status)
    for cid in (METRICS, NONEMPTY):
        assert coverage(out, cid)["status"] == status
        assert all(row["status"] != "PASS" for row in out["findings"] if row["check_id"] == cid)


def test_partial_inventory_retains_proven_failures_and_unknown_safe_cases():
    bad = report([group(enabled=False, rules=[])], [METRICS, NONEMPTY], status="partial")
    good = report([group()], [METRICS, NONEMPTY], status="partial")
    for cid in (METRICS, NONEMPTY):
        assert resource_finding(bad, cid)["status"] == "FAIL"
        assert coverage(bad, cid)["status"] == "partial"
        assert resource_finding(good, cid)["status"] == "UNKNOWN"
        assert coverage(good, cid)["status"] == "partial"


@pytest.mark.parametrize("row", [group(), group(enabled=False),
                                  {**group(), "RuleGroup": {"collection_status": "denied"}},
                                  {**group(), "ARN": ARN.replace(ACCOUNT, "999999999999")}])
def test_common_and_pci_metrics_have_identical_scoped_status(row):
    out = report([row], [EXISTING, METRICS])
    assert resource_finding(out, EXISTING)["status"] == resource_finding(out, METRICS)["status"]


def test_common_and_pci_metrics_share_one_detail_read(monkeypatch):
    original = wafv2_basic.get
    reads = []

    def counted_get(obj, path, *args):
        if path == "VisibilityConfig.CloudWatchMetricsEnabled":
            reads.append(path)
        return original(obj, path, *args)

    monkeypatch.setattr(wafv2_basic, "get", counted_get)
    out = report([group()], [EXISTING, METRICS])
    assert resource_finding(out, EXISTING)["status"] == resource_finding(out, METRICS)["status"] == "PASS"
    assert reads == ["VisibilityConfig.CloudWatchMetricsEnabled"]
