"""Reproduce source and fixture evidence for K8s Hardening native-final candidates.

This is an offline source audit. It never qualifies a runtime allowlist: a
same-snapshot AI comparison and an explicit replay receipt are separate gates.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.k8s_extended import CONTROLLERS, GOOD
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "peaso/checks/k8s_extended.py"
OUTPUT = ROOT / "outputs/k8s-native-final-source-audit-20261027.json"
CREATED_AT = "2026-10-27T00:00:00+00:00"


def main() -> None:
    registry = {check.id: check for check in CHECKS}
    rows = []
    for kind in CONTROLLERS:
        for predicate in GOOD:
            check_id = f"k8s.{kind}.{predicate}"
            check = registry[check_id]
            assert check.provider == "k8s" and check.category == "hardening"
            assert check.kind == kind
            cases = CASES[check_id]
            observed = {}
            for label, expected in (("pass", "PASS"), ("fail", "FAIL"),
                                    ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
                item = copy.deepcopy(cases[label])
                before = copy.deepcopy(item)
                status, _ = check.evaluate(item, {})
                assert item == before, check_id
                assert status == expected, (check_id, label, status)
                observed[label] = status
            rows.append({"check_id": check_id, "kind": kind,
                         "predicate": predicate, "fixture_statuses": observed,
                         "decision": "source_proven_pending_same_snapshot_ai_replay"})

    # Exercise the public engine path as well as the evaluator for a bounded
    # representative cohort. The manifest and receipt contain no resource data.
    item = {"metadata": {"name": "audit-deployment", "namespace": "audit"},
            **copy.deepcopy(CASES["k8s.deployment.no_privileged"]["fail"])}
    snapshot = make_snapshot("k8s", ["audit-cluster/audit"], [
        {"type": "deployment", "scope": "audit-cluster/audit",
         "status": "collected", "items": [item]}], created_at=CREATED_AT,
        metadata={"synthetic": True})
    selected = [f"k8s.deployment.{predicate}" for predicate in GOOD]
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=selected)
    engine = {row["check_id"]: row["status"] for row in report["findings"]}
    assert set(engine) == set(selected), engine
    assert engine["k8s.deployment.no_privileged"] == "FAIL"
    assert engine["k8s.deployment.no_host_network"] == "PASS"
    assert engine["k8s.deployment.no_host_ports"] == "PASS"
    assert engine["k8s.deployment.non_root"] == "FAIL"

    receipt = {
        "version": 1,
        "scope": "k8s Pod-template Hardening source audit; offline synthetic replay",
        "source_path": "peaso/checks/k8s_extended.py",
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "candidate_count": len(rows),
        "fixture_case_count": sum(len(row["fixture_statuses"]) for row in rows),
        "engine_replay": {"check_ids": selected, "statuses": engine},
        "ai_comparison": {"status": "unavailable", "reviewed_failures": 0,
                          "disagreements": None},
        "runtime_admission": "pending",
        "checks": rows,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"{OUTPUT}: {len(rows)} candidates, 96 fixture cases, engine replay passed")


if __name__ == "__main__":
    main()
