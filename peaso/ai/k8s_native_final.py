"""Separate, fail-closed admission for reviewed K8s Hardening failures.

The saved-pair qualification is offline only. Runtime use requires a separate
operator switch and exact manifest digest; both are absent by default.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


MANIFEST = Path(__file__).with_name("k8s_native_final_allowlist.json")
SOURCE = Path(__file__).resolve().parents[1] / "checks/k8s_extended.py"
SOURCE_SCAN = "05a1919efd1849d99c2ae8e6b8637b6f"
SNAPSHOT_ID = "sha256:936d10ad96a726229ef233bc370bf425a9a7724415b9790a61591c9e510aef59"
ELIGIBLE = frozenset({"k8s.deployment.non_root", "k8s.replicaset.non_root"})
# Root pins the reviewed hosted quality/cost receipt after the paired replay.
HOSTED_RECEIPT_SHA256 = None


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value)


def admitted_check_ids(path=MANIFEST):
    """Admit only the two replayed IDs under an exact operator pin."""
    if os.getenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED") != "1":
        return frozenset()
    pin = os.getenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256", "")
    if not _digest(pin):
        return frozenset()
    try:
        body = Path(path).read_bytes()
        if hashlib.sha256(body).hexdigest() != pin:
            return frozenset()
        value = json.loads(body)
        if (type(value) is not dict or set(value) != {
                "version", "source_scan_id", "snapshot_id", "source_sha256",
                "audit_receipt_sha256", "qualification", "checks"}
                or type(value["version"]) is not int or value["version"] != 1
                or value["source_scan_id"] != SOURCE_SCAN
                or value["snapshot_id"] != SNAPSHOT_ID
                or not _digest(value["audit_receipt_sha256"])
                or not _digest(value["source_sha256"])
                or hashlib.sha256(SOURCE.read_bytes()).hexdigest() != value["source_sha256"]):
            return frozenset()
        qualification = value["qualification"]
        if (type(qualification) is not dict or set(qualification) != {
                "status", "hosted_cost_gate"}
                or qualification["status"] != "qualified"
                or not _digest(HOSTED_RECEIPT_SHA256)
                or qualification["hosted_cost_gate"] != HOSTED_RECEIPT_SHA256):
            return frozenset()
        checks = value["checks"]
        if type(checks) is not list or len(checks) != len(ELIGIBLE):
            return frozenset()
        ids = set()
        for check in checks:
            if (type(check) is not dict or set(check) != {
                    "check_id", "reviewed_failures", "disagreements",
                    "source_rechecks"}
                    or check["check_id"] not in ELIGIBLE
                    or check["check_id"] in ids
                    or type(check["reviewed_failures"]) is not int
                    or check["reviewed_failures"] != 15
                    or type(check["disagreements"]) is not int
                    or check["disagreements"] != 0
                    or type(check["source_rechecks"]) is not int
                    or check["source_rechecks"] != 15):
                return frozenset()
            ids.add(check["check_id"])
        return frozenset(ids) if ids == ELIGIBLE else frozenset()
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


def partition(rows, admitted):
    """Select only original K8s Hardening FAILs with complete source evidence."""
    native, ai = [], []
    for row in rows:
        evidence = row.get("evidence")
        if (row.get("provider") == "k8s"
                and row.get("category") == "hardening"
                and row.get("status") == "FAIL"
                and row.get("scanner_status", "FAIL") == "FAIL"
                and not (isinstance(evidence, dict)
                         and "incomplete_dependencies" in evidence)
                and row.get("check_id") in admitted):
            native.append(row)
        else:
            ai.append(row)
    return native, ai
