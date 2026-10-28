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
ROOT = Path(__file__).resolve().parents[2]
HOSTED = ROOT / "outputs/k8s-native-final-hosted-v2.json"
AUDIT_SHA = "de5c535087a27a942cf546af5929477c393b8e127495e64f4834994aece72556"
CHECKS_SHA = "05f9e30a7a16ac7f8e590d152a39aa08eaa58e0cf563ed6996048ede7ed9e24e"


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value)


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _audited_ids():
    try:
        checks = json.loads(MANIFEST.read_bytes())["checks"]
        body = json.dumps(checks, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(body).hexdigest() != CHECKS_SHA or len(checks) != 43:
            return frozenset()
        return frozenset(row["check_id"] for row in checks)
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


ELIGIBLE = _audited_ids()

def admitted_check_ids(path=MANIFEST):
    """Require a pinned v2 manifest and completed hosted qualification."""
    if os.getenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED") != "1":
        return frozenset()
    pin = os.getenv("PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256", "")
    if not _digest(pin) or not ELIGIBLE:
        return frozenset()
    try:
        body = Path(path).read_bytes()
        if hashlib.sha256(body).hexdigest() != pin:
            return frozenset()
        value = json.loads(body)
        if (type(value) is not dict or set(value) != {
                "version", "audit_receipt_sha256", "qualification", "checks"}
                or value["version"] != 2
                or value["audit_receipt_sha256"] != AUDIT_SHA):
            return frozenset()
        qualification = value["qualification"]
        if (type(qualification) is not dict or set(qualification) != {
                "status", "hosted_cost_gate", "hosted_receipt_sha256"}
                or qualification["status"] != "hosted_qualified"
                or qualification["hosted_cost_gate"] != "passed"
                or not _digest(qualification["hosted_receipt_sha256"])
                or _sha(HOSTED) != qualification["hosted_receipt_sha256"]):
            return frozenset()
        hosted = json.loads(HOSTED.read_bytes())
        if (hosted.get("version") != 2 or hosted.get("status") != "qualified"
                or hosted.get("paired_run_count") != 2
                or hosted.get("admitted_check_ids") != 43
                or hosted.get("audit_receipt_sha256") != AUDIT_SHA):
            return frozenset()
        checks = value["checks"]
        if (type(checks) is not list or len(checks) != 43 or
                hashlib.sha256(json.dumps(checks, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != CHECKS_SHA):
            return frozenset()
        seen = set()
        for check in checks:
            if type(check) is not dict or set(check) != {
                    "check_id", "reviewed_failures", "initial_representatives",
                    "disagreements", "source_rechecks", "source"}:
                return frozenset()
            cid = check["check_id"]
            if cid not in ELIGIBLE or cid in seen:
                return frozenset()
            if (type(check["reviewed_failures"]) is not int
                    or check["reviewed_failures"] <= 0
                    or type(check["initial_representatives"]) is not int
                    or check["initial_representatives"] <= 0
                    or check["disagreements"] != 0
                    or check["source_rechecks"] != check["reviewed_failures"]
                    or _sha(ROOT / check["source"]["path"]) != check["source"]["sha256"]):
                return frozenset()
            seen.add(cid)
        return frozenset(seen) if seen == ELIGIBLE else frozenset()
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


def partition(rows, admitted, coverage=None):
    """Select only original K8s Hardening FAILs with complete source evidence."""
    from .native_final_coverage import complete_scopes

    complete = complete_scopes(coverage, set(admitted) & ELIGIBLE)
    native, ai = [], []
    for row in rows:
        evidence = row.get("evidence")
        if (row.get("provider") == "k8s"
                and row.get("category") == "hardening"
                and row.get("status") == "FAIL"
                and row.get("scanner_status", "FAIL") == "FAIL"
                and not (isinstance(evidence, dict)
                         and "incomplete_dependencies" in evidence)
                and row.get("check_id") in admitted
                and (row.get("check_id"), row.get("scope")) in complete):
            native.append(row)
        else:
            ai.append(row)
    return native, ai
