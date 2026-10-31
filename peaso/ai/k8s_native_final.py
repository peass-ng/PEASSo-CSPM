"""Separate, fail-closed admission for reviewed K8s Hardening failures.

The saved-pair qualification is offline only. Runtime use requires a separate
operator switch and a hosted-qualified manifest; both are absent by default.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


MANIFEST = Path(__file__).with_name("k8s_native_final_allowlist.json")


def _audited_ids():
    try:
        checks = json.loads(MANIFEST.read_bytes())["checks"]
        return frozenset(row["check_id"] for row in checks)
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


ELIGIBLE = _audited_ids()

def admitted_check_ids(path=MANIFEST):
    """Require the enable switch and a hosted-qualified v2 manifest."""
    if os.getenv("PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED") != "1" or not ELIGIBLE:
        return frozenset()
    try:
        value = json.loads(Path(path).read_bytes())
        if (type(value) is not dict or set(value) != {"version", "qualification", "checks"}
                or value["version"] != 2):
            return frozenset()
        qualification = value["qualification"]
        if (type(qualification) is not dict or set(qualification) != {
                "status", "hosted_cost_gate"}
                or qualification["status"] != "hosted_qualified"
                or qualification["hosted_cost_gate"] != "passed"):
            return frozenset()
        checks = value["checks"]
        if type(checks) is not list:
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
                    or check["source_rechecks"] != check["reviewed_failures"]):
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
