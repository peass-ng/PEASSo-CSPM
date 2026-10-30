"""Shard integrity for the claude_gcp_k8s partition, validated in memory without regenerating central artifacts."""
from peaso.checks.hacktricks_scope import includes
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.claude_gcp_k8s_common import CHECK_IDS, PREFIXES
from peaso.checks.fixtures import CASES
import peaso.checks.claude_gcp_k8s  # noqa: F401  (registration side effect)

PACK = Path(__file__).resolve().parent.parent / "peaso" / "rulepacks"
REVIEWED = json.loads((PACK / "reviewed_claude_gcp_k8s.json").read_text())
MANUAL = json.loads((PACK / "reviewed_claude_gcp_k8s_manual.json").read_text())
REGISTRY = {check.id: check for check in CHECKS}


def test_supported_rows_reference_registered_predicates():
    for key, entry in REVIEWED.items():
        assert entry["disposition"] in ("ported", "merged", "rejected"), key
        assert entry["reason"], key
        if entry["disposition"] == "rejected":
            assert entry["native_checks"] == [], key
            assert entry.get("official_docs") or entry.get("review_notes"), key
            for cid in entry.get("replacement_checks", []):
                assert cid in REGISTRY, cid
        else:
            assert entry["native_checks"], key
            for cid in entry["native_checks"]:
                assert cid in REGISTRY, cid
            if entry["disposition"] == "ported":
                assert any(cid.startswith(PREFIXES) for cid in entry["native_checks"]), key


def test_manual_rows_preserve_question():
    assert MANUAL
    for key, entry in MANUAL.items():
        assert entry["disposition"] == "rejected" and entry["native_checks"] == [], key
        assert entry["review_classification"] == "manual_attestation", key
        assert entry["manual_requirement"]["question"], key


def test_every_claude_predicate_is_claimed_by_a_review():
    claimed = {cid for entry in REVIEWED.values() for cid in entry["native_checks"] + entry.get("replacement_checks", [])}
    assert set(CHECK_IDS) <= claimed, sorted(set(CHECK_IDS) - claimed)
    assert len(CHECK_IDS) == len(set(CHECK_IDS))


@pytest.mark.parametrize("cid", CHECK_IDS)
def test_claude_predicate_contract(cid):
    check = REGISTRY[cid]
    assert check.provider == ("gcp" if cid.startswith("gcp.") else "k8s") and (HACKTRICKS in check.frameworks) == includes(check.id)
    assert check.remediation and check.dependencies
    cases = CASES[cid]
    # Inheritance- or review-only predicates may only reach MANUAL instead of PASS or FAIL.
    assert ("pass" in cases or "manual" in cases) and ("fail" in cases or "manual" in cases)
    assert check.evaluate(cases.get("missing", {}), {})[0] == "UNKNOWN"
    assert check.evaluate(None, {})[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"
