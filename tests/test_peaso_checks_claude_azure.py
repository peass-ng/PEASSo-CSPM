"""Shard integrity for the claude_azure partition, validated in memory without regenerating central artifacts."""
from peaso.checks.hacktricks_scope import includes
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, HACKTRICKS, resolve_check_id
from peaso.checks.claude_azure_common import CHECK_IDS, PREFIX
from peaso.checks.fixtures import CASES
import peaso.checks.claude_azure  # noqa: F401  (registration side effect)

PACK = Path(__file__).resolve().parent.parent / "peaso" / "rulepacks"
REVIEWED = json.loads((PACK / "reviewed_claude_azure.json").read_text())
MANUAL = json.loads((PACK / "reviewed_claude_azure_manual.json").read_text())
REGISTRY = {check.id: check for check in CHECKS}


def test_supported_rows_reference_registered_claude_predicates():
    for key, entry in REVIEWED.items():
        assert entry["disposition"] in ("ported", "merged", "rejected"), key
        assert entry["reason"], key
        if entry["disposition"] == "rejected":
            assert entry["native_checks"] == [], key
            assert entry.get("official_docs") or entry.get("review_notes"), key
        else:
            assert entry["native_checks"], key
            for cid in entry["native_checks"]:
                assert resolve_check_id(cid) in REGISTRY, cid
            if entry["disposition"] == "ported":
                # A ported row may be a conjunction of a new predicate and an existing native one.
                assert any(cid.startswith(PREFIX) for cid in entry["native_checks"]), key


def test_manual_rows_preserve_question():
    for key, entry in MANUAL.items():
        assert entry["disposition"] == "rejected" and entry["native_checks"] == [], key
        assert entry["review_classification"] == "manual_attestation", key
        assert entry["manual_requirement"]["question"], key


def test_every_claude_predicate_is_claimed_by_a_review():
    from peaso.checks.azure_gap_nsg import EXPOSURE_ONLY_NATIVES
    claimed = {cid for entry in REVIEWED.values() for cid in entry["native_checks"]}
    # Priority-aware NSG exposure natives deliberately carry no compliance row (those controls are declaration
    # audits served by azure.gap.nsg_declared_internet_*); each must have been a former target of such a row.
    former = {cid for entry in REVIEWED.values() for cid in entry.get("former_native_checks", [])}
    assert set(EXPOSURE_ONLY_NATIVES) <= former and not set(EXPOSURE_ONLY_NATIVES) & claimed
    assert set(CHECK_IDS) - set(EXPOSURE_ONLY_NATIVES) <= claimed, sorted(set(CHECK_IDS) - claimed - set(EXPOSURE_ONLY_NATIVES))


@pytest.mark.parametrize("cid", CHECK_IDS)
def test_claude_predicate_contract(cid):
    check = REGISTRY[cid]
    assert check.provider == "azure" and (HACKTRICKS in check.frameworks) == includes(check.id)
    assert check.remediation and check.dependencies
    cases = CASES[cid]
    if cid == "azure.claude.iam_root_custom_role_no_wildcard":
        # Azure RBAC does not support a root '/' CustomRole assignable scope.
        # The valid ordinary scope is outside this obsolete source predicate;
        # historical or malformed root evidence needs owner review.
        assert "pass" not in cases and "fail" not in cases
        assert check.evaluate(cases["not_applicable"], {})[0] == "NOT_APPLICABLE"
        assert check.evaluate(cases["unknown"], {})[0] == "UNKNOWN"
    else:
        assert "pass" in cases and "fail" in cases
    assert check.evaluate(cases.get("missing", {}), cases.get("index", {}))[0] == "UNKNOWN"
    assert check.evaluate(None, {})[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"
