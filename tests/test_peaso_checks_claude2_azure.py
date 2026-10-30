"""Shard integrity for the claude2_azure partition, validated in memory without regenerating central artifacts."""
from peaso.checks.hacktricks_scope import includes
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.claude2_azure_common import CHECK_IDS, PREFIX
from peaso.checks.fixtures import CASES
import peaso.checks.claude2_azure  # noqa: F401  (registration side effect)

PACK = Path(__file__).resolve().parent.parent / "peaso" / "rulepacks"
REVIEWED = json.loads((PACK / "reviewed_claude2_azure.json").read_text())
REGISTRY = {check.id: check for check in CHECKS}
# reviewed_claude_azure.json rejects the MMK leftover (deferral lifted by the supervisor); its rejection wins.
def test_supported_rows_reference_registered_predicates():
    for key, entry in REVIEWED.items():
        assert entry["disposition"] in ("ported", "merged", "rejected"), key
        assert entry["reason"] and entry["official_docs"], key
        assert all(url.startswith("https://learn.microsoft.com/") for url in entry["official_docs"]), key
        if entry["disposition"] == "rejected":
            assert entry["native_checks"] == [], key
        else:
            assert entry["native_checks"] and all(cid in REGISTRY for cid in entry["native_checks"]), key
            if entry["disposition"] == "ported":
                assert any(cid.startswith(PREFIX) for cid in entry["native_checks"]), key


def test_orphaned_predicates_were_removed():
    slug = PREFIX + "storage_account_microsoft_managed_keys"
    assert slug not in REGISTRY and slug not in CASES


def test_every_claude2_predicate_is_claimed():
    claimed = {cid for entry in REVIEWED.values() for cid in entry["native_checks"]}
    assert set(CHECK_IDS) <= claimed, sorted(set(CHECK_IDS) - claimed)


def test_no_predicate_iterates_builtin_role_definitions_per_subscription():
    role_checks = [REGISTRY[c] for c in CHECK_IDS if REGISTRY[c].kind == "role_definition"]
    assert role_checks and all(check.target == "scope" for check in role_checks)


@pytest.mark.parametrize("cid", CHECK_IDS)
def test_predicate_contract(cid):
    check = REGISTRY[cid]
    assert check.provider == "azure" and (HACKTRICKS in check.frameworks) == includes(check.id)
    assert check.remediation and check.dependencies
    cases = CASES[cid]
    assert "pass" in cases and "fail" in cases
    assert check.evaluate(cases.get("missing", {}), cases.get("pass_index", {}))[0] == "UNKNOWN"
    assert check.evaluate(None, {})[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"
