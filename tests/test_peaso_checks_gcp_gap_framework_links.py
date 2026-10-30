"""GCP framework-link re-adjudications: defective upstream predicates whose control intent has a corrected native."""
import json
from pathlib import Path

from peaso.checks import CHECKS
from peaso.checks.catalog import framework_names_for

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "peaso" / "rulepacks"


def rows():
    return [r for r in json.loads((PACK / "upstream_manifest.json").read_text())["checks"]
            if r["provider"] == "gcp" and r.get("review_classification") == "corrected_native_merge"]


def test_corrected_merges_keep_defect_evidence_and_real_natives():
    selected = rows()
    assert len(selected) == 113
    registry = {c.id for c in CHECKS}
    for row in selected:
        assert row["disposition"] == "merged" and set(row["native_checks"]) <= registry, row["check_id"]
        assert row["upstream_defect"]["classification"] == "invalid_predicate" and row["upstream_defect"]["reason"]
        # Only reviewer-declared replacements, natives authored for the same query, or a recorded
        # re-verification target are used.
        verified = row.get("native_equivalence_verification", {}).get("target_native_checks", [])
        assert set(row["native_checks"]) <= set(row.get("replacement_checks", []) + row.get("replacement_native_checks", []) + verified) | {
            c.id for c in CHECKS if c.id.split(".")[-1] in [row["upstream_id"]] + row["upstream_evaluator"].get("query_ids", [])}


def test_example_cis_gcp_v120_corporate_domain_now_labels_native():
    names = framework_names_for("gcp.ports.iam_corporate_domain_declaration")
    assert any("CIS" in name and "1.2.0" in name for name in names), names
