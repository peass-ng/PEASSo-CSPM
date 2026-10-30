"""A future federated credential interception requires manual verification."""
from __future__ import annotations

import json
from pathlib import Path

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
MANUAL_ID = "gcp-firebaseauth-configs-update-exact-idp-principal"


def test_blocking_function_credential_path_is_excluded_from_scan_and_ui():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    assert MANUAL_ID not in active
    assert "gcp-firebase-signblob-exact-custom-token-user" in active
    # PR #181 recorded these exclusions in _excluded_main_reconciliation.yaml; every
    # catalog/gcp/_excluded*.yaml file is part of the excluded catalog.
    excluded = "\n".join(path.read_text() for path in sorted((ROOT / "peaso/privesc/catalog/gcp").glob("_excluded*.yaml")))
    assert MANUAL_ID in excluded and "Manual-only path" in excluded
    for name in ("finding_explanation.json", "gcp_observed_impact.json"):
        assert MANUAL_ID not in json.loads((ROOT / "peaso/privesc" / name).read_text())
    fixture = json.loads((ROOT / "tests/fixtures/shared_evidence_review.json").read_text())
    assert all(row.get("id") != MANUAL_ID for row in fixture)
