"""Source-only App Hosting repointing remains documented but cannot emit a scan edge."""
from __future__ import annotations

import json
from pathlib import Path

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
MANUAL_ID = "gcp-firebaseapphosting-backends-update-source"


def test_source_only_repointing_is_excluded_from_active_catalog_and_ui_copy():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    assert MANUAL_ID not in active
    assert "gcp-firebaseapphosting-backends-update-actas" in active
    assert "gcp-firebaseapphosting-build-rollout-existing-backend" in active
    # PR #181 recorded these exclusions in _excluded_main_reconciliation.yaml; every
    # catalog/gcp/_excluded*.yaml file is part of the excluded catalog.
    excluded = "\n".join(path.read_text() for path in sorted((ROOT / "peaso/privesc/catalog/gcp").glob("_excluded*.yaml")))
    assert MANUAL_ID in excluded and "Manual-only path" in excluded
    for path in (ROOT / "peaso/privesc/finding_explanation.json",
                 ROOT / "peaso/privesc/gcp_observed_impact.json"):
        assert MANUAL_ID not in json.loads(path.read_text())
