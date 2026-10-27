"""Authorized routine indirect access requires manual proof."""

import json
from pathlib import Path
import yaml

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
ID = "gcp-bigquery-authorized-routine-bounded-table-access"


def test_authorized_routine_is_not_runnable_or_displayed():
    assert ID not in {entry["id"] for entry in privesc.catalog()["entries"]}
    for file in ("peaso/privesc/gcp_observed_impact.json",
                 "peaso/privesc/finding_explanation.json"):
        assert ID not in json.loads((ROOT / file).read_text())
    excluded = yaml.safe_load((ROOT / "peaso/privesc/catalog/gcp/_excluded.yaml").read_text())
    record, = (row for row in excluded if row.get("id") == ID)
    assert record["reason"].startswith("Manual-only:")
    assert record["source"].startswith("src/pentesting-cloud/gcp-security/")
