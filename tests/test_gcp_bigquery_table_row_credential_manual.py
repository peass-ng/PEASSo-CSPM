"""Table-row credential recovery requires manual inspection and never enters the CSPM UI."""

import json
from pathlib import Path
import yaml

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
TECHNIQUE = "gcp-bigquery-table-row-credential"


def test_manual_only_table_row_credential_is_not_runnable_or_displayed():
    assert TECHNIQUE not in {entry["id"] for entry in privesc.catalog()["entries"]}
    for name in ("peaso/privesc/gcp_observed_impact.json",
                 "peaso/privesc/finding_explanation.json"):
        assert TECHNIQUE not in json.loads((ROOT / name).read_text())
    fixture = json.loads((ROOT / "tests/fixtures/shared_evidence_review.json").read_text())
    assert TECHNIQUE not in {row.get("id") for row in fixture}
    excluded = yaml.safe_load((ROOT / "peaso/privesc/catalog/gcp/_excluded.yaml").read_text())
    record, = (row for row in excluded if row.get("id") == TECHNIQUE)
    assert record["reason"].startswith("Manual-only:")
    assert record["source"].startswith("src/pentesting-cloud/gcp-security/")
