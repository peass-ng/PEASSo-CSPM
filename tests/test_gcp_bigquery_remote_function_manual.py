"""Remote function application effects require manual review, outside the scan."""

import json
from pathlib import Path
import yaml

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
ID = "gcp-bigquery-remote-function-bounded-cloudrun-invoke"


def test_manual_only_remote_function_path_is_not_runnable_or_displayed():
    assert ID not in {entry["id"] for entry in privesc.catalog()["entries"]}
    for file in ("peaso/privesc/gcp_observed_impact.json",
                 "peaso/privesc/finding_explanation.json"):
        assert ID not in json.loads((ROOT / file).read_text())
    fixture = json.loads((ROOT / "tests/fixtures/shared_evidence_review.json").read_text())
    assert ID not in {row.get("id") for row in fixture}
    excluded = yaml.safe_load((ROOT / "peaso/privesc/catalog/gcp/_excluded.yaml").read_text())
    record, = (row for row in excluded if row.get("id") == ID)
    assert record["reason"].startswith("Manual-only:")
    assert record["source"].startswith("src/pentesting-cloud/gcp-security/")
