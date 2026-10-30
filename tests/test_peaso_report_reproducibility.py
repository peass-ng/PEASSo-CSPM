"""Saved snapshot assessments survive JSON key ordering and process hash seeds."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from peaso.demo import demo_snapshot
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def test_runtime_metadata_string_sharing_preserves_values_and_container_independence():
    from peaso.checks.catalog import PACK, _shared_metadata_strings
    for name in ('runtime_metadata.json', 'compliance_lookup.json', 'check_descriptions.json'):
        raw = (PACK / name).read_text()
        ordinary = json.loads(raw)
        shared = json.loads(raw, object_hook=_shared_metadata_strings)
        assert shared == ordinary
    repeated = '{"a":{"label":"repeated-public-label","values":["repeated-public-label"]},"b":{"label":"repeated-public-label","values":["repeated-public-label"]}}'
    value = json.loads(repeated, object_hook=_shared_metadata_strings)
    assert value['a']['label'] is value['b']['label'] is value['a']['values'][0]
    assert value['a'] is not value['b'] and value['a']['values'] is not value['b']['values']
    value['a']['values'].append('new')
    assert value['b']['values'] == ['repeated-public-label']


def test_azure_storage_endpoint_selection_survives_sorted_json():
    scope = "/subscriptions/sub-one"
    endpoints = {name: f"https://storage.{name}.example/" for name in
                 ("web", "table", "queue", "file", "dfs", "blob")}
    item = {"id": scope + "/providers/Microsoft.Storage/storageAccounts/storage",
            "properties": {"primaryEndpoints": endpoints, "networkAcls": {"defaultAction": "Allow"},
                           "supportsHttpsTrafficOnly": True, "allowBlobPublicAccess": True}}
    snapshot = make_snapshot("azure", [scope], [{"type": "storage_account", "scope": scope,
        "status": "collected", "items": [item]}], created_at="2026-10-14T00:00:00Z")
    options = {"categories": ["exposure", "network"]}
    before = evaluate_snapshot(snapshot, **options)
    after = evaluate_snapshot(json.loads(json.dumps(snapshot, sort_keys=True)), **options)
    assert before == after
    observed = [row["evidence"]["public_addresses"] for row in before["findings"]
                if row["check_id"] == "analysis.internet_exposure" and row["evidence"].get("public_addresses")]
    assert observed == [sorted(endpoints.values())]


@pytest.mark.parametrize("provider", ["azure", "gcp", "k8s"])
def test_network_reports_are_equal_across_process_hash_seeds(tmp_path, provider):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(demo_snapshot(provider)))
    command = [sys.executable, "-c", (
        "import json,sys; from peaso.engine import evaluate_snapshot; "
        "snapshot=json.load(open(sys.argv[1])); "
        "print(json.dumps(evaluate_snapshot(snapshot,categories=['exposure','network']),sort_keys=True))"
    ), str(path)]
    # A cold child process verifies and installs the full attested check registry
    # before evaluating; the bound covers that startup, not the comparison.
    reports = [subprocess.check_output(command, env=dict(os.environ, PYTHONHASHSEED=seed),
               cwd=Path(__file__).resolve().parents[1], text=True, timeout=600) for seed in ("1", "77")]
    assert json.loads(reports[0]) == json.loads(reports[1])
