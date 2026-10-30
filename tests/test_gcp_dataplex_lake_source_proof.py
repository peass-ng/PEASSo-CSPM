"""Exact source reversals without rewriting shared or historical epoch pins."""
import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / 'docs/perf/gcp-dataplex-lake-location-source-proof-20261029.json'
PROOF_SHA256 = '6ee450225cd894225d6617db5f36714b5ae691cca23aaed3fb66e28ea74a491f'


def predecessor(current, row):
    assert hashlib.sha256(current).hexdigest() == row['after_sha256']
    lines = current.decode().splitlines(keepends=True)
    for edit in reversed(row['inverse_edits']):
        assert lines[edit['start']:edit['end']] == edit['current']
        lines[edit['start']:edit['end']] = edit['predecessor']
    result = ''.join(lines).encode()
    assert hashlib.sha256(result).hexdigest() == row['before_sha256']
    return result


def test_exact_lake_location_successors_reverse_and_reject_other_bytes():
    raw = PROOF.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PROOF_SHA256
    proof = json.loads(raw)
    for row in proof['reversible_source_changes']:
        current = (ROOT / row['path']).read_bytes()
        predecessor(current, row)
        with pytest.raises(AssertionError):
            predecessor(current + b'\n', row)
    for name, digest in proof['new_source'].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    assert proof['direct_sdk_sites'] == 29
    assert proof['dynamic_client_error'] is None
