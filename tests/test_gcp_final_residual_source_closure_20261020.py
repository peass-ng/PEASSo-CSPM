"""Portable source and fixture closure for six bounded GCP residual cohorts."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'tests/fixtures/gcp-final-residual-source-closure-20261020.json'
SHA256 = 'd7e42eb82722d28c9b22c3abc338b9ac361e0b754c720d425ff4f320d5d44b23'


def test_exact_historical_tests_and_current_source_fixture_closure():
    raw = (ROOT / MANIFEST).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA256
    receipt = json.loads(raw)
    archive = receipt['predecessor_archive']
    packed = (ROOT / archive['path']).read_bytes()
    assert hashlib.sha256(packed).hexdigest() == archive['sha256']
    historical = json.loads(gzip.decompress(packed))
    assert set(historical) == set(receipt['check_ids']) == set(receipt['predecessor_test_sha256'])
    for path, source in historical.items():
        assert hashlib.sha256(source.encode()).hexdigest() == receipt['predecessor_test_sha256'][path]
    for field in ('current_test_sha256', 'source_fixture_closure'):
        for path, sha in receipt[field].items():
            assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == sha, path
