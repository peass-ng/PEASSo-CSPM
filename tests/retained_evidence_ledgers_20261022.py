"""Exact predecessor bytes for evidence-review ledgers that later gained checks.

The 2026-10-22 native successor cohorts appended checks to the live GCP and
Kubernetes ledgers.  Receipts written before that still pin the earlier bytes.
The earlier ledger is the current one without the recorded successor checks and
with its own registered count; every retained row must be byte-identical.
"""
import hashlib
import json
from pathlib import Path

# Live ledger path -> (successor cohort record, predecessor registered_check_count).
SUCCESSORS = {
    'docs/evidence-reviews/gcp.json': ('docs/evidence-reviews/gcp-current-native-successor-20261022.json', 536),
    'docs/evidence-reviews/k8s.json': ('docs/evidence-reviews/k8s-current-native-successor-20261022.json', 1006),
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ledger_bytes(root, path, sha256):
    """Return the ledger bytes pinned by ``sha256``, live or exactly reconstructed."""
    root = Path(root)
    raw = (root / path).read_bytes()
    if _sha(raw) == sha256 or path not in SUCCESSORS:
        return raw
    record_path, registered = SUCCESSORS[path]
    record = json.loads((root / record_path).read_bytes())
    assert record['prior_ledger'] == path and record['prior_ledger_sha256'] == sha256, path
    current = json.loads(raw)
    added = set(record['added'])
    assert added <= set(current['checks']), path
    prior = {**current, 'registered_check_count': registered,
             'checks': {cid: row for cid, row in current['checks'].items() if cid not in added}}
    assert len(prior['checks']) == record['prior_count'], path
    restored = (json.dumps(prior, indent=2) + '\n').encode()
    assert _sha(restored) == sha256, path
    return restored
