"""Exact predecessor bytes for evidence-review ledgers that later gained checks.

The 2026-10-22 native successor cohorts appended checks to the live GCP and
Kubernetes ledgers.  Receipts written before that still pin the earlier bytes.
The earlier ledger is the current one without the recorded successor checks and
with its own registered count; every retained row must be byte-identical.
Later reviewed re-pins of retained rows are listed in ``REPINNED`` as exact
``(before, after, count)`` digest substitutions and are reversed first.
"""
import hashlib
import json
from pathlib import Path

# Live ledger path -> (successor cohort record, predecessor registered_check_count).
SUCCESSORS = {
    'docs/evidence-reviews/gcp.json': ('docs/evidence-reviews/gcp-current-native-successor-20261022.json', 536),
    'docs/evidence-reviews/k8s.json': ('docs/evidence-reviews/k8s-current-native-successor-20261022.json', 1006),
}

# Live ledger path -> exact digest re-pins made after the successor cohort.
REPINNED = {
    'docs/evidence-reviews/gcp.json': (
        # 5826f6d2 moved per-resource proofs to prove_once in the Workbench head3
        # source; the three head3 rows and the Cloud Run job runtime receipt were re-pinned.
        ('c974c7adbba841fa2b17a54e02fb677fe859f08eda0885c292b5be33da4b3a7d',
         '8c012bfbe24bdfbe1b5915f500ee61720f1f3a70c4eec757a428d8620c6c049c', 3),
        ('dc63589448228096c334e087e84dd299cc49ac18a53941660a7a3ba8686eb8bc',
         'e096f7f0b34d68c3eed3491f025694f49cba871d017de631d0bfb97f1e8fe08d', 1),
    ),
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
    text = raw.decode('utf-8')
    for before, after, count in REPINNED.get(path, ()):
        assert text.count(after) == count and before not in text, (path, after)
        text = text.replace(after, before)
    current = json.loads(text)
    added = set(record['added'])
    assert added <= set(current['checks']), path
    prior = {**current, 'registered_check_count': registered,
             'checks': {cid: row for cid, row in current['checks'].items() if cid not in added}}
    assert len(prior['checks']) == record['prior_count'], path
    restored = (json.dumps(prior, indent=2) + '\n').encode()
    assert _sha(restored) == sha256, path
    return restored
