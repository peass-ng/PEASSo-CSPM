"""Exact current bytes reviewed after the 2026-10-20 whole-tree conservation epochs.

Two tests pin every file of an earlier package and allow only recorded
successor bytes.  Later integrations changed further files without extending
those maps.  This fixture records, per test, each such file as
``[before_sha256, previously_recorded_after_sha256_or_None, after_sha256, after_size]``.
Earlier rows must still match what they replace, so prior records are never
rewritten silently, and the tests still compare every byte against these rows.
"""
import gzip
import hashlib
import json
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'reviewed_current_successors_20261026.json.gz'
FIXTURE_SHA256 = '0da6969c1a2daa29eaf495af6fe704b6facbaef38c51751716cc48f22533fe69'


def _load():
    raw = FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256, 'Reviewed current successor fixture changed'
    value = json.loads(gzip.decompress(raw))
    assert value['schema'] == 1
    return value


def extend(section, reviewed, reviewable):
    """Add this section's successor rows to ``reviewed`` and return the widened path set."""
    rows = _load()[section]
    for name in rows['reverted']:
        reviewed.pop(name)
    for name, (before, prior_after, after, size) in rows['changes'].items():
        prior = reviewed.get(name)
        assert (prior['after_sha256'] if prior else None) == prior_after, name
        assert prior is None or prior['before_sha256'] == before, name
        assert after != before and type(size) is int and size > 0, name
        reviewed[name] = {'before_sha256': before, 'after_sha256': after, 'after_size': size}
    return frozenset(reviewable) | frozenset(rows['changes'])
