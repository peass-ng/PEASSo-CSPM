"""Larger bounded batches retain every original source and private RawV2 value."""
import json
import pytest
from peaso import secret_scanning as scanning, secret_scanning_batch as batch, secret_evidence
from peaso.collectors import aws_package_content_indicators as packages

class FixtureCipher:
    # Synthetic-only adapter: the test checks attribution, not encryption.
    def encrypt(self, value): return json.dumps(value, sort_keys=True)
    def decrypt(self, value): return json.loads(value)

def test_512_sources_keep_private_full_values_and_original_paths(monkeypatch):
    assert batch.MAX_BATCH_ITEMS == packages.BATCH_ITEMS == 512
    assert batch.MAX_BATCH_BYTES == packages.BATCH_BYTES == 64 * 1024 * 1024
    primary = 'synthetic-primary'
    full = primary + ':' + 'A' * 40
    items = [((full + '\nsource=' + str(i)).encode(), 'original/' + str(i)) for i in range(512)]
    def prepare(items, timeout):
        return {item: json.dumps({'Raw': primary, 'RawV2': full, 'Verified': False,
                                 'DetectorName': 'AWS'}).encode() for item in items}
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', prepare)
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(scanning, '_run', lambda *args: pytest.fail('prepared sources must avoid serial scanner'))
    scanning._RESULTS.clear()
    cipher = FixtureCipher()
    with secret_evidence.capture(cipher, tenant='synthetic', scan_id='synthetic') as sink:
        with secret_evidence.source_context(resource_id='native-resource', scope='native-scope', location_kind='file'):
            with scanning.prepared_content_batch(items):
                outcomes = [scanning.scan_content(payload, path) for payload, path in items]
        for value in (primary, full):
            record = cipher.decrypt(sink.records[scanning._fingerprint(value)])
            assert {loc['path'] for loc in record['locations']} == {path for _, path in items}
            assert all(loc['resource_id'] == 'native-resource' and loc['scope'] == 'native-scope'
                       for loc in record['locations'])
        assert not sink.incomplete
    assert all(outcome['complete'] and len(outcome['leaks']) == 1 for outcome in outcomes)
    assert primary not in json.dumps(outcomes)
    assert batch._PREPARED_BATCH.get() is None
    scanning._RESULTS.clear()

def test_513_sources_remain_outside_finite_bound(monkeypatch):
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', lambda *args: pytest.fail('invalid batch reached scanner'))
    with pytest.raises(ValueError, match='content batch bound'):
        with batch.prepared_content_batch([(b'x', 'path')] * 513):
            pass


def test_exact_64mib_input_bound_keeps_source_bytes(monkeypatch):
    from peaso import secret_scan_clean
    monkeypatch.setattr(secret_scan_clean, 'known_clean', lambda payload: True)
    left, right = b'a' * (32 * 1024 * 1024), b'b' * (32 * 1024 * 1024)
    with batch.prepared_content_batch([(left, 'left'), (right, 'right')]):
        assert batch._PREPARED_BATCH.get() is None
    with pytest.raises(ValueError, match='content batch bound'):
        with batch.prepared_content_batch([(left, 'left'), (right + b'x', 'right')]):
            pass
