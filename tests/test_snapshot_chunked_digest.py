"""Bounded collection hashing preserves canonical JSON bytes and validation."""
from copy import deepcopy
import hashlib
import json
import random

import pytest

from peaso import snapshot as snapshots


def reference(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    return 'sha256:' + hashlib.sha256(raw.encode()).hexdigest()


def document(count, provider='azure'):
    return {'schema_version': '1.0', 'provider': provider, 'scopes': ['scope'],
            'created_at': '2026-10-29T00:00:00Z', 'metadata': {'unicode': 'é🧙\n\"'},
            'collections': [
                {'type': 'audit', 'scope': 'scope', 'service': 'native', 'status': 'collected',
                 'items': [{'id': str(i), 'native_id': i, 'nested': {'array': [None, True, False, -0.0,
                            1e-30, 1e30, 2**80, 'é🧙\n\"']}} for i in range(count)],
                 'source_evidence': [{'api_version': 'native', 'complete': True}]},
                {'type': 'unavailable', 'scope': 'scope', 'status': 'denied',
                 'items': [], 'error': {'code': '403'}}]}


@pytest.mark.parametrize('provider', snapshots.PROVIDERS)
@pytest.mark.parametrize('count', [0, 1, 127, 128, 129, 257])
def test_exact_canonical_hash_across_providers_and_chunk_boundaries(provider, count):
    value = document(count, provider)
    original = deepcopy(value)
    assert snapshots.digest(value) == reference(value)
    assert value == original


def test_generated_nested_native_values_keep_exact_canonical_bytes():
    rng = random.Random(20261029)
    value = document(1025)
    for row in value['collections'][0]['items']:
        row['generated'] = {str(rng.randrange(10000)): [rng.uniform(-1e50, 1e50), rng.randrange(2**100),
                            {'text': rng.choice(['ascii', 'é', '🧙', '\u0000', '\\', '\n'])}]
                            for _ in range(4)}
    assert snapshots.digest(value) == reference(value)


@pytest.mark.parametrize('value', [
    ['ordinary', {'value': None}], {'plain': [1, 2, 3]}, {'collections': ()},
    {'collections': [None, [1, 2], 'string', {'items': ()}, {3: 'number-key'}]},
    {'collections': [{'items': [{'id': 'x'}], 'extra': {'3': [False, None]}}]},
])
def test_non_snapshot_and_non_plain_collection_fallbacks(value):
    assert snapshots.digest(value) == reference(value)


@pytest.mark.parametrize('bad', [float('nan'), float('inf'), {1, 2}, {'mixed': 1, 2: 'keys'}])
def test_invalid_native_values_keep_encoder_error_type(bad):
    value = document(257)
    value['collections'][0]['items'][-1]['invalid'] = bad
    with pytest.raises((ValueError, TypeError)) as error:
        reference(value)
    with pytest.raises(type(error.value)):
        snapshots.digest(value)


def test_cyclic_native_value_is_still_rejected():
    value = document(2)
    value['collections'][0]['items'][0]['cycle'] = value['collections'][0]['items']
    with pytest.raises(ValueError):
        snapshots.digest(value)


def test_large_inventory_uses_bounded_encodings_without_skipping_items(monkeypatch):
    value = document(4097)
    expected = reference(value)
    encoded_native_counts = []
    original = snapshots.canonical
    def measured(part):
        if isinstance(part, dict) and 'items' in part:
            assert len(part['items']) < 4097, 'encoded complete native inventory'
        if isinstance(part, list) and part and all(isinstance(item, dict) and 'native_id' in item for item in part):
            encoded_native_counts.append(len(part))
        return original(part)
    monkeypatch.setattr(snapshots, 'canonical', measured)
    assert snapshots.digest(value) == expected
    assert sum(encoded_native_counts) == 4097
    assert max(encoded_native_counts) < 4097


@pytest.mark.parametrize('provider', snapshots.PROVIDERS)
def test_shared_metadata_prefix_keeps_both_exact_digest_addresses(provider):
    value = document(257, provider)
    expected = reference(value)
    metadata = {**value['metadata'], 'collection_plan': {'checks': ['a', 'b']}}
    extended = reference({**value, 'metadata': metadata})
    first, second, actual_metadata = snapshots._digests_with_metadata(value, 'collection_plan', {'checks': ['a', 'b']})
    assert (first, second, actual_metadata) == (expected, extended, metadata)


def test_legacy_signed_snapshot_validates_and_native_tampering_still_fails():
    value = document(257)
    value['snapshot_id'] = reference(value)
    assert snapshots.validate(value)['snapshot_id'] == value['snapshot_id']
    value['collections'][0]['items'][-1]['nested']['array'].append('tampered')
    with pytest.raises(ValueError, match='digest mismatch'):
        snapshots.validate(value)
