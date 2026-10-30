"""Immutable artifact reuse never replaces a live admission decision."""
from itertools import product
from pathlib import Path
import re

import pytest
from peaso import private_secret_source_epoch_20261021 as source

ROOT = Path(__file__).resolve().parents[1]




def test_authenticated_code_artifact_is_reused_after_fresh_self_proof():
    source._self()
    path = Path(source.__file__)
    raw = path.read_bytes()
    first = source._self_cached_code(path, raw)
    source._self()
    second = source._self_cached_code(path, raw)
    assert first[0] is second[0]
    assert first[1] == second[1]


def test_mutable_code_is_never_retained_even_when_both_vectors_match():
    source._self()
    original = source._relative.__code__
    mutable = original.replace(co_consts=original.co_consts + ([],))
    before = set(source._SELF_CODE_CACHE_STORAGE)
    with pytest.raises(ValueError, match='mutable code vector refused'):
        source._SELF_CODE_CACHE(Path(source.__file__), Path(source.__file__).read_bytes(),
                                ((mutable,), (mutable,)))
    assert set(source._SELF_CODE_CACHE_STORAGE) == before


def test_private_producer_code_cache_is_source_keyed(tmp_path):
    file = tmp_path / 'native.py'
    first_raw = b'def native(): return 1\n'
    file.write_bytes(first_raw)
    first = source._expected_helper_code(file, first_raw, str(file))
    assert source._expected_helper_code(file, first_raw, str(file)) is first
    second_raw = b'def native(): return 2\n'
    file.write_bytes(second_raw)
    second = source._expected_helper_code(file, second_raw, str(file))
    assert second is not first


def test_parsed_receipt_artifact_returns_fresh_unmodified_objects():
    receipt, rows = source._receipt()
    path = next(iter(rows))
    original = rows[path]['after_sha256']
    rows[path]['after_sha256'] = 'foreign'
    receipt['sources'].clear()
    again, restored = source._receipt()
    assert restored[path]['after_sha256'] == original
    assert len(again['sources']) == 50
    assert again is not receipt and restored is not rows
    assert all(restored[row['path']] is row for row in again['sources'])


def test_parsed_receipt_artifact_bytes_tamper_is_rejected(monkeypatch):
    source._receipt()
    path = Path(source.__file__).with_suffix('.json')
    key = next(k for k in source._SELF_CODE_CACHE_STORAGE if k[0] == str(path))
    code, metadata, signature = source._SELF_CODE_CACHE_STORAGE[key]
    monkeypatch.setitem(source._SELF_CODE_CACHE_STORAGE, key,
        (code, (metadata[0], metadata[1] + b'foreign'), signature))
    with pytest.raises(source.AdmissionError, match='parsed artifact mismatch'):
        source._receipt()


def test_literal_equality_keeps_type_and_arbitrary_key_semantics():
    def previous(a, b):
        if type(a) is not type(b): return False
        if type(a) is re.Pattern: return a.pattern == b.pattern and a.flags == b.flags
        if isinstance(a, (tuple, list)):
            return len(a) == len(b) and all(previous(x, y) for x, y in zip(a, b))
        if isinstance(a, dict):
            return len(a) == len(b) and all(any(previous(k, q) and previous(v, w)
                for q, w in b.items()) for k, v in a.items())
        if isinstance(a, (set, frozenset)):
            return len(a) == len(b) and all(any(previous(x, y) for y in b) for x in a)
        return a == b
    cases = [None, False, 0, True, 1, 'x', {'a': False}, {'a': 0}, {'a': [1, None]},
             {'b': 1, 'a': 'x'}, {'a': 'x', 'b': 1}, {False: 'x'}, {0: 'x'},
             {(1,): 'x'}, {'a': {'b': frozenset({1})}}, {'a': {'b': {True}}}]
    for a, b in product(cases, repeat=2):
        assert source._same(a, b) == previous(a, b)


