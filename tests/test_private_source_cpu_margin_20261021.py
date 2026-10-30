"""Immutable artifact reuse never replaces a live admission decision."""
from itertools import product
from pathlib import Path, PurePosixPath
import hashlib
import re
import sys

import pytest
from peaso import private_secret_source_epoch_20261021 as source
from peaso.checks import private_secret_shared_source_successor_20261021 as shared_source

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


@pytest.mark.parametrize('change', ['code', 'metadata', 'signature'])
def test_cache_replacement_does_not_reuse_admission(monkeypatch, change):
    source._self()
    path = Path(source.__file__)
    raw = path.read_bytes()
    key = next(k for k in source._SELF_CODE_CACHE_STORAGE if k[0] == str(path) and len(k) == 5)
    code, metadata, signature = source._SELF_CODE_CACHE_STORAGE[key]
    changed = {'code': (code.replace(), metadata, signature),
               'metadata': (code, metadata + ('foreign',), signature),
               'signature': (code, metadata, bytes(32))}[change]
    monkeypatch.setitem(source._SELF_CODE_CACHE_STORAGE, key, changed)
    with pytest.raises(source.AdmissionError, match='artifact mismatch'):
        source._self()


@pytest.mark.parametrize('change', ['code', 'defaults', 'global'])
def test_warm_artifact_rechecks_live_bindings(monkeypatch, change):
    source._self()
    if change == 'code':
        def substituted(value): return value
        monkeypatch.setattr(source._relative, '__code__', substituted.__code__)
    elif change == 'defaults':
        monkeypatch.setattr(source._alias_binding, '__defaults__', ('foreign',))
    else:
        monkeypatch.setattr(source, '_HELPER_SHA256', '0' * 64)
    with pytest.raises(source.AdmissionError):
        source._self()


def test_nested_mutable_code_constants_never_match_warm_source(monkeypatch):
    source._self()
    mutable = []
    original = source._relative.__code__
    changed = original.replace(co_consts=original.co_consts + ((mutable,),))
    monkeypatch.setattr(source._relative, '__code__', changed)
    with pytest.raises(source.AdmissionError, match='live code mismatch'):
        source._self()
    mutable.append('changed after first rejection')
    with pytest.raises(source.AdmissionError, match='live code mismatch'):
        source._self()


def test_mutable_default_never_matches_warm_literal(monkeypatch):
    source._self()
    mutable = []
    monkeypatch.setattr(source._alias_binding, '__defaults__', (mutable,))
    for _ in range(2):
        with pytest.raises(source.AdmissionError):
            source._self()
        mutable.append('changed')


def test_warm_cache_closure_tamper_is_rejected(monkeypatch):
    source._self()
    cells = dict(zip(source._SELF_CODE_CACHE.__code__.co_freevars,
                     source._SELF_CODE_CACHE.__closure__))
    monkeypatch.setattr(cells['secret'], 'cell_contents', b'foreign secret of exactly32bytes!!')
    with pytest.raises(source.AdmissionError):
        source._self()


@pytest.mark.parametrize('change', ['actual', 'expected', 'signature'])
def test_code_vector_artifact_replacement_is_rejected(monkeypatch, change):
    source._self()
    key = next(k for k in source._SELF_CODE_CACHE_STORAGE if len(k) == 7)
    vectors, signature = source._SELF_CODE_CACHE_STORAGE[key]
    if change == 'signature':
        changed = (vectors, bytes(32))
    else:
        index = 0 if change == 'actual' else 1
        edited = tuple(c.replace() if n == 0 else c for n, c in enumerate(vectors[index]))
        changed_vectors = (edited, vectors[1]) if index == 0 else (vectors[0], edited)
        changed = (changed_vectors, signature)
    monkeypatch.setitem(source._SELF_CODE_CACHE_STORAGE, key, changed)
    with pytest.raises(source.AdmissionError, match='live code mismatch'):
        source._self()


def test_mutable_code_is_never_retained_even_when_both_vectors_match():
    source._self()
    original = source._relative.__code__
    mutable = original.replace(co_consts=original.co_consts + ([],))
    before = set(source._SELF_CODE_CACHE_STORAGE)
    with pytest.raises(ValueError, match='mutable code vector refused'):
        source._SELF_CODE_CACHE(Path(source.__file__), Path(source.__file__).read_bytes(),
                                ((mutable,), (mutable,)))
    assert set(source._SELF_CODE_CACHE_STORAGE) == before


@pytest.mark.parametrize('change', ['code', 'signature'])
def test_small_bootstrap_artifact_poisoning_is_rejected(monkeypatch, change):
    source._self()
    key = next(iter(source._BOOTSTRAP_ARTIFACT_STORAGE))
    code, signature = source._BOOTSTRAP_ARTIFACT_STORAGE[key]
    changed = (code.replace(), signature) if change == 'code' else (code, bytes(32))
    monkeypatch.setitem(source._BOOTSTRAP_ARTIFACT_STORAGE, key, changed)
    with pytest.raises(source.AdmissionError, match='bootstrap artifact mismatch'):
        source._self()


@pytest.mark.parametrize('change', ['code', 'defaults', 'secret', 'module', 'storage'])
def test_small_bootstrap_live_bindings_are_rechecked(monkeypatch, change):
    source._self()
    fn = source._BOOTSTRAP_ARTIFACT
    cells = dict(zip(fn.__code__.co_freevars, fn.__closure__))
    if change == 'code':
        monkeypatch.setattr(fn, '__code__', fn.__code__.replace(co_consts=fn.__code__.co_consts + ('foreign',)))
    elif change == 'defaults':
        monkeypatch.setattr(fn, '__defaults__', ('foreign',))
    elif change == 'secret':
        monkeypatch.setattr(cells['secret'], 'cell_contents', b'x' * 32)
    elif change == 'module':
        monkeypatch.setattr(cells['m'], 'cell_contents', object())
    else:
        monkeypatch.setattr(cells['cache'], 'cell_contents', {})
    with pytest.raises(source.AdmissionError):
        source._self()


@pytest.mark.parametrize('target', ['self', 'receipt', 'helper', 'producer'])
def test_warm_proof_rechecks_source_and_dependencies(monkeypatch, target):
    rows = source.source_rows()
    relative = 'peaso/secret_scanning.py'
    paths = {'self': Path(source.__file__),
             'receipt': Path(source.__file__).with_suffix('.json'),
             'helper': ROOT / 'peaso/secret_evidence.py',
             'producer': ROOT / relative}
    selected = paths[target].resolve()
    original = Path.read_bytes
    def changed(path):
        raw = original(path)
        return raw + b'\n# changed\n' if path.resolve() == selected else raw
    monkeypatch.setattr(Path, 'read_bytes', changed)
    with pytest.raises(source.AdmissionError):
        checked = source.source_rows()
        source._live(ROOT, relative, checked[relative])


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


