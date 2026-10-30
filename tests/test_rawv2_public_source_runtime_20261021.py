"""Normal native boot and type-sensitive source/callable privacy admission."""
import functools
import hashlib
import json
from pathlib import Path

import pytest
from peaso import rawv2_public_source_successor_20261021 as source
from peaso import secret_scanning as scanner

ROOT = Path(source.__file__).resolve().parents[1]




@pytest.mark.parametrize('change', ['wrong_prior', 'foreign_bytes'])
def test_source_view_rejects_unreviewed_bytes_or_ancestry(change):
    raw = (ROOT / source.SCANNER).read_bytes()
    with pytest.raises(RuntimeError):
        source.source_bytes(source.SCANNER, raw + (b'\n' if change == 'foreign_bytes' else b''),
                            '0' * 64 if change == 'wrong_prior' else source.SCANNER_BEFORE, ROOT)


def test_real_live_false_zero_code_mutation_is_rejected(monkeypatch):
    source.verify_scanner(ROOT)
    fn = scanner._scan_trufflehog
    assert any(type(c) is bool and c is False for c in fn.__code__.co_consts)
    constants = tuple(0 if type(c) is bool and c is False else c for c in fn.__code__.co_consts)
    monkeypatch.setattr(fn, '__code__', fn.__code__.replace(co_consts=constants))
    with pytest.raises(RuntimeError, match='executing code changed'):
        source.verify_scanner(ROOT)


def test_live_defaults_change_is_rejected(monkeypatch):
    source.verify_scanner(ROOT)
    monkeypatch.setattr(scanner.scan_content, '__kwdefaults__', {'unreviewed': None})
    with pytest.raises(RuntimeError, match='defaults changed'):
        source.verify_scanner(ROOT)


def test_global_callable_substitution_is_rejected(monkeypatch):
    monkeypatch.setattr(scanner, '_fingerprint', lambda value: 'unreviewed')
    with pytest.raises(RuntimeError):
        source.verify_scanner(ROOT)


def test_extra_class_behavior_is_rejected(monkeypatch):
    monkeypatch.setattr(scanner._DetectorMatches, '__getattribute__', lambda self, key: None, raising=False)
    with pytest.raises(RuntimeError, match='roster changed'):
        source.verify_scanner(ROOT)


@pytest.mark.parametrize('name', ['_kingfisher', '_trufflehog'])
def test_equivalent_decorated_resolver_replacement_is_rejected(monkeypatch, name):
    wrapped = getattr(scanner, name).__wrapped__
    monkeypatch.setattr(scanner, name, functools.lru_cache(maxsize=1)(wrapped))
    with pytest.raises(RuntimeError, match='decorated callable changed'):
        source.verify_scanner(ROOT)


def test_unknown_guard_cannot_use_source_relation():
    with pytest.raises(RuntimeError, match='Unreviewed'):
        source.install_admission('unreviewed_admission')


def test_old_guard_function_defaults_are_still_bound(monkeypatch):
    from peaso.checks import aws_selected_configuration_admission_20261020 as original
    monkeypatch.setattr(original.reviewed_inputs, '__defaults__', ('unreviewed',))
    with pytest.raises(RuntimeError, match='guard callable changed'):
        source._verify_guard(original, ROOT)


def test_corrupted_receipt_rejected_after_warm_proof():
    source.verify_scanner(ROOT)
    path = ROOT / source.RECEIPT
    before = path.read_bytes()
    try:
        path.write_bytes(before + b'\n')
        with pytest.raises(RuntimeError, match='receipt changed'):
            source.verify_scanner(ROOT)
    finally:
        path.write_bytes(before)
    assert source.verify_scanner(ROOT)


@pytest.mark.parametrize('field,value', [('__firstlineno__', False), ('__static_attributes__', ('foreign',))])
def test_portable_class_metadata_cannot_hide_unreviewed_bindings(monkeypatch, field, value):
    monkeypatch.setattr(scanner._DetectorMatches, field, value, raising=False)
    with pytest.raises(RuntimeError, match='class metadata changed'):
        source.verify_scanner(ROOT)


