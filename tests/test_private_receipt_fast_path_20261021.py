"""Exact fast-path negatives for the private shared source receipt."""
from pathlib import Path

import pytest

from peaso.checks import private_secret_shared_source_successor_20261021 as shared


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / shared._PRIVATE_RECEIPT


def test_unrelated_producer_skips_decode_but_reads_receipt_each_time(monkeypatch):
    row = {'path': 'peaso/collectors/unrelated.py', 'qualname': 'unrelated'}
    reads = []
    original_read = Path.read_bytes

    def read(path):
        if path.resolve() == RECEIPT:
            reads.append(path)
        return original_read(path)

    def unexpected_decode(raw):
        raise AssertionError('unrelated producer decoded the private receipt')

    monkeypatch.setattr(Path, 'read_bytes', read)
    monkeypatch.setattr(shared.json, 'loads', unexpected_decode)
    assert shared._private_row(test_unrelated_producer_skips_decode_but_reads_receipt_each_time,
                               row, ROOT) is row
    assert shared._private_row(test_unrelated_producer_skips_decode_but_reads_receipt_each_time,
                               row, ROOT) is row
    assert len(reads) == 2


def test_unrelated_producer_rejects_changed_receipt_bytes(monkeypatch):
    row = {'path': 'peaso/collectors/unrelated.py', 'qualname': 'unrelated'}
    original_read = Path.read_bytes

    def read(path):
        raw = original_read(path)
        return raw + b'\n' if path.resolve() == RECEIPT else raw

    monkeypatch.setattr(Path, 'read_bytes', read)
    with pytest.raises(RuntimeError, match='Private shared receipt changed'):
        shared._private_row(test_unrelated_producer_rejects_changed_receipt_bytes, row, ROOT)




@pytest.mark.parametrize('change', ['code', 'defaults', 'global'])
def test_warm_private_self_rechecks_live_bindings(monkeypatch, change):
    shared._private_self()
    if change == 'code':
        monkeypatch.setattr(shared._private_row, '__code__', shared._private_row.__code__.replace(
            co_consts=shared._private_row.__code__.co_consts + ('foreign',)))
    elif change == 'defaults':
        monkeypatch.setattr(shared._private_receipt, '__defaults__', (False,))
    else:
        monkeypatch.setattr(shared, '_PRIVATE_RECEIPT_SHA256', '0' * 64)
    with pytest.raises(RuntimeError):
        shared._private_self()
