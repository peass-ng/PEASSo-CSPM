"""Current byte target composes with the retained lease and finite source proof."""
from pathlib import Path
import threading
import time
from types import SimpleNamespace
import pytest
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.collectors import aws_package_content_indicators as package
from peaso.checks import private_secret_shared_source_successor_20261021 as shared

ROOT = Path(__file__).resolve().parents[1]


def request(seconds):
    return SimpleNamespace(deadline=None if seconds is None else time.monotonic() + seconds,
                           _lock=threading.RLock())


@pytest.mark.parametrize('seconds', [None, 5, 600])
def test_real_lease_controls_item_bound_and_byte_target(seconds):
    owner = request(seconds)
    assert package.BATCH_ITEMS == 512
    assert package.BATCH_BYTES == 64 * 1024 * 1024
    assert package.BATCH_TARGET_BYTES == 16 * 1024 * 1024
    assert not package._batch_flush_before(511, 511 * 32768, 32768, owner)
    assert package._batch_flush_before(512, 512 * 32768, 32768, owner)
    assert package._batch_flush_before(512, 512, 1, owner) is (seconds != 600)
    assert package._batch_flush_before(2048, 2048, 1, owner)
    assert package._batch_flush_before(1, package.BATCH_BYTES, 1, owner)
    owner._archive_adaptive_th = SimpleNamespace(large_disabled=True)
    assert package._batch_flush_before(512, 512, 1, owner)


@pytest.mark.parametrize('change', ['helper_code', 'helper_defaults', 'target_bytes',
                                  'max_bytes', 'lease_helper_code', 'lease_helper_defaults'])
def test_actual_dependency_mutations_are_rejected(monkeypatch, change):
    if change == 'helper_code':
        monkeypatch.setattr(package._batch_flush_before, '__code__', package._batch_flush_before.__code__.replace(
            co_consts=package._batch_flush_before.__code__.co_consts + ('unreviewed',)))
    elif change == 'helper_defaults':
        monkeypatch.setattr(package._batch_flush_before, '__defaults__', (None,))
    elif change == 'target_bytes':
        monkeypatch.setattr(package, 'BATCH_TARGET_BYTES', 32 * 1024 * 1024)
    elif change == 'max_bytes':
        monkeypatch.setattr(package, 'BATCH_BYTES', 128 * 1024 * 1024)
    elif change == 'lease_helper_code':
        monkeypatch.setattr(package._archive_batch_items, '__code__', package._archive_batch_items.__code__.replace(
            co_consts=package._archive_batch_items.__code__.co_consts + ('unreviewed',)))
    else:
        monkeypatch.setattr(package._archive_batch_items, '__defaults__', (None,))
    with pytest.raises((RuntimeError, epoch.AdmissionError)):
        shared.rawv2_current_content_definition(package._image, ROOT)
