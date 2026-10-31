"""The package byte target composes with the retained scan lease."""
import threading
import time
from types import SimpleNamespace
import pytest
from peaso.collectors import aws_package_content_indicators as package


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

