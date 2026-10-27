"""Main's sample-first policy is superseded by lease-bound archive preparation.

The common API retains 512 sources. Only the archive owner may admit 2048,
using its existing absolute collection lease and exact typed stdout overflow.
"""
import time
import pytest
from peaso import secret_scanning_batch as batch
from peaso.secret_scanning_adaptive import AdaptiveTH
from peaso.secret_scanning_errors import ScannerStdoutBound


def _items(count=1025):
    return [(('value-%04d' % i).encode(), 'original/%d.cfg' % i) for i in range(count)]


def _policy(dense=False, failure=None):
    calls = []
    def prepare(items, timeout):
        assert 0 < timeout <= 60
        calls.append(len(items))
        if len(items) > 512:
            if failure is not None:
                raise failure
            if dense:
                raise ScannerStdoutBound('scanner output bound')
        return {item: b'finding:' + item[0] for item in items}
    policy = AdaptiveTH(prepare, lambda error: isinstance(error, ScannerStdoutBound))
    return policy, calls


def _consume(policy, items):
    outcomes = []
    retained = []
    with policy.prepared_groups(items, deadline=time.monotonic() + 600) as groups:
        for group, prepared in groups:
            outcomes.extend((item, prepared[item]) for item in group)
            retained.append(prepared)
    assert all(not mapping for mapping in retained)
    return outcomes


def test_sparse_sources_share_one_admitted_process_and_keep_each_source():
    items = _items(); policy, calls = _policy()
    assert _consume(policy, items) == [(item, b'finding:' + item[0]) for item in items]
    assert calls == [1025]


def test_exact_dense_overflow_retries_512_and_disables_next_large_probe():
    items = _items(); policy, calls = _policy(dense=True)
    expected = [(item, b'finding:' + item[0]) for item in items]
    assert _consume(policy, items) == expected
    assert calls == [1025, 512, 512, 1]
    calls.clear()
    assert _consume(policy, items) == expected
    assert calls == [512, 512, 1]
    assert policy.metrics['peak_retained_output_bytes'] <= 4 * 1024 * 1024


def test_same_message_without_exact_exception_type_never_retries():
    policy, calls = _policy(failure=ValueError('scanner output bound'))
    with pytest.raises(ValueError, match='scanner output bound'):
        _consume(policy, _items())
    assert calls == [1025] and not policy.large_disabled


def test_common_api_preserves_512_bound_before_preparation(monkeypatch):
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch',
                        lambda *args: pytest.fail('oversized common input reached scanner'))
    assert batch.MAX_BATCH_ITEMS == 512
    with pytest.raises(ValueError, match='content batch bound'):
        with batch.prepared_content_batch(_items(513)):
            pass
