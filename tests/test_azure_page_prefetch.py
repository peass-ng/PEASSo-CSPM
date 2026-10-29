"""Lookahead overlaps I/O while keeping the reader's exact pages and failures."""
import threading
import weakref
from email.message import Message
from urllib.error import HTTPError

import pytest

from peaso.collectors.azure import GRAPH, _Reader
from peaso.collectors.azure_page_prefetch import PagePrefetch


def test_pages_are_prefetched_and_consumed_once_in_original_order():
    reader = _Reader({'concurrency': 3})
    urls = [GRAPH + '/v1.0/list' + str(i) for i in range(3)]
    entered = threading.Barrier(3)
    calls = []
    lock = threading.Lock()
    def request(url, **kwargs):
        with lock:
            calls.append(url)
        if '?' not in url:
            entered.wait(timeout=3)
            return {'value': [url], '@odata.nextLink': url + '?page=2'}
        return {'value': [url]}
    manager = reader.page_prefetch = PagePrefetch(reader, request, urls, GRAPH)
    manager.start()
    try:
        for future in manager.futures:
            future.result(timeout=3)
        assert len(calls) == 6  # completed while the consumer did unrelated work
        for url in urls:
            assert list(reader.pages(request, url, audience=GRAPH, next_key='@odata.nextLink')) == [[url], [url + '?page=2']]
        assert len(calls) == reader.budget.calls == 6
    finally:
        manager.close()


def test_retry_and_partial_failure_are_identical_to_the_serial_reader(monkeypatch):
    monkeypatch.setattr('peaso.collectors.azure.time.sleep', lambda delay: None)
    url = GRAPH + '/v1.0/items'
    def execute(prefetched):
        reader = _Reader({'concurrency': 2})
        attempts = 0
        def request(current, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                headers = Message(); headers['Retry-After'] = '1'
                raise HTTPError(current, 429, 'throttled', headers, None)
            if current == url:
                return {'value': [{'id': 'one'}], '@odata.nextLink': url + '?page=2'}
            raise ValueError('fixture invalid continuation payload')
        manager = None
        if prefetched:
            manager = reader.page_prefetch = PagePrefetch(reader, request, [url], GRAPH)
            manager.start()
        pages = []
        try:
            with pytest.raises(ValueError, match='fixture invalid'):
                for page in reader.pages(request, url, audience=GRAPH, next_key='@odata.nextLink'):
                    pages.append(page)
            return pages, attempts, reader.budget.calls
        finally:
            if manager is not None:
                manager.close()
    assert execute(True) == execute(False) == ([[{'id': 'one'}]], 3, 3)


def test_a_guarded_request_is_not_replaced_by_another_callable():
    reader = _Reader({'concurrency': 2})
    url = GRAPH + '/v1.0/items'
    def request(current, **kwargs):
        return {'value': []}
    guarded_calls = []
    def guarded(current, **kwargs):
        guarded_calls.append(current)
        return request(current, **kwargs)
    manager = reader.page_prefetch = PagePrefetch(reader, request, [url], GRAPH)
    manager.start()
    try:
        assert list(reader.pages(guarded, url, audience=GRAPH, next_key='@odata.nextLink')) == [[]]
        assert guarded_calls == [url]
    finally:
        manager.close()


def test_dynamic_child_lookahead_is_bounded_and_does_not_duplicate_reads():
    reader = _Reader({'concurrency': 4})
    parent = GRAPH + '/v1.0/groups'
    children = [GRAPH + '/v1.0/policy/' + str(i) for i in range(100)]
    calls = []
    def request(url, **kwargs):
        calls.append(url)
        return {'value': [{'id': url}]}
    def observe(url, page):
        if url == parent:
            manager.add(children)
    manager = reader.page_prefetch = PagePrefetch(reader, request, [parent], GRAPH, on_page=observe)
    manager.start()
    try:
        assert list(reader.pages(request, parent, audience=GRAPH, next_key='@odata.nextLink')) == [[{'id': parent}]]
        assert len(manager.streams) == 64
        for child in children:
            assert list(reader.pages(request, child, audience=GRAPH, next_key='@odata.nextLink')) == [[{'id': child}]]
        assert len(calls) == len(set(calls)) == reader.budget.calls == 101
    finally:
        manager.close()
    manager.add([GRAPH + '/v1.0/not-requested-after-close'])
    assert len(calls) == 101


def test_large_pages_keep_every_json_value_and_failure_prefix():
    reader = _Reader({'concurrency': 2})
    url = GRAPH + '/v1.0/large'
    page = [{'id': str(i), 'text': 'héllo\n' * 300,
             'values': [None, True, False, 2**80, 1.25]} for i in range(100)]
    def request(current, **kwargs):
        if current == url:
            return {'value': page, '@odata.nextLink': url + '?page=2'}
        raise ValueError('fixture final page unavailable')
    manager = reader.page_prefetch = PagePrefetch(reader, request, [url], GRAPH)
    manager.start()
    try:
        manager.futures[0].result(timeout=3)
        buffered = manager.streams[url].pages[0]
        assert buffered is page
        consumed = reader.pages(request, url, audience=GRAPH, next_key='@odata.nextLink')
        assert next(consumed) == page
        with pytest.raises(ValueError, match='fixture final page unavailable'):
            next(consumed)
        assert reader.budget.calls == 2
    finally:
        manager.close()


@pytest.mark.parametrize('value', [(1, 2), {1: 'integer-key'}, float('inf')])
def test_non_json_values_are_preserved_without_a_serialization_failure(value):
    reader = _Reader({'concurrency': 2})
    url = GRAPH + '/v1.0/custom'
    page = [{'id': 'one', 'text': 'x' * 40000, 'value': value}]
    def request(current, **kwargs):
        return {'value': page}
    manager = reader.page_prefetch = PagePrefetch(reader, request, [url], GRAPH)
    manager.start()
    try:
        manager.futures[0].result(timeout=3)
        assert manager.streams[url].pages[0] is page
        assert next(reader.pages(request, url, audience=GRAPH,
                                 next_key='@odata.nextLink')) is page
    finally:
        manager.close()


def test_close_releases_a_producer_waiting_on_a_full_buffer():
    reader = _Reader({'concurrency': 2})
    url = GRAPH + '/v1.0/bounded'
    second_request = threading.Event()
    def request(current, **kwargs):
        if current != url:
            second_request.set()
        return {'value': [{'id': current}],
                '@odata.nextLink': current + ('&' if '?' in current else '?') + 'next'}
    manager = reader.page_prefetch = PagePrefetch(reader, request, [url], GRAPH, lookahead=1)
    manager.start()
    try:
        assert second_request.wait(timeout=3)
    finally:
        manager.close()
    assert manager.futures[0].done()


def test_queued_consumer_cannot_deadlock_behind_full_earlier_streams():
    reader = _Reader({'concurrency': 2})
    urls = [GRAPH + '/v1.0/blocked' + str(i) for i in range(2)]
    queued = GRAPH + '/v1.0/queued'
    full = [threading.Event(), threading.Event()]
    calls = []
    lock = threading.Lock()
    def request(current, **kwargs):
        with lock:
            calls.append(current)
        if current == queued:
            return {'value': [{'id': 'queued'}]}
        index = next(i for i, url in enumerate(urls) if current.startswith(url))
        if '?' in current:
            full[index].set()
        return {'value': [{'id': current}], '@odata.nextLink': current.split('?')[0] + '?next'}
    manager = reader.page_prefetch = PagePrefetch(reader, request, urls + [queued], GRAPH, lookahead=1)
    manager.start()
    try:
        assert all(event.wait(timeout=3) for event in full)
        assert list(reader.pages(request, queued, audience=GRAPH,
                                 next_key='@odata.nextLink')) == [[{'id': 'queued'}]]
        assert calls.count(queued) == 1
        assert manager.streams[queued].future.cancelled()
    finally:
        manager.close()


@pytest.mark.parametrize('failed', [False, True])
def test_close_releases_scan_callbacks_without_waiting_for_cyclic_gc(failed):
    class RetainedInventory:
        pass
    inventory = RetainedInventory()
    witness = weakref.ref(inventory)
    reader = _Reader({'concurrency': 2})
    url = GRAPH + '/v1.0/retained'
    def request(current, *, retained=inventory, **kwargs):
        if failed:
            raise ValueError('fixture unavailable')
        return {'value': []}
    def observe(current, page, *, retained=inventory):
        pass
    manager = reader.page_prefetch = PagePrefetch(reader, request, [url], GRAPH, on_page=observe)
    manager.start()
    manager.futures[0].result(timeout=3)
    del inventory, request, observe
    assert witness() is not None
    manager.close()
    assert not hasattr(reader, 'page_prefetch')
    assert manager.request is manager.on_page is None
    assert witness() is None


@pytest.mark.parametrize('consumed', [False, True])
def test_close_releases_self_referencing_failed_request_frames_without_gc(consumed):
    import gc
    class RetainedInventory:
        pass
    references = []
    errors = []
    def request(url, **kwargs):
        inventory = RetainedInventory()
        references.append(weakref.ref(inventory))
        error = ValueError('fixture self-referencing completed frame')
        errors.append(error)
        raise error
    reader = _Reader({'concurrency': 2, 'retries': 0})
    url = GRAPH + '/v1.0/failed-native-list'
    manager = reader.page_prefetch = PagePrefetch(reader, request, [url], GRAPH)
    enabled = gc.isenabled()
    gc.disable()
    try:
        manager.start()
        manager.futures[0].result(timeout=3)
        if consumed:
            with pytest.raises(ValueError, match='self-referencing'):
                list(reader.pages(request, url, audience=GRAPH, next_key='@odata.nextLink'))
        assert references[0]() is not None
        manager.close()
        assert references[0]() is None
        assert errors[0].__traceback__ is not None
        assert str(errors[0]) == 'fixture self-referencing completed frame'
    finally:
        manager.close()
        if enabled:
            gc.enable()
