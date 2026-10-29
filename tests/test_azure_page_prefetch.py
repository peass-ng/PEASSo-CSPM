"""Lookahead overlaps I/O while keeping the reader's exact pages and failures."""
import threading
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
