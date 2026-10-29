"""Bounded scan-local lookahead for independent, fully consumed Graph lists.

The normal reader owns retries, cancellation, budgets and continuation checks.
Consumers receive the same pages and exception in the same order; only the
network wait overlaps unrelated ARM work. Explicit inventory caps stay serial.
"""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import threading


class _Stream:
    def __init__(self, owner, url):
        self.owner, self.url = owner, url
        self.condition = threading.Condition()
        self.pages = deque()
        self.done = self.claimed = self.stopped = False
        self.error = None

    def produce(self):
        self.owner.local.producing = True
        iterator = self.owner.reader.pages(self.owner.request, self.url,
            audience=self.owner.audience, next_key='@odata.nextLink')
        try:
            for page in iterator:
                if self.owner.on_page is not None:
                    self.owner.on_page(self.url, page)
                with self.condition:
                    while len(self.pages) >= self.owner.lookahead and not self.stopped:
                        self.condition.wait(0.1)
                        self.owner.reader.check_cancelled()
                    if self.stopped:
                        break
                    self.pages.append(page)
                    self.condition.notify_all()
        except BaseException as exc:
            with self.condition:
                self.error = exc
        finally:
            iterator.close()
            with self.condition:
                self.done = True
                self.condition.notify_all()
            self.owner.local.producing = False

    def consume(self):
        try:
            while True:
                self.owner.reader.check_cancelled()
                with self.condition:
                    while not self.pages and not self.done:
                        self.condition.wait(0.1)
                        self.owner.reader.check_cancelled()
                    if self.pages:
                        page = self.pages.popleft()
                        self.condition.notify_all()
                    elif self.error is not None:
                        raise self.error
                    else:
                        return
                yield page
        finally:
            self.stop()

    def stop(self):
        with self.condition:
            self.stopped = True
            self.pages.clear()
            self.condition.notify_all()


class PagePrefetch:
    def __init__(self, reader, request, urls, audience, *, lookahead=64, on_page=None):
        self.reader, self.request, self.audience = reader, request, audience
        self.lookahead, self.on_page = lookahead, on_page
        self.lock, self.closed = threading.Lock(), False
        self.local = threading.local()
        self.streams = {url: _Stream(self, url) for url in dict.fromkeys(urls)}
        self.pool = ThreadPoolExecutor(max_workers=min(4, reader.workers),
                                       thread_name_prefix='azure-page-prefetch')
        self.futures = []

    def start(self):
        for stream in tuple(self.streams.values()):
            self.futures.append(self.pool.submit(copy_context().run, stream.produce))

    def add(self, urls):
        # Bound pending streams too. Unscheduled consumers use the normal reader.
        with self.lock:
            if self.closed:
                return
            for url in urls:
                if url in self.streams or len(self.streams) >= 64:
                    continue
                stream = self.streams[url] = _Stream(self, url)
                self.futures.append(self.pool.submit(copy_context().run, stream.produce))

    def take(self, request, url, audience, key, next_key, body):
        if (getattr(self.local, 'producing', False) or request is not self.request
                or audience != self.audience or key != 'value'
                or next_key != '@odata.nextLink' or body is not None):
            return None
        with self.lock:
            stream = self.streams.get(url)
        if stream is None:
            return None
        with stream.condition:
            if stream.claimed:
                return None
            stream.claimed = True
        return stream.consume()

    def close(self):
        with self.lock:
            self.closed = True
            streams = tuple(self.streams.values())
        for stream in streams:
            stream.stop()
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.streams.clear()
