"""Bounded scan-local lookahead for independent, fully consumed Graph lists.

The normal reader owns retries, cancellation, budgets and continuation checks.
Consumers receive the same pages and exception in the same order; only the
network wait overlaps unrelated ARM work. Explicit inventory caps stay serial.
"""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import json
import threading
import zlib


class _BufferedPage:
    """Keep large JSON pages compact until the ordered consumer needs them."""
    __slots__ = ('value', 'compressed')

    def __init__(self, page):
        self.value, self.compressed = page, False
        pending, visited = [page], set()
        while pending:
            value = pending.pop()
            if type(value) in (dict, list):
                if id(value) in visited:
                    continue
                visited.add(id(value))
                if type(value) is dict:
                    if any(type(key) is not str for key in value):
                        return
                    pending.extend(value.values())
                else:
                    pending.extend(value)
            elif type(value) not in (str, int, float, bool, type(None)):
                return  # Preserve non-JSON test/custom transport values exactly.
        try:
            raw = json.dumps(page, ensure_ascii=False, allow_nan=False,
                             separators=(',', ':')).encode('utf-8')
            if len(raw) < 32768:
                return
            packed = zlib.compress(raw, level=1)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            return
        if len(packed) < len(raw):
            self.value, self.compressed = packed, True

    def load(self):
        if self.compressed:
            return json.loads(zlib.decompress(self.value))
        return self.value


class _Stream:
    def __init__(self, owner, url):
        self.owner, self.url = owner, url
        self.condition = threading.Condition()
        self.pages = deque()
        self.done = self.claimed = self.stopped = False
        self.error = None
        self.future = None

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
                    self.pages.append(_BufferedPage(page))
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
                yield page.load()
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
            stream.future = self.pool.submit(copy_context().run, stream.produce)
            self.futures.append(stream.future)

    def add(self, urls):
        # Bound pending streams too. Unscheduled consumers use the normal reader.
        with self.lock:
            if self.closed:
                return
            for url in urls:
                if url in self.streams or len(self.streams) >= 64:
                    continue
                stream = self.streams[url] = _Stream(self, url)
                stream.future = self.pool.submit(copy_context().run, stream.produce)
                self.futures.append(stream.future)

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
            # Full earlier streams can occupy every producer. A queued stream
            # must let its consumer perform the read rather than wait behind
            # producers that need a later consumer to drain their buffers.
            if stream.future is not None and stream.future.cancel():
                stream.stop()
                return None
        return stream.consume()

    def close(self):
        with self.lock:
            self.closed = True
            streams = tuple(self.streams.values())
        for stream in streams:
            stream.stop()
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.streams.clear()
