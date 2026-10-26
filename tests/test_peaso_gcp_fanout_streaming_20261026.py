"""NEXT-GCP-1: GCP location fan-out streams pages and bounds producer work.

Real lazy generators, real thread pools and the real GCPCollector page/envelope
path with an in-memory transport; no credentials or cloud calls.
"""
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.collectors.gcp_fanout import POOL_PREFIX, fanout_pages, location_fanout

LOCATIONS = ["us-central1", "us-east1", "europe-west1", "asia-east1"]
PAGES_PER_LOCATION = 3


def wait_for(condition, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.002)
    return condition()


@pytest.fixture
def pooled():
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix=POOL_PREFIX)
    try:
        yield SimpleNamespace(location_pool=pool, options={}, max_items=None)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


class PagedTransport:
    """Each location lists PAGES_PER_LOCATION pages of one resource each."""

    def __init__(self, delay=0.0):
        self.delay, self.lock = delay, threading.Lock()
        self.calls = []
        self.evidence, self.cache, self.options = [], {}, {}
        self.run_sbom_metadata_reads, self.datafusion_cdap_reads = {}, {}

    def check_cancelled(self):
        pass

    def request(self, method, url, params=None, body=None, scope=None, operation=None):
        location = urlsplit(url).path.split("/locations/")[1].split("/")[0]
        page = int((params or {}).get("pageToken") or 0)
        with self.lock:
            self.calls.append((location, page))
            number = len(self.calls)
        time.sleep(self.delay)
        data = {"services": [{"name": f"projects/p/locations/{location}/services/s{page}"}]}
        if page + 1 < PAGES_PER_LOCATION:
            data["nextPageToken"] = str(page + 1)
        return data, f"r{number}"

    def close(self):
        pass


def collector_with(transport, **options):
    connector = {"provider": "gcp", "scopes": ["projects/p"], "options": {"inventories": ["cloudrun_service"], **options}}
    return GCPCollector(connector, transport=transport)


def envelope(collector):
    def fetch():
        yield from fanout_pages(collector, LOCATIONS, lambda location: collector.pages(
            f"https://run.googleapis.com/v2/projects/p/locations/{location}/services", "projects/p", key="services"))
    try:
        return collector.envelope("cloudrun_service", "projects/p", "run.googleapis.com", fetch)
    finally:
        collector.hydration_pool.shutdown(wait=True)
        if collector.location_pool is not None:
            collector.location_pool.shutdown(wait=True)


@pytest.mark.parametrize("options", [{"concurrency": 1}, {"concurrency": 8, "location_concurrency": 8}],
                         ids=["serial-no-pool", "parallel-pool"])
def test_max_resources_one_reads_exactly_the_pages_needed_to_hit_the_cap(options):
    transport = PagedTransport()
    collector = collector_with(transport, max_resources=1, **options)
    assert (collector.location_pool is None) == (options["concurrency"] == 1)
    result = envelope(collector)
    # Page 0 holds the one allowed resource; page 1 holds the second resource,
    # which trips the cap. Nothing else is read in the scope or background.
    assert result["error"]["code"] == "resource_limit"
    assert len(result["items"]) == 1
    time.sleep(0.02)
    assert transport.calls == [("us-central1", 0), ("us-central1", 1)]


@pytest.mark.parametrize("options", [{"concurrency": 1}, {"concurrency": 8, "location_concurrency": 8}],
                         ids=["serial-no-pool", "parallel-pool"])
def test_uncapped_collection_reads_every_page_once_in_location_order(options):
    transport = PagedTransport(delay=0.001)
    result = envelope(collector_with(transport, **options))
    assert result["coverage_status"] == "collected"
    assert sorted(transport.calls) == sorted((location, page) for location in LOCATIONS
                                             for page in range(PAGES_PER_LOCATION))
    assert [item["name"] for item in result["items"]] == [
        f"projects/p/locations/{location}/services/s{page}"
        for location in LOCATIONS for page in range(PAGES_PER_LOCATION)]


@pytest.mark.parametrize("make", [lambda: SimpleNamespace(location_pool=None),
                                  lambda: SimpleNamespace(location_pool=None, options={"max_resources": 5})],
                         ids=["no-pool", "capped"])
def test_serial_first_page_is_yielded_before_the_second_is_fetched(make):
    reads = []

    def fetch(location):
        for page in range(5):
            reads.append((location, page))
            yield f"{location}{page}"

    stream = location_fanout(make(), ["a", "b"], fetch)
    assert next(stream) == ("a", ["a0"], None)
    assert reads == [("a", 0)]
    assert next(stream) == ("a", ["a1"], None)
    assert reads == [("a", 0), ("a", 1)]
    stream.close()
    assert reads == [("a", 0), ("a", 1)]


def test_parallel_probe_location_streams_page_by_page(pooled):
    reads = []

    def fetch(location):
        for page in range(3):
            reads.append((location, page))
            yield f"{location}{page}"

    stream = location_fanout(pooled, ["a", "b", "c"], fetch)
    assert next(stream) == ("a", ["a0"], None)
    time.sleep(0.02)
    assert reads == [("a", 0)]
    stream.close()


def test_cancellation_stops_every_producer_promptly(pooled):
    cancel = threading.Event()

    def check_cancelled():
        if cancel.is_set():
            raise ReadError("unavailable", "cancelled")

    pooled.transport = SimpleNamespace(check_cancelled=check_cancelled)
    lock, reads, opened, closed = threading.Lock(), [], set(), set()

    def fetch(location):
        with lock:
            opened.add(location)
        try:
            if location == "a":
                yield ("a", 0)
                return
            for page in range(1000):
                with lock:
                    reads.append((location, page))
                time.sleep(0.002)
                yield (location, page)
        finally:
            with lock:
                closed.add(location)

    stream = fanout_pages(pooled, ["a", "b", "c", "d", "e", "f"], fetch)
    assert [next(stream) for _ in range(3)] == [("a", 0), ("b", 0), ("b", 1)]
    cancel.set()
    with pytest.raises(ReadError) as raised:
        for _page in stream:
            pass
    assert raised.value.error["code"] == "cancelled"
    assert wait_for(lambda: opened <= closed)
    with lock:
        at_cancel = list(reads)
    time.sleep(0.05)
    with lock:
        assert reads == at_cancel
    # b read at most one page beyond the two consumed; every other location
    # read at most its single look-ahead page.
    assert max(page for location, page in at_cancel if location == "b") <= 2
    assert all(page == 0 for location, page in at_cancel if location != "b")


def test_cancelled_background_locations_replay_cancellation_without_reading(pooled):
    cancel = threading.Event()

    def check_cancelled():
        if cancel.is_set():
            raise ReadError("unavailable", "cancelled")

    pooled.transport = SimpleNamespace(check_cancelled=check_cancelled)
    reads = []

    def fetch(location):
        reads.append(location)
        if location == "a":
            cancel.set()
        yield location

    rows = list(location_fanout(pooled, ["a", "b", "c"], fetch))
    assert rows[0] == ("a", ["a"], None)
    assert [(location, pages, error.error["code"]) for location, pages, error in rows[1:]] == [
        ("b", [], "cancelled"), ("c", [], "cancelled")]
    assert reads == ["a"]


def test_background_buffer_never_holds_more_than_one_page_per_location(pooled):
    lock = threading.Lock()
    fetched, consumed, worst = {}, {}, {}

    def fetch(location):
        for page in range(6):
            with lock:
                fetched[location] = fetched.get(location, 0) + 1
                ahead = fetched[location] - consumed.get(location, 0)
                worst[location] = max(worst.get(location, 0), ahead)
            yield (location, page)

    locations = ["a", "b", "c", "d", "e", "f", "g"]
    out = []
    for location, pages, error in location_fanout(pooled, locations, fetch):
        assert error is None
        for page in pages:
            with lock:
                consumed[location] = consumed.get(location, 0) + 1
            out.append(page)
            time.sleep(0.003)  # slow consumer: producers must not run ahead
    assert out == [(location, page) for location in locations for page in range(6)]
    # One page handed to the consumer plus at most one read ahead.
    assert max(worst.values()) <= 2
    assert all(count == 6 for count in fetched.values())


def test_consumer_exception_closes_producers_and_stops_reads(pooled):
    lock, reads, opened, closed = threading.Lock(), [], set(), set()

    def fetch(location):
        with lock:
            opened.add(location)
        try:
            for page in range(1 if location == "a" else 1000):
                with lock:
                    reads.append((location, page))
                yield (location, page)
        finally:
            with lock:
                closed.add(location)

    with pytest.raises(RuntimeError, match="consumer failed"):
        for page in fanout_pages(pooled, ["a", "b", "c", "d", "e", "f"], fetch):
            if page == ("b", 2):
                raise RuntimeError("consumer failed")
    # The pool stays alive: the stop path itself closes every opened iterator.
    assert wait_for(lambda: opened <= closed)
    with lock:
        at_stop = list(reads)
    time.sleep(0.03)
    with lock:
        assert reads == at_stop
    assert max(page for location, page in at_stop if location == "b") <= 3
    assert all(page == 0 for location, page in at_stop if location not in ("a", "b"))
    # No pool worker is left blocked: fresh tasks run on every worker.
    assert all(f.result(timeout=1) for f in [pooled.location_pool.submit(lambda: True) for _ in range(8)])


def test_generator_close_after_partial_read_releases_running_workers(pooled):
    release, started, closed = threading.Event(), threading.Event(), set()
    opened = set()

    def fetch(location):
        opened.add(location)
        try:
            if location == "a":
                yield "a"
                return
            if location == "c":
                started.set()
                release.wait(1)
            for page in range(100):
                yield (location, page)
        finally:
            closed.add(location)

    stream = fanout_pages(pooled, ["a", "b", "c", "d", "e", "f", "g"], fetch)
    assert next(stream) == "a"
    assert next(stream) == ("b", 0)
    assert started.wait(1)
    stream.close()
    release.set()
    # The running c read finishes, then its iterator is closed by the stop path.
    assert wait_for(lambda: opened <= closed and "c" in closed)
    assert all(f.result(timeout=1) for f in [pooled.location_pool.submit(lambda: True) for _ in range(8)])


def random_plan(seed):
    rng = random.Random(seed)
    plan = {}
    for index in range(rng.randint(2, 9)):
        pages = [[f"l{index}p{page}"] for page in range(rng.randint(0, 4))]
        error = rng.choice([None, None, None, ReadError("denied", "permission_denied", http_status=403),
                            ValueError(f"bad {index}")])
        plan[f"l{index}"] = (pages, error, rng.choice([0.0, 0.001, 0.003]))
    return plan


def run(collector, plan):
    def fetch(location):
        pages, error, delay = plan[location]
        for page in pages:
            time.sleep(delay)
            yield page
        if error is not None:
            raise error
    rows, raised = [], None
    try:
        for row in location_fanout(collector, list(plan), fetch):
            rows.append(row)
    except ValueError as exc:
        raised = exc
    return rows, raised


@pytest.mark.parametrize("seed", range(12))
def test_parallel_order_and_errors_match_serial(pooled, seed):
    plan = random_plan(seed)
    serial = run(SimpleNamespace(location_pool=None), plan)
    parallel = run(pooled, plan)
    assert parallel[0] == serial[0]
    assert parallel[1] is serial[1]
