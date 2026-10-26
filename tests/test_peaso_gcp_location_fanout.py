import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from peaso.collectors.gcp import GCPCollector, ReadError, endpoint_page_size
from peaso.collectors.gcp_fanout import POOL_PREFIX, fanout_pages, location_fanout


@pytest.fixture
def collector():
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix=POOL_PREFIX)
    try:
        yield SimpleNamespace(location_pool=pool)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def reader(plan, calls):
    """plan: location -> (pages, error, delay)."""
    lock = threading.Lock()

    def fetch(location):
        with lock:
            calls.append(location)
        pages, error, delay = plan[location]
        time.sleep(delay)
        yield from pages
        if error is not None:
            raise error
    return fetch


def test_replays_pages_and_errors_in_location_order(collector):
    failure = ReadError("denied", "permission_denied", http_status=403)
    plan = {
        "a": ([["a1"], ["a2"]], None, 0.0),
        "b": ([["b1"]], failure, 0.05),  # slowest finishes last but replays second
        "c": ([["c1"]], None, 0.0),
    }
    calls = []
    out = list(location_fanout(collector, ["a", "b", "c"], reader(plan, calls)))
    assert out == [("a", [["a1"]], None), ("a", [["a2"]], None),
                   ("b", [["b1"]], None), ("b", [], failure), ("c", [["c1"]], None)]
    assert sorted(calls) == ["a", "b", "c"] and calls[0] == "a"


def test_matches_serial_loop_without_pool():
    failure = ReadError("unavailable", "read_failed", http_status=500)
    plan = {"a": ([["a1"]], None, 0.0), "b": ([], failure, 0.0), "c": ([["c1"]], None, 0.0)}
    serial = list(location_fanout(SimpleNamespace(location_pool=None), list(plan), reader(plan, [])))
    pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix=POOL_PREFIX)
    try:
        fanned = list(location_fanout(SimpleNamespace(location_pool=pool), list(plan), reader(plan, [])))
    finally:
        pool.shutdown(wait=True)
    assert serial == fanned


def test_disabled_service_probe_short_circuits_before_other_reads(collector):
    disabled = ReadError("not_enabled", "permission_denied", http_status=403, reason="SERVICE_DISABLED")
    plan = {"a": ([], disabled, 0.0), "b": ([["b1"]], None, 0.0), "c": ([["c1"]], None, 0.0)}
    calls = []
    for location, _pages, error in location_fanout(collector, ["a", "b", "c"], reader(plan, calls)):
        assert location == "a" and error is disabled
        break  # call sites stop on a disabled service
    collector.location_pool.shutdown(wait=True)
    assert calls == ["a"]


def test_fanout_pages_raises_first_failure_after_its_pages(collector):
    first = ReadError("denied", "permission_denied", http_status=403)
    later = ReadError("unavailable", "read_failed", http_status=500)
    plan = {"a": ([["a1"]], None, 0.0), "b": ([["b1"]], first, 0.02), "c": ([["c1"]], later, 0.0)}
    seen = []
    with pytest.raises(ReadError) as raised:
        for page in fanout_pages(collector, ["a", "b", "c"], reader(plan, [])):
            seen.append(page)
    assert raised.value is first
    assert seen == [["a1"], ["b1"]]


def test_other_exceptions_raise_at_their_serial_position(collector):
    plan = {"a": ([["a1"]], None, 0.0), "b": ([["b1"]], ValueError("bad identity"), 0.0), "c": ([["c1"]], None, 0.0)}
    seen = []
    with pytest.raises(ValueError, match="bad identity"):
        for location, pages, error in location_fanout(collector, ["a", "b", "c"], reader(plan, [])):
            seen.append((location, pages, error))
    assert seen == [("a", [["a1"]], None), ("b", [["b1"]], None)]


def test_nested_fanout_from_pool_thread_runs_serially(collector):
    plan = {"x": ([["x1"]], None, 0.0), "y": ([["y1"]], None, 0.0)}
    threads = []

    def inner(location):
        threads.append(threading.current_thread().name)
        yield from plan[location][0]

    def outer(location):
        yield list(fanout_pages(collector, ["x", "y"], inner)) + [location]

    out = list(fanout_pages(collector, ["o1", "o2", "o3"], outer))
    assert out == [[["x1"], ["y1"], "o1"], [["x1"], ["y1"], "o2"], [["x1"], ["y1"], "o3"]]
    # Inner reads issued from pool workers stay on that worker (no self-wait).
    assert len(threads) == 6


@pytest.mark.parametrize(("url", "method", "expected"), [
    ("https://cloudasset.googleapis.com/v1/organizations/1:searchAllResources", "GET", 500),
    ("https://cloudasset.googleapis.com/v1/projects/p:searchAllIamPolicies", "GET", 500),
    ("https://cloudasset.googleapis.com/v1/projects/p/assets", "GET", 1000),
    ("https://cloudasset.googleapis.com/v1/folders/1/assets", "GET", 1000),
    ("https://cloudasset.googleapis.com/v1/projects/p/feeds", "GET", None),
    ("https://compute.googleapis.com/compute/v1/projects/p/aggregated/instances", "GET", 500),
    ("https://storage.googleapis.com/storage/v1/b", "GET", 1000),
    ("https://run.googleapis.com/v2/projects/p/locations/-/services", "GET", None),
])
def test_endpoint_page_size(url, method, expected):
    assert endpoint_page_size(url, method) == expected


def test_default_page_size_uses_endpoint_maximum_only_when_unset():
    unset = SimpleNamespace(options={}, page_size=100)
    assert GCPCollector.default_page_size(unset, "https://storage.googleapis.com/storage/v1/b") == 1000
    assert GCPCollector.default_page_size(unset, "https://compute.googleapis.com/compute/v1/x") == 500
    assert GCPCollector.default_page_size(unset, "https://run.googleapis.com/v2/x") == 100
    explicit = SimpleNamespace(options={"page_size": 200}, page_size=200)
    assert GCPCollector.default_page_size(explicit, "https://storage.googleapis.com/storage/v1/b") == 200
    assert GCPCollector.default_page_size(explicit, "https://run.googleapis.com/v2/x") == 200
    big = SimpleNamespace(options={"page_size": 1000}, page_size=1000)
    assert GCPCollector.default_page_size(big, "https://compute.googleapis.com/compute/v1/x") == 500


def test_read_raises_only_the_seeded_default_page_size():
    seen = []
    class Transport:
        def request(self, method, url, *, params=None, body=None, scope=None, operation=None):
            seen.append(dict(params))
            return {}
    storage = "https://storage.googleapis.com/storage/v1/b"
    unset = SimpleNamespace(options={}, page_size=100, transport=Transport())
    for name in ("default_page_size", "_bulk_page_params"):
        setattr(unset, name, getattr(GCPCollector, name).__get__(unset))
    original = {"pageSize": 100, "pageToken": "t"}
    GCPCollector.read(unset, storage, "projects/p", params=original)
    GCPCollector.read(unset, storage, "projects/p", params={"pageSize": 50})
    GCPCollector.read(unset, "https://run.googleapis.com/v2/x", "projects/p", params={"pageSize": 100})
    explicit = SimpleNamespace(options={"page_size": 100}, page_size=100, transport=Transport())
    for name in ("default_page_size", "_bulk_page_params"):
        setattr(explicit, name, getattr(GCPCollector, name).__get__(explicit))
    GCPCollector.read(explicit, storage, "projects/p", params={"pageSize": 100})
    assert seen == [{"pageSize": 1000, "pageToken": "t"}, {"pageSize": 50},
                    {"pageSize": 100}, {"pageSize": 100}]
    assert original == {"pageSize": 100, "pageToken": "t"}


"""Real lazy generators and real thread pools; no provider credentials or SDK calls."""
import ast
import os
import importlib.util
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT=Path(os.environ.get('PEASO_TEST_SOURCE_ROOT',Path(__file__).parents[1]))
CANDIDATE=Path(__file__).parents[1]/'peaso/collectors/gcp_fanout.py'
spec=importlib.util.spec_from_file_location('gcp_bounded_fanout_candidate',CANDIDATE)
fanout=importlib.util.module_from_spec(spec);spec.loader.exec_module(fanout)
node=next(n for n in ast.parse((ROOT/'peaso/collectors/gcp.py').read_text()).body if isinstance(n,ast.ClassDef) and n.name=='ReadError')
ns={'__name__':'peaso.collectors.gcp','SAFE_REASONS':{'SERVICE_DISABLED','BILLING_DISABLED'}}
exec(compile(ast.Module(body=[node],type_ignores=[]),'gcp-read-error','exec'),ns);StreamingReadError=ns['ReadError']

@pytest.fixture
def bounded_collector():
    pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix=fanout.POOL_PREFIX)
    value=SimpleNamespace(location_pool=pool,options={},max_items=None)
    try:yield value
    finally:pool.shutdown(wait=True,cancel_futures=True)


def flattened(rows):
    return [(location,page) for location,pages,error in rows for page in pages]


def test_first_yield_reads_only_one_probe_page_and_close_closes_source(bounded_collector):
    reads=[];closed=[]
    def fetch(location):
        try:
            reads.append(location);yield ['first']
            pytest.fail('First next() drained beyond its visible page')
        finally:closed.append(location)
    stream=fanout.location_fanout(bounded_collector,['a','b','c'],fetch)
    assert next(stream)==('a',[['first']],None)
    stream.close();assert reads==closed==['a']


@pytest.mark.parametrize('cap_kind',['max_items','max_resources'])
def test_hard_resource_cap_has_zero_background_or_next_page_overfetch(bounded_collector,cap_kind):
    if cap_kind=='max_items':bounded_collector.max_items=1
    else:bounded_collector.options={'max_resources':1}
    reads=[]
    def fetch(location):
        for i in range(100):reads.append((location,i));yield [i]
    stream=fanout.fanout_pages(bounded_collector,['a','b','c'],fetch)
    assert next(stream)==[0];time.sleep(.02);assert reads==[('a',0)]
    stream.close();bounded_collector.location_pool.shutdown(wait=True);assert reads==[('a',0)]


def test_serial_no_pool_streams_without_whole_location_buffer():
    reads=[]
    def fetch(location):
        for i in range(10):reads.append((location,i));yield i
    stream=fanout.location_fanout(SimpleNamespace(location_pool=None),['a','b'],fetch)
    assert next(stream)==('a',[0],None) and reads==[('a',0)]
    stream.close()


def test_uncapped_fanout_is_parallel_but_each_location_buffers_at_most_one_page(bounded_collector):
    seen=[];other_started=threading.Event();lock=threading.Lock()
    def fetch(location):
        if location=='a':yield 'probe';return
        if location=='b':assert other_started.wait(1), 'Later location did not overlap b'
        if location=='c':other_started.set()
        for i in range(100):
            with lock:seen.append((location,i))
            yield (location,i)
    stream=fanout.fanout_pages(bounded_collector,['a','b','c','d','e'],fetch)
    assert next(stream)=='probe';assert next(stream)==('b',0)
    time.sleep(.03)
    with lock:
        assert len([x for x in seen if x[0]=='b'])<=2
        assert len([x for x in seen if x[0]=='c'])<=1
        assert not any(x[0] in ('d','e') for x in seen)
    stream.close()


def test_first_failing_location_preserves_pages_and_error_identity(bounded_collector):
    first=StreamingReadError('denied','first');later=StreamingReadError('unavailable','later')
    def fetch(location):
        yield location+'1'
        if location=='b':raise first
        if location=='c':raise later
    seen=[]
    with pytest.raises(StreamingReadError) as exc:
        for page in fanout.fanout_pages(bounded_collector,['a','b','c'],fetch):seen.append(page)
    assert exc.value is first and seen==['a1','b1']


def test_non_read_error_raises_at_serial_position_after_prior_pages(bounded_collector):
    failure=ValueError('synthetic malformed identity')
    def fetch(location):
        yield location+'1'
        if location=='b':raise failure
    stream=fanout.fanout_pages(bounded_collector,['a','b','c'],fetch);seen=[]
    with pytest.raises(ValueError) as exc:
        for page in stream:seen.append(page)
    assert exc.value is failure and seen==['a1','b1']


def test_disabled_probe_schedules_nothing_until_caller_continues(bounded_collector):
    disabled=StreamingReadError(reason='SERVICE_DISABLED');calls=[]
    def fetch(location):
        calls.append(location)
        if location=='a':raise disabled
        yield location
    stream=fanout.location_fanout(bounded_collector,['a','b','c'],fetch)
    assert next(stream)==('a',[],disabled);time.sleep(.02);assert calls==['a']
    stream.close();assert calls==['a']
    calls.clear();rows=list(fanout.location_fanout(bounded_collector,['a','b','c'],fetch))
    assert rows[0]==('a',[],disabled) and flattened(rows)==[('b','b'),('c','c')]


def test_partial_read_close_cancels_and_closes_running_iterators_without_queue_deadlock(bounded_collector):
    release=threading.Event();started=threading.Event();closed=set();calls=[]
    def fetch(location):
        try:
            if location=='a':yield 'a';return
            if location=='c':started.set();assert release.wait(1)
            for i in range(100):calls.append((location,i));yield (location,i)
        finally:closed.add(location)
    stream=fanout.fanout_pages(bounded_collector,['a','b','c','d'],fetch)
    assert next(stream)=='a';assert next(stream)==('b',0);assert started.wait(1)
    stream.close();release.set();bounded_collector.location_pool.shutdown(wait=True,cancel_futures=True)
    assert {'a','b','c'}<=closed and not any(x[0]=='d' for x in calls)
    assert not any(i>1 for location,i in calls if location=='b')
    assert not any(i>0 for location,i in calls if location=='c')


def test_all_pages_order_and_empty_location_are_preserved(bounded_collector):
    def fetch(location):
        if location=='b':return
        yield location+'1';yield location+'2'
    rows=list(fanout.location_fanout(bounded_collector,['a','b','c'],fetch))
    assert flattened(rows)==[('a','a1'),('a','a2'),('c','c1'),('c','c2')]
    assert ('b',[],None) in rows


def test_nested_location_worker_never_waits_for_its_own_pool(bounded_collector):
    def run():return list(fanout.fanout_pages(bounded_collector,['x','y'],lambda location:iter([location])))
    assert bounded_collector.location_pool.submit(run).result(timeout=1)==['x','y']
