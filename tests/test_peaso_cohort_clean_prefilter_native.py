"""Canonical cohort boundaries/cache/metrics contracts with bounded fake tool output."""
import importlib.util
from pathlib import Path
import sys
import time
import types
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
import pytest

BASE=Path(__file__).parent
@pytest.fixture
def setup(monkeypatch):
    from peaso import secret_scanning_cohort as subject,secret_scanning_batch as batch,secret_scan_clean as clean
    with clean._LOCK:
        previous=clean._CLEAN.copy();clean._CLEAN.clear()
    calls=[]
    class Known:
        def add(self,payload):clean.remember_clean(payload)
    def prepare(items,timeout):
        calls.append(tuple(items));return {item:b'positive' for item in items}
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',prepare)
    try:yield subject,Known(),calls
    finally:
        with clean._LOCK:clean._CLEAN.clear();clean._CLEAN.update(previous)

def test_known_clean_has_no_gather_or_process_and_preserves_finish(setup):
    m,known,calls=setup;known.add(b'clean')
    c=m.ContentCohort(['a','b'],time.monotonic()+3,max_bytes=100,gather_seconds=2)
    start=time.monotonic();assert c.output('a',b'clean','a')==b''
    assert time.monotonic()-start<.2 and not calls and not c.pending
    assert not c.finished
    c.finish('a');assert c.finished=={'a'}
    c.close()

def test_mixed_cached_and_uncached_keeps_exact_member_binding(setup):
    m,known,calls=setup;known.add(b'clean')
    c=m.ContentCohort(['a','b'],time.monotonic()+3,max_bytes=100,gather_seconds=.01)
    def run(member):
        try:return c.output(member,b'clean' if member=='a' else b'unknown',member)
        finally:c.finish(member)
    with ThreadPoolExecutor(2) as pool:assert list(pool.map(run,['a','b']))==[b'',b'positive']
    assert calls==[((b'unknown','b'),)]
    assert not c.results and not c.pending
    c.close()

def test_clean_never_bypasses_identity_capacity_deadline_or_closed(setup):
    m,known,calls=setup;known.add(b'clean')
    c=m.ContentCohort(['a'],time.monotonic()+3,max_bytes=3)
    with pytest.raises(ValueError):c.output('a',b'clean','a')
    with pytest.raises(ValueError):c.output('a',b'clean','other')
    c.close()
    with pytest.raises(RuntimeError):c.output('a',b'clean','a')
    c=m.ContentCohort(['a'],time.monotonic()-1,max_bytes=100)
    with pytest.raises(TimeoutError):c.output('a',b'clean','a')
    assert not calls

def test_all_uncached_still_share_original_preparation(setup):
    m,known,calls=setup
    members=['a','b','c','d'];c=m.ContentCohort(members,time.monotonic()+3,max_bytes=100)
    def run(member):
        try:return c.output(member,member.encode(),member)
        finally:c.finish(member)
    with ThreadPoolExecutor(4) as pool:assert list(pool.map(run,members))==[b'positive']*4
    assert len(calls)==1 and set(calls[0])=={(x.encode(),x) for x in members}
    c.close()

def test_clean_preserves_cancel_and_finished_member_rejection(setup):
    import threading
    m,known,calls=setup;known.add(b'clean')
    cancelled=threading.Event();cancelled.set()
    c=m.ContentCohort(['a'],time.monotonic()+3,max_bytes=100,cancelled=cancelled)
    with pytest.raises(TimeoutError):c.output('a',b'clean','a')
    c=m.ContentCohort(['a'],time.monotonic()+3,max_bytes=100);c.finish('a')
    with pytest.raises(RuntimeError):c.output('a',b'clean','a')
    assert not calls

def test_fixed_metrics_labels_are_validated_and_payload_free(setup,monkeypatch):
    m,known,calls=setup;known.add(b'clean')
    from peaso import runtime_metrics as metrics
    frames=[];metrics.configure(frames.append,role='collector',interval_seconds=30)
    try:
        c=m.ContentCohort(['a'],time.monotonic()+3,max_bytes=100)
        assert c.output('a',b'clean','a')==b'';c.finish('a');c.close()
        c=m.ContentCohort(['b'],time.monotonic()+3,max_bytes=100)
        assert c.output('b',b'unknown','b')==b'positive';c.finish('b');c.close()
    finally:metrics.close()
    assert frames and all(metrics.validate(v) for _,v in frames)
    rows={r['stage']:r for r in frames[-1][1]['rows']}
    assert rows['secret.trufflehog.cohort_clean']['count']==1
    assert rows['secret.trufflehog.cohort_prepare']['count']==1
    assert 'unknown' not in repr(frames) and 'positive' not in repr(frames)
