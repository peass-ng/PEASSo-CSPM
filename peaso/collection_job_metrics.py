"""Streaming, value-free job timings for identifying a collector's long pole.

Kind names are SHA256 digests of code-owned inventory labels. Scope bindings
use a fresh process-local HMAC key: account/region values cannot be recovered
by enumerating account IDs. Neither the key nor raw labels/scopes leave here.
No result, exception text, item, source path or resource identifier is read.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from types import MappingProxyType


MAX_STREAMED_JOBS = 4096
MAX_RETAINED_JOBS = 16
ROSTER_SHA256 = '37e677633d601df85231f732f7ee6d04e2d9a497391274cc91f66d23974123b9'
MARKER = 'peaso collection job metrics: '
_FIELDS = frozenset({'version', 'job', 'parent', 'kind_sha256', 'scope_hmac_sha256',
                     'start_ms', 'end_ms', 'wall_ms', 'thread_cpu_ms', 'process_cpu_ms', 'failed'})
_SUMMARY_FIELDS = frozenset({'version', 'summary', 'started_jobs', 'completed_jobs',
                            'streamed_jobs', 'suppressed_jobs', 'delivery_failures',
                            'rejected_jobs', 'longest_jobs'})
_parent = ContextVar('collection_job_metric_parent', default=0)
_state = None


class _State:
    def __init__(self, sink, started):
        self.sink, self.started = sink, started
        self.key = secrets.token_bytes(32)
        self.lock, self.sequence = threading.Lock(), 0
        self.completed = self.streamed = self.delivery_failures = self.rejected = 0
        self.longest = []


def configure(sink, *, started):
    global _state
    _state = _State(sink, started) if callable(sink) else None


def close():
    global _state
    state = _state
    _state = None
    _parent.set(0)
    if state is not None:
        try:
            with state.lock:
                event = dict(version=1, summary=1, started_jobs=state.sequence,
                    completed_jobs=state.completed, streamed_jobs=state.streamed,
                    suppressed_jobs=state.completed - state.streamed,
                    delivery_failures=state.delivery_failures, rejected_jobs=state.rejected,
                    longest_jobs=state.longest)
            if (state.sequence or state.rejected) and validate(event):
                state.sink(('__collection_job_metrics__', event))
        except Exception:
            pass
        finally:
            state.key = b''


def _after_fork():
    # Do not acquire an inherited lock or emit the parent's summary in a child.
    global _state
    _state = None
    _parent.set(0)


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


@lru_cache(maxsize=1)
def roster():
    raw = Path(__file__).with_name('collection_job_kinds_20261029.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != ROSTER_SHA256:
        raise ValueError('unreviewed job roster')
    data = json.loads(raw)
    if (data.keys() != {'schema', 'kinds'} or data['schema'] != 1
            or type(data['kinds']) is not list or not 0 < len(data['kinds']) <= 2048
            or any(type(k) is not str or re.fullmatch('[a-z][a-z0-9_]{0,159}', k) is None
                   for k in data['kinds']) or len(set(data['kinds'])) != len(data['kinds'])):
        raise ValueError('invalid job roster')
    return MappingProxyType({hashlib.sha256(k.encode()).hexdigest(): k for k in data['kinds']})


def kind_digest(kind):
    """Resolve a logged label against the finite inventory roster offline."""
    digest = hashlib.sha256(kind.encode('utf-8')).hexdigest()
    if digest not in roster():
        raise ValueError('unreviewed inventory kind')
    return digest


@contextmanager
def span(kind, scope):
    state = _state
    if state is None or type(kind) is not str or type(scope) is not str:
        yield
        return
    # Explicit bounds protect the diagnostic channel, never the collection.
    token = None
    try:
        if not 0 < len(kind) <= 160 or not 0 < len(scope) <= 512:
            raise ValueError('diagnostic bound')
        kind_hash = kind_digest(kind)
        scope_hash = hmac.digest(state.key, scope.encode('utf-8'), 'sha256').hex()
        wall, cpu, process = time.monotonic(), time.thread_time(), time.process_time()
        with state.lock:
            state.sequence += 1
            job = state.sequence
        parent = _parent.get()
        token = _parent.set(job)
    except Exception:
        # Setup failure cannot prevent the caller's inventory read.
        with state.lock:
            state.rejected += 1
        yield
        return
    failed = False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        try:
            if token is not None:
                _parent.reset(token)
            end = time.monotonic()
            event = dict(version=1, job=job, parent=parent, kind_sha256=kind_hash,
                         scope_hmac_sha256=scope_hash,
                         start_ms=max(0, int((wall - state.started) * 1000)),
                         end_ms=max(0, int((end - state.started) * 1000)),
                         wall_ms=max(0, int((end - wall) * 1000)),
                         thread_cpu_ms=max(0, int((time.thread_time() - cpu) * 1000)),
                         process_cpu_ms=max(0, int((time.process_time() - process) * 1000)),
                         failed=int(failed))
            if _state is state and validate_job(event):
                with state.lock:
                    state.completed += 1
                    state.longest = sorted(state.longest + [event],
                        key=lambda r: (-r['wall_ms'], r['job']))[:MAX_RETAINED_JOBS]
                    emit = state.streamed < MAX_STREAMED_JOBS
                    if emit:
                        state.streamed += 1
                if emit:
                    try:
                        state.sink(('__collection_job_metrics__', event))
                    except Exception:
                        with state.lock:
                            state.delivery_failures += 1
        except Exception:
            pass


def validate_job(event):
    if type(event) is not dict or event.keys() != _FIELDS:
        return False
    for key, value in event.items():
        if key in {'kind_sha256', 'scope_hmac_sha256'}:
            if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
                return False
        elif type(value) is not int or not 0 <= value <= 2**63 - 1:
            return False
    return (event['kind_sha256'] in roster() and event['version'] == 1 and event['job'] > 0
            and event['parent'] < event['job'] and event['failed'] in (0, 1)
            and event['end_ms'] >= event['start_ms']
            and abs(event['end_ms'] - event['start_ms'] - event['wall_ms']) <= 1)


def validate(event):
    try:
        if type(event) is not dict:
            return False
        if event.keys() == _FIELDS:
            return validate_job(event)
        if event.keys() != _SUMMARY_FIELDS or type(event['longest_jobs']) is not list:
            return False
        if any(type(v) is not int or not 0 <= v <= 2**63 - 1
               for k, v in event.items() if k != 'longest_jobs'):
            return False
        return (event['version'] == event['summary'] == 1
            and event['completed_jobs'] <= event['started_jobs']
            and event['streamed_jobs'] <= min(event['completed_jobs'], MAX_STREAMED_JOBS)
            and event['suppressed_jobs'] == event['completed_jobs'] - event['streamed_jobs']
            and event['delivery_failures'] <= event['streamed_jobs']
            and len(event['longest_jobs']) == min(event['completed_jobs'], MAX_RETAINED_JOBS)
            and len({r['job'] for r in event['longest_jobs']}) == len(event['longest_jobs'])
            and all(validate_job(r) and r['job'] <= event['started_jobs'] for r in event['longest_jobs']))
    except (KeyError, TypeError, ValueError, OSError):
        return False


def record(event, logger):
    if not validate(event):
        return False
    try:
        logger.info(MARKER + '%s',
                    json.dumps(event, sort_keys=True, separators=(',', ':')))
        return True
    except Exception:
        return False


class JobRetention:
    """Bounded drop-in retention for the existing root-owned log exporter."""
    def __init__(self):
        self.jobs, self.summary = {}, None
        self.invalid_events = self.overflow_events = 0

    def accept(self, message):
        if type(message) is not str or MARKER not in message:
            return False
        try:
            event = json.loads(message.split(MARKER, 1)[1])
        except ValueError:
            self.invalid_events += 1
            return False
        if not validate(event):
            self.invalid_events += 1
            return False
        if 'summary' in event:
            if (self.summary is not None and self.summary != event) or any(
                    row['job'] in self.jobs and self.jobs[row['job']] != row
                    for row in event['longest_jobs']):
                self.invalid_events += 1
                return False
            self.summary = event
            return True
        if event['job'] in self.jobs:
            if self.jobs[event['job']] != event:
                self.invalid_events += 1
                return False
        elif len(self.jobs) < MAX_STREAMED_JOBS:
            self.jobs[event['job']] = event
        else:
            self.overflow_events += 1
            return False
        return True

    def result(self):
        rows = dict(self.jobs)
        if self.summary is not None:
            for row in self.summary['longest_jobs']:
                rows.setdefault(row['job'], row)
        return dict(version=1, roster_sha256=ROSTER_SHA256,
                    jobs=sorted(rows.values(), key=lambda r: r['job']),
                    summary=self.summary, invalid_events=self.invalid_events,
                    overflow_events=self.overflow_events)
