"""Numeric telemetry is bounded, concurrent and cannot carry scanned content."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import threading

import pytest


@pytest.fixture
def subject():
    source = Path(os.environ.get('PEASO_RUNTIME_METRICS_SOURCE', Path.cwd() / 'peaso/runtime_metrics.py'))
    # A fresh instance still belongs to the peaso package, so its relative
    # import of the sibling collection-job metrics resolves as in production.
    spec = importlib.util.spec_from_file_location('peaso._tested_runtime_metrics', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    module.close()


def frame():
    return dict(version=1, role='collector', elapsed_ms=10, process_cpu_ms=3,
                peak_rss_bytes=1024, rows=[dict(stage='engine.analysis', count=1,
                wall_ms=2, thread_cpu_ms=1, process_cpu_ms=1, max_wall_ms=2,
                errors=0, bytes=4)], active=[dict(stage='collection.job', count=2, oldest_ms=4)])


def test_valid_frame_logs_only_numeric_fixed_schema(subject):
    lines = []
    class Logger:
        def info(self, pattern, value):
            lines.append(pattern % value)
    event = frame()
    assert subject.validate(event) is True
    assert subject.record(event, Logger()) is True
    assert json.loads(lines[0].split(': ', 1)[1]) == event


@pytest.mark.parametrize('field,value', [
    ('role', []), ('role', {}), ('role', None), ('role', True), ('role', 'unknown'),
    ('version', True), ('version', 2), ('elapsed_ms', -1), ('elapsed_ms', 1.5),
    ('process_cpu_ms', float('nan')), ('peak_rss_bytes', 10**18 + 1),
    ('rows', {}), ('rows', [None]), ('active', [None]), ('active', {}),
    ('rows', [{'stage': 'engine.analysis'}]),
])
def test_validator_rejects_malformed_frames_without_raising(subject, field, value):
    event = frame(); event[field] = value
    assert subject.validate(event) is False
    assert subject.record(event, object()) is False


@pytest.mark.parametrize('value', [None, [], '', 1, True, {'unexpected': 'secret'}])
def test_validator_rejects_nonframes(subject, value):
    assert subject.validate(value) is False


@pytest.mark.parametrize('key', ['rows', 'active'])
def test_validator_rejects_duplicate_unknown_or_sensitive_labels(subject, key):
    for label in ['unknown', '/tmp/private-credential-file', 'AWS_SECRET_ACCESS_KEY=synthetic', []]:
        event = frame(); event[key][0]['stage'] = label
        assert subject.validate(event) is False
    event = frame(); event[key].append(copy.deepcopy(event[key][0]))
    assert subject.validate(event) is False
    event = frame(); event[key][0]['extra'] = 'synthetic secret'
    assert subject.validate(event) is False
    event = frame(); event[key] *= len(subject._STAGES) + 1
    assert subject.validate(event) is False


@pytest.mark.parametrize('value', [True, -1, 1.0, '4', None, 10**18 + 1])
def test_validator_checks_every_measurement(subject, value):
    for key in ['rows', 'active']:
        original = frame()
        for name in set(original[key][0]) - {'stage'}:
            event = copy.deepcopy(original); event[key][0][name] = value
            assert subject.validate(event) is False


def test_disabled_and_unknown_labels_do_not_read_clocks(subject, monkeypatch):
    def forbidden():
        raise AssertionError('disabled diagnostic read a clock')
    for name in ['monotonic', 'thread_time', 'process_time']:
        monkeypatch.setattr(subject.time, name, forbidden)
    with subject.span('engine.analysis'):
        pass
    subject.add_bytes('engine.analysis', 10)
    subject.flush(); subject.close()


def test_unsupported_labels_never_enter_frame(subject):
    events = []
    subject.configure(events.append, role='analyzer', interval_seconds=60)
    for label in ['/tmp/private-credential-file', 'AWS_SECRET_ACCESS_KEY=synthetic']:
        with subject.span(label):
            pass
        subject.add_bytes(label, 100)
    subject.flush()
    assert events[-1][1]['rows'] == []
    assert events[-1][1]['active'] == []
    assert 'synthetic' not in json.dumps(events)
    assert '/tmp' not in json.dumps(events)


def test_concurrent_active_spans_are_aggregated_and_completed(subject):
    events = []; errors = []; release = threading.Event(); ready = threading.Barrier(5)
    subject.configure(events.append, role='collector', interval_seconds=60)
    def work():
        try:
            with subject.span('collection.job'):
                ready.wait(timeout=3)
                assert release.wait(timeout=3)
                subject.add_bytes('collection.job', 7)
        except BaseException as exc:
            errors.append(exc)
    threads = [threading.Thread(target=work) for _ in range(4)]
    try:
        for thread in threads: thread.start()
        ready.wait(timeout=3)
        subject.flush()
        event = events[-1][1]
        assert subject.validate(event)
        assert event['active'][0]['stage'] == 'collection.job'
        assert event['active'][0]['count'] == 4
        assert event['active'][0]['oldest_ms'] >= 0
    finally:
        release.set()
        for thread in threads: thread.join(timeout=3)
    assert not errors
    assert not any(thread.is_alive() for thread in threads)
    subject.flush()
    event = events[-1][1]
    assert event['active'] == []
    assert len(event['rows']) == 1
    row = event['rows'][0]
    assert (row['count'], row['bytes'], row['errors']) == (4, 28, 0)
    assert row['max_wall_ms'] <= row['wall_ms']


@pytest.mark.parametrize('error', [RuntimeError('synthetic'), KeyboardInterrupt(), SystemExit(2)])
def test_body_exception_preserved_and_counted(subject, error):
    events = []
    subject.configure(events.append, role='analyzer', interval_seconds=60)
    with pytest.raises(type(error)) as caught:
        with subject.span('engine.analysis'):
            raise error
    assert caught.value is error
    subject.flush()
    assert events[-1][1]['rows'][0]['errors'] == 1
    assert events[-1][1]['active'] == []


def test_sink_and_logger_failures_are_nonfatal(subject):
    def broken(_): raise RuntimeError('sink failed')
    subject.configure(broken, role='collector', interval_seconds=60)
    with subject.span('collection.job'): pass
    subject.flush(); subject.close()
    class Logger:
        def info(self, *args): raise RuntimeError('logger failed')
    assert subject.record(frame(), Logger()) is False


def test_heartbeat_uses_interval_and_stops_without_busy_loop(subject):
    # Exercise the actual loop deterministically without a one-second sleep.
    recorder = object.__new__(subject.Recorder)
    waits = []; calls = []
    class Stop:
        def wait(self, interval):
            waits.append(interval)
            return len(waits) == 3
    recorder.stop = Stop(); recorder.interval = 7
    recorder.flush = lambda: calls.append(True)
    recorder._heartbeat()
    assert waits == [7, 7, 7]
    assert calls == [True, True]


def test_add_bytes_rejects_noninteger_and_negative_values(subject):
    events = []
    subject.configure(events.append, role='collector', interval_seconds=60)
    for count in [True, -1, 1.5, '9', None]:
        subject.add_bytes('artifact.s3.put', count)
    subject.add_bytes('artifact.s3.put', 9)
    subject.flush()
    assert events[-1][1]['rows'][0]['bytes'] == 9


@pytest.mark.parametrize('label', [[], {}, None, True, 12])
def test_invalid_label_arguments_are_nonfatal(subject, label):
    subject.configure(lambda _: None, role=label)
    assert subject._recorder is None
    subject.configure(lambda _: None, role='collector', interval_seconds=60)
    with subject.span(label): pass
    subject.add_bytes(label, 1)
    assert subject._recorder.rows == {}


@pytest.mark.parametrize('interval', [None, [], {}, '1', True, float('nan'), float('inf'), -float('inf')])
def test_invalid_interval_disables_diagnostics_without_impact(subject, interval):
    subject.configure(lambda _: None, role='collector', interval_seconds=interval)
    assert subject._recorder is None
    with subject.span('collection.job'): pass


@pytest.mark.parametrize('clock', ['monotonic', 'thread_time', 'process_time'])
@pytest.mark.parametrize('point', ['start', 'finish'])
def test_clock_failure_preserves_body_and_original_exception(subject, monkeypatch, clock, point):
    subject.configure(lambda _: None, role='collector', interval_seconds=60)
    recorder = subject._recorder
    original = getattr(subject.time, clock)
    calls = 0
    def flaky():
        nonlocal calls
        calls += 1
        if point == 'start' or calls > 1:
            raise RuntimeError('measurement failed')
        return original()
    monkeypatch.setattr(subject.time, clock, flaky)
    error = ValueError('body retained')
    with pytest.raises(ValueError) as caught:
        with subject.span('collection.job'):
            raise error
    assert caught.value is error
    assert recorder.active == {}


def test_unavailable_rss_keeps_frame_valid(subject, monkeypatch):
    monkeypatch.setattr(subject, 'resource', None)
    events = []
    subject.configure(events.append, role='collector', interval_seconds=60)
    subject.flush()
    assert events[-1][1]['peak_rss_bytes'] == 0
    assert subject.validate(events[-1][1])


def test_completed_child_cpu_is_numeric_optional_and_bounded(subject):
    metrics = subject
    frames=[]
    metrics.configure(frames.append,role="collector")
    metrics.flush()
    metrics.close()
    event=frames[-1][1]
    assert type(event["completed_children_cpu_ms"]) is int
    assert event["completed_children_cpu_ms"] >= 0
    assert metrics.validate(event)
    event["completed_children_cpu_ms"]="private-value"
    assert not metrics.validate(event)


def test_diagnostic_join_failure_does_not_replace_completion(subject, monkeypatch):
    metrics = subject
    frames=[]
    metrics.configure(frames.append,role="collector")
    recorder=metrics._recorder
    def fail(*args,**kwargs): raise RuntimeError("private-join-error")
    monkeypatch.setattr(recorder.thread,"join",fail)
    metrics.close()
    assert metrics._recorder is None
    assert frames and metrics.validate(frames[-1][1])
