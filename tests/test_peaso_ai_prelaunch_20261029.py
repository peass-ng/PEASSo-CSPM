"""Prelaunched hosted AI tasks move only image pull/startup, never model work."""
import json
import threading
import time

import pytest

from peaso.ai import fargate, pipeline, task_runtime
from tests.test_peaso_ai_fargate import Storage, Tasks, configured  # noqa: F401 - fixture
from tests.test_peaso_ai_review import environment, mocked_agent_isolation  # noqa: F401 - fixtures


class Ordered(Tasks):
    """ECS stand-in: the first ``live_checks`` reads report ``live``, then a finished agent."""

    def __init__(self, events, live='RUNNING', live_checks=1):
        super().__init__(stopped=True)
        self.events, self.live, self.live_checks = events, live, live_checks

    def describe_task_definition(self, **kw):
        self.events.append('describe_definition')
        return super().describe_task_definition(**kw)

    def run_task(self, **kw):
        self.events.append('launch')
        return super().run_task(**kw)

    def describe_tasks(self, **kw):
        if self.live_checks:
            self.live_checks -= 1
            return {'tasks': [{'lastStatus': self.live, 'desiredStatus': 'RUNNING', 'containers': []}]}
        return super().describe_tasks(**kw)

    def stop_task(self, **kw):
        self.events.append('stop')
        super().stop_task(**kw)


class OrderedStorage(Storage):
    def __init__(self, events):
        super().__init__()
        self.events = events

    def put_object(self, **kw):
        self.events.append(kw['Key'].rsplit('/', 1)[-1])
        return super().put_object(**kw)


def test_prelaunched_task_has_no_credential_and_invocation_budget_starts_at_input(configured, tmp_path):
    events, now = [], [0.0]
    tasks, storage = Ordered(events), OrderedStorage(events)
    warm = fargate.prelaunch(900, ecs=tasks, s3=storage, clock=lambda: now[0])
    assert events == ['describe_definition', 'launch'] and not storage.objects
    request = tasks.requests[0]
    overrides = {row['name']: {item['name']: item['value'] for item in row['environment']}
                 for row in request['overrides']['containerOverrides']}
    assert overrides['relay']['PEASO_AI_BOOTSTRAP_WAIT_SECONDS'] == '900'
    assert overrides['agent'] == {'PEASO_AI_BOOTSTRAP_WAIT_SECONDS': '900'}
    assert overrides['relay']['PEASO_AI_BOOTSTRAP_URL'].split('?')[0].endswith(warm.keys['relay.json'])
    assert 'real-private-token' not in json.dumps(request)

    # Network runs for 400 s while the idle task waits for its bootstrap.
    now[0] = 400.0

    def prepare():
        events.append('prepare')
        (tmp_path / 'credentials.json').write_text('{"entries":[]}')

    assert fargate.invoke('priorities', tmp_path, 'real-private-token', 1500, prepare=prepare,
                          prelaunched=warm, clock=lambda: now[0]) == {'items': []}
    # No second launch or definition read; relay config is written only now.
    assert events[2:] == ['relay.json', 'prepare', 'input.tgz', 'stop']
    relay = json.loads(storage.objects[warm.keys['relay.json']])
    assert relay['token'] == 'real-private-token' and relay['stage'] == 'priorities'
    # The full invocation budget, not budget minus the time spent waiting.
    assert relay['timeout'] == 1500
    assert len(tasks.requests) == 1 and len(tasks.stops) == 1
    assert set(storage.deleted) == set(warm.keys.values())


@pytest.mark.parametrize('state,elapsed', [('STOPPED', 10.0), ('RUNNING', 860.0)])
def test_unusable_prelaunched_task_is_stopped_and_a_fresh_task_is_launched(configured, tmp_path, state, elapsed):
    events, now = [], [0.0]
    tasks, storage = Ordered(events, live=state, live_checks=1 if state == 'STOPPED' else 0), OrderedStorage(events)
    warm = fargate.prelaunch(900, ecs=tasks, s3=storage, clock=lambda: now[0])
    now[0] = elapsed
    (tmp_path / 'credentials.json').write_text('{"entries":[]}')
    assert fargate.invoke('priorities', tmp_path, 'private', 30, prelaunched=warm,
                          ecs=tasks, s3=storage, clock=lambda: now[0]) == {'items': []}
    assert len(tasks.requests) == 2 and len(tasks.stops) == 2
    fresh = tasks.requests[1]['overrides']['containerOverrides']
    assert [row['name'] for row in fresh] == ['relay']
    assert all(row['name'] != 'PEASO_AI_BOOTSTRAP_WAIT_SECONDS' for row in fresh[0]['environment'])


def test_unused_or_late_prelaunch_is_always_stopped():
    closed, release = [], threading.Event()

    class Task:
        def close(self):
            closed.append(True)

    def slow(wait):
        assert release.wait(5)
        return Task()

    handle = fargate.Prelaunch(900, launcher=slow)
    assert handle.claim(timeout=0.01) is None
    release.set()
    handle._thread.join(5)
    assert closed == [True]

    handle = fargate.Prelaunch(900, launcher=lambda wait: Task())
    task = handle.claim()
    assert isinstance(task, Task) and handle.claim() is None
    handle.close()
    assert closed == [True]
    handle = fargate.Prelaunch(900, launcher=lambda wait: Task())
    handle._thread.join(5)
    handle.close()
    assert closed == [True, True]
    failed = fargate.Prelaunch(900, launcher=lambda wait: (_ for _ in ()).throw(RuntimeError('quota')))
    assert failed.claim() is None


def test_relay_waits_only_for_missing_bootstrap_object(monkeypatch):
    statuses, now = [404, 403, 200], [0.0]

    def transfer(method, url, *, limit, pending=()):
        status = statuses.pop(0)
        if status in pending:
            raise task_runtime.TransferPending()
        return b'{"stage":"priorities"}'

    monkeypatch.setattr(task_runtime, 'transfer', transfer)
    sleep = lambda seconds: now.__setitem__(0, now[0] + seconds)
    assert task_runtime.fetch_bootstrap('https://x', 30, clock=lambda: now[0], sleep=sleep) == b'{"stage":"priorities"}'
    statuses[:] = [404] * 200
    with pytest.raises(RuntimeError, match='task_bootstrap_unavailable'):
        task_runtime.fetch_bootstrap('https://x', 30, clock=lambda: now[0], sleep=sleep)
    # Without a prelaunch wait the relay keeps its single-fetch behavior.
    calls = []
    monkeypatch.setattr(task_runtime, 'transfer', lambda method, url, *, limit, pending=(): calls.append(pending) or b'{}')
    assert task_runtime.fetch_bootstrap('https://x', 0) == b'{}' and calls == [()]
    for value in ('0', '-1', '1801', 'x', '1.5'):
        with pytest.raises(ValueError):
            task_runtime.bootstrap_wait(value)
    assert task_runtime.bootstrap_wait(None) == 0 and task_runtime.bootstrap_wait('900') == 900


def test_short_signing_credentials_never_back_a_waiting_relay(configured):
    import datetime

    class Signer:
        _credentials = type('Credentials', (), {'_expiry_time': datetime.datetime.now(
            datetime.timezone.utc) + datetime.timedelta(seconds=200)})()

    storage = Storage()
    storage._request_signer = Signer()
    tasks = Tasks()
    with pytest.raises(RuntimeError, match='ai_prelaunch_signing_lifetime'):
        fargate.prelaunch(900, ecs=tasks, s3=storage)
    assert not tasks.requests


def test_priorities_task_starts_during_network_with_identical_inputs_and_budget(
        environment, mocked_agent_isolation, monkeypatch):
    """Same review_scan with and without prelaunch: identical Priorities calls."""
    from tests import test_peaso_ai_review as review_tests
    data, inventory, network_output = review_tests.network_fixture()
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: inventory)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 4 * 1024**3)
    monkeypatch.setattr('peaso.least_privilege.project', lambda *a, **k: {'items': []})
    monkeypatch.setenv('PEASO_AI_TIMEOUT_SECONDS', '3000')
    clock = [1000.0]
    monkeypatch.setattr(pipeline, 'time', type('T', (), {'monotonic': staticmethod(lambda: clock[0]),
                                                         'time': staticmethod(time.time)}))

    def run(prelaunch_enabled):
        launched, calls = [], []

        class Warm:
            closed = False
            def close(self):
                self.closed = True

        warm = Warm()

        class Handle:
            def __init__(self, wait):
                launched.append(('launch', wait, clock[0]))
            def claim(self, timeout=10):
                launched.append(('claim', clock[0]))
                return warm
            def close(self):
                launched.append(('close', clock[0]))

        monkeypatch.setattr(pipeline, 'start_prelaunch',
                            (lambda wait: Handle(wait)) if prelaunch_enabled else (lambda wait: None))

        def invoke(stage, platform, entries, token, findings, reviews, timeout, **kwargs):
            if stage == 'network':
                assert not kwargs
                # Priorities' idle task is already starting while Network runs.
                assert [row[0] for row in launched] == (['launch'] if prelaunch_enabled else [])
                clock[0] += 477.0
                return network_output
            assert stage == 'priorities'
            assert set(kwargs) == ({'prelaunched'} if prelaunch_enabled else set())
            if prelaunch_enabled:
                assert kwargs['prelaunched'] is warm
            prepared = platform() if callable(platform) else platform
            calls.append(json.dumps({'timeout': timeout, 'findings': findings, 'reviews': reviews,
                                     'entries': entries, 'platform': prepared}, sort_keys=True, default=str))
            return {'actions': [], 'limitations': []}

        monkeypatch.setattr(pipeline, 'invoke', invoke)
        clock[0] = 1000.0
        result = pipeline.review_scan(data, {}, {}, tenant='alice', artifacts=environment[2])
        return result, calls, launched

    baseline, baseline_calls, none = run(False)
    candidate, candidate_calls, launched = run(True)
    assert none == []
    assert baseline_calls == candidate_calls and len(candidate_calls) == 1
    assert json.dumps(baseline, sort_keys=True) == json.dumps(candidate, sort_keys=True)
    assert launched[0][0] == 'launch' and launched[0][2] == 1000.0
    assert launched[1] == ('claim', 1477.0) and launched[-1][0] == 'close'
