"""Hosted Priorities reuses the scan's Network task; no idle prelaunched task."""
import base64
import hashlib
import http.client
from http.server import ThreadingHTTPServer
import json
import subprocess
import sys
import threading
import time

import pytest

from peaso.ai import fargate, model_relay, pipeline, task_runtime
from tests.test_peaso_ai_fargate import configured, definition  # noqa: F401 - fixture
from tests.test_peaso_ai_review import environment, mocked_agent_isolation  # noqa: F401 - fixtures

BINDING = fargate.binding('alice', 'a' * 32)
TASK_ARN = 'arn:aws:ecs:us-east-1:111122223333:task/cspm-ai/' + 'b' * 32


class Missing(Exception):
    response = {'Error': {'Code': 'NoSuchKey'}}


class Storage:
    def __init__(self, events=None):
        self.objects, self.deleted, self.events = {}, [], events if events is not None else []

    def put_object(self, **kw):
        assert kw['ServerSideEncryption'] == 'AES256'
        self.events.append(('put', kw['Key']))
        self.objects[kw['Key']] = kw['Body']

    def generate_presigned_url(self, operation, Params, ExpiresIn):
        assert 0 < ExpiresIn <= 3600
        return 'https://private-ai-bucket.s3.us-east-1.amazonaws.com/' + Params['Key'] + '?signature=inert'

    def get_object(self, **kw):
        import io
        if kw['Key'] not in self.objects:
            raise Missing()
        return {'Body': io.BytesIO(self.objects[kw['Key']])}

    def delete_objects(self, **kw):
        for row in kw['Delete']['Objects']:
            self.deleted.append(row['Key'])
            self.objects.pop(row['Key'], None)


class Tasks:
    """ECS stand-in whose task state the simulated containers change."""

    def __init__(self, events=None):
        self.requests, self.stops, self.state = [], [], {'status': 'RUNNING', 'exit': None}
        self.events = events if events is not None else []

    def describe_task_definition(self, **kw):
        return {'taskDefinition': definition()}

    def run_task(self, **kw):
        self.events.append(('launch',))
        self.requests.append(kw)
        return {'tasks': [{'taskArn': TASK_ARN}]}

    def describe_tasks(self, **kw):
        agent = {'name': 'agent'}
        if self.state['exit'] is not None:
            agent.update(lastStatus='STOPPED', exitCode=self.state['exit'])
        return {'tasks': [{'lastStatus': self.state['status'], 'desiredStatus': 'RUNNING', 'containers': [agent]}]}

    def stop_task(self, **kw):
        self.events.append(('stop',))
        self.stops.append(kw)
        self.state.update(status='STOPPED', exit=self.state['exit'] if self.state['exit'] is not None else 137)


def environment_of(request):
    return {row['name']: {item['name']: item['value'] for item in row['environment']}
            for row in request['overrides']['containerOverrides']}


def write_input(root):
    (root / 'credentials.json').write_text('{"entries":[]}')


def run_network(tasks, storage, root, now, sink):
    keys = None

    def sleep(seconds):
        # The retained agent posts its validated result and stays up.
        now[0] += seconds
        storage.objects[keys['result.json']] = b'{"findings":[]}'

    write_input(root)
    real_keys = fargate._keys

    def capture(ident, sequence=1):
        nonlocal keys
        value = real_keys(ident, sequence)
        if sequence == 1:
            keys = value
        return value

    fargate._keys = capture
    try:
        return fargate.invoke('network', root, 'real-private-token', 600, ecs=tasks, s3=storage,
                              clock=lambda: now[0], sleep=sleep, task_binding=BINDING, retain=sink), keys
    finally:
        fargate._keys = real_keys


def run_priorities(tasks, storage, root, now, descriptor, *, accept=True, exit_code=0, timeout=1500):
    keys = fargate._keys(descriptor['ident'], 2)

    def sleep(seconds):
        now[0] += seconds
        if accept:
            storage.objects[keys['accepted.json']] = b'{}'
            storage.objects[keys['result.json']] = b'{"actions":[]}'
        tasks.state['exit'] = exit_code

    def prepare():
        write_input(root)

    return fargate.invoke('priorities', root, 'real-private-token', timeout, prepare=prepare, ecs=tasks,
                          s3=storage, clock=lambda: now[0], sleep=sleep, task_binding=BINDING,
                          reuse=descriptor), keys


def test_priorities_runs_in_network_task_with_one_launch_per_scan(configured, tmp_path):
    events = []
    tasks, storage, now, sink = Tasks(events), Storage(events), [0.0], {}
    (tmp_path / 'n').mkdir()
    (tmp_path / 'p').mkdir()
    data, network_keys = run_network(tasks, storage, tmp_path / 'n', now, sink)
    assert data == {'findings': []}
    descriptor = sink['task']
    assert descriptor['task'] == TASK_ARN and descriptor['binding'] == BINDING
    assert descriptor['ready_until'] <= time.time() + fargate.REUSE_IDLE_SECONDS
    # Network's task is kept, but its exact transport objects are already gone.
    assert not tasks.stops and set(network_keys.values()) <= set(storage.deleted)
    launch = environment_of(tasks.requests[0])
    assert launch['agent'] == {'PEASO_AI_REUSE_IDLE_SECONDS': str(fargate.REUSE_IDLE_SECONDS)}
    assert launch['relay']['PEASO_AI_TASK_BINDING'] == BINDING
    assert launch['relay']['PEASO_AI_NEXT_BOOTSTRAP_URL'].split('?')[0].endswith(
        fargate._keys(descriptor['ident'], 2)['relay.json'])
    assert 'real-private-token' not in json.dumps(tasks.requests)

    result, keys = run_priorities(tasks, storage, tmp_path / 'p', now, descriptor)
    assert result == {'actions': []}
    assert len(tasks.requests) == 1, 'Priorities must not start a second task'
    assert keys['relay.json'] not in storage.objects  # deleted after the invocation
    assert len(tasks.stops) == 1 and set(keys.values()) <= set(storage.deleted)
    # Ordering: Priorities' credential configuration only after Network finished.
    puts = [event[1].rsplit('/', 2) for event in events if event[0] == 'put']
    assert puts[-2][-2:] == ['2', 'relay.json'] and puts[-1][-2:] == ['2', 'input.tgz']


def test_reused_invocation_has_identical_model_configuration_and_budget(configured, tmp_path):
    from peaso.ai.providers import ModelAccess
    access = ModelAccess('openai', 'OPENAI_BEST_QUALITY', 'high', 'real-private-token')
    captured = {}

    class Recording(Storage):
        def put_object(self, **kw):
            if kw['Key'].endswith('relay.json'):
                captured.setdefault('relays', []).append(json.loads(kw['Body']))
            return super().put_object(**kw)

    # Fresh Priorities task, exactly as before.
    tasks, storage = Tasks(), Recording()
    tasks.state.update(status='STOPPED', exit=0)
    write_input(tmp_path)
    storage.objects['invocations/fixed/result.json'] = b'{"actions":[]}'
    storage.get_object = lambda **kw: Storage.get_object(storage, Key='invocations/fixed/result.json')
    fargate.invoke('priorities', tmp_path, access, 1500, ecs=tasks, s3=storage, clock=lambda: 0.0)
    fresh = captured['relays'][-1]
    # The same invocation sent to this scan's retained Network task.
    tasks, storage, now, sink = Tasks(), Recording(), [0.0], {}
    (tmp_path / 'n').mkdir()
    (tmp_path / 'p').mkdir()
    run_network(tasks, storage, tmp_path / 'n', now, sink)

    def sleep(seconds):
        keys = fargate._keys(sink['task']['ident'], 2)
        storage.objects[keys['accepted.json']] = b'{}'
        storage.objects[keys['result.json']] = b'{"actions":[]}'
        tasks.state['exit'] = 0

    write_input(tmp_path / 'p')
    assert fargate.invoke('priorities', tmp_path / 'p', access, 1500, ecs=tasks, s3=storage, clock=lambda: 0.0,
                          sleep=sleep, task_binding=BINDING, reuse=sink['task']) == {'actions': []}
    reused = captured['relays'][-1]
    for key in ('version', 'stage', 'token', 'ai_configuration', 'timeout'):
        assert reused[key] == fresh[key], key
    assert reused['ai_configuration'] == {'provider': 'openai', 'model': 'OPENAI_BEST_QUALITY', 'thinking': 'high'}
    assert reused['timeout'] == 1500 and reused['sequence'] == 2 and reused['binding'] == BINDING
    assert 'accepted_url' in reused and 'accepted_url' not in fresh and 'sequence' not in fresh


@pytest.mark.parametrize('case', ['stopped', 'expired', 'rejected', 'not_accepted'])
def test_unusable_retained_task_raises_reuse_error_and_cleans_up(configured, tmp_path, case):
    tasks, storage, now, sink = Tasks(), Storage(), [0.0], {}
    (tmp_path / 'n').mkdir()
    (tmp_path / 'p').mkdir()
    run_network(tasks, storage, tmp_path / 'n', now, sink)
    descriptor = dict(sink['task'])
    if case == 'stopped':
        tasks.state.update(status='STOPPED', exit=0)
    if case == 'expired':
        descriptor['ready_until'] = time.time() + fargate.REUSE_MARGIN - 1
    with pytest.raises(fargate.TaskReuseError):
        if case == 'rejected':
            # The relay refuses the invocation and its task stops unacknowledged.
            run_priorities(tasks, storage, tmp_path / 'p', now, descriptor, accept=False, exit_code=137)
        elif case == 'not_accepted':
            def never(seconds):
                now[0] += seconds
            write_input(tmp_path / 'p')
            fargate.invoke('priorities', tmp_path / 'p', 'real-private-token', 1500, ecs=tasks, s3=storage,
                           clock=lambda: now[0], sleep=never, task_binding=BINDING, reuse=descriptor)
        else:
            run_priorities(tasks, storage, tmp_path / 'p', now, descriptor)
    keys = fargate._keys(descriptor['ident'], 2)
    if case in ('stopped', 'expired'):
        # Refused before any credential-bearing configuration was written.
        assert keys['relay.json'] not in storage.objects and not tasks.stops
    else:
        assert tasks.stops and keys['relay.json'] not in storage.objects
    assert len(tasks.requests) == 1


def test_other_scan_or_tenant_cannot_take_a_retained_task(configured, tmp_path):
    tasks, storage, now, sink = Tasks(), Storage(), [0.0], {}
    (tmp_path / 'n').mkdir()
    run_network(tasks, storage, tmp_path / 'n', now, sink)
    calls = []
    tasks.describe_tasks = lambda **kw: calls.append(kw) or pytest.fail('foreign task inspected')
    write_input(tmp_path)
    for other in (fargate.binding('mallory', 'a' * 32), fargate.binding('alice', 'c' * 32)):
        with pytest.raises(fargate.TaskReuseError):
            fargate.invoke('priorities', tmp_path, 'real-private-token', 1500, ecs=tasks, s3=storage,
                           task_binding=other, reuse=sink['task'])
    assert not calls and not any(key.endswith('2/relay.json') for key in storage.objects)
    # The task itself also checks the binding on every invocation.
    assert task_runtime.admit({'sequence': 1, 'binding': BINDING}, 1, BINDING)
    for config, sequence in (({'sequence': 2, 'binding': fargate.binding('mallory', 'a' * 32)}, 2),
                             ({'sequence': 2}, 2), ({'sequence': 1, 'binding': BINDING}, 2),
                             ({'sequence': 2, 'binding': BINDING}, 1)):
        with pytest.raises(ValueError):
            task_runtime.admit(config, sequence, BINDING)
    with pytest.raises(ValueError):
        task_runtime.admit({'sequence': 2, 'binding': BINDING}, 2, None)


def test_invocation_without_binding_cannot_retain_or_reuse(tmp_path):
    for kwargs in ({'retain': {}}, {'reuse': {'version': 1}}):
        with pytest.raises(ValueError, match='invalid_agent_invocation'):
            fargate.invoke('network', tmp_path, 'inert', 30, **kwargs)


def test_relay_waits_a_short_explicit_bound_for_the_next_stage_then_exits(monkeypatch):
    served, fetched = [], []
    monkeypatch.setenv('PEASO_AI_BOOTSTRAP_URL', 'https://first')
    monkeypatch.setenv('PEASO_AI_NEXT_BOOTSTRAP_URL', 'https://next')
    monkeypatch.setenv('PEASO_AI_REUSE_IDLE_SECONDS', str(fargate.REUSE_IDLE_SECONDS))
    monkeypatch.setenv('PEASO_AI_TASK_BINDING', BINDING)
    monkeypatch.setattr(task_runtime, 'transfer', lambda method, url, **kw: json.dumps(
        {'sequence': 1, 'binding': BINDING, 'stage': 'network'}).encode())

    def fetch(url, wait):
        fetched.append((url, wait))
        raise RuntimeError('task_bootstrap_unavailable')

    monkeypatch.setattr(task_runtime, 'fetch_bootstrap', fetch)

    def serve(config, stop_after_result=False):
        served.append((config['sequence'], stop_after_result))
        return True

    task_runtime.run_relay(serve=serve)
    assert served == [(1, True)] and fetched == [('https://next', fargate.REUSE_IDLE_SECONDS)]
    assert fargate.REUSE_IDLE_SECONDS <= 120
    for value in ('0', '-1', str(fargate.REUSE_IDLE_SECONDS + 1), 'x', '1.5'):
        with pytest.raises(ValueError):
            task_runtime.reuse_idle(value)
    assert task_runtime.reuse_idle(None) == 0


def test_relay_without_next_stage_serves_once_like_a_fresh_task(monkeypatch):
    served = []
    monkeypatch.setenv('PEASO_AI_BOOTSTRAP_URL', 'https://first')
    for name in ('PEASO_AI_NEXT_BOOTSTRAP_URL', 'PEASO_AI_REUSE_IDLE_SECONDS', 'PEASO_AI_TASK_BINDING'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(task_runtime, 'transfer', lambda method, url, **kw: b'{"stage":"priorities"}')
    monkeypatch.setattr(task_runtime, 'fetch_bootstrap', lambda *a: pytest.fail('waited for another stage'))
    task_runtime.run_relay(serve=lambda config, stop_after_result=False: served.append(stop_after_result) or True)
    assert served == [False]


def test_relay_takes_second_invocation_only_after_acknowledging_it(monkeypatch):
    served, puts = [], []
    monkeypatch.setenv('PEASO_AI_BOOTSTRAP_URL', 'https://first')
    monkeypatch.setenv('PEASO_AI_NEXT_BOOTSTRAP_URL', 'https://next')
    monkeypatch.setenv('PEASO_AI_REUSE_IDLE_SECONDS', '90')
    monkeypatch.setenv('PEASO_AI_TASK_BINDING', BINDING)

    def transfer(method, url, **kw):
        if method == 'PUT':
            puts.append(url)
            assert served == [1]
            return b''
        return json.dumps({'sequence': 1, 'binding': BINDING}).encode()

    monkeypatch.setattr(task_runtime, 'transfer', transfer)
    monkeypatch.setattr(task_runtime, 'fetch_bootstrap', lambda url, wait: json.dumps(
        {'sequence': 2, 'binding': BINDING, 'accepted_url': 'https://accepted'}).encode())
    task_runtime.run_relay(serve=lambda config, stop_after_result=False: served.append(config['sequence']) or True)
    assert served == [1, 2] and puts == ['https://accepted']


def test_agent_runs_each_stage_in_a_fresh_workspace_and_exits_when_idle(monkeypatch, tmp_path):
    events = []
    monkeypatch.setenv('PEASO_AI_REUSE_IDLE_SECONDS', '90')

    def run(config):
        events.append(('run', config['sequence']))
        # A stage leaves files and a stray process behind.
        (tmp_path / ('left-' + str(config['sequence']))).mkdir()
        (tmp_path / ('left-' + str(config['sequence'])) / 'secret.json').write_text('{}')
        (tmp_path / 'loose.txt').write_text('x')
        events.append(('stray', subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])))

    def wait(sequence, bound):
        events.append(('wait', sequence, bound))
        if sequence == 3:
            raise RuntimeError('relay_unavailable')
        return {'sequence': sequence}

    def clean():
        events.append(('clean',))
        task_runtime.scrub(tmp_path)
        assert not list(tmp_path.iterdir())

    task_runtime.run_agent_task(run=run, wait=wait, clean=clean)
    names = [event[0] for event in events]
    assert names == ['wait', 'run', 'stray', 'clean', 'wait', 'run', 'stray']
    assert events[0] == ('wait', 1, 120) and events[4] == ('wait', 2, 150)
    # Network's stray process did not survive into Priorities.
    assert events[2][1].poll() is not None
    events[-1][1].kill()
    events[-1][1].wait()

    events.clear()
    monkeypatch.setenv('PEASO_AI_REUSE_IDLE_SECONDS', '90')
    task_runtime.run_agent_task(run=lambda c: events.append('run'),
                                wait=lambda s, b: {'sequence': 1} if s == 1 else (_ for _ in ()).throw(RuntimeError()),
                                clean=lambda: None)
    assert events == ['run']
    # A failed scrub never takes a second stage and never fails the stored first result.
    events.clear()
    monkeypatch.setenv('PEASO_AI_REUSE_IDLE_SECONDS', '90')
    task_runtime.run_agent_task(run=lambda c: events.append('run'), wait=lambda s, b: {'sequence': s},
                                clean=lambda: (_ for _ in ()).throw(RuntimeError('task_scrub_failed')))
    assert events == ['run']
    # Without a retained task the agent serves one invocation, as before.
    events.clear()
    assert 'PEASO_AI_REUSE_IDLE_SECONDS' not in __import__('os').environ  # consumed by the agent
    task_runtime.run_agent_task(run=lambda c: events.append('run'), wait=lambda s, b: {'sequence': s},
                                clean=lambda: pytest.fail('scrubbed without a next stage'))
    assert events == ['run']


def test_agent_ignores_previous_invocation_until_next_bootstrap():
    responses = [{'sequence': 1}, {'sequence': 1}, {'sequence': 2, 'relay_token': 'new'}]

    class Response:
        def __init__(self, value):
            self.value = value
        def raise_for_status(self):
            pass
        def json(self):
            return self.value

    now = [0.0]
    config = task_runtime.wait_bootstrap(2, 10, get=lambda: Response(responses.pop(0)),
                                         clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    assert config['relay_token'] == 'new'
    with pytest.raises(RuntimeError, match='relay_unavailable'):
        task_runtime.wait_bootstrap(2, 10, get=lambda: Response({'sequence': 1}),
                                    clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))


def test_relay_stops_serving_and_revokes_capability_after_retained_result(monkeypatch):
    claims = {'https://api.openai.com/auth': {'chatgpt_account_id': 'account'}}
    token = 'e30.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.sig'
    captured, ready, outcome = [], threading.Event(), []
    monkeypatch.setattr(task_runtime, 'transfer', lambda *a, **kw: b'')

    def factory(address, handler):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        captured.append(server)
        ready.set()
        return server

    config = {'token': token, 'stage': 'network', 'timeout': 30, 'sequence': 1,
              'input_url': 'https://private-ai-bucket.s3.us-east-1.amazonaws.com/i?sig=inert',
              'output_url': 'https://private-ai-bucket.s3.us-east-1.amazonaws.com/o?sig=inert'}
    thread = threading.Thread(target=lambda: outcome.append(model_relay.serve(
        config, server_class=factory, stop_after_result=True)), daemon=True)
    thread.start()
    assert ready.wait(3)
    server = captured[0]

    def call(method, path, body=None, auth=None):
        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        connection.request(method, path, body=body, headers={'Authorization': 'Bearer ' + auth} if auth else {})
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, data

    status, data = call('GET', '/bootstrap')
    public = json.loads(data)
    assert status == 200 and public['sequence'] == 1
    assert call('POST', '/result', '{"findings":[]}', public['relay_token'])[0] == 200
    thread.join(5)
    assert outcome == [True], 'relay must stop serving the finished invocation'


def test_review_scan_runs_priorities_in_network_task_with_unchanged_inputs(
        environment, mocked_agent_isolation, configured, monkeypatch):
    from tests import test_peaso_ai_review as review_tests
    data, inventory, network_output = review_tests.network_fixture()
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: inventory)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 4 * 1024**3)
    monkeypatch.setenv('PEASO_AI_TIMEOUT_SECONDS', '3000')
    released = []
    monkeypatch.setattr(fargate, 'release', lambda descriptor, **kw: released.append(descriptor))

    def run(retain_task):
        launches, calls = [], []

        def invoke(stage, root, token, timeout, **kwargs):
            assert kwargs['task_binding'] == fargate.binding('alice', 'a' * 32)
            if stage == 'network':
                launches.append('network')
                assert 'reuse' not in kwargs
                if retain_task:
                    kwargs['retain']['task'] = {'version': 1, 'task': TASK_ARN, 'ident': 'b' * 32,
                                                'binding': kwargs['task_binding'], 'ready_until': time.time() + 90}
                return network_output
            assert stage == 'priorities' and 'retain' not in kwargs
            if retain_task:
                assert kwargs['reuse']['task'] == TASK_ARN
            else:
                assert 'reuse' not in kwargs
                launches.append('priorities')
            kwargs['prepare']()
            calls.append(json.dumps({'timeout': round(timeout, -1), 'files': sorted(
                (path.name, hashlib.sha256(path.read_bytes()).hexdigest()) for path in root.iterdir())}, sort_keys=True))
            return {'actions': [], 'limitations': []}

        monkeypatch.setattr(fargate, 'invoke', invoke)
        result = pipeline.review_scan(data, {}, {}, tenant='alice', artifacts=environment[2], scan_id='a' * 32)
        return result, calls, launches

    baseline, baseline_calls, baseline_launches = run(False)
    candidate, candidate_calls, launches = run(True)
    assert baseline_launches == ['network', 'priorities'] and launches == ['network']
    assert baseline_calls == candidate_calls and len(candidate_calls) == 1
    assert json.dumps(baseline, sort_keys=True) == json.dumps(candidate, sort_keys=True)
    assert released == []  # Priorities consumed the retained task.


def test_review_scan_stops_retained_task_when_priorities_does_not_run(
        environment, mocked_agent_isolation, configured, monkeypatch):
    from tests import test_peaso_ai_review as review_tests
    data, inventory, network_output = review_tests.network_fixture()
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: inventory)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 4 * 1024**3)
    released = []
    monkeypatch.setattr(fargate, 'release', lambda descriptor, **kw: released.append(descriptor))
    descriptor = {'version': 1, 'task': TASK_ARN, 'ident': 'b' * 32,
                  'binding': fargate.binding('alice', 'a' * 32), 'ready_until': time.time() + 90}

    def invoke(stage, root, token, timeout, **kwargs):
        assert stage == 'network'
        kwargs['retain']['task'] = descriptor
        return network_output

    monkeypatch.setattr(fargate, 'invoke', invoke)
    pipeline.review_scan(data, {}, {'ai_priorities_enabled': False}, tenant='alice',
                         artifacts=environment[2], scan_id='a' * 32)
    assert released == []  # Priorities not selected: Network never asked to retain.
    monkeypatch.setattr(pipeline, '_priorities_have_evidence', lambda *a: False)
    pipeline.review_scan(data, {}, {}, tenant='alice', artifacts=environment[2], scan_id='a' * 32)
    assert released == [descriptor]


def test_progressive_handoff_reuses_only_this_scans_descriptor(
        environment, mocked_agent_isolation, configured, monkeypatch):
    from tests import test_peaso_ai_review as review_tests
    data, inventory, network_output = review_tests.network_fixture()
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: inventory)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 4 * 1024**3)
    monkeypatch.setattr(fargate, 'release', lambda descriptor, **kw: None)
    seen = []

    def invoke(stage, root, token, timeout, **kwargs):
        seen.append((stage, kwargs.get('reuse'), 'retain' in kwargs))
        if stage == 'network':
            kwargs['retain']['task'] = {'version': 1, 'task': TASK_ARN, 'ident': 'b' * 32,
                                        'binding': kwargs['task_binding'], 'ready_until': time.time() + 90}
            return network_output
        return {'actions': [], 'limitations': []}

    monkeypatch.setattr(fargate, 'invoke', invoke)
    handoff = {}
    stage = pipeline.review_scan(data, {}, {}, tenant='alice', artifacts=environment[2], stages=('network',),
                                 scan_id='a' * 32, task_handoff=handoff)
    assert seen == [('network', None, True)] and handoff['network']['task'] == TASK_ARN
    reused = dict(stage, task_reuse=handoff['network'])
    for scan, expected in (('a' * 32, handoff['network']), ('c' * 32, None)):
        seen.clear()
        final = pipeline.review_scan(data, {}, {}, tenant='alice', artifacts=environment[2],
                                     reused_stages={'network': reused}, scan_id=scan)
        assert seen == [('priorities', expected, False)]
        assert 'task_reuse' not in json.dumps(final)


def test_priorities_falls_back_to_a_fresh_task_within_its_deadline(monkeypatch):
    calls = []
    chain = pipeline.TaskChain('b' * 64, reuse={'task': TASK_ARN})
    token = pipeline._TASK_CHAIN.set(chain)

    def invoke(stage, platform, entries, access, findings, reviews, timeout, **kwargs):
        options = chain.options(stage)
        calls.append((timeout, 'reuse' in options))
        if 'reuse' in options:
            raise fargate.TaskReuseError('ai_task_not_reusable')
        return {'actions': []}

    monkeypatch.setattr(pipeline, 'invoke', invoke)
    clock = [100.0]
    monkeypatch.setattr(pipeline, 'time', type('T', (), {'monotonic': staticmethod(lambda: clock[0])}))
    try:
        assert pipeline.invoke_before_deadline('priorities', {}, [], 'inert', [], [], 1600.0, 1500) == {'actions': []}
    finally:
        pipeline._TASK_CHAIN.reset(token)
    assert calls == [(1500, True), (1500, False)]
