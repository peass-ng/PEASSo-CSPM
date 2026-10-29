"""Invocation deadlines reach both wrappers without exposing credentials."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from peaso.ai import deadline, fargate, runner, task_runtime


@pytest.mark.parametrize('value', [0, -1, 1801, True, False, float('inf'), float('nan'), 'private-invalid-value', None])
def test_unbounded_or_invalid_deadline_hints_fail_closed(value):
    with pytest.raises(ValueError, match='^invalid_ai_agent_timeout$'):
        deadline.timeout_seconds(value)


@pytest.mark.parametrize('stage,remaining,work_seconds', [
    ('network', 520, 401), ('priorities', 520, 401),
    ('network', 350, 325), ('priorities', 350, 325),
])
def test_runner_does_not_discard_work_within_the_parent_deadline(tmp_path, monkeypatch, stage, remaining, work_seconds):
    # The previous five-minute Chack budget discarded this otherwise valid run.
    config = SimpleNamespace(agent=SimpleNamespace(max_runtime_minutes=5), credentials=SimpleNamespace())
    payload = ({'actions': [], 'limitations': []} if stage == 'priorities' else
               {'explanation': 'Captured network reviewed.', 'findings': []})
    class Chack:
        def __init__(self, actual):
            self.config = actual
        def run(self, *args, **kwargs):
            if self.config.agent.max_runtime_minutes * 60 < work_seconds:
                raise TimeoutError('inner wrapper ended before the admitted work completed')
            assert remaining <= self.config.agent.max_runtime_minutes * 60 < remaining + 60
            return SimpleNamespace(error='', output=json.dumps(payload))
    monkeypatch.setattr(runner, 'validate_runtime', lambda *args: None)
    monkeypatch.setitem(sys.modules, 'chack_agent', SimpleNamespace(Chack=Chack, load_config=lambda _: config))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, 'argv', ['runner', stage])
    monkeypatch.setenv(deadline.ENVIRONMENT_KEY, str(remaining))
    monkeypatch.delenv('PEASO_AI_MODEL_RELAY', raising=False)
    (tmp_path/'codex-auth.json').write_text('{"access_token":"task-local-capability"}')
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    (tmp_path/'findings.json').write_text('{"items":[]}')
    import sqlite3
    with sqlite3.connect(tmp_path/'context.sqlite') as db:
        db.execute('CREATE TABLE records(domain TEXT,id TEXT,detail TEXT)')
    runner.main()
    assert json.loads((tmp_path/'result.json').read_text()) == payload
    assert not (tmp_path/'codex-auth.json').exists()


@pytest.mark.parametrize('stage', ['hardening', 'exposure'])
def test_removed_reviewer_stages_are_rejected_by_runner_and_hosted_runtime(monkeypatch, stage):
    # Hardening and Exposure verdicts are native-final; no model agent runs for them.
    monkeypatch.setattr(sys, 'argv', ['runner', stage])
    with pytest.raises(ValueError, match='^unknown_ai_stage$'):
        runner.main()
    with pytest.raises(ValueError, match='^invalid_task_stage$'):
        task_runtime.run_agent({'stage': stage, 'timeout': 520, 'relay_token': 'task-local-capability'})


def test_hosted_runtime_passes_the_same_budget_to_process_and_runner(tmp_path, monkeypatch):
    source = tmp_path/'source'; source.mkdir()
    (source/'credentials.json').write_text('{"entries":[]}')
    (source/'findings.json').write_text('{"items":[]}')
    packed = fargate.pack_workspace(source)
    observed = {}
    def transfer(method, path, capability, **kwargs):
        if path == '/input':
            # The runtime streams the input archive into a disk-backed sink.
            kwargs['sink'].write(packed if isinstance(packed, bytes) else packed.read())
            return None
        assert path == '/result' and json.loads(kwargs['body']) == {'items': []}
        return b'{}'
    class Process:
        pid = 987654321
        returncode = 0
        def __init__(self, argv, *, cwd, env, **kwargs):
            observed['env'] = env
            (Path(cwd)/'result.json').write_text('{"items":[]}')
        def wait(self, **kwargs):
            if 'timeout' in kwargs: observed['wait_timeout'] = kwargs['timeout']
            return 0
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'never-inherit-platform-secret')
    monkeypatch.setattr(task_runtime, 'relay_request', transfer)
    monkeypatch.setattr(task_runtime.subprocess, 'Popen', Process)
    monkeypatch.setattr(task_runtime.os, 'killpg', lambda *args: None)
    task_runtime.run_agent({'stage': 'network', 'timeout': 520, 'relay_token': 'task-local-capability'})
    assert observed['wait_timeout'] == 520
    assert observed['env'][deadline.ENVIRONMENT_KEY] == '520'
    assert 'AWS_SECRET_ACCESS_KEY' not in observed['env']
    assert 'never-inherit-platform-secret' not in json.dumps(observed)


def test_runner_timeout_uses_a_controlled_exit_code_without_error_text(monkeypatch, capsys):
    def fail(): raise TimeoutError('DO_NOT_LOG_PRIVATE_ERROR_BODY')
    monkeypatch.setattr(runner, 'main', fail)
    assert runner.entrypoint() == 124
    assert capsys.readouterr() == ('', '')


@pytest.mark.parametrize('error,code,output', [
    (TimeoutError('DO_NOT_LOG_PRIVATE_ERROR_BODY'), 124, 'ai_agent_failure=deadline\n'),
    (ValueError('DO_NOT_LOG_PRIVATE_ERROR_BODY'), 1, ''),
])
def test_task_failure_logs_only_a_fixed_deadline_code(monkeypatch, capsys, error, code, output):
    import requests
    monkeypatch.setattr(sys, 'argv', ['task-runtime', 'agent'])
    monkeypatch.setattr(requests, 'get', lambda *a, **k: SimpleNamespace(
        raise_for_status=lambda: None, json=lambda: {'stage': 'network'}))
    def fail(_): raise error
    monkeypatch.setattr(task_runtime, 'run_agent', fail)
    with pytest.raises(SystemExit) as stopped: task_runtime.main()
    assert stopped.value.code == code
    assert capsys.readouterr() == ('', output)


@pytest.mark.parametrize('stage', ['hardening', 'exposure', 'network', 'priorities'])
def test_startup_retry_preserves_the_phase_deadline(monkeypatch, stage):
    from peaso.ai import pipeline
    clock, timeouts = [0], []
    monkeypatch.setattr(pipeline, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    def invoke(*args):
        timeouts.append(args[-1])
        if len(timeouts) == 1:
            clock[0] = 2
            raise fargate.TaskStartupError('ai_task_startup_failed')
        return {'ok': True}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    assert pipeline.invoke_before_deadline(stage, {}, [], 'inert', [], [], 5, 4) == {'ok': True}
    assert timeouts == [4, 3]


@pytest.mark.parametrize('mode,expected_attempts,error', [
    ('twice', 2, fargate.TaskStartupError), ('expired', 1, TimeoutError), ('invalid', 1, ValueError),
])
def test_startup_retry_is_bounded_and_preserves_real_errors(monkeypatch, mode, expected_attempts, error):
    from peaso.ai import pipeline
    clock, attempts = [0], []
    monkeypatch.setattr(pipeline, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    def invoke(*args):
        attempts.append(args[-1])
        if mode == 'invalid': raise ValueError('invalid_result')
        if mode == 'expired': clock[0] = 6
        raise fargate.TaskStartupError('ai_task_startup_failed')
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    with pytest.raises(error):
        pipeline.invoke_before_deadline('network', {}, [], 'inert', [], [], 5, 4)
    assert len(attempts) == expected_attempts
