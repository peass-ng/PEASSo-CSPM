"""Late stage replies and reuse decisions stay fenced; telemetry is numeric."""
import copy
import json
import threading
from types import SimpleNamespace

import pytest

from peaso import engine, runtime_metrics, worker
from peaso.ai import pipeline
from peaso.snapshot import make_snapshot
from peaso.storage import cost, reports
from peaso.storage.artifacts import FileArtifacts


@pytest.fixture(autouse=True)
def reset_recorder():
    runtime_metrics.close()
    yield
    runtime_metrics.close()


@pytest.mark.parametrize('case', ['accepted', 'revision', 'incomplete', 'missing', 'binding', 'unexpected'])
def test_stage_reuse_records_outcome_without_changing_binding_or_failure(case):
    events, reads = [], []
    result = {'status': 'completed', 'private-field': 'PRIVATE-SENTINEL'}
    artifact = {'stage': 'network', 'data_revision': 7, 'result': result}
    section = {'network': {'status': 'complete', 'data_revision': 7}}
    stages = {'network': {'data_revision': 7, 'result_ref': 'PRIVATE-REFERENCE'}}
    if case == 'revision':
        section['network']['data_revision'] = 8
    if case == 'incomplete':
        section['network']['status'] = 'running'
    if case == 'binding':
        artifact['data_revision'] = 6
    before = copy.deepcopy((section, stages, artifact))
    failure = RuntimeError('PRIVATE-EXCEPTION')

    class Artifacts:
        def get(self, tenant, reference):
            reads.append((tenant, reference))
            runtime_metrics.flush()
            assert any(a['stage'] == 'worker.stage_results.load' for a in events[-1][1]['active'])
            if case == 'missing':
                raise OSError('PRIVATE-EXCEPTION')
            if case == 'unexpected':
                raise failure
            return artifact

    runtime_metrics.configure(events.append, role='analyzer', interval_seconds=60)
    if case == 'unexpected':
        with pytest.raises(RuntimeError) as error:
            worker._reusable_stages(Artifacts(), 'PRIVATE-TENANT', section, stages)
        assert error.value is failure
    else:
        reused = worker._reusable_stages(Artifacts(), 'PRIVATE-TENANT', section, stages)
        assert reused == ({'network': result} if case == 'accepted' else {})
        if reused:
            assert reused['network'] is result
    runtime_metrics.flush()
    frame = events[-1][1]
    rows = {row['stage']: row for row in frame['rows']}
    assert rows['ai.network.reuse.revision_check']['count'] == 1
    assert bool(reads) == (case not in {'revision', 'incomplete'})
    assert ('ai.network.reuse.revision_rejected' in rows) == (case in {'revision', 'incomplete'})
    assert ('ai.network.reuse.accepted' in rows) == (case == 'accepted')
    assert ('ai.network.reuse.artifact_unavailable' in rows) == (case == 'missing')
    if reads:
        assert rows['worker.stage_results.load']['errors'] == int(case in {'missing', 'unexpected'})
    assert (section, stages, artifact) == before
    assert all(runtime_metrics.validate(event[1]) for event in events)
    assert 'PRIVATE-' not in json.dumps(events)


@pytest.mark.parametrize('invalid', [False, True])
def test_network_reuse_validation_and_fallback_are_observed_without_model_calls(tmp_path, monkeypatch, invalid):
    events, fresh = [], []
    monkeypatch.setattr(pipeline, 'Settings', lambda: SimpleNamespace(
        state_dir=tmp_path, identity_dir=tmp_path, auth_mode='local'))
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (SimpleNamespace(), None))
    monkeypatch.setattr('peaso.ai.providers.review_disabled', lambda *a: False)
    monkeypatch.setattr('peaso.ai.providers.resolve_access', lambda *a, **k: ('PRIVATE-TOKEN', 'test'))
    monkeypatch.setattr('peaso.ai.providers.credential_value', lambda _: 'PRIVATE-TOKEN')
    monkeypatch.setattr(pipeline.isolation, 'available', lambda: True)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: False)
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: [])
    monkeypatch.setattr('peaso.ai.network.prepare', lambda *a: {
        'report': {'graphs': {'network': {}}}, 'inventory': []})
    prior = {'status': 'completed', 'network': {
        'status': 'completed', 'explanation': 'PRIVATE-MODEL-CONTENT', 'findings': []}}
    if invalid:
        del prior['network']['explanation']
    original = copy.deepcopy(prior)

    def review_network(*args, **kwargs):
        fresh.append(True)
        return {'status': 'completed', 'explanation': 'fresh', 'findings': []}, False

    monkeypatch.setattr(pipeline, 'review_network', review_network)
    runtime_metrics.configure(events.append, role='analyzer', interval_seconds=60)
    result = pipeline.review_scan({'provider': 'k8s', 'findings': [], 'graphs': {}}, {}, {},
        tenant='test', artifacts=None, stages=('network',), reused_stages={'network': prior})
    runtime_metrics.flush()
    rows = {row['stage']: row for row in events[-1][1]['rows']}
    assert result['status'] == 'completed'
    assert fresh == ([True] if invalid else [])
    assert rows['ai.network.reuse.validation']['errors'] == int(invalid)
    assert ('ai.network.reuse.validated' in rows) is not invalid
    assert prior == original
    assert 'PRIVATE-' not in json.dumps(events)


@pytest.mark.parametrize('broken_sink', [False, True])
def test_late_reply_preserves_ack_then_durable_revision_handoff(tmp_path, monkeypatch, broken_sink):
    artifacts = FileArtifacts(tmp_path)
    snapshot = make_snapshot('k8s', ['default'], [], metadata={
        'sections': {'network': {'status': 'complete', 'data_revision': 7}}})
    snapshot_ref = artifacts.put('test', 'a' * 32, 'snapshot', snapshot)
    cached = {'status': 'completed', 'network': {'status': 'completed', 'explanation': 'saved', 'findings': []}}
    stage_ref = artifacts.put('test', 'a' * 32, 'ai-review', {
        'stage': 'network', 'data_revision': 7, 'result': cached})
    ack_entered, ack_ready = threading.Event(), threading.Event()
    reply_entered, reply_ready = threading.Event(), threading.Event()
    events, sent, reviews = [], [], []

    class Pipe:
        last = None
        def send(self, value):
            if value[0] == '__runtime_metrics__':
                if broken_sink:
                    raise RuntimeError('PRIVATE-SINK-FAILURE')
                events.append(value)
            else:
                sent.append(value)
                self.last = value
        def recv(self):
            if self.last[0] == '__checkpoint__':
                ack_entered.set()
                assert ack_ready.wait(5)
                return '__checkpoint_ack__', self.last[1]['sequence'], True
            assert self.last == ('__stage_results__', None)
            reply_entered.set()
            assert reply_ready.wait(5)
            return '__stage_results__', {'network': {'data_revision': 7, 'result_ref': stage_ref}}
        def close(self):
            pass

    def review(*args, **kwargs):
        assert ack_ready.is_set() and reply_ready.is_set()
        assert kwargs['reused_stages'] == {'network': cached}
        reviews.append(True)
        return {'status': 'completed', 'actions': [], 'network': {'findings': []}}

    monkeypatch.setattr(worker.os, 'dup2', lambda *args: None)
    monkeypatch.setattr(worker.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(engine, 'evaluate_snapshot', lambda *a, **k: {
        'provider': 'k8s', 'snapshot_id': snapshot['snapshot_id'], 'findings': [], 'stats': {}, 'graphs': {}})
    monkeypatch.setattr(reports, 'publish_report', lambda *a, **k: (
        'native' if a[3]['publication']['phase'] == 'analyzing' else 'final'))
    monkeypatch.setattr(cost, 'runtime_estimate', lambda *a: {})
    monkeypatch.setattr(pipeline, 'review_scan', review)
    request = {'artifact_config': {'mode': 'file', 'root': str(tmp_path)},
               'tenant_id': 'test', 'scan_id': 'a' * 32, 'snapshot_ref': snapshot_ref,
               'selectors': {'ai_enabled': True}, 'timeline': {}, 'related': [],
               'stage_results': {}, 'refresh_stage_results': True}
    thread = threading.Thread(target=worker._process, args=('analyzer', request, Pipe()))
    thread.start()
    try:
        assert ack_entered.wait(5)
        assert not reviews
        runtime_metrics.flush()
        if not broken_sink:
            assert any(a['stage'] == 'worker.native_checkpoint.wait' for a in events[-1][1]['active'])
        ack_ready.set()
        assert reply_entered.wait(5)
        assert not reviews
        runtime_metrics.flush()
        if not broken_sink:
            assert any(a['stage'] == 'worker.stage_results.wait' for a in events[-1][1]['active'])
        # A simulated late stage result releases exactly the existing reply,
        # without a new sleep/lease timer, early AI run or changed revision.
        reply_ready.set()
        thread.join(5)
        assert not thread.is_alive()
    finally:
        ack_ready.set()
        reply_ready.set()
        thread.join(5)
    assert sent[-1] == (True, 'final') and reviews == [True]
    if not broken_sink:
        rows = {row['stage']: row for row in events[-1][1]['rows']}
        for stage in ('worker.snapshot.load', 'worker.native_checkpoint.wait',
                      'worker.stage_results.wait', 'worker.stage_results.load', 'ai.network.reuse.accepted'):
            assert rows[stage]['count'] == 1
        assert all(runtime_metrics.validate(event[1]) for event in events)
        assert 'PRIVATE-' not in json.dumps(events)


def test_parent_late_stage_result_does_not_wait_for_360_second_heartbeat(tmp_path, monkeypatch):
    import multiprocessing
    import subprocess
    import sys
    import time
    from peaso.auth import CredentialCipher
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore

    # Even a lease whose heartbeat interval is360s must not gate readiness.
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    settings.lease_seconds = 1080
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path/'artifacts')
    cipher = CredentialCipher(settings.identity_dir)
    connector = store.add_connector('test', {'provider': 'k8s'},
        cipher.encrypt({'auth': {}, 'options': {}}))
    job = store.enqueue('test', {'connector_id': connector['id'], 'ai_enabled': False})
    assert store.admit('test', job['id'])
    claim = store.claim('collector', tenant='test', ident=job['id'])
    assert store.claim_stage('test', job['id'], 'network', 7, 'b'*32, 1080)
    snapshot = artifacts.put('test', job['id'], 'snapshot', make_snapshot('k8s', ['default'], []))
    native = artifacts.put('test', job['id'], 'report', {'native': True})
    final = artifacts.put('test', job['id'], 'report', {'final': True})
    stage = artifacts.put('test', job['id'], 'ai-review', {'stage': 'network', 'data_revision': 7})
    assert store.finish(job['id'], claim['owner'], 'collected', snapshot)
    actual_context = multiprocessing.get_context('spawn')
    script = '''import json,sys
from multiprocessing.connection import Connection
c=Connection(int(sys.argv[1]));a=json.loads(sys.argv[2])
c.send(('__checkpoint__',{'sequence':1,'snapshot_ref':a['snapshot'],
    'report_ref':a['native'],'stage':'analyzer_native'}))
assert c.recv()==('__checkpoint_ack__',1,True)
c.send(('__stage_results__',None))
assert c.recv()==('__stage_results__',{'network':{'data_revision':7,'result_ref':a['stage']}})
c.send((True,a['final']));c.close()
'''

    class Process:
        def __init__(self, *, target, args, daemon):
            self.connection = args[-1]
            assert args[1]['refresh_stage_results'] is True
        def start(self):
            values = {'snapshot': snapshot, 'native': native, 'final': final, 'stage': stage}
            self.process = subprocess.Popen([sys.executable, '-c', script,
                str(self.connection.fileno()), json.dumps(values)],
                pass_fds=(self.connection.fileno(),), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def is_alive(self): return self.process.poll() is None
        def join(self, timeout): self.process.wait(timeout=timeout)
        def terminate(self): self.process.terminate()
        def kill(self): self.process.kill()

    context = SimpleNamespace(Pipe=actual_context.Pipe, Process=Process)
    monkeypatch.setattr(worker.multiprocessing, 'get_context', lambda *_: context)
    polls = []
    def late_stage(control):
        assert control['status'] == 'analyzing'
        if store.job('test', job['id']).get('partial_report') != native:
            return False
        polls.append(True)
        if len(polls) < 3:
            return False
        if not store.stage_results('test', job['id']):
            assert store.finish_stage('test', job['id'], 'network', 7, 'b'*32, stage)
        return True

    started = time.monotonic()
    assert worker.Worker('analyzer', settings, store=store, artifacts=artifacts).run_once(
        'test', job['id'], stage_poll=late_stage)
    assert time.monotonic() - started < 10  # Far below the360s heartbeat interval.
    assert len(polls) >= 3
    finished = store.job('test', job['id'])
    assert finished['status'] == 'completed' and finished['report'] == final
    assert store.stage_results('test', job['id']) == {'network': {'data_revision': 7, 'result_ref': stage}}
