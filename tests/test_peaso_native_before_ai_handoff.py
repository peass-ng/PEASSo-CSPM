"""Publish native results before waiting for independently running AI stages."""
import pytest
# Initialize source-attested registrars before replacing worker dependencies.
import peaso.checks
from peaso import engine, worker
from peaso.ai import pipeline, network
from peaso.storage.artifacts import FileArtifacts
from peaso.storage import reports, cost
from peaso.snapshot import make_snapshot


def test_analyzer_native_publication_precedes_fresh_stage_handoff(tmp_path, monkeypatch):
    artifacts = FileArtifacts(tmp_path)
    snapshot = make_snapshot('k8s', ['default'], [])
    reference = artifacts.put('tenant', 'a' * 32, 'snapshot', snapshot)
    events = []
    refreshed = {'network': {'data_revision': 7, 'result_ref': 'durable-network'}}
    calls = []

    def evaluate(*args, **kwargs):
        calls.append('evaluate')
        return {'provider': 'k8s', 'snapshot_id': snapshot['snapshot_id'],
                'findings': [], 'stats': {}, 'graphs': {}}

    def publish(artifacts, tenant, ident, report, native):
        phase = report['publication']['phase']
        events.append(phase)
        return 'native-report' if phase == 'analyzing' else 'final-report'

    def review(*args, **kwargs):
        assert events == ['analyzing', 'stage_results_requested']
        assert kwargs['reused_stages'] == refreshed
        events.append('review')
        return {'status': 'completed', 'network': {'findings': []}}

    class Pipe:
        sent = []
        def send(self, value):
            self.sent.append(value)
            if value[0] == '__stage_results__':
                assert events == ['analyzing']
                events.append('stage_results_requested')
        def recv(self):
            value = self.sent[-1]
            if value[0] == '__checkpoint__':
                return ('__checkpoint_ack__', value[1]['sequence'], True)
            assert value[0] == '__stage_results__'
            return ('__stage_results__', refreshed)
        def close(self): pass

    monkeypatch.setattr(worker.os, 'dup2', lambda *_: None)
    monkeypatch.setattr(worker.signal, 'signal', lambda *_: None)
    monkeypatch.setattr(engine, 'evaluate_snapshot', evaluate)
    monkeypatch.setattr(reports, 'publish_report', publish)
    monkeypatch.setattr(cost, 'runtime_estimate', lambda timeline: {})
    monkeypatch.setattr(worker, '_reusable_stages', lambda a,t,s,r: r)
    monkeypatch.setattr(pipeline, 'review_scan', review)
    monkeypatch.setattr(network, 'with_findings', lambda report, findings: report)
    pipe = Pipe()
    request = {'artifact_config': {'mode': 'file', 'root': str(tmp_path)},
        'tenant_id': 'tenant', 'scan_id': 'a' * 32, 'snapshot_ref': reference,
        'selectors': {}, 'timeline': {}, 'related': [],
        'stage_results': {'old': {}}, 'refresh_stage_results': True}
    worker._process('analyzer', request, pipe)
    assert calls == ['evaluate']
    assert events == ['analyzing', 'stage_results_requested', 'review', 'completed']
    assert pipe.sent[-1] == (True, 'final-report')


@pytest.mark.parametrize('cancel', [False, True])
def test_supervisor_publishes_native_while_waiting_and_reads_fresh_stage_rows(tmp_path, monkeypatch, cancel):
    import json
    import multiprocessing
    import subprocess
    import sys
    from peaso.auth import CredentialCipher
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore

    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path/'artifacts')
    cipher = CredentialCipher(settings.identity_dir)
    connector = store.add_connector('alice', {'provider': 'k8s'},
        cipher.encrypt({'auth': {}, 'options': {}}))
    job = store.enqueue('alice', {'connector_id': connector['id'], 'ai_enabled': False})
    assert store.admit('alice', job['id'])
    claim = store.claim('collector', tenant='alice', ident=job['id'])
    assert store.claim_stage('alice', job['id'], 'network', 7, 'b' * 32, 60)
    snapshot_ref = artifacts.put('alice', job['id'], 'snapshot', make_snapshot('k8s', ['default'], []))
    native_ref = artifacts.put('alice', job['id'], 'report', {'native': True})
    final_ref = artifacts.put('alice', job['id'], 'report', {'final': True})
    stage_ref = artifacts.put('alice', job['id'], 'ai-review', {'stage': 'network', 'data_revision': 7})
    assert store.finish(job['id'], claim['owner'], 'collected', snapshot_ref)
    actual_context = multiprocessing.get_context('spawn')
    script = '''import json,sys
from multiprocessing.connection import Connection
c=Connection(int(sys.argv[1]));a=json.loads(sys.argv[2])
c.send(('__checkpoint__',{'sequence':1,'snapshot_ref':a['snapshot'],
    'report_ref':a['native'],'stage':'analyzer_native'}))
assert c.recv()==('__checkpoint_ack__',1,True)
c.send(('__stage_results__',None))
reply=c.recv();assert reply[0]=='__stage_results__'
assert reply[1]=={'network':{'data_revision':7,'result_ref':a['stage']}}
c.send((True,a['final']));c.close()
'''

    class OwnedProcess:
        def __init__(self, *, target, args, daemon):
            self.connection = args[-1]
            assert args[1]['refresh_stage_results'] is True
        def start(self):
            values = {'snapshot': snapshot_ref, 'native': native_ref, 'final': final_ref, 'stage': stage_ref}
            self.process = subprocess.Popen([sys.executable, '-c', script,
                str(self.connection.fileno()), json.dumps(values)],
                pass_fds=(self.connection.fileno(),), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def is_alive(self): return self.process.poll() is None
        def join(self, timeout): self.process.wait(timeout=timeout)
        def terminate(self): self.process.terminate()
        def kill(self): self.process.kill()

    context = type('Context', (), {'Pipe': staticmethod(actual_context.Pipe), 'Process': OwnedProcess})()
    monkeypatch.setattr(worker.multiprocessing, 'get_context', lambda *_: context)
    polling = []
    def poll_stages(control, native_checkpoint=None):
        current = store.job('alice', job['id'])
        assert control['status'] == 'analyzing'
        published = current.get('partial_report') == native_ref
        if published:
            assert native_checkpoint == {'sequence': 1, 'snapshot_ref': snapshot_ref,
                'report_ref': native_ref, 'stage': 'analyzer_native'}
        else:
            assert native_checkpoint is None
        polling.append(published)
        if published and cancel:
            store.cancel('alice', job['id'])
            return False
        if published and not store.stage_results('alice', job['id']):
            assert store.finish_stage('alice', job['id'], 'network', 7, 'b' * 32, stage_ref)
        return published

    instance = worker.Worker('analyzer', settings, store=store, artifacts=artifacts)
    assert instance.run_once('alice', job['id'], stage_poll=poll_stages)
    finished = store.job('alice', job['id'])
    if cancel:
        assert finished['status'] == 'cancelled' and not finished.get('report')
        assert not store.stage_results('alice', job['id'])
    else:
        assert finished['status'] == 'completed' and finished['report'] == final_ref
    assert finished['snapshot'] == snapshot_ref and finished['partial_report'] == native_ref
    assert False in polling and True in polling
