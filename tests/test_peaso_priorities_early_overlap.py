"""The final native report and precompleted Network result permit early Priorities."""
import threading
import pytest

from peaso import engine, worker
from peaso.ai import isolation, network, pipeline
from peaso.snapshot import make_snapshot
from peaso.storage.artifacts import FileArtifacts
from peaso.storage import cost, reports


@pytest.mark.parametrize('stage_changed', [False, True])
def test_priorities_starts_before_native_publication_and_uses_same_network(tmp_path, monkeypatch, stage_changed):
    artifacts = FileArtifacts(tmp_path)
    snapshot = make_snapshot('k8s', ['default'], [])
    reference = artifacts.put('tenant', 'a' * 32, 'snapshot', snapshot)
    reused = {'network': {'status': 'completed', 'network': {'status': 'completed',
        'explanation': '', 'findings': []}}}
    refreshed = {'network': {'status': 'completed', 'network': {'status': 'completed',
        'explanation': 'refreshed', 'findings': []}}}
    prepared = threading.Event()
    published = threading.Event()
    calls = []

    def review(*args, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            assert kwargs['reused_stages'] == reused
            assert kwargs['require_reused_network'] is True
            kwargs['on_prepared']()
            prepared.set()
            assert published.wait(2)
        else:
            assert kwargs['reused_stages'] == refreshed
            assert 'require_reused_network' not in kwargs
        return {'status': 'completed', 'network': {'findings': []}, 'actions': []}

    def publish(artifacts, tenant, ident, report, native, **kwargs):
        phase = report['publication']['phase']
        if phase == 'analyzing':
            assert prepared.is_set()
            published.set()
        return phase

    class Pipe:
        sent = []
        def send(self, value): self.sent.append(value)
        def recv(self):
            value = self.sent[-1]
            if value[0] == '__checkpoint__':
                return ('__checkpoint_ack__', value[1]['sequence'], True)
            assert value[0] == '__stage_results__'
            return ('__stage_results__', {'network': {'result_ref':
                'changed' if stage_changed else 'same'}})
        def close(self): pass

    monkeypatch.setattr(worker.os, 'dup2', lambda *_: None)
    monkeypatch.setattr(worker.signal, 'signal', lambda *_: None)
    monkeypatch.setattr(engine, 'evaluate_snapshot', lambda *a, **k: {
        'provider': 'k8s', 'snapshot_id': snapshot['snapshot_id'],
        'findings': [], 'stats': {}, 'graphs': {}})
    monkeypatch.setattr(reports, 'publish_report', publish)
    monkeypatch.setattr(cost, 'runtime_estimate', lambda timeline: {})
    monkeypatch.setattr(worker, '_reusable_stages', lambda *a: (
        refreshed if stage_changed and a[-1]['network'].get('result_ref') == 'changed' else reused))
    monkeypatch.setattr(pipeline, 'review_scan', review)
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 2 * 1024**3)
    monkeypatch.setattr(isolation, 'remote', lambda: True)
    monkeypatch.setattr(network, 'with_findings', lambda report, findings: report)
    pipe = Pipe()
    worker._process('analyzer', {'artifact_config': {'mode': 'file', 'root': str(tmp_path)},
        'tenant_id': 'tenant', 'scan_id': 'a' * 32, 'snapshot_ref': reference,
        'selectors': {'ai_enabled': True, 'ai_priorities_enabled': True,
                      'ai_network_enabled': True, 'categories': ['network']},
        'timeline': {}, 'related': [], 'stage_results': {'network': {'result_ref': 'same'}},
        'refresh_stage_results': True}, pipe)
    assert len(calls) == (2 if stage_changed else 1)
    assert pipe.sent[-1] == (True, 'completed')
