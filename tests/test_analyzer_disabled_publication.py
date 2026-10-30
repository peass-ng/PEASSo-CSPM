"""Disabled AI reuses its acknowledged final native bundle without losing fences."""
import copy
import json
import time
from types import SimpleNamespace

import pytest
import peaso.checks
from peaso import engine, worker
from peaso.ai import pipeline
from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.snapshot import make_snapshot
from peaso.storage import SQLiteStore, FileArtifacts
from peaso.storage import reports
from fastapi.testclient import TestClient


class Identities:
    def authenticate(self, value):
        return Identity('bob' if value == 'Bearer bob' else 'alice')


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(tmp_path/'artifacts')
    connector = store.add_connector('alice', {'provider': 'k8s'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id'], 'ai_enabled': False})
    assert store.admit('alice', job['id'])
    collector = store.claim('collector', tenant='alice', ident=job['id'])
    sections = {'network': {'status': 'complete', 'data_revision': 7}}
    snapshot = make_snapshot('k8s', ['default'], [], metadata={'sections': sections})
    snapshot_ref = artifacts.put('alice', job['id'], 'snapshot', snapshot)
    assert store.finish(job['id'], collector['owner'], 'collected', snapshot_ref)
    analyzer = store.claim('analyzer', tenant='alice', ident=job['id'])
    owner = analyzer['owner']
    events = []
    published = []
    real_publish = reports.publish_report
    native = {'schema_version': '1.0', 'provider': 'k8s', 'snapshot_id': snapshot['snapshot_id'],
              'scopes': snapshot['scopes'], 'created_at': snapshot['created_at'], 'resources': [],
              'findings': [], 'coverage': [], 'stats': {}, 'graphs': {}}
    monkeypatch.setattr(engine, 'evaluate_snapshot', lambda *a, **kw: copy.deepcopy(native))
    monkeypatch.setattr(worker.os, 'dup2', lambda *_: None)
    monkeypatch.setattr(worker.signal, 'signal', lambda *_: None)

    def publish(*args, **kwargs):
        reference = real_publish(*args, **kwargs)
        published.append((reference, copy.deepcopy(args[3])))
        events.append('publish_' + args[3]['publication']['state'])
        return reference
    monkeypatch.setattr(reports, 'publish_report', publish)
    stage_ref = artifacts.put('alice', job['id'], 'ai-review', {
        'stage': 'network', 'data_revision': 7, 'result': {'findings': []}})
    stages = {'network': {'data_revision': 7, 'result_ref': stage_ref}}

    class Pipe:
        def __init__(self):
            self.sent = []
            self.rejected = False
            self.bad_refresh = False
            self.cancel_before_ack = False
            self.cancel_after_ack = False
            self.closed = False
        def send(self, message):
            self.sent.append(message)
            if message[0] == '__checkpoint__':
                event = message[1]
                if self.cancel_before_ack:
                    store.cancel('alice', job['id'])
                self.accepted = store.record_checkpoint('alice', job['id'], owner,
                    event['sequence'], event['snapshot_ref'], report_ref=event['report_ref'],
                    stage=event['stage'])
                events.append('checkpoint_accepted' if self.accepted else 'checkpoint_rejected')
            elif message[0] == '__stage_results__':
                events.append('refresh')
                if self.cancel_after_ack:
                    store.cancel('alice', job['id'])
        def recv(self):
            message = self.sent[-1]
            if message[0] == '__checkpoint__':
                return ('__checkpoint_ack__', message[1]['sequence'], self.accepted and not self.rejected)
            assert message[0] == '__stage_results__'
            return ('invalid_handoff', {}) if self.bad_refresh else ('__stage_results__', stages)
        def close(self):
            self.closed = True

    def request(enabled=False, refresh=False):
        return {'artifact_config': {'mode': 'file', 'root': str(artifacts.root)},
            'tenant_id': 'alice', 'scan_id': job['id'], 'snapshot_ref': snapshot_ref,
            'selectors': {'ai_enabled': enabled}, 'timeline': {}, 'related': [],
            'checkpoint_sequence': 0, 'stage_results': {}, 'refresh_stage_results': refresh}
    return SimpleNamespace(settings=settings, store=store, artifacts=artifacts, job=job,
        owner=owner, snapshot=snapshot, snapshot_ref=snapshot_ref, events=events,
        published=published, pipe=Pipe(), request=request, stages=stages)


def assert_api_result(s):
    with TestClient(create_app(s.settings, store=s.store, artifacts=s.artifacts,
                              authenticator=Identities()), base_url='http://127.0.0.1') as client:
        response = client.get('/api/scans/' + s.job['id'] + '/summary')
        assert response.status_code == 200, response.text
        summary = response.json()
        assert summary['publication']['state'] == 'final'
        assert summary['ai']['status'] == 'skipped'
        assert summary['ai']['reason'] == 'disabled_for_scan'
        client.headers['Authorization'] = 'Bearer bob'
        assert client.get('/api/scans/' + s.job['id'] + '/summary').status_code == 404


@pytest.mark.parametrize('refresh', [False, True])
def test_disabled_ai_publishes_once_acks_and_reuses_final_reference(scenario, refresh):
    s = scenario
    worker._process('analyzer', s.request(False, refresh), s.pipe)
    assert len(s.published) == 1
    reference, final = s.published[0]
    assert s.pipe.sent[-1] == (True, reference)
    assert final['ai'] == pipeline.review_scan({}, {}, {'ai_enabled': False}, tenant='alice', artifacts=s.artifacts)
    assert final['publication'] == {'state': 'final', 'phase': 'completed', 'sequence': 1,
                                    'sections': s.snapshot['metadata']['sections']}
    assert s.events == ['publish_final', 'checkpoint_accepted'] + (['refresh'] if refresh else [])
    current = s.store.job('alice', s.job['id'])
    assert current['status'] == 'analyzing' and current['partial_report'] == reference
    assert_api_result(s)  # Native final data is available before supervisor completion.
    assert s.store.finish(s.job['id'], s.owner, 'completed', reference)
    assert s.store.job('alice', s.job['id'])['report'] == reference
    assert s.pipe.closed


@pytest.mark.parametrize('refresh', [False, True])
def test_enabled_ai_keeps_native_durable_before_review_and_final_publication(scenario, monkeypatch, refresh):
    s = scenario
    def review(*args, **kwargs):
        assert s.events == ['publish_partial', 'checkpoint_accepted'] + (['refresh'] if refresh else [])
        assert s.store.job('alice', s.job['id'])['partial_report'] == s.published[0][0]
        assert kwargs['reused_stages'] == ({'network': {'findings': []}} if refresh else {})
        s.events.append('review')
        return {'status': 'completed', 'network': {'findings': []}}
    monkeypatch.setattr(pipeline, 'review_scan', review)
    worker._process('analyzer', s.request(True, refresh), s.pipe)
    assert len(s.published) == 2
    assert s.events == ['publish_partial', 'checkpoint_accepted'] + (['refresh'] if refresh else []) + ['review', 'publish_final']
    assert s.pipe.sent[-1] == (True, s.published[-1][0])


@pytest.mark.parametrize('enabled', [False, True])
def test_rejected_native_ack_never_reports_success_or_runs_review(scenario, monkeypatch, enabled):
    s = scenario
    s.pipe.cancel_before_ack = True
    worker._process('analyzer', s.request(enabled, True), s.pipe)
    assert len(s.published) == 1
    assert s.events == ['publish_partial' if enabled else 'publish_final', 'checkpoint_rejected']
    assert s.pipe.sent[-1][0] is False
    current = s.store.job('alice', s.job['id'])
    assert current['status'] == 'cancelled' and not current.get('partial_report') and not current.get('report')


def test_failure_after_ack_keeps_final_native_data_and_does_not_claim_completed(scenario):
    s = scenario
    s.pipe.bad_refresh = True
    worker._process('analyzer', s.request(False, True), s.pipe)
    assert len(s.published) == 1 and s.pipe.sent[-1][0] is False
    reference = s.published[0][0]
    assert s.store.finish(s.job['id'], s.owner, 'failed', error_code=s.pipe.sent[-1][1])
    current = s.store.job('alice', s.job['id'])
    assert current['status'] == 'failed' and current.get('report') is None
    assert current['partial_report'] == reference
    assert_api_result(s)


def test_cancellation_after_ack_fences_late_completion_and_preserves_result(scenario):
    s = scenario
    s.pipe.cancel_after_ack = True
    worker._process('analyzer', s.request(False, True), s.pipe)
    reference = s.published[0][0]
    assert s.pipe.sent[-1] == (True, reference)
    assert not s.store.finish(s.job['id'], s.owner, 'completed', reference)
    current = s.store.job('alice', s.job['id'])
    assert current['status'] == 'cancelled' and current.get('report') is None
    assert current['partial_report'] == reference
    assert_api_result(s)


def test_native_publication_failure_produces_no_checkpoint_or_success(scenario, monkeypatch):
    s = scenario
    def failure(*args):
        raise OSError('synthetic upload interruption')
    monkeypatch.setattr(reports, 'publish_report', failure)
    worker._process('analyzer', s.request(False), s.pipe)
    assert s.pipe.sent[-1][0] is False
    assert not any(message[0] == '__checkpoint__' for message in s.pipe.sent)
    assert not s.store.job('alice', s.job['id']).get('partial_report')

@pytest.mark.parametrize('selector', [None, 0])
def test_only_explicit_boolean_false_changes_publication_flow(scenario, selector):
    s = scenario
    worker._process('analyzer', s.request(selector), s.pipe)
    assert len(s.published) == 2
    assert s.published[0][1]['publication']['state'] == 'partial'
    assert s.published[1][1]['ai']['reason'] == 'disabled_for_scan'
    assert s.pipe.sent[-1] == (True, s.published[1][0])


def test_expired_lease_after_ack_fences_completion_without_losing_native_data(scenario):
    s = scenario
    worker._process('analyzer', s.request(False), s.pipe)
    reference = s.published[0][0]
    with s.store.transaction() as db:
        db.execute('UPDATE jobs SET lease=? WHERE id=?', (time.time() - 1, s.job['id']))
    assert not s.store.finish(s.job['id'], s.owner, 'completed', reference)
    current = s.store.job('alice', s.job['id'])
    assert current['status'] == 'analyzing' and current.get('report') is None
    assert current['partial_report'] == reference


def test_dynamodb_accepts_final_native_bundle_without_completing_job(tmp_path):
    import boto3
    import moto
    from peaso.storage.dynamodb import DynamoStore, attrs
    with moto.mock_aws():
        client = boto3.client('dynamodb', region_name='us-east-1')
        client.create_table(TableName='native-final', BillingMode='PAY_PER_REQUEST',
            KeySchema=[{'AttributeName':'PK','KeyType':'HASH'}, {'AttributeName':'SK','KeyType':'RANGE'}],
            AttributeDefinitions=[{'AttributeName':name,'AttributeType':'S'} for name in ('PK','SK')])
        store = DynamoStore('native-final', client)
        now = time.time()
        store.clock = lambda: now
        ident, owner = 'a' * 32, 'b' * 32
        artifacts = FileArtifacts(tmp_path)
        snapshot_ref = artifacts.put('alice', ident, 'snapshot', {})
        final_ref = artifacts.put('alice', ident, 'manifest', {'summary': {
            'publication': {'state': 'final', 'phase': 'completed', 'sequence': 1},
            'ai': {'status': 'skipped', 'reason': 'disabled_for_scan'}}})
        client.put_item(TableName=store.table, Item=attrs(dict(store.key('alice','job',ident),
            id=ident, tenant='alice', status='analyzing', owner=owner, lease=now+60,
            deadline=now+600, checkpoint_sequence=0, partial_report_sequence=0)))
        assert store.record_checkpoint('alice', ident, owner, 1, snapshot_ref,
            report_ref=final_ref, stage='analyzer_native')
        row = store.job('alice', ident)
        assert row['status'] == 'analyzing' and row['partial_report'] == final_ref
        assert row.get('report') is None
        assert not store.record_checkpoint('alice', ident, 'stale-owner', 2, snapshot_ref,
            report_ref=final_ref, stage='analyzer_native')
