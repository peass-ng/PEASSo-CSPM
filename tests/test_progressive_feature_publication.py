"""Every native scan feature is durable and reviewable before AI finishes.

The analyzer publishes one native checkpoint (phase ``analyzing``) before any
model stage runs. While Network/Priorities are still running, the owner can
read findings, leaks, compliance frameworks, coverage, resources, least
privilege, the network map and the privilege-escalation map from that
checkpoint; the AI projection reports which stages are pending instead of
"not requested". The final publication keeps the same native results.
"""
import copy
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import peaso.checks  # noqa: F401 - proves the pinned check package once
from peaso import worker
from peaso.ai import pipeline
from peaso.auth import Identity
from peaso.demo import demo_snapshot
from peaso.snapshot import make_snapshot
from peaso.server import create_app
from peaso.server.ai_progress import with_pending_stages
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore, reports


class Identities:
    def authenticate(self, value):
        return Identity('bob' if value == 'Bearer bob' else 'alice')


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path / 'state', identity_dir=tmp_path / 'identity')
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(tmp_path / 'artifacts')
    connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id'], 'ai_enabled': True})
    assert store.admit('alice', job['id'])
    collector = store.claim('collector', tenant='alice', ident=job['id'])
    snapshot = demo_snapshot('aws')
    sections = {name: {'status': 'complete', 'data_revision': 3} for name in
                ('hardening', 'exposure', 'least_privilege', 'network', 'privesc', 'leaks')}
    snapshot = make_snapshot(snapshot['provider'], snapshot['scopes'], snapshot['collections'],
                             created_at=snapshot['created_at'],
                             metadata=dict(snapshot.get('metadata', {}), sections=sections))
    snapshot_ref = artifacts.put('alice', job['id'], 'snapshot', snapshot)
    assert store.finish(job['id'], collector['owner'], 'collected', snapshot_ref)
    analyzer = store.claim('analyzer', tenant='alice', ident=job['id'])
    owner = analyzer['owner']
    monkeypatch.setattr(worker.os, 'dup2', lambda *_: None)
    monkeypatch.setattr(worker.signal, 'signal', lambda *_: None)
    events, published = [], []
    real_publish = reports.publish_report

    def publish(*args, **kwargs):
        reference = real_publish(*args, **kwargs)
        published.append((reference, copy.deepcopy(args[3]['publication'])))
        events.append('publish_' + args[3]['publication']['state'])
        return reference
    monkeypatch.setattr(reports, 'publish_report', publish)

    class Pipe:
        def __init__(self):
            self.sent = []
            self.accepted = False

        def send(self, message):
            self.sent.append(message)
            if message[0] == '__checkpoint__':
                event = message[1]
                self.accepted = store.record_checkpoint('alice', job['id'], owner, event['sequence'],
                    event['snapshot_ref'], report_ref=event['report_ref'], stage=event['stage'])
                events.append('checkpoint_accepted' if self.accepted else 'checkpoint_rejected')

        def recv(self):
            message = self.sent[-1]
            return ('__checkpoint_ack__', message[1]['sequence'], self.accepted)

        def close(self):
            pass

    request = {'artifact_config': {'mode': 'file', 'root': str(artifacts.root)},
               'tenant_id': 'alice', 'scan_id': job['id'], 'snapshot_ref': snapshot_ref,
               'selectors': {'ai_enabled': True}, 'timeline': {}, 'related': [],
               'checkpoint_sequence': 2, 'stage_results': {}, 'refresh_stage_results': False}
    return SimpleNamespace(settings=settings, store=store, artifacts=artifacts, job=job, owner=owner,
                           events=events, published=published, pipe=Pipe(), request=request)


def client_for(s):
    return TestClient(create_app(s.settings, store=s.store, artifacts=s.artifacts,
                                 authenticator=Identities()), base_url='http://127.0.0.1')


FEATURES = {
    'summary': '/summary?aggregation=check',
    'findings': '/findings?limit=500',
    'hardening': '/findings?categories=hardening&limit=500',
    'exposure': '/findings?categories=exposure&limit=500',
    'leaks': '/findings?finding_type=detected_leaks&limit=500',
    'coverage': '/coverage?limit=500',
    'resources': '/resources?limit=100',
    'least_privilege': '/least-privilege?limit=500',
    'network_map': '/graphs/network?max_nodes=500',
    'iam_graph': '/graphs/iam?max_nodes=500',
    'privesc_map': '/graphs/privesc?max_nodes=500',
    'privesc_admins': '/privesc/admins',
    'images': '/image-findings',
}


def read_features(client, ident):
    out = {}
    for name, path in FEATURES.items():
        response = client.get('/api/scans/' + ident + path)
        assert response.status_code == 200, (name, response.text)
        out[name] = response.json()
    rows, offset = [], 0
    while offset is not None:
        page = client.get('/api/scans/' + ident + '/findings?limit=500&offset=' + str(offset)).json()
        rows.extend(page['items'])
        offset = page['next_offset']
    out['all_findings'] = rows
    return out


def native_view(features):
    """The native content a reader reviews, without publication bookkeeping."""
    summary = {key: value for key, value in features['summary'].items()
               if key not in ('publication', 'ai', 'runtime')}
    return dict(features, summary=summary)


def test_native_features_are_reviewable_while_ai_runs_and_final_keeps_them(scenario, monkeypatch):
    s = scenario
    during = {}

    def review(report, snapshot, selectors, **kwargs):
        # The native checkpoint is durable and acknowledged before any model work.
        assert s.events == ['publish_partial', 'checkpoint_accepted']
        row = s.store.job('alice', s.job['id'])
        assert row['status'] == 'analyzing' and row['partial_report'] == s.published[0][0]
        assert row.get('report') is None
        with client_for(s) as client:
            assert client.get('/api/scans').json()['items'][0]['result_available'] is True
            during['features'] = read_features(client, s.job['id'])
            during['ai'] = client.get('/api/scans/' + s.job['id'] + '/ai').json()
            # Access control is unchanged for the running scan's sections.
            client.headers['Authorization'] = 'Bearer bob'
            for path in FEATURES.values():
                assert client.get('/api/scans/' + s.job['id'] + path).status_code == 404, path
            assert client.get('/api/scans/' + s.job['id'] + '/ai').status_code == 404
        s.events.append('review')
        return {'version': 1, 'status': 'completed', 'actions': [], 'reviews': {'hardening': [], 'exposure': []},
                'limitations': [], 'network': {'status': 'completed', 'explanation': '', 'findings': []}}
    monkeypatch.setattr(pipeline, 'review_scan', review)
    worker._process('analyzer', s.request, s.pipe)
    assert s.events == ['publish_partial', 'checkpoint_accepted', 'review', 'publish_final']
    assert s.pipe.sent[-1] == (True, s.published[-1][0])

    partial = during['features']
    publication = partial['summary']['publication']
    assert publication['state'] == 'partial' and publication['phase'] == 'analyzing'
    assert publication['sequence'] == 3
    assert {name for name, row in publication['sections'].items() if row['status'] == 'complete'} >= {
        'hardening', 'exposure', 'least_privilege', 'network', 'privesc', 'leaks'}
    # Every native feature has content during the run.
    assert partial['findings']['total'] > 0 and partial['hardening']['total'] > 0
    assert partial['coverage']['total'] > 0 and partial['resources']['total'] > 0
    assert partial['least_privilege']['total'] > 0
    assert partial['network_map']['nodes'] and partial['iam_graph']['nodes']
    # The demo account has no escalation edge; the map is still served from the checkpoint.
    assert isinstance(partial['privesc_map']['nodes'], list) and 'items' in partial['privesc_admins']
    assert partial['images']['total'] == 0  # images were not selected for this scan
    # No duplicated findings, and the counts agree across views.
    ids = [row['id'] for row in partial['all_findings']]
    assert len(ids) == len(set(ids)) == partial['findings']['total']
    assert partial['summary']['stats']['observation_count'] == partial['findings']['total']
    # AI says it is running, not "not requested".
    assert during['ai']['status'] == 'in_progress'
    assert during['ai']['pending_stages'] == ['network', 'priorities']
    assert during['ai']['actions'] == []

    s.store.finish(s.job['id'], s.owner, 'completed', s.published[-1][0])
    with client_for(s) as client:
        final = read_features(client, s.job['id'])
        ai = client.get('/api/scans/' + s.job['id'] + '/ai').json()
    assert final['summary']['publication'] == dict(publication, state='final', phase='completed')
    assert ai['status'] == 'completed' and 'pending_stages' not in ai
    # Final native results are identical to what was reviewable during the run.
    assert native_view(final) == native_view(partial)
    # Sequences are monotonic: the final never goes below the native checkpoint.
    assert [entry['sequence'] for _, entry in s.published] == [3, 3]


def test_pending_stage_projection_never_rewrites_stored_ai_or_terminal_scans():
    running = {'status': 'analyzing', 'data': '{"ai_enabled": true, "categories": ["network"]}'}
    placeholder = {'status': 'not_requested', 'actions': [], 'reviews': {}}
    assert with_pending_stages(running, placeholder) == dict(placeholder, status='in_progress',
                                                            pending_stages=['network', 'priorities'])
    overlay = {'version': 1, 'status': 'partial', 'actions': [], 'completed_stages': ['network']}
    assert with_pending_stages(running, overlay) == dict(overlay, pending_stages=['priorities'])
    stored = {'version': 1, 'status': 'completed', 'actions': []}
    assert with_pending_stages(running, stored) is stored
    for status in ('completed', 'failed', 'cancelled', 'timed_out'):
        assert with_pending_stages(dict(running, status=status), placeholder) is placeholder
    disabled = dict(running, data='{"ai_enabled": false}')
    assert with_pending_stages(disabled, placeholder) is placeholder
    only_network = dict(running, data='{"ai_priorities_enabled": false, "categories": ["network"]}')
    assert with_pending_stages(only_network, overlay) is overlay
    no_stage = dict(running, data='{"ai_priorities_enabled": false, "categories": ["hardening"]}')
    assert with_pending_stages(no_stage, placeholder) is placeholder
