import pytest
from fastapi.testclient import TestClient
from peaso.storage import SQLiteStore, FileArtifacts, StoreError
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.ai import report_runs
from tests.test_peaso_api import TestIdentities


@pytest.fixture
def completed(tmp_path):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity', local_token='test-token-012345678901234567890')
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path/'artifacts')
    connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    collector = store.claim('collector')
    snapshot = artifacts.put('alice', job['id'], 'snapshot', {'provider': 'aws', 'collections': []})
    store.finish(job['id'], collector['owner'], 'collected', snapshot)
    analyzer = store.claim('analyzer')
    prior = {'status': 'completed', 'actions': [{'rank': 1, 'finding_ids': ['f']}], 'reviews': {},
             'network': {'status': 'completed', 'findings': [], 'explanation': 'Captured architecture.'},
             'findings_report': {'status': 'completed', 'issues': [{'id': 'old', 'title': 'Old issue'}]}}
    report = {'provider': 'aws', 'findings': [{'id': 'f'}], 'ai': prior}
    report_ref = artifacts.put('alice', job['id'], 'report', report)
    ai_ref = artifacts.put('alice', job['id'], 'ai-review', prior)
    manifest = artifacts.put('alice', job['id'], 'manifest', {'bundle_version': 1, 'summary': {}, 'report_json': report_ref, 'ai_review': ai_ref})
    store.finish(job['id'], analyzer['owner'], 'completed', manifest)
    return settings, store, artifacts, job['id'], report, prior


def test_request_hides_old_report_and_prevents_concurrent_runs(completed):
    _, store, artifacts, scan, _, prior = completed
    state = report_runs.request_run(store, 'alice', scan, 'alice')
    row = store.job('alice', scan)
    current = report_runs.current_report(store, artifacts, 'alice', scan, row, prior['findings_report'])
    assert current['status'] == 'in_progress' and current['issues'] == [] and not current['can_launch']
    with pytest.raises(StoreError, match='already running'):
        report_runs.request_run(store, 'alice', scan, 'alice')
    with pytest.raises(StoreError): report_runs.request_run(store, 'bob', scan, 'bob')
    assert state['result_ref'] is None


def test_execute_replaces_all_issues_and_preserves_saved_analyses(completed, monkeypatch):
    _, store, artifacts, scan, native, prior = completed
    state = report_runs.request_run(store, 'alice', scan, 'alice')
    def review(report, snapshot, selectors, **kwargs):
        assert kwargs['stages'] == ('findings_report',)
        assert 'ai' not in report
        context = kwargs['reused_stages']['findings_report_context']
        assert context['actions'] == prior['actions'] and context['network'] == prior['network']
        assert selectors['ai_enabled'] and selectors['ai_user_id'] == 'alice'
        return {'findings_report': {'status': 'completed', 'issues': [{'id': 'stable-id', 'title': 'New issue'}]}}
    monkeypatch.setattr('peaso.ai.pipeline.review_scan', review)
    assert report_runs.execute(store, artifacts, 'alice', scan, state['generation'])
    row = store.job('alice', scan)
    current = report_runs.current_report(store, artifacts, 'alice', scan, row, prior['findings_report'])
    assert [i['title'] for i in current['issues']] == ['New issue']
    assert state['generation'] in current['issues'][0]['id']
    assert artifacts.get('alice', artifacts.get('alice', row['report'])['report_json']) == native
    assert not report_runs.execute(store, artifacts, 'alice', scan, state['generation'])
    next_run = report_runs.request_run(store, 'alice', scan, 'alice')
    assert next_run['generation'] != state['generation']
    assert report_runs.current_report(store, artifacts, 'alice', scan, row, {})['issues'] == []


def test_obsolete_worker_cannot_publish_into_a_new_generation(completed, monkeypatch):
    _, store, artifacts, scan, _, _ = completed
    first = report_runs.request_run(store, 'alice', scan, 'alice')
    def review(*args, **kwargs):
        report_runs.request_run(store, 'alice', scan, 'alice', now=first['expires'] + 1)
        return {'findings_report': {'status': 'completed', 'issues': [{'id': 'stale', 'title': 'Stale'}]}}
    monkeypatch.setattr('peaso.ai.pipeline.review_scan', review)
    assert not report_runs.execute(store, artifacts, 'alice', scan, first['generation'])
    _, state = report_runs._read(store, 'alice', scan)
    assert state['generation'] != first['generation'] and state['result_ref'] is None


def test_launch_endpoint_owns_scan_and_clears_count_immediately(completed, monkeypatch):
    settings, store, artifacts, scan, _, _ = completed
    monkeypatch.setattr('peaso.ai.auth.require_local_codex', lambda *a: None)
    monkeypatch.setenv('PEASO_WORKFLOW_ARN', 'arn:fixture')
    dispatched = []
    monkeypatch.setattr(report_runs, 'dispatch', lambda *a: dispatched.append(a))
    app = create_app(settings, store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url='http://127.0.0.1') as client:
        path = f'/api/scans/{scan}/findings-report'
        assert client.post(path).status_code == 401
        assert client.post(path, headers={'Authorization': 'Bearer bob'}).status_code == 404
        own = {'Authorization': 'Bearer alice'}
        response = client.post(path, headers=own)
        assert response.status_code == 202, response.text
        assert dispatched[0] == ('alice', scan, response.json()['generation'])
        assert client.post(path, headers=own).status_code == 409
        assert client.get(path, headers=own).json()['issues'] == []
        assert client.get(f'/api/scans/{scan}/ai', headers=own).json()['findings_report'] == {'status': 'in_progress', 'total': 0}
