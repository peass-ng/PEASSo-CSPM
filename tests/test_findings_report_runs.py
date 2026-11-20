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


def test_request_preserves_old_report_and_prevents_concurrent_runs(completed):
    _, store, artifacts, scan, _, prior = completed
    state = report_runs.request_run(store, 'alice', scan, 'alice')
    row = store.job('alice', scan)
    current = report_runs.current_report(store, artifacts, 'alice', scan, row, prior['findings_report'])
    assert current['status'] == 'completed' and current['run_status'] == 'queued' and current['issues'] == prior['findings_report']['issues'] and not current['can_launch']
    with pytest.raises(StoreError, match='already running'):
        report_runs.request_run(store, 'alice', scan, 'alice')
    with pytest.raises(StoreError): report_runs.request_run(store, 'bob', scan, 'bob')
    assert state['result_ref'] is None


def test_execute_publishes_updated_issues_and_preserves_saved_analyses(completed, monkeypatch):
    _, store, artifacts, scan, native, prior = completed
    state = report_runs.request_run(store, 'alice', scan, 'alice')
    def review(report, snapshot, selectors, **kwargs):
        assert kwargs['stages'] == ('findings_report',)
        assert 'ai' not in report
        context = kwargs['reused_stages']['findings_report_context']
        assert context['actions'] == prior['actions'] and context['network'] == prior['network']
        assert context['previous_report']['issues'] == prior['findings_report']['issues']
        assert selectors['ai_enabled'] and selectors['ai_user_id'] == 'alice'
        return {'findings_report': {'status': 'completed', 'issues': [{'id': 'stable-id', 'title': 'New issue'}]}}
    monkeypatch.setattr('peaso.ai.pipeline.review_scan', review)
    assert report_runs.execute(store, artifacts, 'alice', scan, state['generation'])
    row = store.job('alice', scan)
    current = report_runs.current_report(store, artifacts, 'alice', scan, row, prior['findings_report'])
    assert [i['title'] for i in current['issues']] == ['New issue']
    assert current['issues'][0]['id'] == 'stable-id'
    assert artifacts.get('alice', artifacts.get('alice', row['report'])['report_json']) == native
    assert not report_runs.execute(store, artifacts, 'alice', scan, state['generation'])
    next_run = report_runs.request_run(store, 'alice', scan, 'alice')
    assert next_run['generation'] != state['generation']
    assert report_runs.current_report(store, artifacts, 'alice', scan, row, {})['issues'] == current['issues']


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


def test_launch_endpoint_owns_scan_and_preserves_report(completed, monkeypatch):
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
        assert client.get(path, headers=own).json()['issues'][0]['id'] == 'old'
        assert client.get(f'/api/scans/{scan}/ai', headers=own).json()['findings_report'] == {'status': 'completed', 'total': 1}


@pytest.mark.parametrize('remote,report_only', [(False, False), (True, False), (True, True)])
def test_report_compilation_is_the_last_model_stage(monkeypatch, tmp_path, remote, report_only):
    from peaso.ai import pipeline, findings_report
    from tests.test_peaso_ai_review import network_fixture
    from types import SimpleNamespace
    report, inventory, architecture = network_fixture()
    monkeypatch.setattr(pipeline, 'Settings', lambda: SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, auth_mode='local'))
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (SimpleNamespace(), None))
    monkeypatch.setattr('peaso.ai.providers.review_disabled', lambda *a: False)
    monkeypatch.setattr('peaso.ai.providers.resolve_access', lambda *a, **kw: ('MODEL-TOKEN', 'test'))
    monkeypatch.setattr('peaso.ai.providers.credential_value', lambda _: 'MODEL-TOKEN')
    monkeypatch.setattr(pipeline.isolation, 'available', lambda: True)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: remote)
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: inventory)
    monkeypatch.setattr('peaso.least_privilege.project', lambda *a, **kw: {'items': []})
    monkeypatch.setattr(pipeline, 'available_memory', lambda: 4 * 1024**3)
    stages = []
    def invoke(stage, platform, *args, **kwargs):
        stages.append(stage)
        if stage == 'network': return architecture
        if stage == 'priorities': return {'actions': [], 'limitations': []}
        assert platform['network_review']['status'] == 'completed'
        return {'summary': 'Compiled supplied evidence.', 'issues': [], 'limitations': [],
                'exclusions': [{'reference': {'domain': r['domain'], 'id': r['id']}, 'reason': 'The supplied observation describes a planned documentation change with no effect on access controls, data handling, or service exposure.'}
                               for r in findings_report.agent_sources(findings_report.source_index(platform)) if r['required']]}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    options = {}
    if report_only:
        from peaso.ai.network import prepare
        saved = dict(pipeline.validate_network(architecture, prepare(report, inventory, {})), status='completed')
        options = {'stages': ('findings_report',), 'reused_stages': {'findings_report_context': {'network': saved, 'actions': []}}}
    result = pipeline.review_scan(report, {}, {}, tenant='test', artifacts=None, **options)
    assert stages == (['findings_report'] if report_only else ['network', 'priorities', 'findings_report'])
    assert result['findings_report']['status'] == 'completed'


def test_rerun_uses_original_observation_ids_instead_of_download_groups(completed, monkeypatch):
    _, store, artifacts, scan, native, prior = completed
    row = store.job('alice', scan)
    bundle = artifacts.get('alice', row['report'])
    grouped = dict(native, findings=[{'id': 'download-group', 'grouped': True, 'observations': native['findings']}], finding_grouping='check-v1')
    detail = artifacts.put('alice', scan, 'detail', {'id': 'f', 'evidence': {'observed': 'original'}})
    chunks = artifacts.put('alice', scan, 'findings', {'items': [{'id': 'f', '_detail_reference': detail}]})
    updated = dict(bundle, report_json=artifacts.put('alice', scan, 'report', grouped), finding_count=1,
                   finding_chunks=[{'reference': chunks}], check_meta={'check': {'category': 'hardening'}})
    manifest = artifacts.put('alice', scan, 'manifest', updated)
    store.replace_completed_report('alice', scan, row['report'], manifest)
    def review(report, *args, **kwargs):
        assert report['findings'] == [{'id': 'f', 'evidence': {'observed': 'original'}}]
        assert 'finding_grouping' not in report
        assert report['check_meta'] == updated['check_meta']
        return {'findings_report': {'status': 'completed', 'issues': []}}
    monkeypatch.setattr('peaso.ai.pipeline.review_scan', review)
    state = report_runs.request_run(store, 'alice', scan, 'alice')
    assert report_runs.execute(store, artifacts, 'alice', scan, state['generation'])
