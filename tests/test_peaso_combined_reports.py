import copy

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from peaso.ai import combined_report_runs as runs, combined_reports as compiler, report_runs
from peaso.finding_subjects import subject
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore, StoreError
from peaso.storage.dynamodb import DynamoStore
from tests.test_peaso_api import TestIdentities


def issue(ident='encryption', kind='vulnerability', severity='medium'):
    return dict(id=ident, title='Insufficient encryption protections', kind=kind, severity=severity,
                status='confirmed', description='Captured disk configuration.', impact='Data confidentiality risk.',
                recommendation='Enable encryption for the affected disks.', verification='Check encrypted disk settings.',
                references=[{'domain': 'findings', 'id': 'native-check'}], affected_assets=['prod/disk'],
                affected_subjects=[subject('aws', 'prod/east', 'disk', 'prod/disk')])


def severity_evidence(reference, *, asset='prod/disk', impact='material'):
    return dict(reference=reference, asset=asset, impact_level=impact, internet_reachable=False,
                prerequisites_supported=True, consequence='Loss of a protection for stored application data.',
                prerequisites='The affected disk stores current application data.')


def compiled(reports):
    rows = []
    for ident in ('encryption', 'images', 'leaks'):
        source = next(i for r in reports for i in r['issues'] if i['id'] == ident)
        rows.append({k: v for k, v in source.items() if k in compiler.CombinedIssue.model_fields} |
                    {'references': [{'report_id': r['scan_id'], 'issue_id': i['id']}
                                    for r in reports for i in r['issues'] if i['id'] == ident]})
        if source['kind'] == 'vulnerability':
            rows[-1]['severity_evidence'] = severity_evidence(rows[-1]['references'][0])
    return dict(summary='Combined captured issues.', issues=rows, limitations=[])


@pytest.fixture
def reports(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity', local_token='test-token-012345678901234567890')
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path/'artifacts')
    scans = []
    for name, provider in [('Production', 'aws'), ('Workloads', 'k8s')]:
        connector = store.add_connector('alice', {'name': name, 'provider': provider}, 'encrypted')
        job = store.enqueue('alice', {'connector_id': connector['id']}, limit=10)
        collector = store.claim('collector')
        snapshot = artifacts.put('alice', job['id'], 'snapshot', {})
        store.finish(job['id'], collector['owner'], 'collected', snapshot)
        analyzer = store.claim('analyzer')
        report = dict(status='completed', summary='Source report.', limitations=['Captured evidence only.'],
                      issues=[issue(), issue('images', 'image_cves', 'high'), issue('leaks', 'leaks', 'high')])
        ai = artifacts.put('alice', job['id'], 'ai-review', {'findings_report': report})
        ref = artifacts.put('alice', job['id'], 'manifest', {'bundle_version': 1, 'ai_review': ai})
        store.finish(job['id'], analyzer['owner'], 'completed', ref)
        scans.append(job['id'])
    monkeypatch.setattr('peaso.server.config.Settings', lambda: settings)
    monkeypatch.setattr('peaso.ai.providers.review_disabled', lambda *args: False)
    monkeypatch.setattr('peaso.ai.providers.resolve_access', lambda *args, **kw: ('MODEL-TOKEN', 'test'))
    monkeypatch.setattr('peaso.ai.auth.require_local_codex', lambda *args: None)
    return settings, store, artifacts, scans


def selected(store, artifacts):
    return [{k: r[k] for k in ('scan_id', 'version')} for r in runs.candidates(store, artifacts, 'alice')]


def test_combines_frozen_issues_and_lists_under_every_source(reports, monkeypatch):
    _, store, artifacts, scans = reports
    entry = runs.create(store, artifacts, 'alice', 'alice', 'Cloud and workloads', selected(store, artifacts))
    assert runs.listing(store, 'bob') == []
    for scan in scans:
        assert [r['id'] for r in runs.listing(store, 'alice', scan)] == [entry['id']]
    with pytest.raises(StoreError): runs.detail(store, artifacts, 'bob', entry['id'])
    # Replacing an original report must not change this combination's input.
    report_runs.request_run(store, 'alice', scans[0], 'alice')
    def invoke(stage, platform, entries, token, findings, reviews, *budget):
        assert stage == 'report_combination' and entries == findings == reviews == []
        assert len(platform['reports']) == 2
        assert all(len(r['issues']) == 3 for r in platform['reports'])
        return compiled(platform['reports'])
    monkeypatch.setattr('peaso.ai.pipeline.invoke_before_deadline', invoke)
    assert runs.execute(store, artifacts, 'alice', entry['id'])
    value = runs.detail(store, artifacts, 'alice', entry['id'])
    assert value['status'] == 'completed' and len(value['issues']) == 3
    assert value['covered_count'] == value['source_count'] == 6
    assert value['limitations'] == ['Captured evidence only.']
    assert {i['kind'] for i in value['issues']} == {'vulnerability', 'leaks', 'image_cves'}
    assert not runs.execute(store, artifacts, 'alice', entry['id'])
    frozen = runs.source_issue(store, artifacts, 'alice', entry['id'], scans[0], 'encryption')
    assert frozen['issue']['description'] == 'Captured disk configuration.'
    store.delete_job('alice', scans[0])
    assert runs.source_issue(store, artifacts, 'alice', entry['id'], scans[0], 'encryption')['assessment_available'] is False
    with pytest.raises(StoreError): runs.source_issue(store, artifacts, 'alice', entry['id'], 'f'*32, 'encryption')


def test_rejects_duplicate_foreign_incomplete_and_changed_sources(reports):
    _, store, artifacts, scans = reports
    selection = selected(store, artifacts)
    with pytest.raises(StoreError, match='different'):
        runs.create(store, artifacts, 'alice', 'alice', 'Duplicate', [selection[0]]*2)
    with pytest.raises(StoreError): runs.create(store, artifacts, 'bob', 'bob', 'Foreign', selection)
    invalid = copy.deepcopy(selection); invalid[0]['version'] = '0'*64
    with pytest.raises(StoreError, match='changed'):
        runs.create(store, artifacts, 'alice', 'alice', 'Stale', invalid)
    report_runs.request_run(store, 'alice', scans[0], 'alice')
    assert runs.create(store, artifacts, 'alice', 'alice', 'Use published report', selection)['status'] == 'queued'


@pytest.mark.parametrize('failure', ['missing', 'duplicate', 'unknown', 'special_duplicate', 'special_kind', 'severity'])
def test_output_requires_complete_unique_provenance_and_special_groups(failure):
    sources = [{'scan_id': s, 'issues': [issue(), issue('images', 'image_cves', 'high'), issue('leaks', 'leaks', 'high')]}
               for s in ('a'*32, 'b'*32)]
    data = compiled(sources)
    if failure == 'missing': data['issues'][0]['references'].pop()
    if failure == 'duplicate': data['issues'][0]['references'] *= 2
    if failure == 'unknown': data['issues'][0]['references'][0]['report_id'] = 'other'
    if failure == 'special_duplicate':
        duplicate = copy.deepcopy(data['issues'][1]); duplicate['references'] = [duplicate['references'].pop()]
        data['issues'][1]['references'] = data['issues'][1]['references'][:1]
        data['issues'].append(duplicate)
    if failure == 'special_kind': data['issues'][1]['kind'] = 'vulnerability'
    if failure == 'severity': data['issues'][0]['severity'] = 'high'
    with pytest.raises(ValueError): compiler.validate(data, sources)


def test_combination_repair_feedback_identifies_omissions_and_duplicates():
    from peaso.ai.output_validation import feedback

    sources = [{'scan_id': scan, 'issues': [issue(), issue('images', 'image_cves', 'high'),
                                           issue('leaks', 'leaks', 'high')]} for scan in ('a'*32, 'b'*32)]
    data = compiled(sources)
    refs = data['issues'][0]['references']
    missing = refs.pop()
    duplicate = refs[0]
    refs.extend([duplicate, {'report_id': 'foreign', 'issue_id': 'unexpected'}])
    with pytest.raises(compiler.CombinedReferenceCoverageError) as error:
        compiler.validate(data, sources)

    assert feedback(error.value) == {
        'code': 'unknown_or_duplicate_combined_reference',
        'missing_references': [missing],
        'duplicate_references': [duplicate],
        'unknown_reference_count': 1,
    }


def test_stale_worker_cannot_publish_deleted_combination(reports, monkeypatch):
    _, store, artifacts, _ = reports
    entry = runs.create(store, artifacts, 'alice', 'alice', 'Fenced', selected(store, artifacts))
    def invoke(stage, platform, *args):
        raw, _ = runs.read(store, 'alice', entry['id'])
        assert store.set_ai_state('alice', runs.key(entry['id']), None, raw)
        return compiled(platform['reports'])
    monkeypatch.setattr('peaso.ai.pipeline.invoke_before_deadline', invoke)
    assert not runs.execute(store, artifacts, 'alice', entry['id'])
    with pytest.raises(StoreError): runs.detail(store, artifacts, 'alice', entry['id'])


def test_api_ownership_creation_dispatch_and_source_read(reports, monkeypatch):
    settings, store, artifacts, scans = reports
    monkeypatch.setenv('PEASO_WORKFLOW_ARN', 'configured')
    dispatched = []
    monkeypatch.setattr(runs, 'dispatch', lambda *args: dispatched.append(args))
    app = create_app(settings, store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url='http://127.0.0.1') as client:
        alice = {'Authorization': 'Bearer alice'}; bob = {'Authorization': 'Bearer bob'}
        assert client.get('/api/combined-reports').status_code == 401
        candidates = client.get('/api/combined-reports/candidates', headers=alice).json()['items']
        response = client.post('/api/combined-reports', headers=alice, json={'name': 'All environments',
            'reports': [{k: row[k] for k in ('scan_id', 'version')} for row in candidates]})
        assert response.status_code == 202, response.text
        ident = response.json()['id']
        assert dispatched == [('alice', ident)]
        assert client.get('/api/combined-reports/'+ident, headers=bob).status_code == 404
        for scan in scans:
            assert client.get('/api/combined-reports?scan_id='+scan, headers=alice).json()['items'][0]['id'] == ident
        source = client.get(f'/api/combined-reports/{ident}/source-issue', params={'report_id': scans[0], 'issue_id': 'images'}, headers=alice)
        assert source.status_code == 200 and source.json()['issue']['kind'] == 'image_cves'


@mock_aws
def test_dynamo_prefix_listing_is_tenant_scoped_and_keeps_auth_private():
    client = boto3.client('dynamodb', region_name='us-east-1')
    client.create_table(TableName='combined-tests', BillingMode='PAY_PER_REQUEST',
        KeySchema=[{'AttributeName': k, 'KeyType': t} for k, t in [('PK', 'HASH'), ('SK', 'RANGE')]],
        AttributeDefinitions=[{'AttributeName': k, 'AttributeType': 'S'} for k in ('PK', 'SK')])
    store = DynamoStore('combined-tests', client=client)
    connector = store.add_connector('alice', {'name': 'Cloud account', 'provider': 'gcp'}, 'encrypted')
    assert runs._connector_index(store, 'alice')[connector['id']] == connector
    for tenant in ('alice', 'bob'):
        store.set_ai_state(tenant, 'auth', 'PRIVATE')
        store.set_ai_state(tenant, runs.PREFIX+'a'*32, tenant)
    assert store.ai_states('alice', runs.PREFIX) == [{'name': runs.PREFIX+'a'*32, 'value': 'alice'}]


def test_remote_agent_workspace_and_backend_share_combined_contract(tmp_path, monkeypatch):
    from peaso.ai import pipeline, output_validation
    sources = [{'scan_id': s, 'connector_name': s, 'provider': 'k8s', 'created_at': '2026-11-20T00:00:00Z',
                'summary': 'Captured issues.', 'limitations': [],
                'issues': [issue(), issue('images', 'image_cves', 'high'), issue('leaks', 'leaks', 'high')]}
               for s in ('a'*32, 'b'*32)]
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    monkeypatch.setattr('peaso.ai.fargate.configuration', lambda: {})
    def remote(stage, root, token, timeout, **kwargs):
        assert stage == 'report_combination'
        kwargs['prepare']()
        assert not (root/'context.sqlite').exists()
        assert not (root/'codex-auth.json').exists()
        original = output_validation.context(stage, root)
        assert original == [{k: v for k, v in source.items() if k != 'summary'} for source in sources]
        data = compiled(original)
        output_validation.validate(stage, data, original)
        return data
    monkeypatch.setattr('peaso.ai.fargate.invoke', remote)
    result = pipeline.invoke('report_combination', {'reports': sources}, [], 'MODEL-TOKEN', [], [], 60)
    assert compiler.validate(result, sources)['covered_count'] == 6
    with pytest.raises(ValueError, match='report_live_access_disabled'):
        pipeline.invoke('report_combination', {'reports': sources}, [{'provider': 'k8s'}], 'MODEL-TOKEN', [], [], 60)


def test_workspace_cleanup_waits_for_combination_then_removes_its_snapshot(reports):
    settings, store, artifacts, _ = reports
    entry = runs.create(store, artifacts, 'alice', 'alice', 'Cleanup', selected(store, artifacts))
    app = create_app(settings, store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url='http://127.0.0.1') as client:
        headers = {'Authorization': 'Bearer alice'}
        response = client.delete('/api/workspace-data?confirmation=DELETE', headers=headers)
        assert response.status_code == 409 and 'combined reports' in response.text
        runs.fail(store, 'alice', entry['id'])
        response = client.delete('/api/workspace-data?confirmation=DELETE', headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()['remaining'] is False
        assert runs.listing(store, 'alice') == []


def test_connector_names_decode_storage_data_and_survive_connector_deletion(reports):
    _, store, artifacts, scans = reports
    rows = runs.candidates(store, artifacts, 'alice')
    assert {(row['connector_name'], row['provider']) for row in rows} == {('Production', 'aws'), ('Workloads', 'k8s')}
    entry = runs.create(store, artifacts, 'alice', 'alice', 'Named sources', selected(store, artifacts))
    assert {(row['connector_name'], row['provider']) for row in entry['sources']} == {('Production', 'aws'), ('Workloads', 'k8s')}
    connector = store.job('alice', scans[0])['connector_id']
    store.delete_connector('alice', connector)
    captured = next(row for row in runs.candidates(store, artifacts, 'alice') if row['scan_id'] == scans[0])
    assert captured['connector_name'] == 'Production' and captured['provider'] == 'aws'


def test_combined_fixed_findings_keep_all_assets_and_breakdowns():
    from peaso.finding_subjects import subject
    sources = []
    for scan, scope in [('a', 'west'), ('b', 'east')]:
        images = issue('images', 'image_cves', 'high')
        images.update(affected_assets=[f'{scope}/image'], affected_subjects=[subject('aws', scope, 'container_image', f'{scope}/image')], special_details=[
            {'asset': f'{scope}/image', 'counts': {'critical': 0, 'high': 2}, 'finding_ids': [f'native-{scan}']}])
        leak = issue('leaks', 'leaks', 'high')
        leak.update(affected_assets=[f'{scope}/workload'], affected_subjects=[subject('aws', scope, 'content_source', f'{scope}/workload')], special_details=[
            {'label': 'Leak 1', 'locations': [f'{scope}/config:12'], 'finding_ids': [f'leak-{scan}']}])
        sources.append({'scan_id': scan, 'issues': [issue(), images, leak]})
    result = compiler.validate(compiled(sources), sources)
    for kind, asset in (('image_cves', 'image'), ('leaks', 'workload')):
        [merged] = [row for row in result['issues'] if row['kind'] == kind]
        assert merged['affected_assets'] == [f'east/{asset}', f'west/{asset}']
        assert {row['report_id'] for row in merged['special_details']} == {'a', 'b'}
        assert len(merged['references']) == 2
    assert 'east/config:12' in next(row for row in result['issues'] if row['kind'] == 'leaks')['description']


def test_combiner_caps_image_severity_and_preserves_leak_severity():
    sources = [{'scan_id': 'a', 'issues': [
        issue('encryption', severity='high'),
        issue('images', 'image_cves', 'high'),
        issue('leaks', 'leaks', 'high'),
    ]}]
    data = compiled(sources)
    data['issues'][0]['severity'] = 'medium'
    assert any(row['severity'] == 'medium' for row in compiler.validate(data, sources)['issues'])
    data['issues'][1]['severity'] = 'critical'
    result = compiler.validate(data, sources)
    assert next(row for row in result['issues'] if row['kind'] == 'image_cves')['severity'] == 'medium'
    data['issues'][2]['severity'] = 'medium'
    with pytest.raises(ValueError, match='combined_severity_mismatch'):
        compiler.validate(data, sources)


def test_unconfirmed_legacy_issue_never_reaches_combination(tmp_path):
    original = dict(issue(), status='needs_review', description='Unverified cross-account retention.')
    frozen = [{'scan_id': 'a', 'connector_name': 'Audit', 'provider': 'aws', 'created_at': '',
               'limitations': [], 'issues': [original]}]
    files = {}
    compiler.build(tmp_path, {'reports': frozen}, lambda path, value: files.update({path.name: value}))
    assert files['combined-reports.json'][0]['issues'] == []
    assert files['platform.json']['reports'][0]['issue_count'] == 0
    data = {'summary': 'Combined report', 'limitations': [], 'issues': []}
    assert compiler.validate(data, frozen)['source_count'] == 0
    candidate = {key: original[key] for key in compiler.CombinedIssue.model_fields if key in original}
    candidate['references'] = [{'report_id': 'a', 'issue_id': original['id']}]
    with pytest.raises(compiler.CombinedReferenceCoverageError):
        compiler.validate(dict(data, issues=[candidate]), frozen)


def test_legacy_linked_assets_do_not_enter_combined_verified_scope():
    from peaso.finding_subjects import present_verified_scope

    original = issue(severity='low')
    original.pop('affected_subjects')
    original['manual_affected_assets'] = ['made-up']
    reports = [{'scan_id': 'a', 'issues': [original]}]
    candidate = {key: value for key, value in original.items() if key in compiler.CombinedIssue.model_fields}
    candidate['references'] = [{'report_id': 'a', 'issue_id': original['id']}]
    result = compiler.validate(dict(summary='Combined findings.', issues=[candidate], limitations=[]), reports)['issues'][0]
    assert result['affected_assets'] == []
    assert result['affected_scope_incomplete']
    public = present_verified_scope(original)
    assert not public['affected_assets'] and 'manual_affected_assets' not in public
    assert original['affected_assets'] == ['prod/disk']


def test_combined_medium_requires_one_source_with_matching_severity_evidence():
    medium = issue('production-recovery')
    medium['severity_evidence'] = severity_evidence(medium['references'][0], asset='prod/state')
    medium['affected_subjects'] = [subject('aws', scope, 'disk', 'prod/state') for scope in ('prod/east', 'prod/west')]
    medium['affected_assets'] = ['prod/state (prod/east, disk)', 'prod/state (prod/west, disk)']
    low = issue('limited-recovery', severity='low')
    legacy = issue('disabled-preventive-guardrail')
    legacy['description'] = 'The account guardrail permits future public sharing. Captured buckets are private.'
    reports = [{'scan_id': 'prod', 'issues': [medium]}, {'scan_id': 'dev', 'issues': [low, legacy]}]
    merged = {key: value for key, value in medium.items() if key in compiler.CombinedIssue.model_fields}
    merged['references'] = [{'report_id': 'prod', 'issue_id': medium['id']},
                            {'report_id': 'dev', 'issue_id': low['id']}]
    merged['severity_evidence'] = dict(medium['severity_evidence'], reference=merged['references'][0])
    preventive = {key: value for key, value in legacy.items() if key in compiler.CombinedIssue.model_fields}
    preventive.update(kind='hardening', severity='info', references=[{'report_id': 'dev', 'issue_id': legacy['id']}])
    data = dict(summary='Combined findings.', issues=[merged, preventive], limitations=[])
    assert [item['severity'] for item in compiler.validate(data, reports)['issues']] == ['medium', 'info']
    for changes in ({'reference': merged['references'][1], 'asset': 'prod/disk'},
                    {'consequence': 'An unsupported consequence across all accounts.'}):
        modified = copy.deepcopy(data)
        modified['issues'][0]['severity_evidence'].update(changes)
        with pytest.raises(ValueError, match='unsupported_report_severity_source'):
            compiler.validate(modified, reports)


def test_combination_correlates_registry_image_with_other_accounts_running_workload():
    digest = 'sha256:' + 'a' * 64
    runtime = {'digest': digest, 'provider': 'aws', 'scope': 'dev/east', 'workload': 'task', 'container': 'app'}
    image = issue('images', 'image_cves', 'high')
    image.update(affected_assets=['repository'], special_details=[
        {'asset': 'repository', 'digest': digest, 'counts': {'critical': 1, 'high': 2}, 'finding_ids': ['native']}])
    sources = [{'scan_id': 'registry', 'issues': [image]}, {'scan_id': 'workload', 'issues': [], 'running_images': [runtime]}]
    candidate = {key: value for key, value in image.items() if key in compiler.CombinedIssue.model_fields}
    candidate['references'] = [{'report_id': 'registry', 'issue_id': 'images'}]
    [merged] = compiler.validate(dict(summary='Combined captured issues.', issues=[candidate], limitations=[]), sources)['issues']
    assert merged['severity'] == 'medium'
    assert merged['special_details'][0]['running_workloads'] == [runtime]
    assert merged['special_details'][0]['counts'] == {'critical': 1, 'high': 2}


def test_combination_preserves_exact_task_scope_and_distinguishes_retention_benchmark():
    a, b = issue('containers'), issue('backup')
    a['source_facts'] = {'writable_task_definitions': [['test', f'task-{i}'] for i in range(25)]}
    b['source_facts'] = {'retention_benchmark': True, 'short_retention_days': [15]}
    reports = [{'scan_id': 'dev', 'issues': [a, b]}]
    merged = {key: value for key, value in a.items() if key in compiler.CombinedIssue.model_fields}
    merged['references'] = [{'report_id': 'dev', 'issue_id': ident} for ident in ('containers', 'backup')]
    merged['severity_evidence'] = severity_evidence(merged['references'][0])
    data = dict(summary='Combined captured issues.', issues=[merged], limitations=[])
    [result] = compiler.validate(data, reports)['issues']
    assert '**25 affected task definitions.** Each has at least one container' in result['description']
    assert 'Some backups expire after 15 days. A problem discovered later may be too old to recover' in result['description']
    assert '35' not in result['description']
    merged['description'] = 'At least one of 25 reviewed development ECS task-definition observations is affected.'
    with pytest.raises(ValueError, match='use_source_task_definition_count'):
        compiler.validate(data, reports)
    merged['description'] = 'Some recovery points have short retention.'
    merged['recommendation'] = 'Meet the approved 35-day target.'
    with pytest.raises(ValueError, match='use_source_retention_benchmark'):
        compiler.validate(data, reports)
