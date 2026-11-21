import copy
import json
from types import SimpleNamespace

import pytest

from peaso.ai import findings_report as compiler, pipeline, output_validation
from peaso.server.findings_report import page


def source(domain, ident, kind=None, confirmed=True):
    return dict(domain=domain, id=ident, kind=kind, confirmed=confirmed, required=True)


def issue(refs, kind='vulnerability', status='confirmed'):
    return dict(title='Restrict the affected boundary', kind=kind, status=status,
                severity='info' if kind == 'hardening' else 'medium',
                description='Observed configuration in the scanned account.', impact='Conditional data access.',
                recommendation='Apply the scoped policy after checking dependencies.',
                verification='Read back the policy and confirm the intended restriction.',
                references=[dict(domain=d, id=i) for d, i in refs])


def report(issues=(), exclusions=()):
    return dict(summary='Completed scan report.', issues=list(issues), exclusions=list(exclusions), limitations=[])


def test_all_source_areas_are_assessed_and_ids_are_stable():
    sources = [source('findings', 'f'), source('least_privilege', 'lp', confirmed=False),
               source('privesc_edges', 'e', confirmed=False), source('actions', '1', confirmed=False)]
    result = compiler.validate(report([issue([('findings', 'f'), ('actions', '1')]),
        issue([('least_privilege', 'lp')], kind='hardening', status='needs_review')],
        [dict(reference=dict(domain='privesc_edges', id='e'), reason='No current grant supports the reported relationship; the required permission is absent in the captured policy and no data access is indicated.')]), sources)
    assert result['covered_count'] == result['source_count'] == 4
    assert result['issues'][0]['id'].startswith('report-')
    original = report([issue([('findings', 'f'), ('actions', '1')])])
    result1 = compiler.validate(original, sources[:1] + sources[3:])
    original['issues'][0]['references'].reverse()
    assert compiler.validate(original, sources[:1] + sources[3:])['issues'][0]['id'] == result1['issues'][0]['id']


def test_confirmed_exclusions_and_omissions_are_reported_together():
    sources = [source('findings', 'first'), source('findings', 'second'),
               source('findings', 'unresolved', confirmed=False)]
    reason = ('The captured entry refers to a retired sample workload that receives no traffic '
              'and processes no user or business data.')
    exclusion = {'reference': {'domain': 'findings', 'id': 'first'}, 'reason': reason}
    unresolved = dict(exclusion, reference={'domain': 'findings', 'id': 'unresolved'})
    with pytest.raises(compiler.MissingReportEvidence) as error:
        compiler.validate(report(exclusions=[exclusion, unresolved]), sources)
    assert [item['id'] for item in error.value.missing] == ['first', 'second']

    result = compiler.validate(report([issue([('findings', 'first'), ('findings', 'second')])],
                                      [unresolved]), sources)
    assert result['covered_count'] == 3
    assert result['exclusions'] == [unresolved]


def test_permission_recommendations_survive_individual_and_combined_compilation(tmp_path):
    from peaso.ai import combined_reports
    from peaso.least_privilege import project

    arn = 'arn:aws:iam::123456789012:role/App'
    aws = project('aws', [{'id': arn, 'type': 'iam_role', 'scope': '123456789012/global', 'data': {
        'Arn': arn, 'RoleName': 'App', 'RolePolicyList': [{'PolicyName': 'inline', 'PolicyDocument': {'Statement': [
            {'Effect': 'Allow', 'Action': ['iam:CreateAccessKey', 'iam:UpdateAssumeRolePolicy', 'iam:PutRolePolicy'], 'Resource': '*'}]}}],
        'ServicesLastAccessedStatus': {'collection_status': 'collected', 'job_completion_date': '2026-10-20T00:00:00Z'},
        'ServicesLastAccessed': [{'ServiceNamespace': 'iam', 'TrackedActionsUnobserved': ['CreateAccessKey', 'PutRolePolicy'],
            'TrackedActionsLastAccessed': [{'ActionName': 'UpdateAssumeRolePolicy', 'LastAccessedTime': '2026-10-18T00:00:00Z'}]}],
    }}])
    member = 'user:app@example.test'
    gcp = project('gcp', [{'type': 'recommendation', 'scope': 'projects/example', 'data': {
        'name': 'recommendations/editor', 'stateInfo': {'state': 'ACTIVE'}, 'lastRefreshTime': '2026-10-20T00:00:00Z',
        'content': {'overview': {'member': member, 'removedRole': 'roles/editor', 'addedRoles': ['roles/viewer']}},
    }}])
    inputs = []
    for provider, projection, principal in [('aws', aws, arn), ('gcp', gcp, member)]:
        platform = {'report': {'provider': provider}, 'least_privilege': projection}
        sources = compiler.source_index(platform)
        ref = ('least_privilege', principal)
        excluded = report(exclusions=[{'reference': dict(zip(('domain', 'id'), ref)),
            'reason': 'This observation is not security relevant according to the owner because this role has no access to the scoped workload.'}])
        assert compiler.validate(excluded, sources)['covered_count'] == 1
        choices = sources[0]['permission_recommendations']
        assert {item['value'] for item in choices} == ({'iam:CreateAccessKey', 'iam:PutRolePolicy'} if provider == 'aws' else {'roles/editor'})
        draft = issue([ref], kind='hardening', status='needs_review')
        draft['permission_review_ids'] = ['PR-111111111111']
        with pytest.raises(ValueError, match='unknown_or_duplicate_permission_review'):
            compiler.validate(report([draft]), sources)
        relevant = 'iam:CreateAccessKey' if provider == 'aws' else 'roles/editor'
        draft['permission_review_ids'] = [next(item['review_id'] for item in choices if item['value'] == relevant)]
        workspace = tmp_path / provider
        workspace.mkdir()
        compiler.build(workspace, platform, [], [], output_validation.private_file)
        worker_sources = output_validation.context('findings_report', workspace)
        assert 'permission_recommendations' not in worker_sources[0]
        output_validation.validate('findings_report', report([draft]), worker_sources)
        final = compiler.complete(report([draft]), sources, compiler.pregenerate(platform, sources))
        [compiled] = final['issues']
        inputs.append({'scan_id': provider, 'issues': [compiled]})
    combined_issue = issue([], kind='hardening', status='needs_review')
    combined_issue['references'] = [{'report_id': item['scan_id'], 'issue_id': item['issues'][0]['id']} for item in inputs]
    merged = combined_reports.validate({'summary': 'Scoped access review.', 'issues': [combined_issue], 'limitations': []}, inputs)
    aws_hint, gcp_hint = merged['issues'][0]['permission_recommendations']
    assert (aws_hint['value'], aws_hint['principal'], aws_hint['report_id']) == ('iam:CreateAccessKey', arn, 'aws')
    assert aws_hint['usage_window_end'] == '2026-10-20T00:00:00Z'
    assert (gcp_hint['value'], gcp_hint['replacement'], gcp_hint['report_id']) == ('roles/editor', ['roles/viewer'], 'gcp')


@pytest.mark.parametrize('kind', ['leaks', 'image_cves'])
def test_platform_pregenerates_special_findings_and_agent_cannot_create_or_reference_them(kind):
    sources = [source('findings', 'a', kind), source('findings', 'b', kind)]
    platform = {'report': {'findings': [dict(id=i, status='FAIL', check_id='custom', scope='account/region',
                 resource_id='asset-' + i, evidence={'secret_leaks': [{'value': 'PRIVATE-SENTINEL'}]}) for i in ('a', 'b')]}}
    prebuilt = compiler.pregenerate(platform, sources)
    assert len(prebuilt['issues']) == 1 and prebuilt['issues'][0]['kind'] == kind
    assert {ref['id'] for ref in prebuilt['issues'][0]['references']} == {'a', 'b'}
    assert 'PRIVATE-SENTINEL' not in json.dumps(prebuilt)
    assert compiler.agent_sources(sources) == []
    with pytest.raises(ValueError):
        compiler.validate(report([issue([('findings', 'a'), ('findings', 'b')], kind)]), sources)
    with pytest.raises(ValueError, match='unknown_report_reference'):
        compiler.validate(report([issue([('findings', 'a')])]), sources)
    completed = compiler.complete(report(), sources, prebuilt)
    assert completed['issues'] == prebuilt['issues'] and completed['covered_count'] == 2


@pytest.mark.parametrize('case', ['missing', 'foreign', 'duplicate', 'unconfirmed', 'tentative', 'hardening'])
def test_bad_coverage_references_and_confidence_fail_closed(case):
    sources = [source('findings', 'f')]
    data = report([issue([('findings', 'f')])])
    if case == 'missing': data['issues'] = []
    if case == 'foreign': data['issues'][0]['references'][0]['id'] = 'another-tenant-finding'
    if case == 'duplicate': data['issues'].append(copy.deepcopy(data['issues'][0]))
    if case == 'unconfirmed': sources[0]['confirmed'] = False
    if case == 'tentative': data['issues'][0]['status'] = 'needs_review'
    if case == 'hardening': data['issues'][0]['kind'] = 'hardening'
    with pytest.raises(ValueError): compiler.validate(data, sources)


def test_index_keeps_uncertainty_and_recognizes_actual_native_image_and_secret_evidence():
    platform = {'report': {'findings': [
        dict(id='leak', status='FAIL', check_id='custom', evidence={'secret_leaks': [{}]}),
        dict(id='image', status='FAIL', check_id='aws.review.ecr.selected_image_vulnerabilities'),
        dict(id='gap', status='DENIED'), dict(id='pass', status='PASS')],
        'graphs': {'privesc': {'edges': [dict(id='edge')]}}},
        'least_privilege': {'items': [dict(id='lp', suggestions=[{}])]}, 'top_actions': [dict(rank=1)]}
    index = compiler.source_index(platform)
    assert {r['id'] for r in index} == {'leak', 'image', 'gap', 'edge', 'lp', '1'}
    assert {r['kind'] for r in index} == {'leaks', 'image_cves', None}
    assert not next(r for r in index if r['id'] == 'gap')['required']


def test_runner_and_backend_validate_the_same_report(tmp_path):
    sources = [source('findings', 'f')]
    (tmp_path / 'report-sources.json').write_text(json.dumps(sources))
    original = output_validation.context('findings_report', tmp_path)
    output_validation.validate('findings_report', report([issue([('findings', 'f')])]), original)
    with pytest.raises(ValueError):
        output_validation.validate('findings_report', report([]), original)


@pytest.mark.parametrize('failed', [False, True])
@pytest.mark.parametrize('with_fixed', [False, True])
def test_final_pipeline_compiles_after_analyses_without_cloud_credentials(tmp_path, monkeypatch, failed, with_fixed):
    monkeypatch.setattr(pipeline, 'Settings', lambda: SimpleNamespace(state_dir=tmp_path, identity_dir=tmp_path, auth_mode='local'))
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (SimpleNamespace(), None))
    monkeypatch.setattr('peaso.ai.providers.review_disabled', lambda *a: False)
    monkeypatch.setattr('peaso.ai.providers.resolve_access', lambda *a, **k: ('MODEL-TOKEN', 'test'))
    monkeypatch.setattr('peaso.ai.providers.credential_value', lambda _: 'MODEL-TOKEN')
    monkeypatch.setattr(pipeline.isolation, 'available', lambda: True)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: False)
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: [])
    monkeypatch.setattr('peaso.least_privilege.project', lambda *a, **k: {'items': []})
    calls = []
    def invoke(stage, platform, entries, *args, **kwargs):
        calls.append(stage)
        assert entries == []
        assert platform['network_review']['status'] == 'not_available'
        assert platform['analysis_status']['priorities'] == 'not_requested'
        if failed: raise RuntimeError('private upstream error')
        return report([issue([('findings', 'f')])])
    monkeypatch.setattr(pipeline, 'invoke_before_deadline', invoke)
    findings = [dict(id='f', provider='aws', category='hardening', check_id='custom', status='FAIL', evidence={})]
    if with_fixed:
        findings += [dict(id='leak', provider='aws', status='FAIL', category='hardening', check_id='custom',
                         evidence={'secret_leaks': [{'value': 'PRIVATE-SENTINEL'}]}),
                     dict(id='image', provider='aws', status='FAIL', category='hardening',
                          check_id='aws.review.ecr.selected_image_vulnerabilities', evidence={})]
    result = pipeline.review_scan({'provider': 'aws', 'findings': findings, 'graphs': {}}, {},
        {'categories': ['hardening'], 'ai_priorities_enabled': False}, tenant='test', artifacts=None)
    assert calls == ['findings_report']
    assert result['status'] == ('partial' if failed else 'completed')
    assert result['findings_report']['status'] == ('partial' if failed and with_fixed else 'unavailable' if failed else 'completed')
    if with_fixed:
        assert {r['kind'] for r in result['findings_report']['issues']} >= {'leaks', 'image_cves'}
        assert 'PRIVATE-SENTINEL' not in json.dumps(result['findings_report'])
    assert result['reviews']['hardening'][0]['verdict'] == 'FAIL'
    assert 'private upstream' not in json.dumps(result)


def test_page_filters_full_report_and_paginates_exclusions_independently():
    value = report([dict(issue([('findings', str(i))]), id=str(i), title='Boundary ' + str(i)) for i in range(60)],
                   [dict(reference=dict(domain='findings', id=str(i)), reason='Non-actionable') for i in range(80)])
    result = page(value, offset=0, limit=25, search='Boundary 59', exclusion_offset=50)
    assert result['total'] == 1 and result['issues'][0]['id'] == '59'
    assert len(result['exclusions']) == 25 and result['exclusions'][0]['reference']['id'] == '50'
    assert len(value['issues']) == 60


def test_report_api_is_tenant_bound_and_keeps_polling_payload_small(tmp_path):
    from fastapi.testclient import TestClient
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage import SQLiteStore, FileArtifacts
    from tests.test_peaso_api import TestIdentities
    settings = Settings(state_dir=tmp_path / 'state', identity_dir=tmp_path / 'identity', local_token='test-token-012345678901234567890')
    store, artifacts = SQLiteStore(settings.state_dir), FileArtifacts(tmp_path / 'artifacts')
    connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    collector = store.claim('collector')
    store.finish(job['id'], collector['owner'], 'collected', artifacts.put('alice', job['id'], 'snapshot', {}))
    analyzer = store.claim('analyzer')
    compiled = compiler.validate(report([issue([('findings', 'f')])]), [source('findings', 'f')])
    ai = {'findings_report': compiled, 'actions': [], 'reviews': {}}
    manifest = dict(bundle_version=1, summary={}, ai_review=artifacts.put('alice', job['id'], 'ai-review', ai),
        finding_count=1, finding_index_chunks=[{'reference': artifacts.put('alice', job['id'], 'finding-index',
        {'items': [{'id': 'f', 'resource_id': 'opaque-internal-id', 'native_resource_id': 'arn:cloud:identity::123:role/reader',
                    'evidence': {'private': 'NOT-A-LABEL'}}]}), 'count': 1}])
    ref = artifacts.put('alice', job['id'], 'manifest', manifest)
    store.finish(job['id'], analyzer['owner'], 'completed', ref)
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=TestIdentities()), base_url='http://127.0.0.1') as client:
        url = f'/api/scans/{job["id"]}'
        own = client.get(url + '/findings-report', headers={'Authorization': 'Bearer alice'})
        assert own.status_code == 200, own.text
        assert own.json()['issues'][0]['references'][0]['id'] == 'f'
        assert client.get(url + '/findings-report', headers={'Authorization': 'Bearer bob'}).status_code == 404
        assert client.get(url + '/findings-report').status_code == 401
        evidence = client.get(url + '/findings-report/evidence?finding_id=f', headers={'Authorization': 'Bearer alice'})
        assert evidence.status_code == 200, evidence.text
        assert evidence.json() == {'items': {'f': 'arn:cloud:identity::123:role/reader'}}
        assert client.get(url + '/findings-report/evidence?finding_id=f', headers={'Authorization': 'Bearer bob'}).status_code == 404
        assert client.get(url + '/findings-report/evidence?finding_id=f').status_code == 401
        assert client.get(url + '/findings-report/evidence?' + '&'.join(['finding_id=f'] * 21), headers={'Authorization': 'Bearer alice'}).status_code == 422
        counts = client.get(url + '/ai', headers={'Authorization': 'Bearer alice'}).json()['findings_report']
        assert counts == {'status': 'completed', 'total': 1}


def test_compiler_refuses_live_credentials_even_if_called_directly():
    with pytest.raises(ValueError, match='report_live_access_disabled'):
        pipeline.invoke('findings_report', {}, [{'provider': 'gcp', 'token': 'private'}], 'model', [], [], 10)


def test_prebuilt_findings_survive_ai_authentication_failure(tmp_path, monkeypatch):
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda *_: (_ for _ in ()).throw(RuntimeError('no model access')))
    findings = [dict(id='leak', status='FAIL', check_id='custom', evidence={'secret_leaks': [{}]})]
    result = pipeline.review_scan({'provider': 'aws', 'findings': findings}, {}, {}, tenant='test', artifacts=None)
    assert result['status'] == 'unavailable'
    assert result['findings_report']['issues'][0]['kind'] == 'leaks'


def test_agent_schema_and_prompt_reserve_fixed_findings_and_give_thematic_merge_examples():
    import yaml
    from pathlib import Path
    root = Path(compiler.__file__).parent
    schema = json.loads((root / 'findings_report.schema.json').read_text())
    assert schema['$defs']['AgentIssue']['properties']['kind']['enum'] == ['vulnerability', 'hardening']
    prompt = yaml.safe_load((root / 'agents/findings_report.yaml').read_text())['system_prompt']
    assert 'pre-generated' not in prompt.lower()
    assert 'leaks' not in prompt.lower() and 'cve' not in prompt.lower()
    assert not any(name in prompt for name in ('AWS', 'S3', 'RDS', 'SNS', 'Firehose', 'CloudTrail', 'DynamoDB', 'EFS', 'VPC'))
    assert 'Encryption:' in prompt and 'Logging and monitoring:' in prompt and 'Backups and recovery:' in prompt


def test_fixed_findings_are_generated_even_when_model_work_is_disabled(monkeypatch):
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda *_: pytest.fail('deterministic findings require no model setup'))
    findings = [dict(id='leak', status='FAIL', check_id='custom', evidence={'secret_leaks': [{}]}),
                dict(id='image', status='FAIL', check_id='aws.review.ecr.selected_image_vulnerabilities', evidence={})]
    result = pipeline.review_scan({'provider': 'aws', 'findings': findings}, {}, {'ai_enabled': False}, tenant='test', artifacts=None)
    assert result['status'] == 'skipped'
    assert result['findings_report']['status'] == 'completed'
    assert {r['kind'] for r in result['findings_report']['issues']} == {'leaks', 'image_cves'}


def test_agent_inputs_contain_only_assigned_observations_and_actions(tmp_path, monkeypatch):
    rows = [dict(id='leak', status='FAIL', check_id='custom', evidence={'secret_leaks': [{}]}),
            dict(id='image', status='FAIL', check_id='custom', evidence={'Image': {'digest': 'image'}, 'Vulnerabilities': [{}]}),
            dict(id='other', status='FAIL', check_id='custom', evidence={})]
    actions = [dict(rank=1, finding_ids=['leak']), dict(rank=2, finding_ids=['other', 'leak']),
               dict(rank=3, finding_ids=['image'])]
    platform = {'report': {'findings': rows}, 'source_report': {'findings': rows}, 'top_actions': actions}
    captured, files = {}, {}
    def context(root, scoped, assigned, reviews, write_json):
        captured.update(platform=scoped, assigned=assigned, reviews=reviews)
    monkeypatch.setattr('peaso.ai.briefing.build', context)
    compiler.build(tmp_path, platform, rows, [dict(finding_id=r['id']) for r in rows],
                   lambda path, value: files.update({path.name: value}))
    assert [r['id'] for r in captured['platform']['report']['findings']] == ['other']
    assert 'source_report' not in captured['platform']
    assert [r['id'] for r in captured['assigned']] == ['other']
    assert captured['reviews'] == [{'finding_id': 'other'}]
    assert {r['id'] for r in files['report-sources.json']} == {'other', '2'}
    assert [a['rank'] for a in files['top-actions.json']] == [2]
    assert 'pre-generated-issues.json' not in files
    sources = compiler.source_index(platform)
    prebuilt = compiler.pregenerate(platform, sources)
    completed = compiler.complete(report([issue([('findings', 'other'), ('actions', '2')])]), sources, prebuilt)
    assert completed['covered_count'] == completed['source_count'] == 6
    assert len(completed['issues']) == 3


def test_context_excludes_passes_unrelated_resources_and_bulk_snapshot_metadata():
    platform = {'report': {'provider': 'cloud', 'findings': [
        dict(id='fail', status='FAIL', check_id='control', resource_id='used', scope='scope'),
        dict(id='pass', status='PASS', check_id='control', resource_id='unused', scope='other'),
        dict(id='gap', status='UNKNOWN', check_id='gap', resource_id='used', scope='scope'),
        dict(id='unrelated-gap', status='UNKNOWN', check_id='gap', resource_id='unused', scope='other')],
        'graphs': {'network': {'nodes': [dict(id='n1', resource_id='used', provider='cloud'),
                                       dict(id='n2', resource_id='dependency', provider='cloud'),
                                       dict(id='n3', resource_id='unused', provider='cloud')],
                               'edges': [dict(id='e', source='n1', target='n2')]}}},
        'inventory': [dict(id='used', native_id='native-used', type='server', scope='scope', data={'depends_on': 'dependency'}),
                      dict(id='dependency', native_id='native-dependency', type='policy', scope='scope'),
                      dict(id='unused', native_id='native-unused', type='server', scope='other')],
        'snapshot_context': {'provider': 'cloud', 'metadata': {'input_mode': 'live', 'bulk': 'UNRELATED-CONTEXT'},
                             'collections': [{'irrelevant': 'UNRELATED-CONTEXT'}]}}
    scoped, sources = compiler._scoped_context(platform, compiler.source_index(platform))
    assert {r['id'] for r in scoped['report']['findings']} == {'fail', 'gap'}
    assert {r['id'] for r in sources} == {'fail', 'gap'}
    assert {r['id'] for r in scoped['inventory']} == {'used', 'dependency'}
    assert {r['id'] for r in scoped['report']['graphs']['network']['nodes']} == {'n1', 'n2'}
    assert 'UNRELATED-CONTEXT' not in json.dumps(scoped)


def test_opening_overview_is_bounded_and_all_case_groups_remain_indexed(tmp_path, monkeypatch):
    captured = {}
    complete_cases = [dict(id=str(i)) for i in range(40)]
    def context(root, scoped, assigned, reviews, write_json):
        write_json(root/'platform.json', {'sections': {'findings': complete_cases}, 'data_index': {}, 'reading_notes': []})
    monkeypatch.setattr('peaso.ai.briefing.build', context)
    compiler.build(tmp_path, {'report': {'findings': []}}, [], [],
                   lambda path, value: captured.update({path.name: value}))
    assert len(captured['platform.json']['sections']['findings']) == 12
    assert captured['platform.json']['section_totals']['findings'] == 40
    assert len(complete_cases) == 40


def test_native_image_scan_summary_and_its_action_belong_to_fixed_cve_finding(tmp_path):
    platform = {'report': {'findings': [
        dict(id='summary', status='FAIL', check_id='custom.image_no_medium_plus_findings',
             evidence={'image_digest': 'sha256:captured', 'severity_counts': {'HIGH': 7}}),
        dict(id='details', status='FAIL', check_id='custom.selected_image_vulnerabilities', evidence={}),
        dict(id='scan-config', status='FAIL', check_id='custom.image_scanning_enabled', evidence={})]},
        'top_actions': [dict(rank=3, finding_ids=['summary', 'details'])]}
    sources = compiler.source_index(platform)
    assert {r['id'] for r in sources if r['kind'] == 'image_cves'} == {'summary', 'details', '3'}
    assert {r['id'] for r in compiler.agent_sources(sources)} == {'scan-config'}
    prebuilt = compiler.pregenerate(platform, sources)
    assert len(prebuilt['issues']) == 1 and prebuilt['issues'][0]['kind'] == 'image_cves'
    assert {r['id'] for r in prebuilt['issues'][0]['references']} == {'summary', 'details', '3'}
    scoped, assigned = compiler._scoped_context(platform, sources)
    assert [r['id'] for r in scoped['report']['findings']] == ['scan-config']
    assert scoped['top_actions'] == []
    result = compiler.complete(report([issue([('findings', 'scan-config')])]), sources, prebuilt)
    assert len(result['issues']) == 2 and result['covered_count'] == 4

@pytest.mark.parametrize('combined', [False, True])
def test_report_descriptions_are_limited_to_2500_characters(combined):
    from pydantic import ValidationError
    from peaso.ai.combined_reports import CombinedIssue
    model = CombinedIssue if combined else compiler.AgentIssue
    value = issue([('findings', 'f')])
    if combined:
        value['references'] = [{'report_id': 'scan', 'issue_id': 'issue'}]
    value['description'] = 'x' * 2500
    assert len(model.model_validate(value).description) == 2500
    value['description'] += 'x'
    with pytest.raises(ValidationError):
        model.model_validate(value)

def test_fixed_findings_bound_description_without_losing_affected_evidence():
    rows = [dict(id=str(i), status='FAIL', scope='scope-' + 's' * 80 + str(i),
                 resource_id='resource-' + 'a' * 150 + str(i), check_id='custom',
                 evidence={'secret_leaks': [{}]}) for i in range(100)]
    value = compiler.pregenerate({'report': {'findings': rows}})
    assert len(value['issues']) == 1
    assert len(value['issues'][0]['description']) <= 2500
    assert len(value['issues'][0]['references']) == 100


def test_draft_source_aliases_coverage_and_assets(tmp_path):
    import subprocess
    import sys
    from peaso.ai import output_validation, report_draft

    platform = {
        'report': {'findings': [
            {'id': 'native-hardening', 'check_id': 'hardening-check', 'status': 'FAIL', 'resource_id': 'disk'},
            {'id': 'native-exposure', 'category': 'exposure', 'status': 'UNKNOWN', 'resource_id': 'workload'},
            {'id': 'native-network', 'category': 'network', 'status': 'FAIL', 'resource_id': 'workload',
             'evidence': {'source': 'ai_network_review', 'resource_ids': ['disk', 'workload']}},
        ], 'check_meta': {'hardening-check': {'category': 'hardening'}}},
        'inventory': [{'id': 'disk', 'native_id': 'disk/production'}],
        'least_privilege': {'items': [{'id': 'principal', 'principal': 'identity/worker',
                                      'exposures': [{'resource_id': 'workload'}]}]},
    }
    sources = compiler.source_index(platform)
    by_alias = {row['source_id']: row for row in sources}
    assert set(by_alias) == {'HC-001', 'EX-001', 'NW-001', 'LP-001'}
    assert by_alias['NW-001']['assets'] == ['disk/production', 'workload']
    assert by_alias['LP-001']['assets'] == ['identity/worker', 'workload']
    (tmp_path / 'report-sources.json').write_text(json.dumps(sources))
    reason = ('The captured entry refers to a retired sample workload that receives no traffic '
              'and processes no user or business data.')
    prior = {'issues': [dict(issue([('findings', 'native-hardening')]), id='prior-issue')],
             'exclusions': [{'reference': {'domain': 'findings', 'id': 'native-network'}, 'reason': reason}]}
    path = tmp_path / 'report-draft.json'
    path.write_text(json.dumps(report_draft.initial_draft(prior, sources)))

    def command(operation, *args, document=None, success=True):
        from pathlib import Path
        import os
        proc = subprocess.run([sys.executable, '-m', 'peaso.ai.report_draft', operation, *args],
                              cwd=tmp_path, input=json.dumps(document), text=True, capture_output=True,
                              env={**os.environ, 'PYTHONPATH': str(Path(compiler.__file__).parents[2])}, check=success)
        return json.loads(proc.stdout) if success else proc

    with pytest.raises(compiler.MissingReportEvidence) as error:
        compiler.validate(report_draft.candidate(json.loads(path.read_text())), sources)
    feedback = output_validation.feedback(error.value)
    assert {row['source_id'] for row in feedback['missing_references']} == {'EX-001', 'NW-001', 'LP-001'}
    rejected = command('exclude', document={'reference': {'source_id': 'NW-001'}, 'reason': reason}, success=False)
    assert 'Include confirmed findings in an issue' in rejected.stderr

    replacement = dict(issue([('findings', 'native-hardening')]), manual_affected_assets=['manual/asset', 'workload'])
    replacement['references'] = [{'source_id': alias} for alias in ('HC-001', 'NW-001', 'LP-001')]
    import sqlite3
    with sqlite3.connect(tmp_path / 'context.sqlite') as db:
        db.execute('CREATE TABLE case_members(case_domain TEXT, case_id TEXT, domain TEXT, id TEXT)')
        db.executemany('INSERT INTO case_members VALUES(?, ?, ?, ?)', [
            ('decision_findings', 'case', 'findings', 'native-hardening'),
            ('decision_findings', 'case', 'findings', 'native-network'),
            ('decision_findings', 'case', 'findings', 'native-exposure'),
            ('decision_findings', 'case', 'findings', 'native-exposure'),
            ('decision_findings', 'case', 'findings', 'unassigned'),
        ])
    replacement['references'] = [{'case_id': 'case', 'except_source_ids': ['EX-001']}, {'source_id': 'LP-001'}]
    command('update', 'prior-issue', document=replacement)
    assert [row['source_id'] for row in command('coverage')['items']] == ['EX-001']
    new_id = command('add', document=dict(replacement, references=[{'source_id': 'HC-001'}]))['id']
    command('delete', new_id)
    assert command('exclude', document={'reference': {'source_id': 'EX-001'}, 'reason': 'Too short'}, success=False).returncode
    rejected = command('exclude', document={'reference': {'case_id': 'case'}, 'reason': reason}, success=False)
    assert 'Include confirmed findings in an issue' in rejected.stderr
    assert command('exclusions')['total'] == 0
    command('exclude', document={'reference': {'case_id': 'case', 'except_source_ids': ['HC-001', 'NW-001']},
                                 'reason': reason})
    draft = json.loads(path.read_text())
    candidate = report_draft.candidate(draft)
    candidate['draft_issue_ids'] = {
        compiler._issue_id(draft['issues']['prior-issue']['references']): 'prior-issue'}
    result = compiler.complete(candidate, sources, compiler.pregenerate(platform, sources), prior)
    assert result['covered_count'] == 4
    [compiled] = result['issues']
    assert compiled['id'] == 'prior-issue'
    assert compiled['affected_assets'] == ['disk/production', 'identity/worker', 'workload']
    assert compiled['manual_affected_assets'] == ['manual/asset']


def test_fixed_reports_show_counts_and_leak_locations_without_values():
    digest = 'sha256:' + 'a' * 64
    package = {'image_digest': digest, 'vulnerability_id': 'CVE-2026-1234',
               'package': 'example-lib', 'installed_version': '1.0', 'severity': 'HIGH'}
    image = {'status': 'FAIL', 'scope': 'production', 'resource_id': 'registry/image',
             'check_id': 'cloud.selected_image_vulnerabilities'}
    leak = {'id': 'leak', 'status': 'FAIL', 'evidence': {'secret_leaks': [{
        'fingerprint': 'fingerprint', 'value': 'PRIVATE-CLEARTEXT', 'detectors': [{'rule': 'api-token'}],
        'locations': [{'resource_id': 'deployment', 'path': 'settings.yaml', 'line': 12}]}]}}
    platform = {'report': {'findings': [
        dict(image, id='detail', evidence={'image_digest': digest, 'vulnerabilities': [package, package]}),
        dict(image, id='summary', evidence={'image_digest': digest, 'severity_counts': {'HIGH': 1, 'MEDIUM': 3}}),
        leak,
    ]}}
    results = {item['kind']: item for item in compiler.pregenerate(platform)['issues']}
    cves = results['image_cves']
    assert cves['special_details'][0]['counts'] == {'critical': 0, 'high': 1, 'medium': 3}
    assert '1 high, 3 medium' in cves['description']
    assert '0 critical' not in cves['description']
    assert 'Some container images include software with known security flaws.' in cves['description']
    assert cves['affected_assets'] == ['registry/image']
    leaks = results['leaks']
    assert 'plaintext values that matched credential or secret patterns' in leaks['description']
    assert 'settings.yaml:12' in leaks['description']
    assert leaks['special_details'][0]['finding_ids'] == ['leak']
    assert leaks['affected_assets'] == ['deployment']
    assert 'PRIVATE-CLEARTEXT' not in json.dumps(results)

def test_snapshot_sharing_guardrail_reaches_report_without_owned_snapshots():
    from peaso.checks import CHECKS
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot, resources

    check_id = 'aws.ec2.prevent_public_snapshot_sharing'
    scope = '123456789012/us-east-1'
    snapshot = make_snapshot('aws', [scope], [{'type': 'ec2_regional_settings', 'scope': scope,
        'service': 'ec2', 'status': 'collected', 'items': [
            {'id': 'ec2-regional-settings', 'SnapshotBlockPublicAccessState': 'unblocked'}]},
        {'type': 'ebs_snapshot', 'scope': scope, 'service': 'ec2', 'status': 'empty', 'items': []}])
    native = evaluate_snapshot(snapshot, checks=[check_id])
    [source] = compiler.source_index({'report': native, 'inventory': resources(snapshot)})
    assert source['confirmed'] and source['required']
    assert source['assets'] == [scope + '/ec2-regional-settings']

    check = next(row for row in CHECKS if row.id == check_id)
    assert check.evaluate({'SnapshotBlockPublicAccessState': 'block-new-sharing'}, {})[0] == 'PASS'
    assert check.evaluate({'SnapshotBlockPublicAccessState': 'block-all-sharing'}, {})[0] == 'PASS'
    assert check.evaluate({'_coverage': {'SnapshotBlockPublicAccessState': {'status': 'denied'}}}, {})[0] == 'UNKNOWN'
