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
        issue([('least_privilege', 'lp')], status='needs_review')],
        [dict(reference=dict(domain='privesc_edges', id='e'), reason='Conditional path lacks a required permission.')]), sources)
    assert result['covered_count'] == result['source_count'] == 4
    assert result['issues'][0]['id'].startswith('report-')
    original = report([issue([('findings', 'f'), ('actions', '1')])])
    result1 = compiler.validate(original, sources[:1] + sources[3:])
    original['issues'][0]['references'].reverse()
    assert compiler.validate(original, sources[:1] + sources[3:])['issues'][0]['id'] == result1['issues'][0]['id']


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


@pytest.mark.parametrize('case', ['missing', 'foreign', 'duplicate', 'unconfirmed', 'hardening'])
def test_bad_coverage_references_and_confidence_fail_closed(case):
    sources = [source('findings', 'f')]
    data = report([issue([('findings', 'f')])])
    if case == 'missing': data['issues'] = []
    if case == 'foreign': data['issues'][0]['references'][0]['id'] = 'another-tenant-finding'
    if case == 'duplicate': data['issues'].append(copy.deepcopy(data['issues'][0]))
    if case == 'unconfirmed': sources[0]['confirmed'] = False
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
    manifest = dict(bundle_version=1, summary={}, ai_review=artifacts.put('alice', job['id'], 'ai-review', ai))
    ref = artifacts.put('alice', job['id'], 'manifest', manifest)
    store.finish(job['id'], analyzer['owner'], 'completed', ref)
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=TestIdentities()), base_url='http://127.0.0.1') as client:
        url = f'/api/scans/{job["id"]}'
        own = client.get(url + '/findings-report', headers={'Authorization': 'Bearer alice'})
        assert own.status_code == 200, own.text
        assert own.json()['issues'][0]['references'][0]['id'] == 'f'
        assert client.get(url + '/findings-report', headers={'Authorization': 'Bearer bob'}).status_code == 404
        assert client.get(url + '/findings-report').status_code == 401
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
    assert [r['id'] for r in captured['platform']['source_report']['findings']] == ['other']
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
