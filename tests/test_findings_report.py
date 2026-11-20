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
def test_special_sources_must_all_land_in_one_issue(kind):
    sources = [source('findings', 'a', kind), source('findings', 'b', kind)]
    assert len(compiler.validate(report([issue([('findings', 'a'), ('findings', 'b')], kind)]), sources)['issues']) == 1
    with pytest.raises(ValueError, match='duplicate_report_group'):
        compiler.validate(report([issue([('findings', 'a')], kind), issue([('findings', 'b')], kind)]), sources)
    with pytest.raises(ValueError, match='invalid_report_exclusion'):
        compiler.validate(report([issue([('findings', 'a')], kind)],
            [dict(reference=dict(domain='findings', id='b'), reason='Omitted')]), sources)
    with pytest.raises(ValueError, match='report_group_mismatch'):
        compiler.validate(report([issue([('findings', 'a'), ('findings', 'b')])]), sources)


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
def test_final_pipeline_compiles_after_analyses_without_cloud_credentials(tmp_path, monkeypatch, failed):
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
    result = pipeline.review_scan({'provider': 'aws', 'findings': findings, 'graphs': {}}, {},
        {'categories': ['hardening'], 'ai_priorities_enabled': False}, tenant='test', artifacts=None)
    assert calls == ['findings_report']
    assert result['status'] == ('partial' if failed else 'completed')
    assert result['findings_report']['status'] == ('unavailable' if failed else 'completed')
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
