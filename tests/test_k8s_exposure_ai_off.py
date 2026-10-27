"""K8s native Exposure reviews preserve downstream stage contracts."""
from types import SimpleNamespace

from peaso.ai import pipeline
from peaso.server.models import ScanCreate, SchedulePatch


def _report(provider='k8s'):
    scope = 'cluster'
    def row(ident, check, category, status='FAIL'):
        return {'id': ident, 'check_id': check, 'category': category,
                'provider': provider, 'scope': scope, 'resource_id': 'resource', 'status': status}
    return {'provider': provider, 'snapshot_id': 'fixed-snapshot', 'created_at': '2026-10-27T00:00:00Z',
            'findings': [row('hard', 'hard-check', 'hardening'),
                         row('exposure', 'exposure-check', 'exposure'),
                         row('duplicate', 'hard-check', 'exposure'),
                         row('unknown', 'unknown-check', 'exposure', 'UNKNOWN')],
            'graphs': {}}


def _ai_setup(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, 'Settings', lambda: SimpleNamespace(
        state_dir=tmp_path, identity_dir=tmp_path, auth_mode='local'))
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (SimpleNamespace(), None))
    monkeypatch.setattr('peaso.ai.providers.review_disabled', lambda *a: False)
    monkeypatch.setattr('peaso.ai.providers.resolve_access', lambda *a, **kw: ('private-token', 'test'))
    monkeypatch.setattr('peaso.ai.providers.credential_value', lambda _: 'private-token')
    monkeypatch.setattr(pipeline.isolation, 'available', lambda: True)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: False)
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 1)
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: [])
    monkeypatch.setattr('peaso.ai.network.with_findings', lambda report, findings: report)
    monkeypatch.setattr('peaso.least_privilege.project', lambda *a, **kw: {'items': []})


def test_k8s_exposure_only_completes_without_auth_or_model(monkeypatch):
    monkeypatch.setattr(pipeline, 'Settings', lambda: (_ for _ in ()).throw(AssertionError('auth started')))
    report = _report()
    result = pipeline.review_scan(report, {}, {}, tenant='tenant', artifacts=None, stages=('exposure',))
    assert result['status'] == 'completed'
    assert result['reason'] == 'k8s_exposure_native_only'
    assert [(row['finding_id'], row['verdict']) for row in result['reviews']['exposure']] == [
        ('duplicate', 'FAIL'), ('exposure', 'FAIL')]
    assert result['coverage'] == {'hardening': 1, 'exposure': 2, 'reviewed': 2, 'total': 2}
    assert report['findings'][-1]['status'] == 'UNKNOWN'


def test_k8s_native_exposure_feeds_priorities_and_ignores_old_ai_reuse(monkeypatch, tmp_path):
    _ai_setup(monkeypatch, tmp_path)
    calls = []
    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        calls.append(stage)
        if stage == 'priorities':
            assert {(row['finding_id'], row['verdict']) for row in reviews} == {
                ('hard', 'PASS'), ('duplicate', 'FAIL'), ('exposure', 'FAIL')}
            return {'actions': [], 'limitations': []}
        assert stage == 'hardening'
        return {'items': [{'finding_id': 'hard', 'verdict': 'PASS', 'reason': 'Captured control passes.'}]}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    prior = {'exposure': {'status': 'completed', 'review_fingerprint_version': 2,
                          'reviews': {'exposure': [{'finding_id': 'exposure', 'verdict': 'PASS',
                                                     'reason': 'Stale model output.'}]}}}
    result = pipeline.review_scan(_report(), {}, {}, tenant='tenant', artifacts=None,
                                  stages=('hardening', 'exposure', 'priorities'), reused_stages=prior)
    assert result['status'] == 'completed', result
    assert calls == ['hardening', 'priorities']
    assert {(row['finding_id'], row['verdict']) for row in result['reviews']['exposure']} == {
        ('duplicate', 'FAIL'), ('exposure', 'FAIL')}
    assert result['coverage'] == {'hardening': 1, 'exposure': 2, 'reviewed': 3, 'total': 3}


def test_explicit_k8s_opt_in_and_other_cloud_still_invoke_exposure(monkeypatch, tmp_path):
    _ai_setup(monkeypatch, tmp_path)
    calls = []
    def invoke(stage, platform, entries, token, findings, reviews, timeout):
        calls.append(stage)
        assert stage == 'exposure'
        return {'items': [{'finding_id': 'exposure', 'verdict': 'FAIL', 'reason': ''}]}
    monkeypatch.setattr(pipeline, 'invoke', invoke)
    for provider, selectors in [('k8s', {'ai_k8s_exposure_enabled': True}), ('aws', {})]:
        result = pipeline.review_scan(_report(provider), {}, selectors, tenant='tenant',
                                      artifacts=None, stages=('exposure',))
        assert result['status'] == 'completed', result
    assert calls == ['exposure', 'exposure']


def test_api_option_defaults_off_and_accepts_explicit_opt_in():
    request = ScanCreate(connector_id='k8s-connector')
    assert request.ai_k8s_exposure_enabled is False
    assert SchedulePatch(ai_k8s_exposure_enabled=True).ai_k8s_exposure_enabled is True
