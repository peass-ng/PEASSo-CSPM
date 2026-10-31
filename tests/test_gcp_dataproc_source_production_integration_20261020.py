"""Production admission, hosted preflight and public native Dataproc gates."""
import inspect
import json
from types import SimpleNamespace
from fastapi import HTTPException
import pytest
from peaso import checks, engine
from peaso.checks import fixtures
from peaso.checks import gcp_dataproc_source_runtime_admission_20261020 as admission
from peaso.collectors import gcp_dataproc_source_runtime_20261020 as runtime
from peaso.server.validation import OPTIONS, validate_connector
from tests import test_gcp_dataproc_referenced_source_secret_review_20261020 as native


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    yield from native.offline.__wrapped__(monkeypatch)


def isolated_registry(monkeypatch):
    monkeypatch.setattr(checks, 'CHECKS', list(checks.CHECKS))
    monkeypatch.setattr(fixtures, 'CASES', dict(fixtures.CASES))


@pytest.mark.parametrize('profile', runtime.source.PROFILES)
@pytest.mark.parametrize('mode', ['local', 'cognito'])
def test_hosted_exact_readonly_selection(profile, mode):
    opts = {'content_secret_scans': True, runtime.source.OPTION: [native.target(profile)]}
    assert runtime.source.OPTION in OPTIONS
    validate_connector('gcp', {'method': 'token', 'token': native.AUTH}, opts, SimpleNamespace(auth_mode=mode), scopes=[native.SCOPE])


@pytest.mark.parametrize('fault', ['foreign', 'empty', 'duplicate', 'five', 'url', 'field', 'generation', 'kind', 'bad_utf8', 'wrong_provider', 'wrong_scope'])
def test_hosted_invalid_source_selection_before_auth(fault):
    t = native.target(); rows = [t]; scope = [native.SCOPE]; provider = 'gcp'
    if fault == 'foreign': t['resource'] = t['resource'].replace('/review/', '/foreign/')
    if fault == 'empty': rows = []
    if fault == 'duplicate': rows *= 2
    if fault == 'five': rows = [{**t, 'resource': t['resource'] + str(n)} for n in range(5)]
    if fault == 'url': t['resource'] = 'https://evil.invalid/' + t['resource']
    if fault == 'field': t['field'] = 'driverOutputResourceUri'
    if fault == 'generation': t['generation'] = '0'
    if fault == 'kind': t['profile'] = []
    if fault == 'bad_utf8': t['object'] = '\ud800.py'
    if fault == 'wrong_provider': provider = 'azure'
    if fault == 'wrong_scope': scope = ['projects/foreign']
    with pytest.raises(HTTPException) as exc:
        validate_connector(provider, {}, {runtime.source.OPTION: rows}, SimpleNamespace(auth_mode='local'), scopes=scope)
    assert exc.value.status_code == 422


@pytest.mark.parametrize('fault', ['missing', 'opposite', 'foreign', 'wrong_provider', 'invalid_bool'])
def test_public_preauth_named_check_requires_its_exact_source(fault):
    t = native.target('cluster' if fault == 'opposite' else 'job'); opts = {'content_secret_scans': True}; scope = [native.SCOPE]; provider = 'gcp'
    if fault != 'missing': opts[runtime.source.OPTION] = [t]
    if fault == 'foreign': scope = ['projects/foreign']
    if fault == 'wrong_provider': provider = 'azure'
    if fault == 'invalid_bool': opts['content_secret_scans'] = 'true'
    request = {'connector': {'provider': provider, 'scopes': scope, 'options': opts},
               'checks': [runtime.source.PROFILES['job']['check']] if provider == 'gcp' else []}
    with pytest.raises(ValueError): engine._request(request)


def test_install_registers_both_checks_once_with_native_cases(monkeypatch):
    isolated_registry(monkeypatch)
    before = list(checks.CHECKS)
    admission.install()
    assert checks.CHECKS == before and set(admission.CHECK_IDS) <= set(fixtures.CASES)
    assert tuple(row['id'] for row in native.consumer.DECLARATIONS) == admission.CHECK_IDS
    for meta in native.consumer.DECLARATIONS:
        actual, = [c for c in checks.CHECKS if c.id == meta['id']]
        assert actual.provider == 'gcp' and actual.allow_incomplete_failure
        assert inspect.unwrap(actual.evaluate) is getattr(native.consumer, admission.EVALUATORS[meta['id']])


@pytest.mark.parametrize('profile', runtime.source.PROFILES)
@pytest.mark.parametrize('branch', ['pass', 'fail', 'unknown', 'missing', 'malformed'])
def test_public_native_cases_api(profile, branch):
    cid = runtime.source.PROFILES[profile]['check']; fn = native.consumer.job_source if profile == 'job' else native.consumer.initialization_source
    case = fixtures.CASES[cid]; idx = case.get(branch + '_index', case['index'])
    assert fn(case[branch], idx)[0] == (branch.upper() if branch in ('pass', 'fail') else 'UNKNOWN')


@pytest.mark.parametrize('profile', runtime.source.PROFILES)
@pytest.mark.parametrize('hit', [False, True])
def test_actual_public_production_minimum_plan_and_union(monkeypatch, profile, hit):
    snap, rows, trace = native.capture(monkeypatch, profile, payload=('token=' + native.TOKEN).encode() if hit else b'mode=ready\n', real=True)
    assert native.statuses(rows) == {'FAIL' if hit else 'PASS'}
    assert snap['metadata']['collection_plan']['requirements'] == [runtime.source.PROFILES[profile]['kind']]
    assert len(trace.calls) == 9 and not trace.collector.transport.cache
    assert native.TOKEN not in json.dumps([snap, rows])


@pytest.mark.parametrize('profile', runtime.source.PROFILES)
@pytest.mark.parametrize('mode', ['inventory', 'category', 'framework', 'flag_false', 'private_spoof'])
def test_default_off_no_content_auth_even_with_internal_kind_input(monkeypatch, profile, mode):
    opts = {runtime.NAMED: list(runtime.CHECKS), '_content_secret_scan_kinds': list(runtime.KINDS)}
    named = mode == 'flag_false'
    if mode == 'flag_false': opts['content_secret_scans'] = False
    fields = {'categories': ['exposure']} if mode == 'category' else {'frameworks': ['hacktricks']} if mode == 'framework' else {}
    snap, rows, trace = native.capture(monkeypatch, profile, options=opts, named=named, request_fields=fields)
    assert native.statuses(rows) <= {'UNKNOWN', 'EMPTY'} and not trace.calls and not trace.auth
    assert not set(snap['metadata']['collection_plan']['requirements']) - runtime.KINDS


def test_final_union_scrubs_earlier_reader_cache_options_and_metadata(monkeypatch):
    def seed(snapshot, collector):
        for key in ('source_requests', 'earlier_selected_object', 'earlier_archive', 'earlier_configuration', 'earlier_log'):
            snapshot['metadata'][key] = {native.TOKEN: native.TOKEN}
        collector.transport.cache[native.TOKEN] = {'name': native.TOKEN}
        collector.options['trusted_users'] = [native.TOKEN]
    snap, rows, trace = native.capture(monkeypatch, payload=('token=' + native.TOKEN).encode(), mutate_meta=seed)
    assert native.statuses(rows) == {'FAIL'}
    assert native.TOKEN in json.dumps([snap, rows, trace.collector.transport.cache, trace.collector.options])
    assert not hasattr(trace.collector.transport, '_dataproc_source_state')


def test_full_default_plan_excludes_both_content_kinds_without_io():
    request = {'connector': {'provider': 'gcp', 'scopes': [native.SCOPE], 'options': {'content_secret_scans': True, runtime.source.OPTION: [native.target()]}}}
    assert not runtime.KINDS & set(engine.plan_collection(request))


@pytest.mark.parametrize('profile', runtime.source.PROFILES)
def test_private_kind_inventory_direct_collector_cannot_authorize(profile):
    from peaso.collectors import gcp
    p = runtime.source.PROFILES[profile]
    c = gcp.GCPCollector({'provider': 'gcp', 'scopes': [native.SCOPE], 'options': {'content_secret_scans': True, runtime.source.OPTION: [native.target(profile)], '_content_secret_scan_kinds': [p['kind']]}}, requirements=[p['kind']])
    try:
        assert not c.needed and not c.options['_content_secret_scan_kinds']
        snapshot = c.collect()
        assert not snapshot['collections'] and c.transport is None
    finally:
        c.hydration_pool.shutdown(wait=True)


def test_retained_collector_metadata_cache_is_union_redacted(monkeypatch):
    retained = []
    def seed(snapshot, collector):
        collector.collections[('previous_selected_metadata', native.SCOPE)] = {'items': [{'name': native.TOKEN}]}
        retained.append(collector)
    _, rows, _ = native.capture(monkeypatch, payload=('token=' + native.TOKEN).encode(), mutate_meta=seed)
    assert native.statuses(rows) == {'FAIL'}
    assert retained and native.TOKEN in repr(retained[0].collections)
