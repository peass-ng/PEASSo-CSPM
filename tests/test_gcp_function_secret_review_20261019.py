"""Synthetic offline detectors and proposed pre-cache hook on real Transport code."""
from copy import deepcopy
from importlib.metadata import version
import inspect
import json
from types import SimpleNamespace

import pytest
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings
from peaso.collectors import gcp
from peaso.collectors import gcp_function_secret_indicators as projection
from peaso.collectors import gcp_function_secret_pairs_20261020 as paired_projection
from peaso.checks import gcp_function_secret_review_20261019 as check
from peaso.checks import CHECKS

SCOPE = 'projects/review'
NAME = SCOPE + '/locations/us-central1/functions/worker'
URL = 'https://cloudfunctions.googleapis.com/v2/' + SCOPE + '/locations/-/functions'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
OTHER = 'ghp_' + '2Yt9Ec5Zp0Ru6Wq1Aa8Kd3Vx7Mn4Bs5Hj9Lf'
HOOK = '''                if parsed.hostname == "cloudfunctions.googleapis.com" and (
                        parsed.path.endswith('/functions') or re.fullmatch(r'/v2/projects/[^/]+/locations/[^/]+/functions/[A-Za-z0-9_-]+', parsed.path)):
                    from peaso.collectors.gcp_function_secret_indicators import project_response
                    data = project_response(data, method=method, url=url, params=params, body=body,
                        scope=scope, enabled=self.options.get('function_secret_scan') is True,
                        check_cancelled=self.check_cancelled)
'''


@pytest.fixture(autouse=True)
def clear_detector_cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def raw(runtime=None, build=None):
    return {'name': NAME, 'state': 'ACTIVE',
            'serviceConfig': {'environmentVariables': runtime or {}},
            'buildConfig': {'environmentVariables': build or {}}}


def projected(row, **kwargs):
    return projection.project_response({'functions': [row]}, method='GET', url=URL, scope=SCOPE,
                                       enabled=True, **kwargs)['functions'][0]


def index(row, status='collected'):
    return {'context': {'provider': 'gcp', 'scope': SCOPE},
            'collections': {'function': [{'scope': SCOPE, 'status': status, 'items': [row]}]}}


def current_check():
    matching = [entry for entry in CHECKS if entry.id == check.CHECK_ID]
    assert len(matching) == 1
    return matching[0]


@pytest.fixture
def mock_clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


def test_default_off_preserves_existing_names_only_and_never_runs_detectors(monkeypatch):
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('default-off scan'))
    response = {'functions': [raw({'DATA': TOKEN}, {'BUILD': TOKEN})]}
    expected = gcp.sanitize(response)
    for enabled in (False, None, 'true', 1):
        actual = projection.project_response(response, method='GET', url=URL, scope=SCOPE, enabled=enabled)
        assert actual == expected
        assert TOKEN not in json.dumps(actual)
        assert check.evaluate(actual['functions'][0], index(actual['functions'][0]))[0] == 'UNKNOWN'


@pytest.mark.parametrize('change', [
    {'url': URL.replace('/review/', '/other/')},
    {'url': URL.replace('/-/', '/europe-west1/')},
    {'url': URL + '/other-function'},
    {'url': URL + '?fields=name'},
    {'params': {'fields': 'functions.name'}}, {'method': 'POST'}, {'body': {}},
    {'url': URL.replace('cloudfunctions.googleapis.com', 'example.invalid')},
])
def test_request_project_location_and_named_function_are_bound(mock_clean, change):
    options = {'method': 'GET', 'url': URL, 'scope': SCOPE, 'enabled': True, **change}
    result = projection.project_response({'functions': [raw()]}, **options)['functions'][0]
    assert check.evaluate(result, index(result))[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', ['denied', 'partial', 'unreachable', 'sanitized', 'missing_config', 'malformed_map', 'foreign', 'duplicate'])
def test_unavailable_incomplete_and_foreign_never_become_clean(mock_clean, case):
    row = raw()
    args = {}
    if case == 'denied': args['collection_status'] = 'denied'
    if case == 'partial': args['response_complete'] = False
    if case == 'sanitized': row['serviceConfig'] = {'environmentVariableNames': []}
    if case == 'missing_config': del row['buildConfig']
    if case == 'malformed_map': row['buildConfig']['environmentVariables'] = []
    if case == 'foreign': row['name'] = NAME.replace('/review/', '/foreign/')
    response = {'functions': [row]}
    if case == 'unreachable': response['unreachable'] = ['europe-west1']
    result = projection.project_response(response, method='GET', url=URL, scope=SCOPE, enabled=True, **args)['functions'][0]
    evidence = index(result)
    if case == 'duplicate': evidence['collections']['function'][0]['items'].append(deepcopy(result))
    assert check.evaluate(result, evidence)[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', ['pairs', 'value', 'total', 'page'])
def test_bounds_prevent_scanning_oversized_input(monkeypatch, case):
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('oversized input scanned'))
    row = raw()
    if case == 'pairs': row['serviceConfig']['environmentVariables'] = {f'K{i}': 'x' for i in range(projection.MAX_PAIRS + 1)}
    if case == 'value': row['serviceConfig']['environmentVariables'] = {'K': 'é' * projection.MAX_VALUE_BYTES}
    if case == 'total': row['serviceConfig']['environmentVariables'] = {f'K{i}': 'x' * projection.MAX_VALUE_BYTES for i in range(10)}
    response = {'functions': [row] * (projection.MAX_FUNCTIONS + 1 if case == 'page' else 1)}
    result = projection.project_response(response, method='GET', url=URL, scope=SCOPE, enabled=True)
    assert all(check.evaluate(r, index(r))[0] == 'UNKNOWN' for r in result['functions'])


@pytest.mark.parametrize('engine', ['kingfisher', 'trufflehog'])
def test_negative_requires_both_real_adapter_successes(monkeypatch, engine, capsys):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])
    def failed(*args): raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_' + engine, failed)
    row = projected(raw({'PUBLIC': 'production'}))
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps(row) + str(capsys.readouterr())



def test_cancelled_projection_cannot_be_negative(monkeypatch):
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('cancelled scan ran'))
    def cancelled(): raise RuntimeError(TOKEN)
    row = projected(raw(), check_cancelled=cancelled)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps(row)


def test_page_budget_is_shared_across_functions(monkeypatch, mock_clean):
    monkeypatch.setattr(projection, 'MAX_PAGE_BYTES', 45)
    response = {'functions': [raw({'DATA': 'production'}), {**raw({'DATA': 'production'}), 'name': NAME + '-other'}]}
    result = projection.project_response(response, method='GET', url=URL, scope=SCOPE, enabled=True)
    assert [check.evaluate(row, index(row))[0] for row in result['functions']] == ['PASS', 'UNKNOWN']


def test_function_get_binds_exact_name_and_reports_separate_surface_scans(mock_clean):
    response = projection.project_response(raw(), method='GET', url='https://cloudfunctions.googleapis.com/v2/' + NAME,
                                           scope=SCOPE, enabled=True)
    assert check.evaluate(response, index(response))[0] == 'PASS'
    assert [s['surface'] for s in response[projection.MARKER]['surfaces']] == ['serviceConfig', 'buildConfig']


def test_expired_page_deadline_runs_no_detectors(monkeypatch):
    monkeypatch.setattr(projection, 'MAX_PAGE_SECONDS', 0)
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('expired page scanned'))
    row = projected(raw())
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'


def test_partial_positive_is_preserved_as_redacted_projection_but_not_complete_verdict(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [(TOKEN, 'synthetic-token', 1)])
    def failed(*args): raise TimeoutError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_trufflehog', failed)
    row = projected(raw({'DATA': TOKEN}))
    assert row[projection.MARKER]['leaks']
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps(row)

def test_explicit_empty_full_maps_are_negative_but_sanitized_maps_are_not(mock_clean):
    row = raw()
    del row['serviceConfig']['environmentVariables']
    del row['buildConfig']['environmentVariables']
    safe = projected(row)
    assert check.evaluate(safe, index(safe))[0] == 'PASS'
    safe['FunctionSecretIndicators']['identity'] = NAME.replace('worker', 'foreign')
    assert check.evaluate(safe, index(safe))[0] == 'UNKNOWN'


@pytest.fixture(scope='module')
def installed_engines():
    pytest.importorskip('kingfisher_sdk')
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    assert scanning._trufflehog()


def test_real_dual_detectors_find_benign_named_values_and_merge_surfaces(installed_engines, monkeypatch, capsys):
    commands = []
    original = scanning._run
    def run(argv, payload, timeout):
        commands.append(argv)
        return original(argv, payload, timeout)
    monkeypatch.setattr(scanning, '_run', run)
    original_row = raw({'SETTING': TOKEN, 'COPY': TOKEN}, {'PUBLIC_CONFIG': TOKEN, 'OTHER': OTHER})
    before = deepcopy(original_row)
    row = projected(original_row)
    status, evidence = check.evaluate(row, index(row))
    assert original_row == before
    assert status == 'FAIL'
    assert len(evidence['secret_leaks']) == 2
    shared = next(leak for leak in evidence['secret_leaks'] if len(leak['locations']) == 3)
    assert {d['engine'] for d in shared['detectors']} == {'kingfisher', 'trufflehog'}
    assert {loc['path'] for loc in shared['locations']} == {'serviceConfig.environmentVariables', 'buildConfig.environmentVariables'}
    assert all({'--no-verification', '--no-update', '--no-verification-cache', '--force-skip-archives'} <= set(argv) for argv in commands if 'stdin' in argv)
    assert any('stdin' in argv for argv in commands)
    encoded = json.dumps([row, evidence]) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert TOKEN not in encoded and OTHER not in encoded
    base = {'provider': 'gcp', 'check_id': check.CHECK_ID, 'scope': SCOPE, 'resource_id': NAME,
            'native_resource_id': NAME, 'resource_type': 'function', 'status': status,
            'finding_type': 'secrets', 'frameworks': [], 'evidence': evidence}
    findings = deduplicate_secret_findings([base])
    assert len(findings) == 2  # one per value, never one per detector
    assert len({finding['secret_fingerprint'] for finding in findings}) == 2


def test_real_dual_detector_negative_is_bounded_observation(installed_engines):
    row = projected(raw({'STAGE': 'production', 'PUBLIC_URL': 'https://example.invalid'}, {'BUILD_MODE': 'release'}))
    status, evidence = check.evaluate(row, index(row))
    assert status == 'PASS' and evidence['complete']
    assert all(len(surface['engines']) == 2 for surface in evidence['surfaces'])
    assert not evidence['secret_leaks']


def instrumented_transport():
    """Use the installed production hook, with no in-memory source patch."""
    return gcp.Transport


@pytest.mark.parametrize('enabled', [False, True])
def test_actual_transport_installed_hook_keeps_cache_evidence_and_serialization_private(installed_engines, monkeypatch, enabled, capsys):
    calls = []
    response = {'functions': [raw({'SETTING': TOKEN}, {'BUILD_SETTING': TOKEN})]}
    class Response:
        status_code = 200
        def json(self): return deepcopy(response)
    def request(*args, **kwargs):
        calls.append((args, kwargs))
        return Response()
    transport = instrumented_transport()(SimpleNamespace(headers=lambda: {}, close=lambda: None),
                                         {'content_secret_scans': enabled, '_content_secret_scan_kinds': ['function'], 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    first, request_id = transport.request('GET', URL, scope=SCOPE)
    repeated, repeated_id = transport.request('GET', URL, scope=SCOPE)
    assert first == repeated and request_id == repeated_id and len(calls) == 1
    item = first['functions'][0]
    assert item['serviceConfig']['environmentVariableNames'] == ['SETTING']
    assert 'environmentVariables' not in item['serviceConfig']
    if enabled:
        assert item[paired_projection.MARKER]['schema'] == paired_projection.SCHEMA
    assert current_check().evaluate(item, index(item))[0] == ('FAIL' if enabled else 'UNKNOWN')
    safe_cache = [entry['data'] for entry in transport.cache.values()]
    serialized = json.dumps([first, repeated, safe_cache, transport.evidence]) + str(capsys.readouterr())
    assert TOKEN not in serialized and TOKEN not in repr(scanning._RESULTS)


def test_real_transport_denied_read_cannot_scan_or_cache_error_content(monkeypatch):
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('denied read scanned'))
    class Response:
        status_code = 403
        def json(self): return {'error': {'message': TOKEN}}
    transport = instrumented_transport()(SimpleNamespace(headers=lambda: {}, close=lambda: None),
                                         {'content_secret_scans': True, '_content_secret_scan_kinds': ['function'], 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=lambda *a, **k: Response(), close=lambda: None))
    with pytest.raises(gcp.ReadError): transport.request('GET', URL, scope=SCOPE)
    assert all('data' not in entry for entry in transport.cache.values())
    assert TOKEN not in json.dumps(transport.evidence)


@pytest.mark.parametrize('enabled', [False, True])
def test_installed_transport_to_collector_pipeline_keeps_names_and_safe_indicator(installed_engines, monkeypatch, enabled):
    collector_type = gcp.GCPCollector
    calls = []
    class Response:
        status_code = 200
        def __init__(self, data): self.data = data
        def json(self): return deepcopy(self.data)
    def request(method, url, **kwargs):
        assert method == 'GET'
        calls.append(url)
        if url == URL: return Response({'functions': [raw({'SETTING': TOKEN}, {'BUILD_SETTING': TOKEN})]})
        if url == 'https://cloudfunctions.googleapis.com/v2/' + SCOPE + '/locations':
            return Response({'locations': []})
        assert url == 'https://cloudfunctions.googleapis.com/v2/' + NAME + ':getIamPolicy'
        return Response({'bindings': []})
    transport = instrumented_transport()(SimpleNamespace(headers=lambda: {}, close=lambda: None),
                                         {'content_secret_scans': enabled, '_content_secret_scan_kinds': ['function'], 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    collector = collector_type({'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'inventories': ['function'], 'include_inherited': False, 'metrics_scopes': False, 'concurrency': 1}},
        requirements=['function'], transport=transport)
    snapshot = collector.collect()
    envelope = next(c for c in snapshot['collections'] if c['type'] == 'function')
    assert envelope['status'] == 'collected', envelope
    row, = envelope['items']
    assert row['serviceConfig']['environmentVariableNames'] == ['SETTING']
    assert row['buildConfig']['environmentVariableNames'] == ['BUILD_SETTING']
    if enabled:
        assert row[paired_projection.MARKER]['schema'] == paired_projection.SCHEMA
    assert current_check().evaluate(row, index(row))[0] == ('FAIL' if enabled else 'UNKNOWN')
    assert TOKEN not in json.dumps(snapshot) + json.dumps(transport.evidence)
    assert sorted(calls) == sorted([
        URL,
        'https://cloudfunctions.googleapis.com/v2/' + NAME + ':getIamPolicy',
        'https://cloudfunctions.googleapis.com/v2/' + SCOPE + '/locations',
    ])


def test_detected_value_repeated_in_names_and_freeform_metadata_is_redacted(installed_engines):
    row = raw({TOKEN: TOKEN}, {'STAGE': 'production'})
    row['description'] = 'Do not retain ' + TOKEN
    projected_row = projected(row)
    assert projected_row[projection.MARKER]['leaks']
    # Found values stay visible (73706ae8): the variable name keeps the detected value.
    assert TOKEN in projected_row['serviceConfig']['environmentVariableNames']
    # Free-text metadata is still not retained, independent of detection.
    assert 'description' not in projected_row
    assert projected_row['_coverage']['description'] == {'status': 'unknown', 'reason': 'free_text_not_retained'}
