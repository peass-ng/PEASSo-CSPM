"""Documented provider JSON -> transient scanners -> redacted Transport cache."""
from copy import deepcopy
import importlib
from importlib.metadata import version
import inspect
import json
from types import SimpleNamespace

import pytest
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings
from peaso.collectors import gcp
from peaso.collectors import gcp_configuration_secret_indicators as projection
from peaso.checks import gcp_configuration_secret_review_20261019 as check

SCOPE = 'projects/review'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
HOOK = '''                if parsed.hostname in ('compute.googleapis.com', 'run.googleapis.com', 'cloudbuild.googleapis.com'):
                    from peaso.collectors.gcp_configuration_secret_indicators import project_response
                    data = project_response(data, method=method, url=url, params=params, body=body,
                        scope=scope, enabled=self.options.get('content_secret_scans') is True,
                        selected_kinds=self.options.get('_content_secret_scan_kinds', []),
                        check_cancelled=self.check_cancelled)
'''


def source(kind, value='production'):
    metadata = {'items': [{'key': 'startup-script', 'value': 'export CONFIG=' + value},
                           {'key': 'shutdown-script', 'value': 'export CONFIG=' + value},
                           {'key': 'setting', 'value': value}]}
    if kind == 'instance':
        row = {'name': 'worker', 'selfLink': 'https://www.googleapis.com/compute/v1/' + SCOPE + '/zones/us-central1-a/instances/worker', 'metadata': metadata}
        return 'https://compute.googleapis.com/compute/v1/' + SCOPE + '/aggregated/instances', {'items': {'zones/us-central1-a': {'instances': [row]}}}
    if kind == 'instance_template':
        row = {'name': 'worker', 'selfLink': 'https://www.googleapis.com/compute/v1/' + SCOPE + '/global/instanceTemplates/worker', 'properties': {'metadata': metadata}}
        return 'https://compute.googleapis.com/compute/v1/' + SCOPE + '/aggregated/instanceTemplates', {'items': {'global': {'instanceTemplates': [row]}}}
    if kind == 'project':
        return 'https://compute.googleapis.com/compute/v1/' + SCOPE, {'name': 'review', 'commonInstanceMetadata': metadata}
    if kind.startswith('cloudrun'):
        segment = 'services' if kind == 'cloudrun_service' else 'jobs'
        template = {'containers': [{'name': 'worker', 'image': 'example.invalid/image',
                     'env': [{'name': 'SETTING', 'value': value}, {'name': 'MANAGED', 'valueSource': {'secretKeyRef': {'secret': 'managed-reference', 'version': 'latest'}}}],
                     'args': ['--config=' + value], 'command': ['printf', value]}]}
        row = {'name': SCOPE + '/locations/us-central1/' + segment + '/worker',
               'template': template if kind == 'cloudrun_service' else {'template': template}}
        return 'https://run.googleapis.com/v2/' + SCOPE + '/locations/us-central1/' + segment, {segment: [row]}
    build = {'substitutions': {'_SETTING': value}, 'options': {'env': ['SETTING=' + value]},
             'steps': [{'id': 'step', 'name': 'example.invalid/builder', 'env': ['SETTING=' + value], 'args': ['--config=' + value]},
                       {'id': 'script-step', 'name': 'example.invalid/builder', 'script': 'export CONFIG=' + value}]}
    if kind == 'cloudbuild_trigger':
        row = {'id': '11111111-1111-1111-1111-111111111111', 'resourceName': SCOPE + '/locations/us-central1/triggers/11111111-1111-1111-1111-111111111111',
               'name': 'worker', 'substitutions': {'_TRIGGER': value}, 'build': build}
        segment = 'triggers'
    else:
        row = {'name': SCOPE + '/locations/us-central1/builds/11111111-1111-1111-1111-111111111111',
               'id': '11111111-1111-1111-1111-111111111111', 'projectId': 'review', 'status': 'SUCCESS', **build}
        segment = 'builds'
    return 'https://cloudbuild.googleapis.com/v1/' + SCOPE + '/locations/us-central1/' + segment, {segment: [row]}


def unwrap(kind, response):
    if kind == 'instance': return response['items']['zones/us-central1-a']['instances'][0]
    if kind == 'instance_template': return response['items']['global']['instanceTemplates'][0]
    if kind == 'project': return {'name': SCOPE, 'computeConfig': response}
    return response[{'cloudrun_service': 'services', 'cloudrun_job': 'jobs', 'cloudbuild_trigger': 'triggers', 'cloudbuild_build': 'builds'}[kind]][0]


def index(kind, row, status='collected'):
    return {'context': {'provider': 'gcp', 'scope': SCOPE},
            'collections': {kind: [{'type': kind, 'scope': SCOPE, 'status': status, 'items': [row]}]}}


def project(kind, value='production', **kwargs):
    url, response = source(kind, value)
    options = {'method': 'GET', 'url': url, 'scope': SCOPE, 'enabled': True, 'selected_kinds': [kind], **kwargs}
    return unwrap(kind, projection.project_response(response, **options))


@pytest.fixture(autouse=True)
def isolate_cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


@pytest.fixture(scope='module')
def real():
    pytest.importorskip('kingfisher_sdk')
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    assert scanning._trufflehog()


@pytest.mark.parametrize('kind', projection.KINDS)
@pytest.mark.parametrize('value,expected', [('production', 'PASS'), (TOKEN, 'FAIL')])
def test_real_native_schemas_dual_detector_results_and_value_dedup(real, kind, value, expected):
    row = project(kind, value)
    status, evidence = check.evaluate(row, index(kind, row), kind)
    assert status == expected, (kind, row)
    assert evidence['complete']
    if expected == 'FAIL':
        assert len(evidence['secret_leaks']) == 1
        leak = evidence['secret_leaks'][0]
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
        assert len(leak['locations']) >= 3
    assert TOKEN not in json.dumps([row, evidence]) + repr(scanning._RESULTS)


@pytest.mark.parametrize('kind', projection.KINDS)
@pytest.mark.parametrize('gate', ['disabled', 'unselected', 'truthy'])
def test_explicit_opt_in_and_named_selection_both_required(monkeypatch, kind, gate):
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('unselected detector'))
    row = project(kind, TOKEN, enabled=gate != 'disabled' if gate != 'truthy' else 'true', selected_kinds=[] if gate == 'unselected' else [kind])
    assert TOKEN not in json.dumps(row)
    assert check.evaluate(row, index(kind, row), kind)[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', projection.KINDS)
@pytest.mark.parametrize('case', ['masked', 'foreign', 'partial', 'cancelled', 'deadline', 'missing', 'oversized', 'denied', 'duplicate'])
def test_missing_denied_foreign_bounds_and_cancelled_are_unknown(clean, monkeypatch, kind, case):
    url, response = source(kind)
    raw = unwrap(kind, response)
    raw = raw['computeConfig'] if kind == 'project' else raw
    options = {'enabled': True, 'selected_kinds': [kind], 'scope': SCOPE, 'method': 'GET', 'url': url}
    if case == 'masked': options['params'] = {'fields': 'name'}
    if case == 'foreign': options['scope'] = 'projects/foreign'
    if case == 'partial': options['response_complete'] = False
    if case == 'cancelled':
        def cancelled(): raise RuntimeError(TOKEN)
        options['check_cancelled'] = cancelled
    if case == 'deadline': monkeypatch.setattr(projection, 'MAX_PAGE_SECONDS', 0)
    if case == 'missing':
        field = {'instance': 'metadata', 'instance_template': 'properties', 'project': 'commonInstanceMetadata', 'cloudrun_service': 'template', 'cloudrun_job': 'template', 'cloudbuild_trigger': 'build', 'cloudbuild_build': 'steps'}[kind]
        del raw[field]
    if case == 'oversized':
        url, response = source(kind, 'z' * (projection.MAX_VALUE_BYTES + 1))
    row = unwrap(kind, projection.project_response(response, **options))
    context = index(kind, row, 'denied' if case == 'denied' else 'collected')
    if case == 'duplicate': context['collections'][kind][0]['items'].append(deepcopy(row))
    assert check.evaluate(row, context, kind)[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps(row)


@pytest.mark.parametrize('failed_engine', ['kingfisher', 'trufflehog'])
def test_failed_detector_cannot_prove_absence(clean, monkeypatch, failed_engine):
    def failed(*args): raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_' + failed_engine, failed)
    row = project('instance')
    assert check.evaluate(row, index('instance', row), 'instance')[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps(row)


def test_one_finding_per_value_across_all_seven_services_and_both_tools(real):
    findings = []
    for kind in projection.KINDS:
        row = project(kind, TOKEN)
        status, evidence = check.evaluate(row, index(kind, row), kind)
        assert status == 'FAIL'
        findings.append({'provider': 'gcp', 'scope': SCOPE, 'check_id': projection.IDS[kind], 'resource_id': kind,
            'native_resource_id': kind, 'resource_type': kind, 'status': status, 'frameworks': [], 'evidence': evidence})
    result = deduplicate_secret_findings(findings)
    assert len(result) == 1
    assert len(result[0]['linked_check_ids']) == 7
    assert len(result[0]['evidence']['secret_leaks'][0]['locations']) >= 21
    assert TOKEN not in json.dumps(result)


def transport_type():
    return gcp.Transport


@pytest.mark.parametrize('kind', projection.KINDS)
def test_real_transport_mock_http_hook_redacts_before_cache_and_serialization(real, monkeypatch, kind, capsys):
    url, raw = source(kind, TOKEN)
    calls = []
    class Response:
        status_code = 200
        def json(self): return deepcopy(raw)
    def request(method, requested_url, **kwargs):
        assert method == 'GET' and requested_url == url
        calls.append(requested_url)
        return Response()
    transport = transport_type()(SimpleNamespace(headers=lambda: {}, close=lambda: None),
        {'content_secret_scans': True, '_content_secret_scan_kinds': [kind], 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    first, request_id = transport.request('GET', url, scope=SCOPE)
    repeated, repeated_id = transport.request('GET', url, scope=SCOPE)
    assert len(calls) == 1 and request_id == repeated_id and first == repeated
    row = unwrap(kind, first)
    assert check.evaluate(row, index(kind, row), kind)[0] == 'FAIL'
    cached = [entry['data'] for entry in transport.cache.values()]
    assert TOKEN not in json.dumps([first, cached, transport.evidence]) + str(capsys.readouterr())


def test_remote_references_and_ambiguous_cloud_run_union_are_unknown(clean):
    url, response = source('cloudbuild_trigger')
    row = response['triggers'][0]
    del row['build'];row['filename'] = 'cloudbuild.yaml'
    item = unwrap('cloudbuild_trigger', projection.project_response(response, method='GET', url=url, scope=SCOPE,
        enabled=True, selected_kinds=['cloudbuild_trigger']))
    assert check.evaluate(item, index('cloudbuild_trigger', item), 'cloudbuild_trigger')[0] == 'UNKNOWN'
    url, response = source('cloudrun_service')
    response['services'][0]['template']['containers'][0]['env'][0]['valueSource'] = {'secretKeyRef': {'secret': 's', 'version': 'latest'}}
    item = unwrap('cloudrun_service', projection.project_response(response, method='GET', url=url, scope=SCOPE,
        enabled=True, selected_kinds=['cloudrun_service']))
    assert check.evaluate(item, index('cloudrun_service', item), 'cloudrun_service')[0] == 'UNKNOWN'


def test_aggregate_group_binding_and_partial_warning_are_not_clean(clean):
    url, response = source('instance')
    response['items']['zones/foreign-zone'] = response['items'].pop('zones/us-central1-a')
    item = projection.project_response(response, method='GET', url=url, scope=SCOPE, enabled=True, selected_kinds=['instance'])['items']['zones/foreign-zone']['instances'][0]
    assert check.evaluate(item, index('instance', item), 'instance')[0] == 'UNKNOWN'
    url, response = source('instance')
    response['items']['zones/us-central1-a']['warning'] = {'code': 'UNREACHABLE'}
    item = unwrap('instance', projection.project_response(response, method='GET', url=url, scope=SCOPE, enabled=True, selected_kinds=['instance']))
    assert check.evaluate(item, index('instance', item), 'instance')[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', ['pairs', 'resource_bytes', 'page_bytes', 'resources'])
def test_global_bounds_reject_before_detectors(monkeypatch, case):
    url, response = source('instance')
    row = response['items']['zones/us-central1-a']['instances'][0]
    if case == 'pairs': row['metadata']['items'] = [{'key': 'k' + str(i), 'value': 'x'} for i in range(projection.MAX_PARTS + 1)]
    if case == 'resource_bytes': row['metadata']['items'] = [{'key': 'k' + str(i), 'value': 'x' * projection.MAX_VALUE_BYTES} for i in range(5)]
    if case == 'page_bytes': monkeypatch.setattr(projection, 'MAX_PAGE_BYTES', 1)
    if case == 'resources': response['items']['zones/us-central1-a']['instances'] = [deepcopy(row) for _ in range(projection.MAX_RESOURCES + 1)]
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('oversized input scanned'))
    result = projection.project_response(response, method='GET', url=url, scope=SCOPE, enabled=True, selected_kinds=['instance'])
    assert all(check.evaluate(item, index('instance', item), 'instance')[0] == 'UNKNOWN'
               for item in result['items']['zones/us-central1-a']['instances'])


def test_literal_container_configuration_never_dereferences_secret_manager(clean, monkeypatch):
    url, response = source('cloudrun_service')
    env = response['services'][0]['template']['containers'][0]['env']
    env[0] = {'name': 'EMPTY'}  # documented omitted literal default
    calls = []
    original = projection.scan_content
    def scan(payload, path, **kwargs):
        calls.append(payload)
        return original(payload, path, **kwargs)
    monkeypatch.setattr(projection, 'scan_content', scan)
    result = projection.project_response(response, method='GET', url=url, scope=SCOPE, enabled=True, selected_kinds=['cloudrun_service'])
    assert check.evaluate(result['services'][0], index('cloudrun_service', result['services'][0]), 'cloudrun_service')[0] == 'PASS'
    assert all(b'managed-reference' not in payload and b'latest' not in payload for payload in calls)


@pytest.mark.parametrize('kind', projection.KINDS)
def test_full_native_collector_pipeline_with_installed_marker_retention(real, monkeypatch, kind):
    from peaso.collectors import gcp_history
    url, raw = source(kind, TOKEN)
    calls = []
    class Response:
        status_code = 200
        def __init__(self, data): self.data = data; self.content = json.dumps(data).encode()
        def json(self): return deepcopy(self.data)
    def request(method, requested_url, **kwargs):
        assert method == 'GET'
        calls.append(requested_url)
        if requested_url == url: return Response(raw)
        if requested_url.endswith(':getIamPolicy'): return Response({'bindings': []})
        if requested_url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            return Response({'name': SCOPE, 'projectId': 'review', 'state': 'ACTIVE'})
        if requested_url.endswith('/locations/global/triggers'): return Response({'triggers': []})
        if requested_url.endswith('/locations/global/builds'): return Response({'builds': []})
        pytest.fail('unexpected native request ' + requested_url)
    transport = transport_type()(SimpleNamespace(headers=lambda: {}, close=lambda: None),
        {'content_secret_scans': True, '_content_secret_scan_kinds': [kind], 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'inventories': [kind], 'include_inherited': False, 'metrics_scopes': False, 'concurrency': 1,
        'compute_resource_iam': False, 'cloudrun_locations': ['us-central1'], 'cloudbuild_locations': ['us-central1']}},
        requirements=[kind], transport=transport)
    snapshot = collector.collect()
    envelope = next(c for c in snapshot['collections'] if c['type'] == kind)
    assert envelope['status'] == 'collected', envelope
    assert len(envelope['items']) == 1
    row = envelope['items'][0]
    assert check.evaluate(row, index(kind, row), kind)[0] == 'FAIL', row
    assert TOKEN not in json.dumps(snapshot) + json.dumps(transport.evidence)
    assert calls and len(calls) <= 3


def test_denied_mock_http_cannot_scan_or_cache_error_content(monkeypatch):
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('denied response scanned'))
    class Response:
        status_code = 403
        def json(self): return {'error': {'message': TOKEN}}
    url, _ = source('cloudbuild_build')
    transport = transport_type()(SimpleNamespace(headers=lambda: {}, close=lambda: None),
        {'content_secret_scans': True, '_content_secret_scan_kinds': ['cloudbuild_build'], 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=lambda *a, **k: Response(), close=lambda: None))
    with pytest.raises(gcp.ReadError): transport.request('GET', url, scope=SCOPE)
    assert all('data' not in entry for entry in transport.cache.values())
    assert TOKEN not in json.dumps(transport.evidence)


def test_cloudbuild_numeric_project_alias_batch_matches_serial(real, monkeypatch):
    from peaso import secret_scanning_batch as batch
    from peaso import secret_scan_clean
    url, response = source('cloudbuild_build', TOKEN)
    first = response['builds'][0]
    first['name'] = first['name'].replace(SCOPE, 'projects/123456789012', 1)
    second = deepcopy(first)
    second['id'] = '22222222-2222-2222-2222-222222222222'
    second['name'] = second['name'].replace(first['id'], second['id'])
    second['substitutions']['_SETTING'] = 'production'
    second['options']['env'] = ['SETTING=production']
    second['steps'] = [{'id': 'step', 'name': 'example.invalid/builder', 'env': ['SETTING=production']}]
    response['builds'].append(second)
    options = {'method': 'GET', 'url': url, 'scope': SCOPE, 'enabled': True,
               'selected_kinds': ['cloudbuild_build']}
    original = batch._prepare_trufflehog_batch
    prepared = []
    def record(items, timeout):
        result = original(items, timeout)
        prepared.append(result is not None)
        return result
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', record)
    actual = projection.project_response(deepcopy(response), **options)
    monkeypatch.setattr(batch, '_prepare_trufflehog_batch', lambda items, timeout: None)
    scanning._RESULTS.clear()
    secret_scan_clean._CLEAN.clear()
    serial = projection.project_response(deepcopy(response), **options)
    assert actual == serial
    assert [check.evaluate(row, index('cloudbuild_build', row), 'cloudbuild_build')[0]
            for row in actual['builds']] == ['FAIL', 'PASS']
    assert TOKEN not in json.dumps(actual)
    if __import__('sys').platform == 'linux':
        assert prepared == [True]
    foreign = deepcopy(response)
    foreign['builds'][0]['projectId'] = 'foreign'
    refused = projection.project_response(foreign, **options)['builds'][0]
    assert check.evaluate(refused, index('cloudbuild_build', refused), 'cloudbuild_build')[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['instance', 'instance_template'])
def test_compute_native_nonaggregated_list_and_exact_get_bindings(clean, kind):
    _, response = source(kind)
    row = unwrap(kind, response)
    link = row['selfLink'].replace('https://www.googleapis.com', 'https://compute.googleapis.com')
    parent = link.rsplit('/', 1)[0]
    listed = projection.project_response({'items': [row]}, method='GET', url=parent, scope=SCOPE,
        enabled=True, selected_kinds=[kind])['items'][0]
    assert check.evaluate(listed, index(kind, listed), kind)[0] == 'PASS'
    fetched = projection.project_response(row, method='GET', url=link, scope=SCOPE,
        enabled=True, selected_kinds=[kind])
    assert check.evaluate(fetched, index(kind, fetched), kind)[0] == 'PASS'
    wrong = projection.project_response(row, method='GET', url=link + '-foreign', scope=SCOPE,
        enabled=True, selected_kinds=[kind])
    assert check.evaluate(wrong, index(kind, wrong), kind)[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['instance', 'instance_template', 'project'])
@pytest.mark.parametrize('value', ['true', 'false', 'True', 'False', 'TRUE', 'FALSE', '1', '0', ' true '])
def test_safe_compute_metadata_settings_and_native_provenance_are_preserved(kind, value):
    url, response = source(kind)
    row = unwrap(kind, response)
    raw = row['computeConfig'] if kind == 'project' else row
    parent = raw['properties'] if kind == 'instance_template' else raw
    field = 'commonInstanceMetadata' if kind == 'project' else 'metadata'
    parent[field] = {'fingerprint': 'native-opaque-fingerprint', 'items': [
        {'key': key, 'value': value} for key in ('enable-oslogin', 'enable-oslogin-2fa', 'block-project-ssh-keys', 'serial-port-enable', 'disable-legacy-endpoints')]}
    raw['_provenance'] = {'representation': 'full', 'scope': SCOPE, 'source_requests': ['request-1']}
    baseline = gcp.sanitize(response)
    result = projection.project_response(response, method='GET', url=url, scope=SCOPE, enabled=False)
    assert result == baseline


@pytest.mark.parametrize('kind', projection.KINDS)
def test_detected_value_repeated_in_freeform_metadata_cannot_leak(real, kind):
    url, response = source(kind, TOKEN)
    # A second occurrence outside the scanned literal fields must not survive
    # as otherwise allowed free-form resource metadata.
    response['description'] = 'Do not retain ' + TOKEN
    result = projection.project_response(response, method='GET', url=url, scope=SCOPE,
        enabled=True, selected_kinds=[kind])
    assert TOKEN not in json.dumps(result)
    assert 'description' not in result
    assert result['_coverage']['description'] == {'status': 'unknown', 'reason': 'free_text_not_retained'}
