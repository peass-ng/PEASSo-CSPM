"""Actual collector -> native mocked streaming HTTP -> pure job callbacks.

Installed collector scheduling runs unchanged; credentials and native HTTP are
mocked, with socket/DNS fail-closed guards. No scheduling fallback is injected.
"""
from copy import deepcopy
import io
import json
import socket
from types import SimpleNamespace

import pytest
import requests

from peaso.collectors import gcp
from peaso.collectors import gcp_job_literal_secret_indicators as adapter
from peaso.checks import gcp_job_literal_secret_review_20261019 as check
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings

SCOPE = 'projects/review'
REGION = 'us-central1'
UUID = '12345678-1234-1234-1234-123456789abc'
TOKEN = 'ghp_' + '7mq2zr9wl4cv8nk1sf6ah3jp5ud0xb2ye9rt'


def native(kind, positive=False):
    value = TOKEN if positive else 'production'
    # Google label values permit lowercase letters/digits/underscores; keep
    # synthetic responses native rather than inventing Job.description fields.
    common = {'labels': {'stage': value}}
    if kind == adapter.DATAFLOW:
        return {**common, 'id': 'job-123', 'projectId': 'review', 'location': REGION,
            'name': 'worker-production', 'currentState': 'JOB_STATE_RUNNING',
            'environment': {'sdkPipelineOptions': {'options': {'api_token': value, 'description': value}},
                            'workerPools': [{'metadata': {'API_TOKEN': value}}]}}
    if kind == adapter.BATCH:
        name = 'projects/10001/locations/' + REGION + '/jobs/job-123'
        return {**common, 'name': name, 'uid': UUID, 'taskGroups': [{
            'name': name + '/taskGroups/group0',
            'taskSpec': {'environment': {'variables': {'API_TOKEN': value}},
                'runnables': [{'script': {'text': 'export API_TOKEN=' + value},
                               'environment': {'variables': {'OTHER': value}}}]},
            'taskEnvironments': [{'variables': {'STAGE': value}}]}]}
    if kind == adapter.CLUSTER:
        return {**common, 'projectId': 'review', 'clusterName': 'worker', 'clusterUuid': UUID,
            'config': {'softwareConfig': {'properties': {'spark:spark.executorEnv.API_TOKEN': value}},
                'gceClusterConfig': {'metadata': {'API_TOKEN': value}},
                'encryptionConfig': {'gcePdKmsKeyName': 'projects/review/locations/global/keyRings/r/cryptoKeys/k'},
                'initializationActions': [{'executableFile': 'gs://selected-bucket/init.sh'}]}}
    return {**common, 'reference': {'projectId': 'review', 'jobId': 'job-123'}, 'jobUuid': UUID,
            'pysparkJob': {'args': ['--api-token', value], 'properties': {'spark.token': value},
                           'mainPythonFileUri': 'gs://selected-bucket/main.py'}}


class Raw:
    def __init__(self, payload): self.stream = io.BytesIO(payload)
    def read(self, amount, *, decode_content):
        assert decode_content is False
        return self.stream.read(amount)


class Response:
    def __init__(self, url, params, data, status=200):
        payload = json.dumps(data).encode()
        self.url = requests.Request('GET', url, params=params).prepare().url
        self.history = []; self.status_code = status; self.closed = False
        self.raw = Raw(payload)
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(payload))}
    def close(self): self.closed = True


def collect_native_pipeline(monkeypatch, kind, row=None, *, case=None, options=None, lowercase_auth=False):
    def forbidden_network(*args, **kwargs):
        raise AssertionError('Real socket/DNS access is forbidden in native fixture tests')
    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, forbidden_network)
    monkeypatch.setattr(socket, 'create_connection', forbidden_network)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden_network)
    row = deepcopy(row if row is not None else native(kind))
    opts = {'inventories': ['project', kind], 'include_inherited': False, 'metrics_scopes': False,
            'concurrency': 1, 'retries': 0, 'content_secret_scans': True,
            '_content_secret_scan_kinds': [kind], 'dataflow_regions': [REGION],
            'batch_regions': [REGION], 'dataproc_regions': [REGION], **(options or {})}
    auth_calls, native_calls, responses = [], [], []
    def headers():
        auth_calls.append(True)
        return {'authorization' if lowercase_auth else 'Authorization': 'Bearer fake-token'}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), opts)
    class Metadata:
        status_code = 200
        headers = {}
        def __init__(self, data):
            self.data = data
            self.content = json.dumps(data).encode("utf-8")
        def json(self): return deepcopy(self.data)
    def normal_request(method, url, **kwargs):
        assert method == 'GET'
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            return Metadata({'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'})
        assert url == 'https://compute.googleapis.com/compute/v1/' + SCOPE
        return Metadata({'name': 'review', 'id': '10001'})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=normal_request))
    class Session:
        closed = False
        trust_env = True
        auth = None
        def request(self, method, url, **kwargs):
            assert method == 'GET' and kwargs['stream'] and kwargs['allow_redirects'] is False
            assert kwargs['headers']['Accept-Encoding'] == 'identity'
            assert not self.trust_env and self.auth is None
            native_calls.append((url, kwargs))
            get = kind == adapter.DATAFLOW and '/jobs/' in url
            if get:
                assert kwargs['params'] == {'view': 'JOB_VIEW_ALL'}
                data = deepcopy(row)
                data['id'] = url.rsplit('/', 1)[1]
            elif kind == adapter.DATAFLOW:
                assert kwargs['params']['view'] == 'JOB_VIEW_SUMMARY'
                data = {'jobs': [{k: row[k] for k in ('id', 'projectId', 'location', 'name', 'currentState') if k in row}], 'failedLocation': []}
                if case in ('multi_get', 'failed_get'):
                    another = deepcopy(data['jobs'][0]); another['id'] = 'job-456'
                    data['jobs'].append(another)
            else:
                data = {'clusters' if kind == adapter.CLUSTER else 'jobs': [row]}
                if kind in (adapter.BATCH, adapter.DATAPROC): data['unreachable'] = []
            if case == 'partial': data = {**data, 'failedLocation' if kind == adapter.DATAFLOW else 'unreachable': ['other']}
            if case == 'cursor': data = {'jobs': [], 'nextPageToken': 'cursor-' + str(len(native_calls))}
            if case == 'resource_count': data = {'jobs': [deepcopy(row) for _ in range(adapter.MAX_ROWS + 1)]}
            if case == 'duplicate' and not get: data = {'clusters' if kind == adapter.CLUSTER else 'jobs': [row, deepcopy(row)]}
            status = 403 if case == 'denied' else 302 if case == 'redirect' else 200
            if case == 'failed_get' and get and data['id'] == 'job-456': status = 403
            response = Response(url, kwargs['params'], data, status)
            if case == 'truncated': response.raw = Raw(b'{')
            if case == 'encoding': response.headers['Content-Encoding'] = 'gzip'
            if case == 'wire_oversize': response.headers['Content-Length'] = str(adapter.MAX_HTTP_BYTES + 1)
            if case == 'response_url': response.url = 'https://example.invalid/'
            if case == 'cancel': transport.options['_cancel_check'] = lambda: True
            responses.append(response)
            return response
        def close(self): self.closed = True
    session = Session()
    # Installed production reader uses this mocked HTTP session. Socket and DNS
    # operations fail closed if any future path escapes the mock boundary.
    monkeypatch.setattr(requests, 'Session', lambda: session)
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts},
                                requirements=['project', kind], transport=transport)
    snapshot = collector.collect()
    collections = {}
    for envelope in snapshot['collections']: collections.setdefault(envelope['type'], []).append(envelope)
    index = {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': collections}
    envelope = collections[kind][0]
    return envelope, index, snapshot, native_calls, responses, transport, session


@pytest.fixture(autouse=True)
def cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


@pytest.mark.parametrize('kind', adapter.KINDS)
def test_native_full_pipeline_clean_and_reference_scope(monkeypatch, clean, kind):
    envelope, context, snapshot, calls, responses, transport, session = collect_native_pipeline(monkeypatch, kind)
    row, = envelope['items']
    assert check.evaluate(row, context, kind)[0] == 'PASS'
    assert len(calls) == (2 if kind == adapter.DATAFLOW else 1)
    assert all(r.closed for r in responses) and session.closed
    assert all('url' not in e for e in transport.evidence if e.get('kind') == kind)
    assert all('JobLiteralSecretIndicators' not in str(v) for v in transport.cache.values())
    if kind == adapter.CLUSTER:
        assert 'properties' not in row['config']['softwareConfig']
        assert row['config']['encryptionConfig']['gcePdKmsKeyName'].endswith('/cryptoKeys/k')
    if kind == adapter.DATAFLOW:
        assert calls[-1][1]['params'] == {'view': 'JOB_VIEW_ALL'}
    else:
        assert row['_coverage'][adapter.MARKER]['source_requests'] == envelope['source_requests']


@pytest.mark.parametrize('case', ['multi_get', 'failed_get'])
def test_each_dataflow_item_owns_list_and_exact_full_get_even_when_denied(monkeypatch, clean, case):
    envelope, context, _, calls, _, transport, _ = collect_native_pipeline(monkeypatch, adapter.DATAFLOW, case=case)
    receipts = [e for e in transport.evidence if e.get('kind') == adapter.DATAFLOW]
    assert len(calls) == len(receipts) == 3
    for row in envelope['items']:
        own = next(e for e in receipts[1:] if e['resource_id'] == row[adapter.IDENTITY])
        expected = {receipts[0]['id'], own['id']}
        assert set(row['_coverage'][adapter.MARKER]['source_requests']) == expected
        assert set(row['_provenance']['source_requests']) == expected
        assert check.evaluate(row, context, adapter.DATAFLOW)[0] == ('UNKNOWN' if own['http_status'] == 403 else 'PASS')


@pytest.mark.parametrize('options', [{'content_secret_scans': False}, {'content_secret_scans': 'true'},
                                     {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': ['other']}])
def test_default_or_missing_named_kind_makes_zero_content_calls(monkeypatch, options):
    if isinstance(options.get('content_secret_scans'), str):
        assert adapter.enabled(options, adapter.DATAFLOW) is False
        with pytest.raises(ValueError, match='boolean'):
            collect_native_pipeline(monkeypatch, adapter.DATAFLOW, options=options)
        return
    envelope, _, _, calls, responses, _, session = collect_native_pipeline(monkeypatch, adapter.DATAFLOW, options=options)
    assert calls == responses == [] and not session.closed
    assert envelope['status'] != 'collected' and not envelope['items']


@pytest.mark.parametrize('case', ['denied', 'redirect', 'partial', 'cursor', 'duplicate', 'truncated',
                                 'encoding', 'wire_oversize', 'response_url', 'cancel', 'resource_count'])
def test_native_partial_denied_integrity_and_bounds_never_pass(monkeypatch, clean, case):
    envelope, context, snapshot, calls, responses, _, session = collect_native_pipeline(monkeypatch, adapter.BATCH, case=case)
    assert not envelope['items'] or all(check.evaluate(row, context, adapter.BATCH)[0] == 'UNKNOWN' for row in envelope['items'])
    assert len(calls) <= adapter.MAX_PAGES and all(r.closed for r in responses) and session.closed
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('kind', [adapter.BATCH, adapter.CLUSTER, adapter.DATAPROC])
def test_foreign_native_owner_cannot_produce_clean_configuration(monkeypatch, clean, kind):
    row = native(kind)
    if kind == adapter.BATCH: row['name'] = row['name'].replace('projects/10001/', 'projects/other/')
    if kind == adapter.CLUSTER: row['projectId'] = 'other'
    if kind == adapter.DATAPROC: row['reference']['projectId'] = 'other'
    envelope, context, *_ = collect_native_pipeline(monkeypatch, kind, row)
    assert not envelope['items'] or all(check.evaluate(item, context, kind)[0] == 'UNKNOWN' for item in envelope['items'])


def test_strict_region_row_scan_budget_and_expired_deadline(monkeypatch, clean):
    envelope, _, _, calls, *_ = collect_native_pipeline(monkeypatch, adapter.BATCH,
        options={'batch_regions': ['-']})
    assert calls == [] and envelope['status'] != 'collected'
    monkeypatch.setattr(adapter, 'MAX_SCAN_BYTES', 1)
    envelope, context, *_ = collect_native_pipeline(monkeypatch, adapter.BATCH)
    row, = envelope['items']
    assert check.evaluate(row, context, adapter.BATCH)[0] == 'UNKNOWN'
    monkeypatch.setattr(adapter, 'MAX_SCAN_BYTES', 1048576)
    monkeypatch.setattr(adapter, 'MAX_SECONDS', 0)
    envelope, _, _, calls, *_ = collect_native_pipeline(monkeypatch, adapter.BATCH)
    assert calls == [] and envelope['status'] != 'collected'


@pytest.mark.parametrize('kind', adapter.KINDS)
def test_native_foreign_or_missing_required_parent_unknown(monkeypatch, clean, kind):
    row = native(kind)
    if kind == adapter.DATAFLOW: del row['environment']
    if kind == adapter.BATCH: del row['taskGroups']
    if kind == adapter.CLUSTER: del row['config']
    if kind == adapter.DATAPROC: del row['pysparkJob']
    envelope, context, *_ = collect_native_pipeline(monkeypatch, kind, row)
    item, = envelope['items']
    assert check.evaluate(item, context, kind)[0] == 'UNKNOWN'


def test_batch_secret_references_and_script_paths_are_not_scanned_or_fetched(monkeypatch, clean):
    row = native(adapter.BATCH)
    spec = row['taskGroups'][0]['taskSpec']
    spec['environment'] = {'secretVariables': {'INTENDED': 'projects/review/secrets/managed/versions/1'},
                           'encryptedVariables': {'keyName': 'projects/review/locations/global/keyRings/r/cryptoKeys/k', 'cipherText': TOKEN}}
    spec['runnables'] = [{'script': {'path': '/opt/scripts/start.sh'}}, {'container': {
        'commands': ['--mode', 'production'], 'password': 'projects/review/secrets/registry/versions/1'}}]
    seen = []; original = adapter.scan_content
    def scan(payload, *a, **kwargs): seen.append(payload); return original(payload, *a, **kwargs)
    monkeypatch.setattr(adapter, 'scan_content', scan)
    envelope, context, _, calls, *_ = collect_native_pipeline(monkeypatch, adapter.BATCH, row)
    item, = envelope['items']
    assert check.evaluate(item, context, adapter.BATCH)[0] == 'PASS'
    assert len(calls) == 1 and all(TOKEN.encode() not in payload for payload in seen)


@pytest.mark.parametrize('mutation', ['foreign_project', 'foreign_region', 'pending', 'sanitized', 'oversize', 'wrong_json_type'])
def test_dataflow_summary_cannot_manufacture_full_negative(monkeypatch, clean, mutation):
    row = native(adapter.DATAFLOW)
    if mutation == 'foreign_project': row['projectId'] = 'other'
    if mutation == 'foreign_region': row['location'] = 'europe-west1'
    if mutation == 'pending': row['currentState'] = 'JOB_STATE_PENDING'
    if mutation == 'sanitized': row['_field_mask'] = 'id,name'
    if mutation == 'oversize': row['environment']['sdkPipelineOptions']['large'] = 'a' * (adapter.MAX_VALUE_BYTES + 1)
    if mutation == 'wrong_json_type': row['environment']['sdkPipelineOptions'] = []
    envelope, context, *_ = collect_native_pipeline(monkeypatch, adapter.DATAFLOW, row)
    assert not envelope['items'] or all(check.evaluate(item, context, adapter.DATAFLOW)[0] == 'UNKNOWN' for item in envelope['items'])


def test_cluster_default_scrub_drops_values_but_preserves_existing_security_config():
    original = native(adapter.CLUSTER, True)
    safe = adapter.metadata_only(original, adapter.CLUSTER)
    assert 'properties' not in safe['config']['softwareConfig']
    assert 'metadata' not in safe['config']['gceClusterConfig']
    assert safe['config']['encryptionConfig'] == original['config']['encryptionConfig']
    page = adapter.cluster_metadata_response({'clusters': [original], 'nextPageToken': 'cursor'})
    assert page['nextPageToken'] == 'cursor' and page['clusters'][0] == safe


def test_native_adc_lowercase_authorization_and_quota_header(monkeypatch, clean):
    envelope, context, _, calls, *_ = collect_native_pipeline(monkeypatch, adapter.BATCH,
        lowercase_auth=True, options={'quota_project': 'billing-review'})
    row, = envelope['items']
    assert check.evaluate(row, context, adapter.BATCH)[0] == 'PASS'
    assert calls[0][1]['headers']['Authorization'] == 'Bearer fake-token'
    assert calls[0][1]['headers']['X-Goog-User-Project'] == 'billing-review'
    with pytest.raises(AssertionError, match='forbidden'):
        socket.create_connection(('example.invalid', 443))


def test_tool_failure_and_consumer_tampering_stay_unknown(monkeypatch, clean):
    def absent(*a): raise OSError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_trufflehog', absent)
    envelope, context, *_ = collect_native_pipeline(monkeypatch, adapter.DATAPROC)
    row, = envelope['items']
    assert check.evaluate(row, context, adapter.DATAPROC)[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps(row)
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])
    envelope, context, *_ = collect_native_pipeline(monkeypatch, adapter.DATAPROC)
    row, = envelope['items']
    row[adapter.MARKER]['engines'][1] = deepcopy(row[adapter.MARKER]['engines'][0])
    assert check.evaluate(row, context, adapter.DATAPROC)[0] == 'UNKNOWN'


@pytest.fixture(scope='module')
def installed_engines():
    pytest.importorskip('kingfisher_sdk')
    assert scanning._trufflehog()


@pytest.mark.parametrize('kind', adapter.KINDS)
@pytest.mark.parametrize('positive', [False, True])
def test_real_dual_tools_native_service_configuration_and_reflection_privacy(installed_engines, monkeypatch, kind, positive, capsys):
    envelope, context, snapshot, calls, responses, transport, _ = collect_native_pipeline(monkeypatch, kind, native(kind, positive))
    row, = envelope['items']
    status, evidence = check.evaluate(row, context, kind)
    assert status == ('FAIL' if positive else 'PASS')
    if positive:
        leak, = evidence['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
        # Found values stay visible (73706ae8) in the retained configuration.
        assert TOKEN in json.dumps(row) and TOKEN in json.dumps(snapshot)
    # Leak evidence carries fingerprints, and nothing is echoed to the console or result cache.
    assert TOKEN not in json.dumps(evidence) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert 'fake-token' not in json.dumps([snapshot, evidence, transport.evidence]) + repr(transport.cache)
    assert all(r.closed for r in responses)


def test_real_exact_value_one_finding_across_all_four_job_owners(installed_engines, monkeypatch):
    findings = []
    for kind in adapter.KINDS:
        envelope, context, *_ = collect_native_pipeline(monkeypatch, kind, native(kind, True))
        row, = envelope['items']; status, evidence = check.evaluate(row, context, kind)
        assert status == 'FAIL'
        findings.append({'provider': 'gcp', 'check_id': check.DECLARATIONS[kind]['id'], 'scope': SCOPE,
            'resource_id': row[adapter.IDENTITY], 'native_resource_id': row[adapter.IDENTITY], 'resource_type': kind,
            'status': status, 'finding_type': 'secrets', 'frameworks': [], 'evidence': evidence})
    merged = deduplicate_secret_findings(findings)
    assert len(merged) == 1 and len(merged[0]['linked_check_ids']) == 4
    assert len(merged[0]['evidence']['secret_leaks'][0]['locations']) == 4
    assert TOKEN not in json.dumps(merged)


def test_local_install_is_idempotent_and_all_source_produced_fixtures_evaluate():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    check.install()
    check.install()
    for kind, declaration in check.DECLARATIONS.items():
        matches = [c for c in CHECKS if c.id == declaration['id']]
        assert len(matches) == 1
        fixtures = CASES[declaration['id']]
        for label in ('pass', 'fail', 'unknown'):
            assert check.CALLBACKS[kind](fixtures[label], fixtures[label + '_index'])[0] == label.upper()
        assert check.CALLBACKS[kind](fixtures['missing'], {})[0] == 'UNKNOWN'
        assert check.CALLBACKS[kind](fixtures['malformed'], {})[0] == 'UNKNOWN'
