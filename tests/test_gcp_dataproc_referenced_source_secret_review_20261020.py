"""Native HTTP -> actual collect_snapshot/GCPCollector -> installed pure consumers.

Exact predecessor219 roster and proposal bridge bytes retained in a separate
pre-integration gzip. No registry, kind or collector scheduling patches.
"""
from copy import deepcopy
import http.client
import io
import inspect
import json
import logging
from pathlib import Path
import socket
from types import SimpleNamespace
from urllib.parse import quote, urlsplit
import pytest
import requests
from peaso import engine, secret_scanning as scanning
from peaso.collectors import gcp
from peaso.collectors import gcp_dataproc_source_runtime_20261020 as runtime
from peaso.collectors import gcp_dataproc_referenced_source_secret_indicators as source
from peaso.checks import gcp_dataproc_referenced_source_secret_review_20261020 as consumer

SCOPE = 'projects/review'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'inert-oauth-canary'
UUID = '12345678-1234-4234-8234-123456789012'


def target(profile='job', field=None):
    return dict(profile=profile, resource=SCOPE + '/regions/us-central1/' + ('jobs/review_job' if profile == 'job' else 'clusters/review-cluster'),
        field=field or ('pysparkJob.mainPythonFileUri' if profile == 'job' else 'config.initializationActions[0].executableFile'),
        bucket='review-source', object='scripts/source.py', generation='12345')


def native(t):
    uri = 'gs://' + t['bucket'] + '/' + t['object']
    if t['profile'] == 'job':
        outer, field = t['field'].split('.')
        return {'reference': {'projectId': 'review', 'jobId': t['resource'].rsplit('/', 1)[1]}, 'jobUuid': UUID,
                outer: {field: uri}, 'placement': {'clusterName': 'review-cluster', 'clusterUuid': UUID}, 'status': {'state': 'DONE'}, 'driverOutputResourceUri': 'https://never-follow.invalid/secret'}
    return {'projectId': 'review', 'clusterName': t['resource'].rsplit('/', 1)[1], 'clusterUuid': UUID,
            'config': {'initializationActions': [{'executableFile': uri}]}, 'status': {'state': 'RUNNING'}}


class Response:
    def __init__(self, data, status=200, headers=None):
        self.payload = json.dumps(data).encode() if isinstance(data, dict) else data
        self.status_code = status
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.payload)), **(headers or {})}
        self.url = ''; self.history = []; self.raw = self; self.stream = io.BytesIO(self.payload); self.closed = False
    def read(self, size, *, decode_content):
        assert decode_content is False and 0 < size <= 16384
        return self.stream.read(size)
    def close(self): self.closed = True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a, **k): pytest.fail('Live network/auth is forbidden')
    for n in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, n, blocked)
    for n in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'): monkeypatch.setattr(socket, n, blocked)
    monkeypatch.setattr(gcp, 'Credentials', blocked)
    monkeypatch.setattr(gcp.Transport, 'request', blocked)
    scanning._RESULTS.clear()
    for profile, p in source.PROFILES.items():
        actual, = [c for c in engine._registry() if c.id == p['check']]
        assert inspect.unwrap(actual.evaluate) is getattr(consumer, 'job_source' if profile == 'job' else 'initialization_source')
    yield
    scanning._RESULTS.clear()


def capture(monkeypatch, profile='job', *, payload=b'mode = "ready"\n', targets=None, real=False,
            fault=None, options=None, absent=None, token_change=False, mutate_meta=None, named=True, request_fields=None):
    targets = deepcopy(targets if targets is not None else [target(profile)])
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [source.PROFILES[p]['kind'] for p in source.PROFILES],
            source.OPTION: targets, 'concurrency': 1, 'metrics_scopes': False, 'include_inherited': False,
            'retries': 0, **(options or {})}
    source.selected_targets(opts, [SCOPE])  # proposed preauth validator
    seen, calls, responses, sessions, auth = [], [], [], [], []
    if not real:
        def detector(raw, path, timeout):
            seen.append((path, timeout))
            return [(TOKEN, 'inert-github', 1)] if TOKEN.encode() in raw else []
        monkeypatch.setattr(scanning, '_scan_kingfisher', detector)
        monkeypatch.setattr(scanning, '_scan_trufflehog', detector)
    if absent:
        def unavailable(*a, **k): raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning, '_scan_' + absent, unavailable)
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer ' + (AUTH + 'changed' if token_change and len(auth) > 1 else AUTH)}
    transports = []
    original_init = gcp.Transport.__init__
    def transport_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        transports.append(self)
    monkeypatch.setattr(gcp.Transport, '__init__', transport_init)
    monkeypatch.setattr(gcp, 'Credentials', lambda *a, **k: SimpleNamespace(headers=headers, close=lambda: None, method='explicit-offline-native-test'))
    if mutate_meta:
        original_final = runtime.final_snapshot
        def final(collector, snapshot, **kw):
            mutate_meta(snapshot, collector)
            return original_final(collector, snapshot, **kw)
        monkeypatch.setattr(runtime, 'final_snapshot', final)
    counts = {}
    def request(method, url, **kw):
        assert method == 'GET' and kw['stream'] is True and kw['allow_redirects'] is False
        assert kw['headers'] == {'Authorization': 'Bearer ' + AUTH, 'Accept': '*/*' if kw['params'].get('alt') == 'media' else 'application/json',
                                 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
        assert 0 < kw['timeout'] <= 20
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        t = next((t for t in targets if url.endswith(t['resource'])), None)
        if parsed.netloc == 'cloudresourcemanager.googleapis.com':
            assert parsed.path == '/v3/' + SCOPE and kw['params'] == {'fields': 'name,projectId,state'}
            op = 'project'; data = {'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'}
        elif parsed.netloc == 'dataproc.googleapis.com':
            assert t is not None and parsed.path == '/v1/' + t['resource'] and kw['params'] == {}
            op = 'reference'; data = native(t)
        else:
            assert parsed.netloc == 'storage.googleapis.com'
            if '/o/' not in parsed.path:
                t = next(t for t in targets if parsed.path == '/storage/v1/b/' + quote(t['bucket'], safe=''))
                assert kw['params'] == {'fields': 'name,projectNumber', 'projection': 'noAcl'}
                op = 'bucket'; data = {'name': t['bucket'], 'projectNumber': '10001'}
            else:
                t = next(t for t in targets if parsed.path == '/storage/v1/b/' + quote(t['bucket'], safe='') + '/o/' + quote(t['object'], safe=''))
                if kw['params'].get('alt') == 'media':
                    assert kw['params'] == {'alt': 'media', 'generation': t['generation'], 'ifGenerationMatch': t['generation']}
                    op = 'content'; data = payload
                else:
                    assert kw['params'] == {'fields': source.objects.FIELDS, 'projection': 'noAcl'}
                    assert 'generation' not in kw['params'] and 'ifGenerationMatch' not in kw['params']
                    op = 'latest'; data = {'bucket': t['bucket'], 'name': t['object'], 'generation': t['generation'],
                        'size': str(len(payload)), 'contentType': 'text/plain'}
        counts[op] = counts.get(op, 0) + 1
        resp = Response(data, headers={'Content-Type': 'text/plain', 'x-goog-generation': t['generation']} if op == 'content' else None)
        if fault: fault(op, counts[op], resp, data)
        resp.url = getattr(resp, 'final_url', requests.Request(method, url, params=kw['params']).prepare().url)
        calls.append((op, method, url, deepcopy(kw['params'])))
        responses.append(resp)
        return resp
    monkeypatch.setattr(source.git, '_session', lambda: SimpleNamespace(request=request, close=lambda: sessions.append(True)))
    ids = [source.PROFILES[p]['check'] for p in set(t['profile'] for t in targets)]
    if not named:
        opts.setdefault('inventories', [source.PROFILES[t['profile']]['kind'] for t in targets])
    scan_request = {'connector': {'provider': 'gcp', 'scopes': [SCOPE], 'options': opts}}
    if named: scan_request['checks'] = ids
    scan_request.update(request_fields or {})
    snapshot = engine.collect_snapshot(scan_request)
    findings = engine.evaluate_snapshot(snapshot, checks=ids)['findings']
    transport = transports[-1] if transports else SimpleNamespace(cache={}, options=opts, evidence=[])
    collector = SimpleNamespace(transport=transport, options=transport.options)
    return snapshot, findings, SimpleNamespace(collector=collector, calls=calls, responses=responses, sessions=sessions, auth=auth, seen=seen)


def statuses(rows): return {r['status'] for r in rows}


@pytest.mark.parametrize('profile', source.PROFILES)
@pytest.mark.parametrize('hit', [False, True])
@pytest.mark.parametrize('real', [False, True])
def test_native_three_branches_both_detectors(monkeypatch, profile, hit, real):
    snap, rows, tr = capture(monkeypatch, profile, payload=('token=' + TOKEN).encode() if hit else b'mode=ready\n', real=real)
    assert statuses(rows) == {'FAIL' if hit else 'PASS'}, rows
    assert len(tr.calls) == 9 and all(r.closed for r in tr.responses) and len(tr.sessions) == 9
    assert [r[0] for r in tr.calls] == ['project', 'reference', 'bucket', 'latest', 'content', 'latest', 'reference', 'bucket', 'project']
    kind = source.PROFILES[profile]['kind']
    env, = [e for e in snap['collections'] if e['type'] == kind]
    item, = env['items']
    idx = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': snap['metadata']}, 'collections': {kind: [env]}}
    verdict, evidence = consumer._evaluate(item, idx, profile)
    assert verdict == ('FAIL' if hit else 'PASS')
    assert evidence['executed_bytes_proven'] is False and evidence['complete'] is True
    assert rows[0]['evidence']['credential_validation'] == 'not_attempted'
    assert {(e['engine'], e['version'], e['status']) for e in evidence['parts'][0]['engines']} == {
        ('kingfisher', '1.4.0', 'complete'), ('trufflehog', '3.92.5', 'complete')}
    if hit:
        leak, = evidence['secret_leaks']; assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    persisted = json.dumps([snap, rows, tr.collector.transport.evidence]) + repr(tr.collector.transport.cache)
    assert TOKEN not in persisted and AUTH not in persisted and 'gs://' not in persisted and 'source.py' not in persisted
    assert not hasattr(tr.collector.transport, '_dataproc_source_state')


@pytest.mark.parametrize('field', source.JOB_FIELDS)
def test_each_supported_job_field(monkeypatch, field):
    t = target(field=field)
    if field.startswith('sparkR'): t['object'] = 'scripts/source.R'
    _, rows, _ = capture(monkeypatch, targets=[t])
    assert statuses(rows) == {'PASS'}


@pytest.mark.parametrize('profile', source.PROFILES)
@pytest.mark.parametrize('op', ['project', 'reference', 'bucket', 'latest', 'content'])
@pytest.mark.parametrize('code', [401, 403, 404, 410, 429, 500])
def test_native_denied_deleted_errors_not_retained(monkeypatch, profile, op, code):
    def fault(operation, n, resp, data):
        if operation == op: resp.status_code = code; resp.stream = io.BytesIO(TOKEN.encode())
    snap, rows, tr = capture(monkeypatch, profile, fault=fault)
    assert statuses(rows) == {'UNKNOWN'} and not tr.seen
    assert all(r.closed for r in tr.responses) and TOKEN not in json.dumps([snap, rows])


@pytest.mark.parametrize('profile', source.PROFILES)
@pytest.mark.parametrize('mutation', ['latest_before', 'latest_after', 'uuid_after', 'reference_after', 'foreign_project', 'foreign_bucket',
    'project_after', 'bucket_after', 'missing_uuid', 'missing_reference', 'query_union', 'wrong_union', 'binary', 'archive', 'empty',
    'redirect', 'history', 'partial', 'duplicate_json', 'truncated', 'media_generation', 'encoding', 'range', 'oversize', 'length_omitted'])
def test_native_binding_generation_and_bounds(monkeypatch, profile, mutation):
    payload = b'\x00\xff' if mutation == 'binary' else b'PK\x03\x04archive' if mutation == 'archive' else b'' if mutation == 'empty' else b'mode=ready\n'
    def fault(op, n, resp, data):
        if mutation in ('latest_before', 'latest_after') and op == 'latest' and n == (1 if mutation.endswith('before') else 2): data['generation'] = '54321'
        elif mutation == 'uuid_after' and op == 'reference' and n == 2: data['jobUuid' if profile == 'job' else 'clusterUuid'] = '87654321-1234-4234-8234-123456789012'
        elif mutation == 'reference_after' and op == 'reference' and n == 2:
            if profile == 'job': data['pysparkJob']['mainPythonFileUri'] += '.other'
            else: data['config']['initializationActions'][0]['executableFile'] += '.other'
        elif mutation == 'foreign_project' and op == 'project': data['projectId'] = 'foreign'
        elif mutation == 'foreign_bucket' and op == 'bucket': data['projectNumber'] = '10002'
        elif mutation == 'project_after' and op == 'project' and n == 2: data['name'] = 'projects/10002'
        elif mutation == 'bucket_after' and op == 'bucket' and n == 2: data['name'] = 'foreign'
        elif mutation == 'missing_uuid' and op == 'reference': data.pop('jobUuid' if profile == 'job' else 'clusterUuid')
        elif mutation == 'missing_reference' and op == 'reference': data.pop('reference' if profile == 'job' else 'config')
        elif mutation in ('query_union', 'wrong_union') and op == 'reference':
            if profile == 'job':
                if mutation == 'query_union': data['pysparkJob']['queryList'] = {'queries': ['select 1']}
                else: data['hiveJob'] = {'queryFileUri': 'gs://foreign/x'}
            else: data['virtualClusterConfig'] = {}
        elif mutation == 'redirect': resp.final_url = 'https://evil.invalid/' + TOKEN
        elif mutation == 'history': resp.history = [object()]
        elif mutation == 'partial' and op == 'reference': data['unreachable'] = ['any']
        elif mutation == 'truncated': resp.headers['Content-Length'] = str(len(resp.payload) + 1)
        elif mutation == 'media_generation' and op == 'content': resp.headers['x-goog-generation'] = '54321'
        elif mutation == 'encoding': resp.headers['Content-Encoding'] = 'gzip'
        elif mutation == 'range': resp.headers['Content-Range'] = 'bytes 0-1/20'
        elif mutation == 'oversize': resp.headers['Content-Length'] = str(source.MAX_CONTENT + 1)
        elif mutation == 'length_omitted': resp.headers.pop('Content-Length')
        if isinstance(data, dict):
            raw = json.dumps(data).encode()
            if mutation == 'duplicate_json': raw = b'{"name":"x","name":"y"}'
            resp.stream = io.BytesIO(raw)
            if mutation not in ('truncated', 'oversize', 'length_omitted'): resp.headers['Content-Length'] = str(len(raw))
    snap, rows, tr = capture(monkeypatch, profile, payload=payload, fault=fault)
    assert statuses(rows) == {'UNKNOWN'}, (mutation, rows)
    assert not tr.seen and all(r.closed for r in tr.responses)
    assert TOKEN not in json.dumps([snap, rows])


@pytest.mark.parametrize('profile', source.PROFILES)
@pytest.mark.parametrize('engine_name', ['kingfisher', 'trufflehog'])
@pytest.mark.parametrize('hit', [False, True])
def test_completed_engine_hit_survives_other_unavailable(monkeypatch, profile, engine_name, hit):
    _, rows, _ = capture(monkeypatch, profile, absent=engine_name, payload=('token=' + TOKEN).encode() if hit else b'clean\n')
    assert statuses(rows) == {'FAIL' if hit else 'UNKNOWN'}, rows
    assert rows[0]['evidence']['complete'] is False


@pytest.mark.parametrize('profile', source.PROFILES)
@pytest.mark.parametrize('options', [{'content_secret_scans': False}, {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': 'spoof'}])
def test_default_disabled_no_credentials(monkeypatch, profile, options):
    _, rows, tr = capture(monkeypatch, profile, options=options, named='_content_secret_scan_kinds' not in options)
    assert statuses(rows) <= {'UNKNOWN', 'EMPTY'} and not tr.auth and not tr.calls and not tr.seen


@pytest.mark.parametrize('mutation', ['foreign', 'url', 'number', 'duplicate', 'five', 'empty', 'field', 'traversal', 'encoded', 'fragment', 'generation', 'negative', 'float', 'unknown_key', 'bool_flag'])
def test_selection_before_credentials(monkeypatch, mutation):
    t = target(); opts = {}; targets = [t]
    if mutation == 'foreign': t['resource'] = t['resource'].replace('/review/', '/foreign/')
    if mutation == 'url': t['resource'] = 'https://evil.invalid/' + t['resource']
    if mutation == 'number': t['resource'] = t['resource'].replace('/review/', '/10001/')
    if mutation == 'duplicate': targets *= 2
    if mutation == 'five': targets = [{**t, 'object': str(n) + '.py'} for n in range(5)]
    if mutation == 'empty': targets = []
    if mutation == 'field': t['field'] = 'driverOutputResourceUri'
    if mutation == 'traversal': t['object'] = '../source.py'
    if mutation == 'encoded': t['object'] = 'a%2fsource.py'
    if mutation == 'fragment': t['object'] = 'source.py#123'
    if mutation == 'generation': t['generation'] = '0'
    if mutation == 'negative': t['generation'] = '-1'
    if mutation == 'float': t['generation'] = 12345.0
    if mutation == 'unknown_key': t['url'] = 'https://evil.invalid'
    if mutation == 'bool_flag': opts['content_secret_scans'] = 'true'
    with pytest.raises(source.Incomplete, match='invalid_selection'):
        capture(monkeypatch, targets=targets, options=opts)


@pytest.mark.parametrize('profile', source.PROFILES)
@pytest.mark.parametrize('limit', [0, 1, 4, 8])
def test_shared_transport_call_limits(monkeypatch, profile, limit):
    _, rows, tr = capture(monkeypatch, profile, options={'max_calls': max(1, limit)})
    assert statuses(rows) == {'UNKNOWN'} and len(tr.calls) <= max(1, limit) and not tr.seen


@pytest.mark.parametrize('profile', source.PROFILES)
def test_debug_and_changed_principal_stop_reads(monkeypatch, profile, capsys):
    monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', 1)
    _, rows, tr = capture(monkeypatch, profile)
    assert statuses(rows) == {'UNKNOWN'} and not tr.auth and not tr.calls
    monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', 0)
    _, rows, tr = capture(monkeypatch, profile, token_change=True)
    assert statuses(rows) == {'UNKNOWN'} and len(tr.calls) == 1
    assert TOKEN not in str(capsys.readouterr()) and AUTH not in str(capsys.readouterr())


def test_cross_surface_dedup_metadata_and_cache_union(monkeypatch):
    a, b = target(), target('cluster'); a['object'] = 'scripts/' + TOKEN + '.py'; b['object'] = a['object']
    def seed(snapshot, collector):
        snapshot['metadata']['other_reader'] = {TOKEN: TOKEN}
        collector.transport.cache[TOKEN] = {'path': TOKEN}
        collector.transport.evidence.append({'path': TOKEN})
    snap, rows, tr = capture(monkeypatch, targets=[a, b], payload=('token=' + TOKEN).encode(), mutate_meta=seed)
    assert statuses(rows) == {'FAIL'} and len(tr.calls) == 18
    leaks = scanning.merge_leaks(*(r['evidence']['secret_leaks'] for r in rows))
    assert len(leaks) == 1 and len(leaks[0]['locations']) == 2
    # Found values stay visible (73706ae8): the object name and every retained copy keep the value.
    assert TOKEN in json.dumps([snap, rows, tr.collector.transport.cache])


@pytest.mark.parametrize('mutation', ['scope', 'provider', 'selection', 'authorization', 'receipt', 'principal', 'capture', 'bound', 'native', 'version', 'complete', 'duplicate'])
def test_consumer_rejects_tampered_native_capture(monkeypatch, mutation):
    snap, _, _ = capture(monkeypatch)
    row = snap['collections'][0]['items'][0]; m = row[source.MARKER]; kind = source.PROFILES['job']['kind']
    if mutation == 'scope': m['scope'] = 'projects/foreign'
    if mutation == 'provider': snap['provider'] = 'azure'
    if mutation == 'selection': snap['metadata'][kind + '_selection'][SCOPE] = []
    if mutation == 'authorization': snap['metadata'][kind + '_authorized'] = False
    if mutation == 'receipt': snap['metadata']['dataproc_source_receipts'][0]['operation'] = 'list'
    if mutation == 'principal': snap['metadata']['dataproc_source_receipts'][0]['principal'] = 'a' * 64
    if mutation == 'capture': m['capture'] = 'a' * 32
    if mutation == 'bound': snap['metadata']['dataproc_source_receipts'][0]['bound'] = False
    if mutation == 'native': m['native_complete'] = False
    if mutation == 'version': m['parts'][0]['engines'][0]['version'] = 'wrong'
    if mutation == 'complete': m['parts'][0]['complete'] = False
    if mutation == 'duplicate': snap['collections'][0]['items'].append(deepcopy(row))
    idx = {'context': {'provider': snap['provider'], 'scope': SCOPE, 'metadata': snap['metadata']},
           'collections': {kind: snap['collections']}}
    assert consumer.job_source(row, idx)[0] == 'UNKNOWN'


@pytest.mark.parametrize('profile', source.PROFILES)
@pytest.mark.parametrize('fault', ['aggregate', 'local_calls', 'deadline', 'cancel', 'diagnostics'])
def test_shared_deadline_cancellation_and_aggregate_bounds(monkeypatch, profile, fault, request):
    opts = {}
    if fault == 'aggregate': monkeypatch.setattr(source, 'MAX_TOTAL', 100)
    if fault == 'local_calls': monkeypatch.setattr(source, 'MAX_CALLS', 8)
    if fault == 'deadline': monkeypatch.setattr(source, 'MAX_SECONDS', 0)
    if fault == 'cancel': opts['_cancel_check'] = lambda: True
    if fault == 'diagnostics':
        logger = logging.getLogger('urllib3.connectionpool'); old_level = logger.level
        logger.setLevel(logging.DEBUG)
        request.addfinalizer(lambda: logger.setLevel(old_level))
    _, rows, tr = capture(monkeypatch, profile, options=opts)
    assert statuses(rows) == {'UNKNOWN'} and not tr.seen
    assert len(tr.calls) <= 8 and all(r.closed for r in tr.responses)
    if fault in ('deadline', 'cancel', 'diagnostics'): assert not tr.auth


@pytest.mark.parametrize('profile', source.PROFILES)
@pytest.mark.parametrize('mutation', ['nontext', 'encryption', 'metasize', 'content_bytes', 'native_error', 'json_scalar', 'metadata_unknown'])
def test_source_unsupported_native_forms(monkeypatch, profile, mutation):
    def fault(op, n, resp, data):
        if op != 'latest': return
        if mutation == 'nontext': data['contentType'] = 'application/octet-stream'
        if mutation == 'encryption': data['customerEncryption'] = {'encryptionAlgorithm': 'AES256', 'keySha256': 'hidden'}
        if mutation == 'metasize': data['size'] = '1'
        if mutation == 'content_bytes': data['size'] = str(source.MAX_CONTENT + 1)
        if mutation == 'native_error': data['error'] = {'message': TOKEN}
        if mutation == 'metadata_unknown': data['arbitrary'] = TOKEN
        raw = b'[]' if mutation == 'json_scalar' else json.dumps(data).encode()
        resp.stream = io.BytesIO(raw); resp.headers['Content-Length'] = str(len(raw))
    snap, rows, tr = capture(monkeypatch, profile, fault=fault)
    assert statuses(rows) == {'UNKNOWN'} and not tr.seen
    assert TOKEN not in json.dumps([snap, rows])


def test_cluster_selected_action_offset_and_not_whole_actions(monkeypatch):
    t = target('cluster'); t['field'] = 'config.initializationActions[1].executableFile'
    def fault(op, n, resp, data):
        if op == 'reference':
            data['config']['initializationActions'].insert(0, {'executableFile': 'gs://unselected/unread.sh'})
            raw = json.dumps(data).encode(); resp.stream = io.BytesIO(raw); resp.headers['Content-Length'] = str(len(raw))
    _, rows, tr = capture(monkeypatch, targets=[t], fault=fault)
    assert statuses(rows) == {'PASS'} and not any('unselected' in c[2] for c in tr.calls)


def test_both_profiles_share_target_cap_without_old_kind_authorization(monkeypatch):
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': ['gcs_selected_object'], source.OPTION: [target()]}
    _, rows, tr = capture(monkeypatch, options=opts, named=False)
    assert not tr.calls and not tr.auth and statuses(rows) <= {'UNKNOWN', 'EMPTY'}
    opts[source.OPTION] = [target(), target('cluster'), {**target(), 'resource': target()['resource'] + '2'},
                           {**target('cluster'), 'resource': target('cluster')['resource'] + '2'},
                           {**target(), 'resource': target()['resource'] + '3'}]
    with pytest.raises(source.Incomplete): source.selected_targets(opts, [SCOPE])


def test_failed_scan_union_removes_values_learned_by_only_one_engine(monkeypatch):
    def partial(raw, path, timeout): return [(TOKEN, 'first-only', 1)]
    monkeypatch.setattr(scanning, '_scan_kingfisher', partial)
    snap, rows, tr = capture(monkeypatch, real=True, absent='trufflehog', payload=('token=' + TOKEN).encode(),
        mutate_meta=lambda snap, c: snap['metadata'].update({'other': TOKEN}))
    assert statuses(rows) == {'FAIL'} and rows[0]['evidence']['complete'] is False
    assert TOKEN in json.dumps([snap, rows, tr.collector.transport.cache])  # found values stay visible


def test_actual_runner_offline_flags_and_no_temp_content(monkeypatch, tmp_path):
    calls = []; original = scanning._run
    def run(argv, payload, timeout):
        calls.append(list(argv))
        if 'stdin' in argv:
            assert {'--no-verification', '--no-update', '--no-verification-cache', '--force-skip-archives', '--fail-on-scan-errors'} <= set(argv)
            assert TOKEN not in ' '.join(argv) and b'token=' in payload and timeout <= 10
        return original(argv, payload, timeout)
    monkeypatch.setattr(scanning, '_run', run)
    _, rows, _ = capture(monkeypatch, real=True, payload=('token=' + TOKEN).encode())
    assert statuses(rows) == {'FAIL'} and any('stdin' in a for a in calls)
    assert not list(tmp_path.iterdir())


def test_native_fixture_verdicts():
    import gzip
    from peaso.rawv2_private_source_successor_20261021 import install_admission
    install_admission('gcp_dataproc_source_runtime_admission_20261020')
    frozen = json.loads(gzip.decompress(Path('peaso/checks/gcp_dataproc_referenced_source_native_cases_20261020.json.gz').read_bytes()))
    for cid, outcomes in frozen['cases'].items():
        assert set(outcomes) == {'PASS', 'FAIL', 'UNKNOWN'}
        for expected, case in outcomes.items():
            rows = engine.evaluate_snapshot(case['snapshot'], checks=[cid])['findings']
            assert statuses(rows) == {expected}, rows
            assert AUTH not in json.dumps(case) and TOKEN not in json.dumps(case)


@pytest.mark.parametrize('field,value', [('profile', []), ('profile', None), ('object', '\ud800.py'), ('object', None), ('resource', {}), ('generation', True), ('field', []), ('bucket', 123)])
def test_malformed_selector_values_are_typed_before_auth(monkeypatch, field, value):
    t = target(); t[field] = value
    with pytest.raises(source.Incomplete, match='invalid_selection'):
        source.selected_targets({'content_secret_scans': True, '_content_secret_scan_kinds': [source.PROFILES['job']['kind']], source.OPTION: [t]}, [SCOPE])


def test_native_session_ignores_ambient_auth_proxy_and_cookie(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'https://never-contact.invalid')
    monkeypatch.setenv('NETRC', '/never-read')
    session = source.git._session()
    try:
        assert session.trust_env is False and list(session.cookies) == []
        prepared = requests.Request('GET', 'https://dataproc.googleapis.com/v1/' + target()['resource'], headers={'Authorization': 'Bearer ' + AUTH}).prepare()
        assert session.auth(prepared) is prepared and prepared.headers['Authorization'] == 'Bearer ' + AUTH
    finally: session.close()


@pytest.mark.parametrize('hit', [False, True])
def test_four_combined_native_targets_share_36_calls(monkeypatch, hit):
    a, b = target(), target('cluster')
    targets = [a, {**a, 'resource': a['resource'] + '2'}, b, {**b, 'resource': b['resource'] + '2'}]
    _, rows, tr = capture(monkeypatch, targets=targets, payload=('token=' + TOKEN).encode() if hit else b'ready\n')
    assert statuses(rows) == {'FAIL' if hit else 'PASS'} and len(tr.calls) == source.MAX_CALLS == 36
    assert all(r.closed for r in tr.responses)
    if hit:
        leaks = scanning.merge_leaks(*(r['evidence']['secret_leaks'] for r in rows))
        assert len(leaks) == 1 and len(leaks[0]['locations']) == 4
