"""Offline fake native HTTP -> actual proposal adapter -> pure consumer.

Real pinned detectors are used unless the test explicitly injects an engine
failure; cloud credentials, sockets and generic Transport.request are blocked.
"""
from copy import deepcopy
import base64
import http.client
import gzip
import io
import json
import logging
from pathlib import Path
import socket
import time
from types import SimpleNamespace
from urllib.parse import quote, urlsplit
import pytest
import requests

from peaso import secret_scanning as scanning
from peaso.collectors import gcp
from peaso.collectors import gcp_batch_referenced_source_20261020 as source
from peaso.checks import gcp_batch_referenced_source_20261020 as consumer

SCOPE = 'projects/review'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'inert-batch-oauth-canary'
NATIVE = Path(__file__).with_name('gcp_batch_referenced_source_20261020_native.json')


def target():
    return dict(resource=SCOPE + '/locations/us-central1/jobs/review-job', task_group=0, runnable=0, volume=0,
        bucket='review-source', object='code/scripts/main.sh', generation='12345')


class Response:
    def __init__(self, data, headers=None):
        raw = json.dumps(data).encode() if isinstance(data, dict) else data
        self.status_code = 200
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(raw)), **(headers or {})}
        self.url = ''; self.history = []; self.raw = self; self.stream = io.BytesIO(raw); self.closed = False
    def read(self, size, *, decode_content):
        assert decode_content is False and 0 < size <= 16384
        return self.stream.read(size)
    def close(self): self.closed = True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs): pytest.fail('Live cloud/auth/network is forbidden')
    for name in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'): monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(gcp, 'Credentials', blocked)
    monkeypatch.setattr(gcp.Transport, 'request', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def capture(monkeypatch, *, payload=b'#!/bin/sh\necho ready\n', targets=None, job=None, fault=None,
            options=None, named=None, change_principal=False, export_metadata=None):
    targets = deepcopy(targets if targets is not None else [target()])
    opts = dict(content_secret_scans=True, **{source.OPTION: targets})
    opts.update(options or {})
    calls, responses, sessions, auth = [], [], [], []
    counts = {}
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer ' + AUTH + ('-changed' if change_principal and len(auth) >= 3 else '')}
    transport = gcp.Transport(SimpleNamespace(headers=headers), opts)
    transport.cache = {'synthetic': TOKEN}
    transport.evidence = [{'synthetic': TOKEN}]
    def request(method, url, **kw):
        assert method == 'GET' and kw['stream'] is True and kw['allow_redirects'] is False
        assert kw['headers']['Authorization'].startswith('Bearer ' + AUTH)
        assert kw['headers']['Accept-Encoding'] == 'identity' and kw['headers']['Cache-Control'] == 'no-store'
        assert 0 < kw['timeout'] <= transport.timeout
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        if parsed.netloc == 'cloudresourcemanager.googleapis.com':
            assert parsed.path == '/v3/' + SCOPE and kw['params'] == {'fields': 'name,projectId,state'}
            op = 'project'; data = dict(name='projects/10001', projectId='review', state='ACTIVE')
        elif parsed.netloc == 'batch.googleapis.com':
            t = next(t for t in targets if parsed.path == '/v1/' + t['resource'])
            assert kw['params'] == {}
            op = 'reference'; data = deepcopy(job if job is not None else json.loads(NATIVE.read_text()))
            if len(targets) > 1:
                data['name'] = t['resource'].replace(SCOPE, 'projects/10001', 1)
                data['taskGroups'][0]['name'] = data['name'] + '/taskGroups/group0'
        else:
            assert parsed.netloc == 'storage.googleapis.com'
            t = next(t for t in targets if parsed.path.startswith('/storage/v1/b/' + quote(t['bucket'], safe='')))
            if '/o/' not in parsed.path:
                assert parsed.path == '/storage/v1/b/' + quote(t['bucket'], safe='')
                assert kw['params'] == {'fields': 'name,projectNumber', 'projection': 'noAcl'}
                op = 'bucket'; data = dict(name=t['bucket'], projectNumber='10001')
            else:
                assert parsed.path == '/storage/v1/b/' + quote(t['bucket'], safe='') + '/o/' + quote(t['object'], safe='')
                if kw['params'].get('alt') == 'media':
                    assert kw['params'] == dict(generation=t['generation'], ifGenerationMatch=t['generation'], alt='media')
                    op = 'content'; data = payload
                else:
                    assert kw['params'] == {'fields': source.objects.FIELDS, 'projection': 'noAcl'}
                    assert 'generation' not in kw['params']
                    op = 'latest'; data = dict(bucket=t['bucket'], name=t['object'], generation=t['generation'],
                        size=str(len(payload)), contentType='text/plain')
        counts[op] = counts.get(op, 0) + 1
        response_headers = {'Content-Type': 'text/plain', 'x-goog-generation': t['generation']} if op == 'content' else None
        response = Response(data, response_headers)
        if fault: fault(op, counts[op], data, response, transport)
        response.url = getattr(response, 'final_url', requests.Request(method, url, params=kw['params']).prepare().url)
        responses.append(response); calls.append((op, url, deepcopy(kw['params'])))
        return response
    monkeypatch.setattr(source.reads.git, '_session', lambda: SimpleNamespace(request=request, close=lambda: sessions.append(True)))
    evidence = source.collect(transport, opts, [SCOPE], named=[source.CHECK] if named is None else named)
    saved = source.finalize(transport, evidence, metadata=export_metadata, options=opts)
    rows = [consumer.evaluate(item, saved['evidence'], SCOPE) for item in saved['evidence']['items']]
    return saved, rows, SimpleNamespace(transport=transport, calls=calls, responses=responses, sessions=sessions, auth=auth)


def statuses(rows): return {r[0] for r in rows}


@pytest.mark.parametrize('hit', [False, True])
def test_real_pinned_engines_native_pipeline(monkeypatch, hit, capsys):
    saved, rows, trace = capture(monkeypatch, payload=('token=' + TOKEN + '\n').encode() if hit else b'#!/bin/sh\necho ready\n')
    assert statuses(rows) == {'FAIL' if hit else 'PASS'}, saved
    assert len(trace.calls) == 9 and len(trace.sessions) == 9 and all(r.closed for r in trace.responses)
    marker = saved['evidence']['items'][0][source.MARKER]
    assert marker['native_complete'] and marker['complete'] and not marker['executed_bytes_proven']
    assert marker['parts'][0]['engines'] == [
        dict(engine='kingfisher', version='1.4.0', status='complete'), dict(engine='trufflehog', version='3.92.5', status='complete')]
    if hit:
        assert len(marker['leaks']) == 1
        assert {d['engine'] for d in marker['leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
        assert marker['leaks'][0]['fingerprint'] == scanning._fingerprint(TOKEN)
    raw = json.dumps(saved)
    assert TOKEN not in raw and AUTH not in raw and 'gs://' not in raw and '/mnt/source' not in raw
    assert 'batch-opaque-native-uid' not in raw
    if hit:
        assert TOKEN in json.dumps([trace.transport.cache, trace.transport.evidence]) and TOKEN not in json.dumps(trace.transport.options)  # found values stay visible
    assert source.OPTION not in trace.transport.options and not hasattr(trace.transport, '_batch_source_redactions')
    captured = capsys.readouterr(); assert not captured.out and not captured.err


@pytest.mark.parametrize('failed', ['kingfisher', 'trufflehog'])
@pytest.mark.parametrize('hit', [False, True])
def test_actual_surviving_engine_fail_only(monkeypatch, failed, hit):
    def unavailable(*args): raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_' + failed, unavailable)
    saved, rows, _ = capture(monkeypatch, payload=('token=' + TOKEN).encode() if hit else b'echo ready')
    assert statuses(rows) == {'FAIL' if hit else 'UNKNOWN'}
    assert saved['evidence']['items'][0][source.MARKER]['complete'] is False
    if hit:
        assert {d['engine'] for l in rows[0][1]['secret_leaks'] for d in l['detectors']} == ({'kingfisher', 'trufflehog'} - {failed})
    assert TOKEN not in json.dumps(saved)


@pytest.mark.parametrize('mutation', [
    'foreign_job', 'foreign_group', 'missing_uid', 'uid_type', 'text', 'text_and_path', 'container', 'script_and_container',
    'gs_uri', 'relative', 'traversal', 'encoded', 'env_path', 'outside', 'directory', 'remote_gs_uri', 'foreign_remote',
    'gcs_and_nfs', 'nfs_only', 'mount_option', 'mount_option_type', 'duplicate_mount', 'shadow_mount', 'ancestor_mount',
    'unrelated_malformed_volume', 'missing_volume', 'volumes_type', 'runnables_type', 'extra_group', 'wrong_prefix',
])
def test_native_unsupported_counterexamples(monkeypatch, mutation):
    job = json.loads(NATIVE.read_text()); group = job['taskGroups'][0]; spec = group['taskSpec']
    runnable = spec['runnables'][0]; volume = spec['volumes'][0]
    if mutation == 'foreign_job': job['name'] = job['name'].replace('10001', '10002')
    elif mutation == 'foreign_group': group['name'] = group['name'].replace('review-job', 'foreign-job')
    elif mutation == 'missing_uid': job.pop('uid')
    elif mutation == 'uid_type': job['uid'] = 1
    elif mutation == 'text': runnable['script'] = {'text': 'echo ready'}
    elif mutation == 'text_and_path': runnable['script']['text'] = 'echo ready'
    elif mutation == 'container': spec['runnables'][0] = {'container': {'imageUri': 'example/image:tag'}}
    elif mutation == 'script_and_container': runnable['container'] = {'imageUri': 'example/image:tag'}
    elif mutation in ('gs_uri', 'relative', 'traversal', 'encoded', 'env_path', 'outside', 'directory'):
        runnable['script']['path'] = {'gs_uri': 'gs://review-source/code/scripts/main.sh', 'relative': 'scripts/main.sh',
            'traversal': '/mnt/source/scripts/../scripts/main.sh', 'encoded': '/mnt/source/scripts/%6dain.sh',
            'env_path': '/mnt/source/${NAME}', 'outside': '/tmp/test.sh', 'directory': '/mnt/source/'}[mutation]
    elif mutation == 'remote_gs_uri': volume['gcs']['remotePath'] = 'gs://review-source/code/'
    elif mutation == 'foreign_remote': volume['gcs']['remotePath'] = 'foreign-source/code/'
    elif mutation == 'gcs_and_nfs': volume['nfs'] = {'server': '1.2.3.4', 'remotePath': '/x'}
    elif mutation == 'nfs_only': volume.pop('gcs'); volume['nfs'] = {'server': '1.2.3.4', 'remotePath': '/x'}
    elif mutation == 'mount_option': volume['mountOptions'] = ['--only-dir=other']
    elif mutation == 'mount_option_type': volume['mountOptions'] = ''
    elif mutation in ('duplicate_mount', 'shadow_mount', 'ancestor_mount', 'unrelated_malformed_volume'):
        spec['volumes'].append({'deviceName': 'disk0', 'mountPath': {'duplicate_mount': '/mnt/source',
            'shadow_mount': '/mnt/source/scripts', 'ancestor_mount': '/mnt', 'unrelated_malformed_volume': 3}[mutation]})
    elif mutation == 'missing_volume': spec.pop('volumes')
    elif mutation == 'volumes_type': spec['volumes'] = {}
    elif mutation == 'runnables_type': spec['runnables'] = {}
    elif mutation == 'extra_group': job['taskGroups'].append(deepcopy(group))
    elif mutation == 'wrong_prefix': volume['gcs']['remotePath'] = 'review-source/other/'
    saved, rows, trace = capture(monkeypatch, job=job)
    assert statuses(rows) == {'UNKNOWN'}
    assert [c[0] for c in trace.calls] == ['project', 'reference']
    assert all(r.closed for r in trace.responses)


@pytest.mark.parametrize('op', ['project', 'reference', 'bucket', 'latest', 'content'])
@pytest.mark.parametrize('code', [401, 403, 404, 429, 500])
def test_native_failure_and_private_errors(monkeypatch, op, code, capsys):
    def fault(current, n, data, response, transport):
        if current == op:
            response.status_code = code
            response.stream = io.BytesIO(TOKEN.encode())
    saved, rows, trace = capture(monkeypatch, fault=fault)
    assert statuses(rows) == {'UNKNOWN'} and all(r.closed for r in trace.responses)
    assert TOKEN not in json.dumps(saved) and AUTH not in json.dumps(saved)
    captured = capsys.readouterr(); assert TOKEN not in captured.out + captured.err


@pytest.mark.parametrize('mutation', [
    'foreign_project', 'foreign_bucket', 'numeric_bucket', 'generation_before', 'generation_after', 'size_after',
    'uid_after', 'path_after', 'volume_after', 'group_after', 'bucket_after', 'project_after', 'partial',
    'truncated_reference', 'truncated_media', 'redirect', 'history', 'duplicate_json', 'malformed_json', 'root_list',
    'length_missing', 'length_oversize', 'length_invalid', 'encoding', 'range', 'transfer', 'location', 'media_generation',
    'media_type', 'binary', 'archive', 'customer_encryption', 'content_encoding',
])
def test_native_binding_framing_changed_and_malformed(monkeypatch, mutation):
    def fault(op, n, data, response, transport):
        if mutation == 'foreign_project' and op == 'project': data['projectId'] = 'foreign'
        elif mutation == 'foreign_bucket' and op == 'bucket': data['projectNumber'] = '10002'
        elif mutation == 'numeric_bucket' and op == 'bucket': data['projectNumber'] = 10001
        elif mutation == 'generation_before' and op == 'latest': data['generation'] = '54321'
        elif mutation == 'generation_after' and op == 'latest' and n == 2: data['generation'] = '54321'
        elif mutation == 'size_after' and op == 'latest' and n == 2: data['size'] = '22'
        elif mutation.endswith('_after') and op == 'reference' and n == 2:
            if mutation == 'uid_after': data['uid'] += '-new'
            elif mutation == 'path_after': data['taskGroups'][0]['taskSpec']['runnables'][0]['script']['path'] = '/tmp/new'
            elif mutation == 'volume_after': data['taskGroups'][0]['taskSpec']['volumes'][0]['mountOptions'] = ['ro']
            elif mutation == 'group_after': data['taskGroups'][0]['name'] += '-new'
        elif mutation == 'bucket_after' and op == 'bucket' and n == 2: data['name'] = 'foreign'
        elif mutation == 'project_after' and op == 'project' and n == 2: data['name'] = 'projects/10002'
        elif mutation == 'partial' and op == 'reference': data['unreachable'] = ['x']
        elif mutation == 'media_generation' and op == 'content': response.headers['x-goog-generation'] = '54321'
        elif mutation == 'media_type' and op == 'content': response.headers['Content-Type'] = 'application/octet-stream'
        elif mutation == 'customer_encryption' and op == 'latest': data['customerEncryption'] = {'encryptionAlgorithm': 'AES256'}
        elif mutation == 'content_encoding' and op == 'latest': data['contentEncoding'] = 'gzip'
        if isinstance(data, dict):
            raw = json.dumps(data).encode(); response.stream = io.BytesIO(raw); response.headers['Content-Length'] = str(len(raw))
        if mutation in ('truncated_reference', 'truncated_media') and op == ('reference' if mutation.endswith('reference') else 'content'):
            response.stream = io.BytesIO(b'{}' if op == 'reference' else b'echo')
        elif mutation == 'redirect' and op == 'reference': response.final_url = 'https://evil.invalid/' + TOKEN
        elif mutation == 'history' and op == 'reference': response.history = [object()]
        elif mutation in ('duplicate_json', 'malformed_json', 'root_list') and op == 'reference':
            raw = {'duplicate_json': b'{"uid":"a","uid":"b"}', 'malformed_json': b'{', 'root_list': b'[]'}[mutation]
            response.stream = io.BytesIO(raw); response.headers['Content-Length'] = str(len(raw))
        elif mutation == 'length_missing' and op == 'reference': response.headers.pop('Content-Length')
        elif mutation == 'length_oversize' and op == 'reference': response.headers['Content-Length'] = str(source.MAX_METADATA + 1)
        elif mutation == 'length_invalid' and op == 'reference': response.headers['Content-Length'] = '+1'
        elif mutation == 'encoding' and op == 'reference': response.headers['Content-Encoding'] = 'gzip'
        elif mutation == 'range' and op == 'reference': response.headers['Content-Range'] = 'bytes 0-1/20'
        elif mutation == 'transfer' and op == 'reference': response.headers['Transfer-Encoding'] = 'chunked'
        elif mutation == 'location' and op == 'reference': response.headers['Location'] = 'https://evil.invalid/' + TOKEN
    payload = b'\x00binary' if mutation == 'binary' else b'PK\x03\x04archive' if mutation == 'archive' else b'echo ready\n'
    saved, rows, trace = capture(monkeypatch, payload=payload, fault=fault)
    assert statuses(rows) == {'UNKNOWN'}, (mutation, saved)
    assert all(r.closed for r in trace.responses) and TOKEN not in json.dumps(saved)


@pytest.mark.parametrize('option', [{'content_secret_scans': False}, {'content_secret_scans': True}])
@pytest.mark.parametrize('named', [[], ['gcp.review.batch_job.literal_configuration_secret_indicators'], ['exposure']])
def test_default_inventory_and_category_cannot_authorize(monkeypatch, option, named):
    option = {**option, '_content_secret_scan_kinds': [source.KIND], 'inventories': [source.KIND]}
    saved, rows, trace = capture(monkeypatch, options=option, named=named)
    assert rows == [] and trace.calls == [] and trace.auth == [] and saved['evidence']['authorized'] is False


@pytest.mark.parametrize('field,value', [('resource', []), ('task_group', True), ('task_group', 1), ('runnable', True),
    ('runnable', -1), ('runnable', 100), ('volume', '0'), ('bucket', 'a/b'), ('object', '../x'), ('object', 'x%2fy'),
    ('generation', 12345), ('generation', '01'), ('generation', '9223372036854775808')])
def test_selector_preflight_before_auth(monkeypatch, field, value):
    t = target(); t[field] = value
    with pytest.raises(source.Incomplete): capture(monkeypatch, targets=[t])


@pytest.mark.parametrize('case', ['duplicate', 'five', 'foreign_scope', 'extra_field', 'empty'])
def test_combined_target_bounds_before_auth(monkeypatch, case):
    t = target(); targets = [t]
    if case == 'duplicate': targets *= 2
    elif case == 'five': targets = [{**t, 'runnable': i} for i in range(5)]
    elif case == 'foreign_scope': t['resource'] = t['resource'].replace('review/', 'foreign/')
    elif case == 'extra_field': t['url'] = 'https://evil.invalid/'
    else: targets = []
    with pytest.raises(source.Incomplete): capture(monkeypatch, targets=targets)


@pytest.mark.parametrize('diagnostic', ['http', 'https', 'urllib3', 'logging'])
def test_unsafe_logging_before_credentials(monkeypatch, diagnostic, capsys):
    from urllib3.connection import HTTPSConnection
    if diagnostic == 'http': monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', 1)
    elif diagnostic == 'https': monkeypatch.setattr(http.client.HTTPSConnection, 'debuglevel', 1)
    elif diagnostic == 'urllib3': monkeypatch.setattr(HTTPSConnection, 'debuglevel', 1)
    else: monkeypatch.setattr(logging.getLogger('urllib3.connectionpool'), 'level', logging.DEBUG)
    saved, rows, trace = capture(monkeypatch)
    assert statuses(rows) == {'UNKNOWN'} and trace.auth == [] and trace.calls == []
    assert saved['evidence']['items'][0][source.MARKER]['reason'] == 'unsafe_http_diagnostics'
    assert AUTH not in json.dumps(saved)


def test_changed_principal_and_shared_call_budget(monkeypatch):
    saved, rows, trace = capture(monkeypatch, change_principal=True)
    assert statuses(rows) == {'UNKNOWN'} and len(trace.calls) == 2
    saved, rows, trace = capture(monkeypatch, options={'max_calls': 4})
    assert statuses(rows) == {'UNKNOWN'} and len(trace.calls) == 4


@pytest.mark.parametrize('hit', [False, True])
def test_four_native_targets_bounded_and_hmac_dedup(monkeypatch, hit):
    targets = [{**target(), 'resource': target()['resource'] + '-' + str(i)} for i in range(4)]
    saved, rows, trace = capture(monkeypatch, targets=targets, payload=('token=' + TOKEN).encode() if hit else b'echo ready\n')
    assert statuses(rows) == {'FAIL' if hit else 'PASS'} and len(trace.calls) == 36
    if hit:
        leaks = scanning.merge_leaks([l for _, r in rows for l in r['secret_leaks']])
        assert len(leaks) == 1 and len({loc['path'] for loc in leaks[0]['locations']}) == 4
        ordinary = scanning.scan_content(('token=' + TOKEN).encode(), 'ordinary-surface')
        assert len(scanning.merge_leaks(leaks + ordinary['leaks'])) == 1


def test_selected_offsets_prefix_and_native_id_alias(monkeypatch):
    job = json.loads(NATIVE.read_text()); spec = job['taskGroups'][0]['taskSpec']
    spec['runnables'].insert(0, {'script': {'text': 'ignored inline literal'}})
    spec['volumes'].insert(0, {'deviceName': 'disk0', 'mountPath': '/mnt/unrelated'})
    spec['volumes'][1]['mountOptions'] = []
    t = {**target(), 'runnable': 1, 'volume': 1}
    saved, rows, trace = capture(monkeypatch, targets=[t], job=job)
    assert statuses(rows) == {'PASS'}
    job['name'] = target()['resource']; job['taskGroups'][0]['name'] = job['name'] + '/taskGroups/group0'
    saved, rows, trace = capture(monkeypatch, targets=[t], job=job)
    assert statuses(rows) == {'PASS'}


def test_bucket_root_mount_native_form(monkeypatch):
    job = json.loads(NATIVE.read_text()); spec = job['taskGroups'][0]['taskSpec']
    spec['volumes'][0]['gcs']['remotePath'] = 'review-source'
    spec['runnables'][0]['script']['path'] = '/mnt/source/code/scripts/main.sh'
    saved, rows, _ = capture(monkeypatch, job=job)
    assert statuses(rows) == {'PASS'}


@pytest.mark.parametrize('mutation', ['capture', 'origin', 'method', 'operation', 'bound', 'status', 'principal', 'request',
    'version', 'engine', 'native_complete', 'executed_bytes', 'generation', 'association', 'duplicate', 'selection', 'scope'])
def test_consumer_rejects_tampering(monkeypatch, mutation):
    saved, rows, _ = capture(monkeypatch)
    evidence = saved['evidence']; item = evidence['items'][0]; marker = item[source.MARKER]; receipt = evidence['receipts'][1]
    if mutation == 'capture': marker['capture'] = '0' * 32
    elif mutation in ('origin', 'method', 'operation', 'principal', 'request'): receipt[mutation] = 'wrong'
    elif mutation in ('bound', 'status'): receipt[mutation] = False
    elif mutation == 'version': marker['parts'][0]['engines'][0]['version'] = '0.0.0'
    elif mutation == 'engine': marker['parts'][0]['engines'][0]['engine'] = 'unknown'
    elif mutation == 'native_complete': marker['native_complete'] = False
    elif mutation == 'executed_bytes': marker['executed_bytes_proven'] = True
    elif mutation == 'generation': marker['generation'] = 12345
    elif mutation == 'association': marker['association'] = None
    elif mutation == 'duplicate': evidence['receipts'].append(deepcopy(receipt))
    elif mutation == 'selection': evidence['selected'][SCOPE] = []
    elif mutation == 'scope': marker['scope'] = 'projects/foreign'
    assert consumer.evaluate(item, evidence, SCOPE)[0] == 'UNKNOWN'


def test_private_metadata_union_and_cleanup(monkeypatch):
    encoded = base64.b64encode(TOKEN.encode()).decode()
    metadata = {'one': TOKEN, 'encoded': encoded, TOKEN: 'synthetic'}
    saved, rows, trace = capture(monkeypatch, payload=('token=' + TOKEN).encode(), export_metadata=metadata)
    assert statuses(rows) == {'FAIL'}
    assert TOKEN in json.dumps(saved)  # found values stay visible
    assert not hasattr(trace.transport, '_batch_source_redactions')


def test_pinned_runner_flags_no_source_files(monkeypatch, tmp_path):
    original = scanning._run; argv = []
    def run(args, payload, timeout):
        argv.append(args)
        return original(args, payload, timeout)
    monkeypatch.setattr(scanning, '_run', run)
    monkeypatch.setenv('TMPDIR', str(tmp_path))
    scanning._trufflehog.cache_clear()
    saved, rows, _ = capture(monkeypatch, payload=('token=' + TOKEN).encode())
    assert statuses(rows) == {'FAIL'} and list(tmp_path.iterdir()) == []
    command, = [a for a in argv if 'stdin' in a]
    for flag in ('--no-verification', '--no-update', '--force-skip-archives', '--no-verification-cache', '--fail-on-scan-errors'):
        assert flag in command


@pytest.mark.parametrize('fault_name', ['deadline', 'cancelled', 'aggregate', 'invalid_stream', 'late_debug'])
def test_budget_cancellation_stream_and_late_privacy_guards(monkeypatch, fault_name):
    def fault(op, n, data, response, transport):
        if op == 'reference' and n == 1:
            if fault_name == 'deadline': transport.deadline = time.time() - 1
            elif fault_name == 'cancelled': transport.options['_cancel_check'] = lambda: True
            elif fault_name == 'aggregate': monkeypatch.setattr(source.reads, 'MAX_TOTAL', 1)
            elif fault_name == 'late_debug': monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', 1)
        if op == 'reference' and fault_name == 'invalid_stream':
            response.raw = SimpleNamespace(read=lambda *args, **kwargs: 'invalid')
    saved, rows, trace = capture(monkeypatch, fault=fault)
    assert statuses(rows) == {'UNKNOWN'} and all(r.closed for r in trace.responses)
    assert len(trace.calls) <= 3 and AUTH not in json.dumps(saved)


@pytest.mark.parametrize('hit', [False, True])
def test_other_invalid_target_prevents_clean_result_preserves_own_hit(monkeypatch, hit):
    targets = [{**target(), 'resource': target()['resource'] + '-' + str(i)} for i in range(2)]
    saved, rows, _ = capture(monkeypatch, targets=targets, payload=('token=' + TOKEN).encode() if hit else b'echo ready')
    evidence = saved['evidence']; evidence['items'][1][source.MARKER]['association'] = None
    result = consumer.evaluate(evidence['items'][0], evidence, SCOPE)
    assert result[0] == ('FAIL' if hit else 'UNKNOWN') and result[1]['complete'] is False


def test_failed_engine_union_value_scrubbed_without_trusting_hit(monkeypatch):
    def malformed(*args): return [(TOKEN, 'Synthetic', 1), (None, 'Synthetic', 1)]
    def clean(*args): return []
    monkeypatch.setattr(scanning, '_scan_kingfisher', malformed)
    monkeypatch.setattr(scanning, '_scan_trufflehog', clean)
    saved, rows, trace = capture(monkeypatch, payload=('token=' + TOKEN).encode(), export_metadata={'synthetic': TOKEN})
    assert statuses(rows) == {'UNKNOWN'} and saved['evidence']['items'][0][source.MARKER]['leaks'] == []
    assert TOKEN in json.dumps([saved, trace.transport.cache, trace.transport.evidence])


def test_native_session_disables_ambient_proxy_auth_and_cookie(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://evil.invalid')
    monkeypatch.setenv('NETRC', '/not-read')
    session = source.reads.git._session()
    try:
        assert session.trust_env is False and not session.cookies
        request = requests.Request('GET', 'https://batch.googleapis.com/v1/selected', headers={'Authorization': 'Bearer ' + AUTH})
        prepared = session.prepare_request(request)
        assert prepared.headers['Authorization'] == 'Bearer ' + AUTH
        assert 'Cookie' not in prepared.headers
    finally: session.close()


def test_immutable_native_proof_replays_through_actual_pure_consumer():
    root = Path(__file__).resolve().parents[1]
    proof = json.loads(gzip.decompress((root / 'docs/gcp-review/recheck-20261020/gcp_batch_referenced_source_20261020_proof.json.gz').read_bytes()))
    for case in proof['cases']:
        assert case['all_responses_closed'] and case['scanner_matches_cleared']
        evidence = case['evidence']
        actual = [consumer.evaluate(item, evidence, SCOPE)[0] for item in evidence['items']]
        assert actual == case['actual'] == [case['expected']]


def test_partial_consumer_rejects_hit_from_unavailable_engine(monkeypatch):
    def unavailable(*args): raise RuntimeError('synthetic unavailable')
    monkeypatch.setattr(scanning, '_scan_kingfisher', unavailable)
    saved, rows, _ = capture(monkeypatch, payload=('token=' + TOKEN).encode())
    assert statuses(rows) == {'FAIL'}
    evidence = saved['evidence']; item = evidence['items'][0]
    leaks = item[source.MARKER]['leaks']
    leaks[0]['detectors'].append({'engine': 'kingfisher', 'rule': 'Synthetic'})
    item[source.MARKER]['leaks'] = scanning.merge_leaks(leaks)
    assert consumer.evaluate(item, evidence, SCOPE)[0] == 'UNKNOWN'
