"""Real pinned offline detectors through fake native HTTP -> actual Transport.

No auth, sockets, generic source receipts, registry patches or scan mocks on the
positive/negative native path. Source and credential canaries stay transient.
"""
from copy import deepcopy
import hashlib
import http.client
import io
import json
import logging
from pathlib import Path
import socket
from types import SimpleNamespace
import zipfile
import tarfile
import pytest
import requests
from peaso import secret_scanning as scanning
from peaso.collectors import gcp
from peaso.collectors import gcp_dataflow_referenced_source_20261020 as source
from peaso.checks import gcp_dataflow_referenced_source_20261020 as consumer

SCOPE = 'projects/review'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'inert-dataflow-oauth-canary'


def target(format='text'):
    return dict(resource=SCOPE + '/locations/us-central1/jobs/2026-10-20_01_23_45-123456789',
                worker_pool=0, package=0, name='workflow.py', bucket='review-source',
                object='staged/workflow.py', generation='12345', format=format)


def native(t, payload):
    return dict(projectId='review', id=t['resource'].split('/')[-1], location='us-central1',
                createTime='2026-10-20T01:23:45Z', currentState='JOB_STATE_DONE',
                environment={'workerPools': [{'packages': [{'name': t['name'],
                    'location': 'storage.googleapis.com/' + t['bucket'] + '/' + t['object'],
                    'sha256': hashlib.sha256(payload).hexdigest()}]}]},
                labels={'private': TOKEN}, steps=[{'properties': {'private': TOKEN}}])


class Response:
    def __init__(self, data, status=200, headers=None):
        self.payload = json.dumps(data).encode() if isinstance(data, dict) else data
        self.status_code, self.url, self.history = status, '', []
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.payload)), **(headers or {})}
        self.raw = self
        self.stream = io.BytesIO(self.payload)
        self.closed = False

    def read(self, size, *, decode_content):
        assert decode_content is False and 0 < size <= 16384
        return self.stream.read(size)

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a, **k):
        pytest.fail('Live network or credentials forbidden')
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex'):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(gcp, 'Credentials', blocked)
    monkeypatch.setattr(gcp.Transport, 'request', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def capture(monkeypatch, payload=b'mode = "ready"\n', *, targets=None, fault=None, options=None, checks=None, credentials=None, transport_options=None):
    targets = deepcopy(targets or [target()])
    opts = {'content_secret_scans': True, source.OPTION: targets, **(options or {})}
    auth_calls, calls, responses, sessions = [], [], [], []
    def headers():
        auth_calls.append(True)
        return {'Authorization': 'Bearer ' + AUTH}
    transport = gcp.Transport(SimpleNamespace(headers=credentials or headers), {'retries': 0, **(transport_options or {})})
    def request(method, url, **kw):
        assert method == 'GET' and kw['stream'] is True and kw['allow_redirects'] is False
        assert kw['headers']['Authorization'].startswith('Bearer ')
        assert kw['headers']['Accept-Encoding'] == 'identity' and kw['headers']['Cache-Control'] == 'no-store'
        assert 0 < kw['timeout'] <= 20
        op = source.OPERATIONS[len(calls) % 9]
        t = targets[min(len(calls) // 9, len(targets) - 1)]
        mime = 'text/x-python' if t['format'] == 'text' else sorted(source.archives.MIME_TYPES[t['format']])[0]
        if op.startswith('project_'):
            assert url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE
            data = {'name': 'projects/123456789', 'projectId': 'review', 'state': 'ACTIVE'}
        elif op.startswith('reference_'):
            assert url == 'https://dataflow.googleapis.com/v1b3/' + t['resource']
            assert kw['params'] == {'view': 'JOB_VIEW_ALL'}
            data = native(t, payload)
        elif op.startswith('bucket_'):
            assert url == 'https://storage.googleapis.com/storage/v1/b/' + t['bucket']
            data = {'name': t['bucket'], 'projectNumber': '123456789'}
        elif op.startswith('latest_'):
            assert 'generation' not in kw['params'] and 'ifGenerationMatch' not in kw['params']
            data = dict(bucket=t['bucket'], name=t['object'], generation=t['generation'], size=str(len(payload)), contentType=mime)
        else:
            assert kw['params'] == {'generation': t['generation'], 'ifGenerationMatch': t['generation'], 'alt': 'media'}
            data = payload
        resp = Response(data, headers={'Content-Type': mime, 'X-Goog-Generation': t['generation']} if op == 'content' else None)
        if fault:
            fault(op, data, resp)
        resp.url = requests.Request(method, url, params=kw['params']).prepare().url
        if getattr(resp, 'redirect', False):
            resp.url = 'https://never-follow.invalid/private'
        calls.append((op, method, url, deepcopy(kw['params'])))
        responses.append(resp)
        return resp
    monkeypatch.setattr(source.git, '_session', lambda: SimpleNamespace(request=request, close=lambda: sessions.append(True)))
    result = source.capture(transport, [SCOPE], opts, [source.CHECK] if checks is None else checks)
    verdicts = [consumer.evaluate(item, result) for item in result['items']]
    assert all(r.closed for r in responses) and len(sessions) == len(responses)
    assert transport.cache == {} and transport.evidence == []
    return result, verdicts, calls, auth_calls


@pytest.mark.parametrize('secret', [True, False])
def test_real_detectors_native_http_transport_producer_consumer(monkeypatch, secret):
    payload = ('github_token = "' + TOKEN + '"\n' if secret else 'mode = "ready"\n').encode()
    result, rows, calls, auth = capture(monkeypatch, payload)
    verdict, evidence = rows[0]
    assert verdict == ('FAIL' if secret else 'PASS') and evidence['complete'] is True
    assert [c[0] for c in calls] == list(source.OPERATIONS) and len(auth) == 9
    assert evidence['executed_bytes_proven'] is False and evidence['credential_validation'] == 'not_attempted'
    assert evidence['parts'][0]['engines'] == [
        {'engine': 'kingfisher', 'version': '1.4.0', 'status': 'complete'},
        {'engine': 'trufflehog', 'version': '3.92.5', 'status': 'complete'}]
    if secret:
        leak, = evidence['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
        assert leak['fingerprint'] == scanning._fingerprint(TOKEN)
    assert TOKEN not in json.dumps(result) and AUTH not in json.dumps(result)
    assert 'workflow.py' not in json.dumps(result) and 'storage.googleapis.com/review-source' not in json.dumps(result)


@pytest.mark.parametrize('mutation', ['project', 'location', 'id', 'created', 'name', 'uri', 'sha256', 'pending',
    'missing_environment', 'partial', 'ownership', 'generation', 'object', 'bucket', 'encryption', 'mime',
    'reference_after', 'project_after', 'bucket_after', 'latest_after', 'denied', 'notfound', 'truncated',
    'encoding', 'range', 'chunked', 'redirect', 'media_generation', 'oversize', 'duplicate_json', 'error_body'])
def test_native_faults_never_make_clean_pass(monkeypatch, mutation):
    def fault(op, data, resp):
        if op == 'reference_before':
            if mutation in {'project', 'location', 'id', 'created'}:
                data[{'project': 'projectId', 'location': 'location', 'id': 'id', 'created': 'createTime'}[mutation]] = 'wrong'
            if mutation in {'name', 'uri', 'sha256'}:
                data['environment']['workerPools'][0]['packages'][0][{'uri': 'location'}.get(mutation, mutation)] = 'wrong'
            if mutation == 'pending': data['currentState'] = 'JOB_STATE_PENDING'
            if mutation == 'missing_environment': data.pop('environment')
            if mutation == 'partial': data['nextPageToken'] = 'never-follow'
            if mutation == 'denied': resp.status_code = 403
            if mutation == 'notfound': resp.status_code = 404
            if mutation == 'duplicate_json':
                resp.stream = io.BytesIO(b'{"id":"a","id":"b"}')
                resp.headers['Content-Length'] = '19'
                return
            if mutation == 'error_body': data['error'] = {'message': TOKEN}
        if op == 'bucket_before' and mutation == 'ownership': data['projectNumber'] = '987654321'
        if op == 'latest_before':
            if mutation in {'generation', 'object', 'bucket'}: data[{'object': 'name'}.get(mutation, mutation)] = 'wrong'
            if mutation == 'encryption': data['customerEncryption'] = {'keySha256': TOKEN}
            if mutation == 'mime': data['contentType'] = 'application/octet-stream'
            if mutation == 'oversize': data['size'] = str(source.MAX_CONTENT + 1)
        if op == 'reference_after' and mutation == 'reference_after':
            data['createTime'] = '2026-10-20T02:23:45Z'
        if op == 'project_after' and mutation == 'project_after': data['name'] = 'projects/987654321'
        if op == 'bucket_after' and mutation == 'bucket_after': data['projectNumber'] = '987654321'
        if op == 'latest_after' and mutation == 'latest_after': data['generation'] = '54321'
        if isinstance(data, dict):
            raw = json.dumps(data).encode()
            resp.stream, resp.headers['Content-Length'] = io.BytesIO(raw), str(len(raw))
        if op == 'content':
            if mutation == 'truncated': resp.stream = io.BytesIO(data[:-1])
            if mutation == 'encoding': resp.headers['Content-Encoding'] = 'gzip'
            if mutation == 'range': resp.headers['Content-Range'] = 'bytes 0-2/3'
            if mutation == 'chunked': resp.headers['Transfer-Encoding'] = 'chunked'
            if mutation == 'redirect': resp.redirect = True
            if mutation == 'media_generation': resp.headers['X-Goog-Generation'] = '54321'
    result, rows, calls, _ = capture(monkeypatch, fault=fault)
    assert rows[0][0] == 'UNKNOWN' and not rows[0][1]['complete']
    assert result['items'][0]['native_complete'] is False
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize('mutation', ['flag', 'no_checks', 'category', 'kind', 'wrong_check', 'multiple_checks'])
def test_exact_named_opt_in_before_auth(monkeypatch, mutation):
    opts, checks = {}, [source.CHECK]
    if mutation == 'flag': opts['content_secret_scans'] = False
    if mutation == 'no_checks': checks = []
    if mutation == 'category': checks = ['exposure']
    if mutation == 'kind': checks = ['dataflow_selected_package_source']; opts['_content_secret_scan_kinds'] = ['dataflow_selected_package_source']
    if mutation == 'wrong_check': checks = ['gcp.review.gcs.selected_object_secret_indicators']
    if mutation == 'multiple_checks': checks = [source.CHECK, 'other']
    result, rows, calls, auth = capture(monkeypatch, options=opts, checks=checks)
    assert not result['authorized'] and rows == calls == auth == []


@pytest.mark.parametrize('mutation', ['empty', 'five', 'duplicate_slot', 'scope', 'bool_index', 'out_index', 'extra',
    'unsafe_object', 'prefix', 'generation', 'generation_overflow', 'format', 'flag_type'])
def test_invalid_selection_before_auth(monkeypatch, mutation):
    t, opts = target(), {'content_secret_scans': True}
    targets = [t]
    if mutation == 'empty': targets = []
    if mutation == 'five': targets = [deepcopy(t) for _ in range(5)]
    if mutation == 'duplicate_slot': targets = [t, {**t, 'format': 'zip'}]
    if mutation == 'scope': t['resource'] = t['resource'].replace('projects/review', 'projects/other-project')
    if mutation == 'bool_index': t['package'] = True
    if mutation == 'out_index': t['worker_pool'] = 100
    if mutation == 'extra': t['url'] = 'https://never-follow.invalid'
    if mutation == 'unsafe_object': t['object'] = '../source.py'
    if mutation == 'prefix': t['object'] = 'staged/'
    if mutation == 'generation': t['generation'] = '0'
    if mutation == 'generation_overflow': t['generation'] = '9223372036854775808'
    if mutation == 'format': t['format'] = 'jar'
    if mutation == 'flag_type': opts['content_secret_scans'] = 'true'
    opts[source.OPTION] = targets
    class NoAuth:
        def __getattribute__(self, name): pytest.fail('Invalid selection touched transport')
    with pytest.raises((source.Incomplete, UnicodeError)):
        source.capture(NoAuth(), [SCOPE], opts, [source.CHECK])


def archive_payload(format, entries):
    out = io.BytesIO()
    if format == 'zip':
        with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for name, value in entries: z.writestr(name, value)
    else:
        with tarfile.open(fileobj=out, mode='w:gz' if format == 'tar.gz' else 'w', format=tarfile.USTAR_FORMAT) as t:
            for name, value in entries:
                info = tarfile.TarInfo(name); info.size = len(value); info.mtime = 0
                t.addfile(info, io.BytesIO(value))
    return out.getvalue()


@pytest.mark.parametrize('format', ['zip', 'tar', 'tar.gz'])
@pytest.mark.parametrize('secret', [True, False])
def test_real_detectors_archives_shared_hmac_no_extraction(monkeypatch, format, secret):
    raw = ('token="' + TOKEN + '"\n' if secret else 'mode="ready"\n').encode()
    payload = archive_payload(format, [('source.py', raw), ('config.py', raw)])
    result, rows, _, _ = capture(monkeypatch, payload, targets=[target(format)])
    verdict, evidence = rows[0]
    assert verdict == ('FAIL' if secret else 'PASS') and evidence['complete'] is True
    assert len(evidence['parts']) == 2
    if secret:
        leak, = evidence['secret_leaks']
        assert leak['fingerprint'] == scanning._fingerprint(TOKEN) and len(leak['locations']) == 2
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in json.dumps(result) and 'source.py' not in json.dumps(result)


@pytest.mark.parametrize('secret', [True, False])
@pytest.mark.parametrize('unavailable', ['kingfisher', 'trufflehog'])
def test_one_actual_detector_partial_positive_fail_negative_unknown(monkeypatch, secret, unavailable):
    def failed(*a, **kw): raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_' + unavailable, failed)
    raw = ('token="' + TOKEN + '"\n' if secret else 'mode="ready"\n').encode()
    result, rows, _, _ = capture(monkeypatch, raw)
    assert rows[0][0] == ('FAIL' if secret else 'UNKNOWN') and rows[0][1]['complete'] is False
    assert result['items'][0]['native_complete'] is True
    if secret:
        leak, = rows[0][1]['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == ({'kingfisher', 'trufflehog'} - {unavailable})
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize('secret', [True, False])
@pytest.mark.parametrize('format', ['zip', 'tar', 'tar.gz'])
def test_trusted_archive_partial_hits_survive_later_binary(monkeypatch, secret, format):
    raw = ('token="' + TOKEN + '"\n' if secret else 'mode="ready"\n').encode()
    payload = archive_payload(format, [('source.py', raw), ('unsupported.pyc', b'\x00\xff')])
    result, rows, _, _ = capture(monkeypatch, payload, targets=[target(format)])
    assert rows[0][0] == ('FAIL' if secret else 'UNKNOWN') and rows[0][1]['complete'] is False
    assert result['items'][0]['native_complete'] is True


@pytest.mark.parametrize('mode', ['http', 'https', 'urllib3', 'logger'])
def test_private_http_logging_rejected_before_auth(monkeypatch, mode):
    if mode in {'http', 'https'}:
        monkeypatch.setattr(http.client.HTTPConnection if mode == 'http' else http.client.HTTPSConnection, 'debuglevel', 1)
    elif mode == 'urllib3':
        from urllib3.connection import HTTPSConnection
        monkeypatch.setattr(HTTPSConnection, 'debuglevel', 1)
    else:
        monkeypatch.setattr(logging.getLogger('urllib3.connectionpool'), 'isEnabledFor', lambda level: True)
    result, rows, calls, auth = capture(monkeypatch)
    assert rows[0][0] == 'UNKNOWN' and calls == auth == []
    assert TOKEN not in json.dumps(result)


def test_principal_change_rejected_and_no_exception_disclosure(monkeypatch, caplog, capsys):
    count = [0]
    def headers():
        count[0] += 1
        return {'Authorization': 'Bearer ' + (AUTH if count[0] < 5 else 'different-principal')}
    result, rows, _, _ = capture(monkeypatch, credentials=headers)
    assert rows[0][0] == 'UNKNOWN'
    assert AUTH not in json.dumps(result) and TOKEN not in json.dumps(result)
    assert not caplog.records and capsys.readouterr() == ('', '')


@pytest.mark.parametrize('mutation', ['authorization', 'capture', 'identity', 'scope', 'native', 'principal', 'receipt',
    'operation', 'origin', 'bound', 'bytes', 'engine', 'leak_path', 'executed', 'validation', 'reason'])
def test_consumer_rejects_tampered_capture(monkeypatch, mutation):
    result, rows, _, _ = capture(monkeypatch, ('token="' + TOKEN + '"\n').encode())
    assert rows[0][0] == 'FAIL'
    item = result['items'][0]
    if mutation == 'authorization': result['authorized'] = False
    if mutation == 'capture': item['capture'] = 'f' * 32
    if mutation == 'identity': item['identity'] = 'dataflow-source:' + 'f' * 64
    if mutation == 'scope': item['scope'] = 'projects/other-project'
    if mutation == 'native': item['native_complete'] = False
    if mutation == 'principal': result['receipts'][0]['principal'] = 'f' * 64
    if mutation == 'receipt': result['receipts'].pop()
    if mutation == 'operation': result['receipts'][0]['operation'] = 'list'
    if mutation == 'origin': result['receipts'][0]['origin'] = 'never-follow.invalid'
    if mutation == 'bound': result['receipts'][0]['bound'] = False
    if mutation == 'bytes': item['source_bytes'] += 1
    if mutation == 'engine': item['parts'][0]['engines'][0]['version'] = 'wrong'
    if mutation == 'leak_path': item['leaks'][0]['locations'][0]['path'] = TOKEN
    if mutation == 'executed': item['executed_bytes_proven'] = True
    if mutation == 'validation': item['credential_validation'] = 'attempted'
    if mutation == 'reason': item['reason'] = TOKEN
    assert consumer.evaluate(item, result)[0] == 'UNKNOWN'


def test_bounds_cancel_and_call_limits_without_auth(monkeypatch):
    for options in ({'max_calls': 1}, {'_cancel_check': lambda: True}):
        result, rows, calls, _ = capture(monkeypatch, transport_options=options)
        assert rows[0][0] == 'UNKNOWN' and len(calls) <= 1


def test_multiple_native_packages_dedup_and_four_target_bound(monkeypatch):
    targets = []
    for i in range(4):
        t = target(); t['resource'] += str(i); targets.append(t)
    result, rows, calls, _ = capture(monkeypatch, ('token="' + TOKEN + '"\n').encode(), targets=targets)
    assert len(calls) == 36 and len(rows) == 4 and all(r[0] == 'FAIL' for r in rows)
    leak, = scanning.merge_leaks([l for _, e in rows for l in e['secret_leaks']])
    assert len(leak['locations']) == 4 and leak['fingerprint'] == scanning._fingerprint(TOKEN)






@pytest.mark.parametrize('format', ['zip', 'tar', 'tar.gz'])
def test_cross_member_partial_engine_dedup_retains_trusted_hit(monkeypatch, format):
    actual = scanning._scan_kingfisher
    count = [0]
    def sometimes(payload, path, timeout):
        count[0] += 1
        if count[0] > 1: raise RuntimeError('offline injected failure')
        return actual(payload, path, timeout)
    monkeypatch.setattr(scanning, '_scan_kingfisher', sometimes)
    raw = ('token="' + TOKEN + '"\n').encode()
    payload = archive_payload(format, [('a.py', raw), ('b.py', raw)])
    _, rows, _, _ = capture(monkeypatch, payload, targets=[target(format)])
    assert rows[0][0] == 'FAIL' and rows[0][1]['complete'] is False
    leak, = rows[0][1]['secret_leaks']
    assert len(leak['locations']) == 2


@pytest.mark.parametrize('mode', ['unsafe_path', 'nested', 'bomb', 'trailing'])
def test_archive_format_and_expansion_bounds(monkeypatch, mode):
    entries = [('source.py', b'mode="ready"\n')]
    if mode == 'unsafe_path': entries = [('../source.py', b'anything')]
    if mode == 'nested': entries = [('nested.zip', b'PK\x03\x04')]
    if mode == 'bomb': entries = [('large.txt', b'x' * (source.archives.MAX_EXPANDED_BYTES + 1))]
    raw = archive_payload('zip', entries)
    if mode == 'trailing': raw += b'trailing'
    result, rows, _, _ = capture(monkeypatch, raw, targets=[target('zip')])
    assert rows[0][0] == 'UNKNOWN' and not result['items'][0]['complete']


def test_native_fixture_reference_and_receipt_cases():
    fixture = json.loads(Path('tests/gcp_dataflow_referenced_source_20261020_native_fixtures.json').read_text())
    for case in fixture['reference_cases']:
        if case['valid']:
            assert source.reference(case['native'], case['target'])[0]
        else:
            with pytest.raises(source.Incomplete): source.reference(case['native'], case['target'])
    receipts = json.loads(Path('tests/gcp_dataflow_referenced_source_20261020_receipt_fixtures.json').read_text())
    for case in receipts['cases']:
        assert consumer.evaluate(case['capture']['items'][0], case['capture'])[0] == case['expected_verdict']


def test_no_source_persistence_and_no_private_error_logs(monkeypatch, caplog, capsys):
    import builtins
    actual_open = builtins.open
    def read_only(file, mode='r', *args, **kwargs):
        assert not any(c in mode for c in 'wax+')
        return actual_open(file, mode, *args, **kwargs)
    monkeypatch.setattr(builtins, 'open', read_only)
    def forbidden(*a, **k): pytest.fail('Extraction or source-byte persistence forbidden')
    monkeypatch.setattr(Path, 'write_bytes', forbidden)
    monkeypatch.setattr(Path, 'write_text', forbidden)
    monkeypatch.setattr(zipfile.ZipFile, 'extractall', forbidden)
    monkeypatch.setattr(tarfile.TarFile, 'extractall', forbidden)
    raw = archive_payload('zip', [('source.py', ('token="' + TOKEN + '"\n').encode())])
    result, rows, _, _ = capture(monkeypatch, raw, targets=[target('zip')])
    assert rows[0][0] == 'FAIL'
    assert TOKEN not in json.dumps(result) and AUTH not in json.dumps(result)
    assert not caplog.records and capsys.readouterr() == ('', '')


@pytest.mark.parametrize('operation', source.OPERATIONS)
def test_each_native_permission_denial_is_unknown_private(monkeypatch, operation, caplog, capsys):
    def denied(op, data, resp):
        if op == operation:
            resp.status_code = 403
            resp.stream = io.BytesIO(TOKEN.encode())
    result, rows, _, _ = capture(monkeypatch, fault=denied)
    assert rows[0][0] == 'UNKNOWN' and not result['items'][0]['native_complete']
    assert TOKEN not in json.dumps(result) and AUTH not in json.dumps(result)
    assert not caplog.records and capsys.readouterr() == ('', '')


def test_missing_or_malformed_other_selection_prevents_clean_pass(monkeypatch):
    targets = [target(), {**target(), 'resource': target()['resource'] + '2'}]
    result, rows, _, _ = capture(monkeypatch, targets=targets)
    assert all(r[0] == 'PASS' for r in rows)
    first = result['items'][0]
    result['items'][1]['parts'][0]['engines'][0]['version'] = 'wrong'
    assert consumer.evaluate(first, result)[0] == 'UNKNOWN'
    result['items'].pop()
    assert consumer.evaluate(first, result)[0] == 'UNKNOWN'
