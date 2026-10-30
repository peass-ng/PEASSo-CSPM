"""Native fake TLS transport plus real, offline Kingfisher and TruffleHog.

No shared hooks/registration patches, scanner fakes, live auth, cloud or source
filesystem tampering. ZIP members exist only in memory.
"""
import base64
from copy import deepcopy
import io
import json
import socket
import time
from types import SimpleNamespace
from urllib.parse import quote
import zipfile

import pytest
from peaso import checks, secret_scanning
from peaso.collectors import azure
from peaso.collectors import azure_function_package_source_20261020 as source
from peaso.collectors import azure_selected_storage_secret_indicators as storage
from peaso.checks import azure_function_package_source_20261020 as consumer

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
OTHER = '/subscriptions/33333333-3333-3333-3333-333333333333'
TENANT = '22222222-2222-2222-2222-222222222222'
PRINCIPAL = '44444444-4444-4444-4444-444444444444'
SITE = SCOPE + '/resourceGroups/review/providers/Microsoft.Web/sites/selected-function'
ACCOUNT = SCOPE + '/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount'
VERSION = '2026-10-19T12:00:00.0000000Z'
SECRET = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
SAS = 'private-sas-do-not-retain'


def target(versioned=True):
    blob = {'service': 'blob', 'resource_id': ACCOUNT, 'container': 'packages',
            'object': 'release/function.zip', 'format': 'zip'}
    if versioned:
        blob['version'] = VERSION
    return {'site_resource_id': SITE, 'blob': blob}


def options(t=None):
    return {'content_secret_scans': True, source.OPTION: [t or target()]}


def package(hit=False, extra=None):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('host.json', b'{"version":"2.0"}')
        z.writestr('main.py', ('TOKEN=' + SECRET if hit else 'mode=ready').encode())
        if extra:
            z.writestr(*extra)
    return out.getvalue()


def jwt(audience, **claims):
    value = {'aud': audience, 'tid': TENANT, 'oid': PRINCIPAL, 'exp': time.time() + 3600, **claims}
    return 'eyJhbGciOiJub25lIn0.' + base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=') + '.b2ZmbGluZQ'


class Response:
    def __init__(self, payload, *, head=False, headers=None, status=200):
        raw = json.dumps(payload).encode() if isinstance(payload, dict) else payload
        self.status = status
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(raw)),
                        'x-ms-request-id': '11111111-1111-4111-8111-111111111111', **(headers or {})}
        self.stream = io.BytesIO(b'' if head else raw)
        self.closed = False
    def getheader(self, key):
        return self.headers.get(key)
    def read(self, size):
        assert 0 < size <= 16384
        return self.stream.read(size)
    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    attempts = []
    def blocked(*a, **kw):
        attempts.append('live-network-or-auth')
        raise AssertionError('Live network/auth forbidden')
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    secret_scanning._RESULTS.clear()
    registry = list(checks.CHECKS)
    yield
    assert list(checks.CHECKS) == registry
    assert not attempts
    secret_scanning._RESULTS.clear()


def capture(monkeypatch, *, t=None, hit=False, raw=None, fault=None, reference=None, hosting='function', claim_changes=None):
    t = t or target()
    payload = package(hit) if raw is None else raw
    trace = SimpleNamespace(calls=[], responses=[], connections=[], audiences=[])
    host, route = storage.data_route(t['blob'])
    url = 'https://' + host + route + ('&' if '?' in route else '?') + 'sv=2023-11-03&sp=r&sig=' + SAS
    if reference is not None:
        url = reference
    class Transport:
        tenant = TENANT
        verified_tenant = TENANT
        def token(self, audience):
            trace.audiences.append(audience)
            return jwt(audience, **(claim_changes(audience) if claim_changes else {}))
        def request(self, *a, **kw):
            pytest.fail('Generic transport/cache must never be used')
    class Connection:
        sock = None
        def __init__(self, origin, timeout):
            assert origin in ('management.azure.com', host)
            assert 0 < timeout <= 10
            self.host = origin
            self.closed = False
            trace.connections.append(self)
        def set_debuglevel(self, level):
            assert level == 0
        def request(self, method, path, body=None, headers=None):
            assert body is None
            assert headers['Accept-Encoding'] == 'identity'
            assert headers['Authorization'].startswith('Bearer ey')
            assert SAS not in path and SECRET not in json.dumps(headers)
            assert 'Range' not in headers and 'x-ms-encryption-key' not in headers
            if self.host == 'management.azure.com':
                if path == SCOPE + '?api-version=' + storage.SUB_VERSION:
                    op = 'subscription'
                    data = {'id': SCOPE, 'subscriptionId': SCOPE.rsplit('/', 1)[1], 'tenantId': TENANT, 'state': 'Enabled'}
                elif path == ACCOUNT + '?api-version=' + storage.ARM_VERSION:
                    op = 'account'
                    data = {'id': ACCOUNT, 'name': 'sourceaccount', 'type': 'Microsoft.Storage/storageAccounts',
                        'properties': {'provisioningState': 'Succeeded', 'primaryEndpoints': {'blob': 'https://' + host + '/'}}}
                elif path == SITE + '?api-version=' + source.SITE_VERSION:
                    op = 'site_before' if not any(c[0] == 'site_before' for c in trace.calls) else 'site_after'
                    data = {'id': SITE, 'name': 'selected-function', 'type': 'Microsoft.Web/sites',
                        'kind': 'functionapp' if hosting == 'function' else 'app',
                        'properties': {'reserved': False, 'siteConfig': {'windowsFxVersion': ''}}}
                elif path == SITE + '/config/appsettings/list?api-version=' + source.SITE_VERSION:
                    assert method == 'POST'
                    op = 'settings_before' if not any(c[0] == 'settings_before' for c in trace.calls) else 'settings_after'
                    data = {'id': SITE + '/config/appsettings', 'type': 'Microsoft.Web/sites/config', 'name': 'appsettings',
                            'properties': {'WEBSITE_RUN_FROM_PACKAGE': url, 'UNRELATED_SECRET': SECRET}}
                else:
                    pytest.fail('Unexpected ARM route')
                response = Response(data)
            else:
                assert path == route
                assert headers['x-ms-version'] == storage.DATA_VERSION
                if method == 'HEAD':
                    op = 'properties_before' if not any(c[0] == 'properties_before' for c in trace.calls) else 'properties_after'
                else:
                    assert method == 'GET' and headers['If-Match'] == '"0x123ABC"'
                    op = 'content'
                props = {'Content-Type': 'application/zip', 'ETag': '"0x123ABC"',
                         'x-ms-version': storage.DATA_VERSION, 'x-ms-blob-type': 'BlockBlob'}
                if 'version' in t['blob']:
                    props['x-ms-version-id'] = VERSION
                response = Response(payload, headers=props, head=method == 'HEAD')
            trace.calls.append((op, self.host, method, path))
            if fault:
                response = fault(op, response)
            self.response = response
            trace.responses.append(response)
        def getresponse(self):
            return self.response
        def close(self):
            self.closed = True
    monkeypatch.setattr(source.http.client, 'HTTPSConnection', Connection)
    reader = azure._Reader({'retries': 0})
    envelope = source.collect(reader, Transport(), [SCOPE], options(t), [source.CHECK],
        customer_context_id='customer-context', credential_context_id='credential-context')
    trace.reader = reader
    return envelope, trace


def evaluate(envelope, **change):
    return consumer.evaluate(envelope, source.identity(target()), **{
        'scope': SCOPE, 'expected_selection': envelope['selection'][SCOPE], 'expected_capture': envelope['capture'],
        'customer_context_id': 'customer-context', 'credential_context_id': 'credential-context', 'tenant_id': TENANT,
        **change})


@pytest.mark.parametrize('hit', [False, True])
@pytest.mark.parametrize('versioned', [False, True])
@pytest.mark.parametrize('hosting', ['function', 'app_service'])
def test_real_two_scanners_native_source(monkeypatch, hit, versioned, hosting):
    t = target(versioned)
    envelope, trace = capture(monkeypatch, t=t, hit=hit, hosting=hosting)
    row = consumer.evaluate(envelope, source.identity(t), scope=SCOPE,
        expected_selection=envelope['selection'][SCOPE], expected_capture=envelope['capture'],
        customer_context_id='customer-context', credential_context_id='credential-context', tenant_id=TENANT)
    assert row[0] == ('FAIL' if hit else 'PASS'), row
    assert row[1]['complete'] is True and row[1]['runtime_bytes'] == 'unknown'
    assert [c[0] for c in trace.calls] == list(source.OPERATIONS)
    for part in row[1]['parts']:
        assert {e['engine']: e['status'] for e in part['engines']} == {'kingfisher': 'complete', 'trufflehog': 'complete'}
    if hit:
        assert {d['engine'] for leak in row[1]['secret_leaks'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    retained = json.dumps([envelope, row, trace.reader.collections, trace.reader.metadata()])
    for private in (SECRET, SAS, 'WEBSITE_RUN_FROM_PACKAGE', 'UNRELATED_SECRET', SITE, 'function.zip', '"0x123ABC"'):
        assert private not in retained
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)
    assert not hasattr(trace.reader, 'storage_source_secret_redactions')


@pytest.mark.parametrize('op', source.OPERATIONS)
def test_denied_never_clean(monkeypatch, op):
    def denied(operation, response):
        if operation == op:
            response.status = 403
        return response
    envelope, trace = capture(monkeypatch, fault=denied)
    assert evaluate(envelope)[0] == 'UNKNOWN'
    assert not envelope['results'][0]['association_complete']
    assert all(r.closed for r in trace.responses)


@pytest.mark.parametrize('operation', ['content', 'properties_after'])
def test_etag_change_never_clean(monkeypatch, operation):
    def changed(op, response):
        if op == operation:
            response.headers['ETag'] = '"0xCHANGED"'
        return response
    envelope, _ = capture(monkeypatch, fault=changed)
    assert evaluate(envelope)[0] == 'UNKNOWN'


def test_settings_change_never_clean(monkeypatch):
    def changed(op, response):
        if op == 'settings_after':
            data = json.loads(response.stream.getvalue())
            data['properties']['WEBSITE_RUN_FROM_PACKAGE'] += 'changed'
            return Response(data)
        return response
    envelope, _ = capture(monkeypatch, fault=changed)
    assert evaluate(envelope)[0] == 'UNKNOWN'
    assert envelope['results'][0]['reason'] == 'package_reference_changed'


@pytest.mark.parametrize('reference', [
    '1', '@Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/package)',
    'https://public.example/package.zip?sig=' + SAS,
    'https://otheraccount.blob.core.windows.net/packages/release/function.zip',
    'https://sourceaccount.blob.core.windows.net/packages/other.zip',
    'https://sourceaccount.blob.core.windows.net:443/packages/release/function.zip',
    'https://sourceaccount.blob.core.windows.net/packages/release/%66unction.zip',
    'https://sourceaccount.blob.core.windows.net/packages/release/function.zip?snapshot=' + VERSION,
    'https://sourceaccount.blob.core.windows.net/packages/release/function.zip?versionid=' + VERSION + '&sig=x&sig=y',
    'https://sourceaccount.blob.core.windows.net/packages/release/function.zip?versionid=' + VERSION + '&unknown=x',
])
def test_reference_mismatch_no_data_fetch(monkeypatch, reference):
    envelope, trace = capture(monkeypatch, reference=reference)
    assert evaluate(envelope)[0] == 'UNKNOWN'
    assert not any(c[1].endswith('.blob.core.windows.net') for c in trace.calls)


@pytest.mark.parametrize('kind', ['truncated', 'partial_status', 'range', 'bad_copy', 'version', 'duplicate_json', 'account_scope', 'tenant'])
def test_partial_or_native_binding_failure(monkeypatch, kind):
    def fault(op, response):
        if kind == 'truncated' and op == 'content':
            response.stream = io.BytesIO(response.stream.getvalue()[:-1])
        if kind == 'partial_status' and op == 'content':
            response.status = 206
        if kind == 'range' and op == 'content':
            response.headers['Content-Range'] = 'bytes 0-100/200'
        if kind == 'bad_copy' and op == 'properties_before':
            response.headers['x-ms-copy-status'] = 'pending'
        if kind == 'version' and op == 'properties_before':
            response.headers['x-ms-version-id'] = '2026-10-18T12:00:00Z'
        if kind == 'duplicate_json' and op == 'settings_before':
            return Response(b'{"properties":{},"properties":{}}')
        if kind == 'account_scope' and op == 'account':
            data = json.loads(response.stream.getvalue())
            data['id'] = ACCOUNT.replace(SCOPE, OTHER)
            return Response(data)
        if kind == 'tenant' and op == 'subscription':
            data = json.loads(response.stream.getvalue())
            data['tenantId'] = PRINCIPAL
            return Response(data)
        return response
    envelope, _ = capture(monkeypatch, fault=fault)
    assert evaluate(envelope)[0] == 'UNKNOWN'


@pytest.mark.parametrize('hit', [False, True])
def test_partial_archive_real_scanners(monkeypatch, hit):
    envelope, _ = capture(monkeypatch, raw=package(hit, ('nested.zip', b'PKbad')))
    status, evidence = evaluate(envelope)
    assert status == ('FAIL' if hit else 'UNKNOWN')
    assert evidence['complete'] is False
    assert envelope['results'][0]['association_complete'] is True
    assert all(e['status'] == 'complete' for p in envelope['results'][0]['parts'] for e in p['engines'])


@pytest.mark.parametrize('changes', [
    {'customer_context_id': 'other'}, {'credential_context_id': 'other'},
    {'expected_capture': 'package-capture:' + '0' * 32}, {'tenant_id': PRINCIPAL},
    {'scope': OTHER}, {'expected_selection': []},
])
def test_context_replay_rejected(monkeypatch, changes):
    envelope, _ = capture(monkeypatch)
    assert evaluate(envelope, **changes)[0] == 'UNKNOWN'


def test_mutated_receipt_seal_rejected(monkeypatch):
    envelope, _ = capture(monkeypatch)
    envelope['receipts'][0]['bound'] = False
    assert evaluate(envelope)[0] == 'UNKNOWN'


@pytest.mark.parametrize('named, flag', [([], True), (['*'], True), ([source.CHECK, '*'], True), ([source.CHECK], False)])
def test_beforeauth_default_off(named, flag):
    opts = options()
    opts['content_secret_scans'] = flag
    opts['_content_secret_scan_kinds'] = [source.KIND]
    assert source.preflight(opts, [SCOPE], named) == []
    assert source.collect(object(), object(), [SCOPE], opts, named,
        customer_context_id='c', credential_context_id='x') is None


@pytest.mark.parametrize('change', ['crossscope', 'slot', 'duplicate', 'extra', 'badversion', 'sas_selection', 'file'])
def test_beforeauth_exact_selection_rejected(change):
    t = target()
    opts = options(t)
    if change == 'crossscope':
        opts[source.OPTION][0]['blob']['resource_id'] = ACCOUNT.replace(SCOPE, OTHER)
    elif change == 'slot':
        opts[source.OPTION][0]['site_resource_id'] += '/slots/private/config'
    elif change == 'duplicate':
        opts[source.OPTION].append(deepcopy(t))
    elif change == 'extra':
        opts[source.OPTION][0]['url'] = 'https://untrusted.example/package.zip'
    elif change == 'badversion':
        opts[source.OPTION][0]['blob']['version'] = 'latest'
    elif change == 'sas_selection':
        opts[source.OPTION][0]['blob']['object'] += '?sig=private'
    elif change == 'file':
        opts[source.OPTION][0]['blob']['service'] = 'file'
    with pytest.raises(source.Incomplete, match='invalid_selection'):
        source.preflight(opts, [SCOPE, OTHER], [source.CHECK])


def test_shared_service_account_beforeauth_denied():
    with pytest.raises(source.Incomplete, match='shared_service_account_forbidden'):
        source.collect(object(), object(), [SCOPE], options(), [source.CHECK],
            customer_context_id='c', credential_context_id='x', shared_service_account=True)


def test_principal_switch_rejected(monkeypatch):
    envelope, _ = capture(monkeypatch, claim_changes=lambda audience: {'oid': TENANT} if audience == storage.STORAGE else {})
    assert evaluate(envelope)[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['container', 'flex', 'missing_config', 'wrong_site', 'setting_alias', 'settings_partial'])
def test_unsupported_hosting_or_projection_unknown(monkeypatch, kind):
    def fault(op, response):
        if op not in ('site_before', 'settings_before'):
            return response
        data = json.loads(response.stream.getvalue())
        if op == 'site_before':
            if kind == 'container':
                data['kind'] = 'functionapp,container'
            elif kind == 'flex':
                data['properties']['functionAppConfig'] = {'runtime': {'name': 'python', 'version': '3.12'}}
            elif kind == 'missing_config':
                data['properties'].pop('siteConfig')
            elif kind == 'wrong_site':
                data['id'] += '-other'
        if op == 'settings_before':
            if kind == 'setting_alias':
                data['properties']['website_run_from_package'] = data['properties'].pop('WEBSITE_RUN_FROM_PACKAGE')
            elif kind == 'settings_partial':
                data['partial'] = True
        return Response(data)
    envelope, trace = capture(monkeypatch, fault=fault)
    assert evaluate(envelope)[0] == 'UNKNOWN'
    assert not any(c[1].endswith('.blob.core.windows.net') for c in trace.calls)


def test_sas_free_native_url_uses_only_object_oauth(monkeypatch):
    t = target()
    host, route = storage.data_route(t['blob'])
    envelope, trace = capture(monkeypatch, reference='https://' + host + route)
    assert evaluate(envelope)[0] == 'PASS'
    assert set(trace.audiences) == {storage.ARM, storage.STORAGE}


@pytest.mark.parametrize('hit', [False, True])
def test_unavailable_second_engine_never_complete(monkeypatch, hit):
    # First engine remains real. Second engine's binary resolution fails before
    # spawning; successful positive/clean tests above run both real engines.
    def unavailable():
        raise RuntimeError('scanner unavailable')
    monkeypatch.setattr(secret_scanning, '_trufflehog', unavailable)
    # Clean outcomes are reused per process; an earlier complete clean scan of
    # identical bytes must not stand in for this simulated engine outage.
    from peaso import secret_scan_clean
    with secret_scanning._RESULT_LOCK:
        monkeypatch.setattr(secret_scanning, '_RESULTS', type(secret_scanning._RESULTS)())
    with secret_scan_clean._LOCK:
        monkeypatch.setattr(secret_scan_clean, '_CLEAN', type(secret_scan_clean._CLEAN)())
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as z:
        z.writestr('main.py', ('TOKEN=' + SECRET if hit else 'mode=ready').encode())
    envelope, _ = capture(monkeypatch, raw=out.getvalue())
    status, evidence = evaluate(envelope)
    assert status == ('FAIL' if hit else 'UNKNOWN')
    assert evidence['complete'] is False


def test_data_and_archive_bounds_no_clean(monkeypatch):
    def excessive(op, response):
        if op == 'properties_before':
            response.headers['Content-Length'] = str(storage.MAX_OBJECT + 1)
        return response
    envelope, _ = capture(monkeypatch, fault=excessive)
    assert evaluate(envelope)[0] == 'UNKNOWN'


def test_explicit_selection_without_flag_does_not_authorize():
    opts = {source.OPTION: [target()]}
    assert source.preflight(opts, [SCOPE], [source.CHECK]) == []


def test_malformed_selection_is_rejected_while_off():
    with pytest.raises(source.Incomplete, match='invalid_selection'):
        source.preflight({'content_secret_scans': False, source.OPTION: 'all'}, [SCOPE], [])


def test_isolation_guard_before_transport():
    reader = azure._Reader({'retries': 0})
    reader.collections.append({'metadata': 'mixed'})
    with pytest.raises(source.Incomplete, match='isolated_reader_required'):
        source.collect(reader, object(), [SCOPE], options(), [source.CHECK],
            customer_context_id='c', credential_context_id='x')
