"""Actual engine, native fake HTTPS and installed offline dual scanners."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from peaso import engine, secret_scanning, snapshot as snapshots
from peaso import azure_function_package_index_20261020 as owner
from peaso.collectors import azure
from peaso.collectors import azure_function_package_integration_20261020 as runtime
from peaso.collectors import azure_function_package_source_20261020 as source
from peaso.checks import azure_function_package_integration_admission_20261020 as admission
from peaso.checks import azure_function_package_integrated_consumer_20261020 as consumer
from peaso.server.validation import validate_connector
from tests import test_azure_function_package_source_20261020 as native

ROOT = Path(__file__).resolve().parents[1]
CAPTURED = []


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    yield from native.offline.__wrapped__(monkeypatch)


def request(**extra):
    return {'connector': {'provider': 'azure', 'scopes': [native.SCOPE],
        'auth': {'method': 'token', 'tenant_id': native.TENANT,
                 'arm_token': native.jwt(azure.ARM), 'storage_token': native.jwt(azure.STORAGE)},
        'options': native.options()}, 'checks': [runtime.CHECK], **extra}


def http_fixture(monkeypatch, *, hit=False, partial=False, fault=None, hosting='function', reference=None, sibling_secret=None, raw=None):
    t = native.target()
    payload = native.package(hit, ('nested.zip', b'PKbad') if partial else None) if raw is None else raw
    host, route = source.storage.data_route(t['blob'])
    url = reference or 'https://' + host + route + '&sv=2023-11-03&sp=r&sig=' + native.SAS
    trace = SimpleNamespace(calls=[], connections=[], responses=[])

    class Connection:
        sock = None

        def __init__(self, origin, timeout):
            assert origin in ('management.azure.com', host) and 0 < timeout <= 10
            self.host, self.closed = origin, False
            trace.connections.append(self)

        def set_debuglevel(self, level):
            assert level == 0

        def request(self, method, path, body=None, headers=None):
            assert body is None and headers['Accept-Encoding'] == 'identity'
            assert native.SAS not in path and native.SECRET not in json.dumps(headers)
            assert headers['Authorization'].startswith('Bearer ey')
            if self.host == 'management.azure.com':
                if path == native.SCOPE + '?api-version=' + source.storage.SUB_VERSION:
                    op = 'subscription'
                    data = {'id': native.SCOPE, 'subscriptionId': native.SCOPE.rsplit('/', 1)[1],
                            'tenantId': native.TENANT, 'state': 'Enabled'}
                elif path == native.ACCOUNT + '?api-version=' + source.storage.ARM_VERSION:
                    op = 'account'
                    data = {'id': native.ACCOUNT, 'name': 'sourceaccount', 'type': 'Microsoft.Storage/storageAccounts',
                            'properties': {'provisioningState': 'Succeeded', 'primaryEndpoints': {'blob': 'https://' + host + '/'}}}
                elif path == native.SITE + '?api-version=' + source.SITE_VERSION:
                    op = 'site_after' if any(x[0] == 'site_before' for x in trace.calls) else 'site_before'
                    data = {'id': native.SITE, 'name': 'selected-function', 'type': 'Microsoft.Web/sites',
                            'kind': 'functionapp' if hosting == 'function' else 'app',
                            'properties': {'reserved': False, 'siteConfig': {'windowsFxVersion': ''}}}
                elif path == native.SITE + '/config/appsettings/list?api-version=' + source.SITE_VERSION:
                    assert method == 'POST'
                    op = 'settings_after' if any(x[0] == 'settings_before' for x in trace.calls) else 'settings_before'
                    data = {'id': native.SITE + '/config/appsettings', 'type': 'Microsoft.Web/sites/config',
                            'name': 'appsettings', 'properties': {'WEBSITE_RUN_FROM_PACKAGE': url,
                            'UNRELATED_SECRET': sibling_secret or native.SECRET}}
                else:
                    raise AssertionError('Unexpected ARM request')
                response = native.Response(data)
            else:
                assert path == route
                op = ('properties_after' if any(x[0] == 'properties_before' for x in trace.calls) else 'properties_before') if method == 'HEAD' else 'content'
                if method != 'HEAD':
                    assert method == 'GET' and headers['If-Match'] == '"0x123ABC"'
                props = {'Content-Type': 'application/zip', 'ETag': '"0x123ABC"',
                    'x-ms-version': source.storage.DATA_VERSION, 'x-ms-blob-type': 'BlockBlob',
                    'x-ms-version-id': native.VERSION}
                response = native.Response(payload, headers=props, head=method == 'HEAD')
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
    return trace


def findings(snapshot):
    return engine.evaluate_snapshot(snapshot, checks=[runtime.CHECK])['findings']


@pytest.mark.parametrize('hit,partial,status', [(False, False, 'PASS'), (True, False, 'FAIL'),
    (False, True, 'UNKNOWN'), (True, True, 'FAIL')])
def test_actual_engine_native_and_both_detectors(monkeypatch, hit, partial, status):
    trace = http_fixture(monkeypatch, hit=hit, partial=partial)
    snapshot = engine.collect_snapshot(request())
    result = findings(snapshot)
    assert result and any(row['status'] == status for row in result)
    assert {row['status'] for row in result} <= {status, 'UNKNOWN'}
    assert [c[0] for c in trace.calls] == list(source.OPERATIONS)
    assert all(c.closed for c in trace.connections) and all(r.closed for r in trace.responses)
    assert snapshot['metadata']['calls'] == 9
    if hit:
        positive, = [row for row in result if row['status'] == 'FAIL']
        assert positive['id'].startswith('secret-')
        assert positive['linked_check_ids'] == [runtime.CHECK]
        assert {d['engine'] for leak in positive['evidence']['secret_leaks'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
        if partial:
            assert positive['evidence']['complete'] is False
    for private in (native.SECRET, native.SAS, native.SITE, 'function.zip', 'WEBSITE_RUN_FROM_PACKAGE', 'Bearer '):
        assert private not in json.dumps([snapshot, result])
    CAPTURED.append({'name': 'native-' + status.lower() + ('-partial' if partial else ''),
        'snapshot': json.loads(json.dumps(snapshot)), 'findings': result,
        'native_operations': [c[0] for c in trace.calls]})


@pytest.mark.parametrize('operation', ['subscription', 'account', 'site_before', 'settings_before', 'properties_before', 'content', 'properties_after', 'settings_after', 'site_after'])
def test_actual_engine_denied_native_is_unknown(monkeypatch, operation):
    def fault(op, response):
        if op == operation:
            response.status = 403
        return response
    http_fixture(monkeypatch, hit=True, fault=fault)
    snapshot = engine.collect_snapshot(request())
    result = findings(snapshot)
    assert result and {row['status'] for row in result} == {'UNKNOWN'}


@pytest.mark.parametrize('case', ['subscription', 'tenant', 'account', 'site', 'etag', 'truncated'])
def test_actual_engine_malformed_or_foreign_native_is_unknown(monkeypatch, case):
    def fault(op, response):
        if case == 'etag' and op == 'properties_after':
            response.headers['ETag'] = '"changed"'
        elif case == 'truncated' and op == 'content':
            response.headers['Content-Length'] = str(int(response.headers['Content-Length']) + 1)
        elif (case, op) in [('subscription', 'subscription'), ('tenant', 'subscription'),
                           ('account', 'account'), ('site', 'site_before')]:
            data = json.loads(response.stream.getvalue())
            if case == 'tenant':
                data['tenantId'] = native.PRINCIPAL
            else:
                data['id'] = native.OTHER + '/foreign'
            return native.Response(data)
        return response
    http_fixture(monkeypatch, hit=True, fault=fault)
    result = findings(engine.collect_snapshot(request()))
    assert result and {row['status'] for row in result} == {'UNKNOWN'}


@pytest.mark.parametrize('reference', ['1', '@Microsoft.KeyVault(SecretUri=private)', 'https://foreign.example/private.zip'])
def test_actual_engine_unsupported_reference_never_fetched(monkeypatch, reference):
    trace = http_fixture(monkeypatch, reference=reference)
    assert findings(engine.collect_snapshot(request()))[0]['status'] == 'UNKNOWN'
    assert not any(c[1].endswith('.blob.core.windows.net') for c in trace.calls)


def test_native_owner_and_explicit_offline_assertion_json_replay(monkeypatch, tmp_path):
    http_fixture(monkeypatch, hit=True)
    snapshot = json.loads(json.dumps(engine.collect_snapshot(request())))
    expected = deepcopy(owner._EXPECTED.get()[-1])
    owner.forget_expected_context(expected['capture'])
    replay = findings(snapshot)
    assert replay[0]['status'] == 'FAIL'
    assert replay[0]['evidence']['package_source_assertions'][0]['context_provenance'] == 'supplied_snapshot_assertions'
    # A copy of untrusted snapshot context cannot self-admit through index data.
    index = {'context': {'provider': 'azure', 'scope': native.SCOPE, 'metadata': snapshot['metadata']},
             'collections': {runtime.KIND: snapshot['collections']}, owner.INDEX_KEY: snapshot['metadata'][runtime.KIND]['index_context']}
    assert consumer.evaluate(snapshot['collections'][0]['items'][0], index)[0] == 'UNKNOWN'
    path = tmp_path / 'native.json'
    path.write_text(json.dumps([snapshot, expected]))
    code = '''
import json, pathlib, socket, sys
from peaso import engine
from peaso.azure_function_package_index_20261020 import owner_admission
def blocked(*args, **kwargs): raise AssertionError('unexpected live IO')
socket.create_connection = socket.getaddrinfo = blocked
snapshot, expected = json.loads(pathlib.Path(sys.argv[1]).read_text())
with owner_admission(expected):
    result = engine.evaluate_snapshot(snapshot, checks=['azure.review.function.selected_package_source_secret_indicators'])
assert len(result['findings']) == 1 and result['findings'][0]['status'] == 'FAIL'
print(json.dumps(result['findings']))
'''
    # Run the shipped attestation mode: the fresh child still proves every pinned
    # source once. The suite-wide PEASO_SOURCE_ATTESTATION=always re-proves on
    # every nested call (minutes of CPU on a cold import), unrelated to replay.
    shipped = {k: v for k, v in os.environ.items() if k != 'PEASO_SOURCE_ATTESTATION'}
    result = subprocess.run([sys.executable, '-c', code, str(path)], cwd=ROOT,
        capture_output=True, text=True, timeout=120, env={**shipped, 'PYTHONPATH': str(ROOT)})
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)[0]['id'].startswith('secret-')
    # The same JSON is not cloud authenticated, and missing or contradictory
    # native/export/identity binding cannot become a favorable offline result.
    for change in ('capture', 'receipts', 'export'):
        malformed = deepcopy(snapshot)
        meta = malformed['metadata'][runtime.KIND]
        if change == 'capture':
            meta['index_context']['capture'] = 'package-capture:' + '0' * 32
        elif change == 'receipts':
            meta['receipts'] = []
        else:
            malformed['metadata'].pop(owner.EXPORT)
        malformed = snapshots.seal(malformed)
        observed = findings(malformed)
        assert observed and {f['status'] for f in observed} == {'UNKNOWN'}


def test_actual_cli_collect_saved_json_and_automatic_fresh_cli_replay(monkeypatch, tmp_path, capsys):
    from peaso import cli
    http_fixture(monkeypatch, hit=True)
    req = request()
    auth, opts, saved = (tmp_path / name for name in ('auth.json', 'options.json', 'snapshot.json'))
    auth.write_text(json.dumps(req['connector']['auth']))
    opts.write_text(json.dumps(req['connector']['options']))
    returned = cli.main(['collect', '--provider', 'azure', '--scopes', native.SCOPE, '--auth-file', str(auth),
            '--options-file', str(opts), '--checks', runtime.CHECK, '--snapshot-output', str(saved), '--quiet'])
    captured = capsys.readouterr()
    output = captured.out
    assert returned in (None, 0), captured.err + captured.out
    snapshot = json.loads(saved.read_text())
    assert native.SECRET not in output
    # Ordinary CLI evaluate consumes self-contained supplied snapshot assertions.
    # No companion state, custom criteria, native grant, or private API is supplied.
    offline_cli = '''
import socket, subprocess, sys
def blocked(*args, **kwargs): raise AssertionError('offline CLI attempted network or scanner execution')
socket.create_connection = socket.getaddrinfo = blocked
subprocess.Popen = blocked
from peaso.cli import main
raise SystemExit(main(sys.argv[1:]))
'''
    command = [sys.executable, '-c', offline_cli, 'evaluate', str(saved), '--checks', runtime.CHECK, '--quiet']
    # Shipped attestation mode in the cold child, as in the JSON replay above.
    shipped = {k: v for k, v in os.environ.items() if k != 'PEASO_SOURCE_ATTESTATION'}
    child = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120,
        env={**shipped, 'XDG_STATE_HOME': str(tmp_path / 'empty-state')})
    assert child.returncode == 0, child.stderr
    result = json.loads(child.stdout)
    assert len(result['findings']) == 1 and result['findings'][0]['status'] == 'FAIL'
    assert result['findings'][0]['id'].startswith('secret-')
    for private in (native.SECRET, native.SAS, native.SITE, 'function.zip'):
        assert private not in child.stdout
    assertion, = result['findings'][0]['evidence']['package_source_assertions']
    assert assertion['context_provenance'] == 'supplied_snapshot_assertions'
    assert assertion['cloud_authenticity'] == 'not_established'
    assert not (tmp_path / 'empty-state').exists()



def test_actual_mixed_native_readers_and_outer_options_union_privacy(monkeypatch):
    import io
    from peaso.collectors import azure_app_settings_secret_indicators as settings
    sibling = 'ghp_' + '9rS3kN8wQ2bV6mL1zD7jF4aC5uE0pT2yH8xG'
    trace = http_fixture(monkeypatch, hit=True, sibling_secret=sibling)
    generic = []

    class Response:
        status = 200

        def __init__(self, data):
            self.raw = io.BytesIO(json.dumps(data).encode())

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.raw.close()

        def read(self, size=-1):
            return self.raw.read(size)

    class Opener:
        def open(self, req, timeout):
            # Real AzureTransport.request owns token audience, Request creation,
            # strict native JSON and generic cache. Only the HTTP wire is fake.
            assert req.get_method() == 'GET'
            assert req.full_url.startswith(azure.ARM + native.SCOPE + '/resources?')
            generic.append(req.full_url)
            row = {'id': native.SCOPE + '/resourceGroups/review/providers/Microsoft.Compute/virtualMachines/sibling',
                   'name': 'sibling', 'type': 'Microsoft.Compute/virtualMachines',
                   'tags': {native.SECRET: sibling},
                   'properties': {'notes': [native.SECRET, sibling], 'nested': {sibling: native.SECRET}}}
            return Response({'value': [row]})

    monkeypatch.setattr(azure, 'build_opener', lambda *args: Opener())
    req = request()
    req['checks'].append(settings.CHECK)
    opts = req['connector']['options']
    opts[settings.OPTION] = [native.SITE]
    opts['inventories'] = [runtime.KIND, settings.KIND, 'azure_resource']
    # Bulk evidence appends parameters after the Azure-local finalizer. Both
    # real readers' union must survive until the outer engine export boundary.
    opts['compliance_parameters'] = {'adversarial_sibling': {native.SECRET: [sibling, {sibling: native.SECRET}]}}
    opts['parameters'] = {native.SECRET: sibling}
    snapshot = engine.collect_snapshot(req)
    report = engine.evaluate_snapshot(snapshot, checks=[runtime.CHECK, settings.CHECK])
    positives = [f for f in report['findings'] if f['status'] == 'FAIL']
    assert generic and len(trace.calls) == 11
    assert len(positives) == 2
    assert {d['engine'] for f in positives for leak in f['evidence']['secret_leaks'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert {cid for f in positives for cid in f['linked_check_ids']} == {runtime.CHECK, settings.CHECK}
    # Found secrets are shown to the tenant in clear text, so the union no longer
    # rewrites caller-supplied parameters; they stay exactly as supplied.
    assert snapshot['metadata']['parameters']['adversarial_sibling'] == {native.SECRET: [sibling, {sibling: native.SECRET}]}
    # The generic inventory keeps the tenant's own sibling resource data as read.
    sibling_row, = [item for c in snapshot['collections'] if c['type'] == 'azure_resource' for item in c['items'] if item.get('name') == 'sibling']
    assert sibling_row['tags'] == {native.SECRET: sibling}
    public = json.dumps([snapshot, report, req['connector']['options']])
    assert native.SAS not in public
    assert runtime.OPTION not in req['connector']['options'] and runtime.GRANT not in req['connector']['options']


def test_two_native_secrets_in_one_member_keep_only_own_fingerprint_parts(monkeypatch):
    second = 'ghp_' + '9rS3kN8wQ2bV6mL1zD7jF4aC5uE0pT2yH8xG'
    raw = native.package(False, ('two.env', ('A=' + native.SECRET + '\nB=' + second).encode()))
    trace = http_fixture(monkeypatch, raw=raw)
    snapshot = engine.collect_snapshot(request())
    result = findings(snapshot)
    positives = [row for row in result if row['status'] == 'FAIL']
    assert len(positives) == 2 and len({f['secret_fingerprint'] for f in positives}) == 2
    assert [c[0] for c in trace.calls] == list(source.OPERATIONS)
    for finding in positives:
        fingerprint = finding['secret_fingerprint']
        assert len(finding['evidence']['secret_leaks']) == 1
        assertion, = finding['evidence']['package_source_assertions']
        assert assertion['context_provenance'] == 'native_owner_retained_context'
        assert assertion['parts'] and all(part['leaks'] for part in assertion['parts'])
        assert {leak['fingerprint'] for part in assertion['parts'] for leak in part['leaks']} == {fingerprint}
        assert {engine['engine']: engine['status'] for part in assertion['parts'] for engine in part['engines']} == {'kingfisher': 'complete', 'trufflehog': 'complete'}
        assert {d['engine'] for leak in finding['evidence']['secret_leaks'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert native.SECRET not in json.dumps([snapshot, result]) and second not in json.dumps([snapshot, result])
    CAPTURED.append({'name': 'native-two-secrets-one-member', 'snapshot': snapshot, 'findings': result,
                     'native_operations': [c[0] for c in trace.calls]})


def test_runtime_union_cache_tuple_keys_pending_and_cleanup(monkeypatch):
    # Obtain values from an actual installed both-detector scan; never fabricate
    # detector parts or a successful scan receipt for this boundary test.
    trace = http_fixture(monkeypatch, hit=True)
    snapshot = engine.collect_snapshot(request())
    assert findings(snapshot)[0]['status'] == 'FAIL' and len(trace.calls) == 9
    observed = []
    result = secret_scanning.scan_content(('TOKEN=' + native.SECRET).encode(), 'opaque-test-source',
                                         _redact_values=lambda values: observed.extend(values))
    # Both detectors still find the value, but found secrets are clear text: the
    # redaction callback contract is kept and receives nothing to redact.
    assert result['complete'] and observed == []
    assert secret_scanning._fingerprint(native.SECRET) in {leak['fingerprint'] for leak in result['leaks']}
    reader = azure._Reader({'retries': 0})
    union = runtime.predecessor._Union(); union.remember([native.SECRET])
    reader.package_source_union = union
    reader.configuration_secret_redactions = {native.SECRET}
    reader.pending_writes = [{native.SECRET: native.SECRET}]
    reader.configuration_secret_metadata = {'mixed': {native.SECRET: native.SECRET}}
    opts = {native.SECRET: [native.SECRET], 'pending': {('opaque', native.SECRET): native.SECRET}}
    cache = {('ARM', '/' + native.SECRET, native.SECRET): {native.SECRET: native.SECRET}}
    locks = {('ARM', native.SECRET): object()}
    transport = SimpleNamespace(tokens={'ARM': native.SECRET})
    safe = runtime.finalize(reader, deepcopy(snapshot), opts, transport, cache, locks)
    assert not cache and not locks and not transport.tokens and not union.descriptors
    assert reader.package_source_union is None and not reader.configuration_secret_redactions
    assert native.SECRET not in repr([safe, opts, reader.pending_writes, reader.configuration_secret_metadata])


@pytest.mark.parametrize('case', ['overflow', 'colliding_keys', 'depth'])
def test_union_fail_closed_and_cleans_every_pending_surface(case):
    reader = azure._Reader({'retries': 0})
    union = runtime.predecessor._Union(); union.remember([native.SECRET])
    reader.package_source_union = union
    reader.pending_writes = [{native.SECRET: native.SECRET}]
    options = {native.SECRET: native.SECRET}
    cache, locks = {(native.SECRET,): native.SECRET}, {native.SECRET: object()}
    if case == 'overflow':
        union.overflow = True
    elif case == 'colliding_keys':
        options['[redacted]'] = 'collision'
    else:
        child = options
        for _ in range(35):
            child['depth'] = {}; child = child['depth']
    transport = SimpleNamespace(tokens={'ARM': native.SECRET})
    with pytest.raises(ValueError, match='package_union_redaction_incomplete'):
        runtime.finish(reader, snapshots.make_snapshot('azure', [native.SCOPE], []), options, transport, cache, locks)
    assert options == cache == locks == transport.tokens == {}
    assert reader.package_source_union is None and reader.pending_writes == []


@pytest.mark.parametrize('options', [{}, {'content_secret_scans': False}, native.options(),
    {**native.options(), runtime.GRANT: {'token': True}},
    {**native.options(), '_content_secret_scan_kinds': [runtime.KIND]}])
def test_direct_private_kind_has_no_auth(monkeypatch, options):
    def denied(*a, **kw):
        pytest.fail('credential construction before owner grant')
    monkeypatch.setattr(azure, 'AzureTransport', denied)
    monkeypatch.setattr(azure, 'AzureTransportExposure', denied)
    result = azure.collect({'provider': 'azure', 'scopes': [native.SCOPE], 'auth': {},
                            'options': deepcopy(options)}, [runtime.KIND])
    assert result['collections'] == []


def test_named_disabled_and_inventory_only_no_auth(monkeypatch):
    def denied(*a, **kw):
        pytest.fail('credential construction without named enabled grant')
    monkeypatch.setattr(azure, 'AzureTransport', denied)
    monkeypatch.setattr(azure, 'AzureTransportExposure', denied)
    req = request()
    req['connector']['options']['content_secret_scans'] = False
    assert engine.collect_snapshot(req)['collections'] == []
    req = request()
    req.pop('checks')
    req['connector']['options']['inventories'] = [runtime.KIND]
    assert engine.collect_snapshot(req)['collections'] == []


@pytest.mark.parametrize('filter', [{'categories': ['exposure']}, {'frameworks': ['nist_800_53']}])
def test_excluded_named_selection_empty_plan_does_not_construct_credentials(monkeypatch, filter):
    assert engine._selection('azure', filter.get('categories'), [runtime.CHECK], filter.get('frameworks'))[1] == []
    def denied(*args, **kwargs):
        pytest.fail('filtered empty plan attempted credential construction')
    monkeypatch.setattr(azure, 'AzureTransport', denied)
    monkeypatch.setattr(azure, 'AzureTransportExposure', denied)
    req = request(**filter)
    assert engine.collect_snapshot(req)['collections'] == []


def test_trusted_shared_account_rejected_before_auth(monkeypatch):
    with runtime.owner_context(shared_service_account=True), pytest.raises(ValueError, match='shared_service_account_forbidden'):
        engine.collect_snapshot(request())


@pytest.mark.parametrize('mutation', ['foreign', 'many', 'url', 'slot', 'malformed'])
def test_selector_rejected_before_auth_and_hosted(mutation):
    opts = native.options()
    if mutation == 'foreign':
        opts[runtime.OPTION][0]['site_resource_id'] = native.SITE.replace(native.SCOPE, native.OTHER)
    elif mutation == 'many':
        opts[runtime.OPTION] *= 3
    elif mutation == 'url':
        opts[runtime.OPTION][0]['blob'] = {'url': 'https://foreign.example/private?sig=secret'}
    elif mutation == 'slot':
        # An exact slot site is a reviewed selection (see the slots successor);
        # a path below the slot is still not a site selector.
        opts[runtime.OPTION][0]['site_resource_id'] += '/slots/private/config'
    else:
        opts[runtime.OPTION] = 'private-path'
    req = request(); req['connector']['options'] = opts
    with pytest.raises(ValueError):
        engine.collect_snapshot(req)
    with pytest.raises(HTTPException) as exc:
        validate_connector('azure', {}, opts, SimpleNamespace(auth_mode='local'), scopes=[native.SCOPE])
    assert exc.value.status_code == 422 and 'private-path' not in str(exc.value.detail)


def test_scope_selection_and_single_use_grant():
    opts = native.options()
    runtime.issue_engine_grant(opts, [native.SCOPE], [runtime.CHECK])
    grant = opts[runtime.GRANT]
    changed = deepcopy(opts)
    changed[runtime.OPTION][0]['blob']['object'] = 'another.zip'
    assert runtime.authorize(changed, [native.SCOPE]) is None
    assert runtime.authorize(opts, [native.SCOPE]) is grant
    replay = native.options(); replay[runtime.GRANT] = grant
    assert runtime.authorize(replay, [native.SCOPE]) is None


@pytest.mark.parametrize('limit', ['calls', 'cancelled', 'deadline'])
def test_native_owner_budgets(monkeypatch, limit):
    trace = http_fixture(monkeypatch, hit=True)
    req = request()
    opts = req['connector']['options']
    if limit == 'calls':
        opts['max_calls'] = 4
    elif limit == 'cancelled':
        opts['_cancel_check'] = lambda: True
    else:
        opts['collection_deadline_seconds'] = 0.000001
    snapshot = engine.collect_snapshot(req)
    assert findings(snapshot)[0]['status'] == 'UNKNOWN'
    assert len(trace.calls) <= (4 if limit == 'calls' else 0)


def test_native_saved_branches_and_registration_idempotence():
    receipt, cases = admission.reviewed_inputs()
    for case in cases:
        item, index = admission.native_case(case)
        assert consumer.evaluate(item, index)[0] == case['expected_status']
    admission.install()
