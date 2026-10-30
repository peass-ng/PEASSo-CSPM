"""Real native fake-HTTP capture -> exporter -> exec-process JSON consumer.

No original seal is recreated, no existing file/hook is patched, and no live
cloud/auth is used. Only HTTPS transport and network denial are test doubles;
the positive/clean/partial cases use both actual installed offline detectors.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from peaso import azure_function_package_portable_20261020 as consumer
from peaso.collectors import azure_function_package_portable_20261020 as exporter
from peaso.collectors import azure_function_package_source_20261020 as source
from peaso.checks import azure_function_package_source_20261020 as original_consumer
from peaso import secret_scanning
from tests import test_azure_function_package_source_20261020 as native

PURE_PATH = Path(consumer.__file__).resolve()
ROOT = PURE_PATH.parent.parent


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    yield from native.offline.__wrapped__(monkeypatch)


def context(envelope, target=None):
    # Selection, tenant, principal and customer/credential values come from the
    # test orchestrator, not copied from envelope metadata. Capture is retained
    # from this controlled invocation; the exporter checks its original seal.
    return exporter.build_expected_context([target or native.target()], [native.SCOPE],
        capture=envelope['capture'], customer_context_id='customer-context',
        credential_context_id='credential-context', tenant_id=native.TENANT, principal_id=native.PRINCIPAL)


def export(envelope, target=None):
    expected = context(envelope, target)
    snapshot = exporter.export_native_projection(envelope, expected_index_context=expected)
    return snapshot, expected


def evaluate(snapshot, expected):
    return consumer.evaluate(snapshot, expected['target_order'][0], expected_index_context=expected)


def rehash(snapshot):
    # A public content checksum is deliberately recomputable. Adverse tests
    # use it to exercise semantic admission, not just checksum mismatch.
    snapshot['snapshot_id'] = consumer.digest({k: v for k, v in snapshot.items() if k != 'snapshot_id'})
    return snapshot


def run_external(snapshot, expected, tmp_path):
    snapshot_path, expected_path = tmp_path / 'snapshot.json', tmp_path / 'expected.json'
    snapshot_path.write_text(json.dumps(snapshot))
    expected_path.write_text(json.dumps(expected))
    code = '''
import importlib.util, json, pathlib, socket, subprocess, sys
def forbidden(*args, **kwargs):
    raise AssertionError('pure saved consumer attempted I/O or execution')
socket.create_connection = socket.getaddrinfo = forbidden
subprocess.Popen = subprocess.run = forbidden
spec = importlib.util.spec_from_file_location('portable_consumer_only', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
snapshot = json.loads(pathlib.Path(sys.argv[2]).read_text())
expected = json.loads(pathlib.Path(sys.argv[3]).read_text())
result = module.evaluate(snapshot, expected['target_order'][0], expected_index_context=expected)
assert 'peaso.secret_scanning' not in sys.modules
assert not any(name.startswith('peaso.collectors') for name in sys.modules)
print(json.dumps(result))
'''
    # -I executes a fresh interpreter, not multiprocessing/fork inheritance.
    process = subprocess.run([sys.executable, '-I', '-c', code, str(PURE_PATH), str(snapshot_path), str(expected_path)],
                             capture_output=True, text=True, timeout=20, env={'PATH': os.defpath})
    assert process.returncode == 0, process.stderr
    return json.loads(process.stdout)


@pytest.fixture(scope='module')
def native_cases():
    cases = {}
    # Run actual native collection once per supported state, retaining only the
    # original already-redacted projection, never HTTP bodies/headers or matches.
    for case, hit, partial in (('clean', False, False), ('positive', True, False),
                               ('partial_clean', False, True), ('partial_positive', True, True)):
        with pytest.MonkeyPatch.context() as monkeypatch:
            def blocked(*args, **kwargs):
                raise AssertionError('live network forbidden')
            monkeypatch.setattr(socket, 'create_connection', blocked)
            monkeypatch.setattr(socket, 'getaddrinfo', blocked)
            raw = native.package(hit, ('nested.zip', b'PKbad')) if partial else None
            envelope, trace = native.capture(monkeypatch, hit=hit, raw=raw)
            assert source.authentic(envelope)
            assert all(e['status'] == 'complete' for p in envelope['results'][0]['parts'] for e in p['engines'])
            assert all(c.closed for c in trace.connections) and all(r.closed for r in trace.responses)
            if hit:
                assert {d['engine'] for l in envelope['results'][0]['leaks'] for d in l['detectors']} == set(consumer.VERSIONS)
            cases[case] = envelope
    return cases


@pytest.mark.parametrize('case,status,complete', [('clean', 'PASS', True), ('positive', 'FAIL', True),
    ('partial_clean', 'UNKNOWN', False), ('partial_positive', 'FAIL', False)])
def test_native_dual_detectors_json_saved_new_process(native_cases, case, status, complete, tmp_path):
    envelope = native_cases[case]
    before = deepcopy(envelope)
    old = original_consumer.evaluate(envelope, source.identity(native.target()), scope=native.SCOPE,
        expected_selection=[source.identity(native.target())], expected_capture=envelope['capture'],
        customer_context_id='customer-context', credential_context_id='credential-context', tenant_id=native.TENANT)
    assert old[0] == status
    snapshot, expected = export(envelope)
    result = evaluate(json.loads(json.dumps(snapshot)), json.loads(json.dumps(expected)))
    assert result[0] == status and result[1]['complete'] is complete
    external = run_external(snapshot, expected, tmp_path)
    assert external == json.loads(json.dumps(result))
    assert envelope == before and source.authentic(envelope)
    assert result[1]['runtime_bytes'] == result[1]['continuous_immutability'] == 'unknown'
    assert result[1]['credential_validation'] == 'not_attempted'
    assert result[1]['cloud_authenticity'] == 'not_established'
    assert result[1]['snapshot_trust'] == consumer.TRUST
    retained = json.dumps([snapshot, expected, result])
    for private in (native.SECRET, native.SAS, native.SITE, 'function.zip', 'WEBSITE_RUN_FROM_PACKAGE',
                    'Authorization', 'Bearer ', 'https://', '"0x123ABC"'):
        assert private not in retained
    assert 'seal' not in snapshot and 'seal' not in snapshot['metadata'][consumer.KIND]


@pytest.mark.parametrize('operation', source.OPERATIONS)
def test_actual_denied_capture_exports_unknown(monkeypatch, operation):
    def denied(op, response):
        if op == operation:
            response.status = 403
        return response
    envelope, _ = native.capture(monkeypatch, fault=denied)
    snapshot, expected = export(envelope)
    assert evaluate(snapshot, expected)[0] == 'UNKNOWN'
    assert original_consumer.evaluate(envelope, source.identity(native.target()), scope=native.SCOPE,
        expected_selection=[source.identity(native.target())], expected_capture=envelope['capture'],
        customer_context_id='customer-context', credential_context_id='credential-context', tenant_id=native.TENANT)[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', ('malformed_json', 'changed_etag', 'changed_reference', 'crossscope_account', 'wrong_tenant', 'truncated', 'range'))
def test_actual_native_adverse_capture_keeps_unknown(monkeypatch, case):
    def fault(op, response):
        if case == 'malformed_json' and op == 'subscription':
            return native.Response(b'{bad')
        if case == 'changed_etag' and op == 'properties_after':
            response.headers['ETag'] = '"0xCHANGED"'
        if case == 'changed_reference' and op == 'settings_after':
            data = json.loads(response.stream.getvalue())
            data['properties']['WEBSITE_RUN_FROM_PACKAGE'] += 'changed'
            return native.Response(data)
        if case in ('crossscope_account', 'wrong_tenant') and op == ('account' if case == 'crossscope_account' else 'subscription'):
            data = json.loads(response.stream.getvalue())
            if case == 'crossscope_account':
                data['id'] = data['id'].replace(native.SCOPE, native.OTHER)
            else:
                data['tenantId'] = native.PRINCIPAL
            return native.Response(data)
        if case == 'truncated' and op == 'content':
            response.headers['Content-Length'] = str(int(response.headers['Content-Length']) + 1)
        if case == 'range' and op == 'content':
            response.headers['Content-Range'] = 'bytes 0-1/100'
        return response
    envelope, _ = native.capture(monkeypatch, fault=fault)
    snapshot, expected = export(envelope)
    assert evaluate(snapshot, expected)[0] == 'UNKNOWN'


@pytest.mark.parametrize('reference', ('1', 'https://foreign.example/package.zip',
    'https://sourceaccount.blob.core.windows.net/packages/other.zip'))
def test_actual_wrong_reference_never_exported_as_bound(monkeypatch, reference):
    envelope, trace = native.capture(monkeypatch, reference=reference)
    snapshot, expected = export(envelope)
    assert evaluate(snapshot, expected)[0] == 'UNKNOWN'
    assert not any(c[1].endswith('.blob.core.windows.net') for c in trace.calls)


@pytest.mark.parametrize('field,value', [('customer_context_id', 'other'), ('credential_context_id', 'other'),
    ('capture', 'package-capture:' + '0' * 32), ('tenant_id', native.PRINCIPAL),
    ('principal', 'storage-source-principal:' + '0' * 64), ('provider', 'aws')])
def test_independent_expected_context_rejects_replay_on_export_and_consume(native_cases, field, value):
    envelope = native_cases['clean']
    snapshot, expected = export(envelope)
    wrong = deepcopy(expected)
    wrong[field] = value
    with pytest.raises(consumer.Invalid, match='native_package_export_rejected'):
        exporter.export_native_projection(envelope, expected_index_context=wrong)
    assert consumer.evaluate(snapshot, expected['target_order'][0], expected_index_context=wrong)[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', ('selection', 'object', 'mode', 'request', 'scope', 'extra', 'order'))
def test_expected_index_selection_bindings_are_independent(native_cases, case):
    envelope = native_cases['clean']
    snapshot, expected = export(envelope)
    wrong = deepcopy(expected)
    ident = wrong['target_order'][0]
    target = wrong['targets'][ident]
    if case == 'selection':
        wrong['selection'][native.SCOPE] = []
    elif case == 'object':
        target['object_identity'] = 'azure_storage_selected_source:' + '0' * 64
    elif case == 'mode':
        target['selection_mode'] = 'current'
    elif case == 'request':
        target['requests'][3] = target['requests'][2]
    elif case == 'scope':
        wrong['scopes'] = [native.OTHER]
    elif case == 'extra':
        wrong['trusted'] = True
    else:
        wrong['target_order'] *= 2
    with pytest.raises(consumer.Invalid):
        exporter.export_native_projection(envelope, expected_index_context=wrong)
    assert consumer.evaluate(snapshot, ident, expected_index_context=wrong)[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', ('bound', 'bytes', 'rows', 'authorized', 'seal', 'source_ref', 'error'))
def test_export_never_resigns_mutated_original_envelopes(native_cases, case):
    envelope = deepcopy(native_cases['positive'])
    expected = context(envelope)
    if case == 'bound':
        envelope['receipts'][0]['bound'] = False
    elif case == 'bytes':
        envelope['receipts'][5]['bytes'] = 1
    elif case == 'rows':
        envelope['results'].append(deepcopy(envelope['results'][0]))
    elif case == 'authorized':
        envelope['authorized'] = False
    elif case == 'seal':
        envelope['seal'] = '0' * 64
    elif case == 'source_ref':
        envelope['results'][0]['source_requests'].reverse()
    else:
        envelope['error'] = native.SECRET
    before = deepcopy(envelope)
    assert not source.authentic(envelope)
    with pytest.raises(consumer.Invalid, match='native_package_export_rejected'):
        exporter.export_native_projection(envelope, expected_index_context=expected)
    assert envelope == before


@pytest.mark.parametrize('case', ('context', 'rows', 'refs', 'receipts_order', 'orphan', 'capture', 'bound',
    'byte_bool', 'body_count', 'body_status', 'body_cap', 'request', 'native_ref', 'tenant', 'principal',
    'origin', 'version', 'method', 'flag', 'reason', 'runtime', 'error', 'parts_bytes', 'parts_complete',
    'engine_version', 'engine_status', 'engine_extra', 'engine_duplicate', 'detector_engine', 'detector_rule',
    'detector_location', 'fingerprint', 'aggregate', 'extra', 'status', 'export_assertion', 'trust', 'digest'))
def test_public_rehash_cannot_bypass_structural_context_or_native_fact_validation(native_cases, case):
    snapshot, expected = export(native_cases['positive'])
    original = deepcopy(snapshot)
    meta = snapshot['metadata'][consumer.KIND]
    rows = snapshot['collections'][0]['items']
    marker, receipt = rows[0], meta['receipts'][5]
    part = next(p for p in marker['parts'] if p['leaks'])
    leak = part['leaks'][0]
    if case == 'context': meta['index_context']['customer_context_id'] = 'other'
    elif case == 'rows': rows.append(deepcopy(marker))
    elif case == 'refs': marker['source_requests'].reverse()
    elif case == 'receipts_order': meta['receipts'].reverse()
    elif case == 'orphan': meta['receipts'].append(deepcopy(receipt))
    elif case == 'capture': receipt['capture'] = 'package-capture:' + '0' * 32
    elif case == 'bound': receipt['bound'] = False
    elif case == 'byte_bool': receipt['bytes'] = True
    elif case == 'body_count': receipt['bytes'] -= 1
    elif case == 'body_status': receipt['http_status'] = 206
    elif case == 'body_cap': receipt['bytes'] = consumer.MAX_OBJECT + 1
    elif case == 'request': receipt['request'] = meta['receipts'][0]['request']
    elif case == 'native_ref': receipt['native_request'] = 'package-web-response:' + '0' * 64
    elif case == 'tenant': receipt['tenant'] = native.PRINCIPAL
    elif case == 'principal': receipt['principal'] = 'storage-source-principal:' + '0' * 64
    elif case == 'origin': receipt['origin'] = 'arm'
    elif case == 'version': receipt['version'] = 'untrusted'
    elif case == 'method': receipt['method'] = 'POST'
    elif case == 'flag': marker['complete'] = 1
    elif case == 'reason': marker['reason'] = 'secret=' + native.SECRET
    elif case == 'runtime': marker['runtime_bytes'] = 'verified'
    elif case == 'error': marker['error'] = native.SECRET
    elif case == 'parts_bytes': part['bytes'] = consumer.MAX_MEMBER + 1
    elif case == 'parts_complete': part['complete'] = False
    elif case == 'engine_version': part['engines'][0]['version'] = 'next'
    elif case == 'engine_status': part['engines'][0]['status'] = 'unavailable'
    elif case == 'engine_extra': part['engines'][0]['error'] = native.SECRET
    elif case == 'engine_duplicate': part['engines'][1] = deepcopy(part['engines'][0])
    elif case == 'detector_engine': leak['detectors'][0]['engine'] = 'invented'
    elif case == 'detector_rule': leak['detectors'][0]['rule'] = 'https://private.example'
    elif case == 'detector_location': leak['locations'] = [{'path': native.SITE}]
    elif case == 'fingerprint': leak['fingerprint'] = native.SECRET
    elif case == 'aggregate': marker['leaks'] = []
    elif case == 'extra': snapshot['headers'] = {'Authorization': native.SECRET}
    elif case == 'status': snapshot['collections'][0]['status'] = 'denied'
    elif case == 'export_assertion': meta['native_projection_verified_at_export'] = False
    elif case == 'trust': meta['trust_boundary'] = 'online_authenticated'
    else: snapshot['snapshot_id'] = 'sha256:' + '0' * 64
    if case != 'digest': rehash(snapshot)
    before = deepcopy(snapshot)
    result = evaluate(snapshot, expected)
    assert result[0] == 'UNKNOWN', (case, result)
    assert native.SECRET not in json.dumps(result)
    assert snapshot == before
    assert evaluate(original, expected)[0] == 'FAIL'


def test_new_process_cannot_export_old_native_projection(native_cases, tmp_path):
    envelope = native_cases['clean']
    native_path, expected_path = tmp_path / 'native.json', tmp_path / 'expected.json'
    native_path.write_text(json.dumps(envelope))
    expected_path.write_text(json.dumps(context(envelope)))
    code = '''
import json, pathlib, sys
from peaso.collectors import azure_function_package_portable_20261020 as exporter
from peaso.collectors import azure_function_package_source_20261020 as source
from peaso import azure_function_package_portable_20261020 as contract
native = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert not source.authentic(native)
try:
    exporter.export_native_projection(native, expected_index_context=expected)
except contract.Invalid:
    print('saved native export rejected')
else:
    raise AssertionError('old process seal was accepted')
'''
    process = subprocess.run([sys.executable, '-c', code, str(native_path), str(expected_path)],
                             cwd=ROOT, capture_output=True, text=True, timeout=90)
    assert process.returncode == 0, process.stderr
    assert process.stdout.strip() == 'saved native export rejected'


@pytest.mark.parametrize('hit', (False, True))
def test_actual_detector_unavailability_keeps_original_incomplete_semantics(monkeypatch, hit):
    import io
    import zipfile
    def unavailable():
        raise RuntimeError('native-private-scanner-error ' + native.SECRET)
    monkeypatch.setattr(secret_scanning, '_trufflehog', unavailable)
    # Bytes an earlier complete TruffleHog run reported clean are reused from the
    # per-process clean memo; start empty so this run really needs the detector.
    from peaso import secret_scan_clean
    with secret_scan_clean._LOCK:
        monkeypatch.setattr(secret_scan_clean, '_CLEAN', type(secret_scan_clean._CLEAN)())
    package = io.BytesIO()
    with zipfile.ZipFile(package, 'w') as archive:
        archive.writestr('main.py', ('TOKEN=' + native.SECRET if hit else 'mode=ready').encode())
    envelope, _ = native.capture(monkeypatch, raw=package.getvalue())
    snapshot, expected = export(envelope)
    status, evidence = evaluate(snapshot, expected)
    assert status == ('FAIL' if hit else 'UNKNOWN')
    assert evidence['complete'] is False
    assert native.SECRET not in json.dumps([snapshot, evidence])
    assert 'native-private-scanner-error' not in json.dumps([snapshot, evidence])


@pytest.mark.parametrize('case', ('clean', 'positive', 'partial_clean', 'partial_positive'))
def test_standard_snapshot_format_and_readonly_views(native_cases, case):
    from peaso.snapshot import validate
    envelope = native_cases[case]
    before = deepcopy(envelope)
    snapshot, expected = export(envelope)
    original_expected = deepcopy(expected)
    standard = validate(json.loads(json.dumps(snapshot)), read_only=True)
    assert standard['snapshot_id'] == snapshot['snapshot_id']
    assert evaluate(standard, expected) == evaluate(snapshot, expected)
    snapshot['collections'][0]['items'][0]['reason'] = 'changed'
    snapshot['metadata'][consumer.KIND]['index_context']['customer_context_id'] = 'changed'
    assert envelope == before and expected == original_expected
    assert source.authentic(envelope)


def test_crosscapture_rows_or_receipts_never_bind(native_cases):
    snapshot, expected = export(native_cases['clean'])
    other, _ = export(native_cases['positive'])
    snapshot['collections'][0]['items'] = other['collections'][0]['items']
    assert evaluate(rehash(snapshot), expected)[0] == 'UNKNOWN'
    snapshot, expected = export(native_cases['clean'])
    snapshot['metadata'][consumer.KIND]['receipts'] = other['metadata'][consumer.KIND]['receipts']
    assert evaluate(rehash(snapshot), expected)[0] == 'UNKNOWN'


def test_actual_two_target_native_capture_keeps_exact_index_and_receipt_partition(monkeypatch, tmp_path):
    from peaso.collectors import azure
    # Reuse the real proposal's fake HTTP responder; extend only its synthetic
    # native site identity to a second explicitly selected site. Both collectors
    # and the exporter remain real and unmodified.
    native.capture(monkeypatch)
    base_connection = source.http.client.HTTPSConnection
    second_site = native.SITE + '-second'
    actual_requests = []
    class TwoSiteConnection(base_connection):
        def request(self, method, path, body=None, headers=None):
            actual_requests.append((method, path))
            second = path.startswith(second_site + '?') or path.startswith(second_site + '/')
            super().request(method, path.replace(second_site, native.SITE) if second else path, body, headers)
            if second:
                data = json.loads(self.response.stream.getvalue())
                data['id'] = data['id'].replace(native.SITE, second_site)
                if data['type'] == 'Microsoft.Web/sites':
                    data['name'] = second_site.rsplit('/', 1)[1]
                self.response.close()
                self.response = native.Response(data)
    class Transport:
        tenant = verified_tenant = native.TENANT
        def token(self, audience):
            return native.jwt(audience)
    monkeypatch.setattr(source.http.client, 'HTTPSConnection', TwoSiteConnection)
    targets = [native.target(), native.target()]
    targets[1]['site_resource_id'] = second_site
    envelope = source.collect(azure._Reader({'retries': 0}), Transport(), [native.SCOPE],
        {'content_secret_scans': True, source.OPTION: targets}, [source.CHECK],
        customer_context_id='customer-context', credential_context_id='credential-context')
    expected = exporter.build_expected_context(targets, [native.SCOPE], capture=envelope['capture'],
        customer_context_id='customer-context', credential_context_id='credential-context',
        tenant_id=native.TENANT, principal_id=native.PRINCIPAL)
    snapshot = exporter.export_native_projection(envelope, expected_index_context=expected)
    assert len(actual_requests) == 18
    assert len(snapshot['metadata'][consumer.KIND]['receipts']) == 18
    for ident in expected['target_order']:
        assert consumer.evaluate(snapshot, ident, expected_index_context=expected)[0] == 'PASS'
    assert run_external(snapshot, expected, tmp_path)[0] == 'PASS'
    rows = snapshot['collections'][0]['items']
    rows[0]['source_requests'], rows[1]['source_requests'] = rows[1]['source_requests'], rows[0]['source_requests']
    assert evaluate(rehash(snapshot), expected)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field', ('tenant_id', 'principal_id'))
def test_context_builder_rejects_missing_trusted_authority(native_cases, field):
    kwargs = dict(capture=native_cases['clean']['capture'], customer_context_id='customer-context',
                  credential_context_id='credential-context', tenant_id=native.TENANT, principal_id=native.PRINCIPAL)
    kwargs[field] = None
    with pytest.raises(consumer.Invalid):
        exporter.build_expected_context([native.target()], [native.SCOPE], **kwargs)


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='POSIX fork contract')
def test_fork_does_not_inherit_usable_native_projection_key(native_cases):
    envelope = native_cases['positive']
    snapshot, expected = export(envelope)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            payload = {'native_authentic': source.authentic(envelope), 'portable_status': evaluate(snapshot, expected)[0]}
            os.write(write_fd, json.dumps(payload).encode())
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    raw = os.read(read_fd, 4096)
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert json.loads(raw) == {'native_authentic': False, 'portable_status': 'FAIL'}
    assert source.authentic(envelope)


