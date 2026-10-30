"""Independent native ARM bytes -> actual Azure collector -> public engine.

Candidate only: registry injection is test-local, historical CASES are untouched.
All socket/DNS/authentication discovery is forbidden. No secret is validated.
"""
import base64
from copy import deepcopy
import importlib
import inspect
import io
import json
import os
from pathlib import Path
import socket
from types import SimpleNamespace

import pytest

from peaso import engine, secret_scanning as scanning
from peaso.checks import Check
from peaso.checks import azure_selected_configuration_secret_review_20261020 as consumer
from peaso.collectors import azure
from peaso.collectors import azure_selected_configuration_secret_indicators as source
from peaso.snapshot import seal

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
FOREIGN = '/subscriptions/33333333-3333-3333-3333-333333333333'
TENANT = '22222222-2222-2222-2222-222222222222'
PREFIX = SCOPE + '/resourceGroups/review/providers/'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
SECOND = 'ghp_' + '9hK3vP6xM7cQ2bL8nR4dF1sA0zJ5wT6uY7eC'
AUTH = 'offline-configuration-auth-canary'
# Independent expected wire/type/version table: no provider mocks from CASES.
NATIVE = {
    'aci_literals': ('Microsoft.ContainerInstance/containerGroups/selected', 'Microsoft.ContainerInstance/containerGroups', '2023-05-01', ''),
    'container_app_literals': ('Microsoft.App/containerApps/selected', 'Microsoft.App/containerApps', '2024-03-01', ''),
    'logic_workflow': ('Microsoft.Logic/workflows/selected', 'Microsoft.Logic/workflows', '2016-06-01', ''),
    'vm_userdata': ('Microsoft.Compute/virtualMachines/selected', 'Microsoft.Compute/virtualMachines', '2025-04-01', '&$expand=userData'),
    'vmss_model_userdata': ('Microsoft.Compute/virtualMachineScaleSets/selected', 'Microsoft.Compute/virtualMachineScaleSets', '2025-04-01', '&$expand=userData'),
    'vm_extension_settings': ('Microsoft.Compute/virtualMachines/selected/extensions/public', 'Microsoft.Compute/virtualMachines/extensions', '2025-04-01', ''),
    'image_builder_inline': ('Microsoft.VirtualMachineImages/imageTemplates/selected', 'Microsoft.VirtualMachineImages/imageTemplates', '2022-07-01', ''),
    'automation_runbook': ('Microsoft.Automation/automationAccounts/selected/runbooks/public', 'Microsoft.Automation/automationAccounts/runbooks', '2023-11-01', ''),
    'automation_variable': ('Microsoft.Automation/automationAccounts/selected/variables/public', 'Microsoft.Automation/automationAccounts/variables', '2023-11-01', ''),
    'apim_policy': ('Microsoft.ApiManagement/service/selected/policies/policy', 'Microsoft.ApiManagement/service/policies', '2024-05-01', '&format=rawxml'),
}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('socket/DNS/auth discovery forbidden')
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    registered, = [c for c in engine._registry() if c.id == source.CHECK]
    assert inspect.unwrap(registered.evaluate) is consumer.evaluate
    assert registered.kind == source.KIND and registered.allow_incomplete_failure
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def target(surface):
    return {'surface': surface, 'resource_id': PREFIX + NATIVE[surface][0]}


def native(surface, literal='mode=ready', selected=None):
    t = selected or target(surface); rid = t['resource_id']
    properties = {
        'aci_literals': lambda: {'containers': [{'name': 'selected', 'properties': {'image': 'alpine',
            'command': ['/bin/sh', '-c', literal], 'environmentVariables': [{'name': 'MODE', 'value': literal}]}}]},
        'container_app_literals': lambda: {'template': {'containers': [{'name': 'selected', 'image': 'alpine',
            'command': ['/bin/sh'], 'args': ['-c', literal], 'env': [{'name': 'MODE', 'value': literal}]}]}},
        'logic_workflow': lambda: {'definition': {'$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#',
            'contentVersion': '1.0.0.0', 'triggers': {}, 'actions': {'Literal': {'type': 'Compose', 'inputs': literal}}, 'outputs': {}}},
        'vm_userdata': lambda: {'userData': base64.b64encode(literal.encode()).decode(), 'osProfile': {'customData': TOKEN}},
        'vmss_model_userdata': lambda: {'virtualMachineProfile': {'userData': base64.b64encode(literal.encode()).decode(), 'osProfile': {'customData': TOKEN}}},
        'vm_extension_settings': lambda: {'publisher': 'Microsoft.Azure.Extensions', 'type': 'CustomScript', 'typeHandlerVersion': '2.1',
            'settings': {'commandToExecute': literal}, 'protectedSettings': {'password': TOKEN}},
        'image_builder_inline': lambda: {'customize': [{'type': 'Shell', 'name': 'public', 'inline': [literal]}]},
        'automation_runbook': lambda: {'runbookType': 'PowerShell', 'state': 'Published', 'description': TOKEN},
        'automation_variable': lambda: {'isEncrypted': False, 'value': json.dumps(literal)},
        'apim_policy': lambda: {'format': 'rawxml', 'value': '<policies><inbound><set-header name="X"><value>' + literal + '</value></set-header></inbound><backend/><outbound/><on-error/></policies>'},
    }[surface]()
    typ = NATIVE[surface][1]
    if surface == 'apim_policy':
        typ = 'Microsoft.ApiManagement/service' + ('/apis' if '/apis/' in rid else '') + ('/operations' if '/operations/' in rid else '') + '/policies'
    return {'id': rid, 'name': rid.rsplit('/', 1)[1], 'type': typ, 'properties': properties}


class Response:
    def __init__(self, payload, status=200, headers=None):
        self.payload = json.dumps(payload).encode() if isinstance(payload, dict) else payload
        self.stream = io.BytesIO(self.payload); self.status = status; self.closed = False
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.payload)), **(headers or {})}
    def getheader(self, key):
        return self.headers.get(key)
    def read(self, size):
        assert 0 < size <= 16384
        return self.stream.read(size)
    def close(self):
        self.closed = True


def request(targets, **options):
    return {'connector': {'provider': 'azure', 'scopes': [SCOPE],
        'auth': {'method': 'token', 'tenant_id': TENANT, 'arm_token': AUTH},
        'options': {'content_secret_scans': True, source.OPTION: targets, 'retries': 0, **options}}, 'checks': [source.CHECK]}


def collect(monkeypatch, targets=None, literal='mode=ready', *, real=False, transform=None, fault=None,
            req=None, missing_engine=None, detector=None, tenant=TENANT):
    targets = targets or [target('aci_literals')]
    trace = SimpleNamespace(calls=[], responses=[], scans=[], connections=[], tokens=[])
    if not real:
        def scan(payload, path, timeout):
            trace.scans.append((payload, path, timeout))
            if detector:
                return detector(payload, path, timeout)
            return [(t, 'github-pat', 1) for t in (TOKEN, SECOND) if t.encode() in payload]
        monkeypatch.setattr(scanning, '_scan_kingfisher', scan)
        monkeypatch.setattr(scanning, '_scan_trufflehog', scan)
        if missing_engine:
            def unavailable(*args, **kwargs):
                raise RuntimeError(TOKEN)
            monkeypatch.setattr(scanning, '_scan_' + missing_engine, unavailable)
    class Transport:
        verified_tenant = tenant
        def __init__(self, auth):
            self.tenant = TENANT
        def token(self, audience):
            assert audience == 'https://management.azure.com'
            trace.tokens.append(audience)
            return AUTH
        def request(self, *args, **kwargs):
            if args == ('https://management.azure.com' + SCOPE + '?api-version=2022-12-01',):
                assert kwargs.get('body') is None and kwargs.get('audience') == 'https://management.azure.com'
                return {'id': SCOPE, 'subscriptionId': SCOPE.rsplit('/', 1)[1], 'tenantId': TENANT,
                    'state': 'Enabled', 'displayName': 'review'}
            pytest.fail('generic native cache/discovery must not read selected content')
        def close(self):
            pass
    class Connection:
        sock = None
        def __init__(self, host, timeout):
            assert host == 'management.azure.com' and 0 < timeout <= 10
            self.closed = False; trace.connections.append(self)
        def set_debuglevel(self, level):
            assert level == 0
        def request(self, method, path, body=None, headers=None):
            assert method == 'GET' and body is None
            assert headers['Authorization'] == 'Bearer ' + AUTH and headers['Accept-Encoding'] == 'identity'
            matches = []
            for t in targets:
                surface = t['surface']; version, suffix = NATIVE[surface][2:]
                for content in ((False, True) if surface == 'automation_runbook' else (False,)):
                    expected = t['resource_id'] + ('/content' if content else '') + '?api-version=' + version + suffix
                    if path == expected:
                        matches.append((t, content))
            assert len(matches) == 1, path
            t, content = matches[0]; trace.calls.append((method, 'management.azure.com', path))
            payload = (literal.encode() if content else native(t['surface'], literal, t))
            if transform and not content:
                payload = transform(t, deepcopy(payload))
            response = Response(payload, headers={'Content-Type': 'text/powershell'} if content else {})
            if fault:
                response = fault(t, content, response)
            self.response = response; trace.responses.append(response)
        def getresponse(self):
            return self.response
        def close(self):
            self.closed = True
    monkeypatch.setattr(azure, 'AzureTransport', Transport)
    monkeypatch.setattr(azure, 'AzureTransportExposure', Transport)
    monkeypatch.setattr(source.http.client, 'HTTPSConnection', Connection)
    snapshot = engine.collect_snapshot(deepcopy(req if req is not None else request(targets)))
    result = engine.evaluate_snapshot(snapshot, checks=[source.CHECK])
    return snapshot, result['findings'], trace


def own(snapshot):
    row, = [c for c in snapshot['collections'] if c['type'] == source.KIND]
    return row


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('hit', [False, True])
def test_native_each_surface_collector_public_engine(monkeypatch, surface, hit):
    snapshot, results, trace = collect(monkeypatch, [target(surface)], TOKEN if hit else 'mode=ready')
    assert [r['status'] for r in results] == ['FAIL' if hit else 'PASS'], results
    item, = own(snapshot)['items']
    assert item[source.MARKER]['complete'] is True
    assert len(trace.calls) == (2 if surface == 'automation_runbook' else 1)
    assert len(trace.scans) == 2
    persisted = json.dumps([snapshot, results])
    for raw in (TOKEN, AUTH, target(surface)['resource_id'], 'mode=ready', 'protectedSettings', 'customData'):
        assert raw not in persisted
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)
    if os.environ.get('AZURE_CONFIGURATION_NATIVE_CAPTURE_DIR'):
        path = Path(os.environ['AZURE_CONFIGURATION_NATIVE_CAPTURE_DIR'])
        path.mkdir(parents=True, exist_ok=True)
        (path / (surface + ('-hit' if hit else '-clean') + '.json')).write_text(json.dumps({
            'surface': surface, 'expected_status': 'FAIL' if hit else 'PASS',
            'snapshot': snapshot, 'findings': results, 'http': trace.calls}, sort_keys=True, indent=2))


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('hit', [False, True])
def test_pinned_real_both_offline_engines_each_surface(monkeypatch, surface, hit):
    snapshot, results, _ = collect(monkeypatch, [target(surface)], TOKEN if hit else 'mode=ready', real=True)
    assert [r['status'] for r in results] == ['FAIL' if hit else 'PASS'], results
    engines = own(snapshot)['items'][0][source.MARKER]['parts'][0]['engines']
    assert {e['status'] for e in engines} == {'complete'}
    if hit:
        leaks = own(snapshot)['items'][0][source.MARKER]['leaks']
        assert len(leaks) == 1 and {d['engine'] for d in leaks[0]['detectors']} == {'kingfisher', 'trufflehog'}


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('mutation', ['foreign', 'sibling', 'type', 'name', 'missing_properties', 'partial', 'duplicate_json', 'empty', 'denied', 'redirect', 'truncated'])
def test_native_identity_denied_partial_matrix(monkeypatch, surface, mutation):
    def transform(t, data):
        if mutation == 'foreign': data['id'] = data['id'].replace(SCOPE, FOREIGN)
        if mutation == 'sibling': data['id'] += '-sibling'
        if mutation == 'type': data['type'] = 'Microsoft.Fake/foreign'
        if mutation == 'name': data['name'] = 'foreign'
        if mutation == 'missing_properties': data.pop('properties')
        if mutation == 'partial': data['nextLink'] = 'https://foreign.invalid/continue'
        return data
    def fault(t, content, response):
        if mutation == 'denied': return Response({'error': {'message': TOKEN}}, 403)
        if mutation == 'redirect': return Response(b'', 302, {'Location': 'https://foreign.invalid/' + TOKEN})
        if mutation == 'duplicate_json': return Response(b'{"id":"a","id":"b"}')
        if mutation == 'empty': return Response(b'')
        if mutation == 'truncated': response.headers['Content-Length'] = str(len(response.payload) + 1)
        return response
    snapshot, results, trace = collect(monkeypatch, [target(surface)], TOKEN, transform=transform, fault=fault)
    assert [r['status'] for r in results] == ['UNKNOWN'], results
    assert not trace.scans
    assert TOKEN not in json.dumps([snapshot, results])


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('missing', ['kingfisher', 'trufflehog'])
@pytest.mark.parametrize('hit', [False, True])
def test_one_engine_missing_trusted_hit_survives(monkeypatch, surface, missing, hit):
    snapshot, results, _ = collect(monkeypatch, [target(surface)], TOKEN if hit else 'mode=ready', missing_engine=missing)
    assert [r['status'] for r in results] == ['FAIL' if hit else 'UNKNOWN'], results
    assert own(snapshot)['items'][0][source.MARKER]['complete'] is False
    if hit:
        assert results[0]['evidence']['complete'] is False


@pytest.mark.parametrize('surface', NATIVE)
@pytest.mark.parametrize('field', ['capture', 'identity', 'tenant', 'credential', 'receipt', 'operation', 'bytes', 'engine_version'])
def test_tampered_native_bindings_cannot_decide(monkeypatch, surface, field):
    snapshot, _, _ = collect(monkeypatch, [target(surface)], TOKEN)
    item = own(snapshot)['items'][0]; marker = item[source.MARKER]
    receipt = snapshot['metadata'][source.KIND + '_receipts'][0]
    if field == 'capture': marker['capture'] = 'arm-config-capture:' + '0' * 32
    if field == 'identity': marker['identity'] = source.KIND + ':' + '0' * 64
    if field == 'tenant': receipt['tenant_id'] = '33333333-3333-3333-3333-333333333333'
    if field == 'credential': item['_provenance']['credential_context_id'] = 'foreign'
    if field == 'receipt': receipt['identity_bound'] = False
    if field == 'operation': receipt['operation'] = 'arbitrary_content'
    if field == 'bytes': receipt['bytes'] = source.MAX_WIRE + 1
    if field == 'engine_version': marker['parts'][0]['engines'][0]['version'] = 'foreign'
    results = engine.evaluate_snapshot(seal(snapshot), checks=[source.CHECK])['findings']
    assert [r['status'] for r in results] == ['UNKNOWN'], results


@pytest.mark.parametrize('level', ['global', 'api', 'operation'])
def test_apim_exact_native_policy_levels(monkeypatch, level):
    t = target('apim_policy')
    t['resource_id'] = PREFIX + 'Microsoft.ApiManagement/service/selected' + (
        '/apis/native-api' if level != 'global' else '') + ('/operations/native-operation' if level == 'operation' else '') + '/policies/policy'
    _, results, trace = collect(monkeypatch, [t], TOKEN)
    assert [r['status'] for r in results] == ['FAIL']
    assert trace.calls[0][2].endswith('/policies/policy?api-version=2024-05-01&format=rawxml')


@pytest.mark.parametrize('surface,patch', [
    ('aci_literals', {'containers': [{'name': 'selected', 'properties': {'command': ['mode=ready'], 'environmentVariables': [{'name': 'secret', 'secureValue': TOKEN}]}}]}),
    ('container_app_literals', {'template': {'containers': [{'name': 'selected', 'command': ['mode=ready'], 'env': [{'name': 'secret', 'secretRef': TOKEN}]}]}}),
    ('logic_workflow', {'definition': {'actions': {'Reference': {'type': 'Compose', 'inputs': "@parameters('token')"}}}}),
    ('vm_extension_settings', {'settings': {'commandToExecute': 'mode=ready', 'fileUris': ['https://foreign.invalid/source.sh']}}),
    ('image_builder_inline', {'customize': [{'type': 'Shell', 'scriptUri': 'https://foreign.invalid/' + TOKEN}]}),
    ('automation_variable', {'isEncrypted': True, 'value': TOKEN}),
    ('apim_policy', {'format': 'rawxml', 'value': '<policies><inbound><base/></inbound></policies>'}),
    ('apim_policy', {'format': 'rawxml-link', 'value': 'https://foreign.invalid/' + TOKEN}),
])
def test_secret_stores_external_references_not_followed_or_clean(monkeypatch, surface, patch):
    def transform(t, data):
        data['properties'] = patch
        return data
    snapshot, results, trace = collect(monkeypatch, [target(surface)], transform=transform)
    assert [r['status'] for r in results] == ['UNKNOWN']
    assert len(trace.calls) == 1 and TOKEN not in json.dumps(snapshot)
    assert all(TOKEN.encode() not in call[0] for call in trace.scans) if surface in ('aci_literals', 'container_app_literals', 'automation_variable') else True


@pytest.mark.parametrize('surface', ['aci_literals', 'container_app_literals', 'vm_extension_settings', 'image_builder_inline', 'apim_policy'])
def test_independent_literal_hit_survives_external_or_secret_reference(monkeypatch, surface):
    def transform(t, data):
        p = data['properties']
        if surface == 'aci_literals':
            p['containers'][0]['properties']['environmentVariables'].append({'name': 'SECRET', 'secureValue': 'intended_store'})
        elif surface == 'container_app_literals':
            p['template']['containers'][0]['env'].append({'name': 'SECRET', 'secretRef': 'intended_store'})
        elif surface == 'vm_extension_settings':
            p['settings']['fileUris'] = ['https://foreign.invalid/' + SECOND]
        elif surface == 'image_builder_inline':
            p['customize'].append({'type': 'Shell', 'scriptUri': 'https://foreign.invalid/source.sh'})
        else:
            p['value'] = p['value'].replace('<inbound>', '<inbound><base/>')
        return data
    snapshot, results, trace = collect(monkeypatch, [target(surface)], TOKEN, transform=transform)
    assert len(results) == (2 if surface == 'vm_extension_settings' else 1)
    assert all(r['status'] == 'FAIL' and r['evidence']['complete'] is False for r in results)
    assert len(trace.calls) == 1 and TOKEN not in json.dumps(snapshot) and SECOND not in json.dumps(snapshot)


@pytest.mark.parametrize('surface', ['aci_literals', 'container_app_literals'])
@pytest.mark.parametrize('field', ['env', 'command', 'init'])
def test_container_literal_branches(monkeypatch, surface, field):
    def transform(t, data):
        p = data['properties'] if surface == 'aci_literals' else data['properties']['template']
        container = p['containers'][0]
        values = container['properties'] if surface == 'aci_literals' else container
        values.pop('command', None); values.pop('args', None)
        values['environmentVariables' if surface == 'aci_literals' else 'env'] = []
        if field == 'env': values['environmentVariables' if surface == 'aci_literals' else 'env'] = [{'name': 'TOKEN', 'value': TOKEN}]
        if field == 'command': values['command'] = [TOKEN]
        if field == 'init':
            extra = {'name': 'init', 'command': [TOKEN]}
            p['initContainers'] = [{'name': 'init', 'properties': extra}] if surface == 'aci_literals' else [extra]
        return data
    _, results, _ = collect(monkeypatch, [target(surface)], transform=transform)
    assert [r['status'] for r in results] == ['FAIL']


@pytest.mark.parametrize('surface', NATIVE)
def test_missing_deciding_field_cannot_prove_clean(monkeypatch, surface):
    def transform(t, data):
        data['properties'] = {}
        return data
    snapshot, results, trace = collect(monkeypatch, [target(surface)], transform=transform)
    assert [r['status'] for r in results] == ['UNKNOWN'] and not trace.scans
    if os.environ.get('AZURE_CONFIGURATION_NATIVE_CAPTURE_DIR'):
        path = Path(os.environ['AZURE_CONFIGURATION_NATIVE_CAPTURE_DIR'])
        path.mkdir(parents=True, exist_ok=True)
        (path / (surface + '-unknown.json')).write_text(json.dumps({
            'surface': surface, 'expected_status': 'UNKNOWN', 'snapshot': snapshot,
            'findings': results, 'http': trace.calls}, sort_keys=True, indent=2))


@pytest.mark.parametrize('surface', ['automation_runbook', 'automation_variable'])
def test_documented_automation_type_omission_still_exact_id_bound(monkeypatch, surface):
    def transform(t, data):
        data.pop('type')
        return data
    _, results, _ = collect(monkeypatch, [target(surface)], TOKEN, transform=transform)
    assert [r['status'] for r in results] == ['FAIL']


@pytest.mark.parametrize('runbook_type', ['Graph', 'GraphPowerShell', 'Unknown', None])
def test_unsupported_runbook_never_downloads(monkeypatch, runbook_type):
    def transform(t, data):
        data['properties']['runbookType'] = runbook_type
        return data
    _, results, trace = collect(monkeypatch, [target('automation_runbook')], TOKEN, transform=transform)
    assert [r['status'] for r in results] == ['UNKNOWN'] and len(trace.calls) == 1


@pytest.mark.parametrize('mime', ['application/zip', 'application/octet-stream', 'text/html'])
def test_runbook_nontext_native_body_rejected(monkeypatch, mime):
    def fault(t, content, response):
        if content: response.headers['Content-Type'] = mime
        return response
    _, results, trace = collect(monkeypatch, [target('automation_runbook')], TOKEN, fault=fault)
    assert [r['status'] for r in results] == ['UNKNOWN'] and not trace.scans


@pytest.mark.parametrize('surface', ['vm_userdata', 'vmss_model_userdata'])
@pytest.mark.parametrize('value', [None, '', 'not_base64!', 'AA==', '//8='])
def test_userdata_missing_binary_malformed_never_customdata_fallback(monkeypatch, surface, value):
    def transform(t, data):
        props = data['properties'] if surface == 'vm_userdata' else data['properties']['virtualMachineProfile']
        props['userData'] = value
        return data
    _, results, trace = collect(monkeypatch, [target(surface)], transform=transform)
    assert [r['status'] for r in results] == ['UNKNOWN'] and not trace.scans


@pytest.mark.parametrize('surface', NATIVE)
def test_masks_and_empty_literals_unresolved(monkeypatch, surface):
    _, results, _ = collect(monkeypatch, [target(surface)], '***')
    assert [r['status'] for r in results] == ['UNKNOWN']


@pytest.mark.parametrize('surface', NATIVE)
def test_authenticated_tenant_required(monkeypatch, surface):
    _, results, trace = collect(monkeypatch, [target(surface)], TOKEN, tenant=None)
    assert [r['status'] for r in results] == ['UNKNOWN'] and not trace.calls


def test_union_redaction_same_value_hmac_and_names(monkeypatch):
    first = target('aci_literals'); first['resource_id'] = first['resource_id'].replace('/selected', '/' + TOKEN)
    second = target('vm_userdata')
    snapshot, results, trace = collect(monkeypatch, [first, second], TOKEN + ' ' + SECOND)
    assert [r['status'] for r in results] == ['FAIL', 'FAIL']
    markers = [i[source.MARKER] for i in own(snapshot)['items']]
    assert {l['fingerprint'] for m in markers for l in m['leaks']} == {scanning._fingerprint(TOKEN), scanning._fingerprint(SECOND)}
    persisted = json.dumps([snapshot, results, scanning._RESULTS])
    assert TOKEN not in persisted and SECOND not in persisted and AUTH not in persisted
    assert len(trace.calls) == 2


def test_hmac_matches_existing_adapter_exact_values(monkeypatch):
    _, _, trace = collect(monkeypatch, literal=TOKEN)
    shared = scanning.scan_content(TOKEN.encode(), 'other-adapter', _redact_values=lambda _: None)
    assert shared['leaks'][0]['fingerprint'] == scanning._fingerprint(TOKEN)
    assert shared['leaks'][0]['fingerprint'] != scanning._fingerprint(TOKEN.lower())


def test_union_final_snapshot_scrubs_other_metadata(monkeypatch):
    reader = SimpleNamespace(configuration_secret_redactions={TOKEN, SECOND})
    sample = {'metadata': {TOKEN: SECOND, 'encoded': base64.b64encode(TOKEN.encode()).decode()},
        'collections': [{'items': [{'id': TOKEN, 'name': SECOND}]}]}
    result = source.final_snapshot(reader, sample)
    assert TOKEN in json.dumps(result) and SECOND in json.dumps(result)  # found values stay visible
    assert not reader.configuration_secret_redactions


@pytest.mark.parametrize('change', ['off', 'unnamed'])
def test_defaultoff_and_named_check_gate(monkeypatch, change):
    targets = [target('aci_literals')]; req = request(targets)
    if change == 'off': req['connector']['options']['content_secret_scans'] = False
    else:
        candidate = next(c for c in engine._registry() if c.id == source.CHECK)
        monkeypatch.setattr(engine, '_registry', lambda: [candidate])
        req['checks'] = []
        req['connector']['options']['inventories'] = [source.KIND]
    snapshot, _, trace = collect(monkeypatch, targets, req=req)
    assert not trace.calls and not trace.scans
    assert source.KIND not in azure._selected({}, None)
    assert source.KIND in engine.BULK_STREAM_TYPES['azure']


@pytest.mark.parametrize('bad', [[], [target('aci_literals')] * 2,
    [{'surface': 'aci_literals', 'resource_id': FOREIGN + '/resourceGroups/review/providers/Microsoft.ContainerInstance/containerGroups/selected'}],
    [{'surface': 'aci_literals', 'resource_id': 'https://foreign.invalid/' + TOKEN}],
    [{'surface': 'aci_literals', 'resource_id': PREFIX + 'MicrosoftXContainerInstance/containerGroups/selected'}],
    [{'surface': 'vm_userdata', 'resource_id': PREFIX + 'Microsoft.Compute/virtualMachines/../secret'}],
    [{'surface': 'automation_runbook', 'resource_id': PREFIX + 'Microsoft.Automation/automationAccounts/a/runbooks/b/content'}],
    [dict(target('aci_literals'), url='https://foreign.invalid')], [target('aci_literals')] * 9])
def test_selection_rejected_before_transport(monkeypatch, bad):
    with pytest.raises(ValueError, match='invalid_configuration_selection'):
        engine.collect_snapshot(request(bad))


@pytest.mark.parametrize('bound', ['wire', 'total', 'content', 'calls', 'deadline', 'reader_calls', 'resources'])
def test_budgets_never_prove_clean(monkeypatch, bound):
    options = {}
    if bound == 'wire': monkeypatch.setattr(source, 'MAX_WIRE', 20)
    if bound == 'total': monkeypatch.setattr(source, 'MAX_TOTAL', 20)
    if bound == 'content': monkeypatch.setattr(source, 'MAX_CONTENT', 2)
    if bound == 'calls': monkeypatch.setattr(source, 'MAX_CALLS', 0)
    if bound == 'deadline': monkeypatch.setattr(source, 'MAX_SECONDS', -1)
    if bound == 'reader_calls': options['max_calls'] = 0
    if bound == 'resources': options['max_resources'] = 1
    targets = [target('aci_literals'), target('vm_userdata')] if bound == 'resources' else [target('aci_literals')]
    if bound == 'reader_calls':
        # Existing public budgets require a positive bound; runbook's second
        # source request must stop at the global one-call limit.
        options['max_calls'] = 1; targets = [target('automation_runbook')]
    _, results, trace = collect(monkeypatch, targets, req=request(targets, **options))
    assert results and all(r['status'] == 'UNKNOWN' for r in results), results
    assert len(trace.calls) <= 2


def test_reviewed_import_keeps_exact_registered_identity_and_native_cases():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    before = list(CHECKS); keys = set(CASES)
    imported=importlib.import_module(consumer.__name__)
    registered,=[c for c in CHECKS if c.id==source.CHECK]
    assert CHECKS == before and set(CASES) == keys and source.CHECK in CASES
    assert imported is consumer and inspect.unwrap(registered.evaluate) is consumer.evaluate
    for branch in ('pass','fail','unknown'):
        assert registered.evaluate(CASES[source.CHECK][branch],CASES[source.CHECK][branch+'_index'])[0]==branch.upper()


def test_hit_survives_collection_partial_but_clean_does_not(monkeypatch):
    snapshot, _, _ = collect(monkeypatch, literal=TOKEN)
    row = own(snapshot); row['status'] = 'partial'; row['error'] = {'code': 'resource_limit'}
    findings = engine.evaluate_snapshot(seal(snapshot), checks=[source.CHECK])['findings']
    failed = [r for r in findings if r['status'] == 'FAIL']
    assert failed and all(r['evidence']['complete'] is False for r in failed)
    assert all(r['status'] in ('FAIL', 'UNKNOWN') for r in findings)
    row['items'][0][source.MARKER]['leaks'] = []
    findings = engine.evaluate_snapshot(seal(snapshot), checks=[source.CHECK])['findings']
    assert findings and all(r['status'] == 'UNKNOWN' for r in findings)


def test_final_deadline_cannot_erase_already_trusted_hit(monkeypatch):
    original = source.scan_content; done = False; before = source.remaining
    def scan(*args, **kwargs):
        nonlocal done
        result = original(*args, **kwargs); done = True
        return result
    def remaining(*args, **kwargs):
        if done: raise source.Incomplete('configuration_deadline')
        return before(*args, **kwargs)
    monkeypatch.setattr(source, 'scan_content', scan)
    monkeypatch.setattr(source, 'remaining', remaining)
    _, findings, _ = collect(monkeypatch, literal=TOKEN)
    assert findings and all(r['status'] == 'FAIL' and r['evidence']['complete'] is False for r in findings)


def test_partial_detector_exception_text_never_retained(monkeypatch):
    snapshot, findings, _ = collect(monkeypatch, literal=TOKEN, missing_engine='trufflehog')
    assert findings[0]['status'] == 'FAIL' and TOKEN not in json.dumps([snapshot, findings])


def test_casefold_native_identity_but_not_secret_value(monkeypatch):
    def transform(t, data):
        data['id'] = data['id'].upper(); data['type'] = data['type'].upper(); data['name'] = data['name'].upper()
        return data
    snapshot, findings, _ = collect(monkeypatch, literal=TOKEN, transform=transform)
    assert findings[0]['status'] == 'FAIL'
    assert own(snapshot)['items'][0][source.MARKER]['leaks'][0]['fingerprint'] == scanning._fingerprint(TOKEN)


@pytest.mark.parametrize('surface', ['vm_userdata', 'vmss_model_userdata'])
def test_userdata_native_64k_limit(monkeypatch, surface):
    _, findings, trace = collect(monkeypatch, [target(surface)], 'a' * (65536 + 1))
    assert [r['status'] for r in findings] == ['UNKNOWN'] and not trace.scans


def test_eight_selected_runbooks_sixteen_fixed_gets(monkeypatch):
    targets = [dict(target('automation_runbook'), resource_id=target('automation_runbook')['resource_id'] + str(i)) for i in range(8)]
    snapshot, findings, trace = collect(monkeypatch, targets)
    assert len(trace.calls) == 16 and len(own(snapshot)['items']) == 8
    assert len(findings) == 8 and all(r['status'] == 'PASS' for r in findings)
    assert all('/content?' in path or '/runbooks/' in path for _, _, path in trace.calls)


def test_same_value_two_surfaces_one_report_leak(monkeypatch):
    snapshot, findings, _ = collect(monkeypatch, [target('aci_literals'), target('vm_userdata')], TOKEN)
    assert len(findings) == 1 and findings[0]['status'] == 'FAIL'
    assert len({i[source.MARKER]['leaks'][0]['fingerprint'] for i in own(snapshot)['items']}) == 1
    assert len(findings[0]['evidence']['secret_leaks'][0]['locations']) == 2


def test_multiple_explicit_subscription_scopes_remain_bound(monkeypatch):
    t1 = target('aci_literals'); t2 = target('vm_userdata')
    t2['resource_id'] = t2['resource_id'].replace(SCOPE, FOREIGN)
    req = request([t1, t2]); req['connector']['scopes'] = [SCOPE, FOREIGN]
    snapshot, findings, trace = collect(monkeypatch, [t1, t2], req=req)
    assert len(findings) == 2 and all(r['status'] == 'PASS' for r in findings)
    assert {c['scope'] for c in snapshot['collections'] if c['type'] == source.KIND} == {SCOPE, FOREIGN}
    assert len(trace.calls) == 2
