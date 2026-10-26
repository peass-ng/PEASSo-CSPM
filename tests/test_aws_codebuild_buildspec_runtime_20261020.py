"""Actual engine -> native SDK Stubber -> real detectors -> portable public output."""
from contextlib import ExitStack
from copy import deepcopy
from concurrent.futures import Future
import base64
import gzip
import hashlib
import json
import io
import logging
from pathlib import Path
import socket
import threading
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber
from botocore.awsrequest import AWSResponse
import pytest

from peaso import engine, secret_scanning as scanning
from peaso.collectors import aws, aws_codebuild_buildspec_runtime_20261020 as runtime
from peaso.checks import aws_codebuild_buildspec_runtime_consumer_20261020 as consumer
from peaso.checks import aws_codebuild_buildspec_runtime_admission_20261020 as admission
from peaso.server import validation

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
OTHER = 'ghp_' + '8nR3aS0xM5dW9pL2tG7bJ4kQ6vE1yC3zF0sU'
CLEAN = 'version: 0.2\nphases:\n  build:\n    commands:\n      - echo ready\n'
POSITIVE = CLEAN + 'env:\n  variables:\n    TOKEN: ' + TOKEN + '\n'
CALLER = {'Account': ACCOUNT, 'UserId': 'AIDALOCALCODEBUILD',
          'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/local-review'}


def target(name='AuditProject'):
    return {'scope': SCOPE, 'project_arn': f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{name}'}


def metadata():
    return {'HTTPStatusCode': 200, 'RequestId': '11111111-1111-4111-8111-111111111111'}


def response(selected, text):
    return {'projects': [{'name': selected['project_arn'].split('/')[-1], 'arn': selected['project_arn'],
        'source': {'type': 'NO_SOURCE', 'buildspec': text}, 'description': TOKEN,
        'environment': {'type': 'LINUX_CONTAINER', 'computeType': 'BUILD_GENERAL1_SMALL',
            'image': TOKEN, 'environmentVariables': [{'name': TOKEN, 'value': TOKEN, 'type': 'PLAINTEXT'}]}}],
        'ResponseMetadata': metadata()}


def request(targets=None, **options):
    return {'connector': {'provider': 'aws', 'scopes': [SCOPE], 'auth': {'method': 'access_keys',
        'aws_access_key_id': 'offline-key', 'aws_secret_access_key': 'offline-secret'},
        'options': {'content_secret_scans': True, runtime.OPTION: targets or [target()], 'retry_attempts': 1,
                    'service_concurrency': 1, 'scope_concurrency': 1, 'region_concurrency': 1, **options}},
        'checks': [runtime.CHECK]}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    calls = []
    def blocked(*args, **kwargs):
        calls.append(True)
        raise AssertionError('No live network or credential discovery')
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(aws, '_session', blocked)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    monkeypatch.setenv('AWS_CONFIG_FILE', '/nonexistent/buildspec-runtime-proof')
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', '/nonexistent/buildspec-runtime-proof')
    scanning._RESULTS.clear(); scanning._trufflehog.cache_clear()
    yield
    scanning._RESULTS.clear(); scanning._trufflehog.cache_clear()
    assert not calls


def capture(monkeypatch, texts=(CLEAN,), *, mutate=None, denied=False, caller=None,
            sibling=False, opts=None, supplied=None, seed=False, mixed=False, native_caller=None, endpoint=False):
    targets = [target('AuditProject' + str(i)) for i in range(len(texts))]
    req = deepcopy(supplied or request(targets, **(opts or {})))
    if sibling:
        req['connector']['options']['inventories'] = ['aws_account', runtime.KIND, 'codebuild_project']
        req['connector']['options']['opaque_note'] = 'before/' + TOKEN + '/after'
    if mixed:
        req['checks'].append(runtime.configuration.CHECK)
        if 'inventories' in req['connector']['options']:
            req['connector']['options']['inventories'].append(runtime.configuration.KIND)
        req['connector']['options'][runtime.configuration.OPTION] = [
            {'surface': 'codebuild_environment', 'scope': SCOPE, 'resource_id': target('MixedProject')['project_arn']}]
        req['connector']['options']['mixed_note'] = TOKEN + '/' + OTHER
    session = boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret', region_name=REGION)
    clients = {s: session.client(s, region_name=REGION, endpoint_url=f'https://{s}.{REGION}.amazonaws.com') for s in ('sts', 'codebuild')}
    if endpoint:
        clients['codebuild'].meta._endpoint_url = 'https://untrusted.invalid'
    trace = SimpleNamespace(auth=[], calls=[], readers=[], requests=[], source_session=session)
    for service, client in clients.items():
        def before(params, model, context, _service=service, **kwargs):
            trace.calls.append((_service, model.name, deepcopy(params)))
        client.meta.events.register('before-parameter-build.*.*', before)
    def factory(auth, region):
        trace.auth.append(region)
        return session, 'offline-pinned'
    monkeypatch.setattr(aws, '_session', factory)
    monkeypatch.setattr(aws.Requests, 'client', lambda self, chosen, service, region, **kw: clients[service])
    def native_client(service, **kw):
        assert kw['region_name'] == REGION and kw['endpoint_url'] == f'https://{service}.{REGION}.amazonaws.com'
        assert kw['config'].retries == {'total_max_attempts': 1}
        return clients[service]
    monkeypatch.setattr(session, 'client', native_client)
    original_init = aws.Requests.__init__
    def init(self, options, **kw):
        trace.requests.append(options)
        original_init(self, options, **kw)
        trace.readers.append(self)
        if seed:
            value = {'path/' + TOKEN: {'note': TOKEN, 'encoded': base64.b64encode(TOKEN.encode()).decode()}}
            future = Future(); future.set_result(value)
            self._cache[(TOKEN, 'seed', REGION, TOKEN, 'x/' + TOKEN)] = future
            trace.prior_alias = value
    monkeypatch.setattr(aws.Requests, '__init__', init)
    with ExitStack() as stack:
        stubs = {s: stack.enter_context(Stubber(c)) for s, c in clients.items()}
        stubs['sts'].add_response('get_caller_identity', {**(caller or CALLER), 'ResponseMetadata': metadata()}, {})
        stubs['sts'].add_response('get_caller_identity', {**(native_caller or caller or CALLER), 'ResponseMetadata': metadata()}, {})
        if sibling:
            stubs['codebuild'].add_response('list_projects', {'projects': [TOKEN]}, {})
            stubs['codebuild'].add_response('batch_get_projects', response(target(TOKEN), CLEAN), {'names': [TOKEN]})
        for selected, text in zip(targets, texts):
            if denied:
                stubs['codebuild'].add_client_error('batch_get_projects', service_error_code='AccessDeniedException',
                    service_message=TOKEN, http_status_code=403, expected_params={'names': [selected['project_arn']]})
            else:
                value = response(selected, text)
                if mutate:
                    mutate(value)
                stubs['codebuild'].add_response('batch_get_projects', value, {'names': [selected['project_arn']]})
        if mixed:
            value = response(target('MixedProject'), CLEAN)
            value['projects'][0]['environment']['environmentVariables'] = [{'name': 'TOKEN', 'value': OTHER, 'type': 'PLAINTEXT'}]
            stubs['codebuild'].add_response('batch_get_projects', value, {'names': [target('MixedProject')['project_arn']]})
        snapshot = engine.collect_snapshot(req)
    return snapshot, trace


def rows(snapshot):
    return [row for c in snapshot['collections'] if c['type'] == runtime.KIND for row in c['items']]


def evaluate(snapshot):
    return engine.evaluate_snapshot(snapshot, checks=[runtime.CHECK])['findings']


def native_index(snapshot):
    by_kind = {}
    for collection in snapshot['collections']:
        if collection['type'] in (runtime.KIND, 'aws_account'):
            by_kind.setdefault(collection['type'], []).append(deepcopy(collection))
    return {'context': {'provider': 'aws', 'scope': SCOPE, 'metadata': deepcopy(snapshot['metadata'])}, 'collections': by_kind}


def test_native_real_detectors_public_pass_fail_unknown_roundtrip(monkeypatch):
    for text, expected in ((CLEAN, 'PASS'), (POSITIVE, 'FAIL'), ('ci/buildspec.yml', 'UNKNOWN')):
        snapshot, trace = capture(monkeypatch, (text,))
        results = evaluate(json.loads(json.dumps(snapshot)))
        assert results and all(r['status'] == expected for r in results)
        if expected != 'UNKNOWN':
            assert len(results) == 1
        assert trace.auth and [c[1] for c in trace.calls] == ['GetCallerIdentity', 'GetCallerIdentity', 'BatchGetProjects']
        assert TOKEN not in json.dumps(snapshot) + json.dumps(results)
        if expected == 'FAIL':
            leak, = results[0]['evidence']['secret_leaks']
            assert len(leak['detectors']) == 2
            assert {x['engine'] for x in leak['detectors']} == {'kingfisher', 'trufflehog'}
            assert results[0]['id'] == 'secret-' + leak['fingerprint']


def test_real_sdk_hit_scrubs_adversarial_sibling_options_aliases_and_cache_keys(monkeypatch):
    snapshot, trace = capture(monkeypatch, (POSITIVE,), sibling=True, seed=True)
    findings = evaluate(snapshot)
    assert len(findings) == 1 and findings[0]['status'] == 'FAIL'
    assert any(c[1] == 'ListProjects' for c in trace.calls)
    all_surfaces = json.dumps(snapshot) + json.dumps(findings) + repr(trace.prior_alias) + repr(trace.requests)
    for reader in trace.readers:
        all_surfaces += repr(list(reader._cache)) + repr(reader.configuration_content_redactions)
        assert not reader.configuration_content_redactions and not getattr(reader, runtime.STATE)
    assert TOKEN not in all_surfaces
    assert base64.b64encode(TOKEN.encode()).decode() not in all_surfaces


def test_partial_positive_is_retained_without_manufactured_detector_parts(monkeypatch):
    monkeypatch.setenv('PATH', '/nonexistent/offline-scanner')
    snapshot, _ = capture(monkeypatch, (POSITIVE, CLEAN))
    findings = evaluate(snapshot)
    assert sum(f['status'] == 'FAIL' for f in findings) == 1
    assert any(f['status'] == 'UNKNOWN' for f in findings)
    failed, = [f for f in findings if f['status'] == 'FAIL']
    assert failed['evidence']['complete'] is False
    leak, = failed['evidence']['secret_leaks']
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher'}


def test_mixed_reader_hmac_union_survives_until_global_cleanup(monkeypatch):
    snapshot, trace = capture(monkeypatch, (POSITIVE,), sibling=True, seed=True, mixed=True)
    all_findings = engine.evaluate_snapshot(snapshot, checks=[runtime.CHECK, runtime.configuration.CHECK])['findings']
    failures = [f for f in all_findings if f['status'] == 'FAIL']
    assert len(failures) == 2
    assert len({f['secret_fingerprint'] for f in failures}) == 2
    exposed = json.dumps(snapshot) + json.dumps(all_findings) + repr(trace.requests) + repr(trace.prior_alias)
    assert TOKEN in exposed and OTHER in exposed  # found values stay visible
    assert all(not r.configuration_content_redactions for r in trace.readers)


def test_denial_malformed_identity_and_partial_selected_reference(monkeypatch):
    for kw in ({'denied': True}, {'mutate': lambda r: r['projects'][0].update(name='OtherProject')},
               {'mutate': lambda r: r.update(projectsNotFound=['AuditProject0'])}):
        snapshot, _ = capture(monkeypatch, (POSITIVE,), **kw)
        assert all(f['status'] == 'UNKNOWN' for f in evaluate(snapshot))
    snapshot, _ = capture(monkeypatch, (POSITIVE, 'ci/buildspec.yml'))
    assert sum(f['status'] == 'FAIL' for f in evaluate(snapshot)) == 1
    assert any(f['status'] == 'UNKNOWN' for f in evaluate(snapshot))


@pytest.mark.parametrize('options', [{}, {'content_secret_scans': False},
    {runtime.GRANT: {'token': True, 'scopes': [SCOPE], 'selection': 'fake'}, '_content_secret_scan_kinds': [runtime.KIND]}])
def test_ungranted_content_only_does_not_resolve_credentials(options):
    connector = {'provider': 'aws', 'scopes': [SCOPE], 'auth': {}, 'options': {runtime.OPTION: [target()], **options}}
    result = aws.collect(connector, requirements=[runtime.KIND, 'aws_account'])
    assert not rows(result)
    assert next(c for c in result['collections'] if c['type'] == runtime.KIND)['status'] == 'not_collected'


def test_named_optin_required_and_category_default_do_not_issue_grant():
    for named in ([], ['other']):
        options = {'content_secret_scans': True, runtime.OPTION: [target()], runtime.GRANT: {'forged': True}}
        runtime.issue_engine_grant(options, [SCOPE], named)
        assert runtime.GRANT not in options
    assert runtime.KIND not in engine.plan_collection({'connector': {'provider': 'aws', 'scopes': [SCOPE], 'options': {}}})


@pytest.mark.parametrize('selection', [{}, {'categories': ['exposure']}, {'frameworks': ['HackTricks Cloud Best Practices']}])
def test_default_category_framework_and_internal_kind_do_not_authenticate_optional_content(selection):
    req = request()
    req.pop('checks')
    req.update(selection)
    req['connector']['auth'] = {}
    req['connector']['options'].update(inventories=[runtime.KIND],
        _content_secret_scan_kinds=[runtime.KIND], **{runtime.GRANT: {'forged': True}})
    snapshot = engine.collect_snapshot(req)
    assert not rows(snapshot)


@pytest.mark.parametrize('native_caller,endpoint', [({**CALLER, 'UserId': 'AIDACHANGED'}, False),
    ({**CALLER, 'Account': '999999999999'}, False), (None, True)])
def test_actual_session_identity_or_endpoint_change_is_never_inspected_pass(monkeypatch, native_caller, endpoint):
    snapshot, trace = capture(monkeypatch, (POSITIVE,), native_caller=native_caller, endpoint=endpoint)
    assert all(row['status'] == 'UNKNOWN' for row in evaluate(snapshot))


def test_scope_selection_token_cannot_be_replayed_or_changed():
    options = {'content_secret_scans': True, runtime.OPTION: [target()], '_content_secret_scan_kinds': [runtime.KIND]}
    runtime.issue_engine_grant(options, [SCOPE], [runtime.CHECK])
    options[runtime.OPTION][0] = target('AnotherProject')
    assert runtime.authorize_collector(options, [SCOPE]) is False
    assert runtime.GRANT not in options
    assert runtime.KIND not in options['_content_secret_scan_kinds']


def test_hosted_selector_and_fake_internal_grant_reject_before_auth():
    from fastapi import HTTPException
    settings = SimpleNamespace(auth_mode='cognito')
    with pytest.raises(HTTPException):
        validation.validate_connector('aws', {}, {runtime.OPTION: [{'scope': SCOPE, 'project_arn': 'https://evil.invalid/path'}]}, settings, scopes=[SCOPE])
    with pytest.raises(HTTPException):
        validation.validate_connector('aws', {}, {runtime.OPTION: [target()], runtime.GRANT: {'forged': True}}, settings, scopes=[SCOPE])


def test_read_budget_and_cancel_event_bound_native_calls(monkeypatch):
    snapshot, trace = capture(monkeypatch, (POSITIVE,), opts={'max_calls': 1})
    assert evaluate(snapshot)[0]['status'] == 'UNKNOWN'
    assert [c[1] for c in trace.calls] == ['GetCallerIdentity']
    event = SimpleNamespace(is_set=lambda: True)
    snapshot, trace = capture(monkeypatch, (POSITIVE,), opts={'cancel_event': event})
    assert not any(c[1] == 'BatchGetProjects' for c in trace.calls)


def test_registered_admission_is_idempotent_and_all_predecessor_bytes_preserved():
    from peaso.checks import CHECKS
    before = tuple(CHECKS)
    admission.install(); admission.install()
    assert tuple(CHECKS) == before
    root = Path(__file__).resolve().parents[1]
    archive = json.loads(gzip.decompress((root / 'peaso/checks/aws_codebuild_buildspec_runtime_predecessors_20261020.json.gz').read_bytes()))
    for name, row in archive['files'].items():
        if name.startswith('peaso/checks/') and not name.endswith('/__init__.py'):
            assert (root / name).read_bytes() == bytes.fromhex(row['hex'])


def test_admission_failure_leaves_registry_and_cases_unchanged(monkeypatch):
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    before, cases = tuple(CHECKS), deepcopy(CASES[runtime.CHECK])
    monkeypatch.setattr(runtime, 'scan_content', lambda *a, **kw: {'complete': True, 'leaks': []})
    with pytest.raises(RuntimeError):
        admission.install()
    with pytest.raises(RuntimeError):
        engine.collect_snapshot(request())
    assert tuple(CHECKS) == before and CASES[runtime.CHECK] == cases


def test_registration_failure_rolls_back_only_new_control(monkeypatch):
    import peaso.checks as checks
    from peaso.checks.fixtures import CASES
    before, case = tuple(checks.CHECKS), deepcopy(CASES[runtime.CHECK])
    original = next(c for c in checks.CHECKS if c.id == runtime.CHECK)
    checks.CHECKS.remove(original)
    CASES.pop(runtime.CHECK)
    def broken_register(*args, **kwargs):
        def broken(function):
            checks.CHECKS.append(original)
            raise RuntimeError('simulated registration failure')
        return broken
    try:
        monkeypatch.setattr(checks, 'register', broken_register)
        with pytest.raises(RuntimeError, match='simulated registration failure'):
            admission.install()
        assert not any(c.id == runtime.CHECK for c in checks.CHECKS) and runtime.CHECK not in CASES
    finally:
        checks.CHECKS[:] = before
        CASES[runtime.CHECK] = case


def test_malformed_or_foreign_envelope_and_json_replay_are_unknown(monkeypatch):
    snapshot, _ = capture(monkeypatch, (POSITIVE,))
    snapshot = json.loads(json.dumps(snapshot))
    index = native_index(snapshot)
    item = rows(snapshot)[0]
    assert consumer.evaluate(item, index)[0] == 'FAIL'
    for field, value in (('scope', ACCOUNT + '/us-west-2'), ('capture', 'fake')):
        bad = deepcopy(item); bad['_provenance'][field] = value
        assert consumer.evaluate(bad, index)[0] == 'UNKNOWN'


def test_signed_native_sdk_http_real_detectors_and_private_debug_metadata(monkeypatch):
    """Only socket transport is fake; real signing, wire guard and parser run."""
    from urllib.parse import urlsplit, parse_qs
    session = boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret', region_name=REGION)
    original_client = session.client
    wire = []
    aliases = []
    class Raw:
        def __init__(self, data):
            self.data = io.BytesIO(data)
        def stream(self, amt=1024, decode_content=False):
            while part := self.data.read(amt):
                yield part
        def close(self):
            self.data.close()
    def client(service, **kwargs):
        sdk = original_client(service, **kwargs)
        def send(request):
            parsed = urlsplit(request.url)
            assert request.method == 'POST' and parsed.netloc == f'{service}.{REGION}.amazonaws.com'
            assert parsed.path == '/' and not parsed.query
            assert any(k.lower() == 'authorization' for k in request.headers)
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            headers = {'x-amzn-requestid': metadata()['RequestId'], 'x-private-canary': TOKEN}
            if service == 'sts':
                assert parse_qs(body)['Action'] == ['GetCallerIdentity']
                payload = ('<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
                    '<GetCallerIdentityResult><Arn>' + CALLER['Arn'] + '</Arn><UserId>' + CALLER['UserId'] + '</UserId><Account>'
                    + ACCOUNT + '</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>' + metadata()['RequestId']
                    + '</RequestId></ResponseMetadata></GetCallerIdentityResponse>').encode()
                headers['content-type'] = 'text/xml'
                wire.append('GetCallerIdentity')
            else:
                assert json.loads(body) == {'names': [target()['project_arn']]}
                payload = json.dumps({k: v for k, v in response(target(), POSITIVE).items() if k != 'ResponseMetadata'}).encode()
                headers['content-type'] = 'application/x-amz-json-1.1'
                wire.append('BatchGetProjects')
            return AWSResponse(request.url, 200, headers, Raw(payload))
        monkeypatch.setattr(sdk._endpoint.http_session, 'send', send)
        return sdk
    monkeypatch.setattr(session, 'client', client)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'offline-native-wire'))
    original_init = aws.Requests.__init__
    def initialize(self, options, **kwargs):
        original_init(self, options, **kwargs)
        future = Future()
        value = {'path/' + TOKEN: {'native_sibling': TOKEN}}
        aliases.append(value)
        future.set_result(value)
        self._cache[(TOKEN, 'native-wire', REGION)] = future
    monkeypatch.setattr(aws.Requests, '__init__', initialize)
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    logger = logging.getLogger('botocore')
    old_level = logger.level
    logger.setLevel(logging.DEBUG); logger.addHandler(handler)
    try:
        snapshot = engine.collect_snapshot(request(opaque_note=TOKEN))
    finally:
        logger.removeHandler(handler); logger.setLevel(old_level)
    findings = evaluate(snapshot)
    assert wire == ['GetCallerIdentity', 'GetCallerIdentity', 'BatchGetProjects']
    assert len(findings) == 1 and findings[0]['status'] == 'FAIL'
    leak, = findings[0]['evidence']['secret_leaks']
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in json.dumps(snapshot) + json.dumps(findings) + repr(aliases) + output.getvalue()
