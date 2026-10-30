"""Directed proposal proof: native botocore Stubber and installed offline engines."""
from contextlib import ExitStack
from copy import deepcopy
import json
import socket
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber
import pytest

from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings
from peaso.collectors import aws_codebuild_buildspec_source_20261020 as source
from peaso.checks import aws_codebuild_buildspec_source_20261020 as consumer

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
CLEAN = 'version: 0.2\nphases:\n  build:\n    commands:\n      - echo ready\n'
POSITIVE = CLEAN + 'env:\n  variables:\n    TOKEN: ' + TOKEN + '\n'
CALLER = {'Account': ACCOUNT, 'UserId': 'AIDALOCALREVIEW',
          'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/local-review'}


def metadata():
    return {'HTTPStatusCode': 200, 'RequestId': '11111111-1111-4111-8111-111111111111',
            'HTTPHeaders': {'discarded': TOKEN}}


def target(name='AuditProject'):
    return {'scope': SCOPE, 'project_arn': f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{name}'}


def options(targets):
    return {'content_secret_scans': True, 'check_id': source.CHECK,
            'content_secret_scan_grants': [source.GRANT], source.OPTION: targets}


def response(selected, text):
    return {'projects': [{'name': selected['project_arn'].split('/')[-1],
        'arn': selected['project_arn'], 'source': {'type': 'NO_SOURCE', 'buildspec': text},
        'description': TOKEN, 'environment': {'type': 'LINUX_CONTAINER', 'image': TOKEN,
            'computeType': 'BUILD_GENERAL1_SMALL', 'environmentVariables': [
                {'name': TOKEN, 'value': TOKEN, 'type': 'PLAINTEXT'}]}}],
        'ResponseMetadata': metadata()}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    attempts = []
    def blocked(*args, **kwargs):
        attempts.append(True)
        raise AssertionError('Live network/auth is forbidden')
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    monkeypatch.setenv('AWS_CONFIG_FILE', '/nonexistent/buildspec-local-proof')
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', '/nonexistent/buildspec-local-proof')
    scanning._RESULTS.clear()
    scanning._trufflehog.cache_clear()
    yield
    scanning._RESULTS.clear()
    scanning._trufflehog.cache_clear()
    assert not attempts


def capture(texts, *, mutate=None, caller=None, error=False, endpoint=False, auth_error=False):
    targets = [target('AuditProject' + str(i)) for i in range(len(texts))]
    plan = source.prepare(options(targets), [SCOPE])
    session = boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret', region_name=REGION)
    clients = {s: session.client(s, region_name=REGION, endpoint_url=f'https://{s}.{REGION}.amazonaws.com')
               for s in ('sts', 'codebuild')}
    trace = SimpleNamespace(calls=[], auth=[])
    for service, client in clients.items():
        def before(params, model, context, _service=service, **kwargs):
            trace.calls.append((_service, model.name, deepcopy(params)))
        client.meta.events.register('before-parameter-build.*.*', before)
    def client(service, **kwargs):
        assert kwargs['endpoint_url'] == f'https://{service}.{REGION}.amazonaws.com'
        assert kwargs['config'].retries == {'total_max_attempts': 1}
        assert 0 < kwargs['config'].read_timeout <= 3
        if endpoint:
            clients[service].meta._endpoint_url = 'https://untrusted.invalid'
        return clients[service]
    def factory(scope):
        trace.auth.append(scope)
        if auth_error:
            raise RuntimeError(TOKEN)
        return SimpleNamespace(client=client)
    with ExitStack() as stack:
        stubs = {s: stack.enter_context(Stubber(c)) for s, c in clients.items()}
        stubs['sts'].add_response('get_caller_identity', {**(caller or CALLER), 'ResponseMetadata': metadata()}, {})
        for selected, text in zip(targets, texts):
            if error:
                stubs['codebuild'].add_client_error('batch_get_projects', service_error_code='AccessDeniedException',
                    service_message=TOKEN, http_status_code=403, expected_params={'names': [selected['project_arn']]})
            else:
                payload = response(selected, text)
                if mutate:
                    mutate(payload)
                stubs['codebuild'].add_response('batch_get_projects', payload, {'names': [selected['project_arn']]})
        collection = source.collect(plan, factory)
    return collection, trace


def statuses(collection):
    return [consumer.evaluate(row, collection)[0] for row in collection['items']]


def test_real_installed_dual_engines_native_pass_fail_and_privacy():
    collection, trace = capture([CLEAN, POSITIVE])
    # Global coverage is complete; each row's own result remains distinct.
    assert statuses(collection) == ['PASS', 'FAIL']
    assert trace.auth == [SCOPE]
    assert [c[1] for c in trace.calls] == ['GetCallerIdentity', 'BatchGetProjects', 'BatchGetProjects']
    assert all(c[2] == {'names': [target('AuditProject' + str(i))['project_arn']]}
               for i, c in enumerate(trace.calls[1:]))
    row = collection['items'][1]
    assert len(row['leaks']) == 1
    assert {d['engine'] for d in row['leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    public = json.dumps(collection) + json.dumps(consumer.evaluate(row, collection))
    for raw in (TOKEN, POSITIVE, target('AuditProject1')['project_arn'], 'offline-key', 'local-review'):
        assert raw not in public
    assert row['field'] == 'projects[0].source.buildspec'
    assert row['verification'] == 'not_attempted'


@pytest.mark.parametrize('text', ['', 'buildspec.yml', 'ci/buildspec.yaml',
    's3://private-bucket/buildspec.yml', 'arn:aws:s3:::private-bucket/buildspec.yml',
    'ci/' + TOKEN + '/buildspec.yml', 'version: 0.3\nphases: {}\n', '{"version":0.2}'])
def test_references_empty_and_ambiguous_source_are_unknown(text):
    collection, _ = capture([text])
    assert statuses(collection) == ['UNKNOWN']
    assert not collection['items'][0]['native_complete']
    assert not collection['items'][0]['engines']
    assert text not in json.dumps(collection) if text else True


@pytest.mark.parametrize('field', ['arn', 'name'])
def test_native_identity_mismatch_is_unknown(field):
    collection, _ = capture([POSITIVE], mutate=lambda p: p['projects'][0].update({field: 'wrong'}))
    assert statuses(collection) == ['UNKNOWN']
    assert not collection['items'][0]['leaks']


def test_denial_auth_failure_caller_mismatch_and_endpoint_are_unknown():
    for kwargs in ({'error': True}, {'auth_error': True}, {'caller': {**CALLER, 'Account': '999999999999'}}, {'endpoint': True}):
        collection, trace = capture([POSITIVE], **kwargs)
        assert statuses(collection) == ['UNKNOWN']
        assert TOKEN not in json.dumps(collection)
        if kwargs.get('caller') or kwargs.get('endpoint') or kwargs.get('auth_error'):
            assert not any(c[0] == 'codebuild' for c in trace.calls)


def test_partial_positive_retained_and_clean_partial_unknown(monkeypatch):
    # Exercise actual Kingfisher; make TruffleHog unavailable through lookup.
    monkeypatch.setenv('PATH', '/nonexistent/buildspec-offline-engine')
    collection, _ = capture([POSITIVE, CLEAN])
    assert statuses(collection) == ['FAIL', 'UNKNOWN']
    row = collection['items'][0]
    assert row['engines'] == [
        {'engine': 'kingfisher', 'version': scanning.KINGFISHER_VERSION, 'status': 'complete'},
        {'engine': 'trufflehog', 'version': scanning.TRUFFLEHOG_VERSION, 'status': 'unavailable'}]
    assert consumer.evaluate(row, collection)[1]['complete'] is False


def test_partial_selected_reference_keeps_positive_but_no_clean_pass():
    collection, _ = capture([POSITIVE, CLEAN, 'ci/buildspec.yml'])
    assert statuses(collection) == ['FAIL', 'UNKNOWN', 'UNKNOWN']


def test_total_byte_exhaustion_keeps_earlier_positive():
    collection, trace = capture([POSITIVE, CLEAN, CLEAN],
        mutate=lambda p: p['projects'][0].update(description='x' * (1400 * 1024)))
    assert statuses(collection) == ['FAIL', 'UNKNOWN', 'UNKNOWN']
    assert len(trace.calls) == 4
    assert collection['response_bytes'] <= source.MAX_TOTAL


def test_existing_value_level_dedup_retains_both_detectors_and_locations():
    collection, _ = capture([POSITIVE, POSITIVE])
    findings = []
    for row in collection['items']:
        status, evidence = consumer.evaluate(row, collection)
        findings.append({'id': row['id'], 'provider': 'aws', 'scope': row['scope'], 'resource_id': row['id'],
            'check_id': source.CHECK, 'status': status, 'evidence': evidence})
    merged = deduplicate_secret_findings(findings)
    assert len(merged) == 1
    leak, = merged[0]['evidence']['secret_leaks']
    assert len(leak['locations']) == 2 and len(leak['detectors']) == 2
    assert TOKEN not in json.dumps(merged)


@pytest.mark.parametrize('edit', [
    lambda o: o.update(content_secret_scans=False), lambda o: o.pop('check_id'),
    lambda o: o.update(content_secret_scan_grants=[]), lambda o: o.update(content_secret_scan_grants=['other']),
    lambda o: o.update(selected_aws_codebuild_inline_buildspecs=[target()] * 2),
    lambda o: o.update(selected_aws_codebuild_inline_buildspecs=[target(str(i) + 'x') for i in range(9)]),
    lambda o: o[source.OPTION][0].update(project_arn='arn:aws:codebuild:us-west-2:123456789012:project/AuditProject')])
def test_invalid_or_ungranted_selection_fails_before_auth(edit):
    opts = options([target()])
    edit(opts)
    with pytest.raises(ValueError):
        source.prepare(opts, [SCOPE])


def test_plan_tamper_fails_before_auth():
    plan = source.prepare(options([target()]), [SCOPE])
    plan['body']['targets'][0]['project_arn'] += 'Other'
    calls = []
    with pytest.raises(ValueError):
        source.collect(plan, lambda s: calls.append(s))
    assert not calls


def test_loaded_code_and_imported_helper_binding_fail_before_auth(monkeypatch):
    def counterfeit(*args, **kwargs):
        return b'clean'
    with monkeypatch.context() as patch:
        patch.setattr(source, 'inline_bytes', counterfeit)
        with pytest.raises((ValueError, RuntimeError)):
            source.prepare(options([target()]), [SCOPE])
    with monkeypatch.context() as patch:
        patch.setattr(source, 'scan_content', counterfeit)
        with pytest.raises((ValueError, RuntimeError)):
            source.prepare(options([target()]), [SCOPE])
    with monkeypatch.context() as patch:
        patch.setattr(source.inline_bytes, '__code__', counterfeit.__code__)
        with pytest.raises((ValueError, RuntimeError)):
            source.prepare(options([target()]), [SCOPE])


def test_bounds_and_native_call_limit_do_not_read_more():
    collection, _ = capture([CLEAN + '#' * (source.MAX_CONTENT + 1)])
    assert statuses(collection) == ['UNKNOWN']
    collection, _ = capture([CLEAN], mutate=lambda p: p['projects'][0].update(description='x' * (source.MAX_RESPONSE + 1)))
    assert statuses(collection) == ['UNKNOWN']
    with pytest.raises(ValueError, match='call_bound'):
        source.native_call(None, 'codebuild', REGION, 'BatchGetProjects', {}, 1e20,
                           {'calls': source.MAX_CALLS, 'bytes': 0})
    with pytest.raises(ValueError, match='deadline'):
        source.native_call(None, 'codebuild', REGION, 'BatchGetProjects', {}, 0, {'calls': 0, 'bytes': 0})


@pytest.mark.parametrize('change', ['none', 'body', 'target', 'url', 'retry'])
def test_native_serialized_wire_guard_without_live_transport(change):
    from botocore.awsrequest import AWSRequest
    selected = target()
    args = {'names': [selected['project_arn']]}
    session = boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret', region_name=REGION)
    endpoint = f'https://codebuild.{REGION}.amazonaws.com'
    client = session.client('codebuild', region_name=REGION, endpoint_url=endpoint)
    def send(**passed):
        wire = client._convert_to_request_dict(passed, client.meta.service_model.operation_model('BatchGetProjects'), endpoint_url=endpoint)
        request = AWSRequest(method=wire['method'], url=wire['url'], data=wire['body'], headers=wire['headers']).prepare()
        if change == 'body':
            request.body = json.dumps({'names': ['OtherProject']}).encode()
        elif change == 'target':
            request.headers['X-Amz-Target'] = 'CodeBuild_20161006.StartBuild'
        elif change == 'url':
            request.url = 'https://untrusted.invalid/'
        event = 'before-send.codebuild.BatchGetProjects'
        client.meta.events.emit(event, request=request)
        if change == 'retry':
            client.meta.events.emit(event, request=request)
        return response(selected, CLEAN)
    # Fake only transport dispatch; use real model, serializer and event bus.
    client.batch_get_projects = send
    fake = SimpleNamespace(client=lambda *a, **k: client)
    state = {'calls': 0, 'bytes': 0}
    if change == 'none':
        payload, receipt = source.native_call(fake, 'codebuild', REGION, 'BatchGetProjects', args, 1e20, state)
        assert payload['projects'][0]['arn'] == selected['project_arn']
        assert receipt['operation'] == 'BatchGetProjects'
    else:
        with pytest.raises(ValueError, match='wire_binding'):
            source.native_call(fake, 'codebuild', REGION, 'BatchGetProjects', args, 1e20, state)


@pytest.mark.parametrize('field,value', [('field', 'source.location'), ('scope', ACCOUNT + '/us-west-2'),
    ('capture', 'buildspec-capture:' + 'a' * 32), ('binding', 'a' * 64), ('principal', None),
    ('native_complete', False), ('verification', 'verified')])
def test_consumer_rejects_foreign_or_unbound_positive(field, value):
    collection, _ = capture([POSITIVE])
    collection['items'][0][field] = value
    assert statuses(collection) == ['UNKNOWN']


def test_consumer_rejects_raw_paths_and_wrong_request_provenance():
    collection, _ = capture([POSITIVE])
    collection['items'][0]['leaks'][0]['locations'][0]['path'] = TOKEN + '/buildspec.yml'
    assert statuses(collection) == ['UNKNOWN']
    collection, _ = capture([POSITIVE])
    collection['items'][0]['requests'][1]['request'] = 'a' * 64
    assert statuses(collection) == ['UNKNOWN']
