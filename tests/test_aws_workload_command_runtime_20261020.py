"""Directed normal-engine acceptance using actual native SDK and offline engines."""
from contextlib import ExitStack
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber
import pytest

from peaso import engine, secret_scanning as scanning
from peaso.collectors import aws, aws_workload_command_runtime_20261020 as runtime
from peaso.checks import aws_workload_command_shared_successor_20261020 as shared
from peaso.checks import aws_workload_command_runtime_admission_20261020 as admission
from peaso.server import validation

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
OTHER = 'ghp_' + '8nR3aS0xM5dW9pL2tG7bJ4kQ6vE1yC3zF0sU'
CALLER = {'Account': ACCOUNT, 'UserId': 'AIDALOCALREVIEW', 'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/local-review'}
ROOT = Path(__file__).resolve().parents[1]


def target(service='ecs', name='AuditDefinition', revision=3, scope=SCOPE):
    account, region = scope.split('/')
    resource = 'task-definition' if service == 'ecs' else 'job-definition'
    return {'scope': scope, 'service': service,
        'definition_arn': f'arn:aws:{service}:{region}:{account}:{resource}/{name}:{revision}'}


def metadata():
    return {'HTTPStatusCode': 200, 'RequestId': '11111111-1111-4111-8111-111111111111'}


def response(selected, command=None, entry=None):
    command = ['echo', 'ready'] if command is None else command
    entry = ['/bin/sh', '-c'] if entry is None else entry
    _, _, _, name, revision = runtime.source.parse(selected)
    if selected['service'] == 'ecs':
        return {'taskDefinition': {'taskDefinitionArn': selected['definition_arn'],
            'family': name, 'revision': revision, 'status': 'ACTIVE',
            'containerDefinitions': [{'name': 'app', 'entryPoint': entry, 'command': command,
                'image': TOKEN, 'environmentFiles': [{'type': 's3', 'value': TOKEN}],
                'secrets': [{'name': 'TOKEN', 'valueFrom': TOKEN}]}]}, 'ResponseMetadata': metadata()}
    return {'jobDefinitions': [{'jobDefinitionArn': selected['definition_arn'], 'jobDefinitionName': name,
        'revision': revision, 'status': 'ACTIVE', 'type': 'container',
        'containerProperties': {'command': command, 'image': TOKEN,
            'secrets': [{'name': 'TOKEN', 'valueFrom': TOKEN}]}}], 'ResponseMetadata': metadata()}


def request(targets=None, **options):
    return {'connector': {'provider': 'aws', 'scopes': [SCOPE],
        'auth': {'method': 'access_keys', 'aws_access_key_id': 'offline-key', 'aws_secret_access_key': 'offline-secret'},
        'options': {'content_secret_scans': True, runtime.OPTION: targets or [target()],
            'retry_attempts': 1, 'service_concurrency': 1, 'scope_concurrency': 1, 'region_concurrency': 1, **options}},
        'checks': [runtime.CHECK]}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    attempts = []
    def blocked(*args, **kwargs):
        attempts.append(True)
        raise AssertionError('live network and credential discovery forbidden')
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(aws, '_session', blocked)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    monkeypatch.setenv('AWS_CONFIG_FILE', '/nonexistent/workload-runtime-proof')
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', '/nonexistent/workload-runtime-proof')
    scanning._RESULTS.clear(); scanning._trufflehog.cache_clear()
    yield
    scanning._RESULTS.clear(); scanning._trufflehog.cache_clear()
    assert not attempts


def capture(monkeypatch, specs, *, native_caller=None, req=None):
    selected = [t for t, _ in specs]
    req = deepcopy(req or request(selected))
    sdk = boto3.Session(aws_access_key_id='offline-key', aws_secret_access_key='offline-secret', region_name=REGION)
    clients = {s: sdk.client(s, region_name=REGION, endpoint_url=f'https://{s}.{REGION}.amazonaws.com') for s in ('sts', 'ecs', 'batch')}
    trace = SimpleNamespace(calls=[], auth=[], clients=clients, closes=[], sends={})
    for service, client in clients.items():
        trace.sends[service] = client._endpoint.http_session.send
        original_close = client.close
        def close(_service=service, _close=original_close):
            trace.closes.append(_service)
            return _close()
        monkeypatch.setattr(client, 'close', close)
        def before(params, model, context, _service=service, **kwargs):
            trace.calls.append((_service, model.name, deepcopy(params)))
        client.meta.events.register('before-parameter-build.*.*', before)
    def factory(auth, region):
        trace.auth.append(region)
        return sdk, 'offline-pinned'
    monkeypatch.setattr(aws, '_session', factory)
    monkeypatch.setattr(aws.Requests, 'client', lambda self, chosen, service, region, **kw: clients[service])
    def client(service, **kw):
        assert kw['region_name'] == REGION and kw['endpoint_url'] == f'https://{service}.{REGION}.amazonaws.com'
        assert kw['config'].retries == {'total_max_attempts': 1} and kw['config'].proxies == {}
        assert kw['verify'] is True and kw['config'].ignore_configured_endpoint_urls
        return clients[service]
    monkeypatch.setattr(sdk, 'client', client)
    with ExitStack() as stack:
        stubs = {s: stack.enter_context(Stubber(c)) for s, c in clients.items()}
        for caller in (CALLER, native_caller or CALLER):
            stubs['sts'].add_response('get_caller_identity', {**caller, 'ResponseMetadata': metadata()}, {})
        for t, payload in specs:
            method = 'describe_task_definition' if t['service'] == 'ecs' else 'describe_job_definitions'
            if payload is None:
                stubs[t['service']].add_client_error(method, service_error_code='AccessDeniedException',
                    service_message=TOKEN, http_status_code=403, expected_params=runtime.source.request_for(t))
            else:
                stubs[t['service']].add_response(method, payload, runtime.source.request_for(t))
        snapshot = engine.collect_snapshot(req)
    return snapshot, trace


def findings(snapshot):
    return engine.evaluate_snapshot(snapshot, checks=[runtime.CHECK])['findings']


def test_real_normal_engine_sdk_dual_detector_value_union_and_saved_json_replay(monkeypatch, tmp_path):
    ecs, batch = target(), target('batch')
    snapshot, trace = capture(monkeypatch, [(ecs, response(ecs, [TOKEN, OTHER], [TOKEN])), (batch, response(batch, [TOKEN]))])
    rows = findings(snapshot)
    failed = [f for f in rows if f['status'] == 'FAIL']
    assert len(failed) == 2
    assert {d['engine'] for f in failed for leak in f['evidence']['secret_leaks'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert all(len(f['evidence']['secret_leaks']) == 1 for f in failed)
    assert sorted(len(f['evidence']['secret_leaks'][0]['locations']) for f in failed) == [1, 3]
    assert [c[1] for c in trace.calls] == ['GetCallerIdentity', 'GetCallerIdentity', 'DescribeTaskDefinition', 'DescribeJobDefinitions']
    assert [c[2] for c in trace.calls[2:]] == [runtime.source.request_for(ecs), runtime.source.request_for(batch)]
    saved = tmp_path / 'snapshot.json'; saved.write_text(json.dumps(snapshot))
    code = 'import json,sys; from peaso.engine import evaluate_snapshot; print(json.dumps(evaluate_snapshot(json.load(open(sys.argv[1])), checks=[sys.argv[2]])["findings"]))'
    replay = subprocess.run([sys.executable, '-c', code, str(saved), runtime.CHECK], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert replay.returncode == 0, replay.stderr
    assert json.loads(replay.stdout) == rows
    public = json.dumps(snapshot) + json.dumps(rows)
    for value in (TOKEN, OTHER, 'offline-key', 'offline-secret', 'environmentFiles', 'AuditDefinition'):
        assert value not in public


@pytest.mark.parametrize('empty', [False, True])
def test_native_clean_and_explicit_empty_complete(monkeypatch, empty):
    ecs, batch = target(), target('batch')
    snapshot, _ = capture(monkeypatch, [(ecs, response(ecs, [] if empty else None, [] if empty else None)), (batch, response(batch, [] if empty else None))])
    assert [f['status'] for f in findings(snapshot)] == ['PASS']


def test_missing_command_is_unknown_and_partial_positive_survives(monkeypatch):
    ecs, batch = target(), target('batch')
    payload = response(ecs, [TOKEN]); del payload['taskDefinition']['containerDefinitions'][0]['entryPoint']
    snapshot, _ = capture(monkeypatch, [(ecs, payload), (batch, None)])
    failed, = [f for f in findings(snapshot) if f['status'] == 'FAIL']
    assert failed['evidence']['complete'] is False
    payload = response(ecs); del payload['taskDefinition']['containerDefinitions'][0]['command']
    snapshot, _ = capture(monkeypatch, [(ecs, payload)])
    assert all(f['status'] == 'UNKNOWN' for f in findings(snapshot))


@pytest.mark.parametrize('mutation', ['denied', 'revision', 'foreign', 'eks', 'placeholder'])
def test_native_denied_exact_revision_crossscope_and_unsupported_are_unknown(monkeypatch, mutation):
    t = target('batch') if mutation in ('eks', 'placeholder') else target()
    payload = response(t)
    if mutation == 'denied':payload = None
    elif mutation == 'revision':payload['taskDefinition']['revision'] = 4
    elif mutation == 'foreign':payload['taskDefinition']['taskDefinitionArn'] = t['definition_arn'].replace(ACCOUNT, '999999999999')
    elif mutation == 'eks':payload['jobDefinitions'][0]['eksProperties'] = {'podProperties': {'containers': []}}
    elif mutation == 'placeholder':payload['jobDefinitions'][0]['containerProperties']['command'] = ['Ref::unresolved']
    snapshot, _ = capture(monkeypatch, [(t, payload)])
    assert not any(f['status'] in ('PASS', 'FAIL') for f in findings(snapshot))


def test_native_caller_drift_is_unknown(monkeypatch):
    t = target()
    snapshot, _ = capture(monkeypatch, [(t, response(t, [TOKEN]))], native_caller={**CALLER, 'UserId': 'AIDACHANGED'})
    assert not any(f['status'] in ('PASS', 'FAIL') for f in findings(snapshot))


def test_actual_partial_detector_keeps_positive(monkeypatch):
    monkeypatch.setenv('PATH', '/nonexistent/offline-scanner')
    t = target()
    snapshot, _ = capture(monkeypatch, [(t, response(t, [TOKEN]))])
    failed, = [f for f in findings(snapshot) if f['status'] == 'FAIL']
    assert failed['evidence']['complete'] is False
    assert {d['engine'] for leak in failed['evidence']['secret_leaks'] for d in leak['detectors']} == {'kingfisher'}


@pytest.mark.parametrize('options', [{}, {'content_secret_scans': False}, {'content_secret_scans': True, runtime.GRANT: {'fake': True}, '_content_secret_scan_kinds': [runtime.KIND]}])
def test_ungranted_content_only_never_authenticates(options):
    snapshot = aws.collect({'provider': 'aws', 'scopes': [SCOPE], 'auth': {}, 'options': {runtime.OPTION: [target()], **options}}, [runtime.KIND])
    assert all(c['status'] == 'not_collected' for c in snapshot['collections'])


def test_default_metadata_plan_excludes_command_content():
    req = {'connector': {'provider': 'aws', 'scopes': [SCOPE], 'options': {}}}
    assert runtime.KIND not in engine.plan_collection(req)
    for named in ([], ['other']):
        options = {'content_secret_scans': True, runtime.OPTION: [target()]}
        runtime.issue_engine_grant(options, [SCOPE], named)
        assert runtime.GRANT not in options


@pytest.mark.parametrize('kind', ['missing', 'foreign_scope', 'unversioned', 'duplicate', 'bad_service', 'too_many'])
def test_invalid_selection_rejected_before_auth(kind):
    req = request()
    options = req['connector']['options']
    if kind == 'missing':options.pop(runtime.OPTION)
    elif kind == 'foreign_scope':options[runtime.OPTION][0]['scope'] = '999999999999/' + REGION
    elif kind == 'unversioned':options[runtime.OPTION][0]['definition_arn'] = options[runtime.OPTION][0]['definition_arn'].rsplit(':', 1)[0]
    elif kind == 'duplicate':options[runtime.OPTION] *= 2
    elif kind == 'bad_service':options[runtime.OPTION][0]['service'] = 'eks'
    elif kind == 'too_many':options[runtime.OPTION] = [target(name='D' + str(i)) for i in range(9)]
    with pytest.raises(ValueError):engine.collect_snapshot(req)




def test_native_clients_transport_and_handlers_cleanup_on_success_and_denial(monkeypatch):
    t = target()
    for payload in (response(t), None):
        _, trace = capture(monkeypatch, [(t, payload)])
        assert trace.closes.count('sts') == 1 and trace.closes.count('ecs') == 1
        for service, client in trace.clients.items():
            assert client._endpoint.http_session.send == trace.sends[service]
            operation = 'GetCallerIdentity' if service == 'sts' else 'DescribeTaskDefinition' if service == 'ecs' else 'DescribeJobDefinitions'
            event = 'before-send.' + client.meta.service_model.service_id.hyphenize() + '.' + operation
            assert not any(getattr(handler, '__name__', '') == 'guard' for handler in client.meta.events._emitter._handlers.prefix_search(event))


def test_selected_unconfigured_account_cannot_borrow_base_session(monkeypatch):
    t = target()
    foreign_scope = '999999999999/' + REGION
    foreign = target(scope=foreign_scope)
    req = request([t, foreign]); req['connector']['scopes'] = [SCOPE, foreign_scope]
    snapshot, trace = capture(monkeypatch, [(t, response(t, [TOKEN]))], req=req)
    native = snapshot['metadata'][runtime.CAPTURE]['native']
    assert len(native['items']) == 2
    assert native['items'][1]['native_bound'] is False
    assert native['items'][1]['leaks'] == []
    assert len([call for call in trace.calls if call[0] == 'ecs']) == 1
    failed, = [f for f in findings(snapshot) if f['status'] == 'FAIL']
    assert failed['evidence']['complete'] is False


def test_connector_rejects_invalid_foreign_provider_and_private_grants():
    from fastapi import HTTPException
    settings = SimpleNamespace(auth_mode='cognito')
    for provider, options in (
            ('gcp', {runtime.OPTION: [target()]}),
            ('aws', {runtime.OPTION: [dict(target(), definition_arn='https://untrusted.invalid')]}),
            ('aws', {runtime.OPTION: [target()], runtime.GRANT: {'forged': True}})):
        with pytest.raises(HTTPException) as raised:
            validation.validate_connector(provider, {}, options, settings, scopes=[SCOPE])
        assert raised.value.status_code == 422


def test_saved_capture_binding_damage_cannot_publish_secret_or_clean_pass(monkeypatch):
    from peaso.snapshot import seal
    t = target()
    snapshot, _ = capture(monkeypatch, [(t, response(t, [TOKEN]))])
    damaged = deepcopy(snapshot)
    damaged['metadata'][runtime.CAPTURE]['native']['binding'] = '0' * 64
    assert all(f['status'] == 'UNKNOWN' for f in findings(seal(damaged)))


def test_native_bounds_cannot_change_under_same_admission(monkeypatch):
    admission.reviewed_inputs()
    with monkeypatch.context() as patch:
        patch.setattr(runtime.source, 'MAX_CONTENT', runtime.source.MAX_CONTENT * 2)
        with pytest.raises(RuntimeError, match='schema changed'):
            admission.reviewed_inputs()
    admission.reviewed_inputs()


@pytest.mark.parametrize('selection', [{}, {'categories': ['exposure']}, {'frameworks': ['HackTricks Cloud Best Practices']}])
def test_default_category_framework_and_forged_kind_never_grant_command_content(selection):
    req = request(inventories=[runtime.KIND], **{runtime.GRANT: {'fake': True}, '_content_secret_scan_kinds': [runtime.KIND]})
    req.pop('checks'); req.update(selection)
    snapshot = engine.collect_snapshot(req)
    assert all(not c['items'] and c['status'] == 'not_collected' for c in snapshot['collections'])
    assert runtime.CHECK not in [c.id for c in engine._selection('aws', req.get('categories'), None, req.get('frameworks'))[1]]


def test_normal_call_budget_exhaustion_is_unknown_without_definition_read(monkeypatch):
    t = target()
    snapshot, trace = capture(monkeypatch, [(t, response(t, [TOKEN]))], req=request([t], max_calls=1))
    assert [call[1] for call in trace.calls] == ['GetCallerIdentity']
    assert all(f['status'] == 'UNKNOWN' for f in findings(snapshot))
