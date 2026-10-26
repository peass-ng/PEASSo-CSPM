"""Device login and account opt-out; synthetic tokens and no external inference."""
import base64
import json
import time
from types import SimpleNamespace

import pytest
import requests
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from peaso.ai import auth, providers, pipeline
from peaso.ai.crypto import AICipher
from peaso.auth import CredentialCipher, Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts


def token():
    body = {'exp': time.time() + 3600, 'https://api.openai.com/auth': {'chatgpt_account_id': 'synthetic'}}
    return 'e30.' + base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip('=') + '.synthetic'


@pytest.fixture
def state(tmp_path, monkeypatch, request):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity',
                        auth_mode=getattr(request, 'param', 'local'))
    store, cipher = SQLiteStore(settings.state_dir), AICipher(settings.identity_dir)
    monkeypatch.setattr('peaso.ai.isolation.available', lambda: True)
    monkeypatch.setattr(auth, 'default_token', token)
    app = FastAPI()
    def identity(authorization: str | None = Header(default=None)):
        return Identity('bob' if authorization == 'Bearer bob' else 'alice',
                        auth_kind='api_key' if authorization == 'Bearer key' else 'user')
    auth.mount_auth_routes(app, store, settings.identity_dir, identity, auth_mode=settings.auth_mode)
    with TestClient(app) as client:
        yield settings, store, cipher, client


class Reply:
    def __init__(self, status, body):
        self.status_code, self.body = status, body
        self.content = json.dumps(body).encode()
    def json(self): return self.body
    def __enter__(self): return self
    def __exit__(self, *args): pass


def test_requests_device_flow_shows_code_polls_and_encrypts_tokens(state, monkeypatch, caplog):
    _, store, cipher, client = state
    calls, phase = [], [0]
    def post(url, **kwargs):
        calls.append((url, kwargs))
        assert kwargs['timeout'] == 20 and kwargs['allow_redirects'] is False
        if url.endswith('/usercode'):
            assert kwargs['json'] == {'client_id': auth.CLIENT}
            return Reply(200, {'device_auth_id': 'PRIVATE-device', 'usercode': 'ABCD-1234', 'interval': 'bad'})
        if url.endswith('deviceauth/token'):
            assert kwargs['json'] == {'device_auth_id': 'PRIVATE-device', 'user_code': 'ABCD-1234'}
            phase[0] += 1
            return Reply(400, {'error': 'authorization_pending'}) if phase[0] == 1 else Reply(200, {'authorization_code': 'PRIVATE-code', 'code_verifier': 'PRIVATE-verifier'})
        assert kwargs['data']['redirect_uri'] == auth.ISSUER+'/deviceauth/callback'
        return Reply(200, {'access_token': token(), 'refresh_token': 'PRIVATE-refresh'})
    monkeypatch.setattr(auth.requests, 'post', post)
    started = client.post('/api/ai/codex/login', json={})
    assert started.status_code == 200
    assert started.json()['verification_url'] == 'https://auth.openai.com/codex/device'
    assert started.json()['user_code'] == 'ABCD-1234' and started.json()['interval'] == 5
    assert started.headers['cache-control'] == 'private, no-store'
    assert 'PRIVATE' not in started.text
    assert client.post('/api/ai/codex/login', json={}).json() == started.json()
    assert len(calls) == 1
    assert client.post('/api/ai/codex/login/poll').json() == {'status': 'pending'}
    raw = store.ai_state('alice', 'pending')
    assert 'PRIVATE' not in raw
    pending = cipher.decrypt(raw)
    pending['next_poll'] = 0
    assert store.set_ai_state('alice', 'pending', cipher.encrypt(pending), raw)
    connected = client.post('/api/ai/codex/login/poll')
    assert connected.json() == {'status': 'connected'} and 'PRIVATE' not in connected.text
    assert 'PRIVATE' not in caplog.text
    assert cipher.decrypt(store.ai_state('alice', 'auth'))['refresh_token'] == 'PRIVATE-refresh'
    assert store.ai_state('alice', 'pending') is None and store.ai_state('bob', 'auth') is None


@pytest.mark.parametrize('status,body', [(530, {'error': 'PRIVATE-error'}), (200, {}), (200, {'device_auth_id': 'PRIVATE-only'})])
def test_start_failures_do_not_misdiagnose_settings_or_save_bad_codes(state, monkeypatch, status, body):
    _, store, _, client = state
    monkeypatch.setattr(auth.requests, 'post', lambda *a, **k: Reply(status, body))
    result = client.post('/api/ai/codex/login')
    assert result.status_code in (502, 503)
    assert 'enable device code login in ChatGPT settings' not in result.text
    assert 'PRIVATE' not in result.text and store.ai_state('alice', 'pending') is None


def test_network_errors_are_controlled_and_oauth_errors_are_allowlisted(monkeypatch):
    def fail(*args, **kw): raise requests.Timeout('PRIVATE-credential')
    monkeypatch.setattr(auth.requests, 'post', fail)
    assert auth.post('/oauth/token', {}, form=True) == (503, {})
    monkeypatch.setattr(auth.requests, 'post', lambda *a, **k: Reply(400, {'error': 'slow_down', 'description': 'PRIVATE'}))
    assert auth.post('/api/accounts/deviceauth/token', {}) == (400, {'error': 'slow_down'})


@pytest.mark.parametrize('status,body', [(400, {'error': 'expired_token'}), (400, {'error': 'access_denied'}), (200, {})])
def test_terminal_or_malformed_poll_can_restart_without_replacing_auth(state, monkeypatch, status, body):
    _, store, cipher, client = state
    saved = cipher.encrypt({'access_token': token(), 'refresh_token': 'PRIVATE-retained'})
    store.set_ai_state('alice', 'auth', saved)
    store.set_ai_state('alice', 'pending', cipher.encrypt({'device_auth_id': 'PRIVATE-device', 'user_code': 'TEST-CODE', 'interval': 5, 'next_poll': 0, 'expires_at': time.time() + 900}))
    monkeypatch.setattr(auth.requests, 'post', lambda *a, **k: Reply(status, body))
    result = client.post('/api/ai/codex/login/poll')
    assert result.status_code in (410, 502) and 'PRIVATE' not in result.text
    assert store.ai_state('alice', 'pending') is None
    assert store.ai_state('alice', 'auth') == saved


@pytest.mark.parametrize('state', ['local', 'cognito'], indirect=True)
def test_account_disable_is_private_persistent_and_skips_credentials(state, monkeypatch):
    settings, store, cipher, client = state
    saved = cipher.encrypt({'provider': 'openai', 'model': 'gpt-5.3-codex', 'thinking': 'high', 'credential': 'PRIVATE-key', 'validated': True})
    assert store.set_ai_state('alice', providers.STATE_KEY, saved)
    monkeypatch.setattr(providers, 'validate_access', lambda *a: pytest.fail('No provider validation while disabled'))
    disabled = client.patch('/api/ai/preferences', json={'disabled': True})
    assert disabled.status_code == 200 and disabled.json() == {'disabled': True}
    configuration = client.get('/api/ai/configuration').json()
    assert configuration['disabled'] is True and not configuration['available']
    assert configuration['hosted'] is (settings.auth_mode != 'local')
    assert 'PRIVATE' not in disabled.text
    assert providers.review_disabled(SQLiteStore(settings.state_dir), 'alice')
    assert not providers.review_disabled(store, 'bob')
    assert store.ai_state('alice', providers.STATE_KEY) == saved
    assert client.get('/api/ai/codex').json()['disabled'] is True
    assert client.patch('/api/ai/preferences', json={'disabled': False}, headers={'Authorization': 'Bearer key'}).status_code == 403
    assert client.patch('/api/ai/preferences', json={'disabled': 'false'}).status_code == 422
    with pytest.raises(providers.ReviewDisabled):
        providers.resolve_access(store, cipher, 'alice', auth_mode=settings.auth_mode)
    auth.require_local_codex(settings, store, 'alice')
    assert store.ai_state('alice', providers.ERROR_KEY) is None
    assert client.patch('/api/ai/preferences', json={'disabled': False}).json()['disabled'] is False
    assert store.ai_state('alice', providers.STATE_KEY) == saved


def test_hosted_policy_persists_in_dynamo_without_platform_credentials(tmp_path, monkeypatch):
    import boto3
    from botocore.stub import Stubber
    from peaso.storage.dynamodb import DynamoStore, attrs

    # Synthetic table and credentials; Stubber rejects every unplanned request.
    client = boto3.client('dynamodb', region_name='us-east-1',
                          aws_access_key_id='testing', aws_secret_access_key='testing')
    store = DynamoStore('ai-policy-test', client)
    key = attrs(store.key('alice', 'ai', providers.REVIEW_POLICY_KEY))
    enabled, disabled = '{"disabled":false}', '{"disabled":true}'
    def read(stub, value):
        stub.add_response('get_item', {} if value is None else {'Item': dict(key, value={'S': value})},
                          {'TableName': store.table, 'Key': key, 'ConsistentRead': True})
    monkeypatch.setenv('PEASO_STORAGE', 'dynamodb')
    monkeypatch.setattr('peaso.ai.crypto.AICipher', lambda *a: pytest.fail('No encryption key needed for the preference'))
    monkeypatch.setattr(auth, 'default_token', lambda: pytest.fail('No hosted credential access'))
    app = FastAPI()
    auth.mount_auth_routes(app, store, tmp_path/'identity', lambda: Identity('alice'), auth_mode='cognito')
    with Stubber(client) as stub, TestClient(app) as web:
        read(stub, None)
        stub.add_response('put_item', {}, {'TableName': store.table,
            'ConditionExpression': 'attribute_not_exists(PK)', 'Item': dict(key, value={'S': disabled})})
        assert web.patch('/api/ai/preferences', json={'disabled': True}).json() == {'disabled': True}
        # A newly constructed repository sees the committed preference.
        read(stub, disabled)
        assert providers.review_disabled(DynamoStore(store.table, client), 'alice')
        read(stub, disabled)
        with pytest.raises(providers.ReviewDisabled):
            providers.resolve_access(store, None, 'alice', auth_mode='cognito')
        read(stub, disabled)
        stub.add_response('put_item', {}, {'TableName': store.table, 'ConditionExpression': '#v=:old',
            'ExpressionAttributeNames': {'#v': 'value'}, 'ExpressionAttributeValues': {':old': {'S': disabled}},
            'Item': dict(key, value={'S': enabled})})
        assert web.patch('/api/ai/preferences', json={'disabled': False}).json() == {'disabled': False}
        read(stub, enabled)
        assert not providers.review_disabled(DynamoStore(store.table, client), 'alice')
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('state', ['local', 'cognito'], indirect=True)
def test_disable_after_preflight_stops_next_agent_without_credential_warning(state, monkeypatch):
    settings, store, cipher, _ = state
    access = providers.ModelAccess('openai', 'gpt-5.3-codex', 'high', 'PRIVATE')
    guard = providers.LaunchGuard(store, cipher, 'alice', settings.auth_mode, None, access)
    store.set_ai_state('alice', providers.REVIEW_POLICY_KEY, json.dumps({'disabled': True}))
    monkeypatch.setattr(providers, 'validate_access', lambda *a: pytest.fail('No inference probe'))
    with pytest.raises(providers.ReviewDisabled):
        providers.validate_before_launch(providers.guarded(access, guard))
    assert store.ai_state('alice', providers.ERROR_KEY) is None


@pytest.mark.parametrize('state', ['local', 'cognito'], indirect=True)
def test_review_pipeline_skips_all_stages_when_account_disabled(state, monkeypatch):
    settings, store, cipher, _ = state
    store.set_ai_state('alice', providers.REVIEW_POLICY_KEY, json.dumps({'disabled': True}))
    monkeypatch.setenv('PEASO_AUTH_MODE', settings.auth_mode)
    monkeypatch.setattr(pipeline, 'invoke', lambda *a, **k: pytest.fail('No agent launch'))
    monkeypatch.setattr(pipeline, 'personal_token', lambda *a, **k: pytest.fail('No credential read'))
    monkeypatch.setattr(pipeline, 'AICipher', lambda *a: pytest.fail('No AI envelope key needed to opt out'))
    result = pipeline.review_scan({}, {}, {'ai_enabled': True}, tenant='alice',
        artifacts=FileArtifacts(settings.state_dir/'artifacts'),
        context={'state_dir': str(settings.state_dir), 'identity_dir': str(settings.identity_dir)})
    assert result['status'] == 'skipped' and result['reason'] == 'disabled_for_account'


@pytest.mark.parametrize('state', ['local', 'cognito'], indirect=True)
def test_manual_scan_request_is_overridden_when_disabled(state, monkeypatch):
    settings, store, cipher, _ = state
    store.set_ai_state('alice', providers.REVIEW_POLICY_KEY, json.dumps({'disabled': True}))
    encrypted = CredentialCipher(settings.identity_dir).encrypt(
        {'auth': {'method': 'container'}, 'options': {}})
    connector = store.add_connector('alice', {'provider': 'aws', 'name': 'fixture'}, encrypted)
    class IdentityProvider:
        def authenticate(self, value): return Identity('alice')
    monkeypatch.setattr(providers, 'validate_access', lambda *a: pytest.fail('No provider probe'))
    app = create_app(settings, store=store, artifacts=FileArtifacts(settings.state_dir/'artifacts'), authenticator=IdentityProvider())
    with TestClient(app, base_url='http://127.0.0.1:8000') as client:
        response = client.post('/api/scans', json={'connector_id': connector['id'], 'ai_enabled': True})
    assert response.status_code == 201, response.text
    job = store.job('alice', response.json()['id'])
    assert json.loads(job['data'])['ai_enabled'] is False


def test_queued_collector_rechecks_current_policy_before_child_start(state, monkeypatch):
    from peaso.worker import Worker
    settings, store, cipher, _ = state
    credential_cipher = CredentialCipher(settings.identity_dir)
    connector = store.add_connector('alice', {'provider': 'aws', 'name': 'fixture'}, credential_cipher.encrypt({'auth': {}, 'options': {}}))
    store.enqueue('alice', {'connector_id': connector['id'], 'ai_enabled': True, 'ai_user_id': 'alice'})
    store.set_ai_state('alice', providers.REVIEW_POLICY_KEY, json.dumps({'disabled': True}))
    captured = {}
    class Process:
        def __init__(self, target, args, **kw): captured.update(args[1])
        def start(self): raise RuntimeError('Stop before child execution')
        def is_alive(self): return False
        def join(self, **kw): pass
    pipe = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr('peaso.worker.multiprocessing.get_context', lambda *a: SimpleNamespace(Pipe=lambda **k: (pipe, pipe), Process=Process))
    assert Worker('collector', settings, store=store, artifacts=FileArtifacts(settings.state_dir/'artifacts')).run_once()
    assert captured['ai_enabled'] is False


@pytest.mark.parametrize('state', ['local', 'cognito'], indirect=True)
def test_due_schedule_runs_without_ai_preflight_and_preserves_scan_selection(state, monkeypatch):
    from peaso.worker import Worker
    settings, store, _, _ = state
    encrypted = CredentialCipher(settings.identity_dir).encrypt(
        {'auth': {'method': 'container'}, 'options': {}})
    connector = store.add_connector('alice', {'provider': 'aws', 'name': 'schedule'}, encrypted)
    data = {'connector_id': connector['id'], 'ai_enabled': True, 'ai_user_id': 'alice',
            'timezone': 'UTC', 'rules': [{'frequency': 'daily', 'time': '09:00'}]}
    store.add_schedule('alice', data, time.time() - 1)
    store.set_ai_state('alice', providers.REVIEW_POLICY_KEY, json.dumps({'disabled': True}))
    monkeypatch.setattr(providers, 'validate_access', lambda *a: pytest.fail('Disabled schedule must not probe credentials'))
    monkeypatch.setattr('peaso.worker.WorkflowDispatcher.dispatch', lambda *a: False)
    worker = Worker('collector', settings, store=store, artifacts=FileArtifacts(settings.state_dir/'artifacts'),
                    authenticator=SimpleNamespace(is_paid=lambda tenant: True))
    assert len(worker.schedule_tick()) == 1
    assert store.schedules('alice')[0]['ai_enabled'] is True


def test_unreadable_policy_fails_closed_without_an_ai_key(state, monkeypatch):
    _, store, _, _ = state
    store.set_ai_state('alice', providers.REVIEW_POLICY_KEY, 'invalid-json')
    assert providers.review_disabled(store, 'alice')
    assert not providers.review_disabled(store, 'bob')
