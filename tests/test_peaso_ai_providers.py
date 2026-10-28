"""Provider choice is tenant-owned, validated and shared by every scan agent."""
import base64
import json
import os
from pathlib import Path
import time

from fastapi import FastAPI, Header
from fastapi.testclient import TestClient
import pytest

pytest.importorskip('chack_agent')

from peaso.ai import auth, providers
from peaso.ai.crypto import AICipher
from peaso.auth import Identity
from peaso.storage import SQLiteStore

CASES = [
    ('codex', 'gpt-5.3-codex', 'codex'),
    ('openai', 'gpt-5.3-codex', 'codex'),
    ('anthropic', 'claude-sonnet-4-6', 'claude'),
    ('anthropic_token', 'claude-sonnet-4-6', 'claude'),
    ('openrouter', 'openai/gpt-5.3-codex', 'openrouter'),
]


def codex_token():
    claims = {'exp': time.time() + 3600, 'https://api.openai.com/auth': {'chatgpt_account_id': 'test-account'}}
    return 'e30.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.PRIVATE'


@pytest.fixture
def api(tmp_path, monkeypatch):
    store, identity = SQLiteStore(tmp_path/'state'), tmp_path/'identity'
    cipher = AICipher(identity)
    monkeypatch.setattr('peaso.ai.isolation.available', lambda: True)
    monkeypatch.setattr(auth, 'default_token', codex_token)
    calls = []
    def provider_json(method, url, headers, body=None):
        calls.append((method, url, headers, body))
        if '/codex/models' in url:
            return {'models': [{'slug': 'gpt-5.3-codex', 'supported_reasoning_levels': [{'effort': 'high'}]}]}
        if 'api.anthropic.com/' in url and method == 'GET':
            return {'id': 'claude-sonnet-4-6', 'capabilities': {'effort': {'supported': True, 'high': {'supported': True}}}}
        return {'id': 'validated-response', 'type': 'message', 'status': 'completed'}
    monkeypatch.setattr(providers, 'provider_json', provider_json)
    monkeypatch.setattr(providers, 'codex_probe', lambda *args: {'id': 'probe'})
    def make(mode='local'):
        app = FastAPI()
        def identity(authorization: str | None = Header(default=None)):
            return Identity('bob' if authorization == 'Bearer bob' else 'alice')
        auth.mount_auth_routes(app, store, tmp_path/'identity', identity, auth_mode=mode)
        return TestClient(app)
    return make, store, cipher, calls


@pytest.mark.parametrize('provider,model,backend', CASES)
def test_save_validates_access_encrypts_secret_and_isolates_users(api, provider, model, backend):
    make, store, cipher, calls = api
    if provider == 'codex':
        store.set_ai_state('alice', 'auth', cipher.encrypt({'access_token': codex_token()}), None)
    with make() as client:
        body = {'provider': provider, 'model': model, 'thinking': 'high'}
        if provider != 'codex':
            body['credential'] = 'PRIVATE-provider-key'
        saved = client.post('/api/ai/configuration', json=body)
        assert saved.status_code == 200, saved.text
        assert saved.json()['source'] == 'personal' and saved.json()['available']
        assert saved.json()['selection']['model'] == model
        assert 'PRIVATE' not in saved.text
        assert client.get('/api/ai/codex').json()['available'] is True
        assert client.get('/api/ai/configuration', headers={'Authorization': 'Bearer bob'}).json()['selection'] is None
        raw = store.ai_state('alice', providers.STATE_KEY)
        assert 'PRIVATE' not in raw
        stored = cipher.decrypt(raw)
        assert stored['validated'] is True
        assert stored.get('credential') == (None if provider == 'codex' else 'PRIVATE-provider-key')
        if provider != 'codex':
            # Updating only model/effort retains this user's encrypted credential.
            assert client.post('/api/ai/configuration', json={k: v for k, v in body.items() if k != 'credential'}).status_code == 200
        assert client.delete('/api/ai/configuration').status_code == 204
        assert store.ai_state('alice', providers.STATE_KEY) is None
    assert calls and all('PRIVATE' not in (body or {}).get('input', '') for _, _, _, body in calls)
    if provider in {'openai', 'openrouter'}:
        assert calls[0][1].endswith('/responses')
        assert calls[0][3]['reasoning']['effort'] == 'high'


@pytest.mark.parametrize('patch', [
    {'provider': 'unknown'}, {'model': ''}, {'model': 'model\nPRIVATE'},
    {'thinking': 'ultra'}, {'thinking': 'minimal'}, {'credential': 'PRIVATE\ninvalid'},
])
def test_invalid_selection_is_rejected_before_provider_call_and_not_stored(api, patch):
    make, store, _, calls = api
    with make() as client:
        result = client.post('/api/ai/configuration', json={
            'provider': 'openai', 'model': 'gpt-5.3-codex', 'thinking': 'high',
            'credential': 'PRIVATE-provider-key', **patch})
        assert result.status_code == 422
        assert 'PRIVATE' not in result.text
        assert store.ai_state('alice', providers.STATE_KEY) is None
        assert not calls


def test_validation_errors_never_return_transport_exception_text(api, monkeypatch):
    make, store, _, _ = api
    def fail(*args): raise ValueError('PRIVATE-provider-error-with-token')
    monkeypatch.setattr(providers, 'provider_json', fail)
    with make('cognito') as client:
        result = client.post('/api/ai/configuration', json={
            'provider': 'openai', 'model': 'gpt-5.3-codex', 'thinking': 'high', 'credential': 'PRIVATE-key'})
        assert result.status_code == 422 and 'PRIVATE' not in result.text
        fallback = client.get('/api/ai/configuration').json()
        assert not fallback['available'] and fallback['source'] is None
        assert fallback['configuration_error']
        assert fallback['selection'] is None
        assert 'gpt-' not in json.dumps(fallback) and 'thinking' not in json.dumps(fallback)


@pytest.mark.parametrize('mode', ['local', 'cognito'])
def test_revoked_configuration_is_not_blended_with_platform_defaults(api, monkeypatch, mode):
    make, store, cipher, _ = api
    selected = {'provider': 'openai', 'model': 'gpt-5.3-codex', 'thinking': 'high',
                'credential': 'PRIVATE-user-key', 'validated': True}
    store.set_ai_state('alice', providers.STATE_KEY, cipher.encrypt(selected), None)
    def fail(*args): raise providers.ConfigurationError('AI credential is unavailable.')
    monkeypatch.setattr(providers, 'validate_access', fail)
    with pytest.raises(providers.ConfigurationError):
        providers.resolve_access(store, cipher, 'alice', auth_mode=mode)
    assert providers.configuration_error(store, cipher, 'alice')
    assert cipher.decrypt(store.ai_state('alice', providers.STATE_KEY)) == selected
    with make(mode) as client:
        status = client.get('/api/ai/configuration').json()
        assert status['available'] is False
        assert 'PRIVATE' not in json.dumps(status)


def test_disconnected_codex_never_uses_user_model_with_platform_token(api):
    _, store, cipher, _ = api
    store.set_ai_state('alice', 'auth', cipher.encrypt({'disconnected': True}), None)
    store.set_ai_state('alice', providers.STATE_KEY, cipher.encrypt({
        'provider': 'codex', 'model': 'user-only-model', 'thinking': 'high', 'validated': True}), None)
    with pytest.raises(providers.ConfigurationError):
        providers.resolve_access(store, cipher, 'alice', auth_mode='cognito')


def test_new_local_codex_signin_requires_explicit_model_and_thinking(api):
    make, store, cipher, _ = api
    store.set_ai_state('alice', 'auth', cipher.encrypt({
        'access_token': codex_token(), 'requires_selection': True}), None)
    with make() as client:
        assert client.get('/api/ai/configuration').json()['available'] is False
        assert client.get('/api/ai/configuration').json()['codex_connected'] is True
        result = client.post('/api/ai/configuration', json={
            'provider': 'codex', 'model': 'gpt-5.3-codex', 'thinking': 'high'})
        assert result.status_code == 200 and result.json()['available'] is True
        assert client.delete('/api/ai/configuration').status_code == 204
        assert client.get('/api/ai/configuration').json()['available'] is False


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('provider,model,backend', CASES)
def test_failed_inference_does_not_save_settings_or_switch_to_platform(api, monkeypatch, mode, provider, model, backend):
    make, store, cipher, _ = api
    old = {'provider': 'openai', 'model': 'gpt-5.3-codex', 'thinking': 'high', 'credential': 'PRIVATE-existing', 'validated': True}
    previous = cipher.encrypt(old)
    store.set_ai_state('alice', providers.STATE_KEY, previous, None)
    if provider == 'codex':
        store.set_ai_state('alice', 'auth', cipher.encrypt({'access_token': codex_token()}), None)
    original = providers.provider_json
    def probe(method, *args, **kwargs):
        if method == 'POST':
            raise providers.ConfigurationError('Inference access was denied. Validate your credential.')
        return original(method, *args, **kwargs)
    def codex_failure(*args):
        raise providers.ConfigurationError('Codex inference access was denied.')
    monkeypatch.setattr(providers, 'provider_json', probe)
    monkeypatch.setattr(providers, 'codex_probe', codex_failure)
    monkeypatch.setattr(auth, 'default_token', lambda: pytest.fail('Never switch credentials after failed custom validation'))
    with make(mode) as client:
        response = client.post('/api/ai/configuration', json={
            'provider': provider, 'model': model, 'thinking': 'high', 'credential': 'PRIVATE-new'})
        assert response.status_code == 422 and 'PRIVATE' not in response.text
        assert store.ai_state('alice', providers.STATE_KEY) == previous
        status = client.get('/api/ai/configuration').json()
        assert not status['available'] and status['source'] is None and status['configuration_error']


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('provider,model,backend', CASES)
def test_expiration_blocks_local_hosted_workflow_and_subsequent_launches(api, monkeypatch, tmp_path, mode, provider, model, backend):
    from peaso.ai import pipeline, fargate
    from peaso.storage.runtime import WorkflowDispatcher
    from peaso.server.config import Settings
    make, store, cipher, _ = api
    profile = {'provider': provider, 'model': model, 'thinking': 'high', 'credential': 'PRIVATE-user', 'validated': True}
    if provider == 'codex':
        store.set_ai_state('alice', 'auth', cipher.encrypt({'access_token': codex_token()}), None)
    store.set_ai_state('alice', providers.STATE_KEY, cipher.encrypt(profile), None)
    access, _ = providers.resolve_access(store, cipher, 'alice', auth_mode=mode)
    def revoked(*args): raise providers.ConfigurationError('Credential expired or inference access was revoked.')
    monkeypatch.setattr(providers, 'validate_access', revoked)
    monkeypatch.setattr(auth, 'default_token', lambda: pytest.fail('No automatic platform fallback'))
    monkeypatch.setattr('peaso.ai.isolation.remote', lambda: False)
    monkeypatch.setattr('peaso.ai.isolation.launcher', lambda: '/unused')
    monkeypatch.setattr(pipeline.subprocess, 'Popen', lambda *a, **k: pytest.fail('Do not launch a process'))
    with pytest.raises(providers.ConfigurationError):
        pipeline.invoke('network', {'report': {'provider': 'aws', 'findings': [], 'graphs': {}}, 'inventory': []}, [], access, [], [], 30)
    monkeypatch.setattr(fargate, 'configuration', lambda: pytest.fail('Do not touch hosted infrastructure'))
    with pytest.raises(providers.ConfigurationError):
        fargate.invoke('network', tmp_path, access, 30)
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity', auth_mode=mode)
    monkeypatch.setattr('peaso.server.config.Settings', lambda: settings)
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (store, None))
    class Client:
        def start_execution(self, **kwargs): pytest.fail('Do not dispatch a workflow/build')
    assert WorkflowDispatcher(arn='workflow', client=Client()).dispatch('alice', {'id': 'queued', 'ai_enabled': True}) is False
    with make(mode) as client:
        assert client.get('/api/ai/configuration').json()['configuration_error']
        assert client.get('/api/ai/codex').json()['configuration_error']
    # Recovery requires an explicit validated action, not a later stage retry.
    monkeypatch.setattr(providers, 'validate_access', lambda value: value)
    with pytest.raises(providers.ConfigurationError):
        providers.validate_before_launch(access)
    with make(mode) as client:
        assert client.post('/api/ai/configuration/validate').status_code == 200
        assert client.get('/api/ai/configuration').json()['configuration_error'] is None


def test_runner_refuses_to_construct_chack_after_preflight_failure(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace
    from peaso.ai import runner
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, 'argv', ['runner', 'network'])
    (tmp_path/'codex-auth.json').write_text('{"access_token":"PRIVATE"}')
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    monkeypatch.setitem(sys.modules, 'chack_agent', SimpleNamespace(
        load_config=lambda _: SimpleNamespace(agent=SimpleNamespace(max_runtime_minutes=5)),
        Chack=lambda *args: pytest.fail('No Chack instance before successful preflight')))
    monkeypatch.delenv('PEASO_AI_MODEL_RELAY', raising=False)
    def fail(*args): raise providers.ConfigurationError('Inference access is unavailable.')
    monkeypatch.setattr(runner, 'validate_runtime', fail)
    assert runner.entrypoint() == 78
    assert not (tmp_path/'result.json').exists()


def test_container_startup_validation_failure_records_warning_and_stops_the_pool(api, monkeypatch):
    from peaso.ai import pipeline
    make, store, cipher, _ = api
    store.set_ai_state('alice', providers.STATE_KEY, cipher.encrypt({
        'provider': 'openai', 'model': 'gpt-5.3-codex', 'thinking': 'high',
        'credential': 'PRIVATE-user-key', 'validated': True}), None)
    access, _ = providers.resolve_access(store, cipher, 'alice')
    monkeypatch.setattr('peaso.ai.isolation.remote', lambda: False)
    monkeypatch.setattr('peaso.ai.isolation.launcher', lambda: '/unused')
    monkeypatch.setattr('peaso.ai.isolation.wrap_command', lambda command, _: command)
    monkeypatch.setattr('peaso.ai.network.build', lambda *args: None)
    monkeypatch.setattr(pipeline, 'kill_tree', lambda _: None)
    launches = []
    class Process:
        returncode = 78
        def __init__(self, *args, **kwargs): launches.append(True)
        def wait(self, **kwargs): pass
    monkeypatch.setattr(pipeline.subprocess, 'Popen', Process)
    with pytest.raises(providers.ConfigurationError, match='before starting the agent'):
        pipeline.invoke('network', {'report': {'provider': 'aws', 'findings': [], 'graphs': {}}, 'inventory': []}, [], access, [], [], 30)
    with pytest.raises(providers.ConfigurationError):
        pipeline.invoke('network', {'report': {'provider': 'aws', 'findings': [], 'graphs': {}}, 'inventory': []}, [], access, [], [], 30)
    assert len(launches) == 1
    with make() as client:
        status = client.get('/api/ai/configuration').json()
        assert not status['available'] and status['configuration_error']
        assert 'PRIVATE' not in json.dumps(status)


def test_queued_access_rejects_a_changed_saved_configuration(api):
    _, store, cipher, _ = api
    original = {'provider': 'openai', 'model': 'gpt-5.3-codex', 'thinking': 'high',
                'credential': 'PRIVATE-old', 'validated': True}
    raw = cipher.encrypt(original)
    store.set_ai_state('alice', providers.STATE_KEY, raw, None)
    access, _ = providers.resolve_access(store, cipher, 'alice')
    replacement = cipher.encrypt({**original, 'credential': 'PRIVATE-replacement'})
    assert store.set_ai_state('alice', providers.STATE_KEY, replacement, raw)
    with pytest.raises(providers.ConfigurationError, match='settings changed'):
        providers.validate_before_launch(access)
    assert store.ai_state('alice', providers.STATE_KEY) == replacement
    assert providers.configuration_error(store, cipher, 'alice')


def test_switch_to_hacktricks_requires_live_validation_and_preserves_personal_settings_on_failure(api, monkeypatch):
    make, store, cipher, _ = api
    original = cipher.encrypt({'provider': 'openai', 'model': 'gpt-5.3-codex', 'thinking': 'high',
                               'credential': 'PRIVATE-existing', 'validated': True})
    store.set_ai_state('alice', providers.STATE_KEY, original, None)
    def fail(*args): raise providers.ConfigurationError('Default AI inference is unavailable.')
    monkeypatch.setattr(providers, 'validate_access', fail)
    with make('cognito') as client:
        assert client.delete('/api/ai/configuration').status_code == 422
        assert store.ai_state('alice', providers.STATE_KEY) == original
        assert client.get('/api/ai/configuration').json()['source'] is None
    monkeypatch.setattr(providers, 'validate_access', lambda value: value)
    with make('cognito') as client:
        assert client.delete('/api/ai/configuration').status_code == 204
        status = client.get('/api/ai/configuration').json()
        assert status['source'] == 'hacktricks' and status['configuration_error'] is None
        assert 'gpt-' not in json.dumps(status) and 'PRIVATE' not in json.dumps(status)


@pytest.mark.parametrize('terminal,accepted', [
    ({'type': 'response.completed', 'response': {'id': 'probe', 'status': 'completed'}}, True),
    ({'type': 'response.incomplete', 'response': {'id': 'probe', 'status': 'incomplete'}}, True),
    ({'type': 'response.failed', 'response': {'id': 'probe', 'error': {'message': 'PRIVATE'}}}, False),
    ({'type': 'error', 'message': 'PRIVATE'}, False),
    ({'type': 'response.created', 'response': {'id': 'probe'}}, False),
])
def test_codex_validation_requires_a_successful_terminal_inference_event(monkeypatch, terminal, accepted):
    captured = {}
    class Response:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def iter_lines(self, **kwargs):
            yield b'data: ' + json.dumps(terminal).encode()
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, **kwargs):
            captured.update(kwargs)
            return Response()
    monkeypatch.setattr('requests.Session', Session)
    if accepted:
        assert providers.codex_probe({'Authorization': 'Bearer PRIVATE'}, {})['id'] == 'probe'
    else:
        with pytest.raises(providers.ConfigurationError) as failure:
            providers.codex_probe({'Authorization': 'Bearer PRIVATE'}, {})
        assert 'PRIVATE' not in str(failure.value)
    assert captured['stream'] is True and captured['allow_redirects'] is False


@pytest.mark.parametrize('provider,model,backend', CASES)
def test_scan_resolves_once_and_passes_same_selection_to_network_and_priorities(api, monkeypatch, tmp_path, provider, model, backend):
    from types import SimpleNamespace
    from peaso.ai import pipeline
    _, store, cipher, _ = api
    secret = codex_token() if provider == 'codex' else 'PRIVATE-selected-key'
    if provider == 'codex':
        store.set_ai_state('alice', 'auth', cipher.encrypt({'access_token': secret}), None)
    profile = {'provider': provider, 'model': model, 'thinking': 'high', 'validated': True}
    if provider != 'codex': profile['credential'] = secret
    store.set_ai_state('alice', providers.STATE_KEY, cipher.encrypt(profile), None)
    monkeypatch.setattr(pipeline, 'Settings', lambda: SimpleNamespace(identity_dir=tmp_path, auth_mode='local'))
    monkeypatch.setattr(pipeline, 'AICipher', lambda _: cipher)
    monkeypatch.setattr('peaso.storage.runtime.stores', lambda _: (store, None))
    monkeypatch.setattr('peaso.snapshot.resources', lambda _: [])
    monkeypatch.setattr('peaso.ai.network.prepare', lambda *a: {'inventory': []})
    monkeypatch.setattr('peaso.least_privilege.project', lambda *a, **k: {})
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 1)
    captured = []
    def network_review(report, entries, access, network, end):
        captured.append(access)
        return {'status': 'completed', 'explanation': '', 'findings': []}, False
    def priorities(stage, platform, entries, access, *args):
        captured.append(access)
        return {'actions': [], 'limitations': [secret]}
    monkeypatch.setattr(pipeline, 'review_network', network_review)
    monkeypatch.setattr(pipeline, 'invoke_before_deadline', priorities)
    result = pipeline.review_scan({'provider': 'aws', 'findings': [], 'graphs': {}}, {}, {}, tenant='alice', artifacts=None)
    assert result['status'] == 'completed' and result['auth_source'] == 'personal'
    assert len(captured) == 2 and captured[0] is captured[1]
    assert captured[0].public() == {'provider': provider, 'model': model, 'thinking': 'high'}
    assert captured[0].credential == secret
    assert secret not in json.dumps(result)


@pytest.mark.parametrize('stage', ['network', 'priorities'])
@pytest.mark.parametrize('provider,model,backend', CASES)
def test_every_stage_and_child_role_uses_the_exact_selection(monkeypatch, stage, provider, model, backend):
    from chack_agent import load_config
    from chack_agent.config import ROLE_AGENT_FIELDS
    from peaso.ai.prompting import agent_config_path
    for key in ('CODEX_ACCESS_TOKEN', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CLAUDE_API_KEY',
                'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN', 'CLAUDE_ACCESS_TOKEN',
                'OPENROUTER_API_KEY', 'OPENROUTER_BASE_URL', 'ANTHROPIC_BASE_URL'):
        monkeypatch.setenv(key, 'unselected-credential')
    config = load_config(str(agent_config_path(stage)))
    config.env = {}
    access = providers.ModelAccess(provider, model, 'high', 'PRIVATE-selected-key')
    providers.configure_agent(config, providers.auth_document(access), relay='http://127.0.0.1:8765')
    assert config.model.provider == backend and config.model.primary == model
    assert config.agent.thinking_effort == 'high'
    for role in ROLE_AGENT_FIELDS:
        if hasattr(config.model, role): assert getattr(config.model, role) == model
        assert getattr(config.model, role + '_thinking_effort') == 'high'
    assert 'PRIVATE-selected-key' not in repr(access)
    assert 'unselected-credential' not in json.dumps(vars(config.credentials))
    assert 'unselected-credential' not in [os.environ.get(key) for key in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN')]
    if provider == 'anthropic_token': assert os.environ['CLAUDE_CODE_OAUTH_TOKEN'] == access.credential
    if provider == 'anthropic': assert os.environ['ANTHROPIC_API_KEY'] == access.credential
    if provider == 'openrouter': assert config.credentials.openrouter_base_url == 'http://127.0.0.1:8765/openrouter/api/v1'


def test_validation_http_never_follows_redirects_or_exposes_errors(monkeypatch):
    captured = {}
    class Response:
        status_code = 401
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def request(self, *args, **kwargs):
            captured.update(kwargs)
            return Response()
    monkeypatch.setattr('requests.Session', Session)
    with pytest.raises(providers.ConfigurationError) as error:
        providers.provider_json('GET', 'https://api.openai.com/v1/models', {'Authorization': 'Bearer PRIVATE'})
    assert 'PRIVATE' not in str(error.value)
    assert captured['allow_redirects'] is False and captured['stream'] is True


def test_sdk_structured_output_uses_original_object_and_never_evaluates_model_text():
    from types import SimpleNamespace
    from peaso.ai.runner import output_text
    native = {'items': [], 'confirmed': True, 'unknown': None}
    assert json.loads(output_text(SimpleNamespace(output=str(native), run1_output=native))) == native
    assert output_text(SimpleNamespace(output=str(native))) == str(native)
    changed = str(native) + '\nBudget warning'
    assert output_text(SimpleNamespace(output=changed, run1_output=native)) == changed


@pytest.mark.parametrize('provider,model,backend', CASES)
def test_hosted_relay_forwards_only_selected_provider_and_hides_real_credentials(monkeypatch, provider, model, backend):
    import http.client
    from http.server import ThreadingHTTPServer
    import threading
    from peaso.ai import model_relay
    captured, upstream, ready = [], [], threading.Event()
    def factory(address, handler):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        captured.append(server)
        ready.set()
        return server
    class Response:
        status_code = 200
        headers = {'Content-Type': 'text/event-stream', 'Set-Cookie': 'PRIVATE'}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def iter_content(self, *args, **kwargs): yield b'data: {"ok":true}\n\n'
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def request(self, method, url, **kwargs):
            upstream.append((method, url, kwargs))
            return Response()
    monkeypatch.setattr('requests.Session', Session)
    secret = codex_token() if provider == 'codex' else 'PRIVATE-real-key'
    config = {'stage': 'network', 'timeout': 10, 'token': secret,
              'ai_configuration': {'provider': provider, 'model': model, 'thinking': 'high'}}
    thread = threading.Thread(target=lambda: model_relay.serve(config, server_class=factory), daemon=True)
    thread.start()
    assert ready.wait(3)
    server = captured[0]
    def call(method, path, body=None, capability=None):
        headers = ({'x-api-key': capability} if provider == 'anthropic' else {'Authorization': 'Bearer ' + capability}) if capability else {}
        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        connection.request(method, path, body=body, headers=headers)
        result = connection.getresponse()
        status, headers, raw = result.status, dict(result.getheaders()), result.read()
        connection.close()
        return status, headers, raw
    route, upstream_url = {
        'codex': ('/codex/responses', 'https://chatgpt.com/backend-api/codex/responses'),
        'openai': ('/openai/v1/responses', 'https://api.openai.com/v1/responses'),
        'anthropic': ('/anthropic/v1/messages', 'https://api.anthropic.com/v1/messages'),
        'anthropic_token': ('/anthropic/v1/messages', 'https://api.anthropic.com/v1/messages'),
        'openrouter': ('/openrouter/api/v1/responses', 'https://openrouter.ai/api/v1/responses'),
    }[provider]
    try:
        status, _, raw = call('GET', '/bootstrap')
        assert status == 200 and secret.encode() not in raw
        capability = json.loads(raw)['relay_token']
        assert json.loads(raw)['ai_configuration'] == config['ai_configuration']
        checks = []
        monkeypatch.setattr(providers, 'validate_access', lambda value: checks.append(value))
        assert call('GET', '/validate')[0] == 403
        assert not checks
        status, _, raw = call('GET', '/validate', capability=capability)
        assert status == 200 and json.loads(raw) == {'valid': True}
        assert checks[-1].credential == secret and checks[-1].public() == config['ai_configuration']
        def unavailable(*args): raise RuntimeError('PRIVATE-provider-error')
        monkeypatch.setattr(providers, 'validate_access', unavailable)
        status, _, raw = call('GET', '/validate', capability=capability)
        assert status == 422 and secret.encode() not in raw and b'PRIVATE' not in raw
        assert call('POST', route, '{}')[0] == 403
        assert call('POST', '/v1/messages', '{}', capability)[0] == 403
        assert call('POST', route, json.dumps({'model': 'different-model'}), capability)[0] == 403
        field = 'output_config' if backend == 'claude' else 'reasoning'
        assert call('POST', route, json.dumps({'model': model, field: {'effort': 'low'}}), capability)[0] == 403
        status, headers, raw = call('POST', route, json.dumps({'model': model}), capability)
        assert status == 200 and secret.encode() not in raw and 'Set-Cookie' not in headers
        method, url, arguments = upstream[-1]
        assert url == upstream_url and arguments['allow_redirects'] is False
        assert arguments['headers'].get('x-api-key', arguments['headers'].get('Authorization')) in {secret, 'Bearer ' + secret}
        body = json.loads(arguments['data'])
        assert body['model'] == model and body[field]['effort'] == 'high'
        if provider == 'openrouter': assert body['provider']['require_parameters'] is True
        if backend == 'claude':
            assert call('POST', route + '?beta=true', json.dumps({'model': model}), capability)[0] == 200
            assert upstream[-1][1] == upstream_url + '?beta=true'
            assert call('POST', route + '?beta=false', json.dumps({'model': model}), capability)[0] == 403
        Response.status_code = 401
        status, _, raw = call('POST', route, json.dumps({'model': model}), capability)
        assert status == 502 and secret.encode() not in raw
    finally:
        server.shutdown()
        thread.join(timeout=3)
