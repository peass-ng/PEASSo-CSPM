"""AI settings/launch preflight must run in package_api without the worker SDK."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'peaso/ai/_vendor/chack'
PIN = '53ab40167c4df367e2e7ca980f1bf3ac8c0b3375'


def test_vendored_helpers_and_data_match_exact_worker_pin():
    manifest = json.loads((VENDOR/'provenance.json').read_text())
    assert manifest['commit'] == PIN and PIN in (ROOT/'pyproject.toml').read_text()
    assert manifest['license']['declared'] == 'MIT'
    for name in manifest['files']:
        assert (VENDOR/name).is_file()
    from peaso.ai._vendor.chack import thinking_effort
    assert thinking_effort._PUBLISHED_EFFORTS_FILE == str(VENDOR/'config/thinking_effort.yaml')
    assert thinking_effort.published_thinking_efforts()
    # All non-Python vendor assets must also enter installed wheels.
    import tomllib
    package_data = tomllib.loads((ROOT/'pyproject.toml').read_text())['tool']['setuptools']['package-data']
    assert set(package_data['peaso.ai._vendor.chack']) >= {'config/thinking_effort.yaml', 'LICENSE', 'provenance.json'}


PROBE = r'''
import base64, importlib.abc, importlib.metadata, json, os, pathlib, socket, sys, tempfile, time
from types import SimpleNamespace
attempted = []
class NoWorkerSDK(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'chack_agent', 'agents', 'langchain', 'langgraph', 'qdrant_client', 'fastembed'}:
            attempted.append(fullname)
            raise ImportError('worker SDK deliberately unavailable in API')
sys.meta_path.insert(0, NoWorkerSDK())
def offline(*args, **kwargs): raise AssertionError('unexpected external request')
socket.socket.connect = offline
from fastapi import FastAPI
from peaso.ai import auth, providers, isolation
from peaso.ai.crypto import AICipher
from peaso.auth import Identity
from peaso.storage import SQLiteStore
from peaso.ai._vendor.chack import model_aliases
# The exact pinned resolver retains the central alias service, stubbed here.
model_aliases.requests.get = lambda *a, **k: SimpleNamespace(
    raise_for_status=lambda: None, json=lambda: {'model_aliases': {'OPENAI_BEST_QUALITY': 'gpt-6-sol'}})
claims = {'exp': time.time()+7200, 'https://api.openai.com/auth': {'chatgpt_account_id': 'fixture-account'}}
token = 'e30.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.fixture'
os.environ['CODEX_ACCESS_TOKEN'] = token
isolation.available = lambda: True
calls = []
def response(method, url, headers, body=None):
    calls.append((method, url, body))
    if '/codex/models' in url:
        return {'models': [{'slug': model, 'supported_reasoning_levels': [{'effort': 'high'}]}
                           for model in ('gpt-6-sol', 'gpt-5.3-codex')]}
    if method == 'GET' and 'api.anthropic.com' in url:
        return {'id': 'claude-sonnet-4-6', 'capabilities': {'effort': {'supported': True, 'high': {'supported': True}}}}
    return {'id': 'validated-response', 'status': 'completed', 'type': 'message'}
providers.provider_json = response
providers.codex_probe = lambda *args: {'id': 'validated-codex-response'}
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    store, cipher = SQLiteStore(root/'state'), AICipher(root/'identity')
    user = Identity('alice')
    app = FastAPI()
    auth.mount_auth_routes(app, store, root/'identity', lambda: user, auth_mode='cognito')
    def endpoint(path, method):
        return next(r.endpoint for r in app.routes if getattr(r, 'path', None) == path and method in r.methods)
    get = endpoint('/api/ai/configuration', 'GET')
    save = endpoint('/api/ai/configuration', 'POST')
    validate = endpoint('/api/ai/configuration/validate', 'POST')
    settings = SimpleNamespace(identity_dir=root/'identity', auth_mode='cognito')
    # Real default path: YAML + alias resolution + model/effort + live preflight.
    default = providers.model_access(token)
    assert default.model == 'gpt-6-sol' and default.thinking == 'high'
    auth.require_local_codex(settings, store, 'alice')
    status = get(user=user)
    assert status['available'] and status['source'] == 'hacktricks' and status['selection'] is None
    assert 'gpt-' not in json.dumps(status) and token not in json.dumps(status)
    store.set_ai_state('alice', 'auth', cipher.encrypt({'access_token': token}), None)
    for provider, model in [('codex','gpt-5.3-codex'), ('openai','gpt-5.3-codex'),
            ('anthropic','claude-sonnet-4-6'), ('anthropic_token','claude-sonnet-4-6'),
            ('openrouter','openai/gpt-5.3-codex')]:
        body = providers.Selection(provider=provider, model=model, thinking='high',
                                   credential=None if provider == 'codex' else 'fixture-private-key')
        result = save(body, user=user)
        assert result['available'] and result['selection']['provider'] == provider
        auth.require_local_codex(settings, store, 'alice')
        assert validate(user=user)['available']
        access, source = providers.resolve_access(store, cipher, 'alice', auth_mode='cognito')
        assert source == 'personal' and access.public() == {'provider':provider, 'model':model, 'thinking':'high'}
        assert providers.validate_before_launch(access).public() == access.public()
    try:
        providers.check_selection('openai','gpt-5.3-codex','minimal','fixture-private-key')
    except providers.ConfigurationError:
        pass
    else:
        raise AssertionError('invalid model/effort was accepted')
    def revoked(*args): raise providers.ConfigurationError('Inference access was revoked.')
    providers.provider_json = revoked
    try:
        auth.require_local_codex(settings, store, 'alice')
    except Exception as error:
        assert error.status_code == 409
    else:
        raise AssertionError('revoked configuration did not block launch')
    assert not get(user=user)['available'] and get(user=user)['configuration_error']
assert not attempted and 'chack_agent' not in sys.modules and 'agents' not in sys.modules
print(json.dumps({'default_and_all_five_personal_options': 'passed', 'revoked_launch_blocked': True,
                  'worker_sdk_import_attempts': attempted, 'python': sys.version.split()[0]}))
'''


def test_api_dependencies_only_subprocess_blocks_worker_sdk_and_validates_default_and_personal_options(tmp_path):
    # Release verification sets this to the real API-only Python 3.12 venv.
    # CI also runs the same hard import blocker in its interpreter; no skips.
    executable = os.getenv('PEASO_TEST_API_PYTHON', sys.executable)
    environment = {**os.environ, 'PYTHONPATH': str(ROOT), 'PYTHONDONTWRITEBYTECODE': '1',
                   'AWS_EC2_METADATA_DISABLED': 'true'}
    for key in ('PEASO_STORAGE', 'PEASO_AI_CREDENTIAL_SECRET_ARN', 'CODEX_TOKEN_SECRET_ARN',
                'CHACK_MODEL_ALIASES_LAMBDA_URL'):
        environment.pop(key, None)
    result = subprocess.run([executable, '-B', '-c', PROBE], cwd=tmp_path, env=environment,
                            capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['worker_sdk_import_attempts'] == []
