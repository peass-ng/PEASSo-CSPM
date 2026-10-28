"""User-owned model selection, validation and bounded runner configuration."""
from dataclasses import dataclass, field, replace
import json
import os
import re
import threading
import time
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, SecretStr

PROVIDERS = {'codex': 'codex', 'openai': 'codex', 'anthropic': 'claude',
             'anthropic_token': 'claude', 'openrouter': 'openrouter'}
EFFORTS = ('none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max')
STATE_KEY = 'configuration'
ERROR_KEY = 'configuration_error'
REVIEW_POLICY_KEY = 'review_policy'


class ConfigurationError(ValueError):
    """A controlled, credential-free validation message."""


class ReviewDisabled(ConfigurationError):
    """Explicit account preference, not a credential validation failure."""


class ReviewPolicy(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    disabled: bool


def review_disabled(store, user):
    """Read the non-secret account override before loading any AI credential."""
    raw = store.ai_state(user, REVIEW_POLICY_KEY) if user else None
    if raw is None:
        return False
    try:
        return ReviewPolicy.model_validate_json(raw).disabled
    except Exception:
        # An unreadable policy must never authorize additional AI execution.
        return True


class Selection(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, hide_input_in_errors=True)
    provider: str = Field(max_length=32)
    model: str = Field(min_length=1, max_length=200)
    thinking: str = Field(min_length=1, max_length=16)
    credential: SecretStr | None = Field(default=None, max_length=32000)


@dataclass(frozen=True)
class ModelAccess:
    provider: str
    model: str
    thinking: str
    credential: str = field(repr=False)
    guard: object = field(default=None, repr=False, compare=False)

    def public(self):
        return {'provider': self.provider, 'model': self.model, 'thinking': self.thinking}


def auth_document(access):
    # Keep the legacy private-file protocol for existing Codex deployments.
    if isinstance(access, GuardedToken):
        return {**access.guard.identity, 'access_token': str(access)}
    return ({**access.public(), 'access_token': access.credential}
            if isinstance(access, ModelAccess) else {'access_token': access})


def credential_value(access):
    return access.credential if isinstance(access, ModelAccess) else access


def check_selection(provider, model, thinking, credential):
    if provider not in PROVIDERS:
        raise ConfigurationError('Select a supported AI provider.')
    if not isinstance(model, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}', model):
        raise ConfigurationError('Enter an exact provider model ID.')
    if thinking not in EFFORTS:
        raise ConfigurationError('Select a supported thinking effort.')
    if (not isinstance(credential, str) or not credential or len(credential) > 32000
            or any(c.isspace() or ord(c) < 32 for c in credential)):
        raise ConfigurationError('A usable AI credential is required.')
    # Reject unsupported explicit efforts, including Chack's default-high
    # downgrade. A user's choice must never silently become a different level.
    from ._vendor.chack.thinking_effort import supported_thinking_efforts
    supported = supported_thinking_efforts(model)
    if supported is not None and thinking not in supported:
        raise ConfigurationError('The selected model does not support that thinking effort.')
    if provider in {'anthropic', 'anthropic_token'} and thinking not in {'low', 'medium', 'high', 'xhigh', 'max'}:
        raise ConfigurationError('Claude requires low, medium, high, xhigh or max thinking effort.')
    return ModelAccess(provider, model, thinking, credential)


def provider_json(method, url, headers, body=None):
    """Fixed provider origins only; never return provider error bodies."""
    import requests
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.request(method, url, headers=headers, json=body,
                                 allow_redirects=False, timeout=(5, 25), stream=True) as response:
                if response.status_code != 200:
                    raise ValueError()
                raw = bytearray()
                for chunk in response.iter_content(65536):
                    raw.extend(chunk)
                    if len(raw) > 12_000_000:
                        raise ValueError()
                result = json.loads(raw)
                if not isinstance(result, dict) or result.get('error'):
                    raise ValueError()
                return result
    except Exception:
        raise ConfigurationError('AI credential, model or thinking could not be validated. Check access and try again.') from None


def codex_probe(headers, body):
    """Read a bounded real Responses stream; catalog access alone is insufficient."""
    import requests
    deadline = time.monotonic() + 30
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.post('https://chatgpt.com/backend-api/codex/responses', headers=headers,
                              json=body, stream=True, allow_redirects=False, timeout=(5, 25)) as response:
                if response.status_code != 200:
                    raise ValueError()
                total = 0
                for line in response.iter_lines(chunk_size=1024):
                    total += len(line)
                    if total > 1_000_000 or time.monotonic() > deadline:
                        raise ValueError()
                    if not line.startswith(b'data: '):
                        continue
                    event = json.loads(line[6:])
                    if event.get('type') in {'error', 'response.failed'}:
                        raise ValueError()
                    if event.get('type') in {'response.completed', 'response.incomplete'}:
                        result = event.get('response') or {}
                        if result.get('id') and not result.get('error') and result.get('status') != 'failed':
                            return result
                        raise ValueError()
                raise ValueError()
    except Exception:
        raise ConfigurationError('Codex inference validation failed. Reconnect or check the selected model and thinking effort.') from None


def validate_access(access):
    """Verify the actual credential's model access and selected effort."""
    access = check_selection(**access.public(), credential=access.credential)
    provider, model, thinking, secret = access.provider, access.model, access.thinking, access.credential
    headers = {'Authorization': 'Bearer ' + secret}
    schema = {'type': 'object', 'properties': {'ok': {'type': 'boolean'}}, 'required': ['ok'], 'additionalProperties': False}
    tool = {'type': 'function', 'name': 'configuration_probe', 'description': 'Confirm configuration.', 'parameters': schema, 'strict': True}
    request = {'model': model, 'input': 'Call configuration_probe with ok=true.', 'max_output_tokens': 64,
               'tools': [tool], 'reasoning': {'effort': thinking}, 'store': False}
    if provider == 'codex':
        from .auth import claims, valid
        if not valid(secret):
            raise ConfigurationError('Reconnect your Codex account.')
        headers['ChatGPT-Account-ID'] = claims(secret)['https://api.openai.com/auth']['chatgpt_account_id']
        models = provider_json('GET', 'https://chatgpt.com/backend-api/codex/models?client_version=0.147.0', headers)
        entry = next((m for m in models.get('models', []) if isinstance(m, dict) and m.get('slug') == model), None)
        # Discovery omits some usable manual IDs/aliases. An unlisted model
        # must pass the exact inference probe below, without any fallback.
        if entry is not None and thinking not in {level.get('effort') for level in entry.get('supported_reasoning_levels', []) if isinstance(level, dict)}:
            raise ConfigurationError('That model and thinking effort are unavailable for this Codex account.')
        probe = {key: value for key, value in request.items() if key != 'max_output_tokens'}
        probe.update(stream=True, instructions='Validate configuration; call configuration_probe with ok=true.',
                     input=[{'role': 'user', 'content': [{'type': 'input_text', 'text': 'Call configuration_probe with ok=true.'}]}])
        codex_probe(headers, probe)
    elif provider in {'anthropic', 'anthropic_token'}:
        if provider == 'anthropic':
            headers = {'x-api-key': secret}
        else:
            headers['anthropic-beta'] = 'oauth-2025-04-20'
        headers['anthropic-version'] = '2023-06-01'
        entry = provider_json('GET', 'https://api.anthropic.com/v1/models/' + quote(model, safe=''), headers)
        if entry.get('id') != model:
            raise ConfigurationError('Enter the exact Claude model ID available to this credential.')
        effort = (entry.get('capabilities') or {}).get('effort')
        if isinstance(effort, dict) and (not effort.get('supported') or not (effort.get(thinking) or {}).get('supported')):
            raise ConfigurationError('The selected Claude model does not support that thinking effort.')
        if effort is None:
            from ._vendor.chack.thinking_effort import supported_thinking_efforts
            if supported_thinking_efforts(model) is None:
                raise ConfigurationError('Thinking support for that Claude model could not be verified.')
        headers['User-Agent'] = 'claude-cli/2.1.304 (external, cli)'
        response = provider_json('POST', 'https://api.anthropic.com/v1/messages?beta=true', headers, {
            'model': model, 'max_tokens': 64, 'system': "You are Claude Code, Anthropic's official CLI for Claude.",
            'messages': [{'role': 'user', 'content': 'Call configuration_probe with ok=true.'}],
            'tools': [{'name': 'configuration_probe', 'description': 'Confirm configuration.', 'input_schema': schema}],
            'output_config': {'effort': thinking}})
        if not isinstance(response.get('id'), str) or response.get('type') != 'message':
            raise ConfigurationError('Claude inference validation did not confirm the selected configuration.')
    elif provider == 'openai':
        # A tiny inference verifies both key-specific model access and the exact
        # Responses reasoning parameter, rather than trusting a global catalog.
        response = provider_json('POST', 'https://api.openai.com/v1/responses', headers, request)
        if not isinstance(response.get('id'), str) or response.get('status') == 'failed':
            raise ConfigurationError('The provider did not confirm the selected AI configuration.')
    else:
        response = provider_json('POST', 'https://openrouter.ai/api/v1/responses', headers,
                                 {**request, 'provider': {'require_parameters': True}})
        if not isinstance(response.get('id'), str) or response.get('status') == 'failed':
            raise ConfigurationError('The provider did not confirm the selected AI configuration.')
    return access


def connected_codex_token(store, cipher, user, resolver=None):
    from .auth import personal_token
    raw = store.ai_state(user, 'auth') if user else None
    if raw is None or cipher.decrypt(raw).get('disconnected'):
        raise ConfigurationError('Sign in with your Codex account first.')
    token, source = (resolver or personal_token)(store, cipher, user)
    if source != 'personal':
        raise ConfigurationError('Sign in with your Codex account first.')
    return token


def configuration_error(store, cipher, user):
    raw = store.ai_state(user, ERROR_KEY) if user else None
    if not raw:
        return None
    try:
        data = cipher.decrypt(raw)
        return {'message': data['message'], 'at': data['at']}
    except Exception:
        return {'message': 'AI configuration could not be read. Validate and save it again.', 'at': None}


def record_error(store, cipher, user, error):
    message = str(error) if isinstance(error, ConfigurationError) else 'AI configuration validation failed. Check your credential, model and thinking, then validate and save again.'
    if user:
        raw = store.ai_state(user, ERROR_KEY)
        store.set_ai_state(user, ERROR_KEY, cipher.encrypt({'message': message, 'at': time.time()}), raw)
    return ConfigurationError(message)


def clear_error(store, cipher, user):
    raw = store.ai_state(user, ERROR_KEY)
    if raw and not store.set_ai_state(user, ERROR_KEY, None, raw):
        raise ConfigurationError('AI settings changed. Reload and validate again.')


def model_access(access):
    if isinstance(access, ModelAccess):
        return access
    import yaml
    from ._vendor.chack.model_aliases import resolve_model_alias
    from .prompting import agent_config_path
    # Lambda intentionally has no Chack/model SDK. Read the same shipped stage
    # YAML and resolve its alias with the exact worker pin's small pure helper.
    config = yaml.safe_load(agent_config_path('network').read_text())['agent']
    alias = config['primary']
    # The platform default uses a Codex credential. The shared OpenAI alias
    # can name a model unavailable to that account while the central catalog
    # provides a separate Codex alias for the same quality tier.
    if alias == 'OPENAI_BEST_QUALITY':
        alias = 'CODEX_BEST_QUALITY'
    model = resolve_model_alias(alias, provider='codex')
    return check_selection('codex', model, config.get('thinking_effort', 'high'), str(access))


class GuardedToken(str):
    def __new__(cls, value, guard):
        token = str.__new__(cls, value)
        token.guard = guard
        return token


def guarded(access, guard):
    return replace(access, guard=guard) if isinstance(access, ModelAccess) else GuardedToken(access, guard)


class LaunchGuard:
    """One failed preflight stops subsequent launches in the same review pool."""
    def __init__(self, store, cipher, user, auth_mode, resolver, access):
        self.store, self.cipher, self.user = store, cipher, user
        self.auth_mode, self.resolver = auth_mode, resolver
        self.profile = store.ai_state(user, STATE_KEY) if user else None
        self.identity = model_access(access).public()
        self.secrets = {credential_value(access)}
        self.lock = threading.Lock()
        self.failed = False

    def __call__(self):
        with self.lock:
            if self.failed:
                raise ConfigurationError('AI launch stopped after a configuration validation failure.')
            try:
                if self.user and self.store.ai_state(self.user, STATE_KEY) != self.profile:
                    raise ConfigurationError('AI settings changed during this scan. Retry with the current configuration.')
                access, _ = resolve_access(self.store, self.cipher, self.user,
                    auth_mode=self.auth_mode, token_resolver=self.resolver, attach_guard=False)
                if model_access(access).public() != self.identity:
                    raise ConfigurationError('AI settings changed during this scan. Retry with the current configuration.')
                self.secrets.add(credential_value(access))
                return guarded(access, self)
            except ReviewDisabled:
                raise
            except Exception as error:
                self.failed = True
                raise record_error(self.store, self.cipher, self.user, error) from None


def validate_before_launch(access):
    guard = getattr(access, 'guard', None)
    if guard is not None:
        return guard()
    validate_access(model_access(access))
    return access


def launch_error(access):
    error = ConfigurationError('AI inference validation failed before starting the agent. Validate and save your settings again.')
    guard = getattr(access, 'guard', None)
    if isinstance(guard, LaunchGuard):
        with guard.lock:
            guard.failed = True
            return record_error(guard.store, guard.cipher, guard.user, error)
    return error


def resolve_access(store, cipher, user, *, auth_mode='local', token_resolver=None, verify=True, attach_guard=True, ignore_error=False, ignore_recorded_error=False):
    from .auth import default_token, personal_token
    token_resolver = token_resolver or personal_token
    try:
        if review_disabled(store, user):
            raise ReviewDisabled('AI review is disabled for every scan in your settings.')
        warning = configuration_error(store, cipher, user)
        if warning and not (ignore_error or ignore_recorded_error):
            raise ConfigurationError(warning['message'])
        raw = store.ai_state(user, STATE_KEY) if user else None
        if raw:
            data = cipher.decrypt(raw)
            if not ignore_error and (data.get('validation_failed') or data.get('validated') is not True):
                raise ConfigurationError('AI configuration needs validation. Validate and save it again.')
            secret = data.get('credential', '')
            if data['provider'] == 'codex':
                secret = connected_codex_token(store, cipher, user, token_resolver)
            access = check_selection(data['provider'], data['model'], data['thinking'], secret)
            source = 'personal'
        elif auth_mode != 'local':
            access, source = default_token(), 'platform'
        else:
            raw_auth = store.ai_state(user, 'auth') if user else None
            if raw_auth and cipher.decrypt(raw_auth).get('requires_selection'):
                raise ConfigurationError('Choose your model and thinking effort, then validate and save AI settings.')
            access, source = token_resolver(store, cipher, user)
        if verify:
            validate_access(model_access(access))
            if attach_guard:
                access = guarded(access, LaunchGuard(store, cipher, user, auth_mode, token_resolver, access))
        return access, source
    except ReviewDisabled:
        raise
    except Exception as error:
        if verify:
            raise record_error(store, cipher, user, error) from None
        raise


def configure_agent(config, document, *, relay=None):
    """Apply the same selection to every stage and any Chack child role."""
    provider = document.get('provider', 'codex')
    secret = document['access_token']
    if provider not in PROVIDERS:
        raise ConfigurationError('invalid_ai_provider')
    for name in ('codex_access_token', 'openai_api_key', 'anthropic_api_key', 'claude_api_key', 'openrouter_api_key'):
        setattr(config.credentials, name, '')
    for name in ('CODEX_ACCESS_TOKEN', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CLAUDE_API_KEY',
                 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN', 'CLAUDE_ACCESS_TOKEN',
                 'OPENROUTER_API_KEY', 'OPENROUTER_BASE_URL', 'ANTHROPIC_BASE_URL'):
        os.environ.pop(name, None)
    if document.get('model') is not None:
        access = check_selection(provider, document['model'], document['thinking'], secret)
        config.model.primary = access.model
        config.model.provider = PROVIDERS[provider]
        config.model.api_key_type = {'codex': 'codex', 'openai': 'openai',
                                     'anthropic': 'anthropic', 'anthropic_token': 'anthropic',
                                     'openrouter': 'openrouter'}[provider]
        config.agent.thinking_effort = access.thinking
        from chack_agent.config import ROLE_AGENT_FIELDS
        for role, tool in ROLE_AGENT_FIELDS.items():
            if hasattr(config.model, role):
                setattr(config.model, role, access.model)
            setattr(config.model, role + '_thinking_effort', access.thinking)
            settings = getattr(config.tools, tool, None)
            if isinstance(settings, dict):
                settings['thinking_effort'] = access.thinking
    credential_field = {'codex': 'codex_access_token', 'openai': 'openai_api_key',
                        'anthropic': 'anthropic_api_key', 'anthropic_token': None,
                        'openrouter': 'openrouter_api_key'}[provider]
    if credential_field:
        setattr(config.credentials, credential_field, secret)
    if provider in {'anthropic', 'anthropic_token'}:
        name = 'ANTHROPIC_API_KEY' if provider == 'anthropic' else 'CLAUDE_CODE_OAUTH_TOKEN'
        os.environ[name] = secret  # The Claude backend consumes these at construction.
        if relay:
            os.environ['ANTHROPIC_BASE_URL'] = relay + '/anthropic'
            config.env['ANTHROPIC_BASE_URL'] = relay + '/anthropic'
    if provider == 'openrouter' and relay:
        config.credentials.openrouter_base_url = relay + '/openrouter/api/v1'
