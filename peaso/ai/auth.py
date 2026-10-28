"""Encrypted personal AI configuration, Codex sign-in and explicit platform default.

Device protocol mirrors codex-rs/login/src/device_code_auth.rs. Never accepts
an issuer, verification URL or OAuth client supplied by a browser.
"""
import base64
import json
import os
import time
import uuid
import requests
from fastapi import Depends, HTTPException, Response

ISSUER = "https://auth.openai.com"
CLIENT = "app_EMoamEEZ73f0CkXaXp7hrann"


def claims(token):
    try:
        part = token.split('.')[1]
        return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
    except (ValueError, IndexError, TypeError):
        return {}


def valid(token):
    data = claims(token)
    try:
        return bool((data.get('https://api.openai.com/auth') or {}).get('chatgpt_account_id')) and float(data.get('exp') or 0) > time.time() + 120
    except (ValueError, TypeError, AttributeError):
        return False


def post(path, data, *, form=False):
    try:
        # Match the working device flow transport. Python-urllib requests to
        # this issuer can be rejected before the OAuth endpoint is reached.
        with requests.post(ISSUER + path, **({'data': data} if form else {'json': data}),
                           timeout=20, allow_redirects=False) as response:
            if len(response.content) > 128000:
                return 502, {}
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            if response.status_code != 200:
                # Only protocol enums are needed for polling, never provider
                # descriptions or bodies that could contain credentials.
                code = payload.get('error') or payload.get('error_code')
                payload = {'error': code} if code in ('authorization_pending', 'slow_down', 'expired_token', 'access_denied') else {}
            return response.status_code, payload
    except requests.RequestException:
        return 503, {}


def default_token():
    token = os.getenv('CODEX_ACCESS_TOKEN', '')
    if valid(token):
        return token
    secret = os.getenv('CODEX_TOKEN_SECRET_ARN', '').strip()
    if secret:
        import boto3
        try:
            response = boto3.client('secretsmanager', region_name=secret.split(':')[3]).get_secret_value(SecretId=secret)
            raw = response.get('SecretString', '')
            try:
                data = json.loads(raw)
            except (ValueError, TypeError):
                data = raw
            token = data.get('access_token', '') if isinstance(data, dict) else data
            if isinstance(token, str) and valid(token):
                return token
        except Exception:
            # Provider exceptions can contain private secret identifiers.
            raise RuntimeError('codex_auth_unavailable') from None
    raise RuntimeError('codex_auth_unavailable')


def personal_token(store, cipher, user):
    raw = store.ai_state(user, 'auth') if user else None
    if raw is None:
        return default_token(), 'platform'
    data = cipher.decrypt(raw)
    if data.get('disconnected'):
        return default_token(), 'platform'
    if valid(data.get('access_token', '')):
        return data['access_token'], 'personal'
    if data.get('lock_until', 0) > time.time():
        raise RuntimeError('codex_auth_busy')
    locked = dict(data, lock_until=time.time() + 60, lock_id=uuid.uuid4().hex)
    locked_raw = cipher.encrypt(locked)
    if not store.set_ai_state(user, 'auth', locked_raw, raw):
        raise RuntimeError('codex_auth_busy')
    try:
        status, new = post('/oauth/token', {'grant_type': 'refresh_token', 'client_id': CLIENT, 'refresh_token': data['refresh_token']}, form=True)
        if status != 200 or not valid(new.get('access_token', '')):
            raise RuntimeError('codex_reconnect_required')
        data.update({key: new.get(key, data.get(key, '')) for key in ('access_token', 'refresh_token', 'id_token')})
        if not store.set_ai_state(user, 'auth', cipher.encrypt(data), locked_raw):
            raise RuntimeError('codex_auth_changed')
        return data['access_token'], 'personal'
    except Exception:
        store.set_ai_state(user, 'auth', cipher.encrypt(data), locked_raw)
        raise


def codex_available(store, identity_dir, user):
    """Compatibility name: resolve any configured AI provider for local scans."""
    try:
        from .crypto import AICipher
        from .providers import resolve_access
        resolve_access(store, AICipher(identity_dir), user, verify=False)
        return True
    except Exception:
        return False


def require_local_codex(settings, store, user):
    from .crypto import AICipher
    from .providers import ERROR_KEY, resolve_access, review_disabled
    if review_disabled(store, user):
        return
    try:
        # A previous attempt can leave an encrypted error even after the
        # current credential becomes usable. Revalidate the current selection
        # at every admission. Only the exact error observed before that fresh
        # validation may be cleared; a concurrent newer failure still blocks.
        prior_error = store.ai_state(user, ERROR_KEY) if user else None
        resolve_access(store, AICipher(settings.identity_dir), user,
                       auth_mode=settings.auth_mode, ignore_recorded_error=True)
        if prior_error and not store.set_ai_state(user, ERROR_KEY, None, prior_error):
            raise RuntimeError('AI configuration changed during admission')
    except Exception:
        raise HTTPException(409, 'AI checks require a valid AI configuration. Configure a provider, model and thinking effort in Settings, or disable AI for this scan.')
    if settings.auth_mode == 'local':
        from .isolation import available
        if not available():
            raise HTTPException(409, 'AI checks require a configured isolation launcher. Configure isolated AI execution or disable AI for this scan.')


def mount_auth_routes(app, store, identity_dir, account_identity, *, auth_mode='local'):
    from .crypto import AICipher
    # Lazy so unavailable AI infrastructure cannot prevent CSPM startup.
    class Cipher:
        def encrypt(self, value):
            return AICipher(identity_dir).encrypt(value)
        def decrypt(self, value):
            return AICipher(identity_dir).decrypt(value)
    cipher = Cipher()
    if os.getenv("PEASO_STORAGE", "sqlite") == "sqlite":
        AICipher(identity_dir)  # Initialize before read-only collector/analyzer mounts use it.
    def owner(user):
        if user.auth_kind != 'user':
            raise HTTPException(403, 'Sign in with your user account')
        return user.tenant_id

    from .providers import (ConfigurationError, Selection, ReviewPolicy, REVIEW_POLICY_KEY, review_disabled, STATE_KEY, check_selection,
        connected_codex_token, resolve_access, validate_access, configuration_error, record_error, clear_error)

    @app.get('/api/ai/configuration')
    def configuration(user=Depends(account_identity)):
        uid = owner(user)
        raw = store.ai_state(uid, STATE_KEY)
        try:
            selected = cipher.decrypt(raw) if raw else None
        except Exception:
            selected = None
        selection = ({key: selected.get(key, '') for key in ('provider', 'model', 'thinking')}
                     if isinstance(selected, dict) else None)
        if selection is not None:
            selection['credential_saved'] = bool(selected.get('credential'))
        raw_auth = store.ai_state(uid, 'auth')
        connected = bool(raw_auth and not cipher.decrypt(raw_auth).get('disconnected'))
        from .isolation import available as isolation_available
        isolated = isolation_available()
        source, usable = None, False
        disabled = review_disabled(store, uid)
        try:
            if not disabled:
                _, source = resolve_access(store, cipher, uid, auth_mode=auth_mode, verify=False)
                usable = True
        except Exception as error:
            if selected or raw_auth or (auth_mode != 'local' and (os.getenv('CODEX_ACCESS_TOKEN') or os.getenv('CODEX_TOKEN_SECRET_ARN'))):
                record_error(store, cipher, uid, error)
        return {'available': usable and isolated, 'disabled': disabled, 'hosted': auth_mode != 'local',
                'source': 'hacktricks' if source == 'platform' and auth_mode != 'local' else source,
                'selection': selection, 'codex_connected': connected,
                'isolation_available': isolated, 'configuration_error': None if disabled else configuration_error(store, cipher, uid)}

    @app.patch('/api/ai/preferences')
    def save_preferences(body: ReviewPolicy, user=Depends(account_identity)):
        uid = owner(user)
        raw = store.ai_state(uid, REVIEW_POLICY_KEY)
        if not store.set_ai_state(uid, REVIEW_POLICY_KEY, body.model_dump_json(), raw):
            raise HTTPException(409, 'AI preferences changed; reload and try again.')
        return body.model_dump()

    @app.post('/api/ai/configuration')
    def save_configuration(body: Selection, user=Depends(account_identity)):
        uid = owner(user)
        raw = store.ai_state(uid, STATE_KEY)
        previous = cipher.decrypt(raw) if raw else {}
        try:
            if body.provider == 'codex':
                secret = connected_codex_token(store, cipher, uid)
            else:
                secret = body.credential.get_secret_value() if body.credential else (
                    previous.get('credential', '') if previous.get('provider') == body.provider else '')
            access = validate_access(check_selection(body.provider, body.model, body.thinking, secret))
        except Exception as error:
            # Validation helpers expose controlled messages only. OAuth, SDK and
            # transport exception bodies can contain private credentials.
            detail = str(error) if isinstance(error, ConfigurationError) else 'AI authentication is unavailable. Reconnect or supply a valid credential.'
            record_error(store, cipher, uid, ConfigurationError(detail))
            raise HTTPException(422, detail) from None
        value = {**access.public(), 'validated': True}
        if body.provider != 'codex':
            value['credential'] = secret
        if not store.set_ai_state(uid, STATE_KEY, cipher.encrypt(value), raw):
            raise HTTPException(409, 'AI settings changed; reload and try again.')
        clear_error(store, cipher, uid)
        return configuration(user)

    @app.post('/api/ai/configuration/validate')
    def revalidate_configuration(user=Depends(account_identity)):
        uid = owner(user)
        raw = store.ai_state(uid, STATE_KEY)
        try:
            resolve_access(store, cipher, uid, auth_mode=auth_mode, ignore_error=True)
            if store.ai_state(uid, STATE_KEY) != raw:
                raise ConfigurationError('AI settings changed. Reload and validate again.')
            if raw:
                data = cipher.decrypt(raw)
                if not store.set_ai_state(uid, STATE_KEY, cipher.encrypt({**data, 'validated': True, 'validation_failed': False}), raw):
                    raise ConfigurationError('AI settings changed. Reload and validate again.')
            clear_error(store, cipher, uid)
        except Exception as error:
            raise HTTPException(422, str(record_error(store, cipher, uid, error))) from None
        return configuration(user)

    @app.delete('/api/ai/configuration', status_code=204)
    def clear_configuration(user=Depends(account_identity)):
        uid = owner(user)
        # Switching to the hosted default is an explicit selection and must be
        # validated before replacing any saved personal configuration.
        if auth_mode != 'local':
            try:
                from .providers import model_access
                validate_access(model_access(default_token()))
            except Exception as error:
                raise HTTPException(422, str(record_error(store, cipher, uid, error))) from None
        raw = store.ai_state(uid, STATE_KEY)
        if not store.set_ai_state(uid, STATE_KEY, None, raw):
            raise HTTPException(409, 'AI settings changed; reload and try again.')
        clear_error(store, cipher, uid)
        return Response(status_code=204)

    @app.get('/api/ai/codex')
    def status(user=Depends(account_identity)):
        uid = owner(user)
        raw = store.ai_state(uid, 'auth')
        connected = bool(raw and not cipher.decrypt(raw).get('disconnected'))
        platform_configured = bool(valid(os.getenv('CODEX_ACCESS_TOKEN', '')) or os.getenv('CODEX_TOKEN_SECRET_ARN'))
        summary = configuration(user)
        available = summary['available']
        from .isolation import available as isolation_available
        isolated = isolation_available()
        return {'connected': connected, 'source': 'personal' if connected else 'platform',
                'disabled': summary['disabled'],
                'platform_configured': platform_configured, 'available': available and isolated,
                'isolation_available': isolated, 'configuration_error': summary['configuration_error'],
                'unavailable_reason': 'ai_isolation_unavailable' if not isolated else None}

    @app.post('/api/ai/codex/login')
    def start(response: Response, user=Depends(account_identity)):
        response.headers['Cache-Control'] = 'private, no-store'
        response.headers['Pragma'] = 'no-cache'
        uid = owner(user)
        old = store.ai_state(uid, 'pending')
        if old and cipher.decrypt(old).get('expires_at', 0) > time.time():
            pending = cipher.decrypt(old)
            return {'verification_url': ISSUER + '/codex/device', 'user_code': pending['user_code'], 'interval': pending['interval'], 'expires_at': pending['expires_at']}
        status, data = post('/api/accounts/deviceauth/usercode', {'client_id': CLIENT})
        if status != 200:
            raise HTTPException(503, 'Could not start Codex device sign-in. Retry in a moment.' if status != 404 else 'Codex device sign-in is not available from the authentication server. Retry or check device-login permissions for your ChatGPT account.')
        device_id, code = data.get('device_auth_id'), data.get('user_code') or data.get('usercode')
        if not isinstance(device_id, str) or not device_id.strip() or not isinstance(code, str) or not code.strip():
            raise HTTPException(502, 'Codex did not return a usable device sign-in code. Retry.')
        try:
            interval = max(5, min(60, int(data.get('interval') or 5)))
        except (TypeError, ValueError):
            interval = 5
        pending = {'device_auth_id': device_id.strip(), 'user_code': code.strip(),
                   'interval': interval, 'expires_at': time.time() + 900, 'next_poll': 0}
        if not store.set_ai_state(uid, 'pending', cipher.encrypt(pending), old):
            raise HTTPException(409, 'Sign-in already started; retry')
        return {'verification_url': ISSUER + '/codex/device', 'user_code': pending['user_code'], 'interval': pending['interval'], 'expires_at': pending['expires_at']}

    @app.post('/api/ai/codex/login/poll')
    def poll(response: Response, user=Depends(account_identity)):
        response.headers['Cache-Control'] = 'private, no-store'
        response.headers['Pragma'] = 'no-cache'
        uid = owner(user)
        raw = store.ai_state(uid, 'pending')
        if not raw:
            raise HTTPException(409, 'Start Codex sign-in first')
        previous_auth = store.ai_state(uid, 'auth')
        data = cipher.decrypt(raw)
        if data['expires_at'] <= time.time():
            store.set_ai_state(uid, 'pending', None, raw)
            raise HTTPException(410, 'Codex sign-in expired')
        if data.get('next_poll', 0) > time.time():
            return {'status': 'pending'}
        locked = cipher.encrypt(dict(data, next_poll=time.time() + 60))
        if not store.set_ai_state(uid, 'pending', locked, raw):
            return {'status': 'pending'}
        status, result = post('/api/accounts/deviceauth/token', {key: data[key] for key in ('device_auth_id', 'user_code')})
        if status in (403, 404) or status == 400 and result.get('error') in ('authorization_pending', 'slow_down'):
            interval = min(60, data['interval'] + 5) if result.get('error') == 'slow_down' else data['interval']
            store.set_ai_state(uid, 'pending', cipher.encrypt(dict(data, interval=interval, next_poll=time.time() + interval)), locked)
            return {'status': 'pending'}
        if status == 400 and result.get('error') in ('expired_token', 'access_denied'):
            store.set_ai_state(uid, 'pending', None, locked)
            raise HTTPException(410, 'Codex sign-in expired or was declined. Start sign-in again.')
        if status != 200:
            store.set_ai_state(uid, 'pending', cipher.encrypt(dict(data, next_poll=time.time() + data['interval'])), locked)
            raise HTTPException(502, 'Codex sign-in could not be polled. Retry sign-in.')
        if not all(isinstance(result.get(key), str) and result[key] for key in ('authorization_code', 'code_verifier')):
            store.set_ai_state(uid, 'pending', None, locked)
            raise HTTPException(502, 'Codex did not complete device authorization. Start sign-in again.')
        status, tokens = post('/oauth/token', {'grant_type': 'authorization_code', 'client_id': CLIENT,
            'code': result['authorization_code'], 'code_verifier': result['code_verifier'], 'redirect_uri': ISSUER + '/deviceauth/callback'}, form=True)
        if status != 200 or not valid(tokens.get('access_token', '')):
            store.set_ai_state(uid, 'pending', None, locked)
            raise HTTPException(502, 'Codex token exchange failed')
        # CAS pending first: a disconnected/cancelled login cannot reconnect later.
        if not store.set_ai_state(uid, 'pending', None, locked):
            raise HTTPException(409, 'Sign-in was cancelled')
        if not store.set_ai_state(uid, 'auth', cipher.encrypt({**tokens, 'requires_selection': True}), previous_auth):
            raise HTTPException(409, 'Codex connection changed; retry')
        return {'status': 'connected'}

    @app.delete('/api/ai/codex', status_code=204)
    def disconnect(user=Depends(account_identity)):
        uid = owner(user)
        for name in ('pending', 'auth'):
            raw = store.ai_state(uid, name)
            replacement = cipher.encrypt({'disconnected': True, 'revision': uuid.uuid4().hex}) if name == 'auth' else None
            if not store.set_ai_state(uid, name, replacement, raw):
                raise HTTPException(409, 'Codex connection is busy; retry')
        return Response(status_code=204)
