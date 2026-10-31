"""Unregistered, exact selected Function declaration reader; no detectors.

Only fixed typed setting states leave the ephemeral HTTP projection. Production
hooks/options/admission remain a separate integration decision.
"""
from contextlib import contextmanager
from copy import deepcopy
import http.client
import json
import logging
import re
import threading
import time

from peaso.secret_scanning import _fingerprint
from .azure_app_settings_secret_indicators import _RESOURCE, _SCOPE, _pairs, _remaining

KIND = 'azure_selected_function_settings_declaration'
TELEMETRY = 'azure.review.function.application_insights_setting_declared'
RUNTIME = 'azure.review.function.runtime_major4_update_channel_declared'
CHECKS = (TELEMETRY, RUNTIME)
OPTION = 'selected_azure_function_settings'
MARKER = 'FunctionSettingsDeclaration'
SCHEMA = 'azure-selected-function-declarations-v1'
ARM = 'https://management.azure.com'
HOST = 'management.azure.com'
SITE_VERSION = '2025-03-01'
SUB_VERSION = '2022-12-01'
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', re.I)
MAX_TARGETS, MAX_CALLS = 4, 12
MAX_WIRE, MAX_TOTAL = 2 * 1024 * 1024, 8 * 1024 * 1024
MAX_SECONDS, MAX_SETTINGS, MAX_VALUE, MAX_CONTENT = 60, 512, 65536, 262144
CHANNELS = frozenset(('major4_automatic', 'legacy_automatic', 'major4_pin', 'legacy_pin', 'absent', 'reference', 'masked', 'unresolved'))
PRESENCE = frozenset(('literal', 'absent', 'empty', 'reference', 'masked'))


class Incomplete(ValueError):
    """Fixed non-sensitive errors only."""


def identity(target):
    return KIND + ':' + _fingerprint(target.casefold())


def preflight(options, scopes, named_checks):
    """Credential-free gating; kinds/frameworks never authorize settings reads."""
    if not isinstance(options, dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_selection')
    named = [c for c in named_checks if c in CHECKS] if isinstance(named_checks, list) and all(isinstance(c, str) for c in named_checks) and '*' not in named_checks else []
    authorized = bool(options.get('content_secret_scans') is True and named)
    if OPTION not in options and not authorized:
        return [], []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not _SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes}) != len(scopes)
            or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
        raise Incomplete('invalid_selection')
    seen = set()
    for target in targets:
        match = _RESOURCE.fullmatch(target) if isinstance(target, str) and len(target) <= 512 else None
        if (not match or match[4] is not None or '/.' in target
                or match[1].casefold() not in {s.casefold() for s in scopes}
                or target.casefold() in seen):
            raise Incomplete('invalid_selection')
        seen.add(target.casefold())
    return (list(targets), list(dict.fromkeys(named))) if authorized else ([], [])


@contextmanager
def private_native_logs():
    """Suppress this thread's SDK/auth HTTP DEBUG records; restore all filters."""
    owner = threading.get_ident()
    prefixes = ('azure', 'msal', 'msal_extensions', 'urllib3', 'requests', 'http.client')
    def native(name):
        return any(name == p or name.startswith(p + '.') for p in prefixes)
    for name in ('azure.identity', 'azure.core.pipeline.policies.http_logging_policy', 'msal', 'urllib3.connectionpool'):
        logging.getLogger(name)
    loggers = [logging.getLogger(n) for n in list(logging.root.manager.loggerDict) if native(n)]
    handlers = set(logging.getLogger().handlers)
    for logger in loggers:
        handlers.update(logger.handlers)
    class Guard(logging.Filter):
        def filter(self, record):
            return threading.get_ident() != owner or not native(record.name)
    guard = Guard()
    for obj in [*loggers, *handlers]:
        obj.addFilter(guard)
    try:
        yield
    finally:
        for obj in [*loggers, *handlers]:
            obj.removeFilter(guard)


def _presence(value):
    if value is None:
        return 'absent'
    if not value.strip():
        return 'empty'
    if value.lstrip().casefold().startswith('@microsoft.keyvault'):
        return 'reference'
    if value.strip().casefold() in ('[redacted]', '<redacted>', 'redacted') or set(value.strip()) <= {'*'}:
        return 'masked'
    return 'literal'


def _settings(data, target):
    """Whitelist states, never raw runtime text, keys, values or references."""
    if (not isinstance(data.get('id'), str) or data['id'].casefold() != (target + '/config/appsettings').casefold()
            or str(data.get('type', '')).casefold() != 'microsoft.web/sites/config'
            or data.get('name') != 'appsettings' or not isinstance(data.get('properties'), dict)
            or len(data['properties']) > MAX_SETTINGS):
        raise Incomplete('settings_unbound')
    seen, size = set(), 0
    for key, value in data['properties'].items():
        if (not isinstance(key, str) or not 1 <= len(key) <= 512 or key.casefold() in seen
                or not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in key)):
            raise Incomplete('settings_malformed')
        seen.add(key.casefold())
        raw = value.encode('utf-8', errors='strict')
        if len(raw) > MAX_VALUE or any(ord(c) < 32 and c not in '\r\n\t' or ord(c) == 127 for c in value):
            raise Incomplete('settings_malformed')
        size += len(raw)
        if size > MAX_CONTENT:
            raise Incomplete('settings_limit')
    props = data['properties']
    keys = ('APPLICATIONINSIGHTS_CONNECTION_STRING', 'APPINSIGHTS_INSTRUMENTATIONKEY', 'FUNCTIONS_EXTENSION_VERSION')
    if any(k.casefold() == expected.casefold() and k != expected for k in props for expected in keys):
        raise Incomplete('setting_alias')
    cs, ik, version = (props.get(k) for k in keys)
    state = _presence(version)
    channel = state if state in ('absent', 'reference', 'masked') else 'absent' if state == 'empty' else 'unresolved'
    if state == 'literal':
        if version == '~4': channel = 'major4_automatic'
        elif version in ('~1', '~2', '~3'): channel = 'legacy_automatic'
        elif re.fullmatch(r'4\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})', version): channel = 'major4_pin'
        elif re.fullmatch(r'[1-3]\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})', version): channel = 'legacy_pin'
    return {'connection_string': _presence(cs), 'instrumentation_key': _presence(ik),
        'runtime_setting': state, 'channel': channel}


def _site(data, target):
    if (not isinstance(data.get('id'), str) or data['id'].casefold() != target.casefold()
            or str(data.get('type', '')).casefold() != 'microsoft.web/sites'
            or not isinstance(data.get('name'), str) or data['name'].casefold() != target.rsplit('/', 1)[1].casefold()
            or not isinstance(data.get('properties'), dict) or not isinstance(data.get('kind'), str)):
        raise Incomplete('site_unbound')
    kinds = [v.strip().casefold() for v in data['kind'].split(',')]
    if not kinds or any(not re.fullmatch('[a-z0-9-]+', k) for k in kinds) or len(set(kinds)) != len(kinds):
        raise Incomplete('site_kind')
    if 'functionapp' not in kinds:
        return {'hosting': 'not_function'}
    if 'workflowapp' in kinds:
        return {'hosting': 'not_function'}
    if set(kinds) - {'functionapp', 'linux', 'container'}:
        return {'hosting': 'unsupported'}
    p = data['properties']
    config = p.get('siteConfig')
    flex = p.get('functionAppConfig')
    container = 'container' in kinds
    if config is not None and not isinstance(config, dict):
        raise Incomplete('site_config')
    for key in ('linuxFxVersion', 'windowsFxVersion'):
        value = config.get(key) if isinstance(config, dict) else None
        if value is not None and not isinstance(value, str):
            raise Incomplete('site_config')
        relevant = 'linuxFxVersion' if 'linux' in kinds else 'windowsFxVersion'
        if key == relevant and isinstance(value, str) and value.upper().startswith('DOCKER|'):
            container = True
    if flex is not None:
        if (not isinstance(flex, dict) or not isinstance(flex.get('runtime'), dict)
                or flex['runtime'].get('name') not in ('dotnet-isolated', 'node', 'java', 'powershell', 'python')
                or not isinstance(flex['runtime'].get('version'), str) or not flex['runtime']['version']
                or container):
            raise Incomplete('flex_config')
        return {'hosting': 'flex'}
    if container:
        return {'hosting': 'container'}
    # Missing full native site config cannot rule out a custom image. A null
    # field is not replaced with a synthetic classic-hosting declaration.
    if not isinstance(config, dict) or type(p.get('reserved')) is not bool or ('linux' in kinds) != p['reserved']:
        return {'hosting': 'unresolved'}
    field = 'linuxFxVersion' if p['reserved'] else 'windowsFxVersion'
    if not isinstance(config.get(field), str):
        return {'hosting': 'unresolved'}
    if p['reserved'] and not re.fullmatch(r'(?:PYTHON|NODE|JAVA|DOTNET|DOTNET-ISOLATED|POWERSHELL)\|[A-Za-z0-9._-]+', config[field], re.I):
        return {'hosting': 'unresolved'}
    return {'hosting': 'classic'}


def _read(reader, transport, target, scope, operation, state, receipts):
    """Bound read and native projection execute before the shared reader returns."""
    from .azure import _claims
    match = _RESOURCE.fullmatch(target) if isinstance(target, str) and len(target) <= 512 else None
    if (operation not in ('subscription', 'site', 'settings') or not match or match[4] is not None
            or not isinstance(scope, str) or match[1].casefold() != scope.casefold()
            or '/.' in target):
        raise Incomplete('operation_forbidden')
    _remaining(reader, state)
    if state['calls'] >= MAX_CALLS:
        raise Incomplete('call_limit')
    state['calls'] += 1
    version = SUB_VERSION if operation == 'subscription' else SITE_VERSION
    path = (scope if operation == 'subscription' else target + ('/config/appsettings/list' if operation == 'settings' else '')) + '?api-version=' + version
    method = 'POST' if operation == 'settings' else 'GET'
    receipt = {'id': 'function-declaration-read-' + str(len(receipts) + 1), 'identity': identity(target),
        'scope': scope, 'capture': state['capture'], 'operation': operation, 'method': method,
        'host': HOST, 'api_version': version, 'request_digest': _fingerprint(path), 'status': 'unavailable',
        'bytes': 0, 'tenant_id': None, 'identity_bound': False}
    receipts.append(receipt)
    response = connection = None
    with private_native_logs():
        try:
            token = transport.token(ARM)
            claims = _claims(token)
            tenant = claims.get('tid')
            if (not isinstance(token, str) or not token or any(c in token for c in '\r\n')
                    or not isinstance(tenant, str) or not GUID.fullmatch(tenant)
                    or claims.get('aud') not in (ARM, ARM + '/', 'https://management.core.windows.net/')
                    or str(getattr(transport, 'verified_tenant', '')).casefold() != tenant.casefold()
                    or str(getattr(transport, 'tenant', '')).casefold() != tenant.casefold()
                    or state.get('tenant') not in (None, tenant.casefold())):
                raise Incomplete('tenant_unbound')
            state['tenant'] = tenant.casefold()
            receipt['tenant_id'] = tenant.casefold()
            connection = http.client.HTTPSConnection(HOST, timeout=_remaining(reader, state))
            connection.set_debuglevel(0)
            connection.request(method, path, body=None, headers={'Authorization': 'Bearer ' + token,
                'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Content-Length': '0'})
            del token, claims
            response = connection.getresponse()
            if (type(response.status) is not int or response.status != 200
                    or response.getheader('Content-Encoding') not in (None, '', 'identity')
                    or response.getheader('Location') or response.getheader('Link')
                    or (response.getheader('Content-Type') or '').split(';')[0].strip().casefold() != 'application/json'):
                raise Incomplete('native_unavailable')
            length = response.getheader('Content-Length')
            if length is not None and (not re.fullmatch('[0-9]{1,8}', length) or not 0 < int(length) <= MAX_WIRE):
                raise Incomplete('wire_limit')
            chunks, size = [], 0
            while True:
                timeout = _remaining(reader, state)
                if getattr(connection, 'sock', None) is not None: connection.sock.settimeout(timeout)
                block = response.read(min(16384, MAX_WIRE + 1 - size))
                if not isinstance(block, bytes): raise Incomplete('wire_malformed')
                size += len(block); state['bytes'] += len(block); receipt['bytes'] = size
                if size > MAX_WIRE or state['bytes'] > MAX_TOTAL: raise Incomplete('wire_limit')
                if not block: break
                chunks.append(block)
            if not size or length is not None and int(length) != size: raise Incomplete('wire_partial')
            data = json.loads(b''.join(chunks).decode('utf-8', errors='strict'), object_pairs_hook=_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('json_malformed')))
            if (not isinstance(data, dict) or set(data) & {'error', 'nextLink', 'value', 'continuationToken',
                    '_coverage', 'partial', '_partial', 'hasMore', 'resultTruncated'}):
                raise Incomplete('native_shape')
            if operation == 'subscription':
                if (str(data.get('id', '')).casefold() != scope.casefold()
                        or str(data.get('subscriptionId', '')).casefold() != scope.rsplit('/', 1)[1].casefold()
                        or str(data.get('tenantId', '')).casefold() != state['tenant']
                        or data.get('state') != 'Enabled'):
                    raise Incomplete('subscription_unbound')
                projected = {'subscription_bound': True}
            elif operation == 'site': projected = _site(data, target)
            else: projected = _settings(data, target)
            data.clear(); chunks.clear()
            receipt.update(status='collected', identity_bound=True)
            return projected
        except Exception:
            raise Incomplete('native_read_unavailable') from None
        finally:
            # No raw objects, response errors or locators enter reader state.
            if response is not None:
                try: response.close()
                except Exception: pass
            if connection is not None:
                try: connection.close()
                except Exception: pass


def collect(reader, transport, scopes, wanted, options, *, named_checks,
            credential_context_id=None, customer_context_id=None):
    targets, selected = preflight(options, scopes, named_checks)
    if KIND not in wanted or not targets:
        return
    transport_capture = getattr(transport, 'ai_context_id', None)
    capture = transport_capture if credential_context_id is None else credential_context_id
    if (not isinstance(transport_capture, str) or not re.fullmatch('[0-9a-f]{32}', transport_capture)
            or not isinstance(capture, str) or not re.fullmatch('[0-9a-f]{32}', capture)
            or credential_context_id is not None and customer_context_id != 'scan-local:' + capture
            or credential_context_id is None and customer_context_id is not None):
        raise Incomplete('capture_unavailable')
    metadata = {KIND + '_authorized': True, KIND + '_checks': selected,
        KIND + '_capture': capture, KIND + '_selection': {
            scope: [identity(t) for t in targets if _RESOURCE.fullmatch(t)[1].casefold() == scope.casefold()] for scope in scopes},
        KIND + '_receipts': []}
    reader.function_declaration_metadata = metadata
    state = {'capture': capture, 'tenant': None, 'deadline': time.monotonic() + MAX_SECONDS, 'bytes': 0, 'calls': 0}
    receipts = metadata[KIND + '_receipts']
    for scope in scopes:
        names = [t for t in targets if _RESOURCE.fullmatch(t)[1].casefold() == scope.casefold()]
        if not names: continue
        def fetch(names=names, scope=scope):
            rows = []
            for target in names:
                ident = identity(target); start = len(receipts)
                marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'capture': capture,
                    'complete': False, 'hosting': 'unresolved', 'declarations': None, 'source_requests': []}
                try:
                    reader.call(_read, reader, transport, target, scope, 'subscription', state, receipts)
                    facts = reader.call(_read, reader, transport, target, scope, 'site', state, receipts)
                    marker.update(facts)
                    if facts['hosting'] not in ('not_function', 'unsupported') and (TELEMETRY in selected or facts['hosting'] == 'classic'):
                        marker['declarations'] = reader.call(_read, reader, transport, target, scope, 'settings', state, receipts)
                    marker['complete'] = True
                except Exception:
                    marker.update(complete=False, declarations=None)
                marker['source_requests'] = [r['id'] for r in receipts[start:]]
                rows.append({'id': ident, MARKER: marker, '_provenance': {'scope': scope,
                    'capture': capture, 'tenant_id': state['tenant'], 'source_requests': list(marker['source_requests'])}})
            yield rows
        reader.run([(KIND, scope, 'Microsoft.Web', fetch)])
    metadata[KIND + '_tenant'] = state['tenant']


def final_snapshot(reader, snapshot):
    """Attach only safe facts before the existing matched-value union scrub."""
    from .azure_selected_secret_integration_20261020 import final_snapshot as union_scrub
    from peaso.snapshot import seal
    snapshot.setdefault('metadata', {}).update(deepcopy(getattr(reader, 'function_declaration_metadata', {})))
    safe = seal(union_scrub(reader, snapshot))
    reader.function_declaration_metadata = {key: deepcopy(value) for key, value in safe['metadata'].items()
        if key.startswith(KIND + '_')}
    return safe


def collect_proposal(connector, named_checks, *, credential=None):
    """Unregistered testable entrypoint; future root hooks must preserve gating."""
    from .azure import AzureTransport, _Reader
    from peaso.snapshot import make_snapshot
    options, scopes = connector.get('options', {}), connector.get('scopes', [])
    targets, selected = preflight(options, scopes, named_checks)
    if not targets:
        return make_snapshot('azure', scopes, [], metadata={'collection': 'read-only'})
    reader = _Reader({**options, 'concurrency': 1, 'retries': 0})
    transport = None
    try:
        with private_native_logs():
            try:
                transport = AzureTransport(connector.get('auth', {}), credential=credential)
            except Exception:
                for scope in scopes:
                    reader.unavailable(KIND, scope, 'Microsoft.Web', Incomplete('credential_unavailable'))
        if transport is None:
            return final_snapshot(reader, make_snapshot('azure', scopes, reader.collections, metadata=reader.metadata()))
        collect(reader, transport, scopes, [KIND], options, named_checks=list(selected))
        return final_snapshot(reader, make_snapshot('azure', scopes, reader.collections, metadata=reader.metadata()))
    finally:
        if transport is not None:
            transport.tokens.clear()
            with private_native_logs():
                try: transport.close()
                except Exception: pass
