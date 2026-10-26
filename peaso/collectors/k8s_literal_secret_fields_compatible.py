"""Existing selected-literal kind with bounded workload field extraction."""
from types import FunctionType

from peaso.collectors import k8s_literal_secret_indicators as base
from peaso.collectors import k8s_selected_metadata_secret_indicators_20261020 as metadata
from peaso.collectors.k8s_selected_log_sample_secret_indicators import private_native_logs, _wire_debug_enabled

KIND = base.KIND
CHECK = base.CHECK
OPTION = base.OPTION
MARKER = base.MARKER
SCHEMA = base.SCHEMA
NATIVE_KINDS = base.NATIVE_KINDS
Incomplete = base.Incomplete


def _mapping(parent, field, code):
    value = parent.get(field, {})
    if not isinstance(value, dict):
        raise Incomplete(code)
    return value


def _sequence(parent, field, code):
    value = parent.get(field, [])
    if not isinstance(value, list) or len(value) > base.MAX_LITERALS:
        raise Incomplete(code)
    return value


def env_reference_count(document, target):
    """Count env valueFrom and envFrom references exactly as the base reader does.

    Only used after the base reader validated every field and stopped solely
    because no literal was present, so its own count was not returned.
    """
    spec = document
    for field in base.NATIVE_KINDS[target['kind']][2]:
        spec = spec[field]
    total = 0
    for group in ('containers', 'initContainers', 'ephemeralContainers'):
        for container in spec.get(group, []):
            total += sum('valueFrom' in entry for entry in container.get('env', []))
            total += len(container.get('envFrom', []))
    return total


def _extract(document, target):
    if target['kind'] == 'ConfigMap':
        return base._extract(document, target)
    # The predecessor validates exact native identity and every old supported
    # field before this reader accepts an object. Its sole no-literals outcome
    # occurs after validation and can be covered by new fields alone.
    try:
        original, uid, version, old_count, references = base._extract(document, target)
    except Incomplete as exc:
        if str(exc) != 'no_nonempty_supported_literals':
            raise
        meta = document['metadata']
        uid, version, old_count = meta['uid'], meta['resourceVersion'], 0
        references = env_reference_count(document, target)
        original = '\n'.join((target['cluster_id'], meta['namespace'], meta['name'], uid, version)).encode()
    values = []
    count = 0

    def add(value, code='unsupported_workload_literal'):
        nonlocal count
        if not isinstance(value, str) or '\x00' in value or len(value.encode('utf-8')) > base.MAX_VALUE:
            raise Incomplete(code)
        values.append(value)
        if value:
            count += 1
        if count + old_count > base.MAX_LITERALS:
            raise Incomplete('literal_count_limit')

    def annotations(meta):
        for field in ('labels', 'annotations'):
            mapping = _mapping(meta, field, 'malformed_template_metadata')
            for key, value in sorted(mapping.items(), key=lambda item: str(item[0])):
                if (not metadata._key(key) or not isinstance(value, str) or '\x00' in value
                        or len(value.encode('utf-8')) > base.MAX_VALUE
                        or (field == 'labels' and value and not metadata._NAME.fullmatch(value))):
                    raise Incomplete('unsupported_template_metadata')
                add(key)
                add(value)

    def http_get(action):
        if 'httpGet' not in action:
            return
        get = _mapping(action, 'httpGet', 'malformed_http_get')
        if set(get) - {'path', 'port', 'host', 'scheme', 'httpHeaders'}:
            raise Incomplete('unsupported_http_get_shape')
        for header in _sequence(get, 'httpHeaders', 'malformed_http_headers'):
            if (not isinstance(header, dict) or not isinstance(header.get('name'), str)
                    or not header['name'] or 'value' not in header
                    or set(header) - {'name', 'value'}):
                raise Incomplete('malformed_http_header')
            add(header['name'])
            add(header['value'])

    def exec_command(action):
        if 'exec' not in action:
            return
        command = _mapping(action, 'exec', 'malformed_exec')
        if 'command' not in command:
            raise Incomplete('missing_exec_command')
        if set(command) - {'command'}:
            raise Incomplete('unsupported_exec_shape')
        for part in _sequence(command, 'command', 'malformed_exec_command'):
            add(part)

    def handler(action, *, lifecycle=False):
        supported = ('exec', 'httpGet')
        known = supported + (('tcpSocket', 'sleep') if lifecycle else ('tcpSocket', 'grpc'))
        allowed = set(known) if lifecycle else set(known) | {
            'initialDelaySeconds', 'timeoutSeconds', 'periodSeconds',
            'successThreshold', 'failureThreshold', 'terminationGracePeriodSeconds'}
        present = [name for name in known if name in action]
        if set(action) - allowed or len(present) != 1 or present[0] not in supported:
            raise Incomplete('unsupported_handler_shape')
        http_get(action)
        exec_command(action)

    template = document
    if target['kind'] != 'Pod':
        path = base.NATIVE_KINDS[target['kind']][2][:-1]
        for field in path:
            template = _mapping(template, field, 'malformed_template_path')
        annotations(_mapping(template, 'metadata', 'malformed_template_metadata'))
    else:
        annotations(document['metadata'])
    spec = template.get('spec')
    if not isinstance(spec, dict):
        raise Incomplete('malformed_podspec_path')
    for field in ('containers', 'initContainers', 'ephemeralContainers'):
        for container in _sequence(spec, field, 'malformed_containers'):
            if not isinstance(container, dict):
                raise Incomplete('malformed_container_identity')
            for probe_name in ('livenessProbe', 'readinessProbe', 'startupProbe'):
                if probe_name in container:
                    probe = _mapping(container, probe_name, 'malformed_probe')
                    handler(probe)
            if 'lifecycle' in container:
                lifecycle = _mapping(container, 'lifecycle', 'malformed_lifecycle')
                for hook_name in ('postStart', 'preStop'):
                    if hook_name in lifecycle:
                        hook = _mapping(lifecycle, hook_name, 'malformed_lifecycle_hook')
                        handler(hook, lifecycle=True)
    if not count and not old_count:
        raise Incomplete('no_nonempty_supported_literals')
    payload = original + (b'\n' if values else b'') + '\n'.join(values).encode('utf-8')
    if len(payload) > base.MAX_CONTENT:
        raise Incomplete('literal_byte_limit')
    return payload, uid, version, count + old_count, references


_GLOBALS = {**vars(base), '__name__': __name__, 'KIND': KIND, 'CHECK': CHECK,
    'OPTION': OPTION, 'MARKER': MARKER, 'SCHEMA': SCHEMA,
    'NATIVE_KINDS': NATIVE_KINDS, '_extract': _extract}
for _name in ('enabled', 'selected_targets', 'identity', '_path', '_remaining', '_pairs', '_read', 'collect'):
    _function = getattr(base, _name)
    _GLOBALS[_name] = FunctionType(_function.__code__, _GLOBALS, _name,
        _function.__defaults__, _function.__closure__)
_native_read = _GLOBALS['_read']


def _read(reader, api, target, state):
    client = getattr(getattr(api, 'api', api), 'api_client', None)
    pool = getattr(getattr(client, 'rest_client', None), 'pool_manager', None)
    if _wire_debug_enabled(getattr(pool, 'pool', None)):
        raise Incomplete('native_wire_debug_enabled')
    return _native_read(reader, api, target, state)


_GLOBALS['_read'] = _read
enabled = _GLOBALS['enabled']
selected_targets = _GLOBALS['selected_targets']
identity = _GLOBALS['identity']
_path = _GLOBALS['_path']


# The copied functions above resolve limits from _GLOBALS, a snapshot of the
# base module taken at import. Re-read them from the base module on every
# collection so there is one source of limits for every read path.
LIMITS = ('MAX_WIRE', 'MAX_CONTENT', 'MAX_VALUE', 'MAX_TOTAL', 'MAX_SECONDS',
    'MAX_LITERALS', 'MAX_LEAKS', 'MAX_LOCATIONS')


def sync_limits(*namespaces):
    for namespace in (_GLOBALS, *namespaces):
        for name in LIMITS:
            namespace[name] = getattr(base, name)


def collect(reader, api, options, scopes, cluster):
    sync_limits()
    if enabled(options):
        with private_native_logs():
            return _GLOBALS['collect'](reader, api, options, scopes, cluster)
    return _GLOBALS['collect'](reader, api, options, scopes, cluster)


redact_output = base.redact_output
