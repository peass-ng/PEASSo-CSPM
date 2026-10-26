"""Bounded ConfigMap association for the existing selected literal reader.

Proposal only: the installed predicate has no ConfigMap receipt vocabulary yet.
"""
import base64
from contextvars import ContextVar
import hashlib
import json
import re
import time
from types import FunctionType
from urllib.parse import urlsplit

from peaso.collectors import k8s_literal_secret_fields_compatible as previous
from peaso.collectors import k8s_literal_secret_indicators as base
from peaso.collectors.k8s_selected_log_sample_secret_indicators import private_native_logs, _wire_debug_enabled
from peaso.secret_scanning import _fingerprint, _trufflehog

KIND, CHECK, OPTION, MARKER, SCHEMA = (base.KIND, base.CHECK, base.OPTION, base.MARKER, base.SCHEMA)
NATIVE_KINDS = base.NATIVE_KINDS
Incomplete = base.Incomplete
MAX_CONFIGMAPS = 6  # Two workload reads plus twelve ConfigMap reads fit the 16-call cap.
MAX_REFERENCES = 64
_KEY = re.compile(r'[A-Za-z0-9._-]{1,253}\Z')


def _seal(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        allow_nan=False).encode('utf-8')).hexdigest()


def _opaque(value):
    return _fingerprint(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False))


def _scope_binding(scope):
    # Namespace scope is already public in the snapshot.
    return hashlib.sha256(scope.encode('utf-8')).hexdigest()


class AssociatedDoc(dict):
    __slots__ = ('associations',)


def _map(value, code):
    if not isinstance(value, dict):
        raise Incomplete(code)
    return value


def _seq(value, code, limit=None):
    if not isinstance(value, list) or len(value) > (base.MAX_LITERALS if limit is None else limit):
        raise Incomplete(code)
    return value


def _name(value):
    return (isinstance(value, str) and base._NAME.fullmatch(value)
        and all(base._NAMESPACE.fullmatch(part) for part in value.split('.')))


def _reference(value, *, keyed=False, items=False):
    ref = _map(value, 'malformed_configmap_reference')
    allowed = {'name', 'optional'} | ({'key'} if keyed else set()) | ({'items', 'defaultMode'} if items else set())
    if set(ref) - allowed or not _name(ref.get('name')) or ('optional' in ref and type(ref['optional']) is not bool):
        raise Incomplete('malformed_configmap_reference')
    keys = None
    if keyed:
        if not isinstance(ref.get('key'), str) or not _KEY.fullmatch(ref['key']):
            raise Incomplete('malformed_configmap_key')
        keys = (ref['key'],)
    if items and 'items' in ref:
        entries = _seq(ref['items'], 'malformed_configmap_items')
        if len(entries) != len({e.get('key') for e in entries if isinstance(e, dict)}):
            raise Incomplete('duplicate_configmap_key')
        found = []
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) - {'key', 'path', 'mode'}
                    or not isinstance(entry.get('key'), str) or not _KEY.fullmatch(entry['key'])
                    or not isinstance(entry.get('path'), str) or not entry['path']):
                raise Incomplete('malformed_configmap_items')
            found.append(entry['key'])
        keys = tuple(found)
    return ref['name'], keys, ref.get('optional') is True


def _plan(document, target):
    if target['kind'] == 'ConfigMap':
        return ()
    spec = document
    for field in base.NATIVE_KINDS[target['kind']][2]:
        spec = _map(spec, 'malformed_podspec_path').get(field)
    spec = _map(spec, 'malformed_podspec_path')
    refs = []
    for group in ('containers', 'initContainers', 'ephemeralContainers'):
        for container in _seq(spec.get(group, []), 'malformed_containers', 128):
            container = _map(container, 'malformed_container_identity')
            for entry in _seq(container.get('envFrom', []), 'malformed_environment'):
                entry = _map(entry, 'malformed_environment')
                if 'configMapRef' in entry:
                    refs.append((*_reference(entry['configMapRef']), 'env'))
            for entry in _seq(container.get('env', []), 'malformed_environment'):
                entry = _map(entry, 'malformed_environment')
                source = entry.get('valueFrom')
                if source is not None:
                    source = _map(source, 'malformed_environment')
                    if 'configMapKeyRef' in source:
                        refs.append((*_reference(source['configMapKeyRef'], keyed=True), 'env'))
    seen_volumes = set()
    for volume in _seq(spec.get('volumes', []), 'malformed_volumes'):
        volume = _map(volume, 'malformed_volume')
        name = volume.get('name')
        if not _name(name) or name in seen_volumes:
            raise Incomplete('duplicate_or_malformed_volume')
        seen_volumes.add(name)
        if 'configMap' in volume:
            refs.append((*_reference(volume['configMap'], items=True), 'volume'))
        if 'projected' in volume:
            projection = _map(volume['projected'], 'malformed_projection')
            for source in _seq(projection.get('sources'), 'malformed_projection'):
                source = _map(source, 'malformed_projection')
                if 'configMap' in source:
                    refs.append((*_reference(source['configMap'], items=True), 'volume'))
    if len(refs) > MAX_REFERENCES or len({ref[0] for ref in refs}) > MAX_CONFIGMAPS:
        raise Incomplete('configmap_reference_limit')
    return tuple(sorted(refs, key=lambda item: (item[0], item[3], item[1] or (), item[2])))


def _cm_target(workload, name):
    return {**workload, 'kind': 'ConfigMap', 'name': name}


def _read_cm(reader, api, target, state, *, optional):
    """Use predecessor GET; optional 404 needs a distinct bounded status path."""
    if not optional:
        return previous._read(reader, api, target, state)
    from peaso.collectors.k8s import _BoundedPool
    client = getattr(getattr(api, 'api', api), 'api_client', None)
    pool = getattr(getattr(client, 'rest_client', None), 'pool_manager', None)
    host = getattr(getattr(client, 'configuration', None), 'host', None)
    if _wire_debug_enabled(getattr(pool, 'pool', None)):
        raise Incomplete('native_wire_debug_enabled')
    if (not isinstance(pool, _BoundedPool) or not pool.server or not isinstance(host, str)
            or urlsplit(host) != pool.server or not callable(getattr(client, 'update_params_for_auth', None))):
        raise Incomplete('bounded_native_transport_required')
    path = previous._path(target)
    if path not in pool.literal_paths:
        raise Incomplete('unselected_native_path')
    headers = dict(getattr(client, 'default_headers', {}) or {})
    headers.update({'Accept': 'application/json', 'Accept-Encoding': 'identity'})
    query = []
    client.update_params_for_auth(headers, query, ['BearerToken'])
    if query:
        raise Incomplete('query_auth_unsupported')
    timeout = base._remaining(reader, state)
    response = None
    try:
        def request():
            if state['calls'] >= 16:
                raise Incomplete('native_call_limit')
            state['calls'] += 1
            try:
                return pool.request('GET', host.rstrip('/') + path, headers=headers,
                    preload_content=False, decode_content=False, timeout=timeout)
            except Exception:
                raise Incomplete('native_transport_unavailable') from None
        response = reader.call(request)
        if response.status == 404:
            return None, 0
        if response.status != 200:
            raise Incomplete('native_get_denied' if response.status in (401, 403) else 'native_get_unavailable')
        if (response.headers.get('Content-Encoding', 'identity') != 'identity'
                or response.headers.get('Content-Type', '').split(';', 1)[0].lower() != 'application/json'):
            raise Incomplete('unsupported_native_response')
        length = response.headers.get('Content-Length')
        if length is not None and (not isinstance(length, str) or not length.isdecimal()
                or not 1 <= int(length) <= base.MAX_WIRE):
            raise Incomplete('native_byte_limit')
        chunks, count = [], 0
        while True:
            base._remaining(reader, state)
            chunk = response.read(min(16384, base.MAX_WIRE + 1 - count))
            if not isinstance(chunk, bytes):
                raise Incomplete('malformed_native_stream')
            if not chunk:
                break
            count += len(chunk)
            state['bytes'] += len(chunk)
            if count > base.MAX_WIRE or state['bytes'] > base.MAX_TOTAL:
                raise Incomplete('native_byte_limit')
            chunks.append(chunk)
        if not count or (length is not None and count != int(length)):
            raise Incomplete('truncated_native_response')
        document = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=base._pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('non_json_number')))
        if not isinstance(document, dict):
            raise Incomplete('malformed_native_response')
        return document, count
    finally:
        if response is not None:
            response.close()
            release = getattr(response, 'release_conn', None)
            if callable(release):
                release()


def _read(reader, api, target, state):
    document, workload_bytes = previous._read(reader, api, target, state)
    if target['kind'] == 'ConfigMap':
        return document, workload_bytes
    if type(document) is not dict:
        raise Incomplete('malformed_native_response')
    try:
        previous._extract(document, target)
    except Incomplete as exc:
        if str(exc) != 'no_nonempty_supported_literals':
            raise
    plan = _plan(document, target)
    by_name = {name: [] for name, _, _, _ in plan}
    for entry in plan:
        by_name[entry[0]].append(entry)
    client = getattr(getattr(api, 'api', api), 'api_client', None)
    pool = getattr(getattr(client, 'rest_client', None), 'pool_manager', None)
    from peaso.collectors.k8s import _BoundedPool
    if by_name and not isinstance(pool, _BoundedPool):
        raise Incomplete('bounded_native_transport_required')
    maps = []
    for name in sorted(by_name):
        cm_target = _cm_target(target, name)
        path = previous._path(cm_target)
        allowed = pool.literal_paths
        try:
            pool.literal_paths = allowed | {path}
            cm, count = _read_cm(reader, api, cm_target, state,
                optional=all(ref[2] for ref in by_name[name]))
        finally:
            pool.literal_paths = allowed
        maps.append((name, cm, count))
    bound = AssociatedDoc(document)
    bound.associations = (plan, tuple(maps))
    if plan:
        ident = identity(target)
        phases = reader._configmap_association_phases.setdefault(ident, [])
        ordinal = len(phases) + 1
        if ordinal > 2:
            raise Incomplete('association_read_limit')
        meta = document['metadata']
        plan_binding = _opaque(plan)
        proof_maps = []
        for name, cm, count in maps:
            references = [ref for ref in plan if ref[0] == name]
            cm_target = _cm_target(target, name)
            if cm is None:
                selected_keys = ()
                uid_binding = version_binding = None
            else:
                projected, _ = _project(cm, cm_target, references)
                selected_keys = tuple(projected[3::2])
                uid_binding = _fingerprint(cm['metadata']['uid'])
                version_binding = _fingerprint(cm['metadata']['resourceVersion'])
            proof_maps.append({'map_binding': _opaque(cm_target),
                'path_binding': _fingerprint(previous._path(cm_target)),
                'selection_binding': _opaque((references, selected_keys)),
                'optional': all(ref[2] for ref in references),
                'status': 404 if cm is None else 200, 'bytes': count,
                'uid_binding': uid_binding, 'version_binding': version_binding})
        phases.append({'ordinal': ordinal, 'plan_binding': plan_binding,
            'workload_uid_binding': _fingerprint(meta['uid']),
            'workload_version_binding': _fingerprint(meta['resourceVersion']),
            'maps': proof_maps})
    return bound, workload_bytes


def _project(cm, target, references):
    meta = cm.get('metadata')
    if (cm.get('apiVersion') != 'v1' or cm.get('kind') != 'ConfigMap'
            or any(k in cm for k in ('items', 'continue', 'partial', '_partial', '_coverage', 'hasMore'))
            or not isinstance(meta, dict) or meta.get('name') != target['name']
            or any(k in meta for k in ('continue', 'remainingItemCount', '_partial', '_coverage'))
            or meta.get('namespace') != target['namespace'] or meta.get('deletionTimestamp') is not None
            or any(not isinstance(meta.get(k), str) or not 1 <= len(meta[k]) <= 253
                or any(ord(c) < 33 or ord(c) > 126 for c in meta[k]) for k in ('uid', 'resourceVersion'))):
        raise Incomplete('configmap_identity_unresolved')
    data, binary = cm.get('data', {}), cm.get('binaryData', {})
    if not isinstance(data, dict) or not isinstance(binary, dict) or set(data) & set(binary):
        raise Incomplete('malformed_configmap')
    if len(data) + len(binary) > base.MAX_LITERALS:
        raise Incomplete('configmap_key_limit')
    if any(not isinstance(k, str) or not _KEY.fullmatch(k) for k in (*data, *binary)):
        raise Incomplete('malformed_configmap_key')
    values = [target['name'], meta['uid'], meta['resourceVersion']]
    selected = set()
    for _, keys, optional, mode in references:
        source = data if mode == 'env' else {**data, **binary}
        needed = source.keys() if keys is None else keys
        for key in needed:
            if key not in source:
                if optional:
                    continue
                raise Incomplete('required_configmap_key_missing')
            selected.add(key)
    if len(selected) > base.MAX_LITERALS:
        raise Incomplete('configmap_key_limit')
    for key in sorted(selected):
        value = data[key] if key in data else binary[key]
        if key in binary:
            if not isinstance(value, str) or len(value) > base.MAX_VALUE * 2:
                raise Incomplete('unsupported_binary_literal')
            try:
                value = base64.b64decode(value, validate=True).decode('utf-8')
            except (ValueError, UnicodeError):
                raise Incomplete('unsupported_binary_literal') from None
        if not isinstance(value, str) or '\x00' in value or len(value.encode('utf-8')) > base.MAX_VALUE:
            raise Incomplete('unsupported_configmap_literal')
        values.extend((key, value))
    return values, len(selected)


def _extract(document, target):
    if target['kind'] == 'ConfigMap':
        return previous._extract(document, target)
    try:
        payload, uid, version, count, references = previous._extract(document, target)
    except Incomplete as exc:
        if str(exc) != 'no_nonempty_supported_literals':
            raise
        meta = document['metadata']
        uid, version, count, references = meta['uid'], meta['resourceVersion'], 0, 0
        payload = '\n'.join((target['cluster_id'], meta['namespace'], meta['name'], uid, version)).encode()
    plan, maps = document.associations
    if plan != _plan(document, target):
        raise Incomplete('configmap_plan_changed')
    if [name for name, _, _ in maps] != sorted({ref[0] for ref in plan}):
        raise Incomplete('association_identity_unresolved')
    additions = []
    for name, cm, _ in maps:
        associated = [ref for ref in plan if ref[0] == name]
        if cm is None:
            if not all(ref[2] for ref in associated):
                raise Incomplete('required_configmap_missing')
            values, added = [name, 'optional_configmap_absent'], 0
        else:
            values, added = _project(cm, _cm_target(target, name), associated)
        additions.extend(values)
        count += added
        if count > base.MAX_LITERALS:
            raise Incomplete('literal_count_limit')
    if not count:
        raise Incomplete('no_nonempty_supported_literals')
    combined = payload + (b'\n' if additions else b'') + '\n'.join(additions).encode('utf-8')
    if len(combined) > base.MAX_CONTENT:
        raise Incomplete('literal_byte_limit')
    return combined, uid, version, count, references + len(plan)


_GLOBALS = {**previous._GLOBALS, '__name__': __name__, '_extract': _extract, '_read': _read}
_SCAN_DEADLINE = ContextVar('k8s_selected_literal_scan_deadline', default=None)
_SOURCE_SCAN_CONTENT = _GLOBALS['scan_content']


def _scan_selected_content(payload, path, *, timeout, **kwargs):
    """Give the two pinned detectors CPU time inside the existing collection deadline."""
    deadline = _SCAN_DEADLINE.get()
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('selected literal collection deadline')
        timeout = min(15, remaining / 2)
    return _SOURCE_SCAN_CONTENT(payload, path, timeout=timeout, **kwargs)


_GLOBALS['scan_content'] = _scan_selected_content
_source_collect = previous._GLOBALS['collect']
_GLOBALS['collect'] = FunctionType(_source_collect.__code__, _GLOBALS, 'collect',
    _source_collect.__defaults__, _source_collect.__closure__)
enabled, selected_targets, identity, _path = (previous.enabled, previous.selected_targets,
    previous.identity, previous._path)


def collect(reader, api, options, scopes, cluster):
    previous.sync_limits(_GLOBALS)
    reader._configmap_association_phases = {}
    deadline_token = _SCAN_DEADLINE.set(time.monotonic() + base.MAX_SECONDS)
    try:
        if enabled(options):
            # The pinned 5-second version probe is tight on a cold 1-vCPU
            # worker. Run it once before Kingfisher starts on another thread;
            # a failed probe is retried by the normal scanner and stays UNKNOWN.
            try:
                _trufflehog()
            except Exception:
                pass
            with private_native_logs():
                result = _GLOBALS['collect'](reader, api, options, scopes, cluster)
        else:
            result = _GLOBALS['collect'](reader, api, options, scopes, cluster)
        metadata, matches = result
        receipts = []
        for collection in reader.collections:
            if collection.get('type') != KIND:
                continue
            for item in collection.get('items', []):
                phases = reader._configmap_association_phases.get(item.get('id'), [])
                marker = item.get(MARKER, {})
                if not phases or not marker.get('parts'):
                    continue
                if (len(phases) != 2 or phases[0]['plan_binding'] != phases[1]['plan_binding']
                        or phases[0]['workload_uid_binding'] != marker.get('uid_binding')
                        or phases[1]['workload_uid_binding'] != marker.get('uid_binding')
                        or phases[0]['workload_version_binding'] != marker.get('version_binding')
                        or phases[1]['workload_version_binding'] != marker.get('version_binding')):
                    collection['status'] = 'partial'
                    collection['error'] = {'code': 'configmap_proof_incomplete'}
                    continue
                if (not 1 <= len(phases[0]['maps']) <= MAX_CONFIGMAPS
                        or len(phases[0]['maps']) != len(phases[1]['maps'])):
                    collection['status'] = 'partial'
                    collection['error'] = {'code': 'configmap_proof_incomplete'}
                    continue
                maps = []
                for first, second in zip(phases[0]['maps'], phases[1]['maps']):
                    if ({k: v for k, v in first.items() if k != 'bytes'}
                            != {k: v for k, v in second.items() if k != 'bytes'}
                            or first['status'] not in (200, 404)
                            or (first['status'] == 404 and not first['optional'])):
                        collection['status'] = 'partial'
                        collection['error'] = {'code': 'configmap_proof_incomplete'}
                        break
                    refs = []
                    for ordinal, phase in enumerate(phases, 1):
                        proof = phase['maps'][len(maps)]
                        receipt = {'id': 'k8s-configmap-read-' + str(len(receipts) + 1),
                            'identity': item['id'], 'scope_binding': _scope_binding(collection['scope']),
                            'cluster_binding': marker['cluster_binding'],
                            'workload_uid_binding': marker['uid_binding'],
                            'workload_version_binding': marker['version_binding'],
                            'plan_binding': phase['plan_binding'], 'map_binding': proof['map_binding'],
                            'path_binding': proof['path_binding'], 'selection_binding': proof['selection_binding'],
                            'optional': proof['optional'], 'method': 'GET', 'status': proof['status'],
                            'bytes': proof['bytes'], 'uid_binding': proof['uid_binding'],
                            'version_binding': proof['version_binding'], 'ordinal': ordinal}
                        receipt['seal'] = _seal(receipt)
                        receipts.append(receipt)
                        refs.append(receipt['id'])
                    maps.append({'map_binding': first['map_binding'], 'path_binding': first['path_binding'],
                        'selection_binding': first['selection_binding'], 'optional': first['optional'],
                        'requests': refs})
                else:
                    association = {'schema': 'k8s-selected-configmap-association-v1',
                        'plan_binding': phases[0]['plan_binding'], 'maps': maps}
                    association['seal'] = _seal({'identity': item['id'], 'uid_binding': marker['uid_binding'],
                        'version_binding': marker['version_binding'],
                        'cluster_binding': marker['cluster_binding'], 'scope': marker['scope'],
                        'literal_count': marker['literal_count'],
                        'reference_count': marker['reference_count'],
                        'source_requests': marker['source_requests'], **association})
                    marker['association'] = association
        metadata[KIND + '_configmap_receipts'] = receipts
        return metadata, matches
    finally:
        _SCAN_DEADLINE.reset(deadline_token)
        reader._configmap_association_phases = {}


redact_output = previous.redact_output
