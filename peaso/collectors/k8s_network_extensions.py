"""Discover installed CNI, load-balancer and service-mesh network resources.

Only reviewed resource plurals are read. Arbitrary CRDs are not requested.
Unserved APIs are absent, denied discovery remains unknown. No workload plugin
payload, embedded TLS material, annotation or free-form CNI argument is kept.
"""
import json
import re

# inventory kind: API group alternatives, plural, namespaced
from pathlib import Path
RESOURCES = json.loads(Path(__file__).with_suffix('.json').read_text())

BY_ENDPOINT = {(group, plural): kind for kind, (groups, plural, ns) in RESOURCES.items() for group in groups}


def endpoint(kind):
    groups, plural, namespaced = RESOURCES[kind]
    return f'/apis/{groups[0]}/v1/{plural}', namespaced


def match(path):
    result = re.fullmatch(r'/apis/([^/]+)/v1(?:/namespaces/[a-z0-9-]+)?/([^/]+)', path)
    return BY_ENDPOINT.get((result[1], result[2])) if result else None


def allowed_path(path):
    """A reviewed extension plural at any served version, as read() negotiates it."""
    result = re.fullmatch(r'/apis/([a-z0-9.-]+)/v[0-9]+(?:(?:alpha|beta)[0-9]+)?'
                          r'(/namespaces/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)?/([a-z0-9]+)', path)
    kind = BY_ENDPOINT.get((result[1], result[3])) if result else None
    return kind is not None and (result[2] is None or RESOURCES[kind][2] is True)


def _configuration(value):
    """Positive native configuration, plus network facts through SDK wrappers."""
    from peaso.analysis.network_services import project_network_data
    from peaso.analysis.network_observations import network_observations
    projected = project_network_data(value)
    facts = network_observations(value, network_context=True)
    if facts:
        projected['NetworkAttributes'] = facts
    return projected


def project(response, kind):
    if not isinstance(response, dict) or not isinstance(response.get('items'), list):
        return {}  # The ordinary list validator records malformed coverage.
    rows = []
    for row in response['items']:
        if not isinstance(row, dict):
            return {}
        spec = row.get('spec', {})
        coverage = {}
        if kind == 'network_attachment_definition':
            config = spec.get('config') if isinstance(spec, dict) else None
            if not isinstance(config, str) or len(config) > 1024 * 1024:
                coverage = {'plugin_configuration': {'status': 'malformed'}}
                spec = {}
            else:
                try:
                    spec = {'config': json.loads(config)}
                    if not isinstance(spec['config'], dict):
                        raise ValueError('non_object_cni_config')
                except (ValueError, TypeError):
                    spec = {}
                    coverage = {'plugin_configuration': {'status': 'malformed'}}
        item = {key: row[key] for key in ('apiVersion', 'kind') if key in row}
        meta = row.get('metadata')
        item['metadata'] = {key: meta[key] for key in ('name', 'namespace', 'uid', 'resourceVersion', 'ownerReferences', 'labels') if key in meta} if isinstance(meta, dict) else {}
        item['spec'] = _configuration(spec)
        if isinstance(row.get('status'), dict):
            item['status'] = _configuration(row['status'])
        if coverage:
            item['_coverage'] = coverage
        rows.append(item)
    return {key: value for key, value in response.items() if key in ('apiVersion', 'kind', 'metadata')} | {'items': rows}


def read(reader, native_call, operation, path, *args, **kwargs):
    from .k8s import K8sReadError
    kind = match(path)
    groups, plural, namespaced = RESOURCES[kind]
    with reader.gateway_discovery_lock:
        cache = getattr(reader, 'network_extension_discovery', None)
        if cache is None:
            doc = native_call(operation, '/apis')
            if not isinstance(doc, dict) or not isinstance(doc.get('groups'), list):
                raise ValueError('malformed network extension discovery')
            cache = {'groups': {g['name']: g for g in doc['groups'] if isinstance(g, dict) and isinstance(g.get('name'), str)}, 'resources': {}}
            reader.network_extension_discovery = cache
        selected = None
        for group in groups:
            if group not in cache['groups']:
                continue
            if group not in cache['resources']:
                discovered = {}
                versions = cache['groups'][group].get('versions', [])
                versions = [v.get('version') for v in versions if isinstance(v, dict) and isinstance(v.get('version'), str)]
                if not versions:
                    raise K8sReadError('network_extension_versions_unavailable')
                # Prefer stable over beta over alpha, while respecting all served versions.
                versions.sort(key=lambda v: ('alpha' not in v and 'beta' not in v, 'alpha' not in v, v), reverse=True)
                for version in versions:
                    if not re.fullmatch(r'v[0-9]+(?:(?:alpha|beta)[0-9]+)?', version):
                        continue
                    resources = native_call(operation, f'/apis/{group}/{version}')
                    if not isinstance(resources, dict) or not isinstance(resources.get('resources'), list):
                        raise ValueError('malformed network extension resource discovery')
                    for resource in resources['resources']:
                        if isinstance(resource, dict) and 'list' in resource.get('verbs', []):
                            discovered.setdefault(resource.get('name'), (version, resource.get('namespaced')))
                cache['resources'][group] = discovered
            if plural in cache['resources'][group]:
                version, actual_namespace = cache['resources'][group][plural]
                if actual_namespace is not namespaced:
                    raise ValueError('network extension scope mismatch')
                selected = group, version
                break
        if selected is None:
            reader.network_extension_absent = getattr(reader, 'network_extension_absent', set()) | {kind}
            return {'items': [], 'metadata': {}, 'kind': 'List'}
    group, version = selected
    original_group = path.split('/')[2]
    target = path.replace(f'/apis/{original_group}/v1/', f'/apis/{group}/{version}/', 1)
    # Native API output is projected before the shared read scheduler keeps it.
    def projected_read(*call_args, **call_kwargs):
        return project(operation(*call_args, **call_kwargs), kind)
    return native_call(projected_read, target, *args, **kwargs)
