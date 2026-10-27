"""Bounded offline scans of documented native GCP literal configurations.

Call on successful raw GET JSON before any application cache or serialization.
Always drop sensitive configuration content; detectors require explicit opt-in
AND an internally selected native kind. External references are never fetched.
"""

from peaso.secret_evidence import scan_with_source
import re
import time
from urllib.parse import urlsplit

from peaso.secret_scanning import scan_content, merge_leaks, redact_matches, prepared_content_batch

MARKER = 'ConfigurationSecretIndicators'
SCHEMA = 'gcp-configuration-literal-secrets-v1'
KINDS = ('instance', 'instance_template', 'project', 'cloudrun_service', 'cloudrun_job', 'cloudbuild_trigger', 'cloudbuild_build')
IDS = {kind: 'gcp.review.' + kind + '.literal_configuration_secret_indicators' for kind in KINDS}
FIELDS = {
    'instance': ['metadata.items[].value'],
    'instance_template': ['properties.metadata.items[].value'],
    'project': ['commonInstanceMetadata.items[].value'],
    'cloudrun_service': ['template.containers[].env[].value', 'template.containers[].args[]', 'template.containers[].command[]'],
    'cloudrun_job': ['template.template.containers[].env[].value', 'template.template.containers[].args[]', 'template.template.containers[].command[]'],
    'cloudbuild_trigger': ['substitutions', 'build.substitutions', 'build.options.env[]', 'build.steps[].env[]', 'build.steps[].script', 'build.steps[].args[]'],
    'cloudbuild_build': ['substitutions', 'options.env[]', 'steps[].env[]', 'steps[].script', 'steps[].args[]'],
}
MAX_RESOURCES = 100
MAX_PARTS = 256
MAX_VALUE_BYTES = 65536
MAX_RESOURCE_BYTES = 262144
MAX_PAGE_BYTES = 1048576
MAX_PAGE_SECONDS = 30
MAX_LEAKS = 256
MAX_LOCATIONS = 512
IDENT = r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}'
LOC = r'[a-z][a-z0-9-]{0,62}'


def request_route(method, url, scope, params=None, body=None):
    parsed = urlsplit(url)
    if (method != 'GET' or body is not None or parsed.scheme != 'https' or parsed.query or parsed.fragment
            or parsed.netloc not in ('compute.googleapis.com', 'run.googleapis.com', 'cloudbuild.googleapis.com')
            or not isinstance(scope, str) or not re.fullmatch(r'projects/' + IDENT, scope)
            or not isinstance(params or {}, dict) or set(params or {}) - {'pageSize', 'pageToken', 'maxResults', 'returnPartialSuccess', 'projectId'}
            or 'projectId' in (params or {}) and params['projectId'] != scope.split('/')[1]):
        raise ValueError('unbound configuration request')
    prefix = re.escape(scope)
    path = parsed.path
    if parsed.netloc == 'compute.googleapis.com':
        if path == '/compute/v1/' + scope:
            return {'kind': 'project', 'scope': scope, 'location': None, 'name': None, 'aggregate': False, 'key': None}
        match = re.fullmatch(r'/compute/v1/' + prefix + r'/(aggregated|zones/' + LOC + r'|regions/' + LOC + r'|global)/(instances|instanceTemplates)(?:/(' + IDENT + r'))?', path)
        if match is None or match[1] == 'aggregated' and match[3] is not None:
            raise ValueError('unsupported Compute read')
        if match[2] == 'instances' and not (match[1] == 'aggregated' or match[1].startswith('zones/')):
            raise ValueError('invalid Compute instance location')
        if match[2] == 'instanceTemplates' and match[1].startswith('zones/'):
            raise ValueError('invalid Compute template location')
        return {'kind': 'instance' if match[2] == 'instances' else 'instance_template', 'scope': scope,
                'location': match[1], 'name': match[3], 'aggregate': match[1] == 'aggregated', 'key': match[2]}
    version = 'v2' if parsed.netloc == 'run.googleapis.com' else 'v1'
    match = re.fullmatch('/' + version + '/' + prefix + r'/locations/(' + LOC + r')/(services|jobs|triggers|builds)(?:/(' + IDENT + r'))?', path)
    if match is None or (parsed.netloc == 'run.googleapis.com') != (match[2] in ('services', 'jobs')):
        raise ValueError('unsupported Run or Build read')
    kind = {'services': 'cloudrun_service', 'jobs': 'cloudrun_job', 'triggers': 'cloudbuild_trigger', 'builds': 'cloudbuild_build'}[match[2]]
    return {'kind': kind, 'scope': scope, 'location': match[1], 'name': match[3], 'aggregate': False, 'key': match[2]}


def _object(row):
    if not isinstance(row, dict) or row.get('_coverage') or row.get('collection_status', 'collected') != 'collected':
        raise ValueError('incomplete native configuration')
    return row


def number_alias(name, route, ident, row):
    """Cloud Build names builds with the project number, not the project id.

    The alias binds only a build whose own projectId names the scanned project.
    """
    return (route['kind'] == 'cloudbuild_build' and isinstance(name, str)
            and row.get('projectId') == route['scope'].split('/')[1]
            and re.fullmatch(r'projects/[1-9][0-9]{0,19}/locations/' + re.escape(route['location'])
                             + '/builds/' + re.escape(ident), name) is not None)


def identity(row, route):
    kind, scope = route['kind'], route['scope']
    _object(row)
    if kind == 'project':
        if row.get('name') != scope.split('/')[1]:
            raise ValueError('Compute project identity mismatch')
        return scope
    if kind in ('instance', 'instance_template'):
        link = row.get('selfLink')
        if not isinstance(link, str):
            raise ValueError('Compute selfLink missing')
        link = re.sub(r'^https://(?:www\.googleapis\.com|compute\.googleapis\.com)/compute/v1/', '', link)
        match = re.fullmatch(re.escape(scope) + r'/(zones/' + LOC + r'|regions/' + LOC + r'|global)/' + route['key'] + r'/(' + IDENT + ')', link)
        if (not match or row.get('name') != match[2] or route['location'] not in ('aggregated', match[1])
                or route['name'] is not None and route['name'] != match[2]):
            raise ValueError('Compute identity differs from request')
        return link
    segment = route['key']
    prefix = scope + '/locations/' + route['location'] + '/' + segment + '/'
    if kind.startswith('cloudrun'):
        name = row.get('name')
        ident = name[len(prefix):] if isinstance(name, str) and name.startswith(prefix) else None
    else:
        ident = row.get('id')
        if not isinstance(ident, str) or not re.fullmatch(IDENT, ident):
            raise ValueError('Cloud Build id missing')
        if kind == 'cloudbuild_build' and row.get('projectId') != scope.split('/')[1]:
            raise ValueError('Cloud Build project mismatch')
        resource_name = row.get('resourceName') if kind == 'cloudbuild_trigger' else row.get('name')
        if resource_name is not None and resource_name != prefix + ident and not number_alias(resource_name, route, ident, row):
            raise ValueError('Cloud Build resource name mismatch')
    if not isinstance(ident, str) or not re.fullmatch(IDENT, ident) or route['name'] is not None and ident != route['name']:
        raise ValueError('Run/Build identity differs from request')
    return prefix + ident


def _parts(row, kind):
    parts, size = [], 0
    def add(label, value):
        nonlocal size
        if not isinstance(value, str) or len(value) > MAX_VALUE_BYTES:
            raise ValueError('invalid or oversized literal')
        encoded = (label + '=' + value + '\n').encode('utf-8')
        if len(value.encode('utf-8')) > MAX_VALUE_BYTES:
            raise ValueError('literal byte bound')
        size += len(encoded)
        if len(parts) >= MAX_PARTS or size > MAX_RESOURCE_BYTES:
            raise ValueError('configuration bound')
        parts.append(encoded)
    def mapping(value, label):
        _object(value)
        if len(value) > MAX_PARTS:
            raise ValueError('pair bound')
        for key, val in sorted(value.items()):
            if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', key):
                raise ValueError('invalid literal name')
            add(label + '.' + key, val)
    def strings(value, label):
        if not isinstance(value, list) or len(value) > MAX_PARTS:
            raise ValueError('literal vector bound')
        for ordinal, val in enumerate(value): add(label + '.' + str(ordinal), val)
    def metadata(value):
        _object(value)
        items = value.get('items', [])
        if not isinstance(items, list) or len(items) > MAX_PARTS:
            raise ValueError('metadata pair bound')
        seen = set()
        for entry in items:
            _object(entry)
            key = entry.get('key')
            if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,127}', key) or key in seen:
                raise ValueError('invalid or duplicate metadata key')
            seen.add(key)
            add('metadata.' + key, entry['value'])
    if kind in ('instance', 'project', 'instance_template'):
        parent = _object(row['properties']) if kind == 'instance_template' else row
        field = 'commonInstanceMetadata' if kind == 'project' else 'metadata'
        metadata(parent[field])
    elif kind.startswith('cloudrun'):
        template = _object(row['template'])
        if kind == 'cloudrun_job': template = _object(template['template'])
        containers = template['containers']
        if not isinstance(containers, list) or not 1 <= len(containers) <= 16:
            raise ValueError('container bound')
        for ordinal, container in enumerate(containers):
            _object(container)
            prefix = 'container.' + str(ordinal)
            env = container.get('env', [])
            if not isinstance(env, list) or len(env) > MAX_PARTS: raise ValueError('environment bound')
            for entry in env:
                _object(entry)
                name = entry.get('name')
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', name):
                    raise ValueError('environment name invalid')
                if 'valueSource' in entry:
                    if 'value' in entry: raise ValueError('ambiguous environment union')
                    ref = _object(_object(entry['valueSource'])['secretKeyRef'])
                    if not all(isinstance(ref.get(k), str) and ref[k] for k in ('secret', 'version')):
                        raise ValueError('invalid secret reference')
                else:
                    # The native EnvVar schema documents omitted literal value as empty.
                    if 'valueFrom' in entry: raise ValueError('unexpected v1 environment union')
                    add(prefix + '.env.' + name, entry.get('value', ''))
            for field in ('args', 'command'): strings(container.get(field, []), prefix + '.' + field)
    else:
        def build(config):
            _object(config)
            mapping(config.get('substitutions', {}), 'substitution')
            options = _object(config.get('options', {}))
            strings(options.get('env', []), 'build.env')
            steps = config['steps']
            if not isinstance(steps, list) or not 1 <= len(steps) <= 64: raise ValueError('build step bound')
            for ordinal, step in enumerate(steps):
                _object(step)
                label = 'step.' + str(ordinal)
                strings(step.get('env', []), label + '.env')
                strings(step.get('args', []), label + '.args')
                if 'script' in step: add(label + '.script', step['script'])
        if kind == 'cloudbuild_trigger':
            if any(row.get(field) for field in ('filename', 'gitFileSource', 'autodetect')):
                raise ValueError('external or ambiguous build template')
            mapping(row.get('substitutions', {}), 'trigger.substitution')
            build(row['build'])  # remote filename/autodetect configurations are not inspected
        else:
            build(row)
    return b''.join(parts) or b'\n', len(parts)


def _scrub(value):
    """Remove literal payloads even with detection disabled, before transport cache."""
    from .gcp import sanitize
    if isinstance(value, list): return [_scrub(x) for x in value]
    if not isinstance(value, dict): return value
    output = {}
    for key, item in value.items():
        if key == MARKER: continue
        if key in ('script', 'args', 'command', 'secrets'): continue
        if key == 'substitutions':
            if isinstance(item, dict):
                output['substitutionNames'] = sorted(k for k in item if isinstance(k, str))
                commit = item.get('COMMIT_SHA')
                if isinstance(commit, str) and re.fullmatch('[0-9a-fA-F]{40}', commit):
                    output['substitutions'] = {'COMMIT_SHA': commit}
            continue
        if key in ('metadata', 'commonInstanceMetadata') and isinstance(item, dict) and isinstance(item.get('items'), list):
            safe = sanitize({key: item})[key]
            for entry in safe.get('items', []):
                if not isinstance(entry.get('value'), str) or entry['value'].strip().lower() not in ('true', 'false', '0', '1'):
                    entry.pop('value', None)
            output[key] = safe
        else:
            output[key] = _scrub(item)
    return sanitize(output)


def _unknown(reason, cause=None):
    marker = {'schema': SCHEMA, 'status': reason, 'complete': False, 'leaks': []}
    text = str(cause) if isinstance(cause, (ValueError, TimeoutError)) else ''
    # Only this module's fixed literal messages are recorded; never content.
    marker['reason'] = text if re.fullmatch(r'[A-Za-z][A-Za-z /-]{0,79}', text) else (type(cause).__name__ if cause else reason)
    return marker


def project_response(response, *, method, url, scope, params=None, body=None, enabled=False,
                     selected_kinds=(), check_cancelled=None, response_complete=True):
    """Project selected unmasked native list/get responses without content persistence."""
    safe = _scrub(response)
    try:
        route = request_route(method, url, scope, params, body)
    except (TypeError, ValueError):
        return safe
    if not isinstance(response, dict) or not isinstance(safe, dict): return safe
    if enabled is True and isinstance(selected_kinds, (list, tuple, set, frozenset)) and route['kind'] in selected_kinds:
        from peaso.secret_scanning import omit_free_text_metadata
        safe = omit_free_text_metadata(safe)
    pairs = []
    if route['aggregate']:
        raw_groups, safe_groups = response.get('items', {}), safe.get('items', {})
        if not isinstance(raw_groups, dict) or not isinstance(safe_groups, dict): return safe
        for location, group in raw_groups.items():
            if not isinstance(group, dict): continue
            natives = group.get(route['key'], [])
            projected = safe_groups.get(location, {}).get(route['key'], [])
            if isinstance(natives, list) and isinstance(projected, list): pairs.extend((raw, projected_row, {**route, 'location': location}) for raw, projected_row in zip(natives, projected))
    elif route['key'] is not None and route['name'] is None:
        response_key = 'items' if route['kind'] in ('instance', 'instance_template') else route['key']
        raw_rows, safe_rows = response.get(response_key, []), safe.get(response_key, [])
        if isinstance(raw_rows, list) and isinstance(safe_rows, list): pairs = [(raw, projected, route) for raw, projected in zip(raw_rows, safe_rows)]
    else:
        pairs = [(response, safe, route)]
    if enabled is not True or not isinstance(selected_kinds, (list, tuple, set, frozenset)) or route['kind'] not in selected_kinds:
        return safe
    budget, deadline = MAX_PAGE_BYTES, time.monotonic() + MAX_PAGE_SECONDS
    incomplete = (response_complete is not True or any(response.get(k) for k in ('unreachable', 'unreachables', 'warning', 'missingZones', 'failedLocations')))
    if route['aggregate']:
        incomplete |= any(isinstance(group, dict) and group.get('warning', {}).get('code') not in (None, 'NO_RESULTS_ON_PAGE') for group in response.get('items', {}).values() if isinstance(group, dict) and isinstance(group.get('warning', {}), dict))
    redactions = set()
    admitted = []
    for raw, output, row_route in pairs:
        if not isinstance(raw, dict) or not isinstance(output, dict): continue
        try:
            if len(pairs) > MAX_RESOURCES or incomplete:
                raise ValueError('incomplete or oversized native page')
            resource = identity(raw, row_route)
            payload, count = _parts(raw, route['kind'])
            if len(payload) > budget: raise ValueError('page byte bound')
            budget -= len(payload)
            admitted.append((raw, output, resource, payload, count))
        except Exception as exc:
            output[MARKER] = _unknown('unavailable', exc)
    if not admitted:
        return redact_matches(safe, redactions)
    path = route['kind'] + '.literal_configuration'
    # One offline TruffleHog process prepares every admitted row of the page;
    # each row still runs the normal two-engine scan with its own source.
    with prepared_content_batch([(payload, path) for _, _, _, payload, _ in admitted],
                                timeout=max(.001, min(20, (deadline - time.monotonic()) / 2))):
        for raw, output, resource, payload, count in admitted:
            try:
                if check_cancelled is not None: check_cancelled()
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise TimeoutError('scan deadline')
                outcome = scan_with_source(scan_content, payload, path, timeout=min(10, remaining / 2),
                                       _redact_values=redactions.update, source={'resource_id': resource, 'location_kind': 'configuration', 'scope': route['scope']}, native=raw)
                leaks = merge_leaks(outcome['leaks'])
                if len(leaks) > MAX_LEAKS or sum(len(leak['locations']) for leak in leaks) > MAX_LOCATIONS:
                    raise ValueError('redacted result bound')
                output[MARKER] = {'schema': SCHEMA, 'status': 'collected' if outcome['complete'] else 'incomplete',
                    'kind': route['kind'], 'identity': resource, 'scope': scope, 'source_fields': FIELDS[route['kind']],
                    'bytes': len(payload), 'parts': count, 'complete': outcome['complete'], 'engines': outcome['engines'],
                    'leaks': leaks, 'verification': 'not_attempted'}
            except Exception as exc:
                output[MARKER] = _unknown('unavailable', exc)
    return redact_matches(safe, redactions)
