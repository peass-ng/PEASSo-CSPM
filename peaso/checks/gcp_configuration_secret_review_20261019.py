"""Optional offline scans of seven native GCP literal configurations."""
from copy import deepcopy
import re

from .facts import get, Unavailable
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.gcp_configuration_secret_indicators import (
    MARKER, SCHEMA, KINDS, IDS, FIELDS, MAX_RESOURCE_BYTES, MAX_PARTS, MAX_LEAKS, MAX_LOCATIONS, IDENT, LOC,
)

LABELS = {'instance': 'Compute Engine instance', 'instance_template': 'Compute Engine instance template',
          'project': 'Compute Engine project metadata', 'cloudrun_service': 'Cloud Run service',
          'cloudrun_job': 'Cloud Run job', 'cloudbuild_trigger': 'Cloud Build trigger', 'cloudbuild_build': 'Cloud Build build'}

ACTIONS = {
    **{kind: 'Remove credentials from VM metadata and startup scripts, retrieve secrets in authorized runtime code, and rotate exposed credentials.'
       for kind in ('instance', 'instance_template', 'project')},
    **{kind: 'Replace literal credentials with Cloud Run Secret Manager references and rotate exposed credentials.'
       for kind in ('cloudrun_service', 'cloudrun_job')},
    **{kind: 'Use Cloud Build Secret Manager secret variables instead of inline credentials and rotate exposed credentials.'
       for kind in ('cloudbuild_trigger', 'cloudbuild_build')},
}

DECLARATIONS = {kind: {'id': IDS[kind], 'provider': 'gcp', 'kind': kind, 'category': 'hardening',
    'finding_type': 'secrets', 'severity': 'high', 'dependencies': [kind], 'requirements': [],
    'title': LABELS[kind] + ' literal configuration has no detected secrets',
    'remediation': ACTIONS[kind],
    'evidence_sentences': ['A likely secret was detected in the resource’s returned literal configuration.',
                           'The value is hidden; neither detector validated the credential.']} for kind in KINDS}


def _subject(item, kind, scope, marker):
    if kind == 'project':
        config = get(item, 'computeConfig', dict)
        return scope if get(config, 'name', str) == scope.split('/')[1] else None
    if kind in ('instance', 'instance_template'):
        link = get(item, 'selfLink', str)
        return re.sub(r'^https://(?:www\.googleapis\.com|compute\.googleapis\.com)/compute/v1/', '', link)
    if kind.startswith('cloudrun'):
        return get(item, 'name', str)
    ident = get(item, 'id', str)
    resource = marker['identity']
    if not re.fullmatch(IDENT, ident) or not resource.endswith('/' + ident): return None
    supplied = item.get('resourceName') if kind == 'cloudbuild_trigger' else item.get('name')
    alias = (kind == 'cloudbuild_build' and isinstance(supplied, str) and resource.startswith(scope + '/')
             and re.fullmatch(r'projects/[1-9][0-9]{0,19}/' + re.escape(resource[len(scope) + 1:]), supplied))
    if supplied is not None and supplied != resource and not alias: return None
    if kind == 'cloudbuild_build' and item.get('projectId') != scope.split('/')[1]: return None
    return resource


def evaluate(item, index, kind):
    try:
        if kind not in KINDS or get(index, 'context.provider', str) != 'gcp':
            raise Unavailable('foreign configuration kind/provider')
        scope = get(index, 'context.scope', str)
        if not re.fullmatch(r'projects/' + IDENT, scope): raise Unavailable('project scope absent')
        envelopes = get(index, 'collections.' + kind, list)
        candidates = [e for e in envelopes if isinstance(e, dict) and e.get('scope') == scope
                      and e.get('status') == 'collected' and isinstance(e.get('items'), list) and item in e['items']]
        if len(candidates) != 1 or sum(native == item for native in candidates[0]['items']) != 1:
            raise Unavailable('native collection incomplete or ambiguous')
        try:
            marker = get(item, ('computeConfig.' if kind == 'project' else '') + MARKER, dict)
        except (Unavailable, KeyError, TypeError, ValueError, AttributeError):
            raise Unavailable('literal configuration scan marker absent (content_secret_scans off or kind not selected)')
        if marker.get('status') != 'collected':
            raise Unavailable('literal configuration scan ' + str(marker.get('status'))[:32]
                              + (': ' + marker['reason'][:80] if isinstance(marker.get('reason'), str) else ''))
        expected = {'schema', 'status', 'kind', 'identity', 'scope', 'source_fields', 'bytes', 'parts', 'complete', 'engines', 'leaks', 'verification'}
        if (set(marker) != expected or marker['schema'] != SCHEMA or marker['kind'] != kind
                or marker['status'] != 'collected' or marker['complete'] is not True
                or marker['scope'] != scope or marker['verification'] != 'not_attempted'
                or marker['source_fields'] != FIELDS[kind] or type(marker['bytes']) is not int
                or not 1 <= marker['bytes'] <= MAX_RESOURCE_BYTES or type(marker['parts']) is not int
                or not 0 <= marker['parts'] <= MAX_PARTS):
            raise Unavailable('configuration scan absent or incomplete')
        resource = _subject(item, kind, scope, marker)
        if not isinstance(resource, str) or resource != marker['identity']: raise Unavailable('native identity unbound')
        prefix = re.escape(scope)
        if kind == 'project': valid = resource == scope
        elif kind in ('instance', 'instance_template'):
            loc = r'zones/' + LOC if kind == 'instance' else r'(?:global|regions/' + LOC + ')'
            segment = 'instances' if kind == 'instance' else 'instanceTemplates'
            valid = re.fullmatch(prefix + '/' + loc + '/' + segment + '/' + IDENT, resource) and resource.endswith('/' + get(item, 'name', str))
        else:
            segment = {'cloudrun_service': 'services', 'cloudrun_job': 'jobs', 'cloudbuild_trigger': 'triggers', 'cloudbuild_build': 'builds'}[kind]
            valid = re.fullmatch(prefix + '/locations/' + LOC + '/' + segment + '/' + IDENT, resource)
        if not valid: raise Unavailable('resource outside native scope')
        engines = marker['engines']
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if (not isinstance(engines, list) or len(engines) != 2 or any(not isinstance(e, dict)
                or set(e) != {'engine', 'version', 'status'} or e.get('engine') not in versions
                or e.get('version') != versions.get(e.get('engine')) or e.get('status') != 'complete' for e in engines)
                or {e['engine'] for e in engines} != set(versions)):
            raise Unavailable('both offline detector completions required')
        if not isinstance(marker['leaks'], list) or len(marker['leaks']) > MAX_LEAKS: raise Unavailable('leak bound')
        leaks = merge_leaks(marker['leaks'])
        if sum(len(leak['locations']) for leak in leaks) > MAX_LOCATIONS:
            raise Unavailable('location bound')
        if any(loc['path'] != kind + '.literal_configuration' for leak in leaks for loc in leak['locations']):
            raise Unavailable('foreign content location')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted', 'complete': True,
                    'source_fields': FIELDS[kind], 'inspected_bytes': marker['bytes']}
        if leaks:
            return 'FAIL', {**evidence, 'observed': 'A likely secret was detected in the resource’s returned literal configuration. The value is hidden; neither detector validated the credential.'}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors completed without finding a supported secret in the returned literal configuration; external content was not inspected.'}
    except (Unavailable, KeyError, TypeError, ValueError, AttributeError) as exc:
        fact = str(exc.args[0]) if isinstance(exc, Unavailable) and exc.args and isinstance(exc.args[0], str) else type(exc).__name__
        return 'UNKNOWN', {'observed': 'Literal configuration scanning is disabled, incomplete, unreadable or unbound; secret absence could not be assessed.',
                           'reason': 'missing_facts: ' + fact, 'missing_facts': [fact]}


def instance(item, index): return evaluate(item, index, 'instance')
def instance_template(item, index): return evaluate(item, index, 'instance_template')
def project(item, index): return evaluate(item, index, 'project')
def cloudrun_service(item, index): return evaluate(item, index, 'cloudrun_service')
def cloudrun_job(item, index): return evaluate(item, index, 'cloudrun_job')
def cloudbuild_trigger(item, index): return evaluate(item, index, 'cloudbuild_trigger')
def cloudbuild_build(item, index): return evaluate(item, index, 'cloudbuild_build')


def install():
    from pathlib import Path
    import gzip
    import json
    from . import CHECKS, register
    from .fixtures import CASES
    fixtures = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_configuration_secret_fixtures.json.gz').read_bytes()))['cases']
    existing = {check.id for check in CHECKS}
    for kind, declaration in DECLARATIONS.items():
        cid = declaration['id']
        if cid in existing:
            continue
        register(cid, 'gcp', 'hardening', kind, declaration['title'], 'high',
                 'security_configuration', declaration['remediation'])(globals()[kind])
        cases = fixtures[cid]
        CASES[cid] = {'missing': {}, 'malformed': None}
        for branch in ('pass', 'fail', 'unknown'):
            CASES[cid][branch] = deepcopy(cases[branch]['item'])
            CASES[cid][branch + '_index'] = deepcopy(cases[branch]['index'])
