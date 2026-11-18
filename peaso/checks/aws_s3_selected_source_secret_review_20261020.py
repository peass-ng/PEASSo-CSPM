"""Pure unregistered selected S3 source secret-indicator consumer."""
from copy import deepcopy
import re
from peaso.collectors.aws_s3_selected_source_secret_indicators import (
    KIND, CHECK, MARKER, SCHEMA, SCOPE, FORMATS, MAX_TARGETS, MAX_CALLS, MAX_OBJECT, MAX_TEXT,
    MAX_MEMBERS, MAX_LEAKS, MAX_LOCATIONS)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

DECLARATIONS = [{'id': CHECK, 'provider': 'aws', 'category': 'exposure', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'ui_group': 'Secrets', 'requirements': [],
    'dependencies': [KIND], 'allow_incomplete_failure': True,
    'title': 'Selected S3 source text and archive members have no detected secrets',
    'remediation': 'Remove exposed literals from the selected object and rotate confirmed exposed credentials. Use supported secret references or workload identities.',
    'scope': 'Exact selected current object or existing version and supported regular text archive members only; no deployment association, reference resolution, verification or execution.'}]


def evaluate(item, index):
    try:
        ctx = index['context']; meta = ctx['metadata']; scope = ctx['scope']; match = SCOPE.fullmatch(scope)
        if ctx['provider'] != 'aws' or not match or meta[KIND + '_authorized'] is not True:
            raise ValueError()
        capture = meta[KIND + '_capture']; selected = meta[KIND + '_selection'][scope]
        if (not isinstance(capture, str) or not re.fullmatch('s3-source:[0-9a-f]{32}', capture)
                or not isinstance(selected, list) or not 1 <= len(selected) <= MAX_TARGETS
                or len(set(selected)) != len(selected) or any(not isinstance(i, str) or not re.fullmatch(KIND + ':[0-9a-f]{64}', i) for i in selected)):
            raise ValueError()
        collection, = [c for c in index['collections'][KIND] if c.get('scope') == scope]
        if collection.get('service') != 's3' or collection.get('status') not in ('collected', 'partial'):
            raise ValueError()
        rows = collection['items']; ids = [row['id'] for row in rows]
        if len(set(ids)) != len(ids) or not set(ids) <= set(selected) or sum(row == item for row in rows) != 1:
            raise ValueError()
        ident = item['id']; m = item[MARKER]
        if (set(m) - {'source', 'failure'} != {'schema', 'identity', 'scope', 'format', 'capture', 'principal', 'complete', 'source_bound',
                'head_coherent', 'content_complete', 'parts', 'leaks', 'source_requests', 'object', 'member_count', 'verification'}
                or m['schema'] != SCHEMA or m['identity'] != ident or m['scope'] != scope or ident not in selected
                or m['capture'] != capture or m['format'] not in FORMATS or m['source_bound'] is not True
                or any(type(m[k]) is not bool for k in ('complete', 'head_coherent', 'content_complete'))
                or m['verification'] != 'not_attempted' or item['_provenance'].get('scope') != scope
                or item['_provenance'].get('capture') != capture or not isinstance(m['principal'], str)
                or not re.fullmatch('s3-source-principal:[0-9a-f]{64}', m['principal'])
                or meta[KIND + '_principals'].get(scope) != m['principal']):
            raise ValueError()
        obj = m['object']
        if (not isinstance(obj, dict) or set(obj) != {'etag', 'length', 'version', 'explicit_version'}
                or not re.fullmatch('[0-9a-f]{64}', obj['etag']) or type(obj['length']) is not int
                or not 0 <= obj['length'] <= MAX_OBJECT or type(obj['explicit_version']) is not bool
                or obj['version'] is not None and not re.fullmatch('[0-9a-f]{64}', obj['version'])
                or obj['explicit_version'] and obj['version'] is None):
            raise ValueError()
        ledger = meta[KIND + '_receipts']; refs = m['source_requests']
        if (not isinstance(ledger, list) or not 1 <= len(ledger) <= MAX_CALLS or len({r['id'] for r in ledger}) != len(ledger)
                or not isinstance(refs, list) or not 4 <= len(refs) <= 5 or len(set(refs)) != len(refs)):
            raise ValueError()
        receipts = []
        for n, ref in enumerate(refs):
            r, = [row for row in ledger if row['id'] == ref]
            phase = ('caller', 'location', 'head_before', 'get', 'head_after')[n]
            service = 'sts' if phase == 'caller' else 's3'
            operation = {'caller': 'get_caller_identity', 'location': 'get_bucket_location',
                'head_before': 'head_object', 'get': 'get_object', 'head_after': 'head_object'}[phase]
            if (set(r) != {'id', 'identity', 'scope', 'capture', 'service', 'operation', 'phase', 'region', 'method',
                    'host', 'request', 'http_status', 'request_id', 'bound', 'bytes'}
                    or not re.fullmatch('s3-source-read-[1-9][0-9]*', ref) or r['identity'] != ident
                    or r['scope'] != scope or r['capture'] != capture or r['phase'] != phase or r['service'] != service
                    or r['operation'] != operation or r['region'] != match[2] or r['host'] != service + '.' + match[2] + '.amazonaws.com'
                    or r['method'] != ('POST' if service == 'sts' else 'HEAD' if operation == 'head_object' else 'GET')
                    or not re.fullmatch('[0-9a-f]{64}', r['request']) or type(r['bound']) is not bool
                    or type(r['bytes']) is not int or not 0 <= r['bytes'] <= MAX_OBJECT + 1
                    or r['http_status'] is not None and type(r['http_status']) is not int
                    or r['request_id'] is not None and not re.fullmatch('[0-9a-f]{64}', r['request_id'])
                    or n < 4 and (not r['bound'] or r['http_status'] != 200 or r['request_id'] is None)):
                raise ValueError()
            receipts.append(r)
        if receipts[3]['bytes'] != obj['length']:
            raise ValueError()
        parts = m['parts']; versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if (not isinstance(parts, list) or not 1 <= len(parts) <= MAX_MEMBERS
                or len({p['path'] for p in parts}) != len(parts)
                or type(m['member_count']) is not int or not 0 <= m['member_count'] <= MAX_MEMBERS):
            raise ValueError()
        trusted = {}; complete_parts = True
        for p in parts:
            expected_path = re.escape(ident) + (r'\.text' if m['format'] == 'text' else r'\.member:[0-9a-f]{64}')
            engines = p['engines']
            if (set(p) != {'path', 'bytes', 'complete', 'engines'} or not re.fullmatch(expected_path, p['path'])
                    or type(p['bytes']) is not int or not 1 <= p['bytes'] <= MAX_TEXT + 1025 or type(p['complete']) is not bool
                    or not isinstance(engines, list) or len(engines) != 2 or {e['engine'] for e in engines} != set(versions)
                    or any(set(e) != {'engine', 'version', 'status'} or e['version'] != versions[e['engine']]
                        or e['status'] not in ('complete', 'unavailable') for e in engines)
                    or p['complete'] != all(e['status'] == 'complete' for e in engines)):
                raise ValueError()
            trusted[p['path']] = {e['engine'] for e in engines if e['status'] == 'complete'}
            complete_parts = complete_parts and p['complete']
        leaks = m['leaks']
        if (not isinstance(leaks, list) or merge_leaks(leaks) != leaks or len(leaks) > MAX_LEAKS
                or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}', l['fingerprint']) or not l['locations'] or not l['detectors']
                    or any(set(loc) != {'path'} or loc['path'] not in trusted for loc in l['locations'])
                    or any(not any(d['engine'] in trusted[loc['path']] for loc in l['locations']) for d in l['detectors'])
                    or any(not any(d['engine'] in trusted[loc['path']] for d in l['detectors']) for loc in l['locations']) for l in leaks)):
            raise ValueError()
        complete = (m['complete'] and m['content_complete'] and m['head_coherent'] and complete_parts
            and len(receipts) == 5 and receipts[-1]['bound'] and receipts[-1]['http_status'] == 200
            and collection['status'] == 'collected' and set(ids) == set(selected))
        if not complete and not leaks:
            raise ValueError()
        observed = ('A likely secret was detected in selected S3 source text or archive members. The value is hidden and was not validated.' if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected S3 source text and regular archive members. Coverage is limited to the selected object or version.')
        if not complete:observed += ' Coverage is incomplete.'
        evidence = {'observed': observed, 'secret_leaks': deepcopy(leaks),
            'complete': bool(complete), 'coverage': 'selected_s3_source_text_only' if complete else 'incomplete',
            'credential_validation': 'not_attempted', 'format': m['format'], 'parts': deepcopy(parts),
            'source_requests': list(refs), 'object_bytes': obj['length']}
        evidence.update(_source_fields(m))
        if not complete:
            evidence.update(_failure_fields(m))
        return ('FAIL' if leaks else 'PASS'), evidence
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        return 'UNKNOWN', _unknown(item, index)


_CAUSES = {'access_denied': 'access was denied', 'credential_expired': 'the scan credentials expired',
    'source_not_found': 'AWS reported the object or bucket missing', 'source_throttled': 'AWS throttled the read',
    'kms_key_unavailable': 'the object\'s KMS key could not be used', 's3_object_changed': 'the object changed during the read',
    's3_bucket_region_mismatch': 'the bucket is in a different Region than the selected scope',
    's3_source_transport_failed': 'the network connection to AWS failed', 's3_source_deadline': 'the read deadline passed',
    's3_source_read_failed': 'the read failed'}
_PHASES = {'caller': 'GetCallerIdentity', 'location': 'GetBucketLocation', 'head_before': 'HeadObject',
    'get': 'GetObject', 'head_after': 'HeadObject (after read)'}
_SELECTIONS = {'explicit_option': 'it is listed in the connector option selected_aws_s3_sources',
    'ecs_environment_file': 'an ECS task definition references it as an environment file',
    'workload_reference': 'a selected workload references it as its source',
    'build_deployment_reference': 'a selected build or deployment references it as its source'}


def _short(value, pattern):
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else None


def _source_fields(m):
    """The selected object's own locator and how it was chosen."""
    source = m.get('source') if isinstance(m, dict) else None
    if not isinstance(source, dict) or not isinstance(source.get('uri'), str) or not source['uri'].startswith('s3://'):
        return {}
    fields = {'object': source['uri']}
    if isinstance(source.get('version_id'), str):
        fields['version_id'] = source['version_id']
    chosen = source.get('selection')
    if isinstance(chosen, dict) and chosen.get('source') in _SELECTIONS:
        fields['selection'] = {'source': chosen['source'], 'option': _short(chosen.get('option'), r'selected_aws_[a-z0-9_]{1,64}')}
    return fields


def _failure_fields(m):
    failure = m.get('failure') if isinstance(m, dict) else None
    if not isinstance(failure, dict):
        return {}
    fields = {}
    for key, pattern in (('reason', r'[a-z][a-z0-9_]{2,63}'), ('phase', r'[a-z_]{3,16}'),
                         ('operation', r'[a-z0-9-]{2,32}:[A-Za-z]{2,64}'), ('provider_code', r'[A-Za-z0-9][A-Za-z0-9_.]{0,63}'),
                         ('missing_action', r'[a-z0-9-]{2,32}:[A-Za-z]{2,64}'), ('denied_by', r'[a-z_]{2,40}')):
        value = _short(failure.get(key), pattern)
        if value is not None:
            fields[key] = value
    return fields


def _unknown(item, index):
    """An unread object's own UNKNOWN, naming the object, the step, the IAM action and the AWS code."""
    step = _reason(item, index)
    m = item.get(MARKER) if isinstance(item, dict) else None
    source = _source_fields(m)
    failure = _failure_fields(m)
    if not source and not failure:
        return {'observed': 'Selected S3 source content was unreadable, unsupported, incomplete or unbound. A clean result cannot be established.',
            'complete': False, 'coverage': 'incomplete', 'reason': step}
    name = source.get('object', 'The selected S3 object')
    if 'version_id' in source:
        name += ' (version ' + source['version_id'] + ')'
    reason = failure.get('reason', step)
    if failure:
        cause = _CAUSES.get(reason, 'its response was rejected (' + reason + ')')
        call = _PHASES.get(failure.get('phase'))
        observed = (name + ' was not read' + (' at ' + call if call else '') + ' because ' + cause
            + (' (' + failure['provider_code'] + ')' if 'provider_code' in failure else '')
            + ('; the request needs ' + failure['operation'] if 'operation' in failure else '') + '.')
    else:
        observed = name + ' was not fully assessed (' + step + ').'
    chosen = source.get('selection', {}).get('source')
    if chosen in _SELECTIONS:
        observed += ' It was selected because ' + _SELECTIONS[chosen] + '.'
    observed += ' A clean result cannot be established.'
    evidence = {'observed': observed, 'complete': False, 'coverage': 'incomplete', 'reason': reason, 'step': step}
    evidence.update(source)
    evidence.update({k: v for k, v in failure.items() if k != 'reason'})
    return evidence


def _reason(item, index):
    """Name the first read or scan step that kept the selected object unassessed."""
    try:
        m = item[MARKER]
        ledger = {r['id']: r for r in index['context']['metadata'][KIND + '_receipts']}
        for ref in m['source_requests']:
            r = ledger.get(ref) or {}
            if not r.get('bound') or r.get('http_status') != 200:
                status = r.get('http_status')
                return 's3_source_%s_%s' % (r.get('phase', 'read'), 'http_%d' % status if type(status) is int else 'failed')
        if len(m['source_requests']) < 5:
            return 's3_source_read_not_finished'
        engines = sorted({e['engine'] for p in m['parts'] for e in p['engines'] if e['status'] != 'complete'})
        if engines:
            return 'secret_engine_unavailable: ' + ', '.join(engines)
        if not m['parts']:
            return 's3_source_no_supported_text'
        for flag in ('content_complete', 'head_coherent', 'complete'):
            if m[flag] is not True:
                return 's3_source_' + flag + '_false'
        return 's3_source_evidence_binding_rejected'
    except (KeyError, TypeError, AttributeError):
        return 's3_source_not_collected'
