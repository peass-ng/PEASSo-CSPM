"""Positive-only successor for intact native observations in partial inventory."""
from copy import deepcopy

from . import gcp_function_secret_paired_review_20261020 as predecessor
from .facts import Unavailable, get
from peaso.collectors import gcp_function_secret_pairs_20261020 as producer

CHECK_ID, DECLARATION = predecessor.CHECK_ID, predecessor.DECLARATION


def _native_read(item, index, envelope, scope):
    metadata = get(index, 'context.metadata', dict)
    if metadata.get('collector') != 'native-gcp' or metadata.get('collection') != 'read-only':
        raise Unavailable('native collection provenance unavailable')
    provenance = get(item, '_provenance', dict)
    if provenance.get('scope') != scope or envelope.get('coverage_status') != 'partial':
        raise Unavailable('native partial scope unavailable')
    row_refs, collection_refs = provenance.get('source_requests'), envelope.get('source_requests')
    records = metadata.get('source_requests')
    if (not isinstance(row_refs, list) or not row_refs or not isinstance(collection_refs, list)
            or not collection_refs or not isinstance(records, list)
            or any(not isinstance(value, str) or not value for value in row_refs + collection_refs)):
        raise Unavailable('native request references unavailable')
    ids = [record.get('id') for record in records if isinstance(record, dict)]
    if len(ids) != len(records) or any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != len(ids):
        raise Unavailable('native request evidence ambiguous')
    found = []
    for record in records:
        if record['id'] not in row_refs or record['id'] not in collection_refs:
            continue
        if (record.get('scope') != scope or record.get('status') != 'collected'
                or type(record.get('http_status')) is not int or record['http_status'] != 200
                or record.get('error') or record.get('request')):
            continue
        try:
            location, function = producer._request(record.get('method'), record.get('url'),
                scope, record.get('query'), None)
        except (ValueError, TypeError):
            continue
        if producer._bound(item.get('name'), scope, location, function):
            found.append({key: deepcopy(record[key]) for key in (
                'id', 'scope', 'method', 'url', 'query', 'status', 'http_status')})
    if len(found) != 1:
        raise Unavailable('one successful native source read required')
    return found[0]


def _evaluate(item, index):
    ordinary = predecessor._evaluate(item, index)
    if ordinary[0] != 'UNKNOWN':
        return ordinary
    try:
        scope = get(index, 'context.scope', str)
        if get(index, 'context.provider', str) != 'gcp':
            raise Unavailable('foreign provider')
        name = get(item, 'name', str)
        if get(item, producer.MARKER, dict).get('schema') != producer.SCHEMA:
            raise Unavailable('paired source evidence required')
        envelopes = get(index, 'collections.function', list)
        scoped = [row for row in envelopes if isinstance(row, dict) and row.get('scope') == scope]
        if len(scoped) != 1:
            raise Unavailable('native scope ambiguous')
        envelope = scoped[0]
        if (envelope.get('status') != 'partial' or not isinstance(envelope.get('items'), list)
                or sum(isinstance(row, dict) and row.get('name') == name for row in envelope['items']) != 1
                or item not in envelope['items']):
            raise Unavailable('intact partial inventory item required')
        read = _native_read(item, index, envelope, scope)
        normalized = deepcopy(index)
        normalized['collections']['function'] = [{**deepcopy(envelope), 'status': 'collected'}]
        status, evidence = predecessor._evaluate(item, normalized)
        if status != 'FAIL':
            raise Unavailable('partial inventory cannot establish absence')
        evidence['function_secret_scan_complete'] = evidence['complete']
        evidence.update(complete=False, incomplete=True, inventory_complete=False, inventory_status='partial',
            function_secret_native_read=read)
        if 'Coverage is incomplete' not in evidence['observed']:
            evidence['observed'] += ' Coverage is incomplete; the returned function has a supported secret observation.'
        return 'FAIL', evidence
    except (Unavailable, KeyError, TypeError, ValueError, AttributeError):
        return ordinary


def portable_source(finding):
    """Revalidate whitelisted retained-read proof without inferring source pairs."""
    evidence = finding.get('evidence', {})
    if not isinstance(evidence, dict):
        return None
    if evidence.get('inventory_complete') is not False:
        return finding
    read = evidence.get('function_secret_native_read')
    if (not isinstance(read, dict) or set(read) != {
            'id', 'scope', 'method', 'url', 'query', 'status', 'http_status'}
            or evidence.get('incomplete') is not True or evidence.get('complete') is not False
            or type(evidence.get('function_secret_scan_complete')) is not bool):
        return None
    name, scope = finding.get('native_resource_id') or finding.get('resource_id'), finding.get('scope')
    complete = evidence['function_secret_scan_complete']
    marker = {'schema': producer.SCHEMA, 'identity': name, 'scope': scope,
        'status': 'collected' if complete else 'incomplete', 'complete': complete,
        'verification': 'not_attempted', 'surfaces': evidence.get('surfaces'), 'leaks': evidence.get('secret_leaks')}
    row = {'name': name, producer.MARKER: marker,
        '_provenance': {'scope': scope, 'source_requests': [read.get('id')]}}
    envelope = {'scope': scope, 'status': 'partial', 'coverage_status': 'partial',
        'source_requests': [read.get('id')], 'items': [row]}
    index = {'context': {'scope': scope, 'provider': 'gcp', 'metadata': {
        'collector': 'native-gcp', 'collection': 'read-only', 'source_requests': [read]}},
        'collections': {'function': [envelope]}}
    if _evaluate(row, index)[0] != 'FAIL':
        return None
    normalized = deepcopy(finding)
    normalized['evidence']['complete'] = complete
    return normalized


evaluate = _evaluate
