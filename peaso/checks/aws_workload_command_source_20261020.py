"""Pure data consumer for the unregistered workload command proposal.

Constants deliberately do not import the collector/package dispatcher. This
allows finite direct-file proof without loading any existing runtime registry.
"""
from copy import deepcopy
import re

from peaso.secret_scanning import KINGFISHER_VERSION, TRUFFLEHOG_VERSION, merge_leaks

CHECK = 'aws.review.workload.selected_command_literal_secret_indicators'
KIND = 'aws_selected_workload_command_literals'
SCHEMA = 'aws-workload-command-source-20261020-v1'
DECLARATION = {'id': CHECK, 'provider': 'aws', 'category': 'exposure', 'kind': KIND,
    'group': 'Secrets', 'finding_type': 'secrets', 'severity': 'high',
    'title': 'Selected ECS and Batch command literals have no detected secrets',
    'permissions': ['ecs:DescribeTaskDefinition', 'batch:DescribeJobDefinitions'],
    'allow_incomplete_failure': True,
    'observed_contract': 'Both offline detectors inspect returned command literals on exact selected active definition revisions. A supported secret produces FAIL even with partial coverage; PASS requires all selected native fields and both detectors to complete, and malformed fields or unresolved Batch placeholders produce UNKNOWN; an entryPoint or command the definition does not set has zero literals. Definition evidence does not establish running adoption or credential validity.',
    'remediation': 'Remove secret literals from the selected definition and rotate exposed credentials. Use an appropriate secret delivery mechanism, then separately verify deployed workloads and overrides.'}


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def validate_row(row, collection):
    if (not isinstance(row, dict) or set(row) != {'id', 'scope', 'service', 'binding', 'capture',
            'principal', 'requests', 'native_bound', 'native_complete', 'complete', 'scans', 'leaks', 'verification'}
            or row['id'] not in collection['selection'] or row['binding'] != collection['binding']
            or row['capture'] != collection['capture'] or row['verification'] != 'not_attempted'
            or any(type(row[k]) is not bool for k in ('native_bound', 'native_complete', 'complete'))
            or row['scope'] != collection['selection'][row['id']]['scope']
            or row['service'] != collection['selection'][row['id']]['service']):
        raise ValueError()
    if row['native_bound'] is not True:
        if row['leaks'] or row['scans'] or row['complete'] or row['native_complete']:
            raise ValueError()
        return False
    if not digest(row['principal']) or not isinstance(row['requests'], list) or len(row['requests']) != 2:
        raise ValueError()
    operation = 'DescribeTaskDefinition' if row['service'] == 'ecs' else 'DescribeJobDefinitions'
    for receipt, service, op in zip(row['requests'], ('sts', row['service']), ('GetCallerIdentity', operation)):
        if (set(receipt) != {'service', 'operation', 'http_status', 'request', 'response', 'bytes'}
                or receipt['service'] != service or receipt['operation'] != op
                or type(receipt['http_status']) is not int or receipt['http_status'] != 200
                or not digest(receipt['request']) or not digest(receipt['response'])
                or type(receipt['bytes']) is not int or not 1 <= receipt['bytes'] <= 2 * 1024 * 1024):
            raise ValueError()
    if row['requests'][1]['request'] != collection['selection'][row['id']]['request']:
        raise ValueError()
    scans, leaks = row['scans'], row['leaks']
    if (not isinstance(scans, list) or len(scans) > (64 if row['service'] == 'ecs' else 1)
            or not isinstance(leaks, list) or len(leaks) > 128 or merge_leaks(leaks) != leaks
            or sum(len(leak['locations']) for leak in leaks) > 512):
        raise ValueError()
    fields, paths = [], {}
    versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
    for scan in scans:
        if (set(scan) != {'path', 'field', 'bytes', 'literals', 'engines', 'complete'}
                or not isinstance(scan['path'], str) or not scan['path'].startswith(row['id'] + ':')
                or not digest(scan['path'][len(row['id']) + 1:]) or scan['path'] in paths
                or not isinstance(scan['field'], str) or scan['field'] in fields
                or type(scan['bytes']) is not int or not 0 <= scan['bytes'] <= 256 * 1024
                or type(scan['literals']) is not int or not 0 <= scan['literals'] <= 256
                or scan['literals'] == 0 and scan['bytes'] != 0
                or type(scan['complete']) is not bool):
            raise ValueError()
        if row['service'] == 'ecs':
            if not re.fullmatch(r'containerDefinitions\[(?:[0-9]|[12][0-9]|3[01])\]\.(?:entryPoint|command)', scan['field']):
                raise ValueError()
        elif scan['field'] != 'containerProperties.command':
            raise ValueError()
        engines = scan['engines']
        if (not isinstance(engines, list) or len(engines) != 2
                or {e['engine'] for e in engines} != set(versions)
                or any(set(e) != {'engine', 'version', 'status'} or e['version'] != versions[e['engine']]
                    or e['status'] not in ('complete', 'unavailable') for e in engines)
                or scan['complete'] != all(e['status'] == 'complete' for e in engines)):
            raise ValueError()
        fields.append(scan['field'])
        paths[scan['path']] = scan
    if sum(s['bytes'] for s in scans) > 256 * 1024 or sum(s['literals'] for s in scans) > 256:
        raise ValueError()
    for leak in leaks:
        for loc in leak['locations']:
            if set(loc) - {'path', 'line'} or loc['path'] not in paths:
                raise ValueError()
            for detector in leak['detectors']:
                # A merged secret can have engine observations on other paths.
                if not any(e['engine'] == detector['engine'] and e['status'] == 'complete'
                           for s in scans for e in s['engines']):
                    raise ValueError()
    fields_complete = fields == ['containerProperties.command'] if row['service'] == 'batch' else (
        len(fields) >= 2 and set(fields) == {f'containerDefinitions[{i}].{field}'
            for i in range(len(fields) // 2) for field in ('entryPoint', 'command')})
    complete = row['native_complete'] and fields_complete and bool(scans) and all(s['complete'] for s in scans)
    if row['complete'] and not complete:
        raise ValueError()
    return row['complete'] and complete


def evaluate(item, collection):
    """No filesystem access, credentials, SDK calls, registry or source execution."""
    try:
        if (not isinstance(collection, dict) or set(collection) != {'schema', 'kind', 'authorized', 'binding',
                'capture', 'selection', 'items', 'calls', 'response_bytes', 'wire_bytes', 'complete'}
                or collection['schema'] != SCHEMA or collection['kind'] != KIND
                or collection['authorized'] is not True or not digest(collection['binding'])
                or not isinstance(collection['capture'], str)
                or not re.fullmatch('command-capture:[0-9a-f]{32}', collection['capture'])
                or type(collection['calls']) is not int or not 0 <= collection['calls'] <= 12
                or type(collection['response_bytes']) is not int or not 0 <= collection['response_bytes'] <= 4 * 1024 * 1024
                or type(collection['wire_bytes']) is not int or not 0 <= collection['wire_bytes'] <= 4 * 1024 * 1024
                or type(collection['complete']) is not bool):
            raise ValueError()
        selection, rows = collection['selection'], collection['items']
        if (not isinstance(selection, dict) or not 1 <= len(selection) <= 8
                or not isinstance(rows, list) or len(rows) != len(selection)
                or any(not isinstance(row, dict) for row in rows)
                or len({row['id'] for row in rows}) != len(rows)
                or {row['id'] for row in rows} != set(selection) or sum(row == item for row in rows) != 1):
            raise ValueError()
        for ident, selected in selection.items():
            if (not isinstance(ident, str) or not ident.startswith(KIND + ':') or not digest(ident[len(KIND) + 1:])
                    or set(selected) != {'scope', 'service', 'request'} or selected['service'] not in ('ecs', 'batch')
                    or not isinstance(selected['scope'], str) or len(selected['scope']) > 80
                    or not re.fullmatch(r'[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+', selected['scope'])
                    or not digest(selected['request'])):
                raise ValueError()
        completeness = [validate_row(row, collection) for row in rows]
        if item['native_bound'] is not True or collection['calls'] < 2 or collection['response_bytes'] < 1:
            raise ValueError()
        for row in rows:
            if (row['native_bound'] and row['scope'].split('/')[0] == item['scope'].split('/')[0]
                    and row['principal'] != item['principal']):
                raise ValueError()
        complete = collection['complete'] and all(completeness)
        if not item['leaks'] and not complete:
            raise ValueError()
        observed = ('A likely secret was detected in returned command literals of the selected active definition revision. The value is hidden and credential validity was not checked.' if item['leaks'] else
            'Both offline detectors completed without detecting a supported secret in the selected returned command literals. This evidence covers the selected active definition revisions only.')
        return ('FAIL' if item['leaks'] else 'PASS'), {'observed': observed,
            'secret_leaks': deepcopy(item['leaks']), 'complete': bool(complete),
            'credential_validation': 'not_attempted', 'coverage': 'selected_definition_command_literals_only',
            'scans': deepcopy(item['scans'])}
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, StopIteration):
        return 'UNKNOWN', {'observed': 'Selected command literal evidence was missing, unsupported, incomplete or unbound. Secret absence could not be assessed.',
                           'reason': _reason(item, collection)}


def _reason(row, collection):
    """Name what kept one selected definition from being assessed."""
    try:
        if row.get('native_bound') is not True:
            return 'definition_not_read'
        engines = sorted({e['engine'] for s in row.get('scans') or [] for e in s['engines'] if e['status'] != 'complete'})
        if engines:
            return 'secret_engine_unavailable: ' + ', '.join(engines)
        if row.get('native_complete') is not True:
            return 'definition_read_incomplete'
        if not row.get('scans'):
            return 'no_command_literals_scanned'
        if isinstance(collection, dict) and collection.get('complete') is not True:
            return 'selected_collection_incomplete'
        return 'command_evidence_binding_rejected'
    except (TypeError, KeyError, AttributeError):
        return 'command_evidence_unreadable'


def evaluate_collection(collection):
    """One value-level leak across selected revisions, without runtime hooks.

    At most eight rows of 128 leaks/512 locations enter this bounded union.
    Per-row evaluate() remains available for field provenance and native proof.
    """
    if (not isinstance(collection, dict) or not isinstance(collection.get('items'), list)
            or not 1 <= len(collection['items']) <= 8):
        return 'UNKNOWN', {'observed': 'Selected command literal evidence was unavailable. Secret absence could not be assessed.'}
    outcomes = [evaluate(row, collection) for row in collection['items']]
    leaks = merge_leaks([leak for status, evidence in outcomes if status == 'FAIL'
                         for leak in evidence['secret_leaks']])
    complete = all(status != 'UNKNOWN' and evidence.get('complete') is True for status, evidence in outcomes)
    if leaks:
        return 'FAIL', {'observed': 'Likely secrets were detected in returned command literals of selected active definition revisions. Values are hidden and repeated values are combined; credential validity was not checked.',
            'secret_leaks': leaks, 'complete': complete, 'credential_validation': 'not_attempted',
            'coverage': 'selected_definition_command_literals_only'}
    if complete:
        return 'PASS', {'observed': 'Both offline detectors completed without detecting supported secrets in every selected returned command array. Coverage is limited to the selected active definition revisions.',
            'secret_leaks': [], 'complete': True, 'credential_validation': 'not_attempted',
            'coverage': 'selected_definition_command_literals_only'}
    reasons = sorted({evidence.get('reason') or 'definition_incomplete' for status, evidence in outcomes if status == 'UNKNOWN'}
                     | ({'definition_incomplete'} if any(status != 'UNKNOWN' and evidence.get('complete') is not True for status, evidence in outcomes) else set()))
    return 'UNKNOWN', {'observed': 'Selected command literal coverage was incomplete. Secret absence could not be assessed.',
                       'reason': '%d of %d selected definitions unassessed: %s' % (
                           sum(status == 'UNKNOWN' or evidence.get('complete') is not True for status, evidence in outcomes),
                           len(outcomes), ', '.join(reasons))}
