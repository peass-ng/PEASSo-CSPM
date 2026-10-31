"""Fail-closed admission for audited native Hardening failures.

The committed manifest lists audited checks. Admission still requires an
explicit runtime switch and a qualified manifest.
"""
import json
import os
from pathlib import Path


MANIFEST = Path(__file__).with_name('native_final_allowlist.json')
SOURCE_SCAN = '992d7b8cbd4340a79e41139ba1a44c1e'
BASE_COMMIT = 'd3e0e0ebfc8cf85196951460ed6db99f59e99c19'


def admitted_check_ids(path=MANIFEST):
    """Return only explicitly qualified check IDs; malformed input disables all."""
    if os.getenv('PEASO_HARDENING_NATIVE_FINAL_ENABLED') != '1':
        return frozenset()
    try:
        manifest = json.loads(Path(path).read_bytes())
        if (type(manifest) is not dict or set(manifest) != {
                'version', 'source_scan_id', 'base_commit', 'replay_qualification', 'checks'}
                or type(manifest['version']) is not int or manifest['version'] != 2
                or manifest['source_scan_id'] != SOURCE_SCAN
                or manifest['base_commit'] != BASE_COMMIT):
            return frozenset()
        replay = manifest['replay_qualification']
        if (type(replay) is not dict or set(replay) != {'status'}
                or replay['status'] != 'qualified'):
            return frozenset()
        checks = manifest['checks']
        if type(checks) is not list:
            return frozenset()
        ids = set()
        for check in checks:
            if (type(check) is not dict or set(check) != {
                    'check_id', 'prod992_disagreements', 'prod992_reviewed_failures',
                    'deterministic_evidence'}):
                return frozenset()
            ident = check['check_id']
            if (not isinstance(ident, str) or not ident.startswith('aws')
                    or not ident.strip() or ident in ids
                    or type(check['prod992_disagreements']) is not int
                    or check['prod992_disagreements'] != 0
                    or type(check['prod992_reviewed_failures']) is not int
                    or check['prod992_reviewed_failures'] < 1
                    or not _deterministic_evidence(check['deterministic_evidence'])
                    or (check['deterministic_evidence']['operation']['kind'] == 'versioned_lookup_date'
                        and ident != 'aws.cb.lambda.runtime_not_deprecated_list')):
                return frozenset()
            ids.add(ident)
        return frozenset(ids)
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


def _nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def _deterministic_evidence(value):
    """Require an auditable pure operation over typed, recorded API fields.

    This describes the reviewed evaluator; it is not an interpreter for
    arbitrary predicates.
    """
    if type(value) is not dict or set(value) != {
            'source_fields', 'operation', 'scan_time', 'code_path_audit_ref'}:
        return False
    fields = value['source_fields']
    if type(fields) is not list or not fields:
        return False
    for field in fields:
        if (type(field) is not dict or set(field) != {
                'api', 'field_path', 'field_type', 'source_semantics',
                'recorded_evidence_ref'}
                or not all(_nonempty(field[key]) for key in (
                    'api', 'field_path', 'recorded_evidence_ref'))
                or field['field_type'] not in {
                    'boolean', 'number', 'timestamp', 'enum', 'list'}
                or field['source_semantics'] not in {
                    'recorded_api_field', 'recorded_api_timestamp'}
                or (field['field_type'] == 'timestamp') != (
                    field['source_semantics'] == 'recorded_api_timestamp')):
            return False
    operation = value['operation']
    if type(operation) is not dict or 'kind' not in operation:
        return False
    kind = operation['kind']
    operation_keys = {'kind', 'comparison', 'threshold', 'threshold_unit'}
    if kind == 'versioned_lookup_date':
        operation_keys.add('lookup_table')
        if type(operation.get('lookup_table')) is not dict:
            return False
    if set(operation) != operation_keys:
        return False
    comparison = operation['comparison']
    threshold = operation['threshold']
    unit = operation['threshold_unit']
    comparisons = {
        'literal_comparison': {'eq', 'ne'},
        'count_comparison': {'eq', 'ne', 'lt', 'lte', 'gt', 'gte'},
        'number_comparison': {'eq', 'ne', 'lt', 'lte', 'gt', 'gte'},
        'list_membership': {'contains', 'not_contains', 'all', 'any'},
        'boolean_combination': {'and', 'or'},
        'age_comparison': {'lt', 'lte', 'gt', 'gte'},
        'versioned_lookup_date': {'gte'},
    }
    if kind not in comparisons or comparison not in comparisons[kind]:
        return False
    if kind in {'count_comparison', 'age_comparison'}:
        if (type(threshold) is not int or threshold < 0
                or unit != ('days' if kind == 'age_comparison' else 'items')):
            return False
    elif kind == 'number_comparison':
        if (type(threshold) is not int or threshold < 0
                or unit not in {'days', 'characters', 'uses', 'port'}
                or not any(field['field_type'] == 'number' for field in fields)):
            return False
    elif kind == 'boolean_combination':
        if threshold is not None or unit is not None or len(fields) < 2:
            return False
    elif kind == 'versioned_lookup_date':
        if (threshold is not None or unit is not None or len(fields) != 2
                or {field['field_path'] for field in fields} != {'PackageType', 'Runtime'}
                or any(field['field_type'] != 'enum' for field in fields)):
            return False
    elif type(threshold) not in (bool, int, str) or (
            type(threshold) is str and len(threshold) > 128) or unit is not None:
        return False
    scan_time = value['scan_time']
    if kind in {'age_comparison', 'versioned_lookup_date'}:
        if (type(scan_time) is not dict or set(scan_time) != {
                'source_field', 'recorded_evidence_ref'}
                or not all(_nonempty(scan_time[key]) for key in scan_time)
                or (kind == 'age_comparison' and not any(
                    field['field_type'] == 'timestamp' for field in fields))
                or (kind == 'versioned_lookup_date' and scan_time['source_field'] not in {
                    '_provenance.collected_at', 'context.created_at'})):
            return False
    elif scan_time is not None:
        return False
    ref = value['code_path_audit_ref']
    return (type(ref) is dict and set(ref) == {'path', 'symbol', 'audit_ref'}
            and all(_nonempty(ref[key]) for key in ref)
            and (ref['path'].startswith('peaso/checks/')
                 or ref['path'] in {
                     'peaso/unused_iam_aws_activity.py',
                     'peaso/unused_iam_aws_completion.py',
                     'peaso/unused_network_aws.py',
                 })
            and ref['path'].endswith('.py') and '..' not in ref['path'].split('/'))


def partition(rows, admitted):
    """Select only original AWS Hardening FAILs by exact check ID."""
    native, ai = [], []
    for row in rows:
        evidence = row.get('evidence')
        if (row.get('provider') == 'aws' and row.get('category') == 'hardening'
                and row.get('status') == 'FAIL'
                and row.get('scanner_status', 'FAIL') == 'FAIL'
                and not (isinstance(evidence, dict) and 'incomplete_dependencies' in evidence)
                and row.get('check_id') in admitted):
            native.append(row)
        else:
            ai.append(row)
    return native, ai


def reviews(rows):
    return [{'finding_id': row['id'], 'verdict': 'FAIL', 'reason': ''} for row in rows]
