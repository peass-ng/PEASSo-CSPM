"""Fail-closed admission for audited native Hardening failures.

The committed manifest lists source-audited checks. Admission still requires
an explicit runtime switch and the exact manifest SHA-256 pin.
"""
import hashlib
import ast
from datetime import date
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
    pin = os.getenv('PEASO_HARDENING_NATIVE_FINAL_SHA256', '')
    if len(pin) != 64 or any(ch not in '0123456789abcdef' for ch in pin):
        return frozenset()
    try:
        raw = Path(path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin:
            return frozenset()
        manifest = json.loads(raw)
        if (type(manifest) is not dict or set(manifest) != {
                'version', 'source_scan_id', 'base_commit', 'replay_qualification', 'checks'}
                or type(manifest['version']) is not int or manifest['version'] != 2
                or manifest['source_scan_id'] != SOURCE_SCAN
                or manifest['base_commit'] != BASE_COMMIT):
            return frozenset()
        replay = manifest['replay_qualification']
        if (type(replay) is not dict or set(replay) != {'status', 'receipt_sha256'}
                or replay['status'] != 'qualified'
                or not _digest(replay['receipt_sha256'])):
            return frozenset()
        checks = manifest['checks']
        if type(checks) is not list:
            return frozenset()
        ids = set()
        for check in checks:
            if (type(check) is not dict or set(check) != {
                    'check_id', 'prod992_disagreements', 'prod992_reviewed_failures',
                    'audit_receipt_sha256', 'deterministic_evidence'}):
                return frozenset()
            ident = check['check_id']
            if (not isinstance(ident, str) or not ident.startswith('aws')
                    or not ident.strip() or ident in ids
                    or type(check['prod992_disagreements']) is not int
                    or check['prod992_disagreements'] != 0
                    or type(check['prod992_reviewed_failures']) is not int
                    or check['prod992_reviewed_failures'] < 1
                    or not _digest(check['audit_receipt_sha256'])
                    or not _deterministic_evidence(check['deterministic_evidence'])
                    or (check['deterministic_evidence']['operation']['kind'] == 'versioned_lookup_date'
                        and ident != 'aws.cb.lambda.runtime_not_deprecated_list')):
                return frozenset()
            ids.add(ident)
        return frozenset(ids)
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


def _digest(value):
    return (isinstance(value, str) and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def _deterministic_evidence(value):
    """Require an auditable pure operation over typed, recorded API fields.

    This describes the reviewed evaluator; it is not an interpreter for
    arbitrary predicates. Source audit must still prove the declared inputs
    and code path actually match the check implementation.
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
    if not (type(ref) is dict and set(ref) == {
            'path', 'symbol', 'source_sha256', 'audit_ref'}
            and all(_nonempty(ref[key]) for key in ref)
            and (ref['path'].startswith('peaso/checks/')
                 or ref['path'] in {
                     'peaso/unused_iam_aws_activity.py',
                     'peaso/unused_iam_aws_completion.py',
                     'peaso/unused_network_aws.py',
                 })
            and ref['path'].endswith('.py') and '..' not in ref['path'].split('/')
            and _digest(ref['source_sha256'])):
        return False
    root = Path(__file__).resolve().parents[2]
    source = (root / ref['path']).resolve()
    if not source.is_relative_to(root) or not source.is_file():
        return False
    body = source.read_bytes()
    if hashlib.sha256(body).hexdigest() != ref['source_sha256']:
        return False
    try:
        syntax = ast.parse(body)
    except (SyntaxError, UnicodeDecodeError):
        return False
    if not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == ref['symbol'] for node in ast.walk(syntax)):
        return False
    return kind != 'versioned_lookup_date' or _runtime_lookup_table(
        operation['lookup_table'], ref, syntax)


def _runtime_lookup_table(table, ref, syntax):
    """Admit only the reviewed Lambda runtime date table and expiry guard."""
    if (ref['path'] != 'peaso/checks/claude_aws_b_compute.py'
            or ref['symbol'] != 'lambda_runtime'
            or type(table) is not dict or set(table) != {
                'symbol', 'source_sha256', 'reviewed_at',
                'valid_through_symbol', 'audit_ref'}
            or table['symbol'] != 'RUNTIME_DEPRECATION'
            or table['source_sha256'] != ref['source_sha256']
            or table['reviewed_at'] != '2026-10-12'
            or table['valid_through_symbol'] != 'RUNTIME_POLICY_VALID_THROUGH'
            or table['audit_ref'] != 'peaso/checks/claude_aws_b_compute.py:109-158'):
        return False
    assignments = {
        target.id: node.value for node in syntax.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
    }
    reviewed = assignments.get('RUNTIME_POLICY_REVIEWED_AT')
    table_node = assignments.get('RUNTIME_DEPRECATION')
    valid_through = assignments.get('RUNTIME_POLICY_VALID_THROUGH')
    if (not isinstance(reviewed, ast.Constant)
            or reviewed.value != table['reviewed_at']
            or not isinstance(table_node, ast.Dict)
            or not table_node.keys
            or not isinstance(valid_through, ast.AST)
            or ast.unparse(valid_through) !=
                '(date.fromisoformat(RUNTIME_POLICY_REVIEWED_AT) + timedelta(days=180)).isoformat()'):
        return False
    keys = set()
    for key, value in zip(table_node.keys, table_node.values):
        if (not isinstance(key, ast.Constant) or type(key.value) is not str
                or not key.value or key.value in keys
                or not isinstance(value, ast.Constant) or type(value.value) is not str):
            return False
        keys.add(key.value)
        try:
            date.fromisoformat(value.value)
        except ValueError:
            return False
    return True


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
