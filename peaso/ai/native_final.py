"""Fail-closed admission for audited native Hardening failures.

The committed manifest is intentionally empty. A replay-qualified revision must
be reviewed and pinned by its exact SHA-256 before any row can bypass AI.
"""
import hashlib
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
                or type(manifest['version']) is not int or manifest['version'] != 1
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
                    'audit_receipt_sha256', 'direct_api_setting_evidence'}):
                return frozenset()
            ident = check['check_id']
            if (not isinstance(ident, str) or not ident.startswith('aws')
                    or not ident.strip() or ident in ids
                    or type(check['prod992_disagreements']) is not int
                    or check['prod992_disagreements'] != 0
                    or type(check['prod992_reviewed_failures']) is not int
                    or check['prod992_reviewed_failures'] < 1
                    or not _digest(check['audit_receipt_sha256'])
                    or not _direct_setting(check['direct_api_setting_evidence'])):
                return frozenset()
            ids.add(ident)
        return frozenset(ids)
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


def _digest(value):
    return (isinstance(value, str) and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _direct_setting(value):
    return (type(value) is dict and set(value) == {
        'api', 'setting_path', 'recorded_evidence_ref'}
        and all(isinstance(value[key], str) and value[key].strip()
                for key in ('api', 'setting_path', 'recorded_evidence_ref')))


def partition(rows, admitted):
    """Select only original AWS Hardening FAILs by exact check ID."""
    native, ai = [], []
    for row in rows:
        if (row.get('provider') == 'aws' and row.get('category') == 'hardening'
                and row.get('status') == 'FAIL' and row.get('check_id') in admitted):
            native.append(row)
        else:
            ai.append(row)
    return native, ai


def reviews(rows):
    return [{'finding_id': row['id'], 'verdict': 'FAIL', 'reason': ''} for row in rows]
