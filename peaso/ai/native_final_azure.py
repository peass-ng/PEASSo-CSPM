"""Separate, fail-closed Azure Hardening native-final admission.

The committed manifest is pending. It may be marked qualified only after a
hosted same-snapshot quality and cost replay.
"""

import json
import os
from pathlib import Path


MANIFEST = Path(__file__).with_name('native_final_azure_allowlist.json')
SOURCE_SCAN = 'a79ff6f9331246bd9e4f4bf6ba6fa207'
SNAPSHOT_ID = 'sha256:08597df6a1b6f6199eab1c8018409c969bcd9eff2e81b6c2f0bb2bdf76aea301'
BASE_COMMIT = 'f204f3a5b25991390cb6baf2572710c4da8342bd'
CHECK_KEYS = frozenset({'check_id', 'saved_fail_count', 'saved_ai_disagreements', 'source_kind',
                        'dependencies', 'source_file', 'source_line', 'source_basis'})


def _expected():
    try:
        checks = json.loads(MANIFEST.read_bytes())['checks']
        return {row['check_id']: row for row in checks}
    except (OSError, ValueError, TypeError, KeyError):
        return {}


EXPECTED = _expected()


def admitted_check_ids(path=MANIFEST):
    if os.getenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_ENABLED') != '1' or not EXPECTED:
        return frozenset()
    try:
        manifest = json.loads(Path(path).read_bytes())
        if (type(manifest) is not dict or set(manifest) != {
                'version', 'source_scan_id', 'snapshot_id', 'base_commit',
                'replay_qualification', 'checks'}
                or manifest['version'] != 2 or type(manifest['version']) is not int
                or manifest['source_scan_id'] != SOURCE_SCAN
                or manifest['snapshot_id'] != SNAPSHOT_ID
                or manifest['base_commit'] != BASE_COMMIT):
            return frozenset()
        replay = manifest['replay_qualification']
        if (type(replay) is not dict or set(replay) != {'status'}
                or replay['status'] != 'qualified'):
            return frozenset()
        checks = manifest['checks']
        if type(checks) is not list or len(checks) != len(EXPECTED):
            return frozenset()
        actual = {}
        for check in checks:
            if type(check) is not dict or set(check) != CHECK_KEYS:
                return frozenset()
            ident = check['check_id']
            if ident not in EXPECTED or ident in actual or check != EXPECTED[ident]:
                return frozenset()
            actual[ident] = check
        return frozenset(actual)
    except (OSError, ValueError, TypeError, KeyError):
        return frozenset()


def partition(rows, admitted, coverage=None):
    # A recorded item may still evaluate FAIL inside a partial collection.
    # Native-final admission requires complete check and collection envelopes
    # for the exact scope, even when the item's own fields are decisive.
    complete = set()
    if isinstance(coverage, list):
        seen = {}
        for item in coverage:
            if not isinstance(item, dict):
                continue
            level, scope = item.get('level'), item.get('scope')
            if level == 'check':
                key = ('check', item.get('check_id'), scope)
            elif level == 'collection':
                key = ('collection', item.get('type'), scope)
            else:
                continue
            seen.setdefault(key, []).append(item.get('status'))
        for ident, entry in EXPECTED.items():
            for key, statuses in seen.items():
                if (key[0] == 'check' and key[1] == ident and statuses == ['evaluated']
                        and all(seen.get(('collection', kind, key[2])) in (['collected'], ['empty'])
                                for kind in entry['dependencies'])):
                    complete.add((ident, key[2]))
    native, ai = [], []
    for row in rows:
        evidence = row.get('evidence')
        if (row.get('provider') == 'azure' and row.get('category') == 'hardening'
                and row.get('status') == 'FAIL'
                and row.get('scanner_status', 'FAIL') == 'FAIL'
                and not (isinstance(evidence, dict) and 'incomplete_dependencies' in evidence)
                and row.get('check_id') in admitted
                and (row.get('check_id'), row.get('scope')) in complete):
            native.append(row)
        else:
            ai.append(row)
    return native, ai
