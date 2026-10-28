"""Separate, fail-closed Azure Hardening native-final admission.

The committed manifest is pending. Root may qualify it only after a hosted
same-snapshot quality and cost replay and an exact manifest SHA pin.
"""

import hashlib
import json
import os
from pathlib import Path


MANIFEST = Path(__file__).with_name('native_final_azure_allowlist.json')
SOURCE_SCAN = 'a79ff6f9331246bd9e4f4bf6ba6fa207'
SNAPSHOT_ID = 'sha256:08597df6a1b6f6199eab1c8018409c969bcd9eff2e81b6c2f0bb2bdf76aea301'
BASE_COMMIT = 'f204f3a5b25991390cb6baf2572710c4da8342bd'
SOURCE_PROOF_SHA256 = 'a1367e6ce1cecb5a87c768a52704a5be87d7cbae50f2fca45df376650c3a829c'
SOURCE_HASHES = {
    'peaso/checks/azure.py': '616d104fce5d17c8ec66f74b62855b56a04678f1f224cf15d2d79e7c2dfcdd4e',
    'peaso/checks/azure_extended.py': '9c05c602d4279a46c6926b04041a9c8a4d67b3532d8677eb3ca07ee08927517a',
    'peaso/checks/facts.py': '15d83fc5f44bfca7bd3022f7528bfd54c5738d6459fe999f59c2fd4498a1c926',
    'peaso/collectors/azure.py': '7f44e70205f6fb4ffbea3b787af2947871236d16e50095eb8660f6ac846d690f',
}
EXPECTED = {
    'azure.defender.standard_tier': (12, 'security_pricing', ('name', 'properties.pricingTier')),
    'azure.disk.private_export': (5, 'disk', ('properties.publicNetworkAccess', 'properties.networkAccessPolicy')),
    'azure.vault.no_public_network': (2, 'vault', ('properties.publicNetworkAccess',)),
    'azure.vault.rbac': (2, 'vault', ('properties.enableRbacAuthorization',)),
}


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def admitted_check_ids(path=MANIFEST):
    if os.getenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_ENABLED') != '1':
        return frozenset()
    pin = os.getenv('PEASO_AZURE_HARDENING_NATIVE_FINAL_SHA256', '')
    if not _digest(pin):
        return frozenset()
    try:
        raw = Path(path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin:
            return frozenset()
        manifest = json.loads(raw)
        if (type(manifest) is not dict or set(manifest) != {
                'version', 'source_scan_id', 'snapshot_id', 'base_commit',
                'source_proof_sha256', 'source_hashes', 'replay_qualification', 'checks'}
                or manifest['version'] != 1 or type(manifest['version']) is not int
                or manifest['source_scan_id'] != SOURCE_SCAN
                or manifest['snapshot_id'] != SNAPSHOT_ID
                or manifest['base_commit'] != BASE_COMMIT
                or manifest['source_proof_sha256'] != SOURCE_PROOF_SHA256
                or manifest['source_hashes'] != SOURCE_HASHES):
            return frozenset()
        replay = manifest['replay_qualification']
        if (type(replay) is not dict or set(replay) != {
                'status', 'saved_receipt_sha256', 'hosted_receipt_sha256'}
                or replay['status'] != 'qualified'
                or not _digest(replay['saved_receipt_sha256'])
                or not _digest(replay['hosted_receipt_sha256'])):
            return frozenset()
        checks = manifest['checks']
        if type(checks) is not list or len(checks) != len(EXPECTED):
            return frozenset()
        actual = {}
        for check in checks:
            if type(check) is not dict or set(check) != {
                    'check_id', 'saved_fail_count', 'saved_ai_disagreements',
                    'source_kind', 'source_fields'}:
                return frozenset()
            ident = check['check_id']
            if ident not in EXPECTED or ident in actual:
                return frozenset()
            count, kind, fields = EXPECTED[ident]
            if (type(check['saved_fail_count']) is not int or check['saved_fail_count'] != count
                    or type(check['saved_ai_disagreements']) is not int
                    or check['saved_ai_disagreements'] != 0
                    or check['source_kind'] != kind
                    or check['source_fields'] != list(fields)):
                return frozenset()
            actual[ident] = check
        root = Path(__file__).resolve().parents[2]
        if hashlib.sha256((root / 'docs/ai-review/native-final-azure-core-proof-v1.json').read_bytes()).hexdigest() != SOURCE_PROOF_SHA256:
            return frozenset()
        for source, digest in SOURCE_HASHES.items():
            if hashlib.sha256((root / source).read_bytes()).hexdigest() != digest:
                return frozenset()
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
        for ident, (_, kind, _) in EXPECTED.items():
            for key, statuses in seen.items():
                if (key[0] == 'check' and key[1] == ident and statuses == ['evaluated']
                        and seen.get(('collection', kind, key[2])) == ['collected']):
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
