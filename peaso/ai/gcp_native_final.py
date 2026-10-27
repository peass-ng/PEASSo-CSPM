"""Separate, default-off GCP native-final admission for reviewed scalar FAILs.

The committed candidate is intentionally pending a hosted quality/cost gate.
Even with the enable switch set, pending qualification admits no findings.
"""
import hashlib
import json
import os
from pathlib import Path


MANIFEST = Path(__file__).with_name('gcp_native_final_allowlist.json')
SOURCE_AUDIT_SHA256 = '1431f5d57a308d4483de4a5c3408709e137b3e353c602f8a1d87f520dcac781f'
SAVED_PARITY_SHA256 = 'f33b642caadd6335d96f75d871d8f73a5fd37b92909bb990eadb05e31c26da65'
# Root must repin this to the verified hosted receipt in a later code review.
HOSTED_RECEIPT_SHA256 = None
SOURCE_SHA256 = {
    'peaso/checks/__init__.py': '9e30d82d62313b05b8b0c8c83b4c3bb1de339563dd8976fc2d59929cce4587ae',
    'peaso/checks/facts.py': '15d83fc5f44bfca7bd3022f7528bfd54c5738d6459fe999f59c2fd4498a1c926',
    'peaso/checks/gcp.py': '2a05ef582c4527eb97cf757ec9419cb0d8eb7a61bc33be76e02c8a7721eb6bd6',
    'peaso/checks/gcp_extended.py': 'f2d535d449b2babb2d7ba61d839be491b0c83c25642b5f63e41051ffec2689ae',
}
# These IDs alone have source proof and exact saved AI/finding parity.
CHECKS = {
    'gcp.compute.secure_boot': ('shieldedInstanceConfig.enableSecureBoot', False, 6),
    'gcp.gke.secrets_encryption': ('databaseEncryption.state', 'DECRYPTED', 5),
    'gcp.network.custom_subnets': ('autoCreateSubnetworks', True, 6),
    'gcp.reviewed.compute.deletion_protection': ('deletionProtection', False, 6),
}


def _digest(value):
    return (isinstance(value, str) and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _manifest(path):
    try:
        value = json.loads(Path(path).read_bytes())
        if (type(value) is not dict or set(value) != {
                'version', 'provider', 'source_audit_sha256', 'saved_parity_sha256',
                'source_sha256', 'checks', 'replay_qualification'}
                or type(value['version']) is not int or value['version'] != 1
                or value['provider'] != 'gcp'
                or value['source_audit_sha256'] != SOURCE_AUDIT_SHA256
                or value['saved_parity_sha256'] != SAVED_PARITY_SHA256
                or value['source_sha256'] != SOURCE_SHA256):
            return None
        rows = value['checks']
        if (type(rows) is not list or len(rows) != len(CHECKS)
                or rows != [{'check_id': cid, 'field_path': path, 'failing_value': bad,
                             'saved_native_failures': count}
                            for cid, (path, bad, count) in sorted(CHECKS.items())]):
            return None
        qualification = value['replay_qualification']
        if (type(qualification) is not dict
                or set(qualification) != {'status', 'hosted_receipt_sha256'}
                or qualification['status'] not in {'pending_hosted', 'qualified'}
                or (qualification['status'] == 'qualified') !=
                   (_digest(qualification['hosted_receipt_sha256'])
                    and qualification['hosted_receipt_sha256'] == HOSTED_RECEIPT_SHA256)
                or (qualification['status'] == 'pending_hosted'
                    and qualification['hosted_receipt_sha256'] is not None)):
            return None
        root = Path(__file__).resolve().parents[2]
        for source, digest in SOURCE_SHA256.items():
            if hashlib.sha256((root / source).read_bytes()).hexdigest() != digest:
                return None
        return value
    except (OSError, ValueError, TypeError, KeyError):
        return None


def candidate_check_ids(path=MANIFEST):
    """Return the source-proven IDs for offline replay, including pending ones."""
    return frozenset(CHECKS) if _manifest(path) is not None else frozenset()


def admitted_check_ids(path=MANIFEST):
    """Require an explicit enabled switch, exact bytes, and hosted qualification."""
    if os.getenv('PEASO_GCP_HARDENING_NATIVE_FINAL_ENABLED') != '1':
        return frozenset()
    pin = os.getenv('PEASO_GCP_HARDENING_NATIVE_FINAL_SHA256', '')
    if not _digest(pin):
        return frozenset()
    try:
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != pin:
            return frozenset()
    except OSError:
        return frozenset()
    value = _manifest(path)
    return (frozenset(CHECKS) if value is not None
            and value['replay_qualification']['status'] == 'qualified' else frozenset())


def partition(rows, admitted):
    """Substitute only bound GCP Hardening FAIL observations."""
    native, ai = [], []
    for row in rows:
        check_id = row.get('check_id')
        evidence = row.get('evidence')
        spec = CHECKS.get(check_id) if check_id in admitted else None
        if (spec is not None and row.get('provider') == 'gcp'
                and row.get('category') == 'hardening'
                and row.get('status') == 'FAIL'
                and row.get('scanner_status', 'FAIL') == 'FAIL'
                and type(evidence) is dict
                and 'incomplete_dependencies' not in evidence
                and evidence.get('field') == spec[0]
                and type(evidence.get('configured')) is type(spec[1])
                and evidence.get('configured') == spec[1]):
            native.append(row)
        else:
            ai.append(row)
    return native, ai
