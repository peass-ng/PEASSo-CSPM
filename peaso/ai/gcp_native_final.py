"""Separate, default-off, source-pinned GCP Hardening native-final gate.

The committed v2 candidate is offline qualified only. Root must pin a new
hosted receipt after two paired runs before runtime admission can succeed.
"""
import hashlib
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name('gcp_native_final_allowlist.json')
AUDIT = ROOT / 'docs/ai-review/native-final-gcp-exercised-audit-v2.json'
AUDIT_SHA256 = '73c3ded77b64866f99640af52281a428ed9f2fb0ef6f222503d6d6965337bfd9'
HOSTED_RECEIPT_SHA256 = None
# The four direct-setting controls retain their exact field/value guards.
DIRECT = {
    'gcp.compute.secure_boot': ('shieldedInstanceConfig.enableSecureBoot', False),
    'gcp.gke.secrets_encryption': ('databaseEncryption.state', 'DECRYPTED'),
    'gcp.network.custom_subnets': ('autoCreateSubnetworks', True),
    'gcp.reviewed.compute.deletion_protection': ('deletionProtection', False),
}


def _digest(value):
    return (isinstance(value, str) and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _audit():
    try:
        if hashlib.sha256(AUDIT.read_bytes()).hexdigest() != AUDIT_SHA256:
            return None
        value = json.loads(AUDIT.read_text())
        if value['version'] != 2 or value['provider'] != 'gcp' or value['hosted_qualified']:
            return None
        checks = {row['check_id']: row for row in value['checks'] if row['decision'] == 'admit'}
        if len(checks) != 25 or sorted(checks) != value['admitted_check_ids']:
            return None
        return checks
    except (OSError, ValueError, TypeError, KeyError):
        return None


def _manifest(path):
    try:
        checks = _audit()
        if checks is None:
            return None
        value = json.loads(Path(path).read_bytes())
        if (type(value) is not dict or set(value) != {
                'version', 'provider', 'audit_sha256', 'source_sha256',
                'checks', 'replay_qualification'}
                or value['version'] != 2 or value['provider'] != 'gcp'
                or value['audit_sha256'] != AUDIT_SHA256):
            return None
        expected = {row['source']: row['source_sha256'] for row in checks.values()}
        if value['source_sha256'] != expected:
            return None
        if value['checks'] != [
                {'check_id': cid, 'saved_native_failures': row['rows'],
                 'saved_initial_representatives': row['representatives'],
                 'evidence_signatures': row['evidence_signatures']}
                for cid, row in sorted(checks.items())]:
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
        for source, digest in expected.items():
            if hashlib.sha256((ROOT / source).read_bytes()).hexdigest() != digest:
                return None
        return value
    except (OSError, ValueError, TypeError, KeyError):
        return None


def candidate_check_ids(path=MANIFEST):
    """Return the source-proven IDs for offline replay, including pending ones."""
    value = _manifest(path)
    return frozenset(row['check_id'] for row in value['checks']) if value else frozenset()


def admitted_check_ids(path=MANIFEST):
    """Require enable switch, exact manifest bytes, and new hosted pin."""
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
    return (frozenset(row['check_id'] for row in value['checks']) if value is not None
            and value['replay_qualification']['status'] == 'qualified' else frozenset())


def _signature(evidence):
    return [[key, type(value).__name__] for key, value in sorted(evidence.items())]


def partition(rows, admitted, coverage=None):
    """Substitute only saved-shape GCP Hardening FAIL observations."""
    from .native_final_coverage import complete_scopes

    value = _manifest(MANIFEST)
    specs = {row['check_id']: row for row in value['checks']} if value else {}
    complete = complete_scopes(coverage, set(specs) & set(admitted))
    native, ai = [], []
    for row in rows:
        cid = row.get('check_id')
        evidence = row.get('evidence')
        spec = specs.get(cid) if cid in admitted else None
        direct = DIRECT.get(cid)
        if (spec is not None and row.get('provider') == 'gcp'
                and row.get('category') == 'hardening'
                and row.get('status') == 'FAIL'
                and row.get('scanner_status', 'FAIL') == 'FAIL'
                and (cid, row.get('scope')) in complete
                and type(evidence) is dict
                and 'incomplete_dependencies' not in evidence
                and _signature(evidence) in spec['evidence_signatures']
                and (direct is None or (evidence.get('field') == direct[0]
                       and type(evidence.get('configured')) is type(direct[1])
                       and evidence.get('configured') == direct[1]))):
            native.append(row)
        else:
            ai.append(row)
    return native, ai
