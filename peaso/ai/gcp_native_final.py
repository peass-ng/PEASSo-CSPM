"""Separate, default-off GCP Hardening native-final gate.

The committed v2 candidate is offline qualified only. The manifest must be
marked qualified after two paired hosted runs before runtime admission.
"""
import json
import os
from pathlib import Path


MANIFEST = Path(__file__).with_name('gcp_native_final_allowlist.json')
# The four direct-setting controls retain their exact field/value guards.
DIRECT = {
    'gcp.compute.secure_boot': ('shieldedInstanceConfig.enableSecureBoot', False),
    'gcp.gke.secrets_encryption': ('databaseEncryption.state', 'DECRYPTED'),
    'gcp.network.custom_subnets': ('autoCreateSubnetworks', True),
    'gcp.reviewed.compute.deletion_protection': ('deletionProtection', False),
}


def _manifest(path):
    try:
        value = json.loads(Path(path).read_bytes())
        if (type(value) is not dict or set(value) != {
                'version', 'provider', 'checks', 'replay_qualification'}
                or value['version'] != 2 or value['provider'] != 'gcp'
                or type(value['checks']) is not list):
            return None
        for row in value['checks']:
            if (type(row) is not dict or set(row) != {
                    'check_id', 'saved_native_failures',
                    'saved_initial_representatives', 'evidence_signatures'}
                    or not isinstance(row['check_id'], str)
                    or not row['check_id'].startswith('gcp')
                    or type(row['evidence_signatures']) is not list):
                return None
        qualification = value['replay_qualification']
        if (type(qualification) is not dict or set(qualification) != {'status'}
                or qualification['status'] not in {'pending_hosted', 'qualified'}):
            return None
        return value
    except (OSError, ValueError, TypeError, KeyError):
        return None


def candidate_check_ids(path=MANIFEST):
    """Return the manifest IDs for offline replay, including pending ones."""
    value = _manifest(path)
    return frozenset(row['check_id'] for row in value['checks']) if value else frozenset()


def admitted_check_ids(path=MANIFEST):
    """Require the enable switch and a qualified manifest."""
    if os.getenv('PEASO_GCP_HARDENING_NATIVE_FINAL_ENABLED') != '1':
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
