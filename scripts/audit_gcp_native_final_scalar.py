#!/usr/bin/env python3
"""Audit the exact GCP scalar Hardening candidates without enabling them.

Run with Python 3.12. The default receipt contains only source hashes and
fixture outcomes. Optional saved reports add exact review and finding parity.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

from peaso.checks import CHECKS, evaluate_check
from peaso.checks.facts import FIELD_SPECS
from peaso.checks.fixtures import CASES


ROOT = Path(__file__).resolve().parents[1]
SPECS = {
    'gcp.compute.integrity_monitoring': ('shieldedInstanceConfig.enableIntegrityMonitoring', True, False),
    'gcp.compute.secure_boot': ('shieldedInstanceConfig.enableSecureBoot', True, False),
    'gcp.compute.shielded_vtpm': ('shieldedInstanceConfig.enableVtpm', True, False),
    'gcp.gke.secrets_encryption': ('databaseEncryption.state', 'ENCRYPTED', 'DECRYPTED'),
    'gcp.network.custom_subnets': ('autoCreateSubnetworks', False, True),
    'gcp.reviewed.compute.automatic_restart': ('scheduling.automaticRestart', True, False),
    'gcp.reviewed.compute.confidential_computing': ('confidentialInstanceConfig.enableConfidentialCompute', True, False),
    'gcp.reviewed.compute.deletion_protection': ('deletionProtection', True, False),
    'gcp.reviewed.compute.maintenance_migrate': ('scheduling.onHostMaintenance', 'MIGRATE', 'TERMINATE'),
    'gcp.reviewed.loadbalancer.backend_logging': ('logConfig.enable', True, False),
    'gcp.sql.backups': ('settings.backupConfiguration.enabled', True, False),
    'gcp.sql.no_public_ip': ('settings.ipConfiguration.ipv4Enabled', False, True),
}
SOURCES = ('peaso/checks/gcp.py', 'peaso/checks/gcp_extended.py',
           'peaso/checks/facts.py', 'peaso/checks/__init__.py')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def observations(report):
    rows = [row for group in report['findings']
            for row in (group.get('observations') or [group])]
    by_id = {row['id']: row for row in rows}
    if len(rows) != len(by_id):
        raise ValueError('duplicate finding ID')
    return by_id


def saved_replay(before_path, after_path):
    with gzip.open(before_path, 'rt') as stream:
        before = json.load(stream)
    with gzip.open(after_path, 'rt') as stream:
        after = json.load(stream)
    if (before.get('provider') != 'gcp' or after.get('provider') != 'gcp'
            or not before.get('snapshot_id')
            or before['snapshot_id'] != after.get('snapshot_id')):
        raise ValueError('saved reports do not bind to one GCP snapshot')
    native = observations(before)
    final = observations(after)
    reviews = after.get('ai', {}).get('reviews', {}).get('hardening', [])
    by_review = {row['finding_id']: row for row in reviews}
    if len(reviews) != len(by_review):
        raise ValueError('duplicate Hardening review ID')
    selected = [row for row in native.values() if row.get('provider') == 'gcp'
                and row.get('category') == 'hardening' and row.get('status') == 'FAIL'
                and row.get('scanner_status', 'FAIL') == 'FAIL'
                and not (isinstance(row.get('evidence'), dict)
                         and 'incomplete_dependencies' in row['evidence'])
                and row.get('check_id') in SPECS]
    counts = Counter()
    differences = Counter()
    evidence_mismatches = Counter()
    for row in selected:
        ident = row['id']
        cid = row['check_id']
        counts[cid] += 1
        path, _, bad = SPECS[cid]
        evidence = row.get('evidence')
        if (not isinstance(evidence, dict) or evidence.get('field') != path
                or type(evidence.get('configured')) is not type(bad)
                or evidence.get('configured') != bad):
            evidence_mismatches[cid] += 1
        if by_review.get(ident) != {'finding_id': ident, 'verdict': 'FAIL', 'reason': ''}:
            differences[cid] += 1
        published = final.get(ident)
        if published is None or any(published.get(key) != row.get(key) for key in
                ('status', 'severity', 'base_severity', 'evidence', 'evidence_summary')):
            differences[cid] += 1
    return {
        'pre_ai_sha256': sha(before_path), 'final_sha256': sha(after_path),
        'snapshot_id_sha256': hashlib.sha256(before['snapshot_id'].encode()).hexdigest(),
        'selected_failures': len(selected),
        'per_check': [{'check_id': cid, 'native_failures': counts[cid],
                       'parity_differences': differences[cid],
                       'evidence_mismatches': evidence_mismatches[cid]}
                      for cid in sorted(SPECS)],
        'exact_saved_parity': not differences and not evidence_mismatches and bool(selected),
    }


def audit(before_path=None, after_path=None):
    registry = {check.id: check for check in CHECKS}
    actual = {cid for cid in FIELD_SPECS if cid.startswith('gcp.')
              and cid in registry and registry[cid].category == 'hardening'}
    if actual != set(SPECS):
        raise ValueError('GCP scalar Hardening inventory changed')
    rows = []
    for cid, (path, good, bad) in sorted(SPECS.items()):
        check = registry[cid]
        spec = FIELD_SPECS[cid]
        if (check.provider != 'gcp' or check.category != 'hardening'
                or check.target != 'resource' or spec != {
                    'path': path, 'good': good, 'bad': bad, 'expected': type(good)}):
            raise ValueError('scalar source contract changed: ' + cid)
        case = CASES[cid]
        expected = {'pass': 'PASS', 'fail': 'FAIL', 'missing': 'UNKNOWN',
                    'malformed': 'UNKNOWN'}
        for name, status in expected.items():
            actual_status, _ = evaluate_check(cid, case[name])
            if actual_status != status:
                raise ValueError('fixture replay changed: ' + cid + ' ' + name)
        denied = json.loads(json.dumps(case['fail']))
        denied['collection_status'] = 'denied'
        if evaluate_check(cid, denied)[0] != 'UNKNOWN':
            raise ValueError('denied source became FAIL: ' + cid)
        rows.append({'check_id': cid, 'resource_kind': check.kind,
                     'api_field_path': path, 'expected_type': type(good).__name__,
                     'passing_value': good, 'failing_value': bad,
                     'source_ref': 'peaso/checks/gcp.py:8-19' if not cid.startswith('gcp.reviewed.')
                     else 'peaso/checks/gcp_extended.py:22-41',
                     'evaluator_ref': 'peaso/checks/facts.py:56-70',
                     'fixture_outcomes': expected | {'denied': 'UNKNOWN'}})
    result = {'schema_version': 1, 'provider': 'gcp',
              'base_commit': 'f204f3a5', 'candidate_count': len(rows),
              'status': 'source_proven_replay_pending', 'runtime_admitted': False,
              'source_sha256': {name: sha(ROOT / name) for name in SOURCES},
              'checks': rows,
              'saved_replay': saved_replay(before_path, after_path)
              if before_path and after_path else None}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pre-ai-report', type=Path)
    parser.add_argument('--final-report', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if bool(args.pre_ai_report) != bool(args.final_report):
        parser.error('both saved reports are required for parity replay')
    result = audit(args.pre_ai_report, args.final_report)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'candidate_count': result['candidate_count'],
                      'status': result['status'],
                      'saved_replay': result['saved_replay'] is not None}))


if __name__ == '__main__':
    main()
