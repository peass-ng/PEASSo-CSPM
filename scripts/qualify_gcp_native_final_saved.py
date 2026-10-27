#!/usr/bin/env python3
"""Aggregate private GCP report pairs into a sanitized, inactive receipt.

Each --pair is SCAN_ID PRE_AI_GZIP FINAL_GZIP. This proves saved-review
parity only; it neither launches models nor admits checks at runtime.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from scripts.audit_gcp_native_final_scalar import SPECS, audit, saved_replay, sha


ROOT = Path(__file__).resolve().parents[1]
SOURCE_AUDIT = ROOT / 'docs/ai-review/native-final-gcp-scalar-v1.json'


def aggregate(pairs):
    source = json.loads(SOURCE_AUDIT.read_text())
    if (source.get('status') != 'source_proven_replay_pending'
            or source.get('runtime_admitted') is not False
            or {row['check_id'] for row in source['checks']} != set(SPECS)
            or source != audit()):
        raise ValueError('source audit changed or was activated')
    if not pairs:
        raise ValueError('at least one saved pair required')
    seen_scans, seen_snapshots = set(), set()
    totals = Counter()
    differences = Counter()
    evidence_mismatches = Counter()
    scans = []
    for scan_id, pre, final in pairs:
        if (len(scan_id) != 32 or any(ch not in '0123456789abcdef' for ch in scan_id)
                or scan_id in seen_scans):
            raise ValueError('invalid or duplicate scan ID')
        seen_scans.add(scan_id)
        result = saved_replay(pre, final)
        if result['snapshot_id_sha256'] in seen_snapshots:
            raise ValueError('snapshot reused across scan pairs')
        seen_snapshots.add(result['snapshot_id_sha256'])
        for row in result['per_check']:
            cid = row['check_id']
            totals[cid] += row['native_failures']
            differences[cid] += row['parity_differences']
            evidence_mismatches[cid] += row['evidence_mismatches']
        scans.append({'scan_id': scan_id,
                      'pre_ai_sha256': result['pre_ai_sha256'],
                      'final_sha256': result['final_sha256'],
                      'snapshot_id_sha256': result['snapshot_id_sha256'],
                      'selected_failures': result['selected_failures'],
                      'exact_saved_parity': result['exact_saved_parity']})
    checks = []
    for cid in sorted(SPECS):
        count = totals[cid]
        clean = count > 0 and differences[cid] == evidence_mismatches[cid] == 0
        checks.append({'check_id': cid, 'observed_native_failures': count,
                       'parity_differences': differences[cid],
                       'evidence_mismatches': evidence_mismatches[cid],
                       'decision': 'saved_parity_proven' if clean else 'retain_ai'})
    return {'schema_version': 1, 'provider': 'gcp',
            'source_audit_sha256': sha(SOURCE_AUDIT),
            'source_commit': 'fc591041',
            'scan_count': len(scans), 'selected_failures': sum(totals.values()),
            'saved_parity_proven_checks': sum(row['decision'] == 'saved_parity_proven' for row in checks),
            'checks': checks, 'scans': sorted(scans, key=lambda row: row['scan_id']),
            'hosted_model_replay': False, 'runtime_admitted': False,
            'qualification_state': 'saved_parity_only'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair', nargs=3, action='append', metavar=('SCAN_ID', 'PRE', 'FINAL'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = aggregate(args.pair)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: receipt[key] for key in
                      ('scan_count', 'selected_failures', 'saved_parity_proven_checks',
                       'qualification_state')}))


if __name__ == '__main__':
    main()
