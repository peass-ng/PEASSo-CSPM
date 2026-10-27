#!/usr/bin/env python3
"""Verify an inactive native-final candidate against saved 992 review outcomes.

The receipt contains counts and hashes only. This is a saved-review parity gate,
not a hosted model replay or authorization to activate the manifest.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

from peaso.ai.native_final import partition, reviews

PRE_AI_SHA256 = '4dcaa76a21c6b3bfff2b4859c1d4c763964c92c69041fe2d95702315fffde2ba'
FINAL_SHA256 = '399024cf7f69b4b7dd99921766b087514a44512cba244ad9d50de696f83d85b0'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def observations(report):
    rows = [row for group in report['findings']
            for row in (group.get('observations') or [group])]
    by_id = {row['id']: row for row in rows}
    if len(rows) != len(by_id):
        raise ValueError('duplicate finding IDs in saved report')
    return by_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate')
    parser.add_argument('pre_ai_report')
    parser.add_argument('final_report')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    candidate = json.loads(Path(args.candidate).read_text())
    if (candidate.get('source_scan_id') != '992d7b8cbd4340a79e41139ba1a44c1e'
            or candidate.get('replay_qualification') !=
            {'status': 'pending', 'receipt_sha256': None}):
        raise ValueError('expected inactive exact-992 candidate')
    selected_checks = {row['check_id'] for row in candidate['checks']}
    if len(selected_checks) != len(candidate['checks']):
        raise ValueError('duplicate candidate check IDs')
    if (digest(args.pre_ai_report) != PRE_AI_SHA256
            or digest(args.final_report) != FINAL_SHA256):
        raise ValueError('saved 992 report source hash changed')
    with gzip.open(args.pre_ai_report, 'rt') as source:
        before = json.load(source)
    with gzip.open(args.final_report, 'rt') as source:
        after = json.load(source)
    if before['snapshot_id'] != after['snapshot_id'] or before['provider'] != 'aws':
        raise ValueError('saved reports are from different scans')
    native_by_id = observations(before)
    final_by_id = observations(after)
    hardening = [row for row in native_by_id.values()
                 if row.get('category') == 'hardening' and row.get('status') == 'FAIL']
    selected, remaining = partition(hardening, frozenset(selected_checks))
    selected_ids = {row['id'] for row in selected}
    if len(selected_ids) != len(selected):
        raise ValueError('duplicate selected finding IDs')
    expected_count = sum(row['prod992_reviewed_failures'] for row in candidate['checks'])
    if len(selected) != expected_count:
        raise ValueError('candidate count differs from saved native findings')
    ai_reviews = after['ai']['reviews']['hardening']
    by_review = {row['finding_id']: row for row in ai_reviews}
    if len(ai_reviews) != len(by_review):
        raise ValueError('duplicate saved Hardening review IDs')
    native_reviews = {row['finding_id']: row for row in reviews(selected)}
    if selected_ids != set(native_reviews):
        raise ValueError('native-final review IDs differ from partition')
    by_check = Counter()
    for row in selected:
        ident = row['id']
        saved = by_review.get(ident)
        final = final_by_id.get(ident)
        if (saved != native_reviews[ident] or final is None
                or final.get('status') != row['status']
                or final.get('severity') != row.get('severity')
                or final.get('base_severity') != row.get('base_severity')
                or final.get('evidence') != row.get('evidence')
                or final.get('evidence_summary') != row.get('evidence_summary')):
            raise ValueError('saved outcome/evidence parity failed for selected finding')
        by_check[row['check_id']] += 1
    for check in candidate['checks']:
        if by_check[check['check_id']] != check['prod992_reviewed_failures']:
            raise ValueError('per-check saved review count changed')
    receipt = {
        'schema_version': 1,
        'scan_id': candidate['source_scan_id'],
        'candidate_sha256': digest(args.candidate),
        'pre_ai_sha256': digest(args.pre_ai_report),
        'final_sha256': digest(args.final_report),
        'candidate_check_ids': len(selected_checks),
        'native_final_saved_failures': len(selected),
        'remaining_hardening_failures': len(remaining),
        'exact_saved_review_rows_replaced': len(selected),
        'verdict_severity_evidence_parity': True,
        'hosted_model_replay': False,
        'manifest_activated': False,
        'per_check': [
            {'check_id': ident, 'saved_failures': by_check[ident]}
            for ident in sorted(by_check)
        ],
    }
    Path(args.output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: receipt[key] for key in (
        'candidate_check_ids', 'native_final_saved_failures',
        'remaining_hardening_failures', 'verdict_severity_evidence_parity')}))


if __name__ == '__main__':
    main()
