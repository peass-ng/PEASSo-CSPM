"""Verify the pending four-check Azure candidate against one saved scan.

This is an offline saved-review parity check, not a hosted model or cost gate.
Only counts and hashes are emitted.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

from peaso.ai.finding_reviews import apply_review
from peaso.ai.native_final_azure import (
    EXPECTED, SOURCE_SCAN, SNAPSHOT_ID, SOURCE_PROOF_SHA256, SOURCE_HASHES, partition)
from peaso.ai.native_final import reviews as synthetic_reviews


PRE_SHA = '9ed2de0adc5adde4255108177745f76fe87796ad4ec3ca4d8d7febe6a44e84af'
FINAL_SHA = '452f7d615cbfa23bed95b6943aefa1242e7016c62dd879dd0a62b2919f2dd1b9'


def _read(path, expected):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('saved_report_sha256_mismatch')
    return json.loads(gzip.decompress(raw) if raw[:2] == b'\x1f\x8b' else raw)


def _observations(report):
    rows = [row for group in report['findings'] for row in group.get('observations') or [group]]
    by_id = {row['id']: row for row in rows}
    if len(rows) != len(by_id):
        raise ValueError('duplicate_finding_id')
    return by_id


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def replay(candidate, before, after):
    if (candidate.get('source_scan_id') != SOURCE_SCAN
            or candidate.get('snapshot_id') != SNAPSHOT_ID
            or candidate.get('source_proof_sha256') != SOURCE_PROOF_SHA256
            or candidate.get('source_hashes') != SOURCE_HASHES
            or candidate.get('replay_qualification') != {
                'status': 'pending', 'saved_receipt_sha256': None,
                'hosted_receipt_sha256': None}
            or before.get('provider') != 'azure' or after.get('provider') != 'azure'
            or before.get('snapshot_id') != SNAPSHOT_ID
            or after.get('snapshot_id') != SNAPSHOT_ID):
        raise ValueError('wrong_scan_or_active_candidate')
    checks = candidate.get('checks')
    if (type(checks) is not list or {row['check_id'] for row in checks} != set(EXPECTED)
            or len(checks) != len(EXPECTED)):
        raise ValueError('wrong_candidate_checks')
    for row in checks:
        count, kind, fields = EXPECTED[row['check_id']]
        if (set(row) != {'check_id', 'saved_fail_count', 'saved_ai_disagreements',
                         'source_kind', 'source_fields'}
                or row.get('saved_fail_count') != count
                or row.get('saved_ai_disagreements') != 0
                or row.get('source_kind') != kind
                or row.get('source_fields') != list(fields)):
            raise ValueError('wrong_candidate_count')
    native = _observations(before)
    final = _observations(after)
    if set(native) - set(final):
        raise ValueError('missing_final_observations')
    hardening = [row for row in native.values()
                 if row.get('category') == 'hardening' and row.get('status') == 'FAIL']
    stage = after['ai']['stage_inputs']['hardening']
    if len(stage) != len(set(stage)) or set(stage) != {row['id'] for row in hardening}:
        raise ValueError('saved_stage_input_mismatch')
    selected, remaining = partition(hardening, set(EXPECTED), before.get('coverage'))
    selected_ids = {row['id'] for row in selected}
    remaining_ids = {row['id'] for row in remaining}
    if len(selected_ids) != len(selected) or len(selected) != sum(v[0] for v in EXPECTED.values()):
        raise ValueError('selected_count_mismatch')
    original_reviews = after['ai']['reviews']['hardening']
    review_by_id = {row['finding_id']: row for row in original_reviews}
    if len(review_by_id) != len(original_reviews) or set(review_by_id) != set(stage):
        raise ValueError('review_input_mismatch')
    synthetic_by_id = {row['finding_id']: row for row in synthetic_reviews(selected)}
    if any(review_by_id[ident] != synthetic_by_id[ident] for ident in selected_ids):
        raise ValueError('selected_saved_review_differs')
    candidate_reviews = [synthetic_by_id.get(row['finding_id'], row) for row in original_reviews]
    if candidate_reviews != original_reviews:
        raise ValueError('priorities_review_input_changed')
    fields = ('status', 'severity', 'base_severity', 'evidence', 'evidence_summary')
    for ident in selected_ids:
        if any(native[ident].get(key) != final[ident].get(key) for key in fields):
            raise ValueError('selected_final_finding_changed')
    projected = {}
    for ident in stage:
        review = {} if ident in selected_ids else {('hardening', ident): review_by_id[ident]}
        projected[ident] = apply_review(native[ident], review)
        if any(projected[ident].get(key) != final[ident].get(key) for key in fields):
            raise ValueError('projected_final_finding_changed')
    by_check = Counter(native[ident]['check_id'] for ident in selected_ids)
    if any(by_check[ident] != EXPECTED[ident][0] for ident in EXPECTED):
        raise ValueError('per_check_count_mismatch')
    return {
        'version': 1,
        'scan_id': SOURCE_SCAN,
        'snapshot_id': SNAPSHOT_ID,
        'pre_ai_sha256': PRE_SHA,
        'final_sha256': FINAL_SHA,
        'selected_check_count': len(EXPECTED),
        'selected_native_fail_count': len(selected_ids),
        'remaining_ai_input_count': len(remaining_ids),
        'original_ai_input_count': len(stage),
        'remaining_ai_input_ids_sha256': _digest(sorted(remaining_ids)),
        'saved_review_input_sha256': _digest(original_reviews),
        'candidate_review_input_sha256': _digest(candidate_reviews),
        'projected_hardening_public_fields_sha256': _digest({ident: {key: projected[ident].get(key)
                                                             for key in fields} for ident in sorted(projected)}),
        'saved_hardening_public_fields_sha256': _digest({ident: {key: final[ident].get(key)
                                                         for key in fields} for ident in sorted(projected)}),
        'saved_actions_sha256': _digest(after['ai']['actions']),
        'candidate_actions_sha256': _digest(after['ai']['actions']),
        'per_check': [{'check_id': ident, 'selected_fail_count': by_check[ident]}
                      for ident in sorted(EXPECTED)],
        'saved_review_and_public_finding_action_parity': True,
        'hosted_model_replay': False,
        'manifest_activated': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('pre_ai_report', type=Path)
    parser.add_argument('final_report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = replay(json.loads(args.candidate.read_text()),
                     _read(args.pre_ai_report, PRE_SHA), _read(args.final_report, FINAL_SHA))
    receipt['candidate_sha256'] = hashlib.sha256(args.candidate.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: receipt[key] for key in (
        'selected_native_fail_count', 'remaining_ai_input_count',
        'saved_review_and_public_finding_action_parity')}, sort_keys=True))


if __name__ == '__main__':
    main()
