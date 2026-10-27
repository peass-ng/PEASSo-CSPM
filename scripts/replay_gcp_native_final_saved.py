#!/usr/bin/env python3
"""Replay a pending GCP candidate against exact saved report pairs, offline.

The saved AI rows for selected findings are replaced with synthetic FAIL rows.
Remaining AI input IDs, Priorities input/review IDs, published findings and
saved actions must remain identical. No model or cloud request is made.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

from peaso.ai import gcp_native_final
from peaso.ai.finding_reviews import apply_review, review_index
from peaso.ai.native_final import reviews as native_reviews
from peaso.ai.pipeline import inputs


FIELDS = ('status', 'severity', 'base_severity', 'evidence',
          'evidence_summary', 'ai_review', 'scanner_status')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def flat(report):
    rows = [row for group in report['findings']
            for row in (group.get('observations') or [group])]
    result = {row['id']: row for row in rows}
    if len(result) != len(rows):
        raise ValueError('duplicate finding ID')
    return result


def replay(scan_id, pre_path, final_path, candidate):
    with gzip.open(pre_path, 'rt') as source:
        before = json.load(source)
    with gzip.open(final_path, 'rt') as source:
        after = json.load(source)
    if (before.get('provider') != after.get('provider') or before.get('provider') != 'gcp'
            or not before.get('snapshot_id')
            or before['snapshot_id'] != after.get('snapshot_id')
            or after.get('ai', {}).get('status') != 'completed'):
        raise ValueError('reports are not one completed GCP snapshot')
    native_by_id, final_by_id = flat(before), flat(after)
    flat_before = dict(before, findings=list(native_by_id.values()))
    hardening, exposure, _ = inputs(flat_before)
    selected, remaining = gcp_native_final.partition(hardening, candidate)
    selected_ids = {row['id'] for row in selected}
    baseline_inputs = after['ai']['stage_inputs']
    if (set(baseline_inputs['hardening']) != {row['id'] for row in hardening}
            or set(baseline_inputs['exposure']) != {row['id'] for row in exposure}
            or len(selected_ids) != len(selected)
            or set(baseline_inputs['hardening']) - selected_ids != {row['id'] for row in remaining}):
        raise ValueError('saved stage inputs differ from reconstructed partition')
    baseline_reviews = after['ai']['reviews']
    hardening_reviews = baseline_reviews['hardening']
    by_review = {row['finding_id']: row for row in hardening_reviews}
    if len(by_review) != len(hardening_reviews):
        raise ValueError('duplicate saved Hardening review ID')
    synthetic = {row['finding_id']: row for row in native_reviews(selected)}
    for ident, row in synthetic.items():
        if by_review.get(ident) != row:
            raise ValueError('selected saved AI review differs from synthetic FAIL')
    candidate_reviews = [synthetic.get(row['finding_id'], row)
                         for row in hardening_reviews]
    if candidate_reviews != hardening_reviews:
        raise ValueError('combined review rows changed')
    priorities_finding_ids = {row['id'] for row in hardening + exposure}
    if (priorities_finding_ids != set(baseline_inputs['hardening']) | set(baseline_inputs['exposure'])
            or {row['finding_id'] for row in candidate_reviews + baseline_reviews['exposure']}
               != {row['finding_id'] for row in hardening_reviews + baseline_reviews['exposure']}):
        raise ValueError('Priorities finding or review IDs changed')
    candidate_ai = dict(after['ai'],
                        reviews={**baseline_reviews, 'hardening': candidate_reviews},
                        native_final={'hardening': sorted(selected_ids)},
                        stage_inputs={**baseline_inputs, 'hardening': sorted(
                            row['id'] for row in remaining)})
    candidate_index = review_index(candidate_ai)
    differences = Counter()
    for ident, row in native_by_id.items():
        published = final_by_id.get(ident)
        if published is None:
            differences['missing_final'] += 1
            continue
        projected = apply_review(row, candidate_index, before.get('check_meta'))
        # Native-final rows deliberately omit stored model metadata; compare
        # their published decision/evidence, and compare all fields elsewhere.
        fields = FIELDS[:5] if ident in selected_ids else FIELDS
        for field in fields:
            if projected.get(field) != published.get(field):
                differences[field] += 1
    if differences:
        raise ValueError('projected final finding differs: ' + repr(dict(differences)))
    actions = after['ai']['actions']
    if any(not set(action['finding_ids']) <= set(final_by_id) for action in actions):
        raise ValueError('saved action cites an absent final finding')
    # Action bytes are retained from the final report. This is preservation,
    # not a model replay or a claim that a new model would write the same text.
    return {'scan_id': scan_id,
            'pre_ai_sha256': hashlib.sha256(Path(pre_path).read_bytes()).hexdigest(),
            'final_sha256': hashlib.sha256(Path(final_path).read_bytes()).hexdigest(),
            'snapshot_id_sha256': hashlib.sha256(before['snapshot_id'].encode()).hexdigest(),
            'selected_native_failures': len(selected),
            'remaining_ai_hardening_inputs': len(remaining),
            'priorities_input_ids': len(priorities_finding_ids),
            'final_findings_compared': len(native_by_id),
            'final_only_findings_retained': len(set(final_by_id) - set(native_by_id)),
            'saved_actions_retained': len(actions),
            'saved_actions_sha256': digest(actions),
            'final_finding_projection_parity': True,
            'priorities_ids_parity': True,
            'saved_actions_preserved': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair', nargs=3, action='append', required=True,
                        metavar=('SCAN_ID', 'PRE_AI', 'FINAL'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    candidate = gcp_native_final.candidate_check_ids()
    if candidate != frozenset(gcp_native_final.CHECKS):
        raise ValueError('GCP candidate manifest changed')
    rows = [replay(scan_id, pre, final, candidate)
            for scan_id, pre, final in args.pair]
    if len({row['scan_id'] for row in rows}) != len(rows):
        raise ValueError('duplicate scan ID')
    receipt = {'schema_version': 1, 'provider': 'gcp',
               'manifest_sha256': hashlib.sha256(gcp_native_final.MANIFEST.read_bytes()).hexdigest(),
               'candidate_check_ids': sorted(candidate), 'scans': rows,
               'selected_native_failures': sum(row['selected_native_failures'] for row in rows),
               'remaining_ai_hardening_inputs': sum(row['remaining_ai_hardening_inputs'] for row in rows),
               'hosted_model_replay': False, 'runtime_admitted': False,
               'qualification_state': 'offline_saved_parity_only'}
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'scans': len(rows),
                      'selected_native_failures': receipt['selected_native_failures'],
                      'qualification_state': receipt['qualification_state']}))


if __name__ == '__main__':
    main()
