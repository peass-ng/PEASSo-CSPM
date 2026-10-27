#!/usr/bin/env python3
"""Summarize explicitly released GCP paired arms without publishing data."""
import gzip
import hashlib
import json
import os
from pathlib import Path

from peaso.ai.finding_reviews import apply_review

from scripts.prepare_gcp_native_final_hosted import PRIVATE, ROOT, SCAN, sha


FIELDS = ('status', 'severity', 'base_severity', 'evidence', 'evidence_summary')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     default=str).encode()).hexdigest()


def arm(name, plan):
    path = PRIVATE / f'gcp-hosted-{name}/arm-result.json'
    data = json.loads(path.read_text())
    rows = data['reviews']
    by_id = {row['finding_id']: row for row in rows}
    if (len(by_id) != len(rows) or set(by_id) != set(plan['selected_ids'])
            or data['model_calls'] != sum(row['model_calls'] for row in data['launches'])
            or data['input_tokens'] != sum(row['input_tokens'] for row in data['launches'])
            or data['output_tokens'] != sum(row['output_tokens'] for row in data['launches'])
            or data['cpu_x_peak_rss_byte_seconds'] != sum(
                row['cpu_seconds'] * row['peak_rss_bytes'] for row in data['launches'])):
        raise ValueError('hosted arm coverage or usage invalid')
    models = {digest(row['model']) for row in data['launches']}
    credentials = {row['credential_sha256'] for row in data['launches']}
    if len(models) != 1 or len(credentials) != 1:
        raise ValueError('model or credential changed within arm')
    metrics = {key: data[key] for key in
               ('wall_seconds', 'model_calls', 'input_tokens', 'output_tokens',
                'cpu_x_peak_rss_byte_seconds')}
    metrics.update(launches=len(data['launches']), model_sha256=next(iter(models)),
                   credential_sha256=next(iter(credentials)), result_sha256=sha(path))
    return by_id, metrics


def main():
    common = json.loads((PRIVATE / 'gcp-hosted-common.json').read_text())
    plans = json.loads((PRIVATE / 'gcp-hosted-plans.json').read_text())
    baseline, bm = arm('baseline', plans['baseline'])
    candidate, cm = arm('candidate', plans['candidate'])
    if (bm['model_sha256'] != cm['model_sha256']
            or bm['credential_sha256'] != cm['credential_sha256']):
        raise ValueError('arms did not use identical model and credential')
    combined = dict(candidate)
    for ident in common['native_ids']:
        if ident in combined:
            raise ValueError('native and AI results overlap')
        combined[ident] = {'finding_id': ident, 'verdict': 'FAIL', 'reason': ''}
    if set(combined) != set(baseline):
        raise ValueError('combined candidate does not cover baseline IDs')
    with gzip.open(PRIVATE / f'{SCAN}-final.json.gz', 'rt') as stream:
        final = json.load(stream)
    saved = {row['finding_id']: row for row in final['ai']['reviews']['hardening']}
    if set(saved) != set(combined):
        raise ValueError('saved review IDs differ')
    final_rows = {row['id']: row for group in final['findings']
                  for row in (group.get('observations') or [group])}
    verdict_changes = sum(baseline[ident]['verdict'] != combined[ident]['verdict']
                          for ident in baseline)
    review_row_changes = sum(baseline[ident] != combined[ident] for ident in baseline)
    published_changes = 0
    baseline_saved_changes = candidate_saved_changes = 0
    baseline_saved_public = candidate_saved_public = 0
    for row in common['hardening']:
        ident = row['id']
        baseline_row = apply_review(row, {('hardening', ident): baseline[ident]})
        candidate_row = apply_review(row, {('hardening', ident): combined[ident]})
        saved_row = final_rows[ident]
        if any(baseline_row.get(key) != candidate_row.get(key) for key in FIELDS):
            published_changes += 1
        if baseline[ident] != saved[ident]:
            baseline_saved_changes += 1
        if combined[ident] != saved[ident]:
            candidate_saved_changes += 1
        if any(baseline_row.get(key) != saved_row.get(key) for key in FIELDS):
            baseline_saved_public += 1
        if any(candidate_row.get(key) != saved_row.get(key) for key in FIELDS):
            candidate_saved_public += 1
    nonhardening = {'exposure': final['ai']['reviews']['exposure'],
                    'network': final['ai'].get('network'),
                    'duplicates': final['ai'].get('duplicates')}
    shared = {'snapshot_sha256': common['snapshot_sha256'],
              'pre_ai_sha256': common['pre_ai_sha256'],
              'nonhardening_sha256': digest(nonhardening)}
    priorities_inputs = {'baseline': digest({**shared, 'hardening_reviews': baseline}),
                         'candidate': digest({**shared, 'hardening_reviews': combined})}
    actions = final['ai']['actions']
    action_refs = {ident for row in actions for ident in row['finding_ids']}
    action_refs_valid = action_refs <= set(final_rows)
    gates = {'review_id_coverage': set(combined) == set(baseline),
             'same_model_and_credential': bm['model_sha256'] == cm['model_sha256']
                                         and bm['credential_sha256'] == cm['credential_sha256'],
             'exact_baseline_candidate_review_rows': review_row_changes == 0,
             'exact_projected_final_fields': published_changes == 0,
             'identical_priorities_input': priorities_inputs['baseline'] == priorities_inputs['candidate'],
             'saved_action_references_valid': action_refs_valid,
             'no_extra_model_calls': cm['model_calls'] <= bm['model_calls'],
             'no_extra_tokens': cm['input_tokens'] + cm['output_tokens'] <=
                                bm['input_tokens'] + bm['output_tokens'],
             'no_extra_cpu_x_peak_rss': cm['cpu_x_peak_rss_byte_seconds'] <=
                                        bm['cpu_x_peak_rss_byte_seconds'],
             'no_extra_wall_seconds': cm['wall_seconds'] <= bm['wall_seconds']}
    receipt = {'schema_version': 1, 'scan_id': SCAN,
               'comparison': 'paired_same_snapshot_pinned_5_6_high_hardening',
               'baseline': bm, 'candidate': cm,
               'baseline_candidate_verdict_differences': verdict_changes,
               'baseline_candidate_review_row_differences': review_row_changes,
               'baseline_candidate_projected_finding_differences': published_changes,
               'baseline_saved_review_row_differences': baseline_saved_changes,
               'candidate_saved_review_row_differences': candidate_saved_changes,
               'baseline_saved_projected_finding_differences': baseline_saved_public,
               'candidate_saved_projected_finding_differences': candidate_saved_public,
               'priorities_input_sha256': priorities_inputs,
               'saved_action_count': len(actions), 'saved_action_sha256': digest(actions),
               'saved_action_references_valid': action_refs_valid,
               'hosted_priorities_replayed': False,
               'gates': gates, 'ready_for_root_review': all(gates.values()),
               'qualified': False, 'runtime_admitted': False}
    output = PRIVATE / 'gcp-hosted-paired-gate.json'
    if output.exists():
        raise FileExistsError(output)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'ready_for_root_review': receipt['ready_for_root_review'],
                      'qualified': False, 'gates': gates}, sort_keys=True))


if __name__ == '__main__':
    main()
