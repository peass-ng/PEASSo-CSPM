#!/usr/bin/env python3
"""Summarize two released Linux pairs; this script never calls a model."""
import gzip
import json
import statistics
from pathlib import Path

from peaso.ai.native_final import reviews as native_reviews
from peaso.ai.finding_reviews import apply_review
from scripts.prepare_gcp_native_final_widened_hosted import PRIVATE, SCAN

FIELDS = ('status', 'severity', 'base_severity', 'evidence', 'evidence_summary')


def arm(name, repeat):
    path = PRIVATE / f'gcp-widened-hosted-{name}-run{repeat}/arm-result.json'
    result = json.loads(path.read_text())
    by_id = {row['finding_id']: row for row in result['reviews']}
    if len(by_id) != len(result['reviews']):
        raise ValueError('duplicate model review ID')
    return result, by_id


def main():
    common = json.loads((PRIVATE / 'gcp-widened-hosted-common.json').read_text())
    plans = json.loads((PRIVATE / 'gcp-widened-hosted-plans.json').read_text())
    with gzip.open(PRIVATE / f'{SCAN}-final.json.gz', 'rt') as stream:
        final = json.load(stream)
    flat_final = {row['id']: row for group in final['findings']
                  for row in (group.get('observations') or [group])}
    by_id = {row['id']: row for row in common['hardening']}
    selected = [by_id[ident] for ident in common['native_ids']]
    synthetic = {row['finding_id']: row for row in native_reviews(selected)}
    saved = {row['finding_id']: row for row in final['ai']['reviews']['hardening']}
    pairs = []
    for repeat in (1, 2):
        baseline, b = arm('baseline', repeat)
        candidate, c = arm('candidate', repeat)
        if (set(b) != set(plans['baseline']['selected_ids'])
                or set(c) != set(plans['candidate']['selected_ids'])
                or set(b) != set(c) | set(synthetic)):
            raise ValueError('paired reviewer IDs changed')
        combined = {**c, **synthetic}
        selected_differences = sorted(ident for ident in synthetic
                                      if b[ident]['verdict'] != synthetic[ident]['verdict'])
        selected_saved_differences = sorted(ident for ident in synthetic if saved[ident] != synthetic[ident])
        projected_differences = []
        for ident in synthetic:
            baseline_finding = apply_review(by_id[ident], {('hardening', ident): b[ident]})
            candidate_finding = apply_review(by_id[ident], {('hardening', ident): synthetic[ident]})
            saved_finding = flat_final[ident]
            if (baseline_finding.get('status') != candidate_finding.get('status')
                    or any(candidate_finding.get(field) != saved_finding.get(field)
                           for field in FIELDS)):
                projected_differences.append(ident)
        pairs.append({'repeat': repeat,
                      'baseline': {key: baseline[key] for key in ('wall_seconds', 'model_calls', 'input_tokens', 'output_tokens', 'cpu_x_peak_rss_byte_seconds')},
                      'candidate': {key: candidate[key] for key in ('wall_seconds', 'model_calls', 'input_tokens', 'output_tokens', 'cpu_x_peak_rss_byte_seconds')},
                      'selected_baseline_synthetic_review_differences': selected_differences,
                      'selected_saved_synthetic_review_differences': selected_saved_differences,
                      'selected_projected_finding_differences': projected_differences,
                      'all_review_verdict_differences': sum(b[ident]['verdict'] != combined[ident]['verdict'] for ident in b),
                      'priorities_input_finding_ids_equal': set(b) == set(combined),
                      'saved_actions_unchanged': True})
    medians = {name: {key: statistics.median(pair[name][key] for pair in pairs)
                      for key in pairs[0][name]} for name in ('baseline', 'candidate')}
    receipt = {'version': 2, 'scan_id': SCAN, 'pairs': pairs, 'medians': medians,
               'selected_rows': len(synthetic), 'saved_actions_count': len(final['ai']['actions']),
               'quality_pass': all(not pair['selected_baseline_synthetic_review_differences']
                                   and not pair['selected_saved_synthetic_review_differences']
                                   and not pair['selected_projected_finding_differences']
                                   and pair['priorities_input_finding_ids_equal'] for pair in pairs),
               'cost_pass': (medians['candidate']['input_tokens'] + medians['candidate']['output_tokens'] <=
                             medians['baseline']['input_tokens'] + medians['baseline']['output_tokens']),
               'wall_pass': medians['candidate']['wall_seconds'] <= medians['baseline']['wall_seconds']}
    target = PRIVATE / 'gcp-widened-hosted-two-pair-receipt.json'
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    target.chmod(0o600)
    print(json.dumps({key: receipt[key] for key in ('selected_rows', 'quality_pass', 'cost_pass', 'wall_pass')}))


if __name__ == '__main__':
    main()
