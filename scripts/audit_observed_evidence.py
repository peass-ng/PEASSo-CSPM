#!/usr/bin/env python3
"""Audit exact-ID evidence-copy coverage against the current native registry.

Run with the repository on PYTHONPATH. This checks inventory/source accounting;
the provider replay suites verify recorded values and branch interpretations.
"""
import argparse
import json
from pathlib import Path

from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.checks.native_only import exclusions

ROOT = Path(__file__).resolve().parents[1]
FORMAT = ('One to three brief plain-language sentences: what was observed, '
          'the actual setting/value/principal/action, its meaning, and any evidence limit. '
          'Never infer usable access, successful exploitation or a disabled setting from missing evidence.')


def audit():
    result = {'format': FORMAT, 'providers': {}, 'errors': []}
    excluded = exclusions()
    for provider in ('aws', 'gcp', 'azure', 'k8s'):
        native = {check.id for check in CHECKS if check.provider == provider}
        aliases = {old for old, current in CHECK_ALIASES.items() if current in native}
        path = ROOT / 'peaso/checks' / f'{provider}_evidence_explanations.json'
        ledger_path = ROOT / 'docs/evidence-reviews' / f'{provider}.json'
        rows = json.loads(path.read_text()) if path.exists() else {}
        # Providers load later reviewed copy from dated overlay files.
        for overlay in sorted(path.parent.glob(f'{provider}_evidence_explanations_current_*.json')):
            rows.update(json.loads(overlay.read_text()))
        ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else {}
        tracked = ledger.get('checks', ledger)
        missing_copy = sorted((native | aliases) - rows.keys())
        missing_review = sorted((native | aliases) - tracked.keys())
        stale_copy = sorted(rows.keys() - (native | aliases))
        mismatched_review = sorted(
            cid for cid in (native | aliases) & rows.keys() & tracked.keys()
            if rows[cid].get('purpose') != tracked[cid].get('interpretation' if provider == 'azure' else 'purpose')
            or provider == 'azure' and rows[cid].get('limit') != tracked[cid].get('evidence_limit')
        )
        invalid = sorted(cid for cid, row in rows.items() if not isinstance(row, dict)
                         or not isinstance(row.get('purpose'), str) or not row['purpose'].strip()
                         or '\n' in row['purpose'] or len(row['purpose'].split()) > 50)
        result['providers'][provider] = {
            'registered_checks': len(native),
            'active_checks': len(native - excluded.keys()),
            'historical_or_excluded_checks': len(native & excluded.keys()),
            'retired_aliases': len(aliases),
            'explicit_copy_entries': len(rows),
            'review_ledger_entries': len(tracked),
            'missing_copy': missing_copy,
            'missing_review': missing_review,
            'invalid_copy': invalid,
            'stale_copy': stale_copy,
            'mismatched_review': mismatched_review,
            'ledger': str(ledger_path.relative_to(ROOT)),
        }
        for name, values in [('missing_copy', missing_copy), ('missing_review', missing_review),
                             ('invalid_copy', invalid), ('stale_copy', stale_copy),
                             ('mismatched_review', mismatched_review)]:
            if values:
                result['errors'].append({'provider': provider, 'kind': name, 'ids': values})
    result['registered_check_count'] = sum(row['registered_checks'] for row in result['providers'].values())
    result['alias_count'] = len(CHECK_ALIASES)
    analysis = json.loads((ROOT / 'docs/evidence-reviews/analysis.json').read_text())
    from peaso.analysis.finding_clarity import HOW
    analysis_ids = set(HOW) | {'analysis.internet_exposure'}
    expected_pairs = {f'{cid}:{provider}' for cid in analysis_ids
                      for provider in ('aws', 'gcp', 'azure', 'k8s')
                      if (cid, provider) != ('analysis.federated_trust', 'k8s')}
    from peaso.privesc import catalog
    techniques = {entry['id'] for entry in catalog()['entries']}
    privilege_copy = json.loads((ROOT / 'peaso/privesc/finding_explanation.json').read_text())
    privilege_ledger = json.loads((ROOT / 'docs/evidence-reviews/privesc.json').read_text())
    missing = sorted(techniques - privilege_copy.keys())
    unreviewed = sorted((techniques | {'admin-equivalent'}) - privilege_ledger['checks'].keys())
    result['shared_analysis'] = {'check_count': analysis['check_count'],
                                 'applicable_provider_pairs': analysis['applicable_provider_pairs'],
                                 'reviewed_pairs': len(analysis['checks'])}
    result['privilege_paths'] = {'catalog_techniques': len(techniques), 'generated_checks': 1,
                                 'missing_copy': missing, 'missing_review': unreviewed}
    if missing or unreviewed:
        result['errors'].append({'kind': 'privilege_paths', 'missing_copy': missing, 'missing_review': unreviewed})
    if set(analysis['checks']) != expected_pairs:
        result['errors'].append({'kind': 'shared_analysis_coverage',
                                 'missing': sorted(expected_pairs - analysis['checks'].keys()),
                                 'unexpected': sorted(analysis['checks'].keys() - expected_pairs)})
    result['complete'] = not result['errors']
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = audit()
    encoded = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end='')
    raise SystemExit(0 if result['complete'] else 1)
