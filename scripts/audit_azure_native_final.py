"""Audit saved Azure Hardening FAILs against exact AI reviews, without payloads.

This produces a numeric candidate inventory, never a runtime allowlist. A zero
disagreement count is necessary but does not prove a future-safe source path.
"""

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path


def _read(path):
    raw = Path(path).read_bytes()
    data = gzip.decompress(raw) if raw[:2] == b'\x1f\x8b' else raw
    return json.loads(data), hashlib.sha256(raw).hexdigest()


def _observations(report):
    for group in report.get('findings', []):
        if not isinstance(group, dict):
            raise ValueError('malformed_finding_group')
        rows = group.get('observations')
        if rows is None:
            rows = [group]
        if not isinstance(rows, list):
            raise ValueError('malformed_observations')
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('malformed_observation')
            yield row


def audit(pre, final, *, pre_sha, final_sha):
    if pre.get('provider') != 'azure' or final.get('provider') != 'azure':
        raise ValueError('azure_provider_required')
    if not pre.get('snapshot_id') or pre['snapshot_id'] != final.get('snapshot_id'):
        raise ValueError('snapshot_mismatch')
    native = {}
    counts = Counter()
    for row in _observations(pre):
        if row.get('provider') != 'azure' or row.get('category') != 'hardening' or row.get('status') != 'FAIL':
            continue
        ident, check = row.get('id'), row.get('check_id')
        if not isinstance(ident, str) or not ident or not isinstance(check, str) or not check.startswith('azure'):
            raise ValueError('invalid_native_identity')
        if ident in native:
            raise ValueError('duplicate_native_id')
        native[ident] = (check, row.get('severity'))
        counts[check] += 1
    final_rows = {}
    for row in _observations(final):
        ident = row.get('id')
        if ident in native:
            if ident in final_rows:
                raise ValueError('duplicate_final_id')
            final_rows[ident] = row
    reviews = final.get('ai', {}).get('reviews', {}).get('hardening', [])
    if not isinstance(reviews, list):
        raise ValueError('malformed_reviews')
    reviewed = set()
    verdicts = defaultdict(Counter)
    severity_changes = Counter()
    status_changes = Counter()
    missing_final = Counter()
    for ident, (check, severity) in native.items():
        row = final_rows.get(ident)
        if row is None:
            missing_final[check] += 1
        else:
            if row.get('severity') != severity:
                severity_changes[check] += 1
            if row.get('status') != 'FAIL':
                status_changes[check] += 1
    unmatched = 0
    for row in reviews:
        if not isinstance(row, dict) or not isinstance(row.get('finding_id'), str):
            raise ValueError('malformed_review')
        ident = row['finding_id']
        if ident in reviewed:
            raise ValueError('duplicate_review_id')
        reviewed.add(ident)
        if ident not in native:
            unmatched += 1
            continue
        verdict = row.get('verdict')
        if not isinstance(verdict, str) or not verdict:
            raise ValueError('missing_verdict')
        verdicts[native[ident][0]][verdict] += 1
    per_check = []
    for check in sorted(counts):
        observed = sum(verdicts[check].values())
        missing = counts[check] - observed
        disagreement = observed - verdicts[check]['FAIL']
        complete = missing == 0 and missing_final[check] == 0
        candidate = (complete and disagreement == 0 and severity_changes[check] == 0
                     and status_changes[check] == 0)
        per_check.append({
            'check_id': check,
            'native_fail_count': counts[check],
            'review_count': observed,
            'unreviewed_count': missing,
            'ai_disagreement_count': disagreement,
            'ai_verdict_counts': dict(sorted(verdicts[check].items())),
            'missing_final_count': missing_final[check],
            'published_severity_change_count': severity_changes[check],
            'published_status_change_count': status_changes[check],
            'zero_disagreement_candidate': candidate,
        })
    return {
        'version': 1,
        'provider': 'azure',
        'snapshot_id': pre['snapshot_id'],
        'pre_ai_sha256': pre_sha,
        'final_sha256': final_sha,
        'native_fail_ids': len(native),
        'unmatched_review_ids': unmatched,
        'candidate_check_count': sum(row['zero_disagreement_candidate'] for row in per_check),
        'per_check': per_check,
        'qualification_state': 'source_audit_and_hosted_replay_required',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pre-ai', type=Path, required=True)
    parser.add_argument('--final', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    pre, pre_sha = _read(args.pre_ai)
    final, final_sha = _read(args.final)
    receipt = audit(pre, final, pre_sha=pre_sha, final_sha=final_sha)
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: receipt[key] for key in (
        'snapshot_id', 'native_fail_ids', 'candidate_check_count', 'qualification_state')}, sort_keys=True))


if __name__ == '__main__':
    main()
