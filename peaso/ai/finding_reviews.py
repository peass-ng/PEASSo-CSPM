"""Apply validated AI rechecks to finding views without changing native evidence."""
from .contracts import Review

_UNAVAILABLE = 'AI review was unavailable, timed out, or returned an invalid result; the original failure could not be verified.'


def review_index(result):
    """Bind reviews by category and exact finding ID; ignore invalid/duplicate rows."""
    index, seen = {}, set()
    if not isinstance(result, dict) or not isinstance(result.get('reviews'), dict):
        return index
    for category in ('hardening', 'exposure'):
        rows = result['reviews'].get(category, [])
        if not isinstance(rows, list):
            continue
        for raw in rows:
            try:
                row = Review.model_validate(raw).model_dump()
            except ValueError:
                continue
            key = (category, row['finding_id'])
            if key in seen:
                index.pop(key, None)
                continue
            seen.add(key)
            if row['verdict'] == 'UNKNOWN' and row['reason'] == _UNAVAILABLE:
                continue
            index[key] = row
    return index


def _concrete_secret_observation(finding):
    """Recognize one normalized, source-bound offline detector finding."""
    evidence = finding.get('evidence')
    if (finding.get('provider') not in {'aws', 'gcp', 'azure', 'k8s'}
            or type(evidence) is not dict or evidence.get('credential_validation') != 'not_attempted'
            or type(evidence.get('secret_leaks')) is not list
            or not 1 <= len(evidence['secret_leaks']) <= 5000):
        return False
    from peaso.secret_scanning import merge_leaks
    try:
        observations = merge_leaks(evidence['secret_leaks'])
    except (ValueError, TypeError, KeyError):
        return False
    if len(observations) != 1:
        return False
    observation = observations[0]
    fingerprint = observation['fingerprint']
    return (finding.get('id') == 'secret-' + fingerprint
            and finding.get('resource_id') == 'secret:' + fingerprint
            and finding.get('secret_fingerprint') == fingerprint
            and isinstance(finding.get('scope'), str) and bool(finding['scope'])
            and any(location.get('scope') == finding['scope'] for location in observation['locations'])
            and all(isinstance(location.get('resource_id'), str) and bool(location['resource_id'])
                    and isinstance(location.get('scope'), str) and bool(location['scope'])
                    for location in observation['locations']))


def apply_review(finding, reviews, meta=None):
    category = finding.get('category', ((meta or {}).get(finding.get('check_id')) or {}).get('category'))
    review = reviews.get((category, finding.get('id')))
    # Review agents are assigned native FAILs only. Never override another
    # native result or let a review for another category affect this finding.
    if not review or finding.get('scanner_status', finding.get('status')) != 'FAIL':
        return finding
    preserved = review['verdict'] != 'FAIL' and _concrete_secret_observation(finding)
    effective = {'verdict': 'FAIL', 'reason': ''} if preserved else review
    result = dict(finding, scanner_status='FAIL', status=effective['verdict'],
                  ai_review={'verdict': effective['verdict'], 'reason': effective['reason']})
    if preserved:
        # Restore the original recorded observation if a saved report already
        # carries the model's incorrect incomplete-coverage explanation.
        observed = finding['evidence'].get('observed')
        if isinstance(observed, str) and observed:
            result['evidence_summary'] = observed
        else:
            result.pop('evidence_summary', None)
    elif effective['reason']:
        result['evidence_summary'] = effective['reason']
    return result


def apply_report_reviews(report):
    """Publish effective findings/counts while retaining native scanner results."""
    from collections import Counter
    reviews = review_index(report.get('ai'))
    if not reviews:
        return report
    native_ids = set(((report.get('ai') or {}).get('native_final') or {}).get('hardening', ()))
    findings = [row if row.get('id') in native_ids else apply_review(row, reviews, report.get('check_meta'))
                for row in report.get('findings', [])]
    stats = dict(report.get('stats', {}))
    if 'scanner_by_status' not in stats:
        stats['scanner_by_status'] = stats.get('by_status', {})
    counts = Counter(row['status'] for row in findings)
    for row in report.get('finding_aggregates', []):
        counts[row['status']] += row['count']
    stats['by_status'] = dict(counts)
    stats['by_severity'] = dict(Counter(row.get('severity', (report.get('check_meta', {}).get(row.get('check_id')) or {}).get('severity', 'info'))
                                      for row in findings if row.get('status') == 'FAIL'))
    return dict(report, findings=findings, stats=stats)
