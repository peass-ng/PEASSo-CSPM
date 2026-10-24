"""Operator reconciliation of a completed scan, retaining immutable prior artifacts.

This runs no model and makes no target-account collection calls. The supplied captured snapshot is
re-evaluated by the installed engine, then existing validated reviews are applied.
"""
from copy import deepcopy
from datetime import datetime, timezone

from .contracts import Review, validate_actions
from .network import with_findings
from .finding_reviews import apply_report_reviews
from peaso.storage import StoreError
from peaso.storage.artifacts import check_reference, job_prefix


def reconcile_scan(store, artifacts, tenant, scan_id, expected_report, *, source_version,
                   adjudications=(), dry_run=True):
    """Replace only the explicitly authorized completed scan's unchanged report."""
    from peaso.engine import evaluate_snapshot
    from peaso.worker import redact_report
    row = store.job(tenant, scan_id)
    if row['status'] != 'completed' or row.get('report') != expected_report:
        raise StoreError(409, 'Completed scan report changed')
    for reference in (expected_report, row['snapshot']):
        check_reference(tenant, reference)
        if not reference.startswith(job_prefix(tenant, scan_id)):
            raise ValueError('Artifact does not belong to the requested scan')
    bundle = artifacts.get(tenant, expected_report)
    prior = bundle.get('summary', bundle)
    if bundle.get('ai_review') and not bundle['ai_review'].startswith(job_prefix(tenant, scan_id)):
        raise ValueError('AI review does not belong to the requested scan')
    ai = deepcopy(artifacts.get(tenant, bundle['ai_review']) if bundle.get('ai_review') else prior.get('ai', {}))
    if ai.get('status') not in ('completed', 'partial') or not isinstance(ai.get('reviews'), dict):
        raise ValueError('No completed reviews to reconcile')
    import json
    selectors = json.loads(row['data']) if isinstance(row['data'], str) else row['data']
    snapshot = artifacts.get(tenant, row['snapshot'])
    report = evaluate_snapshot(snapshot, categories=selectors.get('categories') if selectors.get('content_checks') else selectors.get('categories') or None,
        checks=selectors.get('checks') or None, frameworks=selectors.get('frameworks') or None,
        include_not_applicable=True, content_checks=selectors.get('content_checks'))
    if report['snapshot_id'] != prior.get('snapshot_id'):
        raise ValueError('Snapshot binding changed')
    # These are explicit operator decisions, not model-provided instructions.
    reviewed = {(category, r['finding_id']): r for category, rows in ai['reviews'].items() for r in rows}
    decisions = []
    seen = set()
    for decision in adjudications:
        key = (decision['category'], decision['finding_id'])
        if key in seen or key not in reviewed or not decision.get('source'):
            raise ValueError('Invalid or duplicate adjudication reference')
        seen.add(key)
        updated = Review.model_validate({k: decision[k] for k in ('finding_id', 'verdict', 'reason')}).model_dump()
        original = deepcopy(reviewed[key])
        reviewed[key].update(updated)
        decisions.append({'category': key[0], 'original_review': original, 'review': updated, 'source': decision['source']})
    all_reviews = [r for rows in ai['reviews'].values() for r in rows]
    if ai.get('coverage'):
        ai['coverage']['reviewed'] = sum(r['verdict'] in ('PASS', 'FAIL', 'NOT_APPLICABLE', 'EMPTY') for r in all_reviews)
    if decisions:
        ai['adjudications'] = [*ai.get('adjudications', []), *decisions]
    report = redact_report(report)
    report['ai'] = ai
    report['runtime'] = prior.get('runtime', {})
    report['input_mode'] = prior.get('input_mode', 'live')
    report = with_findings(report, ai.get('network', {}).get('findings', []))
    validate_actions({'actions': ai.get('actions', []), 'limitations': ai.get('limitations', [])}, report, all_reviews)
    report['analysis_revision'] = {'previous_report': expected_report, 'source_version': source_version,
        'updated_at': datetime.now(timezone.utc).isoformat(), 'snapshot_unchanged': True,
        'native_checks_reevaluated': True, 'model_rerun': False, 'materialized_not_applicable': True}
    effective = apply_report_reviews(report)
    receipt = {'scan_id': scan_id, 'dry_run': dry_run, 'check_count': report['stats']['check_count'],
        'finding_count': len(effective['findings']), 'by_status': effective['stats']['by_status'],
        'native_by_status': report['stats']['by_status'], 'adjudications': len(decisions),
        'actions': len(ai.get('actions', [])), 'snapshot_unchanged': True}
    if dry_run:
        return receipt
    from peaso.storage.reports import publish_report
    reference = publish_report(artifacts, tenant, scan_id, report, snapshot)
    store.replace_completed_report(tenant, scan_id, expected_report, reference)
    return dict(receipt, report_replaced=True)
