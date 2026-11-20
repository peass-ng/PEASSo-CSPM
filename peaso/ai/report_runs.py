"""Tenant-scoped, fenced replacement runs over immutable assessment evidence."""
import json
import re
import time
import uuid
from copy import deepcopy
from peaso.storage import StoreError
from peaso.storage.artifacts import job_prefix


def _key(scan):
    if not isinstance(scan, str) or not re.fullmatch(r'[a-f0-9]{32}', scan):
        raise StoreError(404, 'Assessment not found')
    return 'findings_report/' + scan


def _read(store, tenant, scan):
    raw = store.ai_state(tenant, _key(scan))
    return raw, json.loads(raw) if raw else None


def _save(store, tenant, scan, state, previous):
    return store.set_ai_state(tenant, _key(scan), json.dumps(state, sort_keys=True), previous)


def request_run(store, tenant, scan, actor, *, now=None):
    now = time.time() if now is None else now
    row = store.job(tenant, scan)
    if row['status'] != 'completed' or not row.get('report') or not row.get('snapshot'):
        raise StoreError(409, 'Wait for the assessment to finish before generating its report')
    raw, prior = _read(store, tenant, scan)
    if prior and prior['status'] in ('queued', 'running') and prior['expires'] > now:
        raise StoreError(409, 'Findings Report generation is already running')
    state = {'generation': uuid.uuid4().hex, 'status': 'queued', 'actor': actor,
             'expected_report': row['report'], 'created': now, 'expires': now + 2400,
             'result_ref': prior.get('result_ref') if prior and prior['expected_report'] == row['report'] else None}
    if not _save(store, tenant, scan, state, raw):
        raise StoreError(409, 'Findings Report generation changed; refresh and retry')
    return state


def fail_dispatch(store, tenant, scan, generation):
    raw, state = _read(store, tenant, scan)
    if state and state['generation'] == generation and state['status'] == 'queued':
        _save(store, tenant, scan, dict(state, status='failed'), raw)


def current_report(store, artifacts, tenant, scan, row, fallback):
    _, state = _read(store, tenant, scan)
    if not state:
        return dict(fallback, can_launch=row['status'] == 'completed')
    active = state['status'] in ('queued', 'running') and state['expires'] > time.time()
    if state['expected_report'] != row.get('report'):
        return dict(fallback, can_launch=row['status'] == 'completed')
    if active and not state.get('result_ref') and fallback.get('status') not in ('completed', 'partial'):
        value = {'status': 'in_progress', 'summary': 'Generating a new Findings Report.', 'issues': [], 'exclusions': [], 'limitations': []}
    elif state.get('result_ref') and state['expected_report'] == row.get('report'):
        if not state['result_ref'].startswith(job_prefix(tenant, scan)):
            raise StoreError(409, 'Invalid Findings Report binding')
        value = artifacts.get(tenant, state['result_ref'])
    elif fallback.get('status') in ('completed', 'partial'):
        value = fallback
    else:
        value = {'status': 'unavailable', 'issues': [], 'exclusions': [],
                 'limitations': ['Report generation did not complete. Generate it again to retry.']}
    run_status = 'failed' if not active and state['status'] in ('queued', 'running') else state['status']
    return dict(value, generation=state['generation'], run_status=run_status,
                can_launch=row['status'] == 'completed' and not active)


def execute(store, artifacts, tenant, scan, generation):
    """A generation owns its result; later runs can never be overwritten."""
    raw, state = _read(store, tenant, scan)
    if (not state or state['generation'] != generation or state['status'] != 'queued'
            or state['expires'] <= time.time()):
        return False
    row = store.job(tenant, scan)
    if row['status'] != 'completed' or row.get('report') != state['expected_report']:
        fail_dispatch(store, tenant, scan, generation)
        return False
    state = dict(state, status='running')
    if not _save(store, tenant, scan, state, raw):
        return False
    running_raw = json.dumps(state, sort_keys=True)
    try:
        bundle = artifacts.get(tenant, state['expected_report'])
        report = artifacts.get(tenant, bundle['report_json']) if bundle.get('bundle_version') == 1 else deepcopy(bundle)
        ai = artifacts.get(tenant, bundle['ai_review']) if bundle.get('ai_review') else report.get('ai', {})
        report = dict(report)
        report.pop('ai', None)
        if bundle.get('finding_chunks') is not None:
            # Download JSON groups observations for presentation. Compilation
            # uses the same original observation IDs as the findings UI.
            original = []
            for chunk in bundle['finding_chunks']:
                for finding in artifacts.get(tenant, chunk['reference'])['items']:
                    reference = finding.get('_detail_reference')
                    original.append(artifacts.get(tenant, reference) if reference else finding)
            if len(original) != bundle.get('finding_count', len(original)):
                raise ValueError('Captured finding count changed')
            report['findings'] = original
            report.pop('finding_grouping', None)
            for key in ('check_meta', 'check_meta_encoding', 'check_frameworks', 'remediation_templates'):
                if key in bundle:
                    report[key] = bundle[key]
        least = artifacts.get(tenant, bundle['least_privilege']) if isinstance(bundle.get('least_privilege'), str) else None
        snapshot = artifacts.get(tenant, row['snapshot'])
        selectors = json.loads(row['data']) if isinstance(row['data'], str) else dict(row['data'])
        selectors.update(ai_enabled=True, ai_findings_report_enabled=True, ai_user_id=state['actor'])
        previous_report = current_report(store, artifacts, tenant, scan, row, ai.get('findings_report') or {})
        from .pipeline import review_scan
        reviewed = review_scan(report, snapshot, selectors, tenant=tenant, artifacts=artifacts,
            deadline=state['expires'], scan_id=scan, stages=('findings_report',),
            reused_stages={'findings_report_context': {'network': ai.get('network'),
                'actions': ai.get('actions', []), 'limitations': ai.get('limitations', []),
                'least_privilege': least, 'previous_report': previous_report}})
        value = reviewed.get('findings_report') or {'status': 'unavailable', 'issues': [],
            'limitations': ['The findings report could not be generated. Check AI settings and retry.']}
        status = 'completed' if value.get('status') == 'completed' else 'failed'
        has_previous = previous_report.get('status') in ('completed', 'partial')
        reference = (state['result_ref'] if status == 'failed' and has_previous
                     else artifacts.put(tenant, scan, 'ai-review', value))
        # A reconcile/delete or newer generation invalidates this publication.
        current = store.job(tenant, scan)
        if time.time() >= state['expires'] or current['status'] != 'completed' or current.get('report') != state['expected_report']:
            status, reference = 'failed', state['result_ref']
        published = _save(store, tenant, scan, dict(state, status=status, result_ref=reference), running_raw)
        return published and status == 'completed'
    except Exception:
        _save(store, tenant, scan, dict(state, status='failed'), running_raw)
        return False


def worker(tenant, scan, generation):
    from peaso.server.config import Settings
    from peaso.storage.runtime import stores
    store, artifacts = stores(Settings())
    if not execute(store, artifacts, tenant, scan, generation):
        raise SystemExit(1)


def dispatch(tenant, scan, generation, *, client=None, arn=None):
    import os
    arn = arn or os.environ['PEASO_WORKFLOW_ARN']
    if client is None:
        import boto3
        client = boto3.client('stepfunctions')
    return client.start_execution(stateMachineArn=arn, name='report-' + scan + '-' + generation,
        input=json.dumps({'tenant_id': tenant, 'scan_id': scan, 'report_generation': generation}))
