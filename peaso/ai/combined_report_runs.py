"""Workspace-owned combined reports, frozen inputs and fenced background publication."""
import json
import re
import time
import uuid
from peaso.storage import StoreError
from peaso.storage.sqlite import utc
from peaso.storage.artifacts import job_prefix
from . import report_runs
from .combined_reports import confirmed_issues, version, validate

PREFIX = 'combined_report/'


def key(ident):
    if not isinstance(ident, str) or not re.fullmatch(r'[a-f0-9]{32}', ident):
        raise StoreError(404, 'Combined report not found')
    return PREFIX + ident


def read(store, tenant, ident):
    raw = store.ai_state(tenant, key(ident))
    if raw is None:
        raise StoreError(404, 'Combined report not found')
    return raw, json.loads(raw)


def _report(store, artifacts, tenant, scan):
    row = store.job(tenant, scan)
    if row['status'] != 'completed' or not row.get('report'):
        raise StoreError(409, 'Choose completed assessments with completed Findings Reports')
    bundle = artifacts.get(tenant, row['report'])
    ai = artifacts.get(tenant, bundle['ai_review']) if bundle.get('ai_review') else bundle.get('summary', bundle).get('ai', {})
    return row, report_runs.current_report(store, artifacts, tenant, scan, row, ai.get('findings_report') or {})


def _connector_index(store, tenant):
    return {row['id']: json.loads(row['data']) if isinstance(row['data'], str) else row['data']
            for row in store.connectors(tenant)}


def _connector_metadata(connectors, row):
    request = json.loads(row['data']) if isinstance(row['data'], str) else row['data']
    connector = connectors.get(row.get('connector_id') or request['connector_id'])
    if connector is not None:
        return connector
    captured = row.get('connector') or {}
    captured = json.loads(captured) if isinstance(captured, str) else captured
    return captured.get('data', {})


def candidates(store, artifacts, tenant):
    connectors = _connector_index(store, tenant)
    result = []
    for row in store.jobs(tenant):
        if row['status'] != 'completed' or not row.get('result_available'):
            continue
        saved, report = _report(store, artifacts, tenant, row['id'])
        connector = _connector_metadata(connectors, saved)
        result.append({'scan_id': row['id'], 'connector_name': connector.get('name', 'Unknown connector'),
            'provider': connector.get('provider', ''), 'created_at': row.get('created_at') or utc(row['created']),
            'version': version(report), 'status': report.get('status', 'not_available'),
            'issue_count': len(confirmed_issues(report))})
    return result


def create(store, artifacts, tenant, actor, name, selections):
    ids = [row['scan_id'] for row in selections]
    if not 2 <= len(ids) <= 20 or len(ids) != len(set(ids)):
        raise StoreError(422, 'Select between 2 and 20 different assessment reports')
    connectors = _connector_index(store, tenant)
    reports = []
    for selection in selections:
        row, report = _report(store, artifacts, tenant, selection['scan_id'])
        if report.get('status') != 'completed':
            raise StoreError(409, 'Generate a completed Findings Report for every selected assessment first')
        if selection['version'] != version(report):
            raise StoreError(409, 'A selected report changed; reopen the selection and try again')
        connector = _connector_metadata(connectors, row)
        reports.append({'scan_id': row['id'], 'connector_name': connector.get('name', 'Unknown connector'),
            'provider': connector.get('provider', ''), 'created_at': row.get('created_at') or utc(row['created']),
            'version': selection['version'], 'summary': report.get('summary', ''),
            'issues': confirmed_issues(report), 'limitations': report.get('limitations', []),
            'running_images': report.get('running_images', [])})
    affected_digests = {detail.get('digest') for report in reports for issue in report['issues']
                        if issue['kind'] == 'image_cves' for detail in issue.get('special_details', [])}
    for report in reports:
        report['running_images'] = [row for row in report['running_images'] if row['digest'] in affected_digests]
    if len(json.dumps(reports).encode()) > 64 * 1024 * 1024:
        raise StoreError(413, 'Selected reports are too large; combine fewer reports')
    ident = uuid.uuid4().hex
    reference = artifacts.put(tenant, ident, 'ai-review', {'reports': reports})
    now = time.time()
    state = {'id': ident, 'name': name, 'status': 'queued', 'created': now, 'expires': now + 2400,
             'actor': actor, 'input_ref': reference, 'result_ref': None,
             'sources': [{k: r[k] for k in ('scan_id', 'connector_name', 'provider', 'created_at', 'version')}
                         for r in reports]}
    if not store.set_ai_state(tenant, key(ident), json.dumps(state, sort_keys=True)):
        raise StoreError(409, 'Combined report already exists')
    return public(state)


def public(state):
    status = state['status']
    if status in ('queued', 'running') and state['expires'] <= time.time():
        status = 'failed'
    return {key: state[key] for key in ('id', 'name', 'created', 'sources')} | {'status': status}


def listing(store, tenant, scan=None):
    rows = [public(json.loads(row['value'])) for row in store.ai_states(tenant, PREFIX)]
    if scan:
        store.job(tenant, scan)
        rows = [row for row in rows if any(source['scan_id'] == scan for source in row['sources'])]
    return sorted(rows, key=lambda row: row['created'], reverse=True)


def detail(store, artifacts, tenant, ident):
    _, state = read(store, tenant, ident)
    value = {'status': public(state)['status'], 'issues': [], 'limitations': []}
    if state.get('result_ref'):
        if not state['result_ref'].startswith(job_prefix(tenant, ident)):
            raise StoreError(409, 'Invalid combined report binding')
        value = artifacts.get(tenant, state['result_ref'])
    elif value['status'] == 'failed':
        value['limitations'] = ['Combined report generation did not complete. Create another combined report to retry.']
    return dict(value, **public(state))


def frozen_reports(store, artifacts, tenant, ident):
    _, state = read(store, tenant, ident)
    if not state['input_ref'].startswith(job_prefix(tenant, ident)):
        raise StoreError(409, 'Invalid combined report binding')
    return artifacts.get(tenant, state['input_ref'])['reports']


def source_issue(store, artifacts, tenant, ident, scan, issue_id):
    for report in frozen_reports(store, artifacts, tenant, ident):
        if report['scan_id'] == scan:
            for issue in report['issues']:
                if issue['id'] == issue_id:
                    try:
                        store.job(tenant, scan)
                        available = True
                    except StoreError as exc:
                        if exc.status != 404:
                            raise
                        available = False
                    return {'source': {k: v for k, v in report.items() if k != 'issues'}, 'issue': issue,
                            'assessment_available': available}
    raise StoreError(404, 'Source issue not found')


def fail(store, tenant, ident):
    raw, state = read(store, tenant, ident)
    if state['status'] == 'queued':
        store.set_ai_state(tenant, key(ident), json.dumps(dict(state, status='failed'), sort_keys=True), raw)


def execute(store, artifacts, tenant, ident):
    raw, state = read(store, tenant, ident)
    if state['status'] != 'queued' or state['expires'] <= time.time():
        return False
    running = dict(state, status='running')
    running_raw = json.dumps(running, sort_keys=True)
    if not store.set_ai_state(tenant, key(ident), running_raw, raw):
        return False
    try:
        from peaso.server.config import Settings
        from .crypto import AICipher
        from .providers import resolve_access, review_disabled
        from .auth import personal_token
        from .pipeline import invoke_before_deadline
        settings = Settings()
        actor = state['actor']
        if actor != tenant and store.workspace_role(tenant, actor) not in ('write', 'admin'):
            raise PermissionError('combined_report_owner_no_longer_authorized')
        if review_disabled(store, actor):
            raise PermissionError('ai_disabled_for_account')
        token, _ = resolve_access(store, AICipher(settings.identity_dir), actor,
                                  auth_mode=settings.auth_mode, token_resolver=personal_token)
        if not state['input_ref'].startswith(job_prefix(tenant, ident)):
            raise ValueError('invalid_combined_input_binding')
        inputs = artifacts.get(tenant, state['input_ref'])
        if any(confirmed_issues(report) for report in inputs['reports']):
            data = invoke_before_deadline('report_combination', inputs, [], token, [], [],
                time.monotonic() + max(0, state['expires'] - time.time() - 120), 1500)
        else:
            data = {'summary': 'Selected reports contain no issues.', 'issues': [], 'limitations': []}
        result = validate(data, inputs['reports'])
        source_titles = {(report['scan_id'], issue['id']): issue['title']
                         for report in inputs['reports'] for issue in report['issues']}
        for issue in result['issues']:
            issue['references'] = [dict(ref, title=source_titles[ref['report_id'], ref['issue_id']])
                                   for ref in issue['references']]
        result['issues'] = [dict(issue, id='combined-' + ident + '-' + str(i + 1))
                            for i, issue in enumerate(result['issues'])]
        reference = artifacts.put(tenant, ident, 'ai-review', result)
        return store.set_ai_state(tenant, key(ident), json.dumps(dict(running, status='completed',
            result_ref=reference), sort_keys=True), running_raw)
    except Exception:
        store.set_ai_state(tenant, key(ident), json.dumps(dict(running, status='failed'), sort_keys=True), running_raw)
        return False


def worker(tenant, ident):
    from peaso.server.config import Settings
    from peaso.storage.runtime import stores
    store, artifacts = stores(Settings())
    if not execute(store, artifacts, tenant, ident):
        raise SystemExit(1)


def dispatch(tenant, ident):
    import boto3
    import os
    return boto3.client('stepfunctions').start_execution(stateMachineArn=os.environ['PEASO_WORKFLOW_ARN'],
        name='combined-' + ident, input=json.dumps({'tenant_id': tenant, 'combined_report_id': ident}))
