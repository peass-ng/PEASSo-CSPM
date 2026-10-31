"""Recorded API/HMAC request history; absence is never universal inactivity."""
from __future__ import annotations
from datetime import timedelta
from functools import partial
from pathlib import Path
import json
import re

from peaso.gcp_iam_usage_contract import timestamp
from peaso.gcp_key_usage_contract import API, HMAC, PARENTS, METRICS, RESOURCES, WINDOW_DAYS, LAG, credential_id, parameters
from peaso.unused_iam_gcp import Unavailable, _field, _tokens
from peaso.unused_iam_gcp_authorization import authority, records, _observe, request_rows

API_CHECK = 'gcp.iam.api_key_recent_recorded_successful_requests'
HMAC_CHECK = 'gcp.iam.hmac_key_recent_recorded_successful_requests'


def _credential(item, index, kind):
    scope, now = authority(item, index)
    rows, _ = records(index, PARENTS[kind], scope)
    if sum(row == item for row in rows) != 1:
        raise Unavailable('credential differs from its unique current native identity')
    ident = credential_id(item, kind)
    marker = item.get('_coverage', {}).get('_usageProjectIdentity', {})
    if marker.get('status') == 'denied':
        raise Unavailable('credential project identity read was denied', 'DENIED')
    if kind == API:
        name = _field(item, 'name')
        match = re.fullmatch(r'projects/([^/]+)/locations/global/keys/[^/?#]+', name or '')
        if not match or match[1] not in _tokens(index, scope):
            raise Unavailable('API key belongs to a different project')
        deleted = _field(item, 'deleteTime', None)
        if deleted is not None:
            if timestamp(deleted) > now:
                raise Unavailable('API key deletion time is in the future')
            return scope, now, ident, None, 'deleted'
        created = timestamp(_field(item, 'createTime'))
        endpoint = f'https://apikeys.googleapis.com/v2/{scope}/locations/global/keys'
    else:
        name = ident
        if _field(item, 'projectId') not in _tokens(index, scope):
            raise Unavailable('HMAC key metadata belongs to a different project')
        state = _field(item, 'state')
        if state in ('INACTIVE', 'DELETED'):
            return scope, now, ident, None, state.lower()
        if state != 'ACTIVE':
            raise Unavailable('HMAC key state is unavailable')
        email = _field(item, 'serviceAccountEmail')
        if not isinstance(email, str) or not re.fullmatch(r'[^@/\s]+@[^@/\s]+', email):
            raise Unavailable('HMAC key service-account metadata is unavailable')
        created = timestamp(_field(item, 'timeCreated'))
        endpoint = f'https://storage.googleapis.com/storage/v1/{scope}/hmacKeys'
    request_rows(index, item['_provenance'].get('source_requests'), scope, method='GET', urls={endpoint}, all_required=False)
    if created > now:
        raise Unavailable('credential creation time is in the future')
    return scope, now, ident, created, None


def _view(index, view, kind, ident, start, end, created):
    scope = view.get('scope')
    if view.get('status') == 'denied' and not view.get('series'):
        raise Unavailable('credential metric or project identity read was denied', 'DENIED')
    tokens = _tokens(index, scope)
    binding = index['context']['metadata'].get('data_service_project_bindings', {}).get(scope)
    if (not isinstance(binding, dict) or binding.get('status') != 'collected'
            or view.get('project_id') != binding.get('project_id') or view.get('project_number') != binding.get('project_number')):
        raise Unavailable('metric view project identity is unavailable')
    query = parameters(kind, binding['project_id'], ident, start.isoformat(), end.isoformat())
    if view.get('query') != query:
        raise Unavailable('metric query does not match its exact credential and interval')
    refs = view.get('source_requests')
    if not isinstance(refs, list) or not refs or len(set(refs)) != len(refs):
        raise Unavailable('metric query source requests are unavailable', 'DENIED' if view.get('status') == 'denied' else 'UNKNOWN')
    endpoint = f'https://monitoring.googleapis.com/v3/{scope}/timeSeries'
    ledger = index['context']['metadata'].get('source_requests')
    if not isinstance(ledger, list):
        raise Unavailable('native metric request ledger is unavailable')
    successful = False
    for ref in refs:
        matched = [row for row in ledger if isinstance(row, dict) and row.get('id') == ref]
        if (len(matched) != 1 or matched[0].get('scope') != scope or matched[0].get('method') != 'GET'
                or matched[0].get('url') != endpoint):
            raise Unavailable('metric request belongs to another endpoint or scope')
        receipt = matched[0]
        actual = receipt.get('query')
        if not isinstance(actual, dict) or {k:v for k,v in actual.items() if k not in ('pageSize', 'pageToken')} != query:
            raise Unavailable('metric HTTP request has a different query or aggregation')
        successful = successful or receipt.get('status') == 'collected'
    if not successful:
        raise Unavailable('metric query has no successful response', 'DENIED' if view.get('status') == 'denied' else 'UNKNOWN')
    series = view.get('series')
    if not isinstance(series, list):
        raise Unavailable('metric time series are unavailable')
    positives, attempts, seen = [], 0, set()
    for row in series:
        if not isinstance(row, dict):
            raise Unavailable('metric time series is malformed')
        metric, resource = row.get('metric'), row.get('resource')
        if (not isinstance(metric, dict) or metric.get('type') != METRICS[kind]
                or not isinstance(resource, dict) or resource.get('type') != RESOURCES[kind]
                or resource.get('labels', {}).get('project_id') not in tokens
                or row.get('metricKind') not in ('DELTA', 'GAUGE') or row.get('valueType') != 'INT64'):
            raise Unavailable('metric identity, project or count type is inconsistent')
        labels = metric.get('labels', {})
        if kind == API:
            if resource.get('labels', {}).get('credential_id') != 'apikey:'+ident:
                raise Unavailable('API request metric belongs to a different key UID')
            code = labels.get('response_code_class')
            if code not in ('1xx', '2xx', '3xx', '4xx', '5xx'):
                raise Unavailable('API response code class is unavailable')
            success = code == '2xx'
        else:
            if labels.get('access_id') != ident or labels.get('authentication_method') != 'HMAC':
                raise Unavailable('HMAC metric belongs to another key or authentication method')
            code = labels.get('response_code')
            if not isinstance(code, str) or not re.fullmatch(r'[1-5][0-9]{2}', code):
                raise Unavailable('HMAC request response code is unavailable')
            success = code.startswith('2')
        points = row.get('points')
        if not isinstance(points, list):
            raise Unavailable('metric data points are unavailable')
        for point in points:
            interval = point.get('interval') if isinstance(point, dict) else None
            value = point.get('value') if isinstance(point, dict) else None
            count = value.get('int64Value') if isinstance(value, dict) else None
            if not isinstance(interval, dict) or isinstance(count, bool) or not re.fullmatch(r'[0-9]{1,19}', str(count)):
                raise Unavailable('metric request count or interval is malformed')
            count = int(count)
            if count > 2**63-1:
                raise Unavailable('metric count exceeds the native INT64 range')
            right = timestamp(interval.get('endTime'))
            left = timestamp(interval['startTime']) if interval.get('startTime') else max(start, right-timedelta(days=1))
            identity = (code, left.isoformat(), right.isoformat())
            if identity in seen:
                raise Unavailable('duplicate aggregated credential count interval')
            seen.add(identity)
            if not start <= left < right <= end or right-left > timedelta(days=1):
                raise Unavailable('metric count interval is outside its requested daily observation')
            if count and right < created:
                raise Unavailable('metric requests predate the current credential')
            if count:
                if success:
                    positives.append({'project_scope': scope, 'interval_start': left.isoformat(),
                                      'interval_end': right.isoformat(), 'request_count': count})
                else:
                    attempts += count
    return positives, attempts


def recorded_usage(item, index, *, kind):
    scope, now, ident, created, inactive = _credential(item, index, kind)
    label = 'API key' if kind == API else 'HMAC key'
    if inactive:
        return 'NOT_APPLICABLE', {'credential_id': ident, 'reason': label+' is '+inactive}
    base = {'credential_id': ident, 'created_at': created.isoformat(), 'threshold_days': 90,
            'metric_type': METRICS[kind], 'assessment': 'recorded_metric_activity',
            'universal_inactivity_established': False}
    if created >= now-timedelta(days=90):
        return 'PASS', {**base, 'object_age_days': (now-created).days,
            'summary': f'{label} {ident} was created on {created.date().isoformat()}.\nIt has existed for fewer than 90 days.\nIts creation age is separate from successful request activity.'}
    observations, collection = records(index, kind, scope)
    rows = [row for row in observations if row.get('credential_id') == ident]
    if len(rows) != 1:
        raise Unavailable('unique credential metric observation is unavailable', 'DENIED' if collection.get('status') == 'denied' else 'UNKNOWN')
    observation = rows[0]
    authority(observation, index)
    name = item.get('name') if kind == API else ident
    if (observation.get('owner_scope') != scope or observation.get('credential_name') != name
            or observation.get('name') != scope+'/'+kind+'/'+ident):
        raise Unavailable('metric observation does not match the current credential')
    start, end = timestamp(observation.get('observation_start')), timestamp(observation.get('observation_end'))
    captured = timestamp(item['_provenance']['collected_at'])
    if end != captured-LAG or end-start != timedelta(days=WINDOW_DAYS) or now-end > timedelta(days=1):
        raise Unavailable('credential metric observation interval is stale or contradictory')
    selected = index['context']['metadata'].get('resolved_scopes')
    expected = [s for s in selected if isinstance(s, str) and s.startswith('projects/')] if isinstance(selected, list) else None
    if not expected or scope not in expected or observation.get('selected_project_scopes') != expected:
        raise Unavailable('metric project selection is not bound to the captured scan')
    views = observation.get('views')
    expected_views = [scope] if kind == API else expected
    if not isinstance(views, list) or [view.get('scope') for view in views if isinstance(view, dict)] != expected_views:
        raise Unavailable('credential metric views differ from the selected project scopes')
    successes, attempts, incomplete = [], 0, []
    for view in views:
        try:
            points, failed = _view(index, view, kind, ident, start, end, created)
            successes.extend(points)
            attempts += failed
            if view.get('status') != 'collected':
                incomplete.append({'project_scope': view['scope'], 'status': view.get('status', 'unknown')})
        except (Unavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
            incomplete.append({'project_scope': view.get('scope'), 'status': getattr(exc, 'status', 'UNKNOWN'), 'reason': str(exc)})
    base.update(observation_start=start.isoformat(), observation_end=end.isoformat(),
                metric_project_scopes=expected_views, successful_request_intervals=successes,
                failed_or_redirected_requests=attempts, unresolved_metric_views=incomplete)
    cutoff = now-timedelta(days=90)
    recent = [point for point in successes if timestamp(point['interval_start']) >= cutoff]
    if recent:
        latest = max(recent, key=lambda point: timestamp(point['interval_end']))
        return 'PASS', {**base, 'latest_recorded_successful_interval': latest,
            'summary': f'{label} {ident} has recorded successful requests in the interval ending {timestamp(latest["interval_end"]).date().isoformat()}.\nThe matching metric identifies this credential in {latest["project_scope"]}.\nThe recorded activity is within the 90-day review period.'}
    if incomplete:
        return ('DENIED' if any(str(row['status']).upper() == 'DENIED' for row in incomplete) else 'UNKNOWN'), {**base,
            'summary': f'{label} {ident} has incomplete request-metric observations.\nOne or more selected project views could not supply complete matching counts.\nIts recent recorded successful activity is unresolved.'}
    if not successes:
        return 'UNKNOWN', {**base, 'reason': 'no successful request observations; empty metrics do not establish credential inactivity',
            'summary': f'{label} {ident} has no matching successful request counts in the returned metrics.\nEmpty series or failed requests do not establish when this credential was last successfully used.\nIts recent activity is unresolved.'}
    latest = max(successes, key=lambda point: timestamp(point['interval_end']))
    if timestamp(latest['interval_end']) >= cutoff:
        return 'UNKNOWN', {**base, 'reason': 'daily metric interval straddles the 90-day boundary'}
    days = (now-timestamp(latest['interval_end'])).days
    source = 'Service Runtime' if kind == API else 'Cloud Storage authentication'
    return 'FAIL', {**base, 'latest_recorded_successful_interval': latest, 'days_since_recorded_successful_interval': days,
        'summary': f'{label} {ident} has no newer successful request record after the interval ending {timestamp(latest["interval_end"]).date().isoformat()}, {days} days before capture.\nThe {source} metric query covers the stated project scopes and observation period.\nThis old recorded activity makes the credential a cleanup-review candidate; other activity may exist outside these metrics.'}


def evaluate_api(item, index):
    return _observe(partial(recorded_usage, kind=API), item, index, 'API key request metric')


def evaluate_hmac(item, index):
    return _observe(partial(recorded_usage, kind=HMAC), item, index, 'HMAC request metric')


DECLARATIONS = (
    (API_CHECK, 'api_key', 'API key has recent recorded successful requests', evaluate_api, ('api_key', API)),
    (HMAC_CHECK, 'storage_hmac_key', 'HMAC key has recent recorded successful requests in selected projects', evaluate_hmac, ('storage_hmac_key', HMAC)),
)


def install(registry):
    from peaso.checks.fixtures import CASES
    raw = Path(__file__).with_name('checks').joinpath('unused_iam_gcp_keys_cases.json').read_bytes()
    cases = json.loads(raw)
    if set(cases) != {API_CHECK, HMAC_CHECK}:
        raise ValueError('GCP recorded credential-usage case IDs changed')
    CASES.update(cases)
    for cid, kind, title, evaluate, dependencies in DECLARATIONS:
        registry.register(cid, 'gcp', 'hardening', kind, title, 'low', 'AC-2',
            'Review credential ownership, documented workloads and other activity sources before disabling an old recorded-activity candidate.',
            dependencies=dependencies, allow_incomplete_failure=True)(evaluate)


