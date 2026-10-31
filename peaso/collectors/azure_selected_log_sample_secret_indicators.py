"""Unregistered selected Azure application-message samples; no cached raw rows."""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import http.client
import json
import re
import time
from uuid import uuid4
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from .azure_selected_declaration_secret_indicators import GUID, SCOPE, SEG, _pairs, _bound, remaining
from .azure_selected_secret_integration_20261020 import remember

ARM = 'https://management.azure.com'
LOGS = 'https://api.loganalytics.io'
INSIGHTS = 'https://api.applicationinsights.io'
TABLES = ('AppTraces', 'FunctionAppLogs')
PROFILES = {
    'workspace': {'kind': 'azure_selected_workspace_log_sample', 'check': 'azure.review.log_analytics.selected_message_sample_secret_indicators',
        'option': 'selected_azure_log_workspaces', 'service': 'Microsoft.OperationalInsights',
        'type': 'Microsoft.OperationalInsights/workspaces', 'api': '2022-10-01',
        'host': 'api.loganalytics.azure.com', 'audience': LOGS},
    'application': {'kind': 'azure_selected_application_trace_sample', 'check': 'azure.review.application_insights.selected_trace_sample_secret_indicators',
        'option': 'selected_azure_application_insights', 'service': 'Microsoft.Insights',
        'type': 'Microsoft.Insights/components', 'api': '2015-05-01',
        'host': 'api.applicationinsights.io', 'audience': INSIGHTS},
}
KINDS = tuple(p['kind'] for p in PROFILES.values())
MARKER = 'SelectedLogSampleSecretIndicators'
SCHEMA = 'azure-selected-message-sample-v1'
MAX_TARGETS = 4
MAX_CALLS = 12
# The selected one-hour window is read whole rather than sampled. These bounds
# only stop pathological tables; a window that fills the row budget may hold
# more rows, so it stays incomplete (UNKNOWN) instead of claiming absence.
MAX_ROWS = 10000
MAX_WIRE = 32 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_CONTENT = 16 * 1024 * 1024
MAX_SECONDS = 120
WINDOW_SECONDS = 3600
MAX_LEAKS = 256
MAX_LOCATIONS = 512


class Incomplete(ValueError):
    """Only fixed nonsensitive codes leave native readers."""


def instant(value):
    if not isinstance(value, str) or len(value) > 40 or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z', value):
        raise Incomplete('invalid_timestamp')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def utc(value): return value.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def enabled(options, profile):
    return options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'), list) and PROFILES[profile]['kind'] in options['_content_secret_scan_kinds']


def parse(profile, target):
    fields = {'resource_id', 'table'} if profile == 'workspace' else {'resource_id'}
    if not isinstance(target, dict) or set(target) != fields:
        raise Incomplete('invalid_selection')
    rid = target['resource_id']; typ = PROFILES[profile]['type']
    pattern = r'(/subscriptions/' + GUID + r')/resourceGroups/' + SEG + '/providers/' + re.escape(typ) + '/' + SEG
    match = re.fullmatch(pattern, rid, re.I) if isinstance(rid, str) and len(rid) <= 1024 else None
    if not match or any(s in ('.', '..') for s in rid.split('/')) or profile == 'workspace' and target['table'] not in TABLES:
        raise Incomplete('invalid_selection')
    return match[1], rid, target['table'] if profile == 'workspace' else 'traces'


def selected_targets(options, scopes, profile=None):
    """Pure provider validator. Native customerId/AppId never comes from caller."""
    if not isinstance(options, dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
        raise Incomplete('invalid_selection')
    result = {}; total = 0
    for name in ([profile] if profile is not None else PROFILES):
        option = PROFILES[name]['option']
        if option not in options and not enabled(options, name): result[name] = []; continue
        targets = options.get(option)
        if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
                or any(not isinstance(scope, str) or not SCOPE.fullmatch(scope) for scope in scopes)
                or len({scope.casefold() for scope in scopes}) != len(scopes)
                or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
            raise Incomplete('invalid_selection')
        seen = set()
        for target in targets:
            scope, rid, table = parse(name, target); key = (rid.casefold(), table)
            if scope.casefold() not in {s.casefold() for s in scopes} or key in seen: raise Incomplete('invalid_selection')
            seen.add(key)
        total += len(targets); result[name] = deepcopy(targets)
    if total > MAX_TARGETS: raise Incomplete('invalid_selection')
    return result[profile] if profile is not None else result


def identity(profile, target):
    return PROFILES[profile]['kind'] + ':' + _fingerprint(json.dumps({**target, 'resource_id': target['resource_id'].casefold()}, sort_keys=True))


def columns(profile):
    names = [('Timestamp', 'datetime'), ('Message', 'string')]
    if profile == 'workspace': names += [('WorkspaceCustomerId', 'string'), ('SourceResourceId', 'string')]
    return [{'name': name, 'type': typ} for name, typ in names]


def query_body(profile, target, start, end, limit):
    scope, _, table = parse(profile, target)
    if type(limit) is not int or not 1 <= limit <= MAX_ROWS: raise Incomplete('row_budget')
    if (instant(end) - instant(start)).total_seconds() != WINDOW_SECONDS: raise Incomplete('window_unbound')
    if profile == 'workspace':
        query = (table + ' | where TimeGenerated between (datetime(' + start + ') .. datetime(' + end + '))'
            + ' | where _SubscriptionId =~ "' + scope.rsplit('/', 1)[1].lower() + '"'
            + ' | project Timestamp=TimeGenerated, Message, WorkspaceCustomerId=TenantId, SourceResourceId=_ResourceId')
    else:
        query = 'traces | where timestamp between (datetime(' + start + ') .. datetime(' + end + ')) | project Timestamp=timestamp, Message=message'
    return {'query': query + ' | order by Timestamp desc | take ' + str(limit), 'timespan': start + '/' + end}


def _read(reader, transport, state, receipts, ident, scope, profile, operation, path, body=None):
    remaining(reader, state)
    if state['calls'] >= MAX_CALLS: raise Incomplete('call_limit')
    detail = PROFILES[profile]; native_query = operation == 'query'
    host = detail['host'] if native_query else 'management.azure.com'
    audience = detail['audience'] if native_query else ARM
    method = 'POST' if native_query else 'GET'; state['calls'] += 1
    proof = {'id': 'log-sample-read-' + str(len(receipts) + 1), 'identity': ident, 'scope': scope,
        'profile': profile, 'operation': operation, 'method': method, 'host': host, 'audience': audience,
        'request_digest': _fingerprint(json.dumps([path, body], sort_keys=True)), 'capture': state['capture'],
        'status': 'unavailable', 'bytes': 0, 'tenant_id': None, 'identity_bound': False, 'target_binding': None}
    receipts.append(proof); response = connection = None
    try:
        token = transport.token(audience); tenant = getattr(transport, 'verified_tenant', None)
        if (not isinstance(token, str) or not token or any(c in token for c in '\r\n') or not isinstance(tenant, str)
                or not re.fullmatch(GUID, tenant, re.I) or str(getattr(transport, 'tenant', '')).casefold() != tenant.casefold()):
            raise Incomplete('tenant_unbound')
        proof['tenant_id'] = tenant
        connection = http.client.HTTPSConnection(host, timeout=remaining(reader, state)); connection.set_debuglevel(0)
        payload = json.dumps(body).encode() if native_query else None
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Accept-Encoding': 'identity',
            'Content-Length': str(len(payload) if payload else 0)}
        if native_query: headers.update({'Content-Type': 'application/json', 'Prefer': 'wait=10'})
        connection.request(method, path, body=payload, headers=headers); del token, payload
        response = connection.getresponse()
        if response.status != 200 or response.getheader('Content-Encoding') not in (None, '', 'identity') or response.getheader('Location') or response.getheader('Link'):
            raise Incomplete('read_unavailable')
        if (response.getheader('Content-Type') or '').split(';')[0].strip().lower() != 'application/json': raise Incomplete('encoding')
        length = response.getheader('Content-Length')
        if length is not None and (not re.fullmatch(r'[0-9]{1,8}', length) or not 0 < int(length) <= MAX_WIRE): raise Incomplete('byte_limit')
        chunks = []; size = 0
        while True:
            timeout = remaining(reader, state)
            if getattr(connection, 'sock', None) is not None: connection.sock.settimeout(timeout)
            chunk = response.read(16384)
            if not chunk: break
            size += len(chunk); state['bytes'] += len(chunk); proof['bytes'] = size
            if size > MAX_WIRE or state['bytes'] > MAX_TOTAL: raise Incomplete('byte_limit')
            chunks.append(chunk)
        if not size or length is not None and int(length) != size: raise Incomplete('body_incomplete')
        data = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('nonfinite')))
        if not isinstance(data, dict) or any(k in data for k in ('nextLink','@nextLink','continuationToken','partial','_partial','_coverage')): raise Incomplete('body_incomplete')
        partial = False
        if 'error' in data:
            if (not native_query or profile != 'workspace' or not isinstance(data['error'], dict) or data['error'].get('code') != 'PartialError'
                    or 'tables' not in data): raise Incomplete('query_unavailable')
            partial = True
        if native_query and set(data) - {'tables','error'}: raise Incomplete('unknown_query_shape')
        proof['status'] = 'partial' if partial else 'collected'
        # Raw native error details never leave this function even ephemerally in
        # the parsed projection passed to scanning.
        data.pop('error', None)
        return data, partial
    except Exception:
        raise Incomplete('native_read_unavailable') from None
    finally:
        if response is not None: response.close()
        if connection is not None: connection.close()


def project(profile, data, scope, native_id, start, end, limit):
    table, = data['tables']
    if not isinstance(table, dict) or set(table) != {'name','columns','rows'} or table['name'] != 'PrimaryResult' or table['columns'] != columns(profile):
        raise Incomplete('query_schema_unbound')
    rows = table['rows']
    if not isinstance(rows, list) or not 1 <= len(rows) <= limit: raise Incomplete('rows_unavailable')
    values = []; times = []; total = 0; resource_pattern = re.escape(scope) + r'/resourceGroups/' + SEG + r'/providers/[A-Za-z0-9.]+/[A-Za-z0-9_./()-]+'
    for row in rows:
        if not isinstance(row, list) or len(row) != len(columns(profile)): raise Incomplete('row_unbound')
        stamp = instant(row[0]); message = row[1]
        if stamp < instant(start) or stamp > instant(end) or not isinstance(message, str) or not message:
            raise Incomplete('row_unbound')
        if profile == 'workspace':
            if (not isinstance(row[2], str) or row[2].casefold() != native_id.casefold()
                    or not isinstance(row[3], str) or not re.fullmatch(resource_pattern, row[3], re.I)
                    or any(s in ('', '.', '..') for s in row[3].strip('/').split('/'))): raise Incomplete('row_scope_unbound')
        raw = message.encode(); total += len(raw)
        if total > MAX_CONTENT: raise Incomplete('content_limit')
        values.append(raw); times.append(stamp)
    if times != sorted(times, reverse=True): raise Incomplete('row_order_unbound')
    return values, utc(min(times)), utc(max(times))


def _scan(reader, transport, profile, target, scope, state, receipts):
    ident = identity(profile, target); first = len(receipts); _, rid, table = parse(profile, target)
    marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'profile': profile, 'table': table,
        'capture': state['capture'], 'window_start': state['start'], 'window_end': state['end'],
        'complete': False, 'query_partial': False, 'row_count': 0, 'row_limit': 0, 'first_row_at': None, 'last_row_at': None,
        'target_binding': None, 'parts': [], 'leaks': [], 'source_requests': [], 'verification': 'not_attempted'}
    try:
        def read(operation, path, body=None):
            return reader.call(_read, reader, transport, state, receipts, ident, scope, profile, operation, path, body)
        sub, _ = read('subscription', scope + '?api-version=2022-12-01')
        if (str(sub.get('id','')).casefold() != scope.casefold() or str(sub.get('subscriptionId','')).casefold() != scope.rsplit('/',1)[1].casefold()
                or str(sub.get('tenantId','')).casefold() != str(transport.verified_tenant).casefold() or sub.get('state') != 'Enabled'):
            raise Incomplete('subscription_unbound')
        receipts[-1]['identity_bound'] = True; del sub
        detail = PROFILES[profile]; resource, _ = read('resource', rid + '?api-version=' + detail['api'])
        props = _bound(resource, rid, detail['type'])
        native_id = props.get('customerId' if profile == 'workspace' else 'AppId')
        if (not isinstance(native_id, str) or not re.fullmatch(GUID, native_id, re.I) or props.get('provisioningState') != 'Succeeded'
                or profile == 'application' and str(props.get('TenantId','')).casefold() != str(transport.verified_tenant).casefold()):
            raise Incomplete('native_query_identity_unbound')
        native_id = native_id.lower(); binding = _fingerprint(native_id)
        receipts[-1].update(identity_bound=True,target_binding=binding); marker['target_binding'] = binding; del resource, props
        limit = MAX_ROWS - state['rows']; marker['row_limit'] = limit
        body = query_body(profile, target, state['start'], state['end'], limit)
        path = '/v1/' + ('workspaces/' if profile == 'workspace' else 'apps/') + native_id + '/query'
        data, partial = read('query', path, body); marker['query_partial'] = partial
        values, earliest, latest = project(profile, data, scope, native_id, state['start'], state['end'], limit)
        receipts[-1].update(identity_bound=True,target_binding=binding); del data, native_id, body
        marker.update(row_count=len(values),first_row_at=earliest,last_row_at=latest)
        state['rows'] += len(values)
        payload = b'\n\n'.join(values); del values
        if len(payload) > MAX_CONTENT: raise Incomplete('content_limit')
        result = scan_with_source(scan_content, payload, ident + '.sample_messages', timeout=remaining(reader,state)/2,
            _redact_values=lambda values: remember(reader,'configuration_secret_redactions',values), source=target_source(target, resource_id=ident, scope=scope, location_kind='log'))
        marker['parts'] = [{'bytes':len(payload),'engines':deepcopy(result['engines']),'complete':result['complete']}]; del payload
        leaks = merge_leaks(result['leaks']); bounded = []; locations = 0
        for leak in leaks:
            if len(bounded) >= MAX_LEAKS or locations + len(leak['locations']) > MAX_LOCATIONS: break
            bounded.append(leak); locations += len(leak['locations'])
        marker['leaks'] = bounded
        remaining(reader,state); marker['complete'] = (result['complete'] is True and not partial and len(bounded) == len(leaks)
            and marker['row_count'] < limit)
    except Exception:
        marker['complete'] = False
    marker['source_requests'] = [r['id']for r in receipts[first:]]
    return {'id':ident,MARKER:marker,'_provenance':{'scope':scope,'capture':state['capture'],'source_requests':marker['source_requests'][:]}}


def collect(reader, transport, scopes, wanted, options):
    targets = selected_targets(options, scopes)
    if not hasattr(reader,'configuration_secret_redactions'): reader.configuration_secret_redactions = set()
    reader.log_sample_secret_metadata = {}
    end = datetime.now(timezone.utc)
    state = {'capture':'log-sample-capture:'+uuid4().hex,'deadline':time.monotonic()+MAX_SECONDS,'bytes':0,'calls':0,'rows':0,
        'start':utc(end-timedelta(seconds=WINDOW_SECONDS)),'end':utc(end)}
    for profile,detail in PROFILES.items():
        kind = detail['kind']
        if kind not in wanted: continue
        receipts = []
        reader.log_sample_secret_metadata.update({kind+'_authorized':enabled(options,profile),kind+'_capture':state['capture'],
            kind+'_selection':{scope:[identity(profile,t)for t in targets[profile]if parse(profile,t)[0].casefold()==scope.casefold()]for scope in scopes},
            kind+'_window':{'start':state['start'],'end':state['end']},kind+'_receipts':receipts})
        if not enabled(options,profile): continue
        for scope in scopes:
            selected = [t for t in targets[profile]if parse(profile,t)[0].casefold()==scope.casefold()]
            if selected:
                def fetch(selected=selected,scope=scope,profile=profile,receipts=receipts):
                    yield [_scan(reader,transport,profile,t,scope,state,receipts)for t in selected]
                reader.run([(kind,scope,detail['service'],fetch)])


def final_snapshot(reader,snapshot):
    """Root hook proposal: ledger precedes unchanged declaration/five-reader scrub."""
    snapshot.setdefault('metadata',{}).update(getattr(reader,'log_sample_secret_metadata',{}))
    from .azure_selected_declaration_secret_indicators import final_snapshot as existing
    return existing(reader,snapshot)
