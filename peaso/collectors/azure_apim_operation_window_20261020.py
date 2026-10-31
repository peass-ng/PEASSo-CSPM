"""Research only: opt-in APIM operation breadth, not admitted CSPM posture.

Fixed server-side aggregation returns no caller IP, request bodies or headers.
Only selected-window counts enter the real Azure reader and snapshot. Required
operation IDs/threshold are customer analysis criteria: admission is not advised.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import re
import time
from urllib.parse import quote

from peaso.secret_scanning import _fingerprint
from .azure_function_settings_declarations_20261020 import private_native_logs
from .azure_selected_declaration_secret_indicators import GUID, SEG, SCOPE
from .azure_selected_log_sample_secret_indicators import _read as read_native
from .azure_selected_log_sample_secret_indicators import instant, utc

KIND = 'azure_selected_apim_operation_window'
CHECK = 'azure.review.apim.selected_operation_breadth_anomaly'
OPTION = 'selected_azure_apim_operation_windows'
FLAG = 'log_observation_scans'
MARKER = 'ApimOperationWindow'
SCHEMA = 'selected-apim-operation-window-v1'
ARM = 'https://management.azure.com'
LOGS = 'https://api.loganalytics.io'
VERSIONS = {'subscription': '2022-12-01', 'apim': '2024-05-01', 'workspace': '2025-07-01', 'query': 'v1'}
MAX_TARGETS, MAX_CALLS, MAX_SECONDS = 3, 12, 120
MAX_WIRE, MAX_TOTAL, WINDOW_SECONDS = 2 * 1024 * 1024, 8 * 1024 * 1024, 3600
MAX_CALLERS = 1000000000
BASE = r'(/subscriptions/' + GUID + r')/resourceGroups/' + SEG + r'/providers/'
APIM = re.compile(BASE + r'Microsoft\.ApiManagement/service/([A-Za-z](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?)', re.I)
WORKSPACE = re.compile(BASE + r'Microsoft\.OperationalInsights/workspaces/(' + SEG + ')', re.I)


class Incomplete(ValueError):
    """Fixed non-sensitive errors only."""


def parse(target):
    if not isinstance(target, dict) or set(target) != {'resource_id', 'workspace_resource_id', 'operation_ids', 'threshold_percent'}:
        raise Incomplete('invalid_selection')
    rid, wid = target['resource_id'], target['workspace_resource_id']
    apim = APIM.fullmatch(rid) if isinstance(rid, str) and len(rid) <= 512 else None
    workspace = WORKSPACE.fullmatch(wid) if isinstance(wid, str) and len(wid) <= 512 else None
    ops = target['operation_ids']
    if (not apim or not workspace or apim[1].casefold() != workspace[1].casefold()
            or any(p in ('.', '..') for p in (rid + wid).split('/'))
            or not isinstance(ops, list) or not 2 <= len(ops) <= 32
            or any(not isinstance(o, str) or not re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}', o) for o in ops)
            or len(set(ops)) != len(ops) or type(target['threshold_percent']) is not int
            or not 1 <= target['threshold_percent'] <= 99):
        raise Incomplete('invalid_selection')
    return apim[1], rid, wid


def preflight(options, scopes, named_checks):
    """No default/framework/kind selection authorizes querying logs or auth."""
    if not isinstance(options, dict) or FLAG in options and type(options[FLAG]) is not bool:
        raise Incomplete('invalid_selection')
    selected = (isinstance(named_checks, list) and all(isinstance(c, str) for c in named_checks)
                and '*' not in named_checks and CHECK in named_checks and options.get(FLAG) is True)
    if OPTION not in options and not selected:
        return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes}) != len(scopes)
            or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
        raise Incomplete('invalid_selection')
    seen = set()
    for target in targets:
        scope, rid, _ = parse(target)
        if scope.casefold() not in {s.casefold() for s in scopes} or rid.casefold() in seen:
            raise Incomplete('invalid_selection')
        seen.add(rid.casefold())
    return deepcopy(targets) if selected else []


def identity(target):
    scope, rid, wid = parse(target)
    return KIND + ':' + _fingerprint(json.dumps([rid.casefold(), wid.casefold(), target['operation_ids'], target['threshold_percent']]))


def columns():
    return [{'name': n, 'type': t} for n, t in (
        ('CallerCount', 'long'), ('MaximumOperationCount', 'long'), ('FirstSeen', 'datetime'),
        ('LastSeen', 'datetime'), ('SourceResourceId', 'string'), ('WorkspaceCustomerId', 'string'))]


def query_body(target, customer_id, start, end):
    scope, rid, _ = parse(target)
    if not isinstance(customer_id, str) or not re.fullmatch(GUID, customer_id, re.I) or (instant(end) - instant(start)).total_seconds() != WINDOW_SECONDS:
        raise Incomplete('window_unbound')
    # Exact distinct caller/operation pairs, not approximate dcount; grouping by
    # native resource/workspace columns preserves response identity witnesses.
    query = ('ApiManagementGatewayLogs'
        + ' | where TimeGenerated >= datetime(' + start + ') and TimeGenerated < datetime(' + end + ')'
        + ' | where _ResourceId =~ ' + json.dumps(rid) + ' and _SubscriptionId =~ ' + json.dumps(scope.rsplit('/', 1)[1])
        + ' and TenantId =~ ' + json.dumps(customer_id)
        + ' | where isnotempty(CallerIpAddress) and OperationId in (' + ','.join(json.dumps(o) for o in target['operation_ids']) + ')'
        + ' | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by CallerIpAddress, OperationId, _ResourceId, TenantId'
        + ' | summarize OperationCount=count(), FirstSeen=min(FirstSeen), LastSeen=max(LastSeen) by CallerIpAddress, _ResourceId, TenantId'
        + ' | summarize CallerCount=count(), MaximumOperationCount=max(OperationCount), FirstSeen=min(FirstSeen), LastSeen=max(LastSeen) by _ResourceId, TenantId'
        + ' | project CallerCount, MaximumOperationCount, FirstSeen, LastSeen, SourceResourceId=_ResourceId, WorkspaceCustomerId=TenantId')
    return {'query': query, 'timespan': start + '/' + end}


def project_query(data, target, customer_id, start, end):
    table, = data['tables']
    if (not isinstance(table, dict) or set(table) != {'name', 'columns', 'rows'}
            or table['name'] != 'PrimaryResult' or table['columns'] != columns()
            or not isinstance(table['rows'], list) or len(table['rows']) != 1):
        raise Incomplete('query_unresolved')
    row, = table['rows']
    if not isinstance(row, list) or len(row) != 6:
        raise Incomplete('query_unresolved')
    callers, breadth, first, last, rid, wid = row
    if (type(callers) is not int or not 1 <= callers <= MAX_CALLERS
            or type(breadth) is not int or not 1 <= breadth <= len(target['operation_ids'])
            or not instant(start) <= instant(first) <= instant(last) < instant(end)
            or not isinstance(rid, str) or rid.casefold() != target['resource_id'].casefold()
            or not isinstance(wid, str) or wid.casefold() != customer_id.casefold()):
        raise Incomplete('query_unbound')
    return {'callers': callers, 'maximum_operations': breadth, 'first_seen': utc(instant(first)), 'last_seen': utc(instant(last))}


def _read(reader, transport, state, receipts, target, operation, customer_id=None):
    """Project native objects before the shared reader can cache anything."""
    scope, rid, wid = parse(target)
    if operation not in VERSIONS:
        raise Incomplete('operation_forbidden')
    if state['calls'] >= MAX_CALLS:
        raise Incomplete('call_limit')
    body = query_body(target, customer_id, state['start'], state['end']) if operation == 'query' else None
    path = ('/v1/workspaces/' + customer_id.lower() + '/query' if operation == 'query'
        else quote({'subscription': scope, 'apim': rid, 'workspace': wid}[operation], safe='/') + '?api-version=' + VERSIONS[operation])
    with private_native_logs():
        data, partial = read_native(reader, transport, state, receipts, identity(target), scope, 'workspace', operation, path, body)
        receipt = receipts[-1]
        tenant = receipt['tenant_id']
        if (not isinstance(tenant, str) or not re.fullmatch(GUID, tenant, re.I)
                or state.get('tenant') not in (None, tenant.casefold())):
            raise Incomplete('tenant_unbound')
        state['tenant'] = tenant.casefold()
        receipt['tenant_id'] = state['tenant']
        if partial:
            raise Incomplete('query_partial')
        if operation == 'subscription':
            if (str(data.get('id', '')).casefold() != scope.casefold()
                    or str(data.get('subscriptionId', '')).casefold() != scope.rsplit('/', 1)[1].casefold()
                    or str(data.get('tenantId', '')).casefold() != state['tenant'] or data.get('state') != 'Enabled'):
                raise Incomplete('subscription_unbound')
            safe = {'subscription_bound': True}
        elif operation in ('apim', 'workspace'):
            selected = rid if operation == 'apim' else wid
            typ = 'Microsoft.ApiManagement/service' if operation == 'apim' else 'Microsoft.OperationalInsights/workspaces'
            props = data.get('properties')
            if (str(data.get('id', '')).casefold() != selected.casefold() or str(data.get('type', '')).casefold() != typ.casefold()
                    or str(data.get('name', '')).casefold() != selected.rsplit('/', 1)[1].casefold()
                    or not isinstance(props, dict) or props.get('provisioningState') != 'Succeeded'):
                raise Incomplete('resource_unbound')
            safe = {'resource_bound': True}
            if operation == 'workspace':
                value = props.get('customerId')
                if not isinstance(value, str) or not re.fullmatch(GUID, value, re.I):
                    raise Incomplete('workspace_unbound')
                safe = {'customer_id': value.lower()}
        else:
            safe = project_query(data, target, customer_id, state['start'], state['end'])
        data.clear()
        receipt.update(identity_bound=True, target_binding=_fingerprint(customer_id) if customer_id else None)
        return safe


def collect(reader, transport, scopes, wanted, options, *, named_checks, credential_context_id=None, customer_context_id=None):
    targets = preflight(options, scopes, named_checks)
    if KIND not in wanted or not targets:
        return
    transport_capture = getattr(transport, 'ai_context_id', None)
    capture = transport_capture if credential_context_id is None else credential_context_id
    if (not isinstance(transport_capture, str) or not re.fullmatch('[0-9a-f]{32}', transport_capture)
            or not isinstance(capture, str) or not re.fullmatch('[0-9a-f]{32}', capture)
            or credential_context_id is not None and customer_context_id != 'scan-local:' + capture
            or credential_context_id is None and customer_context_id is not None):
        raise Incomplete('capture_unbound')
    end = datetime.now(timezone.utc).replace(microsecond=0)
    state = {'capture': capture, 'tenant': None, 'deadline': time.monotonic() + MAX_SECONDS, 'bytes': 0,
        'calls': 0, 'start': utc(end - timedelta(seconds=WINDOW_SECONDS)), 'end': utc(end)}
    metadata = {KIND + '_authorized': True, KIND + '_capture': capture, KIND + '_receipts': [],
        KIND + '_selection': {scope: [identity(t) for t in targets if parse(t)[0].casefold() == scope.casefold()] for scope in scopes}}
    reader.apim_window_metadata = metadata
    receipts = metadata[KIND + '_receipts']
    for scope in scopes:
        names = [t for t in targets if parse(t)[0].casefold() == scope.casefold()]
        if not names:
            continue
        def fetch(names=names, scope=scope):
            rows = []
            for target in names:
                ident = identity(target); first = len(receipts)
                marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'capture': capture, 'complete': False,
                    'window_start': state['start'], 'window_end': state['end'], 'operation_count': len(target['operation_ids']),
                    'threshold_percent': target['threshold_percent'], 'summary': None, 'source_requests': []}
                try:
                    for operation in ('subscription', 'apim'):
                        reader.call(_read, reader, transport, state, receipts, target, operation)
                    workspace = reader.call(_read, reader, transport, state, receipts, target, 'workspace')
                    marker['summary'] = reader.call(_read, reader, transport, state, receipts, target, 'query', workspace['customer_id'])
                    marker['complete'] = True
                except Exception:
                    marker.update(complete=False, summary=None)
                marker['source_requests'] = [r['id'] for r in receipts[first:]]
                rows.append({'id': ident, MARKER: marker, '_provenance': {'scope': scope, 'capture': capture,
                    'tenant_id': state['tenant'], 'source_requests': list(marker['source_requests'])}})
            yield rows
        reader.run([(KIND, scope, 'Microsoft.ApiManagement', fetch)])
    metadata[KIND + '_tenant'] = state['tenant']


def final_snapshot(reader, snapshot):
    from .azure_selected_secret_integration_20261020 import final_snapshot as union_scrub
    from peaso.snapshot import seal
    snapshot.setdefault('metadata', {}).update(deepcopy(getattr(reader, 'apim_window_metadata', {})))
    safe = seal(union_scrub(reader, snapshot))
    reader.apim_window_metadata = {k: deepcopy(v) for k, v in safe['metadata'].items() if k.startswith(KIND + '_')}
    return safe


def collect_proposal(connector, named_checks, *, credential=None):
    """Standalone proposal bridge only; production registration is absent."""
    from .azure import AzureTransport, _Reader
    from peaso.snapshot import make_snapshot
    options, scopes = connector.get('options', {}), connector.get('scopes', [])
    targets = preflight(options, scopes, named_checks)
    if not targets:
        return make_snapshot('azure', scopes, [], metadata={'collection': 'read-only'})
    reader = _Reader({**options, 'concurrency': 1, 'retries': 0})
    transport = None
    try:
        with private_native_logs():
            try:
                transport = AzureTransport(connector.get('auth', {}), credential=credential)
            except Exception:
                for scope in scopes:
                    reader.unavailable(KIND, scope, 'Microsoft.ApiManagement', Incomplete('credential_unavailable'))
        if transport is not None:
            collect(reader, transport, scopes, [KIND], options, named_checks=named_checks)
        return final_snapshot(reader, make_snapshot('azure', scopes, reader.collections, metadata=reader.metadata()))
    finally:
        if transport is not None:
            transport.tokens.clear()
            with private_native_logs():
                try: transport.close()
                except Exception: pass
