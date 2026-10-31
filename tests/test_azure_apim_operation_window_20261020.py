"""Independent native APIM/ARM/Logs HTTP -> Azure reader/token -> public engine.

Only the proposed Check is installed locally in this module; no production
registry or historical CASES input is used to manufacture provider responses.
"""
import base64
from copy import deepcopy
from datetime import datetime, timedelta
import gzip
import io
import json
import logging
import os
from pathlib import Path
import socket
import time

from azure.core.credentials import AccessToken
import pytest

from peaso import checks, engine, secret_scanning
from peaso.collectors import azure
from peaso.collectors import azure_apim_operation_window_20261020 as source
from peaso.checks import azure_apim_operation_window_review_20261020 as consumer
from peaso.snapshot import seal, validate

SUB = '11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
CUSTOMER = '33333333-3333-3333-3333-333333333333'
FOREIGN = '44444444-4444-4444-4444-444444444444'
SCOPE = '/subscriptions/' + SUB
APIM = SCOPE + '/resourceGroups/review/providers/Microsoft.ApiManagement/service/selected-apim'
WORKSPACE = SCOPE + '/resourceGroups/review/providers/Microsoft.OperationalInsights/workspaces/selected-logs'
TARGET = {'resource_id': APIM, 'workspace_resource_id': WORKSPACE,
    'operation_ids': ['chat', 'embeddings', 'images', 'models'], 'threshold_percent': 50}
CANARY = 'private-http-auth-or-response-marker-must-not-escape'
CALLER = '192.0.2.17'
CAPTURES = []


def jwt(tenant, audience):
    value = {'tid': tenant, 'aud': audience, 'oid': FOREIGN, 'exp': int(time.time()) + 3600}
    part = base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    return 'eyJhbGciOiJub25lIn0.' + part + '.inert-offline-signature'


class Credential:
    def __init__(self, tenant=TENANT, audience=None, fail=False):
        self.tenant, self.audience, self.fail, self.calls = tenant, audience, fail, []
    def get_token(self, *scopes, **kwargs):
        assert len(scopes) == 1 and not kwargs
        audience = scopes[0].removesuffix('/.default')
        assert audience in (source.ARM, source.LOGS)
        self.calls.append(scopes)
        logging.getLogger('azure.identity').debug(CANARY)
        if self.fail:
            raise RuntimeError(CANARY)
        return AccessToken(jwt(self.tenant, self.audience or audience), int(time.time()) + 3600)


def native_events(operations=('chat',), caller=CALLER):
    return [{'CallerIpAddress': caller, 'OperationId': op, '_ResourceId': APIM,
        '_SubscriptionId': SUB, 'TenantId': CUSTOMER, 'TimeGeneratedOffset': 100 + i,
        'RequestBody': CANARY, 'RequestHeaders': {'secret': CANARY}} for i, op in enumerate(operations)]


def expected_query(target, start, end, customer=CUSTOMER):
    # Independently authored fixed native request contract, not evaluator output.
    rid = target['resource_id']; sub = rid.split('/')[2]
    query = ('ApiManagementGatewayLogs'
        + f' | where TimeGenerated >= datetime({start}) and TimeGenerated < datetime({end})'
        + ' | where _ResourceId =~ ' + json.dumps(rid) + ' and _SubscriptionId =~ ' + json.dumps(sub)
        + ' and TenantId =~ ' + json.dumps(customer)
        + ' | where isnotempty(CallerIpAddress) and OperationId in (' + ','.join(json.dumps(o) for o in target['operation_ids']) + ')'
        + ' | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by CallerIpAddress, OperationId, _ResourceId, TenantId'
        + ' | summarize OperationCount=count(), FirstSeen=min(FirstSeen), LastSeen=max(LastSeen) by CallerIpAddress, _ResourceId, TenantId'
        + ' | summarize CallerCount=count(), MaximumOperationCount=max(OperationCount), FirstSeen=min(FirstSeen), LastSeen=max(LastSeen) by _ResourceId, TenantId'
        + ' | project CallerCount, MaximumOperationCount, FirstSeen, LastSeen, SourceResourceId=_ResourceId, WorkspaceCustomerId=TenantId')
    return {'query': query, 'timespan': start + '/' + end}


def native_result(events, target, start, end):
    """Model the documented exact KQL aggregation over independent native logs."""
    first = datetime.fromisoformat(start.replace('Z', '+00:00'))
    last = datetime.fromisoformat(end.replace('Z', '+00:00'))
    callers, times = {}, []
    for event in events:
        stamp = first + timedelta(seconds=event['TimeGeneratedOffset'])
        if (not first <= stamp < last or event['_ResourceId'].casefold() != target['resource_id'].casefold()
                or event['_SubscriptionId'].casefold() != target['resource_id'].split('/')[2].casefold()
                or event['TenantId'].casefold() != CUSTOMER.casefold() or not event['CallerIpAddress']
                or event['OperationId'] not in target['operation_ids']):
            continue
        callers.setdefault(event['CallerIpAddress'], set()).add(event['OperationId']); times.append(stamp)
    schema = [{'name': n, 'type': t} for n, t in [('CallerCount','long'), ('MaximumOperationCount','long'),
        ('FirstSeen','datetime'), ('LastSeen','datetime'), ('SourceResourceId','string'), ('WorkspaceCustomerId','string')]]
    rows = [] if not callers else [[len(callers), max(map(len, callers.values())),
        min(times).isoformat().replace('+00:00','Z'), max(times).isoformat().replace('+00:00','Z'), target['resource_id'], CUSTOMER]]
    return {'tables': [{'name': 'PrimaryResult', 'columns': schema, 'rows': rows}]}


class Response:
    def __init__(self, value, status=200, headers=None):
        self.raw = json.dumps(value).encode() if not isinstance(value, bytes) else value
        self.stream = io.BytesIO(self.raw); self.closed = False; self.status = status
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.raw)), **(headers or {})}
    def getheader(self, name): return self.headers.get(name)
    def read(self, count):
        assert 0 < count <= 16384
        return self.stream.read(count)
    def close(self): self.closed = True


class Wire:
    def __init__(self, targets, events, fault):
        self.targets, self.events, self.fault = targets, events, fault
        self.calls, self.responses, self.connections = [], [], []
    def connection(self, host, timeout):
        assert host in ('management.azure.com', 'api.loganalytics.azure.com') and 0 < timeout <= 10
        wire = self
        class Connection:
            sock = None
            def __init__(self): self.closed = False; self.debug = None
            def set_debuglevel(self, level): assert level == 0; self.debug = level
            def request(self, method, path, body=None, headers=None):
                assert self.debug == 0 and headers['Authorization'].startswith('Bearer ey')
                assert headers['Accept'] == 'application/json' and headers['Accept-Encoding'] == 'identity'
                logging.getLogger('azure.core.pipeline.policies.http_logging_policy').debug(CANARY + path)
                if host == 'api.loganalytics.azure.com':
                    assert method == 'POST' and path == '/v1/workspaces/' + CUSTOMER + '/query'
                    assert set(headers) == {'Authorization','Accept','Accept-Encoding','Content-Length','Content-Type','Prefer'}
                    assert headers['Content-Type'] == 'application/json' and headers['Prefer'] == 'wait=10'
                    assert headers['Content-Length'] == str(len(body))
                    query = json.loads(body); start, end = query['timespan'].split('/')
                    target, = [t for t in wire.targets if json.dumps(t['resource_id']) in query['query']]
                    assert query == expected_query(target, start, end)
                    assert (datetime.fromisoformat(end.replace('Z','+00:00')) - datetime.fromisoformat(start.replace('Z','+00:00'))).total_seconds() == 3600
                    op, value = 'query', native_result(wire.events, target, start, end)
                else:
                    assert method == 'GET' and body is None and headers['Content-Length'] == '0'
                    assert set(headers) == {'Authorization','Accept','Accept-Encoding','Content-Length'}
                    if path == SCOPE + '?api-version=2022-12-01':
                        op, value = 'subscription', {'id': SCOPE, 'subscriptionId': SUB, 'tenantId': TENANT, 'state': 'Enabled'}
                    else:
                        matches = [(t, op, typ) for t in wire.targets for op, key, version, typ in (
                            ('apim', 'resource_id', '2024-05-01', 'Microsoft.ApiManagement/service'),
                            ('workspace', 'workspace_resource_id', '2025-07-01', 'Microsoft.OperationalInsights/workspaces'))
                            if path == t[key] + '?api-version=' + version]
                        assert matches, (method, host, path)
                        target, op, typ = matches[0]; rid = target['resource_id' if op == 'apim' else 'workspace_resource_id']
                        value = {'id': rid, 'name': rid.rsplit('/',1)[1], 'type': typ,
                            'properties': {'provisioningState': 'Succeeded', 'unretainedValue': CANARY}}
                        if op == 'workspace': value['properties']['customerId'] = CUSTOMER
                wire.calls.append({'method': method, 'host': host, 'path': path, 'operation': op,
                    'body': json.loads(body) if body else None})
                result = wire.fault(op, value) if wire.fault else value
                if isinstance(result, Exception): raise result
                self.response = result if isinstance(result, Response) else Response(result)
                wire.responses.append(self.response)
            def getresponse(self): return self.response
            def close(self): self.closed = True
        result = Connection(); wire.connections.append(result); return result


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError('Actual network/auth/detectors forbidden')
    for key in ('connect','connect_ex'): monkeypatch.setattr(socket.socket, key, blocked)
    for key in ('getaddrinfo','gethostbyname','create_connection'): monkeypatch.setattr(socket, key, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    # Block real detector processes below the attested scanner module.
    monkeypatch.setattr(secret_scanning.subprocess, 'Popen', blocked)
    p = consumer.PROPOSAL
    addition = checks.Check(p['id'], 'azure', p['category'], p['kind'], p['title'], p['severity'], '',
        '\n'.join(p['remediation']), p['evaluate'], declared_dependencies=p['dependencies'])
    assert source.CHECK not in {c.id for c in checks.CHECKS}
    # Extend the live registry in place: attested modules keep their CHECKS binding.
    checks.CHECKS.append(addition)
    try:
        yield
    finally:
        checks.CHECKS.remove(addition)


@pytest.fixture(scope='session', autouse=True)
def record_captures():
    yield
    if folder := os.environ.get('APIM_WINDOW_RECEIPTS'):
        Path(folder).mkdir(parents=True, exist_ok=True)
        Path(folder, 'native-captures.json').write_text(json.dumps(CAPTURES, indent=2) + '\n')


def capture(monkeypatch, *, events=None, fault=None, targets=None, options=None, selected=None, credential=None):
    targets = deepcopy([TARGET] if targets is None else targets)
    wire = Wire(targets, native_events() if events is None else events, fault)
    monkeypatch.setattr(source.read_native.__globals__['http'].client, 'HTTPSConnection', wire.connection)
    credential = credential or Credential()
    settings = {source.FLAG: True, source.OPTION: targets, **(options or {})}
    snapshot = source.collect_proposal({'scopes': [SCOPE], 'auth': {'tenant_id': TENANT}, 'options': settings},
        [source.CHECK] if selected is None else selected, credential=credential)
    validate(snapshot)
    result = engine.evaluate_snapshot(snapshot, checks=[source.CHECK])
    assert CANARY not in json.dumps(snapshot) + json.dumps(result)
    assert CALLER not in json.dumps(snapshot) + json.dumps(result)
    assert all(r.closed for r in wire.responses) and all(c.closed for c in wire.connections)
    finding = result['findings'][0]
    if finding['status'] == 'UNKNOWN' and not any(c['status'] == 'UNKNOWN' for c in CAPTURES):
        CAPTURES.append({'case': 'unresolved_window', 'status': 'UNKNOWN', 'native_requests': wire.calls,
            'snapshot': snapshot, 'finding': finding})
    return snapshot, finding, wire, credential


@pytest.mark.parametrize('ops,threshold,expected', [(['chat'],50,'PASS'),
    (['chat','embeddings'],50,'PASS'), (['chat','embeddings','images'],50,'FAIL'),
    (['chat','embeddings','images','models'],99,'FAIL'), (['chat'],1,'FAIL'),
    (['chat','chat','chat'],50,'PASS')])
def test_native_exact_breadth_boundaries(monkeypatch, ops, threshold, expected):
    target = {**TARGET, 'threshold_percent': threshold}
    snapshot, finding, wire, credential = capture(monkeypatch, targets=[target], events=native_events(ops))
    assert finding['status'] == expected
    assert len(wire.calls) == 4 and len(credential.calls) == 2
    assert 'compromise or alert delivery' in finding['evidence']['observed']
    CAPTURES.append({'case': 'breadth_' + expected.lower(), 'status': expected, 'native_requests': wire.calls,
        'snapshot': snapshot, 'finding': finding})


def test_native_multiple_callers_not_union(monkeypatch):
    events = native_events(['chat','embeddings']) + native_events(['images','models'], caller='2001:db8::12')
    snapshot, finding, _, _ = capture(monkeypatch, events=events)
    assert finding['status'] == 'PASS' and finding['evidence']['maximum_operations'] == 2
    assert finding['evidence']['observed_callers'] == 2


@pytest.mark.parametrize('field,value', [('OperationId','unselected'), ('CallerIpAddress',''),
    ('_ResourceId',APIM + '-foreign'), ('_SubscriptionId',FOREIGN), ('TenantId',FOREIGN),
    ('TimeGeneratedOffset',-1), ('TimeGeneratedOffset',3600)])
def test_native_empty_nonmatching_not_negative(monkeypatch, field, value):
    events = native_events(['chat','embeddings','images'])
    for row in events: row[field] = value
    _, finding, _, _ = capture(monkeypatch, events=events)
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('operation', ['subscription','apim','workspace','query'])
@pytest.mark.parametrize('status', [401,403,404,429,500])
def test_native_denied_and_errors(monkeypatch, operation, status):
    _, finding, wire, _ = capture(monkeypatch, fault=lambda op, data: Response({'error': {'code': CANARY}},status) if op == operation else data)
    assert finding['status'] == 'UNKNOWN'
    assert len(wire.calls) == ['subscription','apim','workspace','query'].index(operation) + 1


@pytest.mark.parametrize('operation', ['subscription','apim','workspace','query'])
@pytest.mark.parametrize('marker', ['nextLink','@nextLink','continuationToken','partial','_coverage'])
def test_native_pagination_and_partial_not_followed(monkeypatch, operation, marker):
    _, finding, wire, _ = capture(monkeypatch, fault=lambda op,data: {**data, marker: 'https://untrusted.invalid/' + CANARY} if op == operation else data)
    assert finding['status'] == 'UNKNOWN'
    assert len(wire.calls) == ['subscription','apim','workspace','query'].index(operation) + 1


@pytest.mark.parametrize('ops', [['chat'], ['chat','embeddings','images']])
def test_native_partial_error_not_complete_even_with_counts(monkeypatch, ops):
    _, finding, _, _ = capture(monkeypatch, events=native_events(ops), fault=lambda op,data:
        {**data, 'error': {'code': 'PartialError', 'details': [{'message': CANARY}]}} if op == 'query' else data)
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('op,field,value', [('subscription','id','/subscriptions/' + FOREIGN),
    ('subscription','subscriptionId',FOREIGN), ('subscription','tenantId',FOREIGN), ('subscription','state','Disabled'),
    ('apim','id',APIM + '-foreign'), ('apim','type','Microsoft.Web/sites'), ('apim','name','foreign'),
    ('workspace','id',WORKSPACE + '-foreign'), ('workspace','type','Microsoft.Web/sites'), ('workspace','name','foreign')])
def test_native_owner_type_scope_binding(monkeypatch, op, field, value):
    _, finding, _, _ = capture(monkeypatch, fault=lambda operation,data: {**data,field:value} if operation == op else data)
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('operation', ['apim','workspace'])
@pytest.mark.parametrize('props', [None, {}, {'provisioningState':'Failed'}, {'provisioningState':'Succeeded','customerId':None}])
def test_native_resource_omissions(monkeypatch, operation, props):
    _, finding, _, _ = capture(monkeypatch, fault=lambda op,data: {**data,'properties':props} if op == operation else data)
    assert finding['status'] == ('PASS' if operation == 'apim' and isinstance(props,dict) and props.get('provisioningState') == 'Succeeded' else 'UNKNOWN')


@pytest.mark.parametrize('column,value', [(0,0),(0,True),(0,1.0),(0,1000000001),(1,0),(1,True),(1,5),(1,'1'),
    (2,'invalid'),(3,'invalid'),(4,APIM + '-foreign'),(5,FOREIGN)])
def test_native_aggregate_grammar(monkeypatch, column, value):
    def fault(op,data):
        if op == 'query': data['tables'][0]['rows'][0][column] = value
        return data
    _, finding, _, _ = capture(monkeypatch, fault=fault)
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('case', ['empty','two_rows','two_tables','columns','table_name','extra_field','missing_rows','reversed_time','outside_time'])
def test_native_query_schema_omission_time_guards(monkeypatch, case):
    def fault(op,data):
        if op != 'query': return data
        table = data['tables'][0]
        if case == 'empty': table['rows'] = []
        elif case == 'two_rows': table['rows'] *= 2
        elif case == 'two_tables': data['tables'] *= 2
        elif case == 'columns': table['columns'][0]['type'] = 'string'
        elif case == 'table_name': table['name'] = 'Other'
        elif case == 'extra_field': data['statistics'] = {'unexpected': CANARY}
        elif case == 'missing_rows': del table['rows']
        elif case == 'reversed_time': table['rows'][0][2] = '2099-01-01T00:00:00Z'
        elif case == 'outside_time': table['rows'][0][3] = '2000-01-01T00:00:00Z'
        return data
    _, finding, _, _ = capture(monkeypatch, fault=fault)
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('headers', [{'Location':'https://untrusted.invalid/' + CANARY}, {'Link':'opaque'},
    {'Content-Encoding':'gzip'}, {'Content-Type':'text/plain'}, {'Content-Length':'0'},
    {'Content-Length':'2097153'}, {'Content-Length':'1'}, {'Content-Length':'-1'}])
def test_native_wire_boundaries(monkeypatch, headers):
    _, finding, _, _ = capture(monkeypatch, fault=lambda op,data: Response(data,headers=headers) if op == 'query' else data)
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('raw', [b'{"tables":[],"tables":[]}', b'[]', b'null', b'{', b'{"tables":NaN}'])
def test_native_duplicate_malformed_json(monkeypatch, raw):
    _, finding, _, _ = capture(monkeypatch, fault=lambda op,data: Response(raw) if op == 'query' else data)
    assert finding['status'] == 'UNKNOWN'


@pytest.mark.parametrize('selected,options', [([] ,{}), (['*'],{}), ([source.CHECK],{source.FLAG:False}),
    (['azure.port.anything'],{}), ([source.CHECK],{source.FLAG:False, '_content_secret_scan_kinds':[source.KIND]})])
def test_native_default_gate_precedes_auth(monkeypatch, selected, options):
    _, finding, wire, credential = capture(monkeypatch, selected=selected, options=options)
    assert finding['status'] == 'UNKNOWN' and not wire.calls and not credential.calls


@pytest.mark.parametrize('change', [{'operation_ids':[]}, {'operation_ids':['chat']}, {'operation_ids':['chat','chat']},
    {'operation_ids':['chat','x") | union * //']}, {'threshold_percent':True}, {'threshold_percent':0},
    {'threshold_percent':100}, {'threshold_percent':50.0}, {'workspace_resource_id':WORKSPACE.replace(SUB,FOREIGN)},
    {'resource_id':'https://untrusted.invalid'}, {'resource_id':APIM + '/apis/x'}, {'extra':'not-supported'}])
def test_invalid_selector_before_auth(monkeypatch, change):
    with pytest.raises(source.Incomplete, match='invalid_selection'):
        capture(monkeypatch, targets=[{**TARGET,**change}])


@pytest.mark.parametrize('targets', [[TARGET,TARGET], [TARGET]*4, [], None])
def test_native_selector_count_or_duplicates(monkeypatch, targets):
    if targets is None: targets = ['bad']
    with pytest.raises(source.Incomplete): capture(monkeypatch, targets=targets)


@pytest.mark.parametrize('credential', [Credential(tenant=FOREIGN), Credential(audience='https://foreign.invalid'), Credential(fail=True)])
def test_native_auth_rejection(monkeypatch, credential):
    _, finding, wire, _ = capture(monkeypatch, credential=credential)
    assert finding['status'] == 'UNKNOWN' and not wire.calls


def test_native_debug_failure_redaction(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    _, finding, _, _ = capture(monkeypatch, fault=lambda op,data: RuntimeError(CANARY) if op == 'query' else data)
    assert finding['status'] == 'UNKNOWN' and CANARY not in caplog.text
    logging.getLogger('azure.identity').debug('logging-restored-after-observation')
    assert 'logging-restored-after-observation' in caplog.text


@pytest.mark.parametrize('tamper', ['authorized','capture','tenant','scope','complete','summary','request','partial','duplicate','customer_context'])
def test_consumer_rejects_capture_or_receipt_spoof(monkeypatch, tamper):
    snapshot, _, _, _ = capture(monkeypatch)
    row = snapshot['collections'][0]; item = row['items'][0]; metadata = snapshot['metadata']; marker = item[source.MARKER]
    if tamper == 'authorized': metadata[source.KIND + '_authorized'] = False
    elif tamper == 'capture': marker['capture'] = '0'*32
    elif tamper == 'tenant': metadata[source.KIND + '_tenant'] = FOREIGN
    elif tamper == 'scope': item['_provenance']['scope'] = '/subscriptions/' + FOREIGN
    elif tamper == 'complete': marker['complete'] = False
    elif tamper == 'summary': marker['summary']['maximum_operations'] = True
    elif tamper == 'request': metadata[source.KIND + '_receipts'][-1]['host'] = 'untrusted.invalid'
    elif tamper == 'partial': row['status'] = 'partial'
    elif tamper == 'duplicate': row['items'].append(deepcopy(item))
    elif tamper == 'customer_context': metadata['customer_context_id'] = 'foreign-context'
    report = engine.evaluate_snapshot(seal(snapshot), checks=[source.CHECK])
    assert report['findings'][0]['status'] == 'UNKNOWN'


def test_native_portable_capture_replay():
    path = Path(__file__).parents[1] / 'peaso/checks/azure_apim_operation_window_native_cases_20261020.json.gz'
    cases = json.loads(gzip.decompress(path.read_bytes()))
    assert {case['status'] for case in cases['cases']} == {'PASS','FAIL','UNKNOWN'}
    for case in cases['cases']:
        report = engine.evaluate_snapshot(case['snapshot'], checks=[source.CHECK])
        assert report['findings'][0]['status'] == case['status']


def test_native_maximum_three_targets_with_shared_budget(monkeypatch):
    targets = [{**deepcopy(TARGET), 'resource_id': APIM + str(i)} for i in range(3)]
    events = [{**row, '_ResourceId': target['resource_id']} for target in targets for row in native_events(['chat'])]
    snapshot, _, wire, _ = capture(monkeypatch, targets=targets, events=events)
    report = engine.evaluate_snapshot(snapshot, checks=[source.CHECK])
    assert len(wire.calls) == 12 and len(report['findings']) == 3
    assert {f['status'] for f in report['findings']} == {'PASS'}


@pytest.mark.parametrize('budget', ['deadline','wire','total','calls'])
def test_native_budget_exhaustion_not_negative(monkeypatch, budget):
    native = source.read_native
    def exhausted(reader, transport, state, receipts, *args, **kwargs):
        if budget == 'deadline': state['deadline'] = time.monotonic() - 1
        elif budget == 'total': state['bytes'] = source.MAX_TOTAL
        elif budget == 'calls': state['calls'] = source.MAX_CALLS
        elif budget == 'wire':
            raise source.Incomplete('bounded_wire_unavailable')
        return native(reader,transport,state,receipts,*args,**kwargs)
    monkeypatch.setattr(source, 'read_native', exhausted)
    # This is a direct producer boundary test, not a change to the signed wire
    # helper or a source receipt bypass in the standalone admission bridge.
    wire = Wire([TARGET], native_events(), None)
    monkeypatch.setattr(native.__globals__['http'].client, 'HTTPSConnection', wire.connection)
    reader = azure._Reader({'concurrency':1,'retries':0})
    transport = azure.AzureTransport({'tenant_id':TENANT},credential=Credential())
    source.collect(reader,transport,[SCOPE],[source.KIND],{source.FLAG:True,source.OPTION:[TARGET]},named_checks=[source.CHECK])
    from peaso.snapshot import make_snapshot
    snapshot = source.final_snapshot(reader,make_snapshot('azure',[SCOPE],reader.collections,metadata=reader.metadata()))
    assert engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings'][0]['status'] == 'UNKNOWN'
    transport.tokens.clear(); transport.close()


