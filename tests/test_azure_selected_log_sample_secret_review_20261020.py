"""Independent query bytes -> real auth transport/collector/public production engine.

Reviewed sources are unchanged; exact admitted production hooks are exercised.
No CASES as native input, cloud authentication, network or credential validation.
"""
from copy import deepcopy
from datetime import timedelta
import inspect
import io
import json
import os
from pathlib import Path
import socket
import time
from types import SimpleNamespace
import pytest
from peaso import engine, secret_scanning as scanning
from peaso.collectors import azure
from peaso.collectors import azure_selected_log_sample_secret_indicators as source
from peaso.checks import azure_selected_log_sample_secret_review_20261020 as consumer
from tests.test_azure_selected_declaration_secret_review_20261020 import jwt
from peaso import checks,engine,secret_scanning as scanning

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
FOREIGN='/subscriptions/33333333-3333-3333-3333-333333333333'
TENANT='22222222-2222-2222-2222-222222222222'
CUSTOMER='44444444-4444-4444-4444-444444444444'
APP='55555555-5555-5555-5555-555555555555'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH='offline-log-client-secret'
PREFIX=SCOPE+'/resourceGroups/review/providers/'
SURFACES=('AppTraces','FunctionAppLogs','traces')


def profile(surface):return'application'if surface=='traces'else'workspace'
def target(surface):
    if surface=='traces':return{'resource_id':PREFIX+'Microsoft.Insights/components/selected'}
    return{'resource_id':PREFIX+'Microsoft.OperationalInsights/workspaces/selected','table':surface}


class Response:
    def __init__(self,payload,status=200,headers=None):
        self.raw=json.dumps(payload).encode()if isinstance(payload,dict)else payload
        self.status=status;self.stream=io.BytesIO(self.raw);self.closed=False;self.reads=0
        self.headers={'Content-Type':'application/json','Content-Length':str(len(self.raw)),**(headers or{})}
    def getheader(self,name):return self.headers.get(name)
    def read(self,size):assert 0<size<=16384;self.reads+=1;return self.stream.read(size)
    def close(self):self.closed=True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):pytest.fail('live socket/DNS/default auth or generic cached read forbidden')
    for name in('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,name,blocked)
    for name in('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,name,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure.AzureTransport,'request',blocked)
    scanning._RESULTS.clear()
    for name,p in source.PROFILES.items():
        registered,=[c for c in engine._registry()if c.id==p['check']]
        assert inspect.unwrap(registered.evaluate)is consumer.EVALUATORS[name]
    yield
    scanning._RESULTS.clear()


def collect(monkeypatch,surface='AppTraces',literal='mode=ready',*,real=False,transform=None,fault=None,options=None,
        targets=None,missing_engine=None,token_tenant=TENANT,token_audience=None,named=True,row_count=1):
    targets=targets or[(surface,target(surface))];trace=SimpleNamespace(calls=[],bodies=[],responses=[],connections=[],scans=[],tokens=[],readers=[])
    if not real:
        def scan(raw,path,timeout):
            trace.scans.append((len(raw),path));return[(TOKEN,'github-pat',1)]if TOKEN.encode()in raw else[]
        monkeypatch.setattr(scanning,'_scan_kingfisher',scan);monkeypatch.setattr(scanning,'_scan_trufflehog',scan)
    if missing_engine:
        def absent(*a,**kw):raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning,'_scan_'+missing_engine,absent)
    class Credential:
        def get_token(self,scope):
            assert scope in('https://management.azure.com/.default','https://api.loganalytics.io/.default','https://api.applicationinsights.io/.default')
            trace.tokens.append(scope);return SimpleNamespace(token=jwt(token_audience or scope.removesuffix('/.default'),token_tenant),expires_on=int(time.time())+3600)
        def close(self):pass
    monkeypatch.setattr(azure,'credential_for',lambda auth:Credential())
    class Connection:
        sock=None
        def __init__(self,host,timeout):
            assert host in('management.azure.com','api.loganalytics.azure.com','api.applicationinsights.io')and 0<timeout<=10
            self.host=host;self.closed=False;trace.connections.append(self)
        def set_debuglevel(self,level):assert level==0
        def request(self,method,path,body=None,headers=None):
            assert headers['Authorization'].startswith('Bearer ')and headers['Accept-Encoding']=='identity'
            operation=current=None;selected=None
            if self.host=='management.azure.com'and path==SCOPE+'?api-version=2022-12-01':
                assert method=='GET'and body is None
                operation='subscription';data={'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':TENANT,'state':'Enabled'}
            else:
                for s,t in targets:
                    rid=t['resource_id'];p=profile(s)
                    if self.host=='management.azure.com'and path==rid+'?api-version='+('2015-05-01'if p=='application'else'2022-10-01'):
                        assert method=='GET'and body is None
                        operation='resource';data={'id':rid,'name':'selected','type':'Microsoft.Insights/components'if p=='application'else'Microsoft.OperationalInsights/workspaces',
                            'properties':{'provisioningState':'Succeeded',**({'AppId':APP,'TenantId':TENANT,'InstrumentationKey':TOKEN}if p=='application'else{'customerId':CUSTOMER})}}
                    elif(self.host==('api.applicationinsights.io'if p=='application'else'api.loganalytics.azure.com')and path=='/v1/'+('apps/'+APP if p=='application'else'workspaces/'+CUSTOMER)+'/query'
                            and (s=='traces'or json.loads(body)['query'].startswith(s+' |'))):
                        assert method=='POST'and headers['Content-Type']=='application/json'and headers['Prefer']=='wait=10'
                        query=json.loads(body);assert set(query)=={'query','timespan'}
                        assert int(headers['Content-Length'])==len(body)
                        start,end=query['timespan'].split('/');assert(source.instant(end)-source.instant(start)).total_seconds()==3600
                        limit=int(query['query'].rsplit(' | take ',1)[1]);assert 1<=limit<=100
                        # Independently spell the expected native request, no source route builder.
                        prefix=('traces | where timestamp between (datetime('+start+') .. datetime('+end+')) | project Timestamp=timestamp, Message=message'if p=='application'else
                            s+' | where TimeGenerated between (datetime('+start+') .. datetime('+end+')) | where _SubscriptionId =~ "'+SCOPE.rsplit('/',1)[1]+'" | project Timestamp=TimeGenerated, Message, WorkspaceCustomerId=TenantId, SourceResourceId=_ResourceId')
                        assert query['query']==prefix+' | order by Timestamp desc | take '+str(limit)
                        trace.bodies.append(query);operation='query'
                        fields=[{'name':'Timestamp','type':'datetime'},{'name':'Message','type':'string'}]
                        if p=='workspace':fields +=[{'name':'WorkspaceCustomerId','type':'string'},{'name':'SourceResourceId','type':'string'}]
                        rows=[]
                        for i in range(row_count):
                            stamp=source.utc(source.instant(end)-timedelta(seconds=i+1))
                            rows.append([stamp,literal]+([CUSTOMER,PREFIX+'Microsoft.Insights/components/source']if p=='workspace'else[]))
                        data={'tables':[{'name':'PrimaryResult','columns':fields,'rows':rows}]}
                    if operation:current=s;selected=t;break
            assert operation is not None,(method,self.host,path)
            trace.calls.append((method,self.host,path,operation))
            if transform:data=transform(current or surface,operation,deepcopy(data))
            response=Response(data)
            if fault:response=fault(current or surface,operation,response)
            self.response=response;trace.responses.append(response)
        def getresponse(self):return self.response
        def close(self):self.closed=True
    monkeypatch.setattr(source.http.client,'HTTPSConnection',Connection)
    selected_options={'content_secret_scans':True,'retries':0}
    for s,t in targets:selected_options.setdefault(source.PROFILES[profile(s)]['option'],[]).append(t)
    selected_options.update(options or{})
    ids=list(dict.fromkeys(source.PROFILES[profile(s)]['check']for s,t in targets))
    req={'connector':{'provider':'azure','scopes':[SCOPE],'auth':{'method':'client-secret','tenant_id':TENANT,'client_id':TENANT,'client_secret':AUTH},'options':selected_options},'checks':ids[:]}
    if not named:
        req['checks']=[next(c.id for c in engine._registry()if c.provider=='azure'and c.kind=='nsg')]
        req['connector']['options']['inventories']=list({source.PROFILES[profile(s)]['kind']for s,t in targets})
    old_init=azure._Reader.__init__
    def init(reader,*a,**kw):old_init(reader,*a,**kw);trace.readers.append(reader)
    monkeypatch.setattr(azure._Reader,'__init__',init)
    snapshot=engine.collect_snapshot(req);rows=engine.evaluate_snapshot(snapshot,checks=ids)['findings']
    return snapshot,rows,trace


def own(snapshot,surface):return next(c for c in snapshot['collections']if c['type']==source.PROFILES[profile(surface)]['kind'])

def capture(surface,branch,snapshot,rows,trace,real=False):
    if os.environ.get('AZURE_LOG_SAMPLE_CAPTURE_DIR'):
        path=Path(os.environ['AZURE_LOG_SAMPLE_CAPTURE_DIR']);path.mkdir(parents=True,exist_ok=True)
        (path/(surface+'-'+branch+'.json')).write_text(json.dumps({'surface':surface,'expected_status':branch.upper(),'real_detectors':real,'snapshot':snapshot,'findings':rows,'http':trace.calls,'query_bodies':trace.bodies},indent=2,sort_keys=True))


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('hit',[False,True])
def test_native_exact_table_and_identity_public_engine(monkeypatch,surface,hit):
    snapshot,rows,trace=collect(monkeypatch,surface,TOKEN if hit else'mode=ready')
    assert {r['status']for r in rows}=={'FAIL'if hit else'PASS'},rows
    assert len(trace.calls)==3 and len(trace.scans)==2
    assert TOKEN not in json.dumps([snapshot,rows])and AUTH not in json.dumps(snapshot)
    assert 'mode=ready'not in json.dumps(snapshot)and target(surface)['resource_id']not in json.dumps(snapshot)
    assert all(r.closed for r in trace.responses)and all(c.closed for c in trace.connections)
    assert not trace.readers[0].configuration_secret_redactions


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('hit',[False,True])
def test_real_both_pinned_engines_one_leak_and_sample_claim(monkeypatch,surface,hit):
    snapshot,rows,trace=collect(monkeypatch,surface,TOKEN if hit else'mode=ready',real=True)
    assert {r['status']for r in rows}=={'FAIL'if hit else'PASS'},rows
    marker=own(snapshot,surface)['items'][0][source.MARKER]
    assert {e['status']for e in marker['parts'][0]['engines']}=={'complete'}
    if hit:
        leak,=marker['leaks'];assert{d['engine']for d in leak['detectors']}=={'kingfisher','trufflehog'}
    else:assert rows[0]['evidence']['whole_history_covered']is False
    capture(surface,'fail'if hit else'pass',snapshot,rows,trace,True)


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('mutation',['denied','deleted','redirect','encoding','truncated','empty','duplicate_json','foreign_resource','resource_type','resource_name','native_id_missing','tenant','partial_marker','extra_table','column_type','column_order','missing_column','empty_rows','too_many_rows','bad_row','row_time','future_time','row_order','row_foreign_workspace','row_foreign_resource','unknown_error'])
def test_native_partial_malformed_denied_scope_matrix(monkeypatch,surface,mutation):
    def transform(s,op,data):
        if op=='resource':
            if mutation=='foreign_resource':data['id']=data['id'].replace(SCOPE,FOREIGN)
            if mutation=='resource_type':data['type']='Microsoft.Unrelated/resources'
            if mutation=='resource_name':data['name']='foreign'
            if mutation=='native_id_missing':data['properties'].pop('AppId'if s=='traces'else'customerId')
            if mutation=='tenant'and s=='traces':data['properties']['TenantId']=CUSTOMER
        if op=='subscription'and mutation=='tenant'and surface!='traces':data['tenantId']=CUSTOMER
        if op=='query':
            table=data['tables'][0];row=table['rows'][0]
            if mutation=='partial_marker':data['nextLink']='https://evil.invalid/'+TOKEN
            if mutation=='extra_table':data['tables'].append(deepcopy(table))
            if mutation=='column_type':table['columns'][1]['type']='dynamic'
            if mutation=='column_order':table['columns'].reverse()
            if mutation=='missing_column':table['columns'].pop()
            if mutation=='empty_rows':table['rows']=[]
            if mutation=='too_many_rows':table['rows']*=101
            if mutation=='bad_row':row[1]=None
            if mutation=='row_time':row[0]='2000-01-01T00:00:00Z'
            if mutation=='future_time':row[0]='2999-01-01T00:00:00Z'
            if mutation=='row_order':table['rows']=[deepcopy(row),deepcopy(row)];table['rows'][0][0]=source.utc(source.instant(row[0])-timedelta(seconds=1))
            if mutation=='row_foreign_workspace':
                if s=='traces':table['columns'].append({'name':'appId','type':'string'})
                else:row[2]=TENANT # Azure tenant is NOT native workspace customerId
            if mutation=='row_foreign_resource':
                if s=='traces':table['rows'][0].append(TOKEN)
                else:row[3]=row[3].replace(SCOPE,FOREIGN)
            if mutation=='unknown_error':data['error']={'code':'ForbiddenError','message':TOKEN}
        return data
    def fault(s,op,response):
        if op!='query':return response
        if mutation in('denied','deleted','redirect'):return Response({'error':{'message':TOKEN}}, {'denied':403,'deleted':404,'redirect':302}[mutation])
        if mutation=='empty':return Response(b'')
        if mutation=='encoding':response.headers['Content-Encoding']='gzip'
        if mutation=='truncated':response.headers['Content-Length']=str(len(response.raw)+1)
        if mutation=='duplicate_json':return Response(b'{"tables":[],"tables":[],"error":"'+TOKEN.encode()+b'"}')
        return response
    snapshot,rows,trace=collect(monkeypatch,surface,transform=transform,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'},rows
    assert not trace.scans and TOKEN not in json.dumps([snapshot,rows])
    if mutation=='denied':
        assert trace.responses[-1].reads==0
        capture(surface,'unknown',snapshot,rows,trace)


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('hit',[False,True])
def test_documented_native_partial_error_no_clean_and_bound_hit(monkeypatch,surface,hit):
    def transform(s,op,data):
        if op=='query':data['error']={'code':'PartialError','message':TOKEN,'details':[{'code':'PartialQueryFailure','message':TOKEN}]}
        return data
    snapshot,rows,trace=collect(monkeypatch,surface,TOKEN if hit else'mode=ready',transform=transform,real=True)
    expected='FAIL'if hit and surface!='traces'else'UNKNOWN'
    assert {r['status']for r in rows}=={expected},rows
    if expected=='FAIL':assert rows[0]['evidence']['complete']is False
    assert TOKEN not in json.dumps([snapshot,rows])


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('missing',['kingfisher','trufflehog'])
@pytest.mark.parametrize('hit',[False,True])
def test_one_real_engine_missing_trusted_hit_decisive(monkeypatch,surface,missing,hit):
    snapshot,rows,_=collect(monkeypatch,surface,TOKEN if hit else'mode=ready',real=True,missing_engine=missing)
    assert {r['status']for r in rows}=={'FAIL'if hit else'UNKNOWN'},rows
    assert own(snapshot,surface)['items'][0][source.MARKER]['complete']is False


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('budget',['MAX_CALLS','MAX_WIRE','MAX_TOTAL','MAX_CONTENT','MAX_ROWS','MAX_SECONDS'])
def test_finite_work_budgets_do_not_clean(monkeypatch,surface,budget):
    monkeypatch.setattr(source,budget,0)
    _,rows,_=collect(monkeypatch,surface)
    assert {r['status']for r in rows}=={'UNKNOWN'}


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('condition',['flag','named','token_tenant','token_audience'])
def test_opt_in_and_auth_separation(monkeypatch,surface,condition):
    snapshot,rows,trace=collect(monkeypatch,surface,options={'content_secret_scans':False}if condition=='flag'else None,named=condition!='named',
        token_tenant=CUSTOMER if condition=='token_tenant'else TENANT,token_audience='https://evil.invalid'if condition=='token_audience'else None)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.calls and not trace.scans


def test_value_dedup_across_profiles_and_multiple_rows(monkeypatch):
    targets=[('AppTraces',target('AppTraces')),('traces',target('traces'))]
    snapshot,rows,_=collect(monkeypatch,literal=TOKEN,targets=targets,row_count=2,real=True)
    assert len(rows)==1 and rows[0]['status']=='FAIL'
    assert len({l['fingerprint']for c in snapshot['collections']for item in c['items']for l in item.get(source.MARKER,{}).get('leaks',[])})==1
    assert TOKEN not in json.dumps([snapshot,rows])


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('bad',['extra','foreign','url','empty','duplicate','table','customer_id'])
def test_exact_selector_contract_before_auth(surface,bad):
    t=target(surface);p=profile(surface);targets=[t]
    if bad=='extra':t['query']='union * | take 100'
    if bad=='foreign':t['resource_id']=t['resource_id'].replace(SCOPE,FOREIGN)
    if bad=='url':t['resource_id']='https://management.azure.com'+t['resource_id']
    if bad=='empty':targets=[]
    if bad=='duplicate':targets=[t,deepcopy(t)]
    if bad=='table':t['table']='union *'
    if bad=='customer_id':t['customerId']=CUSTOMER
    with pytest.raises(source.Incomplete):source.selected_targets({source.PROFILES[p]['option']:targets},[SCOPE],p)


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('mutation',['capture','scope','selection','credential','customer','receipt','binding','audience','method','host','window','snapshot_time','row_time','row_count','engine','parts','duplicate','authorized'])
def test_pure_consumer_rejects_forged_missing_or_incoherent_proof(monkeypatch,surface,mutation):
    snapshot,_,_=collect(monkeypatch,surface)
    collection=own(snapshot,surface);item=deepcopy(collection['items'][0]);kind=source.PROFILES[profile(surface)]['kind']
    index={'context':{'provider':'azure','scope':SCOPE,'created_at':snapshot['created_at'],'metadata':deepcopy(snapshot['metadata'])},'collections':{kind:[deepcopy(collection)]}}
    marker=item[source.MARKER];meta=index['context']['metadata']
    if mutation=='capture':marker['capture']='log-sample-capture:'+'0'*32
    if mutation=='scope':item['_provenance']['scope']=FOREIGN
    if mutation=='selection':meta[kind+'_selection'][SCOPE]=[]
    if mutation=='credential':item['_provenance']['credential_context_id']='foreign'
    if mutation=='customer':item['_provenance']['customer_context_id']='foreign'
    if mutation=='receipt':meta[kind+'_receipts'][-1]['identity_bound']=False
    if mutation=='binding':meta[kind+'_receipts'][-1]['target_binding']='0'*64
    if mutation=='audience':meta[kind+'_receipts'][-1]['audience']='https://evil.invalid'
    if mutation=='method':meta[kind+'_receipts'][-1]['method']='PUT'
    if mutation=='host':meta[kind+'_receipts'][-1]['host']='evil.invalid'
    if mutation=='window':marker['window_start']='2000-01-01T00:00:00Z'
    if mutation=='snapshot_time':index['context']['created_at']='2000-01-01T00:00:00Z'
    if mutation=='row_time':marker['last_row_at']='2999-01-01T00:00:00Z'
    if mutation=='row_count':marker['row_count']=101
    if mutation=='engine':marker['parts'][0]['engines'][0]['version']='invented'
    if mutation=='parts':marker['parts'][0]['complete']=False
    if mutation=='duplicate':index['collections'][kind][0]['items'].append(deepcopy(item))
    if mutation=='authorized':meta[kind+'_authorized']=False
    if mutation!='duplicate':index['collections'][kind][0]['items']=[item]
    assert consumer.EVALUATORS[profile(surface)](item,index)[0]=='UNKNOWN'


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('fault_kind',['header_oversize','stream_oversize','paging_header'])
def test_real_streaming_limits_close_and_never_scan(monkeypatch,surface,fault_kind):
    def fault(s,op,response):
        if op!='query':return response
        if fault_kind=='header_oversize':response.headers['Content-Length']=str(source.MAX_WIRE+1)
        if fault_kind=='paging_header':response.headers['Link']='<https://evil.invalid/'+TOKEN+'>;rel=next'
        if fault_kind=='stream_oversize':
            response=Response(b' '+b'x'*(source.MAX_WIRE+1));response.headers.pop('Content-Length')
        return response
    snapshot,rows,trace=collect(monkeypatch,surface,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans and TOKEN not in json.dumps(snapshot)
    assert trace.responses[-1].closed
    if fault_kind!='stream_oversize':assert trace.responses[-1].reads==0
    else:assert trace.responses[-1].stream.tell()<=source.MAX_WIRE+16384


@pytest.mark.parametrize('hit',[False,True])
def test_global_100row_budget_prevents_next_target_query_and_whole_profile_clean(monkeypatch,hit):
    targets=[('AppTraces',target('AppTraces')),('FunctionAppLogs',target('FunctionAppLogs'))]
    snapshot,rows,trace=collect(monkeypatch,literal=TOKEN if hit else'mode=ready',targets=targets,row_count=100)
    assert len(trace.bodies)==1 and trace.bodies[0]['query'].endswith(' | take 100')
    assert sum(i[source.MARKER]['row_count']for i in own(snapshot,'AppTraces')['items'])==100
    assert {r['status']for r in rows}<={'FAIL','UNKNOWN'}and not any(r['status']=='PASS'for r in rows)
    if hit:
        positive,=[r for r in rows if r['status']=='FAIL'];assert positive['evidence']['complete']is False


@pytest.mark.parametrize('hit',[False,True])
def test_next_native_source_denied_keeps_completed_hit_incomplete(monkeypatch,hit):
    targets=[('AppTraces',target('AppTraces')),('FunctionAppLogs',target('FunctionAppLogs'))]
    def fault(s,op,response):return Response({'error':{'message':TOKEN}},403)if s=='FunctionAppLogs'and op=='query'else response
    snapshot,rows,trace=collect(monkeypatch,literal=TOKEN if hit else'mode=ready',targets=targets,fault=fault)
    assert len(trace.bodies)==2 and trace.responses[-1].status==403
    if hit:
        positive,=[r for r in rows if r['status']=='FAIL'];assert positive['evidence']['complete']is False
    else:assert {r['status']for r in rows}=={'UNKNOWN'}


@pytest.mark.parametrize('surface',SURFACES)
def test_native_hits_redact_late_mixed_metadata_and_cleanup(monkeypatch,surface):
    old=azure._Reader.metadata
    monkeypatch.setattr(azure._Reader,'metadata',lambda reader:{**old(reader),'native_alias':{TOKEN:TOKEN}})
    snapshot,rows,trace=collect(monkeypatch,surface,TOKEN,real=True)
    assert {r['status']for r in rows}=={'FAIL'}and TOKEN in json.dumps(snapshot)  # found values stay visible
    assert not trace.readers[0].configuration_secret_redactions


@pytest.mark.parametrize('surface',SURFACES)
def test_existing_union_redaction_overflow_withholds_sample(monkeypatch,surface):
    from peaso.collectors import azure_selected_secret_integration_20261020 as union
    monkeypatch.setattr(union,'MAX_UNION_VALUES',0)
    snapshot,rows,trace=collect(monkeypatch,surface,TOKEN)
    assert {r['status']for r in rows}=={'FAIL'}  # no redaction budget applies to found values
    assert not trace.readers[0].configuration_secret_redactions


_NATIVE=json.loads(Path('peaso/checks/azure_selected_log_sample_secret_review_20261020_native_fixtures.json').read_text())
@pytest.mark.parametrize('capture',_NATIVE['captures'],ids=lambda row:row['surface']+'-'+row['expected_status'])
def test_portable_actual_native_samples_replay_in_fresh_process(capture):
    p=profile(capture['surface']);inputs=capture['input']
    assert consumer.EVALUATORS[p](inputs['item'],inputs['index'])[0]==capture['expected_status']
    if capture['expected_status']!='UNKNOWN':assert capture['real_detectors']is True


