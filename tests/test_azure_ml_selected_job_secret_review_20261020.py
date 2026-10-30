"""Independent exact native ARM bytes -> real transport/collector -> actual public production engine."""
from copy import deepcopy
import inspect
import io
import json
import logging
import os
from pathlib import Path
import socket
import time
from types import SimpleNamespace
import pytest
from peaso import engine, secret_scanning as scanning
from peaso.collectors import azure
from peaso.collectors import azure_ml_selected_job_secret_indicators as source
from peaso.collectors import azure_selected_declaration_secret_indicators as native_http
from peaso.checks import azure_ml_selected_job_secret_review_20261020 as consumer
from tests.test_azure_selected_declaration_secret_review_20261020 import jwt
from peaso import checks,engine,secret_scanning as scanning

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
FOREIGN='/subscriptions/33333333-3333-3333-3333-333333333333'
TENANT='22222222-2222-2222-2222-222222222222'
WORKSPACE_ID='44444444-4444-4444-4444-444444444444'
WORKSPACE=SCOPE+'/resourceGroups/review/providers/Microsoft.MachineLearningServices/workspaces/selected'
JOB=WORKSPACE+'/jobs/JobCase'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH='offline-ml-client-secret'


def target(rid=JOB):return{'resource_id':rid}


class Response:
    def __init__(self,data,status=200,headers=None):
        self.raw=json.dumps(data).encode()if isinstance(data,dict)else data
        self.status=status;self.stream=io.BytesIO(self.raw);self.closed=False;self.reads=0
        self.headers={'Content-Type':'application/json','Content-Length':str(len(self.raw)),**(headers or{})}
    def getheader(self,name):return self.headers.get(name)
    def read(self,size):assert 0<size<=16384;self.reads+=1;return self.stream.read(size)
    def close(self):self.closed=True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):pytest.fail('Live socket/DNS/default auth/generic cached native requests forbidden')
    for n in('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure.AzureTransport,'request',blocked)
    registered,=[c for c in engine._registry()if c.id==source.CHECK]
    assert inspect.unwrap(registered.evaluate)is consumer.evaluate
    scanning._RESULTS.clear();yield;scanning._RESULTS.clear()


def collect(monkeypatch,literal='mode=ready',*,real=False,transform=None,fault=None,options=None,targets=None,named=True,absent=None,token_tenant=TENANT,late=None,omit_flag=False,concrete_http=False):
    targets=targets or[target()];trace=SimpleNamespace(calls=[],responses=[],scans=[],tokens=[],readers=[],connections=[])
    if not real:
        def scan(raw,path,timeout):trace.scans.append((len(raw),path));return[(TOKEN,'github-pat',1)]if TOKEN.encode()in raw else[]
        monkeypatch.setattr(scanning,'_scan_kingfisher',scan);monkeypatch.setattr(scanning,'_scan_trufflehog',scan)
    if absent:
        def unavailable(*a,**kw):raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning,'_scan_'+absent,unavailable)
    class Credential:
        def get_token(self,scope):
            assert scope=='https://management.azure.com/.default';trace.tokens.append(scope)
            return SimpleNamespace(token=jwt('https://management.azure.com',token_tenant),expires_on=int(time.time())+3600)
        def close(self):pass
    monkeypatch.setattr(azure,'credential_for',lambda auth:Credential())
    class Connection:
        sock=None
        def __init__(self,host,timeout):assert host=='management.azure.com'and 0<timeout<=10;self.closed=False;trace.connections.append(self)
        def set_debuglevel(self,n):assert n==0
        def request(self,method,path,body=None,headers=None):
            assert method=='GET'and body is None and headers['Authorization'].startswith('Bearer ')and headers['Accept-Encoding']=='identity'
            operation=rid=None
            if path==SCOPE+'?api-version=2022-12-01':
                operation='subscription';data={'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':TENANT,'state':'Enabled'}
            elif path==WORKSPACE+'?api-version=2026-03-01':
                operation='workspace';data={'id':WORKSPACE,'name':'selected','type':'Microsoft.MachineLearningServices/workspaces','properties':{'workspaceId':WORKSPACE_ID,'tenantId':TENANT,'provisioningState':'Succeeded','storageAccount':TOKEN}}
            else:
                for t in targets:
                    if path==t['resource_id']+'?api-version=2024-04-01':
                        operation='job';rid=t['resource_id'];data={'id':rid,'name':rid.rsplit('/',1)[1],'type':'Microsoft.MachineLearningServices/workspaces/jobs','properties':{'jobType':'Command','command':'python train.py --mode ready','environmentVariables':{'SETTING':literal},'codeId':WORKSPACE+'/codes/source/versions/1','environmentId':WORKSPACE+'/environments/source/versions/1','services':{'private':{'endpoint':'https://evil.invalid/'+TOKEN}}}}
                        break
            assert operation is not None,(method,path)
            trace.calls.append((method,'management.azure.com',path,operation))
            if transform:data=transform(operation,deepcopy(data),rid)
            response=Response(data)
            if fault:response=fault(operation,response,rid)
            self.response=response;trace.responses.append(response)
        def getresponse(self):return self.response
        def close(self):self.closed=True
    if concrete_http:
        real_https=native_http.http.client.HTTPSConnection
        class MemorySocket:
            def __init__(self,response):
                header=('HTTP/1.1 '+str(response.status)+' '+('OK'if response.status==200 else'Forbidden')+'\r\n'+''.join(k+': '+v+'\r\n'for k,v in response.headers.items())+'\r\n').encode()
                self.stream=io.BytesIO(header+response.raw);self.closed=False
            def sendall(self,data):assert isinstance(data,bytes) # Ephemeral native request; never retained.
            def makefile(self,mode):assert mode=='rb';return self.stream
            def settimeout(self,n):assert 0<n<=10
            def close(self):self.closed=True
        class NativeHTTPS(real_https):
            def __init__(self,host,timeout):
                # Real HTTP serializer/parser; TLS connect replaced by inert memory socket.
                # Avoid stdlib old-style super's patched module-global HTTPSConnection.
                native_http.http.client.HTTPConnection.__init__(self,host,timeout=timeout)
            def connect(self):self.sock=MemorySocket(self.driver.response)
            def request(self,method,path,body=None,headers=None,**kwargs):
                self.driver=Connection(self.host,self.timeout);self.driver.set_debuglevel(self.debuglevel)
                self.driver.request(method,path,body,headers)
                return super().request(method,path,body,headers,**kwargs)
            def close(self):
                if hasattr(self,'driver'):self.driver.response.close();self.driver.close()
                super().close()
        selected_connection=NativeHTTPS
    else:selected_connection=Connection
    monkeypatch.setattr(native_http.http.client,'HTTPSConnection',selected_connection)
    opts={'content_secret_scans':True,source.OPTION:targets,'retries':0};opts.update(options or{})
    if omit_flag:opts.pop('content_secret_scans')
    req={'connector':{'provider':'azure','scopes':[SCOPE],'auth':{'method':'client-secret','tenant_id':TENANT,'client_id':TENANT,'client_secret':AUTH},'options':opts},'checks':[source.CHECK]if named else[next(c.id for c in engine._registry()if c.provider=='azure'and c.kind=='nsg')]}
    if not named:req['connector']['options']['inventories']=[source.KIND]
    old=azure._Reader.__init__
    def init(reader,*a,**kw):old(reader,*a,**kw);trace.readers.append(reader)
    monkeypatch.setattr(azure._Reader,'__init__',init)
    if late:
        final=source.final_snapshot
        def after(reader,snapshot):late(reader,snapshot);return final(reader,snapshot)
        monkeypatch.setattr(azure.azure_ml_selected_job_secret_indicators,'final_snapshot',after)
    snapshot=engine.collect_snapshot(req);rows=engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']
    return snapshot,rows,trace


def own(snapshot):return next(c for c in snapshot['collections']if c['type']==source.KIND)


def capture(branch,snapshot,rows,trace,real):
    if os.environ.get('AZURE_ML_JOB_CAPTURE_DIR'):
        path=Path(os.environ['AZURE_ML_JOB_CAPTURE_DIR']);path.mkdir(parents=True,exist_ok=True)
        (path/(branch+'.json')).write_text(json.dumps({'expected_status':branch.upper(),'real_detectors':real,'snapshot':snapshot,'findings':rows,'http':trace.calls},indent=2,sort_keys=True))


@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('real',[False,True])
def test_native_three_identity_reads_dual_engines_no_execution(monkeypatch,hit,real):
    snapshot,rows,trace=collect(monkeypatch,TOKEN if hit else'mode=ready',real=real)
    assert {r['status']for r in rows}=={'FAIL'if hit else'PASS'},rows
    assert len(trace.calls)==4 and all(r.closed for r in trace.responses)and all(c.closed for c in trace.connections)
    assert TOKEN not in json.dumps([snapshot,rows,scanning._RESULTS.__repr__()])and AUTH not in json.dumps(snapshot)
    if hit:
        leak,=own(snapshot)['items'][0][source.MARKER]['leaks'];assert {d['engine']for d in leak['detectors']}=={'kingfisher','trufflehog'}
    if real:capture('fail'if hit else'pass',snapshot,rows,trace,True)


@pytest.mark.parametrize('mutation',['denied','deleted','version','redirect','gzip','truncated','duplicate_json','empty_body','partial','foreign_subscription','foreign_workspace','workspace_tenant','workspace_id','workspace_state','foreign_job','case_job','job_type','job_name','missing_props','null_command','null_env','wrong_env_type','empty_env_command','unsupported_job','oversize_content','oversize_wire'])
def test_native_unavailable_malformed_foreign_never_clean(monkeypatch,mutation):
    def transform(op,data,rid):
        if op=='subscription'and mutation=='foreign_subscription':data['tenantId']=WORKSPACE_ID
        if op=='workspace':
            if mutation=='foreign_workspace':data['id']=data['id'].replace(SCOPE,FOREIGN)
            if mutation=='workspace_tenant':data['properties']['tenantId']=WORKSPACE_ID
            if mutation=='workspace_id':data['properties'].pop('workspaceId')
            if mutation=='workspace_state':data['properties']['provisioningState']='Creating'
        if op=='job':
            if mutation=='partial':data['nextLink']='https://evil.invalid/'+TOKEN
            if mutation=='foreign_job':data['id']=data['id'].replace(SCOPE,FOREIGN)
            if mutation=='case_job':data['id']=data['id'].lower();data['name']=data['name'].lower()
            if mutation=='job_type':data['type']='Microsoft.Unrelated/jobs'
            if mutation=='job_name':data['name']='foreign'
            if mutation=='missing_props':data.pop('properties')
            if mutation=='null_command':data['properties']['command']=None
            if mutation=='null_env':data['properties'].pop('environmentVariables')
            if mutation=='wrong_env_type':data['properties']['environmentVariables']=[]
            if mutation=='empty_env_command':data['properties'].update(command='',environmentVariables={})
            if mutation=='unsupported_job':data['properties']['jobType']='Pipeline'
            if mutation=='oversize_content':data['properties']['command']='x'*(source.MAX_CONTENT+1)
        return data
    def fault(op,response,rid):
        if op!='job':return response
        if mutation in('denied','deleted','version','redirect'):return Response({'error':TOKEN},{'denied':403,'deleted':404,'version':400,'redirect':302}[mutation])
        if mutation=='gzip':response.headers['Content-Encoding']='gzip'
        if mutation=='truncated':response.headers['Content-Length']=str(len(response.raw)+1)
        if mutation=='duplicate_json':return Response(b'{"id":"'+TOKEN.encode()+b'","id":"duplicate"}')
        if mutation=='empty_body':return Response(b'')
        if mutation=='oversize_wire':response.headers['Content-Length']=str(source.MAX_WIRE+1)
        return response
    snapshot,rows,trace=collect(monkeypatch,transform=transform,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'},rows
    assert TOKEN not in json.dumps([snapshot,rows])and all(r.closed for r in trace.responses)
    if mutation=='denied':assert trace.responses[-1].reads==0;capture('unknown',snapshot,rows,trace,False)


@pytest.mark.parametrize('absent',['kingfisher','trufflehog'])
@pytest.mark.parametrize('hit',[False,True])
def test_one_actual_pinned_engine_absent_never_clean_but_hit_decisive(monkeypatch,absent,hit):
    snapshot,rows,_=collect(monkeypatch,TOKEN if hit else'mode=ready',real=True,absent=absent)
    assert {r['status']for r in rows}=={'FAIL'if hit else'UNKNOWN'}
    if hit:assert rows[0]['evidence']['complete']is False


@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('missing',['command','environmentVariables','reference'])
def test_supported_returned_hit_decisive_with_incomplete_literal_projection(monkeypatch,hit,missing):
    def transform(op,data,rid):
        if op=='job':
            if missing=='reference':data['properties']['environmentVariables']['REF']='${{ secrets.vault }}'
            else:data['properties'].pop(missing)
            if hit:
                if missing=='command':data['properties']['environmentVariables']['SETTING']=TOKEN
                else:data['properties']['command']='python train.py --token '+TOKEN
        return data
    snapshot,rows,_=collect(monkeypatch,transform=transform)
    assert {r['status']for r in rows}=={'FAIL'if hit else'UNKNOWN'}
    if hit:assert rows[0]['evidence']['complete']is False


@pytest.mark.parametrize('condition',['flag_false','flag_missing','named_missing','foreign_token'])
def test_default_off_and_scoped_auth_separation(monkeypatch,condition):
    options={'content_secret_scans':False}if condition=='flag_false'else{}
    snapshot,rows,trace=collect(monkeypatch,options=options,named=condition!='named_missing',token_tenant=WORKSPACE_ID if condition=='foreign_token'else TENANT,omit_flag=condition=='flag_missing')
    assert {r['status']for r in rows}=={'UNKNOWN'}
    if condition in('flag_false','flag_missing','named_missing'):assert not trace.calls and not trace.tokens


@pytest.mark.parametrize('bad',['empty','foreign','duplicate','url','query','extra','scope_missing','wrong_kind','too_many'])
def test_pure_exact_selector_rejects_before_auth(bad):
    t=target();options={source.OPTION:[t]};scopes=[SCOPE]
    if bad=='empty':options[source.OPTION]=[]
    if bad=='foreign':t['resource_id']=JOB.replace(SCOPE,FOREIGN)
    if bad=='duplicate':options[source.OPTION].append(deepcopy(t))
    if bad=='url':t['resource_id']='https://evil.invalid/'+TOKEN
    if bad=='query':t['query']=TOKEN
    if bad=='extra':t['codeUri']=TOKEN
    if bad=='scope_missing':scopes=[]
    if bad=='wrong_kind':t['resource_id']=WORKSPACE+'/codes/JobCase'
    if bad=='too_many':options[source.OPTION]=[target(JOB+str(i))for i in range(5)]
    with pytest.raises(ValueError):source.selected_targets(options,scopes)


def test_job_name_case_sensitive_selector_identity():
    assert source.identity(target())!=source.identity(target(JOB.lower()))
    assert len(source.selected_targets({source.OPTION:[target(),target(JOB.lower())]},[SCOPE]))==2


@pytest.mark.parametrize('mutation',['provider','scope','selection','credential','customer','receipt','binding','audience','host','method','capture','part','engine','duplicate','authorized'])
def test_consumer_rejects_forged_or_incoherent_proof(monkeypatch,mutation):
    snapshot,_,_=collect(monkeypatch);collection=deepcopy(own(snapshot));item=collection['items'][0]
    index={'context':{'provider':'azure','scope':SCOPE,'metadata':deepcopy(snapshot['metadata'])},'collections':{source.KIND:[collection]}}
    m=item[source.MARKER];meta=index['context']['metadata']
    if mutation=='provider':index['context']['provider']='aws'
    if mutation=='scope':index['context']['scope']=FOREIGN
    if mutation=='selection':meta[source.KIND+'_selection'][SCOPE]=[]
    if mutation=='credential':meta['credential_context_id']='foreign'
    if mutation=='customer':meta['customer_context_id']='foreign'
    if mutation=='receipt':meta[source.KIND+'_receipts'].pop()
    if mutation=='binding':meta[source.KIND+'_receipts'][-1]['identity_bound']=False
    if mutation=='audience':meta[source.KIND+'_receipts'][-1]['audience']='https://evil.invalid'
    if mutation=='host':meta[source.KIND+'_receipts'][-1]['host_class']='synapse'
    if mutation=='method':meta[source.KIND+'_receipts'][-1]['method']='POST'
    if mutation=='capture':m['capture']='foreign'
    if mutation=='part':m['parts']=[]
    if mutation=='engine':m['parts'][0]['engines'][0]['version']='future'
    if mutation=='duplicate':collection['items'].append(deepcopy(item))
    if mutation=='authorized':meta[source.KIND+'_authorized']=False
    assert consumer.evaluate(item,index)[0]=='UNKNOWN'


@pytest.mark.parametrize('budget',['MAX_CALLS','MAX_CONTENT','MAX_SECONDS'])
def test_exhausted_finite_budgets_cannot_clean(monkeypatch,budget):
    monkeypatch.setattr(source,budget,0)
    snapshot,rows,_=collect(monkeypatch)
    assert {r['status']for r in rows}=={'UNKNOWN'}


def test_cross_job_exact_value_dedup_and_final_union_scrubs_all_metadata(monkeypatch):
    def late(reader,snapshot):
        snapshot['metadata']['late_literal']=TOKEN
        reader.declaration_secret_metadata={'other_literal':TOKEN}
    snapshot,rows,trace=collect(monkeypatch,TOKEN,targets=[target(),target(JOB+'2')],late=late)
    assert len(rows)==1 and rows[0]['status']=='FAIL'
    assert len(rows[0]['evidence']['secret_leaks'])==1
    assert len(rows[0]['evidence']['secret_leaks'][0]['locations'])==2
    assert TOKEN in json.dumps([snapshot,rows])and not trace.readers[0].configuration_secret_redactions


@pytest.mark.parametrize('hit',[False,True])
def test_next_native_job_denied_is_not_clean_selected_scope(monkeypatch,hit):
    def fault(op,response,rid):return Response({'error':TOKEN},403)if op=='job'and rid.endswith('2')else response
    snapshot,rows,trace=collect(monkeypatch,TOKEN if hit else'mode=ready',targets=[target(),target(JOB+'2')],fault=fault)
    assert 'PASS'not in{r['status']for r in rows}
    if hit:assert any(r['status']=='FAIL'and r['evidence']['complete']is False for r in rows)
    assert len(trace.calls)==7


@pytest.mark.parametrize('location',['command','environment_name','job_name'])
def test_real_pinned_detection_hides_values_in_native_identity_and_literal_names(monkeypatch,location):
    targets=[target(JOB.rsplit('/',1)[0]+'/'+TOKEN)]if location=='job_name'else[target()]
    def transform(op,data,rid):
        if op=='job':
            if location=='command':data['properties']['command']='python train.py --token '+TOKEN
            if location=='environment_name':data['properties']['environmentVariables']={TOKEN:'mode=ready'}
        return data
    snapshot,rows,trace=collect(monkeypatch,TOKEN if location=='job_name'else'mode=ready',targets=targets,transform=transform,real=True)
    assert {r['status']for r in rows}=={'FAIL'}
    assert TOKEN not in json.dumps([snapshot,rows])
    if location=='job_name':assert trace.calls[-1][2]==targets[0]['resource_id']+'?api-version=2024-04-01'


@pytest.mark.parametrize('reference',['@Microsoft.KeyVault(SecretUri=https://vault.invalid/'+TOKEN+')','@microsoft.keyvault(SecretUri=https://vault.invalid/'+TOKEN+')','${{ secrets.'+TOKEN+' }}','***','[REDACTED]','<redacted>'])
def test_intended_secret_references_are_not_dereferenced_or_reported_as_leaks(monkeypatch,reference):
    snapshot,rows,trace=collect(monkeypatch,reference)
    assert {r['status']for r in rows}=={'UNKNOWN'}and len(trace.calls)==4
    assert not own(snapshot)['items'][0][source.MARKER]['leaks']
    assert TOKEN not in json.dumps([snapshot,rows])


@pytest.mark.parametrize('job_type',['AutoML','Sweep','Spark'])
def test_other_native_job_discriminators_are_explicitly_unsupported(monkeypatch,job_type):
    def transform(op,data,rid):
        if op=='job':data['properties']['jobType']=job_type
        return data
    snapshot,rows,trace=collect(monkeypatch,transform=transform)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


def test_explicit_empty_env_still_scans_nonempty_command_without_following_private_source(monkeypatch):
    def transform(op,data,rid):
        if op=='workspace':data['properties']['publicNetworkAccess']='Disabled'
        if op=='job':data['properties']['environmentVariables']={};data['properties']['codeId']='https://evil.invalid/'+TOKEN
        return data
    snapshot,rows,trace=collect(monkeypatch,transform=transform,options={'endpoint':'https://evil.invalid/'+TOKEN})
    assert {r['status']for r in rows}=={'PASS'}and len(trace.calls)==4
    assert rows[0]['evidence']['referenced_sources_inspected']is False
    assert TOKEN not in json.dumps([snapshot,rows])


def test_preexisting_union_overflow_prevents_clean_and_discards_transient_values(monkeypatch):
    def late(reader,snapshot):reader.storage_source_secret_overflow=True
    snapshot,rows,trace=collect(monkeypatch,TOKEN,late=late)
    assert {r['status']for r in rows}=={'UNKNOWN'}
    assert not trace.readers[0].configuration_secret_redactions


_NATIVE=json.loads(Path('peaso/checks/azure_ml_selected_job_secret_review_20261020_native_fixtures.json').read_text())
@pytest.mark.parametrize('capture',_NATIVE['captures'],ids=lambda c:c['expected_status'])
def test_portable_actual_native_capture_replay(capture):
    # The signed predecessor capture has three reads; current clean and positive
    # verdicts require a fourth stable job read.
    assert consumer.evaluate(capture['input']['item'],capture['input']['index'])[0]=='UNKNOWN'
    if capture['expected_status']!='UNKNOWN':assert capture['real_detectors']is True


_CURRENT=json.loads(Path('peaso/checks/azure_ml_job_variants_native_cases_20261021.json').read_text())[source.CHECK]
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_current_four_read_native_capture_replay(branch):
    assert consumer.evaluate(_CURRENT[branch],_CURRENT[branch+'_index'])[0]==branch.upper()


def test_current_databricks_account_reader_cannot_be_reused_as_notebook_export():
    from peaso.collectors import azure_databricks_native as current
    account='66666666-6666-6666-6666-666666666666'
    assert current.endpoint('https://accounts.azuredatabricks.net/api/2.0/accounts/'+account+'/workspaces').endswith('/workspaces')
    with pytest.raises(ValueError):current.endpoint('https://adb-123.7.azuredatabricks.net/api/2.0/workspace/export?path=/Users/selected')


def test_selected_blob_objects_do_not_automatically_bind_ml_job_or_arbitrary_code_uri():
    from peaso.collectors import azure_selected_storage_secret_indicators as storage
    account=SCOPE+'/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount'
    native={'service':'blob','resource_id':account,'container':'sources','object':'code/train.py','format':'text'}
    assert storage.selected_targets({storage.OPTION:[native]},[SCOPE])==[native]
    for rid in(JOB,'https://sourceaccount.blob.core.windows.net/sources/code/train.py'):
        invalid={**native,'resource_id':rid}
        with pytest.raises(ValueError):storage.selected_targets({storage.OPTION:[invalid]},[SCOPE])


def test_real_streaming_wire_limit_without_length_closes_response_and_never_scans(monkeypatch):
    def fault(op,response,rid):
        if op=='job':
            response=Response(b' '*(source.MAX_WIRE+16384));response.headers.pop('Content-Length')
        return response
    snapshot,rows,trace=collect(monkeypatch,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans
    assert trace.responses[-1].reads>1 and trace.responses[-1].closed


def test_explicit_invalid_flag_and_more_than_supported_environment_map_never_clean(monkeypatch):
    with pytest.raises(ValueError):source.selected_targets({'content_secret_scans':None,source.OPTION:[target()]},[SCOPE])
    def transform(op,data,rid):
        if op=='job':data['properties']['environmentVariables']={str(i):'mode=ready'for i in range(source.MAX_VALUES+1)}
        return data
    snapshot,rows,_=collect(monkeypatch,transform=transform)
    assert {r['status']for r in rows}=={'UNKNOWN'}


def test_shared_reader_call_budget_is_obeyed_before_following_native_reads(monkeypatch):
    snapshot,rows,trace=collect(monkeypatch,options={'max_calls':1})
    assert {r['status']for r in rows}=={'UNKNOWN'}and len(trace.calls)==1
    assert snapshot['metadata']['calls']==1 and not trace.scans


@pytest.mark.parametrize('denied',[False,True])
def test_real_http_debug_and_policy_loggers_never_emit_content_auth_or_native_errors(monkeypatch,capsys,caplog,denied):
    monkeypatch.setattr(native_http.http.client.HTTPConnection,'debuglevel',1)
    caplog.set_level(logging.DEBUG,logger='azure.core.pipeline.policies.http_logging_policy')
    caplog.set_level(logging.DEBUG,logger='azure.identity')
    def fault(op,response,rid):return Response({'error':{'message':TOKEN+' '+AUTH}},403)if denied and op=='job'else response
    snapshot,rows,trace=collect(monkeypatch,TOKEN,real=True,concrete_http=True,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'if denied else'FAIL'}
    output=capsys.readouterr();emitted=output.out+output.err+caplog.text
    assert len(trace.calls)==(3 if denied else 4)
    assert TOKEN not in emitted and AUTH not in emitted and 'Bearer 'not in emitted
    assert TOKEN not in json.dumps([snapshot,rows])and all(r.closed for r in trace.responses)
