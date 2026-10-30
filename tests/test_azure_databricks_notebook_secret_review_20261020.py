"""Independent native HTTP through real AzureTransport and actual public production collector hooks."""
from copy import deepcopy
import base64
import hashlib
import inspect
import io
import json
import logging
import os
from pathlib import Path
import socket
import time
from types import SimpleNamespace
from urllib.parse import parse_qs,urlsplit
import pytest
from peaso import checks,engine,secret_scanning as scanning
from peaso.collectors import azure
from peaso.collectors import azure_databricks_notebook_secret_indicators as source
from peaso.collectors import azure_ml_selected_job_secret_indicators as existing
from peaso.checks import azure_databricks_notebook_secret_review_20261020 as consumer

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
FOREIGN='/subscriptions/33333333-3333-3333-3333-333333333333'
TENANT='22222222-2222-2222-2222-222222222222'
CLIENT='77777777-7777-7777-7777-777777777777'
OBJECT='88888888-8888-8888-8888-888888888888'
WORKSPACE=SCOPE+'/resourceGroups/review/providers/Microsoft.Databricks/workspaces/selected'
HOST='adb-1234567890123456.7.azuredatabricks.net'
NOTEBOOK='/Shared/Selected notebook'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH='offline-notebook-client-secret'
PRODUCTION_TYPES=tuple(azure.TYPES)


def target(path=NOTEBOOK):return{'workspace_resource_id':WORKSPACE,'path':path}

def jwt(audience,tenant,oid=OBJECT,client=CLIENT,expiry=None):
    def b64(data):return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
    return b64({'alg':'none'})+'.'+b64({'aud':audience,'tid':tenant,'oid':oid,'appid':client,'exp':expiry if expiry is not None else int(time.time())+3600})+'.offline'


class Response:
    def __init__(self,data,status=200,headers=None):
        self.raw=json.dumps(data).encode()if isinstance(data,dict)else data
        self.status=status;self.stream=io.BytesIO(self.raw);self.closed=False;self.reads=0
        self.headers={'Content-Type':'application/json','Content-Length':str(len(self.raw)),**(headers or{})}
    def getheader(self,k):return self.headers.get(k)
    def read(self,n):assert 0<n<=16384;self.reads+=1;return self.stream.read(n)
    def close(self):self.closed=True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**kw):pytest.fail('Live network/DNS/default credential or cached content read forbidden')
    for n in('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure.AzureTransport,'request',blocked)
    registered,=[c for c in engine._registry()if c.id==source.CHECK]
    assert inspect.unwrap(registered.evaluate)is consumer.evaluate
    scanning._RESULTS.clear();yield;scanning._RESULTS.clear()


def collect(monkeypatch,literal='mode=ready',*,real=False,transform=None,fault=None,options=None,targets=None,named=True,omit_flag=False,absent=None,token_fault=None,late=None,concrete_http=False):
    targets=targets or[target()];trace=SimpleNamespace(calls=[],responses=[],connections=[],scans=[],tokens=[],readers=[]);seen={}
    if not real:
        def scan(raw,path,timeout):trace.scans.append((len(raw),path));return[(TOKEN,'github-pat',1)]if TOKEN.encode()in raw else[]
        monkeypatch.setattr(scanning,'_scan_kingfisher',scan);monkeypatch.setattr(scanning,'_scan_trufflehog',scan)
    if absent:
        def unavailable(*a,**kw):raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning,'_scan_'+absent,unavailable)
    class Credential:
        def get_token(self,scope):
            assert scope in('https://management.azure.com/.default','2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default');trace.tokens.append(scope)
            aud=scope.removesuffix('/.default');tid=TENANT;oid=OBJECT;client=CLIENT;expiry=None
            if aud==source.DATABRICKS:
                if token_fault=='unavailable':raise RuntimeError(TOKEN)
                if token_fault=='tenant':tid=OBJECT
                if token_fault=='principal':oid=TENANT
                if token_fault=='client':client=TENANT
                if token_fault=='audience':aud='https://evil.invalid'
                if token_fault=='expired':expiry=int(time.time())-1
            return SimpleNamespace(token=jwt(aud,tid,oid,client,expiry),expires_on=int(time.time())+3600)
        def close(self):pass
    monkeypatch.setattr(azure,'credential_for',lambda auth:Credential())
    class Connection:
        sock=None
        def __init__(self,host,timeout):assert host in('management.azure.com',HOST)and 0<timeout<=10;self.host=host;self.closed=False;trace.connections.append(self)
        def set_debuglevel(self,n):assert n==0
        def request(self,method,path,body=None,headers=None):
            assert method=='GET'and body is None and set(headers)=={'Authorization','Accept','Accept-Encoding','Content-Length'}
            assert headers['Authorization'].startswith('Bearer ')and headers['Accept-Encoding']=='identity'and headers['Content-Length']=='0'
            op=notebook=None
            if self.host=='management.azure.com'and path==SCOPE+'?api-version=2022-12-01':
                op='subscription';data={'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':TENANT,'state':'Enabled'}
            elif self.host=='management.azure.com'and path==WORKSPACE+'?api-version=2026-01-01':
                op='workspace';data={'id':WORKSPACE,'name':'selected','type':'Microsoft.Databricks/workspaces','properties':{'workspaceId':'1234567890123456','workspaceUrl':HOST,'provisioningState':'Succeeded','publicNetworkAccess':'Disabled'}}
            elif self.host==HOST:
                parsed=urlsplit(path);query=parse_qs(parsed.query,strict_parsing=True);notebook=query['path'][0]
                assert notebook in[t['path']for t in targets]
                if parsed.path=='/api/2.0/workspace/get-status':
                    assert set(query)=={'path'}
                    count=seen.get(notebook,0);seen[notebook]=count+1;op='status_before'if count==0 else'status_after'
                    data={'path':notebook,'object_type':'NOTEBOOK','object_id':789 if notebook==targets[0]['path']else 790,'language':'PYTHON'}
                elif parsed.path=='/api/2.0/workspace/export':
                    assert query=={'path':[notebook],'format':['SOURCE'],'direct_download':['false']}
                    op='export';data={'content':base64.b64encode(('# Databricks notebook source\nsetting = "'+literal+'"\n').encode()).decode(),'file_type':'py'}
            assert op is not None,(method,self.host,path)
            trace.calls.append((method,self.host,path,op))
            if transform:data=transform(op,deepcopy(data),notebook)
            response=Response(data)
            if fault:response=fault(op,response,notebook)
            self.response=response;trace.responses.append(response)
        def getresponse(self):return self.response
        def close(self):self.closed=True
    if concrete_http:
        real_https=source.http.client.HTTPSConnection
        class MemorySocket:
            def __init__(self,response):
                head=('HTTP/1.1 '+str(response.status)+' '+('OK'if response.status==200 else'Forbidden')+'\r\n'+''.join(k+': '+v+'\r\n'for k,v in response.headers.items())+'\r\n').encode()
                self.stream=io.BytesIO(head+response.raw)
            def sendall(self,data):assert isinstance(data,bytes)
            def makefile(self,mode):assert mode=='rb';return self.stream
            def settimeout(self,n):assert 0<n<=10
            def close(self):pass
        class NativeHTTPS(real_https):
            def __init__(self,host,timeout):source.http.client.HTTPConnection.__init__(self,host,timeout=timeout)
            def connect(self):self.sock=MemorySocket(self.driver.response)
            def request(self,method,path,body=None,headers=None,**kw):
                self.driver=Connection(self.host,self.timeout);self.driver.set_debuglevel(self.debuglevel);self.driver.request(method,path,body,headers)
                return super().request(method,path,body,headers,**kw)
            def close(self):
                if hasattr(self,'driver'):self.driver.response.close();self.driver.close()
                super().close()
        selected=NativeHTTPS
    else:selected=Connection
    monkeypatch.setattr(source.http.client,'HTTPSConnection',selected)
    opts={'content_secret_scans':True,source.OPTION:targets,'retries':0};opts.update(options or{})
    if omit_flag:opts.pop('content_secret_scans')
    req={'connector':{'provider':'azure','scopes':[SCOPE],'auth':{'method':'client-secret','tenant_id':TENANT,'client_id':CLIENT,'client_secret':AUTH},'options':opts},'checks':[source.CHECK]if named else[next(c.id for c in engine._registry()if c.provider=='azure'and c.kind=='nsg')]}
    if not named:req['connector']['options']['inventories']=[source.KIND]
    old=azure._Reader.__init__
    def init(reader,*a,**kw):old(reader,*a,**kw);trace.readers.append(reader)
    monkeypatch.setattr(azure._Reader,'__init__',init)
    if late:
        reviewed_final=source.final_snapshot
        def final(reader,snapshot):late(reader,snapshot);return reviewed_final(reader,snapshot)
        monkeypatch.setattr(azure.azure_databricks_notebook_secret_indicators,'final_snapshot',final)
    snapshot=engine.collect_snapshot(req);rows=engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']
    return snapshot,rows,trace


def own(snapshot):return next(c for c in snapshot['collections']if c['type']==source.KIND)

def capture(branch,snapshot,rows,trace,real):
    if os.environ.get('AZURE_NOTEBOOK_CAPTURE_DIR'):
        path=Path(os.environ['AZURE_NOTEBOOK_CAPTURE_DIR']);path.mkdir(parents=True,exist_ok=True)
        (path/(branch+'.json')).write_text(json.dumps({'expected_status':branch.upper(),'real_detectors':real,'snapshot':snapshot,'findings':rows,'http':trace.calls},indent=2,sort_keys=True))


@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('real',[False,True])
def test_native_five_gets_exact_source_dual_engines_no_onboarding(monkeypatch,hit,real):
    snapshot,rows,trace=collect(monkeypatch,TOKEN if hit else'mode=ready',real=real)
    assert {r['status']for r in rows}=={'FAIL'if hit else'PASS'},rows
    assert len(trace.calls)==5 and all(r.closed for r in trace.responses)and all(c.closed for c in trace.connections)
    assert trace.tokens==['https://management.azure.com/.default',source.DATABRICKS+'/.default']
    assert TOKEN not in json.dumps([snapshot,rows])and AUTH not in json.dumps(snapshot)
    c=own(snapshot)
    direct=consumer.evaluate(c['items'][0],{'context':{'provider':'azure','scope':SCOPE,'metadata':snapshot['metadata']},'collections':{source.KIND:[c]}})
    assert direct[1]['immutable_revision_proven']is False
    if hit:
        leak,=own(snapshot)['items'][0][source.MARKER]['leaks'];assert {d['engine']for d in leak['detectors']}=={'kingfisher','trufflehog'}
    if real:capture('fail'if hit else'pass',snapshot,rows,trace,True)


@pytest.mark.parametrize('mutation',['denied','deleted','version','redirect','error200','partial','foreign_subscription','foreign_workspace','workspace_type','workspace_name','host','host_identity','host_url','workspace_id','workspace_state','folder','repo','file','missing_id','wrong_path','unsupported_language','object_changed','language_changed','bad_base64','noncanonical_base64','empty_source','binary_source','invalid_utf8','too_big_source','wrong_file_type','extra_fields','missing_content','gzip','truncated','duplicate_json','oversize_wire','empty_body'])
def test_native_missing_malformed_denied_foreign_never_clean(monkeypatch,mutation):
    def transform(op,data,path):
        if op=='subscription'and mutation=='foreign_subscription':data['tenantId']=OBJECT
        if op=='workspace':
            if mutation=='foreign_workspace':data['id']=data['id'].replace(SCOPE,FOREIGN)
            if mutation=='workspace_type':data['type']='Microsoft.Unrelated/workspaces'
            if mutation=='workspace_name':data['name']='other'
            if mutation=='host':data['properties']['workspaceUrl']='evil.invalid'
            if mutation=='host_identity':data['properties']['workspaceUrl']='adb-999.7.azuredatabricks.net'
            if mutation=='host_url':data['properties']['workspaceUrl']='https://'+HOST
            if mutation=='workspace_id':data['properties'].pop('workspaceId')
            if mutation=='workspace_state':data['properties']['provisioningState']='Creating'
        if op=='status_before':
            if mutation in('folder','repo','file'):data['object_type']={'folder':'DIRECTORY','repo':'REPO','file':'FILE'}[mutation]
            if mutation=='missing_id':data.pop('object_id')
            if mutation=='wrong_path':data['path']+='/other'
            if mutation=='unsupported_language':data['language']='BINARY'
        if op=='status_after':
            if mutation=='object_changed':data['object_id']=999
            if mutation=='language_changed':data['language']='SQL'
        if op=='export':
            if mutation=='error200':data['error_code']='PERMISSION_DENIED';data['message']=TOKEN
            if mutation=='partial':data['next_page_token']=TOKEN
            if mutation=='bad_base64':data['content']='!'+TOKEN
            if mutation=='noncanonical_base64':data['content']='Zh=='
            if mutation=='empty_source':data['content']=''
            if mutation=='binary_source':data['content']=base64.b64encode(b'a\0b').decode()
            if mutation=='invalid_utf8':data['content']=base64.b64encode(b'\xff').decode()
            if mutation=='too_big_source':data['content']=base64.b64encode(b'a'*(source.MAX_CONTENT+1)).decode()
            if mutation=='wrong_file_type':data['file_type']='html'
            if mutation=='extra_fields':data['outputs']=[TOKEN]
            if mutation=='missing_content':data.pop('content')
        return data
    def fault(op,response,path):
        if op!='export':return response
        if mutation in('denied','deleted','version','redirect'):return Response({'error':TOKEN},{'denied':403,'deleted':404,'version':400,'redirect':302}[mutation])
        if mutation=='gzip':response.headers['Content-Encoding']='gzip'
        if mutation=='truncated':response.headers['Content-Length']=str(len(response.raw)+1)
        if mutation=='duplicate_json':return Response(b'{"content":"'+TOKEN.encode()+b'","content":"bad"}')
        if mutation=='oversize_wire':response.headers['Content-Length']=str(source.MAX_WIRE+1)
        if mutation=='empty_body':return Response(b'')
        return response
    snapshot,rows,trace=collect(monkeypatch,transform=transform,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'},rows
    assert not trace.scans and TOKEN not in json.dumps([snapshot,rows])and all(r.closed for r in trace.responses)
    if mutation=='denied':assert trace.responses[-1].reads==0;capture('unknown',snapshot,rows,trace,False)


@pytest.mark.parametrize('bad',['unavailable','tenant','principal','client','audience','expired'])
def test_fixed_sdk_audience_same_principal_and_tenant_no_fallback(monkeypatch,bad):
    snapshot,rows,trace=collect(monkeypatch,token_fault=bad)
    assert {r['status']for r in rows}=={'UNKNOWN'}and len(trace.calls)==2 and not trace.scans
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('engine_absent',['kingfisher','trufflehog'])
@pytest.mark.parametrize('hit',[False,True])
def test_one_real_engine_absent_bound_hit_decisive(monkeypatch,engine_absent,hit):
    snapshot,rows,_=collect(monkeypatch,TOKEN if hit else'mode=ready',real=True,absent=engine_absent)
    assert {r['status']for r in rows}=={'FAIL'if hit else'UNKNOWN'}
    if hit:assert rows[0]['evidence']['complete']is False


@pytest.mark.parametrize('bad',['empty','duplicate','foreign','url','query','token','audience','relative','traversal','encoded','repos','volumes','secret_scope','count','flag'])
def test_exact_selector_only_native_workspace_and_notebook_path(bad):
    t=target();opts={source.OPTION:[t]}
    if bad=='empty':opts[source.OPTION]=[]
    if bad=='duplicate':opts[source.OPTION].append(deepcopy(t))
    if bad=='foreign':t['workspace_resource_id']=WORKSPACE.replace(SCOPE,FOREIGN)
    if bad=='url':t['workspace_resource_id']='https://'+HOST
    if bad in('query','token','audience'):t[bad]=TOKEN
    if bad=='relative':t['path']='Shared/note'
    if bad=='traversal':t['path']='/Shared/../note'
    if bad=='encoded':t['path']='/Shared/%2fother'
    if bad=='repos':t['path']='/Repos/selected'
    if bad=='volumes':t['path']='/Volumes/selected'
    if bad=='secret_scope':t['workspace_resource_id']+='/secretScopes/intended'
    if bad=='count':opts[source.OPTION]=[target(NOTEBOOK+str(i))for i in range(5)]
    if bad=='flag':opts['content_secret_scans']=None
    with pytest.raises(ValueError):source.selected_targets(opts,[SCOPE])


@pytest.mark.parametrize('condition',['flag_false','flag_missing','named_missing'])
def test_optional_default_off_before_any_token_read(monkeypatch,condition):
    snapshot,rows,trace=collect(monkeypatch,options={'content_secret_scans':False}if condition=='flag_false'else{},omit_flag=condition=='flag_missing',named=condition!='named_missing')
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.calls and not trace.tokens


@pytest.mark.parametrize('budget',['MAX_CALLS','MAX_WIRE','MAX_TOTAL','MAX_CONTENT','MAX_SECONDS'])
def test_finite_bound_exhaustion_is_unresolved(monkeypatch,budget):
    monkeypatch.setattr(source,budget,0)
    snapshot,rows,_=collect(monkeypatch)
    assert {r['status']for r in rows}=={'UNKNOWN'}


def test_shared_reader_call_budget_prevents_further_reads(monkeypatch):
    snapshot,rows,trace=collect(monkeypatch,options={'max_calls':2})
    assert {r['status']for r in rows}=={'UNKNOWN'}and len(trace.calls)==2 and not trace.scans
    assert snapshot['metadata']['calls']==2


@pytest.mark.parametrize('mutation',['provider','scope','selection','credential','customer','receipt','principal','binding','audience','host','method','capture','part','engine','duplicate','authorized'])
def test_consumer_requires_coherent_bound_native_receipts(monkeypatch,mutation):
    snapshot,_,_=collect(monkeypatch);collection=deepcopy(own(snapshot));item=collection['items'][0]
    index={'context':{'provider':'azure','scope':SCOPE,'metadata':deepcopy(snapshot['metadata'])},'collections':{source.KIND:[collection]}}
    m=item[source.MARKER];meta=index['context']['metadata']
    if mutation=='provider':index['context']['provider']='aws'
    if mutation=='scope':index['context']['scope']=FOREIGN
    if mutation=='selection':meta[source.KIND+'_selection'][SCOPE]=[]
    if mutation=='credential':meta['credential_context_id']='foreign'
    if mutation=='customer':meta['customer_context_id']='foreign'
    if mutation=='receipt':meta[source.KIND+'_receipts'].pop()
    if mutation=='principal':meta[source.KIND+'_receipts'][-1]['principal_binding']='0'*64
    if mutation=='binding':meta[source.KIND+'_receipts'][-1]['object_binding']='0'*64
    if mutation=='audience':meta[source.KIND+'_receipts'][-1]['audience']='https://evil.invalid'
    if mutation=='host':meta[source.KIND+'_receipts'][-1]['host_class']='arm'
    if mutation=='method':meta[source.KIND+'_receipts'][-1]['method']='POST'
    if mutation=='capture':m['capture']='other'
    if mutation=='part':m['parts']=[]
    if mutation=='engine':m['parts'][0]['engines'][0]['version']='future'
    if mutation=='duplicate':collection['items'].append(deepcopy(item))
    if mutation=='authorized':meta[source.KIND+'_authorized']=False
    assert consumer.evaluate(item,index)[0]=='UNKNOWN'


@pytest.mark.parametrize('hit',[False,True])
def test_second_selected_notebook_denied_no_clean_scope(monkeypatch,hit):
    def fault(op,response,path):return Response({'error':TOKEN},403)if op=='export'and path.endswith('2')else response
    snapshot,rows,trace=collect(monkeypatch,TOKEN if hit else'mode=ready',targets=[target(),target(NOTEBOOK+'2')],fault=fault)
    assert 'PASS'not in{r['status']for r in rows}
    if hit:assert any(r['status']=='FAIL'and r['evidence']['complete']is False for r in rows)


def test_same_value_cross_notebooks_dedup_and_late_union_redaction(monkeypatch):
    def late(reader,snapshot):
        snapshot['metadata']['late']=TOKEN;reader.ml_command_job_secret_metadata={'old_ml':TOKEN};reader.log_sample_secret_metadata={'old_log':TOKEN};reader.declaration_secret_metadata={'old_decl':TOKEN}
    snapshot,rows,trace=collect(monkeypatch,TOKEN,targets=[target(),target(NOTEBOOK+'2')],late=late)
    assert len(rows)==1 and rows[0]['status']=='FAIL'and len(rows[0]['evidence']['secret_leaks'][0]['locations'])==2
    assert TOKEN in json.dumps([snapshot,rows])and not trace.readers[0].configuration_secret_redactions


def test_detected_value_in_selected_path_keeps_exact_native_route_but_opaque_export(monkeypatch):
    selected='/Shared/'+TOKEN
    snapshot,rows,trace=collect(monkeypatch,TOKEN,targets=[target(selected)],real=True)
    assert {r['status']for r in rows}=={'FAIL'}and TOKEN not in json.dumps([snapshot,rows])
    assert any(TOKEN in path for method,host,path,op in trace.calls if op=='export')


@pytest.mark.parametrize('denied',[False,True])
def test_real_http_framing_debug_and_policy_logging_privacy(monkeypatch,capsys,caplog,denied):
    monkeypatch.setattr(source.http.client.HTTPConnection,'debuglevel',1)
    caplog.set_level(logging.DEBUG,logger='azure.core.pipeline.policies.http_logging_policy');caplog.set_level(logging.DEBUG,logger='azure.identity')
    def fault(op,response,path):return Response({'error':TOKEN+' '+AUTH},403)if denied and op=='export'else response
    snapshot,rows,trace=collect(monkeypatch,TOKEN,real=True,concrete_http=True,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'if denied else'FAIL'}and len(trace.calls)==(4 if denied else 5)
    captured=capsys.readouterr();emitted=captured.out+captured.err+caplog.text
    assert TOKEN not in emitted and AUTH not in emitted and 'Bearer 'not in emitted
    assert all(r.closed for r in trace.responses)


def test_exact_registered_identity_no_framework_edges_and_path_case_is_preserved():
    from peaso.checks import azure_databricks_notebook_secrets_admission_20261020 as admission
    from peaso.checks.fixtures import CASES
    # The original admission retains its historical source pins; package
    # initialization installs the reviewed current source through RawV2.
    with pytest.raises(RuntimeError, match='reviewed source changed'):
        admission.reviewed_inputs()
    registered,=[c for c in checks.CHECKS if c.id==source.CHECK]
    assert source.KIND in PRODUCTION_TYPES and inspect.unwrap(registered.evaluate)is consumer.evaluate
    assert source.CHECK in CASES
    assert source.identity(target())!=source.identity(target(NOTEBOOK.lower()))
    assert consumer.DECLARATION['requirements']==[]and consumer.DECLARATION['ui_group']=='Secrets'



@pytest.mark.parametrize('language',['SQL','SCALA','R'])
def test_other_documented_notebook_source_languages(monkeypatch,language):
    def transform(op,data,path):
        if op.startswith('status_'):data['language']=language
        if op=='export':data['file_type']={'SQL':'sql','SCALA':'scala','R':'r'}[language]
        return data
    snapshot,rows,_=collect(monkeypatch,transform=transform)
    assert {r['status']for r in rows}=={'PASS'}


def test_optional_file_type_and_native_resource_id_are_coherent(monkeypatch):
    def transform(op,data,path):
        if op.startswith('status_'):data['resource_id']='notebooks/789'
        if op=='export':data.pop('file_type')
        return data
    snapshot,rows,_=collect(monkeypatch,transform=transform)
    assert {r['status']for r in rows}=={'PASS'}


@pytest.mark.parametrize('bad',['changed_resource_id','repo_metadata','file_timestamp'])
def test_unknown_notebook_association_or_file_only_fields_unresolved(monkeypatch,bad):
    def transform(op,data,path):
        if op.startswith('status_'):
            if bad=='changed_resource_id':data['resource_id']='notebooks/789'if op=='status_before'else'notebooks/999'
            if bad=='repo_metadata':data['directory_info']={'is_git_folder':True}
            if bad=='file_timestamp':data['modified_at']=12345678
        return data
    snapshot,rows,trace=collect(monkeypatch,transform=transform)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


def test_streamed_body_without_length_still_bounded(monkeypatch):
    def fault(op,response,path):
        if op=='export':response=Response(b' '*(source.MAX_WIRE+16384));response.headers.pop('Content-Length')
        return response
    snapshot,rows,trace=collect(monkeypatch,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans and trace.responses[-1].closed
    assert trace.responses[-1].reads>1


def test_redaction_union_overflow_withholds_native_result(monkeypatch):
    def late(reader,snapshot):reader.storage_source_secret_overflow=True
    snapshot,rows,trace=collect(monkeypatch,TOKEN,late=late)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.readers[0].configuration_secret_redactions


_NATIVE=json.loads(Path('peaso/checks/azure_databricks_notebook_secret_review_20261020_native_fixtures.json').read_text())
@pytest.mark.parametrize('capture',_NATIVE['captures'],ids=lambda c:c['expected_status'])
def test_portable_actual_native_capture_replay(capture):
    result=consumer.evaluate(capture['input']['item'],capture['input']['index'])
    assert result[0]==capture['expected_status']and result[1]['immutable_revision_proven']is False
    if capture['expected_status']!='UNKNOWN':assert capture['real_detectors']is True


def test_proposal_pins_unwrapped_predicate_helper_and_reachable_source_bytes():
    # Later reviewed edits are admitted through the exact inverse-delta epoch:
    # every current source must reconstruct the proposal's reviewed bytes.
    import ast
    from peaso import rawv2_private_source_successor_20261021 as epoch
    proposal=json.loads(Path('peaso/checks/azure_databricks_notebook_secret_review_20261020_proposal.json').read_text())
    assert proposal['registration']=='unregistered_proposal_only'
    historical={}
    for path,digest in proposal['sources'].items():
        historical[path]=epoch.source_bytes(path,Path(path).read_bytes(),digest,Path.cwd())
        assert hashlib.sha256(historical[path]).hexdigest()==digest,path
    fixture=proposal['fixture'];assert hashlib.sha256(Path(fixture['path']).read_bytes()).hexdigest()==fixture['sha256']
    raw=historical['peaso/checks/azure_databricks_notebook_secret_review_20261020.py']
    definitions={node.name:node for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef)}
    for name,key in [('evaluate','predicate_sha256'),('_evaluate','reachable_helper_sha256')]:
        node=definitions[name]
        body=b''.join(raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
        assert hashlib.sha256(body).hexdigest()==proposal['check'][key]
