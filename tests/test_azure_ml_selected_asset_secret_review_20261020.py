"""Independent native HTTP -> actual Azure transport/scheduler -> registered production controls.

Original proposed bridge bytes are preserved in a separate historical gzip artifact.
"""
import base64
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
from peaso import checks, engine, secret_scanning as scanning
from peaso.collectors import azure
from peaso.collectors import azure_ml_selected_asset_secret_indicators as source
from peaso.checks import azure_ml_selected_asset_secret_review_20261020 as consumer
from peaso import checks,collectors,engine,secret_scanning as scanning

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
FOREIGN='/subscriptions/33333333-3333-3333-3333-333333333333'
TENANT='22222222-2222-2222-2222-222222222222'
PRINCIPAL='44444444-4444-4444-4444-444444444444'
WORKSPACE_ID='55555555-5555-5555-5555-555555555555'
WORKSPACE=SCOPE+'/resourceGroups/review/providers/Microsoft.MachineLearningServices/workspaces/selected'
ACCOUNT=SCOPE+'/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH='offline-ml-asset-client-secret'
VERSION='2026-10-19T12:00:00.0000000Z'


def target(profile,service='blob',versioned=False):
    result={'resource_id':WORKSPACE+'/'+source.PROFILES[profile]['asset']+'/NameCase/versions/VersionCase'}
    if profile=='code':
        result.update(datastore='source_store',storage={'service':service,'resource_id':ACCOUNT,'container'if service=='blob'else'share':'sources','object':'code/main.py','format':'text'})
        if versioned:result['storage']['version']=VERSION
    return result


def jwt(audience,**claims):
    data={'aud':audience,'tid':TENANT,'oid':PRINCIPAL,'exp':time.time()+3600,**claims}
    return 'eyJhbGciOiJub25lIn0.'+base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')+'.b2ZmbGluZQ'


class Response:
    def __init__(self,payload,status=200,headers=None,head=False):
        self.raw=json.dumps(payload).encode()if isinstance(payload,dict)else payload
        self.status=status;self.stream=io.BytesIO(b''if head else self.raw);self.closed=False
        self.headers={'Content-Type':'application/json','Content-Length':str(len(self.raw)),'x-ms-request-id':'11111111-1111-4111-8111-111111111111',**(headers or{})}
    def getheader(self,name):return self.headers.get(name)
    def read(self,size):assert 0<size<=16384;return self.stream.read(size)
    def close(self):self.closed=True


@pytest.fixture(autouse=True)
def production_offline(monkeypatch):
    def blocked(*a,**kw):pytest.fail('No live socket/DNS/auth or generic cached content transport')
    for n in('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in('getaddrinfo','gethostbyname','gethostbyname_ex','create_connection'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure.AzureTransport,'request',blocked)
    before=tuple(checks.CHECKS)
    for name,p in source.PROFILES.items():
        registered,=[c for c in engine._registry()if c.id==p['check']]
        assert inspect.unwrap(registered.evaluate)is getattr(consumer,name)
    scanning._RESULTS.clear();yield;scanning._RESULTS.clear();assert tuple(checks.CHECKS)==before


def collect(monkeypatch,profile='environment',literal='mode=ready',*,real=False,targets=None,transform=None,fault=None,claims=None,absent=None,flag=True,named=True,late=None,concrete_http=False,uri='short',mixed=False):
    targets=targets or[target(profile)];p=source.PROFILES[profile]
    if mixed:targets=targets+[target('code')]
    trace=SimpleNamespace(calls=[],responses=[],connections=[],tokens=[],readers=[],scans=[])
    if not real:
        def detector(raw,path,timeout):trace.scans.append((len(raw),path));return[(TOKEN,'github-pat',1)]if TOKEN.encode()in raw else[]
        monkeypatch.setattr(scanning,'_scan_kingfisher',detector);monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    if absent:
        def missing(*a,**kw):raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning,'_scan_'+absent,missing)
    class Credential:
        def get_token(self,scope):
            assert scope in(source.ARM+'/.default',source.storage.STORAGE+'/.default');trace.tokens.append(scope)
            return SimpleNamespace(token=jwt(scope.removesuffix('/.default'),**(claims(scope)if claims else{})),expires_on=int(time.time())+(30 if claims else 3600))
        def close(self):pass
    monkeypatch.setattr(azure,'credential_for',lambda auth:Credential())
    class Connection:
        sock=None
        def __init__(self,host,timeout):
            assert host in('management.azure.com','sourceaccount.blob.core.windows.net','sourceaccount.file.core.windows.net')and 0<timeout<=10
            self.host=host;self.closed=False;trace.connections.append(self)
        def set_debuglevel(self,n):assert n==0
        def request(self,method,path,body=None,headers=None):
            assert method in('GET','HEAD')and body is None and headers['Accept-Encoding']=='identity'and headers['Authorization'].startswith('Bearer ey')
            selected=targets[0];op=None;data=None;head=False;extra={}
            if self.host=='management.azure.com':
                assert method=='GET'
                if path==SCOPE+'?api-version=2022-12-01':op='subscription';data={'id':SCOPE,'subscriptionId':SCOPE.split('/')[-1],'tenantId':TENANT,'state':'Enabled','displayName':TOKEN}
                elif path==WORKSPACE+'?api-version='+source.WORKSPACE_API:
                    op='workspace_before'if not any(c[3]=='workspace_before'for c in trace.calls)or sum(c[3].startswith('workspace')for c in trace.calls)%2==0 else'workspace_after'
                    data={'id':WORKSPACE,'name':'selected','type':source.SERVICE+'/workspaces','properties':{'tenantId':TENANT,'workspaceId':WORKSPACE_ID,'provisioningState':'Succeeded','storageAccount':TOKEN}}
                else:
                    for t in targets:
                        if path==t['resource_id']+'?api-version='+source.API:
                            selected=t;op='asset_after'if sum(c[2]==path for c in trace.calls)%2 else'asset_before'
                            tp='code'if 'storage'in t else'environment'
                            if tp=='environment':props={'condaFile':'name: selected\ndependencies:\n- python=3.11\n- pip:\n  - '+literal+'\n','image':'https://evil.invalid/'+TOKEN,'build':{'contextUri':'https://evil.invalid/'+TOKEN}}
                            else:
                                st=t['storage'];base='code/'
                                code_uri={'short':'azureml://datastores/source_store/paths/'+base,'long':'azureml://subscriptions/'+SCOPE.split('/')[-1]+'/resourcegroups/review/workspaces/selected/datastores/source_store/paths/'+base,'https':'https://sourceaccount.'+st['service']+'.core.windows.net/sources/'+base}[uri]
                                props={'codeUri':code_uri}
                            data={'id':t['resource_id'],'name':t['resource_id'].split('/')[-1],'type':source.SERVICE+'/workspaces/'+source.PROFILES[tp]['asset']+'/versions','properties':props};break
                        elif 'storage'in t and path==WORKSPACE+'/datastores/'+t['datastore']+'?api-version='+source.API:
                            selected=t;n=sum(c[2]==path for c in trace.calls)%3;op=('datastore_before','datastore_after','datastore_final')[n];st=t['storage'];data={'id':WORKSPACE+'/datastores/'+t['datastore'],'name':t['datastore'],'type':source.SERVICE+'/workspaces/datastores','properties':{'datastoreType':'AzureBlob'if st['service']=='blob'else'AzureFile','accountName':'sourceaccount','containerName'if st['service']=='blob'else'fileShareName':'sources','endpoint':'core.windows.net','protocol':'https','subscriptionId':SCOPE.split('/')[-1],'resourceGroup':'review','credentials':{'credentialsType':'AccountKey','secrets':{'secretsType':'AccountKey'}}}};break
                        elif 'storage'in t and path==ACCOUNT+'?api-version='+source.storage.ARM_VERSION:
                            selected=t;op='account';data={'id':ACCOUNT,'name':'sourceaccount','type':'Microsoft.Storage/storageAccounts','properties':{'provisioningState':'Succeeded','primaryEndpoints':{'blob':'https://sourceaccount.blob.core.windows.net/','file':'https://sourceaccount.file.core.windows.net/'}}};break
            else:
                for t in targets:
                    if 'storage'not in t:continue
                    host,route=source.storage.data_route(t['storage'])
                    if self.host==host and path==route:
                        selected=t;st=t['storage'];op='content'if method=='GET'else'properties_before'if sum(c[0]=='HEAD'and c[2]==path for c in trace.calls)%2==0 else'properties_after'
                        data=('value='+literal).encode();head=method=='HEAD';extra={'Content-Type':'application/octet-stream','ETag':'"0x123ABC"','x-ms-version':source.storage.DATA_VERSION}
                        if st['service']=='blob':
                            extra['x-ms-blob-type']='BlockBlob'
                            if 'version'in st:extra['x-ms-version-id']=st['version']
                            if method=='GET':assert headers['If-Match']=='"0x123ABC"'
                        else:
                            assert headers['x-ms-file-request-intent']=='backup';extra.update({'x-ms-type':'File','x-ms-file-file-id':'12345678'})
                        assert headers['x-ms-version']==source.storage.DATA_VERSION;break
            assert op is not None,(method,self.host,path)
            trace.calls.append((method,self.host,path,op))
            if transform:data=transform(op,deepcopy(data),selected)
            response=Response(data,headers=extra,head=head)
            if fault:response=fault(op,response,selected)
            self.response=response;trace.responses.append(response)
        def getresponse(self):return self.response
        def close(self):self.closed=True
    original_https=source.http.client.HTTPSConnection
    if concrete_http:
        class MemorySocket:
            def __init__(self,response):self.stream=io.BytesIO(('HTTP/1.1 '+str(response.status)+' OK\r\n'+''.join(k+': '+v+'\r\n'for k,v in response.headers.items())+'\r\n').encode()+(b''if response.stream.getbuffer().nbytes==0 else response.raw))
            def sendall(self,data):assert isinstance(data,bytes)
            def makefile(self,mode):assert mode=='rb';return self.stream
            def settimeout(self,n):assert 0<n<=10
            def close(self):pass
        class NativeHTTPS(original_https):
            def __init__(self,host,timeout):source.http.client.HTTPConnection.__init__(self,host,timeout=timeout)
            def connect(self):self.sock=MemorySocket(self.driver.response)
            def request(self,method,path,body=None,headers=None,**kw):
                self.driver=Connection(self.host,self.timeout);self.driver.set_debuglevel(self.debuglevel);self.driver.request(method,path,body,headers);return super().request(method,path,body,headers,**kw)
            def close(self):
                if hasattr(self,'driver'):self.driver.response.close();self.driver.close()
                super().close()
        connection=NativeHTTPS
    else:connection=Connection
    monkeypatch.setattr(source.http.client,'HTTPSConnection',connection)
    old_init=azure._Reader.__init__
    def init(reader,*a,**kw):old_init(reader,*a,**kw);trace.readers.append(reader)
    monkeypatch.setattr(azure._Reader,'__init__',init)
    if late:
        final=source.final_snapshot
        def finalize(reader,snapshot):late(reader,snapshot);return final(reader,snapshot)
        monkeypatch.setattr(azure.azure_ml_selected_asset_secret_indicators,'final_snapshot',finalize)
    options={'content_secret_scans':flag,p['option']:[t for t in targets if ('storage'in t)==(profile=='code')],'retries':0,'inventories':[p['kind']]}
    ids=[p['check']]
    if mixed:
        q=source.PROFILES['code'];options[q['option']]=[t for t in targets if 'storage'in t];ids.append(q['check']);options['inventories'].append(q['kind'])
    req={'connector':{'provider':'azure','scopes':[SCOPE],'auth':{'method':'client-secret','tenant_id':TENANT,'client_id':TENANT,'client_secret':AUTH},'options':options},'checks':ids if named else[]}
    snapshot=engine.collect_snapshot(req);rows=engine.evaluate_snapshot(snapshot,checks=ids)['findings']
    return snapshot,rows,trace


def own(snapshot,profile):return next(c for c in snapshot['collections']if c['type']==source.PROFILES[profile]['kind'])


def capture(name,profile,snapshot,rows,trace):
    if os.environ.get('AZURE_ML_ASSET_CAPTURE_DIR'):
        folder=Path(os.environ['AZURE_ML_ASSET_CAPTURE_DIR']);folder.mkdir(parents=True,exist_ok=True)
        (folder/(profile+'-'+name+'.json')).write_text(json.dumps({'profile':profile,'expected_status':rows[0]['status'],'snapshot':snapshot,'findings':rows,'http':trace.calls,'real_detectors':name in('pass','fail')},sort_keys=True,indent=2)+'\n')


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('hit',[False,True])
def test_native_positive_negative_real_transport_public_proposed_bridge(monkeypatch,profile,hit):
    snapshot,rows,trace=collect(monkeypatch,profile,TOKEN if hit else'mode=ready')
    assert {r['status']for r in rows}=={'FAIL'if hit else'PASS'},rows
    assert len(trace.calls)==len(source.operations(profile))and len(trace.scans)==2
    assert own(snapshot,profile)['items'][0][source.MARKER]['native_complete']is True
    assert TOKEN not in json.dumps([snapshot,rows])and AUTH not in json.dumps(snapshot)
    assert all(r.closed for r in trace.responses)and all(c.closed for c in trace.connections)
    assert not trace.readers[0].configuration_secret_redactions


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('hit',[False,True])
def test_actual_pinned_dual_engines_capture_and_exact_value_dedup(monkeypatch,profile,hit):
    runs=[];sdk=[];run=scanning._run;kingfisher=scanning._scan_kingfisher
    def runner(argv,payload,timeout):runs.append(argv);return run(argv,payload,timeout)
    def actual_sdk(payload,path,timeout):sdk.append(path);return kingfisher(payload,path,timeout)
    monkeypatch.setattr(scanning,'_run',runner)
    monkeypatch.setattr(scanning,'_scan_kingfisher',actual_sdk)
    snapshot,rows,trace=collect(monkeypatch,profile,TOKEN if hit else'mode=ready',real=True)
    assert {r['status']for r in rows}=={'FAIL'if hit else'PASS'},rows
    scans=[argv for argv in runs if 'stdin'in argv]
    assert len(scans)==1 and len(sdk)==1
    assert '--no-verification'in scans[0]and '--no-update'in scans[0]
    marker=own(snapshot,profile)['items'][0][source.MARKER]
    assert {e['engine']:e['version']for e in marker['parts'][0]['engines']}=={'kingfisher':'1.4.0','trufflehog':'3.92.5'}
    if hit:
        leak,=marker['leaks'];assert {d['engine']for d in leak['detectors']}=={'kingfisher','trufflehog'}
    capture('fail'if hit else'pass',profile,snapshot,rows,trace)


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('failure',['denied','deleted','redirect','empty','truncated','partial','duplicate','nonfinite','encoding','wrong_type','foreign','name','case','missing_properties','malformed_properties','response_bound','missing_request'])
def test_native_unavailable_malformed_foreign_and_partial_matrix(monkeypatch,profile,failure):
    def transform(op,data,t):
        if op!='asset_before':return data
        if failure=='partial':data['partial']=True
        if failure=='foreign':data['id']=data['id'].replace(SCOPE,FOREIGN)
        if failure=='wrong_type':data['type']='Microsoft.Compute/virtualMachines'
        if failure=='name':data['name']='wrong'
        if failure=='case':data['id']=data['id'].replace('NameCase','namecase')
        if failure=='missing_properties':data.pop('properties')
        if failure=='malformed_properties':data['properties']=[]
        if failure=='duplicate':return b'{"id":1,"id":2}'
        if failure=='nonfinite':return b'{"value":NaN}'
        return data
    def fault(op,r,t):
        if op!='asset_before':return r
        if failure in('denied','deleted','redirect'):return Response({'error':TOKEN},{'denied':403,'deleted':404,'redirect':302}[failure],{'Location':'https://evil.invalid/'+TOKEN})
        if failure=='empty':return Response(b'')
        if failure=='truncated':r.headers['Content-Length']=str(len(r.raw)+1)
        if failure=='encoding':r.headers['Content-Encoding']='gzip'
        if failure=='response_bound':r.headers['Content-Length']=str(source.MAX_ARM+1)
        if failure=='missing_request':r.headers.pop('x-ms-request-id')
        return r
    snapshot,rows,trace=collect(monkeypatch,profile,transform=transform,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'},rows
    assert not trace.scans and TOKEN not in json.dumps([snapshot,rows])
    if failure=='denied':capture('unknown',profile,snapshot,rows,trace)


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('op',['subscription','workspace_before','workspace_after','asset_after'])
def test_native_identity_race_never_scans_unbound_bytes(monkeypatch,profile,op):
    def change(operation,data,t):
        if operation!=op:return data
        if op=='subscription':data['tenantId']='66666666-6666-6666-6666-666666666666'
        elif op.startswith('workspace'):data['properties']['workspaceId']='66666666-6666-6666-6666-666666666666'if op=='workspace_after'else None
        elif profile=='environment':data['properties']['condaFile']='dependencies:\n- changed\n'
        else:data['properties']['codeUri']='https://evil.invalid/'+TOKEN
        return data
    snapshot,rows,trace=collect(monkeypatch,profile,TOKEN,transform=change)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


@pytest.mark.parametrize('value',[None,'','***','https://evil.invalid/conda.yml','conda.yml',42,[], 'dependencies:\n- @Microsoft.KeyVault(SecretUri=x)\n','dependencies:\n- '+('x'*(source.MAX_CONTENT+1))])
def test_environment_only_nonempty_supported_inline_conda(monkeypatch,value):
    def change(op,data,t):
        if op=='asset_before':data['properties']['condaFile']=value
        return data
    snapshot,rows,trace=collect(monkeypatch,transform=change)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('versioned',[False,True])
@pytest.mark.parametrize('uri',['short','long','https'])
def test_code_native_datastore_and_exact_current_or_versioned_file(monkeypatch,service,versioned,uri):
    snapshot,rows,trace=collect(monkeypatch,'code',targets=[target('code',service,versioned)],uri=uri)
    assert {r['status']for r in rows}=={'PASS'},rows
    assert own(snapshot,'code')['items'][0][source.MARKER]['immutable_source_proven']is False


@pytest.mark.parametrize('mutation',['uri_external','sas','percent','traversal','prefix_collision','folder_other','datastore_uri_foreign','missing_account_parent','wrong_account_parent','wrong_account','wrong_container','wrong_endpoint','wrong_protocol','unsupported_datastore','protected_payload','credential_type','datastore_race','code_race','storage_endpoint','etag_race','storage_partial','version_race','object_oversize'])
def test_code_source_association_and_storage_safety_matrix(monkeypatch,mutation):
    def change(op,data,t):
        if op=='asset_before':
            value={'uri_external':'https://evil.invalid/code/','sas':'https://sourceaccount.blob.core.windows.net/sources/code/?sig='+TOKEN,'percent':'azureml://datastores/source_store/paths/code/%252e%252e/','traversal':'azureml://datastores/source_store/paths/code/../','prefix_collision':'azureml://datastores/source_store/paths/cod/','folder_other':'azureml://datastores/source_store/paths/other/','datastore_uri_foreign':'azureml://datastores/foreign/paths/code/'}.get(mutation)
            if value:data['properties']['codeUri']=value
        if op=='asset_after'and mutation=='code_race':data['properties']['codeUri']='azureml://datastores/source_store/paths/other/'
        if op.startswith('datastore'):
            p=data['properties']
            if mutation=='missing_account_parent':p.pop('resourceGroup')
            if mutation=='wrong_account_parent':p['subscriptionId']=FOREIGN.split('/')[-1]
            if mutation=='wrong_account':p['accountName']='foreignaccount'
            if mutation=='wrong_container':p['containerName']='other'
            if mutation=='wrong_endpoint':p['endpoint']='evil.invalid'
            if mutation=='wrong_protocol':p['protocol']='http'
            if mutation=='unsupported_datastore':p['datastoreType']='AzureDataLakeGen2'
            if mutation=='protected_payload':p['credentials']['secrets']['key']=TOKEN
            if mutation=='credential_type':p['credentials']['credentialsType']='Custom'
            if mutation=='datastore_race'and op=='datastore_after':p['accountName']='changedaccount'
        if op=='account'and mutation=='storage_endpoint':data['properties']['primaryEndpoints']['blob']='https://evil.invalid/'
        return data
    def fault(op,r,t):
        if op=='properties_after'and mutation=='etag_race':r.headers['ETag']='"changed"'
        if op=='content'and mutation=='storage_partial':r.headers['Content-Length']=str(len(r.raw)+1)
        if op=='content'and mutation=='version_race':r.headers['x-ms-version-id']='2026-10-18T12:00:00.0000000Z'
        if op=='properties_before'and mutation=='object_oversize':r.headers['Content-Length']=str(source.MAX_CONTENT+1)
        return r
    snapshot,rows,trace=collect(monkeypatch,'code',TOKEN,targets=[target('code',versioned=True)],transform=change,fault=fault)
    assert {r['status']for r in rows}=={'UNKNOWN'},rows
    assert not trace.scans and TOKEN not in json.dumps([snapshot,rows])


@pytest.mark.parametrize('typ',['None','AccountKey','Sas','ServicePrincipal','Certificate'])
def test_stored_auth_discriminator_is_not_customer_content_authorization(monkeypatch,typ):
    def change(op,data,t):
        if op.startswith('datastore'):data['properties']['credentials']={'credentialsType':typ,**({'secrets':{'secretsType':typ}}if typ!='None'else{})}
        return data
    snapshot,rows,trace=collect(monkeypatch,'code',transform=change)
    assert {r['status']for r in rows}=={'PASS'}and not any('listSecrets'in c[2]or c[0]not in('GET','HEAD')for c in trace.calls)


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('absent',['kingfisher','trufflehog'])
@pytest.mark.parametrize('hit',[False,True])
def test_incomplete_engine_clean_unknown_but_bound_completed_hit_decisive(monkeypatch,profile,absent,hit):
    snapshot,rows,trace=collect(monkeypatch,profile,TOKEN if hit else'mode=ready',real=True,absent=absent)
    assert {r['status']for r in rows}=={'FAIL'if hit else'UNKNOWN'},rows
    assert own(snapshot,profile)['items'][0][source.MARKER]['complete']is False
    if hit:assert rows[0]['evidence']['complete']is False


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('budget',['calls','total','deadline'])
def test_shared_budgets_never_claim_clean_unread_content(monkeypatch,profile,budget):
    if budget=='calls':monkeypatch.setattr(source,'MAX_CALLS',2)
    if budget=='total':monkeypatch.setattr(source,'MAX_TOTAL',20)
    if budget=='deadline':monkeypatch.setattr(source,'MAX_SECONDS',0)
    snapshot,rows,trace=collect(monkeypatch,profile)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('claim',['tenant','principal','expired','audience'])
def test_native_sdk_token_binding_and_audience_coherence(monkeypatch,profile,claim):
    count=[0]
    def claims(scope):
        count[0]+=1
        if claim=='tenant':return{'tid':FOREIGN.split('/')[-1]}
        if claim=='principal':return{'oid':PRINCIPAL if count[0]==1 else FOREIGN.split('/')[-1]}
        if claim=='expired':return{'exp':time.time()-1}
        return{'aud':'https://evil.invalid/'}
    snapshot,rows,trace=collect(monkeypatch,profile,claims=claims)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('flag,named',[(False,True),(True,False),(False,False)])
def test_default_off_named_flag_and_explicit_inventory_not_authorization(monkeypatch,profile,flag,named):
    snapshot,rows,trace=collect(monkeypatch,profile,flag=flag,named=named)
    assert not trace.calls and not trace.scans
    assert not rows or {r['status']for r in rows}=={'UNKNOWN'}


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('failure',['missing','empty','foreign','extra','duplicate','too_many','scope','traversal','case'])
def test_pure_selection_preauth_limits_and_case_identity(profile,failure):
    t=target(profile);opts={'content_secret_scans':True,'_content_secret_scan_kinds':[source.PROFILES[profile]['kind']],source.PROFILES[profile]['option']:[t]};scopes=[SCOPE]
    if failure=='missing':opts.pop(source.PROFILES[profile]['option'])
    if failure=='empty':opts[source.PROFILES[profile]['option']]=[]
    if failure=='foreign':t['resource_id']=t['resource_id'].replace(SCOPE,FOREIGN)
    if failure=='extra':t['url']='https://evil.invalid/'
    if failure=='duplicate':opts[source.PROFILES[profile]['option']]*=2
    if failure=='too_many':opts[source.PROFILES[profile]['option']]=[{**t,'resource_id':t['resource_id']+str(i)}for i in range(5)]
    if failure=='scope':scopes=[]
    if failure=='traversal':t['resource_id']=t['resource_id'].replace('NameCase','..')
    if failure=='case':
        assert source.identity(profile,t)!=source.identity(profile,{**t,'resource_id':t['resource_id'].replace('NameCase','namecase')});return
    with pytest.raises(ValueError):source.selected_targets(opts,scopes)


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('hit',[False,True])
def test_actual_http_framing_debug_error_privacy_and_cross_reader_union(monkeypatch,profile,hit,capsys,caplog):
    monkeypatch.setattr(source.http.client.HTTPConnection,'debuglevel',1)
    for name in('azure.identity','azure.core.pipeline.policies.http_logging_policy'):caplog.set_level(logging.DEBUG,logger=name)
    def late(reader,snapshot):
        snapshot['metadata']['late_alias']=TOKEN
        for attr in('databricks_notebook_secret_metadata','ml_command_job_secret_metadata','log_sample_secret_metadata','declaration_secret_metadata','configuration_secret_metadata','storage_source_secret_metadata','devops_selected_metadata','app_setting_secret_metadata','acr_image_secret_metadata'):setattr(reader,attr,{attr+'_alias':TOKEN})
    def fault(op,r,t):return Response({'error':TOKEN},403)if not hit and op=='asset_before'else r
    snapshot,rows,trace=collect(monkeypatch,profile,TOKEN,real=True,fault=fault,late=late if hit else None,concrete_http=True)
    assert {r['status']for r in rows}=={'FAIL'if hit else'UNKNOWN'},rows
    logs=capsys.readouterr();retained=json.dumps([snapshot,rows])+logs.out+logs.err+caplog.text
    assert (TOKEN in retained)==hit and AUTH not in retained and 'Bearer ey'not in retained
    assert all(r.closed for r in trace.responses)and not trace.readers[0].configuration_secret_redactions


def test_registered_typed_consumers_keep_no_numbered_equivalence():
    for name,p in source.PROFILES.items():
        actual,=[c for c in checks.CHECKS if c.id==p['check']]
        assert inspect.unwrap(actual.evaluate)is getattr(consumer,name)
        assert actual.kind==p['kind']and actual.allow_incomplete_failure
    assert all(d['requirements']==[]and d['ui_group']=='Secrets'and d['severity']=='high'for d in consumer.DECLARATIONS)
    assert len(source.operations('code')) * source.MAX_TARGETS <= source.MAX_CALLS
    assert len(source.operations('code', build=True, job=True)) * source.MAX_TARGETS == source.MAX_CALLS


@pytest.mark.parametrize('operation',['datastore_before','account','properties_before','content','properties_after','datastore_after','asset_after','datastore_final','workspace_after'])
def test_code_every_late_native_read_denied_stays_unknown_no_raw_error(monkeypatch,operation):
    def deny(op,r,t):return Response({'error':TOKEN},403)if op==operation else r
    snapshot,rows,trace=collect(monkeypatch,'code',TOKEN,fault=deny)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans
    assert TOKEN not in json.dumps([snapshot,rows])


def test_cross_profile_native_collection_hmac_value_dedup_and_shared_union(monkeypatch):
    snapshot,rows,trace=collect(monkeypatch,literal=TOKEN,real=True,mixed=True)
    assert len(rows)==1 and rows[0]['status']=='FAIL' # Public exact-value dedup.
    markers=[own(snapshot,p)['items'][0][source.MARKER]for p in source.PROFILES]
    assert len({m['leaks'][0]['fingerprint']for m in markers})==1
    assert all({d['engine']for d in m['leaks'][0]['detectors']}=={'kingfisher','trufflehog'}for m in markers)
    assert TOKEN not in json.dumps([snapshot,rows])and not trace.readers[0].configuration_secret_redactions


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('failure',['missing','foreign','wrong_provider','storage_escape'])
def test_proposed_public_request_validation_precedes_credential_acquisition(monkeypatch,profile,failure):
    t=target(profile);p=source.PROFILES[profile];opts={'content_secret_scans':True,p['option']:[t]};provider='azure'
    if failure=='missing':opts.pop(p['option'])
    if failure=='foreign':t['resource_id']=t['resource_id'].replace(SCOPE,FOREIGN)
    if failure=='wrong_provider':provider='aws'
    if failure=='storage_escape':
        if profile=='code':t['storage']['object']='code/../secret.txt'
        else:t['resource_id']=t['resource_id'].replace('NameCase','..')
    with pytest.raises(ValueError):engine.collect_snapshot({'connector':{'provider':provider,'scopes':[SCOPE],'auth':{},'options':opts},'checks':[p['check']]})


@pytest.mark.parametrize('profile',['environment','code'])
def test_all_four_explicit_targets_complete_within_shared_bound(monkeypatch,profile):
    t=target(profile);targets=[{**deepcopy(t),'resource_id':t['resource_id']+str(i)}for i in range(4)]
    snapshot,rows,trace=collect(monkeypatch,profile,targets=targets)
    assert len(rows)==4 and {r['status']for r in rows}=={'PASS'},rows
    assert len(trace.calls)==4*len(source.operations(profile))<=source.MAX_CALLS


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('hit',[False,True])
def test_selected_partial_native_scope_never_clean_but_first_bound_hit_remains(monkeypatch,profile,hit):
    t=target(profile);other={**deepcopy(t),'resource_id':t['resource_id']+'Other'}
    def deny(op,r,target):return Response({'error':TOKEN},403)if op=='asset_before'and target['resource_id']==other['resource_id']else r
    snapshot,rows,trace=collect(monkeypatch,profile,TOKEN if hit else'mode=ready',targets=[t,other],fault=deny)
    assert 'PASS'not in {r['status']for r in rows}
    if hit:
        decisive,=[r for r in rows if r['status']=='FAIL'];assert decisive['evidence']['complete']is False
    else:assert {r['status']for r in rows}=={'UNKNOWN'}


@pytest.mark.parametrize('profile',['environment','code'])
@pytest.mark.parametrize('mutation',['foreign_scope','missing_binding','capture','principal','request','duplicate_receipt','unbound_receipt','wrong_version','missing_part','missing_engine','fake_engine_version','provenance','selected','immutable_claim'])
def test_actual_native_consumer_rejects_unbound_or_tampered_evidence(monkeypatch,profile,mutation):
    from peaso.snapshot import seal
    snapshot,rows,trace=collect(monkeypatch,profile)
    assert {r['status']for r in rows}=={'PASS'}
    snapshot=deepcopy(snapshot);own_collection=own(snapshot,profile);item=own_collection['items'][0];marker=item[source.MARKER];kind=source.PROFILES[profile]['kind'];ledger=snapshot['metadata'][kind+'_receipts']
    if mutation=='foreign_scope':marker['scope']=FOREIGN
    if mutation=='missing_binding':marker['association_binding']=None
    if mutation=='capture':marker['capture']='ml-asset-capture:'+'0'*32
    if mutation=='principal':ledger[-1]['principal']='storage-source-principal:'+'0'*64
    if mutation=='request':ledger[-1]['request']='https://evil.invalid/'
    if mutation=='duplicate_receipt':ledger.append(deepcopy(ledger[-1]))
    if mutation=='unbound_receipt':ledger[-1]['bound']=False
    if mutation=='wrong_version':ledger[-1]['version']='1900-01-01'
    if mutation=='missing_part':marker['parts']=[]
    if mutation=='missing_engine':marker['parts'][0]['engines'].pop()
    if mutation=='fake_engine_version':marker['parts'][0]['engines'][0]['version']='0.0.0'
    if mutation=='provenance':item['_provenance']['credential_context_id']='foreign'
    if mutation=='selected':snapshot['metadata'][kind+'_selection'][SCOPE]=[]
    if mutation=='immutable_claim':marker['immutable_source_proven']=True
    rows=engine.evaluate_snapshot(seal(snapshot),checks=[source.PROFILES[profile]['check']])['findings']
    assert {r['status']for r in rows}=={'UNKNOWN'},rows


@pytest.mark.parametrize('profile',['environment','code'])
def test_secret_bearing_selected_asset_and_object_aliases_are_opaque(monkeypatch,profile):
    t=target(profile);t['resource_id']=t['resource_id'].replace('NameCase',TOKEN)
    if profile=='code':t['storage']['object']='code/'+TOKEN+'.py'
    snapshot,rows,trace=collect(monkeypatch,profile,TOKEN,targets=[t],real=True)
    assert {r['status']for r in rows}=={'FAIL'}
    retained=json.dumps([snapshot,rows,trace.readers[0].collections,trace.readers[0].ml_asset_secret_metadata,dict(scanning._RESULTS)])
    assert TOKEN not in retained and t['resource_id']not in retained


@pytest.mark.parametrize('profile',['environment','code'])
def test_conflicting_http_framing_never_clean(monkeypatch,profile):
    def conflict(op,r,t):
        if op=='asset_before':r.headers['Transfer-Encoding']='chunked'
        return r
    snapshot,rows,trace=collect(monkeypatch,profile,fault=conflict)
    assert {r['status']for r in rows}=={'UNKNOWN'}and not trace.scans


def test_file_path_case_alias_is_duplicate_but_blob_paths_remain_distinct():
    t=target('code','file');other=deepcopy(t);other['storage']['object']=t['storage']['object'].upper()
    assert source.identity('code',t)==source.identity('code',other)
    p=source.PROFILES['code']
    with pytest.raises(ValueError):source.selected_targets({p['option']:[t,other]},[SCOPE])
    t=target('code','blob');other=deepcopy(t);other['storage']['object']=t['storage']['object'].upper()
    assert source.identity('code',t)!=source.identity('code',other)


def test_storage_receipt_service_cannot_contradict_native_bound_projection(monkeypatch):
    from peaso.snapshot import seal
    snapshot,rows,trace=collect(monkeypatch,'code');kind=source.PROFILES['code']['kind']
    for r in snapshot['metadata'][kind+'_receipts']:
        if r['operation']=='content':r['origin']='file'
    rows=engine.evaluate_snapshot(seal(snapshot),checks=[source.PROFILES['code']['check']])['findings']
    assert {r['status']for r in rows}=={'UNKNOWN'}
