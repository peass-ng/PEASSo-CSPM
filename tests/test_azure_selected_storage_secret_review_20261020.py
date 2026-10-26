"""Native HTTP bytes -> real Azure scheduler/collector -> public engine.

Unregistered proposal hooks are injected only within each test, never persisted
into shared Azure source. Native payloads are independent of historical CASES.
"""
import base64
from copy import deepcopy
from contextlib import ExitStack
import importlib
import io
import json
from pathlib import Path
import socket
import stat
import tarfile
import time
from types import SimpleNamespace
from urllib.parse import quote
import zipfile
import pytest
from peaso import checks,engine,secret_scanning as scanning
from peaso import collectors
from peaso.collectors import azure,azure_selected_storage_secret_indicators as source
from peaso.snapshot import seal

consumer=importlib.import_module('peaso.checks.azure_selected_storage_secret_review_20261020')
SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
OTHER='33333333-3333-3333-3333-333333333333'
PRINCIPAL='44444444-4444-4444-4444-444444444444'
ACCOUNT=SCOPE+'/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount'
VERSION='2026-10-19T12:00:00.0000000Z'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
SECOND='ghp_'+'8nR3aS0xM5dW9pL2tG7bJ4kQ6vE1yC3zF0sU'
SCRATCH=Path('/tmp/peasso-secret-surface-review-20261020/azure-selected-storage')


def target(service='blob',form='text',path='source.txt'):
    return {'service':service,'resource_id':ACCOUNT,'container' if service=='blob' else 'share':'sources','object':path,'version':VERSION,'format':form}


def archive(form='zip',payload=b'mode=ready',members=None):
    if form=='text':return payload
    members=members or [('main.py',payload)]
    stream=io.BytesIO()
    if form=='zip':
        with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for name,raw in members:z.writestr(name,raw)
    else:
        with tarfile.open(fileobj=stream,mode='w:gz' if form=='tar.gz' else 'w',format=tarfile.USTAR_FORMAT) as z:
            for name,raw in members:
                entry=tarfile.TarInfo(name);entry.size=len(raw);z.addfile(entry,io.BytesIO(raw))
    return stream.getvalue()


def jwt(audience,**claims):
    obj={'aud':audience,'tid':TENANT,'oid':PRINCIPAL,'exp':time.time()+3600,**claims}
    return 'eyJhbGciOiJub25lIn0.'+base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')+'.b2ZmbGluZQ'


class Response:
    def __init__(self,payload=b'',status=200,headers=None,head=False):
        raw=json.dumps(payload).encode() if isinstance(payload,dict) else payload
        self.status=status;self.headers={'Content-Type':'application/json','Content-Length':str(len(raw)),'x-ms-request-id':'11111111-1111-4111-8111-111111111111',**(headers or {})}
        self.stream=io.BytesIO(b'' if head else raw);self.closed=False;self.reads=0
    def getheader(self,key):return self.headers.get(key)
    def read(self,size):
        assert 0<size<=16384;self.reads+=1;return self.stream.read(size)
    def close(self):self.closed=True


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    attempts=[]
    def blocked(*a,**kw):attempts.append('network/auth');raise AssertionError('No live sockets, DNS or credentials')
    for key in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo'):monkeypatch.setattr(socket,key,blocked)
    for key in ('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,key,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)
    monkeypatch.setenv('AZURE_CONFIG_DIR','/nonexistent/selected-storage-review')
    original=list(checks.CHECKS);consumer.install(checks.register);scanning._RESULTS.clear()
    yield
    checks.CHECKS[:]=original;scanning._RESULTS.clear();assert not attempts


def request(targets,**opts):
    return {'connector':{'provider':'azure','scopes':[SCOPE],'auth':{'method':'token','tenant_id':TENANT,'arm_token':'offline-transport-only'},
             'options':{'content_secret_scans':True,source.OPTION:targets,'retries':0,**opts}},'checks':[source.CHECK]}


def collect(monkeypatch,targets=None,raw=None,*,real=False,fault=None,missing_engine=None,token_claims=None,req=None,seed=None):
    targets=targets or [target()];raw=raw if raw is not None else {source.identity(t):archive(t['format']) for t in targets}
    if isinstance(raw,bytes):raw={source.identity(t):raw for t in targets}
    trace=SimpleNamespace(calls=[],responses=[],connections=[],scans=[],tokens=[],readers=[])
    original_init=azure._Reader.__init__
    def reader_init(reader,*args,**kwargs):
        original_init(reader,*args,**kwargs);trace.readers.append(reader)
    monkeypatch.setattr(azure._Reader,'__init__',reader_init)
    if not real:
        def detector(payload,path,timeout):
            trace.scans.append((bytes(payload),path,timeout));return [(v,'github-pat',1) for v in (TOKEN,SECOND) if v.encode() in payload]
        monkeypatch.setattr(scanning,'_scan_kingfisher',detector);monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    if missing_engine:
        def absent(*a,**kw):raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning,'_scan_'+missing_engine,absent)
    class Transport:
        tenant=TENANT;verified_tenant=TENANT
        def __init__(self,auth):pass
        def token(self,audience):
            assert audience in ('https://management.azure.com','https://storage.azure.com');trace.tokens.append(audience)
            return jwt(audience,**(token_claims(audience) if token_claims else {}))
        def request(self,*a,**kw):pytest.fail('No generic native cache/list/discovery may fetch selected content')
        def close(self):pass
    class Connection:
        sock=None
        def __init__(self,host,timeout):
            assert host in {'management.azure.com','sourceaccount.blob.core.windows.net','sourceaccount.file.core.windows.net'}
            assert 0<timeout<=10;self.host=host;self.closed=False;trace.connections.append(self)
        def set_debuglevel(self,level):assert level==0
        def request(self,method,path,body=None,headers=None):
            assert body is None and method in ('GET','HEAD') and headers['Accept-Encoding']=='identity'
            assert headers['Authorization'].startswith('Bearer ey') and not any(h in headers for h in ('x-ms-encryption-key','x-ms-encryption-algorithm','x-ms-structured-body','Range'))
            matches=[]
            for t in targets:
                named='/sources/'+quote(t['object'],safe='/')
                if 'version' in t:named+='?'+('versionid' if t['service']=='blob' else 'sharesnapshot')+'='+quote(t['version'],safe='')
                if self.host=='management.azure.com':
                    if path==SCOPE+'?api-version=2022-12-01':matches.append((t,'subscription'))
                    elif path==t['resource_id']+'?api-version=2025-06-01':matches.append((t,'account'))
                elif path==named and self.host=='sourceaccount.'+t['service']+'.core.windows.net':matches.append((t,'data'))
            assert matches,(self.host,path)
            t,operation=matches[0]
            if operation=='subscription':payload={'id':SCOPE,'subscriptionId':SCOPE.rsplit('/',1)[1],'tenantId':TENANT,'state':'Enabled','displayName':TOKEN};response=Response(payload)
            elif operation=='account':
                payload={'id':ACCOUNT,'name':'sourceaccount','type':'Microsoft.Storage/storageAccounts','tags':{'source':TOKEN},'properties':{'provisioningState':'Succeeded','primaryEndpoints':{'blob':'https://sourceaccount.blob.core.windows.net/','file':'https://sourceaccount.file.core.windows.net/'}}};response=Response(payload)
            else:
                assert headers['x-ms-version']=='2023-11-03' and headers['x-ms-date'].endswith('GMT')
                if t['service']=='file':assert headers['x-ms-file-request-intent']=='backup' and 'If-Match' not in headers
                elif method=='GET':assert headers['If-Match']=='"0x123ABC"'
                data=raw[source.identity(t)];properties={'Content-Type':'application/octet-stream','ETag':'"0x123ABC"','x-ms-version':'2023-11-03'}
                if t['service']=='blob':
                    properties['x-ms-blob-type']='BlockBlob'
                    if 'version' in t:properties['x-ms-version-id']=t['version']
                else:properties.update({'x-ms-type':'File','x-ms-file-file-id':'12345678'})
                response=Response(data,headers=properties,head=method=='HEAD')
                n=sum(c[2]==path and c[0]=='HEAD' for c in trace.calls);operation='content' if method=='GET' else 'properties_before' if n==0 else 'properties_after'
            trace.calls.append((method,self.host,path,operation))
            if fault:response=fault(t,operation,response)
            self.response=response;trace.responses.append(response)
        def getresponse(self):return self.response
        def close(self):self.closed=True
    monkeypatch.setattr(azure,'AzureTransport',Transport);monkeypatch.setattr(source.http.client,'HTTPSConnection',Connection)
    # Final production hooks perform selection, scoped reads, provenance and
    # union redaction; no candidate integration bridge is installed here.
    if seed:
        original_metadata=azure._Reader.metadata
        def seeded(reader):return {**original_metadata(reader),'legacy_name':seed}
        monkeypatch.setattr(azure._Reader,'metadata',seeded)
    current=deepcopy(req if req is not None else request(targets))
    snapshot=engine.collect_snapshot(current);rows=engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']
    return snapshot,rows,trace


def own(snapshot):return next(c for c in snapshot['collections'] if c['type']==source.KIND)


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('form',['text','zip','tar','tar.gz'])
@pytest.mark.parametrize('hit',[False,True])
def test_native_collector_public_engine_good_bad(monkeypatch,service,form,hit):
    t=target(service,form,TOKEN+'.py');payload=('TOKEN='+TOKEN if hit else 'mode=ready').encode()
    snapshot,rows,trace=collect(monkeypatch,[t],archive(form,payload),seed=TOKEN if hit else None)
    assert [r['status'] for r in rows]==['FAIL' if hit else 'PASS'],rows
    assert own(snapshot)['items'][0][source.MARKER]['complete'] is True and len(trace.calls)==5
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)
    retained=json.dumps([snapshot,rows,trace.readers[0].collections,trace.readers[0].storage_source_secret_metadata])
    assert (TOKEN in retained)==hit and t['object'] not in retained and 'Bearer ey' not in retained
    assert not trace.readers[0].storage_source_secret_redactions


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('form',['text','zip','tar','tar.gz'])
@pytest.mark.parametrize('hit',[False,True])
def test_true_pinned_both_engines_each_native_format(monkeypatch,service,form,hit):
    t=target(service,form);payload=('TOKEN='+TOKEN if hit else 'mode=ready').encode();runs=[];run=scanning._run
    def runner(argv,payload,timeout):runs.append(list(argv));return run(argv,payload,timeout)
    monkeypatch.setattr(scanning,'_run',runner)
    snapshot,rows,trace=collect(monkeypatch,[t],archive(form,payload),real=True)
    assert [r['status'] for r in rows]==['FAIL' if hit else 'PASS'],rows
    engines=own(snapshot)['items'][0][source.MARKER]['parts'][0]['engines']
    assert {e['engine']:e['version'] for e in engines}=={'kingfisher':'1.4.0','trufflehog':'3.92.5'}
    assert all(e['status']=='complete' for e in engines)
    stdin=[r for r in runs if 'stdin' in r];assert stdin and all({'--no-verification','--no-update','--force-skip-archives','--fail-on-scan-errors'}<=set(r) for r in stdin)


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('operation',['subscription','account','properties_before','content','properties_after'])
@pytest.mark.parametrize('failure',['denied','deleted','redirect','partial','missing_provenance','truncated'])
def test_native_read_failures_never_clean(monkeypatch,service,operation,failure):
    def fault(t,op,r):
        if op!=operation:return r
        if failure in ('denied','deleted','redirect','partial'):return Response(TOKEN.encode(),{'denied':403,'deleted':404,'redirect':302,'partial':206}[failure],{'Location':'https://untrusted.invalid/'+TOKEN})
        if failure=='missing_provenance':r.headers.pop('x-ms-request-id')
        if failure=='truncated':r.headers['Content-Length']=str(int(r.headers['Content-Length'])+1)
        return r
    snapshot,rows,trace=collect(monkeypatch,[target(service)],b'mode=ready',fault=fault)
    assert {r['status'] for r in rows}=={'UNKNOWN'},rows
    assert not trace.scans and TOKEN not in json.dumps([snapshot,rows])
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('change',['foreign_subscription','foreign_tenant','foreign_account','wrong_name','wrong_type','endpoint','provisioning','partial','duplicate_json','version','etag','file_id','api_version','content_range','encoding'])
def test_native_identity_and_version_coherence(monkeypatch,service,change):
    def fault(t,operation,r):
        if operation in ('subscription','account'):
            data=json.loads(r.stream.getvalue())
            if change=='foreign_subscription' and operation=='subscription':data['subscriptionId']=OTHER
            if change=='foreign_tenant' and operation=='subscription':data['tenantId']=OTHER
            if operation=='account':
                if change=='foreign_account':data['id']=ACCOUNT+'foreign'
                if change=='wrong_name':data['name']='foreign'
                if change=='wrong_type':data['type']='Microsoft.Web/sites'
                if change=='endpoint':data['properties']['primaryEndpoints'][service]='https://untrusted.invalid/'
                if change=='provisioning':data['properties']['provisioningState']='Updating'
                if change=='partial':data['nextLink']='https://untrusted.invalid/'+TOKEN
                if change=='duplicate_json':return Response(b'{"id":"a","id":"b"}')
            return Response(data)
        if operation=='content':
            if change=='version':r.headers['x-ms-version-id']='2026-10-18T12:00:00.0000000Z' if service=='blob' else VERSION
            if change=='etag':r.headers['ETag']='"foreign"'
            if change=='file_id' and service=='file':r.headers['x-ms-file-file-id']='foreign'
            if change=='api_version':r.headers['x-ms-version']='2025-05-05'
            if change=='content_range':r.headers['Content-Range']='bytes 0-9/100'
            if change=='encoding':r.headers['Content-Encoding']='gzip'
        return r
    snapshot,rows,trace=collect(monkeypatch,[target(service)],b'mode=ready',fault=fault)
    # File snapshots have no returned version-id; their exact native query and
    # stable file ID/ETag bind the version. Blob has no file-id field.
    applicable=not (change=='version' and service=='file' or change=='file_id' and service=='blob')
    assert {r['status'] for r in rows}==({'UNKNOWN'} if applicable else {'PASS'}),rows
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('engine_name',['kingfisher','trufflehog'])
@pytest.mark.parametrize('hit',[False,True])
def test_one_engine_unavailable_never_clean_but_trusted_hit_remains_fail(monkeypatch,engine_name,hit):
    snapshot,rows,_=collect(monkeypatch,raw=('TOKEN='+TOKEN if hit else 'mode=ready').encode(),missing_engine=engine_name)
    assert {r['status'] for r in rows}==({'FAIL'} if hit else {'UNKNOWN'})
    if hit:assert rows[0]['evidence']['complete'] is False and 'incomplete' in rows[0]['evidence']['observed'].lower()


@pytest.mark.parametrize('case',['missing','empty','too_many','duplicate','foreign','url','traversal','escaped','empty_segment','format','version','bad_date','extra','wrong_container','flag'])
def test_selection_rejected_without_authentication(monkeypatch,case):
    t=target();options={'content_secret_scans':True,source.OPTION:[t]};scopes=[SCOPE]
    if case=='missing':options.pop(source.OPTION);options['_content_secret_scan_kinds']=[source.KIND]
    elif case=='empty':options[source.OPTION]=[]
    elif case=='too_many':options[source.OPTION]=[target(path='f'+str(i)) for i in range(5)]
    elif case=='duplicate':options[source.OPTION]*=2
    elif case=='foreign':scopes=['/subscriptions/'+OTHER]
    elif case=='url':t['object']='https://untrusted.invalid/source'
    elif case=='traversal':t['object']='a/../source'
    elif case=='escaped':t['object']='a%2fsource'
    elif case=='empty_segment':t['object']='a//source'
    elif case=='format':t['format']='auto'
    elif case=='version':t['version']='latest'
    elif case=='bad_date':t['version']='2026-99-01T12:00:00Z'
    elif case=='extra':t['sas']='secret'
    elif case=='wrong_container':t['share']=t.pop('container')
    elif case=='flag':options['content_secret_scans']='true'
    with pytest.raises(ValueError,match='invalid_selection'):source.selected_targets(options,scopes)


@pytest.mark.parametrize('change',['audience','expired','tenant','principal','not_yet_valid','malformed'])
def test_native_oauth_context_is_pinned_without_following_challenges(monkeypatch,change):
    def claims(audience):
        if change=='audience':return {'aud':'https://untrusted.invalid'}
        if change=='expired':return {'exp':time.time()-10}
        if change=='tenant':return {'tid':OTHER}
        if change=='principal':return {'oid':OTHER} if audience==source.STORAGE else {}
        if change=='not_yet_valid':return {'nbf':time.time()+600}
        return {'oid':'malformed'}
    snapshot,rows,trace=collect(monkeypatch,raw=b'mode=ready',token_claims=claims)
    assert {r['status'] for r in rows}=={'UNKNOWN'} and not trace.scans


def test_exact_values_deduplicate_across_native_blob_file_archives_and_metadata(monkeypatch):
    targets=[target('blob','zip'),target('file','tar.gz')]
    snapshot,rows,trace=collect(monkeypatch,targets,raw={source.identity(t):archive(t['format'],('TOKEN='+TOKEN).encode(),[(TOKEN+'.py',('TOKEN='+TOKEN).encode()),('copy.py',('TOKEN='+TOKEN).encode())]) for t in targets},seed=TOKEN)
    assert len(rows)==1 and rows[0]['status']=='FAIL'
    assert len(rows[0]['evidence']['secret_leaks'][0]['locations'])==4
    assert TOKEN in json.dumps([snapshot,rows,trace.readers[0].collections])


@pytest.mark.parametrize('form',['zip','tar','tar.gz'])
@pytest.mark.parametrize('case',['truncated','traversal','duplicate','binary','nested','empty'])
def test_unsafe_or_incomplete_archives_cannot_clean_pass(monkeypatch,form,case):
    members=[('main.py',b'mode=ready')]
    if case=='traversal':members=[('../main.py',b'mode=ready')]
    elif case=='duplicate':members*=2
    elif case=='binary':members=[('binary.dat',b'\x00\xffbinary')]
    elif case=='nested':members=[('nested.zip',archive('zip'))]
    elif case=='empty':members=[('empty.py',b'')]
    raw=archive(form,members=members)
    # Tar's trailing record padding is optional beyond the two zero blocks;
    # truncate actual file/header bytes rather than only valid padding.
    if case=='truncated':raw=raw[:600] if form=='tar' else raw[:len(raw)//2]
    snapshot,rows,_=collect(monkeypatch,[target(form=form)],raw)
    assert {r['status'] for r in rows}=={'UNKNOWN'}


def test_later_unsupported_archive_member_does_not_erase_native_observed_hit(monkeypatch):
    raw=archive('tar',members=[('main.py',('TOKEN='+TOKEN).encode()),('unknown.dat',b'\x00binary')])
    snapshot,rows,_=collect(monkeypatch,[target(form='tar')],raw)
    assert len(rows)==1 and rows[0]['status']=='FAIL' and rows[0]['evidence']['complete'] is False


@pytest.mark.parametrize('budget',['calls','wire','total','member','expanded','members','deadline','redaction','redaction_values'])
def test_bounded_resources_never_claim_clean_complete(monkeypatch,budget):
    field={'calls':'MAX_CALLS','wire':'MAX_OBJECT','total':'MAX_TOTAL','member':'MAX_MEMBER','expanded':'MAX_EXPANDED','members':'MAX_MEMBERS','deadline':'MAX_SECONDS','redaction':'MAX_REDACTION_BYTES','redaction_values':'MAX_REDACTION_VALUES'}[budget]
    monkeypatch.setattr(source,field,0 if budget in ('calls','members','deadline','redaction','redaction_values') else 1)
    snapshot,rows,_=collect(monkeypatch,[target(form='zip')],archive('zip',('TOKEN='+TOKEN).encode()),seed=TOKEN if budget.startswith('redaction') else None)
    if budget.startswith('redaction'):
        # Found values stay visible, so redaction bounds no longer withhold the hit.
        assert {r['status'] for r in rows}=={'FAIL'} and TOKEN in json.dumps(snapshot)
        return
    assert {r['status'] for r in rows}=={'UNKNOWN'}
    assert TOKEN not in json.dumps(snapshot)


def test_content_flag_and_exact_named_check_both_required(monkeypatch):
    req=request([target()],content_secret_scans=False)
    snapshot,rows,trace=collect(monkeypatch,req=req)
    assert {r['status'] for r in rows}=={'UNKNOWN'} and not trace.calls


def test_capture_independent_native_fixtures(monkeypatch):
    cases={}
    for state in ('pass','fail','unknown'):
        with monkeypatch.context() as local:
            def denied(t,op,r):return Response(TOKEN.encode(),403) if op=='content' else r
            snapshot,rows,_=collect(local,raw=('TOKEN='+TOKEN if state=='fail' else 'mode=ready').encode(),real=True,fault=denied if state=='unknown' else None)
            assert {r['status'] for r in rows}=={state.upper()}
            collection=own(snapshot);item=deepcopy(collection['items'][0])
            # Keep the predicate's actual native context, excluding unrelated
            # not-selected inventory metadata; no favorable facts are added.
            native_meta={k:deepcopy(v) for k,v in snapshot['metadata'].items() if k.startswith(source.KIND+'_') or k in
                         ('tenant_id','tenant_verified','context_binding','credential_context_id','customer_context_id')}
            index={'context':{'provider':'azure','scope':SCOPE,'metadata':native_meta},'collections':{source.KIND:[deepcopy(collection)]}}
            assert consumer.evaluate(item,index)[0]==state.upper()
            cases[state]=item;cases[state+'_index']=index
    cases['index']=deepcopy(cases['pass_index']);cases['missing']={};cases['malformed']={'id':1}
    serialized=json.dumps({source.CHECK:cases},indent=2,sort_keys=True)+'\n';assert TOKEN not in serialized
    SCRATCH.mkdir(parents=True,exist_ok=True);(SCRATCH/'native-fixtures.json').write_text(serialized)


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('form',['text','zip','tar','tar.gz'])
@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('real',[False,True])
def test_current_objects_need_no_snapshot_or_versioning_write(monkeypatch,service,form,hit,real):
    t=target(service,form);t.pop('version')
    snapshot,rows,trace=collect(monkeypatch,[t],archive(form,('TOKEN='+TOKEN if hit else 'mode=ready').encode()),real=real)
    assert [r['status'] for r in rows]==['FAIL' if hit else 'PASS']
    assert own(snapshot)['items'][0][source.MARKER]['selection_mode']=='current'
    assert len(trace.calls)==5 and all('?' not in path for method,host,path,operation in trace.calls if host!='management.azure.com')
    assert all(method in ('GET','HEAD') for method,*_ in trace.calls)


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('operation',['content','properties_after'])
@pytest.mark.parametrize('change',['etag','length','native_version_or_file_id'])
def test_current_overwrite_counterexamples_are_unresolved(monkeypatch,service,operation,change):
    t=target(service);t.pop('version')
    def fault(t,op,r):
        if op==operation:
            if change=='etag':r.headers['ETag']='"0xNEW"'
            elif change=='length':r.headers['Content-Length']=str(int(r.headers['Content-Length'])+1)
            else:r.headers['x-ms-version-id' if service=='blob' else 'x-ms-file-file-id']=VERSION if service=='blob' else 'newfileid'
        return r
    snapshot,rows,trace=collect(monkeypatch,[t],b'mode=ready',fault=fault)
    assert {r['status'] for r in rows}=={'UNKNOWN'} and not trace.scans


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('payload',[b'',b'\x00binary',b'   '])
def test_empty_binary_or_whitespace_plain_bytes_are_not_clean(monkeypatch,service,payload):
    snapshot,rows,_=collect(monkeypatch,[target(service)],payload)
    assert {r['status'] for r in rows}=={'UNKNOWN'}


@pytest.mark.parametrize('service',['blob','file'])
@pytest.mark.parametrize('header',['Content-Length','ETag','x-ms-version','native_identity'])
def test_omitted_native_properties_never_clean(monkeypatch,service,header):
    def fault(t,operation,response):
        if operation=='properties_before':
            key=header if header!='native_identity' else 'x-ms-version-id' if service=='blob' else 'x-ms-file-file-id'
            response.headers.pop(key)
        return response
    snapshot,rows,_=collect(monkeypatch,[target(service)],b'mode=ready',fault=fault)
    assert {r['status'] for r in rows}=={'UNKNOWN'}


@pytest.mark.parametrize('case',['capture','item_context','collection_context','selected','receipt_binding','receipt_identity','receipt_operation','receipt_scope','mode','version_locator','engine_version','engine_complete','foreign_tenant','source_requests'])
def test_consumer_rejects_tampered_native_capture(monkeypatch,case):
    snapshot,rows,_=collect(monkeypatch,raw=b'mode=ready')
    assert [r['status'] for r in rows]==['PASS']
    snapshot=deepcopy(snapshot);collection=own(snapshot);item=collection['items'][0];m=item[source.MARKER];meta=snapshot['metadata'];receipt=meta[source.KIND+'_receipts'][0]
    if case=='capture':m['capture']='storage-source-capture:'+'0'*32
    elif case=='item_context':item['_provenance']['customer_context_id']='foreign'
    elif case=='collection_context':collection['_provenance']['credential_context_id']='foreign'
    elif case=='selected':meta[source.KIND+'_selection'][SCOPE]=[]
    elif case=='receipt_binding':receipt['bound']=False
    elif case=='receipt_identity':receipt['identity']=source.KIND+':'+'0'*64
    elif case=='receipt_operation':receipt['operation']='content'
    elif case=='receipt_scope':receipt['scope']='/subscriptions/'+OTHER
    elif case=='mode':m['selection_mode']='current'
    elif case=='version_locator':m['version_locator']='native-version-placeholder'
    elif case=='engine_version':m['parts'][0]['engines'][0]['version']='untrusted'
    elif case=='engine_complete':m['parts'][0]['engines'][0]['status']='unavailable'
    elif case=='foreign_tenant':meta['tenant_id']=OTHER
    else:m['source_requests']=[]
    result=engine.evaluate_snapshot(seal(snapshot),checks=[source.CHECK])['findings']
    assert {r['status'] for r in result}=={'UNKNOWN'}


def test_native_file_case_aliases_rejected_but_blob_case_is_preserved():
    a=target('file',path='Source.py');b=target('file',path='source.py')
    assert source.identity(a)==source.identity(b)
    with pytest.raises(ValueError):source.selected_targets({'content_secret_scans':True,source.OPTION:[a,b]},[SCOPE])
    a['service']=b['service']='blob';a['container']=a.pop('share');b['container']=b.pop('share')
    assert source.identity(a)!=source.identity(b)
    assert len(source.selected_targets({'content_secret_scans':True,source.OPTION:[a,b]},[SCOPE]))==2


def test_native_file_segment_bound_rejected_before_credentials():
    with pytest.raises(ValueError):source.selected_targets({source.OPTION:[target('file',path='a'*256)]},[SCOPE])
