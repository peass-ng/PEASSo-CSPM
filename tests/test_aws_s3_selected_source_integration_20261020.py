"""Independent native AWS HTTP -> botocore StreamingBody -> Requests -> engine.

Production Requests/client/collector/engine hooks are used; no draft bridge or registry override.
"""
from copy import deepcopy
import gzip
import inspect
import io
import json
import socket
import stat
import sys
import tarfile
from types import SimpleNamespace
from urllib.parse import urlsplit, parse_qs, unquote
import zipfile
import boto3
from botocore.awsrequest import AWSResponse
import botocore.response
import pytest
from peaso import engine, secret_scanning as scanning
from peaso.collectors import aws
from peaso.collectors import aws_s3_selected_source_secret_indicators as source
from peaso.checks import aws_s3_selected_source_secret_review_20261020 as consumer

ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
BUCKET='selected-source-review';KEY='scripts/selected file#one.txt'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH='offline-s3-session-token-canary'
ETAG='"opaque-native-tag-7"'
CAPTURES=[]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail('actual socket/DNS/auth discovery forbidden')
    for key in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,key,blocked)
    for key in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex'):monkeypatch.setattr(socket,key,blocked)
    monkeypatch.setattr(aws,'_session',blocked)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED','true')
    installed,=[c for c in engine._registry() if c.id==source.CHECK]
    assert inspect.unwrap(installed.evaluate)is consumer.evaluate
    # Actual StreamingBody.set_socket_timeout calls this native socket adapter;
    # the offline HTTP raw stream has no OS socket, and checks every time slice.
    monkeypatch.setattr(botocore.response,'set_socket_timeout',lambda raw,seconds: 0<seconds<=5 or pytest.fail('unbounded stream timeout'))
    scanning._RESULTS.clear();yield;scanning._RESULTS.clear()


def target(fmt='text',version=None):
    t={'scope':SCOPE,'bucket':BUCKET,'key':KEY,'format':fmt}
    if version is not None:t['version_id']=version
    return t


def archive(fmt,hit=False,entries=None):
    literal=(TOKEN if hit else 'mode=ready').encode()
    if fmt=='text':return literal
    entries=entries or [('src/main.txt',literal),('src/opposite.txt',b'mode=public')]
    output=io.BytesIO()
    if fmt=='zip':
        with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED)as z:
            for name,data in entries:z.writestr(name,data)
        return output.getvalue()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT)as tar:
        for name,data in entries:
            info=tarfile.TarInfo(name);info.size=len(data);info.mtime=0;tar.addfile(info,io.BytesIO(data))
    raw=output.getvalue()
    return gzip.compress(raw,mtime=0)if fmt=='tar.gz'else raw


class Raw:
    def __init__(self,data,trace):self.stream_=io.BytesIO(data);self.closed=False;self.reads=[];trace.raw.append(self)
    def read(self,size=None):
        assert isinstance(size,int)and 0<size<=16384
        self.reads.append(size);return self.stream_.read(size)
    def stream(self,amt=1024,decode_content=False):
        while chunk:=self.read(amt):yield chunk
    def close(self):self.closed=True


def collect(monkeypatch,fmt='text',hit=False,*,real=False,fault=None,version=None,payload=None,missing_engine=None,targets=None,options=None):
    t=target(fmt,version);selected=targets or[t];body=archive(fmt,hit)if payload is None else payload
    opts={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.OPTION:selected,
        'retry_attempts':1,'service_concurrency':1,**(options or{})}
    trace=SimpleNamespace(calls=[],raw=[],clients=[],scans=[],inputs=[])
    original_init=aws.Requests.__init__
    def init(self,*args,**kwargs):
        original_init(self,*args,**kwargs);trace.reader=self
    monkeypatch.setattr(aws.Requests,'__init__',init)
    if not real:
        def detector(data,path,timeout):
            trace.scans.append((path,timeout));return [(TOKEN,'github-pat',1)]if TOKEN.encode()in data else[]
        monkeypatch.setattr(scanning,'_scan_kingfisher',detector);monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    if missing_engine:
        def missing(*args,**kwargs):raise TimeoutError(TOKEN)
        monkeypatch.setattr(scanning,'_scan_'+missing_engine,missing)
    session=boto3.Session(aws_access_key_id='AKIAOFFLINEONLYTEST12',aws_secret_access_key='offline-signing-key-only',aws_session_token=AUTH,region_name=REGION)
    original=session.client
    head_count=0;current_version=version
    def client(service,**kwargs):
        sdk=original(service,**kwargs);trace.clients.append(sdk)
        is_source_profile=bool(kwargs.get('config').s3 and kwargs['config'].s3.get('addressing_style')=='path')
        if fault=='custom_endpoint':sdk.meta._endpoint_url='https://foreign.invalid/'
        def send(request,**kw):
            nonlocal head_count,current_version
            p=urlsplit(request.url);q=parse_qs(p.query,keep_blank_values=True)
            assert p.scheme=='https' and p.hostname==service+'.'+REGION+'.amazonaws.com' and not p.fragment
            headers={k.lower():v.decode()if isinstance(v,bytes)else v for k,v in request.headers.items()}
            assert 'Authorization'in request.headers and AUTH not in json.dumps(list(trace.reader._cache),default=str)
            status=200;native_headers={'x-amz-request-id':'request-11111111'}
            if service=='sts':
                assert request.method=='POST'and p.path=='/'and not q
                if is_source_profile:
                    current_version=selected[len([c for c in trace.calls if c['operation']=='caller'])].get('version_id');head_count=0
                operation='caller'if is_source_profile else'collector_caller'
                account='999999999999'if fault=='caller_account'and is_source_profile else ACCOUNT
                response=(f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::{account}:user/reviewer</Arn><UserId>AIDAOFFLINEREVIEW</UserId><Account>{account}</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>request-11111111</RequestId></ResponseMetadata></GetCallerIdentityResponse>').encode()
                native_headers['content-type']='text/xml'
            else:
                assert headers['x-amz-expected-bucket-owner']==ACCOUNT
                assert not any(k in headers for k in ('x-amz-request-payer','x-amz-checksum-mode','x-amz-server-side-encryption-customer-key'))
                if 'location'in q:
                    assert request.method=='GET'and p.path=='/'+BUCKET and q=={'location':['']}
                    operation='location';region='us-west-2'if fault=='region'else ''
                    response=('<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'+region+'</LocationConstraint>').encode();native_headers['content-type']='application/xml'
                else:
                    assert unquote(p.path)=='/'+BUCKET+'/'+KEY
                    assert q==({'versionId':[current_version]}if current_version is not None else{})
                    operation='get'if request.method=='GET'else'head_after'if head_count else'head_before'
                    if request.method=='HEAD':head_count+=1
                    assert request.method in('HEAD','GET')
                    if operation in('get','head_after'):assert headers['if-match']==ETAG
                    native_headers.update({'content-length':str(len(body)),'etag':ETAG,'content-type':'application/octet-stream'})
                    if current_version is not None:native_headers['x-amz-version-id']=current_version
                    if fault=='current_versioned':native_headers['x-amz-version-id']='native-current-v7'
                    if fault=='malformed_version':native_headers['x-amz-version-id']='invalid version'
                    if fault=='malformed_etag':native_headers['etag']='not-quoted'
                    if fault=='version_mismatch'and operation=='get':native_headers['x-amz-version-id']='foreign-version'
                    if fault=='etag_mismatch'and operation=='get':native_headers['etag']='"foreign"'
                    if fault=='head_mutation'and operation=='head_after':native_headers['etag']='"changed-later"'
                    if fault=='get_length'and operation=='get':native_headers['content-length']=str(len(body)+1)
                    if fault=='content_range'and operation=='get':native_headers['content-range']='bytes 0-3/999';status=206
                    if fault=='ssec':native_headers['x-amz-server-side-encryption-customer-algorithm']='AES256'
                    if fault=='requester':native_headers['x-amz-request-charged']='requester'
                    if fault=='encoding':native_headers['content-encoding']='gzip'
                    if fault=='delete_marker':native_headers['x-amz-delete-marker']='true'
                    response=body if request.method=='GET'else b''
            trace.calls.append({'service':service,'operation':operation,'method':request.method,'host':p.hostname,'path':p.path,'query':q})
            if fault in('denied','absent')and operation=='get':
                status=403 if fault=='denied'else 404;response=('<Error><Code>AccessDenied</Code><Message>'+TOKEN+'</Message><RequestId>request-11111111</RequestId></Error>').encode();native_headers['content-length']=str(len(response));native_headers['content-type']='application/xml'
            if fault=='truncated'and operation=='get':response=response[:-1]
            if fault=='redirect'and operation=='get':status=301;native_headers['location']='https://foreign.invalid/'+TOKEN
            if fault=='stream_timeout'and operation=='get':
                raw=Raw(response,trace)
                def timeout(size=None):raise TimeoutError(TOKEN)
                raw.read=timeout
            else:raw=Raw(response,trace)
            if fault=='stream_close'and operation=='get':
                def close_failed():raw.closed=True;raise OSError(TOKEN)
                raw.close=close_failed
            raw.selected_source=is_source_profile
            return AWSResponse(request.url,status,native_headers,raw)
        sdk._endpoint.http_session.send=send
        return sdk
    monkeypatch.setattr(session,'client',client)
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'offline-native-http'))
    named=not(options and options.get('_content_secret_scan_kinds')==[])
    if not named:opts['inventories']=[source.KIND]
    request={'connector':{'provider':'aws','scopes':[SCOPE],'auth':{'method':'access_keys','aws_access_key_id':'AKIAOFFLINEONLYTEST12','aws_secret_access_key':'offline-signing-key-only','aws_session_token':AUTH,'region_name':REGION},'options':opts}}
    if named:request['checks']=[source.CHECK]
    else:request['categories']=['exposure']
    snapshot=engine.collect_snapshot(request)
    code=inspect.unwrap(consumer.evaluate).__code__;previous=sys.getprofile()
    def observe(frame,event,arg):
        if event=='call'and frame.f_code is code:trace.inputs.append({'item':deepcopy(frame.f_locals['item']),'index':deepcopy(frame.f_locals['index'])})
    try:
        sys.setprofile(observe);findings=engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']
    finally:sys.setprofile(previous)
    return snapshot,findings,trace


@pytest.mark.parametrize('fmt',source.FORMATS)
@pytest.mark.parametrize('branch',['clean','hit','denied'])
def test_native_each_format_three_branches(monkeypatch,fmt,branch):
    snapshot,findings,trace=collect(monkeypatch,fmt,branch=='hit',fault='denied'if branch=='denied'else None)
    assert [f['status']for f in findings]==[{'clean':'PASS','hit':'FAIL','denied':'UNKNOWN'}[branch]],findings
    assert len(trace.calls)==(5 if branch=='denied'else 6)
    assert all(r.closed for r in trace.raw if r.selected_source)
    retained=json.dumps([snapshot,findings,list(scanning._RESULTS.values())])
    for value in(TOKEN,AUTH,KEY,BUCKET,ETAG,'mode=ready'):assert value not in retained
    assert not trace.reader.s3_source_heads and not trace.reader.s3_source_redactions and not any(source.PROFILE in key for key in trace.reader._cache)
    CAPTURES.append({'format':fmt,'branch':branch,'input':trace.inputs[0],'snapshot':snapshot,'findings':findings,'real_engines':False})


@pytest.mark.parametrize('fmt',source.FORMATS)
@pytest.mark.parametrize('hit',[False,True])
def test_real_pinned_both_engines_native(monkeypatch,fmt,hit):
    snapshot,findings,trace=collect(monkeypatch,fmt,hit,real=True)
    assert [f['status']for f in findings]==['FAIL'if hit else'PASS'],findings
    marker=next(c for c in snapshot['collections']if c['type']==source.KIND)['items'][0][source.MARKER]
    assert all({e['status']for e in p['engines']}=={'complete'}for p in marker['parts'])
    if hit:assert {d['engine']for d in marker['leaks'][0]['detectors']}=={'kingfisher','trufflehog'}
    CAPTURES.append({'format':fmt,'branch':'hit'if hit else'clean','input':trace.inputs[0],
        'snapshot':snapshot,'findings':findings,'real_engines':True})


@pytest.mark.parametrize('fmt',source.FORMATS)
@pytest.mark.parametrize('fault',['caller_account','region','malformed_version','malformed_etag','etag_mismatch','version_mismatch','get_length','content_range','ssec','requester','encoding','delete_marker','truncated','redirect','stream_timeout','custom_endpoint','absent'])
def test_native_identity_transport_and_stream_unknown(monkeypatch,fmt,fault):
    snapshot,findings,trace=collect(monkeypatch,fmt,True,fault=fault)
    assert findings and all(f['status']in('UNKNOWN','DENIED')for f in findings),findings
    assert TOKEN not in json.dumps([snapshot,findings])


@pytest.mark.parametrize('fmt',source.FORMATS)
@pytest.mark.parametrize('hit',[False,True])
@pytest.mark.parametrize('missing',['kingfisher','trufflehog'])
def test_trusted_completed_hit_survives_other_engine(monkeypatch,fmt,hit,missing):
    _,findings,_=collect(monkeypatch,fmt,hit,missing_engine=missing)
    assert [f['status']for f in findings]==['FAIL'if hit else'UNKNOWN']
    if hit:assert findings[0]['evidence']['complete']is False


@pytest.mark.parametrize('fmt',source.FORMATS)
@pytest.mark.parametrize('hit',[False,True])
def test_head_after_mutation_never_clean_but_retains_point_in_time_hit(monkeypatch,fmt,hit):
    _,findings,_=collect(monkeypatch,fmt,hit,fault='head_mutation')
    assert [f['status']for f in findings]==['FAIL'if hit else'UNKNOWN']
    if hit:assert findings[0]['evidence']['complete']is False


@pytest.mark.parametrize('version',[None,'null','opaque+version/3'])
@pytest.mark.parametrize('fmt',source.FORMATS)
def test_current_unversioned_and_explicit_existing_versions(monkeypatch,fmt,version):
    _,findings,trace=collect(monkeypatch,fmt,version=version)
    assert [f['status']for f in findings]==['PASS']
    for call in trace.calls:
        if call['operation']in('head_before','get','head_after'):assert call['query']==({'versionId':[version]}if version is not None else{})


@pytest.mark.parametrize('fmt',['zip','tar','tar.gz'])
@pytest.mark.parametrize('hit',[False,True])
def test_binary_and_nested_members_never_prove_clean(monkeypatch,fmt,hit):
    payload=archive(fmt,entries=[('first.txt',(TOKEN if hit else'mode=ready').encode()),('binary.dat',b'\0\xff\x01')])
    _,findings,_=collect(monkeypatch,fmt,payload=payload)
    assert [f['status']for f in findings]==['FAIL'if hit else'UNKNOWN']


@pytest.mark.parametrize('fmt',['zip','tar','tar.gz'])
def test_binary_only_unknown(monkeypatch,fmt):
    _,findings,_=collect(monkeypatch,fmt,payload=archive(fmt,entries=[('binary.dat',b'\0\xff\x01')]))
    assert [f['status']for f in findings]==['UNKNOWN']


@pytest.mark.parametrize('fmt',['zip','tar','tar.gz'])
@pytest.mark.parametrize('name',['../outside.txt','/absolute.txt','C:/outside.txt','a\\b.txt','a/../b.txt'])
def test_archive_paths_are_data_never_extracted(monkeypatch,fmt,name):
    _,findings,_=collect(monkeypatch,fmt,payload=archive(fmt,entries=[(name,b'public')]))
    assert [f['status']for f in findings]==['UNKNOWN']


def test_stream_reader_has_actual_botocore_stream_model():
    reader=aws.Requests({'content_secret_scans':True});opts={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.OPTION:[target()]}
    source.initialize(reader,opts,[SCOPE])
    with pytest.raises(ValueError):source._read_body(reader,io.BytesIO(b'fake'),4,{'bytes':0})


@pytest.mark.parametrize('field,value',[('bucket','arn:aws:s3:::selected'),('bucket','directory--az1--x-s3'),('bucket','alias-s3alias'),
    ('bucket','object--ol-s3'),('bucket','192.168.0.1'),('bucket','evil.example/path'),('key','https://foreign.invalid/source'),
    ('key','../source'),('key','a/../b'),('scope','999999999999/us-east-1'),('format','auto'),('version_id',''),('endpoint_url','https://foreign.invalid')])
def test_selection_rejected_before_native_client(field,value):
    t=target();t[field]=value;opts={'content_secret_scans':True,source.OPTION:[t]}
    with pytest.raises(ValueError):source.selected_targets(opts,[SCOPE])


@pytest.mark.parametrize('mode',['flag','unnamed'])
def test_default_off_no_native_reads(monkeypatch,mode):
    options={'content_secret_scans':False}if mode=='flag'else{'_content_secret_scan_kinds':[]}
    _,findings,trace=collect(monkeypatch,options=options)
    assert all(c['operation']=='collector_caller'for c in trace.calls) and not any(f['status']in('PASS','FAIL')for f in findings)



@pytest.mark.parametrize('fmt',['zip','tar','tar.gz'])
@pytest.mark.parametrize('edge',['nested','symlink','duplicate','trailing','member_limit','ratio','oversize'])
def test_native_archive_structural_budgets(monkeypatch,fmt,edge):
    entries=[('first.txt',b'public')]
    if edge=='nested':entries=[('nested.zip',archive('zip'))]
    if edge=='duplicate':entries=[('same.txt',b'public'),('same.txt',b'public')]
    if edge=='member_limit':entries=[(str(i)+'.txt',b'public')for i in range(source.MAX_MEMBERS+1)]
    if edge=='ratio':entries=[('compressible.txt',b'x'*100000)]
    if edge=='oversize':entries=[('large.txt',b'x'*(source.MAX_TEXT+1))]
    payload=archive(fmt,entries=entries)
    if edge=='symlink':
        output=io.BytesIO()
        if fmt=='zip':
            with zipfile.ZipFile(output,'w')as z:
                info=zipfile.ZipInfo('link');info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(info,'target')
        else:
            with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT)as tar:
                info=tarfile.TarInfo('link');info.type=tarfile.SYMTYPE;info.linkname='target';tar.addfile(info)
        payload=output.getvalue()
        if fmt=='tar.gz':payload=gzip.compress(payload,mtime=0)
    if edge=='trailing':payload+=b'unsupported-trailing-bytes'
    # Uncompressed tar has no compression-ratio violation; an ordinary large
    # textual member is supported and remains under the member byte bound.
    expected='PASS'if edge=='ratio'and fmt=='tar'else'UNKNOWN'
    _,findings,_=collect(monkeypatch,fmt,payload=payload)
    assert [f['status']for f in findings]==[expected],findings


@pytest.mark.parametrize('fmt',['zip','tar','tar.gz'])
def test_native_exact_value_union_deduplicates_locations(monkeypatch,fmt):
    payload=archive(fmt,entries=[('one.txt',TOKEN.encode()),('two.txt',TOKEN.encode())])
    snapshot,findings,_=collect(monkeypatch,fmt,payload=payload)
    assert [f['status']for f in findings]==['FAIL']
    leaks=findings[0]['evidence']['secret_leaks']
    assert len(leaks)==1 and len(leaks[0]['locations'])==2 and len(leaks[0]['detectors'])==2
    assert TOKEN not in json.dumps([snapshot,findings])


@pytest.mark.parametrize('fmt',source.FORMATS)
@pytest.mark.parametrize('hit',[False,True])
def test_native_later_call_budget_keeps_only_bound_positive(monkeypatch,fmt,hit):
    _,findings,trace=collect(monkeypatch,fmt,hit,options={'max_calls':5})
    assert len(trace.calls)==5
    assert [f['status']for f in findings]==['FAIL'if hit else'UNKNOWN']
    if hit:assert findings[0]['evidence']['complete']is False


@pytest.mark.parametrize('budget',['wire','time','object'])
def test_native_early_budget_is_uncertain(monkeypatch,budget):
    monkeypatch.setattr(source,{'wire':'MAX_WIRE_TOTAL','time':'MAX_SECONDS','object':'MAX_OBJECT'}[budget],0 if budget=='time'else 16)
    _,findings,_=collect(monkeypatch,hit=True)
    assert all(f['status']=='UNKNOWN'for f in findings)


def test_native_both_engine_timeouts_never_clean(monkeypatch):
    def timeout(*args,**kwargs):raise TimeoutError(TOKEN)
    monkeypatch.setattr(scanning,'_scan_kingfisher',timeout)
    _,findings,_=collect(monkeypatch,missing_engine='trufflehog',real=True)
    assert [f['status']for f in findings]==['UNKNOWN']


def test_fixed_native_sdk_ignores_configured_endpoint(monkeypatch):
    monkeypatch.setenv('AWS_ENDPOINT_URL','https://foreign.invalid/')
    monkeypatch.setenv('AWS_ENDPOINT_URL_S3','https://foreign.invalid/')
    _,findings,trace=collect(monkeypatch)
    assert [f['status']for f in findings]==['PASS']
    assert all(c['host'].endswith('.amazonaws.com')for c in trace.calls)


def test_finalizer_union_scrubs_existing_metadata_and_future_aliases():
    from concurrent.futures import Future
    options={'content_secret_scans':True,'_content_secret_scan_kinds':[source.KIND],source.OPTION:[target()]}
    reader=aws.Requests(options);source.initialize(reader,options,[SCOPE])
    alias={TOKEN:{'locator':'prefix-'+TOKEN,'values':[TOKEN]}};future=Future();future.set_result(alias);reader._cache[('prior',)]=future
    reader.s3_source_redactions.add(TOKEN)
    collections,metadata=source.finalize(reader,[{'locator':TOKEN}],{'previous':TOKEN})
    assert TOKEN in json.dumps([alias,collections,metadata])
    assert future.result()is alias and not reader.s3_source_redactions


@pytest.mark.parametrize('tamper',['foreign_scope','capture','engine_version','source_request','object_version','provenance','part_path'])
def test_native_output_binding_tampering_unknown(monkeypatch,tamper):
    snapshot,_,_=collect(monkeypatch)
    item=next(c for c in snapshot['collections']if c['type']==source.KIND)['items'][0];m=item[source.MARKER]
    if tamper=='foreign_scope':m['scope']='999999999999/'+REGION
    if tamper=='capture':m['capture']='s3-source:'+'0'*32
    if tamper=='engine_version':m['parts'][0]['engines'][0]['version']='untrusted'
    if tamper=='source_request':m['source_requests'][0]=m['source_requests'][1]
    if tamper=='object_version':m['object']['explicit_version']=True
    if tamper=='provenance':item['_provenance']['scope']='999999999999/'+REGION
    if tamper=='part_path':m['parts'][0]['path']='https://foreign.invalid/'
    # Recompute the snapshot envelope so this probes the consumer's source
    # binding rather than stopping at the separate snapshot digest guard.
    snapshot.pop('snapshot_id',None)
    findings=engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']
    assert [f['status']for f in findings]==['UNKNOWN']


@pytest.mark.parametrize('hit',[False,True])
def test_native_four_exact_sources_bound_call_cap_and_value_union(monkeypatch,hit):
    targets=[target(version='selected-version-'+str(n))for n in range(4)]
    snapshot,findings,trace=collect(monkeypatch,hit=hit,targets=targets)
    assert len(trace.calls)==21 and len(next(c for c in snapshot['collections']if c['type']==source.KIND)['items'])==4
    assert findings and {f['status']for f in findings}=={'FAIL'if hit else'PASS'},findings
    if hit:
        locations={loc['path']for f in findings for leak in f['evidence']['secret_leaks']for loc in leak['locations']}
        assert len(locations)==4
    assert TOKEN not in json.dumps([snapshot,findings])


@pytest.mark.parametrize('hit',[False,True])
def test_native_close_failure_restores_transport_and_retains_bound_hit(monkeypatch,hit):
    snapshot,findings,trace=collect(monkeypatch,hit=hit,fault='stream_close')
    assert [f['status']for f in findings]==['FAIL'if hit else'UNKNOWN']
    assert all(client._endpoint.http_session.send.__name__=='send'for client in trace.clients)
    assert all(r.closed for r in trace.raw if r.selected_source)
    assert TOKEN not in json.dumps([snapshot,findings])


@pytest.mark.parametrize('fmt',source.FORMATS)
def test_native_current_versioned_object_needs_no_version_selector(monkeypatch,fmt):
    snapshot,findings,trace=collect(monkeypatch,fmt,fault='current_versioned')
    assert [f['status']for f in findings]==['PASS']
    marker=next(c for c in snapshot['collections']if c['type']==source.KIND)['items'][0][source.MARKER]
    assert marker['object']['explicit_version']is False and marker['object']['version']
    assert not any(call['query']for call in trace.calls if call['operation']in('get','head_before','head_after'))


@pytest.mark.parametrize('fmt',source.FORMATS)
def test_native_wrong_format_never_clean(monkeypatch,fmt):
    _,findings,_=collect(monkeypatch,fmt,payload=b'\0binary'if fmt=='text'else b'plain text instead of archive')
    assert [f['status']for f in findings]==['UNKNOWN']


def test_fixture_captures_replay_to_recorded_statuses():
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    fixture=root/'peaso/checks/aws_s3_selected_source_secret_review_20261020_fixtures.json'
    captures=json.loads(fixture.read_text())['captures'];assert captures
    for row in captures:
        status,_=consumer.evaluate(row['input']['item'],row['input']['index'])
        assert status==row['findings'][0]['status']
    assert any(r['real_engines'] for r in captures)


def test_native_sdk_debug_logging_cannot_emit_auth_content_or_selectors(monkeypatch):
    import logging
    records=[]
    class Memory(logging.Handler):
        def emit(self,record):records.append(record.getMessage())
    handler=Memory();prior=[]
    for name in('botocore.auth','botocore.endpoint','botocore.parsers','botocore.hooks'):
        logger=logging.getLogger(name);prior.append((logger,logger.level,logger.propagate));logger.setLevel(logging.DEBUG);logger.propagate=False;logger.addHandler(handler)
    try:
        _,findings,_=collect(monkeypatch,hit=True,fault='denied')
        leaked=any(value in message for message in records for value in(TOKEN,AUTH,KEY,BUCKET))
        records.clear()
    finally:
        for logger,level,propagate in prior:logger.removeHandler(handler);logger.setLevel(level);logger.propagate=propagate
    assert [f['status']for f in findings]==['UNKNOWN']
    assert not leaked


def test_private_sdk_logs_restore_filters_and_preserve_other_threads():
    import logging,threading
    messages=[]
    class Memory(logging.Handler):
        def emit(self,record):messages.append(record.getMessage())
    logger=logging.getLogger('botocore.endpoint');handler=Memory()
    before=list(logger.filters);level,propagate=logger.level,logger.propagate
    logger.setLevel(logging.DEBUG);logger.propagate=False;logger.addHandler(handler)
    try:
        with source._private_sdk_logs():
            logger.debug('selected-call-private')
            worker=threading.Thread(target=lambda:logger.debug('other-thread-observation'))
            worker.start();worker.join(timeout=1);assert not worker.is_alive()
        assert list(logger.filters)==before and not handler.filters
        logger.debug('after-call-observation')
        assert messages==['other-thread-observation','after-call-observation']
    finally:
        logger.removeHandler(handler);logger.setLevel(level);logger.propagate=propagate


def test_private_sdk_logs_overlapping_threads_restore_independent_filters():
    import logging,threading
    from peaso.collectors.aws_content_sdk_logging import private_sdk_logs
    messages=[];errors=[];entered=threading.Barrier(3);release=threading.Barrier(3)
    class Memory(logging.Handler):
        def emit(self,record):messages.append(record.getMessage())
    logger=logging.getLogger('botocore.endpoint');handler=Memory()
    before=list(logger.filters);level,propagate=logger.level,logger.propagate
    logger.setLevel(logging.DEBUG);logger.propagate=False;logger.addHandler(handler)
    def worker():
        try:
            with private_sdk_logs():
                logger.debug('selected-call-private')
                entered.wait(timeout=3);release.wait(timeout=3)
        except Exception as exc:errors.append(type(exc).__name__)
    workers=[threading.Thread(target=worker)for _ in range(2)]
    try:
        for thread in workers:thread.start()
        entered.wait(timeout=3);logger.debug('unrelated-thread-observation');release.wait(timeout=3)
        for thread in workers:thread.join(timeout=3)
        assert not errors and not any(t.is_alive()for t in workers)
        assert messages==['unrelated-thread-observation']
        assert list(logger.filters)==before and not handler.filters
    finally:
        logger.removeHandler(handler);logger.setLevel(level);logger.propagate=propagate

def test_write_native_source_receipts():
    from pathlib import Path
    root=Path('/tmp/peasso-secret-surface-review-20261020/aws-s3-production');root.mkdir(parents=True,exist_ok=True)
    (root/'native-captures.json').write_text(json.dumps(CAPTURES,indent=2)+'\n')
    assert TOKEN not in(root/'native-captures.json').read_text()
