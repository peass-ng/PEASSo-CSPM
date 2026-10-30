"""Independent native ARM/OAuth/registry/data wire -> Azure collector -> engine."""
from copy import deepcopy
from tests.selected_secret_source_successors_20261020 import assert_source_receipt
import base64
import gzip
import io
import json
from pathlib import Path
import socket
import tarfile
import time
from types import SimpleNamespace
from urllib.parse import parse_qs
import pytest
from peaso import engine,secret_scanning as scanning
from peaso.collectors import azure
from peaso.collectors import azure_acr_image_secret_indicators as source
from peaso.collectors import azure_acr_image_stream_inspection_20261021 as stream
from peaso.checks import azure_acr_image_secret_review_20261020 as checks

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
OTHER='/subscriptions/33333333-3333-3333-3333-333333333333'
REGISTRY=SCOPE+'/resourceGroups/review/providers/Microsoft.ContainerRegistry/registries/reviewregistry'
HOST='reviewregistry.azurecr.io'
DATA_HOST='reviewregistry.eastus.data.azurecr.io'
TENANT='22222222-2222-2222-2222-222222222222'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
REPO='selected/application'


from tests.pinned_secret_scanners import require_pinned_scanners


def jwt(audience,**extra):
    claims={'aud':audience,'exp':int(time.time())+3600,**extra}
    encode=lambda value:base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=').decode()
    return encode({'alg':'RS256'})+'.'+encode(claims)+'.synthetic_signature'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a,**k):pytest.fail('actual network/DNS/auth discovery forbidden')
    for n in ('connect','connect_ex'):monkeypatch.setattr(socket.socket,n,blocked)
    for n in ('create_connection','getaddrinfo'):monkeypatch.setattr(socket,n,blocked)
    monkeypatch.setattr(azure,'credential_for',blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def packed(value):return json.dumps(value,separators=(',',':'),sort_keys=True).encode()


def image(*,positive=None,media=source.OCI,compressed=False,names=None,files=None):
    content=(TOKEN if positive=='layer' else 'ready = true').encode()
    files=files if files is not None else [(name,content) for name in (names or ['application/config.txt'])]
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,raw in files:
            member=tarfile.TarInfo(name);member.size=len(raw)
            archive.addfile(member,io.BytesIO(raw))
    layer=output.getvalue();wire=gzip.compress(layer,mtime=0) if compressed else layer
    config={'architecture':'amd64','os':'linux','rootfs':{'type':'layers','diff_ids':[source._sha(layer)]},
        'config':{'Env':['TOKEN='+TOKEN] if positive=='config' else ['MODE=ready']},'history':[{'created_by':'COPY application /app'}]}
    cfg=packed(config)
    layer_type='application/vnd.oci.image.layer.v1.tar'+('+gzip' if compressed else '')
    manifest={'schemaVersion':2,'mediaType':media,'config':{'digest':source._sha(cfg),'size':len(cfg),'mediaType':'application/vnd.oci.image.config.v1+json'},
        'layers':[{'digest':source._sha(wire),'size':len(wire),'mediaType':layer_type}],
        'annotations':{'example':'token='+TOKEN} if positive=='manifest' else {}}
    raw=packed(manifest)
    return SimpleNamespace(manifest=manifest,manifest_raw=raw,config=config,config_raw=cfg,layer=layer,wire=wire,
        target={'registry_id':REGISTRY,'repository':REPO,'digest':source._sha(raw)})


def request(targets):
    return {'connector':{'provider':'azure','scopes':[SCOPE],'auth':{'method':'token','tenant_id':TENANT,'arm_token':'unused-by-fake'},
        'options':{'content_secret_scans':True,source.OPTION:targets,'retries':0}},'checks':[source.CHECK]}


class Response:
    def __init__(self,payload,status=200,headers=None):
        self.payload=packed(payload) if isinstance(payload,dict) else payload
        self.status=status;self.stream=io.BytesIO(self.payload);self.closed=False
        self.headers={'Content-Length':str(len(self.payload)),'Content-Type':'application/json',**(headers or {})}
    def getheader(self,key):return self.headers.get(key)
    def read(self,size):
        assert 0<size<=16384
        return self.stream.read(size)
    def close(self):self.closed=True


def capture(monkeypatch,*,img=None,native=None,overrides=None,redirect=False,real=False,req=None,collect=True,access_claims=None,refresh_claims=None,arm_claims=None,acr=False,acr_claims=None):
    img=img or image();overrides=overrides or {};trace=SimpleNamespace(calls=[],responses=[],connections=[],scans=[],tokens=[])
    arm=jwt('https://management.azure.com',tid=TENANT,**(arm_claims or {}))
    refresh=jwt(HOST,tenant=TENANT,**(refresh_claims or {}))
    claims={'access':[{'type':'repository','name':REPO,'actions':['pull']}],**(access_claims or {})}
    access=jwt(HOST,**claims)
    acr_token=jwt(source.ACR_AUDIENCE,**{'tid':TENANT,**(acr_claims or {})})
    trace.credentials=(arm,refresh,access,acr_token)
    req=deepcopy(req if req is not None else request([img.target]))
    repositories={t['repository'] for t in req['connector']['options'][source.OPTION]}
    access_tokens={r:(access if r==REPO else jwt(HOST,access=[{'type':'repository','name':r,'actions':['pull']}])) for r in repositories}
    native=native if native is not None else {'id':REGISTRY,'name':'reviewregistry','type':'Microsoft.ContainerRegistry/registries',
        'properties':{'loginServer':HOST,'provisioningState':'Succeeded','roleAssignmentMode':'LegacyRegistryPermissions',
            'policies':{'azureADAuthenticationAsArmPolicy':{'status':'enabled'}},'dataEndpointEnabled':True,'dataEndpointHostNames':[DATA_HOST]},'tags':{'neverRetain':TOKEN}}
    if not real:
        def detector(payload,path,timeout):
            trace.scans.append((bytes(payload),path,timeout))
            return [(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else []
        monkeypatch.setattr(scanning,'_scan_kingfisher',detector);monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    blobs={source._sha(img.config_raw):img.config_raw,source._sha(img.wire):img.wire}
    class Transport:
        tenant=verified_tenant=TENANT
        def __init__(self,auth):pass
        def token(self,audience):
            trace.tokens.append(audience)
            if audience==source.ACR_AUDIENCE:
                if not acr:raise azure.AzureReadError('audience_token_unavailable',401)
                return acr_token
            assert audience=='https://management.azure.com';return arm
        def request(self,*a,**k):pytest.fail('no generic ARM response cache/enumeration')
        def close(self):pass
    class Connection:
        sock=None
        def __init__(self,host,timeout):
            assert host in ('management.azure.com',HOST,DATA_HOST) and 0<timeout<=10
            self.host=host;self.closed=False;trace.connections.append(self)
        def set_debuglevel(self,level):assert level==0
        def request(self,method,route,body=None,headers=None):
            assert headers['Accept-Encoding']=='identity'
            if self.host=='management.azure.com':
                assert method=='GET' and route==REGISTRY+'?api-version=2025-11-01' and body is None
                assert headers['Authorization']=='Bearer '+arm
                operation='registry_identity';response=Response(native)
            elif route=='/oauth2/exchange':
                assert self.host==HOST and method=='POST' and 'Authorization' not in headers
                assert parse_qs(body.decode())=={'grant_type':['access_token'],'service':[HOST],'tenant':[TENANT],'access_token':[acr_token if acr else arm]}
                operation='oauth_exchange';response=Response({'refresh_token':refresh})
            elif route=='/oauth2/token':
                assert self.host==HOST and method=='POST' and 'Authorization' not in headers
                fields=parse_qs(body.decode())
                repository=fields['scope'][0][len('repository:'):-len(':pull')]
                assert repository in repositories
                assert fields=={'grant_type':['refresh_token'],'service':[HOST],'scope':['repository:'+repository+':pull'],'refresh_token':[refresh]}
                operation='oauth_pull';response=Response({'access_token':access_tokens[repository]})
            elif self.host==DATA_HOST:
                assert method=='GET' and 'Authorization' not in headers and body is None
                assert route.startswith('/native/blob/') and route.endswith('?sig=synthetic')
                digest='sha256:'+route.split('/')[3].split('?')[0]
                assert digest in blobs
                operation='blob_data';response=Response(blobs[digest])
            else:
                matches=[r for r in repositories if route.startswith('/v2/'+r+'/')]
                assert len(matches)==1
                repository=matches[0]
                assert method=='GET' and headers['Authorization']=='Bearer '+access_tokens[repository] and body is None
                prefix='/v2/'+repository+'/'
                assert route.startswith(prefix)
                category,digest=route[len(prefix):].split('/',1)
                if category=='manifests':
                    assert digest==img.target['digest'];operation='manifest';response=Response(img.manifest_raw)
                else:
                    assert category=='blobs' and digest in blobs
                    operation='config_blob' if digest==source._sha(img.config_raw) else 'layer_blob'
                    response=Response(b'',307,{'Location':'https://'+DATA_HOST+'/native/blob/'+digest[7:]+'?sig=synthetic'}) if redirect else Response(blobs[digest])
            trace.calls.append((method,self.host,route,operation))
            selected=overrides.get(operation,response)
            self.response=selected() if callable(selected) else selected
            trace.responses.append(self.response)
        def getresponse(self):return self.response
        def close(self):self.closed=True
    monkeypatch.setattr(azure,'AzureTransportExposure',Transport);monkeypatch.setattr(source.http.client,'HTTPSConnection',Connection)
    monkeypatch.setattr(stream,'_PublicPinnedHTTPSConnection',Connection)
    trace.req=req;trace.img=img
    return (engine.collect_snapshot(req) if collect else req),trace


def findings(snapshot):return engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']

def index_of(snapshot):
    c=next(c for c in snapshot['collections'] if c['type']==source.KIND)
    return c['items'][0],{'context':{'provider':'azure','scope':c['scope'],'metadata':snapshot['metadata']},'collections':{source.KIND:[c]}}


@pytest.mark.parametrize('positive',[None,'manifest','config','layer'])
@pytest.mark.parametrize('redirect',[False,True])
@pytest.mark.parametrize('compressed',[False,True])
def test_native_end_to_end_hidden_dual_scan(monkeypatch,positive,redirect,compressed):
    img=image(positive=positive,compressed=compressed)
    snapshot,trace=capture(monkeypatch,img=img,redirect=redirect)
    result=findings(snapshot);status='FAIL' if positive else 'PASS'
    assert len(result)==1 and result[0]['status']==status,result
    assert checks.evaluate(*index_of(snapshot))[0]==status
    assert len(trace.calls)==(8 if redirect else 6) and len(trace.scans)==10
    exported=json.dumps([snapshot,result])
    assert all(value not in exported for value in (TOKEN,REGISTRY,HOST,REPO,'application/config.txt',*trace.credentials))
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)


@pytest.mark.parametrize('positive',[None,'manifest','config','layer'])
def test_real_both_scanners(monkeypatch,positive):
    require_pinned_scanners()
    snapshot,trace=capture(monkeypatch,img=image(positive=positive),redirect=True,real=True)
    result=findings(snapshot)
    assert len(result)==1 and result[0]['status']==('FAIL' if positive else 'PASS'),result
    _,evidence=checks.evaluate(*index_of(snapshot))
    assert [p['part'] for p in evidence['parts']]==[
        'manifest','config','layer-1.member-1.name','layer-1.member-1.chunk-1']
    assert all({(e['engine'],e['version'],e['status']) for e in p['engines']}=={
        ('kingfisher','1.4.0','complete'),('trufflehog','3.92.5','complete')} for p in evidence['parts'])
    if positive:assert {d['engine'] for d in result[0]['evidence']['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}
    assert TOKEN not in json.dumps([snapshot,result])


@pytest.mark.parametrize('removed', ['name', 'chunk-1'])
def test_missing_file_scan_receipt_cannot_produce_clean_leaf(monkeypatch,removed):
    snapshot,_=capture(monkeypatch)
    item,_=index_of(snapshot)
    marker=item[source.MARKER]
    marker['parts']=[p for p in marker['parts']
        if p['part']!='layer-1.member-1.'+removed]
    assert checks.evaluate(*index_of(snapshot))[0]=='UNKNOWN'


def test_explicit_empty_file_retains_both_name_and_content_receipts(monkeypatch):
    snapshot,_=capture(monkeypatch,img=image(files=[('empty.txt',b'')]))
    status,evidence=checks.evaluate(*index_of(snapshot))
    assert status=='PASS'
    assert evidence['parts'][-1]['part']=='layer-1.member-1.chunk-1'
    assert evidence['parts'][-1]['bytes']==0


@pytest.mark.parametrize('operation',['registry_identity','oauth_exchange','oauth_pull','manifest','config_blob','layer_blob','blob_data'])
@pytest.mark.parametrize('code',[201,206,301,307,401,403,404,410,429,500])
def test_native_denied_partial_redirect_error_redaction(monkeypatch,operation,code):
    response=Response({'errors':[{'message':TOKEN}]},code,{'Location':'https://attacker.invalid/'+TOKEN} if code in (301,307) else {})
    snapshot,trace=capture(monkeypatch,redirect=operation=='blob_data',overrides={operation:response})
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert TOKEN not in json.dumps(snapshot) and all(r.closed for r in trace.responses)


@pytest.mark.parametrize('mutate',[
    lambda n:n.update(id=REGISTRY.replace(SCOPE,OTHER)),lambda n:n.update(name='foreignregistry'),
    lambda n:n.update(type='Microsoft.Web/sites'),lambda n:n.pop('properties'),
    lambda n:n['properties'].update(loginServer='attacker.invalid'),
    lambda n:n['properties'].update(loginServer='foreignregistry.azurecr.io'),
    lambda n:n['properties'].update(loginServer=HOST+'.attacker.invalid'),
    lambda n:n['properties'].update(loginServer='https://'+HOST),
    lambda n:n['properties'].update(loginServer=HOST+':443'),
    lambda n:n['properties'].update(provisioningState='Creating'),
    lambda n:n['properties'].update(roleAssignmentMode='unknown'),
    lambda n:n['properties'].update(policies={}),
    lambda n:n['properties']['policies']['azureADAuthenticationAsArmPolicy'].update(status='disabled'),
    lambda n:n['properties'].update(dataEndpointHostNames=['foreign.eastus.data.azurecr.io']),
    lambda n:n['properties'].update(dataEndpointHostNames=[DATA_HOST,DATA_HOST]),
])
def test_native_registry_identity_host_and_policy_before_exchange(monkeypatch,mutate):
    _,trace=capture(monkeypatch,collect=False)
    # Build the exact authoritative response independently.
    n={'id':REGISTRY,'name':'reviewregistry','type':'Microsoft.ContainerRegistry/registries','properties':{
        'loginServer':HOST,'provisioningState':'Succeeded','roleAssignmentMode':'LegacyRegistryPermissions',
        'policies':{'azureADAuthenticationAsArmPolicy':{'status':'enabled'}},'dataEndpointEnabled':True,'dataEndpointHostNames':[DATA_HOST]}}
    mutate(n);snapshot,trace=capture(monkeypatch,native=n)
    assert findings(snapshot)[0]['status']=='UNKNOWN' and len(trace.calls)==1 and not trace.scans


@pytest.mark.parametrize('location',[
    'https://attacker.invalid/blob','https://127.0.0.1/blob','http://'+DATA_HOST+'/blob',
    'https://'+DATA_HOST+':443/blob','https://user@'+DATA_HOST+'/blob',
    'https://'+DATA_HOST+'.attacker.invalid/blob','https://'+DATA_HOST+'/../blob',
    'https://'+DATA_HOST+'/%2e%2e/blob','https://'+DATA_HOST+'/blob#fragment',
    'https://random.blob.core.windows.net/container/blob?sig=signed',
    'https://'+DATA_HOST+'/blob\r\nHeader: true',
])
def test_redirect_ssrf_not_followed(monkeypatch,location):
    snapshot,trace=capture(monkeypatch,overrides={'layer_blob':Response(b'',307,{'Location':location})})
    assert findings(snapshot)[0]['status']=='UNKNOWN'
    assert all(host!=DATA_HOST for _,host,_,_ in trace.calls)
    assert location not in json.dumps(snapshot)


@pytest.mark.parametrize('claims',[{'exp':1},{'nbf':9999999999},{'aud':'foreign.azurecr.io'},
    {'access':[{'type':'repository','name':REPO,'actions':['pull','push']}]},
    {'access':[{'type':'repository','name':'foreign','actions':['pull']}]}, {'access':[]}])
def test_expired_foreign_or_overbroad_access_token_unknown(monkeypatch,claims):
    snapshot,trace=capture(monkeypatch,access_claims=claims)
    assert findings(snapshot)[0]['status']=='UNKNOWN'
    assert len(trace.calls)==3 and not trace.scans


@pytest.mark.parametrize('kind',['refresh','arm'])
def test_expired_refresh_or_arm_token_unknown(monkeypatch,kind):
    snapshot,trace=capture(monkeypatch,**{kind+'_claims':{'exp':1}})
    assert findings(snapshot)[0]['status']=='UNKNOWN' and not trace.scans
    assert len(trace.calls)==(2 if kind=='refresh' else 0)


@pytest.mark.parametrize('operation',['manifest','config_blob','layer_blob','blob_data'])
def test_digest_mismatch_never_clean(monkeypatch,operation):
    snapshot,trace=capture(monkeypatch,redirect=operation=='blob_data',overrides={operation:Response(b'altered '+TOKEN.encode())})
    assert findings(snapshot)[0]['status']=='UNKNOWN' and TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('mutation',[
    lambda m:m.update(mediaType='application/vnd.oci.image.index.v1+json',manifests=[]),
    lambda m:m.update(schemaVersion=1),lambda m:m.update(layers=[]),
    lambda m:m['layers'].append(deepcopy(m['layers'][0])),
    lambda m:m['layers'][0].update(urls=['https://attacker.invalid/foreign']),
    lambda m:m['layers'][0].update(mediaType='application/vnd.docker.image.rootfs.foreign.diff.tar.gzip'),
    lambda m:m['layers'][0].update(size=source.MAX_LAYER+1),
    lambda m:m['config'].update(size=True),
])
def test_multiarch_foreign_duplicate_unsupported_manifests_unknown(monkeypatch,mutation):
    img=image();mutation(img.manifest);img.manifest_raw=packed(img.manifest);img.target['digest']=source._sha(img.manifest_raw)
    snapshot,trace=capture(monkeypatch,img=img)
    assert findings(snapshot)[0]['status']=='UNKNOWN'
    # An OCI index is inspected before child discovery. An empty or malformed
    # index still cannot authorize a child/config/layer read or a clean result.
    if img.manifest.get('mediaType')=='application/vnd.oci.image.index.v1+json':
        assert len(trace.scans)==2 and all(call[1].endswith('.index') for call in trace.scans)
    else:
        assert not trace.scans


@pytest.mark.parametrize('config',[
    {'os':'windows'}, {'architecture':'unsupported'}, {'rootfs':{'type':'layers','diff_ids':['sha256:'+'0'*64]}},
    {'rootfs':{'type':'layers','diff_ids':[]}},
])
def test_rootfs_and_config_native_digest_identity_unknown(monkeypatch,config):
    img=image();img.config.update(config);img.config_raw=packed(img.config)
    img.manifest['config'].update(size=len(img.config_raw),digest=source._sha(img.config_raw))
    img.manifest_raw=packed(img.manifest);img.target['digest']=source._sha(img.manifest_raw)
    snapshot,trace=capture(monkeypatch,img=img)
    assert findings(snapshot)[0]['status']=='UNKNOWN'


@pytest.mark.parametrize('shape',['symlink','traversal','duplicate','nested','truncated','extra','gzip_extra'])
def test_unsafe_archive_and_partial_members_unknown_no_extraction(monkeypatch,shape):
    img=image()
    if shape=='symlink':
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as a:
            m=tarfile.TarInfo('link');m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';a.addfile(m)
        raw=out.getvalue()
    elif shape=='traversal':raw=image(names=['../escape']).layer
    elif shape=='duplicate':raw=image(names=['same','same']).layer
    elif shape=='nested':raw=image(files=[('nested.zip',b'PK\x03\x04'+b'x'*10)]).layer
    elif shape=='truncated':raw=img.layer[:600]
    elif shape=='extra':raw=img.layer+b'nonzero'
    else:raw=img.layer
    img.layer=raw;img.wire=gzip.compress(raw)+gzip.compress(b'other') if shape=='gzip_extra' else raw
    img.config['rootfs']['diff_ids']=[source._sha(raw)];img.config_raw=packed(img.config)
    img.manifest['config'].update(size=len(img.config_raw),digest=source._sha(img.config_raw))
    img.manifest['layers'][0].update(size=len(img.wire),digest=source._sha(img.wire),mediaType='application/vnd.oci.image.layer.v1.tar+gzip' if shape=='gzip_extra' else 'application/vnd.oci.image.layer.v1.tar')
    img.manifest_raw=packed(img.manifest);img.target['digest']=source._sha(img.manifest_raw)
    snapshot,_=capture(monkeypatch,img=img)
    assert findings(snapshot)[0]['status']=='UNKNOWN'


@pytest.mark.parametrize('targets',[None,[],{},'image',[{}],[{'registry_id':REGISTRY,'repository':REPO,'digest':'latest'}],
    [{'registry_id':REGISTRY.replace(SCOPE,OTHER),'repository':REPO,'digest':'sha256:'+'0'*64}],
    [{'registry_id':REGISTRY,'repository':'../foreign','digest':'sha256:'+'0'*64}],
    [{'registry_id':REGISTRY,'repository':'image?query','digest':'sha256:'+'0'*64}],
    [{'registry_id':REGISTRY,'repository':REPO,'digest':'sha256:'+'0'*64,'url':'https://attacker.invalid'}]])
def test_invalid_selection_before_auth(monkeypatch,targets):
    req=request([image().target]);req['connector']['options'][source.OPTION]=targets
    def blocked(*a,**k):pytest.fail('invalid selector reached auth')
    monkeypatch.setattr(azure,'AzureTransportExposure',blocked)
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('scopes',[[],['*'],[OTHER],[SCOPE,SCOPE.upper()]])
def test_foreign_wildcard_duplicate_scope_rejected(monkeypatch,scopes):
    req=request([image().target]);req['connector']['scopes']=scopes
    with pytest.raises(ValueError):engine._request(req)


@pytest.mark.parametrize('flag',[False,None])
def test_disabled_no_content_reads(monkeypatch,flag):
    req=request([image().target]);req['connector']['options'].pop('content_secret_scans')
    if flag is not None:req['connector']['options']['content_secret_scans']=flag
    snapshot,trace=capture(monkeypatch,req=req)
    assert not trace.calls and not trace.scans and findings(snapshot)[0]['status']=='UNKNOWN'


def test_named_selection_required_and_internal_optin_overwritten(monkeypatch):
    img=image();req=request([img.target]);req.pop('checks');req['categories']=['hardening']
    req['connector']['options'].update(inventories=[source.KIND],_content_secret_scan_kinds=[source.KIND])
    snapshot,trace=capture(monkeypatch,img=img,req=req)
    assert not trace.calls and snapshot['metadata'][source.KIND+'_authorized'] is False
    assert source.KIND not in azure._selected({},None) and source.KIND in engine.BULK_STREAM_TYPES['azure']


@pytest.mark.parametrize('failed',['kingfisher','trufflehog'])
def test_one_engine_absent_never_clean(monkeypatch,failed):
    req,trace=capture(monkeypatch,collect=False)
    def absent(*a,**k):raise ImportError(TOKEN)
    monkeypatch.setattr(scanning,'_scan_'+failed,absent)
    snapshot=engine.collect_snapshot(req)
    assert findings(snapshot)[0]['status']=='UNKNOWN' and TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('field',['MAX_TOTAL','MAX_CALLS','MAX_SECONDS','MAX_EXPANDED','MAX_MEMBERS'])
def test_shared_actual_bounds_unknown(monkeypatch,field):
    # Expanded bytes are enforced by the streaming archive reader, rather
    # than the superseded in-memory reader's identically named constant.
    monkeypatch.setattr(stream.archive if field=='MAX_EXPANDED' else source,field,0)
    snapshot,trace=capture(monkeypatch)
    assert findings(snapshot)[0]['status']=='UNKNOWN'


@pytest.mark.parametrize('headers',[{'Content-Length':'99999999'},{'Content-Length':'0'},{'Content-Encoding':'gzip'},
    {'Docker-Content-Digest':'sha256:'+'0'*64},{'WWW-Authenticate':'Bearer realm="https://attacker.invalid/oauth"'}])
def test_native_stream_headers_and_challenges_unresolved(monkeypatch,headers):
    img=image();snapshot,trace=capture(monkeypatch,img=img,overrides={'manifest':Response(img.manifest_raw,headers=headers)})
    assert findings(snapshot)[0]['status']=='UNKNOWN'


def test_secret_in_archive_path_never_retained_or_given_to_scan_cache(monkeypatch):
    img=image(names=['config/'+TOKEN+'.txt'],positive='layer')
    snapshot,trace=capture(monkeypatch,img=img)
    assert findings(snapshot)[0]['status']=='FAIL'
    assert TOKEN not in json.dumps(snapshot) and TOKEN not in repr(scanning._RESULTS)
    assert all(TOKEN not in path for _,path,_ in trace.scans)


def test_both_real_runner_offline_contract(monkeypatch):
    require_pinned_scanners()
    calls=[];original=scanning._run
    def run(argv,payload,timeout):calls.append(list(argv));return original(argv,payload,timeout)
    monkeypatch.setattr(scanning,'_run',run)
    snapshot,trace=capture(monkeypatch,img=image(positive='layer'),real=True)
    assert findings(snapshot)[0]['status']=='FAIL'
    runs=[a for a in calls if 'stdin' in a];assert runs
    for args in runs:assert {'stdin','--no-verification','--no-update','--no-verification-cache','--force-skip-archives','--fail-on-scan-errors','--concurrency=1'}<=set(args)
    assert all(r.closed for r in trace.responses) and all(c.closed for c in trace.connections)


def test_native_derived_fixture_receipt(monkeypatch,tmp_path):
    require_pinned_scanners()
    cases={}
    for state in ('pass','fail','unknown'):
        with monkeypatch.context() as patch:
            snapshot,_=capture(patch,img=image(positive='layer' if state=='fail' else None),redirect=True,real=True,
                overrides={'layer_blob':Response({},403)} if state=='unknown' else None)
            assert findings(snapshot)[0]['status']==state.upper()
            item,index=index_of(snapshot);cases[state]=deepcopy(item);cases[state+'_index']=deepcopy(index)
    cases.update(index=deepcopy(cases['pass_index']),missing={},malformed={source.MARKER:None})
    (tmp_path/'native-fixtures.json').write_text(json.dumps({source.CHECK:cases},sort_keys=True,indent=2)+'\n')


@pytest.mark.parametrize('mutate',[
    lambda s,i:i[source.MARKER].update(complete=False),
    lambda s,i:i[source.MARKER].update(manifest_digest='sha256:'+'0'*64),
    lambda s,i:i[source.MARKER]['layers_scanned'].clear(),
    lambda s,i:i[source.MARKER]['parts'][0]['engines'].pop(),
    lambda s,i:i[source.MARKER]['parts'][0]['engines'][0].update(version='foreign'),
    lambda s,i:i[source.MARKER]['parts'].pop(),
    lambda s,i:i[source.MARKER].update(regular_files=999),
    lambda s,i:i['_provenance'].update(credential_context_id='foreign'),
    lambda s,i:s['metadata'].update(context_binding='foreign'),
    lambda s,i:s['metadata'][source.KIND+'_receipts'][0].update(bound=False),
    lambda s,i:s['metadata'][source.KIND+'_receipts'][1].update(operation='admin_credentials'),
    lambda s,i:s['metadata'][source.KIND+'_receipts'][2].update(method='GET'),
    lambda s,i:s['metadata'][source.KIND+'_receipts'][3].update(digest='sha256:'+'0'*64),
    lambda s,i:s['metadata'][source.KIND+'_receipts'][-1].update(bytes=1),
    lambda s,i:s['collections'][0].update(status='partial'),
    lambda s,i:s['collections'][0]['items'].append(deepcopy(i)),
    lambda s,i:s['metadata'][source.KIND+'_selection'][SCOPE].append('foreign'),
])
def test_pure_receipt_and_selection_coherence(monkeypatch,mutate):
    snapshot,_=capture(monkeypatch,redirect=True);item,_=index_of(snapshot)
    mutate(snapshot,item)
    assert checks.evaluate(*index_of(snapshot))[0]=='UNKNOWN'


@pytest.mark.parametrize('operation',['oauth_exchange','oauth_pull'])
@pytest.mark.parametrize('payload',[b'not-json',b'{"refresh_token":"duplicate","refresh_token":"duplicate"}',b'{"token":null}',b'{"refresh_token":NaN}',b'\xff'])
def test_malformed_auth_response_never_retained(monkeypatch,operation,payload):
    snapshot,_=capture(monkeypatch,overrides={operation:Response(payload)})
    assert findings(snapshot)[0]['status']=='UNKNOWN'


def test_four_exact_targets_and_duplicate_rejection(monkeypatch):
    t=image().target
    assert len(source.selected_targets({source.OPTION:[dict(t,repository='repo'+str(i)) for i in range(4)]},[SCOPE]))==4
    for targets in ([t,t],[dict(t,registry_id=t['registry_id'].upper()),t],[dict(t,repository='repo'+str(i)) for i in range(5)]):
        with pytest.raises(ValueError):source.selected_targets({source.OPTION:targets},[SCOPE])


def test_abac_mode_native_does_not_claim_effective_access(monkeypatch):
    n={'id':REGISTRY,'name':'reviewregistry','type':'Microsoft.ContainerRegistry/registries','properties':{
        'loginServer':HOST,'provisioningState':'Succeeded','roleAssignmentMode':'AbacRepositoryPermissions',
        'policies':{'azureADAuthenticationAsArmPolicy':{'status':'enabled'}},'dataEndpointEnabled':True,'dataEndpointHostNames':[DATA_HOST]}}
    snapshot,_=capture(monkeypatch,native=n)
    assert findings(snapshot)[0]['status']=='PASS'
    item,_=index_of(snapshot)
    assert item[source.MARKER]['mode']=='AbacRepositoryPermissions'
    assert snapshot['metadata']['authorization_semantics']['effective_access']=='not_computed'


def test_classic_default_storage_redirect_does_not_get_bearer(monkeypatch):
    snapshot,trace=capture(monkeypatch,overrides={'layer_blob':Response(b'',307,{'Location':'https://random.blob.core.windows.net/image?sig=do-not-follow'})})
    assert findings(snapshot)[0]['status']=='UNKNOWN'
    assert len(trace.calls)==6 and all(h!='random.blob.core.windows.net' for _,h,_,_ in trace.calls)
    assert 'do-not-follow' not in json.dumps(snapshot)


def test_same_exact_value_deduplicates_manifest_config_and_layer(monkeypatch):
    img=image(positive='layer');img.config['config']['Env']=['TOKEN='+TOKEN];img.config_raw=packed(img.config)
    img.manifest['config'].update(size=len(img.config_raw),digest=source._sha(img.config_raw));img.manifest['annotations']={'token':TOKEN}
    img.manifest_raw=packed(img.manifest);img.target['digest']=source._sha(img.manifest_raw)
    snapshot,_=capture(monkeypatch,img=img)
    result=findings(snapshot)
    assert len(result)==1 and result[0]['status']=='FAIL'
    leak,=result[0]['evidence']['secret_leaks'];assert len(leak['locations'])==3
    assert {d['engine'] for d in leak['detectors']}=={'kingfisher','trufflehog'}
    assert TOKEN not in json.dumps([snapshot,result])


@pytest.mark.parametrize('positive',[None,'layer'])
def test_four_native_exact_images_deduplicate_or_pass(monkeypatch,positive):
    img=image(positive=positive)
    targets=[dict(img.target,repository=REPO+str(i)) for i in range(4)]
    snapshot,trace=capture(monkeypatch,img=img,req=request(targets),redirect=True)
    result=findings(snapshot)
    assert len(trace.calls)==32
    assert len(result)==(1 if positive else 4)
    assert {f['status'] for f in result}==({'FAIL'} if positive else {'PASS'})
    if positive:assert len(result[0]['evidence']['secret_leaks'][0]['locations'])==4
    assert TOKEN not in json.dumps([snapshot,result])


def test_escaped_json_literals_are_decoded_before_both_engines(monkeypatch):
    img=image();img.config['config']['Env']=['token=first\n'+TOKEN];img.config_raw=packed(img.config)
    img.manifest['config'].update(size=len(img.config_raw),digest=source._sha(img.config_raw));img.manifest_raw=packed(img.manifest);img.target['digest']=source._sha(img.manifest_raw)
    req,_=capture(monkeypatch,img=img,collect=False)
    seen=[]
    def detector(payload,path,timeout):
        seen.append(bytes(payload))
        return [(TOKEN,'github-pat',2)] if b'first\n'+TOKEN.encode() in payload else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detector);monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    snapshot=engine.collect_snapshot(req)
    assert findings(snapshot)[0]['status']=='FAIL'
    assert sum(b'first\n'+TOKEN.encode() in p for p in seen)==2
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('policy',['enabled','disabled'])
def test_fixed_acr_audience_supports_hardened_registries(monkeypatch,policy):
    n={'id':REGISTRY,'name':'reviewregistry','type':'Microsoft.ContainerRegistry/registries','properties':{
        'loginServer':HOST,'provisioningState':'Succeeded','roleAssignmentMode':'AbacRepositoryPermissions',
        'policies':{'azureADAuthenticationAsArmPolicy':{'status':policy}},'dataEndpointEnabled':True,'dataEndpointHostNames':[DATA_HOST]}}
    snapshot,trace=capture(monkeypatch,native=n,acr=True)
    assert findings(snapshot)[0]['status']=='PASS'
    assert trace.tokens==['https://management.azure.com',source.ACR_AUDIENCE]
    assert index_of(snapshot)[0][source.MARKER]['auth_audience']=='acr'


@pytest.mark.parametrize('claims',[{'exp':1},{'aud':'https://attacker.invalid'},{'tid':'33333333-3333-3333-3333-333333333333'}])
def test_acr_audience_foreign_expired_token_never_arm_fallback(monkeypatch,claims):
    snapshot,trace=capture(monkeypatch,acr=True,acr_claims=claims)
    assert findings(snapshot)[0]['status']=='UNKNOWN' and len(trace.calls)==1
    assert all(op not in ('oauth_exchange','oauth_pull') for _,_,_,op in trace.calls)


def test_acr_missing_sdk_credential_hardened_registry_stays_unknown(monkeypatch):
    n={'id':REGISTRY,'name':'reviewregistry','type':'Microsoft.ContainerRegistry/registries','properties':{
        'loginServer':HOST,'provisioningState':'Succeeded','roleAssignmentMode':'LegacyRegistryPermissions',
        'policies':{'azureADAuthenticationAsArmPolicy':{'status':'disabled'}},'dataEndpointEnabled':False,'dataEndpointHostNames':[]}}
    snapshot,trace=capture(monkeypatch,native=n,acr=False)
    assert findings(snapshot)[0]['status']=='UNKNOWN' and len(trace.calls)==1


def test_native_dns_case_alias_is_bound_without_foreign_identity(monkeypatch):
    n={'id':REGISTRY.upper(),'name':'ReviewRegistry','type':'Microsoft.ContainerRegistry/registries','properties':{
        'loginServer':HOST.upper(),'provisioningState':'Succeeded','roleAssignmentMode':'LegacyRegistryPermissions',
        'policies':{'azureADAuthenticationAsArmPolicy':{'status':'enabled'}},'dataEndpointEnabled':True,'dataEndpointHostNames':[DATA_HOST.upper()]}}
    snapshot,trace=capture(monkeypatch,native=n,redirect=True,acr=True)
    assert findings(snapshot)[0]['status']=='PASS'
    assert all(host in ('management.azure.com',HOST,DATA_HOST) for _,host,_,_ in trace.calls)


def test_registered_real_native_cases_and_exact_admission_sources():
    import hashlib
    import inspect
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    check,=[c for c in CHECKS if c.id==source.CHECK]
    assert check.kind==source.KIND and check.dependencies==[source.KIND] and check.severity=='high'
    assert checks.DECLARATIONS[0]['requirements']==[] and checks.DECLARATIONS[0]['finding_type']=='secrets'
    from tests.azure_native_successor_inputs_20261020 import current_cases
    cases=current_cases(source.CHECK,CASES[source.CHECK])
    for state in ('pass','fail','unknown'):assert check.evaluate(cases[state],cases[state+'_index'])[0]==state.upper()
    for shape in ('missing','malformed'):assert check.evaluate(cases[shape],cases['index'])[0]=='UNKNOWN'
    a=json.loads(Path('peaso/checks/azure_acr_image_secret_review_20261020_admission.json').read_text())
    for p,h in a['source_hashes'].items():assert_source_receipt(p,h)
    assert hashlib.sha256(Path(a['fixture']['path']).read_bytes()).hexdigest()==a['fixture']['sha256']
    from peaso import private_secret_source_epoch_20261021 as epoch
    relative='peaso/checks/azure_acr_image_secret_review_20261020.py'
    native_transition=epoch._receipt()[0]['current_reviewed_files'][relative]
    previous=epoch.predecessor_bytes(relative,Path(relative).read_bytes(),
        native_transition['predecessor_sha256'],Path.cwd())
    import ast
    node=next(n for n in ast.parse(previous).body if isinstance(n,ast.FunctionDef) and n.name=='evaluate')
    previous_function=b''.join(previous.splitlines(keepends=True)[node.lineno-1:node.end_lineno]).decode()
    assert a['checks'][source.CHECK]['predicate_sha256']==hashlib.sha256(previous_function.encode()).hexdigest()


def test_native_acr_and_app_settings_exact_value_dedup(monkeypatch):
    from tests import test_azure_app_settings_secret_review_20261020 as app
    from peaso.secret_findings import deduplicate_secret_findings
    with monkeypatch.context() as patch:
        snapshot,_=capture(patch,img=image(positive='layer'))
        acr_findings=findings(snapshot)
    with monkeypatch.context() as patch:
        snapshot,_=app.capture(patch,data={app.SITE:app.native(values={'Token':app.TOKEN})})
        app_findings=app.findings(snapshot)
    assert {r['status'] for r in acr_findings+app_findings}=={'FAIL'}
    merged=deduplicate_secret_findings(acr_findings+app_findings)
    assert len(merged)==1 and set(merged[0]['linked_check_ids'])=={source.CHECK,app.source.CHECK}
    assert len(merged[0]['evidence']['secret_leaks'][0]['locations'])==2
    assert TOKEN not in json.dumps(merged)
