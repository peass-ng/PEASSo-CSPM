"""Synthetic OCI bytes and streaming native-registry HTTP; never a live image."""
import base64
from copy import deepcopy
import gzip
from importlib.metadata import version
import io
import json
from threading import RLock
from types import SimpleNamespace
import tarfile
from urllib.parse import quote

import pytest
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings
from peaso.collectors import gcp_image_secret_indicators as projection
from peaso.checks import gcp_image_secret_review_20261019 as check

SCOPE = 'projects/review'
REPO = SCOPE + '/locations/us-central1/repositories/images'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
REPOSITORIES = [{'name': REPO, 'format': 'DOCKER'}]
PROJECTS = [{'name': 'projects/123456789', 'projectId': 'review'}]


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def tar_bytes(value, *, name='app/config.txt', link=False, nested=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        raw = b'PK\x03\x04nested' if nested else ('github_token=' + value + '\ncopy=' + value).encode()
        member = tarfile.TarInfo(name)
        member.size = 0 if link else len(raw)
        if link: member.type, member.linkname = tarfile.SYMTYPE, 'outside'
        archive.addfile(member, None if link else io.BytesIO(raw))
    return output.getvalue()


def image(value='production', *, compressed=True, docker=False, layers=2, **tar_options):
    diff_raw = [tar_bytes(value, **{'name':'app/config'+str(i)+'.txt', **tar_options}) for i in range(layers)]
    layer_raw = [gzip.compress(raw, mtime=0) if compressed else raw for raw in diff_raw]
    config = {'architecture': 'amd64', 'os': 'linux', 'config': {'Env': ['SETTING='+value]},
              'history': [{'created_by': 'setting='+value}], 'rootfs': {'type': 'layers', 'diff_ids': [projection._sha(raw) for raw in diff_raw]}}
    config_raw = encoded(config)
    manifest = {'schemaVersion': 2, 'mediaType': projection.DOCKER if docker else projection.OCI,
        'config': {'mediaType': 'application/vnd.docker.container.image.v1+json' if docker else 'application/vnd.oci.image.config.v1+json',
                   'digest': projection._sha(config_raw), 'size': len(config_raw)},
        'layers': [{'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip' if docker else 'application/vnd.oci.image.layer.v1.tar'+('+gzip' if compressed else ''),
                    'digest': projection._sha(raw), 'size': len(raw)} for raw in layer_raw]}
    return package(manifest, {projection._sha(raw): raw for raw in [config_raw]+layer_raw})


def package(manifest, blobs):
    raw = encoded(manifest);digest = projection._sha(raw)
    bare = 'us-central1-docker.pkg.dev/review/images/app@'+digest
    row = {'name': REPO+'/dockerImages/'+quote('app@'+digest, safe=''), 'uri': 'https://'+bare, 'digest':digest,'repository':REPO}
    responses = {'https://us-central1-docker.pkg.dev/v2/review/images/app/manifests/'+digest: raw}
    responses.update({'https://us-central1-docker.pkg.dev/v2/review/images/app/blobs/'+d: value for d,value in blobs.items()})
    return row, responses


class Session:
    def __init__(self, bodies, *, status=200, redirect=False, challenge=False, truncated=False):
        self.bodies=bodies;self.calls=[];self.closed=False
        self.status,self.redirect,self.challenge,self.truncated=status,redirect,challenge,truncated
    def request(self, method, url, **kwargs):
        assert method=='GET' and kwargs['allow_redirects'] is False and kwargs['stream'] is True
        assert url.startswith('https://us-central1-docker.pkg.dev/v2/review/images/app/')
        auth=kwargs['headers']['Authorization'];assert auth.startswith('Basic ')
        assert base64.b64decode(auth[6:])==b'oauth2accesstoken:fixture-access-token'
        self.calls.append(url)
        raw=self.bodies.get(url,b'')
        session=self
        class Response:
            status_code=session.status
            history=[]
            headers={'Content-Length':str(len(raw)), **({'WWW-Authenticate':'Bearer realm="https://external.invalid/token"'} if session.challenge else {})}
            def iter_content(self, chunk_size):
                body=raw[:-1] if session.truncated else raw
                for start in range(0,len(body),17): yield body[start:start+17]
            def close(self): pass
        response=Response();response.url='https://external.invalid/blob' if self.redirect else url
        return response
    def close(self): self.closed=True


def transport(cancel=None, max_calls=None):
    return SimpleNamespace(lock=RLock(),calls=0,max_calls=max_calls,timeout=10,
        credentials=SimpleNamespace(headers=lambda:{'Authorization':'Bearer fixture-access-token'}),
        check_cancelled=cancel or (lambda:None))


def run(value='production', **kwargs):
    row,bodies=image(value,**kwargs);session=Session(bodies);reader=projection.Reader(transport(),session=session)
    row[projection.MARKER]=projection.inspect_image(row,SCOPE,REPOSITORIES,PROJECTS,reader)
    return row,session,reader


def index(row, image_status='collected'):
    return {'context':{'provider':'gcp','scope':SCOPE},'collections':{
        'artifact_image':[{'scope':SCOPE,'status':image_status,'items':[row]}],
        'artifact_repository':[{'scope':SCOPE,'status':'collected','items':deepcopy(REPOSITORIES)}],
        'project':[{'scope':SCOPE,'status':'collected','items':deepcopy(PROJECTS)}]}}


@pytest.fixture(autouse=True)
def isolate():
    scanning._RESULTS.clear();yield;scanning._RESULTS.clear()


@pytest.fixture(scope='module')
def real():
    pytest.importorskip('kingfisher_sdk');assert version('kingfisher-secret-scanner')==scanning.KINGFISHER_VERSION
    assert scanning._trufflehog()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning,'_scan_kingfisher',lambda *a:[])
    monkeypatch.setattr(scanning,'_scan_trufflehog',lambda *a:[])


@pytest.mark.parametrize('value,status',[('production','PASS'),(TOKEN,'FAIL')])
@pytest.mark.parametrize('docker,compressed',[(False,False),(False,True),(True,True)])
def test_real_dual_detectors_scan_config_and_all_supported_layers(real,value,status,docker,compressed,capsys):
    row,session,reader=run(value,docker=docker,compressed=compressed)
    verdict,evidence=check.evaluate(row,index(row));assert verdict==status,row
    assert len(session.calls)==4 and reader.calls==4
    assert evidence['layers_scanned']==2 and evidence['regular_files']==2
    if status=='FAIL':
        assert len(evidence['secret_leaks'])==1
        leak=evidence['secret_leaks'][0]
        assert {d['engine'] for d in leak['detectors']}=={'kingfisher','trufflehog'}
        assert len({loc['layer'] for loc in leak['locations']})==3
        base={'provider':'gcp','scope':SCOPE,'resource_id':row['uri'],'native_resource_id':row['uri'],
              'resource_type':'artifact_image','check_id':projection.CHECK_ID,'status':verdict,'frameworks':[],'evidence':evidence}
        assert len(deduplicate_secret_findings([base,deepcopy(base)]))==1
    assert TOKEN not in json.dumps([row,evidence])+repr(scanning._RESULTS)+str(capsys.readouterr())
    assert 'fixture-access-token' not in json.dumps([row,evidence])


@pytest.mark.parametrize('case',['manifest_hash','config_hash','layer_hash','descriptor_size','rootfs','index','missing_layers','foreign_layer','config_platform','oversized_descriptor','annotations'])
def test_descriptor_identity_platform_and_manifest_fail_closed(clean,case):
    row,bodies=image()
    manifest_url=next(k for k in bodies if '/manifests/' in k)
    manifest=json.loads(bodies[manifest_url]);blobs={k.rsplit('/',1)[1]:v for k,v in bodies.items() if '/blobs/' in k}
    if case=='manifest_hash': bodies[manifest_url]+=b' '
    elif case=='config_hash': bodies[next(k for k in bodies if k.endswith(manifest['config']['digest']))]+=b'changed'
    elif case=='layer_hash': bodies[next(k for k in bodies if k.endswith(manifest['layers'][0]['digest']))]+=b'changed'
    else:
        if case=='descriptor_size':manifest['layers'][0]['size']+=1
        if case=='rootfs':
            config=json.loads(blobs[manifest['config']['digest']]);config['rootfs']['diff_ids'][0]='sha256:'+'0'*64
            config_raw=encoded(config);blobs[projection._sha(config_raw)]=config_raw;manifest['config'].update(digest=projection._sha(config_raw),size=len(config_raw))
        if case=='index':manifest={'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[]}
        if case=='missing_layers':manifest['layers']=[]
        if case=='foreign_layer':manifest['layers'][0]['urls']=['https://external.invalid/blob']
        if case=='config_platform':
            config=json.loads(blobs[manifest['config']['digest']]);config['architecture']='unsupported'
            raw=encoded(config);blobs[projection._sha(raw)]=raw;manifest['config'].update(digest=projection._sha(raw),size=len(raw))
        if case=='oversized_descriptor':manifest['layers'][0]['size']=projection.MAX_LAYER+1
        if case=='annotations':manifest['config']['annotations']={'private':TOKEN}
        row,bodies=package(manifest,blobs)
    reader=projection.Reader(transport(),session=Session(bodies));row[projection.MARKER]=projection.inspect_image(row,SCOPE,REPOSITORIES,PROJECTS,reader)
    assert check.evaluate(row,index(row))[0]==('PASS' if case=='annotations' else 'UNKNOWN')
    assert TOKEN not in json.dumps(row)


@pytest.mark.parametrize('case',['denied','redirect','challenge','truncated','calls','cancel','deadline'])
def test_stream_http_failures_and_budgets_are_unknown(clean,monkeypatch,case):
    row,bodies=image();session=Session(bodies,status=403 if case=='denied' else 200,redirect=case=='redirect',challenge=case=='challenge',truncated=case=='truncated')
    def cancel():raise RuntimeError(TOKEN)
    if case=='deadline':monkeypatch.setattr(projection,'MAX_SECONDS',0)
    reader=projection.Reader(transport(cancel if case=='cancel' else None,max_calls=2 if case=='calls' else None),session=session)
    row[projection.MARKER]=projection.inspect_image(row,SCOPE,REPOSITORIES,PROJECTS,reader)
    assert check.evaluate(row,index(row))[0]=='UNKNOWN'
    assert len(session.calls)<=2 if case=='calls' else len(session.calls)<=1
    assert TOKEN not in json.dumps(row)


@pytest.mark.parametrize('case',['link','nested','traversal','expanded','members'])
def test_unsupported_archives_and_layer_limits_are_unknown(clean,monkeypatch,case):
    options={'link':case=='link','nested':case=='nested'}
    if case=='traversal':options['name']='../outside'
    if case=='expanded':monkeypatch.setattr(projection,'MAX_EXPANDED',1)
    if case=='members':monkeypatch.setattr(projection,'MAX_MEMBERS',1)
    row,bodies=image(**options);reader=projection.Reader(transport(),session=Session(bodies))
    row[projection.MARKER]=projection.inspect_image(row,SCOPE,REPOSITORIES,PROJECTS,reader)
    assert check.evaluate(row,index(row))[0]=='UNKNOWN'


@pytest.mark.parametrize('engine',['kingfisher','trufflehog'])
def test_tool_failure_is_unknown(clean,monkeypatch,engine):
    def fail(*args):raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning,'_scan_'+engine,fail)
    row,_,_=run();assert check.evaluate(row,index(row))[0]=='UNKNOWN';assert TOKEN not in json.dumps(row)


def collector(row,**options):
    return SimpleNamespace(scopes=[SCOPE],options={'content_secret_scans':True,'_content_secret_scan_kinds':['artifact_image'],
        'selected_artifact_images':[row['uri'].removeprefix('https://')],**options},transport=transport(),collections={
            ('artifact_image',SCOPE):{'scope':SCOPE,'status':'collected','items':[row]},
            ('artifact_repository',SCOPE):{'scope':SCOPE,'status':'collected','items':deepcopy(REPOSITORIES)},
            ('project',SCOPE):{'scope':SCOPE,'status':'collected','items':deepcopy(PROJECTS)}})


@pytest.mark.parametrize('case',['disabled','unselected','truthy','missing_selection','foreign_selection','tag_selection','foreign_repository','missing_project'])
def test_opt_in_named_selection_native_binding_gate_zero_extra_calls(case):
    row,_=image();c=collector(row)
    if case=='disabled':c.options['content_secret_scans']=False
    if case=='unselected':c.options['_content_secret_scan_kinds']=[]
    if case=='truthy':c.options['content_secret_scans']='true'
    if case=='missing_selection':del c.options['selected_artifact_images']
    if case=='foreign_selection':c.options['selected_artifact_images']=['external.invalid/review/images/app@'+row['digest']]
    if case=='tag_selection':c.options['selected_artifact_images']=['us-central1-docker.pkg.dev/review/images/app:latest']
    if case=='foreign_repository':row['repository']=REPO+'-foreign'
    if case=='missing_project':c.collections[('project',SCOPE)]['items']=[]
    projection.enrich(c,reader_factory=lambda *a:pytest.fail('unbound/default inspection created reader'))
    assert c.transport.calls==0


def test_selected_native_enrichment_returns_only_safe_marker(real):
    row,bodies=image(TOKEN);c=collector(row);session=Session(bodies)
    projection.enrich(c,reader_factory=lambda t:projection.Reader(t,session=session))
    assert session.closed and len(session.calls)==4
    assert check.evaluate(row,index(row))[0]=='FAIL'
    assert TOKEN not in json.dumps(list(c.collections.values()))


@pytest.mark.parametrize('case',['native_digest','repository','project_duplicate','parent_denied','marker_identity','marker_missing_layer'])
def test_native_parent_and_marker_mismatches_are_unknown(clean,case):
    row,_,_=run();idx=index(row)
    if case=='native_digest':row['digest']='sha256:'+'0'*64
    if case=='repository':idx['collections']['artifact_repository'][0]['items'][0]['name']+='-foreign'
    if case=='project_duplicate':idx['collections']['project'][0]['items']*=2
    if case=='parent_denied':idx['collections']['project'][0]['status']='denied'
    if case=='marker_identity':row[projection.MARKER]['uri']+='foreign'
    if case=='marker_missing_layer':row[projection.MARKER]['layers_scanned'].pop()
    assert check.evaluate(row,idx)[0]=='UNKNOWN'


@pytest.mark.parametrize('value',['https://us-central1-docker.pkg.dev/review/images/app@sha256:'+'1'*64,
    'mirror.gcr.io/review/app@sha256:'+'1'*64,'us-central1-docker.pkg.dev/foreign/images/app@sha256:'+'1'*64,
    'us-central1-docker.pkg.dev/review/images/../app@sha256:'+'1'*64,
    'us-central1-docker.pkg.dev:443/review/images/app@sha256:'+'1'*64])
def test_selection_is_exact_immutable_native_host_project_path(value):
    with pytest.raises(ValueError):projection.normalize_selected([value],SCOPE)


def test_actual_collector_metadata_to_selected_stream_enrichment_pipeline(real,monkeypatch):
    import inspect
    from peaso.collectors import gcp
    row,bodies=image(TOKEN);binary_session=Session(bodies)
    # The collector routes selected images through the streaming inspector, so
    # bind its reader to the fixture session; never reach a live registry.
    from peaso.collectors import gcp_image_stream_inspection_20261021 as stream_inspection
    original_reader=stream_inspection.Reader
    monkeypatch.setattr(stream_inspection,'Reader',lambda t:original_reader(t,session=binary_session))
    namespace = {'GCPCollector': gcp.GCPCollector}
    calls=[]
    class Response:
        status_code=200
        def __init__(self,data):self.data=data; self.content = json.dumps(data).encode()
        def json(self):return deepcopy(self.data)
    def request(method,url,**kwargs):
        assert method=='GET';calls.append(url)
        if url=='https://cloudresourcemanager.googleapis.com/v3/'+SCOPE:
            return Response({'name':'projects/123456789','projectId':'review','state':'ACTIVE'})
        if url=='https://compute.googleapis.com/compute/v1/'+SCOPE:return Response({'name':'review','commonInstanceMetadata':{'items':[]}})
        if url=='https://artifactregistry.googleapis.com/v1/'+SCOPE+'/locations/us-central1/repositories':return Response({'repositories':deepcopy(REPOSITORIES)})
        if url=='https://artifactregistry.googleapis.com/v1/'+REPO+'/dockerImages':return Response({'dockerImages':[{'name':row['name'],'uri':row['uri'].removeprefix('https://')}]})
        if url.endswith(':getIamPolicy'):return Response({'bindings':[]})
        pytest.fail('unexpected native metadata request '+url)
    options={'content_secret_scans':True,'_content_secret_scan_kinds':['artifact_image'],'selected_artifact_images':[row['uri'].removeprefix('https://')],
             'inventories':['artifact_image','artifact_repository','project'],'artifactregistry_locations':['us-central1'],'include_inherited':False,'metrics_scopes':False,'concurrency':1}
    native=gcp.Transport(SimpleNamespace(headers=lambda:{'Authorization':'Bearer fixture-access-token'},close=lambda:None),options)
    monkeypatch.setattr(native,'_session',lambda:SimpleNamespace(request=request,close=lambda:None))
    collector=namespace['GCPCollector']({'provider':'gcp','scopes':[SCOPE],'options':options},requirements=['artifact_image','artifact_repository','project'],transport=native)
    snapshot=collector.collect();image_envelope=next(e for e in snapshot['collections'] if e['type']=='artifact_image')
    item,=image_envelope['items'];idx={'context':{'provider':'gcp','scope':SCOPE},'collections':{kind:[e for e in snapshot['collections'] if e['type']==kind] for kind in ['artifact_image','artifact_repository','project']}}
    assert check.evaluate(item,idx)[0]=='FAIL',snapshot
    assert len(binary_session.calls)==4 and binary_session.closed
    assert len(calls)<=5
    receipts=[r for r in snapshot['metadata']['source_requests'] if r.get('operation')=='artifactregistry.registry_content_get']
    assert len(receipts)==4 and all(r['status']=='collected' for r in receipts)
    request_ids={r['id'] for r in receipts}
    assert request_ids <= set(item['_provenance']['source_requests'])
    assert request_ids <= set(image_envelope['source_requests'])
    assert all(set(r) <= {'id','method','operation','category','digest','scope','status','attempts','http_attempts','http_status'} for r in receipts)
    assert TOKEN not in json.dumps(snapshot)+json.dumps(native.evidence)
    assert 'fixture-access-token' not in json.dumps(snapshot) and 'Basic ' not in json.dumps(snapshot)
    assert TOKEN not in json.dumps([entry.get('data') for entry in native.cache.values()])


def test_repository_dot_traversal_cannot_reach_registry_credentials():
    value='us-central1-docker.pkg.dev/review/../app@sha256:'+'1'*64
    with pytest.raises(ValueError):projection.normalize_selected([value],SCOPE)
    t=transport();reader=projection.Reader(t,session=Session({}))
    with pytest.raises(ValueError):reader.get('https://'+value,'manifests','sha256:'+'1'*64,1024)
    assert t.calls==0


@pytest.mark.parametrize('field,value',[('Docker-Content-Digest','sha256:'+'0'*64),('Content-Length','not-numeric'),('Content-Encoding','gzip')])
def test_foreign_headers_and_encoding_are_unknown(clean,field,value):
    row,bodies=image();session=Session(bodies);original=session.request
    def request(*args,**kwargs):
        response=original(*args,**kwargs);response.headers={**response.headers,field:value};return response
    session.request=request;reader=projection.Reader(transport(),session=session)
    row[projection.MARKER]=projection.inspect_image(row,SCOPE,REPOSITORIES,PROJECTS,reader)
    assert check.evaluate(row,index(row))[0]=='UNKNOWN' and len(session.calls)==1


@pytest.mark.parametrize('case',['urls','config_size','layer_size','boolean_size'])
def test_malformed_serialized_descriptor_cannot_be_trusted(clean,case):
    row,_,_=run();descriptors=row[projection.MARKER]['descriptors']
    if case=='urls':descriptors[1]['urls']=['https://external.invalid/blob']
    if case=='config_size':descriptors[0]['size']=projection.MAX_CONFIG+1
    if case=='layer_size':descriptors[1]['size']=projection.MAX_LAYER+1
    if case=='boolean_size':descriptors[1]['size']=True
    assert check.evaluate(row,index(row))[0]=='UNKNOWN'


def test_actual_chunk_limit_applies_without_content_length(clean,monkeypatch):
    row,bodies=image();session=Session(bodies);original=session.request
    def request(*args,**kwargs):
        response=original(*args,**kwargs);response.headers={};return response
    session.request=request;monkeypatch.setattr(projection,'MAX_MANIFEST',64)
    reader=projection.Reader(transport(),session=session)
    row[projection.MARKER]=projection.inspect_image(row,SCOPE,REPOSITORIES,PROJECTS,reader)
    assert check.evaluate(row,index(row))[0]=='UNKNOWN'
    assert len(session.calls)==1 and reader.bytes<=81


def test_different_secret_in_filename_is_never_retained(real):
    other='ghp_'+'2Yt9Ec5Zp0Ru6Wq1Aa8Kd3Vx7Mn4Bs5Hj9Lf'
    row,bodies=image(other,name='app/'+TOKEN+'.txt');reader=projection.Reader(transport(),session=Session(bodies))
    row[projection.MARKER]=projection.inspect_image(row,SCOPE,REPOSITORIES,PROJECTS,reader)
    status,evidence=check.evaluate(row,index(row));assert status=='FAIL'
    assert TOKEN not in json.dumps([row,evidence]) and other not in json.dumps([row,evidence])
    assert TOKEN not in repr(scanning._RESULTS) and other not in repr(scanning._RESULTS)


def test_original_duplicate_paths_rejected_before_pseudonymized_scan(clean,monkeypatch):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for _ in range(2):
            member=tarfile.TarInfo('same.txt');member.size=4;archive.addfile(member,io.BytesIO(b'safe'))
    raw=output.getvalue()
    monkeypatch.setattr(projection,'scan_tar',lambda *a,**k:pytest.fail('duplicate paths reached scanner'))
    with pytest.raises(ValueError):projection._tar(raw,'application/vnd.oci.image.layer.v1.tar',projection._sha(raw))


def test_denied_registry_read_retains_safe_request_provenance(clean):
    row,bodies=image();c=collector(row);session=Session(bodies,status=403)
    projection.enrich(c,reader_factory=lambda t:projection.Reader(t,session=session))
    assert check.evaluate(row,index(row))[0]=='UNKNOWN'
    receipt,=c.transport.evidence
    assert receipt['status']=='denied' and receipt['http_status']==403
    assert receipt['id'] in row['_provenance']['source_requests']
    assert receipt['id'] in c.collections[('artifact_image',SCOPE)]['source_requests']
    assert row['_coverage'][projection.MARKER]['source_requests']==[receipt['id']]
    assert 'fixture-access-token' not in json.dumps([receipt,row]) and 'Basic ' not in json.dumps([receipt,row])
