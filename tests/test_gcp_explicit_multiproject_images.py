"""Exact multi-project image selections remain native-bound and independent."""
import base64
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote
import threading
import pytest
from peaso import checks as _normal_registry
from peaso import gcp_image_selection_20261021 as selection
from peaso.collectors import gcp_registry_trivy_runtime_20261021 as installed_runtime
from peaso.collectors import gcp_registry_trivy_20261021 as registry_native
from peaso.collectors import gcp_image_stream_inspection_20261021 as installed_stream
from peaso.collectors import gcp_image_secret_indicators as secret_native
from peaso.server.config import Settings
from peaso.server import validation as installed_validation
from peaso import trivy_database_20261021 as database
from tests import gcp_job_image_vulnerability_fixture_20261021 as fixture

SCOPES=['projects/project-one','projects/project-two']
DIGEST='sha256:'+'a'*64
REFS=[host+'-docker.pkg.dev/'+scope.split('/')[1]+'/images/'+name+'@'+DIGEST for scope,host in zip(SCOPES,['us-central1','europe-west1']) for name in ['positive','clean']]
@pytest.fixture
def modules():
    from peaso import engine
    return selection, installed_runtime, installed_stream, installed_validation, engine


def options():return {'content_secret_scans':True,'image_vulnerability_scans':True,
 'selected_artifact_images':list(REFS),'selected_gcp_registry_image_vulnerabilities':list(REFS)}

def test_exact_two_project_four_target_validation_across_api_engine_and_grant(modules):
 s,r,stream,v,e=modules;opts=options();original=deepcopy(opts)
 assert s.selections(opts,SCOPES)==REFS
 assert s.grouped_selections(opts,SCOPES)==dict(zip(SCOPES,[REFS[:2],REFS[2:]]))
 v.validate_connector('gcp',{'method':'token','token':'synthetic-token'},opts,Settings(auth_mode='hosted'),scopes=SCOPES)
 request={'connector':{'provider':'gcp','scopes':SCOPES,'auth':{'method':'token','token':'synthetic-token'},'options':opts},
  'categories':['hardening','exposure'],'checks':['gcp.review.artifact_image.content_secret_indicators',r.CHECK_ID]}
 assert e._request(request)['scopes']==SCOPES
 assert opts==original
 r.issue_engine_grant(opts,SCOPES,[r.CHECK_ID]);assert r.prepare(opts,SCOPES,{r.KIND})==REFS
 with pytest.raises(ValueError):r.prepare(opts,SCOPES,{r.KIND})


@pytest.mark.parametrize('bad', ['foreign_project','prefix_project','duplicate_reference','duplicate_scope','discovery','wildcard','folder','https','tag','five_targets'])
def test_foreign_ambiguous_or_unbounded_targets_rejected_without_io(modules,bad):
 s,r,*_=modules;opts=options();scopes=list(SCOPES)
 if bad=='foreign_project':opts[s.OPTION][0]=REFS[0].replace('project-one','project-outside')
 elif bad=='prefix_project':opts[s.OPTION][0]=REFS[0].replace('project-one','project-one-suffix')
 elif bad=='duplicate_reference':opts[s.OPTION][1]=opts[s.OPTION][0]
 elif bad=='duplicate_scope':scopes.append(scopes[0])
 elif bad=='discovery':opts['discover_projects']=True
 elif bad=='wildcard':scopes[0]='*'
 elif bad=='folder':scopes[0]='folders/123'
 elif bad=='https':opts[s.OPTION][0]='https://'+REFS[0]
 elif bad=='tag':opts[s.OPTION][0]=REFS[0].split('@')[0]+':latest'
 else:opts[s.OPTION].append(REFS[0].replace('/positive@','/fifth@'))
 with pytest.raises(ValueError):s.grouped_selections(opts,scopes)
 with pytest.raises(ValueError):r.issue_engine_grant(opts,scopes,[r.CHECK_ID])


def test_scope_spliced_grant_is_rejected(modules):
 s,r,*_=modules;opts=options();r.issue_engine_grant(opts,SCOPES,[r.CHECK_ID])
 with pytest.raises(ValueError):r.authorize_collector(opts,list(reversed(SCOPES)))


def test_disabled_image_features_perform_no_reader_or_database_access(modules,monkeypatch):
 s,r,stream,*_=modules
 monkeypatch.setattr(database,'database_lease',lambda **kw:pytest.fail('disabled database lease'))
 opts={**options(),'content_secret_scans':False,'image_vulnerability_scans':False,'_content_secret_scan_kinds':['artifact_image']}
 collector=SimpleNamespace(options=opts,scopes=SCOPES,registry_image_vulnerability_targets=[],collections={},transport=object())
 assert r.prepare(opts,SCOPES,{r.KIND})==[]
 stream.enrich(collector,reader_factory=lambda _:pytest.fail('disabled reader'))
 r.enrich(collector)
 assert collector.collections=={}


@pytest.mark.parametrize('denied_scope',[None,SCOPES[0],SCOPES[1]])
def test_secret_targets_partition_before_native_binding_and_denial_does_not_poison_peer(modules,monkeypatch,denied_scope):
 s,r,stream,*_=modules;opts={**options(),'_content_secret_scan_kinds':['artifact_image']}
 collections={};all_rows=[]
 for scope,refs in zip(SCOPES,[REFS[:2],REFS[2:]]):
  repo=scope+'/locations/'+refs[0].split('-docker.pkg.dev')[0]+'/repositories/images'
  rows=[{'uri':'https://'+ref,'name':repo+'/dockerImages/'+quote(ref.split('/images/')[1],safe=''),'digest':DIGEST,'repository':repo} for ref in refs]
  all_rows+=rows
  collections[('artifact_image',scope)]={'status':'collected','items':rows}
  collections[('artifact_repository',scope)]={'status':'denied' if scope==denied_scope else 'collected','items':[{'name':repo,'format':'DOCKER'}]}
  collections[('project',scope)]={'status':'collected','items':[{'name':'projects/12345','projectId':scope.split('/')[1]}]}
 calls=[];readers=[]
 class Reader:
  def __init__(self):self.request_ids=[];self.closed=False;readers.append(self)
  def close(self):self.closed=True
 def inspect(row,scope,repos,projects,reader):
  assert row['repository'].startswith(scope+'/')
  calls.append((scope,row['uri']));reader.request_ids.append('read-'+scope.split('/')[1]+'-'+str(len(calls)))
  return {'schema':secret_native.SCHEMA,'status':'collected','complete':True,'leaks':[]}
 monkeypatch.setattr(stream,'inspect_image',inspect)
 collector=SimpleNamespace(options=opts,scopes=SCOPES,collections=collections,transport=object())
 stream.enrich(collector,reader_factory=lambda _:Reader())
 expected=[(scope,'https://ref') for scope in []]
 assert len(calls)==(4 if denied_scope is None else 2)
 assert {scope for scope,_ in calls}==set(SCOPES)-{denied_scope}
 assert all(reader.closed for reader in readers)
 if denied_scope:assert collections[('artifact_image',denied_scope)]['status']=='partial'
 assert all(secret_native.MARKER in row for scope in SCOPES if scope!=denied_scope for row in collections[('artifact_image',scope)]['items'])


def test_cve_projects_overlap_share_one_database_and_keep_exact_scope_rows(modules,monkeypatch,tmp_path):
 s,r,*_=modules;opts=options();opts['concurrency']=2
 barrier=threading.Barrier(2);leases=[];calls=[]
 @contextmanager
 def lease(**kw):leases.append('opened');yield tmp_path;leases.append('closed')
 monkeypatch.setattr(database,'database_lease',lease)
 def collect(transport,*,scope,targets,**kw):
  assert targets==s.grouped_selections(opts,SCOPES)[scope]
  assert all('/'+scope.split('/')[1]+'/' in ref for ref in targets)
  barrier.wait(timeout=3);calls.append(scope)
  return {'complete':scope!=SCOPES[0],'rows':[{'immutable_reference':ref,'status':'UNKNOWN' if scope==SCOPES[0] else 'FAIL',
   'complete':scope!=SCOPES[0],'reason':'denied' if scope==SCOPES[0] else None,'vulnerability_record':None,
   'source_requests':[scope+'-read'],'source_ledger':[]} for ref in targets],
   'observations':[None for _ in targets]}
 monkeypatch.setattr(r,'collect_selected',collect)
 collector=SimpleNamespace(options=opts,scopes=SCOPES,registry_image_vulnerability_targets=REFS,transport=object(),collections={})
 r.enrich(collector);metadata={};r.finish_metadata(collector,metadata)
 assert leases==['opened','closed'] and set(calls)==set(SCOPES)
 assert len(metadata['image_vulnerability_scan']['observations'])==4
 assert collector.collections[(r.KIND,SCOPES[0])]['status']=='partial'
 assert collector.collections[(r.KIND,SCOPES[1])]['status']=='collected'
 for scope in SCOPES:
  rows=collector.collections[(r.KIND,scope)]['items']
  assert len(rows)==2 and all(row['native_id'] in s.grouped_selections(opts,SCOPES)[scope] for row in rows)


@pytest.mark.parametrize('limit',[1,2])
def test_unselected_project_settles_empty_without_scanner_io(modules,monkeypatch,tmp_path,limit):
 s,r,*_=modules;opts=options();opts[r.OPTION]=REFS[:2];opts['concurrency']=limit
 @contextmanager
 def lease(**kw):yield tmp_path
 monkeypatch.setattr(database,'database_lease',lease)
 calls=[]
 def collect(transport,*,scope,targets,**kw):
  calls.append(scope);return {'complete':True,'rows':[{'immutable_reference':ref,'status':'PASS','complete':True,'reason':None,
    'vulnerability_record':None,'source_requests':[],'source_ledger':[]} for ref in targets],'observations':[]}
 monkeypatch.setattr(r,'collect_selected',collect)
 c=SimpleNamespace(options=opts,scopes=SCOPES,registry_image_vulnerability_targets=REFS[:2],transport=object(),collections={})
 r.enrich(c)
 assert calls==[SCOPES[0]]
 assert c.collections[(r.KIND,SCOPES[1])]['status']=='empty' and c.collections[(r.KIND,SCOPES[1])]['items']==[]


@pytest.mark.parametrize('denied_project',[None,'project-one','project-two'])
def test_real_native_cve_metadata_wire_and_digest_binding_across_registries(modules,monkeypatch,tmp_path,denied_project):
    """Only HTTPS sessions/Trivy output are scripted; actual collect_native runs."""
    import gzip,hashlib,io,tarfile
    from peaso.image_findings import build_report
    s,r,*_=modules
    def sha(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
    bodies={};blobs={};targets=[];expect_positive=set()
    for scope,host in zip(SCOPES,['us-central1','europe-west1']):
        project=scope.split('/')[1];repo=scope+'/locations/'+host+'/repositories/images'
        for name in ['positive','clean']:
            stream=io.BytesIO();content=('synthetic package '+('1.0' if name=='positive' else '2.0')+'\n').encode()
            with tarfile.open(fileobj=stream,mode='w') as tar:
                entry=tarfile.TarInfo('app/package-version.txt');entry.size=len(content);tar.addfile(entry,io.BytesIO(content))
            raw=stream.getvalue();layer=gzip.compress(raw,mtime=0)
            config=json.dumps({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[sha(raw)]}},separators=(',',':')).encode()
            manifest=json.dumps({'schemaVersion':2,'mediaType':secret_native.OCI,'config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':sha(config),'size':len(config)},
              'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':sha(layer),'size':len(layer)}]},separators=(',',':')).encode()
            reference=host+'-docker.pkg.dev/'+project+'/images/'+name+'@'+sha(manifest);targets.append(reference)
            if name=='positive':expect_positive.add(reference)
            request_urls=registry_native.requests_for(reference,scope)
            bodies[request_urls[0][0]]={'name':'projects/'+('123456789' if project=='project-one' else '987654321'),'projectId':project,'state':'ACTIVE'}
            bodies[request_urls[1][0]]={'name':repo,'format':'DOCKER','mode':'STANDARD_REPOSITORY','updateTime':'2026-10-24T12:00:00Z'}
            bodies[request_urls[2][0]]={'name':repo+'/dockerImages/'+name+'@'+sha(manifest),'uri':reference,'mediaType':secret_native.OCI,'updateTime':'2026-10-24T12:00:00Z'}
            prefix='https://'+host+'-docker.pkg.dev/v2/'+project+'/images/'+name+'/'
            for category,data in [('manifests',manifest),('blobs',config),('blobs',layer)]:blobs[prefix+category+'/'+sha(data)]=data
    transports=fixture.transport();calls=[];closed=[];guard=threading.Lock()
    class Response:
        history=[]
        def __init__(self,url,raw,status):self.url=url;self.raw=raw;self.status_code=status;self.headers={'Content-Length':str(len(raw)),'Content-Type':'application/json','Content-Encoding':'identity'}
        def iter_content(self,chunk_size):yield self.raw
        def close(self):closed.append(self.url)
    class Session:
        def __init__(self,scope,images=False):self.scope=scope;self.images=images;self.closed=False
        def request(self,method,url,**kw):
            assert method=='GET' and kw['allow_redirects'] is False
            project=self.scope.split('/')[1]
            if self.images:
                assert '/v2/'+project+'/images/' in url
                auth=kw['headers']['Authorization'];assert auth.startswith('Basic ')
                assert base64.b64decode(auth[6:])==b'oauth2accesstoken:fixture-access-token'
                raw=blobs[url];status=200;prepared=url
            else:
                assert '/'+self.scope in url
                assert kw['headers']['Authorization']=='Bearer fixture-access-token'
                raw=json.dumps(bodies[url],separators=(',',':')).encode();status=403 if project==denied_project else 200
                import requests
                prepared=requests.Request('GET',url,params=kw['params']).prepare().url
            with guard:calls.append((self.scope,self.images,url))
            return Response(prepared,raw,status)
        def close(self):self.closed=True
    sessions=[];original=registry_native.collect_native
    def runner(image,manifest,config,layers,**kw):
        assert kw['native_verifier']()==image and all(path.exists() for path in layers)
        positive=image['immutable_reference'] in expect_positive
        finding={'vulnerability_id':'CVE-2026-1001','severity':'HIGH','package_types':['debian'],'package':'synthetic-package',
          'version':'1.0','fixed_in':['2.0'],'fix_status':'fixed','classes':['os-pkgs'],'image_digest':image['manifest_digest']}
        return {'image':image,'status':'FAIL' if positive else 'PASS','complete':True,'scan_complete':True,'coverage_status':'COMPLETE','database':{'fresh':True},'findings':[finding] if positive else []}
    def native(transport,*,scope,selectors,**kw):
        metadata,image=Session(scope),Session(scope,True);sessions.extend([metadata,image])
        return original(transport,scope=scope,selectors=selectors,metadata_session=metadata,image_session=image,runner=runner,**kw)
    monkeypatch.setattr(registry_native,'collect_native',native)
    @contextmanager
    def lease(**kw):yield tmp_path
    monkeypatch.setattr(database,'database_lease',lease)
    opts={r.OPTION:targets,r.ENABLE:True,'concurrency':2}
    collector=SimpleNamespace(options=opts,scopes=SCOPES,registry_image_vulnerability_targets=targets,transport=transports,collections={})
    r.enrich(collector);metadata={};r.finish_metadata(collector,metadata)
    result=build_report(metadata['image_vulnerability_scan']['observations'],selected=True)
    expected=2 if denied_project is None else 1
    assert len(result['rows'])==expected,result
    assert {row['scope'] for row in result['rows']}=={scope for scope in SCOPES if scope.split('/')[1]!=denied_project}
    assert all(session.closed for session in sessions)
    for scope in SCOPES:
        collection=collector.collections[(r.KIND,scope)]
        assert len(collection['items'])==2
        assert all('/'+scope.split('/')[1]+'/' in row['native_id'] for row in collection['items'])
        statuses=[row['RegistryImageVulnerabilityReview']['status'] for row in collection['items']]
        if scope.split('/')[1]==denied_project:
            assert statuses==['UNKNOWN','UNKNOWN'] and collection['status']=='partial'
            assert not any(current==scope and images for current,images,_ in calls)
        else:assert statuses==['FAIL','PASS'] and collection['status']=='collected'


def test_completed_positive_scope_survives_database_lease_exit_error(modules,monkeypatch,tmp_path):
    s,r,*_=modules;opts=options()
    @contextmanager
    def lease(**kw):
        yield tmp_path
        raise OSError('synthetic database cleanup error')
    monkeypatch.setattr(database,'database_lease',lease)
    def collect(transport,*,scope,targets,**kw):
        return {'complete':True,'rows':[{'immutable_reference':ref,'status':'FAIL','complete':True,'reason':None,
            'vulnerability_record':None,'source_requests':[],'source_ledger':[]} for ref in targets],
            'observations':[None for ref in targets]}
    monkeypatch.setattr(r,'collect_selected',collect)
    c=SimpleNamespace(options=opts,scopes=SCOPES,registry_image_vulnerability_targets=REFS,transport=object(),collections={})
    r.enrich(c)
    assert all(row['RegistryImageVulnerabilityReview']['status']=='FAIL' for scope in SCOPES for row in c.collections[(r.KIND,scope)]['items'])


def test_full_catalog_request_keeps_explicit_image_kinds_in_collection_plan(modules):
    """The shared planner fix is required in addition to multi-project grouping."""
    import gzip
    s,r,stream,v,e=modules
    root=Path(_normal_registry.__file__).resolve().parents[2]
    catalog=json.loads(gzip.decompress((root/'peaso/rulepacks/api_catalog.json.gz').read_bytes()))['full']
    chosen={'gcp.review.artifact_image.content_secret_indicators',r.CHECK_ID}
    checks=[c['id'] for c in catalog['checks'] if c['provider']=='gcp' and (c['id'] not in e.EXPLICIT_CONTENT_CHECK_IDS or c['id'] in chosen)]
    request={'connector':{'provider':'gcp','scopes':SCOPES,'auth':{'method':'token','token':'synthetic-token'},'options':options()},
        'categories':list(e.CATEGORIES),'checks':checks+['privesc']}
    categories,selected=e._selection('gcp',request['categories'],request['checks'],None)
    assert e._full_selection('gcp',categories,selected), 'final request must cover the complete active native catalogue'
    planned=e.plan_collection(request)
    assert 'artifact_image' in planned
    assert r.KIND in planned
    assert 'cloudbuild_log_source' not in planned, 'unselected expensive content stays disabled'


def test_strict_source_profiles_are_not_accidentally_opted_in_by_full_image_request(modules):
    s,r,stream,v,e=modules
    expected = {'gcp.review.dataproc.selected_job_referenced_source_secret_indicators', 'gcp.review.sourcerepo.selected_file_secret_indicators', 'gcp.review.dataform.selected_file_secret_indicators', 'gcp.review.gke_workload.literal_configuration_secret_indicators', 'gcp.review.workbench.selected_referenced_source_secret_indicators_20261020', 'gcp.review.cloudbuild.artifact_secret_indicators', 'gcp.review.artifactregistry.selected_file_secret_indicators', 'gcp.review.appengine.deployment_source_secret_indicators', 'gcp.review.dataflow.selected_package_referenced_source_secret_indicators', 'gcp.review.cloudtasks.selected_payload_secret_indicators', 'gcp.review.clouddeploy.release_source_secret_indicators', 'gcp.review.storage.selected_archive_secret_indicators', 'gcp.review.storage.selected_object_secret_indicators', 'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators', 'gcp.review.cloudbuild.stored_log_secret_indicators', 'gcp.review.bigquery.selected_routine_secret_indicators', 'gcp.review.batch.selected_mounted_script_source_secret_indicators'}
    assert expected <= set(e.EXPLICIT_CONTENT_CHECK_IDS)
    categories, selected = e._selection('gcp', list(e.CATEGORIES), None, None)
    assert not expected & {check.id for check in selected}
    # Explicit users retain their original exact-selector requirements.
    for check in ('gcp.review.dataflow.selected_package_referenced_source_secret_indicators',
                  'gcp.review.workbench.selected_referenced_source_secret_indicators_20261020'):
        request={'connector':{'provider':'gcp','scopes':SCOPES,'auth':{'method':'token','token':'synthetic-token'},'options':options()},
                 'checks':[check], 'categories':list(e.CATEGORIES)}
        with pytest.raises(ValueError):e._request(request)
