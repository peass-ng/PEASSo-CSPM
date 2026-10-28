"""Native complete GCP IAM/ACL metadata through collect_live and the engine."""
import copy,json,threading
from urllib.parse import urlsplit
import pytest
from peaso.collectors import collect_live,gcp
from tests.archived_check_contract import evaluate_snapshot,plan_collection
SCOPE='projects/demo-project';BUCKET='private-bucket';NUMBER='1234567890'
ACCESS='gcp_pci_bucket_7dc6cb8c2e05';WRITE='gcp_pci_bucket_56c6b1b7f813';CHECKS=[ACCESS,WRITE]
class API:
 def __init__(self,mode):self.mode=mode;self.calls=0;self.evidence=[];self.requests=[];self.lock=threading.Lock()
 def close(self):pass
 def request(self,method,url,**kw):
  with self.lock:self.calls+=1;rid='request-'+str(self.calls);self.requests.append((method,url,copy.deepcopy(kw)))
  path=urlsplit(url).path;params=kw.get('params',{})
  mode=self.mode;nonuniform=mode.startswith('acl_') or mode in ('object_partial','missing_object_acl','duplicate_object','foreign_acl','multi_bucket','unknown_acl_bucket','metadata_private','embedded_acl_parents_omitted','object_writer_invalid','object_second_page_public','object_page_limit','empty_objects','default_acl_public','default_acl_private')
  if path=='/storage/v1/b':
   bucket={'name':BUCKET,'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':not nonuniform},'publicAccessPrevention':'enforced' if mode.startswith('pap_') else 'inherited'}}
   if mode in ('hns','hns_managed_public'):bucket['hierarchicalNamespace']={'enabled':True}
   if mode=='malformed_uniform':bucket['iamConfiguration']=None
   data={'items':[bucket]}
   if mode=='multi_bucket':data['items'].append({**bucket,'name':'other-bucket'})
  elif path.endswith('/iam') and '/storage/v1/b/' in path:
   if mode=='denied_bucket_iam':raise gcp.ReadError('denied','forbidden')
   bindings=[]
   if mode in ('pap_write','public_write'):bindings=[{'role':'roles/storage.objectCreator','members':['allUsers']}]
   if mode in ('pap_read','public_read'):bindings=[{'role':'roles/storage.objectViewer','members':['allUsers']}]
   if mode in ('public_object_user','public_legacy_bucket_owner'):
    bindings=[{'role':'roles/storage.objectUser' if mode=='public_object_user' else 'roles/storage.legacyBucketOwner','members':['allUsers']}]
   if mode=='bucket_custom':bindings=[{'role':'projects/demo-project/roles/custom','members':['allUsers']}]
   if '/managedFolders/' in path and mode in ('managed_public','hns_managed_public'):
    bindings=[{'role':'roles/storage.objectViewer','members':['allUsers']}]
   data={'bindings':bindings,'version':3}
  elif path=='/v3/'+SCOPE:data={'name':'projects/'+NUMBER,'projectId':'demo-project'}
  elif path=='/v1/'+SCOPE+':getAncestry':
   if mode=='denied_ancestry':raise gcp.ReadError('denied','forbidden')
   data={'ancestor':[{'resourceId':{'type':'project','id':'wrong' if mode=='foreign_ancestry' else NUMBER}}]}
   if mode.startswith('ancestor_'):data['ancestor'].append({'resourceId':{'type':'organization','id':'999'}})
  elif path.endswith(':getIamPolicy'):
   if mode=='denied_root_iam':raise gcp.ReadError('denied','forbidden')
   data={'bindings':[]}
   if path.startswith('/v3/organizations/'):
    if mode=='ancestor_public':data['bindings']=[{'role':'roles/storage.objectViewer','members':['allUsers']}]
    if mode=='ancestor_object_user':data['bindings']=[{'role':'roles/storage.objectUser','members':['allUsers']}]
    if mode=='ancestor_custom':data['bindings']=[{'role':'organizations/999/roles/custom','members':['allUsers']}]
    if mode=='ancestor_conditional':data['bindings']=[{'role':'roles/storage.objectViewer','members':['allUsers'],'condition':{'expression':'true'}}]
    if mode=='ancestor_private_conditional':data['bindings']=[{'role':'roles/storage.objectViewer','members':['user:internal@example.com'],'condition':{'expression':'true'}}]
  elif path.startswith('/v3/organizations/'):data={'name':'organizations/999'}
  elif path.endswith('/managedFolders'):
   if mode=='denied_managed':raise gcp.ReadError('denied','forbidden')
   data={'items':[{'name':'managed/','bucket':BUCKET}] if mode in ('managed','managed_public','hns_managed_public') else []}
  elif path.endswith('/defaultObjectAcl'):
   data={'items':[{'bucket':BUCKET,'entity':'allUsers' if mode=='default_acl_public' else 'user-private-marker@example.com','role':'READER'}]}
  elif path.endswith('/acl'):
   if mode=='acl_denied':raise gcp.ReadError('denied','forbidden')
   bucket=path.split('/')[4]
   entity='allUsers' if mode in ('acl_public_read','acl_public_write') or mode=='multi_bucket' and bucket=='other-bucket' else 'user-private-marker@example.com'
   role='WRITER' if mode=='acl_public_write' else 'READER' if entity=='allUsers' else 'OWNER'
   data={'items':[{'bucket':'foreign-bucket' if mode=='foreign_acl' else bucket,'entity':entity,'role':role}]}
  elif path.endswith('/o'):
   if mode=='object_partial' and params.get('pageToken'):raise gcp.ReadError('denied','forbidden')
   bucket=path.split('/')[4];name='private-marker/document.csv';generation='1234'
   if mode in ('object_second_page_public','object_page_limit') and params.get('pageToken'):
    name='another-private-marker';generation='5678'
   entry={'bucket':bucket,'object':name,'generation':generation,'entity':'allUsers' if mode=='acl_object_owner' or mode in ('object_second_page_public','object_page_limit') and params.get('pageToken') else 'user-private-marker@example.com','role':'OWNER'}
   if mode=='embedded_acl_parents_omitted':entry={'entity':entry['entity'],'role':entry['role']}
   if mode=='object_writer_invalid':entry['role']='WRITER'
   obj={'bucket':bucket,'name':name,'generation':generation,'acl':[entry]}
   if mode=='missing_object_acl':obj.pop('acl')
   data={'items':[] if mode=='empty_objects' else [obj,obj] if mode=='duplicate_object' else [obj]}
   if mode=='object_partial' or mode in ('object_second_page_public','object_page_limit') and not params.get('pageToken'):data['nextPageToken']='next'
  elif path.startswith('/compute/v1/'):data={}
  else:data={}
  self.evidence.append({'id':rid,'url':url,'method':method,'status':'collected'})
  return copy.deepcopy(data),rid

@pytest.mark.parametrize('mode,expected',[
 ('malformed_uniform',['UNKNOWN','UNKNOWN']),('embedded_acl_parents_omitted',['PASS','PASS']),('object_writer_invalid',['PASS','UNKNOWN']),
 ('object_second_page_public',['PASS','FAIL']),('object_page_limit',['PASS','UNKNOWN']),('empty_objects',['PASS','PASS']),
 ('no_inherited',['UNKNOWN','UNKNOWN']),('complete',['PASS','PASS']),('pap_write',['FAIL','FAIL']),('pap_read',['FAIL','PASS']),
 ('public_write',['FAIL','FAIL']),('public_read',['FAIL','PASS']),('bucket_custom',['FAIL','UNKNOWN']),
 ('public_object_user',['FAIL','FAIL']),('public_legacy_bucket_owner',['FAIL','FAIL']),
 ('ancestor_public',['FAIL','PASS']),('ancestor_custom',['UNKNOWN','UNKNOWN']),('ancestor_conditional',['UNKNOWN','UNKNOWN']),
 ('ancestor_object_user',['FAIL','FAIL']),
 ('ancestor_private_conditional',['PASS','PASS']),
 ('denied_ancestry',['UNKNOWN','UNKNOWN']),('foreign_ancestry',['UNKNOWN','UNKNOWN']),('denied_root_iam',['UNKNOWN','UNKNOWN']),
 ('hns',['UNKNOWN','UNKNOWN']),('managed',['UNKNOWN','UNKNOWN']),('denied_managed',['UNKNOWN','UNKNOWN']),
 ('denied_bucket_iam',['UNKNOWN','UNKNOWN']),('acl_private',['PASS','PASS']),('metadata_private',['PASS','PASS']),
 ('acl_public_read',['FAIL','PASS']),('acl_public_write',['FAIL','FAIL']),('acl_object_owner',['PASS','FAIL']),
 ('acl_denied',['UNKNOWN','UNKNOWN']),('object_partial',['PASS','UNKNOWN']),('missing_object_acl',['PASS','UNKNOWN']),
 ('duplicate_object',['PASS','UNKNOWN']),('foreign_acl',['UNKNOWN','UNKNOWN'])])
def test_actual_storage_public_grant_and_acl_pipeline(mode,expected,monkeypatch):
 api=API(mode);monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None);monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
 connector={'provider':'gcp','scopes':[SCOPE],'options':{'resource_iam':False,'metrics_scopes':False,'include_inherited':True,
 'sw51_policy':{'status':'collected','scope':SCOPE,'excludedPublicBuckets':[]}}}
 if mode=='object_page_limit':connector['options']['max_pages']=1
 if mode=='no_inherited':connector['options']['include_inherited']=False
 snap=collect_live(connector,plan_collection({'connector':connector,'checks':CHECKS}))
 report=evaluate_snapshot(snap,checks=CHECKS,include_not_applicable=True)
 actual={cid:[f['status'] for f in report['findings'] if f['check_id']==cid] for cid in CHECKS}
 assert all(actual[cid] and set(actual[cid])=={value} for cid,value in zip(CHECKS,expected)),actual
 if mode in ('public_object_user','public_legacy_bucket_owner','ancestor_object_user'):
  effective=collection(snap,'bucket_effective_iam',SCOPE)
  assert effective['coverage_status']=='collected' and len(effective['items'])==1
  assert effective['items'][0]['publicAccess'] is True
  assert effective['items'][0]['publicWrite'] is True
 assert 'private-marker' not in json.dumps(snap)
 assert all('/download/' not in url and (kw.get('params') or {}).get('alt')!='media' for method,url,kw in api.requests)
 for method,url,kw in api.requests:
  if url.endswith('/o'):assert kw['params']['projection']=='full' and kw['params']['versions']=='true'

def test_multiple_native_bucket_acl_owners_are_joined_without_poisoning_neighbors(monkeypatch):
 api=API('multi_bucket');monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None);monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
 connector={'provider':'gcp','scopes':[SCOPE],'options':{'resource_iam':False,'metrics_scopes':False,'include_inherited':True,'sw51_policy':{'status':'collected','scope':SCOPE,'excludedPublicBuckets':[]}}}
 snap=collect_live(connector,plan_collection({'connector':connector,'checks':CHECKS}))
 report=evaluate_snapshot(snap,checks=CHECKS,include_not_applicable=True)
 actual={(f['check_id'],f['evidence']['bucket']):f['status'] for f in report['findings']}
 assert actual=={(ACCESS,BUCKET):'PASS',(ACCESS,'other-bucket'):'FAIL',(WRITE,BUCKET):'PASS',(WRITE,'other-bucket'):'PASS'}


from peaso.collectors import gcp_network_catalog as network
from peaso.collectors import gcp_storage_acl_native as storage
from tests.test_peaso_collectors_gcp import snapshot, collection
def test_private_service_networking_contract():
    def resolver(request):
        if request['url'].endswith('/networks'):
            return {'items':[{'name':'default'}]}
        assert request['method']=='GET'
        assert request['params']=={'network':'projects/p-one/global/networks/default'}
        return {'connections':[{'peering':'native-peering'}]}
    snap,_=snapshot(['service_networking_connection'],resolver)
    assert collection(snap,'service_networking_connection')['items'][0]['peering']=='native-peering'

@pytest.mark.parametrize('has_folders',[False,True])
def test_managed_folder_evidence_semantics(has_folders,monkeypatch):
    from types import SimpleNamespace,MethodType
    from peaso.collectors.gcp import GCPCollector,ReadError
    bucket={'name':'private-bucket','iamPolicy':{'bindings':[]},
        'iamConfiguration':{'uniformBucketLevelAccess':{'enabled':True}},
        '_coverage':{'iamPolicy':{'status':'collected','source_requests':['iam']}}}
    monkeypatch.setattr(storage,'_parents',lambda *args:{'items':[bucket],'source_requests':['buckets']})
    monkeypatch.setattr(storage,'_root_policies',lambda *args:[])
    calls=[]
    def read(url,scope,**kwargs):
        calls.append(kwargs)
        assert 'fields' not in kwargs.get('params',{})
        assert 'maxResults' in kwargs['params']
        return {'items':[{'name':'managed/'}] if has_folders else []},'folders'
    collector=SimpleNamespace(read=read,page_size=100,max_pages=None)
    collector.pages=MethodType(GCPCollector.pages,collector)
    if has_folders:
        with pytest.raises(ReadError) as exc:list(storage._effective(collector,'projects/owned'))
        assert exc.value.error['code']=='storage_managed_folder_iam_unresolved'
    else:
        result=list(storage._effective(collector,'projects/owned'))
        rows=[item for page,_ in result for item in page]
        assert len(rows)==1 and rows[0]['resolutionComplete'] is True
        assert rows[0]['publicAccess'] is False and rows[0]['publicWrite'] is False
    assert len(calls)==1


@pytest.mark.parametrize('mode,public',[
    ('managed',False),('managed_public',True),('hns',False),('hns_managed_public',True)])
def test_effective_bucket_iam_reuses_complete_managed_folder_inventory(mode,public,monkeypatch):
    api=API(mode)
    monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None)
    monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
    connector={'provider':'gcp','scopes':[SCOPE],'options':{'inventories':['bucket','project','iam_policy',
        'managed_folder','bucket_effective_iam'],'include_inherited':True,'concurrency':1}}
    snap=collect_live(connector)
    folders=collection(snap,'managed_folder',SCOPE)
    effective=collection(snap,'bucket_effective_iam',SCOPE)
    assert folders['coverage_status'] in ('collected','empty')
    assert effective['coverage_status']=='collected',effective
    assert len(effective['items'])==1
    row=effective['items'][0]
    assert (row['name'],row['resolutionComplete'],row['publicAccess'],row['publicWrite'])==(
        BUCKET,True,public,False)
    assert sum(urlsplit(url).path.endswith('/managedFolders') for _,url,_ in api.requests)==1


@pytest.mark.parametrize('role,status',[
    ('roles/storage.objectUser','FAIL'),
    ('roles/storage.legacyBucketOwner','PASS'),
])
def test_inherited_object_read_grant_role_permissions(role,status,monkeypatch):
    from peaso.checks import gcp_public_read_native as public_read
    monkeypatch.setattr(public_read,'project_roots',lambda item,index:[
        {'name':SCOPE,'bindings':[{'role':role,'members':['allUsers']}]}])
    monkeypatch.setattr(public_read,'complete_items',lambda index,kind:[
        {'name':BUCKET,'resolutionComplete':True,'policyScopes':[SCOPE]}])
    actual,evidence=public_read.inherited_read({'name':BUCKET},object())
    assert actual==status
    if status=='FAIL':
        assert evidence['inherited_public_read_grants']==[{'scope':SCOPE,'role':role}]


@pytest.mark.parametrize('mode,public',[('default_acl_public',True),('default_acl_private',False)])
def test_default_object_acl_future_upload_public_grant(mode,public,monkeypatch):
    from peaso.analysis import analyze
    from peaso.engine import plan_collection as exposure_plan
    assert 'default_object_acl' in exposure_plan({'connector':{'provider':'gcp'},'categories':['exposure']})
    api=API(mode)
    monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None)
    monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
    snap=collect_live({'provider':'gcp','scopes':[SCOPE],
                       'options':{'inventories':['bucket','default_object_acl'],'concurrency':1}})
    rows=collection(snap,'default_object_acl',SCOPE)
    assert rows['coverage_status']=='collected' and len(rows['items'])==1
    assert 'private-marker' not in json.dumps(snap)
    if not public:
        snap['metadata']['trusted_domains']=['owned.example']
        snap.pop('snapshot_id',None)
    report=analyze(snap)
    findings=[f for f in report['findings'] if f['check_id']=='analysis.gcp_public_default_object_acl']
    assert (len(findings)==1)==public
    if public:
        assert findings[0]['status']=='FAIL'
        assert findings[0]['evidence']['semantics'].startswith('Future object ACL template')
    else:
        third_party=[f for f in report['findings'] if f['check_id']=='analysis.principal_exposure'
                     and f['status']=='FAIL']
        assert third_party and any(entry['classification']=='external'
            for finding in third_party for entry in finding['evidence']['principals'])
