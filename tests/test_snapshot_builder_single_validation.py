"""Builder validates and hashes once while preserving its former wire contract."""
import copy,pytest
from peaso import snapshot as baseline
candidate=baseline

def retained_builder(provider,scopes,collections,*,created_at=None,metadata=None):
 # Previous public builder semantics retained for output/error parity.
 return baseline.validate(baseline.seal({'schema_version':baseline.SCHEMA_VERSION,
  'provider':provider,'scopes':list(scopes),'created_at':created_at,
  'collections':collections,'metadata':metadata or {}}))

AT='2026-10-24T15:00:00+00:00'

def fixture(provider='aws',status='collected',items=None):
 return {'provider':provider,'scopes':['111111111111/us-east-1'],'collections':[{'type':'instance','scope':'111111111111/us-east-1','status':status,'items':[{'InstanceId':'i-example','nested':{'list':[1,True,None,'é🧙']}}] if items is None else items}],'created_at':AT,'metadata':{'scope_coverage':{'status':'partial'}}}

@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_identical_full_content_and_digest(provider):
 args=fixture(provider);before=copy.deepcopy(args)
 assert retained_builder(**args)==candidate.make_snapshot(**args)
 assert args==before

@pytest.mark.parametrize('status',baseline.STATUSES)
def test_all_collection_statuses_identical(status):
 args=fixture(status=status,items=[])
 assert retained_builder(**args)==candidate.make_snapshot(**args)

@pytest.mark.parametrize('change',[
 lambda a:a.update(provider='unsupported'),
 lambda a:a.update(scopes=[123]),
 lambda a:a['collections'][0].update(status='bad'),
 lambda a:a['collections'][0].update(items=['not-object']),
 lambda a:a['collections'].append(copy.deepcopy(a['collections'][0])),
 lambda a:a['collections'][0].update(status='denied'),
 lambda a:a.update(metadata=['wrong']),
 lambda a:a['collections'][0].update(service=7),
 lambda a:a['collections'][0].update(error='wrong'),
 lambda a:a.update(created_at=123),
 lambda a:a['metadata'].update(nonfinite=float('nan')),
])
def test_invalid_snapshot_still_rejected(change):
 args=fixture();change(args)
 with pytest.raises((ValueError,TypeError)) as old:retained_builder(**args)
 with pytest.raises(type(old.value)):candidate.make_snapshot(**args)

def test_built_snapshot_is_independent():
 args=fixture();made=candidate.make_snapshot(**args)
 args['collections'][0]['items'][0]['nested']['list'].append('new')
 args['metadata']['scope_coverage']['status']='complete'
 assert made['collections'][0]['items'][0]['nested']['list']==[1,True,None,'é🧙']
 assert made['metadata']['scope_coverage']['status']=='partial'
 assert baseline.validate(made)==made

def test_tampering_still_fails_external_digest_validation():
 made=candidate.make_snapshot(**fixture());made['collections'][0]['items'][0]['InstanceId']='i-tampered'
 with pytest.raises(ValueError,match='digest mismatch'):candidate.validate(made)

def test_builder_only_one_hash_and_structural_copy(monkeypatch):
 calls={'copy':0,'digest':0};oldcopy=candidate._sealed_structure;olddigest=candidate.digest
 def countedcopy(*args,**kwargs):calls['copy']+=1;return oldcopy(*args,**kwargs)
 def counteddigest(*args,**kwargs):calls['digest']+=1;return olddigest(*args,**kwargs)
 monkeypatch.setattr(candidate,'_sealed_structure',countedcopy);monkeypatch.setattr(candidate,'digest',counteddigest)
 candidate.make_snapshot(**fixture())
 assert calls=={'copy':1,'digest':1}
