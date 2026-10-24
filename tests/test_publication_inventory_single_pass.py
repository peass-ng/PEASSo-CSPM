"""Native exports share one publication-local inventory and retain complete data."""
import copy,pytest
import peaso.engine as engine
import peaso.snapshot as snapshots
import peaso.storage.reports as publisher
from peaso.storage.artifacts import FileArtifacts, check_reference

def normalize(value,store):
 if isinstance(value,str):
  try:check_reference('owner',value)
  except (ValueError,TypeError):return value
  return store.get_text('owner',value) if value.endswith('.md') else normalize(store.get('owner',value),store)
 if isinstance(value,list):return [normalize(item,store) for item in value]
 if isinstance(value,dict):return {key:normalize(item,store) for key,item in value.items()}
 return value

def snapshot(provider):
 return snapshots.make_snapshot(provider,['scope'],[{'type':'fixture_unrelated','scope':'scope','status':'collected','items':[{'id':'native-one','config':{'string':'café','values':[1,None,False]}}]}],created_at='2026-10-24T15:00:00Z')

def report(snap):
 inventory=snapshots.resources(snap)
 return {'schema_version':engine.REPORT_SCHEMA_VERSION,'snapshot_id':snap['snapshot_id'],'provider':snap['provider'],'scopes':snap['scopes'],'created_at':snap['created_at'],'resources':[{key:value for key,value in row.items() if key!='data'} for row in inventory],'findings':[],'coverage':[],'graphs':{},'stats':{},'check_frameworks':{},'check_meta':{},'snapshot_metadata':{}}

@pytest.mark.parametrize('provider',['aws','azure','gcp','k8s'])
def test_complete_exports_share_exactly_one_native_inventory(provider,tmp_path,monkeypatch):
 from peaso.finding_groups import group_report
 from peaso.reports import render_markdown
 snap=snapshot(provider);value=report(snap);before=copy.deepcopy((snap,value))
 expected=group_report(value)
 expected_markdown=render_markdown(engine.expand_report(expected,snap))
 store=FileArtifacts(tmp_path/'new')
 calls=[];original=snapshots.resources
 def counted(source):calls.append(source);return original(source)
 monkeypatch.setattr(snapshots,'resources',counted)
 monkeypatch.setattr(engine,'resources',counted)
 ref=publisher._publish_report(store,'owner','a'*32,value,snap)
 assert calls==[snap]
 manifest=normalize(store.get('owner',ref),store)
 assert manifest['report_json']==expected
 assert manifest['report_markdown']==expected_markdown
 assert manifest['resource_chunks'][0]['reference']['items'][0]['data']==snap['collections'][0]['items'][0]
 assert before==(snap,value)

def test_no_inventory_survives_publication_or_crosses_revision(tmp_path,monkeypatch):
 store=FileArtifacts(tmp_path/'all');first=snapshot('aws');firstreport=report(first)
 publisher._publish_report(store,'owner','a'*32,firstreport,first)
 second=snapshot('aws');second['collections'][0]['items'][0]['config']['string']='changed'
 second=snapshots.seal(second);secondreport=report(second)
 ref=publisher._publish_report(store,'owner','a'*32,secondreport,second)
 manifest=normalize(store.get('owner',ref),store)
 assert manifest['report_json']['snapshot_id']==second['snapshot_id']
 assert manifest['resource_chunks'][0]['reference']['items'][0]['data']['config']['string']=='changed'

def test_nonembeddable_legacy_report_needs_no_native_inventory(tmp_path,monkeypatch):
 value={'provider':'aws','schema_version':'1.0','resources':[],'findings':[],'coverage':[],'stats':{},'graphs':{}}
 def unexpected(*a,**kw):raise AssertionError('legacy report cannot normalize absent snapshot')
 monkeypatch.setattr(snapshots,'resources',unexpected)
 store=FileArtifacts(tmp_path/'legacy');assert publisher._publish_report(store,'owner','a'*32,value,None)
