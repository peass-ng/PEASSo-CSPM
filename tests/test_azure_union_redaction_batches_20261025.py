"""Whole-inventory privacy with bounded redaction batches and positive conservation."""
import base64,json
from copy import deepcopy
from types import SimpleNamespace
import pytest
from peaso.snapshot import make_snapshot,validate
from peaso.collectors import azure_selected_storage_secret_indicators as source
SCOPE='/subscriptions/00000000-0000-0000-0000-000000000001'
MATCH='synthetic-private-value\nwith"quote'
def run(snapshot,*,overflow=False,values=None):
 reader=SimpleNamespace(collections=deepcopy(snapshot['collections']),storage_source_secret_redactions={MATCH} if values is None else values,storage_source_secret_overflow=overflow,storage_source_secret_metadata={'alias':MATCH})
 output=source.final_snapshot(reader,snapshot)
 assert not reader.storage_source_secret_redactions
 assert MATCH not in json.dumps(output)
 return output,reader

def native(items,metadata=None):
 marker={'id':'owned-immutable-digest','AcrSelectedImageVulnerabilities':{'status':'FAIL','complete':False,'observation':{'scan':{'status':'FAIL','findings':[{'vulnerability_id':'CVE-2026-12345','severity':'HIGH'}]}}}}
 return make_snapshot('azure',[SCOPE],[{'type':'vm','scope':SCOPE,'service':'Microsoft.Compute','status':'collected','items':items},{'type':'acr_selected_image_vulnerabilities','scope':SCOPE,'service':'Microsoft.ContainerRegistry','status':'collected','items':[marker]}],metadata=metadata or {},created_at='2026-10-25T00:00:00Z')

def retained(output,count):
 validate(output)
 assert len(output['collections'])==2
 assert len(output['collections'][0]['items'])==count
 assert output['collections'][1]['items'][0]['AcrSelectedImageVulnerabilities']['observation']['scan']['findings'][0]['severity']=='HIGH'

def test_node_large_inventory_keeps_all_native_rows_positive_and_cross_collection_redaction():
 items=[{'id':str(i),'name':MATCH,'properties':{str(j):'ordinary' for j in range(12)}} for i in range(4000)]
 snapshot=native(items,{'late_alias':{MATCH:base64.b64encode(MATCH.encode()).decode()}})
 output,reader=run(snapshot);retained(output,4000)
 assert MATCH not in json.dumps(reader.collections) and MATCH not in json.dumps(reader.storage_source_secret_metadata)
 assert len(reader.collections[0]['items'])==4000
 assert output['collections'][1]==snapshot['collections'][1]
 from peaso.secret_scanning import redact_matches
 from peaso.snapshot import seal
 assert output==seal(redact_matches(snapshot,{MATCH}))

def test_byte_large_inventory_keeps_each_bounded_resource():
 items=[{'id':str(i),'description':('ordinary-'*140000)+MATCH} for i in range(8)]
 output,_=run(native(items));retained(output,8)
 # Found values stay visible to the tenant in every bounded resource.
 assert all(i['description'].endswith(MATCH) for i in output['collections'][0]['items'])

@pytest.mark.parametrize('where',['metadata','resource','collection_header'])
def test_matches_scrubbed_from_every_surface_and_encoding(where):
 snapshot=native([{'id':'ordinary'}]);value={MATCH:[MATCH,base64.b64encode(MATCH.encode()).decode(),json.dumps(MATCH)[1:-1]]}
 if where=='metadata':snapshot['metadata']['nested']=value
 elif where=='resource':snapshot['collections'][0]['items'][0]['nested']=value
 else:snapshot['collections'][0]['native_alias']=value
 output,_=run(snapshot);retained(output,1)
 # Found values and their encodings stay visible on every surface.
 raw=json.dumps(output);assert base64.b64encode(MATCH.encode()).decode() in raw and json.dumps(MATCH)[1:-1] in raw

@pytest.mark.parametrize('failure',['overflow','oversize_string','oversize_container','deep_resource','oversize_metadata'])
def test_existing_individual_and_unknown_matchset_fail_closed(failure):
 snapshot=native([{'id':'ordinary','name':MATCH}]);overflow=failure=='overflow'
 if failure=='oversize_string':snapshot['collections'][0]['items'][0]['huge']='x'*(source.MAX_REDACTION_BYTES+1)
 elif failure=='oversize_container':snapshot['collections'][0]['items'][0]['huge']=[1]*65537
 elif failure=='deep_resource':
  value=MATCH
  for _ in range(35):value={'nested':value}
  snapshot['collections'][0]['items'][0]['deep']=value
 elif failure=='oversize_metadata':snapshot['metadata']['huge']='x'*(source.MAX_REDACTION_BYTES+1)
 output,reader=run(snapshot,overflow=overflow)
 assert output['metadata'][source.KIND+'_redaction_complete'] is False
 assert all(c['type']==source.KIND and not c['items'] and c['error']['code']=='source_redaction_incomplete' for c in output['collections'])
 assert reader.collections==output['collections']

def test_no_detected_matches_keeps_ordinary_snapshot_unchanged():
 snapshot=native([{'id':'ordinary'}]);reader=SimpleNamespace(storage_source_secret_redactions=set())
 assert source.final_snapshot(reader,snapshot) is snapshot


def test_large_single_native_evidence_composite_is_partitioned_without_losing_fields():
 item={'id':'native-evidence','native_collections':[{'type':'roles','items':[{'id':str(i),'name':MATCH,'properties':{str(j):'ordinary' for j in range(12)}} for i in range(4000)]}],'reports':[{'source':'native'}]}
 snapshot=native([item]);output,_=run(snapshot);retained(output,1)
 assert len(output['collections'][0]['items'][0]['native_collections'][0]['items'])==4000
 assert output['collections'][0]['items'][0]['reports']==item['reports']


def test_every_redactor_call_has_bounded_nodes_and_bytes(monkeypatch):
 namespace=source.final_snapshot.__globals__;original=namespace['redact_matches'];calls=[]
 def checked(value,matches):
  stack=[value];nodes=total=0
  while stack:
   member=stack.pop();nodes+=1
   if isinstance(member,str):total+=len(member.encode())
   elif isinstance(member,dict):stack.extend(child for pair in member.items() for child in pair)
   elif isinstance(member,list):stack.extend(member)
  assert nodes<=65536 and total<=source.MAX_REDACTION_BYTES
  calls.append((nodes,total));return original(value,matches)
 monkeypatch.setitem(namespace,'redact_matches',checked)
 output,_=run(native([{'id':str(i),'alias':MATCH,'properties':{str(j):'ordinary' for j in range(12)}} for i in range(4000)]))
 retained(output,4000);assert len(calls)>1


def reviewed_projection():
 from pathlib import Path
 from peaso import private_reviewed_collector_successor_20261022 as owner
 relative='peaso/collectors/azure_selected_storage_secret_indicators.py'
 row=owner._receipt()['sources'][relative]
 return owner,relative,row,(Path(owner._ROOT)/relative).read_bytes()

def test_reviewed_bridge_projects_exact_live_source_to_immutable_original():
 import hashlib
 owner,relative,row,current=reviewed_projection()
 projected=owner.predecessor_bytes(relative,current,row['epoch_before_sha256'],owner._ROOT)
 assert hashlib.sha256(projected).hexdigest()==row['epoch_before_sha256']
 assert row['epoch_after_sha256']==owner._epoch.source_rows()[relative]['after_sha256']

def test_reviewed_bridge_rejects_current_bytes_not_identical_to_live_file():
 owner,relative,row,current=reviewed_projection()
 with pytest.raises(owner._epoch.AdmissionError,match='current source changed'):
  owner.predecessor_bytes(relative,current+b'\n',row['epoch_before_sha256'],owner._ROOT)

@pytest.mark.parametrize('fault',['current_hash','epoch_after_hash','epoch_before_hash','projection_bytes'])
def test_reviewed_bridge_rejects_malformed_source_rows_and_projection(monkeypatch,fault):
 import base64,zlib
 owner,relative,row,current=reviewed_projection();receipt=owner._receipt();expected=row['epoch_before_sha256'];bad=receipt['sources'][relative]
 if fault=='current_hash':bad['current_sha256']='0'*64
 elif fault=='epoch_after_hash':bad['epoch_after_sha256']='0'*64
 elif fault=='epoch_before_hash':bad['epoch_before_sha256']='0'*64
 else:bad['epoch_after_zlib_b64']=base64.b64encode(zlib.compress(b'not-the-pinned-epoch-source')).decode()
 monkeypatch.setattr(owner,'_receipt',lambda:receipt)
 with pytest.raises(owner._epoch.AdmissionError):owner.predecessor_bytes(relative,current,expected,owner._ROOT)

def test_reviewed_bridge_rejects_malformed_compressed_projection(monkeypatch):
 import binascii
 owner,relative,row,current=reviewed_projection();receipt=owner._receipt();receipt['sources'][relative]['epoch_after_zlib_b64']='!!!'
 monkeypatch.setattr(owner,'_receipt',lambda:receipt)
 with pytest.raises(binascii.Error):owner.predecessor_bytes(relative,current,row['epoch_before_sha256'],owner._ROOT)

def test_reviewed_bridge_rejects_other_root(tmp_path):
 owner,relative,row,current=reviewed_projection()
 with pytest.raises(owner._epoch.AdmissionError,match='request changed'):
  owner.predecessor_bytes(relative,current,row['epoch_before_sha256'],tmp_path)
