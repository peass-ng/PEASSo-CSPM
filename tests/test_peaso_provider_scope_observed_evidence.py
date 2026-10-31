"""Actual source scope and nested incomplete evidence, without status inference."""
from copy import deepcopy
import gzip,json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.provider_scope_observed_evidence import provider_scope,REVIEWED_SCOPES
CHECK={c.id:c for c in CHECKS}
BULK=json.loads(gzip.decompress((Path(__file__).parent/'fixtures/azure_bulk_clarity_reviewed.json.gz').read_bytes()))

@pytest.mark.parametrize('row',REVIEWED_SCOPES,ids=lambda r:r['check_id']+'-'+r['status'])
def test_every_scope_observation_comes_from_actual_registered_fixture(row):
 cid,state=row['check_id'],row['case']
 if cid in BULK:
  fx=BULK[cid][state.upper()];item,index=fx['item'],fx['index']
 else:
  fx=CASES[cid];item,index=fx[state],fx.get(state+'_index',fx.get('index',{}))
 if cid=='azure.claude.vm_windows_secure_boot' and state=='not_applicable':
  # The old image-offer witness only describes archived reports. Native OS
  # facts now take precedence; the same Windows fixture correctly fails today.
  native_status,native_evidence=CHECK[cid].evaluate(deepcopy(item),deepcopy(index))
  assert native_status=='FAIL'
  assert provider_scope({'provider':'azure','check_id':cid,'status':native_status,'evidence':native_evidence}) is None
  return
 else:
  status,evidence=CHECK[cid].evaluate(deepcopy(item),deepcopy(index))
 assert status==row['status'] and evidence==row['witness']
 finding={'provider':row['provider'],'check_id':cid,'status':status,'evidence':evidence};before=deepcopy(finding)
 assert provider_scope(finding)==row['summary']
 assert len(row['summary'].split())<=30
 assert finding==before

@pytest.mark.parametrize('row',REVIEWED_SCOPES,ids=lambda r:r['check_id']+'-'+r['status'])
def test_omitted_malformed_and_wrong_status_inputs_keep_fallback(row):
 f={'provider':row['provider'],'check_id':row['check_id'],'status':row['status'],'evidence':deepcopy(row['witness'])}
 assert provider_scope(dict(f,provider='aws'))is None
 assert provider_scope(dict(f,check_id='unreviewed.scope'))is None
 for status in ('PASS','FAIL','DENIED','EMPTY'):
  assert provider_scope(dict(f,status=status))is None
 for field,original in row['witness'].items():
  omitted=deepcopy(row['witness']);omitted.pop(field)
  assert provider_scope(dict(f,evidence=omitted))is None
  for malformed in (False,0,None,'not-a-native-value',{'unexpected':True}):
   if type(malformed)is type(original)and malformed==original:continue
   bad=deepcopy(row['witness']);bad[field]=malformed
   assert provider_scope(dict(f,evidence=bad))is None


def test_unknown_parent_link_is_not_recast_as_success_or_failure():
 row=next(r for r in REVIEWED_SCOPES if r['status']=='UNKNOWN')
 text=provider_scope({'provider':'azure','check_id':row['check_id'],'status':'UNKNOWN','evidence':row['witness']})
 assert 'incomplete'in text and 'parent resource identifier is missing'in text
 assert 'compliant'not in text and 'secure'not in text.lower()
