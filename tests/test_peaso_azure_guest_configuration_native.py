"""Real ARM report-shaped end-to-end evidence; no guest commands or writes."""
import copy
from datetime import datetime, timezone
import json
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot

SUB='/subscriptions/11111111-1111-1111-1111-111111111111'
VM=SUB+'/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/test'
AID=VM+'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/baseline'
RID=AID+'/reports/7367cbb8-ae99-47d0-a33b-a283564d2cb1'
IDS=['azure.gap.network_security_group_rdp_access_restricted','azure.other.clock_sync']
class Denied(RuntimeError):status=403

def capture(monkeypatch,cid,mode='ok'):
 now=datetime.now(timezone.utc).isoformat()
 baseline={'name':'approved','version':'1.0','parameters':{'Expected':'safe'},'maxAgeSeconds':3600}
 if cid==IDS[1]:baseline.update(measurementResourceId='[TimeSync]service',measurementReasonCode='TimeSync::Measurement')
 policy={'status':'collected','scope':SUB,'userRightsBaseline' if cid==IDS[0] else 'timeSyncBaseline':baseline,'approvedTimeSourceIds':['time.example.org']}
 assignment={'id':AID,'name':'baseline','properties':{'latestReportId':RID,'guestConfiguration':{'name':'approved','version':'1.0','configurationParameter':[{'name':'Expected','value':'safe'}]}}}
 if mode=='short_latest':assignment['properties']['latestReportId']=RID.rsplit('/',1)[-1]
 if mode=='foreign_latest':assignment['properties']['latestReportId']=RID.replace('/test/','/foreign/')
 if mode=='parameters':assignment['properties']['guestConfiguration']['configurationParameter'][0]['value']='unsafe'
 if mode=='version':assignment['properties']['guestConfiguration']['version']='2.0'
 measured={'sourceId':'time.example.org','synchronized':True,'driftExceeded':False}
 if mode=='unapproved_source':measured['sourceId']='other.example.org'
 if mode=='drift':measured['driftExceeded']=True
 if mode=='unsynchronized':measured['synchronized']=False
 if mode=='measurement_extra':measured['token']='SECRET_SHOULD_NOT_ESCAPE'
 resource={'resourceId':'[TimeSync]service','properties':{},'reasons':[{'code':'TimeSync::Measurement','phrase':json.dumps(measured)}]}
 if mode=='missing_reason':resource['reasons']=[]
 if mode=='wrong_resource':resource['resourceId']='[Unrelated]service'
 if mode=='duplicate_reason':resource['reasons']*=2
 if mode=='duplicate_key':resource['reasons'][0]['phrase']='{"sourceId":"time.example.org","sourceId":"other","synchronized":true,"driftExceeded":false}'
 native={'id':RID,'properties':{'assignment':{'name':'baseline','configuration':{'name':'approved','version':'1.0'}},'vm':{'id':VM},'reportId':RID.rsplit('/',1)[-1],'complianceStatus':'NonCompliant' if mode=='noncompliant' else 'Compliant','startTime':now,'endTime':now,'details':{'complianceStatus':'NonCompliant' if mode=='noncompliant' else 'Compliant','resources':[resource]}}}
 if mode=='stale':native['properties']['endTime']='2000-01-01T00:00:00Z'
 if mode=='future':native['properties']['endTime']='2099-01-01T00:00:00Z'
 if mode=='foreign_vm':native['properties']['vm']['id']=VM+'foreign'
 if mode=='foreign_report':native['id']=RID+'foreign'
 if mode=='wrong_report_id':native['properties']['reportId']='other'
 if mode=='wrong_job_id':native['properties']['details']['jobId']='other'
 if mode=='contradictory_status':native['properties']['details']['complianceStatus']='NonCompliant'
 if mode=='wrong_detail_time':native['properties']['details']['endTime']='2000-01-01T00:00:00Z'
 if mode=='report_version':native['properties']['assignment']['configuration']['version']='2.0'
 if mode=='missing_details':native['properties'].pop('details')
 class Transport:
  tenant=verified_tenant='22222222-2222-2222-2222-222222222222'
  calls=[]
  def close(self):pass
  def request(self,url,*,body=None,audience=azure.ARM):
   assert body is None and audience==azure.ARM
   self.calls.append(url)
   path=urlsplit(url).path
   if path.casefold()==(SUB+'/providers/Microsoft.Compute/virtualMachines').casefold():
    if mode=='vm_denied':raise Denied('SECRET_SHOULD_NOT_ESCAPE')
    return {'value':[{'id':VM,'type':'Microsoft.Compute/virtualMachines','name':'test','properties':{'storageProfile':{'osDisk':{'osType':'Windows'}}}}]}
   if path.casefold()==VM.casefold():
    return {'id':VM,'type':'Microsoft.Compute/virtualMachines','name':'test','properties':{'storageProfile':{'osDisk':{'osType':'Windows'}}}}
   if path.casefold()==(VM+'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments').casefold():
    if mode=='assignment_denied':raise Denied('SECRET_SHOULD_NOT_ESCAPE')
    value=[] if mode=='no_assignments' else [assignment]
    return {'value':value,'nextLink':'https://evil.test/next'} if mode=='assignment_partial' else {'value':value}
   if '/reports/' in path:
    if mode=='report_denied':raise Denied('SECRET_SHOULD_NOT_ESCAPE')
    return native
   return {'value':[]}
 transport=Transport();monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:transport)
 review={'sw18':policy}
 if mode in ('mixed_policy', 'foreign_named_policy'):
  review.update(status='collected', scope=SUB, checks={})
 if mode in ('foreign_named_policy','malformed_policy'):
  policy['scope']=SUB.replace('11111111','aaaaaaaa')
 options={'retries':0}
 if mode!='missing_policy':options['compliance_policy']=review
 snapshot=collect_live({'provider':'azure','scopes':[SUB],'auth':{'method':'token','arm_token':'fixture'},'options':options},['vm','azure_sw18_evidence'])
 assert 'SECRET_SHOULD_NOT_ESCAPE' not in json.dumps(snapshot)
 findings=[f for f in evaluate_snapshot(snapshot,checks=[cid])['findings'] if f.get('check_id') == cid]
 finding=next((f for f in findings if f.get('native_resource_id') == VM),findings[-1])
 return finding,snapshot,transport,policy

@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('mode,expected',[('ok','PASS'),('short_latest','PASS'),('noncompliant','FAIL'),('stale','UNKNOWN'),('future','UNKNOWN'),('parameters','UNKNOWN'),('version','UNKNOWN'),('foreign_latest','UNKNOWN'),('foreign_vm','UNKNOWN'),('foreign_report','UNKNOWN'),('report_version','UNKNOWN'),('no_assignments','UNKNOWN'),('vm_denied','DENIED'),('assignment_denied','UNKNOWN'),('assignment_partial','UNKNOWN'),('report_denied','UNKNOWN'),('wrong_report_id','UNKNOWN'),('wrong_job_id','UNKNOWN'),('contradictory_status','UNKNOWN'),('wrong_detail_time','UNKNOWN')])
def test_native_guest_baseline_end_to_end(monkeypatch,cid,mode,expected):
 finding,_,_,_=capture(monkeypatch,cid,mode)
 if mode=='noncompliant' and cid==IDS[1]:expected='UNKNOWN'
 assert finding['status']==expected

@pytest.mark.parametrize('mode,expected',[('unapproved_source','FAIL'),('drift','FAIL'),('unsynchronized','UNKNOWN'),('measurement_extra','UNKNOWN'),('missing_reason','UNKNOWN'),('wrong_resource','UNKNOWN'),('duplicate_reason','UNKNOWN'),('duplicate_key','UNKNOWN'),('missing_details','UNKNOWN')])
def test_time_sync_requires_exact_native_measurement(monkeypatch,mode,expected):
 finding,_,_,_=capture(monkeypatch,IDS[1],mode)
 assert finding['status']==expected


def test_denied_report_is_preserved_in_native_collection(monkeypatch):
 _,snapshot,_,_=capture(monkeypatch,IDS[0],'report_denied')
 collection,=[c for c in snapshot['collections'] if c['type']=='azure_sw18_evidence']
 assert collection['status']=='denied'
 assert collection['items']==[]

def test_missing_guest_baseline_policy_is_unknown_not_malformed(monkeypatch):
 finding,snapshot,transport,_=capture(monkeypatch,IDS[0],'missing_policy')
 collection,=[c for c in snapshot['collections'] if c['type']=='azure_sw18_evidence']
 assert finding['status']=='UNKNOWN'
 assert collection['status']=='unknown'
 assert collection['error']=={'code':'approved_guest_baseline_policy_unavailable','kind':'AzureReadError'}
 assert collection['items']==[]
 assert not any('/reports/' in url for url in transport.calls)

def test_provided_foreign_guest_baseline_policy_remains_malformed(monkeypatch):
 finding,snapshot,_,_=capture(monkeypatch,IDS[0],'malformed_policy')
 collection,=[c for c in snapshot['collections'] if c['type']=='azure_sw18_evidence']
 assert finding['status']=='UNKNOWN'
 assert collection['status']=='malformed'
 assert collection['error']=={'code':'read_failed','kind':'ValueError'}
 assert collection['items']==[]

def test_flat_legacy_policy_keeps_priority_over_namespace(monkeypatch):
 from peaso.collectors.azure_guest_configuration_native import _policy
 p={'status':'collected','scope':SUB,'userRightsBaseline':{'name':'legacy'},'sw18':{'status':'collected','scope':SUB,'userRightsBaseline':{'name':'new'}}}
 assert _policy({'compliance_policy':p},SUB)['userRightsBaseline']['name']=='legacy'


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('mode,expected', [('mixed_policy','PASS'),('foreign_named_policy','UNKNOWN')])
def test_guest_review_can_coexist_with_other_flat_policy_without_foreign_approval(monkeypatch,cid,mode,expected):
 finding,_,_,_=capture(monkeypatch,cid,mode)
 assert finding['status']==expected
