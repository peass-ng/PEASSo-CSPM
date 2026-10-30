"""Actual Graph hierarchy through collect_live and the scoped review engine."""
from datetime import datetime,timezone,timedelta
from urllib.parse import urlsplit,parse_qs
import json
import pytest
from peaso.collectors import azure,collect_live
from tests.archived_check_contract import evaluate_snapshot,plan_collection
SUB='11111111-1111-1111-1111-111111111111';SCOPE='/subscriptions/'+SUB
TENANT='22222222-2222-2222-2222-222222222222';USER='33333333-3333-3333-3333-333333333333';GROUP='44444444-4444-4444-4444-444444444444'
DEFINITION='55555555-5555-5555-5555-555555555555';REVIEWER='66666666-6666-6666-6666-666666666666'
ROOT='/v1.0/identityGovernance/accessReviews/definitions';MONTHLY='azure.cis.guest_users_reviewed_monthly_basis';REGULAR='azure.cis.guest_users_reviewed_regular_basis';CHECKS=[MONTHLY,REGULAR]
class API:
 tenant=verified_tenant=TENANT
 def __init__(self,mode):
  self.mode=mode;self.calls=[];self.now=datetime.now(timezone.utc).replace(microsecond=0);self.instances=[]
  for i,days in enumerate((15,8,1)):
   begin=self.now-timedelta(days=days);end=begin+timedelta(days=1)
   self.instances.append({'id':f'77777777-7777-7777-7777-77777777777{i}','startDateTime':begin.isoformat(),'endDateTime':end.isoformat(),'status':'Completed'})
 def close(self):pass
 def request(self,url,*,body=None,audience=azure.ARM):
  self.calls.append((url,audience,body));path=urlsplit(url).path;params=parse_qs(urlsplit(url).query)
  if path=='/subscriptions':return {'value':[{'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT}]}
  if path==SCOPE:return {'id':SCOPE,'subscriptionId':SUB,'tenantId':TENANT}
  if path=='/v1.0/groups':
   if self.mode=='denied_groups':raise azure.AzureReadError('forbidden',403)
   return {'value':[{'id':GROUP,'groupTypes':['DynamicMembership'] if self.mode=='dynamic' else ['Unified']}]}
  if path=='/v1.0/users':
   if self.mode=='denied_users':raise azure.AzureReadError('forbidden',403)
   row={'id':USER,'accountEnabled':True,'userType':'Member' if self.mode=='no_guest' else 'Guest','createdDateTime':'2025-01-01T00:00:00Z'}
   if self.mode=='review_before_creation':row['createdDateTime']=self.now.isoformat()
   if self.mode=='future_guest':row['createdDateTime']=(self.now+timedelta(days=1)).isoformat()
   if self.mode=='new_guest':row['createdDateTime']=(self.now-timedelta(hours=3)).isoformat()
   if self.mode=='malformed_user':row['userType']='FutureType'
   return {'value':[] if self.mode=='empty_users' else [row,row] if self.mode=='duplicate_user' else [row]}
  if path==ROOT:
   if self.mode=='denied_definitions':raise azure.AzureReadError('forbidden',403)
   scope={'@odata.type':'#microsoft.graph.accessReviewQueryScope','query':f'/groups/{GROUP}/transitiveMembers/microsoft.graph.user?$count=true&$filter=(userType eq \'Guest\')','queryType':'MicrosoftGraph','queryRoot':None}
   if self.mode=='application_scope':scope['query']='/servicePrincipals/'+GROUP+'/appRoleAssignedTo'
   if self.mode=='unknown_scope':scope['queryType']='Other'
   recurrence={'pattern':{'type':'weekly','interval':1,'daysOfWeek':[(self.now-timedelta(days=1)).strftime('%A').lower()]},'range':{'type':'noEnd','startDate':'2025-01-01','recurrenceTimeZone':'UTC'}}
   if self.mode=='bad_timezone':recurrence['range']['recurrenceTimeZone']='Eastern Standard Time'
   if self.mode=='inactive_schedule':recurrence['range'].update(type='endDate',endDate='2025-02-01')
   row={'id':DEFINITION,'status':'InProgress','scope':scope,'instanceEnumerationScope':None,'settings':{'recurrence':recurrence,'instanceDurationInDays':1,'mailNotificationsEnabled':True},'descriptionForAdmins':'private-marker'}
   if self.mode=='multistage':row['stageSettings']=[{'stageId':'first'}]
   if self.mode=='unknown_definition_state':row['status']='FutureState'
   if self.mode=='relative_scope':row['scope']['query']='./members';row['instanceEnumerationScope']={'query':'/groups'}
   if self.mode=='partial_definitions':
    if '$skiptoken' in params:raise azure.AzureReadError('forbidden',403)
    return {'value':[row],'@odata.nextLink':azure.GRAPH+ROOT+'?$skiptoken=next'}
   return {'value':[] if self.mode=='no_definitions' else [row]}
  if path==ROOT+'/'+DEFINITION+'/instances':
   if self.mode=='denied_instances':raise azure.AzureReadError('forbidden',403)
   rows=[dict(r) for r in self.instances]
   if self.mode=='no_instances':rows=[]
   if self.mode=='late_latest':rows[-1]['status']='InProgress'
   if self.mode=='old_instances':
    for r in rows:
     for k in ('startDateTime','endDateTime'):r[k]=(datetime.fromisoformat(r[k])-timedelta(days=180)).isoformat()
   if self.mode=='gap':rows.pop(1)
   return {'value':rows}
  if path.startswith(ROOT+'/'+DEFINITION+'/instances/') and path.endswith('/decisions'):
   if self.mode=='denied_decisions':raise azure.AzureReadError('forbidden',403)
   instance=next(r for r in self.instances if r['id']==path.split('/')[-2]);i=self.instances.index(instance);at=datetime.fromisoformat(instance['startDateTime'])+timedelta(hours=6)
   row={'id':f'88888888-8888-8888-8888-88888888888{i}','accessReviewId':instance['id'],'principal':{'id':USER,'@odata.type':'#microsoft.graph.userIdentity'},'resource':None,'reviewedDateTime':at.isoformat(),'decision':'Approve','reviewedBy':{'id':REVIEWER},'justification':'private-marker'}
   if self.mode=='wrong_instance':row['accessReviewId']='99999999-9999-9999-9999-999999999999'
   if self.mode=='foreign_resource':row['resource']={'id':'99999999-9999-9999-9999-999999999999'}
   if self.mode=='malformed_principal':row['principal']={'id':'not-a-guid'}
   if self.mode=='zero_reviewer':row['reviewedBy']['id']='00000000-0000-0000-0000-000000000000'
   if self.mode=='future_decision':row['reviewedDateTime']=(self.now+timedelta(days=1)).isoformat()
   if self.mode=='not_reviewed':row.update(decision='NotReviewed',reviewedDateTime=None)
   if self.mode=='deny_decision':row['decision']='Deny'
   return {'value':[] if self.mode in ('missing_decisions','new_guest') else [row]}
  return {'value':[]}

@pytest.mark.parametrize('mode,expected',[
 ('review_before_creation',['UNKNOWN']*2),('future_guest',['UNKNOWN']*2),('multistage',['UNKNOWN']*2),('unknown_definition_state',['UNKNOWN']*2),
 ('complete',['PASS']*2),('deny_decision',['PASS']*2),('no_definitions',['FAIL']*2),('missing_decisions',['FAIL']*2),
 ('not_reviewed',['FAIL']*2),('new_guest',['UNKNOWN']*2),('late_latest',['FAIL','PASS']),('no_instances',['UNKNOWN']*2),
 ('old_instances',['UNKNOWN']*2),('gap',['UNKNOWN']*2),('bad_timezone',['UNKNOWN']*2),('inactive_schedule',['UNKNOWN']*2),
 ('application_scope',['UNKNOWN']*2),('unknown_scope',['UNKNOWN']*2),('dynamic',['UNKNOWN']*2),('relative_scope',['UNKNOWN']*2),
 ('malformed_user',['UNKNOWN']*2),('duplicate_user',['UNKNOWN']*2),('malformed_principal',['UNKNOWN']*2),('foreign_resource',['UNKNOWN']*2),
 ('wrong_instance',['UNKNOWN']*2),('zero_reviewer',['UNKNOWN']*2),('future_decision',['UNKNOWN']*2),('denied_definitions',['DENIED']*2),
 ('denied_instances',['DENIED']*2),('denied_decisions',['DENIED']*2),('denied_users',['DENIED']*2),('denied_groups',['DENIED']*2),
 ('partial_definitions',['UNKNOWN']*2),('no_guest',['NOT_APPLICABLE']*2),('empty_users',['NOT_APPLICABLE']*2),('foreign_tenant',['UNKNOWN']*2)])
def test_actual_native_access_review_pipeline(mode,expected,monkeypatch):
 api=API(mode)
 if mode=='foreign_tenant':api.tenant=api.verified_tenant='99999999-9999-9999-9999-999999999999'
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
 policy={'sw25':{'status':'collected','scope':SCOPE,'checks':{cid:{'maxReviewAgeDays':90} for cid in CHECKS}}}
 connector={'provider':'azure','scopes':[SUB],'options':{'retries':0,'compliance_policy':policy}}
 snapshot=collect_live(connector,plan_collection({'connector':connector,'checks':CHECKS}))
 assert snapshot['metadata']['compliance_policy']['sw25']==policy['sw25']
 assert 'completedDateTime' not in json.dumps(snapshot)
 assert 'private-marker' not in json.dumps(snapshot)
 report=evaluate_snapshot(snapshot,checks=CHECKS,include_not_applicable=True)
 actual={cid:[f['status'] for f in report['findings'] if f['check_id']==cid] for cid in CHECKS}
 assert all(actual[cid] and set(actual[cid])=={value} for cid,value in zip(CHECKS,expected)),actual
 assert all(body is None or url.startswith(azure.ARM+'/providers/Microsoft.ResourceGraph/resources?') for url,audience,body in api.calls)

@pytest.mark.parametrize('cid',[
 'azure.cis.access_review_up_external_users_in_entra_privileged_identity_694482',
 'azure.cis.non_privileged_role_assignments_periodically_reviewed',
 'azure.cis.privileged_role_assignments_periodically_reviewed',
 'azure.cis.tenant_creator_role_assignments_periodically_reviewed'])
def test_native_users_never_claim_role_or_pim_coverage(cid,monkeypatch):
 api=API('complete');monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
 connector={'provider':'azure','scopes':[SUB],'options':{'retries':0}}
 snapshot=collect_live(connector,plan_collection({'connector':connector,'checks':[cid]}))
 report=evaluate_snapshot(snapshot,checks=[cid],include_not_applicable=True)
 findings=[f for f in report['findings'] if f['check_id']==cid]
 assert findings and all(f['status']=='UNKNOWN' for f in findings)

@pytest.mark.parametrize('mode,expected',[
 ('complete',['PASS','PASS']),('deny_decision',['PASS','PASS']),
 ('no_definitions',['UNKNOWN','UNKNOWN']),('missing_decisions',['UNKNOWN','UNKNOWN']),
 ('not_reviewed',['UNKNOWN','UNKNOWN']),('late_latest',['UNKNOWN','UNKNOWN']),
 ('new_guest',['UNKNOWN','UNKNOWN']),('old_instances',['UNKNOWN','UNKNOWN']),
 ('gap',['UNKNOWN','UNKNOWN']),('dynamic',['UNKNOWN','UNKNOWN']),
 ('application_scope',['UNKNOWN','UNKNOWN']),('future_decision',['UNKNOWN','UNKNOWN']),
 ('denied_users',['DENIED','DENIED']),('denied_definitions',['DENIED','DENIED']),
 ('denied_instances',['DENIED','DENIED']),('denied_decisions',['DENIED','DENIED']),
 ('partial_definitions',['UNKNOWN','UNKNOWN']),('foreign_tenant',['UNKNOWN','UNKNOWN']),
 ('no_guest',['NOT_APPLICABLE','NOT_APPLICABLE'])])
def test_source_wide_no_company_policy_with_real_collector(mode,expected,monkeypatch):
 api=API(mode)
 if mode=='foreign_tenant':api.tenant=api.verified_tenant='99999999-9999-9999-9999-999999999999'
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
 connector={'provider':'azure','scopes':[SUB],'options':{'retries':0}}
 snapshot=collect_live(connector,plan_collection({'connector':connector,'checks':CHECKS}))
 assert not snapshot['metadata'].get('compliance_policy')
 report=evaluate_snapshot(snapshot,checks=CHECKS,include_not_applicable=True)
 actual={cid:[f['status'] for f in report['findings'] if f['check_id']==cid] for cid in CHECKS}
 assert all(actual[cid] and set(actual[cid])=={value} for cid,value in zip(CHECKS,expected)),actual
 assert all(body is None or url.startswith(azure.ARM+'/providers/Microsoft.ResourceGraph/resources?')
            for url,audience,body in api.calls)

@pytest.mark.parametrize('policy',[
 {'sw25':{'status':'collected','scope':'/subscriptions/99999999-9999-9999-9999-999999999999','checks':{}}},
 {'sw25':{'status':'partial','scope':SCOPE,'checks':{}}}])
def test_explicit_malformed_company_policy_does_not_default(policy,monkeypatch):
 api=API('complete');monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
 connector={'provider':'azure','scopes':[SUB],'options':{'retries':0,'compliance_policy':policy}}
 snapshot=collect_live(connector,plan_collection({'connector':connector,'checks':CHECKS}))
 report=evaluate_snapshot(snapshot,checks=CHECKS,include_not_applicable=True)
 actual={cid:[f['status'] for f in report['findings'] if f['check_id']==cid] for cid in CHECKS}
 assert all(actual[cid] and set(actual[cid])=={'UNKNOWN'} for cid in CHECKS),actual

def test_source_wide_calendar_month_31_day_case_is_unknown_not_permissive_pass(monkeypatch):
 api=API('complete')
 api.now=datetime(2026,4,1,12,tzinfo=timezone.utc)
 begin=datetime(2026,3,1,12,tzinfo=timezone.utc)
 api.instances=[{'id':'77777777-7777-7777-7777-777777777771',
                 'startDateTime':begin.isoformat(),
                 'endDateTime':(begin+timedelta(hours=12)).isoformat(),
                 'status':'Completed'}]
 original_request=api.request
 def request(url,*,body=None,audience=azure.ARM):
  answer=original_request(url,body=body,audience=audience)
  if urlsplit(url).path==ROOT and answer.get('value'):
   answer['value'][0]['settings']['recurrence']['pattern']={
    'type':'absoluteMonthly','interval':1,'dayOfMonth':1}
  return answer
 api.request=request
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
 connector={'provider':'azure','scopes':[SUB],'options':{'retries':0}}
 snapshot=collect_live(connector,plan_collection({'connector':connector,'checks':CHECKS}))
 report=evaluate_snapshot(snapshot,checks=CHECKS,include_not_applicable=True)
 actual={cid:[f['status'] for f in report['findings'] if f['check_id']==cid] for cid in CHECKS}
 assert all(actual[cid] and set(actual[cid])=={'UNKNOWN'} for cid in CHECKS),actual
 assert all(body is None for url,audience,body in api.calls)
