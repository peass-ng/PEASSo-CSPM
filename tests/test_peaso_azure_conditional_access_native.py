"""Actual collect_live -> sealed snapshot -> registered engine, private source candidate."""
import copy
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit,parse_qs
import pytest
from peaso.collectors import azure,collect_live
from peaso.engine import evaluate_snapshot,plan_collection

SUB='11111111-1111-1111-1111-111111111111'
TENANT='22222222-2222-2222-2222-222222222222'
SCOPE='/tenants/'+TENANT
USERS='azure.cis.multifactor_authentication_policy_exists_users'
ADMIN='azure.cis.multifactor_authentication_policy_exists_administrative_groups'
RISK='azure.cis.multifactor_authentication_risky_sign_ins'
CHECKS=[USERS,ADMIN,RISK]
STRENGTH='00000000-0000-0000-0000-000000000004'

class API:
 tenant=verified_tenant=TENANT
 def __init__(self,mode):self.mode=mode;self.calls=[]
 def close(self):pass
 def request(self,url,*,body=None,audience=azure.ARM):
  self.calls.append((url,audience,body));path=urlsplit(url).path
  rule={'id':'ca-1','state':'enabled','conditions':{'users':{'includeUsers':['All'],'excludeUsers':[],
   'includeGroups':[],'excludeGroups':[],'includeRoles':[],'excludeRoles':[]},
   'applications':{'includeApplications':['All'],'excludeApplications':[]},'clientAppTypes':['all'],
   'locations':None,'platforms':None,'devices':None,'signInRiskLevels':[],'userRiskLevels':[],'authenticationFlows':None},
   'grantControls':{'operator':'AND','builtInControls':['mfa'],'authenticationStrength':None,
    'customAuthenticationFactors':[],'termsOfUse':[]}}
  if path=='/v1.0/identity/conditionalAccess/policies':
   if self.mode=='denied_ca':raise azure.AzureReadError('forbidden',403)
   if self.mode=='empty_ca':return {'value':[]}
   if self.mode=='disabled':rule['state']='disabled'
   if self.mode=='reportonly':rule['state']='enabledForReportingButNotEnforced'
   if self.mode=='conditional_risk':rule['conditions']['signInRiskLevels']=['high']
   if self.mode=='device':rule['conditions']['devices']={'deviceFilter':{'mode':'exclude','rule':'x'}}
   if self.mode in ('strength','future_strength','denied_strength'):
    rule['grantControls'].update(builtInControls=[],authenticationStrength={'id':STRENGTH})
    rule['grantControls']['authenticationStrength@odata.context']='https://graph.microsoft.com/v1.0/$metadata#strength'
   if self.mode=='partial_ca' and '$skiptoken' in parse_qs(urlsplit(url).query):raise azure.AzureReadError('forbidden',403)
   result={'value':[rule]}
   if self.mode=='partial_ca':result['@odata.nextLink']=azure.GRAPH+path+'?$skiptoken=next'
   return result
  if path=='/v1.0/users':
   if self.mode=='denied_users':raise azure.AzureReadError('forbidden',403)
   return {'value':[] if self.mode=='empty_users' else [{'id':'user-1','accountEnabled':True,'userType':'Member','isMfaRegistered':True}]}
  if path=='/v1.0/policies/identitySecurityDefaultsEnforcementPolicy':
   if self.mode=='denied_defaults':raise azure.AzureReadError('forbidden',403)
   return {'id':'defaults','isEnabled':self.mode=='defaults'}
  if path=='/v1.0/policies/authenticationStrengthPolicies':
   if self.mode=='denied_strength':raise azure.AzureReadError('forbidden',403)
   return {'value':[{'id':STRENGTH,'requirementsSatisfied':'mfa',
    'allowedCombinations':['futureMethod' if self.mode=='future_strength' else 'fido2']} ]}
  return {'value':[]}

@pytest.mark.parametrize('mode,expected',[('complete',['PASS']*3),('strength',['PASS']*3),
 ('future_strength',['UNKNOWN']*3),('denied_strength',['UNKNOWN']*3),('denied_ca',['DENIED']*3),
 ('empty_ca',['EMPTY']*3),('denied_users',['UNKNOWN']*3),('denied_defaults',['UNKNOWN']*3),
 ('foreign',['UNKNOWN']*3),('conditional_risk',['UNKNOWN']*3),('device',['UNKNOWN']*3),
 ('partial_ca',['UNKNOWN']*3),('empty_users',['UNKNOWN']*3),('defaults',['UNKNOWN']*3),
 ('disabled',['FAIL','UNKNOWN','UNKNOWN']),('reportonly',['FAIL','UNKNOWN','UNKNOWN'])])
def test_actual_collect_live_and_signed_engine_mfa(mode,expected,monkeypatch):
 api=API(mode)
 if mode=='foreign':api.tenant=api.verified_tenant='33333333-3333-3333-3333-333333333333'
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:api)
 monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
 now=datetime.now(timezone.utc)
 policy={'sw13':{'status':'collected','scope':SCOPE,'authorized_by':'security-owner','document_id':'owner-obligation',
  'observed_at':(now-timedelta(days=1)).isoformat(),'expires_at':(now+timedelta(days=1)).isoformat(),
  'checks':{cid.replace('.','|'):{'userScope':'administrative' if cid==ADMIN else 'all',
   'designatedGroups':['admin-group'],'designatedRoles':[],'requiredApplications':['app-1'],
   'requiredClientAppTypes':['browser']} for cid in CHECKS}}}
 connector={'provider':'azure','scopes':[SUB],'options':{'retries':0,'compliance_policy':policy}}
 requirements=plan_collection({'connector':connector,'checks':CHECKS})
 assert 'authentication_strength' in requirements
 snapshot=collect_live(connector,requirements)
 assert snapshot['metadata']['compliance_policy']['sw13']==policy['sw13']
 report=evaluate_snapshot(snapshot,checks=CHECKS,include_not_applicable=True)
 actual={cid:[f['status'] for f in report['findings'] if f['check_id']==cid] for cid in CHECKS}
 assert all(actual[cid] and set(actual[cid])=={status} for cid,status in zip(CHECKS,expected))
 assert all(body is None or url.startswith(azure.ARM+'/providers/Microsoft.ResourceGraph/resources?') for url,audience,body in api.calls)
 assert all(audience==azure.GRAPH for url,audience,body in api.calls if url.startswith(azure.GRAPH))
