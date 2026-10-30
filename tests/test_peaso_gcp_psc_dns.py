"""Signed PSC configuration verdicts and native producer integration."""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import pytest
from peaso.gcp_psc_policy import OPTION,normalize
from peaso.checks import gcp_psc_dns as m

SCOPE='projects/demo';VPC='https://www.googleapis.com/compute/v1/projects/demo/global/networks/private'

def bundle():
 rules=[{'name':'psc','network':VPC,'target':'all-apis','IPAddress':'10.0.0.1'}]
 records=[{'name':'*.googleapis.com.','type':'A','managed_zone':'googleapis','network':VPC,'rrdatas':['10.0.0.1']}]
 groups={'forwarding_rule':rules,'dns_record':records}
 policy={'status':'approved','scope':SCOPE,'source_ref':'owner-test-scope','observed_at':'2026-10-14T00:00:00Z','max_age_seconds':86400,'required_vpcs':[VPC],'required_google_api_hostnames':['*.googleapis.com']}
 index={'context':{'provider':'gcp','scope':SCOPE,'created_at':'2026-10-14T01:00:00Z','metadata':{OPTION:policy}},'collections':{}}
 for kind,rows in groups.items():
  index['collections'][kind]=[{'type':kind,'scope':SCOPE,'status':'collected','items':rows}];index[kind]=[{'provider':'gcp','type':kind,'scope':SCOPE,'data':row} for row in rows]
 return {'scope':SCOPE},index

def test_pass_and_exact_missing_endpoint_dns_failures():
 item,index=bundle();before=deepcopy((item,index));assert m.evaluate(item,index)[0]=='PASS';assert (item,index)==before
 index['forwarding_rule'][0]['data']['target']='https://evil.invalid/all-apis';assert m.evaluate(item,index)[0]=='FAIL'
 item,index=bundle();index['dns_record'][0]['data']['rrdatas']=['10.0.0.2'];assert m.evaluate(item,index)[0]=='FAIL'

@pytest.mark.parametrize('kind', ['forwarding_rule','dns_record'])
@pytest.mark.parametrize('status', ['partial','denied','unknown'])
def test_unread_inventory_is_unknown(kind,status):
 item,index=bundle();index['collections'][kind][0]['status']=status;assert m.evaluate(item,index)[0]=='UNKNOWN'

@pytest.mark.parametrize('change', ['absent','expired','future','foreign','projection','ambiguous_zone','malformed_ip'])
def test_owner_and_native_fact_boundaries(change):
 item,index=bundle();p=index['context']['metadata'][OPTION]
 if change=='absent':index['context']['metadata'].clear()
 elif change=='expired':p['max_age_seconds']=1
 elif change=='future':p['observed_at']='2026-10-15T00:00:00Z'
 elif change=='foreign':p['scope']='projects/foreign'
 elif change=='projection':index['dns_record']=[]
 elif change=='ambiguous_zone':
  second={**index['dns_record'][0]['data'],'managed_zone':'another'};index['collections']['dns_record'][0]['items'].append(second);index['dns_record'].append({'provider':'gcp','type':'dns_record','scope':SCOPE,'data':second})
 elif change=='malformed_ip':index['dns_record'][0]['data']['rrdatas']=['not-an-ip']
 assert m.evaluate(item,index)[0]=='UNKNOWN'

def test_wildcard_cannot_be_treated_as_missing_specific_hostname():
 item,index=bundle();index['context']['metadata'][OPTION]['required_google_api_hostnames']=['storage.googleapis.com'];assert m.evaluate(item,index)[0]=='UNKNOWN'

def test_equivalent_native_network_url_hosts_join():
 item,index=bundle();index['dns_record'][0]['data']['network']=VPC.replace('www.googleapis.com','compute.googleapis.com');assert m.evaluate(item,index)[0]=='PASS'

@pytest.mark.parametrize('field,value',[('required_vpcs',[VPC,VPC]),('required_vpcs',[VPC.replace('demo','foreign')]),('required_google_api_hostnames',['example.com']),('max_age_seconds',True),('status','draft'),('source_ref','')])
def test_owner_input_rejects_unapproved_or_foreign_scope(field,value):
 item,index=bundle();p=index['context']['metadata'][OPTION];p[field]=value
 with pytest.raises(ValueError):normalize(p)


@pytest.mark.parametrize('approval_age_seconds,expected', [(0, 'PASS'), (86401, 'UNKNOWN'), (-3600, 'UNKNOWN')])
def test_native_collector_to_engine_preserves_policy_and_scores_one_project(approval_age_seconds, expected):
 from tests.test_peaso_collectors_gcp import snapshot
 from tests.archived_check_contract import evaluate_snapshot
 _,index=bundle();policy=index['context']['metadata'][OPTION]
 # Collection uses its real capture clock; keep the approved fixture relative to it.
 policy['observed_at']=(datetime.now(timezone.utc)-timedelta(seconds=approval_age_seconds)).isoformat()
 def resolve(request):
  if request['url'].endswith('/managedZones'):
   return {'managedZones':[{'name':'googleapis','dnsName':'googleapis.com.','visibility':'private','privateVisibilityConfig':{'networks':[{'networkUrl':VPC}]}}]}
  if request['url'].endswith('/managedZones/googleapis:getIamPolicy'):
   # 16bb81e0 hydrates each managed zone's IAM policy.
   return {'version':3,'bindings':[]}
  if request['url'].endswith('/rrsets'):
   return {'rrsets':[{'name':'*.googleapis.com.','type':'A','rrdatas':['10.0.0.1']}]}
  if request['url'].endswith('/aggregated/forwardingRules'):
   return {'items':{'global':{'forwardingRules':[{'name':'psc','network':VPC,'target':'all-apis','IPAddress':'10.0.0.1'}]}}}
  raise AssertionError(request['url'])
 native,_=snapshot(['forwarding_rule','dns_record'],resolve,scopes=[SCOPE],**{OPTION:policy})
 assert native['metadata'][OPTION]==policy
 report=evaluate_snapshot(native,checks=[m.CHECK_ID])
 findings=[f for f in report['findings'] if f['check_id']==m.CHECK_ID]
 assert len(findings)==1 and findings[0]['status']==expected
 assert any(c['framework_id']=='cis_5.0_gcp' and c['requirement_id']=='3.9' and c['runtime_status']=='partial'
            for c in next(c for c in __import__('peaso.checks',fromlist=['CHECKS']).CHECKS if c.id==m.CHECK_ID).public()['requirement_controls'])


@pytest.mark.parametrize('mode',['local','cognito'])
def test_web_and_cli_intake_accept_explicit_approved_policy(mode):
 from types import SimpleNamespace
 from peaso.server.validation import validate_connector
 _,index=bundle();policy=index['context']['metadata'][OPTION]
 validate_connector('gcp',{'method':'token','token':'fixture'},{OPTION:policy},SimpleNamespace(auth_mode=mode))


@pytest.mark.parametrize('provider',['aws','azure','k8s'])
def test_hosted_rejects_cross_provider_psc_policy(provider):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 _,index=bundle();policy=index['context']['metadata'][OPTION]
 with pytest.raises(HTTPException) as error:
  validate_connector(provider,{}, {OPTION:policy},SimpleNamespace(auth_mode='cognito'))
 assert error.value.status_code==422


