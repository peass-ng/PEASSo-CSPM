"""Signed PSC configuration verdicts and native producer integration."""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import pytest
from peaso.gcp_psc_policy import OPTION,normalize
from peaso.checks import gcp_psc_dns as m

from tests.release_successor_history import (ancestor_json, ancestor_bytes, ancestor_sha, registered_before_bulk, registry_source_before_bulk)
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


def test_signed_intake_changes_only_one_requirement_and_one_description():
 # Compare the historical admission with its immutable views. Later, unrelated
 # AWS admissions legitimately change the working manifest and descriptions.
 from pathlib import Path
 import json,zipfile,hashlib
 root=Path(__file__).resolve().parents[1]
 version='e022caf8ffd81b18571939a12313dfd9afa60c8f2095239cf3ad25e3002a31b7'
 from tests.release_successor_history import historical_bytes
 archive_path=root/'infra/aws/build'/('peaso-source-'+version+'.zip')
 ledger=root/'docs/compliance-ledgers'
 before=json.loads(historical_bytes(archive_path, 'docs/compliance-ledgers/gcp-cis-cft.json'))
 after=json.loads((ledger/'gcp-cis-cft.json').read_text())
 for data in [before,after]:
  row=next(r for fw in data['frameworks'] if fw['id']=='cis_5.0_gcp' for r in fw['requirements'] if r['requirement_id']=='3.9')
  if data is after:
   assert row['decision']=='PARTIAL'
   assert 'firewall enforcement' in row['reason']
  row.pop('decision');row.pop('reason')
 assert before==after
 import gzip
 from tests.release_successor_history import historical_release, ANCESTOR_MANIFEST
 packed=(root/'tests/fixtures/gcp-psc-admission-history.json.gz').read_bytes()
 assert hashlib.sha256(packed).hexdigest()=='e3ce566868d26c6d34d6bcc03433b92fb1138af871ee8709111a5e5eb27f7a0c'
 history=json.loads(gzip.decompress(packed))
 assert history['historical_release']==version
 release=historical_release(archive_path)
 for name,text in history['original_members'].items():
  assert hashlib.sha256(text.encode()).hexdigest()==release['files'][name]
 ancestor=history['ancestor_members']
 assert hashlib.sha256(ancestor['docs/compliance-ledgers/manifest.json'].encode()).hexdigest()==ANCESTOR_MANIFEST
 old_manifest=json.loads(history['original_members']['docs/compliance-ledgers/manifest.json'])
 current_manifest=json.loads(ancestor['docs/compliance-ledgers/manifest.json'])
 assert set(old_manifest)==set(current_manifest)
 for key in old_manifest:
  if key not in ['slices','new_descriptions']:assert old_manifest[key]==current_manifest[key]
 for name,entry in old_manifest['slices'].items():
  newer=current_manifest['slices'][name]
  if name in json.loads((root/'tests/fixtures/post_dfaf_integration/two_hour_native_cohort.json').read_text())['changed_slices']:
   assert {k for k in entry if entry[k]!=newer[k]}=={'sha256'}
   if name.startswith('gcp'):
    assert newer['sha256']==hashlib.sha256((ledger/entry['path']).read_bytes()).hexdigest()
  else:assert entry==newer
 old=json.loads(history['original_members']['docs/compliance-ledgers/descriptions/implemented-new-checks.json'])
 text=ancestor['docs/compliance-ledgers/descriptions/implemented-new-checks.json']
 assert hashlib.sha256(text.encode()).hexdigest()==current_manifest['new_descriptions']['sha256']
 new=json.loads(text)
 additive=set(json.loads((root/'tests/fixtures/post_dfaf_integration/two_hour_native_cohort.json').read_text())['ids'])|{m.CHECK_ID}
 assert set(new)-set(old)==additive
 assert {k:v for k,v in new.items() if k not in additive}==old
