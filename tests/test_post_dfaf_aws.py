"""Portable tests: copy bundle files into repo-native paths without rewriting."""
import importlib.util
import json
import sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
for name in ('post_dfaf_aws_specs','post_dfaf_aws'):
 full='peaso.checks.'+name
 spec=importlib.util.spec_from_file_location(full,ROOT/'peaso/checks'/f'{name}.py')
 module=importlib.util.module_from_spec(spec);sys.modules[full]=module;spec.loader.exec_module(module)
batch=sys.modules['peaso.checks.post_dfaf_aws']
FIXTURES=json.loads((ROOT/'tests/fixtures/post_dfaf_aws.json').read_text())

@pytest.mark.parametrize('fixture',FIXTURES,ids=lambda f:f['id']+':'+f['name'])
def test_signed_predicate(fixture):
 status,evidence=batch.EVALUATORS[fixture['id']](fixture['item'],fixture['index'])
 assert status==fixture['expected'],evidence
 assert isinstance(evidence,dict)

def test_signed_contract_and_no_registry_mutation():
 from peaso.checks import CHECKS
 public_ids={c.id for c in CHECKS}
 assert set(batch.EVALUATORS)&public_ids == set(batch.READY_IDS) | {'aws.nist.rds_cluster_member_enhanced_monitoring', 'aws_nist_efs_access_point_enforce_root_directory'}
 assert set(batch.EVALUATORS)==set(batch.SPECS)
 for check in batch.CANDIDATES:
  row=batch.SPECS[check.id]
  assert (check.provider,check.category,check.severity,check.title,check.remediation)==(row['provider'],row['category'],row['severity'],row['title'],row['remediation_hint'])
  names={f['expected'] for f in FIXTURES if f['id']==check.id}
  assert {'PASS','FAIL','UNKNOWN'}<=names


def test_registry_path_isolated(monkeypatch):
 import peaso.checks as registry
 isolated=[]
 monkeypatch.setattr(registry,'CHECKS',isolated)
 batch.install()
 assert {c.id for c in isolated} == set(batch.READY_IDS)
 by_id={c.id:c for c in isolated}
 for fixture in FIXTURES:
  if fixture['id'] not in batch.READY_IDS:
   continue
  check=by_id[fixture['id']]
  assert check.evaluate(fixture['item'],fixture['index'])[0]==fixture['expected']
  signed=batch.SPECS[check.id]
  assert check.category==(signed['category'] if signed['category'] in {'hardening','exposure','least_privilege','iam_graph','network'} else 'hardening')
  assert check.severity==signed['severity']


@pytest.mark.parametrize('cid,dependency',[
 ('aws_vpc_uses_amazonprovided_dns','dhcp_options'),
 ('aws.nist.rds_cluster_member_enhanced_monitoring','rds_instance'),
 ('aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days','elasticache_cluster')])
def test_repeated_joins_are_memoized(cid,dependency):
 from peaso.checks.facts import MemoIndex
 class CountedList(list):
  iterations=0
  def __iter__(self):
   self.iterations+=1
   return super().__iter__()
 fixture=next(f for f in FIXTURES if f['id']==cid and f['name']=='pass')
 index=MemoIndex(fixture['index'])
 counted=CountedList(index[dependency]);index[dependency]=counted
 check=batch.EVALUATORS[cid]
 assert check(fixture['item'],index)[0]=='PASS'
 initial=counted.iterations
 assert initial>0
 for _ in range(20):assert check(fixture['item'],index)[0]=='PASS'
 assert counted.iterations==initial


@pytest.mark.parametrize('cid,kind,producer',[
 ('aws_g6_elbv2_only_https_tls_listeners','load_balancer_v2','_lb'),
 ('aws_g6_api_stage_valid_client_certificate','rest_api_stage','_stage'),
 ('aws_shield_automatic_application_layer_response','shield_protection','_shield')])
def test_actual_swc_producer_shapes(cid,kind,producer):
 import copy
 from peaso.collectors import aws_facts_swc
 from peaso.collectors.aws import ReadResult
 fixture=copy.deepcopy(next(f for f in FIXTURES if f['id']==cid and f['name']=='pass'))
 raw=copy.deepcopy(fixture['item'])
 class OfflineRequests:
  def pages(self,session,service,region,operation,expression,**arguments):
   assert (service,operation)==('elbv2','describe_listeners')
   return ReadResult(copy.deepcopy(fixture['item']['Listeners']['items']),'collected')
  def detail(self,session,service,region,operation,**arguments):
   if operation=='get_client_certificate':return copy.deepcopy(fixture['item']['ClientCertificate'])
   if operation=='describe_protection':return {'collection_status':'collected','Protection':{'Id':'p1','ApplicationLayerAutomaticResponseConfiguration':{'Status':'ENABLED'}}}
   if operation=='get_health_check':return {'collection_status':'collected','HealthCheck':{'Id':'h1'}}
   raise AssertionError('unexpected producer request')
 if producer=='_lb':raw.pop('Listeners')
 if producer=='_stage':raw.pop('ClientCertificate')
 if producer=='_shield':raw.pop('Protection');raw.pop('HealthChecks')
 item=getattr(aws_facts_swc,producer)(OfflineRequests(),object(),'us-east-1',[raw])[0]
 fixture['index']['collections'][kind][0]['items']=[item]
 fixture['index'][kind][0]['data']=item
 assert batch.EVALUATORS[cid](item,fixture['index'])[0]=='PASS'


@pytest.mark.parametrize('rule_action,expected',[
 ({'Type':'redirect','RedirectConfig':{'Protocol':'HTTPS','Port':'443'}},'PASS'),
 ({'Type':'forward','TargetGroupArn':'arn:tg'},'FAIL')])
def test_swc_producer_collects_http_redirect_rules(rule_action,expected):
 import copy
 from peaso.collectors import aws_facts_swc
 from peaso.collectors.aws import ReadResult
 cid='aws_g6_elbv2_only_https_tls_listeners'
 fixture=copy.deepcopy(next(f for f in FIXTURES if f['id']==cid and f['name']=='pass'))
 raw=copy.deepcopy(fixture['item']);raw.pop('Listeners')
 https=copy.deepcopy(fixture['item']['Listeners']['items'][0])
 redirect=[{'Type':'redirect','Order':1,'RedirectConfig':{'Protocol':'HTTPS','Port':'443','StatusCode':'HTTP_301'}}]
 http={'ListenerArn':https['ListenerArn']+'-http','Protocol':'HTTP','Port':80,'DefaultActions':redirect}
 calls=[]
 class OfflineRequests:
  def pages(self,session,service,region,operation,expression,**arguments):
   calls.append(operation)
   if operation=='describe_listeners':return ReadResult([copy.deepcopy(https),copy.deepcopy(http)],'collected')
   assert operation=='describe_rules' and arguments=={'ListenerArn':http['ListenerArn']}
   return ReadResult([{'RuleArn':'r1','Priority':'10','IsDefault':False,'Actions':[rule_action]},
                      {'RuleArn':'r0','Priority':'default','IsDefault':True,'Actions':copy.deepcopy(redirect)}],'collected')
 item=aws_facts_swc._lb(OfflineRequests(),object(),'us-east-1',[raw])[0]
 assert calls==['describe_listeners','describe_rules']
 fixture['index']['collections']['load_balancer_v2'][0]['items']=[item]
 fixture['index']['load_balancer_v2'][0]['data']=item
 assert batch.EVALUATORS[cid](item,fixture['index'])[0]==expected
