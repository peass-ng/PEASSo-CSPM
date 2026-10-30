"""Union boundaries: owner inputs before I/O and the exact new IAM delta."""
import copy,json
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from fastapi import HTTPException
from peaso.collectors import azure
from peaso.server.validation import validate_connector
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from scripts import peaso_deploy_customer_policy as policy
from test_peaso_azure_diagnostics_storage_retention import fixture,API,SUB,SCOPE,CHECK,ROUTES
OPS=[('iam','get_role'),('iam','get_context_keys_for_principal_policy'),('iam','simulate_principal_policy'),('codecommit','list_repositories'),('codecommit','list_pull_requests'),('codecommit','get_pull_request'),('codecommit','describe_pull_request_events'),('codecommit','get_pull_request_approval_states')]
ACTIONS=['iam:GetRole','iam:GetContextKeysForPrincipalPolicy','iam:SimulatePrincipalPolicy','codecommit:ListRepositories','codecommit:ListPullRequests','codecommit:GetPullRequest','codecommit:DescribePullRequestEvents','codecommit:GetPullRequestApprovalStates']

@pytest.mark.parametrize('op,action',list(zip(OPS,ACTIONS)))
def test_exact_one_metadata_read_never_adds_another_grant(op,action):
 docs=policy.split_policy(policy.build_policy({op},include_credential_report_generation=False))
 statements=[s for d in docs for s in d['Statement']]
 assert len(statements)==1 and statements[0]['Action']==action and statements[0]['Effect']=='Allow'
 resource=statements[0]['Resource']
 if action.startswith('iam:'):assert resource=={'Fn::Sub':'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*'}
 elif op[1]=='list_repositories':assert resource=='*'
 else:assert resource=={'Fn::Sub':'arn:${AWS::Partition}:codecommit:*:${AWS::AccountId}:*'}
 assert all(policy.policy_size(d)<=6144 for d in docs)


@pytest.mark.parametrize('mode',['injected_observation','invalid_retention','foreign_scope','bad_options'])
def test_direct_library_rejects_invalid_owner_inputs_before_transport(mode,monkeypatch):
 _,owner,_=fixture();options={'compliance_parameters':{'azure_resource_logging':copy.deepcopy(owner)}}
 if mode=='injected_observation':options['compliance_parameters']['azure_resource_logging']['complete']=True
 if mode=='invalid_retention':options['compliance_parameters']['azure_resource_logging']['resources'][0]['minRetentionDays']=True
 if mode=='foreign_scope':
  foreign='/subscriptions/22222222-2222-2222-2222-222222222222'
  value=options['compliance_parameters']['azure_resource_logging'];value['scope']=foreign
  for row in value['resources']:
   row['resourceId']=row['resourceId'].replace(SCOPE,foreign);row['approvedSinkIds']=[s.replace(SCOPE,foreign)for s in row['approvedSinkIds']]
 if mode=='bad_options':options=[]
 transport=Mock(side_effect=AssertionError('cloud I/O forbidden'));factory=Mock(side_effect=AssertionError('credential resolution forbidden'))
 monkeypatch.setattr(azure,'AzureTransport',factory);monkeypatch.setattr(azure,'AzureTransportExposure',factory)
 with pytest.raises(ValueError):azure.collect({'provider':'azure','scopes':[SUB],'options':options},['azure_diagnostic_eligible_resource'],transport=transport)
 assert transport.call_count==factory.call_count==0


@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('provider',['aws','gcp','k8s'])
def test_hosted_and_local_namespace_is_azure_only(auth_mode,provider):
 _,owner,_=fixture();options={'compliance_parameters':{'azure_resource_logging':owner}}
 with pytest.raises(HTTPException)as caught:validate_connector(provider,{},options,SimpleNamespace(auth_mode=auth_mode))
 assert caught.value.status_code==422


@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_owner_policy_roundtrips_intake_to_native_evaluation(auth_mode):
 responses,owner,_=fixture();options={'retries':1,'compliance_parameters':{'azure_resource_logging':owner}}
 original=copy.deepcopy(options);validate_connector('azure',{'method':'token','arm_token':'fixture-token'},options,SimpleNamespace(auth_mode=auth_mode))
 assert options==original
 connector={'provider':'azure','scopes':[SUB],'options':options}
 snapshot=azure.collect(connector,plan_collection({'connector':connector,'checks':[CHECK,ROUTES]}),transport=API(responses))
 findings=evaluate_snapshot(snapshot,checks=[CHECK,ROUTES])['findings']
 assert {f['check_id']:f['status']for f in findings}=={CHECK:'PASS',ROUTES:'PASS'}


def test_repeated_policy_generation_reuses_every_sdk_model_name_map():
 # More than64 services are exercised by the actual current generator.
 # This catches bounded-cache thrashing without a flaky timing threshold.
 policy._sdk_operation_names.cache_clear()
 first=json.dumps(policy.build_policy(),sort_keys=True,separators=(',',':'))
 cold=policy._sdk_operation_names.cache_info()
 second=json.dumps(policy.build_policy(),sort_keys=True,separators=(',',':'))
 warm=policy._sdk_operation_names.cache_info()
 assert first==second
 assert cold.misses>64
 assert warm.misses==cold.misses
 assert warm.hits>cold.hits


# Reuse a synthetic CA fixture; this test exercises only the newly composed path.
from tests.test_peaso_azure_aks_workloads_native import ca


def test_private_union_aks_databricks_and_route_policy_survive_one_public_pipeline(monkeypatch,ca):
 from tests import test_peaso_azure_aks_workloads_native as aks
 from tests import test_peaso_azure_databricks_native as db
 from peaso.collectors import k8s
 from tests.archived_check_contract import collect_snapshot
 routes,_,options,auth,Api=aks.fixture(ca)
 raw=db.parent(db.RID,'Microsoft.Databricks/workspaces',{'workspaceId':'123','provisioningState':'Succeeded'})
 row={'workspace_id':123,'account_id':db.ACCOUNT,'workspace_status':'RUNNING','cloud':'azure','azure_workspace_info':{'subscription_id':db.SUB,'resource_group':'rg'}}
 routes.update({db.SCOPE+'/providers/Microsoft.Databricks/workspaces':{'value':[raw]},db.RID:raw,db.PATH:[row],db.PATH+'/123':row,db.PATH+'/123/metastore':{'metastore_assignment':{'workspace_id':123,'metastore_id':db.META}}})
 table=db.BASE+'Microsoft.Network/routeTables/routes'
 route=db.parent(table,'Microsoft.Network/routeTables',{'routes':[{'id':table+'/routes/approved','properties':{'addressPrefix':'10.0.0.0/24'}}]})
 routes[db.SCOPE+'/providers/Microsoft.Network/routeTables']={'value':[route]}
 routes[table]=route
 # Complete ARG must include the same native AKS parent as the ARM list.
 resources=[raw,route,routes[aks.RID]]
 routes[db.SCOPE+'/resources']={'value':resources}
 routes['/providers/Microsoft.ResourceGraph/resources']={'data':resources,'count':3,'totalRecords':3,'resultTruncated':'false'}
 owner=db.policy();owner['sw33']['routeDestinations']={'routeTableIds':[table],'allowedDestinationCidrs':['10.0.0.0/8']}
 owner['sw33']['backupAlerts']={'responseWindowMinutes':5}
 options.update(retries=1,compliance_policy=owner)
 auth['databricks_account_token']=db.TOKEN
 validate_connector('azure',auth,options,SimpleNamespace(auth_mode='cognito'))
 arm=db.API(routes);arm.close=lambda:None;apis=[]
 def new_api(context):
  api=Api();apis.append(api);return api
 monkeypatch.setattr(azure,'AzureTransport',lambda auth:arm);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:arm);monkeypatch.setattr(k8s,'_new_api',new_api)
 route_check='azure_route_table_network_http_internet_access_restricted_5cd2484'
 checks=[aks.native.IMAGES,aks.native.PORTS,db.CHECK,route_check]
 snapshot=collect_snapshot({'connector':{'provider':'azure','scopes':[db.SUB],'auth':auth,'options':options},'checks':checks})
 report=evaluate_snapshot(snapshot,checks=checks)
 assert {f['check_id']:f['status']for f in report['findings']}=={cid:'PASS'for cid in checks}, {'findings': report['findings'], 'collections': [{k:row[k] for k in ('type','status','scope','error') if k in row} for row in snapshot['collections']], 'API_calls': [a.calls for a in apis]}
 assert snapshot['metadata']['compliance_policy']['sw33']['backupAlerts']=={'responseWindowMinutes':5}
 assert all(api.closed for api in apis) and apis
 encoded=json.dumps(snapshot)+json.dumps(report)
 assert aks.TOKEN not in encoded and db.TOKEN not in encoded
