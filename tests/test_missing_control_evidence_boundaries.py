"""Native registry regressions for invalid consumer and capture evidence.

Copy this file into tests/ together with the implementation patch. These tests
use actual registered predicates and package native fixtures, without module
stubs, cloud clients, or changes to existing fixture expectations.
"""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

CHECKS_BY_ID={check.id:check for check in CHECKS}
PERMISSION='aws.iam.identity_center.permission_set_has_consumer_all_accounts'

def fixture(check_id,branch='pass'):
 case=CASES[check_id]
 return deepcopy(case[branch]),deepcopy(case[branch+'_index'])

def synchronize(item,index,kind):
 index['collections'][kind][0]['items']=[item]
 if kind in index:
  index[kind][0]['data']=item

def evaluate(check_id,item,index):
 return CHECKS_BY_ID[check_id].evaluate(item,index)[0]

@pytest.mark.parametrize('mode',['null_assignment','foreign_assignment','duplicate_assignment','bad_principal','foreign_provisioned'])
def test_permission_set_rejects_invalid_consumer_declarations(mode):
 item,index=fixture(PERMISSION);kind='aws_identity_center_permission_set_consumer'
 account=item['OrganizationAccounts'][0]
 assignment={'AccountId':account,'PrincipalType':'USER','PrincipalId':'00000000-0000-4000-8000-000000000000'}
 item.update(Assignments=[assignment],ProvisionedAccounts=[],ProvisioningStates={})
 if mode=='null_assignment':item['Assignments']=[None]
 elif mode=='foreign_assignment':assignment['AccountId']='999999999999'
 elif mode=='duplicate_assignment':item['Assignments'].append(deepcopy(assignment))
 elif mode=='bad_principal':assignment['PrincipalId']='invalid'
 elif mode=='foreign_provisioned':
  item.update(Assignments=[],ProvisionedAccounts=['999999999999'],ProvisioningStates={'999999999999':'latest_provisioned'})
 synchronize(item,index,kind)
 assert evaluate(PERMISSION,item,index)=='UNKNOWN'

@pytest.mark.parametrize('mode',['partial_organization','other_account_denied'])
def test_valid_permission_set_assignment_survives_incomplete_reads(mode):
 item,index=fixture(PERMISSION);kind='aws_identity_center_permission_set_consumer'
 account=item['OrganizationAccounts'][0]
 item.update(Assignments=[{'AccountId':account,'PrincipalType':'USER','PrincipalId':'00000000-0000-4000-8000-000000000000'}],ProvisionedAccounts=[],ProvisioningStates={})
 item['_provenance']['all_accounts_checked']=False
 if mode=='partial_organization':item['_provenance']['organization_accounts_complete']=False
 else:item['status']='denied'
 index['collections'][kind][0]['status']='partial'
 synchronize(item,index,kind)
 assert evaluate(PERMISSION,item,index)=='PASS'

@pytest.mark.parametrize('expressions',[
 [{'key':'app','operator':'Unknown'}],
 [{'key':'app','operator':'In','values':['absent']},{'key':'app','operator':'Unknown'}],
])
def test_networkpolicy_validates_every_selector_expression_without_pods(expressions):
 cid='k8s.network.networkpolicy_selects_current_pod'
 item,index=fixture(cid,'fail')
 item['spec']['podSelector']={'matchExpressions':expressions}
 synchronize(item,index,'networkpolicy')
 index['pod']=[];index['collections']['pod'][0].update(status='empty',items=[])
 assert evaluate(cid,item,index)=='UNKNOWN'

def test_ingress_rejects_malformed_http_path():
 cid='k8s.network.ingress_service_backends_resolve'
 item,index=fixture(cid);item['spec']={'rules':[{'http':{'paths':[None]}}]}
 synchronize(item,index,'ingress')
 assert evaluate(cid,item,index)=='UNKNOWN'

@pytest.mark.parametrize('cid,kind',[
 ('azure.network.nic_has_owner_reference','nic'),
 ('azure.network.public_ip_has_network_reference','public_ip'),
 ('azure.network.route_table_has_subnet_reference','route_table'),
])
def test_azure_network_rejects_resource_from_another_declared_capture(cid,kind):
 item,index=fixture(cid)
 credential='a'*32
 metadata={'collection':'read-only','credential_context_id':credential,'customer_context_id':'scan-local:'+credential}
 index['context']['metadata']=metadata
 index['collections'][kind][0]['_provenance']={k:metadata[k] for k in ('credential_context_id','customer_context_id')}
 item['_provenance'].update(credential_context_id='b'*32,customer_context_id='scan-local:'+'b'*32)
 synchronize(item,index,kind)
 assert evaluate(cid,item,index)=='UNKNOWN'
