"""WAF companion reads preserve the existing customer's grants and trust."""
import copy
import hashlib
import json
from pathlib import Path
import pytest
from scripts import peaso_deploy_customer_policy as policy
from tests.customer_policy_history import historical_role_bytes, historical_derivative_sha256

EXPECTED={
 'appsync:GetWebACLForResource','appsync:ListResourcesForWebACL',
 'elasticloadbalancing:DescribeWebACLAssociation','cognito-idp:ListResourcesForWebACL',
 'apprunner:ListAssociatedServicesForWebAcl','ec2:DescribeVerifiedAccessInstanceWebAclAssociations',
}

def actions(document):
 return {a for s in document['Statement']for a in ([s['Action']]if isinstance(s['Action'],str)else s['Action'])}

def test_default_companion_policy_preserves_three_existing_documents_and_scopes():
 root=policy.REVIEWED_ROLE_PATH.parent
 before_hash='a57cdf166f64c9ad96a367a48fb62e54754a58a89ed767119f9dc46c05e46980'
 after_hash='0eeba5694a23a8fd93013b1c15dd2bfbc3f0ec4de7554a9a9405b0306b611e6d'
 before_raw=historical_role_bytes(before_hash)
 after_raw=historical_role_bytes(after_hash)
 assert hashlib.sha256(before_raw).hexdigest()==historical_derivative_sha256(before_hash)
 assert hashlib.sha256(after_raw).hexdigest()==historical_derivative_sha256(after_hash)
 baseline=json.loads(before_raw);updated=json.loads(after_raw)
 assert set(updated['Resources'])-set(baseline['Resources'])=={'CspmConfigurationReadOnly4'}
 assert all(updated['Resources'][key]==value for key,value in baseline['Resources'].items())
 assert updated['Parameters']==baseline['Parameters'] and updated['Outputs']==baseline['Outputs']
 documents=[updated['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument'] for i in range(1,5)]
 old=[baseline['Resources'][f'CspmConfigurationReadOnly{i}']['Properties']['PolicyDocument'] for i in range(1,4)]
 assert documents[:3]==old
 assert actions(documents[3])==EXPECTED
 assert all(policy.policy_size(d)<=6144 for d in documents)
 wildcard={a for s in documents[3]['Statement']if s['Resource']=='*'for a in ([s['Action']]if isinstance(s['Action'],str)else s['Action'])}
 assert wildcard=={'appsync:ListResourcesForWebACL','elasticloadbalancing:DescribeWebACLAssociation','ec2:DescribeVerifiedAccessInstanceWebAclAssociations'}
 scoped={s['Action']:s['Resource']['Fn::Sub']for s in documents[3]['Statement']if s['Resource']!='*'}
 assert scoped=={'appsync:GetWebACLForResource':'arn:${AWS::Partition}:appsync:*:${AWS::AccountId}:apis/*','cognito-idp:ListResourcesForWebACL':'arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:regional/webacl/*/*','apprunner:ListAssociatedServicesForWebAcl':'arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:regional/webacl/*/*'}
 for s in documents[3]['Statement']:
  assert s['Effect']=='Allow'
  if s['Resource']!='*':
   arn=s['Resource']['Fn::Sub'];assert '${AWS::Partition}'in arn and '${AWS::AccountId}'in arn
 assert all(not any(c in a for c in '*?')and a.split(':')[1].startswith(('Get','List','Describe'))for a in EXPECTED)

@pytest.mark.parametrize('operation,expected',[
 (('wafv2','get_web_acl_for_resource'),{'appsync:GetWebACLForResource'}),
 (('wafv2','list_resources_for_web_acl'),EXPECTED-{'appsync:GetWebACLForResource'}),
 (('ec2','describe_instances'),set()),
])
def test_only_requested_waf_operations_add_companion_reads(operation,expected):
 logical=policy.build_policy({operation},include_credential_report_generation=False)
 assert actions(logical)&EXPECTED==expected
 assert all(policy.policy_size(d)<=6144 for d in policy.split_policy(logical))

def test_refresh_is_idempotent_and_preserves_role_and_every_existing_resource(tmp_path):
 # Refresh today's template in isolation; historical grants are checked by archive transition above.
 folder=tmp_path/'infra/aws';folder.mkdir(parents=True)
 original_raw=(Path(__file__).resolve().parents[1]/'infra/aws/customer-role.json').read_bytes()
 original=json.loads(original_raw)
 path=folder/'customer-role.json';path.write_bytes(original_raw)
 policy.refresh(tmp_path);first=path.read_bytes();updated=json.loads(first)
 assert set(updated['Resources'])==set(original['Resources'])
 assert all(updated['Resources'][key]==value for key,value in original['Resources'].items()
            if not key.startswith('CspmConfigurationReadOnly'))
 assert updated['Parameters']==original['Parameters'] and updated['Outputs']==original['Outputs']
 documents=[r['Properties']['PolicyDocument'] for name,r in sorted(updated['Resources'].items()) if r['Type']=='AWS::IAM::ManagedPolicy']
 assert documents==policy.split_policy(policy.build_policy())
 assert all(policy.policy_size(document)<=6144 for document in documents)
 # The role is delivered by S3 TemplateURL (quick-create, or `cloudformation deploy`
 # staging a local file), whose CloudFormation limit is 1 MB. The 51,200-byte
 # inline TemplateBody limit must therefore never be the delivery path.
 assert len(first)<=1048576
 policy.refresh(tmp_path);assert path.read_bytes()==first


def test_unknown_companion_mapping_fails_closed(monkeypatch):
 rows=copy.deepcopy(policy.WAF_ASSOCIATION_STATEMENTS)
 rows[('wafv2','get_web_acl_for_resource')][0]['Action']='iam:CreateRole'
 monkeypatch.setattr(policy,'WAF_ASSOCIATION_STATEMENTS',rows)
 with pytest.raises(ValueError,match='reference review'):
  policy.build_policy({('wafv2','get_web_acl_for_resource')})


def test_companions_still_obey_the_existing_policy_count_budget(monkeypatch):
 monkeypatch.setattr(policy,'IAM_MANAGED_POLICIES_PER_ROLE',3)
 with pytest.raises(ValueError,match='existing IAM policy budgets|attached managed-policy quota'):
  policy.build_policy()



