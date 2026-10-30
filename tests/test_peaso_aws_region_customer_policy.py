import fnmatch, hashlib, json
from pathlib import Path
import pytest

from scripts import peaso_deploy_customer_policy as builder

ROOT=Path(builder.__file__).resolve().parents[1]
# Synthetic historical derivatives retain the exact permission delta without
# bundling a private collector principal or claiming the original byte hashes.
FIXTURE_BYTES=(ROOT/'tests/fixtures/aws-region-customer-policy-history.json').read_bytes()
assert hashlib.sha256(FIXTURE_BYTES).hexdigest()=='fde88927692adb1b0a17bbf1c6626c360c091a372cc203e429fe1163b4ff2f05'
HISTORY=json.loads(FIXTURE_BYTES)
NEW_ROLE_SHA='74813fd6631bd7a03873208235cf6d3ea05d41ffec587ed8a900c4c53f520bdd'
DELTA={'new_role_sha256':NEW_ROLE_SHA}
BASE=HISTORY['baseline']
ROLE=HISTORY['regional']
BASE_BYTES=(json.dumps(BASE,indent=2)+'\n').encode()
HISTORICAL_ROLE_BYTES=(json.dumps(ROLE,indent=2)+'\n').encode()
ACTIVE_ROLE_SHA='e6395747d1a4196cf1261328d84c7e7d51355e7b2ace7fc132e82d378e5243bc'
ACTIVE_ROLE_BYTES=(ROOT/'infra/aws/customer-role.json').read_bytes()
ACTIVE_ROLE=json.loads(ACTIVE_ROLE_BYTES)
OPS={('outposts','list_outposts'):'outposts:ListOutposts',('s3control','list_regional_buckets'):'s3-outposts:ListRegionalBuckets',('s3tables','list_table_buckets'):'s3tables:ListTableBuckets',('s3vectors','list_vector_buckets'):'s3vectors:ListVectorBuckets',('dynamodb','list_backups'):'dynamodb:ListBackups',('rds','describe_db_instance_automated_backups'):'rds:DescribeDBInstanceAutomatedBackups',('rds','describe_db_cluster_automated_backups'):'rds:DescribeDBClusterAutomatedBackups',('redshift-serverless','list_snapshots'):'redshift-serverless:ListSnapshots',('redshift-serverless','list_recovery_points'):'redshift-serverless:ListRecoveryPoints'}

def added():
 before=BASE['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 after=ROLE['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement']
 assert after[:len(before)]==before
 return after[len(before):-1]

def test_transit_gateway_route_evidence_grant_is_read_only_and_archived():
 row=ROLE['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement'][-1]
 assert row=={'Sid':'NativeTransitGatewayRouteEvidenceRead','Effect':'Allow',
  'Action':['ec2:DescribeTransitGatewayVpcAttachments','ec2:GetTransitGatewayRouteTableAssociations','ec2:SearchTransitGatewayRoutes'],
  'Resource':'*'}
 operations={('ec2','describe_transit_gateway_vpc_attachments'),
  ('ec2','get_transit_gateway_route_table_associations'),('ec2','search_transit_gateway_routes')}
 policy=builder.build_policy(operations,include_credential_report_generation=False)
 assert set(policy['Statement'][0]['Action'])==set(row['Action'])

@pytest.mark.parametrize('operation,expected',list(OPS.items()))
def test_new_action_has_verified_alias_and_exact_grant(operation,expected):
 assert builder.iam_action(*operation)==expected
 native=builder.NATIVE_METADATA_STATEMENTS[operation]
 assert native in added()
 policy=builder.build_policy({operation},include_credential_report_generation=False)
 assert policy['Statement']==[native]
 assert native['Action']==expected and '*'not in expected

@pytest.mark.parametrize('service,operation',[
 ('s3vectors','create_vector_bucket'),('s3vectors','put_vectors'),('s3vectors','delete_vectors'),
 ('s3tables','create_table_bucket'),('outposts','create_outpost'),
 ('rds','delete_db_cluster_automated_backup'),('redshift-serverless','restore_from_snapshot'),
 ('redshift-serverless','get_credentials'),('s3','put_object'),('secretsmanager','get_secret_value')])
def test_added_delta_cannot_authorize_mutation_or_content(service,operation):
 with pytest.raises(ValueError):builder.iam_action(service,operation)


def test_optional_s3_source_object_read_is_never_a_default_metadata_grant():
 # s3:GetObject is a reviewed opt-in source read only; the default role never holds it.
 assert builder.iam_action('s3','get_object')=='s3:GetObject'
 assert ('s3','get_object') in builder.UNGRANTED_CONTENT_OPERATIONS
 with pytest.raises(ValueError):builder.build_policy({('s3','get_object')},include_credential_report_generation=False)
 granted={action for resource in ACTIVE_ROLE['Resources'].values() if resource['Type']=='AWS::IAM::ManagedPolicy'
  for statement in resource['Properties']['PolicyDocument']['Statement']
  for action in (statement['Action'] if isinstance(statement['Action'],list) else [statement['Action']])}
 assert not any(fnmatch.fnmatchcase('s3:GetObject',action) for action in granted)

@pytest.mark.parametrize('action,types',[
 ('rds:DescribeDBInstanceAutomatedBackups',{'auto-backup:*','db:*'}),
 ('rds:DescribeDBClusterAutomatedBackups',{'cluster:*','cluster-auto-backup:*'}),
 ('redshift-serverless:ListSnapshots',{'snapshot/*'}),
 ('redshift-serverless:ListRecoveryPoints',{'recoverypoint/*'})])
def test_resource_supported_metadata_grants_are_customer_scoped(action,types):
 row=next(r for r in added()if r['Action']==action)
 resources=row['Resource']if isinstance(row['Resource'],list)else[row['Resource']]
 assert {r['Fn::Sub'].split('${AWS::AccountId}:',1)[1]for r in resources}==types
 assert all('${AWS::Partition}'in r['Fn::Sub']and ':*:${AWS::AccountId}:'in r['Fn::Sub']for r in resources)
 # Concrete ARN matching proves added action does not match another account.
 for resource in resources:
  pattern=resource['Fn::Sub'].replace('${AWS::Partition}','aws').replace('${AWS::AccountId}','123456789012')
  actual=pattern.replace(':*:',':eu-west-1:').replace('*','owned')
  assert fnmatch.fnmatchcase(actual,pattern)
  assert not fnmatch.fnmatchcase(actual.replace('123456789012','999999999999'),pattern)


