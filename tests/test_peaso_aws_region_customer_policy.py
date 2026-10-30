import copy,fnmatch,hashlib,json
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
 assert hashlib.sha256(HISTORICAL_ROLE_BYTES).hexdigest()==DELTA['new_role_sha256']

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

def test_only_nine_enumerations_added_originals_and_limits_preserved():
 assert len(added())==9 and {r['Action']for r in added()}==set(OPS.values())
 for row in added():
  assert set(row)=={'Sid','Effect','Action','Resource'}and row['Effect']=='Allow'
  assert row['Action'].split(':')[1].startswith(('List','Describe'))
 for n in ['AuditRole','CspmConfigurationReadOnly1','CspmConfigurationReadOnly2','CspmConfigurationReadOnly3']:
  assert BASE['Resources'][n]==ROLE['Resources'][n]
 assert set(BASE['Resources'])==set(ROLE['Resources'])
 assert BASE['Parameters']==ROLE['Parameters']and BASE['Outputs']==ROLE['Outputs']
 for r in ROLE['Resources'].values():
  if r['Type']=='AWS::IAM::ManagedPolicy':assert len(json.dumps(r['Properties']['PolicyDocument'],separators=(',',':')))<=6144
 assert len(HISTORICAL_ROLE_BYTES)<=51200
 assert hashlib.sha256(HISTORICAL_ROLE_BYTES).hexdigest()==DELTA['new_role_sha256']
 assert builder.iam_action('sts','get_caller_identity')is None


def test_current_active_template_retains_exact_historical_metadata_and_transit_grants():
 # Freeze the historical artifact; the active role gains reviewed network reads.
 archived=(ROOT/'infra/aws'/('customer-role-'+ACTIVE_ROLE_SHA+'.json')).read_bytes()
 assert hashlib.sha256(archived).hexdigest()==ACTIVE_ROLE_SHA==hashlib.sha256(ACTIVE_ROLE_BYTES).hexdigest()
 historical_rows=added()
 transit=ROLE['Resources']['CspmConfigurationReadOnly4']['Properties']['PolicyDocument']['Statement'][-1]
 expected={row['Action']:row for row in historical_rows}
 transit_actions=set(transit['Action'])
 assert len(expected)==9 and len(transit_actions)==3
 scoped=[statement for resource in ACTIVE_ROLE['Resources'].values() if resource['Type']=='AWS::IAM::ManagedPolicy' for statement in resource['Properties']['PolicyDocument']['Statement']]
 for action,row in expected.items():
  assert [current for current in scoped if current.get('Sid')==row['Sid']]==[row]
 # Inspect every generated managed-policy statement: none may repeat or widen one
 # of the twelve reviewed permissions, including via an Action wildcard.
 matches={action:[] for action in set(expected)|transit_actions}
 for resource in ACTIVE_ROLE['Resources'].values():
  if resource['Type']!='AWS::IAM::ManagedPolicy':continue
  for statement in resource['Properties']['PolicyDocument']['Statement']:
   assert 'NotAction' not in statement
   actions=statement['Action']if isinstance(statement['Action'],list)else[statement['Action']]
   for action in matches:
    for granted in actions:
     if fnmatch.fnmatchcase(action,granted):matches[action].append((granted,statement))
 for action,row in expected.items():
  assert matches[action]==[(action,row)]
 for action in transit_actions:
  assert len(matches[action])==1
  granted,statement=matches[action][0]
  assert granted==action and statement['Effect']=='Allow' and statement['Resource']=='*'
  assert set(statement)=={'Sid','Effect','Action','Resource'}
 operations={('ec2','describe_transit_gateway_vpc_attachments'),
  ('ec2','get_transit_gateway_route_table_associations'),('ec2','search_transit_gateway_routes')}
 generated=builder.build_policy(operations,include_credential_report_generation=False)
 assert set(generated['Statement'][0]['Action'])==transit_actions
 assert generated['Statement'][0]['Effect']=='Allow' and generated['Statement'][0]['Resource']=='*'
 assert all(a.startswith(('ec2:Describe','ec2:Get','ec2:Search')) for a in transit_actions)


def test_current_role_preserves_reviewed_scheduler_and_dead_letter_metadata_reads():
 previous_sha = 'd43535005ba3ccf7c3179253d2dadb4ff6c521eb26884c571bc1f01c780995b8'
 previous_bytes = (ROOT/'infra/aws'/('customer-role-'+previous_sha+'.json')).read_bytes()
 assert hashlib.sha256(previous_bytes).hexdigest() == previous_sha
 previous = json.loads(previous_bytes)
 def grants(template):
  result = set()
  for resource in template['Resources'].values():
   if resource['Type'] != 'AWS::IAM::ManagedPolicy': continue
   for statement in resource['Properties']['PolicyDocument']['Statement']:
    assert statement['Effect'] == 'Allow' and 'NotAction' not in statement
    actions = statement['Action'] if isinstance(statement['Action'], list) else [statement['Action']]
    scope = json.dumps({k:v for k,v in statement.items() if k not in {'Sid','Action'}}, sort_keys=True)
    result.update((action, scope) for action in actions)
  return result
 before, after = grants(previous), grants(ACTIVE_ROLE)
 # Every reviewed grant survives, either exactly or with the same action over a
 # superset of the earlier resource list; nothing becomes an Allow on new terms.
 def resources(scope):
  value = json.loads(scope)
  listed = value.pop('Resource')
  return value, {json.dumps(item, sort_keys=True) for item in (listed if isinstance(listed, list) else [listed])}
 for action, scope in before - after:
  terms, earlier = resources(scope)
  assert any(granted == action and resources(current)[0] == terms and earlier <= resources(current)[1]
             for granted, current in after), (action, scope)
 reviewed = {'scheduler:GetSchedule', 'scheduler:ListSchedules', 'sqs:ListDeadLetterSourceQueues'}
 assert {(action, json.dumps({'Effect': 'Allow', 'Resource': '*'}, sort_keys=True)) for action in reviewed} <= after
 for key in ('Parameters','Outputs'):
  assert previous[key] == ACTIVE_ROLE[key]
 for key in ('RoleName', 'MaxSessionDuration', 'AssumeRolePolicyDocument'):
  assert previous['Resources']['AuditRole']['Properties'][key] == ACTIVE_ROLE['Resources']['AuditRole']['Properties'][key]
