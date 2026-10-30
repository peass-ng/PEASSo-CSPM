"""Data service SDK-to-public-collector closure review.

Responses are validated and served by botocore Stubber, never live AWS. These
cases prove only the named branches, not complete service semantics.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import threading

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.checks import resolve_check_id
from peaso.engine import evaluate_snapshot

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
STAMP = datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.fixture
def pipeline(monkeypatch):
    """Real SDK clients and response validation, with every call stubbed locally."""
    session = boto3.Session(aws_access_key_id='offline', aws_secret_access_key='offline', region_name=REGION)
    original_requests = aws.Requests
    runs = []

    def collect(kind, responses):
        calls, clients = [], {}
        requests = original_requests({'retry_attempts': 1, 'max_workers': 1, 'max_calls': 300}, sleep=lambda _: None)
        requests.observed_at = STAMP
        native = {('sts', 'get_caller_identity'): {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/review', 'UserId': 'AIDAOFFLINEREVIEW'}, **responses}

        class Client:
            def __init__(self, service, region):
                self.service = service
                self.sdk = session.client(service, region_name=region)
                self.lock = threading.Lock()  # Stubber state is per client; collectors may use threads.
                self.meta = self.sdk.meta

            def can_paginate(self, operation):
                return False

            def __getattr__(self, operation):
                def call(**arguments):
                    calls.append((self.service, operation, deepcopy(arguments)))
                    response = native.get((self.service, operation))
                    if callable(response):
                        response = response(arguments)
                    with self.lock, Stubber(self.sdk) as stub:
                        if response is None or isinstance(response, tuple):
                            stub.add_client_error(operation, service_error_code=response[0] if isinstance(response, tuple) else 'AccessDeniedException', expected_params=arguments)
                        else:
                            stub.add_response(operation, deepcopy(response), arguments)
                        result = getattr(self.sdk, operation)(**arguments)
                        stub.assert_no_pending_responses()
                        return result
                return call

        def client(_session, service, region):
            if (service, region) not in clients:
                clients[service, region] = Client(service, region)
            return clients[service, region]

        requests.client = client
        monkeypatch.setattr(aws, 'Requests', lambda options: requests)
        monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'offline'))
        snapshot = aws.collect({'provider': 'aws', 'scopes': [SCOPE], 'options': {'regions': [REGION]}}, [kind] if isinstance(kind, str) else kind)
        runs.append((snapshot, calls))
        return snapshot, calls

    return collect


def item_of(snapshot, kind):
    rows = [row for envelope in snapshot['collections'] if envelope['type'] == kind for row in envelope['items']]
    assert len(rows) == 1
    return rows[0]


def verdict(snapshot, cid):
    canonical_id = resolve_check_id(cid)
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid])['findings'] if row['check_id'] == canonical_id]
    assert len(rows) == 1, rows
    return rows[0]['status']


KEY_ID = '11111111-2222-3333-4444-555555555555'
KEY_ARN = f'arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}'
OTHER_ID = '66666666-2222-3333-4444-555555555555'
OTHER_ARN = f'arn:aws:kms:{REGION}:{ACCOUNT}:key/{OTHER_ID}'
SECRET_ARN = f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:example-AbCdEf'


def kms_responses(manager='CUSTOMER', identity='matching'):
    keyid, arn = (OTHER_ID, OTHER_ARN) if identity == 'foreign' else (KEY_ID, KEY_ARN)
    return {('kms', 'list_keys'): {'Keys': [{'KeyId': KEY_ID, 'KeyArn': KEY_ARN}]},
        ('kms', 'describe_key'): {'KeyMetadata': {'KeyId': keyid, 'Arn': arn, 'AWSAccountId': ACCOUNT,
            'KeyManager': manager, 'KeyState': 'Enabled', 'Enabled': True, 'KeyUsage': 'ENCRYPT_DECRYPT', 'KeySpec': 'SYMMETRIC_DEFAULT', 'CreationDate': STAMP}} if identity != 'denied' else None}


def database_responses(kind, **fields):
    if kind == 'rds_instance':
        return {('rds', 'describe_db_instances'): {'DBInstances': [{'DBInstanceIdentifier': 'example',
            'DBInstanceArn': f'arn:aws:rds:{REGION}:{ACCOUNT}:db:example', 'Engine': 'postgres', **fields}]}}
    if kind == 'rds_cluster':
        return {('rds', 'describe_db_clusters'): {'DBClusters': [{'DBClusterIdentifier': 'example',
            'DBClusterArn': f'arn:aws:rds:{REGION}:{ACCOUNT}:cluster:example', 'Engine': 'aurora-postgresql', **fields}]}}
    return {('redshift', 'describe_clusters'): {'Clusters': [{'ClusterIdentifier': 'example',
        'ClusterNamespaceArn': f'arn:aws:redshift:{REGION}:{ACCOUNT}:namespace:00000000-1111-2222-3333-444444444444', **fields}]}}


SCALARS = [
 ('rds_instance','aws.b.rds.backup_retention_seven_days','BackupRetentionPeriod',7,0),
 ('rds_instance','aws.b.rds_instance.iam_authentication','IAMDatabaseAuthenticationEnabled',True,False),
 ('rds_instance','aws.b.rds_instance.minor_upgrade','AutoMinorVersionUpgrade',True,False),
 ('rds_instance','aws.b.rds_instance.snapshot_tags','CopyTagsToSnapshot',True,False),
 ('rds_instance','aws.rds.backups','BackupRetentionPeriod',7,0),
 ('rds_cluster','aws.b.rds.cluster_minor_upgrade','AutoMinorVersionUpgrade',True,False),
 ('rds_cluster','aws.b.rds_cluster.iam_authentication','IAMDatabaseAuthenticationEnabled',True,False),
 ('rds_cluster','aws.b.rds_cluster.multiple_az','MultiAZ',True,False),
 ('redshift_cluster','aws.b.redshift.allow_version_upgrade','AllowVersionUpgrade',True,False),
 ('redshift_cluster','aws.b.redshift.enhanced_vpc_routing','EnhancedVpcRouting',True,False),
 ('redshift_cluster','aws.b.redshift.no_public_endpoint','PubliclyAccessible',False,True),
 ('redshift_cluster','aws.b.redshift.snapshots_seven_days','AutomatedSnapshotRetentionPeriod',7,0),
 ('redshift_cluster','aws.b.redshift.nondefault_admin','MasterUsername','application_owner','awsuser'),
 ('redshift_cluster','aws.b.redshift.nondefault_database','DBName','application','dev'),
 ('redshift_cluster','aws.cb.redshift.allow_version_upgrade','AllowVersionUpgrade',True,False),
 ('redshift_cluster','aws.cb.redshift.enhanced_vpc_routing','EnhancedVpcRouting',True,False),
 ('redshift_cluster','aws.cb.redshift.multi_az','MultiAZ','Enabled','Disabled'),
 ('redshift_cluster','aws.cb.redshift.encrypted','Encrypted',True,False),
 ('redshift_cluster','aws.cb.redshift.not_publicly_accessible','PubliclyAccessible',False,True),
 ('redshift_cluster','aws.cb.redshift.non_default_master_username','MasterUsername','application_owner','awsuser'),
 ('redshift_cluster','aws.cb.redshift.non_default_database_name','DBName','application','dev'),
]


@pytest.mark.parametrize('kind,cid,field,good,bad', SCALARS)
def test_native_database_scalar_branches(pipeline, kind, cid, field, good, bad):
    for value, expected in [(good,'PASS'),(bad,'FAIL')]:
        snapshot, _ = pipeline(kind, database_responses(kind, **{field:value}))
        assert verdict(snapshot,cid)==expected
    snapshot, _ = pipeline(kind, database_responses(kind))
    assert verdict(snapshot,cid)=='UNKNOWN'
    snapshot, _ = pipeline(kind, {})
    assert verdict(snapshot,cid)=='DENIED'


@pytest.mark.parametrize('kind,cid', [
 ('rds_cluster','aws.cb.rds.cluster_cmk_encryption'),
 ('redshift_cluster','aws.cb.redshift.cmk_encryption'),
 ('secret','aws.cb.secretsmanager.cmk_encryption'),
])
@pytest.mark.parametrize('scenario,expected', [('customer','PASS'),('aws','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN')])
def test_kms_native_key_identity_join(pipeline,kind,cid,scenario,expected):
    ref=OTHER_ARN if scenario=='foreign' else KEY_ARN
    responses=kms_responses('AWS' if scenario=='aws' else 'CUSTOMER',scenario if scenario in ('denied','foreign') else 'matching')
    if kind=='secret':
        responses.update({('secretsmanager','list_secrets'):{'SecretList':[{'ARN':SECRET_ARN,'Name':'example'}]},
            ('secretsmanager','describe_secret'):{'ARN':SECRET_ARN,'Name':'example','KmsKeyId':ref}})
    else:
        responses.update(database_responses(kind,**{'StorageEncrypted' if kind=='rds_cluster' else 'Encrypted':True,'KmsKeyId':ref}))
    snapshot,_=pipeline([kind,'kms_key'],responses)
    assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('value,expected',[('true','PASS'),('false','FAIL'),(None,'UNKNOWN'),('missing','UNKNOWN')])
def test_redshift_require_ssl_native_parameter(pipeline,value,expected):
    responses=database_responses('redshift_cluster',ClusterParameterGroups=[{'ParameterGroupName':'example','ParameterApplyStatus':'in-sync'}])
    responses['redshift','describe_cluster_parameters']=None if value is None else {'Parameters':[] if value=='missing' else [{'ParameterName':'require_ssl','ParameterValue':value}]}
    snapshot,_=pipeline('redshift_cluster',responses)
    assert verdict(snapshot,'aws.cb.redshift.require_ssl')==expected


@pytest.mark.parametrize('cid,engine,param',[
 ('aws.cb.rds.instance_tls_parameters','postgres','rds.force_ssl'),
 ('aws.cb.rds.postgres_force_ssl_parameter','postgres','rds.force_ssl'),
 ('aws.cb.rds.sqlserver_force_ssl_parameter','sqlserver-se','rds.force_ssl'),
 ('aws.cb.rds.mariadb_require_secure_transport','mariadb','require_secure_transport'),
 ('aws.cb.rds.cluster_tls_parameters','aurora-postgresql','rds.force_ssl'),
])
@pytest.mark.parametrize('value,expected',[('1','PASS'),('0','FAIL'),(None,'UNKNOWN'),('missing','UNKNOWN')])
def test_rds_parameter_presence_and_unavailability(pipeline,cid,engine,param,value,expected):
    cluster=cid=='aws.cb.rds.cluster_tls_parameters';kind='rds_cluster' if cluster else 'rds_instance'
    fields={'Engine':engine,'EngineVersion':'10.11.8' if engine=='mariadb' else '15.4'}
    fields.update({'DBClusterParameterGroup':'example'} if cluster else {'DBParameterGroups':[{'DBParameterGroupName':'example','ParameterApplyStatus':'in-sync'}]})
    responses=database_responses(kind,**fields)
    responses['rds','describe_db_cluster_parameters' if cluster else 'describe_db_parameters']=None if value is None else {'Parameters':[] if value=='missing' else [{'ParameterName':param,'ParameterValue':value}]}
    snapshot,_=pipeline(kind,responses)
    assert verdict(snapshot,cid)==expected


def secret_responses(**fields):
    row={'ARN':SECRET_ARN,'Name':'example','CreatedDate':datetime(2024,1,1,tzinfo=timezone.utc),**fields}
    return {('secretsmanager','list_secrets'):{'SecretList':[row]},('secretsmanager','describe_secret'):deepcopy(row)}


@pytest.mark.parametrize('cid,field',[
 ('aws.secretsmanager.rotation','RotationEnabled'),
 ('aws_nist_secretsmanager_secret_automatic_rotation_enabled','RotationEnabled'),
 ('aws.cb.secretsmanager.rotation_rules_present','RotationRules'),
 ('aws.cb.secretsmanager.rotation_lambda','RotationLambdaARN'),
 ('aws.cb.secretsmanager.changed_within_365_days','LastChangedDate'),
 ('aws.cb.secretsmanager.changed_within_90_days','LastChangedDate'),
 ('aws.cb.secretsmanager.rotated_within_90_days','LastRotatedDate'),
 ('aws.cb.secretsmanager.accessed_within_90_days','LastAccessedDate'),
 ('aws.cb.secretsmanager.accessed_within_90_calendar_days','LastAccessedDate'),
 ('aws.cb.secretsmanager.used_after_creation_day','LastAccessedDate'),
 ('aws.cb.secretsmanager.rotated_as_scheduled','LastRotatedDate'),
])
def test_secret_native_rotation_and_date_metadata(pipeline,cid,field):
    for positive in (True,False):
        fields={'RotationEnabled':True,'RotationRules':{'AutomaticallyAfterDays':30},
            'RotationLambdaARN':f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:rotation',
            'LastChangedDate':datetime(2026,10,18,tzinfo=timezone.utc),
            'LastAccessedDate':datetime(2026,10,18,tzinfo=timezone.utc),
            'LastRotatedDate':datetime(2026,10,18,tzinfo=timezone.utc)}
        if not positive:
            if field=='RotationEnabled':fields[field]=False
            elif field=='RotationRules':
                fields.pop(field)
                fields['RotationEnabled']=False
            elif field=='RotationLambdaARN':fields.pop(field)
            else:fields[field]=datetime(2024,1,1,tzinfo=timezone.utc)
        snapshot,_=pipeline('secret',secret_responses(**fields))
        assert verdict(snapshot,cid)==('PASS' if positive else 'FAIL')
    # Denied base inventory cannot establish any of these outcomes.
    snapshot,_=pipeline('secret',{})
    assert verdict(snapshot,cid)=='DENIED'


@pytest.mark.parametrize('cid,expected', [('aws.cb.secretsmanager.cmk_encryption','FAIL'),('aws.pci.secretsmanager.kms_encryption_any','PASS')])
def test_secret_documented_default_key_without_key_value_read(pipeline,cid,expected):
    snapshot,calls=pipeline(['secret','kms_key'],secret_responses())
    assert verdict(snapshot,cid)==expected
    assert item_of(snapshot,'secret')['_coverage']['KmsKeyId']['documented_default']=='aws/secretsmanager'
    assert not any(op in ('get_secret_value','batch_get_secret_value')for svc,op,args in calls)


@pytest.mark.parametrize('mode,expected',[('enabled','PASS'),('disabled','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN')])
def test_secret_enabled_kms_key(pipeline,mode,expected):
    responses={**secret_responses(KmsKeyId=KEY_ARN),**kms_responses(identity='denied' if mode=='denied' else 'foreign' if mode=='foreign' else 'matching')}
    if mode=='disabled':responses['kms','describe_key']['KeyMetadata'].update(KeyState='Disabled',Enabled=False)
    snapshot,_=pipeline(['secret','kms_key'],responses)
    assert verdict(snapshot,'aws.pci.secretsmanager.kms_encryption_any')==expected


@pytest.mark.parametrize('cid',['aws.cb.secretsmanager.policy_not_public','aws.cb.secretsmanager.policy_prohibit_public_access_perimeter'])
@pytest.mark.parametrize('mode,expected',[('private','PASS'),('public','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN')])
def test_secret_resource_policy_identity(pipeline,cid,mode,expected):
    policy={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':'*' if mode=='public' else {'AWS':f'arn:aws:iam::{ACCOUNT}:role/application'},'Action':'secretsmanager:GetSecretValue','Resource':'*'}]}
    responses=secret_responses()
    responses['secretsmanager','get_resource_policy']=None if mode=='denied' else {'ARN':SECRET_ARN.replace('example','foreign') if mode=='foreign' else SECRET_ARN,'Name':'foreign' if mode=='foreign' else 'example','ResourcePolicy':json.dumps(policy)}
    snapshot,_=pipeline('secret',responses)
    assert verdict(snapshot,cid)==expected


BUCKET='example-review-data'
BLOCKS=('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')
def bucket_responses():
    return {('s3','list_buckets'):{'Buckets':[{'Name':BUCKET}]},('s3','get_bucket_location'):{},
        ('s3','get_public_access_block'):{'PublicAccessBlockConfiguration':dict.fromkeys(BLOCKS,False)},
        ('s3control','get_public_access_block'):{'PublicAccessBlockConfiguration':dict.fromkeys(BLOCKS,False)},
        ('s3','get_bucket_policy'):('NoSuchBucketPolicy',),('s3','get_bucket_policy_status'):{'PolicyStatus':{'IsPublic':False}},
        ('s3','get_bucket_acl'):{'Owner':{'ID':'a'*64},'Grants':[{'Grantee':{'Type':'CanonicalUser','ID':'a'*64},'Permission':'FULL_CONTROL'}]},
        ('s3','get_bucket_ownership_controls'):{'OwnershipControls':{'Rules':[{'ObjectOwnership':'ObjectWriter'}]}},
        ('s3','get_bucket_versioning'):{'Status':'Enabled'}}


@pytest.mark.parametrize('cid', ['aws.a.s3.default_encryption_configuration','aws.s3.default_encryption','aws.claude_a.s3.default_encryption_kms_key','aws.claude_a.s3.prowler_kms_encryption'])
def test_s3_native_encryption_metadata(pipeline,cid):
    for mode,expected in [('kms','PASS'),('negative','UNKNOWN' if cid=='aws.s3.default_encryption' else 'FAIL'),('denied','UNKNOWN')]:
        responses=bucket_responses()
        if mode=='denied':value=None
        elif mode=='negative' and cid in ('aws.a.s3.default_encryption_configuration','aws.s3.default_encryption'):value=('ServerSideEncryptionConfigurationNotFoundError',)
        else:value={'ServerSideEncryptionConfiguration':{'Rules':[{'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256' if mode=='negative' else 'aws:kms',**({'KMSMasterKeyID':KEY_ARN}if mode=='kms' else {})}}]}}
        responses['s3','get_bucket_encryption']=value
        snapshot,_=pipeline('bucket',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid',['aws.a.s3.bucket_account_public_blocks','aws.s3.public_access_block','aws.claude_a.s3.bucket_public_access_block_all','aws.claude_a.s3.prowler_bucket_level_public_access_block'])
def test_s3_bucket_account_native_blocks(pipeline,cid):
    for mode,expected in [('enabled','PASS'),('disabled','FAIL'),('denied','UNKNOWN')]:
        responses=bucket_responses();responses['s3','get_public_access_block']=None if mode=='denied' else {'PublicAccessBlockConfiguration':dict.fromkeys(BLOCKS,mode=='enabled')}
        snapshot,_=pipeline(['bucket','s3_account_public_access_block'],responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid', ['aws.claude_a.s3.perimeter_policy_not_public','aws.claude_a.s3.prowler_cross_account_policy','aws.claude_a.s3.policy_no_cross_account_permission_changes','aws.claude_a.s3.prowler_policy_public_write'])
def test_s3_native_policy_document_branches(pipeline,cid):
    for mode,expected in [('private','PASS'),('public','FAIL'),('denied','UNKNOWN')]:
        responses=bucket_responses()
        principal={'AWS':f'arn:aws:iam::{ACCOUNT}:root'} if mode=='private' else '*'
        policy={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':principal,'Action':['s3:GetObject','s3:PutObject','s3:PutBucketPolicy'],'Resource':[f'arn:aws:s3:::{BUCKET}',f'arn:aws:s3:::{BUCKET}/*']}]}
        responses['s3','get_bucket_policy']=None if mode=='denied' else {'Policy':json.dumps(policy)}
        snapshot,_=pipeline(['bucket','s3_account_public_access_block'],responses)
        assert verdict(snapshot,cid)==expected




@pytest.mark.parametrize('cid,operation,positive,negative',[
 ('aws.claude_a.s3.lifecycle_rule_enabled','get_bucket_lifecycle_configuration',{'Rules':[{'Status':'Enabled','Filter':{}}]},('NoSuchLifecycleConfiguration',)),
 ('aws.claude_a.s3.versioning_and_lifecycle','get_bucket_lifecycle_configuration',{'Rules':[{'Status':'Enabled','Filter':{}}]},('NoSuchLifecycleConfiguration',)),
 ('aws.claude_a.s3.object_lock_configured','get_object_lock_configuration',{'ObjectLockConfiguration':{'ObjectLockEnabled':'Enabled'}},('ObjectLockConfigurationNotFoundError',)),
 ('aws.claude_a.s3.event_notifications','get_bucket_notification_configuration',{'EventBridgeConfiguration':{}},{}),
 ('aws.s3.access_logging','get_bucket_logging',{'LoggingEnabled':{'TargetBucket':'log-review-bucket','TargetPrefix':'review/'}},{}),
 ('aws.s3.versioning','get_bucket_versioning',{'Status':'Enabled'},{}),
 ('aws.claude_a.s3.prowler_acl_disabled','get_bucket_ownership_controls',{'OwnershipControls':{'Rules':[{'ObjectOwnership':'BucketOwnerEnforced'}]}},{'OwnershipControls':{'Rules':[{'ObjectOwnership':'ObjectWriter'}]}}),
])
def test_s3_native_defaults_and_configuration_absence(pipeline,cid,operation,positive,negative):
    for response,expected in [(positive,'PASS'),(negative,'FAIL'),(None,'UNKNOWN')]:
        responses=bucket_responses();responses['s3',operation]=response
        snapshot,_=pipeline('bucket',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid,permission',[
 ('aws.claude_a.s3.prowler_public_access','READ'),
 ('aws.claude_a.s3.prowler_public_list_acl','READ'),
 ('aws.claude_a.s3.prowler_public_write_acl','WRITE'),
 ('aws.claude_a.s3.restrict_public_read','READ'),
 ('aws.gap.s3.no_public_write_acl_or_policy','WRITE'),
])
def test_s3_native_public_acl_and_mitigations(pipeline,cid,permission):
    for mode,expected in [('private','PASS'),('public','FAIL'),('denied','UNKNOWN')]:
        responses=bucket_responses()
        if mode=='public':responses['s3','get_bucket_acl']['Grants'].append({'Grantee':{'Type':'Group','URI':'http://acs.amazonaws.com/groups/global/AllUsers'},'Permission':permission})
        if mode=='denied':responses['s3','get_bucket_acl']=None
        snapshot,_=pipeline(['bucket','s3_account_public_access_block'],responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('positive,expected',[(True,'PASS'),(False,'FAIL'),(None,'UNKNOWN')])
def test_s3_native_bucket_policy_requires_tls(pipeline,positive,expected):
    responses=bucket_responses()
    responses['s3','get_bucket_policy']=None if positive is None else {'Policy':json.dumps({'Version':'2012-10-17','Statement':[{
        'Effect':'Deny','Principal':'*','Action':'s3:*' if positive else 's3:PutObject','Resource':[f'arn:aws:s3:::{BUCKET}',f'arn:aws:s3:::{BUCKET}/*'],'Condition':{'Bool':{'aws:SecureTransport':'false'}}}]})}
    snapshot,_=pipeline('bucket',responses)
    assert verdict(snapshot,'aws.gap.s3.bucket_policy_denies_insecure_transport')==expected


@pytest.mark.parametrize('kind,cid', [('rds_instance','aws.cb.rds.instance_in_backup_plan_selection'),('rds_cluster','aws.cb.rds.cluster_in_backup_plan_selection'),('rds_instance','aws.cb.rds.instance_in_backup_selection_or_tag')])
def test_native_backup_plan_selection_join(pipeline,kind,cid):
    arn=f'arn:aws:rds:{REGION}:{ACCOUNT}:'+('db:example' if kind=='rds_instance' else 'cluster:example')
    for mode,expected in [('matched','PASS'),('foreign','FAIL'),('denied','UNKNOWN')]:
        responses=database_responses(kind)
        responses.update({('backup','list_backup_plans'):{'BackupPlansList':[{'BackupPlanId':'example','BackupPlanName':'example','BackupPlanArn':f'arn:aws:backup:{REGION}:{ACCOUNT}:backup-plan:example'}]},
            ('backup','get_backup_plan'):{'BackupPlan':{'BackupPlanName':'example','Rules':[{'RuleName':'daily','TargetBackupVaultName':'example','ScheduleExpression':'cron(0 5 ? * * *)'}]}},
            ('backup','list_backup_selections'):{'BackupSelectionsList':[{'SelectionId':'example','BackupPlanId':'example'}]},
            ('backup','get_backup_selection'):None if mode=='denied' else {'BackupSelection':{'SelectionName':'example','IamRoleArn':f'arn:aws:iam::{ACCOUNT}:role/backup','Resources':[arn if mode=='matched' else arn.replace(':example',':other')]}}})
        snapshot,_=pipeline([kind,'backup_plan'],responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('kind,cid,engine,field,good,bad',[
 ('rds_instance','aws.cb.rds.postgres_log_exports','postgres','EnabledCloudwatchLogsExports',['postgresql','upgrade'],[]),
 ('rds_instance','aws.cb.rds.mariadb_log_exports','mariadb','EnabledCloudwatchLogsExports',['audit','error','general','slowquery'],[]),
 ('rds_instance','aws.cb.rds.sqlserver_error_log_export','sqlserver-ee','EnabledCloudwatchLogsExports',['error'],[]),
 ('rds_instance','aws.rds.enhanced_monitoring','postgres','EnhancedMonitoringResourceArn',f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:RDSOSMetrics:log-stream:example',''),
 ('rds_instance','aws.cb.rds.instance_default_master_username','postgres','MasterUsername','application_owner','postgres'),
 ('rds_instance','aws.cb.rds.instance_multi_az_or_cluster','postgres','MultiAZ',True,False),
 ('rds_cluster','aws.cb.rds.aurora_postgres_postgresql_log_export','aurora-postgresql','EnabledCloudwatchLogsExports',['postgresql'],[]),
 ('rds_cluster','aws.cb.rds.cluster_log_exports_declared','aurora-postgresql','EnabledCloudwatchLogsExports',['postgresql'],[]),
 ('rds_cluster','aws.cb.rds.cluster_backtrack_window_positive','aurora-mysql','BacktrackWindow',3600,0),
 ('rds_cluster','aws.cb.rds.aurora_backtracking_configured','aurora-mysql','BacktrackWindow',3600,0),
])
def test_native_database_remaining_base_fields(pipeline,kind,cid,engine,field,good,bad):
    for value,expected in [(good,'PASS'),(bad,'FAIL')]:
        snapshot,_=pipeline(kind,database_responses(kind,Engine=engine,EngineVersion='8.0.mysql_aurora.3.08.2' if engine=='aurora-mysql' else '15.4',**{field:value}))
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid',['aws.b.redshift.audit_logging'])
def test_redshift_native_logging_status(pipeline,cid):
    for value,expected in [(True,'PASS'),(False,'FAIL'),(None,'UNKNOWN')]:
        responses=database_responses('redshift_cluster')
        responses['redshift','describe_logging_status']=None if value is None else {'LoggingEnabled':value}
        snapshot,_=pipeline('redshift_cluster',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('mode,expected',[('guardrail','PASS'),('allow_only','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN')])
def test_secret_explicit_principal_guardrail_identity(pipeline,mode,expected):
    policy={'Version':'2012-10-17','Statement':[{'Effect':'Deny','Principal':'*','Action':'secretsmanager:*','Resource':SECRET_ARN,
        'Condition':{'ArnNotEquals':{'aws:PrincipalArn':f'arn:aws:iam::{ACCOUNT}:role/application'}}}]}
    if mode=='allow_only':policy={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'AWS':f'arn:aws:iam::{ACCOUNT}:role/application'},'Action':'secretsmanager:GetSecretValue','Resource':SECRET_ARN}]}
    responses=secret_responses()
    responses['secretsmanager','get_resource_policy']=None if mode=='denied' else {'ARN':SECRET_ARN.replace('example','foreign') if mode=='foreign' else SECRET_ARN,'Name':'foreign' if mode=='foreign' else 'example','ResourcePolicy':json.dumps(policy)}
    snapshot,_=pipeline('secret',responses)
    assert verdict(snapshot,'aws.review.secretsmanager.explicit_principal_deny')==expected


@pytest.mark.parametrize('cid',['aws.secretsmanager.rotation','aws_nist_secretsmanager_secret_automatic_rotation_enabled'])
def test_foreign_describe_secret_cannot_prove_rotation(pipeline,cid):
    responses=secret_responses(RotationEnabled=True)
    responses['secretsmanager','describe_secret']['ARN']=SECRET_ARN.replace('example','foreign')
    responses['secretsmanager','describe_secret']['Name']='foreign'
    snapshot,_=pipeline('secret',responses)
    assert verdict(snapshot,cid)=='UNKNOWN'


@pytest.mark.parametrize('kind,cid', [('rds_instance','aws.cb.rds.instance_in_backup_plan_selection'),('rds_cluster','aws.cb.rds.cluster_in_backup_plan_selection'),('rds_instance','aws.cb.rds.instance_in_backup_selection_or_tag')])
def test_backup_explicit_exclusion_cannot_certify_selection(pipeline,kind,cid):
    arn=f'arn:aws:rds:{REGION}:{ACCOUNT}:'+('db:example' if kind=='rds_instance' else 'cluster:example')
    responses=database_responses(kind)
    responses.update({('backup','list_backup_plans'):{'BackupPlansList':[{'BackupPlanId':'example','BackupPlanName':'example'}]},
        ('backup','get_backup_plan'):{'BackupPlan':{'BackupPlanName':'example','Rules':[{'RuleName':'daily','TargetBackupVaultName':'example'}]}},
        ('backup','list_backup_selections'):{'BackupSelectionsList':[{'SelectionId':'example','BackupPlanId':'example'}]},
        ('backup','get_backup_selection'):{'BackupSelection':{'SelectionName':'example','IamRoleArn':f'arn:aws:iam::{ACCOUNT}:role/backup','Resources':[arn],'NotResources':[arn]}}})
    snapshot,_=pipeline([kind,'backup_plan'],responses)
    assert verdict(snapshot,cid)=='UNKNOWN'


@pytest.mark.parametrize('cid',['aws.b.redshift.kms_key_declared','aws.cb.redshift.kms_key_declared'])
def test_redshift_native_declared_key_reference(pipeline,cid):
    for fields,expected in [({'Encrypted':True,'KmsKeyId':KEY_ARN},'PASS'),({'Encrypted':False},'FAIL')]:
        snapshot,_=pipeline('redshift_cluster',database_responses('redshift_cluster',**fields))
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid',['aws.claude_a.s3.replication_rule_enabled'])
def test_s3_native_replication_status(pipeline,cid):
    for state,expected in [('Enabled','PASS'),('Disabled','FAIL'),(None,'UNKNOWN')]:
        responses=bucket_responses()
        responses['s3','get_bucket_replication']=None if state is None else {'ReplicationConfiguration':{'Role':f'arn:aws:iam::{ACCOUNT}:role/replication','Rules':[{'Status':state,'Destination':{'Bucket':'arn:aws:s3:::destination-review'},'Priority':1,'Filter':{}}]}}
        snapshot,_=pipeline('bucket',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid',['aws.claude_a.s3.acls_prohibit_user_access'])
def test_s3_native_canonical_acl_owner(pipeline,cid):
    for mode,expected in [('owner','PASS'),('other','FAIL'),('denied','UNKNOWN')]:
        responses=bucket_responses()
        if mode=='other':responses['s3','get_bucket_acl']['Grants'].append({'Grantee':{'Type':'CanonicalUser','ID':'b'*64},'Permission':'READ'})
        if mode=='denied':responses['s3','get_bucket_acl']=None
        snapshot,_=pipeline('bucket',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('mode,expected',[('matching','PASS'),('wrong_value','FAIL'),('wrong_case','FAIL'),('or_match','PASS'),('denied','UNKNOWN'),('unsupported','UNKNOWN')])
def test_backup_tag_condition_requires_native_value_match(pipeline,mode,expected):
    responses=database_responses('rds_instance',TagList=[{'Key':'backup','Value':'daily'}])
    conditions=[{'ConditionType':'STRINGLIKE' if mode=='unsupported' else 'STRINGEQUALS','ConditionKey':'backup',
                 'ConditionValue':'weekly' if mode=='wrong_value' else 'Daily' if mode=='wrong_case' else 'daily'}]
    if mode=='or_match':conditions.insert(0,{'ConditionType':'STRINGEQUALS','ConditionKey':'irrelevant','ConditionValue':'weekly'})
    responses.update({('backup','list_backup_plans'):{'BackupPlansList':[{'BackupPlanId':'example','BackupPlanName':'example'}]},
        ('backup','get_backup_plan'):{'BackupPlan':{'BackupPlanName':'example','Rules':[{'RuleName':'daily','TargetBackupVaultName':'example'}]}},
        ('backup','list_backup_selections'):{'BackupSelectionsList':[{'SelectionId':'example','BackupPlanId':'example'}]},
        ('backup','get_backup_selection'):None if mode=='denied' else {'BackupSelection':{'SelectionName':'example','IamRoleArn':f'arn:aws:iam::{ACCOUNT}:role/backup','Resources':[],'ListOfTags':conditions}}})
    snapshot,_=pipeline(['rds_instance','backup_plan'],responses)
    assert verdict(snapshot,'aws.cb.rds.instance_in_backup_selection_or_tag')==expected
