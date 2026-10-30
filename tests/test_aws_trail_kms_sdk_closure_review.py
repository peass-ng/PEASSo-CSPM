"""CloudTrail and KMS SDK-to-public-collector closure review.

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

    def collect(kind, responses, *, options=None):
        calls, clients = [], {}
        requests = original_requests({'retry_attempts': 1, 'service_concurrency': 1, 'max_calls': 300, **(options or {})}, sleep=lambda _: None)
        requests.observed_at = STAMP
        native = {('ec2', 'describe_regions'): {'Regions': [{'RegionName': REGION, 'OptInStatus': 'opt-in-not-required'}]}, ('sts', 'get_caller_identity'): {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/review', 'UserId': 'AIDAOFFLINEREVIEW'}, **responses}

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
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'options': options or {}}, [kind] if isinstance(kind, str) else kind)
        runs.append((snapshot, calls))
        return snapshot, calls

    return collect


def item_of(snapshot, kind):
    rows = [row for envelope in snapshot['collections'] if envelope['type'] == kind for row in envelope['items']]
    assert len(rows) == 1
    return rows[0]


def verdict(snapshot, cid):
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid])['findings'] if row['check_id'] == cid]
    assert len(rows) == 1, rows
    return rows[0]['status']




KEY_ID = '11111111-2222-3333-4444-555555555555'
KEY_ARN = f'arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}'
TRAIL_ARN = f'arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/audit'
GROUP_ARN = f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:audit:*'
BUCKET = 'offline-audit-review'
ROLE = f'arn:aws:iam::{ACCOUNT}:role/delivery'
ORG = 'o-abcdefghij'


def kms_responses(**metadata):
    return {('kms','list_keys'): {'Keys': [{'KeyId': KEY_ID, 'KeyArn': KEY_ARN}]},
        ('kms','describe_key'): {'KeyMetadata': {'KeyId': KEY_ID, 'Arn': KEY_ARN,
            'AWSAccountId': ACCOUNT, 'KeyManager': 'CUSTOMER', 'Origin': 'AWS_KMS',
            'KeySpec': 'SYMMETRIC_DEFAULT', 'CustomerMasterKeySpec': 'SYMMETRIC_DEFAULT',
            'Enabled': True, 'KeyState': 'Enabled', 'MultiRegion': False, **metadata}},
        ('kms','get_key_rotation_status'): {'KeyRotationEnabled': True, 'KeyId': KEY_ID},
        ('kms','get_key_policy'): {'Policy': json.dumps({'Statement': [{'Effect': 'Allow',
            'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'}, 'Action': 'kms:*', 'Resource': '*'}]})},
        ('kms','list_aliases'): {'Aliases': []}, ('kms','list_resource_tags'): {'Tags': []}}


def trail_responses(**metadata):
    return {('cloudtrail','describe_trails'): {'trailList': [{'Name': 'audit', 'TrailARN': TRAIL_ARN,
        'HomeRegion': REGION, 'IsMultiRegionTrail': True, 'IsOrganizationTrail': False,
        'IncludeGlobalServiceEvents': True, 'LogFileValidationEnabled': True, 'KmsKeyId': KEY_ARN,
        'S3BucketName': BUCKET, 'S3KeyPrefix': '', 'CloudWatchLogsLogGroupArn': GROUP_ARN,
        'CloudWatchLogsRoleArn': ROLE, **metadata}]},
        ('cloudtrail','get_trail_status'): {'IsLogging': True,
            'LatestCloudWatchLogsDeliveryTime': STAMP, 'LatestDeliveryTime': STAMP, 'LatestDeliveryError': ''},
        ('cloudtrail','get_event_selectors'): {'TrailARN': TRAIL_ARN, 'EventSelectors': [
            {'ReadWriteType': 'All', 'IncludeManagementEvents': True, 'DataResources': [
                {'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}]}]},
        ('cloudtrail','get_insight_selectors'): {'TrailARN': TRAIL_ARN,
            'InsightSelectors': [{'InsightType': 'ApiCallRateInsight'}]},
        ('logs','describe_log_groups'): {'logGroups': [{'logGroupName': 'audit', 'arn': GROUP_ARN, 'kmsKeyId': KEY_ARN}]},
        ('s3','list_buckets'): {'Buckets': [{'Name': BUCKET}]},
        ('s3','get_bucket_location'): {},
        ('s3','get_bucket_logging'): {'LoggingEnabled': {'TargetBucket': 'offline-access-review', 'TargetPrefix': 'access/'}},
        ('s3','get_bucket_versioning'): {'Status': 'Enabled', 'MFADelete': 'Enabled'},
        ('s3','get_bucket_policy'): ('NoSuchBucketPolicy',),
        ('s3','get_bucket_acl'): {'Owner': {'ID': 'a'*64}, 'Grants': []},
        ('s3','get_bucket_lifecycle_configuration'): {'Rules': [{'ID': 'retention', 'Status': 'Enabled', 'Filter': {}, 'Expiration': {'Days': 365}}]},
        ('s3','get_object_lock_configuration'): {'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 365}}}}}


TRAIL_KINDS = ['cloudtrail', 'cloudtrail_account_inventory', 'bucket', 'log_group', 'kms_key']


@pytest.mark.parametrize('cid,field', [
    ('aws.cloudtrail.kms_encryption','KmsKeyId'),
    ('aws.cloudtrail.log_validation','LogFileValidationEnabled'),
])
def test_native_trail_base(pipeline, cid, field):
    for value, expected in [(KEY_ARN if field=='KmsKeyId' else True, 'PASS'), ('' if field=='KmsKeyId' else False, 'FAIL')]:
        snapshot, _ = pipeline('cloudtrail', trail_responses(**{field: value}))
        assert verdict(snapshot, cid)==expected
    snapshot, _ = pipeline('cloudtrail', {})
    assert verdict(snapshot, cid)=='DENIED'


@pytest.mark.parametrize('cid', [
    'aws.cloudtrail.management_events', 'aws.gap.cloudtrail.multi_region_read_write_management',
    'aws.gap.cloudtrail.region_logging_management_events', 'aws.gap.cloudtrail.trail_security_best_practices',
    'aws.gap.cloudtrail.bedrock_api_logging', 'aws.gap.cloudtrail.s3_all_buckets_read_data_events',
    'aws.gap.cloudtrail.s3_all_buckets_write_data_events',
])
def test_native_trail_selectors(pipeline, cid):
    for mode, expected in [('all','PASS'), ('excluded','FAIL'), ('denied','UNKNOWN')]:
        responses=trail_responses()
        if mode=='excluded':
            responses['cloudtrail','get_event_selectors']['EventSelectors']=[{'ReadWriteType':'ReadOnly','IncludeManagementEvents':False}]
        if mode=='denied': responses['cloudtrail','get_event_selectors']=None
        snapshot,_=pipeline('cloudtrail',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid', ['aws.a.cloudtrail.cloudwatch_delivery_24h',
    'aws.a.cloudtrail.home_cloudwatch_date', 'aws.a.cloudtrail.home_multiregion_cloudwatch_date'])
def test_native_cloudwatch_timestamp(pipeline,cid):
    for stamp,expected in [(STAMP,'PASS'),(datetime(2024,1,1,tzinfo=timezone.utc),'FAIL'),(None,'UNKNOWN')]:
        responses=trail_responses()
        if stamp is None:responses['cloudtrail','get_trail_status']=None
        else:responses['cloudtrail','get_trail_status']['LatestCloudWatchLogsDeliveryTime']=stamp
        snapshot,_=pipeline('cloudtrail',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid', ['aws.a.cloudtrail.insights_logging_trail','aws.claude2_a.cloudtrail.region_has_logging_trail'])
def test_logging_and_insights(pipeline,cid):
    for mode,expected in [('enabled','PASS'),('disabled','FAIL'),('denied','UNKNOWN')]:
        responses=trail_responses()
        operation='get_insight_selectors' if 'insights' in cid else 'get_trail_status'
        if mode=='disabled': responses['cloudtrail',operation]=('InsightNotEnabledException',) if 'insights' in cid else {'IsLogging':False}
        if mode=='denied':responses['cloudtrail',operation]=None
        snapshot,_=pipeline('cloudtrail',responses)
        assert verdict(snapshot,cid)==expected


BUCKET_LOG_IDS = ['aws.a.cloudtrail.bucket_access_logging','aws.a.cloudtrail.home_bucket_access_logging',
    'aws.nist.all_cloudtrail_destination_bucket_access_logging','aws_g6_all_cloudtrail_destination_bucket_access_logging',
    'aws_nist_cloudtrail_s3_logging_enabled']
BUCKET_MFA_IDS = ['aws.a.cloudtrail.bucket_mfa_delete','aws.a.cloudtrail.home_bucket_mfa_join','aws.claude2_a.cloudtrail.trail_bucket_mfa_delete']
@pytest.mark.parametrize('cid',BUCKET_LOG_IDS+BUCKET_MFA_IDS)
def test_native_destination_bucket_configuration(pipeline,cid):
    for mode,expected in [('enabled','PASS'),('absent','FAIL'),('denied','UNKNOWN')]:
        responses=trail_responses()
        operation='get_bucket_versioning' if cid in BUCKET_MFA_IDS else 'get_bucket_logging'
        if mode=='absent':responses['s3',operation]={}
        if mode=='denied':responses['s3',operation]=None
        snapshot,_=pipeline(TRAIL_KINDS,responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('mode,expected',[('private','PASS'),('public','FAIL'),('denied','UNKNOWN')])
def test_destination_declared_public_grants(pipeline,mode,expected):
    responses=trail_responses()
    if mode=='public':responses['s3','get_bucket_acl']['Grants']=[{'Grantee':{'Type':'Group','URI':'http://acs.amazonaws.com/groups/global/AllUsers'},'Permission':'READ'}]
    if mode=='denied':responses['s3','get_bucket_acl']=None
    snapshot,_=pipeline(TRAIL_KINDS,responses)
    assert verdict(snapshot,'aws.a.cloudtrail.joined_bucket_declared_public_grants')==expected


@pytest.mark.parametrize('cid',['aws.nist.cloudtrail_cloudwatch_integration','aws_g6_cloudtrail_all_trails_cloudwatch_integration'])
def test_native_log_group_destination(pipeline,cid):
    for mode,expected in [('matching','PASS'),('missing','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN')]:
        responses=trail_responses()
        if mode=='missing':responses['logs','describe_log_groups']={'logGroups':[]}
        if mode=='denied':responses['logs','describe_log_groups']=None
        if mode=='foreign':responses['logs','describe_log_groups']['logGroups'][0]['arn']=GROUP_ARN.replace(ACCOUNT,'999999999999')
        snapshot,_=pipeline(TRAIL_KINDS,responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid',['aws.nist.cloudtrail_cloudwatch_destination_kms','aws_fedramp_cloudtrail_destination_kms',
    'aws_g6_cloudtrail_kms_destination_join','aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk'])
def test_native_destination_customer_key_join(pipeline,cid):
    for mode,expected in [('customer','PASS'),('aws','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN')]:
        responses={**trail_responses(),**kms_responses()}
        if mode=='aws':responses['kms','describe_key']['KeyMetadata']['KeyManager']='AWS'
        if mode=='denied':responses['kms','describe_key']=None
        if mode=='foreign':responses['kms','describe_key']['KeyMetadata']['Arn']=KEY_ARN.replace(KEY_ID,'66666666-2222-3333-4444-555555555555')
        snapshot,_=pipeline(TRAIL_KINDS,responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('days,expected',[(365,'PASS'),(30,'FAIL'),(None,'UNKNOWN')])
def test_native_bucket_retention(pipeline,days,expected):
    responses=trail_responses()
    if days is None:responses['s3','get_object_lock_configuration']=None
    else:responses['s3','get_bucket_lifecycle_configuration']['Rules'][0]['Expiration']['Days']=days
    snapshot,_=pipeline(TRAIL_KINDS,responses)
    assert verdict(snapshot,'aws_cloudtrail_bucket_lifecycle_retention_365')==expected


@pytest.mark.parametrize('cid,field,bad',[
    ('aws.claude_a.kms.customer_key_enabled_or_pending_deletion','Enabled',False),
    ('aws.claude_a.kms.customer_key_not_pending_deletion','KeyState','PendingDeletion'),
    ('aws.claude_a.kms.prowler_cmk_used','KeyState','Disabled'),
    ('aws.claude_a.kms.prowler_cmk_single_region','MultiRegion',True),
])
def test_native_key_state(pipeline,cid,field,bad):
    for mode,expected in [('enabled','PASS'),('negative','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN')]:
        responses=kms_responses()
        if mode=='negative':
            responses['kms','describe_key']['KeyMetadata'][field]=bad
            if field=='Enabled':responses['kms','describe_key']['KeyMetadata']['KeyState']='Disabled'
        if mode=='denied':responses['kms','describe_key']=None
        if mode=='foreign':responses['kms','describe_key']['KeyMetadata']['KeyId']='foreign'
        snapshot,_=pipeline('kms_key',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid',['aws.kms.rotation','aws.claude_a.kms.prowler_cmk_rotation'])
def test_native_rotation(pipeline,cid):
    for value,expected in [(True,'PASS'),(False,'FAIL'),(None,'UNKNOWN')]:
        responses=kms_responses()
        responses['kms','get_key_rotation_status']=None if value is None else {'KeyRotationEnabled':value,'KeyId':KEY_ID}
        snapshot,_=pipeline('kms_key',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid',['aws.claude_a.kms.key_policy_not_public','aws.claude_a.kms.prowler_key_not_public'])
def test_native_key_policy(pipeline,cid):
    for mode,expected in [('private','PASS'),('public','FAIL'),('denied','UNKNOWN'),('malformed','UNKNOWN')]:
        responses=kms_responses()
        if mode=='public':responses['kms','get_key_policy']={'Policy':json.dumps({'Statement':[{'Effect':'Allow','Principal':'*','Action':'kms:*','Resource':'*'}]})}
        if mode=='denied':responses['kms','get_key_policy']=None
        if mode=='malformed':responses['kms','get_key_policy']={'Policy':'{'}
        snapshot,_=pipeline('kms_key',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('cid',['aws.review.kms.enclave_attestation_enforced','aws.review.kms.enclave_no_bypass','aws.review.kms.enclave_deployment_binding'])
def test_native_enclave_policy(pipeline,cid):
    for mode,expected in [('bound','PASS'),('unbound','FAIL'),('denied','UNKNOWN')]:
        responses=kms_responses(Description='enclave application key')
        condition={'StringEquals':{'kms:RecipientAttestation:PCR3':'ab'*48}}
        if mode=='unbound':condition={'StringEquals':{'kms:RecipientAttestation:PCR0':'ab'*48}} if 'deployment' in cid else {}
        responses['kms','get_key_policy']=None if mode=='denied' else {'Policy':json.dumps({'Statement':[{'Effect':'Allow','Principal':{'AWS':f'arn:aws:iam::{ACCOUNT}:role/application'},'Action':'kms:Decrypt','Resource':'*','Condition':condition}]})}
        snapshot,_=pipeline('kms_key',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('spec,expected',[('RSA_2048','PASS'),('SYMMETRIC_DEFAULT','FAIL'),(None,'UNKNOWN')])
def test_native_imported_key_spec(pipeline,spec,expected):
    responses=kms_responses(Origin='EXTERNAL',KeyUsage='ENCRYPT_DECRYPT')
    if spec is None:responses['kms','describe_key']=None
    else:responses['kms','describe_key']['KeyMetadata']['KeySpec']=spec
    snapshot,_=pipeline('kms_key',responses)
    assert verdict(snapshot,'aws_kms_imported_key_origin_spec')==expected


@pytest.mark.parametrize('cid,tag',[('aws_kms_compromised_key_restricted','Compromised'),('aws_kms_key_expiry','Retired')])
def test_native_key_lifecycle_tags(pipeline,cid,tag):
    for mode,expected in [('disabled','PASS'),('enabled','FAIL'),('denied','UNKNOWN')]:
        responses=kms_responses(KeyState='Disabled' if mode=='disabled' else 'Enabled',Enabled=mode!='disabled')
        responses['kms','list_resource_tags']=None if mode=='denied' else {'Tags':[{'TagKey':tag,'TagValue':'true'}]}
        snapshot,_=pipeline('kms_key',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('mode,expected',[('normal','PASS'),('debug','FAIL'),('foreign','UNKNOWN'),('malformed','UNKNOWN'),('denied','DENIED')])
def test_native_enclave_event_projection(pipeline,mode,expected):
    event_id='11111111-1111-1111-1111-111111111111'
    digest='0'*96 if mode=='debug' else 'ab'*48
    payload={'eventID':event_id,'eventName':'Decrypt','eventSource':'kms.amazonaws.com',
        'eventType':'AwsApiCall','eventTime':STAMP.isoformat(),'recipientAccountId':ACCOUNT,
        'awsRegion':REGION,'additionalEventData':{'recipient':{
            'attestationDocumentModuleId':'i-0123456789abcdef0-enc0123456789abcdef',
            'attestationDocumentEnclaveImageDigest':digest,'attestationDocumentEnclavePCR1':digest,
            'attestationDocumentEnclavePCR2':digest}}}
    if mode=='foreign':payload['recipientAccountId']='999999999999'
    if mode=='malformed':payload['additionalEventData']['recipient']['attestationDocumentEnclavePCR1']='invalid'
    def events(arguments):
        if mode=='denied':return None
        if arguments['LookupAttributes'][0]['AttributeValue']!='Decrypt':return {'Events':[]}
        return {'Events':[{'EventId':event_id,'EventName':'Decrypt','EventSource':'kms.amazonaws.com',
            'EventTime':STAMP,'CloudTrailEvent':json.dumps(payload)}]}
    snapshot,calls=pipeline('cloudtrail_event',{('cloudtrail','lookup_events'):events})
    assert verdict(snapshot,'aws.review.kms.enclave_debug_measurements')==expected
    # The projection must discard raw event JSON before the public snapshot.
    assert 'CloudTrailEvent' not in json.dumps(snapshot)
    assert all(operation not in ('decrypt','generate_data_key') for service,operation,args in calls)


def organization_responses():
    member='222222222222'
    return {('organizations','describe_organization'):{'Organization':{'Id':ORG,
        'Arn':f'arn:aws:organizations::{ACCOUNT}:organization/{ORG}','MasterAccountId':ACCOUNT,
        'MasterAccountArn':f'arn:aws:organizations::{ACCOUNT}:account/{ORG}/{ACCOUNT}','FeatureSet':'ALL'}},
        ('organizations','list_accounts'):{'Accounts':[{'Id':member,'Name':'member','State':'ACTIVE'}]},
        ('organizations','describe_resource_policy'):{'ResourcePolicy':{
            'ResourcePolicySummary':{'Id':'rp-abcdefghij','Arn':f'arn:aws:organizations::{ACCOUNT}:resourcepolicy/{ORG}/rp-abcdefghij'},
            'Content':json.dumps({'Statement':[{'Effect':'Allow','Principal':{'AWS':f'arn:aws:iam::{member}:root'},
                'Action':['organizations:CreatePolicy','organizations:UpdatePolicy','organizations:AttachPolicy'],'Resource':'*'}]})}}}


@pytest.mark.parametrize('mode,expected',[('delegate','PASS'),('absent','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN')])
def test_native_organization_delegate(pipeline,mode,expected):
    responses=organization_responses()
    if mode=='absent':responses['organizations','describe_resource_policy']=('ResourcePolicyNotFoundException',)
    if mode=='denied':responses['organizations','describe_resource_policy']=None
    if mode=='foreign':responses['organizations','describe_resource_policy']['ResourcePolicy']['ResourcePolicySummary']['Arn']=f'arn:aws:organizations::999999999999:resourcepolicy/{ORG}/rp-abcdefghij'
    snapshot,_=pipeline(['organization','organization_resource_policy','organization_account'],responses)
    assert verdict(snapshot,'aws_cis_organizations_policy_management_delegated')==expected


@pytest.mark.parametrize('mode,expected',[('fresh','PASS'),('empty','FAIL'),('denied','UNKNOWN'),('foreign','UNKNOWN'),('partial','UNKNOWN')])
def test_native_s3_delivery_metadata(pipeline,mode,expected):
    responses={**trail_responses(IsOrganizationTrail=True),**organization_responses()}
    prefix=f'AWSLogs/{ORG}/{ACCOUNT}/CloudTrail/{REGION}/'
    responses['s3','get_bucket_location']={'ResponseMetadata':{'HTTPStatusCode':200}}
    response={'Name':BUCKET,'Prefix':prefix,'IsTruncated':mode=='partial','KeyCount':0 if mode=='empty' else 1,
        'Contents':[] if mode=='empty' else [{'Key':prefix+f'2026/10/19/{ACCOUNT}_CloudTrail_{REGION}_20261019T0000Z_0123456789abcdef.json.gz','LastModified':STAMP,'Size':100}],
        'ResponseMetadata':{'HTTPStatusCode':200}}
    if mode=='foreign':response['Name']='foreign-bucket'
    if mode=='partial':response['NextContinuationToken']='next-page'
    responses['s3','list_objects_v2']=None if mode=='denied' else response
    snapshot,calls=pipeline(TRAIL_KINDS,responses,options={'max_pages':1} if mode=='partial' else None)
    assert verdict(snapshot,'aws_cloudtrail_s3_siem_delivery')==expected
    assert not any(op in ('get_object','select_object_content') for svc,op,args in calls)


@pytest.mark.parametrize('mode,expected',[('missing','FAIL'),('denied','UNKNOWN')])
def test_native_delivery_role_boundary(pipeline,mode,expected):
    # Full permission proof belongs to the role agent; this bounds the consumer's
    # native missing-destination and denied-role branches without fabricating it.
    responses=trail_responses(CloudWatchLogsLogGroupArn='' if mode=='missing' else GROUP_ARN)
    snapshot,_=pipeline(TRAIL_KINDS+['cloudtrail_delivery_role_scope'],responses)
    assert verdict(snapshot,'aws_nist_cloudtrail_trail_integrated_with_logs')==expected


@pytest.mark.parametrize('cid',['aws.kms.rotation','aws.claude_a.kms.prowler_cmk_rotation'])
def test_foreign_rotation_identity_cannot_certify_subject(pipeline,cid):
    responses=kms_responses()
    responses['kms','get_key_rotation_status']['KeyId']='66666666-2222-3333-4444-555555555555'
    snapshot,_=pipeline('kms_key',responses)
    assert verdict(snapshot,cid)=='UNKNOWN'


@pytest.mark.parametrize('cid',['aws.cloudtrail.management_events','aws.gap.cloudtrail.region_logging_management_events',
    'aws.gap.cloudtrail.s3_all_buckets_read_data_events'])
def test_foreign_event_selector_identity(pipeline,cid):
    responses=trail_responses()
    responses['cloudtrail','get_event_selectors']['TrailARN']=TRAIL_ARN.replace('/audit','/foreign')
    snapshot,_=pipeline('cloudtrail',responses)
    assert verdict(snapshot,cid)=='UNKNOWN'


@pytest.mark.parametrize('cid',['aws.nist.all_cloudtrail_destination_bucket_access_logging',
    'aws.nist.cloudtrail_cloudwatch_destination_kms'])
def test_partial_account_inventory_cannot_certify_universe(pipeline,cid):
    responses={**trail_responses(),**kms_responses()}
    # Native paginator token plus a one-page bound yields a real partial read.
    responses['cloudtrail','describe_trails']['NextToken']='next-page'
    snapshot,_=pipeline(TRAIL_KINDS,responses,options={'max_pages':1})
    assert verdict(snapshot,cid)=='UNKNOWN'


@pytest.mark.parametrize('reference',[KEY_ID, KEY_ARN, None])
def test_native_rotation_optional_identity(pipeline,reference):
    responses=kms_responses()
    if reference is None:responses['kms','get_key_rotation_status'].pop('KeyId')
    else:responses['kms','get_key_rotation_status']['KeyId']=reference
    snapshot,_=pipeline('kms_key',responses)
    assert verdict(snapshot,'aws.kms.rotation')=='PASS'


@pytest.mark.parametrize('cid',['aws.a.cloudtrail.bucket_access_logging','aws.a.cloudtrail.home_bucket_mfa_join',
    'aws.claude2_a.cloudtrail.trail_bucket_mfa_delete','aws.nist.all_cloudtrail_destination_bucket_access_logging'])
def test_native_destination_bucket_identity(pipeline,cid):
    responses=trail_responses()
    responses['s3','list_buckets']={'Buckets':[{'Name':'other-owned-review'}]}
    snapshot,_=pipeline(TRAIL_KINDS,responses)
    expected={'aws.a.cloudtrail.bucket_access_logging':'UNKNOWN','aws.a.cloudtrail.home_bucket_mfa_join':'FAIL',
        'aws.claude2_a.cloudtrail.trail_bucket_mfa_delete':'MANUAL',
        'aws.nist.all_cloudtrail_destination_bucket_access_logging':'UNKNOWN'}[cid]
    assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('mode,expected',[('denied','UNKNOWN'),('partial','UNKNOWN'),('foreign_alias','NOT_APPLICABLE')])
def test_native_enclave_applicability_inventory(pipeline,mode,expected):
    responses=kms_responses()
    if mode=='denied':responses['kms','list_resource_tags']=None
    if mode=='partial':responses['kms','list_resource_tags']={'Tags':[],'Truncated':True,'NextMarker':'next'}
    if mode=='foreign_alias':responses['kms','list_aliases']={'Aliases':[{'AliasName':'alias/enclave-foreign','TargetKeyId':'66666666-2222-3333-4444-555555555555'}]}
    snapshot,_=pipeline('kms_key',responses,options={'max_pages':1} if mode=='partial' else None)
    assert verdict(snapshot,'aws.review.kms.enclave_attestation_enforced')==expected


@pytest.mark.parametrize('cid',['aws.cloudtrail.management_events',
    'aws.gap.cloudtrail.region_logging_management_events',
    'aws.gap.cloudtrail.s3_all_buckets_read_data_events'])
def test_missing_native_selector_identity_is_unknown(pipeline,cid):
    responses=trail_responses()
    responses['cloudtrail','get_event_selectors'].pop('TrailARN')
    snapshot,_=pipeline('cloudtrail',responses)
    assert verdict(snapshot,cid)=='UNKNOWN'
