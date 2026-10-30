"""Independent SDK-shaped contract probes; no runtime/catalog mutation or live AWS.

Assertions cover named branches only. Expected conservative UNKNOWN outcomes and
known defects are recorded explicitly rather than masked as passing compliance.
"""
import copy
import json
from datetime import datetime, timezone
from urllib.parse import quote
import pytest
from peaso import engine
from peaso.collectors import aws

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT+'/'+REGION
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
REGISTRY = {check.id: check for check in engine._registry()}
IDS = ['aws.claude2_a.cloudtrail.region_has_logging_trail', 'aws.claude_a.ec2.instance_in_vpc', 'aws.claude_a.ec2.instance_no_public_ip', 'aws.claude_a.ec2.instance_no_public_ip_not_terminated', 'aws.claude_a.ec2.instance_profile_attached', 'aws.claude_a.ec2.instance_profile_attached_not_terminated', 'aws.claude_a.ec2.internet_facing_without_profile', 'aws.claude_a.ec2.public_instance_has_profile', 'aws.claude_a.ec2.running_instance_no_key_pair', 'aws.claude_a.iam.prowler_role_inline_no_admin', 'aws.claude_a.iam.prowler_role_inline_no_cloudtrail_full_access', 'aws.claude_a.iam.prowler_role_inline_no_kms_full_access', 'aws.claude_a.iam.prowler_role_inline_no_marketplace_subscribe', 'aws.claude_a.iam.prowler_role_inline_no_privilege_escalation', 'aws.claude_a.iam.prowler_user_inline_no_admin', 'aws.claude_a.iam.prowler_user_inline_no_cloudtrail_full_access', 'aws.claude_a.iam.prowler_user_inline_no_kms_full_access', 'aws.claude_a.iam.prowler_user_inline_no_marketplace_subscribe', 'aws.claude_a.iam.prowler_user_inline_no_privilege_escalation', 'aws.claude_a.iam.role_inline_kms_decrypt_restricted', 'aws.claude_a.iam.role_inline_no_admin', 'aws.claude_a.iam.role_inline_no_blocked_kms_actions', 'aws.claude_a.iam.user_inline_kms_decrypt_restricted', 'aws.claude_a.iam.user_inline_no_admin', 'aws.claude_a.iam.user_inline_no_assume_role_text', 'aws.claude_a.iam.user_inline_no_blocked_kms_actions', 'aws.claude_a.s3.acls_prohibit_user_access', 'aws.claude_a.s3.bucket_public_access_block_all', 'aws.claude_a.s3.lifecycle_rule_enabled', 'aws.claude_a.s3.object_lock_configured', 'aws.claude_a.s3.replication_rule_enabled', 'aws.cloudtrail.kms_encryption', 'aws.cloudtrail.management_events', 'aws.gap.cloudtrail.trail_security_best_practices', 'aws.iam.console_mfa', 'aws.iam.restrict_public_trust', 'aws.rds.backups', 'aws.rds.enhanced_monitoring', 'aws.rds.vpc_configuration', 'aws.s3.access_logging', 'aws.s3.default_encryption', 'aws.s3.no_public_acl', 'aws.s3.public_access_block', 'aws.s3.versioning']

@pytest.fixture
def sdk(monkeypatch):
    import boto3
    from botocore.stub import Stubber
    session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name=REGION)
    clients, stubs, routes = {}, {}, []
    def stub(service, region=REGION):
        if (service, region) not in clients:
            clients[service, region] = session.client(service, region_name=region)
            stubs[service, region] = Stubber(clients[service, region])
            stubs[service, region].activate()
        return stubs[service, region]
    def client(self, selected, service, region):
        assert selected is session
        routes.append((service, region))
        return clients[service, region]
    monkeypatch.setattr(aws.Requests, 'client', client)
    # botocore Stubber answers in FIFO order per client. b8745bca reads the
    # per-bucket S3 details concurrently, so keep one worker here; the serial
    # path assigns identical rows (aws_request_pool.ordered_map keeps order).
    requests = aws.Requests({'retry_attempts': 1, 'service_concurrency': 1})
    yield requests, session, stub, routes
    for value in stubs.values():
        value.assert_no_pending_responses()
        value.deactivate()


def index_for(kind, rows, *, status='collected', global_type=False):
    return {'context': {'provider': 'aws', 'scope': SCOPE, 'Account': ACCOUNT, 'created_at': NOW.isoformat()},
            'collections': {kind: [{'type': kind, 'scope': ACCOUNT+'/global' if global_type else SCOPE,
                                   'account_id': ACCOUNT, 'region': 'global' if global_type else REGION,
                                   'global': global_type, 'status': status, 'items': rows}]},
            kind: [{'data': row, 'scope': ACCOUNT+'/global' if global_type else SCOPE, 'type': kind} for row in rows]}


def collect_iam(sdk, cid, unsafe=False, login_absent=False, trust_variant=None):
    requests, session, stub, _ = sdk
    kind = REGISTRY[cid].kind
    is_user = kind == 'iam_user'
    key, list_key, arn_key = ('UserName', 'UserPolicyList', 'user') if is_user else ('RoleName', 'RolePolicyList', 'role')
    statement = {'Effect': 'Allow', 'Action': ['*', 'sts:AssumeRole', 'kms:Decrypt'] if unsafe else ['s3:GetObject'], 'Resource': '*'}
    trust = {'Statement': [{'Effect': 'Allow', 'Principal': '*' if unsafe else {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}
    if trust_variant == 'Condition':
        trust['Statement'][0]['Condition'] = {'StringEquals': {'aws:PrincipalOrgID': 'o-example'}}
    if trust_variant == 'NotAction':
        trust['Statement'][0].pop('Action')
        trust['Statement'][0]['NotAction'] = 'sts:TagSession'
    row = {key: 'review', 'Arn': f'arn:aws:iam::{ACCOUNT}:{arn_key}/review',
           list_key: [{'PolicyName': 'review-policy', 'PolicyDocument': quote(json.dumps({'Statement': [statement]}))}]}
    if not is_user:
        row['AssumeRolePolicyDocument'] = quote(json.dumps(trust))
    auth = {'IsTruncated': False, 'UserDetailList': [row] if is_user else [], 'RoleDetailList': [] if is_user else [row], 'Policies': []}
    api = stub('iam')
    api.add_response('get_account_authorization_details', auth, {})
    if is_user:
        api.add_response('list_access_keys', {'AccessKeyMetadata': [], 'IsTruncated': False}, {'UserName': 'review'})
        if login_absent:
            api.add_client_error('get_login_profile', service_error_code='NoSuchEntity', expected_params={'UserName': 'review'})
        else:
            api.add_response('get_login_profile', {'LoginProfile': {'UserName': 'review', 'CreateDate': NOW}}, {'UserName': 'review'})
        api.add_response('list_mfa_devices', {'MFADevices': [] if unsafe else [{'UserName': 'review', 'SerialNumber': f'arn:aws:iam::{ACCOUNT}:mfa/review', 'EnableDate': NOW}], 'IsTruncated': False}, {'UserName': 'review'})
    read = aws._iam(requests, session, REGION, {kind})[kind]
    assert read.status == 'collected'
    item = read.items[0]
    assert isinstance(item[list_key][0]['PolicyDocument'], dict)
    return item, index_for(kind, [item], global_type=True)


def collect_instance(sdk, cid, unsafe=False):
    requests, session, stub, _ = sdk
    suffix = cid.rsplit('.', 1)[-1]
    row = {'InstanceId': 'i-0123456789abcdef0', 'State': {'Name': 'running'}, 'VpcId': 'vpc-0123456789abcdef0',
           'IamInstanceProfile': {'Arn': f'arn:aws:iam::{ACCOUNT}:instance-profile/review', 'Id': 'AIPAXXXXXXXXXXXXXXXXX'}}
    if suffix == 'instance_in_vpc' and unsafe: row.pop('VpcId')
    if 'profile_attached' in suffix and unsafe: row.pop('IamInstanceProfile')
    if suffix in ('instance_no_public_ip', 'instance_no_public_ip_not_terminated', 'internet_facing_without_profile') and unsafe: row['PublicIpAddress'] = '203.0.113.5'
    if suffix == 'public_instance_has_profile':
        row['PublicIpAddress'] = '203.0.113.5'
        if unsafe: row.pop('IamInstanceProfile')
    if suffix == 'running_instance_no_key_pair' and unsafe: row['KeyName'] = 'review-key'
    api = stub('ec2')
    api.add_response('describe_instances', {'Reservations': [{'Instances': [row]}]}, {})
    api.add_response('describe_instance_attribute', {'InstanceId': row['InstanceId'], 'UserData': {'Value': ''}}, {'InstanceId': row['InstanceId'], 'Attribute': 'userData'})
    api.add_response('describe_instance_attribute', {'InstanceId': row['InstanceId'], 'DisableApiTermination': {'Value': False}}, {'InstanceId': row['InstanceId'], 'Attribute': 'disableApiTermination'})
    read = requests.pages(session, 'ec2', REGION, 'describe_instances', 'Reservations[].Instances[]')
    item = aws._enrich(requests, session, REGION, 'instance', read.items, account=ACCOUNT, partition='aws')[0]
    return item, index_for('instance', [item])


def collect_rds(sdk, cid, unsafe=False):
    requests, session, stub, _ = sdk
    row = {'DBInstanceIdentifier': 'review', 'DBInstanceArn': f'arn:aws:rds:{REGION}:{ACCOUNT}:db:review', 'Engine': 'postgres',
           'BackupRetentionPeriod': 0 if unsafe else 7, 'MonitoringInterval': 0 if unsafe else 60}
    if not unsafe:
        row.update(DBSubnetGroup={'VpcId': 'vpc-0123456789abcdef0'}, EnhancedMonitoringResourceArn=f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:RDSOSMetrics:log-stream:review')
    stub('rds').add_response('describe_db_instances', {'DBInstances': [row]}, {})
    read = requests.pages(session, 'rds', REGION, 'describe_db_instances', 'DBInstances')
    item = aws._enrich(requests, session, REGION, 'rds_instance', read.items, account=ACCOUNT, partition='aws')[0]
    return item, index_for('rds_instance', [item])


def collect_trail(sdk, cid, unsafe=False, foreign=False):
    requests, session, stub, _ = sdk
    arn = f'arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/review'
    row = {'Name': 'review', 'TrailARN': arn, 'HomeRegion': REGION, 'IsMultiRegionTrail': True,
           'IncludeGlobalServiceEvents': True, 'LogFileValidationEnabled': not (unsafe and cid.endswith('trail_security_best_practices'))}
    if not (unsafe and cid.endswith('kms_encryption')): row['KmsKeyId'] = f'arn:aws:kms:{REGION}:{ACCOUNT}:key/review'
    api = stub('cloudtrail')
    api.add_response('describe_trails', {'trailList': [row]}, {})
    api.add_response('get_trail_status', {'IsLogging': not (unsafe and cid.endswith('region_has_logging_trail'))}, {'Name': arn})
    api.add_response('get_event_selectors', {'TrailARN': arn+'-foreign' if foreign else arn, 'EventSelectors': [{'IncludeManagementEvents': not (unsafe and cid.endswith('management_events')), 'ReadWriteType': 'All'}]}, {'TrailName': arn})
    api.add_response('get_insight_selectors', {'TrailARN': arn, 'InsightSelectors': []}, {'TrailName': arn})
    read = requests.pages(session, 'cloudtrail', REGION, 'describe_trails', 'trailList')
    item = aws._enrich(requests, session, REGION, 'cloudtrail', read.items, account=ACCOUNT, partition='aws')[0]
    return item, index_for('cloudtrail', [item])


def collect_bucket(sdk, cid, unsafe=False, absent_blocks=False):
    requests, session, stub, _ = sdk
    api = stub('s3')
    api.add_response('list_buckets', {'Buckets': [{'Name': 'review-bucket'}]}, {})
    api.add_response('get_bucket_location', {}, {'Bucket': 'review-bucket'})
    flags = {key: not unsafe for key in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')}
    owner = 'a'*64
    grants = [{'Grantee': {'Type': 'CanonicalUser', 'ID': owner}, 'Permission': 'FULL_CONTROL'}]
    if unsafe:
        grants += [{'Grantee': {'Type': 'CanonicalUser', 'ID': 'b'*64}, 'Permission': 'READ'}, {'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}]
    operations = [
        ('get_public_access_block', {'PublicAccessBlockConfiguration': flags}, 'NoSuchPublicAccessBlockConfiguration' if absent_blocks else None),
        ('get_bucket_policy_status', None, 'NoSuchBucketPolicy'), ('get_bucket_policy', None, 'NoSuchBucketPolicy'),
        ('get_bucket_encryption', {'ServerSideEncryptionConfiguration': {'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}}, 'ServerSideEncryptionConfigurationNotFoundError' if unsafe else None),
        ('get_bucket_versioning', {} if unsafe else {'Status': 'Enabled'}, None),
        ('get_bucket_acl', {'Owner': {'ID': owner}, 'Grants': grants}, None),
        ('get_bucket_ownership_controls', None, 'OwnershipControlsNotFoundError'),
        ('get_bucket_logging', {} if unsafe else {'LoggingEnabled': {'TargetBucket': 'audit', 'TargetPrefix': 'review/'}}, None),
        ('get_bucket_lifecycle_configuration', {'Rules': [{'Status': 'Enabled', 'Prefix': '', 'Expiration': {'Days': 365}}]}, 'NoSuchLifecycleConfiguration' if unsafe else None),
        ('get_bucket_notification_configuration', {}, None),
        ('get_bucket_replication', {'ReplicationConfiguration': {'Role': f'arn:aws:iam::{ACCOUNT}:role/replicate', 'Rules': [{'Status': 'Enabled', 'Destination': {'Bucket': 'arn:aws:s3:::replica'}, 'Prefix': ''}]}}, 'ReplicationConfigurationNotFoundError' if unsafe else None),
        ('get_object_lock_configuration', {'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled'}}, 'ObjectLockConfigurationNotFoundError' if unsafe else None),
        ('get_bucket_tagging', None, 'NoSuchTagSet')]
    for operation, response, error in operations:
        if error:
            api.add_client_error(operation, service_error_code=error, expected_params={'Bucket': 'review-bucket'})
        else:
            api.add_response(operation, response, {'Bucket': 'review-bucket'})
    read = aws._buckets(requests, session, REGION)
    assert read.status == 'collected'
    item = read.items[0]
    index = index_for('bucket', [item], global_type=True)
    if cid == 'aws.s3.public_access_block':
        control = stub('s3control')
        control.add_client_error('get_public_access_block', service_error_code='NoSuchPublicAccessBlockConfiguration', expected_params={'AccountId': ACCOUNT})
        account_read = aws._single(requests, session, REGION, 's3control', 'get_public_access_block', absent=('NoSuchPublicAccessBlockConfiguration',), AccountId=ACCOUNT)
        index['collections']['s3_account_public_access_block'] = [{'type': 's3_account_public_access_block', 'scope': ACCOUNT+'/global', 'account_id': ACCOUNT, 'global': True, 'status': account_read.status, 'items': account_read.items, 'error': account_read.error}]
        index['s3_account_public_access_block'] = []
    return item, index


def collect(sdk, cid, unsafe=False):
    kind = REGISTRY[cid].kind
    if kind in ('iam_user', 'iam_role'): return collect_iam(sdk, cid, unsafe)
    if kind == 'instance': return collect_instance(sdk, cid, unsafe)
    if kind == 'rds_instance': return collect_rds(sdk, cid, unsafe)
    if kind == 'cloudtrail': return collect_trail(sdk, cid, unsafe)
    if kind == 'bucket': return collect_bucket(sdk, cid, unsafe)
    raise AssertionError(kind)


def evaluate(cid, item, index):
    return REGISTRY[cid].evaluate({'scope': SCOPE} if REGISTRY[cid].target == 'scope' else item, index)


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('unsafe', [False, True])
def test_sdk_collector_to_registered_consumer(sdk, cid, unsafe):
    item, index = collect(sdk, cid, unsafe)
    expected = 'PASS'
    if unsafe:
        expected = 'FAIL'
        if cid in ('aws.rds.enhanced_monitoring', 'aws.rds.vpc_configuration', 'aws.s3.default_encryption'): expected = 'UNKNOWN'
        if cid == 'aws.s3.no_public_acl': expected = 'MANUAL'
    status, evidence = evaluate(cid, item, index)
    assert status == expected, (cid, status, evidence)


@pytest.mark.parametrize('cid', IDS)
def test_denied_root_never_passes(sdk, cid):
    item, index = collect(sdk, cid)
    item['collection_status'] = 'denied'
    if REGISTRY[cid].target == 'scope':
        index['collections']['cloudtrail'][0]['status'] = 'denied'
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


def test_foreign_trail_selector_counterexample(sdk):
    cid = 'aws.gap.cloudtrail.trail_security_best_practices'
    item, index = collect_trail(sdk, cid, foreign=True)
    # Confirmed pre-fix PASS; strict native identity now rejects this response.
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'
    assert evaluate('aws.cloudtrail.management_events', item, index)[0] == 'UNKNOWN'


def test_denied_selector_field_counterexample(sdk):
    cid = 'aws.gap.cloudtrail.trail_security_best_practices'
    item, index = collect_trail(sdk, cid)
    item['EventSelectors']['_coverage'] = {'EventSelectors': {'status': 'denied'}}
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'
    assert evaluate('aws.cloudtrail.management_events', item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', ['aws.claude_a.ec2.instance_profile_attached', 'aws.claude_a.ec2.instance_profile_attached_not_terminated', 'aws.claude_a.ec2.public_instance_has_profile'])
def test_empty_instance_profile_counterexample(sdk, cid):
    item, index = collect_instance(sdk, cid)
    item['IamInstanceProfile'] = {}
    # Confirmed pre-fix PASS; malformed attachment no longer establishes safety.
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mutation', ['missing_identity', 'denied_identity', 'both_selector_types'])
def test_native_selector_binding_guards(sdk, mutation):
    cid = 'aws.gap.cloudtrail.trail_security_best_practices'
    item, index = collect_trail(sdk, cid)
    body = item['EventSelectors']
    if mutation == 'missing_identity': body.pop('TrailARN')
    if mutation == 'denied_identity': body['_coverage'] = {'TrailARN': {'status': 'denied'}}
    if mutation == 'both_selector_types': body['AdvancedEventSelectors'] = [{'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Management']}]}]
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


def test_legacy_unmarked_single_selector_contract():
    from peaso.checks.aws_gap_core import selector_body
    row = {'EventSelectors': {'EventSelectors': [{'ReadWriteType': 'All', 'IncludeManagementEvents': True}]}}
    basic, advanced = selector_body(row)
    assert len(basic) == 1 and advanced == []


def test_user_inline_text_missing_document_counterexample(sdk):
    cid = 'aws.claude_a.iam.user_inline_no_assume_role_text'
    item, index = collect_iam(sdk, cid)
    item['UserPolicyList'][0].pop('PolicyDocument')
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


def test_login_profile_documented_absence(sdk):
    cid = 'aws.iam.console_mfa'
    item, index = collect_iam(sdk, cid, login_absent=True)
    assert item['LoginProfile']['absent'] is True
    assert item['LoginProfile']['error']['code'] == 'NoSuchEntity'
    assert evaluate(cid, item, index)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('cid', ['aws.s3.public_access_block', 'aws.claude_a.s3.bucket_public_access_block_all'])
def test_public_block_documented_absence(sdk, cid):
    item, index = collect_bucket(sdk, cid, absent_blocks=True)
    assert item['PublicAccessBlock']['absent'] is True
    assert item['PublicAccessBlock']['error']['code'] == 'NoSuchPublicAccessBlockConfiguration'
    assert evaluate(cid, item, index)[0] == 'FAIL'


@pytest.mark.parametrize('alternative', ['Condition', 'NotAction'])
def test_trust_relative_statement_paths(sdk, alternative):
    cid = 'aws.iam.restrict_public_trust'
    item, index = collect_iam(sdk, cid, unsafe=True, trust_variant=alternative)
    assert evaluate(cid, item, index)[0] == ('MANUAL' if alternative == 'Condition' else 'FAIL')


@pytest.mark.parametrize('cid', ['aws.claude_a.ec2.instance_no_public_ip', 'aws.iam.console_mfa', 'aws.s3.versioning', 'aws.rds.backups', 'aws.cloudtrail.management_events', 'aws.claude2_a.cloudtrail.region_has_logging_trail'])
def test_snapshot_engine_contract(sdk, cid, monkeypatch):
    from peaso.snapshot import make_snapshot
    item, index = collect(sdk, cid)
    monkeypatch.setattr(engine, '_registry', lambda: [REGISTRY[cid]])
    snapshot = make_snapshot('aws', [SCOPE], aws._safe(sum(index['collections'].values(), [])), created_at=NOW.isoformat())
    findings = [row for row in engine.evaluate_snapshot(snapshot, checks=[cid])['findings'] if row['check_id'] == cid]
    assert len(findings) == 1 and findings[0]['status'] == 'PASS', findings


@pytest.mark.parametrize('profile', [{'Arn': 'arn:aws:iam::123456789012:instance-profile/review'}, {'Id': 'AIPAXXXXX'}, {'Arn': '', 'Id': 'AIPAXXXXX'}, {'Arn': 'arn:aws:iam::123456789012:instance-profile/review', 'Id': 'AIPAXXXXX', '_coverage': {'Arn': {'status': 'denied'}}}])
def test_profile_member_guards(sdk, profile):
    cid = 'aws.claude_a.ec2.instance_profile_attached'
    item, index = collect_instance(sdk, cid)
    item['IamInstanceProfile'] = profile
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mutation', ['empty_document', 'denied_document', 'missing_name', 'denied_name'])
def test_inline_text_member_guards(sdk, mutation):
    cid = 'aws.claude_a.iam.user_inline_no_assume_role_text'
    item, index = collect_iam(sdk, cid)
    policy = item['UserPolicyList'][0]
    if mutation == 'empty_document': policy['PolicyDocument'] = {}
    if mutation == 'denied_document': policy['_coverage'] = {'PolicyDocument': {'status': 'denied'}}
    if mutation == 'missing_name': policy.pop('PolicyName')
    if mutation == 'denied_name': policy['_coverage'] = {'PolicyName': {'status': 'denied'}}
    assert evaluate(cid, item, index)[0] == 'UNKNOWN'
