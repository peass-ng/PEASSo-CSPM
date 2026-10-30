"""Portable archive scope and account-wide CloudTrail collector checks."""
from copy import deepcopy
import pytest
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot

ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/global'
BUCKET = 'archive-example'
CID = 'aws_log_archive_immutable'
ARN = 'arn:aws:cloudtrail:us-east-1:' + ACCOUNT + ':trail/audit'


def bucket(*, lock=True):
    return {'Name': BUCKET, 'Versioning': {'collection_status': 'collected', 'Status': 'Enabled'},
        'ObjectLock': {'collection_status': 'collected', 'ObjectLockConfiguration': {
            'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 30}}}}
            if lock else {'collection_status': 'empty'}}


def trail(destination=BUCKET):
    observed = {'TrailARN': ARN, 'Name': 'audit', 'HomeRegion': 'us-east-1',
        'SourceRegion': 'us-east-1', 'IsOrganizationTrail': False, 'IsMultiRegionTrail': True}
    return {**observed, 'AccountId': ACCOUNT, 'S3BucketName': destination,
        '_provenance': {'operation': 'cloudtrail:DescribeTrails', 'native_response_complete': True},
        '_account_trail_observations': [observed],
        '_account_trail_binding': {'caller_account_id': ACCOUNT,
            'identity_operation': 'sts:GetCallerIdentity',
            'describe_operation': 'cloudtrail:DescribeTrails',
            'include_shadow_trails': True, 'trail_arn': ARN,
            'capture_observed_at': '2026-10-18T00:00:00+00:00'}}


def envelope(kind, rows, *, status=None, scope=SCOPE, account=ACCOUNT, global_flag=True):
    return {'type': kind, 'scope': scope, 'account_id': account, 'global': global_flag,
        'service': 's3' if kind == 's3_bucket' else 'cloudtrail',
        'status': status or ('collected' if rows else 'empty'), 'items': deepcopy(rows)}


def _metadata():
    return {'region_discovery': [{'account_id': ACCOUNT, 'caller_account_id': ACCOUNT,
        'scope': SCOPE, 'partition': 'aws', 'source_operation': 'ec2:DescribeRegions',
        'all_regions': True, 'read_only': True, 'status': 'collected',
        'observed_at': '2026-10-18T00:00:00+00:00', 'regions': ['us-east-1']}]}


def verdict(bucket_rows=None, trails=None, *, trail_status=None, trail_scope=SCOPE, mutate=None, metadata_mutate=None):
    collections = [envelope('s3_bucket', [bucket()] if bucket_rows is None else bucket_rows),
        envelope('cloudtrail_account_inventory', [] if trail_status == 'denied' else ([trail()] if trails is None else trails),
            status=trail_status, scope=trail_scope)]
    if mutate is not None:
        mutate(collections)
    metadata = _metadata()
    if metadata_mutate is not None:
        metadata_mutate(metadata)
    snapshot = make_snapshot('aws', [SCOPE], collections, created_at='2026-10-18T00:00:00+00:00', metadata=metadata)
    before = deepcopy(snapshot)
    rows = [row for row in evaluate_snapshot(snapshot, checks=[CID])['findings'] if row['check_id'] == CID]
    assert snapshot == before
    assert len(rows) == 1
    return rows[0]['status']


def test_account_global_archive_decisions_and_incomplete_guards():
    assert verdict() == 'PASS'
    assert verdict(bucket_rows=[bucket(lock=False)]) == 'FAIL'
    assert verdict(trails=[trail('other-example')]) == 'NOT_APPLICABLE'
    assert verdict(trails=[]) == 'NOT_APPLICABLE'
    assert verdict(trail_status='partial') == 'UNKNOWN'
    assert verdict(trail_status='denied') == 'UNKNOWN'
    assert verdict(trail_scope=ACCOUNT + '/us-east-1') == 'UNKNOWN'
    row = trail(); row['_account_trail_binding']['caller_account_id'] = '999999999999'
    assert verdict(trails=[row]) == 'UNKNOWN'
    for field in ('S3BucketName', '_account_trail_binding'):
        row = trail(); row.setdefault('_coverage', {})[field] = {'status': 'denied'}
        assert verdict(trails=[row]) == 'UNKNOWN'
    row = trail(); row['S3BucketName'] = None
    assert verdict(trails=[row]) == 'UNKNOWN'
    row = trail(); row.pop('S3BucketName')
    assert verdict(trails=[row]) == 'UNKNOWN'
    assert verdict(mutate=lambda c: c[1].update(account_id='999999999999')) == 'UNKNOWN'
    assert verdict(mutate=lambda c: c[1].update({'global': False})) == 'UNKNOWN'
    assert verdict(mutate=lambda c: c[1].setdefault('_coverage', {}).update(status={'status': 'denied'})) == 'UNKNOWN'
    assert verdict(mutate=lambda c: c[0]['items'][0]['Versioning'].setdefault('_coverage', {}).update(Status={'status': 'denied'})) == 'UNKNOWN'
    assert verdict(mutate=lambda c: c[0]['items'][0].update(ObjectLock=None)) == 'UNKNOWN'
    assert verdict(mutate=lambda c: c[1]['items'][0]['_provenance'].setdefault('_coverage', {}).update(operation={'status': 'denied'})) == 'UNKNOWN'
    assert verdict(mutate=lambda c: c[1]['items'][0].setdefault('_coverage', {}).update(_account_trail_observations={'status': 'denied'})) == 'UNKNOWN'
    assert verdict(metadata_mutate=lambda m: m['region_discovery'][0].update(partition='aws-cn')) == 'UNKNOWN'
    assert verdict(metadata_mutate=lambda m: m['region_discovery'][0].setdefault('_coverage', {}).update(regions={'status': 'denied'})) == 'UNKNOWN'


def test_organization_trail_and_identity_boundaries():
    org = trail()
    foreign_arn = 'arn:aws:cloudtrail:us-east-1:999999999999:trail/organization'
    org.update(TrailARN=foreign_arn, IsOrganizationTrail=True)
    org['_account_trail_binding']['trail_arn'] = foreign_arn
    org['_account_trail_observations'][0].update(TrailARN=foreign_arn, IsOrganizationTrail=True)
    assert verdict(trails=[org]) == 'PASS'
    foreign_nonorg = deepcopy(org); foreign_nonorg['IsOrganizationTrail'] = False
    foreign_nonorg['_account_trail_observations'][0]['IsOrganizationTrail'] = False
    assert verdict(trails=[foreign_nonorg]) == 'UNKNOWN'
    invalid = deepcopy(org); invalid_arn = 'arn:aws:cloudtrail:us-east-1:999999999999:trail/a/b'
    invalid['TrailARN'] = invalid_arn
    invalid['_account_trail_binding']['trail_arn'] = invalid_arn
    invalid['_account_trail_observations'][0]['TrailARN'] = invalid_arn
    assert verdict(trails=[invalid]) == 'UNKNOWN'
    for field, value in (('capture_observed_at', '2026-10-17T00:00:00+00:00'),
            ('caller_account_id', '999999999999')):
        bad = deepcopy(org); bad['_account_trail_binding'][field] = value
        assert verdict(trails=[bad]) == 'UNKNOWN'
    wrong_home = deepcopy(org); wrong_home['HomeRegion'] = 'eu-west-1'
    wrong_home['_account_trail_observations'][0]['HomeRegion'] = 'eu-west-1'
    assert verdict(trails=[wrong_home]) == 'UNKNOWN'
    wrong_partition = deepcopy(org)
    arn = foreign_arn.replace('arn:aws:', 'arn:aws-us-gov:')
    wrong_partition['TrailARN'] = arn
    wrong_partition['_account_trail_binding']['trail_arn'] = arn
    wrong_partition['_account_trail_observations'][0]['TrailARN'] = arn
    assert verdict(trails=[wrong_partition]) == 'UNKNOWN'


def test_retention_representation_requires_exactly_one_positive_unit():
    for retention in ({'Mode': 'COMPLIANCE', 'Days': None},
            {'Mode': 'COMPLIANCE', 'Days': 30, 'Years': 1},
            {'Mode': 'COMPLIANCE', 'Days': 30, 'Years': None},
            {'Mode': 'COMPLIANCE', 'Days': 0},
            {'Mode': 'COMPLIANCE', 'Years': -1},
            {'Mode': 'COMPLIANCE', 'Days': True}):
        item = bucket()
        item['ObjectLock']['ObjectLockConfiguration']['Rule']['DefaultRetention'] = retention
        assert verdict(bucket_rows=[item]) == 'UNKNOWN'
    item = bucket(); item['Versioning']['Status'] = None
    assert verdict(bucket_rows=[item]) == 'UNKNOWN'
    item = bucket(); item['ObjectLock']['ObjectLockConfiguration']['Rule'] = None
    assert verdict(bucket_rows=[item]) == 'UNKNOWN'
    item = bucket(); item['ObjectLock']['ObjectLockConfiguration'].pop('Rule')
    assert verdict(bucket_rows=[item]) == 'FAIL'
    item = bucket(); item['ObjectLock']['ObjectLockConfiguration']['Rule']['DefaultRetention'].setdefault('_coverage', {})['Days'] = {'status': 'denied'}
    assert verdict(bucket_rows=[item]) == 'UNKNOWN'
    item = bucket(); item['ObjectLock']['ObjectLockConfiguration']['Rule']['DefaultRetention'] = {'Mode': 'GOVERNANCE', 'Years': 1}
    assert verdict(bucket_rows=[item]) == 'PASS'
    item = bucket(); item['Versioning'].pop('Status')
    assert verdict(bucket_rows=[item]) == 'FAIL'


def test_sdk_collector_account_inventory_to_engine(monkeypatch):
    boto3 = pytest.importorskip('boto3')
    from botocore.stub import Stubber
    from peaso.collectors import aws, bulk_evidence
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name='us-east-1')
    clients = {service: session.client(service, region_name='us-east-1') for service in ('sts', 'ec2', 'cloudtrail', 's3')}
    stubs = {service: Stubber(client) for service, client in clients.items()}
    monkeypatch.setattr(aws, '_session', lambda *args: (session, 'inert'))
    monkeypatch.setattr(aws.Requests, 'client', lambda self, context, service, region: clients[service])
    stubs['sts'].add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/inert', 'UserId': 'INERT'}, {})
    stubs['ec2'].add_response('describe_regions', {'Regions': [
        {'RegionName': 'us-east-1', 'OptInStatus': 'opt-in-not-required'}]}, {'AllRegions': True})
    stubs['s3'].add_response('list_buckets', {'Buckets': [{'Name': BUCKET}]}, {})
    stubs['s3'].add_response('get_bucket_location', {}, {'Bucket': BUCKET})
    for operation in ('get_public_access_block', 'get_bucket_policy_status', 'get_bucket_policy',
        'get_bucket_encryption'):
        params = {'Bucket': BUCKET, **({'ExpectedBucketOwner': ACCOUNT} if operation == 'get_bucket_policy' else {})}
        stubs['s3'].add_client_error(operation, service_error_code='AccessDenied', expected_params=params)
    stubs['s3'].add_response('get_bucket_versioning', {'Status': 'Enabled'}, {'Bucket': BUCKET})
    for operation in ('get_bucket_acl', 'get_bucket_ownership_controls', 'get_bucket_logging',
        'get_bucket_lifecycle_configuration', 'get_bucket_notification_configuration',
        'get_bucket_replication'):
        stubs['s3'].add_client_error(operation, service_error_code='AccessDenied', expected_params={'Bucket': BUCKET})
    stubs['s3'].add_response('get_object_lock_configuration', {'ObjectLockConfiguration': {
        'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 30}}}}, {'Bucket': BUCKET})
    stubs['s3'].add_client_error('get_bucket_tagging', service_error_code='AccessDenied', expected_params={'Bucket': BUCKET})
    native_trail = {'Name': 'audit', 'S3BucketName': BUCKET, 'TrailARN': ARN,
        'HomeRegion': 'us-east-1', 'IsMultiRegionTrail': True, 'IsOrganizationTrail': False}
    stubs['cloudtrail'].add_response('describe_trails', {'trailList': [native_trail]}, {'includeShadowTrails': True})
    stubs['cloudtrail'].add_response('get_trail_status', {'IsLogging': True}, {'Name': ARN})
    stubs['cloudtrail'].add_response('get_event_selectors', {'EventSelectors': []}, {'TrailName': ARN})
    stubs['cloudtrail'].add_client_error('get_insight_selectors', service_error_code='InsightNotEnabledException', expected_params={'TrailName': ARN})
    with stubs['sts'], stubs['ec2'], stubs['s3'], stubs['cloudtrail']:
        snap = bulk_evidence.collect(aws, {'provider': 'aws', 'scopes': [ACCOUNT],
            'options': {'service_concurrency': 1, 'scope_concurrency': 1, 'region_concurrency': 1}},
            ['s3_bucket', 'cloudtrail_account_inventory'])
        source = next(c for c in snap['collections'] if c['type'] == 'cloudtrail_account_inventory')
        assert source['scope'] == SCOPE and source['status'] == 'collected'
        assert source['items'][0]['_account_trail_binding']['caller_account_id'] == ACCOUNT
        row = next(f for f in evaluate_snapshot(snap, checks=[CID])['findings'] if f['check_id'] == CID)
        assert row['status'] == 'PASS'
        for stub in stubs.values(): stub.assert_no_pending_responses()


def test_two_buckets_keep_independent_destination_results():
    first = bucket()
    other = deepcopy(first)
    other["Name"] = "unrelated-example"
    snapshot = make_snapshot("aws", [SCOPE], [
        envelope("s3_bucket", [first, other]),
        envelope("cloudtrail_account_inventory", [trail()])],
        created_at="2026-10-18T00:00:00+00:00", metadata=_metadata())
    rows = [r for r in evaluate_snapshot(snapshot, checks=[CID])["findings"] if r["check_id"] == CID]
    assert sorted(r["status"] for r in rows) == ["NOT_APPLICABLE", "PASS"]
