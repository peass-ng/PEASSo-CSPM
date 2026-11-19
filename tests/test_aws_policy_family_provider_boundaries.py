"""Provider-managed identities and optional empty responses preserve policy coverage."""
import json
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber
from botocore.exceptions import EndpointConnectionError

from peaso.collectors import aws, aws_resource_policy_families as families
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = '123456789012'
REGION = 'us-east-1'
PUBLIC = {'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': '*', 'Resource': '*'}]}


@pytest.fixture
def sdk():
    real = boto3.Session(aws_access_key_id='fixture', aws_secret_access_key='fixture', region_name=REGION)
    clients, stubs = {}, {}
    class Session:
        def get_partition_for_region(self, region):
            return 'aws'
        def client(self, service, region_name=None, **kwargs):
            return clients[service]
    def add(service):
        clients[service] = real.client(service)
        stubs[service] = Stubber(clients[service])
        stubs[service].activate()
        return stubs[service]
    yield Session(), add
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def collect(session, *ids):
    selected = [r for r in families.RECIPES if r.id in ids]
    return families.collect(aws.Requests({'retry_attempts': 1}), session, REGION, ACCOUNT, selected)


def test_schemas_requests_customer_registries_and_reads_public_policy(sdk):
    session, add = sdk
    stub = add('schemas')
    arn = f'arn:aws:schemas:{REGION}:{ACCOUNT}:registry/customer'
    stub.add_response('list_registries', {'Registries': [{'RegistryName': 'customer', 'RegistryArn': arn}]}, {'Scope': 'LOCAL'})
    stub.add_response('get_resource_policy', {'Policy': json.dumps(PUBLIC)}, {'RegistryName': 'customer'})
    read = collect(session, 'eventbridge-schemas')
    assert read.status == 'collected' and read.items[0]['ResourceArn'] == arn
    assert read.items[0]['Policy']['Statement'] == PUBLIC['Statement']


@pytest.mark.parametrize('kind', ['cloudtrail', 'resolver'])
def test_managed_resources_are_skipped_but_customer_policy_is_still_read(sdk, kind):
    session, add = sdk
    if kind == 'cloudtrail':
        stub = add('cloudtrail')
        arn = f'arn:aws:cloudtrail:{REGION}:{ACCOUNT}:channel/customer'
        managed = {'ChannelArn': f'arn:aws:cloudtrail:{REGION}:{ACCOUNT}:channel/aws-service-channel/guardduty/default', 'Name': 'aws-service-channel/guardduty/default'}
        stub.add_response('list_channels', {'Channels': [managed, {'ChannelArn': arn, 'Name': 'aws-service-channel/customer-name-only'}]}, {})
        stub.add_response('get_resource_policy', {'ResourcePolicy': json.dumps(PUBLIC)}, {'ResourceArn': arn})
        id = 'cloudtrail-channels'
    else:
        stub = add('route53resolver')
        arn = f'arn:aws:route53resolver:{REGION}:{ACCOUNT}:resolver-rule/rslvr-rr-customer'
        managed = {'Arn': f'arn:aws:route53resolver:{REGION}::autodefined-rule/rslvr-autodefined-rr-internet-resolver', 'OwnerId': 'Route 53 Resolver'}
        stub.add_response('list_resolver_rules', {'ResolverRules': [managed, {'Arn': arn, 'OwnerId': ACCOUNT}]}, {})
        stub.add_response('get_resolver_rule_policy', {'ResolverRulePolicy': json.dumps(PUBLIC)}, {'Arn': arn})
        id = 'resolver-rules'
    read = collect(session, id)
    assert read.status == 'collected' and [r['ResourceArn'] for r in read.items] == [arn]
    assert read.items[0]['Policy']['Statement'] == PUBLIC['Statement']


@pytest.mark.parametrize('family', ['s3-outposts-buckets', 's3-outposts-access-points'])
@pytest.mark.parametrize('mode', ['empty', 'denied', 'foreign', 'public'])
def test_outposts_discovery_routes_bucket_reads_or_retains_gap(sdk, mode, family):
    session, add = sdk
    outposts = add('outposts')
    outpost_id = 'op-0123456789abcdef0'
    owner = '999999999999' if mode == 'foreign' else ACCOUNT
    row = {'OutpostId': outpost_id, 'OwnerId': owner, 'OutpostArn': f'arn:aws:outposts:{REGION}:{owner}:outpost/{outpost_id}'}
    if mode == 'denied':
        outposts.add_client_error('list_outposts', 'AccessDeniedException', expected_params={})
    else:
        outposts.add_response('list_outposts', {'Outposts': [] if mode == 'empty' else [row]}, {})
    if mode == 'public':
        stub = add('s3control')
        arn = f'arn:aws:s3-outposts:{REGION}:{ACCOUNT}:outpost/{outpost_id}/bucket/customer'
        stub.add_response('list_regional_buckets', {'RegionalBucketList': [{'BucketArn': arn, 'Bucket': 'customer', 'PublicAccessBlockEnabled': True, 'CreationDate': datetime(2026, 1, 1, tzinfo=timezone.utc)}]}, {'AccountId': ACCOUNT, 'OutpostId': outpost_id})
        if family == 's3-outposts-buckets':
            stub.add_response('get_bucket_policy', {'Policy': json.dumps(PUBLIC)}, {'AccountId': ACCOUNT, 'Bucket': arn})
        else:
            point = f'arn:aws:s3-outposts:{REGION}:{ACCOUNT}:outpost/{outpost_id}/accesspoint/customer'
            stub.add_response('list_access_points', {'AccessPointList': [{'Name': 'customer', 'NetworkOrigin': 'VPC', 'Bucket': 'customer', 'AccessPointArn': point}]}, {'AccountId': ACCOUNT, 'Bucket': arn})
            stub.add_response('get_access_point_policy', {'Policy': json.dumps(PUBLIC)}, {'AccountId': ACCOUNT, 'Name': point})
    read = collect(session, family)
    assert read.status == {'empty': 'empty', 'denied': 'denied', 'foreign': 'unknown', 'public': 'collected'}[mode]
    if mode == 'denied':
        assert read.error['families'][0]['operation'] == 'list_outposts'
        assert read.error['families'][0]['service'] == 'outposts'
    if mode == 'public':
        assert read.items[0]['Policy']['Statement'] == PUBLIC['Statement']


@pytest.mark.parametrize('response,status', [({}, 'empty'), ({'sequenceStores': []}, 'empty'), ({'sequenceStores': None}, 'malformed'), ({'sequenceStores': {}}, 'malformed')])
def test_omics_absent_optional_list_is_empty_but_malformed_values_stay_unknown(sdk, response, status):
    session, add = sdk
    add('omics')
    # Invalid provider shapes cannot enter Stubber; inject at the transport boundary.
    requests = aws.Requests({'retry_attempts': 1})
    requests.call = lambda *args, **kwargs: response
    read = requests.pages(session, 'omics', REGION, 'list_sequence_stores', 'sequenceStores')
    assert read.status == status
    recipe = next(r for r in families.RECIPES if r.id == 'omics-store-access')
    family = families.collect(requests, session, REGION, ACCOUNT, [recipe])
    assert family.status == ('empty' if status == 'empty' else 'unknown')
    if status == 'malformed':
        assert family.error['families'][0]['operation'] == 'list_sequence_stores'


def test_endpoint_failure_does_not_retain_url_or_claim_absence():
    failure = aws._failure(EndpointConnectionError(endpoint_url='https://private.invalid/secret'))
    assert (failure.status, failure.code) == ('unknown', 'endpoint_unreachable')


def test_failed_policy_api_is_visible_in_frozen_report_without_provider_payload():
    scope = ACCOUNT + '/' + REGION
    error = {'code': 'resource_policy_coverage_incomplete', 'details': [{'families': [
        {'family': 'qbusiness-applications', 'status': 'unknown', 'code': 'endpoint_unreachable',
         'service': 'qbusiness', 'operation': 'list_applications', 'Message': 'PRIVATE-PAYLOAD'}]}]}
    snapshot = make_snapshot('aws', [scope], [{'type': 'aws_resource_policy', 'scope': scope,
        'service': 'aws', 'status': 'unknown', 'items': [], 'error': error}])
    report = evaluate_snapshot(snapshot, checks=['aws_cis_aws_resource_policy_unrestricted_principal'])
    evidence = report['findings'][0]['evidence']
    assert report['findings'][0]['status'] == 'UNKNOWN'
    assert evidence['failed_policy_reads'][0]['operation'] == 'list_applications'
    assert 'PRIVATE-PAYLOAD' not in json.dumps(report)
