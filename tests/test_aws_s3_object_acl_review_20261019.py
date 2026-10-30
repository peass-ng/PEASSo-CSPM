"""Real request/cache and offline-boundary tests for S3 object ACL sampling."""
import copy
import importlib
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks import aws_s3_object_acl_review_20261019 as check
from peaso.collectors import aws_s3_object_acl_review_20261019 as collector

ACCOUNT = '123456789012'
NAME = 'sample-review-bucket'


def case(public=False):
    fixture = check.RUNTIME_CASES[check.CHECK_ID]
    return copy.deepcopy((fixture['fail'], fixture['fail_index']) if public else (fixture['pass'], fixture['pass_index']))


def public_acl(permission='READ', uri=None):
    return {'Grants': [{'Permission': permission, 'Grantee': {
        'Type': 'Group', 'URI': uri or 'http://acs.amazonaws.com/groups/global/AllUsers'}}]}


PRIVATE = {'Grants': [{'Permission': 'FULL_CONTROL', 'Grantee': {'Type': 'CanonicalUser', 'ID': 'a' * 64}}]}


@pytest.fixture
def reader(monkeypatch):
    boto3 = pytest.importorskip('boto3')
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name='us-east-1')
    clients, stubs, routes = {}, {}, []

    def add(region='us-east-1'):
        if region not in clients:
            clients[region] = session.client('s3', region_name=region)
            stubs[region] = Stubber(clients[region])
            stubs[region].activate()
        return stubs[region]

    def client(self, _session, service, region):
        assert service == 's3'
        routes.append(region)
        return clients[region]

    monkeypatch.setattr(aws, 'READ_ACTIONS', aws.READ_ACTIONS | collector.READ_ACTIONS)
    monkeypatch.setattr(aws.Requests, 'client', client)
    requests = aws.Requests({'retry_attempts': 1})
    yield requests, session, add, routes
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def list_response(keys, *, more=False, token=None):
    return {'Name': NAME, 'IsTruncated': more, 'KeyCount': len(keys),
            **({'Contents': [{'Key': key} for key in keys]} if keys else {}),
            **({'NextContinuationToken': token} if token is not None else {})}


def sample(reader, keys, *, public=False, limit=20):
    requests, session, add, routes = reader
    stub = add()
    stub.add_response('list_objects_v2', list_response(keys), {'Bucket': NAME, 'MaxKeys': limit})
    for key in keys:
        stub.add_response('get_object_acl', public_acl() if public else PRIVATE, {'Bucket': NAME, 'Key': key})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item, limit=limit)
    return item, index


@pytest.mark.parametrize('permission', sorted(check.PERMISSIONS))
@pytest.mark.parametrize('uri', sorted(check.PUBLIC))
def test_every_public_group_and_permission_returns_exact_key_and_grant(permission, uri):
    item, index = case(True)
    grant = item['ObjectAclSample']['objects'][0]['Grants'][0]
    grant.update(Permission=permission, Grantee={'Type': 'Group', 'URI': uri})
    status, evidence = check.evaluate(item, index)
    assert status == 'FAIL'
    assert evidence['public_grants'] == [{'Key': 'example.txt', **grant}]
    assert len(evidence['observed']) <= 150
    assert evidence['unseen_objects_assessed'] is False


def test_actual_read_cache_and_input_immutability(reader):
    item, index = sample(reader, ['alpha.txt'], public=True)
    requests, session, add, routes = reader
    assert check.evaluate(item, index)[0] == 'FAIL'
    before = copy.deepcopy(item)
    first = collector.enrich(requests, session, 'eu-west-1', [item])
    second = collector.enrich(requests, session, 'ap-southeast-2', [item])
    assert first == second and item == before
    assert requests.calls == 2 and requests.cache_hits >= 4
    assert set(routes) == {'us-east-1'}
    assert all(operation in ('list_objects_v2', 'get_object_acl') for _sid, _service, _region, operation, *_rest in requests._cache)
    assert 'aaaaaaaa' not in json.dumps(item['ObjectAclSample'])


def test_actual_pagination_decrements_remaining_cap(reader):
    requests, session, add, routes = reader
    stub = add()
    stub.add_response('list_objects_v2', list_response(['one'], more=True, token='next'), {'Bucket': NAME, 'MaxKeys': 2})
    stub.add_response('get_object_acl', PRIVATE, {'Bucket': NAME, 'Key': 'one'})
    stub.add_response('list_objects_v2', list_response(['two']), {'Bucket': NAME, 'MaxKeys': 1, 'ContinuationToken': 'next'})
    stub.add_response('get_object_acl', PRIVATE, {'Bucket': NAME, 'Key': 'two'})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item, limit=2)
    assert check.evaluate(item, index)[0] == 'PASS'
    assert item['ObjectAclSample']['sampled_count'] == 2
    assert item['ObjectAclSample']['listing_complete'] is True
    assert requests.calls == 4


def test_default_cap_reads_twenty_acls_and_never_calls_next_page(reader):
    requests, session, add, routes = reader
    stub = add()
    keys = [f'object-{i}' for i in range(20)]
    stub.add_response('list_objects_v2', list_response(keys, more=True, token='unread'), {'Bucket': NAME, 'MaxKeys': 20})
    for key in keys:
        stub.add_response('get_object_acl', PRIVATE, {'Bucket': NAME, 'Key': key})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert requests.calls == 21
    assert item['ObjectAclSample']['sampled_count'] == 20
    status, evidence = check.evaluate(item, index)
    assert status == 'UNKNOWN' and evidence['listing_complete'] is False
    assert len(evidence['observed']) <= 150


@pytest.mark.parametrize('location,region', [('EU', 'eu-west-1'), ('ap-southeast-2', 'ap-southeast-2'), (None, 'us-east-1')])
def test_region_routing_uses_verified_location(reader, location, region):
    requests, session, add, routes = reader
    add(region).add_response('list_objects_v2', list_response([]), {'Bucket': NAME, 'MaxKeys': 20})
    item, index = case()
    item['Location']['LocationConstraint'] = location
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert set(routes) == {region}
    assert check.evaluate(item, index)[0] == 'EMPTY'


def test_denied_location_does_not_guess_a_region_or_make_calls(reader):
    requests, session, add, routes = reader
    item, index = case()
    item['Location'] = {'collection_status': 'denied'}
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert requests.calls == 0
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_initial_listing_denied_is_not_empty(reader):
    requests, session, add, routes = reader
    add().add_client_error('list_objects_v2', 'AccessDenied', expected_params={'Bucket': NAME, 'MaxKeys': 20})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert item['ObjectAclSample']['collection_status'] == 'denied'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('public', [False, True])
def test_partial_acl_denial_retains_public_positive_but_never_private_pass(reader, public):
    requests, session, add, routes = reader
    stub = add()
    stub.add_response('list_objects_v2', list_response(['one', 'two']), {'Bucket': NAME, 'MaxKeys': 20})
    stub.add_response('get_object_acl', public_acl() if public else PRIVATE, {'Bucket': NAME, 'Key': 'one'})
    stub.add_client_error('get_object_acl', 'AccessDenied', expected_params={'Bucket': NAME, 'Key': 'two'})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert item['ObjectAclSample']['collection_status'] == 'partial'
    status, evidence = check.evaluate(item, index)
    assert status == ('FAIL' if public else 'UNKNOWN')
    if public:
        assert evidence['public_grants'][0]['Key'] == 'one'


def test_listing_denied_on_second_page_still_reports_known_public_object(reader):
    requests, session, add, routes = reader
    stub = add()
    stub.add_response('list_objects_v2', list_response(['one'], more=True, token='next'), {'Bucket': NAME, 'MaxKeys': 20})
    stub.add_response('get_object_acl', public_acl(), {'Bucket': NAME, 'Key': 'one'})
    stub.add_client_error('list_objects_v2', 'AccessDenied', expected_params={'Bucket': NAME, 'MaxKeys': 19, 'ContinuationToken': 'next'})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert item['ObjectAclSample']['collection_status'] == 'partial'
    assert check.evaluate(item, index)[0] == 'FAIL'


@pytest.mark.parametrize('override', ['ownership', 'bucket', 'account'])
def test_proven_ownership_or_ignore_public_acls_suppresses_exposure(override):
    item, index = case(True)
    if override == 'ownership':
        item['OwnershipControls']['OwnershipControls']['Rules'][0]['ObjectOwnership'] = 'BucketOwnerEnforced'
    elif override == 'bucket':
        item['PublicAccessBlock']['PublicAccessBlockConfiguration']['IgnorePublicAcls'] = True
    else:
        index['collections']['s3_account_public_access_block'][0]['items'][0]['PublicAccessBlockConfiguration']['IgnorePublicAcls'] = True
    assert check.evaluate(item, index)[0] == 'NOT_APPLICABLE'


def test_block_public_acls_does_not_ignore_existing_acl():
    item, index = case(True)
    item['PublicAccessBlock']['PublicAccessBlockConfiguration']['BlockPublicAcls'] = True
    assert check.evaluate(item, index)[0] == 'FAIL'


def test_unreadable_account_override_retains_grants_as_unknown():
    item, index = case(True)
    index['collections']['s3_account_public_access_block'][0]['status'] = 'denied'
    status, evidence = check.evaluate(item, index)
    assert status == 'UNKNOWN' and evidence['public_grants']


@pytest.mark.parametrize('change', ['missing', 'mismatch', 'count', 'duplicate', 'denied_grant', 'contradictory_coverage'])
def test_missing_malformed_or_foreign_sample_never_passes(change):
    item, index = case(True)
    sample = item['ObjectAclSample']
    if change == 'missing':
        item.pop('ObjectAclSample')
    elif change == 'mismatch':
        sample['bucket'] = 'other-bucket'
    elif change == 'count':
        sample['sampled_count'] = 2
    elif change == 'duplicate':
        sample['objects'] *= 2
        sample['sampled_count'] = 2
    elif change == 'denied_grant':
        sample['objects'][0]['Grants'][0]['collection_status'] = 'denied'
    else:
        sample['_coverage'] = {'bucket': {'status': 'empty'}}
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_malformed_sdk_acl_with_valid_public_grant_keeps_positive_evidence(reader, monkeypatch):
    requests, session, add, routes = reader
    add()
    client = requests.client(session, 's3', 'us-east-1')
    monkeypatch.setattr(client, 'list_objects_v2', lambda **_: list_response(['one']))
    raw = public_acl()
    raw['Grants'].append({'unexpected': True})
    monkeypatch.setattr(client, 'get_object_acl', lambda **_: raw)
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert item['ObjectAclSample']['objects'][0]['collection_status'] == 'partial'
    assert check.evaluate(item, index)[0] == 'FAIL'


def test_unhandled_continuation_is_malformed_not_private(reader):
    requests, session, add, routes = reader
    add().add_response('list_objects_v2', {'Name': NAME, 'IsTruncated': True}, {'Bucket': NAME, 'MaxKeys': 20})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert item['ObjectAclSample']['collection_status'] == 'malformed'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_exports_are_unregistered_and_global_bucket_compatible():
    from peaso.collectors import aws
    before = {c.id for c in CHECKS}
    importlib.reload(check)
    assert {c.id for c in CHECKS} == before
    assert 'bucket' in aws.GLOBAL_TYPES
    assert collector.ENRICHERS == {'bucket': collector.enrich}
    declaration = check.DECLARATIONS[0]
    assert declaration['kind'] == 'bucket' and declaration['target'] == 'resource'
    assert declaration['allow_incomplete_failure'] is True
    fixture = check.RUNTIME_CASES[check.CHECK_ID]
    assert check.evaluate(fixture['pass'], fixture['pass_index'])[0] == 'PASS'
    assert check.evaluate(fixture['fail'], fixture['fail_index'])[0] == 'FAIL'
    assert check.evaluate(fixture['missing'], fixture['pass_index'])[0] == 'UNKNOWN'
    assert check.evaluate(fixture['malformed'], fixture['pass_index'])[0] == 'UNKNOWN'
    admission = check.ADMISSION_DATA['checks'][0]
    assert admission['requirements'] == []


def test_real_engine_evaluates_global_bucket_once_across_two_regions(monkeypatch):
    from peaso import engine
    from peaso.checks import Check
    from peaso.snapshot import make_snapshot
    item, index = case(True)
    declaration = check.DECLARATIONS[0]
    native = Check(check.CHECK_ID, 'aws', 'exposure', 'bucket', declaration['title'], 'medium', 'AC-3',
                   declaration['remediation'], check.evaluate, 'resource', tuple(declaration['dependencies']), True)
    monkeypatch.setattr(engine, '_registry', lambda: [native])
    snapshot = make_snapshot('aws', [ACCOUNT + '/us-east-1', ACCOUNT + '/eu-west-1'],
                             sum(index['collections'].values(), []), created_at='2026-10-19T00:00:00Z')
    findings = [finding for finding in engine.evaluate_snapshot(snapshot, categories=['exposure'],
                checks=[check.CHECK_ID])['findings'] if finding['check_id'] == check.CHECK_ID]
    assert len(findings) == 1
    assert findings[0]['scope'] == ACCOUNT + '/global'
    assert findings[0]['status'] == 'FAIL'


def test_denied_account_identity_marker_cannot_establish_non_suppression():
    item, index = case(True)
    row = index['collections']['s3_account_public_access_block'][0]['items'][0]
    row['_coverage'] = {'AccountId': {'status': 'denied'}}
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_repeated_pagination_token_stops_and_keeps_private_sample_unknown(reader):
    requests, session, add, routes = reader
    stub = add()
    stub.add_response('list_objects_v2', list_response(['one'], more=True, token='repeat'), {'Bucket': NAME, 'MaxKeys': 20})
    stub.add_response('get_object_acl', PRIVATE, {'Bucket': NAME, 'Key': 'one'})
    stub.add_response('list_objects_v2', list_response([], more=True, token='repeat'),
                      {'Bucket': NAME, 'MaxKeys': 19, 'ContinuationToken': 'repeat'})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert item['ObjectAclSample']['collection_status'] == 'partial'
    assert requests.calls == 3
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_scan_page_budget_is_preserved(reader):
    requests, session, add, routes = reader
    requests.max_pages = 1
    stub = add()
    stub.add_response('list_objects_v2', list_response(['one'], more=True, token='next'), {'Bucket': NAME, 'MaxKeys': 20})
    stub.add_response('get_object_acl', PRIVATE, {'Bucket': NAME, 'Key': 'one'})
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item)
    assert requests.calls == 2
    assert item['ObjectAclSample']['errors'][-1]['code'] == 'listing_page_limit'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('limit', [0, 21, True, '20'])
def test_invalid_cap_never_makes_cloud_calls(reader, limit):
    requests, session, add, routes = reader
    item, index = case()
    item['ObjectAclSample'] = collector.sample_bucket(requests, session, item, limit=limit)
    assert requests.calls == 0
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_grant_permission_unknown_is_not_assumed_public_or_private():
    item, index = case(True)
    item['ObjectAclSample']['objects'][0]['Grants'][0]['Permission'] = 'FUTURE_PERMISSION'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('code,expected', [('NoSuchPublicAccessBlockConfiguration', 'FAIL'),
                                         ('AccessDenied', 'UNKNOWN'), (None, 'UNKNOWN')])
def test_account_block_absence_requires_exact_native_not_found(code, expected):
    item, index = case(True)
    envelope = index['collections']['s3_account_public_access_block'][0]
    envelope.update(status='empty', items=[])
    if code:
        envelope['error'] = {'code': code}
    assert check.evaluate(item, index)[0] == expected


def test_all_runtime_observed_sentences_are_at_most_150_characters():
    for public in (True, False):
        item, index = case(public)
        assert len(check.evaluate(item, index)[1]['observed']) <= 150
