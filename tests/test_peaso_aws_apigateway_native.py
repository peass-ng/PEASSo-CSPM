"""Deployed API Gateway methods and effective WAF associations from SDK shapes."""
import copy
import json

import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT
from peaso.collectors import aws, aws_apigateway_native as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGION = 'eu-west-1'
SCOPE = ACCOUNT + '/' + REGION
API = 'abc123'
DEPLOYMENT = 'deploy1'
STAGE = f'arn:aws:apigateway:{REGION}::/restapis/{API}/stages/prod'
UUID = '12345678-1234-1234-1234-123456789012'
ACL = f'arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/security/{UUID}'
CACHE_CHECK = 'aws_nist_apigateway_stage_cache_encryption_at_rest_enabled'
WAF_CHECK = 'aws_g6_api_stage_effective_waf_acl'


def stage():
    return {'stageName': 'prod', 'deploymentId': DEPLOYMENT,
            'methodSettings': {'*/*': {'cachingEnabled': True, 'cacheDataEncrypted': True}},
            'webAclArn': ACL}


def parent(stub, row, *, error=None, next_token=None):
    stub.add_response('get_rest_apis', {'items': [{'id': API, 'name': 'api'}]}, {})
    if error:
        stub.add_client_error('get_stages', error, expected_params={'restApiId': API})
    else:
        stub.add_response('get_stages', {'item': [row]}, {'restApiId': API})


def decision(read, row, check_id=CACHE_CHECK, kind='rest_api_method'):
    row = {**copy.deepcopy(row), 'id': STAGE, 'ParentApiId': API,
           '_provenance': {'source_operation': 'get_stages', 'parent_api_id': API, 'read_only': True}}
    snapshot = make_snapshot('aws', [SCOPE], [
        {'type': 'rest_api_stage', 'scope': SCOPE, 'status': 'collected', 'items': [row]},
        {'type': kind, 'scope': SCOPE, 'status': read.status, 'items': read.items},
        {'type': 'wafv2_web_acl', 'scope': SCOPE, 'status': 'collected', 'items': [{'ARN': ACL}]}])
    findings = evaluate_snapshot(snapshot, checks=[check_id])['findings']
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('mode', ['complete', 'root', 'any', 'empty', 'missing', 'wrong_id', 'denied', 'parent_denied', 'canary', 'invalid_deployment'])
def test_deployed_methods_are_bound_to_stage_deployment(sdk, mode):
    session, add = sdk
    stub = add('apigateway')
    row = stage()
    if mode == 'canary':
        row['canarySettings'] = {'percentTraffic': 10, 'deploymentId': 'canary1'}
    if mode == 'invalid_deployment':
        row['deploymentId'] = '../escape'
    parent(stub, row, error='AccessDeniedException' if mode == 'parent_denied' else None)
    if mode not in ('parent_denied', 'canary', 'invalid_deployment'):
        args = {'restApiId': API, 'deploymentId': DEPLOYMENT, 'embed': ['apisummary']}
        if mode == 'denied':
            stub.add_client_error('get_deployment', 'AccessDeniedException', expected_params=args)
        else:
            summary = {'/' if mode == 'root' else '/pets': {'ANY' if mode == 'any' else 'GET': {'authorizationType': 'NONE', 'apiKeyRequired': False}}}
            response = {'id': 'foreign' if mode == 'wrong_id' else DEPLOYMENT,
                        'description': 'never-export-private-text', 'apiSummary': {} if mode == 'empty' else summary}
            if mode == 'missing':
                response.pop('apiSummary')
            stub.add_response('get_deployment', response, args)
    read = native.deployed_methods(aws.Requests({'retries': 0}), session, REGION, ACCOUNT)
    if mode in ('complete', 'root', 'any'):
        assert read.status == 'collected' and len(read.items) == 1
        assert read.items[0]['deploymentId'] == DEPLOYMENT
        assert read.items[0]['authorizationType'] == 'NONE'
        assert read.items[0]['apiKeyRequired'] is False
        assert read.items[0]['_provenance']['stage_deployment_join_verified'] is True
        assert 'never-export-private-text' not in json.dumps(read.items)
        assert decision(read, row) == 'PASS'
    else:
        assert read.status not in ('collected', 'empty')
        assert decision(read, row) == 'UNKNOWN'
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('settings,expected', [
    ({'*/*': {'cachingEnabled': True, 'cacheDataEncrypted': True}}, 'PASS'),
    ({'/*/*': {'cachingEnabled': True, 'cacheDataEncrypted': True}}, 'PASS'),
    ({'~1pets/GET': {'cachingEnabled': True, 'cacheDataEncrypted': True}}, 'PASS'),
    ({'/pets/GET': {'cachingEnabled': True, 'cacheDataEncrypted': False}}, 'FAIL'),
    ({'*/*': {'cachingEnabled': False}}, 'PASS'),
    ({'*/*': {'cachingEnabled': True, 'cacheDataEncrypted': True},
      '~1pets/GET': {'cacheDataEncrypted': False}}, 'FAIL'),
    ({'*/*': {'cachingEnabled': True, 'cacheDataEncrypted': True},
      '/pets/*': {'cacheDataEncrypted': False}}, 'UNKNOWN'),
    ({'~1pets/GET': {'cachingEnabled': False}, '/pets/GET': {'cachingEnabled': False}}, 'UNKNOWN'),
    ({}, 'UNKNOWN'),
])
def test_native_cache_setting_spellings_and_overrides(sdk, settings, expected):
    session, add = sdk
    stub = add('apigateway')
    row = stage()
    row['methodSettings'] = settings
    parent(stub, row)
    stub.add_response('get_deployment', {'id': DEPLOYMENT, 'apiSummary': {'/pets': {'GET': {}}}},
                      {'restApiId': API, 'deploymentId': DEPLOYMENT, 'embed': ['apisummary']})
    read = native.deployed_methods(aws.Requests({}), session, REGION, ACCOUNT)
    assert decision(read, row) == expected
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['complete', 'absent', 'denied', 'missing_resource', 'foreign', 'wrong_region', 'wrong_partition', 'wrong_uuid'])
def test_effective_waf_association_is_resource_account_and_region_bound(sdk, mode):
    session, add = sdk
    api = add('apigateway')
    waf = add('wafv2')
    row = stage()
    if mode == 'absent':
        row.pop('webAclArn')
    parent(api, row)
    args = {'ResourceArn': STAGE}
    if mode in ('denied', 'missing_resource'):
        waf.add_client_error('get_web_acl_for_resource', 'AccessDeniedException' if mode == 'denied' else 'WAFNonexistentItemException', expected_params=args)
    else:
        arn = ACL.replace(ACCOUNT, '999999999999') if mode == 'foreign' else ACL
        if mode == 'wrong_region': arn = arn.replace(REGION, 'eu-west-2')
        if mode == 'wrong_partition': arn = arn.replace('arn:aws:', 'arn:aws-cn:')
        acl = {'Name': 'security', 'Id': 'ffffffff-ffff-ffff-ffff-ffffffffffff' if mode == 'wrong_uuid' else UUID,
               'ARN': arn, 'DefaultAction': {'Block': {}}, 'Rules': [],
               'VisibilityConfig': {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True, 'MetricName': 'qa'}}
        waf.add_response('get_web_acl_for_resource', {} if mode == 'absent' else {'WebACL': acl}, args)
    read = native.stage_waf(aws.Requests({'retries': 0}), session, REGION, ACCOUNT)
    assert decision(read, row, WAF_CHECK, 'stage_waf_association') == (
        'PASS' if mode == 'complete' else 'FAIL' if mode == 'absent' else 'UNKNOWN')
    api.assert_no_pending_responses()
    waf.assert_no_pending_responses()


def test_any_method_cannot_hide_verb_specific_cache_override(sdk):
    session, add = sdk
    stub = add('apigateway')
    row = stage()
    row['methodSettings']['~1pets/GET'] = {'cacheDataEncrypted': False}
    parent(stub, row)
    stub.add_response('get_deployment', {'id': DEPLOYMENT, 'apiSummary': {'/pets': {'ANY': {}}}},
                      {'restApiId': API, 'deploymentId': DEPLOYMENT, 'embed': ['apisummary']})
    read = native.deployed_methods(aws.Requests({}), session, REGION, ACCOUNT)
    assert decision(read, row) == 'UNKNOWN'
    stub.assert_no_pending_responses()


def test_shared_stage_pages_are_fetched_once_across_both_inventories(sdk):
    session, add = sdk
    api = add('apigateway')
    waf = add('wafv2')
    row = stage()
    parent(api, row)
    api.add_response('get_deployment', {'id': DEPLOYMENT, 'apiSummary': {'/pets': {'GET': {}}}},
                     {'restApiId': API, 'deploymentId': DEPLOYMENT, 'embed': ['apisummary']})
    waf.add_response('get_web_acl_for_resource', {}, {'ResourceArn': STAGE})
    requests = aws.Requests({})
    assert native.deployed_methods(requests, session, REGION, ACCOUNT).status == 'collected'
    assert native.stage_waf(requests, session, REGION, ACCOUNT).status == 'collected'
    assert requests.calls == 4 and requests.cache_hits >= 2
    api.assert_no_pending_responses()
    waf.assert_no_pending_responses()


def test_stage_summary_reused_by_full_native_collector(sdk, monkeypatch):
    from peaso.collectors.bulk_evidence import collect
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'test-pinned'))
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    api = add('apigateway')
    row = stage()
    parent(api, row)
    api.add_response('get_deployment', {'id': DEPLOYMENT, 'apiSummary': {'/pets': {'GET': {}}}},
                     {'restApiId': API, 'deploymentId': DEPLOYMENT, 'embed': ['apisummary']})
    snapshot = collect(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': {'service_concurrency': 1}},
                       ['rest_api_stage', 'rest_api_method'])
    assert evaluate_snapshot(snapshot, checks=[CACHE_CHECK])['findings'][0]['status'] == 'PASS'
    assert snapshot['metadata']['calls'] == 4
    api.assert_no_pending_responses()
    sts.assert_no_pending_responses()


@pytest.mark.parametrize('enabled,status,expected', [
    (False, 'NOT_AVAILABLE', 'NOT_APPLICABLE'),
    (False, 'DELETE_IN_PROGRESS', 'UNKNOWN'),
    (True, 'CREATE_IN_PROGRESS', 'UNKNOWN'),
    (True, 'FLUSH_IN_PROGRESS', 'UNKNOWN'),
    (True, 'NOT_AVAILABLE', 'UNKNOWN'),
    (True, 'AVAILABLE', 'PASS'),
])
def test_native_absent_and_transitioning_cache_clusters(sdk, enabled, status, expected):
    session, add = sdk
    api = add('apigateway')
    row = stage()
    row.update(cacheClusterEnabled=enabled, cacheClusterStatus=status)
    if not enabled:
        row['methodSettings'] = {}
    parent(api, row)
    api.add_response('get_deployment', {'id': DEPLOYMENT, 'apiSummary': {'/pets': {'GET': {}}}},
                     {'restApiId': API, 'deploymentId': DEPLOYMENT, 'embed': ['apisummary']})
    read = native.deployed_methods(aws.Requests({}), session, REGION, ACCOUNT)
    assert decision(read, row) == expected
    api.assert_no_pending_responses()
