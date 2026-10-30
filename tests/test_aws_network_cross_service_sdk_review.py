"""Exact-six offline native SDK -> real Requests -> public collect -> consumer review.

No native response is patched after collection. Receipts certify visited branches
and emitted paths only; external S3 origin existence stays unresolved.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

import boto3
from botocore.stub import Stubber
import pytest

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from scripts import audit_aws_native_contracts as native

ACCOUNT, REGION = '123456789012', 'us-east-1'
STAMP = datetime(2026, 10, 19, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
IDS = [
 'aws.c2b.bedrock.vpc_endpoints',
 'aws.c2b.cloudfront.s3_origin_bucket_exists',
 'aws.cb.shield.cloudfront_protected',
 'aws.claude_a.networkfirewall.in_use_vpc_has_firewall',
 'aws.review.rest_api_stage.configuration_secret_indicators',
 'aws_g6_api_stage_effective_waf_acl',
]
CHECKS = {c.id: c for c in native.registry() if c.id in IDS}
assert set(CHECKS) == set(IDS)
CFARN = f'arn:aws:cloudfront::{ACCOUNT}:distribution/E123'
FWARN = f'arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall/review'
ACLID = '11111111-2222-3333-4444-555555555555'
ACLARN = f'arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/review/{ACLID}'
STAGEARN = f'arn:aws:apigateway:{REGION}::/restapis/abc123/stages/prod'
TOKEN = 'Complex123!SyntheticOnly'  # Synthetic; never verified.


@pytest.fixture
def pipeline(monkeypatch):
    session = boto3.Session(aws_access_key_id='offline', aws_secret_access_key='offline', region_name=REGION)
    original_requests = aws.Requests

    def run(cid, scenario, responses, kinds=None, options=None):
        calls, clients, validation_errors, invocations = [], {}, [], []
        requests = original_requests({'retry_attempts': 1, 'max_workers': 1, 'max_calls': 300, **(options or {})}, sleep=lambda _: None)
        requests.observed_at = STAMP
        original_call = requests.call
        def traced_call(session, service, region, operation, **arguments):
            invocations.append({'service': service, 'region': region, 'operation': operation,
                'arguments': deepcopy(arguments)})
            return original_call(session, service, region, operation, **arguments)
        requests.call = traced_call
        responses = {('sts', 'get_caller_identity'): {'Account': ACCOUNT,
            'Arn': f'arn:aws:iam::{ACCOUNT}:user/review', 'UserId': 'AIDAREVIEW'}, **responses}

        class Client:
            def __init__(self, service, region):
                self.service, self.region = service, region
                self.sdk = session.client(service, region_name=region)
                self.meta = self.sdk.meta

            def can_paginate(self, operation):
                return self.sdk.can_paginate(operation)

            def get_paginator(self, operation):
                return self.sdk.get_paginator(operation)

            def __getattr__(self, operation):
                def invoke(**arguments):
                    assert operation.startswith(('get_', 'list_', 'describe_'))
                    response = responses.get((self.service, operation))
                    if callable(response):
                        response = response(arguments)
                    calls.append({'service': self.service, 'region': self.region,
                        'operation': operation, 'arguments': deepcopy(arguments),
                        'stub_result': 'denied' if response is None or isinstance(response, tuple) else 'response'})
                    with Stubber(self.sdk) as stub:
                        try:
                            if response is None or isinstance(response, tuple):
                                stub.add_client_error(operation, service_error_code=response[0] if isinstance(response, tuple) else 'AccessDeniedException',
                                    http_status_code=403, expected_params=arguments)
                            else:
                                stub.add_response(operation, deepcopy(response), arguments)
                        except Exception as exc:
                            validation_errors.append(str(exc))
                            raise
                        result = getattr(self.sdk, operation)(**arguments)
                        stub.assert_no_pending_responses()
                        return result
                return invoke

        def client(_session, service, region):
            if (service, region) not in clients:
                clients[service, region] = Client(service, region)
            return clients[service, region]

        requests.client = client
        monkeypatch.setattr(aws, 'Requests', lambda options: requests)
        monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'offline'))
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
            'options': {'regions': [REGION], 'service_concurrency': 1}},
            kinds or sorted({CHECKS[cid].kind, *CHECKS[cid].dependencies}))
        assert not validation_errors, validation_errors
        findings = [f for f in evaluate_snapshot(snapshot, checks=[cid])['findings'] if f['check_id'] == cid]
        assert findings and len({f['status'] for f in findings}) == 1, findings
        cached = [future.result() for future in requests._cache.values() if future.done() and not future.exception()]
        assert TOKEN not in json.dumps([snapshot, findings, cached], default=str)
        return findings[0]['status'], snapshot, calls
    return run


def network_base(in_use=True):
    return {('ec2', 'describe_vpcs'): {'Vpcs': [{'VpcId': 'vpc-1', 'State': 'available'}]},
        ('ec2', 'describe_network_interfaces'): {'NetworkInterfaces': [{'NetworkInterfaceId': 'eni-1', 'VpcId': 'vpc-1'}] if in_use else []}}


BR = ('bedrock', 'bedrock-runtime', 'bedrock-agent', 'bedrock-agent-runtime', 'bedrock-mantle')
@pytest.mark.parametrize('scenario,expected', [
 ('all_available','PASS'), ('missing_mantle','FAIL'), ('pending','FAIL'), ('foreign_vpc','FAIL'),
 ('no_interfaces','NOT_APPLICABLE'), ('inactive','NOT_APPLICABLE'), ('endpoints_denied','UNKNOWN'),
 ('interfaces_denied','UNKNOWN'), ('activity_denied','UNKNOWN'), ('endpoint_partial','UNKNOWN'),
])
def test_bedrock_vpc_endpoint_join(pipeline, scenario, expected):
    responses = network_base(scenario != 'no_interfaces')
    endpoints = [{'VpcEndpointId': 'vpce-' + str(n), 'VpcId': 'vpc-other' if scenario == 'foreign_vpc' else 'vpc-1',
        'State': 'pending' if scenario == 'pending' else 'available', 'ServiceName': f'com.amazonaws.{REGION}.{service}',
        'VpcEndpointType': 'Interface'} for n, service in enumerate(BR)]
    if scenario == 'missing_mantle': endpoints.pop()
    responses.update({('ec2', 'describe_vpc_endpoints'): {'VpcEndpoints': endpoints},
        ('bedrock', 'get_model_invocation_logging_configuration'): {'loggingConfig': {'textDataDeliveryEnabled': True}} if scenario != 'inactive' else {},
        ('bedrock', 'list_guardrails'): {'guardrails': []}, ('bedrock-agent', 'list_agents'): {'agentSummaries': []}})
    if scenario == 'endpoints_denied': responses['ec2', 'describe_vpc_endpoints'] = None
    if scenario == 'interfaces_denied': responses['ec2', 'describe_network_interfaces'] = None
    if scenario == 'activity_denied':
        for key in [('bedrock', 'get_model_invocation_logging_configuration'), ('bedrock', 'list_guardrails'), ('bedrock-agent', 'list_agents')]: responses[key] = None
    if scenario == 'endpoint_partial':
        responses['ec2', 'describe_vpc_endpoints'] = lambda args: None if 'NextToken' in args else {'VpcEndpoints': endpoints, 'NextToken': 'next'}
    status, snapshot, calls = pipeline(IDS[0], scenario, responses)
    if scenario == 'endpoint_partial':
        assert next(e for e in snapshot['collections'] if e['type'] == 'vpc_endpoint')['status'] == 'partial'
    assert status == expected
    if scenario == 'endpoint_partial': assert any(c['arguments'] == {'NextToken': 'next'} for c in calls)


def cloudfront():
    origin = {'Id': 'origin', 'DomainName': 'site.s3.amazonaws.com', 'S3OriginConfig': {'OriginAccessIdentity': ''}}
    config = {'CallerReference': 'review', 'Comment': '', 'Enabled': True,
        'Origins': {'Quantity': 1, 'Items': [origin]},
        'DefaultCacheBehavior': {'TargetOriginId': 'origin', 'ViewerProtocolPolicy': 'https-only'}}
    summary = {'Id': 'E123', 'ARN': CFARN, 'Status': 'Deployed', 'LastModifiedTime': STAMP,
        'DomainName': 'd123.cloudfront.net', 'Aliases': {'Quantity': 0}, 'Origins': config['Origins'],
        'DefaultCacheBehavior': config['DefaultCacheBehavior'], 'CacheBehaviors': {'Quantity': 0},
        'CustomErrorResponses': {'Quantity': 0}, 'Comment': '', 'PriceClass': 'PriceClass_All',
        'Enabled': True, 'ViewerCertificate': {'CloudFrontDefaultCertificate': True},
        'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}},
        'WebACLId': '', 'HttpVersion': 'http2', 'IsIPV6Enabled': True, 'Staging': False}
    return {('cloudfront', 'list_distributions'): {'DistributionList': {'Marker': '', 'MaxItems': 100,
        'IsTruncated': False, 'Quantity': 1, 'Items': [summary]}},
        ('cloudfront', 'get_distribution_config'): {'DistributionConfig': config, 'ETag': 'review'}}


@pytest.mark.parametrize('scenario,expected', [('owned','PASS'), ('external','UNKNOWN'), ('unrelated_bucket','UNKNOWN'),
 ('inventory_denied','UNKNOWN'), ('inventory_partial','UNKNOWN'), ('custom_origin','NOT_APPLICABLE'), ('config_denied','UNKNOWN')])
def test_cloudfront_origin_existence(pipeline, scenario, expected):
    responses = cloudfront()
    responses['s3', 'list_buckets'] = {'Buckets': [{'Name': 'site' if scenario == 'owned' else 'other'}] if scenario in {'owned','unrelated_bucket'} else []}
    if scenario == 'inventory_denied': responses['s3', 'list_buckets'] = None
    if scenario == 'inventory_partial': responses['s3', 'list_buckets'] = lambda args: None if 'ContinuationToken' in args else {'Buckets': [{'Name': 'site'}], 'ContinuationToken': 'next'}
    if scenario == 'custom_origin':
        cfg = responses['cloudfront', 'get_distribution_config']['DistributionConfig']
        cfg['Origins']['Items'] = [{'Id': 'origin', 'DomainName': 'origin.example.org',
            'CustomOriginConfig': {'HTTPPort': 80, 'HTTPSPort': 443, 'OriginProtocolPolicy': 'https-only'}}]
    if scenario == 'config_denied': responses['cloudfront', 'get_distribution_config'] = None
    status, snapshot, calls = pipeline(IDS[1], scenario, responses)
    if scenario == 'inventory_partial':
        assert next(e for e in snapshot['collections'] if e['type'] == 'bucket')['status'] == 'partial'
    assert status == expected
    assert not any(c['operation'] == 'head_bucket' for c in calls)


@pytest.mark.parametrize('scenario,expected', [('matching','PASS'), ('empty','FAIL'), ('foreign_resource','FAIL'),
 ('inactive','NOT_APPLICABLE'), ('protections_denied','UNKNOWN'), ('subscription_denied','UNKNOWN'), ('protections_partial','UNKNOWN'), ('foreign_distribution_owner','UNKNOWN')])
def test_shield_cloudfront_join(pipeline, scenario, expected):
    responses = cloudfront()
    responses['shield', 'get_subscription_state'] = {'SubscriptionState': 'INACTIVE' if scenario == 'inactive' else 'ACTIVE'}
    protections = [] if scenario == 'empty' else [{'Id': ACLID, 'Name': 'review',
        'ResourceArn': CFARN.replace('E123', 'EOTHER') if scenario == 'foreign_resource' else CFARN}]
    responses['shield', 'list_protections'] = {'Protections': protections}
    if scenario == 'protections_denied': responses['shield', 'list_protections'] = None
    if scenario == 'subscription_denied': responses['shield', 'get_subscription_state'] = None
    if scenario == 'protections_partial': responses['shield', 'list_protections'] = lambda args: None if 'NextToken' in args else {'Protections': protections, 'NextToken': 'next'}
    if scenario == 'foreign_distribution_owner': responses['cloudfront', 'list_distributions']['DistributionList']['Items'][0]['ARN'] = CFARN.replace(ACCOUNT, '999999999999')
    status, _, _ = pipeline(IDS[2], scenario, responses)
    assert status == expected


@pytest.mark.parametrize('scenario,expected', [('matching','PASS'), ('empty','FAIL'), ('foreign_vpc','FAIL'),
 ('unused','NOT_APPLICABLE'), ('denied','UNKNOWN'), ('detail_denied','UNKNOWN'), ('foreign_detail','UNKNOWN'), ('interfaces_denied','UNKNOWN'), ('partial','UNKNOWN')])
def test_network_firewall_vpc_join(pipeline, scenario, expected):
    responses = network_base(scenario != 'unused')
    rows = [] if scenario == 'empty' else [{'FirewallArn': FWARN, 'FirewallName': 'review'}]
    responses.update({('network-firewall', 'list_firewalls'): {'Firewalls': rows},
        ('network-firewall', 'describe_firewall'): {'Firewall': {'FirewallName': 'review', 'FirewallArn': FWARN + '-other' if scenario == 'foreign_detail' else FWARN,
            'FirewallId': '11111111-2222-3333-4444-555555555555', 'VpcId': 'vpc-other' if scenario == 'foreign_vpc' else 'vpc-1',
            'FirewallPolicyArn': FWARN.replace('firewall/', 'firewall-policy/'), 'SubnetMappings': []}},
        ('network-firewall', 'describe_logging_configuration'): {}})
    if scenario == 'denied': responses['network-firewall', 'list_firewalls'] = None
    if scenario == 'detail_denied': responses['network-firewall', 'describe_firewall'] = None
    if scenario == 'interfaces_denied': responses['ec2', 'describe_network_interfaces'] = None
    if scenario == 'partial': responses['network-firewall', 'list_firewalls'] = lambda args: None if 'NextToken' in args else {'Firewalls': rows, 'NextToken': 'next'}
    status, _, _ = pipeline(IDS[3], scenario, responses)
    assert status == expected


def stages(rows):
    return {('apigateway', 'get_rest_apis'): {'items': [{'id': 'abc123', 'name': 'review'}]},
        ('apigateway', 'get_stages'): {'item': rows}}


@pytest.mark.parametrize('scenario,expected', [('clean','PASS'), ('canary','FAIL'), ('omitted_variables','PASS'),
 ('oversize','UNKNOWN'), ('denied','DENIED'), ('parent_partial','UNKNOWN'), ('invalid_stage','UNKNOWN')])
def test_stage_secret_indicators(pipeline, scenario, expected):
    row = {'stageName': 'prod', 'variables': {'DB_PASSWORD': TOKEN} if scenario == 'canary' else {'mode': 'review'}}
    if scenario == 'omitted_variables': row.pop('variables')
    if scenario == 'oversize': row['variables'] = {'token': 'a' * 100000}
    if scenario == 'invalid_stage': row['stageName'] = 'invalid/stage'
    responses = stages([row])
    if scenario == 'denied': responses['apigateway', 'get_stages'] = None
    if scenario == 'parent_partial':
        responses['apigateway', 'get_rest_apis'] = {'items': [{'id': 'abc123'}, {'id': 'other123'}]}
        responses['apigateway', 'get_stages'] = lambda args: {'item': [row]} if args['restApiId'] == 'abc123' else None
    status, snapshot, calls = pipeline(IDS[4], scenario, responses)
    assert status == expected
    if scenario == 'canary':
        item = next(e['items'][0] for e in snapshot['collections'] if e['type'] == 'rest_api_stage')
        assert item['AdditionalSecretIndicators']['HighConfidenceSecretPresent'] is True
        assert item['AdditionalSecretIndicators']['ResourceId'] == 'abc123/prod'
        assert next(c for c in calls if c['operation'] == 'get_stages')['arguments'] == {'restApiId': 'abc123'}


def acl():
    return {'Name': 'review', 'Id': ACLID, 'ARN': ACLARN, 'DefaultAction': {'Allow': {}},
        'VisibilityConfig': {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True, 'MetricName': 'review'},
        'Capacity': 1, 'Rules': []}


@pytest.mark.parametrize('scenario,expected', [('matching','PASS'), ('absent','FAIL'), ('declaration_mismatch','FAIL'),
 ('inventory_missing','FAIL'), ('association_denied','UNKNOWN'), ('inventory_denied','UNKNOWN'),
 ('foreign_acl_owner','UNKNOWN'), ('association_partial','UNKNOWN'), ('duplicate_stage','UNKNOWN')])
def test_effective_stage_waf_join(pipeline, scenario, expected):
    row = {'stageName': 'prod', 'webAclArn': ACLARN}
    if scenario == 'absent': row.pop('webAclArn')
    if scenario == 'declaration_mismatch': row['webAclArn'] = ACLARN.replace('/review/', '/different/')
    responses = stages([row, row] if scenario == 'duplicate_stage' else [row])
    effective = acl()
    if scenario == 'foreign_acl_owner': effective['ARN'] = ACLARN.replace(ACCOUNT, '999999999999')
    responses['wafv2', 'get_web_acl_for_resource'] = {} if scenario == 'absent' else {'WebACL': effective}
    summary = {key: acl()[key] for key in ('Name', 'Id', 'ARN')}
    responses['wafv2', 'list_web_acls'] = lambda args: {'WebACLs': [summary] if args['Scope'] == 'REGIONAL' and scenario != 'inventory_missing' else []}
    responses['wafv2', 'get_web_acl'] = {'WebACL': acl(), 'LockToken': ACLID}
    responses['wafv2', 'get_logging_configuration'] = ('WAFNonexistentItemException',)
    responses['wafv2', 'list_resources_for_web_acl'] = {'ResourceArns': [STAGEARN]}
    if scenario == 'association_denied': responses['wafv2', 'get_web_acl_for_resource'] = None
    if scenario == 'inventory_denied': responses['wafv2', 'list_web_acls'] = None
    if scenario == 'association_partial':
        responses['apigateway', 'get_stages'] = {'item': [row, {'stageName': 'other', 'webAclArn': ACLARN}]}
        responses['wafv2', 'get_web_acl_for_resource'] = lambda args: {'WebACL': effective} if args['ResourceArn'] == STAGEARN else None
    status, _, calls = pipeline(IDS[5], scenario, responses)
    assert status == expected
    if scenario == 'matching':
        assert any(c['operation'] == 'get_web_acl_for_resource' and c['arguments'] == {'ResourceArn': STAGEARN} for c in calls)
