"""Actual SDK association responses to bounded collector and registered consumer."""
from copy import deepcopy

import pytest

from peaso.collectors import aws
from peaso.collectors import aws_alb_waf_association_metadata as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot, validate
from tests.test_peaso_collectors_aws import sdk, ACCOUNT, REGION, IDENTITY

CID = 'aws_wafv2_request_validation_rules'
SCOPE = ACCOUNT + '/' + REGION
ALB = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/public-alb/0123456789abcdef'
ACL = f'arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/validation/12345678-1234-1234-1234-123456789012'


def lb():
    return {'LoadBalancerArn': ALB, 'LoadBalancerName': 'public-alb', 'Type': 'application', 'Scheme': 'internet-facing'}


def webacl():
    return {'ARN': ACL, 'Id': ACL.rsplit('/', 1)[1], 'Name': 'validation',
            'DefaultAction': {'Allow': {}},
            'VisibilityConfig': {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True, 'MetricName': 'validation'},
            'Rules': [{'Name': 'common', 'Priority': 1,
                       'Statement': {'ManagedRuleGroupStatement': {'VendorName': 'AWS', 'Name': 'AWSManagedRulesCommonRuleSet'}},
                       'OverrideAction': {'None': {}},
                       'VisibilityConfig': {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True, 'MetricName': 'common'}}]}


def consumer(items, *, web=None):
    # WAF subject inventory is a controlled native-shape fixture; this receipt
    # proves the new association producer, not the WAF inventory collector.
    web = webacl() if web is None else web
    row = {'ARN': web['ARN'], 'Id': web['Id'], 'Scope': 'REGIONAL', 'WebACL': web}
    snapshot = make_snapshot('aws', [SCOPE], [
        {'type': 'wafv2_web_acl', 'scope': SCOPE, 'status': 'collected', 'items': [row]},
        {'type': 'load_balancer_v2', 'scope': SCOPE, 'status': 'collected', 'items': items}])
    return evaluate_snapshot(snapshot, checks=[CID])['findings'][0]['status']


def stub_reply(stub, mode):
    params = {'ResourceArn': ALB}
    if mode in ('denied', 'absent', 'unrelated_error'):
        stub.add_client_error('get_web_acl_for_resource', service_error_code={
            'denied': 'AccessDeniedException', 'absent': 'WAFNonexistentItemException',
            'unrelated_error': 'WAFUnavailableEntityException'}[mode], http_status_code=400 if mode != 'denied' else 403,
            expected_params=params)
        return
    response = {'WebACL': webacl()}
    if mode == 'empty': response = {}
    if mode == 'missing_arn': response['WebACL'].pop('ARN')
    if mode == 'wrong_account': response['WebACL']['ARN'] = ACL.replace(ACCOUNT, '999999999999')
    if mode == 'wrong_region': response['WebACL']['ARN'] = ACL.replace(REGION, 'eu-west-1')
    if mode == 'wrong_partition': response['WebACL']['ARN'] = ACL.replace('arn:aws:', 'arn:aws-cn:')
    if mode == 'wrong_scope': response['WebACL']['ARN'] = ACL.replace(':regional/', ':global/')
    if mode == 'wrong_id': response['WebACL']['Id'] = '87654321-1234-1234-1234-123456789012'
    if mode == 'wrong_name': response['WebACL']['Name'] = 'another'
    stub.add_response('get_web_acl_for_resource', response, params)


@pytest.mark.parametrize('mode,expected', [('bound', 'PASS'), ('absent', 'FAIL'), ('denied', 'UNKNOWN'),
    ('empty', 'UNKNOWN'), ('wrong_account', 'UNKNOWN'), ('wrong_region', 'UNKNOWN'),
    ('wrong_partition', 'UNKNOWN'), ('wrong_scope', 'UNKNOWN'), ('wrong_id', 'UNKNOWN'), ('wrong_name', 'UNKNOWN'),
    ('unrelated_error', 'UNKNOWN')])
def test_actual_sdk_request_bound_association_to_registered_consumer(sdk, mode, expected):
    session, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    stub_reply(add('wafv2'), mode)
    requests = aws.Requests({'retry_attempts': 1})
    original = lb()
    original['WAFWebACLArn'] = 'stale-never-trust'
    before = deepcopy(original)
    rows = native.enrich(requests, session, REGION, [original])
    assert original == before
    assert consumer(rows) == expected
    if mode == 'bound': assert rows[0]['WAFWebACLArn'] == ACL
    elif mode == 'absent': assert rows[0]['WAFWebACLArn'] == ''
    else: assert 'WAFWebACLArn' not in rows[0]
    # Shared cache coalesces a second observation and maintains the outcome.
    assert native.enrich(requests, session, REGION, [original]) == rows
    assert requests.calls == 2


@pytest.mark.parametrize('change', [
    {'Type': 'network'}, {'Scheme': 'internal'}, {'LoadBalancerArn': 'not-an-arn'},
    {'LoadBalancerName': 'wrong'}, {'LoadBalancerArn': ALB.replace(REGION, 'eu-west-1')},
])
def test_ineligible_or_unbound_load_balancer_never_requests_waf(sdk, change):
    session, _, _ = sdk
    row = lb()
    row.update(change)
    row['WAFWebACLArn'] = ACL
    requests = aws.Requests({'retry_attempts': 1})
    result = native.enrich(requests, session, REGION, [row])[0]
    assert 'WAFWebACLArn' not in result
    assert requests.calls == 0


@pytest.mark.parametrize('identity', [
    {**IDENTITY, 'Account': '999999999999'},
    {**IDENTITY, 'Arn': IDENTITY['Arn'].replace('arn:aws:', 'arn:aws-cn:')},
    {**IDENTITY, 'Arn': IDENTITY['Arn'].replace(ACCOUNT, '999999999999')},
])
def test_caller_account_and_partition_must_bind_before_waf_read(sdk, identity):
    session, add, _ = sdk
    add('sts').add_response('get_caller_identity', identity, {})
    requests = aws.Requests({'retry_attempts': 1})
    result = native.enrich(requests, session, REGION, [lb()])
    assert consumer(result) == 'UNKNOWN'
    assert requests.calls == 1


def _contains_callback(function, target, seen=None):
    seen = set() if seen is None else seen
    if function is target: return True
    if id(function) in seen: return False
    seen.add(id(function))
    for cell in getattr(function, '__closure__', ()) or ():
        value = cell.cell_contents
        if callable(value) and _contains_callback(value, target, seen): return True
    return False


@pytest.mark.parametrize('mode,expected', [('bound', 'PASS'), ('absent', 'FAIL'), ('denied', 'UNKNOWN'), ('empty', 'UNKNOWN')])
def test_sdk_public_lb_pipeline_to_consumer_with_controlled_waf_inventory(sdk, monkeypatch, mode, expected, request):
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    elb = add('elbv2')
    elb.add_response('describe_load_balancers', {'LoadBalancers': [lb()]}, {})
    elb.add_response('describe_listeners', {'Listeners': []}, {'LoadBalancerArn': ALB})
    stub_reply(add('wafv2'), mode)
    # Root owns the shared extension hook. Exercise its exact intended chain
    # locally until root registers the module, without writing aws.py here.
    current = aws.ENRICHERS['load_balancer_v2']
    if not _contains_callback(current, native.enrich):
        monkeypatch.setitem(aws.ENRICHERS, 'load_balancer_v2', aws._chain(current, native.enrich))
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                            'options': {'regions': [REGION], 'retry_attempts': 1}}, ['load_balancer_v2'])
    validate(snapshot)
    envelope = next(e for e in snapshot['collections'] if e['type'] == 'load_balancer_v2')
    assert envelope['status'] == 'collected'
    assert consumer(envelope['items']) == expected


@pytest.mark.parametrize('response', [{}, {'collection_status': 'collected'},
    {'collection_status': 'collected', 'WebACL': {}},
    {'collection_status': 'empty', 'absent': True},
    {'collection_status': 'empty', 'absent': True, 'error': {'code': 'AccessDeniedException'}}])
def test_malformed_or_unproved_lower_boundary_response_is_unknown(response):
    """Deliberately malformed data is not claimed to be SDK-valid output."""
    from types import SimpleNamespace
    identity = {**IDENTITY, 'collection_status': 'collected'}
    request = SimpleNamespace(detail=lambda session, service, region, operation, **kwargs:
                              identity if service == 'sts' else deepcopy(response))
    rows = native.enrich(request, object(), REGION, [lb()])
    assert 'WAFWebACLArn' not in rows[0]
    assert consumer(rows) == 'UNKNOWN'


def test_budget_exhaustion_and_denied_identity_cannot_preserve_old_association(sdk):
    session, add, _ = sdk
    add('sts').add_client_error('get_caller_identity', service_error_code='AccessDenied',
                                http_status_code=403, expected_params={})
    requests = aws.Requests({'retry_attempts': 1, 'max_calls': 1})
    item = {**lb(), 'WAFWebACLArn': ACL}
    assert consumer(native.enrich(requests, session, REGION, [item])) == 'UNKNOWN'
    assert requests.calls == 1
    exhausted = aws.Requests({'retry_attempts': 1, 'max_calls': 1})
    exhausted.calls = 1
    assert consumer(native.enrich(exhausted, session, REGION, [item])) == 'UNKNOWN'


def test_root_registered_association_hook_and_existing_read_allowlist():
    assert 'peaso.collectors.aws_alb_waf_association_metadata' in aws.EXTENSION_MODULES
    assert native.READ_ACTIONS <= aws.READ_ACTIONS
    assert _contains_callback(aws.ENRICHERS['load_balancer_v2'], native.enrich)
