"""Pinned customer-managed IAM wildcard controls and native SDK producer."""
import copy
import json
import boto3
from botocore.stub import Stubber
import pytest
from peaso.collectors import aws
from peaso.collectors.aws_customer_policies import collect
from peaso.checks import evaluate_check
from peaso.checks.aws_all_policies import MODES
from peaso.engine import plan_collection

ACCOUNT = '123456789012'
LOCAL = f'arn:aws:iam::{ACCOUNT}:policy/Custom'
AWS = 'arn:aws:iam::aws:policy/AdministratorAccess'
SAFE = {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::bucket/object'}]}


def produce(document=SAFE, arn=LOCAL, deny=False, partial=False):
    session = boto3.Session(aws_access_key_id='fake', aws_secret_access_key='fake', region_name='us-east-1')
    client = session.client('iam')
    requests = aws.Requests({'concurrency': 1})
    requests.client = lambda *args: client
    with Stubber(client) as stub:
        stub.add_response('list_policies', {'Policies': [{'Arn': arn, 'DefaultVersionId': 'v1'}], 'IsTruncated': True, 'Marker': 'next'}, {'Scope': 'Local', 'OnlyAttached': False})
        if partial:
            stub.add_client_error('list_policies', service_error_code='AccessDenied', expected_params={'Scope': 'Local', 'OnlyAttached': False, 'Marker': 'next'})
        else:
            stub.add_response('list_policies', {'Policies': [], 'IsTruncated': False}, {'Scope': 'Local', 'OnlyAttached': False, 'Marker': 'next'})
        if arn == AWS:
            pass  # Rejected by account-owned Local inventory validation before detail reads.
        elif deny:
            stub.add_client_error('get_policy_version', service_error_code='AccessDenied', expected_params={'PolicyArn': arn, 'VersionId': 'v1'})
        else:
            stub.add_response('get_policy_version', {'PolicyVersion': {'VersionId': 'v1', 'IsDefaultVersion': True, 'Document': json.dumps(document)}}, {'PolicyArn': arn, 'VersionId': 'v1'})
        result = collect(requests, session, 'us-east-1', ACCOUNT)
        stub.assert_no_pending_responses()
    return result


def index(read, *, status=None):
    scope = ACCOUNT+'/global'
    return {'context': {'provider': 'aws', 'Account': ACCOUNT, 'scope': scope},
            'collections': {'iam_customer_policy': [{'type': 'iam_customer_policy', 'scope': scope, 'status': status or read.status, 'items': read.items}]},
            'iam_customer_policy': [{'type': 'iam_customer_policy', 'scope': scope, 'data': row} for row in read.items]}


def grade(ident, facts):
    return evaluate_check(ident, {'scope': ACCOUNT+'/global'}, facts)[0]


@pytest.mark.parametrize('ident', MODES)
def test_sdk_customer_only_unattached_and_complete(ident):
    mode = MODES[ident]
    assert grade(ident, index(produce())) == 'PASS'
    bad = {'Statement': [{'Effect': 'Allow', 'Action': 's3:*' if mode == 'service' else '*', 'Resource': '*'}]}
    facts = index(produce(bad))
    before = copy.deepcopy(facts)
    assert grade(ident, facts) == 'FAIL'
    assert facts == before
    assert grade(ident, index(produce(bad, arn=AWS))) == 'UNKNOWN'
    assert grade(ident, index(produce(deny=True))) in ('UNKNOWN', 'DENIED')
    assert grade(ident, index(produce(partial=True))) in ('UNKNOWN', 'DENIED')
    assert grade(ident, index(produce(), status='partial')) != 'PASS'
    mismatch = index(produce())
    mismatch['iam_customer_policy'][0]['data']['DefaultVersionId'] = 'v2'
    assert grade(ident, mismatch) == 'UNKNOWN'


@pytest.mark.parametrize('ident', MODES)
def test_aws_library_and_inline_do_not_fail_mapped_control(ident):
    facts = index(produce())
    facts['iam_managed_policy'] = [{'type': 'iam_managed_policy', 'scope': ACCOUNT+'/global',
                                    'data': {'Arn': AWS, 'DefaultDocument': {'Document': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}}}]
    facts['iam_role'] = [{'type': 'iam_role', 'scope': ACCOUNT+'/global',
                          'data': {'RolePolicyList': [{'PolicyName': 'inline', 'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}]}}]
    assert grade(ident, facts) == 'PASS'


@pytest.mark.parametrize('ident', MODES)
def test_literal_sql_action_resource_and_bad_evidence(ident):
    mode = MODES[ident]
    assert grade(ident, index(produce({'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': 'arn:aws:s3:::bucket/object'}]}))) == 'PASS'
    assert grade(ident, index(produce({'Statement': [{'Effect': 'Allow', 'Action': '*:*', 'Resource': '*'}]}))) == 'FAIL'
    assert grade(ident, index(produce({'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*'}]}))) == ('FAIL' if mode == 'service' else 'PASS')
    assert grade(ident, index(produce({'Statement': ['bad']}))) == 'UNKNOWN'
    foreign = index(produce())
    foreign['iam_customer_policy'][0]['data']['Arn'] = AWS
    assert grade(ident, foreign) == 'UNKNOWN'
    duplicate = index(produce())
    duplicate['collections']['iam_customer_policy'][0]['items'] *= 2
    duplicate['iam_customer_policy'] *= 2
    assert grade(ident, duplicate) == 'UNKNOWN'


def test_planner_avoids_orphan_aws_library_but_preserves_explicit_inventory():
    default = plan_collection({'connector': {'provider': 'aws'}})
    assert 'iam_customer_policy' in default
    assert 'iam_managed_policy' not in default
    assert plan_collection({'connector': {'provider': 'aws', 'options': {'inventories': ['iam_managed_policy']}}}) == ['iam_managed_policy']
    all_kinds = plan_collection({'connector': {'provider': 'aws', 'options': {'collect_all': True}}})
    assert {'iam_managed_policy', 'iam_customer_policy'} <= set(all_kinds)


def test_engine_statuses_from_stubbed_customer_inventory():
    from peaso.snapshot import make_snapshot
    from peaso.engine import evaluate_snapshot
    cid = 'aws_nist_iam_policy_no_star_star'
    scope = ACCOUNT+'/global'
    for read, expected in (
        (produce(), 'PASS'),
        (produce({'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}), 'FAIL'),
        (produce(deny=True), 'UNKNOWN'),
        (produce(partial=True), 'UNKNOWN'),
    ):
        snapshot = make_snapshot('aws', [scope], [{'type': 'iam_customer_policy', 'scope': scope,
            'status': read.status, 'items': read.items}])
        report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[cid])
        assert report['findings'][0]['status'] == expected


@pytest.mark.parametrize('ident', MODES)
def test_aws_administratoraccess_alone_is_not_a_control_failure(ident):
    facts = index(aws.ReadResult([], 'empty'))
    facts['iam_managed_policy'] = [{'type': 'iam_managed_policy', 'scope': ACCOUNT+'/global',
        'data': {'Arn': AWS, 'DefaultDocument': {'Document': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}}}]
    assert grade(ident, facts) == 'PASS'


@pytest.mark.parametrize('mutation', ['missing_document', 'false_default', 'wrong_version'])
def test_successful_but_invalid_default_detail_is_partial(mutation):
    session = boto3.Session(aws_access_key_id='fake', aws_secret_access_key='fake', region_name='us-east-1')
    client = session.client('iam')
    requests = aws.Requests({'concurrency': 1})
    requests.client = lambda *args: client
    version = {'VersionId': 'v2' if mutation == 'wrong_version' else 'v1',
               'IsDefaultVersion': mutation != 'false_default'}
    if mutation != 'missing_document':
        version['Document'] = json.dumps(SAFE)
    with Stubber(client) as stub:
        stub.add_response('list_policies', {'Policies': [{'Arn': LOCAL, 'DefaultVersionId': 'v1'}], 'IsTruncated': False},
                          {'Scope': 'Local', 'OnlyAttached': False})
        stub.add_response('get_policy_version', {'PolicyVersion': version}, {'PolicyArn': LOCAL, 'VersionId': 'v1'})
        read = collect(requests, session, 'us-east-1', ACCOUNT)
        stub.assert_no_pending_responses()
    assert read.status == 'partial'
    assert read.items[0]['DefaultDocument']['collection_status'] == 'partial'
    assert all(grade(cid, index(read)) != 'PASS' for cid in MODES)


def test_zero_item_list_denial_preserves_denied_cause():
    session = boto3.Session(aws_access_key_id='fake', aws_secret_access_key='fake', region_name='us-east-1')
    client = session.client('iam')
    requests = aws.Requests({'concurrency': 1})
    requests.client = lambda *args: client
    with Stubber(client) as stub:
        stub.add_client_error('list_policies', service_error_code='AccessDenied',
                              expected_params={'Scope': 'Local', 'OnlyAttached': False})
        read = collect(requests, session, 'us-east-1', ACCOUNT)
        stub.assert_no_pending_responses()
    assert read.items == []
    assert read.status == 'denied'
    assert read.error['code'] == 'AccessDenied'
    assert all(grade(cid, index(read)) != 'PASS' for cid in MODES)


