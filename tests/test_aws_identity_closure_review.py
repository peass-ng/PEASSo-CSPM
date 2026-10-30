"""Directed native identity closure receipts; no cloud access or mutations.

Regression expectations follow AWS field semantics. Original pre-fix receipts are
preserved separately; fixture witnesses never establish complete semantics.
"""
import copy
import json
from datetime import datetime, timezone
from urllib.parse import quote

import boto3
import pytest
from botocore.stub import Stubber
from peaso import engine
from peaso.collectors import aws, aws_facts_gap, aws_facts_cb_ca

ACCOUNT, FOREIGN, REGION = '123456789012', '999999999999', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
REGISTRY = {c.id: c for c in engine._registry()}
METRICS = sorted(cid for cid in REGISTRY if cid.startswith(('aws.gap.cloudwatch.cis_alarm.', 'aws.gap.cloudwatch.metric_alarm.')))
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    clients, stubs = {}, {}
    def stub(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service])
            stubs[service].activate()
        return stubs[service]
    monkeypatch.setattr(aws.Requests, 'client', lambda self, selected, service, region: clients[service])
    yield aws.Requests({'retry_attempts': 1}), session, stub
    for value in stubs.values():
        value.assert_no_pending_responses()
        value.deactivate()


def metric_index(sdk, state):
    """SDK Describe* responses -> Requests -> real projection -> scope index."""
    requests, session, stub = sdk
    group, topic = 'CloudTrail/audit', f'arn:aws:sns:{REGION}:{ACCOUNT}:security-alerts'
    query = {'Id': 'm1', 'AccountId': FOREIGN if state == 'foreign' else ACCOUNT,
             'ReturnData': True, 'MetricStat': {'Metric': {'Namespace': 'Other' if state == 'wrong_namespace' else 'CISBenchmark',
             'MetricName': 'm', 'Dimensions': []}, 'Period': 60, 'Stat': 'Sum'}}
    alarm = {'AlarmName': 'review', 'AlarmArn': f'arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:review',
             'ActionsEnabled': True, 'AlarmActions': [topic], 'Metrics': [query]}
    if state in ('mixed_foreign_output', 'mixed_local_output', 'mixed_expression'):
        other = copy.deepcopy(query)
        other.update(Id='m2', AccountId=FOREIGN, ReturnData=state == 'mixed_foreign_output')
        query['ReturnData'] = state == 'mixed_local_output'
        alarm['Metrics'].append(other)
        if state == 'mixed_expression':
            alarm['Metrics'].append({'Id': 'e1', 'Expression': 'm1 + m2', 'ReturnData': True})
    if state == 'malformed_account': query['AccountId'] = 'invalid-account'
    if state == 'missing_account': query.pop('AccountId')
    if state == 'expression':
        query['ReturnData'] = False
        alarm['Metrics'].append({'Id': 'e1', 'Expression': 'm1 * 0', 'ReturnData': True})
    cw = stub('cloudwatch')
    if state == 'denied':
        cw.add_client_error('describe_alarms', service_error_code='AccessDenied', expected_params={})
    else:
        cw.add_response('describe_alarms', {'MetricAlarms': [alarm]}, {})
    stub('logs').add_response('describe_metric_filters', {'metricFilters': [
        {'filterName': 'all-management', 'logGroupName': group, 'filterPattern': '',
         'metricTransformations': [{'metricName': 'm', 'metricNamespace': 'CISBenchmark', 'metricValue': '1', **({} if state == 'omitted_dimensions' else {'dimensions': {}})}]}]}, {})
    sns = stub('sns')
    if state == 'subscriptions_denied':
        sns.add_client_error('list_subscriptions', service_error_code='AuthorizationError', expected_params={})
    else:
        sns.add_response('list_subscriptions', {'Subscriptions': [
            {'SubscriptionArn': 'PendingConfirmation' if state == 'pending' else topic + ':11111111-1111-1111-1111-111111111111',
             'TopicArn': topic, 'Protocol': 'email'}]}, {})
    def regional_job(selected, identity, region, kind):
        if kind == 'log_metric_filter':
            return aws_facts_gap.FETCHERS[kind](requests, selected, region, identity['Account'])
        if kind == 'sns_subscription':
            return aws_facts_cb_ca.FETCHERS[kind](requests, selected, region, identity['Account'])
        service, operation, expression = {'cloudwatch_alarm': ('cloudwatch', 'describe_alarms', 'MetricAlarms'),
            'sns_subscription': ('sns', 'list_subscriptions', 'Subscriptions')}[kind]
        return requests.pages(selected, service, region, operation, expression)
    read = aws_facts_gap.metric_alarm_rows(regional_job, session, {'Account': ACCOUNT}, [REGION])
    # Native CloudTrail details are independently modeled rather than copied from CASES.
    trail_arn = f'arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/audit'
    ct = stub('cloudtrail')
    ct.add_response('get_trail_status', {'IsLogging': True}, {'Name': trail_arn})
    ct.add_response('get_event_selectors', {'TrailARN': trail_arn, 'EventSelectors': [
        {'ReadWriteType': 'All', 'IncludeManagementEvents': True}]}, {'TrailName': trail_arn})
    ct.add_client_error('get_insight_selectors', service_error_code='InsightNotEnabledException', expected_params={'TrailName': trail_arn})
    trail = aws._enrich(requests, session, REGION, 'cloudtrail', [{'Name': 'audit', 'TrailARN': trail_arn,
        'HomeRegion': REGION, 'IsMultiRegionTrail': True, 'IncludeGlobalServiceEvents': True,
        'CloudWatchLogsLogGroupArn': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{group}:*'}])[0]
    index = {'context': {'provider': 'aws', 'scope': SCOPE, 'Account': ACCOUNT, 'created_at': NOW.isoformat()}, 'collections': {}}
    for kind, rows in [('cloudtrail_account_inventory', [trail]), ('metric_alarm_account_inventory', read.items)]:
        index['collections'][kind] = [{'type': kind, 'scope': ACCOUNT+'/global', 'account_id': ACCOUNT,
                                      'global': True, 'status': 'collected', 'items': rows}]
        index[kind] = [{'type': kind, 'scope': ACCOUNT+'/global', 'data': row} for row in rows]
    return index


@pytest.mark.parametrize('cid', METRICS)
@pytest.mark.parametrize('state,expected', [('local', 'PASS'), ('missing_account', 'PASS'), ('wrong_namespace', 'FAIL'),
                                          ('denied', 'UNKNOWN'), ('expression', 'UNKNOWN')])
def test_native_metric_positive_negative_unavailable(sdk, cid, state, expected):
    assert REGISTRY[cid].evaluate({'id': 'account-configuration'}, metric_index(sdk, state))[0] == expected


@pytest.mark.parametrize('cid', METRICS)
def test_native_foreign_metric_required_aws_semantics(sdk, cid):
    index = metric_index(sdk, 'foreign')
    projected = index['metric_alarm_account_inventory'][0]['data']['MetricAlarms']['items'][0]['Metrics'][0]
    assert projected['AccountId'] == FOREIGN
    assert REGISTRY[cid].evaluate({'id': 'account-configuration'}, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid', METRICS)
def test_native_omitted_dimensions_required_aws_semantics(sdk, cid):
    index = metric_index(sdk, 'omitted_dimensions')
    assert REGISTRY[cid].evaluate({'id': 'account-configuration'}, index)[0] == 'PASS'


@pytest.mark.parametrize('cid', METRICS)
@pytest.mark.parametrize('state,expected', [('mixed_foreign_output', 'UNKNOWN'), ('mixed_local_output', 'PASS'),
                                          ('mixed_expression', 'UNKNOWN'), ('malformed_account', 'UNKNOWN')])
def test_native_mixed_metric_account_and_output_binding(sdk, cid, state, expected):
    assert REGISTRY[cid].evaluate({'id': 'account-configuration'}, metric_index(sdk, state))[0] == expected


@pytest.mark.parametrize('cid', METRICS)
@pytest.mark.parametrize('state', ['pending', 'subscriptions_denied'])
def test_native_subscription_join(sdk, cid, state):
    strict = '.cis_alarm.' in cid
    expected = ('FAIL' if state == 'pending' else 'UNKNOWN') if strict else 'PASS'
    assert REGISTRY[cid].evaluate({'id': 'account-configuration'}, metric_index(sdk, state))[0] == expected


@pytest.mark.parametrize('state,expected', [('present', 'PASS'), ('absent', 'FAIL'), ('denied', 'UNKNOWN')])
def test_native_organization_id_alias(sdk, state, expected):
    requests, session, stub = sdk
    stub('account').add_client_error('get_alternate_contact', service_error_code='ResourceNotFoundException',
                                     expected_params={'AlternateContactType': 'SECURITY'})
    organizations = stub('organizations')
    if state == 'present':
        organizations.add_response('describe_organization', {'Organization': {'Id': 'o-example1234', 'MasterAccountId': ACCOUNT}}, {})
    else:
        organizations.add_client_error('describe_organization', service_error_code='AWSOrganizationsNotInUseException' if state == 'absent' else 'AccessDeniedException', expected_params={})
    read = aws._account_configuration(requests, session, REGION, {'Arn': f'arn:aws:iam::{ACCOUNT}:role/review'})
    item = read.items[0]
    if state == 'present': assert item['Organization']['OrganizationId'] == 'o-example1234'
    assert REGISTRY['aws.a.account.organization_member'].evaluate(item, {})[0] == expected


def policy_index(read):
    return {'context': {'provider': 'aws', 'scope': SCOPE, 'Account': ACCOUNT, 'created_at': NOW.isoformat()},
            'collections': {'iam_policy': [{'type': 'iam_policy', 'scope': ACCOUNT+'/global', 'global': True,
                            'account_id': ACCOUNT, 'status': read.status, 'items': read.items}]},
            'iam_policy': [{'type': 'iam_policy', 'scope': ACCOUNT+'/global', 'data': row} for row in read.items]}


POLICIES = ['aws.iam.no_full_admin', 'aws.a.iam.attached_policy_no_star_star',
            'aws.claude_a.iam.custom_policy_no_star_star', 'aws.claude_a.iam.prowler_customer_attached_policy_no_admin']


@pytest.mark.parametrize('cid', POLICIES)
@pytest.mark.parametrize('state,expected', [('safe','PASS'), ('unsafe','FAIL'), ('missing_document','UNKNOWN'), ('denied','UNKNOWN')])
def test_gaad_default_native_contract(sdk, cid, state, expected):
    requests, session, stub = sdk
    api = stub('iam')
    if state == 'denied':
        api.add_client_error('get_account_authorization_details', service_error_code='AccessDenied', expected_params={})
    else:
        document = {'Statement': [{'Effect': 'Allow', 'Action': '*' if state == 'unsafe' else 's3:GetObject', 'Resource': '*'}]}
        version = {'VersionId': 'v1', 'IsDefaultVersion': True}
        if state != 'missing_document': version['Document'] = quote(json.dumps(document))
        api.add_response('get_account_authorization_details', {'IsTruncated': False, 'Policies': [{
            'Arn': f'arn:aws:iam::{ACCOUNT}:policy/review', 'PolicyName': 'review', 'AttachmentCount': 1,
            'DefaultVersionId': 'v1', 'PolicyVersionList': [version]}]}, {})
    read = aws._iam(requests, session, REGION, {'iam_policy'})['iam_policy']
    assert REGISTRY[cid].evaluate(read.items[0] if read.items else {}, policy_index(read))[0] == expected
