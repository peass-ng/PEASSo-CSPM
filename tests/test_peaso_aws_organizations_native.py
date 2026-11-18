"""SDK-backed Organizations inheritance, exact native identities and decisions."""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT
from peaso.collectors import aws, aws_organizations_native as native
from peaso.collectors.bulk_evidence import collect as collect_bulk
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGION = 'eu-west-1'
SCOPE = ACCOUNT + '/' + REGION
MASTER = '111111111111'
ORG = {'Id': 'o-abcdefghij', 'MasterAccountId': MASTER, 'FeatureSet': 'ALL'}
ROOT = 'r-abcd'
OU = 'ou-abcd-abcdefgh'
PID = 'p-abcdefgh'


def summary(kind='SERVICE_CONTROL_POLICY', *, managed=False):
    identifier = 'p-FullAWSAccess' if managed else PID
    suffix = 'service_control_policy' if kind == 'SERVICE_CONTROL_POLICY' else 'tag_policy'
    arn = ('arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess' if managed else
           f'arn:aws:organizations::{MASTER}:policy/{ORG["Id"]}/{suffix}/{identifier}')
    return {'Id': identifier, 'Arn': arn, 'Type': kind, 'Name': 'policy', 'AwsManaged': managed}


def organization(stub):
    stub.add_response('describe_organization', {'Organization': ORG}, {})


def parents(stub, *, mode='complete'):
    if mode == 'denied':
        stub.add_client_error('list_parents', 'AccessDeniedException', expected_params={'ChildId': ACCOUNT})
        return
    first = {'Id': OU, 'Type': 'ORGANIZATIONAL_UNIT'}
    stub.add_response('list_parents', {'Parents': [first]}, {'ChildId': ACCOUNT})
    if mode == 'cycle':
        stub.add_response('list_parents', {'Parents': [first]}, {'ChildId': OU})
    else:
        stub.add_response('list_parents', {'Parents': [{'Id': ROOT, 'Type': 'ROOT'}]}, {'ChildId': OU})


def statements():
    return [{'Effect': 'Deny', 'Action': ['ec2:RunInstances'], 'Resource': '*',
             'Condition': {'StringNotEquals': {'ec2:InstanceType': ['t3.micro']}}},
            {'Effect': 'Deny', 'Action': ['cloudtrail:*', 'config:*', 'guardduty:*', 'securityhub:*'], 'Resource': '*'}]


def scp_read(sdk, mode='complete'):
    session, add = sdk
    stub = add('organizations')
    organization(stub)
    if mode == 'accounts_denied':
        stub.add_client_error('list_accounts', 'AccessDeniedException', expected_params={})
        return native.effective_scp(aws.Requests({'retries': 0}), session, REGION, ACCOUNT), stub
    stub.add_response('list_accounts', {'Accounts': [{'Id': ACCOUNT, 'Status': 'ACTIVE'}]}, {})
    parents(stub, mode=mode)
    if mode in ('denied', 'cycle'):
        return native.effective_scp(aws.Requests({'retries': 0}), session, REGION, ACCOUNT), stub
    for target in (ACCOUNT, OU, ROOT):
        policy = summary(managed=mode == 'managed')
        stub.add_response('list_policies_for_target', {'Policies': [policy] if target == ROOT and mode != 'empty' else []},
                          {'TargetId': target, 'Filter': 'SERVICE_CONTROL_POLICY'})
        if target == ROOT and mode != 'empty':
            if mode == 'detail_denied':
                stub.add_client_error('describe_policy', 'AccessDeniedException', expected_params={'PolicyId': policy['Id']})
            else:
                detail = copy.deepcopy(policy)
                if mode == 'foreign_detail':
                    detail['Arn'] = detail['Arn'].replace(MASTER, '999999999999')
                content = {'Statement': statements() if mode != 'managed' else [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
                stub.add_response('describe_policy', {'Policy': {'PolicySummary': detail, 'Content': json.dumps(content)}},
                                  {'PolicyId': policy['Id']})
    return native.effective_scp(aws.Requests({'retries': 0}), session, REGION, ACCOUNT), stub


def decision(read, check_id, *, parameters=None, policy=True, kind='organization_effective_scp'):
    org = {'id': ORG['Id'], 'Organization': ORG}
    snapshot = make_snapshot('aws', [SCOPE], [
        {'type': 'organization', 'scope': ACCOUNT + '/global', 'global': True, 'account_id': ACCOUNT,
         'status': 'collected', 'items': [org]},
        {'type': kind, 'scope': ACCOUNT + '/global', 'global': True, 'account_id': ACCOUNT,
         'status': read.status, 'items': read.items},
        {'type': 'organization_account', 'scope': ACCOUNT + '/global', 'global': True, 'account_id': ACCOUNT,
         'status': 'collected', 'items': [{'Id': ACCOUNT, 'Status': 'ACTIVE'}]}])
    approved = {'status': 'collected', 'scope': ACCOUNT + '/global', 'audited_account_ids': [ACCOUNT],
                'allowed_instance_types': ['t3.micro'], 'approved_break_glass_principals': []}
    module = SimpleNamespace(AWS_TYPES={'organization', kind, 'organization_account'},
                             collect=lambda connector, requirements: snapshot)
    options = {'compliance_policy': {'aws_organizations': approved}} if policy else {}
    if parameters:
        options['compliance_parameters'] = parameters
    captured = collect_bulk(module, {'provider': 'aws', 'options': options}, ['organization', kind])
    findings = evaluate_snapshot(captured, checks=[check_id])['findings']
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('mode', ['complete', 'empty', 'denied', 'cycle', 'accounts_denied', 'detail_denied', 'foreign_detail', 'managed'])
def test_inherited_scp_read_and_complete_native_path(sdk, mode):
    read, stub = scp_read(sdk, mode)
    if mode in ('complete', 'empty', 'managed'):
        assert read.status == 'collected'
        row, = read.items
        assert row['ParentPath'] == [ACCOUNT, OU, ROOT]
        assert row['Complete'] is True and row['ScpApplicable'] is True
        assert row['TargetAccountId'] == ACCOUNT
        if mode == 'complete':
            assert row['Policies'][0]['Attachments'][0]['TargetId'] == ROOT
    else:
        assert read.status not in ('collected', 'empty')
    for check_id in ('aws_organizations_restrict_ec2_instance_types', 'aws_organizations_security_service_tamper_scp'):
        # FullAWSAccess alone denies nothing, so the native tamper check fails it.
        expected = 'PASS' if mode == 'complete' else 'FAIL' if mode in ('empty', 'managed') else 'UNKNOWN'
        assert decision(read, check_id) == expected
    stub.assert_no_pending_responses()


def test_missing_approved_policy_remains_unknown(sdk):
    read, stub = scp_read(sdk)
    assert decision(read, 'aws_organizations_restrict_ec2_instance_types', policy=False) == 'UNKNOWN'
    stub.assert_no_pending_responses()


def test_management_account_has_no_scp_protection_claim(sdk):
    session, add = sdk
    stub = add('organizations')
    organization(stub)
    stub.add_response('list_accounts', {'Accounts': [{'Id': MASTER, 'Status': 'ACTIVE'}, {'Id': ACCOUNT, 'Status': 'CLOSED'}]}, {})
    read = native.effective_scp(aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == 'collected' and read.items[0]['ScpApplicable'] is False
    assert read.items[0]['Policies'] == []
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['complete', 'empty', 'denied', 'cycle', 'foreign_summary', 'foreign_detail', 'detail_denied', 'merge', 'wildcard'])
def test_attached_tag_policy_native_literal_projection(sdk, mode):
    session, add = sdk
    stub = add('organizations')
    organization(stub)
    parents(stub, mode=mode)
    if mode not in ('denied', 'cycle'):
        for target in (ACCOUNT, OU, ROOT):
            item = summary('TAG_POLICY')
            if mode == 'foreign_summary':
                item['Arn'] = item['Arn'].replace(MASTER, '999999999999')
            stub.add_response('list_policies_for_target', {'Policies': [item] if target == ACCOUNT and mode != 'empty' else []},
                              {'TargetId': target, 'Filter': 'TAG_POLICY'})
            if target == ACCOUNT and mode != 'empty' and mode != 'foreign_summary':
                if mode == 'detail_denied':
                    stub.add_client_error('describe_policy', 'AccessDeniedException', expected_params={'PolicyId': PID})
                else:
                    detail = copy.deepcopy(item)
                    if mode == 'foreign_detail':
                        detail['Id'] = 'p-foreignid'
                    document = {'tags': {'environment': {'tag_key': {'@@assign': 'Environment'},
                        'tag_value': {'@@append' if mode == 'merge' else '@@assign': ['*' if mode == 'wildcard' else 'Production']}}}}
                    stub.add_response('describe_policy', {'Policy': {'PolicySummary': detail, 'Content': json.dumps(document)}}, {'PolicyId': PID})
            if target == ACCOUNT and mode in ('foreign_summary', 'foreign_detail', 'detail_denied', 'merge', 'wildcard'):
                break
    read = native.tag_policies(aws.Requests({'retries': 0}), session, REGION, ACCOUNT)
    expected = 'PASS' if mode == 'complete' else 'FAIL' if mode == 'empty' else 'DENIED' if mode in ('denied', 'detail_denied') else 'UNKNOWN'
    assert decision(read, 'aws_cis_ec2_tag_policy', parameters={'approved_ec2_tag_values': {'Environment': ['Production']}},
                    kind='organization_tag_policy') == expected
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['complete', 'absent', 'denied', 'foreign_arn'])
def test_organization_resource_policy_exact_typed_absence(sdk, mode):
    session, add = sdk
    stub = add('organizations')
    organization(stub)
    if mode in ('absent', 'denied'):
        stub.add_client_error('describe_resource_policy', 'ResourcePolicyNotFoundException' if mode == 'absent' else 'AccessDeniedException', expected_params={})
    else:
        arn = f'arn:aws:organizations::{MASTER}:resourcepolicy/{ORG["Id"]}/rp-abcdefgh'
        if mode == 'foreign_arn':
            arn = arn.replace(MASTER, '999999999999')
        statement = {'Effect': 'Allow', 'Action': ['organizations:CreatePolicy', 'organizations:UpdatePolicy', 'organizations:AttachPolicy'],
                     'Resource': '*', 'Principal': {'AWS': ACCOUNT}}
        stub.add_response('describe_resource_policy', {'ResourcePolicy': {'ResourcePolicySummary': {'Id': 'rp-abcdefgh', 'Arn': arn},
            'Content': json.dumps({'Statement': [statement]})}}, {})
    read = native.resource_policy(aws.Requests({'retries': 0}), session, REGION, ACCOUNT)
    assert decision(read, 'aws_cis_organizations_policy_management_delegated', kind='organization_resource_policy') == (
        'PASS' if mode == 'complete' else 'FAIL' if mode == 'absent' else 'UNKNOWN')
    stub.assert_no_pending_responses()


def test_complete_collector_preserves_distinct_target_accounts_and_global_policy(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'test-pinned'))
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    stub = add('organizations')
    organization(stub)
    stub.add_response('list_accounts', {'Accounts': [{'Id': MASTER, 'State': 'ACTIVE'}, {'Id': ACCOUNT, 'State': 'ACTIVE'}]}, {})
    parents(stub)
    for target in (ACCOUNT, OU, ROOT):
        policy = summary()
        stub.add_response('list_policies_for_target', {'Policies': [policy] if target == ROOT else []},
                          {'TargetId': target, 'Filter': 'SERVICE_CONTROL_POLICY'})
        if target == ROOT:
            stub.add_response('describe_policy', {'Policy': {'PolicySummary': policy,
                'Content': json.dumps({'Statement': statements()})}}, {'PolicyId': PID})
    options = {'service_concurrency': 1, 'compliance_policy': {'aws_organizations': {
        'status': 'collected', 'scope': ACCOUNT + '/global', 'audited_account_ids': [MASTER, ACCOUNT],
        'allowed_instance_types': ['t3.micro'], 'approved_break_glass_principals': []}}}
    snapshot = collect_bulk(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': options},
                            ['organization', 'organization_effective_scp'])
    envelope, = [row for row in snapshot['collections'] if row['type'] == 'organization_effective_scp']
    assert envelope['status'] == 'collected'
    assert len(envelope['items']) == 2
    assert {row['TargetAccountId'] for row in envelope['items']} == {MASTER, ACCOUNT}
    assert {row['AccountId'] for row in envelope['items']} == {ACCOUNT}
    for check_id in ('aws_organizations_restrict_ec2_instance_types', 'aws_organizations_security_service_tamper_scp'):
        assert evaluate_snapshot(snapshot, checks=[check_id])['findings'][0]['status'] == 'PASS'
    for row in envelope['items']:
        row['ScpApplicable'] = False
    # A member account cannot exempt itself by changing one flag.
    resealed = make_snapshot('aws', snapshot['scopes'], snapshot['collections'], metadata=snapshot['metadata'])
    assert evaluate_snapshot(resealed, checks=['aws_organizations_restrict_ec2_instance_types'])['findings'][0]['status'] == 'UNKNOWN'
    stub.assert_no_pending_responses()
    sts.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['page_limit', 'second_page_denied', 'complete_empty_first'])
def test_parent_pagination_failure_and_empty_page_are_not_absence(sdk, mode):
    session, add = sdk
    stub = add('organizations')
    organization(stub)
    stub.add_response('list_parents', {'Parents': [], 'NextToken': 'next'}, {'ChildId': ACCOUNT})
    if mode == 'second_page_denied':
        stub.add_client_error('list_parents', 'AccessDeniedException', expected_params={'ChildId': ACCOUNT, 'NextToken': 'next'})
    elif mode == 'complete_empty_first':
        stub.add_response('list_parents', {'Parents': [{'Id': ROOT, 'Type': 'ROOT'}]}, {'ChildId': ACCOUNT, 'NextToken': 'next'})
        for target in (ACCOUNT, ROOT):
            stub.add_response('list_policies_for_target', {'Policies': []}, {'TargetId': target, 'Filter': 'TAG_POLICY'})
    read = native.tag_policies(aws.Requests({'retries': 0, **({'max_pages': 1} if mode == 'page_limit' else {})}),
                               session, REGION, ACCOUNT)
    assert (read.status == 'empty') is (mode == 'complete_empty_first')
    stub.assert_no_pending_responses()


def test_shared_requests_cache_keeps_identical_policy_reads_single_flight(sdk):
    session, add = sdk
    stub = add('organizations')
    organization(stub)
    parents(stub)
    for target in (ACCOUNT, OU, ROOT):
        stub.add_response('list_policies_for_target', {'Policies': []}, {'TargetId': target, 'Filter': 'TAG_POLICY'})
    requests = aws.Requests({})
    assert native.tag_policies(requests, session, REGION, ACCOUNT).status == 'empty'
    count = requests.calls
    assert native.tag_policies(requests, session, REGION, ACCOUNT).status == 'empty'
    assert requests.calls == count == 6
    assert requests.cache_hits >= 6
    stub.assert_no_pending_responses()
