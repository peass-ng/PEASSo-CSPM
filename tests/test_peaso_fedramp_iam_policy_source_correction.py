"""Pinned FedRAMP IAM aliases, exercised through the SDK collector and engine."""
from __future__ import annotations

import copy
import json

import boto3
from botocore.stub import Stubber
import pytest

from peaso.collectors import aws
from peaso.collectors.aws_customer_policies import collect
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot
import botocore


ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/global'
LOCAL = f'arn:aws:iam::{ACCOUNT}:policy/FedrampFixture'
AWS_OWNED = 'arn:aws:iam::aws:policy/AdministratorAccess'
ADMIN = 'aws_fedramp_iam_all_policies_no_admin_star'
SERVICE = 'aws_fedramp_iam_all_policies_no_service_wildcard'
SAFE = {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::fixture/object'}]}


def collect_sdk(document=SAFE, *, list_denied=False, version_denied=False, incomplete_page=False):
    session = boto3.Session(aws_access_key_id='synthetic', aws_secret_access_key='synthetic', region_name='us-east-1')
    client = session.client('iam')
    requests = aws.Requests({'concurrency': 1})
    requests.client = lambda *args: client
    with Stubber(client) as stub:
        if list_denied:
            stub.add_client_error('list_policies', service_error_code='AccessDenied',
                                  expected_params={'Scope': 'Local', 'OnlyAttached': False})
        else:
            stub.add_response('list_policies', {
                'Policies': [{'Arn': LOCAL, 'DefaultVersionId': 'v1', 'AttachmentCount': 0}],
                'IsTruncated': incomplete_page, **({'Marker': 'next'} if incomplete_page else {})},
                {'Scope': 'Local', 'OnlyAttached': False})
            if incomplete_page:
                stub.add_client_error('list_policies', service_error_code='AccessDenied',
                                      expected_params={'Scope': 'Local', 'OnlyAttached': False, 'Marker': 'next'})
            if version_denied:
                stub.add_client_error('get_policy_version', service_error_code='AccessDenied',
                                      expected_params={'PolicyArn': LOCAL, 'VersionId': 'v1'})
            else:
                stub.add_response('get_policy_version', {'PolicyVersion': {
                    'VersionId': 'v1', 'IsDefaultVersion': True, 'Document': json.dumps(document)}},
                    {'PolicyArn': LOCAL, 'VersionId': 'v1'})
        read = collect(requests, session, 'us-east-1', ACCOUNT)
        stub.assert_no_pending_responses()
    return read


def evaluate(cid, read, *, aws_library=False, inline=False):
    collections = [{'type': 'iam_customer_policy', 'scope': SCOPE,
                    'status': read.status, 'items': read.items}]
    if aws_library:
        collections.append({'type': 'iam_managed_policy', 'scope': SCOPE, 'status': 'collected', 'items': [{
            'Arn': AWS_OWNED, 'DefaultDocument': {'Document': {'Statement': [
                {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}}]})
    if inline:
        collections.append({'type': 'iam_role', 'scope': SCOPE, 'status': 'collected', 'items': [{
            'Arn': f'arn:aws:iam::{ACCOUNT}:role/Fixture', 'RoleName': 'Fixture',
            'RolePolicyList': [{'PolicyName': 'InlineAdmin', 'PolicyDocument': {'Statement': [
                {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}]}]})
    snapshot = make_snapshot('aws', [SCOPE], collections)
    before = copy.deepcopy(snapshot)
    findings = [f for f in evaluate_snapshot(snapshot, checks=[cid])['findings'] if f['check_id'] == cid]
    assert snapshot == before
    assert len(findings) == 1
    return findings[0]['status']


def test_plan_collects_only_customer_policies():
    for cid in (ADMIN, SERVICE):
        plan = plan_collection({'connector': {'provider': 'aws'}, 'checks': [cid]})
        assert 'iam_customer_policy' in plan
        assert 'iam_managed_policy' not in plan
        assert not {'iam_policy', 'iam_user', 'iam_group', 'iam_role'} & set(plan)


@pytest.mark.parametrize('cid', [ADMIN, SERVICE])
def test_sdk_collector_to_engine_customer_only_and_incomplete(cid):
    assert evaluate(cid, collect_sdk()) == 'PASS'
    matching = {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
    assert evaluate(cid, collect_sdk(matching)) == 'FAIL'  # Unattached Local policy is in source scope.
    assert evaluate(cid, collect_sdk(), aws_library=True) == 'PASS'
    assert evaluate(cid, collect_sdk(), inline=True) == 'PASS'
    assert evaluate(cid, collect_sdk(list_denied=True)) in {'UNKNOWN', 'DENIED'}
    assert evaluate(cid, collect_sdk(version_denied=True)) in {'UNKNOWN', 'DENIED'}
    assert evaluate(cid, collect_sdk(incomplete_page=True)) in {'UNKNOWN', 'DENIED'}


def test_pinned_policy_std_literal_action_resource_and_declared_shape():
    scoped = {'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': 'arn:aws:s3:::fixture/*'}]}
    assert evaluate(ADMIN, collect_sdk(scoped)) == 'PASS'
    assert evaluate(SERVICE, collect_sdk(scoped)) == 'PASS'
    service = {'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject', 'S3:*'], 'Resource': ['*']}]}
    assert evaluate(ADMIN, collect_sdk(service)) == 'PASS'
    assert evaluate(SERVICE, collect_sdk(service)) == 'FAIL'
    declared = {'Statement': [
        {'Effect': 'Allow', 'Action': '*:*', 'Resource': '*',
         'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}},
        {'Effect': 'Deny', 'Action': 's3:DeleteObject', 'Resource': 'arn:aws:s3:::fixture/*'}]}
    assert evaluate(ADMIN, collect_sdk(declared)) == 'FAIL'
    assert evaluate(SERVICE, collect_sdk(declared)) == 'FAIL'
