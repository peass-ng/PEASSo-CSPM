"""Bounded SDK/GAAD and immutable-engine tests; no live AWS or new registration."""
import copy
import importlib
import json
from urllib.parse import quote

import pytest
from peaso import engine
from peaso.collectors import aws
from peaso.checks import aws_lambda_role_policy_review_20261019 as check

ACCOUNT, REGION = '123456789012', 'us-east-1'
ROLE = f'arn:aws:iam::{ACCOUNT}:role/review'
POLICY = f'arn:aws:iam::{ACCOUNT}:policy/review'


def fixture(admin=False):
    value = check.RUNTIME_CASES[check.CHECK_ID]
    return copy.deepcopy((value['fail'], value['fail_index']) if admin else (value['pass'], value['pass_index']))


def principal(index):
    return index['collections']['iam_role'][0]['items'][0]


def statement(index):
    return principal(index)['RolePolicyList'][0]['PolicyDocument']['Statement'][0]


def managed(index, *, admin=False, aws_managed=False):
    arn = 'arn:aws:iam::aws:policy/AdministratorAccess' if aws_managed else POLICY
    row = {'Arn': arn, 'AccountId': ACCOUNT, 'DefaultVersionId': 'v2', 'PolicyVersionList': [
        {'VersionId': 'v1', 'IsDefaultVersion': False, 'Document': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}},
        {'VersionId': 'v2', 'IsDefaultVersion': True, 'Document': {'Statement': [{'Effect': 'Allow', 'Action': '*' if admin else 's3:GetObject', 'Resource': '*'}]}}]}
    role = principal(index)
    role['AttachedManagedPolicies'] = [{'PolicyArn': arn, 'PolicyName': 'AdministratorAccess' if aws_managed else 'review'}]
    envelope = index['collections']['iam_policy'][0]
    envelope.update(status='collected', items=[row])
    index['iam_policy'] = [{'data': row}]
    return row


@pytest.mark.parametrize('admin', [False, True])
def test_runtime_cases(admin):
    item, index = fixture(admin)
    before = copy.deepcopy((item, index))
    status, evidence = check.evaluate(item, index)
    assert status == ('FAIL' if admin else 'PASS')
    assert len(evidence['observed']) <= 150
    assert (item, index) == before
    assert 'effective access' in evidence['observed']


@pytest.mark.parametrize('actions', ['*', '*:*', ['s3:GetObject', '*'], ['*:*']])
def test_literal_action_variants(actions):
    item, index = fixture()
    statement(index)['Action'] = actions
    assert check.evaluate(item, index)[0] == 'FAIL'


@pytest.mark.parametrize('change,expected', [
    ({'Effect': 'Deny', 'Action': '*'}, 'PASS'),
    ({'Action': 'iam:*'}, 'PASS'),
    ({'Action': '*', 'Resource': 'arn:aws:s3:::review/*'}, 'PASS'),
    ({'Action': '*', 'Resource': ['arn:aws:s3:::review/*', '*']}, 'FAIL'),
])
def test_narrow_pattern_scope(change, expected):
    item, index = fixture()
    statement(index).update(change)
    assert check.evaluate(item, index)[0] == expected


def test_condition_visible_without_values_and_deny_not_effective_subtraction():
    item, index = fixture(True)
    statement(index)['Condition'] = {'StringEquals': {'aws:PrincipalTag/Review': 'SYNTHETIC_CONDITION_VALUE'}}
    principal(index)['RolePolicyList'][0]['PolicyDocument']['Statement'].append({'Effect': 'Deny', 'Action': '*', 'Resource': '*'})
    status, evidence = check.evaluate(item, index)
    assert status == 'FAIL' and evidence['declared_admin_patterns'][0]['condition_present'] is True
    assert 'SYNTHETIC_CONDITION_VALUE' not in json.dumps(evidence)
    assert '"Condition":' not in json.dumps(evidence)


@pytest.mark.parametrize('selector', ['NotAction', 'NotResource'])
def test_negative_selector_limitation_is_explicit(selector):
    item, index = fixture()
    row = statement(index)
    row.pop('Action' if selector == 'NotAction' else 'Resource')
    row[selector] = 'iam:DeleteUser' if selector == 'NotAction' else 'arn:aws:s3:::review/*'
    status, evidence = check.evaluate(item, index)
    assert status == 'PASS'
    assert evidence['not_action_statements_unexpanded' if selector == 'NotAction' else 'not_resource_statements_unexpanded'] == 1
    assert 'NotAction/NotResource' in evidence['semantics']


@pytest.mark.parametrize('aws_managed', [False, True])
@pytest.mark.parametrize('admin', [False, True])
def test_attached_default_policy_not_name_or_nondefault(aws_managed, admin):
    item, index = fixture()
    managed(index, admin=admin, aws_managed=aws_managed)
    assert check.evaluate(item, index)[0] == ('FAIL' if admin else 'PASS')


@pytest.mark.parametrize('mutation', ['missing_join', 'duplicate_join', 'two_defaults', 'no_default', 'wrong_default_id', 'missing_version_id', 'missing_document', 'foreign_attachment', 'foreign_partition', 'duplicate_attachment'])
def test_managed_join_errors_unknown(mutation):
    item, index = fixture(True)  # Known inline match cannot hide incomplete attached evidence.
    policy = managed(index)
    envelope = index['collections']['iam_policy'][0]
    if mutation == 'missing_join': envelope['items'] = []
    if mutation == 'duplicate_join': envelope['items'].append(copy.deepcopy(policy))
    if mutation == 'two_defaults': policy['PolicyVersionList'][0]['IsDefaultVersion'] = True
    if mutation == 'no_default': policy['PolicyVersionList'][1]['IsDefaultVersion'] = False
    if mutation == 'wrong_default_id': policy['DefaultVersionId'] = 'v3'
    if mutation == 'missing_version_id': policy['PolicyVersionList'][1].pop('VersionId')
    if mutation == 'missing_document': policy['PolicyVersionList'][1].pop('Document')
    if mutation == 'foreign_attachment': principal(index)['AttachedManagedPolicies'][0]['PolicyArn'] = POLICY.replace(ACCOUNT, '999999999999')
    if mutation == 'foreign_partition': principal(index)['AttachedManagedPolicies'][0]['PolicyArn'] = POLICY.replace('arn:aws:', 'arn:aws-cn:')
    if mutation == 'duplicate_attachment': principal(index)['AttachedManagedPolicies'].append(copy.deepcopy(principal(index)['AttachedManagedPolicies'][0]))
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['lambda_function', 'iam_role', 'iam_policy'])
@pytest.mark.parametrize('status', ['denied', 'partial', 'not_collected', 'malformed'])
def test_dependency_status_requires_complete(kind, status):
    item, index = fixture(True)
    index['collections'][kind][0]['status'] = status
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mutation', ['foreign_function', 'foreign_region', 'foreign_role', 'foreign_role_inventory', 'foreign_policy_inventory', 'role_missing', 'role_duplicate', 'function_duplicate', 'stale_function', 'role_name', 'provider', 'context_account'])
def test_native_identity_and_membership(mutation):
    item, index = fixture()
    if mutation == 'foreign_function': item['FunctionArn'] = item['FunctionArn'].replace(ACCOUNT, '999999999999')
    if mutation == 'foreign_region': item['FunctionArn'] = item['FunctionArn'].replace(REGION, 'eu-west-1')
    if mutation == 'foreign_role': item['Role'] = ROLE.replace(ACCOUNT, '999999999999')
    if mutation == 'foreign_role_inventory': index['collections']['iam_role'][0]['scope'] = '999999999999/global'
    if mutation == 'foreign_policy_inventory': index['collections']['iam_policy'][0]['scope'] = '999999999999/global'
    if mutation == 'role_missing': index['collections']['iam_role'][0]['items'] = []
    if mutation == 'role_duplicate': index['collections']['iam_role'][0]['items'].append(copy.deepcopy(principal(index)))
    if mutation == 'function_duplicate': index['collections']['lambda_function'][0]['items'].append(copy.deepcopy(item))
    if mutation == 'stale_function':
        item = copy.deepcopy(item)
        item['Role'] += '-stale'
    if mutation == 'role_name': principal(index)['RoleName'] = 'foreign'
    if mutation == 'provider': index['context']['provider'] = 'gcp'
    if mutation == 'context_account': index['context']['Account'] = '999999999999'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field', ['RolePolicyList', 'AttachedManagedPolicies'])
def test_gaad_omission_requires_native_provenance(field):
    item, index = fixture()
    principal(index).pop(field)
    assert check.evaluate(item, index)[0] == 'PASS'
    principal(index).pop('_provenance')
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field', ['Action', 'Resource', 'Effect', 'Condition'])
def test_denied_statement_member_unknown(field):
    item, index = fixture()
    statement(index)['_coverage'] = {field: {'status': 'denied'}}
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('malformed', [None, {}, {'Statement': 'invalid'}, {'Statement': [{'Effect': 'Allow', 'Action': '*'}]}, {'Statement': [{'Effect': 'invalid', 'Action': '*', 'Resource': '*'}]}])
def test_malformed_documents_unknown(malformed):
    item, index = fixture()
    principal(index)['RolePolicyList'][0]['PolicyDocument'] = malformed
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_complete_empty_policy_set_and_empty_statements_pass():
    item, index = fixture()
    principal(index)['RolePolicyList'][0]['PolicyDocument']['Statement'] = []
    assert check.evaluate(item, index)[0] == 'PASS'
    principal(index)['RolePolicyList'] = []
    assert check.evaluate(item, index)[0] == 'PASS'


@pytest.fixture
def sdk(monkeypatch):
    import boto3
    from botocore.stub import Stubber
    session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name=REGION)
    clients = {service: session.client(service, region_name=REGION) for service in ('lambda', 'iam')}
    stubs = {service: Stubber(client) for service, client in clients.items()}
    for stub in stubs.values(): stub.activate()
    monkeypatch.setattr(aws.Requests, 'client', lambda self, selected, service, region: clients[service])
    requests = aws.Requests({'retry_attempts': 1})
    yield requests, session, stubs
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def collect(sdk, *, admin=False, omit_lists=False, attached=True, direct_admin=False):
    requests, session, stubs = sdk
    item, index = fixture(admin)
    if attached: managed(index, admin=admin, aws_managed=direct_admin)
    role = copy.deepcopy(principal(index))
    role.pop('_provenance')
    role.pop('AccountId')
    for policy in role.get('RolePolicyList', []):
        policy['PolicyDocument'] = quote(json.dumps(policy['PolicyDocument']))
    policies = copy.deepcopy(index['collections']['iam_policy'][0]['items'])
    for policy in policies:
        policy.pop('AccountId')
        for version in policy['PolicyVersionList']:
            version['Document'] = quote(json.dumps(version['Document']))
    if omit_lists:
        role.pop('RolePolicyList')
        role.pop('AttachedManagedPolicies')
    stubs['lambda'].add_response('list_functions', {'Functions': [item]}, {})
    stubs['iam'].add_response('get_account_authorization_details', {'RoleDetailList': [role], 'Policies': policies, 'IsTruncated': False}, {})
    functions = requests.pages(session, 'lambda', REGION, 'list_functions', 'Functions')
    facts = aws._iam(requests, session, REGION, {'iam_role', 'iam_policy'})
    for kind, read in facts.items():
        # Production collect.append stamps verified STS AccountId before
        # global IAM inventories enter the snapshot/scoped engine index.
        for row in read.items:
            row['AccountId'] = ACCOUNT
        index['collections'][kind][0].update(items=read.items, status=read.status)
        index[kind] = [{'data': row} for row in read.items]
    item = functions.items[0]
    index['collections']['lambda_function'][0]['items'] = [item]
    index['lambda_function'] = [{'data': item}]
    return item, index


@pytest.mark.parametrize('admin', [False, True])
def test_actual_sdk_collector_to_pure_predicate(sdk, admin):
    requests, session, stubs = sdk
    item, index = collect(sdk, admin=admin)
    assert isinstance(principal(index)['RolePolicyList'][0]['PolicyDocument'], dict)
    assert isinstance(index['collections']['iam_policy'][0]['items'][0]['PolicyVersionList'][1]['Document'], dict)
    assert check.evaluate(item, index)[0] == ('FAIL' if admin else 'PASS')
    assert requests.calls == 2 and requests.cache_hits >= 1


def test_actual_gaad_optional_omissions(sdk):
    item, index = collect(sdk, omit_lists=True, attached=False)
    assert 'RolePolicyList' not in principal(index)
    assert check.evaluate(item, index)[0] == 'PASS'


@pytest.mark.parametrize('admin', [False, True])
def test_snapshot_engine_with_explicit_local_check(sdk, admin, monkeypatch):
    from peaso.checks import Check
    from peaso.snapshot import make_snapshot
    item, index = collect(sdk, admin=admin)
    declaration = check.DECLARATIONS[0]
    native = Check(check.CHECK_ID, 'aws', declaration['category'], 'lambda_function', declaration['title'],
                   'high', declaration['control'], declaration['remediation'], check.evaluate,
                   'resource', tuple(declaration['dependencies']))
    monkeypatch.setattr(engine, '_registry', lambda: [native])
    snapshot = make_snapshot('aws', [ACCOUNT+'/'+REGION], aws._safe(sum(index['collections'].values(), [])), created_at='2026-10-19T00:00:00Z')
    findings = [row for row in engine.evaluate_snapshot(snapshot, checks=[check.CHECK_ID])['findings'] if row['check_id'] == check.CHECK_ID]
    assert len(findings) == 1 and findings[0]['status'] == ('FAIL' if admin else 'PASS'), findings


def test_exports_are_unregistered_and_reuse_pure_helpers():
    from peaso.checks import aws_bedrock_review_20261019 as bedrock
    before = {row.id for row in engine._registry()}
    importlib.reload(check)
    assert {row.id for row in engine._registry()} == before
    assert check._documents is bedrock._documents and check._policy_document is bedrock._policy_document
    admission = check.ADMISSION_DATA['checks'][0]
    assert admission['requirements'] == []
    assert check.DECLARATIONS[0]['dependencies'] == ['lambda_function', 'iam_role', 'iam_policy']
    assert 'EffectiveAdminAccess' not in admission['spec']['data_source']


LEGACY_ID = 'aws_cis_lambda_execution_role_no_admin'


def legacy(item, index):
    # The old signed evaluator requires authoritative typed wrapper parity.
    index = copy.deepcopy(index)
    for kind, envelopes in index['collections'].items():
        index[kind] = [{'type': kind, 'scope': envelope['scope'], 'data': row}
                       for envelope in envelopes for row in envelope['items']]
    return next(row for row in engine._registry() if row.id == LEGACY_ID).evaluate(item, index)


@pytest.mark.parametrize('branch,expected', [('narrow', 'PASS'), ('direct_aws_admin', 'FAIL'), ('custom_star', 'UNKNOWN')])
def test_legacy_actual_sdk_native_branches(sdk, branch, expected):
    item, index = collect(sdk, admin=branch != 'narrow', direct_admin=branch == 'direct_aws_admin')
    status, evidence = legacy(item, index)
    assert status == expected
    assert len(evidence['observed']) <= 150
    assert 'EffectiveAdminAccess' not in json.dumps(index)


@pytest.mark.parametrize('selector,value,expected', [
    ('Action', 'IAM:CREATEROLE', 'UNKNOWN'),
    ('Action', 'i?m:Create*', 'UNKNOWN'),
    ('Action', 'iam:*', 'UNKNOWN'),
    ('Action', 's3:*', 'PASS'),
    ('Action', 'sts:AssumeRole', 'PASS'),
    ('NotAction', 'IAM:CREATEROLE', 'PASS'),
    ('NotAction', 'iam:*', 'PASS'),
    ('NotAction', 'logs:*', 'UNKNOWN'),
    ('NotAction', 'iam:[Cc]reateRole', 'UNKNOWN'),
])
def test_legacy_necessary_action_only(selector, value, expected):
    item, index = fixture()
    row = statement(index)
    row.pop('Action')
    row[selector] = value
    status, evidence = legacy(item, index)
    assert status == expected
    if expected == 'PASS': assert 'escalation is unassessed' in evidence['observed']


def test_legacy_synthetic_fact_ignored_and_custom_allow_deny_unresolved():
    item, index = fixture()
    principal(index)['EffectiveAdminAccess'] = {'collection_status': 'collected', 'complete': True,
        'role_arn': ROLE, 'unconditional_action_resource_star': True}
    assert legacy(item, index)[0] == 'PASS'
    statement(index)['Action'] = '*'
    principal(index)['RolePolicyList'][0]['PolicyDocument']['Statement'].append({'Effect': 'Deny', 'Action': 'iam:CreateRole', 'Resource': '*'})
    assert legacy(item, index)[0] == 'UNKNOWN'
    principal(index)['RolePolicyList'][0].pop('PolicyDocument')
    assert legacy(item, index)[0] == 'UNKNOWN'


def test_legacy_aws_admin_exact_arn_or_branch_and_missing_documents():
    item, index = fixture()
    principal(index)['AttachedManagedPolicies'] = [{'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]
    principal(index)['RolePolicyList'][0].pop('PolicyDocument')
    assert legacy(item, index)[0] == 'FAIL'  # Signed explicit attachment OR, not effective-access proof.
    principal(index)['AttachedManagedPolicies'][0]['PolicyArn'] = f'arn:aws:iam::{ACCOUNT}:policy/AdministratorAccess'
    assert legacy(item, index)[0] == 'UNKNOWN'


def test_legacy_default_managed_policy_join_and_dependency():
    item, index = fixture()
    policy = managed(index)
    assert legacy(item, index)[0] == 'PASS'
    policy['PolicyVersionList'][1]['Document']['Statement'][0]['Action'] = '*'
    assert legacy(item, index)[0] == 'UNKNOWN'
    policy['PolicyVersionList'][1].pop('Document')
    assert legacy(item, index)[0] == 'UNKNOWN'
    registered = next(row for row in engine._registry() if row.id == LEGACY_ID)
    assert registered.dependencies == ['lambda_function', 'iam_role', 'iam_policy']


@pytest.mark.parametrize('kind', ['lambda_function', 'iam_role', 'iam_policy'])
def test_native_row_account_binding(kind):
    item, index = fixture()
    if kind == 'iam_policy': managed(index)
    index['collections'][kind][0]['items'][0]['AccountId'] = '999999999999'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['iam_role', 'iam_policy'])
def test_contradictory_iam_global_marker(kind):
    item, index = fixture()
    index['collections'][kind][0]['global'] = False
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_duplicate_managed_version_identity_unknown():
    item, index = fixture()
    policy = managed(index)
    policy['PolicyVersionList'][0]['VersionId'] = 'v2'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('actions', ['invalid', ['iam:GetRole', 'not-an-action'], 'iam:[Cc]reateRole'])
def test_malformed_action_syntax_unknown(actions):
    item, index = fixture()
    statement(index)['Action'] = actions
    assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_malformed_native_role_name_unknown():
    item, index = fixture()
    item['Role'] = ROLE.replace('/review', '/invalid:role')
    principal(index).update(Arn=item['Role'], RoleName='invalid:role')
    assert check.evaluate(item, index)[0] == 'UNKNOWN'
