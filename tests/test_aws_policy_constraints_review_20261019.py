"""Independent boundary cases for proposed read-only policy guardrails."""
import copy
import importlib

import pytest

from peaso.checks import CHECKS
from peaso.checks.aws_policy_constraints_review_20261019 import ADMISSION_DATA, DECLARATIONS, ROLES_ID, RUNTIME_CASES, SECRETS_ID, SOURCE_MAPPINGS, SPECS, _full_access, rolesanywhere_session_constraints, secrets_explicit_principal_deny

ACCOUNT = '123456789012'
REGION = 'us-east-1'
ROLE_ARN = f'arn:aws:iam::{ACCOUNT}:role/Reader'
POLICY_ARN = f'arn:aws:iam::{ACCOUNT}:policy/Scoped'
SECRET_ARN = f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:demo-abc123'
ADMIN = {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
SCOPED = {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}


def context():
    return {'context': {'provider': 'aws', 'scope': f'{ACCOUNT}/{REGION}'}}


def secret(policy=None, **detail):
    return {'ARN': SECRET_ARN, 'Policy': {'collection_status': 'collected',
            **({'ResourcePolicy': policy} if policy is not None else {}), **detail}}


def deny(**changes):
    return {'Effect': 'Deny', 'Principal': '*', 'Action': 'secretsmanager:*',
            'Resource': '*', 'Condition': {'StringNotEquals': {'aws:PrincipalArn': ROLE_ARN}}, **changes}


def profile(**changes):
    return {'profileArn': f'arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:profile/p',
            'enabled': True, 'SessionPolicy': None, 'managedPolicyArns': [],
            'roleArns': [ROLE_ARN], **changes}


def role(document=None, **changes):
    return {'Arn': ROLE_ARN, 'AttachedManagedPolicies': [],
            'RolePolicyList': [{'PolicyName': 'Local', 'PolicyDocument': document or ADMIN}],
            '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails', 'native_response_complete': True}, **changes}


def inventory(roles=None, policies=None):
    index = context()
    index['collections'] = {}
    for kind, rows in [('iam_role', [role()] if roles is None else roles), ('iam_policy', [] if policies is None else policies)]:
        index[kind] = [{'data': row} for row in rows]
        index['collections'][kind] = [{'status': 'collected' if rows else 'empty'}]
    return index


def policy(document, arn=POLICY_ARN):
    return {'Arn': arn, 'PolicyVersionList': [{'IsDefaultVersion': True, 'Document': document}]}


@pytest.mark.parametrize('statement', [deny(), deny(Principal={'AWS': ['*']}),
    deny(Resource=SECRET_ARN), deny(Resource=SECRET_ARN[:-6] + '*'),
    deny(Condition={'ArnNotEquals': {'AWS:PrincipalARN': [ROLE_ARN]}})])
def test_secret_canonical_guardrail_passes(statement):
    status, evidence = secrets_explicit_principal_deny(secret({'Statement': [statement]}), context())
    assert status == 'PASS'
    assert evidence['exceptions_approved'] is False
    assert evidence['exception_count'] == 1
    assert evidence['observed'].startswith('Secret policy denies Secrets Manager access except ')


@pytest.mark.parametrize('document', [None, {'Statement': [
    {'Effect': 'Allow', 'Principal': '*', 'Action': 'secretsmanager:GetSecretValue', 'Resource': '*'}]},
    {'Statement': [deny(Action='secretsmanager:GetSecretValue')]},
    {'Statement': [deny(Resource=SECRET_ARN + 'other')]}])
def test_secret_known_missing_canonical_guardrail_fails(document):
    assert secrets_explicit_principal_deny(secret(document), context())[0] == 'FAIL'


@pytest.mark.parametrize('statement', [
    deny(Condition={'StringNotEqualsIfExists': {'aws:PrincipalArn': ROLE_ARN,
                                              'aws:PrincipalServiceName': 'lambda.amazonaws.com'},
                    'Null': {'aws:PrincipalArn': 'true', 'aws:PrincipalServiceName': 'true'}}),
    deny(Condition={'ArnNotLike': {'aws:PrincipalArn': ROLE_ARN + '*'}}),
    deny(Condition={'StringNotEquals': {'aws:PrincipalArn': ROLE_ARN.replace(ACCOUNT, '999999999999')}}),
    deny(Condition={'StringNotEquals': {'aws:PrincipalArn': ROLE_ARN + '?'}}),
    deny(Condition={'StringNotEquals': {'aws:PrincipalArn': ROLE_ARN}, 'Bool': {'aws:SecureTransport': 'false'}}),
])
def test_secret_unsupported_shapes_never_claim_restriction(statement):
    assert secrets_explicit_principal_deny(secret({'Statement': [statement]}), context())[0] == 'UNKNOWN'


def test_upstream_dual_null_deny_is_false_for_signed_iam_request():
    request = {'aws:principalarn': ROLE_ARN.replace('Reader', 'Unexpected')}
    nulls = {'aws:principalarn': 'true', 'aws:principalservicename': 'true'}
    # IAM ANDs distinct keys/operators; Null=true tests key absence.
    null_block_matches = all((key not in request) == (value == 'true') for key, value in nulls.items())
    assert not null_block_matches
    assert request['aws:principalarn'] != ROLE_ARN


@pytest.mark.parametrize('detail', [{'collection_status': 'denied'}, {'collection_status': 'partial'},
    {'ResourcePolicy': {'collection_status': 'malformed'}},
    {'_coverage': {'ResourcePolicy': {'status': 'denied'}}}])
def test_unreadable_secret_policy_is_unknown(detail):
    assert secrets_explicit_principal_deny(secret(**detail), context())[0] == 'UNKNOWN'


def test_foreign_secret_cannot_use_local_context():
    item = secret({'Statement': [deny()]})
    item['ARN'] = SECRET_ARN.replace(ACCOUNT, '999999999999')
    assert secrets_explicit_principal_deny(item, context())[0] == 'UNKNOWN'


def test_iam_resource_glob_does_not_treat_brackets_as_character_classes():
    document = {'Statement': [deny(Resource=SECRET_ARN[:-1] + '[3]')]}
    assert secrets_explicit_principal_deny(secret(document), context())[0] == 'FAIL'


def test_roles_enabled_unscoped_admin_fails_and_disabled_passes_without_iam():
    status, evidence = rolesanywhere_session_constraints(profile(), inventory())
    assert status == 'FAIL'
    assert '1 role(s)' in evidence['observed']
    assert rolesanywhere_session_constraints(profile(enabled=False), context())[0] == 'PASS'


def test_roles_scoped_inline_policy_passes_without_iam_role_reads():
    assert rolesanywhere_session_constraints(profile(SessionPolicy=SCOPED), context())[0] == 'PASS'


def test_roles_managed_session_documents_are_union_not_intersection():
    policies = [policy(SCOPED), policy(ADMIN, POLICY_ARN + 'Admin')]
    item = profile(managedPolicyArns=[POLICY_ARN, POLICY_ARN + 'Admin'])
    assert rolesanywhere_session_constraints(item, inventory(policies=policies))[0] == 'FAIL'


def test_roles_deny_in_different_document_constrains_broad_session_allow():
    denial = {'Statement': [{'Effect': 'Deny', 'Action': 'iam:CreateRole', 'Resource': '*'}]}
    item = profile(SessionPolicy=ADMIN, managedPolicyArns=[POLICY_ARN])
    assert rolesanywhere_session_constraints(item, inventory(policies=[policy(denial)]))[0] == 'PASS'


def test_roles_scoped_identity_policy_is_not_administrative():
    assert rolesanywhere_session_constraints(profile(), inventory(roles=[role(SCOPED)]))[0] == 'PASS'


def test_role_boundary_intersects_identity_grants():
    admin_role = role(PermissionsBoundary={'PermissionsBoundaryArn': POLICY_ARN})
    assert rolesanywhere_session_constraints(profile(), inventory(roles=[admin_role], policies=[policy(SCOPED)]))[0] == 'PASS'
    assert rolesanywhere_session_constraints(profile(), inventory(roles=[admin_role], policies=[policy(ADMIN)]))[0] == 'FAIL'


def test_administrator_access_arn_recognized_in_actual_partition():
    admin = f'arn:aws:iam::aws:policy/AdministratorAccess'
    admin_role = role(RolePolicyList=[], AttachedManagedPolicies=[{'PolicyArn': admin}])
    assert rolesanywhere_session_constraints(profile(), inventory(roles=[admin_role]))[0] == 'FAIL'
    item = profile(managedPolicyArns=['arn:aws-cn:iam::aws:policy/AdministratorAccess'])
    assert rolesanywhere_session_constraints(item, inventory())[0] == 'UNKNOWN'


@pytest.mark.parametrize('change', [
    {'SessionPolicy': 'not JSON'}, {'SessionPolicy': {'Statement': []}},
    {'managedPolicyArns': [POLICY_ARN]}, {'managedPolicyArns': None}, {'enabled': 'true'},
])
def test_unresolved_session_inputs_remain_unknown(change):
    assert rolesanywhere_session_constraints(profile(**change), inventory())[0] == 'UNKNOWN'


def test_condition_guarded_admin_or_deny_does_not_create_false_pass():
    guarded_allow = copy.deepcopy(ADMIN)
    guarded_allow['Statement'][0]['Condition'] = {'StringEquals': {'aws:PrincipalTag/Team': 'Prod'}}
    assert rolesanywhere_session_constraints(profile(SessionPolicy=guarded_allow), inventory())[0] == 'UNKNOWN'
    guarded_deny = {'Effect': 'Deny', 'Action': '*', 'Resource': '*', 'Condition': {'Bool': {'aws:SecureTransport': 'false'}}}
    assert _full_access([{'Statement': ADMIN['Statement'] + [guarded_deny]}]) is None


def test_missing_role_or_incomplete_dependencies_remain_unknown():
    assert rolesanywhere_session_constraints(profile(), inventory(roles=[]))[0] == 'UNKNOWN'
    data = inventory()
    data['collections']['iam_role'] = [{'status': 'partial'}]
    assert rolesanywhere_session_constraints(profile(), data)[0] == 'UNKNOWN'
    data = inventory(roles=[role()])
    data['iam_role'][0]['data'].pop('_provenance')
    assert rolesanywhere_session_constraints(profile(), data)[0] == 'UNKNOWN'


def test_one_proven_admin_role_fails_even_if_other_role_unresolved():
    assert rolesanywhere_session_constraints(profile(roleArns=[ROLE_ARN, ROLE_ARN + 'Missing']), inventory())[0] == 'FAIL'


def test_inputs_are_unchanged_and_policy_values_not_in_evidence():
    item, index = secret({'Statement': [deny()]}), context()
    original = copy.deepcopy((item, index))
    status, evidence = secrets_explicit_principal_deny(item, index)
    assert (item, index) == original
    assert ROLE_ARN not in str(evidence)
    item, index = profile(), inventory()
    original = copy.deepcopy((item, index))
    rolesanywhere_session_constraints(item, index)
    assert (item, index) == original


def test_proposals_have_exact_partial_source_mapping_and_no_registration_side_effects():
    before = {check.id for check in CHECKS}
    importlib.reload(importlib.import_module('peaso.checks.aws_policy_constraints_review_20261019'))
    assert {check.id for check in CHECKS} == before
    assert {d['id'] for d in DECLARATIONS} == {SECRETS_ID, ROLES_ID}
    assert all(mapping['decision'] == 'PARTIAL' for mapping in SOURCE_MAPPINGS.values())
    assert all(spec['cloud_calls_at_evaluation'] == 0 for spec in SPECS.values())
    for entry in ADMISSION_DATA['checks']:
        assert entry['requirements'] == []
        assert entry['sources'][0]['sha256']
        assert entry['function'].startswith('peaso.checks.aws_policy_constraints_review_20261019:')


@pytest.mark.parametrize('cid,function', [(SECRETS_ID, secrets_explicit_principal_deny),
                                         (ROLES_ID, rolesanywhere_session_constraints)])
def test_exported_runtime_cases_are_evaluable_with_complete_native_envelopes(cid, function):
    case = RUNTIME_CASES[cid]
    assert function(case['pass'], case['pass_index'])[0] == 'PASS'
    assert function(case['fail'], case['fail_index'])[0] == 'FAIL'
    assert function(case['missing'], case['pass_index'])[0] == 'UNKNOWN'
    assert function(case['malformed'], case['pass_index'])[0] == 'UNKNOWN'
    for key in ('pass_index', 'fail_index'):
        assert all(row['scope'] == ACCOUNT + '/' + REGION and row['status'] in {'collected', 'empty'}
                   for rows in case[key]['collections'].values() for row in rows)


@pytest.fixture
def profile_reader(monkeypatch):
    boto3 = pytest.importorskip('boto3')
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name=REGION)
    client = session.client('rolesanywhere', region_name=REGION)
    monkeypatch.setattr(aws.Requests, 'client', lambda *_args: client)
    reader = aws.Requests({'retry_attempts': 1})
    with Stubber(client) as stub:
        yield session, client, stub, reader
        stub.assert_no_pending_responses()


def native_profile(**changes):
    return {'profileArn': f'arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:profile/11111111-2222-3333-4444-555555555555',
            'enabled': True, 'roleArns': [ROLE_ARN], **changes}


def test_profile_collector_successful_optional_omission_has_proof_and_uses_cache(profile_reader):
    from peaso.collectors import aws_facts_ext as ext
    session, client, stub, reader = profile_reader
    stub.add_response('list_profiles', {'profiles': [native_profile()]}, {})
    read = ext.FETCHERS['rolesanywhere_profile'](reader, session, REGION, ACCOUNT)
    assert read.status == 'collected'
    item = read.items[0]
    assert item['managedPolicyArns'] == []
    assert item['_coverage']['managedPolicyArns'] == {
        'status': 'empty', 'reason': 'documented_optional_api_omission',
        'source_operation': 'rolesanywhere:ListProfiles', 'native_member_present': False}
    assert item['SessionPolicy'] is None
    assert rolesanywhere_session_constraints(item, inventory())[0] == 'FAIL'
    # The projection must not modify the raw cached SDK response or duplicate a call.
    cached = reader.pages(session, 'rolesanywhere', REGION, 'list_profiles', 'profiles')
    assert 'managedPolicyArns' not in cached.items[0]
    again = ext.FETCHERS['rolesanywhere_profile'](reader, session, REGION, ACCOUNT)
    assert again.items == read.items
    assert reader.calls == 1 and reader.cache_hits >= 2


def test_profile_collector_preserves_explicit_managed_array(profile_reader):
    from peaso.collectors import aws_facts_ext as ext
    session, client, stub, reader = profile_reader
    stub.add_response('list_profiles', {'profiles': [native_profile(managedPolicyArns=[POLICY_ARN])]}, {})
    read = ext.FETCHERS['rolesanywhere_profile'](reader, session, REGION, ACCOUNT)
    assert read.status == 'collected'
    assert read.items[0]['managedPolicyArns'] == [POLICY_ARN]
    assert 'managedPolicyArns' not in read.items[0].get('_coverage', {})


@pytest.mark.parametrize('managed', [None, {}, 'not-an-array', [42], ['not-an-arn']])
def test_profile_collector_rejects_malformed_present_managed_array(profile_reader, monkeypatch, managed):
    from peaso.collectors import aws_facts_ext as ext
    session, client, stub, reader = profile_reader
    # Inject malformed SDK data after botocore's test-response shape validator;
    # the real Requests call, shared Future/cache and pages path still execute.
    monkeypatch.setattr(client, 'list_profiles', lambda **_args: {'profiles': [native_profile(managedPolicyArns=managed)]})
    read = ext.FETCHERS['rolesanywhere_profile'](reader, session, REGION, ACCOUNT)
    assert read.status == 'malformed' and read.items == []
    assert read.error['cause_status'] == 'malformed'


def test_profile_collector_does_not_default_omission_on_partial_read(profile_reader):
    from peaso.collectors import aws_facts_ext as ext
    session, client, stub, reader = profile_reader
    stub.add_response('list_profiles', {'profiles': [native_profile()], 'nextToken': 'next'}, {})
    stub.add_client_error('list_profiles', 'AccessDeniedException', expected_params={'nextToken': 'next'})
    read = ext.FETCHERS['rolesanywhere_profile'](reader, session, REGION, ACCOUNT)
    assert read.status == 'partial'
    assert read.error['cause_status'] == 'denied'
    assert 'managedPolicyArns' not in read.items[0]
    assert rolesanywhere_session_constraints(read.items[0], inventory())[0] == 'UNKNOWN'


def test_profile_collector_preserves_denied_read(profile_reader):
    from peaso.collectors import aws_facts_ext as ext
    session, client, stub, reader = profile_reader
    stub.add_client_error('list_profiles', 'AccessDeniedException', expected_params={})
    read = ext.FETCHERS['rolesanywhere_profile'](reader, session, REGION, ACCOUNT)
    assert read.status == 'denied' and read.items == []
