"""Account-bound KMS policies through frozen public analysis; synthetic identities."""
from copy import deepcopy
import pytest
from peaso.analysis import analyze
from peaso.snapshot import make_snapshot

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
KEY = f'arn:aws:kms:{REGION}:{ACCOUNT}:key/key-1'


def observations(condition, *, service='kms', public_allow=False, conditional_deny=False, dedicated=False):
    arn = KEY if service == 'kms' else f'arn:aws:sns:{REGION}:{ACCOUNT}:fixture'
    statement = {'Effect': 'Allow', 'Principal': {'AWS': '*'},
                 'Action': service + ':*', 'Resource': '*', 'Condition': condition}
    statements = [statement, {'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'},
                             'Action': service + ':Get*', 'Resource': '*'}]
    if public_allow:
        statements.append({'Effect': 'Allow', 'Principal': {'AWS': '*'},
                           'Action': service + ':Decrypt', 'Resource': '*'})
    if conditional_deny:
        statements.append({'Effect': 'Deny', 'Principal': {'AWS': '*'},
                           'Action': 'kms:ReEncrypt*', 'Resource': '*',
                           'Condition': {'Bool': {'kms:ReEncryptOnSameKey': 'false'}}})
    policy = {'Version': '2012-10-17', 'Statement': statements}
    if dedicated:
        kind = 'kms_key'
        data = {'KeyId': 'key-1', 'KeyArn': KEY,
                'Metadata': {'collection_status': 'collected', 'KeyMetadata': {
                    'KeyId': 'key-1', 'Arn': KEY, 'KeyManager': 'CUSTOMER',
                    'KeyUsage': 'ENCRYPT_DECRYPT', 'KeyState': 'Enabled', 'Enabled': True}},
                'Policy': {'collection_status': 'collected', 'Policy': policy}}
        exposure = 'external_kms_decrypt_grant'
    else:
        kind = 'aws_resource_policy'
        data = {'ResourceArn': arn, 'Policy': policy, '_provenance': {
            'read_only': True, 'owner_account': ACCOUNT, 'source_region': REGION,
            'collection_region': REGION, 'families': [service + '-keys' if service == 'kms' else 'sns-base'],
            'source_operations': [service + ':GetKeyPolicy']}}
        exposure = 'external_generic_policy_grant'
    snapshot = make_snapshot('aws', [SCOPE], [{'type': kind, 'scope': SCOPE,
        'service': service, 'status': 'collected', 'items': [data]}])
    return [f for f in analyze(snapshot)['findings'] if f['check_id'] == 'analysis.internet_exposure'
            and f.get('evidence', {}).get('exposure_kind') == exposure]


@pytest.mark.parametrize('dedicated', [False, True])
@pytest.mark.parametrize('extra', [{}, {'StringLike': {'kms:ViaService': 'secretsmanager.*.amazonaws.com'}},
                                   {'Bool': {'kms:GrantIsForAWSResource': 'true'}}])
def test_mandatory_owner_caller_account_excludes_foreign_grants_with_conjunctive_conditions(extra, dedicated):
    condition = {'StringEquals': {'kms:CallerAccount': ACCOUNT}, **deepcopy(extra)}
    assert observations(condition, dedicated=dedicated) == []


def test_owner_bound_allows_remain_local_with_a_conditional_deny():
    condition = {'StringEquals': {'kms:CallerAccount': ACCOUNT, 'kms:ViaService': 'acm.us-east-1.amazonaws.com'},
                 'ForAllValues:StringEquals': {'kms:GrantOperations': ['Decrypt']}}
    assert observations(condition, conditional_deny=True) == []


@pytest.mark.parametrize('condition', [
    {'StringEqualsIfExists': {'kms:CallerAccount': ACCOUNT}},
    {'StringLike': {'kms:CallerAccount': '12345678901*'}},
    {'ForAllValues:StringEquals': {'kms:CallerAccount': ACCOUNT}},
    {'StringEquals': {'kms:CallerAccount': '999999999999'}},
    {'StringEquals': {'kms:CallerAccount': []}},
])
def test_optional_wildcard_vacuous_or_foreign_conditions_never_establish_owner_only_access(condition):
    rows = observations(condition)
    assert rows and all(f['status'] in {'UNKNOWN', 'FAIL'} for f in rows)


def test_service_condition_does_not_establish_a_boundary_on_other_services():
    rows = observations({'StringEquals': {'kms:CallerAccount': ACCOUNT}}, service='sns')
    assert rows and all(f['status'] in {'UNKNOWN', 'FAIL'} for f in rows)


def test_separate_public_allow_still_reports_foreign_exposure():
    rows = observations({'StringEquals': {'kms:CallerAccount': ACCOUNT}}, public_allow=True)
    assert len(rows) == 1 and rows[0]['status'] == 'FAIL'
