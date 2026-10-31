from copy import deepcopy
import json

import pytest

from peaso import unused_iam_aws_federation_consumers as subject

ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/global'
NOW = '2026-10-21T12:00:00Z'


def fixture(kind='iam_saml_provider', bound=False):
    label, action = ('saml-provider', 'sts:AssumeRoleWithSAML') if kind == 'iam_saml_provider' else ('oidc-provider', 'sts:AssumeRoleWithWebIdentity')
    provider = {'Arn': f'arn:aws:iam::{ACCOUNT}:{label}/idp.example.com', 'AccountId': ACCOUNT}
    role = {'RoleName': 'federated-reader', 'RoleId': 'AROA0123456789ABCDE',
            'Arn': f'arn:aws:iam::{ACCOUNT}:role/team/federated-reader',
            'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Action': action, 'Principal': {'Federated': provider['Arn'] if bound else
                    f'arn:aws:iam::{ACCOUNT}:{label}/different'},
                'Condition': {'StringEquals': {'synthetic:aud': 'example'}}}]},
            '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails', 'native_response_complete': True}}
    index = {'context': {'provider': 'aws', 'scope': SCOPE, 'created_at': NOW}, 'collections': {}}
    for resource_kind, items in ((kind, [provider]), ('iam_role', [role])):
        index[resource_kind] = [{'type': resource_kind, 'scope': SCOPE, 'data': row} for row in items]
        index['collections'][resource_kind] = [{'type': resource_kind, 'scope': SCOPE, 'service': 'iam',
                                                  'status': 'collected', 'items': items, 'account_id': ACCOUNT, 'global': True}]
    return provider, role, index


@pytest.mark.parametrize('kind,check', [('iam_saml_provider', subject.SAML_CHECK), ('iam_oidc_provider', subject.OIDC_CHECK)])
@pytest.mark.parametrize('bound', [False, True])
def test_exact_native_role_trust_consumers(kind, check, bound):
    provider, _, index = fixture(kind, bound)
    before = deepcopy(index)
    status, evidence = subject.evaluate(provider, index, check)
    assert status == ('PASS' if bound else 'FAIL'), evidence
    assert len(evidence['summary'].splitlines()) == 3
    assert evidence['role_consumers'] if bound else not evidence['role_consumers']
    assert index == before


@pytest.mark.parametrize('change,expected', [
    ('partial_roles', 'DENIED'), ('missing_roles', 'UNKNOWN'), ('projection', 'UNKNOWN'),
    ('foreign_provider', 'UNKNOWN'), ('foreign_role', 'UNKNOWN'), ('bad_provider_proof', 'UNKNOWN'),
    ('missing_role_proof', 'UNKNOWN'), ('missing_trust', 'UNKNOWN'), ('bad_condition', 'UNKNOWN'),
    ('not_principal', 'UNKNOWN'), ('wildcard_principal', 'UNKNOWN'), ('not_action', 'UNKNOWN'),
    ('wildcard_federated', 'UNKNOWN'), ('wildcard_aws', 'UNKNOWN'), ('duplicate_role', 'UNKNOWN')])
def test_absence_requires_complete_source_bound_trusts(change, expected):
    provider, role, index = fixture()
    source = index['collections']['iam_role'][0]
    statement = role['AssumeRolePolicyDocument']['Statement'][0]
    if change == 'partial_roles': source.update(status='partial', error={'cause_status': 'denied'})
    elif change == 'missing_roles': index['collections'].pop('iam_role'); index.pop('iam_role')
    elif change == 'projection': index['iam_role'] = []
    elif change == 'foreign_provider': provider['Arn'] = provider['Arn'].replace(ACCOUNT, '999999999999')
    elif change == 'foreign_role': role['Arn'] = role['Arn'].replace(ACCOUNT, '999999999999')
    elif change == 'bad_provider_proof': provider['_provenance'] = {'operation': 'iam:GetRole'}
    elif change == 'missing_role_proof': role.pop('_provenance')
    elif change == 'missing_trust': role.pop('AssumeRolePolicyDocument')
    elif change == 'bad_condition': statement['Condition'] = None
    elif change == 'not_principal': statement['NotPrincipal'] = statement.pop('Principal')
    elif change == 'wildcard_principal': statement['Principal'] = '*'
    elif change == 'not_action': statement['NotAction'] = statement.pop('Action')
    elif change == 'wildcard_federated': statement['Principal']['Federated'] = 'arn:aws:iam::*:saml-provider/*'
    elif change == 'wildcard_aws': statement['Principal'] = {'AWS': '*'}
    elif change == 'duplicate_role': source['items'].append(deepcopy(role)); index['iam_role'].append({'type': 'iam_role', 'scope': SCOPE, 'data': source['items'][-1]})
    assert subject.evaluate(provider, index, subject.SAML_CHECK)[0] == expected


def test_known_reference_survives_unrelated_partial_and_conditions():
    provider, role, index = fixture(bound=True)
    other = deepcopy(role); other['RoleId'] = 'AROA0123456789ABCDF'; other['RoleName'] = 'other'; other['Arn'] = f'arn:aws:iam::{ACCOUNT}:role/other'
    other.pop('AssumeRolePolicyDocument')
    index['iam_role'].append({'type': 'iam_role', 'scope': SCOPE, 'data': other})
    index['collections']['iam_role'][0].update(status='partial', error={'cause_status': 'denied'})
    index['collections']['iam_role'][0]['items'].append(other)
    assert subject.evaluate(provider, index, subject.SAML_CHECK)[0] == 'PASS'
    role['AssumeRolePolicyDocument']['Statement'][0]['Effect'] = 'Deny'
    assert subject.evaluate(provider, index, subject.SAML_CHECK)[0] == 'DENIED'


def test_deny_only_trust_does_not_consume_provider():
    provider, role, index = fixture(bound=True)
    role['AssumeRolePolicyDocument']['Statement'][0]['Effect'] = 'Deny'
    assert subject.evaluate(provider, index, subject.SAML_CHECK)[0] == 'FAIL'


def test_existing_memo_index_scans_roles_once(monkeypatch):
    from peaso.checks.facts import MemoIndex
    provider, _, index = fixture(bound=True)
    index = MemoIndex(index)
    calls = []; original = subject.records
    def tracked(current, kind, scope):
        if kind == 'iam_role': calls.append(kind)
        return original(current, kind, scope)
    monkeypatch.setattr(subject, 'records', tracked)
    for _ in range(2):
        assert subject.evaluate(provider, index, subject.SAML_CHECK)[0] == 'PASS'
    assert calls == ['iam_role']


def test_bound_cases_and_real_hardening_engine():
    from peaso import checks as registry
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    if subject.SAML_CHECK not in {check.id for check in registry.CHECKS}:
        subject.install(registry)
    assert {subject.SAML_CHECK, subject.OIDC_CHECK} <= set(CASES)
    for check_id in (subject.SAML_CHECK, subject.OIDC_CHECK):
        check = next(check for check in registry.CHECKS if check.id == check_id)
        assert check.category == 'hardening'
        for status in ('PASS', 'FAIL', 'UNKNOWN'):
            key = status.lower(); case = CASES[check_id]
            assert check.evaluate(case[key], case[key + '_index'])[0] == status
        kind = subject.CHECKS[check_id][0]
        provider, _, index = fixture(kind, True)
        snapshot = make_snapshot('aws', [SCOPE], [deepcopy(c) for group in index['collections'].values() for c in group], created_at=NOW)
        report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[check_id])
        findings = [finding for finding in report['findings'] if finding['check_id'] == check_id]
        assert len(findings) == 1 and findings[0]['status'] == 'PASS'
        assert findings[0]['evidence']['provider_arn'] == provider['Arn']
