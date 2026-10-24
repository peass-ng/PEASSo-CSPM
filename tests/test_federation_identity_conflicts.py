"""A role with a conflicting native identity cannot certify a provider consumer."""
from copy import deepcopy
import importlib.util
import os
from pathlib import Path
import pytest
from tests.test_unused_iam_aws_federation_consumers import fixture, ACCOUNT, SCOPE
from peaso import unused_iam_aws_federation_consumers as subject

FAMILIES = [('iam_oidc_provider', subject.OIDC_CHECK), ('iam_saml_provider', subject.SAML_CHECK)]


def append_role(index, role):
    index['iam_role'].append({'type': 'iam_role', 'scope': SCOPE, 'data': role})
    index['collections']['iam_role'][0]['items'].append(role)


@pytest.mark.parametrize('kind,check', FAMILIES)
@pytest.mark.parametrize('mutation', ['conflicting_trust', 'shared_stable_id', 'shared_arn', 'missing_provenance'])
def test_conflicting_captured_consumer_identity_is_unknown(kind, check, mutation):
    provider, role, index = fixture(kind, True)
    other = deepcopy(role)
    if mutation == 'conflicting_trust': other['AssumeRolePolicyDocument']['Statement'][0]['Effect'] = 'Deny'
    elif mutation == 'shared_stable_id':
        other['RoleName'] = 'other'
        other['Arn'] = f'arn:aws:iam::{ACCOUNT}:role/other'
    elif mutation == 'shared_arn': other['RoleId'] = 'AROA0123456789ABCDF'
    else: other.pop('_provenance')
    append_role(index, other)
    before = deepcopy(index)
    status, evidence = subject.evaluate(provider, index, check)
    assert status == 'UNKNOWN', evidence
    assert index == before


@pytest.mark.parametrize('kind,check', FAMILIES)
@pytest.mark.parametrize('case', ['unrelated_malformed', 'unrelated_duplicate', 'partial_unrelated_denial'])
def test_unique_known_consumer_survives_unrelated_unresolved_rows(kind, check, case):
    provider, role, index = fixture(kind, True)
    other = deepcopy(role)
    other.update(RoleName='other', RoleId='AROA0123456789ABCDF', Arn=f'arn:aws:iam::{ACCOUNT}:role/other')
    other['AssumeRolePolicyDocument']['Statement'][0]['Effect'] = 'Deny'
    if case == 'unrelated_malformed': other.pop('_provenance')
    append_role(index, other)
    if case == 'unrelated_duplicate': append_role(index, deepcopy(other))
    if case == 'partial_unrelated_denial': index['collections']['iam_role'][0].update(status='partial', error={'cause_status': 'denied'})
    status, evidence = subject.evaluate(provider, index, check)
    assert status == 'PASS', evidence
    assert [r['role_arn'] for r in evidence['role_consumers']] == [role['Arn']]


@pytest.mark.parametrize('kind,check', FAMILIES)
@pytest.mark.parametrize('case,expected', [('complete_absence','FAIL'),('complete_consumer','PASS'),('denied','DENIED'),('partial_denied','DENIED'),('missing_provenance','UNKNOWN'),('foreign_arn','UNKNOWN')])
def test_each_federation_family_retains_exact_negative_positive_and_boundary_states(kind, check, case, expected):
    provider, role, index = fixture(kind, case == 'complete_consumer')
    if case == 'denied': index['collections']['iam_role'][0].update(status='denied', error={'code':'AccessDenied'})
    elif case == 'partial_denied': index['collections']['iam_role'][0].update(status='partial', error={'cause_status':'denied'})
    elif case == 'missing_provenance': role.pop('_provenance')
    elif case == 'foreign_arn': role['Arn'] = role['Arn'].replace(ACCOUNT,'999999999999')
    status, evidence = subject.evaluate(provider,index,check)
    assert status == expected,evidence
