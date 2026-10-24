"""Sparse native inventory must preserve IAM facts without caching empty trees."""
from copy import deepcopy
import json
import pytest
from peaso.analysis import iam
from peaso.analysis.common import analysis_context
from peaso.snapshot import make_snapshot, resources

DOC = {'Statement':[{'Effect':'Allow','Action':'iam:*','Resource':'*','Principal':{'AWS':'*'}}]}

@pytest.mark.parametrize('field', ['PolicyDocument','Document','Policy','policy','AssumeRolePolicyDocument',
    'Attributes','Domain','Table','PolicyDetails','ResourcePolicy','AccessPolicy','AccessPolicies',
    'policyText','DomainStatus','Identity','document','policyDocument','UserPolicyList','GroupPolicyList',
    'RolePolicyList','PolicyVersionList','PolicySources'])
def test_all_native_policy_shapes_retain_original_documents_and_principals(field):
    if field.endswith('List') or field == 'PolicySources':
        value = [{'PolicyDocument':deepcopy(DOC),'IsDefaultVersion':True}]
    elif field == 'Identity':value = {'Policies':{'native':deepcopy(DOC)}}
    elif field == 'DomainStatus':value = {'AccessPolicies':json.dumps(DOC)}
    else:value = deepcopy(DOC)
    snapshot = make_snapshot('aws', ['111122223333/us-east-1'], [{'type':'iam_role',
        'scope':'111122223333/us-east-1','service':'iam','status':'collected',
        'items':[{'RoleName':'reviewed',field:value}]}])
    row = resources(snapshot)[0]
    expected = list(iam.policy_documents(row['data']))
    assert expected
    before = deepcopy(snapshot)
    with analysis_context(snapshot):
        assert list(iam._resource_policy_documents(row)) == expected
        assert list(iam.principals(row))
        assert list(iam._resource_policy_documents(row)) == expected
    assert snapshot == before

@pytest.mark.parametrize('provider', ['aws','gcp','azure','k8s'])
def test_policy_free_inventory_preserves_empty_analysis(provider):
    snapshot = make_snapshot(provider, ['scope'], [{'type':'inventory_fact','scope':'scope',
        'service':'native','status':'collected','items':[{'name':str(i),'state':'active'} for i in range(64)]}])
    rows = resources(snapshot)
    with analysis_context(snapshot):
        assert iam.review_findings(snapshot, rows, include_manual_only=False) == []
        assert all(list(iam.principals(row)) == [] for row in rows)


def test_custom_policy_parser_still_runs_on_policy_free_facts(monkeypatch):
    snapshot = make_snapshot('aws', ['scope'], [{'type':'iam_role','scope':'scope','service':'iam',
        'status':'collected','items':[{'RoleName':'custom-reader'}]}])
    row = resources(snapshot)[0]
    def custom(data):yield 'custom', DOC
    monkeypatch.setattr(iam,'policy_documents',custom)
    with analysis_context(snapshot):
        assert list(iam._resource_policy_documents(row)) == [('custom', DOC)]
        assert list(iam.principals(row))


def test_custom_document_decoder_is_not_short_circuited(monkeypatch):
    snapshot = make_snapshot('aws', ['scope'], [{'type':'iam_role','scope':'scope','service':'iam',
        'status':'collected','items':[{'RoleName':'custom-decoder'}]}])
    row = resources(snapshot)[0]
    monkeypatch.setattr(iam,'document',lambda value:deepcopy(DOC))
    with analysis_context(snapshot):assert list(iam._resource_policy_documents(row))
