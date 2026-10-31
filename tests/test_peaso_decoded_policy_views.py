"""Decoded sealed policy facts are shared without changing their declarations."""
import copy
import json
from urllib.parse import quote

import pytest

from tests.synthetic.benchmark_peaso_decoded_policies import literal_documents, synthetic_snapshot, run_stage
from peaso.analysis import iam, trust
from peaso.analysis.common import analysis_context
from peaso.snapshot import FrozenDict, FrozenList, digest, freeze, resources


@pytest.mark.parametrize('policy_format', ['dict', 'json', 'percent'])
@pytest.mark.parametrize('trust_principals', [0, 5])
def test_complete_iam_findings_graph_and_principal_projection_match_original(monkeypatch, policy_format, trust_principals):
    snapshot = synthetic_snapshot(5, policy_format, trust_principals)
    rows, before = resources(snapshot), digest(snapshot)
    actual = run_stage(snapshot, rows)
    monkeypatch.setattr(iam, '_resource_policy_documents', literal_documents)
    expected = run_stage(snapshot, rows)
    assert json.dumps(actual, ensure_ascii=False) == json.dumps(expected, ensure_ascii=False)
    assert digest(snapshot) == before


def test_reviews_and_cards_share_decoded_native_statements_in_one_run():
    snapshot = synthetic_snapshot(1, 'json', 5)
    rows = resources(snapshot)
    with analysis_context(snapshot):
        documents = iam._resource_policy_documents(rows[0])
        assert iam._resource_policy_documents(rows[0]) is documents
        assert all(type(document) is FrozenDict for _, document in documents)
        native = iam.grants(rows[0])[1]['native_grant']
        assert type(native) is FrozenDict and type(native['Action']) is FrozenList
        findings = iam.review_findings(snapshot, rows)
        review = next(row for row in findings if row['check_id'] == 'analysis.grant_review')
        unknown = next(row for row in findings if row['check_id'] == 'analysis.coverage')
        assert any(grant['native_grant'] is native for grant in review['evidence']['grants'])
        assert any(grant['native_grant'] is native for grant in unknown['evidence']['unclassified_grants'])
        graph = iam.build_iam(snapshot, rows)
        role = next(row for row in graph['nodes'] if row['type'] == 'iam_role')
        assert any(grant['native_grant'] is native for grant in role['card']['source_grants'])
        with pytest.raises(TypeError, match='read-only'):
            native['Action'].append('local change')
        mutable = copy.deepcopy(native)
        mutable['Action'].append('local change')
        assert 'local change' not in native['Action']


def test_public_parsers_and_context_free_grants_keep_mutable_decoded_copies():
    snapshot = synthetic_snapshot(1, 'percent', 0)
    row = resources(snapshot)[0]
    value = row['data']['RolePolicyList'][0]['PolicyDocument']
    parsed = iam.document(value)
    assert type(parsed) is dict and type(parsed['Statement']) is list
    parsed['Statement'].append({'local': True})
    assert {'local': True} not in iam.document(value)['Statement']
    documents = dict(iam.policy_documents(row['data']))
    assert type(documents['RolePolicyList[0]']) is dict
    assert type(iam.grants(row)[0]['native_grant']) is dict
    assert type(iam.full_grants(row)[0]['native_grant']) is dict
    assert type(dict(iam._resource_policy_documents(row))['RolePolicyList[0]']) is dict


def test_mutable_resource_inputs_keep_the_original_policy_object_contract():
    snapshot = synthetic_snapshot(1, 'json', 0)
    row = copy.deepcopy(resources(snapshot)[0])
    assert type(row['data']) is dict
    with analysis_context(snapshot):
        documents = iam._resource_policy_documents(row)
        policy = dict(documents)['RolePolicyList[0]']
        assert type(policy) is dict
        policy['Statement'][0]['Sid'] = 'local change'
        assert dict(iam._resource_policy_documents(row))['RolePolicyList[0]']['Statement'][0]['Sid'] == 'local change'


@pytest.mark.parametrize('value', [None, '', 'invalid JSON', '{}', '{"Statement":null}',
    '{"Statement":3}', '{"Statement":[]}', '{"Statement":{"Effect":"Allow","NotAction":["iam:DeleteRole"],'
    '"NotResource":["arn:aws:s3:::excluded/*"],"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-native"}}}}',
    quote('{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'),
    '{"Statement":[{"Effect":"Allow","Action":["cloud:Unknown"],"Resource":"雲", "value":NaN}]}'])
def test_unsupported_documents_empty_statements_and_native_constraints_match_original(value):
    snapshot = synthetic_snapshot(1, 'json', 0)
    row = dict(resources(snapshot)[0], data=freeze({'Policy': value, 'PolicyDetails': {'policyText': value}}))
    with analysis_context(snapshot):
        actual = iam._resource_policy_documents(row)
    with analysis_context(snapshot):
        expected = literal_documents(row)
    assert json.dumps(actual, ensure_ascii=False) == json.dumps(expected, ensure_ascii=False)


def test_all_native_wrappers_and_policy_versions_keep_exact_paths_and_order():
    snapshot = synthetic_snapshot(1, 'json', 0)
    policy = {'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': 'arn:aws:s3:::one/*'}]}
    text = json.dumps(policy)
    data = {'Policy': text, 'policy': quote(text), 'DomainStatus': {'AccessPolicies': text},
        'Identity': {'Policies': {'z-last': text, 'a-first': quote(text)}},
        'PolicyVersionList': [{'IsDefaultVersion': False, 'Document': text},
                              {'IsDefaultVersion': True, 'Document': text}],
        'PolicySources': [{'document': text}]}
    row = dict(resources(snapshot)[0], data=freeze(data))
    with analysis_context(snapshot):
        actual = iam._resource_policy_documents(row)
    with analysis_context(snapshot):
        expected = literal_documents(row)
    assert json.dumps(actual) == json.dumps(expected)
    assert 'PolicyVersionList[0]' not in dict(actual) and 'PolicyVersionList[1]' in dict(actual)
    assert [path for path, _ in actual if '.Policies.' in path] == ['Identity.Policies.a-first', 'Identity.Policies.z-last']


def test_fresh_scan_recomputes_views_and_preserves_preparsed_native_identity():
    snapshot = synthetic_snapshot(1, 'dict', 0)
    row = resources(snapshot)[0]
    native = row['data']['RolePolicyList'][0]['PolicyDocument']
    with analysis_context(snapshot):
        assert dict(iam._resource_policy_documents(row))['RolePolicyList[0]'] is native
    encoded = dict(row, data=freeze({'Policy': '{"Statement":[{"Effect":"Allow","Action":"*"}]}'}))
    with analysis_context(snapshot):
        first = dict(iam._resource_policy_documents(encoded))['Policy']
    changed = dict(encoded, data=freeze({'Policy': '{"Statement":[{"Effect":"Deny","Action":"*"}]}'}))
    with analysis_context(snapshot):
        second = dict(iam._resource_policy_documents(changed))['Policy']
    assert first['Statement'][0]['Effect'] == 'Allow'
    assert second['Statement'][0]['Effect'] == 'Deny'


def test_view_conversion_limit_keeps_complete_original_policies(monkeypatch):
    snapshot = synthetic_snapshot(2, 'json', 5)
    rows = resources(snapshot)
    with monkeypatch.context() as original:
        original.setattr(iam, '_resource_policy_documents', literal_documents)
        expected = run_stage(snapshot, rows)

    def unavailable(value):
        raise RecursionError('recursive view conversion limit')

    monkeypatch.setattr(iam, 'freeze', unavailable)
    actual = run_stage(snapshot, rows)
    assert json.dumps(actual) == json.dumps(expected)


def test_shared_policy_facts_do_not_cache_trust_classification():
    snapshot = synthetic_snapshot(1, 'json', 2)
    rows = resources(snapshot)
    with analysis_context(snapshot):
        documents = iam._resource_policy_documents(rows[0])
        first = iam.review_findings(snapshot, rows)
        assert any(row['check_id'] == 'analysis.principal_exposure' for row in first)
        boundary = trust.trusted_scopes(snapshot)
        boundary['ids'].add('222233334444')
        second = iam.review_findings(snapshot, rows)
        assert not any(row['check_id'] == 'analysis.principal_exposure' for row in second)
        assert iam._resource_policy_documents(rows[0]) is documents
        boundary['ids'].remove('222233334444')
        third = iam.review_findings(snapshot, rows)
        assert any(row['check_id'] == 'analysis.principal_exposure' for row in third)
