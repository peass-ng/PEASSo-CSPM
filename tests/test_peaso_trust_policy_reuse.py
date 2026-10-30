"""Trust consumers reuse only sealed documents that IAM has already decoded."""
import copy
import json
from urllib.parse import quote

import pytest

from examples.benchmark_peaso_decoded_policies import synthetic_snapshot, run_stage
from peaso.analysis import iam, trust
from peaso.analysis.common import analysis_context, node_id
from peaso.snapshot import FrozenDict, digest, freeze, resources


@pytest.mark.parametrize('encoding', [json.dumps, lambda value: quote(json.dumps(value))])
def test_reuses_decoded_trust_without_calling_parser_again(monkeypatch, encoding):
    snapshot = synthetic_snapshot(1, 'dict', 5)
    row = resources(snapshot)[0]
    row['data'] = freeze({**row['data'], 'AssumeRolePolicyDocument': encoding(row['data']['AssumeRolePolicyDocument'])})
    with analysis_context(snapshot):
        cached = dict(iam._resource_policy_documents(row))['AssumeRolePolicyDocument']
        assert type(cached) is FrozenDict
        monkeypatch.setattr(iam, 'document', lambda value: pytest.fail('decoded again'))
        assert iam.assume_role_document(row) is cached


def test_cold_trust_does_not_eagerly_parse_other_policy_fields(monkeypatch):
    snapshot = synthetic_snapshot(1, 'json', 5)
    row = resources(snapshot)[0]
    original = iam.document
    calls = []
    def parse(value):
        calls.append(value)
        return original(value)
    monkeypatch.setattr(iam, 'document', parse)
    with analysis_context(snapshot):
        first = iam.assume_role_document(row)
        second = iam.assume_role_document(row)
        assert first == second and first is not second
        assert len(calls) == 2
        assert calls == [row['data']['AssumeRolePolicyDocument']] * 2


def test_replaced_native_wrapper_data_does_not_reuse_previous_trust_policy():
    snapshot = synthetic_snapshot(1, 'json', 5)
    row = resources(snapshot)[0]
    with analysis_context(snapshot):
        iam._resource_policy_documents(row)
        row['data'] = freeze({**row['data'], 'AssumeRolePolicyDocument':
            '{"Statement":[{"Effect":"Deny","Action":"sts:*","Principal":"*"}]}'})
        assert iam.assume_role_document(row) == iam.document(row['data']['AssumeRolePolicyDocument'])


@pytest.mark.parametrize('value', [None, '', 'broken', '{}', '{"Statement":null}',
    '{"Statement":[]}', '{"Statement":{"Effect":"Deny"}}', {'Statement': []}])
def test_invalid_empty_and_native_values_keep_public_parser_semantics(value):
    snapshot = synthetic_snapshot(1, 'dict', 0)
    row = dict(resources(snapshot)[0], data=freeze({'AssumeRolePolicyDocument': value}))
    expected = iam.document(row['data']['AssumeRolePolicyDocument'])
    with analysis_context(snapshot):
        iam._resource_policy_documents(row)
        assert iam.assume_role_document(row) == expected
    assert iam.assume_role_document(row) == expected


@pytest.mark.parametrize('mutable_source', [True, False])
def test_mutable_cached_trees_and_sources_keep_independent_decodes(mutable_source):
    snapshot = synthetic_snapshot(1, 'json', 5)
    row = resources(snapshot)[0]
    if mutable_source:
        row = copy.deepcopy(row)
    with analysis_context(snapshot) as context:
        parsed = iam.document(row['data']['AssumeRolePolicyDocument'])
        context['derivations'][('iam_policy_documents', node_id(row))] = (('AssumeRolePolicyDocument', parsed),)
        first = iam.assume_role_document(row)
        second = iam.assume_role_document(row)
        assert first == parsed and first is not parsed and first is not second
        first['Statement'].clear()
        assert second['Statement']


@pytest.mark.parametrize('policy_format', ['dict', 'json', 'percent'])
def test_complete_iam_stage_matches_literal_trust_parsing(monkeypatch, policy_format):
    from peaso import principal_exposure
    snapshot = synthetic_snapshot(8, policy_format, 5)
    rows, before = resources(snapshot), digest(snapshot)
    actual = run_stage(snapshot, rows)
    def literal(row):
        return iam.document(row['data'].get('AssumeRolePolicyDocument'))
    monkeypatch.setattr(iam, 'assume_role_document', literal)
    monkeypatch.setattr(principal_exposure, 'assume_role_document', literal)
    expected = run_stage(snapshot, rows)
    assert json.dumps(actual) == json.dumps(expected)
    assert digest(snapshot) == before


def test_mutable_trust_source_is_read_once():
    class Data(dict):
        def get(self, key, *args):
            if key == 'AssumeRolePolicyDocument':
                self['reads'] += 1
            return super().get(key, *args)
    data = Data(AssumeRolePolicyDocument='{"Statement":[]}', reads=0)
    assert trust.aws_federated_trust({'provider': 'aws'}, {'data': data}) is None
    assert data['reads'] == 1


def test_complete_workflow_decodes_each_trust_policy_once(monkeypatch):
    from examples import benchmark_peaso_trust_policy_reuse as benchmark
    from peaso import principal_exposure
    snapshot = benchmark.synthetic_snapshot(2, 2, 'percent')
    inventory = resources(snapshot)
    encoded = inventory[0]['data']['AssumeRolePolicyDocument']
    original = iam.document
    calls = []
    def counted(value):
        if type(value) is str and value == encoded:
            calls.append(value)
        return original(value)
    monkeypatch.setattr(iam, 'document', counted)
    benchmark.run_stage(snapshot, inventory)
    assert len(calls) == 2
    calls.clear()
    monkeypatch.setattr(iam, 'assume_role_document', benchmark.literal_document)
    monkeypatch.setattr(principal_exposure, 'assume_role_document', benchmark.literal_document)
    benchmark.run_stage(snapshot, inventory)
    # The uncached baseline re-decodes the same policy for every trust consumer
    # (federation review, foreign-assumption review, principal projection, ...),
    # so the optimized path above must stay at exactly one decode per role.
    roles = len(inventory)
    assert len(calls) > roles and len(calls) % roles == 0


@pytest.mark.parametrize('policy_format', ['dict', 'json', 'percent'])
@pytest.mark.parametrize('mode', ['pinned', 'wildcard', 'missing-subject', 'cognito-guest', 'malformed'])
def test_complete_federation_stage_retains_conditions_verdicts_and_uncertainty(monkeypatch, policy_format, mode):
    from examples import benchmark_peaso_trust_policy_reuse as benchmark
    from peaso import principal_exposure
    from peaso.snapshot import seal, validate
    snapshot = benchmark.synthetic_snapshot(3, 3, 'dict')
    for role in snapshot['collections'][0]['items']:
        policy = role['AssumeRolePolicyDocument']
        for statement in policy['Statement']:
            if mode == 'wildcard':
                statement['Condition']['StringLike']['token.actions.githubusercontent.com:sub'] = '*'
            elif mode == 'missing-subject':
                statement['Condition'].pop('StringLike')
            elif mode == 'cognito-guest':
                statement['Principal']['Federated'] = 'cognito-identity.amazonaws.com'
                statement['Condition'] = {'StringEquals': {'cognito-identity.amazonaws.com:aud': 'native-pool',
                    'cognito-identity.amazonaws.com:amr': ['unauthenticated']}}
            elif mode == 'malformed':
                statement['Condition'] = ['invalid-condition']
        if policy_format != 'dict':
            role['AssumeRolePolicyDocument'] = json.dumps(policy)
            if policy_format == 'percent':
                role['AssumeRolePolicyDocument'] = quote(role['AssumeRolePolicyDocument'])
    snapshot = validate(seal(snapshot))
    inventory, before = resources(snapshot), digest(snapshot)
    actual = benchmark.run_stage(snapshot, inventory)
    monkeypatch.setattr(iam, 'assume_role_document', benchmark.literal_document)
    monkeypatch.setattr(principal_exposure, 'assume_role_document', benchmark.literal_document)
    expected = benchmark.run_stage(snapshot, inventory)
    assert json.dumps(actual) == json.dumps(expected)
    assert digest(snapshot) == before
