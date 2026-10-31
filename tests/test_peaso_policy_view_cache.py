"""Identical encoded IAM policies share sealed facts in one scan only."""
import copy
import json
from urllib.parse import quote

import pytest

from peaso.analysis import iam
from peaso.analysis.common import analysis_context
from peaso.snapshot import FrozenDict, freeze, resources, digest
from tests.synthetic.benchmark_peaso_trust_policy_reuse import synthetic_snapshot, run_stage


def text(marker='same'):
    return json.dumps({'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject'],
        'Resource': '*', 'Condition': {'StringEquals': {'native:recorded': marker + 'x' * 300}}}]})


@pytest.mark.parametrize('encode', [lambda x: x, quote])
def test_shared_decoding_is_scoped_and_sealed_without_changing_public_parser(monkeypatch, encode):
    raw = encode(text())
    source = synthetic_snapshot(2, 2, 'dict')
    rows = resources(source)
    for row in rows:
        row['data'] = freeze({**row['data'], 'AssumeRolePolicyDocument': raw})
    loads, calls = json.loads, []
    def counted(value, *args, **kwargs):
        calls.append(value)
        return loads(value, *args, **kwargs)
    monkeypatch.setattr(iam.json, 'loads', counted)
    with analysis_context(source):
        first = dict(iam._resource_policy_documents(rows[0]))['AssumeRolePolicyDocument']
        second = dict(iam._resource_policy_documents(rows[1]))['AssumeRolePolicyDocument']
        assert first is second and type(first) is FrozenDict and len(calls) == 1
        with pytest.raises(TypeError):
            first['Statement'][0]['Effect'] = 'Deny'
        ordinary = iam.document(raw)
        ordinary['Statement'].clear()
        assert first['Statement']
        mutable = copy.deepcopy(first)
        mutable['Statement'].clear()
        assert second['Statement']
    with analysis_context(source):
        third = dict(iam._resource_policy_documents(rows[0]))['AssumeRolePolicyDocument']
        assert third == first and third is not first


def test_changed_exact_source_keeps_condition_effect_and_resource_independent():
    source = synthetic_snapshot(1, 1, 'dict')
    with analysis_context(source):
        a = iam._sealed_policy_document(text('first'))
        b = iam._sealed_policy_document(text('second'))
        assert a is not b and a != b
        assert a['Statement'][0]['Condition']['StringEquals']['native:recorded'].startswith('first')
        assert b['Statement'][0]['Condition']['StringEquals']['native:recorded'].startswith('second')


def test_nested_scan_contexts_never_share_policy_trees():
    outer = synthetic_snapshot(1, 1, 'dict')
    inner = synthetic_snapshot(1, 1, 'dict')
    with analysis_context(outer):
        first = iam._sealed_policy_document(text())
        with analysis_context(inner):
            second = iam._sealed_policy_document(text())
            assert second == first and second is not first
        assert iam._sealed_policy_document(text()) is first


@pytest.mark.parametrize('limit,budget', [(1, 4 * 1024 * 1024), (256, 70000), (0, 0)])
def test_admission_bounds_fall_back_without_dropping_documents(monkeypatch, limit, budget):
    monkeypatch.setattr(iam, 'POLICY_VIEW_LIMIT', limit)
    monkeypatch.setattr(iam, 'POLICY_VIEW_BYTES', budget)
    source = synthetic_snapshot(1, 1, 'dict')
    with analysis_context(source) as context:
        for i in range(12):
            value = text(str(i))
            assert iam._sealed_policy_document(value) == iam.document(value)
        cache = context['derivations'][('snapshot', 'iam_encoded_policy_views')]
        assert len(cache['entries']) <= limit and cache['bytes'] <= budget


@pytest.mark.parametrize('value', ['', 'invalid' * 50, '{"Statement":null}' + ' ' * 300,
                                  '{"Statement":[]}', text() + ' ' * 40000, None,
                                  {'Statement': [{'Effect': 'Deny'}]}])
def test_unsupported_small_large_invalid_and_mutable_inputs_keep_semantics(value):
    source = synthetic_snapshot(1, 1, 'dict')
    with analysis_context(source) as context:
        assert iam._sealed_policy_document(value) == iam.document(value)
        cache = context['derivations'].get(('snapshot', 'iam_encoded_policy_views'), {})
        assert not cache.get('entries')


def test_custom_parser_remains_uncached(monkeypatch):
    parser, calls = iam.document, []
    def custom(value):
        calls.append(value)
        return parser(value)
    monkeypatch.setattr(iam, 'document', custom)
    with analysis_context(synthetic_snapshot(1, 1, 'dict')) as context:
        first = iam._sealed_policy_document(text())
        assert iam._sealed_policy_document(text()) == first
        assert len(calls) == 2
        assert ('snapshot', 'iam_encoded_policy_views') not in context['derivations']


def test_unique_policies_disable_admission_without_changing_later_facts(monkeypatch):
    monkeypatch.setattr(iam, 'POLICY_VIEW_MISS_LIMIT', 4)
    with analysis_context(synthetic_snapshot(1, 1, 'dict')) as context:
        for i in range(6):
            assert iam._sealed_policy_document(text(str(i))) == iam.document(text(str(i)))
        cache = context['derivations'][('snapshot', 'iam_encoded_policy_views')]
        assert not cache['enabled'] and not cache['entries'] and cache['bytes'] == 0
        first = iam._sealed_policy_document(text('later'))
        second = iam._sealed_policy_document(text('later'))
        assert first == second and first is not second


@pytest.mark.parametrize('mode', ['pinned', 'wildcard', 'missing-subject', 'malformed'])
def test_whole_iam_federation_stage_matches_cache_disabled(monkeypatch, mode):
    source = synthetic_snapshot(10, 3, 'dict')
    for row in source['collections'][0]['items']:
        for statement in row['AssumeRolePolicyDocument']['Statement']:
            if mode == 'wildcard':
                statement['Condition']['StringLike']['token.actions.githubusercontent.com:sub'] = '*'
            elif mode == 'missing-subject':
                statement['Condition'].pop('StringLike')
            elif mode == 'malformed':
                statement['Condition'] = ['malformed']
        row['AssumeRolePolicyDocument'] = quote(json.dumps(row['AssumeRolePolicyDocument']))
    inventory, before = resources(source), digest(source)
    actual = run_stage(source, inventory)
    monkeypatch.setattr(iam, 'POLICY_VIEW_LIMIT', 0)
    expected = run_stage(source, inventory)
    assert json.dumps(actual) == json.dumps(expected) and digest(source) == before
