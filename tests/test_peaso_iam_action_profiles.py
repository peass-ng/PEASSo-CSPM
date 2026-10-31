"""Shared action summaries never merge native grants or erase uncertainty."""
import copy
import random
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from threading import Barrier
from unittest.mock import patch

import pytest

from tests.synthetic.benchmark_peaso_iam_action_profiles import literal_text, run_stage, synthetic_snapshot
from peaso.analysis import finding_clarity, iam
from peaso.analysis.common import analysis_context
from peaso.snapshot import resources


@pytest.mark.parametrize('provider', ['aws', 'azure'])
@pytest.mark.parametrize('actions', [[], ['known'], ['s3:GetObject'] * 8,
    ['unknownvendor:UnmappedBenchmarkOperation'] * 8,
    ['s3:GetObject', 'unknownvendor:UnmappedBenchmarkOperation'] * 4,
    ['*', 'unknownvendor:UnmappedBenchmarkOperation'] * 4,
    [None, {}, [], True] * 3, ['long' * 100] * 8])
@pytest.mark.parametrize('force_broad', [False, True])
def test_profiles_equal_former_classification_including_unknowns(provider, actions, force_broad):
    snapshot = {'provider': provider, 'collections': []}
    original = copy.deepcopy(actions)
    expected = iam._permission_profile_uncached(provider, actions, force_broad=force_broad)
    with analysis_context(snapshot):
        for _ in range(2):
            assert iam._permission_profile(provider, actions, force_broad=force_broad) == expected
    assert actions == original


def test_one_profile_reuses_classifier_work_and_retains_missing_catalog_results():
    actions = ['unknownvendor:UnmappedBenchmarkOperation'] * 8
    snapshot = {'provider': 'aws', 'collections': []}
    with analysis_context(snapshot), patch.object(iam, '_permission_profile_uncached', wraps=iam._permission_profile_uncached) as compute:
        for _ in range(10):
            assert iam._permission_profile('aws', list(actions)) == (False, 'info', 'unknown')
        assert compute.call_count == 1


def test_rulepack_revision_and_classifier_identity_invalidate_summaries(monkeypatch):
    state = {'revision': 'one'}
    monkeypatch.setattr(iam, '_rulepack_revision', lambda provider: state['revision'])
    monkeypatch.setattr(iam, '_permission_severity', lambda provider, permission, revision: 'low' if revision == 'one' else 'high')
    with analysis_context({'collections': []}):
        assert iam._permission_profile('aws', ['action'] * 8) == (False, 'low', 'rule_based')
        state['revision'] = 'two'
        assert iam._permission_profile('aws', ['action'] * 8) == (False, 'high', 'rule_based')
        monkeypatch.setattr(iam, '_permission_severity', lambda *args: None)
        assert iam._permission_profile('aws', ['action'] * 8) == (False, 'info', 'unknown')


def test_external_classifier_and_ad_hoc_mutations_keep_original_call_semantics(monkeypatch):
    calls = []
    monkeypatch.setattr(iam, 'permission_severity', lambda provider, permission: calls.append(permission) or 'low')
    with analysis_context({'collections': []}):
        iam._permission_profile('aws', ['action'] * 8)
        iam._permission_profile('aws', ['action'] * 8)
    assert len(calls) == 16
    assert iam._permission_profile('aws', ['action'], force_broad=True) == (True, 'high', 'rule_based')


@pytest.mark.parametrize('limit,byte_budget', [(0, 2 * 1024 * 1024), (1, 2 * 1024 * 1024), (1024, 0)])
def test_exhausted_budgets_recompute_without_omitting_grants(limit, byte_budget):
    snapshot = {'provider': 'aws', 'collections': []}
    with patch.object(iam, 'ACTION_PROFILE_LIMIT', limit), patch.object(iam, 'ACTION_PROFILE_BYTES', byte_budget), analysis_context(snapshot) as context:
        for i in range(5):
            actions = [f'unknownvendor:UnmappedOperation{i}'] * 8
            assert iam._permission_profile('aws', actions) == iam._permission_profile_uncached('aws', actions)
        cache = context['derivations'][('snapshot', 'iam_action_profiles')]
        assert len(cache['entries']) <= limit
        assert cache['bytes'] <= byte_budget


def test_errors_are_not_cached(monkeypatch):
    calls = []
    original = iam._permission_profile_uncached

    def compute(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise ValueError('recorded classifier failure')
        return original(*args, **kwargs)

    monkeypatch.setattr(iam, '_permission_profile_uncached', compute)
    with analysis_context({'collections': []}):
        with pytest.raises(ValueError, match='recorded classifier failure'):
            iam._permission_profile('aws', ['s3:GetObject'] * 8)
        assert iam._permission_profile('aws', ['s3:GetObject'] * 8)
    assert len(calls) == 2


@pytest.mark.parametrize('provider', ['aws', 'azure'])
@pytest.mark.parametrize('budget', [0, 2 * 1024 * 1024])
@pytest.mark.parametrize('actions', [1, None])
def test_complete_iam_workflow_keeps_every_grant_condition_and_exception(provider, budget, actions):
    snapshot = synthetic_snapshot(provider, 6, 30, actions)
    before, inventory = copy.deepcopy(snapshot), resources(snapshot)
    with patch.object(iam, '_permission_profile', iam._permission_profile_uncached), patch.object(finding_clarity, '_text', literal_text):
        expected = run_stage(snapshot, inventory)
    with patch.object(iam, 'ACTION_PROFILE_BYTES', budget):
        actual = run_stage(snapshot, inventory)
    assert actual == expected
    assert snapshot == before
    definitions = [r for r in inventory if r['type'] in {'iam_role', 'role_definition'}]
    assert all(len(iam.full_grants(r)) == 30 for r in definitions)
    assert all(iam.full_grants(r)[0]['conditional'] for r in definitions)


def test_profile_cache_ends_with_each_scan_and_stays_unused_for_short_lists():
    caches = []
    snapshot = {'provider': 'aws', 'collections': []}
    for _ in range(2):
        with analysis_context(snapshot) as context:
            iam._permission_profile('aws', ['s3:GetObject'])
            assert ('snapshot', 'iam_action_profiles') not in context['derivations']
            iam._permission_profile('aws', ['s3:GetObject'] * 8)
            caches.append(context['derivations'][('snapshot', 'iam_action_profiles')])
    assert caches[0] is not caches[1]


def test_text_validation_exactly_matches_legacy_controls_unicode_and_limits():
    values = [None, 0, [], '', 'native evidence', '\x7f', '\x80', '\x85', '\u2028', '\u2029', '\ud800', '\udfff', '\U0010ffff']
    values.extend('prefix' + chr(code) + 'suffix' for code in range(256))
    rng = random.Random(88)
    values.extend(''.join(chr(rng.randrange(0x110000)) for _ in range(rng.randrange(1, 250))) for _ in range(100))
    for value in values:
        for limit in (0, 1, 80, 240, 300):
            assert finding_clarity._text(value, limit) == literal_text(value, limit)


def test_text_subclasses_keep_original_iteration_semantics():
    class Native(str):
        def __iter__(self):
            return iter('\x00')
    assert finding_clarity._text(Native('otherwise acceptable')) is False
    assert finding_clarity._text(Native('otherwise acceptable')) == literal_text(Native('otherwise acceptable'))


def test_native_not_action_and_missing_catalog_keep_their_original_uncertainty(monkeypatch):
    monkeypatch.setattr(iam, '_rulepack_revision', lambda provider: None)
    native = {'Effect': 'Allow', 'NotAction': ['s3:GetObject'], 'Resource': '*',
              'Condition': {'Bool': {'aws:SecureTransport': 'true'}}}
    resource = {'provider': 'aws', 'data': {'Policy': {'Statement': [native]}}}
    grant = iam.full_grants(resource)[0]
    assert grant['native_grant'] is native
    assert grant['broad'] is True and grant['severity'] == 'high'
    assert grant['conditional'] is True and grant['criticality_state'] == 'unknown'
    with analysis_context({'collections': []}):
        assert iam._permission_profile('aws', ['s3:GetObject'] * 8) == (False, 'info', 'unknown')


def test_concurrent_copied_contexts_admit_a_shared_profile_only_once():
    actions = ['s3:GetObject'] * 8
    original = iam._permission_profile_uncached
    barrier = Barrier(4, timeout=5)

    def simultaneous(*args, **kwargs):
        barrier.wait()
        return original(*args, **kwargs)

    with analysis_context({'collections': []}) as context:
        with patch.object(iam, 'ACTION_PROFILE_BYTES', 0):
            iam._permission_profile('aws', actions)
        with patch.object(iam, '_permission_profile_uncached', simultaneous), patch.object(iam, 'ACTION_PROFILE_LIMIT', 1):
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(copy_context().run, iam._permission_profile, 'aws', list(actions)) for _ in range(4)]
                results = [future.result(timeout=10) for future in futures]
        assert all(result == original('aws', actions) for result in results)
        cache = context['derivations'][('snapshot', 'iam_action_profiles')]
        assert len(cache['entries']) == 1
        assert cache['bytes'] == 320 + len(actions) * 16 + sum(len(p) * 4 for p in actions)
