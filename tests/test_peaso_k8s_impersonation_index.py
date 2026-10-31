"""Candidate pruning preserves exact impersonation predicates and native order."""
import copy
import gc
import json
import weakref

import pytest

from tests.synthetic.benchmark_peaso_k8s_impersonation import LinearAccounts, synthetic_snapshot, run_stage
from peaso import principal_exposure
from peaso.analysis import k8s_impersonation_index as indexes
from peaso.snapshot import digest, resources, seal, validate


def account(name='runtime', namespace='default', cluster='cluster'):
    return {'id': f'{cluster}/{namespace}/{name}', 'scope': f'{cluster}/{namespace}',
        'type': 'serviceaccount', 'data': {'metadata': {'name': name, 'namespace': namespace},
                                        'provenance': {'cluster_id': cluster}}}


def owner(kind='rolebinding', namespace='default', cluster='cluster'):
    return dict(account('binding', namespace, cluster), type=kind)


def select(rows, binding, namespace, names):
    result = []
    for sa in rows:
        meta = sa['data'].get('metadata') or {}
        sa_ns = meta.get('namespace', 'default')
        if (principal_exposure._cluster(sa) != principal_exposure._cluster(binding)
                or binding['type'] == 'rolebinding' and sa_ns != namespace
                or names and meta.get('name') not in names):
            continue
        result.append(sa)
    return result


def outcome(function):
    try:
        return 'result', function()
    except Exception as error:
        return type(error), str(error)


@pytest.mark.parametrize('kind', ['rolebinding', 'clusterrolebinding'])
@pytest.mark.parametrize('namespace', ['default', 'other', None])
@pytest.mark.parametrize('names', [None, [], ['runtime'], ['runtime', 'runtime'], ['missing'],
                                 ['other', 'runtime'], 'runtime-extra', {'runtime': True}, 7, [None], [['runtime']]])
def test_candidates_match_literal_membership_scope_and_duplicate_rows(kind, namespace, names):
    rows = [account('runtime'), account('other'), account('runtime', 'other'),
            account('runtime', cluster='foreign'), account('runtime')]
    rows.append(dict(account('missing'), data={'metadata': {}}))
    binding = owner(kind, namespace)
    index = indexes.K8sImpersonationIndex(rows, principal_exposure._cluster)
    actual = lambda: select(index.candidates(binding, namespace, names), binding, namespace, names)
    expected = lambda: select(rows, binding, namespace, names)
    assert outcome(actual) == outcome(expected)


@pytest.mark.parametrize('bad', [
    {'metadata': None}, {'metadata': []}, {'metadata': 'invalid'},
    {'metadata': {'namespace': ['invalid'], 'name': 'runtime'}},
    {'metadata': {'namespace': 'default', 'name': ['runtime']}},
    {'metadata': {'namespace': 'default', 'name': None}},
    {'metadata': {'namespace': 'default', 'name': 'runtime'}, 'provenance': 'invalid'},
])
@pytest.mark.parametrize('kind', ['rolebinding', 'clusterrolebinding'])
def test_malformed_rows_still_reach_the_original_predicate(bad, kind):
    rows = [account('valid-first'), dict(account(), data=bad), account('valid-last')]
    binding = owner(kind)
    index = indexes.K8sImpersonationIndex(rows, principal_exposure._cluster)
    assert outcome(lambda: select(index.candidates(binding, 'default', ['runtime']), binding, 'default', ['runtime'])) == outcome(
        lambda: select(rows, binding, 'default', ['runtime']))


def test_namespace_cluster_and_name_indexes_restrict_large_candidate_sets():
    rows = [account(f'runtime-{i}', f'ns-{i}', cluster=f'cluster-{i % 3}') for i in range(100)]
    index = indexes.K8sImpersonationIndex(rows, principal_exposure._cluster)
    assert index.candidates(owner(namespace='ns-4', cluster='cluster-1'), 'ns-4', None) == [rows[4]]
    binding = owner('clusterrolebinding', cluster='cluster-1')
    assert index.candidates(binding, 'ignored', ['runtime-4', 'runtime-4']) == [rows[4]]
    assert index.candidates(binding, 'ignored', None) == rows[1::3]


@pytest.mark.parametrize('budget', ['keys', 'bytes'])
def test_index_capacity_falls_back_to_all_accounts_without_truncation(monkeypatch, budget):
    monkeypatch.setattr(indexes, 'MAX_KEYS' if budget == 'keys' else 'MAX_BYTES', 1)
    rows = [account(str(i)) for i in range(10)]
    binding = owner()
    index = indexes.K8sImpersonationIndex(rows, principal_exposure._cluster)
    assert index.candidates(binding, 'default', ['3']) is rows
    assert index.candidates(binding, 'default', ['4']) is rows
    assert index.indexes[True, True] is None
    assert select(index.candidates(binding, 'default', ['3']), binding, 'default', ['3']) == [rows[3]]


def test_large_name_queries_and_string_subclasses_keep_literal_semantics(monkeypatch):
    class Name(str):
        __hash__ = None

    row = account(Name('runtime'))
    rows = [row]
    binding = owner()
    index = indexes.K8sImpersonationIndex(rows, principal_exposure._cluster)
    assert select(index.candidates(binding, 'default', ['runtime']), binding, 'default', ['runtime']) == rows
    monkeypatch.setattr(indexes, 'MAX_QUERY_NAMES', 1)
    assert select(index.candidates(binding, 'default', ['missing', 'runtime']), binding, 'default', ['missing', 'runtime']) == rows


def test_empty_accounts_and_unused_indexes_do_not_inspect_evidence():
    empty = []
    index = indexes.K8sImpersonationIndex(empty, principal_exposure._cluster)
    assert index.candidates({}, [], 7) is empty
    unused = indexes.K8sImpersonationIndex([{'invalid': 'unused'}], principal_exposure._cluster)
    assert unused.indexes == {}


def test_index_owner_is_not_retained_by_callback_cycles_with_gc_disabled():
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        index = indexes.K8sImpersonationIndex([account()], principal_exposure._cluster)
        reference = weakref.ref(index)
        assert index.candidates(owner(), 'default', ['runtime'])
        del index
        assert reference() is None
    finally:
        if was_enabled:
            gc.enable()


@pytest.mark.parametrize('layout', ['namespaces', 'shared'])
@pytest.mark.parametrize('binding_kind', ['rolebinding', 'clusterrolebinding'])
@pytest.mark.parametrize('capacity', [0, 200000])
def test_complete_iam_findings_graph_and_principals_match_full_inventory(monkeypatch, layout, binding_kind, capacity):
    snapshot = synthetic_snapshot(12, layout, binding_kind)
    inventory, before = resources(snapshot), digest(snapshot)
    monkeypatch.setattr(indexes, 'MAX_KEYS', capacity)
    actual = run_stage(snapshot, inventory)
    monkeypatch.setattr(indexes, 'K8sImpersonationIndex', LinearAccounts)
    expected = run_stage(snapshot, inventory)
    assert json.dumps(actual) == json.dumps(expected)
    assert digest(snapshot) == before
    signals = [exposure for card in actual['principals'].values() for exposure in card['exposures']
               if exposure['kind'] == 'external_impersonation']
    assert len(signals) == 12


def test_fresh_projection_reads_changed_rule_constraints():
    snapshot = synthetic_snapshot(3)
    first = run_stage(snapshot, resources(snapshot))
    changed = copy.deepcopy(snapshot)
    for collection in changed['collections']:
        if collection['type'] == 'role':
            collection['items'][0]['rules'][0]['resourceNames'] = ['not-collected']
    changed = validate(seal(changed))
    second = run_stage(changed, resources(changed))
    assert any(exposure['kind'] == 'external_impersonation' for card in first['principals'].values() for exposure in card['exposures'])
    assert not any(exposure['kind'] == 'external_impersonation' for card in second['principals'].values() for exposure in card['exposures'])


def test_complete_privilege_analysis_preserves_impersonated_admin_annotations(monkeypatch):
    from peaso.privesc import analyze

    snapshot = synthetic_snapshot(3)
    snapshot['scopes'].append('cluster')
    snapshot['collections'].extend([
        {'scope': 'cluster', 'type': 'clusterrole', 'status': 'collected', 'items': [{
            'metadata': {'name': 'native-admin'},
            'rules': [{'apiGroups': ['*'], 'resources': ['*'], 'verbs': ['*']}]}]},
        {'scope': 'cluster', 'type': 'clusterrolebinding', 'status': 'collected', 'items': [{
            'metadata': {'name': 'native-admin'}, 'roleRef': {'kind': 'ClusterRole', 'name': 'native-admin'},
            'subjects': [{'kind': 'ServiceAccount', 'name': f'runtime-{i}', 'namespace': f'ns-{i}'}
                         for i in range(3)]}]}])
    snapshot = validate(seal(snapshot))
    before = digest(snapshot)
    actual = analyze(snapshot)
    assert any(node.get('exposures') or node.get('exposed_member_count') for node in actual['graph']['nodes'])
    monkeypatch.setattr(indexes, 'K8sImpersonationIndex', LinearAccounts)
    expected = analyze(snapshot)
    actual['stats'].pop('timing_seconds')
    expected['stats'].pop('timing_seconds')
    assert actual == expected
    assert digest(snapshot) == before
