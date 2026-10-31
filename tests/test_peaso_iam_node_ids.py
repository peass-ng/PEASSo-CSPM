"""Prepared IAM identities preserve native aliases, folding and edge evidence."""
import copy
from functools import lru_cache
import json

import pytest

from tests.synthetic.benchmark_peaso_iam_action_profiles import synthetic_snapshot as role_snapshot, run_stage
from tests.synthetic.benchmark_peaso_iam_node_ids import synthetic_snapshot
from tests.synthetic.benchmark_peaso_trust_domains import synthetic_snapshot as trust_snapshot
from tests.synthetic.reference_peaso_iam_node_ids import original_builder
from peaso import analysis
from peaso.analysis import common, iam
from peaso.snapshot import digest, make_snapshot, resources


def k8s_snapshot(bindings=1500, layout='namespaces', binding_kind='rolebinding'):
    if bindings < 1 or layout not in ('namespaces', 'shared') or binding_kind not in ('rolebinding', 'clusterrolebinding'):
        raise ValueError('positive binding count and supported layout/binding kind required')
    grouped = {}
    for i in range(bindings):
        namespace = f'ns-{i}' if layout == 'namespaces' else 'workloads'
        namespaced = binding_kind == 'rolebinding'
        scope = 'cluster/' + namespace
        definition_scope = scope if namespaced else 'cluster'
        role_kind = 'role' if namespaced else 'clusterrole'
        account = f'runtime-{i}'
        role = f'impersonator-{i}'
        meta = {'namespace': namespace} if namespaced else {}
        facts = [
            ('serviceaccount', scope, {'metadata': {'name': account, 'namespace': namespace}}),
            (role_kind, definition_scope, {'metadata': {**meta, 'name': role}, 'rules': [{
                'verbs': ['impersonate'], 'resources': ['serviceaccounts'], 'apiGroups': [''],
                'resourceNames': [account]}]}),
            (binding_kind, definition_scope, {'metadata': {**meta, 'name': f'binding-{i}'},
                'roleRef': {'kind': 'Role' if namespaced else 'ClusterRole', 'name': role,
                            'apiGroup': 'rbac.authorization.k8s.io'},
                'subjects': [{'kind': 'User', 'name': f'person-{i}@outside.example'}]})]
        for kind, collection_scope, value in facts:
            grouped.setdefault((collection_scope, kind), []).append(value)
    collections = [{'scope': scope, 'type': kind, 'status': 'collected', 'items': items}
                   for (scope, kind), items in grouped.items()]
    return make_snapshot('k8s', sorted({scope for scope, _ in grouped}), collections,
        metadata={'trusted_domains': ['corp.example']}, created_at='2026-01-01T00:00:00+00:00')



def provider_snapshot(provider):
    if provider == 'aws':
        return synthetic_snapshot(8)
    if provider == 'azure':
        return role_snapshot('azure', 8, 3)
    if provider == 'k8s':
        return k8s_snapshot(8, 'shared')
    return trust_snapshot('gcp', 8, 4)


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_complete_iam_stage_matches_original_builder(monkeypatch, provider):
    snapshot = provider_snapshot(provider)
    inventory, before = resources(snapshot), digest(snapshot)
    actual = run_stage(snapshot, inventory)
    monkeypatch.setattr(iam, 'build_iam', original_builder())
    expected = run_stage(snapshot, inventory)
    assert json.dumps(actual) == json.dumps(expected)
    assert digest(snapshot) == before


@pytest.mark.parametrize('defer', [(), ('iam_role', 'role_definition', 'clusterrole')])
@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_deferred_and_complete_cards_retain_all_graph_evidence(provider, defer):
    snapshot = provider_snapshot(provider)
    inventory = resources(snapshot)
    with common.analysis_context(snapshot):
        actual = iam.build_iam(snapshot, inventory, defer_types=defer)
    with common.analysis_context(snapshot):
        expected = original_builder()(snapshot, inventory, defer_types=defer)
    assert json.dumps(actual) == json.dumps(expected)


def test_each_selected_row_has_one_prepared_id_and_no_repeated_alias_lookup(monkeypatch):
    snapshot = synthetic_snapshot(20)
    inventory = resources(snapshot)
    calls = []
    original = iam.node_id
    def counted(row):
        calls.append(row)
        return original(row)
    monkeypatch.setattr(iam, 'node_id', counted)
    actual = iam.build_iam(snapshot, inventory)
    assert len(calls) == len(inventory)
    calls.clear()
    expected = original_builder()(snapshot, inventory)
    assert len(calls) >= len(inventory) * 8
    assert json.dumps(actual) == json.dumps(expected)


def test_inventory_larger_than_id_cache_does_not_rehash_every_graph_phase(monkeypatch):
    snapshot = synthetic_snapshot(40)
    inventory = resources(snapshot)
    cache = lru_cache(maxsize=8)(common._node_id.__wrapped__)
    monkeypatch.setattr(common, '_node_id', cache)
    actual = iam.build_iam(snapshot, inventory)
    optimized = cache.cache_info()
    cache.cache_clear()
    expected = original_builder()(snapshot, inventory)
    baseline = cache.cache_info()
    assert json.dumps(actual) == json.dumps(expected)
    assert optimized.misses == len(inventory)
    assert baseline.misses >= len(inventory) * 4


def test_equal_managed_copies_fold_but_conflicting_grants_remain_separate():
    collections = []
    for i, permission in enumerate(('storage.objects.get', 'storage.objects.get', 'iam.serviceAccounts.actAs')):
        scope = f'projects/project-{i}'
        collections.extend([
            {'type': 'iam_role', 'scope': scope, 'status': 'collected',
                'items': [{'name': 'roles/shared', 'includedPermissions': [permission]}]},
            {'type': 'iam_policy', 'scope': scope, 'status': 'collected', 'items': [{'name': scope + '/iamPolicy',
                'bindings': [{'role': 'roles/shared', 'members': ['user:reader@outside.example']}]}]},
        ])
    snapshot = make_snapshot('gcp', [row['scope'] for row in collections[::2]], collections)
    inventory = resources(snapshot)
    with common.analysis_context(snapshot):
        actual = iam.build_iam(snapshot, inventory)
    with common.analysis_context(snapshot):
        expected = original_builder()(snapshot, inventory)
    assert json.dumps(actual) == json.dumps(expected)
    definitions = [row for row in actual['nodes'] if row['type'] == 'iam_role']
    assert len(definitions) == 2
    assert len(next(row for row in definitions if row.get('provider_managed'))['scope_refs']) == 2


@pytest.mark.parametrize('duplicate_first', [False, True])
def test_duplicate_native_nodes_keep_last_node_and_all_edges(duplicate_first):
    snapshot = synthetic_snapshot(3)
    inventory = resources(snapshot)
    duplicate = copy.deepcopy(inventory[0])
    duplicate['data']['RoleName'] = 'second recorded label'
    inventory.insert(0 if duplicate_first else 1, duplicate)
    before = copy.deepcopy(inventory)
    actual = iam.build_iam(snapshot, inventory)
    expected = original_builder()(snapshot, inventory)
    assert json.dumps(actual) == json.dumps(expected)
    assert inventory == before


@pytest.mark.parametrize('native', [None, 7, ['native', 'id'], {'native': 'id'}])
def test_non_string_and_unhashable_native_ids_keep_original_fallback(native):
    snapshot = synthetic_snapshot(2)
    inventory = resources(snapshot)
    inventory[0] = dict(inventory[0], native_id=native)
    assert json.dumps(iam.build_iam(snapshot, inventory)) == json.dumps(original_builder()(snapshot, inventory))


def test_malformed_native_metadata_keeps_partial_graph_fallback(monkeypatch):
    snapshot = synthetic_snapshot(2)
    inventory = resources(snapshot)
    inventory[0] = dict(inventory[0], data={**inventory[0]['data'], 'metadata': None})
    actual = analysis.build_graphs(snapshot, inventory, max_nodes=None)
    monkeypatch.setattr(analysis, 'build_iam', original_builder())
    expected = analysis.build_graphs(snapshot, inventory, max_nodes=None)
    assert json.dumps(actual) == json.dumps(expected)
    assert actual['iam']['status'] == 'partial'


def test_empty_and_generator_inventories_match_original():
    snapshot = synthetic_snapshot(2)
    inventory = resources(snapshot)
    assert iam.build_iam(snapshot, iter(inventory)) == original_builder()(snapshot, iter(inventory))
    assert iam.build_iam(snapshot, iter(())) == original_builder()(snapshot, iter(()))
