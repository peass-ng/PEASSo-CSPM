"""Reuse topology identities without merging native rows or changing graph proof."""
import copy
from functools import lru_cache
import json

import pytest

from tests.synthetic.benchmark_peaso_network import synthetic_snapshot as provider_snapshot
from tests.synthetic.benchmark_peaso_gcp_lb_workloads import run_stage
from tests.synthetic.benchmark_peaso_network_node_ids import fingerprint, synthetic_snapshot
from tests.synthetic.reference_peaso_network_node_ids import original_builder
from peaso.analysis import common, network
from peaso.snapshot import digest, resources


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_complete_network_findings_graph_and_principals_equal_original(monkeypatch, provider):
    snapshot = provider_snapshot(provider, workloads=24, selectors=6, subnets=2)
    rows, before = resources(snapshot), digest(snapshot)
    actual = run_stage(snapshot, rows)
    monkeypatch.setattr(network, 'build_network', original_builder())
    expected = run_stage(snapshot, rows)
    assert encoded(actual) == encoded(expected)
    assert digest(snapshot) == before


def test_inventory_larger_than_id_cache_hashes_each_selected_resource_once(monkeypatch):
    snapshot = synthetic_snapshot(30)
    rows = resources(snapshot)
    cache = lru_cache(maxsize=16)(common._node_id.__wrapped__)
    monkeypatch.setattr(common, '_node_id', cache)
    with common.analysis_context(snapshot):
        actual = network.build_network(snapshot, rows)
    optimized = cache.cache_info()
    cache.cache_clear()
    with common.analysis_context(snapshot):
        expected = original_builder()(snapshot, rows)
    baseline = cache.cache_info()
    assert encoded(actual) == encoded(expected)
    assert optimized.misses == len(rows)
    assert baseline.misses >= len(rows) * 3
    assert len(actual['nodes']) == len(rows) and len(actual['edges']) == 30


@pytest.mark.parametrize('duplicate_first', [True, False])
def test_duplicate_node_id_rows_keep_each_native_path_and_original_reduction(duplicate_first):
    snapshot = provider_snapshot('aws', workloads=2, selectors=1, subnets=2)
    rows = resources(snapshot)
    original = next(row for row in rows if row['type'] == 'instance')
    duplicate = dict(original, data={**original['data'], 'SubnetId': 'subnet-other',
                                    'NetworkAttributes': {'VpcId': 'vpc-other'}})
    position = rows.index(original)
    rows.insert(position if duplicate_first else position + 1, duplicate)
    before = copy.deepcopy(rows)
    with common.analysis_context(snapshot):
        actual = network.build_network(snapshot, rows)
    with common.analysis_context(snapshot):
        expected = original_builder()(snapshot, rows)
    assert encoded(actual) == encoded(expected)
    assert rows == before
    assert any(edge['source'] == common.node_id(original) for edge in actual['edges'])


@pytest.mark.parametrize('native', [None, 7, ['unhashable', 'native'], {'unhashable': 'native'}])
def test_non_string_id_fallbacks_keep_original_graph(native):
    snapshot = synthetic_snapshot(2)
    rows = resources(snapshot)
    rows[0] = dict(rows[0], native_id=native)
    with common.analysis_context(snapshot):
        actual = network.build_network(snapshot, rows)
    with common.analysis_context(snapshot):
        expected = original_builder()(snapshot, rows)
    assert encoded(actual) == encoded(expected)


def test_matching_native_ids_in_different_scopes_keep_distinct_nodes():
    snapshot = synthetic_snapshot(2)
    rows = resources(snapshot)
    rows.extend(dict(row, scope='projects/other', id='other-' + row['id']) for row in list(rows))
    with common.analysis_context(snapshot):
        actual = network.build_network(snapshot, rows)
    with common.analysis_context(snapshot):
        expected = original_builder()(snapshot, rows)
    assert encoded(actual) == encoded(expected)
    assert len(actual['nodes']) >= len(rows)
    assert len({row['id'] for row in actual['nodes']}) == len(actual['nodes'])


def test_global_id_cache_eviction_during_alias_preparation_does_not_change_graph(monkeypatch):
    snapshot = synthetic_snapshot(8)
    rows = resources(snapshot)
    with common.analysis_context(snapshot):
        expected = original_builder()(snapshot, rows)
    gcp_ref = network.gcp_ref

    def evict(*args):
        common._node_id.cache_clear()
        return gcp_ref(*args)

    monkeypatch.setattr(network, 'gcp_ref', evict)
    with common.analysis_context(snapshot):
        actual = network.build_network(snapshot, rows)
    assert encoded(actual) == encoded(expected)


def test_non_network_resources_are_still_omitted_from_topology():
    snapshot = synthetic_snapshot(1)
    rows = resources(snapshot)
    rows.append(dict(rows[0], type='not_a_network_inventory', native_id='not-selected'))
    with common.analysis_context(snapshot):
        actual = network.build_network(snapshot, rows)
    with common.analysis_context(snapshot):
        expected = original_builder()(snapshot, rows)
    assert encoded(actual) == encoded(expected)
    assert len(actual['nodes']) == 2


def test_empty_and_generator_inputs_keep_original_topology():
    snapshot = synthetic_snapshot(2)
    for rows in ([], resources(snapshot)):
        with common.analysis_context(snapshot):
            actual = network.build_network(snapshot, iter(rows))
        with common.analysis_context(snapshot):
            expected = original_builder()(snapshot, iter(rows))
        assert encoded(actual) == encoded(expected)


def test_benchmark_streaming_verification_matches_canonical_digest():
    value = {'graph': {'nodes': [{'id': '雲', 'value': -0.0}], 'edges': []},
             'findings': [{'evidence': {'value': None, 'native': [True, 7, '```']}}]}
    assert fingerprint(value) == digest(value)
