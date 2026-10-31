"""Shared native projections retain credential filtering and exact graph paths."""
import copy
import gc
from unittest.mock import patch
import weakref

import pytest

from tests.synthetic.benchmark_peaso_network import run_stage as network_stage, synthetic_snapshot as network_snapshot
from tests.synthetic.benchmark_peaso_network_facts import RepeatedNetworkFacts
from tests.synthetic.benchmark_peaso_gcp_lb_workloads import run_stage, synthetic_snapshot
from peaso.analysis import network, network_facts, network_observations as observations, network_services
from peaso.analysis.network_catalog_refs import references as catalog_references
from peaso.snapshot import make_snapshot, resources


def test_native_tree_and_observations_are_computed_once_without_input_mutation():
    data = {'network': 'projects/p/global/networks/one', 'properties': {'port': 443}}
    before = copy.deepcopy(data)
    facts = network_facts.NetworkFacts(data)
    with patch.object(observations, 'network_observations', wraps=observations.network_observations) as extract:
        first = facts.observations()
        assert facts.observations() is first
        assert extract.call_count == 1
    original = network_services.project_network_data
    roots = []

    def counted(value):
        if value is data:
            roots.append(1)
        return original(value)

    with patch.object(network_services, 'project_network_data', counted):
        projected = facts.projected()
        assert facts.projected() is projected
        assert len(roots) == 1
    assert projected == original(data)
    assert data == before


def test_null_projection_is_cached_and_failed_projection_retries():
    facts = network_facts.NetworkFacts(None)
    with patch.object(network_services, 'project_network_data', return_value=None) as project:
        assert facts.projected() is None
        assert facts.projected() is None
        assert project.call_count == 1
    failed = network_facts.NetworkFacts({})
    with patch.object(network_services, 'project_network_data', side_effect=[ValueError('recorded'), {}]) as project:
        with pytest.raises(ValueError, match='recorded'):
            failed.projected()
        assert failed.projected() == {}
        assert project.call_count == 2


def test_complete_stage_extracts_each_graph_resource_once():
    snapshot = synthetic_snapshot(8)
    inventory = resources(snapshot)
    original = observations.network_observations
    called = []

    def counted(data, **options):
        called.append(id(data))
        return original(data, **options)

    with patch.object(observations, 'network_observations', counted):
        actual = run_stage(snapshot, inventory)
    assert len(called) == len(inventory)
    assert len(set(called)) == len(inventory)
    with patch.object(network_facts, 'NetworkFacts', RepeatedNetworkFacts):
        assert run_stage(snapshot, inventory) == actual


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'k8s'])
def test_complete_network_workflows_equal_repeated_native_traversals(provider):
    snapshot = network_snapshot(provider, workloads=24, selectors=12, subnets=2)
    before = copy.deepcopy(snapshot)
    with patch.object(network_facts, 'NetworkFacts', RepeatedNetworkFacts), patch.object(observations, '_field_traits', lambda key: None):
        expected = network_stage(snapshot)
    assert network_stage(snapshot) == expected
    assert snapshot == before


def row(provider='gcp', **data):
    return {'provider': provider, 'scope': 'projects/p', 'type': 'cloudrun_service',
            'native_id': 'service', 'id': 'resource-service', 'data': data}


def test_duplicate_node_ids_keep_each_native_reference_and_last_node_observations():
    snapshot = make_snapshot('gcp', ['projects/p'], [])
    inventory = [row(name='one', network='projects/p/global/networks/one'),
                 row(name='two', network='projects/p/global/networks/two')]
    with patch.object(network_facts, 'NetworkFacts', RepeatedNetworkFacts):
        expected = network.build_network(snapshot, inventory)
    assert network.build_network(snapshot, inventory) == expected
    assert any('networks/one' in str(n) for n in expected['nodes'])
    assert any('networks/two' in str(n) for n in expected['nodes'])


@pytest.mark.parametrize('reader', [network.references, catalog_references, network_services.service_references])
@pytest.mark.parametrize('native', [None, [], [{'network': 'projects/p/global/networks/one'}], {'network': 'projects/p/global/networks/one'}])
def test_standalone_readers_keep_nonobject_and_empty_native_behavior(reader, native):
    resource = row()
    resource['data'] = native

    def outcome():
        try:
            return 'value', list(reader(resource))
        except (TypeError, KeyError, AttributeError, ValueError) as error:
            return 'error', type(error)

    with patch.object(network_facts, 'NetworkFacts', RepeatedNetworkFacts):
        expected = outcome()
    assert outcome() == expected


@pytest.mark.parametrize('network_context', [False, True])
def test_field_traits_keep_credentials_multus_and_projected_path_rules(network_context):
    data = {'properties': {'networkProfile': {'subnetId': 'subnet-one', 'enabled': True},
        'endpoint': 'https://user:password@example.test/path?token=private#hidden',
        'password': {'network': 'forbidden-password'}, 'environmentVariables': {'network': 'forbidden-environment'},
        'command': {'endpoint': 'forbidden-command'}, 'environment': {'workerPools': [{'network': 'native-worker-network'}]}},
        'metadata': {'annotations': {'arbitrary': 'forbidden-annotation',
            'k8s.v1.cni.cncf.io/networks': '[{"name":"net-a","namespace":"ns","ips":["10.1.0.2"]}]'}},
        'NetworkAttributes': [{'path': 'native.endpoint', 'name': 'endpoint', 'value': 'https://user:password@example.test/?token=private'},
                              {'path': 'native.secret', 'name': 'secretToken', 'value': 'forbidden-secret'},
                              {'path': 'privateNetwork.enabled', 'name': 'customToggle', 'value': True}]}
    before = copy.deepcopy(data)
    with patch.object(observations, '_field_traits', lambda key: None):
        expected = observations.network_observations(data, network_context=network_context)
    actual = observations.network_observations(data, network_context=network_context)
    assert actual == expected
    assert data == before
    assert 'forbidden-' not in str(actual)
    assert 'user:password' not in str(actual) and 'token=private' not in str(actual)
    assert any(row['value'] == 'ns/net-a' for row in actual)


def test_schema_cache_is_bounded_and_long_or_custom_keys_use_original_path():
    observations._field_traits.cache_clear()
    data = {f'field{i}': True for i in range(4200)}
    observations.network_observations(data)
    assert observations._field_traits.cache_info().currsize == 4096
    before = observations._field_traits.cache_info()

    class CustomKey(str):
        pass

    unusual = {'network' * 40: True, CustomKey('network'): 'native-network'}
    actual = observations.network_observations(unusual)
    assert observations._field_traits.cache_info() == before
    with patch.object(observations, '_field_traits', lambda key: None):
        assert observations.network_observations(unusual) == actual
    observations._field_traits.cache_clear()


def test_prepared_facts_do_not_create_garbage_collection_cycles():
    enabled = gc.isenabled()
    gc.disable()
    try:
        class Prepared(network_facts.NetworkFacts):
            pass
        facts = Prepared({'network': 'native-network'})
        facts.observations()
        facts.projected()
        ref = weakref.ref(facts)
        del facts
        assert ref() is None
    finally:
        if enabled:
            gc.enable()


def test_graph_releases_projected_native_trees_as_each_resource_finishes():
    snapshot = synthetic_snapshot(16)
    inventory = resources(snapshot)
    originals = {id(row['data']) for row in inventory}
    references, peak = [], []
    original = network_services.project_network_data

    class Projected(dict):
        pass

    def counted(data):
        value = original(data)
        if id(data) in originals and isinstance(value, dict):
            value = Projected(value)
            references.append(weakref.ref(value))
            peak.append(sum(ref() is not None for ref in references))
        return value

    enabled = gc.isenabled()
    gc.disable()
    try:
        with patch.object(network_services, 'project_network_data', counted):
            graph = network.build_network(snapshot, inventory)
        assert graph['nodes']
        assert len(references) == len(inventory)
        assert max(peak) <= 2
        assert all(ref() is None for ref in references)
    finally:
        if enabled:
            gc.enable()
