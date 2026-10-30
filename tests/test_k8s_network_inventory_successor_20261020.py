"""Kubernetes network inventory routes never claim selected secret-review kinds."""
import importlib.util
from pathlib import Path

import pytest

from peaso.collectors import k8s_network_extensions as network
from peaso.collectors import k8s_network_route_extensions as route
from peaso.collectors.k8s_literal_secret_indicators import NATIVE_KINDS

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'peaso/checks/k8s_network_inventory_successor_20261020.py'
spec = importlib.util.spec_from_file_location('_network_successor_proposal_test', PATH)
proposal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proposal)


def merged_resources():
    return dict(network.RESOURCES, **route.RESOURCES)


@pytest.mark.parametrize('kind', ['Pod', 'ConfigMap', 'Deployment', 'DaemonSet', 'StatefulSet',
    'ReplicaSet', 'Job', 'CronJob', 'ReplicationController', 'PodTemplate'])
def test_every_supported_selected_kind_get_and_list_route_is_disjoint(kind):
    proposal.assert_disjoint(merged_resources(), NATIVE_KINDS)
    version, plural, _ = NATIVE_KINDS[kind]
    prefix = '/api/v1' if version == 'v1' else '/apis/' + version
    for module in (network, route):
        for namespace in ('a', 'review', 'a' * 63):
            for name in ('x', 'selected-name', 'a.b'):
                for path in (prefix + '/' + plural, prefix + '/namespaces/' + namespace + '/' + plural,
                             prefix + '/namespaces/' + namespace + '/' + plural + '/' + name):
                    assert module.match(path) is None
    assert not set(proposal.endpoints(merged_resources())) & {('apps', 'deployments'), ('batch', 'jobs')}

def test_selected_log_native_pod_and_log_routes_are_disjoint():
    module = network
    for namespace in ('a', 'review', 'a' * 63):
        for pod in ('x', 'selected-name', 'a.b'):
            path = '/api/v1/namespaces/' + namespace + '/pods/' + pod
            assert module.match(path) is None and module.match(path + '/log') is None
            assert module.match(path + '/log?container=app&follow=false') is None


@pytest.mark.parametrize('group,plural', [('apps', 'deployments'), ('apps', 'daemonsets'),
    ('apps', 'statefulsets'), ('apps', 'replicasets'), ('batch', 'jobs'), ('batch', 'cronjobs')])
def test_structural_overlap_rejects_arbitrary_namespace_routes(group, plural):
    resources = merged_resources()
    resources['hostile_endpoint'] = [[group], plural, True]
    with pytest.raises(ValueError, match='selected_route_overlap'):
        proposal.assert_disjoint(resources, NATIVE_KINDS)


def test_duplicate_group_plural_and_duplicate_json_keys_reject():
    with pytest.raises(ValueError, match='duplicate_endpoint'):
        proposal.endpoints({'first': [['a.example'], 'routes', True], 'second': [['a.example'], 'routes', False]})
    with pytest.raises(ValueError, match='duplicate_json_key'):
        proposal.read_json(b'{"kind":1,"kind":2}')


