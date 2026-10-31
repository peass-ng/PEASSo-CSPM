"""Kubernetes network inventory routes never claim selected secret-review kinds."""
import pytest

from peaso.collectors import k8s_network_extensions as network
from peaso.collectors import k8s_network_route_extensions as route
from peaso.collectors.k8s_literal_secret_indicators import NATIVE_KINDS

def merged_endpoints():
    return {(group, plural) for groups, plural, _ in dict(network.RESOURCES, **route.RESOURCES).values()
            for group in groups}


@pytest.mark.parametrize('kind', ['Pod', 'ConfigMap', 'Deployment', 'DaemonSet', 'StatefulSet',
    'ReplicaSet', 'Job', 'CronJob', 'ReplicationController', 'PodTemplate'])
def test_every_supported_selected_kind_get_and_list_route_is_disjoint(kind):
    version, plural, _ = NATIVE_KINDS[kind]
    prefix = '/api/v1' if version == 'v1' else '/apis/' + version
    for module in (network, route):
        for namespace in ('a', 'review', 'a' * 63):
            for name in ('x', 'selected-name', 'a.b'):
                for path in (prefix + '/' + plural, prefix + '/namespaces/' + namespace + '/' + plural,
                             prefix + '/namespaces/' + namespace + '/' + plural + '/' + name):
                    assert module.match(path) is None
    assert not merged_endpoints() & {('apps', 'deployments'), ('batch', 'jobs')}

def test_selected_log_native_pod_and_log_routes_are_disjoint():
    module = network
    for namespace in ('a', 'review', 'a' * 63):
        for pod in ('x', 'selected-name', 'a.b'):
            path = '/api/v1/namespaces/' + namespace + '/pods/' + pod
            assert module.match(path) is None and module.match(path + '/log') is None
            assert module.match(path + '/log?container=app&follow=false') is None
