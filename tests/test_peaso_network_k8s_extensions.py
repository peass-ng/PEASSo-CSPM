"""Installed CNI/mesh discovery, Multus parsing and native network projection."""
import json
import pytest
from peaso.collectors import k8s
from peaso.analysis.network_observations import multus_networks
from tests.test_peaso_collectors_azurek8s import FakeKube, collection, kube_item, kube_list
from tests.test_peaso_network_managed_services import topology, node, linked


def test_cilium_served_version_network_fields_reach_map_and_agent():
    calls = []
    def native(path, params):
        calls.append(path)
        if path == '/apis':
            return {'groups': [{'name': 'cilium.io', 'versions': [{'version': 'v2'}]}]}
        if path == '/apis/cilium.io/v2':
            return {'resources': [{'name': 'ciliumegressgatewaypolicies', 'namespaced': False, 'verbs': ['get', 'list']}]}
        assert path == '/apis/cilium.io/v2/ciliumegressgatewaypolicies'
        return kube_list([kube_item('egress', namespace='', apiVersion='cilium.io/v2', kind='CiliumEgressGatewayPolicy',
            spec={'destinationCIDRs': ['10.0.0.0/8'], 'egressGateway': {'egressIP': '192.0.2.4', 'nodeSelector': {'matchLabels': {'role': 'gateway'}}}})])
    snap = k8s.collect({'scopes': ['team-a']}, ['cilium_egress_gateway_policy'], api=FakeKube(native))
    envelope = collection(snap, 'cilium_egress_gateway_policy')
    assert envelope['status'] == 'collected', envelope.get('error')
    row = envelope['items'][0]
    graph, ai = topology('k8s', [('cilium_egress_gateway_policy', row['id'], envelope['scope'], row)], {'cluster_id': snap['metadata']['cluster_id']})
    assert '192.0.2.4' in json.dumps(ai)
    assert '192.0.2.4' in json.dumps(graph)
    assert '/apis/cilium.io/v2/ciliumegressgatewaypolicies' in calls


def test_absent_network_extension_is_explicit_while_denied_discovery_is_unknown():
    kind = 'metallb_ip_address_pool'
    snap = k8s.collect({'scopes': ['team-a']}, [kind], api=FakeKube(lambda path, params: {'groups': []}))
    row = collection(snap, kind)
    assert row['status'] == 'empty'
    assert row['applicability']['observed_resource_absent'] == 'ipaddresspools'
    def denied(path, params):
        raise k8s.K8sReadError('forbidden', 403)
    snap = k8s.collect({'scopes': ['team-a'], 'options': {'retries': 0}}, [kind], api=FakeKube(denied))
    assert collection(snap, kind)['status'] not in {'empty', 'collected'}


def test_calico_discovery_falls_back_to_native_crd_group_without_scope_collision():
    from peaso.collectors.k8s_network_extensions import match
    assert match('/apis/metallb.io/v1/namespaces/metallb-system/bgppeers') == 'metallb_bgp_peer'
    assert match('/apis/projectcalico.org/v1/bgppeers') == 'calico_bgp_peer'
    def native(path, params):
        if path == '/apis':return {'groups': [{'name': 'crd.projectcalico.org', 'versions': [{'version': 'v1'}]}]}
        if path == '/apis/crd.projectcalico.org/v1':
            return {'resources': [{'name': 'ippools', 'namespaced': False, 'verbs': ['get', 'list']}]}
        assert path == '/apis/crd.projectcalico.org/v1/ippools'
        return kube_list([kube_item('pool', namespace='', apiVersion='crd.projectcalico.org/v1', kind='IPPool', spec={'cidr': '10.244.0.0/16', 'natOutgoing': True})])
    snap = k8s.collect({'scopes': ['team-a']}, ['calico_ip_pool'], api=FakeKube(native))
    assert collection(snap, 'calico_ip_pool')['status'] == 'collected'
    assert '10.244.0.0/16' in json.dumps(collection(snap, 'calico_ip_pool')['items'])


def test_nad_projection_parses_native_json_and_excludes_plugin_credentials():
    from peaso.collectors.k8s_network_extensions import project
    raw = kube_list([kube_item('extra', spec={'config': json.dumps({'cniVersion': '0.4.0', 'type': 'macvlan', 'master': 'eth1',
        'ipam': {'type': 'host-local', 'subnet': '10.20.0.0/24', 'gateway': '10.20.0.1', 'kubeconfig': 'SECRET_SENTINEL'},
        'args': {'network': 'SECRET_SENTINEL'}, 'credentials': {'password': 'SECRET_SENTINEL'}})})])
    safe = project(raw, 'network_attachment_definition')
    assert 'SECRET_SENTINEL' not in json.dumps(safe)
    assert '10.20.0.0/24' in json.dumps(safe)
    assert 'eth1' in json.dumps(safe)


def test_multus_native_annotations_link_exact_cluster_and_namespace_and_reach_agent():
    pod = {'metadata': {'name': 'pod', 'namespace': 'apps', 'uid': 'pod', 'annotations': {
        'k8s.v1.cni.cncf.io/networks': json.dumps([{'name': 'shared/extra', 'interface': 'net1', 'ips': ['10.20.0.4/24'],
            'cni-args': {'network': 'SECRET_SENTINEL'}}]),
        'k8s.v1.cni.cncf.io/network-status': json.dumps([{'name': 'shared/extra', 'interface': 'net1', 'ips': ['10.20.0.4'],
            'default': False, 'secret': 'SECRET_SENTINEL'}])}}, 'spec': {}}
    nad = {'metadata': {'name': 'extra', 'namespace': 'shared', 'uid': 'extra'}, 'spec': {'config': {'type': 'macvlan'}}}
    facts = multus_networks(pod)
    assert facts[0]['namespace'] == 'shared' and facts[0]['name'] == 'extra'
    assert 'SECRET_SENTINEL' not in json.dumps(facts)
    # Collection keeps the Multus attachment facts but never the CNI arguments or plugin data.
    collected = k8s._sanitize(pod)
    assert 'SECRET_SENTINEL' not in json.dumps(collected)
    assert multus_networks(collected) == facts
    graph, ai = topology('k8s', [('pod', 'pod', 'apps', collected), ('network_attachment_definition', 'extra', 'shared', nad)], {'cluster_id': 'cluster'})
    assert linked(graph, node(graph, 'pod', 'pod'), node(graph, 'network_attachment_definition', 'extra'))
    assert '10.20.0.4' in json.dumps(ai)
    pod_data = next(r['data'] for r in ai['inventory'] if r['type'] == 'pod')
    assert '10.20.0.4' in json.dumps(pod_data)
    assert 'SECRET_SENTINEL' not in json.dumps(ai)


def test_traefik_native_served_routes_reach_service_map_and_agent_without_headers():
    def native(path, params):
        if path == '/apis':
            return {'groups': [{'name': 'traefik.io', 'versions': [{'version': 'v1alpha1'}]}]}
        if path == '/apis/traefik.io/v1alpha1':
            return {'resources': [{'name': 'ingressroutes', 'namespaced': True, 'verbs': ['list']}]}
        assert path == '/apis/traefik.io/v1alpha1/namespaces/team-a/ingressroutes'
        return kube_list([kube_item('route', apiVersion='traefik.io/v1alpha1', kind='IngressRoute',
            spec={'entryPoints': ['websecure'], 'routes': [{'match': 'Host(`app.example`)', 'kind': 'Rule',
                'services': [{'name': 'backend', 'port': 8443}]}], 'headers': {'Authorization': 'SECRET_SENTINEL'}})])
    snap = k8s.collect({'scopes': ['team-a']}, ['traefik_ingress_route'], api=FakeKube(native))
    result = collection(snap, 'traefik_ingress_route')
    assert result['status'] == 'collected', result.get('error')
    row = result['items'][0]
    graph, ai = topology('k8s', [('traefik_ingress_route', row['id'], 'team-a', row),
        ('service', 'backend', 'team-a', {'metadata': {'name': 'backend', 'namespace': 'team-a', 'uid': 'backend'}, 'spec': {}})],
        {'cluster_id': snap['metadata']['cluster_id']})
    assert linked(graph, node(graph, 'traefik_ingress_route', row['id']), node(graph, 'service', 'backend'))
    assert '8443' in json.dumps(ai) and 'SECRET_SENTINEL' not in json.dumps(ai)


def test_uninstalled_ingress_extension_has_explicit_absence():
    snap = k8s.collect({'scopes': ['team-a']}, ['envoy_backend'], api=FakeKube(lambda path, params: {'groups': []}))
    result = collection(snap, 'envoy_backend')
    assert result['status'] == 'empty'
    assert result['applicability']['observed_resource_absent'] == 'backends'
