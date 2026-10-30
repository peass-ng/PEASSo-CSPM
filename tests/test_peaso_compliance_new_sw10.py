"""Signed sw10 Kubernetes checks: strict scoped evidence boundaries."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw10 as sw10


POLICY = {
    'status': 'collected', 'cluster_id': 'fixture',
    'approved_namespaces': ['apps'],
    'approved_node_pool_selector': {'pool': 'safe'},
    'approved_node_selector': {'pool': 'safe'},
    'approved_label_selector': {'team': 'safe'},
    'approved_max_request_timeout': 60,
    'oldestVersionSupported': 'v1.29.0',
    'system_namespaces': ['kube-system'],
    'approved_min_event_qps': 10,
    'in_scope_service_names': ['edge'],
    'required_external_traffic_policy': 'Local',
    'allowed_namespaces': ['apps'],
    'required_subject_kind': 'Group',
    'required_subject_name': 'incident-response',
    'required_role_kind': 'ClusterRole',
    'required_role_name': 'view',
}


def facts(kind, row, *, extras=None, policy=None, scope='*', status='collected'):
    groups = {kind: [row]}
    groups.update(extras or {})
    return {
        'context': {'provider': 'k8s', 'scope': scope, 'created_at': '2026-10-12T12:00:00Z',
                    'metadata': {'cluster_id': 'fixture', 'compliance_policy': copy.deepcopy(POLICY if policy is None else policy),
                                 **{key: {'status': 'attested_complete', 'cluster_id': 'fixture', 'node_count': 1,
                                          'observed_at': '2026-10-12T12:00:00Z', 'max_age_seconds': 600}
                                    for key in ('component_configuration_coverage', 'kube_proxy_pod_coverage')}}},
        'collections': {k: [{'type': k, 'scope': scope, 'status': status if k == kind else 'collected', 'items': rows}]
                        for k, rows in groups.items()},
        **{k: [{'type': k, 'scope': scope, 'data': x} for x in rows] for k, rows in groups.items()},
    }


def pod(**changes):
    row = {'metadata': {'name': 'web', 'namespace': 'apps', 'labels': {'team': 'safe'}},
           'spec': {'nodeName': 'node1', 'nodeSelector': {'pool': 'safe'}, 'serviceAccountName': 'default',
                    'containers': [{'name': 'web'}]},
           'status': {'phase': 'Running'},
           'provenance': {'evidence': 'read-only list'}}
    row.update(changes)
    return row


def component(name, flags):
    row = pod()
    row['spec']['containers'][0]['_component_config'] = {'component': name, 'flags_complete': True, 'flags': flags}
    return row


def check(check_id, row, kind=None, *, extras=None, policy=None, scope='*', status='collected'):
    kind = kind or ('api_discovery' if check_id in sw10.VERSION_IDS else 'rolebinding' if check_id == 'k8s_response_team_required_binding' else sw10.SPECS[check_id]['resource_kind'])
    index = facts(kind, row, extras=extras, policy=policy, scope=scope, status=status)
    item = {'scope': scope} if check_id in sw10.VERSION_IDS or check_id == 'k8s_response_team_required_binding' else row
    return evaluate_check(check_id, item, index)[0]


CASES = [
    ('k8s.cis.consider_external_secret_storage', lambda: (pod(spec={'containers': [{'name': 'web'}], 'volumes': [{'secret': {'secretName': 'one'}}, {'csi': {'driver': 'secrets-store.csi.k8s.io'}}]}), {}, None),
     lambda row, extras, pol: row['spec']['volumes'].pop()),
    ('k8s.cis.controller_manager_rotate_kubelet_server_certificate_true', lambda: (component('kube-controller-manager', {'feature-gates': 'RotateKubeletServerCertificate=true'}), {}, None),
     lambda row, extras, pol: row['spec']['containers'][0]['_component_config']['flags'].__setitem__('feature-gates', 'RotateKubeletServerCertificate=false')),
    ('k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost', lambda: (component('kube-proxy', {'metrics-bind-address': '127.0.0.1:10249'}), {}, None),
     lambda row, extras, pol: row['spec']['containers'][0]['_component_config']['flags'].__setitem__('metrics-bind-address', '0.0.0.0:10249')),
    ('k8s.cis.the_request_timeout_argument_is_set_as_appropriate', lambda: (component('kube-apiserver', {'request-timeout': '30s'}), {}, None),
     lambda row, extras, pol: row['spec']['containers'][0]['_component_config']['flags'].__setitem__('request-timeout', '90s')),
    ('k8s.cis.the_service_account_extend_token_expiration_parameter_is_set_to_false', lambda: (component('kube-apiserver', {'service-account-extend-token-expiration': 'false'}), {}, None),
     lambda row, extras, pol: row['spec']['containers'][0]['_component_config']['flags'].__setitem__('service-account-extend-token-expiration', 'true')),
    ('k8s_pod_pod_deployed_specific_namespace_its_76714f9dfe', lambda: (pod(), {'node': [{'metadata': {'name': 'node1', 'labels': {'pool': 'safe'}}}]}, None),
     lambda row, extras, pol: extras['node'][0]['metadata']['labels'].__setitem__('pool', 'other')),
    ('k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b', lambda: (pod(), {}, None),
     lambda row, extras, pol: row['metadata'].__setitem__('namespace', 'other')),
    ('k8s_pod_pod_deployed_within_specific_namespace_3790c81f90', lambda: (pod(), {}, None),
     lambda row, extras, pol: row['spec']['nodeSelector'].__setitem__('pool', 'other')),
    ('k8s_pod_pod_deployed_within_specific_namespace_62bb9e62c0', lambda: (pod(), {}, None),
     lambda row, extras, pol: row['metadata']['labels'].__setitem__('team', 'other')),
    ('k8s_pod_pod_running_within_specific_namespace_0f3d581358', lambda: (pod(), {}, None),
     lambda row, extras, pol: row['status'].__setitem__('phase', 'Pending')),
    ('k8s_pod_serviceaccount_has_rbac_binding', lambda: (pod(), {
        'rolebinding': [{'metadata': {'name': 'view', 'namespace': 'apps'}, 'subjects': [{'kind': 'ServiceAccount', 'name': 'default', 'namespace': 'apps'}]}],
        'clusterrolebinding': []}, None),
     lambda row, extras, pol: extras['rolebinding'].clear()),
    ('k8s_networkpolicy_has_ingress_rules', lambda: ({'metadata': {'name': 'np', 'namespace': 'apps'}, 'spec': {'ingress': [{}]}}, {}, None),
     lambda row, extras, pol: row['spec'].__setitem__('ingress', [])),
    ('k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c', lambda: ({'metadata': {'name': 'np', 'namespace': 'apps'}, 'spec': {'podSelector': {'matchLabels': {'app': 'web'}, 'matchExpressions': []}}}, {}, None),
     lambda row, extras, pol: row['spec']['podSelector'].__setitem__('matchLabels', {})),
    ('k8s_cluster_version_at_least_oldest_supported', lambda: ({'serverVersion': {'gitVersion': 'v1.30.0'}}, {}, None),
     lambda row, extras, pol: row['serverVersion'].__setitem__('gitVersion', 'v1.28.0')),
    ('k8s_cluster_version_supported', lambda: ({'serverVersion': {'gitVersion': 'v1.30.0'}}, {}, None),
     lambda row, extras, pol: row['serverVersion'].__setitem__('gitVersion', 'v1.29.0')),
    ('k8s.cis.namespace_has_networkpolicy', lambda: ({'metadata': {'name': 'apps'}}, {'networkpolicy': [{'metadata': {'name': 'np', 'namespace': 'apps'}}]}, None),
     lambda row, extras, pol: extras['networkpolicy'].clear()),
    ('k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture', lambda: ({'component': 'kubelet', 'configuration': {'eventRecordQPS': 20}}, {}, None),
     lambda row, extras, pol: row['configuration'].__setitem__('eventRecordQPS', 1)),
    ('k8s_service_external_traffic_policy_matches_required', lambda: ({'metadata': {'name': 'edge', 'namespace': 'apps'}, 'spec': {'type': 'LoadBalancer', 'externalTrafficPolicy': 'Local'}}, {}, None),
     lambda row, extras, pol: row['spec'].__setitem__('externalTrafficPolicy', 'Cluster')),
    ('k8s_ingress_ingress_has_any_associated_ingress_93579100f9', lambda: ({'metadata': {'name': 'edge', 'namespace': 'apps'}, 'spec': {'rules': [{}]}}, {}, None),
     lambda row, extras, pol: row['spec'].__setitem__('rules', [])),
    ('k8s_response_team_required_binding', lambda: ({'metadata': {'name': 'team', 'namespace': 'apps'}, 'roleRef': {'kind': 'ClusterRole', 'name': 'view'}, 'subjects': [{'kind': 'Group', 'name': 'incident-response'}]},
        {'clusterrolebinding': []}, None),
     lambda row, extras, pol: row['subjects'][0].__setitem__('name', 'other')),
]


@pytest.mark.parametrize('check_id,build,make_fail', CASES, ids=[x[0] for x in CASES])
def test_sw10_pass_fail_and_incomplete(check_id, build, make_fail):
    row, extras, pol = build()
    assert check(check_id, row, extras=extras, policy=pol) == 'PASS'
    make_fail(row, extras, pol)
    assert check(check_id, row, extras=extras, policy=pol) == 'FAIL'
    assert check(check_id, row, extras=extras, policy=pol, status='partial') == 'UNKNOWN'


@pytest.mark.parametrize('check_id,build,make_fail', CASES, ids=[x[0] for x in CASES])
def test_sw10_missing_and_malformed_facts(check_id, build, make_fail):
    row, extras, pol = build()
    kind = 'api_discovery' if check_id in sw10.VERSION_IDS else 'rolebinding' if check_id == 'k8s_response_team_required_binding' else sw10.SPECS[check_id]['resource_kind']
    index = facts(kind, row, extras=extras)
    del index['collections'][kind]
    item = {'scope': '*'} if check_id in sw10.VERSION_IDS or check_id == 'k8s_response_team_required_binding' else row
    assert evaluate_check(check_id, item, index)[0] == 'UNKNOWN'
    index = facts(kind, row, extras=extras)
    index['context']['provider'] = 'aws'
    assert evaluate_check(check_id, item, index)[0] == 'UNKNOWN'
    index = facts(kind, row, extras=extras)
    index['collections'][kind][0]['scope'] = 'foreign'
    assert evaluate_check(check_id, item, index)[0] == 'UNKNOWN'
    index = facts(kind, row, extras=extras)
    index['collections'][kind][0]['items'] = 'bad'
    assert evaluate_check(check_id, item, index)[0] == 'UNKNOWN'


def test_sw10_not_applicable_boundaries():
    no_secret = pod()
    assert check('k8s.cis.consider_external_secret_storage', no_secret) == 'NOT_APPLICABLE'
    system = {'metadata': {'name': 'kube-system'}}
    assert check('k8s.cis.namespace_has_networkpolicy', system, extras={'networkpolicy': []}) == 'NOT_APPLICABLE'
    service = {'metadata': {'name': 'internal', 'namespace': 'apps'}, 'spec': {'type': 'ClusterIP'}}
    assert check('k8s_service_external_traffic_policy_matches_required', service) == 'NOT_APPLICABLE'
    config = {'component': 'kube-apiserver', 'configuration': {'eventRecordQPS': 20}}
    assert check('k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture', config) == 'NOT_APPLICABLE'
    other = component('kube-scheduler', {})
    assert check('k8s.cis.the_request_timeout_argument_is_set_as_appropriate', other) == 'NOT_APPLICABLE'


@pytest.mark.parametrize('check_id,build,make_fail', [case for case in CASES if case[0] in {
    'k8s.cis.the_request_timeout_argument_is_set_as_appropriate',
    'k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b',
    'k8s_cluster_version_supported',
    'k8s.cis.namespace_has_networkpolicy',
    'k8s_service_external_traffic_policy_matches_required',
    'k8s_response_team_required_binding',
}], ids=lambda value: value if isinstance(value, str) else None)
def test_sw10_missing_policy_is_unknown(check_id, build, make_fail):
    row, extras, _ = build()
    policy = dict(POLICY)
    policy.pop({
        'k8s.cis.the_request_timeout_argument_is_set_as_appropriate': 'approved_max_request_timeout',
        'k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b': 'approved_namespaces',
        'k8s_cluster_version_supported': 'oldestVersionSupported',
        'k8s.cis.namespace_has_networkpolicy': 'system_namespaces',
        'k8s_service_external_traffic_policy_matches_required': 'required_external_traffic_policy',
        'k8s_response_team_required_binding': 'required_subject_name',
    }[check_id])
    assert check(check_id, row, extras=extras, policy=policy) == 'UNKNOWN'


def test_sw10_semver_prerelease_and_kubelet_coverage():
    version = {'serverVersion': {'gitVersion': 'v1.29.0-rc.1'}}
    assert check('k8s_cluster_version_at_least_oldest_supported', version) == 'FAIL'
    version['serverVersion']['gitVersion'] = 'v1.29.0+build.4'
    assert check('k8s_cluster_version_at_least_oldest_supported', version) == 'PASS'
    config = {'component': 'kubelet', 'configuration': {'eventRecordQPS': 20}}
    index = facts('component_configuration', config)
    index['context']['metadata']['component_configuration_coverage']['status'] = 'unknown'
    assert evaluate_check('k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture', config, index)[0] == 'UNKNOWN'


def target(check_id, row):
    return {'scope': '*'} if check_id in sw10.VERSION_IDS or check_id == 'k8s_response_team_required_binding' else row


@pytest.mark.parametrize('check_id,build,_', CASES, ids=[x[0] for x in CASES])
@pytest.mark.parametrize('mutation', ['cluster', 'wrapper_provider', 'cluster_missing'])
def test_swr_foreign_cluster_and_provider_are_unknown(check_id, build, _, mutation):
    row, extras, policy = build()
    kind = 'api_discovery' if check_id in sw10.VERSION_IDS else 'rolebinding' if check_id == 'k8s_response_team_required_binding' else sw10.SPECS[check_id]['resource_kind']
    index = facts(kind, row, extras=extras, policy=policy)
    if mutation == 'cluster':
        row.setdefault('provenance', {})['cluster_id'] = 'other-cluster'
    elif mutation == 'wrapper_provider':
        index[kind][0]['provider'] = 'aws'
    else:
        index['context']['metadata']['cluster_id'] = ''
        index['context']['metadata']['compliance_policy']['cluster_id'] = ''
    assert evaluate_check(check_id, target(check_id, row), index)[0] == 'UNKNOWN'


def native(row, kind):
    from peaso.collectors.k8s import _native
    return _native(row, kind, 'fixture', '*', kind in {'pod', 'networkpolicy', 'service', 'ingress', 'rolebinding'})


@pytest.mark.parametrize('check_id,kind,row', [
    ('k8s_networkpolicy_has_ingress_rules', 'networkpolicy', {'metadata': {'name': 'np', 'namespace': 'apps'}, 'spec': {}}),
    ('k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c', 'networkpolicy', {'metadata': {'name': 'np', 'namespace': 'apps'}, 'spec': {'podSelector': {}}}),
    ('k8s_ingress_ingress_has_any_associated_ingress_93579100f9', 'ingress', {'metadata': {'name': 'ing', 'namespace': 'apps'}, 'spec': {'defaultBackend': {'service': {'name': 'web', 'port': {'number': 80}}}}}),
])
def test_swr_native_omissions_fail_and_partial_projections_unknown(check_id, kind, row):
    observed = native(row, kind)
    assert check(check_id, observed) == 'FAIL'
    observed.pop('provenance')
    assert check(check_id, observed) == 'UNKNOWN'


@pytest.mark.parametrize('selector', [
    {'matchLabels': {'app': 'web'}},
    {'matchExpressions': [{'key': 'app', 'operator': 'Exists'}]},
    {'matchExpressions': [{'key': 'app', 'operator': 'In', 'values': ['web']}]},
])
def test_swr_native_selector_optional_components(selector):
    row = native({'metadata': {'name': 'np', 'namespace': 'apps'}, 'spec': {'podSelector': selector}}, 'networkpolicy')
    assert check('k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c', row) == 'PASS'


@pytest.mark.parametrize('expression', [
    {'key': '', 'operator': 'Exists', 'values': []},
    {'key': 'bad key', 'operator': 'Exists', 'values': []},
    {'key': 'app', 'operator': 'In', 'values': []},
    {'key': 'app', 'operator': 'NotIn', 'values': 'web'},
    {'key': 'app', 'operator': 'In', 'values': [1]},
    {'key': 'app', 'operator': 'Exists', 'values': ['web']},
    {'key': 'app', 'operator': 'DoesNotExist', 'values': ['web']},
    {'key': 'app', 'operator': 'Exists', '_coverage': {'values': {'status': 'denied'}}},
])
def test_swr_malformed_selector_expression_unknown(expression):
    row = native({'metadata': {'name': 'np', 'namespace': 'apps'}, 'spec': {'podSelector': {'matchExpressions': [expression]}}}, 'networkpolicy')
    assert check('k8s_networkpolicy_network_policy_associated_podselectors_that_92dbc93b4c', row) == 'UNKNOWN'


@pytest.mark.parametrize('check_id,path', [
    (sw10.POD_NODE_SELECTOR_ID, ('spec', 'nodeSelector')),
    (sw10.POD_LABEL_ID, ('metadata', 'labels')),
    (sw10.POD_RUNNING_ID, ('metadata', 'labels')),
])
def test_swr_native_omitted_workload_selectors(check_id, path):
    row = pod()
    row[path[0]].pop(path[1])
    assert check(check_id, native(row, 'pod')) == 'FAIL'
    row.pop('provenance')
    assert check(check_id, row) == 'UNKNOWN'


def test_swr_native_omitted_node_labels_fail():
    n = native({'metadata': {'name': 'node1'}}, 'node')
    assert check(sw10.POD_NODE_POOL_ID, pod(), extras={'node': [n]}) == 'FAIL'


@pytest.mark.parametrize('value,expected', [
    ('1m', 'PASS'), ('1m0s', 'PASS'), ('30.5s', 'PASS'), ('.5s', 'PASS'),
    ('1.s', 'PASS'), ('+30s', 'PASS'), ('1m1ns', 'FAIL'), ('0', 'FAIL'),
    ('-1s', 'FAIL'), ('500us', 'PASS'), ('0.1ns', 'FAIL'), ('9223372036854775808ns', 'UNKNOWN'),
    ('1.5', 'UNKNOWN'), ('1xs', 'UNKNOWN'), ('1h-1m', 'UNKNOWN'),
])
def test_swr_go_duration_literals(value, expected):
    row = native({'metadata': {'name': 'api', 'namespace': 'apps'},
                  'spec': {'containers': [{'command': ['kube-apiserver'], 'args': ['--request-timeout=' + value]}]}}, 'pod')
    assert check('k8s.cis.the_request_timeout_argument_is_set_as_appropriate', row) == expected


@pytest.mark.parametrize('check_id', sorted(sw10.VERSION_IDS))
@pytest.mark.parametrize('version', ['v1.30.0+build..4', 'v1.30.0+.', 'v1.30.0+build.', 'v1.30.0-01', 'v1.3٠.0'])
def test_swr_malformed_semver_build_unknown(check_id, version):
    assert check(check_id, {'serverVersion': {'gitVersion': version}}) == 'UNKNOWN'


@pytest.mark.parametrize('endpoint,expected', [
    ('[[127.0.0.1]]:10249', 'UNKNOWN'), ('127.0.0.1:+10249', 'UNKNOWN'),
    ('127.0.0.1: 10249', 'UNKNOWN'), ('::1:10249', 'UNKNOWN'),
    ('[::1]:10249', 'PASS'), ('127.0.0.1:0', 'PASS'), ('0.0.0.0:10249', 'FAIL'),
])
def test_swr_metrics_endpoint_syntax(endpoint, expected):
    assert check('k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost', component('kube-proxy', {'metrics-bind-address': endpoint})) == expected


@pytest.mark.parametrize('check_id,build,key', [
    ('k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost', lambda: component('kube-proxy', {'metrics-bind-address': '127.0.0.1:10249'}), 'kube_proxy_pod_coverage'),
    ('k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture', lambda: {'component': 'kubelet', 'configuration': {'eventRecordQPS': 20}}, 'component_configuration_coverage'),
])
@pytest.mark.parametrize('change', [{'node_count': 0}, {'node_count': True}, {'max_age_seconds': 0},
                                  {'observed_at': '2026-10-11T12:00:00Z'}, {'observed_at': '2026-10-13T12:00:00Z'},
                                  {'observed_at': '2026-10-12T12:00:00'}, {'cluster_id': 'foreign'}])
def test_swr_coverage_bounds_and_freshness(check_id, build, key, change):
    row = build()
    index = facts(sw10.SPECS[check_id]['resource_kind'], row)
    index['context']['metadata'][key].update(change)
    assert evaluate_check(check_id, row, index)[0] == 'UNKNOWN'


def test_swr_namespace_identity_and_proxy_scope():
    namespace = {'metadata': {'name': 'foreign'}}
    assert check('k8s.cis.namespace_has_networkpolicy', namespace, extras={'networkpolicy': []}, scope='apps') == 'UNKNOWN'
    row = component('kube-proxy', {'metrics-bind-address': '127.0.0.1:10249'})
    assert check('k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost', row, scope='apps') == 'UNKNOWN'


def test_swr_duplicate_resource_identity_unknown():
    row = pod()
    index = facts('pod', row)
    index['collections']['pod'][0]['items'].append(copy.deepcopy(row))
    index['pod'].append({'scope': '*', 'type': 'pod', 'data': copy.deepcopy(row)})
    assert evaluate_check('k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b', row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('config', [{'component': 'future-component', 'flags_complete': True, 'flags': {}},
                                  {'component': None, 'component_identification': 'ordinary_command', 'flags_complete': False}])
def test_swr_malformed_component_projection_unknown(config):
    row = pod()
    row['spec']['containers'][0]['_component_config'] = config
    assert check('k8s.cis.the_request_timeout_argument_is_set_as_appropriate', row) == 'UNKNOWN'


@pytest.mark.parametrize('value', [-1, 1 << 31, True])
def test_swr_malformed_qps_unknown(value):
    assert check('k8s.cis.the_eventrecordqps_argument_is_set_to_a_level_which_ensures_appropriate_event_capture',
                 {'component': 'kubelet', 'configuration': {'eventRecordQPS': value}}) == 'UNKNOWN'


@pytest.mark.parametrize('reference', [{'valueFrom': 'bad'}, {'valueFrom': {'secretKeyRef': {'name': ''}}},
                                     {'valueFrom': {'_coverage': {'secretKeyRef': {'status': 'denied'}}}}])
def test_swr_malformed_or_unavailable_secret_reference_unknown(reference):
    row = pod(spec={'containers': [{'name': 'web', 'env': [reference]}]})
    assert check('k8s.cis.consider_external_secret_storage', row) == 'UNKNOWN'


@pytest.mark.parametrize('volume', [{'secret': {'secretName': ''}}, {'csi': {'driver': ''}},
                                  {'_coverage': {'csi': {'status': 'denied'}}}])
def test_swr_malformed_secret_volume_unknown(volume):
    row = pod(spec={'containers': [{'name': 'web'}], 'volumes': [volume]})
    assert check('k8s.cis.consider_external_secret_storage', row) == 'UNKNOWN'


@pytest.mark.parametrize('subject', [{'kind': 'Alien', 'name': 'x'}, {'kind': 'Group', 'name': ''},
                                   {'kind': 'ServiceAccount', 'name': 'default'}])
def test_swr_malformed_rbac_subject_unknown(subject):
    bindings = {'rolebinding': [], 'clusterrolebinding': [{'metadata': {'name': 'binding'}, 'subjects': [subject]}]}
    assert check('k8s_pod_serviceaccount_has_rbac_binding', pod(), extras=bindings) == 'UNKNOWN'


def test_swr_native_serviceaccount_defaults_and_unavailable_coverage():
    row = pod()
    row['spec'].pop('serviceAccountName')
    binding = native({'metadata': {'name': 'binding', 'namespace': 'apps'},
                      'subjects': [{'kind': 'ServiceAccount', 'name': 'default'}]}, 'rolebinding')
    extras = {'rolebinding': [binding], 'clusterrolebinding': []}
    assert check('k8s_pod_serviceaccount_has_rbac_binding', row, extras=extras) == 'PASS'
    row['spec']['serviceAccountName'] = ''
    assert check('k8s_pod_serviceaccount_has_rbac_binding', row, extras=extras) == 'PASS'
    row['spec'].pop('serviceAccountName')
    row['spec']['_coverage'] = {'serviceAccountName': {'status': 'denied'}}
    assert check('k8s_pod_serviceaccount_has_rbac_binding', row, extras=extras) == 'UNKNOWN'
    row['spec'].pop('_coverage')
    binding.pop('provenance')
    assert check('k8s_pod_serviceaccount_has_rbac_binding', row, extras=extras) == 'UNKNOWN'


@pytest.mark.parametrize('kind,name', [('Role', 'view'), ('FutureRole', 'view'), ('ClusterRole', '')])
def test_swr_malformed_cluster_role_reference_unknown(kind, name):
    row = {'metadata': {'name': 'team'}, 'roleRef': {'kind': kind, 'name': name},
           'subjects': [{'kind': 'Group', 'name': 'incident-response'}]}
    assert check('k8s_response_team_required_binding', row, kind='clusterrolebinding', extras={'rolebinding': []}) == 'UNKNOWN'


@pytest.mark.parametrize('check_id', ['k8s.cis.consider_external_secret_storage', 'k8s_pod_serviceaccount_has_rbac_binding'])
def test_swr_unavailable_native_provenance_unknown(check_id):
    row = pod()
    row['spec'].pop('serviceAccountName')
    row['provenance']['_coverage'] = {'evidence': {'status': 'denied'}}
    assert check(check_id, row, extras={'rolebinding': [], 'clusterrolebinding': []}) == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [('approved_namespaces', ['bad name']), ('approved_node_selector', {'bad key': 'safe'}),
                                       ('approved_node_selector', {'pool': 'bad value'}), ('approved_max_request_timeout', 1 << 63)])
def test_swr_malformed_owner_policy_unknown(field, value):
    policy = copy.deepcopy(POLICY)
    policy[field] = value
    check_id = 'k8s.cis.the_request_timeout_argument_is_set_as_appropriate' if field == 'approved_max_request_timeout' else sw10.POD_NODE_SELECTOR_ID
    row = component('kube-apiserver', {'request-timeout': '30s'}) if field == 'approved_max_request_timeout' else pod()
    assert check(check_id, row, policy=policy) == 'UNKNOWN'


def test_swr_naive_owner_policy_timestamp_unknown():
    policy = copy.deepcopy(POLICY)
    policy.update(observed_at='2026-10-12T12:00:00', max_age_seconds=600)
    row = pod()
    index = facts('pod', row, policy=policy)
    index['context']['created_at'] = '2026-10-12T12:00:00'
    assert evaluate_check('k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b', row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [('required_subject_name', ' '), ('required_role_name', 'bad role'),
                                       ('required_role_name', 'a' * 254)])
def test_swr_malformed_response_team_policy_names(field, value):
    row, extras, _ = CASES[-1][1]()
    policy = copy.deepcopy(POLICY)
    policy[field] = value
    assert check('k8s_response_team_required_binding', row, extras=extras, policy=policy) == 'UNKNOWN'


def test_swr_native_service_defaults_and_partial_projection_unknown():
    check_id = 'k8s_service_external_traffic_policy_matches_required'
    row = native({'metadata': {'name': 'edge', 'namespace': 'apps'}, 'spec': {}}, 'service')
    assert check(check_id, row) == 'NOT_APPLICABLE'
    row['spec']['type'] = 'LoadBalancer'
    assert check(check_id, row) == 'FAIL'
    policy = copy.deepcopy(POLICY)
    policy['required_external_traffic_policy'] = 'Cluster'
    assert check(check_id, row, policy=policy) == 'PASS'
    row['spec']['_coverage'] = {'externalTrafficPolicy': {'status': 'denied'}}
    assert check(check_id, row, policy=policy) == 'UNKNOWN'
    row['spec'].pop('_coverage')
    row.pop('provenance')
    assert check(check_id, row, policy=policy) == 'UNKNOWN'


def test_swr_live_collector_ipv6_flag_limit_remains_unknown():
    row = native({'metadata': {'name': 'proxy', 'namespace': 'apps'}, 'spec': {'containers': [
        {'command': ['kube-proxy'], 'args': ['--metrics-bind-address=[::1]:10249']}]}}, 'pod')
    assert check('k8s.cis.the_kube_proxy_metrics_service_is_bound_to_localhost', row) == 'UNKNOWN'


@pytest.mark.parametrize('check_id,build,make_fail', CASES, ids=[x[0] for x in CASES])
def test_swr_collector_projection_matches_every_predicate(check_id, build, make_fail):
    from peaso.collectors import k8s as collector

    def projected(row, kind):
        if kind == 'api_discovery':
            return {'serverVersion': {'gitVersion': row['serverVersion']['gitVersion']},
                    'provenance': {'cluster_id': 'fixture', 'source': 'GET /apis'}}
        if kind == 'component_configuration':
            return {'component': row['component'],
                    'configuration': collector._configuration_metadata(row['configuration'], row['component']),
                    'provenance': {'cluster_id': 'fixture', 'source': 'operator-supplied metadata', 'runtime_verified': False}}
        row = copy.deepcopy(row)
        for container in row.get('spec', {}).get('containers', []):
            if '_component_config' in container:
                config = container.pop('_component_config')
                container.update(command=[config['component']], args=['--' + key + '=' + value for key, value in config['flags'].items()])
        return native(row, kind)

    row, extras, _ = build()
    kind = 'api_discovery' if check_id in sw10.VERSION_IDS else 'rolebinding' if check_id == 'k8s_response_team_required_binding' else sw10.SPECS[check_id]['resource_kind']
    policy = copy.deepcopy(POLICY)
    policy.pop('status')
    policy['max_policy_items'] = 100
    projected_policy = collector._owner_policy_metadata({'compliance_policy': policy}, 'fixture', '2026-10-12T12:00:00Z')
    assert projected_policy['status'] == 'collected'
    for expected in ('PASS', 'FAIL'):
        observed = projected(row, kind)
        dependencies = {key: [projected(dependency, key) for dependency in rows] for key, rows in extras.items()}
        assert check(check_id, observed, kind=kind, extras=dependencies, policy=projected_policy) == expected
        make_fail(row, extras, None)


def test_swr_descriptions_match_inventory_and_managed_resource_handling():
    row = native({'metadata': {'name': 'np', 'namespace': 'apps',
                               'labels': {'addonmanager.kubernetes.io/mode': 'Reconcile'}}, 'spec': {}}, 'networkpolicy')
    index = facts('networkpolicy', row)
    status, evidence = evaluate_check('k8s_networkpolicy_has_ingress_rules', row, index)
    assert status == 'NOT_APPLICABLE' and evidence['underlying_status'] == 'FAIL'
