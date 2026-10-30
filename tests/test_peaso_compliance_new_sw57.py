"""Isolated signed Kubernetes swarm 57 evaluator tests."""
from __future__ import annotations

import copy
import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw57 as sw
from peaso.checks.facts import MemoIndex

C = 'cluster-57'
S = '*'
P = {'status': 'collected', 'cluster_id': C, 'allowed_public_ports': [{'protocol': 'TCP', 'port': 22}],
     'allowed_ports': [{'protocol': 'TCP', 'port': 22}],
     'network_policy_intent': {'apps/p': {'policyTypes': ['Ingress'], 'ingress': [], 'egress': []}},
     'approved_clock_skew': 2, 'authorized_subjects': ['ServiceAccount:apps/safe'],
     'authorized_utility_namespaces': ['tools'], 'privileged_utility_pods': ['tools/utility', 'apps/utility'], 'classification_label_key': 'classification',
     'approved_values': ['internal'],
     'environment_matrix': {'environment_key': 'environment', 'namespaces': {'apps': 'prod'},
                            'allowed_cross_environment': [], 'subject_environments': {}},
     'resolved_etcd_accounts': {'node1': {'uid': 100, 'gid': 101}},
     'approved_control_namespaces': ['control']}
M = {'cluster_id': C, 'network_policy_enforcement': {'status': 'verified', 'cluster_id': C, 'scope': S, 'policy_union_complete': True},
     'file_metadata_coverage': {'status': 'attested_complete', 'cluster_id': C,
                                'selector_paths': {'/var/lib/etcd': [{'node_name': 'node1', 'path': '/var/lib/etcd'}]}},
     'file_metadata_recursive_coverage': {'status': 'attested_complete', 'cluster_id': C,
                                          'path': '/etc/kubernetes/pki', 'enumeration_complete': True,
                                          'applicable_nodes': ['node1']},
     'compliance_policy': P}


def native(kind, name='x', namespace=None, **extra):
    meta = {'name': name}
    if namespace:
        meta['namespace'] = namespace
    return {'metadata': meta, 'provenance': {'cluster_id': C, 'evidence': 'read-only list'}, **extra}


def facts(kinds, *, policy=None, metadata=None, status=None):
    p = copy.deepcopy(P)
    if policy:
        p.update(policy)
    m = copy.deepcopy(M)
    m['compliance_policy'] = p
    if metadata:
        m.update(metadata)
    context = {'provider': 'k8s', 'scope': S, 'metadata': m, 'created_at': '2026-10-12T00:00:00Z'}
    out = {'context': context, 'collections': {}}
    for kind, rows in kinds.items():
        out['collections'][kind] = [{'type': kind, 'scope': S, 'status': (status or {}).get(kind, 'collected'), 'items': rows}]
        out[kind] = [{'type': kind, 'scope': S, 'data': row} for row in rows]
    return MemoIndex(out)


def check(id, kinds, item=None, **kwargs):
    index = facts(kinds, **kwargs)
    return evaluate_check(id, index['context'] if item is None else item, index)[0]


def np(ingress=None):
    return native('networkpolicy', 'p', 'apps', spec={'podSelector': {}, 'policyTypes': ['Ingress'],
        'ingress': [] if ingress is None else ingress, 'egress': []})


def public(port=22):
    return {'from': [{'ipBlock': {'cidr': '0.0.0.0/0'}}], 'ports': [{'protocol': 'TCP', 'port': port}]}


def role(name='r', namespace='apps', rules=None):
    return native('role', name, namespace, rules=[] if rules is None else rules)


def binding(name='b', namespace='apps', subjects=None, refkind='Role', refname='r'):
    return native('rolebinding', name, namespace, subjects=[] if subjects is None else subjects,
                  roleRef={'kind': refkind, 'name': refname})


def sa(name='sa', namespace='apps'):
    return {'kind': 'ServiceAccount', 'name': name, 'namespace': namespace}


def rule(resources, verbs, group=''):
    return {'apiGroups': [group], 'resources': resources, 'verbs': verbs}


def test_networkpolicy_public_port_predicates():
    for id in (sw.SPECS.keys()):
        if id not in ('k8s_networkpolicy_cluster_has_network_policies_that_1fd253608e',
                      'k8s_networkpolicy_cluster_has_network_policies_that_24d2fc90b0',
                      'k8s_networkpolicy_world_ingress_authorized_ports'):
            continue
        good, bad = np([public(22)]), np([public(80)])
        assert check(id, {'networkpolicy': [good]}, good) == 'PASS'
        assert check(id, {'networkpolicy': [bad]}, bad) == 'FAIL'
        assert check(id, {'networkpolicy': [good]}, good, status={'networkpolicy': 'partial'}) == 'UNKNOWN'
        missing = copy.deepcopy(good)
        missing['spec'].pop('podSelector')
        assert check(id, {'networkpolicy': [missing]}, missing) == 'UNKNOWN'
        field = 'allowed_public_ports' if id.endswith('1fd253608e') else 'allowed_ports'
        if not id.endswith('24d2fc90b0'):
            assert check(id, {'networkpolicy': [good]}, good, policy={field: []}) == 'UNKNOWN'


def test_networkpolicy_intent_and_enforcement():
    id = 'k8s_networkpolicy_has_ingress_or_egress_rules'
    good = np()
    bad = np([public()])
    assert check(id, {'networkpolicy': [good]}, good) == 'PASS'
    assert check(id, {'networkpolicy': [bad]}, bad) == 'FAIL'
    assert check(id, {'networkpolicy': [good]}, good,
                 metadata={'network_policy_enforcement': {'status': 'unknown'}}) == 'UNKNOWN'
    assert check(id, {'networkpolicy': [good]}, good, status={'networkpolicy': 'partial'}) == 'UNKNOWN'
    malformed = np()
    malformed['spec']['policyTypes'] = 'Ingress'
    assert check(id, {'networkpolicy': [malformed]}, malformed) == 'UNKNOWN'


def test_clock_synchronization():
    id = 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4'
    node = native('node', 'node1')
    clock = {'node_name': 'node1', 'source_operation': 'GET /api/v1/nodes/{name}/proxy/healthz',
             'date_header': 'Mon, 12 Oct 2026 00:00:00 GMT',
             'node_response_verified': True, 'trusted_clock_verified': True,
             'trusted_utc_at_response': '2026-10-12T00:00:00Z', 'provenance': {'cluster_id': C}}
    kinds = {'node': [node], 'node_clock': [clock]}
    assert check(id, kinds) == 'PASS'
    clock['date_header'] = 'Mon, 12 Oct 2026 00:00:10 GMT'
    assert check(id, kinds) == 'FAIL'
    assert check(id, {'node': [node]}) == 'UNKNOWN'
    clock['date_header'] = 'malformed'
    assert check(id, kinds) == 'UNKNOWN'
    assert check(id, kinds, status={'node_clock': 'partial'}) == 'UNKNOWN'


def test_privileged_utility_access():
    id = 'k8s_privileged_utility_access'
    pod = native('pod', 'utility', 'tools', spec={'containers': [{'securityContext': {'privileged': True}}]})
    kinds = {'role': [], 'clusterrole': [], 'rolebinding': [], 'clusterrolebinding': [], 'pod': [pod]}
    assert check(id, kinds) == 'PASS'
    pod['metadata']['namespace'] = 'apps'
    assert check(id, kinds) == 'FAIL'
    pod['spec']['containers'][0]['securityContext']['privileged'] = 'yes'
    assert check(id, kinds) == 'UNKNOWN'
    assert check(id, kinds, status={'pod': 'partial'}) == 'UNKNOWN'
    assert check(id, {'pod': [pod]}) == 'UNKNOWN'


def test_privileged_utility_init_and_ephemeral_containers():
    id = 'k8s_privileged_utility_access'
    pod = native('pod', 'utility', 'apps', spec={'containers': [{}],
        'initContainers': [{'securityContext': {'privileged': True}}]})
    kinds = {'role': [], 'clusterrole': [], 'rolebinding': [], 'clusterrolebinding': [], 'pod': [pod]}
    assert check(id, kinds) == 'FAIL'
    pod['spec']['initContainers'] = []
    pod['spec']['ephemeralContainers'] = [{'securityContext': {'privileged': True}}]
    assert check(id, kinds) == 'FAIL'
    pod['spec']['ephemeralContainers'] = [{'securityContext': {'privileged': 'yes'}}]
    assert check(id, kinds) == 'UNKNOWN'


def test_classification_labels():
    id = 'k8s_cluster_appropriate_set_procedures_information_labelling_should_e24bda19'
    ns = native('namespace', 'apps')
    ns['metadata']['labels'] = {'classification': 'internal'}
    kinds = {'namespace': [ns], 'secret_metadata': [], 'pod': [], 'deployment': []}
    assert check(id, kinds, ns) == 'PASS'
    ns['metadata']['labels']['classification'] = 'public'
    assert check(id, kinds, ns) == 'FAIL'
    ns['metadata']['labels'] = []
    assert check(id, kinds, ns) == 'UNKNOWN'
    assert check(id, kinds, ns, status={'secret_metadata': 'partial'}) == 'UNKNOWN'
    assert check(id, {'namespace': [ns]}, ns) == 'UNKNOWN'


def test_environment_separation():
    id = 'k8s_environment_separation'
    ns = native('namespace', 'apps')
    ns['metadata']['labels'] = {'environment': 'prod'}
    kinds = {'namespace': [ns], 'role': [], 'clusterrole': [], 'rolebinding': [], 'clusterrolebinding': [], 'networkpolicy': []}
    assert check(id, kinds, ns) == 'PASS'
    ns['metadata']['labels']['environment'] = 'dev'
    assert check(id, kinds, ns) == 'FAIL'
    ns['metadata']['labels'] = []
    assert check(id, kinds, ns) == 'UNKNOWN'
    assert check(id, kinds, ns, status={'networkpolicy': 'partial'}) == 'UNKNOWN'
    assert check(id, {'namespace': [ns]}, ns) == 'UNKNOWN'


def test_file_ownership():
    for id, path, uid, gid in (
        ('k8s.cis.file_pki_owner', '/etc/kubernetes/pki/ca.crt', 0, 0),
        ('k8s.cis.file_var_lib_etcd_owner', '/var/lib/etcd', 100, 101)):
        f = {'path': path, 'node_name': 'node1', 'uid': uid, 'gid': gid,
             'provenance': {'cluster_id': C}}
        rows = [f]
        if id.endswith('file_pki_owner'):
            rows.append({'path': '/etc/kubernetes/pki', 'node_name': 'node1', 'uid': 0, 'gid': 0,
                         'provenance': {'cluster_id': C}})
        assert check(id, {'file_metadata': rows}, f) == 'PASS'
        f['uid'] = 500
        assert check(id, {'file_metadata': rows}, f) == 'FAIL'
        f.pop('gid')
        assert check(id, {'file_metadata': rows}, f) == 'UNKNOWN'
        assert check(id, {'file_metadata': rows}, f, status={'file_metadata': 'partial'}) == 'UNKNOWN'
        assert check(id, {}, f) == 'UNKNOWN'
        other = dict(f, path='/tmp/other', gid=gid)
        absent = {'file_metadata_recursive_coverage': {'status': 'attested_complete', 'cluster_id': C,
                  'path': '/etc/kubernetes/pki', 'enumeration_complete': True, 'applicable_nodes': []},
                  'file_metadata_coverage': {'status': 'attested_complete', 'cluster_id': C,
                  'selector_paths': {'/var/lib/etcd': []}}}
        assert check(id, {'file_metadata': [other]}, other, metadata=absent) == 'NOT_APPLICABLE'


def test_windows_ipaddressdeny():
    id = 'k8s.cis.the_ipaddressdeny_is_set_to_any'
    node = native('node', 'node1', status={'nodeInfo': {'operatingSystem': 'windows'}})
    config = {'component': 'kubelet', 'node_name': 'node1', 'configuration': {'IPAddressDeny': 'Any'},
              'provenance': {'cluster_id': C}}
    assert check(id, {'node': [node], 'component_configuration': [config]}) == 'PASS'
    config['configuration']['IPAddressDeny'] = 'None'
    assert check(id, {'node': [node], 'component_configuration': [config]}) == 'FAIL'
    config['configuration'].clear()
    assert check(id, {'node': [node], 'component_configuration': [config]}) == 'UNKNOWN'
    assert check(id, {'node': [node]}) == 'UNKNOWN'
    node['status']['nodeInfo']['operatingSystem'] = 'linux'
    assert check(id, {'node': [node]}) == 'NOT_APPLICABLE'


def test_system_masters_group():
    id = 'k8s.cis.avoid_use_of_system_masters_group'
    b = binding(subjects=[{'kind': 'Group', 'name': 'system:masters'}])
    kinds = {'rolebinding': [b], 'clusterrolebinding': []}
    assert check(id, kinds) == 'FAIL'
    b['subjects'] = []
    assert check(id, kinds) == 'UNKNOWN'
    # A bare count/boolean is not observed certificate or provider identity membership.
    assert check(id, kinds, metadata={'identity_group_coverage': {'status': 'attested_complete', 'cluster_id': C, 'certificate_and_provider_memberships_complete': True, 'system_masters_subject_count': 0}}) == 'UNKNOWN'
    b['subjects'] = [{}]
    assert check(id, kinds) == 'UNKNOWN'
    assert check(id, kinds, status={'rolebinding': 'partial'}) == 'UNKNOWN'
    assert check(id, {'rolebinding': [b]}) == 'UNKNOWN'


def test_legacy_psp_binding():
    id = 'k8s.cis.psp_binding_enforced'
    discovery = {'serverVersion': {'gitVersion': 'v1.24.0'}, 'provenance': {'cluster_id': C}}
    psp = native('podsecuritypolicy', 'restricted')
    create = rule(['pods'], ['create'])
    use = dict(rule(['podsecuritypolicies'], ['use'], 'policy'), resourceNames=['restricted'])
    r = role(rules=[create, use])
    b = binding(subjects=[sa()])
    kinds = {'api_discovery': [discovery], 'podsecuritypolicy': [psp],
             'role': [r], 'clusterrole': [], 'rolebinding': [b], 'clusterrolebinding': []}
    assert check(id, kinds) == 'PASS'
    r['rules'] = [create]
    assert check(id, kinds) == 'FAIL'
    r['rules'] = [{}]
    assert check(id, kinds) == 'UNKNOWN'
    assert check(id, kinds, status={'rolebinding': 'partial'}) == 'UNKNOWN'
    assert check(id, {'api_discovery': [discovery]}) == 'UNKNOWN'
    discovery['serverVersion']['gitVersion'] = 'v1.25.0'
    assert check(id, {'api_discovery': [discovery]}) == 'NOT_APPLICABLE'


def test_cross_namespace_pvc_rbac():
    id = 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0'
    ns = native('namespace', 'apps')
    r = role(rules=[rule(['persistentvolumeclaims'], ['get'])])
    b = binding(subjects=[sa(namespace='apps')])
    kinds = {'namespace': [ns], 'role': [r], 'clusterrole': [], 'rolebinding': [b], 'clusterrolebinding': []}
    assert check(id, kinds) == 'PASS'
    b['subjects'][0]['namespace'] = 'other'
    assert check(id, kinds) == 'FAIL'
    r['rules'] = [{}]
    assert check(id, kinds) == 'UNKNOWN'
    assert check(id, kinds, status={'role': 'partial'}) == 'UNKNOWN'
    assert check(id, {'namespace': [ns]}) == 'UNKNOWN'


@pytest.fixture(scope='module', autouse=True)
def _remove_draft_registration_after_module():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.SPECS]


def test_privileged_rbac_and_foreign_scope_are_strict():
    id = 'k8s_privileged_utility_access'
    r = role(rules=[rule(['pods/exec'], ['create'])])
    b = binding(subjects=[sa(name='intruder')])
    kinds = {'role': [r], 'clusterrole': [], 'rolebinding': [b], 'clusterrolebinding': [], 'pod': []}
    assert check(id, kinds) == 'FAIL'
    b['subjects'] = [sa(name='safe')]
    assert check(id, kinds) == 'PASS'
    index = facts(kinds)
    index['context']['scope'] = 'foreign'
    assert evaluate_check(id, index['context'], index)[0] == 'UNKNOWN'


def test_environment_cross_namespace_binding_and_selector():
    id = 'k8s_environment_separation'
    apps = native('namespace', 'apps')
    apps['metadata']['labels'] = {'environment': 'prod'}
    dev = native('namespace', 'dev')
    dev['metadata']['labels'] = {'environment': 'dev'}
    r = role(rules=[])
    b = binding(subjects=[sa(namespace='dev')])
    kinds = {'namespace': [apps, dev], 'role': [r], 'clusterrole': [],
             'rolebinding': [b], 'clusterrolebinding': [], 'networkpolicy': []}
    matrix = {'environment_matrix': {'environment_key': 'environment',
        'namespaces': {'apps': 'prod', 'dev': 'dev'}, 'subject_environments': {},
        'allowed_cross_environment': []}}
    assert check(id, kinds, apps, policy=matrix) == 'FAIL'
    kinds['rolebinding'] = []
    policy = np([{'from': [{'namespaceSelector': {'matchLabels': {'environment': 'dev'}}}]}])
    kinds['networkpolicy'] = [policy]
    assert check(id, kinds, apps, policy=matrix) == 'FAIL'
    kinds['networkpolicy'] = []
    assert check(id, kinds, apps, policy=matrix) == 'PASS'


def test_environment_ingress_uses_peer_as_source():
    id = 'k8s_environment_separation'
    apps = native('namespace', 'apps')
    apps['metadata']['labels'] = {'environment': 'prod'}
    dev = native('namespace', 'dev')
    dev['metadata']['labels'] = {'environment': 'dev'}
    policy = np([{'from': [{'namespaceSelector': {'matchLabels': {'environment': 'dev'}}}]}])
    kinds = {'namespace': [apps, dev], 'role': [], 'clusterrole': [],
             'rolebinding': [], 'clusterrolebinding': [], 'networkpolicy': [policy]}
    matrix = {'environment_matrix': {'environment_key': 'environment',
        'namespaces': {'apps': 'prod', 'dev': 'dev'}, 'subject_environments': {},
        'allowed_cross_environment': [['prod', 'dev']]}}
    assert check(id, kinds, apps, policy=matrix) == 'FAIL'
    matrix['environment_matrix']['allowed_cross_environment'] = [['dev', 'prod']]
    assert check(id, kinds, apps, policy=matrix) == 'PASS'


def test_etcd_missing_selector_coverage_is_unknown():
    id = 'k8s.cis.file_var_lib_etcd_owner'
    other = {'path': '/tmp/other', 'node_name': 'node1', 'uid': 0, 'gid': 0,
             'provenance': {'cluster_id': C}}
    coverage = {'file_metadata_coverage': {'status': 'attested_complete',
                'cluster_id': C, 'selector_paths': {}}}
    assert check(id, {'file_metadata': [other]}, other, metadata=coverage) == 'UNKNOWN'


def test_psp_use_must_cover_pod_create_namespace():
    id = 'k8s.cis.psp_binding_enforced'
    discovery = {'serverVersion': {'gitVersion': 'v1.24.0'}, 'provenance': {'cluster_id': C}}
    create_role = role('create', 'apps', [rule(['pods'], ['create'])])
    use_role = role('use', 'other', [dict(rule(['podsecuritypolicies'], ['use'], 'policy'),
                                     resourceNames=['restricted'])])
    create_binding = binding('create-binding', 'apps', [sa()], refname='create')
    use_binding = binding('use-binding', 'other', [sa()], refname='use')
    kinds = {'api_discovery': [discovery], 'podsecuritypolicy': [native('podsecuritypolicy', 'restricted')],
             'namespace': [native('namespace', 'apps'), native('namespace', 'other')],
             'role': [create_role, use_role], 'clusterrole': [],
             'rolebinding': [create_binding, use_binding], 'clusterrolebinding': []}
    assert check(id, kinds) == 'FAIL'
    use_role['metadata']['namespace'] = 'apps'
    use_binding['metadata']['namespace'] = 'apps'
    assert check(id, kinds) == 'PASS'


def test_recursive_file_coverage_and_pvc_control_exemption():
    file_id = 'k8s.cis.file_pki_owner'
    f = {'path': '/etc/kubernetes/pki/ca.crt', 'node_name': 'node1', 'uid': 0, 'gid': 0,
         'provenance': {'cluster_id': C}}
    assert check(file_id, {'file_metadata': [f]}, f,
                 metadata={'file_metadata_recursive_coverage': {'status': 'unknown'}}) == 'UNKNOWN'
    assert check(file_id, {'file_metadata': []}, f) == 'UNKNOWN'
    assert check('k8s.cis.file_var_lib_etcd_owner', {'file_metadata': []}, f) == 'UNKNOWN'
    pvc_id = 'k8s_persistentvolume_persistentvolumeclaims_pvc_permissions_do_not_allow_00af04b0'
    r = role('r', 'control', [rule(['persistentvolumeclaims'], ['get'])])
    b = binding('b', 'control', [sa(namespace='apps')])
    kinds = {'namespace': [native('namespace', 'apps'), native('namespace', 'control')],
             'role': [r], 'clusterrole': [], 'rolebinding': [b], 'clusterrolebinding': []}
    assert check(pvc_id, kinds) == 'PASS'


@pytest.mark.parametrize("coverage", [
    None,
    {'status': 'attested_complete', 'cluster_id': C, 'certificate_and_provider_memberships_complete': True, 'system_masters_subject_count': 0},
    {'status': 'attested_complete', 'cluster_id': C, 'certificate_and_provider_memberships_complete': True, 'system_masters_subject_count': True},
    {'status': 'attested_complete', 'cluster_id': C, 'certificate_and_provider_memberships_complete': True, 'system_masters_subject_count': 1},
    {'status': 'attested_complete', 'cluster_id': 'foreign', 'certificate_and_provider_memberships_complete': True, 'system_masters_subject_count': 0},
    {'status': 'attested_complete', 'cluster_id': C, 'certificate_and_provider_memberships_complete': 'true', 'system_masters_subject_count': 0},
], ids=['absent', 'bare-zero', 'bool-zero', 'one', 'foreign', 'malformed'])
def test_masters_unobserved_membership_claims_cannot_pass(coverage):
    kinds = {'rolebinding': [binding(subjects=[])], 'clusterrolebinding': []}
    metadata = {} if coverage is None else {'identity_group_coverage': coverage}
    assert check('k8s.cis.avoid_use_of_system_masters_group', kinds, metadata=metadata) == 'UNKNOWN'


def test_masters_known_binding_fails_despite_bare_clean_claim():
    kinds = {'rolebinding': [binding(subjects=[{'kind': 'Group', 'name': 'system:masters'}])], 'clusterrolebinding': []}
    claim = {'identity_group_coverage': {'status': 'attested_complete', 'cluster_id': C,
             'certificate_and_provider_memberships_complete': True, 'system_masters_subject_count': 0}}
    assert check('k8s.cis.avoid_use_of_system_masters_group', kinds, metadata=claim) == 'FAIL'


def test_masters_partial_source_remains_unknown_despite_bare_clean_claim():
    kinds = {'rolebinding': [binding(subjects=[])], 'clusterrolebinding': []}
    claim = {'identity_group_coverage': {'status': 'attested_complete', 'cluster_id': C,
             'certificate_and_provider_memberships_complete': True, 'system_masters_subject_count': 0}}
    assert check('k8s.cis.avoid_use_of_system_masters_group', kinds, metadata=claim,
                 status={'rolebinding': 'partial'}) == 'UNKNOWN'
