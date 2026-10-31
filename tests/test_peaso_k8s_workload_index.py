"""Indexed workload candidates retain selectors, identity facts and uncertainty."""
from collections import defaultdict
import copy
import gc
from unittest.mock import patch
import weakref

import pytest

from tests.synthetic.benchmark_peaso_k8s_workloads import LinearK8sWorkloads, synthetic_snapshot
from peaso.analysis import k8s_workload_index as indexed
from peaso.principal_exposure import _cluster, project
from peaso.snapshot import resources, seal, validate


def row(kind, name='one', namespace='default', cluster='cluster', **data):
    return {'id': f'{cluster}:{namespace}:{kind}:{name}', 'type': kind, 'scope': cluster + '/' + str(namespace),
            'data': {'metadata': {'name': name, 'namespace': namespace}, 'provenance': {'cluster_id': cluster}, **data}}


def outcome(function):
    try:
        return 'value', function()
    except (KeyError, TypeError, AttributeError) as error:
        return 'error', type(error)


@pytest.mark.parametrize('invalid_labels', [False, True])
def test_all_service_selectors_match_literal_scans(invalid_labels):
    by_type = defaultdict(list)
    for cluster in ('one', 'two'):
        for namespace in ('a', 'b', 'default'):
            for i, labels in enumerate(({}, {'app': 'same', 'id': '0'}, {'app': 'same', 'id': '1'},
                                       {'app': None}, {'structured': {'value': 'one'}})):
                by_type['pod'].append(row('pod', str(i), namespace, cluster,
                    metadata={'name': str(i), 'namespace': namespace, 'labels': labels}))
            if invalid_labels:
                by_type['pod'].append(row('pod', 'invalid', namespace, cluster,
                    metadata={'name': 'invalid', 'namespace': namespace, 'labels': None}))
    original = copy.deepcopy(by_type)
    snapshot = {'collections': []}
    reference = LinearK8sWorkloads(snapshot, by_type, _cluster)
    actual = indexed.K8sWorkloadIndex(snapshot, by_type, _cluster)
    for cluster in ('one', 'two', 'uncollected'):
        for namespace in ('a', 'b', 'default', 'missing'):
            for selector in ({}, None, {'app': 'same'}, {'app': 'same', 'id': '1'}, {'absent': None},
                             {'app': None}, {'structured': {'value': 'one'}}, ['invalid']):
                service = row('service', namespace=namespace, cluster=cluster, spec={'selector': selector})
                assert outcome(lambda: actual.pods(service)) == outcome(lambda: reference.pods(service))
    assert by_type == original


def test_empty_selectors_and_missing_pods_do_not_read_bad_owner_metadata():
    workload = indexed.K8sWorkloadIndex({'collections': []}, defaultdict(list), _cluster)
    service = row('service', metadata=None, spec={'selector': {'app': 'one'}})
    assert workload.pods(service) == []
    workload.by_type['pod'].append(row('pod', metadata=None))
    service['data']['spec']['selector'] = {}
    assert workload.pods(service) == []


def test_label_index_chooses_rare_key_without_scanning_shared_label_matches():
    gets = []

    class Labels(dict):
        def get(self, name, *args):
            gets.append(name)
            return super().get(name, *args)

    by_type = defaultdict(list)
    for i in range(300):
        by_type['pod'].append(row('pod', str(i), metadata={'name': str(i),
            'labels': Labels(app='shared', instance=str(i))}))
    workload = indexed.K8sWorkloadIndex({'collections': []}, by_type, _cluster)
    for i in range(300):
        service = row('service', str(i), spec={'selector': {'app': 'shared', 'instance': str(i)}})
        assert workload.pods(service) == [by_type['pod'][i]]
    assert len(gets) == 600


def test_label_index_memory_admission_never_removes_pods_or_skips_later_scopes(monkeypatch):
    monkeypatch.setattr(indexed, 'MAX_LABEL_KEYS', 1)
    by_type = defaultdict(list)
    for namespace in ('one', 'two'):
        for i in range(10):
            by_type['pod'].append(row('pod', str(i), namespace=namespace,
                metadata={'name': str(i), 'namespace': namespace, 'labels': {'app': 'shared', 'instance': str(i)}}))
    snapshot = {'collections': []}
    index = indexed.K8sWorkloadIndex(snapshot, by_type, _cluster)
    reference = LinearK8sWorkloads(snapshot, by_type, _cluster)
    for namespace in ('one', 'two', 'one'):
        service = row('service', namespace=namespace, spec={'selector': {'app': 'shared'}})
        assert index.pods(service) == reference.pods(service)
    assert all(label_index is None for _, label_index in index.pod_labels.values())
    assert index.remaining_label_keys == 1


def test_completed_indexes_release_resources_while_cyclic_gc_is_paused():
    by_type = defaultdict(list, pod=[row('pod', metadata={'name': 'one', 'labels': {'app': 'one'}})],
                          serviceaccount=[row('serviceaccount', 'one')])
    enabled = gc.isenabled()
    gc.disable()
    try:
        index = indexed.K8sWorkloadIndex({'collections': []}, by_type, _cluster)
        reference = weakref.ref(index)
        service = row('service', spec={'selector': {'app': 'one'}})
        assert index.pods(service)
        assert index.candidates('serviceaccount', by_type['pod'][0], names=['one'])
        del index
        assert reference() is None
    finally:
        if enabled:
            gc.enable()


@pytest.mark.parametrize('invalid_first', [False, True])
def test_first_service_account_match_retains_malformed_row_order(invalid_first):
    target = row('pod', spec={'serviceAccountName': 'runtime'})
    valid = row('serviceaccount', 'runtime')
    bad = row('serviceaccount', 'bad', metadata=None)
    foreign_bad = row('serviceaccount', 'foreign', cluster='foreign', metadata=None)
    rows = [bad, valid, foreign_bad] if invalid_first else [valid, bad, foreign_bad]
    by_type = defaultdict(list, serviceaccount=rows)
    index = indexed.K8sWorkloadIndex({'collections': []}, by_type, _cluster)

    def select(candidates):
        return next((s for s in candidates if _cluster(s) == _cluster(target)
            and s['data'].get('metadata', {}).get('namespace', 'default') == 'default'
            and s['data'].get('metadata', {}).get('name') == 'runtime'), None)

    assert outcome(lambda: select(index.candidates('serviceaccount', target, names=['runtime']))) == outcome(lambda: select(rows))


def test_unhashable_service_account_name_retains_equality_matching():
    account = row('serviceaccount', metadata={'name': ['recorded-name']})
    target = row('pod')
    index = indexed.K8sWorkloadIndex({'collections': []}, defaultdict(list, serviceaccount=[account]), _cluster)
    assert index.candidates('serviceaccount', target, names=[['recorded-name']]) == [account]


def test_ingress_candidates_preserve_missing_names_and_invalid_native_name_errors():
    services = [row('service', 'valid'), row('service', metadata={'namespace': 'default'}),
                row('service', metadata={'namespace': 'default', 'name': []}), row('service', 'foreign', cluster='foreign')]
    index = indexed.K8sWorkloadIndex({'collections': []}, defaultdict(list, service=services), _cluster)
    ingress = row('ingress')

    def select(rows, names):
        return [s for s in rows if _cluster(s) == _cluster(ingress)
            and s['data'].get('metadata', {}).get('namespace', 'default') == 'default'
            and s['data'].get('metadata', {}).get('name') in names]

    for names in ({None}, {'valid'}, {'missing'}):
        assert outcome(lambda: select(index.candidates('service', ingress, names=names), names)) == outcome(lambda: select(services, names))


def test_policy_completeness_preserves_scopes_order_errors_and_caches_results():
    reads = []

    class Envelope(dict):
        def get(self, name, *args):
            if name == 'status':
                reads.append(self['scope'])
            return super().get(name, *args)

    snapshot = {'collections': [Envelope(type='networkpolicy', scope='complete', status='empty'),
        Envelope(type='networkpolicy', scope='complete', status=[]),
        Envelope(type='networkpolicy', scope='partial', status='partial'),
        Envelope(type='networkpolicy', scope='bad', status=[])]}
    reference = LinearK8sWorkloads(snapshot, defaultdict(list), _cluster)
    index = indexed.K8sWorkloadIndex(snapshot, defaultdict(list), _cluster)
    for scope in ('complete', 'partial', 'missing', 'bad'):
        assert outcome(lambda: index.complete_policies(scope)) == outcome(lambda: reference.complete_policies(scope))
    reads.clear()
    for _ in range(10):
        assert index.complete_policies('complete') is True
        assert index.complete_policies('partial') is False
    assert reads == []


@pytest.mark.parametrize('layout', ['namespaces', 'shared'])
@pytest.mark.parametrize('variant', ['normal', 'policy', 'missing-policy', 'automount', 'projected', 'terminated', 'ingress'])
def test_complete_projection_matches_previous_workload_correlation(layout, variant):
    snapshot = synthetic_snapshot(6, layout)
    for collection in snapshot['collections']:
        if collection['type'] == 'networkpolicy':
            if variant == 'missing-policy':
                collection['status'] = 'denied'
            elif variant == 'policy':
                namespace = collection['scope'].split('/', 1)[-1]
                collection.update(status='collected', items=[{'metadata': {'name': 'selected', 'namespace': namespace},
                    'spec': {'podSelector': {'matchLabels': {'app': 'shared'}}, 'policyTypes': ['Ingress'],
                             'ingress': [{'from': [{'podSelector': {}}]}]}}])
        if collection['type'] == 'pod':
            for pod in collection['items']:
                if variant in ('automount', 'projected'):
                    pod['spec']['automountServiceAccountToken'] = False
                if variant == 'projected':
                    pod['spec'].update(containers=[{'name': 'app', 'volumeMounts': [{'name': 'token', 'mountPath': '/token'}]}],
                        volumes=[{'name': 'token', 'projected': {'sources': [{'serviceAccountToken': {'path': 'token'}}]}}])
                if variant == 'terminated':
                    pod['status']['phase'] = 'Succeeded'
    if variant == 'ingress':
        service = next(c for c in snapshot['collections'] if c['type'] == 'service')
        namespace = service['items'][0]['metadata']['namespace']
        snapshot['collections'].append({'type': 'ingress', 'scope': service['scope'], 'status': 'collected', 'items': [
            {'metadata': {'name': 'ingress', 'namespace': namespace},
             'spec': {'defaultBackend': {'service': {'name': service['items'][0]['metadata']['name']}}},
             'status': {'loadBalancer': {'ingress': [{'ip': '8.8.8.8'}]}}}]})
    snapshot = validate(seal(snapshot))
    original = copy.deepcopy(snapshot)
    inventory = resources(snapshot)
    actual = project(snapshot, inventory)
    with patch.object(indexed, 'K8sWorkloadIndex', LinearK8sWorkloads):
        assert project(snapshot, inventory) == actual
    assert snapshot == original


def test_complete_privilege_analysis_preserves_exposed_admin_annotations():
    from peaso.privesc import analyze

    snapshot = synthetic_snapshot(4, 'namespaces')
    role = {'metadata': {'name': 'admin'}, 'rules': [{'apiGroups': ['*'], 'resources': ['*'], 'verbs': ['*']}]}
    binding = {'metadata': {'name': 'admin'}, 'roleRef': {'kind': 'ClusterRole', 'name': 'admin'},
        'subjects': [{'kind': 'ServiceAccount', 'name': f'identity-{i}', 'namespace': f'ns-{i}'} for i in range(4)]}
    snapshot['collections'].extend([
        {'type': 'clusterrole', 'scope': snapshot['scopes'][0], 'status': 'collected', 'items': [role]},
        {'type': 'clusterrolebinding', 'scope': snapshot['scopes'][0], 'status': 'collected', 'items': [binding]}])
    snapshot = validate(seal(snapshot))
    original = copy.deepcopy(snapshot)
    actual = analyze(snapshot)
    assert any(node.get('exposures') or node.get('exposed_member_count') for node in actual['graph']['nodes'])
    with patch.object(indexed, 'K8sWorkloadIndex', LinearK8sWorkloads):
        expected = analyze(snapshot)
    actual['stats'].pop('timing_seconds')
    expected['stats'].pop('timing_seconds')
    assert actual == expected
    assert snapshot == original


def test_many_small_namespaces_do_not_retain_per_scope_label_indexes():
    by_type=defaultdict(list)
    for i in range(250):
        namespace=f'ns-{i}'
        by_type['pod'].append(row('pod',str(i),namespace=namespace,
            metadata={'name':str(i),'namespace':namespace,'labels':{'app':'native'}}))
    owner=indexed.K8sWorkloadIndex({'collections':[]},by_type,_cluster)
    for i in range(250):
        service=row('service',namespace=f'ns-{i}',spec={'selector':{'app':'native'}})
        assert owner.pods(service)==[by_type['pod'][i]]
    assert owner.remaining_label_keys==indexed.MAX_LABEL_KEYS
    assert not owner.pod_labels
