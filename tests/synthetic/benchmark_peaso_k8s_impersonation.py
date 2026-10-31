"""Complete Kubernetes IAM findings, graph and principal projection.

python -m tests.synthetic.benchmark_peaso_k8s_impersonation --bindings 1500
python -m tests.synthetic.benchmark_peaso_k8s_impersonation --bindings 1500 --layout shared
python -m tests.synthetic.benchmark_peaso_k8s_impersonation --binding-kind clusterrolebinding
The reference retains the original full service-account loop and predicates.
"""
import argparse
import gc
import json
import statistics
import time
from unittest.mock import patch

from tests.synthetic.benchmark_peaso_iam_action_profiles import run_stage
from peaso.analysis import k8s_impersonation_index
from peaso.snapshot import digest, make_snapshot, resources


class LinearAccounts:
    def __init__(self, accounts, cluster_of):
        self.accounts = accounts

    def candidates(self, binding, namespace, names):
        return self.accounts


def synthetic_snapshot(bindings=1500, layout='namespaces', binding_kind='rolebinding'):
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


def compare(bindings=1500, layout='namespaces', binding_kind='rolebinding'):
    snapshot = synthetic_snapshot(bindings, layout, binding_kind)
    inventory, before = resources(snapshot), digest(snapshot)
    variants = (('baseline', LinearAccounts), ('optimized', k8s_impersonation_index.K8sImpersonationIndex))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name, _ in variants}
    for iteration in range(3):
        for name, factory in variants if iteration % 2 == 0 else variants[::-1]:
            with patch.object(k8s_impersonation_index, 'K8sImpersonationIndex', factory):
                gc.collect()
                start, cpu_start = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, inventory)
                results[name]['seconds'].append(time.perf_counter() - start)
                results[name]['cpu_seconds'].append(time.process_time() - cpu_start)
                results[name]['digests'].append(digest(output))
                counts = {'findings': len(output['findings']), 'nodes': len(output['graph']['nodes']),
                          'edges': len(output['graph']['edges']), 'principals': len(output['principals'])}
                del output
    for result in results.values():
        fingerprints = result.pop('digests')
        assert len(set(fingerprints)) == 1
        result['output_digest'] = fingerprints[0]
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == before
    return {**results, 'bindings': bindings, 'layout': layout, 'binding_kind': binding_kind,
        'resources': len(inventory), **counts, 'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline Kubernetes IAM findings, graph and principal projection. '
                       'Excludes collection, native checks, privilege techniques, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindings', type=int, default=1500)
    parser.add_argument('--layout', choices=('namespaces', 'shared'), default='namespaces')
    parser.add_argument('--binding-kind', choices=('rolebinding', 'clusterrolebinding'), default='rolebinding')
    args = parser.parse_args()
    print(json.dumps(compare(args.bindings, args.layout, args.binding_kind), indent=2))
