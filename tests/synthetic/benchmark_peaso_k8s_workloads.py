"""Complete Kubernetes principal/exposure projection with workload correlation.

python -m tests.synthetic.benchmark_peaso_k8s_workloads --workloads 1000 --layout namespaces
python -m tests.synthetic.benchmark_peaso_k8s_workloads --workloads 1000 --layout shared

Both paths run real endpoint assessment and identity correlation. The reference
retains the former full-inventory scans. No agents or cloud calls are used.
"""
import argparse
import hashlib
import json
import statistics
import time
from unittest.mock import patch

from peaso.analysis import k8s_workload_index
from peaso.principal_exposure import project
from peaso.snapshot import digest, make_snapshot, resources


class LinearK8sWorkloads:
    """Former literal candidates, selector matching and completeness scan."""
    def __init__(self, snapshot, by_type, cluster_of):
        self.snapshot, self.by_type, self.cluster_of = snapshot, by_type, cluster_of

    def candidates(self, kind, owner, *, names=None):
        return self.by_type[kind]

    def pods(self, service):
        data = service['data']
        selector = (data.get('spec') or {}).get('selector')
        meta = data.get('metadata') or {}
        if not selector:
            return []
        return [pod for pod in self.by_type['pod'] if self.cluster_of(pod) == self.cluster_of(service)
            and pod['data'].get('metadata', {}).get('namespace', 'default') == meta.get('namespace', 'default')
            and all(pod['data'].get('metadata', {}).get('labels', {}).get(k) == v for k, v in selector.items())]

    def complete_policies(self, scope):
        return any(c.get('type') == 'networkpolicy' and c.get('scope') == scope
            and c.get('status') in {'collected', 'empty'} for c in self.snapshot.get('collections', []))


def synthetic_snapshot(workloads=1000, layout='namespaces'):
    if workloads < 1 or layout not in ('namespaces', 'shared'):
        raise ValueError('positive workloads and namespaces/shared layout required')
    grouped = {}
    for i in range(workloads):
        namespace = f'ns-{i}' if layout == 'namespaces' else 'workloads'
        scope = 'cluster/' + namespace
        meta = {'namespace': namespace}
        facts = {
            'pod': {'metadata': {**meta, 'name': f'pod-{i}', 'labels': {'app': 'shared', 'instance': str(i)}},
                'spec': {'serviceAccountName': f'identity-{i}', 'containers': []}, 'status': {'phase': 'Running'}},
            'service': {'metadata': {**meta, 'name': f'public-{i}'},
                'spec': {'type': 'LoadBalancer', 'selector': {'app': 'shared', 'instance': str(i)}, 'ports': [{'port': 80}]},
                'status': {'loadBalancer': {'ingress': [{'ip': '8.8.8.8'}]}}},
            'serviceaccount': {'metadata': {**meta, 'name': f'identity-{i}'}},
        }
        for kind, row in facts.items():
            grouped.setdefault((scope, kind), []).append(row)
        grouped.setdefault((scope, 'networkpolicy'), [])
    cols = [{'scope': scope, 'type': kind, 'status': 'collected' if rows else 'empty', 'items': rows}
            for (scope, kind), rows in grouped.items()]
    return make_snapshot('k8s', sorted({scope for scope, _ in grouped}), cols,
                         created_at='2026-10-22T00:00:00Z')


def compare(workloads=1000, layout='namespaces'):
    snapshot = synthetic_snapshot(workloads, layout)
    inventory = resources(snapshot)
    original = digest(snapshot)
    results = {}
    optimized = k8s_workload_index.K8sWorkloadIndex
    for name, factory in (('baseline', LinearK8sWorkloads), ('optimized', optimized)):
        elapsed, cpu, fingerprints = [], [], []
        with patch.object(k8s_workload_index, 'K8sWorkloadIndex', factory):
            for _ in range(3):
                cpu_started = time.process_time()
                started = time.perf_counter()
                output = project(snapshot, inventory)
                elapsed.append(round(time.perf_counter() - started, 6))
                cpu.append(round(time.process_time() - cpu_started, 6))
                fingerprints.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
        assert len(set(fingerprints)) == 1
        results[name] = {'seconds': elapsed, 'cpu_seconds': cpu, 'output_digest': fingerprints[0]}
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == original
    return {**results, 'workloads': workloads, 'layout': layout, 'resources': len(inventory),
        'principal_cards': len(output), 'exposures': sum(len(card['exposures']) for card in output.values()),
        'identical_output': True, 'input_unchanged': True, 'cloud_calls': 0,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete Kubernetes principal/exposure projection with public-service workload correlation. '
                       'Excludes collection, native checks, other analyses, graph building and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workloads', type=int, default=1000)
    parser.add_argument('--layout', choices=('namespaces', 'shared'), default='namespaces')
    args = parser.parse_args()
    print(json.dumps(compare(args.workloads, args.layout), indent=2))
