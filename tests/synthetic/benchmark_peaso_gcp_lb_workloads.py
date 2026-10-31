"""Complete offline GCP network findings, topology and workload identity joins.

python -m tests.synthetic.benchmark_peaso_gcp_lb_workloads --workloads 2000
Reference keeps earlier indexes but scans all backend services and VMs per LB.
"""
import argparse
import hashlib
import json
import statistics
import time
from unittest.mock import patch

from peaso.analysis import analysis_context, internet_exposure, network
from peaso.analysis import cloud_workload_index
from peaso.analysis.cloud_workload_index import CloudWorkloadIndex as IndexedCloudWorkloads
from peaso.principal_exposure import project
from peaso.snapshot import digest, make_snapshot, resources


class FormerGcpWorkloads(IndexedCloudWorkloads):
    def candidates(self, kind, field, values, **options):
        if field in {'gcp_backend_path', 'gcp_running_instance_path'}:
            return self.by_type[kind]
        return super().candidates(kind, field, values, **options)


def synthetic_snapshot(workloads=2000):
    if workloads < 1:
        raise ValueError('positive workloads required')
    scope = 'projects/benchmark'
    base = 'https://www.googleapis.com/compute/v1/' + scope
    facts = {kind: [] for kind in ('instance', 'forwarding_rule', 'target_proxy', 'backend_service')}
    for i in range(workloads):
        vm, service = base + f'/zones/us-central1-a/instances/vm-{i}', base + f'/global/backendServices/web-{i}'
        proxy = base + f'/global/targetHttpsProxies/web-{i}'
        facts['instance'].append({'name': f'vm-{i}', 'selfLink': vm, 'status': 'RUNNING',
            'serviceAccounts': [{'email': f'web-{i}@benchmark.iam.gserviceaccount.com'}]})
        facts['forwarding_rule'].append({'name': f'front-{i}', 'IPAddress': f'8.8.{i // 250 % 250}.{i % 250 + 1}',
            'loadBalancingScheme': 'EXTERNAL_MANAGED', 'IPProtocol': 'TCP', 'portRange': '443', 'target': proxy})
        facts['target_proxy'].append({'name': f'web-{i}', 'selfLink': proxy, 'service': service})
        facts['backend_service'].append({'name': f'web-{i}', 'selfLink': service,
            'BackendHealth': {'collection_status': 'collected', 'groups': [{'collection_status': 'collected',
                'group': base + f'/zones/us-central1-a/instanceGroups/web-{i}',
                'source_requests': [f'health-request-{i}'],
                'healthStatus': [{'instance': vm, 'healthState': 'HEALTHY'}]}]}})
    return make_snapshot('gcp', [scope], [{'type': kind, 'scope': scope, 'status': 'collected', 'items': items}
        for kind, items in facts.items()], created_at='2026-01-01T00:00:00+00:00')


def run_stage(snapshot, inventory):
    with analysis_context(snapshot):
        findings = network.exposure_findings(snapshot, inventory) + internet_exposure.internet_findings(snapshot, inventory)
        graph = internet_exposure.annotate_network(network.build_network(snapshot, inventory), snapshot, inventory)
        principals = project(snapshot, inventory)
    return {'findings': findings, 'graph': graph, 'principals': principals}


def compare(workloads=2000):
    snapshot = synthetic_snapshot(workloads)
    rows, original = resources(snapshot), digest(snapshot)
    results = {}
    optimized = cloud_workload_index.CloudWorkloadIndex
    for name, factory in (('baseline', FormerGcpWorkloads), ('optimized', optimized)):
        elapsed, cpu, fingerprints = [], [], []
        with patch.object(cloud_workload_index, 'CloudWorkloadIndex', factory):
            for _ in range(3):
                start, cpu_start = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, rows)
                elapsed.append(time.perf_counter() - start)
                cpu.append(time.process_time() - cpu_start)
                assert len(output['principals']) == workloads
                assert all(card['exposures'][0]['state'] == 'declared' for card in output['principals'].values())
                fingerprints.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
        assert len(set(fingerprints)) == 1
        results[name] = {'seconds': elapsed, 'cpu_seconds': cpu, 'output_digest': fingerprints[0]}
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == original
    return {**results, 'workloads': workloads, 'resources': len(rows),
        'findings': len(output['findings']), 'nodes': len(output['graph']['nodes']),
        'edges': len(output['graph']['edges']), 'principal_cards': len(output['principals']),
        'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'limitations': 'Synthetic complete offline GCP network findings, topology and principal/exposure '
                       'projection. Excludes collection, native checks, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workloads', type=int, default=2000)
    args = parser.parse_args()
    print(json.dumps(compare(args.workloads), indent=2))
