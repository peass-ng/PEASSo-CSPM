"""Complete offline network stage with shared native projections.

python -m tests.synthetic.benchmark_peaso_network_facts --workloads 2000
Includes findings, full topology and principal/exposure correlation. The
reference repeats native traversals and classifies each field as before.
"""
from contextlib import ExitStack
import argparse
import hashlib
import json
import statistics
import time
from unittest.mock import patch

from tests.synthetic.benchmark_peaso_gcp_lb_workloads import run_stage, synthetic_snapshot
from peaso.analysis import network_facts, network_observations, network_services
from peaso.snapshot import digest, resources


class RepeatedNetworkFacts:
    def __init__(self, data, **options):
        self.data = data

    def observations(self):
        return network_observations.network_observations(self.data)

    def projected(self):
        return network_services.project_network_data(self.data)


def compare(workloads=2000):
    snapshot = synthetic_snapshot(workloads)
    rows, original = resources(snapshot), digest(snapshot)
    results = {}
    optimized = network_facts.NetworkFacts
    for name, factory in (('baseline', RepeatedNetworkFacts), ('optimized', optimized)):
        elapsed, cpu, fingerprints = [], [], []
        with ExitStack() as stack:
            stack.enter_context(patch.object(network_facts, 'NetworkFacts', factory))
            if name == 'baseline':
                stack.enter_context(patch.object(network_observations, '_field_traits', lambda key: None))
            for _ in range(3):
                start, cpu_start = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, rows)
                elapsed.append(time.perf_counter() - start)
                cpu.append(time.process_time() - cpu_start)
                assert len(output['principals']) == workloads
                fingerprints.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
        assert len(set(fingerprints)) == 1
        results[name] = {'seconds': elapsed, 'cpu_seconds': cpu, 'output_digest': fingerprints[0]}
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == original
    return {**results, 'workloads': workloads, 'resources': len(rows),
        'findings': len(output['findings']), 'nodes': len(output['graph']['nodes']),
        'edges': len(output['graph']['edges']), 'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'limitations': 'Synthetic complete offline GCP network and principal/exposure stage; excludes '
                       'collection, native checks, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workloads', type=int, default=2000)
    args = parser.parse_args()
    print(json.dumps(compare(args.workloads), indent=2))
