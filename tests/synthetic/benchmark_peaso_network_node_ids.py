"""Complete network stage above and below the shared node-ID cache capacity.

python -m tests.synthetic.benchmark_peaso_network_node_ids --networks 70000
The original topology builder is preserved verbatim in the reference module.
"""
import argparse
import gc
import hashlib
import json
import statistics
import sys
import time
from unittest.mock import patch

from tests.synthetic.reference_peaso_network_node_ids import original_builder
from tests.synthetic.benchmark_peaso_gcp_lb_workloads import run_stage
from peaso.analysis import common, network
from peaso.snapshot import digest, make_snapshot, resources


def synthetic_snapshot(networks=70000):
    if networks < 1:
        raise ValueError('positive network count required')
    scope = 'projects/benchmark'
    base = 'https://www.googleapis.com/compute/v1/' + scope
    nets, subnets = [], []
    for i in range(networks):
        link = base + f'/global/networks/net-{i}'
        nets.append({'name': f'net-{i}', 'selfLink': link})
        subnets.append({'name': f'subnet-{i}',
            'selfLink': base + f'/regions/us-central1/subnetworks/subnet-{i}',
            'network': link, 'ipCidrRange': '10.0.0.0/24'})
    return make_snapshot('gcp', [scope], [
        {'type': 'network', 'scope': scope, 'status': 'collected', 'items': nets},
        {'type': 'subnetwork', 'scope': scope, 'status': 'collected', 'items': subnets}],
        created_at='2026-01-01T00:00:00+00:00')


def fingerprint(value):
    # Verification is outside the timed stage. Stream the exact canonical
    # JSON bytes instead of allocating another full Unicode/UTF-8 graph copy.
    hashed = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    for part in encoder.iterencode(value):
        hashed.update(part.encode())
    return 'sha256:' + hashed.hexdigest()


def compare(networks=70000, runs=3):
    if runs < 1:
        raise ValueError('positive run count required')
    snapshot = synthetic_snapshot(networks)
    inventory, before = resources(snapshot), digest(snapshot)
    builders = (('baseline', original_builder()), ('optimized', network.build_network))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': [], 'id_cache': []} for name, _ in builders}
    for run in range(runs):
        for name, builder in builders if run % 2 == 0 else builders[::-1]:
            result = results[name]
            with patch.object(network, 'build_network', builder):
                common._node_id.cache_clear()
                gc.collect()
                start, cpu_start = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, inventory)
                result['seconds'].append(time.perf_counter() - start)
                result['cpu_seconds'].append(time.process_time() - cpu_start)
                result['id_cache'].append(common._node_id.cache_info()._asdict())
                print(name, run + 1, 'seconds', round(result['seconds'][-1], 3),
                      'cpu', round(result['cpu_seconds'][-1], 3), 'hashes', result['id_cache'][-1]['misses'],
                      file=sys.stderr, flush=True)
                result['digests'].append(fingerprint(output))
                counts = {key: len(output[key]) for key in ('findings', 'principals')}
                counts.update(nodes=len(output['graph']['nodes']), edges=len(output['graph']['edges']))
                del output
    for result in results.values():
        fingerprints = result.pop('digests')
        assert len(set(fingerprints)) == 1
        result['output_digest'] = fingerprints[0]
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == before
    return {**results, 'networks': networks, 'resources': len(inventory), 'runs': runs,
        'python': sys.version.split()[0], **counts,
        'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline GCP network findings, topology, exposure annotation '
                       'and principal projection. Excludes collection, native checks, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--networks', type=int, default=70000)
    parser.add_argument('--runs', type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(compare(args.networks, args.runs), indent=2))
