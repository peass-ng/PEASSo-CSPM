"""Complete IAM review, graph and principal projection with a shared domain boundary.

python -m tests.synthetic.benchmark_peaso_trust_domains --provider gcp --bindings 1000
python -m tests.synthetic.benchmark_peaso_trust_domains --provider k8s --bindings 1000
Reference repeats the former domain normalization on every classification.
"""
import argparse
import gc
import json
import statistics
import sys
import time
from unittest.mock import patch

from tests.synthetic.benchmark_peaso_iam_action_profiles import run_stage
from peaso.analysis import trust
from peaso.snapshot import digest, make_snapshot, resources


def gcp_snapshot(projects=1000, domains=64):
    if projects < 1 or domains < 0:
        raise ValueError('positive project count and nonnegative domain count required')
    members = [f'user:person-{j}@' + ('corp.example' if j % 2 else 'outside.example') for j in range(20)]
    collections = [{'type': 'iam_policy', 'scope': f'projects/project-{i}', 'status': 'collected', 'items': [{
        'name': f'projects/project-{i}', 'bindings': [{'role': 'roles/owner', 'members': list(members)}]}]}
        for i in range(projects)]
    return make_snapshot('gcp', [c['scope'] for c in collections], collections,
        metadata={'trusted_domains': (['CORP.EXAMPLE'] + [f'partner-{i}.example' for i in range(domains - 1)]) if domains else []},
        created_at='2026-01-01T00:00:00+00:00')



def literal_normalized(values):
    return {value.lower() for value in values}


def synthetic_snapshot(provider='gcp', bindings=1000, domains=64):
    if bindings < 1 or domains < 0:
        raise ValueError('positive binding count and nonnegative domain count required')
    if provider == 'gcp':
        return gcp_snapshot(bindings, domains)
    if provider != 'k8s':
        raise ValueError('provider must be gcp or k8s')
    users = [f'person-{i}@' + ('corp.example' if i % 2 else 'outside.example') for i in range(20)]
    return make_snapshot('k8s', ['cluster'], [
        {'scope': 'cluster', 'type': 'clusterrole', 'status': 'collected', 'items': [{
            'metadata': {'name': 'admin'}, 'rules': [{'apiGroups': ['*'], 'resources': ['*'], 'verbs': ['*']}]}]},
        {'scope': 'cluster', 'type': 'clusterrolebinding', 'status': 'collected', 'items': [{
            'metadata': {'name': f'binding-{i}'},
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'admin'},
            'subjects': [{'kind': 'User', 'name': user} for user in users]} for i in range(bindings)]}],
        metadata={'trusted_domains': ['CORP.EXAMPLE'] + [f'partner-{i}.example' for i in range(domains - 1)]
                  if domains else []}, created_at='2026-01-01T00:00:00+00:00')


def compare(provider='gcp', bindings=1000, domains=64):
    snapshot = synthetic_snapshot(provider, bindings, domains)
    inventory, before = resources(snapshot), digest(snapshot)
    variants = (('baseline', literal_normalized), ('optimized', trust.normalized_domains))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name, _ in variants}
    for iteration in range(3):
        for name, normalized in variants if iteration % 2 == 0 else variants[::-1]:
            with patch.object(trust, 'normalized_domains', normalized):
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
    return {**results, 'provider': provider, 'bindings': bindings, 'trusted_domains': domains,
        'resources': len(inventory), 'python': sys.version.split()[0], **counts,
        'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline IAM findings, graph and principal projection. '
                       'Excludes cloud collection, native checks, privilege techniques, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('gcp', 'k8s'), default='gcp')
    parser.add_argument('--bindings', type=int, default=1000)
    parser.add_argument('--domains', type=int, default=64)
    args = parser.parse_args()
    print(json.dumps(compare(args.provider, args.bindings, args.domains), indent=2))
