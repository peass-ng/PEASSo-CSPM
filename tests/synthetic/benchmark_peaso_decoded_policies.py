"""Complete IAM review, graph and principal projection for encoded native policies.

python -m tests.synthetic.benchmark_peaso_decoded_policies --principals 1000 --format json
python -m tests.synthetic.benchmark_peaso_decoded_policies --principals 1000 --format percent
Reference retains the former mutable decoded policy trees in the per-run memo.
"""
import argparse
import gc
import json
import statistics
import time
from urllib.parse import quote
from unittest.mock import patch

from tests.synthetic.benchmark_peaso_iam_action_profiles import synthetic_snapshot as role_snapshot, run_stage
from peaso.analysis import iam
from peaso.analysis.common import derived
from peaso.snapshot import digest, resources, seal, validate


def literal_documents(resource):
    return derived(resource, 'iam_policy_documents', lambda: tuple(iam.policy_documents(resource['data'])))


def synthetic_snapshot(principals=1000, policy_format='json', trust_principals=20):
    snapshot = role_snapshot('aws', principals, 24)
    if policy_format not in ('dict', 'json', 'percent') or trust_principals < 0:
        raise ValueError('supported policy format and nonnegative trust-principal count required')
    for collection in snapshot['collections']:
        for role in collection['items']:
            if trust_principals:
                role['AssumeRolePolicyDocument'] = {'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                    'Principal': {'AWS': [f'arn:aws:iam::222233334444:role/external-{i}' for i in range(trust_principals)]},
                    'Condition': {'StringEquals': {'sts:ExternalId': 'recorded-id'}}}]}
            if policy_format == 'dict':
                continue
            policies = [role, *role['RolePolicyList']]
            for row in policies:
                field = 'AssumeRolePolicyDocument' if row is role else 'PolicyDocument'
                value = json.dumps(row[field], ensure_ascii=False)
                row[field] = quote(value) if policy_format == 'percent' else value
    return validate(seal(snapshot))


def compare(principals=1000, policy_format='json', trust_principals=20):
    snapshot = synthetic_snapshot(principals, policy_format, trust_principals)
    inventory, before = resources(snapshot), digest(snapshot)
    variants = (('baseline', literal_documents), ('optimized', iam._resource_policy_documents))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name, _ in variants}
    for iteration in range(3):
        for name, extract in variants if iteration % 2 == 0 else variants[::-1]:
            with patch.object(iam, '_resource_policy_documents', extract):
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
    return {**results, 'resources': len(inventory), 'policy_format': policy_format,
        'trust_principals_per_role': trust_principals, **counts,
        'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline AWS IAM findings, graph and principal projection. '
                       'Excludes cloud collection, native checks, privilege techniques, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--principals', type=int, default=1000)
    parser.add_argument('--format', choices=('dict', 'json', 'percent'), default='json')
    parser.add_argument('--trust-principals', type=int, default=20)
    args = parser.parse_args()
    print(json.dumps(compare(args.principals, args.format, args.trust_principals), indent=2))
