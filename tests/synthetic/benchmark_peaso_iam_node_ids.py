"""Complete IAM review, graph and principal stage with prepared graph identities.

python -m tests.synthetic.benchmark_peaso_iam_node_ids --principals 4000
The reference builder retains the original repeated node-ID lookups.
"""
import argparse
import gc
import json
import statistics
import time
from unittest.mock import patch

from tests.synthetic.benchmark_peaso_iam_action_profiles import synthetic_snapshot as role_snapshot, run_stage
from tests.synthetic.reference_peaso_iam_node_ids import original_builder
from peaso.analysis import iam
from peaso.snapshot import digest, resources, seal, validate


def synthetic_snapshot(principals=4000):
    snapshot = role_snapshot('aws', principals, 4, actions=1)
    for role in snapshot['collections'][0]['items']:
        statements = role['RolePolicyList'][0]['PolicyDocument']['Statement']
        statements[0].update(Effect='Allow', Action='*')
        statements[-1]['Effect'] = 'Deny'
    return validate(seal(snapshot))


def compare(principals=4000):
    snapshot = synthetic_snapshot(principals)
    inventory, before = resources(snapshot), digest(snapshot)
    variants = (('baseline', original_builder()), ('optimized', iam.build_iam))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name, _ in variants}
    for iteration in range(3):
        for name, builder in variants if iteration % 2 == 0 else variants[::-1]:
            with patch.object(iam, 'build_iam', builder):
                gc.collect()
                start, cpu = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, inventory)
                results[name]['seconds'].append(time.perf_counter() - start)
                results[name]['cpu_seconds'].append(time.process_time() - cpu)
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
    return {**results, 'resources': len(inventory), **counts, 'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline AWS IAM findings, graph and principal projection stage. '
            'Excludes collection, native checks, privilege techniques, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--principals', type=int, default=4000)
    print(json.dumps(compare(parser.parse_args().principals), indent=2))
