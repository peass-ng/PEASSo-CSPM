"""Whole offline IAM/network workflows with identical JSON-addressed IDs.

python -m tests.synthetic.benchmark_peaso_stable_ids --stage iam --size 4000
python -m tests.synthetic.benchmark_peaso_stable_ids --stage network --size 1000
"""
import argparse
from contextlib import contextmanager
import gc
import hashlib
import json
import statistics
import time
from unittest.mock import patch

from peaso.analysis import common, iam, internet_exposure, network
from peaso.principal_exposure import project
from peaso.snapshot import digest, make_snapshot, resources


def literal_id(*parts):
    encoded = json.dumps(parts, sort_keys=True, default=str, separators=(',', ':'))
    return 'analysis:' + hashlib.sha256(encoded.encode()).hexdigest()[:24]


OPTIMIZED_ID = common.stable_id


@contextmanager
def id_factory(factory):
    # Preserve the production function and every imported alias. Disabling the
    # fast-path marker exercises exactly the former json.dumps implementation.
    if factory is literal_id:
        with patch.object(common, '_JSON_DUMPS', None):
            yield
    elif factory is OPTIMIZED_ID:
        yield
    else:
        raise ValueError('supported ID encoder required')


def iam_snapshot(size):
    scope = '111122223333/global'
    roles = [{'RoleName': f'role-{i}', 'Arn': f'arn:aws:iam::111122223333:role/role-{i}',
        'AssumeRolePolicyDocument': {'Statement': []}, 'RolePolicyList': [{'PolicyName': 'native-policy',
            'PolicyDocument': {'Statement': [{'Sid': f'Native-{i}-{j}',
                'Effect': 'Deny' if j == 3 else 'Allow', 'Action': '*' if j == 0 else ['s3:GetObject'],
                'Resource': f'arn:aws:s3:::native-{i}/path-{j}/*',
                'Condition': {'Bool': {'aws:SecureTransport': 'true'}}} for j in range(4)]}}]}
        for i in range(size)]
    return make_snapshot('aws', [scope], [{'type': 'iam_role', 'scope': scope,
        'status': 'collected', 'items': roles}], created_at='2026-01-01T00:00:00+00:00')


def network_snapshot(size):
    scope = 'projects/benchmark'
    base = 'https://www.googleapis.com/compute/v1/' + scope
    facts = {kind: [] for kind in ('instance', 'forwarding_rule', 'target_proxy', 'backend_service')}
    for i in range(size):
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


def iam_stage(snapshot, inventory):
    with common.analysis_context(snapshot):
        findings = iam.review_findings(snapshot, inventory)
        graph = iam.build_iam(snapshot, inventory)
        principals = project(snapshot, inventory)
    return {'findings': findings, 'graph': graph, 'principals': principals}


def network_stage(snapshot, inventory):
    with common.analysis_context(snapshot):
        findings = network.exposure_findings(snapshot, inventory) + internet_exposure.internet_findings(snapshot, inventory)
        graph = internet_exposure.annotate_network(network.build_network(snapshot, inventory), snapshot, inventory)
        principals = project(snapshot, inventory)
    return {'findings': findings, 'graph': graph, 'principals': principals}


def workload(stage, size):
    if size < 1:
        raise ValueError('positive workload size required')
    if stage == 'iam':
        return iam_snapshot(size), iam_stage
    if stage == 'network':
        return network_snapshot(size), network_stage
    raise ValueError('supported workflow required')


def compare(stage='iam', size=4000):
    snapshot, run_stage = workload(stage, size)
    inventory, before = resources(snapshot), digest(snapshot)
    small, warm = workload(stage, 2)
    warm(small, resources(small))
    variants = (('baseline', literal_id), ('optimized', OPTIMIZED_ID))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name, _ in variants}
    for iteration in range(3):
        for name, factory in variants if iteration % 2 == 0 else variants[::-1]:
            with id_factory(factory):
                common._node_id.cache_clear()
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
    return {**results, 'stage': stage, 'resources': len(inventory), **counts,
        'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline IAM or network findings, graph and principal projection workflow. '
            'Excludes collection, native checks, privilege techniques, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=('iam', 'network'), default='iam')
    parser.add_argument('--size', type=int, default=4000)
    args = parser.parse_args()
    print(json.dumps(compare(args.stage, args.size), indent=2))
