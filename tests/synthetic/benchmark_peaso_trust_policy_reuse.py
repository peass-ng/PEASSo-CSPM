"""Complete AWS IAM/federation stage with encoded native role trust policies.

python -m tests.synthetic.benchmark_peaso_trust_policy_reuse --roles 600 --statements 4 --format percent
"""
import argparse
import gc
import json
import statistics
import time
from unittest.mock import patch
from urllib.parse import quote

from peaso import principal_exposure
from peaso.analysis import iam, internet_exposure
from peaso.analysis.common import analysis_context
from peaso.snapshot import digest, make_snapshot, resources


def literal_document(row):
    return iam.document(row['data'].get('AssumeRolePolicyDocument'))


def synthetic_snapshot(roles=600, statements=4, policy_format='percent'):
    if roles < 1 or statements < 1 or policy_format not in {'dict', 'json', 'percent'}:
        raise ValueError('positive role/statement counts and supported policy format required')
    scope = '111122223333/global'
    inventory = []
    for i in range(roles):
        policy = {'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
            'Principal': {'Federated': 'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com'},
            'Condition': {'StringEquals': {'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com'},
                'StringLike': {'token.actions.githubusercontent.com:sub':
                    f'repo:owner/repository-{j}:ref:refs/heads/*'}}} for j in range(statements)]}
        value = policy if policy_format == 'dict' else json.dumps(policy)
        if policy_format == 'percent':
            value = quote(value)
        inventory.append({'Arn': f'arn:aws:iam::111122223333:role/role-{i}',
            'RoleName': f'role-{i}', 'AssumeRolePolicyDocument': value})
    return make_snapshot('aws', [scope], [{'scope': scope, 'type': 'iam_role',
        'status': 'collected', 'items': inventory}], created_at='2026-01-01T00:00:00+00:00')


def run_stage(snapshot, inventory):
    with analysis_context(snapshot):
        findings = iam.review_findings(snapshot, inventory) + internet_exposure.federated_findings(snapshot, inventory)
        graph = iam.build_iam(snapshot, inventory)
        principals = principal_exposure.project(snapshot, inventory)
    return {'findings': findings, 'graph': graph, 'principals': principals}


def compare(roles=600, statements=4, policy_format='percent'):
    snapshot = synthetic_snapshot(roles, statements, policy_format)
    inventory, before = resources(snapshot), digest(snapshot)
    variants = (('baseline', literal_document), ('optimized', iam.assume_role_document))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name, _ in variants}
    for iteration in range(3):
        for name, parser in variants if iteration % 2 == 0 else variants[::-1]:
            with patch.object(iam, 'assume_role_document', parser), patch.object(principal_exposure, 'assume_role_document', parser):
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
    return {**results, 'resources': len(inventory), 'statements_per_role': statements,
        'policy_format': policy_format, **counts, 'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline AWS IAM/federation findings, graph and principal projection. '
            'Excludes collection, native checks, privilege techniques, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--roles', type=int, default=600)
    parser.add_argument('--statements', type=int, default=4)
    parser.add_argument('--format', choices=('dict', 'json', 'percent'), default='percent')
    args = parser.parse_args()
    print(json.dumps(compare(args.roles, args.statements, args.format), indent=2))
