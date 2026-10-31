"""Complete Azure IAM and federation review, graph and principal projection.

python -m tests.synthetic.benchmark_peaso_azure_federation --identities 1500
Reference retains the former full service-principal and managed-identity loops.
"""
import argparse
import gc
import json
import statistics
import time
from unittest.mock import patch

from peaso.analysis import azure_federation_index, iam, internet_exposure
from peaso.analysis.common import analysis_context
from peaso.principal_exposure import project
from peaso.snapshot import digest, make_snapshot, resources


class LinearFederation:
    def __init__(self, by_type):
        self.by_type = by_type

    def service_principals(self, credential):
        return self.by_type['directory_service_principal']

    def managed_identities(self, credential, parent):
        return self.by_type['managed_identity']


def synthetic_snapshot(identities=1500):
    if identities < 1:
        raise ValueError('positive identity count required')
    tenant = '11111111-1111-1111-1111-111111111111'
    directory = '/tenants/' + tenant
    subscription = '/subscriptions/22222222-2222-2222-2222-222222222222'
    facts = {kind: [] for kind in ('directory_service_principal', 'directory_federated_credential',
                                  'managed_identity', 'managed_identity_federated_credential')}
    for i in range(identities):
        app_id = f'33333333-3333-3333-3333-{i:012d}'
        principal = f'44444444-4444-4444-4444-{i:012d}'
        identity = f'55555555-5555-5555-5555-{i:012d}'
        parent = subscription + f'/resourceGroups/native/providers/Microsoft.ManagedIdentity/userAssignedIdentities/identity-{i}'
        trust = {'issuer': 'https://token.actions.githubusercontent.com',
                 'subject': f'repo:owner/repository-{i}:ref:refs/heads/main',
                 'audiences': ['api://AzureADTokenExchange']}
        facts['directory_service_principal'].append({'id': principal, 'appId': app_id,
            'appOwnerOrganizationId': tenant, 'displayName': f'Application {i}'})
        facts['directory_federated_credential'].append({'id': f'directory-credential-{i}', 'appId': app_id, **trust})
        facts['managed_identity'].append({'id': parent, 'properties': {'principalId': identity}})
        facts['managed_identity_federated_credential'].append({
            'id': parent + f'/federatedIdentityCredentials/credential-{i}', 'properties': dict(trust)})
    collections = [{'scope': directory if kind.startswith('directory_') else subscription,
                    'type': kind, 'status': 'collected', 'items': items} for kind, items in facts.items()]
    return make_snapshot('azure', [directory, subscription], collections, metadata={'tenant_id': tenant},
                         created_at='2026-01-01T00:00:00+00:00')


def run_stage(snapshot, inventory):
    with analysis_context(snapshot):
        findings = iam.review_findings(snapshot, inventory) + internet_exposure.federated_findings(snapshot, inventory)
        graph = iam.build_iam(snapshot, inventory)
        principals = project(snapshot, inventory)
    return {'findings': findings, 'graph': graph, 'principals': principals}


def compare(identities=1500):
    snapshot = synthetic_snapshot(identities)
    inventory, before = resources(snapshot), digest(snapshot)
    variants = (('baseline', LinearFederation), ('optimized', azure_federation_index.AzureFederationIndex))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name, _ in variants}
    for iteration in range(3):
        for name, factory in variants if iteration % 2 == 0 else variants[::-1]:
            with patch.object(azure_federation_index, 'AzureFederationIndex', factory):
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
    return {**results, 'identities_per_kind': identities, 'resources': len(inventory), **counts,
        'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline Azure IAM/federation findings, graph and principal projection. '
                       'Excludes collection, native checks, privilege techniques, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identities', type=int, default=1500)
    args = parser.parse_args()
    print(json.dumps(compare(args.identities), indent=2))
