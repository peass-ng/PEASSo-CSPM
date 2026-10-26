"""Native privilege model, all provider techniques, graph, findings and coverage.

python -m examples.benchmark_peaso_permission_prefilter --provider azure --principals 5000
python -m examples.benchmark_peaso_permission_prefilter --provider k8s --principals 1000

No provider APIs or application registry imports are needed. The final principal
exposure annotation and report rendering are outside this benchmark.
"""
import argparse
import gc
import hashlib
import json
import time

from peaso.privesc import MODELS, catalog
try:
    from peaso.privesc.effective_permissions import indexed_inventory
except ImportError:  # Releases without scoped inventory indexes scan collections linearly.
    def indexed_inventory(function):
        return function
from peaso.privesc.evaluator import Evaluator
from peaso.privesc.graph import GraphBuilder


def synthetic_snapshot(provider='azure', principals=1500):
    if principals < 1:
        raise ValueError('principals must be positive')
    if provider == 'azure':
        sub, tenant = '/subscriptions/benchmark', '/tenants/benchmark'
        role = sub + '/providers/Microsoft.Authorization/roleDefinitions/operator'
        admin_role = sub + '/providers/Microsoft.Authorization/roleDefinitions/delegator'
        actions = ['Microsoft.Compute/virtualMachines/*', 'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action']
        facts = {
            'subscription': [{'id': sub, 'subscriptionId': 'benchmark'}],
            'role_definition': [{'id': rid, 'properties': {'roleName': name, 'type': 'CustomRole',
                'assignableScopes': [sub], 'permissions': [{'actions': allowed,
                    'notActions': ['Microsoft.Compute/virtualMachines/delete']}]}}
                for rid, name, allowed in ((role, 'VM Operator', actions),
                    (admin_role, 'Delegator', actions + ['Microsoft.Authorization/roleAssignments/write']))],
            'role_assignment': [{'id': f'{sub}/providers/Microsoft.Authorization/roleAssignments/{i}', 'properties': {
                'principalId': f'user-{i}', 'principalType': 'User', 'roleDefinitionId': admin_role if i % 10 == 0 else role,
                'scope': f'{sub}/resourceGroups/rg-{i}'}} for i in range(principals)],
            'directory_user': [{'id': f'user-{i}', 'userPrincipalName': f'user-{i}@benchmark.invalid', 'userType': 'Member'}
                               for i in range(principals)],
            'directory_group': [{'id': f'group-{i}', 'displayName': f'group-{i}'} for i in range(principals // 5)],
            'directory_role_assignment': [], 'directory_role_definition': [], 'deny_assignment': [],
        }
        cols = [{'type': kind, 'scope': tenant if kind.startswith('directory') else sub, 'items': rows,
                 'status': 'collected' if rows else 'empty'} for kind, rows in facts.items()]
        cols += [{'type': 'directory_membership', 'scope': tenant + '/groups/' + g['id'], 'items': [], 'status': 'empty'}
                 for g in facts['directory_group']]
        return {'provider': provider, 'scopes': [sub, tenant], 'collections': cols, 'metadata': {'tenant_id': 'benchmark'}}
    if provider == 'k8s':
        cluster = 'benchmark'

        def obj(kind, name, namespace=None, **extra):
            return {'kind': kind, 'metadata': {'name': name, **({'namespace': namespace} if namespace else {})},
                    'provenance': {'cluster_id': cluster}, **extra}

        # Each binding has distinct native evidence and a distinct scope, but
        # they share the same ClusterRole. Exact checks still use each binding.
        facts = {
            'clusterrole': [obj('ClusterRole', 'workload-reader', rules=[
                {'apiGroups': [''], 'resources': ['pods', 'secrets'], 'verbs': ['get', 'list', 'create']},
                {'apiGroups': [''], 'resources': ['pods/exec'], 'verbs': ['create']}])],
            'rolebinding': [obj('RoleBinding', 'reader', f'ns-{i}', roleRef={'kind': 'ClusterRole', 'name': 'workload-reader'},
                subjects=[{'kind': 'User', 'name': f'user-{i}'}]) for i in range(principals)],
            'serviceaccount': [obj('ServiceAccount', 'runtime', f'ns-{i}') for i in range(principals)],
            'namespace': [obj('Namespace', f'ns-{i}') for i in range(principals)],
            'clusterrolebinding': [], 'role': [],
        }
        return {'provider': provider, 'scopes': [cluster], 'metadata': {}, 'collections': [
            {'type': kind, 'scope': cluster, 'items': rows, 'status': 'collected' if rows else 'empty'}
            for kind, rows in facts.items()]}
    if provider == 'gcp':
        cols, scopes = [], []
        for i in range(principals):
            scope = f'projects/benchmark-{i}'
            scopes.append(scope)
            facts = {
                'project': [{'projectId': f'benchmark-{i}', 'name': scope, '_ancestry': []}],
                'iam_policy': [{'name': scope, 'bindings': [{'role': 'roles/iam.serviceAccountAdmin',
                    'members': [f'user:user-{i}@benchmark.invalid']}]}],
                'service_account': [{'email': f'runtime@benchmark-{i}.iam.gserviceaccount.com',
                    'name': scope + f'/serviceAccounts/runtime@benchmark-{i}.iam.gserviceaccount.com'}],
                'iam_deny_policy': [], 'iam_role': [],
            }
            cols += [{'type': kind, 'scope': scope, 'items': rows, 'status': 'collected' if rows else 'empty'}
                     for kind, rows in facts.items()]
        return {'provider': provider, 'scopes': scopes, 'collections': cols, 'metadata': {}}
    raise ValueError('provider must be azure, gcp or k8s')


@indexed_inventory
def run_stage(snapshot, entries=None, *, model_class=None, include_unknown=False, diagnostics=None):
    provider = snapshot['provider']
    if entries is None:
        entries = [entry for entry in catalog()['entries'] if entry['provider'] == provider]
    model = (model_class or MODELS[provider])(snapshot)
    admin = {principal.id: model.admin_targets(principal) for principal in model.sources()}
    evaluator = Evaluator(model, entries, include_unknown=include_unknown, admin_scopes={
        pid: sorted({node.scope for node, _ in found}) for pid, found in admin.items() if found})
    reaches = evaluator.run()
    builder = GraphBuilder(model)
    builder.add_admin(model.sources(), admin)
    for reach in reaches:
        builder.add(reach)
    if diagnostics is not None:
        diagnostics['permission_cache_entries'] = len(model._check_cache)
    return {'graph': builder.result(), 'findings': builder.findings, 'coverage': model.coverage,
            'blocked': evaluator.blocked, 'sources': len(evaluator.all_sources)}


def benchmark(provider='azure', principals=1500, *, model_class=None):
    snapshot = synthetic_snapshot(provider, principals)
    entries = [entry for entry in catalog()['entries'] if entry['provider'] == provider]
    original = json.dumps(snapshot, sort_keys=True)
    elapsed, fingerprints = [], []
    for _ in range(3):
        started = time.perf_counter()
        diagnostics = {}
        enabled = gc.isenabled()
        gc.disable()  # Match privesc.analyze's treatment of its acyclic temporary objects.
        try:
            output = run_stage(snapshot, entries, model_class=model_class, diagnostics=diagnostics)
        finally:
            if enabled:
                gc.enable()
        elapsed.append(round(time.perf_counter() - started, 6))
        fingerprints.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
    assert len(set(fingerprints)) == 1 and json.dumps(snapshot, sort_keys=True) == original
    return {'provider': provider, 'resources': sum(len(c['items']) for c in snapshot['collections']),
            'techniques': len(entries), 'sources': output['sources'], 'seconds': elapsed,
            'findings': len(output['findings']), 'nodes': len(output['graph']['nodes']), 'edges': len(output['graph']['edges']),
            'output_digest': fingerprints[0], 'input_unchanged': True, 'cloud_calls': 0,
            **diagnostics,
            'limitations': 'Synthetic native privilege stage with the full provider catalog. '
                           'Excludes catalog loading, final principal exposure annotation, cloud collection and report persistence.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('azure', 'gcp', 'k8s'), default='azure')
    parser.add_argument('--principals', type=int, default=1500)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.provider, args.principals), indent=2))
