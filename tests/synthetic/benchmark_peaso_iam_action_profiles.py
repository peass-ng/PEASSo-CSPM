"""Complete offline IAM review, graph and principal projection.

python -m tests.synthetic.benchmark_peaso_iam_action_profiles --provider aws --principals 1000
python -m tests.synthetic.benchmark_peaso_iam_action_profiles --provider azure --principals 1000
Reference preserves the former per-grant classification of every action list.
"""
import argparse
import gc
import hashlib
import json
import statistics
import time
from unittest.mock import patch

from peaso.analysis import analysis_context, finding_clarity, iam
from peaso.principal_exposure import project
from peaso.snapshot import digest, make_snapshot, resources
from contextlib import ExitStack

AWS_ACTIONS = ['s3:GetObject', 's3:PutObject', 's3:DeleteObject', 's3:GetBucketPolicy', 's3:PutBucketPolicy',
    's3:ListBucket', 's3:GetBucketLocation', 'ec2:DescribeInstances', 'ec2:DescribeNetworkInterfaces',
    'ec2:CreateTags', 'ec2:ModifyInstanceAttribute', 'iam:PassRole', 'iam:CreateRole', 'iam:PutRolePolicy',
    'iam:AttachRolePolicy', 'iam:ListRoles', 'iam:GetRole', 'lambda:CreateFunction', 'lambda:UpdateFunctionCode',
    'lambda:GetFunction', 'sts:AssumeRole', 'logs:DescribeLogGroups', 'logs:GetLogEvents',
    'cloudwatch:GetMetricData', 'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Scan',
    'secretsmanager:GetSecretValue', 'kms:Decrypt', 'ssm:SendCommand', 'unknownvendor:UnmappedBenchmarkOperation']
AZURE_ACTIONS = ['Microsoft.Compute/virtualMachines/read', 'Microsoft.Compute/virtualMachines/write',
    'Microsoft.Compute/virtualMachines/delete', 'Microsoft.Compute/disks/read', 'Microsoft.Compute/disks/write',
    'Microsoft.Network/virtualNetworks/read', 'Microsoft.Network/virtualNetworks/write',
    'Microsoft.Network/networkInterfaces/read', 'Microsoft.Network/networkInterfaces/write',
    'Microsoft.Network/networkSecurityGroups/read', 'Microsoft.Network/networkSecurityGroups/write',
    'Microsoft.Storage/storageAccounts/read', 'Microsoft.Storage/storageAccounts/write',
    'Microsoft.Storage/storageAccounts/listKeys/action', 'Microsoft.KeyVault/vaults/read',
    'Microsoft.KeyVault/vaults/write', 'Microsoft.Authorization/roleAssignments/read',
    'Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleDefinitions/read',
    'Microsoft.Authorization/roleDefinitions/write', 'Microsoft.Resources/subscriptions/resourceGroups/read',
    'Microsoft.Resources/subscriptions/resourceGroups/write', 'Microsoft.Web/sites/read',
    'Microsoft.Web/sites/write', 'Microsoft.ManagedIdentity/userAssignedIdentities/read',
    'Microsoft.ManagedIdentity/userAssignedIdentities/write', 'Microsoft.ContainerService/managedClusters/read',
    'Microsoft.ContainerService/managedClusters/write', 'Microsoft.Sql/servers/read',
    'Microsoft.Sql/servers/write', 'Unknown.Provider/unmappedBenchmarkOperation/read']


def literal_text(value, limit=240):
    return isinstance(value, str) and 0 < len(value) <= limit and all(ord(c) >= 32 for c in value)


def synthetic_snapshot(provider='aws', principals=1000, grants=24, actions=None):
    if principals < 1 or grants < 1:
        raise ValueError('positive principal and grant counts required')
    maximum = len(AWS_ACTIONS) if provider == 'aws' else len(AZURE_ACTIONS) + 1
    if actions is not None and not 1 <= actions <= maximum:
        raise ValueError('action count outside fixture range')
    if provider == 'aws':
        selected_actions = AWS_ACTIONS if actions is None else AWS_ACTIONS[:actions]
        scope = '111122223333/global'
        roles = [{'RoleName': f'role-{i}', 'Arn': f'arn:aws:iam::111122223333:role/role-{i}',
            'AssumeRolePolicyDocument': {'Statement': []}, 'RolePolicyList': [{'PolicyName': 'native-policy',
                'PolicyDocument': {'Statement': [{'Sid': f'Native-{i}-{j}',
                    'Effect': 'Deny' if j % 4 == 0 else 'Allow', 'Action': list(selected_actions),
                    'Resource': f'arn:aws:s3:::native-{i}/path-{j}/*',
                    'Condition': {'Bool': {'aws:SecureTransport': 'true'}}} for j in range(grants)]}}]}
            for i in range(principals)]
        facts = {'iam_role': roles}
    elif provider == 'azure':
        data_actions = ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'] if actions != 1 else []
        selected_actions = AZURE_ACTIONS if actions is None else AZURE_ACTIONS[:max(1, actions - len(data_actions))]
        scope = '/subscriptions/11111111-1111-1111-1111-111111111111'
        definitions, assignments = [], []
        for i in range(principals):
            guid = f'00000000-0000-0000-0000-{i:012d}'
            role = scope + '/providers/Microsoft.Authorization/roleDefinitions/' + guid
            definitions.append({'id': role, 'name': guid, 'properties': {'roleName': f'Native role {i}',
                'type': 'CustomRole', 'permissions': [{'actions': list(selected_actions),
                    'notActions': [f'Microsoft.Compute/virtualMachines/extensions/native-{i}-{j}/read'],
                    'dataActions': list(data_actions),
                    'notDataActions': []} for j in range(grants)]}})
            assignments.append({'id': scope + f'/providers/Microsoft.Authorization/roleAssignments/assignment-{i}',
                'properties': {'principalId': f'22222222-2222-2222-2222-{i:012d}',
                    'roleDefinitionId': role, 'scope': scope, 'condition': f'native condition {i}'}})
        facts = {'role_definition': definitions, 'role_assignment': assignments}
    else:
        raise ValueError('AWS or Azure required')
    return make_snapshot(provider, [scope], [{'type': kind, 'scope': scope, 'status': 'collected', 'items': items}
        for kind, items in facts.items()], created_at='2026-01-01T00:00:00+00:00')


def run_stage(snapshot, inventory):
    with analysis_context(snapshot):
        findings = iam.review_findings(snapshot, inventory)
        graph = iam.build_iam(snapshot, inventory)
        principals = project(snapshot, inventory)
    return {'findings': findings, 'graph': graph, 'principals': principals}


def compare(provider='aws', principals=1000, grants=24, actions=None):
    snapshot = synthetic_snapshot(provider, principals, grants, actions)
    inventory, original = resources(snapshot), digest(snapshot)
    variants = (('baseline', iam._permission_profile_uncached), ('optimized', iam._permission_profile))
    results = {name: {'seconds': [], 'cpu_seconds': [], 'digests': []} for name, _ in variants}
    for iteration in range(3):
        for name, classify in variants if iteration % 2 == 0 else variants[::-1]:
            with patch.object(iam, '_permission_profile', classify):
                gc.collect()
                start, cpu_start = time.perf_counter(), time.process_time()
                output = run_stage(snapshot, inventory)
                results[name]['seconds'].append(time.perf_counter() - start)
                results[name]['cpu_seconds'].append(time.process_time() - cpu_start)
                results[name]['digests'].append(digest(output))
                counts = {'findings': len(output['findings']), 'nodes': len(output['graph']['nodes']),
                    'edges': len(output['graph']['edges'])}
                del output
    for result in results.values():
        fingerprints = result.pop('digests')
        assert len(set(fingerprints)) == 1
        result['output_digest'] = fingerprints[0]
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == original
    return {**results, 'provider': provider, 'principals': principals, 'grants_per_definition': grants,
        'actions_per_grant': actions if actions is not None else len(AWS_ACTIONS) if provider == 'aws' else len(AZURE_ACTIONS) + 1,
        'resources': len(inventory), **counts, 'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'cpu_speedup': round(statistics.median(results['baseline']['cpu_seconds']) /
                             statistics.median(results['optimized']['cpu_seconds']), 2),
        'limitations': 'Synthetic complete offline IAM reviews, graph and principal projection. '
                       'Excludes collection, native checks, other analyses, privilege techniques and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('aws', 'azure'), default='aws')
    parser.add_argument('--principals', type=int, default=1000)
    parser.add_argument('--grants', type=int, default=24)
    parser.add_argument('--actions', type=int)
    args = parser.parse_args()
    print(json.dumps(compare(args.provider, args.principals, args.grants, args.actions), indent=2))
