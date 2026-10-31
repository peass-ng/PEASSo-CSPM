"""Compare complete offline AWS/Azure principal/exposure projection.

python -m tests.synthetic.benchmark_peaso_cloud_workloads --provider azure --workloads 1000
The reference returns original full inventories to the unchanged join predicates.
No cloud requests, native checks or report rendering are included.
"""
import argparse
import hashlib
import json
import statistics
import time
from unittest.mock import patch

from tests.synthetic.benchmark_peaso_network import synthetic_snapshot as network_snapshot
from peaso.analysis import cloud_workload_index
from peaso.principal_exposure import project
from peaso.snapshot import digest, resources, seal, validate


class LinearCloudWorkloads:
    def __init__(self, by_type):
        self.by_type = by_type

    def candidates(self, kind, field, values, **options):
        return self.by_type[kind]


def synthetic_snapshot(provider, workloads=1000):
    snapshot = network_snapshot(provider, workloads=workloads, selectors=workloads, subnets=1)
    scope = snapshot['scopes'][0]
    collections = {c['type']: c['items'] for c in snapshot['collections']}
    additions = {}
    if provider == 'azure':
        additions = {'vm': [], 'managed_identity': []}
        for i, nic in enumerate(collections['nic']):
            vm = f'/subscriptions/benchmark/resourceGroups/benchmark/providers/Microsoft.Compute/virtualMachines/vm-{i}'
            identity = f'/subscriptions/benchmark/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-{i}'
            nic['properties']['virtualMachine'] = {'id': vm.upper()}
            additions['vm'].append({'id': vm, 'identity': {'userAssignedIdentities': {identity.upper(): {}}}})
            additions['managed_identity'].append({'id': identity, 'properties': {'principalId': f'identity-{i}'}})
    elif provider == 'aws':
        additions = {'network_interface': [], 'ecs_task': [], 'ecs_task_definition': []}
        for i, instance in enumerate(collections['instance']):
            eni, definition = f'eni-{i}', f'arn:aws:ecs:us-east-1:111122223333:task-definition/task-{i}:1'
            additions['network_interface'].append({'NetworkInterfaceId': eni,
                'VpcId': 'vpc-a', 'SubnetId': 'subnet-0', 'Groups': [{'GroupId': 'sg-a'}],
                'Status': 'in-use', 'Association': {'PublicIp': instance['PublicIpAddress']}})
            additions['ecs_task'].append({'taskArn': f'arn:aws:ecs:us-east-1:111122223333:task/task-{i}',
                'lastStatus': 'RUNNING', 'taskDefinitionArn': definition,
                'attachments': [{'details': [{'name': 'networkInterfaceId', 'value': eni}]}]})
            additions['ecs_task_definition'].append({'taskDefinitionArn': definition,
                'taskRoleArn': f'arn:aws:iam::111122223333:role/task-{i}'})
    else:
        raise ValueError('AWS or Azure required')
    snapshot['collections'].extend({'type': kind, 'scope': scope, 'status': 'collected', 'items': items}
                                   for kind, items in additions.items())
    return validate(seal(snapshot))


def compare(provider, workloads=1000):
    snapshot = synthetic_snapshot(provider, workloads)
    inventory, original = resources(snapshot), digest(snapshot)
    results = {}
    optimized = cloud_workload_index.CloudWorkloadIndex
    for name, factory in (('baseline', LinearCloudWorkloads), ('optimized', optimized)):
        elapsed, cpu, fingerprints = [], [], []
        with patch.object(cloud_workload_index, 'CloudWorkloadIndex', factory):
            for _ in range(3):
                cpu_started, started = time.process_time(), time.perf_counter()
                output = project(snapshot, inventory)
                elapsed.append(time.perf_counter() - started)
                cpu.append(time.process_time() - cpu_started)
                fingerprints.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
                assert len(output) == workloads, 'fixture must exercise every workload identity'
        assert len(set(fingerprints)) == 1
        results[name] = {'seconds': elapsed, 'cpu_seconds': cpu, 'output_digest': fingerprints[0]}
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == original
    return {**results, 'provider': provider, 'workloads': workloads, 'resources': len(inventory),
        'principal_cards': len(output), 'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'limitations': 'Synthetic complete offline principal/exposure projection; excludes collection, '
                       'native checks, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('aws', 'azure'), required=True)
    parser.add_argument('--workloads', type=int, default=1000)
    args = parser.parse_args()
    print(json.dumps(compare(args.provider, args.workloads), indent=2))
