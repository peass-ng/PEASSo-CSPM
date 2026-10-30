"""Complete offline ALB -> healthy ECS workload -> runtime identity projection.

python -m examples.benchmark_peaso_alb_workloads --workloads 1000
Reference retains earlier identity indexes and the former ALB inventory scans.
"""
import argparse
import hashlib
import json
import statistics
import time
from unittest.mock import patch

from examples.benchmark_peaso_network import synthetic_snapshot as network_snapshot
from peaso.analysis import cloud_workload_index
from peaso.analysis.cloud_workload_index import CloudWorkloadIndex as IndexedCloudWorkloads
from peaso.principal_exposure import project
from peaso.snapshot import digest, resources, seal, validate


class FormerAlbWorkloads(IndexedCloudWorkloads):
    def candidates(self, kind, field, values, **options):
        if field in {'target_group_lb', 'ecs_service_target_group', 'running_task_definition'} or (kind, field) in {
                ('target_group', 'TargetGroupArn'), ('ecs_task', 'taskDefinitionArn'),
                ('network_interface', 'NetworkInterfaceId')}:
            return self.by_type[kind]
        return super().candidates(kind, field, values, **options)


def synthetic_snapshot(workloads=1000, layout='distributed'):
    if layout not in ('distributed', 'shared'):
        raise ValueError('distributed or shared layout required')
    snapshot = network_snapshot('aws', workloads=workloads, selectors=1, subnets=1)
    scope = snapshot['scopes'][0]
    for collection in snapshot['collections']:
        if collection['type'] == 'instance':
            collection.update(items=[], status='empty')
        elif collection['type'] == 'route_table':
            # The ALB subnet path needs a confirmed association and an active IGW default route.
            for table in collection['items']:
                for association in table['Associations']:
                    association['AssociationState'] = {'State': 'associated'}
                for route in table['Routes']:
                    route['State'] = 'active'
    snapshot['collections'].extend([
        {'type': 'vpc_block_public_access_options', 'scope': scope, 'status': 'collected', 'items': [
            {'VpcBlockPublicAccessOptions': {'State': 'default-state', 'InternetGatewayBlockMode': 'off'}}]},
        {'type': 'internet_gateway', 'scope': scope, 'status': 'collected', 'items': [
            {'InternetGatewayId': 'igw-a', 'Attachments': [{'VpcId': 'vpc-a', 'State': 'available'}]}]}])
    facts = {kind: [] for kind in ('load_balancer', 'target_group', 'ecs_service', 'ecs_task',
                                  'ecs_task_definition', 'network_interface')}
    for i in range(workloads):
        prefix = 'arn:aws:elasticloadbalancing:us-east-1:111122223333:'
        lb, tg = prefix + f'loadbalancer/app/web-{i}/1', prefix + f'targetgroup/web-{i}/1'
        definition = f'arn:aws:ecs:us-east-1:111122223333:task-definition/web-{i}:1'
        ip, eni = f'10.{i // 62500 % 250}.{i // 250 % 250}.{i % 250 + 1}', f'eni-{i}'
        facts['load_balancer'].append({'LoadBalancerArn': lb, 'Type': 'application',
            'Scheme': 'internet-facing', 'State': {'Code': 'active'}, 'IpAddressType': 'ipv4',
            'DNSName': f'web-{i}.example.elb.amazonaws.com',
            'VpcId': 'vpc-a', 'SecurityGroups': ['sg-a'], 'AvailabilityZones': [{'SubnetId': 'subnet-0'}],
            'Listeners': {'collection_status': 'collected', 'items': [{'Port': 400, 'Protocol': 'HTTP',
                'DefaultActions': [{'Type': 'forward', 'TargetGroupArn': tg}]}]}})
        facts['target_group'].append({'TargetGroupArn': tg, 'LoadBalancerArns': [lb], 'TargetType': 'ip',
            'TargetHealth': {'collection_status': 'collected', 'TargetHealthDescriptions': [
                {'Target': {'Id': ip, 'Port': 8080}, 'TargetHealth': {'State': 'healthy'}}]}})
        facts['ecs_service'].append({'serviceName': f'web-{i}', 'taskDefinition': definition,
            'loadBalancers': [{'targetGroupArn': tg, 'containerPort': 8080}]})
        facts['ecs_task'].append({'taskArn': f'arn:aws:ecs:us-east-1:111122223333:task/task-{i}',
            'group': f'service:web-{i}', 'lastStatus': 'RUNNING', 'taskDefinitionArn': definition,
            'attachments': [{'details': [{'name': 'networkInterfaceId', 'value': eni}]}]})
        facts['ecs_task_definition'].append({'taskDefinitionArn': definition,
            'taskRoleArn': f'arn:aws:iam::111122223333:role/task-{i}'})
        facts['network_interface'].append({'NetworkInterfaceId': eni, 'PrivateIpAddress': ip})
    if layout == 'shared':
        facts['load_balancer'] = facts['load_balancer'][:1]
        lb = facts['load_balancer'][0]
        health_rows = [tg['TargetHealth']['TargetHealthDescriptions'] for tg in facts['target_group']]
        facts['target_group'] = facts['target_group'][:5]
        for target_group in facts['target_group']:
            target_group['LoadBalancerArns'] = [lb['LoadBalancerArn']]
            target_group['TargetHealth']['TargetHealthDescriptions'] = []
        for i, service in enumerate(facts['ecs_service']):
            target_group = facts['target_group'][i % len(facts['target_group'])]
            service['loadBalancers'][0]['targetGroupArn'] = target_group['TargetGroupArn']
            target_group['TargetHealth']['TargetHealthDescriptions'].extend(health_rows[i])
        lb['Listeners']['items'][0]['DefaultActions'] = [{'Type': 'forward', 'ForwardConfig': {
            'TargetGroups': [{'TargetGroupArn': tg['TargetGroupArn'], 'Weight': 1} for tg in facts['target_group']]}}]
    snapshot['collections'].extend({'type': kind, 'scope': scope, 'status': 'collected', 'items': items}
                                   for kind, items in facts.items())
    return validate(seal(snapshot))


def compare(workloads=1000, layout='distributed'):
    snapshot = synthetic_snapshot(workloads, layout)
    rows, original = resources(snapshot), digest(snapshot)
    results = {}
    optimized = cloud_workload_index.CloudWorkloadIndex
    for name, factory in (('baseline', FormerAlbWorkloads), ('optimized', optimized)):
        elapsed, cpu, fingerprints = [], [], []
        with patch.object(cloud_workload_index, 'CloudWorkloadIndex', factory):
            for _ in range(3):
                start, cpu_start = time.perf_counter(), time.process_time()
                output = project(snapshot, rows)
                elapsed.append(time.perf_counter() - start)
                cpu.append(time.process_time() - cpu_start)
                assert len(output) == workloads
                assert all(card['exposures'][0]['state'] == 'declared' for card in output.values())
                fingerprints.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
        assert len(set(fingerprints)) == 1
        results[name] = {'seconds': elapsed, 'cpu_seconds': cpu, 'output_digest': fingerprints[0]}
    assert results['baseline']['output_digest'] == results['optimized']['output_digest']
    assert digest(snapshot) == original
    return {**results, 'workloads': workloads, 'layout': layout, 'resources': len(rows), 'principal_cards': len(output),
        'identical_output': True, 'input_unchanged': True,
        'speedup': round(statistics.median(results['baseline']['seconds']) /
                         statistics.median(results['optimized']['seconds']), 2),
        'limitations': 'Synthetic complete offline ALB/ECS principal/exposure projection; excludes collection, '
                       'native checks, other analyses and rendering.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workloads', type=int, default=1000)
    parser.add_argument('--layout', choices=('distributed', 'shared'), default='distributed')
    args = parser.parse_args()
    print(json.dumps(compare(args.workloads, args.layout), indent=2))
