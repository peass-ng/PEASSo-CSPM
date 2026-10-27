"""ALB correlation keeps listener, service, task identity and health proofs."""
from collections import defaultdict
import copy
from unittest.mock import patch

import pytest

from examples.benchmark_peaso_alb_workloads import FormerAlbWorkloads, synthetic_snapshot
from peaso.analysis import cloud_workload_index as indexed
from peaso.principal_exposure import project
from peaso.snapshot import make_snapshot, resources, seal, validate


def outcome(function):
    try:
        return 'value', function()
    except (KeyError, TypeError, AttributeError) as error:
        return 'error', type(error)


@pytest.mark.parametrize('relation,field,native', [
    ('target_group_lb', 'LoadBalancerArns', ['match', 'other']),
    ('target_group_lb', 'LoadBalancerArns', 'prefix-match-suffix'),
    ('target_group_lb', 'LoadBalancerArns', {'match': 'value'}),
    ('target_group_lb', 'LoadBalancerArns', 4),
    ('ecs_service_target_group', 'loadBalancers', [{'targetGroupArn': 'match'}]),
    ('ecs_service_target_group', 'loadBalancers', [{'targetGroupArn': 'match'}, None]),
    ('ecs_service_target_group', 'loadBalancers', [{'targetGroupArn': []}]),
    ('running_task_definition', 'taskDefinitionArn', 'match'),
    ('running_task_definition', 'taskDefinitionArn', [])])
@pytest.mark.parametrize('keys', [['match'], ['absent'], [], [None]])
def test_candidates_retain_original_membership_errors_and_order(relation, field, native, keys):
    rows = [{'data': {'lastStatus': 'RUNNING', field: value}} for value in (None, native)]
    rows += [rows[-1], {'data': {'lastStatus': 'STOPPED', field: []}}]
    owner = indexed.CloudWorkloadIndex(defaultdict(list, test=rows))

    def match(source):
        if relation == 'target_group_lb':
            # Original outer predicate uses native membership, including strings.
            key = keys[0] if keys else None
            return [row for row in source if key and key in (row['data'].get(field) or [])]
        if relation == 'ecs_service_target_group':
            return [row for row in source if any(b.get('targetGroupArn') in set(keys)
                    for b in row['data'].get(field) or [])]
        return [row for row in source if row['data'].get('lastStatus') == 'RUNNING'
                and row['data'].get(field) in set(keys)]

    assert outcome(lambda: match(owner.candidates('test', relation, keys))) == outcome(lambda: match(rows))


@pytest.mark.parametrize('scenario', ['healthy', 'unhealthy', 'wrong_ip', 'wrong_port', 'health_missing',
    'other_service', 'stopped', 'missing_eni', 'no_forward', 'zero_weight', 'private_source',
    'public_source', 'narrow_public_source', 'capacity', 'duplicates', 'shared_definition', 'substring'])
def test_complete_projection_keeps_exact_health_and_routing_evidence(scenario):
    snapshot = synthetic_snapshot(6)
    facts = {c['type']: c['items'] for c in snapshot['collections']}
    listener = facts['load_balancer'][0]['Listeners']['items'][0]
    tg = facts['target_group'][0]
    health = tg['TargetHealth']['TargetHealthDescriptions'][0]
    if scenario == 'unhealthy':
        health['TargetHealth']['State'] = 'unhealthy'
    elif scenario == 'wrong_ip':
        health['Target']['Id'] = '10.10.10.10'
    elif scenario == 'wrong_port':
        health['Target']['Port'] = 9999
    elif scenario == 'health_missing':
        tg['TargetHealth']['collection_status'] = 'denied'
    elif scenario == 'other_service':
        facts['ecs_task'][0]['group'] = 'service:unrelated'
    elif scenario == 'stopped':
        facts['ecs_task'][0]['lastStatus'] = 'STOPPED'
    elif scenario == 'missing_eni':
        facts['network_interface'].pop(0)
    elif scenario == 'no_forward':
        listener['DefaultActions'] = [{'Type': 'fixed-response'}]
    elif scenario == 'zero_weight':
        listener['DefaultActions'] = [{'Type': 'forward', 'ForwardConfig': {
            'TargetGroups': [{'TargetGroupArn': tg['TargetGroupArn'], 'Weight': 0}]}}]
    elif scenario in ('private_source', 'public_source', 'narrow_public_source'):
        listener['DefaultActions'] = []
        listener['Rules'] = {'collection_status': 'collected', 'items': [{'RuleArn': 'rule-first',
            'Conditions': [{'Field': 'source-ip', 'Values': ['10.0.0.0/8' if scenario == 'private_source' else
                                                            '8.8.8.8/32' if scenario == 'narrow_public_source' else '0.0.0.0/0']}],
            'Actions': [{'Type': 'forward', 'TargetGroupArn': tg['TargetGroupArn']}]}]}
    elif scenario == 'duplicates':
        for kind in ('target_group', 'ecs_service', 'ecs_task', 'network_interface'):
            facts[kind].append(copy.deepcopy(facts[kind][0]))
    elif scenario == 'shared_definition':
        facts['ecs_task'][1]['taskDefinitionArn'] = facts['ecs_task'][0]['taskDefinitionArn']
        facts['ecs_service'][1]['taskDefinition'] = facts['ecs_service'][0]['taskDefinition']
    elif scenario == 'substring':
        tg['LoadBalancerArns'] = 'prefix-' + tg['LoadBalancerArns'][0] + '-suffix'
    snapshot = validate(seal(snapshot))
    before, rows = copy.deepcopy(snapshot), resources(snapshot)
    with patch.object(indexed, 'CloudWorkloadIndex', FormerAlbWorkloads):
        expected = project(snapshot, rows)
    with patch.object(indexed, 'MAX_KEYS', 1 if scenario == 'capacity' else indexed.MAX_KEYS):
        actual = project(snapshot, rows)
    assert actual == expected
    assert snapshot == before
    key = 'arn:aws:iam::111122223333:role/task-0'
    if scenario == 'stopped':
        assert key not in actual
    else:
        target_id = next(r['id'] for r in rows if r['type'] == 'ecs_task'
                         and r['data']['taskArn'].endswith('/task-0'))
        signal = next(s for s in actual[key]['exposures'] if s['workload_resource'] == target_id
                      and s['public_addresses'] == ['web-0.example.elb.amazonaws.com'])
        confirmed = scenario in ('healthy', 'public_source', 'narrow_public_source', 'capacity', 'duplicates', 'shared_definition', 'substring')
        assert signal['state'] == ('declared' if confirmed else 'unknown')
        assert ('backend_evidence' in signal) == confirmed
        if confirmed:
            assert signal['backend_evidence']['healthy_target'] == {'ip': '10.0.0.1', 'port': 8080}


def test_whole_privilege_pipeline_preserves_alb_exposure_annotations():
    from peaso.privesc import analyze

    snapshot = synthetic_snapshot(4)
    roles = [{'Arn': f'arn:aws:iam::111122223333:role/task-{i}', 'RoleName': f'task-{i}',
        'AssumeRolePolicyDocument': {'Statement': []}, 'RolePolicyList': [{'PolicyName': 'admin',
        'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}]} for i in range(4)]
    snapshot['collections'].append({'type': 'iam_role', 'scope': snapshot['scopes'][0],
                                    'status': 'collected', 'items': roles})
    snapshot = validate(seal(snapshot))
    before = copy.deepcopy(snapshot)
    with patch.object(indexed, 'CloudWorkloadIndex', FormerAlbWorkloads):
        expected = analyze(snapshot)
    actual = analyze(snapshot)
    expected['stats'].pop('timing_seconds')
    actual['stats'].pop('timing_seconds')
    assert actual == expected
    assert snapshot == before
    assert actual['graph']['nodes']


def test_shared_load_balancer_keeps_all_workload_health_pairs():
    snapshot = synthetic_snapshot(30, 'shared')
    rows = resources(snapshot)
    with patch.object(indexed, 'CloudWorkloadIndex', FormerAlbWorkloads):
        expected = project(snapshot, rows)
    actual = project(snapshot, rows)
    assert actual == expected
    assert len(actual) == 30
    assert all(len(card['exposures']) == 1 and card['exposures'][0]['state'] == 'declared' for card in actual.values())


@pytest.mark.parametrize('backend_open,healthy,expected', [
    (True, True, 'declared'), (False, True, 'unknown'), (True, False, 'unknown')])
def test_nlb_tcp_ip_target_requires_exact_health_and_backend_sg_nacl(backend_open, healthy, expected):
    snapshot = synthetic_snapshot(1)
    facts = {c['type']: c['items'] for c in snapshot['collections']}
    lb = facts['load_balancer'][0]
    lb['Type'] = 'network'
    lb['SecurityGroups'] = []
    lb['Listeners']['items'][0]['Protocol'] = 'TCP'
    tg = facts['target_group'][0]
    tg['Protocol'] = 'TCP'
    if not healthy:
        tg['TargetHealth']['TargetHealthDescriptions'][0]['TargetHealth']['State'] = 'unhealthy'
    eni = facts['network_interface'][0]
    eni.update(SubnetId='subnet-0', VpcId='vpc-a', Groups=[{'GroupId': 'sg-target'}])
    facts['security_group'].append({'GroupId': 'sg-target', 'VpcId': 'vpc-a', 'IpPermissions': [
        {'IpProtocol': 'tcp', 'FromPort': 8080, 'ToPort': 8080, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ] if backend_open else []})
    snapshot = validate(seal(snapshot))
    actual = project(snapshot, resources(snapshot))
    signal = actual['arn:aws:iam::111122223333:role/task-0']['exposures'][0]
    assert signal['state'] == expected
    assert ('backend_evidence' in signal) == (expected == 'declared')
    if expected == 'declared':
        assert signal['backend_evidence']['healthy_target'] == {'ip': '10.0.0.1', 'port': 8080}
        assert signal['backend_evidence']['backend_security_groups'] == ['sg-target']
        assert signal['backend_evidence']['backend_acl'] == 'acl-0'


@pytest.mark.parametrize('healthy,backend_open,expected', [
    (True, True, 'declared'), (False, True, 'unknown'), (True, False, 'unknown')])
def test_classic_elb_instance_role_requires_health_and_backend_port(healthy, backend_open, expected):
    scope = '111122223333/us-east-1'
    role = 'arn:aws:iam::111122223333:role/classic-target'
    profile = 'arn:aws:iam::111122223333:instance-profile/classic-target'
    lb = {'LoadBalancerName': 'classic-web', 'Scheme': 'internet-facing', 'DNSName': 'classic.example.com',
          'VPCId': 'vpc-1', 'Subnets': ['subnet-1'], 'SecurityGroups': ['sg-lb'],
          'ListenerDescriptions': [{'Listener': {'LoadBalancerPort': 443, 'InstancePort': 8080,
                                                  'Protocol': 'HTTPS', 'InstanceProtocol': 'HTTP'}}],
          'Instances': [{'InstanceId': 'i-1'}],
          'InstanceHealth': {'collection_status': 'collected', 'InstanceStates': [
              {'InstanceId': 'i-1', 'State': 'InService' if healthy else 'OutOfService'}]}}
    instance = {'InstanceId': 'i-1', 'State': {'Name': 'running'}, 'VpcId': 'vpc-1',
                'IamInstanceProfile': {'Arn': profile}, 'NetworkInterfaces': [
                    {'NetworkInterfaceId': 'eni-1', 'SubnetId': 'subnet-1', 'VpcId': 'vpc-1',
                     'Attachment': {'DeviceIndex': 0}, 'Groups': [{'GroupId': 'sg-target'}]}]}
    def sg(name, port, open_rule=True):
        return {'GroupId': name, 'VpcId': 'vpc-1', 'IpPermissions': [
            {'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ] if open_rule else []}
    collections = {
        'classic_load_balancer': [lb], 'instance': [instance],
        'iam_instance_profile': [{'Arn': profile, 'Roles': [{'Arn': role}]}],
        'vpc': [{'VpcId': 'vpc-1'}], 'subnet': [{'SubnetId': 'subnet-1', 'VpcId': 'vpc-1'}],
        'security_group': [sg('sg-lb', 443), sg('sg-target', 8080, backend_open)],
        'network_acl': [{'NetworkAclId': 'acl-1', 'VpcId': 'vpc-1',
                         'Associations': [{'SubnetId': 'subnet-1'}],
                         'Entries': [{'RuleNumber': 100, 'Protocol': '-1', 'CidrBlock': '0.0.0.0/0',
                                      'RuleAction': 'allow', 'Egress': egress} for egress in (False, True)]}],
    }
    snap = make_snapshot('aws', [scope], [{'type': kind, 'scope': scope,
        'status': 'collected', 'items': items} for kind, items in collections.items()])
    actual = project(snap, resources(snap))
    signal = actual[role]['exposures'][0]
    assert signal['state'] == expected
    assert ('backend_evidence' in signal) == (expected == 'declared')
    if expected == 'declared':
        assert signal['backend_evidence']['healthy_target'] == {'instance_id': 'i-1', 'port': 8080}
        assert signal['backend_evidence']['listener_port'] == 443
