"""Whole network-stage scaling without dropping evidence or uncertain matches."""
import copy

import pytest

from tests.synthetic.benchmark_peaso_network import run_stage, synthetic_snapshot
from peaso.analysis import network, internet_exposure


def test_selective_workloads_use_index_and_keep_every_native_match(monkeypatch):
    snapshot = synthetic_snapshot("k8s", workloads=1000, selectors=100)
    before = copy.deepcopy(snapshot)
    original, calls = network._k8s_matches, []

    def counted(labels, requirements):
        calls.append(1)
        return original(labels, requirements)

    monkeypatch.setattr(network, '_k8s_matches', counted)
    result = run_stage(snapshot)
    matches = [e for e in result['graph']['edges'] if e['type'] == 'matches_pod']
    assert len(matches) == 200
    assert len(calls) == 200  # One candidate per Service and NetworkPolicy, rather than 200,000 pod scans.
    assert snapshot == before
    assert len([f for f in result['findings'] if f['check_id'] == 'analysis.internet_exposure']) == 25


@pytest.mark.parametrize('operator,values,expected', [
    ('In', ['web'], {'app-0'}), ('NotIn', ['web'], {'app-1', 'app-2'}),
    ('Exists', [], {'app-0', 'app-1'}), ('DoesNotExist', [], {'app-2'}),
])
def test_expression_semantics_and_malformed_pod_uncertainty(operator, values, expected):
    snapshot = synthetic_snapshot('k8s', workloads=4, selectors=1)
    for collection in snapshot['collections']:
        if collection['type'] == 'pod':
            for row, labels in zip(collection['items'], ({'tier': 'web'}, {'tier': 'data'}, {}, {'tier': []})):
                row['metadata']['labels'] = labels
        if collection['type'] == 'networkpolicy':
            collection['items'][0]['spec']['podSelector'] = {
                'matchExpressions': [{'key': 'tier', 'operator': operator, 'values': values}]}
    result = run_stage(snapshot)
    graph = result['graph']
    nodes = {row['id']: row for row in graph['nodes']}
    selector = next(row for row in graph['nodes'] if row['type'] == 'workload_selector'
                    and row['evidence']['selector_kind'] == 'networkpolicy')
    assert selector['evidence']['matching_workloads'] == 'partial'
    assert selector['evidence']['reason'] == 'some_pod_labels_are_malformed'
    assert {nodes[e['target']]['label'] for e in graph['edges']
            if e['type'] == 'matches_pod' and e['source'] == selector['id']} == expected


def test_aws_shared_rules_are_parsed_once_and_full_findings_remain(monkeypatch):
    snapshot = synthetic_snapshot('aws', workloads=100, subnets=3)
    before = copy.deepcopy(snapshot)
    original, calls = internet_exposure._aws_group_rules, []

    def counted(group, *args, **kwargs):
        calls.append(group['id'])
        return original(group, *args, **kwargs)

    monkeypatch.setattr(internet_exposure, '_aws_group_rules', counted)
    result = run_stage(snapshot)
    assert len(calls) == 1
    exposures = [f for f in result['findings'] if f['check_id'] == 'analysis.internet_exposure']
    assert len(exposures) == 100 and all(f['status'] == 'FAIL' for f in exposures)
    assert all(len(next(p for p in f['evidence']['path'] if p['layer'] == 'security_group')
                       ['groups'][0]['internet_rules']) == 20 for f in exposures)
    assert snapshot == before
    # Each new evaluation derives facts afresh, including changed rules at the same resource ID.
    for collection in snapshot['collections']:
        if collection['type'] == 'security_group':
            collection['items'][0]['IpPermissions'] = []
    refreshed = run_stage(snapshot)
    assert len(calls) == 2
    assert all(f['status'] == 'PASS' for f in refreshed['findings'] if f['check_id'] == 'analysis.internet_exposure')


def test_aws_association_index_keeps_first_native_match_and_default_order():
    snapshot = synthetic_snapshot('aws', workloads=2, subnets=2)
    inventory = internet_exposure.Inventory(snapshot, [
        {'id': 'first', 'native_id': 'first', 'type': 'route_table', 'scope': 'scope',
         'data': {'VpcId': 'vpc', 'Associations': [{'SubnetId': 'subnet', 'Main': True}]}},
        {'id': 'second', 'native_id': 'second', 'type': 'route_table', 'scope': 'scope',
         'data': {'VpcId': 'vpc', 'Associations': [{'SubnetId': 'subnet', 'Main': True}]}},
    ])
    subnets, defaults = inventory.aws_associations('route_table')
    assert subnets['subnet']['id'] == defaults['vpc']['id'] == 'first'
