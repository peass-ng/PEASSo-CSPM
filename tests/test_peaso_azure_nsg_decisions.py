"""Shared NSG decisions retain exact ordered rules and per-target evidence."""
import copy
import random
from unittest.mock import patch

import pytest

from tests.synthetic.benchmark_peaso_cloud_workloads import synthetic_snapshot
from peaso.analysis import internet_exposure as exposure
from peaso.principal_exposure import project
from peaso.snapshot import resources, seal, validate


def nsg(rules):
    return {'data': {'properties': {'securityRules': rules}}}


def rule(priority=100, **properties):
    return {'name': f'rule-{priority}', 'properties': {'priority': priority, 'direction': 'Inbound',
        'sourceAddressPrefix': '*', 'destinationAddressPrefix': '*', 'protocol': 'Tcp',
        'destinationPortRange': '443', 'access': 'Allow', **properties}}


def outcome(function):
    try:
        return 'value', function()
    except (TypeError, KeyError, AttributeError, ValueError) as error:
        return 'error', type(error)


def test_random_ordered_rules_match_literal_evaluation_for_every_target():
    rng = random.Random(347)
    for _ in range(30):
        rules = []
        for i in range(12):
            props = {'access': rng.choice(['Allow', 'Deny']), 'protocol': rng.choice(['*', 'Tcp', 'Udp', 'Icmp']),
                'sourceAddressPrefix': rng.choice(['*', 'Internet', '10.0.0.0/8', '::/0']),
                'destinationAddressPrefix': rng.choice(['*', 'VirtualNetwork', '10.0.0.0/24', '10.0.1.1', '::/0']),
                'destinationPortRange': rng.choice(['*', '400-420', '443', '80', 'invalid'])}
            if rng.randrange(3) == 0:
                props['destinationApplicationSecurityGroups'] = [{'id': rng.choice(['/groups/a', '/groups/b'])}]
            if rng.randrange(5) == 0:
                props['direction'] = 'Outbound'
            rules.append(rule(100 + i, **props))
        owner = nsg(rules)
        cache, literal = {}, {}
        for address in ('10.0.0.1', '10.0.1.1', '2001:db8::1', 'invalid', None):
            for groups in ([], ['/GROUPS/A'], ['/groups/b', '/groups/a']):
                expected = outcome(lambda: exposure._nsg_allowed_rules(owner, address, groups, cache=literal))
                assert outcome(lambda: exposure._nsg_allowed(owner, address, groups, cache=cache)) == expected
                assert outcome(lambda: exposure._nsg_allowed(owner, address, groups, cache=cache)) == expected


def test_unconditional_nsg_reuses_one_decision_across_unique_addresses(monkeypatch):
    owner, cache = nsg([rule()]), {}
    original = exposure._nsg_allowed_rules
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(exposure, '_nsg_allowed_rules', counted)
    for i in range(200):
        assert exposure._nsg_allowed(owner, f'10.0.0.{i}', [f'/groups/{i}'], cache=cache)[0] == exposure.pset('tcp', 443, 443)
    assert len(calls) == 1
    assert len(cache['azure_nsg_decisions']['entries']) == 1


def test_cidr_and_asg_dependencies_keep_distinct_contexts_and_priorities():
    owner = nsg([rule(100, access='Deny', destinationAddressPrefix='10.0.0.1/32'),
                 rule(200, destinationApplicationSecurityGroups=[{'id': '/groups/web'}])])
    cache = {}
    assert exposure._nsg_allowed(owner, '10.0.0.1', ['/GROUPS/WEB'], cache=cache)[0] == {}
    assert exposure._nsg_allowed(owner, '10.0.0.2', ['/GROUPS/WEB'], cache=cache)[0] == exposure.pset('tcp', 443, 443)
    assert exposure._nsg_allowed(owner, '10.0.0.2', [], cache=cache)[0] == {}
    assert len(cache['azure_nsg_decisions']['entries']) == 3


def test_cache_replays_have_independent_evidence_containers():
    owner, cache = nsg([rule()]), {}
    first = exposure._nsg_allowed(owner, cache=cache)
    expected = copy.deepcopy(first)
    first[0].clear()
    first[1][0]['ports'].clear()
    first[1][0]['access'] = 'changed'
    second = exposure._nsg_allowed(owner, cache=cache)
    assert second == expected
    second[1].clear()
    assert exposure._nsg_allowed(owner, cache=cache) == expected


@pytest.mark.parametrize('rules', [[None], [rule(priority='invalid')], [{'properties': 'invalid'}],
                                  [rule(destinationPortRange={})], [rule(destinationApplicationSecurityGroups=[None])]])
@pytest.mark.parametrize('address,groups', [(None, ()), ('10.0.0.1', [None]), ([], []), ('invalid', {})])
def test_malformed_values_preserve_literal_errors_and_results(rules, address, groups):
    owner, cache, literal = nsg(rules), {}, {}
    for _ in range(2):
        assert outcome(lambda: exposure._nsg_allowed(owner, address, groups, cache=cache)) == outcome(
            lambda: exposure._nsg_allowed_rules(owner, address, groups, cache=literal))


def test_unique_targets_fall_back_when_cache_is_full():
    owner = nsg([rule(destinationAddressPrefix='10.0.0.0/8')])
    cache = {}
    for i in range(1030):
        address = f'10.0.{i // 250}.{i % 250 + 1}'
        assert exposure._nsg_allowed(owner, address, cache=cache) == exposure._nsg_allowed_rules(owner, address)
    assert len(cache['azure_nsg_decisions']['entries']) == 1024
    assert cache['azure_nsg_decisions']['weight'] <= 20_000


def test_rule_budget_falls_back_without_losing_evidence():
    owner = nsg([rule()])
    cache = {'azure_nsg_decisions': {'entries': {}, 'dependencies': {}, 'weight': 20_000}}
    assert exposure._nsg_allowed(owner, cache=cache) == exposure._nsg_allowed_rules(owner)
    assert cache['azure_nsg_decisions']['entries'] == {}


def test_many_distinct_nsgs_keep_both_caches_bounded():
    owners = [nsg([rule()]) for _ in range(1030)]
    cache = {}
    for owner in owners:
        assert exposure._nsg_allowed(owner, cache=cache) == exposure._nsg_allowed_rules(owner)
    assert len(cache['azure_nsg_decisions']['entries']) == 1024
    assert len(cache['azure_nsg_decisions']['dependencies']) == 1024


@pytest.mark.parametrize('scenario', ['shared', 'cidr', 'asg', 'deny', 'missing', 'malformed'])
def test_complete_projection_equals_literal_nsg_evaluation_and_refreshes(scenario):
    snapshot = synthetic_snapshot('azure', 12)
    collections = {c['type']: c for c in snapshot['collections']}
    rules = collections['nsg']['items'][0]['properties']['securityRules']
    if scenario == 'cidr':
        rules[0]['properties']['destinationAddressPrefix'] = '10.0.0.1/32'
    elif scenario == 'asg':
        rules[0]['properties']['destinationApplicationSecurityGroups'] = [{'id': '/groups/web'}]
        for nic in collections['nic']['items'][::2]:
            nic['properties']['ipConfigurations'][0]['properties']['applicationSecurityGroups'] = [{'id': '/GROUPS/WEB'}]
    elif scenario == 'deny':
        rules[0]['properties']['access'] = 'Deny'
    elif scenario == 'missing':
        snapshot['collections'].remove(collections['nsg'])
    elif scenario == 'malformed':
        rules[0]['properties']['priority'] = 'invalid'
    snapshot = validate(seal(snapshot))
    before, rows = copy.deepcopy(snapshot), resources(snapshot)
    with patch.object(exposure, '_nsg_allowed', exposure._nsg_allowed_rules):
        expected = project(snapshot, rows)
    assert project(snapshot, rows) == expected
    assert snapshot == before
    if scenario == 'shared':
        rules = next(c for c in snapshot['collections'] if c['type'] == 'nsg')['items'][0]['properties']['securityRules']
        for rule_ in rules:
            rule_['properties']['access'] = 'Deny'
        refreshed = validate(seal(snapshot))
        assert project(refreshed, resources(refreshed)) == {}
