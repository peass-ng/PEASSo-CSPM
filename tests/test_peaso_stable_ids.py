"""String-only IDs retain the exact general JSON encoder's bytes and fallback."""
import json
import random

import pytest

from tests.synthetic.benchmark_peaso_stable_ids import id_factory, literal_id, network_stage, iam_stage, iam_snapshot, network_snapshot as lb_snapshot
from tests.synthetic.benchmark_peaso_network import synthetic_snapshot as network_snapshot
from peaso.analysis import common
from peaso.snapshot import digest, make_snapshot, resources


def workflow_snapshot(provider):
    if provider == 'gcp':
        return lb_snapshot(8)
    if provider != 'azure':
        return network_snapshot(provider, workloads=8, selectors=3, subnets=2)
    scope = '/subscriptions/benchmark'
    network = scope + '/resourceGroups/native/providers/Microsoft.Network'
    nsg, subnet = network + '/networkSecurityGroups/native', network + '/virtualNetworks/native/subnets/default'
    nic, public = network + '/networkInterfaces/native', network + '/publicIPAddresses/native'
    vm = scope + '/resourceGroups/native/providers/Microsoft.Compute/virtualMachines/native'
    facts = {
        'nsg': [{'id': nsg, 'properties': {'securityRules': [{'name': 'https', 'properties': {
            'priority': 100, 'direction': 'Inbound', 'access': 'Allow', 'protocol': 'Tcp',
            'sourceAddressPrefix': '*', 'destinationAddressPrefix': '*', 'destinationPortRange': '443'}}]}}],
        'subnet': [{'id': subnet, 'properties': {'networkSecurityGroup': {'id': nsg}}}],
        'nic': [{'id': nic, 'properties': {'ipConfigurations': [{'properties': {
            'privateIPAddress': '10.0.0.4', 'subnet': {'id': subnet}, 'publicIPAddress': {'id': public}}}]}}],
        'public_ip': [{'id': public, 'properties': {'ipAddress': '20.1.1.1'}}],
        'vm': [{'id': vm, 'identity': {'principalId': 'native-principal'},
            'properties': {'networkProfile': {'networkInterfaces': [{'id': nic}]}}}],
    }
    return make_snapshot('azure', [scope], [{'scope': scope, 'type': kind, 'status': 'collected', 'items': items}
        for kind, items in facts.items()], created_at='2026-01-01T00:00:00+00:00')


@pytest.mark.parametrize('parts', [(), ('',), ('native', 'scope', 'kind', 'path'),
    ('quotes"', 'backslash\\', 'tab\t', 'newline\n'), ('\0\1\x1f\x7f',),
    ('雲', '😀', '\u2028\u2029'), ('\ud800', '\udfff', '\ud83d\ude00'),
    tuple(str(i) for i in range(8)), tuple(str(i) for i in range(9)),
    ('large-' + 'x' * 100000,), ('literal%2F', 'literal/path'),
    (None,), ('source', 'target', 'kind', None), (True, False, 1, 0, 1.5),
    (float('nan'), float('inf'), -float('inf')), (['list'], {'dict': [None, '雲']}),
    ({'nested': {'b': 2, 'a': 1}},), (b'bytes',),
])
def test_exact_identifiers_match_original_encoding(parts):
    assert common.stable_id(*parts) == literal_id(*parts)


def test_randomized_unicode_and_escaping_match_original_json_encoder():
    randomizer = random.Random(84367)
    characters = ['"', '\\', '\n', '\0', '/', '\x1f', '\u2028', '\ud800', '\udfff']
    characters += [chr(randomizer.randrange(0x110000)) for _ in range(200)]
    for _ in range(1000):
        parts = tuple(''.join(randomizer.choices(characters, k=randomizer.randrange(24)))
            for _ in range(randomizer.randrange(10)))
        assert common.stable_id(*parts) == literal_id(*parts)


def test_string_subclasses_and_custom_values_keep_general_encoder_behavior():
    class Text(str):
        def __str__(self):
            raise AssertionError('JSON strings do not call this override')
    class Native:
        def __str__(self):
            return 'native-value'
    assert common.stable_id(Text('native')) == literal_id(Text('native'))
    assert common.stable_id('scope', Native()) == literal_id('scope', Native())


def test_custom_serialization_failure_is_not_hidden():
    class Native:
        def __str__(self):
            raise ValueError('invalid native string')
    with pytest.raises(ValueError, match='invalid native string'):
        common.stable_id('scope', Native())


def test_custom_json_function_keeps_original_call_contract(monkeypatch):
    original = json.dumps
    calls = []
    def serialize(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)
    expected = literal_id('scope', 'native')
    monkeypatch.setattr(json, 'dumps', serialize)
    assert common.stable_id('scope', 'native') == expected
    assert calls == [((('scope', 'native'),), {'sort_keys': True, 'default': str, 'separators': (',', ':')})]


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_complete_network_workflow_preserves_findings_ids_and_graphs(provider):
    snapshot = workflow_snapshot(provider)
    inventory, before = resources(snapshot), digest(snapshot)
    common._node_id.cache_clear()
    actual = network_stage(snapshot, inventory)
    with id_factory(literal_id):
        common._node_id.cache_clear()
        expected = network_stage(snapshot, inventory)
    assert json.dumps(actual) == json.dumps(expected)
    assert digest(snapshot) == before


def test_complete_iam_workflow_preserves_findings_ids_and_graphs():
    snapshot = iam_snapshot(12)
    inventory, before = resources(snapshot), digest(snapshot)
    common._node_id.cache_clear()
    actual = iam_stage(snapshot, inventory)
    with id_factory(literal_id):
        common._node_id.cache_clear()
        expected = iam_stage(snapshot, inventory)
    assert json.dumps(actual) == json.dumps(expected)
    assert digest(snapshot) == before
