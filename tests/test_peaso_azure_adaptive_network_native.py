"""Directed local HTTP stubs for native Adaptive Network Hardening collection."""
from copy import deepcopy

import pytest

from peaso.collectors.azure import _Reader
from peaso.collectors import azure_adaptive_network_native as native

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
VM = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
NIC = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic'
NSG = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg'
RID = VM + '/providers/Microsoft.Security/adaptiveNetworkHardenings/default'


def row(vm=VM):
    return {'id': vm + '/providers/Microsoft.Security/adaptiveNetworkHardenings/default',
            'name': 'default', 'type': 'Microsoft.Security/adaptiveNetworkHardenings',
            'properties': {'rulesCalculationTime': '2026-10-16T09:00:00Z',
                           'rules': [{'name': 'rule1', 'direction': 'Inbound',
                                      'ipAddresses': ['10.0.0.0/8'], 'destinationPort': 443,
                                      'protocols': ['TCP']}],
                           'effectiveNetworkSecurityGroups': [
                               {'networkInterface': NIC, 'networkSecurityGroups': [NSG]}]}}


def reader(vms=None, status='collected'):
    instance = _Reader({'retries': 0, 'concurrency': 1})
    instance.collections.append({'type': 'vm', 'scope': SCOPE, 'status': status,
                                 'items': [{'id': value} for value in ([VM] if vms is None else vms)]})
    return instance


def collect(instance, responses, wanted=None):
    calls = []
    def request(url, *, body, audience):
        calls.append(url)
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result
    native.collect(instance, request, [SCOPE], {native.KIND} if wanted is None else wanted)
    return instance.collections[-1], calls


def test_complete_native_row_has_exact_vm_rule_and_nsg_identities_without_application_claim():
    result, calls = collect(reader(), [{'value': [row()]}])
    assert result['status'] == 'collected'
    assert len(calls) == 1 and calls[0].endswith('/providers/Microsoft.Security/adaptiveNetworkHardenings?api-version=2020-01-01')
    item = result['items'][0]
    assert item['id'] == RID and item['vm_id'] == VM
    assert item['recommended_rules'][0]['destinationPort'] == 443
    assert item['effective_nsg_associations'][0]['network_security_group_ids'] == [NSG]
    assert item['_provenance']['source_operation'] == 'AdaptiveNetworkHardenings_ListByExtendedResource'
    assert not ({'approved', 'applied', 'effective', 'internetFacing'} & item.keys())


def test_unrequested_kind_makes_zero_calls():
    result, calls = collect(reader(), [], wanted=set())
    assert calls == [] and result['type'] == 'vm'
    assert native.required_types({native.KIND}) == {'vm'}


def test_http_200_empty_is_empty_native_inventory():
    result, calls = collect(reader(), [{'value': []}])
    assert result['status'] == 'empty' and result['items'] == [] and len(calls) == 1


def test_two_vm_roster_requires_both_requests_before_complete():
    vm2 = VM + '2'
    result, calls = collect(reader([VM, vm2]), [{'value': [row()]}, {'value': []}])
    assert result['status'] == 'collected' and len(calls) == 2


def test_second_vm_denial_keeps_first_row_partial():
    vm2 = VM + '2'
    result, calls = collect(reader([VM, vm2]), [{'value': [row()]}, PermissionError('denied')])
    assert result['status'] == 'partial' and len(result['items']) == 1 and len(calls) == 2


def test_unfinished_paging_is_never_complete():
    result, calls = collect(reader(), [{'value': [row()], 'nextLink': 'https://management.azure.com/elsewhere'}])
    assert result['status'] == 'partial' and len(result['items']) == 1 and len(calls) == 1


@pytest.mark.parametrize('mutate', [
    lambda item: item.update(id=item['id'].replace('/subscriptions/11111111-1111-1111-1111-111111111111', '/subscriptions/other')),
    lambda item: item['properties']['rules'][0].update(destinationPort='443'),
    lambda item: item['properties']['effectiveNetworkSecurityGroups'][0].update(networkSecurityGroups=[NSG, NSG]),
])
def test_foreign_or_malformed_native_metadata_never_completes(mutate):
    item = row()
    mutate(item)
    result, _ = collect(reader(), [{'value': [item]}])
    assert result['status'] not in ('collected', 'empty') and result['items'] == []


def test_duplicate_child_identity_is_partial_not_deduplicated_complete():
    item = row()
    result, _ = collect(reader(), [{'value': [item, deepcopy(item)]}])
    assert result['status'] == 'malformed' and result['items'] == []


def test_raw_rule_cap_fails_closed(monkeypatch):
    monkeypatch.setattr(native, 'MAX_RULES', 1)
    item = row()
    item['properties']['rules'] *= 2
    result, _ = collect(reader(), [{'value': [item]}])
    assert result['status'] not in ('collected', 'empty') and result['items'] == []


def test_incomplete_vm_source_makes_zero_http_calls():
    result, calls = collect(reader(status='partial'), [])
    assert calls == [] and result['status'] not in ('collected', 'empty')


def test_normal_collect_live_requests_vm_then_native_child_without_secrets(monkeypatch):
    import json
    from urllib.parse import urlsplit
    from peaso.collectors import azure, collect_live

    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def __init__(self):
            self.calls = []
        def close(self):
            pass
        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append(url)
            path = urlsplit(url).path
            if path == SCOPE + '/providers/Microsoft.Compute/virtualMachines':
                return {'value': [{'id': VM, 'name': 'vm', 'type': 'Microsoft.Compute/virtualMachines',
                                   'properties': {}}]}
            if path == VM:
                return {'id': VM, 'name': 'vm', 'type': 'Microsoft.Compute/virtualMachines',
                        'properties': {}, 'instanceView': {}}
            if path == VM + '/providers/Microsoft.Security/adaptiveNetworkHardenings':
                item = row()
                item['properties']['irrelevantSecret'] = 'do-not-retain'
                return {'value': [item]}
            return {'value': []}

    transport = Transport()
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: transport);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: transport)
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE],
                             'options': {'retries': 0}}, [native.KIND])
    envelopes = [item for item in snapshot['collections'] if item['type'] == native.KIND]
    assert len(envelopes) == 1 and envelopes[0]['status'] == 'collected'
    assert envelopes[0]['items'][0]['vm_id'] == VM
    assert any('/adaptiveNetworkHardenings?' in call for call in transport.calls)
    assert 'do-not-retain' not in json.dumps(snapshot)
