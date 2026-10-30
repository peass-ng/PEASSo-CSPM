"""Official JIT response type through real collector and registered engine."""
from copy import deepcopy
import json
import socket
from urllib.parse import parse_qs, urlsplit

import pytest
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate
from tests.test_azure_compute_network_native_review_20261020 import (
    BASE, REGISTRY, SCOPE, SUB, NativeARM, native_case)

CID = 'azure.claude.vm_jit_access'
NATIVE_TYPE = 'Microsoft.Security/locations/jitNetworkAccessPolicies'
OFFICIAL_SOURCE = ('https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/security/'
                   'resource-manager/Microsoft.Security/Security/stable/2020-01-01/examples/'
                   'JitNetworkAccessPolicies/GetJitNetworkAccessPoliciesSubscription_example.json')


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('No live network or credential access in JIT successor proof')
    for name in ('create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    monkeypatch.setattr(azure, 'AzureTransport', blocked)


class JitNativeARM(NativeARM):
    def __init__(self, variant):
        objects, children = native_case(CID, variant == 'opposite')
        self.policy = next(row for row in objects if row['type'] == NATIVE_TYPE)
        # Official List example identity shape: selected subscription, resource
        # group, Security locations/{location}, then named JIT policy.
        self.policy['id'] = BASE + 'Microsoft.Security/locations/eastus/jitNetworkAccessPolicies/native'
        self.variant = variant
        self.jit_calls = []
        super().__init__(objects, children, CID, 'good')

    def request(self, url, *, body=None, audience=azure.ARM):
        parts = urlsplit(url)
        endpoint = SCOPE + '/providers/Microsoft.Security/jitNetworkAccessPolicies'
        if parts.path not in (endpoint, self.policy['id']):
            return super().request(url, body=body, audience=audience)
        assert body is None and audience == azure.ARM
        assert parts.scheme == 'https' and parts.netloc == 'management.azure.com' and not parts.fragment
        query = parse_qs(parts.query)
        assert query['api-version'] == ['2020-01-01']
        self.jit_calls.append({'method': 'GET', 'url': url})
        if parts.path == endpoint:
            if self.variant == 'denied' or self.variant == 'partial' and query.get('page') == ['2']:
                raise azure.AzureReadError('forbidden', 403)
            row = deepcopy(self.policy)
            if self.variant == 'foreign_list':
                row['id'] = row['id'].replace(SUB, '99999999-9999-9999-9999-999999999999')
            if self.variant == 'wrong_type':
                row['type'] = 'Microsoft.Security/securityContacts'
            if self.variant == 'short_route_type':
                row['type'] = 'Microsoft.Security/jitNetworkAccessPolicies'
            if self.variant == 'missing_fact':
                row['properties'].pop('virtualMachines')
            if self.variant in ('foreign_detail', 'wrong_detail_type'):
                row.pop('properties')  # Force the genuine fallback GET path.
            result = {'value': [row]}
            if self.variant == 'partial':
                result['nextLink'] = azure.ARM + endpoint + '?api-version=2020-01-01&page=2'
            return result
        row = deepcopy(self.policy)
        if self.variant == 'foreign_detail':
            row['id'] += '-foreign'
        if self.variant == 'wrong_detail_type':
            row['type'] = 'Microsoft.Compute/virtualMachines'
        return row


@pytest.mark.parametrize('variant,expected', [
    ('official', 'PASS'), ('opposite', 'FAIL'), ('wrong_type', 'UNKNOWN'),
    ('short_route_type', 'UNKNOWN'), ('foreign_list', 'UNKNOWN'),
    ('foreign_detail', 'UNKNOWN'), ('wrong_detail_type', 'UNKNOWN'),
    ('missing_fact', 'UNKNOWN'), ('denied', 'UNKNOWN'), ('partial', 'UNKNOWN'),
])
def test_official_jit_inventory_and_unsafe_responses_through_engine(variant, expected, record_property):
    api = JitNativeARM(variant)
    snapshot = azure.collect({'provider': 'azure', 'scopes': [SUB],
                              'options': {'retries': 0, 'concurrency': 1}},
                             list(REGISTRY[CID].dependencies), transport=api)
    assert not api.errors, api.errors
    assert validate(snapshot) == snapshot
    before = deepcopy(snapshot)
    findings = evaluate_snapshot(snapshot, checks=[CID], include_not_applicable=True)['findings']
    rows = [row for row in findings if row['check_id'] == CID]
    assert rows and {row['status'] for row in rows} == {expected}, rows
    assert before == snapshot
    assert api.jit_calls
    assert any(urlsplit(call['url']).path == SCOPE + '/providers/Microsoft.Security/jitNetworkAccessPolicies'
               for call in api.jit_calls)
    record_property('jit_official_native_receipt', json.dumps({
        'variant': variant, 'expected': expected, 'statuses': [row['status'] for row in rows],
        'jit_calls': api.jit_calls, 'official_source': OFFICIAL_SOURCE}, sort_keys=True))


