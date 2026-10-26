"""Official JIT response type through real collector and registered engine."""
from copy import deepcopy
import gzip
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import socket
from urllib.parse import parse_qs, urlsplit

import pytest
from tests.shared_admission_epoch_compatibility_20261020 import active_shared
from tests.test_provider_combined_source_bridge_20261020 import cpu_epoch_bytes, cpu_receipt
from peaso.checks import native_admission_cpu_shared_successor_20261020 as bridge
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate
from tests.test_azure_compute_network_native_review_20261020 import (
    BASE, REGISTRY, SCOPE, SUB, VM, NativeARM, native_case)

ROOT = Path(__file__).resolve().parents[1]
CID = 'azure.claude.vm_jit_access'
NATIVE_TYPE = 'Microsoft.Security/locations/jitNetworkAccessPolicies'
OLD = 'aws_deployed_ai_shared_successor_20261020'
OLD_HELPER = 'peaso/checks/' + OLD + '.py'
OLD_RECEIPT = 'peaso/checks/' + OLD + '.json'
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


def test_ready_bridge_and_original_1818_file_baseline_remain_immutable():
    assert hashlib.sha256((ROOT / OLD_HELPER).read_bytes()).hexdigest() == '2c0229f0d1b52b660e543bc0b22d0c2255cddb28bae7217e326cf497da22b73f'
    assert hashlib.sha256((ROOT / OLD_RECEIPT).read_bytes()).hexdigest() == 'ffc024b6908fb5b9ae5330f327eda5634897ed45845db62ccd6637539e1b8f06'
    raw = (ROOT / 'tests/fixtures/provider_combined_bridge_baseline_20261020.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '82799a2e0c366c80f3ec4d0626837fdf37ec0b38fc426d0ede565301df4c54a6'
    assert len(json.loads(gzip.decompress(raw))['files']) == 1818
    old = importlib.import_module('peaso.checks.' + OLD)
    assert bridge.accepted is old
    for qualified, function in bridge._ACCEPTED_FUNCTIONS.items():
        assert getattr(old, qualified.split(':')[1]) is function
    active_shared().reviewed_delta(ROOT)


def test_azure_full_file_and_helper_reconstruct_ready_then_azure_package_ancestor():
    active_shared().reviewed_delta(ROOT)
    receipt = cpu_receipt()
    name = 'peaso/collectors/azure.py'
    current = cpu_epoch_bytes(name, (ROOT / name).read_bytes()).decode()
    restored = bridge._reverse(current, receipt['integration_file_deltas'][name])
    assert hashlib.sha256(restored.encode()).hexdigest() == '22aa297159aeec7ab4a0645877bf69de4c8c8c645098ffe1d0dd05a56f0f8aac'
    old = json.loads((ROOT / 'peaso/checks/azure_function_package_shared_successor_20261020.json').read_bytes())
    ancestor = bridge._reverse(restored, old['file_deltas'][name])
    assert hashlib.sha256(ancestor.encode()).hexdigest() == '06f920ae74c65ce07911e3748dd336eae6b770ad2cead2131036564bcb35bde8'
    fn = 'peaso.collectors.azure:_arm_parent_native_type'
    restored_fn = bridge._reverse(inspect.getsource(azure._arm_parent_native_type), receipt['integration_functions'][fn])
    assert hashlib.sha256(restored_fn.encode()).hexdigest() == 'c6b907cab38962c087004af36040642fbb4a8cb771f73e53a90d6e3b87a83071'
    assert azure.ENDPOINTS['jit_network_access_policy'] == ('Microsoft.Security/jitNetworkAccessPolicies', '2020-01-01')


@pytest.mark.parametrize('variant', ['identity', 'code'])
def test_jit_executing_helper_tamper_fails_after_warm_admission(monkeypatch, variant):
    current = active_shared()
    current.reviewed_delta(ROOT)
    if variant == 'identity':
        monkeypatch.setattr(azure, '_arm_parent_native_type', lambda *args: None)
    else:
        monkeypatch.setattr(azure._arm_parent_native_type, '__code__', bridge.accepted._reverse.__code__)
    with pytest.raises(RuntimeError):
        current.reviewed_delta(ROOT)
