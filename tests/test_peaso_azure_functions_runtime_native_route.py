"""Selected read-only Function site and plan metadata reaches the registered check."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from threading import Barrier, Lock
from urllib.parse import urlsplit

import pytest
from peaso.collectors import azure, azure_functions_runtime_native as native
from peaso.collectors.azure import _Reader
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot

SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
APP = SUB + '/resourceGroups/rg/providers/Microsoft.Web/sites/fn'
PLAN = SUB + '/resourceGroups/rg/providers/Microsoft.Web/serverfarms/flex'
CID = 'azure_app_service_app_function_latest_runtime_version_f50215a'
SECRET = 'DO_NOT_RETAIN_STORAGE_CONNECTION_STRING'


class Denied(Exception):
    status_code = 403


class API:
    tenant = verified_tenant = TENANT

    def __init__(self, mode):
        self.mode, self.calls = mode, []

    def close(self):
        pass

    def site(self, full=False):
        memory = 2048 if self.mode == 'same' else 512
        config = {'runtime': {'name': 'python', 'version': '3.12'},
                  'scaleAndConcurrency': {'instanceMemoryMB': memory},
                  'deployment': {'storage': {'authentication': {'storageAccountConnectionString': SECRET}}}}
        if self.mode == 'missing':
            config['scaleAndConcurrency'] = {}
        return {'id': APP, 'type': 'Microsoft.Web/sites',
                'kind': 'app' if self.mode == 'nonfunction' else 'functionapp,linux',
                'properties': {'serverFarmId': PLAN, 'functionAppConfig': config}}

    def plan(self):
        sku = {'name': 'FC1', 'tier': 'FlexConsumption'}
        if self.mode == 'unknown_hosting':
            sku = {'name': 'P1v3', 'tier': 'PremiumV3'}
        return {'id': PLAN + '-other' if self.mode == 'foreign' else PLAN,
                'type': 'Microsoft.Web/serverfarms', 'sku': sku, 'properties': {}}

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        assert audience == azure.ARM
        path = urlsplit(url).path
        if path == '/providers/Microsoft.ResourceGraph/resources':
            assert isinstance(body, dict)
            return {'data': [], 'resultTruncated': False}
        assert body is None
        if path == '/subscriptions':
            return {'value': [{'id': SUB, 'subscriptionId': SUB.rsplit('/', 1)[1], 'tenantId': TENANT}]}
        if path == SUB:
            return {'id': SUB, 'subscriptionId': SUB.rsplit('/', 1)[1], 'tenantId': TENANT}
        if path == SUB + '/providers/Microsoft.Web/sites':
            return {'value': [self.site()]}
        if path == SUB + '/providers/Microsoft.Web/serverfarms':
            return {'value': [self.plan() if self.mode != 'foreign' else {'id': PLAN, 'type': 'Microsoft.Web/serverfarms', 'sku': {'name': 'FC1', 'tier': 'FlexConsumption'}}]}
        if path == APP:
            if self.mode == 'denied':
                raise Denied('site denied')
            return self.site(full=True)
        if path == PLAN:
            return self.plan()
        raise AssertionError('unexpected ARM route: ' + path)


def request():
    now = datetime.now(timezone.utc)
    policy = {'status': 'collected', 'scope': SUB, 'authorized_by': 'owner',
              'document_id': 'approved-flex-memory-baseline',
              'observed_at': (now - timedelta(days=1)).isoformat(),
              'expires_at': (now + timedelta(days=1)).isoformat(),
              'checks': {CID.replace('.', '|'): {'expectedFunctionSettings': {
                  APP: {'hostingModel': 'FlexConsumption', 'memoryMetric': 'FlexInstanceMemoryMB', 'memoryMB': 2048}}}}}
    return {'connector': {'provider': 'azure', 'scopes': [SUB],
                          'auth': {'method': 'token', 'arm_token': 'inert-fixture'},
                          'options': {'retries': 0, 'concurrency': 1,
                                      'compliance_policy': {'sw13': policy}}},
            'checks': [CID]}


def finding(snapshot):
    rows = [row for row in evaluate_snapshot(snapshot, checks=[CID])['findings']
            if row['check_id'] == CID]
    assert len(rows) == 1
    return rows[0]


@pytest.mark.parametrize('mode,expected', [
    ('mismatch', 'FAIL'), ('same', 'UNKNOWN'), ('missing', 'UNKNOWN'),
    ('denied', 'UNKNOWN'), ('foreign', 'UNKNOWN'), ('missing_metric', 'UNKNOWN'),
    ('unknown_hosting', 'UNKNOWN'), ('nonfunction', 'NOT_APPLICABLE'),
])
def test_selected_normal_route(monkeypatch, mode, expected):
    api = API(mode)
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: api)
    req = request()
    if mode == 'missing_metric':
        req['connector']['options']['compliance_policy']['sw13']['checks'][CID.replace('.', '|')]['expectedFunctionSettings'][APP].pop('memoryMetric')
    plan = plan_collection(req)
    assert {'app_service', 'app_service_plan', 'subscription', 'function_app_runtime_native'} <= set(plan)
    snapshot = collect_snapshot(req)
    result = finding(snapshot)
    assert result['status'] == expected, result
    assert SECRET not in json.dumps(snapshot)
    assert all(urlsplit(url).path in {SUB, '/subscriptions', SUB + '/providers/Microsoft.Web/sites',
                                   SUB + '/providers/Microsoft.Web/serverfarms', APP, PLAN}
               for url, _, _ in api.calls)
    assert all(body is None for _, body, _ in api.calls)
    assert all('config' not in url.lower() and 'hostruntime' not in url.lower()
               and 'runcommand' not in url.lower() for url, _, _ in api.calls)
    native = next(c for c in snapshot['collections'] if c['type'] == 'function_app_runtime_native')
    if mode == 'mismatch':
        assert native['items'][0]['memoryMB'] == 512
        assert result['evidence']['mismatched_settings'] == ['memoryMB']
    else:
        assert result['status'] != 'PASS'


@pytest.mark.parametrize('mutation', [
    'credential', 'customer', 'tenant', 'site', 'plan', 'capture', 'operation',
    'api_version', 'unverified_tenant',
])
def test_foreign_or_stale_capture_cannot_prove_mismatch(monkeypatch, mutation):
    api = API('mismatch')
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: api)
    snapshot = collect_snapshot(request())
    collections = deepcopy(snapshot['collections'])
    metadata = deepcopy(snapshot['metadata'])
    row = next(c for c in collections if c['type'] == 'function_app_runtime_native')['items'][0]
    if mutation == 'credential':
        row['_provenance']['credential_context_id'] = 'foreign'
    elif mutation == 'customer':
        row['_provenance']['customer_context_id'] = 'foreign'
    elif mutation == 'tenant':
        row['_provenance']['tenant_id'] = '33333333-3333-3333-3333-333333333333'
    elif mutation == 'site':
        row['source']['resourceId'] = APP + '-other'
    elif mutation == 'plan':
        row['source']['planResourceId'] = SUB + '/resourceGroups/rg/providers/Microsoft.Web/serverfarms/other'
    elif mutation == 'capture':
        row['observedAt'] = '2020-01-01T00:00:00Z'
        row['_provenance']['observed_at'] = row['observedAt']
    elif mutation == 'operation':
        row['_provenance']['source_operation'] = 'custom observation'
    elif mutation == 'api_version':
        row['_provenance']['api_version'] = '2023-12-01'
    else:
        metadata['tenant_verified'] = False
    altered = make_snapshot('azure', [SUB], collections, metadata=metadata,
                            created_at=snapshot['created_at'])
    assert finding(altered)['status'] == 'UNKNOWN'


def test_native_site_reads_use_shared_bounded_workers():
    second = APP + '2'
    reader = _Reader({'concurrency': 2, 'retries': 0})
    reader.collections = [
        {'type': 'app_service', 'scope': SUB, 'status': 'collected',
         'items': [{'id': app, 'kind': 'functionapp,linux'} for app in (APP, second)]},
        {'type': 'app_service_plan', 'scope': SUB, 'status': 'collected',
         'items': [{'id': PLAN}]},
        {'type': 'subscription', 'scope': '/tenants/' + TENANT, 'status': 'collected',
         'items': [{'id': SUB, 'tenantId': TENANT}]},
    ]
    barrier = Barrier(2, timeout=2)
    guard = Lock()
    active = [0, 0]

    def get(url, *, body=None, audience=azure.ARM):
        assert body is None and audience == azure.ARM
        path = urlsplit(url).path
        if path in (APP, second):
            with guard:
                active[0] += 1
                active[1] = max(active)
            try:
                barrier.wait()
            finally:
                with guard:
                    active[0] -= 1
            return {'id': path, 'type': 'Microsoft.Web/sites', 'kind': 'functionapp,linux',
                    'properties': {'serverFarmId': PLAN, 'functionAppConfig': {
                        'runtime': {'name': 'python'},
                        'scaleAndConcurrency': {'instanceMemoryMB': 512}}}}
        assert path == PLAN
        return {'id': PLAN, 'type': 'Microsoft.Web/serverfarms',
                'sku': {'name': 'FC1', 'tier': 'FlexConsumption'}}

    native.collect(reader, get, [SUB], {native.KIND}, tenant_id=TENANT, tenant_verified=True)
    rows = [row for collection in reader.collections if collection['type'] == native.KIND
            for row in collection['items']]
    assert [row['appId'] for row in rows] == [APP, second]
    assert all(row['status'] == 'collected' for row in rows)
    assert active[1] == 2
    assert reader.budget.calls == 4


def test_exhausted_shared_call_budget_leaves_native_memory_unresolved(monkeypatch):
    api = API('mismatch')
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: api)
    req = request()
    req['connector']['options']['max_calls'] = 3
    snapshot = collect_snapshot(req)
    assert finding(snapshot)['status'] == 'UNKNOWN'
    assert len(api.calls) == 3
    assert SECRET not in json.dumps(snapshot)
