# Historical fixture contracts; current native admission is tested separately.
"""Metric name presence does not require an unrequested native namespace.

2018-03-01 MultiMetricCriteria lists metricNamespace outside required:
https://github.com/Azure/azure-rest-api-specs/blob/main/specification/monitor/resource-manager/Microsoft.Insights/Insights/stable/2018-03-01/metricAlert_API.json
"""
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot
from peaso.server.validation import validate_connector
from peaso.checks.compliance_new_sw25_facts import REQUIRED_ID
from tests.test_peaso_azure_metric_requirements import RESOURCE, SCOPE, approval, settings


@pytest.mark.parametrize('mode,required,expected', [
    ('missing', False, 'PASS'), ('null', False, 'UNKNOWN'),
    ('missing', True, 'UNKNOWN'), ('null', True, 'UNKNOWN'),
    ('boolean', False, 'UNKNOWN'), ('empty', False, 'UNKNOWN'),
    ('correct', True, 'PASS'), ('foreign', True, 'FAIL'),
])
def test_public_required_metric_namespace_remains_optional_and_scope_bound(monkeypatch, mode, required, expected):
    properties = settings()
    properties.update(enabled=True, autoMitigate=True, actions=[])
    condition = properties['criteria']['allOf'][0]
    if mode == 'missing': condition.pop('metricNamespace')
    elif mode == 'null': condition['metricNamespace'] = None
    elif mode == 'boolean': condition['metricNamespace'] = True
    elif mode == 'empty': condition['metricNamespace'] = ''
    elif mode == 'foreign': condition['metricNamespace'] = 'Another.Provider/resource'
    alert_id = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/metricAlerts/transactions'
    row = {'id': alert_id, 'type': 'Microsoft.Insights/metricAlerts', 'properties': properties}
    calls = []

    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self): pass
        def request(self, url, *, body=None, audience=azure.ARM):
            calls.append(url)
            path = urlsplit(url).path
            if path == '/providers/Microsoft.ResourceGraph/resources':
                assert isinstance(body, dict)
                return {'data': [], 'resultTruncated': False}
            assert body is None
            if path == SCOPE + '/resources':
                return {'value': [{'id': RESOURCE, 'type': 'Microsoft.Storage/storageAccounts'}]}
            if path == SCOPE + '/providers/Microsoft.Insights/metricAlerts':
                return {'value': [deepcopy(row)]}
            if path in {rid + '/providers/Microsoft.Insights/diagnosticSettings' for rid in (RESOURCE, alert_id)}:
                return {'value': []}
            raise AssertionError('Unexpected endpoint: ' + path)

    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: Transport());monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: Transport())
    value = approval(REQUIRED_ID)
    if required:
        value['checks'][REQUIRED_ID]['requiredMetrics'][0]['metricNamespace'] = 'Microsoft.Storage/storageAccounts'
    options = {'retries': 1, 'concurrency': 1, 'compliance_policy': {'sw25': value}}
    auth = {'method': 'token', 'arm_token': 'inert-fixture'}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options},
                            ['metric_alert', 'azure_resource'])
    findings = evaluate_snapshot(snapshot, checks=[REQUIRED_ID])['findings']
    assert len(findings) == 1
    assert findings[0]['status'] == expected
    assert calls
