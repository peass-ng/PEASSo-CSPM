# Historical fixture contracts; current native admission is tested separately.
"""Hosted normative requirements through the existing readonly Azure collector."""
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit, parse_qs
import pytest

from peaso.collectors import collect_live, azure
from tests.archived_check_contract import evaluate_snapshot
from peaso.server.validation import validate_connector
from peaso.checks.compliance_new_sw25_facts import REQUIRED_ID
from tests.test_peaso_azure_alert_routing_native import native, SCOPE, RESOURCE


@pytest.mark.parametrize('mode,expected', [('present', 'PASS'), ('absent', 'FAIL'), ('disabled', 'FAIL'),
    ('resource_missing', 'UNKNOWN'), ('resource_partial', 'UNKNOWN')])
def test_hosted_required_metrics_collect_native_inventory_and_declarations(monkeypatch, mode, expected):
    calls, closed = [], []
    alert = native('metric_alert')
    alert['properties']['criteria'] = {
        'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria',
        'allOf': [{'criterionType': 'StaticThresholdCriterion', 'metricName': 'Percentage CPU',
            'metricNamespace': 'Microsoft.Compute/virtualMachines', 'timeAggregation': 'Average',
            'operator': 'GreaterThan', 'threshold': 80, 'dimensions': []}]}
    if mode == 'disabled': alert['properties']['enabled'] = False
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self): closed.append(True)
        def request(self, url, *, body=None, audience=azure.ARM):
            assert audience == azure.ARM
            calls.append((url, deepcopy(body)))
            parsed = urlsplit(url)
            if parsed.path == '/providers/Microsoft.ResourceGraph/resources':
                assert isinstance(body, dict)
                return {'data': [], 'resultTruncated': False}
            assert body is None
            if parsed.path == SCOPE + '/resources':
                if parse_qs(parsed.query).get('page') == ['2']:
                    raise azure.AzureReadError('fixture_resource_page_denied', 403)
                rows = [] if mode == 'resource_missing' else [{'id': RESOURCE, 'type': 'Microsoft.Compute/virtualMachines'}]
                return {'value': rows, **({'nextLink': azure.ARM + SCOPE + '/resources?api-version=2021-04-01&page=2'} if mode == 'resource_partial' else {})}
            if parsed.path == SCOPE + '/providers/Microsoft.Insights/metricAlerts':
                return {'value': [] if mode == 'absent' else [deepcopy(alert)]}
            if parsed.path in {rid + '/providers/Microsoft.Insights/diagnosticSettings' for rid in (RESOURCE, alert['id'])}:
                return {'value': []}
            raise AssertionError('Unexpected endpoint: ' + parsed.path)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: Transport())
    options = {'concurrency': 1, 'retries': 1, 'compliance_policy': {'sw25': {
        'status': 'collected', 'scope': SCOPE, 'checks': {REQUIRED_ID: {'requiredMetrics': [{
            'resourceId': RESOURCE, 'metricName': 'Percentage CPU', 'metricNamespace': 'Microsoft.Compute/virtualMachines'}]}}}}}
    auth = {'method': 'token', 'arm_token': 'inert-fixture'}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}, {'azure_resource', 'metric_alert'})
    assert closed == [True]
    resource_inventory = next(c for c in snapshot['collections'] if c['type'] == 'azure_resource')
    if mode == 'resource_partial':
        assert resource_inventory['status'] == 'partial'
        assert resource_inventory['items'][0]['id'] == RESOURCE
    findings = evaluate_snapshot(snapshot, checks=[REQUIRED_ID])['findings']
    assert next(f['status'] for f in findings if f['check_id'] == REQUIRED_ID) == expected
    assert any(urlsplit(url).path == SCOPE + '/resources' for url, _ in calls)
    assert all(body is None for url, body in calls if urlsplit(url).path != '/providers/Microsoft.ResourceGraph/resources')
