# Historical fixture contracts; current native admission is tested separately.
"""Normal hosted metric settings reach native declaration and enabled-group reads."""
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest

from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot
from peaso.server.validation import validate_connector
from peaso.checks.compliance_new_sw25_facts import SETTINGS_ID
from tests.test_peaso_azure_metric_requirements import settings, approval, SCOPE, GROUP


@pytest.mark.parametrize('mode,expected', [('matching', 'PASS'), ('absent', 'FAIL'), ('disabled', 'FAIL'),
    ('mismatch', 'FAIL'), ('group_missing', 'UNKNOWN'), ('group_denied', 'DENIED'),
    ('group_disabled', 'FAIL'), ('incomplete_criteria', 'UNKNOWN')])
def test_hosted_settings_use_native_rules_and_group_enabled_state(monkeypatch, mode, expected):
    calls, closed = [], []
    props = settings()
    props.pop('actionGroupIds')
    props.update(enabled=mode != 'disabled', autoMitigate=True, actions=[{'actionGroupId': GROUP}])
    if mode == 'mismatch': props['criteria']['allOf'][0]['threshold'] += 1
    if mode == 'incomplete_criteria': del props['criteria']['allOf'][0]['threshold']
    alert_id = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/metricAlerts/rule'
    alert = {'id': alert_id, 'type': 'Microsoft.Insights/metricAlerts', 'properties': props}
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self): closed.append(True)
        def request(self, url, *, body=None, audience=azure.ARM):
            assert audience == azure.ARM
            calls.append((url, deepcopy(body)))
            path = urlsplit(url).path
            if path == '/providers/Microsoft.ResourceGraph/resources':
                assert isinstance(body, dict)
                return {'data': [], 'resultTruncated': False}
            assert body is None
            if path == SCOPE + '/providers/Microsoft.Insights/metricAlerts':
                return {'value': [] if mode == 'absent' else [deepcopy(alert)]}
            if path == SCOPE + '/providers/Microsoft.Insights/actionGroups':
                if mode == 'group_denied': raise azure.AzureReadError('fixture_action_group_denied', 403)
                return {'value': [] if mode == 'group_missing' else [{'id': GROUP,
                    'type': 'Microsoft.Insights/actionGroups', 'properties': {'enabled': mode != 'group_disabled'}}]}
            if path == GROUP:
                return {'id': GROUP, 'type': 'Microsoft.Insights/actionGroups',
                    'properties': {'enabled': mode != 'group_disabled'}}
            if path in {rid + '/providers/Microsoft.Insights/diagnosticSettings' for rid in (GROUP, alert_id)}:
                return {'value': []}
            raise AssertionError('Unexpected endpoint: ' + path)
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: Transport())
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: Transport())
    auth = {'method': 'token', 'arm_token': 'inert-fixture'}
    options = {'concurrency': 1, 'retries': 1, 'compliance_policy': {'sw25': approval()}}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}, {'metric_alert', 'action_group'})
    assert closed == [True]
    groups = next(c for c in snapshot['collections'] if c['type'] == 'action_group')
    if mode == 'group_denied': assert groups['status'] == 'denied'
    if mode == 'group_disabled': assert groups['items'][0]['properties']['enabled'] is False
    findings = evaluate_snapshot(snapshot, checks=[SETTINGS_ID])['findings']
    assert next(f['status'] for f in findings if f['check_id'] == SETTINGS_ID) == expected
    assert all(body is None for url, body in calls if urlsplit(url).path != '/providers/Microsoft.ResourceGraph/resources')
