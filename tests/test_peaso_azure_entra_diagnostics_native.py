"""Tenant-target dispatch is backed by native subscription and credential joins."""
import copy
from types import SimpleNamespace
from urllib.parse import urlsplit

from peaso.collectors import azure, collect_live
from peaso.engine import _scope_check_scopes
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import validate
import pytest

SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
TSCOPE = '/tenants/' + TENANT
WORKSPACE = SUB + '/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/security'
KIND = 'entra_diagnostic_setting'
SETTING = '/providers/Microsoft.aadiam/diagnosticSettings/security'
IDS = ['azure.cis.entra_activity_diagnostic', 'azure.cis.entra_graph_activity_diagnostic']


class Denied(RuntimeError):
    status = 403


def capture(monkeypatch, mode='ok', subscriptions=1):
    class Transport:
        tenant = verified_tenant = TENANT
        calls = []

        def close(self):
            pass

        def request(self, url, *, body=None, audience=azure.ARM):
            self.calls.append((url, body, audience))
            path = urlsplit(url).path
            assert body is None and audience == azure.ARM
            if path.startswith('/subscriptions/') and '/providers/' not in path:
                return {'id': path, 'tenantId': TENANT if mode != 'foreign_subscription' else '33333333-3333-3333-3333-333333333333'}
            if path.casefold() == '/providers/microsoft.aadiam/diagnosticsettings':
                if mode == 'denied':
                    raise Denied('SECRET_RECEIVER_OR_TOKEN')
                if mode == 'empty':
                    return {'value': []}
                item = {'id': SETTING, 'properties': {'workspaceId': WORKSPACE,
                    'storageAccountId': None, 'eventHubAuthorizationRuleId': None,
                    'logs': [{'category': name, 'enabled': mode != 'disabled'} for name in
                        ('AuditLogs', 'SignInLogs', 'MicrosoftGraphActivityLogs')],
                    'unusedSecret': 'SECRET_RECEIVER_OR_TOKEN'}}
                if mode == 'foreign_setting':
                    item['id'] = '/providers/foreign/diagnosticSettings/security'
                if mode == 'relative_identity':
                    item['id'] = SETTING.lstrip('/')
                if mode == 'missing_logs':
                    item['properties'].pop('logs')
                if mode == 'duplicate':
                    return {'value': [item, copy.deepcopy(item)]}
                if mode == 'foreign_destination':
                    item['properties']['workspaceId'] = WORKSPACE + '/../outside'
                if mode == 'continuation':
                    return {'value': [item], 'nextLink': 'https://evil.test/next'}
                return {'value': [item]}
            if path.casefold() == WORKSPACE.casefold():
                if mode == 'destination_denied':
                    raise Denied('SECRET_RECEIVER_OR_TOKEN')
                return {'id': WORKSPACE if mode != 'wrong_destination' else WORKSPACE + 'other',
                        'properties': {'retentionInDays': 30, 'irrelevant': 'SECRET_RECEIVER_OR_TOKEN'}}
            return {'value': []}
    transport = Transport()
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: transport)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: transport)
    policy = {'sw21': {'status': 'collected', 'scope': TSCOPE, 'entraDiagnostics': {
        'activityCategories': ['AuditLogs', 'SignInLogs'], 'requiredActivityCategories': ['AuditLogs', 'SignInLogs'],
        'approvedSinkIds': [WORKSPACE], 'minimumRetentionDays': 30}}}
    scopes = [SUB] if subscriptions == 1 else [SUB, SUB.replace('11111111', 'aaaaaaaa')]
    result = collect_live({'provider': 'azure', 'scopes': scopes,
        'auth': {'method': 'token', 'arm_token': 'fixture', 'tenant_id': TENANT},
        'options': {'retries': 0, 'compliance_policy': policy}}, [KIND])
    validate(result)
    assert 'SECRET_RECEIVER_OR_TOKEN' not in str(result)
    return result, transport


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('mode,expected', [('ok', 'PASS'), ('relative_identity', 'PASS'), ('empty', 'FAIL'), ('disabled', 'FAIL'),
    ('denied', 'DENIED'), ('destination_denied', 'DENIED'), ('wrong_destination', 'UNKNOWN'),
    ('foreign_subscription', 'UNKNOWN'), ('foreign_setting', 'UNKNOWN'), ('missing_logs', 'UNKNOWN'),
    ('duplicate', 'UNKNOWN'), ('foreign_destination', 'UNKNOWN'), ('continuation', 'UNKNOWN')])
def test_native_tenant_export_end_to_end(monkeypatch, cid, mode, expected):
    result, transport = capture(monkeypatch, mode)
    findings = evaluate_snapshot(result, checks=[cid])['findings']
    assert len(findings) == 1
    assert findings[0]['status'] == expected
    if mode != 'foreign_subscription':
        assert findings[0]['scope'] == TSCOPE
    assert all(body is None for _, body, _ in transport.calls)


def test_same_tenant_across_two_subscriptions_runs_once(monkeypatch):
    result, _ = capture(monkeypatch, subscriptions=2)
    findings = evaluate_snapshot(result, checks=IDS)['findings']
    assert len(findings) == 2 and all(f['status'] == 'PASS' and f['scope'] == TSCOPE for f in findings)
    assert result['scopes'] == [SUB, SUB.replace('11111111', 'aaaaaaaa')]


def test_configuration_export_does_not_invent_broad_event_coverage(monkeypatch):
    result, _ = capture(monkeypatch)
    finding, = evaluate_snapshot(result, checks=['azure.other.entra_identity_audit_events'])['findings']
    assert finding['status'] == 'UNKNOWN'


def test_unmarked_checks_keep_selected_subscription_targets(monkeypatch):
    result, _ = capture(monkeypatch)
    check = SimpleNamespace(kind=KIND, evaluate=lambda *_: None)
    assert _scope_check_scopes(result, check) == result['scopes']


@pytest.mark.parametrize('field', ['tenant_verified', 'subscription_tenants', 'credential_context_id', 'customer_context_id'])
def test_tenant_target_requires_all_capture_authority_fields(monkeypatch, field):
    result, _ = capture(monkeypatch)
    result['metadata'].pop(field)
    def callback(*_):
        pass
    callback.evaluation_scope = 'tenant'
    check = SimpleNamespace(kind=KIND, evaluate=callback)
    assert _scope_check_scopes(result, check) == result['scopes']


def test_marker_survives_the_signed_callback_wrapper(monkeypatch):
    result, _ = capture(monkeypatch)
    def inner(*_):
        pass
    inner.evaluation_scope = 'tenant'
    def wrapper(*_):
        pass
    wrapper.__wrapped__ = inner
    assert _scope_check_scopes(result, SimpleNamespace(kind=KIND, evaluate=wrapper)) == [TSCOPE]
