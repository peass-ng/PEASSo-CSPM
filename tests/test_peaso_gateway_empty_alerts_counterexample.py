# Historical fixture contracts; current native admission is tested separately.
"""A complete empty alert universe proves no gateway rule is configured."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso.checks import CHECKS
from peaso.checks.compliance_new_sw25_facts import GATEWAY_ID, FAMILIES
from peaso.collectors import collect_live, azure
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
GATEWAY = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw'
NOW = datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc)


def owner(now=NOW):
    return {'windowStart': (now - timedelta(minutes=10)).isoformat(),
        'windowEnd': (now - timedelta(minutes=5)).isoformat(), 'maxAlertLatencySeconds': 120,
        'evaluationIntervalSeconds': 60, 'targetDenominator': 'totalTargetsAtWindowStart'}


def capture(history='missing', gateway=True):
    gateways = [{'id': GATEWAY, 'type': 'Microsoft.Network/applicationGateways'}] if gateway else []
    collections = [{'type': 'application_gateway', 'scope': SCOPE, 'service': 'Microsoft.Network',
        'status': 'collected' if gateways else 'empty', 'items': gateways}]
    collections += [{'type': kind, 'scope': SCOPE, 'service': 'Microsoft.Insights', 'status': 'empty', 'items': []} for kind in FAMILIES]
    if history != 'missing':
        collections += [{'type': kind, 'scope': SCOPE, 'service': 'reviewed_evidence',
            'status': history, 'items': []} for kind in ('action_group', 'gateway_alert_semantics', 'gateway_health_evidence')]
    return make_snapshot('azure', [SCOPE], collections, created_at=NOW.isoformat(),
        metadata={'sw25_policy': {GATEWAY_ID: {'scope': SCOPE, **owner()}}})


def verdict(snapshot):
    findings = [f for f in evaluate_snapshot(snapshot, checks=[GATEWAY_ID], include_not_applicable=True)['findings'] if f['check_id'] == GATEWAY_ID]
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('history', ['missing', 'denied', 'partial', 'empty'])
def test_native_empty_alerts_prove_failure_without_group_semantics_or_health_history(history):
    assert verdict(capture(history)) == 'FAIL'
    check = next(c for c in CHECKS if c.id == GATEWAY_ID)
    assert check.allow_incomplete_failure is True
    assert set(check.dependencies) == {'application_gateway', *FAMILIES, 'action_group', 'gateway_alert_semantics', 'gateway_health_evidence'}


@pytest.mark.parametrize('mode', ['wrong_type', 'wrong_id', 'foreign_policy', 'future_window', 'bad_latency', 'bad_denominator', 'untrusted_proof'])
def test_invalid_gateway_or_required_owner_policy_cannot_assert_empty_alert_violation(mode):
    snapshot = capture()
    row = snapshot['collections'][0]['items'][0]
    policy = snapshot['metadata']['sw25_policy'][GATEWAY_ID]
    if mode == 'wrong_type': row['type'] = 'Microsoft.Compute/virtualMachines'
    elif mode == 'wrong_id': row['id'] = GATEWAY.replace('applicationGateways', 'virtualNetworks')
    elif mode == 'foreign_policy': policy['scope'] = SCOPE.replace('1111', '2222')
    elif mode == 'future_window': policy['windowEnd'] = (NOW + timedelta(minutes=5)).isoformat()
    elif mode == 'bad_latency': policy['maxAlertLatencySeconds'] = True
    elif mode == 'bad_denominator': policy['targetDenominator'] = 'unverifiedCurrentTargets'
    elif mode == 'untrusted_proof': row['_provenance'] = {'read_only': False}
    assert verdict(make_snapshot('azure', [SCOPE], snapshot['collections'], metadata=snapshot['metadata'], created_at=NOW.isoformat())) == 'UNKNOWN'


@pytest.mark.parametrize('state,expected', [('denied', 'DENIED'), ('partial', 'UNKNOWN')])
@pytest.mark.parametrize('family', FAMILIES)
def test_unavailable_alert_family_never_proves_absence(family, state, expected):
    snapshot = capture()
    next(c for c in snapshot['collections'] if c['type'] == family)['status'] = state
    assert verdict(make_snapshot('azure', [SCOPE], snapshot['collections'], metadata=snapshot['metadata'], created_at=NOW.isoformat())) == expected


def test_existing_alert_with_unknown_semantics_remains_unknown():
    snapshot = capture('empty')
    alerts = next(c for c in snapshot['collections'] if c['type'] == 'metric_alert')
    alerts.update(status='collected', items=[{'id': SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/metricAlerts/unknown',
        'properties': {'enabled': True, 'scopes': [GATEWAY]}}])
    assert verdict(make_snapshot('azure', [SCOPE], snapshot['collections'], metadata=snapshot['metadata'], created_at=NOW.isoformat())) == 'UNKNOWN'


def test_malformed_alert_is_not_an_empty_native_alert_inventory():
    snapshot = capture()
    collection = next(c for c in snapshot['collections'] if c['type'] == 'metric_alert')
    collection.update(status='collected', items=[{'id': SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/metricAlerts/bad',
        'properties': {'enabled': 'true', 'scopes': [GATEWAY]}}])
    assert verdict(make_snapshot('azure', [SCOPE], snapshot['collections'], metadata=snapshot['metadata'], created_at=NOW.isoformat())) == 'UNKNOWN'


def test_complete_empty_gateway_inventory_keeps_not_applicable():
    assert verdict(capture('empty', gateway=False)) == 'NOT_APPLICABLE'


def test_public_collector_uses_normative_policy_and_readonly_alert_inventory(monkeypatch):
    calls, closed = [], []
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self): closed.append(True)
        def request(self, url, *, body=None, audience=azure.ARM):
            assert audience == azure.ARM
            calls.append((url, deepcopy(body)))
            path = urlsplit(url).path
            assert 'backendhealth' not in path.casefold()
            if '/resourcegraph/' in path.casefold():
                assert isinstance(body, dict)  # Standard read-only discovery query.
                return {'data': [], 'resultTruncated': False}
            assert body is None  # Every gateway/alert management operation is GET.
            if path == SCOPE + '/providers/Microsoft.Network/applicationGateways':
                return {'value': [{'id': GATEWAY, 'name': 'gw', 'type': 'Microsoft.Network/applicationGateways', 'properties': {}}]}
            if path == GATEWAY:
                return {'id': GATEWAY, 'name': 'gw', 'type': 'Microsoft.Network/applicationGateways', 'properties': {}}
            return {'value': []}
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: Transport());monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: Transport())
    now = datetime.now(timezone.utc)
    review = {'status': 'collected', 'scope': SCOPE, 'checks': {GATEWAY_ID: owner(now)}}
    dependencies = next(c for c in CHECKS if c.id == GATEWAY_ID).dependencies
    options = {'concurrency': 1, 'retries': 1, 'compliance_policy': {'sw25': review}}
    auth = {'method': 'token', 'arm_token': 'inert-fixture'}
    from peaso.server.validation import validate_connector
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE],
        'auth': auth, 'options': options}, dependencies)
    assert closed == [True]
    assert {c['type'] for c in snapshot['collections'] if c['status'] == 'empty'} >= set(FAMILIES)
    assert any('/applicationGateways?' in url for url, _ in calls)
    assert verdict(snapshot) == 'FAIL'
