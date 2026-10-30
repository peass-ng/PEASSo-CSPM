"""Native-only Graph MFA source-wide proofs without owner policy metadata."""
import copy
from urllib.parse import urlsplit

import pytest
from peaso.collectors import azure, collect_live
from peaso.checks import evaluate_check
from peaso.engine import _index, plan_collection, evaluate_snapshot
from peaso.snapshot import resources
from tests.test_peaso_azure_conditional_access_native import API as ExistingAPI, CHECKS, USERS, ADMIN, RISK, SUB, TENANT
from peaso.collectors.azure_conditional_access_risk_native import P2_SERVICE_PLAN_ID

UID = '44444444-4444-4444-4444-444444444444'
CAID = '55555555-5555-5555-5555-555555555555'
SKU = '66666666-6666-6666-6666-666666666666'


class NativeAPI(ExistingAPI):
    def request(self, url, *, body=None, audience=azure.ARM):
        path = urlsplit(url).path
        if path == '/v1.0/users':
            self.calls.append((url, audience, body))
            if self.mode == 'denied_users':
                raise azure.AzureReadError('forbidden', 403)
            return {'value': [{'id': UID, 'accountEnabled': True, 'userType': 'Member',
                              'assignedPlans': [{'servicePlanId': P2_SERVICE_PLAN_ID,
                                                 'capabilityStatus': 'Enabled'}]}]}
        if path == '/v1.0/subscribedSkus':
            self.calls.append((url, audience, body))
            return {'value': [{'id': 'sku-1', 'skuId': SKU, 'capabilityStatus': 'Enabled',
                              'appliesTo': 'User', 'servicePlans': [
                                  {'servicePlanId': P2_SERVICE_PLAN_ID,
                                   'servicePlanName': 'AAD_PREMIUM_P2',
                                   'provisioningStatus': 'Success'}]}]}
        response = super().request(url, body=body, audience=audience)
        if path == '/v1.0/identity/conditionalAccess/policies' and isinstance(response, dict):
            rows = response.get('value', [])
            for row in rows:
                row['id'] = CAID
            if rows and self.mode == 'excluded':
                rows[0]['conditions']['users']['excludeUsers'] = [UID]
            if rows and self.mode == 'risk_only':
                rows[0]['conditions']['signInRiskLevels'] = ['medium', 'high']
            if rows and self.mode == 'complete':
                risk = copy.deepcopy(rows[0])
                risk['id'] = '77777777-7777-7777-7777-777777777777'
                risk['conditions']['signInRiskLevels'] = ['medium', 'high']
                rows.append(risk)
        return response


def snapshot(monkeypatch, mode='complete', checks=CHECKS):
    api = NativeAPI(mode)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    connector = {'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}}
    required = plan_collection({'connector': connector, 'checks': list(checks)})
    assert 'conditional_access_policy' in required
    snap = collect_live(connector, required)
    assert 'compliance_policy' not in snap['metadata']
    return snap, api


def outcomes(snap, checks=CHECKS):
    index = _index(snap, resources(snap))
    scope = next(row['scope'] for row in snap['collections']
                 if row['type'] == 'conditional_access_policy')
    index['context'] = {'provider': 'azure', 'scope': scope, '_scope': scope,
                        'created_at': snap['created_at'],
                        'snapshot_id': snap['snapshot_id'], 'metadata': snap['metadata']}
    rows = index.get('conditional_access_policy', [])
    item = rows[0]['data'] if rows else {'id': 'missing'}
    return {cid: evaluate_check(cid, item, index)[0] for cid in checks}


def test_no_policy_complete_native_graph_mfa_covers_all_three(monkeypatch):
    snap, api = snapshot(monkeypatch)
    assert outcomes(snap) == {cid: 'PASS' for cid in CHECKS}
    assert all(body is None for _, _, body in api.calls)
    assert all(audience == azure.GRAPH for url, audience, _ in api.calls
               if url.startswith(azure.GRAPH))


def test_risk_specific_native_policy_requires_p2_and_covers_both_levels(monkeypatch):
    snap, _ = snapshot(monkeypatch, 'risk_only', [RISK])
    assert outcomes(snap, [RISK]) == {RISK: 'PASS'}
    rows = snap['collections']
    assert any(row['type'] == 'conditional_access_risk_entitlement'
               and row['status'] == 'collected' for row in rows)


@pytest.mark.parametrize('mode', ['device', 'conditional_risk', 'excluded',
                                  'defaults', 'partial_ca', 'denied_ca', 'denied_users',
                                  'denied_defaults', 'foreign'])
def test_inconclusive_or_untrusted_graph_is_never_a_native_pass(monkeypatch, mode):
    snap, _ = snapshot(monkeypatch, mode)
    if mode == 'foreign':
        snap = copy.deepcopy(snap)
        snap['metadata']['tenant_id'] = '33333333-3333-3333-3333-333333333333'
    states = outcomes(snap)
    assert all(state not in ('PASS', 'FAIL') for state in states.values())


@pytest.mark.parametrize('mode', ['disabled', 'reportonly'])
def test_complete_no_enabled_ca_is_only_native_user_failure(monkeypatch, mode):
    snap, _ = snapshot(monkeypatch, mode)
    states = outcomes(snap)
    assert states[USERS] == 'FAIL'
    assert states[ADMIN] == states[RISK] == 'UNKNOWN'


def test_malformed_explicit_owner_policy_does_not_become_native_default(monkeypatch):
    snap, _ = snapshot(monkeypatch)
    snap = copy.deepcopy(snap)
    snap['metadata']['compliance_policy'] = {'sw13': {'status': 'collected', 'scope': '/tenants/foreign'}}
    assert all(state == 'UNKNOWN' for state in outcomes(snap).values())


def test_malformed_snapshot_clock_is_not_accepted(monkeypatch):
    snap, _ = snapshot(monkeypatch)
    snap = copy.deepcopy(snap)
    snap['created_at'] = 'not-an-instant'
    assert all(state == 'UNKNOWN' for state in outcomes(snap).values())


def test_real_engine_without_company_policy_uses_native_graph(monkeypatch):
    snap, _ = snapshot(monkeypatch)
    report = evaluate_snapshot(snap, checks=CHECKS, include_not_applicable=True)
    for cid in CHECKS:
        statuses = [row['status'] for row in report['findings'] if row['check_id'] == cid]
        assert statuses and set(statuses) == {'PASS'}


def test_real_engine_report_only_has_only_supported_failure(monkeypatch):
    snap, _ = snapshot(monkeypatch, 'reportonly')
    report = evaluate_snapshot(snap, checks=CHECKS, include_not_applicable=True)
    statuses = {cid: [row['status'] for row in report['findings'] if row['check_id'] == cid]
                for cid in CHECKS}
    assert statuses[USERS] == ['FAIL']
    assert statuses[ADMIN] == statuses[RISK] == ['UNKNOWN']
