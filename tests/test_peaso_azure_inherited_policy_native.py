"""Offline ARM List -> native collector -> registered Defender control evidence."""
from __future__ import annotations

import copy
import os
from urllib.parse import parse_qs, urlsplit

import pytest

from peaso.collectors import azure
from peaso.engine import plan_collection, collect_snapshot, evaluate_snapshot
from peaso.snapshot import seal

SUB = '11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
SCOPE = '/subscriptions/' + SUB
MG = '/providers/Microsoft.Management/managementGroups/parent'
EFFECT = 'azure.claude.defender_default_initiative_no_disabled_effects'
ENFORCE = 'azure.claude.defender_default_policy_enforced'
CHECKS = [EFFECT, ENFORCE]
PATH = SCOPE + '/providers/Microsoft.Authorization/policyAssignments'


def assignment(effect='AuditIfNotExists', mode='Default', scope=MG):
    return {'id': scope + '/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn',
            'name': 'SecurityCenterBuiltIn', 'properties': {'scope': scope, 'enforcementMode': mode,
            'parameters': {'systemUpdatesMonitoringEffect': {'value': effect}}}}


def status(snapshot):
    findings = evaluate_snapshot(snapshot, checks=CHECKS, categories=[], include_not_applicable=True)['findings']
    found = {row['check_id']: row['status'] for row in findings if row['check_id'] in CHECKS}
    assert set(found) == set(CHECKS)
    return found


def scan(monkeypatch, rows=(), fault=None):
    calls = []
    class FakeTransport:
        def __init__(self, auth):
            assert auth['method'] == 'token' and auth['tenant_id'] == TENANT
            self.tenant = TENANT
            self.verified_tenant = TENANT
        def request(self, url, *, body=None, audience=azure.ARM, capture_subject=False):
            assert audience == azure.ARM
            parsed = urlsplit(url)
            query = parse_qs(parsed.query)
            calls.append(('POST_READ' if body is not None else 'GET', parsed.path, query))
            if parsed.path == '/providers/Microsoft.ResourceGraph/resources' and body is not None:
                return {'data': [], 'totalRecords': 0, 'count': 0}
            if parsed.path == SCOPE and body is None:
                return {'id': SCOPE, 'subscriptionId': SUB, 'tenantId': TENANT, 'state': 'Enabled'}
            if parsed.path == PATH and body is None:
                if fault == 'denied' or 'skipToken' in query:
                    raise azure.AzureReadError('denied', 403)
                if fault == 'partial':
                    return {'value': copy.deepcopy(list(rows)), 'nextLink': url + '&skipToken=unread'}
                if fault == 'filtered_continuation':
                    return {'value': copy.deepcopy(list(rows)), 'nextLink': url + '&$filter=atExactScope()'}
                if fault == 'wrong_version_continuation':
                    return {'value': copy.deepcopy(list(rows)), 'nextLink': PATH + '?api-version=2024-04-01'}
                if fault == 'needs_get':
                    values = copy.deepcopy(list(rows))
                    for value in values: value.pop('properties', None)
                    return {'value': values}
                return {'value': copy.deepcopy(list(rows))}
            if fault == 'needs_get' and parsed.path == rows[0]['id'] and body is None:
                assert query == {'api-version': ['2023-04-01']}
                return copy.deepcopy(rows[0])
            raise AssertionError('unexpected read-only request ' + parsed.path)
        def close(self):
            pass
    monkeypatch.setattr(azure, 'AzureTransportExposure', FakeTransport)
    req = {'connector': {'provider': 'azure', 'scopes': [SCOPE],
           'auth': {'method': 'token', 'tenant_id': TENANT, 'arm_token': 'inert-test-value'},
           'options': {'max_calls': 10, 'max_resources': 100, 'retries': 0, 'concurrency': 1}},
           'checks': CHECKS, 'categories': []}
    assert 'policy_assignment' in plan_collection(req)
    snapshot = collect_snapshot(req)
    assert all(method in ('GET', 'POST_READ') for method, _, _ in calls)
    assert any(method == 'GET' and path == PATH and query == {'api-version': ['2023-04-01']}
               for method, path, query in calls)
    return status(snapshot), snapshot, calls


def test_baseline_counterexample_or_candidate_inherited_pass(monkeypatch):
    found, snapshot, _ = scan(monkeypatch, [assignment()])
    if os.environ.get('PEASO_BASELINE') == '1':
        assert found == {EFFECT: 'UNKNOWN', ENFORCE: 'UNKNOWN'}
        return
    assert found == {EFFECT: 'PASS', ENFORCE: 'PASS'}
    rows = next(c for c in snapshot['collections'] if c['type'] == 'policy_assignment')['items']
    assert len(rows) == 1
    assert rows[0]['_native_policy_assignment_list'] == {
        'source_operation': 'PolicyAssignments_List', 'api_version': '2023-04-01',
        'read_only': True, 'selected_scope': SCOPE, 'filter': None, 'request_path': PATH}


@pytest.mark.parametrize(('effect', 'mode', 'expected'), [
    ('Disabled', 'DoNotEnforce', ('FAIL', 'FAIL')),
    ('Disabled', 'Default', ('FAIL', 'PASS')),
    ('AuditIfNotExists', 'DoNotEnforce', ('PASS', 'FAIL'))])
def test_inherited_independent_criteria(monkeypatch, effect, mode, expected):
    found, _, _ = scan(monkeypatch, [assignment(effect, mode)])
    assert found == dict(zip(CHECKS, expected))


@pytest.mark.parametrize(('effect', 'mode', 'expected'), [
    ('AuditIfNotExists', 'Default', ('PASS', 'PASS')),
    ('Disabled', 'DoNotEnforce', ('FAIL', 'FAIL'))])
def test_direct_contract_unchanged(monkeypatch, effect, mode, expected):
    found, _, _ = scan(monkeypatch, [assignment(effect, mode, SCOPE)])
    assert found == dict(zip(CHECKS, expected))


def test_child_retained_but_not_subscription_verdict(monkeypatch):
    child = assignment('Disabled', 'DoNotEnforce', SCOPE + '/resourceGroups/child')
    found, snapshot, _ = scan(monkeypatch, [child])
    assert found == {EFFECT: 'NOT_APPLICABLE', ENFORCE: 'NOT_APPLICABLE'}
    collection = next(c for c in snapshot['collections'] if c['type'] == 'policy_assignment')
    assert collection['status'] == 'collected' and collection['items'][0]['id'] == child['id']


def test_mixed_inherited_and_child(monkeypatch):
    rows = [assignment(), assignment('Disabled', 'DoNotEnforce', SCOPE + '/resourceGroups/child')]
    found, snapshot, _ = scan(monkeypatch, rows)
    assert found == {EFFECT: 'PASS', ENFORCE: 'PASS'}
    assert len(next(c for c in snapshot['collections'] if c['type'] == 'policy_assignment')['items']) == 2


def test_native_list_with_detail_get_retains_subscription_binding(monkeypatch):
    found, snapshot, calls = scan(monkeypatch, [assignment()], fault='needs_get')
    assert found == {EFFECT: 'PASS', ENFORCE: 'PASS'}
    assert any(path == assignment()['id'] and method == 'GET' for method, path, _ in calls)
    row = next(c for c in snapshot['collections'] if c['type'] == 'policy_assignment')['items'][0]
    assert row['_native_policy_assignment_list']['selected_scope'] == SCOPE


def test_empty_signed_branches(monkeypatch):
    found, _, _ = scan(monkeypatch, [])
    assert found == {EFFECT: 'NOT_APPLICABLE', ENFORCE: 'NOT_APPLICABLE'}


@pytest.mark.parametrize('fault', ['denied', 'partial', 'filtered_continuation', 'wrong_version_continuation'])
def test_incomplete_list_is_not_certified(monkeypatch, fault):
    found, _, _ = scan(monkeypatch, [assignment()], fault=fault)
    assert all(value in ('UNKNOWN', 'DENIED') for value in found.values())


@pytest.mark.parametrize('damage', ['missing', 'foreign_scope', 'wrong_version', 'filtered', 'unreadable'])
def test_imported_inherited_source_requires_exact_marker(monkeypatch, damage):
    found, snapshot, _ = scan(monkeypatch, [assignment()])
    assert found == {EFFECT: 'PASS', ENFORCE: 'PASS'}
    def corrupt(node):
        if isinstance(node, dict):
            proof = node.get('_native_policy_assignment_list')
            if isinstance(proof, dict):
                if damage == 'missing': node.pop('_native_policy_assignment_list')
                elif damage == 'foreign_scope': proof['selected_scope'] = '/subscriptions/33333333-3333-3333-3333-333333333333'
                elif damage == 'wrong_version': proof['api_version'] = '2024-04-01'
                elif damage == 'filtered': proof['filter'] = 'atExactScope()'
                else: node['_native_policy_assignment_list'] = {'status': 'denied'}
            for value in node.values(): corrupt(value)
        elif isinstance(node, list):
            for value in node: corrupt(value)
    modified = copy.deepcopy(snapshot)
    corrupt(modified)
    modified = seal(modified)
    assert status(modified) == {EFFECT: 'UNKNOWN', ENFORCE: 'UNKNOWN'}


@pytest.mark.parametrize('damage', ['notScopes', 'resourceSelectors', 'overrides', 'declared_scope', 'foreign_subscription', 'duplicate'])
def test_conditional_or_foreign_inherited_evidence_unknown(monkeypatch, damage):
    row = assignment()
    rows = [row]
    if damage in ('notScopes', 'resourceSelectors', 'overrides'):
        row['properties'][damage] = [SCOPE] if damage == 'notScopes' else [{'name': 'conditional'}]
    elif damage == 'declared_scope': row['properties']['scope'] = SCOPE
    elif damage == 'foreign_subscription': rows = [assignment(scope='/subscriptions/33333333-3333-3333-3333-333333333333')]
    else: rows = [row, copy.deepcopy(row)]
    found, _, _ = scan(monkeypatch, rows)
    assert found == {EFFECT: 'UNKNOWN', ENFORCE: 'UNKNOWN'}
