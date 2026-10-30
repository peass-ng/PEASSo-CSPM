"""Combined native Graph boundaries through collect_live and registered checks.

No network or credentials: the actual collector receives an inert HTTP transport.
"""
import copy
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest
from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import validate
from tests.test_peaso_azure_conditional_access_native import API, SUB, SCOPE, CHECKS, ADMIN


class CombinedAPI(API):
    def __init__(self, rows, mode='complete'):
        super().__init__(mode)
        self.rows = rows

    def request(self, url, *, body=None, audience=azure.ARM):
        result = super().request(url, body=body, audience=audience)
        if urlsplit(url).path == '/v1.0/identity/conditionalAccess/policies':
            universal = result['value'][0]
            rows = []
            for rid, changes in self.rows:
                row = copy.deepcopy(universal)
                row['id'] = rid
                for key, value in changes.items():
                    row[key] = copy.deepcopy(value)
                rows.append(row)
            return {'value': rows}
        return result


def snapshot(monkeypatch, rows, mode='complete'):
    api = CombinedAPI(rows, mode)
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    now = datetime.now(timezone.utc)
    owner = {'status': 'collected', 'scope': SCOPE, 'authorized_by': 'security-owner',
        'document_id': 'explicit-mfa-obligation', 'observed_at': (now-timedelta(hours=1)).isoformat(),
        'expires_at': (now+timedelta(hours=1)).isoformat(),
        'checks': {cid.replace('.', '|'): {'userScope': 'administrative' if cid == ADMIN else 'all',
            'designatedGroups': ['admin-group'], 'designatedRoles': [],
            'requiredApplications': ['app-1'], 'requiredClientAppTypes': ['browser']}
            for cid in CHECKS}}
    connector = {'provider': 'azure', 'scopes': [SUB],
        'options': {'retries': 0, 'compliance_policy': {'sw13': owner}}}
    result = collect_live(connector, plan_collection({'connector': connector, 'checks': CHECKS}))
    assert all(body is None for url, audience, body in api.calls)
    assert result['metadata']['compliance_policy']['sw13'] == owner
    return result


def statuses(snap):
    report = evaluate_snapshot(snap, checks=CHECKS, include_not_applicable=True)
    actual = {cid: {f['status'] for f in report['findings'] if f['check_id'] == cid} for cid in CHECKS}
    assert all(actual.values()), actual
    return actual


@pytest.mark.parametrize('invalid_first', [False, True], ids=['invalid-last', 'invalid-first'])
@pytest.mark.parametrize('boundary', ['unknown-state', 'unverified-authority'])
def test_global_native_policy_consistency_cannot_depend_on_row_order(monkeypatch, boundary, invalid_first):
    changes = {'state': 'futureUnrecognizedState'} if boundary == 'unknown-state' else {}
    rows = [('universal', {}), ('inconsistent', changes)]
    if invalid_first:
        rows.reverse()
    snap = snapshot(monkeypatch, rows)
    if boundary == 'unverified-authority':
        # A projected snapshot can retain the same tenant while failing its
        # explicit native authority flag; this is not an owner approval.
        env = next(e for e in snap['collections'] if e['type'] == 'conditional_access_policy')
        next(r for r in env['items'] if r['id'] == 'inconsistent')['_provenance']['tenant_verified'] = False
        snap.pop('snapshot_id')
        snap = validate(snap)  # Reseal this deliberately constructed offline fixture.
    assert statuses(snap) == {cid: {'UNKNOWN'} for cid in CHECKS}


def test_valid_universal_mfa_survives_unrelated_supported_and_unsupported_conditions(monkeypatch):
    rows = [('report-only', {'state': 'enabledForReportingButNotEnforced'}),
            ('universal', {}),
            ('device-filter', {'conditions': {'users': {'includeUsers': ['All']},
                'devices': {'deviceFilter': {'mode': 'exclude', 'rule': 'inert-filter'}}}})]
    assert statuses(snapshot(monkeypatch, rows)) == {cid: {'PASS'} for cid in CHECKS}


def test_excluded_user_cannot_borrow_report_only_universal_mfa(monkeypatch):
    conditions = {'users': {'includeUsers': ['All'], 'excludeUsers': ['user-1']},
        'applications': {'includeApplications': ['All']}, 'clientAppTypes': ['all']}
    rows = [('excluded', {'conditions': conditions}),
            ('unenforced-universal', {'state': 'enabledForReportingButNotEnforced'})]
    assert statuses(snapshot(monkeypatch, rows)) == {cid: {'UNKNOWN'} for cid in CHECKS}


def test_security_defaults_does_not_fill_exclusion_without_context_proof(monkeypatch):
    rows = [('disabled-universal', {'state': 'disabled'}),
            ('conditional', {'conditions': {'users': {'includeUsers': ['All'], 'excludeUsers': ['user-1']},
                'applications': {'includeApplications': ['All']}, 'clientAppTypes': ['all']}})]
    assert statuses(snapshot(monkeypatch, rows, mode='defaults')) == {cid: {'UNKNOWN'} for cid in CHECKS}


def test_universal_policy_cannot_override_partial_directory_collection(monkeypatch):
    snap = snapshot(monkeypatch, [('universal', {}), ('second-universal', {})])
    env = next(e for e in snap['collections'] if e['type'] == 'directory_user')
    env['status'] = 'partial'
    env['error'] = {'code': 'inert_second_page_denied'}
    snap.pop('snapshot_id')
    snap = validate(snap)  # Independent partial-collection fixture, not tampering bypass.
    assert statuses(snap) == {cid: {'UNKNOWN'} for cid in CHECKS}
