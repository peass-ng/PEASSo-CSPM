# Historical fixture contracts; current native admission is tested separately.
"""Selected CMK scan plans collect optional key metadata through inert readers."""
from datetime import datetime, timedelta, timezone
from copy import deepcopy

from peaso.collectors import azure
from peaso.checks import CHECKS
from tests.archived_check_contract import collect_snapshot, plan_collection
from test_peaso_azure_cmk_native_key_negative import API, CHECK, SUB, KEY, finding


def request():
    now = datetime.now(timezone.utc)
    policy = {'status': 'collected', 'scope': SUB, 'authorized_by': 'owner', 'document_id': 'policy',
              'observed_at': (now-timedelta(days=1)).isoformat(),
              'expires_at': (now+timedelta(days=1)).isoformat(),
              'checks': {CHECK.replace('.', '|'): {'approvedKeyUris': [KEY]}}}
    return {'connector': {'provider': 'azure', 'scopes': [SUB],
            'auth': {'method': 'token', 'arm_token': 'fixture', 'vault_token': 'fixture-vault'},
            'options': {'retries': 0, 'concurrency': 1, 'compliance_policy': {'sw13': policy}}},
            'checks': [CHECK]}


def test_key_selection_is_optional_and_explicit_inventory_is_respected():
    req = request()
    assert 'vault_key' in plan_collection(req)
    check = next(c for c in CHECKS if c.id == CHECK)
    assert 'vault_key' not in check.dependencies
    req['connector']['options']['inventories'] = ['recovery_vault']
    assert 'vault_key' not in plan_collection(req)


def test_exact_scan_selection_reaches_native_disabled_key_failure(monkeypatch):
    api = API('disabled', {})
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: api)
    snapshot = collect_snapshot(request())
    assert finding(snapshot)['status'] == 'FAIL'
    assert 'vault_key' in snapshot['metadata']['collection_plan']['requirements']
    assert any(audience == azure.VAULT for _, _, audience in api.calls)


def test_denied_optional_key_does_not_mask_absent_vault_identity(monkeypatch):
    class AbsentIdentity(API):
        def recovery(self):
            row = deepcopy(super().recovery())
            row['identity'] = {'type': 'None'}
            return row
    api = AbsentIdentity('denied', {})
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: api)
    snapshot = collect_snapshot(request())
    assert finding(snapshot)['status'] == 'FAIL'
    key = next(c for c in snapshot['collections'] if c['type'] == 'vault_key')
    assert key['status'] not in ('collected', 'empty')
