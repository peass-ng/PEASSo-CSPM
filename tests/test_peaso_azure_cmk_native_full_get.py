"""Registered CMK control against a read-only ARM list and vault GET stub."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot

SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
VAULT = SUB + '/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/cmkvault'
UAI = SUB + '/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/cmk'
KEY = 'https://cmk.vault.azure.net/keys/backup/0123456789abcdef'
CHECK = 'azure.gap.recovery_service_vault_encrypted_with_cmk'
TYPE = 'Microsoft.RecoveryServices/vaults'


def vault(mode):
    row = {'id': VAULT, 'type': TYPE, 'name': 'cmkvault', 'location': 'westeurope',
           'properties': {'encryption': {'keyVaultProperties': {'keyUri': KEY},
                         'kekIdentity': {'useSystemAssignedIdentity': True}}},
           'identity': {'type': 'SystemAssigned', 'principalId': 'system-principal'}}
    if mode == 'system_missing': row['identity'] = {'type': 'None'}
    if mode in ('user_missing_selection', 'user_unassigned', 'user_valid_no_auth'):
        row['identity'] = {'type': 'UserAssigned', 'userAssignedIdentities':
                           {UAI: {'principalId': 'user-principal'}} if mode == 'user_valid_no_auth' else {}}
        row['properties']['encryption']['kekIdentity'] = {'useSystemAssignedIdentity': False}
        if mode != 'user_missing_selection':
            row['properties']['encryption']['kekIdentity']['userAssignedIdentity'] = UAI
    if mode == 'mutually_exclusive':
        row['properties']['encryption']['kekIdentity']['userAssignedIdentity'] = UAI
    if mode == 'key_absent': row['properties'].pop('encryption')
    if mode == 'wrong_version':
        row['properties']['encryption']['keyVaultProperties']['keyUri'] = KEY[:-1] + '0'
    return row


class API:
    tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
    def __init__(self, mode): self.mode, self.calls = mode, []
    def close(self): pass
    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        path = urlsplit(url).path
        if body is not None: return {'data': []}
        if path == '/subscriptions':
            return {'value': [{'id': SUB, 'subscriptionId': SUB.rsplit('/', 1)[1], 'tenantId': self.tenant}]}
        if path == SUB:
            return {'id': SUB, 'subscriptionId': SUB.rsplit('/', 1)[1], 'tenantId': self.tenant}
        if path == SUB + '/providers/' + TYPE:
            return {'value': [vault(self.mode)]}
        if path == VAULT:
            if self.mode == 'denied_detail': raise azure.AzureReadError('AuthorizationFailed', 403)
            row = vault(self.mode)
            if self.mode == 'foreign_detail': row['id'] = row['id'].replace(SUB, '/subscriptions/foreign')
            return row
        return {'value': []}


def capture(monkeypatch, mode):
    api = API(mode)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    now = datetime.now(timezone.utc)
    authority = {'status': 'collected', 'scope': SUB, 'authorized_by': 'security-owner',
                 'document_id': 'cmk-policy', 'observed_at': (now-timedelta(days=1)).isoformat(),
                 'expires_at': (now+timedelta(days=1)).isoformat(),
                 'checks': {CHECK.replace('.', '|'): {'approvedKeyUris': [KEY]}}}
    connector = {'provider': 'azure', 'scopes': [SUB],
                 'options': {'retries': 0, 'concurrency': 1, 'compliance_policy': {'sw13': authority}}}
    required = plan_collection({'connector': connector, 'checks': [CHECK]})
    snapshot = collect_live(connector, required)
    if mode in ('foreign_capability', 'stale_capability'):
        capability = {'id': VAULT + '/capabilities/cmk', 'scope':
            '/subscriptions/foreign' if mode == 'foreign_capability' else SUB,
            '_provenance': {'read_only': True}, 'vaultId': VAULT, 'cmkSupported': True,
            'document_id': 'independent-capability', 'authorized_by': 'capability-reader',
            'observed_at': (now-timedelta(days=5)).isoformat(),
            'expires_at': (now-timedelta(days=1)).isoformat() if mode == 'stale_capability' else (now+timedelta(days=1)).isoformat()}
        collections = [c for c in snapshot['collections'] if c['type'] != 'recovery_vault_capability']
        collections.append({'type': 'recovery_vault_capability', 'scope': SUB,
                            'status': 'collected', 'items': [capability]})
        snapshot = make_snapshot('azure', [SUB], collections,
                                 metadata=snapshot['metadata'], created_at=snapshot['created_at'])
    finding = next(f for f in evaluate_snapshot(snapshot, checks=[CHECK])['findings'] if f['check_id'] == CHECK)
    return finding, snapshot, api, required


@pytest.mark.parametrize('mode,expected', [
    ('system_missing', 'FAIL'),
    ('system_valid_no_auth', 'UNKNOWN'),
    ('user_missing_selection', 'FAIL'),
    ('user_unassigned', 'FAIL'),
    ('user_valid_no_auth', 'UNKNOWN'),
    ('mutually_exclusive', 'UNKNOWN'),
    ('key_absent', 'UNKNOWN'),
    ('foreign_capability', 'UNKNOWN'),
    ('stale_capability', 'UNKNOWN'),
    ('wrong_version', 'UNKNOWN'),
    ('denied_detail', 'UNKNOWN'),
    ('foreign_detail', 'UNKNOWN'),
])
def test_full_get_cmk_applicability_and_identity_join(monkeypatch, mode, expected):
    finding, snapshot, api, required = capture(monkeypatch, mode)
    assert finding['status'] == expected, finding
    assert 'recovery_vault' in required
    if mode == 'foreign_capability': assert 'foreign observation scope' in finding['evidence']['reason']
    if mode == 'stale_capability': assert 'CMK capability evidence stale' in finding['evidence']['reason']
    assert all(body is None or url.startswith(azure.ARM + '/providers/Microsoft.ResourceGraph/resources?')
               for url, body, _ in api.calls)
    assert all('/keys/' not in url and '/secrets/' not in url and 'RunCommand' not in url for url, _, _ in api.calls)
    if mode not in ('denied_detail', 'foreign_detail'):
        row = next(c for c in snapshot['collections'] if c['type'] == 'recovery_vault')['items'][0]
        assert row['_provenance']['representation'] == 'full'
        assert row['_provenance']['api_version'] == '2024-04-01'
