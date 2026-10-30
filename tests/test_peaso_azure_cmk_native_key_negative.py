"""Exact read-only Key Vault version facts can witness a configured CMK failure."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest
from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
VAULT = SUB + '/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/cmkvault'
KEY_VAULT = SUB + '/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/cmk'
ORIGIN = 'https://cmk.vault.azure.net'
KEY = ORIGIN + '/keys/backup/0123456789abcdef'
CHECK = 'azure.gap.recovery_service_vault_encrypted_with_cmk'


class Denied(Exception):
    status_code = 403


class API:
    tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'

    def __init__(self, mode, validity):
        self.mode, self.validity, self.calls = mode, validity, []

    def close(self):
        pass

    def allow_vault(self, url):
        assert url.rstrip('/') == ORIGIN

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        assert body is None
        path = urlsplit(url).path
        if audience == azure.VAULT:
            if self.mode == 'denied':
                raise Denied('denied')
            attrs = {'enabled': self.mode != 'disabled', **self.validity}
            if path == '/keys':
                return {'value': [{'kid': ORIGIN + '/keys/backup', 'attributes': attrs}]}
            if path == '/keys/backup/versions':
                return {'value': [{'kid': KEY, 'attributes': attrs}]}
            if path == '/keys/backup/0123456789abcdef':
                return {'key': {'kid': KEY, 'kty': 'RSA', 'key_ops': ['wrapKey', 'unwrapKey']}, 'attributes': attrs}
            raise AssertionError('unexpected key endpoint: ' + path)
        if path == '/subscriptions':
            return {'value': [{'id': SUB, 'subscriptionId': SUB.rsplit('/', 1)[1], 'tenantId': self.tenant}]}
        if path == SUB:
            return {'id': SUB, 'subscriptionId': SUB.rsplit('/', 1)[1], 'tenantId': self.tenant}
        if path == SUB + '/providers/Microsoft.RecoveryServices/vaults':
            return {'value': [self.recovery()]}
        if path == VAULT:
            return self.recovery()
        if path == SUB + '/providers/Microsoft.KeyVault/vaults':
            return {'value': [{'id': KEY_VAULT, 'type': 'Microsoft.KeyVault/vaults',
                               'properties': {'vaultUri': ORIGIN}}]}
        if path == KEY_VAULT:
            return {'id': KEY_VAULT, 'type': 'Microsoft.KeyVault/vaults',
                    'properties': {'vaultUri': ORIGIN}}
        return {'value': []}

    def recovery(self):
        return {'id': VAULT, 'type': 'Microsoft.RecoveryServices/vaults',
                'properties': {'encryption': {'keyVaultProperties': {'keyUri': KEY},
                               'kekIdentity': {'useSystemAssignedIdentity': True}}},
                'identity': {'type': 'SystemAssigned', 'principalId': 'system-principal'}}


def observed(monkeypatch, mode='enabled', validity=None, selected=True):
    api = API(mode, validity or {})
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: api)
    now = datetime.now(timezone.utc)
    policy = {'status': 'collected', 'scope': SUB, 'authorized_by': 'owner', 'document_id': 'policy',
              'observed_at': (now-timedelta(days=1)).isoformat(),
              'expires_at': (now+timedelta(days=1)).isoformat(),
              'checks': {CHECK.replace('.', '|'): {'approvedKeyUris': [KEY]}}}
    connector = {'provider': 'azure', 'scopes': [SUB],
                 'auth': {'method': 'token', 'arm_token': 'fixture', 'vault_token': 'fixture-vault'},
                 'options': {'retries': 0, 'concurrency': 1, 'compliance_policy': {'sw13': policy}}}
    snapshot = collect_live(connector, ['recovery_vault', 'vault_key'] if selected else ['recovery_vault'])
    return snapshot, api


def finding(snapshot):
    return next(row for row in evaluate_snapshot(snapshot, checks=[CHECK])['findings']
                if row['check_id'] == CHECK)


def changed(snapshot, transform):
    collections = deepcopy(snapshot['collections'])
    metadata = deepcopy(snapshot['metadata'])
    transform(collections, metadata)
    return make_snapshot('azure', [SUB], collections, metadata=metadata,
                         created_at=snapshot['created_at'])


def key_collection(collections):
    return next(row for row in collections if row['type'] == 'vault_key')


@pytest.mark.parametrize('mode,validity,expected', [
    ('disabled', {}, 'FAIL'),
    ('enabled', {}, 'UNKNOWN'),
    ('enabled', {'exp': 1}, 'FAIL'),
    ('enabled', {'nbf': 4102444800}, 'FAIL'),
    ('denied', {}, 'UNKNOWN'),
])
def test_native_version_negative_or_unavailable(monkeypatch, mode, validity, expected):
    snapshot, api = observed(monkeypatch, mode, validity)
    assert finding(snapshot)['status'] == expected
    assert all(body is None for _, body, audience in api.calls if audience == azure.VAULT)
    assert all('/secrets/' not in url and 'RunCommand' not in url for url, _, _ in api.calls)
    key = next(c for c in snapshot['collections'] if c['type'] == 'vault_key')
    if mode == 'denied':
        assert key['status'] not in ('collected', 'empty')
    else:
        assert key['status'] == 'collected'
        assert key['items'][0]['versions'][0]['native_key_id'] == KEY


@pytest.mark.parametrize('mutation', [
    'foreign_parent', 'foreign_capture', 'foreign_request', 'duplicate_version',
    'partial', 'unverified_tenant', 'missing_key_get', 'versionless',
])
def test_negative_witness_requires_exact_native_identity(monkeypatch, mutation):
    snapshot, _ = observed(monkeypatch, 'disabled')
    def alter(collections, metadata):
        envelope = key_collection(collections)
        row = envelope['items'][0]
        version = row['versions'][0]
        if mutation == 'foreign_parent':
            row['id'] = row['id'].replace('/subscriptions/11111111-1111-1111-1111-111111111111', '/subscriptions/foreign')
        elif mutation == 'foreign_capture':
            version['_provenance']['credential_context_id'] = 'foreign'
        elif mutation == 'foreign_request':
            version['_provenance']['request_uri'] = KEY + '-other'
        elif mutation == 'duplicate_version':
            row['versions'].append(deepcopy(version))
        elif mutation == 'partial':
            envelope['status'] = 'partial'
        elif mutation == 'unverified_tenant':
            metadata['tenant_verified'] = False
        elif mutation == 'missing_key_get':
            version['_provenance'].pop('source_operation')
        elif mutation == 'versionless':
            recovery = next(c for c in collections if c['type'] == 'recovery_vault')
            recovery['items'][0]['properties']['encryption']['keyVaultProperties']['keyUri'] = KEY.rsplit('/', 1)[0]
    assert finding(changed(snapshot, alter))['status'] == 'UNKNOWN'


def test_no_key_inventory_does_not_claim_failure(monkeypatch):
    snapshot, api = observed(monkeypatch, 'disabled', selected=False)
    assert finding(snapshot)['status'] == 'UNKNOWN'
    assert not any(audience == azure.VAULT for _, _, audience in api.calls)


def external_key_access(snapshot, *, enabled=True, complete=True, operations=None, network=True):
    now = datetime.now(timezone.utc)
    row = {'id': VAULT + '/keyAccess/access', 'scope': SUB,
           '_provenance': {'read_only': True}, 'vaultId': VAULT, 'keyUri': KEY,
           'principalId': 'system-principal', 'document_id': 'external-key-observation',
           'authorized_by': 'independent-authority',
           'observed_at': (now-timedelta(minutes=2)).isoformat(),
           'expires_at': (now+timedelta(days=1)).isoformat(),
           'authorizationComplete': complete, 'keyEnabled': enabled,
           'networkAccessible': network,
           'effectiveKeyOperations': ['get', 'wrapKey', 'unwrapKey'] if operations is None else operations}
    def include(collections, metadata):
        collections[:] = [c for c in collections if c['type'] != 'key_authorization_evidence']
        collections.append({'type': 'key_authorization_evidence', 'scope': SUB,
                            'service': 'external', 'status': 'collected', 'items': [row]})
    return changed(snapshot, include)


@pytest.mark.parametrize('complete,enabled,operations,network,expected', [
    (True, False, ['get', 'wrapKey', 'unwrapKey'], True, 'FAIL'),
    (True, True, ['get', 'wrapKey'], True, 'FAIL'),
    (True, True, ['get', 'wrapKey', 'unwrapKey'], False, 'UNKNOWN'),
    (False, False, ['get', 'wrapKey', 'unwrapKey'], True, 'UNKNOWN'),
    (True, True, ['get', 'wrapKey', 'unwrapKey'], True, 'PASS'),
])
def test_independent_complete_key_state_precedes_network_uncertainty(
        monkeypatch, complete, enabled, operations, network, expected):
    snapshot, _ = observed(monkeypatch, 'enabled')
    assert finding(external_key_access(snapshot, enabled=enabled, complete=complete,
                                       operations=operations, network=network))['status'] == expected


def test_foreign_external_key_state_cannot_prove_failure(monkeypatch):
    snapshot, _ = observed(monkeypatch, 'enabled')
    proven = external_key_access(snapshot, enabled=False)
    def foreign(collections, metadata):
        collection = next(c for c in collections if c['type'] == 'key_authorization_evidence')
        collection['items'][0]['keyUri'] = KEY + '-other'
    assert finding(changed(proven, foreign))['status'] == 'UNKNOWN'
