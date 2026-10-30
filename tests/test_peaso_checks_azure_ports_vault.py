"""Metadata-only Key Vault source truth, parent scope, auth and API fixtures."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_vault as ports
from peaso.checks.fixtures import CASES
from peaso.collectors.azure import collect, AzureTransport, AzureReadError, VAULT, ARM

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_vault.json').read_text())
REGISTRY = {check.id: check for check in CHECKS}
SOURCE = {r['source_review']['query_id']: r['source_review']['status_case_sql'] for r in REVIEWS.values()}


@pytest.mark.parametrize('cid', ports.CHECK_IDS, ids=str)
def test_vault_actual_pass_fail_missing_denied_malformed_and_purity(cid):
    fixture = CASES[cid]
    for label, expected in (('pass', 'PASS'), ('fail', 'FAIL')):
        item, index = copy.deepcopy(fixture[label]), copy.deepcopy(fixture.get(label + '_index', {}))
        before = copy.deepcopy((item, index))
        assert REGISTRY[cid].evaluate(item, index)[0] == expected
        assert (item, index) == before
    for item in ({}, None, [], {'collection_status': 'denied'}, {'collection_status': 'partial'}):
        assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', SOURCE, ids=str)
def test_pinned_vault_source_cases_differential_truth(query):
    duckdb = pytest.importorskip('duckdb')
    case = SOURCE[query].replace('audit.id', 'audit_id').replace('alllogs.id', 'alllogs_id').replace('v.name', 'parent_name').replace('p.id', 'policy_id')
    case = re.sub(r'\b[a-z_]+\.(\w+)\b', r'\1', case)
    case = re.sub(r"(\w+)\s*@>\s*('(?:[^']*)')", r'json_contains(\1, \2::JSON)', case)
    case = case.replace('jsonb_array_length(', 'json_array_length(')
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*(=|<>|!=|is\s+not\s+null)", r'(\1) \2', case, flags=re.I)
    for good in (True, False):
        if 'expiration_set' in query:
            cols = {'enabled': True, 'expires_at': '2033-05-18' if good else None, 'parent_name': 'vault'}
        elif query == 'keyvault_key_automatic_rotation_enabled': cols = {'policy_id': 'policy' if good else None}
        elif query == 'keyvault_logging_enabled': cols = {'diagnostic_settings': [], 'audit_id': 'vault' if good else None, 'alllogs_id': 'vault'}
        elif query == 'keyvault_rbac_enabled': cols = {'enable_rbac_authorization': good}
        elif query == 'keyvault_purge_protection_enabled': cols = {'purge_protection_enabled': good}
        elif query == 'keyvault_vault_private_link_used': cols = {'network_acls': {'defaultAction': 'Deny'}, 'private_endpoint_connections': [{'PrivateLinkServiceConnectionStateStatus': 'Approved'}] if good else []}
        elif query == 'keyvault_public_network_access_disabled': cols = {'private_endpoint_connections': [{}], 'network_acls': {'defaultAction': 'Deny' if good else 'Allow'}}
        else: cols = {'network_acls': {'defaultAction': 'Deny' if good else 'Allow'}}
        defs, values = [], []
        for field, value in cols.items():
            defs.append('?' + ('::JSON' if isinstance(value, (list, dict)) else '') + ' AS ' + field)
            values.append(json.dumps(value) if isinstance(value, (list, dict)) else value)
        with duckdb.connect(':memory:') as db:
            assert db.execute('SELECT ' + case + ' FROM (SELECT ' + ','.join(defs) + ')', values).fetchone()[0] == ('ok' if good else 'alarm')


@pytest.mark.parametrize('query', [q for q in ports.SOURCE_QUERIES if 'with_' in q], ids=str)
def test_authorization_mode_applicability_requires_complete_exact_vault_join(query):
    cid = ports.SOURCE_QUERIES[query]; fixture = CASES[cid]
    item, index = copy.deepcopy(fixture['pass']), copy.deepcopy(fixture['pass_index'])
    parent = index['vault'][0]['data']
    parent['properties']['enableRbacAuthorization'] = not parent['properties']['enableRbacAuthorization']
    assert REGISTRY[cid].evaluate(item, index)[0] == 'NOT_APPLICABLE'
    parent['properties']['enableRbacAuthorization'] = not parent['properties']['enableRbacAuthorization']
    for state in ('denied', 'partial', 'malformed'):
        broken = copy.deepcopy(index); broken['collections']['vault'][0]['status'] = state
        assert REGISTRY[cid].evaluate(item, broken)[0] == 'UNKNOWN'
    parent['id'] = parent['id'].replace('/sub/', '/foreign/')
    assert REGISTRY[cid].evaluate(item, index)[0] == 'UNKNOWN'
    parent['id'] = parent['id'].replace('/foreign/', '/sub/')
    index['vault'].append(copy.deepcopy(index['vault'][0]))
    assert REGISTRY[cid].evaluate(item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', [q for q in ports.SOURCE_QUERIES if 'expiration_set' in q], ids=str)
def test_expiration_presence_source_is_not_rotation_or_freshness(query):
    cid = ports.SOURCE_QUERIES[query]; fixture = CASES[cid]
    item, index = copy.deepcopy(fixture['pass']), copy.deepcopy(fixture.get('pass_index', {}))
    attrs = item['properties']['attributes']
    attrs['exp'] = 1000000000  # Expired in the past; exact source only checks presence.
    assert REGISTRY[cid].evaluate(item, index)[0] == 'PASS'
    attrs['enabled'] = False; attrs.pop('exp')
    assert REGISTRY[cid].evaluate(item, index)[0] == 'PASS'
    attrs['enabled'] = True
    assert REGISTRY[cid].evaluate(item, index)[0] == 'FAIL'
    attrs['_coverage'] = {'exp': {'status': 'denied'}}
    assert REGISTRY[cid].evaluate(item, index)[0] == 'UNKNOWN'


def test_private_acl_empty_nonapplicable_and_known_absence_info_are_distinct():
    link = REGISTRY[ports.SOURCE_QUERIES['keyvault_vault_private_link_used']]
    acl = REGISTRY[ports.SOURCE_QUERIES['keyvault_public_network_access_disabled']]
    item = {'properties': {'networkAcls': {'defaultAction': 'Deny'}}}
    assert link.evaluate(item, {})[0] == 'MANUAL'
    item['properties']['privateEndpointConnections'] = []
    assert link.evaluate(item, {})[0] == 'FAIL'
    assert acl.evaluate(item, {})[0] == 'NOT_APPLICABLE'
    item['properties']['_coverage'] = {'privateEndpointConnections': {'status': 'denied'}}
    assert link.evaluate(item, {})[0] == 'UNKNOWN'


def test_rotation_before_expiry_only_differs_and_malformed_null_stays_unknown():
    cid = ports.SOURCE_QUERIES['keyvault_key_automatic_rotation_enabled']
    index = copy.deepcopy(CASES[cid]['pass_index'])
    row = index['key_rotation_policy'][0]['data']; trigger = row['properties']['lifetimeActions'][0]['trigger']
    trigger['timeAfterCreate'] = None
    assert REGISTRY[cid].evaluate(CASES[cid]['pass'], index)[0] == 'UNKNOWN'
    row['properties'] = {}
    assert REGISTRY[cid].evaluate(CASES[cid]['pass'], index)[0] == 'FAIL'
    index['collections']['key_rotation_policy'][0]['status'] = 'denied'
    assert REGISTRY[cid].evaluate(CASES[cid]['pass'], index)[0] == 'UNKNOWN'


def test_required_vault_diagnostics_complete_empty_fails_but_other_scope_never_satisfies():
    cid = ports.SOURCE_QUERIES['keyvault_logging_enabled']
    empty = ports._index('diagnostic_setting', [], status='empty')
    assert REGISTRY[cid].evaluate({'id': ports.VAULT_ID}, empty)[0] == 'FAIL'
    empty['collections']['diagnostic_setting'][0]['scope'] = ports.VAULT_ID.replace('/sub/', '/foreign/')
    assert REGISTRY[cid].evaluate({'id': ports.VAULT_ID}, empty)[0] == 'UNKNOWN'
    index = copy.deepcopy(CASES[cid]['pass_index'])
    index['diagnostic_setting'][0]['data']['id'] = index['diagnostic_setting'][0]['data']['id'].replace('/sub/', '/foreign/')
    assert REGISTRY[cid].evaluate({'id': ports.VAULT_ID}, index)[0] == 'FAIL'


class KeyAPI:
    tenant = 'tenant'
    def __init__(self, mode='pass'): self.mode, self.calls = mode, []
    def request(self, url, body=None, audience=ARM):
        self.calls.append((url, body, audience))
        if body: return {'data': []}
        if '/providers/Microsoft.KeyVault/vaults?' in url:
            return {'value': [{'id': ports.VAULT_ID, 'type': 'Microsoft.KeyVault/vaults', 'properties': {'vaultUri': 'https://vault.vault.azure.net/'}}]}
        if '/keys?' in url:
            if self.mode == 'denied': raise AzureReadError('denied', 403)
            if self.mode == 'empty': return {'value': []}
            if self.mode == 'foreign': return {'value': [{'kid': 'https://other.vault.azure.net/keys/key', 'attributes': {'enabled': True}}]}
            if 'page=2' in url: return {'value': [{'kid': 'https://vault.vault.azure.net/keys/key2', 'attributes': {'enabled': False}, 'key': {'d': 'INERT_PRIVATE_MATERIAL'}}]}
            return {'value': [{'kid': 'https://vault.vault.azure.net/keys/key1', 'attributes': {'enabled': True, 'exp': 2000000000}, 'key': {'d': 'INERT_PRIVATE_MATERIAL'}}], 'nextLink': 'https://vault.vault.azure.net/keys?api-version=2025-07-01&page=2'}
        if '/rotationpolicy?' in url: return {'lifetimeActions': [{'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P90D'}}]}
        raise AssertionError('unexpected operation ' + url)


@pytest.mark.parametrize('mode, expected', [('pass', 'collected'), ('empty', 'empty'), ('denied', 'denied'), ('foreign', 'malformed')])
def test_native_key_metadata_pagination_denial_empty_foreign_and_no_material(mode, expected):
    api = KeyAPI(mode)
    snap = collect({'scopes': ['sub'], 'options': {'retries': 0}}, ['key_rotation_policy'], transport=api)
    keys = next(row for row in snap['collections'] if row['type'] == 'key_metadata')
    policies = [row for row in snap['collections'] if row['type'] == 'key_rotation_policy']
    assert keys['status'] == expected
    assert 'INERT_PRIVATE_MATERIAL' not in json.dumps(snap)
    assert all(body is None or '/Microsoft.ResourceGraph/' in url for url, body, audience in api.calls)
    assert all(audience == VAULT for url, body, audience in api.calls if 'vault.azure.net' in url)
    assert all('/secrets/' not in url and '/rotate?' not in url and '/backup' not in url and '/release' not in url for url, body, audience in api.calls)
    if mode == 'pass':
        assert len(keys['items']) == 2 and len(policies) == 2
        assert keys['items'][0]['id'] == ports.VAULT_ID + '/keys/key1'
    else: assert all(row['status'] == expected for row in policies)


def test_vault_origin_must_be_arm_observed_validated_and_audience_has_no_ambient_fallback():
    transport = AzureTransport({'method': 'token', 'arm_token': 'inert-arm-token'})
    with pytest.raises(AzureReadError): transport.token(VAULT)
    for uri in ('https://evil.invalid', 'http://vault.vault.azure.net', 'https://user:password@vault.vault.azure.net', 'https://vault.vault.azure.net:443', 'https://vault.vault.azure.net/path', 'https://vault.vault.azure.net/?token=inert'):
        with pytest.raises((AzureReadError, ValueError)): transport.allow_vault(uri)
    transport.allow_vault('https://vault.vault.azure.net/')
    with pytest.raises(AzureReadError): transport.request('https://other.vault.azure.net/keys', audience=VAULT)
