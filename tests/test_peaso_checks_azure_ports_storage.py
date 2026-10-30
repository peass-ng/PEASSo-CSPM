"""Independent pinned-SQL truth and complete ARM identity join fixtures."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_storage as ports
from peaso.checks.fixtures import CASES

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / 'peaso/rulepacks/reviewed_azure_ports_storage.json').read_text())
REGISTRY = {check.id: check for check in CHECKS}
SOURCE = {row['source_review']['query_id']: row['source_review']['status_case_sql'] for row in REVIEWS.values()}
TRUTH = {
    'storage_account_infrastructure_encryption_enabled': ({'require_infrastructure_encryption': True}, {'require_infrastructure_encryption': False}),
    'storage_account_cross_tenant_replication_disabled': ({'allow_cross_tenant_replication': False}, {'allow_cross_tenant_replication': True}),
    'storage_account_block_public_access': ({'public_network_access': 'Disabled'}, {'public_network_access': 'Enabled'}),
    'storage_account_default_network_access_deny': ({'network_rule_default_action': 'Deny'}, {'network_rule_default_action': 'Allow'}),
    'storage_account_encryption_at_rest_using_cmk': ({'encryption_key_source': 'Microsoft.Keyvault'}, {'encryption_key_source': 'Microsoft.Storage'}),
    'storage_account_geo_redundant_enabled': ({'sku_name': 'Standard_GRS'}, {'sku_name': 'Standard_LRS'}),
    'storage_account_key_rotation_reminder_enabled': ({'key_policy': {'keyExpirationPeriodInDays': 90}}, {'key_policy': {'keyExpirationPeriodInDays': 89}}),
    'storage_account_soft_delete_enabled': ({'blob_soft_delete_enabled': True}, {'blob_soft_delete_enabled': False}),
    'storage_account_blob_soft_delete_enabled': ({'blob_soft_delete_enabled': True, 'blob_soft_delete_retention_days': 7}, {'blob_soft_delete_enabled': True, 'blob_soft_delete_retention_days': 6}),
    'storage_account_container_soft_delete_enabled': ({'blob_container_soft_delete_enabled': True, 'blob_container_soft_delete_retention_days': 7}, {'blob_container_soft_delete_enabled': True, 'blob_container_soft_delete_retention_days': 6}),
    'storage_account_blob_and_container_soft_delete_enabled': ({'blob_soft_delete_enabled': True, 'blob_container_soft_delete_enabled': True, 'blob_soft_delete_retention_days': 7, 'blob_container_soft_delete_retention_days': 365}, {'blob_soft_delete_enabled': True, 'blob_container_soft_delete_enabled': False, 'blob_soft_delete_retention_days': 7, 'blob_container_soft_delete_retention_days': None}),
    'storage_account_blob_versioning_enabled': ({'is_versioning_enabled': True}, {'is_versioning_enabled': False}),
    'storage_account_file_share_smb_protocol_version_3_1_1': ({'f': {'properties': {'protocolSettings': {'smb': {'versions': 'SMB3.1.1;'}}}}}, {'f': {'properties': {'protocolSettings': {'smb': {'versions': 'SMB3.0;SMB3.1.1;'}}}}}),
    'storage_account_file_share_smb_channel_encryption_aes_256_gcm': ({'f': {'properties': {'protocolSettings': {'smb': {'channelEncryption': 'AES-256-GCM;'}}}}}, {'f': {'properties': {'protocolSettings': {'smb': {'channelEncryption': 'AES-128-GCM;AES-256-GCM;'}}}}}),
    'storage_account_access_keys_periodically_regenerated': ({'key_name': 'key1', 'days_since_rotation': 90.0}, {'key_name': 'key1', 'days_since_rotation': 90.0001}),
}


@pytest.mark.parametrize('query', SOURCE, ids=str)
def test_independent_pinned_source_case_and_native_fixtures_agree(query):
    duckdb = pytest.importorskip('duckdb')
    case = re.sub(r'\b[a-z_]+\.(\w+)\b', r'\1', SOURCE[query])
    case = re.sub(r"(\w+(?:\s*->>?\s*'[^']+')+)\s*(=|is\s+not\s+null)", r'(\1) \2', case, flags=re.I)
    cid = ports.SOURCE_QUERIES[query]
    for n, (label, upstream, native) in enumerate((('pass', 'ok', 'PASS'), ('fail', 'alarm', 'FAIL'))):
        definitions, values = [], []
        for field, value in TRUTH[query][n].items():
            definitions.append('?' + ('::JSON' if isinstance(value, dict) else '') + ' AS ' + field)
            values.append(json.dumps(value) if isinstance(value, dict) else value)
        with duckdb.connect(':memory:') as db:
            assert db.execute('SELECT ' + case + ' FROM (SELECT ' + ','.join(definitions) + ')', values).fetchone()[0] == upstream
        fixture = CASES[cid]
        item, index = copy.deepcopy(fixture[label]), copy.deepcopy(fixture.get(label + '_index', {}))
        original = copy.deepcopy((item, index))
        assert REGISTRY[cid].evaluate(item, index)[0] == native
        assert (item, index) == original


@pytest.mark.parametrize('cid', ports.CHECK_IDS, ids=str)
def test_storage_missing_denied_partial_malformed_are_unknown(cid):
    for item in ({}, None, [], {'collection_status': 'denied'}, {'collection_status': 'partial'}):
        assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'
    fixture = CASES[cid]
    data = copy.deepcopy(fixture['pass'])
    data['_coverage'] = {key: {'status': 'denied'} for key in data}
    assert REGISTRY[cid].evaluate(data, fixture.get('pass_index', {}))[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', [query for query, cid in ports.SOURCE_QUERIES.items() if cid in ports.CHECK_IDS and 'storage_service' in REGISTRY[cid].dependencies], ids=str)
def test_child_dependency_denial_empty_duplicate_crossscope_and_malformed_type(query):
    cid = ports.SOURCE_QUERIES[query]
    item, index = copy.deepcopy(CASES[cid]['pass']), copy.deepcopy(CASES[cid]['pass_index'])
    for status in ('denied', 'partial', 'malformed', 'not_collected'):
        broken = copy.deepcopy(index)
        broken['collections']['storage_service'][0]['status'] = status
        assert REGISTRY[cid].evaluate(item, broken)[0] == 'UNKNOWN'
    for transform in ('empty', 'duplicate', 'foreign', 'type'):
        broken = copy.deepcopy(index)
        row = broken['storage_service'][0]
        if transform == 'empty': broken['storage_service'] = []
        if transform == 'duplicate': broken['storage_service'].append(copy.deepcopy(row))
        if transform == 'foreign': row['data']['id'] = row['data']['id'].replace('/sub/', '/foreign/')
        if transform == 'type': row['data']['type'] = 'Microsoft.Storage/storageAccounts'
        assert REGISTRY[cid].evaluate(item, broken)[0] == 'UNKNOWN'


@pytest.mark.parametrize('query', ['storage_account_blob_soft_delete_enabled', 'storage_account_container_soft_delete_enabled'])
def test_retention_boundaries_and_disabled_omission(query):
    cid = ports.SOURCE_QUERIES[query]
    index = copy.deepcopy(CASES[cid]['pass_index'])
    policy = next(iter(index['storage_service'][0]['data']['properties'].values()))
    for days, expected in ((1, 'FAIL'), (6, 'FAIL'), (7, 'PASS'), (365, 'PASS'), (366, 'FAIL'), (True, 'UNKNOWN'), ('7', 'UNKNOWN')):
        policy['days'] = days
        assert REGISTRY[cid].evaluate({'id': ports.ACCOUNT}, index)[0] == expected
    policy.clear(); policy['enabled'] = False
    assert REGISTRY[cid].evaluate({'id': ports.ACCOUNT}, index)[0] == 'FAIL'
    policy['enabled'] = True
    assert REGISTRY[cid].evaluate({'id': ports.ACCOUNT}, index)[0] == 'UNKNOWN'


def test_key_rotation_is_capture_anchored_and_never_needs_key_values():
    cid = ports.SOURCE_QUERIES['storage_account_access_keys_periodically_regenerated']
    item = copy.deepcopy(CASES[cid]['pass'])
    assert REGISTRY[cid].evaluate(item, {})[0] == 'UNKNOWN'
    context = CASES[cid]['pass_index']
    item['properties']['keyCreationTime']['key2'] = '2026-10-11T00:00:00Z'
    assert REGISTRY[cid].evaluate(item, context)[0] == 'UNKNOWN'
    item['properties']['keyCreationTime']['key2'] = None
    assert REGISTRY[cid].evaluate(item, context)[0] == 'UNKNOWN'
    item['properties']['keyCreationTime']['key2'] = '2026-10-10T00:00:00'
    assert REGISTRY[cid].evaluate(item, context)[0] == 'UNKNOWN'


def test_reminder_omission_is_known_disabled_but_denied_stays_unknown():
    check = REGISTRY[ports.SOURCE_QUERIES['storage_account_key_rotation_reminder_enabled']]
    assert check.evaluate({'properties': {}}, {})[0] == 'FAIL'
    assert check.evaluate({'properties': {'keyPolicy': None}}, {})[0] == 'FAIL'
    assert check.evaluate({'properties': {'_coverage': {'keyPolicy': {'status': 'denied'}}}}, {})[0] == 'UNKNOWN'
    assert check.evaluate({'properties': {'keyPolicy': {'keyExpirationPeriodInDays': True}}}, {})[0] == 'UNKNOWN'
