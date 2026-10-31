"""Properties ARM leaves out are read as their documented Azure default, and named as such."""
import pytest

import peaso.checks
from peaso.checks import CHECKS
from peaso.checks.facts import Unavailable, get
from peaso.finding_observation import evidence_summary

ACCOUNT = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct'
VAULT = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv'


def _run(check_id, item):
    check = next(check for check in CHECKS if check.id == check_id)
    return check.evaluate(item, {})


def _account(**properties):
    return {'id': ACCOUNT, 'name': 'acct', 'type': 'Microsoft.Storage/storageAccounts',
            'properties': {'supportsHttpsTrafficOnly': True, **properties}}


def _vault(**properties):
    return {'id': VAULT, 'name': 'kv', 'type': 'Microsoft.KeyVault/vaults',
            'properties': {'enableSoftDelete': True, **properties}}


@pytest.mark.parametrize('properties', [{}, {'allowSharedKeyAccess': None}])
def test_unset_shared_key_access_is_the_allowed_default(properties):
    status, evidence = _run('azure.storage.no_shared_key', _account(**properties))
    assert status == 'FAIL'
    assert [(row['field'], row['value'], row['note']) for row in evidence['platform_defaults']] == [
        ('properties.allowSharedKeyAccess', True, 'not set; Azure default is true')]


def test_an_explicit_setting_is_not_reported_as_a_default():
    status, evidence = _run('azure.storage.no_shared_key', _account(allowSharedKeyAccess=False))
    assert status == 'PASS' and 'platform_defaults' not in evidence


def test_vault_without_purge_protection_or_network_rules_uses_the_defaults():
    vault = _vault()
    assert _run('azure.vault.purge_protection', vault)[0] == 'FAIL'
    status, evidence = _run('azure.vault.default_deny', vault)
    assert status == 'FAIL'
    assert evidence['platform_defaults'][0]['field'] == 'properties.networkAcls'


def test_property_without_a_documented_default_stays_unknown():
    item = _account()
    del item['properties']['supportsHttpsTrafficOnly']
    assert _run('azure.storage.https_only', item)[0] == 'UNKNOWN'


def test_partial_representation_never_takes_a_default():
    item = _account()
    item['_provenance'] = {'representation': 'metadata'}
    assert _run('azure.storage.no_shared_key', item)[0] == 'UNKNOWN'


def test_child_service_policy_absent_reads_as_disabled():
    service = {'id': ACCOUNT + '/blobServices/default', 'type': 'Microsoft.Storage/storageAccounts/blobServices',
               'properties': {'cors': {'corsRules': []}}}
    assert get(service, 'properties.containerDeleteRetentionPolicy.enabled', bool) is False
    assert get(service, 'properties.isVersioningEnabled', bool) is False
    with pytest.raises(Unavailable):
        get(service, 'properties.changeFeed.enabled', bool)


def test_observation_names_the_unset_property_first():
    status, evidence = _run('azure.storage.no_shared_key', _account())
    finding = {'provider': 'azure', 'check_id': 'azure.storage.no_shared_key', 'status': status, 'evidence': evidence}
    lines = evidence_summary(finding).split('\n')
    assert lines[0] == evidence['platform_defaults'][0]['sentence']
    assert 1 < len(lines) <= 5
