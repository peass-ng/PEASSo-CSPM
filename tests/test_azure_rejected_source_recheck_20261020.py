"""555 source accounting cases are not 555 native-production verdict proofs.

The independent ARM DTO matrix below exercises one unregistered proposal. No
historical CASES, runtime registration, cloud credentials or network are used.
"""
from copy import deepcopy
import json
import socket

import pytest

from peaso.checks import azure_function_monitoring_declaration_proposal_20261020 as proposal

SUB = '11111111-1111-1111-1111-111111111111'
SITE = '/subscriptions/' + SUB + '/resourceGroups/rg/providers/Microsoft.Web/sites/function-app'


@pytest.fixture(autouse=True)
def no_network_or_auth(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('Network/DNS/authentication forbidden in source reassessment')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)
    import peaso.collectors.azure as azure
    monkeypatch.setattr(azure, 'credential_for', blocked)
    monkeypatch.setattr(azure.AzureTransport, 'token', blocked)


def native(properties):
    # Independently authored documented Microsoft.Web site + StringDictionary.
    return ({'id': SITE, 'type': 'Microsoft.Web/sites', 'name': 'function-app',
             'kind': 'functionapp,linux', 'properties': {}},
            {'id': SITE + '/config/appsettings', 'type': 'Microsoft.Web/sites/config',
             'name': 'appsettings', 'properties': properties})


def verdict(site, settings, **kwargs):
    return proposal.evaluate_native(site, settings, selected_site=SITE,
                                    subscription_id=SUB, **kwargs)


@pytest.mark.parametrize('properties,expected', [
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': 'InstrumentationKey=00000000-0000-0000-0000-000000000001'}, 'PASS'),
    ({'APPINSIGHTS_INSTRUMENTATIONKEY': '00000000-0000-0000-0000-000000000001'}, 'PASS'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': 'declared-but-unvalidated-destination'}, 'PASS'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': '', 'APPINSIGHTS_INSTRUMENTATIONKEY': 'configured'}, 'PASS'),
    ({}, 'FAIL'),
    ({'OTHER_NONSECRET_SETTING': 'enabled'}, 'FAIL'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': '', 'APPINSIGHTS_INSTRUMENTATIONKEY': ''}, 'FAIL'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': '   '}, 'FAIL'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': None}, 'UNKNOWN'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': 1}, 'UNKNOWN'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': '*****'}, 'UNKNOWN'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': '@Microsoft.KeyVault(SecretUri=https://example.vault.azure.net/secrets/key)'}, 'UNKNOWN'),
    ({'applicationinsights_connection_string': 'configured'}, 'UNKNOWN'),
    ({'APPLICATIONINSIGHTS_CONNECTION_STRING': 'configured', 'applicationinsights_connection_string': ''}, 'UNKNOWN'),
    ({'OTHER': ['not-a-native-string']}, 'UNKNOWN'),
])
def test_independent_native_string_dictionary_declaration(properties, expected):
    site, settings = native(properties)
    before = deepcopy((site, settings))
    status, evidence = verdict(site, settings)
    assert status == expected
    assert (site, settings) == before
    rendered = json.dumps(evidence)
    assert 'InstrumentationKey=' not in rendered and 'vault.azure.net' not in rendered
    assert 'declared-but-unvalidated-destination' not in rendered
    assert 'configured' not in rendered
    if status != 'UNKNOWN':
        assert 'Telemetry delivery and destination validity were not tested.' in evidence['observed']


@pytest.mark.parametrize('mutation', [
    'foreign_site', 'foreign_settings', 'wrong_site_type', 'wrong_settings_type',
    'wrong_settings_name', 'non_function', 'missing_site_properties',
    'missing_settings_properties', 'site_error', 'settings_error',
    'foreign_subscription', 'query_selector', 'slot_not_selected',
])
def test_native_identity_type_omission_and_error_counterexamples(mutation):
    site, settings = native({'APPLICATIONINSIGHTS_CONNECTION_STRING': 'configured'})
    kwargs = {'selected_site': SITE, 'subscription_id': SUB}
    if mutation == 'foreign_site': site['id'] += '-foreign'
    if mutation == 'foreign_settings': settings['id'] = settings['id'].replace('/rg/', '/foreign/')
    if mutation == 'wrong_site_type': site['type'] = 'Microsoft.Web/serverfarms'
    if mutation == 'wrong_settings_type': settings['type'] = 'Microsoft.Web/sites/slots/config'
    if mutation == 'wrong_settings_name': settings['name'] = 'web'
    if mutation == 'non_function': site['kind'] = 'app,linux'
    if mutation == 'missing_site_properties': site.pop('properties')
    if mutation == 'missing_settings_properties': settings.pop('properties')
    if mutation == 'site_error': site['error'] = {'code': 'Denied'}
    if mutation == 'settings_error': settings['error'] = {'code': 'Denied'}
    if mutation == 'foreign_subscription': kwargs['subscription_id'] = '22222222-2222-2222-2222-222222222222'
    if mutation == 'query_selector': kwargs['selected_site'] += '?api-version=other'
    if mutation == 'slot_not_selected': kwargs['selected_site'] += '/slots/staging'
    assert proposal.evaluate_native(site, settings, **kwargs)[0] == 'UNKNOWN'


@pytest.mark.parametrize('statuses', [(403, 200), (200, 403), (200, 206), (200, 404), (200, 429), (200, 500), (True, 200), (200, '200')])
def test_denied_partial_and_malformed_native_status(statuses):
    assert verdict(*native({'APPLICATIONINSIGHTS_CONNECTION_STRING': 'configured'}),
                   site_status=statuses[0], settings_status=statuses[1])[0] == 'UNKNOWN'


def test_existing_metadata_sanitizer_retains_native_SAS_policy_without_tokens():
    from peaso.collectors.azure import _metadata_only
    account = {'id': '/subscriptions/' + SUB + '/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/auditstore',
               'type': 'Microsoft.Storage/storageAccounts', 'properties': {
                   'sasPolicy': {'sasExpirationPeriod': '00.01:00:00', 'expirationAction': 'Block'},
                   'sasToken': 'never-retain-this-field'}}
    safe = _metadata_only(account)
    assert safe['properties']['sasPolicy'] == account['properties']['sasPolicy']
    assert 'sasToken' not in safe['properties']
