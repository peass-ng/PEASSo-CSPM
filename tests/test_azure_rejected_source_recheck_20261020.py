"""555 source accounting cases are not 555 native-production verdict proofs.

The independent ARM DTO matrix below exercises one unregistered proposal. No
historical CASES, runtime registration, cloud credentials or network are used.
"""
import base64
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import socket

import pytest

from peaso.checks import azure_function_monitoring_declaration_proposal_20261020 as proposal
from tests.provider_observation_residual_successors_20261020 import checked, immutable_inputs

ROOT = Path(__file__).resolve().parents[1]
REPORT = json.loads((ROOT / 'docs/check-review/azure-rejected-source-recheck-20261020.json').read_text())
QUEUE = json.loads((ROOT / REPORT['queue']['path']).read_text())
PACK_BYTES = (ROOT / REPORT['source_verification']['retained_pack']['path']).read_bytes()
PACK = json.loads(gzip.decompress(PACK_BYTES))
ROWS = {row['source_id']: row for row in REPORT['sources']}
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


def digest(value):
    return hashlib.sha256(value).hexdigest()


def native(properties):
    # Independently authored documented Microsoft.Web site + StringDictionary.
    return ({'id': SITE, 'type': 'Microsoft.Web/sites', 'name': 'function-app',
             'kind': 'functionapp,linux', 'properties': {}},
            {'id': SITE + '/config/appsettings', 'type': 'Microsoft.Web/sites/config',
             'name': 'appsettings', 'properties': properties})


def verdict(site, settings, **kwargs):
    return proposal.evaluate_native(site, settings, selected_site=SITE,
                                    subscription_id=SUB, **kwargs)


def test_exact_finite_roster_and_original_reasons_preserved():
    assert digest((ROOT / REPORT['queue']['path']).read_bytes()) == REPORT['queue']['sha256']
    assert len(QUEUE['predicates']) == len(REPORT['predicates']) == 70
    assert len(ROWS) == len(REPORT['sources']) == 555
    assert set(ROWS) == {sid for p in QUEUE['predicates'] for sid in p['source_ids']}
    for original, assessed in zip(QUEUE['predicates'], REPORT['predicates']):
        for key in ('predicate', 'source_ids', 'reasons', 'baseline_sha256', 'baseline_revision', 'current_revision'):
            assert assessed[key] == original[key]
    assert REPORT['summary']['native_production_acceptance_claimed'] is False
    assert digest(PACK_BYTES) == REPORT['source_verification']['retained_pack']['sha256']


@pytest.mark.parametrize('source_id', sorted(ROWS))
def test_every_preserved_source_has_individual_reassessment(source_id):
    row = ROWS[source_id]
    assert row['original_reason'] or row['original_reason_fallback']
    assessment = row['assessment']
    assert assessment['source_disposition']
    assert assessment['required_native_fields'] and assessment['counterexample_or_limit']
    body = PACK['predicates'][row['predicate']]['body'].encode()
    assert digest(body) == row['predicate_source_sha256']
    assert all(cid in REPORT['native_candidates'] for cid in assessment['native_candidates'])
    if row.get('requirement'):
        control = PACK['controls'][source_id]
        assert digest(control['body'].encode()) == row['control_source']['sha256']
        assert 'query.' + row['predicate'] in control['body']
        assert row['requirement']['question'] and row['requirement']['guidance']
        assert assessment['family'] in REPORT['manual_families']
        assert assessment['requirement_disposition']


@pytest.mark.parametrize('name', [p['predicate'] for p in QUEUE['predicates']])
def test_exact_retained_predicate_byte_proof(name):
    original = next(p for p in QUEUE['predicates'] if p['predicate'] == name)
    capture = PACK['predicates'][name]
    assert digest(capture['body'].encode()) == capture['sha256'] == original['baseline_sha256']
    assessed = next(p for p in REPORT['predicates'] if p['predicate'] == name)
    assert assessed['source_proof']['unchanged'] is True
    if 'original_gzip_base64' in capture:
        retained = base64.b64decode(capture['original_gzip_base64'], validate=True)
        assert gzip.decompress(retained).decode() == capture['body']
        for pair in assessed['source_proof']['captures']:
            assert digest(retained) == pair['retained_sha256']
            assert digest(gzip.decompress(retained)) == pair['sha256']


@pytest.mark.parametrize('cid', sorted(REPORT['native_candidates']))
def test_existing_candidate_current_unwrapped_source_not_registration_only(cid):
    from peaso.checks import CHECKS
    from peaso.checks.native_only import exclusions
    c, = [c for c in CHECKS if c.id == cid]
    capture = REPORT['native_candidates'][cid]
    function = inspect.unwrap(c.evaluate)
    body = inspect.getsource(function)
    assert body == PACK['native_candidates'][cid]['predicate_body']
    assert digest(body.encode()) == capture['predicate']['sha256']
    assert str(Path(inspect.getsourcefile(function)).relative_to(ROOT)) == capture['predicate']['file']
    # ``line`` is where the reviewed body sat when the report was written.
    # Later edits above it shift the position without touching the body, so the
    # current location is bound by the exact, unique body text instead.
    source = (ROOT / capture['predicate']['file']).read_text()
    assert source.count(body) == 1
    line = inspect.getsourcelines(function)[1]
    assert source.splitlines(keepends=True)[line - 1:line - 1 + body.count('\n')] == body.splitlines(keepends=True)
    assert isinstance(capture['predicate']['line'], int) and capture['predicate']['line'] >= 1
    assert capture['active'] == (cid not in exclusions())
    assert c.dependencies == capture['dependencies']


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


def test_historical_proposal_is_not_registered_and_exact_later_admission_is_source_proven():
    from peaso.checks import CHECKS
    from peaso.checks import azure_function_settings_runtime_consumer_20261020 as admitted
    receipt=checked('peaso/checks/azure_function_settings_runtime_admission_20261020.json')
    check,=[c for c in CHECKS if c.id==proposal.PROPOSED_ID]
    # The original pure proposal and all its native tests stay unchanged.
    # A later explicit admission uses a different, scan-bound native consumer.
    assert all(inspect.unwrap(c.evaluate) is not proposal.evaluate_native for c in CHECKS)
    assert inspect.unwrap(check.evaluate) is admitted.telemetry
    assert receipt['functions'][proposal.PROPOSED_ID]=='telemetry'
    assert digest(inspect.getsource(admitted.telemetry).encode())==receipt['runtime_callables']['telemetry']
    assert str(Path(inspect.getsourcefile(admitted.telemetry)).relative_to(Path(__import__('peaso').__file__).resolve().parent.parent))=='peaso/checks/azure_function_settings_runtime_consumer_20261020.py'
    assert check.kind=='azure_selected_function_settings_declaration'
    assert check.dependencies==['azure_selected_function_settings_declaration']
    with pytest.raises(AssertionError):
        socket.getaddrinfo('management.azure.com', 443)
    import peaso.collectors.azure as azure
    with pytest.raises(AssertionError):
        azure.credential_for({})


def test_proposal_source_receipt_uses_same_unwrapped_callable():
    function = inspect.unwrap(proposal.evaluate_native)
    captured = REPORT['pure_proposal_source']
    assert inspect.getsource(function) == captured['body']
    assert digest(captured['body'].encode()) == captured['sha256']
    assert str(Path(inspect.getsourcefile(function)).relative_to(ROOT)) == captured['file']
    assert inspect.getsourcelines(function)[1] == captured['line']


def test_existing_metadata_sanitizer_retains_native_SAS_policy_without_tokens():
    from peaso.collectors.azure import _metadata_only
    account = {'id': '/subscriptions/' + SUB + '/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/auditstore',
               'type': 'Microsoft.Storage/storageAccounts', 'properties': {
                   'sasPolicy': {'sasExpirationPeriod': '00.01:00:00', 'expirationAction': 'Block'},
                   'sasToken': 'never-retain-this-field'}}
    safe = _metadata_only(account)
    assert safe['properties']['sasPolicy'] == account['properties']['sasPolicy']
    assert 'sasToken' not in safe['properties']
