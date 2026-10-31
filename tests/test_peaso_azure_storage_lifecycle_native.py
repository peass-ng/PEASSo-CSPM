"""Native lifecycle configuration is useful evidence, never execution proof."""
import copy
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from fastapi import HTTPException
from peaso.collectors import azure, collect_live, azure_storage_lifecycle_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector

SUB = '11111111-1111-1111-1111-111111111111'
SCOPE = '/subscriptions/' + SUB
ACCOUNT = SCOPE + '/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account'
POLICY = ACCOUNT + '/managementPolicies/default'
CHECK = 'azure.other.storage_lifecycle'


def options(mode='fresh'):
    now = datetime.now(timezone.utc)
    delta = timedelta(days=-3 if mode == 'stale' else 3 if mode == 'future' else 0)
    return {'retries': 1, 'compliance_parameters': {native.NAMESPACE: {
        'scope': SCOPE, 'status': 'collected', 'authorized_by': 'owner-fixture', 'document_id': 'retention-review',
        'observed_at': (now + delta - timedelta(hours=1)).isoformat(),
        'expires_at': (now + delta + timedelta(hours=1)).isoformat(),
        'accounts': [{'account_id': ACCOUNT, 'protected_prefixes': [
            {'prefix': 'protected/', 'minimum_retention_days': 30, 'maximum_deletion_days': 90}]}]}}}


def policy(days=60):
    return {'id': POLICY, 'name': 'DefaultManagementPolicy', 'type': 'Microsoft.Storage/storageAccounts/managementPolicies',
            'opaque_nonpolicy': 'never-keep-this-marker', 'properties': {'policy': {'rules': [
                {'name': 'DeleteProtected', 'enabled': True, 'type': 'Lifecycle', 'definition': {
                    'filters': {'blobTypes': ['blockBlob'], 'prefixMatch': ['protected/']},
                    'actions': {'baseBlob': {'delete': {'daysAfterModificationGreaterThan': days}}}}}]}}}


class Transport:
    tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
    def __init__(self, raw=None):
        self.raw = policy() if raw is None else raw
        self.calls = []
    def request(self, url, *, body=None, audience=azure.ARM):
        assert body is None and audience == azure.ARM
        self.calls.append(url)
        path = urlsplit(url).path
        if path == POLICY:
            assert urlsplit(url).query == 'api-version=' + native.API_VERSION
            if isinstance(self.raw, Exception):
                raise self.raw
            return copy.deepcopy(self.raw)
        if path == ACCOUNT:
            return {'id': ACCOUNT, 'name': 'account', 'type': 'Microsoft.Storage/storageAccounts', 'properties': {}}
        if path == SCOPE + '/providers/Microsoft.Storage/storageAccounts':
            return {'value': [{'id': ACCOUNT, 'name': 'account', 'type': 'Microsoft.Storage/storageAccounts', 'properties': {}}]}
        return {'value': []}


def capture(monkeypatch, raw=None, supplied=None):
    api = Transport(raw)
    connector = {'provider': 'azure', 'scopes': [SUB], 'options': options() if supplied is None else supplied}
    actual_collect = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, k: actual_collect(c, k, transport=api))
    snapshot = collect_live(connector, plan_collection({'connector': connector, 'checks': [CHECK]}))
    report = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)
    collection = next(c for c in snapshot['collections'] if c['type'] == native.KIND and c['scope'] == SCOPE)
    assert report['findings'] and all(f['status'] == 'UNKNOWN' for f in report['findings'])
    assert any(f.get('native_resource_id', '').casefold() == ACCOUNT.casefold() for f in report['findings'])
    assert 'never-keep-this-marker' not in json.dumps(snapshot)
    assert len([u for u in api.calls if urlsplit(u).path == POLICY]) <= 2  # retries only on failures
    return snapshot, collection, api


@pytest.mark.parametrize('mode', ['fresh', 'stale', 'future', 'absent'])
@pytest.mark.parametrize('days', [7, 60, 120])
def test_actual_public_collection_and_signed_dispatch_preserve_missing_authorities(monkeypatch, mode, days):
    supplied = {} if mode == 'absent' else options(mode)
    snapshot, collection, api = capture(monkeypatch, policy(days), supplied)
    assert collection['status'] == 'collected', json.dumps({'collection': collection, 'parents': [c for c in snapshot['collections'] if c['type'] == 'storage_account'], 'policy_calls': [u for u in api.calls if '/managementPolicies/' in u]})
    row = collection['items'][0]
    provenance = row['_provenance']
    assert provenance['captured_at'] == snapshot['created_at']
    assert provenance['policy_approved'] is (mode == 'fresh')
    assert provenance['complete'] is False and provenance['read_only'] is True
    assert provenance['native_source_id'] == POLICY
    assert row['payload']['management_policy']['read_complete'] is True
    assert row['payload']['management_policy']['properties']['policy']['rules'][0]['definition']['actions']['baseBlob']['delete']['daysAfterModificationGreaterThan'] == days
    assert row['payload']['protected_scope_authoritative'] is (mode == 'fresh')
    assert row['payload']['version_snapshot_protection_resolved'] is False
    assert row['payload']['overlap_resolved'] is False
    assert len([u for u in api.calls if urlsplit(u).path == POLICY]) == 1


@pytest.mark.parametrize('mode', ['denied', 'notfound', 'foreign', 'type', 'missing_rules', 'duplicate_rules', 'unknown_action', 'nan', 'oversized'])
def test_native_failure_is_unknown_and_never_complete_empty(monkeypatch, mode):
    raw = policy()
    if mode == 'denied': raw = azure.AzureReadError('forbidden', 403)
    if mode == 'notfound': raw = azure.AzureReadError('not_found', 404)
    if mode == 'foreign': raw['id'] = POLICY.replace('/account/', '/another/')
    if mode == 'type': raw['type'] = 'Microsoft.Storage/storageAccounts'
    if mode == 'missing_rules': raw['properties']['policy'].pop('rules')
    if mode == 'duplicate_rules': raw['properties']['policy']['rules'] *= 2
    if mode == 'unknown_action': raw['properties']['policy']['rules'][0]['definition']['actions']['secret'] = {'value': 'marker'}
    if mode == 'nan': raw['properties']['policy']['rules'][0]['definition']['actions']['baseBlob']['delete']['daysAfterModificationGreaterThan'] = float('nan')
    if mode == 'oversized': raw['padding'] = 'x' * (1024 * 1024)
    _, collection, _ = capture(monkeypatch, raw)
    assert collection['status'] not in ('collected', 'empty') and not collection['items']


@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_intake_valid_preserves_supplied_clock_and_copy(auth_mode):
    supplied = options()
    before = copy.deepcopy(supplied)
    validate_connector('azure', {'method': 'token', 'arm_token': 'INERT'}, supplied, SimpleNamespace(auth_mode=auth_mode))
    normalized = native.normalize(supplied)
    normalized['accounts'][0]['protected_prefixes'].clear()
    assert supplied == before
    assert native.normalize(supplied)['observed_at'] == before['compliance_parameters'][native.NAMESPACE]['observed_at']


@pytest.mark.parametrize('mode', ['null', 'observations', 'resolution', 'foreign_account', 'duplicate_account', 'dot_segment', 'boolean_days', 'reversed_days', 'duplicate_prefix', 'naive_time', 'missing_identity', 'too_many_accounts', 'flat_conflict'])
@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_invalid_normative_input_rejected_by_intake_and_before_transport(monkeypatch, mode, auth_mode):
    supplied = options(); review = supplied['compliance_parameters'][native.NAMESPACE]
    if mode == 'null': supplied['compliance_parameters'][native.NAMESPACE] = None
    if mode == 'observations': review['management_policy'] = policy()
    if mode == 'resolution': review['version_snapshot_protection_resolved'] = True
    if mode == 'foreign_account': review['accounts'][0]['account_id'] = ACCOUNT.replace(SUB, '33333333-3333-3333-3333-333333333333')
    if mode == 'duplicate_account': review['accounts'].append({**copy.deepcopy(review['accounts'][0]), 'account_id': ACCOUNT.upper()})
    if mode == 'dot_segment': review['accounts'][0]['account_id'] = ACCOUNT.replace('/rg/', '/../')
    if mode == 'boolean_days': review['accounts'][0]['protected_prefixes'][0]['minimum_retention_days'] = True
    if mode == 'reversed_days': review['accounts'][0]['protected_prefixes'][0]['minimum_retention_days'] = 100
    if mode == 'duplicate_prefix': review['accounts'][0]['protected_prefixes'] *= 2
    if mode == 'naive_time': review['observed_at'] = '2026-10-01T00:00:00'
    if mode == 'missing_identity': review['authorized_by'] = ''
    if mode == 'too_many_accounts': review['accounts'] *= 257
    if mode == 'flat_conflict': supplied['compliance_policy'] = {'scope': SCOPE}
    with pytest.raises(HTTPException) as caught:
        validate_connector('azure', {}, supplied, SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code == 422
    monkeypatch.setattr(azure, 'AzureTransport', lambda *a, **k: pytest.fail('credentials/transport constructed'))
    with pytest.raises(ValueError):
        azure.collect({'scopes': [SUB], 'options': supplied}, [native.KIND])


def test_selected_scope_mismatch_before_credentials(monkeypatch):
    monkeypatch.setattr(azure, 'AzureTransport', lambda *a, **k: pytest.fail('credentials/transport constructed'))
    with pytest.raises(ValueError):
        azure.collect({'scopes': ['33333333-3333-3333-3333-333333333333'], 'options': options()}, [native.KIND])


@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_other_provider_rejects_namespace(auth_mode):
    with pytest.raises(HTTPException) as caught:
        validate_connector('aws', {}, options(), SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code == 422


def test_snapshot_binding_reuses_existing_native_instant_and_no_owner_synthesis():
    raw = policy(); native_policy = native._native_policy(raw, ACCOUNT)
    row = {'_provenance': {'complete': False, 'policy_approved': False}, 'payload': {'management_policy': native_policy}}
    collections = [{'type': native.KIND, 'items': [row]}]
    instant = '2026-10-16T02:00:00+00:00'
    assert native.snapshot_instant(collections, {native.KIND}, instant) == instant
    assert row['_provenance']['captured_at'] == instant
    assert row['_provenance']['complete'] is False and row['_provenance']['policy_approved'] is False
    assert native.normalize({}) is None
    assert native.required_types({native.KIND}) == {'storage_account'}


@pytest.mark.parametrize('mode', ['missing_enabled', 'snapshot_without_filters', 'huge_native_days'])
def test_native_documented_optional_fields_and_extreme_days(monkeypatch, mode):
    raw = policy()
    rule = raw['properties']['policy']['rules'][0]
    if mode == 'missing_enabled': rule.pop('enabled')
    if mode == 'snapshot_without_filters':
        rule['definition'] = {'actions': {'snapshot': {'delete': {'daysAfterCreationGreaterThan': 30}}}}
    if mode == 'huge_native_days':
        rule['definition']['actions']['baseBlob']['delete']['daysAfterModificationGreaterThan'] = 10 ** 1000
    _, collection, _ = capture(monkeypatch, raw)
    if mode == 'huge_native_days':
        assert collection['status'] == 'malformed' and collection['error']['kind'] == 'ValueError'
    else:
        assert collection['status'] == 'collected', collection
        native_policy = collection['items'][0]['payload']['management_policy']
        actual_rule = native_policy['properties']['policy']['rules'][0]
        if mode == 'missing_enabled':
            assert actual_rule['enabled'] is True
            assert native_policy['documented_defaults'] == [{'rule': 'DeleteProtected', 'field': 'enabled', 'value': True}]
        else:
            assert 'filters' not in actual_rule['definition']  # never invent observed filters

VERSION_CHECK = 'azure_storage_account_10_5_1_13_2f5d4f6'


def capture_version(monkeypatch, raw, dual=False):
    api = Transport(raw)
    checks = [CHECK, VERSION_CHECK] if dual else [VERSION_CHECK]
    connector = {'provider': 'azure', 'scopes': [SUB], 'options': options()}
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, k: original(c, k, transport=api))
    snapshot = collect_live(connector, plan_collection({'connector': connector, 'checks': checks}))
    report = evaluate_snapshot(snapshot, checks=checks, include_not_applicable=True)
    assert report['findings'] and all(f['status'] == 'UNKNOWN' for f in report['findings'])
    assert {f['check_id'] for f in report['findings']} == set(checks)
    assert any(f.get('native_resource_id') == ACCOUNT for f in report['findings'])
    collections = {c['type']: c for c in snapshot['collections'] if c['type'] in native.NATIVE_TYPES}
    assert len([u for u in api.calls if urlsplit(u).path == POLICY]) == 1
    return snapshot, collections


@pytest.mark.parametrize('target', ['baseBlob', 'version', 'snapshot'])
@pytest.mark.parametrize('tags', [False, True])
def test_version_native_public_action_projection_never_infers_population(monkeypatch, target, tags):
    raw = policy(); rule = raw['properties']['policy']['rules'][0]
    rule['definition']['actions'] = {target: {'delete': {
        'daysAfterModificationGreaterThan' if target == 'baseBlob' else 'daysAfterCreationGreaterThan': 30}}}
    if tags:
        rule['definition']['filters']['blobIndexMatch'] = [{'name': 'Classification', 'op': '==', 'value': 'Protected'}]
    snapshot, collections = capture_version(monkeypatch, raw)
    row = collections[native.VERSION_KIND]['items'][0]
    assert row['_provenance']['captured_at'] == snapshot['created_at']
    assert row['_provenance']['complete'] is False and row['_provenance']['policy_approved'] is False
    payload = row['payload']
    assert payload['management_policy']['properties']['policy']['rules'][0] == rule
    assert payload['versioning_read_complete'] is False
    assert payload['containers'] == {'collection_status': 'unavailable', 'items': []}
    assert 'protected_scope_authoritative' not in payload


@pytest.mark.parametrize('state', ['valid', 'denied', 'malformed'])
def test_dual_lifecycle_actual_public_dispatch_shares_one_native_get(monkeypatch, state):
    raw = azure.AzureReadError('forbidden', 403) if state == 'denied' else policy()
    if state == 'malformed': raw['properties']['policy'].pop('rules')
    snapshot, collections = capture_version(monkeypatch, raw, dual=True)
    assert set(collections) == native.NATIVE_TYPES
    for c in collections.values():
        if state == 'valid':
            assert c['status'] == 'collected'
            assert c['items'][0]['_provenance']['captured_at'] == snapshot['created_at']
        else:
            assert c['status'] == ('denied' if state == 'denied' else 'malformed')
            assert not c['items']
    if state == 'valid':
        assert collections[native.KIND]['items'][0]['_provenance']['policy_approved'] is True
        assert collections[native.VERSION_KIND]['items'][0]['_provenance']['policy_approved'] is False


@pytest.mark.parametrize('state', ['valid', 'disabled', 'foreign_service', 'duplicate_service', 'missing_versioning', 'foreign_container', 'duplicate_container'])
def test_version_reuses_only_exact_native_metadata_without_object_history(state):
    reader = azure._Reader({'retries': 0})
    service = {'id': ACCOUNT + '/blobServices/default', 'type': 'Microsoft.Storage/storageAccounts/blobServices',
               'properties': {'isVersioningEnabled': state != 'disabled'}}
    container = {'id': ACCOUNT + '/blobServices/default/containers/protected',
                 'type': 'Microsoft.Storage/storageAccounts/blobServices/containers'}
    services = {'type': 'storage_service', 'scope': ACCOUNT + '/blobServices', 'status': 'collected', 'items': [service]}
    containers = {'type': 'storage_container', 'scope': ACCOUNT, 'status': 'collected', 'items': [container]}
    if state == 'foreign_service': service['id'] = service['id'].replace('/account/', '/other/')
    if state == 'missing_versioning': service['properties'].clear()
    if state == 'foreign_container': container['id'] = container['id'].replace('/account/', '/other/')
    if state == 'duplicate_container': containers['items'] *= 2
    reader.collections = [services, containers] + ([copy.deepcopy(services)] if state == 'duplicate_service' else [])
    observed = native._version_payload(reader, ACCOUNT, native._native_policy(policy(), ACCOUNT))
    assert observed['versioning_read_complete'] is (state not in ('foreign_service', 'duplicate_service', 'missing_versioning'))
    if observed['versioning_read_complete']:
        assert observed['blob_service']['properties']['isVersioningEnabled'] is (state != 'disabled')
    if state in ('foreign_container', 'duplicate_container'):
        assert observed['containers']['collection_status'] == 'unavailable'
    else:
        actual = observed['containers']['items'][0]
        assert actual['blob_population_complete'] is False and actual['blob_tags_complete'] is False
        assert actual['required_scope_authoritative'] is False
        assert actual['required_objects'] == {'collection_status': 'unavailable', 'items': []}
    assert native.required_types({native.VERSION_KIND}) == {'storage_account'}


def test_account_without_lifecycle_policy_is_collected_with_zero_rules(monkeypatch):
    import io
    from urllib.error import HTTPError
    body = json.dumps({'error': {'code': 'ManagementPolicyNotFound', 'message': 'No ManagementPolicy found'}}).encode()
    missing = HTTPError(POLICY, 404, 'Not Found', {}, io.BytesIO(body))
    _, collection, _ = capture(monkeypatch, missing)
    assert collection['status'] == 'collected'
    policy_row = collection['items'][0]['payload']['management_policy']
    assert policy_row['read_complete'] is True and policy_row['properties']['policy']['rules'] == []


def test_other_not_found_bodies_stay_unknown(monkeypatch):
    import io
    from urllib.error import HTTPError
    body = json.dumps({'error': {'code': 'ResourceNotFound'}}).encode()
    _, collection, _ = capture(monkeypatch, HTTPError(POLICY, 404, 'Not Found', {}, io.BytesIO(body)))
    assert collection['status'] not in ('collected', 'empty') and not collection['items']
