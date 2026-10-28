"""Federated identity candidates retain native joins, ordering and error paths."""
from collections import defaultdict
import copy
import gc
import json
import weakref

import pytest

from examples.benchmark_peaso_azure_federation import LinearFederation, synthetic_snapshot, run_stage
from peaso import principal_exposure
from peaso.analysis import azure_federation_index, cloud_workload_index
from peaso.snapshot import digest, freeze, resources, seal, validate


def source(kind, data, *, sealed=True, scope='native-scope'):
    return {'id': 'wrapper', 'provider': 'azure', 'scope': scope, 'type': kind,
            'data': freeze(data) if sealed else data}


def sp_targets(rows, data):
    return [row['data'].get('id') for row in rows
            if data.get('appId') and row['data'].get('appId') == data['appId']]


def mi_targets(rows, parent):
    return [row['data'].get('properties', {}).get('principalId') for row in rows
            if str(row['data'].get('id', '')).lower() == parent]


def outcome(function):
    try:
        return 'result', function()
    except Exception as error:
        return type(error), str(error)


@pytest.mark.parametrize('app_id', [None, '', 'app', 'APP', ['app'], {'app': True}, 7, False])
@pytest.mark.parametrize('sealed', [True, False])
def test_service_principal_candidates_preserve_literal_equality_and_duplicates(app_id, sealed):
    kind = 'directory_service_principal'
    rows = [source(kind, {'id': 'first', 'appId': 'app'}, sealed=sealed),
            source(kind, {'id': 'other', 'appId': 'APP'}, sealed=sealed),
            source(kind, {'id': 'missing'}, sealed=sealed),
            source(kind, {'id': 'list', 'appId': ['app']}, sealed=sealed),
            source(kind, {'id': None, 'appId': 'app'}, sealed=sealed),
            source(kind, {'id': 'dict', 'appId': {'app': True}}, sealed=sealed),
            source(kind, {'id': 'first', 'appId': 'app'}, sealed=sealed)]
    data = freeze({'appId': app_id})
    index = azure_federation_index.AzureFederationIndex(defaultdict(list, directory_service_principal=rows))
    assert outcome(lambda: sp_targets(index.service_principals(data), data)) == outcome(lambda: sp_targets(rows, data))


@pytest.mark.parametrize('parent', ['arm/identity', '', 'none', '7', "{'id': 1}", 'missing'])
@pytest.mark.parametrize('sealed', [True, False])
def test_managed_identity_candidates_preserve_lowercase_coercion_and_missing_fields(parent, sealed):
    kind = 'managed_identity'
    rows = [source(kind, {'id': 'ARM/Identity', 'properties': {'principalId': 'first'}}, sealed=sealed),
            source(kind, {'id': None, 'properties': {'principalId': 'null'}}, sealed=sealed),
            source(kind, {'properties': {'principalId': 'missing'}}, sealed=sealed),
            source(kind, {'id': 7, 'properties': {'principalId': 'number'}}, sealed=sealed),
            source(kind, {'id': {'id': 1}, 'properties': {'principalId': 'dict'}}, sealed=sealed),
            source(kind, {'id': 'arm/identity', 'properties': {'principalId': 'last'}}, sealed=sealed)]
    index = azure_federation_index.AzureFederationIndex(defaultdict(list, managed_identity=rows))
    credential = freeze({'id': parent + '/federatedIdentityCredentials/one'})
    assert outcome(lambda: mi_targets(index.managed_identities(credential, parent), parent)) == outcome(
        lambda: mi_targets(rows, parent))


def test_missing_app_id_does_not_build_or_read_unused_service_principal_sources():
    rows = [{'unused': 'malformed source'}]
    index = azure_federation_index.AzureFederationIndex(defaultdict(list, directory_service_principal=rows))
    for credential in (freeze({}), freeze({'appId': None}), freeze({'appId': ''})):
        assert index.service_principals(credential) == []
    assert index.index.indexes == {}


def test_mutable_credentials_keep_original_read_order_and_side_effects():
    class Credential(dict):
        def get(self, *args):
            raise AssertionError('must be read by the literal predicate')

    rows = [source('directory_service_principal', {'id': 'one', 'appId': 'app'})]
    index = azure_federation_index.AzureFederationIndex(defaultdict(list, directory_service_principal=rows))
    assert index.service_principals(Credential()) is rows
    assert index.managed_identities(Credential(), 'parent') == []
    assert index.index.indexes == {}


def test_native_and_custom_app_ids_keep_case_and_equality_semantics():
    class App(str):
        __hash__ = None

    rows = [source('directory_service_principal', {'id': 'same', 'appId': App('app')})]
    index = azure_federation_index.AzureFederationIndex(defaultdict(list, directory_service_principal=rows))
    data = freeze({'appId': 'app'})
    assert sp_targets(index.service_principals(data), data) == ['same']
    assert sp_targets(index.service_principals(freeze({'appId': 'APP'})), freeze({'appId': 'APP'})) == []


@pytest.mark.parametrize('matching', [True, False])
def test_unreadable_target_properties_keep_original_short_circuit_and_errors(matching):
    rows = [source('managed_identity', {'id': 'parent' if matching else 'other', 'properties': None})]
    index = azure_federation_index.AzureFederationIndex(defaultdict(list, managed_identity=rows))
    credential = freeze({'id': 'parent/federatedIdentityCredentials/one'})
    assert outcome(lambda: mi_targets(index.managed_identities(credential, 'parent'), 'parent')) == outcome(
        lambda: mi_targets(rows, 'parent'))


def test_duplicate_cross_scope_sources_are_not_silently_collapsed():
    rows = [source('directory_service_principal', {'id': 'one', 'appId': 'app'}, scope='tenant-one'),
            source('directory_service_principal', {'id': 'two', 'appId': 'app'}, scope='tenant-two')]
    index = azure_federation_index.AzureFederationIndex(defaultdict(list, directory_service_principal=rows))
    credential = freeze({'appId': 'app'})
    assert index.service_principals(credential) == rows
    assert sp_targets(index.service_principals(credential), credential) == ['one', 'two']


def test_empty_source_inventories_do_not_inspect_credentials():
    index = azure_federation_index.AzureFederationIndex(defaultdict(list))
    assert index.service_principals(None) == []
    assert index.managed_identities(None, None) == []


def test_native_candidate_sets_narrow_both_identity_inventories():
    sp = [source('directory_service_principal', {'id': str(i), 'appId': f'app-{i}'}) for i in range(100)]
    mi = [source('managed_identity', {'id': f'ARM/Identity-{i}', 'properties': {'principalId': str(i)}}) for i in range(100)]
    index = azure_federation_index.AzureFederationIndex(defaultdict(list, directory_service_principal=sp, managed_identity=mi))
    credential = freeze({'appId': 'app-40'})
    assert index.service_principals(credential) == [sp[40]]
    assert index.managed_identities(credential, 'arm/identity-60') == [mi[60]]


def test_index_owner_and_callbacks_do_not_create_gc_cycles():
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        rows = [source('directory_service_principal', {'id': 'one', 'appId': 'app'})]
        index = azure_federation_index.AzureFederationIndex(defaultdict(list, directory_service_principal=rows))
        owner, child = weakref.ref(index), weakref.ref(index.index)
        assert index.service_principals(freeze({'appId': 'app'}))
        del index
        assert owner() is None and child() is None
    finally:
        if was_enabled:
            gc.enable()


@pytest.mark.parametrize('capacity', [0, 1, 200000])
def test_complete_federation_findings_graph_and_principals_match_literal_scan(monkeypatch, capacity):
    snapshot = synthetic_snapshot(12)
    # Keep unknown subject coverage and failing wildcard-expression reviews.
    for collection in snapshot['collections']:
        if collection['type'] in {'directory_federated_credential', 'managed_identity_federated_credential'}:
            for i, row in enumerate(collection['items']):
                props = row.get('properties', row)
                if i % 3 == 1:
                    props.pop('subject')
                elif i % 3 == 2:
                    props.pop('subject')
                    props['issuer'] = 'https://app.terraform.io'
                    props['claimsMatchingExpression'] = {'languageVersion': 1, 'value': "claims['sub'] matches '*'"}
    snapshot = validate(seal(snapshot))
    inventory, before = resources(snapshot), digest(snapshot)
    monkeypatch.setattr(cloud_workload_index, 'MAX_KEYS', capacity)
    actual = run_stage(snapshot, inventory)
    monkeypatch.setattr(azure_federation_index, 'AzureFederationIndex', LinearFederation)
    expected = run_stage(snapshot, inventory)
    assert json.dumps(actual) == json.dumps(expected)
    assert digest(snapshot) == before
    assert {'MANUAL', 'FAIL', 'UNKNOWN'} <= {row['status'] for row in actual['findings']}


def test_fresh_projection_observes_changed_credential_targets():
    snapshot = synthetic_snapshot(2)
    first = principal_exposure.project(snapshot, resources(snapshot))
    changed = copy.deepcopy(snapshot)
    service_principals = next(row for row in changed['collections'] if row['type'] == 'directory_service_principal')['items']
    credentials = next(row for row in changed['collections'] if row['type'] == 'directory_federated_credential')['items']
    credentials[0]['appId'] = service_principals[1]['appId']
    changed = validate(seal(changed))
    second = principal_exposure.project(changed, resources(changed))
    assert first[service_principals[0]['id']]['exposures']
    assert not second[service_principals[0]['id']]['exposures']
    assert len(second[service_principals[1]['id']]['exposures']) == 2
