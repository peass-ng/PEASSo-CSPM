"""Independent ARM HTTP -> existing AzureTransport/_Reader -> public engine.

The new adapters and consumers are uninstalled; only this bridge registers them.
No CASES are imported or used as native HTTP inputs.
"""
from copy import deepcopy
import io
import json
import gzip
import socket
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest
from peaso import checks
from peaso.collectors import azure
from peaso.collectors import azure_nsp_query_cmk_metadata_proposal_20261020 as native
from peaso.checks import azure_nsp_query_cmk_metadata_proposal_20261020 as consumer
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SUB = '11111111-1111-1111-1111-111111111111'
OTHER = '99999999-9999-9999-9999-999999999999'
SCOPE = '/subscriptions/' + SUB
ROOT = SCOPE + '/resourceGroups/review/providers/'
PERIMETER = ROOT + native.NSP + '/perimeter'
ASSOC = PERIMETER + '/resourceAssociations/association'
PROFILE = PERIMETER + '/profiles/profile'
ACCOUNT = ROOT + native.STORAGE + '/storageone'
WORKSPACE = ROOT + native.WORKSPACE + '/workspace'
LINK = WORKSPACE + '/linkedStorageAccounts/Query'
CANARY = 'NEVER_EXPORT_RESPONSE_VALUE_20261020'
FIXTURE_PATH = Path(__file__).parent / 'fixtures/azure_nsp_query_cmk_metadata_proposal_20261020.json.gz'
NATIVE_FIXTURES = json.loads(gzip.decompress(FIXTURE_PATH.read_bytes()))['cases']


def resource(rid, typ, props):
    return {'id': rid, 'name': rid.rsplit('/', 1)[-1], 'type': typ,
            'location': 'eastus', 'properties': props, 'tags': {'opaque': CANARY}}


class NativeHTTP:
    def __init__(self):
        self.calls = []
        self.routes = {}
        self.status = 200
        self.put(SCOPE + '/providers/' + native.NSP, native.NSP_VERSION, {'value': [resource(
            PERIMETER, native.NSP, {'provisioningState': 'Succeeded'})]})
        association = resource(ASSOC, native.NSP + '/resourceAssociations', {
            'accessMode': 'Enforced', 'hasProvisioningIssues': 'no',
            'provisioningState': 'Succeeded', 'profile': {'id': PROFILE},
            'privateLinkResource': {'id': ACCOUNT}})
        self.put(PERIMETER + '/resourceAssociations', native.NSP_VERSION, {'value': [association]})
        self.put(ASSOC, native.NSP_VERSION, deepcopy(association))
        self.put(PROFILE, native.NSP_VERSION, resource(PROFILE, native.NSP + '/profiles', {
            'accessRulesVersion': '0', 'diagnosticSettingsVersion': '0'}))
        self.put(ACCOUNT, native.STORAGE_VERSION, resource(ACCOUNT, native.STORAGE, {
            'provisioningState': 'Succeeded', 'encryption': {'keySource': 'Microsoft.Keyvault',
            'services': {'table': {'keyType': 'Account', 'enabled': True}},
            'keyvaultproperties': {'keyname': 'declared-key', 'keyvaulturi': 'https://reviewvault.vault.azure.net',
                                   'keyversion': 'a' * 32}}}))
        workspace = resource(WORKSPACE, native.WORKSPACE, {'provisioningState': 'Succeeded'})
        self.put(SCOPE + '/providers/' + native.WORKSPACE, native.WORKSPACE_VERSION, {'value': [workspace]})
        self.put(WORKSPACE, native.WORKSPACE_VERSION, deepcopy(workspace))
        self.put(WORKSPACE + '/linkedStorageAccounts', native.LINK_VERSION, {'value': [resource(
            LINK, native.WORKSPACE + '/linkedStorageAccounts',
            {'dataSourceType': 'Query', 'storageAccountIds': [ACCOUNT]})]})

    def put(self, path, version, body, token=None):
        self.routes[(path.casefold(), version, token)] = body

    def get(self, path, version):
        return self.routes[(path.casefold(), version, None)]

    def props(self, path, version):
        return self.get(path, version)['properties']

    def associations(self):
        return (self.get(PERIMETER + '/resourceAssociations', native.NSP_VERSION)['value'][0],
                self.get(ASSOC, native.NSP_VERSION))

    def links(self):
        return self.get(WORKSPACE + '/linkedStorageAccounts', native.LINK_VERSION)['value']

    def open(self, request, timeout):
        u = urlsplit(request.full_url)
        query = parse_qs(u.query)
        assert request.get_method() == 'GET' and request.data is None
        assert u.scheme == 'https' and u.netloc == 'management.azure.com'
        assert not u.fragment and not u.username and not u.password
        assert timeout == 20 and request.get_header('Authorization') == 'Bearer INERT_NATIVE_FIXTURE'
        assert set(query) <= {'api-version', '$skipToken'}
        key = (u.path.casefold(), query['api-version'][0], query.get('$skipToken', [None])[0])
        self.calls.append({'method': 'GET', 'host': u.netloc, 'path': u.path,
                           'api_version': key[1], 'page': key[2] is not None})
        assert key in self.routes, key
        body = self.routes[key]
        if isinstance(body, int):
            raise HTTPError(request.full_url, body, CANARY, {}, io.BytesIO(CANARY.encode()))
        if isinstance(body, bytes):
            response = io.BytesIO(body)
        else:
            response = io.BytesIO(json.dumps(body).encode())
        response.status = self.status
        return response


@pytest.fixture(autouse=True)
def offline_local_registry(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network, DNS and authentication forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto')), (azure, ('credential_for',))):
        for name in names:
            monkeypatch.setattr(owner, name, blocked)
    original = list(checks.CHECKS)
    checks.CHECKS[:] = [c for c in original if c.id not in (consumer.NSP_CHECK, consumer.QUERY_CHECK)]
    for declaration, evaluator in zip(consumer.DECLARATIONS, (consumer.nsp, consumer.query)):
        assert not any(row.id == declaration['id'] for row in checks.CHECKS)
        checks.register(declaration['id'], 'azure', 'hardening', declaration['kind'],
                        declaration['title'], 'medium', '', declaration['remediation'],
                        dependencies=declaration['dependencies'])(evaluator)
    yield
    checks.CHECKS[:] = original


def capture(monkeypatch, http, kind, options=None):
    monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    transport = azure.AzureTransport({'method': 'token', 'arm_token': 'INERT_NATIVE_FIXTURE'})
    connector = {'provider': 'azure', 'scopes': [SUB], 'options': options or {}}
    snapshot = native.collect(connector, [kind], transport=transport)
    check_id = consumer.NSP_CHECK if kind == native.NSP_KIND else consumer.QUERY_CHECK
    findings = evaluate_snapshot(snapshot, checks=[check_id], include_not_applicable=True)['findings']
    assert CANARY not in json.dumps(snapshot) + json.dumps(findings)
    assert all(not any(s in call['path'].casefold() for s in ('/keys/', '/secrets/', '/listkeys', '/query'))
               for call in http.calls)
    return {finding['status'] for finding in findings}, snapshot, findings


NSP_CASES = [
    ('enforced', 'PASS'), ('learning', 'FAIL'), ('audit', 'FAIL'), ('transition', 'UNKNOWN'),
    ('omitted_mode', 'UNKNOWN'), ('bad_mode_type', 'UNKNOWN'), ('provisioning', 'UNKNOWN'),
    ('issues_yes', 'UNKNOWN'), ('issues_boolean', 'UNKNOWN'), ('issues_omitted', 'UNKNOWN'),
    ('foreign_profile', 'UNKNOWN'), ('foreign_account', 'UNKNOWN'), ('unsupported_protected', 'UNKNOWN'),
    ('foreign_association', 'UNKNOWN'), ('wrong_association_type', 'UNKNOWN'), ('wrong_parent_type', 'UNKNOWN'),
    ('foreign_parent', 'UNKNOWN'), ('profile_wrong_id', 'UNKNOWN'), ('profile_wrong_type', 'UNKNOWN'),
    ('profile_wrong_name', 'UNKNOWN'), ('storage_wrong_id', 'UNKNOWN'), ('storage_wrong_type', 'UNKNOWN'),
    ('storage_unprovisioned', 'UNKNOWN'), ('parent_unprovisioned', 'UNKNOWN'), ('detail_race', 'UNKNOWN'),
    ('duplicate_association', 'UNKNOWN'), ('duplicate_parent', 'UNKNOWN'), ('duplicate_protected', 'UNKNOWN'),
    ('parent_denied', 'DENIED'), ('association_denied', 'DENIED'), ('profile_denied', 'DENIED'),
    ('storage_denied', 'DENIED'), ('empty_parent', 'EMPTY'), ('empty_associations', 'EMPTY'),
    ('association_partial', 'UNKNOWN'), ('parent_partial', 'UNKNOWN'), ('foreign_continuation', 'UNKNOWN'),
    ('changed_api_continuation', 'UNKNOWN'), ('paginated', 'PASS'), ('uppercase_identity', 'PASS'),
]


def nsp_mode(http, mode):
    for row in http.associations():
        p = row['properties']
        if mode in ('learning', 'audit', 'transition'):
            p['accessMode'] = {'learning': 'Learning', 'audit': 'Audit', 'transition': 'Transition'}[mode]
        if mode == 'omitted_mode': p.pop('accessMode')
        if mode == 'bad_mode_type': p['accessMode'] = {'opaque': CANARY}
        if mode == 'provisioning': p['provisioningState'] = 'Updating'
        if mode == 'issues_yes': p['hasProvisioningIssues'] = 'yes'
        if mode == 'issues_boolean': p['hasProvisioningIssues'] = False
        if mode == 'issues_omitted': p.pop('hasProvisioningIssues')
        if mode == 'foreign_profile': p['profile']['id'] = PROFILE.replace('/perimeter/', '/sibling/')
        if mode == 'foreign_account': p['privateLinkResource']['id'] = ACCOUNT.replace(SUB, OTHER)
        if mode == 'unsupported_protected': p['privateLinkResource']['id'] = ACCOUNT.replace(native.STORAGE, 'Microsoft.KeyVault/vaults')
        if mode == 'foreign_association': row['id'] = ASSOC.replace('/perimeter/', '/sibling/')
        if mode == 'wrong_association_type': row['type'] = native.NSP + '/profiles'
        if mode == 'uppercase_identity':
            row['id'] = row['id'].upper();row['type'] = row['type'].upper();row['name'] = row['name'].upper()
    parent = http.get(SCOPE + '/providers/' + native.NSP, native.NSP_VERSION)['value'][0]
    if mode == 'wrong_parent_type': parent['type'] = native.WORKSPACE
    if mode == 'foreign_parent': parent['id'] = PERIMETER.replace(SUB, OTHER)
    if mode == 'parent_unprovisioned': parent['properties']['provisioningState'] = 'Updating'
    for target, version, prefix in ((PROFILE, native.NSP_VERSION, 'profile'), (ACCOUNT, native.STORAGE_VERSION, 'storage')):
        if mode == prefix + '_wrong_id': http.get(target, version)['id'] += 'other'
        if mode == prefix + '_wrong_type': http.get(target, version)['type'] = native.WORKSPACE
        if mode == prefix + '_wrong_name': http.get(target, version)['name'] = 'other'
        if mode == prefix + '_denied': http.put(target, version, 403)
    if mode == 'storage_unprovisioned': http.props(ACCOUNT, native.STORAGE_VERSION)['provisioningState'] = 'Updating'
    if mode == 'detail_race': http.props(ASSOC, native.NSP_VERSION)['accessMode'] = 'Audit'
    if mode == 'duplicate_association': http.get(PERIMETER + '/resourceAssociations', native.NSP_VERSION)['value'] *= 2
    if mode == 'duplicate_parent': http.get(SCOPE + '/providers/' + native.NSP, native.NSP_VERSION)['value'] *= 2
    if mode == 'duplicate_protected':
        row = deepcopy(http.associations()[0]);row['id'] += 'two';row['name'] += 'two'
        http.get(PERIMETER + '/resourceAssociations', native.NSP_VERSION)['value'].append(row)
        http.put(row['id'], native.NSP_VERSION, deepcopy(row))
    paths = {'parent_denied': SCOPE + '/providers/' + native.NSP, 'association_denied': PERIMETER + '/resourceAssociations'}
    if mode in paths: http.put(paths[mode], native.NSP_VERSION, 403)
    if mode == 'empty_parent': http.get(SCOPE + '/providers/' + native.NSP, native.NSP_VERSION)['value'] = []
    if mode == 'empty_associations': http.get(PERIMETER + '/resourceAssociations', native.NSP_VERSION)['value'] = []
    if mode in ('association_partial', 'parent_partial', 'foreign_continuation', 'changed_api_continuation', 'paginated'):
        path = SCOPE + '/providers/' + native.NSP if mode == 'parent_partial' else PERIMETER + '/resourceAssociations'
        more = native.ARM + path + '?api-version=' + native.NSP_VERSION + '&$skipToken=next'
        if mode == 'foreign_continuation': more = more.replace('management.azure.com', 'foreign.invalid')
        if mode == 'changed_api_continuation': more = more.replace(native.NSP_VERSION, '2025-01-01')
        http.get(path, native.NSP_VERSION)['nextLink'] = more
        http.put(path, native.NSP_VERSION, {'value': []} if mode == 'paginated' else 403, 'next')


@pytest.mark.parametrize('mode,want', NSP_CASES, ids=[case[0] for case in NSP_CASES])
def test_native_nsp(monkeypatch, mode, want, record_property):
    http = NativeHTTP();nsp_mode(http, mode)
    actual, snapshot, findings = capture(monkeypatch, http, native.NSP_KIND)
    record_property('check_id', consumer.NSP_CHECK);record_property('actual', ','.join(sorted(actual)))
    assert actual == {want}, findings


QUERY_CASES = [
    ('cmk', 'PASS'), ('provider', 'FAIL'), ('mixed', 'FAIL'), ('versionless', 'PASS'),
    ('version_omitted', 'PASS'), ('version_null', 'UNKNOWN'), ('managed_hsm_reference', 'PASS'),
    ('key_casefold', 'PASS'), ('no_links', 'NOT_APPLICABLE'),
    ('other_links', 'NOT_APPLICABLE'), ('empty_query_accounts', 'UNKNOWN'), ('absent_ids', 'UNKNOWN'),
    ('missing_encryption', 'UNKNOWN'), ('missing_keysource', 'UNKNOWN'), ('unknown_keysource', 'UNKNOWN'),
    ('missing_key_reference', 'UNKNOWN'), ('bad_key_name', 'UNKNOWN'), ('bad_key_version', 'UNKNOWN'),
    ('http_key_uri', 'UNKNOWN'), ('foreign_key_uri', 'UNKNOWN'), ('userinfo_key_uri', 'UNKNOWN'),
    ('key_uri_query', 'UNKNOWN'), ('key_uri_port', 'UNKNOWN'), ('reference_shape', 'UNKNOWN'),
    ('wrong_source', 'UNKNOWN'), ('contradictory_source', 'UNKNOWN'), ('foreign_link', 'UNKNOWN'),
    ('wrong_link_type', 'UNKNOWN'), ('duplicate_link', 'UNKNOWN'), ('duplicate_account', 'UNKNOWN'),
    ('foreign_account', 'UNKNOWN'), ('sibling_account_response', 'UNKNOWN'), ('wrong_account_type', 'UNKNOWN'),
    ('wrong_workspace_type', 'UNKNOWN'), ('foreign_workspace', 'UNKNOWN'), ('workspace_detail_mismatch', 'UNKNOWN'),
    ('account_unprovisioned', 'UNKNOWN'), ('workspace_unprovisioned', 'UNKNOWN'), ('malformed_list', 'UNKNOWN'),
    ('denied_links', 'DENIED'), ('denied_storage', 'DENIED'), ('denied_workspace', 'DENIED'),
    ('partial_links', 'UNKNOWN'), ('empty_partial_links', 'UNKNOWN'), ('foreign_page', 'UNKNOWN'),
    ('paginated', 'PASS'), ('two_accounts', 'PASS'), ('two_workspaces_cache', 'PASS'),
    ('oversize', 'UNKNOWN'), ('invalid_json', 'UNKNOWN'), ('opaque_fields', 'PASS'),
    ('table_service_key', 'FAIL'), ('table_key_missing', 'UNKNOWN'), ('table_key_unknown', 'UNKNOWN'),
]


def query_mode(http, mode):
    enc = http.props(ACCOUNT, native.STORAGE_VERSION)['encryption']
    key = enc['keyvaultproperties']
    link = http.links()[0];props = link['properties']
    if mode == 'provider': enc['keySource'] = 'Microsoft.Storage';enc.pop('keyvaultproperties')
    if mode == 'versionless': key['keyversion'] = ''
    if mode == 'version_omitted': key.pop('keyversion')
    if mode == 'version_null': key['keyversion'] = None
    if mode == 'managed_hsm_reference': key['keyvaulturi'] = 'https://reviewhsm.managedhsm.azure.net'
    if mode == 'key_casefold': enc['keySource'] = 'microsoft.KEYVAULT'
    if mode == 'no_links': http.links().clear()
    if mode == 'other_links':
        link['id'] = LINK.replace('/Query', '/Alerts');link['name'] = 'Alerts';props['dataSourceType'] = 'Alerts'
    if mode == 'empty_query_accounts': props['storageAccountIds'] = []
    if mode == 'absent_ids': props.pop('storageAccountIds')
    if mode == 'missing_encryption': http.props(ACCOUNT, native.STORAGE_VERSION).pop('encryption')
    if mode == 'missing_keysource': enc.pop('keySource')
    if mode == 'table_service_key': enc['services']['table']['keyType'] = 'Service'
    if mode == 'table_key_missing': enc.pop('services')
    if mode == 'table_key_unknown': enc['services']['table']['keyType'] = 'FutureKey'
    if mode == 'unknown_keysource': enc['keySource'] = 'FutureProvider'
    if mode == 'missing_key_reference': enc.pop('keyvaultproperties')
    if mode == 'bad_key_name': key['keyname'] = '../invalid'
    if mode == 'bad_key_version': key['keyversion'] = 'invalid'
    if mode == 'http_key_uri': key['keyvaulturi'] = 'http://reviewvault.vault.azure.net'
    if mode == 'foreign_key_uri': key['keyvaulturi'] = 'https://reviewvault.vault.azure.net.foreign.invalid'
    if mode == 'userinfo_key_uri': key['keyvaulturi'] = 'https://evil@reviewvault.vault.azure.net'
    if mode == 'key_uri_query': key['keyvaulturi'] += '?token=' + CANARY
    if mode == 'key_uri_port': key['keyvaulturi'] += ':443'
    if mode == 'reference_shape': enc['keyvaultproperties'] = CANARY
    if mode == 'wrong_source': props['dataSourceType'] = 'FutureSource'
    if mode == 'contradictory_source': props['dataSourceType'] = 'Alerts'
    if mode == 'foreign_link': link['id'] = LINK.replace('/workspace/', '/sibling/')
    if mode == 'wrong_link_type': link['type'] = native.STORAGE
    if mode == 'duplicate_link': http.links().append(deepcopy(link))
    if mode == 'duplicate_account': props['storageAccountIds'] *= 2
    if mode == 'foreign_account': props['storageAccountIds'] = [ACCOUNT.replace(SUB, OTHER)]
    if mode == 'sibling_account_response': http.get(ACCOUNT, native.STORAGE_VERSION)['id'] += 'other'
    if mode == 'wrong_account_type': http.get(ACCOUNT, native.STORAGE_VERSION)['type'] = native.WORKSPACE
    parent = http.get(SCOPE + '/providers/' + native.WORKSPACE, native.WORKSPACE_VERSION)['value'][0]
    if mode == 'wrong_workspace_type': parent['type'] = native.STORAGE
    if mode == 'foreign_workspace': parent['id'] = WORKSPACE.replace(SUB, OTHER)
    if mode == 'workspace_detail_mismatch': http.get(WORKSPACE, native.WORKSPACE_VERSION)['id'] += 'other'
    if mode == 'account_unprovisioned': http.props(ACCOUNT, native.STORAGE_VERSION)['provisioningState'] = 'Updating'
    if mode == 'workspace_unprovisioned': http.props(WORKSPACE, native.WORKSPACE_VERSION)['provisioningState'] = 'Updating'
    path = WORKSPACE + '/linkedStorageAccounts'
    if mode == 'malformed_list': http.get(path, native.LINK_VERSION)['value'] = {}
    if mode == 'denied_links': http.put(path, native.LINK_VERSION, 403)
    if mode == 'denied_storage': http.put(ACCOUNT, native.STORAGE_VERSION, 403)
    if mode == 'denied_workspace': http.put(SCOPE + '/providers/' + native.WORKSPACE, native.WORKSPACE_VERSION, 403)
    if mode in ('partial_links', 'empty_partial_links', 'foreign_page', 'paginated'):
        more = native.ARM + path + '?api-version=' + native.LINK_VERSION + '&$skipToken=next'
        if mode == 'empty_partial_links': http.links().clear()
        if mode == 'foreign_page': more = more.replace('management.azure.com', 'foreign.invalid')
        http.get(path, native.LINK_VERSION)['nextLink'] = more
        http.put(path, native.LINK_VERSION, {'value': []} if mode == 'paginated' else 403, 'next')
    if mode in ('two_accounts', 'mixed'):
        account2 = ACCOUNT + 'two';body = deepcopy(http.get(ACCOUNT, native.STORAGE_VERSION))
        body['id'] = account2;body['name'] += 'two'
        if mode == 'mixed': body['properties']['encryption'] = {'keySource': 'Microsoft.Storage'}
        props['storageAccountIds'].append(account2);http.put(account2, native.STORAGE_VERSION, body)
    if mode == 'two_workspaces_cache':
        workspace2 = WORKSPACE + 'two';body = deepcopy(parent);body['id'] = workspace2;body['name'] += 'two'
        http.get(SCOPE + '/providers/' + native.WORKSPACE, native.WORKSPACE_VERSION)['value'].append(body)
        http.put(workspace2, native.WORKSPACE_VERSION, deepcopy(body))
        row = deepcopy(link);row['id'] = workspace2 + '/linkedStorageAccounts/Query'
        http.put(workspace2 + '/linkedStorageAccounts', native.LINK_VERSION, {'value': [row]})
    if mode == 'oversize': http.put(path, native.LINK_VERSION, b' ' * (native.MAX_BYTES + 1))
    if mode == 'invalid_json': http.put(path, native.LINK_VERSION, b'{broken ' + CANARY.encode())
    if mode == 'opaque_fields':
        for body in http.routes.values():
            if isinstance(body, dict): body['arbitrary'] = {'connectionString': CANARY, 'blob': CANARY}
        key['opaque'] = CANARY


@pytest.mark.parametrize('mode,want', QUERY_CASES, ids=[case[0] for case in QUERY_CASES])
def test_native_query_cmk(monkeypatch, mode, want, record_property):
    http = NativeHTTP();query_mode(http, mode)
    actual, snapshot, findings = capture(monkeypatch, http, native.QUERY_KIND)
    record_property('check_id', consumer.QUERY_CHECK);record_property('actual', ','.join(sorted(actual)))
    assert actual == {want}, findings
    if mode == 'two_workspaces_cache':
        assert sum(row['path'] == ACCOUNT for row in http.calls) == 1
    if mode in ('no_links', 'other_links'):
        assert all(row['path'] != ACCOUNT for row in http.calls)


@pytest.mark.parametrize('kind', native.KINDS)
@pytest.mark.parametrize('field', ['schema', 'scope', 'credential_context_id', 'reads'])
def test_capture_metadata_missing_never_clean(monkeypatch, kind, field):
    _, snapshot, _ = capture(monkeypatch, NativeHTTP(), kind)
    collections = deepcopy(snapshot['collections']);collections[0]['items'][0]['_capture'].pop(field)
    changed = make_snapshot('azure', snapshot['scopes'], collections, metadata=snapshot['metadata'])
    check_id = consumer.NSP_CHECK if kind == native.NSP_KIND else consumer.QUERY_CHECK
    assert {row['status'] for row in evaluate_snapshot(changed, checks=[check_id])['findings']} == {'UNKNOWN'}


@pytest.mark.parametrize('kind', native.KINDS)
@pytest.mark.parametrize('budget', [1, 2])
def test_finite_call_budget_never_clean(monkeypatch, kind, budget):
    http = NativeHTTP()
    actual, _, _ = capture(monkeypatch, http, kind, {'max_calls': budget})
    assert actual == {'UNKNOWN'} and len(http.calls) <= budget


@pytest.mark.parametrize('kind', native.KINDS)
def test_page_loop_and_row_limit(monkeypatch, kind):
    http = NativeHTTP();path = (SCOPE + '/providers/' + native.NSP if kind == native.NSP_KIND else WORKSPACE + '/linkedStorageAccounts')
    version = native.NSP_VERSION if kind == native.NSP_KIND else native.LINK_VERSION
    http.get(path, version)['value'] *= native.MAX_ROWS + 1
    actual, _, _ = capture(monkeypatch, http, kind)
    assert actual == {'UNKNOWN'}


def test_unregistered_assets_have_no_global_effect():
    assert set(c.id for c in checks.CHECKS) >= {consumer.NSP_CHECK, consumer.QUERY_CHECK}  # fixture-only registrations
    assert all(not d['registered'] and d['requirements'] == [] for d in consumer.DECLARATIONS)
    assert all(azure.TYPES.count(kind) == 1 for kind in native.KINDS)  # Distinct accepted production adapter.


@pytest.mark.parametrize('scopes', [[], [OTHER, OTHER], ['not-a-subscription'], ['https://foreign.invalid'], [SUB] * 9])
def test_invalid_or_ambiguous_scopes_rejected_before_transport(scopes):
    with pytest.raises(ValueError):
        native.collect({'provider': 'azure', 'scopes': scopes}, transport=azure.AzureTransport({'method': 'token', 'arm_token': 'INERT_NATIVE_FIXTURE'}))


@pytest.mark.parametrize('kind', native.KINDS)
def test_partial_http_status_cannot_prove_clean(monkeypatch, kind):
    http = NativeHTTP();http.status = 206
    actual, _, _ = capture(monkeypatch, http, kind)
    assert actual == {'UNKNOWN'}


def test_duplicate_native_json_field_cannot_prove_clean(monkeypatch):
    http = NativeHTTP()
    raw = json.dumps(http.get(ACCOUNT, native.STORAGE_VERSION)).replace(
        '"keySource": "Microsoft.Keyvault"', '"keySource": "Microsoft.Storage", "keySource": "Microsoft.Keyvault"')
    http.put(ACCOUNT, native.STORAGE_VERSION, raw.encode())
    actual, _, _ = capture(monkeypatch, http, native.QUERY_KIND)
    assert actual == {'UNKNOWN'}


@pytest.mark.parametrize('kind', native.KINDS)
@pytest.mark.parametrize('mutation', ['foreign_context', 'missing_decisive_read', 'wrong_api', 'wrong_method',
                                    'wrong_parent_path', 'foreign_collection', 'duplicate_collection'])
def test_source_or_collection_contradictions_unresolved(monkeypatch, kind, mutation):
    _, snapshot, _ = capture(monkeypatch, NativeHTTP(), kind)
    collections = deepcopy(snapshot['collections'])
    collection = collections[0];item = collection['items'][0]
    marker = item['_capture'];last = marker['reads'][-1]
    if mutation == 'foreign_context': last['credential_context_id'] = '0' * 32
    if mutation == 'missing_decisive_read': marker['reads'].pop()
    if mutation == 'wrong_api': last['api_version'] = '2099-01-01'
    if mutation == 'wrong_method': last['method'] = 'POST'
    if mutation == 'wrong_parent_path': last['path'] += 'foreign'
    if mutation == 'foreign_collection': collection['scope'] = SCOPE.replace(SUB, OTHER)
    if mutation == 'duplicate_collection': collections.append(deepcopy(collection))
    if mutation == 'duplicate_collection':
        with pytest.raises(ValueError, match='duplicate collection type/scope'):
            make_snapshot('azure', snapshot['scopes'], collections, metadata=snapshot['metadata'])
        return
    changed = make_snapshot('azure', snapshot['scopes'], collections, metadata=snapshot['metadata'])
    check_id = consumer.NSP_CHECK if kind == native.NSP_KIND else consumer.QUERY_CHECK
    assert {row['status'] for row in evaluate_snapshot(changed, checks=[check_id])['findings']} == {'UNKNOWN'}


@pytest.mark.parametrize('kind', native.KINDS)
def test_repeated_continuation_and_page_cap(monkeypatch, kind):
    http = NativeHTTP()
    path = PERIMETER + '/resourceAssociations' if kind == native.NSP_KIND else WORKSPACE + '/linkedStorageAccounts'
    version = native.NSP_VERSION if kind == native.NSP_KIND else native.LINK_VERSION
    more = native.ARM + path + '?api-version=' + version + '&$skipToken=repeat'
    http.get(path, version)['nextLink'] = more
    http.put(path, version, {'value': [], 'nextLink': more}, 'repeat')
    actual, _, _ = capture(monkeypatch, http, kind)
    assert actual == {'UNKNOWN'} and len(http.calls) <= 4


@pytest.mark.parametrize('kind', native.KINDS)
def test_metadata_read_budget_and_privacy_for_both_jobs(monkeypatch, kind):
    http = NativeHTTP();monkeypatch.setattr(azure, 'build_opener', lambda *a: http)
    transport = azure.AzureTransport({'method': 'token', 'arm_token': 'INERT_NATIVE_FIXTURE'})
    snapshot = native.collect({'provider': 'azure', 'scopes': [SUB]}, transport=transport)
    assert snapshot['metadata']['calls'] == len(http.calls)
    assert sum(call['path'] == ACCOUNT for call in http.calls) == 1
    assert CANARY not in json.dumps(snapshot)
    assert all('keyvaulturi' not in json.dumps(item) and 'keyname' not in json.dumps(item)
               for collection in snapshot['collections'] for item in collection['items'])


def test_time_budget_rejects_before_any_http(monkeypatch):
    http = NativeHTTP()
    monkeypatch.setattr(azure.time, 'monotonic', iter([0, 121, 121, 121, 121]).__next__)
    actual, _, _ = capture(monkeypatch, http, native.NSP_KIND)
    assert actual == {'UNKNOWN'} and http.calls == []


@pytest.mark.parametrize('url', ['https://foreign.invalid/path', 'http://management.azure.com/path',
                               'https://user@management.azure.com/path', 'https://management.azure.com/path#fragment'])
def test_metadata_get_rejects_foreign_origin_before_auth(url, monkeypatch):
    transport = azure.AzureTransport({'method': 'token', 'arm_token': 'INERT_NATIVE_FIXTURE'})
    monkeypatch.setattr(transport, 'token', lambda *a: pytest.fail('auth must not be used'))
    with pytest.raises(ValueError): native.metadata_get(transport, url)


@pytest.mark.parametrize('branch', NATIVE_FIXTURES, ids=[row['kind'] + ':' + row['mode'] for row in NATIVE_FIXTURES])
def test_retained_native_fixture_replays_real_reader_and_engine(monkeypatch, branch):
    http = NativeHTTP();http.routes.clear()
    for call in branch['native_http']:
        assert call['method'] == 'GET' and call['host'] == 'management.azure.com'
        assert '_capture' not in json.dumps(call['body'])
        http.put(call['path'], call['api_version'], call['body'] if call['status'] == 200 else call['status'], call['skipToken'])
    actual, _, _ = capture(monkeypatch, http, branch['kind'])
    assert sorted(actual) == branch['expected']


