"""Native ARM -> Blob metadata -> pure frozen key verdict; no cloud transport."""
from copy import deepcopy
import json
from urllib.parse import parse_qs, urlsplit
import pytest
from peaso.collectors import azure, azure_storage_blob_keys_native as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
ACCOUNT = SCOPE + '/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account'
CONTAINER = ACCOUNT + '/blobServices/default/containers/data'
ES = ACCOUNT + '/encryptionScopes/customer'
EP = 'https://account.blob.core.windows.net/'
URI = 'https://vault.vault.azure.net/keys/key/version1'
PRIVATE = 'NEVER_RETAIN_BLOB_CONTENT_METADATA_OR_TAGS'


def fixture(mode):
    account = {'id': ACCOUNT, 'type': 'Microsoft.Storage/storageAccounts', 'etag': 'a1', 'properties': {
        'primaryEndpoints': {'blob': EP}, 'encryption': {'services': {'blob': {'enabled': True, 'keyType': 'Account'}},
        'keySource': 'Microsoft.Keyvault', 'keyvaultproperties': {'keyvaulturi': 'https://vault.vault.azure.net',
        'keyname': 'key', 'keyversion': '', 'currentVersionedKeyIdentifier': URI}}}}
    container = {'id': CONTAINER, 'parent_id': ACCOUNT, 'type': 'Microsoft.Storage/storageAccounts/blobServices/containers', 'etag': 'c1',
        'properties': {'defaultEncryptionScope': 'customer', 'denyEncryptionScopeOverride': True}}
    scope = {'id': ES, 'parent_id': ACCOUNT, 'type': 'Microsoft.Storage/storageAccounts/encryptionScopes', 'etag': 'e1',
        'properties': {'state': 'Enabled', 'source': 'Microsoft.KeyVault',
                       'keyVaultProperties': {'keyUri': URI.rsplit('/', 1)[0], 'currentVersionedKeyIdentifier': URI}}}
    blob = {'identity_sha256': 'a' * 64, 'server_encrypted': True, 'customer_provided_key': False, 'encryption_scope': 'customer'}
    objects = [blob]
    if mode in ('account_ms', 'optional_ms', 'mandatory_ms'):
        account['properties']['encryption']['keySource'] = 'Microsoft.Storage'
        account['properties']['encryption'].pop('keyvaultproperties')
    if mode in ('account_ms', 'optional_ms'):
        container['properties']['denyEncryptionScopeOverride'] = False
    if mode == 'account_ms': blob.pop('encryption_scope')
    if mode == 'mandatory_ms':
        scope['properties']['source'] = 'Microsoft.Storage'; scope['properties'].pop('keyVaultProperties')
    if mode == 'optional_cmk': container['properties']['denyEncryptionScopeOverride'] = False
    if mode == 'cpk': blob['customer_provided_key'] = True
    if mode == 'not_encrypted': blob['server_encrypted'] = False
    if mode == 'unresolved_version': account['properties']['encryption']['keyvaultproperties'].pop('currentVersionedKeyIdentifier')
    if mode == 'scope_version_missing': scope['properties']['keyVaultProperties'].pop('currentVersionedKeyIdentifier')
    if mode == 'scope_foreign_key': scope['properties']['keyVaultProperties']['keyUri'] = URI.replace('/key/', '/other/')
    if mode == 'unknown_scope': blob['encryption_scope'] = 'unknown'
    if mode == 'scope_disabled': scope['properties']['state'] = 'Disabled'
    if mode == 'foreign_endpoint': account['properties']['primaryEndpoints']['blob'] = 'https://evil.blob.core.windows.net/'
    if mode == 'service_key': account['properties']['encryption']['services']['blob']['keyType'] = 'Service'
    if mode == 'missing_default': container['properties'].pop('defaultEncryptionScope')
    if mode == 'foreign_container': container['parent_id'] = ACCOUNT + 'other'
    if mode == 'foreign_scope': scope['parent_id'] = ACCOUNT + 'other'
    if mode == 'duplicate_blob': objects.append(deepcopy(blob))
    if mode == 'malformed_scope': blob['encryption_scope'] = '../customer'
    if mode == 'missing_bool': blob.pop('server_encrypted')
    if mode == 'bool_type': blob['customer_provided_key'] = 0
    if mode == 'empty': objects = []
    containers = [] if mode == 'no_containers' else [container]
    return account, containers, [scope], objects


class Transport:
    def __init__(self, mode):
        self.mode = mode
        self.account, self.containers, self.scopes, self.blobs = fixture(mode)
        self.calls, self.allow, self.parent_catalog = [], [], False
    def allow_storage(self, endpoint, account, service):
        assert (endpoint, account, service) == (EP, 'account', 'blob')
        self.allow.append((endpoint, account, service))
    def request(self, url):
        self.calls.append(url)
        assert urlsplit(url).scheme == 'https' and urlsplit(url).netloc == 'management.azure.com'
        path = urlsplit(url).path
        # Hosted collection also GETs the parent account at the storage account
        # catalog version; every native evidence read (account, container,
        # encryption scope) keeps the native version.
        versions = {native.VERSION}
        if path == ACCOUNT and self.parent_catalog:
            versions.add(azure.ENDPOINTS['storage_account'][1])
        query = parse_qs(urlsplit(url).query)
        assert set(query) == {'api-version'} and len(query['api-version']) == 1 and query['api-version'][0] in versions
        if self.mode == 'denied_arm': raise azure.AzureReadError('fixture_denied', 403)
        row = next((r for r in [self.account, *self.containers, *self.scopes] if r['id'] == path), None)
        assert row is not None, path
        result = deepcopy(row); result['clientSecret'] = PRIVATE
        return result
    def request_blob_inventory(self, url):
        self.calls.append(url)
        parsed = urlsplit(url); query = parse_qs(parsed.query)
        assert parsed.scheme == 'https' and parsed.netloc == 'account.blob.core.windows.net' and parsed.path == '/data'
        assert query['include'] == ['snapshots,versions,deleted,deletedwithversions']
        assert set(query) <= {'restype', 'comp', 'maxresults', 'include', 'marker'}
        assert query['comp'] == ['list'] and query['restype'] == ['container'] and query['maxresults'] == ['500']
        marker = query.get('marker', [''])[0]
        if self.mode == 'denied_blob': raise azure.AzureReadError('fixture_denied', 403)
        if self.mode == 'partial' and marker: raise azure.AzureReadError('fixture_denied', 403)
        blobs = deepcopy(self.blobs)
        next_marker = ''
        if self.mode in ('pages', 'partial', 'cycle'):
            next_marker = 'opaque +/?&marker' if not marker or self.mode == 'cycle' else ''
            if marker and self.mode == 'pages': blobs[0]['identity_sha256'] = 'b' * 64
        value = {'items': blobs, 'next_marker': next_marker, 'marker': marker,
            'service_endpoint': EP, 'container_name': 'data', 'api_version': native.BLOB_VERSION}
        if self.mode == 'wrong_page_binding': value['container_name'] = 'foreign'
        if self.mode == 'wrong_marker': value['marker'] = 'foreign'
        return value


def capture(mode, **options):
    transport = Transport(mode)
    reader = azure._Reader({'concurrency': 1, 'retries': 0, **options})
    reader.collections = [
        {'type': kind, 'scope': SCOPE, 'status': 'collected' if rows else 'empty', 'items': deepcopy(rows)}
        for kind, rows in [('storage_account', [transport.account]), ('storage_container', transport.containers),
                           ('storage_encryption_scope', transport.scopes)]]
    if mode == 'partial_source': reader.collections[2]['status'] = 'partial'
    if mode == 'duplicate_scope': reader.collections[2]['items'].append(deepcopy(transport.scopes[0]))
    native.collect(reader, transport.request, transport, [SCOPE], {native.KIND}, options)
    instant = native.snapshot_instant(reader.collections, {native.KIND})
    snapshot = make_snapshot('azure', [SCOPE], reader.collections, created_at=instant)
    assert PRIVATE not in json.dumps(snapshot)
    return snapshot, transport


@pytest.mark.parametrize('mode,expected', [
    ('cmk','PASS'), ('optional_cmk','PASS'), ('empty','PASS'), ('no_containers','NOT_APPLICABLE'),
    ('account_ms','FAIL'), ('mandatory_ms','FAIL'), ('optional_ms','UNKNOWN'), ('cpk','UNKNOWN'),
    ('not_encrypted','UNKNOWN'), ('unresolved_version','UNKNOWN'), ('scope_version_missing','UNKNOWN'),
    ('scope_foreign_key','UNKNOWN'), ('unknown_scope','UNKNOWN'), ('scope_disabled','UNKNOWN'),
    ('foreign_endpoint','UNKNOWN'), ('service_key','UNKNOWN'), ('missing_default','UNKNOWN'),
    ('foreign_container','UNKNOWN'), ('foreign_scope','UNKNOWN'), ('duplicate_blob','UNKNOWN'),
    ('malformed_scope','UNKNOWN'), ('missing_bool','UNKNOWN'), ('bool_type','UNKNOWN'),
    ('pages','PASS'), ('partial','UNKNOWN'), ('cycle','UNKNOWN'), ('denied_arm','UNKNOWN'),
    ('denied_blob','UNKNOWN'), ('wrong_page_binding','UNKNOWN'), ('wrong_marker','UNKNOWN'),
    ('partial_source','UNKNOWN'), ('duplicate_scope','UNKNOWN')])
def test_native_collect_evaluate(mode, expected):
    snapshot, transport = capture(mode)
    report = evaluate_snapshot(snapshot, checks=[native.CID], include_not_applicable=True)
    assert report['findings'] and all(f['status'] == expected for f in report['findings']), report['findings']
    assert all('/keys/' not in url and '/secrets/' not in url for url in transport.calls)
    env = next(c for c in snapshot['collections'] if c['type'] == native.KIND)
    if expected == 'UNKNOWN' and env['status'] == 'collected':
        assert all(f['evidence'].get('reason') == 'native Blob inventory or effective encryption key binding unresolved' for f in report['findings'])
    for row in env['items']:

        assert row['_provenance']['captured_at'] == snapshot['created_at']
        assert 'policy_approved' not in row['_provenance']
    if mode == 'pages':
        assert len([u for u in transport.calls if urlsplit(u).netloc == 'account.blob.core.windows.net']) == 2
        assert len(env['items'][0]['payload']['containers'][0]['blobs']) == 2


@pytest.mark.parametrize('limits', [{'max_pages': 1}, {'max_resources': 1}, {'max_calls': 3}])
def test_native_enumeration_budgets_never_clean(limits):
    snapshot, _ = capture('pages', **limits)
    report = evaluate_snapshot(snapshot, checks=[native.CID], include_not_applicable=True)
    assert report['findings'] and all(f['status'] == 'UNKNOWN' for f in report['findings'])


@pytest.mark.parametrize('mode,expected', [('cmk', 'PASS'), ('account_ms', 'FAIL'), ('denied_blob', 'UNKNOWN')])
def test_normal_hosted_intake_plan_collect(monkeypatch, mode, expected):
    from peaso.collectors import collect_live
    from peaso.engine import plan_collection
    from peaso.server.validation import validate_connector
    from types import SimpleNamespace
    backend = Transport(mode)
    backend.parent_catalog = True
    class HostedTransport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def __init__(self): self.closed = False
        def close(self): self.closed = True
        allow_storage = staticmethod(backend.allow_storage)
        request_blob_inventory = staticmethod(backend.request_blob_inventory)
        def request_xml(self, url): return {'read': True, 'write': True, 'delete': True}
        def request(self, url, *, body=None, audience=azure.ARM):
            assert audience == azure.ARM
            path = urlsplit(url).path
            if body is not None:
                assert path == '/providers/Microsoft.ResourceGraph/resources'
                return {'data': [], 'resultTruncated': False}
            if path in ('/subscriptions', SCOPE):
                row = {'id': SCOPE, 'subscriptionId': SCOPE.rsplit('/',1)[1], 'tenantId': self.tenant, 'state': 'Enabled'}
                return {'value': [row]} if path == '/subscriptions' else row
            if path == SCOPE + '/providers/Microsoft.Storage/storageAccounts': return {'value': [deepcopy(backend.account)]}
            if path == ACCOUNT + '/blobServices/default/containers': return {'value': deepcopy(backend.containers)}
            if path == ACCOUNT + '/encryptionScopes': return {'value': deepcopy(backend.scopes)}
            if path in (ACCOUNT, CONTAINER, ES): return backend.request(url)
            return {'value': []}
    transport = HostedTransport()
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: transport)
    monkeypatch.setattr(azure, 'AzureTransportExposure', lambda auth: transport)
    auth, options = {'method': 'token', 'arm_token': 'inert-fixture'}, {'concurrency': 1, 'retries': 1}
    validate_connector('azure', auth, options, SimpleNamespace(auth_mode='cognito'))
    connector = {'provider': 'azure', 'scopes': [SCOPE], 'auth': auth, 'options': options}
    required = plan_collection({'connector': connector, 'checks': [native.CID]})
    assert set(required) == {'storage_account', native.KIND}
    snapshot = collect_live(connector, required)
    report = evaluate_snapshot(snapshot, checks=[native.CID], include_not_applicable=True)
    assert report['findings'] and all(f['status'] == expected for f in report['findings']), report['findings']
    assert transport.closed and PRIVATE not in json.dumps(snapshot)
    assert native.KIND in {c['type'] for c in snapshot['collections']}
