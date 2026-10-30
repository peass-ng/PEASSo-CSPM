"""Read-only service dependency fixtures; no primary evaluator or feature pipeline."""
import copy
import json
from urllib.parse import urlsplit, parse_qs

import pytest

from peaso.collectors import azure, azure_sql_ltr_native

NEW_KINDS = tuple('vm_scale_set container_group disk_access databox_edge_device jit_network_access_policy resource_link eventgrid_domain eventgrid_topic eventhub_namespace frontdoor hdinsight_cluster healthcare_fhir_service hpc_cache iot_hub managed_hsm network_watcher bastion_host log_analytics_workspace logic_app_workflow ml_workspace mssql_managed_instance mysql_flexible_server postgresql_flexible_server recovery_vault policy_assignment security_assessment iot_security_solution servicebus_namespace service_fabric_cluster signalr_service spring_cloud_service storage_sync_service stream_analytics_job synapse_workspace web_application_firewall_policy'.split())
SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'


class ServiceAPI:
    tenant = 'tenant'
    verified_tenant = 'tenant'
    def __init__(self, kind, mode='pass'):
        self.kind, self.mode, self.calls = kind, mode, []
        self.endpoint, self.version = azure.ENDPOINTS[kind]
        self.rid = SUB + '/resourceGroups/group/providers/' + self.endpoint + '/resource'
        self.native_type = self.endpoint
        if kind == 'jit_network_access_policy':
            # Official JIT DTO identity/type includes the location segment;
            # the subscription-wide list URL itself intentionally does not.
            self.native_type = 'Microsoft.Security/locations/jitNetworkAccessPolicies'
            self.rid = SUB + '/resourceGroups/group/providers/Microsoft.Security/locations/eastus/jitNetworkAccessPolicies/resource'
        self.root = SUB + '/providers/' + self.endpoint
    def request(self, url, body=None, audience=azure.ARM):
        self.calls.append((url, body, audience))
        path = urlsplit(url).path
        if body:
            assert '/Microsoft.ResourceGraph/' in path
            return {'data': []}
        if path == SUB + '/resources':
            # Authoritative ARM resource index: only this service's tracked type exists.
            return {'value': [{'id': self.rid, 'type': self.native_type}]}
        if path == self.root:
            assert parse_qs(urlsplit(url).query)['api-version'] == [self.version]
            if self.mode == 'denied': raise azure.AzureReadError('403', 403)
            if self.mode == 'malformed': return {'value': 'invalid-list'}
            if self.mode == 'empty': return {'value': []}
            suffix = 'other' if '$skiptoken' in url else self.rid.rsplit('/', 1)[-1]
            rid = self.rid.rsplit('/', 1)[0] + '/' + suffix
            if self.mode == 'foreign': rid = rid.replace(SUB + '/', '/subscriptions/33333333-3333-3333-3333-333333333333/')
            value = {'id': rid, 'name': suffix, 'type': self.native_type, 'sku': {'name': 'Premium', 'tier': 'Premium'}, 'properties': {'publicNetworkAccess': 'Disabled', 'enablePurgeProtection': True}}
            reply = {'value': [value]}
            if self.mode == 'pagination' and suffix == 'resource': reply['nextLink'] = url + '&$skiptoken=page2'
            return reply
        if self.kind == 'container_group' and path.rsplit('/', 1)[0] == self.rid.rsplit('/', 1)[0]:
            return {'id': path, 'type': self.native_type, 'properties': {'containers': [{'properties': {'environmentVariables': [{'name': 'CONFIG', 'value': 'INERT_VALUE'}, {'name': 'PASSWORD', 'secureValue': 'INERT_SECRET'}]}}], 'encryptionProperties': {'keyName': 'metadata-key'}}}
        if path.rsplit('/', 1)[0] == self.rid.rsplit('/', 1)[0] and path.rsplit('/', 1)[-1] in ('resource', 'other'):
            return {'id': path, 'name': path.rsplit('/', 1)[-1], 'type': self.native_type, 'sku': {'name': 'Premium', 'tier': 'Premium'}, 'properties': {'publicNetworkAccess': 'Disabled', 'enablePurgeProtection': True}}
        if path.endswith(('/networkRuleSets/default', '/vulnerabilityAssessments/default', '/sqlVulnerabilityAssessments/default', '/encryptionProtector/current')):
            return {'id': path, 'properties': {'state': 'Enabled', 'defaultAction': 'Deny', 'publicNetworkAccess': 'Disabled'}}
        return {'value': []}


@pytest.mark.parametrize('kind', NEW_KINDS)
@pytest.mark.parametrize('mode,expected', [('pass', 'collected'), ('empty', 'empty'), ('denied', 'denied'), ('malformed', 'malformed'), ('foreign', 'malformed'), ('pagination', 'collected')])
def test_documented_new_service_authoritative_list_scope_pagination_and_denial(kind, mode, expected):
    api = ServiceAPI(kind, mode)
    snapshot = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, [kind], transport=api)
    row = next(c for c in snapshot['collections'] if c['type'] == kind)
    assert row['status'] == expected
    if mode == 'pagination': assert len(row['items']) == 2
    assert all(body is None or '/Microsoft.ResourceGraph/' in url for url, body, audience in api.calls)
    assert 'INERT_VALUE' not in json.dumps(snapshot) and 'INERT_SECRET' not in json.dumps(snapshot)
    if mode == 'pass' and kind == 'container_group':
        assert row['items'][0]['properties']['encryptionProperties']['keyName'] == 'metadata-key'
        variables = row['items'][0]['properties']['containers'][0]['properties']['environmentVariables']
        assert variables[0]['value'] == '[REDACTED]' and variables[1]['secureValue'] == '[REDACTED]'
    if mode == 'pass' and kind in azure.NO_DIAGNOSTIC_KINDS:
        # Proxy/extension kinds reject Microsoft.Insights/diagnosticSettings; none is requested.
        assert 'diagnosticSettings' not in row['items'][0]
        assert not any('/diagnosticSettings' in url for url, body, audience in api.calls)
    elif mode == 'pass': assert isinstance(row['items'][0]['diagnosticSettings'], list)


EMBEDS = [(kind, field, path, version, True) for kind, specs in azure.EMBEDDED_LISTS.items() for field, path, version in specs]
EMBEDS += [(kind, field, path, version, False) for kind, specs in azure.EMBEDDED_SINGLETONS.items() for field, path, version in specs]


@pytest.mark.parametrize('kind,field,path,version,is_list', EMBEDS)
@pytest.mark.parametrize('mode', ['pass', 'empty', 'denied', 'malformed', 'partial'])
def test_embedded_children_have_native_values_and_explicit_unavailable_coverage(kind, field, path, version, is_list, mode):
    endpoint, _ = azure.ENDPOINTS.get(kind, ('Microsoft.Sql/servers/server/databases', '2023-08-01'))
    rid = SUB + '/resourceGroups/group/providers/' + endpoint + '/parent'
    parent = {'id': rid, 'name': 'parent', 'type': endpoint, 'sku': {'name': 'Premium'}, 'properties': {}}
    if field == 'longTermRetentionBackups': parent['location'] = 'eastus'
    # Storage perimeter associations are read only for perimeter-secured accounts.
    if field == 'networkSecurityPerimeterConfigurations': parent['properties']['publicNetworkAccess'] = 'SecuredByPerimeter'
    native_path = azure_sql_ltr_native.binding(parent)[0] if field == 'longTermRetentionBackups' else rid + '/' + path
    reader = azure._Reader({'retries': 0})
    def request(url, body=None, audience=azure.ARM):
        parsed = urlsplit(url)
        if parsed.path != native_path: return {'value': []}
        assert parse_qs(parsed.query)['api-version'] == [version]
        if field == 'longTermRetentionBackups': assert parse_qs(parsed.query)['databaseState'] == ['Live']
        if mode == 'denied' or mode == 'partial' and 'page=2' in url: raise azure.AzureReadError('403', 403)
        if mode == 'malformed': return {'value': [None]} if is_list else None
        if is_list:
            if mode == 'empty': return {'value': []}
            child_name = ('require_secure_transport' if field == 'configurations' else
                          'default' if field in ('workspaceVulnerabilityAssessments', 'azureADOnlyAuthentications') else
                          'ActiveDirectory' if field in ('serverAdministrators', 'instanceAdministrators') else 'child')
            native_type = {'resources': 'Microsoft.Compute/virtualMachines/extensions',
                           'flowLogs': 'Microsoft.Network/networkWatchers/flowLogs',
                           'extensions': 'Microsoft.KubernetesConfiguration/extensions',
                           'eventSubscriptions': 'Microsoft.EventGrid/eventSubscriptions',
                           'vulnerabilityAssessmentScans': 'Microsoft.Sql/servers/databases/vulnerabilityAssessments/scans'}.get(field, endpoint + '/' + path)
            value = {'id': rid + '/' + path + '/' + child_name, 'name': child_name, 'type': native_type,
                     'properties': {'value': 'ON', 'publisher': 'Microsoft.GuestConfiguration', 'type': 'ConfigurationForLinux', 'settings': {'password': 'INERT_PRIVATE'}}}
            # Children with field-specific native contracts carry their deciding properties.
            if field == 'httpRouteConfigs':
                value['properties'].update(fqdn='route.example.test', rules=[{'targets': [{'containerApp': 'app'}]}])
            if field == 'authorizationRules': value['properties']['rights'] = ['Listen']
            if field == 'azureADOnlyAuthentications': value['properties']['azureADOnlyAuthentication'] = True
            if field == 'streamOutputs':
                value['properties']['datasource'] = {'type': 'Microsoft.Storage/Blob', 'properties': {'storageAccounts': [{'accountName': 'account'}]}}
            if field in ('vmssNetworkInterfaces', 'vmssPublicIPAddresses'):
                value['id'] = rid + '/virtualMachines/0/networkInterfaces/nic' + ('/ipConfigurations/ip/publicIPAddresses/pip' if field == 'vmssPublicIPAddresses' else '')
            if field == 'longTermRetentionBackups':
                value = {'id': native_path + '/child', 'type': azure_sql_ltr_native.NATIVE_TYPE,
                         'properties': {'serverName': 'server', 'databaseName': 'parent',
                                        'databaseDeletionTime': None, 'backupStorageRedundancy': 'Geo'}}
            result = {'value': [value]}
            if mode == 'partial': result['nextLink'] = url + '&page=2'
            return result
        native_type = {'vulnerabilityAssessment': 'Microsoft.Sql/servers/vulnerabilityAssessments',
                       'expressVulnerabilityAssessment': 'Microsoft.Sql/servers/sqlVulnerabilityAssessments',
                       'encryptionProtector': 'Microsoft.Sql/servers/encryptionProtector'}.get(field, endpoint + '/' + path.rsplit('/', 1)[0])
        return {'id': rid + '/' + path, 'name': path.rsplit('/', 1)[-1], 'type': native_type,
                'properties': {'state': 'Enabled'}}
    azure._embed(reader, request, [(kind, parent)])
    coverage = parent['_coverage'][field]['status']
    expected = 'partial' if mode == 'partial' and is_list else 'collected' if mode in ('pass', 'partial') or mode == 'empty' and not is_list else mode
    # Every SQL server/managed instance has exactly one native authentication-mode row.
    if field == 'azureADOnlyAuthentications' and mode == 'empty': expected = 'malformed'
    assert coverage == expected
    if expected in ('denied', 'malformed'): assert field not in parent
    elif mode == 'empty' and is_list: assert parent[field] == []
    if mode == 'pass' and field == 'resources': assert 'settings' not in parent[field][0]['properties']
    if mode == 'pass' and field == 'configurations': assert parent[field][0]['properties']['value'] == 'ON'
    assert 'INERT_PRIVATE' not in json.dumps(parent)


def test_graph_policy_fields_credential_metadata_and_verified_tenant_provenance():
    calls = []
    class Directory:
        tenant = verified_tenant = TENANT
        def request(self, url, body=None, audience=azure.ARM):
            calls.append(url)
            if audience == azure.ARM:
                assert urlsplit(url).path == SUB and body is None
                assert parse_qs(urlsplit(url).query) == {'api-version': ['2022-12-01']}
                return {'id': SUB, 'subscriptionId': SUB.rsplit('/', 1)[-1], 'tenantId': TENANT}
            assert audience == azure.GRAPH
            if 'authenticationMethodsPolicy' in url: return {'id': 'authenticationMethodsPolicy', 'registrationEnforcement': {'authenticationMethodsRegistrationCampaign': {'state': 'enabled'}}}
            if '/applications?' in url:
                assert 'passwordCredentials,keyCredentials' in url
                return {'value': [{'id': 'app', 'passwordCredentials': [{'keyId': 'key', 'endDateTime': '2026-10-10T00:00:00Z', 'secretText': 'INERT_PRIVATE'}], 'keyCredentials': [{'keyId': 'cert', 'endDateTime': '2027-01-01T00:00:00Z', 'key': 'INERT_CERT'}]}]}
            if '/users?' in url:
                assert 'signInActivity' in url
                return {'value': [{'id': 'user', 'signInActivity': {'lastSignInDateTime': '2026-10-10T00:00:00Z'}}]}
            return {'value': [{'id': '33333333-3333-3333-3333-333333333333',
                               '@odata.type': '#microsoft.graph.ipNamedLocation',
                               'state': 'enabled', 'isMfaCapable': True, 'isTrusted': True}]}
    kinds = ['conditional_access_policy', 'named_location', 'user_registration_detail', 'authentication_methods_policy', 'directory_setting', 'directory_user', 'directory_application']
    snapshot = azure.collect({'scopes': [SUB]}, kinds, transport=Directory())
    assert all(row['status'] == 'collected' for row in snapshot['collections'])
    assert snapshot['metadata']['tenant_verified'] is True
    assert 'INERT_PRIVATE' not in json.dumps(snapshot) and 'INERT_CERT' not in json.dumps(snapshot)
    app = next(c for c in snapshot['collections'] if c['type'] == 'directory_application')['items'][0]
    assert app['passwordCredentials'] == [{'keyId': 'key', 'endDateTime': '2026-10-10T00:00:00Z'}]
    assert app['_provenance']['tenant_id'] == TENANT and app['_provenance']['tenant_verified']


def test_subscription_backup_inventory_is_incomplete_when_one_vault_denies_child_read():
    class Backup:
        tenant = verified_tenant = 'tenant'
        def request(self, url, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            if body: return {'data': []}
            base = SUB + '/resourceGroups/group/providers/Microsoft.RecoveryServices/vaults/'
            if path == SUB + '/providers/Microsoft.RecoveryServices/vaults':
                return {'value': [{'id': base + name, 'name': name, 'type': 'Microsoft.RecoveryServices/vaults', 'properties': {}} for name in ('a', 'b')]}
            if path in (base + 'a', base + 'b'):
                return {'id': path, 'name': path.rsplit('/', 1)[-1],
                        'type': 'Microsoft.RecoveryServices/vaults', 'properties': {}}
            if path.endswith('/backupProtectedItems'):
                if '/vaults/b/' in path: raise azure.AzureReadError('403', 403)
                return {'value': [{'id': path + '/item', 'properties': {'sourceResourceId': SUB + '/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/vm', 'protectionState': 'Protected'}}]}
            return {'value': []}
    snapshot = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, ['backup_protected_item'], transport=Backup())
    row = next(c for c in snapshot['collections'] if c['type'] == 'backup_protected_item')
    assert row['scope'] == SUB and row['status'] == 'partial' and len(row['items']) == 1
    assert row['items'][0]['parent_id'].endswith('/vaults/a')
    vault = next(c for c in snapshot['collections'] if c['type'] == 'recovery_vault')['items'][1]
    assert 'backupProtectedItems' not in vault
    assert vault['_coverage']['backupProtectedItems']['status'] == 'denied'


def test_storage_analytics_oauth_metadata_and_service_diagnostics_never_request_keys():
    class Storage(ServiceAPI):
        def __init__(self):
            super().__init__('storage_account'); self.allowed = []
        def request(self, url, body=None, audience=azure.ARM):
            response = super().request(url, body, audience)
            if urlsplit(url).path in (self.root, self.rid):
                item = response['value'][0] if 'value' in response else response
                item['properties']['primaryEndpoints'] = {kind: 'https://resource.' + kind + '.core.windows.net/' for kind in ('blob', 'queue', 'table')}
            return response
        def allow_storage(self, uri, account, service): self.allowed.append((uri, account, service))
        def request_xml(self, url):
            self.calls.append((url, None, azure.STORAGE))
            return {'read': True, 'write': False, 'delete': True}
    api = Storage()
    snapshot = azure.collect({'scopes': [SUB]}, ['storage_account'], transport=api)
    item = next(c for c in snapshot['collections'] if c['type'] == 'storage_account')['items'][0]
    assert item['serviceAnalyticsLogging']['blob'] == {'read': True, 'write': False, 'delete': True}
    assert item['serviceDiagnosticSettings']['blob'] == []
    assert len(api.allowed) == 3
    assert all('listkeys' not in url.lower() and 'sharedkeys' not in url.lower() for url, body, audience in api.calls)


def test_certificate_policy_list_and_policy_get_exclude_all_private_material():
    class Certificates(ServiceAPI):
        def __init__(self): super().__init__('vault')
        def request(self, url, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            if urlsplit(url).netloc == 'vault.vault.azure.net':
                assert audience == azure.VAULT
                if path == '/certificates': return {'value': [{'id': 'https://vault.vault.azure.net/certificates/cert', 'cer': 'INERT_PUBLIC_CERT'}]}
                assert path == '/certificates/cert/policy'
                return {'x509_props': {'validity_months': 12}, 'secret_props': {'contentType': 'application/x-pkcs12'}, 'private_key': 'INERT_PRIVATE'}
            response = super().request(url, body, audience)
            if path == self.root: response['value'][0]['properties']['vaultUri'] = 'https://vault.vault.azure.net/'
            return response
    api = Certificates()
    snapshot = azure.collect({'scopes': [SUB]}, ['key_vault_certificate_policy'], transport=api)
    row = next(c for c in snapshot['collections'] if c['type'] == 'key_vault_certificate_policy')
    assert row['status'] == 'collected'
    assert row['items'][0]['x509_props'] == {'validity_months': 12}
    assert 'INERT_PRIVATE' not in json.dumps(snapshot) and 'INERT_PUBLIC_CERT' not in json.dumps(snapshot)
    assert '/certificates/' in row['items'][0]['id'] and row['items'][0]['parent_id'] == api.rid


def test_diagnostic_request_is_coalesced_when_requested_as_collection_and_parent_embed():
    api = ServiceAPI('vault')
    snapshot = azure.collect({'scopes': [SUB]}, ['vault', 'diagnostic_setting'], transport=api)
    target = api.rid + '/providers/Microsoft.Insights/diagnosticSettings'
    assert sum(urlsplit(url).path == target for url, body, audience in api.calls) == 1
    vault = next(c for c in snapshot['collections'] if c['type'] == 'vault')['items'][0]
    assert vault['diagnosticSettings'] == []


def test_signin_access_denied_preserves_basic_users_and_denied_field_coverage():
    class Users:
        tenant = verified_tenant = 'tenant'
        def request(self, url, body=None, audience=azure.ARM):
            assert audience == azure.GRAPH
            if 'signInActivity' in url: raise azure.AzureReadError('403', 403)
            return {'value': [{'id': 'user', 'accountEnabled': False, 'userType': 'Member'}]}
    snapshot = azure.collect({'scopes': [SUB]}, ['directory_user'], transport=Users())
    users = snapshot['collections'][0]
    assert users['status'] == 'collected' and users['items'][0]['accountEnabled'] is False
    assert users['items'][0]['_coverage']['signInActivity']['status'] == 'denied'
    assert snapshot['metadata']['directory_coverage']['status'] == 'incomplete'


def test_xml_properties_requires_date_pinned_https_origin_and_parses_only_booleans(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return b'<StorageServiceProperties><Logging><Read>true</Read><Write>false</Write><Delete>true</Delete></Logging></StorageServiceProperties>'
    class Opener:
        def open(self, request, timeout):
            assert request.get_method() == 'GET'
            assert request.get_header('X-ms-version') == '2023-11-03'
            assert request.get_header('X-ms-date').endswith(' GMT')
            assert request.data is None
            return Response()
    monkeypatch.setattr(azure, 'build_opener', lambda *args: Opener())
    transport = azure.AzureTransport({'method': 'token', 'storage_token': 'inert-storage-token'})
    transport.allow_storage('https://account.blob.core.windows.net/', 'account', 'blob')
    assert transport.request_xml('https://account.blob.core.windows.net/?restype=service&comp=properties') == {'read': True, 'write': False, 'delete': True}
    for url in ('https://foreign.blob.core.windows.net/?restype=service&comp=properties', 'https://account.blob.core.windows.net/?comp=list', 'https://account.blob.core.windows.net/object?restype=service&comp=properties'):
        with pytest.raises(azure.AzureReadError): transport.request_xml(url)


def test_valid_default_https_port_continuation_does_not_allow_host_or_path_changes():
    reader = azure._Reader({})
    calls = []
    def request(url, **kwargs):
        calls.append(url)
        return {'value': [{'id': '/resource'}], 'nextLink': 'https://vault.vault.azure.net:443/keys?page=2'} if len(calls) == 1 else {'value': []}
    assert list(reader.pages(request, 'https://vault.vault.azure.net/keys', audience=azure.VAULT)) == [[{'id': '/resource'}], []]
    def foreign(url, **kwargs): return {'value': [], 'nextLink': 'https://foreign.vault.azure.net:443/keys?page=2'}
    with pytest.raises(azure.AzureReadError): list(azure._Reader({}).pages(foreign, 'https://vault.vault.azure.net/keys', audience=azure.VAULT))


@pytest.mark.parametrize('mode,expected', [('empty', 'empty'), ('denied', 'denied'), ('malformed', 'malformed')])
def test_absent_key_parent_produces_explicit_real_child_coverage(mode, expected):
    api = ServiceAPI('vault', mode)
    snapshot = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, ['key_vault_key', 'key_vault_certificate_policy'], transport=api)
    for kind in ('key_vault_key', 'key_vault_certificate_policy', 'key_metadata', 'key_rotation_policy'):
        row = next(c for c in snapshot['collections'] if c['type'] == kind)
        assert row['status'] == expected and row['items'] == []
        if mode != 'empty': assert row['error']['code'] == 'parent_inventory_unavailable'


def test_staged_canonical_reference_conversion_conserves_real_counts_and_resolves_exact_paths():
    from peaso.checks.facts import resolve_embedded_fact, Unavailable
    vault_id = SUB + '/resourceGroups/group/providers/Microsoft.KeyVault/vaults/vault'
    key_id = vault_id + '/keys/key'
    diagnostic = {'id': vault_id + '/providers/Microsoft.Insights/diagnosticSettings/diag', 'properties': {'logs': [{'categoryGroup': 'audit', 'enabled': True}]}}
    key = {'id': key_id, 'parent_id': vault_id, 'properties': {'attributes': {'enabled': True, 'exp': 2000000000}}}
    policy = {'id': key_id + '/rotationpolicy', 'parent_id': key_id, 'properties': {'lifetimeActions': [{'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P90D'}}]}}
    vault = {'id': vault_id, 'properties': {}, 'diagnosticSettings': [diagnostic], '_coverage': {'diagnosticSettings': {'status': 'collected'}}}
    def envelope(kind, scope, rows): return {'type': kind, 'scope': scope, 'status': 'collected', 'items': rows}
    collections = [envelope('vault', SUB, [vault]), envelope('key_metadata', vault_id, [key]), envelope('key_vault_key', vault_id, [key]), envelope('key_rotation_policy', key_id, [policy]), envelope('diagnostic_setting', vault_id, [diagnostic])]
    azure._canonicalize_embedded(collections)
    assert vault['keyVaultKeys'] == [key]
    assert vault['diagnosticSettings'] == [diagnostic]
    parents = [{'native_id': vault_id, 'type': 'vault', 'provider': 'azure', 'data': vault}, {'native_id': key_id, 'type': 'key_metadata', 'provider': 'azure', 'data': key}]
    for collection in collections[1:]:
        assert collection['observed_count'] == 1 and len(collection['items']) == 1
        assert collection['metadata']['schema'] == 'embedded_refs_v1'
        ref = collection['items'][0]
        assert '_embedded_ref' in ref and 'properties' not in ref
        resolved = resolve_embedded_fact(ref, parents, child_status=collection['status'])
        identity = resolved.get('id') or resolved.get('_provenance', {}).get('native_id')
        assert identity == ref['id']
        with pytest.raises(Unavailable): resolve_embedded_fact(ref, parents, child_status='partial')
    diag_ref = collections[-1]['items'][0]
    vault['_coverage']['diagnosticSettings']['status'] = 'denied'
    with pytest.raises(Unavailable): resolve_embedded_fact(diag_ref, parents)
    assert collections[3]['items'][0]['_embedded_ref']['index'] is None


def test_same_tenant_directory_binding_is_scoped_to_one_generated_capture_context():
    from peaso.checks.facts import azure_directory_join_authorized
    class TenantAPI:
        tenant = verified_tenant = 'tenant'
        def request(self, url, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            if path == SUB: return {'id': SUB, 'tenantId': 'tenant'}
            if body: return {'data': []}
            if audience == azure.GRAPH: return {'value': [{'id': 'user', 'accountEnabled': True}]}
            return {'value': []}
    snapshots = [azure.collect({'scopes': [SUB], 'options': {'customer_context_id': 'untrusted-supplied-marker'}}, ['role_assignment', 'directory_user'], transport=TenantAPI()) for _ in range(2)]
    first, second = snapshots
    users = next(c for c in first['collections'] if c['type'] == 'directory_user')
    assert first['metadata']['credential_context_id'] != second['metadata']['credential_context_id']
    assert first['metadata']['customer_context_id'] != 'untrusted-supplied-marker'
    assert azure_directory_join_authorized(SUB, first['metadata'], users)
    assert not azure_directory_join_authorized(SUB, second['metadata'], users)
    wrong = copy.deepcopy(first['metadata']); wrong['subscription_tenants'][SUB] = 'foreign'
    assert not azure_directory_join_authorized(SUB, wrong, users)


@pytest.mark.parametrize('mode', ['pass', 'denied'])
def test_azure_progress_reports_cumulative_settled_metadata_without_auth_or_resource_payload(mode):
    events = []
    connector = {'scopes': [SUB], 'auth': {'unused_secret': 'INERT_SECRET'}, 'options': {'_progress_callback': events.append, 'retries': 0, '_content_secret_scan_kinds': []}}
    before = copy.copy(connector['options'])
    snapshot = azure.collect(connector, ['eventhub_namespace'], transport=ServiceAPI('eventhub_namespace', mode))
    assert connector['options'] == before
    assert events[0]['phase'] == 'discovering' and events[-1]['phase'] == 'completed'
    assert [event['completed'] for event in events] == sorted(event['completed'] for event in events)
    assert events[-1]['completed'] > 0
    assert all(set(event) == {'phase', 'provider', 'scope', 'completed', 'total', 'resources', 'dynamic_total'} for event in events)
    assert all(event['provider'] == 'azure' and event['scope'] in ('', SUB) for event in events)
    assert 'INERT_SECRET' not in json.dumps(events) and '/resourceGroups/' not in json.dumps(events)
    assert '_progress_callback' not in json.dumps(snapshot)
    assert all(event['total'] is None and event['dynamic_total'] is True for event in events)


def test_progress_callback_failure_does_not_change_coverage_and_shared_reader_stays_provider_neutral():
    def callback(event): raise RuntimeError('inert callback failure')
    snapshot = azure.collect({'scopes': [SUB], 'options': {'_progress_callback': callback}}, ['eventhub_namespace'], transport=ServiceAPI('eventhub_namespace'))
    assert next(c for c in snapshot['collections'] if c['type'] == 'eventhub_namespace')['status'] == 'collected'
    reader = azure._Reader({'_progress_callback': callback})
    assert reader.progress_provider is None


def test_nested_arm_credentials_and_named_secret_parameters_are_not_snapshot_facts():
    value = {'properties': {'storageAccountKey': 'INERT_PRIVATE', 'sasUrl': 'INERT_SAS', 'settings': {'commandToExecute': 'INERT_COMMAND'}, 'fabricSettings': [{'parameters': [{'name': 'ClusterCredentialType', 'value': 'X509'}, {'name': 'SharedAccessKey', 'value': 'INERT_SHARED'}]}]}}
    safe = azure._metadata_only(value)
    assert 'INERT_' not in json.dumps(safe)
    params = safe['properties']['fabricSettings'][0]['parameters']
    assert params[0]['value'] == 'X509' and params[1]['value'] == '[REDACTED]'


@pytest.mark.parametrize('mode,expected', [('pass', 'collected'), ('empty', 'empty'), ('denied', 'denied'), ('foreign', 'malformed')])
def test_real_secret_list_metadata_shape_no_individual_get_or_values(mode, expected):
    class Secrets(ServiceAPI):
        def __init__(self):
            super().__init__('vault')
            self.rid = self.rid.rsplit('/', 1)[0] + '/vault'
        def request(self, url, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            if urlsplit(url).netloc.startswith('vault.vault.azure.net'):
                assert path == '/secrets' and audience == azure.VAULT
                if mode == 'denied': raise azure.AzureReadError('403', 403)
                if mode == 'empty': return {'value': []}
                host = 'foreign' if mode == 'foreign' else 'vault'
                return {'value': [{'id': 'https://' + host + '.vault.azure.net/secrets/name', 'attributes': {'enabled': True, 'exp': 2000000000}, 'value': 'INERT_PRIVATE'}]}
            reply = super().request(url, body, audience)
            if path == self.root:
                reply['value'][0]['properties'].update(vaultUri='https://vault.vault.azure.net/', enableRbacAuthorization=True)
            return reply
    api = Secrets()
    snapshot = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, ['secret_metadata'], transport=api)
    row = next(c for c in snapshot['collections'] if c['type'] == 'secret_metadata')
    assert row['status'] == expected
    assert 'INERT_PRIVATE' not in json.dumps(snapshot)
    assert all('/secrets/' not in url and '/backup' not in url for url, body, audience in api.calls)
    if mode == 'pass':
        assert row['items'][0]['id'] == api.rid + '/secrets/name'
        assert row['items'][0]['vaultProperties']['enableRbacAuthorization'] is True
        assert row['items'][0]['properties']['attributes']['exp'] == 2000000000
