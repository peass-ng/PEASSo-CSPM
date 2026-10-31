"""Native ARM child reads, safe metadata and complete failure boundaries."""
import copy
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qs
import pytest
from peaso.collectors import azure
from tests.archived_check_contract import evaluate_snapshot

SUB = '11111111-1111-1111-1111-111111111111'
SCOPE = '/subscriptions/' + SUB
BASE = SCOPE + '/resourceGroups/rg/providers/'
SQL = BASE + 'Microsoft.Sql/servers/server/databases/db'
STORAGE = BASE + 'Microsoft.Storage/storageAccounts/account'
ARC = BASE + 'Microsoft.Kubernetes/connectedClusters/cluster'
ISE = BASE + 'Microsoft.Logic/integrationServiceEnvironments/environment'
ARC_CHECK = 'azure.gap.arc_kubernetes_cluster_azure_defender_extension_installed'
ISE_CHECK = 'azure.gap.logic_app_integration_service_environment_encrypted_with_cmk'
PITR = 'azure_recovery_vault_10_3_3_1_1f42f66'
RETENTION = 'azure_recovery_vault_10_3_3_8_26e08d7'

class Transport:
    tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
    def __init__(self, routes):
        self.routes = routes
        self.calls = []
    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append(url)
        value = self.routes.get(urlsplit(url).path, {'value': []})
        if callable(value): value = value(parse_qs(urlsplit(url).query))
        if isinstance(value, Exception): raise value
        return copy.deepcopy(value)

def parent(rid, kind, properties):
    return {'id': rid, 'name': rid.rsplit('/', 1)[-1], 'type': kind, 'properties': properties}

def routes(kind, rid, properties):
    endpoint = azure.ENDPOINTS[kind][0]
    value = parent(rid, endpoint, properties)
    return {SCOPE + '/providers/' + endpoint: {'value': [value]}, rid: value}

def collect(kinds, api, **options):
    return azure.collect({'scopes': [SUB], 'options': {'retries': 0, **options}}, kinds, transport=api)

def envelope(snapshot, kind):
    return next(c for c in snapshot['collections'] if c['type'] == kind and c['scope'] == SCOPE)


@pytest.mark.parametrize('present', [False, True])
@pytest.mark.parametrize('diagnostics', [False, True])
def test_container_app_job_and_environment_have_one_native_owner_per_scope(present, diagnostics):
    job = BASE + 'Microsoft.App/jobs/job'
    environment = BASE + 'Microsoft.App/managedEnvironments/environment'
    native = {
        SCOPE + '/providers/Microsoft.App/jobs': {'value': [parent(job, 'Microsoft.App/jobs', {})] if present else []},
        SCOPE + '/providers/Microsoft.App/managedEnvironments': {'value': [parent(environment, 'Microsoft.App/managedEnvironments', {})] if present else []},
        job: parent(job, 'Microsoft.App/jobs', {'provisioningState': 'Succeeded', 'environmentId': environment}),
        environment: parent(environment, 'Microsoft.App/managedEnvironments', {'provisioningState': 'Succeeded'}),
    }
    api = Transport(native)
    kinds = ['container_app_job', 'container_app_environment']
    result = collect(kinds + (['diagnostic_setting'] if diagnostics else []), api)
    for kind, resource_id in (('container_app_job', job), ('container_app_environment', environment)):
        rows = [row for row in result['collections'] if row['type'] == kind and row['scope'] == SCOPE]
        assert len(rows) == 1
        assert rows[0]['status'] == ('collected' if present else 'empty')
        if present:
            assert rows[0]['items'][0]['id'] == resource_id
            assert rows[0]['items'][0]['_provenance']['method'] == 'LIST+GET'
        assert sum(urlsplit(url).path == resource_id for url in api.calls) == int(present)
        assert sum(urlsplit(url).path == SCOPE + '/providers/' + azure.ENDPOINTS[kind][0]
                   for url in api.calls) == 1


def test_diagnostics_keep_implicit_container_app_parent_discovery():
    api = Transport({SCOPE + '/resources': {'value': [
        parent(BASE + 'Microsoft.App/jobs/job', 'Microsoft.App/jobs', {}),
        parent(BASE + 'Microsoft.App/managedEnvironments/environment', 'Microsoft.App/managedEnvironments', {}),
    ]}})
    result = collect(['diagnostic_setting'], api)
    for kind in ('container_app_job', 'container_app_environment'):
        assert any(row['type'] == kind and row['scope'] == SCOPE for row in result['collections'])
        assert any(urlsplit(url).path == SCOPE + '/providers/' + azure.ENDPOINTS[kind][0]
                   for url in api.calls)

def verdict(snapshot, check):
    return evaluate_snapshot(snapshot, checks=[check], include_not_applicable=True)['findings'][0]['status']

def fixture(kind):
    if kind == 'storage_local_user':
        r = routes('storage_account', STORAGE, {'isSftpEnabled': True, 'isLocalUserEnabled': True})
        path = STORAGE + '/localUsers'
        rows = [parent(path + '/alice', 'Microsoft.Storage/storageAccounts/localUsers', {
            'permissionScopes': [{'permissions': 'rl', 'service': 'blob', 'resourceName': 'qa', 'secret': 'sensitive-marker'}],
            'homeDirectory': 'qa', 'hasSshPassword': True, 'hasSshKey': True,
            'allowAclAuthorization': False, 'sid': 'sid-alice',
            'sshAuthorizedKeys': [{'key': 'sensitive-marker'}], 'sshPassword': 'sensitive-marker'})]
    elif kind == 'arc_kubernetes_cluster':
        r = routes(kind, ARC, {'provisioningState': 'Succeeded'})
        path = ARC + '/providers/Microsoft.KubernetesConfiguration/extensions'
        rows = [parent(path + '/defender', 'Microsoft.KubernetesConfiguration/extensions', {
            'extensionType': 'microsoft.azuredefender.kubernetes', 'provisioningState': 'Succeeded',
            'configurationSettings': {'arbitrary': 'sensitive-marker'},
            'configurationProtectedSettings': {'password': 'sensitive-marker'}})]
    elif kind == 'sql_backup_short_term_policy':
        server = SQL.rsplit('/databases/', 1)[0]
        r = routes('sql_server', server, {})
        r[server + '/databases'] = {'value': [parent(SQL, 'Microsoft.Sql/servers/databases', {'status': 'Online'})]}
        path = SQL + '/backupShortTermRetentionPolicies'
        rows = [parent(path + '/default', 'Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies', {'retentionDays': 7})]
        r[SQL + '/restorePoints'] = {'value': [parent(SQL + '/restorePoints/qa', 'Microsoft.Sql/servers/databases/restorePoints', {'restorePointCreationDate': datetime.now(timezone.utc).isoformat()})]}
    else:
        r = routes('storage_account', STORAGE, {})
        path = STORAGE + '/providers/Microsoft.EventGrid/eventSubscriptions'
        rows = [parent(path + '/qa', 'Microsoft.EventGrid/eventSubscriptions', {'provisioningState': 'Succeeded', 'destination': {'endpointType': 'StorageQueue', 'properties': {'resourceId': STORAGE + '/queueServices/default/queues/qa'}}})]
    r[path] = {'value': rows}
    return r, path, rows

KINDS = ['storage_local_user', 'arc_kubernetes_cluster', 'sql_backup_short_term_policy', 'eventgrid_subscription']

@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('state', ['complete', 'empty', 'denied', 'partial', 'foreign', 'duplicate', 'foreign_kind'])
def test_native_parent_child_identity_and_failure_boundaries(kind, state):
    r, path, rows = fixture(kind)
    if state == 'empty': r[path] = {'value': []}
    if state == 'denied': r[path] = azure.AzureReadError('denied', 403)
    if state == 'partial':
        r[path] = lambda query: azure.AzureReadError('denied', 403) if 'page' in query else {'value': rows, 'nextLink': azure.ARM + path + '?page=2'}
    if state == 'foreign': r[path]['value'][0]['id'] = rows[0]['id'].replace(SUB, '33333333-3333-3333-3333-333333333333')
    if state == 'foreign_kind': r[path]['value'][0]['id'] = path.rsplit('/', 1)[0] + '/foreignType/name'
    if state == 'duplicate':
        r[path]['value'] *= 2
    api = Transport(r)
    snapshot = collect([kind], api)
    result = envelope(snapshot, kind)
    if state == 'complete': assert result['status'] == 'collected'
    elif state == 'empty':
        assert result['status'] == ('collected' if kind == 'arc_kubernetes_cluster' else 'empty')
    elif kind == 'arc_kubernetes_cluster':
        assert verdict(snapshot, ARC_CHECK) == 'UNKNOWN'
    else: assert result['status'] not in ('collected', 'empty')
    assert 'sensitive-marker' not in json.dumps(snapshot)
    assert not any('listKeys' in url or 'regenerate' in url or 'listCredentials' in url for url in api.calls)

def test_arc_native_success_and_successful_empty_extension_fail():
    r, path, rows = fixture('arc_kubernetes_cluster')
    assert verdict(collect(['arc_kubernetes_cluster'], Transport(r)), ARC_CHECK) == 'PASS'
    r[path] = {'value': []}
    assert verdict(collect(['arc_kubernetes_cluster'], Transport(r)), ARC_CHECK) == 'FAIL'

@pytest.mark.parametrize('check', [PITR, RETENTION])
def test_sql_native_positive_and_negative_retention(check):
    r, path, rows = fixture('sql_backup_short_term_policy')
    kinds = ['sql_backup_short_term_policy', 'sql_restore_point']
    snapshot = collect(kinds, Transport(r))
    snapshot['metadata']['compliance_policy'] = {'sw31': {}}
    snapshot.pop('snapshot_id')
    assert verdict(snapshot, check) == 'PASS'
    rows[0]['properties']['retentionDays'] = 0
    snapshot = collect(kinds, Transport(r))
    snapshot['metadata']['compliance_policy'] = {'sw31': {}}
    snapshot.pop('snapshot_id')
    assert verdict(snapshot, check) == 'FAIL'

@pytest.mark.parametrize('kind', KINDS + ['integration_service_environment'])
def test_complete_empty_parent_is_authoritative_and_no_child_call(kind):
    api = Transport({})
    result = envelope(collect([kind], api), kind)
    assert result['status'] == 'empty'
    assert not any('/localUsers?' in url or '/extensions?' in url or '/backupShortTermRetentionPolicies?' in url for url in api.calls)

@pytest.mark.parametrize('kind', ['storage_local_user', 'sql_backup_short_term_policy'])
def test_denied_parent_never_fabricates_empty_child(kind):
    source = 'storage_account' if kind == 'storage_local_user' else 'sql_server'
    endpoint = azure.ENDPOINTS[source][0]
    snapshot = collect([kind], Transport({SCOPE + '/providers/' + endpoint: azure.AzureReadError('denied', 403)}))
    assert envelope(snapshot, kind)['status'] not in ('collected', 'empty')

def test_ise_native_get_approved_configured_key_and_absent_key():
    vault = BASE + 'Microsoft.KeyVault/vaults/vault'
    props = {'encryptionConfiguration': {'encryptionKeyReference': {'keyName': 'qa', 'keyVersion': None, 'keyVault': {'id': vault}}}}
    r = routes('integration_service_environment', ISE, props)
    snapshot = collect(['integration_service_environment'], Transport(r))
    snapshot['metadata']['sw22'] = {'approved_ise_keys': {'status': 'collected', 'scope': SCOPE, 'evidence_ref': 'owner-test-declared-configured-key', 'keys': [{'vault_id': vault, 'key_name': 'qa', 'key_version': None}]}}
    snapshot.pop('snapshot_id')
    assert verdict(snapshot, ISE_CHECK) == 'PASS'
    r[ISE]['properties']['encryptionConfiguration']['encryptionKeyReference'] = None
    assert verdict(collect(['integration_service_environment'], Transport(r)), ISE_CHECK) == 'FAIL'

def test_local_user_permissions_are_exact_metadata_and_never_credentials():
    r, _, _ = fixture('storage_local_user')
    snapshot = collect(['storage_local_user'], Transport(r))
    row = envelope(snapshot, 'storage_local_user')['items'][0]
    assert row['parent_id'] == STORAGE
    assert row['properties']['permissionScopes'] == [{'permissions': 'rl', 'service': 'blob', 'resourceName': 'qa'}]
    assert row['properties']['sid'] == 'sid-alice'
    assert row['_provenance']['source_operation'] == 'LocalUsers_List'
    assert row['_provenance']['representation'] == 'metadata'

@pytest.mark.parametrize('mutation', ['partial_parent', 'partial_child', 'partial_projection', 'missing_server', 'missing_projection', 'altered_projection', 'foreign_server', 'duplicate_server', 'wrong_source', 'foreign_child'])
def test_sql_subscription_join_requires_exact_full_native_roster(mutation):
    from peaso.collectors.azure_sql_inventory import authorized_database_scopes
    r, _, _ = fixture('sql_backup_short_term_policy')
    snapshot = collect(['sql_backup_short_term_policy'], Transport(r))
    assert len(authorized_database_scopes(snapshot, SCOPE)) == 1
    servers = envelope(snapshot, 'sql_server')
    projection = envelope(snapshot, 'sql_database_inventory')
    child = next(c for c in snapshot['collections'] if c['type'] == 'sql_database')
    if mutation == 'partial_parent': servers['status'] = 'partial'
    if mutation == 'partial_child': child['status'] = 'partial'
    if mutation == 'partial_projection': projection['status'] = 'partial'
    if mutation == 'missing_server': servers['items'] = []
    if mutation == 'missing_projection': snapshot['collections'].remove(projection)
    if mutation == 'altered_projection': projection['items'][0]['properties']['status'] = 'Offline'
    if mutation == 'foreign_server': servers['items'][0]['id'] = STORAGE
    if mutation == 'duplicate_server': servers['items'] *= 2
    if mutation == 'wrong_source': projection['source_inventory'] = 'sql_unverified'
    if mutation == 'foreign_child': child['items'][0]['id'] = SQL + '/foreign'
    assert not authorized_database_scopes(snapshot, SCOPE)
    snapshot.pop('snapshot_id')
    assert verdict(snapshot, PITR) == 'UNKNOWN'


def test_user_assigned_identity_gets_no_diagnostic_settings_read():
    identity = BASE + 'Microsoft.ManagedIdentity/userAssignedIdentities/uami'
    mapping = routes('managed_identity', identity, {'principalId': 'p', 'clientId': 'c'})
    mapping[SCOPE + '/resources'] = {'value': [{'id': identity, 'type': 'Microsoft.ManagedIdentity/userAssignedIdentities'}]}
    api = Transport(mapping)
    snapshot = collect(['managed_identity', 'diagnostic_setting'], api)
    assert envelope(snapshot, 'managed_identity')['status'] == 'collected'
    assert not any('diagnosticsettings' in urlsplit(url).path.casefold() and 'userassignedidentities' in url.casefold()
                   for url in api.calls)
    assert not any(c['type'] == 'diagnostic_setting' and c['status'] not in ('collected', 'empty') for c in snapshot['collections'])
