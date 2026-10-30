"""Independent ARM/data-plane HTTP bytes -> Azure collector -> public engine storage review.

No CASES import, owner approval, effective-access assertion or invented provider marker.
All network and credential discovery are disabled; urllib receives exact routed bytes.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import socket
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest
from tests.azure_native_inventory_routes_20261020 import empty_inventory_versions,matches_empty_inventory_query
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot, plan_collection

SUB = "11111111-1111-1111-1111-111111111111"
SCOPE = "/subscriptions/" + SUB
RG = SCOPE + "/resourceGroups/rg"
ACCOUNT = RG + "/providers/Microsoft.Storage/storageAccounts/account"
VM = RG + "/providers/Microsoft.Compute/virtualMachines/vm"
MG = "/providers/Microsoft.Management/managementGroups/root"
BLOB = ACCOUNT + "/blobServices/default"
FILE = ACCOUNT + "/fileServices/default"
PRIVATE = "MUST_NOT_RETAIN_SECRET_VALUE"

ROSTER = ('azure.cis.legacy_vhds_encrypted',
 'azure.cis.resource_manager_delete_locks_applied_storage_accounts',
 'azure.claude.activity_log_storage_cmk',
 'azure.claude.activity_log_storage_private',
 'azure.claude.insights_activity_logs_container_byok',
 'azure.claude.insights_activity_logs_container_private',
 'azure.claude.insights_operational_logs_container_byok',
 'azure.claude.insights_operational_logs_container_private',
 'azure.claude.storage_access_keys_rotated_90',
 'azure.claude.storage_account_cmk',
 'azure.claude.storage_account_geo_redundant',
 'azure.claude.storage_blob_and_container_soft_delete_7_365',
 'azure.claude.storage_blob_classic_logging',
 'azure.claude.storage_blob_diagnostic_logging',
 'azure.claude.storage_blob_soft_delete_enabled',
 'azure.claude.storage_file_share_soft_delete_1_365',
 'azure.claude.storage_file_share_soft_delete_enabled',
 'azure.claude.storage_key_expiration_policy_90',
 'azure.claude.storage_key_expiration_policy_max_90',
 'azure.claude.storage_private_endpoint_present',
 'azure.claude.storage_private_link_all_approved',
 'azure.claude.storage_queue_classic_logging',
 'azure.claude.storage_queue_diagnostic_logging',
 'azure.claude.storage_smb_channel_encryption_aes_256_gcm',
 'azure.claude.storage_smb_version_3_1_1',
 'azure.claude.storage_table_classic_logging',
 'azure.claude.storage_table_diagnostic_logging',
 'azure.claude.storage_trusted_azure_services_bypass',
 'azure.claude.storage_vhd_accounts_cmk',
 'azure.claude.storage_vnet_service_endpoint_rules',
 'azure.htbp.storage.sftp_local_users_disabled',
 'azure.port.storage_account_access_keys_periodically_regenerated',
 'azure.port.storage_account_blob_and_container_soft_delete_enabled',
 'azure.port.storage_account_blob_soft_delete_enabled',
 'azure.port.storage_account_blob_versioning_enabled',
 'azure.port.storage_account_container_soft_delete_enabled',
 'azure.port.storage_account_encryption_at_rest_using_cmk',
 'azure.port.storage_account_file_share_smb_channel_encryption_aes_256_gcm',
 'azure.port.storage_account_file_share_smb_protocol_version_3_1_1',
 'azure.port.storage_account_geo_redundant_enabled',
 'azure.port.storage_account_key_rotation_reminder_enabled',
 'azure.port.storage_account_soft_delete_enabled',
 'azure.port.storage_account_trusted_microsoft_services_enabled',
 'azure.storage.blob_soft_delete_retention',
 'azure.storage.blob_versioning',
 'azure.storage.container_soft_delete',
 'azure.storage.cross_tenant_replication',
 'azure.storage.default_deny',
 'azure.storage.default_oauth',
 'azure.storage.https_only',
 'azure.storage.infrastructure_encryption',
 'azure.storage.minimum_tls',
 'azure.storage.no_blob_public_access',
 'azure.storage.no_public_network',
 'azure.storage.no_shared_key',
 'azure_storage_account_10_3_4_7_02943e9',
 'azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3')

# Literal API paths and values are independently authored, not registry fixtures.
SCALARS = {
 'azure.storage.cross_tenant_replication': ('properties.allowCrossTenantReplication', False, True),
 'azure.storage.default_deny': ('properties.networkAcls.defaultAction', 'Deny', 'Allow'),
 'azure.storage.default_oauth': ('properties.defaultToOAuthAuthentication', True, False),
 'azure.storage.https_only': ('properties.supportsHttpsTrafficOnly', True, False),
 'azure.storage.infrastructure_encryption': ('properties.encryption.requireInfrastructureEncryption', True, False),
 'azure.storage.minimum_tls': ('properties.minimumTlsVersion', 'TLS1_2', 'TLS1_0'),
 'azure.storage.no_blob_public_access': ('properties.allowBlobPublicAccess', False, True),
 'azure.storage.no_public_network': ('properties.publicNetworkAccess', 'Disabled', 'Enabled'),
 'azure.storage.no_shared_key': ('properties.allowSharedKeyAccess', False, True),
 'azure.claude.storage_account_cmk': ('properties.encryption.keySource', 'Microsoft.Keyvault', 'Microsoft.Storage'),
 'azure.port.storage_account_encryption_at_rest_using_cmk': ('properties.encryption.keySource', 'Microsoft.Keyvault', 'Microsoft.Storage'),
 'azure.claude.storage_account_geo_redundant': ('sku.name', 'Standard_GRS', 'Standard_LRS'),
 'azure.port.storage_account_geo_redundant_enabled': ('sku.name', 'Standard_GRS', 'Standard_LRS'),
 'azure.claude.storage_key_expiration_policy_90': ('properties.keyPolicy.keyExpirationPeriodInDays', 90, 180),
 'azure.claude.storage_key_expiration_policy_max_90': ('properties.keyPolicy.keyExpirationPeriodInDays', 60, 180),
 'azure.port.storage_account_key_rotation_reminder_enabled': ('properties.keyPolicy.keyExpirationPeriodInDays', 90, 180),
 'azure.claude.storage_trusted_azure_services_bypass': ('properties.networkAcls.bypass', 'Logging,AzureServices', 'None'),
 'azure.port.storage_account_trusted_microsoft_services_enabled': ('properties.networkAcls.bypass', 'Logging,AzureServices', 'None'),
}
UNSUPPORTED = {
 'azure_storage_account_10_3_4_7_02943e9': 'storage_immutability_evidence requires explicit retention review; no owner approval fabricated',
}
# storage_immutability_native_successor decides the native container default
# retention built for positive/negative below; other modes stay unknown.
NATIVE_SUCCESSOR_DECIDES = {'azure_storage_account_10_3_4_7_02943e9'}


def assign(row, path, value, *, omit=False):
    bits = path.split('.')
    for bit in bits[:-1]:
        row = row.setdefault(bit, {})
    if omit:
        row.pop(bits[-1], None)
    else:
        row[bits[-1]] = deepcopy(value)


def account():
    recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    return {'id': ACCOUNT, 'name': 'account', 'type': 'Microsoft.Storage/storageAccounts', 'etag': 'a1',
      'kind': 'StorageV2', 'sku': {'name': 'Standard_GRS', 'tier': 'Standard'}, 'clientSecret': PRIVATE,
      'properties': {'provisioningState': 'Succeeded', 'supportsHttpsTrafficOnly': True,
       'allowBlobPublicAccess': False, 'allowSharedKeyAccess': False, 'defaultToOAuthAuthentication': True,
       'publicNetworkAccess': 'Disabled', 'minimumTlsVersion': 'TLS1_2', 'allowCrossTenantReplication': False,
       'isSftpEnabled': False, 'isLocalUserEnabled': True,
       'keyCreationTime': {'key1': recent, 'key2': recent}, 'keyPolicy': {'keyExpirationPeriodInDays': 90},
       'encryption': {'keySource': 'Microsoft.Keyvault', 'requireInfrastructureEncryption': True,
                      'services': {'blob': {'enabled': True, 'keyType': 'Account'}},
                      'keyvaultproperties':{'keyvaulturi':'https://vault.vault.azure.net','keyname':'key','keyversion':'version1','currentVersionedKeyIdentifier':'https://vault.vault.azure.net/keys/key/version1'}},
       'networkAcls': {'defaultAction': 'Deny', 'bypass': 'Logging,AzureServices',
           'virtualNetworkRules': [{'id': RG + '/providers/Microsoft.Network/virtualNetworks/v/subnets/s', 'action': 'Allow', 'state': 'Succeeded'}]},
       'privateEndpointConnections': [{'id': ACCOUNT + '/privateEndpointConnections/pe', 'properties': {
           'privateEndpoint': {'id': RG + '/providers/Microsoft.Network/privateEndpoints/pe'},
           'privateLinkServiceConnectionState': {'status': 'Approved'}}}],
       'primaryEndpoints': {s: 'https://account.' + s + '.core.windows.net/' for s in ('blob','queue','table','file')}}}


def provider_case(cid, mode):
    a = account()
    blob = {'id': BLOB, 'name': 'default', 'type': 'Microsoft.Storage/storageAccounts/blobServices', 'properties': {
       'isVersioningEnabled': True, 'deleteRetentionPolicy': {'enabled': True, 'days': 30},
       'containerDeleteRetentionPolicy': {'enabled': True, 'days': 30}}}
    file = {'id': FILE, 'name': 'default', 'type': 'Microsoft.Storage/storageAccounts/fileServices', 'properties': {
       'shareDeleteRetentionPolicy': {'enabled': True, 'days': 30},
       'protocolSettings': {'smb': {'versions': 'SMB3.1.1;', 'channelEncryption': 'AES-256-GCM;'}}}}
    v = {'id': VM, 'name': 'vm', 'type': 'Microsoft.Compute/virtualMachines', 'properties': {
       'storageProfile': {'osDisk': {'vhd': {'uri': 'https://account.blob.core.windows.net/vhds/os.vhd'}}, 'dataDisks': []}}}
    target, path, good, bad = a, None, None, None
    if cid in SCALARS:
        path, good, bad = SCALARS[cid]
    elif 'access_keys_' in cid:
        path = 'properties.keyCreationTime'
        good = deepcopy(a['properties']['keyCreationTime'])
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        bad = {'key1': old, 'key2': old}
    elif 'activity_log_storage_' in cid:
        path, good, bad = ('properties.encryption.keySource', 'Microsoft.Keyvault', 'Microsoft.Storage') if cid.endswith('_cmk') else ('properties.allowBlobPublicAccess', False, True)
    elif 'insights_' in cid:
        path, good, bad = ('properties.encryption.keySource', 'Microsoft.Keyvault', 'Microsoft.Storage') if cid.endswith('_byok') else ('properties.allowBlobPublicAccess', False, True)
    elif 'sftp_local_users' in cid:
        path, good, bad = 'properties.isSftpEnabled', False, True
    elif 'private_link_all' in cid or 'private_endpoint_present' in cid:
        path, good, bad = 'properties.privateEndpointConnections', deepcopy(a['properties']['privateEndpointConnections']), []
    elif 'vnet_service_endpoint' in cid:
        path, good, bad = 'properties.networkAcls.virtualNetworkRules', deepcopy(a['properties']['networkAcls']['virtualNetworkRules']), []
    elif 'vhd_accounts_cmk' in cid:
        path, good, bad = 'properties.encryption.keySource', 'Microsoft.Keyvault', 'Microsoft.Storage'
    elif 'legacy_vhds' in cid:
        path, good, bad = 'properties.encryption.services.blob.enabled', True, False
    elif 'smb_' in cid:
        target = file
        field, good, bad = ('versions', 'SMB3.1.1;', 'SMB3.0;SMB3.1.1;') if ('version' in cid or 'protocol' in cid) else ('channelEncryption', 'AES-256-GCM;', 'AES-128-GCM;AES-256-GCM;')
        path = 'properties.protocolSettings.smb.' + field
    elif any(s in cid for s in ('soft_delete','blob_versioning','delete_retention')):
        target = file if 'file_share' in cid else blob
        field = 'shareDeleteRetentionPolicy' if 'file_share' in cid else 'containerDeleteRetentionPolicy' if 'container_soft_delete' in cid and 'blob_and_container' not in cid else 'deleteRetentionPolicy'
        path, good, bad = ('properties.isVersioningEnabled', True, False) if 'versioning' in cid else ('properties.' + field, {'enabled': True, 'days': 30}, {'enabled': False})
    elif cid == 'azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3':
        path, good, bad = 'properties.encryption.keySource', 'Microsoft.Keyvault', 'Microsoft.Storage'
    elif cid not in UNSUPPORTED and not any(s in cid for s in ('logging','delete_locks')):
        raise AssertionError('Unassigned native branch ' + cid)
    if cid in UNSUPPORTED:
        if '10_3_4_7' in cid:
            a['properties']['immutableStorageWithVersioning'] = {'enabled':mode!='negative'}
            if mode!='negative': a['properties']['immutableStorageWithVersioning']['immutabilityPolicy']={'state':'Locked','immutabilityPeriodSinceCreationInDays':30}
        elif mode == 'negative':
            a['properties']['encryption']['keySource'] = 'Microsoft.Storage'
    if path:
        assign(target, path, bad if mode == 'negative' else good, omit=mode == 'missing')
    if 'insights_' in cid and cid.endswith('_private') and mode == 'negative':
        a['properties']['allowBlobPublicAccess'] = True
    if mode == 'missing' and path is None:
        a['properties'].pop('primaryEndpoints', None)
    return a, blob, file, v, path


class NativeHTTP:
    """urllib opener boundary: actual AzureTransport parses JSON/XML response bytes."""
    def __init__(self, cid, mode, mutate=None):
        self.cid, self.mode, self.calls = cid, mode, []
        self.unexpected = []
        self.a, self.blob, self.file, self.vm, self.field = provider_case(cid, mode)
        self.mutate = mutate
        if mutate:
            mutate(self)

    def open(self, request, timeout):
        try:
            response = self._open(request, timeout)
            response.status = 200
            return response
        except AssertionError as exc:
            self.unexpected.append((request.full_url, str(exc)))
            raise

    def _open(self, request, timeout):
        p = urlsplit(request.full_url); q = parse_qs(p.query); path = p.path
        for prefix in (ACCOUNT,RG,SCOPE):
            if path.casefold()==prefix.casefold() or path.casefold().startswith(prefix.casefold()+'/'):
                path=prefix+path[len(prefix):]
                break
        assert request.get_method() in ('GET', 'POST')
        assert p.scheme == 'https' and p.netloc in {'management.azure.com', *('account.' + s + '.core.windows.net' for s in ('blob','queue','table'))}
        assert timeout == 20
        self.calls.append({'method': request.get_method(), 'host': p.netloc, 'path': path, 'query': q})
        def deny():
            raise HTTPError(request.full_url, 403, 'fixture denial', {}, io.BytesIO(b'{}'))
        if self.mode == 'denied': deny()
        if p.netloc != 'management.azure.com':
            assert request.get_method() == 'GET'
            if q.get('comp')==['list']:
                assert p.netloc=='account.blob.core.windows.net' and path in ('/insights-activity-logs','/insights-operational-logs')
                assert q=={'restype':['container'],'comp':['list'],'maxresults':['500'],'include':['snapshots,versions,deleted,deletedwithversions']}
                return io.BytesIO(('<EnumerationResults ServiceEndpoint="https://account.blob.core.windows.net/" ContainerName="'+path[1:]+'"><Marker/><MaxResults>500</MaxResults><Blobs><Blob><Name>object.bin</Name><Properties><ServerEncrypted>true</ServerEncrypted></Properties></Blob></Blobs><NextMarker/></EnumerationResults>').encode())
            assert path == '/' and q == {'restype':['service'], 'comp':['properties']}
            if self.mode == 'missing': deny()
            enabled = 'false' if self.mode == 'negative' else 'true'
            return io.BytesIO(('<StorageServiceProperties><Logging><Version>1.0</Version>' + ''.join('<'+op+'>'+enabled+'</'+op+'>' for op in ('Read','Write','Delete')) + '</Logging></StorageServiceProperties>').encode())
        assert q.get('api-version') and set(q) <= {'api-version','$expand','page','$filter','$select','$top'}
        if request.get_method() == 'POST':
            assert path == '/providers/Microsoft.ResourceGraph/resources'
            body = json.loads(request.data)
            assert body['subscriptions'] == [SUB] and isinstance(body['query'], str)
            if 'resourcecontainers' not in body['query']:
                rows=[deepcopy(self.a),deepcopy(self.vm)]
                if self.mode=='foreign': rows[0]['id']=rows[0]['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
                return io.BytesIO(json.dumps({'data': rows, 'resultTruncated': False, 'count': 2}).encode())
            if self.mode == 'missing': deny()
            value = {'data':[{'id':SCOPE,'properties':{'managementGroupAncestorsChain':[{'name':'root'}]}}], 'resultTruncated':False}
        elif path == SCOPE + '/providers/Microsoft.Storage/storageAccounts':
            if 'page' in q: deny()
            row = deepcopy(self.a)
            if self.mode == 'foreign': row['id'] = row['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
            value = {'value':[row]}
            if self.mode == 'partial': value['nextLink'] = azure.ARM + path + '?api-version=2023-05-01&page=2'
        elif path == ACCOUNT:
            value = self.a
        elif path == SCOPE:
            value = {'id':SCOPE, 'subscriptionId':SUB, 'tenantId':'22222222-2222-2222-2222-222222222222', 'state':'Enabled'}
        elif path == SCOPE+'/resources':
            value={'value':[deepcopy(self.a),deepcopy(self.vm)]}
        elif path in empty_inventory_versions(SCOPE):
            assert matches_empty_inventory_query(SCOPE,path,q)
            value={'value':[]}
        elif path in {SCOPE+s for s in ('/resourcegroups','/providers/Microsoft.ContainerService/managedClusters','/providers/Microsoft.Network/applicationGateways','/providers/Microsoft.Kubernetes/connectedClusters','/providers/Microsoft.Network/firewallPolicies','/providers/Microsoft.Network/natGateways','/providers/Microsoft.Network/networkInterfaces','/providers/Microsoft.Network/networkSecurityGroups','/providers/Microsoft.Network/publicIPAddresses','/providers/Microsoft.Network/routeTables','/providers/Microsoft.Network/virtualNetworks','/providers/Microsoft.Network/locations/westcentralus/serviceTags')}:
            value = {'value':[]}
        elif path == SCOPE + '/providers/Microsoft.Compute/virtualMachines':
            value = {'value':[self.vm]}
        elif path == VM:
            value = self.vm
        elif path == MG:
            value = {'id':MG,'properties':{'details':{'parent':None}}}
        elif path == MG + '/subscriptions/' + SUB:
            value = {'id':path,'properties':{'parent':{'id':MG}}}
        elif path.endswith('/providers/Microsoft.Authorization/locks'):
            assert path.rsplit('/providers/',1)[0] in (ACCOUNT,RG,SCOPE,MG)
            if self.mode == 'missing': deny()
            values = [{'id':path+'/protect','properties':{'level':'CanNotDelete'}}] if path.startswith(ACCOUNT+'/') and self.mode != 'negative' else []
            value = {'value':values}
        elif path == BLOB: value = self.blob
        elif path == FILE: value = self.file
        elif path in (ACCOUNT+'/queueServices/default',ACCOUNT+'/tableServices/default'):
            value = {'id':path,'type':'Microsoft.Storage/storageAccounts/'+path.split('/')[-2], 'properties':{}}
        elif path == ACCOUNT + '/blobServices/default/containers':
            names = ['insights-activity-logs','insights-operational-logs']
            access = 'Container' if self.mode == 'negative' else 'None'
            value = {'value':[{'id':path+'/'+name,'name':name,'type':'Microsoft.Storage/storageAccounts/blobServices/containers','properties':{'publicAccess':access}} for name in names]}
            if self.mode == 'missing': deny()
        elif path.startswith(BLOB+'/containers/') and path.rsplit('/',1)[-1] in ('insights-activity-logs','insights-operational-logs'):
            value={'id':path,'etag':'c1','name':path.rsplit('/',1)[-1],'type':'Microsoft.Storage/storageAccounts/blobServices/containers','properties':{'publicAccess':'None','defaultEncryptionScope':'$account-encryption-key','denyEncryptionScopeOverride':False,'hasImmutabilityPolicy':False,'immutableStorageWithVersioning':{'enabled':self.mode!='negative'}}}
        elif path in (FILE + '/shares',BLOB+'/shares'):
            value = {'value':[{'id':path+'/share','name':'share','type':'Microsoft.Storage/storageAccounts/fileServices/shares','properties':{}}]}
            if self.mode == 'missing': deny()
        elif path.endswith('/providers/Microsoft.Insights/diagnosticSettings'):
            assert path.startswith((ACCOUNT+'/',VM+'/',SCOPE+'/providers/'))
            if self.mode == 'missing': deny()
            parent = path.rsplit('/providers/',1)[0]
            props = {'logs':[{'category':s,'enabled':self.mode!='negative'} for s in ('StorageRead','StorageWrite','StorageDelete')], 'storageAccountId':ACCOUNT}
            value = {'value':[{'id':path+'/logs','name':'logs','type':'Microsoft.Insights/diagnosticSettings','properties':props}]}
        elif path.endswith('/providers/Microsoft.Insights/diagnosticSettingsCategories'):
            value = {'value':[]}
        else:
            # Exact non-deciding ancillary reads; accidental expansion fails loudly.
            assert path in {ACCOUNT+'/'+s for s in ('encryptionScopes','localUsers','providers/Microsoft.EventGrid/eventSubscriptions')} | {VM+'/instanceView',VM+'/extensions', VM+'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments'}, path
            value = {'value':[]}
        return io.BytesIO(json.dumps(deepcopy(value)).encode())


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError('Network/auth is blocked in native review')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket.socket, 'connect_ex', forbidden)
    monkeypatch.setattr(azure, 'credential_for', forbidden)


def capture(monkeypatch, cid, mode='positive', mutate=None):
    http = NativeHTTP(cid, mode, mutate)
    monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    connector = {'provider':'azure','scopes':[SUB], 'auth':{'method':'token','arm_token':'fixture-inert','storage_token':'fixture-inert'}, 'options':{'concurrency':1,'retries':0}}
    required = plan_collection({'connector':connector,'checks':[cid]})
    snapshot = azure.collect(connector, required)
    findings = evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)['findings']
    # Other service subjects are expected N/A; the requested actual resource remains.
    rid = FILE if any(s in cid for s in ('file_share','smb_')) and cid.startswith('azure.claude.') else BLOB if cid.startswith('azure.storage.blob_') or cid=='azure.storage.container_soft_delete' or cid.startswith('azure.claude.storage_blob_') and 'logging' not in cid else ACCOUNT
    selected = [f for f in findings if str(f.get('native_resource_id','')).casefold()==rid.casefold()]
    if not selected:
        selected = [f for f in findings if f.get('status') != 'NOT_APPLICABLE'] or findings
    assert selected, findings
    assert PRIVATE not in json.dumps(snapshot)
    assert not http.unexpected, http.unexpected
    assert http.calls and all('listKeys' not in c['path'] for c in http.calls)
    return selected, snapshot, http


def expected(cid, mode):
    if mode == 'denied': return 'DENIED'
    if cid in UNSUPPORTED and not (cid in NATIVE_SUCCESSOR_DECIDES and mode in ('positive','negative')): return 'UNKNOWN'
    if mode == 'foreign': return 'UNKNOWN'
    if mode == 'partial':
        return 'UNKNOWN' if cid in ('azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3','azure.cis.legacy_vhds_encrypted','azure.cis.resource_manager_delete_locks_applied_storage_accounts','azure.claude.activity_log_storage_cmk','azure.claude.activity_log_storage_private','azure.claude.storage_vhd_accounts_cmk') else 'PASS'
    if mode == 'missing':
        if cid in ('azure.claude.activity_log_storage_cmk','azure.claude.activity_log_storage_private'): return 'DENIED'
        if cid in ('azure.claude.storage_smb_channel_encryption_aes_256_gcm','azure.claude.storage_smb_version_3_1_1'): return 'FAIL'  # documented default permits all supported values
        if cid == 'azure.htbp.storage.sftp_local_users_disabled': return 'PASS'  # omitted SFTP flag is false
        return 'UNKNOWN'
    return 'FAIL' if mode == 'negative' else 'PASS'


@pytest.mark.parametrize('cid', ROSTER, ids=ROSTER)
@pytest.mark.parametrize('mode', ['positive','negative','missing','denied','foreign','partial'])
def test_native_matrix(monkeypatch, cid, mode):
    findings, snapshot, api = capture(monkeypatch, cid, mode)
    want = expected(cid, mode)
    assert {f['status'] for f in findings} == {want}, (cid, mode, findings, [(c['type'],c['status'],c.get('error')) for c in snapshot['collections']], api.calls)
    if mode == 'positive' and cid not in UNSUPPORTED:
        account_rows = [r for c in snapshot['collections'] if c['type']=='storage_account' for r in c['items']]
        assert account_rows and all(r.get('_provenance',{}).get('representation')=='full' for r in account_rows)

@pytest.mark.parametrize('mode', ['one_key','empty_keys','future_key','fractional_90_days'])
def test_claude_key_rotation_complete_capture_bound_metadata(monkeypatch, mode):
    cid = 'azure.claude.storage_access_keys_rotated_90'
    def change(api):
        times = api.a['properties']['keyCreationTime']
        if mode == 'one_key': times.pop('key2')
        if mode == 'empty_keys': times.clear()
        if mode == 'future_key': times['key1'] = (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
        if mode == 'fractional_90_days': times['key1'] = (datetime.now(timezone.utc)-timedelta(days=90,hours=12)).isoformat()
    fs, _, _ = capture(monkeypatch,cid,mutate=change)
    assert {f['status'] for f in fs} == {'FAIL' if mode=='fractional_90_days' else 'UNKNOWN'}, fs


@pytest.mark.parametrize('uri', ['https://account.attacker.invalid/vhds/os.vhd','http://account.blob.core.windows.net/vhds/os.vhd','https://account.blob.core.windows.net:8443/vhds/os.vhd'])
def test_vhd_cmk_joins_authoritative_blob_origin(monkeypatch, uri):
    def change(api): api.vm['properties']['storageProfile']['osDisk']['vhd']['uri'] = uri
    fs, _, _ = capture(monkeypatch,'azure.claude.storage_vhd_accounts_cmk',mutate=change)
    assert {f['status'] for f in fs} == {'UNKNOWN'}, fs


@pytest.mark.parametrize('cid', ['azure.storage.https_only','azure.storage.no_shared_key','azure.claude.storage_account_cmk'])
def test_account_full_get_type_must_match_native_identity(monkeypatch, cid):
    def change(api): api.a['type'] = 'Microsoft.Compute/virtualMachines'
    fs, _, _ = capture(monkeypatch,cid,mutate=change)
    assert {f['status'] for f in fs} == {'UNKNOWN'}, fs


@pytest.mark.parametrize('cid', ['azure.storage.blob_versioning','azure.storage.blob_soft_delete_retention','azure.claude.storage_blob_soft_delete_enabled'])
def test_service_get_type_cannot_override_scoped_arm_kind(monkeypatch, cid):
    def change(api): api.blob['type'] = 'Microsoft.Storage/storageAccounts/fileServices'
    fs, _, _ = capture(monkeypatch,cid,mutate=change)
    assert {f['status'] for f in fs} == {'UNKNOWN'}, fs


@pytest.mark.parametrize('cid', ['azure.storage.https_only','azure.port.storage_account_access_keys_periodically_regenerated'])
@pytest.mark.parametrize('mutation', ['case_alias','wrong_detail_id'])
def test_account_exact_get_binding_and_case_alias(monkeypatch,cid,mutation):
    def change(api):
        # LIST retains canonical identity; mutate only the subsequent GET bytes.
        original = api.open
        def opened(request,timeout):
            if urlsplit(request.full_url).path == ACCOUNT:
                row = deepcopy(api.a)
                row['id'] = ACCOUNT.upper() if mutation=='case_alias' else ACCOUNT+'foreign'
                api.calls.append({'method':'GET','host':'management.azure.com','path':ACCOUNT,'query':parse_qs(urlsplit(request.full_url).query)})
                response=io.BytesIO(json.dumps(row).encode());response.status=200
                return response
            return original(request,timeout)
        api.open = opened
    fs,_,_ = capture(monkeypatch,cid,mutate=change)
    assert {f['status'] for f in fs} == {'PASS' if mutation=='case_alias' else 'UNKNOWN'}, fs


@pytest.mark.parametrize('cid', ['azure.claude.storage_blob_classic_logging','azure.claude.storage_queue_classic_logging','azure.claude.storage_table_classic_logging','azure.claude.storage_blob_diagnostic_logging','azure.claude.storage_queue_diagnostic_logging','azure.claude.storage_table_diagnostic_logging'])
def test_premium_upstream_exclusion_is_explicit(monkeypatch,cid):
    def change(api): api.a['sku'] = {'name':'Premium_LRS','tier':'Premium'}
    fs,_,_ = capture(monkeypatch,cid,mutate=change)
    assert {f['status'] for f in fs} == {'NOT_APPLICABLE'}, fs


@pytest.mark.parametrize('cid', ['azure.storage.blob_soft_delete_retention','azure.claude.storage_blob_and_container_soft_delete_7_365','azure.claude.storage_file_share_soft_delete_1_365'])
@pytest.mark.parametrize('days,status', [(1,'FAIL'),(7,'PASS'),(365,'PASS'),(366,'FAIL'),(True,'UNKNOWN'),('30','UNKNOWN')])
def test_native_retention_type_and_boundaries(monkeypatch,cid,days,status):
    if 'file_share' in cid and type(days) is int and days == 1: status = 'PASS'
    def change(api):
        target = api.file if 'file_share' in cid else api.blob
        for key,value in target['properties'].items():
            if isinstance(value,dict) and 'days' in value: value['days']=days
    fs,_,_ = capture(monkeypatch,cid,mutate=change)
    assert {f['status'] for f in fs} == {status}, fs


@pytest.mark.parametrize('cid', ['azure.claude.storage_key_expiration_policy_90','azure.claude.storage_key_expiration_policy_max_90','azure.port.storage_account_key_rotation_reminder_enabled'])
def test_authoritative_absent_key_policy_fails_reminder_only(monkeypatch,cid):
    def change(api): api.a['properties'].pop('keyPolicy')
    fs,_,_ = capture(monkeypatch,cid,mutate=change)
    assert {f['status'] for f in fs} == {'FAIL'}, fs

CHILD_PORTS = (
 'azure.port.storage_account_soft_delete_enabled',
 'azure.port.storage_account_blob_soft_delete_enabled',
 'azure.port.storage_account_container_soft_delete_enabled',
 'azure.port.storage_account_blob_and_container_soft_delete_enabled',
 'azure.port.storage_account_blob_versioning_enabled',
 'azure.port.storage_account_file_share_smb_protocol_version_3_1_1',
 'azure.port.storage_account_file_share_smb_channel_encryption_aes_256_gcm',
)


@pytest.mark.parametrize('cid', CHILD_PORTS)
@pytest.mark.parametrize('mode', ['child_denied','child_missing','sibling_account','foreign_subscription','parent_denied'])
def test_storage_child_scope_binding(monkeypatch,cid,mode):
    target = FILE if 'file_share' in cid else BLOB
    def change(api):
        original = api.open
        def opened(request,timeout):
            path = urlsplit(request.full_url).path
            if mode == 'parent_denied' and path == ACCOUNT or mode == 'child_denied' and path == target:
                api.calls.append({'method':request.get_method(),'host':urlsplit(request.full_url).netloc,'path':path,'query':parse_qs(urlsplit(request.full_url).query)})
                assert request.get_method()=='GET' and urlsplit(request.full_url).netloc=='management.azure.com'
                raise HTTPError(request.full_url,403,'fixture denied',{},io.BytesIO(b'{}'))
            response = original(request,timeout)
            if path==target:
                row = json.load(response)
                if mode=='child_missing': row['properties']={}
                if mode=='sibling_account': row['id']=row['id'].replace('/storageAccounts/account/','/storageAccounts/sibling/')
                if mode=='foreign_subscription': row['id']=row['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
                response=io.BytesIO(json.dumps(row).encode());response.status=200
                return response
            return response
        api.open=opened
    fs,_,_=capture(monkeypatch,cid,mutate=change)
    assert {f['status'] for f in fs} == {'UNKNOWN'}, fs


def test_sibling_subscription_denial_does_not_contaminate_native_storage_child(monkeypatch):
    import sys
    from peaso.snapshot import make_snapshot
    cid=CHILD_PORTS[0]
    fs, first, _=capture(monkeypatch,cid)
    assert {f['status'] for f in fs}=={'PASS'}
    second_sub='99999999-9999-9999-9999-999999999999'
    this=sys.modules[__name__]
    original_sub=SUB
    with pytest.MonkeyPatch.context() as scoped:
        for key in ('SUB','SCOPE','RG','ACCOUNT','VM','BLOB','FILE'):
            scoped.setattr(this,key,globals()[key].replace(original_sub,second_sub))
        _, second, _=capture(scoped,cid,'denied')
    combined=make_snapshot('azure',[SCOPE,'/subscriptions/'+second_sub],first['collections']+second['collections'])
    rows=evaluate_snapshot(combined,checks=[cid])['findings']
    own=[f for f in rows if f.get('native_resource_id')==ACCOUNT]
    assert own and {f['status'] for f in own}=={'PASS'},rows
    assert any(f['scope']=='/subscriptions/'+second_sub and f['status']=='DENIED' for f in rows),rows
