"""Exactly 60 application/compute controls through native HTTP -> collector -> engine.

Native response builders are independent of CASES, signed fixtures and evaluator
callbacks. The roster selects IDs only; all security facts originate below.
"""
from copy import deepcopy
import json
import re
import socket
from urllib.parse import parse_qs, urlsplit

import pytest

from peaso.checks import CHECKS
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate

SUB = '11111111-1111-1111-1111-111111111111'
TENANT = '22222222-2222-2222-2222-222222222222'
SCOPE = '/subscriptions/' + SUB
BASE = SCOPE + '/resourceGroups/native-app-review/providers/'
SITE = BASE + 'Microsoft.Web/sites/native-app'
ACR = BASE + 'Microsoft.ContainerRegistry/registries/nativeregistry'
GROUP = BASE + 'Microsoft.ContainerInstance/containerGroups/native-group'
DBX = BASE + 'Microsoft.Databricks/workspaces/native-workspace'
DISK = BASE + 'Microsoft.Compute/disks/native-disk'
SYNAPSE = BASE + 'Microsoft.Synapse/workspaces/native-synapse'
VMSS = BASE + 'Microsoft.Compute/virtualMachineScaleSets/native-scale'
VNET = BASE + 'Microsoft.Network/virtualNetworks/native-vnet'
NSG_REF = BASE + 'Microsoft.Network/networkSecurityGroups/native-nsg'
WORKSPACE = BASE + 'Microsoft.OperationalInsights/workspaces/native-logs'
REGISTRY = {c.id: c for c in CHECKS}
# A repository-local literal cohort avoids making repeat runs depend on /tmp.
IDS = (
    'azure.app.client_certificates', 'azure.app.cors_no_wildcards', 'azure.app.ftps_only',
    'azure.app.http2', 'azure.app.https_only', 'azure.app.minimum_tls', 'azure.app.remote_debugging_off',
    'azure.app.request_logging', 'azure.app.scm_minimum_tls', 'azure.cis.app_service_entra_registration_enabled',
    'azure.claude.acr_admin_user_disabled', 'azure.claude.acr_cmk', 'azure.claude.acr_geo_replication',
    'azure.claude.acr_network_default_deny', 'azure.claude.acr_private_endpoint_present',
    'azure.claude.acr_private_link_approved', 'azure.claude.acr_public_network_access_disabled',
    'azure.claude.acr_quarantine_policy', 'azure.claude.acr_retention_policy', 'azure.claude.acr_trust_policy',
    'azure.claude.acr_vnet_service_endpoint', 'azure.claude.container_group_cmk',
    'azure.claude.container_group_managed_identity', 'azure.claude.container_group_secure_environment_variables',
    'azure.claude.container_group_virtual_network', 'azure.claude.databricks_diagnostic_log_delivery',
    'azure.claude.databricks_managed_disk_cmk', 'azure.claude.databricks_subnet_nsg',
    'azure.claude.databricks_vnet_injection_value', 'azure.claude.disk_attached_cmk',
    'azure.claude.disk_attached_customer_key', 'azure.claude.disk_attached_double_encryption',
    'azure.claude.disk_unattached_cmk', 'azure.claude.disk_unattached_customer_key',
    'azure.claude.synapse_workspace_cmk', 'azure.claude.synapse_workspace_exfiltration_protection',
    'azure.claude.synapse_workspace_private_link', 'azure.claude.synapse_workspace_vulnerability_assessment',
    'azure.claude.vmss_automatic_upgrade_mode', 'azure.claude.vmss_boot_diagnostics',
    'azure.claude.vmss_linux_ssh_keys', 'azure.claude.vmss_load_balancer_backend',
    'azure.claude.vmss_managed_disks', 'azure.claude.vmss_not_empty',
    'azure.claude2.api_app_client_certificates', 'azure.claude2.api_app_cors_no_wildcard',
    'azure.claude2.api_app_ftps_required', 'azure.claude2.api_app_https_only',
    'azure.claude2.api_app_managed_identity', 'azure.claude2.api_app_min_tls_12',
    'azure.claude2.api_app_remote_debugging_disabled', 'azure.claude2.app_workers_more_than_one',
    'azure.claude2.function_app_authentication_enabled', 'azure.claude2.function_app_client_certificates',
    'azure.claude2.function_app_ftps_required', 'azure.claude2.function_app_linux_http2',
    'azure.claude2.function_app_managed_identity', 'azure.claude2.function_app_restrict_public_access',
    'azure.claude2.prowler_app_authentication', 'azure.claude2.prowler_app_client_certificates_required',
)
ENDPOINTS = {
    'app_service': ('Microsoft.Web/sites', '2023-12-01', SITE),
    'container_registry': ('Microsoft.ContainerRegistry/registries', '2023-07-01', ACR),
    'container_group': ('Microsoft.ContainerInstance/containerGroups', '2023-05-01', GROUP),
    'databricks_workspace': ('Microsoft.Databricks/workspaces', '2024-05-01', DBX),
    'disk': ('Microsoft.Compute/disks', '2023-10-02', DISK),
    'synapse_workspace': ('Microsoft.Synapse/workspaces', '2021-06-01', SYNAPSE),
    'vm_scale_set': ('Microsoft.Compute/virtualMachineScaleSets', '2024-07-01', VMSS),
    'vnet': ('Microsoft.Network/virtualNetworks', '2023-09-01', VNET),
}
# Explicit independent good/bad native values for simple field declarations.
FIELDS = {
    'azure.app.client_certificates': ('properties.clientCertMode', 'Required', 'Optional'),
    'azure.app.cors_no_wildcards': ('properties.cors.allowedOrigins', ['https://client.example'], ['*']),
    'azure.app.ftps_only': ('properties.ftpsState', 'FtpsOnly', 'AllAllowed'),
    'azure.app.http2': ('properties.http20Enabled', True, False),
    'azure.app.https_only': ('properties.httpsOnly', True, False),
    'azure.app.minimum_tls': ('properties.minTlsVersion', '1.2', '1.0'),
    'azure.app.remote_debugging_off': ('properties.remoteDebuggingEnabled', False, True),
    'azure.app.request_logging': ('properties.httpLoggingEnabled', True, False),
    'azure.app.scm_minimum_tls': ('properties.scmMinTlsVersion', '1.3', '1.1'),
    'azure.claude.acr_admin_user_disabled': ('properties.adminUserEnabled', False, True),
    'azure.claude.acr_cmk': ('properties.encryption.status', 'enabled', 'disabled'),
    'azure.claude.acr_network_default_deny': ('properties.networkRuleSet.defaultAction', 'Deny', 'Allow'),
    'azure.claude.acr_public_network_access_disabled': ('properties.publicNetworkAccess', 'Disabled', 'Enabled'),
    'azure.claude.acr_quarantine_policy': ('properties.policies.quarantinePolicy.status', 'enabled', 'disabled'),
    'azure.claude.acr_retention_policy': ('properties.policies.retentionPolicy.status', 'enabled', 'disabled'),
    'azure.claude.acr_trust_policy': ('properties.policies.trustPolicy.status', 'enabled', 'disabled'),
    'azure.claude.synapse_workspace_exfiltration_protection': ('properties.managedVirtualNetworkSettings.preventDataExfiltration', True, False),
    'azure.claude.vmss_automatic_upgrade_mode': ('properties.upgradePolicy.mode', 'Automatic', 'Manual'),
    'azure.claude.vmss_boot_diagnostics': ('properties.virtualMachineProfile.diagnosticsProfile.bootDiagnostics.enabled', True, False),
    'azure.claude.vmss_linux_ssh_keys': ('properties.virtualMachineProfile.osProfile.linuxConfiguration.disablePasswordAuthentication', True, False),
    'azure.claude.vmss_not_empty': ('sku.capacity', 2, 0),
}
APP_FIELDS = {
    'api_app_client_certificates': ('properties.clientCertEnabled', True, False),
    'api_app_cors_no_wildcard': ('configuration.properties.cors.allowedOrigins', ['https://client.example'], ['*']),
    'api_app_ftps_required': ('configuration.properties.ftpsState', 'Disabled', 'AllAllowed'),
    'api_app_https_only': ('properties.httpsOnly', True, False),
    'api_app_min_tls_12': ('configuration.properties.minTlsVersion', '1.3', '1.1'),
    'api_app_remote_debugging_disabled': ('configuration.properties.remoteDebuggingEnabled', False, True),
    'app_workers_more_than_one': ('configuration.properties.numberOfWorkers', 2, 1),
    'function_app_authentication_enabled': ('authSettingsV2.properties.platform.enabled', True, False),
    'function_app_client_certificates': ('properties.clientCertEnabled', True, False),
    'function_app_ftps_required': ('configuration.properties.ftpsState', 'FtpsOnly', 'AllAllowed'),
    'function_app_linux_http2': ('configuration.properties.http20Enabled', True, False),
    'function_app_restrict_public_access': ('configuration.properties.ipSecurityRestrictions', [{'ipAddress': '203.0.113.0/24', 'action': 'Allow', 'priority': 100}], [{'ipAddress': 'Any', 'action': 'Allow', 'priority': 100}]),
    'prowler_app_authentication': ('authSettingsV2.properties.platform.enabled', True, False),
    'prowler_app_client_certificates_required': ('properties.clientCertMode', 'Required', 'Optional'),
}


@pytest.fixture(autouse=True)
def no_auth_or_network(monkeypatch):
    attempted = []
    def prohibited(*args, **kwargs):
        attempted.append('actual auth/socket/DNS'); raise AssertionError('Azure native60 forbids auth/network')
    for name in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo'):
        monkeypatch.setattr(socket, name, prohibited)
    for name in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, name, prohibited)
    monkeypatch.setattr(azure, 'credential_for', prohibited)
    monkeypatch.setattr(azure, 'AzureTransport', prohibited)
    yield
    assert not attempted, attempted


def resource(rid, typ, properties=None, **other):
    return {'id': rid, 'name': rid.rsplit('/', 1)[-1], 'type': typ, 'location': 'eastus',
            'properties': properties if properties is not None else {}, **other}


def put(obj, path, value, *, remove=False):
    parts = path.split('.')
    for part in parts[:-1]: obj = obj.setdefault(part, {})
    if remove: obj.pop(parts[-1], None)
    else: obj[parts[-1]] = deepcopy(value)


def native_case(cid, mode):
    check = REGISTRY[cid]; kind = check.kind if check.kind != 'app_service_config' else 'app_service'
    typ, version, rid = ENDPOINTS[kind]
    obj = resource(rid, typ, {'provisioningState': 'Succeeded'})
    children, additional = {}, []
    deciding = None
    slug, bad = cid.split('.')[-1], mode == 'bad'
    if kind == 'app_service':
        obj.update(kind='functionapp,linux' if slug.startswith('function_app_') else 'api' if slug.startswith('api_app_') else 'app')
        obj['properties'].update(httpsOnly=True, clientCertEnabled=True, clientCertMode='Required', publicNetworkAccess='Enabled')
        obj['identity'] = {'type': 'SystemAssigned', 'principalId': '33333333-3333-3333-3333-333333333333', 'tenantId': TENANT}
        cfg = resource(SITE + '/config/web', 'Microsoft.Web/sites/config', {
            'minTlsVersion': '1.2', 'scmMinTlsVersion': '1.2', 'ftpsState': 'FtpsOnly',
            'http20Enabled': True, 'httpLoggingEnabled': True, 'remoteDebuggingEnabled': False,
            'cors': {'allowedOrigins': ['https://client.example']}, 'numberOfWorkers': 2,
            'ipSecurityRestrictions': [{'ipAddress': '203.0.113.0/24', 'action': 'Allow', 'priority': 100}],
            'ipSecurityRestrictionsDefaultAction': 'Deny'})
        auth = resource(SITE + '/config/authsettingsV2', 'Microsoft.Web/sites/config', {'platform': {'enabled': True}})
        children[SITE + '/config/web'] = cfg; children[SITE + '/config/authsettingsV2'] = auth
        if cid in FIELDS:
            path, good, fail = FIELDS[cid]; target = cfg if check.kind == 'app_service_config' else obj
            put(target, path, fail if bad else good); deciding = (target, path)
        elif slug in APP_FIELDS:
            path, good, fail = APP_FIELDS[slug]
            target = cfg if path.startswith('configuration.') else auth if path.startswith('authSettingsV2.') else obj
            path = path.removeprefix('configuration.').removeprefix('authSettingsV2.')
            put(target, path, fail if bad else good); deciding = (target, path)
        elif slug.endswith('managed_identity') or cid == 'azure.cis.app_service_entra_registration_enabled':
            obj['identity'] = {'type': 'None'} if bad else obj['identity']; deciding = (obj, 'identity')
        else: raise AssertionError(cid)
    elif kind == 'container_registry':
        obj['sku'] = {'name': 'Premium', 'tier': 'Premium'}
        obj['properties'].update(loginServer='nativeregistry.azurecr.io', adminUserEnabled=False,
            encryption={'status': 'enabled', 'keyVaultProperties': {'keyIdentifier': 'https://native.vault.azure.net/keys/review/v1'}},
            publicNetworkAccess='Disabled', networkRuleSet={'defaultAction': 'Deny', 'ipRules': [],
                'virtualNetworkRules': [{'action': 'Allow', 'id': VNET + '/subnets/registry'}]},
            policies={p: {'status': 'enabled'} for p in ('quarantinePolicy', 'retentionPolicy', 'trustPolicy')},
            privateEndpointConnections=[resource(ACR + '/privateEndpointConnections/native', 'Microsoft.ContainerRegistry/registries/privateEndpointConnections', {
                'privateEndpoint': {'id': BASE + 'Microsoft.Network/privateEndpoints/native'},
                'privateLinkServiceConnectionState': {'status': 'Approved'}})])
        if cid in FIELDS:
            path, good, fail = FIELDS[cid]; put(obj, path, fail if bad else good); deciding = (obj, path)
        elif slug == 'acr_geo_replication':
            children[ACR + '/replications'] = [resource(ACR + '/replications/' + loc, 'Microsoft.ContainerRegistry/registries/replications', {'provisioningState': 'Succeeded'}, location=loc) for loc in (['eastus'] if bad else ['eastus', 'westeurope'])]
            deciding = (children, ACR + '/replications')
        elif slug in ('acr_private_endpoint_present', 'acr_private_link_approved'):
            if bad: obj['properties']['privateEndpointConnections'] = []
            deciding = (obj, 'properties.privateEndpointConnections')
        elif slug == 'acr_vnet_service_endpoint':
            if bad: obj['properties']['networkRuleSet']['virtualNetworkRules'] = []
            deciding = (obj, 'properties.networkRuleSet.virtualNetworkRules')
        else: raise AssertionError(cid)
    elif kind == 'container_group':
        var = {'name': 'REVIEW_MODE', 'value': 'plain-public-marker'} if bad else {'name': 'REVIEW_TOKEN', 'secureValue': None}
        obj['properties'].update(osType='Linux', containers=[{'name': 'workload', 'properties': {
            'image': 'mcr.microsoft.com/azuredocs/aci-helloworld:latest', 'resources': {'requests': {'cpu': 1, 'memoryInGB': 1}},
            'environmentVariables': [var]}}], encryptionProperties={'vaultBaseUrl': 'https://native.vault.azure.net', 'keyName': 'review', 'keyVersion': 'v1'},
            subnetIds=[{'id': VNET + '/subnets/containers'}])
        obj['identity'] = {'type': 'SystemAssigned', 'principalId': '33333333-3333-3333-3333-333333333333', 'tenantId': TENANT}
        if slug.endswith('_cmk'):
            if bad: obj['properties']['encryptionProperties'] = None
            deciding = (obj, 'properties.encryptionProperties')
        elif slug.endswith('managed_identity'):
            if bad: obj['identity'] = {'type': 'None'}
            deciding = (obj, 'identity')
        elif slug.endswith('virtual_network'):
            if bad: obj['properties']['subnetIds'] = []
            deciding = (obj, 'properties.subnetIds')
        else: deciding = (obj, 'properties.containers')
    elif kind == 'databricks_workspace':
        obj['sku'] = {'name': 'premium'}
        obj['properties'].update(managedResourceGroupId=SCOPE + '/resourceGroups/native-managed',
            parameters={'customVirtualNetworkId': {'type': 'String', 'value': VNET},
                'customPrivateSubnetName': {'type': 'String', 'value': 'private'},
                'customPublicSubnetName': {'type': 'String', 'value': 'public'}},
            encryption={'entities': {'managedDisk': {'keySource': 'Microsoft.Keyvault',
                'keyVaultProperties': {'keyVaultUri': 'https://native.vault.azure.net', 'keyName': 'disk', 'keyVersion': 'v1'}}}})
        if slug == 'databricks_diagnostic_log_delivery':
            children[DBX + '/providers/Microsoft.Insights/diagnosticSettings'] = [resource(DBX + '/providers/Microsoft.Insights/diagnosticSettings/native', 'Microsoft.Insights/diagnosticSettings', {
                'workspaceId': WORKSPACE, 'logs': [{'category': name, 'enabled': True} for name in (['clusters'] if bad else ['clusters', 'accounts', 'jobs', 'notebook', 'workspace', 'sqlPermissions'])]})]
            deciding = (children, DBX + '/providers/Microsoft.Insights/diagnosticSettings')
        elif slug == 'databricks_managed_disk_cmk':
            if bad: obj['properties']['encryption']['entities'] = {'managedServices': {'keySource': 'Microsoft.Keyvault'}}
            deciding = (obj, 'properties.encryption')
        elif slug == 'databricks_subnet_nsg':
            subnets = [resource(VNET + '/subnets/' + name, 'Microsoft.Network/virtualNetworks/subnets', {
                'addressPrefix': '10.0.' + str(i) + '.0/24', **({'networkSecurityGroup': {'id': NSG_REF}} if not bad or i == 0 else {})}) for i, name in enumerate(('private', 'public'))]
            additional.append(resource(VNET, 'Microsoft.Network/virtualNetworks', {'subnets': subnets}))
            deciding = (obj, 'properties.parameters.customVirtualNetworkId.value')
        else:
            if bad: obj['properties']['parameters']['customVirtualNetworkId']['value'] = ''
            deciding = (obj, 'properties.parameters.customVirtualNetworkId.value')
    elif kind == 'disk':
        state = 'Unattached' if 'unattached' in slug else 'Attached'
        enc = 'EncryptionAtRestWithPlatformAndCustomerKeys' if slug.endswith('double_encryption') else 'EncryptionAtRestWithCustomerKey'
        obj['properties'].update(diskState=state, encryption={'type': 'EncryptionAtRestWithPlatformKey' if bad else enc},
            creationData={'createOption': 'Empty'}, diskSizeGB=32)
        if not bad: obj['properties']['encryption']['diskEncryptionSetId'] = BASE + 'Microsoft.Compute/diskEncryptionSets/native'
        deciding = (obj, 'properties.encryption.type')
    elif kind == 'synapse_workspace':
        obj['properties'].update(defaultDataLakeStorage={'accountUrl': 'https://native.dfs.core.windows.net', 'filesystem': 'synapse'},
            managedResourceGroupName='native-synapse-managed', managedVirtualNetwork='default',
            managedVirtualNetworkSettings={'preventDataExfiltration': True}, encryption={'cmk': {'key': {'name': 'native-key', 'keyVaultUrl': 'https://native.vault.azure.net/keys/native/v1'}}},
            privateEndpointConnections=[resource(SYNAPSE + '/privateEndpointConnections/native', 'Microsoft.Synapse/workspaces/privateEndpointConnections', {'privateLinkServiceConnectionState': {'status': 'Approved'}})])
        if cid in FIELDS:
            path, good, fail = FIELDS[cid]; put(obj, path, fail if bad else good); deciding = (obj, path)
        elif slug == 'synapse_workspace_cmk':
            if bad: obj['properties']['encryption'] = {'doubleEncryptionEnabled': False}
            deciding = (obj, 'properties.encryption')
        elif slug == 'synapse_workspace_private_link':
            if bad: obj['properties']['privateEndpointConnections'] = []
            deciding = (obj, 'properties.privateEndpointConnections')
        else:
            pool = resource(SYNAPSE + '/sqlPools/native', 'Microsoft.Synapse/workspaces/sqlPools', {'status': 'Online'})
            children[SYNAPSE + '/sqlPools'] = [pool]
            children[pool['id'] + '/vulnerabilityAssessments'] = [resource(pool['id'] + '/vulnerabilityAssessments/default', 'Microsoft.Synapse/workspaces/sqlPools/vulnerabilityAssessments', {'recurringScans': {'isEnabled': not bad}})]
            children[SYNAPSE + '/vulnerabilityAssessments'] = [resource(SYNAPSE + '/vulnerabilityAssessments/default', 'Microsoft.Synapse/workspaces/vulnerabilityAssessments', {'recurringScans': {'isEnabled': not bad}})]
            deciding = (children[SYNAPSE + '/vulnerabilityAssessments'][0], 'properties.recurringScans.isEnabled')
    elif kind == 'vm_scale_set':
        obj['sku'] = {'name': 'Standard_D2s_v5', 'capacity': 2}
        children[VMSS + '/virtualMachines'] = [resource(VMSS + '/virtualMachines/' + str(i), 'Microsoft.Compute/virtualMachineScaleSets/virtualMachines', {'instanceId': str(i), 'provisioningState': 'Succeeded'}) for i in range(2)]
        obj['properties'].update(orchestrationMode='Uniform', upgradePolicy={'mode': 'Automatic'},
            virtualMachineProfile={'storageProfile': {'osDisk': {'osType': 'Linux', 'createOption': 'FromImage', 'managedDisk': {'storageAccountType': 'Premium_LRS'}}, 'dataDisks': []},
                'osProfile': {'computerNamePrefix': 'native', 'adminUsername': 'native-user', 'linuxConfiguration': {'disablePasswordAuthentication': True}},
                'diagnosticsProfile': {'bootDiagnostics': {'enabled': True}},
                'networkProfile': {'networkInterfaceConfigurations': [{'name': 'nic', 'properties': {'primary': True,
                    'ipConfigurations': [{'name': 'primary', 'properties': {'subnet': {'id': VNET + '/subnets/scales'},
                        'loadBalancerBackendAddressPools': [{'id': BASE + 'Microsoft.Network/loadBalancers/native/backendAddressPools/pool'}]}}]}}]}})
        if cid in FIELDS:
            path, good, fail = FIELDS[cid]; put(obj, path, fail if bad else good); deciding = (obj, path)
        elif slug == 'vmss_managed_disks':
            if bad: obj['properties']['virtualMachineProfile']['storageProfile']['osDisk'] = {'osType': 'Linux', 'vhdContainers': ['https://native.blob.core.windows.net/vhds']}
            deciding = (obj, 'properties.virtualMachineProfile.storageProfile.osDisk')
        else:
            ip = obj['properties']['virtualMachineProfile']['networkProfile']['networkInterfaceConfigurations'][0]['properties']['ipConfigurations'][0]
            if bad: ip['properties']['loadBalancerBackendAddressPools'] = []
            deciding = (ip, 'properties.loadBalancerBackendAddressPools')
    else: raise AssertionError(cid)
    assert deciding is not None, cid
    if mode == 'missing':
        target, path = deciding
        if target is children:
            children[path] = azure.AzureReadError('missing native child response', 404)
        else: put(target, path, None, remove=True)
    return kind, obj, additional, children


class NativeHTTP:
    tenant = verified_tenant = TENANT
    def __init__(self, cid, mode, kind, obj, additional, children):
        self.cid, self.mode, self.kind = cid, mode, kind
        self.obj, self.objects, self.children = obj, [obj, *additional], children
        self.calls, self.errors = [], []
        self.allowed = {kind} | (set(REGISTRY[cid].dependencies) & set(ENDPOINTS))
    def request(self, url, *, body=None, audience=azure.ARM):
        parts, query = urlsplit(url), parse_qs(urlsplit(url).query)
        method = 'POST' if body is not None else 'GET'
        self.calls.append({'method': method, 'url': url, 'body': deepcopy(body)})
        try:
            assert parts.scheme == 'https' and parts.netloc == 'management.azure.com' and not parts.fragment
            assert audience == azure.ARM and query.get('api-version')
            path = parts.path
            if path == '/providers/Microsoft.ResourceGraph/resources':
                assert method == 'POST' and body['subscriptions'] == [SUB]
                if query['api-version'] == ['2024-04-01']:
                    assert self.kind == 'vm_scale_set' and 'patchassessmentresources' in body['query'] and VMSS.casefold() in body['query']
                    return {'data': [{'id': r['id'] + '/patchAssessmentResults/latest', 'type': r['type'] + '/patchAssessmentResults', 'properties': {'status': 'Succeeded', 'lastModifiedDateTime': '2026-10-20T00:00:00Z', 'availablePatchCountByClassification': {'critical': 0, 'security': 0}}} for r in self.children[VMSS + '/virtualMachines']]}
                assert query['api-version'] == ['2022-10-01']
                return {'data': deepcopy(self.objects)}
            assert method == 'GET' and path.startswith(SCOPE + '/')
            if path == SCOPE + '/resources':
                assert query['api-version'] == ['2021-04-01']; return {'value': deepcopy(self.objects)}
            for kind, (typ, version, rid) in ENDPOINTS.items():
                if path == SCOPE + '/providers/' + typ:
                    assert kind in self.allowed and query['api-version'] == [version]
                    rows = [r for r in self.objects if r['type'].casefold() == typ.casefold()]
                    if kind == self.kind:
                        if self.mode == 'denied': raise azure.AzureReadError('forbidden', 403)
                        if self.mode == 'partial' and query.get('page') == ['2']: raise azure.AzureReadError('forbidden', 403)
                        if self.mode == 'foreign':
                            rows = deepcopy(rows); rows[0]['id'] = rows[0]['id'].replace(SUB, '99999999-9999-9999-9999-999999999999')
                        if self.mode == 'partial': return {'value': deepcopy(rows), 'nextLink': azure.ARM + path + '?api-version=' + version + '&page=2'}
                    return {'value': deepcopy(rows)}
            for row in self.objects:
                if path == row['id']:
                    version = ENDPOINTS[next(k for k, v in ENDPOINTS.items() if v[0].casefold() == row['type'].casefold())][1]
                    assert query['api-version'] == [version] or (path == SITE and query['api-version'] == ['2025-03-01']) or (path == ACR and query['api-version'] == ['2023-11-01-preview'])
                    if self.mode == 'detail-denied' and path == self.obj['id']: raise azure.AzureReadError('forbidden', 403)
                    response = deepcopy(row)
                    if self.mode == 'wrong-detail-type' and path == self.obj['id']: response['type'] = 'Microsoft.Network/networkSecurityGroups'
                    return response
                if path == row['id'] + '/functions':
                    # Function apps (and their slots) list FunctionEnvelope rows natively.
                    site = re.split(r'/slots/', row['id'], maxsplit=1, flags=re.I)[0]
                    owner = next(r for r in self.objects if r['id'].casefold() == site.casefold())
                    assert row['type'].casefold() in ('microsoft.web/sites', 'microsoft.web/sites/slots')
                    assert 'functionapp' in {part.strip().casefold() for part in str(owner.get('kind', '')).split(',')}
                    assert query['api-version'] == ['2025-05-01']
                    value = self.children.get(path, [])
                    if isinstance(value, Exception): raise value
                    return {'value': deepcopy(value)}
                if path == row['id'] + '/providers/Microsoft.Insights/diagnosticSettings':
                    assert query['api-version'] == ['2021-05-01-preview']
                    return {'value': deepcopy(self.children.get(path, []))}
                kind = next(k for k, v in ENDPOINTS.items() if v[0].casefold() == row['type'].casefold())
                for field, suffix, version in azure.EMBEDDED_LISTS.get(kind, ()):
                    if path == row['id'] + '/' + suffix:
                        assert query['api-version'] == [version]
                        value = self.children.get(path, [])
                        if isinstance(value, Exception): raise value
                        if field == 'workspaceVulnerabilityAssessments' and isinstance(value, dict):
                            if query.get('page') == ['2']: raise azure.AzureReadError('forbidden', 403)
                            return deepcopy(value)
                        return {'value': deepcopy(value)}
                for field, suffix, version in azure.EMBEDDED_SINGLETONS.get(kind, ()):
                    if path == row['id'] + '/' + suffix:
                        assert query['api-version'] == [version]
                        value = self.children.get(path, resource(path, row['type'] + '/config', {}))
                        if isinstance(value, Exception): raise value
                        if self.mode == 'child-denied' and path in self.children: raise azure.AzureReadError('forbidden', 403)
                        if self.mode == 'foreign-child' and path in self.children: return {**deepcopy(value), 'id': value['id'] + '-foreign'}
                        if self.mode == 'wrong-child-type' and path in self.children: return {**deepcopy(value), 'type': 'Microsoft.Web/sites/slots'}
                        return deepcopy(value)
            if path == VMSS + '/virtualMachines':
                assert query['api-version'] == ['2024-07-01']
                return {'value': deepcopy(self.children[path])}
            if path in self.children and path.endswith('/vulnerabilityAssessments'):
                assert query['api-version'] == ['2021-06-01']
                value = self.children[path]
                if isinstance(value, Exception): raise value
                return {'value': deepcopy(value)}
            raise AssertionError('Unexpected native route ' + path)
        except azure.AzureReadError: raise
        except AssertionError as exc:
            self.errors.append(str(exc)); raise


def run_case(cid, mode, record_property, *, mutate=None):
    kind, obj, additional, children = native_case(cid, mode)
    if mutate: mutate(obj, additional, children)
    api = NativeHTTP(cid, mode, kind, obj, additional, children)
    snapshot = azure.collect({'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0, 'concurrency': 1}},
                             list(REGISTRY[cid].dependencies), transport=api)
    assert not api.errors, api.errors
    assert validate(snapshot) == snapshot
    before = deepcopy(snapshot)
    report = evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)
    assert before == snapshot
    rows = [r for r in report['findings'] if r['check_id'] == cid]
    assert rows, report
    envelopes = [c for c in snapshot['collections'] if c['type'] == kind]
    record_property('native_receipt', json.dumps({'id': cid, 'mode': mode, 'calls': api.calls,
        'primary_statuses': [c['status'] for c in envelopes], 'statuses': [r['status'] for r in rows],
        'evidence': [r['evidence'] for r in rows]}, sort_keys=True))
    return snapshot, rows


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('mode,expected', [('good', 'PASS'), ('bad', 'FAIL')])
def test_native_each_id_positive_and_negative(cid, mode, expected, record_property):
    _, rows = run_case(cid, mode, record_property)
    assert {r['status'] for r in rows} == {expected}, rows


@pytest.mark.parametrize('cid', IDS)
@pytest.mark.parametrize('mode', ['missing', 'denied', 'partial', 'foreign'])
def test_native_each_id_missing_denied_partial_and_scope(cid, mode, record_property):
    snapshot, rows = run_case(cid, mode, record_property)
    statuses = {r['status'] for r in rows}
    if mode == 'partial':
        assert any(c['status'] == 'partial' for c in snapshot['collections']), snapshot
        assert statuses <= {'UNKNOWN', 'PASS', 'FAIL'}, rows
    elif mode in ('denied', 'foreign'):
        assert statuses <= {'UNKNOWN', 'DENIED'}, rows
    else:
        # An explicitly returned CORS object with omitted allowedOrigins has
        # no cross-origin grants. Other deciding omissions cannot clean PASS.
        allowed = {'PASS'} if cid == 'azure.claude2.api_app_cors_no_wildcard' else {'UNKNOWN', 'FAIL'}
        assert statuses <= allowed, rows


@pytest.mark.parametrize('mode', ['child-denied', 'foreign-child'])
@pytest.mark.parametrize('cid', ['azure.claude2.api_app_min_tls_12', 'azure.claude2.function_app_authentication_enabled', 'azure.app.minimum_tls'])
def test_native_app_child_unavailable_or_foreign_is_unknown(cid, mode, record_property):
    _, rows = run_case(cid, mode, record_property)
    assert {r['status'] for r in rows} <= {'UNKNOWN', 'DENIED'}, rows


@pytest.mark.parametrize('source', ['0.0.0.0/0', '::/0'])
def test_native_function_world_cidr_cannot_clean_pass(source, record_property):
    cid = 'azure.claude2.function_app_restrict_public_access'
    def mutate(obj, additional, children):
        children[SITE + '/config/web']['properties']['ipSecurityRestrictions'] = [{'ipAddress': source, 'action': 'Allow', 'priority': 100}]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {'FAIL'}, rows


@pytest.mark.parametrize('value', [None, []])
def test_native_function_unrestricted_empty_acl_cannot_clean_pass(value, record_property):
    cid = 'azure.claude2.function_app_restrict_public_access'
    def mutate(obj, additional, children):
        cfg = children[SITE + '/config/web']['properties']
        cfg['ipSecurityRestrictions'] = value; cfg.pop('ipSecurityRestrictionsDefaultAction')
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {'FAIL'}, rows


def test_native_synapse_workspace_policy_is_distinct_from_sql_pool_policy(record_property):
    cid = 'azure.claude.synapse_workspace_vulnerability_assessment'
    def mutate(obj, additional, children):
        pool = resource(SYNAPSE + '/sqlPools/unprotected', 'Microsoft.Synapse/workspaces/sqlPools', {'status': 'Online'})
        children[SYNAPSE + '/sqlPools'].append(pool)
        children[pool['id'] + '/vulnerabilityAssessments'] = [resource(pool['id'] + '/vulnerabilityAssessments/default', 'Microsoft.Synapse/workspaces/sqlPools/vulnerabilityAssessments', {'recurringScans': {'isEnabled': False}})]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {'PASS'}, rows


@pytest.mark.parametrize('source', ['2001:db8::/32', '203.0.113.0/24', '10.0.0.0/8'])
def test_native_function_restricted_cidrs_remain_restricted(source, record_property):
    cid = 'azure.claude2.function_app_restrict_public_access'
    def mutate(obj, additional, children):
        children[SITE + '/config/web']['properties']['ipSecurityRestrictions'][0]['ipAddress'] = source
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {'PASS'}, rows


@pytest.mark.parametrize('rules,default,expected', [
    ([], 'Deny', 'PASS'), (None, 'Deny', 'PASS'), ([], 'Allow', 'FAIL'),
    ([{'ipAddress': '203.0.113.0/24', 'action': 'Allow', 'priority': 100}], 'Allow', 'FAIL'),
    ([{'ipAddress': '10.0.0.0/8', 'action': 'Allow', 'priority': 100}], None, 'PASS'),
    ([{'ipAddress': '::/0', 'action': 'Deny', 'priority': 100}], None, 'PASS'),
    ([{'ipAddress': '2001:db8::/32,::/0', 'action': 'Allow', 'priority': 100}], None, 'FAIL'),
    ([{'ipAddress': 'Any', 'action': 'Allow', 'headers': {'x-azure-fdid': ['native-frontdoor']}, 'priority': 100}], None, 'UNKNOWN'),
    ([{'ipAddress': 'AzureFrontDoor.Backend', 'tag': 'ServiceTag', 'action': 'Allow', 'priority': 100}], None, 'UNKNOWN'),
    ([{'ipAddress': 'Any', 'action': 'Deny', 'priority': 100}, {'ipAddress': 'Any', 'action': 'Allow', 'priority': 200}], None, 'UNKNOWN'),
    ([{'ipAddress': {'malformed': True}, 'action': 'Allow', 'priority': 100}], 'Deny', 'UNKNOWN'),
    ([], 'Unsupported', 'UNKNOWN'),
])
def test_native_function_unmatched_and_conditional_matrix(rules, default, expected, record_property):
    cid = 'azure.claude2.function_app_restrict_public_access'
    def mutate(obj, additional, children):
        cfg = children[SITE + '/config/web']['properties']
        cfg['ipSecurityRestrictions'] = deepcopy(rules)
        if default is None: cfg.pop('ipSecurityRestrictionsDefaultAction')
        else: cfg['ipSecurityRestrictionsDefaultAction'] = default
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {expected}, rows


@pytest.mark.parametrize('cid', [cid for cid in IDS if REGISTRY[cid].kind == 'app_service_config'])
@pytest.mark.parametrize('mode', ['foreign-child', 'wrong-child-type'])
def test_native_standalone_configuration_exact_child_binding(cid, mode, record_property):
    _, rows = run_case(cid, mode, record_property)
    assert {r['status'] for r in rows} == {'UNKNOWN'}, rows


@pytest.mark.parametrize('case,expected', [('all-enabled', 'PASS'), ('empty-sibling', 'PASS'), ('denied-sibling', 'PASS'), ('foreign-policy-kind', 'PASS'), ('duplicate-policy', 'PASS'), ('conflicting-policy', 'PASS')])
def test_native_synapse_pool_failures_do_not_change_authoritative_workspace_policy(case, expected, record_property):
    cid = 'azure.claude.synapse_workspace_vulnerability_assessment'
    def mutate(obj, additional, children):
        pool = resource(SYNAPSE + '/sqlPools/second', 'Microsoft.Synapse/workspaces/sqlPools', {'status': 'Online'})
        children[SYNAPSE + '/sqlPools'].append(pool)
        path = pool['id'] + '/vulnerabilityAssessments'
        policy = resource(path + '/default', 'Microsoft.Synapse/workspaces/sqlPools/vulnerabilityAssessments', {'recurringScans': {'isEnabled': True}})
        if case == 'empty-sibling': children[path] = []
        elif case == 'denied-sibling': children[path] = azure.AzureReadError('forbidden', 403)
        elif case == 'foreign-policy-kind': children[path] = [{**policy, 'id': pool['id'] + '/otherKind/default'}]
        elif case == 'duplicate-policy': children[path] = [policy, deepcopy(policy)]
        elif case == 'conflicting-policy':
            conflict = deepcopy(policy); conflict['properties']['recurringScans']['isEnabled'] = False
            children[path] = [policy, conflict]
        else: children[path] = [policy]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {expected}, rows


@pytest.mark.parametrize('cid', [cid for cid in IDS if cid.startswith('azure.claude2.')])
def test_native_app_kind_applicability(cid, record_property):
    def mutate(obj, additional, children):
        obj['kind'] = 'app' if 'function_app' in cid or 'api_app' in cid else 'functionapp,linux'
    _, rows = run_case(cid, 'bad', record_property, mutate=mutate)
    expected = 'FAIL' if cid.endswith('app_workers_more_than_one') else 'NOT_APPLICABLE'
    assert {r['status'] for r in rows} == {expected}, rows


@pytest.mark.parametrize('cid', [cid for cid in IDS if REGISTRY[cid].kind == 'disk'])
def test_native_disk_opposite_attachment_is_not_applicable(cid, record_property):
    def mutate(obj, additional, children):
        obj['properties']['diskState'] = 'Attached' if 'unattached' in cid else 'Unattached'
    _, rows = run_case(cid, 'bad', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {'NOT_APPLICABLE'}, rows


@pytest.mark.parametrize('cid', ['azure.claude.acr_geo_replication', 'azure.claude.databricks_diagnostic_log_delivery', 'azure.claude.vmss_linux_ssh_keys'])
def test_native_sku_or_os_applicability(cid, record_property):
    def mutate(obj, additional, children):
        if 'acr_' in cid: obj['sku']['name'] = 'Standard'
        elif 'databricks_' in cid: obj['sku']['name'] = 'standard'
        else: obj['properties']['virtualMachineProfile']['storageProfile']['osDisk']['osType'] = 'Windows'
    _, rows = run_case(cid, 'bad', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {'NOT_APPLICABLE'}, rows


@pytest.mark.parametrize('cid', [cid for cid in IDS if REGISTRY[cid].kind in ('container_group', 'vm_scale_set')])
def test_native_full_get_wrong_type_cannot_supply_deciding_facts(cid, record_property):
    _, rows = run_case(cid, 'wrong-detail-type', record_property)
    assert {r['status'] for r in rows} == {'UNKNOWN'}, rows


@pytest.mark.parametrize('cid', ['azure.claude.acr_private_endpoint_present', 'azure.claude.acr_private_link_approved'])
def test_native_acr_pending_connection_is_presence_but_not_approval(cid, record_property):
    def mutate(obj, additional, children):
        obj['properties']['privateEndpointConnections'][0]['properties']['privateLinkServiceConnectionState']['status'] = 'Pending'
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    expected = 'PASS' if cid.endswith('present') else 'FAIL'
    assert {r['status'] for r in rows} == {expected}, rows


@pytest.mark.parametrize('cid', ['azure.claude.disk_attached_cmk', 'azure.claude.disk_attached_customer_key', 'azure.claude.disk_unattached_cmk', 'azure.claude.disk_unattached_customer_key'])
def test_native_disk_double_key_is_broad_cmk_but_not_exact_customer_key(cid, record_property):
    def mutate(obj, additional, children):
        obj['properties']['encryption']['type'] = 'EncryptionAtRestWithPlatformAndCustomerKeys'
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    expected = 'PASS' if cid.endswith('_cmk') else 'FAIL'
    assert {r['status'] for r in rows} == {expected}, rows


@pytest.mark.parametrize('cid', ['azure.claude.databricks_subnet_nsg', 'azure.claude.databricks_vnet_injection_value'])
def test_native_databricks_unreturned_or_managed_network_parameters(cid, record_property):
    def mutate(obj, additional, children):
        obj['properties']['parameters'] = None
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {'UNKNOWN'}, rows


@pytest.mark.parametrize('cid', ['azure.claude.container_group_secure_environment_variables', 'azure.claude.vmss_boot_diagnostics', 'azure.cis.app_service_entra_registration_enabled'])
def test_native_deciding_full_get_denial_remains_unresolved(cid, record_property):
    _, rows = run_case(cid, 'detail-denied', record_property)
    assert {r['status'] for r in rows} <= {'UNKNOWN', 'DENIED'}, rows


@pytest.mark.parametrize('case,expected', [('disabled', 'FAIL'), ('empty', 'FAIL'), ('denied', 'UNKNOWN'), ('partial', 'UNKNOWN'), ('foreign-workspace', 'UNKNOWN'), ('pool-policy', 'UNKNOWN'), ('wrong-type', 'UNKNOWN'), ('duplicate-identical', 'PASS'), ('duplicate-conflicting', 'UNKNOWN'), ('mixed-identities', 'UNKNOWN')])
def test_native_synapse_workspace_policy_scope_and_unavailability(case, expected, record_property):
    cid = 'azure.claude.synapse_workspace_vulnerability_assessment'
    def mutate(obj, additional, children):
        path = SYNAPSE + '/vulnerabilityAssessments'
        policy = deepcopy(children[path][0])
        if case == 'disabled': policy['properties']['recurringScans']['isEnabled'] = False
        if case == 'foreign-workspace': policy['id'] = policy['id'].replace('native-synapse/', 'other-workspace/')
        if case == 'pool-policy': policy['id'] = SYNAPSE + '/sqlPools/native/vulnerabilityAssessments/default'
        if case == 'wrong-type': policy['type'] = 'Microsoft.Synapse/workspaces/sqlPools/vulnerabilityAssessments'
        if case == 'empty': children[path] = []
        elif case == 'denied': children[path] = azure.AzureReadError('forbidden', 403)
        elif case == 'partial': children[path] = {'value': [policy], 'nextLink': azure.ARM + path + '?api-version=2021-06-01&page=2'}
        elif case == 'mixed-identities': children[path] = [policy, {**deepcopy(policy), 'id': path + '/other'}]
        elif case.startswith('duplicate-'):
            duplicate = deepcopy(policy)
            if case.endswith('conflicting'): duplicate['properties']['recurringScans']['isEnabled'] = False
            children[path] = [policy, duplicate]
        else: children[path] = [policy]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {expected}, rows




@pytest.mark.parametrize('case', ['empty-nsg-reference', 'foreign-subnet-identity', 'foreign-nsg-reference', 'duplicate-subnet-name'])
def test_native_databricks_subnet_binding_cannot_use_unresolved_association(case, record_property):
    cid = 'azure.claude.databricks_subnet_nsg'
    def mutate(obj, additional, children):
        subnet = additional[0]['properties']['subnets'][0]
        if case == 'empty-nsg-reference': subnet['properties']['networkSecurityGroup'] = {}
        elif case == 'foreign-nsg-reference': subnet['properties']['networkSecurityGroup']['id'] = NSG_REF.replace(SUB, '99999999-9999-9999-9999-999999999999')
        elif case == 'duplicate-subnet-name': additional[0]['properties']['subnets'].append(deepcopy(subnet))
        else: subnet['id'] = BASE + 'Microsoft.Network/virtualNetworks/foreign/subnets/private'
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {r['status'] for r in rows} == {'UNKNOWN'}, rows


def test_native_acr_vnet_declaration_does_not_claim_exclusive_network_access(record_property):
    cid = 'azure.claude.acr_vnet_service_endpoint'
    def mutate(obj, additional, children):
        obj['properties']['publicNetworkAccess'] = 'Enabled'
        obj['properties']['networkRuleSet']['ipRules'] = [{'action': 'Allow', 'value': '0.0.0.0/0'}]
    snapshot, rows = run_case(cid, 'good', record_property, mutate=mutate)
    # This literal upstream criterion observes defaultAction plus VNet presence.
    # The report records the permissive IP rule and requires truthful copy.
    assert {r['status'] for r in rows} == {'PASS'}, rows
    companion = 'azure.claude.acr_public_network_access_disabled'
    findings = [r for r in evaluate_snapshot(snapshot, checks=[companion])['findings'] if r['check_id'] == companion]
    assert {r['status'] for r in findings} == {'FAIL'}, findings
    record_property('native_receipt', json.dumps({'id': companion, 'mode': 'same_native_world_ip_witness',
        'calls': [], 'primary_statuses': [c['status'] for c in snapshot['collections'] if c['type'] == 'container_registry'],
        'statuses': [r['status'] for r in findings], 'evidence': [r['evidence'] for r in findings],
        'native_proof': 'Same already collected finite HTTP snapshot as VNet criterion in this node; no additional provider read.'}, sort_keys=True))
