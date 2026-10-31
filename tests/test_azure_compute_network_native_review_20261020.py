"""Independent, finite ARM responses -> Azure collector -> registered engine.

No CASES, saved snapshots, callback outputs or production credentials construct
the responses. CSV selects the assigned cohort only; native fixtures below set
the security facts. Red assertions intentionally preserve genuine counterexamples.
"""
from copy import deepcopy
import json
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
BASE = SCOPE + '/resourceGroups/native-review/providers/'
VM = BASE + 'Microsoft.Compute/virtualMachines/native-vm'
NSG = BASE + 'Microsoft.Network/networkSecurityGroups/native-nsg'
NIC = BASE + 'Microsoft.Network/networkInterfaces/native-nic'
VNET = BASE + 'Microsoft.Network/virtualNetworks/native-vnet'
SUBNET = VNET + '/subnets/workload'
PIP = BASE + 'Microsoft.Network/publicIPAddresses/native-pip'
VAULT = BASE + 'Microsoft.RecoveryServices/vaults/native-vault'
WATCHER = BASE + 'Microsoft.Network/networkWatchers/native-watcher'
WORKSPACE = BASE + 'Microsoft.OperationalInsights/workspaces/native-workspace'
REGISTRY = {check.id: check for check in CHECKS}
with open('tests/fixtures/azure_vm_nsg_check_ids.json') as stream:
    ASSIGNED = tuple(json.load(stream))

GUEST = {
    'vm_linux_no_passwordless_accounts': ('Linux', 'PasswordPolicy_msid232'),
    'vm_linux_remote_requires_password': ('Linux', 'PasswordPolicy_msid110'),
    'vm_linux_security_baseline': ('Linux', 'AzureLinuxBaseline'),
    'vm_windows_exploit_guard': ('Windows', 'WindowsDefenderExploitGuard'),
    'vm_windows_max_password_age': ('Windows', 'MaximumPasswordAge'),
    'vm_windows_min_password_age': ('Windows', 'MinimumPasswordAge'),
    'vm_windows_min_password_length': ('Windows', 'MinimumPasswordLength'),
    'vm_windows_no_reversible_password_encryption': ('Windows', 'StorePasswordsUsingReversibleEncryption'),
    'vm_windows_password_complexity': ('Windows', 'PasswordMustMeetComplexityRequirements'),
    'vm_windows_password_history': ('Windows', 'EnforcePasswordHistory'),
    'vm_windows_secure_protocol_tls13': ('Windows', 'AuditSecureProtocol'),
    'vm_windows_security_baseline': ('Windows', 'AzureWindowsBaseline'),
    'vm_linux_ssh_key_only_guest_config': ('Linux', 'LinuxNoPasswordForSSH'),
}
EXTENSIONS = {
    'vm_guest_configuration_extension': ('Linux', 'Microsoft.GuestConfiguration', 'ConfigurationforLinux', 'AzurePolicyforLinux'),
    'vm_guest_configuration_extension_linux': ('Linux', 'Microsoft.GuestConfiguration', 'ConfigurationforLinux', 'AzurePolicyforLinux'),
    'vm_guest_configuration_extension_windows': ('Windows', 'Microsoft.GuestConfiguration', 'ConfigurationforWindows', 'AzurePolicyforWindows'),
    'vm_antimalware_extension': ('Windows', 'Microsoft.Azure.Security', 'IaaSAntimalware', 'IaaSAntimalware'),
    'vm_antimalware_auto_upgrade': ('Windows', 'Microsoft.Azure.Security', 'IaaSAntimalware', 'IaaSAntimalware'),
    'vm_dependency_agent_linux': ('Linux', 'Microsoft.Azure.Monitoring.DependencyAgent', 'DependencyAgentLinux', 'DependencyAgentLinux'),
    'vm_dependency_agent_windows': ('Windows', 'Microsoft.Azure.Monitoring.DependencyAgent', 'DependencyAgentWindows', 'DependencyAgentWindows'),
}


@pytest.fixture(autouse=True)
def no_network_or_auth(monkeypatch):
    attempts = []
    def blocked(*args, **kwargs):
        attempts.append('prohibited network/auth')
        raise AssertionError('Native Azure review forbids network, DNS and credentials')
    for name in ('create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, blocked)
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(azure, 'credential_for', blocked)
    monkeypatch.setattr(azure, 'AzureTransport', blocked)
    yield
    assert not attempts


def resource(rid, kind, properties):
    return {'id': rid, 'name': rid.rsplit('/', 1)[1], 'type': kind,
            'location': 'eastus', 'etag': '"native-generation-1"', 'properties': properties}


def rule(name, *, priority=200, access='Allow', protocol='Tcp', port='22',
         source='Internet', destination='*', source_port='*', direction='Inbound'):
    return resource(NSG + '/securityRules/' + name, 'Microsoft.Network/networkSecurityGroups/securityRules', {
        'priority': priority, 'access': access, 'direction': direction, 'protocol': protocol,
        'sourceAddressPrefix': source, 'destinationAddressPrefix': destination,
        'sourcePortRange': source_port, 'destinationPortRange': port})


def defaults():
    specs = [('AllowVnetInBound', 65000, 'Inbound', 'Allow', 'VirtualNetwork', 'VirtualNetwork'),
             ('AllowAzureLoadBalancerInBound', 65001, 'Inbound', 'Allow', 'AzureLoadBalancer', '*'),
             ('DenyAllInBound', 65500, 'Inbound', 'Deny', '*', '*'),
             ('AllowVnetOutBound', 65000, 'Outbound', 'Allow', 'VirtualNetwork', 'VirtualNetwork'),
             ('AllowInternetOutBound', 65001, 'Outbound', 'Allow', '*', 'Internet'),
             ('DenyAllOutBound', 65500, 'Outbound', 'Deny', '*', '*')]
    rows = []
    for name, priority, direction, access, source, destination in specs:
        row = rule(name, priority=priority, access=access, direction=direction, protocol='*',
                   source=source, destination=destination, port='*')
        row['id'] = NSG + '/defaultSecurityRules/' + name
        row['type'] = 'Microsoft.Network/networkSecurityGroups/defaultSecurityRules'
        rows.append(row)
    return rows


def nsg_target(cid):
    suffix = cid.split('.')[-1]
    protocol = 'Udp' if 'udp' in suffix else 'Icmp' if suffix.endswith('icmp') else 'Tcp'
    if suffix.rsplit('_', 1)[-1].isdigit(): port = suffix.rsplit('_', 1)[-1]
    elif 'rdp' in suffix: port = '3389'
    elif 'http' in suffix: port = '80'
    elif 'udp_services' in suffix: port = '53'
    elif 'udp_any' in suffix: port = '5000'
    elif 'common_ports' in suffix: port = '9200'
    elif suffix.endswith(('icmp', 'all_ports_tcp_udp', 'outbound_restricted')): port = '*'
    else: port = '22'
    return protocol, port


def extension(publisher, kind, name):
    return resource(VM + '/extensions/' + name, 'Microsoft.Compute/virtualMachines/extensions', {
        'publisher': publisher, 'type': kind, 'typeHandlerVersion': '1.0',
        'provisioningState': 'Succeeded', 'autoUpgradeMinorVersion': True})


def assignment(config, *, state='Compliant'):
    return resource(VM + '/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/' + config,
                    'Microsoft.GuestConfiguration/guestConfigurationAssignments', {
        'complianceStatus': state, 'provisioningState': 'Succeeded',
        'lastComplianceStatusChecked': '2026-10-20T01:00:00Z',
        'guestConfiguration': {'name': config, 'version': '1.0.0',
            'configurationParameter': [{'name': 'MinimumTLSVersion', 'value': '1.3'}]}})


def native_case(cid, bad=False):
    """Native service response data. No evaluator fixtures or helper builders."""
    check, slug = REGISTRY[cid], cid.split('.')[-1]
    os_type = GUEST.get(slug, EXTENSIONS.get(slug, ('Linux',)))[0]
    if slug.startswith('vm_windows_'): os_type = 'Windows'
    vm = resource(VM, 'Microsoft.Compute/virtualMachines', {
        'provisioningState': 'Succeeded', 'vmId': '33333333-3333-3333-3333-333333333333',
        'hardwareProfile': {'vmSize': 'Standard_D2s_v5'},
        'storageProfile': {'osDisk': {'osType': os_type, 'name': 'os',
             'managedDisk': {'id': BASE + 'Microsoft.Compute/disks/os'}}, 'dataDisks': [],
             'imageReference': {'publisher': 'MicrosoftWindowsServer' if os_type == 'Windows' else 'Canonical',
                                'offer': 'WindowsServer' if os_type == 'Windows' else 'ubuntu-24_04-lts',
                                'sku': '2022-datacenter-azure-edition' if os_type == 'Windows' else 'server', 'version': 'latest'}},
        'securityProfile': {'encryptionAtHost': True, 'securityType': 'TrustedLaunch',
                            'uefiSettings': {'secureBootEnabled': True, 'vTpmEnabled': True}},
        'osProfile': {'computerName': 'native-vm', 'adminUsername': 'native-user',
                     'linuxConfiguration': {'disablePasswordAuthentication': True, 'ssh': {'publicKeys': []}},
                     'windowsConfiguration': {'enableAutomaticUpdates': True}},
        'networkProfile': {'networkInterfaces': [{'id': NIC, 'properties': {'primary': True}}]},
        'instanceView': {'statuses': [{'code': 'PowerState/running'}]}})
    # Real VM models have only their applicable OS configuration container.
    vm['properties']['osProfile'].pop('linuxConfiguration' if os_type == 'Windows' else 'windowsConfiguration')
    vm['identity'] = {'type': 'SystemAssigned', 'principalId': '44444444-4444-4444-4444-444444444444', 'tenantId': TENANT}
    nsg = resource(NSG, 'Microsoft.Network/networkSecurityGroups', {
        'provisioningState': 'Succeeded', 'securityRules': [], 'defaultSecurityRules': defaults(),
        'subnets': [{'id': SUBNET}], 'networkInterfaces': [{'id': NIC}]})
    subnet = resource(SUBNET, 'Microsoft.Network/virtualNetworks/subnets', {
        'addressPrefix': '10.0.0.0/24', 'networkSecurityGroup': {'id': NSG}, 'ipConfigurations': [{'id': NIC + '/ipConfigurations/primary'}]})
    nic = resource(NIC, 'Microsoft.Network/networkInterfaces', {
        'provisioningState': 'Succeeded', 'enableIPForwarding': False,
        'networkSecurityGroup': {'id': NSG}, 'virtualMachine': {'id': VM},
        'ipConfigurations': [{'id': NIC + '/ipConfigurations/primary', 'name': 'primary', 'properties': {
            'privateIPAddress': '10.0.0.4', 'privateIPAllocationMethod': 'Static', 'subnet': {'id': SUBNET}}}]})
    vnet = resource(VNET, 'Microsoft.Network/virtualNetworks', {'addressSpace': {'addressPrefixes': ['10.0.0.0/16']},
                    'subnets': [subnet], 'virtualNetworkPeerings': []})
    objects = [vm, nsg, nic, vnet]
    children = {VM + '/extensions': [], VM + '/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments': []}
    diagnostics = VM if check.kind == 'vm' else NSG
    if slug in EXTENSIONS:
        _, publisher, kind, name = EXTENSIONS[slug]
        children[VM + '/extensions'] = [] if bad else [extension(publisher, kind, name)]
    elif slug in GUEST:
        children[VM + '/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments'] = [assignment(GUEST[slug][1], state='NonCompliant' if bad else 'Compliant')]
    elif slug.startswith('vm_guest_configuration_') and slug.endswith(('managed_identity', 'system_identity', 'user_and_system_identity')):
        children[VM + '/extensions'] = [extension('Microsoft.GuestConfiguration', 'ConfigurationforLinux', 'AzurePolicyforLinux')]
        if slug.endswith('user_and_system_identity'):
            vm['identity']['type'] = 'UserAssigned' if bad else 'SystemAssigned, UserAssigned'
            vm['identity']['userAssignedIdentities'] = {BASE + 'Microsoft.ManagedIdentity/userAssignedIdentities/native': {}}
        elif bad: vm['identity'] = {'type': 'None'}
    elif slug in ('vm_encryption_at_host', 'encryption_at_host'):
        vm['properties']['securityProfile']['encryptionAtHost'] = not bad
    elif slug in ('vm_trusted_launch_secure_boot_vtpm', 'trusted_launch', 'vm_windows_secure_boot'):
        vm['properties']['securityProfile']['uefiSettings']['secureBootEnabled'] = not bad
    elif slug == 'vm_windows_automatic_updates':
        vm['properties']['osProfile']['windowsConfiguration']['enableAutomaticUpdates'] = not bad
    elif slug == 'linux_ssh_keys':
        vm['properties']['osProfile']['linuxConfiguration']['disablePasswordAuthentication'] = not bad
    elif slug in ('vm_os_managed_disk', 'managed_disks'):
        if bad:
            disk = vm['properties']['storageProfile']['osDisk']
            disk.pop('managedDisk'); disk['vhd'] = {'uri': 'https://nativevhds.blob.core.windows.net/vhds/os.vhd'}
    elif cid == 'azure_vm_app_function_identity_is_configured_bdb10d4':
        if bad: vm['identity'] = {'type': 'None'}
    elif cid == 'azure_vm_8_2_1_1_712e1ad':
        if bad: vm['properties']['osProfile']['linuxConfiguration']['ssh']['publicKeys'] = [{'path': '/home/native-user/.ssh/authorized_keys', 'keyData': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG5hdGl2ZXJldmlld25vbnNlY3JldHB1YmtleQ== native'}]
    elif slug == 'vm_no_public_ip':
        if bad: nic['properties']['ipConfigurations'][0]['properties']['publicIPAddress'] = {'id': PIP}
    elif slug == 'vm_nic_ip_forwarding_disabled':
        nic['properties']['enableIPForwarding'] = bad
    elif slug in ('vm_nic_nsg_internet_tcp_ingress', 'vm_nsg_internet_management_ports', 'compute_vm_remote_access_restricted_all_ports'):
        if bad: nsg['properties']['securityRules'] = [rule('InternetManagement', protocol='*', port='*')]
        if slug == 'compute_vm_remote_access_restricted_all_ports':
            nsg['properties']['securityRules'] = [rule('DeclaredDenyAll', priority=300, access='Deny', protocol='*', source='*', port='*')]
            if bad:
                nsg['properties']['securityRules'].insert(0, rule('DeclaredPublicAllow', priority=200, protocol='*', source='*', port='*'))
    elif slug == 'compute_vm_tcp_udp_access_restricted_internet':
        nic['properties']['ipConfigurations'][0]['properties']['publicIPAddress'] = {'id': PIP}
        objects.append(resource(PIP, 'Microsoft.Network/publicIPAddresses', {'ipAddress': '8.8.8.8', 'ipConfiguration': {'id': NIC + '/ipConfigurations/primary'}}))
        if bad:
            nic['properties'].pop('networkSecurityGroup'); subnet['properties'].pop('networkSecurityGroup')
    elif slug in ('vm_backup_protected', 'vm_backup_daily_retention_7_days'):
        objects.append(resource(VAULT, 'Microsoft.RecoveryServices/vaults', {'provisioningState': 'Succeeded'}))
        policy = VAULT + '/backupPolicies/native'
        children[VAULT + '/backupProtectedItems'] = [] if bad and slug == 'vm_backup_protected' else [resource(
            VAULT + '/backupFabrics/Azure/protectionContainers/iaasvmcontainer;iaasvmcontainerv2;rg;native-vm/protectedItems/VM;iaasvmcontainerv2;rg;native-vm',
            'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems', {
                'protectedItemType': 'Microsoft.Compute/virtualMachines', 'backupManagementType': 'AzureIaasVM',
                'workloadType': 'VM', 'sourceResourceId': VM, 'policyId': policy, 'protectionState': 'Protected'})]
        children[VAULT + '/backupPolicies'] = [resource(policy, 'Microsoft.RecoveryServices/vaults/backupPolicies', {
            'backupManagementType': 'AzureIaasVM', 'retentionPolicy': {'retentionPolicyType': 'LongTermRetentionPolicy',
                'dailySchedule': {'retentionDuration': {'count': 5 if bad else 7, 'durationType': 'Days'}}}})]
    elif slug in ('nsg_flow_log_configured', 'nsg_flow_log_retention_90'):
        objects.append(resource(WATCHER, 'Microsoft.Network/networkWatchers', {'provisioningState': 'Succeeded'}))
        children[WATCHER + '/flowLogs'] = [] if bad and slug == 'nsg_flow_log_configured' else [resource(
            WATCHER + '/flowLogs/native-flow', 'Microsoft.Network/networkWatchers/flowLogs', {
                'targetResourceId': NSG, 'enabled': True, 'storageId': BASE + 'Microsoft.Storage/storageAccounts/nativeflow',
                'retentionPolicy': {'enabled': True, 'days': 30 if bad else 90}})]
    elif slug == 'vm_jit_access':
        objects.append(resource(BASE + 'Microsoft.Security/locations/eastus/jitNetworkAccessPolicies/native',
            'Microsoft.Security/locations/jitNetworkAccessPolicies', {'provisioningState': 'Succeeded',
                'virtualMachines': [] if bad else [{'id': VM, 'ports': [{'number': 22, 'protocol': '*', 'allowedSourceAddressPrefix': '*', 'maxRequestAccessDuration': 'PT3H'}]}]}))
    elif slug == 'vm_site_recovery_enabled':
        objects.append(resource(VM + '/providers/Microsoft.Resources/links/' + ('Other' if bad else 'ASR-Protect-native'),
            'Microsoft.Resources/links', {'sourceId': VM, 'targetId': VAULT, 'notes': 'native recovery link'}))
    elif slug in ('nsg_associated_with_subnet',) or cid == 'azure_pci_1_2_8_39':
        if bad: nsg['properties'].update(subnets=[], networkInterfaces=[])
    elif slug == 'nsg_diagnostic_logging' or cid == 'azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679':
        children[diagnostics + '/providers/Microsoft.Insights/diagnosticSettings'] = [] if bad else [resource(
            diagnostics + '/providers/Microsoft.Insights/diagnosticSettings/native', 'Microsoft.Insights/diagnosticSettings', {
                'workspaceId': WORKSPACE, 'logs': [{'categoryGroup': 'allLogs', 'enabled': True}],
                'metrics': [{'category': 'AllMetrics', 'enabled': True}]})]
    elif check.kind == 'nsg':
        protocol, port = nsg_target(cid)
        if slug == 'nsg_outbound_restricted':
            if not bad: nsg['properties']['securityRules'] = [rule('DenyInternetEgress', priority=100, access='Deny', direction='Outbound', protocol='*', source='*', destination='Internet', port='*')]
        elif bad: nsg['properties']['securityRules'] = [rule('InternetTarget', protocol=protocol, port=port)]
    else:
        raise AssertionError('Unaccounted assigned ID: ' + cid)
    return objects, children


class NativeARM:
    tenant = verified_tenant = TENANT
    def __init__(self, objects, children, cid, mode):
        self.objects, self.children, self.cid, self.mode = objects, children, cid, mode
        self.calls, self.errors = [], []
        self.primary = VM if REGISTRY[cid].kind == 'vm' else NSG
        self.primary_type = 'Microsoft.Compute/virtualMachines' if self.primary == VM else 'Microsoft.Network/networkSecurityGroups'
        self.allowed_kinds = set(REGISTRY[cid].dependencies)
        for child, parent in [('flow_log', 'network_watcher'), ('backup_protected_item', 'recovery_vault'),
                              ('backup_policy', 'recovery_vault'), ('subnet', 'vnet')]:
            if child in self.allowed_kinds: self.allowed_kinds.add(parent)

    def request(self, url, *, body=None, audience=azure.ARM):
        p, query = urlsplit(url), parse_qs(urlsplit(url).query)
        method = 'POST' if body is not None else 'GET'
        self.calls.append({'method': method, 'url': url, 'body': deepcopy(body)})
        try:
            assert p.scheme == 'https' and p.netloc == 'management.azure.com' and not p.fragment
            assert audience == azure.ARM and query.get('api-version')
            path = p.path
            if path == '/providers/Microsoft.ResourceGraph/resources':
                assert method == 'POST' and body['subscriptions'] == [SUB]
                assert query['api-version'] == ['2022-10-01']
                return {'data': deepcopy(self.objects)}
            assert method == 'GET' and path.startswith(SCOPE + '/')
            if path == SCOPE + '/resources':
                assert query['api-version'] == ['2021-04-01']
                return {'value': deepcopy(self.objects)}
            for kind, (endpoint, version) in azure.ENDPOINTS.items():
                if path == SCOPE + '/providers/' + endpoint:
                    assert kind in self.allowed_kinds, ('unselected native inventory', kind)
                    assert query['api-version'] == [version]
                    if kind in ('vm', 'nsg', 'nic', 'vnet', 'public_ip', 'load_balancer', 'network_watcher'):
                        assert query['api-version'] == ['2023-09-01']
                    rows = [r for r in self.objects if r['type'].casefold() == endpoint.casefold()
                            or (kind == 'jit_network_access_policy' and r['type'] == 'Microsoft.Security/locations/jitNetworkAccessPolicies')]
                    if endpoint == self.primary_type:
                        if self.mode == 'denied': raise azure.AzureReadError('forbidden', 403)
                        if self.mode == 'partial' and query.get('page') == ['2']: raise azure.AzureReadError('forbidden', 403)
                        if self.mode == 'foreign-list':
                            rows = deepcopy(rows)
                            rows[0]['id'] = rows[0]['id'].replace(SUB, '99999999-9999-9999-9999-999999999999')
                        if self.mode == 'partial': return {'value': deepcopy(rows), 'nextLink': azure.ARM + path + '?api-version=' + version + '&page=2'}
                    return {'value': deepcopy(rows)}
            for item in self.objects:
                if path == item['id']:
                    if path == self.primary:
                        assert query['api-version'] == ['2023-09-01']
                        if path == VM: assert query.get('$expand') == ['instanceView']
                        if self.mode == 'missing': return {k: deepcopy(v) for k, v in item.items() if k != 'properties'}
                        if self.mode == 'foreign-detail': return {**deepcopy(item), 'id': item['id'] + '-foreign'}
                        if self.mode == 'wrong-detail-type': return {**deepcopy(item), 'type': 'Microsoft.Storage/storageAccounts'}
                    return deepcopy(item)
                if path == item['id'] + '/providers/Microsoft.Insights/diagnosticSettings':
                    assert query['api-version'] == ['2021-05-01-preview']
                    return {'value': deepcopy(self.children.get(path, []))}
                for field, suffix, version in azure.EMBEDDED_LISTS.get(next((k for k, v in azure.ENDPOINTS.items() if v[0].casefold() == item['type'].casefold()), ''), ()):
                    if path == item['id'] + '/' + suffix:
                        assert query['api-version'] == [version]
                        if self.mode == 'child-denied' and path in self.children: raise azure.AzureReadError('forbidden', 403)
                        return {'value': deepcopy(self.children.get(path, []))}
            if path == VM + '/instanceView':
                assert query['api-version'] == ['2023-09-01']
                return {'statuses': [{'code': 'PowerState/running'}]}
            if path == SUBNET:
                assert query['api-version'] == ['2023-09-01']
                vnet = next(row for row in self.objects if row['id'] == VNET)
                return deepcopy(vnet['properties']['subnets'][0])
            # These exact derived inventories use independent service list routes.
            if path == SCOPE + '/providers/Microsoft.Resources/links':
                return {'value': deepcopy([r for r in self.objects if r['type'] == 'Microsoft.Resources/links'])}
            raise AssertionError('Unexpected native read: ' + path)
        except azure.AzureReadError:
            raise
        except AssertionError as exc:
            self.errors.append(str(exc)); raise


def run_case(cid, mode, record_property, *, mutate=None):
    objects, children = native_case(cid, mode == 'bad')
    wire_mode = mode
    if mode == 'missing':
        # Remove a deciding native fact, not unrelated VM model fields when
        # an independently read child can already prove a declared relation.
        populated = [(path, rows) for path, rows in children.items() if rows]
        if populated:
            path, child_rows = populated[0]
            if path.endswith('/backupProtectedItems'):
                child_rows[0]['properties'].pop('sourceResourceId')
            elif path.endswith('/flowLogs'):
                child_rows[0]['properties'].pop('targetResourceId')
            else:
                child_rows[0].pop('properties')
            wire_mode = 'missing-child-fact'
        elif cid.endswith('vm_jit_access'):
            next(row for row in objects if 'jitNetworkAccessPolicies' in row['type'])['properties'].pop('virtualMachines')
            wire_mode = 'missing-child-fact'
        elif cid.endswith('vm_site_recovery_enabled'):
            next(row for row in objects if row['type'] == 'Microsoft.Resources/links')['properties'].pop('sourceId')
            wire_mode = 'missing-child-fact'
    if mutate: mutate(objects, children)
    api = NativeARM(objects, children, cid, wire_mode)
    snapshot = azure.collect({'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0, 'concurrency': 1}},
                             list(REGISTRY[cid].dependencies), transport=api)
    assert not api.errors, api.errors
    assert validate(snapshot) == snapshot
    before = deepcopy(snapshot)
    findings = evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)['findings']
    assert before == snapshot
    rows = [row for row in findings if row['check_id'] == cid]
    assert rows, findings
    record_property('native_receipt', json.dumps({'id': cid, 'mode': mode, 'calls': api.calls,
        'statuses': [row['status'] for row in rows], 'evidence': [row['evidence'] for row in rows]}, sort_keys=True))
    return snapshot, rows


@pytest.mark.parametrize('cid', ASSIGNED)
@pytest.mark.parametrize('mode,expected', [('good', 'PASS'), ('bad', 'FAIL'), ('missing', 'UNKNOWN'),
                                         ('partial', 'UNKNOWN'), ('foreign-list', 'UNKNOWN'), ('foreign-detail', 'UNKNOWN')])
def test_native_per_id_security_and_binding_matrix(cid, mode, expected, record_property):
    _, rows = run_case(cid, mode, record_property)
    statuses = {row['status'] for row in rows}
    if mode in ('partial', 'foreign-detail'):
        # Coverage must be unresolved. An independently returned resource or
        # child relationship may still carry a separate measured result.
        assert 'UNKNOWN' in statuses and statuses <= {'UNKNOWN', 'PASS', 'FAIL'}, rows
    else:
        assert statuses == {expected}, rows


@pytest.mark.parametrize('cid', ASSIGNED)
def test_native_primary_permission_denied_never_clean(cid, record_property):
    _, rows = run_case(cid, 'denied', record_property)
    assert {row['status'] for row in rows} <= {'UNKNOWN', 'DENIED'}, rows


@pytest.mark.parametrize('cid', ['azure.claude.nsg_internet_ssh', 'azure.gap.nsg_declared_internet_ssh'])
@pytest.mark.parametrize('narrow,expected', [(False, 'PASS'), (True, 'FAIL')])
def test_native_priority_shadow_and_declaration_distinction(cid, narrow, expected, record_property):
    def mutate(objects, children):
        nsg = next(row for row in objects if row['id'] == NSG)
        nsg['properties']['securityRules'] = [rule('Deny', access='Deny', priority=100, source_port='80' if narrow else '*'), rule('Allow')]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    wanted = 'FAIL' if '.gap.' in cid else expected
    assert {row['status'] for row in rows} == {wanted}, rows


@pytest.mark.parametrize('cid', ['azure.claude.vm_guest_configuration_extension_linux', 'azure.claude.vm_windows_min_password_length', 'azure.claude2.vm_linux_ssh_key_only_guest_config'])
def test_native_denied_extension_or_guest_assignment_is_unknown(cid, record_property):
    _, rows = run_case(cid, 'child-denied', record_property)
    assert {row['status'] for row in rows} == {'UNKNOWN'}, rows


@pytest.mark.parametrize('cid', ['azure.vm.encryption_at_host', 'azure.claude.nsg_internet_ssh'])
def test_native_primary_resource_type_contradiction_never_clean(cid, record_property):
    # LIST is coherent; only the exact selected GET body contradicts its type.
    _, rows = run_case(cid, 'wrong-detail-type', record_property)
    assert {row['status'] for row in rows} == {'UNKNOWN'}, rows


def test_native_wrong_child_route_cannot_install_guest_extension(record_property):
    cid = 'azure.claude.vm_guest_configuration_extension_linux'
    def mutate(objects, children):
        child = children[VM + '/extensions'][0]
        child['id'] = VM + '/unrelatedChildren/AzurePolicyforLinux'
        child['type'] = 'Microsoft.Compute/virtualMachines/unrelatedChildren'
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'UNKNOWN'}, rows


def test_native_disabled_nsg_flow_log_is_not_capture(record_property):
    cid = 'azure.claude2.nsg_flow_log_configured'
    def mutate(objects, children):
        children[WATCHER + '/flowLogs'][0]['properties']['enabled'] = False
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'FAIL'}, rows


OS_ONLY = tuple('azure.claude.' + slug for slug in GUEST if not slug.endswith('key_only_guest_config')) + (
    'azure.claude2.vm_linux_ssh_key_only_guest_config', 'azure.vm.linux_ssh_keys',
    'azure.claude.vm_windows_automatic_updates', 'azure.claude.vm_windows_secure_boot',
    *(('azure.claude.' + slug) for slug in EXTENSIONS if slug not in ('vm_guest_configuration_extension', 'vm_antimalware_extension')))


@pytest.mark.parametrize('cid', OS_ONLY)
def test_native_opposite_os_applicability(cid, record_property):
    def mutate(objects, children):
        vm = next(row for row in objects if row['id'] == VM)
        disk = vm['properties']['storageProfile']['osDisk']
        disk['osType'] = 'Linux' if disk['osType'] == 'Windows' else 'Windows'
        vm['properties']['osProfile'] = {'linuxConfiguration': {'disablePasswordAuthentication': True}} if disk['osType'] == 'Linux' else {'windowsConfiguration': {'enableAutomaticUpdates': True}}
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'NOT_APPLICABLE'}, rows


@pytest.mark.parametrize('cid', ['azure.claude.nsg_internet_ssh', 'azure.gap.nsg_declared_internet_ssh', 'azure.network.restrict_internet_ingress'])
def test_native_augmented_ipv6_rule_cannot_clean_pass(cid, record_property):
    def mutate(objects, children):
        nsg = next(row for row in objects if row['id'] == NSG)
        item = rule('AugmentedIPv6')
        props = item['properties']
        props.pop('sourceAddressPrefix'); props['sourceAddressPrefixes'] = ['10.0.0.0/8', '::/0']
        props.pop('destinationPortRange'); props['destinationPortRanges'] = ['22', '3389']
        nsg['properties']['securityRules'] = [item]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'FAIL'}, rows


@pytest.mark.parametrize('cid', ['azure.claude.nsg_internet_ssh', 'azure.gap.nsg_declared_internet_ssh'])
def test_native_selected_nsg_source_field_missing_is_unknown(cid, record_property):
    def mutate(objects, children):
        nsg = next(row for row in objects if row['id'] == NSG)
        item = rule('UnknownSource'); item['properties'].pop('sourceAddressPrefix')
        nsg['properties']['securityRules'] = [item]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'UNKNOWN'}, rows


@pytest.mark.parametrize('variant', ['foreign-vm', 'foreign-kind', 'nested-route', 'missing-type',
                                    'missing-properties', 'duplicate', 'case-alias-duplicate', 'malformed-publisher'])
def test_native_extension_child_binding_and_malformed_matrix(variant, record_property):
    cid = 'azure.claude.vm_guest_configuration_extension_linux'
    def mutate(objects, children):
        rows = children[VM + '/extensions']; child = rows[0]
        if variant == 'foreign-vm': child['id'] = child['id'].replace('/native-vm/', '/foreign-vm/')
        elif variant == 'foreign-kind': child['type'] = 'Microsoft.Compute/virtualMachines/unrelatedChildren'
        elif variant == 'nested-route': child['id'] += '/nested/child'
        elif variant == 'missing-type': child.pop('type')
        elif variant == 'missing-properties': child.pop('properties')
        elif variant == 'malformed-publisher': child['properties']['publisher'] = 1
        else:
            rows.append(deepcopy(child))
            if variant == 'case-alias-duplicate': rows[-1]['id'] = rows[-1]['id'].upper()
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'UNKNOWN'}, rows


def test_native_extension_projection_drops_protected_and_public_settings(record_property):
    cid = 'azure.claude.vm_guest_configuration_extension_linux'
    def mutate(objects, children):
        props = children[VM + '/extensions'][0]['properties']
        props['settings'] = {'not-retained': 'native-extension-private-marker'}
        props['protectedSettings'] = {'not-retained': 'native-extension-private-marker'}
    snapshot, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'PASS'}, rows
    assert 'native-extension-private-marker' not in json.dumps(snapshot)


@pytest.mark.parametrize('variant,expected', [('enabled', 'PASS'), ('disabled', 'FAIL'), ('missing-enabled', 'UNKNOWN'),
                                            ('malformed-enabled', 'UNKNOWN'), ('reference-only', 'FAIL'),
                                            ('vnet-successor', 'PASS'), ('denied', 'UNKNOWN')])
def test_native_flow_capture_requires_enabled_authoritative_row(variant, expected, record_property):
    cid = 'azure.claude2.nsg_flow_log_configured'
    def mutate(objects, children):
        flow = children[WATCHER + '/flowLogs'][0]
        if variant == 'disabled': flow['properties']['enabled'] = False
        elif variant == 'missing-enabled': flow['properties'].pop('enabled')
        elif variant == 'malformed-enabled': flow['properties']['enabled'] = 'true'
        elif variant == 'vnet-successor': flow['properties']['targetResourceId'] = VNET
        elif variant == 'reference-only':
            nsg = next(row for row in objects if row['id'] == NSG)
            nsg['properties']['flowLogs'] = [{'id': flow['id']}]
            children[WATCHER + '/flowLogs'] = []
    _, rows = run_case(cid, 'child-denied' if variant == 'denied' else 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {expected}, rows


@pytest.mark.parametrize('source,expected', [('::/0', 'FAIL'), ('0:0:0:0:0:0:0:0/0', 'FAIL'),
                                          ('2001:db8::/32', 'PASS'), ('::/128', 'PASS'),
                                          ('10.0.0.0/8', 'PASS')])
@pytest.mark.parametrize('cid', ['azure.claude.nsg_internet_ssh', 'azure.gap.nsg_declared_internet_ssh',
                               'azure.claude.vm_nic_nsg_internet_tcp_ingress', 'azure.network.restrict_internet_ingress'])
def test_native_world_ipv6_equivalence_preserves_restricted_sources(cid, source, expected, record_property):
    def mutate(objects, children):
        nsg = next(row for row in objects if row['id'] == NSG)
        nsg['properties']['securityRules'] = [rule('SourceBoundary', source=source)]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {expected}, rows


@pytest.mark.parametrize('cid', ['azure.claude.nsg_internet_ssh', 'azure.gap.nsg_declared_internet_ssh'])
def test_native_application_security_group_is_not_world_source(cid, record_property):
    def mutate(objects, children):
        nsg = next(row for row in objects if row['id'] == NSG)
        item = rule('ApplicationGroup'); props = item['properties']
        props.pop('sourceAddressPrefix')
        props['sourceApplicationSecurityGroups'] = [{'id': BASE + 'Microsoft.Network/applicationSecurityGroups/native'}]
        nsg['properties']['securityRules'] = [item]
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'PASS'}, rows


@pytest.mark.parametrize('cid', ['azure.vm.encryption_at_host', 'azure.claude.nsg_internet_ssh'])
def test_native_resource_type_case_alias_is_coherent(cid, record_property):
    def mutate(objects, children):
        primary = VM if REGISTRY[cid].kind == 'vm' else NSG
        native_type = 'MICROSOFT.COMPUTE/VIRTUALMACHINES' if REGISTRY[cid].kind == 'vm' else 'MICROSOFT.NETWORK/NETWORKSECURITYGROUPS'
        next(row for row in objects if row['id'] == primary)['type'] = native_type
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'PASS'}, rows


def test_native_windows_sql_marketplace_offer_cannot_skip_disabled_secure_boot(record_property):
    cid = 'azure.claude.vm_windows_secure_boot'
    def mutate(objects, children):
        vm = next(row for row in objects if row['id'] == VM)
        vm['properties']['storageProfile']['imageReference'].update(
            publisher='MicrosoftSQLServer', offer='sql2022-ws2022', sku='standard-gen2')
        vm['properties']['securityProfile']['uefiSettings']['secureBootEnabled'] = False
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {'FAIL'}, rows


@pytest.mark.parametrize('image', ['sql-marketplace', 'managed', 'gallery', 'specialized'])
@pytest.mark.parametrize('boot,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_native_windows_image_identity_does_not_replace_os_type(image, boot, expected, record_property):
    cid = 'azure.claude.vm_windows_secure_boot'
    def mutate(objects, children):
        vm = next(row for row in objects if row['id'] == VM)
        storage = vm['properties']['storageProfile']
        if image == 'sql-marketplace': storage['imageReference'] = {'publisher': 'MicrosoftSQLServer', 'offer': 'sql2022-ws2022', 'sku': 'standard-gen2', 'version': 'latest'}
        elif image == 'managed': storage['imageReference'] = {'id': BASE + 'Microsoft.Compute/images/native-windows'}
        elif image == 'gallery': storage['imageReference'] = {'id': BASE + 'Microsoft.Compute/galleries/native/images/windows/versions/1.0.0'}
        else:
            storage.pop('imageReference'); vm['properties'].pop('osProfile')
        vm['properties']['securityProfile']['uefiSettings']['secureBootEnabled'] = boot
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {expected}, rows


@pytest.mark.parametrize('variant,expected', [('linux', 'NOT_APPLICABLE'), ('missing-os', 'UNKNOWN'),
    ('unknown-os', 'UNKNOWN'), ('contradictory-profile', 'UNKNOWN'), ('contradictory-linux-profile', 'UNKNOWN'),
    ('malformed-profile', 'UNKNOWN'), ('unsupported-security', 'UNKNOWN'), ('missing-uefi', 'UNKNOWN'),
    ('malformed-boot', 'UNKNOWN'), ('standard', 'FAIL'), ('confidential', 'PASS')])
def test_native_windows_secure_boot_platform_applicability(variant, expected, record_property):
    cid = 'azure.claude.vm_windows_secure_boot'
    def mutate(objects, children):
        vm = next(row for row in objects if row['id'] == VM); props = vm['properties']
        if variant in ('linux', 'contradictory-linux-profile'):
            props['storageProfile']['osDisk']['osType'] = 'Linux'
            if variant == 'linux': props['osProfile'] = {'linuxConfiguration': {'disablePasswordAuthentication': True}}
        elif variant == 'missing-os': props['storageProfile']['osDisk'].pop('osType')
        elif variant == 'unknown-os': props['storageProfile']['osDisk']['osType'] = 'Solaris'
        elif variant == 'contradictory-profile': props['osProfile'] = {'linuxConfiguration': {'disablePasswordAuthentication': True}}
        elif variant == 'malformed-profile': props['osProfile'] = []
        elif variant == 'unsupported-security': props['securityProfile']['securityType'] = 'FutureType'
        elif variant == 'missing-uefi': props['securityProfile'].pop('uefiSettings')
        elif variant == 'malformed-boot': props['securityProfile']['uefiSettings']['secureBootEnabled'] = 'true'
        elif variant == 'standard': props['securityProfile']['securityType'] = 'Standard'
        elif variant == 'confidential': props['securityProfile']['securityType'] = 'ConfidentialVM'
    _, rows = run_case(cid, 'good', record_property, mutate=mutate)
    assert {row['status'] for row in rows} == {expected}, rows
