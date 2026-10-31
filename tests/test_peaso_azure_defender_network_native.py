"""Native SQL VM, Defender settings/findings and per-RG VPN API acceptance."""
import copy
import json
from datetime import datetime, timezone

import pytest

from peaso.collectors import azure
from peaso.collectors.azure_defender_network_native import NATIVE_TYPES
from tests.test_peaso_azure_bulk_native import Transport, parent, routes, envelope, verdict, SCOPE, BASE

VM = BASE + 'Microsoft.Compute/virtualMachines/vm'
SQL = BASE + 'Microsoft.SqlVirtualMachine/sqlVirtualMachines/sql'
ASSESSMENT = VM + '/providers/Microsoft.Security/assessments/stable-key'
FINDING = ASSESSMENT + '/subAssessments/finding-1'
GROUP = SCOPE + '/resourceGroups/rg'
GATEWAY = BASE + 'Microsoft.Network/virtualNetworkGateways/gateway'
CONNECTION = BASE + 'Microsoft.Network/connections/connection'
SETTING = SCOPE + '/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/azureServersSetting'
SQL_CHECK = 'azure.gap.compute_vm_vulnerability_findings_resolved_for_sql_server'
CIS_CHECK = 'azure.cis.auto_provision_vulnerability_assessment_machines'
VPN_CHECK = 'azure_azure_resource_1_3_1_46_b70e2c8'


def collect(kinds, api, **options):
    from types import SimpleNamespace
    from peaso.collectors import bulk_evidence
    module = SimpleNamespace(TYPES=azure.TYPES, collect=lambda connector, requirements:
        azure.collect(connector, requirements, transport=api))
    return bulk_evidence.collect(module, {'provider': 'azure', 'scopes': [SCOPE],
        'options': {'retries': 0, **options}}, kinds)


def sql_snapshot(mode='complete'):
    mapping = routes('vm', VM, {'storageProfile': {'osDisk': {'osType': 'Windows'}}})
    sql = parent(SQL, 'Microsoft.SqlVirtualMachine/sqlVirtualMachines', {'virtualMachineResourceId': VM,
        'storageConfigurationSettings': {'sqlSystemDbOnDataDisk': True, 'private': 'private-marker'}})
    assessment = parent(ASSESSMENT, 'Microsoft.Security/assessments', {'resourceDetails': {'id': VM}, 'status': {'code': 'Healthy'}})
    finding = parent(FINDING, 'Microsoft.Security/assessments/subAssessments', {
        'resourceDetails': {'id': VM}, 'status': {'code': 'Healthy', 'description': 'private-marker'},
        'additionalData': {'query': 'private-marker'}, 'description': 'private-marker',
        'timeGenerated': datetime.now(timezone.utc).isoformat()})
    if mode == 'stalereport': finding['properties']['timeGenerated'] = '2020-01-01T00:00:00Z'
    if mode == 'missingreporttime': finding['properties'].pop('timeGenerated')
    if mode == 'malformedreporttime': finding['properties']['timeGenerated'] = 'invalid'
    if mode == 'futurereport': finding['properties']['timeGenerated'] = '2099-01-01T00:00:00Z'
    if mode == 'unhealthy': finding['properties']['status']['code'] = 'Unhealthy'
    if mode == 'foreignsql': sql['properties']['virtualMachineResourceId'] = VM.replace(SCOPE, '/subscriptions/foreign')
    if mode == 'foreignfinding': finding['id'] = FINDING.replace(SCOPE, '/subscriptions/foreign')
    if mode == 'foreignbinding': finding['properties']['resourceDetails']['id'] = VM.replace(SCOPE, '/subscriptions/foreign')
    mapping[SCOPE + '/providers/Microsoft.SqlVirtualMachine/sqlVirtualMachines'] = {'value': [] if mode == 'not_sql' else [sql]}
    mapping[SCOPE + '/providers/Microsoft.Security/assessments'] = {'value': [assessment]}
    def findings(query):
        if mode == 'retired':
            import io
            from urllib.error import HTTPError
            body = json.dumps({'Error': {'Code': 'SubAssessmentsDeprecated', 'Message': 'fixture'}}).encode()
            raise HTTPError(azure.ARM + SCOPE, 404, 'Not Found', {}, io.BytesIO(body))
        if mode == 'denied' or mode == 'partial' and '$skiptoken' in query:
            raise azure.AzureReadError('forbidden', 403)
        result = {'value': [] if mode == 'missing' else [finding]}
        if mode == 'partial': result['nextLink'] = azure.ARM + SCOPE + '/providers/Microsoft.Security/subAssessments?api-version=2019-01-01-preview&$skiptoken=next'
        return result
    mapping[SCOPE + '/providers/Microsoft.Security/subAssessments'] = findings
    class GraphTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            if body is not None and 'subassessments' in str(body.get('query', '')):
                self.calls.append(url)
                assert body['subscriptions'] == [SCOPE.rsplit('/', 1)[-1]]
                return {'data': [copy.deepcopy(finding)], 'totalRecords': 1}
            return super().request(url, body=body, audience=audience)
    api = GraphTransport(mapping)
    policy = {'status': 'collected', 'scope': SCOPE, 'checks': {SQL_CHECK: {'assessmentKeys': ['stable-key'],
        'maxReportAgeSeconds': 3600, 'requiredFindingIds': ['finding-1'], 'findingSetComplete': True}}}
    return collect(['vm', 'security_assessment', 'sql_vm', 'security_subassessment'], api, compliance_policy=policy), api


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('retired', 'PASS'), ('unhealthy', 'FAIL'), ('not_sql', 'NOT_APPLICABLE'),
    ('missing', 'UNKNOWN'), ('denied', 'UNKNOWN'), ('partial', 'UNKNOWN'), ('foreignsql', 'UNKNOWN'),
    ('foreignfinding', 'UNKNOWN'), ('foreignbinding', 'UNKNOWN'),
    ('stalereport', 'UNKNOWN'), ('missingreporttime', 'UNKNOWN'),
    ('malformedreporttime', 'UNKNOWN'), ('futurereport', 'UNKNOWN')])
def test_sql_vm_native_join_and_security_finding_status(mode, expected):
    snapshot, api = sql_snapshot(mode)
    assert verdict(snapshot, SQL_CHECK) == expected
    assert 'private-marker' not in json.dumps(snapshot)
    assert all(url.startswith(azure.ARM + '/') for url in api.calls)
    if mode in ('complete', 'retired'):
        row = envelope(snapshot, 'security_subassessment')['items'][0]
        assert row['assessment_key'] == 'stable-key'
        assert row['_provenance']['source_operation'] == 'SubAssessments_ListAll'


def cis_snapshot(mode='complete'):
    mapping = routes('security_pricing', SCOPE + '/providers/Microsoft.Security/pricings/VirtualMachines', {'pricingTier': 'Standard'})
    setting = {'id': SETTING, 'kind': 'AzureServersSetting', 'properties': {'selectedProvider': 'MdeTvm'},
               'systemData': {'createdBy': 'private-marker'}}
    if mode == 'disabled': setting['properties']['selectedProvider'] = 'None'
    if mode == 'foreign': setting['id'] = SETTING.replace(SCOPE, '/subscriptions/foreign')
    if mode == 'denied': setting = azure.AzureReadError('forbidden', 403)
    if mode == 'absent': setting = azure.AzureReadError('ResourceNotFound', 404)
    mapping[SETTING] = setting
    if mode == 'arc_unproven':
        arc = BASE + 'Microsoft.HybridCompute/machines/arc'
        mapping[SCOPE + '/providers/Microsoft.HybridCompute/machines'] = {'value': [parent(arc, 'Microsoft.HybridCompute/machines', {})]}
    api = Transport(mapping)
    from tests.archived_check_contract import plan_collection
    needed = plan_collection({'connector': {'provider': 'azure'}, 'checks': [CIS_CHECK]})
    return collect(needed, api), api


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('disabled', 'FAIL'), ('absent', 'FAIL'),
    ('denied', 'DENIED'), ('foreign', 'UNKNOWN'), ('arc_unproven', 'UNKNOWN')])
def test_native_server_vulnerability_provider_and_honest_arc_unknown(mode, expected):
    snapshot, api = cis_snapshot(mode)
    assert verdict(snapshot, CIS_CHECK) == expected
    assert 'private-marker' not in json.dumps(snapshot)
    assert any('/serverVulnerabilityAssessmentsSettings/azureServersSetting?' in url for url in api.calls)


def vpn_snapshot(mode='complete'):
    mapping = {GROUP + '/providers/Microsoft.Network/virtualNetworkGateways': {'value': [parent(GATEWAY, 'Microsoft.Network/virtualNetworkGateways', {})]}}
    mapping[SCOPE + '/resourcegroups'] = {'value': [parent(GROUP, 'Microsoft.Resources/resourceGroups', {})]}
    props = {'virtualNetworkGateway1': {'id': GATEWAY, 'properties': {'private': 'private-marker'}},
             'localNetworkGateway2': {'id': GROUP + '/providers/Microsoft.Network/localNetworkGateways/peer',
                                      'properties': {'private': 'private-marker'}},
             'connectionType': 'IPsec', 'connectionStatus': 'Connected', 'provisioningState': 'Succeeded',
             'tunnelConnectionStatus': [{'tunnel': 'a', 'connectionStatus': 'Connected'},
                                         {'tunnel': 'b', 'connectionStatus': 'Connected'}], 'sharedKey': 'private-marker'}
    if mode == 'disconnected': props['tunnelConnectionStatus'][1]['connectionStatus'] = 'Disconnected'
    if mode == 'unknownstate': props['tunnelConnectionStatus'][1]['connectionStatus'] = 'Connecting'
    if mode == 'extra': props['tunnelConnectionStatus'].append({'tunnel': 'extra', 'connectionStatus': 'Connected'})
    connection = parent(CONNECTION, 'Microsoft.Network/connections', props)
    if mode == 'foreign': connection['id'] = CONNECTION.replace('/resourceGroups/rg/', '/resourceGroups/foreign/')
    def connections(query):
        if mode == 'denied' or mode == 'partial' and '$skiptoken' in query:
            raise azure.AzureReadError('forbidden', 403)
        result = {'value': [] if mode == 'missing' else [connection]}
        if mode == 'partial': result['nextLink'] = azure.ARM + GROUP + '/providers/Microsoft.Network/connections?api-version=2025-01-01&$skiptoken=next'
        return result
    mapping[GROUP + '/providers/Microsoft.Network/connections'] = connections
    if mode == 'deniedgroups': mapping[SCOPE + '/resourcegroups'] = azure.AzureReadError('forbidden', 403)
    api = Transport(mapping)
    policy = {'sw33': {'status': 'collected', 'scope': SCOPE, 'vpnTunnels': {'gatewayId': GATEWAY,
        'expectedTunnels': [{'connectionId': CONNECTION, 'tunnel': 'a'}, {'connectionId': CONNECTION, 'tunnel': 'b'}]}}}
    return collect(['virtual_network_gateway', 'virtual_network_gateway_connection'], api, compliance_policy=policy), api


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('disconnected', 'FAIL'), ('unknownstate', 'UNKNOWN'),
    ('extra', 'UNKNOWN'), ('foreign', 'UNKNOWN'), ('missing', 'UNKNOWN'), ('denied', 'DENIED'),
    ('partial', 'UNKNOWN'), ('deniedgroups', 'DENIED')])
def test_vpn_real_tunnel_health_and_rg_roster_coverage(mode, expected):
    snapshot, api = vpn_snapshot(mode)
    assert verdict(snapshot, VPN_CHECK) == expected
    assert 'private-marker' not in json.dumps(snapshot)
    assert not any(c['type'] == '_native_vpn_connection_rg' for c in snapshot['collections'])
    if mode == 'complete': assert envelope(snapshot, 'virtual_network_gateway_connection')['covered_parent_ids'] == [GROUP]
    if mode == 'complete':
        connection = envelope(snapshot, 'virtual_network_gateway_connection')['items'][0]
        assert connection['properties']['localNetworkGateway2'] == {
            'id': GROUP + '/providers/Microsoft.Network/localNetworkGateways/peer'}
        assert connection['properties']['connectionStatus'] == 'Connected'
        assert connection['properties']['connectionType'] == 'IPsec'


def test_native_selection_includes_complete_positive_cis_dependencies():
    from tests.archived_check_contract import plan_collection
    assert NATIVE_TYPES <= set(azure.TYPES)
    needed = plan_collection({'connector': {'provider': 'azure'}, 'checks': [CIS_CHECK]})
    assert {'security_pricing', 'server_vulnerability_assessment_setting', 'arc_machine', 'arc_vulnerability_assessment_evidence'} <= set(needed)
