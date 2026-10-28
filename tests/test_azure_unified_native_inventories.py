"""Full and exposure projections share one resource inventory without data loss."""
import copy
from collections import Counter
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure
from peaso.snapshot import validate

SUB = '/subscriptions/00000000-0000-0000-0000-000000000001'
TENANT = '00000000-0000-0000-0000-000000000002'
RG = SUB + '/resourceGroups/rg'
MG = '/providers/Microsoft.Management/managementGroups/root'
BILL = '/providers/Microsoft.Billing/billingAccounts/account'


class Fixture:
    tenant = verified_tenant = TENANT
    def __init__(self, *, populated=True, deny_detail=False):
        self.populated, self.deny_detail, self.calls = populated, deny_detail, []
        self.attest = {'id': RG + '/providers/Microsoft.Attestation/attestationProviders/a', 'name': 'a',
            'type': 'Microsoft.Attestation/attestationProviders', 'properties': {'status': 'Ready',
            'publicNetworkAccess': 'Enabled', 'attestUri': 'https://a.eus.attest.azure.net',
            'trustModel': 'AAD', 'tpmAttestationAuthentication': 'Disabled',
            'privateEndpointConnections': [], 'policySigningCertificates': {'keys': [{'d': 'private-marker'}]}}}
        self.fabric = {'id': RG + '/providers/Microsoft.ServiceFabric/clusters/f', 'name': 'f',
            'type': 'Microsoft.ServiceFabric/clusters', 'properties': {'provisioningState': 'Succeeded',
            'clusterState': 'Ready', 'managementEndpoint': 'https://f.example.test:19080',
            'nodeTypes': [{'clientConnectionEndpointPort': 19000, 'httpGatewayEndpointPort': 19080}],
            'fabricSettings': [{'name': 'Security', 'parameters': [{'name': 'ClusterProtectionLevel', 'value': 'EncryptAndSign'}]}],
            'azureActiveDirectory': {'tenantId': TENANT}}}
    def request(self, url, **kwargs):
        self.calls.append(url)
        path = urlsplit(url).path
        if kwargs.get('body') is not None:
            return {'data': []}
        if path == SUB + '/resources':
            return {'value': [self.attest, self.fabric] if self.populated else []}
        if path == SUB + '/resourcegroups':
            return {'value': [{'id': RG, 'name': 'rg', 'type': 'Microsoft.Resources/resourceGroups', 'properties': {}}]}
        if path == '/providers/Microsoft.Management/managementGroups':
            return {'value': [{'id': MG, 'name': 'root', 'properties': {}}]}
        if path == MG:
            return {'id': MG, 'properties': {'tenantId': TENANT}}
        if path == '/providers/Microsoft.Billing/billingAccounts':
            return {'value': [{'id': BILL, 'properties': {'agreementType': 'MicrosoftOnlineServicesProgram'}}]}
        if path.endswith('/providers/Microsoft.CostManagement/exports'):
            scope = path.split('/providers/Microsoft.CostManagement/exports')[0]
            return {'value': [{'id': path + '/monthly', 'name': 'monthly', 'type': 'Microsoft.CostManagement/exports',
                'properties': {'deliveryInfo': {'destination': {'resourceId': RG + '/providers/Microsoft.Storage/storageAccounts/costs',
                'container': 'reports', 'storageAccount': 'costs', 'sasToken': 'private-marker'}},
                'schedule': {'status': 'Active'}, 'definition': {'type': 'ActualCost'}, 'provisioningState': 'Succeeded'}}] if self.populated else []}
        for row in (self.attest, self.fabric):
            if path == row['id']:
                if self.deny_detail:
                    error = RuntimeError('fixture denied'); error.status = 403; raise error
                return copy.deepcopy(row)
            if path == SUB + '/providers/' + row['type']:
                return {'value': [copy.deepcopy(row)] if self.populated else []}
        return {'value': []}
    def close(self):
        pass


def collect(api):
    result = azure.collect({'provider': 'azure', 'scopes': [SUB], 'auth': {'tenant_id': TENANT},
                            'options': {'retries': 0}},
                           ['attestation_provider', 'service_fabric_cluster', 'cost_export'], transport=api)
    assert validate(result) == result
    assert max(Counter((c['type'], c['scope']) for c in result['collections']).values()) == 1
    return result


@pytest.mark.parametrize('populated', [True, False])
def test_normal_collection_seals_one_inventory_and_preserves_billing_scopes(populated):
    api = Fixture(populated=populated)
    result = collect(api)
    for kind in ('attestation_provider', 'service_fabric_cluster'):
        rows = [c for c in result['collections'] if c['type'] == kind]
        assert len(rows) == 1
        assert rows[0]['status'] == ('collected' if populated else 'empty')
    exports = [c for c in result['collections'] if c['type'] == 'cost_export']
    assert {c['scope'] for c in exports} == {SUB, RG, MG, BILL}
    paths = [urlsplit(url).path for url in api.calls]
    assert all(count == 1 for path, count in Counter(paths).items() if path.endswith('/exports'))
    if populated:
        items = {c['type']: c['items'][0] for c in result['collections']
                 if c['type'] in ('attestation_provider', 'service_fabric_cluster', 'cost_export') and c['items']}
        fabric = items['service_fabric_cluster']['properties']
        assert fabric['fabricSettings'][0]['parameters'][0]['value'] == 'EncryptAndSign'
        assert fabric['azureActiveDirectory']['tenantId'] == TENANT
        assert fabric['managementHost'] == 'f.example.test' and fabric['managementPort'] == 19080
        assert fabric['nodePorts'] == [{'client': 19000, 'http': 19080}]
        assert items['attestation_provider']['properties']['attestUri'] == api.attest['properties']['attestUri']
        assert items['attestation_provider']['properties']['attestHost'] == 'a.eus.attest.azure.net'
        cost = items['cost_export']['properties']
        assert cost['sourceScope'] in {SUB, RG, MG, BILL}
        assert cost['destination']['resourceId'].endswith('/storageAccounts/costs')
        assert cost['deliveryInfo']['destination']['container'] == 'reports'
        assert cost['schedule']['status'] == 'Active' and cost['definition']['type'] == 'ActualCost'
        assert 'private-marker' not in str(result)
        assert Counter(paths)[SUB + '/providers/Microsoft.ServiceFabric/clusters'] == 1
        assert Counter(paths)[SUB + '/providers/Microsoft.Attestation/attestationProviders'] == 1


def test_denied_full_detail_keeps_verified_list_endpoint_metadata_and_denial():
    result = collect(Fixture(deny_detail=True))
    row = next(c for c in result['collections'] if c['type'] == 'attestation_provider')
    assert row['status'] in {'partial', 'denied'}
    assert row['items'][0]['properties']['attestHost']
    assert row['items'][0]['detail']['collection_status'] == 'denied'
    assert row['items'][0]['_provenance']['representation'] == 'metadata'
    # Classic Service Fabric's complete LIST already contains its native
    # configuration, so it needs no second GET to retain those facts.
    fabric = next(c for c in result['collections'] if c['type'] == 'service_fabric_cluster')
    assert fabric['status'] == 'collected'
    assert fabric['items'][0]['properties']['fabricSettings']
    assert 'private-marker' not in str(result)


def test_managed_fabric_still_has_its_separate_authoritative_inventory():
    api = Fixture()
    result = azure.collect({'provider': 'azure', 'scopes': [SUB],
                            'auth': {'tenant_id': TENANT}, 'options': {'retries': 0}},
                           ['service_fabric_cluster', 'service_fabric_managed_cluster'], transport=api)
    assert validate(result) == result
    rows = {c['type']: c for c in result['collections']}
    assert rows['service_fabric_cluster']['status'] == 'collected'
    assert rows['service_fabric_managed_cluster']['status'] == 'empty'
    paths = [urlsplit(url).path for url in api.calls]
    assert paths.count(SUB + '/providers/Microsoft.ServiceFabric/managedClusters') == 1
    assert paths.count(SUB + '/providers/Microsoft.ServiceFabric/clusters') == 1
