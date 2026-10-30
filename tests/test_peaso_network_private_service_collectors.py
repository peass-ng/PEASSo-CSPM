"""Provider-native collection -> topology -> AI for independently audited families."""
import json
import pytest
from tests.test_peaso_network_managed_services import topology, node, linked
from tests.test_peaso_collectors_gcp import snapshot, collection

NET = 'projects/host/global/networks/private'
SUBNET = 'projects/host/regions/us-central1/subnetworks/private'


@pytest.mark.parametrize('kind,data,target_kind,target', [
    ('memcached_instance', {'authorizedNetwork': NET, 'memcacheNodes': [{'host': '10.0.0.4', 'port': 11211}]}, 'network', NET),
    ('looker_instance', {'consumerNetwork': NET, 'pscEnabled': True, 'ingressPrivateIp': '10.0.0.4'}, 'network', NET),
    ('lustre_instance', {'network': NET}, 'network', NET),
    ('cloud_ids_endpoint', {'network': NET, 'endpointIp': '10.0.0.4'}, 'network', NET),
    ('tpu_node', {'networkConfig': {'network': NET, 'subnetwork': SUBNET, 'enableExternalIps': False}}, 'subnetwork', SUBNET),
    ('backupdr_management_server', {'networks': [{'network': NET, 'peeringMode': 'PRIVATE_SERVICE_ACCESS'}]}, 'network', NET),
    ('data_fusion_instance', {'privateInstance': True, 'networkConfig': {'network': NET}}, 'network', NET),
    ('workstation_cluster', {'network': NET, 'subnetwork': SUBNET, 'privateClusterConfig': {'enablePrivateEndpoint': True}}, 'subnetwork', SUBNET),
    ('vertex_custom_job', {'jobSpec': {'network': NET}}, 'network', NET),
    ('vertex_pipeline_job', {'network': NET}, 'network', NET),
    ('vertex_persistent_resource', {'network': NET, 'reservedIpRanges': ['private-range']}, 'network', NET),
    ('vertex_notebook_runtime', {'networkSpec': {'network': NET, 'subnetwork': SUBNET, 'enableInternetAccess': False}}, 'subnetwork', SUBNET),
    ('integration_endpoint_attachment', {'serviceAttachment': 'projects/host/regions/us-central1/serviceAttachments/producer', 'endpointIp': '10.0.0.4'},
        'service_attachment', 'projects/host/regions/us-central1/serviceAttachments/producer'),
])
def test_gcp_native_private_service_fields_survive_collection_and_both_consumers(kind, data, target_kind, target):
    from peaso.collectors.gcp_network_catalog import PRIVATE_SERVICES
    plan = PRIVATE_SERVICES[kind]
    def resolve(request):
        if request['url'].endswith('/' + plan['segment']):
            fields = request['params']['fields']
            assert fields == plan['fields']
            assert all(word not in fields for word in ('containerSpec', 'pipelineSpec', 'trainingInputData', 'authConfig', 'configVariables'))
            return {plan['key']: [{'name': 'projects/p-one/locations/us-central1/' + plan['segment'] + '/one', **data}]}
        return {}
    locations = {plan['service'] + '_network_locations': ['us-central1-a']} if plan.get('location_kind') == 'zone' else {}
    snap, transport = snapshot([kind], resolve, regions=['us-central1'], **locations)
    envelope = collection(snap, kind)
    assert envelope['status'] == 'collected', envelope.get('error')
    row = envelope['items'][0]
    canonical = 'https://www.googleapis.com/compute/v1/' + target
    graph, ai = topology('gcp', [(kind, row['name'], 'projects/p-one', row), (target_kind, canonical, 'projects/host', {})])
    assert linked(graph, node(graph, kind, row['name']), node(graph, target_kind, canonical))
    assert target in json.dumps(ai)
    assert node(graph, kind, row['name'])['network_attributes']


def test_apigee_uses_native_project_mapping_and_does_not_read_other_visible_organizations():
    def resolve(request):
        path = request['url']
        if path.endswith('/organizations'):
            assert 'pageSize' not in request['params']
            return {'organizations': [{'organization': 'own', 'projectId': 'p-one'}, {'organization': 'other', 'projectId': 'p-other'}]}
        assert '/other' not in path
        if path.endswith('/own/instances'):
            return {'instances': [{'name': 'instance', 'serviceAttachment': 'projects/host/regions/us-central1/serviceAttachments/producer', 'host': '10.0.0.4', 'port': '443'}]}
        if path.endswith('/own'):
            return {'name': 'own', 'authorizedNetwork': NET}
        return {}
    snap, transport = snapshot(['apigee_instance', 'apigee_organization'], resolve)
    assert collection(snap, 'apigee_instance')['items'][0]['name'] == 'organizations/own/instances/instance'
    assert collection(snap, 'apigee_organization')['items'][0]['authorizedNetwork'] == NET
    assert all('/other' not in r['url'] for r in transport.requests)


def test_gcp_private_service_pagination_and_denied_location_are_explicit():
    from peaso.collectors.gcp import ReadError
    def resolve(request):
        if '/locations/us-east1/' in request['url']:
            raise ReadError('denied', 'IAM_PERMISSION_DENIED')
        if request['url'].endswith('/instances'):
            if request['params'].get('pageToken'):
                return {'instances': [{'name': 'projects/p-one/locations/us-central1/instances/two', 'authorizedNetwork': NET}]}
            return {'instances': [{'name': 'projects/p-one/locations/us-central1/instances/one', 'authorizedNetwork': NET}], 'nextPageToken': 'two'}
        return {}
    snap, _ = snapshot(['memcached_instance'], resolve, regions=['us-central1', 'us-east1'])
    row = collection(snap, 'memcached_instance')
    assert row['status'] == 'partial' and len(row['items']) == 2


@pytest.mark.parametrize('kind', [
    'attestation_provider', 'cosmos_postgresql_cluster', 'digital_twins_instance', 'durable_task_scheduler',
    'iot_central_app', 'ml_registry', 'migrate_assessment_project', 'relay_namespace', 'static_web_app',
    'synapse_private_link_hub', 'video_indexer_account', 'desktop_host_pool', 'desktop_workspace',
    'device_update_account', 'logic_integration_account', 'powerbi_private_link_service', 'arm_private_link', 'stream_analytics_cluster',
])
def test_azure_private_link_targets_are_enumerated_and_bound_to_native_private_endpoints(kind):
    from peaso.collectors import azure
    from peaso.collectors.azure_network_catalog import PRIVATE_SERVICES
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, envelope
    plan = PRIVATE_SERVICES[kind]
    rid = BASE + plan['resource_type'] + '/one'
    pe = BASE + 'Microsoft.Network/privateEndpoints/pe'
    native = routes(kind, rid, {'publicNetworkAccess': 'Disabled', 'privateEndpointConnections': [{
        'id': rid + '/privateEndpointConnections/connection', 'properties': {'privateEndpoint': {'id': pe},
            'privateLinkServiceConnectionState': {'status': 'Approved'}}}]})
    snap = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, [kind], transport=Transport(native))
    result = envelope(snap, kind)
    assert result['status'] == 'collected', result.get('error')
    row = result['items'][0]
    graph, ai = topology('azure', [(kind, rid, SCOPE, row), ('private_endpoint', pe, SCOPE, {})])
    assert linked(graph, node(graph, kind, rid), node(graph, 'private_endpoint', pe))
    assert rid in json.dumps(ai)
    assert 'Disabled' in json.dumps(ai)


@pytest.mark.parametrize('kind,properties', [
    ('managed_domain_service', lambda subnet: {'replicaSets': [{'subnetId': subnet, 'domainControllerIpAddress': ['10.0.0.4']}]}),
    ('managed_service_fabric_cluster', lambda subnet: {'subnetId': subnet}),
    ('devcenter_network_connection', lambda subnet: {'subnetId': subnet}),
    ('devops_managed_pool', lambda subnet: {'fabricProfile': {'networkProfile': {'subnetId': subnet}}}),
    ('azure_lustre_filesystem', lambda subnet: {'filesystemSubnet': subnet}),
    ('cassandra_cluster', lambda subnet: {'delegatedManagementSubnetId': subnet}),
    ('openshift_cluster', lambda subnet: {'masterProfile': {'subnetId': subnet}, 'workerProfiles': [{'subnetId': subnet}]}),
    ('dedicated_hsm', lambda subnet: {'networkProfile': {'subnet': {'id': subnet}}}),
])
def test_azure_dedicated_service_native_subnet_wrappers_reach_map_and_agent(kind, properties):
    from peaso.collectors import azure
    from peaso.collectors.azure_network_catalog import PRIVATE_SERVICES
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, envelope
    subnet = BASE + 'Microsoft.Network/virtualNetworks/host/subnets/service'
    rid = BASE + PRIVATE_SERVICES[kind]['resource_type'] + '/one'
    snap = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, [kind], transport=Transport(routes(kind, rid, properties(subnet))))
    result = envelope(snap, kind)
    assert result['status'] == 'collected', result.get('error')
    graph, ai = topology('azure', [(kind, rid, SCOPE, result['items'][0]), ('subnet', subnet, SCOPE, {})])
    assert linked(graph, node(graph, kind, rid), node(graph, 'subnet', subnet))
    assert subnet in json.dumps(ai)


def test_azure_virtual_hub_route_table_child_lists_and_next_hop_networks_are_retained():
    from peaso.collectors import azure
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, envelope, parent
    hub = BASE + 'Microsoft.Network/virtualHubs/hub'
    route_table = hub + '/hubRouteTables/table'
    vnet = BASE + 'Microsoft.Network/virtualNetworks/host'
    native = routes('virtual_hub', hub, {'virtualRouterAsn': 65515, 'virtualRouterIps': ['10.0.0.4']})
    native[hub + '/hubRouteTables'] = {'value': [parent(route_table, 'Microsoft.Network/virtualHubs/hubRouteTables', {
        'routes': [{'name': 'private-route', 'destinationType': 'CIDR', 'destinations': ['10.20.0.0/16'],
            'nextHopType': 'ResourceId', 'nextHops': [vnet]}]})]}
    snap = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, ['hub_route_table'], transport=Transport(native))
    result = envelope(snap, 'hub_route_table')
    assert result['status'] == 'collected', result.get('error')
    graph, ai = topology('azure', [('hub_route_table', route_table, SCOPE, result['items'][0]), ('virtual_hub', hub, SCOPE, {}), ('vnet', vnet, SCOPE, {})])
    assert linked(graph, node(graph, 'hub_route_table', route_table), node(graph, 'virtual_hub', hub))
    assert '10.20.0.0/16' in json.dumps(ai)
    assert '10.20.0.0/16' in json.dumps(node(graph, 'hub_route_table', route_table)['network_attributes'])


@pytest.mark.parametrize('kind', ['iot_dps_network', 'eventgrid_namespace', 'eventgrid_partner_namespace', 'fabric_private_link_service',
    'managed_file_share', 'healthcare_workspace', 'arc_private_link_scope', 'maps_account', 'migrate_project', 'monitor_workspace',
    'traffic_controller', 'apim_workspace_gateway', 'container_app_connected_environment', 'aks_fleet', 'dataprotection_backup_vault'])
def test_azure_independent_private_link_census_targets_are_collected_with_native_network_fields(kind):
    from peaso.collectors import azure
    from peaso.collectors.azure_network_catalog import PRIVATE_SERVICES
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, envelope
    rid = BASE + PRIVATE_SERVICES[kind]['resource_type'] + '/one'
    endpoint = BASE + 'Microsoft.Network/privateEndpoints/private'
    snap = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, [kind], transport=Transport(routes(kind, rid,
        {'publicNetworkAccess': 'Disabled', 'ipFilterRules': [{'action': 'Accept', 'ipMask': '10.0.0.0/8'}],
         'privateEndpointConnections': [{'properties': {'privateEndpoint': {'id': endpoint}}}]})))
    result = envelope(snap, kind)
    assert result['status'] == 'collected', result.get('error')
    graph, ai = topology('azure', [(kind, rid, SCOPE, result['items'][0]), ('private_endpoint', endpoint, SCOPE, {})])
    assert linked(graph, node(graph, kind, rid), node(graph, 'private_endpoint', endpoint))
    assert 'Disabled' in json.dumps(ai)
    if kind == 'monitor_workspace':
        # Microsoft.Monitor/accounts has no IP filter property; the reviewed metadata
        # projection keeps only native access fields and private endpoint links.
        assert '10.0.0.0/8' not in json.dumps(result['items'][0])
        assert result['items'][0]['properties']['privateEndpointConnections'][0]['privateEndpointId'] == endpoint
    else:
        assert '10.0.0.0/8' in json.dumps(ai)


def test_azure_traffic_controller_association_is_the_native_subnet_attachment():
    from peaso.collectors import azure
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, envelope, parent
    rid = BASE + 'Microsoft.ServiceNetworking/trafficControllers/controller'
    association = rid + '/associations/private'
    subnet = BASE + 'Microsoft.Network/virtualNetworks/host/subnets/alb'
    native = routes('traffic_controller', rid, {})
    native[rid + '/associations'] = {'value': [parent(association, 'Microsoft.ServiceNetworking/trafficControllers/associations',
        {'associationType': 'subnets', 'subnet': {'id': subnet}})]}
    snap = azure.collect({'scopes': [SUB], 'options': {'retries': 0}}, ['traffic_controller_association'], transport=Transport(native))
    result = envelope(snap, 'traffic_controller_association')
    assert result['status'] == 'collected'
    graph, ai = topology('azure', [('traffic_controller_association', association, SCOPE, result['items'][0]),
        ('traffic_controller', rid, SCOPE, {}), ('subnet', subnet, SCOPE, {})])
    assert linked(graph, node(graph, 'traffic_controller_association', association), node(graph, 'subnet', subnet))
    assert linked(graph, node(graph, 'traffic_controller_association', association), node(graph, 'traffic_controller', rid))
    assert subnet in json.dumps(ai)
