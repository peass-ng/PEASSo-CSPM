"""Native API detail, ownership, data-plane and real agent publication paths."""
import json
import sqlite3
import pytest
from tests.test_peaso_collectors_gcp import snapshot, collection, NativeDataFixtureTransport, connector
from tests.test_peaso_network_managed_services import topology, node, linked

NET = 'projects/host/global/networks/private'
SUBNET = 'projects/host/regions/us-central1/subnetworks/private'
ATTACH = 'projects/host/regions/us-central1/networkAttachments/psc'


@pytest.mark.parametrize('kind,data,expected', [
    ('metastore_service', {'network': NET, 'endpointUri': 'thrift://10.0.0.4:9083'}, NET),
    ('parallelstore_instance', {'network': NET, 'reservedIpRange': '10.0.0.0/24'}, NET),
    ('bigquery_private_connection', {'configuration': {'network': {'privateServiceConnect': {'networkAttachment': ATTACH}}}}, ATTACH),
    ('cloud_ftp_server', {'internalConfig': {'pscEndpoints': [{'network': NET, 'endpoint': '10.0.0.5'}]}}, NET),
    ('eventarc_pipeline', {'destinations': [{'networkConfig': {'networkAttachment': ATTACH}}]}, ATTACH),
    ('vertex_agent_engine', {'spec': {'deploymentSpec': {'pscInterfaceConfig': {'networkAttachment': ATTACH}}}}, ATTACH),
    ('managed_kafka_connect_cluster', {'gcpConfig': {'accessConfig': {'networkConfigs': [{'primarySubnet': SUBNET}]}}}, SUBNET),
    ('dataproc_batch', {'environmentConfig': {'executionConfig': {'networkUri': NET, 'subnetworkUri': SUBNET}}}, SUBNET),
    ('managed_ad_domain', {'authorizedNetworks': [NET], 'reservedIpRange': '10.0.0.0/24'}, NET),
])
def test_google_native_detail_metadata_reaches_map_and_actual_agent_database(tmp_path, kind, data, expected):
    from peaso.collectors.gcp_network_catalog import PRIVATE_SERVICES, api_root
    from peaso.ai.network import build
    from peaso.ai.pipeline import private_json
    from peaso.collectors.gcp import HOSTS
    from urllib.parse import urlsplit
    plan = PRIVATE_SERVICES[kind]
    location = 'global' if plan.get('location_kind') == 'global' else 'us-central1'
    name = f"projects/p-one/locations/{location}/{plan['segment']}/one"
    root = api_root(plan['service'], plan['version'], location)
    assert urlsplit(root).hostname in HOSTS
    def resolve(request):
        assert request['method'] == 'GET'
        if request['url'] == root + '/' + name.rsplit('/', 1)[0]:
            return {plan['key']: [{'name': name}]}
        if plan.get('iam_policy') and request['url'] == root + '/' + name + ':getIamPolicy':
            # Self-grant inventories also read the exact resource policy.
            assert request['params'] == {'options.requestedPolicyVersion': 3}
            return {'bindings': []}
        assert request['url'] == root + '/' + name
        assert request['params']['fields'] == plan['get_fields']
        assert 'environmentVariables' not in request['params']['fields']
        if kind == 'cloud_ftp_server':
            assert request['params']['view'] == 'SERVER_VIEW_FULL'
        return {'name': name, **data}
    snap, transport = snapshot([kind], resolve, regions=['us-central1'])
    result = collection(snap, kind)
    assert result['status'] == 'collected', result.get('error')
    assert len(transport.requests) == (3 if plan.get('iam_policy') else 2)
    graph, ai = topology('gcp', [(kind, name, 'projects/p-one', result['items'][0])])
    assert expected in json.dumps(node(graph, kind, name)['network_attributes'])
    build(tmp_path, ai, [], private_json)
    with sqlite3.connect(tmp_path / 'context.sqlite') as db:
        resources = '\n'.join(v for v, in db.execute("SELECT detail FROM records WHERE domain='resources'"))
        assert expected in resources
        assert name in resources
    assert json.loads((tmp_path / 'topology.json').read_text())['resource_counts'][kind] == 1


def test_google_zone_expansion_uses_real_zone_inventory_and_retains_denied_zone():
    from peaso.collectors.gcp import ReadError
    def resolve(request):
        path = request['url']
        if path.endswith('/zones'):
            return {'items': [{'name': 'us-central1-a', 'region': 'projects/p-one/regions/us-central1'},
                {'name': 'us-central1-f', 'region': 'projects/p-one/regions/us-central1'},
                {'name': 'us-east1-b', 'region': 'projects/p-one/regions/us-east1'}]}
        if '/us-central1-f/' in path:
            raise ReadError('denied', 'PERMISSION_DENIED')
        assert '/us-central1-a/' in path
        return {'nodes': [{'name': 'projects/p-one/locations/us-central1-a/nodes/one', 'networkConfig': {'network': NET}}]}
    snap, transport = snapshot(['tpu_node'], resolve, regions=['us-central1'])
    result = collection(snap, 'tpu_node')
    assert result['status'] == 'partial' and len(result['items']) == 1
    assert len(transport.requests) == 3
    assert all('/us-east1-b/' not in r['url'] for r in transport.requests)


def test_google_project_number_alias_requires_independent_crm_receipt():
    from peaso.collectors.gcp import GCPCollector
    kind = 'parallelstore_instance'
    name = 'projects/123456789/locations/us-central1/instances/one'
    def resolve(request):
        if request['url'].startswith('https://cloudresourcemanager.googleapis.com/'):
            return {'name': 'projects/123456789', 'projectId': 'project-one'}
        if request['url'].endswith('/instances'):
            return {'instances': [{'name': name}]}
        assert request['url'].endswith('/' + name)
        return {'name': name, 'network': NET}
    transport = NativeDataFixtureTransport(resolve)
    snap = GCPCollector(connector([kind], scopes=['projects/project-one'], regions=['us-central1']), transport=transport).collect()
    result = collection(snap, kind, 'projects/project-one')
    assert result['status'] == 'collected', result.get('error')
    assert len(result['source_requests']) == 3
    assert result['items'][0]['name'] == name
    # The returned name cannot prove its own ownership.
    def unproven(request):
        if request['url'].startswith('https://cloudresourcemanager.googleapis.com/'):
            return {'name': 'projects/999999999', 'projectId': 'other-project'}
        return resolve(request)
    transport = NativeDataFixtureTransport(unproven)
    snap = GCPCollector(connector([kind], scopes=['projects/project-one'], regions=['us-central1']), transport=transport).collect()
    result = collection(snap, kind, 'projects/project-one')
    assert result['status'] == 'partial'
    assert result['items'][0]['_coverage']['network_detail']['status'] == 'malformed'
    assert not any(r['url'].endswith('/' + name) for r in transport.requests)


def test_google_nested_service_directory_lists_endpoints_and_links_exact_service():
    service = 'projects/p-one/locations/us-central1/namespaces/ns/services/svc'
    endpoint = service + '/endpoints/one'
    def resolve(request):
        path = request['url']
        if path.endswith('/namespaces'):
            return {'namespaces': [{'name': service.rsplit('/services/', 1)[0]}]}
        if path.endswith('/services'):
            return {'services': [{'name': service}]}
        if path.endswith('/endpoints'):
            return {'endpoints': [{'name': endpoint}]}
        assert path.endswith('/' + endpoint)
        return {'name': endpoint, 'address': '10.0.0.8', 'port': 443, 'network': NET}
    snap, _ = snapshot(['service_directory_endpoint'], resolve, regions=['us-central1'])
    result = collection(snap, 'service_directory_endpoint')
    assert result['status'] == 'collected', result.get('error')
    graph, ai = topology('gcp', [('service_directory_endpoint', endpoint, 'projects/p-one', result['items'][0]),
        ('service_directory_service', service, 'projects/p-one', {})])
    assert linked(graph, node(graph, 'service_directory_endpoint', endpoint), node(graph, 'service_directory_service', service), 'service_parent')
    assert '10.0.0.8' in json.dumps(ai)


def test_azure_data_plane_networks_use_correct_audiences_and_drop_test_content():
    from peaso.collectors import azure
    from peaso.collectors.azure_network_data import SYNAPSE, LOAD_TEST
    from tests.test_peaso_azure_bulk_native import Transport, SUB, SCOPE, BASE, routes, envelope
    workspace = BASE + 'Microsoft.Synapse/workspaces/one'
    testing = BASE + 'Microsoft.LoadTestService/loadTests/test'
    subnet = BASE + 'Microsoft.Network/virtualNetworks/host/subnets/test'
    storage = BASE + 'Microsoft.Storage/storageAccounts/storage'
    native = routes('synapse_workspace', workspace, {'managedVirtualNetwork': 'default',
        'connectivityEndpoints': {'dev': 'https://one.dev.azuresynapse.net'}})
    native.update(routes('load_test_resource', testing, {'dataPlaneURI': '00000000-0000-0000-0000-000000000000.westus2.cnt-prod.loadtesting.azure.com'}))
    native['/managedVirtualNetworks/default/managedPrivateEndpoints'] = {'value': [{'name': 'endpoint', 'properties': {
        'privateLinkResourceId': storage, 'groupId': 'blob', 'connectionState': {'status': 'Approved', 'description': 'CONTENT_SENTINEL'}}}]}
    native['/tests'] = {'value': [{'testId': 'test-one', 'subnetId': subnet, 'environmentVariables': {'network': 'CONTENT_SENTINEL'},
        'inputArtifacts': {'url': 'CONTENT_SENTINEL'}, 'secrets': {'password': 'CONTENT_SENTINEL'}}]}
    class Audiences(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            if '.dev.azuresynapse.net/' in url: assert audience == SYNAPSE
            if '.cnt-prod.loadtesting.azure.com/' in url: assert audience == LOAD_TEST
            return super().request(url, body=body, audience=audience)
    snap = azure.collect({'scopes': [SUB], 'options': {'retries': 0}},
        ['synapse_managed_private_endpoint', 'load_test_network_test'], transport=Audiences(native))
    rows = [(kind, envelope(snap, kind)) for kind in ('synapse_managed_private_endpoint', 'load_test_network_test')]
    assert all(c['status'] == 'collected' for k, c in rows), rows
    assert 'CONTENT_SENTINEL' not in json.dumps([c for k, c in rows])
    graph, ai = topology('azure', [(k, c['items'][0]['id'], SCOPE, c['items'][0]) for k, c in rows] +
        [('synapse_workspace', workspace, SCOPE, {}), ('storage_account', storage, SCOPE, {}), ('subnet', subnet, SCOPE, {})])
    assert linked(graph, node(graph, 'synapse_managed_private_endpoint', rows[0][1]['items'][0]['id']), node(graph, 'storage_account', storage))
    assert linked(graph, node(graph, 'load_test_network_test', rows[1][1]['items'][0]['id']), node(graph, 'subnet', subnet))
    assert subnet in json.dumps(ai)


def test_aws_serverless_network_policy_is_decoded_before_request_cache():
    from tests.test_peaso_network_native_vpc_workloads import NativeClient, Session
    from peaso.collectors.aws_network_inventory import FETCHERS
    from peaso.collectors.aws import Requests
    native = NativeClient({'list_security_policies': {'securityPolicySummaries': [{'name': 'private'}]},
        'get_security_policy': {'securityPolicyDetail': {'name': 'private', 'type': 'network', 'description': 'CONTENT_SENTINEL',
            'policy': json.dumps([{'Rules': [{'ResourceType': 'collection', 'Resource': ['collection/private-*']}],
                'AllowFromPublic': False, 'SourceVPCEs': ['vpce-one'], 'Description': 'CONTENT_SENTINEL'}])}}})
    reader = Requests({'retry_attempts': 1})
    result = FETCHERS['aoss_network_policy'](reader, Session(native), 'us-east-1', '111111111111')
    assert result.status == 'collected', result.error
    cache = json.dumps([f.result() for f in reader._cache.values()])
    assert 'CONTENT_SENTINEL' not in cache and 'vpce-one' in cache
    scope = '111111111111/us-east-1'
    graph, ai = topology('aws', [('aoss_network_policy', 'private', scope, result.items[0]), ('aoss_vpc_endpoint', 'vpce-one', scope, {})])
    assert linked(graph, node(graph, 'aoss_network_policy', 'private'), node(graph, 'aoss_vpc_endpoint', 'vpce-one'))
    assert 'AllowFromPublic' in json.dumps(ai) and 'collection/private-*' in json.dumps(ai)


def test_google_organization_firewall_inventory_uses_organization_scope():
    name = 'organizations/123/locations/us-central1-a/firewallEndpoints/endpoint'
    def resolve(request):
        assert request['scope'] == 'organizations/123'
        if request['url'].endswith('/firewallEndpoints'):
            return {'firewallEndpoints': [{'name': name}]}
        assert request['url'].endswith('/' + name)
        return {'name': name, 'state': 'ACTIVE'}
    snap, transport = snapshot(['ngfw_organization_endpoint'], resolve, scopes=['organizations/123'],
        networksecurity_network_locations=['us-central1-a'])
    assert collection(snap, 'ngfw_organization_endpoint', 'organizations/123')['status'] == 'collected'
    assert len(transport.requests) == 2


@pytest.mark.parametrize('url,audience', [
    ('https://one.dev.azuresynapse.net/managedVirtualNetworks/default/managedPrivateEndpoints?api-version=2020-12-01', 'https://dev.azuresynapse.net'),
    ('https://00000000-0000-0000-0000-000000000000.westus2.cnt-prod.loadtesting.azure.com/tests?api-version=2022-11-01', 'https://cnt-prod.loadtesting.azure.com'),
])
def test_azure_native_transport_projects_network_data_before_returning_to_cache(monkeypatch, url, audience):
    from peaso.collectors import azure
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            if audience.endswith('dev.azuresynapse.net'):
                row = {'name': 'pe', 'properties': {'privateLinkResourceId': '/subscriptions/one/providers/Microsoft.Storage/storageAccounts/account',
                    'connectionState': {'status': 'Approved', 'description': 'CONTENT_SENTINEL'}}}
            else:
                row = {'testId': 'one', 'subnetId': '/subscriptions/one/providers/Microsoft.Network/virtualNetworks/net/subnets/sub',
                    'environmentVariables': {'network': 'CONTENT_SENTINEL'}, 'inputArtifacts': {'url': 'CONTENT_SENTINEL'}}
            return json.dumps({'value': [row]}).encode()
    class Opener:
        def open(self, request, timeout):
            assert request.get_method() == 'GET'
            return Response()
    monkeypatch.setattr(azure, 'build_opener', lambda *args: Opener())
    transport = azure.AzureTransport({}, credential=object())
    transport.token = lambda value: 'test-token' if value == audience else pytest.fail('wrong audience')
    data = transport.request(url, audience=audience)
    assert 'CONTENT_SENTINEL' not in json.dumps(data)
    assert data['value']
    with pytest.raises(azure.AzureReadError, match='untrusted_continuation'):
        transport.request(url.replace('/tests?', '/tests/one/files?').replace('/managedPrivateEndpoints?', '/managedPrivateEndpoints/one?'), audience=audience)


def test_kubernetes_native_policy_selectors_survive_new_extension_projection():
    from peaso.collectors.k8s_network_extensions import project
    from peaso.ai.network import native_network_resource
    spec = {'endpointSelector': {'matchLabels': {'app': 'frontend'}}, 'egress': [{'toServices': [
        {'k8sService': {'serviceName': 'backend', 'namespace': 'data'}}], 'toEndpoints': [
        {'matchLabels': {'role': 'database'}}], 'toFQDNs': [{'matchPattern': '*.internal.example'}]}]}
    row = project({'items': [{'metadata': {'name': 'policy', 'namespace': 'apps'}, 'spec': spec}]}, 'cilium_networkpolicy')['items'][0]
    ai = native_network_resource({'provider': 'k8s', 'type': 'cilium_networkpolicy', 'data': row})
    assert ai['data']['spec']['egress'][0]['toServices'][0]['k8sService']['serviceName'] == 'backend'
    assert '*.internal.example' in json.dumps(ai)


def test_network_context_boolean_flags_survive_repeated_agent_projection():
    from peaso.ai.network import native_network_resource
    row = {'provider': 'gcp', 'type': 'vertex_custom_job', 'data': {'pscInterfaceConfig': {'newNativeFlag': False}}}
    once = native_network_resource(row)
    assert native_network_resource(once)['data'] == once['data']
    assert 'newNativeFlag' in json.dumps(once)


@pytest.mark.parametrize('kind,responses,expected', [
    ('dms_serverless_replication', {'describe_replication_configs': {'ReplicationConfigs': [{'ReplicationConfigArn': 'arn:aws:dms:us-east-1:111111111111:replication-config:one',
        'ComputeConfig': {'ReplicationSubnetGroupId': 'group', 'VpcSecurityGroupIds': ['sg-one']}, 'TableMappings': 'CONTENT_SENTINEL'}]}}, 'sg-one'),
    ('ecs_capacity_provider', {'list_clusters': {'clusterArns': ['arn:aws:ecs:us-east-1:111111111111:cluster/one']},
        'describe_capacity_providers': {'capacityProviders': [{'capacityProviderArn': 'arn:aws:ecs:us-east-1:111111111111:capacity-provider/one',
            'managedInstancesProvider': {'infrastructureRoleArn': 'not-network', 'instanceLaunchTemplate': {'networkConfiguration': {'subnets': ['subnet-one']}}}}]}}, 'subnet-one'),
    ('network_firewall_proxy', {'list_proxies': {'Proxies': [{'Arn': 'arn:aws:network-firewall:us-east-1:111111111111:proxy/one'}]},
        'describe_proxy': {'Proxy': {'ProxyArn': 'arn:aws:network-firewall:us-east-1:111111111111:proxy/one', 'VpcEndpointServiceName': 'com.amazonaws.vpce.us-east-1.vpce-svc-one'}}}, 'vpce-svc-one'),
])
def test_final_same_service_native_families_retain_network_metadata_before_cache(kind, responses, expected):
    from tests.test_peaso_network_native_vpc_workloads import NativeClient, Session
    from peaso.collectors.aws_network_inventory import FETCHERS
    from peaso.collectors.aws import Requests
    reader = Requests({'retry_attempts': 1})
    result = FETCHERS[kind](reader, Session(NativeClient(responses)), 'us-east-1', '111111111111')
    assert result.status == 'collected', result.error
    cached = json.dumps([f.result() for f in reader._cache.values()])
    assert expected in cached and 'CONTENT_SENTINEL' not in cached
    graph, ai = topology('aws', [(kind, result.items[0]['NetworkResourceId'], '111111111111/us-east-1', result.items[0])])
    assert expected in json.dumps(ai)
    assert expected in json.dumps(node(graph, kind, result.items[0]['NetworkResourceId'])['network_attributes'])


def test_remote_endpoint_association_does_not_use_the_producer_account_as_owner():
    from peaso.analysis.network_observations import projected_metadata
    scope, remote = '111111111111/us-east-1', '222222222222/us-west-2'
    row = projected_metadata({'Id': 'association', 'VpcEndpointId': 'vpce-one',
        'VpcEndpointOwner': '222222222222', 'VpcEndpointRegion': 'us-west-2'})
    graph, _ = topology('aws', [('vpc_endpoint_association', 'association', scope, row), ('vpc_endpoint', 'vpce-one', remote, {})])
    assert linked(graph, node(graph, 'vpc_endpoint_association', 'association'), node(graph, 'vpc_endpoint', 'vpce-one'))
    assert not any(n['type'] == 'vpc_endpoint' and n['scope'] == scope for n in graph['nodes'])


def test_gcp_bucket_native_ip_filter_is_network_inventory():
    from peaso.analysis.network_services import SERVICE_TYPES
    assert 'bucket' in SERVICE_TYPES['gcp']
    graph, ai = topology('gcp', [('bucket', 'private-bucket', 'projects/p-one', {'name': 'private-bucket',
        'ipFilter': {'mode': 'Enabled', 'vpcNetworkSources': [{'network': NET, 'allowedIpCidrRanges': ['10.0.0.0/8']}]}},),
        ('network', 'https://www.googleapis.com/compute/v1/' + NET, 'projects/host', {})])
    assert linked(graph, node(graph, 'bucket', 'private-bucket'), node(graph, 'network', 'https://www.googleapis.com/compute/v1/' + NET))
    assert '10.0.0.0/8' in json.dumps(ai)


def test_client_vpn_routes_keep_native_cidr_identity_and_all_network_fields():
    from tests.test_peaso_network_native_vpc_workloads import NativeClient, Session
    from peaso.collectors.aws_network_inventory import FETCHERS
    from peaso.collectors.aws import Requests
    native = NativeClient({'describe_client_vpn_endpoints': {'ClientVpnEndpoints': [{'ClientVpnEndpointId': 'cvpn-endpoint-one'}]},
        'describe_client_vpn_routes': {'Routes': [{'ClientVpnEndpointId': 'cvpn-endpoint-one', 'DestinationCidr': '10.0.0.0/8', 'TargetSubnet': 'subnet-one'}, {'ClientVpnEndpointId': 'cvpn-endpoint-one', 'DestinationCidr': '10.0.0.0/8', 'TargetSubnet': 'subnet-two'}]}})
    result = FETCHERS['client_vpn_route'](Requests({'retry_attempts': 1}), Session(native), 'us-east-1', '111111111111')
    assert result.status == 'collected'
    assert {row['NetworkResourceId'] for row in result.items} == {'cvpn-endpoint-one/10.0.0.0/8/subnet-one', 'cvpn-endpoint-one/10.0.0.0/8/subnet-two'}
    assert 'subnet-one' in json.dumps(result.items)
    scope = '111111111111/us-east-1'
    graph, _ = topology('aws', [('client_vpn_route', row['NetworkResourceId'], scope, row) for row in result.items] +
        [('ec2_client_vpn_endpoint', 'cvpn-endpoint-one', scope, {}), ('subnet', 'subnet-one', scope, {}), ('subnet', 'subnet-two', scope, {})])
    for row in result.items:
        assert linked(graph, node(graph, 'client_vpn_route', row['NetworkResourceId']), node(graph, 'ec2_client_vpn_endpoint', 'cvpn-endpoint-one'))


def test_datasync_locations_use_native_type_filter_and_get_vpc_attachment():
    from tests.test_peaso_network_native_vpc_workloads import NativeClient, Session
    from peaso.collectors.aws_network_inventory import FETCHERS
    from peaso.collectors.aws import Requests
    arn = 'arn:aws:datasync:us-east-1:111111111111:location/loc-one'
    def locations(arguments):
        assert arguments['Filters'] == [{'Name': 'LocationType', 'Operator': 'Equals', 'Values': ['EFS']}]
        return {'Locations': [{'LocationArn': arn, 'LocationUri': 'efs://fs-one/'}]}
    native = NativeClient({'list_locations': locations, 'describe_location_efs': {'LocationArn': arn,
        'Ec2Config': {'SubnetArn': 'arn:aws:ec2:us-east-1:111111111111:subnet/subnet-one',
            'SecurityGroupArns': ['arn:aws:ec2:us-east-1:111111111111:security-group/sg-one']}}})
    result = FETCHERS['datasync_efs_location'](Requests({'retry_attempts': 1}), Session(native), 'us-east-1', '111111111111')
    assert result.status == 'collected'
    graph, ai = topology('aws', [('datasync_efs_location', arn, '111111111111/us-east-1', result.items[0]),
        ('subnet', 'subnet-one', '111111111111/us-east-1', {})])
    assert linked(graph, node(graph, 'datasync_efs_location', arn), node(graph, 'subnet', 'subnet-one'))
    assert 'sg-one' in json.dumps(ai)


def test_quicksight_ip_policy_retains_only_native_rule_keys_and_account_binding():
    from tests.test_peaso_network_native_vpc_workloads import NativeClient, Session
    from peaso.collectors.aws_network_inventory import FETCHERS
    from peaso.collectors.aws import Requests
    def policy(arguments):
        assert arguments == {'AwsAccountId': '111111111111'}
        return {'AwsAccountId': '111111111111', 'Enabled': True,
            'IpRestrictionRuleMap': {'10.0.0.0/8': 'CONTENT_SENTINEL'},
            'VpcIdRestrictionRuleMap': {'vpc-one': 'CONTENT_SENTINEL'},
            'VpcEndpointIdRestrictionRuleMap': {'vpce-one': 'CONTENT_SENTINEL'}}
    reader = Requests({'retry_attempts': 1})
    result = FETCHERS['quicksight_network_restrictions'](reader, Session(NativeClient({'describe_ip_restriction': policy})), 'us-east-1', '111111111111')
    assert result.status == 'collected', result.error
    assert 'CONTENT_SENTINEL' not in json.dumps([f.result() for f in reader._cache.values()])
    assert '10.0.0.0/8' in json.dumps(result.items)
    assert any(f['name'] == 'Enabled' and f['value'] is True for f in result.items[0]['NetworkAttributes'])


def test_endpoint_url_arrays_do_not_retain_embedded_credentials_in_agent_resources():
    from peaso.ai.network import native_network_resource
    row = native_network_resource({'provider': 'aws', 'type': 'mq_broker', 'data': {'Endpoints': [
        'amqps://user:CONTENT_SENTINEL@private.example:5671/path?token=CONTENT_SENTINEL#CONTENT_SENTINEL']}})
    assert row['data']['Endpoints'] == ['amqps://private.example:5671/path']
    assert 'CONTENT_SENTINEL' not in json.dumps(row)


def test_export_policy_network_clients_survive_managed_storage_agent_projection():
    from peaso.ai.network import native_network_resource
    row = native_network_resource({'provider': 'gcp', 'type': 'netapp_volume', 'data': {'exportPolicy': {'rules': [
        {'allowedClients': '10.0.0.0/8', 'accessType': 'READ_ONLY', 'nfsv3': True}]}}})
    assert row['data']['exportPolicy']['rules'][0]['allowedClients'] == '10.0.0.0/8'
    assert 'READ_ONLY' in json.dumps(row)


@pytest.mark.parametrize('provider,kind,scope,native,data,expected', [
    ('aws', 'datasync_efs_location', '111111111111/us-east-1', 'arn:aws:datasync:us-east-1:111111111111:location/loc-one',
        {'Ec2Config': {'SubnetArn': 'arn:aws:ec2:us-east-1:111111111111:subnet/subnet-one'}}, 'subnet-one'),
    ('azure', 'traffic_controller_association', '/subscriptions/11111111-1111-1111-1111-111111111111',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.ServiceNetworking/trafficControllers/controller/associations/private',
        {'properties': {'subnet': {'id': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/host/subnets/alb'}}}, '/subnets/alb'),
    ('k8s', 'traefik_ingress_route', 'team-a', 'route', {'metadata': {'name': 'route', 'namespace': 'team-a'},
        'spec': {'routes': [{'services': [{'name': 'backend', 'port': 8443}]}]}}, '8443'),
])
def test_native_network_resources_survive_actual_agent_database_for_each_provider(tmp_path, provider, kind, scope, native, data, expected):
    from peaso.ai.network import build
    from peaso.ai.pipeline import private_json
    graph, ai = topology(provider, [(kind, native, scope, data)], {'cluster_id': 'cluster'} if provider == 'k8s' else {})
    build(tmp_path, ai, [], private_json)
    with sqlite3.connect(tmp_path / 'context.sqlite') as db:
        records = [json.loads(row[0]) for row in db.execute("SELECT detail FROM records WHERE domain='resources'")]
    assert len(records) == 1
    assert records[0]['type'] == kind
    assert expected in json.dumps(records[0]['data'])
    catalog = json.loads((tmp_path / 'topology.json').read_text())
    assert catalog['resource_counts'][kind] == 1
    assert sum(group['count'] for group in catalog['node_groups']) == len(graph['nodes'])
