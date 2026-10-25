"""Regression evidence for independent SDK-audit additions, not name-only fixtures."""
import json
import pytest
from types import SimpleNamespace
from peaso.collectors.aws_network_inventory import PLANS, FETCHERS, READ_ACTIONS
from peaso.collectors.aws import Requests
from tests.test_peaso_network_managed_services import topology, node, linked


class NativeClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
    def can_paginate(self, name):
        return False
    def __getattr__(self, operation):
        def read(**arguments):
            self.calls.append((operation, arguments))
            response = self.responses[operation]
            return response(arguments) if callable(response) else response
        return read


class Session:
    def __init__(self, client):
        self.native = client
    def client(self, service, **kwargs):
        return self.native


def test_agentcore_harness_unavailable_sdk_operation_is_not_collected():
    client = NativeClient({})
    client.meta = SimpleNamespace(service_model=SimpleNamespace(operation_names=[]))
    read = FETCHERS['agentcore_harness'](Requests({}), Session(client), 'us-east-1', '111111111111')
    assert read.status == 'not_collected' and read.items == []
    assert read.error == {'code': 'sdk_operation_unavailable'}
    assert client.calls == []


@pytest.mark.parametrize('kind,responses,target_kind,target', [
    ('mwaa_environment', {'list_environments': {'Environments': ['airflow']}, 'get_environment': {'Environment': {
        'Name': 'airflow', 'Arn': 'arn:aws:airflow:us-east-1:111111111111:environment/airflow',
        'NetworkConfiguration': {'SubnetIds': ['subnet-one'], 'SecurityGroupIds': ['sg-one']},
        'AirflowConfigurationOptions': {'network': 'SECRET_SENTINEL'}}}}, 'subnet', 'subnet-one'),
    ('flink_application', {'list_applications': {'ApplicationSummaries': [{'ApplicationName': 'flink', 'ApplicationARN': 'arn:aws:kinesisanalytics:us-east-1:111111111111:application/flink'}]},
        'describe_application': {'ApplicationDetail': {'ApplicationName': 'flink', 'ApplicationARN': 'arn:aws:kinesisanalytics:us-east-1:111111111111:application/flink',
            'ApplicationConfigurationDescription': {'VpcConfigurationDescriptions': [{'VpcId': 'vpc-one', 'SubnetIds': ['subnet-one']}],
                'EnvironmentPropertyDescriptions': {'PropertyGroups': [{'PropertyMap': {'password': 'SECRET_SENTINEL'}}]}}}}}, 'vpc', 'vpc-one'),
    ('comprehend_document_classifier', {'list_document_classifiers': {'DocumentClassifierPropertiesList': [{'DocumentClassifierArn': 'arn:aws:comprehend:us-east-1:111111111111:document-classifier/classifier',
        'VpcConfig': {'Subnets': ['subnet-one'], 'SecurityGroupIds': ['sg-one']}, 'InputDataConfig': {'S3Uri': 'SECRET_SENTINEL'}}]}}, 'security_group', 'sg-one'),
    ('documentdb_elastic_cluster', {'list_clusters': {'clusters': [{'clusterArn': 'arn:aws:docdb-elastic:us-east-1:111111111111:cluster/id'}]},
        'get_cluster': {'cluster': {'clusterArn': 'arn:aws:docdb-elastic:us-east-1:111111111111:cluster/id', 'subnetIds': ['subnet-one'],
            'vpcSecurityGroupIds': ['sg-one'], 'adminUserName': 'SECRET_SENTINEL'}}}, 'security_group', 'sg-one'),
    ('eventbridge_pipe', {'list_pipes': {'Pipes': [{'Name': 'pipe', 'Arn': 'arn:aws:pipes:us-east-1:111111111111:pipe/pipe'}]},
        'describe_pipe': {'Name': 'pipe', 'Arn': 'arn:aws:pipes:us-east-1:111111111111:pipe/pipe',
            'SourceParameters': {'SelfManagedKafkaParameters': {'Vpc': {'Subnets': ['subnet-one'], 'SecurityGroup': ['sg-one']},
                'Credentials': {'BasicAuth': 'SECRET_SENTINEL'}}}, 'TargetParameters': {'HttpParameters': {'HeaderParameters': {'network': 'SECRET_SENTINEL'}}}}}, 'subnet', 'subnet-one'),
    ('prometheus_scraper', {'list_scrapers': {'scrapers': [{'arn': 'arn:aws:aps:us-east-1:111111111111:scraper/scraper',
        'source': {'eksConfiguration': {'clusterArn': 'arn:aws:eks:us-east-1:111111111111:cluster/cluster', 'subnetIds': ['subnet-one'], 'securityGroupIds': ['sg-one']}}}]}}, 'subnet', 'subnet-one'),
])
def test_native_reads_filter_before_cache_and_reach_map_and_agent(kind, responses, target_kind, target):
    client = NativeClient(responses)
    requests = Requests({'retry_attempts': 1})
    result = FETCHERS[kind](requests, Session(client), 'us-east-1', '111111111111')
    assert result.status == 'collected', result.error
    assert len(result.items) == 1
    cache = json.dumps([future.result() for future in requests._cache.values()])
    assert target in cache
    assert 'SECRET_SENTINEL' not in cache
    row = result.items[0]
    graph, ai = topology('aws', [(kind, row['NetworkResourceId'], '111111111111/us-east-1', row),
        (target_kind, target, '111111111111/us-east-1', {})])
    assert linked(graph, node(graph, kind, row['NetworkResourceId']), node(graph, target_kind, target))
    assert target in json.dumps(ai)
    assert 'SECRET_SENTINEL' not in json.dumps(ai)
    assert node(graph, kind, row['NetworkResourceId'])['network_attributes']


def test_native_pagination_without_sdk_paginator_and_detail_denial_preserve_gap():
    from botocore.exceptions import ClientError
    def page(arguments):
        if not arguments: return {'Environments': ['first'], 'NextToken': 'page-two'}
        assert arguments == {'NextToken': 'page-two'}
        return {'Environments': ['second']}
    def detail(arguments):
        if arguments['Name'] == 'second': raise ClientError({'Error': {'Code': 'AccessDeniedException'}}, 'GetEnvironment')
        return {'Environment': {'Name': 'first', 'Arn': 'arn:aws:airflow:us-east-1:111111111111:environment/first', 'NetworkConfiguration': {'SubnetIds': ['subnet-one']}}}
    client = NativeClient({'list_environments': page, 'get_environment': detail})
    result = FETCHERS['mwaa_environment'](Requests({'retry_attempts': 1}), Session(client), 'us-east-1', '111111111111')
    assert result.status == 'partial'
    assert len(result.items) == 2
    assert result.items[1]['_coverage']['network_detail']['status'] == 'denied'
    assert len([op for op, args in client.calls if op == 'list_environments']) == 2


def test_parent_scoped_resources_do_not_collide_and_parent_failure_is_not_empty():
    client = NativeClient({'list_farms': {'farms': [{'farmId': 'farm-one'}, {'farmId': 'farm-two'}]},
        'list_fleets': {'fleets': [{'fleetId': 'fleet'}]},
        'get_fleet': lambda a: {'farmId': a['farmId'], 'fleetId': 'fleet',
            'configuration': {'serviceManagedEc2': {'vpcConfiguration': {'subnetIds': ['subnet-one']}}}}})
    result = FETCHERS['deadline_fleet'](Requests({'retry_attempts': 1}), Session(client), 'us-east-1', '111111111111')
    assert result.status == 'collected'
    assert {row['NetworkResourceId'] for row in result.items} == {'farm-one/fleet', 'farm-two/fleet'}
    from botocore.exceptions import ClientError
    def denied(a): raise ClientError({'Error': {'Code': 'AccessDeniedException'}}, 'ListFarms')
    result = FETCHERS['deadline_fleet'](Requests({'retry_attempts': 1}), Session(NativeClient({'list_farms': denied})), 'us-east-1', '111111111111')
    assert result.status == 'denied'
    assert result.items == []


def test_network_projection_retains_lowercase_wrappers_but_excludes_content():
    from peaso.analysis.network_observations import network_observations
    from peaso.ai.network import native_network_resource
    data = {'workspace': {'vpcConfiguration': {'subnetIds': ['subnet-one'], 'securityGroupIds': ['sg-one']}},
        'requestTemplates': {'VpcId': 'SECRET_SENTINEL'}, 'environment': {'network': 'SECRET_SENTINEL'},
        'VpcEndpoint': 'https://user:SECRET_SENTINEL@endpoint.example/path?token=SECRET_SENTINEL'}
    safe = native_network_resource({'provider': 'aws', 'type': 'grafana_workspace', 'data': data})
    assert 'subnet-one' in json.dumps(safe)
    assert 'SECRET_SENTINEL' not in json.dumps(safe)
    assert 'SECRET_SENTINEL' not in json.dumps(network_observations(data))


def test_manifest_arguments_roots_identities_and_permissions_match_provider_schema():
    import botocore.session
    from botocore import xform_name
    from scripts.peaso_deploy_customer_policy import iam_action
    session = botocore.session.get_session()
    for kind, plan in PLANS.items():
        model = session.get_service_model(plan['service'])
        names = {xform_name(name): name for name in model.operation_names}
        for step in [*plan.get('parents', []), plan, *([plan['detail']] if 'detail' in plan else [])]:
            op = model.operation_model(names[step['operation']])
            args = {k.removesuffix('[]') for k in step.get('arguments', {})} | set(step.get('constants', {}))
            assert set(op.input_shape.required_members if op.input_shape else []) <= args, kind
            if step['key']: assert step['key'] in op.output_shape.members, kind
            assert iam_action(plan['service'], step['operation']), kind


def test_projection_does_not_mistake_scripts_or_free_form_properties_for_psc():
    from peaso.analysis.network_observations import network_observations
    data = {'startupScript': 'SECRET_SENTINEL', 'shutdownScript': 'SECRET_SENTINEL',
        'HyperParameters': {'VpcId': 'SECRET_SENTINEL'},
        'config': {'softwareConfig': {'properties': {'network': 'SECRET_SENTINEL'}}},
        'configurationOverrides': {'applicationConfiguration': [{'properties': {'vpcId': 'SECRET_SENTINEL'}}]},
        'pscConfig': {'allowedVpcs': ['projects/host/global/networks/network']},
        'enablePscGlobalAccess': False, 'privateServiceConnectConfig': {'networkAttachment': 'network-attachment'}}
    facts = network_observations(data)
    assert 'SECRET_SENTINEL' not in json.dumps(facts)
    assert 'projects/host/global/networks/network' in json.dumps(facts)
    assert any(f['name'] == 'enablePscGlobalAccess' and f['value'] is False for f in facts)


def test_sdk_user_maps_cannot_supply_network_field_names_to_metadata_projection():
    import botocore.session
    from peaso.collectors.aws_network_inventory import _native_structure
    from peaso.analysis.network_observations import network_observations
    model = botocore.session.get_session().get_service_model('bedrock')
    shape = model.operation_model('GetModelCustomizationJob').output_shape
    native = {'jobArn': 'arn:aws:bedrock:us-east-1:111111111111:model-customization-job/id',
        'hyperParameters': {'subnetIds': 'SECRET_SENTINEL', 'network': 'SECRET_SENTINEL'},
        'vpcConfig': {'subnetIds': ['subnet-one'], 'securityGroupIds': ['sg-one']}}
    safe = _native_structure(native, shape)
    assert 'SECRET_SENTINEL' not in json.dumps(safe)
    assert 'subnet-one' in json.dumps(network_observations(safe))


def test_agent_repeated_projection_preserves_existing_attributes_and_pod_ports():
    from peaso.ai.network import native_network_resource
    source = {'provider': 'aws', 'type': 'grafana_workspace', 'data': {
        'NetworkAttributes': [{'path': 'vpcConfiguration.subnetIds', 'name': 'subnetIds', 'value': ['subnet-one']}],
        'UnknownWrapper': {'networkConfiguration': {'securityGroupIds': ['sg-one']}}}}
    first = native_network_resource(source)
    second = native_network_resource(first)
    for result in (first, second):
        assert 'subnet-one' in json.dumps(result)
        assert 'sg-one' in json.dumps(result)
    pod = {'provider': 'k8s', 'type': 'pod', 'data': {'metadata': {'name': 'pod', 'namespace': 'apps'},
        'spec': {'containers': [{'ports': [{'containerPort': 8080, 'protocol': 'TCP'}]}]}}}
    assert native_network_resource(native_network_resource(pod))['data']['ports'] == [{'containerPort': 8080, 'protocol': 'TCP'}]


def test_attachment_ids_are_not_names_composites_or_comma_separated_references():
    from peaso.analysis.network_observations import aws_attachment
    for name, value in [('NetworkResourceId', 'sg-one/vpc-two'), ('NetworkName', 'vpc-one'), ('SubnetIds', 'subnet-one,subnet-two')]:
        assert list(aws_attachment({'path': name, 'name': name, 'value': value})) == []
    assert list(aws_attachment({'path': 'VpcEndpointServiceId', 'name': 'VpcEndpointServiceId', 'value': 'vpce-svc-one'}))[0][1] == 'vpc_endpoint_service'


def test_flink_applications_sharing_an_execution_role_keep_distinct_arn_identities():
    role = 'arn:aws:iam::111111111111:role/flink-exec'
    arn = 'arn:aws:kinesisanalytics:us-east-1:111111111111:application/{}'.format
    client = NativeClient({'list_applications': {'ApplicationSummaries': [
            {'ApplicationName': name, 'ApplicationARN': arn(name)} for name in ('one', 'two')]},
        'describe_application': lambda a: {'ApplicationDetail': {'ApplicationName': a['ApplicationName'],
            'ApplicationARN': arn(a['ApplicationName']), 'ApplicationMode': 'STREAMING', 'ServiceExecutionRole': role}}})
    result = FETCHERS['flink_application'](Requests({'retry_attempts': 1}), Session(client), 'us-east-1', '111111111111')
    assert result.status == 'collected', result.error
    assert [row['NetworkResourceId'] for row in result.items] == [arn('one'), arn('two')]
    # Privesc evaluation still receives the retained mode and execution role.
    assert all(row['ApplicationMode'] == 'STREAMING' and row['ServiceExecutionRole'] == role for row in result.items)
