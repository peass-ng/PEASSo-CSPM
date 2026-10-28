"""Purpose evidence must survive the managed-service AI projection boundary."""
import copy
import json
import sqlite3

import pytest

from peaso.ai.network import build, native_network_resource, prepare, WORKLOAD_TYPES
from peaso.ai.pipeline import private_json
from peaso.analysis.network_services import SERVICE_TYPES


# Every workload whose native projection is shadowed by SERVICE_TYPES, with
# provider-native metadata and network attachments rather than generic mocks.
WORKLOAD_CASES = [
    ('aws', 'lambda_function', {
        'FunctionName': 'orders-api', 'Description': 'Order processing API',
        'Tags': {'tier': 'api'}, 'VpcConfig': {'VpcId': 'vpc-app', 'SubnetIds': ['subnet-app']},
        'Environment': {'Variables': {'TOKEN': 'NEVER_DISCLOSE'}},
        'Code': {'Content': 'NEVER_DISCLOSE'},
    }, [('Tags',), ('FunctionName',), ('Description',)], ('VpcConfig', 'VpcId'), 'vpc-app'),
    ('aws', 'rds_instance', {
        'TagList': [{'Key': 'tier', 'Value': 'database'}], 'DBInstanceIdentifier': 'orders-db',
        'DBSubnetGroup': {'VpcId': 'vpc-app'}, 'MasterUserPassword': 'NEVER_DISCLOSE',
    }, [('TagList',)], ('DBSubnetGroup', 'VpcId'), 'vpc-app'),
    ('aws', 'rds_cluster', {
        'TagList': [{'Key': 'Name', 'Value': 'orders-database'}],
        'DBClusterIdentifier': 'orders-db', 'DBSubnetGroupDetails': {'VpcId': 'vpc-app'},
        'MasterUserSecret': {'SecretArn': 'NEVER_DISCLOSE'},
    }, [('TagList',)], ('DBSubnetGroupDetails', 'VpcId'), 'vpc-app'),
    ('aws', 'eks_cluster', {
        'name': 'orders', 'Cluster': {'cluster': {'name': 'orders', 'tags': {'purpose': 'api'},
            'resourcesVpcConfig': {'vpcId': 'vpc-app'},
            'certificateAuthority': {'data': 'NEVER_DISCLOSE'}}},
    }, [('Cluster', 'cluster', 'tags')], ('Cluster', 'cluster', 'resourcesVpcConfig', 'vpcId'), 'vpc-app'),
    ('azure', 'app_service', {
        'name': 'orders-api', 'tags': {'tier': 'api'},
        'properties': {'virtualNetworkSubnetId': '/virtualNetworks/app/subnets/api',
            'siteConfig': {'appSettings': [{'name': 'TOKEN', 'value': 'NEVER_DISCLOSE'}]}}},
     [('tags',)], ('properties', 'virtualNetworkSubnetId'), '/virtualNetworks/app/subnets/api'),
    ('gcp', 'function', {
        'name': 'projects/p/locations/r/functions/orders', 'labels': {'tier': 'api'},
        'description': 'Orders API', 'serviceConfig': {'vpcConnector': 'projects/p/locations/r/connectors/app',
            'environmentVariables': {'TOKEN': 'NEVER_DISCLOSE'}},
        'buildConfig': {'source': {'content': 'NEVER_DISCLOSE'}},
    }, [('labels',), ('description',)], ('serviceConfig', 'vpcConnector'), 'projects/p/locations/r/connectors/app'),
    ('gcp', 'gke_cluster', {
        'name': 'orders', 'resourceLabels': {'tier': 'api'}, 'description': 'Orders cluster',
        'network': 'projects/p/global/networks/app',
        'masterAuth': {'password': 'NEVER_DISCLOSE'},
    }, [('resourceLabels',), ('description',)], ('network',), 'projects/p/global/networks/app'),
    ('k8s', 'daemonset', {
        'metadata': {'name': 'api-proxy', 'labels': {'app': 'api'}},
        'spec': {'template': {'metadata': {'labels': {'tier': 'api'}},
            'spec': {'hostNetwork': True, 'containers': [{'name': 'proxy',
                'env': [{'name': 'TOKEN', 'value': 'NEVER_DISCLOSE'}],
                'command': ['NEVER_DISCLOSE']}]}}},
    }, [('metadata', 'labels'), ('spec', 'template', 'metadata', 'labels')],
     ('spec', 'template', 'spec', 'hostNetwork'), True),
]


def at_path(data, path):
    for key in path:
        data = data[key]
    return data


def test_all_workload_service_overlaps_are_reviewed():
    assert {(provider, kind) for provider, kinds in SERVICE_TYPES.items()
            for kind in kinds & WORKLOAD_TYPES} == {(case[0], case[1]) for case in WORKLOAD_CASES}


@pytest.mark.parametrize('provider,kind,data,purpose_paths,network_path,network_value', WORKLOAD_CASES,
                         ids=[f'{case[0]}-{case[1]}' for case in WORKLOAD_CASES])
def test_workload_purpose_survives_prepare_and_agent_database(
        tmp_path, provider, kind, data, purpose_paths, network_path, network_value):
    inventory = [{'id': 'workload', 'native_id': 'native-workload', 'scope': 'test',
                  'provider': provider, 'type': kind, 'data': data}]
    original = copy.deepcopy(inventory)
    report = {'provider': provider, 'findings': [], 'graphs': {'network': {
        'nodes': [{'id': 'node-workload', 'resource_id': 'workload', 'type': kind}], 'edges': []}}}
    prepared = prepare(report, inventory, {})
    build(tmp_path, prepared, [], private_json)  # Reprojects at the file boundary.
    with sqlite3.connect(tmp_path / 'context.sqlite') as db:
        stored = json.loads(db.execute(
            "SELECT detail FROM records WHERE domain='resources' AND id='workload'").fetchone()[0])
        assert 'NEVER_DISCLOSE' not in '\n'.join(row[0] for row in db.execute("SELECT detail FROM records WHERE domain NOT IN ('source_resources','source_report')"))
    for projected in (prepared['inventory'][0], stored):
        for path in purpose_paths:
            assert at_path(projected['data'], path) == at_path(data, path)
        assert at_path(projected['data'], network_path) == network_value
    assert native_network_resource(prepared['inventory'][0]) == prepared['inventory'][0]
    assert inventory == original


@pytest.mark.parametrize('provider,kind,path', [
    ('aws', 'lambda_function', ('Tags',)),
    ('aws', 'rds_instance', ('TagList',)),
    ('aws', 'eks_cluster', ('tags',)),
    ('aws', 'eks_cluster', ('Cluster', 'cluster', 'tags')),
    ('gcp', 'function', ('labels',)),
    ('gcp', 'gke_cluster', ('resourceLabels',)),
    ('azure', 'app_service', ('tags',)),
])
def test_restored_purpose_maps_allow_only_known_string_labels(provider, kind, path):
    data = {}
    parent = data
    for key in path[:-1]:
        parent = parent.setdefault(key, {})
    parent[path[-1]] = {
        'tier': 'api', 'app.kubernetes.io/part-of': 'orders',
        'password': 'NEVER_DISCLOSE', 'apiKey': 'NEVER_DISCLOSE',
        'environment': 'NEVER_DISCLOSE', 'content': 'NEVER_DISCLOSE',
        'custom-application-setting': 'NEVER_DISCLOSE',
        'Name': {'content': 'NEVER_DISCLOSE'}, 'purpose': ['NEVER_DISCLOSE'], 'app': 42,
    }
    row = {'provider': provider, 'type': kind, 'data': data}
    first = native_network_resource(row)
    assert at_path(first['data'], path) == {'tier': 'api', 'app.kubernetes.io/part-of': 'orders'}
    assert 'NEVER_DISCLOSE' not in json.dumps(first)
    assert native_network_resource(first) == first


@pytest.mark.parametrize('field', ['Tags', 'TagList'])
def test_aws_purpose_tag_lists_check_tag_key_and_strip_extra_payload(field):
    row = {'provider': 'aws', 'type': 'rds_cluster', 'data': {field: [
        {'Key': 'tier', 'Value': 'database', 'Content': 'NEVER_DISCLOSE'},
        {'Key': 'password', 'Value': 'NEVER_DISCLOSE'},
        {'Key': 'environment', 'Value': 'NEVER_DISCLOSE'},
        {'Key': 'content', 'Value': 'NEVER_DISCLOSE'},
        {'Key': 'custom-setting', 'Value': 'NEVER_DISCLOSE'},
        {'Key': 'Name', 'Value': {'content': 'NEVER_DISCLOSE'}},
        {'Key': ['tier'], 'Value': 'NEVER_DISCLOSE'},
        {'Key': 'purpose'}, None, 'NEVER_DISCLOSE',
    ]}}
    first = native_network_resource(row)
    assert first['data'][field] == [{'Key': 'tier', 'Value': 'database'}]
    assert 'NEVER_DISCLOSE' not in json.dumps(first)
    assert native_network_resource(first) == first


@pytest.mark.parametrize('provider,kind,field', [
    ('aws', 'lambda_function', 'FunctionName'), ('aws', 'lambda_function', 'Description'),
    ('gcp', 'function', 'description'),
])
def test_purpose_text_does_not_admit_nested_settings(provider, kind, field):
    row = {'provider': provider, 'type': kind, 'data': {
        field: {'content': 'NEVER_DISCLOSE', 'Environment': {'TOKEN': 'NEVER_DISCLOSE'}},
        'Purpose': 'NEVER_DISCLOSE', 'DescriptionExtra': 'NEVER_DISCLOSE',
        'Environment': {'Tags': {'tier': 'NEVER_DISCLOSE'}},
        'content': {'labels': {'tier': 'NEVER_DISCLOSE'}},
    }}
    projected = native_network_resource(row)
    assert field not in projected['data']
    assert 'NEVER_DISCLOSE' not in json.dumps(projected)
