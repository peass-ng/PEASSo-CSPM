from copy import deepcopy

import pytest

from peaso.ai.special_report_details import running_images
from peaso.container_exposure import enrich_runtime
from peaso.snapshot import make_snapshot, resources

DIGEST = 'sha256:' + 'a' * 64
SCOPE = '123456789012/us-east-1'
TASK = 'arn:aws:ecs:us-east-1:123456789012:task/cluster/task'
SERVICE = 'arn:aws:ecs:us-east-1:123456789012:service/cluster/web'
TARGET = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/id'
BALANCER = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/id'


def inventory_rows(provider, scope, values):
    return resources(make_snapshot(provider, [scope], [
        {'type': kind, 'scope': scope, 'status': 'collected', 'items': [value]}
        for kind, value in values.items()
    ]))


def aws_facts():
    listener = {'Protocol': 'HTTPS', 'Port': 443, 'MutualAuthentication': {'Mode': 'verify'}, 'Rules': {
        'collection_status': 'collected', 'items': [{
            'RuleArn': 'rule', 'Conditions': [{'Field': 'host-header'}],
            'Actions': [{'Type': 'forward', 'TargetGroupArn': TARGET}],
        }],
    }}
    return {
        'ecs_task': {'taskArn': TASK, 'clusterArn': 'cluster', 'group': 'service:web', 'lastStatus': 'RUNNING',
                     'containers': [{'name': 'web', 'lastStatus': 'RUNNING', 'imageDigest': DIGEST},
                                    {'name': 'sidecar', 'lastStatus': 'RUNNING', 'imageDigest': DIGEST}],
                     'attachments': [{'type': 'ElasticNetworkInterface', 'status': 'ATTACHED',
                                      'details': [{'name': 'privateIPv4Address', 'value': '10.0.0.2'}]}]},
        'ecs_service': {'serviceArn': SERVICE, 'serviceName': 'web', 'clusterArn': 'cluster', 'status': 'ACTIVE',
                        'loadBalancers': [{'targetGroupArn': TARGET, 'containerName': 'web', 'containerPort': 8080}]},
        'load_balancer': {'LoadBalancerArn': BALANCER, 'Scheme': 'internet-facing', 'Type': 'application',
                          'DNSName': 'edge.example.com', 'Listeners': {'collection_status': 'collected', 'items': [listener]}},
        'target_group': {'TargetGroupArn': TARGET, 'TargetType': 'ip', 'TargetHealth': {
            'collection_status': 'collected', 'TargetHealthDescriptions': [
                {'Target': {'Id': '10.0.0.2', 'Port': 8080}, 'TargetHealth': {'State': 'healthy'}},
            ],
        }},
    }


def open_finding(inventory, kind, exposure_kind, address='edge.example.com', port=443, status='FAIL'):
    resource = next(row for row in inventory if row['type'] == kind)
    return {'id': 'open', 'check_id': 'analysis.internet_exposure', 'resource_id': resource['id'], 'status': status,
            'evidence': {'exposure_kind': exposure_kind, 'exposed_ports': [f'tcp/{port}'], 'public_addresses': [address]}}


@pytest.mark.parametrize('gap', ['unknown_exposure', 'zero_weight', 'wrong_ip', 'stopped', 'wrong_port', 'private_rule', None])
def test_aws_routes_require_the_running_container_and_exact_healthy_target(gap):
    facts = aws_facts()
    rule = facts['load_balancer']['Listeners']['items'][0]['Rules']['items'][0]
    health = facts['target_group']['TargetHealth']['TargetHealthDescriptions'][0]
    if gap == 'zero_weight':
        rule['Actions'][0]['ForwardConfig'] = {'TargetGroups': [{'TargetGroupArn': TARGET, 'Weight': 0}]}
    if gap == 'wrong_ip':
        health['Target']['Id'] = '10.0.0.3'
    if gap == 'wrong_port':
        health['Target']['Port'] = 8081
    if gap == 'stopped':
        facts['ecs_task']['lastStatus'] = 'STOPPED'
    if gap == 'private_rule':
        rule['Conditions'] = [{'Field': 'source-ip', 'Values': ['10.0.0.0/8']}]
    inventory = inventory_rows('aws', SCOPE, facts)
    finding = open_finding(inventory, 'load_balancer', 'load_balancer',
                           status='UNKNOWN' if gap == 'unknown_exposure' else 'FAIL')
    attributed = [row for row in enrich_runtime(running_images(inventory), inventory, [finding]) if row.get('exposure_routes')]
    if gap:
        assert attributed == []
    else:
        [container] = attributed
        assert container['container'] == 'web'
        assert container['exposure_routes'][0]['controls'] == ['Client certificate required']
        assert container['exposure_routes'][0]['port'] == 443


def test_k8s_public_service_requires_ready_pod_identity_and_unique_container_port():
    facts = {
        'service': {'metadata': {'namespace': 'apps', 'name': 'front', 'uid': 'service-uid'},
                    'spec': {'type': 'LoadBalancer', 'ports': [{'name': 'https', 'port': 443}]},
                    'status': {'loadBalancer': {'ingress': [{'hostname': 'edge.example.com'}]}}},
        'endpointslice': {'metadata': {'namespace': 'apps', 'name': 'front-1',
            'labels': {'kubernetes.io/service-name': 'front'},
            'ownerReferences': [{'kind': 'Service', 'uid': 'service-uid'}]},
            'ports': [{'name': 'https', 'port': 8443}],
            'endpoints': [{'conditions': {'ready': True}, 'addresses': ['10.0.0.2'],
                           'targetRef': {'kind': 'Pod', 'namespace': 'apps', 'uid': 'pod-uid'}}]},
        'pod': {'metadata': {'namespace': 'apps', 'name': 'front-pod', 'uid': 'pod-uid'},
                'spec': {'containers': [{'name': 'front', 'ports': [{'containerPort': 8443}]}]},
                'status': {'phase': 'Running', 'podIP': '10.0.0.2',
                           'conditions': [{'type': 'Ready', 'status': 'True'}],
                           'containerStatuses': [{'name': 'front', 'state': {'running': {}},
                                                  'imageID': f'docker-pullable://registry.example/front@{DIGEST}'}]}},
    }
    for stale in (False, True):
        data = deepcopy(facts)
        if stale:
            data['endpointslice']['endpoints'][0]['targetRef']['uid'] = 'stale-uid'
        inventory = inventory_rows('k8s', 'cluster', data)
        evidence = open_finding(inventory, 'service', 'service')
        [container] = enrich_runtime(running_images(inventory), inventory, [evidence])
        if stale:
            assert 'exposure_routes' not in container
        else:
            assert container['exposure_routes'][0]['container_port'] == 8443


@pytest.mark.parametrize('mode', ['allow', 'deny', None])
def test_aws_route_preserves_listener_authentication(mode):
    facts = aws_facts()
    rule = facts['load_balancer']['Listeners']['items'][0]['Rules']['items'][0]
    rule['Actions'].insert(0, {'Type': 'authenticate-oidc',
                               'AuthenticateOidcConfig': {'OnUnauthenticatedRequest': mode} if mode else {}})
    inventory = inventory_rows('aws', SCOPE, facts)
    evidence = open_finding(inventory, 'load_balancer', 'load_balancer')
    [container] = [row for row in enrich_runtime(running_images(inventory), inventory, [evidence])
                   if row.get('exposure_routes')]
    assert ('Listener authentication required' in container['exposure_routes'][0]['controls']) == (mode != 'allow')


def test_cross_assessment_route_requires_ownership_of_both_sources(monkeypatch):
    from types import SimpleNamespace

    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient

    from peaso.image_findings import SCHEMA
    from peaso.server.image_findings_routes import install_routes
    from peaso.storage.artifacts import reference_for
    from tests.test_peaso_image_findings_20261021 import BASE

    tenant, workload_scan, image_scan = 'tenant-a', 'a' * 32, 'b' * 32
    reference = reference_for(tenant, workload_scan, 'snapshot')
    image_reference = reference_for(tenant, image_scan, 'detail')
    snapshot = make_snapshot('aws', [SCOPE], [
        {'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': [value]}
        for kind, value in aws_facts().items()
    ])
    inventory = resources(snapshot)
    exposure = open_finding(inventory, 'load_balancer', 'load_balancer')
    allowed = {workload_scan, image_scan}
    reads = []

    def owned_bundle(request_tenant, scan):
        if request_tenant != tenant or scan not in allowed:
            raise HTTPException(404, 'Scan not found')
        if scan == workload_scan:
            return {'status': 'completed', 'snapshot': reference}, {'findings': [exposure]}
        return {'status': 'completed'}, {'image_vulnerability_scan': {'selected': True, 'artifact': image_reference}}

    def get(request_tenant, ref):
        assert request_tenant == tenant
        reads.append(ref)
        if ref == reference:
            return snapshot
        assert ref == image_reference
        return {'schema': SCHEMA, 'scan_id': image_scan, 'observations': [BASE]}

    # The existing image route validates the complete immutable observation
    # contract independently. The emitted report rows use the real builder here.
    from peaso.image_findings import build_report
    from peaso.server import image_findings_routes
    built = build_report([BASE], selected=True)
    assert built['rows']
    for item in built['rows']:
        item['image_digest'] = DIGEST
    monkeypatch.setattr(image_findings_routes, 'build_report', lambda *_args, **_kwargs: built)
    app = FastAPI()
    install_routes(app, identity=lambda: SimpleNamespace(tenant_id=tenant),
                   owned_bundle=owned_bundle, artifacts=SimpleNamespace(get=get))
    client = TestClient(app)
    path = f'/api/scans/{workload_scan}/exposed-containers'
    allowed.remove(image_scan)
    assert client.get(path, params={'image_scan_id': image_scan}).status_code == 404
    assert reads == []
    allowed.add(image_scan)
    body = client.get(path, params={'image_scan_id': image_scan}).json()
    assert body['total'] == 1
    assert [container['container'] for container in body['items']] == ['web']
    assert body['items'][0]['counts']['high'] == 1
