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
        assert container['exposure_routes'][0]['controls'] == [
            'Client certificate required', 'Rule requires a matching hostname']
        assert container['exposure_routes'][0]['port'] == 443


def test_k8s_public_service_requires_ready_pod_identity_and_unique_container_port():
    facts = {
        'service': {'metadata': {'namespace': 'apps', 'name': 'front', 'uid': 'service-uid'},
                    'spec': {'type': 'LoadBalancer', 'ports': [{'name': 'https', 'port': 443, 'targetPort': 8443}]},
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


@pytest.mark.parametrize('mode', ['allow', 'deny', 'unresolved', None])
def test_aws_route_preserves_listener_authentication(mode):
    facts = aws_facts()
    rule = facts['load_balancer']['Listeners']['items'][0]['Rules']['items'][0]
    action = {'UnauthenticatedRequestMode': mode} if mode else {'AuthenticateOidcConfig': {}}
    rule['Actions'].insert(0, {'Type': 'authenticate-oidc', **action})
    rule['Conditions'] = [{'Field': 'host-header'}, {'Field': 'path-pattern'}]
    inventory = inventory_rows('aws', SCOPE, facts)
    evidence = open_finding(inventory, 'load_balancer', 'load_balancer')
    evidence['evidence']['exposed_ports'] = ['tcp/440-445']
    [container] = [row for row in enrich_runtime(running_images(inventory), inventory, [evidence])
                   if row.get('exposure_routes')]
    controls = container['exposure_routes'][0]['controls']
    assert ('Listener authentication required' in controls) == (mode in ('deny', None))
    assert ('Listener authentication unverified' in controls) == (mode == 'unresolved')
    assert 'Rule requires a matching hostname' in controls
    assert 'Rule requires a matching URL path' in controls


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


@pytest.mark.parametrize('provider,scope,kind,exposure_kind,facts', [
    ('aws', SCOPE, 'load_balancer', 'load_balancer', aws_facts()),
    ('gcp', 'projects/lab', 'cloudrun_service', 'serverless', {
        'cloudrun_service': {'name': 'projects/lab/locations/us-east1/services/web',
            'latestCreatedRevision': 'web-00001', 'latestReadyRevision': 'web-00001',
            'generation': '1', 'observedGeneration': '1',
            'trafficStatuses': [{'percent': 100, 'revision': 'web-00001'}],
            'template': {'containers': [{'name': 'web', 'image': f'registry.example/web@{DIGEST}',
                                         'ports': [{'containerPort': 8080}]}]}},
    }),
    ('azure', '/subscriptions/abc', 'container_group', 'container', {
        'container_group': {'id': '/subscriptions/abc/resourceGroups/qa/providers/Microsoft.ContainerInstance/containerGroups/web',
            'properties': {'containers': [{'name': 'web', 'properties': {
                'image': f'registry.example/web@{DIGEST}', 'ports': [{'port': 443}],
                'instanceView': {'currentState': {'state': 'Running'}}}}]}},
    }),
])
def test_native_exposure_is_a_required_report_source(provider, scope, kind, exposure_kind, facts):
    from peaso.ai.findings_report import source_index
    from peaso.container_exposure import CHECK, exposure_findings
    from tests.test_peaso_image_findings_20261021 import BASE

    observed = deepcopy(BASE)
    observed.update(provider=provider, scope=scope)
    observed['scan']['image'].update(provider=provider, scope=scope, manifest_digest=DIGEST,
                                      immutable_reference=f'registry.example/web@{DIGEST}')
    for advisory in observed['scan']['findings']:
        advisory['image_digest'] = DIGEST
    snapshot = make_snapshot(provider, [scope], [
        {'type': key, 'scope': scope, 'status': 'collected', 'items': [value]} for key, value in facts.items()
    ], metadata={'image_vulnerability_scan': {'selected': True, 'observations': [observed, observed]}})
    inventory = resources(snapshot)
    edge = open_finding(inventory, kind, exposure_kind)
    [result] = exposure_findings(snapshot, inventory, [edge], [])
    assert (result['check_id'], result['category'], result['status'], result['severity']) == (CHECK, 'exposure', 'FAIL', 'medium')
    assert sum(result['evidence']['advisory_totals'].values()) == 1
    assert result['evidence']['container'] == 'web'
    assert result['evidence']['exposure_routes'][0]['finding_id'] == edge['id']
    [assigned] = source_index({'inventory': inventory, 'report': {'findings': [result]}})
    assert assigned['id'] == result['id'] and assigned['required'] and assigned['kind'] is None
    assert assigned['assets'] == [result['native_resource_id']]
    assert exposure_findings(snapshot, inventory, [dict(edge, status='UNKNOWN')], []) == []


def test_gke_requires_exact_project_cluster_pod_and_cloud_edge():
    scope, cluster = 'projects/lab', 'projects/lab/locations/us-east1/clusters/test'
    meta = dict(cluster=cluster, namespace='apps')
    facts = {
        'gke_exposure_service': dict(meta, kubernetesName='web', uid='service-uid',
            spec={'type': 'LoadBalancer', 'ports': [{'port': 443, 'targetPort': 'http'}]},
            status={'loadBalancer': {'ingress': [{'ip': '192.0.0.9'}]}}),
        'gke_exposure_endpointslice': dict(meta, kubernetesName='web-slice', serviceName='web',
            serviceOwners=[{'kind': 'Service', 'uid': 'service-uid'}], ports=[{'port': 8080}],
            podTargets=[{'targetRef': {'kind': 'Pod', 'namespace': 'apps', 'uid': 'pod-uid'},
                         'conditions': {'ready': True}, 'addresses': ['10.0.0.2']}]),
        'gke_exposure_pod': dict(meta, kubernetesName='web-pod', uid='pod-uid',
            workloadSpec={'containers': [{'name': 'web', 'ports': [{'name': 'http', 'containerPort': 8080}]}]},
            workloadStatus={'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                'podIPs': [{'ip': '10.0.0.2'}], 'containerStatuses': [{'name': 'web',
                    'state': {'running': {}}, 'imageID': f'docker-pullable://registry.example/web@{DIGEST}'}]}),
    }
    inventory = inventory_rows('gcp', scope, facts)
    edge = open_finding(inventory, 'gke_exposure_service', 'gke_workload', address='192.0.0.9')
    [web] = enrich_runtime(running_images(inventory), inventory, [edge])
    assert web['provider'] == 'gcp' and web['scope'] == scope and 'exposure_routes' not in web
    edge['evidence']['path'] = [{'layer': 'gke_cloud_edge', 'decision': 'allow',
                                'public_ip': '192.0.0.9', 'ports': ['tcp/443']}]
    [web] = enrich_runtime(running_images(inventory), inventory, [edge])
    assert web['exposure_routes'][0]['container_port'] == 8080
    facts['gke_exposure_endpointslice']['cluster'] = cluster + '-other'
    separate = inventory_rows('gcp', scope, facts)
    [web] = enrich_runtime(running_images(separate), separate, [edge])
    assert 'exposure_routes' not in web


def test_azure_container_app_requires_a_healthy_replica_receiving_traffic():
    from peaso.collectors.azure_containerapp_runtime import _project

    scope = '/subscriptions/abc'
    ident = scope + '/resourceGroups/qa/providers/Microsoft.App/containerApps/web'
    app = {'id': ident, 'type': 'Microsoft.App/containerApps', 'identity': {'type': 'None'},
           'properties': {'latestReadyRevisionName': 'web--one', 'configuration': {'ingress': {
               'external': True, 'targetPort': 8080, 'clientCertificateMode': 'require',
               'traffic': [{'latestRevision': True, 'weight': 100}],
           }}}}
    revision = {'id': ident + '/revisions/web--one', 'properties': {
        'active': True, 'healthState': 'Healthy', 'replicas': 1,
        'template': {'containers': [{'name': 'web', 'image': f'registry.example/web@{DIGEST}',
                                     'env': [{'name': 'TEST', 'value': 'synthetic test data'}]}]},
    }}
    inventory = inventory_rows('azure', scope, {'container_app': app,
                                                 'container_app_runtime': _project(app, [revision], ident)})
    edge = open_finding(inventory, 'container_app', 'container_app')
    [web] = enrich_runtime(running_images(inventory), inventory, [edge])
    assert web['exposure_routes'][0]['controls'] == ['Client certificate required']
    revision['properties']['replicas'] = 0
    projection = _project(app, [revision], ident)
    assert 'synthetic test data' not in str(projection)
    inventory = inventory_rows('azure', scope, {'container_app': app, 'container_app_runtime': projection})
    assert not running_images(inventory)
