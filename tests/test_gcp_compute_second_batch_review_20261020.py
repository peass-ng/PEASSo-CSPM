"""Independent native producer proof for the assigned 37 Compute/GKE controls."""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate
from tests.test_peaso_collectors_gcp import FixtureTransport, connector

ROOT = Path('/tmp/peasso-gcp-review-20261020/compute-second')
P = 'projects/p-one'
C = 'https://compute.googleapis.com/compute/v1/' + P
NETWORK = C + '/global/networks/review'
SUBNET = C + '/regions/us-central1/subnetworks/review'
POLICY = C + '/global/sslPolicies/review'
BACKEND = C + '/global/backendServices/review'
BUCKET = C + '/global/backendBuckets/review'
FLOW = 'https://networkmanagement.googleapis.com/v1/' + P + '/locations/global/vpcFlowLogsConfigs'
CLUSTERS = 'https://container.googleapis.com/v1/' + P + '/locations/-/clusters'
CRM = 'https://cloudresourcemanager.googleapis.com/v3/' + P
DNS = 'https://dns.googleapis.com/dns/v1/projects/p-one/policies'
FULL = 'https://www.googleapis.com/auth/cloud-platform'
DEFAULT = '123-compute@developer.gserviceaccount.com'
RECEIPTS = []


class NativeTransport(FixtureTransport):
    """Mirror the real transport's request-scope ledger used for alias proof."""
    def request(self, method, url, **kwargs):
        first = len(self.evidence)
        try:
            return super().request(method, url, **kwargs)
        finally:
            for entry in self.evidence[first:]:
                entry['scope'] = kwargs.get('scope')


@pytest.fixture(autouse=True)
def no_network_or_credentials(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('This native review forbids sockets, DNS and authentication')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(gcp, 'Credentials', blocked)


@pytest.fixture(scope='session', autouse=True)
def write_receipts():
    ROOT.mkdir(parents=True, exist_ok=True)
    yield
    (ROOT / 'native-cases.json').write_text(json.dumps(RECEIPTS, indent=2) + '\n')


def spec(cid, kind, path, good, bad, missing='UNKNOWN', dependencies=()):
    return dict(id=cid, kind=kind, path=path, good=good, bad=bad, missing=missing, dependencies=list(dependencies))


def nested(path, value):
    parts = path.split('.')
    result = value
    for part in reversed(parts): result = {part: result}
    return result


def scalar(cid, kind, path, good, bad, missing='UNKNOWN'):
    return spec(cid, kind, path, nested(path, good), nested(path, bad), missing)


def meta(key, value):
    return {'metadata': {'fingerprint': 'YWJj', 'items': [{'key': key, 'value': value}]}}


def pool(cid, path, good, bad, missing='UNKNOWN'):
    return spec('gcp.ports.' + cid, 'gke_cluster', 'nodePools',
                {'nodePools': [{'name': 'pool-a', 'config': nested(path, good)}]},
                {'nodePools': [{'name': 'pool-a', 'config': nested(path, bad)}]}, missing)


FW = {'direction': 'INGRESS', 'sourceRanges': ['0.0.0.0/0'], 'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}]}
SPECS = [
    spec('gcp.ports.compute_disk_encrypted_with_csk', 'disk', 'diskEncryptionKey.sha256',
         {'diskEncryptionKey': {'sha256': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='}}, {}, 'FAIL'),
    *[spec('gcp.ports.compute_firewall_rule_' + name + '_access_restricted', 'firewall', 'allowed',
           {**FW, 'sourceRanges': ['10.0.0.0/8'], 'allowed': [{'IPProtocol': 'tcp', 'ports': [str(port)]}]},
           {**FW, 'allowed': [{'IPProtocol': 'tcp', 'ports': [str(port)]}]}, 'PASS') for name, port in [('rdp', 3389), ('ssh', 22)]],
    spec('gcp.ports.compute_instance_block_project_wide_ssh_enabled', 'instance', 'metadata.items',
         meta('block-project-ssh-keys', 'true'), meta('block-project-ssh-keys', 'false')),
    scalar('gcp.ports.compute_instance_ip_forwarding_disabled', 'instance', 'canIpForward', False, True),
    spec('gcp.ports.compute_instance_shielded_vm_enabled', 'instance', 'shieldedInstanceConfig',
         {'shieldedInstanceConfig': {'enableVtpm': True, 'enableIntegrityMonitoring': True}},
         {'shieldedInstanceConfig': {'enableVtpm': True, 'enableIntegrityMonitoring': False}}),
    *[spec('gcp.ports.compute_instance_with_no_default_service_account' + suffix, 'instance', 'serviceAccounts',
           {'serviceAccounts': [{'email': 'nodes@p-one.iam.gserviceaccount.com', 'scopes': [FULL]}]},
           {'serviceAccounts': [{'email': DEFAULT, 'scopes': [FULL]}]}) for suffix in ['', '_with_full_access']],
    spec('gcp.ports.compute_instance_with_no_public_ip_addresses', 'instance', 'networkInterfaces',
         {'networkInterfaces': [{'name': 'nic0', 'network': NETWORK}]},
         {'networkInterfaces': [{'name': 'nic0', 'network': NETWORK, 'accessConfigs': [{'type': 'ONE_TO_ONE_NAT', 'natIP': '8.8.8.8'}]}]}),
    spec('gcp.ports.compute_network_contains_no_legacy_network', 'network', 'IPv4Range', {}, {'IPv4Range': '10.0.0.0/8'}, 'PASS'),
    spec('gcp.ports.compute_network_dns_logging_scoped', 'network', 'selfLink', {}, {}, dependencies=['dns_policy']),
    spec('gcp.ports.compute_oslogin_metadata_precedence', 'instance', 'metadata.items',
         meta('enable-oslogin', 'true'), meta('enable-oslogin', 'false'), 'FAIL', dependencies=['project', 'org_policy_effective']),
    spec('gcp.ports.compute_ssl_policy_strict_declaration', 'target_proxy', 'sslPolicy',
         {'kind': 'compute#targetHttpsProxy', 'sslPolicy': POLICY},
         {'kind': 'compute#targetHttpsProxy', 'sslPolicy': POLICY}, 'FAIL', dependencies=['ssl_policy']),
    spec('gcp.ports.compute_url_map_backend_logging', 'url_map', 'defaultService',
         {'defaultService': BACKEND}, {'defaultService': BACKEND}, dependencies=['backend_service', 'backend_bucket']),
    *[spec('gcp.ports.kubernetes_cluster_auto_' + word + '_enabled', 'gke_cluster', 'nodePools',
           {'nodePools': [{'name': 'pool-a', 'management': {field: True}}]},
           {'nodePools': [{'name': 'pool-a', 'management': {field: False}}]}) for word, field in [('repair', 'autoRepair'), ('upgrade', 'autoUpgrade')]],
    scalar('gcp.ports.kubernetes_cluster_intra_node_visibility_enabled', 'gke_cluster', 'networkConfig.enableIntraNodeVisibility', True, False, 'FAIL'),
    pool('kubernetes_cluster_legacy_endpoints_disabled', 'metadata.disable-legacy-endpoints', 'true', 'false'),
    pool('kubernetes_cluster_node_config_image_cos_containerd', 'imageType', 'COS_CONTAINERD', 'UBUNTU_CONTAINERD'),
    pool('kubernetes_cluster_shielded_instance_integrity_monitoring_enabled', 'shieldedInstanceConfig.enableIntegrityMonitoring', True, False),
    pool('kubernetes_cluster_shielded_node_secure_boot_enabled', 'shieldedInstanceConfig.enableSecureBoot', True, False),
    spec('gcp.ports.kubernetes_cluster_use_ip_aliases', 'gke_cluster', 'ipAllocationPolicy',
         {'ipAllocationPolicy': {'useIpAliases': True}}, {'ipAllocationPolicy': {'useRoutes': True}}),
    scalar('gcp.reviewed.compute.automatic_restart', 'instance', 'scheduling.automaticRestart', True, False),
    spec('gcp.reviewed.compute.block_project_ssh_keys', 'instance', 'metadata.items',
         meta('block-project-ssh-keys', 'true'), meta('block-project-ssh-keys', 'false')),
    scalar('gcp.reviewed.compute.confidential_computing', 'instance', 'confidentialInstanceConfig.enableConfidentialCompute', True, False),
    scalar('gcp.reviewed.compute.deletion_protection', 'instance', 'deletionProtection', True, False),
    spec('gcp.reviewed.compute.disk_auto_delete', 'instance', 'disks',
         {'disks': [{'type': 'PERSISTENT', 'deviceName': 'boot', 'autoDelete': False}]},
         {'disks': [{'type': 'PERSISTENT', 'deviceName': 'boot', 'autoDelete': True}]}),
    scalar('gcp.reviewed.compute.ip_forwarding', 'instance', 'canIpForward', False, True),
    scalar('gcp.reviewed.compute.maintenance_migrate', 'instance', 'scheduling.onHostMaintenance', 'MIGRATE', 'TERMINATE'),
    *[spec('gcp.reviewed.compute.' + suffix, 'instance', 'serviceAccounts',
           {'serviceAccounts': [{'email': 'nodes@p-one.iam.gserviceaccount.com', 'scopes': [FULL]}]},
           {'serviceAccounts': [{'email': DEFAULT, 'scopes': [FULL]}]}) for suffix in ['no_default_full_api', 'no_default_service_account']],
    spec('gcp.reviewed.compute.no_serial_console', 'instance', 'metadata.items',
         meta('serial-port-enable', 'false'), meta('serial-port-enable', 'true')),
    spec('gcp.reviewed.compute.single_interface', 'instance', 'networkInterfaces',
         {'networkInterfaces': [{'name': 'nic0', 'network': NETWORK}]},
         {'networkInterfaces': [{'name': 'nic0', 'network': NETWORK}, {'name': 'nic1', 'network': C + '/global/networks/other'}]}),
    scalar('gcp.reviewed.loadbalancer.backend_logging', 'backend_service', 'logConfig.enable', True, False),
    spec('gcp.reviewed.network.flow_logs', 'subnetwork', 'logConfig.enable',
         {'purpose': 'PRIVATE', 'logConfig': {'enable': True}},
         {'purpose': 'PRIVATE', 'logConfig': {'enable': False}}, 'FAIL', dependencies=['vpc_flow_logs_config']),
    spec('gcp.reviewed.network.no_default_vpc', 'network', 'name', {'name': 'dedicated'}, {'name': 'default'}),
    spec('gcp.reviewed.project.os_login_2fa', 'project', 'commonInstanceMetadata.items',
         {'commonInstanceMetadata': {'fingerprint': 'YWJj', 'items': [{'key': 'enable-oslogin', 'value': 'true'}, {'key': 'enable-oslogin-2fa', 'value': 'true'}]}},
         {'commonInstanceMetadata': {'fingerprint': 'YWJj', 'items': [{'key': 'enable-oslogin', 'value': 'true'}, {'key': 'enable-oslogin-2fa', 'value': 'false'}]}}, 'FAIL'),
]
assert len(SPECS) == 37


def find(suffix):
    return next(s for s in SPECS if s['id'].endswith(suffix))


def plan(case, branch):
    kind = case['kind']
    row = {'name': 'review', **deepcopy(case['bad' if branch == 'bad' else 'good'])}
    routes = {}
    def add(url, data, target=False): routes[url] = {'data': data, 'target': target}
    if kind == 'gke_cluster':
        row.update(location='us-central1-a', selfLink='https://container.googleapis.com/v1/' + P + '/locations/us-central1-a/clusters/review')
        add(CLUSTERS, {'clusters': [row]}, True)
    elif kind == 'project':
        metadata = row.pop('commonInstanceMetadata')
        row.update(name='projects/123', projectId='p-one')
        add(CRM, row, True)
        add(C, {'name': 'p-one', 'commonInstanceMetadata': metadata})
    else:
        for ck, endpoint, key, aggregated in gcp.COMPUTE:
            if ck != kind: continue
            location = 'zones/us-central1-a' if kind in ('instance', 'disk') else 'regions/us-central1' if kind == 'subnetwork' else 'global'
            selected = kind != 'target_proxy' or endpoint == 'aggregated/targetHttpsProxies'
            if selected:
                row.setdefault('selfLink', C + '/' + location + '/' + endpoint.rsplit('/', 1)[-1] + '/' + row['name'])
                if kind in ('instance', 'disk'): row['zone'] = C + '/zones/us-central1-a'
                if kind == 'subnetwork': row.update(region=C + '/regions/us-central1', network=NETWORK)
            items = [row] if selected else []
            add(C + '/' + endpoint, {'items': {location: {key: items}}} if aggregated else {'items': items}, selected)
    if 'dns_policy' in case['dependencies']:
        add(DNS, {'policies': [{'name': 'logging', 'enableLogging': branch != 'bad', 'networks': [{'networkUrl': row['selfLink']}]}]})
    if 'ssl_policy' in case['dependencies']:
        add(C + '/aggregated/sslPolicies', {'items': {'global': {'sslPolicies': [
            {'name': 'review', 'selfLink': POLICY, 'profile': 'COMPATIBLE' if branch == 'bad' else 'MODERN', 'minTlsVersion': 'TLS_1_2'}]}}})
    if 'backend_service' in case['dependencies']:
        add(C + '/aggregated/backendServices', {'items': {'global': {'backendServices': [
            {'name': 'review', 'selfLink': BACKEND, 'logConfig': {'enable': branch != 'bad'}}]}}})
    if 'backend_bucket' in case['dependencies']: add(C + '/global/backendBuckets', {'items': []})
    if 'project' in case['dependencies']:
        add(CRM, {'name': 'projects/123', 'projectId': 'p-one'})
        add(C, {'name': 'p-one', 'commonInstanceMetadata': {'fingerprint': 'YWJj'}})
    if 'org_policy_effective' in case['dependencies']:
        for constraint in gcp.ORG_POLICY_CONSTRAINTS:
            add('https://orgpolicy.googleapis.com/v2/' + P + '/policies/' + constraint + ':getEffectivePolicy',
                {'name': P + '/policies/' + constraint, 'spec': {'rules': [{'enforce': False}]}})
    if 'vpc_flow_logs_config' in case['dependencies']:
        add(FLOW, {'vpcFlowLogsConfigs': []})
        add(FLOW + ':queryOrgVpcFlowLogsConfigs', {'vpcFlowLogsConfigs': []})
    return row, routes


def capture(case, branch='good', mutate=None, denied_url=None):
    row, routes = plan(case, branch)
    if mutate: mutate(row, routes)
    primary = next(url for url, route in routes.items() if route['target'])
    if denied_url is None and branch == 'denied_inventory': denied_url = primary
    native = []
    def resolve(request):
        assert request['method'] == 'GET' and request['url'] in routes, request
        if request['url'] == denied_url or branch == 'partial' and request['url'] == primary and request.get('params', {}).get('pageToken'):
            native.append({'request': deepcopy(request), 'read_error': {'status': 'denied', 'http_status': 403}})
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        response = deepcopy(routes[request['url']]['data'])
        if branch == 'partial' and request['url'] == primary and case['kind'] != 'project': response['nextPageToken'] = 'review-next-page'
        native.append({'request': deepcopy(request), 'response': deepcopy(response)})
        return response
    transport = NativeTransport(resolve)
    collected = gcp.GCPCollector(connector([case['kind'], *case['dependencies']], metrics_scopes=False,
                                         compute_resource_iam=False), transport=transport).collect()
    assert validate(collected) == collected
    transport.review_native_responses = native
    return collected, transport


def verdict(case, branch, collected, transport, expected):
    original = deepcopy(collected)
    findings = evaluate_snapshot(collected, checks=[case['id']])['findings']
    assert collected == original
    RECEIPTS.append({'check_id': case['id'], 'scenario': branch,
                     'test_nodeid': os.environ.get('PYTEST_CURRENT_TEST', '').removesuffix(' (call)'),
                     'expected': expected, 'statuses': [f['status'] for f in findings], 'findings': findings,
                     'native_responses': transport.review_native_responses, 'collections': collected['collections']})
    assert sorted(f['status'] for f in findings) == sorted(expected if isinstance(expected, list) else [expected]), findings


@pytest.mark.parametrize('case', SPECS, ids=lambda c: c['id'])
@pytest.mark.parametrize('branch', ['good', 'bad', 'missing', 'malformed', 'denied_field', 'denied_inventory', 'partial'])
def test_native_deciding_field_matrix(case, branch):
    def mutate(row, routes):
        if branch not in ('missing', 'malformed'): return
        parent, parts = row, case['path'].split('.')
        if case['kind'] == 'project': parent = routes[C]['data']
        for part in parts[:-1]: parent = parent[part]
        if branch == 'missing': parent.pop(parts[-1], None)
        else: parent[parts[-1]] = {'invalid': True}
    collected, transport = capture(case, branch, mutate)
    expected = {'good': 'PASS', 'bad': 'FAIL', 'missing': case['missing'], 'malformed': 'UNKNOWN',
                'denied_field': 'UNKNOWN', 'denied_inventory': 'DENIED',
                'partial': 'PASS' if case['kind'] == 'project' else ['UNKNOWN', 'PASS']}[branch]
    if branch == 'denied_field':
        row = next(c for c in collected['collections'] if c['type'] == case['kind'])['items'][0]
        row.setdefault('_coverage', {})[case['path'].split('.')[0]] = {'status': 'denied'}
        collected.pop('snapshot_id', None)
    verdict(case, branch, collected, transport, expected)


@pytest.mark.parametrize('suffix', ['compute_instance_block_project_wide_ssh_enabled', 'compute_instance_ip_forwarding_disabled',
                                  'compute_instance_with_no_default_service_account', 'compute_instance_with_no_default_service_account_with_full_access'])
@pytest.mark.parametrize('scenario,expected', [('declared_gke', 'NOT_APPLICABLE'), ('name_only', 'FAIL'), ('label_only', 'FAIL')])
def test_source_gke_exclusion_requires_both_indicators(suffix, scenario, expected):
    case = find('gcp.ports.' + suffix)
    def mutate(row, routes):
        if scenario != 'label_only': row['name'] = 'gke-review'
        if scenario != 'name_only': row['labels'] = {'goog-gke-node': 'review'}
    collected, transport = capture(case, 'bad', mutate)
    verdict(case, 'gke_scope:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('suffix', ['compute.ip_forwarding', 'compute.no_default_full_api', 'compute.no_default_service_account', 'compute.single_interface'])
def test_reviewed_gke_naming_hint_requires_manual_review(suffix):
    case = find('gcp.reviewed.' + suffix)
    collected, transport = capture(case, 'bad', lambda row, routes: row.update(name='gke-review'))
    verdict(case, 'gke_naming_hint', collected, transport, 'MANUAL')


@pytest.mark.parametrize('suffix', ['compute_instance_with_no_default_service_account_with_full_access', 'compute.no_default_full_api'])
def test_default_account_with_narrow_oauth_scope(suffix):
    case = find(suffix)
    def mutate(row, routes): row['serviceAccounts'][0]['scopes'] = ['https://www.googleapis.com/auth/devstorage.read_only']
    collected, transport = capture(case, 'bad', mutate)
    verdict(case, 'narrow_default_scope', collected, transport, 'PASS')


@pytest.mark.parametrize('suffix', ['compute_instance_block_project_wide_ssh_enabled', 'compute.block_project_ssh_keys', 'compute.no_serial_console'])
def test_duplicate_explicit_metadata_is_ambiguous(suffix):
    case = find(suffix)
    def mutate(row, routes): row['metadata']['items'] *= 2
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'duplicate_metadata', collected, transport, 'UNKNOWN')


@pytest.mark.parametrize('scenario,instance,project,enforce,expected', [
    ('instance_overrides_enabled_project', 'false', 'true', False, 'FAIL'),
    ('instance_overrides_disabled_project', 'true', 'false', False, 'PASS'),
    ('inherits_enabled_project', None, 'true', False, 'PASS'),
    ('inherits_disabled_project', None, 'false', False, 'FAIL'),
    ('inherits_enforced_org_policy', None, None, True, 'PASS'),
    ('inherits_unenforced_org_policy', None, None, False, 'FAIL'),
    ('numeric_policy_alias', None, None, True, 'PASS'),
])
def test_oslogin_native_precedence_and_verified_project_alias(scenario, instance, project, enforce, expected):
    case = find('compute_oslogin_metadata_precedence')
    def mutate(row, routes):
        row['metadata'] = {'fingerprint': 'YWJj'}
        if instance is not None: row['metadata']['items'] = [{'key': 'enable-oslogin', 'value': instance}]
        if project is not None: routes[C]['data']['commonInstanceMetadata']['items'] = [{'key': 'enable-oslogin', 'value': project}]
        url = 'https://orgpolicy.googleapis.com/v2/' + P + '/policies/compute.requireOsLogin:getEffectivePolicy'
        routes[url]['data']['spec']['rules'][0]['enforce'] = enforce
        if scenario == 'numeric_policy_alias': routes[url]['data']['name'] = 'projects/123/policies/compute.requireOsLogin'
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'oslogin:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('scenario,expected', [('denied_inheritance', 'UNKNOWN'), ('explicit_instance', 'PASS')])
def test_oslogin_compute_metadata_denial(scenario, expected):
    case = find('compute_oslogin_metadata_precedence')
    def mutate(row, routes):
        if scenario == 'denied_inheritance': row['metadata'].pop('items')
    collected, transport = capture(case, 'good', mutate, denied_url=C)
    verdict(case, 'oslogin:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('suffix', ['compute_firewall_rule_ssh_access_restricted', 'compute_firewall_rule_rdp_access_restricted'])
@pytest.mark.parametrize('scenario,expected', [('ipv6', 'FAIL'), ('disabled', 'NOT_APPLICABLE'), ('egress', 'NOT_APPLICABLE'),
    ('deny_only', 'PASS'), ('omitted_source', 'FAIL'), ('source_tag_only', 'PASS'), ('numeric_tcp', 'FAIL'), ('invalid_port', 'UNKNOWN')])
def test_firewall_protocol_source_and_applicability(suffix, scenario, expected):
    case = find(suffix)
    def mutate(row, routes):
        if scenario == 'ipv6': row['sourceRanges'] = ['::/0']
        elif scenario == 'disabled': row['disabled'] = True
        elif scenario == 'egress': row['direction'] = 'EGRESS'
        elif scenario == 'deny_only': row.pop('allowed'); row['denied'] = [{'IPProtocol': 'all'}]
        elif scenario == 'omitted_source': row.pop('sourceRanges')
        elif scenario == 'source_tag_only': row.pop('sourceRanges'); row['sourceTags'] = ['internal']
        elif scenario == 'numeric_tcp': row['allowed'][0]['IPProtocol'] = '6'
        elif scenario == 'invalid_port': row['allowed'][0]['ports'] = ['70000']
    collected, transport = capture(case, 'bad', mutate)
    verdict(case, 'firewall:' + scenario, collected, transport, expected)


POOL_CASES = [s for s in SPECS if s['kind'] == 'gke_cluster' and s['path'] == 'nodePools']


@pytest.mark.parametrize('case', POOL_CASES, ids=lambda c: c['id'])
@pytest.mark.parametrize('reverse', [False, True])
def test_every_node_pool_is_evaluated(case, reverse):
    def mutate(row, routes):
        bad = deepcopy(case['bad']['nodePools'][0]); bad['name'] = 'pool-b'
        row['nodePools'].append(bad)
        if reverse: row['nodePools'].reverse()
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'pool_override:' + str(reverse), collected, transport, 'FAIL')


@pytest.mark.parametrize('suffix,expected', [
    ('kubernetes_cluster_shielded_instance_integrity_monitoring_enabled', 'PASS'),
    ('kubernetes_cluster_shielded_node_secure_boot_enabled', 'FAIL'),
    ('kubernetes_cluster_auto_repair_enabled', 'FAIL'), ('kubernetes_cluster_auto_upgrade_enabled', 'FAIL'),
])
def test_documented_node_pool_omission_defaults(suffix, expected):
    case = find(suffix)
    def mutate(row, routes):
        body = row['nodePools'][0]
        if 'management' in body: body['management'] = {}
        else: body['config']['shieldedInstanceConfig'] = {}
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'native_pool_omission_default', collected, transport, expected)


@pytest.mark.parametrize('scenario,expected', [('contradictory', 'UNKNOWN'), ('server_chosen', 'UNKNOWN'), ('routes', 'FAIL')])
def test_gke_ip_allocation_modes(scenario, expected):
    case = find('kubernetes_cluster_use_ip_aliases')
    values = {'contradictory': {'useIpAliases': True, 'useRoutes': True}, 'server_chosen': {}, 'routes': {'useRoutes': True}}
    collected, transport = capture(case, 'good', lambda row, routes: row.update(ipAllocationPolicy=values[scenario]))
    verdict(case, 'allocation:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('scenario,expected', [('weighted_bad_backend', 'FAIL'), ('redirect', 'NOT_APPLICABLE'),
    ('backend_bucket_only', 'NOT_APPLICABLE'), ('missing_backend', 'UNKNOWN'), ('denied_backend', 'UNKNOWN')])
def test_url_map_all_routes_and_backend_kinds(scenario, expected):
    case = find('compute_url_map_backend_logging')
    def mutate(row, routes):
        if scenario == 'weighted_bad_backend':
            row['defaultRouteAction'] = {'weightedBackendServices': [{'backendService': BACKEND, 'weight': 1}]}
            row.pop('defaultService')
            routes[C + '/aggregated/backendServices']['data']['items']['global']['backendServices'][0]['logConfig']['enable'] = False
        elif scenario == 'redirect':
            row.pop('defaultService'); row['defaultUrlRedirect'] = {'httpsRedirect': True}
        elif scenario == 'backend_bucket_only':
            row['defaultService'] = BUCKET
            routes[C + '/global/backendBuckets']['data']['items'] = [{'name': 'review', 'selfLink': BUCKET, 'bucketName': 'assets'}]
        elif scenario == 'missing_backend': row['defaultService'] = BACKEND.replace('p-one', 'p-two')
    collected, transport = capture(case, 'good', mutate, denied_url=C + '/aggregated/backendServices' if scenario == 'denied_backend' else None)
    verdict(case, 'url_map:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('scenario,expected', [('unfiltered_project', 'PASS'), ('filtered_project', 'MANUAL'), ('organization', 'PASS'),
    ('disabled', 'FAIL'), ('foreign_network', 'FAIL'), ('denied_alternative', 'UNKNOWN'), ('local_enabled_denied_alternative', 'PASS')])
def test_flow_logs_native_alternative_configuration(scenario, expected):
    case = find('gcp.reviewed.network.flow_logs')
    def mutate(row, routes):
        if scenario == 'local_enabled_denied_alternative': row['logConfig']['enable'] = True
        config = {'name': P + '/locations/global/vpcFlowLogsConfigs/logging', 'network': NETWORK, 'state': 'ENABLED'}
        if scenario == 'filtered_project': config['filterExpr'] = 'src_ip == "10.0.0.1"'
        elif scenario == 'disabled': config['state'] = 'DISABLED'
        elif scenario == 'foreign_network': config['network'] = NETWORK.replace('p-one', 'p-two')
        if scenario == 'organization':
            config.pop('network'); config['name'] = 'organizations/123/locations/global/vpcFlowLogsConfigs/logging'
            routes[FLOW + ':queryOrgVpcFlowLogsConfigs']['data']['vpcFlowLogsConfigs'] = [config]
        elif 'denied_alternative' not in scenario: routes[FLOW]['data']['vpcFlowLogsConfigs'] = [config]
    collected, transport = capture(case, 'bad', mutate, denied_url=FLOW if 'denied_alternative' in scenario else None)
    verdict(case, 'flow_alternative:' + scenario, collected, transport, expected)


def test_oslogin_2fa_requires_oslogin_enabled_native_counterexample():
    case = find('gcp.reviewed.project.os_login_2fa')
    def mutate(row, routes): routes[C]['data']['commonInstanceMetadata']['items'][0]['value'] = 'false'
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'regression:oslogin_disabled_2fa_true', collected, transport, 'FAIL')


def test_strict_ssl_policy_accepts_documented_tls13_native_counterexample():
    case = find('compute_ssl_policy_strict_declaration')
    def mutate(row, routes):
        policy = routes[C + '/aggregated/sslPolicies']['data']['items']['global']['sslPolicies'][0]
        policy.update(profile='RESTRICTED', minTlsVersion='TLS_1_3')
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'regression:documented_restricted_tls13', collected, transport, 'PASS')


def test_flow_logs_retains_observed_project_enablement_when_org_query_denied():
    case = find('gcp.reviewed.network.flow_logs')
    def mutate(row, routes):
        routes[FLOW]['data']['vpcFlowLogsConfigs'] = [
            {'name': P + '/locations/global/vpcFlowLogsConfigs/observed', 'network': NETWORK, 'state': 'ENABLED'}]
    collected, transport = capture(case, 'bad', mutate, denied_url=FLOW + ':queryOrgVpcFlowLogsConfigs')
    verdict(case, 'regression:observed_project_config_denied_org', collected, transport, 'PASS')


def test_url_map_documented_partial_backend_reference_native_counterexample():
    """UrlMap.defaultService accepts full or partial backend resource URLs."""
    case = find('compute_url_map_backend_logging')
    def mutate(row, routes): row['defaultService'] = 'projects/p-one/global/backendServices/review'
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'regression:documented_partial_backend_url', collected, transport, 'PASS')


@pytest.mark.parametrize('scenario,expected', [('v6_second_nic', 'FAIL'), ('v4_second_nic', 'FAIL'), ('private_two_nics', 'PASS')])
def test_external_addresses_scan_all_interface_families(scenario, expected):
    case = find('compute_instance_with_no_public_ip_addresses')
    def mutate(row, routes):
        second = {'name': 'nic1', 'network': C + '/global/networks/other'}
        if scenario == 'v6_second_nic': second['ipv6AccessConfigs'] = [{'type': 'DIRECT_IPV6', 'externalIpv6': '2600:1901:0:1::1'}]
        elif scenario == 'v4_second_nic': second['accessConfigs'] = [{'type': 'ONE_TO_ONE_NAT', 'natIP': '8.8.4.4'}]
        row['networkInterfaces'].append(second)
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'external_family:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('vtpm,monitoring,expected', [(True, False, 'FAIL'), (False, False, 'FAIL')])
def test_vm_shielding_requires_both_controls(vtpm, monitoring, expected):
    case = find('compute_instance_shielded_vm_enabled')
    def mutate(row, routes): row['shieldedInstanceConfig'] = {'enableVtpm': vtpm, 'enableIntegrityMonitoring': monitoring}
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'shielded:' + str((vtpm, monitoring)), collected, transport, expected)


@pytest.mark.parametrize('scenario,expected', [('persistent_and_scratch', 'PASS'), ('unknown_type', 'UNKNOWN')])
def test_retention_policy_distinguishes_local_scratch_disks(scenario, expected):
    case = find('gcp.reviewed.compute.disk_auto_delete')
    def mutate(row, routes):
        scratch = {'type': 'SCRATCH', 'deviceName': 'local-ssd', 'autoDelete': True}
        if scenario == 'persistent_and_scratch': row['disks'].append(scratch)
        else: row['disks'][0]['type'] = 'FUTURE'
    collected, transport = capture(case, 'good', mutate)
    verdict(case, 'disk_type:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('automatic', [False, True])
def test_nonlegacy_network_is_independent_of_auto_subnet_mode(automatic):
    case = find('compute_network_contains_no_legacy_network')
    collected, transport = capture(case, 'good', lambda row, routes: row.update(autoCreateSubnetworks=automatic))
    verdict(case, 'vpc_auto_subnets:' + str(automatic), collected, transport, 'PASS')
