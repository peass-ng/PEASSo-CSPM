"""Assigned 30-check native API -> collector -> engine review; no credentials/network.

Positive fixtures contain only documented native fields, never collector attestations.
Coverage fault cases are explicitly post-collection faults, not provider responses.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot

ROOT = Path(os.environ.get('GCP_COMPUTE_REVIEW_RECEIPT_DIR', '/tmp/peasso-gcp-review-20261020/compute'))
P = 'projects/p-one'
C = 'https://compute.googleapis.com/compute/v1/' + P
N = C + '/global/networks/review'
G = C + '/zones/us-central1-a/instanceGroups/review'
SSL = C + '/global/sslPolicies/review'
PREFIX = 'gcp.claude.'
RECEIPTS = []


@pytest.fixture(autouse=True)
def no_network_or_auth(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('native review forbids socket, DNS and authentication')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(gcp, 'Credentials', blocked)


@pytest.fixture(scope='session', autouse=True)
def receipts():
    ROOT.mkdir(parents=True, exist_ok=True)
    yield
    (ROOT / 'native-cases.json').write_text(json.dumps(RECEIPTS, indent=2) + '\n')


def spec(slug, kind, good, bad, path, **kwargs):
    return {'id': PREFIX + slug, 'kind': kind, 'good': good, 'bad': bad,
            'path': path, **kwargs}


FW = {'name': 'default-allow-ssh', 'direction': 'INGRESS',
      'network': C + '/global/networks/default', 'sourceRanges': ['0.0.0.0/0'],
      'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}]}
SPECS = [
    spec('backend_service.external_iap', 'backend_service',
         {'loadBalancingScheme': 'EXTERNAL_MANAGED', 'iap': {'enabled': True}},
         {'loadBalancingScheme': 'EXTERNAL_MANAGED', 'iap': {'enabled': False}}, 'iap.enabled'),
    spec('firewall.default_rules_not_open', 'firewall', {**FW, 'sourceRanges': ['10.0.0.0/8']}, FW, 'sourceRanges'),
    spec('firewall.logging_enabled', 'firewall', {**FW, 'logConfig': {'enable': True}},
         {**FW, 'logConfig': {'enable': False}}, 'logConfig.enable'),
    spec('firewall.public_ingress_all_protocols', 'firewall',
         {**FW, 'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}]},
         {**FW, 'allowed': [{'IPProtocol': 'all'}]}, 'allowed'),
    spec('firewall.public_ingress_common_ports', 'firewall', {**FW, 'sourceRanges': ['10.0.0.0/8']}, FW, 'allowed'),
    spec('firewall.public_ingress_tcp_udp', 'firewall', {**FW, 'sourceRanges': ['10.0.0.0/8']}, FW, 'allowed'),
    spec('firewall.public_ingress_without_target', 'firewall', {**FW, 'targetTags': ['web']}, FW, 'targetTags'),
    spec('image.not_public', 'image', {'iamPolicy': {}},
         {'iamPolicy': {'bindings': [{'role': 'roles/compute.imageUser', 'members': ['allAuthenticatedUsers']}]}}, 'iamPolicy'),
    spec('instance.disks_csek', 'instance', {'disks': [{'type': 'PERSISTENT', 'deviceName': 'boot',
         'diskEncryptionKey': {'sha256': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='}}]},
         {'disks': [{'type': 'PERSISTENT', 'deviceName': 'boot'}]}, 'disks'),
    spec('instance.not_preemptible', 'instance', {'scheduling': {'preemptible': False}},
         {'scheduling': {'preemptible': True}}, 'scheduling.preemptible'),
    spec('instance.not_preemptible_or_spot', 'instance', {'scheduling': {'provisioningModel': 'STANDARD'}},
         {'scheduling': {'provisioningModel': 'SPOT'}}, 'scheduling.provisioningModel'),
    spec('instance.suspended_without_disks', 'instance', {'status': 'SUSPENDED', 'disks': []},
         {'status': 'SUSPENDED', 'disks': [{'deviceName': 'boot', 'type': 'PERSISTENT'}]}, 'disks'),
    spec('instance_group_manager.autohealing', 'instance_group_manager',
         {'autoHealingPolicies': [{'healthCheck': C + '/global/healthChecks/review'}]}, {}, 'autoHealingPolicies'),
    spec('instance_group_manager.load_balancer_attached', 'instance_group_manager', {'instanceGroup': G},
         {'instanceGroup': G}, 'instanceGroup', dependencies=['backend_service'], bad_status='MANUAL'),
    spec('instance_group_manager.multiple_zones', 'instance_group_manager',
         {'region': C + '/regions/us-central1', 'distributionPolicy': {'zones': [
             {'zone': C + '/zones/us-central1-a'}, {'zone': C + '/zones/us-central1-b'}]}},
         {'zone': C + '/zones/us-central1-a'}, 'distributionPolicy'),
    spec('instance_template.no_ip_forwarding', 'instance_template', {'properties': {'canIpForward': False}},
         {'properties': {'canIpForward': True}}, 'properties.canIpForward'),
    spec('network.dns_logging', 'network', {'selfLink': N}, {'selfLink': N}, 'selfLink', dependencies=['dns_policy']),
    spec('organization.essential_contacts_any', 'organization', {'name': 'organizations/123'},
         {'name': 'organizations/123'}, 'name', dependencies=['essential_contact'], scope='organizations/123'),
    spec('project.container_scanning_api_enabled', 'project', {}, {}, 'name', dependencies=['service_usage']),
    spec('project.gemini_api_disabled', 'project', {}, {}, 'name', dependencies=['service_usage']),
    spec('project.no_api_keys', 'project', {}, {}, 'name', dependencies=['api_key']),
    spec('project.oslogin_enabled', 'project', {'commonInstanceMetadata': {'fingerprint': 'abc',
         'items': [{'key': 'enable-oslogin', 'value': 'TRUE'}]}},
         {'commonInstanceMetadata': {'fingerprint': 'abc', 'items': [{'key': 'enable-oslogin', 'value': 'FALSE'}]}},
         'commonInstanceMetadata.items'),
    *[spec(kind + '.not_public', kind, {'iamPolicy': {}},
           {'iamPolicy': {'bindings': [{'role': 'roles/pubsub.viewer', 'members': ['allUsers']}]}}, 'iamPolicy')
      for kind in ['pubsub_snapshot', 'pubsub_subscription', 'pubsub_topic']],
    spec('snapshot.not_outdated', 'snapshot', {'creationTimestamp': 'RECENT'},
         {'creationTimestamp': 'OLD'}, 'creationTimestamp'),
    spec('target_proxy.https_custom_ssl_policy', 'target_proxy', {'kind': 'compute#targetHttpsProxy', 'sslPolicy': SSL},
         {'kind': 'compute#targetHttpsProxy'}, 'sslPolicy'),
    spec('target_proxy.https_min_tls_1_2', 'target_proxy', {'kind': 'compute#targetHttpsProxy', 'sslPolicy': SSL},
         {'kind': 'compute#targetHttpsProxy', 'sslPolicy': SSL}, 'sslPolicy', dependencies=['ssl_policy']),
    {'id': 'gcp.claude2.api_key.created_within_90_days', 'kind': 'api_key',
     'good': {'createTime': 'RECENT'}, 'bad': {'createTime': 'OLD'}, 'path': 'createTime'},
    {'id': 'gcp.appengine.version_https_only', 'kind': 'app_engine_version',
     'good': {'servingStatus': 'SERVING', 'handlers': [{'securityLevel': 'SECURE_ALWAYS'}]},
     'bad': {'servingStatus': 'SERVING', 'handlers': [{'securityLevel': 'SECURE_OPTIONAL'}]},
     'path': 'handlers', 'good_status': 'PASS', 'bad_status': 'FAIL'},
]
assert len(SPECS) == 30


def native_plan(case, variant):
    """Only fake public API responses; keys assert exact method/host/path."""
    kind, scope = case['kind'], case.get('scope', P)
    row = {'name': 'review', 'id': '10001', **deepcopy(case['bad' if variant == 'bad' else 'good'])}
    for field in ['creationTimestamp', 'createTime']:
        if row.get(field) in ('RECENT', 'OLD'):
            days = 1 if row[field] == 'RECENT' else 100
            row[field] = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    routes = {}
    def add(url, data, target=False):
        routes[url] = {'data': data, 'target': target}
    if kind == 'project':
        metadata = row.pop('commonInstanceMetadata', {'fingerprint': 'abc'})
        row.update(name=P, projectId='p-one', parent='organizations/123')
        row.pop('id', None)
        add('https://cloudresourcemanager.googleapis.com/v3/' + P, row, True)
        add(C, {'name': 'p-one', 'commonInstanceMetadata': metadata})
    elif kind == 'organization':
        row.pop('id', None)
        add('https://cloudresourcemanager.googleapis.com/v3/' + scope, row, True)
    elif kind == 'api_key':
        row.update(name=P + '/locations/global/keys/review', uid='11111111-1111-4111-8111-111111111111')
        row.pop('id', None)
        add('https://apikeys.googleapis.com/v2/' + P + '/locations/global/keys', {'keys': [row]}, True)
    elif kind == 'app_engine_version':
        service = 'apps/p-one/services/default'
        row.update(name=service + '/versions/v1', id='v1')
        add('https://appengine.googleapis.com/v1/apps/p-one/services', {'services': [{'id': 'default', 'name': service}]})
        add('https://appengine.googleapis.com/v1/' + service + '/versions', {'versions': [row]}, True)
    elif kind.startswith('pubsub_'):
        segment = {'pubsub_topic': 'topics', 'pubsub_subscription': 'subscriptions', 'pubsub_snapshot': 'snapshots'}[kind]
        policy = row.pop('iamPolicy')
        row = {'name': P + '/' + segment + '/review'}
        add('https://pubsub.googleapis.com/v1/' + P + '/' + segment, {segment: [row]}, True)
        add('https://pubsub.googleapis.com/v1/' + row['name'] + ':getIamPolicy', policy)
    else:
        policy = row.pop('iamPolicy', None)
        for ck, endpoint, key, aggregate in gcp.COMPUTE:
            if ck != kind:
                continue
            chosen = kind != 'target_proxy' or endpoint == 'aggregated/targetHttpsProxies'
            items = [row] if chosen else []
            location = ('zones/us-central1-a' if kind in ('instance', 'instance_group_manager') else 'global')
            if 'region' in row:
                location = 'regions/us-central1'
            if chosen:
                segment = endpoint.split('/')[-1]
                row.setdefault('selfLink', C + '/' + location + '/' + segment + '/' + row['name'])
            data = {'items': {location: {key: items}}} if aggregate else {'items': items}
            # 9b483c7d: the snapshot aggregatedList exists only in Compute beta.
            root = C.replace('/compute/v1/', '/compute/beta/') if kind == 'snapshot' else C
            add(root + '/' + endpoint, data, chosen)
        if kind == 'snapshot':
            add(row['selfLink'] + '/getIamPolicy', policy or {'bindings': []})
        if kind == 'image':
            add(C + '/global/images/review/getIamPolicy', policy)
    if 'backend_service' in case.get('dependencies', []):
        add(C + '/aggregated/backendServices', {'items': {'global': {'backendServices': [] if variant == 'bad' else [
            {'name': 'backend', 'backends': [{'group': G}]}]}}})
    if 'dns_policy' in case.get('dependencies', []):
        add('https://dns.googleapis.com/dns/v1/projects/p-one/policies', {'policies': [
            {'name': 'review', 'networks': [{'networkUrl': N}], 'enableLogging': variant != 'bad'}]})
    if 'ssl_policy' in case.get('dependencies', []):
        add(C + '/aggregated/sslPolicies', {'items': {'global': {'sslPolicies': [
            {'name': 'review', 'selfLink': SSL, 'minTlsVersion': 'TLS_1_0' if variant == 'bad' else 'TLS_1_2'}]}}})
    if 'api_key' in case.get('dependencies', []):
        add('https://apikeys.googleapis.com/v2/' + P + '/locations/global/keys', {'keys': [
            {'name': P + '/locations/global/keys/review'}] if variant == 'bad' else []})
    if 'essential_contact' in case.get('dependencies', []):
        add('https://essentialcontacts.googleapis.com/v1/' + scope + '/contacts', {'contacts': [] if variant == 'bad' else [
            {'name': scope + '/contacts/1', 'email': 'review@example.invalid', 'validationState': 'VALID'}]})
    if 'service_usage' in case.get('dependencies', []):
        service, want = ('containerscanning.googleapis.com', 'ENABLED') if 'container_scanning' in case['id'] else ('generativelanguage.googleapis.com', 'DISABLED')
        add('https://serviceusage.googleapis.com/v1/' + P + '/services', {'services': [
            {'name': 'projects/123/services/' + service, 'state': ('DISABLED' if want == 'ENABLED' else 'ENABLED') if variant == 'bad' else want}]})
        row['name'] = 'projects/123'
    return row, routes


def collect(case, variant, mutate=None):
    row, routes = native_plan(case, variant)
    if mutate:
        mutate(row, routes)
    expected_routes = set(routes)
    primary = next(url for url, route in routes.items() if route['target'])
    responses = []
    def resolve(request):
        parsed = urlsplit(request['url'])
        assert request['method'] == 'GET'
        assert (parsed.scheme, parsed.netloc, parsed.path) in {
            (urlsplit(u).scheme, urlsplit(u).netloc, urlsplit(u).path) for u in expected_routes}
        assert request['url'] in routes, request
        if variant == 'denied' and request['url'] == primary:
            responses.append({'request': deepcopy(request), 'read_error': {'status': 'denied', 'http_status': 403}})
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        if variant == 'partial' and request['url'] == primary and request.get('params', {}).get('pageToken'):
            responses.append({'request': deepcopy(request), 'read_error': {'status': 'denied', 'http_status': 403}})
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        data = deepcopy(routes[request['url']]['data'])
        if variant == 'partial' and request['url'] == primary:
            # Singleton metadata has no pagination; represent denied hydration in separate cases.
            if case['kind'] not in ('project', 'organization'):
                data['nextPageToken'] = 'review-page-two'
        if 'appengine.googleapis.com' in request['url'] and request['url'].endswith('/versions'):
            assert request['params']['view'] == 'FULL'
            assert request['params']['fields'] == 'versions(id,name,servingStatus,env,runtime,serviceAccount,handlers(securityLevel)),nextPageToken'
        if request['url'].endswith('getIamPolicy'):
            assert request['params'] == ({'optionsRequestedPolicyVersion': 3} if case['kind'] in ('image', 'snapshot') else {'options.requestedPolicyVersion': 3})
        responses.append({'request': deepcopy(request), 'response': deepcopy(data)})
        return data
    collected, transport = snapshot([case['kind'], *case.get('dependencies', [])], resolve,
                                    scopes=[case.get('scope', P)], metrics_scopes=False)
    assert transport.requests
    transport.review_native_responses = responses
    return collected, transport


def verdict(case, variant, collected, transport, expected):
    before = deepcopy(collected)
    findings = evaluate_snapshot(collected, checks=[case['id']])['findings']
    assert collected == before
    RECEIPTS.append({'check_id': case['id'], 'scenario': variant, 'expected': expected,
                     'test_nodeid': os.environ.get('PYTEST_CURRENT_TEST', '').removesuffix(' (call)'),
                     'statuses': [f['status'] for f in findings], 'findings': findings,
                     'native_responses': getattr(transport, 'review_native_responses', []),
                     'requests': transport.requests, 'collections': collected['collections']})
    expected_statuses = expected if isinstance(expected, list) else [expected]
    assert sorted(f['status'] for f in findings) == sorted(expected_statuses), findings


@pytest.mark.parametrize('case', SPECS, ids=lambda c: c['id'])
@pytest.mark.parametrize('variant', ['good', 'bad', 'denied', 'denied_field', 'malformed_field', 'partial'])
def test_native_roundtrip(case, variant):
    def malformed(row, routes):
        if variant != 'malformed_field':
            return
        if case['path'] == 'iamPolicy':
            next(route for url, route in routes.items() if url.endswith('getIamPolicy'))['data']['bindings'] = {'invalid': True}
            return
        if case['id'].endswith('project.oslogin_enabled'):
            routes[C]['data']['commonInstanceMetadata']['items'] = {'invalid': True}
            return
        if case['id'].endswith('project.no_api_keys'):
            routes['https://apikeys.googleapis.com/v2/' + P + '/locations/global/keys']['data']['keys'] = [
                {'name': P + '/locations/global/keys/review', 'deleteTime': {'invalid': True}}]
            return
        # Producer uses real field shapes; only this explicit malformed native witness violates its contract.
        path = case['path'].split('.')
        parent = row
        for part in path[:-1]:
            parent = parent.setdefault(part, {})
        parent[path[-1]] = {'invalid': True}
    collected, transport = collect(case, variant, malformed)
    expected = case.get('good_status', 'PASS') if variant == 'good' else case.get('bad_status', 'FAIL')
    if variant == 'denied':
        expected = 'DENIED'
    elif variant in ('denied_field', 'malformed_field'):
        expected = 'UNKNOWN'
    elif variant == 'partial':
        expected = case.get('good_status', 'PASS') if case['kind'] in ('project', 'organization') else ['UNKNOWN', case.get('good_status', 'PASS')]
        if case['kind'] == 'app_engine_version':
            expected = ['UNKNOWN', 'UNKNOWN']  # Handler check requires the complete version inventory.
    if variant == 'denied_field':
        item = next(c for c in collected['collections'] if c['type'] == case['kind'])['items'][0]
        if case['id'].endswith('project.no_api_keys'):
            # This control reads the complete key inventory, not the project name.
            envelope = next(c for c in collected['collections'] if c['type'] == 'api_key')
            envelope.update(status='denied', coverage_status='denied')
        else:
            item.setdefault('_coverage', {})[case['path'].split('.')[0]] = {'status': 'denied'}
        collected.pop('snapshot_id', None)
    verdict(case, variant, collected, transport, expected)


def find(slug):
    return next(case for case in SPECS if case['id'].endswith(slug))


@pytest.mark.parametrize('suffix', ['all_protocols', 'common_ports', 'tcp_udp', 'without_target'])
@pytest.mark.parametrize('change,expected', [('disabled', 'NOT_APPLICABLE'), ('egress', 'NOT_APPLICABLE'),
                                          ('private', 'PASS'), ('ipv6', 'FAIL'), ('deny_only', 'PASS')])
def test_firewall_applicability(suffix, change, expected):
    case = find('public_ingress_' + suffix)
    def mutate(row, routes):
        if change == 'disabled': row['disabled'] = True
        elif change == 'egress': row['direction'] = 'EGRESS'
        elif change == 'private': row['sourceRanges'] = ['10.0.0.0/8']
        elif change == 'ipv6': row['sourceRanges'] = ['::/0']
        else:
            row.pop('allowed', None)
            row['denied'] = [{'IPProtocol': 'all'}]
    collected, transport = collect(case, 'bad', mutate)
    verdict(case, change, collected, transport, expected)


@pytest.mark.parametrize('kind', ['image', 'pubsub_topic', 'pubsub_subscription', 'pubsub_snapshot'])
def test_policy_hydration_denied(kind):
    case = find(kind + '.not_public')
    row, routes = native_plan(case, 'good')
    responses = []
    def resolve(request):
        assert request['method'] == 'GET' and request['url'] in routes
        if request['url'].endswith('getIamPolicy'):
            responses.append({'request': deepcopy(request), 'read_error': {'status': 'denied', 'http_status': 403}})
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        responses.append({'request': deepcopy(request), 'response': deepcopy(routes[request['url']]['data'])})
        return routes[request['url']]['data']
    collected, transport = snapshot([kind], resolve)
    transport.review_native_responses = responses
    verdict(case, 'denied_policy', collected, transport, 'UNKNOWN')


@pytest.mark.parametrize('slug', ['network.dns_logging', 'instance_group_manager.load_balancer_attached',
                                 'target_proxy.https_min_tls_1_2', 'project.no_api_keys',
                                 'project.container_scanning_api_enabled', 'project.gemini_api_disabled',
                                 'organization.essential_contacts_any'])
def test_denied_dependency(slug):
    case = find(slug)
    def select_dependency(row, routes):
        for route in routes.values():
            route['target'] = False
        dependency = case['dependencies'][0]
        endings = {'backend_service': '/aggregated/backendServices', 'dns_policy': '/policies',
                   'ssl_policy': '/aggregated/sslPolicies', 'api_key': '/keys',
                   'service_usage': '/services', 'essential_contact': '/contacts'}
        next(route for url, route in routes.items() if url.endswith(endings[dependency]))['target'] = True
    collected, transport = collect(case, 'denied', select_dependency)
    verdict(case, 'denied_dependency', collected, transport, 'UNKNOWN')


MISSING = dict(zip([s['id'] for s in SPECS], [
    'FAIL', 'FAIL', 'UNKNOWN', 'PASS', 'PASS', 'PASS', 'FAIL', 'PASS',
    'UNKNOWN', 'PASS', 'PASS', 'PASS', 'FAIL', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
    'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'PASS', 'UNKNOWN',
    'PASS', 'PASS', 'PASS', 'UNKNOWN', 'FAIL', 'FAIL', 'UNKNOWN', 'UNKNOWN']))


@pytest.mark.parametrize('case', SPECS, ids=lambda c: c['id'])
def test_native_omitted_field(case):
    def omit(row, routes):
        if case['path'] == 'iamPolicy':
            next(route for url, route in routes.items() if url.endswith('getIamPolicy'))['data'].pop('bindings', None)
        elif case['id'].endswith('project.oslogin_enabled'):
            routes[C]['data']['commonInstanceMetadata'].pop('items', None)
        elif case['id'].endswith('project.no_api_keys'):
            routes['https://apikeys.googleapis.com/v2/' + P + '/locations/global/keys']['data'].pop('keys')
        else:
            parts, parent = case['path'].split('.'), row
            for part in parts[:-1]:
                parent = parent[part]
            parent.pop(parts[-1], None)
    collected, transport = collect(case, 'good', omit)
    verdict(case, 'omitted_field', collected, transport, MISSING[case['id']])


@pytest.mark.parametrize('slug,patch,expected', [
    ('backend_service.external_iap', {'loadBalancingScheme': 'INTERNAL_MANAGED'}, 'NOT_APPLICABLE'),
    ('instance.not_preemptible_or_spot', {'scheduling': {'provisioningModel': 'FLEX_START'}}, 'PASS'),
    ('instance.not_preemptible_or_spot', {'scheduling': {'provisioningModel': 'FUTURE'}}, 'UNKNOWN'),
    ('instance.disks_csek', {'disks': []}, 'NOT_APPLICABLE'),
    ('instance.disks_csek', {'disks': [{'deviceName': 'boot', 'diskEncryptionKey': {'kmsKeyName': 'projects/123/locations/global/keyRings/r/cryptoKeys/k'}}]}, 'FAIL'),
    ('instance.suspended_without_disks', {'status': 'RUNNING'}, 'NOT_APPLICABLE'),
    ('target_proxy.https_custom_ssl_policy', {'kind': 'compute#targetSslProxy'}, 'NOT_APPLICABLE'),
    ('target_proxy.https_min_tls_1_2', {'kind': 'compute#targetSslProxy'}, 'NOT_APPLICABLE'),
    ('api_key.created_within_90_days', {'createTime': 'not-a-time'}, 'UNKNOWN'),
    ('snapshot.not_outdated', {'creationTimestamp': 'not-a-time'}, 'UNKNOWN'),
    ('appengine.version_https_only', {'servingStatus': 'STOPPED'}, 'NOT_APPLICABLE'),
])
def test_native_extra_branches(slug, patch, expected):
    case = find(slug)
    def mutate(row, routes):
        row.update(deepcopy(patch))
        if patch.get('kind') == 'compute#targetSslProxy':
            row['selfLink'] = C + '/global/targetSslProxies/review'
            routes[C + '/aggregated/targetHttpsProxies'].update(data={'items': {}}, target=False)
            routes[C + '/global/targetSslProxies'].update(data={'items': [row]}, target=True)
    collected, transport = collect(case, 'good', mutate)
    verdict(case, 'extra:' + json.dumps(patch, sort_keys=True), collected, transport, expected)


@pytest.mark.parametrize('slug', ['network.dns_logging', 'target_proxy.https_min_tls_1_2',
                                 'project.container_scanning_api_enabled', 'project.gemini_api_disabled'])
@pytest.mark.parametrize('scenario', ['foreign', 'duplicate'])
def test_native_join_identity(slug, scenario):
    case = find(slug)
    def mutate(row, routes):
        if slug == 'network.dns_logging':
            rows = routes['https://dns.googleapis.com/dns/v1/projects/p-one/policies']['data']['policies']
            if scenario == 'foreign': rows[0]['networks'][0]['networkUrl'] = N.replace('p-one', 'p-two')
        elif slug == 'target_proxy.https_min_tls_1_2':
            rows = routes[C + '/aggregated/sslPolicies']['data']['items']['global']['sslPolicies']
            if scenario == 'foreign': rows[0]['selfLink'] = SSL.replace('p-one', 'p-two')
        else:
            rows = routes['https://serviceusage.googleapis.com/v1/' + P + '/services']['data']['services']
            if scenario == 'foreign': rows[0]['name'] = rows[0]['name'].replace('projects/123', 'projects/999')
        if scenario == 'duplicate':
            duplicate = deepcopy(rows[0])
            # Distinct DNS policies sharing a network are ambiguous. Identical
            # immutable TLS/service identities repeated across pages deduplicate.
            if slug == 'network.dns_logging': duplicate['name'] = 'second'
            rows.append(duplicate)
    collected, transport = collect(case, 'good', mutate)
    expected = 'UNKNOWN'
    if slug == 'network.dns_logging' and scenario == 'foreign': expected = 'FAIL'
    elif slug != 'network.dns_logging' and scenario == 'duplicate': expected = 'PASS'
    verdict(case, scenario + '_join', collected, transport, expected)


def test_default_named_deny_rule_does_not_allow_internet():
    """Native counterexample: a recreated default name may carry DENY only."""
    case = find('firewall.default_rules_not_open')
    def deny(row, routes):
        row.pop('allowed', None)
        row['denied'] = [{'IPProtocol': 'all'}]
    collected, transport = collect(case, 'bad', deny)
    verdict(case, 'default_named_deny_only_regression', collected, transport, 'PASS')


@pytest.mark.parametrize('slug', ['target_proxy.https_min_tls_1_2',
                                 'project.container_scanning_api_enabled', 'project.gemini_api_disabled'])
def test_conflicting_dependency_across_native_pages(slug):
    """Both pages are individually valid native responses; facts change mid-list."""
    case = find(slug)
    _, routes = native_plan(case, 'good')
    tls = slug.startswith('target_proxy')
    endpoint = C + '/aggregated/sslPolicies' if tls else 'https://serviceusage.googleapis.com/v1/' + P + '/services'
    responses = []
    def resolve(request):
        assert request['method'] == 'GET' and request['url'] in routes
        response = deepcopy(routes[request['url']]['data'])
        if request['url'] == endpoint:
            if request.get('params', {}).get('pageToken'):
                if tls:
                    response['items']['global']['sslPolicies'][0]['minTlsVersion'] = 'TLS_1_0'
                else:
                    service = response['services'][0]
                    service['state'] = 'DISABLED' if service['state'] == 'ENABLED' else 'ENABLED'
            else:
                response['nextPageToken'] = 'changed-resource'
        responses.append({'request': deepcopy(request), 'response': deepcopy(response)})
        return response
    collected, transport = snapshot([case['kind'], *case['dependencies']], resolve, metrics_scopes=False)
    transport.review_native_responses = responses
    assert len([r for r in transport.requests if r['url'] == endpoint]) == 2
    verdict(case, 'conflicting_native_pages_regression', collected, transport, 'UNKNOWN')


@pytest.mark.parametrize('scenario,expected', [
    ('enforced', 'PASS'), ('not_enforced', 'FAIL'), ('unset_policy', 'FAIL'),
    ('conditional_policy', 'UNKNOWN'), ('foreign_policy', 'UNKNOWN'),
    ('duplicate_metadata', 'UNKNOWN'), ('compute_denied', 'UNKNOWN'),
    ('own_service_disabled', 'NOT_APPLICABLE'), ('foreign_service_disabled', 'UNKNOWN'),
])
def test_oslogin_native_policy_and_hydration(scenario, expected):
    case = find('project.oslogin_enabled')
    crm = 'https://cloudresourcemanager.googleapis.com/v3/' + P
    policies = {'https://orgpolicy.googleapis.com/v2/' + P + '/policies/' + constraint + ':getEffectivePolicy': constraint
                for constraint in gcp.ORG_POLICY_CONSTRAINTS}
    responses = []
    def resolve(request):
        url = request['url']
        assert request['method'] == 'GET' and url in {crm, C, *policies}
        if url == crm:
            data = {'name': 'projects/123', 'projectId': 'p-one'}
        elif url == C:
            if scenario == 'compute_denied':
                responses.append({'request': deepcopy(request), 'read_error': {'status': 'denied', 'http_status': 403}})
                raise gcp.ReadError('denied', 'permission_denied', http_status=403)
            if scenario.endswith('service_disabled'):
                consumer = P if scenario == 'own_service_disabled' else 'projects/p-two'
                error = {'reason': 'SERVICE_DISABLED', 'consumer': consumer, 'service': 'compute.googleapis.com'}
                responses.append({'request': deepcopy(request), 'read_error': error})
                raise gcp.http_error(403, {'error': {'details': [{'reason': 'SERVICE_DISABLED',
                    'metadata': {'consumer': consumer, 'service': 'compute.googleapis.com'}}]}})
            data = {'name': 'p-one', 'commonInstanceMetadata': {'fingerprint': 'abc'}}
            if scenario == 'duplicate_metadata':
                data['commonInstanceMetadata']['items'] = [
                    {'key': 'enable-oslogin', 'value': 'TRUE'}, {'key': 'enable-oslogin', 'value': 'FALSE'}]
        else:
            constraint = policies[url]
            data = {'name': P + '/policies/' + constraint}
            if constraint == 'compute.requireOsLogin':
                if scenario == 'foreign_policy': data['name'] = 'projects/p-two/policies/' + constraint
                if scenario != 'unset_policy': data['spec'] = {'rules': [{'enforce': scenario != 'not_enforced'}]}
                if scenario == 'conditional_policy': data['spec']['rules'][0]['condition'] = {'expression': 'true'}
        responses.append({'request': deepcopy(request), 'response': deepcopy(data)})
        return data
    collected, transport = snapshot(['project', 'org_policy_effective'], resolve, metrics_scopes=False)
    transport.review_native_responses = responses
    verdict(case, 'oslogin:' + scenario, collected, transport, expected)


@pytest.mark.parametrize('slug', ['target_proxy.https_min_tls_1_2',
                                 'project.container_scanning_api_enabled', 'project.gemini_api_disabled'])
@pytest.mark.parametrize('mode', ['pages', 'merged_jobs'])
@pytest.mark.parametrize('scenario,first,second,expected', [
    ('identical_good', 'good', 'good', 'PASS'),
    ('identical_bad', 'bad', 'bad', 'FAIL'),
    ('good_then_bad', 'good', 'bad', 'UNKNOWN'),
    ('bad_then_good', 'bad', 'good', 'UNKNOWN'),
    ('good_then_malformed', 'good', 'malformed', 'UNKNOWN'),
    ('malformed_then_good', 'malformed', 'good', 'UNKNOWN'),
    ('identical_malformed', 'malformed', 'malformed', 'UNKNOWN'),
])
def test_duplicate_dependency_payload_contract(monkeypatch, slug, mode, scenario, first, second, expected):
    """Compare native payloads both within an envelope and between merged jobs."""
    case = find(slug)
    tls = slug.startswith('target_proxy')
    dependency = 'ssl_policy' if tls else 'service_usage'
    endpoint = C + '/aggregated/sslPolicies' if tls else 'https://serviceusage.googleapis.com/v1/' + P + '/services'
    _, routes = native_plan(case, 'good')
    observations = 0
    responses = []
    if mode == 'merged_jobs':
        original_jobs = gcp.GCPCollector.scope_jobs
        def repeated_jobs(collector, scope):
            jobs = original_jobs(collector, scope)
            return [*jobs, next(job for job in jobs if job[0] == dependency)]
        monkeypatch.setattr(gcp.GCPCollector, 'scope_jobs', repeated_jobs)

    def resolve(request):
        nonlocal observations
        assert request['method'] == 'GET' and request['url'] in routes
        response = deepcopy(routes[request['url']]['data'])
        if request['url'] == endpoint:
            value = first if observations == 0 else second
            observations += 1
            if tls:
                row = response['items']['global']['sslPolicies'][0]
                if value == 'bad': row['minTlsVersion'] = 'TLS_1_0'
                elif value == 'malformed': row['minTlsVersion'] = {'invalid': True}
            else:
                row = response['services'][0]
                if value == 'bad': row['state'] = 'DISABLED' if row['state'] == 'ENABLED' else 'ENABLED'
                elif value == 'malformed': row['state'] = {'invalid': True}
            if mode == 'pages' and observations == 1:
                response['nextPageToken'] = 'same-native-identity'
            if mode == 'pages':
                assert request.get('params', {}).get('pageToken') == (None if observations == 1 else 'same-native-identity')
        responses.append({'request': deepcopy(request), 'response': deepcopy(response)})
        return response

    collected, transport = snapshot([case['kind'], dependency], resolve, metrics_scopes=False)
    transport.review_native_responses = responses
    assert observations == 2
    envelope = next(c for c in collected['collections'] if c['type'] == dependency)
    conflict = first != second
    assert envelope['coverage_status'] == ('partial' if conflict else 'collected')
    if conflict:
        assert envelope['error'] == {'kind': 'malformed', 'code': 'conflicting_' + dependency + '_identity'}
    else:
        assert len(envelope['items']) == 1
        assert len(envelope['items'][0]['_provenance']['source_requests']) == 2
    verdict(case, 'duplicate_contract:' + mode + ':' + scenario, collected, transport, expected)


@pytest.mark.parametrize('allowed,expected', [
    ([], 'PASS'), ([{'IPProtocol': 'tcp', 'ports': ['22']}], 'FAIL'),
    ([{'IPProtocol': 'all'}], 'FAIL'),
    ({'IPProtocol': 'tcp'}, 'UNKNOWN'),
    ([{'IPProtocol': 'tcp', 'ports': ['invalid']}], 'UNKNOWN'),
])
def test_default_rule_validates_allow_action(allowed, expected):
    case = find('firewall.default_rules_not_open')
    def mutate(row, routes):
        row['allowed'] = deepcopy(allowed)
    collected, transport = collect(case, 'bad', mutate)
    verdict(case, 'default_allow_validation:' + json.dumps(allowed, sort_keys=True), collected, transport, expected)
