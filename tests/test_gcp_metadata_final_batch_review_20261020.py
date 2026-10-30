"""35 independent native declarations through the real offline GCP collector.

No CASES imports, credentials, provider sockets, or mutations to runtime metadata.
Red assertions preserve actionable native producer/consumer counterexamples.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
from urllib.parse import urlsplit

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate
from tests.test_peaso_collectors_gcp import FixtureTransport, connector

SCOPE = 'projects/review-project'
NUMBER = 'projects/123456789'
REGION = 'us-central1'
SA = 'runtime@review-project.iam.gserviceaccount.com'
DEFAULT = '123456789-compute@developer.gserviceaccount.com'
CLOUD = 'https://www.googleapis.com/auth/cloud-platform'
BASE = {
    'project': {'name': NUMBER, 'projectId': 'review-project', 'state': 'ACTIVE'},
    'cloudrun_service': {'name': SCOPE + '/locations/' + REGION + '/services/review', 'template': {'serviceAccount': SA, 'containers': [{'name': 'app', 'image': 'gcr.io/review-project/app'}]}},
    'cloudrun_job': {'name': SCOPE + '/locations/' + REGION + '/jobs/review', 'template': {'template': {'serviceAccount': SA, 'containers': [{'name': 'app', 'image': 'gcr.io/review-project/app'}]}}},
    'function': {'name': SCOPE + '/locations/' + REGION + '/functions/review', 'environment': 'GEN_2', 'state': 'ACTIVE', 'serviceConfig': {'serviceAccountEmail': SA}},
    'app_engine_application': {'name': 'apps/review-project', 'id': 'review-project', 'serviceAccount': SA},
    'cloudbuild_trigger': {'resourceName': SCOPE + '/locations/global/triggers/review', 'name': 'review', 'id': 'review'},
    'composer_environment': {'name': SCOPE + '/locations/' + REGION + '/environments/review', 'config': {'nodeConfig': {'serviceAccount': SA}}},
    'workbench_instance': {'name': SCOPE + '/locations/us-central1-a/instances/review', 'gceSetup': {'serviceAccounts': [{'email': SA}]}},
    'instance_template': {'name': 'review', 'selfLink': 'https://www.googleapis.com/compute/v1/' + SCOPE + '/global/instanceTemplates/review', 'properties': {'serviceAccounts': [{'email': SA, 'scopes': [CLOUD]}]}},
    'pubsub_subscription': {'name': SCOPE + '/subscriptions/review', 'topic': SCOPE + '/topics/review'},
    'scheduler_job': {'name': SCOPE + '/locations/' + REGION + '/jobs/review', 'state': 'ENABLED', 'schedule': '0 * * * *', 'timeZone': 'Etc/UTC'},
    'access_approval_settings': {'name': SCOPE + '/accessApprovalSettings'},
    'api_key': {'name': NUMBER + '/locations/global/keys/review', 'createTime': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
    'firewall': {'name': 'review', 'selfLink': 'https://www.googleapis.com/compute/v1/' + SCOPE + '/global/firewalls/review', 'direction': 'INGRESS', 'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}], 'sourceRanges': ['10.0.0.0/8']},
    'gke_cluster': {'name': 'review', 'location': 'us-central1-a'},
}


def merge(base, fragment):
    out = deepcopy(base)
    for key, value in fragment.items():
        out[key] = merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else deepcopy(value)
    return out


def declaration(cid, kind, good, bad, omitted_path=None, omitted_status='UNKNOWN'):
    return {'id': cid, 'kind': kind, 'good': good, 'bad': bad, 'omitted_path': omitted_path, 'omitted_status': omitted_status}


SPECS = [
    declaration('gcp.claude2.cloudrun_service.invoker_not_public', 'cloudrun_service', {'iamPolicy': {'bindings': []}}, {'iamPolicy': {'bindings': [{'role': 'roles/run.invoker', 'members': ['allUsers']}]}}, 'iamPolicy', 'PASS'),
    declaration('gcp.claude2.function.ingress_not_allow_all', 'function', {'serviceConfig': {'ingressSettings': 'ALLOW_INTERNAL_ONLY'}}, {'serviceConfig': {'ingressSettings': 'ALLOW_ALL'}}, 'serviceConfig.ingressSettings'),
    declaration('gcp.compute.restrict_internet_ingress', 'firewall', {}, {'sourceRanges': ['0.0.0.0/0']}, 'sourceRanges', 'FAIL'),
    declaration('gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only', 'firewall', {'sourceRanges': ['35.235.240.0/20', '130.211.0.0/22', '35.191.0.0/16']}, {'sourceRanges': ['0.0.0.0/0']}, 'sourceRanges', 'FAIL'),
    declaration('gcp.gke.control_plane_restricted', 'gke_cluster', {'masterAuthorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '192.0.2.0/24'}]}}, {'masterAuthorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '0.0.0.0/0'}]}}, 'masterAuthorizedNetworksConfig', 'FAIL'),
    declaration('gcp.htbp.appengine.no_default_service_account', 'app_engine_application', {}, {'serviceAccount': 'review-project@appspot.gserviceaccount.com'}, 'serviceAccount', 'FAIL'),
    declaration('gcp.htbp.cloudbuild.pr_trigger_gated', 'cloudbuild_trigger', {'github': {'owner': 'review', 'name': 'repo', 'pullRequest': {'branch': '^main$', 'commentControl': 'COMMENTS_ENABLED'}}}, {'github': {'owner': 'review', 'name': 'repo', 'pullRequest': {'branch': '^main$', 'commentControl': 'COMMENTS_DISABLED'}}}, 'github.pullRequest.commentControl', 'FAIL'),
    declaration('gcp.htbp.cloudbuild.trigger_no_default_sa', 'cloudbuild_trigger', {'serviceAccount': 'projects/review-project/serviceAccounts/' + SA}, {'serviceAccount': 'projects/review-project/serviceAccounts/' + DEFAULT}, 'serviceAccount', 'FAIL'),
]
for kind, noun, path in [('cloudrun_service', 'service', 'template'), ('cloudrun_job', 'job', 'template.template')]:
    def nest(fragment): return {'template': fragment} if kind == 'cloudrun_service' else {'template': {'template': fragment}}
    SPECS += [declaration('gcp.htbp.cloudrun.' + noun + '_no_default_compute_sa', kind, {}, nest({'serviceAccount': DEFAULT}), path + '.serviceAccount', 'FAIL'),
        declaration('gcp.htbp.cloudrun.' + noun + '_secret_env_from_secret_manager', kind,
            nest({'containers': [{'name': 'app', 'image': 'gcr.io/review-project/app', 'env': [{'name': 'DB_PASSWORD', 'valueSource': {'secretKeyRef': {'secret': 'db', 'version': 'latest'}}}]}]}),
            nest({'containers': [{'name': 'app', 'image': 'gcr.io/review-project/app', 'env': [{'name': 'DB_PASSWORD', 'value': 'synthetic-do-not-retain'}]}]}), path + '.containers', 'UNKNOWN')]
SPECS += [
    declaration('gcp.htbp.composer.no_default_compute_sa', 'composer_environment', {}, {'config': {'nodeConfig': {'serviceAccount': DEFAULT}}}, 'config.nodeConfig.serviceAccount', 'FAIL'),
    declaration('gcp.htbp.function.runtime_no_default_sa', 'function', {}, {'serviceConfig': {'serviceAccountEmail': DEFAULT}}, 'serviceConfig.serviceAccountEmail', 'FAIL'),
    declaration('gcp.htbp.function.secret_env_from_secret_manager', 'function', {'serviceConfig': {'environmentVariables': {'DB_HOST': 'db.internal'}, 'secretEnvironmentVariables': [{'key': 'DB_PASSWORD', 'projectId': 'review-project', 'secret': 'db', 'version': 'latest'}]}}, {'serviceConfig': {'environmentVariables': {'DB_PASSWORD': 'synthetic-do-not-retain'}}}, 'serviceConfig.environmentVariables', 'PASS'),
    declaration('gcp.htbp.instance_template.no_default_sa_full_scope', 'instance_template', {}, {'properties': {'serviceAccounts': [{'email': DEFAULT, 'scopes': [CLOUD]}]}}, 'properties.serviceAccounts', 'PASS'),
    declaration('gcp.htbp.pubsub.push_endpoint_not_tunnel', 'pubsub_subscription', {'pushConfig': {'pushEndpoint': 'https://owned.example.com/events'}}, {'pushConfig': {'pushEndpoint': 'https://capture.ngrok-free.app/events'}}, 'pushConfig', 'NOT_APPLICABLE'),
    declaration('gcp.htbp.scheduler.no_recurring_access_regrant', 'scheduler_job', {'httpTarget': {'uri': 'https://run.googleapis.com/v2/' + SCOPE + '/locations/us-central1/jobs/review:run', 'httpMethod': 'POST', 'oauthToken': {'serviceAccountEmail': SA}}}, {'httpTarget': {'uri': 'https://cloudresourcemanager.googleapis.com/v1/' + SCOPE + ':setIamPolicy?key=drop-me', 'httpMethod': 'POST', 'oauthToken': {'serviceAccountEmail': SA}}}, 'httpTarget', 'NOT_APPLICABLE'),
    declaration('gcp.htbp.workbench.no_default_compute_sa', 'workbench_instance', {}, {'gceSetup': {'serviceAccounts': [{'email': DEFAULT}]}}, 'gceSetup.serviceAccounts', 'FAIL'),
    declaration('gcp.ports.access_approval_explicit_enrollment', 'access_approval_settings', {'enrolledServices': [{'cloudProduct': 'all', 'enrollmentLevel': 'BLOCK_ALL'}]}, {'notificationEmails': ['security@example.com']}, 'enrolledServices', 'FAIL'),
    declaration('gcp.ports.api_key_elapsed_age_gt90', 'api_key', {}, {'createTime': (datetime.now(timezone.utc) - timedelta(days=92)).isoformat()}, 'createTime'),
    declaration('gcp.ports.api_key_meaningful_restrictions', 'api_key', {'restrictions': {'apiTargets': [{'service': 'storage.googleapis.com'}]}}, {'restrictions': {'serverKeyRestrictions': {'allowedIps': ['0.0.0.0/0']}}}, 'restrictions'),
    declaration('gcp.ports.app_engine_application_iap_enabled', 'app_engine_application', {'iap': {'enabled': True}}, {'iap': {'enabled': False}}, 'iap', 'FAIL'),
    declaration('gcp.ports.artifacts_container_analysis_enabled', 'project', {'services': [{'name': NUMBER + '/services/containeranalysis.googleapis.com', 'state': 'ENABLED'}]}, {'services': [{'name': NUMBER + '/services/containeranalysis.googleapis.com', 'state': 'DISABLED'}]}, 'services', 'UNKNOWN'),
    declaration('gcp.ports.cloud_run_not_publicly_accessible', 'cloudrun_service', {'ingress': 'INGRESS_TRAFFIC_INTERNAL_ONLY'}, {'ingress': 'INGRESS_TRAFFIC_ALL'}, 'ingress'),
    declaration('gcp.ports.cloud_run_service_policy_prohibit_public_access', 'cloudrun_service', {'iamPolicy': {'bindings': []}}, {'iamPolicy': {'bindings': [{'role': 'roles/viewer', 'members': ['allUsers']}]}}, 'iamPolicy', 'PASS'),
    declaration('gcp.ports.cloudfunction_function_no_ingress_settings_allow_all', 'function', {'serviceConfig': {'ingressSettings': 'ALLOW_INTERNAL_ONLY'}}, {'serviceConfig': {'ingressSettings': 'ALLOW_ALL'}}, 'serviceConfig.ingressSettings'),
    declaration('gcp.ports.cloudfunction_function_restrict_public_access', 'function', {'iamPolicy': {'bindings': []}}, {'iamPolicy': {'bindings': [{'role': 'roles/cloudfunctions.invoker', 'members': ['allUsers']}]}}, 'iamPolicy', 'PASS'),
    declaration('gcp.ports.cloudfunction_function_vpc_connector_enabled', 'function', {'serviceConfig': {'vpcConnector': SCOPE + '/locations/us-central1/connectors/private'}}, {'serviceConfig': {'vpcConnector': ''}}, 'serviceConfig.vpcConnector', 'FAIL'),
    declaration('gcp.ports.cloudrun_service_restrict_public_access', 'cloudrun_service', {'iamPolicy': {'bindings': []}}, {'iamPolicy': {'bindings': [{'role': 'roles/run.invoker', 'members': ['allUsers']}]}}, 'iamPolicy', 'PASS'),
]
POLICY_IDS = {
    'gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled': ('iam.disableCrossProjectServiceAccountUsage',),
    'gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled': ('iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts', 'iam.automaticIamGrantsForDefaultServiceAccounts'),
    'gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked': ('iam.managed.disableServiceAccountKeyCreation', 'iam.disableServiceAccountKeyCreation', 'iam.managed.disableServiceAccountKeyUpload', 'iam.disableServiceAccountKeyUpload'),
    'gcp.htbp.orgpolicy.domain_restricted_sharing': ('iam.managed.allowedPolicyMembers', 'iam.allowedPolicyMemberDomains'),
    'gcp.htbp.orgpolicy.essential_contacts_domain_restricted': ('essentialcontacts.managed.allowedContactDomains', 'essentialcontacts.allowedContactDomains'),
}
for cid, constraints in POLICY_IDS.items():
    good = {name: [{'enforce': True}] for name in constraints if 'managed.' in name or cid.endswith('not_disabled')}
    if cid.endswith('domain_restricted_sharing'): good['iam.managed.allowedPolicyMembers'] = [{'enforce': True, 'parameters': {'allowedMemberSubjects': ['user:admin@example.com']}}]
    if cid.endswith('essential_contacts_domain_restricted'): good['essentialcontacts.managed.allowedContactDomains'] = [{'enforce': True, 'parameters': {'allowedDomains': ['@example.com']}}]
    SPECS.append(declaration(cid, 'project', {'policies': good}, {'policies': {name: [{'enforce': False}] if 'managed.' in name or cid.endswith('not_disabled') else [] for name in constraints}}, 'policies', 'UNKNOWN' if cid.endswith('not_disabled') else 'FAIL'))


@pytest.fixture(autouse=True)
def forbid_network_auth(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError('Native review forbids live network, DNS and credentials')
    for name in ('create_connection', 'getaddrinfo'): monkeypatch.setattr(socket, name, blocked)
    for name in ('connect', 'connect_ex', 'sendto'): monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('Credentials', 'GcloudCredentials', '_gcloud'):
        monkeypatch.setattr(gcp, name, blocked)
    import google.auth
    monkeypatch.setattr(google.auth, 'default', blocked)


def native(kind, item, *, denied=False, partial=False, policy_denied=False, policies=None, services=None, foreign_policy=False, dependency_denied=False):
    """Finite exact provider method/host/path contracts, with genuine API fragments."""
    paths = {
      'project': ('cloudresourcemanager.googleapis.com', '/v3/' + SCOPE, None),
      'cloudrun_service': ('run.googleapis.com', '/v2/' + SCOPE + '/locations/us-central1/services', 'services'),
      'cloudrun_job': ('run.googleapis.com', '/v2/' + SCOPE + '/locations/us-central1/jobs', 'jobs'),
      'function': ('cloudfunctions.googleapis.com', '/v2/' + SCOPE + '/locations/-/functions', 'functions'),
      'app_engine_application': ('appengine.googleapis.com', '/v1/apps/review-project', None),
      'cloudbuild_trigger': ('cloudbuild.googleapis.com', '/v1/' + SCOPE + '/locations/global/triggers', 'triggers'),
      'composer_environment': ('composer.googleapis.com', '/v1/' + SCOPE + '/locations/us-central1/environments', 'environments'),
      'workbench_instance': ('notebooks.googleapis.com', '/v2/' + SCOPE + '/locations/-/instances', 'instances'),
      'instance_template': ('compute.googleapis.com', '/compute/v1/' + SCOPE + '/aggregated/instanceTemplates', 'instanceTemplates'),
      'pubsub_subscription': ('pubsub.googleapis.com', '/v1/' + SCOPE + '/subscriptions', 'subscriptions'),
      'scheduler_job': ('cloudscheduler.googleapis.com', '/v1/' + SCOPE + '/locations/us-central1/jobs', 'jobs'),
      'access_approval_settings': ('accessapproval.googleapis.com', '/v1/' + SCOPE + '/accessApprovalSettings', None),
      'api_key': ('apikeys.googleapis.com', '/v2/' + SCOPE + '/locations/global/keys', 'keys'),
      'firewall': ('compute.googleapis.com', '/compute/v1/' + SCOPE + '/global/firewalls', 'items'),
      'gke_cluster': ('container.googleapis.com', '/v1/' + SCOPE + '/locations/-/clusters', 'clusters'),
    }
    host, path, key = paths[kind]
    endpoint = 'https://' + host + path
    clean = deepcopy(item)
    iam = clean.pop('iamPolicy', {'bindings': []})
    routes = {endpoint: clean if key is None else ({'items': {'global': {key: [clean]}}} if kind == 'instance_template' else {key: [clean]})}
    routes['https://cloudresourcemanager.googleapis.com/v3/' + SCOPE] = deepcopy(BASE['project'])
    routes['https://compute.googleapis.com/compute/v1/' + SCOPE] = {'name': 'review-project', 'id': '123456789'}
    iam_url = None
    # Workbench instance IAM is hydrated on every listed instance (75087001).
    if kind in ('cloudrun_service', 'cloudrun_job', 'function', 'pubsub_subscription', 'workbench_instance'):
        version = '/v1/' if kind == 'pubsub_subscription' else '/v2/'
        iam_url = 'https://' + host + version + clean['name'] + ':getIamPolicy'
        routes[iam_url] = iam
    kinds = [kind]
    if policies is not None:
        kinds.append('org_policy_effective')
        for constraint in gcp.ORG_POLICY_CONSTRAINTS:
            routes['https://orgpolicy.googleapis.com/v2/' + SCOPE + '/policies/' + constraint + ':getEffectivePolicy'] = {
                'name': ('projects/987654321' if foreign_policy else NUMBER) + '/policies/' + constraint, 'spec': {'rules': deepcopy(policies.get(constraint, []))}}
    if services is not None:
        kinds.append('service_usage')
        routes['https://serviceusage.googleapis.com/v1/' + SCOPE + '/services'] = {'services': deepcopy(services)}
    original = deepcopy(item)

    def resolve(request):
        parsed = urlsplit(request['url'])
        assert parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        assert request['method'] == 'GET'
        assert request['url'] in routes, 'Unexpected native host/path ' + request['url']
        if request['url'] == iam_url:
            assert request['params']['options.requestedPolicyVersion'] == 3
            if policy_denied: raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        if dependency_denied and parsed.hostname in ('orgpolicy.googleapis.com', 'serviceusage.googleapis.com'):
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        if request['url'] == endpoint:
            if denied: raise gcp.ReadError('denied', 'permission_denied', http_status=403)
            if partial and (request.get('params') or {}).get('pageToken'):
                assert request['params']['pageToken'] == 'next-review-page'
                raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        response = deepcopy(routes[request['url']])
        if partial and request['url'] == endpoint and key is not None: response['nextPageToken'] = 'next-review-page'
        return response

    class ScopedTransport(FixtureTransport):
        def request(self, method, url, **kwargs):
            try: return super().request(method, url, **kwargs)
            finally: self.evidence[-1]['scope'] = kwargs['scope']
    api = ScopedTransport(resolve)
    options = {'cloudrun_locations': ['us-central1'], 'cloudbuild_locations': ['global'],
               'composer_locations': ['us-central1'], 'cloudscheduler_locations': ['us-central1'],
               'metrics_scopes': False, 'include_inherited': False, 'resource_iam': False, 'compute_resource_iam': False}
    captured = gcp.GCPCollector(connector(kinds, scopes=[SCOPE], **options), transport=api).collect()
    assert validate(captured) == captured and item == original
    return captured, api


def observe(spec, scenario='good'):
    item = merge(BASE[spec['kind']], spec['bad' if scenario == 'bad' else 'good'])
    if scenario == 'omitted' and spec['omitted_path']:
        node = item
        parts = spec['omitted_path'].split('.')
        for part in parts[:-1]: node = node.get(part, {})
        node.pop(parts[-1], None)
    policies, services = item.pop('policies', None), item.pop('services', None)
    if spec['id'] in POLICY_IDS and policies is None: policies = {}
    if spec['id'].endswith('artifacts_container_analysis_enabled') and services is None: services = []
    captured, api = native(spec['kind'], item, denied=scenario == 'denied',
                           partial=scenario == 'partial', policies=policies, services=services)
    if scenario == 'denied_fact' and spec['omitted_path']:
        path = ('serviceConfig.environmentVariableNames' if spec['id'].endswith('function.secret_env_from_secret_manager') else spec['omitted_path'])
        row = next(c for c in captured['collections'] if c['type'] == spec['kind'])['items'][0]
        if path in ('policies', 'services'):
            dep = 'org_policy_effective' if path == 'policies' else 'service_usage'
            next(c for c in captured['collections'] if c['type'] == dep).update(status='partial', coverage_status='partial')
        else:
            node = row
            parts = path.split('.')
            node.setdefault('_coverage', {})[parts[0]] = {'status': 'denied'}
        captured.pop('snapshot_id', None)
    before = deepcopy(captured)
    findings = evaluate_snapshot(captured, checks=[spec['id']])['findings']
    assert before == captured and findings, findings
    resources = [f for f in findings if 'native_resource_id' in f]
    if scenario == 'partial' and spec['kind'] not in ('project', 'app_engine_application', 'access_approval_settings'):
        assert any(f['status'] == 'UNKNOWN' and f['evidence'].get('collection_status') == 'partial' for f in findings), findings
    assert len(resources) <= 1, findings
    return (resources or findings)[-1], captured, api


MATRIX = [(spec, scenario) for scenario in ('good', 'bad', 'omitted', 'denied', 'denied_fact', 'partial') for spec in SPECS
          if scenario != 'partial' or spec['kind'] not in ('project', 'app_engine_application', 'access_approval_settings')]

@pytest.mark.parametrize('spec,scenario', MATRIX, ids=[scenario + '-' + spec['id'] for spec, scenario in MATRIX])
def test_every_assigned_native_declaration(spec, scenario):
    row, captured, api = observe(spec, scenario)
    expected = {'good': 'PASS', 'bad': 'FAIL', 'omitted': spec['omitted_status'], 'denied': 'DENIED', 'denied_fact': 'UNKNOWN', 'partial': 'PASS'}[scenario]
    assert row['status'] == expected, row
    assert 'synthetic-do-not-retain' not in json.dumps(captured)
    if spec['kind'] == 'scheduler_job': assert '?key=' not in json.dumps(captured)


def test_assigned_roster_is_exactly_35():
    # The immutable assignment is recorded in the durable report; repository
    # execution remains independent of a /tmp assignment file.
    assert len(SPECS) == 35 and len({s['id'] for s in SPECS}) == 35


def extra(cid, label, fragment, expected):
    spec = next(deepcopy(s) for s in SPECS if s['id'] == cid)
    spec['good'] = fragment
    return {'spec': spec, 'label': label, 'expected': expected}


EXTRAS = []
def add(cid, label, fragment, expected): EXTRAS.append(extra(cid, label, fragment, expected))

for cid in [s['id'] for s in SPECS if 'cloudrun' in s['id'] and 'no_default' in s['id']]:
    kind = next(s['kind'] for s in SPECS if s['id'] == cid)
    add(cid, 'managed-functions-identity-scope', {'labels': {'goog-managed-by': 'cloudfunctions'}}, 'NOT_APPLICABLE')
    add(cid, 'empty-native-identity-default', {'template': {'serviceAccount': ''}} if kind == 'cloudrun_service' else {'template': {'template': {'serviceAccount': ''}}}, 'FAIL')
for cid in [s['id'] for s in SPECS if 'cloudrun' in s['id'] and 'secret_env' in s['id']]:
    kind = next(s['kind'] for s in SPECS if s['id'] == cid)
    env = {'containers': [{'image': 'gcr.io/review-project/app', 'env': [{'name': 'TOKEN_URL', 'value': 'https://auth.example.com'}, {'name': 'LOG_LEVEL', 'value': 'info'}]}]}
    add(cid, 'noncredential-names', {'template': env} if kind == 'cloudrun_service' else {'template': {'template': env}}, 'PASS')
    add(cid, 'explicit-no-environment', {'template': {'containers': [{'image': 'gcr.io/review-project/app'}]}} if kind == 'cloudrun_service' else {'template': {'template': {'containers': [{'image': 'gcr.io/review-project/app'}]}}}, 'PASS')

pr = 'gcp.htbp.cloudbuild.pr_trigger_gated'
add(pr, 'disabled-ungated-trigger', {'disabled': True, 'github': {'pullRequest': {'branch': '.*', 'commentControl': 'COMMENTS_DISABLED'}}}, 'NOT_APPLICABLE')
add(pr, 'approval-overrides-comment-disabled', {'approvalConfig': {'approvalRequired': True}, 'github': {'pullRequest': {'branch': '.*', 'commentControl': 'COMMENTS_DISABLED'}}}, 'PASS')
add(pr, 'repository-native-pr-not-gated', {'repositoryEventConfig': {'repository': SCOPE + '/locations/us-central1/connections/c/repositories/r', 'pullRequest': {'branch': '.*', 'commentControl': 'COMMENTS_DISABLED'}}}, 'FAIL')
add(pr, 'repository-native-pr-gated', {'repositoryEventConfig': {'repository': SCOPE + '/locations/us-central1/connections/c/repositories/r', 'pullRequest': {'branch': '.*', 'commentControl': 'COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY'}}}, 'PASS')
add(pr, 'developer-connect-native-pr-not-gated', {'developerConnectEventConfig': {'gitRepositoryLink': SCOPE + '/locations/us-central1/connections/c/gitRepositoryLinks/r', 'pullRequest': {'branch': '.*', 'commentControl': 'COMMENTS_DISABLED'}}}, 'FAIL')
add(pr, 'developer-connect-native-pr-gated', {'developerConnectEventConfig': {'gitRepositoryLink': SCOPE + '/locations/us-central1/connections/c/gitRepositoryLinks/r', 'pullRequest': {'branch': '.*', 'commentControl': 'COMMENTS_ENABLED'}}}, 'PASS')
add(pr, 'push-trigger-outside-pr-contract', {'repositoryEventConfig': {'repository': SCOPE + '/locations/us-central1/connections/c/repositories/r', 'push': {'branch': '.*'}}}, 'NOT_APPLICABLE')
add('gcp.htbp.cloudbuild.trigger_no_default_sa', 'legacy-cloudbuild-default', {'serviceAccount': 'projects/review-project/serviceAccounts/123456789@cloudbuild.gserviceaccount.com'}, 'FAIL')
add('gcp.htbp.cloudbuild.trigger_no_default_sa', 'disabled-default-identity', {'disabled': True}, 'NOT_APPLICABLE')
add('gcp.htbp.function.runtime_no_default_sa', 'appengine-default-runtime', {'serviceConfig': {'serviceAccountEmail': 'review-project@appspot.gserviceaccount.com'}}, 'FAIL')
add('gcp.htbp.function.secret_env_from_secret_manager', 'same-name-inline-still-fails', {'serviceConfig': {'environmentVariables': {'DB_PASSWORD': 'synthetic-do-not-retain'}, 'secretEnvironmentVariables': [{'key': 'DB_PASSWORD', 'secret': 'db', 'version': 'latest'}]}}, 'FAIL')
add('gcp.htbp.instance_template.no_default_sa_full_scope', 'default-limited-scope', {'properties': {'serviceAccounts': [{'email': DEFAULT, 'scopes': ['https://www.googleapis.com/auth/devstorage.read_only']}]}}, 'PASS')
add('gcp.htbp.instance_template.no_default_sa_full_scope', 'no-attached-identities', {'properties': {'serviceAccounts': []}}, 'PASS')

for cid in ('gcp.compute.restrict_internet_ingress', 'gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only'):
    add(cid, 'disabled-rule', {'disabled': True, 'sourceRanges': ['0.0.0.0/0']}, 'NOT_APPLICABLE')
    add(cid, 'egress-rule', {'direction': 'EGRESS', 'sourceRanges': ['0.0.0.0/0']}, 'NOT_APPLICABLE')
    add(cid, 'expanded-ipv6-universal-source', {'sourceRanges': ['0:0:0:0:0:0:0:0/0']}, 'FAIL')
add('gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only', 'source-tags-or-trusted-cidrs', {'sourceRanges': ['35.235.240.0/20'], 'sourceTags': ['extra-sources']}, 'FAIL')
add('gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only', 'trusted-subnet', {'sourceRanges': ['35.235.240.0/24']}, 'PASS')
add('gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only', 'udp-not-tcp', {'allowed': [{'IPProtocol': 'udp'}]}, 'NOT_APPLICABLE')

gke = 'gcp.gke.control_plane_restricted'
add(gke, 'modern-private-endpoint', {'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enabled': True, 'enablePublicEndpoint': False}}}, 'PASS')
add(gke, 'dns-only-control-plane', {'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enabled': False}, 'dnsEndpointConfig': {'endpoint': 'c.gke.goog', 'allowExternalTraffic': True}}}, 'NOT_APPLICABLE')
add(gke, 'google-public-cidr-additional-access', {'masterAuthorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '192.0.2.0/24'}], 'gcpPublicCidrsAccessEnabled': True}}, 'MANUAL')
add(gke, 'empty-authorized-networks-deny-all', {'masterAuthorizedNetworksConfig': {'enabled': True}}, 'PASS')
add(gke, 'modern-legacy-mirrored-cidrs', {'masterAuthorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '192.0.2.0/24'}]}, 'controlPlaneEndpointsConfig': {'ipEndpointsConfig': {'enabled': True, 'enablePublicEndpoint': True, 'authorizedNetworksConfig': {'enabled': True, 'cidrBlocks': [{'cidrBlock': '192.0.2.0/24'}]}}}}, 'PASS')

for cid in ['gcp.claude2.function.ingress_not_allow_all', 'gcp.ports.cloudfunction_function_no_ingress_settings_allow_all']:
    add(cid, 'internal-load-balancer', {'serviceConfig': {'ingressSettings': 'ALLOW_INTERNAL_AND_GCLB'}}, 'PASS')
    add(cid, 'unspecified-enum', {'serviceConfig': {'ingressSettings': 'INGRESS_SETTINGS_UNSPECIFIED'}}, 'UNKNOWN' if cid.startswith('gcp.claude2') else 'FAIL')
add('gcp.claude2.function.ingress_not_allow_all', 'deleting-function', {'state': 'DELETING', 'serviceConfig': {'ingressSettings': 'ALLOW_ALL'}}, 'NOT_APPLICABLE')
add('gcp.ports.cloud_run_not_publicly_accessible', 'internal-load-balancer', {'ingress': 'INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER'}, 'PASS')
add('gcp.claude2.cloudrun_service.invoker_not_public', 'invoker-iam-bypass', {'invokerIamDisabled': True, 'iamPolicy': {'bindings': []}}, 'FAIL')
add('gcp.claude2.cloudrun_service.invoker_not_public', 'conditional-public-invoker', {'iamPolicy': {'version': 3, 'bindings': [{'role': 'roles/run.invoker', 'members': ['allUsers'], 'condition': {'title': 'time', 'expression': 'request.time < timestamp("2030-01-01T00:00:00Z")'}}]}}, 'MANUAL')
add('gcp.claude2.cloudrun_service.invoker_not_public', 'unconditional-public-servicesInvoker', {'iamPolicy': {'bindings': [{'role': 'roles/run.servicesInvoker', 'members': ['allAuthenticatedUsers']}]}}, 'FAIL')
for cid in ('gcp.ports.cloud_run_service_policy_prohibit_public_access', 'gcp.ports.cloudfunction_function_restrict_public_access', 'gcp.ports.cloudrun_service_restrict_public_access'):
    role = 'roles/cloudfunctions.invoker' if 'cloudfunction_' in cid else 'roles/run.invoker'
    add(cid, 'authenticated-public-conditional-declaration', {'iamPolicy': {'version': 3, 'bindings': [{'role': role, 'members': ['allAuthenticatedUsers'], 'condition': {'title': 'time', 'expression': 'request.time < timestamp("2030-01-01T00:00:00Z")'}}]}}, 'FAIL')

key = 'gcp.ports.api_key_meaningful_restrictions'
add(key, 'uppercase-universal-api-target', {'restrictions': {'apiTargets': [{'service': 'CLOUDAPIS.GOOGLEAPIS.COM'}]}}, 'FAIL')
add(key, 'expanded-ipv6-universal-caller', {'restrictions': {'serverKeyRestrictions': {'allowedIps': ['0:0:0:0:0:0:0:0/0']}}}, 'FAIL')
add(key, 'universal-plus-specific-api-target', {'restrictions': {'apiTargets': [{'service': 'cloudapis.googleapis.com'}, {'service': 'storage.googleapis.com'}]}}, 'FAIL')
add(key, 'restricted-ip-caller', {'restrictions': {'serverKeyRestrictions': {'allowedIps': ['192.0.2.0/24']}}}, 'PASS')
add(key, 'known-caller-but-universal-api', {'restrictions': {'apiTargets': [{'service': 'cloudapis.googleapis.com'}], 'serverKeyRestrictions': {'allowedIps': ['192.0.2.1']}}}, 'PASS')
add('gcp.ports.access_approval_explicit_enrollment', 'zero-enum-defaults-block-all', {'enrolledServices': [{'cloudProduct': 'Cloud Storage', 'enrollmentLevel': 'ENROLLMENT_LEVEL_UNSPECIFIED'}]}, 'PASS')
add('gcp.ports.access_approval_explicit_enrollment', 'omitted-enum-defaults-block-all', {'enrolledServices': [{'cloudProduct': 'Cloud Storage'}]}, 'PASS')
add('gcp.ports.access_approval_explicit_enrollment', 'ancestor-only-enrollment', {'enrolledAncestor': True}, 'UNKNOWN')
add('gcp.ports.access_approval_explicit_enrollment', 'specific-product-explicit-enrollment', {'enrolledServices': [{'cloudProduct': 'Cloud Storage', 'enrollmentLevel': 'BLOCK_ALL'}]}, 'PASS')
add('gcp.htbp.pubsub.push_endpoint_not_tunnel', 'raw-ip-push', {'pushConfig': {'pushEndpoint': 'https://192.0.2.1/events'}}, 'FAIL')
add('gcp.htbp.pubsub.push_endpoint_not_tunnel', 'pubsub-pull-no-push', {}, 'NOT_APPLICABLE')
add('gcp.htbp.scheduler.no_recurring_access_regrant', 'paused-iam-regrant', {'state': 'PAUSED', 'httpTarget': {'uri': 'https://cloudresourcemanager.googleapis.com/v1/' + SCOPE + ':setIamPolicy', 'httpMethod': 'POST', 'oauthToken': {'serviceAccountEmail': SA}}}, 'NOT_APPLICABLE')
add('gcp.htbp.scheduler.no_recurring_access_regrant', 'iam-regrant-without-token', {'httpTarget': {'uri': 'https://cloudresourcemanager.googleapis.com/v1/' + SCOPE + ':setIamPolicy', 'httpMethod': 'POST'}}, 'NOT_APPLICABLE')

for cid, constraints in POLICY_IDS.items():
    legacy = {name: [{'enforce': True}] for name in constraints if 'managed.' not in name}
    if cid.endswith('domain_restricted_sharing'): legacy = {'iam.allowedPolicyMemberDomains': [{'values': {'allowedValues': ['C0123456']}}]}
    if cid.endswith('essential_contacts_domain_restricted'): legacy = {'essentialcontacts.allowedContactDomains': [{'values': {'allowedValues': ['@example.com']}}]}
    add(cid, 'legacy-effective-policy', {'policies': legacy}, 'PASS')
    if cid.endswith(('domain_restricted_sharing', 'essential_contacts_domain_restricted')):
        legacy_constraint = next(name for name in constraints if 'managed.' not in name)
        add(cid, 'legacy-allow-all', {'policies': {legacy_constraint: [{'allowAll': True}]}}, 'FAIL')


@pytest.mark.parametrize('case', EXTRAS, ids=[c['spec']['id'] + '-' + c['label'] for c in EXTRAS])
def test_native_override_and_scope_branches(case):
    row, captured, api = observe(case['spec'])
    assert row['status'] == case['expected'], row
    assert 'synthetic-do-not-retain' not in json.dumps(captured)


IAM_SPECS = [s for s in SPECS if s['omitted_path'] == 'iamPolicy']
@pytest.mark.parametrize('spec', IAM_SPECS, ids=[s['id'] for s in IAM_SPECS])
def test_denied_native_iam_hydration(spec):
    item = merge(BASE[spec['kind']], spec['good'])
    captured, api = native(spec['kind'], item, policy_denied=True)
    findings = evaluate_snapshot(captured, checks=[spec['id']])['findings']
    assert any(f['status'] == 'UNKNOWN' for f in findings) and all(f['status'] != 'PASS' for f in findings), findings
    assert any(r['url'].endswith(':getIamPolicy') for r in api.requests)


@pytest.mark.parametrize('spec', [s for s in SPECS if s['kind'] == 'project'], ids=[s['id'] for s in SPECS if s['kind'] == 'project'])
@pytest.mark.parametrize('scenario', ['foreign-scope', 'denied-dependency'])
def test_project_dependency_scope_and_native_denial(spec, scenario):
    item = merge(BASE['project'], spec['good'])
    policies, services = item.pop('policies', None), item.pop('services', None)
    if services is not None and scenario == 'foreign-scope':
        for service in services: service['name'] = 'projects/987654321/services/containeranalysis.googleapis.com'
    captured, api = native('project', item, policies=policies, services=services,
                           foreign_policy=scenario == 'foreign-scope', dependency_denied=scenario == 'denied-dependency')
    findings = evaluate_snapshot(captured, checks=[spec['id']])['findings']
    assert findings and all(f['status'] in ('UNKNOWN', 'DENIED') for f in findings), findings


@pytest.mark.parametrize('elapsed,expected', [(timedelta(days=90), 'PASS'), (timedelta(days=90, hours=23), 'PASS'), (timedelta(days=91), 'FAIL')])
def test_api_key_native_elapsed_whole_day_boundary(monkeypatch, elapsed, expected):
    captured_at = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    class CapturedClock(datetime):
        @classmethod
        def now(cls, tz=None): return captured_at if tz else captured_at.replace(tzinfo=None)
    monkeypatch.setattr(gcp, 'datetime', CapturedClock)
    item = merge(BASE['api_key'], {'createTime': (captured_at - elapsed).isoformat()})
    captured, api = native('api_key', item)
    findings = evaluate_snapshot(captured, checks=['gcp.ports.api_key_elapsed_age_gt90'])['findings']
    assert len(findings) == 1 and findings[0]['status'] == expected, findings
