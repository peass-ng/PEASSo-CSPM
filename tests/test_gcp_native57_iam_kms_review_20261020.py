"""Independent native HTTP -> collector -> engine evidence for 32 exact IDs.

Only documented service response fields enter the fake transport. Completeness,
IAM joins, activity facts and effective-use rows are produced by GCPCollector.
No CASES or callback output is used to construct a native positive response.
"""
from copy import deepcopy
import json
import socket
from urllib.parse import urlsplit

import google.auth
import pytest

from peaso.checks import CHECKS
from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate

PROJECT = 'native-proof'
NUMBER = '123456789012'
SCOPE = 'projects/' + PROJECT
CAPTURED = '2026-10-20T12:00:00Z'
EMAIL = 'auditor@native-proof.iam.gserviceaccount.com'
ACCOUNT = SCOPE + '/serviceAccounts/' + EMAIL
ACCOUNT_ID = '123456789012345678901'
SA_KEY = ACCOUNT + '/keys/' + 'a' * 40
RING = SCOPE + '/locations/global/keyRings/native-ring'
KEY = RING + '/cryptoKeys/native-key'
VERSION = KEY + '/cryptoKeyVersions/1'
ROLE = SCOPE + '/roles/nativeReader'
BUCKET = 'native-proof-bucket'
SECRET = SCOPE + '/secrets/native-secret'
HUMAN = 'user:reviewer@corp.example'
CRYPTO = 'roles/cloudkms.cryptoKeyEncrypter'
PERMISSION = 'cloudkms.cryptoKeyVersions.useToEncrypt'


@pytest.fixture(autouse=True)
def block_network_and_auth(monkeypatch):
    attempted = []
    def prohibited(*args, **kwargs):
        attempted.append('actual socket/DNS/auth attempted')
        raise AssertionError('Native57 audit forbids actual sockets/DNS/auth')
    for name in ('create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, prohibited)
    for name in ('connect', 'connect_ex', 'sendto'):
        monkeypatch.setattr(socket.socket, name, prohibited)
    for name in ('Credentials', 'GcloudCredentials', '_gcloud'):
        monkeypatch.setattr(gcp, name, prohibited)
    monkeypatch.setattr(google.auth, 'default', prohibited)
    yield
    assert not attempted, attempted


def declaration(cid, family, omitted='UNKNOWN'):
    return {'id': cid, 'family': family, 'omitted': omitted}


SPECS = [
    declaration('gcp.claude.iam_policy.no_all_users', 'policy', 'PASS'),
    declaration('gcp.claude.iam_policy.no_project_sa_user_or_token_creator', 'policy', 'PASS'),
    declaration('gcp.claude.project.audit_logs_configured', 'policy', 'FAIL'),
    declaration('gcp.claude.project.storage_data_access_audit_logs', 'policy', 'FAIL'),
    declaration('gcp.htbp.iam.policy_no_pool_wide_workload_principal_set', 'policy', 'PASS'),
    declaration('gcp.iam.avoid_basic_roles', 'policy', 'PASS'),
    declaration('gcp.iam.restrict_public_members', 'policy', 'PASS'),
    declaration('gcp.ports.iam_user_not_assigned_service_account_user_role_project_level', 'policy', 'PASS'),
    declaration('gcp.ports.iam_user_separation_of_duty_scoped', 'policy', 'PASS'),
    declaration('gcp.ports.kms_key_separation_of_duties_enforced', 'policy', 'PASS'),
    declaration('gcp.claude.service_account.recently_used', 'account-activity'),
    declaration('gcp.gap.iam_user_managed_sa_no_admin_roles', 'account-role', 'PASS'),
    declaration('gcp.htbp.iam.sa_no_pool_wide_workload_principal_set', 'account-policy', 'PASS'),
    declaration('gcp.ports.service_account_mutating_role_declarations', 'role-definition'),
    declaration('gcp.ports.iam_service_account_gcp_managed_key', 'account-keys'),
    declaration('gcp.claude.service_account_key.age_100_days', 'key-age'),
    declaration('gcp.ports.iam_service_account_key_age_90', 'key-age'),
    declaration('gcp.claude.service_account_key.recently_used', 'key-activity', 'FAIL'),
    declaration('gcp.iam.no_user_managed_sa_keys', 'key-type'),
    declaration('gcp.claude.kms_key.rotation_100_days', 'kms', 'FAIL'),
    declaration('gcp.claude.kms_key.users_limited_to_3', 'kms', 'PASS'),
    declaration('gcp.htbp.kms.destroy_window_not_shortened', 'kms', 'PASS'),
    declaration('gcp.ports.kms_key_rotated_within_90_day', 'kms', 'FAIL'),
    declaration('gcp.reviewed.kms.no_public_iam', 'kms', 'PASS'),
    declaration('gcp.reviewed.kms.rotation_90_days', 'kms', 'FAIL'),
    declaration('gcp.reviewed.kms.rotation_enabled', 'kms', 'FAIL'),
    declaration('gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650', 'kms-versions', 'PASS'),
    declaration('gcp_pci_kms_key_a3927a5f3b84', 'kms-effective', 'PASS'),
    declaration('gcp.claude.secret.not_public', 'secret', 'PASS'),
    declaration('gcp.htbp.storage.hmac_key_not_stale_or_default_sa', 'hmac'),
    declaration('gcp.htbp.storage.notification_topic_in_bucket_project', 'notification'),
    declaration('gcp_pci_asset_6ee2fef37d98', 'logging'),
]
BY_ID = {s['id']: s for s in SPECS}


def policy_for(cid, mode):
    if mode in ('omitted', 'empty'):
        return {}
    policy = {'version': 3, 'etag': 'ZXRhZw==', 'bindings': []}
    bad = mode == 'bad'
    if cid.endswith('audit_logs_configured'):
        if not bad: policy['auditConfigs'] = [{'service': 'storage.googleapis.com', 'auditLogConfigs': [{'logType': 'DATA_READ'}]}]
    elif cid.endswith('storage_data_access_audit_logs'):
        policy['auditConfigs'] = [{'service': 'storage.googleapis.com', 'auditLogConfigs': [{'logType': kind} for kind in (['DATA_READ'] if bad else ['DATA_READ', 'DATA_WRITE'])]}]
    elif bad:
        bindings = {
            # Resource Manager rejects public principals on project policies.
            # Exercise a legal similarly named human, not an impossible grant.
            'gcp.claude.iam_policy.no_all_users': [{'role': 'roles/logging.viewer', 'members': ['user:allUsers@corp.example']}],
            'gcp.claude.iam_policy.no_project_sa_user_or_token_creator': [{'role': 'roles/iam.serviceAccountUser', 'members': [HUMAN]}],
            'gcp.htbp.iam.policy_no_pool_wide_workload_principal_set': [{'role': 'roles/iam.workloadIdentityUser', 'members': ['principalSet://iam.googleapis.com/projects/' + NUMBER + '/locations/global/workloadIdentityPools/shared/*']}],
            'gcp.iam.avoid_basic_roles': [{'role': 'roles/editor', 'members': [HUMAN]}],
            'gcp.iam.restrict_public_members': [],  # Public resource policy comes from actual CAI below.
            'gcp.ports.iam_user_not_assigned_service_account_user_role_project_level': [{'role': 'roles/iam.serviceAccountUser', 'members': [HUMAN]}],
            'gcp.ports.iam_user_separation_of_duty_scoped': [{'role': role, 'members': [HUMAN]} for role in ('roles/iam.serviceAccountAdmin', 'roles/iam.serviceAccountUser')],
            'gcp.ports.kms_key_separation_of_duties_enforced': [{'role': role, 'members': [HUMAN]} for role in ('roles/cloudkms.admin', CRYPTO)],
        }
        policy['bindings'] = bindings.get(cid, [])
    return policy


class NativeAPI:
    """Finite native endpoint router, including read-only POST contracts."""
    def __init__(self, spec, mode, scope=SCOPE, **overrides):
        self.spec, self.cid, self.mode, self.scope = spec, spec['id'], mode, scope
        self.overrides = overrides
        self.requests, self.evidence, self.contract_errors = [], [], []

    def denied(self):
        raise gcp.ReadError('denied', 'permission_denied', http_status=403)

    def paged(self, request, field, rows, *, target=False):
        mode = self.mode.removeprefix('role-') if self.mode in ('role-paginate', 'role-partial') else self.mode
        token = (request.get('params') or {}).get('pageToken')
        if target and mode == 'denied': self.denied()
        if target and mode == 'empty': return {field: []}
        if target and mode in ('paginate', 'partial'):
            if token:
                assert token == 'native-page-two'
                if mode == 'partial': self.denied()
                return {field: rows}
            return {field: rows if mode == 'partial' else [], 'nextPageToken': 'native-page-two'}
        return {field: rows}

    def respond(self, request):
        method, url = request['method'], request['url']
        p = urlsplit(url)
        assert p.scheme == 'https' and not p.query and not p.fragment and p.port is None
        assert request['scope'] in (self.scope, 'organizations/999')
        path, host, mode, cid = p.path, p.hostname, self.mode, self.cid
        family = self.spec['family']
        if host == 'cloudresourcemanager.googleapis.com':
            if path == '/v3/' + self.scope:
                assert method == 'GET'
                return {'name': 'projects/' + NUMBER, 'projectId': 'foreign-project' if mode == 'foreign-project' else PROJECT, 'state': 'ACTIVE'}
            if path == '/v1/' + self.scope + ':getAncestry':
                assert method == 'POST' and request['body'] == {}
                if mode == 'ancestry-denied': self.denied()
                return {'ancestor': [{'resourceId': {'type': 'project', 'id': NUMBER}}]}
            if path == '/v3/' + self.scope + ':getIamPolicy':
                assert method == 'POST' and request['body'] == {'options': {'requestedPolicyVersion': 3}}
                if family == 'policy' and mode == 'denied': self.denied()
                if family == 'policy': return policy_for(cid, mode)
                if family == 'account-role':
                    return {'bindings': [] if mode == 'omitted' else [{'role': 'roles/compute.instanceAdmin' if mode == 'bad' else 'roles/logging.viewer', 'members': ['serviceAccount:' + EMAIL]}]}
                if family == 'role-definition': return {'bindings': [{'role': ROLE, 'members': ['serviceAccount:' + EMAIL]}]}
                return {'bindings': []}
            raise AssertionError((method, url))
        if host == 'compute.googleapis.com':
            assert method == 'GET' and path == '/compute/v1/' + self.scope
            return {'kind': 'compute#project', 'id': NUMBER, 'name': PROJECT}
        if host == 'cloudasset.googleapis.com':
            assert method == 'GET' and path == '/v1/' + self.scope + ':searchAllIamPolicies'
            if cid == 'gcp.iam.restrict_public_members' and mode == 'bad':
                return {'results': [{'resource': '//storage.googleapis.com/' + BUCKET, 'assetType': 'storage.googleapis.com/Bucket',
                                     'project': 'projects/' + NUMBER, 'policy': {'bindings': [{'role': 'roles/storage.objectViewer', 'members': ['allAuthenticatedUsers']}]}}]}
            return self.paged(request, 'results', [], target=family == 'policy')
        if host == 'iam.googleapis.com':
            if path == '/v1/' + self.scope + '/serviceAccounts':
                assert method == 'GET'
                account = {'name': ACCOUNT, 'projectId': PROJECT, 'uniqueId': ACCOUNT_ID, 'email': EMAIL, 'disabled': False}
                return self.paged(request, 'accounts', [account], target=family in ('account-activity', 'account-role', 'account-policy', 'role-definition', 'account-keys'))
            if path == '/v1/' + ACCOUNT + ':getIamPolicy':
                assert method == 'POST' and request['params']['options.requestedPolicyVersion'] == 3
                if mode == 'local-policy-denied': self.denied()
                if family == 'account-policy' and mode == 'bad':
                    return {'bindings': [{'role': 'roles/iam.workloadIdentityUser', 'members': ['principalSet://iam.googleapis.com/projects/' + NUMBER + '/locations/global/workloadIdentityPools/shared/*']}]}
                return {}
            if path == '/v1/' + ACCOUNT + '/keys':
                assert method == 'GET'
                key = {'name': SA_KEY, 'keyType': 'USER_MANAGED', 'keyOrigin': 'GOOGLE_PROVIDED', 'keyAlgorithm': 'KEY_ALG_RSA_2048', 'validAfterTime': '2026-10-01T00:00:00Z', 'validBeforeTime': '9999-12-31T23:59:59Z', 'disabled': False}
                if family == 'key-activity' and mode in ('bad', 'omitted', 'activity-absent', 'activity-denied'):
                    key['validAfterTime'] = '2025-01-01T00:00:00Z'
                if family in ('key-type', 'account-keys') and mode != 'bad': key['keyType'] = 'SYSTEM_MANAGED'
                if key['keyType'] == 'SYSTEM_MANAGED': key['validBeforeTime'] = '2026-11-01T00:00:00Z'
                if family == 'key-age' and mode == 'bad': key['validAfterTime'] = '2026-01-01T00:00:00Z'
                if mode == 'omitted' and family != 'key-activity': key.pop('validAfterTime' if family == 'key-age' else 'keyType', None)
                key.update(self.overrides.get('key', {}))
                return self.paged(request, 'keys', [key], target=family.startswith('key-'))
            if path == '/v1/' + self.scope + '/roles':
                assert method == 'GET' and request['params']['view'] == 'FULL' and request['params']['showDeleted'] == 'true'
                if mode == 'role-denied': self.denied()
                role = {'name': ROLE, 'title': 'Native reviewed role', 'etag': 'ZXRhZw==', 'stage': 'GA', 'includedPermissions': ['storage.buckets.update' if mode == 'bad' else 'storage.buckets.get']}
                if mode == 'omitted': role.pop('includedPermissions')
                return self.paged(request, 'roles', [role], target=mode in ('role-paginate', 'role-partial'))
            if path == '/v1/' + ROLE:
                assert method == 'GET'
                if mode == 'role-denied': self.denied()
                return {'name': ROLE, 'stage': 'GA', 'includedPermissions': ['storage.buckets.get']}
            if path.startswith('/v1/roles/'):
                assert method == 'GET' and path in ('/v1/' + CRYPTO, '/v1/roles/logging.viewer', '/v1/roles/compute.instanceAdmin')
                if mode == 'role-denied': self.denied()
                return {'name': path.removeprefix('/v1/'), 'includedPermissions': [PERMISSION] if path.endswith(CRYPTO) else ['logging.logEntries.list']}
            raise AssertionError((method, url))
        if host == 'policyanalyzer.googleapis.com':
            assert method == 'GET'
            is_key = path == '/v1/' + self.scope + '/locations/global/activityTypes/serviceAccountKeyLastAuthentication/activities:query'
            assert is_key or path == '/v1/' + self.scope + '/locations/global/activityTypes/serviceAccountLastAuthentication/activities:query'
            if mode == 'activity-denied': self.denied()
            name = SA_KEY if is_key else ACCOUNT
            body = {'lastAuthenticatedTime': '2026-01-01T07:00:00Z' if mode == 'bad' else '2026-10-01T07:00:00Z',
                    'serviceAccount': {'fullResourceName': '//iam.googleapis.com/' + ACCOUNT, 'serviceAccountId': ACCOUNT_ID, 'projectNumber': NUMBER}}
            if mode == 'omitted': body.pop('lastAuthenticatedTime')
            if mode == 'foreign-activity': body['serviceAccount']['projectNumber'] = '999999999999'
            row = {'fullResourceName': '//iam.googleapis.com/' + name, 'activityType': 'serviceAccountKeyLastAuthentication' if is_key else 'serviceAccountLastAuthentication',
                   'observationPeriod': {'startTime': '2025-01-01T07:00:00Z', 'endTime': '2026-10-20T07:00:00Z'}, 'activity': body}
            return {'activities': [] if mode == 'activity-absent' else [row]}
        if host == 'cloudkms.googleapis.com':
            assert method == 'GET'
            if path == '/v1/' + self.scope + '/locations/global/keyRings': return {'keyRings': [{'name': RING}]}
            if path == '/v1/' + RING + ':getIamPolicy': return {}
            if path == '/v1/' + RING + '/cryptoKeys':
                key = {'name': KEY, 'purpose': 'ENCRYPT_DECRYPT', 'createTime': '2025-01-01T00:00:00Z',
                       'primary': {'name': VERSION, 'state': 'ENABLED', 'protectionLevel': 'SOFTWARE', 'algorithm': 'GOOGLE_SYMMETRIC_ENCRYPTION'},
                       'rotationPeriod': '7776000s', 'nextRotationTime': '2026-11-01T00:00:00Z', 'destroyScheduledDuration': '2592000s'}
                if mode == 'bad':
                    if 'rotation_enabled' in cid: key.pop('rotationPeriod')
                    elif 'rotation' in cid or 'rotated' in cid: key['rotationPeriod'] = '9504000s'
                    elif 'destroy_window' in cid: key['destroyScheduledDuration'] = '86400s'
                if mode == 'omitted':
                    key.pop('rotationPeriod', None);key.pop('destroyScheduledDuration', None)
                key.update(self.overrides.get('kms_key', {}))
                return self.paged(request, 'cryptoKeys', [key], target=True)
            if path == '/v1/' + KEY + ':getIamPolicy':
                if mode == 'local-policy-denied': self.denied()
                if family == 'kms-effective':
                    members = [] if mode == 'omitted' else ['user:user' + str(i) + '@corp.example' for i in range(4 if mode == 'bad' else 1)]
                    if mode == 'group': members = ['group:operators@corp.example']
                    return {'bindings': [{'role': CRYPTO, 'members': members}]} if members else {}
                if mode == 'bad' and cid.endswith('users_limited_to_3'):
                    return {'bindings': [{'role': CRYPTO, 'members': ['user:user' + str(i) + '@corp.example' for i in range(4)]}]}
                if mode == 'bad' and cid.endswith('no_public_iam'): return {'bindings': [{'role': CRYPTO, 'members': ['allUsers']}]}
                return {}
            if path == '/v1/' + KEY + '/cryptoKeyVersions':
                if mode == 'version-denied': self.denied()
                version = {'name': VERSION, 'state': 'DESTROY_SCHEDULED' if mode == 'bad' else 'ENABLED', 'protectionLevel': 'SOFTWARE', 'algorithm': 'GOOGLE_SYMMETRIC_ENCRYPTION'}
                if mode == 'bad': version['destroyTime'] = '2026-11-01T00:00:00Z'
                return {'cryptoKeyVersions': [] if mode == 'omitted' else [version]}
            raise AssertionError((method, url))
        if host == 'policytroubleshooter.googleapis.com':
            assert method == 'POST' and path == '/v3beta/iam:troubleshoot'
            access = request['body']['accessTuple']
            assert access['fullResourceName'] == '//cloudkms.googleapis.com/' + KEY and access['permission'] == PERMISSION
            assert access['principal'] in ['user' + str(i) + '@corp.example' for i in range(4)]
            if mode == 'troubleshooter-denied': self.denied()
            return {'accessTuple': {'principal': access['principal'], 'fullResourceName': '//cloudkms.googleapis.com/' + KEY, 'permission': PERMISSION},
                    'overallAccessState': 'CANNOT_ACCESS' if mode == 'effective-denied' else 'CAN_ACCESS',
                    'pabPolicyExplanation': {'principalAccessBoundaryAccessState': 'PAB_ACCESS_STATE_NOT_ENFORCED'}}
        if host == 'secretmanager.googleapis.com':
            assert method == 'GET'
            if path == '/v1/' + self.scope + '/secrets': return self.paged(request, 'secrets', [{'name': SECRET, 'replication': {'automatic': {}}}], target=True)
            assert path == '/v1/' + SECRET + ':getIamPolicy'
            if mode == 'local-policy-denied': self.denied()
            return {'bindings': [{'role': 'roles/secretmanager.secretAccessor', 'members': ['allUsers']}]} if mode == 'bad' else {}
        if host == 'storage.googleapis.com':
            assert method == 'GET'
            if path == '/storage/v1/projects/' + self.scope.split('/')[1] + '/hmacKeys':
                key = {'id': PROJECT + '/GOOG' + 'A' * 56, 'accessId': 'GOOG' + 'A' * 56, 'projectId': PROJECT, 'serviceAccountEmail': EMAIL, 'state': 'ACTIVE', 'timeCreated': '2026-10-01T00:00:00Z'}
                if mode == 'bad': key['timeCreated'] = '2026-01-01T00:00:00Z'
                if mode == 'omitted': key.pop('timeCreated')
                return self.paged(request, 'items', [key], target=True)
            if path == '/storage/v1/b':
                assert request['params']['project'] == self.scope.split('/')[1] and request['params']['projection'] == 'full'
                return {'items': [{'kind': 'storage#bucket', 'name': BUCKET, 'projectNumber': NUMBER, 'iamConfiguration': {'uniformBucketLevelAccess': {'enabled': True}}}]}
            if path == '/storage/v1/b/' + BUCKET + '/iam': return {}
            assert path == '/storage/v1/b/' + BUCKET + '/notificationConfigs'
            config = {'id': '1', 'topic': '//pubsub.googleapis.com/projects/' + ('foreign-project' if mode == 'bad' else PROJECT) + '/topics/object-events', 'payload_format': 'JSON_API_V1', 'event_types': ['OBJECT_FINALIZE']}
            if mode == 'omitted': config.pop('topic')
            if mode == 'denied': self.denied()
            return {'items': [] if mode == 'empty' else [config]}
        if host == 'logging.googleapis.com':
            assert method == 'GET' and path == '/v2/' + self.scope + '/locations/global/buckets'
            bucket = {'name': self.scope + '/locations/global/buckets/native-audit', 'retentionDays': 30 if mode == 'bad' else 365, 'lifecycleState': 'ACTIVE', 'locked': True}
            if mode == 'omitted': bucket.pop('retentionDays')
            assert 'retentionDays' not in (request.get('params') or {}).get('fields', '') or request['params']['fields']
            return self.paged(request, 'buckets', [bucket], target=True)
        raise AssertionError((method, url))

    def request(self, method, url, **kwargs):
        request = {'method': method, 'url': url, **deepcopy(kwargs)}
        self.requests.append(request)
        rid = 'native-request-' + str(len(self.requests))
        entry = {'id': rid, 'method': method, 'url': url, 'scope': kwargs['scope']}
        try:
            value = self.respond(request)
            def native_fields(obj):
                if isinstance(obj, dict):
                    assert not any(str(k).startswith('_') or k in ('resolutionComplete', 'effectiveAuditConfigs', 'principals') for k in obj)
                    for v in obj.values(): native_fields(v)
                elif isinstance(obj, list):
                    for v in obj: native_fields(v)
            native_fields(value)
            request['response'] = deepcopy(value)
        except gcp.ReadError as exc:
            exc.request_id = rid;entry.update(status=exc.status, error=exc.error);request['response_error'] = deepcopy(exc.error)
            raise
        except Exception as exc:
            self.contract_errors.append(repr(exc))
            raise
        finally:
            self.evidence.append(entry)
        entry['status'] = 'collected'
        return deepcopy(value), rid


def run_case(spec, mode, record_property, **overrides):
    check = next(c for c in CHECKS if c.id == spec['id'])
    kinds = list(check.dependencies)
    if spec['family'] == 'policy' and 'project' not in kinds: kinds.append('project')
    options = {'inventories': kinds, 'include_inherited': True, 'resource_iam': (mode in ('partial', 'paginate') and spec['family'] == 'policy') or (spec['id'] == 'gcp.iam.restrict_public_members' and mode == 'bad'),
               'metrics_scopes': False, 'concurrency': 1, 'kms_locations': ['global'], 'logging_locations': ['global'],
               'service_account_activity': spec['family'] in ('account-activity', 'key-activity')}
    scope = overrides.pop('scope', SCOPE)
    api = NativeAPI(spec, mode, scope, **overrides)
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [scope], 'options': options}, requirements=kinds, transport=api)
    collector.read_time = CAPTURED
    import peaso.snapshot
    make_snapshot = peaso.snapshot.make_snapshot
    with pytest.MonkeyPatch.context() as patch:
        # Provider activity windows are dated against CAPTURED; seal the
        # snapshot on that same clock so the three-day lag gate does not
        # expire as wall time passes.
        patch.setattr(peaso.snapshot, 'make_snapshot',
                      lambda *args, **kwargs: make_snapshot(*args, **{**kwargs, 'created_at': CAPTURED}))
        captured = collector.collect()
    assert not api.contract_errors, (api.contract_errors, api.requests)
    assert validate(captured) == captured
    before = deepcopy(captured)
    rows = evaluate_snapshot(captured, checks=[spec['id']], include_not_applicable=True)['findings']
    assert captured == before
    record_property('native_case', json.dumps({'id': spec['id'], 'family': spec['family'], 'mode': mode, 'requests': api.requests,
        'collections': [{'type': c['type'], 'scope': c['scope'], 'status': c['status'], 'coverage_status': c.get('coverage_status'), 'items': len(c['items'])} for c in captured['collections']],
        'findings': rows}, sort_keys=True))
    return rows, captured, api


@pytest.mark.parametrize('spec', SPECS, ids=[s['id'] for s in SPECS])
@pytest.mark.parametrize('mode', ['good', 'bad', 'omitted', 'denied', 'empty'])
def test_every_assigned_id_native_http_to_engine(spec, mode, record_property):
    rows, captured, api = run_case(spec, mode, record_property)
    if mode == 'denied':
        assert rows and all(r['status'] in ('DENIED', 'UNKNOWN') for r in rows), rows
    elif mode == 'empty' and spec['family'] != 'policy':
        assert rows and all(r['status'] == 'EMPTY' for r in rows), rows
    else:
        expected = spec['omitted'] if mode in ('omitted', 'empty') else 'FAIL' if mode == 'bad' else 'PASS'
        if spec['id'] == 'gcp.claude.iam_policy.no_all_users' and mode == 'bad':
            expected = 'PASS'  # Legal user principal; public project grants are not native-supported.
        resources = [r for r in rows if 'native_resource_id' in r]
        if spec['id'] == 'gcp.iam.restrict_public_members' and mode == 'bad':
            assert len(resources) == 2 and sorted(r['status'] for r in resources) == ['FAIL', 'PASS'], rows
        else:
            assert len(resources) == 1 and resources[0]['status'] == expected, rows


@pytest.mark.parametrize('cid', [s['id'] for s in SPECS if s['family'] in ('policy', 'kms', 'kms-versions', 'kms-effective', 'account-role', 'role-definition', 'key-age', 'hmac', 'secret', 'logging')])
@pytest.mark.parametrize('mode', ['paginate', 'partial'])
def test_native_pagination_preserves_coverage_uncertainty(cid, mode, record_property):
    spec = BY_ID[cid]
    rows, captured, api = run_case(spec, mode, record_property)
    page_two = [q for q in api.requests if (q.get('params') or {}).get('pageToken') == 'native-page-two']
    assert page_two, api.requests
    if mode == 'paginate':
        resources = [r for r in rows if 'native_resource_id' in r]
        assert len(resources) == 1 and resources[0]['status'] == 'PASS', rows
    else:
        assert any(r['status'] == 'UNKNOWN' for r in rows), rows
        assert any(c['status'] == 'partial' for c in captured['collections']), captured['collections']


@pytest.mark.parametrize('cid', ['gcp.claude.service_account.recently_used', 'gcp.claude.service_account_key.recently_used'])
@pytest.mark.parametrize('mode', ['activity-absent', 'activity-denied'])
def test_activity_absence_or_denial_is_not_unused_proof(cid, mode, record_property):
    rows, _, _ = run_case(BY_ID[cid], mode, record_property)
    resources = [r for r in rows if 'native_resource_id' in r]
    expected = 'DENIED' if mode == 'activity-denied' else 'UNKNOWN'
    assert len(resources) == 1 and resources[0]['status'] == expected, rows


@pytest.mark.parametrize('cid', ['gcp.gap.iam_user_managed_sa_no_admin_roles', 'gcp.ports.service_account_mutating_role_declarations'])
@pytest.mark.parametrize('mode', ['foreign-project', 'ancestry-denied'])
def test_native_project_alias_and_ancestry_guards(cid, mode, record_property):
    rows, _, _ = run_case(BY_ID[cid], mode, record_property)
    resources = [r for r in rows if 'native_resource_id' in r]
    assert len(resources) == 1 and resources[0]['status'] == 'UNKNOWN', rows


@pytest.mark.parametrize('cid', ['gcp.gap.iam_user_managed_sa_no_admin_roles', 'gcp.ports.service_account_mutating_role_declarations'])
def test_native_numeric_project_alias_with_independent_crm_identity(cid, record_property):
    rows, _, _ = run_case(BY_ID[cid], 'good', record_property, scope='projects/' + NUMBER)
    resources = [r for r in rows if 'native_resource_id' in r]
    assert len(resources) == 1 and resources[0]['status'] == 'PASS', rows


@pytest.mark.parametrize('mode,expected', [('role-paginate', 'PASS'), ('role-partial', 'UNKNOWN'), ('role-denied', 'UNKNOWN')])
def test_native_role_definition_pagination_and_denial(mode, expected, record_property):
    cid = 'gcp.ports.service_account_mutating_role_declarations'
    rows, _, _ = run_case(BY_ID[cid], mode, record_property)
    resources = [r for r in rows if 'native_resource_id' in r]
    assert len(resources) == 1 and resources[0]['status'] == expected, rows


@pytest.mark.parametrize('mode,expected', [('group', 'UNKNOWN'), ('role-denied', 'UNKNOWN'), ('troubleshooter-denied', 'UNKNOWN'), ('effective-denied', 'PASS')])
def test_native_kms_effective_use_requires_resolvable_access(mode, expected, record_property):
    cid = 'gcp_pci_kms_key_a3927a5f3b84'
    rows, _, _ = run_case(BY_ID[cid], mode, record_property)
    resources = [r for r in rows if 'native_resource_id' in r]
    assert len(resources) == 1 and resources[0]['status'] == expected, rows


@pytest.mark.parametrize('cid', ['gcp.claude.kms_key.users_limited_to_3', 'gcp.reviewed.kms.no_public_iam', 'gcp.claude.secret.not_public', 'gcp.htbp.iam.sa_no_pool_wide_workload_principal_set'])
def test_native_local_policy_denial_cannot_prove_safety(cid, record_property):
    rows, _, _ = run_case(BY_ID[cid], 'local-policy-denied', record_property)
    resources = [r for r in rows if 'native_resource_id' in r]
    assert len(resources) == 1 and resources[0]['status'] == 'UNKNOWN', rows


def test_native_fractional_kms_duration_above_100_days_is_not_compliant(record_property):
    cid = 'gcp.claude.kms_key.rotation_100_days'
    rows, _, _ = run_case(BY_ID[cid], 'fractional-duration', record_property, kms_key={'rotationPeriod': '8640000.500s'})
    resources = [r for r in rows if 'native_resource_id' in r]
    assert len(resources) == 1 and resources[0]['status'] == 'FAIL', rows
