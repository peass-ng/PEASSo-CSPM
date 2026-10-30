"""VM IAM permission decisions use native role contents, not role-name heuristics."""
from copy import deepcopy

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.checks.claude_gcp_k8s_compute import INSTANCE_PERMISSIONS
from tests.test_peaso_collectors_gcp import snapshot
from tests.test_gcp_firewall_port_native_matrix_review_20261020 import forbid_provider_network

ACCOUNT = 'app@p-one.iam.gserviceaccount.com'


def capture(family, permissions, role='roles/review.nativeRole', *, denied=False, duplicate=False, conditional=False, email=ACCOUNT, stage="GA"):
    requests = []
    definition = {'name': role, 'title': 'Native review', 'includedPermissions': permissions, 'stage': stage}
    binding = {'role': role, 'members': ['serviceAccount:' + ACCOUNT]}
    if conditional: binding['condition'] = {'title': 'condition', 'expression': 'request.time < timestamp("2030-01-01T00:00:00Z")'}

    def resolve(request):
        requests.append(deepcopy(request));url = request['url']
        assert request['method'] == ('POST' if url.endswith(':getIamPolicy') else 'GET')
        if url == 'https://compute.googleapis.com/compute/v1/projects/p-one/aggregated/instances':
            return {'items': {'zones/us-central1-a': {'instances': [{'name': 'review',
                    'selfLink': 'https://www.googleapis.com/compute/v1/projects/p-one/zones/us-central1-a/instances/review',
                    'serviceAccounts': [{'email': email}]}]}}}
        if url.endswith('/projects/p-one:getIamPolicy'):
            return {'version': 3, 'bindings': [binding]}
        if url == 'https://iam.googleapis.com/v1/projects/p-one/roles':
            rows = [deepcopy(definition), {**deepcopy(definition), 'includedPermissions': ['compute.instances.get']}]
            return {'roles': list(reversed(rows)) if duplicate == 'reversed' else rows} if duplicate else {'roles': []}
        if url == 'https://iam.googleapis.com/v1/' + role:
            if denied: raise gcp.ReadError('denied', 'permission_denied', http_status=403)
            return definition
        if url == 'https://cloudresourcemanager.googleapis.com/v3/projects/p-one':
            return {'name': 'projects/123', 'projectId': 'p-one', 'state': 'ACTIVE'}
        if url == 'https://cloudresourcemanager.googleapis.com/v1/projects/p-one':
            return {'projectNumber': '123', 'projectId': 'p-one', 'lifecycleState': 'ACTIVE'}
        if url == 'https://compute.googleapis.com/compute/v1/projects/p-one':
            return {'kind': 'compute#project', 'name': 'p-one', 'id': '123'}
        raise AssertionError('Unplanned native request: ' + url)

    collected, _ = snapshot(['instance', 'iam_policy', 'iam_role', 'project'], resolve,
                            resource_iam=False, metrics_scopes=False)
    before = deepcopy(collected)
    cid = 'gcp.claude.instance.sa_no_basic_role' if family == 'basic' else 'gcp.claude.instance.sa_no_' + family + '_permission'
    rows = evaluate_snapshot(collected, checks=[cid])['findings']
    assert collected == before and len(rows) == 1
    return rows[0], requests


@pytest.mark.parametrize('family', sorted(INSTANCE_PERMISSIONS))
@pytest.mark.parametrize('mode,expected', [('dangerous', 'FAIL'), ('read_only', 'PASS'),
                                          ('denied', 'UNKNOWN'), ('conditional', 'MANUAL'),
                                          ('duplicate', 'UNKNOWN')])
def test_every_permission_family_uses_the_native_role_definition(family, mode, expected):
    permission = INSTANCE_PERMISSIONS[family][0][0]
    row, requests = capture(family, ['compute.instances.get'] if mode == 'read_only' else [permission],
                            role='projects/p-one/roles/custom' if mode == 'duplicate' else 'roles/review.nativeRole',
                            denied=mode == 'denied', duplicate=mode == 'duplicate', conditional=mode == 'conditional')
    assert row['status'] == expected, row
    if mode != 'duplicate':
        assert any(r['url'] == 'https://iam.googleapis.com/v1/roles/review.nativeRole' for r in requests)


@pytest.mark.parametrize('family,role,permissions', [
    ('data_destruction', 'roles/cloudsql.instanceUser', ['cloudsql.instances.get', 'cloudsql.instances.login', 'cloudsql.instances.executeSql']),
    ('disrupt_logging', 'roles/logging.bucketWriter', ['logging.buckets.write']),
])
def test_predefined_role_name_cannot_invent_unlisted_permissions(family, role, permissions):
    row, _ = capture(family, permissions, role)
    assert row['status'] == 'PASS', row


@pytest.mark.parametrize('family', sorted(INSTANCE_PERMISSIONS))
def test_previously_unlisted_predefined_role_with_a_deciding_permission_fails(family):
    row, _ = capture(family, [INSTANCE_PERMISSIONS[family][0][0]], 'roles/review.newPredefinedRole')
    assert row['status'] == 'FAIL', row


@pytest.mark.parametrize('family', sorted(INSTANCE_PERMISSIONS))
def test_permission_free_duplicate_cannot_hide_a_later_grant(family):
    row, _ = capture(family, [INSTANCE_PERMISSIONS[family][0][0]],
                     'projects/p-one/roles/custom', duplicate='reversed')
    assert row['status'] == 'UNKNOWN', row


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('mode', ['pages', 'jobs'])
def test_duplicate_role_identity_is_incomplete_in_both_producer_merge_paths(reverse, mode):
    from tests.test_peaso_collectors_gcp import FixtureTransport
    role = 'projects/p-one/roles/custom'
    rows = [{'name': role, 'includedPermissions': [permission]}
            for permission in ('compute.instances.get', 'compute.instances.delete')]
    if reverse: rows.reverse()
    def forbidden(request): raise AssertionError('No HTTP required for merge proof')
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': ['projects/p-one'],
                                 'options': {'include_inherited': False}}, ['iam_role'],
                                transport=FixtureTransport(forbidden))
    if mode == 'pages':
        row = collector.envelope('iam_role', 'projects/p-one', 'iam',
                                 lambda: iter([([rows[0]], 'read-1'), ([rows[1]], 'read-2')]))
    else:
        collector.add('iam_role', 'projects/p-one', 'iam', lambda: iter([([rows[0]], 'read-1')]))
        row = collector.add('iam_role', 'projects/p-one', 'iam', lambda: iter([([rows[1]], 'read-2')]))
    assert row['coverage_status'] == 'partial'
    assert row['error']['code'] == 'duplicate_iam_role_identity'
    assert row['source_requests'] == ['read-1', 'read-2']


@pytest.mark.parametrize('family', [*sorted(INSTANCE_PERMISSIONS), 'basic'])
@pytest.mark.parametrize('email', ['', 'default', 'not-an-email', ' app@p-one.iam.gserviceaccount.com'])
def test_unresolved_attached_service_account_identity_never_passes(family, email):
    permissions = INSTANCE_PERMISSIONS[family][0][:1] if family != 'basic' else ['compute.instances.get']
    row, _ = capture(family, permissions, 'roles/editor', email=email)
    assert row['status'] == 'UNKNOWN', row


@pytest.mark.parametrize('role,expected', [('roles/editor', 'FAIL'), ('roles/owner', 'FAIL'), ('roles/viewer', 'PASS')])
def test_basic_role_control_remains_a_literal_declared_role_check(role, expected):
    row, _ = capture('basic', ['compute.instances.get'], role)
    assert row['status'] == expected, row


@pytest.mark.parametrize('family', sorted(INSTANCE_PERMISSIONS))
@pytest.mark.parametrize('stage,expected', [('DISABLED', 'PASS'), ('ALPHA', 'FAIL')])
def test_native_disabled_role_does_not_grant_its_retained_permissions(family, stage, expected):
    row, _ = capture(family, INSTANCE_PERMISSIONS[family][0][:1],
                     'projects/p-one/roles/custom', stage=stage)
    assert row['status'] == expected, row
