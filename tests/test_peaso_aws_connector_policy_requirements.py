"""Connector readiness must inspect policy grants, not merely authenticate."""
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from peaso.server import create_app
from peaso.server.access_check import check_access
from peaso.server.aws_access_requirements import BASELINE_ACTIONS, check_policy_requirements
from peaso.server.config import Settings
from test_peaso_connector_access_check import IdentityStub

ACCOUNT = '555566667777'
PREFIX = 'arn:aws:iam::aws:policy/'
POLICIES = ['ReadOnlyAccess', 'SecurityAudit', 'IAMAccessAnalyzerFullAccess']


def test_hosted_role_attaches_recommended_managed_policies_within_quota():
    from scripts.peaso_deploy_customer_policy import IAM_MANAGED_POLICIES_PER_ROLE

    template = json.loads((Path(__file__).parents[1] / 'infra/aws/customer-role.json').read_text())
    role = template['Resources']['AuditRole']['Properties']
    # The hosted role grants only the read-only baseline policies. Product
    # collectors never call live IAM Access Analyzer APIs
    # (access_analyzer_live_api_banned), so the broad analyzer policy, which
    # also allows analyzer creation, is intentionally not attached.
    assert role['ManagedPolicyArns'] == [PREFIX + 'ReadOnlyAccess', PREFIX + 'SecurityAudit']
    assert PREFIX + 'IAMAccessAnalyzerFullAccess' not in role['ManagedPolicyArns']
    custom = sum(resource['Type'] == 'AWS::IAM::ManagedPolicy'
                 for resource in template['Resources'].values())
    assert custom + len(role['ManagedPolicyArns']) <= IAM_MANAGED_POLICIES_PER_ROLE


class IAM:
    def __init__(self, names=(), *, group_names=(), equivalent=False):
        self.names, self.group_names, self.equivalent = names, group_names, equivalent
        self.calls = []

    def attachments(self, names):
        return {'AttachedPolicies': [{'PolicyArn': PREFIX + name} for name in names], 'IsTruncated': False}

    def list_attached_user_policies(self, **kwargs):
        self.calls.append(('user', kwargs))
        return self.attachments(self.names)

    def list_groups_for_user(self, **kwargs):
        return {'Groups': [{'GroupName': 'scanning'}] if self.group_names else []}

    def list_attached_group_policies(self, **kwargs):
        self.calls.append(('group', kwargs))
        return self.attachments(self.group_names)

    def list_attached_role_policies(self, **kwargs):
        self.calls.append(('role', kwargs))
        return self.attachments(self.names)

    def get_role(self, **kwargs):
        return {'Role': {'Arn': f'arn:aws:iam::{ACCOUNT}:role/path/scan'}}

    def simulate_principal_policy(self, **kwargs):
        self.calls.append(('simulate', kwargs))
        return {'EvaluationResults': [{'EvalActionName': action,
            'EvalDecision': 'allowed' if self.equivalent else 'implicitDeny'} for action in BASELINE_ACTIONS]}


def inspect(iam, resource='user/path/scan', service='iam', partition='aws'):
    issues = []
    identity = {'Account': ACCOUNT, 'Arn': f'arn:{partition}:{service}::{ACCOUNT}:{resource}'}
    check_policy_requirements(iam, identity, ACCOUNT, issues)
    return issues


def test_readonly_alone_warns_for_missing_security_and_analyzer_policies(monkeypatch):
    iam = IAM(['ReadOnlyAccess'])
    class Session:
        def client(self, service, **kwargs):
            return iam if service == 'iam' else self
        def get_caller_identity(self):
            return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/scan'}
        def describe_instances(self, **kwargs): return {}
        def list_buckets(self): return {}
        def list_analyzers(self, **kwargs): return {}
    iam.get_account_authorization_details = lambda **kwargs: {}
    monkeypatch.setattr('peaso.collectors.aws._session', lambda auth, region: (Session(), region))
    result = check_access('aws', {}, [ACCOUNT], {}, Settings())
    assert result['status'] == 'warning'
    assert result['requires_warning_acknowledgement'] is True
    assert result['scope_summary']['warning'] == 1
    assert result['scope_results'][0]['status'] == 'warning'
    assert len(result['issues']) == 2
    assert all(any(PREFIX + name in issue['message'] for issue in result['issues']) for name in POLICIES[1:])


@pytest.mark.parametrize('names,critical,advisories', [
    ([], True, 3), (['SecurityAudit', 'IAMAccessAnalyzerFullAccess'], False, 1),
    (['ReadOnlyAccess'], False, 2), (POLICIES, False, 0),
    (['AdministratorAccess'], True, 3),
])
def test_required_and_recommended_policy_classification(names, critical, advisories):
    issues = inspect(IAM(names))
    assert any(row['severity'] == 'critical' for row in issues) is critical
    assert sum(row['severity'] == 'advisory' for row in issues) == advisories


def test_group_inherited_policies_are_counted_for_the_actual_user():
    iam = IAM(group_names=POLICIES)
    assert inspect(iam) == []
    assert ('group', {'GroupName': 'scanning', 'MaxItems': 100}) in iam.calls


def test_assumed_role_uses_actual_role_and_preserves_path_for_custom_baseline_simulation():
    iam = IAM(equivalent=True)
    issues = inspect(iam, 'assumed-role/scan/session', 'sts')
    assert all(row['severity'] == 'advisory' for row in issues)
    assert ('role', {'RoleName': 'scan', 'MaxItems': 100}) in iam.calls
    params = next(kwargs for method, kwargs in iam.calls if method == 'simulate')
    assert params['PolicySourceArn'] == f'arn:aws:iam::{ACCOUNT}:role/path/scan'


def test_policy_pagination_reads_later_pages():
    iam = IAM()
    def pages(**kwargs):
        if 'Marker' not in kwargs:
            return {**iam.attachments(['ReadOnlyAccess']), 'IsTruncated': True, 'Marker': 'page2'}
        assert kwargs['Marker'] == 'page2'
        return iam.attachments(POLICIES[1:])
    iam.list_attached_user_policies = pages
    assert inspect(iam) == []


@pytest.mark.parametrize('response', [{}, {'AttachedPolicies': [], 'IsTruncated': True},
                                      {'AttachedPolicies': [], 'IsTruncated': True, 'Marker': 'repeated'}])
def test_incomplete_or_repeated_pages_never_report_policies_as_verified(response):
    iam = IAM()
    iam.list_attached_user_policies = lambda **kwargs: response
    issues = inspect(iam)
    assert any(row['severity'] == 'critical' and 'Could not verify required policy' in row['message'] for row in issues)
    assert any('Could not verify recommended policy' in row['message'] for row in issues)


def test_denied_policy_inspection_is_not_misreported_as_a_complete_inventory():
    iam = IAM()
    def denied(**kwargs): raise PermissionError('denied')
    iam.list_attached_user_policies = denied
    assert any('inspection was incomplete' in row['message'] for row in inspect(iam))


def test_custom_baseline_requires_complete_allowed_simulation_without_missing_context():
    iam = IAM(equivalent=True)
    assert not any(row['severity'] == 'critical' for row in inspect(iam))
    iam.simulate_principal_policy = lambda **kwargs: {'EvaluationResults': [{'EvalActionName': action,
        'EvalDecision': 'allowed', 'MissingContextValues': ['aws:PrincipalTag/team']} for action in BASELINE_ACTIONS]}
    assert any(row['severity'] == 'critical' for row in inspect(iam))


def test_partition_specific_policy_arns_are_required():
    issues = inspect(IAM(['ReadOnlyAccess']), partition='aws-us-gov')
    assert any('arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess' in row['message'] for row in issues)


def test_warning_receipt_requires_explicit_boolean_acknowledgement_and_stays_bound(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity', require_connector_access_check=True)
    monkeypatch.setattr('peaso.server.access_check.check_access', lambda *args, **kwargs: {
        'status': 'warning', 'issues': [{'severity': 'advisory', 'scope': ACCOUNT, 'message': 'Missing SecurityAudit'}], 'principals': []})
    body = {'name': 'Read only', 'provider': 'aws', 'auth': {'method': 'access_keys',
            'aws_access_key_id': 'inert', 'aws_secret_access_key': 'inert'}, 'scopes': [ACCOUNT], 'options': {}}
    with TestClient(create_app(settings, authenticator=IdentityStub()), base_url='http://127.0.0.1') as client:
        assert client.post('/api/connectors', json=body).status_code == 422
        checked = client.post('/api/connectors/check-access', json=body)
        assert checked.status_code == 200, checked.text
        body['check_token'] = checked.json()['check_token']
        for acknowledgement in (False, 'true', 1):
            response = client.post('/api/connectors', json={**body, 'acknowledge_access_warnings': acknowledgement})
            assert response.status_code == 422, response.text
        altered = {**body, 'scopes': ['111111111111'], 'acknowledge_access_warnings': True}
        assert client.post('/api/connectors', json=altered).status_code == 422
        saved = client.post('/api/connectors', json={**body, 'acknowledge_access_warnings': True})
        assert saved.status_code == 201, saved.text
        assert 'acknowledge_access_warnings' not in saved.json()


def test_blocked_access_never_issues_a_save_receipt(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity', require_connector_access_check=True)
    monkeypatch.setattr('peaso.server.access_check.check_access', lambda *args, **kwargs: {
        'status': 'blocked', 'issues': [{'severity': 'critical', 'scope': ACCOUNT, 'message': 'Missing ReadOnlyAccess'}], 'principals': []})
    body = {'name': 'Blocked', 'provider': 'aws', 'auth': {'method': 'access_keys',
            'aws_access_key_id': 'inert', 'aws_secret_access_key': 'inert'}, 'scopes': [ACCOUNT], 'options': {}}
    with TestClient(create_app(settings, authenticator=IdentityStub()), base_url='http://127.0.0.1') as client:
        checked = client.post('/api/connectors/check-access', json=body)
        assert checked.status_code == 200 and 'check_token' not in checked.json()
        assert client.post('/api/connectors', json={**body, 'acknowledge_access_warnings': True}).status_code == 422


def test_live_create_and_edit_require_current_access_receipts_even_with_default_settings(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    result = {'status': 'pass', 'issues': [], 'principals': []}
    monkeypatch.setattr('peaso.server.access_check.check_access', lambda *args, **kwargs: result)
    body = {'name': 'Initial', 'provider': 'aws', 'auth': {'method': 'access_keys',
            'aws_access_key_id': 'inert', 'aws_secret_access_key': 'inert'}, 'scopes': [ACCOUNT], 'options': {}}
    with TestClient(create_app(settings, authenticator=IdentityStub()), base_url='http://127.0.0.1') as client:
        assert client.post('/api/connectors', json=body).status_code == 422
        checked = client.post('/api/connectors/check-access', json=body).json()
        created = client.post('/api/connectors', json={**body, 'check_token': checked['check_token']})
        assert created.status_code == 201, created.text
        ident = created.json()['id']
        patch = {'name': 'Renamed'}
        assert client.patch(f'/api/connectors/{ident}', json=patch).status_code == 422
        edit_check = client.post('/api/connectors/check-access', json={
            **body, 'name': 'Renamed', 'auth': {}, 'connector_id': ident}).json()
        assert edit_check['status'] == 'pass' and edit_check['check_token']
        assert client.patch(f'/api/connectors/{ident}', json={**patch, 'check_token': checked['check_token']}).status_code == 422
        edited = client.patch(f'/api/connectors/{ident}', json={**patch, 'check_token': edit_check['check_token']})
        assert edited.status_code == 200, edited.text
        assert edited.json()['name'] == 'Renamed'
        assert client.patch(f'/api/connectors/{ident}', json={**patch, 'check_token': edit_check['check_token']}).status_code == 422


def test_edit_warning_needs_acknowledgement_and_blocked_edit_has_no_receipt(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    current = {'status': 'pass', 'issues': [], 'principals': []}
    monkeypatch.setattr('peaso.server.access_check.check_access', lambda *args, **kwargs: current)
    body = {'name': 'Initial', 'provider': 'aws', 'auth': {'method': 'access_keys',
            'aws_access_key_id': 'inert', 'aws_secret_access_key': 'inert'}, 'scopes': [ACCOUNT], 'options': {}}
    with TestClient(create_app(settings, authenticator=IdentityStub()), base_url='http://127.0.0.1') as client:
        receipt = client.post('/api/connectors/check-access', json=body).json()['check_token']
        ident = client.post('/api/connectors', json={**body, 'check_token': receipt}).json()['id']
        current.update(status='warning', issues=[{'severity': 'advisory', 'scope': ACCOUNT,
                            'message': 'Missing recommended IAMAccessAnalyzerFullAccess; analyzer findings may be unavailable.'}])
        checked = client.post('/api/connectors/check-access', json={**body, 'name': 'Edited',
                    'auth': {}, 'connector_id': ident}).json()
        assert checked['status'] == 'warning'
        patch = {'name': 'Edited', 'check_token': checked['check_token']}
        assert client.patch(f'/api/connectors/{ident}', json=patch).status_code == 422
        assert client.patch(f'/api/connectors/{ident}', json={**patch, 'acknowledge_access_warnings': True}).status_code == 200
        current.update(status='blocked', issues=[{'severity': 'critical', 'scope': ACCOUNT, 'message': 'Required inventory denied.'}])
        blocked = client.post('/api/connectors/check-access', json={**body, 'name': 'Blocked',
                    'auth': {}, 'connector_id': ident}).json()
        assert blocked['status'] == 'blocked' and 'check_token' not in blocked
        assert client.patch(f'/api/connectors/{ident}', json={'name': 'Blocked',
                     'acknowledge_access_warnings': True}).status_code == 422


def test_switching_demo_connector_to_live_requires_access_receipt(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    monkeypatch.setattr('peaso.server.access_check.check_access', lambda *args, **kwargs: {
        'status': 'pass', 'issues': [], 'principals': []})
    body = {'name': 'Demo', 'provider': 'aws', 'auth': {'method': 'access_keys',
            'aws_access_key_id': 'inert', 'aws_secret_access_key': 'inert'},
            'scopes': [ACCOUNT], 'options': {'demo': True}}
    with TestClient(create_app(settings, authenticator=IdentityStub()), base_url='http://127.0.0.1') as client:
        created = client.post('/api/connectors', json=body)
        assert created.status_code == 201, created.text
        ident = created.json()['id']
        assert client.patch(f'/api/connectors/{ident}', json={'options': {}}).status_code == 422
        check = client.post('/api/connectors/check-access', json={**body, 'auth': {},
                            'options': {}, 'connector_id': ident}).json()
        saved = client.patch(f'/api/connectors/{ident}', json={'options': {}, 'check_token': check['check_token']})
        assert saved.status_code == 200, saved.text
        assert saved.json()['input_mode'] == 'live'
