"""Independent SDK -> Requests -> public aws.collect -> engine identity contracts.

Every AWS client uses inert credentials and Stubber. No fixture documents or
handmade collection indexes are used; unsupported native-only branches stay open.
"""
import copy
import csv
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import boto3
import pytest
from botocore.stub import Stubber
from peaso import engine
from peaso.collectors import aws

ACCOUNT, FOREIGN, REGION = '123456789012', '999999999999', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def days_ago(days):
    return (NOW - timedelta(days=days)).isoformat().replace('+00:00', 'Z')
REGISTRY = {c.id: c for c in engine._registry()}
INPUT = json.loads(Path('docs/aws-review/identity-closure-review.json').read_text())
INPUT_IDS = [r['id'] for r in INPUT['checks'] if r['disposition'] == 'unproved_contract']
IAM_KINDS = {'iam_policy', 'iam_user', 'iam_role', 'iam_group'}
IAM_IDS = [cid for cid in INPUT_IDS if REGISTRY[cid].kind in IAM_KINDS]
SERVICE_USAGE_IDS = ['aws.claude_a.iam.user_long_lived_keys_only_iam_sts',
    'aws.claude_a.iam.user_bedrock_access_not_stale', 'aws.claude_a.iam.user_sagemaker_access_not_stale',
    'aws.claude_a.iam.role_bedrock_access_not_stale']
def document(action='s3:GetObject', resource='*', **extra):
    return {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': action, 'Resource': resource, **extra}]}


def gaad(action='s3:GetObject', *, account=ACCOUNT, attached=True, inline=True, trust='own', version='valid', attachment_name='review'):
    policy_arn = f'arn:aws:iam::{account}:policy/review'
    attachment = [{'PolicyArn': policy_arn, 'PolicyName': attachment_name}] if attached else []
    doc = document(action)
    encoded = quote(json.dumps(doc))
    trust_principal = {'AWS': f'arn:aws:iam::{FOREIGN if trust == "foreign" else account}:root'}
    if trust == 'public': trust_principal = '*'
    if trust == 'service': trust_principal = {'Service': 'ec2.amazonaws.com'}
    row = {'Arn': policy_arn, 'PolicyName': 'review', 'PolicyId': 'ANPA'+'A'*17, 'Path': '/', 'CreateDate': NOW,
           'AttachmentCount': 3 if attached else 0, 'DefaultVersionId': 'v1',
           'PolicyVersionList': [{'VersionId': 'v1', 'IsDefaultVersion': True, 'Document': encoded},
                                 {'VersionId': 'v2', 'IsDefaultVersion': False, 'Document': quote(json.dumps(document('*')))}]}
    if version == 'mismatch': row['DefaultVersionId'] = 'v2'
    if version == 'missing': row['PolicyVersionList'][0].pop('Document')
    if version == 'missing_statement': row['PolicyVersionList'][0]['Document'] = quote(json.dumps({}))
    if version == 'empty': row['PolicyVersionList'][0]['Document'] = quote(json.dumps({'Statement': []}))
    out = {'IsTruncated': False, 'Policies': [row]}
    for kind, prefix in [('User', 'AIDA'), ('Group', 'AGPA'), ('Role', 'AROA')]:
        entity = kind.lower()
        item = {kind+'Name': 'review', kind+'Id': prefix+'A'*17, 'Arn': f'arn:aws:iam::{account}:{entity}/review',
                'Path': '/', 'CreateDate': NOW, 'AttachedManagedPolicies': copy.deepcopy(attachment),
                kind+'PolicyList': [{'PolicyName': 'inline', 'PolicyDocument': encoded}] if inline else []}
        if kind == 'User': item['GroupList'] = ['review']
        if kind == 'Role':
            item['AssumeRolePolicyDocument'] = quote(json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': trust_principal}]}))
            item['RoleLastUsed'] = {'LastUsedDate': NOW, 'Region': REGION}
        out[kind+'DetailList'] = [item]
    return out


def csv_content(**changes):
    row = {'user': 'review', 'arn': f'arn:aws:iam::{ACCOUNT}:user/review', 'user_creation_time': days_ago(730),
           'password_enabled': 'true', 'password_last_used': days_ago(1),
           'password_last_changed': days_ago(18), 'password_next_rotation': 'N/A', 'mfa_active': 'true',
           'cert_1_active': 'false', 'cert_1_last_rotated': 'N/A', 'cert_2_active': 'false', 'cert_2_last_rotated': 'N/A'}
    for n in (1, 2):
        row.update({f'access_key_{n}_active': 'false', f'access_key_{n}_last_rotated': 'N/A',
                    f'access_key_{n}_last_used_date': 'N/A', f'access_key_{n}_last_used_region': 'N/A',
                    f'access_key_{n}_last_used_service': 'N/A'})
    row.update(changes)
    stream = io.StringIO(); writer = csv.DictWriter(stream, fieldnames=list(row)); writer.writeheader(); writer.writerow(row)
    return stream.getvalue().encode()


class Native:
    def __init__(self, monkeypatch):
        # SDK responses below are dated at NOW. Capture on that same timeline
        # so native report reads and the scan clock describe one interval.
        original_init = aws.Requests.__init__
        def captured_init(requests, *args, **kwargs):
            original_init(requests, *args, **kwargs)
            requests.observed_at = NOW
        monkeypatch.setattr(aws.Requests, '__init__', captured_init)
        self.session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
        self.clients, self.stubs, self.calls, self.native, self.attempts = {}, {}, [], [], []
        monkeypatch.setattr(aws, '_session', lambda auth, region: (self.session, 'inert'))
        monkeypatch.setattr(aws.Requests, 'client', lambda requests, selected, service, region: self.clients[service])
        self.add('sts', 'get_caller_identity', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'inert'})

    def stub(self, service):
        if service not in self.clients:
            client = self.clients[service] = self.session.client(service, region_name=REGION)
            original = client._make_api_call
            def read_only(operation, arguments):
                self.calls.append((service, operation))
                self.attempts.append((service, operation, copy.deepcopy(arguments)))
                assert operation.startswith(('Get', 'List', 'Describe')) or (service == 'iam' and operation in {'GenerateCredentialReport', 'GenerateServiceLastAccessedDetails'}), 'non-read operation: '+operation
                return original(operation, arguments)
            client._make_api_call = read_only
            self.stubs[service] = Stubber(client)
            self.stubs[service].activate()
        return self.stubs[service]

    def add(self, service, operation, response=None, arguments=None, error=None):
        stub = self.stub(service)
        args = {} if arguments is None else arguments
        self.native.append({'service': service, 'operation': operation, 'arguments': copy.deepcopy(args),
                            'response': copy.deepcopy(response), 'error': error})
        if error: stub.add_client_error(operation, service_error_code=error, expected_params=args)
        else: stub.add_response(operation, response, args)

    def iam(self, response=None, *, denied=False, mfa=True, login=True, keys=False, paginate=True, reports=None):
        if denied:
            self.add('iam', 'get_account_authorization_details', error='AccessDenied')
            return
        response = gaad() if response is None else copy.deepcopy(response)
        if paginate:
            self.add('iam', 'get_account_authorization_details', {'IsTruncated': True, 'Marker': 'next-page', 'UserDetailList': [], 'GroupDetailList': [], 'RoleDetailList': [], 'Policies': []})
        self.add('iam', 'get_account_authorization_details', response, {'Marker': 'next-page'} if paginate else {})
        for user in response.get('UserDetailList', []):
            name = user['UserName']; args = {'UserName': name}
            key_rows = [{'AccessKeyId': 'AKIA'+'A'*16, 'UserName': name, 'Status': 'Active', 'CreateDate': NOW}] if keys else []
            self.add('iam', 'list_access_keys', {'AccessKeyMetadata': key_rows, 'IsTruncated': False}, args)
            if keys: self.add('iam', 'get_access_key_last_used', {'UserName': name, 'AccessKeyLastUsed': {'LastUsedDate': NOW, 'ServiceName': 's3', 'Region': REGION}}, {'AccessKeyId': key_rows[0]['AccessKeyId']})
            if login: self.add('iam', 'get_login_profile', {'LoginProfile': {'UserName': name, 'CreateDate': NOW, 'PasswordResetRequired': False}}, args)
            else: self.add('iam', 'get_login_profile', error='NoSuchEntity', arguments=args)
            self.add('iam', 'list_mfa_devices', {'MFADevices': [{'UserName': name, 'SerialNumber': 'GAHT'+'1'*12, 'EnableDate': NOW}] if mfa else [], 'IsTruncated': False}, args)
            if reports is not None: self.report(user['Arn'], reports, 1)
        if reports is not None:
            for role in response.get('RoleDetailList', []): self.report(role['Arn'], reports, 2)

    def report(self, arn, state, number):
        job = '11111111-1111-1111-1111-'+str(number).zfill(12)
        if state == 'reused_job': job = '11111111-1111-1111-1111-111111111111'
        if state == 'generate_denied':
            self.add('iam', 'generate_service_last_accessed_details', arguments={'Arn': arn, 'Granularity': 'SERVICE_LEVEL'}, error='AccessDenied')
            return
        self.add('iam', 'generate_service_last_accessed_details', {'JobId': job}, {'Arn': arn, 'Granularity': 'SERVICE_LEVEL'})
        if state == 'reused_job' and number == 2: return
        if state == 'read_denied':
            self.add('iam', 'get_service_last_accessed_details', arguments={'JobId': job}, error='AccessDenied')
            return
        if state == 'failed':
            self.add('iam', 'get_service_last_accessed_details', {'JobStatus': 'FAILED', 'JobType': 'SERVICE_LEVEL', 'JobCreationDate': NOW, 'JobCompletionDate': NOW,
                'ServicesLastAccessed': [], 'IsTruncated': False}, {'JobId': job})
            return
        if state == 'poll_timeout':
            self.add('iam', 'get_service_last_accessed_details', {'JobStatus': 'IN_PROGRESS', 'JobType': 'SERVICE_LEVEL',
                'JobCreationDate': NOW, 'JobCompletionDate': NOW, 'ServicesLastAccessed': [], 'IsTruncated': False}, {'JobId': job})
            return
        if state == 'poll_once':
            self.add('iam', 'get_service_last_accessed_details', {'JobStatus': 'IN_PROGRESS', 'JobType': 'SERVICE_LEVEL', 'JobCreationDate': NOW, 'JobCompletionDate': NOW,
                'ServicesLastAccessed': [], 'IsTruncated': False}, {'JobId': job})
        services = [{'ServiceNamespace': namespace, 'ServiceName': namespace, 'LastAuthenticated':
                     datetime(2025, 1, 1, tzinfo=timezone.utc) if state == 'old' else NOW,
                     'LastAuthenticatedRegion': REGION, 'TotalAuthenticatedEntities': 1} for namespace in ('bedrock', 'sagemaker')]
        if state == 'future_authenticated':
            for entry in services: entry['LastAuthenticated'] = NOW + timedelta(days=1)
        common = {'JobStatus': 'COMPLETED', 'JobType': 'ACTION_LEVEL' if state == 'wrong_type' else 'SERVICE_LEVEL',
            'JobCreationDate': NOW, 'JobCompletionDate': NOW, 'IsTruncated': False}
        if state in ('paginated', 'repeat_cursor', 'changed_dates', 'partial_page'):
            self.add('iam', 'get_service_last_accessed_details', {**common, 'ServicesLastAccessed': services[:1], 'IsTruncated': True, 'Marker': 'next'}, {'JobId': job})
            if state == 'partial_page': return
            second = {**common, 'ServicesLastAccessed': services[1:]}
            if state == 'repeat_cursor': second.update(IsTruncated=True, Marker='next')
            if state == 'changed_dates': second['JobCreationDate'] = datetime(2025, 1, 1, tzinfo=timezone.utc)
            self.add('iam', 'get_service_last_accessed_details', second, {'JobId': job, 'Marker': 'next'})
        else:
            self.add('iam', 'get_service_last_accessed_details', {**common, 'ServicesLastAccessed': services}, {'JobId': job})

    def collect(self, kinds, *, options=None):
        result = aws.collect({'provider': 'aws', 'scopes': [SCOPE], 'options': {'service_concurrency': 1,
            'scope_concurrency': 1, 'region_concurrency': 1, 'retry_attempts': 1, **(options or {})}}, list(kinds))
        for stub in self.stubs.values(): stub.assert_no_pending_responses()
        assert all(op.startswith(('Get', 'List', 'Describe')) or (service == 'iam' and op in {'GenerateCredentialReport', 'GenerateServiceLastAccessedDetails'}) for service, op in self.calls)
        if not (options or {}).get('_iam_report_generation_requested'):
            assert result['metadata']['authorized_evidence_generation']['generation_requests'] == 0
        return result

    def close(self):
        for stub in self.stubs.values(): stub.deactivate()


@pytest.fixture
def native(monkeypatch):
    value = Native(monkeypatch)
    yield value
    value.close()


def evaluate(snapshot, ids, scenario, native):
    result = engine.evaluate_snapshot(snapshot, checks=list(ids))
    findings = [f for f in result['findings'] if f['check_id'] in ids]
    return {cid: [f['status'] for f in findings if f['check_id'] == cid] for cid in ids}


def test_public_native_usage_generation_disabled(native):
    native.iam(gaad(action=['bedrock:InvokeModel', 'sagemaker:InvokeEndpoint']), keys=True)
    snapshot = native.collect(IAM_KINDS)
    statuses = evaluate(snapshot, SERVICE_USAGE_IDS, 'service_usage_unavailable', native)
    assert all(statuses[cid] == ['UNKNOWN'] for cid in SERVICE_USAGE_IDS)
    for collection in snapshot['collections']:
        if collection['type'] in ('iam_user', 'iam_role'):
            for row in collection['items']:
                assert 'ServicesLastAccessed' not in row
                assert row['ServicesLastAccessedStatus']['error']['code'] == 'service_last_accessed_generation_disabled'


@pytest.mark.parametrize('kind,cid', [('iam_policy', 'aws.claude_a.iam.custom_policy_no_service_wildcard'),
    ('iam_user', 'aws.claude_a.iam.user_inline_no_admin'), ('iam_role', 'aws.claude_a.iam.role_inline_no_admin'),
    ('iam_group', 'aws.claude_a.iam.group_inline_no_admin')])
def test_public_foreign_gaad_identity_current_behavior(native, kind, cid):
    native.iam(gaad(account=FOREIGN))
    snapshot = native.collect(IAM_KINDS)
    collection = next(c for c in snapshot['collections'] if c['type'] == kind)
    assert collection['status'] == 'malformed' and collection['items'] == []
    status = evaluate(snapshot, [cid], 'foreign_gaad_'+kind, native)[cid]
    assert status == ['UNKNOWN']  # Foreign identity cannot become local compliance evidence.


# One literal-policy example covers native decoding/default selection across
# these shared consumers; it does not establish effective permissions.
POLICY_DOCUMENT_IDS = [cid for cid in IAM_IDS if REGISTRY[cid].kind == 'iam_policy' and REGISTRY[cid].target == 'resource' and any(token in cid for token in (
    'no_star_star', 'custom_policy_kms_decrypt', 'custom_policy_no_', 'custom_unattached_policy_no_',
    'prowler_aws_attached_policy_no_admin', 'prowler_customer_', 'prowler_policy_'))]
INLINE_DOCUMENT_IDS = [cid for cid in IAM_IDS if '_inline_' in cid and not cid.endswith('no_inline_policies')]
DOCUMENT_IDS = sorted(set(POLICY_DOCUMENT_IDS + INLINE_DOCUMENT_IDS))
UNSAFE_ACTIONS = ['*', 'cloudtrail:*', 'kms:*', 'kms:Decrypt', 'aws-marketplace:Subscribe',
                  'sts:AssumeRole', 'bedrock-agentcore:GetWorkloadAccessToken', 'iam:PassRole']


@pytest.mark.parametrize('cid', DOCUMENT_IDS)
@pytest.mark.parametrize('state,expected', [('safe', 'PASS'), ('unsafe', 'FAIL'), ('missing', 'UNKNOWN'), ('mismatch', 'UNKNOWN'), ('denied', 'DENIED')])
def test_public_gaad_policy_document_contract(monkeypatch, cid, state, expected):
    native = Native(monkeypatch)
    try:
        body = gaad(UNSAFE_ACTIONS if state == 'unsafe' else 's3:GetObject',
                    attached='unattached' not in cid, version='missing' if state == 'missing' else 'mismatch' if state == 'mismatch' else 'valid')
        if 'prowler_aws_attached' in cid:
            body['Policies'][0]['Arn'] = 'arn:aws:iam::aws:policy/review'
        if REGISTRY[cid].kind != 'iam_policy' and state in ('missing', 'mismatch'):
            # Inline policies have no version selector: malformed/missing policy
            # text is the unavailable branch; GAAD policy-version mismatch is separate.
            key = {'iam_user': 'User', 'iam_group': 'Group', 'iam_role': 'Role'}[REGISTRY[cid].kind]
            body[key+'DetailList'][0][key+'PolicyList'][0]['PolicyDocument'] = quote(json.dumps({}))
        native.iam(body, denied=state == 'denied')
        snapshot = native.collect(IAM_KINDS)
        statuses = evaluate(snapshot, [cid], 'document_'+state+'_'+cid, native)
        assert statuses[cid] == [expected]
    finally:
        native.close()


ATTACHMENT_CASES = [
 ('aws.claude_a.iam.custom_policy_attached_to_role', True),
 ('aws.claude_a.iam.policy_in_use', True), ('aws.claude_a.iam.custom_policy_in_use', True),
 ('aws.claude_a.iam.aws_managed_policy_attached_to_role', True),
 ('aws.pci.iam.policy_attached_to_active_principal', True),
 ('aws.claude_a.iam.cloudshell_full_access_not_attached', False),
 ('aws.claude_a.iam.securityaudit_role_exists', True), ('aws.claude_a.iam.support_role_exists', True),
] + [(cid, False) for cid in IAM_IDS if cid.endswith(('_no_inline_policies','_no_cloudshell_full_access','_no_administratoraccess','role_no_administrator_access'))]


@pytest.mark.parametrize('cid,wants_attachment', ATTACHMENT_CASES)
@pytest.mark.parametrize('configured', [False, True])
def test_public_gaad_native_attachments_and_membership(monkeypatch, cid, wants_attachment, configured):
    native = Native(monkeypatch)
    try:
        body = gaad(attached=configured, inline=configured)
        suffix = cid.split('.')[-1]
        name = ('AWSCloudShellFullAccess' if 'cloudshell' in suffix else
                'SecurityAudit' if 'securityaudit' in suffix else 'AWSSupportAccess' if 'support_role' in suffix else
                'AdministratorAccess' if 'administrator' in suffix else 'review')
        if name != 'review' or 'aws_managed_policy' in cid:
            policy_arn = 'arn:aws:iam::aws:policy/'+name
            body['Policies'][0]['Arn'] = policy_arn
            for key in ('UserDetailList', 'GroupDetailList', 'RoleDetailList'):
                for row in body[key]:
                    row['AttachedManagedPolicies'] = [{'PolicyArn': policy_arn, 'PolicyName': name}] if configured else []
        native.iam(body)
        statuses = evaluate(native.collect(IAM_KINDS), [cid], 'attachment_'+str(configured)+'_'+cid, native)
        assert statuses[cid] == ['PASS' if configured == wants_attachment else 'FAIL']
    finally:
        native.close()

CREDENTIAL_IDS = [cid for cid in INPUT_IDS if REGISTRY[cid].kind == 'iam_credential_report']
CREDENTIAL_ORDINARY = [cid for cid in CREDENTIAL_IDS if not cid.endswith(('console_key_created_at_setup', 'prowler_root_hardware_mfa'))]


def credential_changes(cid, unsafe):
    old, recent = days_ago(700), days_ago(1)
    changes = {}
    if cid.endswith(('report_all_mfa', 'report_console_mfa', 'root_mfa')):
        changes['mfa_active'] = 'false' if unsafe else 'true'
    if 'root_' in cid or cid.endswith('root_mfa'):
        changes.update(user='<root_account>', arn=f'arn:aws:iam::{ACCOUNT}:root')
    if 'unused_credentials' in cid or 'console_password_used' in cid:
        changes.update(password_last_used=old if unsafe else recent, password_last_changed=old if unsafe else recent)
    if 'access_keys_rotated' in cid:
        changes.update(access_key_1_active='true', access_key_1_last_rotated=old if unsafe else recent)
    if 'access_keys_used' in cid or 'active_keys_used' in cid:
        changes.update(access_key_1_active='true', access_key_1_last_used_date=old if unsafe else recent,
                       access_key_1_last_rotated=old if unsafe else recent)
    if 'no_unused_initial' in cid:
        changes.update(access_key_1_active='true', access_key_1_last_used_date='N/A' if unsafe else recent)
    if 'not_two_active' in cid:
        changes.update(access_key_1_active='true', access_key_2_active='true' if unsafe else 'false')
    if 'root_not_used' in cid:
        changes.update(password_last_used=recent if unsafe else old)
    return changes


@pytest.mark.parametrize('cid', CREDENTIAL_ORDINARY)
@pytest.mark.parametrize('state', ['safe', 'unsafe', 'denied', 'not_present', 'malformed_flag'])
def test_public_credential_csv_field_contract(native, cid, state):
    args = credential_changes(cid, state == 'unsafe')
    if state == 'malformed_flag':
        args.update(password_enabled='malformed', mfa_active='malformed', access_key_1_active='malformed', access_key_2_active='malformed')
    native.add('iam', 'get_credential_report', {'Content': csv_content(**args), 'ReportFormat': 'text/csv', 'GeneratedTime': NOW} if state not in ('denied', 'not_present') else None,
               error='AccessDenied' if state == 'denied' else 'ReportNotPresent' if state == 'not_present' else None)
    snapshot = native.collect(['iam_credential_report'])
    statuses = evaluate(snapshot, [cid], 'credential_'+state+'_'+cid, native)
    if state == 'safe': expected = 'PASS'
    elif state == 'unsafe': expected = 'FAIL'
    elif state == 'denied': expected = 'DENIED'
    else: expected = 'UNKNOWN'
    # Root-use checks consume dates, not credential enablement/MFA booleans.
    if state == 'malformed_flag' and 'root_not_used' in cid: expected = 'PASS'
    assert statuses[cid] == [expected]
    if state in ('safe', 'unsafe'):
        row = next(c for c in snapshot['collections'] if c['type'] == 'iam_credential_report')['items'][0]
        assert row['ReportGeneratedTime'] == NOW.isoformat()
        assert row['arn'] == args.get('arn', f'arn:aws:iam::{ACCOUNT}:user/review')


@pytest.mark.parametrize('configured', [False, True])
def test_public_credential_rotation_does_not_invent_setup_creation(native, configured):
    native.add('iam', 'get_credential_report', {'Content': csv_content(access_key_1_active='true' if configured else 'false',
        access_key_1_last_rotated=days_ago(18) if configured else 'N/A'), 'ReportFormat': 'text/csv', 'GeneratedTime': NOW})
    cid = 'aws.a.iam.console_key_created_at_setup'
    statuses = evaluate(native.collect(['iam_credential_report']), [cid], 'credential_setup_'+str(configured), native)
    assert statuses[cid] == ['UNKNOWN' if configured else 'PASS']


SUMMARY_IDS = [cid for cid in INPUT_IDS if REGISTRY[cid].kind == 'iam_account_summary']


@pytest.mark.parametrize('cid', SUMMARY_IDS+['aws.claude_a.iam.prowler_root_hardware_mfa'])
@pytest.mark.parametrize('state', ['safe', 'unsafe', 'denied'])
def test_public_native_root_mfa_joins(native, cid, state):
    native.add('iam', 'get_account_summary', {'SummaryMap': {'AccountMFAEnabled': 0 if state == 'unsafe' else 1, 'AccountPasswordPresent': 1}}, error='AccessDenied' if state == 'denied' else None)
    kinds = ['iam_account_summary', 'iam_virtual_mfa_device']
    if REGISTRY[cid].kind == 'iam_credential_report':
        native.add('iam', 'get_credential_report', {'Content': csv_content(user='<root_account>', arn=f'arn:aws:iam::{ACCOUNT}:root'), 'ReportFormat': 'text/csv', 'GeneratedTime': NOW})
        kinds.append('iam_credential_report')
    native.add('iam', 'list_virtual_mfa_devices', {'VirtualMFADevices': [], 'IsTruncated': False})
    statuses = evaluate(native.collect(kinds), [cid], 'root_mfa_'+state+'_'+cid, native)
    expected = 'PASS' if state == 'safe' else 'FAIL' if state == 'unsafe' else ('UNKNOWN' if REGISTRY[cid].kind == 'iam_credential_report' else 'DENIED')
    assert statuses[cid] == [expected]


ANALYZER_IDS = ['aws.a.accessanalyzer.region_present', 'aws.a.accessanalyzer.region_active']


def test_public_analyzer_checks_never_contact_live_access_analyzer(native):
    # 88f12bec banned every live IAM Access Analyzer read in scans. Without a
    # saved analyzer result both analyzer checks stay UNKNOWN (never PASS),
    # and no Access Analyzer client or operation is ever used.
    snapshot = native.collect(['access_analyzer'])
    statuses = evaluate(snapshot, ANALYZER_IDS, 'analyzer_live_api_banned', native)
    assert statuses == {cid: ['UNKNOWN'] for cid in ANALYZER_IDS}
    assert 'accessanalyzer' not in native.clients
    assert not any(service == 'accessanalyzer' for service, operation in native.calls)
    assert all(c['status'] != 'collected' for c in snapshot['collections'] if c['type'] == 'access_analyzer')


@pytest.mark.parametrize('state', ['present', 'absent', 'denied', 'malformed'])
def test_public_account_configuration_contact_alias(native, state):
    cid = 'aws.a.account.security_contact_present'
    contact = {'AlternateContact': {'AlternateContactType': 'SECURITY', 'Name': 'inert', 'EmailAddress': 'inert@example.invalid',
            'PhoneNumber': '+12025550100', 'Title': 'inert'}}
    if state == 'malformed': contact = {}
    native.add('account', 'get_alternate_contact', contact if state in ('present', 'malformed') else None,
        {'AlternateContactType': 'SECURITY'}, error='AccessDeniedException' if state == 'denied' else 'ResourceNotFoundException' if state == 'absent' else None)
    native.add('organizations', 'describe_organization', {'Organization': {'Id': 'o-example1234', 'MasterAccountId': ACCOUNT}})
    snapshot = native.collect(['aws_account_configuration'])
    statuses = evaluate(snapshot, [cid], 'account_contact_'+state, native)
    assert statuses[cid] == [{'present': 'PASS', 'absent': 'FAIL', 'denied': 'UNKNOWN', 'malformed': 'UNKNOWN'}[state]]
    assert 'inert@example.invalid' not in json.dumps(snapshot)

AGGREGATE_IDS = [cid for cid in IAM_IDS if REGISTRY[cid].dependencies == ['iam_customer_policy']]


@pytest.mark.parametrize('state', ['safe', 'unsafe', 'denied', 'mismatch', 'foreign', 'missing_document'])
def test_public_customer_default_policy_universe(native, state):
    arn = f'arn:aws:iam::{FOREIGN if state == "foreign" else ACCOUNT}:policy/review'
    row = {'Arn': arn, 'PolicyName': 'review', 'DefaultVersionId': 'v3', 'AttachmentCount': 0}
    args = {'Scope': 'Local', 'OnlyAttached': False}
    if state == 'denied':
        native.add('iam', 'list_policies', arguments=args, error='AccessDenied')
    else:
        native.add('iam', 'list_policies', {'Policies': [], 'IsTruncated': True, 'Marker': 'next'}, args)
        native.add('iam', 'list_policies', {'Policies': [row], 'IsTruncated': False}, {**args, 'Marker': 'next'})
        if state != 'foreign':
            version = {'VersionId': 'v2' if state == 'mismatch' else 'v3', 'IsDefaultVersion': True}
            if state != 'missing_document': version['Document'] = quote(json.dumps(document('*' if state == 'unsafe' else 's3:GetObject')))
            native.add('iam', 'get_policy_version', {'PolicyVersion': version}, {'PolicyArn': arn, 'VersionId': 'v3'})
    statuses = evaluate(native.collect(['iam_customer_policy']), AGGREGATE_IDS, 'customer_default_'+state, native)
    expected = 'PASS' if state == 'safe' else 'FAIL' if state == 'unsafe' else 'DENIED' if state == 'denied' else 'UNKNOWN'
    for cid in AGGREGATE_IDS: assert statuses[cid] == [expected]


TRUST_IDS = [cid for cid in IAM_IDS if cid.endswith(('role_trust_not_public', 'restrict_public_trust',
    'role_readonly_not_cross_account', 'role_confused_deputy_prevented', 'role_service_trust_bound_to_account', 'role_used_within_60_days'))]


@pytest.mark.parametrize('cid', TRUST_IDS)
@pytest.mark.parametrize('unsafe', [False, True])
def test_public_role_trust_and_last_used(native, cid, unsafe):
    service = 'confused_deputy' in cid or 'service_trust' in cid
    body = gaad(trust='service' if service else 'foreign' if unsafe and 'readonly' in cid else 'public' if unsafe else 'own')
    role = body['RoleDetailList'][0]
    if 'readonly' in cid:
        role['AttachedManagedPolicies'] = [{'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess', 'PolicyName': 'ReadOnlyAccess'}]
    if service:
        trust = json.loads(__import__('urllib.parse', fromlist=['unquote']).unquote(role['AssumeRolePolicyDocument']))
        if not unsafe: trust['Statement'][0]['Condition'] = {'StringEquals': {'aws:SourceAccount': ACCOUNT}}
        elif 'service_trust' in cid: trust['Statement'][0]['Condition'] = {'StringEquals': {'aws:SourceIp': '192.0.2.1'}}
        role['AssumeRolePolicyDocument'] = quote(json.dumps(trust))
    if 'role_used' in cid:
        role['CreateDate'] = NOW - timedelta(days=90)
        role['RoleLastUsed']['LastUsedDate'] = NOW - timedelta(days=75) if unsafe else NOW
    native.iam(body)
    assert evaluate(native.collect(IAM_KINDS), [cid], 'role_'+str(unsafe)+'_'+cid, native)[cid] == ['FAIL' if unsafe else 'PASS']


@pytest.mark.parametrize('cid', ['aws.claude_a.iam.admin_user_has_mfa', 'aws.claude_a.iam.prowler_user_hardware_mfa', 'aws.c2b.bedrock.role_no_full_access_policy'])
@pytest.mark.parametrize('unsafe', [False, True])
def test_public_principal_mfa_and_managed_attachment(native, cid, unsafe):
    body = gaad()
    if 'admin_user' in cid:
        body['UserDetailList'][0]['AttachedManagedPolicies'] = [{'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess', 'PolicyName': 'AdministratorAccess'}]
    if 'bedrock' in cid:
        body['RoleDetailList'][0]['AttachedManagedPolicies'] = [{'PolicyArn': 'arn:aws:iam::aws:policy/'+('AmazonBedrockFullAccess' if unsafe else 'ReadOnlyAccess'), 'PolicyName': 'review'}]
    native.iam(body, mfa=not unsafe)
    assert evaluate(native.collect(IAM_KINDS), [cid], 'principal_'+str(unsafe)+'_'+cid, native)[cid] == ['FAIL' if unsafe else 'PASS']


@pytest.mark.parametrize('unsafe', [False, True])
def test_public_nonconsole_admin_policy_mfa_condition(native, unsafe):
    body = gaad('*')
    doc = document('*')
    if not unsafe: doc['Statement'][0]['Condition'] = {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}
    body['Policies'][0]['PolicyVersionList'][0]['Document'] = quote(json.dumps(doc))
    native.iam(body)
    cid = 'aws.pci.iam.nonconsole_mfa_policy'
    assert evaluate(native.collect(IAM_KINDS), [cid], 'nonconsole_mfa_'+str(unsafe), native)[cid] == ['FAIL' if unsafe else 'PASS']


@pytest.mark.parametrize('unsafe', [False, True])
def test_public_admin_group_membership_csv_mfa_join(native, unsafe):
    body = gaad()
    body['GroupDetailList'][0]['AttachedManagedPolicies'] = [{'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess', 'PolicyName': 'AdministratorAccess'}]
    native.iam(body)
    native.add('iam', 'get_credential_report', {'Content': csv_content(mfa_active='false' if unsafe else 'true'), 'ReportFormat': 'text/csv', 'GeneratedTime': NOW})
    cid = 'aws.claude_a.iam.prowler_admin_group_members_mfa'
    assert evaluate(native.collect(IAM_KINDS|{'iam_credential_report'}), [cid], 'group_report_mfa_'+str(unsafe), native)[cid] == ['FAIL' if unsafe else 'PASS']

@pytest.mark.parametrize('state', ['recent', 'old', 'poll_once', 'paginated', 'generate_denied', 'read_denied',
                                  'failed', 'wrong_type', 'repeat_cursor', 'changed_dates', 'partial_page', 'reused_job', 'future_authenticated'])
def test_public_selected_service_access_reports(native, state):
    native.iam(gaad(action=['bedrock:InvokeModel', 'sagemaker:InvokeEndpoint']), keys=state == 'old',
               paginate=state != 'partial_page', reports=state)
    options = {'_iam_report_generation_requested': True, '_iam_service_access_reports_requested': True,
               '_iam_credential_report_generation_requested': False}
    if state == 'partial_page': options['max_pages'] = 1
    snapshot = native.collect(IAM_KINDS, options=options)
    statuses = evaluate(snapshot, SERVICE_USAGE_IDS, 'selected_service_'+state, native)
    for cid in SERVICE_USAGE_IDS:
        expected = 'PASS' if state in ('recent', 'poll_once', 'paginated') else 'FAIL' if state == 'old' else 'UNKNOWN'
        if state == 'reused_job' and '.user_' in cid: expected = 'PASS'
        assert statuses[cid] == [expected]
    assert snapshot['metadata']['authorized_evidence_generation']['generation_requests'] == 0
    if state == 'partial_page':
        assert not any(op == 'GetServiceLastAccessedDetails' and args.get('Marker') for service, op, args in native.attempts)
    if state != 'generate_denied':
        assert snapshot['metadata']['authorized_evidence_generation']['service_last_accessed_generation_requests'] == 2


@pytest.mark.parametrize('state', ['complete', 'poll_once', 'generate_denied', 'invalid_state', 'read_denied', 'report_denied'])
def test_public_selected_credential_report_fallback(native, state):
    native.add('iam', 'get_credential_report', error='AccessDenied' if state == 'report_denied' else 'ReportNotPresent')
    if state != 'report_denied':
        if state == 'generate_denied': native.add('iam', 'generate_credential_report', error='AccessDenied')
        else:
            if state == 'poll_once': native.add('iam', 'generate_credential_report', {'State': 'STARTED'})
            native.add('iam', 'generate_credential_report', {'State': 'FUTURE' if state == 'invalid_state' else 'COMPLETE'})
            if state != 'invalid_state':
                native.add('iam', 'get_credential_report', {'Content': csv_content(), 'ReportFormat': 'text/csv', 'GeneratedTime': NOW}
                           if state != 'read_denied' else None, error='AccessDenied' if state == 'read_denied' else None)
    options = {'_iam_report_generation_requested': True, '_iam_service_access_reports_requested': False,
               '_iam_credential_report_generation_requested': True}
    cid = 'aws.a.iam.report_all_mfa'
    snapshot = native.collect(['iam_credential_report'], options=options)
    statuses = evaluate(snapshot, [cid], 'selected_credential_'+state, native)
    assert statuses[cid] == ['PASS' if state in ('complete', 'poll_once') else 'UNKNOWN' if state == 'invalid_state' else 'DENIED']
    assert not any(op == 'GenerateServiceLastAccessedDetails' for service, op in native.calls)


@pytest.mark.parametrize('cid', ['aws.a.iam.report_all_mfa', 'aws.claude_a.iam.console_password_used_45'])
def test_public_foreign_credential_arn_is_not_relabelled(native, cid):
    native.add('iam', 'get_credential_report', {'Content': csv_content(arn=f'arn:aws:iam::{FOREIGN}:user/review'),
               'ReportFormat': 'text/csv', 'GeneratedTime': NOW})
    snapshot = native.collect(['iam_credential_report'])
    envelope = next(c for c in snapshot['collections'] if c['type'] == 'iam_credential_report')
    assert envelope['status'] == 'malformed' and envelope['items'] == []
    assert evaluate(snapshot, [cid], 'foreign_credential_'+cid, native)[cid] == ['UNKNOWN']

@pytest.mark.parametrize('state', ['distinct', 'duplicate', 'absent', 'denied'])
def test_public_account_contact_distinct_metadata(native, state):
    native.add('account', 'get_contact_information', {'ContactInformation': {'FullName': 'person0', 'PhoneNumber': '+12025550100',
        'AddressLine1': '1 Inert Street', 'City': 'Inert', 'CountryCode': 'US', 'PostalCode': '10001'}})
    for number, label in enumerate(('BILLING', 'OPERATIONS', 'SECURITY'), 1):
        args = {'AlternateContactType': label}
        if label == 'SECURITY' and state in ('denied', 'absent'):
            native.add('account', 'get_alternate_contact', arguments=args,
                       error='AccessDeniedException' if state == 'denied' else 'ResourceNotFoundException')
        else:
            native.add('account', 'get_alternate_contact', {'AlternateContact': {'AlternateContactType': label,
                'Name': 'person0' if state == 'duplicate' else 'person'+str(number), 'PhoneNumber': '+1202555010'+str(number),
                'EmailAddress': 'person'+str(number)+'@example.invalid', 'Title': 'inert'}}, args)
    cid = 'aws.gap.account.distinct_primary_billing_operations_security_contacts'
    snapshot = native.collect(['aws_account_contact_details'])
    assert evaluate(snapshot, [cid], 'account_distinct_'+state, native)[cid] == [{'distinct':'PASS', 'duplicate':'FAIL', 'absent':'FAIL', 'denied':'UNKNOWN'}[state]]
    assert not any(value in json.dumps(snapshot) for value in ('person0', '@example.invalid', '+12025550100', 'Inert Street'))

@pytest.mark.parametrize('service,operation,options', [
    ('iam','generate_service_last_accessed_details',{}), ('iam','generate_credential_report',{}),
    ('iam','generate_organizations_access_report',{'_iam_report_generation_requested':True}),
    ('kms','generate_random',{'_iam_report_generation_requested':True})])
def test_requests_generation_gate_is_exact_and_default_closed(native, service, operation, options):
    with pytest.raises(aws.ReadFailure, match='non_read_operation'):
        aws.Requests(options).call(native.session, service, REGION, operation)
    assert native.calls == []


@pytest.mark.parametrize('selection', ['mfa_only', 'service_usage', 'credential_report'])
def test_engine_selection_drives_only_required_native_report_family(native, selection):
    if selection == 'mfa_only':
        cid = 'aws.claude_a.iam.prowler_user_hardware_mfa'
        native.iam(gaad())
    elif selection == 'service_usage':
        cid = 'aws.claude_a.iam.user_bedrock_access_not_stale'
        body = gaad('bedrock:InvokeModel'); body['RoleDetailList'] = []
        native.iam(body, reports='recent')
    else:
        cid = 'aws.a.iam.report_all_mfa'
        native.add('iam','get_credential_report',error='ReportNotPresent')
        native.add('iam','generate_credential_report',{'State':'COMPLETE'})
        native.add('iam','get_credential_report',{'Content':csv_content(),'ReportFormat':'text/csv','GeneratedTime':NOW})
    snapshot = engine.collect_snapshot({'connector':{'provider':'aws','scopes':[SCOPE],
        'options':{'service_concurrency':1,'retry_attempts':1}},'checks':[cid]})
    for stub in native.stubs.values():stub.assert_no_pending_responses()
    assert evaluate(snapshot,[cid],'engine_selection_'+selection,native)[cid] == ['PASS']
    operations = [op for service,op in native.calls]
    assert ('GenerateServiceLastAccessedDetails' in operations) is (selection=='service_usage')
    assert ('GenerateCredentialReport' in operations) is (selection=='credential_report')


@pytest.mark.parametrize('family', ['service', 'credential'])
def test_public_selected_report_timeout_is_bounded(native, monkeypatch, family):
    from types import SimpleNamespace
    from peaso.collectors import aws_iam_report_native as reports
    clock = iter(range(30, 10000, 30))
    monkeypatch.setattr(reports, 'time', SimpleNamespace(monotonic=lambda: next(clock)))
    if family == 'service':
        body = gaad('bedrock:InvokeModel'); body['RoleDetailList'] = []
        native.iam(body, reports='poll_timeout')
        kinds, cid = ['iam_user'], 'aws.claude_a.iam.user_bedrock_access_not_stale'
    else:
        native.add('iam','get_credential_report',error='ReportNotPresent')
        native.add('iam','generate_credential_report',{'State':'STARTED'})
        kinds, cid = ['iam_credential_report'], 'aws.a.iam.report_all_mfa'
    snapshot = native.collect(kinds, options={'_iam_report_generation_requested':True,
        '_iam_service_access_reports_requested':family=='service', '_iam_credential_report_generation_requested':family=='credential'})
    assert evaluate(snapshot,[cid],'report_timeout_'+family,native)[cid] == ['UNKNOWN']
    assert sum(op.startswith('Generate') for service,op in native.calls) == 1


def test_public_selected_service_report_rejects_foreign_principal_before_generation(native):
    native.iam(gaad(action='bedrock:InvokeModel',account=FOREIGN))
    snapshot = native.collect(IAM_KINDS, options={'_iam_report_generation_requested':True,
        '_iam_service_access_reports_requested':True, '_iam_credential_report_generation_requested':False})
    assert not any(op.startswith('Generate') for service,op in native.calls)
    assert all(value==['UNKNOWN'] for value in evaluate(snapshot,SERVICE_USAGE_IDS,'foreign_report_principal',native).values())
