"""Bounded independent IAM SDK -> production projection -> registered callback probes.

Regression receipts describe current defects explicitly; PASS in a defect receipt
is the observed unsafe result, never a compliance expectation for malformed data.
No live AWS, mutations, credential-report generation, or secret payloads.
"""
import copy
import io
import csv
import json
from datetime import datetime, timezone
from urllib.parse import quote
import boto3
import pytest
from botocore.stub import Stubber
from peaso import engine
from peaso.collectors import aws

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
REGISTRY = {c.id: c for c in engine._registry()}
KINDS = {'iam_policy', 'iam_role', 'iam_user', 'iam_group', 'iam_credential_report', 'aws_account_configuration', 'aws_account'}
MANAGED = [cid for cid in REGISTRY if cid.startswith('aws.claude_a.iam.prowler_') and REGISTRY[cid].kind == 'iam_policy']
PASSWORD = [cid for cid in REGISTRY if cid.startswith('aws.a.iam.password_policy_')]

@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name=REGION)
    clients, stubs = {}, {}
    def stub(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service]); stubs[service].activate()
        return stubs[service]
    monkeypatch.setattr(aws.Requests, 'client', lambda self, selected, service, region: clients[service])
    yield aws.Requests({'retry_attempts': 1}), session, stub
    for value in stubs.values():
        value.assert_no_pending_responses(); value.deactivate()


def index(kind, read):
    rows = copy.deepcopy(read.items)
    for row in rows: row['AccountId'] = ACCOUNT
    return {'context': {'provider': 'aws', 'scope': SCOPE, 'Account': ACCOUNT, 'created_at': NOW.isoformat()},
            'collections': {kind: [{'type': kind, 'scope': ACCOUNT+'/global', 'account_id': ACCOUNT,
                                    'global': True, 'status': read.status, 'items': rows, 'error': read.error or {}}]},
            kind: [{'type': kind, 'scope': ACCOUNT+'/global', 'data': row} for row in rows]}


def policy_read(sdk, document, attached=1, denied=False):
    requests, session, stub = sdk
    api = stub('iam')
    if denied:
        api.add_client_error('get_account_authorization_details', service_error_code='AccessDenied', expected_params={})
    else:
        row = {'Arn': f'arn:aws:iam::{ACCOUNT}:policy/review', 'PolicyName': 'review', 'AttachmentCount': attached,
               'DefaultVersionId': 'v1', 'PolicyVersionList': [{'VersionId': 'v1', 'IsDefaultVersion': True,
                                                               'Document': quote(json.dumps(document))}]}
        api.add_response('get_account_authorization_details', {'Policies': [row], 'IsTruncated': False}, {})
    return aws._iam(requests, session, REGION, {'iam_policy'})['iam_policy']

@pytest.mark.parametrize('cid', MANAGED)
def test_managed_gaad_missing_statement_is_unknown(sdk, cid):
    attached = 0 if 'unattached' in cid else 1
    read = policy_read(sdk, {}, attached)
    item = read.items[0]
    if 'aws_attached' in cid: item['Arn'] = 'arn:aws:iam::aws:policy/review'
    assert item['PolicyVersionList'][0]['Document'] == {}
    assert REGISTRY[cid].evaluate(item, index('iam_policy', read))[0] == 'UNKNOWN'

@pytest.mark.parametrize('unsafe', [False, True])
@pytest.mark.parametrize('cid', ['aws.claude_a.iam.custom_policy_no_star_star', 'aws.claude_a.iam.prowler_customer_attached_policy_no_admin', 'aws.a.iam.attached_policy_no_star_star'])
def test_managed_gaad_decodes_and_reaches_consumer(sdk, cid, unsafe):
    read = policy_read(sdk, {'Statement': [{'Effect': 'Allow', 'Action': '*' if unsafe else 's3:GetObject', 'Resource': '*'}]})
    item = read.items[0]
    assert isinstance(item['PolicyVersionList'][0]['Document'], dict)
    assert REGISTRY[cid].evaluate(item, index('iam_policy', read))[0] == ('FAIL' if unsafe else 'PASS')


def test_gaad_denied_has_no_policy_evidence(sdk):
    read = policy_read(sdk, {}, denied=True)
    assert read.status == 'denied' and read.items == []
    for cid in MANAGED:
        assert REGISTRY[cid].evaluate({}, index('iam_policy', read))[0] == 'UNKNOWN'

@pytest.mark.parametrize('cid', PASSWORD)
@pytest.mark.parametrize('state', ['good', 'absent', 'denied', 'missing'])
def test_password_sdk_scope_join(sdk, cid, state):
    requests, session, stub = sdk
    api = stub('iam')
    if state in ('absent', 'denied'):
        api.add_client_error('get_account_password_policy', service_error_code='NoSuchEntity' if state == 'absent' else 'AccessDenied', expected_params={})
    else:
        policy = {'MinimumPasswordLength': 14, 'RequireSymbols': True, 'RequireNumbers': True,
                  'RequireUppercaseCharacters': True, 'RequireLowercaseCharacters': True,
                  'PasswordReusePrevention': 24, 'MaxPasswordAge': 90}
        api.add_response('get_account_password_policy', {'PasswordPolicy': policy if state == 'good' else {}}, {})
    read = aws._single(requests, session, REGION, 'iam', 'get_account_password_policy', absent=('NoSuchEntity',))
    status = REGISTRY[cid].evaluate({'scope': SCOPE}, index('iam_password_policy', read))[0]
    assert status == {'good': 'PASS', 'absent': 'FAIL', 'denied': 'UNKNOWN', 'missing': 'UNKNOWN'}[state]


def credential_read(sdk, **changes):
    requests, session, stub = sdk
    row = {'user': 'alice', 'arn': f'arn:aws:iam::{ACCOUNT}:user/alice', 'user_creation_time': '2026-10-01T00:00:00+00:00',
           'password_enabled': 'true', 'mfa_active': 'true', 'password_last_used': '2026-10-18T00:00:00+00:00',
           'password_last_changed': '2026-10-01T00:00:00+00:00', 'password_next_rotation': 'N/A'}
    for n in (1, 2):
        row.update({f'access_key_{n}_active': 'false', f'access_key_{n}_last_rotated': 'N/A',
                    f'access_key_{n}_last_used_date': 'N/A', f'access_key_{n}_last_used_region': 'N/A', f'access_key_{n}_last_used_service': 'N/A'})
    row.update(changes)
    output = io.StringIO(); writer = csv.DictWriter(output, fieldnames=list(row)); writer.writeheader(); writer.writerow(row)
    stub('iam').add_response('get_credential_report', {'Content': output.getvalue().encode(), 'ReportFormat': 'text/csv', 'GeneratedTime': NOW}, {})
    return aws._credentials_report(requests, session, REGION)

@pytest.mark.parametrize('cid', ['aws.a.iam.report_console_mfa', 'aws.a.iam.report_all_mfa'])
@pytest.mark.parametrize('mfa,expected', [('true', 'PASS'), ('false', 'FAIL'), ('MALFORMED', 'UNKNOWN')])
def test_credential_csv_strict_mfa_consumer(sdk, cid, mfa, expected):
    read = credential_read(sdk, mfa_active=mfa)
    assert read.items[0]['ReportGeneratedTime'] == NOW.isoformat()
    assert REGISTRY[cid].evaluate(read.items[0], index('iam_credential_report', read))[0] == expected

@pytest.mark.parametrize('cid', ['aws.claude_a.iam.access_keys_rotated_90', 'aws.claude_a.iam.access_keys_used_45', 'aws.claude_a.iam.not_two_active_keys'])
def test_credential_invalid_active_flag_is_unknown(sdk, cid):
    read = credential_read(sdk, access_key_1_active='MALFORMED', access_key_2_active='MALFORMED')
    assert REGISTRY[cid].evaluate(read.items[0], index('iam_credential_report', read))[0] == 'UNKNOWN'

@pytest.mark.parametrize('code', ['ReportNotPresent', 'ReportExpired', 'ReportInProgress', 'AccessDenied'])
def test_credential_unavailable_never_generates(sdk, code):
    requests, session, stub = sdk
    stub('iam').add_client_error('get_credential_report', service_error_code=code, expected_params={})
    read = aws._credentials_report(requests, session, REGION)
    assert read.items == [] and read.status == ('denied' if code == 'AccessDenied' else 'not_collected')

@pytest.mark.parametrize('state', ['present', 'absent', 'denied'])
def test_account_sdk_presence_projection_and_consumers(sdk, state):
    requests, session, stub = sdk
    api, org = stub('account'), stub('organizations')
    if state == 'present':
        api.add_response('get_alternate_contact', {'AlternateContact': {'AlternateContactType': 'SECURITY', 'Name': 'synthetic', 'EmailAddress': 'synthetic@example.com', 'PhoneNumber': '+12025550100', 'Title': 'synthetic'}}, {'AlternateContactType': 'SECURITY'})
        org.add_response('describe_organization', {'Organization': {'Id': 'o-example1234', 'MasterAccountId': ACCOUNT}}, {})
    else:
        api.add_client_error('get_alternate_contact', service_error_code='AccessDeniedException' if state == 'denied' else 'ResourceNotFoundException', expected_params={'AlternateContactType': 'SECURITY'})
        org.add_client_error('describe_organization', service_error_code='AccessDeniedException' if state == 'denied' else 'AWSOrganizationsNotInUseException', expected_params={})
    read = aws._account_configuration(requests, session, REGION, {'Arn': f'arn:aws:iam::{ACCOUNT}:role/review'})
    assert 'synthetic' not in json.dumps(read.items)
    for cid in ('aws.a.account.security_contact_present', 'aws.a.account.organization_member'):
        assert REGISTRY[cid].evaluate(read.items[0], index('aws_account_configuration', read))[0] == {'present': 'PASS', 'absent': 'FAIL', 'denied': 'UNKNOWN'}[state]


@pytest.mark.parametrize('statement', [None, {}, {'Effect': 'invalid', 'Action': '*', 'Resource': '*'},
    {'Effect': 'Allow', 'Action': [None], 'Resource': '*'}, {'Effect': 'Allow', 'Action': '*'},
    {'Effect': 'Allow', 'Action': '*', 'NotAction': 's3:GetObject', 'Resource': '*'}])
@pytest.mark.parametrize('cid', [c for c in MANAGED if 'customer_attached' in c])
def test_malformed_identity_statement_unknown(sdk, statement, cid):
    read = policy_read(sdk, {'Statement': statement})
    assert REGISTRY[cid].evaluate(read.items[0], index('iam_policy', read))[0] == 'UNKNOWN'

@pytest.mark.parametrize('cid', MANAGED)
def test_empty_statement_list_is_preserved(sdk, cid):
    read = policy_read(sdk, {'Statement': []}, 0 if 'unattached' in cid else 1)
    item = read.items[0]
    if 'aws_attached' in cid: item['Arn'] = 'arn:aws:iam::aws:policy/review'
    assert REGISTRY[cid].evaluate(item, index('iam_policy', read))[0] == 'PASS'

@pytest.mark.parametrize('kind', ['iam_user', 'iam_role', 'iam_group'])
@pytest.mark.parametrize('unsafe', [False, True])
def test_inline_three_principal_sdk_shapes(sdk, kind, unsafe):
    requests, session, stub = sdk
    entity = kind.removeprefix('iam_')
    namekey, policykey, responsekey = { 'user': ('UserName', 'UserPolicyList', 'UserDetailList'),
        'group': ('GroupName', 'GroupPolicyList', 'GroupDetailList'), 'role': ('RoleName', 'RolePolicyList', 'RoleDetailList')}[entity]
    doc = {'Statement': [{'Effect': 'Allow', 'Action': '*' if unsafe else 's3:GetObject', 'Resource': '*'}]}
    row = {namekey: 'review', 'Arn': f'arn:aws:iam::{ACCOUNT}:{entity}/review',
           policykey: [{'PolicyName': 'review', 'PolicyDocument': quote(json.dumps(doc))}]}
    if entity == 'role': row['AssumeRolePolicyDocument'] = quote(json.dumps({'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))
    api = stub('iam'); api.add_response('get_account_authorization_details', {'IsTruncated': False, responsekey: [row]}, {})
    if entity == 'user':
        api.add_response('list_access_keys', {'AccessKeyMetadata': [], 'IsTruncated': False}, {'UserName': 'review'})
        api.add_client_error('get_login_profile', service_error_code='NoSuchEntity', expected_params={'UserName': 'review'})
        api.add_response('list_mfa_devices', {'MFADevices': [], 'IsTruncated': False}, {'UserName': 'review'})
    read = aws._iam(requests, session, REGION, {kind})[kind]
    item = read.items[0]
    assert item['AttachedManagedPolicies'] == []
    cid = f'aws.claude_a.iam.prowler_{entity}_inline_no_admin'
    assert REGISTRY[cid].evaluate(item, index(kind, read))[0] == ('FAIL' if unsafe else 'PASS')
    if entity in ('user', 'role'):
        assert 'ServicesLastAccessed' not in item
        assert item['ServicesLastAccessedStatus']['collection_status'] == 'not_collected'

@pytest.mark.parametrize('cid', ['aws.claude_a.iam.access_keys_rotated_90', 'aws.claude_a.iam.access_keys_used_45', 'aws.claude_a.iam.not_two_active_keys', 'aws.claude_a.iam.no_unused_initial_access_key'])
@pytest.mark.parametrize('state', ['no_keys', 'active_no_date', 'invalid_second'])
def test_active_flag_and_date_boundaries(sdk, cid, state):
    changes = {'no_keys': {}, 'active_no_date': {'access_key_1_active': 'true'},
               'invalid_second': {'access_key_2_active': 'N/A'}}[state]
    read = credential_read(sdk, **changes)
    expected = ('NOT_APPLICABLE' if state == 'no_keys' and cid.endswith('access_keys_used_45') else
                'UNKNOWN' if state == 'invalid_second' or (state == 'active_no_date' and cid.endswith(('rotated_90', 'used_45'))) else
                'FAIL' if state == 'active_no_date' and cid.endswith('initial_access_key') else 'PASS')
    assert REGISTRY[cid].evaluate(read.items[0], index('iam_credential_report', read))[0] == expected


def test_default_version_binding_rejects_contradiction(sdk):
    read = policy_read(sdk, {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]})
    item = read.items[0]; item['DefaultVersionId'] = 'v2'
    # The flagged version must agree with the selected native default version.
    assert REGISTRY['aws.claude_a.iam.custom_policy_no_star_star'].evaluate(item, index('iam_policy', read))[0] == 'UNKNOWN'

@pytest.mark.parametrize('partial', [False, True])
def test_gaad_pagination_cache_global_engine(sdk, partial):
    from peaso.snapshot import make_snapshot
    requests, session, stub = sdk
    api = stub('iam')
    row = {'Arn': f'arn:aws:iam::{ACCOUNT}:policy/review', 'PolicyName': 'review', 'AttachmentCount': 1,
           'DefaultVersionId': 'v1', 'PolicyVersionList': [{'VersionId': 'v1', 'IsDefaultVersion': True,
                'Document': quote(json.dumps({'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}))}]}
    api.add_response('get_account_authorization_details', {'Policies': [row], 'IsTruncated': True, 'Marker': 'next'}, {})
    if partial: requests.max_pages = 1
    else: api.add_response('get_account_authorization_details', {'Policies': [], 'IsTruncated': False}, {'Marker': 'next'})
    reads = aws._iam(requests, session, REGION, {'iam_policy', 'iam_group'})
    assert requests.calls == (1 if partial else 2)
    assert requests.cache_hits >= 1
    read = reads['iam_policy']
    assert read.status == ('partial' if partial else 'collected')
    env = index('iam_policy', read)['collections']['iam_policy'][0]
    snapshot = make_snapshot('aws', [SCOPE, ACCOUNT+'/eu-west-1'], [env], created_at=NOW.isoformat())
    cid = 'aws.claude_a.iam.prowler_customer_attached_policy_no_admin'
    findings = [r for r in engine.evaluate_snapshot(snapshot, checks=[cid])['findings'] if r['check_id'] == cid]
    native = [r for r in findings if r.get('native_resource_id') == row['Arn']]
    assert len(native) == 1
    assert native[0]['status'] == 'PASS'  # complete observed document; inventory coverage is separate
    assert all(r['status'] == 'UNKNOWN' for r in findings if r not in native)
    assert len(findings) == (2 if partial else 1)  # partial inventory notice plus native resource

@pytest.mark.parametrize('foreign', ['account', 'item_account'])
def test_global_identity_envelope_binding_rejects_foreign_provenance(sdk, foreign):
    from peaso.snapshot import make_snapshot
    read = policy_read(sdk, {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]})
    env = index('iam_policy', read)['collections']['iam_policy'][0]
    if foreign == 'account': env['account_id'] = '999999999999'
    else: env['items'][0]['AccountId'] = '999999999999'
    cid = 'aws.claude_a.iam.prowler_customer_attached_policy_no_admin'
    snapshot = make_snapshot('aws', [SCOPE], [env], created_at=NOW.isoformat())
    findings = [r for r in engine.evaluate_snapshot(snapshot, checks=[cid])['findings'] if r['check_id'] == cid]
    # The shared engine now refuses contradictory known global provenance.
    assert findings and all(r['status'] == 'UNKNOWN' for r in findings)

@pytest.mark.parametrize('cid', [cid for cid in REGISTRY if cid.startswith('aws.claude_a.iam.prowler_')])
def test_existing_prowler_truth_contract_regression_only(cid):
    # Replaying existing fixtures is regression evidence only, not SDK/source proof.
    from peaso.checks.fixtures import CASES
    cases = CASES[cid]
    for state, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('missing', 'UNKNOWN'), ('malformed', 'UNKNOWN')]:
        item = copy.deepcopy(cases[state])
        ix = copy.deepcopy(cases.get(state+'_index', cases.get('index', {})))
        assert REGISTRY[cid].evaluate(item, ix)[0] == expected, (cid, state)

@pytest.mark.parametrize('mutation', ['missing_default', 'missing_version_id', 'duplicate_version_id', 'two_defaults', 'wrong_default', 'invalid_flag'])
def test_gaad_default_version_integrity(sdk, mutation):
    read = policy_read(sdk, {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]})
    item = read.items[0]; versions = item['PolicyVersionList']
    if mutation == 'missing_default': item.pop('DefaultVersionId')
    elif mutation == 'missing_version_id': versions[0].pop('VersionId')
    elif mutation == 'duplicate_version_id': versions.append({**versions[0], 'IsDefaultVersion': False})
    elif mutation == 'two_defaults': versions.append({**versions[0], 'VersionId': 'v2'})
    elif mutation == 'wrong_default': item['DefaultVersionId'] = 'v2'
    else: versions[0]['IsDefaultVersion'] = 'true'
    for cid in ['aws.claude_a.iam.custom_policy_no_star_star', 'aws.claude_a.iam.prowler_customer_attached_policy_no_admin',
                'aws.a.iam.attached_policy_no_star_star']:
        assert REGISTRY[cid].evaluate(item, index('iam_policy', read))[0] == 'UNKNOWN'

@pytest.mark.parametrize('state', ['good', 'no_mfa', 'malformed', 'duplicate', 'missing_member'])
def test_admin_group_native_user_membership_and_csv_join(sdk, state):
    requests, session, stub = sdk
    group = {'GroupName': 'admins', 'Arn': f'arn:aws:iam::{ACCOUNT}:group/admins',
             'AttachedManagedPolicies': [{'PolicyName': 'AdministratorAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]}
    user = {'UserName': 'alice', 'Arn': f'arn:aws:iam::{ACCOUNT}:user/alice', 'GroupList': ['admins']}
    api = stub('iam')
    api.add_response('get_account_authorization_details', {'IsTruncated': False, 'UserDetailList': [user], 'GroupDetailList': [group]}, {})
    api.add_response('list_access_keys', {'AccessKeyMetadata': [], 'IsTruncated': False}, {'UserName': 'alice'})
    api.add_client_error('get_login_profile', service_error_code='NoSuchEntity', expected_params={'UserName': 'alice'})
    api.add_response('list_mfa_devices', {'MFADevices': [], 'IsTruncated': False}, {'UserName': 'alice'})
    reads = aws._iam(requests, session, REGION, {'iam_group', 'iam_user'})
    report = credential_read(sdk, mfa_active={'no_mfa': 'false', 'malformed': 'MALFORMED'}.get(state, 'true'))
    if state == 'duplicate': report.items.append({**report.items[0], 'mfa_active': 'false'})
    if state == 'missing_member': report.items[0]['user'] = 'other'
    ix = index('iam_group', reads['iam_group'])
    for kind, read in [('iam_user', reads['iam_user']), ('iam_credential_report', report)]:
        extra = index(kind, read); ix['collections'].update(extra['collections']); ix[kind] = extra[kind]
    cid = 'aws.claude_a.iam.prowler_admin_group_members_mfa'
    assert REGISTRY[cid].evaluate(reads['iam_group'].items[0], ix)[0] == {'good':'PASS','no_mfa':'FAIL','malformed':'UNKNOWN','duplicate':'UNKNOWN','missing_member':'UNKNOWN'}[state]

@pytest.mark.parametrize('cid,expected', [
    ('aws.a.iam.attached_policy_no_star_star', 'UNKNOWN'),
    ('aws.iam.no_full_admin', 'UNKNOWN'),
])
def test_other_default_version_helpers_review_disposition(sdk, cid, expected):
    read = policy_read(sdk, {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]})
    assert REGISTRY[cid].evaluate(read.items[0], index('iam_policy', read))[0] == 'PASS'
    item = read.items[0]; item['DefaultVersionId'] = 'v2'
    # Both reviewed helpers require the native selected default version.
    # A contradictory flag cannot prove the active managed policy is safe.
    assert REGISTRY[cid].evaluate(item, index('iam_policy', read))[0] == expected
