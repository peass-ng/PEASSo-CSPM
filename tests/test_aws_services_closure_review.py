"""Bounded, offline SDK-to-public-collector service closure review.

Responses are validated and served by botocore Stubber, never live AWS. These
cases prove only the named branches, not complete service semantics.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import threading

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
STAMP = datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.fixture
def pipeline(monkeypatch):
    """Real SDK clients and response validation, with every call stubbed locally."""
    session = boto3.Session(aws_access_key_id='offline', aws_secret_access_key='offline', region_name=REGION)
    original_requests = aws.Requests
    runs = []

    def collect(kind, responses):
        calls, clients = [], {}
        requests = original_requests({'retry_attempts': 1, 'max_workers': 1, 'max_calls': 300}, sleep=lambda _: None)
        requests.observed_at = STAMP
        native = {('sts', 'get_caller_identity'): {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/review', 'UserId': 'AIDAOFFLINEREVIEW'}, **responses}

        class Client:
            def __init__(self, service, region):
                self.service = service
                self.sdk = session.client(service, region_name=region)
                self.lock = threading.Lock()  # Stubber state is per client; collectors may use threads.
                self.meta = self.sdk.meta

            def can_paginate(self, operation):
                return False

            def __getattr__(self, operation):
                def call(**arguments):
                    calls.append((self.service, operation, deepcopy(arguments)))
                    response = native.get((self.service, operation))
                    if callable(response):
                        response = response(arguments)
                    with self.lock, Stubber(self.sdk) as stub:
                        if response is None:
                            stub.add_client_error(operation, service_error_code='AccessDeniedException', expected_params=arguments)
                        else:
                            stub.add_response(operation, deepcopy(response), arguments)
                        result = getattr(self.sdk, operation)(**arguments)
                        stub.assert_no_pending_responses()
                        return result
                return call

        def client(_session, service, region):
            if (service, region) not in clients:
                clients[service, region] = Client(service, region)
            return clients[service, region]

        requests.client = client
        monkeypatch.setattr(aws, 'Requests', lambda options: requests)
        monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'offline'))
        snapshot = aws.collect({'provider': 'aws', 'scopes': [SCOPE], 'options': {'regions': [REGION]}}, [kind] if isinstance(kind, str) else kind)
        runs.append((snapshot, calls))
        return snapshot, calls

    return collect


def item_of(snapshot, kind):
    rows = [row for envelope in snapshot['collections'] if envelope['type'] == kind for row in envelope['items']]
    assert len(rows) == 1
    return rows[0]


def verdict(snapshot, cid):
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid])['findings'] if row['check_id'] == cid]
    assert len(rows) == 1, rows
    return rows[0]['status']


@pytest.mark.parametrize('enabled,expected', [(True, 'PASS'), (False, 'FAIL'), (None, 'UNKNOWN')])
@pytest.mark.parametrize('kind,cid,operation,key,arnfield', [
    ('rds_instance', 'aws.b.rds_instance.minor_upgrade', 'describe_db_instances', 'DBInstances', 'DBInstanceArn'),
    ('rds_cluster', 'aws.b.rds_cluster.iam_authentication', 'describe_db_clusters', 'DBClusters', 'DBClusterArn'),
])
def test_rds_native_boolean_public_pipeline(pipeline, enabled, expected, kind, cid, operation, key, arnfield):
    field = 'AutoMinorVersionUpgrade' if kind == 'rds_instance' else 'IAMDatabaseAuthenticationEnabled'
    row = {arnfield: f'arn:aws:rds:{REGION}:{ACCOUNT}:' + ('db:example' if kind == 'rds_instance' else 'cluster:example'), 'Engine': 'postgres'}
    if enabled is not None:
        row[field] = enabled
    snapshot, calls = pipeline(kind, {('rds', operation): {key: [row]}})
    assert verdict(snapshot, cid) == expected
    assert item_of(snapshot, kind).get(field) == enabled


@pytest.mark.parametrize('enabled,expected', [(True, 'PASS'), (False, 'FAIL'), (None, 'UNKNOWN')])
def test_codebuild_native_configuration_public_pipeline(pipeline, enabled, expected):
    project = {'name': 'example', 'arn': f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/example',
               'environment': {'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0', 'computeType': 'BUILD_GENERAL1_SMALL'}}
    if enabled is not None:
        project['environment']['privilegedMode'] = not enabled
    snapshot, calls = pipeline('codebuild_project', {('codebuild', 'list_projects'): {'projects': ['example']},
        ('codebuild', 'batch_get_projects'): {'projects': [project]}})
    assert verdict(snapshot, 'aws.b.codebuild.nonprivileged') == expected
    assert item_of(snapshot, 'codebuild_project')['Configuration']['projects'][0]['name'] == 'example'
    assert sum(service == 'codebuild' and op == 'batch_get_projects' for service, op, args in calls) == 1


@pytest.mark.parametrize('mode,expected', [('Active', 'PASS'), ('PassThrough', 'FAIL'), (None, 'UNKNOWN')])
def test_lambda_configuration_public_pipeline(pipeline, mode, expected):
    row = {'FunctionName': 'example', 'FunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:example'}
    configuration = {**row, **({'TracingConfig': {'Mode': mode}} if mode is not None else {})}
    snapshot, calls = pipeline('lambda_function', {('lambda', 'list_functions'): {'Functions': [row]},
        ('lambda', 'get_function_configuration'): configuration})
    assert verdict(snapshot, 'aws.b.lambda.active_tracing') == expected


@pytest.mark.parametrize('mode,expected', [('ON', 'PASS'), ('OFF', 'FAIL'), (None, 'UNKNOWN')])
def test_cognito_configuration_public_pipeline(pipeline, mode, expected):
    pool = {'Id': REGION + '_Example', 'Name': 'example'}
    detail = {'UserPool': {**pool, 'Arn': f'arn:aws:cognito-idp:{REGION}:{ACCOUNT}:userpool/{pool["Id"]}',
                           **({'MfaConfiguration': mode} if mode is not None else {})}} if mode is not None else None
    snapshot, calls = pipeline('cognito_user_pool', {('cognito-idp', 'list_user_pools'): {'UserPools': [pool]},
        ('cognito-idp', 'describe_user_pool'): detail})
    assert verdict(snapshot, 'aws.b.cognito.required_mfa') == expected


@pytest.mark.parametrize('mode,expected', [('Enabled', 'PASS'), ('Suspended', 'FAIL'), (None, 'UNKNOWN')])
def test_s3_versioning_public_pipeline(pipeline, mode, expected):
    snapshot, calls = pipeline('bucket', {('s3', 'list_buckets'): {'Buckets': [{'Name': 'example-review-bucket'}]},
        ('s3', 'get_bucket_location'): {}, ('s3', 'get_bucket_versioning'): {'Status': mode} if mode else None})
    assert verdict(snapshot, 'aws.s3.versioning') == expected


@pytest.mark.parametrize('cid', ['aws.c2b.codebuild.invoked_last_90_days', 'aws.c2b.codebuild.built_within_90_days'])
def test_codebuild_reported_missing_build_is_unavailable_reproduction(pipeline, cid):
    """Known SDK buildsNotFound is lost evidence, not proof of no invocation."""
    build_id = 'example:00000000-0000-0000-0000-000000000000'
    snapshot, calls = pipeline('codebuild_project', {
        ('codebuild', 'list_projects'): {'projects': ['example']},
        ('codebuild', 'batch_get_projects'): {'projects': [{'name': 'example'}]},
        ('codebuild', 'list_builds_for_project'): {'ids': [build_id]},
        ('codebuild', 'batch_get_builds'): {'buildsNotFound': [build_id]},
    })
    # Before the proposed fix, Builds was falsely empty and both checks FAILed.
    assert verdict(snapshot, cid) == 'UNKNOWN'
    assert item_of(snapshot, 'codebuild_project')['Builds']['collection_status'] == 'partial'


@pytest.mark.parametrize('mode,expected', [('ALLOW', 'FAIL'), ('PRIVATE', 'PASS'), (None, 'UNKNOWN')])
def test_sns_native_attribute_map_public_pipeline(pipeline, mode, expected):
    arn = f'arn:aws:sns:{REGION}:{ACCOUNT}:example'
    policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': '*' if mode == 'ALLOW' else {'AWS': f'arn:aws:iam::{ACCOUNT}:root'}, 'Action': 'sns:Publish', 'Resource': arn}]}
    snapshot, calls = pipeline('sns_topic', {('sns', 'list_topics'): {'Topics': [{'TopicArn': arn}]},
        ('sns', 'get_topic_attributes'): {'Attributes': {'TopicArn': arn, 'Policy': json.dumps(policy)}} if mode else None})
    assert verdict(snapshot, 'aws.cb.sns.policy_no_unrestricted_wildcard') == expected
    if mode:
        assert item_of(snapshot, 'sns_topic')['Attributes']['Attributes']['TopicArn'] == arn


@pytest.mark.parametrize('enabled,expected', [(True, 'PASS'), (False, 'FAIL'), (None, 'UNKNOWN')])
def test_emr_security_configuration_native_json_public_pipeline(pipeline, enabled, expected):
    responses = {('emr', 'list_clusters'): {'Clusters': [{'Id': 'j-EXAMPLE', 'Name': 'example', 'Status': {'State': 'WAITING'}}]},
        ('emr', 'describe_cluster'): {'Cluster': {'Id': 'j-EXAMPLE', 'Name': 'example', 'SecurityConfiguration': 'example-config'}},
        ('emr', 'list_security_configurations'): {'SecurityConfigurations': [{'Name': 'example-config'}]},
        ('emr', 'describe_security_configuration'): {'Name': 'example-config', 'SecurityConfiguration': json.dumps({'EncryptionConfiguration': {'EnableAtRestEncryption': enabled}})} if enabled is not None else None}
    # Joining this field requires both native kinds in the collected snapshot.
    first, _ = pipeline(['emr_cluster', 'emr_security_configuration'], responses)
    assert verdict(first, 'aws.c2b.emr.cluster_at_rest_encryption') == expected


@pytest.mark.parametrize('enabled,expected', [(True, 'PASS'), (False, 'FAIL'), (None, 'UNKNOWN')])
def test_secretsmanager_documented_rotation_public_pipeline(pipeline, enabled, expected):
    """Corroboration outside the 713-ID input; never retrieve a secret value."""
    from peaso.checks import CHECKS
    candidates = [c for c in CHECKS if c.kind == 'secret' and 'rotation' in c.id]
    assert candidates
    arn = f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:example-AbCdEf'
    snapshot, calls = pipeline('secret', {('secretsmanager', 'list_secrets'): {'SecretList': [{'ARN': arn, 'Name': 'example'}]},
        ('secretsmanager', 'describe_secret'): {'ARN': arn, 'Name': 'example', 'RotationEnabled': enabled} if enabled is not None else None})
    assert verdict(snapshot, 'aws.secretsmanager.rotation') == expected
    assert not any(op in {'get_secret_value', 'batch_get_secret_value'} for service, op, args in calls)


@pytest.mark.parametrize('cid', [
    'aws.cb.sns.policy_no_unrestricted_wildcard',
    'aws.cb.sns.policy_no_public_publish', 'aws.cb.sns.policy_no_public_subscribe',
    'aws.cb.sns.topic_not_publicly_accessible_prowler',
])
def test_sns_missing_policy_is_unavailable_reproduction(pipeline, cid):
    """GetTopicAttributes properties depend on caller authorization (AWS docs)."""
    arn = f'arn:aws:sns:{REGION}:{ACCOUNT}:example'
    snapshot, _ = pipeline('sns_topic', {('sns', 'list_topics'): {'Topics': [{'TopicArn': arn}]},
        ('sns', 'get_topic_attributes'): {'Attributes': {'TopicArn': arn}}})
    assert verdict(snapshot, cid) == 'UNKNOWN'


def test_retired_sns_perimeter_id_points_to_the_active_native_control(pipeline):
    from peaso.checks import CHECK_ALIASES
    old = 'aws.cb.sns.policy_prohibit_public_access_perimeter'
    active = 'aws.cb.sns.policy_no_unrestricted_wildcard'
    assert CHECK_ALIASES[old] == active
    arn = f'arn:aws:sns:{REGION}:{ACCOUNT}:example'
    snapshot, _ = pipeline('sns_topic', {('sns', 'list_topics'): {'Topics': [{'TopicArn': arn}]},
        ('sns', 'get_topic_attributes'): {'Attributes': {'TopicArn': arn}}})
    assert verdict(snapshot, active) == 'UNKNOWN'
    aliased, = evaluate_snapshot(snapshot, checks=[old])['findings']
    assert aliased['check_id'] == active and aliased['status'] == 'UNKNOWN'


@pytest.mark.parametrize('mode,expected', [('ENABLED', 'PASS'), ('DISABLED', 'FAIL'), (None, 'DENIED')])
def test_inspector_native_account_state_public_pipeline(pipeline, mode, expected):
    """The public State.status projection comes from native accounts[].state."""
    state = {'status': mode, 'errorCode': 'ALREADY_ENABLED' if mode == 'ENABLED' else 'ACCESS_DENIED', 'errorMessage': 'offline'} if mode else None
    responses = {('inspector2', 'batch_get_account_status'): {'accounts': [{'accountId': ACCOUNT, 'state': state,
        'resourceState': {k: {'status': mode, 'errorCode': 'ALREADY_ENABLED' if mode == 'ENABLED' else 'ACCESS_DENIED', 'errorMessage': 'offline'} for k in ('ec2', 'ecr', 'lambda', 'lambdaCode')}}]} if mode else None}
    responses.update({('lambda', 'list_functions'): {'Functions': [{'FunctionName': 'example', 'FunctionArn': f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:example'}]},
                      ('ec2', 'describe_instances'): {'Reservations': []},
                      ('ecr', 'describe_repositories'): {'repositories': []}})
    snapshot, calls = pipeline(['inspector2_account_status', 'lambda_function', 'instance', 'ecr_repository'], responses)
    if mode:
        assert item_of(snapshot, 'inspector2_account_status')['State']['status'] == mode
    assert verdict(snapshot, 'aws.cb.inspector2.enabled_for_present_resources') == expected


@pytest.mark.parametrize('cid', [
    'aws.b.codebuild.artifact_encryption', 'aws.b.codebuild.logs_enabled',
    'aws.b.codebuild.s3_artifact_encryption', 'aws.b.codebuild.s3_log_encryption',
    'aws.c2b.codebuild.buildspec_not_user_controlled', 'aws.c2b.codebuild.buildspec_not_yml_file',
    'aws.c2b.codebuild.no_plaintext_sensitive_env_names', 'aws.c2b.codebuild.project_private',
    'aws.c2b.codebuild.s3_logs_encrypted_when_enabled', 'aws.c2b.codebuild.source_url_no_credentials',
    'aws.c2b.codebuild.webhook_filters_anchored', 'aws.nist.codebuild_exact_aws_key_env_names',
    'aws.pci.codebuild.aws_key_environment_vars',
])
def test_codebuild_shared_project_field_branches(pipeline, cid):
    for failing in (False, True):
        project = {'name': 'example', 'arn': f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/example',
            'source': {'type': 'BITBUCKET', 'location': 'https://x-token-auth:synthetic@bitbucket.org/review/repo.git' if failing else 'https://bitbucket.org/review/repo.git', 'buildspec': 'buildspec.yml' if failing else 'version: 0.2\nphases: {}'},
            'environment': {'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0', 'computeType': 'BUILD_GENERAL1_SMALL', 'privilegedMode': False,
                            'environmentVariables': [{'name': 'AWS_SECRET_ACCESS_KEY' if failing else 'STAGE', 'type': 'PLAINTEXT', 'value': 'synthetic'}]},
            'projectVisibility': 'PUBLIC_READ' if failing else 'PRIVATE',
            'artifacts': {'type': 'S3', 'encryptionDisabled': failing}, 'secondaryArtifacts': [],
            'logsConfig': {'cloudWatchLogs': {'status': 'DISABLED' if failing else 'ENABLED'},
                           's3Logs': {'status': 'DISABLED' if failing and cid.endswith('logs_enabled') else 'ENABLED', 'encryptionDisabled': failing}},
            'webhook': {'filterGroups': [[{'type': 'HEAD_REF', 'pattern': 'refs/heads/main' if failing else '^refs/heads/main$'}]]}}
        snapshot, calls = pipeline('codebuild_project', {('codebuild', 'list_projects'): {'projects': ['example']},
            ('codebuild', 'batch_get_projects'): {'projects': [project]}})
        assert verdict(snapshot, cid) == ('FAIL' if failing else 'PASS')
        published = json.dumps(snapshot)
        assert 'x-token-auth:synthetic' not in published
        assert 'version: 0.2' not in published
        assert 'value' not in item_of(snapshot, 'codebuild_project')['Configuration']['projects'][0]['environment']['environmentVariables'][0]


@pytest.mark.parametrize('kind,cid,operation,listkey,groupkey,groupvalue,param_operation,param_argument', [
    ('rds_instance', 'aws.cb.rds.instance_tls_parameters', 'describe_db_instances', 'DBInstances', 'DBParameterGroups', [{'DBParameterGroupName': 'example', 'ParameterApplyStatus': 'in-sync'}], 'describe_db_parameters', 'DBParameterGroupName'),
    ('rds_cluster', 'aws.cb.rds.cluster_tls_parameters', 'describe_db_clusters', 'DBClusters', 'DBClusterParameterGroup', 'example', 'describe_db_cluster_parameters', 'DBClusterParameterGroupName'),
])
def test_rds_literal_dotted_parameter_public_pipeline(pipeline, kind, cid, operation, listkey, groupkey, groupvalue, param_operation, param_argument):
    for value, expected in [('1', 'PASS'), ('0', 'FAIL'), (None, 'UNKNOWN')]:
        cluster = kind == 'rds_cluster'
        row = {('DBClusterArn' if cluster else 'DBInstanceArn'): f'arn:aws:rds:{REGION}:{ACCOUNT}:' + ('cluster:example' if cluster else 'db:example'),
               'Engine': 'aurora-postgresql' if cluster else 'postgres', groupkey: groupvalue}
        snapshot, calls = pipeline(kind, {('rds', operation): {listkey: [row]},
            ('rds', param_operation): {'Parameters': [{'ParameterName': 'rds.force_ssl', 'ParameterValue': value}]} if value is not None else None})
        assert verdict(snapshot, cid) == expected
        assert any(service == 'rds' and op == param_operation and args[param_argument] == 'example' for service, op, args in calls)


@pytest.mark.parametrize('cid,path,passing,failing', [
    ('aws.b.cognito.password_lowercase', 'Policies.PasswordPolicy.RequireLowercase', True, False),
    ('aws.b.cognito.password_uppercase', 'Policies.PasswordPolicy.RequireUppercase', True, False),
    ('aws.b.cognito.password_number', 'Policies.PasswordPolicy.RequireNumbers', True, False),
    ('aws.b.cognito.password_symbol', 'Policies.PasswordPolicy.RequireSymbols', True, False),
    ('aws.b.cognito.password_minimum_fourteen', 'Policies.PasswordPolicy.MinimumLength', 14, 13),
    ('aws.b.cognito.admin_only_signup', 'AdminCreateUserConfig.AllowAdminCreateUserOnly', True, False),
    ('aws.b.cognito.deletion_protection', 'DeletionProtection', 'ACTIVE', 'INACTIVE'),
    ('aws.b.cognito.enforced_threat_protection', 'UserPoolAddOns.AdvancedSecurityMode', 'ENFORCED', 'AUDIT'),
])
def test_cognito_shared_userpool_field_branches(pipeline, cid, path, passing, failing):
    pool = {'Id': REGION + '_Example', 'Name': 'example'}
    for value, expected in [(passing, 'PASS'), (failing, 'FAIL')]:
        row = deepcopy(pool)
        selected = row
        for part in path.split('.')[:-1]:
            selected = selected.setdefault(part, {})
        selected[path.split('.')[-1]] = value
        snapshot, calls = pipeline('cognito_user_pool', {('cognito-idp', 'list_user_pools'): {'UserPools': [pool]},
            ('cognito-idp', 'describe_user_pool'): {'UserPool': row}})
        assert verdict(snapshot, cid) == expected


def test_s3_never_versioned_native_omission(pipeline):
    snapshot, _ = pipeline('bucket', {('s3', 'list_buckets'): {'Buckets': [{'Name': 'example-review-bucket'}]},
        ('s3', 'get_bucket_location'): {}, ('s3', 'get_bucket_versioning'): {}})
    assert verdict(snapshot, 'aws.s3.versioning') == 'FAIL'
