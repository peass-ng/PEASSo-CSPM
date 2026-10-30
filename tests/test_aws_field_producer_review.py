"""Bounded producer audit and SDK -> collector -> RDS predicate regressions."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path

import pytest

from scripts import audit_aws_field_producers as audit
from scripts import audit_aws_native_contracts as native
from tests.test_peaso_collectors_aws import sdk, IDENTITY, ACCOUNT, REGION

ID = 'aws_nist_rds_db_cluster_aurora_backtracking_enabled'
PIPELINE_SOURCE_FINGERPRINT = audit.pipeline_source_fingerprint()


def record_sdk_emission(request, kind, items, stage):
    """JUnit receipt from executed SDK pipeline outputs; never save raw values."""
    source = Path(request.node.path)
    request.node.user_properties.append(('aws_field_emission', json.dumps({
        'kind': kind, 'paths': sorted(set().union(*(audit.field_paths(item) for item in items))),
        'stage': stage, 'pipeline_source_fingerprint': PIPELINE_SOURCE_FINGERPRINT, 'test_source': str(source.relative_to(audit.ROOT)),
        'test_source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    }, sort_keys=True)))


@pytest.fixture(scope='module')
def ledger():
    return json.loads((audit.ROOT / 'docs/aws-review/field-producers.json').read_text())


def test_every_current_active_aws_id_has_an_explicit_field_review(ledger):
    ids = [row['id'] for row in ledger['checks']]
    assert len(ids) == len(set(ids))
    assert set(ids) == native.active_ids()
    assert not ledger['missing_registered_ids']
    for row in ledger['checks']:
        assert row['status'] in {'proven-native-shape', 'derived-producer', 'witness-only', 'needsmanualreview'}
        assert row['callback_contract'] in ledger['callback_contracts']
        assert not row['semantic_completeness_proven'] and not row['live_verified']
        for kind in {*row['dependencies'], row['kind']}:
            assert kind in ledger['producers']


def test_exact_dict_image_reviews_keep_the_tracing_limit_visible(ledger):
    rows = {row['id']: row for row in ledger['checks']}
    assert audit.EXACT_DICT_IMAGE_EVALUATORS == {
        'aws.review.ecr.selected_image_vulnerabilities',
        'aws.review.ecr_public.selected_image_high_vulnerabilities',
        'aws.review.ecr_public.selected_image_secret_indicators',
        'aws.review.workload.selected_image_secret_indicators',
    }
    for cid in audit.EXACT_DICT_IMAGE_EVALUATORS:
        row = rows[cid]
        assert row['direct_dict_instrumentation'] == 'exact_dict_native_predicate'
        assert row['fixture_outcomes'] == {'pass': 'PASS', 'fail': 'FAIL', 'unknown': 'UNKNOWN'}
        assert any('dict-subclass read tracing' in blocker for blocker in row['blockers'])


def test_sdk_member_presence_is_not_enough_when_projection_is_custom(ledger):
    # RDS has a parameter enrichment callback; API shape alone cannot prove its
    # output. The real callback must run before these paths receive credit.
    producer = ledger['producers']['rds_cluster']
    assert 'BacktrackWindow' in producer['api_top_fields']
    assert not producer['native_shape_retention_proven']
    assert 'BacktrackWindow' in producer['modeled_probe']['paths']
    assert 'BacktrackingSupported' not in producer['modeled_probe']['paths']


@pytest.mark.parametrize('kind,path', [
    ('instance', 'MetadataOptions.HttpTokens'),
    ('instance', 'UserDataSecretIndicators.HighConfidenceSecretPresent'),
    ('bucket', 'PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls'),
    ('bucket', 'Logging.LoggingEnabled.TargetBucket'),
    ('iam_user', 'MFADevices.items[].SerialNumber'),
    ('iam_user', 'AccessKeys.items[].AccessKeyFingerprint'),
    ('iam_role', 'AssumeRolePolicyDocument.Statement'),
    ('rds_instance', 'StorageEncrypted'),
    ('rds_cluster', 'BacktrackWindow'),
    ('cloudtrail', 'Status.IsLogging'),
    ('cloudtrail', 'EventSelectors.EventSelectors[].IncludeManagementEvents'),
])
def test_core_fields_emitted_by_actual_projection_chain(ledger, kind, path):
    probe = ledger['producers'][kind]['modeled_probe']
    assert probe['status'] == 'modeled-projection-executed'
    assert path in probe['paths']


def test_final_redaction_drops_raw_access_key_identifier(ledger):
    paths = ledger['producers']['iam_user']['modeled_probe']['paths']
    assert 'AccessKeys.items[].AccessKeyId' not in paths
    assert 'AccessKeys.items[].AccessKeyFingerprint' in paths


def test_reproducible_probe_runs_current_request_and_projection_code():
    probe = audit.probe_producer('iam_user', audit.Models())
    assert probe['status'] == 'modeled-projection-executed'
    assert probe['collection_status'] == 'collected'
    assert 'MFADevices.items[].SerialNumber' in probe['paths']
    assert 'AccessKeys.items[].AccessKeyId' not in probe['paths']


def test_engine_index_metadata_is_not_mistaken_for_an_aws_api_field(ledger):
    row = next(c for c in ledger['checks'] if c['id'] == 'aws.review.lambda.configuration_secret_indicators')
    metadata = [f for f in row['fields'] if f['kind'] == '@engine']
    assert any(f['path'] == 'context.provider' and f['status'] == 'derived-producer' for f in metadata)
    assert not any(f['kind'] == 'lambda_function' and f['path'] == 'context.provider' for f in row['fields'])


def test_resolves_registered_forwarder_and_actual_per_id_callable():
    check = next(c for c in native.registry() if c.id == 'aws.review.shield.drt_role_configured')
    functions = audit.callback_graph(check)
    assert any(fn.__module__ == 'peaso.checks.aws_service_status_review_20261019' and fn.__name__ == 'shield_drt_role_configured' for fn in functions)
    assert any(read['path'] == 'RoleArn' for read in audit.static_reads(functions))


def test_sdk_contract_documents_window_and_has_no_invented_support_flag():
    model = audit.Models()
    cluster = audit.shape_at(model.output('rds', 'describe_db_clusters'), 'DBClusters')
    assert audit.shape_at(cluster, 'BacktrackWindow') is not None
    assert audit.shape_at(cluster, 'BacktrackingSupported') is None
    documentation = cluster.members['BacktrackWindow'].documentation
    assert 'backtracking is disabled' in documentation and 'backtracking is enabled' in documentation


def scoped_index(item):
    scope = ACCOUNT + '/' + REGION
    return {'context': {'provider': 'aws', 'scope': scope, 'Account': ACCOUNT},
            'collections': {'rds_cluster': [{'type': 'rds_cluster', 'scope': scope,
                'account_id': ACCOUNT, 'status': 'collected', 'items': [item]}]},
            'rds_cluster': [{'type': 'rds_cluster', 'scope': scope, 'data': item}]}


@pytest.mark.parametrize('window,engine,expected', [
    (3600, 'aurora-mysql', 'PASS'), (0, 'aurora-mysql', 'FAIL'),
    (None, 'aurora-mysql', 'UNKNOWN'), (None, 'aurora-postgresql', 'NOT_APPLICABLE'),
])
def test_backtracking_sdk_to_public_collector_to_registered_predicate(sdk, window, engine, expected, request):
    from peaso.collectors import aws
    from peaso.snapshot import validate
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    row = {'DBClusterIdentifier': 'cluster-1', 'DBClusterArn': f'arn:aws:rds:{REGION}:{ACCOUNT}:cluster:cluster-1', 'Engine': engine}
    if window is not None:
        row['BacktrackWindow'] = window
    add('rds').add_response('describe_db_clusters', {'DBClusters': [row]}, {})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                            'options': {'regions': [REGION], 'retry_attempts': 1}}, ['rds_cluster'])
    validate(snapshot)
    envelope = next(e for e in snapshot['collections'] if e['type'] == 'rds_cluster' and e['status'] == 'collected')
    item, = envelope['items']
    record_sdk_emission(request, 'rds_cluster', envelope['items'], 'public-collector')
    assert 'BacktrackingSupported' not in item
    check = next(c for c in native.registry() if c.id == ID)
    assert check.evaluate(item, scoped_index(item))[0] == expected


def test_backtracking_denied_sdk_inventory_cannot_pass(sdk):
    from peaso.collectors import aws
    from tests.archived_check_contract import evaluate_snapshot
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    add('rds').add_client_error('describe_db_clusters', service_error_code='AccessDenied', http_status_code=403, expected_params={})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                            'options': {'regions': [REGION], 'retry_attempts': 1}}, ['rds_cluster'])
    report = evaluate_snapshot(snapshot, checks=[ID])
    assert report['findings'][0]['status'] == 'DENIED'
    assert report['stats']['by_status'].get('PASS', 0) == 0


@pytest.mark.parametrize('window', [-1, True, '3600', {}, None])
def test_backtracking_malformed_or_unavailable_window_is_unknown(window):
    check = next(c for c in native.registry() if c.id == ID)
    item = {'DBClusterIdentifier': 'cluster-1', 'Engine': 'aurora-mysql', 'BacktrackWindow': window}
    assert check.evaluate(item, scoped_index(item))[0] == 'UNKNOWN'


def test_backtracking_partial_and_denied_fact_cannot_pass():
    check = next(c for c in native.registry() if c.id == ID)
    item = {'DBClusterIdentifier': 'cluster-1', 'Engine': 'aurora-mysql', 'BacktrackWindow': 3600}
    index = scoped_index(item)
    index['collections']['rds_cluster'][0]['status'] = 'partial'
    assert check.evaluate(item, index)[0] == 'UNKNOWN'
    item['_coverage'] = {'BacktrackWindow': {'status': 'denied'}}
    assert check.evaluate(item, scoped_index(item))[0] == 'UNKNOWN'


def resource_index(kind, item):
    scope = ACCOUNT + '/' + REGION
    return {'context': {'provider': 'aws', 'scope': scope, 'Account': ACCOUNT},
            'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [item]}]},
            kind: [{'type': kind, 'scope': scope, 'data': item}]}


@pytest.mark.parametrize('access,expected', [
    ({'getObject': 'private', 'allowPublicOverrides': False}, 'PASS'),
    ({'getObject': 'public', 'allowPublicOverrides': False}, 'FAIL'),
    ({'getObject': 'public', 'allowPublicOverrides': True}, 'FAIL'),
    ({'getObject': 'private', 'allowPublicOverrides': True}, 'UNKNOWN'),
    ({'getObject': 'private'}, 'UNKNOWN'), ({}, 'UNKNOWN'),
])
def test_lightsail_sdk_public_collector_retains_native_access_rules(sdk, access, expected, request):
    from peaso.collectors import aws
    from peaso.snapshot import validate
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    row = {'name': 'native-bucket', 'arn': f'arn:aws:lightsail:{REGION}:{ACCOUNT}:Bucket/native-bucket',
           'accessRules': access}
    stub = add('lightsail')
    stub.add_response('get_buckets', {'buckets': [row]}, {})
    stub.add_response('get_bucket_access_keys', {'accessKeys': []}, {'bucketName': 'native-bucket'})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                            'options': {'regions': [REGION], 'retry_attempts': 1}}, ['lightsail_bucket'])
    validate(snapshot)
    envelope = next(e for e in snapshot['collections'] if e['type'] == 'lightsail_bucket' and e['status'] == 'collected')
    item, = envelope['items']
    record_sdk_emission(request, 'lightsail_bucket', envelope['items'], 'public-collector')
    assert item['accessRules'] == access
    assert 'AccountPublicAccessBlock' not in item
    check = next(c for c in native.registry() if c.id == 'aws_cis_lightsail_bucket_private')
    assert check.evaluate(item, resource_index('lightsail_bucket', item))[0] == expected


def test_lightsail_denied_inventory_is_denied_not_pass(sdk):
    from peaso.collectors import aws
    from tests.archived_check_contract import evaluate_snapshot
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    add('lightsail').add_client_error('get_buckets', service_error_code='AccessDeniedException', http_status_code=403, expected_params={})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                            'options': {'regions': [REGION], 'retry_attempts': 1}}, ['lightsail_bucket'])
    report = evaluate_snapshot(snapshot, checks=['aws_cis_lightsail_bucket_private'])
    assert report['findings'][0]['status'] == 'DENIED'


@pytest.mark.parametrize('case,expected', [('enabled', 'PASS'), ('short', 'UNKNOWN'), ('missing', 'UNKNOWN'), ('denied', 'UNKNOWN'), ('short_lifecycle_denied_lock', 'FAIL')])
def test_sdk_bucket_object_lock_response_wrapper_reaches_retention_predicate(sdk, case, expected, request):
    from peaso.collectors import aws
    session, add, _ = sdk
    stub = add('s3')
    stub.add_response('list_buckets', {'Buckets': [{'Name': 'trail-bucket'}]}, {})
    stub.add_response('get_bucket_location', {}, {'Bucket': 'trail-bucket'})
    operations = ['get_public_access_block', 'get_bucket_policy_status', 'get_bucket_policy', 'get_bucket_encryption',
                  'get_bucket_versioning', 'get_bucket_acl', 'get_bucket_ownership_controls', 'get_bucket_logging',
                  'get_bucket_lifecycle_configuration', 'get_bucket_notification_configuration', 'get_bucket_replication',
                  'get_object_lock_configuration', 'get_bucket_tagging']
    for operation in operations:
        params = {'Bucket': 'trail-bucket'}
        if operation == 'get_bucket_lifecycle_configuration':
            rules = [{'ID': 'short', 'Status': 'Enabled', 'Prefix': 'AWSLogs/', 'Expiration': {'Days': 30}}] if case == 'short_lifecycle_denied_lock' else []
            stub.add_response(operation, {'Rules': rules}, params)
        elif operation == 'get_object_lock_configuration' and case not in ('denied', 'short_lifecycle_denied_lock'):
            response = {} if case == 'missing' else {'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled',
                'Rule': {'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 30 if case == 'short' else 365}}}}
            stub.add_response(operation, response, params)
        else:
            stub.add_client_error(operation, service_error_code='AccessDenied', http_status_code=403, expected_params=params)
    # One stubbed queue is consumed in request order: keep the per-bucket
    # detail reads serial so each response reaches its own operation.
    requests = aws.Requests({'retry_attempts': 1, 'service_concurrency': 1})
    result = aws._buckets(requests, session, REGION)
    assert result.status == 'collected'
    item, = result.items
    record_sdk_emission(request, 'bucket', result.items, 'real-bucket-callback')
    cid = 'aws_cloudtrail_bucket_lifecycle_retention_365'
    fixture = native.behavior_module().CASES[cid]
    index = deepcopy(fixture.get('pass_index', fixture.get('index', {})))
    index['bucket'][0]['data'] = item
    index['collections']['bucket'][0]['items'] = [item]
    check = next(c for c in native.registry() if c.id == cid)
    assert check.evaluate(deepcopy(fixture['pass']), index)[0] == expected


@pytest.mark.parametrize('marker', [None, 'empty', 'partial', 'denied'])
def test_positive_object_lock_body_requires_successful_read_status(marker):
    cid = 'aws_cloudtrail_bucket_lifecycle_retention_365'
    fixture = native.behavior_module().CASES[cid]
    index = deepcopy(fixture.get('pass_index', fixture.get('index', {})))
    def alter(value):
        if isinstance(value, dict):
            if isinstance(value.get('ObjectLock'), dict):
                lock = value['ObjectLock']
                if marker is None:
                    lock.pop('collection_status', None)
                else:
                    lock['collection_status'] = marker
            for child in value.values():
                alter(child)
        elif isinstance(value, list):
            for child in value:
                alter(child)
    alter(index)
    check = next(c for c in native.registry() if c.id == cid)
    assert check.evaluate(deepcopy(fixture['pass']), index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mutation', ['valid', 'wrong_default_id', 'missing_default_id', 'missing_version_id',
                                     'duplicate_version_id', 'two_defaults', 'no_default', 'empty_version_id'])
@pytest.mark.parametrize('cid', ['aws.a.iam.attached_policy_no_star_star', 'aws.pci.iam.nonconsole_mfa_policy',
                                  'aws.pci.iam.policy_attached_to_active_principal'])
def test_sdk_gaad_public_pipeline_binds_managed_default_version(sdk, mutation, cid, request):
    """A modeled API member does not authenticate a contradictory default join."""
    from peaso.collectors import aws
    from peaso.engine import evaluate_snapshot
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    safe = {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}
    unsafe = {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
    row = {'Arn': f'arn:aws:iam::{ACCOUNT}:policy/audit', 'PolicyName': 'audit',
           'AttachmentCount': 1, 'DefaultVersionId': 'v2', 'PolicyVersionList': [
               {'VersionId': 'v1', 'IsDefaultVersion': False, 'Document': json.dumps(unsafe)},
               {'VersionId': 'v2', 'IsDefaultVersion': True, 'Document': json.dumps(safe)}]}
    if mutation == 'wrong_default_id': row['DefaultVersionId'] = 'v3'
    if mutation == 'missing_default_id': row.pop('DefaultVersionId')
    if mutation == 'missing_version_id': row['PolicyVersionList'][1].pop('VersionId')
    if mutation == 'empty_version_id': row['PolicyVersionList'][1]['VersionId'] = ''
    if mutation == 'duplicate_version_id': row['PolicyVersionList'][0]['VersionId'] = 'v2'
    if mutation == 'two_defaults': row['PolicyVersionList'][0]['IsDefaultVersion'] = True
    if mutation == 'no_default': row['PolicyVersionList'][1]['IsDefaultVersion'] = False
    response = {'Policies': [row], 'IsTruncated': False}
    kinds = ['iam_policy']
    iam = add('iam')
    if cid == 'aws.pci.iam.policy_attached_to_active_principal':
        response.update(UserDetailList=[{'UserName': 'audit-user', 'Arn': f'arn:aws:iam::{ACCOUNT}:user/audit-user',
            'AttachedManagedPolicies': [{'PolicyArn': row['Arn'], 'PolicyName': 'audit'}]}], GroupDetailList=[], RoleDetailList=[])
        kinds += ['iam_user', 'iam_group', 'iam_role']
    iam.add_response('get_account_authorization_details', response, {})
    if 'iam_user' in kinds:
        iam.add_response('list_access_keys', {'AccessKeyMetadata': []}, {'UserName': 'audit-user'})
        iam.add_client_error('get_login_profile', service_error_code='NoSuchEntity', http_status_code=404,
                             expected_params={'UserName': 'audit-user'})
        iam.add_response('list_mfa_devices', {'MFADevices': []}, {'UserName': 'audit-user'})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                            'options': {'regions': [REGION], 'retry_attempts': 1}}, kinds)
    report = evaluate_snapshot(snapshot, checks=[cid])
    for envelope in snapshot['collections']:
        if envelope['type'] in kinds and envelope.get('items'):
            record_sdk_emission(request, envelope['type'], envelope['items'], 'public-collector')
    assert [f['status'] for f in report['findings']] == ['PASS' if mutation == 'valid' else 'UNKNOWN']


@pytest.mark.parametrize('code', [200, 301, 400, 403, 404])
def test_external_cloudfront_unbound_probe_never_proves_existence_or_absence(code):
    from peaso.checks import evaluate_check
    from peaso.checks import claude2_aws_b_edge as edge
    item = edge._cf(Origins=edge._origins_of(edge._s3o(bucket='external-origin')))
    item['OriginBucketProbes'] = {'collection_status': 'collected',
                                'results': [{'Bucket': 'external-origin', 'HttpStatusCode': code}]}
    assert evaluate_check('aws.c2b.cloudfront.s3_origin_bucket_exists', item,
                          edge.inventory('bucket', []))[0] == 'UNKNOWN'


@pytest.mark.parametrize('code', [403, 404])
def test_sdk_head_bucket_generic_error_is_not_bucket_existence_evidence(sdk, code):
    from botocore.exceptions import ClientError
    from peaso.checks import evaluate_check
    from peaso.checks import claude2_aws_b_edge as edge
    _, add, clients = sdk
    add('s3').add_client_error('head_bucket', service_error_code=str(code), http_status_code=code,
                               expected_params={'Bucket': 'external-origin'})
    with pytest.raises(ClientError) as error:
        clients[('s3', REGION)].head_bucket(Bucket='external-origin')
    observed_code = error.value.response['ResponseMetadata']['HTTPStatusCode']
    assert observed_code == code
    item = edge._cf(Origins=edge._origins_of(edge._s3o(bucket='external-origin')))
    item['OriginBucketProbes'] = {'collection_status': 'collected',
                                'results': [{'Bucket': 'external-origin', 'HttpStatusCode': observed_code}]}
    assert evaluate_check('aws.c2b.cloudfront.s3_origin_bucket_exists', item,
                          edge.inventory('bucket', []))[0] == 'UNKNOWN'
    documentation = audit.Models().session.get_service_model('s3').operation_model('HeadBucket').documentation
    assert "bucket doesn't exist or you don't have permission" in documentation
    assert all(str(c) in documentation for c in (400, 403, 404))


def test_owned_cloudfront_origin_requires_complete_bucket_inventory():
    from peaso.checks import evaluate_check
    from peaso.checks import claude2_aws_b_edge as edge
    item = edge._cf(Origins=edge._origins_of(edge._s3o(bucket='owned-origin')))
    complete = edge.inventory('bucket', [{'Name': 'owned-origin'}])
    cid = 'aws.c2b.cloudfront.s3_origin_bucket_exists'
    assert evaluate_check(cid, item, complete)[0] == 'PASS'
    for state in ('denied', 'partial', 'not_collected'):
        incomplete = deepcopy(complete)
        incomplete['collections']['bucket'][0]['status'] = state
        assert evaluate_check(cid, item, incomplete)[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind,service,operation,response,path', [
    ('iam_account_summary', 'iam', 'get_account_summary', {'SummaryMap': {'AccountMFAEnabled': 1}}, 'SummaryMap.AccountMFAEnabled'),
    ('iam_password_policy', 'iam', 'get_account_password_policy', {'PasswordPolicy': {'MinimumPasswordLength': 14}}, 'PasswordPolicy.MinimumPasswordLength'),
    ('s3_account_public_access_block', 's3control', 'get_public_access_block',
     {'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}}, 'PublicAccessBlockConfiguration.BlockPublicAcls'),
])
def test_sdk_singleton_public_pipeline_produces_required_paths(sdk, kind, service, operation, response, path, request):
    from peaso.collectors import aws
    from peaso.snapshot import validate
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    params = {'AccountId': ACCOUNT} if service == 's3control' else {}
    add(service).add_response(operation, response, params)
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                            'options': {'regions': [REGION], 'retry_attempts': 1}}, [kind])
    validate(snapshot)
    envelope = next(e for e in snapshot['collections'] if e['type'] == kind)
    assert envelope['status'] == 'collected'
    assert envelope['scope'] == ACCOUNT + '/global'
    assert path in audit.field_paths(envelope['items'][0])
    record_sdk_emission(request, kind, envelope['items'], 'public-collector')


def test_direct_dict_tracking_retains_native_semantics_and_baseline_comparison():
    from types import SimpleNamespace
    namespace = {'__name__': 'peaso.checks.audit_test'}
    exec(compile('def evaluate(item, index):\n    return ("PASS" if item["required"] and item.get("optional", False) else "FAIL"), {}\n',
                 str(audit.ROOT / 'peaso/checks/audit_tracking_test.py'), 'exec'), namespace)
    check = SimpleNamespace(id='audit-test', evaluate=namespace['evaluate'], kind='instance', target='resource')
    reads, outcomes = audit.fixture_reads(check, {'pass': {'required': True, 'optional': True},
                                                'fail': {'required': True}})
    assert outcomes == {'pass': 'PASS', 'fail': 'FAIL'}
    assert any(r['path'] == 'required' and r['observed_accessors'] == ['subscript'] for r in reads)
    assert any(r['path'] == 'optional' and r['observed_accessors'] == ['dict.get'] for r in reads)


def test_bound_empty_declared_policy_statement_list_still_passes():
    from peaso.checks import evaluate_check
    from peaso.checks import aws_a_iam_policies as rules
    item = deepcopy(rules.POLICY)
    item['PolicyVersionList'][0]['Document'] = {'Statement': []}
    assert evaluate_check('aws.a.iam.attached_policy_no_star_star', item, {})[0] == 'PASS'


@pytest.mark.parametrize('cid,path', [
    ('aws_cis_lightsail_ssm_patch_compliance', 'SsmMatch'),
    ('aws_cis_lightsail_ssm_patch_compliance', 'PatchState'),
    ('aws_cis_elasticbeanstalk_https_listener', 'EnvironmentResources'),
    ('aws_cis_elasticbeanstalk_load_balancer_access_logs', 'AssociatedLoadBalancers'),
    ('aws_cis_beanstalk_persistent_logs_s3', 'S3LogDestination'),
    ('aws_cis_beanstalk_persistent_logs_s3', 'hostmanager_options_complete'),
    ('aws_wafv2_request_validation_rules', 'WAFWebACLArn'),
])
def test_required_derived_contract_has_causal_synchronized_reproduction(cid, path):
    case = native.behavior_module().CASES[cid]
    item = deepcopy(case['pass'])
    index = deepcopy(case.get('pass_index', case.get('case_indices', {}).get('pass', case.get('index', {}))))
    check = next(c for c in native.registry() if c.id == cid)
    assert check.evaluate(item, index)[0] == 'PASS'
    def remove(value):
        if isinstance(value, dict):
            value.pop(path, None)
            for child in value.values(): remove(child)
        elif isinstance(value, list):
            for child in value: remove(child)
    remove(item)
    remove(index)
    status, evidence = check.evaluate(item, index)
    assert status == 'UNKNOWN'
    assert 'missing fact: ' + path in evidence['reason']


@pytest.mark.parametrize('kind,missing', [
    ('lightsail_instance', {'SsmMatch', 'PatchState'}),
    ('elastic_beanstalk_environment', {'EnvironmentResources', 'AssociatedLoadBalancers', 'S3LogDestination', 'Configuration.hostmanager_options_complete'}),
    ('load_balancer_v2', {'WAFWebACLArn'}),
])
def test_historical_derived_contracts_are_not_base_sdk_members(kind, missing):
    """Base SDK absence is historical context; repaired enrichers may emit paths."""
    models = audit.Models()
    producer, shape = audit.producer(kind, models)
    probe = audit.probe_producer(kind, models, public_pipeline=True)
    assert probe['status'] == 'modeled-public-pipeline-executed'
    assert probe['collection_status'] == 'collected'
    assert all(audit.shape_at(shape, path) is None for path in missing)
    if kind == 'lightsail_instance':
        assert 'fetcher' not in producer and 'enricher' not in producer


def test_lightsail_native_models_do_not_establish_immutable_ssm_join():
    review = audit.lightsail_ssm_contract_review(audit.Models(), native.active_ids())
    assert review['status'] == 'unsupported-exact-join-in-reviewed-native-surfaces'
    assert not review['candidate_cross_identity_members']
    assert 'GetInstance' in review['reviewed_get_list_operations']
    assert 'GetInstances' in review['reviewed_get_list_operations']
    assert 'AWS::Lightsail::Instance' not in review['ssm_source_types']
    assert 'support' in review['support_code_documentation'].lower()
    assert set(review['active_alternatives']) == {'aws.cb.ssm.instance_patch_compliant',
                                                'aws.cb.ssm.resource_compliance_summary_compliant'}


@pytest.mark.parametrize('mfa,expected', [('true', 'PASS'), ('false', 'FAIL')])
def test_sdk_existing_csv_report_public_pipeline_to_registered_consumer(sdk, mfa, expected, request):
    from peaso.collectors import aws
    from peaso.engine import evaluate_snapshot
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    # The SDK validates Content as a blob; native report columns are established
    # only after executing the real CSV parser and the registered consumer.
    content = ('user,arn,password_enabled,mfa_active\naudit,arn:aws:iam::' + ACCOUNT + ':user/audit,true,' + mfa + '\n').encode()
    add('iam').add_response('get_credential_report', {'Content': content, 'ReportFormat': 'text/csv',
                                                   'GeneratedTime': audit.datetime(2026, 10, 19, tzinfo=audit.timezone.utc)}, {})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
                            'options': {'regions': [REGION], 'retry_attempts': 1}}, ['iam_credential_report'])
    report = evaluate_snapshot(snapshot, checks=['aws.a.iam.report_console_mfa'])
    for envelope in snapshot['collections']:
        if envelope['type'] == 'iam_credential_report':
            record_sdk_emission(request, envelope['type'], envelope['items'], 'public-collector-existing-report-parser')
    assert [f['status'] for f in report['findings']] == [expected]


def test_all_supported_aws_kinds_have_explicit_public_pipeline_review(ledger):
    from peaso.collectors import aws
    assert set(aws.AWS_TYPES) <= set(ledger['producers'])
    assert set(ledger['producers']) == {row['kind'] for row in ledger['kind_remainder']}
    assert ledger['supported_aws_kinds'] == len(aws.AWS_TYPES)
    for row in ledger['kind_remainder']:
        assert not row['semantic_completeness_proven']


def test_every_id_enumerates_exact_unproved_observed_contracts(ledger):
    for row in ledger['checks']:
        unproved = {(field['kind'], field['path']) for field in row['fields']
                    if field['status'] not in ('proven-native-shape', 'derived-producer')}
        assert unproved == {(field['kind'], field['path']) for field in row['unproved_contracts']}
        assert not row['branch_completeness_proven']
        assert isinstance(row['unvisited_static_reads'], list)
        for field in row['fields']:
            if field.get('emission_receipts'):
                assert all(field['path'] in ledger['producers'][field['kind']][receipt]['paths']
                           for receipt in field['emission_receipts'])
