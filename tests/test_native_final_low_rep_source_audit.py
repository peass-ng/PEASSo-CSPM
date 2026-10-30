"""The independent source receipt cannot treat a helper name as proof."""
import hashlib
import inspect
import gzip
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks.facts import FIELD_SPECS
from scripts import audit_native_final_low_reps as audit
from scripts.audit_native_final_low_reps import proof, S3_EXPECTED, SNAPSHOT_SHA256


def reviewed(check_id, **kwargs):
    check = next(check for check in CHECKS if check.id == check_id)
    source = ''.join(inspect.getsourcelines(inspect.unwrap(check.evaluate))[0])
    inventory = {
        'check_id': check_id,
        'evaluator_source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'native_fail_count': 1,
        'initial_representatives': 1,
        'evidence_keys': [],
        'evidence_type_counts': {},
    }
    return proof(inventory, inventory, FIELD_SPECS, **kwargs)


def test_strict_field_and_complete_scoped_join_have_source_proof():
    direct = reviewed('aws.a.cloudwatch.alarm_state_actions')
    assert direct['decision'] == 'native_final_source_proven'
    assert 'AlarmActions' in direct['bound_api_fields']
    scoped = reviewed('aws.a.iam.password_policy_expiry_at_most_90')
    assert scoped['decision'] == 'native_final_source_proven'
    assert 'iam_password_policy.PasswordPolicy.MaxPasswordAge' in scoped['bound_api_fields']
    assert any(ref['path'] == 'peaso/checks/aws_a_facts.py' for ref in scoped['helper_source_refs'])
    mounted = reviewed('aws.htbp.ecs.no_sensitive_host_mounts')
    assert mounted['decision'] == 'native_final_source_proven'
    assert mounted['underlying_evaluator']['path'] == 'peaso/checks/hacktricks_bp_aws.py'
    assert mounted['fail_predicates'] == [{'line': 252, 'expression': 'bool(mounted)'}]


def test_ambiguous_omission_and_serialized_policy_fail_closed():
    assert reviewed('aws.b.cloudfront.custom_acm_certificate')['decision'] == 'provisional_source_candidate'
    assert reviewed('aws.b.ecr.lifecycle_rules')['decision'] == 'retain_ai'
    assert reviewed('aws.b.rds_instance.nondefault_port_policy')['decision'] == 'provisional_source_candidate'
    assert reviewed('aws.c2b.cloudfront.custom_ssl_certificate')['decision'] == 'native_final_source_proven'


def test_s3_optional_absence_needs_exact_snapshot_completeness():
    assert reviewed('aws.s3.versioning')['decision'] == 'provisional_source_candidate'
    assert reviewed('aws.s3.versioning', s3_coverage={
        'snapshot_sha256': SNAPSHOT_SHA256, 'bucket_rows': 148,
        'detail_status_counts': {'Versioning': {'collected': 148}},
    })['decision'] == 'provisional_source_candidate'
    verified = reviewed('aws.s3.versioning', s3_coverage={
        'snapshot_sha256': SNAPSHOT_SHA256, 'bucket_rows': 148,
        'detail_status_counts': S3_EXPECTED,
    })
    assert verified['decision'] == 'native_final_source_proven'
    assert 'Versioning.Status' in verified['bound_api_fields']


def test_sqs_and_cloudformation_omission_proof_requires_complete_rows():
    assert reviewed('aws.cb.sqs.cmk_encryption')['decision'] == 'provisional_source_candidate'
    assert reviewed('aws.c2b.cloudformation.notifications')['decision'] == 'provisional_source_candidate'
    coverage = {'snapshot_sha256': SNAPSHOT_SHA256, 'bucket_rows': 148,
                'detail_status_counts': S3_EXPECTED,
                'ecr_repository_rows': 35,
                'ecr_lifecycle_status_counts': {'collected': 26, 'empty': 9},
                'log_group_rows': 101, 'log_group_complete_omitted_kms_key_count': 101,
                'sqs_queue_rows': 32, 'sqs_attributes_complete_count': 32,
                'cloudformation_stack_rows': 22,
                'cloudformation_root_notification_complete_count': 22}
    assert reviewed('aws.cb.sqs.cmk_encryption', s3_coverage=coverage)['decision'] == 'native_final_source_proven'
    assert reviewed('aws.c2b.cloudformation.notifications', s3_coverage=coverage)['decision'] == 'native_final_source_proven'
    coverage['sqs_attributes_complete_count'] = 31
    assert reviewed('aws.cb.sqs.cmk_encryption', s3_coverage=coverage)['decision'] == 'provisional_source_candidate'


def test_unregistered_and_changed_evaluator_are_rejected():
    with pytest.raises(ValueError, match='missing registered evaluator'):
        proof({'check_id': 'unknown.check'}, {}, FIELD_SPECS)
    check = reviewed('aws.a.cloudwatch.alarm_state_actions')
    with pytest.raises(ValueError, match='source or exact-992 count changed'):
        proof({'check_id': check['check_id'], 'native_fail_count': 1,
               'initial_representatives': 1}, {'evaluator_source_sha256': 'bad',
               'native_fail_count': 1, 'initial_representatives': 1}, FIELD_SPECS)


def test_exact_fail_scope_does_not_use_empty_denied_collection(tmp_path, monkeypatch):
    snapshot = tmp_path / 'snapshot.gz'
    report = tmp_path / 'pre-ai.gz'
    snapshot.write_bytes(gzip.compress(json.dumps({'collections': [
        {'type': 'bucket', 'scope': 'scope-a', 'status': 'collected', 'items': [{'id': 'bucket-a'}]},
        {'type': 'bucket', 'scope': 'scope-b', 'status': 'denied', 'items': []},
    ]}).encode()))
    def write_report(scope):
        report.write_bytes(gzip.compress(json.dumps({'findings': [{
            'observations': [{'id': 'native-1', 'check_id': 'aws.test',
                              'status': 'FAIL', 'scope': scope,
                              'native_resource_id': 'bucket-a'}],
        }]}).encode()))
        monkeypatch.setattr(audit, 'PRE_AI_SHA256', hashlib.sha256(report.read_bytes()).hexdigest())
    rows = [{'check_id': 'aws.test', 'decision': 'native_final_source_proven',
             'native_fail_count': 1}]
    inventory = {'aws.test': {'kind': 'bucket', 'target': 'resource', 'dependencies': []}}
    write_report('scope-a')
    binding = audit.bind_fail_scopes(snapshot, report, rows, inventory)
    assert binding['zero_item_partial_or_denied_envelopes_excluded'] == 1
    assert rows[0]['exact_fail_scope_binding']['matched_native_fail_ids'] == 1
    assert binding['source_proven_fail_ids_bound_to_exact_resources'] == 1
    write_report('scope-b')
    with pytest.raises(ValueError, match='lacks complete collection'):
        audit.bind_fail_scopes(snapshot, report, rows, inventory)


def test_partial_envelope_in_same_scope_blocks_absence_proof(tmp_path, monkeypatch):
    snapshot = tmp_path / 'snapshot.gz'
    report = tmp_path / 'pre-ai.gz'
    snapshot.write_bytes(gzip.compress(json.dumps({'collections': [
        {'type': 'bucket', 'scope': 'same', 'status': 'collected', 'items': [{'id': 'bucket-a'}]},
        {'type': 'bucket', 'scope': 'same', 'status': 'partial', 'items': []},
    ]}).encode()))
    report.write_bytes(gzip.compress(json.dumps({'findings': [{
        'observations': [{'id': 'native-1', 'check_id': 'aws.test',
                          'status': 'FAIL', 'scope': 'same',
                          'native_resource_id': 'bucket-a'}],
    }]}).encode()))
    monkeypatch.setattr(audit, 'PRE_AI_SHA256', hashlib.sha256(report.read_bytes()).hexdigest())
    rows = [{'check_id': 'aws.test', 'decision': 'native_final_source_proven',
             'native_fail_count': 1}]
    with pytest.raises(ValueError, match='lacks complete collection'):
        audit.bind_fail_scopes(snapshot, report, rows, {'aws.test': {'kind': 'bucket', 'target': 'resource', 'dependencies': []}})


def test_exact_resource_and_nested_detail_required(tmp_path, monkeypatch):
    snapshot = tmp_path / 'snapshot.gz'
    report = tmp_path / 'pre-ai.gz'
    inventory = {'aws.test': {'kind': 'bucket', 'target': 'resource', 'dependencies': []}}
    rows = [{'check_id': 'aws.test', 'decision': 'native_final_source_proven',
             'native_fail_count': 1,
             'snapshot_completeness_ref': {'response_sections': ['Notifications']}}]
    def write_snapshot(status):
        snapshot.write_bytes(gzip.compress(json.dumps({'collections': [
            {'type': 'bucket', 'scope': 'same', 'status': 'collected', 'items': [
                {'id': 'bucket-a', 'Notifications': {'collection_status': status}},
                {'id': 'bucket-b', 'Notifications': {'collection_status': 'collected'}}]},
        ]}).encode()))
    def write_report(resource):
        report.write_bytes(gzip.compress(json.dumps({'findings': [
            {'observations': [{'id': 'native-1', 'check_id': 'aws.test',
                               'status': 'FAIL', 'scope': 'same',
                               'native_resource_id': resource}]},
        ]}).encode()))
        monkeypatch.setattr(audit, 'PRE_AI_SHA256', hashlib.sha256(report.read_bytes()).hexdigest())
    write_snapshot('collected')
    write_report('bucket-missing')
    with pytest.raises(ValueError, match='resource identity unresolved'):
        audit.bind_fail_scopes(snapshot, report, rows, inventory)
    write_report('bucket-a')
    write_snapshot('denied')
    with pytest.raises(ValueError, match='resource detail incomplete'):
        audit.bind_fail_scopes(snapshot, report, rows, inventory)
    write_snapshot('collected')
    assert audit.bind_fail_scopes(snapshot, report, rows, inventory)[
        'source_proven_fail_ids_bound_to_exact_resources'] == 1


def test_third_pass_optional_fields_require_complete_snapshot():
    check_id = 'aws.b.apigateway.waf_reference'
    assert reviewed(check_id)['decision'] == 'provisional_source_candidate'
    coverage = {'snapshot_sha256': SNAPSHOT_SHA256,
                'third_pass_complete_rows': {'aws_account_configuration': 2,
                                             'rest_api_stage': 2,
                                             'ec2_launch_template': 11}}
    proven = reviewed(check_id, s3_coverage=coverage)
    assert proven['decision'] == 'native_final_source_proven'
    assert 'webAclArn' in proven['bound_api_fields']
    coverage['third_pass_complete_rows']['rest_api_stage'] = 1
    assert reviewed(check_id, s3_coverage=coverage)['decision'] == 'provisional_source_candidate'


def test_action_lists_and_elb_attribute_helpers_require_exact_responses():
    action = 'aws.a.cloudwatch.any_state_actions'
    balancer = 'aws.b.alb.access_logs'
    assert reviewed(action)['decision'] == 'provisional_source_candidate'
    assert reviewed(balancer)['decision'] == 'provisional_source_candidate'
    coverage = {'snapshot_sha256': SNAPSHOT_SHA256,
                'fourth_pass_complete_rows': {'cloudwatch_alarm': 196,
                                              'load_balancer': 10}}
    for check_id in (action, balancer, 'aws.elbv2.drop_invalid_headers',
                     'aws_nist_cloudwatch_alarm_action_enabled'):
        row = reviewed(check_id, s3_coverage=coverage)
        assert row['decision'] == 'native_final_source_proven'
        assert row['snapshot_completeness_ref']['resource_rows'] > 0
    coverage['fourth_pass_complete_rows']['load_balancer'] = 9
    assert reviewed(balancer, s3_coverage=coverage)['decision'] == 'provisional_source_candidate'


def test_registered_scalar_fields_require_exact_complete_response():
    check_id = 'aws.b.dynamodb.point_in_time_recovery'
    assert reviewed(check_id)['decision'] == 'provisional_source_candidate'
    coverage = {'snapshot_sha256': SNAPSHOT_SHA256,
                'fifth_pass_complete_rows': {'cognito_identity_pool': 3,
                                             'dynamodb_table': 4,
                                             'rds_instance': 4,
                                             'sns_topic': 5}}
    row = reviewed(check_id, s3_coverage=coverage)
    assert row['decision'] == 'native_final_source_proven'
    assert 'ContinuousBackups.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' in row['bound_api_fields']
    coverage['fifth_pass_complete_rows']['dynamodb_table'] = 3
    assert reviewed(check_id, s3_coverage=coverage)['decision'] == 'provisional_source_candidate'


def test_final_helper_proof_and_incomplete_absence_stay_separate():
    coverage = {'snapshot_sha256': SNAPSHOT_SHA256,
                'final_pass_complete_rows': {
                    'iam_credential_report': 13, 'acm_certificate': 45,
                    'http_api_stage': 1, 'codebuild_project': 1,
                    'cognito_user_pool': 1, 'rds_instance': 4,
                    'sagemaker_training_job': 5, 'ssmincidents_account': 2,
                    'ebs_volume': 34, 'ec2_image': 1,
                    'network_interface': 104, 'instance': 34,
                    'ec2_launch_template': 11, 'guardduty_detector': 1,
                    'kms_key': 34}}
    proven = reviewed('aws.cb.sagemaker.training_volume_kms', s3_coverage=coverage)
    assert proven['decision'] == 'native_final_source_proven'
    assert 'ResourceConfig.VolumeKmsKeyId' in proven['bound_api_fields']
    coverage['final_pass_complete_rows']['sagemaker_training_job'] = 4
    assert reviewed('aws.cb.sagemaker.training_volume_kms', s3_coverage=coverage)['decision'] == 'provisional_source_candidate'
    for check_id in ('aws.logs.retention', 'aws.iam.console_mfa',
                     'aws.claude_a.guardduty.detector_no_findings',
                     'aws.claude_a.guardduty.prowler_ai_protection',
                     'aws.claude_a.guardduty.prowler_no_high_severity_findings',
                     'aws.claude_a.guardduty.prowler_runtime_monitoring'):
        assert reviewed(check_id, s3_coverage=coverage)['decision'] == 'retain_ai'


def test_collector_pin_refresh_receipt_binds_current_cited_ranges():
    # The refreshed whole-file collector pins must come from the reviewed
    # range-by-range receipt, and every cited range must still hash exactly.
    from pathlib import Path
    root = Path(audit.__file__).resolve().parents[1]
    receipt = json.loads((root / 'docs/ai-review/native-final-low-rep-collector-pin-refresh-20261030.json').read_text())
    assert receipt['audit_commit'] == 'a9d62a01'
    for path, row in receipt['sources'].items():
        assert audit.SPECIAL_SOURCE_PINS[path] == row['new_source_sha256']
        assert hashlib.sha256((root / path).read_bytes()).hexdigest() == row['new_source_sha256']
    cited = {(path, span) for path, spans in audit.FINAL_COLLECTOR_REFS.values() for span in spans.split(',')}
    recorded = {(row['path'], row['new_lines']) for row in receipt['ranges']}
    assert cited <= recorded
    for row in receipt['ranges']:
        first, last = map(int, row['new_lines'].split('-'))
        data = b''.join((root / row['path']).read_bytes().splitlines(True)[first - 1:last])
        assert hashlib.sha256(data).hexdigest() == row['new_range_sha256'], row
        if row['status'] == 'byte_identical_moved':
            assert row['old_range_sha256'] == row['new_range_sha256'], row
        else:
            assert row['status'] == 'reviewed_additive' and row['review_note'], row
