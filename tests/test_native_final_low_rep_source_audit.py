"""The independent source receipt cannot treat a helper name as proof."""
import hashlib
import inspect

import pytest

from peaso.checks import CHECKS
from peaso.checks.facts import FIELD_SPECS
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
