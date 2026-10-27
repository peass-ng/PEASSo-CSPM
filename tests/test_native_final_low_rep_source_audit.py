"""The independent source receipt cannot treat a helper name as proof."""
import hashlib
import inspect

import pytest

from peaso.checks import CHECKS
from peaso.checks.facts import FIELD_SPECS
from scripts.audit_native_final_low_reps import proof


def reviewed(check_id):
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
    return proof(inventory, inventory, FIELD_SPECS)


def test_strict_field_and_complete_scoped_join_have_source_proof():
    direct = reviewed('aws.a.cloudwatch.alarm_state_actions')
    assert direct['decision'] == 'native_final_source_proven'
    assert 'AlarmActions' in direct['bound_api_fields']
    scoped = reviewed('aws.a.iam.password_policy_expiry_at_most_90')
    assert scoped['decision'] == 'native_final_source_proven'
    assert 'iam_password_policy.PasswordPolicy.MaxPasswordAge' in scoped['bound_api_fields']
    assert any(ref['path'] == 'peaso/checks/aws_a_facts.py' for ref in scoped['helper_source_refs'])


def test_ambiguous_omission_and_serialized_policy_fail_closed():
    assert reviewed('aws.b.cloudfront.custom_acm_certificate')['decision'] == 'provisional_source_candidate'
    assert reviewed('aws.b.ecr.lifecycle_rules')['decision'] == 'retain_ai'
    assert reviewed('aws.b.rds_instance.nondefault_port_policy')['decision'] == 'provisional_source_candidate'
    assert reviewed('aws.c2b.cloudfront.custom_ssl_certificate')['decision'] == 'native_final_source_proven'


def test_unregistered_and_changed_evaluator_are_rejected():
    with pytest.raises(ValueError, match='missing registered evaluator'):
        proof({'check_id': 'unknown.check'}, {}, FIELD_SPECS)
    check = reviewed('aws.a.cloudwatch.alarm_state_actions')
    with pytest.raises(ValueError, match='source or exact-992 count changed'):
        proof({'check_id': check['check_id'], 'native_fail_count': 1,
               'initial_representatives': 1}, {'evaluator_source_sha256': 'bad',
               'native_fail_count': 1, 'initial_representatives': 1}, FIELD_SPECS)
