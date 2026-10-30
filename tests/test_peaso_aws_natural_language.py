"""Meaningful sentences for the exact root-account cases reported by the user."""
from copy import deepcopy
import pytest
from peaso.finding_observation import evidence_summary


def explanation(cid, evidence, status='PASS'):
    finding = {'provider': 'aws', 'check_id': cid, 'status': status, 'evidence': evidence}
    before = deepcopy(finding)
    text = evidence_summary(finding)
    assert finding == before
    assert text and ':' not in text and len(text) < 230
    return text


def test_present_root_keys_explain_the_risk_without_saying_the_account_was_compromised():
    text = explanation('aws.a.iam.root_summary_no_keys', {'account_access_keys_present': 2}, 'FAIL')
    assert 'has 2 access keys' in text and 'Remove unused root keys' in text
    assert 'compromised' not in text


@pytest.mark.parametrize('bad', [None, {}, [], True, -1, '0'])
def test_missing_or_malformed_key_count_is_not_interpreted_as_zero(bad):
    text = explanation('aws.a.iam.root_summary_no_keys', {'account_access_keys_present': bad}, 'UNKNOWN')
    assert 'cannot confirm whether root keys exist' in text
    assert 'No access keys are configured' not in text


@pytest.mark.parametrize('bad', [None, {}, [], 2, '0'])
def test_missing_or_nonbinary_password_flag_is_not_interpreted_as_no_password(bad):
    text = explanation('aws.claude_a.iam.root_console_has_mfa', {'password_present': bad, 'mfa_enabled': 0}, 'UNKNOWN')
    assert 'could not be checked' in text
    assert 'has no console password' not in text


@pytest.mark.parametrize('cid,evidence,expected,absent', [
    ('aws.claude_a.vpc.route_table_no_default_igw_route', {'destinations':['0.0.0.0/0']}, 'default route to an internet gateway', 'log destinations'),
    ('aws.claude_a.iam.not_two_active_keys', {'both_active':True}, 'Both access keys are active.', 'is enabled'),
    ('aws.claude_a.iam.access_keys_rotated_90', {'stale_keys':[1]}, '1 active access key has not been rotated within 90 days.', 'stale key was found'),
    ('aws.claude_a.iam.prowler_admin_group_members_mfa', {'members_without_mfa':['alice']}, '1 member of this administrator group lacks MFA.', 'Members without MFA is'),
    ('aws.c2b.cloudfront.s3_origin_bucket_exists', {'buckets':['external'], 'reason':'origin bucket existence not resolvable'}, 'could not confirm whether the referenced S3 origin buckets exist', 'Buckets is'),
])
def test_native_values_describe_the_resource_and_setting(cid, evidence, expected, absent):
    text = evidence_summary({'provider':'aws', 'check_id':cid, 'status':'UNKNOWN' if 'reason' in evidence else 'FAIL', 'evidence':evidence})
    assert expected in text and absent not in text


def test_an_age_requirement_is_not_reported_as_the_age_of_a_finding():
    text = explanation('aws.cb.inspector2.findings_within_max_age', {'max_age_days':192, 'stale_findings':0, 'scope':'123456789012/us-east-1'})
    assert 'Findings must be no older than 192 days.' in text
    assert 'oldest recorded finding is 192' not in text


def test_function_url_without_iam_authentication_still_explains_resource_policy_limits():
    text = explanation('aws.lambda.function_url_authentication', {'auth_type':'NONE'}, 'FAIL')
    assert 'does not require IAM authentication' in text
    assert 'resource policies still determine who is allowed' in text
    assert 'anyone can invoke' not in text and 'is NONE' not in text


def test_a_disabled_exec_logging_enum_is_explained_as_disabled_session_logs():
    text = explanation('aws.htbp.ecs.exec_session_logging_not_disabled', {'exec_logging':'NONE'}, 'FAIL')
    assert 'ECS command-session logging is disabled.' in text
    assert 'NONE' not in text
