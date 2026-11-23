import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/global'
CHECKS = ['aws.a.iam.password_policy_lowercase', 'aws.iam.password_lowercase']


@pytest.mark.parametrize(('user_collection', 'password_policy', 'expected'), [
    ([], {'RequireLowercaseCharacters': False}, 'NOT_APPLICABLE'),
    ([{'collection_status': 'empty', 'absent': True}], {'RequireLowercaseCharacters': False}, 'NOT_APPLICABLE'),
    ([{'collection_status': 'denied'}], {'RequireLowercaseCharacters': False}, 'UNKNOWN'),
    (None, {'RequireLowercaseCharacters': False}, 'UNKNOWN'),
    ([{'collection_status': 'collected', 'LoginProfile': {'UserName': 'workload'}}], {'RequireLowercaseCharacters': False}, 'FAIL'),
    ([{'collection_status': 'collected', 'LoginProfile': {'UserName': 'workload'}}], {'RequireLowercaseCharacters': True}, 'PASS'),
])
def test_password_policy_requires_password_enabled_iam_user(user_collection, password_policy, expected):
    collections = [{'type': 'iam_password_policy', 'scope': SCOPE, 'status': 'collected',
                    'items': [{'PasswordPolicy': password_policy}]}]
    if user_collection is not None:
        users = [{'UserName': 'workload', 'LoginProfile': profile} for profile in user_collection]
        collections.append({'type': 'iam_user', 'scope': SCOPE, 'status': 'collected' if users else 'empty', 'items': users})
    snapshot = make_snapshot('aws', [SCOPE], collections)
    report = evaluate_snapshot(snapshot, categories=['hardening'], checks=CHECKS)
    assert {row['check_id']: row['status'] for row in report['findings']} == dict.fromkeys(CHECKS, expected)
