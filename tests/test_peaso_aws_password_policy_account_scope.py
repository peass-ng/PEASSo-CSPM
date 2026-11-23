"""Account-global IAM password policy is evaluated once per account."""

from peaso.checks import CHECKS
from peaso.engine import _scope_check_scopes
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

CHECK_ID = "aws.pci.iam.configured_password_policy"
ACCOUNT_A = "123456789012"
ACCOUNT_B = "210987654321"
THRESHOLDS = {
    "MinimumPasswordLength": 14,
    "RequireSymbols": True,
    "RequireNumbers": True,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "MaxPasswordAge": 90,
    "PasswordReusePrevention": 12,
    "HardExpiry": True,
}


def _collection(account, status="collected"):
    return {
        "type": "iam_password_policy",
        "scope": account + "/global",
        "service": "iam",
        "status": status,
        "global": True,
        "account_id": account,
        "items": [{"PasswordPolicy": dict(THRESHOLDS)}] if status == "collected" else [],
        **({"error": {"code": "AccessDenied"}} if status == "denied" else {}),
    }



def _console_user(account):
    return {"type": "iam_user", "scope": account + "/global", "status": "collected", "items": [
        {"UserName": "console-user", "LoginProfile": {"collection_status": "collected",
                                                      "LoginProfile": {"UserName": "console-user"}}}
    ]}


def _findings(snapshot):
    return [row for row in evaluate_snapshot(snapshot, checks=[CHECK_ID])["findings"]
            if row["check_id"] == CHECK_ID]


def test_password_policy_dispatches_once_per_account_global_scope():
    scopes = [ACCOUNT_A + "/us-east-1", ACCOUNT_A + "/eu-west-1",
              ACCOUNT_B + "/us-west-2"]
    check = next(row for row in CHECKS if row.id == CHECK_ID)
    selected = _scope_check_scopes({"provider": "aws", "scopes": scopes}, check)
    assert selected == [ACCOUNT_A + "/global", ACCOUNT_B + "/global"]


def test_password_policy_requires_own_complete_global_inventory_and_thresholds():
    scopes = [ACCOUNT_A + "/us-east-1", ACCOUNT_A + "/eu-west-1",
              ACCOUNT_B + "/us-west-2"]
    snapshot = make_snapshot("aws", scopes, [_collection(ACCOUNT_A), _console_user(ACCOUNT_A)],
                             metadata={"password_policy_thresholds": dict(THRESHOLDS)})
    rows = _findings(snapshot)
    assert [(row["scope"], row["status"]) for row in rows] == [
        (ACCOUNT_A + "/global", "PASS"), (ACCOUNT_B + "/global", "UNKNOWN")]
    assert all("scope mismatch" not in row["evidence"].get("reason", "") for row in rows)

    without_thresholds = make_snapshot("aws", scopes, [_collection(ACCOUNT_A), _console_user(ACCOUNT_A)])
    rows = _findings(without_thresholds)
    assert [(row["scope"], row["status"]) for row in rows] == [
        (ACCOUNT_A + "/global", "UNKNOWN"), (ACCOUNT_B + "/global", "UNKNOWN")]

    denied = make_snapshot("aws", scopes, [_collection(ACCOUNT_A, "denied"), _console_user(ACCOUNT_A)],
                           metadata={"password_policy_thresholds": dict(THRESHOLDS)})
    rows = _findings(denied)
    assert [(row["scope"], row["status"]) for row in rows] == [
        (ACCOUNT_A + "/global", "DENIED"), (ACCOUNT_B + "/global", "UNKNOWN")]
