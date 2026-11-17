"""Root and IAM-user MFA checks only apply where a credential exists."""
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

A = "123456789012"
GLOBAL = A + "/global"
NO_ROOT_CREDENTIALS = {"AccountMFAEnabled": 0, "AccountPasswordPresent": 0, "AccountAccessKeysPresent": 0,
                       "AccountSigningCertificatesPresent": 0}
ROOT_ROW = {"user": "<root_account>", "arn": f"arn:aws:iam::{A}:root", "password_enabled": "false", "mfa_active": "false",
            "access_key_1_active": "false", "access_key_2_active": "false", "cert_1_active": "false", "cert_2_active": "false"}
USER_ROW = {"user": "smtp", "arn": f"arn:aws:iam::{A}:user/smtp", "password_enabled": "false", "mfa_active": "false",
            "access_key_1_active": "true", "access_key_2_active": "false", "cert_1_active": "false", "cert_2_active": "false"}


def envelope(kind, items):
    return {"type": kind, "scope": GLOBAL, "service": "iam", "status": "collected" if items else "empty",
            "global": True, "account_id": A, "items": items}


def statuses(summary, rows=()):
    collections = [envelope("iam_account_summary", [{"AccountId": A, "SummaryMap": summary}]),
                   envelope("iam_virtual_mfa_device", []),
                   envelope("iam_credential_report", [dict(row, AccountId=A) for row in rows])]
    report = evaluate_snapshot(make_snapshot("aws", [A + "/us-east-1"], collections),
                               checks=["aws.a.iam.root_summary_mfa", "aws.a.iam.root_hardware_mfa", "aws.a.iam.report_all_mfa"])
    return {(f["check_id"], f.get("native_resource_id") or f["resource_id"]): f["status"] for f in report["findings"]}


def test_root_without_any_credential_is_not_applicable_for_root_mfa():
    found = statuses(NO_ROOT_CREDENTIALS, [ROOT_ROW, USER_ROW])
    by_check = {}
    for (check, _), status in found.items():
        by_check.setdefault(check, set()).add(status)
    assert by_check == {"aws.a.iam.root_summary_mfa": {"NOT_APPLICABLE"}, "aws.a.iam.root_hardware_mfa": {"NOT_APPLICABLE"},
                        "aws.a.iam.report_all_mfa": {"NOT_APPLICABLE"}}


def test_root_with_a_password_or_key_still_requires_mfa():
    for field in ("AccountPasswordPresent", "AccountAccessKeysPresent"):
        found = statuses(dict(NO_ROOT_CREDENTIALS, **{field: 1}))
        assert {s for (c, _), s in found.items() if c != "aws.a.iam.report_all_mfa"} == {"FAIL"}, field
    root_with_key = dict(ROOT_ROW, access_key_1_active="true")
    console_user = dict(USER_ROW, password_enabled="true")
    found = statuses(NO_ROOT_CREDENTIALS, [root_with_key, console_user])
    assert {s for (c, _), s in found.items() if c == "aws.a.iam.report_all_mfa"} == {"FAIL"}


def test_summary_without_credential_counts_cannot_prove_absence():
    found = statuses({"AccountMFAEnabled": 0})
    assert {s for (c, _), s in found.items() if c != "aws.a.iam.report_all_mfa"} == {"FAIL"}
