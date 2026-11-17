"""Reviewed IAM SQL variants retain joins, absence and threshold semantics."""
from __future__ import annotations

from . import register, result, unknown
from .facts import get
from .fixtures import CASES
from .aws_a_facts import complete_items, csv_boolean, scope_fixture, scope_subject


NATIVE_IDS = []
PASSWORD_SPECS = {
    "minimum_length_14": ("MinimumPasswordLength", int, lambda v: v >= 14, 14, 13),
    "lowercase": ("RequireLowercaseCharacters", bool, bool, True, False),
    "uppercase": ("RequireUppercaseCharacters", bool, bool, True, False),
    "numbers": ("RequireNumbers", bool, bool, True, False),
    "symbols": ("RequireSymbols", bool, bool, True, False),
    "reuse_at_least_24": ("PasswordReusePrevention", int, lambda v: v >= 24, 24, 23),
    "expiry_at_most_90": ("MaxPasswordAge", int, lambda v: v <= 90, 90, 91),
}


def password_row(spec, scope):
    rows = complete_items(spec, "iam_password_policy", scope)
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError("account password policy must be unique")
    return get(rows[0], "PasswordPolicy", dict)


for suffix, (field, expected, acceptable, good, bad) in PASSWORD_SPECS.items():
    def install(suffix=suffix, field=field, expected=expected, acceptable=acceptable, good=good, bad=bad):
        cid = "aws.a.iam.password_policy_" + suffix
        @register(cid, "aws", "hardening", "aws_account", "Account password policy enforces " + suffix.replace("_", " "),
            "medium", "IA-5", "Configure the account password policy and verify its applicability to native IAM credentials.",
            target="scope", dependencies=["iam_password_policy"])
        def evaluate(item, index):
            policy = password_row(index, scope_subject(item))
            if policy is None:
                return result(True, password_policy="absent", semantics="Complete account left join proves no configured password policy")
            value = get(policy, field, expected)
            return result(not acceptable(value), field=field, configured=value)
        CASES[cid] = {"pass": {"scope": "123456789012/us-east-1"}, "fail": {"scope": "123456789012/us-east-1"},
            "missing": {}, "malformed": None, "index": scope_fixture("iam_password_policy", [{"PasswordPolicy": {field: good}}]),
            "fail_index": scope_fixture("iam_password_policy", [{"PasswordPolicy": {field: bad}}]),
            "empty_index": scope_fixture("iam_password_policy", [])}
        NATIVE_IDS.append(cid)
    install()


STRONG_FIELDS = ("RequireLowercaseCharacters", "RequireUppercaseCharacters", "RequireNumbers", "RequireSymbols")


for suffix, minimum, reuse, age in [("strong_min_length_8", 8, False, False), ("strong_min_length_14_reuse_24_age_90", 14, True, True)]:
    def install(suffix=suffix, minimum=minimum, reuse=reuse, age=age):
        cid = "aws.a.iam.password_policy_" + suffix
        @register(cid, "aws", "hardening", "aws_account", "Account password policy enforces " + suffix.replace("_", " "),
            "medium", "IA-5", "Configure all declared composition, length, reuse and age requirements for IAM passwords.",
            target="scope", dependencies=["iam_password_policy"])
        def evaluate(item, index):
            policy = password_row(index, scope_subject(item))
            if policy is None:
                return result(True, password_policy="absent")
            length = get(policy, "MinimumPasswordLength", int)
            requirements = {key: get(policy, key, bool) for key in STRONG_FIELDS}
            valid = length >= minimum and all(requirements.values())
            inspected = {}
            if reuse and valid:
                inspected["password_reuse_prevention"] = get(policy, "PasswordReusePrevention", int)
                valid = inspected["password_reuse_prevention"] >= 24
            if age and valid:
                inspected["maximum_password_age"] = get(policy, "MaxPasswordAge", int)
                valid = inspected["maximum_password_age"] <= 90
            return result(not valid, minimum_password_length=length, composition=requirements, minimum=minimum, **inspected)
        good = {"MinimumPasswordLength": minimum, **{key: True for key in STRONG_FIELDS}, "PasswordReusePrevention": 24, "MaxPasswordAge": 90}
        bad = {**good, "RequireSymbols": False}
        CASES[cid] = {"pass": {"scope": "123456789012/us-east-1"}, "missing": {}, "malformed": None,
            "index": scope_fixture("iam_password_policy", [{"PasswordPolicy": good}]),
            "fail_index": scope_fixture("iam_password_policy", [{"PasswordPolicy": bad}]),
            "empty_index": scope_fixture("iam_password_policy", [])}
        CASES[cid]["fail"] = {"scope": "123456789012/us-east-1"}
        NATIVE_IDS.append(cid)
    install()


def root_without_credentials(summary):
    """True when GetAccountSummary proves the root user has no sign-in or API credential.

    Organizations centralized root access deletes member-account root passwords, access
    keys and signing certificates; MFA then has no credential to protect.
    """
    counts = summary.get("SummaryMap") if isinstance(summary, dict) else None
    if not isinstance(counts, dict):
        return False
    fields = ("AccountPasswordPresent", "AccountAccessKeysPresent")
    values = [counts.get(field) for field in fields] + [counts.get("AccountSigningCertificatesPresent", 0)]
    return all(type(value) is int and value == 0 for value in values)


ROOT_WITHOUT_CREDENTIALS = ("Root user has no password, access keys or signing certificates (for example under "
                            "AWS Organizations centralized root access); root MFA has no credential to protect.")


@register("aws.a.iam.root_summary_mfa", "aws", "hardening", "iam_account_summary", "Root account MFA is configured",
    "high", "IA-2", "Configure MFA for the root account and verify root credential governance.")
def root_mfa(item, index):
    value = get(item, "SummaryMap.AccountMFAEnabled", int)
    if value not in {0, 1}:
        return unknown("malformed account MFA summary flag")
    if value != 1 and root_without_credentials(item):
        return "NOT_APPLICABLE", {"reason": ROOT_WITHOUT_CREDENTIALS, "account_mfa_enabled": value,
                                  "root_credentials_present": False}
    return result(value != 1, account_mfa_enabled=value)
CASES["aws.a.iam.root_summary_mfa"] = {"pass": {"SummaryMap": {"AccountMFAEnabled": 1}}, "fail": {"SummaryMap": {"AccountMFAEnabled": 0}}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.iam.root_summary_mfa")


@register("aws.a.iam.root_summary_no_keys", "aws", "hardening", "iam_account_summary", "Root account has no access keys",
    "high", "IA-5", "Remove unneeded root access keys using the account owner's credential governance process.")
def root_keys(item, index):
    value = get(item, "SummaryMap.AccountAccessKeysPresent", int)
    if value < 0:
        return unknown("negative root access key count")
    return result(value > 0, account_access_keys_present=value)
CASES["aws.a.iam.root_summary_no_keys"] = {"pass": {"SummaryMap": {"AccountAccessKeysPresent": 0}}, "fail": {"SummaryMap": {"AccountAccessKeysPresent": 1}}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.iam.root_summary_no_keys")


@register("aws.a.iam.report_console_mfa", "aws", "hardening", "iam_credential_report", "Credential-report password-enabled principals have MFA",
    "high", "IA-2", "Configure MFA for principals with native IAM password login enabled.")
def report_console_mfa(item, index):
    password = csv_boolean(item, "password_enabled")
    mfa = csv_boolean(item, "mfa_active")
    return result(password and not mfa, password_enabled=password, mfa_active=mfa)
CASES["aws.a.iam.report_console_mfa"] = {"pass": {"password_enabled": "true", "mfa_active": "true"}, "fail": {"password_enabled": "true", "mfa_active": "false"}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.iam.report_console_mfa")


@register("aws.a.iam.report_all_mfa", "aws", "hardening", "iam_credential_report", "Credential-report principals have MFA configured",
    "high", "IA-2", "Review and configure MFA for each applicable IAM principal.")
def report_all_mfa(item, index):
    mfa = csv_boolean(item, "mfa_active")
    if not mfa:
        # IAM MFA devices protect console sign-in; a principal with no password (root:
        # and no access keys or signing certificates) has no credential MFA applies to.
        root = isinstance(item, dict) and item.get("user") == "<root_account>"
        fields = ("password_enabled",) + (("access_key_1_active", "access_key_2_active", "cert_1_active", "cert_2_active") if root else ())
        if all(get(item, field, str) == "false" for field in fields):
            return "NOT_APPLICABLE", {"reason": ROOT_WITHOUT_CREDENTIALS if root else
                                      "IAM user has no console password; MFA applies to console sign-in only.",
                                      "mfa_active": mfa, "password_enabled": False}
    return result(not mfa, mfa_active=mfa)
CASES["aws.a.iam.report_all_mfa"] = {"pass": {"mfa_active": "true"}, "fail": {"mfa_active": "false", "user": "alice", "password_enabled": "true"}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.iam.report_all_mfa")
