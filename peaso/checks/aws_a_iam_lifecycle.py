"""Pinned IAM lifecycle predicates with captured UTC date and complete joins."""
from datetime import datetime, timedelta, timezone

from . import register, result, unknown
from .facts import get, list_of_objects, Unavailable
from .fixtures import CASES
from .aws_a_facts import captured_clock, csv_boolean, complete_items, scope_subject, scope_fixture
from .aws_a_iam_usage import report_date

NATIVE_IDS = []
CLOCK = {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}


def stamp(item, field):
    value = datetime.fromisoformat(get(item, field, str).replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise Unavailable("native date lacks timezone: " + field)
    return value


def midnight(item, index):
    return captured_clock(item, index).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


@register("aws.a.iam.active_key_age_90", "aws", "hardening", "iam_access_key", "Active IAM access key is newer than the captured 90-day date cutoff",
    "medium", "IA-5", "Rotate stale active credentials and prefer temporary credentials; inspect captured creation metadata.")
def key_age(item, index):
    state = get(item, "Status", str)
    if state == "Inactive":
        return "NOT_APPLICABLE", {"status": state}
    if state != "Active":
        return unknown("unrecognized access-key status")
    created = stamp(item, "CreateDate")
    cutoff = midnight(item, index) - timedelta(days=90)
    return result(created <= cutoff, created_at=created.isoformat(), cutoff=cutoff.isoformat(), comparison="<=")
CASES["aws.a.iam.active_key_age_90"] = {"pass": {"Status": "Active", "CreateDate": "2026-10-09T00:00:00+00:00"},
    "fail": {"Status": "Active", "CreateDate": "2026-01-01T00:00:00+00:00"}, "missing": {}, "malformed": None,
    "not_applicable": {"Status": "Inactive"}, "index": CLOCK}
NATIVE_IDS.append("aws.a.iam.active_key_age_90")


@register("aws.a.iam.server_certificate_expiry_date", "aws", "hardening", "iam_server_certificate", "IAM server certificate expiration is not before the captured date minus one second",
    "medium", "SC-17", "Replace expired IAM server certificates; review the exact captured source cutoff.")
def certificate(item, index):
    expiry = stamp(item, "Expiration")
    cutoff = midnight(item, index) - timedelta(seconds=1)
    return result(expiry < cutoff, expires_at=expiry.isoformat(), cutoff=cutoff.isoformat(), comparison="<")
CASES["aws.a.iam.server_certificate_expiry_date"] = {"pass": {"Expiration": "2027-01-01T00:00:00+00:00"},
    "fail": {"Expiration": "2026-01-01T00:00:00+00:00"}, "missing": {}, "malformed": None, "index": CLOCK}
NATIVE_IDS.append("aws.a.iam.server_certificate_expiry_date")


@register("aws.a.iam.console_key_created_at_setup", "aws", "hardening", "iam_credential_report", "Console IAM user's current key rotation cannot prove initial key setup",
    "medium", "IA-5", "Provision only the credential forms an identity needs; review creation and rotation metadata.")
def setup(item, index):
    enabled = csv_boolean(item, "password_enabled")
    if not enabled:
        return result(False, console_enabled=False)
    rotated = report_date(item, "access_key_1_last_rotated")
    if rotated is None:
        return result(False, console_enabled=True, first_key_rotation="null")
    return unknown("last rotation cannot establish when the first access key was created")
SETUP = {"password_enabled": "true", "user_creation_time": "2026-01-01T00:00:00+00:00", "access_key_1_last_rotated": "2026-01-01T00:00:10+00:00"}
CASES["aws.a.iam.console_key_created_at_setup"] = {
    "pass": {"password_enabled": "true", "access_key_1_last_rotated": "N/A"},
    "fail": {**SETUP, "access_key_1_last_rotated": "2026-01-01T00:00:09+00:00"},
    "fail_expect": "UNKNOWN",  # Last rotation cannot establish first-key creation.
    "missing": {}, "malformed": None,
}
NATIVE_IDS.append("aws.a.iam.console_key_created_at_setup")


for inline in (False, True):
    def install(inline=inline):
        cid = "aws.a.iam.user_no_direct_policies" if inline else "aws.a.iam.user_no_managed_policies"
        @register(cid, "aws", "least_privilege", "iam_user", "IAM user has no " + ("direct inline or managed policies" if inline else "direct managed policies"),
            "medium", "AC-6", "Review direct user policy attachments and use approved groups or roles.")
        def evaluate(item, index):
            managed = list_of_objects(get(item, "AttachedManagedPolicies", list))
            embedded = list_of_objects(get(item, "UserPolicyList", list)) if inline else []
            return result(bool(managed or embedded), managed_attachment_count=len(managed), inline_policy_count=len(embedded),
                semantics="Direct attachments only; group membership and effective permissions are separate")
        CASES[cid] = {"pass": {"UserPolicyList": [], "AttachedManagedPolicies": []},
            "fail": {"UserPolicyList": [], "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]}, "missing": {}, "malformed": None}
        NATIVE_IDS.append(cid)
    install()


@register("aws.a.iam.root_hardware_mfa", "aws", "hardening", "iam_account_summary", "Root MFA is enabled without an assigned virtual MFA device",
    "high", "IA-2", "Review root MFA devices and use hardware MFA consistent with the source requirement.", target="scope", dependencies=["iam_account_summary", "iam_virtual_mfa_device"])
def hardware_mfa(item, index):
    scope = scope_subject(item)
    summaries = complete_items(index, "iam_account_summary", scope)
    if len(summaries) != 1:
        return unknown("exactly one account summary required")
    enabled = get(summaries[0], "SummaryMap.AccountMFAEnabled", int)
    if enabled not in (0, 1):
        return unknown("invalid account MFA summary value")
    from .aws_a_iam import ROOT_WITHOUT_CREDENTIALS, root_without_credentials
    if enabled != 1 and root_without_credentials(summaries[0]):
        return "NOT_APPLICABLE", {"reason": ROOT_WITHOUT_CREDENTIALS, "account_mfa_enabled": enabled,
                                  "root_credentials_present": False}
    devices = complete_items(index, "iam_virtual_mfa_device", scope)
    account = scope.split("/")[0]
    virtual_root = False
    for device in devices:
        get(device, "SerialNumber", str)
        # Unassigned devices have no User member in a complete list response.
        if "User" not in device:
            continue
        arn = get(device, "User.Arn", str)
        parts = arn.split(":", 5)
        if len(parts) != 6 or parts[2] != "iam":
            return unknown("malformed assigned virtual MFA ARN")
        if parts[4] == account and parts[5] == "root":
            virtual_root = True
    return result(enabled != 1 or virtual_root, account_mfa_enabled=enabled, virtual_root_mfa_present=virtual_root)
GOOD = scope_fixture("iam_account_summary", [{"SummaryMap": {"AccountMFAEnabled": 1}}])
GOOD["collections"].update(scope_fixture("iam_virtual_mfa_device", [])["collections"])
BAD = scope_fixture("iam_account_summary", [{"SummaryMap": {"AccountMFAEnabled": 0}}])
BAD["collections"].update(scope_fixture("iam_virtual_mfa_device", [])["collections"])
CASES["aws.a.iam.root_hardware_mfa"] = {"pass": {"scope": "123456789012/us-east-1"}, "fail": {"scope": "123456789012/us-east-1"},
    "missing": {}, "malformed": None, "index": GOOD, "fail_index": BAD}
NATIVE_IDS.append("aws.a.iam.root_hardware_mfa")


@register("aws.a.iam.root_console_summary_mfa", "aws", "hardening", "iam_account_summary", "Console-enabled root has MFA in native account summary",
    "high", "IA-2", "Configure root MFA when console credentials exist, keeping console-disabled applicability explicit.")
def console_root_mfa(item, index):
    password = get(item, "SummaryMap.AccountPasswordPresent", int)
    if password not in (0, 1):
        return unknown("invalid root password summary flag")
    if password == 0:
        return result(False, root_console_enabled=False)
    mfa = get(item, "SummaryMap.AccountMFAEnabled", int)
    if mfa not in (0, 1):
        return unknown("invalid root MFA summary flag")
    return result(mfa == 0, root_console_enabled=True, root_mfa_enabled=bool(mfa))
CASES["aws.a.iam.root_console_summary_mfa"] = {"pass": {"SummaryMap": {"AccountPasswordPresent": 1, "AccountMFAEnabled": 1}},
    "fail": {"SummaryMap": {"AccountPasswordPresent": 1, "AccountMFAEnabled": 0}}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.iam.root_console_summary_mfa")
