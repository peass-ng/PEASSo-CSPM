"""All-account permission-set consumer decisions and incomplete-read handling."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

import pytest

from peaso.collectors.unused_iam_aws_completion import collect
from peaso.unused_iam_aws_completion import evaluate_permission_set, evaluate_permission_set_native, evaluate_credential_report

INSTANCE = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
PERMISSION = "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef"
ACCOUNTS = ("111111111111", "222222222222")
USER = "12345678-1234-1234-1234-123456789012"


@dataclass
class Read:
    items: list
    status: str = "collected"
    error: dict | None = None


class Requests:
    def __init__(self, *, provisioned=(), not_provisioned=(), assignments=(), failures=None):
        self.provisioned = set(provisioned)
        self.not_provisioned = set(not_provisioned)
        self.assignments = set(assignments)
        self.failures = failures or {}
        self.calls = []

    def pages(self, session, service, region, operation, expression, **kwargs):
        assert session is SESSION and region == "eu-west-1"
        self.calls.append((service, operation, kwargs))
        key = (operation, kwargs.get("AccountId"), kwargs.get("ProvisioningStatus"))
        if key in self.failures:
            return Read([], self.failures[key], {"code": "source_incomplete"})
        if operation == "list_accounts":
            return Read([{"Id": account} for account in ACCOUNTS])
        if operation == "list_instances":
            return Read([{"InstanceArn": INSTANCE, "Status": "ACTIVE", "OwnerAccountId": ACCOUNTS[0]}])
        if operation == "list_permission_sets":
            assert kwargs == {"InstanceArn": INSTANCE}
            return Read([PERMISSION])
        if operation == "list_accounts_for_provisioned_permission_set":
            state = kwargs.get("ProvisioningStatus")
            values = (self.provisioned | self.not_provisioned if state is None else
                      self.provisioned if state == "LATEST_PERMISSION_SET_PROVISIONED" else self.not_provisioned)
            return Read(sorted(values), "collected" if values else "empty")
        if operation == "list_account_assignments":
            account = kwargs["AccountId"]
            values = ([{"AccountId": account, "PermissionSetArn": PERMISSION,
                        "PrincipalType": "USER", "PrincipalId": USER}]
                      if account in self.assignments else [])
            return Read(values, "collected" if values else "empty")
        raise AssertionError(operation)


class Session:
    def get_partition_for_region(self, region):
        return "aws"


SESSION = Session()


def test_complete_all_account_absence():
    requests = Requests()
    result = collect(requests, SESSION, "eu-west-1")
    row = result["items"][0]
    assert row["_provenance"]["all_accounts_checked"] is True
    assert {call[2]["AccountId"] for call in requests.calls if call[1] == "list_account_assignments"} == set(ACCOUNTS)
    assert evaluate_permission_set(row)[0] == "FAIL"


def test_provisioned_account_is_structural_consumer_without_assignment():
    row = collect(Requests(provisioned={ACCOUNTS[1]}), SESSION, "eu-west-1")["items"][0]
    status, evidence = evaluate_permission_set(row)
    assert status == "PASS"
    assert evidence["consumer_accounts"] == [ACCOUNTS[1]]
    assert evidence["provisioning_states"][ACCOUNTS[1]] == "latest_provisioned"


def test_latest_not_provisioned_still_has_deployed_permission_set():
    row = collect(Requests(not_provisioned={ACCOUNTS[1]}), SESSION, "eu-west-1")["items"][0]
    status, evidence = evaluate_permission_set(row)
    assert status == "PASS"
    assert evidence["provisioning_states"][ACCOUNTS[1]] == "latest_not_provisioned"


def test_denied_assignment_cannot_prove_absence():
    requests = Requests(failures={("list_account_assignments", ACCOUNTS[1], None): "denied"})
    row = collect(requests, SESSION, "eu-west-1")["items"][0]
    assert row["status"] == "denied"
    assert evaluate_permission_set(row)[0] == "UNKNOWN"


def test_positive_assignment_survives_other_account_denial():
    requests = Requests(assignments={ACCOUNTS[0]},
                        failures={("list_account_assignments", ACCOUNTS[1], None): "denied"})
    row = collect(requests, SESSION, "eu-west-1")["items"][0]
    assert evaluate_permission_set(row)[0] == "PASS"
    assert len(row["Assignments"]) == 1


def test_provisioning_failure_still_reads_all_account_assignments():
    requests = Requests(assignments={ACCOUNTS[0]},
                        failures={("list_accounts_for_provisioned_permission_set", None, None): "partial"})
    row = collect(requests, SESSION, "eu-west-1")["items"][0]
    assert len([call for call in requests.calls if call[1] == "list_account_assignments"]) == 2
    assert evaluate_permission_set(row)[0] == "PASS"


def test_provisioning_failure_without_positive_is_unknown():
    requests = Requests(failures={("list_accounts_for_provisioned_permission_set", None, None): "partial"})
    row = collect(requests, SESSION, "eu-west-1")["items"][0]
    assert evaluate_permission_set(row)[0] == "UNKNOWN"


def test_foreign_assignment_cannot_become_positive():
    class Foreign(Requests):
        def pages(self, *args, **kwargs):
            result = super().pages(*args, **kwargs)
            if args[3] == "list_account_assignments" and result.items:
                result.items[0]["AccountId"] = "999999999999"
            return result
    row = collect(Foreign(assignments={ACCOUNTS[0]}), SESSION, "eu-west-1")["items"][0]
    assert row["status"] == "malformed"
    assert evaluate_permission_set(row)[0] == "UNKNOWN"


def test_organization_account_denial_prevents_absence():
    result = collect(Requests(failures={("list_accounts", None, None): "denied"}), SESSION, "eu-west-1")
    assert result["status"] == "denied" and result["items"] == []


def test_overlapping_provisioning_states_prevent_absence():
    row = collect(Requests(provisioned={ACCOUNTS[0]}, not_provisioned={ACCOUNTS[0]}), SESSION, "eu-west-1")["items"][0]
    assert row["reason"] == "provisioning_state_partition_invalid"
    assert evaluate_permission_set(row)[0] == "UNKNOWN"


REPORT = {
    "user": "reviewer", "arn": "arn:aws:iam::111111111111:user/reviewer",
    "user_creation_time": "2024-01-01T00:00:00Z",
    "ReportGeneratedTime": "2026-10-21T12:00:00Z",
    "password_enabled": "false", "password_last_used": "N/A", "password_last_changed": "N/A",
    "access_key_1_active": "true", "access_key_1_last_rotated": "2026-01-01T00:00:00Z",
    "access_key_1_last_used_date": "2026-10-20T10:00:00Z",
    "access_key_2_active": "false", "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A",
}
CONTEXT = {"context": {"provider": "aws", "scope": "111111111111/global",
                       "created_at": "2026-10-21T13:00:00Z"}}


def test_recent_key_use_passes_with_report_clock_and_identity():
    assert evaluate_credential_report(REPORT, CONTEXT, include_password=False)[0] == "PASS"


def test_old_key_use_has_exact_slot_and_date():
    row = {**REPORT, "access_key_1_last_used_date": "2026-08-01T00:00:00Z"}
    status, evidence = evaluate_credential_report(row, CONTEXT, include_password=False)
    assert status == "FAIL"
    assert evidence["stale_credentials"][0]["credential"] == "access_key_1"
    assert evidence["stale_credentials"][0]["last_used"] == "2026-08-01T00:00:00+00:00"


def test_new_key_with_no_recorded_use_is_unresolved():
    row = {**REPORT, "access_key_1_last_rotated": "2026-10-01T00:00:00Z",
           "access_key_1_last_used_date": "N/A"}
    assert evaluate_credential_report(row, CONTEXT, include_password=False)[0] == "UNKNOWN"


def test_old_key_with_documented_no_use_marker_fails():
    row = {**REPORT, "access_key_1_last_used_date": "N/A"}
    status, evidence = evaluate_credential_report(row, CONTEXT, include_password=False)
    assert status == "FAIL"
    assert evidence["stale_credentials"][0]["observation"].startswith("no recorded use")


def test_missing_or_unsupported_marker_cannot_pass():
    for value in (None, "no_information", "not_supported"):
        row = {**REPORT, "access_key_1_last_used_date": value}
        assert evaluate_credential_report(row, CONTEXT, include_password=False)[0] == "UNKNOWN"


def test_missing_all_enabled_credential_dates_is_unknown():
    row = {**REPORT, "access_key_1_last_used_date": "N/A", "access_key_1_last_rotated": "N/A"}
    assert evaluate_credential_report(row, CONTEXT, include_password=False)[0] == "UNKNOWN"


def test_stale_report_or_foreign_account_is_unknown():
    assert evaluate_credential_report(REPORT, {"context": {**CONTEXT["context"], "created_at": "2026-10-22T00:00:00Z"}}, include_password=False)[0] == "UNKNOWN"
    assert evaluate_credential_report({**REPORT, "arn": "arn:aws:iam::999999999999:user/reviewer"}, CONTEXT, include_password=False)[0] == "UNKNOWN"


def test_password_no_information_after_tracking_window():
    row = {**REPORT, "password_enabled": "true", "password_last_used": "no_information",
           "password_last_changed": "2026-01-01T00:00:00Z"}
    status, evidence = evaluate_credential_report(row, CONTEXT, days=90)
    assert status == "FAIL"
    assert {entry["credential"] for entry in evidence["stale_credentials"]} == {"password"}


def test_packaged_permission_set_cases():
    cases = json.loads((Path(__file__).resolve().parents[1] / "peaso/checks/unused_iam_aws_completion_cases.json").read_text())
    variants = cases["aws_identity_center_permission_set_consumer"]
    assert {name: evaluate_permission_set_native(variants[name], variants[name + "_index"])[0]
            for name in ("pass", "fail", "unknown")} == {
        "pass": "PASS", "fail": "FAIL", "unknown": "UNKNOWN"}




def test_report_generated_during_scan_uses_bound_read_time():
    row = {**REPORT, 'ReportGeneratedTime': '2026-10-21T13:01:00Z',
        '_credential_report_observation': {'operation': 'iam:GetCredentialReport',
            'scan_started_at': CONTEXT['context']['created_at'],
            'observed_at': '2026-10-21T13:02:00Z'}}
    assert evaluate_credential_report(row, CONTEXT, include_password=False)[0] == 'PASS'
    row['_credential_report_observation']['scan_started_at'] = '2026-10-20T12:00:00Z'
    assert evaluate_credential_report(row, CONTEXT, include_password=False)[0] == 'UNKNOWN'


def test_report_read_clock_before_generated_report_is_unknown():
    row = {**REPORT, '_credential_report_observation': {
        'operation': 'iam:GetCredentialReport', 'scan_started_at': CONTEXT['context']['created_at'],
        'observed_at': '2026-10-21T12:00:00Z'}, 'ReportGeneratedTime': '2026-10-21T12:01:00Z'}
    assert evaluate_credential_report(row, CONTEXT, include_password=False)[0] == 'UNKNOWN'


@pytest.mark.parametrize('ident', [
    'aws.claude_a.iam.console_password_used_45',
    'aws.claude_a.iam.prowler_console_password_used_45',
    'aws.claude_a.iam.access_keys_used_45',
])
def test_legacy_native_inactivity_uses_only_its_credential_family(ident):
    from peaso.checks import CHECKS
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    check = next(c for c in CHECKS if c.id == ident)
    console = 'console_password' in ident
    for variant, expected in [('new', 'UNKNOWN'), ('old', 'FAIL'), ('recent', 'PASS')]:
        row = {**REPORT}
        if console:
            row.update(password_enabled='true', password_last_changed='2026-10-20T00:00:00Z' if variant == 'new' else '2026-01-01T00:00:00Z',
                password_last_used='2026-10-20T10:00:00Z' if variant == 'recent' else 'no_information',
                access_key_1_last_used_date='not_supported')
        else:
            row.update(password_enabled='true', password_last_used='not_supported',
                access_key_1_last_rotated='2026-10-20T00:00:00Z' if variant == 'new' else '2026-01-01T00:00:00Z',
                access_key_1_last_used_date='2026-10-20T10:00:00Z' if variant == 'recent' else 'N/A')
        snapshot = make_snapshot('aws', [CONTEXT['context']['scope']],
            [{'type': 'iam_credential_report', 'scope': CONTEXT['context']['scope'], 'service': 'iam',
              'status': 'collected', 'items': [row]}], created_at=CONTEXT['context']['created_at'])
        report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[ident])
        finding = next(f for f in report['findings'] if f['check_id'] == ident)
        assert finding['status'] == expected, finding
        assert check.category == 'hardening'
        assert all(entry['credential'] == 'password' if console else entry['credential'].startswith('access_key_')
                   for entry in finding['evidence']['captured_credentials'])
        stale_snapshot = make_snapshot('aws', snapshot['scopes'], snapshot['collections'],
            created_at='2026-10-22T12:00:00Z')
        stale = evaluate_snapshot(stale_snapshot, categories=['hardening'], checks=[ident])
        assert next(f for f in stale['findings'] if f['check_id'] == ident)['status'] == 'UNKNOWN'
