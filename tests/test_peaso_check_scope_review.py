"""Every check is classified; account-global questions never fan out by Region."""
import pytest

from peaso.check_scope import evaluation_scope, explicit_scope, scope_audit, aws_global_types
from peaso.checks import CHECKS
from peaso.engine import _registry, _scope_check_scopes, evaluate_snapshot
from peaso.snapshot import make_snapshot

A, B = "123456789012", "210987654321"
REGIONS = ["us-east-1", "us-east-2", "eu-north-1"]


def test_every_registered_check_has_a_scope_and_grouping_contract():
    _registry()
    rows = scope_audit(CHECKS)
    assert {row["check_id"] for row in rows} == {check.id for check in CHECKS}
    assert len(rows) == len(CHECKS)
    assert all(row["report_group"] == "check_id" and row["preserves_member_statuses"] for row in rows)
    assert {row["provider"] for row in rows} == {"aws", "gcp", "azure", "k8s"}


def test_all_account_only_scope_checks_run_once_per_account_even_when_evidence_is_missing():
    checks = [check for check in _registry() if check.provider == "aws" and check.target == "scope"
              and set(check.dependencies) <= aws_global_types() and explicit_scope(check) != "aws_region"]
    # aws.claude_a.organizations.no_untrusted_delegated_administrators is an
    # account-global check, but native_only.json excludes it from the automated
    # registry: it needs a customer trusted-account list (see test_peaso_native_only_scope).
    assert len(checks) >= 33
    scopes = [account + "/" + region for account in (A, B) for region in REGIONS]
    for check in checks:
        assert evaluation_scope(check) == "aws_account", check.id
        assert _scope_check_scopes({"provider": "aws", "scopes": scopes}, check) == [A + "/global", B + "/global"], check.id


def test_regional_guardduty_is_evaluated_in_every_selected_region():
    check = next(c for c in _registry() if c.id == "aws.a.guardduty.region_enabled")
    scopes = [A + "/" + region for region in REGIONS]
    assert evaluation_scope(check) == "aws_region"
    assert _scope_check_scopes({"provider": "aws", "scopes": scopes}, check) == scopes


def test_root_mfa_uses_each_accounts_own_global_facts_once():
    scopes = [account + "/" + region for account in (A, B) for region in REGIONS]
    collections = [{"type": "iam_account_summary", "scope": A + "/global", "service": "iam", "status": "collected", "global": True, "account_id": A,
                    "items": [{"AccountId": A, "SummaryMap": {"AccountMFAEnabled": 0}}]},
                   {"type": "iam_virtual_mfa_device", "scope": A + "/global", "service": "iam", "status": "empty", "global": True, "account_id": A, "items": []}]
    report = evaluate_snapshot(make_snapshot("aws", scopes, collections), checks=["aws.a.iam.root_hardware_mfa"])
    rows = report["findings"]
    assert len(rows) == 2
    assert {(r["scope"], r["status"]) for r in rows} == {(A + "/global", "FAIL"), (B + "/global", "UNKNOWN")}
    assert len([c for c in report["coverage"] if c["level"] == "check"]) == 2


def test_missing_global_resource_inventory_is_reported_once_per_account():
    check = next(check for check in _registry() if check.provider == "aws" and check.target == "resource" and check.kind == "iam_account_summary")
    scopes = [account + "/" + region for account in (A, B) for region in REGIONS]
    report = evaluate_snapshot(make_snapshot("aws", scopes, []), checks=[check.id])
    checked_scopes = {row["scope"] for row in report["coverage"] if row["level"] == "check"}
    assert checked_scopes == {A + "/global", B + "/global"}
    # The existing unknown-inventory coalescer keeps one row and records both accounts.
    assert len(report["findings"]) == 1 and report["findings"][0]["status"] == "UNKNOWN"
    assert set(report["findings"][0]["evidence"]["scopes"]) == checked_scopes


def test_aws_global_scope_guard_is_not_relaxed_for_an_unmarked_or_foreign_context():
    from peaso.checks.aws_a_facts import scope_subject
    from peaso.checks.facts import Unavailable
    for context in ({"scope": A + "/global"}, {"scope": A + "/global", "evaluation_scope": "aws_account", "Account": B}):
        with pytest.raises(Unavailable):
            scope_subject(context)
    assert scope_subject({"scope": A + "/global", "evaluation_scope": "aws_account", "Account": A}) == A + "/global"


def test_global_partition_uses_only_native_caller_identity_for_its_account():
    from peaso.checks.claude_aws_a_ec2 import partition
    from peaso.checks.facts import Unavailable
    context = {"scope": A + "/global", "metadata": {"caller_identities": [
        {"Account": B, "Arn": f"arn:aws-cn:iam::{B}:root"},
        {"Account": A, "Arn": f"arn:aws:sts::{A}:assumed-role/reader/test"}]}}
    assert partition({"context": context}) == "aws"
    context["metadata"]["caller_identities"][1]["Arn"] = f"arn:aws:iam::{B}:root"
    with pytest.raises(Unavailable, match="mismatch"):
        partition({"context": context})


def test_focused_account_support_role_check_does_not_need_unrequested_account_contact_inventory():
    from peaso.checks.fixtures import CASES
    check = next(check for check in _registry() if check.id == "aws.claude_a.iam.support_role_exists")
    import copy
    index = copy.deepcopy(CASES[check.id]["pass_index"])
    roles = [resource["data"] for resource in index["iam_role"]]
    for item in roles:
        item["AccountId"] = A
    snapshot = make_snapshot("aws", [A + "/" + region for region in REGIONS], [{
        "type": "iam_role", "scope": A + "/global", "service": "iam", "global": True,
        "account_id": A, "status": "collected", "items": roles}],
        metadata={"caller_identities": [{"Account": A, "Arn": f"arn:aws:iam::{A}:root"}]})
    report = evaluate_snapshot(snapshot, checks=[check.id])
    assert len(report["findings"]) == 1 and report["findings"][0]["status"] == "PASS"


def test_account_global_scope_preserves_existing_positive_and_negative_fixture_verdicts():
    """Changing execution scope must not turn known IAM facts into UNKNOWN."""
    from copy import deepcopy
    from peaso.checks.fixtures import CASES
    checked = []
    for check in _registry():
        if check.target != "scope" or evaluation_scope(check) != "aws_account" or check.id not in CASES:
            continue
        cases = CASES[check.id]
        for name in ("pass", "fail"):
            if name not in cases:
                continue
            data = deepcopy(cases[name])
            original = deepcopy(cases.get(name + "_index", cases.get("case_indices", {}).get(name, cases.get("index", {}))))
            before = check.evaluate(deepcopy(data), deepcopy(original))[0]
            changed = deepcopy(original)
            context = changed.setdefault("context", {})
            context.update(scope=A + "/global", _scope=A + "/global", Account=A, evaluation_scope="aws_account")
            context.setdefault("metadata", {})["caller_identities"] = [{"Account": A, "Arn": f"arn:aws:iam::{A}:root"}]
            # Rebind the fixture envelopes to the native global inventory scope,
            # rather than asking a global evaluator to consume regional labels.
            for kind in check.dependencies:
                for envelope in changed.get("collections", {}).get(kind, []):
                    envelope.update({"scope": A + "/global", "global": True, "account_id": A})
                for resource in changed.get(kind, []):
                    resource["scope"] = A + "/global"
            if isinstance(data, dict) and "scope" in data:
                data.update(scope=A + "/global", Account=A, evaluation_scope="aws_account")
            after = check.evaluate(data, changed)[0]
            assert before == after, (check.id, name, before, after)
            checked.append((check.id, name))
    # 28 registered account-scope checks with pass and fail fixtures; the
    # excluded organizations delegated-administrator check no longer counts.
    assert len(checked) >= 56
