"""Narrowed scans read only selected content; unrequested content checks are skipped, not UNKNOWN."""
from peaso.content_scan_selection import normalize_request
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot

LAMBDA_ENV = "aws.review.lambda.selected_environment_secret_indicators"
LAMBDA_PACKAGE = "aws.review.lambda_function.package_content_secret_indicators"
LOGS = "aws.review.cloudwatch.sampled_log_secret_indicators"


def _request(**selectors):
    return {"connector": {"provider": "aws", "scopes": ["111122223333"], "auth": {"method": "default"},
                          "options": {"content_secret_scans": True}}, "leaks_enabled": True, **selectors}


def test_selected_checks_narrow_enabled_content_scanning():
    assert LOGS in normalize_request(_request())["content_checks"]
    narrowed = normalize_request(_request(checks=[LAMBDA_ENV]))
    assert narrowed["content_checks"] == [LAMBDA_ENV]
    assert "log_group" in plan_collection(_request())
    assert "log_group" not in plan_collection(_request(checks=[LAMBDA_ENV]))


def _report(plan):
    metadata = {"collection_plan": plan} if plan is not None else None
    snapshot = make_snapshot("aws", ["111122223333/us-east-1"], [], created_at="2026-10-10T00:00:00+00:00", metadata=metadata)
    return evaluate_snapshot(snapshot, categories=["hardening"])


def test_content_checks_are_skipped_when_content_scanning_was_off():
    report = _report({"content_checks": []})
    assert LAMBDA_PACKAGE not in {f["check_id"] for f in report["findings"]}
    assert LAMBDA_PACKAGE in report["skipped_opt_in_checks"]["check_ids"]
    requested = _report({"content_checks": [LAMBDA_PACKAGE]})
    assert LAMBDA_PACKAGE in {f["check_id"] for f in requested["findings"]}
    assert LAMBDA_PACKAGE not in requested.get("skipped_opt_in_checks", {}).get("check_ids", [])
