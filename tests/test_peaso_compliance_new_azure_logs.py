"""Workspace default-retention semantics and inventory completeness."""
import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_azure_logs as new


def verdict(days, *, threshold=None, status="collected"):
    item = {"properties": {"retentionInDays": days}}
    policy = {} if threshold is None else {"MinRetentionTime": threshold}
    index = new._index(status, policy)
    index["log_analytics_workspace"] = [{"data": item}]
    return evaluate_check(new.ID, item, index)


@pytest.mark.parametrize("days,status", [(365, "PASS"), (730, "PASS"), (364, "FAIL"), (30, "FAIL")])
def test_signed_365_day_default_threshold(days, status):
    actual, evidence = verdict(days)
    assert actual == status
    assert evidence["required_days"] == 365
    assert "table overrides" in evidence["semantics"]


def test_explicit_policy_threshold_is_honored_without_guessing_table_retention():
    assert verdict(180, threshold=180)[0] == "PASS"
    assert verdict(180, threshold=181)[0] == "FAIL"
    assert verdict(730, threshold=365)[0] == "PASS"


@pytest.mark.parametrize("value", [None, "365", True, {}, -1, 0])
def test_missing_or_malformed_retention_is_unknown(value):
    item = {"properties": {}} if value is None else {"properties": {"retentionInDays": value}}
    index = new._index()
    index["log_analytics_workspace"] = [{"data": item}]
    assert evaluate_check(new.ID, item, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("threshold", [0, -1, True, "365", {}, []])
def test_malformed_owner_threshold_is_unknown(threshold):
    assert verdict(365, threshold=threshold)[0] == "UNKNOWN"


def test_unreadable_or_partial_inventory_cannot_pass():
    assert verdict(365, status="denied")[0] == "UNKNOWN"
    assert verdict(365, status="partial")[0] == "UNKNOWN"
    assert evaluate_check(new.ID, {"collection_status": "denied"}, new._index())[0] == "UNKNOWN"
