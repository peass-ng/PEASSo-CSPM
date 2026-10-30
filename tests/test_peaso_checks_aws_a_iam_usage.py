"""Strict cutoff/null/enabled/root and timezone truth cases for the credential-report checks."""
import copy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

IDS = ("aws.a.iam.unused_credentials_45_days", "aws.a.iam.unused_credentials_90_days")
REGISTRY = {c.id: c for c in CHECKS if c.id in IDS}
INDEX = CASES[IDS[0]]["index"]
REPORT = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)


def row():
    """A current, identity-bound report row with only the console password enabled and recently used."""
    item = copy.deepcopy(CASES[IDS[0]]["pass"])
    item.update({"access_key_1_active": "false", "access_key_1_last_rotated": "N/A",
                 "access_key_1_last_used_date": "N/A"})
    return item


def test_both_thresholds_are_registered():
    assert set(REGISTRY) == set(IDS)


@pytest.mark.parametrize("cid", IDS)
def test_usage_source_variants_have_real_states_without_mutation(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN"),
                            ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(cases[state])
        before = copy.deepcopy(item)
        assert check.evaluate(item, cases["index"])[0] == expected
        assert item == before
    assert check.evaluate({"collection_status": "denied"}, cases["index"])[0] == "UNKNOWN"


@pytest.mark.parametrize("days", [45, 90])
def test_exact_report_cutoff_is_strict_less_than_not_age_floor(days):
    check = REGISTRY[f"aws.a.iam.unused_credentials_{days}_days"]
    cutoff = REPORT - timedelta(days=days)
    item = row()
    item["password_last_used"] = cutoff.isoformat()
    assert check.evaluate(item, INDEX)[0] == "PASS"
    item["password_last_used"] = (cutoff - timedelta(seconds=1)).isoformat()
    assert check.evaluate(item, INDEX)[0] == "FAIL"


@pytest.mark.parametrize("days", [45, 90])
def test_active_key_null_last_use_falls_back_to_rotation_date_but_disabled_key_is_skipped(days):
    check = REGISTRY[f"aws.a.iam.unused_credentials_{days}_days"]
    item = row()
    item.update({"access_key_1_active": "true", "access_key_1_last_used_date": "N/A",
                 "access_key_1_last_rotated": "2026-01-01T00:00:00+00:00"})
    assert check.evaluate(item, INDEX)[0] == "FAIL"
    item["access_key_1_active"] = "false"
    assert check.evaluate(item, INDEX)[0] == "PASS"


def test_recent_credential_without_recorded_use_stays_unresolved():
    item = row()
    item.update({"access_key_1_active": "true", "access_key_1_last_used_date": "N/A",
                 "access_key_1_last_rotated": (REPORT - timedelta(days=3)).isoformat()})
    assert REGISTRY[IDS[0]].evaluate(item, INDEX)[0] == "UNKNOWN"


def test_45_and_90_days_are_distinct_security_thresholds():
    item = row()
    item["password_last_used"] = (REPORT - timedelta(days=60)).isoformat()
    assert REGISTRY["aws.a.iam.unused_credentials_45_days"].evaluate(item, INDEX)[0] == "FAIL"
    assert REGISTRY["aws.a.iam.unused_credentials_90_days"].evaluate(item, INDEX)[0] == "PASS"


def test_missing_clock_fields_and_unrecognized_report_values_stay_unknown():
    check = REGISTRY["aws.a.iam.unused_credentials_45_days"]
    item = row()
    assert check.evaluate(item, {})[0] == "UNKNOWN"
    stale = copy.deepcopy(item)
    stale.pop("ReportGeneratedTime")
    assert check.evaluate(stale, INDEX)[0] == "UNKNOWN"
    item["password_last_used"] = "not-a-date"
    assert check.evaluate(item, INDEX)[0] == "UNKNOWN"


def test_naive_timestamp_is_not_assumed_to_be_utc():
    item = row()
    item["password_last_used"] = "2026-10-20T10:00:00"
    assert REGISTRY[IDS[0]].evaluate(item, INDEX)[0] == "UNKNOWN"
