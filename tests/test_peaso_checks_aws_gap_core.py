"""AWS upstream-gap audit: corrected native predicates and their framework links."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import aws_gap_core as gap
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS}
EXPECTED = {"pass": "PASS", "fail": "FAIL", "unknown": "UNKNOWN", "not_applicable": "NOT_APPLICABLE"}


def _evaluate(cid, item, index):
    item_copy, index_copy = copy.deepcopy(item), copy.deepcopy(index)
    status = REGISTRY[cid].evaluate(item_copy, index_copy)[0]
    assert item_copy == item and index_copy == index, f"{cid} mutated its inputs"
    return status


def test_gap_natives_registered_with_prefix():
    assert len(gap.NATIVE_IDS) == len(set(gap.NATIVE_IDS)) == 18
    for cid in gap.NATIVE_IDS:
        assert cid.startswith("aws.gap.") and cid in REGISTRY


@pytest.mark.parametrize("cid", gap.NATIVE_IDS)
def test_gap_behaviour_fixtures(cid):
    case = CASES[cid]
    assert {"pass", "fail"} <= set(case)
    default = case.get("index", {})
    for name, expected in EXPECTED.items():
        if name in case:
            assert _evaluate(cid, case[name], case.get(f"{name}_index", default)) == expected, (cid, name)
    for expected, item, index in case.get("variants", []):
        assert _evaluate(cid, item, default if index is None else index) == expected, cid


@pytest.mark.parametrize("cid", gap.NATIVE_IDS)
def test_gap_missing_or_denied_facts_never_pass(cid):
    default = CASES[cid].get("index", {})
    for item in ({}, None, {"collection_status": "denied"}):
        assert REGISTRY[cid].evaluate(item, default)[0] == "UNKNOWN"


def test_management_coverage_rejects_event_source_filters():
    trail = copy.deepcopy(gap.TRAIL)
    trail["EventSelectors"] = {"collection_status": "collected", "TrailARN": trail["TrailARN"], "AdvancedEventSelectors": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]},
        {"Field": "eventSource", "Equals": ["s3.amazonaws.com"]},
    ]}]}
    read, write, _ = gap.management_coverage(trail)
    assert not (read and write)


def test_s3_all_bucket_coverage_rejects_arn_filters():
    trail = copy.deepcopy(gap.TRAIL)
    trail["EventSelectors"] = {"collection_status": "collected", "TrailARN": trail["TrailARN"], "AdvancedEventSelectors": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
        {"Field": "resources.ARN", "StartsWith": ["arn:aws:s3:::only-this/"]},
    ]}]}
    assert gap.s3_data_coverage(trail, None, "aws") == (False, False)
    assert gap.s3_data_coverage(trail, "only-this", "aws") == (True, True)
