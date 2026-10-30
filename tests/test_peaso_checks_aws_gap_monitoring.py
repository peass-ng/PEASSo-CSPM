"""AWS upstream-gap audit: CloudWatch metric-filter/alarm, account-contact and instance-role natives."""
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks import aws_gap_account as account
from peaso.checks import aws_gap_ec2 as ec2
from peaso.checks import aws_gap_metrics as metrics
from peaso.checks.fixtures import CASES

PACK = Path(__file__).resolve().parents[1] / "peaso" / "rulepacks"
REGISTRY = {check.id: check for check in CHECKS}
NATIVES = metrics.NATIVE_IDS + account.NATIVE_IDS + ec2.NATIVE_IDS
EXPECTED = {"pass": "PASS", "fail": "FAIL", "manual": "MANUAL", "unknown": "UNKNOWN"}


def _evaluate(cid, item, index):
    item_copy, index_copy = copy.deepcopy(item), copy.deepcopy(index)
    status = REGISTRY[cid].evaluate(item_copy, index_copy)[0]
    assert item_copy == item and index_copy == index, f"{cid} mutated its inputs"
    return status


def test_natives_registered():
    assert (len(metrics.NATIVE_IDS), len(account.NATIVE_IDS), len(ec2.NATIVE_IDS)) == (30, 1, 20)
    assert len(set(NATIVES)) == 51
    for cid in NATIVES:
        assert cid.startswith("aws.gap.") and cid in REGISTRY


@pytest.mark.parametrize("cid", NATIVES)
def test_behaviour_fixtures(cid):
    case = CASES[cid]
    assert {"pass", "fail"} <= set(case)
    default = case.get("index", {})
    for name, expected in EXPECTED.items():
        if name in case:
            assert _evaluate(cid, case[name], case.get(f"{name}_index", default)) == expected, (cid, name)
    for expected, item, index in case.get("variants", []):
        assert _evaluate(cid, item, default if index is None else index) == expected, cid
    assert any(v[0] == "UNKNOWN" for v in case.get("variants", [])) or "unknown" in case or cid in ec2.NATIVE_IDS


@pytest.mark.parametrize("cid", NATIVES)
def test_missing_or_denied_facts_never_pass(cid):
    default = CASES[cid].get("index", {})
    for item in ({}, None, {"collection_status": "denied"}):
        assert REGISTRY[cid].evaluate(item, default)[0] == "UNKNOWN"


# ------------------------------------------------------------------ FilterPattern semantics
CIS_ROOT = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'


def test_reference_patterns_match_their_family_events():
    for key, spec in metrics.FAMILIES.items():
        pattern = metrics.FilterPattern(spec[6])
        for probes in (spec[4], spec[5]):
            assert all(pattern.matches(event) for event in probes), key


def test_reordered_pattern_still_matches_and_negation_does_not():
    root = metrics.ROOT_USAGE[0]
    reordered = metrics.FilterPattern('{ ($.eventType != "AwsServiceEvent") && ($.userIdentity.invokedBy NOT EXISTS) && ($.userIdentity.type = "Root") }')
    assert reordered.matches(root)
    assert not metrics.FilterPattern('{ $.userIdentity.type != "Root" }').matches(root)
    assert not metrics.FilterPattern(CIS_ROOT).matches(metrics.api("s3.amazonaws.com", "ListBuckets", userIdentity={"type": "Root", "invokedBy": "x"}))


def test_wildcards_and_missing_fields():
    event = metrics.api("ec2.amazonaws.com", "RunInstances", errorCode="Client.UnauthorizedOperation")
    assert metrics.FilterPattern('{ $.errorCode = "*UnauthorizedOperation" }').matches(event)
    assert not metrics.FilterPattern('{ $.errorCode = "AccessDenied*" }').matches(event)
    assert not metrics.FilterPattern('{ $.missing.field = "x" }').matches(event)
    assert metrics.FilterPattern("").matches(event)


def test_precedence_ambiguity_is_not_coverage():
    # a || b && c: conventional (a || (b && c)) and left-to-right ((a || b) && c) disagree on this event.
    pattern = metrics.FilterPattern('{ $.eventName = "A" || $.eventName = "B" && $.eventSource = "x" }')
    with pytest.raises(metrics.PatternError):
        pattern.matches(metrics.api("y", "A"))


@pytest.mark.parametrize("text", ["%Root%", "Root", '{ $.eventName = %Create.*% }', '{ $.a = "x" '])
def test_unmodelled_patterns_raise(text):
    with pytest.raises(metrics.PatternError):
        metrics.FilterPattern(text)


# ------------------------------------------------------------------ metric identity counterexamples
LEAD = json.loads((PACK / "lead_audit_counterexamples.json").read_text())["cloudwatch_metric_identity_join"]["counterexample"]
FAMILY = metrics.FAMILIES["root_account_usage"]


def _alarm(**changes):
    alarm = {"AlarmName": "a", "AlarmArn": "arn:aws:cloudwatch:us-east-1:%s:alarm:a" % metrics.ACCOUNT, "MetricName": LEAD["filter"]["metric_name"],
             "Namespace": LEAD["filter"]["namespace"], "Dimensions": [], "ActionsEnabled": True, "AlarmActions": [metrics.TOPIC]}
    alarm.update(changes)
    return alarm


def _row(alarm):
    row = metrics._row(FAMILY[6], alarm=alarm, namespace=LEAD["filter"]["namespace"])
    row["MetricFilters"]["items"][0]["metricTransformations"][0]["metricName"] = LEAD["filter"]["metric_name"]
    return row


@pytest.mark.parametrize("cid", [metrics.PROWLER_NATIVES[FAMILY[1]], metrics.STEAMPIPE_NATIVES[FAMILY[2]]])
def test_same_name_other_namespace_or_dimension_alarm_is_not_coverage(cid):
    assert _evaluate(cid, metrics.ACCT, metrics._index(metrics.LOGGED, _row(_alarm()))) == "PASS"
    assert LEAD["source_match_by_name"] and not LEAD["same_actual_metric"]
    other_namespace = _row(_alarm(Namespace=LEAD["alarm"]["namespace"]))
    assert _evaluate(cid, metrics.ACCT, metrics._index(metrics.LOGGED, other_namespace)) == "FAIL"
    other_dimension = _row(_alarm(Dimensions=[{"Name": "Environment", "Value": "Unrelated"}]))
    assert _evaluate(cid, metrics.ACCT, metrics._index(metrics.LOGGED, other_dimension)) == "FAIL"


def test_alarm_in_another_region_is_not_coverage():
    cid = metrics.STEAMPIPE_NATIVES[FAMILY[2]]
    row = _row(_alarm())
    elsewhere = copy.deepcopy(row)
    elsewhere["id"], elsewhere["SourceRegion"] = "metric-alarm-coverage/%s/eu-west-1" % metrics.ACCOUNT, "eu-west-1"
    filters_only = copy.deepcopy(row)
    filters_only["MetricAlarms"]["items"] = []
    assert _evaluate(cid, metrics.ACCT, metrics._index(metrics.LOGGED, filters_only, elsewhere)) == "FAIL"


# ------------------------------------------------------------------ shard mapping
