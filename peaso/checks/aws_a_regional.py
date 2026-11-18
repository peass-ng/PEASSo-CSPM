"""Region-level security presence rules: observed empty differs from unavailable."""
from __future__ import annotations

from . import register, result, unknown
from .facts import get, list_of_objects
from .fixtures import CASES
from .aws_config_recording import canonical_recorder_status
from .aws_a_facts import complete_items, scope_subject, scope_fixture

NATIVE_IDS = []
SUBJECT = {"scope": "123456789012/us-east-1"}


@register("aws.a.guardduty.region_enabled", "aws", "hardening", "guardduty_detector",
    "GuardDuty is enabled in the selected region", "high", "SI-4",
    "Enable GuardDuty for the applicable region and review detector configuration.", target="scope", dependencies=["guardduty_detector"])
def guardduty_region(item, index):
    rows = complete_items(index, "guardduty_detector", scope_subject(item))
    if not rows:
        return result(True, detector="absent", semantics="Successfully collected empty regional detector inventory")
    if len(rows) != 1:
        return unknown("regional detector inventory is not unique")
    status = get(rows[0], "Configuration.Status", str)
    if status not in {"ENABLED", "DISABLED"}:
        return unknown("unrecognized detector status")
    return result(status != "ENABLED", status=status)
CASES["aws.a.guardduty.region_enabled"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "pass_index": scope_fixture("guardduty_detector", [{"Configuration": {"Status": "ENABLED"}}]),
    "fail_index": scope_fixture("guardduty_detector", []),
    "index": scope_fixture("guardduty_detector", [{"Configuration": {"Status": "ENABLED"}}])}
NATIVE_IDS.append("aws.a.guardduty.region_enabled")


@register("aws.a.config.region_recorder_enabled", "aws", "hardening", "config_recorder",
    "An AWS Config recorder is recording without a reported failure in the selected region", "high", "CM-8",
    "Configure and enable an applicable recorder and resolve reported failures.", target="scope", dependencies=["config_recorder"])
def config_region(item, index):
    rows = complete_items(index, "config_recorder", scope_subject(item))
    if not rows:
        return result(True, recorder="absent", semantics="Successfully collected empty regional recorder inventory")
    states = []
    for row in rows:
        name = get(row, "name", str)
        status_rows = list_of_objects(get(row, "Status.ConfigurationRecordersStatus", list))
        matching = [status for status in status_rows if get(status, "name", str) == name]
        if len(matching) != 1:
            return unknown("recorder status missing or ambiguous")
        recording = get(matching[0], "recording", bool)
        state = canonical_recorder_status(get(matching[0], "lastStatus", str))
        if state not in {"Pending", "Success", "Failure", "NotApplicable"}:
            return unknown("unrecognized native Config recorder state")
        states.append({"name": name, "recording": recording, "last_status": state})
    return result(any(not state["recording"] or state["last_status"] == "Failure" for state in states), recorders=states,
        semantics="Pinned Prowler predicate: recording and lastStatus is not Failure; Pending is distinct from Success")
GOOD_CONFIG = {"name": "default", "Status": {"ConfigurationRecordersStatus": [{"name": "default", "recording": True, "lastStatus": "Success"}]}}
CASES["aws.a.config.region_recorder_enabled"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "pass_index": scope_fixture("config_recorder", [GOOD_CONFIG]), "fail_index": scope_fixture("config_recorder", []),
    "index": scope_fixture("config_recorder", [GOOD_CONFIG])}
NATIVE_IDS.append("aws.a.config.region_recorder_enabled")
