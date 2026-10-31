"""Output metadata contracts; statuses and evaluator facts remain unchanged."""
import copy

import pytest

from peaso.report_quality import normalize_unknown_reasons


@pytest.mark.parametrize("evidence,reason", [
    ({"gaps": [{"type": "iam_user", "status": "not_collected"}]}, "incomplete_inventory: iam_user(not_collected)"),
    ({"dependencies": [{"type": "vpc_endpoint", "status": "denied"}]}, "incomplete_inventory: vpc_endpoint(denied)"),
    ({"conditions": ["target_inventory_not_collected"]}, "unresolved_conditions: target_inventory_not_collected"),
    ({"missing_facts": [{"field": "ServicesLastAccessed"}]}, "missing_facts: ServicesLastAccessed"),
    ({"missing_fields": ["Attributes.DisableApiTermination"]}, "missing_facts: Attributes.DisableApiTermination"),
    ({"unresolved": [{"layer": "authorization", "reason": "downstream access unresolved"}]},
     "unresolved: authorization: downstream access unresolved"),
    ({}, "unknown_reason_not_supplied"),
])
def test_unknown_reason_uses_existing_evidence_only(evidence, reason):
    finding = {"id": "stable", "check_id": "fixture", "status": "UNKNOWN", "evidence": evidence}
    before = copy.deepcopy(finding)
    normalized = normalize_unknown_reasons([finding])[0]
    assert finding == before
    assert normalized == dict(before, evidence=dict(evidence, reason=reason))
    assert normalize_unknown_reasons([normalized])[0] is normalized


def test_existing_reason_and_nonunknown_metadata_are_preserved():
    findings = [{"status": status, "evidence": {"conditions": ["missing_inventory"]}} for status in
                ("PASS", "FAIL", "DENIED", "MANUAL", "EMPTY", "NOT_APPLICABLE")]
    findings.append({"status": "UNKNOWN", "evidence": {"reason": "original exact reason", "gaps": [{"type": "iam_user"}]}})
    output = normalize_unknown_reasons(findings)
    assert all(a is b for a, b in zip(findings, output))


def test_whitespace_invalid_reason_and_top_level_reason():
    findings = [{"status": "UNKNOWN", "evidence": {"reason": "  "}, "reason": "source_reason"},
                {"status": "UNKNOWN", "evidence": {"reason": None, "conditions": ["z", "a", "a"]}},
                {"status": "UNKNOWN", "evidence": None}]
    output = normalize_unknown_reasons(findings)
    assert [f["evidence"]["reason"] for f in output] == ["source_reason", "unresolved_conditions: a, z", "unknown_reason_not_supplied"]


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "k8s"])
def test_demo_report_unknowns_have_explicit_reasons(provider, monkeypatch):
    import json
    from collections import Counter
    from peaso import engine
    from peaso.demo import demo_snapshot
    from peaso.engine import compact_report, evaluate_snapshot, expand_report
    snapshot = demo_snapshot(provider)
    # Compare the same evaluator/facts with only the output helper disabled.
    with monkeypatch.context() as context:
        context.setattr(engine, "normalize_unknown_reasons", lambda findings: findings)
        baseline = evaluate_snapshot(snapshot, include_not_applicable=False)
    report = evaluate_snapshot(snapshot, include_not_applicable=False)
    assert len(report["findings"]) == len(baseline["findings"])
    assert [f["id"] for f in report["findings"]] == [f["id"] for f in baseline["findings"]]
    assert Counter(f["status"] for f in report["findings"]) == Counter(f["status"] for f in baseline["findings"])
    assert report["stats"] == baseline["stats"]
    restored = copy.deepcopy(report)
    for finding, previous in zip(restored["findings"], baseline["findings"]):
        reason = previous["evidence"].get("reason")
        if finding["status"] == "UNKNOWN" and not (isinstance(reason, str) and reason.strip()):
            if "reason" in previous["evidence"]:
                finding["evidence"]["reason"] = previous["evidence"]["reason"]
            else:
                finding["evidence"].pop("reason", None)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert canonical(restored) == canonical(baseline)
    assert canonical(compact_report(expand_report(report, snapshot))) == canonical(report)
    for finding in report["findings"]:
        if finding["status"] == "UNKNOWN":
            assert isinstance(finding["evidence"].get("reason"), str)
            assert finding["evidence"]["reason"].strip()


def test_scan_path_uses_one_reason_hook(monkeypatch):
    from peaso import engine
    from peaso.demo import demo_snapshot
    from peaso.engine import scan
    snapshot = demo_snapshot("aws")
    calls = []
    original = engine.normalize_unknown_reasons
    def record(findings):
        calls.append(len(findings))
        return original(findings)
    monkeypatch.setattr(engine, "normalize_unknown_reasons", record)
    report, _ = scan({"connector": {"provider": "aws", "options": {"snapshot": snapshot}}})
    assert calls == [len(report["findings"])]
    assert all(f["evidence"].get("reason") for f in report["findings"] if f["status"] == "UNKNOWN")


def test_related_snapshot_path_uses_one_reason_hook(monkeypatch):
    from peaso import engine
    from peaso.demo import demo_snapshot
    from peaso.engine import evaluate_snapshot
    calls = []
    original = engine.normalize_unknown_reasons
    def record(findings):
        calls.append(len(findings))
        return original(findings)
    monkeypatch.setattr(engine, "normalize_unknown_reasons", record)
    report = evaluate_snapshot(demo_snapshot("gcp"), include_not_applicable=False,
                               related_snapshots=[demo_snapshot("k8s")])
    assert calls == [len(report["findings"])]
    assert all(f["evidence"].get("reason") for f in report["findings"] if f["status"] == "UNKNOWN")
