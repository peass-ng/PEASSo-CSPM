"""Semantic fixtures for the signed GuardDuty active-high scope predicate."""
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_aws_guardduty  # noqa: F401  (registration side effect)
from peaso.checks import CHECKS, evaluate_check


CHECK_ID = "aws_guardduty_no_active_high_findings"
SCOPE = "123456789012/us-east-1"


def detector(status="ENABLED", detector_id="det-inert", ids=()):
    return {"DetectorId": detector_id, "Configuration": {"Status": status},
            "FindingIds": {"collection_status": "collected" if ids else "empty", "items": list(ids)}}


def finding(severity=7.0, archived=False, account="123456789012", region="us-east-1", detector_id="det-inert", finding_id="finding-inert"):
    return {"Id": finding_id, "AccountId": account, "Region": region, "Severity": severity,
            "Service": {"DetectorId": detector_id, "Archived": archived}}


def scoped(detectors=None, findings=None, detector_status="collected", finding_status="collected", finding_scope=SCOPE):
    findings = [] if findings is None else findings
    detectors = [detector(ids=[row["Id"] for row in findings if isinstance(row.get("Id"), str)])] if detectors is None else detectors
    return {"collections": {
                "guardduty_detector": [{"scope": SCOPE, "status": detector_status}],
                "guardduty_finding": [{"scope": finding_scope, "status": finding_status}]},
            "guardduty_detector": [{"data": row} for row in detectors],
            "guardduty_finding": [{"data": row} for row in findings]}


def evaluate(index):
    return evaluate_check(CHECK_ID, {"scope": SCOPE}, index)


def test_high_severity_range_archive_and_scope():
    assert evaluate(scoped(findings=[]))[0] == "PASS"
    status, evidence = evaluate(scoped(findings=[finding(severity=7.0)]))
    assert status == "FAIL" and evidence["active_high_finding_ids"] == ["finding-inert"]
    assert evaluate(scoped(findings=[finding(severity=8.9)]))[0] == "FAIL"
    assert evaluate(scoped(findings=[finding(severity=9.0)]))[0] == "PASS"
    assert evaluate(scoped(findings=[finding(severity=6.9)]))[0] == "PASS"
    assert evaluate(scoped(findings=[finding(severity=8.0, archived=True)]))[0] == "PASS"
    assert evaluate(scoped(findings=[finding(account="999999999999")]))[0] == "PASS"
    assert evaluate(scoped(findings=[finding(account="999999999999", severity="foreign")]))[0] == "PASS"
    assert evaluate(scoped(findings=[finding(region="eu-west-1")]))[0] == "PASS"
    assert evaluate(scoped(detectors=[detector("DISABLED")], findings=[]))[0] == "NOT_APPLICABLE"
    assert evaluate(scoped(detectors=[], findings=[], detector_status="empty", finding_status="empty"))[0] == "NOT_APPLICABLE"
    second = finding(severity=8.1, detector_id="det-second", finding_id="second-finding")
    assert evaluate(scoped(detectors=[detector(ids=[]), detector(detector_id="det-second", ids=["second-finding"])],
                           findings=[second]))[0] == "FAIL"


def test_incomplete_or_malformed_inventory_never_passes():
    assert evaluate(scoped(findings=[], finding_status="partial"))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[], detector_status="denied"))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[], finding_scope="123456789012/eu-west-1"))[0] == "UNKNOWN"
    assert evaluate(scoped(detectors=[detector("FUTURE")]))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[finding(severity="8")]))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[finding(severity=True)]))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[finding(detector_id="other")]))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[finding(account="not-an-account")]))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[finding(region="not-a-region")]))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[finding() | {"_coverage": {"Service": {"status": "denied"}}}]))[0] == "UNKNOWN"
    assert evaluate(scoped(findings=[{"Id": "missing-fields"}]))[0] == "UNKNOWN"
    assert evaluate(scoped(detectors=[detector(ids=["lost-id"])], findings=[]))[0] == "UNKNOWN"
    assert evaluate(scoped(detectors=[detector(ids=[12])], findings=[]))[0] == "UNKNOWN"
