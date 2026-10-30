"""Signed ACM expiry boundary and incomplete-inventory fixtures."""

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_aws_acm_expiry as acm
from peaso.checks.facts import MemoIndex
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks import CHECKS, evaluate_check


FEDRAMP = "aws_fedramp_acm_all_certificates_30_day_expiry"
NIST_CLOSED = "aws.nist.acm_all_certificates_expiry_30_days"
NIST_STRICT = "aws_nist_acm_certificate_expires_30_days"
G6_DATE = "aws_g6_acm_all_certificates_30_day_expiry"
IDS = (FEDRAMP, NIST_CLOSED, NIST_STRICT, G6_DATE)
SCOPE = "123456789012/eu-west-1"


def certificate(suffix="a", *, status="ISSUED", expires="2026-11-11T00:00:00Z",
                eligibility="ELIGIBLE"):
    return {"CertificateArn": f"arn:aws:acm:eu-west-1:123456789012:certificate/{suffix}",
            "CertificateKeyPairOrigin": "ACME",
            "Certificate": {"collection_status": "collected", "Certificate": {
                "Status": status, "NotAfter": expires, "RenewalEligibility": eligibility}}}


def index(rows, *, status="collected", clock="2026-10-12T00:00:00Z"):
    return {"context": {"created_at": clock},
            "collections": {"acm_certificate": [{"type": "acm_certificate", "scope": SCOPE,
                                                 "status": status, "items": rows}]},
            "acm_certificate": [{"type": "acm_certificate", "scope": SCOPE, "data": row}
                                for row in rows]}


def evaluate(check_id, row, rows=None, **kwargs):
    return evaluate_check(check_id, row, index(rows if rows is not None else [row], **kwargs))


def test_exact_instant_and_calendar_boundaries_do_not_merge():
    exactly = certificate()
    assert evaluate(FEDRAMP, exactly)[0] == "FAIL"
    assert evaluate(NIST_CLOSED, exactly)[0] == "FAIL"
    assert evaluate(NIST_STRICT, exactly)[0] == "PASS"
    assert evaluate(G6_DATE, exactly)[0] == "PASS"
    before = certificate(expires="2026-11-10T23:59:59Z", eligibility="INELIGIBLE")
    assert all(evaluate(check_id, before)[0] == "FAIL" for check_id in IDS)
    same_date = certificate(expires="2026-11-11T00:00:01Z")
    assert all(evaluate(check_id, same_date)[0] == "PASS" for check_id in IDS)
    # Calendar policy does not fail for earlier hours on the threshold date.
    shifted = certificate(expires="2026-11-11T11:00:00Z")
    assert evaluate(G6_DATE, shifted, clock="2026-10-12T12:00:00Z")[0] == "PASS"
    assert evaluate(NIST_STRICT, shifted, clock="2026-10-12T12:00:00Z")[0] == "FAIL"


def test_issued_applicability_and_renewal_eligibility_independence():
    pending = certificate(status="PENDING_VALIDATION", expires="2026-10-13T00:00:00Z")
    assert evaluate(FEDRAMP, pending)[0] == "FAIL"
    assert evaluate(G6_DATE, pending)[0] == "FAIL"
    assert evaluate(NIST_CLOSED, pending)[0] == "NOT_APPLICABLE"
    assert evaluate(NIST_STRICT, pending)[0] == "NOT_APPLICABLE"
    ineligible = certificate(eligibility="INELIGIBLE", expires="2026-10-13T00:00:00Z")
    assert all(evaluate(check_id, ineligible)[0] == "FAIL" for check_id in IDS)


def test_absent_denied_malformed_and_truncated_facts_stay_unknown():
    safe = certificate(expires="2026-12-01T00:00:00Z")
    assert all(evaluate(check_id, safe, status="partial")[0] == "UNKNOWN" for check_id in IDS)
    missing = certificate()
    del missing["Certificate"]["Certificate"]["NotAfter"]
    assert all(evaluate(check_id, missing)[0] == "UNKNOWN" for check_id in IDS)
    denied = certificate()
    denied["Certificate"] = {"collection_status": "denied", "error": {"code": "AccessDeniedException"}}
    assert all(evaluate(check_id, denied)[0] == "UNKNOWN" for check_id in IDS)
    malformed = certificate(expires="not-a-time")
    assert all(evaluate(check_id, malformed)[0] == "UNKNOWN" for check_id in IDS)
    assert all(evaluate(check_id, safe, clock="not-a-time")[0] == "UNKNOWN" for check_id in IDS)
    other = certificate("b")
    other["Certificate"] = {"collection_status": "denied"}
    assert all(evaluate(check_id, safe, [safe, other])[0] == "UNKNOWN" for check_id in IDS)
    expired = certificate(expires="2026-10-20T00:00:00Z")
    assert all(evaluate(check_id, expired, [expired, other])[0] == "FAIL" for check_id in IDS)


def test_ambiguous_identity_or_detached_source_never_passes():
    safe = certificate(expires="2026-12-01T00:00:00Z")
    duplicate = certificate(expires="2026-11-01T00:00:00Z")
    assert all(evaluate(check_id, safe, [safe, duplicate])[0] == "UNKNOWN" for check_id in IDS)
    detached = certificate(expires="2027-01-01T00:00:00Z")
    assert all(evaluate(check_id, detached, [safe])[0] == "UNKNOWN" for check_id in IDS)


def test_memoized_scope_validates_many_details_once_per_population(monkeypatch):
    rows = [certificate(str(i), expires="2026-12-01T00:00:00Z") for i in range(64)]
    scoped = MemoIndex(index(rows))
    original = acm._instant
    calls = []

    def counted(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(acm, "_instant", counted)
    for row in rows:
        for check_id in IDS:
            assert evaluate_check(check_id, row, scoped)[0] == "PASS"
    assert len(calls) == 2 * len(rows)
    assert set(scoped.memo) >= {("acm_expiry_inventory", False), ("acm_expiry_inventory", True)}


def test_production_engine_scopes_complete_certificate_inventory():
    row = certificate(expires="2026-10-20T00:00:00Z")
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "acm_certificate", "scope": SCOPE,
        "service": "acm", "status": "collected", "items": [row]}],
        created_at="2026-10-12T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=list(IDS))
    findings = [finding for finding in report["findings"] if finding["check_id"] in IDS]
    assert len(findings) == 4 and all(finding["status"] == "FAIL" for finding in findings)
