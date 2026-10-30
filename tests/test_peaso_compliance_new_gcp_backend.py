"""Semantic fixture for the signed backend cookie-affinity TTL check."""
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_gcp_backend  # noqa: F401  (registration side effect)


CHECK_ID = "gcp_cloudcdn_cookie_ttl"


def evaluate(item):
    return evaluate_check(CHECK_ID, item, {})


def backend(**fields):
    return {"name": "inert-backend", "_provenance": {"representation": "full"}, **fields}


def test_cookie_ttl_enforces_signed_modes_and_range_only():
    assert evaluate(backend(sessionAffinity="GENERATED_COOKIE", affinityCookieTtlSec=1800))[0] == "PASS"
    assert evaluate(backend(sessionAffinity="HTTP_COOKIE", affinityCookieTtlSec=1801))[0] == "FAIL"
    assert evaluate(backend(sessionAffinity="HTTP_COOKIE", affinityCookieTtlSec=0))[0] == "PASS"
    assert evaluate(backend(sessionAffinity="CLIENT_IP", affinityCookieTtlSec=999999))[0] == "NOT_APPLICABLE"
    assert evaluate(backend(sessionAffinity="STRONG_COOKIE_AFFINITY", affinityCookieTtlSec=999999))[0] == "NOT_APPLICABLE"
    assert evaluate(backend(affinityCookieTtlSec=999999))[0] == "UNKNOWN"
    assert evaluate(backend(sessionAffinity="HTTP_COOKIE"))[0] == "UNKNOWN"
    assert evaluate(backend(sessionAffinity="HTTP_COOKIE", affinityCookieTtlSec="1800"))[0] == "UNKNOWN"
    assert evaluate(backend(sessionAffinity="HTTP_COOKIE", affinityCookieTtlSec=1209601))[0] == "UNKNOWN"
    assert evaluate(backend(sessionAffinity="FUTURE_MODE", affinityCookieTtlSec=900))[0] == "UNKNOWN"
    assert evaluate({"name": "inert-backend", "sessionAffinity": "HTTP_COOKIE", "affinityCookieTtlSec": 900})[0] == "UNKNOWN"
    assert evaluate(backend(sessionAffinity="HTTP_COOKIE", affinityCookieTtlSec=900,
                            _coverage={"affinityCookieTtlSec": {"status": "denied"}}))[0] == "UNKNOWN"
    assert evaluate(backend(sessionAffinity="HTTP_COOKIE", affinityCookieTtlSec=900,
                            collection_status="denied"))[0] == "UNKNOWN"
