"""Independent native MFA proof; synthetic facts never certify a live tenant."""
import copy
from datetime import datetime, timezone, timedelta
import pytest
from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot, plan_collection, collect_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_conditional_access_native import API, SUB, SCOPE, CHECKS, ADMIN


def baseline(monkeypatch):
    now = datetime.now(timezone.utc)
    policy = {"sw13": {"status": "collected", "scope": SCOPE,
        "authorized_by": "security-owner", "document_id": "owner-obligation",
        "observed_at": (now-timedelta(days=1)).isoformat(),
        "expires_at": (now+timedelta(days=1)).isoformat(),
        "checks": {cid.replace(".", "|"): {
            "userScope": "administrative" if cid == ADMIN else "all",
            "designatedGroups": ["admin-group"], "designatedRoles": [],
            "requiredApplications": ["app-1"], "requiredClientAppTypes": ["browser"]}
            for cid in CHECKS}}}
    connector = {"provider": "azure", "scopes": [SUB],
                 "options": {"retries": 0, "compliance_policy": policy}}
    api = API("complete")
    monkeypatch.setattr(azure, "AzureTransport", lambda auth: api)
    monkeypatch.setattr(azure, "AzureTransportExposure", lambda auth: api)
    return collect_live(connector, plan_collection({"connector": connector, "checks": CHECKS}))


def selected_rule(snapshot, field, mode):
    env = next(e for e in snapshot["collections"] if e["type"] == "conditional_access_policy")
    valid = copy.deepcopy(env["items"][0])
    bad = copy.deepcopy(valid); bad["id"] = "ca-unreadable"
    if mode == "denied":
        bad.setdefault("_coverage", {})[field] = {"status": "denied"}
    elif mode == "missing":
        del bad[field]
    else:
        bad[field] = "not-an-object"
    return env, valid, bad


def outcomes(snapshot):
    supplied = make_snapshot("azure", snapshot["scopes"], snapshot["collections"],
        metadata=snapshot["metadata"], created_at=snapshot["created_at"])
    before = copy.deepcopy(supplied)
    connector = {"provider": "azure", "scopes": supplied["scopes"],
                 "options": {"snapshot": supplied}}
    admitted = collect_snapshot({"connector": connector, "checks": CHECKS})
    findings = evaluate_snapshot(admitted, checks=CHECKS, include_not_applicable=True)["findings"]
    assert supplied == before
    result = {cid: {f["status"] for f in findings if f["check_id"] == cid} for cid in CHECKS}
    assert all(result.values())
    return result


@pytest.mark.parametrize("field", ["conditions", "grantControls"])
def test_independent_universal_policy_survives_unreadable_peer_in_either_order(field, monkeypatch):
    source = baseline(monkeypatch)
    for mode in ("denied", "missing", "malformed"):
        for reverse in (False, True):
            snapshot = copy.deepcopy(source)
            env, valid, bad = selected_rule(snapshot, field, mode)
            env["items"] = [valid, bad] if reverse else [bad, valid]
            assert outcomes(snapshot) == {cid: {"PASS"} for cid in CHECKS}


def test_unreadable_candidates_without_sufficient_alternative_stay_unknown(monkeypatch):
    source = baseline(monkeypatch)
    for field in ("conditions", "grantControls"):
        for mode in ("denied", "missing", "malformed"):
            snapshot = copy.deepcopy(source)
            env, valid, bad = selected_rule(snapshot, field, mode)
            env["items"] = [bad]
            assert outcomes(snapshot) == {cid: {"UNKNOWN"} for cid in CHECKS}


@pytest.mark.parametrize("invalid", ["partial", "duplicate", "capture", "state"])
def test_independent_candidate_cannot_bypass_global_source_prerequisites(invalid, monkeypatch):
    snapshot = baseline(monkeypatch)
    env, valid, bad = selected_rule(snapshot, "conditions", "denied")
    env["items"] = [valid, bad]
    if invalid == "partial":
        env["status"] = "partial"
    elif invalid == "duplicate":
        bad["id"] = valid["id"]
    elif invalid == "capture":
        bad["_provenance"]["customer_context_id"] = "foreign-customer"
    else:
        bad["state"] = "unrecognized-state"
    assert outcomes(snapshot) == {cid: {"UNKNOWN"} for cid in CHECKS}
