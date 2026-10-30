"""Stage-declared API Gateway logging and cache encryption source boundaries."""
from __future__ import annotations

import copy

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_aws_apigateway as api
from peaso.checks.facts import MemoIndex
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


SCOPE = "123456789012/us-east-1"
ARN = "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod"


def stage(settings=None, **extra):
    return {"id": ARN, "ParentApiId": "abc123", "stageName": "prod",
        "_provenance": {"source_operation": "get_stages", "parent_api_id": "abc123",
            "read_only": True},
        "methodSettings": {"*/*": {"loggingLevel": "INFO", "cachingEnabled": True,
            "cacheDataEncrypted": True}} if settings is None else settings,
        "cacheClusterEnabled": True, "cacheClusterStatus": "AVAILABLE", **extra}


def scoped(rows, *, status="collected", scope=SCOPE):
    return {"context": {"provider": "aws", "scope": scope},
        "collections": {"rest_api_stage": [{"type": "rest_api_stage", "scope": scope,
            "status": status, "items": rows}]},
        "rest_api_stage": [{"type": "rest_api_stage", "scope": scope, "data": row}
            for row in rows]}


def evaluate(check_id, row, *, rows=None, **kwargs):
    return evaluate_check(check_id, row, scoped([row] if rows is None else rows, **kwargs))


def test_logging_declared_default_override_and_unknown_coverage():
    safe = stage({"*/*": {"loggingLevel": "ERROR"},
                  "~1pets/GET": {"loggingLevel": "INFO"}})
    assert evaluate(api.LOGGING_ID, safe)[0] == "PASS"
    unsafe = stage({"*/*": {"loggingLevel": "INFO"},
                    "~1pets/GET": {"loggingLevel": "OFF"}})
    status, evidence = evaluate(api.LOGGING_ID, unsafe)
    assert status == "FAIL" and evidence["unsafe_method_overrides"] == ["~1pets/GET"]
    assert evaluate(api.LOGGING_ID, stage({"*/*": {"loggingLevel": "OFF"}}))[0] == "UNKNOWN"
    assert evaluate(api.LOGGING_ID, stage({"~1pets/GET": {"loggingLevel": "INFO"}}))[0] == "UNKNOWN"
    assert evaluate(api.LOGGING_ID, stage({"*/*": {"loggingLevel": "INFO"},
                                           "~1pets/GET": {"metricsEnabled": True}}))[0] == "UNKNOWN"
    assert evaluate(api.LOGGING_ID, stage({"*/*": {"loggingLevel": "TRACE"}}))[0] == "UNKNOWN"


def test_cache_encryption_only_when_effectively_enabled():
    safe = stage({"*/*": {"cachingEnabled": True, "cacheDataEncrypted": True},
                  "~1pets/GET": {"cachingEnabled": True, "cacheDataEncrypted": True}})
    assert evaluate(api.CACHE_ID, safe)[0] == "PASS"
    unsafe = stage({"*/*": {"cachingEnabled": True, "cacheDataEncrypted": True},
                    "~1pets/GET": {"cachingEnabled": True, "cacheDataEncrypted": False}})
    status, evidence = evaluate(api.CACHE_ID, unsafe)
    assert status == "FAIL" and evidence["unencrypted_enabled_overrides"] == ["~1pets/GET"]
    assert evaluate(api.CACHE_ID, stage({"*/*": {"cachingEnabled": False}}))[0] == "NOT_APPLICABLE"
    assert evaluate(api.CACHE_ID, stage({"*/*": {"cachingEnabled": False},
        "~1pets/GET": {"cachingEnabled": True, "cacheDataEncrypted": True}}))[0] == "PASS"
    assert evaluate(api.CACHE_ID, stage({"*/*": {"cachingEnabled": True,
        "cacheDataEncrypted": False}}))[0] == "UNKNOWN"
    assert evaluate(api.CACHE_ID, stage({"*/*": {"cachingEnabled": True,
        "cacheDataEncrypted": True}, "~1pets/GET": {"cachingEnabled": True}}))[0] == "UNKNOWN"
    assert evaluate(api.CACHE_ID, stage({"~1pets/GET": {"cachingEnabled": True,
        "cacheDataEncrypted": True}}))[0] == "UNKNOWN"


def test_disabled_or_transitioning_cluster_and_missing_provenance():
    disabled = stage({"*/*": {"cachingEnabled": True, "cacheDataEncrypted": False}},
                     cacheClusterEnabled=False, cacheClusterStatus="NOT_AVAILABLE")
    assert evaluate(api.CACHE_ID, disabled)[0] == "NOT_APPLICABLE"
    disabled.pop("methodSettings")
    assert evaluate(api.CACHE_ID, disabled)[0] == "NOT_APPLICABLE"
    assert evaluate(api.CACHE_ID, stage(cacheClusterEnabled=False,
        cacheClusterStatus="AVAILABLE"))[0] == "UNKNOWN"
    assert evaluate(api.CACHE_ID, stage(cacheClusterStatus="CREATE_IN_PROGRESS"))[0] == "UNKNOWN"
    assert evaluate(api.CACHE_ID, stage(cacheClusterStatus="FUTURE"))[0] == "UNKNOWN"
    untrusted = stage(_provenance={"source_operation": "get_stage"})
    assert evaluate(api.LOGGING_ID, untrusted)[0] == "UNKNOWN"
    assert evaluate(api.CACHE_ID, untrusted)[0] == "UNKNOWN"


def test_partial_denied_malformed_and_duplicate_stage_facts_stay_unknown():
    row = stage()
    for check_id in (api.LOGGING_ID, api.CACHE_ID):
        assert evaluate(check_id, row, status="partial")[0] == "UNKNOWN"
        assert evaluate(check_id, row, status="denied")[0] == "UNKNOWN"
        assert evaluate(check_id, row, rows=[row, copy.deepcopy(row)])[0] == "UNKNOWN"
        assert evaluate(check_id, row, scope="123456789012/eu-west-1")[0] == "UNKNOWN"
        assert evaluate(check_id, stage(ParentApiId="other"))[0] == "UNKNOWN"
        assert evaluate(check_id, stage({"/pets/GET": {"loggingLevel": "INFO"}}))[0] == "UNKNOWN"
    masked = stage({"*/*": {"_coverage": {"loggingLevel": {"status": "denied"}},
                            "loggingLevel": "INFO"}})
    assert evaluate(api.LOGGING_ID, masked)[0] == "UNKNOWN"


def test_historical_internal_rest_stage_id_is_source_bound():
    legacy = stage(id=ARN.replace("/restapis/", "/apis/"))
    assert evaluate(api.LOGGING_ID, legacy)[0] == "PASS"
    assert evaluate(api.CACHE_ID, legacy)[0] == "PASS"
    untrusted = stage(id=legacy["id"], _provenance={"source_operation": "get_stage"})
    assert evaluate(api.LOGGING_ID, untrusted)[0] == "UNKNOWN"
    assert evaluate(api.CACHE_ID, untrusted)[0] == "UNKNOWN"


def test_many_stages_validate_identity_once_per_memo_index(monkeypatch):
    rows = [stage(id=ARN.replace("/prod", f"/stage{number}"),
                  stageName=f"stage{number}") for number in range(64)]
    index = MemoIndex(scoped(rows))
    original = api.complete_items
    calls = []

    def counted(facts, kind):
        calls.append(kind)
        return original(facts, kind)

    monkeypatch.setattr(api, "complete_items", counted)
    for row in rows:
        assert evaluate_check(api.LOGGING_ID, row, index)[0] == "PASS"
        assert evaluate_check(api.CACHE_ID, row, index)[0] == "PASS"
    assert calls == ["rest_api_stage"]


def test_repeat_evaluation_is_immutable_and_ignores_current_rest_api_resources():
    row = stage({"*/*": {"loggingLevel": "INFO", "cachingEnabled": True,
                          "cacheDataEncrypted": True}})
    facts = scoped([row])
    original_row, original_index = copy.deepcopy(row), copy.deepcopy(facts)
    for _ in range(3):
        assert evaluate_check(api.LOGGING_ID, row, facts)[0] == "PASS"
        assert evaluate_check(api.CACHE_ID, row, facts)[0] == "PASS"
    assert row == original_row and facts == original_index
    snapshot = make_snapshot("aws", [SCOPE], [
        {"type": "rest_api_stage", "scope": SCOPE, "service": "apigateway",
         "status": "collected", "items": [row]},
        {"type": "rest_api", "scope": SCOPE, "service": "apigateway",
         "status": "collected", "items": [{"id": "abc123", "Resources": {
             "items": [{"path": "/pets", "resourceMethods": {"GET": {"loggingLevel": "OFF"}}}]}}]},
    ], created_at="2026-10-12T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening"],
                               checks=[api.LOGGING_ID, api.CACHE_ID])
    findings = {finding["check_id"]: finding for finding in report["findings"]
                if finding["check_id"] in (api.LOGGING_ID, api.CACHE_ID)}
    assert {check_id: row["status"] for check_id, row in findings.items()} == {
        api.LOGGING_ID: "PASS", api.CACHE_ID: "PASS"}
