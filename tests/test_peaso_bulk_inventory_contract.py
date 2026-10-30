# Historical fixture contracts; current native admission is tested separately.
"""Signed partial definitions never masquerade as native evidence producers."""
import copy
from importlib import import_module

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.collectors import collect_live, supported_types
from peaso.collectors.bulk_evidence import coverage, declared_types
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot, validate
from tests.release_successor_history import BULK_IDS


SCOPES = {
    "aws": "123456789012",
    "azure": "/subscriptions/00000000-0000-0000-0000-000000000001",
    "gcp": "projects/fixture-project",
    "k8s": "fixture-cluster",
}


def partial_checks(provider):
    native = set(supported_types(provider))
    return [check for check in CHECKS if check.provider == provider
            and check.id in BULK_IDS and set(check.dependencies) - native]


def stub_native(monkeypatch, provider):
    module = import_module("peaso.collectors." + provider)
    native = set(getattr(module, "AWS_TYPES", getattr(module, "SUPPORTED_TYPES", getattr(module, "TYPES", ()))))
    calls = []

    def collect(connector, requirements):
        if requirements is not None:
            assert set(requirements) <= native
        if "inventories" in connector.get("options", {}):
            assert set(connector["options"]["inventories"]) <= native
        calls.append((copy.deepcopy(connector), requirements))
        return make_snapshot(provider, connector["scopes"], [], metadata={"native_stub": True})

    monkeypatch.setattr(module, "collect", collect)
    return calls


def test_only_the_exact_signed_bulk_can_require_declared_unavailable_facts():
    for check in CHECKS:
        missing = set(check.dependencies) - set(supported_types(check.provider))
        assert missing <= declared_types(check.provider), (check.id, missing)
        if missing:
            assert evaluate_check(check.id, None, {})[0] == "UNKNOWN", check.id
            assert evaluate_check(check.id, {"collection_status": "denied"}, {})[0] == "UNKNOWN", check.id


@pytest.mark.parametrize("provider", tuple(SCOPES))
def test_every_unavailable_type_is_explicit_and_dispatches_to_not_collected(provider, monkeypatch):
    calls = stub_native(monkeypatch, provider)
    native = set(supported_types(provider))
    missing = declared_types(provider) - native
    assert missing == set(coverage()[provider]["unavailable_projections"])
    assert not missing & native
    for kind in sorted(missing):
        for explicit_inventory in (False, True):
            connector = {"provider": provider, "scopes": [SCOPES[provider]],
                         "options": {"inventories": [kind]} if explicit_inventory else {}}
            before = copy.deepcopy(connector)
            snapshot = validate(collect_live(connector, None if explicit_inventory else [kind]))
            assert connector == before
            assert snapshot["metadata"]["intentional_partial"] is True
            assert snapshot["metadata"]["bulk_evidence"]["unavailable_projections"] == [kind]
            rows = [row for row in snapshot["collections"] if row["type"] == kind]
            assert len(rows) == 1, kind
            assert rows[0]["scope"] == SCOPES[provider]
            assert rows[0]["status"] == "not_collected" and rows[0]["items"] == [], kind
            assert rows[0]["error"]["code"] == "native_evidence_projection_unavailable", kind
    assert len(calls) == 2 * len(missing)


@pytest.mark.parametrize("provider", tuple(SCOPES))
def test_selected_partial_checks_keep_all_missing_facts_in_plan_and_report(provider, monkeypatch):
    checks = partial_checks(provider)
    if not checks:
        # A provider may now implement every declared producer. Simulate an
        # unavailable producer to retain this missing-evidence contract test.
        from peaso import collectors
        module = import_module("peaso.collectors." + provider)
        attribute = next(name for name in ("AWS_TYPES", "SUPPORTED_TYPES", "TYPES")
                         if hasattr(module, name))
        available = set(getattr(module, attribute))
        used = {kind for check in CHECKS if check.provider == provider and check.id in BULK_IDS
                for kind in check.dependencies}
        removable = sorted(available & declared_types(provider) & used)
        assert removable, provider
        monkeypatch.setitem(collectors.TYPES, provider, collectors.TYPES[provider])
        monkeypatch.setattr(module, attribute, tuple(sorted(available - {removable[0]})))
        checks = partial_checks(provider)
    assert checks, provider
    stub_native(monkeypatch, provider)
    native = set(supported_types(provider))
    expected_missing = {kind for check in checks for kind in check.dependencies if kind not in native}
    request = {"connector": {"provider": provider, "scopes": [SCOPES[provider]], "options": {}},
               "checks": [check.id for check in checks]}
    snapshot = collect_snapshot(request)
    plan = snapshot["metadata"]["collection_plan"]
    assert expected_missing <= set(plan["requirements"])
    assert set(snapshot["metadata"]["bulk_evidence"]["unavailable_projections"]) == expected_missing
    assert snapshot["metadata"]["intentional_partial"] is True
    report = evaluate_snapshot(snapshot, checks=request["checks"])
    observed = {check.id: [finding["status"] for finding in report["findings"] if finding["check_id"] == check.id]
                for check in checks}
    assert all(statuses and set(statuses) == {"UNKNOWN"} for statuses in observed.values()), observed
    assert report["stats"]["coverage_complete"] is False


@pytest.mark.parametrize("provider", tuple(SCOPES))
def test_unknown_types_fail_before_the_native_collector(provider, monkeypatch):
    calls = stub_native(monkeypatch, provider)
    with pytest.raises(ValueError, match="unrecognized inventory requirements"):
        collect_live({"provider": provider, "scopes": [SCOPES[provider]], "options": {}},
                     ["undeclared_fixture_type_must_not_be_accepted"])
    assert calls == []
