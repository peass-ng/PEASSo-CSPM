"""Regional/account presence semantics: empty inventory can fail an enabled control."""
from dataclasses import replace
import pytest
from peaso.checks import Check
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def presence(item, index):
    if not item.get("scope"):
        return "UNKNOWN", {"reason": "scope context unavailable"}
    return ("PASS" if index.get("service_config") else "FAIL"), {"scope": item["scope"], "created_at": item["created_at"], "observed": len(index.get("service_config", []))}


@pytest.mark.parametrize("state,expected", [("empty", "FAIL"), ("collected", "PASS"), ("denied", "DENIED"), ("partial", "UNKNOWN"), ("not_collected", "UNKNOWN")])
def test_presence_check_uses_complete_inventory_not_per_object_empty(monkeypatch, state, expected):
    check = Check("aws.scope.test", "aws", "hardening", "service_config", "Service enabled", "medium", "CM-6", "Review service configuration", presence, "scope", ("service_config",))
    monkeypatch.setattr("peaso.engine._registry", lambda: [check])
    items = [{"id": "config"}] if state in ("collected", "partial") else []
    snapshot = make_snapshot("aws", ["111111111111/us-east-1"], [{"type": "service_config", "scope": "111111111111/us-east-1", "status": state, "items": items}], created_at="2026-01-01T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check.id])
    assert len(report["findings"]) == 1
    assert report["findings"][0]["status"] == expected
    if expected not in ("UNKNOWN", "DENIED"):
        assert report["findings"][0]["evidence"]["created_at"] == snapshot["created_at"]
    assert "EMPTY" not in report["stats"]["by_status"]


def test_scope_check_cannot_use_other_account_or_region_configuration(monkeypatch):
    check = Check("aws.scope.test", "aws", "hardening", "service_config", "Service enabled", "medium", "CM-6", "Review", presence, "scope", ("service_config",))
    monkeypatch.setattr("peaso.engine._registry", lambda: [check])
    scopes = ["111111111111/us-east-1", "111111111111/eu-west-1", "222222222222/us-east-1"]
    snapshot = make_snapshot("aws", scopes, [{"type": "service_config", "scope": scope, "status": "collected" if i == 0 else "empty", "items": [{"id": "config"}] if i == 0 else []} for i, scope in enumerate(scopes)])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check.id])
    assert {(f["scope"], f["status"]) for f in report["findings"]} == {(scopes[0], "PASS"), (scopes[1], "FAIL"), (scopes[2], "FAIL")}


def test_global_inventory_requires_explicit_verified_same_account_proof(monkeypatch):
    check = Check("aws.scope.test", "aws", "hardening", "service_config", "Service enabled", "medium", "CM-6", "Review", presence, "scope", ("service_config",))
    monkeypatch.setattr("peaso.engine._registry", lambda: [check])
    first, second, foreign = "111111111111/us-east-1", "111111111111/eu-west-1", "222222222222/us-east-1"
    envelope = {"type": "service_config", "scope": first, "status": "collected", "global": True, "account_id": "111111111111", "items": [{"id": "config", "AccountId": "111111111111"}]}
    snapshot = make_snapshot("aws", [first, second, foreign], [envelope])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[check.id])
    assert {(f["scope"], f["status"]) for f in report["findings"]} == {(first, "PASS"), (second, "PASS"), (foreign, "UNKNOWN")}
    for malformed in ({"global": False}, {"account_id": "222222222222"}, {"items": [{"id": "config", "AccountId": "222222222222"}]}):
        report = evaluate_snapshot(make_snapshot("aws", [second], [{**envelope, **malformed}]), categories=["hardening"], checks=[check.id])
        assert report["findings"][0]["status"] == "UNKNOWN"


def test_manual_attestation_is_not_an_automatic_scan_selection(monkeypatch):
    requirement_id = "aws-compliance.control.account_manual"
    monkeypatch.setattr("peaso.checks.catalog.manual_requirement_ids", lambda provider=None: {requirement_id})
    snapshot = make_snapshot("aws", ["111111111111/us-east-1"], [])
    with pytest.raises(ValueError, match="external policy or manual evidence"):
        evaluate_snapshot(snapshot, categories=["hardening"], checks=[requirement_id])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    assert report["stats"]["manual_requirement_count"] == 0
    assert report["manual_requirements"] == []


def test_human_labels_preserve_native_identity_and_stable_routing():
    scope = "111111111111/us-east-1"
    snapshot = make_snapshot("aws", [scope], [{"type": "instance", "scope": scope, "status": "collected", "items": [{"InstanceId": "i-native", "Tags": [{"Key": "Name", "Value": "web <host>"}], "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required"}}]}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    finding = report["findings"][0]
    assert finding["resource_name"] == "web <host>"
    assert finding["native_resource_id"] == "i-native"
    assert finding["resource_id"] == report["resources"][0]["id"]
    from peaso.reports import render_markdown
    assert "web &lt;host&gt;" in render_markdown(report)


def test_default_scan_plans_full_supported_inventory_and_explicit_filters_remain_targeted():
    from peaso.engine import plan_collection, get_catalog, BULK_STREAM_TYPES
    catalog = get_catalog()
    for provider in catalog["providers"]:
        consumed = {"cloudtrail_event"} if provider == "aws" else set()
        expected = sorted(set(catalog["inventories"][provider]) - (BULK_STREAM_TYPES.get(provider, set()) - consumed)
                          - ({"iam_managed_policy"} if provider == "aws" else set()))
        assert plan_collection({"connector": {"provider": provider}}) == expected
        assert plan_collection({"connector": {"provider": provider}, "categories": list(catalog["categories"]), "checks": [], "frameworks": []}) == expected
    assert plan_collection({"connector": {"provider": "aws"}, "categories": ["hardening"], "checks": ["aws.ec2.imdsv2"]}) == ["instance"]


def test_shared_budget_defaults_do_not_stop_after_old_hidden_caps():
    from peaso.collectors.base import Budget, Collector
    budget = Budget({})
    assert budget.max_calls is budget.max_pages is budget.max_items is None
    for _ in range(201):
        budget.call(lambda: {})
    assert budget.calls == 201
    collector = Collector("aws", ["scope"], {"inventories": ["instance"]})
    pages = [[{"InstanceId": "i-" + str(page * 1000 + n)} for n in range(1000)] for page in range(11)]
    collector.collect("instance", "scope", "ec2", lambda: iter(pages))
    snapshot = collector.finish()
    assert len(snapshot["collections"][0]["items"]) == 11000
    assert snapshot["collections"][0]["status"] == "collected"
    assert snapshot["metadata"]["intentional_limits"] == {}


def test_shared_explicit_budget_is_intentional_partial_and_cancelable():
    from peaso.collectors.base import Budget, Collector
    from threading import Event
    collector = Collector("aws", ["scope"], {"inventories": ["instance"], "max_resources": 1})
    collector.collect("instance", "scope", "ec2", lambda: iter([[{"InstanceId": "i-1"}, {"InstanceId": "i-2"}]]))
    snapshot = collector.finish()
    assert snapshot["collections"][0]["status"] == "partial"
    assert snapshot["metadata"]["intentional_limits"] == {"max_resources": 1}
    event = Event(); event.set()
    with pytest.raises(RuntimeError, match="cancelled"):
        Budget({"cancel_event": event}).call(lambda: pytest.fail("cancelled collection made a call"))


def test_successful_selected_inventory_does_not_hide_intentional_scope_partial():
    scope = "111111111111/us-east-1"
    snapshot = make_snapshot("aws", [scope], [{"type": "instance", "scope": scope, "status": "collected", "items": [{"InstanceId": "i-1", "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required"}}]}], metadata={"intentional_partial": True, "scope_coverage": {"status": "partial", "reason": "explicit max_scopes limit"}})
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    assert report["findings"][0]["status"] == "PASS"
    assert not report["stats"]["coverage_complete"] and not report["stats"]["inventory_complete"]
    assert any(c["level"] == "scope" and c["status"] == "partial" for c in report["coverage"])


def test_default_and_framework_scans_do_not_emit_attestation_questions():
    from peaso.checks.catalog import manual_requirements
    from peaso.engine import get_catalog
    assert manual_requirements(provider="azure")  # Source references remain available.
    subs = ["/subscriptions/%08d-0000-0000-0000-000000000000" % i for i in range(3)]
    tenant = "/tenants/11111111-1111-1111-1111-111111111111"
    snap = make_snapshot("azure", subs, [{"type": "tenant", "scope": tenant, "service": "entra", "status": "empty", "items": []}])
    for frameworks in (None, ["HackTricks Cloud Best Practices"]):
        report = evaluate_snapshot(snap, categories=["hardening"], frameworks=frameworks)
        assert report["manual_requirements"] == []
        assert report["stats"]["manual_requirement_count"] == 0
        assert not any(f.get("service") == "manual_review" for f in report["findings"])
        assert not any(row["level"] == "manual" for row in report["coverage"])
    assert get_catalog()["manual_requirements"] == []
