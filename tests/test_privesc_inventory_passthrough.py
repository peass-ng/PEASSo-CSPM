"""The engine's snapshot inventory reaches privesc entry-point annotation unchanged."""
import json

from peaso import engine, principal_exposure, privesc
from peaso.snapshot import make_snapshot, resources
from tests.test_peaso_privesc_followups import aws_snap, role, trust_service, user


def _snapshot():
    return aws_snap(
        [user("alice", {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction",
                                                      "lambda:InvokeFunction"], "Resource": "*"})],
        [role("admin", trust_service("lambda.amazonaws.com"),
              {"Effect": "Allow", "Action": "*", "Resource": "*"})],
    )


def test_analyze_with_inventory_matches_the_rebuilt_fallback():
    snapshot = _snapshot()
    rebuilt = privesc.analyze(snapshot)
    passed = privesc.analyze(snapshot, inventory=resources(snapshot))
    for result in (rebuilt, passed):
        result["stats"].pop("timing_seconds", None)
    assert rebuilt["findings"]
    assert json.dumps(passed, sort_keys=True, default=repr) == json.dumps(rebuilt, sort_keys=True, default=repr)


def test_engine_hands_its_own_inventory_to_annotation(monkeypatch):
    built, seen = [], []
    original_resources, original_project = engine.resources, principal_exposure.project

    def recorded(snapshot):
        built.append(original_resources(snapshot))
        return built[-1]

    def project(snapshot, inventory, *args, **kwargs):
        seen.append(inventory)
        return original_project(snapshot, inventory, *args, **kwargs)

    monkeypatch.setattr(engine, "resources", recorded)
    monkeypatch.setattr(principal_exposure, "project", project)
    raw = _snapshot()
    collections = [{key: value for key, value in row.items() if key != "error"} for row in raw["collections"]]
    snapshot = make_snapshot(raw["provider"], raw["scopes"], collections, created_at="2026-10-26T00:00:00Z")
    report = engine.evaluate_snapshot(snapshot, categories=["privesc"])
    assert report["stats"].get("privesc") is not None
    assert seen and all(any(item is inventory for inventory in built) for item in seen)
