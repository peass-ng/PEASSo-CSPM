"""collect_snapshot verifies the collector digest and addresses its plan in one pass.

validate(..., metadata_entry=(key, value)) must equal validate, set the key,
validate again: same document, same snapshot_id. A document changed after
make_snapshot still fails its digest, and nothing a collection callback does
can leave the returned snapshot with a stale address.
"""
import copy

import pytest

from peaso import collectors, engine
from peaso.snapshot import digest, make_snapshot, validate

PLAN = {"mode": "dependencies", "requirements": ["pod", "namespace"], "categories": ["hardening"],
        "checks": "all_selected", "frameworks": "all_selected"}


def _snapshot(**metadata):
    return make_snapshot("k8s", ["cluster"], [
        {"type": "pod", "scope": "cluster", "status": "collected",
         "items": [{"metadata": {"name": "a", "namespace": "default"}, "spec": {"containers": [{"name": "c"}]}}]},
        {"type": "namespace", "scope": "cluster", "status": "empty", "items": []},
    ], created_at="2026-10-26T00:00:00Z", metadata=metadata)


def _two_pass(snapshot, key, value):
    first = validate(snapshot)
    first["metadata"][key] = value
    return validate({k: v for k, v in first.items() if k != "snapshot_id"}, owned=True)


def _address(snapshot):
    return digest({k: v for k, v in snapshot.items() if k != "snapshot_id"})


@pytest.mark.parametrize("metadata", [{}, {"native_auth": "x", "zeta": [1, {"b": None}]}])
@pytest.mark.parametrize("claimed", [True, False])
def test_one_pass_equals_validate_set_validate(metadata, claimed):
    snapshot = _snapshot(**metadata)
    if not claimed:
        snapshot.pop("snapshot_id")
    expected = _two_pass(copy.deepcopy(snapshot), "collection_plan", PLAN)
    actual = validate(copy.deepcopy(snapshot), metadata_entry=("collection_plan", PLAN))
    assert actual == expected
    assert actual["snapshot_id"] == _address(actual)


def test_entry_is_an_independent_copy():
    plan = copy.deepcopy(PLAN)
    actual = validate(_snapshot(), metadata_entry=("collection_plan", plan))
    plan["requirements"].append("mutated")
    assert actual["metadata"]["collection_plan"] == PLAN
    assert actual["snapshot_id"] == _address(actual)


@pytest.mark.parametrize("mutate", [
    lambda s: s["collections"][0]["items"][0]["spec"].update(hostNetwork=True),
    lambda s: s["collections"].pop(),
    lambda s: s["metadata"].update(native_auth="changed"),
    lambda s: s.update(created_at="2026-10-27T00:00:00Z"),
])
def test_a_document_changed_after_make_snapshot_fails_its_digest(mutate):
    snapshot = _snapshot()
    mutate(snapshot)
    with pytest.raises(ValueError, match="digest mismatch"):
        validate(snapshot)
    with pytest.raises(ValueError, match="digest mismatch"):
        validate(snapshot, metadata_entry=("collection_plan", PLAN))
    # Without a claimed address the changed content is digested from scratch.
    snapshot.pop("snapshot_id")
    recomputed = validate(copy.deepcopy(snapshot), metadata_entry=("collection_plan", PLAN))
    assert recomputed == _two_pass(snapshot, "collection_plan", PLAN)
    assert recomputed["snapshot_id"] == _address(recomputed)


def test_collect_snapshot_address_survives_a_mutating_callback(monkeypatch):
    emitted = []

    def callback(collection):
        emitted.append(copy.deepcopy(collection))
        collection["items"].append({"metadata": {"name": "injected"}})
        collection["status"] = "denied"

    monkeypatch.setattr(collectors, "collect_live", lambda connector, requirements: _snapshot())
    snapshot = engine.collect_snapshot({"connector": {"provider": "k8s", "scopes": ["cluster"], "options": {}},
                                        "_collection_callback": callback})
    pristine = _snapshot()
    assert emitted == pristine["collections"]
    assert snapshot["collections"] == pristine["collections"]
    assert snapshot["snapshot_id"] == _address(snapshot)
    assert set(snapshot["metadata"]) == {"collection_plan"}
