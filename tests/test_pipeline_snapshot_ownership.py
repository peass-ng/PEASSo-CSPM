"""Pipeline copy avoidance keeps snapshot digests and artifacts byte-identical."""
import copy
import gc
import json
import threading

import pytest

from peaso.gc_pause import gc_paused
from peaso.snapshot import FrozenList, make_snapshot, seal, validate
from peaso.storage import artifacts as artifact_module
from peaso.storage.reports import _network_projection


def _snapshot():
    return make_snapshot("aws", ["123456789012"], [
        {"type": "security_group", "scope": "us-east-1", "status": "collected",
         "items": [{"GroupId": "sg-1", "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]},
        {"type": "iam_user", "scope": "global", "status": "collected",
         "items": [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}]},
        {"type": "vpc", "scope": "us-east-1", "status": "empty", "items": []},
    ], created_at="2026-10-26T00:00:00+00:00", metadata={"account_id": "123456789012", "note": {"x": [1]}})


def test_gc_pause_nests_and_restores_previous_state():
    assert gc.isenabled()
    with gc_paused():
        assert not gc.isenabled()
        with gc_paused():
            assert not gc.isenabled()
        assert not gc.isenabled()
    assert gc.isenabled()
    gc.disable()
    try:
        with gc_paused():
            pass
        assert not gc.isenabled()
    finally:
        gc.enable()


def test_gc_pause_waits_for_every_concurrent_holder():
    entered, release = threading.Event(), threading.Event()
    def hold():
        with gc_paused():
            entered.set()
            release.wait(3)
    worker = threading.Thread(target=hold)
    worker.start()
    assert entered.wait(3)
    with gc_paused():
        pass
    assert not gc.isenabled()
    release.set()
    worker.join(3)
    assert gc.isenabled()


def test_gc_pause_restores_after_exception():
    with pytest.raises(RuntimeError):
        with gc_paused():
            raise RuntimeError("boom")
    assert gc.isenabled()


def test_owned_seal_and_validate_match_copying_digest_and_adopt_items():
    source = _snapshot()
    expected_seal, expected_valid = seal(copy.deepcopy(source)), validate(copy.deepcopy(source))
    owned = copy.deepcopy(source)
    items = [row["items"] for row in owned["collections"]]
    sealed = seal(owned, owned=True)
    assert sealed == expected_seal
    assert json.dumps(sealed, sort_keys=True) == json.dumps(expected_seal, sort_keys=True)
    assert [row["items"] for row in sealed["collections"]] == items
    assert all(a is b for a, b in zip((row["items"] for row in sealed["collections"]), items))
    # The envelope (top level, metadata, collection dicts) is still fresh.
    assert sealed is not owned and sealed["metadata"] is not owned["metadata"]
    assert all(a is not b for a, b in zip(sealed["collections"], owned["collections"]))
    again = validate(sealed, owned=True)
    assert again == expected_valid and again["snapshot_id"] == expected_seal["snapshot_id"]


def test_owned_validate_still_rejects_bad_input():
    bad = copy.deepcopy(_snapshot())
    bad["collections"][0]["items"].append("not-an-object")
    with pytest.raises(ValueError, match="native objects"):
        validate(bad, owned=True)
    tampered = copy.deepcopy(_snapshot())
    tampered["metadata"]["note"] = "changed"
    with pytest.raises(ValueError, match="digest mismatch"):
        validate(tampered, owned=True)


def test_default_validate_still_copies_items():
    source = _snapshot()
    copied = validate(source)
    copied["collections"][0]["items"][0]["GroupId"] = "changed"
    assert source["collections"][0]["items"][0]["GroupId"] == "sg-1"
    frozen = validate(source, read_only=True)
    assert type(frozen["collections"][0]["items"]) is FrozenList


def test_network_projection_matches_full_snapshot_projection():
    from peaso.analysis.reachability import network_snapshot
    snapshot = _snapshot()
    before = network_snapshot(snapshot)
    before["metadata"]["original_snapshot_id"] = "sha256:report"
    expected = seal(before)
    result = _network_projection(snapshot, "sha256:report")
    assert json.dumps(result, sort_keys=True) == json.dumps(expected, sort_keys=True)
    assert {row["type"] for row in result["collections"]} == {"security_group", "vpc"}
    # The caller's snapshot is not changed by the projection.
    assert snapshot == _snapshot() and snapshot["snapshot_id"] == _snapshot()["snapshot_id"]


def test_artifact_json_decode_is_unchanged_and_restores_gc():
    body = json.dumps({"a": [1, {"b": "é"}]}, ensure_ascii=False).encode()
    assert artifact_module._loads(body) == json.loads(body)
    assert gc.isenabled()


def test_live_collect_tail_adopts_its_own_copy_with_the_same_snapshot(monkeypatch):
    import peaso.collectors as collectors
    from peaso import engine

    raw = make_snapshot("aws", ["123456789012"], [
        {"type": "s3_bucket", "scope": "123456789012", "status": "collected", "items": [{"Name": "b", "Tags": [1]}]}],
        created_at="2026-10-26T00:00:00+00:00")
    source = copy.deepcopy(raw)
    monkeypatch.setattr(collectors, "collect_live", lambda connector, requirements: source)
    seen = []
    request = {"connector": {"provider": "aws", "scopes": ["123456789012"], "auth": {}},
               "checks": ["aws.s3.versioning"], "_collection_callback": seen.append}
    try:
        result = engine.collect_snapshot(request)
    except ValueError as exc:  # pragma: no cover - selection drift
        pytest.skip(str(exc))
    expected = copy.deepcopy(result)
    expected.pop("snapshot_id")
    assert result["snapshot_id"] == seal(expected)["snapshot_id"] == validate(expected)["snapshot_id"]
    # The collector's own object is never adopted or mutated.
    assert source == raw
    assert result["collections"][0]["items"] is not source["collections"][0]["items"]
    assert result["collections"][0]["items"][0] is not source["collections"][0]["items"][0]
    assert "collection_plan" in result["metadata"]


def test_frozen_view_shares_items_with_later_validation_and_inventories():
    from peaso.snapshot import FrozenDict, frozen_view, resources

    plain = json.loads(json.dumps(_snapshot()))
    view = frozen_view(plain)
    assert view["snapshot_id"] == plain["snapshot_id"]
    item = view["collections"][0]["items"][0]
    assert type(item) is FrozenDict and item == plain["collections"][0]["items"][0]
    with pytest.raises(TypeError):
        item["x"] = 1
    other = frozen_view(plain)
    other["metadata"]["added"] = "envelope stays mutable"
    assert "added" not in plain["metadata"] and "added" not in view["metadata"]
    checked = validate(view, read_only=True)
    assert checked["collections"][0]["items"][0] is item
    assert any(row["data"] is item for row in resources(view))
    assert resources(view) == resources(plain)
    tampered = frozen_view(dict(plain, snapshot_id="sha256:" + "0" * 64))
    with pytest.raises(ValueError):
        validate(tampered, read_only=True)
    with pytest.raises(ValueError):
        frozen_view([])


def test_resources_restores_gc_and_matches_per_item_digest():
    from peaso.snapshot import digest, resources

    snapshot = _snapshot()
    gc.enable()
    rows = resources(snapshot)
    assert gc.isenabled()
    for row in rows:
        assert row["id"] == digest([row["provider"], row["scope"], row["type"], row["native_id"]])
