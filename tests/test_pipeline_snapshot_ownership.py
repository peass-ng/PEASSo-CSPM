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
