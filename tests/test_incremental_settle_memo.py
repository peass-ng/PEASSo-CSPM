"""Re-emitted identical envelopes skip the public rebuild only under an exact, unchanged state token."""
import json
from types import SimpleNamespace

from peaso.incremental import CheckpointSession
from peaso.settle_memo import public_state, settle_token
from peaso.snapshot import seal

SCOPE = "123456789012/us-east-1"


def _session(state):
    calls, checkpoints = [], []

    def public_snapshot(snapshot):
        calls.append([row["type"] for row in snapshot["collections"]])
        return seal(json.loads(json.dumps(snapshot).replace("PRIVATE", "[REDACTED]")))

    if state is not None:
        public_snapshot.settle_state = lambda: state["value"]
    request = {"connector": {"provider": "aws", "scopes": [SCOPE]}, "categories": [], "checks": []}
    session = CheckpointSession(request, lambda snapshot, report, sequence: checkpoints.append((sequence, snapshot)),
                                public_snapshot, interval=60, batch_size=1)
    return session, calls, checkpoints


def _envelope(value="PRIVATE"):
    return {"type": "bucket", "scope": SCOPE, "status": "collected", "items": [{"id": "b", "v": value}]}


def test_identical_reemit_skips_rebuild_and_keeps_sequence():
    state = {"value": b"s1"}
    session, calls, checkpoints = _session(state)
    try:
        assert session.on_collection(_envelope()) == 1
        built = len(calls)
        assert session.on_collection(_envelope()) == 1
        assert len(calls) == built, "unchanged envelope must not be rebuilt"
        assert [seq for seq, _ in checkpoints] == [1]
        assert "PRIVATE" not in json.dumps(checkpoints[0][1])
    finally:
        session.close()


def test_changed_content_or_state_rebuilds_exactly_as_before():
    state = {"value": b"s1"}
    session, calls, checkpoints = _session(state)
    try:
        session.on_collection(_envelope())
        built = len(calls)
        # New public state (credentials or private evidence changed): rebuilt,
        # and the existing equality check still suppresses an identical result.
        state["value"] = b"s2"
        assert session.on_collection(_envelope()) == 1
        assert len(calls) == built + 1
        assert session.on_collection(_envelope("other")) == 2
        assert [seq for seq, _ in checkpoints] == [1, 2]
        assert checkpoints[-1][1]["collections"][0]["items"][0]["v"] == "other"
        # Returning to earlier native content is a real revision, never skipped.
        assert session.on_collection(_envelope()) == 3
    finally:
        session.close()


def test_without_declared_state_every_envelope_is_rebuilt():
    session, calls, _ = _session(None)
    try:
        session.on_collection(_envelope())
        built = len(calls)
        assert session.on_collection(_envelope()) == 1
        assert len(calls) == built + 1
    finally:
        session.close()


def test_externally_replaced_collection_is_rebuilt():
    state = {"value": b"s1"}
    session, calls, _ = _session(state)
    try:
        session.on_collection(_envelope())
        key = ("bucket", SCOPE)
        session.collections[key] = dict(session.collections[key], status="partial")
        built = len(calls)
        assert session.on_collection(_envelope()) == 2
        assert len(calls) > built
    finally:
        session.close()


def test_token_requires_string_identity_and_exact_content():
    holder = SimpleNamespace(settle_state=lambda: b"x")
    assert settle_token(holder, {"type": 1, "scope": SCOPE}) is None
    assert settle_token(lambda s: s, _envelope()) is None
    a = settle_token(holder, {"type": "bucket", "scope": SCOPE, "items": [{"n": 1}]})
    b = settle_token(holder, {"type": "bucket", "scope": SCOPE, "items": [{"n": True}]})
    assert a is not None and b is not None and a != b


def test_public_state_tracks_credentials_and_private_records(monkeypatch):
    from peaso import settle_memo
    fingerprint = settle_memo.exact_fingerprint
    calls = []
    def counted(value):
        calls.append(True)
        return fingerprint(value)
    monkeypatch.setattr(settle_memo, 'exact_fingerprint', counted)
    capture = SimpleNamespace(records={"fp": "sealed-1"}, redactions={}, redaction_incomplete=False)
    first = public_state(("key",), capture)
    assert first == public_state(("key",), capture)
    assert len(calls) == 1
    assert first != public_state(("other",), capture)
    capture.records["fp"] = "sealed-2"
    assert first != public_state(("key",), capture)
    capture.records = {"fp": "sealed-1"}
    assert first == public_state(("key",), capture)
    capture.redactions['fp'] = {'changed'}
    redacted = public_state(("key",), capture)
    capture.redactions['fp'].add('again')
    assert redacted != public_state(("key",), capture)
    capture.redaction_incomplete = True
    assert public_state(("key",), capture) is None
