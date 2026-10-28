"""Exact tokens for skipping re-emitted, unchanged collection envelopes.

Collectors emit each envelope when it settles and again after their finalizers.
Rebuilding the public envelope (structural copy, privacy callback, validation
and digest) for identical native content repeats work whose result and side
effects are already recorded. A token is only issued when the privacy callback
declares the complete state its output depends on; otherwise every envelope is
rebuilt as before.
"""
from .redaction_memo import exact_fingerprint


def settle_token(public_snapshot, envelope):
    """((type, scope), native fingerprint, public state) or None when unprovable."""
    state_of = getattr(public_snapshot, "settle_state", None)
    if not callable(state_of) or not isinstance(envelope, dict):
        return None
    key = (envelope.get("type"), envelope.get("scope"))
    if type(key[0]) is not str or type(key[1]) is not str:
        return None
    state = state_of()
    if state is None:
        return None
    fingerprint = exact_fingerprint(envelope)
    return None if fingerprint is None else (key, fingerprint, state)


def public_state(credentials, capture):
    """Digest of connector credentials plus the private-evidence state.

    The capture's record and redaction sets also govern location binding side
    effects of its public snapshot callback, so any change there (a secret
    found, rebound or restored later) re-runs the callback for every envelope.
    """
    records, redactions = getattr(capture, "records", None), getattr(capture, "redactions", None)
    if not isinstance(records, dict) or not isinstance(redactions, dict) or getattr(capture, "redaction_incomplete", False):
        return None
    credentials = tuple(credentials)
    # Finalizer replay asks for this state once per envelope. The private
    # records are sealed strings, so an exact tuple comparison is enough to
    # reuse the expensive digest until a record is added or rebound. A
    # nonempty redaction map takes the uncached path because its values may be
    # mutable. The cache is owned by this capture and expires with the scan.
    if (not redactions and all(type(value) is str for value in credentials)
            and all(type(key) is str and type(value) is str
                    for key, value in records.items())):
        signature = (credentials, tuple(records.items()))
        cached = getattr(capture, "_public_state_cache", None)
        if cached is not None and cached[0] == signature:
            return cached[1]
        state = exact_fingerprint((credentials, sorted((repr(k), repr(v)) for k, v in records.items()), []))
        capture._public_state_cache = (signature, state)
        return state
    # Sealed record values change whenever a record is added, rebound or
    # re-encrypted, so equal tokens mean the callback sees identical state.
    return exact_fingerprint((credentials, sorted((repr(k), repr(v)) for k, v in records.items()),
                              sorted((repr(k), repr(v)) for k, v in redactions.items())))
