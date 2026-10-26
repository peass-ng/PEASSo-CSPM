"""Scan-local reuse of exact per-collection snapshot redaction.

A scan's checkpoint path scrubs its own connector credentials from each
envelope when it settles, again in its batch, and again in every cumulative
partial report. The redaction is a deterministic, element-wise function of one
collection and one exact secret set, so an unchanged collection needs it only
once per secret set. Memos are owned by one connector closure and never cross
a tenant or scan. Secrets found in customer resources are never scrubbed.
"""
import hashlib
import io
import pickle
import threading


def exact_fingerprint(value):
    """Type- and order-exact content digest, or None when it cannot be proven.

    Unlike JSON, pickle keeps key order, key types, bool/int/float and
    container classes distinct. Fast mode records no object sharing, so equal
    structures produce equal bytes. Nothing is ever unpickled.
    """
    buffer = io.BytesIO()
    pickler = pickle.Pickler(buffer, protocol=5)
    pickler.fast = True
    try:
        pickler.dump(value)
    except (pickle.PicklingError, TypeError, ValueError, RecursionError, AttributeError):
        return None
    return hashlib.sha256(buffer.getbuffer()).digest()


_UNCHANGED = object()


class SnapshotRedactionMemo:
    """One fixed, element-wise redaction of snapshot collections.

    ``transform`` must be a recursive per-value redaction such as Redactor (or
    a key pass built on it): a list maps each element independently and a
    dict's result for a child depends only on that child and sibling labels.
    The snapshot's other fields are redacted on every call; each collection
    is redacted once per exact input content. Every (type, scope) slot keeps
    only the digest of its last input and, when it differs from that input,
    the output. A different secret set needs a new memo. Cached outputs are
    shared, so callers must seal (copy) the result before exposing or
    mutating it.
    """
    def __init__(self, transform):
        self.transform = transform
        self.slots = {}
        self.lock = threading.Lock()
        self.hits = self.misses = 0

    def __call__(self, snapshot):
        rows = snapshot.get('collections') if isinstance(snapshot, dict) else None
        if not isinstance(rows, list):
            return self.transform(snapshot)
        shell = {key: ([] if key == 'collections' else value) for key, value in snapshot.items()}
        public = self.transform(shell)
        # Fall back unless 'collections' kept its exact key and slot and was
        # not itself redacted as a sensitive field.
        if (not isinstance(public, dict) or len(public) != len(shell)
                or 'collections' not in public
                or list(public).index('collections') != list(shell).index('collections')
                or type(public['collections']) is not list or public['collections']):
            return self.transform(snapshot)
        with self.lock:
            public['collections'] = [self._row(row) for row in rows]
        return public

    def _row(self, row):
        key = (row.get('type'), row.get('scope')) if isinstance(row, dict) else None
        fingerprint = (exact_fingerprint(row) if key is not None
                       and type(key[0]) is str and type(key[1]) is str else None)
        if fingerprint is not None:
            slot = self.slots.get(key)
            if slot is not None and slot[0] == fingerprint:
                self.hits += 1
                return row if slot[1] is _UNCHANGED else slot[1]
        self.misses += 1
        public = self.transform(row)
        if fingerprint is not None:
            self.slots[key] = (fingerprint, _UNCHANGED
                               if exact_fingerprint(public) == fingerprint else public)
        return public


def credential_redaction(connector, credential_values):
    """redact(snapshot, connector credentials) for one scan's checkpoints.

    Credential values are read again on every call; each unchanged public
    collection is redacted once per exact credential set.
    """
    state = {}

    def public(snapshot):
        values = tuple(credential_values(connector.get("auth", {})))
        if state.get("values") != values:
            from peaso.auth.secrets import Redactor
            state.clear()
            # Only the scanner's own connector credentials are scrubbed. Found
            # secrets and secret-named native fields stay visible to the tenant.
            state.update(values=values, memo=SnapshotRedactionMemo(Redactor(values, fields=False)))
        return state["memo"](snapshot)

    public.state = state
    return public
