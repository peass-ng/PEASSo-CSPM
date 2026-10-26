"""JSON snapshots are sealed at boundaries and addressed by a verified content digest.

seal(), validate() and make_snapshot() return ordinary mutable copies (one structural copy, as before).
Evaluation paths call validate(snapshot, read_only=True): native collection items are converted once
into read-only views (FrozenDict / FrozenList), already-frozen items are shared, and every later
consumer (checks, analysis, privesc, graphs, reports) shares those views instead of deep-copying native
data. A view cannot be mutated in place; ``copy.deepcopy`` of a view returns an ordinary mutable copy.
"""
from __future__ import annotations
import copy
import hashlib
import json
from datetime import datetime, timezone

from .gc_pause import gc_paused


def _read_only(self, *args, **kwargs):
    raise TypeError("sealed snapshot data is read-only; copy.deepcopy() it to obtain a mutable copy")


class FrozenDict(dict):
    """A dict view of sealed native data. JSON-serialisable and isinstance(dict); mutation raises TypeError."""
    __slots__ = ()
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _read_only

    def __copy__(self):
        return dict(self)

    def __deepcopy__(self, memo):
        return thaw(self)

    def __reduce__(self):
        return (FrozenDict, (dict(self),))


class FrozenList(list):
    """A list view of sealed native data. JSON-serialisable and isinstance(list); mutation raises TypeError."""
    __slots__ = ()
    __setitem__ = __delitem__ = __iadd__ = __imul__ = append = extend = insert = remove = pop = clear = sort = reverse = _read_only

    def __copy__(self):
        return list(self)

    def __deepcopy__(self, memo):
        return thaw(self)

    def __reduce__(self):
        return (FrozenList, (list(self),))


def _freeze(value):
    kind = type(value)
    if kind is FrozenDict or kind is FrozenList:
        return value
    if isinstance(value, dict):
        return FrozenDict({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return FrozenList([_freeze(item) for item in value])
    return value


# Exact scalar types are returned unchanged by _thaw; skipping the call for them is identical.
_THAW_LEAVES = frozenset((str, int, float, bool, type(None)))


def _thaw(value):
    if isinstance(value, dict):
        return {key: (item if type(item) in _THAW_LEAVES else _thaw(item)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [item if type(item) in _THAW_LEAVES else _thaw(item) for item in value]
    return value


def freeze(value):
    """Read-only view of JSON-like data; already-frozen values are shared, never copied again."""
    # Copies create no reference cycles; skip cyclic GC rescans of the live heap.
    with gc_paused():
        return _freeze(value)


def thaw(value):
    """Ordinary mutable deep copy of (possibly frozen) JSON-like data."""
    with gc_paused():
        return _thaw(value)


def _sealed_structure(snapshot, read_only=False, owned=False):
    """New envelope (top level, metadata, collection dicts) around the native items.

    Envelopes stay mutable plain dicts because callers annotate metadata after validation. With read_only
    the items (the large native facts) are frozen exactly once and shared afterwards; otherwise they are
    copied into ordinary mutable objects. With owned, the caller hands over plain item lists it built for
    this call and never uses again (e.g. a fresh redaction or snapshot copy); they are adopted, not copied.
    """
    with gc_paused():
        return _structure(snapshot, read_only, owned)


def frozen_view(snapshot):
    """Mutable envelope over read-only native items, frozen exactly once.

    The stored snapshot_id is kept as is: this is not a validation, and the
    engine's validate(read_only=True) still verifies structure and digest. It
    shares these frozen items instead of copying them again, and so does every
    later inventory (publication, AI review) of the same analyzer snapshot.
    """
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be an object")
    return _sealed_structure(snapshot, read_only=True)


def _structure(snapshot, read_only, owned):
    thaw = _thaw
    items_of = ((lambda value: FrozenList([_freeze(item) for item in value])) if read_only
                else (lambda value: value) if owned else thaw)
    result = {key: (thaw(value) if key != "collections" else value) for key, value in snapshot.items()}
    collections = result.get("collections")
    if isinstance(collections, list):
        sealed = []
        for collection in collections:
            if isinstance(collection, dict):
                collection = {key: (items_of(value) if key == "items" and isinstance(value, list)
                                    else thaw(value)) for key, value in collection.items()}
            sealed.append(collection)
        result["collections"] = sealed
    return result

SCHEMA_VERSION = "1.0"
PROVIDERS = ("aws", "gcp", "azure", "k8s")
STATUSES = ("collected", "empty", "partial", "denied", "unknown", "malformed", "timeout", "not_collected")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _hash_canonical(value):
    """sha256 of canonical(value).encode(), streamed one collection at a time for snapshot documents.

    canonical() of a dict with only str keys is '{' + ','.join(canonical(key) + ':' + canonical(item)
    for key in sorted keys) + '}', and of a list '[' + ','.join(canonical(item)) + ']'; hashing those
    pieces in order hashes exactly the same bytes without holding the whole document as one string
    and one bytes object at once. Anything else is encoded in one piece, as before.
    """
    digest = hashlib.sha256()
    collections = value.get("collections") if type(value) is dict else None
    if type(collections) is not list or not all(type(key) is str for key in value):
        digest.update(canonical(value).encode())
        return digest
    update = digest.update
    update(b"{")
    for index, key in enumerate(sorted(value)):
        if index:
            update(b",")
        update(canonical(key).encode())
        update(b":")
        if key == "collections":
            update(b"[")
            for position, collection in enumerate(collections):
                if position:
                    update(b",")
                update(canonical(collection).encode())
            update(b"]")
        else:
            update(canonical(value[key]).encode())
    update(b"}")
    return digest


def digest(value):
    with gc_paused():
        return "sha256:" + _hash_canonical(value).hexdigest()


def seal(snapshot, *, owned=False):
    """Sealed mutable copy; owned=True adopts the caller's fresh item lists instead of copying them."""
    result = _sealed_structure(snapshot, owned=owned)
    result.pop("snapshot_id", None)
    result["snapshot_id"] = digest(result)
    return result


def validate(snapshot, *, read_only=False, owned=False, metadata_entry=None):
    """Validated copy of a snapshot; read_only=True shares sealed read-only item views (evaluation paths).

    owned=True: the caller transfers a plain snapshot it just built (sealed, redacted or copied) and never
    uses again; its item lists are adopted instead of copied. Every check and the digest still apply.
    metadata_entry=(key, value): the claimed snapshot_id is verified against the document as given, then
    the copy gains metadata[key] = an independent copy of value and is addressed by that final digest.
    This equals validating, setting the key and validating again; see _digests_with_metadata.
    """
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be an object")
    result = _sealed_structure(snapshot, read_only, owned)
    if result.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported snapshot schema_version")
    if result.get("provider") not in PROVIDERS:
        raise ValueError("snapshot provider must be aws, gcp, azure, or k8s")
    if not isinstance(result.get("scopes"), list) or not all(isinstance(x, str) for x in result["scopes"]):
        raise ValueError("snapshot scopes must be a string list")
    if not isinstance(result.get("created_at"), str):
        raise ValueError("snapshot created_at must be a string")
    if not isinstance(result.get("collections"), list):
        raise ValueError("snapshot collections must be a list")
    if not isinstance(result.get("metadata", {}), dict):
        raise ValueError("snapshot metadata must be an object")
    seen = set()
    for collection in result["collections"]:
        if not isinstance(collection, dict) or not all(isinstance(collection.get(k), str) for k in ("type", "scope", "status")):
            raise ValueError("collection requires type, scope, and status strings")
        if collection["status"] not in STATUSES or not isinstance(collection.get("items"), list):
            raise ValueError("collection requires a known status and items list")
        if "error" in collection and not isinstance(collection["error"], dict):
            raise ValueError("collection error must be an object")
        if "service" in collection and not isinstance(collection["service"], str):
            raise ValueError("collection service must be a string")
        if any(not isinstance(item, dict) for item in collection["items"]):
            raise ValueError("collection items must be native objects")
        key = (collection["type"], collection["scope"])
        if key in seen:
            raise ValueError("duplicate collection type/scope")
        seen.add(key)
        if collection["status"] in ("empty", "denied", "unknown", "malformed", "timeout", "not_collected") and collection["items"]:
            raise ValueError("unavailable/empty collection cannot contain items")
    original = result.pop("snapshot_id", None)
    if metadata_entry is None:
        calculated = digest(result)
    else:
        calculated, extended, metadata = _digests_with_metadata(result, *metadata_entry)
    if original is not None and original != calculated:
        raise ValueError("snapshot content digest mismatch")
    result["snapshot_id"] = calculated
    if metadata_entry is not None:
        result["metadata"] = metadata
        result["snapshot_id"] = extended
    return result


def _digests_with_metadata(result, key, value):
    """digest(result), digest(result with metadata[key] = value) and that metadata, sharing one pass.

    The canonical document sorts its keys and "collections" sorts before "metadata". Every key before
    "metadata" is identical in both documents, so that prefix (the native items) is streamed once and
    the hash state is copied for the two endings; the bytes are exactly those _hash_canonical hashes.
    Nothing else runs between the two digests, so no change can fall between them. Any other shape is
    digested twice in full.
    """
    metadata = dict(result["metadata"])
    metadata[key] = _thaw(value)
    collections = result.get("collections")
    if (type(collections) is not list or not all(type(name) is str for name in result)
            or type(result["metadata"]) is not dict):
        return digest(result), digest({**result, "metadata": metadata}), metadata
    names = sorted(result)
    cut = names.index("metadata")
    with gc_paused():
        shared = hashlib.sha256()
        update = shared.update
        update(b"{")
        for index, name in enumerate(names[:cut]):
            if index:
                update(b",")
            update(canonical(name).encode())
            update(b":")
            if name == "collections":
                update(b"[")
                for position, collection in enumerate(collections):
                    if position:
                        update(b",")
                    update(canonical(collection).encode())
                update(b"]")
            else:
                update(canonical(result[name]).encode())

        def ending(document_metadata):
            state = shared.copy()
            for index, name in enumerate(names[cut:], cut):
                if index:
                    state.update(b",")
                state.update(canonical(name).encode())
                state.update(b":")
                state.update(canonical(document_metadata if name == "metadata" else result[name]).encode())
            state.update(b"}")
            return "sha256:" + state.hexdigest()

        return ending(result["metadata"]), ending(metadata), metadata


def make_snapshot(provider, scopes, collections, *, created_at=None, metadata=None, owned=False):
    # This builder owns the new document and has no inherited digest to verify.
    # validate() already makes the independent copy, checks the full structure,
    # and computes its canonical digest. Sealing first repeated both operations.
    # owned=True: the collector hands over item lists it built fresh and never touches again; they are
    # adopted instead of copied (see validate). Envelopes and metadata are still copied.
    return validate({"schema_version": SCHEMA_VERSION, "provider": provider,
        "scopes": list(scopes), "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "collections": collections, "metadata": metadata or {}}, owned=owned)


def resource_id(provider, kind, scope, item):
    identifiers = {"security_group": "GroupId", "vpc": "VpcId", "subnet": "SubnetId", "instance": "InstanceId",
                   "route_table": "RouteTableId", "ebs_volume": "VolumeId", "network_interface": "NetworkInterfaceId",
                   "lambda_function": "FunctionArn", "apigateway_domain_name": "domainName",
                   "apigatewayv2_domain_name": "DomainName", "http_api": "ApiId",
                   "ecs_task": "taskArn", "ecs_service": "serviceArn", "ecs_task_definition": "taskDefinitionArn"}
    for explicit in ("_resource_id", "native_id"):
        if isinstance(item.get(explicit), str):
            return item[explicit]
    # Prefer authoritative self identity, never a referenced parent such as VpcId.
    for key in ("Arn", "arn", "id", "selfLink", identifiers.get(kind, "_unused"), "UserName", "GroupName", "RoleName", "PolicyName", "Name", "name"):
        if isinstance(item.get(key), (str, int)):
            return str(item[key])
    meta = item.get("metadata", {})
    if isinstance(meta, dict) and meta.get("name"):
        return f"{meta.get('namespace', '_cluster')}/{meta['name']}"
    return digest(item)


def resources(snapshot):
    # One collector pause for the whole inventory instead of two per item.
    with gc_paused():
        return _resources(snapshot)


def _resources(snapshot):
    from .check_services import service_for
    output = {}
    sha256 = hashlib.sha256
    for collection in snapshot["collections"]:
        for item in collection["items"]:
            if not isinstance(item, dict):
                continue
            rid = resource_id(snapshot["provider"], collection["type"], collection["scope"], item)
            key = (collection["scope"], collection["type"], rid)
            output[key] = {"id": "sha256:" + sha256(canonical([snapshot["provider"], collection["scope"], collection["type"], rid]).encode()).hexdigest(), "native_id": rid, "type": collection["type"], "service": service_for(snapshot["provider"], collection["type"], collection.get("service")),
                "scope": collection["scope"], "provider": snapshot["provider"], "data": _freeze(item)}
    return [output[key] for key in sorted(output)]


def nothing_readable(snapshot):
    """True when a collection run read nothing at all (no collection collected, empty or partial),
    e.g. every call failed on expired or wrong credentials."""
    return not any(c.get("status") in ("collected", "empty", "partial") for c in snapshot.get("collections", []))
