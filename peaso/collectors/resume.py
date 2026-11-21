"""Reuse sealed, fully settled native inventory kinds on the original scan row."""
from __future__ import annotations

import copy

from peaso.snapshot import make_snapshot, validate


def partition(connector, requirements, saved):
    """Return remaining kinds and exact prior envelopes eligible for reuse.

    A kind is reused only when every explicitly selected scope was settled.
    Discovery and intentionally limited reads always run again.  In particular,
    one successful region cannot stand in for a failed sibling region.
    """
    if saved is None or requirements is None:
        return requirements, []
    saved = validate(saved)
    provider = connector["provider"]
    scopes = connector.get("scopes") or []
    options = connector.get("options") or {}
    from peaso.collectors import supported_types
    if (saved["provider"] != provider or not scopes or "*" in scopes
            or not set(requirements) <= set(supported_types(provider))
            or any(options.get(key) is not None for key in
                   ("max_calls", "max_pages", "max_resources", "max_scopes", "deadline_seconds"))):
        return requirements, []
    by_kind = {}
    for row in saved["collections"]:
        if row["status"] in {"collected", "empty"} and not row.get("error"):
            by_kind.setdefault(row["type"], []).append(row)
    keep = set()
    for kind in requirements:
        rows = by_kind.get(kind, [])
        observed = {row["scope"] for row in rows}
        if rows and all(scope in observed or
                        (provider == "aws" and "/" in scope and
                         scope.split("/", 1)[0] + "/global" in observed)
                        for scope in scopes):
            keep.add(kind)
    return [kind for kind in requirements if kind not in keep], [
        copy.deepcopy(row) for row in saved["collections"] if row["type"] in keep]


def scoped_gcp_lookup(connector, requirements, saved):
    """Bound a private GCP scheduler callback to one sealed scan's scope plan.

    The collector still performs fresh discovery. It calls this callback only
    for jobs in its current discovered scope plan; new scopes and failed units
    therefore reach the SDK. The worker supplies the same frozen selectors and
    options from the original scan row before creating this callback.
    """
    saved = validate(saved)
    if (connector.get("provider") != "gcp" or saved["provider"] != "gcp"
            or not requirements):
        return None
    options = connector.get("options") or {}
    if any(options.get(key) is not None for key in
           ("max_calls", "max_pages", "max_resources", "max_scopes", "deadline_seconds")):
        return None
    requested = connector.get("scopes") or []
    metadata = saved.get("metadata") or {}
    if (not isinstance(requested, list) or not all(isinstance(scope, str) for scope in requested)
            or metadata.get("requested_scopes") != requested
            or metadata.get("collection_mode") != "full"):
        return None
    resolved = metadata.get("resolved_scopes") if not requested else saved["scopes"]
    if (not isinstance(resolved, list) or not resolved
            or not all(isinstance(scope, str) for scope in resolved)
            or len(set(resolved)) != len(resolved)
            or set(resolved) != set(saved["scopes"])):
        return None
    wanted = set(requirements)
    rows = {(row["type"], row["scope"], row.get("service")): row
            for row in saved["collections"]
            if row["type"] in wanted and row["scope"] in resolved
            and row["status"] in {"collected", "empty"} and not row.get("error")}
    if not rows:
        return None

    def lookup(kind, scope, service):
        row = rows.get((kind, scope, service))
        return copy.deepcopy(row) if row is not None else None

    return lookup


def _not_requested(row):
    return (row is not None and row["status"] == "not_collected"
            and (row.get("error") or {}).get("code") == "inventory_not_requested")


def checkpoint_with_reuse(callback, saved_rows):
    """Keep the restored evidence when the retry emits an inventory placeholder."""
    reused = {(row["type"], row["scope"]) for row in saved_rows}

    def settled(row):
        if (row["type"], row["scope"]) in reused and _not_requested(row):
            return
        return callback(row)

    return settled


def merge(snapshot, saved_rows, prior):
    if not saved_rows:
        return snapshot
    current = {(row["type"], row["scope"]): row for row in snapshot["collections"]}
    for row in saved_rows:
        key = row["type"], row["scope"]
        if key not in current or _not_requested(current[key]):
            current[key] = row
    metadata = copy.deepcopy(prior.get("metadata", {}))
    metadata.update(snapshot.get("metadata", {}))
    metadata["resume"] = {"reused_collections": len(saved_rows)}
    scopes = sorted(set(snapshot["scopes"]) | {row["scope"] for row in saved_rows})
    return make_snapshot(snapshot["provider"], scopes, list(current.values()),
                         metadata=metadata)
