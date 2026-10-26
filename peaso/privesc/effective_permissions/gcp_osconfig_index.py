"""Scan-local lookups shared by the OS Config privesc selectors.

The selectors ask the same snapshot questions for every (source, target) pair: which rows sit in a
project, which service agents a parent grants, which APIs a project enables.  The answers depend only
on the model's frozen snapshot and project aliases, so they are computed once per model.
"""

from __future__ import annotations

from . import items

_MISSING = object()


def _store(model, name):
    state = getattr(model, "__dict__", None)
    if state is None:
        return None
    caches = state.get("_gcp_osconfig_index")
    if caches is None:
        caches = state["_gcp_osconfig_index"] = {}
    return caches.setdefault(name, {})


def memo(model, name, key, compute):
    """compute() once per model and key; uncached when the key or model cannot hold it."""
    store = _store(model, name)
    if store is None:
        return compute()
    try:
        value = store.get(key, _MISSING)
    except TypeError:
        return compute()
    if value is _MISSING:
        value = store[key] = compute()
    return value


def rows_in(model, kind, scope):
    """(scope, row) pairs of a collection type whose normalized scope equals scope, in snapshot order."""
    store = _store(model, "rows_in")
    if store is None:
        return [(raw, row) for raw, row in items(model.snapshot, kind) if model._norm_scope(raw) == scope]
    index = store.get(kind)
    if index is None:
        index = {}
        for raw, row in items(model.snapshot, kind):
            index.setdefault(model._norm_scope(raw), []).append((raw, row))
        store[kind] = index
    return index.get(scope, ())
