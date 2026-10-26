"""Bounded per-process memo for the K8s collector's key-drop decision.

The decision itself stays in ``peaso.collectors.k8s._sanitize``; this module
only remembers its boolean result for exact ``str`` keys, which repeat across
every object of a scan (metadata, spec, containers, ...). It stores no values.
"""

MAX_KEYS = 8192
# Exact scalar types that _sanitize returns unchanged; skipping the call is identical.
LEAVES = frozenset((str, int, float, bool, type(None)))
DROPPED = {}


def remember(key, dropped):
    if type(key) is not str:
        return
    if len(DROPPED) >= MAX_KEYS:
        DROPPED.clear()
    DROPPED[key] = dropped
