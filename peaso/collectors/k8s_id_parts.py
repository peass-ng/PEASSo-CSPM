"""Bounded per-process memo of percent-encoded K8s resource-id parts.

``peaso.collectors.k8s._native`` builds ``k8s://cluster/kind/namespace/uid`` ids with
``quote(str(part), safe="")``. Cluster, kind and namespace repeat across every object of a
scan, so their encoding is remembered; the result is exactly ``quote(text, safe="")``.
"""
from urllib.parse import quote

MAX_PARTS = 4096
QUOTED = {}


def quoted(text):
    """quote(text, safe="") for a str ``text``, remembered for repeated exact str values."""
    value = QUOTED.get(text) if type(text) is str else None
    if value is None:
        value = quote(text, safe="")
        if type(text) is str:
            if len(QUOTED) >= MAX_PARTS:
                QUOTED.clear()
            QUOTED[text] = value
    return value
