"""Shared strict helpers for the claude2_gcp partition (see docs/checks.md).

Missing, denied, malformed or unrecognized facts raise ``Unavailable`` (-> UNKNOWN). Absence-based FAIL
results require complete scoped inventories *and* proof that no uncollected organization/folder
configuration can satisfy the control; otherwise the result is MANUAL.
"""
from __future__ import annotations
from datetime import datetime, timezone
import re

from . import register, result, unknown
from .facts import get, list_of_objects, optional, complete_items, Unavailable
from .fixtures import CASES

PREFIX = "gcp.claude2."
CHECK_IDS = []
SCOPE = "projects/p"
PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")


def gcp(slug, kind, title, *, severity="medium", control="CM-6", remediation, category="hardening", dependencies=None):
    cid = PREFIX + slug
    CHECK_IDS.append(cid)
    registrar = register(cid, "gcp", category, kind, title, severity, control, remediation, target="resource",
                         dependencies=list(dependencies or [kind]))

    def apply(function):
        def evaluate(item, index):
            if isinstance(item, dict) and not any(not str(key).startswith("_") and key != "collection_status" for key in item):
                raise Unavailable("native resource has no collected fields")
            return function(item, index)
        evaluate.__name__ = function.__name__
        registrar(evaluate)
        return function
    return apply


def cid(slug):
    return PREFIX + slug


def cases(check_id, good, bad, **extra):
    CASES[check_id] = {"pass": good, "fail": bad, "missing": {}, **extra}
    return CASES[check_id]


def scope_index(kind_items, scope=SCOPE, created_at="2026-10-10T12:00:00Z"):
    """Fixture builder: {kind: [items]} with complete scoped envelopes and context."""
    index = {"collections": {}, "context": {"provider": "gcp", "scope": scope, "created_at": created_at}}
    for kind, items in kind_items.items():
        index["collections"][kind] = [{"scope": scope, "status": "collected" if items else "empty"}]
        index[kind] = [{"data": item} for item in items]
    return index


def strings(value, what="string list"):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise Unavailable("malformed " + what)
    return value


def parse_time(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp unavailable")
    text = value.replace("Z", "+00:00")
    # RFC 3339 allows nanosecond precision; Python parses at most microseconds.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise Unavailable("malformed timestamp") from None
    if parsed.tzinfo is None:
        raise Unavailable("timestamp timezone missing")
    return parsed.astimezone(timezone.utc)


def captured_at(item, index):
    observed = None
    if isinstance(item.get("_provenance"), dict):
        observed = item["_provenance"].get("collected_at")
    if observed is None and isinstance(index.get("context"), dict):
        observed = index["context"].get("created_at")
    return parse_time(observed)


def bindings(policy):
    out = []
    for row in list_of_objects(get(policy, "bindings", list)):
        role = get(row, "role", str)
        members = strings(get(row, "members", list), "IAM binding members")
        out.append({"role": role, "members": members, "conditional": row.get("condition") is not None})
    return out


def public_bindings(policy):
    return [{"role": b["role"], "members": sorted(set(b["members"]) & set(PUBLIC_MEMBERS)), "conditional": b["conditional"]}
            for b in bindings(policy) if set(b["members"]) & set(PUBLIC_MEMBERS)]


def project_ids(project):
    """The project's ID and number as they appear in resource names."""
    values = {get(project, "projectId", str)}
    number = optional(project, "name", "", str).removeprefix("projects/")
    if number:
        values.add(number)
    return values


def in_project(name, ids):
    return any(name.startswith("projects/" + value + "/") for value in ids)


__all__ = [name for name in dir() if not name.startswith("__")]
