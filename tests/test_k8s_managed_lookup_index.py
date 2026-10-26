"""The managed owner lookup table returns exactly what the linear scan returned."""
from peaso.checks import k8s_managed as managed


def _linear(index, kind, namespace, name, uid):
    if not isinstance(name, str) or not name or not isinstance(uid, str) or not uid:
        return None
    rows = index.get(kind)
    if not isinstance(rows, list):
        return None
    matches = [row["data"] for row in rows
               if isinstance(row, dict) and isinstance(row.get("data"), dict)
               and isinstance(row["data"].get("metadata"), dict)
               and row["data"]["metadata"].get("name") == name
               and row["data"]["metadata"].get("namespace") == namespace
               and row["data"]["metadata"].get("uid") == uid]
    return matches[0] if len(matches) == 1 else None


class _Name(str):
    pass


def _obj(name, namespace, uid, owner=None, labels=None, **extra):
    metadata = {"name": name, "uid": uid, "labels": labels or {}}
    if namespace is not None:
        metadata["namespace"] = namespace
    if owner:
        metadata["ownerReferences"] = [dict(owner, controller=True)]
    return dict({"metadata": metadata}, **extra)


def _index():
    addon = {"addonmanager.kubernetes.io/mode": "Reconcile"}
    return {
        "deployment": [{"data": _obj("dns", "kube-system", "d1", labels=addon)},
                       {"data": _obj("app", "team", "d2")},
                       {"data": _obj("twin", "team", "d3")}, {"data": _obj("twin", "team", "d3")},
                       {"data": {"metadata": {"name": ["x"], "namespace": "team", "uid": "d4"}}},
                       {"data": "malformed"}, "malformed"],
        "replicaset": [{"data": _obj("dns-1", "kube-system", "r1", {"kind": "Deployment", "name": "dns", "uid": "d1"})},
                       {"data": _obj("app-1", "team", "r2", {"kind": "Deployment", "name": "app", "uid": "d2"})},
                       {"data": _obj("twin-1", "team", "r3", {"kind": "Deployment", "name": "twin", "uid": "d3"})}],
        "node": [{"data": _obj("gke-node", None, "n1", labels={"cloud.google.com/gke-nodepool": "p"})}],
    }


def test_table_lookup_matches_linear_scan():
    index = _index()
    probes = [(kind, ns, name, uid) for kind in ("deployment", "replicaset", "node", "missing")
              for ns in ("kube-system", "team", None, "other")
              for name in ("dns", "app", "twin", "dns-1", "app-1", "twin-1", "gke-node", "", None, _Name("dns"))
              for uid in ("d1", "d2", "d3", "r1", "r2", "r3", "n1", "", None)]
    for probe in probes:
        assert managed._lookup(index, *probe) == _linear(index, *probe), probe


def test_owner_chain_reasons_are_unchanged():
    index = _index()
    pod = _obj("dns-1-abc", "kube-system", "p1", {"kind": "ReplicaSet", "name": "dns-1", "uid": "r1"})
    assert managed.managed_reason(pod, "pod", index) == (
        "owned by managed ReplicaSet dns-1 (owned by managed Deployment dns (label addonmanager.kubernetes.io/mode=Reconcile))")
    assert managed.managed_reason(_obj("app-1-x", "team", "p2", {"kind": "ReplicaSet", "name": "app-1", "uid": "r2"}), "pod", index) is None
    # Two identical owners are ambiguous, as before.
    assert managed._lookup(index, "deployment", "team", "twin", "d3") is None


def test_table_follows_index_changes():
    index = _index()
    assert managed._lookup(index, "deployment", "team", "new", "d9") is None
    index["deployment"].append({"data": _obj("new", "team", "d9")})
    assert managed._lookup(index, "deployment", "team", "new", "d9") == index["deployment"][-1]["data"]
    index["deployment"] = [{"data": _obj("new", "team", "d9")}]
    assert managed._lookup(index, "deployment", "team", "dns", "d1") is None


def test_str_subclass_rows_keep_exact_comparison():
    index = {"deployment": [{"data": {"metadata": {"name": _Name("dns"), "namespace": "kube-system", "uid": "d1"}}}]}
    assert managed._lookup(index, "deployment", "kube-system", "dns", "d1") == _linear(index, "deployment", "kube-system", "dns", "d1")
    assert managed._lookup(index, "deployment", "kube-system", "dns", "d1") is not None
