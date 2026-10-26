"""Kubernetes collector CPU and latency changes keep output and requests identical."""
import gc
import io
import json
import re
import threading
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

import pytest
from urllib3 import HTTPResponse

from peaso import snapshot
from peaso.collectors import k8s, k8s_response_cache as rc, k8s_sanitize_keys, k8s_scan_gc
from peaso.collectors import k8s_annotation_indicators_20261020 as annotation_indicators


# --- deferred full garbage collection -------------------------------------------------

@pytest.fixture
def threshold():
    saved = gc.get_threshold()
    gc.set_threshold(700, 10, 10)
    yield
    gc.set_threshold(*saved)


def test_full_collections_are_deferred_and_restored_by_the_last_holder(threshold):
    outer = k8s_scan_gc.pause()
    assert gc.get_threshold() == (700, 10, k8s_scan_gc._DEFERRED)
    with k8s_scan_gc.paused():
        assert gc.get_threshold()[2] == k8s_scan_gc._DEFERRED
    assert gc.get_threshold()[2] == k8s_scan_gc._DEFERRED  # The outer scan still holds it.
    outer.close()
    outer.close()  # Idempotent: never restores twice or underflows.
    assert gc.get_threshold() == (700, 10, 10) and k8s_scan_gc._depth == 0


def test_a_threshold_changed_by_someone_else_is_left_alone(threshold):
    hold = k8s_scan_gc.pause()
    gc.set_threshold(100, 5, 5)
    hold.close()
    assert gc.get_threshold() == (100, 5, 5)


def test_disabled_automatic_collection_is_not_touched(threshold):
    gc.set_threshold(0, 10, 10)
    with k8s_scan_gc.paused():
        assert gc.get_threshold() == (0, 10, 10)
    assert gc.get_threshold() == (0, 10, 10)


# --- _sanitize key memo ------------------------------------------------------------------

def _reference_sanitize_drop(key):
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return bool((normalized != "automountserviceaccounttoken" and normalized.endswith(
        ("password", "token", "privatekey", "clientsecret", "secretvalue")))
        or normalized in ("apikey", "credentials", "stringdata", "privatekeydata") or key in ("managedFields",))


class _Key(str):
    pass


def _sample():
    return {
        "metadata": {"name": "web", "namespace": "a", "uid": "u", "resourceVersion": "1",
                     "annotations": {"nginx.ingress.kubernetes.io/server-snippet": "lua_x alias", "x": "y"},
                     "managedFields": [{"manager": "kubectl"}]},
        "spec": {"automountServiceAccountToken": True, "serviceAccountToken": "drop", "API_KEY": "drop",
                 "nested": {"clientSecret": "drop", "keep": [1, 2.5, None, True, {"password": "drop"}]},
                 _Key("password"): "subclass", 1: "one", True: "true",
                 annotation_indicators.MARKER: "forged",
                 "containers": [{"name": "c", "command": ["sh"], "args": ["-c"], "env": [{"name": "A", "value": "b"}]}]},
        "kind": "Ingress", "apiVersion": "networking.k8s.io/v1",
    }


def test_memoized_drop_decision_matches_the_rule_for_every_key():
    keys = ["password", "Password", "db-password", "automountServiceAccountToken", "serviceAccountToken",
            "apiKey", "API_KEY", "credentials", "stringData", "privateKeyData", "managedFields", "managed_fields",
            "name", "clientSecret", "secretValue", "privateKey", "tokenTTL", "spec", ""]
    k8s_sanitize_keys.DROPPED.clear()
    for _ in range(2):  # First pass computes, second pass is served from the memo.
        for key in keys:
            assert ("x" in k8s._sanitize({key: "x", "x": 1})) is True
            assert (key not in k8s._sanitize({key: "v"})) is _reference_sanitize_drop(key)
    assert all(k8s_sanitize_keys.DROPPED[key] is _reference_sanitize_drop(key) for key in keys)


def test_sanitize_output_is_the_same_with_a_cold_or_warm_memo_and_under_projection():
    token = annotation_indicators._TARGET_KIND.set("ingress")
    try:
        k8s_sanitize_keys.DROPPED.clear()
        cold = k8s._sanitize(_sample())
        warm = k8s._sanitize(_sample())
    finally:
        annotation_indicators._TARGET_KIND.reset(token)
    assert cold == warm and repr(cold) == repr(warm)
    assert cold[annotation_indicators.MARKER]["status"] == "projected"
    assert cold[annotation_indicators.MARKER]["flags"]["snippet"] is True
    assert "managedFields" not in cold["metadata"] and "serviceAccountToken" not in cold["spec"]
    assert cold["spec"]["automountServiceAccountToken"] is True and 1 in cold["spec"]
    assert annotation_indicators.MARKER not in cold["spec"]
    # Subclass keys are never memoized; they are still decided by the rule.
    assert not any(type(key) is not str for key in k8s_sanitize_keys.DROPPED)
    assert all(not isinstance(key, _Key) or "password" not in key for key in cold["spec"])


def test_projection_is_only_attempted_for_objects_with_a_spec():
    token = annotation_indicators._TARGET_KIND.set("ingress")
    try:
        row = {"metadata": {"name": "n", "namespace": "a", "uid": "u", "resourceVersion": "1"}}
        assert annotation_indicators.project(row) is None
        assert annotation_indicators.MARKER not in k8s._sanitize(row)
    finally:
        annotation_indicators._TARGET_KIND.reset(token)


def test_memo_is_bounded_and_keeps_only_booleans():
    k8s_sanitize_keys.DROPPED.clear()
    for index in range(k8s_sanitize_keys.MAX_KEYS + 10):
        k8s_sanitize_keys.remember(f"k{index}", False)
    assert len(k8s_sanitize_keys.DROPPED) <= k8s_sanitize_keys.MAX_KEYS
    assert set(k8s_sanitize_keys.DROPPED.values()) <= {True, False}
    k8s_sanitize_keys.DROPPED.clear()


# --- snapshot.thaw -------------------------------------------------------------------

def _reference_thaw(value):
    if isinstance(value, dict):
        return {key: _reference_thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_reference_thaw(item) for item in value]
    return value


def test_thaw_is_an_independent_deep_copy_identical_to_the_recursive_definition():
    class Text(str):
        pass
    source = {"a": [1, 2.5, None, True, "s", Text("t"), (1, {"b": [2]})], "c": {"d": {"e": []}},
              "f": snapshot.freeze({"g": [{"h": 1}], "i": (3,)})}
    copied = snapshot.thaw(source)
    assert copied == _reference_thaw(source)
    assert type(copied["f"]) is dict and type(copied["f"]["g"]) is list and copied["a"][6] == [1, {"b": [2]}]
    assert type(copied["a"][5]) is Text
    copied["a"][6][1]["b"].append(3)
    copied["c"]["d"]["e"].append(1)
    assert source["a"][6][1]["b"] == [2] and source["c"]["d"]["e"] == []


# --- warmed per-namespace Secret Table reads ------------------------------------------

SERVER = "https://api.example:443"


class _Cluster:
    """Inner transport: a metadata-only Secret list and one Table per namespace."""

    def __init__(self, namespaces=("b", "a", "c")):
        self.calls, self.lock = [], threading.Lock()
        self.items = [{"metadata": {"name": f"s{i}", "namespace": ns, "uid": f"{ns}-{i}", "resourceVersion": "7"}}
                      for ns in namespaces for i in range(2)]
        self.connection_pool_kw = {}

    def request(self, method, url, **kwargs):
        target = urlsplit(url)
        query = dict(parse_qsl(target.query)) | dict(kwargs.get("fields") or ())
        with self.lock:
            self.calls.append((target.path, tuple(sorted(query.items()))))
        if target.path == "/api/v1/secrets":
            body = {"kind": "PartialObjectMetadataList", "apiVersion": "meta.k8s.io/v1",
                    "metadata": {"resourceVersion": "7"}, "items": self.items}
        else:
            namespace = target.path.split("/")[4]
            rows = [{"cells": [item["metadata"]["name"], "Opaque"], "object": None}
                    for item in self.items if item["metadata"]["namespace"] == namespace]
            body = {"kind": "Table", "apiVersion": "meta.k8s.io/v1", "metadata": {"resourceVersion": "7"},
                    "columnDefinitions": [{"name": "Name"}, {"name": "Type"}], "rows": rows}
        raw = json.dumps(body).encode()
        return HTTPResponse(body=io.BytesIO(raw), status=200, preload_content=False,
                            headers={"Content-Length": str(len(raw))})


def _api(cluster):
    pool = k8s._BoundedPool(cluster, SERVER)

    def call_api(path, method, query_params=(), header_params=None, **_):
        return pool.request(method, SERVER + path, fields=list(query_params), headers=dict(header_params or {}),
                            preload_content=False)
    return SimpleNamespace(api_client=SimpleNamespace(call_api=call_api, rest_client=SimpleNamespace(pool_manager=pool)))


def _reader(workers=4, max_calls=None):
    return SimpleNamespace(call=lambda operation, *args, **kwargs: operation(*args, **kwargs), page_size=500,
                           workers=workers, budget=SimpleNamespace(max_pages=None, max_calls=max_calls, calls=0))


def _read_secret_metadata(reader, cached):
    cluster = _Cluster()
    api = _api(cluster)
    if cached:
        rc.install(api)
    try:
        pages = list(k8s._metadata_pages(reader, api, "/api/v1/secrets", "secret_metadata", "c", "*", True,
                                         include_type=True))
    finally:
        stats = rc.uninstall(api) if cached else None
    return pages, sorted(cluster.calls), stats


def test_warmed_table_reads_return_the_same_inventory_and_the_same_requests():
    plain, plain_calls, _ = _read_secret_metadata(_reader(), cached=False)
    warmed, warmed_calls, stats = _read_secret_metadata(_reader(), cached=True)
    assert json.dumps(warmed, sort_keys=True) == json.dumps(plain, sort_keys=True)
    assert warmed_calls == plain_calls and len(plain_calls) == 4  # One list and one Table per namespace.
    assert stats["misses"] == 4 and stats["hits"] + stats["misses"] == 7
    assert all(item["type"] == "Opaque" for page in warmed for item in page)


def test_serial_or_budgeted_readers_are_never_warmed():
    for reader in (_reader(workers=1), _reader(max_calls=2)):
        _, calls, stats = _read_secret_metadata(reader, cached=True)
        assert stats["hits"] == 0 and len(calls) == 4


def test_warm_needs_an_installed_cache_and_stops_at_scan_end():
    cluster = _Cluster()
    api = _api(cluster)
    done = threading.Event()

    def read():
        try:
            k8s._metadata_get(api, "/api/v1/namespaces/a/secrets", {"limit": 500, "includeObject": "None",
                              "resourceVersion": "7", "resourceVersionMatch": "Exact"}, "Table")
        finally:
            done.set()
    assert rc.warm(api, [read], _reader()) == 0 and cluster.calls == []
    rc.install(api)
    pool = api.api_client.rest_client.pool_manager.pool
    assert rc.warm(api, [read], _reader()) == 1
    assert done.wait(5)
    rc.uninstall(api)
    assert pool._warmer is None and pool._closed
    assert rc.warm(api, [read], _reader()) == 0 and len(cluster.calls) == 1


# --- the snapshot adopts the collector's item lists (make_snapshot(owned=True)) ---------

def _routes():
    def lst(items):
        return {"metadata": {"resourceVersion": "1"}, "items": items}
    shared_labels = {"app": "web", "tier": ["front"]}  # One object referenced by several responses.
    container = {"name": "c", "image": "nginx:1", "env": [{"name": "MODE", "value": "x"}],
                 "securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}, "ports": [{"containerPort": 80}]}
    pod = {"metadata": {"name": "web", "namespace": "apps", "uid": "p1", "labels": shared_labels,
                        "annotations": {"note": "kept"}},
           "spec": {"serviceAccountName": "web", "nodeName": "n1", "containers": [container, container]},
           "status": {"phase": "Running", "containerStatuses": [{"name": "c", "ready": True}]}}
    template = {"metadata": {"labels": shared_labels}, "spec": {"containers": [container]}}
    return {
        "/api/v1/pods": lst([pod]),
        "/api/v1/namespaces": lst([{"metadata": {"name": "apps", "uid": "n1", "labels": shared_labels}}]),
        "/api/v1/nodes": lst([{"metadata": {"name": "n1", "uid": "node1", "labels": shared_labels},
                               "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}}]),
        "/api/v1/services": lst([{"metadata": {"name": "web", "namespace": "apps", "uid": "s1", "labels": shared_labels},
                                  "spec": {"type": "LoadBalancer", "selector": shared_labels, "ports": [{"port": 80}]}}]),
        "/api/v1/serviceaccounts": lst([{"metadata": {"name": "web", "namespace": "apps", "uid": "sa1"}}]),
        "/apis/apps/v1/deployments": lst([{"metadata": {"name": "web", "namespace": "apps", "uid": "d1"},
                                           "spec": {"selector": {"matchLabels": shared_labels}, "template": template}}]),
        "/apis/rbac.authorization.k8s.io/v1/clusterroles": lst([{"metadata": {"name": "admin", "uid": "r1"},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]}]),
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": lst([{"metadata": {"name": "b", "uid": "rb1"},
            "roleRef": {"kind": "ClusterRole", "name": "admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "web", "namespace": "apps"}]}]),
        "/apis/networking.k8s.io/v1/networkpolicies": lst([{"metadata": {"name": "np", "namespace": "apps", "uid": "np1"},
            "spec": {"podSelector": {"matchLabels": shared_labels}, "ingress": [{}]}}]),
    }


def _evidence():
    coverage = {"mode": {"status": "observed"}}
    return {"metadata_evidence": {
        "file_metadata": [{"path": "/etc/kubernetes/kubelet.conf", "uid": 0, "gid": 0, "mode": "0600",
                           "node_name": "n1", "node_uid": "node1", "observed_at": "2026-10-26T00:00:00Z",
                           "_coverage": coverage}],
        "secret_metadata": [{"metadata": {"name": "s", "namespace": "apps", "labels": {"k": "v"}}, "type": "Opaque"}]}}


def _containers(value, out):
    if isinstance(value, (dict, list)):
        out.append(value)
        for child in (value.values() if isinstance(value, dict) else value):
            _containers(child, out)
    return out


def _module_containers():
    import sys
    seen, stack = set(), [vars(module) for name, module in list(sys.modules.items())
                          if module is not None and name.startswith(("peaso.collectors", "peaso.snapshot"))]
    while stack:
        value = stack.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, dict):
            stack.extend(v for v in value.values() if isinstance(v, (dict, list, tuple, set, frozenset)))
        elif isinstance(value, (list, tuple, set, frozenset)):
            stack.extend(v for v in value if isinstance(v, (dict, list, tuple, set, frozenset)))
    return seen


def _namespaced(routes, namespaces):
    out = dict(routes)
    for path, document in routes.items():
        head, _, plural = path.rpartition("/")
        if plural in ("namespaces", "nodes", "clusterroles", "clusterrolebindings"):
            continue
        for namespace in namespaces:
            out[f"{head}/namespaces/{namespace}/{plural}"] = document  # The same object behind several reads.
    return out


def _collect(owned=True, monkeypatch=None, scopes=None):
    from tests.test_peaso_collectors_k8s_privesc_facts import FakeKube
    routes, options = _routes(), _evidence()
    if scopes:
        routes = _namespaced(routes, scopes)
    if not owned:
        real = k8s.make_snapshot
        monkeypatch.setattr(k8s, "make_snapshot", lambda *a, **kw: real(*a, **{**kw, "owned": False}))
    connector = {"provider": "k8s", "auth": {"cluster_id": "fixture"}, "options": options}
    if scopes:
        connector["scopes"] = list(scopes)
    snap = k8s.collect(connector, api=FakeKube(routes))
    return snap, routes, options


def _scramble(value):
    if isinstance(value, dict):
        for key in list(value):
            _scramble(value[key])
            value[key] = "MUTATED" if not isinstance(value[key], (dict, list)) else value[key]
        value["mutated"] = True
    elif isinstance(value, list):
        for child in value:
            _scramble(child)
        value.append("MUTATED")


@pytest.mark.parametrize("scopes", [None, ("apps", "ops")])
def test_adopted_items_share_nothing_with_the_api_responses_options_or_module_state(scopes):
    snap, routes, options = _collect(scopes=scopes)
    items = [item for collection in snap["collections"] for item in collection["items"]]
    assert {c["type"] for c in snap["collections"] if c["items"]} >= {"pod", "deployment", "clusterrole", "file_metadata"}
    adopted = _containers(items, [])
    ids = [id(value) for value in adopted]
    assert len(ids) == len(set(ids)), "an item container is shared inside the snapshot"
    inputs = {id(value) for value in _containers([routes, options], [])}
    assert not inputs.intersection(ids), "a snapshot item aliases an API response or connector option"
    assert not _module_containers().intersection(ids), "a snapshot item aliases module-level state"


@pytest.mark.parametrize("scopes", [None, ("apps", "ops")])
def test_mutating_every_source_after_the_snapshot_leaves_its_digest_unchanged(scopes):
    snap, routes, options = _collect(scopes=scopes)
    before = snapshot.canonical(snap)
    _scramble(routes)
    _scramble(options)
    assert snapshot.canonical(snap) == before
    assert snapshot.validate(snap)["snapshot_id"] == snap["snapshot_id"]


@pytest.mark.parametrize("scopes", [None, ("apps", "ops")])
def test_adopting_items_gives_the_same_snapshot_bytes_as_copying_them(monkeypatch, scopes):
    adopted, _, _ = _collect(scopes=scopes)
    copied, _, _ = _collect(owned=False, monkeypatch=monkeypatch, scopes=scopes)
    for snap in (adopted, copied):
        snap.pop("snapshot_id")
        snap["created_at"] = "fixed"
        snap["metadata"].pop("captured_at", None)
    assert snapshot.canonical(adopted) == snapshot.canonical(copied)


def test_make_snapshot_owned_adopts_item_lists_and_still_copies_envelopes():
    items = [{"a": [1]}]
    collections = [{"type": "pod", "scope": "*", "status": "collected", "items": items}]
    metadata = {"m": {"n": 1}}
    owned = snapshot.make_snapshot("k8s", ["*"], collections, created_at="t", metadata=metadata, owned=True)
    copied = snapshot.make_snapshot("k8s", ["*"], collections, created_at="t", metadata=metadata)
    assert owned == copied and owned["snapshot_id"] == copied["snapshot_id"]
    assert owned["collections"][0]["items"] is items and copied["collections"][0]["items"] is not items
    assert owned["collections"][0] is not collections[0] and owned["metadata"]["m"] is not metadata["m"]


# --- streamed snapshot digest -------------------------------------------------------

def _reference_digest(value):
    import hashlib
    return "sha256:" + hashlib.sha256(snapshot.canonical(value).encode()).hexdigest()


def test_streamed_digest_hashes_exactly_the_canonical_bytes():
    class Key(str):
        pass
    documents = [
        {"collections": [], "metadata": {}},
        {"z": 1, "collections": [{"type": "pod", "items": [{"é": "ü", "n": 1.5, "b": None}]}, 3, "x", [1]],
         "a": {"b": [1, {"c": "✓"}]}, "provider": "k8s"},
        {"collections": [{"items": [{"k": i, "v": [str(i)] * i} for i in range(20)]}] * 3, "scopes": ["*"]},
        {"collections": "not-a-list", "x": 1},
        {1: "int key", 2: []},
        {Key("k"): 1, "collections": []},
        snapshot.FrozenDict({"collections": snapshot.FrozenList([{"a": 1}])}),
        [{"collections": []}], "text", 1, None,
    ]
    for document in documents:
        assert snapshot.digest(document) == _reference_digest(document)
    snap = snapshot.make_snapshot("k8s", ["*"], [{"type": "pod", "scope": "*", "status": "collected",
                                                 "items": [{"metadata": {"name": "ü"}}]}], created_at="t")
    body = {key: value for key, value in snap.items() if key != "snapshot_id"}
    assert snap["snapshot_id"] == _reference_digest(body)


def test_streamed_digest_rejects_what_canonical_rejects():
    for bad in ({"collections": [{"x": float("nan")}]}, {"collections": [{"x": object()}]}):
        with pytest.raises((ValueError, TypeError)) as streamed:
            snapshot.digest(bad)
        with pytest.raises((ValueError, TypeError)) as reference:
            _reference_digest(bad)
        assert type(streamed.value) is type(reference.value) and str(streamed.value) == str(reference.value)
    loop = {"collections": []}
    loop["collections"].append({"parent": loop})
    with pytest.raises(ValueError):
        snapshot.digest(loop)


# --- remembered resource-id part encoding ------------------------------------------------

def test_quoted_id_parts_equal_quote_and_stay_bounded():
    from urllib.parse import quote
    from peaso.collectors import k8s_id_parts

    class Text(str):
        pass
    k8s_id_parts.QUOTED.clear()
    for text in ["fixture", "kube-system", "a/b c", "ü✓", "", "%2F", "_cluster", Text("x/y")] * 2:
        assert k8s_id_parts.quoted(text) == quote(text, safe="")
    assert all(type(key) is str for key in k8s_id_parts.QUOTED) and "x/y" not in k8s_id_parts.QUOTED
    for index in range(k8s_id_parts.MAX_PARTS + 5):
        k8s_id_parts.quoted(f"ns-{index}")
    assert len(k8s_id_parts.QUOTED) <= k8s_id_parts.MAX_PARTS
    k8s_id_parts.QUOTED.clear()


def test_native_ids_are_unchanged_by_the_part_memo():
    from urllib.parse import quote
    item = {"metadata": {"name": "web", "namespace": "a b/c", "uid": "u/1"}, "kind": "Pod", "apiVersion": "v1",
            "spec": {"containers": []}}
    for _ in range(2):
        row = k8s._native(dict(item), "pod", "clu ster", "*", True)
        assert row["id"] == "k8s://" + "/".join(quote(x, safe="") for x in ("clu ster", "pod", "a b/c", "u/1"))
