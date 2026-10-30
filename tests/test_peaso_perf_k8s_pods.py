"""Pod lookups of the K8s privesc model equal a plain scan of model.pods.

Fixture for the pod-index optimization (ledgers/proposed-k8s-pods.patch): every pod-based selector, the
`node` placeholder and _pods_for_sa are checked against reference scans over model.pods (the pre-index code), across
two clusters sharing namespace / service-account / node names, pods without a node, non-running pods and an SA or
node with no pods. The checks hold before and after the patch, so they pin its output.
"""
from peaso.privesc.effective_permissions.k8s import K8sModel


def obj(kind, name, ns=None, cluster="c1", **body):
    meta = {"name": name}
    if ns:
        meta["namespace"] = ns
    return {"kind": kind, "metadata": meta, "provenance": {"cluster_id": cluster}, **body}


def pod(name, ns, sa, node, cluster="c1", phase="Running", privileged=False, host=False, owned=False, configmap=False):
    spec = {"serviceAccountName": sa, "containers": [{"name": "c", "image": "i", "securityContext": {"privileged": privileged}}]}
    if node:
        spec["nodeName"] = node
    if host:
        spec["volumes"] = [{"name": "h", "hostPath": {"path": "/var/run"}}]
    if configmap:
        spec.setdefault("volumes", []).append({"name": "cm", "configMap": {"name": "cfg"}})
    item = obj("Pod", name, ns, cluster, spec=spec, status={"phase": phase})
    if owned:
        item["metadata"]["ownerReferences"] = [{"kind": "ReplicaSet", "name": "rs"}]
    return item


def snapshot():
    pods = [pod("p1", "a", "builder", "n1", privileged=True),
            pod("p2", "a", "builder", None, phase="Pending"),
            pod("p3", "a", "default", "n2", host=True, owned=True, configmap=True),
            pod("p4", "b", "builder", "n1", phase="Succeeded"),
            pod("p5", "a", "builder", "n1", cluster="c2", privileged=True, owned=True),
            pod("p6", "a", "builder", "n1", owned=True)]
    sas = [obj("ServiceAccount", n, ns, c) for c, ns, n in
           (("c1", "a", "builder"), ("c1", "a", "default"), ("c1", "b", "builder"), ("c1", "b", "app"), ("c2", "a", "builder"))]
    nodes = [obj("Node", n, None, c) for c, n in (("c1", "n1"), ("c1", "n2"), ("c1", "n3"), ("c2", "n1"))]
    namespaces = [obj("Namespace", ns, None, c) for c, ns in (("c1", "a"), ("c1", "b"), ("c2", "a"))]
    cols = [("pod", pods), ("serviceaccount", sas), ("node", nodes), ("namespace", namespaces), ("role", []), ("rolebinding", []),
            ("clusterrole", []), ("clusterrolebinding", [])]
    return {"schema_version": 1, "provider": "k8s", "scopes": ["c1"], "metadata": {},
            "collections": [{"type": t, "scope": "c1", "service": t, "status": "collected", "items": i, "error": None} for t, i in cols]}


def model_and_nodes():
    model = K8sModel(snapshot())
    return model, list(model.sas.values()), list(model.nodes.values())


def ref_pods_for_sa(model, sa):
    return [p for p in model.pods if p["cluster"] == sa.attrs["cluster"] and p["ns"] == sa.attrs["namespace"]
            and p["sa"] == sa.attrs["name"]]


def ref_on_node(model, node):
    return [p for p in model.pods if p["node"] == node.attrs.get("name") and p["cluster"] == node.attrs.get("cluster")]


def test_fixture_exercises_shared_names_and_empty_lookups():
    model, sas, nodes = model_and_nodes()
    assert len(model.pods) == 6
    counts = sorted(len(ref_pods_for_sa(model, sa)) for sa in sas)
    assert counts[0] == 0 and counts[-1] >= 3          # an SA without pods and one with several
    assert any(not ref_on_node(model, n) for n in nodes)   # a node without pods
    assert {n.attrs["cluster"] for n in nodes if n.attrs["name"] == "n1"} == {"c1", "c2"}


def test_pods_for_sa_matches_scan_in_order():
    model, sas, _ = model_and_nodes()
    for sa in sas:
        got = model._pods_for_sa(sa)
        assert got == ref_pods_for_sa(model, sa)
        assert all(a is b for a, b in zip(got, ref_pods_for_sa(model, sa)))
        got.append("sentinel")                          # callers get their own list
        assert model._pods_for_sa(sa) == ref_pods_for_sa(model, sa)


def test_pods_added_after_first_lookup_are_seen():
    model, sas, nodes = model_and_nodes()
    sa = next(s for s in sas if s.attrs["name"] == "app")
    assert model._pods_for_sa(sa) == []
    model.pods.append(dict(model.pods[0], ns="b", sa="app", node="n3"))
    assert model._pods_for_sa(sa) == ref_pods_for_sa(model, sa) and len(model._pods_for_sa(sa)) == 1
    n3 = next(n for n in nodes if n.attrs["name"] == "n3")
    assert set(model.selector("k8s_node_hosting_pods_with_sa", True, {n3.id: n3}, None)) == {n3.id}


def test_node_placeholder_matches_scan():
    model, sas, _ = model_and_nodes()
    for sa in sas:
        expected = sorted({p["node"] for p in ref_pods_for_sa(model, sa) if p["node"]}) or None
        got = model.placeholder_values("source.node", sa, None)
        assert (got or None) == expected


def candidates(nodes):
    return {n.id: n for n in nodes}


def hosted(pod):
    # A node hosts the SA's pod while it runs, or is conditionally bound while pending; finished pods do not count.
    return not pod["deleting"] and (pod["running"] or pod["phase"] in ("Pending", None))


def test_pod_selectors_match_scan():
    model, sas, nodes = model_and_nodes()
    both = candidates(sas + nodes)
    expect = {
        "k8s_sa_used_by_pending_pod": {s.id for s in sas if any(p["phase"] == "Pending" and not p["node"] for p in ref_pods_for_sa(model, s))},
        "k8s_sa_used_by_pod_consuming_configmap": {s.id for s in sas if any(p["configmaps"] and p["running"] for p in ref_pods_for_sa(model, s))},
        "k8s_sa_used_by_running_pod": {s.id for s in sas if any(p["running"] for p in ref_pods_for_sa(model, s))}
                                      | {n.id for n in nodes if ref_on_node(model, n)},
        "k8s_sa_used_by_controller_managed_pod": {s.id for s in sas if any(p["owned"] for p in ref_pods_for_sa(model, s))}
                                                 | {n.id for n in nodes if ref_on_node(model, n)},
        "k8s_node_hosting_pods_with_sa": {s.id for s in sas if any(p["node"] and hosted(p) for p in ref_pods_for_sa(model, s))}
                                         | {n.id for n in nodes if ref_on_node(model, n)},
    }
    for key, wanted in expect.items():
        assert set(model.selector(key, True, both, None)) == wanted, key
    # A k8s_node source restricts the SA's pods to that node.
    for source in nodes:
        got = set(model.selector("k8s_node_hosting_pods_with_sa", True, candidates(sas), source))
        assert got == {s.id for s in sas if any(p["node"] == source.attrs["name"] and hosted(p)
                                                for p in ref_pods_for_sa(model, s))}


def test_node_hosting_pod_of_source_matches_scan():
    model, sas, nodes = model_and_nodes()
    for sa in sas:
        hosts = {p["node"] for p in ref_pods_for_sa(model, sa) if p["node"] and p["running"]}
        got = set(model.selector("k8s_node_hosting_pod_of_source", True, candidates(nodes), sa))
        assert got == {n.id for n in nodes if n.attrs["name"] in hosts}


def test_node_hosting_privileged_or_host_mount_pod_in_namespace_matches_scan():
    model, _, nodes = model_and_nodes()
    for key, field in (("k8s_node_hosting_privileged_pod_in_namespace", "privileged"),
                       ("k8s_node_hosting_host_mount_pod_in_namespace", "host_mount")):
        for value, namespaces in (("*", None), ("a", {"a"}), ("b", {"b"})):
            wanted = {n.id for n in nodes if any((namespaces is None or p["ns"] in namespaces) and p.get(field) is True
                                                 for p in ref_on_node(model, n))}
            assert set(model.selector(key, value, candidates(nodes), None)) == wanted, (key, value)
    assert any(set(model.selector("k8s_node_hosting_privileged_pod_in_namespace", "*", candidates(nodes), None)))
