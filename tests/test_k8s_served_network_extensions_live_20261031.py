"""Network extension CRDs as GKE Dataplane V2 serves them.

Cilium serves its CRDs at cilium.io/v2 and installs only some of them. The transport must admit a
reviewed plural at the negotiated served version, and a policy resource missing from a served group
cannot exist, so it is empty rather than unknown.
"""
import pytest

from peaso.collectors import k8s
from tests.test_peaso_collectors_azurek8s import FakeKube


class InnerPool:
    def __init__(self):
        self.urls = []

    def request(self, method, url, **kwargs):
        self.urls.append(url)
        return "ok"


@pytest.mark.parametrize("path", ["/apis/cilium.io/v2/ciliumendpoints",
                                  "/apis/cilium.io/v2/namespaces/apps/ciliumendpoints",
                                  "/apis/cilium.io/v2/ciliumnodes"])
def test_transport_admits_reviewed_extension_at_served_version(path):
    inner = InnerPool()
    pool = k8s._BoundedPool(inner, "https://cluster.example")
    assert pool.request("GET", "https://cluster.example" + path) == "ok"


@pytest.mark.parametrize("path", ["/apis/cilium.io/v2/ciliumidentities",
                                  "/apis/cilium.io/v2/namespaces/apps/ciliumnodes",
                                  "/apis/cilium.io/v2/ciliumendpoints/x/status"])
def test_transport_still_rejects_unreviewed_or_misscoped_extension_paths(path):
    pool = k8s._BoundedPool(InnerPool(), "https://cluster.example")
    with pytest.raises(ValueError):
        pool.request("GET", "https://cluster.example" + path)


def discovery(path, params):
    if path == "/apis":
        return {"groups": [{"name": "cilium.io", "versions": [{"version": "v2"}]},
                           {"name": "policy.networking.k8s.io", "versions": [{"version": "v1alpha2"}]}]}
    if path == "/apis/cilium.io/v2":
        return {"resources": [{"name": "ciliumendpoints", "namespaced": True, "verbs": ["list"]}]}
    if path == "/apis/policy.networking.k8s.io/v1alpha2":
        return {"resources": [{"name": "clusternetworkpolicies", "namespaced": False, "verbs": ["list"]}]}
    if path in ("/api", "/version", "/api/v1"):
        return {}
    pytest.fail("unexpected read " + path)


def test_policy_resource_missing_from_served_group_is_empty():
    snap = k8s.collect({"scopes": ["*"]}, ["cilium_networkpolicy", "cilium_clusterwide_networkpolicy",
                                           "admin_networkpolicy"], api=FakeKube(discovery))
    rows = {c["type"]: c for c in snap["collections"] if c["type"] != "api_discovery"}
    assert set(rows) == {"cilium_networkpolicy", "cilium_clusterwide_networkpolicy", "admin_networkpolicy"}
    assert all(row["status"] == "empty" and row["items"] == [] for row in rows.values())


def test_policy_resource_served_only_at_another_version_stays_unknown():
    def handler(path, params):
        if path == "/apis":
            return {"groups": [{"name": "cilium.io", "versions": [{"version": "v3"}]}]}
        if path == "/apis/cilium.io/v3":
            return {"resources": [{"name": "ciliumnetworkpolicies", "namespaced": True, "verbs": ["list"]}]}
        return discovery(path, params)
    snap = k8s.collect({"scopes": ["*"]}, ["cilium_networkpolicy"], api=FakeKube(handler))
    row = next(c for c in snap["collections"] if c["type"] == "cilium_networkpolicy")
    assert row["status"] not in ("empty", "collected")
