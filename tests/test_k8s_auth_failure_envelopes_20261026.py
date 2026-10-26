"""A Kubernetes client that cannot be built still yields one valid envelope per inventory.

Regression: a kubeconfig whose user runs an exec helper (e.g. gke-gcloud-auth-plugin) is refused
before any request. The failure handler marked every wanted kind unavailable, including node_clock,
and the node_clock projection then appended its own envelope: make_snapshot rejected the
duplicate ('node_clock', '*') and the whole scan failed. No network access is attempted here.
"""
import socket

import pytest

from peaso.collectors import k8s
from peaso.engine import evaluate_snapshot

KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- name: c
  cluster: {server: "https://203.0.113.10"}
contexts:
- name: c
  context: {cluster: c, user: u}
current-context: c
users:
- name: u
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: /bin/false
      provideClusterInfo: true
"""


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.mark.parametrize("inventories", [["node_clock"], ["node_clock", "node", "namespace", "pod"], None])
def test_refused_exec_kubeconfig_yields_unique_envelopes_and_one_node_clock(inventories):
    options = {} if inventories is None else {"inventories": inventories}
    snap = k8s.collect({"provider": "k8s", "auth": {"kubeconfig_data": KUBECONFIG, "cluster_id": "c"}, "options": options})
    keys = [(c["type"], c["scope"]) for c in snap["collections"]]
    assert len(keys) == len(set(keys))
    clock = [c for c in snap["collections"] if c["type"] == "node_clock"]
    assert len(clock) == 1 and clock[0]["scope"] == "*"
    assert clock[0]["status"] == "not_collected" and clock[0]["error"]["code"] == "external_clock_measurement_unavailable"
    native = [c for c in snap["collections"] if c["type"] != "node_clock"]
    assert (inventories == ["node_clock"] or native) and all(c["status"] not in ("collected", "empty") and c["items"] == [] for c in native)
    evaluate_snapshot(snap)  # The engine accepts the snapshot.
