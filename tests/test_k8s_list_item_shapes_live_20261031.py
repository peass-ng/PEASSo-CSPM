"""Checks must evaluate objects as a real API list returns them.

Items of a typed list carry no per-item kind, and an Ingress without TLS simply has no spec.tls.
Neither absence may turn the check UNKNOWN.
"""
import pytest

from peaso.collectors import k8s
from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_azurek8s import kube_list
from tests.test_peaso_k8s_read_boundary import sdk_spy

POD = {"metadata": {"name": "web", "namespace": "apps", "uid": "uid-web", "resourceVersion": "5"},
       "spec": {"containers": [{"name": "c", "image": "registry.example/web:1"}]}}
INGRESS = {"metadata": {"name": "web", "namespace": "apps", "uid": "uid-ing", "resourceVersion": "6"},
           "spec": {"rules": [{"host": "app.example.org", "http": {"paths": []}}]}}


def handler(url, kwargs):
    from urllib.parse import urlsplit
    path = urlsplit(url).path.removeprefix("/control")
    if path.endswith("/pods"):
        return kube_list([POD])
    if path.endswith("/ingresses"):
        return kube_list([INGRESS])
    if path.endswith("/secrets"):
        return {"kind": "PartialObjectMetadataList", "apiVersion": "meta.k8s.io/v1",
                "metadata": {"resourceVersion": "7"}, "items": []}
    return {"groups": []} if path == "/apis" else kube_list([])


def statuses(kinds, check):
    api, _ = sdk_spy(handler)
    snap = k8s.collect({"scopes": ["apps"]}, kinds, api=api)
    assert all(c["status"] in ("collected", "empty") for c in snap["collections"] if c["type"] in kinds)
    report = evaluate_snapshot(snap, checks=[check])
    return {o["status"] for f in report["findings"] if f["check_id"] == check
            for o in (f.get("observations") or [f]) if o.get("resource_name") in ("web", None) and o["status"] != "NOT_APPLICABLE"}


def test_pod_list_item_without_kind_is_evaluated():
    found = statuses(["pod"], "k8s_pod_secret_pod_rule_non_compliant_fcdc38e543")
    assert found and "UNKNOWN" not in found


@pytest.mark.parametrize("check,kinds", [("k8s_ingress_sni_hosts", ["ingress"]),
                                         ("k8s_ingress_tls_configured", ["ingress", "secret_metadata"])])
def test_ingress_without_tls_fails_instead_of_unknown(check, kinds):
    assert statuses(kinds, check) == {"FAIL"}
