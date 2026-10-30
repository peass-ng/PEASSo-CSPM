"""Provider-shaped facts for signed Pod UID and Ingress declaration predicates."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_k8s_workload_ingress as new
from peaso.collectors import k8s


def verdict(check_id, item, index=None):
    return evaluate_check(check_id, item, {} if index is None else index)


def ingress_index(*, controller="k8s.io/ingress-nginx", service_namespace="apps",
                  class_status="collected", service_status="collected"):
    return {"collections": {"ingressclass": [{"status": class_status}],
                            "service": [{"status": service_status}]},
            "ingressclass": [{"data": {"metadata": {"name": "nginx", "uid": "class-1"},
                                        "spec": {"controller": controller}}}],
            "service": [{"data": {"metadata": {"namespace": service_namespace, "name": "app"}}}]}


def test_pod_uid_inheritance_override_and_unknown_image_user():
    cid = new.POD_ID
    cases = new.CASES[cid]
    assert verdict(cid, cases["pass"])[0] == "PASS"
    status, evidence = verdict(cid, cases["fail"])
    assert status == "FAIL" and evidence["explicit_root_containers"] == ["app"]
    assert verdict(cid, cases["missing"])[0] == "UNKNOWN"
    assert verdict(cid, cases["malformed"])[0] == "UNKNOWN"
    windows = deepcopy(cases["pass"])
    windows["spec"]["os"]["name"] = "windows"
    assert verdict(cid, windows)[0] == "NOT_APPLICABLE"
    missing_os = deepcopy(cases["pass"])
    del missing_os["spec"]["os"]
    assert verdict(cid, missing_os)[0] == "UNKNOWN"
    init_root = deepcopy(cases["pass"])
    init_root["spec"]["initContainers"][0]["securityContext"]["runAsUser"] = 0
    assert verdict(cid, init_root)[0] == "FAIL"
    partial = deepcopy(cases["pass"])
    partial["spec"]["securityContext"] = {}
    assert verdict(cid, partial)[0] == "UNKNOWN"
    boolean_uid = deepcopy(cases["pass"])
    boolean_uid["spec"]["securityContext"]["runAsUser"] = True
    assert verdict(cid, boolean_uid)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", [new.BACKEND_ID, new.REDIRECT_ID])
def test_ingress_requires_resolved_ingressclass_controller_and_tls(cid):
    cases = new.CASES[cid]
    index = ingress_index()
    assert verdict(cid, cases["pass"], index)[0] == "PASS"
    assert verdict(cid, cases["fail"], index)[0] == "FAIL"
    assert verdict(cid, cases["missing"], index)[0] == "UNKNOWN"
    assert verdict(cid, cases["malformed"], index)[0] == "UNKNOWN"
    assert verdict(cid, cases["pass"], ingress_index(controller="example.net/other"))[0] == "UNKNOWN"
    assert verdict(cid, cases["pass"], ingress_index(class_status="denied"))[0] == "UNKNOWN"
    unnamed_class = deepcopy(cases["pass"])
    unnamed_class["spec"]["ingressClassName"] = "not-listed"
    assert verdict(cid, unnamed_class, index)[0] == "UNKNOWN"
    no_tls = deepcopy(cases["pass"])
    no_tls["spec"]["tls"] = []
    assert verdict(cid, no_tls, index)[0] == "NOT_APPLICABLE"


def test_backend_service_exact_namespace_and_declaration_limit():
    cid = new.BACKEND_ID
    item = new.CASES[cid]["pass"]
    status, evidence = verdict(cid, item, ingress_index())
    assert status == "PASS" and evidence["resolved_backend_services"] == ["app"]
    assert "runtime unverified" in evidence["semantics"]
    assert verdict(cid, item, ingress_index(service_namespace="other"))[0] == "UNKNOWN"
    assert verdict(cid, item, ingress_index(service_status="partial"))[0] == "UNKNOWN"
    missing_backend = deepcopy(item)
    missing_backend["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"] = "missing"
    assert verdict(cid, missing_backend, ingress_index())[0] == "UNKNOWN"
    no_annotation = deepcopy(new.CASES[cid]["fail"])
    assert verdict(cid, no_annotation, ingress_index())[0] == "FAIL"
    grpc = deepcopy(item)
    grpc["metadata"]["annotations"]["nginx.ingress.kubernetes.io/backend-protocol"] = "GRPCS"
    assert verdict(cid, grpc, ingress_index())[0] == "PASS"


def test_redirect_missing_and_conflicting_annotations_are_unknown():
    cid = new.REDIRECT_ID
    item = deepcopy(new.CASES[cid]["pass"])
    assert verdict(cid, item, ingress_index())[0] == "PASS"
    item["metadata"]["annotations"] = {}
    assert verdict(cid, item, ingress_index())[0] == "UNKNOWN"
    item["metadata"]["annotations"] = {
        "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
        "nginx.ingress.kubernetes.io/ssl-redirect": "false",
    }
    assert verdict(cid, item, ingress_index())[0] == "UNKNOWN"


def test_collector_preserves_only_three_bounded_nginx_annotations_and_class_endpoint():
    assert k8s.ENDPOINTS["ingressclass"] == ("/apis/networking.k8s.io/v1/ingressclasses", False)
    assert "ingressclass" in k8s.TYPES
    source = {"metadata": {"name": "app", "namespace": "apps", "uid": "ing-1",
                           "annotations": {"nginx.ingress.kubernetes.io/backend-protocol": "HTTPS",
                                           "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
                                           "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                                           "nginx.ingress.kubernetes.io/auth-secret": "sensitive-ref",
                                           "nginx.ingress.kubernetes.io/backend-protocol-unknown": "value"}},
              "spec": {"ingressClassName": "nginx", "tls": [{}]}}
    native = k8s._native(source, "ingress", "cluster-a", "apps", True)
    assert native["metadata"]["annotations"] == {
        "nginx.ingress.kubernetes.io/backend-protocol": "HTTPS",
        "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
        "nginx.ingress.kubernetes.io/ssl-redirect": "false",
    }
    assert k8s._native({"metadata": {"name": "nginx", "uid": "class-1"},
                        "spec": {"controller": "k8s.io/ingress-nginx"}},
                       "ingressclass", "cluster-a", "*", False)["spec"]["controller"] == "k8s.io/ingress-nginx"
    source["metadata"]["annotations"]["nginx.ingress.kubernetes.io/backend-protocol"] = "x" * 254
    oversized = k8s._native(source, "ingress", "cluster-a", "apps", True)
    assert "nginx.ingress.kubernetes.io/backend-protocol" not in oversized["metadata"]["annotations"]
    assert oversized["metadata"]["_coverage"]["annotations"]["status"] == "malformed"
    assert verdict(new.BACKEND_ID, oversized, ingress_index())[0] == "UNKNOWN"
    source["metadata"]["annotations"]["nginx.ingress.kubernetes.io/backend-protocol"] = 42
    assert verdict(new.BACKEND_ID, k8s._native(source, "ingress", "cluster-a", "apps", True), ingress_index())[0] == "UNKNOWN"


def test_ingressclass_inventory_uses_existing_bounded_pagination():
    class Reader:
        page_size = 1
        budget = type("Budget", (), {"max_pages": 3})()
        calls = []

        def call(self, request, path, params):
            self.calls.append((path, dict(params)))
            page = len(self.calls)
            return {"metadata": {"resourceVersion": "same", **({"continue": "next"} if page == 1 else {})},
                    "items": [{"metadata": {"name": "nginx" if page == 1 else "other", "uid": str(page)},
                               "spec": {"controller": "k8s.io/ingress-nginx" if page == 1 else "example.net/other"}}]}

    reader = Reader()
    api = type("API", (), {"get_json": lambda self, *args: None})()
    pages = list(k8s._pages(reader, api, k8s.ENDPOINTS["ingressclass"][0],
                            "ingressclass", "cluster-a", "*", False))
    assert [row[0]["metadata"]["name"] for row in pages] == ["nginx", "other"]
    assert reader.calls[0][1] == {"limit": 1}
    assert reader.calls[1][1] == {"limit": 1, "continue": "next"}
