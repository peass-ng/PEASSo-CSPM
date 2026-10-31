"""Inert transport spies; no Kubernetes server or credentials."""
from types import SimpleNamespace
import pytest
from peaso.collectors import k8s


def boundary(server=None):
    calls = []
    pool = SimpleNamespace(request=lambda *a, **kw: calls.append((a, kw)) or object())
    return k8s._BoundedPool(pool, server) if server else k8s._BoundedPool(pool), calls


def test_interactive_get_rejected_before_io():
    pool, calls = boundary()
    with pytest.raises(ValueError):
        pool.request("GET", "https://cluster.example/api/v1/namespaces/default/pods/p/attach")
    assert calls == []


def test_access_checker_can_only_post_self_subject_access_review():
    pool, calls = boundary("https://cluster.example")
    path = "https://cluster.example/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
    with pytest.raises(ValueError):
        pool.request("POST", path, body=b"{}")
    pool.allow_self_subject_access_review = True
    pool.request("POST", path, body=b"{}")
    for url in ("https://other.example/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                "https://cluster.example/api/v1/namespaces"):
        with pytest.raises(ValueError):
            pool.request("POST", url, body=b"{}")
    with pytest.raises(ValueError):
        pool.request("POST", path + "?extra=true", body=b"{}")
    assert len(calls) == 1
    assert calls[0][1]["redirect"] is False and calls[0][1]["retries"] is False


@pytest.mark.parametrize("path", [
    "/api/v1/nodes/node/proxy/other", "/api/v1/namespaces/default/pods/p/exec",
    "/api/v1/namespaces/default/pods/p/portforward", "/api/v1/nodes/node/proxy/configz/extra",
    "/api/v1/nodes/node%2fother/proxy/configz", "/api/v1/../api/v1/pods",
    "/api//v1/pods", "/api/v1/namespaces/default/secrets/name",
])
def test_noninventory_paths_rejected(path):
    pool, calls = boundary()
    with pytest.raises(ValueError):
        pool.request("GET", "https://cluster.example" + path)
    assert not calls


def test_current_inventory_paths_and_discovery():
    pool, calls = boundary()
    paths = [path for path, _ in k8s.ENDPOINTS.values()]
    paths += [path.rsplit("/", 1)[0] + "/namespaces/default/" + path.rsplit("/", 1)[1]
              for path, namespaced in k8s.ENDPOINTS.values() if namespaced]
    paths += ["/apis", "/version", "/apis/policy/v1beta1", "/apis/policy/v1beta1/podsecuritypolicies",
              "/apis/security.openshift.io/v1/securitycontextconstraints",
              "/apis/admissionregistration.k8s.io/v1", "/apis/cilium.io/v2",
              "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
              "/apis/admissionregistration.k8s.io/v1beta1/validatingadmissionpolicies",
              "/api/v1/namespaces/default", "/api/v1/namespaces/default/configmaps/admission"]
    for path in paths:
        pool.request("GET", "https://cluster.example" + path + "?limit=100&continue=a%2Fb")
    assert len(calls) == len(paths)
    assert all(c[1]["redirect"] is False and c[1]["retries"] is False for c in calls)


def test_exact_configz_only():
    pool, calls = boundary()
    pool.request("GET", "https://cluster.example/api/v1/nodes/node.example/proxy/configz")
    with pytest.raises(ValueError):
        pool.request("GET", "https://cluster.example/api/v1/nodes/node/proxy/configz?other=value")
    assert len(calls) == 1


def test_metadata_negotiation_required():
    pool, calls = boundary()
    for path in ("/api/v1/secrets", "/api/v1/configmaps", "/api/v1/namespaces/default/secrets"):
        with pytest.raises(ValueError):
            pool.request("GET", "https://cluster.example" + path)
        pool.request("GET", "https://cluster.example" + path,
                     headers={"Accept": "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"})
    assert len(calls) == 3


def test_table_never_requests_objects():
    pool, calls = boundary()
    headers = {"Accept": "application/json;as=Table;g=meta.k8s.io;v=v1"}
    pool.request("GET", "https://cluster.example/api/v1/secrets?includeObject=None", headers=headers)
    for query in ("", "?includeObject=Object", "?includeObject=None&includeObject=Object"):
        with pytest.raises(ValueError):
            pool.request("GET", "https://cluster.example/api/v1/secrets" + query, headers=headers)
    assert len(calls) == 1


def test_origin_basepath_and_redirects():
    pool, calls = boundary("https://cluster.example:443/control")
    pool.request("GET", "https://cluster.example/control/api/v1/pods", redirect=True, retries=3)
    for url in ("https://foreign.example/control/api/v1/pods", "http://cluster.example/control/api/v1/pods",
                "https://cluster.example/api/v1/pods", "https://cluster.example/control-other/api/v1/pods",
                "https://user@cluster.example/control/api/v1/pods", "https://cluster.example/control/api/v1/pods#fragment"):
        with pytest.raises(ValueError):
            pool.request("GET", url)
    assert len(calls) == 1 and calls[0][1] == {"redirect": False, "retries": False}


def test_wrap_pins_actual_connection_not_original_dns():
    calls = []
    client = SimpleNamespace(configuration=SimpleNamespace(host="https://203.0.113.8/base"),
        rest_client=SimpleNamespace(pool_manager=SimpleNamespace(request=lambda *a, **kw: calls.append(a))),
        set_default_header=lambda *a: None)
    k8s._wrap_client(client, "https://cluster.example/base")
    client.rest_client.pool_manager.request("GET", "https://203.0.113.8/base/api/v1/pods")
    with pytest.raises(ValueError):
        client.rest_client.pool_manager.request("GET", "https://cluster.example/base/api/v1/pods")
    assert len(calls) == 1


def test_transport_cannot_append_fields_after_admission():
    pool, calls = boundary()
    with pytest.raises(ValueError):
        pool.request("GET", "https://cluster.example/api/v1/nodes/node/proxy/configz", fields={"other": "value"})
    assert not calls


def test_duplicate_metadata_accept_rejected():
    pool, calls = boundary()
    with pytest.raises(ValueError):
        pool.request("GET", "https://cluster.example/api/v1/secrets", headers={
            "Accept": "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1", "accept": "application/json"})
    assert not calls


def sdk_spy(handler):
    import json
    from io import BytesIO
    from kubernetes import client
    from urllib3.response import HTTPResponse
    config = client.Configuration()
    config.host = "https://cluster.example/control"
    api_client = client.ApiClient(config)
    calls = []
    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        value = handler(url, kwargs)
        return HTTPResponse(body=BytesIO(json.dumps(value).encode()), status=200,
                            headers={"Content-Type": "application/json"}, preload_content=False)
    api_client.rest_client.pool_manager = SimpleNamespace(request=request)
    return k8s._wrap_client(api_client), calls


def test_sdk_normal_collect_inventory_and_discovery():
    from urllib.parse import urlsplit
    def handler(url, kwargs):
        path = urlsplit(url).path.removeprefix("/control")
        if path == "/apis":
            return {"groups": [{"name": "cilium.io", "versions": [{"version": "v2"}]}]}
        if path == "/apis/cilium.io/v2":
            return {"resources": [{"name": "ciliumnetworkpolicies", "namespaced": True, "verbs": ["list"]}]}
        assert path in ("/api/v1/namespaces/team-a/pods", "/apis/cilium.io/v2/namespaces/team-a/ciliumnetworkpolicies")
        return {"items": [], "metadata": {"resourceVersion": "11"}}
    api, calls = sdk_spy(handler)
    snapshot = k8s.collect({"scopes": ["team-a"]}, ["pod", "cilium_networkpolicy"], api=api)
    assert all(c["status"] in ("collected", "empty") for c in snapshot["collections"])
    assert len(calls) == 4
    assert all(method == "GET" and kw["redirect"] is False and kw["retries"] is False for method, _, kw in calls)


def test_sdk_metadata_negotiation_and_configz_compatible():
    def handler(url, kwargs):
        if "configz" in url:
            return {"kubeletconfig": {"authentication": {"anonymous": {"enabled": False}}}}
        accept = kwargs["headers"]["Accept"]
        kind = "Table" if ";as=Table;" in accept else "PartialObjectMetadataList"
        return {"kind": kind, "apiVersion": "meta.k8s.io/v1", "metadata": {"resourceVersion": "11"}, "items": [], "rows": []}
    api, calls = sdk_spy(handler)
    for representation, params in (("PartialObjectMetadataList", {"limit": 10}), ("Table", {"includeObject": "None"})):
        value = k8s._metadata_get(api, "/api/v1/namespaces/team-a/secrets", params, representation)
        assert value["kind"] == representation
    assert api.get_json("/api/v1/nodes/node/proxy/configz")["kubeletconfig"]
    assert len(calls) == 3
