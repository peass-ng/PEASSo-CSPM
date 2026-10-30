"""IAP policy collection follows exact Compute VM identities and preserves failures."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace


def collection_pages(collector, scope):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_iap_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType("isolated_iap_collector.gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    names = ("isolated_iap_collector", "isolated_iap_collector.gcp",
             "isolated_iap_collector.gcp_iap_tunnel_policies")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        sys.modules[names[0]] = package
        sys.modules[names[1]] = gcp
        spec = importlib.util.spec_from_file_location(names[2], root / "gcp_iap_tunnel_policies.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[names[2]] = module
        spec.loader.exec_module(module)
        yield from module.collection_pages(collector, scope)
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


PROJECT = "projects/demo-project1"
INSTANCE = {"name": "login1", "selfLink": "https://www.googleapis.com/compute/v1/" +
            PROJECT + "/zones/us-central1-a/instances/login1"}


def test_collects_project_zone_and_instance_iap_policies():
    requests = []
    def hydrate(row, field, url, scope, **kwargs):
        requests.append((row["name"], url, kwargs))
        return {**row, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected",
                                             "source_requests": ["receipt"]}}}
    listed = []
    def pages(url, scope, **kwargs):
        # 16bb81e0 also lists tunnel destination groups; none exist here.
        listed.append((url, scope, kwargs))
        yield [], "groups-receipt"
    collector = SimpleNamespace(collections={('instance', PROJECT): {
        "coverage_status": "collected", "items": [INSTANCE]}}, hydrate=hydrate, pages=pages)
    rows = [item for page, _ in collection_pages(collector, PROJECT) for item in page]
    assert [row["name"] for row in rows] == [
        PROJECT + "/iap_tunnel", PROJECT + "/iap_tunnel/zones/us-central1-a",
        PROJECT + "/iap_tunnel/zones/us-central1-a/instances/login1"]
    assert all(url == "https://iap.googleapis.com/v1/" + name + ":getIamPolicy"
               and options == {"method": "POST", "body": {"options": {
                   "requestedPolicyVersion": 3}}} for name, url, options in requests)
    assert listed == [("https://iap.googleapis.com/v1/" + PROJECT + "/iap_tunnel/locations/-/destGroups",
                       PROJECT, {"key": "tunnelDestGroups"})]
