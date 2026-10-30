"""CA pools retain exact identities and their IAM policies."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


PROJECT = "projects/p1"
POOL = PROJECT + "/locations/us-central1/caPools/trusted"


@pytest.fixture
def module(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_privateca_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType(package.__name__ + ".gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, gcp.__name__, gcp)
    name = package.__name__ + ".gcp_privateca_pool"
    spec = importlib.util.spec_from_file_location(name, root / "gcp_privateca_pool.py")
    result = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, result)
    spec.loader.exec_module(result)
    return result, gcp.ReadError


class Collector:
    needed = {"ca_pool"}

    def __init__(self, names=None, policy=None):
        self.names = names if names is not None else [POOL]
        self.policy = policy if policy is not None else {"bindings": []}
        self.urls = []

    def _data_project_binding(self, scope, *, require_alias=False):
        assert scope == PROJECT and require_alias
        return {"project_id": "p1", "project_number": "1234"}

    def pages(self, url, scope, *, key=None, single=False, transform=None, params=None):
        self.urls.append(url)
        assert scope == PROJECT
        if key == "locations":
            yield [{"locationId": "us-central1"}], "locations"
        elif key == "caPools":
            yield [transform({"name": name}) for name in self.names], "pools"
        elif key == "certificateAuthorities":
            yield [], "authorities"
        elif single:
            yield [transform(self.policy)], "policy"
        else:
            raise AssertionError(url)


def test_reads_pool_and_policy_with_verified_project_alias(module):
    m, _ = module
    collector = Collector(["projects/1234/locations/us-central1/caPools/trusted"])
    fetch = m.scope_jobs(collector, PROJECT)[0][3]
    rows = [row for page, _ in fetch() for row in page]
    assert rows == [{"name": POOL, "certificateAuthorities": [], "iamPolicy": {"bindings": []},
                     "_coverage": {"iamPolicy": {"status": "collected"}}}]
    assert collector.urls[-1] == "https://privateca.googleapis.com/v1/" + POOL + ":getIamPolicy"


def test_rejects_duplicate_foreign_or_malformed_policy(module):
    m, error = module
    for collector in (Collector([POOL, POOL]),
                      Collector(["projects/other/locations/us-central1/caPools/trusted"]),
                      Collector(policy={"bindings": {}})):
        with pytest.raises(error):
            list(m.scope_jobs(collector, PROJECT)[0][3]())
