"""Graph $batch first-page prefetch keeps Azure directory collections identical."""
import re
import json, threading, time
from urllib.parse import urlsplit, parse_qs
from peaso.collectors import azure
from peaso.collectors.azure import AzureTransport, AzureReadError, GRAPH, _validate_readonly_post

class Throttled(Exception):
    status_code = 429
    headers = {"Retry-After": "0"}

class FakeGraph(AzureTransport):
    def __init__(self, n=200, latency=0.05, seed=0):
        self.n, self.latency, self.lock = n, latency, threading.Lock()
        self.tenant = "tenant-a"; self.verified_tenant = None
        self.round_trips = 0; self.batch_posts = 0; self.sub_requests = 0; self.inflight = 0; self.peak = 0
        self.throttle_once = set()
        ids = lambda p: [f"{p}{i:04d}" for i in range(n)]
        self.apps, self.sps, self.groups, self.units = ids("app"), ids("sp"), ids("grp"), ids("au")
        # Deterministic per-object behaviour: some denied, some paginated, some throttled once.
        self.denied = {x for i, x in enumerate(self.apps + self.sps + self.groups) if i % 17 == 3}
        self.paged = {x for i, x in enumerate(self.groups + self.units) if i % 11 == 5}
        self.throttle = {x for i, x in enumerate(self.sps + self.groups) if i % 13 == 7}

    def close(self):
        pass

    def single(self, url):
        parts = urlsplit(url); path = parts.path.removeprefix("/v1.0").removeprefix("/beta")
        seg = path.strip("/").split("/")
        if path in ("/applications", "/servicePrincipals", "/groups", "/directory/administrativeUnits"):
            rows = {"/applications": self.apps, "/servicePrincipals": self.sps, "/groups": self.groups,
                    "/directory/administrativeUnits": self.units}[path]
            return {"value": [{"id": x, "appRoles": [{"id": "r1", "value": "Read", "isEnabled": True}]} if path == "/servicePrincipals" else {"id": x} for x in rows]}
        obj = seg[-2]
        if obj in self.denied:
            raise AzureReadError("Forbidden", 403)
        with self.lock:
            if obj in self.throttle and (obj, seg[-1]) not in self.throttle_once:
                self.throttle_once.add((obj, seg[-1]))
                raise Throttled()
        token = parse_qs(parts.query).get("$skiptoken", [None])[0]
        kind = seg[-1]
        if kind == "owners":
            return {"value": [{"id": "owner-" + obj}]}
        if kind == "members":
            if obj in self.paged and token is None:
                return {"value": [{"id": "m1-" + obj}], "@odata.nextLink": GRAPH + parts.path + "?$select=id&$skiptoken=2"}
            return {"value": [{"id": ("m2-" if token else "m-") + obj}]}
        if kind == "federatedIdentityCredentials":
            return {"value": [{"id": "fic-" + obj, "name": "n", "issuer": "https://issuer", "subject": "s", "audiences": ["a"]}]}
        if kind == "appRoleAssignments":
            return {"value": [{"id": "ara-" + obj, "principalId": obj, "resourceId": self.sps[0], "appRoleId": "r1"}]}
        raise AssertionError("unreviewed " + url)

    def request(self, url, *, body=None, audience=azure.ARM, capture_subject=False, max_response_bytes=None):
        if body is not None:
            _validate_readonly_post(url, audience, body)
        with self.lock:
            self.round_trips += 1; self.inflight += 1; self.peak = max(self.peak, self.inflight)
        try:
            time.sleep(self.latency)
            if audience != GRAPH:
                if body is not None:
                    return {"data": []}
                return {"value": []}
            if url in (GRAPH + "/v1.0/$batch", GRAPH + "/beta/$batch"):
                with self.lock:
                    self.batch_posts += 1; self.sub_requests += len(body["requests"])
                out = []
                for row in body["requests"]:
                    try:
                        out.append({"id": row["id"], "status": 200, "headers": {"Content-Type": "application/json"},
                                    "body": json.loads(json.dumps(self.single(GRAPH + ("/beta" if url.endswith("/beta/$batch") else "/v1.0") + row["url"])))})
                    except Throttled:
                        out.append({"id": row["id"], "status": 429, "headers": {"Retry-After": "0"}, "body": {"error": {"code": "TooManyRequests"}}})
                    except AzureReadError:
                        out.append({"id": row["id"], "status": 403, "body": {"error": {"code": "Authorization_RequestDenied"}}})
                return {"responses": list(reversed(out))}
            return json.loads(json.dumps(self.single(url)))
        finally:
            with self.lock:
                self.inflight -= 1


import pytest
from peaso.collectors import azure_graph_batch_exposure as azure_graph_batch

WANTED = ["directory_owner", "directory_administrative_unit_member", "directory_federated_credential",
          "directory_app_role_assignment", "directory_membership"]


def _collect(api, *, batch=True, options=None, monkeypatch=None):
    if not batch:
        original = azure_graph_batch.first_pages
        monkeypatch.setattr(azure_graph_batch, "first_pages",
                            lambda *a, enabled, **k: original(*a, enabled=False, **k))
    snapshot = azure.collect({"scopes": ["sub"], "auth": {"tenant_id": "tenant-a"}, "options": options or {}},
                             WANTED, transport=api)
    if not batch:
        monkeypatch.undo()
    return sorted(re.sub(r'"(credential|customer)_context_id": "[0-9a-z:-]+"', "", json.dumps(c, sort_keys=True))
                  for c in snapshot["collections"])


def test_batched_directory_reads_match_individual_reads_with_fewer_round_trips(monkeypatch):
    direct_api, batch_api = FakeGraph(n=45, latency=0), FakeGraph(n=45, latency=0)
    direct = _collect(direct_api, batch=False, monkeypatch=monkeypatch)
    batched = _collect(batch_api)
    assert batched == direct
    # Denied, throttled-once and paginated objects are all represented.
    assert any('"status": "denied"' in row for row in direct)
    assert any("m2-grp" in row for row in direct)
    assert batch_api.batch_posts and batch_api.round_trips * 3 < direct_api.round_trips
    assert batch_api.peak <= 12


@pytest.mark.parametrize("options", [{"max_calls": 100000}, {"max_resources": 100000},
                                      {"max_pages": 100000}, {"max_scopes": 100000}])
def test_explicit_budget_keeps_individual_reads(options):
    api = FakeGraph(n=5, latency=0)
    _collect(api, options=options)
    assert api.batch_posts == 0


@pytest.mark.parametrize("body", [
    {"requests": [{"id": "0", "method": "POST", "url": "/groups/g1/members?$select=id"}]},
    {"requests": [{"id": "0", "method": "GET", "url": "/groups/g1/members"}]},
    {"requests": [{"id": "0", "method": "GET", "url": "/users/u1/memberOf?$select=id"}]},
    {"requests": [{"id": "0", "method": "GET", "url": "/groups/g1/members?$select=id", "headers": {"x": "y"}}]},
    {"requests": [{"id": "0", "method": "GET", "url": "/groups/../members?$select=id"}]},
    {"requests": [{"id": "0", "method": "GET", "url": "/groups/g1/members?$select=id"}] * 2},
    {"requests": [{"id": str(i), "method": "GET", "url": "/groups/g1/members?$select=id"} for i in range(21)]},
    {"requests": []}, {"requests": [], "extra": 1},
])
def test_only_reviewed_directory_gets_may_be_batched(body):
    with pytest.raises(AzureReadError):
        _validate_readonly_post(GRAPH + "/v1.0/$batch", GRAPH, body)


def test_reviewed_batch_versions_restrict_beta_to_group_members_and_app_credentials():
    body = {"requests": [{"id": "0", "method": "GET", "url": "/groups/g1/members?$select=id"},
                         {"id": "1", "method": "GET", "url": "/servicePrincipals/s-1/appRoleAssignments"}]}
    _validate_readonly_post(GRAPH + "/v1.0/$batch", GRAPH, body)
    beta_body = {"requests": [body["requests"][0]]}
    _validate_readonly_post(GRAPH + "/beta/$batch", GRAPH, beta_body)
    beta_fic = {"requests": [{"id": "0", "method": "GET", "url":
        "/applications/app1/federatedIdentityCredentials?$select=id,name,issuer,subject,audiences,claimsMatchingExpression"}]}
    _validate_readonly_post(GRAPH + "/beta/$batch", GRAPH, beta_fic)
    for url, audience in ((GRAPH + "/beta/$batch", GRAPH), (GRAPH + "/v1.0/$batch?x=1", GRAPH),
                          (GRAPH + "/v1.0/$batch", azure.ARM)):
        with pytest.raises(AzureReadError):
            _validate_readonly_post(url, audience, body)


class _Reader:
    workers, deadline = 4, None

    def check_cancelled(self):
        pass


def _url(n):
    return GRAPH + f"/v1.0/groups/g{n}/members?$select=id"


def test_beta_group_members_share_one_read_only_batch():
    calls = []
    class Transport:
        def request(self, url, *, body=None, audience=None):
            _validate_readonly_post(url, audience, body)
            calls.append((url, body))
            return {"responses": [{"id": row["id"], "status": 200,
                                   "body": {"value": [{"id": row["url"]}]}}
                                  for row in body["requests"]]}
    urls = [GRAPH + f"/beta/groups/g{n}/members?$select=id" for n in range(2)]
    with azure_graph_batch.FirstPages(_Reader(), Transport(), lambda url, **k: None, urls) as request:
        assert request(urls[0], audience=GRAPH)["value"][0]["id"] == "/groups/g0/members?$select=id"
        assert request(urls[1], audience=GRAPH)["value"][0]["id"] == "/groups/g1/members?$select=id"
    assert len(calls) == 1 and calls[0][0] == GRAPH + "/beta/$batch"


def test_throttled_sub_responses_are_retried_in_a_later_batch(monkeypatch):
    monkeypatch.setattr(azure_graph_batch.time, "sleep", lambda seconds: None)
    posts = []

    class Transport:
        def request(self, url, *, body=None, audience=None):
            posts.append([row["url"] for row in body["requests"]])
            return {"responses": [{"id": row["id"], "status": 429 if len(posts) == 1 and row["id"] == "1" else 200,
                                   "headers": {"Retry-After": "1"}, "body": {"value": [{"id": row["url"]}]}}
                                  for row in body["requests"]]}
    fallback = []
    with azure_graph_batch.FirstPages(_Reader(), Transport(), lambda url, **k: fallback.append(url), [_url(0), _url(1)]) as request:
        assert request(_url(1), audience=GRAPH) == {"value": [{"id": "/groups/g1/members?$select=id"}]}
        assert request(_url(0), audience=GRAPH) == {"value": [{"id": "/groups/g0/members?$select=id"}]}
        # A repeated read shares the successful first response without refetching.
        assert request(_url(0), audience=GRAPH) == {"value": [{"id": "/groups/g0/members?$select=id"}]}
    assert posts == [["/groups/g0/members?$select=id", "/groups/g1/members?$select=id"], ["/groups/g1/members?$select=id"]]
    assert fallback == []


@pytest.mark.parametrize("response", [None, {"responses": "x"}, {"responses": [{"id": "0", "status": 403, "body": {}}]},
                                      {"responses": [{"id": "0", "status": 200, "body": "text"}]},
                                      {"responses": [{"id": "0", "status": 200, "body": {"value": []}},
                                                     {"id": "0", "status": 200, "body": {"value": []}}]},
                                      RuntimeError("boom")])
def test_failed_or_unusable_batches_fall_back_to_individual_reads(response):
    class Transport:
        def request(self, url, *, body=None, audience=None):
            if isinstance(response, Exception):
                raise response
            return response
    calls = []
    with azure_graph_batch.FirstPages(_Reader(), Transport(), lambda url, **k: calls.append(url) or "native", [_url(0)]) as request:
        assert request(_url(0), audience=GRAPH) == "native"
        assert request(GRAPH + "/v1.0/groups", audience=GRAPH) == "native"
    assert calls == [_url(0), GRAPH + "/v1.0/groups"]


def test_lookahead_bounds_prefetched_chunks():
    class Transport:
        def request(self, url, *, body=None, audience=None):
            return {"responses": [{"id": row["id"], "status": 200, "body": {"value": []}} for row in body["requests"]]}
    urls = [_url(n) for n in range(20 * 30)]
    prefetch = azure_graph_batch.FirstPages(_Reader(), Transport(), lambda url, **k: None, urls)
    try:
        assert prefetch.submitted == _Reader.workers
        prefetch.request(urls[20 * 10], audience=GRAPH)
        assert prefetch.submitted == 10 + _Reader.workers + 1
    finally:
        prefetch.close()
