"""Contact Center view self-grants use one exact view and its collected policy."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
SOURCE = "user:operator@example.com"
VIEW = PROJECT + "/locations/us-central1/authorizedViewSets/support/authorizedViews/team-a"
WRITER = PROJECT + "/roles/viewPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-contactcenterinsights-authorizedviews-setiampolicy-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case(*, writer=True, prior=False, wrong_project=False, duplicate=False,
         view_policy="collected", detail="collected", viewer_permission=True,
         project_policy="collected", prior_view=False, malformed_view_policy=False):
    roles = [{"name": WRITER, "includedPermissions":
              ["contactcenterinsights.authorizedViews.setIamPolicy"] if writer else []},
             {"name": "roles/contactcenterinsights.authorizedViewer", "includedPermissions":
              ["contactcenterinsights.authorizedViews.get"] if viewer_permission else []}]
    bindings = [{"role": WRITER, "members": [SOURCE]}]
    if prior:
        bindings.append({"role": "roles/contactcenterinsights.authorizedViewer", "members": [SOURCE]})
    view = {"name": VIEW.replace("demo-project1", "other-project1") if wrong_project else VIEW,
            "conversationFilter": 'agent_id = "team-a"',
            "iamPolicy": {"bindings": "invalid" if malformed_view_policy else
                          ([{"role": "roles/contactcenterinsights.authorizedViewer", "members": [SOURCE]}]
                           if prior_view else [])},
            "_coverage": {"iamPolicy": {"status": view_policy},
                          "network_detail": {"status": detail}}}
    snapshot = {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", roles),
        envelope("iam_policy", [{"name": PROJECT, "bindings": bindings}], project_policy),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("contact_center_authorized_view", [view, deepcopy(view)] if duplicate else [view]),
    ]}
    return [(target, grant.confidence) for reach in
            Evaluator(GcpModel(snapshot), [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_exact_view_grant_is_conditional():
    result = case()
    assert len(result) == 1 and result[0][0].endswith(VIEW)
    assert result[0][1] == "conditional"
    assert case(writer=False) == []
    assert case(prior=True) == []
    assert case(prior_view=True) == []
    assert case(wrong_project=True) == []
    assert case(duplicate=True) == []


def test_missing_policy_role_or_view_detail_stays_unresolved():
    for variation in ({"view_policy": "access_denied"}, {"detail": "access_denied"},
                      {"viewer_permission": False}, {"project_policy": "access_denied"},
                      {"malformed_view_policy": True}):
        result = case(**variation)
        assert len(result) == 1 and result[0][1] == "unknown", variation


def test_native_view_collection_uses_nested_parent_and_policy_get():
    from peaso.collectors.gcp_network_catalog import PRIVATE_SERVICES, inventory_pages

    class Collector:
        def __init__(self):
            self.urls = []

        def pages(self, url, scope, *, key=None, single=False, params=None, transform=None):
            # Mirrors GCPCollector.pages, which projects each row before yielding it.
            for rows, receipt in self._pages(url, scope, key=key, single=single, params=params):
                yield ([transform(row) for row in rows] if transform else rows), receipt

        def _pages(self, url, scope, *, key=None, single=False, params=None):
            self.urls.append(url)
            if key == "authorizedViewSets":
                yield [{"name": VIEW.rsplit("/authorizedViews/", 1)[0]}], "sets"
            elif key == "authorizedViews":
                yield [{"name": VIEW}], "views"
            elif single:
                yield [{"name": VIEW, "conversationFilter": 'agent_id = "team-a"'}], "detail"
            else:
                raise AssertionError(url)

        def hydrate(self, item, field, url, scope, *, params=None):
            self.urls.append(url)
            assert params == {"options.requestedPolicyVersion": 3}
            return {**item, "iamPolicy": {"bindings": []},
                    "_coverage": {**item["_coverage"], "iamPolicy": {"status": "collected"}}}

    collector = Collector()
    plan = PRIVATE_SERVICES["contact_center_authorized_view"]
    rows = list(inventory_pages(collector, PROJECT, plan,
                               PROJECT + "/locations/us-central1",
                               "https://contactcenterinsights.googleapis.com/v1"))
    assert rows[-1][0][0]["name"] == VIEW
    assert rows[-1][0][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert collector.urls == [
        "https://contactcenterinsights.googleapis.com/v1/" +
        PROJECT + "/locations/us-central1/authorizedViewSets",
        "https://contactcenterinsights.googleapis.com/v1/" +
        VIEW.rsplit("/authorizedViews/", 1)[0] + "/authorizedViews",
        "https://contactcenterinsights.googleapis.com/v1/" + VIEW,
        "https://contactcenterinsights.googleapis.com/v1/" + VIEW + ":getIamPolicy",
    ]


def test_native_transport_preserves_policy_conditions_and_denied_reads():
    from peaso.collectors.gcp import GCPCollector, ReadError

    class Transport:
        def __init__(self, denied=False):
            self.denied = denied
            self.requests = []

        def request(self, method, url, **kwargs):
            self.requests.append((method, url, kwargs.get("params")))
            if url.endswith("/authorizedViewSets"):
                body = {"authorizedViewSets": [{"name": VIEW.rsplit("/authorizedViews/", 1)[0]}]}
            elif url.endswith("/authorizedViews"):
                body = {"authorizedViews": [{"name": VIEW}]}
            elif url.endswith(":getIamPolicy"):
                if self.denied:
                    raise ReadError("denied", "IAM_PERMISSION_DENIED")
                body = {"version": 3, "bindings": [{"role": "roles/contactcenterinsights.authorizedViewer",
                        "members": ["user:other@example.com"],
                        "condition": {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}}]}
            elif url.endswith("/team-a"):
                body = {"name": VIEW, "conversationFilter": 'agent_id = "team-a"'}
            else:
                raise AssertionError(url)
            return deepcopy(body), str(len(self.requests))

    options = {"inventories": ["contact_center_authorized_view"],
               "include_inherited": False, "concurrency": 1, "regions": ["us-central1"]}
    for denied in (False, True):
        transport = Transport(denied)
        snapshot = GCPCollector({"provider": "gcp", "scopes": [PROJECT],
                                 "options": options}, transport=transport).collect()
        collection = next(row for row in snapshot["collections"]
                          if row["type"] == "contact_center_authorized_view")
        view = collection["items"][0]
        policy = view["_coverage"]["iamPolicy"]
        assert policy["status"] == ("denied" if denied else "collected")
        if not denied:
            assert view["iamPolicy"]["bindings"][0]["condition"]["expression"].startswith("request.time")
        assert transport.requests[-1][2] == {"options.requestedPolicyVersion": 3}
