"""A Connector IAM self grant stays tied to a ready, exact connection."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
ACTOR = "user:operator@example.com"
RESOURCE = PROJECT + "/locations/us-central1/connections/orders"
WRITER = PROJECT + "/roles/connectionPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-connectors-connections-setiampolicy-connection-self-grant")


def envelope(kind, rows, *, status=None):
    return {"type": kind, "scope": PROJECT, "status": status or ("collected" if rows else "empty"),
            "items": rows}


def case(*, write=True, prior=False, state="ACTIVE", suspended=False,
         policy_status="collected", detail_status="collected", duplicate=False,
         wrong_project=False, invoker_permission=True, project_policy_status="collected"):
    roles = [
        {"name": WRITER, "includedPermissions":
         ["connectors.connections.setIamPolicy"] if write else []},
        {"name": "roles/connectors.invoker", "includedPermissions":
         ["connectors.connections.executeSqlQuery"] if invoker_permission else []},
    ]
    bindings = [{"role": WRITER, "members": [ACTOR]}]
    if prior:
        bindings.append({"role": "roles/connectors.invoker", "members": [ACTOR]})
    connection = {"name": RESOURCE.replace("demo-project1", "other-project1") if wrong_project else RESOURCE,
                  "status": {"state": state}, "suspended": suspended,
                  "iamPolicy": {"bindings": []},
                  "_coverage": {"iamPolicy": {"status": policy_status},
                                "network_detail": {"status": detail_status}}}
    snapshot = {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", roles),
        envelope("iam_policy", [{"name": PROJECT, "bindings": bindings}],
                 status=project_policy_status),
        envelope("iam_deny_policy", []),
        envelope("org_policy_effective", []),
        envelope("group", []),
        envelope("group_membership", []),
        envelope("integration_connection", [connection, deepcopy(connection)] if duplicate else [connection]),
    ]}
    return [(target, grant.confidence) for reach in
            Evaluator(GcpModel(snapshot), [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == ACTOR for target, grant in reach.targets.items()]


def test_exact_ready_connection_can_gain_query_permission():
    result = case()
    assert len(result) == 1
    assert result[0][0].endswith(RESOURCE)
    assert result[0][1] == "conditional"
    assert case(write=False) == []
    assert case(prior=True) == []
    assert case(duplicate=True) == []
    assert case(wrong_project=True) == []


def test_unready_or_incomplete_connection_stays_unresolved():
    for variant in ({"state": "INACTIVE"}, {"suspended": True},
                    {"policy_status": "access_denied"}, {"detail_status": "access_denied"},
                    {"invoker_permission": False}, {"project_policy_status": "access_denied"}):
        result = case(**variant)
        assert len(result) == 1 and result[0][1] == "unknown", variant


def test_native_collector_reads_exact_connection_and_iam_policy():
    from peaso.collectors.gcp_network_catalog import PRIVATE_SERVICES, inventory_pages

    class Collector:
        def __init__(self):
            self.requests = []

        def pages(self, url, scope, *, key=None, single=False, params=None, transform=None):
            # Mirrors GCPCollector.pages, which projects each row before yielding it.
            for rows, receipt in self._pages(url, scope, key=key, single=single, params=params):
                yield ([transform(row) for row in rows] if transform else rows), receipt

        def _pages(self, url, scope, *, key=None, single=False, params=None):
            self.requests.append((url, scope, key, single, params))
            if key == "connections":
                yield [{"name": RESOURCE}], "list-receipt"
            elif single:
                yield [{"name": RESOURCE, "status": {"state": "ACTIVE"}}], "get-receipt"
            else:
                raise AssertionError(url)

        def hydrate(self, item, field, url, scope, *, params=None):
            self.requests.append((url, scope, field, False, params))
            assert field == "iamPolicy"
            assert params == {"options.requestedPolicyVersion": 3}
            return {**item, "iamPolicy": {"bindings": []},
                    "_coverage": {**item["_coverage"], "iamPolicy": {"status": "collected"}}}

    collector = Collector()
    plan = PRIVATE_SERVICES["integration_connection"]
    rows = list(inventory_pages(collector, PROJECT, plan,
                               PROJECT + "/locations/us-central1",
                               "https://connectors.googleapis.com/v1"))
    assert len(rows) == 2
    assert rows[1][0][0]["_coverage"] == {"network_detail": {"status": "collected"},
                                           "iamPolicy": {"status": "collected"}}
    assert [request[0] for request in collector.requests] == [
        "https://connectors.googleapis.com/v1/" + PROJECT + "/locations/us-central1/connections",
        "https://connectors.googleapis.com/v1/" + RESOURCE,
        "https://connectors.googleapis.com/v1/" + RESOURCE + ":getIamPolicy",
    ]
