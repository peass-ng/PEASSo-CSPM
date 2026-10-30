"""Membership policy self-grants stay bound to an exact registered member."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
MEMBER = PROJECT + "/locations/global/memberships/team-a"
SOURCE = "user:operator@example.com"
WRITER = PROJECT + "/roles/memberPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-gkehub-memberships-setiampolicy-membership-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case(*, writer=True, prior=False, member_prior=False, member_policy="collected",
         state="READY", wrong_project=False, role_known=True, condition=None,
         malformed_member_policy=False, duplicate=False, editor_prior=False):
    roles = [{"name": WRITER, "includedPermissions": [
        "gkehub.memberships.setIamPolicy", "gkehub.memberships.getIamPolicy"] if writer else []}]
    if not role_known:
        roles.append({"name": "roles/gkehub.gatewayReader", "includedPermissions": []})
    bindings = [{"role": WRITER, "members": [SOURCE]}]
    if prior:
        bindings.append({"role": "roles/gkehub.gatewayReader", "members": [SOURCE]})
    if editor_prior:
        bindings.append({"role": "roles/editor", "members": [SOURCE]})
    if condition:
        bindings[0]["condition"] = {"expression": condition}
    member = {"name": MEMBER.replace("demo-project1", "other-project1") if wrong_project else MEMBER,
              "state": {"code": state},
              "iamPolicy": {"bindings": "invalid" if malformed_member_policy else
                            ([{"role": "roles/gkehub.gatewayReader", "members": [SOURCE]}]
                             if member_prior else [])},
              "_coverage": {"iamPolicy": {"status": member_policy}}}
    snapshot = {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", roles),
        envelope("iam_policy", [{"name": PROJECT, "bindings": bindings}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("fleet_membership", [member, dict(member)] if duplicate else [member]),
    ]}
    return [(target, grant.confidence) for reach in
            Evaluator(GcpModel(snapshot), [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_exact_ready_member_self_grant_is_conditional():
    result = case()
    assert len(result) == 1 and result[0][0].endswith(MEMBER)
    assert result[0][1] == "conditional"
    assert case(writer=False) == []
    assert case(prior=True) == []
    assert case(member_prior=True) == []
    assert case(wrong_project=True) == []
    assert case(duplicate=True) == []
    assert case(state="DELETING") == []


def test_incomplete_policy_or_member_state_remains_unknown():
    for variation in ({"member_policy": "denied"}, {"state": "UPDATING"},
                      {"state": ""},
                      {"role_known": False}, {"malformed_member_policy": True},
                      {"editor_prior": True}):
        result = case(**variation)
        assert len(result) == 1 and result[0][1] == "unknown", variation


def test_iam_resource_condition_uses_the_exact_member():
    assert case(condition="resource.name == '" + MEMBER + "'")[0][1] == "conditional"
    assert case(condition="resource.name == '" + PROJECT +
                "/locations/global/memberships/team-b'") == []


def test_native_member_hydration_requests_its_iam_policy():
    from test_gcp_config_delivery_location import catalog
    module = catalog()

    class Collector:
        def __init__(self):
            self.urls = []

        def pages(self, url, scope, *, key=None, single=False, params=None, transform=None):
            # Like GCPCollector.pages, apply the optional per-item projection.
            self.urls.append(url)
            apply = transform or (lambda item: item)
            if key == "resources":
                yield [apply({"name": MEMBER})], "list"
            elif single:
                yield [apply({"name": MEMBER, "state": {"code": "READY"}})], "detail"
            else:
                raise AssertionError(url)

        def hydrate(self, item, field, url, scope, *, params=None):
            self.urls.append(url)
            assert params == {"options.requestedPolicyVersion": 3}
            return {**item, "iamPolicy": {"bindings": []},
                    "_coverage": {**item["_coverage"], "iamPolicy": {"status": "collected"}}}

    collector = Collector()
    plan = module.PRIVATE_SERVICES["fleet_membership"]
    rows = list(module.inventory_pages(collector, PROJECT, plan,
                               PROJECT + "/locations/global", "https://gkehub.googleapis.com/v1"))
    assert rows[-1][0][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert collector.urls[-1] == "https://gkehub.googleapis.com/v1/" + MEMBER + ":getIamPolicy"
