"""Cloud Workstations paths join an exact cluster, config, workstation, and SA."""


from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from peaso.collectors.gcp_workstations import scope_jobs
from tests.test_peaso_privesc_audit_fixes import snapshot


PROJECT = "projects/p1"
SA = "builder@p1.iam.gserviceaccount.com"
ACTOR = "user:dev@example.com"
CLUSTER = PROJECT + "/locations/us-central1/workstationClusters/cluster"
CONFIG = CLUSTER + "/workstationConfigs/config"
WORKSTATION = CONFIG + "/workstations/dev"


def _snapshot(perms=(), *, act_as=False, cluster=True, config=True, workstation=True,
              scoped=False, state="STATE_RUNNING", workstation_name=WORKSTATION):
    role = {"name": PROJECT + "/roles/actor", "includedPermissions": list(perms)}
    config_item = {"name": CONFIG, "host": {"gceInstance": {
        "serviceAccount": SA, "serviceAccountScopes": (["https://www.googleapis.com/auth/cloud-platform"]
                                                if scoped else [])}},
        "iamPolicy": {"bindings": []}, "_coverage": {"iamPolicy": {"status": "collected"}}}
    workstation_item = {"name": workstation_name, "state": state,
        "iamPolicy": {"bindings": []}, "_coverage": {"iamPolicy": {"status": "collected"}}}
    return snapshot("gcp", [
        ("project", PROJECT, [{"name": "projects/123", "projectId": "p1"}], "collected"),
        ("service_account", PROJECT, [{"name": f"{PROJECT}/serviceAccounts/{SA}",
            "email": SA, "projectId": "p1", "iamPolicy": {"bindings": (
                [{"role": "roles/iam.serviceAccountUser", "members": [ACTOR]}] if act_as else [])}}], "collected"),
        ("iam_role", PROJECT, [role], "collected"),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": role["name"], "members": [ACTOR]}]}], "collected"),
        ("workstations_cluster", PROJECT, ([{"name": CLUSTER}] if cluster else []),
         "collected" if cluster else "empty"),
        ("workstations_config", PROJECT, ([config_item] if config else []),
         "collected" if config else "empty"),
        ("workstations_workstation", PROJECT, ([workstation_item] if workstation else []),
         "collected" if workstation else "empty"),
    ])


def _reached(ident, perms, **options):
    entry = next(item for item in privesc.catalog()["entries"] if item["id"] == ident)
    model = GcpModel(_snapshot(perms, **options))
    return {target: grant.confidence for reach in Evaluator(model, [entry]).run()
            if reach.source.id == ACTOR for target, grant in reach.targets.items()
            if not target.startswith("unresolved:")}


def test_create_config_needs_cluster_create_rights_and_actas():
    ident = "gcp-workstations-config-create-actas"
    perms = ["workstations.workstationConfigs.create", "workstations.workstations.create"]
    target = "serviceAccount:" + SA
    assert _reached(ident, perms, act_as=True).get(target) == "conditional"
    assert target not in _reached(ident, perms, act_as=False)
    assert target not in _reached(ident, perms[:1], act_as=True)
    assert target not in _reached(ident, perms, act_as=True, cluster=False)
    assert _reached(ident, perms + ["workstations.workstationClusters.create"],
                    act_as=True, cluster=False).get(target) == "conditional"


def test_update_config_requires_existing_pinned_config_and_actas():
    ident = "gcp-workstations-config-update-code"
    perms = ["workstations.workstationConfigs.update"]
    target = "serviceAccount:" + SA
    assert _reached(ident, perms, act_as=True).get(target) == "conditional"
    assert target not in _reached(ident, perms, act_as=False)
    assert target not in _reached(ident, perms, act_as=True, config=False)


def test_existing_workstation_use_follows_state_and_exact_config():
    ident = "gcp-workstations-use-existing-workstation"
    target = "serviceAccount:" + SA
    assert _reached(ident, ["workstations.workstations.use"]).get(target) == "conditional"
    assert target not in _reached(ident, ["workstations.workstations.use"], state="STATE_STOPPED")
    assert _reached(ident, ["workstations.workstations.use", "workstations.workstations.start"],
                    state="STATE_STOPPED").get(target) == "conditional"
    assert target not in _reached(ident, ["workstations.workstations.use"], scoped=True)
    assert _reached(ident, ["workstations.workstations.use"], scoped=True, act_as=True).get(target) == "conditional"


def test_config_policy_self_grant_and_create_from_config():
    target = "serviceAccount:" + SA
    use = "gcp-workstations-use-existing-workstation"
    create = "gcp-workstations-create-from-existing-config"
    assert _reached(use, ["workstations.workstationConfigs.setIamPolicy"]).get(target) == "conditional"
    assert _reached(create, ["workstations.workstations.create"]).get(target) == "conditional"
    assert target not in _reached(create, ["workstations.workstations.create"], scoped=True)
    assert _reached(create, ["workstations.workstations.create"], scoped=True,
                    act_as=True).get(target) == "conditional"
    assert target not in _reached(create, ["workstations.workstations.create"], config=False)


def test_read_only_workstations_inventory_keeps_exact_parent_names():
    class Collector:
        needed = {"workstations_cluster", "workstations_config", "workstations_workstation"}

        def pages(self, url, scope, *, key, response_validator):
            assert scope == PROJECT
            rows = {
                "/locations": [{"name": PROJECT + "/locations/us-central1"}],
                "/workstationClusters": [{"name": CLUSTER}],
                "/workstationConfigs": [{"name": CONFIG, "host": {"gceInstance": {"serviceAccount": SA}}}],
                "/workstations": [{"name": WORKSTATION, "state": "STATE_RUNNING"}],
            }
            yield rows["/" + url.rsplit("/", 1)[-1]], url

        def hydrate(self, item, field, url, scope, *, params=None):
            assert url.endswith(item["name"] + ":getIamPolicy")
            assert params == {"options.requestedPolicyVersion": 3}
            return {**item, field: {"bindings": []}, "_coverage": {field: {"status": "collected"}}}

        def parallel(self, function, items):
            return [function(item) for item in items]

    outputs = {kind: [item for page, _ in factory() for item in page]
               for kind, _, _, factory in scope_jobs(Collector(), PROJECT)}
    assert outputs["workstations_cluster"][0]["name"] == CLUSTER
    assert outputs["workstations_config"][0]["name"] == CONFIG
    assert outputs["workstations_workstation"][0]["name"] == WORKSTATION


