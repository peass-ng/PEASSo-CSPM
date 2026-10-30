"""Cloud Source repository routes require an exact privileged push trigger."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from peaso.privesc.gcp_observed_impact import evidence_summary
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@example.com"
SA = "build@p1.iam.gserviceaccount.com"
ENTRIES = [entry for entry in privesc.catalog()["entries"] if entry["id"] in {
    "gcp-sourcerepos-update-build-trigger", "gcp-sourcerepos-setiampolicy"}]


def case(*, permission="source.repos.update", granted_repo="a", trigger_repo="a",
         approved=False, disabled=False, source_file=True, extra_right=True,
         source_has_extra=False, incomplete=False, file_filter=False):
    def binding(role, member):
        return {"role": role, "members": [member]}

    repos = []
    for name in ("a", "b"):
        repos.append({"name": f"{PROJECT}/repos/{name}",
                      "iamPolicy": {"bindings": [binding(PROJECT + "/roles/write", SOURCE)]
                                    if name == granted_repo else []},
                      "_coverage": {"iamPolicy": {"status": "collected"}}})
    trigger = {"resourceName": PROJECT + "/locations/global/triggers/t",
               "triggerTemplate": {"projectId": "p1", "repoName": trigger_repo, "branchName": "main"},
               "serviceAccount": PROJECT + "/serviceAccounts/" + SA,
               "approvalConfig": {"approvalRequired": approved}, "disabled": disabled}
    if source_file:
        trigger["filename"] = "cloudbuild.yaml"
    if file_filter:
        trigger["filter"] = "release/.*"
    collections = [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings":
            [binding(PROJECT + "/roles/source-extra", SOURCE)] if source_has_extra else []}]),
        ("iam_role", PROJECT, [
            {"name": PROJECT + "/roles/write", "includedPermissions": [permission]},
            {"name": PROJECT + "/roles/source-extra", "includedPermissions": ["secretmanager.versions.access"]},
            {"name": PROJECT + "/roles/build", "includedPermissions":
             ["secretmanager.versions.access"] if extra_right else []},
        ]),
        ("service_account", PROJECT, [{"email": SA, "projectId": "p1", "iamPolicy": {"bindings": []}}]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("source_repository", PROJECT, repos, "collected"),
        ("cloudbuild_trigger", PROJECT, [trigger], "partial" if incomplete else "collected"),
    ]
    if extra_right:
        collections[1][2][0]["bindings"].append(binding(PROJECT + "/roles/build", "serviceAccount:" + SA))
    model = GcpModel(snapshot("gcp", collections))
    return {reach.entry["entry"]["id"]: {tid: grant.confidence for tid, grant in reach.targets.items()}
            for reach in Evaluator(model, ENTRIES).run() if reach.source.id == SOURCE}


def test_push_and_selfgrant_join_exact_repository_to_build_service_account():
    push = case()["gcp-sourcerepos-update-build-trigger"]
    selfgrant = case(permission="source.repos.setIamPolicy")["gcp-sourcerepos-setiampolicy"]
    assert push == {"serviceAccount:" + SA: "conditional"}
    assert selfgrant == {"serviceAccount:" + SA: "conditional"}


def test_split_repository_and_non_privileged_target_do_not_report_escalation():
    for options in ({"granted_repo": "a", "trigger_repo": "b"},
                    {"extra_right": False}, {"source_has_extra": True}, {"disabled": True}):
        assert case(**options).get("gcp-sourcerepos-update-build-trigger", {}) == {}


def test_approval_filter_or_uncontrolled_build_source_stays_unresolved():
    for options in ({"approved": True}, {"source_file": False},
                    {"file_filter": True}, {"incomplete": True}):
        assert case(**options).get("gcp-sourcerepos-update-build-trigger", {}).get(
            "serviceAccount:" + SA) != "conditional"


def test_repository_evidence_names_recorded_setting_and_keeps_outcome_conditional():
    for ident in ("gcp-sourcerepos-update-build-trigger", "gcp-sourcerepos-setiampolicy"):
        entry = next(entry for entry in ENTRIES if entry["id"] == ident)
        finding = {"provider": "gcp", "check_id": ident, "status": "MANUAL", "evidence": {
            "technique": {"id": ident, "source": entry["source"]},
            "source": {"id": SOURCE, "label": SOURCE},
            "targets": [{"id": "serviceAccount:" + SA, "label": SA, "underlying_count": 1}],
            "target_count": 1, "confidence": "conditional", "conditions": [],
            "blockers_not_evaluated": [], "granting_statements": [{"effect": "Allow"}],
        }}
        lines = evidence_summary(finding).splitlines()
        assert len(lines) == 3
        assert "Cloud Source repository" in lines[0]
        assert "could" in " ".join(lines[1:])
