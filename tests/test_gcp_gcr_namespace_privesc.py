"""A gcr.io namespace edge needs one exact redirected repository and consumer."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


REGISTRY = "projects/p1"
CONSUMER = "projects/p2"
TARGET = "runtime@p2.iam.gserviceaccount.com"
REPOSITORY = REGISTRY + "/locations/us/repositories/gcr.io"
TECHNIQUE = "gcp-artifactregistry-gcrio-namespace-squat"


def snapshot(*, image="gcr.io/p1/app:latest", redirect="REDIRECTION_FROM_GCR_IO_ENABLED",
             settings_status="collected", repo_exists=False, create=True, upload=True,
             selected_locations=("us",)):
    def row(kind, scope, records, status="collected"):
        return {"type": kind, "scope": scope, "service": kind, "status": status,
                "items": records, "error": None}
    actions = []
    if create:
        actions.append("artifactregistry.repositories.create")
    if upload:
        actions.append("artifactregistry.repositories.uploadArtifacts")
    return {"schema_version": 1, "provider": "gcp", "scopes": [REGISTRY, CONSUMER],
            "metadata": {"artifactregistry_location_mode": "selected",
                         "artifactregistry_location_selection": list(selected_locations)},
            "collections": [
                row("project", REGISTRY, [{"projectId": "p1", "name": "projects/111"}]),
                row("project", CONSUMER, [{"projectId": "p2", "name": "projects/222"}]),
                row("iam_role", REGISTRY, [{"name": REGISTRY + "/roles/writer",
                                           "includedPermissions": actions}]),
                row("iam_policy", REGISTRY, [{"name": REGISTRY, "bindings": [
                    {"role": REGISTRY + "/roles/writer", "members": ["user:source@example.com"]}]}]),
                row("service_account", CONSUMER, [{"email": TARGET, "projectId": "p2",
                                                   "iamPolicy": {"bindings": []}}]),
                row("cloudrun_service", CONSUMER, [{"name": CONSUMER + "/locations/us-central1/services/app",
                    "template": {"serviceAccount": TARGET,
                                 "containers": [{"image": image}]}}]),
                row("artifact_repository", REGISTRY,
                    [{"name": REPOSITORY, "format": "DOCKER"}] if repo_exists else [],
                    status="collected" if repo_exists else "empty"),
                row("gcp_v4_workload_facts", REGISTRY, [{"name": REGISTRY, "scope": REGISTRY,
                    "artifact_registry": {"settings_status": settings_status,
                        "redirection_state": redirect}}]),
                row("iam_deny_policy", REGISTRY, [], "empty"),
            ]}


def outcome(snap):
    model = GcpModel(snap)
    source = model.principals["user:source@example.com"]
    target = model.sas["serviceAccount:" + TARGET]
    direct = model.selector("gcp_gcr_namespace_path", True, {target.id: target}, source)
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = [reach for reach in Evaluator(model, [entry]).run()
               if reach.source.id == source.id]
    return direct.get(target.id), reaches


def test_tagged_cross_project_consumer_has_conditional_path():
    verdict, reaches = outcome(snapshot())
    assert verdict[0] == "conditional"
    assert reaches


def test_european_legacy_host_uses_europe_repository_location():
    verdict, reaches = outcome(snapshot(image="eu.gcr.io/p1/app:stable",
                                        selected_locations=("europe",)))
    assert verdict[0] == "conditional"
    assert reaches


def test_existing_repository_or_disabled_redirection_has_no_squat_path():
    assert outcome(snapshot(repo_exists=True)) == (None, [])
    assert outcome(snapshot(redirect="REDIRECTION_FROM_GCR_IO_DISABLED")) == (None, [])


def test_digest_pinned_image_cannot_be_replaced_by_tag():
    assert outcome(snapshot(image="gcr.io/p1/app@sha256:" + "a" * 64)) == (None, [])


def test_other_registry_project_cannot_be_joined_to_source_grants():
    verdict, reaches = outcome(snapshot(image="gcr.io/p3/app:latest"))
    assert verdict[0] == "unknown"
    assert all(all(target_id.startswith("unresolved:") for target_id in reach.targets)
               for reach in reaches)


def test_create_and_upload_must_both_apply_to_the_exact_future_repository():
    assert outcome(snapshot(create=False)) == (None, [])
    assert outcome(snapshot(upload=False)) == (None, [])


def test_unreadable_settings_or_unlisted_location_stays_unknown():
    assert outcome(snapshot(settings_status="denied"))[0][0] == "unknown"
    assert outcome(snapshot(selected_locations=("europe",)))[0][0] == "unknown"


def test_org_policy_restricted_repository_location_stays_unknown():
    snap = snapshot()
    snap["metadata"]["regional_policy_skips"] = {"artifactregistry": {REGISTRY: ["us"]}}
    assert outcome(snap)[0][0] == "unknown"


def test_partial_redirection_stays_unknown():
    assert outcome(snapshot(redirect="REDIRECTION_FROM_GCR_IO_PARTIAL_AND_COPYING"))[0][0] == "unknown"


