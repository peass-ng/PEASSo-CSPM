"""Native-shaped declaration/adverse matrix; no registry, cloud or credentials."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import socket
import subprocess

import pytest


# Load only the owned pure file: never import the production registry. Normal
# pytest collection still uses conftest unless --noconftest is explicitly set.
MODULE_PATH = (Path(__file__).resolve().parents[1] / "peaso/checks/"
               "gcp_workload_image_source_association_20261020.py")
SPEC = importlib.util.spec_from_file_location("gcp_workload_image_association", MODULE_PATH)
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)

PROJECT = "example-project"
ROOT = "projects/example-project/locations/europe-west1"
REPOSITORY = ROOT + "/repositories/workloads"
IMAGE_PATH = "europe-west1-docker.pkg.dev/example-project/workloads/team/api"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
IMAGE = IMAGE_PATH + "@" + DIGEST
UID = "00000000-0000-4000-8000-000000000001"
KINDS = ("Service", "Revision", "Job", "Execution", "Task")
NAMES = {
    "Service": ROOT + "/services/api",
    "Revision": ROOT + "/services/api/revisions/api-00001-xyz",
    "Job": ROOT + "/jobs/worker",
    "Execution": ROOT + "/jobs/worker/executions/worker-abcde",
    "Task": ROOT + "/jobs/worker/executions/worker-abcde/tasks/worker-abcde-task0",
}


@pytest.fixture(autouse=True)
def forbid_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("pure resolver attempted network or execution")
    for field in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, field, forbidden)
    for field in ("Popen", "run", "check_output"):
        monkeypatch.setattr(subprocess, field, forbidden)


def native(kind, image=IMAGE):
    rows = [{"name": "api", "image": image,
             "env": [{"name": "DO_NOT_READ", "value": "never-export-this-payload"},
                     {"name": "REF", "valueSource": {"secretKeyRef": {
                         "secret": "never-fetch-this-secret", "version": "latest"}}}],
             "command": ["do-not-execute"], "args": ["never-export-this-payload"]},
            {"name": "sidecar", "image": "docker.io/example/sidecar:mutable"}]
    body = {"name": NAMES[kind], "uid": UID, "generation": "2", "observedGeneration": "2",
            "reconciling": False, "etag": "native-etag-2",
            "createTime": "2026-10-20T08:00:00Z", "updateTime": "2026-10-20T09:00:00Z",
            "labels": {"team": "example"}, "annotations": {"private": "never-export-this-payload"}}
    if kind in ("Service", "Execution"):
        body["template"] = {"containers": rows}
    elif kind == "Job":
        body["template"] = {"template": {"containers": rows}}
    else:
        body["containers"] = rows
    if kind == "Revision":
        body["service"] = NAMES["Service"]
        body["conditions"] = [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}]
    if kind in ("Execution", "Task"):
        body["job"] = NAMES["Job"]
    if kind == "Task":
        body["execution"] = NAMES["Execution"]
        body["index"] = 0
        body["lastAttemptResult"] = {"exitCode": 0, "status": {}}
    if kind == "Service":
        body["latestReadyRevision"] = NAMES["Revision"]
        body["latestCreatedRevision"] = NAMES["Revision"]
        body["trafficStatuses"] = [{"revision": NAMES["Revision"], "percent": 100}]
    if kind == "Job":
        body["latestCreatedExecution"] = {"name": NAMES["Execution"]}
    return body


def containers(body, kind):
    if kind in ("Service", "Execution"):
        return body["template"]["containers"]
    if kind == "Job":
        return body["template"]["template"]["containers"]
    return body["containers"]


def selector(kind):
    return {"api_version": resolver.RUN_API, "kind": kind, "project_id": PROJECT,
            "resource_name": NAMES[kind], "resource_uid": UID, "container_name": "api",
            "digest": DIGEST, "repository": REPOSITORY, "immutable_reference": IMAGE}


def resolve(kind, body=None, selected=None):
    return resolver.resolve_image_source(selector(kind) if selected is None else selected,
                                         native(kind) if body is None else body, project_id=PROJECT)


def assert_unknown(result, reason=None):
    assert result["status"] == "UNKNOWN"
    assert result["selected_artifact_image_hint"] is None
    assert result["association_kind"] is None
    assert result["reason"]
    if reason:
        assert result["reason"] == reason
    assert_limits(result)


def assert_limits(result):
    assert result["runtime_association_status"] == "UNKNOWN"
    assert result["observed_runtime_digest"] is None
    assert result["deployed_bytes_proven"] is False
    assert result["complete"] is False
    assert result["content_status"] == "not_inspected"
    assert len(json.dumps(result)) < 4096
    assert "never-export" not in json.dumps(result)
    assert "never-fetch" not in json.dumps(result)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("reverse", (False, True))
@pytest.mark.parametrize("single", (False, True))
def test_exact_named_digest_declaration_is_a_bounded_hint(kind, reverse, single):
    body, selected = native(kind), selector(kind)
    rows = containers(body, kind)
    if single:
        rows.pop()
    if reverse:
        rows.reverse()
    before_body, before_selected = deepcopy(body), deepcopy(selected)
    result = resolve(kind, body, selected)
    assert result["status"] == "ASSOCIATED_DECLARATION"
    assert result["association_kind"] == ("desired_digest_declaration" if kind in ("Service", "Job")
                                           else "resource_snapshot_digest_declaration")
    hint = result["selected_artifact_image_hint"]
    assert hint["selected_artifact_images"] == [IMAGE]
    assert hint["repository"] == REPOSITORY and hint["digest"] == DIGEST
    assert hint["source"]["name"] == NAMES[kind] and hint["source"]["uid"] == UID
    assert hint["source"]["container_name"] == "api"
    pointer = hint["source"]["image_json_pointer"].strip("/").split("/")
    node = body
    for part in pointer:
        node = node[int(part)] if type(node) is list else node[part]
    assert node == IMAGE
    assert hint["repository_access"]["status"] == "not_evaluated"
    assert hint["repository_access"]["resource"] == REPOSITORY
    assert hint["repository_access"]["independent_of_workload_metadata_read"] is True
    assert hint["repository_access"]["required_pull_permission"] == "artifactregistry.repositories.downloadArtifacts"
    assert hint["requires_independent_native_repository_and_dockerimage_binding"] is True
    assert_limits(result)
    assert body == before_body and selected == before_selected
    # Output holds only new containers; mutating it cannot alter caller inputs.
    hint["selected_artifact_images"].append("changed")
    hint["source"]["name"] = "changed"
    assert body == before_body and selected == before_selected


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("image", [
    IMAGE_PATH + ":latest", IMAGE_PATH + ":release", IMAGE_PATH,
    IMAGE_PATH + "@" + OTHER_DIGEST,
    IMAGE.replace("/team/api@", "/team/other@"),
    IMAGE.replace("/workloads/", "/other/"),
    IMAGE.replace("example-project", "foreign-project"),
    IMAGE.replace("europe-west1-docker", "us-docker"),
    IMAGE.replace("docker.pkg.dev", "docker.pkg.dev.attacker.example"),
    "gcr.io/example-project/team/api@" + DIGEST,
    "registry.example/team/api@" + DIGEST,
    "docker-pullable://" + IMAGE, "https://" + IMAGE,
    IMAGE_PATH + ":release@" + DIGEST, IMAGE + "?url=attacker",
    IMAGE.replace("/team/", "/../"), IMAGE.replace("/team/", "/team//"),
    IMAGE.replace("/team/", "/%2e%2e/"), IMAGE + "\n", "x" * 513,
    IMAGE.replace("sha256:", "sha512:"), IMAGE.upper(), None, {}, [],
])
def test_mutable_foreign_crossregistry_malformed_or_wrong_digest_never_associates(kind, image):
    body = native(kind, image)
    before = deepcopy(body)
    assert_unknown(resolve(kind, body))
    assert body == before


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("change", [
    {"generation": "3"}, {"generation": 2}, {"observedGeneration": "1"},
    {"observedGeneration": None}, {"observedGeneration": 2}, {"reconciling": True},
    {"reconciling": None}, {"reconciling": 0}, {"etag": None}, {"uid": None},
    {"uid": "00000000-0000-4000-8000-000000000002"},
    {"name": ROOT + "/services/wrong"},
    {"deleteTime": "2026-10-20T09:00:00Z"}, {"expireTime": "2026-10-21T09:00:00Z"},
    {"containerStatuses": [{"name": "api", "imageDigest": IMAGE}]},
    {"imageDigest": IMAGE}, {"status": {"imageDigest": IMAGE}},
    {"partial": True}, {"nextPageToken": "next"}, {"items": []}, {"complete": True},
])
def test_stale_missing_foreign_status_and_synthetic_aggregation(kind, change):
    body = native(kind)
    body.update(deepcopy(change))
    before = deepcopy(body)
    assert_unknown(resolve(kind, body))
    assert body == before


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("case", ["duplicate", "unnamed", "wrong_name", "missing_selected",
                                 "missing_image", "synthetic_status", "too_many"])
def test_multicontainer_ambiguity_and_missing_selection(kind, case):
    body = native(kind)
    rows = containers(body, kind)
    if case == "duplicate":
        rows.append(deepcopy(rows[0]))
    elif case == "unnamed":
        rows[1].pop("name")
    elif case == "wrong_name":
        rows[0]["name"] = "not-api"
    elif case == "missing_selected":
        rows.pop(0)
    elif case == "missing_image":
        rows[0].pop("image")
    elif case == "synthetic_status":
        rows[0]["imageDigest"] = IMAGE
    else:
        rows.extend({"name": f"extra-{i}", "image": IMAGE} for i in range(resolver.MAX_CONTAINERS))
    assert_unknown(resolve(kind, body))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("field", ["api_version", "kind", "project_id", "resource_name", "resource_uid",
                                   "container_name", "digest", "repository", "immutable_reference"])
def test_selection_must_independently_pin_every_identity_component(kind, field):
    selected = selector(kind)
    selected[field] = "wrong"
    before = deepcopy(selected)
    assert_unknown(resolve(kind, selected=selected))
    assert selected == before
    selected.pop(field)
    assert_unknown(resolve(kind, selected=selected), "exact_closed_selector_required")


@pytest.mark.parametrize("kind", KINDS)
def test_missing_native_objects_lists_wrappers_and_optional_capture_fields(kind):
    for body in ({}, [], {"items": [native(kind)]}, {"resource": native(kind)}):
        assert_unknown(resolver.resolve_image_source(selector(kind), body, project_id=PROJECT))
    for field in ("name", "uid", "generation", "observedGeneration", "reconciling", "etag"):
        body = native(kind)
        body.pop(field)
        assert_unknown(resolve(kind, body))
    selected = selector(kind)
    selected["latest"] = True
    assert_unknown(resolve(kind, selected=selected), "exact_closed_selector_required")


@pytest.mark.parametrize("kind,field", [("Revision", "service"), ("Execution", "job"),
                                       ("Task", "job"), ("Task", "execution")])
def test_native_parent_link_cannot_point_elsewhere(kind, field):
    body = native(kind)
    body[field] = body[field].replace("example-project", "foreign-project")
    assert_unknown(resolve(kind, body))
    body.pop(field)
    assert_unknown(resolve(kind, body))


@pytest.mark.parametrize("kind", KINDS)
def test_two_pinned_containers_keep_independent_digests_and_repositories(kind):
    body = native(kind)
    other_image = IMAGE.replace("/workloads/", "/observability/").replace(DIGEST, OTHER_DIGEST)
    containers(body, kind)[1]["image"] = other_image
    selected = selector(kind)
    selected.update(container_name="sidecar", digest=OTHER_DIGEST,
                    repository=REPOSITORY.replace("/workloads", "/observability"),
                    immutable_reference=other_image)
    result = resolve(kind, body, selected)
    assert result["status"] == "ASSOCIATED_DECLARATION"
    hint = result["selected_artifact_image_hint"]
    assert hint["selected_artifact_images"] == [other_image]
    assert hint["source"]["container_name"] == "sidecar"
    assert hint["digest"] == OTHER_DIGEST
    selected["digest"] = DIGEST
    selected["immutable_reference"] = other_image.replace(OTHER_DIGEST, DIGEST)
    assert_unknown(resolve(kind, body, selected), "selected_container_image_identity_mismatch")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("rows", ([], {}, None, [None], [{"name": 1, "image": IMAGE}]))
def test_missing_or_malformed_native_container_lists(kind, rows):
    body = native(kind)
    if kind in ("Service", "Execution"):
        body["template"]["containers"] = rows
    elif kind == "Job":
        body["template"]["template"]["containers"] = rows
    else:
        body["containers"] = rows
    assert_unknown(resolve(kind, body))


@pytest.mark.parametrize("kind", ("Service", "Job", "Execution"))
def test_nested_templates_are_native_objects_and_cannot_supply_synthetic_status(kind):
    body = native(kind)
    body["template"] = None
    assert_unknown(resolve(kind, body))
    body = native(kind)
    body["template"]["containerStatuses"] = [{"name": "api", "imageDigest": IMAGE}]
    assert_unknown(resolve(kind, body), "synthetic_or_foreign_api_shape")


@pytest.mark.parametrize("image", [IMAGE, IMAGE_PATH + ":latest", "gcr.io/example-project/api@" + DIGEST, None])
def test_appengine_flexible_explicitly_unsupported_even_for_pinned_declaration(image):
    selected = selector("Service")
    selected.update(api_version=resolver.APPENGINE_API, kind="AppEngineVersion",
                    resource_name="apps/example-project/services/default/versions/v1")
    body = {"name": selected["resource_name"], "id": "v1", "env": "flex",
            "deployment": {"container": {"image": image}}, "servingStatus": "SERVING"}
    before = deepcopy(body)
    assert_unknown(resolve("Service", body, selected),
                   "appengine_flexible_runtime_digest_association_unsupported")
    assert body == before


@pytest.mark.parametrize("kind", KINDS)
def test_synthetic_status_cannot_resolve_mutable_tags(kind):
    body = native(kind, IMAGE_PATH + ":latest")
    body["containerStatuses"] = [{"name": "api", "imageDigest": DIGEST},
                                 {"name": "sidecar", "imageDigest": OTHER_DIGEST}]
    assert_unknown(resolve(kind, body), "synthetic_or_foreign_api_shape")


@pytest.mark.parametrize("kind", ("Service", "Job"))
def test_parent_latest_pointer_does_not_supply_child_runtime_or_digest(kind):
    body = native(kind, IMAGE_PATH + ":latest")
    # A ready/latest child pointer and registry digest selection do not prove
    # which digest this mutable declaration resolved to when deployed.
    assert_unknown(resolve(kind, body), "immutable_artifact_registry_reference_required")


