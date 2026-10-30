"""Native API-shape association cases; no cluster, registry, auth or detectors."""
from copy import deepcopy
import builtins
from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

# This unregistered pure helper has no dependency on the global control registry.
# Loading the exact owned file keeps unit cases independent of concurrent receipt
# changes in other providers. Normal pytest conftest admission still runs unless
# the caller explicitly supplies --noconftest for isolated validation.
_SPEC = importlib.util.spec_from_file_location("k8s_image_source_association_20261020",
    Path(__file__).resolve().parents[1] / "peaso/checks/k8s_image_source_association_20261020.py")
resolver = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = resolver
_SPEC.loader.exec_module(resolver)


DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
REPOSITORY = "123456789012.dkr.ecr.eu-west-1.amazonaws.com/team/api"
IMAGE = REPOSITORY + ":release"
IMMUTABLE = REPOSITORY + "@" + DIGEST
GROUPS = {
    "regular": ("containers", "containerStatuses"),
    "init": ("initContainers", "initContainerStatuses"),
    "ephemeral": ("ephemeralContainers", "ephemeralContainerStatuses"),
}


@pytest.fixture(autouse=True)
def forbid_network_auth_exec(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("pure association must not perform I/O or execute")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


def metadata(name, uid):
    return {"namespace": "team-a", "name": name, "uid": uid, "resourceVersion": "1098",
            "creationTimestamp": "2026-10-20T08:00:00Z", "labels": {"app": "api"},
            "annotations": {"some/unused": "do-not-export"}}


def native_pod(typ="regular", image=IMAGE, image_id=IMMUTABLE, state="running"):
    declaration = {"name": "api", "image": image, "imagePullPolicy": "Always",
                   "env": [{"name": "DO_NOT_READ", "value": "never-return-this"}],
                   "command": ["unused"], "args": ["unused"]}
    status = {"name": "api", "image": image, "imageID": image_id,
              "containerID": "containerd://instance-123", "restartCount": 2, "ready": True,
              "state": {"running": {"startedAt": "2026-10-20T09:00:00Z"}},
              "lastState": {"terminated": {"containerID": "containerd://old-instance",
                  "exitCode": 1, "reason": "unused", "message": "never-return-this"}}}
    if state == "terminated":
        status["state"] = {"terminated": {"exitCode": 0, "startedAt": "2026-10-20T09:00:00Z",
            "finishedAt": "2026-10-20T09:01:00Z", "containerID": status["containerID"]}}
    if typ == "ephemeral":
        declaration["targetContainerName"] = "main"
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": metadata("api-pod", "pod-uid-1"),
           "spec": {"containers": [], "serviceAccountName": "unused",
               "nodeName": "worker-1", "restartPolicy": "Always", "dnsPolicy": "ClusterFirst",
               "imagePullSecrets": [{"name": "never-fetch"}],
               "volumes": [{"name": "private", "secret": {"secretName": "never-fetch"}}]},
           "status": {"phase": "Running", "podIP": "192.0.2.1", GROUPS[typ][1]: [status]}}
    pod["spec"][GROUPS[typ][0]] = [declaration]
    if typ != "regular":
        pod["spec"]["containers"] = [{"name": "main", "image": "registry.example/main:v1"}]
    return pod


def selection(resource, typ="regular"):
    return {"cluster_id": "cluster-1", "api_version": resource["apiVersion"], "kind": resource["kind"],
            **{k: resource["metadata"][k] for k in ("namespace", "name", "uid")},
            "container_type": typ, "container_name": "api"}


def run(resource, typ="regular", **kwargs):
    return resolver.resolve_image_source(selection(resource, typ), resource, cluster_id="cluster-1", **kwargs)


def controller(kind, image=IMAGE):
    version = "v1" if kind in ("PodTemplate", "ReplicationController") else (
        "batch/v1" if kind in ("Job", "CronJob") else "apps/v1")
    resource = {"apiVersion": version, "kind": kind,
                "metadata": metadata(kind.lower(), kind.lower() + "-uid")}
    spec = {"containers": [{"name": "api", "image": image}],
            "restartPolicy": "Never" if kind in ("Job", "CronJob") else "Always"}
    if kind == "CronJob":
        resource["spec"] = {"schedule": "0 * * * *", "jobTemplate": {"spec": {"template": {"spec": spec}}}}
    elif kind == "PodTemplate":
        resource["template"] = {"metadata": {"labels": {"app": "api"}}, "spec": spec}
    else:
        resource["spec"] = {"selector": {"matchLabels": {"app": "api"}}, "template": {
            "metadata": {"labels": {"app": "api"}}, "spec": spec}}
    if kind == "ReplicationController":
        resource["spec"]["selector"] = {"app": "api"}
    if kind == "StatefulSet":
        resource["spec"]["serviceName"] = "api-headless"
    if kind == "Job":
        resource["spec"]["manualSelector"] = True
    return resource


def owned_by(child, parent):
    child["metadata"]["ownerReferences"] = [{"apiVersion": parent["apiVersion"], "kind": parent["kind"],
        "name": parent["metadata"]["name"], "uid": parent["metadata"]["uid"], "controller": True,
        "blockOwnerDeletion": True}]


def controller_inputs(kind="Deployment", image=IMAGE):
    root, pod = controller(kind, image), native_pod(image=image)
    intermediate = {"Deployment": "ReplicaSet", "CronJob": "Job"}.get(kind)
    chain = [controller(intermediate, image)] if intermediate else []
    nodes = [root, *chain, pod]
    for parent, child in zip(nodes, nodes[1:]):
        owned_by(child, parent)
    return root, {"pod": pod, "pod_selection": {k: pod["metadata"][k] for k in ("namespace", "name", "uid")},
                  "owner_chain": chain}


def run_controller(kind="Deployment", image=IMAGE):
    root, kwargs = controller_inputs(kind, image)
    return run(root, **kwargs)


def assert_unresolved(result, reason=None):
    assert result["status"] in ("unknown", "invalid", "mismatch", "declaration_only")
    assert result["immutable_reference"] is None
    assert result["effective_deployment_proven"] is False
    assert result["image_bytes_scanned"] is False
    assert result["registry_access"] == "not_checked"
    if reason:
        assert result["reason"] == reason


@pytest.mark.parametrize("typ", list(GROUPS))
@pytest.mark.parametrize("prefix", ["", "docker-pullable://"])
@pytest.mark.parametrize("state", ["running", "terminated"])
def test_native_pod_container_types_status_bound_positive(typ, prefix, state):
    pod = native_pod(typ, image_id=prefix + IMMUTABLE, state=state)
    before = deepcopy(pod)
    result = run(pod, typ)
    assert result["status"] == "associated"
    assert result["immutable_reference"] == IMMUTABLE
    assert result["claim"] == "pod_status_reported_digest"
    assert result["pod"]["uid"] == "pod-uid-1"
    assert result["pod"]["resource_version"] == "1098"
    assert result["container_instance"]["state"] == state
    assert result["container_instance"]["container_id"] == "containerd://instance-123"
    assert result["container_type"] == typ
    assert result["status_path"] == "/status/" + GROUPS[typ][1] + "/0"
    assert result["image_bytes_scanned"] is False
    assert result["effective_deployment_proven"] is False
    assert result["registry_access"] == "not_checked"
    assert pod == before
    assert "never-" not in json.dumps(result)
    assert "do-not-export" not in json.dumps(result)
    assert "lastState" not in json.dumps(result)


@pytest.mark.parametrize("host", ["123456789012.dkr.ecr.eu-west-1.amazonaws.com",
    "us-central1-docker.pkg.dev", "customer.azurecr.io", "registry.example:5000"])
def test_registry_neutral_identity_does_not_grant_access(host):
    repository = host + "/project/repository/api"
    result = run(native_pod(image=repository + ":release", image_id=repository + "@" + DIGEST))
    assert result["status"] == "associated"
    assert result["registry_access"] == "not_checked"


@pytest.mark.parametrize("kind", ["Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job",
                                   "CronJob", "ReplicationController"])
def test_selected_controller_native_owner_chain_one_pod(kind):
    result = run_controller(kind)
    assert result["status"] == "associated"
    assert result["immutable_reference"] == IMMUTABLE
    assert result["owner_chain"][0]["kind"] == kind
    assert result["owner_chain"][-1]["kind"] == "Pod"
    assert result["effective_deployment_proven"] is False


@pytest.mark.parametrize("kind", ["Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job",
                                   "CronJob", "ReplicationController", "PodTemplate"])
@pytest.mark.parametrize("immutable", [True, False])
def test_controller_declaration_is_never_pod_status_or_tag_deployment_proof(kind, immutable):
    result = run(controller(kind, IMMUTABLE if immutable else IMAGE))
    assert result["status"] == ("declaration_only" if immutable else "unknown")
    assert result["claim"] == "desired_image_declaration"
    assert result["desired_immutable_reference"] == (IMMUTABLE if immutable else None)
    assert_unresolved(result)


@pytest.mark.parametrize("desired", [IMMUTABLE, REPOSITORY + ":ignored@" + DIGEST])
def test_desired_digest_and_tag_plus_digest_keep_desired_actual_distinct(desired):
    pod = native_pod(image=desired)
    pod["status"]["containerStatuses"][0]["image"] = IMMUTABLE
    result = run(pod)
    assert result["status"] == "associated"
    assert result["desired_image"]["digest"] == DIGEST
    assert result["status_image_id"] == IMMUTABLE


@pytest.mark.parametrize("image", ["busybox", "busybox:latest", "docker.io/busybox:latest",
                                   "index.docker.io/library/busybox:latest"])
def test_only_documented_docker_shorthand_and_legacy_alias(image):
    result = run(native_pod(image=image, image_id="docker.io/library/busybox@" + DIGEST))
    assert result["status"] == "associated"
    assert result["immutable_reference"] == "docker.io/library/busybox@" + DIGEST


@pytest.mark.parametrize("image_id", [DIGEST, "containerd://" + DIGEST, "docker://" + DIGEST,
    "containerd://" + IMMUTABLE, IMAGE, "busybox@" + DIGEST, "", None])
def test_non_pullable_runtime_ids_and_tags_cannot_select_manifest(image_id):
    assert_unresolved(run(native_pod(image_id=image_id)))


@pytest.mark.parametrize("value", ["https://registry.example/team/api:tag", "registry.example/a?x=1",
    "registry.example/a#x", "registry.example/a%2fb", "registry.example/../api:tag", "a\\b",
    "registry.example/UPPER:tag", "registry.example/a:", "registry.example/a:bad+tag",
    "registry.example/a@" + DIGEST + "@" + DIGEST, "user:pass@registry.example/a:tag",
    "bad..host/a:v1", "registry.example:70000/a:v1", "-bad.example/a:v1", "a b", "x" * 1025,
    4, None, [], {}])
def test_malformed_selected_image_is_conservative(value):
    assert_unresolved(run(native_pod(image=value)))


@pytest.mark.parametrize("digest", ["sha256:" + "A" * 64, "sha256:" + "a" * 63,
                                    "sha512:" + "a" * 128, "sha999:xyz"])
def test_unsupported_digest_subset_is_unknown(digest):
    assert_unresolved(run(native_pod(image_id=REPOSITORY + "@" + digest)),
                      "unsupported_or_malformed_digest")


def test_runtime_can_resolve_status_image_to_digest():
    pod = native_pod()
    pod["status"]["containerStatuses"][0]["image"] = IMMUTABLE
    assert run(pod)["status"] == "associated"


@pytest.mark.parametrize("field", ["image", "imageID"])
def test_registry_alias_and_foreign_repository_are_never_guessed(field):
    pod = native_pod()
    pod["status"]["containerStatuses"][0][field] = "mirror.example/other/api@" + DIGEST
    assert_unresolved(run(pod), "registry_alias_or_repository_mismatch")


def test_status_tag_disagreement_is_not_effective_deployment():
    pod = native_pod()
    pod["status"]["containerStatuses"][0]["image"] = REPOSITORY + ":old"
    assert_unresolved(run(pod), "desired_status_tag_disagreement")


@pytest.mark.parametrize("desired_mismatch", [True, False])
def test_index_platform_digest_relation_needs_manifest_bytes(desired_mismatch):
    pod = native_pod(image=REPOSITORY + "@" + OTHER_DIGEST if desired_mismatch else IMAGE)
    if not desired_mismatch:
        pod["status"]["containerStatuses"][0]["image"] = REPOSITORY + "@" + OTHER_DIGEST
    result = run(pod)
    assert_unresolved(result, "desired_status_digest_relation_unverified" if desired_mismatch
                      else "status_image_digest_relation_unverified")
    assert result["status_image_id"] == IMMUTABLE


@pytest.mark.parametrize("mutation", ["missing", "empty", "waiting", "two_states", "bad_restart",
    "bool_restart", "bad_ready", "bad_instance", "no_image_id", "no_timestamp", "naive_timestamp",
    "invalid_timestamp", "deleting", "last_state_only"])
def test_incomplete_or_incoherent_native_status_is_unresolved(mutation):
    pod = native_pod()
    row = pod["status"]["containerStatuses"][0]
    if mutation == "missing": pod.pop("status")
    elif mutation == "empty": pod["status"]["containerStatuses"] = []
    elif mutation == "waiting": row["state"] = {"waiting": {"reason": "ImagePullBackOff"}}
    elif mutation == "two_states": row["state"]["terminated"] = {"exitCode": 0}
    elif mutation == "bad_restart": row["restartCount"] = -1
    elif mutation == "bool_restart": row["restartCount"] = True
    elif mutation == "bad_ready": row["ready"] = "true"
    elif mutation == "bad_instance": row["containerID"] = "not-an-instance"
    elif mutation == "no_image_id": row.pop("imageID")
    elif mutation == "no_timestamp": row["state"]["running"] = {}
    elif mutation == "naive_timestamp": row["state"]["running"]["startedAt"] = "2026-10-20T09:00:00"
    elif mutation == "invalid_timestamp": row["state"]["running"]["startedAt"] = "tomorrow"
    elif mutation == "deleting": pod["metadata"]["deletionTimestamp"] = "2026-10-20T10:00:00Z"
    elif mutation == "last_state_only": row.pop("state")
    assert_unresolved(run(pod))


@pytest.mark.parametrize("mutation", ["duplicate_declaration", "cross_type_declaration", "duplicate_status",
    "cross_type_status", "wrong_name", "too_many_declarations", "too_many_statuses",
    "invalid_status_list", "null_status", "null_declarations"])
def test_ambiguous_malformed_and_bounded_shapes(mutation):
    pod = native_pod()
    declaration = pod["spec"]["containers"][0]
    row = pod["status"]["containerStatuses"][0]
    if mutation == "duplicate_declaration": pod["spec"]["containers"].append(deepcopy(declaration))
    elif mutation == "cross_type_declaration": pod["spec"]["initContainers"] = [deepcopy(declaration)]
    elif mutation == "duplicate_status": pod["status"]["containerStatuses"].append(deepcopy(row))
    elif mutation == "cross_type_status":
        pod["status"]["initContainerStatuses"] = [row]
        pod["status"]["containerStatuses"] = []
    elif mutation == "wrong_name": row["name"] = "other"
    elif mutation == "too_many_declarations": pod["spec"]["containers"] *= 129
    elif mutation == "too_many_statuses": pod["status"]["containerStatuses"] *= 129
    elif mutation == "invalid_status_list": pod["status"]["containerStatuses"] = {"api": row}
    elif mutation == "null_status": pod["status"] = None
    elif mutation == "null_declarations": pod["spec"]["initContainers"] = None
    assert_unresolved(run(pod))


@pytest.mark.parametrize("field,value", [("uid", "recreated-pod-uid"), ("namespace", "other"),
    ("name", "other"), ("api_version", "apps/v1"), ("kind", "Deployment"), ("cluster_id", "other"),
    ("container_type", "sidecar"), ("container_type", []), ("container_name", "*"), ("extra", True)])
def test_exact_selection_rejects_cross_resource_and_cross_cluster(field, value):
    pod = native_pod()
    target = selection(pod)
    target[field] = value
    assert_unresolved(resolver.resolve_image_source(target, pod, cluster_id="cluster-1"))


@pytest.mark.parametrize("field", ["uid", "resourceVersion", "namespace", "name"])
def test_native_identity_required_before_interpretation(field):
    pod = native_pod()
    target = selection(pod)
    pod["metadata"].pop(field)
    assert_unresolved(resolver.resolve_image_source(target, pod, cluster_id="cluster-1"))


@pytest.mark.parametrize("mutation", ["no_owner", "label_only", "wrong_uid", "wrong_version", "non_controller",
    "two_owners", "wrong_pod_uid", "cross_namespace", "old_rollout", "missing_intermediate",
    "wrong_intermediate", "unbounded_chain", "too_many_refs"])
def test_controller_association_rejects_inferred_or_stale_links(mutation):
    root, kwargs = controller_inputs()
    pod, chain = kwargs["pod"], kwargs["owner_chain"]
    ref = pod["metadata"]["ownerReferences"][0]
    if mutation in ("no_owner", "label_only"): pod["metadata"].pop("ownerReferences")
    elif mutation == "wrong_uid": ref["uid"] = "recreated-replicaset"
    elif mutation == "wrong_version": ref["apiVersion"] = "apps/v1beta1"
    elif mutation == "non_controller": ref["controller"] = False
    elif mutation == "two_owners": pod["metadata"]["ownerReferences"].append(deepcopy(ref))
    elif mutation == "wrong_pod_uid": kwargs["pod_selection"]["uid"] = "recreated-pod"
    elif mutation == "cross_namespace":
        pod["metadata"]["namespace"] = "other"
        kwargs["pod_selection"]["namespace"] = "other"
    elif mutation == "old_rollout": chain[0]["spec"]["template"]["spec"]["containers"][0]["image"] = REPOSITORY + ":old"
    elif mutation == "missing_intermediate": kwargs["owner_chain"] = []
    elif mutation == "wrong_intermediate": kwargs["owner_chain"] = [controller("Job")]
    elif mutation == "unbounded_chain": kwargs["owner_chain"] *= 2
    elif mutation == "too_many_refs": pod["metadata"]["ownerReferences"] *= 9
    assert_unresolved(run(root, **kwargs))


def test_selected_pod_must_be_explicit_for_controller():
    root, kwargs = controller_inputs()
    kwargs.pop("pod_selection")
    assert_unresolved(run(root, **kwargs), "explicit_pod_selection_required")


def test_podtemplate_declaration_cannot_claim_owner_link():
    root, kwargs = controller_inputs("PodTemplate")
    assert_unresolved(run(root, **kwargs), "podtemplate_has_no_native_controller_ownership")


def test_selected_ephemeral_container_requires_actual_pod():
    root = controller("Deployment")
    root["spec"]["template"]["spec"]["ephemeralContainers"] = [{"name": "debug", "image": IMAGE}]
    assert_unresolved(run(root), "ephemeral_containers_require_selected_pod")


def test_matching_names_and_tags_never_substitute_for_status_digest():
    pod = native_pod(image_id=IMAGE)
    pod["spec"]["containers"][0]["imagePullPolicy"] = "Always"
    assert_unresolved(run(pod), "image_id_not_qualified_immutable_reference")


def test_init_sidecar_uses_init_status_not_main_status():
    pod = native_pod("init")
    pod["spec"]["initContainers"][0]["restartPolicy"] = "Always"
    assert run(pod, "init")["status"] == "associated"


def test_native_status_order_does_not_choose_container_by_position():
    pod = native_pod()
    pod["spec"]["containers"].insert(0, {"name": "other", "image": "registry.example/other:v1"})
    other = deepcopy(pod["status"]["containerStatuses"][0])
    other.update(name="other", image="registry.example/other:v1", imageID="registry.example/other@" + OTHER_DIGEST)
    pod["status"]["containerStatuses"].append(other)
    assert run(pod)["immutable_reference"] == IMMUTABLE


def test_terminated_instance_mismatch_and_invalid_time_order():
    pod = native_pod(state="terminated")
    row = pod["status"]["containerStatuses"][0]
    row["state"]["terminated"]["containerID"] = "containerd://other-instance"
    assert_unresolved(run(pod), "terminated_container_instance_mismatch")
    row["state"]["terminated"]["containerID"] = row["containerID"]
    row["state"]["terminated"]["finishedAt"] = "2026-10-19T09:00:00Z"
    assert_unresolved(run(pod), "container_state_timestamp_order_invalid")


def test_no_secret_or_unused_content_traversal_and_no_file_access(monkeypatch):
    class NeverRead(dict):
        def get(self, *args): raise AssertionError("unrelated content traversed")
        def items(self): raise AssertionError("unrelated content traversed")
        def __iter__(self): raise AssertionError("unrelated content traversed")
    pod = native_pod()
    pod["spec"]["imagePullSecrets"] = NeverRead()
    pod["spec"]["volumes"] = NeverRead()
    pod["spec"]["containers"][0]["env"] = NeverRead()
    pod["metadata"]["annotations"] = NeverRead()
    def no_files(*args, **kwargs): raise AssertionError("file access forbidden")
    monkeypatch.setattr(builtins, "open", no_files)
    result = run(pod)
    assert result["status"] == "associated"
    assert "NeverRead" not in json.dumps(result)


def test_native_json_roundtrip_and_result_are_deterministic():
    pod = json.loads(json.dumps(native_pod()))
    first = run(pod)
    assert first == run(pod)
    assert first == json.loads(json.dumps(first))
    parsed = resolver.parse_image_reference("registry.example/a:tag@" + DIGEST)
    assert asdict(parsed)["tag"] == "tag"
    assert parsed.immutable_reference == "registry.example/a@" + DIGEST


@pytest.mark.parametrize("field", ["items", "continue", "nextLink", "remainingItemCount",
    "partial", "_partial", "hasMore", "continuationToken", "_coverage"])
@pytest.mark.parametrize("location", ["root", "metadata"])
def test_partial_and_list_markers_do_not_produce_complete_association(field, location):
    pod = native_pod()
    (pod if location == "root" else pod["metadata"])[field] = True
    assert_unresolved(run(pod), "partial_or_list_object_not_supported")


@pytest.mark.parametrize("kind,version", [("PartialObjectMetadata", "meta.k8s.io/v1"),
    ("PodList", "v1"), ("Secret", "v1"), ("Deployment", "apps/v1beta1")])
def test_metadata_projection_secret_and_unsupported_version_rejected(kind, version):
    pod = native_pod()
    target = selection(pod)
    pod.update(kind=kind, apiVersion=version)
    assert_unresolved(resolver.resolve_image_source(target, pod, cluster_id="cluster-1"),
                      "unsupported_native_kind_or_api_version")


def test_multiple_container_types_and_total_bound():
    pod = native_pod()
    pod["spec"]["initContainers"] = [{"name": "init-" + str(i), "image": IMAGE} for i in range(128)]
    assert_unresolved(run(pod), "invalid_or_unbounded_container_declarations")


def test_intermediate_and_pod_both_match_current_desired_declaration():
    root, kwargs = controller_inputs()
    kwargs["pod"]["spec"]["containers"][0]["image"] = REPOSITORY + ":old"
    assert_unresolved(run(root, **kwargs), "controller_pod_declaration_mismatch")


def test_controller_native_init_container_status_and_digest():
    root, kwargs = controller_inputs("DaemonSet")
    root["spec"]["template"]["spec"]["initContainers"] = [{"name": "api", "image": IMAGE}]
    root["spec"]["template"]["spec"]["containers"] = [{"name": "main", "image": IMAGE}]
    kwargs["pod"] = native_pod("init", state="terminated")
    owned_by(kwargs["pod"], root)
    assert run(root, "init", **kwargs)["status"] == "associated"
