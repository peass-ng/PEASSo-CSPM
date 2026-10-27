"""Native workload predicates reviewed against pinned Kubernetes SQL recipes.

Resource templates select their actual PodSpec paths. Optional defaults are
interpreted only inside a readable, structurally valid PodSpec. These predicates
assess declarations, not admission enforcement or kernel/runtime behavior.
"""
from __future__ import annotations
import copy
import re
from decimal import Decimal

from . import register, result, unknown
from .facts import get, guard, Unavailable, list_of_objects, optional
from .fixtures import CASES, nest

KIND_PATHS = {"pod": "spec", "deployment": "spec.template.spec", "daemonset": "spec.template.spec",
    "statefulset": "spec.template.spec", "replicaset": "spec.template.spec", "replicationcontroller": "spec.template.spec",
    "job": "spec.template.spec", "cronjob": "spec.jobTemplate.spec.template.spec", "podtemplate": "template.spec"}
PREFIXES = {"replication_controller": "replicationcontroller", "pod_template": "podtemplate",
            **{kind: kind for kind in KIND_PATHS if kind not in ("replicationcontroller", "podtemplate")}}
IDS = []
REFERENCE_SPECS = {}
PORT_CASES = {}
CANONICAL = {("pod", "privileged"): "k8s.pod.no_privileged_containers",
    ("pod", "privilege_escalation"): "k8s.pod.no_privilege_escalation",
    ("pod", "readonly_root"): "k8s.pod.read_only_root"}
for _kind in ("deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob"):
    CANONICAL[(_kind, "privileged")] = f"k8s.{_kind}.no_privileged"
    CANONICAL[(_kind, "host_network")] = f"k8s.{_kind}.no_host_network"
DOCS = ["https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "https://kubernetes.io/docs/concepts/workloads/pods/"]


def pod_spec(item, kind, *, require_containers=True):
    guard(item)
    expected_kind = {"pod": "Pod", "deployment": "Deployment", "daemonset": "DaemonSet",
        "statefulset": "StatefulSet", "replicaset": "ReplicaSet", "replicationcontroller": "ReplicationController",
        "job": "Job", "cronjob": "CronJob", "podtemplate": "PodTemplate"}[kind]
    version = "apps/v1" if kind in ("deployment", "daemonset", "statefulset", "replicaset") else "batch/v1" if kind in ("job", "cronjob") else "v1"
    for field, expected in (("kind", expected_kind), ("apiVersion", version)):
        if field in item and get(item, field, str) != expected:
            raise Unavailable("workload type conflicts with selected native inventory")
    spec = get(item, KIND_PATHS[kind], dict)
    if not require_containers:
        return spec, []
    rows = list(list_of_objects(get(spec, "containers", list)))
    if not rows:
        raise Unavailable("PodSpec requires at least one regular container")
    for key in ("initContainers", "ephemeralContainers"):
        rows += list_of_objects(optional(spec, key, [], list))
    names = set()
    for row in rows:
        name = get(row, "name", str)
        if not name or len(name) > 63 or re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", name) is None or name in names:
            raise Unavailable("container name is malformed or ambiguous")
        names.add(name)
    return spec, rows


def flag(item, key, default=False):
    guard(item)
    if key in item or key in item.get("_coverage", {}):
        return get(item, key, bool)
    return default


def strings(item, key):
    guard(item)
    values = get(item, key, list) if key in item or key in item.get("_coverage", {}) else []
    if any(not isinstance(value, str) for value in values):
        raise Unavailable("malformed string list")
    return values


def quantity(value):
    if type(value) not in (str, int, float) or isinstance(value, bool):
        raise Unavailable("malformed Kubernetes quantity")
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([EPTGMK]i|[eE][+-]?[0-9]+|[numkMGTPE])?", str(value))
    if not match:
        raise Unavailable("malformed Kubernetes quantity")
    return Decimal(match[1])


def evaluate_predicate(item, kind, predicate):
    spec, rows = pod_spec(item, kind, require_containers=not (
        kind == "pod" and predicate in (
            "host_namespaces", "host_network", "pod_runtime_default_seccomp", "explicit_serviceaccount")))
    if predicate == "host_namespaces":
        observed, unavailable = {}, []
        for field in ("hostPID", "hostIPC"):
            try:
                observed[field] = flag(spec, field)
            except Unavailable:
                unavailable.append(field)
        if any(observed.values()):
            return result(True, **observed, unavailable_fields=unavailable)
        if unavailable:
            raise Unavailable("host namespace declaration unavailable: " + ", ".join(unavailable))
        return result(False, **observed)
    if predicate == "host_network":
        return result(flag(spec, "hostNetwork"), hostNetwork=flag(spec, "hostNetwork"))
    if predicate == "pod_runtime_default_seccomp":
        context = optional(spec, "securityContext", {}, dict)
        profile = optional(context, "seccompProfile", {}, dict)
        value = optional(profile, "type", None)
        if value not in (None, "RuntimeDefault", "Localhost", "Unconfined"):
            return unknown("unknown seccomp profile type")
        return result(value != "RuntimeDefault", declared_pod_profile=value,
            semantics="Explicit Pod-level declaration; per-container overrides remain separate")
    if predicate == "explicit_serviceaccount":
        value = optional(spec, "serviceAccountName", None)
        if value is not None and not isinstance(value, str):
            raise Unavailable("malformed service account name")
        return result(not bool(value), declared_service_account=value)
    violations = []
    uncertain_containers = []
    excluded_containers = []
    for container in rows:
        try:
            ephemeral = any(container is row for row in spec.get("ephemeralContainers", []))
            init = any(container is row for row in spec.get("initContainers", []))
            if predicate in ("readiness_probe", "liveness_probe", "cpu_limit", "cpu_request", "memory_limit", "memory_request") and ephemeral:
                excluded_containers.append(container["name"])
                continue
            if predicate in ("readiness_probe", "liveness_probe") and init:
                restart = optional(container, "restartPolicy", None)
                if restart not in (None, "Always"):
                    raise Unavailable("unrecognized init container restart policy")
                if restart is None:
                    excluded_containers.append(container["name"])
                    continue
            context = (optional(container, "securityContext", {}, dict)
                       if predicate in ("privileged", "privilege_escalation", "readonly_root", "declared_nonroot",
                                        "context_present", "container_runtime_default_seccomp", "no_added_capabilities",
                                        "drop_all", "drop_net_raw", "no_sys_admin") else None)
            if predicate == "privileged":
                failed = flag(context, "privileged")
            elif predicate == "privilege_escalation":
                failed = flag(context, "allowPrivilegeEscalation", True)
            elif predicate == "readonly_root":
                failed = not flag(context, "readOnlyRootFilesystem")
            elif predicate == "declared_nonroot":
                failed = not flag(context, "runAsNonRoot")
            elif predicate == "context_present":
                failed = "securityContext" not in container
            elif predicate == "container_runtime_default_seccomp":
                profile = optional(context, "seccompProfile", {}, dict)
                value = optional(profile, "type", None)
                if value not in (None, "RuntimeDefault", "Localhost", "Unconfined"):
                    raise Unavailable("unknown seccomp profile type")
                failed = value != "RuntimeDefault"
            elif predicate in ("no_added_capabilities", "drop_all", "drop_net_raw", "no_sys_admin"):
                caps = optional(context, "capabilities", {}, dict)
                added, dropped = strings(caps, "add"), strings(caps, "drop")
                failed = {"no_added_capabilities": bool(added),
                    "drop_all": not bool(set(dropped) & {"ALL", "all"}),
                    "drop_net_raw": not bool(set(dropped) & {"ALL", "all", "NET_RAW"}),
                    "no_sys_admin": bool(set(added) & {"CAP_SYS_ADMIN", "SYS_ADMIN"})}[predicate]
            elif predicate in ("cpu_limit", "cpu_request", "memory_limit", "memory_request"):
                group = "limits" if predicate.endswith("limit") else "requests"
                resource = "cpu" if predicate.startswith("cpu") else "memory"
                resources = optional(container, "resources", {}, dict)
                values = optional(resources, group, {}, dict)
                failed = resource not in values and resource not in values.get("_coverage", {})
                if not failed:
                    quantity(get(values, resource))
            elif predicate in ("readiness_probe", "liveness_probe"):
                key = "readinessProbe" if predicate == "readiness_probe" else "livenessProbe"
                if key in container or key in container.get("_coverage", {}):
                    probe = get(container, key, dict)
                    handlers = [field for field in ("exec", "httpGet", "tcpSocket", "grpc") if field in probe]
                    if len(handlers) != 1 or not get(probe, handlers[0], dict):
                        raise Unavailable("probe requires one native action declaration")
                failed = key not in container
            elif predicate == "no_host_ports":
                try:
                    ports = list_of_objects(optional(container, "ports", [], list))
                except Unavailable:
                    uncertain_containers.append(container["name"])
                    continue
                failed = unresolved = False
                for port in ports:
                    try:
                        guard(port)
                        if "hostPort" in port:
                            value = get(port, "hostPort", int)
                            if not 0 <= value <= 65535:
                                raise Unavailable("invalid host port")
                            # Reference forbids even an explicit hostPort=0 declaration.
                            failed = True
                        elif "hostPort" in port.get("_coverage", {}):
                            coverage = port["_coverage"]["hostPort"]
                            if not isinstance(coverage, dict) or coverage.get("status") != "empty":
                                raise Unavailable("host port declaration unavailable")
                    except Unavailable:
                        unresolved = True
                if unresolved and not failed:
                    uncertain_containers.append(container["name"])
                    continue
            elif predicate in ("pinned_image", "always_pull", "content_digest_or_always_pull"):
                image = get(container, "image", str)
                if not image:
                    failed = True
                else:
                    tail = image.rsplit("/", 1)[-1]
                    immutable = bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-fA-F]{64}", image))
                    if "@" in image and not immutable:
                        raise Unavailable("unrecognized or malformed content digest reference")
                    tagged = immutable or (":" in tail and tail.rsplit(":", 1)[1] not in ("", "latest"))
                    if predicate == "pinned_image":
                        failed = not tagged
                    else:
                        policy = optional(container, "imagePullPolicy", None)
                        if policy is not None and policy not in ("Always", "IfNotPresent", "Never"):
                            raise Unavailable("invalid image pull policy")
                        # Kubernetes defaults untagged/latest images to Always;
                        # pinned tags/digests default to IfNotPresent.
                        failed = (policy != "Always" if predicate == "always_pull" or policy is not None else tagged)
                        # A SHA256 digest is content-addressed: IfNotPresent can only run the
                        # pinned bytes, so it satisfies the intent of an Always pull for both
                        # variants. Never still trusts whatever the node cached under that name.
                        if predicate == "content_digest_or_always_pull" and immutable and policy in (None, "IfNotPresent", "Always"):
                            failed = False
            else:
                raise ValueError("unreviewed workload predicate")
            if failed:
                violations.append(container["name"])
        except Unavailable:
            uncertain_containers.append(container["name"])
    if uncertain_containers and not violations:
        raise Unavailable("container declaration unavailable: " + ", ".join(uncertain_containers))
    return result(bool(violations), containers_needing_review=violations,
        assessed_container_classes=["containers", "initContainers", "ephemeralContainers"],
        containers_excluded_by_native_applicability=excluded_containers,
        semantics="Declared native configuration; admission, inheritance and runtime state are not inferred")


SPECS = {
    "container_privilege_disabled": ("privileged", {"securityContext": {"privileged": False}}, {"securityContext": {"privileged": True}}),
    "container_privilege_escalation_disabled": ("privilege_escalation", {"securityContext": {"allowPrivilegeEscalation": False}}, {"securityContext": {"allowPrivilegeEscalation": True}}),
    "immutable_container_filesystem": ("readonly_root", {"securityContext": {"readOnlyRootFilesystem": True}}, {"securityContext": {"readOnlyRootFilesystem": False}}),
    "non_root_container": ("declared_nonroot", {"securityContext": {"runAsNonRoot": True}}, {"securityContext": {"runAsNonRoot": False}}),
    "container_security_context_exists": ("context_present", {"securityContext": {}}, {}),
    "container_with_added_capabilities": ("no_added_capabilities", {"securityContext": {"capabilities": {}}}, {"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}}),
    "container_capabilities_drop_all": ("drop_all", {"securityContext": {"capabilities": {"drop": ["ALL"]}}}, {}),
    "container_admission_capability_restricted": ("drop_net_raw", {"securityContext": {"capabilities": {"drop": ["NET_RAW"]}}}, {}),
    "container_sys_admin_capability_disabled": ("no_sys_admin", {"securityContext": {"capabilities": {"add": []}}}, {"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}}}),
    "cpu_limit": ("cpu_limit", {"resources": {"limits": {"cpu": "1"}}}, {}),
    "cpu_request": ("cpu_request", {"resources": {"requests": {"cpu": "100m"}}}, {}),
    "memory_limit": ("memory_limit", {"resources": {"limits": {"memory": "128Mi"}}}, {}),
    "memory_request": ("memory_request", {"resources": {"requests": {"memory": "64Mi"}}}, {}),
    "container_memory_limit": ("memory_limit", {"resources": {"limits": {"memory": "128Mi"}}}, {}),
    "container_memory_request": ("memory_request", {"resources": {"requests": {"memory": "64Mi"}}}, {}),
    "container_readiness_probe": ("readiness_probe", {"readinessProbe": {"tcpSocket": {"port": 8080}}}, {}),
    "container_liveness_probe": ("liveness_probe", {"livenessProbe": {"tcpSocket": {"port": 8080}}}, {}),
    "container_host_port_not_specified": ("no_host_ports", {}, {"ports": [{"containerPort": 8080, "hostPort": 8080}]}),
    "container_image_tag_specified": ("pinned_image", {"image": "registry.example/app:v2"}, {"image": "registry.example/app:latest"}),
    "container_image_pull_policy_always": ("always_pull", {"image": "app:v2", "imagePullPolicy": "Always"}, {"image": "app:v2", "imagePullPolicy": "IfNotPresent"}),
}


def register_workload(kind, predicate, good, bad, *, pod_field=False):
    def fixture(value):
        spec = {"containers": [{"name": "app", **({} if pod_field else copy.deepcopy(value))}]}
        if pod_field:
            spec.update(copy.deepcopy(value))
        return nest(KIND_PATHS[kind], spec)
    cases = {"pass": fixture(good), "fail": fixture(bad), "missing": {}, "malformed": None}
    if (kind, predicate) in CANONICAL:
        cid = CANONICAL[(kind, predicate)]
        if cid not in IDS:
            IDS.append(cid)
        PORT_CASES[cid] = cases
        return cid
    cid = f"k8s.ports.{kind}.{predicate}"
    if cid in IDS:
        return cid
    IDS.append(cid)
    title = kind + " " + predicate.replace("_", " ")
    if predicate == "always_pull":
        title = kind + " declares literal Always image pull policy (pinned source variant)"
    elif predicate == "content_digest_or_always_pull":
        title = kind + " uses SHA256 image digest with pull-on-miss or Always policy"
    @register(cid, "k8s", "hardening", kind, title, "medium", "CM-6",
        "Review the workload's explicit PodSpec declaration and operational requirements before changing its security or availability policy.")
    def evaluate(item, index):
        return evaluate_predicate(item, kind, predicate)
    CASES[cid] = cases
    PORT_CASES[cid] = cases
    return cid


def native_id(kind, predicate):
    return CANONICAL.get((kind, predicate), f"k8s.ports.{kind}.{predicate}")


for _prefix, _kind in PREFIXES.items():
    for _suffix, (_predicate, _good, _bad) in SPECS.items():
        REFERENCE_SPECS[_prefix + "_" + _suffix] = register_workload(_kind, _predicate, _good, _bad)
    for _suffix, _predicate, _good, _bad in (
        ("hostpid_hostipc_sharing_disabled", "host_namespaces", {"hostPID": False, "hostIPC": False}, {"hostPID": True}),
        ("host_network_access_disabled", "host_network", {"hostNetwork": False}, {"hostNetwork": True}),
        ("service_account_not_exist", "explicit_serviceaccount", {"serviceAccountName": "app"}, {"serviceAccountName": ""}),
    ):
        REFERENCE_SPECS[_prefix + "_" + _suffix] = register_workload(_kind, _predicate, _good, _bad, pod_field=True)
    _container_profile = _kind != "pod"
    _predicate = "container_runtime_default_seccomp" if _container_profile else "pod_runtime_default_seccomp"
    _good = {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}
    _bad = {"securityContext": {"seccompProfile": {"type": "Unconfined"}}}
    REFERENCE_SPECS[_prefix + "_default_seccomp_profile_enabled"] = register_workload(_kind, _predicate, _good, _bad, pod_field=not _container_profile)
    # Official immutable-image intent is a distinct policy from the pinned SQL's
    # explicit Always requirement. Do not move its source/framework associations.
    register_workload(_kind, "content_digest_or_always_pull",
        {"image": "app@sha256:" + "a" * 64, "imagePullPolicy": "IfNotPresent"},
        {"image": "app:v2", "imagePullPolicy": "IfNotPresent"})
