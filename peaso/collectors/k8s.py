"""Read-only Kubernetes facts through the official authenticated API client."""
from __future__ import annotations

import copy
import base64
import hashlib
import ipaddress
import os
import posixpath
import re
import socket
import tempfile
import threading
from datetime import datetime, timezone
from itertools import count
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from peaso.snapshot import make_snapshot
from .azure import _Reader, AzureReadError, _trusted_scopes, _safe_error
from . import k8s_network_catalog
from . import k8s_annotation_indicators_20261020 as annotation_indicators
from . import k8s_sanitize_keys
from . import k8s_network_extensions


class K8sReadError(AzureReadError):
    """Kubernetes read failures retain the shared scheduler's safe error shape."""


class K8sReader(_Reader):
    def __init__(self, options):
        runtime = dict(options)
        self.k8s_progress_callback = runtime.pop("_progress_callback", None)
        if self.k8s_progress_callback is None:
            from peaso.progress import current_callback
            self.k8s_progress_callback = current_callback()
        super().__init__(runtime)
        self.k8s_progress_phase = "discovering"
        self.k8s_settled = {}
        self.k8s_progress_lock = threading.RLock()
        self.gateway_discovery_lock = threading.RLock()
        self.gateway_discovery = None

    def call(self, operation, *args, **kwargs):
        if args and isinstance(args[0], str) and k8s_network_extensions.match(args[0]):
            return k8s_network_extensions.read(self, super().call, operation, *args, **kwargs)
        if args and isinstance(args[0], str) and k8s_network_catalog.allowed_path(args[0]):
            return k8s_network_catalog.read(self, super().call, operation, *args, **kwargs)
        return super().call(operation, *args, **kwargs)

    def progress(self, phase=None, scope="", settled=None, *, complete=False, _kept=False):
        if settled is not None and not _kept:
            return  # Shared _read fires before deterministic global-cap reduction.
        if not callable(self.k8s_progress_callback):
            return
        from peaso.progress import emit_progress
        with self.k8s_progress_lock:
            if phase:
                self.k8s_progress_phase = phase
            if complete:
                self.k8s_settled = {(row["type"], row["scope"]): len(row["items"]) for row in self.collections}
            if settled is not None:
                self.k8s_settled[(settled["type"], settled["scope"])] = len(settled.get("items", []))
            count = len(self.k8s_settled)
            emit_progress(self.k8s_progress_callback, phase=self.k8s_progress_phase, provider="k8s", scope=scope,
                completed=count, total=count if complete else None, resources=sum(self.k8s_settled.values()), dynamic_total=not complete)

    def _read(self, job):
        value = super()._read(job)
        if job[0] in getattr(self, 'network_route_absent', set()):
            value['applicability'] = {'observed_resource_absent': k8s_network_catalog.route_extensions.RESOURCES[job[0]][1],
                                    'source': 'GET /apis and served API resource discovery'}
        if job[0] in getattr(self, 'network_extension_absent', set()):
            value['applicability'] = {'observed_resource_absent': k8s_network_extensions.RESOURCES[job[0]][1],
                                    'source': 'GET /apis and served API resource discovery'}
        if job[0] in k8s_network_catalog.GATEWAYS and self.gateway_discovery and self.gateway_discovery.get("absent"):
            value["applicability"] = {"observed_api_group_absent": k8s_network_catalog.GROUP, "source": "GET /apis"}
        if value.get("error", {}).get("kind") == "AzureReadError":
            value["error"]["kind"] = "K8sReadError"
        return value

    def run(self, jobs):
        # Preserve the shared reader's request-order reduction and budget hooks;
        # report kept envelopes after the cross-inventory resource cap applies.
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for value in pool.map(self._read, jobs):
                capacity = len(value["items"]) if self.budget.max_items is None else max(0, self.budget.max_items - self.total)
                if len(value["items"]) > capacity:
                    value["items"] = value["items"][:capacity]
                    value.update(status="partial", error={"kind": "K8sReadError", "code": "resource_limit"})
                self.total += len(value["items"])
                self.collections.append(value)
                self.progress(scope=value["scope"], settled=value, _kept=True)

    def unavailable(self, kind, scope, service, exc):
        if type(exc) is AzureReadError:
            exc = K8sReadError(exc.code, exc.status_code)
        super().unavailable(kind, scope, service, exc)
        self.progress(scope=scope, settled=self.collections[-1], _kept=True)

# Inventory paths; the transport separately admits metadata-only Secret lists and exact node configz.
ENDPOINTS = {
    "configsync_rootsync": ("/apis/configsync.gke.io/v1beta1/rootsyncs", True),
    "configconnector": ("/apis/core.cnrm.cloud.google.com/v1beta1/configconnectors", False),
    "configconnectorcontext": ("/apis/core.cnrm.cloud.google.com/v1beta1/configconnectorcontexts", True),
    "kcc_iampolicy": ("/apis/iam.cnrm.cloud.google.com/v1beta1/iampolicies", True),
    "kcc_iampartialpolicy": ("/apis/iam.cnrm.cloud.google.com/v1beta1/iampartialpolicies", True),
    "kcc_project": ("/apis/resourcemanager.cnrm.cloud.google.com/v1beta1/projects", True),
    "role": ("/apis/rbac.authorization.k8s.io/v1/roles", True),
    "clusterrole": ("/apis/rbac.authorization.k8s.io/v1/clusterroles", False),
    "rolebinding": ("/apis/rbac.authorization.k8s.io/v1/rolebindings", True),
    "clusterrolebinding": ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", False),
    "serviceaccount": ("/api/v1/serviceaccounts", True),
    "namespace": ("/api/v1/namespaces", False),
    "pod": ("/api/v1/pods", True),
    "node": ("/api/v1/nodes", False),
    "deployment": ("/apis/apps/v1/deployments", True),
    "daemonset": ("/apis/apps/v1/daemonsets", True),
    "statefulset": ("/apis/apps/v1/statefulsets", True),
    "replicaset": ("/apis/apps/v1/replicasets", True),
    "job": ("/apis/batch/v1/jobs", True),
    "cronjob": ("/apis/batch/v1/cronjobs", True),
    "replicationcontroller": ("/api/v1/replicationcontrollers", True),
    "podtemplate": ("/api/v1/podtemplates", True),
    "service": ("/api/v1/services", True),
    "endpoints": ("/api/v1/endpoints", True),
    "endpointslice": ("/apis/discovery.k8s.io/v1/endpointslices", True),
    "persistentvolume": ("/api/v1/persistentvolumes", False),
    "persistentvolumeclaim": ("/api/v1/persistentvolumeclaims", True),
    "ingress": ("/apis/networking.k8s.io/v1/ingresses", True),
    "ingressclass": ("/apis/networking.k8s.io/v1/ingressclasses", False),
    "networkpolicy": ("/apis/networking.k8s.io/v1/networkpolicies", True),
    "cilium_networkpolicy": ("/apis/cilium.io/v2/ciliumnetworkpolicies", True),
    "cilium_clusterwide_networkpolicy": ("/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies", False),
    "calico_networkpolicy": ("/apis/projectcalico.org/v3/networkpolicies", True),
    "calico_global_networkpolicy": ("/apis/projectcalico.org/v3/globalnetworkpolicies", False),
    "admin_networkpolicy": ("/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies", False),
    "baseline_admin_networkpolicy": ("/apis/policy.networking.k8s.io/v1alpha1/baselineadminnetworkpolicies", False),
    "cluster_networkpolicy": ("/apis/policy.networking.k8s.io/v1alpha2/clusternetworkpolicies", False),
    "resourcequota": ("/api/v1/resourcequotas", True),
    "limitrange": ("/api/v1/limitranges", True),
}
TYPES = tuple(ENDPOINTS) + ("network_interface", "admission_configuration", "api_discovery", "securitycontextconstraint",
                           "component_configuration", "file_metadata", "secret_metadata", "configmap_metadata", "podsecuritypolicy",
                           "admission_policy", "admission_configuration_file", "node_clock", "k8s_selected_literals",
                           "kubelet_configmap_declaration", "k8s_selected_log_samples", "k8s_selected_metadata", "k8s_selected_text_content", "k8s_selected_flux_artifact", "k8s_selected_registry_image_secrets", "k8s_selected_registry_image_vulnerabilities")
ENDPOINTS.update(k8s_network_catalog.ENDPOINTS)
ENDPOINTS.update({kind: (f"/apis/{k8s_network_catalog.GROUP}/v1/{plural}", namespaced)
                  for kind, (plural, namespaced) in k8s_network_catalog.GATEWAYS.items()})
TYPES = tuple(dict.fromkeys((*TYPES, *k8s_network_catalog.ENDPOINTS, *k8s_network_catalog.GATEWAYS)))
ENDPOINTS.update({kind: k8s_network_extensions.endpoint(kind) for kind in k8s_network_extensions.RESOURCES})
TYPES = tuple(dict.fromkeys((*TYPES, *k8s_network_extensions.RESOURCES)))

# In-tree CEL admission policies (admissionregistration.k8s.io): plural, inventory kind marker, object Kind.
# Listed only for the resources the server advertises (resource discovery of each served group version).
ADMISSION_POLICY_GROUP = "admissionregistration.k8s.io"
ADMISSION_POLICY_RESOURCES = (
    ("validatingadmissionpolicies", "validatingadmissionpolicy", "ValidatingAdmissionPolicy"),
    ("validatingadmissionpolicybindings", "validatingadmissionpolicybinding", "ValidatingAdmissionPolicyBinding"),
    ("mutatingadmissionpolicies", "mutatingadmissionpolicy", "MutatingAdmissionPolicy"),
    ("mutatingadmissionpolicybindings", "mutatingadmissionpolicybinding", "MutatingAdmissionPolicyBinding"))
ADMISSION_POLICY_VERSIONS = ("v1", "v1beta1", "v1alpha1")
# Out-of-tree policy engines are recognised by their served API groups (CRD presence), not by their policy objects.
POLICY_ENGINE_GROUPS = {"kyverno": ("kyverno.io", "policies.kyverno.io"),
                        "gatekeeper": ("templates.gatekeeper.sh", "constraints.gatekeeper.sh", "config.gatekeeper.sh")}
CUSTOM_NETWORK_POLICY_GROUPS = {"cilium_networkpolicy": ("cilium.io", "v2"),
                                "cilium_clusterwide_networkpolicy": ("cilium.io", "v2"),
                                "calico_networkpolicy": ("projectcalico.org", "v3"),
                                "calico_global_networkpolicy": ("projectcalico.org", "v3"),
                                "admin_networkpolicy": ("policy.networking.k8s.io", "v1alpha1"),
                                "baseline_admin_networkpolicy": ("policy.networking.k8s.io", "v1alpha1"),
                                "cluster_networkpolicy": ("policy.networking.k8s.io", "v1alpha2")}


def _policy_engines(group_names):
    return {engine: sorted(g for g in group_names if g in groups) for engine, groups in POLICY_ENGINE_GROUPS.items()}


def _admission_policy_resources(reader, api, groups):
    """{plural: groupVersion} for the admission-policy resources the server advertises (read-only discovery)."""
    served = [str(v.get("version") or str(v.get("groupVersion", "")).rpartition("/")[2])
              for group in groups if group.get("name") == ADMISSION_POLICY_GROUP
              for v in group.get("versions", []) if isinstance(v, dict)]
    found = {}
    for version in [v for v in ADMISSION_POLICY_VERSIONS if v in served]:
        document = reader.call(api.get_json, f"/apis/{ADMISSION_POLICY_GROUP}/{version}")
        resources = document.get("resources") if isinstance(document, dict) else None
        if not isinstance(resources, list) or any(not isinstance(resource, dict) for resource in resources):
            raise ValueError("malformed admissionregistration resource discovery")
        names = {resource.get("name") for resource in resources}
        for plural, _, _ in ADMISSION_POLICY_RESOURCES:
            if plural in names and plural not in found:
                found[plural] = f"{ADMISSION_POLICY_GROUP}/{version}"
    return found


def _admission_policy_pages(reader, api, cluster, scope, advertised):
    for plural, kind, object_kind in ADMISSION_POLICY_RESOURCES:
        if plural not in advertised:
            continue
        for page in _pages(reader, api, f"/apis/{advertised[plural]}/{plural}", kind, cluster, scope, False):
            for item in page:
                item.setdefault("kind", object_kind)
                item.setdefault("apiVersion", advertised[plural])
                item["provenance"].setdefault("apiVersion", advertised[plural])
            yield page

# Only configuration declarations needed for reviewed component predicates are
# preserved. Shell text, arbitrary argv and credential values remain redacted.
COMPONENTS = frozenset(("kube-apiserver", "kube-controller-manager", "kube-scheduler", "kubelet", "etcd", "kube-proxy"))
CONFIG_FLAGS = frozenset(("anonymous-auth", "profiling", "authorization-mode", "audit-log-maxage", "audit-log-maxbackup",
    "audit-log-maxsize", "audit-log-path", "etcd-cafile", "etcd-certfile", "etcd-keyfile", "kubelet-client-certificate",
    "kubelet-client-key", "kubelet-certificate-authority", "tls-cert-file", "tls-private-key-file", "client-ca-file",
    "cert-file", "key-file", "peer-cert-file", "peer-key-file", "client-cert-auth", "peer-client-cert-auth",
    "auto-tls", "peer-auto-tls", "rotate-certificates", "protect-kernel-defaults", "make-iptables-util-chains",
    "event-qps", "read-only-port", "secure-port", "insecure-port", "insecure-bind-address", "bind-address",
    "hostname-override", "kubelet-https", "use-service-account-credentials", "service-account-private-key-file",
    "root-ca-file", "service-account-key-file", "service-account-lookup", "enable-admission-plugins",
    "disable-admission-plugins", "feature-gates", "terminated-pod-gc-threshold", "tls-cipher-suites",
    "request-timeout", "streaming-connection-idle-timeout", "encryption-provider-config", "basic-auth-file", "token-auth-file",
    "metrics-bind-address", "service-account-extend-token-expiration", "admission-control-config-file"))

CONFIGURATION_PATHS = ("authentication.anonymous.enabled", "authentication.x509.clientCAFile", "authorization.mode",
    "readOnlyPort", "makeIPTablesUtilChains", "rotateCertificates", "serverTLSBootstrap", "eventRecordQPS",
    "streamingConnectionIdleTimeout", "tlsCipherSuites", "tlsCertFile", "tlsPrivateKeyFile", "protectKernelDefaults",
    "podPidsLimit", "seccompDefault", "featureGates.RotateKubeletServerCertificate", "IPAddressDeny")


def _configuration_metadata(value, component):
    if not isinstance(value, dict):
        raise ValueError("component configuration metadata must be an object")
    kubelet_only = ("podPidsLimit", "seccompDefault", "featureGates.RotateKubeletServerCertificate", "IPAddressDeny")
    if component != "kubelet" and ("podPidsLimit" in value or "seccompDefault" in value or "IPAddressDeny" in value or
            isinstance(value.get("featureGates"), dict) and "RotateKubeletServerCertificate" in value["featureGates"]):
        raise ValueError("kubelet-only configuration metadata supplied for another component")
    output = {}
    for path in CONFIGURATION_PATHS:
        if path in kubelet_only and component != "kubelet":
            continue
        parts, current = path.split("."), value
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                break
            current = current[part]
        else:
            if isinstance(current, (dict, list)) and path != "tlsCipherSuites":
                raise ValueError("component metadata scalar is malformed")
            if path == "podPidsLimit" and (type(current) is not int or not -(1 << 63) <= current < (1 << 63)):
                raise ValueError("kubelet podPidsLimit metadata must be a signed int64")
            if path in ("seccompDefault", "featureGates.RotateKubeletServerCertificate") and type(current) is not bool:
                raise ValueError("kubelet security metadata must be boolean")
            if path == "IPAddressDeny" and (not isinstance(current, str) or current not in ("Any", "None")):
                raise ValueError("Windows kubelet IPAddressDeny metadata is malformed")
            if path == "tlsCipherSuites" and (not isinstance(current, list) or any(not isinstance(x, str) or not x.startswith("TLS_") for x in current)):
                raise ValueError("component cipher metadata is malformed")
            if path.endswith(("File", "KeyFile")) and (not isinstance(current, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", current)):
                raise ValueError("component file metadata must be a simple absolute path")
            target = output
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = copy.deepcopy(current)
    return output


def _component_config(value):
    command, args = value.get("command"), value.get("args", [])
    if command is None:
        return None
    if not isinstance(command, list) or not isinstance(args, list) or any(not isinstance(x, str) for x in command + args):
        return {"collection_status": "malformed", "error": {"code": "invalid_component_argv"}}
    if len(command) + len(args) > 1024:
        return {"collection_status": "partial", "error": {"code": "component_argv_limit"}}
    executable = command[0].rsplit("/", 1)[-1] if command else ""
    selected = [executable] if executable in COMPONENTS else []
    if not selected:
        candidates = {token.rsplit("/", 1)[-1] for token in command + args if token.rsplit("/", 1)[-1] in COMPONENTS}
        return {"component": None, "component_identification": "ambiguous_wrapped_component" if candidates else "ordinary_command",
                "flags_complete": not bool(candidates)}
    tokens, flags = command[1:] + args, {}
    boolean_flags = frozenset(("anonymous-auth", "profiling", "client-cert-auth", "peer-client-cert-auth",
        "auto-tls", "peer-auto-tls", "rotate-certificates", "protect-kernel-defaults", "make-iptables-util-chains",
        "kubelet-https", "use-service-account-credentials", "service-account-lookup", "service-account-extend-token-expiration"))
    boolean_values = {"true": "true", "1": "true", "t": "true", "false": "false", "0": "false", "f": "false"}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token == "--":
            # Positional operands after the terminator are not flag evidence.
            return {"collection_status": "partial", "error": {"code": "component_argv_terminator"}}
        if not token.startswith("--"):
            continue
        name, separator, captured = token[2:].partition("=")
        if selected[0] != "etcd":
            # Kubernetes normalizes underscores to hyphens before pflag parsing.
            name = name.replace("_", "-")
        if name not in CONFIG_FLAGS:
            continue
        if not separator:
            if name in boolean_flags:
                # pflag boolean flags do not consume a following space value.
                # Such positional text cannot establish a coherent declaration.
                if index < len(tokens) and not tokens[index].startswith("-"):
                    return {"collection_status": "malformed", "error": {"code": "component_boolean_positional_value"}}
                captured = "true"
            elif index < len(tokens) and not tokens[index].startswith("--"):
                captured = tokens[index]
                index += 1
            else:
                return {"collection_status": "malformed", "error": {"code": "component_flag_value_missing"}}
        # Fixed flag names, simple paths/lists/durations/enums; no URI credentials,
        # shell expressions, token payloads or multiline values cross the boundary.
        if len(captured) > 2048 or not re.fullmatch(r"[A-Za-z0-9_.,/:=+@-]*", captured) or "://" in captured:
            return {"collection_status": "malformed", "error": {"code": "unsafe_component_flag_value"}}
        if name in flags:
            return {"collection_status": "malformed", "error": {"code": "duplicate_component_flag"}}
        if name in boolean_flags:
            normalized = boolean_values.get(captured.lower())
            if normalized is None or captured not in ("true", "false", "TRUE", "FALSE", "True", "False", "t", "f", "T", "F", "0", "1"):
                return {"collection_status": "malformed", "error": {"code": "component_boolean_value_invalid"}}
            captured = normalized
        flags[name] = captured
    output = {"component": selected[0], "flags": flags, "flags_complete": True,
              "evidence": "explicit PodSpec executable/args declarations; no host or runtime configuration read"}
    image = value.get("image", "")
    version = re.fullmatch(r"(?:registry\.k8s\.io|k8s\.gcr\.io|gcr\.io/google_containers)/" + re.escape(selected[0]) + r":(v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?)", image) if isinstance(image, str) else None
    if version:
        output.update(version=version[1], version_evidence="Explicit official component image tag; runtime binary version not verified")
    return output


def validate_inline_kubeconfig(data, context=None):
    """Tenant-uploaded data cannot invoke helpers or dereference local paths."""
    if isinstance(data, str):
        from peaso.auth.documents import credential_document
        data = credential_document(data)
    if not isinstance(data, dict):
        raise ValueError("inline kubeconfig must be an object")
    for section in ("users", "clusters", "contexts"):
        entries = data.get(section)
        if not isinstance(entries, list) or not entries or any(not isinstance(entry, dict) or not isinstance(entry.get("name"), str) for entry in entries):
            raise ValueError("malformed inline kubeconfig section")
        if len({entry["name"] for entry in entries}) != len(entries):
            raise ValueError("duplicate kubeconfig names")
    for entry in data["users"]:
        user = entry.get("user")
        if not isinstance(user, dict) or set(user) - {"token", "client-certificate-data", "client-key-data"}:
            raise ValueError("inline kubeconfig cannot execute helpers or read files")
        if any(not isinstance(value, str) or not value or len(value) > 1_000_000 for value in user.values()):
            raise ValueError("kubeconfig requires embedded token or certificate strings")
    for entry in data["clusters"]:
        cluster = entry.get("cluster")
        if (not isinstance(cluster, dict) or set(cluster) - {"server", "certificate-authority-data", "tls-server-name", "insecure-skip-tls-verify"}
                or cluster.get("insecure-skip-tls-verify") not in (None, False)):
            raise ValueError("inline kubeconfig requires verified TLS and inline CA")
        if any(not isinstance(value, str) or not value or len(value) > 1_000_000
               for key, value in cluster.items() if key != 'insecure-skip-tls-verify'):
            raise ValueError("invalid embedded kubeconfig cluster settings")
        parsed = urlsplit(cluster.get("server", ""))
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("inline kubeconfig server must use HTTPS")
    selected = context or data.get("current-context")
    match = next((entry.get("context") for entry in data["contexts"] if entry["name"] == selected), None)
    if not isinstance(match, dict):
        raise ValueError("inline kubeconfig context does not exist")
    cluster = next((entry["cluster"] for entry in data["clusters"] if entry["name"] == match.get("cluster")), None)
    user = next((entry["user"] for entry in data["users"] if entry["name"] == match.get("user")), None)
    if not isinstance(cluster, dict) or not isinstance(user, dict):
        raise ValueError("inline kubeconfig context references are invalid")
    return {"server": cluster["server"], "token": user.get("token"),
            "ca_cert_data": cluster.get("certificate-authority-data"),
            "client_cert_data": user.get("client-certificate-data"),
            "client_key_data": user.get("client-key-data"), "context": selected,
            "tls_server_name": cluster.get("tls-server-name")}


def hosted_auth(auth):
    """Hosted probes and scans use only explicit tenant-owned inline material."""
    method = auth.get('method', 'auto')
    if method not in {'auto', 'token', 'certificate', 'client-cert', 'direct', 'kubeconfig', 'context', 'inline'}:
        raise ValueError('hosted Kubernetes cannot use ambient authentication')
    if any(key in auth for key in ('kubeconfig', 'token_file', 'ca_cert', 'client_cert', 'client_key', 'in_cluster')):
        raise ValueError('hosted Kubernetes cannot read local credential files')
    if method in {'kubeconfig', 'context', 'inline'} and auth.get('kubeconfig_data') is None:
        raise ValueError('hosted kubeconfig selection requires inline material')
    selected = validate_inline_kubeconfig(auth['kubeconfig_data'], auth.get('context')) if auth.get('kubeconfig_data') is not None else dict(auth)
    if (not selected.get('server') or not (selected.get('token') or
            (selected.get('client_cert_data') and selected.get('client_key_data')))):
        raise ValueError('hosted Kubernetes requires an explicit server and embedded credentials')
    return dict(selected, **({'cluster_id': auth['cluster_id']} if auth.get('cluster_id') else {}),
                **({'registry_auth': auth['registry_auth']} if 'registry_auth' in auth else {}),
                method='direct', _hosted=True)


def _public_server(server):
    """Resolve and reject hosted metadata/private destinations before API access."""
    parsed = urlsplit(server)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
        raise ValueError("hosted Kubernetes server requires HTTPS")
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(entry[4][0].split("%")[0]).is_global for entry in addresses):
        raise ValueError("hosted Kubernetes destination must resolve to public addresses")
    # Pin the validated address to eliminate a second DNS resolution. TLS SNI
    # and certificate hostname validation continue to use the original name.
    address = addresses[0][4][0]
    authority = "[" + address + "]" if ":" in address else address
    if parsed.port:
        authority += ":" + str(parsed.port)
    return "https://" + authority + parsed.path.rstrip("/"), parsed.hostname


class _TemporaryApi:
    def __init__(self, api, temporary):
        self.api, self.temporary = api, temporary
        self.api_client = api.api_client
        self.server = getattr(api, "server", None)

    def get_json(self, *args, **kwargs):
        return self.api.get_json(*args, **kwargs)

    def close(self):
        try:
            self.api.close()
        finally:
            self.temporary.cleanup()


def _allowed_calico_alias(path):
    """Admit served Calico CRD list paths only for reviewed kind and scope."""
    result = re.fullmatch(
        r"/apis/crd\.projectcalico\.org/v1(?:/namespaces/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?))?/([a-z0-9]+)",
        path)
    if result is None:
        return False
    reviewed = {plural: namespaced for groups, plural, namespaced
                in k8s_network_extensions.RESOURCES.values()
                if "crd.projectcalico.org" in groups}
    namespaced = reviewed.get(result[2])
    return namespaced is not None and (result[1] is None or namespaced is True)


def _inventory_read_path(path, query, headers):
    """Admit only collector metadata reads, never arbitrary GET subresources."""
    dns = r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?"
    namespace = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    version = r"v[0-9]+(?:(?:alpha|beta)[0-9]+)?"
    if path in ("/api", "/api/v1", "/apis", "/version"):
        return True
    if k8s_network_catalog.allowed_path(path):
        return True
    if _allowed_calico_alias(path):
        return True
    if re.fullmatch(r"/apis/" + dns + r"(?:/" + version + r")?", path):
        return True  # API group/resource discovery, including installed CRDs.
    for endpoint, namespaced in ENDPOINTS.values():
        if path == endpoint:
            return True
        prefix, plural = endpoint.rsplit("/", 1)
        if namespaced and re.fullmatch(re.escape(prefix) + r"/namespaces/" + namespace + "/" + plural, path):
            return True
    if re.fullmatch(r"/api/v1/namespaces/" + namespace, path):
        return True
    if re.fullmatch(r"/api/v1/namespaces/" + namespace + r"/configmaps/" + dns, path):
        return True  # Explicit volume-bound admission configuration, not Secret contents.
    if re.fullmatch(r"/api/v1/nodes/" + dns + r"/proxy/configz", path):
        return not query  # Sole bounded passive proxy exception; no alternate target/query.
    if re.fullmatch(r"/api/v1/(?:namespaces/" + namespace + r"/)?(?:secrets|configmaps)", path):
        accepts = [v for k, v in (headers or {}).items() if k.lower() == "accept"]
        accept = accepts[0] if len(accepts) == 1 else ""
        if accept == "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1":
            return True
        return (accept == "application/json;as=Table;g=meta.k8s.io;v=v1"
                and parse_qs(query, keep_blank_values=True).get("includeObject") == ["None"])
    if path in ("/apis/policy/v1beta1/podsecuritypolicies",
                "/apis/security.openshift.io/v1/securitycontextconstraints"):
        return True
    return bool(re.fullmatch(r"/apis/admissionregistration\.k8s\.io/" + version
                + r"/(?:validatingwebhookconfigurations|mutatingwebhookconfigurations|"
                  r"validatingadmissionpolicies|validatingadmissionpolicybindings|"
                  r"mutatingadmissionpolicies|mutatingadmissionpolicybindings)", path))


class _BoundedPool:
    """Constrain credentialed reads before I/O; disable SDK retries and redirects."""
    def __init__(self, pool, server=None):
        self.pool = pool
        self.server = urlsplit(server) if server else None
        self.allow_self_subject_access_review = False
        self.literal_paths = frozenset()  # Populated only for the exact optional selected reader.
        self.selected_log_requests = frozenset()  # Exact runtime grants from the opted-in log sampler.

    def request(self, method, url, **kwargs):
        review_request = method == "POST" and self.allow_self_subject_access_review
        if method != "GET" and not review_request:
            raise ValueError("native inventory transport is read-only")
        target = urlsplit(url)
        path = target.path
        if (target.scheme not in ("http", "https") or not target.hostname
                or target.username is not None or target.password is not None or target.fragment
                or any(c in path for c in ("%", "\\")) or "//" in path
                or any(c.isspace() or ord(c) < 32 for c in url)
                or any(part in (".", "..") for part in path.split("/"))):
            raise ValueError("invalid native inventory target")
        if self.server:
            def origin(value):
                return (value.scheme, value.hostname, value.port or (443 if value.scheme == "https" else 80))
            base = self.server.path.rstrip("/")
            if origin(target) != origin(self.server) or (base and not path.startswith(base + "/")):
                raise ValueError("native inventory target differs from configured API server")
            path = path[len(base):]
        # The official SDK supplies GET pagination/negotiation query via fields.
        # Validate that eventual query too, before urllib3 appends it to the URL.
        fields_query = urlencode(kwargs.get("fields") or {}, doseq=True)
        query = "&".join(part for part in (target.query, fields_query) if part)
        if review_request:
            if (path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
                    or query or not kwargs.get("body")):
                raise ValueError("unsupported access review request")
        else:
            from .k8s_selected_log_sample_secret_indicators import allowed_request
            if (kwargs.get("body") is not None
                    or not ((not query and path in self.literal_paths)
                        or (path.endswith("/log") and allowed_request(path, query, self.selected_log_requests))
                        or _inventory_read_path(path, query, kwargs.get("headers")))):
                raise ValueError("unsupported native inventory read path")
        kwargs.update(redirect=False, retries=False)
        return self.pool.request(method, url, **kwargs)

    def __getattr__(self, name):
        return getattr(self.pool, name)


def _wrap_client(api_client, source_server=None):
    from bluepeass.k8s import KubernetesApi
    rest_client = getattr(api_client, "rest_client", None)
    pool = getattr(rest_client, "pool_manager", None)
    if pool is None:
        raise ValueError("Kubernetes ApiClient requires rest_client.pool_manager for bounded reads")
    rest_client.pool_manager = _BoundedPool(pool, getattr(getattr(api_client, "configuration", None), "host", None))
    if source_server and callable(getattr(api_client, "set_default_header", None)):
        api_client.set_default_header("Host", urlsplit(source_server).netloc)
    api = KubernetesApi(api_client)
    if source_server:
        api.server = source_server
    return api


def _new_api(auth):
    if auth.get('_hosted'):
        auth = hosted_auth(auth)
    from kubernetes import client, config
    from bluepeass.k8s import KubernetesApi
    method = auth.get("method", "auto")
    if method == "inline":
        if auth.get("kubeconfig_data") is None:
            raise ValueError("inline authentication requires kubeconfig_data")
        method = "kubeconfig"
    if method not in ("auto", "kubeconfig", "context", "in_cluster", "in-cluster", "token", "certificate", "client-cert", "direct"):
        raise ValueError("unsupported Kubernetes authentication method")
    if method in ("token", "certificate", "client-cert", "direct") and not auth.get("server"):
        raise ValueError("selected direct authentication requires server")
    if method in ("auto", "kubeconfig", "context") and auth.get("kubeconfig_data") is not None:
        auth = {**auth, **validate_inline_kubeconfig(auth["kubeconfig_data"], auth.get("context"))}
        method = 'direct'
    elif method in ('kubeconfig', 'context') or (method == 'auto' and not auth.get('server')
            and not auth.get('in_cluster') and not os.getenv('KUBERNETES_SERVICE_HOST')):
        # Parse local files as data too. Never call the SDK kubeconfig loader,
        # which can execute exec/auth-provider helpers and read referenced files.
        path = auth.get('kubeconfig') or os.getenv('KUBECONFIG') or os.path.expanduser('~/.kube/config')
        if not isinstance(path, str) or os.pathsep in path:
            raise ValueError('use one data-only kubeconfig file')
        with open(path, encoding='utf-8') as stream:
            raw = stream.read(2_000_001)
        auth = {**auth, **validate_inline_kubeconfig(raw, auth.get('context'))}
        method = 'direct'
    direct = None if method in ("in_cluster", "in-cluster") or (method in ("kubeconfig", "context") and auth.get("kubeconfig_data") is None) else auth.get("server")
    if direct:
        parsed = urlsplit(direct)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("direct Kubernetes server must be an HTTPS origin")
        configuration = client.Configuration()
        configuration.host = direct.rstrip("/")
        configuration.verify_ssl = True
        if auth.get('tls_server_name'):
            configuration.tls_server_name = auth['tls_server_name']
            configuration.assert_hostname = auth['tls_server_name']
        if auth.get("_disable_proxy") is True:
            configuration.proxy = None
            configuration.proxy_headers = None
            configuration.no_proxy = None
        if auth.get("_hosted"):
            configuration.host, hostname = _public_server(direct)
            configuration.tls_server_name = auth.get('tls_server_name') or hostname
            configuration.assert_hostname = auth.get('tls_server_name') or hostname
        if auth.get("ca_cert"):
            configuration.ssl_ca_cert = auth["ca_cert"]
        certificate_mode = method in ("certificate", "client-cert")
        token = None if certificate_mode else auth.get("token")
        if not certificate_mode and auth.get("token_file"):
            with open(auth["token_file"], encoding="utf-8") as stream:
                token = stream.read().strip()
        if token:
            configuration.api_key = {"authorization": token}
            configuration.api_key_prefix = {"authorization": "Bearer"}
        cert, key = auth.get("client_cert"), auth.get("client_key")
        temporary = None
        inline = (("ca_cert_data", "ssl_ca_cert"), ("client_cert_data", "cert_file"), ("client_key_data", "key_file"))
        try:
            if any(auth.get(source) for source, _ in inline):
                temporary = tempfile.TemporaryDirectory(prefix="peaso-k8s-")
                for source, target in inline:
                    value = auth.get(source)
                    if value:
                        if not isinstance(value, str) or len(value) > 1_000_000:
                            raise ValueError("invalid inline TLS material")
                        payload = value.encode() if value.startswith("-----BEGIN") else base64.b64decode(value, validate=True)
                        path = os.path.join(temporary.name, source)
                        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(descriptor, "wb") as stream:
                            stream.write(payload)
                        setattr(configuration, target, path)
        except Exception:
            if temporary:
                temporary.cleanup()
            raise
        cert = cert or configuration.cert_file
        key = key or configuration.key_file
        if bool(cert) != bool(key):
            if temporary:
                temporary.cleanup()
            raise ValueError("client_cert and client_key must be supplied together")
        if cert:
            configuration.cert_file, configuration.key_file = cert, key
        if not token and not cert:
            if temporary:
                temporary.cleanup()
            raise ValueError("direct server requires token, token_file or client certificate")
        api_client = None
        try:
            api_client = client.ApiClient(configuration)
            api = _wrap_client(api_client, direct)
            return _TemporaryApi(api, temporary) if temporary else api
        except Exception:
            try:
                if api_client is not None:
                    api_client.close()
            finally:
                if temporary:
                    temporary.cleanup()
            raise
    elif method in ("in_cluster", "in-cluster") or (method == "auto" and (auth.get("in_cluster") or (not auth.get("kubeconfig") and not auth.get("context") and os.getenv("KUBERNETES_SERVICE_HOST")))):
        configuration = client.Configuration()
        config.load_incluster_config(client_configuration=configuration)
        api_client = client.ApiClient(configuration)
    else:
        raise ValueError('Kubernetes requires explicit credentials or a data-only kubeconfig')
    try:
        return _wrap_client(api_client)
    except Exception:
        api_client.close()
        raise


def _cluster_id(api, auth):
    # Prefer provider IDs when supplied (EKS ARN/GKE full path/AKS ARM ID).
    selected = auth.get("cluster_id")
    if selected:
        return str(selected)
    configuration = getattr(getattr(api, "api_client", None), "configuration", None)
    server = getattr(api, "server", None) or getattr(configuration, "host", None) or auth.get("server")
    if not server:
        raise ValueError("cluster identity requires an API server or authoritative cluster_id")
    parsed = urlsplit(server)
    if parsed.username or not parsed.netloc:
        raise ValueError("invalid Kubernetes API origin")
    origin = parsed.scheme.lower() + "://" + parsed.netloc.lower() + parsed.path.rstrip("/")
    return "k8s-cluster:" + hashlib.sha256(origin.encode()).hexdigest()


# Provider-ownership annotations (GKE components.gke.io/component-name, -version, layer): short identifiers
# the managed-component classifier (peaso.checks.k8s_managed) reads. They carry no workload literals.
_MANAGED_ANNOTATION_PREFIXES = ("components.gke.io/",)


def _env_entry(entry):
    """Env var: name plus valueFrom reference, or only the literal's length. A literal value never leaves here."""
    if "valueFrom" in entry:
        return {"name": entry.get("name"), "valueFrom": _sanitize(entry["valueFrom"])}
    value = entry.get("value", "")
    redacted = {"name": entry.get("name"), "value_redacted": True}
    if isinstance(value, str):
        redacted["value_length"] = len(value)
    return redacted


def _sanitize(value):
    """Workload literals and last-applied annotations can carry credentials."""
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    marker = annotation_indicators.MARKER
    # project() only ever projects an object that has a spec; nested maps skip the call.
    annotation_projection = annotation_indicators.project(value) if "spec" in value else None
    if annotation_projection is not None:
        result[marker] = annotation_projection
    if "command" in value or "args" in value:
        component = _component_config(value)
        if component is not None:
            result["_component_config"] = component
    # The drop decision depends only on the key; exact str keys reuse it.
    dropped_keys, leaves = k8s_sanitize_keys.DROPPED, k8s_sanitize_keys.LEAVES
    for key, child in value.items():
        if key == marker:
            continue  # Provider/customer fields cannot supply trusted indicators.
        dropped = dropped_keys.get(key) if type(key) is str else None
        if dropped is None:
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            dropped = bool((normalized_key != "automountserviceaccounttoken" and normalized_key.endswith(("password", "token", "privatekey", "clientsecret", "secretvalue"))) or normalized_key in (
                "apikey", "credentials", "stringdata", "privatekeydata") or key in ("managedFields",))
            k8s_sanitize_keys.remember(key, dropped)
        if dropped:
            continue
        if key == "annotations" and not isinstance(child, dict):
            result[key] = {}
            result.setdefault("_coverage", {})["annotations"] = {"status": "malformed"}
        elif key == "annotations" and isinstance(child, dict):
            # Retain only documented identity, networking and policy provenance.
            nginx_fields = ("nginx.ingress.kubernetes.io/backend-protocol",
                            "nginx.ingress.kubernetes.io/force-ssl-redirect",
                            "nginx.ingress.kubernetes.io/ssl-redirect")
            if any(field in child and (not isinstance(child[field], str) or len(child[field]) > 253)
                   for field in nginx_fields):
                result.setdefault("_coverage", {})["annotations"] = {"status": "malformed"}
            result[key] = {k: v for k, v in child.items() if isinstance(k, str) and isinstance(v, str) and (k in (
                "eks.amazonaws.com/role-arn", "iam.gke.io/gcp-service-account",
                "azure.workload.identity/client-id", "azure.workload.identity/tenant-id",
                "k8s.v1.cni.cncf.io/networks", "k8s.v1.cni.cncf.io/network-status",
                "kubernetes.io/ingress.class", "kubernetes.io/psp", "iam.amazonaws.com/permitted",
                "iam.amazonaws.com/role", "openshift.io/scc", "openshift.io/required-scc", "kubernetes.io/service-account.name",
                "kubernetes.io/service-account.uid") or (isinstance(k, str) and k.startswith(_MANAGED_ANNOTATION_PREFIXES) and isinstance(v, str) and len(v) <= 253)
                or (k in nginx_fields and isinstance(v, str) and len(v) <= 253))}
        elif key == "env" and isinstance(child, list):
            result[key] = [_env_entry(entry) for entry in child if isinstance(entry, dict)]
        elif key in ("command", "args"):
            result[key + "_redacted"] = True
        else:
            result[key] = child if type(child) in leaves else _sanitize(child)
    return result


def _native(item, kind, cluster, scope, namespaced):
    if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict):
        raise ValueError("malformed Kubernetes object")
    # LIST items may omit TypeMeta. A supplied contradictory type must never
    # acquire the requested endpoint's identity through provenance stamping.
    native_types = {
        "configsync_rootsync": ("configsync.gke.io/v1beta1", "RootSync"),
        "configconnector": ("core.cnrm.cloud.google.com/v1beta1", "ConfigConnector"),
        "configconnectorcontext": ("core.cnrm.cloud.google.com/v1beta1", "ConfigConnectorContext"),
        "kcc_iampolicy": ("iam.cnrm.cloud.google.com/v1beta1", "IAMPolicy"),
        "kcc_iampartialpolicy": ("iam.cnrm.cloud.google.com/v1beta1", "IAMPartialPolicy"),
        "kcc_project": ("resourcemanager.cnrm.cloud.google.com/v1beta1", "Project"),
        "pod": ("v1", "Pod"), "podtemplate": ("v1", "PodTemplate"),
        "replicationcontroller": ("v1", "ReplicationController"),
        "namespace": ("v1", "Namespace"), "node": ("v1", "Node"),
        "service": ("v1", "Service"), "serviceaccount": ("v1", "ServiceAccount"),
        "resourcequota": ("v1", "ResourceQuota"), "limitrange": ("v1", "LimitRange"),
        "deployment": ("apps/v1", "Deployment"), "daemonset": ("apps/v1", "DaemonSet"),
        "statefulset": ("apps/v1", "StatefulSet"), "replicaset": ("apps/v1", "ReplicaSet"),
        "job": ("batch/v1", "Job"), "cronjob": ("batch/v1", "CronJob"),
        "role": ("rbac.authorization.k8s.io/v1", "Role"),
        "clusterrole": ("rbac.authorization.k8s.io/v1", "ClusterRole"),
        "rolebinding": ("rbac.authorization.k8s.io/v1", "RoleBinding"),
        "clusterrolebinding": ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding"),
        "ingress": ("networking.k8s.io/v1", "Ingress"),
        "ingressclass": ("networking.k8s.io/v1", "IngressClass"),
        "networkpolicy": ("networking.k8s.io/v1", "NetworkPolicy"),
        "endpoints": ("v1", "Endpoints"),
        "endpointslice": ("discovery.k8s.io/v1", "EndpointSlice"),
        "podsecuritypolicy": ("policy/v1beta1", "PodSecurityPolicy"),
        "secret_metadata": ("meta.k8s.io/v1", "PartialObjectMetadata"),
        "configmap_metadata": ("meta.k8s.io/v1", "PartialObjectMetadata"),
    }
    expected = native_types.get(kind)
    if kind in {entry[1] for entry in ADMISSION_POLICY_RESOURCES}:
        object_kind = next(entry[2] for entry in ADMISSION_POLICY_RESOURCES if entry[1] == kind)
        version = item.get("apiVersion", ADMISSION_POLICY_GROUP + "/v1")
        if version not in {ADMISSION_POLICY_GROUP + "/" + v for v in ADMISSION_POLICY_VERSIONS}:
            raise ValueError("admission policy object version conflicts with endpoint")
        expected = (version, object_kind)
    if expected and (item.get("apiVersion", expected[0]) != expected[0]
                     or item.get("kind", expected[1]) != expected[1]):
        raise ValueError("Kubernetes object type conflicts with selected endpoint")
    if kind == "namespace":
        # GET /api/v1/namespaces fixes the GVK even when list items omit TypeMeta.
        # Reject a supplied, conflicting TypeMeta instead of silently replacing it.
        if item.get("kind", "Namespace") != "Namespace" or item.get("apiVersion", "v1") != "v1":
            raise ValueError("namespace object type conflicts with endpoint")
        item = {**item, "kind": "Namespace", "apiVersion": "v1"}
    meta = item["metadata"]
    name, namespace = meta.get("name"), meta.get("namespace")
    if not isinstance(name, str) or not name or (namespaced and (not isinstance(namespace, str) or not namespace)):
        raise ValueError("missing Kubernetes identity")
    if namespaced and scope != "*" and namespace != scope:
        raise ValueError("object outside requested namespace")
    if not namespaced and namespace:
        raise ValueError("cluster object has namespace")
    namespace = namespace if namespaced else "_cluster"
    from peaso.secret_evidence import pod_environment
    native_id = "k8s://" + "/".join(quote(str(x), safe="") for x in (cluster, kind, namespace, meta.get("uid") or name))
    pod_environment(item, kind=kind, resource_id=native_id, scope=namespace if scope == '*' else scope)
    result = _sanitize(item)
    if kind == "kcc_project":
        from .k8s_kcc_project import project_identity
        result = project_identity(result)
    annotations = meta.get("annotations", {})
    if isinstance(annotations, dict):
        mirror = annotations.get("kubernetes.io/config.mirror")
        source = annotations.get("kubernetes.io/config.source")
        result["_static_pod_metadata"] = bool(isinstance(mirror, str) and re.fullmatch(r"[0-9a-fA-F]{16,64}", mirror) or source in ("file", "http"))
    result["id"] = native_id
    result["provenance"] = {"cluster_id": cluster, "namespace": namespace, "uid": meta.get("uid"),
                            "apiVersion": item.get("apiVersion"), "resourceVersion": meta.get("resourceVersion"),
                            "evidence": "read-only list", "credential_material": "omitted"}
    return result


def _pages(reader, api, path, kind, cluster, scope, namespaced):
    continuation = None
    seen = set()
    node_names, node_uids = set(), set()
    version = None
    workload_types = {"pod": ("v1", "PodList"), "podtemplate": ("v1", "PodTemplateList"),
        "replicationcontroller": ("v1", "ReplicationControllerList"), "deployment": ("apps/v1", "DeploymentList"),
        "daemonset": ("apps/v1", "DaemonSetList"), "statefulset": ("apps/v1", "StatefulSetList"),
        "replicaset": ("apps/v1", "ReplicaSetList"), "job": ("batch/v1", "JobList"),
        "cronjob": ("batch/v1", "CronJobList")}
    for page in count():
        params = {"limit": reader.page_size}
        if continuation:
            params["continue"] = continuation
        response = reader.call(api.get_json, path, params)
        if not isinstance(response, dict) or not isinstance(response.get("items"), list) or not isinstance(response.get("metadata", {}), dict):
            raise ValueError("malformed Kubernetes list")
        if kind == "namespace" and (response.get("kind", "NamespaceList") != "NamespaceList"
                                    or response.get("apiVersion", "v1") != "v1"):
            raise ValueError("namespace list type conflicts with endpoint")
        if kind in workload_types:
            api_version, list_kind = workload_types[kind]
            if response.get("apiVersion", api_version) != api_version or response.get("kind", list_kind) != list_kind:
                raise ValueError("workload list type conflicts with endpoint")
        metadata = response.get("metadata", {})
        current_version = metadata.get("resourceVersion")
        if version is not None and current_version != version:
            raise ValueError("list resourceVersion changed across pages")
        version = current_version
        if kind == "node":
            for item in response["items"]:
                node_meta = item.get("metadata") if isinstance(item, dict) else None
                node_name = node_meta.get("name") if isinstance(node_meta, dict) else None
                node_uid = node_meta.get("uid") if isinstance(node_meta, dict) else None
                if (not isinstance(node_name, str) or not node_name or not isinstance(node_uid, str)
                        or not node_uid):
                    raise K8sReadError("node_identity_missing")
                if node_name in node_names or node_uid in node_uids:
                    raise K8sReadError("duplicate_node_identity")
                node_names.add(node_name)
                node_uids.add(node_uid)
        yield [_native(item, kind, cluster, scope, namespaced) for item in response["items"]]
        continuation = metadata.get("continue")
        if not continuation:
            return
        if not isinstance(continuation, str) or continuation in seen:
            raise ValueError("repeated or malformed continuation")
        seen.add(continuation)
        if reader.budget.max_pages is not None and page + 1 >= reader.budget.max_pages:
            raise K8sReadError("page_limit")


def _metadata_get(api, path, params, representation):
    """Negotiate metadata-only encodings; never add full-object JSON fallback."""
    if not hasattr(api, "api_client") or not hasattr(api.api_client, "call_api"):
        raise K8sReadError("metadata_negotiation_transport_unavailable")
    accept = "application/json;as=" + representation + ";g=meta.k8s.io;v=v1"
    try:
        response = api.api_client.call_api(path, "GET", query_params=list(params.items()),
            header_params={"Accept": accept}, auth_settings=["BearerToken"], _preload_content=False,
            _return_http_data_only=True, _request_timeout=30)
    except Exception as exc:
        raise K8sReadError("metadata_negotiation_failed", getattr(exc, "status", None)) from None
    try:
        # Kubernetes JSON encodes TypeMeta first. Reject a full SecretList before
        # consuming its object contents when a server violates negotiation.
        import json
        prefix = b""
        for _ in range(32):
            chunk = response.read(32)
            prefix += chunk
            match = re.search(rb'"kind"\s*:\s*"([^"\\]+)"', prefix)
            if match:
                if match[1].decode() != representation:
                    raise K8sReadError("metadata_representation_unsupported")
                break
            if not chunk:
                raise K8sReadError("metadata_representation_malformed")
        else:
            raise K8sReadError("metadata_representation_malformed")
        document = json.loads(prefix + response.read())
        if not isinstance(document, dict) or document.get("kind") != representation:
            raise K8sReadError("metadata_representation_malformed")
        if representation == "PartialObjectMetadataList":
            # Scrub metadata before it crosses the shared reader boundary;
            # last-applied annotations can embed the original Secret's data.
            document = _sanitize(document)
            for item in document.get("items", []):
                metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
                annotations = metadata.get("annotations", {})
                if isinstance(annotations, dict):
                    metadata["annotations"] = {key: value for key, value in annotations.items() if key in (
                        "kubernetes.io/service-account.name", "kubernetes.io/service-account.uid")}
        return document
    finally:
        response.close()
        response.release_conn()


def _metadata_pages(reader, api, path, kind, cluster, scope, namespaced, *, include_type=False):
    continuation, seen, resource_version = None, set(), None
    type_catalog = {}
    for page in count():
        params = {"limit": reader.page_size}
        if continuation:
            params["continue"] = continuation
        partial = reader.call(_metadata_get, api, path, params, "PartialObjectMetadataList")
        metadata = partial.get("metadata", {})
        items = partial.get("items")
        if not isinstance(metadata, dict) or not isinstance(items, list):
            raise K8sReadError("metadata_representation_malformed")
        if resource_version is not None and metadata.get("resourceVersion") != resource_version:
            raise K8sReadError("metadata_resource_version_changed")
        resource_version = metadata.get("resourceVersion")
        for item in items:
            if not isinstance(item, dict) or set(item) - {"kind", "apiVersion", "metadata"}:
                raise K8sReadError("metadata_response_contains_full_object")
        if include_type and items:
            # Tables without row objects do not always include namespace cells.
            # Resolve types per namespace, at the partial-list resourceVersion,
            # so identical names in different namespaces cannot collide.
            namespaces = {item.get("metadata", {}).get("namespace") for item in items}
            if all(isinstance(namespace, str) for namespace in namespaces):
                from functools import partial
                from .k8s_response_cache import warm
                # Each namespace's first Table page is read concurrently into the scan cache;
                # the loop below still performs, validates and orders every read itself.
                warm(api, [partial(_metadata_get, api, f"/api/v1/namespaces/{quote(namespace, safe='')}/secrets",
                                   {"limit": reader.page_size, "includeObject": "None", "resourceVersion": resource_version,
                                    "resourceVersionMatch": "Exact"}, "Table")
                           for namespace in sorted(namespaces) if namespace not in type_catalog], reader)
            for namespace in sorted(namespaces):
                if namespace in type_catalog:
                    continue
                if not isinstance(namespace, str):
                    raise K8sReadError("metadata_namespace_missing")
                table_path = f"/api/v1/namespaces/{quote(namespace, safe='')}/secrets"
                table_params = {"limit": reader.page_size, "includeObject": "None", "resourceVersion": resource_version,
                                "resourceVersionMatch": "Exact"}
                types, table_seen = {}, set()
                for table_page in count():
                    table = reader.call(_metadata_get, api, table_path, table_params, "Table")
                    if table.get("metadata", {}).get("resourceVersion") != resource_version:
                        raise K8sReadError("metadata_table_version_mismatch")
                    columns = table.get("columnDefinitions", [])
                    if not isinstance(columns, list) or any(not isinstance(column, dict) for column in columns):
                        raise K8sReadError("metadata_table_malformed")
                    names = [str(column.get("name", "")).lower() for column in columns]
                    if "name" not in names or "type" not in names:
                        raise K8sReadError("secret_type_metadata_unavailable")
                    for row in table.get("rows", []):
                        if not isinstance(row, dict) or row.get("object") not in (None, {}) or not isinstance(row.get("cells"), list):
                            raise K8sReadError("metadata_table_contains_object")
                        cells = row["cells"]
                        if len(cells) != len(names) or not isinstance(cells[names.index("type")], str):
                            raise K8sReadError("metadata_table_malformed")
                        types[str(cells[names.index("name")])] = cells[names.index("type")]
                    table_token = table.get("metadata", {}).get("continue")
                    if not table_token:
                        break
                    if not isinstance(table_token, str) or table_token in table_seen:
                        raise K8sReadError("metadata_table_continuation_malformed")
                    table_seen.add(table_token)
                    if reader.budget.max_pages is not None and table_page + 1 >= reader.budget.max_pages:
                        raise K8sReadError("page_limit")
                    table_params["continue"] = table_token
                type_catalog[namespace] = types
        output = []
        for item in items:
            native = _native(item, kind, cluster, scope, namespaced)
            native["provenance"]["representation"] = "PartialObjectMetadataList"
            if include_type:
                name = item["metadata"]["name"]
                types = type_catalog[item["metadata"]["namespace"]]
                if name not in types:
                    raise K8sReadError("secret_type_metadata_incomplete")
                native["type"] = types[name]
                native["provenance"]["type_source"] = "Table;includeObject=None"
            output.append(native)
        yield output
        continuation = metadata.get("continue")
        if not continuation:
            return
        if not isinstance(continuation, str) or continuation in seen:
            raise K8sReadError("metadata_continuation_malformed")
        seen.add(continuation)
        if reader.budget.max_pages is not None and page + 1 >= reader.budget.max_pages:
            raise K8sReadError("page_limit")


_OBSERVED_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$")

# Exact selectors from the reviewed, signed file-metadata family. This list is
# a validation allowlist for operator declarations, not a host path scanner.
FILE_METADATA_SELECTORS = (
    "/etc/cni/net.d/*", "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/controller-manager.conf", "/etc/kubernetes/manifests/etcd.yaml",
    "/etc/kubernetes/manifests/kube-apiserver.yaml",
    "/etc/kubernetes/manifests/kube-controller-manager.yaml",
    "/etc/kubernetes/manifests/kube-scheduler.yaml",
    "/etc/kubernetes/pki/*.crt", "/etc/kubernetes/pki/*.key",
    "/etc/kubernetes/pki/ca.crt", "/etc/kubernetes/proxy.conf",
    "/etc/kubernetes/scheduler.conf", "/var/lib/etcd",
)


def _file_path(value):
    return (isinstance(value, str) and 1 < len(value) <= 4096
            and value.startswith("/") and "\x00" not in value
            and not any(part in ("", ".", "..") or any(char in part for char in "*?[]")
                        for part in value[1:].split("/"))
            and posixpath.normpath(value) == value)


def _file_selector_matches(selector, path):
    if selector not in FILE_METADATA_SELECTORS or not _file_path(path):
        return False
    if "*" not in selector:
        return path == selector
    prefix, suffix = selector.split("*", 1)
    remainder = path[len(prefix):] if path.startswith(prefix) else ""
    return bool(remainder and "/" not in remainder and remainder.endswith(suffix))


def _component_configuration_coverage(options, cluster, collections, captured_at):
    """Validate an owner attestation against one complete current Node LIST.

    This is provenance for declaration checks, never kubelet runtime proof.
    A failed validation records only a reason code, not supplied values.
    """
    def unresolved(reason):
        return {"status": "unknown", "reason": reason, "runtime_verified": False}

    def parsed(value):
        if not isinstance(value, str) or len(value) > 64 or not _OBSERVED_UTC.fullmatch(value):
            raise ValueError("timestamp_shape")
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def identity(row, name_key, uid_key):
        if not isinstance(row, dict):
            raise ValueError("identity_shape")
        name, uid = row.get(name_key), row.get(uid_key)
        if any(not isinstance(value, str) or not value or len(value) > 253 for value in (name, uid)):
            raise ValueError("identity_shape")
        return name, uid

    supplied = options.get("metadata_evidence_coverage")
    if not isinstance(supplied, dict) or "component_configuration" not in supplied:
        return unresolved("coverage_manifest_missing")
    manifest = supplied["component_configuration"]
    if not isinstance(manifest, dict) or manifest.get("status") != "complete" or manifest.get("cluster_id") != cluster:
        return unresolved("coverage_manifest_invalid_or_foreign")
    policy = options.get("component_metadata_policy")
    if not isinstance(policy, dict):
        return unresolved("freshness_policy_missing")
    max_age = policy.get("max_age_seconds")
    if type(max_age) is not int or max_age <= 0:
        return unresolved("freshness_policy_invalid")
    node_pages = [row for row in collections if row.get("type") == "node"]
    component_pages = [row for row in collections if row.get("type") == "component_configuration"]
    if len(node_pages) == 1 and node_pages[0].get("error", {}).get("code") == "duplicate_node_identity":
        return unresolved("duplicate_node_identity")
    if len(node_pages) != 1 or node_pages[0].get("status") not in ("collected", "empty"):
        return unresolved("node_inventory_incomplete")
    if len(component_pages) != 1 or component_pages[0].get("status") not in ("collected", "empty"):
        return unresolved("component_inventory_incomplete")
    if not isinstance(manifest.get("nodes"), list) or not manifest["nodes"]:
        return unresolved("coverage_nodes_missing")
    try:
        now = parsed(captured_at)
        attested_at = parsed(manifest.get("observed_at"))
        if not 0 <= (now - attested_at).total_seconds() <= max_age:
            return unresolved("coverage_manifest_stale_or_future")
        live = [identity(row.get("metadata"), "name", "uid") for row in node_pages[0]["items"]]
        declared = [identity(row, "name", "uid") for row in manifest["nodes"]]
        kubelets = [row for row in component_pages[0]["items"] if row.get("component") == "kubelet"]
        observed = [identity(row, "node_name", "node_uid") for row in kubelets]
        for identities in (live, declared, observed):
            if (len(identities) != len(set(identities))
                    or len({name for name, _ in identities}) != len(identities)
                    or len({uid for _, uid in identities}) != len(identities)):
                return unresolved("duplicate_node_identity")
        if not live or set(live) != set(declared) or set(live) != set(observed):
            return unresolved("node_identity_sets_differ")
        for row in kubelets:
            at = parsed(row.get("observed_at"))
            if not 0 <= (now - at).total_seconds() <= max_age or at > attested_at:
                return unresolved("component_evidence_stale_or_future")
    except (ValueError, TypeError, KeyError, AttributeError):
        return unresolved("coverage_evidence_malformed")
    return {"status": "attested_complete", "component": "kubelet", "cluster_id": cluster,
            "node_count": len(live), "observed_at": manifest["observed_at"],
            "max_age_seconds": max_age, "runtime_verified": False,
            "source": "operator-supplied declaration checked against complete paged Node LIST"}


def _kube_proxy_pod_coverage(options, cluster, collections, captured_at):
    """Join bounded owner deployment declarations to complete Node/Pod LISTs.

    The owner declares each node's sole proxy Pod and excludes host-managed
    proxies. This attests Pod declarations only, never running processes.
    """
    def unresolved(reason):
        return {"status": "unknown", "reason": reason, "runtime_verified": False}

    supplied = options.get("metadata_evidence_coverage")
    manifest = supplied.get("kube_proxy_pod") if isinstance(supplied, dict) else None
    if (not isinstance(manifest, dict) or manifest.get("status") != "complete"
            or manifest.get("cluster_id") != cluster
            or set(manifest) != {"status", "cluster_id", "observed_at", "max_age_seconds", "max_nodes", "nodes"}):
        return unresolved("coverage_manifest_missing_invalid_or_foreign")
    budget, age = manifest.get("max_nodes"), manifest.get("max_age_seconds")
    if type(budget) is not int or not 0 < budget <= 10000 or type(age) is not int or age <= 0:
        return unresolved("coverage_bounds_invalid")
    nodes = manifest.get("nodes")
    if not isinstance(nodes, list) or not 0 < len(nodes) <= budget:
        return unresolved("coverage_nodes_missing_or_unbounded")
    node_pages = [row for row in collections if row.get("type") == "node"]
    pod_pages = [row for row in collections if row.get("type") == "pod"]
    if len(node_pages) != 1 or node_pages[0].get("status") not in ("collected", "empty"):
        return unresolved("node_inventory_incomplete")
    if len(pod_pages) != 1 or pod_pages[0].get("scope") != "*" or pod_pages[0].get("status") not in ("collected", "empty"):
        return unresolved("cluster_pod_inventory_incomplete")
    try:
        at = manifest["observed_at"]
        if not isinstance(at, str) or len(at) > 64 or not _OBSERVED_UTC.fullmatch(at):
            return unresolved("coverage_timestamp_invalid")
        elapsed = (datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
                   - datetime.fromisoformat(at.replace("Z", "+00:00"))).total_seconds()
        if not 0 <= elapsed <= age:
            return unresolved("coverage_manifest_stale_or_future")
        live = [(row["metadata"]["name"], row["metadata"]["uid"]) for row in node_pages[0]["items"]]
        declared, declared_pods = [], []
        for row in nodes:
            fields = {"name", "uid", "deployment", "host_managed", "pod_namespace", "pod_name", "pod_uid"}
            if (not isinstance(row, dict) or set(row) != fields or row["deployment"] != "pod"
                    or row["host_managed"] is not False
                    or any(not isinstance(row[k], str) or not 0 < len(row[k]) <= 253
                           for k in fields - {"deployment", "host_managed"})):
                return unresolved("coverage_deployment_invalid_or_host_managed")
            declared.append((row["name"], row["uid"]))
            declared_pods.append((row["name"], row["pod_namespace"], row["pod_name"], row["pod_uid"]))
        if (not live or len(live) > budget or set(live) != set(declared)
                or any(len({x[0] for x in identities}) != len(identities)
                       or len({x[1] for x in identities}) != len(identities) for identities in (live, declared))):
            return unresolved("node_identity_sets_differ_or_duplicate")
        observed = []
        for pod in pod_pages[0]["items"]:
            containers = pod.get("spec", {}).get("containers")
            if not isinstance(containers, list) or not containers:
                return unresolved("pod_declaration_malformed")
            for container in containers:
                config = container.get("_component_config")
                if isinstance(config, dict) and (config.get("collection_status") in ("malformed", "partial")
                        or config.get("component_identification") == "ambiguous_wrapped_component"):
                    return unresolved("component_declaration_incomplete")
                if isinstance(config, dict) and config.get("component") == "kube-proxy":
                    if config.get("flags_complete") is not True:
                        return unresolved("component_declaration_incomplete")
                    meta = pod["metadata"]
                    observed.append((pod["spec"]["nodeName"], meta["namespace"], meta["name"], meta["uid"]))
        if len(observed) != len(declared_pods) or len(set(observed)) != len(observed) or set(observed) != set(declared_pods):
            return unresolved("proxy_pod_identity_sets_differ_or_duplicate")
    except (ValueError, TypeError, KeyError, AttributeError):
        return unresolved("coverage_evidence_malformed")
    return {"status": "attested_complete", "cluster_id": cluster, "node_count": len(live),
            "observed_at": at, "max_age_seconds": age, "runtime_verified": False,
            "source": "operator-supplied deployment declaration checked against complete paged Node and Pod LISTs"}


def _file_metadata_coverage(options, cluster, collections, captured_at):
    """Match supplied file metadata to an exact, fresh, all-Node path manifest.

    The result attests only the owner's declarations, never a host stat or
    runtime permission. No filesystem access occurs here.
    """
    def unresolved(reason):
        return {"status": "unknown", "reason": reason, "runtime_verified": False}

    def parsed(value):
        if not isinstance(value, str) or len(value) > 64 or not _OBSERVED_UTC.fullmatch(value):
            raise ValueError("timestamp_shape")
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    supplied = options.get("metadata_evidence_coverage")
    manifest = supplied.get("file_metadata") if isinstance(supplied, dict) else None
    if not isinstance(manifest, dict) or manifest.get("status") != "complete" or manifest.get("cluster_id") != cluster:
        return unresolved("coverage_manifest_missing_invalid_or_foreign")
    policy = options.get("file_metadata_policy")
    max_age = policy.get("max_age_seconds") if isinstance(policy, dict) else None
    if type(max_age) is not int or max_age <= 0:
        return unresolved("freshness_policy_missing_or_invalid")
    node_pages = [row for row in collections if row.get("type") == "node"]
    file_pages = [row for row in collections if row.get("type") == "file_metadata"]
    if any(row.get("error", {}).get("code") == "duplicate_node_identity" for row in node_pages):
        return unresolved("duplicate_node_identity")
    if len(node_pages) != 1 or node_pages[0].get("status") not in ("collected", "empty"):
        return unresolved("node_inventory_incomplete")
    if len(file_pages) != 1 or file_pages[0].get("status") not in ("collected", "empty"):
        return unresolved("file_metadata_inventory_incomplete")
    nodes = manifest.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return unresolved("coverage_nodes_missing")
    if len(nodes) != len(node_pages[0]["items"]):
        return unresolved("node_identity_sets_differ")
    try:
        now, attested_at = parsed(captured_at), parsed(manifest.get("observed_at"))
        if not 0 <= (now - attested_at).total_seconds() <= max_age:
            return unresolved("coverage_manifest_stale_or_future")
        live, live_uids = {}, set()
        for row in node_pages[0]["items"]:
            meta = row.get("metadata")
            if not isinstance(meta, dict):
                raise ValueError("node_identity_shape")
            name, uid = meta.get("name"), meta.get("uid")
            if any(not isinstance(v, str) or not v or len(v) > 253 for v in (name, uid)) or name in live or uid in live_uids:
                return unresolved("node_identity_missing_or_duplicate")
            live[name] = uid
            live_uids.add(uid)
        declared, declared_uids = {}, set()
        expected = {selector: [] for selector in FILE_METADATA_SELECTORS}
        for node in nodes:
            if not isinstance(node, dict):
                raise ValueError("manifest_node_shape")
            name, uid = node.get("name"), node.get("uid")
            if any(not isinstance(v, str) or not v or len(v) > 253 for v in (name, uid)) or name in declared or uid in declared_uids:
                return unresolved("manifest_node_identity_missing_or_duplicate")
            declared[name] = uid
            declared_uids.add(uid)
            selectors = node.get("selectors")
            if not isinstance(selectors, dict) or set(selectors) != set(FILE_METADATA_SELECTORS):
                return unresolved("selector_applicability_incomplete")
            for selector in FILE_METADATA_SELECTORS:
                value = selectors[selector]
                if not isinstance(value, dict) or type(value.get("applicable")) is not bool:
                    return unresolved("selector_applicability_malformed")
                paths = value.get("paths")
                if value["applicable"]:
                    if value.get("enumeration_complete") is not True or not isinstance(paths, list) or not paths:
                        return unresolved("selector_paths_incomplete")
                    if len(paths) > len(file_pages[0]["items"]):
                        return unresolved("selector_paths_exceed_observed_files")
                    if len(paths) != len(set(paths)) or any(not _file_selector_matches(selector, path) for path in paths):
                        return unresolved("selector_paths_malformed")
                    expected[selector].extend({"node_name": name, "node_uid": uid, "path": path} for path in paths)
                elif (paths not in (None, []) or not isinstance(value.get("reason"), str)
                      or not value["reason"].strip() or len(value["reason"]) > 253):
                    return unresolved("selector_nonapplicability_unexplained")
        if not live or live != declared:
            return unresolved("node_identity_sets_differ")
        observed = {}
        for row in file_pages[0]["items"]:
            name, uid, path = row.get("node_name"), row.get("node_uid"), row.get("path")
            if not isinstance(name, str) or not isinstance(uid, str) or live.get(name) != uid or not _file_path(path):
                return unresolved("file_identity_unresolved")
            key = (uid, path)
            if key in observed:
                return unresolved("duplicate_node_path")
            observed[key] = row
            when = parsed(row.get("observed_at"))
            if not 0 <= (now - when).total_seconds() <= max_age or when > attested_at:
                return unresolved("file_evidence_stale_or_future")
        by_selector = {selector: {(row["node_uid"], row["path"]) for row in rows}
                       for selector, rows in expected.items()}
        required = set().union(*by_selector.values())
        if not required <= set(observed):
            return unresolved("declared_file_row_missing")
        for key in observed:
            if any(_file_selector_matches(selector, key[1]) and key not in by_selector[selector]
                   for selector in FILE_METADATA_SELECTORS):
                return unresolved("observed_path_omitted_from_manifest")
    except (ValueError, TypeError, KeyError, AttributeError):
        return unresolved("coverage_evidence_malformed")
    return {"status": "attested_complete", "cluster_id": cluster, "node_count": len(live),
            "observed_at": manifest["observed_at"], "max_age_seconds": max_age,
            "selector_paths": expected, "runtime_verified": False,
            "source": "operator-supplied path declarations checked against complete paged Node LIST"}


def _owner_policy_metadata(options, cluster, captured_at):
    """Retain only bounded, fresh, cluster-bound owner declarations.

    No Kubernetes API operation or inferred default is involved. Reject the
    whole policy when any supplied field is malformed, so an omitted or bad
    parameter cannot be mistaken for an approved configuration.
    """
    def unresolved(reason):
        return {"status": "unknown", "reason": reason, "source": "operator-supplied"}

    raw = options.get("compliance_policy")
    if raw is None:
        return unresolved("owner_policy_missing")
    if not isinstance(raw, dict) or set(raw) - {
        "cluster_id", "observed_at", "max_age_seconds", "max_policy_items",
        "namespace_labels", "target_namespace", "authorized_namespaces",
        "serviceType", "selected_loadbalancer_services",
        "approved_max_request_timeout", "approved_min_event_qps", "approved_namespaces",
        "approved_node_pool_selector", "approved_node_selector", "approved_label_selector",
        "oldestVersionSupported", "system_namespaces", "in_scope_service_names",
        "required_external_traffic_policy", "allowed_namespaces", "required_subject_kind",
        "required_subject_name", "required_role_kind", "required_role_name",
        "approved_images", "allowed_public_ports", "allowed_ports", "network_policy_intent",
        "authorized_subjects", "authorized_utility_namespaces", "privileged_utility_pods",
        "classification_label_key", "approved_values", "environment_matrix",
        "approved_clock_skew", "approved_control_namespaces", "resolved_etcd_accounts",
    }:
        return unresolved("owner_policy_shape_invalid")
    budget = raw.get("max_policy_items")
    if type(budget) is not int or not 0 < budget <= 10000:
        return unresolved("owner_policy_bounds_missing_or_invalid")
    if raw.get("cluster_id") != cluster:
        return unresolved("owner_policy_cluster_mismatch")
    has_observed, has_age = "observed_at" in raw, "max_age_seconds" in raw
    if has_observed != has_age:
        return unresolved("owner_policy_expiry_pair_incomplete")
    expiry = {}
    if has_observed:
        try:
            observed, age = raw["observed_at"], raw["max_age_seconds"]
            if type(age) is not int or age <= 0 or not isinstance(observed, str) or len(observed) > 64 or not _OBSERVED_UTC.fullmatch(observed):
                raise ValueError("timestamp or age")
            elapsed = (datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
                       - datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds()
            if not 0 <= elapsed <= age:
                return unresolved("owner_policy_stale_or_future")
        except (TypeError, ValueError):
            return unresolved("owner_policy_observation_invalid")
        expiry = {"observed_at": observed, "max_age_seconds": age}

    def dns_name(value):
        return (isinstance(value, str) and 0 < len(value) <= 63
                and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", value) is not None)

    def label_key(value):
        if not isinstance(value, str) or len(value) > 253:
            return False
        prefix, sep, name = value.rpartition("/")
        return (bool(name) and len(name) <= 63 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", name) is not None
                and (not sep or bool(prefix) and len(prefix) <= 253
                     and all(dns_name(part) for part in prefix.split("."))))

    def label_value(value):
        return (isinstance(value, str) and len(value) <= 63
                and (not value or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", value) is not None))

    kept = {"status": "collected", "source": "operator-supplied", "cluster_id": cluster,
            **expiry, "max_policy_items": budget}
    count = 0
    labels = raw.get("namespace_labels")
    if labels is not None:
        keys = {"required_key", "required_value", "master_label_key", "required_master_value"}
        if not isinstance(labels, dict) or set(labels) != keys or not all(label_key(labels[k]) for k in ("required_key", "master_label_key")) or not all(label_value(labels[k]) for k in ("required_value", "required_master_value")):
            return unresolved("owner_namespace_label_policy_invalid")
        if labels["required_key"] == labels["master_label_key"] and labels["required_value"] != labels["required_master_value"]:
            return unresolved("owner_namespace_label_policy_conflicting")
        kept["namespace_labels"] = dict(labels)
        count += 2
    if "target_namespace" in raw:
        if not dns_name(raw["target_namespace"]):
            return unresolved("owner_target_namespace_invalid")
        kept["target_namespace"] = raw["target_namespace"]
        count += 1
    if "authorized_namespaces" in raw:
        names = raw["authorized_namespaces"]
        if not isinstance(names, list) or not names or len(names) > budget or any(not dns_name(x) for x in names) or len(names) != len(set(names)):
            return unresolved("owner_authorized_namespaces_invalid")
        kept["authorized_namespaces"] = list(names)
        count += len(names)
    if "serviceType" in raw:
        if raw["serviceType"] not in ("ClusterIP", "NodePort", "LoadBalancer", "ExternalName") or type(raw["serviceType"]) is not str:
            return unresolved("owner_service_type_invalid")
        kept["serviceType"] = raw["serviceType"]
        count += 1
    if "selected_loadbalancer_services" in raw:
        rows = raw["selected_loadbalancer_services"]
        if not isinstance(rows, list) or not rows or len(rows) > budget:
            return unresolved("owner_selected_services_invalid")
        selected, identities = [], set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"namespace", "name", "uid"} or not dns_name(row["namespace"]) or not dns_name(row["name"]) or not isinstance(row["uid"], str) or not 0 < len(row["uid"]) <= 253 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", row["uid"]):
                return unresolved("owner_selected_service_identity_invalid")
            identity = (row["namespace"], row["name"])
            if identity in identities:
                return unresolved("owner_selected_service_identity_duplicate")
            identities.add(identity)
            selected.append(dict(row))
        kept["selected_loadbalancer_services"] = selected
        count += len(selected)
    for key in ("approved_max_request_timeout", "approved_min_event_qps"):
        if key in raw:
            value = raw[key]
            if type(value) is not int or value < (1 if key == "approved_max_request_timeout" else 0) or value >= (1 << 63):
                return unresolved("owner_" + key + "_invalid")
            kept[key] = value
            count += 1
    for key in ("approved_namespaces", "system_namespaces", "in_scope_service_names", "allowed_namespaces"):
        if key in raw:
            values = raw[key]
            if (not isinstance(values, list) or not values or len(values) > budget
                    or any(not dns_name(x) and not (key == "allowed_namespaces" and x == "*") for x in values)
                    or len(values) != len(set(values))):
                return unresolved("owner_" + key + "_invalid")
            kept[key] = list(values)
            count += len(values)
    for key in ("approved_node_pool_selector", "approved_node_selector", "approved_label_selector"):
        if key in raw:
            value = raw[key]
            if (not isinstance(value, dict) or not value or len(value) > budget
                    or any(not label_key(k) or not label_value(v) for k, v in value.items())):
                return unresolved("owner_" + key + "_invalid")
            kept[key] = dict(value)
            count += len(value)
    enums = {"required_external_traffic_policy": ("Cluster", "Local"),
             "required_subject_kind": ("User", "Group", "ServiceAccount"),
             "required_role_kind": ("Role", "ClusterRole")}
    for key, allowed in enums.items():
        if key in raw:
            if type(raw[key]) is not str or raw[key] not in allowed:
                return unresolved("owner_" + key + "_invalid")
            kept[key] = raw[key]
            count += 1
    for key in ("required_subject_name", "required_role_name"):
        if key in raw:
            value = raw[key]
            if (not isinstance(value, str) or not 0 < len(value) <= 253
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]*", value) is None):
                return unresolved("owner_" + key + "_invalid")
            kept[key] = value
            count += 1
    if "approved_images" in raw:
        images = raw["approved_images"]
        pattern = r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-zA-Z0-9._/-]+@sha256:[a-f0-9]{64}"
        if (not isinstance(images, list) or not images or len(images) > budget or
                any(not isinstance(image, str) or len(image) > 512 or re.fullmatch(pattern, image) is None for image in images) or
                len(set(images)) != len(images)):
            return unresolved("owner_approved_images_invalid")
        kept["approved_images"] = list(images)
        count += len(images)
    for key in ("allowed_public_ports", "allowed_ports"):
        if key not in raw:
            continue
        rows = raw[key]
        if not isinstance(rows, list) or not rows or len(rows) > budget:
            return unresolved("owner_" + key + "_invalid")
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"protocol", "port"} or row["protocol"] not in ("TCP", "UDP", "SCTP"):
                return unresolved("owner_" + key + "_invalid")
            port = row["port"]
            if not (type(port) is int and 1 <= port <= 65535 or isinstance(port, str) and 0 < len(port) <= 63 and re.fullmatch(r"[a-z][a-z0-9-]*", port)):
                return unresolved("owner_" + key + "_invalid")
            identity = (row["protocol"], port)
            if identity in seen:
                return unresolved("owner_" + key + "_invalid")
            seen.add(identity)
        kept[key] = copy.deepcopy(rows)
        count += len(rows)
    for key in ("authorized_subjects", "authorized_utility_namespaces", "privileged_utility_pods",
                "approved_values", "approved_control_namespaces"):
        if key not in raw:
            continue
        values = raw[key]
        if (not isinstance(values, list) or not values or len(values) > budget or
                any(not isinstance(value, str) or not 0 < len(value) <= 253 or
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]*", value) is None for value in values) or
                len(set(values)) != len(values)):
            return unresolved("owner_" + key + "_invalid")
        kept[key] = list(values)
        count += len(values)
    if "classification_label_key" in raw:
        if not label_key(raw["classification_label_key"]):
            return unresolved("owner_classification_label_key_invalid")
        kept["classification_label_key"] = raw["classification_label_key"]
        count += 1
    if "approved_clock_skew" in raw:
        skew = raw["approved_clock_skew"]
        if type(skew) is not int or not 0 <= skew <= 86400:
            return unresolved("owner_approved_clock_skew_invalid")
        kept["approved_clock_skew"] = skew
        count += 1
    if "resolved_etcd_accounts" in raw:
        accounts = raw["resolved_etcd_accounts"]
        if (not isinstance(accounts, dict) or not accounts or len(accounts) > budget or
                any(not dns_name(name) or not isinstance(value, dict) or set(value) != {"uid", "gid"} or
                    any(type(value[field]) is not int or value[field] < 0 for field in ("uid", "gid"))
                    for name, value in accounts.items())):
            return unresolved("owner_resolved_etcd_accounts_invalid")
        kept["resolved_etcd_accounts"] = copy.deepcopy(accounts)
        count += len(accounts)
    if "network_policy_intent" in raw:
        intent = raw["network_policy_intent"]
        if not isinstance(intent, dict) or not intent or len(intent) > budget:
            return unresolved("owner_network_policy_intent_invalid")
        rule_count = 0
        for identity, value in intent.items():
            if (not isinstance(identity, str) or len(identity.split("/")) != 2 or
                    not all(dns_name(part) for part in identity.split("/")) or not isinstance(value, dict) or
                    set(value) != {"policyTypes", "ingress", "egress"} or
                    not isinstance(value["policyTypes"], list) or
                    any(item not in ("Ingress", "Egress") for item in value["policyTypes"]) or
                    any(not isinstance(value[field], list) or len(value[field]) > budget or
                        any(not isinstance(rule, dict) or set(rule) - ({"from", "ports"} if field == "ingress" else {"to", "ports"})
                            for rule in value[field]) for field in ("ingress", "egress"))):
                return unresolved("owner_network_policy_intent_invalid")
            rule_count += len(value["ingress"]) + len(value["egress"])
            for rule in value["ingress"] + value["egress"]:
                if len(repr(rule)) > 8192 or any(field in repr(rule).lower() for field in ("password", "token", "private_key", "secretvalue")):
                    return unresolved("owner_network_policy_intent_invalid")
        kept["network_policy_intent"] = copy.deepcopy(intent)
        count += len(intent) + rule_count
    if "environment_matrix" in raw:
        matrix = raw["environment_matrix"]
        if not isinstance(matrix, dict) or set(matrix) != {"environment_key", "namespaces", "subject_environments", "allowed_cross_environment"} or not label_key(matrix["environment_key"]):
            return unresolved("owner_environment_matrix_invalid")
        namespaces, subjects, crosses = (matrix[name] for name in ("namespaces", "subject_environments", "allowed_cross_environment"))
        if (not isinstance(namespaces, dict) or not namespaces or not isinstance(subjects, dict) or not isinstance(crosses, list) or
                len(namespaces) + len(subjects) + len(crosses) > budget or
                any(not dns_name(name) or not label_value(env) or not env for name, env in namespaces.items()) or
                any(not isinstance(name, str) or re.fullmatch(r"(?:User|Group):[A-Za-z0-9_.@/-]+", name) is None or
                    not label_value(env) or not env for name, env in subjects.items()) or
                any(not isinstance(pair, list) or len(pair) != 2 or any(not label_value(env) or not env for env in pair) for pair in crosses)):
            return unresolved("owner_environment_matrix_invalid")
        kept["environment_matrix"] = copy.deepcopy(matrix)
        count += len(namespaces) + len(subjects) + len(crosses)
    if "oldestVersionSupported" in raw:
        value = raw["oldestVersionSupported"]
        match = re.fullmatch(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?", value) if isinstance(value, str) and len(value) <= 253 else None
        if (not match or any(not part or part.isdigit() and len(part) > 1 and part[0] == "0"
                             for part in (match[4] or "x").split("."))
                or any(not part for part in (match[5] or "x").split("."))):
            return unresolved("owner_oldestVersionSupported_invalid")
        kept["oldestVersionSupported"] = value
        count += 1
    if count > budget:
        return unresolved("owner_policy_item_budget_exceeded")
    if kept.get("serviceType") not in (None, "LoadBalancer") and kept.get("selected_loadbalancer_services"):
        # Namespace labels and RoleBindings remain independently assessable.
        # Only Service checks treat the conflicting owner intent as unknown.
        kept["service_type_conflict"] = True
    return kept


def collect(connector, requirements=None, *, api=None):
    options, auth = dict(connector.get("options", {})), connector.get("auth", {})
    from . import k8s_node_clock_evidence as clock_evidence
    from . import k8s_literal_configmap_association as literals
    from . import k8s_selected_text_content as selected_text
    from . import k8s_selected_flux_artifact_20261021 as flux_artifacts
    from . import k8s_selected_log_sample_secret_indicators as log_samples
    from . import k8s_selected_registry_image_20261021 as registry_images
    from . import k8s_selected_metadata_runtime_20261020 as selected_metadata
    from . import k8s_annotation_indicators_20261020 as annotation_indicators
    from . import k8s_legacy_psp_planner_20261020 as legacy_psp
    from . import k8s_kubelet_configmap_indicators_20261020 as kubelet_configmaps
    imported_clock = clock_evidence.normalize(options)
    trusted_scopes = _trusted_scopes(options)
    requested = options.get("inventories", [kind for kind in TYPES if kind not in (literals.KIND, log_samples.KIND, selected_metadata.KIND, selected_text.KIND, flux_artifacts.KIND, registry_images.SECRET_KIND, registry_images.VULN_KIND)]) if requirements is None else requirements
    if not isinstance(requested, (list, tuple)) or any(kind not in TYPES for kind in requested):
        raise ValueError("unsupported Kubernetes inventory requirement")
    wanted = set(requested)
    actual = set(wanted)
    auto_workload_literals = (options.get('content_secret_scans') is True
        and literals.KIND in options.get('_content_secret_scan_kinds', [])
        and literals.OPTION not in options and literals.KIND in wanted)
    if auto_workload_literals:
        wanted.update(('pod', 'deployment', 'daemonset', 'statefulset', 'replicaset',
            'job', 'cronjob', 'replicationcontroller', 'podtemplate'))
        actual.update(wanted)
    legacy_psp_requested = options.get(legacy_psp.OPTION) is True and "api_discovery" in wanted
    annotation_context = None
    scopes = connector.get("scopes") or ["*"]
    if not isinstance(scopes, list) or any(not isinstance(x, str) or (x != "*" and (len(x) > 63 or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", x) is None)) for x in scopes):
        raise ValueError("scopes must contain valid namespaces or '*'")
    scopes = ["*"] if "*" in scopes else list(dict.fromkeys(scopes))
    if not auto_workload_literals:
        literals.selected_targets(options, scopes)  # Reject malformed selectors before authentication.
    log_targets = log_samples.selected_targets(options, scopes)
    selected_metadata.preflight(options, scopes)
    selected_text.selected_targets(options, scopes)
    flux_artifacts.selected_targets(options, scopes, options.get("_flux_artifact_named_checks", []))
    registry_targets = registry_images.selected_targets(options, scopes, options.get("_registry_image_named_checks", []))
    registry_images.registry_credentials(auth, registry_targets, options.get(registry_images.ALLOWLIST, []))
    literal_metadata, literal_matches = {}, set()
    log_metadata, log_matches = {}, set()
    selected_metadata_facts, selected_metadata_matches = {}, set()
    text_facts, text_matches = {}, set()
    flux_facts, flux_matches = {}, set()
    registry_facts, registry_matches = {}, set()
    requested_scopes = list(scopes)
    max_scopes = options.get("max_scopes")
    if max_scopes is not None and (type(max_scopes) is not int or max_scopes <= 0):
        raise ValueError("max_scopes must be a positive explicit limit")
    scopes = scopes if max_scopes is None else scopes[:max_scopes]
    reader = K8sReader(options)
    reader.collection_callback = options.get("_collection_callback")
    from peaso.collection_events import SettledCollections
    deferred = {"network_interface"}
    if auto_workload_literals:
        deferred.add(literals.KIND)
    reader.collections = SettledCollections(reader.collection_callback, deferred=deferred)
    private_content = ((log_samples.KIND in wanted and log_samples.enabled(options))
        or (literals.KIND in wanted and literals.enabled(options))
        or (selected_metadata.KIND in wanted and selected_metadata.enabled(options, scopes))
        or ((selected_text.KIND in wanted and selected_text.enabled(options)) or (flux_artifacts.KIND in wanted and flux_artifacts.enabled(options, options.get("_flux_artifact_named_checks", []))))
        or (bool(wanted & {registry_images.SECRET_KIND, registry_images.VULN_KIND})
            and any(registry_images.enabled(options, options.get("_registry_image_named_checks", [])))))
    if private_content:
        native_read = reader._read
        def private_metadata_read(job):
            with log_samples.private_native_logs():
                return native_read(job)
        reader._read = private_metadata_read
    if wanted.intersection((literals.KIND, log_samples.KIND, selected_metadata.KIND, selected_text.KIND, flux_artifacts.KIND,
                            registry_images.SECRET_KIND, registry_images.VULN_KIND)) and callable(reader.k8s_progress_callback):
        literal_callback = reader.k8s_progress_callback
        # Namespaces themselves can contain detected values. Optional content
        # jobs publish counts only, including before detection has completed.
        reader.k8s_progress_callback = lambda event: literal_callback({**event, "scope": ""})
    reader.progress("discovering")
    owned = api is None
    cluster = auth.get("cluster_id")
    from .k8s_scan_gc import pause as pause_full_gc
    full_gc_hold = pause_full_gc()  # Young collections continue; closed in the finally block below.
    try:
        if options.get("hosted"):
            auth = hosted_auth(auth)
        if owned:
            if selected_metadata.KIND in wanted and selected_metadata.enabled(options, scopes):
                with log_samples.private_native_logs():
                    api = _new_api(auth)
            else:
                api = _new_api(auth)
        if selected_metadata.KIND in wanted and selected_metadata.enabled(options, scopes):
            selected_metadata.assert_private_transport(api)
        from .k8s_response_cache import install as install_response_cache
        install_response_cache(api)  # This scan only; discarded in the finally block below.
        cluster = _cluster_id(api, auth)
        annotation_context = annotation_indicators.collection_context(api, cluster)
        from peaso.ai.access import k8s as capture_ai_access
        if not ((literals.KIND in wanted and literals.enabled(options))
                or (log_samples.KIND in wanted and log_samples.enabled(options))
                or (selected_metadata.KIND in wanted and selected_metadata.enabled(options, scopes))
                or ((selected_text.KIND in wanted and selected_text.enabled(options)) or (flux_artifacts.KIND in wanted and flux_artifacts.enabled(options, options.get("_flux_artifact_named_checks", []))))
                or bool(wanted & {registry_images.SECRET_KIND, registry_images.VULN_KIND})):
            capture_ai_access(getattr(getattr(api, "api_client", None), "configuration", None),
                              cluster_id=cluster, namespaces=scopes)
        jobs = []
        if kubelet_configmaps.KIND in actual:
            for scope in scopes:
                path = "/api/v1/" + ("" if scope == "*" else "namespaces/" + quote(scope, safe="") + "/") + "configmaps"
                jobs.append((kubelet_configmaps.KIND, scope, "kubernetes", lambda path=path, scope=scope:
                    kubelet_configmaps.pages(reader, api, path, kubelet_configmaps.KIND, cluster,
                        scope, True, annotation_context, _native)))
        coverage_input = options.get("metadata_evidence_coverage")
        component_manifest = (isinstance(coverage_input, dict) and "component_configuration" in coverage_input
                              and "component_configuration" in wanted)
        file_manifest = (isinstance(coverage_input, dict) and "file_metadata" in coverage_input
                         and "file_metadata" in wanted)
        proxy_manifest = (isinstance(coverage_input, dict) and "kube_proxy_pod" in coverage_input
                          and "pod" in wanted)
        actual |= {"pod", "node"} if "network_interface" in wanted else set()
        if "node_clock" in wanted:
            actual |= {"node", "namespace"}
        if "admission_configuration_file" in wanted:
            actual.add("pod")
        if component_manifest or file_manifest or proxy_manifest:
            actual.add("node")  # one paged LIST shared by all requested metadata attestations
        discover_psp = legacy_psp_requested or ("podsecuritypolicy" in actual and "podsecuritypolicy" not in options.get("metadata_evidence", {}))
        for imported_kind in sorted(actual.intersection({"component_configuration", "file_metadata", "secret_metadata", "configmap_metadata", "podsecuritypolicy"})):
            if imported_kind == "podsecuritypolicy" and discover_psp:
                continue
            if imported_kind in ("secret_metadata", "configmap_metadata") and imported_kind not in options.get("metadata_evidence", {}):
                plural = "secrets" if imported_kind == "secret_metadata" else "configmaps"
                for scope in scopes:
                    path = "/api/v1/" + plural if scope == "*" else f"/api/v1/namespaces/{quote(scope, safe='')}/{plural}"
                    jobs.append((imported_kind, scope, "kubernetes", lambda path=path, scope=scope, imported_kind=imported_kind:
                        _metadata_pages(reader, api, path, imported_kind, cluster, scope, True, include_type=imported_kind == "secret_metadata")))
                continue
            def supplied(imported_kind=imported_kind):
                entries = options.get("metadata_evidence", {}).get(imported_kind)
                if entries is None:
                    raise K8sReadError("manual_metadata_source_required")
                if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
                    raise ValueError("metadata evidence must be an object list")
                output = []
                seen_ids = set()
                for index, entry in enumerate(entries):
                    if any(field in entry for field in ("data", "stringData", "contents", "private_key", "token", "password")):
                        raise ValueError("metadata evidence cannot contain values or host file contents")
                    if imported_kind == "file_metadata":
                        item = {key: entry[key] for key in ("path", "uid", "gid", "mode", "node", "platform",
                                                             "node_name", "node_uid", "observed_at", "symlink_status", "_coverage") if key in entry}
                        # Retain legacy string-mode and incomplete owner rows for
                        # existing checks. The attested family validates typed
                        # fields separately and stays UNKNOWN on malformed rows.
                        for field in ("node_name", "node_uid", "observed_at"):
                            value = item.get(field)
                            if field in item and (not isinstance(value, str) or not value or len(value) > 253):
                                del item[field]
                                item.setdefault("_coverage", {})[field] = {"status": "malformed"}
                        if "symlink_status" in item and item["symlink_status"] not in ("not_symlink", "symlink", "unknown"):
                            del item["symlink_status"]
                            item.setdefault("_coverage", {})["symlink_status"] = {"status": "malformed"}
                    elif imported_kind in ("secret_metadata", "configmap_metadata"):
                        item = {"metadata": _sanitize(entry.get("metadata", {}))}
                        # Secret type is metadata (the live path reads it from the Table view); never values.
                        if imported_kind == "secret_metadata" and isinstance(entry.get("type"), str) and len(entry["type"]) <= 253:
                            item["type"] = entry["type"]
                    elif imported_kind == "component_configuration":
                        if entry.get("component") not in COMPONENTS:
                            raise ValueError("component metadata subject unsupported")
                        item = {"component": entry["component"], "configuration": _configuration_metadata(entry.get("configuration", {}), entry["component"])}
                        for field in ("node_name", "node_uid", "observed_at"):
                            if field in entry:
                                value = entry[field]
                                if not isinstance(value, str) or not value or len(value) > 253:
                                    raise ValueError("component evidence identity or timestamp malformed")
                                item[field] = value
                    else:
                        item = _sanitize(entry)
                    supplied_id = f"k8s://{quote(cluster, safe='')}/{imported_kind}/supplied-{index}"
                    if (imported_kind == "file_metadata" and isinstance(item.get("node_uid"), str)
                            and item["node_uid"] and _file_path(item.get("path"))):
                        supplied_id = (f"k8s://{quote(cluster, safe='')}/file_metadata/node/"
                                       f"{quote(item['node_uid'], safe='')}/{quote(item['path'], safe='')}")
                        if supplied_id in seen_ids:
                            supplied_id += f"/duplicate-{index}"
                    if imported_kind == "component_configuration" and item.get("node_name") and item.get("node_uid"):
                        # The declared node identity is syntactically validated above;
                        # whole-cluster/current-node validation remains separate.
                        supplied_id = (f"k8s://{quote(cluster, safe='')}/component_configuration/"
                                       f"{quote(item['component'], safe='')}/node/{quote(item['node_uid'], safe='')}")
                        if supplied_id in seen_ids:
                            supplied_id += f"/duplicate-{index}"
                    item["id"] = supplied_id
                    seen_ids.add(supplied_id)
                    item["provenance"] = {"cluster_id": cluster, "source": "operator-supplied metadata", "runtime_verified": False,
                        "namespace": item.get("metadata", {}).get("namespace", "_cluster")}
                    output.append(item)
                yield output
            jobs.append((imported_kind, scopes[0], "kubernetes", supplied))
        if actual.intersection({"api_discovery", "securitycontextconstraint", "admission_policy", "configsync_rootsync", "configconnector", "configconnectorcontext", "kcc_iampolicy", "kcc_iampartialpolicy", "kcc_project", *CUSTOM_NETWORK_POLICY_GROUPS}) or discover_psp:
            def discovery():
                document = reader.call(api.get_json, "/apis")
                groups = document.get("groups") if isinstance(document, dict) else None
                if not isinstance(groups, list) or any(not isinstance(group, dict) or not isinstance(group.get("name"), str) for group in groups):
                    raise ValueError("malformed Kubernetes API group discovery")
                item = {"id": f"k8s://{quote(cluster, safe='')}/api-discovery", "groups": _sanitize(groups),
                    "provenance": {"cluster_id": cluster, "source": "GET /apis", "authoritative_for": "advertised API groups only"}}
                # Kyverno / Gatekeeper CRD presence from served API groups; presence is not enforcement evidence.
                item["policy_engines"] = _policy_engines({group["name"] for group in groups})
                if actual.intersection({"configconnector", "configconnectorcontext", "kcc_iampolicy", "kcc_iampartialpolicy"}):
                    kcc_group = next((group for group in groups if group["name"] == "iam.cnrm.cloud.google.com"), None)
                    served = any(isinstance(version, dict) and version.get("groupVersion") ==
                                 "iam.cnrm.cloud.google.com/v1beta1"
                                 for version in (kcc_group or {}).get("versions", []))
                    if served:
                        try:
                            iam_api = reader.call(api.get_json, "/apis/iam.cnrm.cloud.google.com/v1beta1")
                            resources = iam_api.get("resources") if isinstance(iam_api, dict) else None
                            if not isinstance(resources, list) or any(not isinstance(resource, dict)
                                    or not isinstance(resource.get("name"), str) for resource in resources):
                                raise ValueError("malformed Config Connector IAM API discovery")
                            for field, name in (("kccIAMPolicyMemberAdvertised", "iampolicymembers"),
                                                ("kccIAMPolicyAdvertised", "iampolicies"),
                                                ("kccIAMPartialPolicyAdvertised", "iampartialpolicies"),
                                                ("kccIAMServiceAccountKeyAdvertised", "iamserviceaccountkeys")):
                                item[field] = any(resource.get("name") == name and resource.get("namespaced") is True
                                                  for resource in resources)
                        except Exception as exc:
                            status, error = _safe_error(exc)
                            item.setdefault("_coverage", {})["kccIAMPolicyMemberAdvertised"] = {
                                "status": status, "error": error, "reason": "Config Connector IAM resource discovery unavailable"}
                    else:
                        item["kccIAMPolicyMemberAdvertised"] = False
                        item["kccIAMPolicyAdvertised"] = False
                        item["kccIAMPartialPolicyAdvertised"] = False
                        item["kccIAMServiceAccountKeyAdvertised"] = False
                if "kcc_project" in actual:
                    project_group = next((group for group in groups
                                          if group["name"] == "resourcemanager.cnrm.cloud.google.com"), None)
                    project_served = any(isinstance(version, dict) and version.get("groupVersion") ==
                                         "resourcemanager.cnrm.cloud.google.com/v1beta1"
                                         for version in (project_group or {}).get("versions", []))
                    if project_served:
                        try:
                            project_api = reader.call(
                                api.get_json, "/apis/resourcemanager.cnrm.cloud.google.com/v1beta1")
                            resources = project_api.get("resources") if isinstance(project_api, dict) else None
                            if not isinstance(resources, list) or any(not isinstance(resource, dict)
                                    or not isinstance(resource.get("name"), str) for resource in resources):
                                raise ValueError("malformed Config Connector Project API discovery")
                            item["kccProjectAdvertised"] = any(
                                resource.get("name") == "projects" and resource.get("namespaced") is True
                                for resource in resources)
                        except Exception as exc:
                            status, error = _safe_error(exc)
                            item.setdefault("_coverage", {})["kccProjectAdvertised"] = {
                                "status": status, "error": error,
                                "reason": "Config Connector Project resource discovery unavailable"}
                    else:
                        item["kccProjectAdvertised"] = False
                if discover_psp:
                    try:
                        version = reader.call(api.get_json, "/version")
                        if not isinstance(version, dict) or legacy_psp.parse_version(version.get("gitVersion")) is None:
                            raise ValueError("malformed Kubernetes server version")
                        item["serverVersion"] = {"gitVersion": version["gitVersion"]}
                    except Exception as exc:
                        status, error = _safe_error(exc)
                        item.setdefault("_coverage", {})["serverVersion"] = {"status": status, "error": error, "reason": "Server version read unavailable"}
                    advertised = any(version.get("groupVersion") == "policy/v1beta1" for group in groups if group["name"] == "policy" for version in group.get("versions", []) if isinstance(version, dict))
                    if advertised:
                        try:
                            document = reader.call(api.get_json, "/apis/policy/v1beta1")
                            resources = document.get("resources") if isinstance(document, dict) else None
                            if not isinstance(resources, list) or any(not isinstance(resource, dict) for resource in resources):
                                raise ValueError("malformed policy API resource discovery")
                            item["podSecurityPolicyAdvertised"] = any(resource.get("name") == "podsecuritypolicies" for resource in resources)
                        except Exception as exc:
                            status, error = _safe_error(exc)
                            item.setdefault("_coverage", {})["podSecurityPolicyAdvertised"] = {"status": status, "error": error, "reason": "Policy API resource discovery unavailable"}
                    else:
                        item["podSecurityPolicyAdvertised"] = False
                    item["provenance"]["authoritative_for"] = "Advertised API groups, optional policy resources and captured server version; not secure admission enforcement"
                yield [item]
            reader.run([("api_discovery", scopes[0], "kubernetes", discovery)])
            discovered = reader.collections[-1]
            if "api_discovery" in actual:
                from .batch_remaining_k8s import attach_server_version
                attach_server_version(reader, api, discovered, _safe_error)
            actual.update(legacy_psp.legacy_support(discovered, legacy_psp_requested))
            groups = {group["name"] for item in discovered["items"] for group in item["groups"]}
            for kind in sorted(actual.intersection(CUSTOM_NETWORK_POLICY_GROUPS)):
                group_name, version = CUSTOM_NETWORK_POLICY_GROUPS[kind]
                base_path, namespaced = ENDPOINTS[kind]
                group_versions = {str(v.get("version") or "") for item in discovered["items"]
                    for group in item["groups"] if group["name"] == group_name
                    for v in group.get("versions", []) if isinstance(v, dict)}
                for scope in scopes if namespaced else scopes[:1]:
                    if discovered["status"] not in ("collected", "empty"):
                        reader.unavailable(kind, scope, "kubernetes", K8sReadError("api_discovery_incomplete"))
                    elif group_name not in groups:
                        reader.collections.append({"type": kind, "scope": scope, "service": "kubernetes", "status": "empty",
                            "items": [], "applicability": {"observed_api_group_absent": group_name, "source": "GET /apis"}})
                    elif version not in group_versions:
                        reader.unavailable(kind, scope, "kubernetes", K8sReadError("network_policy_api_version_unavailable"))
                    else:
                        path = base_path
                        if namespaced and scope != "*":
                            prefix, plural = base_path.rsplit("/", 1)
                            path = prefix + "/namespaces/" + quote(scope, safe="") + "/" + plural
                        jobs.append((kind, scope, "kubernetes", lambda path=path, kind=kind, scope=scope, namespaced=namespaced:
                            _pages(reader, api, path, kind, cluster, scope, namespaced)))
            if discover_psp:
                item = discovered["items"][0] if discovered["items"] else {}
                version = item.get("serverVersion", {}).get("gitVersion", "")
                match = re.match(r"^v?([0-9]+)\.([0-9]+)", version)
                modern = bool(match and tuple(map(int, match.groups())) >= (1, 25))
                if discovered["status"] not in ("collected", "empty") or "podSecurityPolicyAdvertised" in item.get("_coverage", {}):
                    reader.unavailable("podsecuritypolicy", scopes[0], "kubernetes", K8sReadError("api_discovery_incomplete"))
                elif modern and item.get("podSecurityPolicyAdvertised") is False:
                    reader.collections.append({"type": "podsecuritypolicy", "scope": scopes[0], "service": "kubernetes",
                        "status": "not_collected", "coverage_status": "not_applicable", "items": [],
                        "error": {"kind": "not_applicable", "code": "pod_security_policy_api_absent"},
                        "applicability": {"kubernetes_version": version, "observed_resource_absent": "policy/v1beta1/podsecuritypolicies",
                            "source": "GET /apis and GET /version", "guidance": "Review Pod Security Admission/SCC metadata separately; API absence is not evidence of secure admission"}})
                elif match is not None and not modern and item.get("podSecurityPolicyAdvertised") is True:
                    def psp_pages(version=version):
                        for page in annotation_indicators.pages(reader, api, "/apis/policy/v1beta1/podsecuritypolicies", "podsecuritypolicy", cluster, scopes[0], False, annotation_context, _pages):
                            for policy in page:
                                if version:
                                    policy["_provenance"] = {"kubernetes_version": version}
                            yield page
                    jobs.append(("podsecuritypolicy", scopes[0], "kubernetes", psp_pages))
                else:
                    reader.unavailable("podsecuritypolicy", scopes[0], "kubernetes", K8sReadError("psp_version_or_advertisement_unavailable"))
            if "securitycontextconstraint" in actual:
                if discovered["status"] not in ("collected", "empty"):
                    reader.collections.append({"type": "securitycontextconstraint", "scope": scopes[0], "service": "kubernetes",
                        "status": "unknown", "items": [], "error": {"code": "api_discovery_incomplete"}})
                elif "security.openshift.io" not in groups:
                    reader.collections.append({"type": "securitycontextconstraint", "scope": scopes[0], "service": "kubernetes",
                        "status": "not_collected", "coverage_status": "not_applicable", "items": [],
                        "error": {"kind": "not_applicable", "code": "openshift_api_group_absent"},
                        "applicability": {"observed_api_group_absent": "security.openshift.io", "source": "GET /apis"}})
                else:
                    jobs.append(("securitycontextconstraint", scopes[0], "kubernetes", lambda: _pages(reader, api,
                        "/apis/security.openshift.io/v1/securitycontextconstraints", "securitycontextconstraint", cluster, scopes[0], False)))
            if "admission_policy" in actual:
                if discovered["status"] not in ("collected", "empty"):
                    reader.collections.append({"type": "admission_policy", "scope": scopes[0], "service": "kubernetes",
                        "status": "unknown", "items": [], "error": {"code": "api_discovery_incomplete"}})
                else:
                    try:
                        advertised = _admission_policy_resources(reader, api, [g for item in discovered["items"] for g in item["groups"]])
                    except Exception as exc:
                        reader.unavailable("admission_policy", scopes[0], "kubernetes", exc)
                    else:
                        for discovery_item in discovered["items"]:
                            discovery_item["admissionPolicyResources"] = sorted(advertised)
                        if not advertised:
                            reader.collections.append({"type": "admission_policy", "scope": scopes[0], "service": "kubernetes",
                                "status": "not_collected", "coverage_status": "not_applicable", "items": [],
                                "error": {"kind": "not_applicable", "code": "admission_policy_api_absent"},
                                "applicability": {"observed_resource_absent": ADMISSION_POLICY_GROUP + "/validatingadmissionpolicies",
                                                  "source": "GET /apis and API resource discovery"}})
                        else:
                            jobs.append(("admission_policy", scopes[0], "kubernetes", lambda advertised=advertised:
                                _admission_policy_pages(reader, api, cluster, scopes[0], advertised)))
        for kind in sorted(actual.intersection(ENDPOINTS) - CUSTOM_NETWORK_POLICY_GROUPS.keys()):
            path, namespaced = ENDPOINTS[kind]
            if kind in ("configsync_rootsync", "configconnector", "configconnectorcontext", "kcc_iampolicy", "kcc_iampartialpolicy", "kcc_project"):
                discovery = next((row for row in reader.collections if row["type"] == "api_discovery"), None)
                core = kind in ("configconnector", "configconnectorcontext")
                group_name = ("configsync.gke.io" if kind == "configsync_rootsync" else
                              "core.cnrm.cloud.google.com" if core else
                              "resourcemanager.cnrm.cloud.google.com" if kind == "kcc_project" else
                              "iam.cnrm.cloud.google.com")
                group_version = group_name + "/v1beta1"
                group_served = bool(discovery and discovery["status"] in ("collected", "empty") and
                    any(group.get("name") == group_name and any(isinstance(version, dict) and
                        version.get("groupVersion") == group_version for version in group.get("versions", []))
                        for item in discovery["items"] for group in item.get("groups", [])))
                resource_field = {"kcc_iampolicy": "kccIAMPolicyAdvertised",
                                  "kcc_iampartialpolicy": "kccIAMPartialPolicyAdvertised",
                                  "kcc_project": "kccProjectAdvertised"}.get(kind)
                resource_values = [item.get(resource_field) for item in discovery["items"]] if (
                    resource_field and group_served) else []
                for scope in scopes if namespaced else [scopes[0]]:
                    if discovery is None or discovery["status"] not in ("collected", "empty"):
                        reader.unavailable(kind, scope, "kubernetes", K8sReadError("api_discovery_incomplete"))
                    elif not group_served or resource_field and resource_values == [False]:
                        reader.collections.append({"type": kind, "scope": scope, "service": "kubernetes",
                            "status": "empty", "items": [],
                            "applicability": {"observed_api_version_absent": group_version if not group_served else
                                              group_version + "/" + path.rsplit("/", 1)[-1],
                                              "source": "GET /apis"}})
                    elif resource_field and resource_values != [True]:
                        reader.unavailable(kind, scope, "kubernetes", K8sReadError("kcc_resource_discovery_incomplete"))
                if (not group_served or resource_field and resource_values != [True]):
                    continue
            if kind == "namespace" and scopes != ["*"]:
                for scope in scopes:
                    def namespace(scope=scope):
                        item = reader.call(api.get_json, "/api/v1/namespaces/" + quote(scope, safe=""))
                        if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict) or item["metadata"].get("name") != scope:
                            raise ValueError("namespace object does not match selected scope")
                        yield [_native(item, "namespace", cluster, scope, False)]
                    jobs.append((kind, scope, "kubernetes", namespace))
                continue
            for scope in scopes if namespaced else [scopes[0]]:
                scoped_path = path
                if namespaced and scope != "*":
                    prefix, plural = path.rsplit("/", 1)
                    scoped_path = prefix + "/namespaces/" + quote(scope, safe="") + "/" + plural
                jobs.append((kind, scope, "kubernetes", lambda path=scoped_path, kind=kind, scope=scope, namespaced=namespaced:
                    annotation_indicators.pages(reader, api, path, kind, cluster, scope, namespaced, annotation_context, _pages)
                    if kind == "ingress" else _pages(reader, api, path, kind, cluster, scope, namespaced)))
        if "admission_configuration" in wanted:
            def admission():
                for plural, kind, object_kind in (("validatingwebhookconfigurations", "validatingwebhookconfiguration", "ValidatingWebhookConfiguration"),
                                                  ("mutatingwebhookconfigurations", "mutatingwebhookconfiguration", "MutatingWebhookConfiguration")):
                    for page in _pages(reader, api, "/apis/admissionregistration.k8s.io/v1/" + plural, kind, cluster, scopes[0], False):
                        for item in page:
                            item.setdefault("kind", object_kind)  # list items carry no Kind; failurePolicy/rules stay native
                        yield page
            jobs.append(("admission_configuration", scopes[0], "kubernetes", admission))
        reader.progress("collecting")
        reader.run(jobs)
        if legacy_psp_requested:
            legacy_psp.copy_cluster_envelopes(reader, scopes)
        if "admission_policy" in actual and len(scopes) > 1:
            source = next((row for row in reader.collections if row["type"] == "admission_policy" and row["scope"] == scopes[0]), None)
            if source is not None:
                for scope in scopes[1:]:
                    copied = copy.deepcopy(source)
                    copied["scope"] = scope
                    for item in copied["items"]:
                        item["provenance"]["scope"] = scope
                    capacity = len(copied["items"]) if reader.budget.max_items is None else max(0, reader.budget.max_items - reader.total)
                    if len(copied["items"]) > capacity:
                        copied["items"] = copied["items"][:capacity]
                        copied.update(status="partial", error={"kind": "K8sReadError", "code": "resource_limit"})
                    reader.total += len(copied["items"])
                    reader.collections.append(copied)
                    reader.progress(scope=scope, settled=copied, _kept=True)
        if "admission_configuration_file" in wanted:
            from .k8s_admission_file import pages as admission_file_pages
            for scope in scopes:
                source = next((row for row in reader.collections if row["type"] == "pod" and row["scope"] == scope),
                              {"status": "unavailable"})
                reader.run([("admission_configuration_file", scope, "kubernetes",
                    lambda source=source: admission_file_pages(reader, api, source, cluster))])
        if "network_interface" in wanted:
            for scope in scopes:
                interfaces = []
                source_statuses = []
                for collection in reader.collections:
                    if collection["type"] not in ("pod", "node") or collection["scope"] != scope:
                        continue
                    source_statuses.append(collection["status"])
                    for item in collection["items"]:
                        status = item.get("status") or {}
                        addresses = status.get("podIPs", []) if collection["type"] == "pod" else status.get("addresses", [])
                        if addresses:
                            interfaces.append({"id": item["id"] + "/observed-addresses", "resource_id": item["id"], "addresses": copy.deepcopy(addresses),
                                               "nodeName": (item.get("spec") or {}).get("nodeName"),
                                               "provenance": {"cluster_id": cluster, "source": "object.status", "authoritative_interface_inventory": False}})
                complete = source_statuses and all(s in ("collected", "empty") for s in source_statuses)
                reader.run([("network_interface", scope, "kubernetes", lambda interfaces=interfaces: iter([interfaces]))])
                if not complete:
                    reader.collections[-1].update(status="partial", error={"code": "source_inventory_incomplete"})
                from peaso.collection_events import emit_collection
                emit_collection(reader.collection_callback, reader.collections[-1])
        # Optional content/images run after native inventory and network batches
        # have become durable; their latency never hides completed core data.
        if literals.KIND in wanted:
            literal_options = options
            if auto_workload_literals:
                from . import workload_environment_discovery as environment_discovery
                literal_plan = environment_discovery.k8s_workloads(reader.collections, cluster, expected_scopes=scopes)
                reader.automatic_literal_coverage = {'discovered': literal_plan.discovered,
                    'planned': len(literal_plan.targets), 'complete': literal_plan.complete,
                    'reason': literal_plan.reason}
                reader.automatic_literal_batches = []
            if auto_workload_literals and literal_plan.targets:
                all_matches = set()
                for batch in environment_discovery.batches(literal_plan.targets, 1):
                    literal_options = {**options, literals.OPTION: list(batch)}
                    scope = batch[0]['namespace'] if batch[0]['namespace'] in scopes else '*'
                    if private_content:
                        with log_samples.private_native_logs():
                            literal_metadata, matches = literals.collect(reader, api, literal_options, [scope], cluster)
                    else:
                        literal_metadata, matches = literals.collect(reader, api, literal_options, [scope], cluster)
                    all_matches.update(matches)
                    batch_id = literals.KIND + ':' + str(len(reader.automatic_literal_batches) + 1)
                    reader.collections[-1]['automatic_batch'] = batch_id
                    reader.automatic_literal_batches.append({'id': batch_id, 'scope': scope,
                        'metadata': literal_metadata,
                        'issues': environment_discovery.native_denial_issues(
                            literals.KIND, literals.MARKER, reader.collections[-1]['items'],
                            literal_metadata)})
                literal_matches = all_matches
                environment_discovery.fold_collections(reader.collections,
                    literals.KIND, reader.automatic_literal_batches)
            elif not auto_workload_literals:
                if private_content:
                    with log_samples.private_native_logs():
                        literal_metadata, literal_matches = literals.collect(reader, api, literal_options, scopes, cluster)
                else:
                    literal_metadata, literal_matches = literals.collect(reader, api, literal_options, scopes, cluster)
            elif auto_workload_literals:
                literal_metadata = {literals.KIND + '_authorized': True,
                    literals.KIND + '_selection': {scope: [] for scope in scopes}}
                for scope in scopes:
                    reader.collections.append({'type': literals.KIND, 'scope': scope, 'service': 'kubernetes',
                        'status': 'empty' if literal_plan.complete else 'unknown', 'items': [],
                        **({} if literal_plan.complete else {'error': {'code': literal_plan.reason}})})
            if auto_workload_literals:
                literal_content_complete = all(
                    row['status'] in ('collected', 'empty') and
                    all(item.get(literals.MARKER, {}).get('complete') is True for item in row['items'])
                    for row in reader.collections if row['type'] == literals.KIND)
                reader.automatic_literal_coverage.update(
                    inspected=sum(len(row['items']) for row in reader.collections if row['type'] == literals.KIND),
                    targets=environment_discovery.target_coverage(literal_plan.targets,
                        literals.identity, reader.collections, literals.KIND, literals.MARKER,
                        {ident: issue for batch in reader.automatic_literal_batches
                         for ident, issue in batch['issues'].items()}),
                    complete=literal_plan.complete and literal_content_complete,
                    reason=literal_plan.reason if not literal_plan.complete else
                           'automatic_content_incomplete' if not literal_content_complete else 'complete')
        if selected_metadata.KIND in wanted:
            selected_metadata_facts, selected_metadata_matches = selected_metadata.collect(
                reader, api, options, scopes, cluster)
        if selected_text.KIND in wanted:
            text_facts, text_matches = selected_text.collect(reader, api, options, scopes, cluster)
        if flux_artifacts.KIND in wanted:
            flux_facts, flux_matches = flux_artifacts.collect(reader, api, options, scopes, cluster)
        if wanted & {registry_images.SECRET_KIND, registry_images.VULN_KIND}:
            registry_facts, registry_matches = registry_images.collect(reader, api, options, scopes, cluster, auth)
        if log_samples.KIND in wanted:
            selected_logs = [target for target in log_targets if target['namespace'] in scopes]
            if selected_logs:
                log_options = {**options, log_samples.OPTION: selected_logs}
                log_metadata, log_matches = log_samples.collect(reader, api, log_options, scopes, cluster)
    except Exception as exc:
        existing = {(c["type"], c["scope"]) for c in reader.collections}
        for scope in scopes:
            for kind in sorted(wanted):
                if (kind, scope) not in existing:
                    reader.unavailable(kind, scope, "kubernetes", exc)
    finally:
        full_gc_hold.close()
        if ((literals.KIND in wanted and literals.enabled(options))
                or (log_samples.KIND in wanted and log_samples.enabled(options))
                or (selected_metadata.KIND in wanted and selected_metadata.enabled(options, scopes))
                or ((selected_text.KIND in wanted and selected_text.enabled(options)) or (flux_artifacts.KIND in wanted and flux_artifacts.enabled(options, options.get("_flux_artifact_named_checks", []))))
                or bool(wanted & {registry_images.SECRET_KIND, registry_images.VULN_KIND})):
            # Metadata jobs use the SDK too; do not retain their raw identity
            # fields in its response cache after union redaction is available.
            literal_client = getattr(getattr(api, "api", api), "api_client", None)
            if literal_client is not None:
                literal_client.last_response = None
        if api is not None:
            from .k8s_response_cache import uninstall as uninstall_response_cache
            reader.response_cache_stats = uninstall_response_cache(api)
        if owned and api is not None:
            if selected_metadata.KIND in wanted and selected_metadata.enabled(options, scopes):
                with log_samples.private_native_logs():
                    api.close()
            else:
                api.close()
    for scope in requested_scopes[len(scopes):]:
        for kind in sorted(wanted):
            reader.unavailable(kind, scope, "kubernetes", K8sReadError("scope_limit"))
    captured_at = datetime.now(timezone.utc).isoformat()
    clock_review = None
    if "node_clock" in wanted:
        clock_collection, clock_review = clock_evidence.collect(
            imported_clock, reader.collections, requested_scopes, cluster, captured_at)
        if reader.budget.max_items is not None and reader.total + len(clock_collection["items"]) > reader.budget.max_items:
            clock_collection.update(status="partial", items=[], error={"code": "resource_limit"})
            clock_review = None
        reader.collections.append(clock_collection)
        reader.total += len(clock_collection["items"])
    metadata = reader.metadata()
    if annotation_context is not None:
        metadata[annotation_indicators.CONTEXT] = annotation_context
    metadata.update(cluster_id=cluster, cluster_id_source="explicit" if auth.get("cluster_id") else "API origin digest",
                    trusted_scope_ids=trusted_scopes,
                    context=auth.get("context"), namespace_semantics="administrative scope; not a subnet",
                    network_policy_enforcement={"status": "unknown", "reason": "CNI implementation and runtime enforcement are not verified by Kubernetes policy objects"},
                    network_interfaces={"status": "observed_addresses_only", "authoritative": False},
                    usage_evidence={"status": "unknown", "reason": "No audit logs, pod logs, exec or Secret objects read"},
                    omitted_inventories=sorted(set(TYPES) - actual))
    metadata["compliance_policy"] = _owner_policy_metadata(options, cluster, captured_at)
    if clock_review is not None:
        metadata["external_node_clock_review"] = clock_review
    if "pod" in wanted:
        metadata["kube_proxy_pod_coverage"] = _kube_proxy_pod_coverage(
            options, cluster, reader.collections, captured_at)
    if "component_configuration" in wanted:
        metadata["component_configuration_coverage"] = _component_configuration_coverage(
            options, cluster, reader.collections, captured_at)
    if "file_metadata" in wanted:
        metadata["file_metadata_coverage"] = _file_metadata_coverage(
            options, cluster, reader.collections, captured_at)
    metadata.update(literal_metadata)
    if auto_workload_literals:
        metadata['automatic_workload_environment_coverage'] = {literals.KIND: reader.automatic_literal_coverage}
        metadata['automatic_workload_environment_batches'] = {literals.KIND: reader.automatic_literal_batches}
    metadata.update(log_metadata)
    metadata.update(selected_metadata_facts)
    metadata.update(text_facts)
    metadata.update(flux_facts)
    metadata.update(registry_facts)
    if log_samples.KIND in wanted and log_samples.enabled(options):
        metadata['usage_evidence'] = {'status': 'selected_current_container_samples_only',
            'reason': 'Only explicitly selected current-container samples were requested; other logs, exec and Secrets were not read'}
    from .k8s_scan_gc import paused as full_gc_paused
    with full_gc_paused():
        if any((log_matches, literal_matches, selected_metadata_matches, text_matches, registry_matches, flux_matches)):
            # With no detected value the union scrub is an exact copy; skip the full walk.
            requested_scopes, reader.collections, metadata = selected_metadata.finalize(
                requested_scopes, reader.collections, metadata, log_matches, literal_matches, selected_metadata_matches, text_matches, registry_matches, flux_matches)
        snapshot = make_snapshot("k8s", requested_scopes, reader.collections, created_at=captured_at, metadata=metadata)
    reader.progress("completed", complete=True)
    return snapshot
