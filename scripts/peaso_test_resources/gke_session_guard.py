"""Dispatch-specific disposable GKE fixture with a durable exact-resource ledger.

Run plan first, notify the coordinator, then run. A detached watchdog executes
the same ownership-checked cleanup if the runner fails to finish by its deadline.
This helper is deliberately pinned to this dispatch's authorized project/account.
"""
from __future__ import annotations

from peaso import deployment
import argparse
import copy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import urlsplit

ACCOUNT = deployment.value("test_gcp_account")
PROJECT = deployment.value("test_gcp_project")
NUMBER = "882210141464"
TASK = "task_5e05a82b0109"
DISPATCH = "ctx_d12c7cfe9bea"
ZONE = "us-central1-a"
REGION = "us-central1"
NODE_ROLE = "roles/container.defaultNodeServiceAccount"
CATEGORIES = ["hardening", "exposure", "least_privilege", "iam_graph", "network"]


class SessionError(Exception):
    pass


def private_write(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".evidence-", dir=Path(path).parent)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(json.dumps(value, indent=2) if not isinstance(value, str) else value)
    os.replace(temporary, path)


def plan(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    ledger = directory / "gke-ledger.json"
    if ledger.exists():
        raise SessionError("ledger_already_exists")
    owner = uuid.uuid4().hex[:12]
    name = "peaso-qa-" + owner
    value = {"schema_version": 1, "task_id": TASK, "dispatch_id": DISPATCH,
             "account": ACCOUNT, "project": PROJECT, "project_number": NUMBER,
             "zone": ZONE, "owner": owner, "cluster": name, "namespace": name,
             "created_at": datetime.now(timezone.utc).isoformat(),
             "cleanup_deadline": (datetime.now(timezone.utc) + timedelta(minutes=35)).isoformat(),
             "resources": [
                 {"kind": "service_account", "name": name + "-node", "email": name + "-node@" + PROJECT + ".iam.gserviceaccount.com", "status": "planned"},
                 {"kind": "service_account", "name": name + "-work", "email": name + "-work@" + PROJECT + ".iam.gserviceaccount.com", "status": "planned"},
                 {"kind": "network", "name": name, "status": "planned"},
                 {"kind": "subnetwork", "name": name, "region": REGION, "status": "planned"},
                 {"kind": "cluster", "name": name, "zone": ZONE, "status": "planned"}],
             "iam_additions": [], "workloads": [], "phase": "planned"}
    private_write(ledger, value)
    return value


class Session:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.ledger = self.directory / "gke-ledger.json"
        self.data = json.loads(self.ledger.read_text())
        if any(self.data.get(k) != v for k, v in [("task_id", TASK), ("dispatch_id", DISPATCH), ("account", ACCOUNT),
                                                 ("project", PROJECT), ("project_number", NUMBER), ("zone", ZONE)]):
            raise SessionError("ledger_identity_mismatch")
        name = "peaso-qa-" + self.data["owner"]
        if self.data["cluster"] != name or self.data["namespace"] != name:
            raise SessionError("ledger_name_mismatch")
        expected = {( "service_account", name + "-node"), ("service_account", name + "-work"), ("network", name), ("subnetwork", name), ("cluster", name)}
        if {(x["kind"], x["name"]) for x in self.data["resources"]} != expected:
            raise SessionError("ledger_resources_mismatch")
        for row in self.data["resources"]:
            if row["kind"] == "service_account" and row.get("email") != row["name"] + "@" + PROJECT + ".iam.gserviceaccount.com":
                raise SessionError("ledger_service_account_mismatch")
        self.env = dict(os.environ, CLOUDSDK_CORE_ACCOUNT=ACCOUNT, CLOUDSDK_CORE_PROJECT=PROJECT,
                        CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT="", CLOUDSDK_CORE_DISABLE_PROMPTS="1",
                        KUBECONFIG=str(self.directory / "kubeconfig"))
        self.kubeconfig = self.directory / "kubeconfig"
        self.credentials = None
        self.http = None

    def save(self):
        private_write(self.ledger, self.data)

    def cli(self, args, *, timeout=60, optional=False):
        result = subprocess.run(["gcloud", *args, "--project", PROJECT, "--account", ACCOUNT,
                                 "--format=json", "--quiet"], env=self.env, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            if optional and ("code=404" in result.stderr or "not_found" in result.stderr.lower() or "not found" in result.stderr.lower()):
                return None
            reason = next((name for name in ("PERMISSION_DENIED", "QUOTA_EXCEEDED", "SERVICE_DISABLED", "RESOURCE_EXHAUSTED", "INVALID_ARGUMENT")
                           if name in result.stderr), "cli_operation_failed")
            raise SessionError(reason + ":" + "_".join(args[:3]))
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def identity(self):
        project = self.api("GET", "cloudresourcemanager.googleapis.com/v3/projects/" + PROJECT)
        if self.credentials.gcloud.account != ACCOUNT or project.get("projectId") != PROJECT or project.get("name") != "projects/" + NUMBER or project.get("state") != "ACTIVE":
            raise SessionError("cloud_project_identity_mismatch")

    def service_account(self, email):
        # IAM get on a deleted address can return403 with "or it may not exist".
        # A successful fully-paginated project list proves absence;403 never does.
        listed = []
        page_token = None
        seen_tokens = set()
        while True:
            path = "iam.googleapis.com/v1/projects/" + PROJECT + "/serviceAccounts?pageSize=100"
            if page_token:
                from urllib.parse import quote
                path += "&pageToken=" + quote(page_token, safe="")
            page = self.api("GET", path)
            if not isinstance(page, dict) or not isinstance(page.get("accounts", []), list):
                raise SessionError("service_account_list_malformed")
            listed.extend(page.get("accounts", []))
            page_token = page.get("nextPageToken")
            if not page_token:
                break
            if page_token in seen_tokens:
                raise SessionError("service_account_list_repeated_token")
            seen_tokens.add(page_token)
        matching = [item for item in listed if item.get("email") == email and item.get("projectId") == PROJECT]
        if len(matching) > 1:
            raise SessionError("duplicate_service_account_identity")
        return matching[0] if matching else None

    def api(self, method, path, body=None, *, mutation=False):
        import requests
        from peaso.collectors.gcp import Credentials
        if self.credentials is None:
            self.credentials = Credentials({"method": "gcloud", "account": ACCOUNT, "impersonate_service_account": ""})
            self.http = requests.Session()
        if mutation:
            self.identity()
        headers = self.credentials.headers()
        response = self.http.request(method, "https://" + path, headers=headers, json=body, timeout=30, allow_redirects=False)
        if response.status_code == 404:
            return None
        if not response.ok:
            raise SessionError("api_status_" + str(response.status_code))
        return response.json()

    def project_policy(self):
        return self.api("POST", "cloudresourcemanager.googleapis.com/v3/projects/" + PROJECT + ":getIamPolicy",
                        {"options": {"requestedPolicyVersion": 3}})

    def membership(self, email, *, remove=False):
        member = "serviceAccount:" + email
        row = next((x for x in self.data["iam_additions"] if x["member"] == member), None)
        if remove and row is None:
            return
        policy = self.project_policy()
        if not policy.get("etag"):
            raise SessionError("policy_etag_missing")
        matching = [b for b in policy.get("bindings", []) if b.get("role") == NODE_ROLE and not b.get("condition")]
        present = any(member in b.get("members", []) for b in matching)
        if remove and not present:
            row.update(status="removed", verification="exact_membership_absent")
            self.save()
            return
        if not remove:
            if present:
                raise SessionError("preexisting_membership_not_owned")
            row = {"role": NODE_ROLE, "member": member, "etag_before_add": policy["etag"], "status": "planned"}
            self.data["iam_additions"].append(row)
            self.save()  # Ownership and exact membership BEFORE grant.
        edited = copy.deepcopy(policy)
        if remove:
            for binding in edited.get("bindings", []):
                if binding.get("role") == NODE_ROLE and not binding.get("condition"):
                    binding["members"] = [m for m in binding.get("members", []) if m != member]
            edited["bindings"] = [b for b in edited.get("bindings", []) if b.get("members")]
        else:
            binding = next((b for b in edited.get("bindings", []) if b.get("role") == NODE_ROLE and not b.get("condition")), None)
            if binding is None:
                binding = {"role": NODE_ROLE, "members": []}
                edited.setdefault("bindings", []).append(binding)
            binding["members"].append(member)
        result = self.api("POST", "cloudresourcemanager.googleapis.com/v3/projects/" + PROJECT + ":setIamPolicy", {"policy": edited}, mutation=True)
        row.update(status="removed" if remove else "added", etag_after_write=result.get("etag"))
        self.save()
        verification = self.project_policy()
        exists = any(member in b.get("members", []) for b in verification.get("bindings", []) if b.get("role") == NODE_ROLE and not b.get("condition"))
        if exists == remove:
            raise SessionError("membership_verification_failed")
        row["verification"] = "exact_membership_absent" if remove else "exact_membership_present"
        self.save()

    def cluster(self):
        return self.api("GET", "container.googleapis.com/v1/projects/" + PROJECT + "/locations/" + ZONE + "/clusters/" + self.data["cluster"])

    def validate_cluster(self, cluster):
        if cluster.get("name") != self.data["cluster"] or cluster.get("location") != ZONE or cluster.get("resourceLabels", {}).get("peaso-owner") != self.data["owner"]:
            raise SessionError("cluster_ownership_mismatch")

    def record_generated(self):
        entries = []
        for group in ["instances", "disks", "instance-templates", "firewall-rules", "routes", "instance-groups"]:
            items = self.cli(["compute", group, "list", "--filter", "name~^gke-" + self.data["cluster"] + "-"])
            for item in items:
                link = item.get("selfLink", "")
                if not item.get("name", "").startswith("gke-" + self.data["cluster"] + "-") or "/projects/" + PROJECT + "/" not in link:
                    raise SessionError("generated_resource_identity_mismatch")
                entries.append({"kind": group, "name": item["name"], "id": str(item.get("id", "")), "selfLink": link, "status": "created",
                                "ownership": "exact_unique_cluster_name_prefix_in_authorized_project"})
        self.data["generated_resources"] = entries
        self.save()

    def verify_generated_absent(self):
        for row in self.data.get("generated_resources", []):
            path = urlsplit(row["selfLink"]).path
            if not path.startswith("/compute/v1/projects/" + PROJECT + "/"):
                raise SessionError("generated_verification_scope_mismatch")
            item = self.api("GET", "compute.googleapis.com" + path)
            if item is not None:
                raise SessionError("generated_resource_cleanup_unverified:" + row["kind"])
            row.update(status="deleted", verification="exact_resource_get_404")
            self.save()

    def create(self):
        self.identity()
        services = self.cli(["services", "list", "--enabled"])
        enabled = {x.get("config", {}).get("name") for x in services}
        if not {"container.googleapis.com", "compute.googleapis.com", "iam.googleapis.com"}.issubset(enabled):
            raise SessionError("required_api_disabled_no_enablement")
        if self.cluster() is not None:
            raise SessionError("cluster_name_preexists")
        for row in self.data["resources"]:
            if row["kind"] != "service_account":
                continue
            if self.service_account(row["email"]) is not None:
                raise SessionError("service_account_name_preexists")
            self.data["phase"] = "creating_service_account"
            self.save()
            result = self.api("POST", "iam.googleapis.com/v1/projects/" + PROJECT + "/serviceAccounts",
                              {"accountId": row["name"], "serviceAccount": {"displayName": "peaso-owned-" + self.data["owner"],
                               "description": "Disposable acceptance " + TASK + " owner " + self.data["owner"]}}, mutation=True)
            row.update(status="created", unique_id=result.get("uniqueId"))
            self.save()
        node = self.data["resources"][0]
        self.membership(node["email"])
        for row in self.data["resources"]:
            if row["kind"] not in {"network", "subnetwork"}:
                continue
            group = "networks" if row["kind"] == "network" else "networks-subnets"
            describe = ["compute", "networks", "describe", row["name"]] if row["kind"] == "network" else ["compute", "networks", "subnets", "describe", row["name"], "--region", REGION]
            if self.cli(describe, optional=True) is not None:
                raise SessionError("network_prerequisite_name_preexists")
            self.identity()
            row["status"] = "creating"
            self.save()
            if row["kind"] == "network":
                result = self.cli(["compute", "networks", "create", row["name"], "--subnet-mode", "custom", "--description", "peaso-owned-" + self.data["owner"]])
            else:
                result = self.cli(["compute", "networks", "subnets", "create", row["name"], "--network", self.data["cluster"], "--region", REGION,
                                   "--range", "10.233.0.0/24", "--secondary-range", "qa-pods=10.234.0.0/20,qa-services=10.235.0.0/24",
                                   "--description", "peaso-owned-" + self.data["owner"]])
            actual = result[0] if isinstance(result, list) else result
            row.update(status="created", id=actual.get("id"), selfLink=actual.get("selfLink"))
            self.save()
        self.identity()
        self.data["phase"] = "creating_cluster"
        self.data["resources"][-1]["status"] = "creating"
        self.save()
        result = self.cli(["container", "clusters", "create", self.data["cluster"], "--zone", ZONE, "--num-nodes", "1",
                           "--machine-type", "e2-medium", "--disk-size", "20", "--disk-type", "pd-standard", "--max-pods-per-node", "32",
                           "--network", self.data["cluster"], "--subnetwork", self.data["cluster"], "--enable-ip-alias",
                           "--cluster-secondary-range-name", "qa-pods", "--services-secondary-range-name", "qa-services",
                           "--enable-dns-access", "--no-enable-ip-access",
                           "--workload-pool", PROJECT + ".svc.id.goog", "--service-account", node["email"], "--enable-network-policy",
                           "--enable-shielded-nodes", "--no-enable-basic-auth", "--no-issue-client-certificate", "--enable-autoupgrade",
                           "--release-channel", "regular", "--logging", "SYSTEM", "--monitoring", "SYSTEM",
                           "--labels", "peaso-owner=" + self.data["owner"] + ",peaso-task=" + TASK, "--async"], timeout=120)
        self.data["create_operation"] = result.get("name")
        self.save()
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            cluster = self.cluster()
            if cluster:
                self.validate_cluster(cluster)
                if cluster.get("status") == "RUNNING":
                    self.data["resources"][-1].update(status="created", id=cluster.get("id"))
                    self.data["phase"] = "cluster_ready"
                    self.save()
                    self.record_generated()
                    return cluster
                if cluster.get("status") in {"ERROR", "DEGRADED"}:
                    raise SessionError("cluster_creation_" + cluster["status"])
            time.sleep(10)
        raise SessionError("cluster_creation_timeout")

    def kubectl(self, args, *, timeout=60):
        result = subprocess.run(["kubectl", "--kubeconfig", str(self.kubeconfig), "--context", "gke_" + PROJECT + "_" + ZONE + "_" + self.data["cluster"],
                                 *args], env=self.env, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise SessionError("kubectl_operation_failed")
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def seed(self):
        import yaml
        import requests
        self.identity()
        self.cli(["container", "clusters", "get-credentials", self.data["cluster"], "--zone", ZONE, "--dns-endpoint"])
        os.chmod(self.kubeconfig, 0o600)
        config = yaml.safe_load(self.kubeconfig.read_text())
        selected = next(x for x in config["contexts"] if x["name"] == config["current-context"])
        cluster_config = next(x for x in config["clusters"] if x["name"] == selected["context"]["cluster"])["cluster"]
        server = cluster_config["server"]
        parsed = urlsplit(server)
        if parsed.scheme != "https" or not parsed.hostname.endswith(".gke.goog") or parsed.username or parsed.password:
            raise SessionError("unexpected_fixture_dns_endpoint")
        kube_http = requests.Session()
        def kube_api(method, path, body=None):
            response = kube_http.request(method, server.rstrip("/") + path, json=body,
                                         headers=self.credentials.headers(), timeout=30, allow_redirects=False)
            if not response.ok:
                raise SessionError("fixture_kubernetes_http_" + str(response.status_code))
            return response.json()
        name = self.data["namespace"]
        context = {"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}}
        security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
        objects = [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": {"pod-security.kubernetes.io/enforce": "baseline"}}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "qa-identity", "namespace": name,
             "annotations": {"iam.gke.io/gcp-service-account": self.data["resources"][1]["email"]}}, "automountServiceAccountToken": False},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "qa-private", "namespace": name},
             "spec": {"type": "ClusterIP", "selector": {"app": "qa"}, "ports": [{"port": 9999, "targetPort": 9999}]}},
            {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "qa-deny-all", "namespace": name},
             "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "qa-view-pods", "namespace": name},
             "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "qa-view-pods", "namespace": name},
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "qa-view-pods"},
             "subjects": [{"kind": "ServiceAccount", "name": "qa-identity", "namespace": name}]},
        ]
        for pod_name in ["qa-pass", "qa-review"]:
            spec = {"serviceAccountName": "qa-identity", "securityContext": context,
                    "containers": [{"name": "inert", "image": "registry.k8s.io/pause:3.10", "resources": {
                        "requests": {"cpu": "5m", "memory": "8Mi"}, "limits": {"cpu": "25m", "memory": "16Mi"}},
                                    "securityContext": {**security, "readOnlyRootFilesystem": pod_name == "qa-pass"}}]}
            if pod_name == "qa-pass":
                spec["automountServiceAccountToken"] = False
            objects.append({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod_name, "namespace": name, "labels": {"app": "qa"}}, "spec": spec})
        for obj in objects:
            self.identity()
            self.validate_cluster(self.cluster())
            obj["metadata"].setdefault("labels", {})["peaso-owner"] = self.data["owner"]
            record = {"kind": obj["kind"], "name": obj["metadata"]["name"], "namespace": obj["metadata"].get("namespace"), "status": "planned"}
            self.data["workloads"].append(record)
            self.save()
            manifest = self.directory / "fixture.json"
            private_write(manifest, obj)
            group = "/api/v1" if obj["apiVersion"] == "v1" else "/apis/" + obj["apiVersion"]
            plural = {"Namespace": "namespaces", "ServiceAccount": "serviceaccounts", "Service": "services", "NetworkPolicy": "networkpolicies",
                      "Role": "roles", "RoleBinding": "rolebindings", "Pod": "pods"}[obj["kind"]]
            path = group + ("/namespaces/" + name if obj["kind"] != "Namespace" else "") + "/" + plural
            created = kube_api("POST", path, obj)
            record.update(status="created", uid=created["metadata"]["uid"])
            self.save()
            manifest.unlink()
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            pods = kube_api("GET", "/api/v1/namespaces/" + name + "/pods")["items"]
            if len(pods) == 2 and all(any(c.get("type") == "Ready" and c.get("status") == "True" for c in p.get("status", {}).get("conditions", [])) for p in pods):
                kube_http.close()
                return
            time.sleep(5)
        kube_http.close()
        raise SessionError("fixture_pods_not_ready")

    def cleanup(self):
        lock = open(self.directory / "cleanup.lock", "a+")
        os.chmod(self.directory / "cleanup.lock", 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        self.data = json.loads(self.ledger.read_text())
        try:
            self.data["phase"] = "cleanup"
            self.save()
            cluster = self.cluster()
            if cluster:
                self.validate_cluster(cluster)
                self.identity()
                if cluster.get("status") != "STOPPING":
                    self.cli(["container", "clusters", "delete", self.data["cluster"], "--zone", ZONE, "--async"], timeout=120)
                deadline = time.monotonic() + 900
                while time.monotonic() < deadline and self.cluster() is not None:
                    time.sleep(10)
                if self.cluster() is not None:
                    raise SessionError("cluster_cleanup_timeout")
            self.data["resources"][-1].update(status="deleted", verification="not_found")
            self.verify_generated_absent()
            for row in self.data["workloads"]:
                row.update(status="deleted", verification="owning_cluster_not_found")
            self.save()
            self.kubeconfig.unlink(missing_ok=True)
            auth_cache = self.directory / "gke_gcloud_auth_plugin_cache"
            auth_cache.unlink(missing_ok=True)
            (self.directory / "fixture.json").unlink(missing_ok=True)
            self.membership(self.data["resources"][0]["email"], remove=True)
            for row in self.data["resources"]:
                if row["kind"] != "service_account":
                    continue
                actual = self.service_account(row["email"])
                if actual:
                    if actual.get("displayName") != "peaso-owned-" + self.data["owner"] or (row.get("unique_id") and actual.get("uniqueId") != row["unique_id"]):
                        raise SessionError("service_account_ownership_mismatch")
                    self.api("DELETE", "iam.googleapis.com/v1/projects/" + PROJECT + "/serviceAccounts/" + row["email"], mutation=True)
                deadline = time.monotonic() + 60
                while self.service_account(row["email"]) is not None:
                    if time.monotonic() >= deadline:
                        raise SessionError("service_account_cleanup_not_verified")
                    time.sleep(2)
                row.update(status="deleted", verification="not_found")
                self.save()
            for kind in ["subnetwork", "network"]:
                row = next(x for x in self.data["resources"] if x["kind"] == kind)
                prefix = ["compute", "networks", "subnets"] if kind == "subnetwork" else ["compute", "networks"]
                region = ["--region", REGION] if kind == "subnetwork" else []
                actual = self.cli([*prefix, "describe", row["name"], *region], optional=True)
                if actual:
                    if actual.get("description") != "peaso-owned-" + self.data["owner"] or (row.get("id") and str(actual.get("id")) != str(row["id"])):
                        raise SessionError("network_prerequisite_ownership_mismatch")
                    self.identity()
                    self.cli([*prefix, "delete", row["name"], *region])
                if self.cli([*prefix, "describe", row["name"], *region], optional=True) is not None:
                    raise SessionError("network_prerequisite_cleanup_not_verified")
                row.update(status="deleted", verification="not_found")
                self.save()
            self.data.update(phase="cleaned", cleaned_at=datetime.now(timezone.utc).isoformat(),
                             kubeconfig_removed=not self.kubeconfig.exists(), credential_cache_removed=not auth_cache.exists())
            self.save()
        finally:
            lock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["plan", "run", "cleanup", "watchdog"])
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    directory = Path(args.directory).resolve()
    if args.mode == "plan":
        value = plan(directory)
        print(json.dumps({"ledger": str(directory / "gke-ledger.json"), "cluster": value["cluster"], "deadline": value["cleanup_deadline"]}))
        return
    session = Session(directory)
    if args.mode == "watchdog":
        deadline = datetime.fromisoformat(session.data["cleanup_deadline"]) - timedelta(minutes=5)
        while datetime.now(timezone.utc) < deadline:
            if json.loads(session.ledger.read_text()).get("phase") == "cleaned":
                return
            time.sleep(10)
        latest = json.loads(session.ledger.read_text())
        pid = latest.get("runner_pid")
        if isinstance(pid, int):
            import shlex
            command = subprocess.run(["ps", "-p", str(pid), "-o", "args="], capture_output=True, text=True, timeout=5)
            args_parts = shlex.split(command.stdout)
            if "scripts.peaso_test_resources.gke_session_guard" in args_parts and "run" in args_parts and "--directory" in args_parts:
                actual_directory = Path(args_parts[args_parts.index("--directory") + 1]).resolve()
                if actual_directory == directory:
                    os.kill(pid, signal.SIGTERM)
        session.cleanup()
        return
    if args.mode == "cleanup":
        session.cleanup()
        print(json.dumps({"cleanup": session.data["phase"]}))
        return
    watchdog_log = open(directory / "watchdog.log", "a")
    os.chmod(directory / "watchdog.log", 0o600)
    prior_watchdog = session.data.get("watchdog_pid")
    try:
        if prior_watchdog is None:
            raise ProcessLookupError()
        os.kill(prior_watchdog, 0)
    except ProcessLookupError:
        watcher = subprocess.Popen([sys.executable, "-m", "scripts.peaso_test_resources.gke_session_guard", "watchdog", "--directory", str(directory)],
                                   stdout=watchdog_log, stderr=watchdog_log, start_new_session=True)
        session.data["watchdog_pid"] = watcher.pid
    session.data["runner_pid"] = os.getpid()
    session.save()
    def interrupted(signum, frame):
        raise SessionError("runner_interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        session.create()
        session.seed()
        from scripts.peaso_test_resources.gcp_live_acceptance import collect_gke
        collect_gke(session)
        session.data["acceptance"] = "passed"
        session.save()
    except Exception as exc:
        session.data["acceptance"] = "failed"
        session.data["safe_failure"] = str(exc) if isinstance(exc, SessionError) else type(exc).__name__
        session.save()
        raise SessionError(session.data["safe_failure"]) from None
    finally:
        session.cleanup()
        watchdog_log.close()


if __name__ == "__main__":
    main()
