"""Kubernetes RBAC effective permissions.

  * Role/ClusterRole rules bound by RoleBinding (namespace-limited) and
    ClusterRoleBinding (cluster-wide, incl. cluster-scoped resources),
  * ClusterRole aggregation (aggregationRule.clusterRoleSelectors.matchLabels),
  * resource matching per the apiserver: '*' covers subresources, 'res/sub' and
    '*/sub' forms; resourceNames restrict (create/list/watch/deletecollection never
    match a rule restricted by resourceNames, except create on a subresource, which names the parent),
  * service accounts implicitly belong to system:serviceaccounts,
    system:serviceaccounts:<ns> and system:authenticated,
  * cloud identities from SA annotations (IRSA, GKE Workload Identity, Azure
    Workload Identity) and kiam/kube2iam namespace annotations; with related cloud
    snapshots (analyze(..., related_snapshots=[...])) the cloud side is verified
    (IAM role trust / workloadIdentityUser bindings / kube2iam role regexes) and each
    cloud identity is joined to its IAM principal by a cross-snapshot edge,
  * node cloud identities (GKE node-pool service account, EKS node instance role, AKS kubelet identity) from
    related cloud snapshots,
  * provider / control-plane managed subjects (managed_source) are never escalation sources but stay targets.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re

from . import ANY, Grant, Model, Node, as_list, best, combine, downgrade, glob_match, inventory_status, items, unavailable
from .exact_evidence import ExactEvidenceMixin
from peaso.snapshot import FrozenDict

CLUSTER_SCOPED = {
    "nodes", "namespaces", "clusterroles", "clusterrolebindings", "certificatesigningrequests", "persistentvolumes",
    "mutatingwebhookconfigurations", "validatingwebhookconfigurations", "customresourcedefinitions", "storageclasses",
    "priorityclasses", "apiservices", "tokenreviews", "subjectaccessreviews", "selfsubjectaccessreviews", "users", "groups",
    "userextras", "uids", "signers", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings",
    "validatingadmissionpolicies", "validatingadmissionpolicybindings", "runtimeclasses", "csidrivers", "volumeattachments",
    "ingressclasses", "securitycontextconstraints", "clusterissuers",
}
NO_NAME_VERBS = {"create", "list", "watch", "deletecollection"}
# Provider / control-plane managed subjects (see K8sModel.managed_source).
MANAGED_SUBJECT_PREFIXES = ("system:", "eks:")
# Reserved "system:" subjects any customer workload or person can act as: never managed.
ATTACKER_REACHABLE = {"system:authenticated", "system:unauthenticated", "system:anonymous", "system:serviceaccounts",
                      "system:nodes"}
CONTROL_PLANE_USERS = {"kube-apiserver", "kube-apiserver-kubelet-client", "kubelet", "kubelet-bootstrap",
                       "kubelet-nodepool-bootstrap", "kube-controller-manager", "kube-scheduler", "kube-proxy",
                       "aksService", "aks-support", "konnectivity-agent"}
MANAGED_NAMESPACES = {"gmp-system", "gmp-public", "gke-gmp-system", "gke-connect", "gke-mcs", "aks-command",
                      "amazon-guardduty", "amazon-network-flow-monitor"}
MANAGED_NAMESPACE_PREFIXES = ("gke-managed-", "aks-istio-")
MANAGED_LABELS = {"kubernetes.io/bootstrapping": None, "addonmanager.kubernetes.io/mode": None,
                  "kubernetes.azure.com/managedby": None, "eks.amazonaws.com/component": None}
MANAGED_ANNOTATION_PREFIXES = ("components.gke.io/",)
SEP = "\x1f"
PREFIX = "\x1eprefix:"     # requirement-key verb marker for verb_prefix
ANY_MATCH = "\x1eany"      # requirement-key group / resource marker for resource_match: any
# Secret metadata hints (name / label / annotation tokens) of static cloud credentials; data is never collected.
SECRET_CLOUD_HINTS = {
    "gcp": ("gcp", "gcloud", "google", "gcs", "service-account-key", "sa-key", "clouddns", "credentials-json"),
    "aws": ("aws", "access-key", "s3", "route53", "awscreds"),
    "azure": ("azure", "aad", "entra", "client-secret", "azuredns"),
}
NON_CLOUD_SECRET_TYPES = {"kubernetes.io/service-account-token", "kubernetes.io/tls", "kubernetes.io/dockerconfigjson",
                          "kubernetes.io/dockercfg", "helm.sh/release.v1", "bootstrap.kubernetes.io/token"}
MODIFIABLE_OBJECTS = {"pods": "pod", "deployments": "deployment", "daemonsets": "daemonset",
                      "statefulsets": "statefulset", "replicasets": "replicaset", "replicationcontrollers": "replicationcontroller",
                      "jobs": "job", "cronjobs": "cronjob", "roles": "role", "clusterroles": "clusterrole",
                      "rolebindings": "rolebinding", "clusterrolebindings": "clusterrolebinding",
                      "namespaces": "namespace", "persistentvolumes": "persistentvolume",
                      "mutatingwebhookconfigurations": "admission_configuration"}
REMOTE_CLUSTER_MARKERS = ("argocd.argoproj.io/secret-type=cluster", "cluster.x-k8s.io/cluster-name")
# These settings can let an admitted pod reach host resources. Host network,
# PID, or IPC sharing alone does not establish node authority.
HOST_SCC_FIELDS = ("allowPrivilegedContainer", "allowHostDirVolumePlugin")


def _managed_meta(meta):
    """True when object metadata carries a provider / addon-manager ownership marker."""
    labels = meta.get("labels") or {}
    annotations = meta.get("annotations") or {}
    return any(k in labels for k in MANAGED_LABELS) or any(
        str(k).startswith(MANAGED_ANNOTATION_PREFIXES) for k in list(labels) + list(annotations))


def _cluster(item, scope=None):
    prov = item.get("provenance") or {}
    meta = item.get("metadata") or {}
    return str(prov.get("cluster_id") or meta.get("cluster_id") or "cluster")


_PH = re.compile(r"(?<!\$)\{([^{}]+)\}")


BINDING_PROVIDER = {"irsa": "aws", "kube2iam": "aws", "eks_pod_identity": "aws", "gke_workload_identity": "gcp",
                    "azure_workload_identity": "azure", "aks_identity_binding": "azure",
                    "gke_node": "gcp", "eks_node": "aws", "aks_kubelet": "azure"}
NODE_BINDINGS = ("gke_node", "eks_node", "aks_kubelet")
JOIN_TECHNIQUE = "cloud-identity-join"


class RelatedClouds:
    """Lightweight indexes over related cloud snapshots used to verify / join K8s cloud identities."""

    def __init__(self, snapshots):
        from .aws import AwsModel
        from .azure import AzureModel
        from .gcp import GcpModel
        classes = {"aws": AwsModel, "gcp": GcpModel, "azure": AzureModel}
        self.models = {"aws": [], "gcp": [], "azure": []}
        for snapshot in snapshots or ():
            cls = classes.get((snapshot or {}).get("provider"))
            if cls is not None:
                self.models[snapshot["provider"]].append(cls(snapshot))
        self.aws_roles, self.aws_roles_by_name, self.aws_accounts = {}, {}, set()
        for model in self.models["aws"]:
            self.aws_accounts |= model.accounts
            for node in model.principals.values():
                if node.kind == "aws_role":
                    self.aws_roles[node.id] = (model, node)
                    self.aws_roles_by_name.setdefault(node.label, []).append(node.id)
        self._wi = None

    def has(self, provider):
        return bool(self.models.get(provider))

    def aws_role(self, ref):
        """(model, node) for a role ARN or name; None when unknown."""
        ref = str(ref)
        if ref in self.aws_roles:
            return self.aws_roles[ref]
        # An annotated or associated ARN names one role in one account.
        # Falling back to a same-named role in another account invents a pivot.
        if ref.startswith("arn:"):
            return None
        name = ref.rsplit("/", 1)[-1]
        for arn in self.aws_roles_by_name.get(name, ()):
            if ref == name or arn.endswith("/" + name):
                return self.aws_roles[arn]
        return None

    def aws_account_covered(self, ref):
        match = re.match(r"arn:[^:]+:iam::(\d{12}):", str(ref))
        return bool(match and match.group(1) in self.aws_accounts)

    def oidc_subjects(self, role_model, role, issuer=None):
        """Subject patterns in trust statements for this issuer and the STS audience.

        Without a known cluster issuer this is useful only for candidate discovery;
        callers must not turn those candidates into reachable IRSA identities.
        """
        out = []
        issuer_path = str(issuer or "").removeprefix("https://").rstrip("/")
        for st in role_model.trust.get(role.id, []):
            if (st.effect != "allow" or st.ref.get("not_principal")
                    or not st.action_matches("sts:AssumeRoleWithWebIdentity")):
                continue
            principal = st.principals if isinstance(st.principals, dict) else {}
            providers = [(str(f), str(f).split("oidc-provider/", 1)[-1].rstrip("/"))
                         for f in as_list(principal.get("Federated")) if "oidc-provider/" in str(f)]
            providers = [(arn, path) for arn, path in providers if not issuer_path or path == issuer_path]
            if not providers:
                continue
            raw = _trust_raw(role_model, role, st)
            subjects = []
            audience_seen = False
            audience_allowed = True
            for op, block in ((raw.get("Condition") or {}).items()):
                for key, value in (block or {}).items():
                    if str(key).endswith(":aud") and (not issuer_path or str(key) == issuer_path + ":aud"):
                        audience_seen = True
                        if str(op).startswith(("StringEquals", "StringLike", "ForAnyValue:String")):
                            audience_allowed &= any(glob_match(str(v), "sts.amazonaws.com", False)
                                                    for v in as_list(value))
                        else:
                            audience_allowed = False
                    if str(key).endswith(":sub") and (not issuer_path or str(key) == issuer_path + ":sub") and \
                            str(op).startswith(("StringEquals", "StringLike", "ForAnyValue:String")):
                        subjects.extend(str(v) for v in as_list(value))
            if audience_seen and not audience_allowed:
                continue
            for provider_arn, provider_path in providers:
                for subject in subjects or ["*"]:
                    overrides = {(provider_path + ":aud").lower(): ["sts.amazonaws.com"]}
                    if not any(char in subject for char in ("*", "?", "${")):
                        overrides[(provider_path + ":sub").lower()] = [subject]
                    denied = role_model._trust_explicit_deny(
                        role.id, "sts:AssumeRoleWithWebIdentity", federated=provider_arn,
                        extra_overrides=overrides)
                    if denied is not True:
                        out.append(subject)
        return out

    def gcp_sa(self, email):
        for model in self.models["gcp"]:
            node = model.principals.get(f"serviceAccount:{email}")
            if node is not None and node.attrs.get("resource"):
                return model, node
        return None

    def gcp_project_covered(self, email):
        domain = str(email).split("@", 1)[-1]
        project = "projects/" + domain.split(".", 1)[0]
        return any(project in m.scopes or any(n.scope == project for n in m.sas.values()) for m in self.models["gcp"])

    def gke_workload_pool(self, cluster_ids):
        """The exact GKE cluster's workload pool, or None when the join is unavailable."""
        for model in self.models["gcp"]:
            resources = {model._match_gke(cid) for cid in cluster_ids if cid}
            resources.discard(None)
            if len(resources) != 1:
                continue
            cluster = model.gke[next(iter(resources))]
            return str((cluster.get("workloadIdentityConfig") or {}).get("workloadPool") or "")
        return None

    def gcp_wi_grant(self, email, namespace, name, pool=None):
        found = self.gcp_sa(email)
        if found is None:
            return None
        model, sa = found
        suffix = f".svc.id.goog[{namespace}/{name}]"
        exact_member = f"serviceAccount:{pool}[{namespace}/{name}]" if pool else None
        chain = set(model.ancestors(sa.attrs["resource"]))
        for member, grants in model.grants.items():
            if not (member == exact_member if exact_member else
                    (member.startswith("serviceAccount:") and member.endswith(suffix))):
                continue
            for node, role_name, conditional, ref in grants:
                role = model.roles.get(role_name)
                if node in chain and role is not None and role.has("iam.serviceaccounts.getaccesstoken"):
                    return Grant("conditional" if conditional else "derived", [dict(ref)], ["binding_condition"] if conditional else [])
        return False

    def azure_principal(self, client_id):
        low = str(client_id).lower()
        for model in self.models["azure"]:
            for node in model.principals.values():
                if str(node.attrs.get("client_id") or node.attrs.get("app_id") or "").lower() == low or str(node.id).lower() == low:
                    return model, node
        return None

    def azure_fic(self, client_id, subject, cluster_ids):
        """Exact Entra federated credential match, or a reason it remains conditional."""
        found = self.azure_principal(client_id)
        if found is None:
            return "federated_identity_not_in_related_snapshot"
        model, principal = found
        app_id = str(principal.attrs.get("app_id") or "").lower()
        uai = str(principal.attrs.get("uai_resource") or "").lower().rstrip("/")
        kind = "managed_identity_federated_credential" if uai else "directory_federated_credential"
        credentials = []
        for _, row in items(model.snapshot, kind):
            if uai:
                belongs = str(row.get("id") or "").lower().startswith(uai + "/federatedidentitycredentials/")
            else:
                belongs = app_id and str(row.get("appId") or "").lower() == app_id
            if belongs:
                credentials.append(row.get("properties") or row)
        names = {str(v or "").lower().rsplit("/", 1)[-1] for v in cluster_ids if v}
        issuers = {str(((row.get("properties") or {}).get("oidcIssuerProfile") or {}).get("issuerURL") or "").rstrip("/")
                   for _, row in items(model.snapshot, "aks_cluster")
                   if str(row.get("name") or str(row.get("id") or "").rsplit("/", 1)[-1]).lower() in names}
        issuers.discard("")
        issuer = next(iter(issuers)) if len(issuers) == 1 else None
        matched = [c for c in credentials if str(c.get("subject") or "") == subject
                   and "api://AzureADTokenExchange" in as_list(c.get("audiences") or c.get("audience"))]
        if issuer and any(str(c.get("issuer") or "").rstrip("/") == issuer for c in matched):
            return True
        if matched and not issuer:
            return "federated_issuer_not_verified"
        states = inventory_status(model.snapshot, kind)
        complete = bool(states) and not unavailable(states)
        if complete:
            return False
        return "federated_identity_credential_not_collected"

    # ---------------------------------------------------------------- node cloud identities
    def gke_pool(self, cluster_ids, pool_name, project):
        """(email of the node-pool SA, metadata mode 'open' / 'concealed' / None) for a GKE node pool, or None.
        `cluster_ids` are the K8s cluster id and kubeconfig context; unset / "default" SA = the project's default
        compute SA. Mode: GCE_METADATA -> open, GKE_METADATA (Workload Identity) / SECURE -> concealed."""
        for model in self.models["gcp"]:
            resource = next((r for r in (model._match_gke(c) for c in cluster_ids if c) if r), None)
            if resource is None and project:
                named = [r for r, it in model.gke.items() if r.startswith(f"projects/{project}/") and any(
                    (p or {}).get("name") == pool_name for p in as_list(it.get("nodePools")))]
                resource = named[0] if len(named) == 1 else None
            if resource is None:
                continue
            item = model.gke[resource]
            pool = next((p for p in as_list(item.get("nodePools")) if (p or {}).get("name") == pool_name), None)
            if pool is None:
                return None
            config = pool.get("config") or {}
            email = config.get("serviceAccount")
            if email in (None, "", "default"):
                pid = resource.split("/")[1]
                number = next((n for n, p in model.project_alias.items() if p == pid), None)
                if number is None:
                    return None
                email = f"{number}-compute@developer.gserviceaccount.com"
            mode = str((config.get("workloadMetadataConfig") or {}).get("mode") or (
                config.get("workloadMetadataConfig") or {}).get("nodeMetadata") or "").upper()
            state = {"GCE_METADATA": "open", "EXPOSE": "open", "GKE_METADATA": "concealed", "GKE_METADATA_SERVER": "concealed",
                     "SECURE": "concealed"}.get(mode)
            return email, state
        return None

    def aws_instance(self, instance_id):
        """([role arns of the instance profile], metadata 'open' / 'concealed' / None) for an EC2 instance, or None.
        IMDS reachable from a pod: endpoint enabled and (IMDSv1 allowed or a PUT response hop limit >= 2)."""
        for model in self.models["aws"]:
            arn = next((a for a, v in model.instances.items() if v[2] == instance_id), None)
            if arn is None:
                continue
            roles = sorted(r for r, hosts in model.hosts.items() if arn in hosts.get("ec2_instance", []))
            options = next(((it.get("MetadataOptions") or {}) for _, it in items(model.snapshot, "instance")
                            if it.get("InstanceId") == instance_id), {})
            state = None
            if options:
                if str(options.get("HttpEndpoint") or "enabled") == "disabled":
                    state = "blocked"
                elif str(options.get("HttpTokens") or "") == "optional" or int(options.get("HttpPutResponseHopLimit") or 1) >= 2:
                    state = "open"
                else:
                    state = "concealed"
            return roles, state
        return None

    def eks_facts(self, cluster_ids):
        """EKS API facts of the EKS cluster a K8s cluster id / kubeconfig context names (EKS ARN, eksctl context,
        `k8s-cluster:<sha256(origin)>` of the eks_cluster endpoint, or the bare cluster name), from related AWS
        snapshots: {"entries": [eks_access_entry], "associations": [eks_pod_identity_association],
        "entries_state" / "associations_state": "collected" | None, "auth_mode": str | None}; None when no related
        AWS snapshot carries that cluster."""
        import hashlib
        names, account = set(), None
        for cid in cluster_ids:
            cid = str(cid or "")
            arn = re.match(r"arn:aws[\w-]*:eks:[^:]*:(\d{12}):cluster/(.+)$", cid)
            eksctl = re.match(r"^[^@]+@([^.]+)\.[a-z0-9-]+\.eksctl\.io$", cid)
            if arn:
                account = arn.group(1)
                names.add(arn.group(2))
            elif eksctl:
                names.add(eksctl.group(1))
            elif cid and not cid.startswith("k8s-cluster:"):
                names.add(cid.rsplit("/", 1)[-1])
        digests = {str(c) for c in cluster_ids if str(c or "").startswith("k8s-cluster:")}
        for model in self.models["aws"]:
            if account and account not in model.accounts:
                continue
            clusters = {}
            for _, it in items(model.snapshot, "eks_cluster"):
                body = it.get("cluster") if isinstance(it.get("cluster"), dict) else it
                name = body.get("name") or it.get("name")
                if not isinstance(name, str):
                    continue
                endpoint = str(body.get("endpoint") or "").lower().rstrip("/")
                digest = "k8s-cluster:" + hashlib.sha256(endpoint.encode()).hexdigest() if endpoint else None
                issuer = str((((body.get("identity") or {}).get("oidc") or {}).get("issuer")) or "") or None
                clusters[name] = (digest, str(((body.get("accessConfig") or {}).get("authenticationMode")) or "") or None, issuer)
            wanted = {n for n in names} | {n for n, (d, _, _) in clusters.items() if d and d in digests}
            entries = [it for _, it in items(model.snapshot, "eks_access_entry") if it.get("clusterName") in wanted]
            assoc = [it for _, it in items(model.snapshot, "eks_pod_identity_association") if it.get("clusterName") in wanted]
            if not (entries or assoc or wanted & set(clusters)):
                continue

            def state(kind):
                statuses = inventory_status(model.snapshot, kind)
                return "collected" if statuses and not unavailable(statuses) else None
            mode = next((clusters[n][1] for n in sorted(wanted) if n in clusters and clusters[n][1]), None)
            issuer = next((clusters[n][2] for n in sorted(wanted) if n in clusters and clusters[n][2]), None)
            return {"entries": entries, "associations": assoc, "entries_state": state("eks_access_entry"),
                    "associations_state": state("eks_pod_identity_association"), "auth_mode": mode,
                    "oidc_issuer": issuer}
        return None

    def pods_trust(self, ref):
        """True / False / None: the role trust admits EKS Pod Identity's STS call."""
        found = self.aws_role(ref)
        if not found:
            return None
        model, role = found
        eligible = [st for st in model.trust.get(role.id, []) if st.effect == "allow"
                    and "pods.eks.amazonaws.com" in as_list(
                        (st.principals if isinstance(st.principals, dict) else {}).get("Service"))]
        assume = [st for st in eligible if st.action_matches("sts:AssumeRole")]
        tag = [st for st in eligible if st.action_matches("sts:TagSession")]
        if not assume or not tag:
            return False
        return True if all(any(not (_trust_raw(model, role, st).get("Condition") or {}) for st in group)
                           for group in (assume, tag)) else None

    def aks_kubelet(self, node_resource_group):
        """Kubelet identity id (client id, else object id) of the AKS cluster owning a node resource group, or None."""
        low = str(node_resource_group).lower()
        for model in self.models["azure"]:
            for _, item in items(model.snapshot, "aks_cluster"):
                props = item.get("properties") or {}
                if str(props.get("nodeResourceGroup") or "").lower() != low:
                    continue
                kubelet = ((props.get("identityProfile") or {}).get("kubeletidentity") or {})
                return kubelet.get("clientId") or kubelet.get("objectId")
        return None


def _trust_raw(model, role, statement):
    """The raw trust statement (Condition blocks are not kept on Statement)."""
    cache = model.__dict__.get("_raw_trust")
    if cache is None:
        from .aws import _doc
        cache = model._raw_trust = {}
        for scope, item in items(model.snapshot, "iam_role"):
            doc = _doc(item.get("AssumeRolePolicyDocument")) or {}
            cache[item.get("Arn")] = [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]
    raws = cache.get(role.id, [])
    index = statement.ref.get("statement", 0)
    return raws[index] if index < len(raws) else {}


def _subject_matches(pattern, namespace, name=None):
    """OIDC sub pattern admits system:serviceaccount:<namespace>:<name> (any name when name is None)."""
    if pattern == "*":
        return True
    parts = pattern.split(":")
    if len(parts) != 4 or not glob_match(parts[0], "system", False) or not glob_match(parts[1], "serviceaccount", False):
        return glob_match(pattern, f"system:serviceaccount:{namespace}:{name or 'x'}", False)
    if not glob_match(parts[2], namespace, False):
        return False
    return True if name is None else glob_match(parts[3], name, False)


class K8sModel(ExactEvidenceMixin, Model):
    provider = "k8s"

    def __init__(self, snapshot, catalog_keys=()):
        super().__init__(snapshot, catalog_keys)
        self.roles = {}            # (cluster, ns or None, name) -> {"rules": [...], "labels": {}, "aggregation": [...]}
        self.bindings = {}         # (cluster, subject key) -> [(ns or None, role key, binding ref)]
        self.sas, self.nodes = {}, {}
        self.namespaces = {}       # cluster -> set
        self.pods = []             # (cluster, ns, sa, node, privileged, owned, running)
        self.clusters = set()
        self.cluster_scopes = {}
        self.cloud = {}
        self.related = RelatedClouds(())
        self.pod_roles = {}        # cluster -> set of iam.amazonaws.com/role pod annotations
        self._load()
        from .k8s_helm_values_rbac import load as load_helm_values_rbac
        self.helm_values_rbac_targets, self.helm_values_rbac_records = load_helm_values_rbac(self)
        from .k8s_verified_pivots import load as load_verified_pivots
        self.verified_pivot_targets, self.verified_pivot_records = load_verified_pivots(self)
        self.load_exact_evidence("k8s_privesc_challenge_evidence", {"k8s_service_account", "k8s_remote_cluster"})
        self.exact_scopes = set(self.clusters)
        self._load_admission()
        self.require_collections(("role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"), {
            "role": "Namespaced RBAC grants are unknown", "clusterrole": "Cluster role rules are unknown",
            "rolebinding": "Namespaced bindings are unknown", "clusterrolebinding": "Cluster-wide bindings are unknown",
            "serviceaccount": "Service-account targets are unknown"})
        for kind in ("pod", "node"):
            if not inventory_status(snapshot, kind):
                self.add_coverage("collection", "*", "not_collected", f"{kind} not in snapshot",
                                  "Pod/node placement selectors are unknown")

    # ------------------------------------------------------------------ load
    def _load(self):
        snap = self.snapshot
        for kind in ("role", "clusterrole"):
            for scope, item in items(snap, kind):
                meta = item.get("metadata") or {}
                cluster = _cluster(item)
                self.clusters.add(cluster)
                ns = meta.get("namespace") if kind == "role" else None
                self.roles[(cluster, ns, meta.get("name"))] = {
                    "rules": [r for r in as_list(item.get("rules")) if isinstance(r, dict)],
                    "labels": meta.get("labels") or {},
                    "aggregation": [((s or {}).get("matchLabels") or {}) for s in
                                    as_list((item.get("aggregationRule") or {}).get("clusterRoleSelectors"))],
                    "aggregation_selectable": any(_aggregation_selector_satisfiable(s) for s in
                                                  as_list((item.get("aggregationRule") or {}).get("clusterRoleSelectors"))),
                    "name": meta.get("name"), "namespace": ns, "kind": "ClusterRole" if ns is None else "Role"}
        for key, role in list(self.roles.items()):
            if role["aggregation"]:
                extra = []
                for other_key, other in self.roles.items():
                    if other_key[0] == key[0] and other_key[1] is None and other_key != key and any(
                            sel and all(other["labels"].get(k) == v for k, v in sel.items()) for sel in role["aggregation"]):
                        extra.extend(other["rules"])
                role["rules"] = role["rules"] + [r for r in extra if r not in role["rules"]]
        # Cluster-flavour and secret facts (metadata only; Secret data is never collected).
        self.api_groups, self.node_providers, self.legacy_tokens, self.configmaps = {}, {}, {}, set()
        self.admission_api_resources = {}
        self.server_versions = {}
        for scope, item in items(snap, "api_discovery"):
            self.api_groups.setdefault(_cluster(item), set()).update(
                str((g or {}).get("name")) for g in as_list(item.get("groups")) if isinstance(g, dict))
            if isinstance(item.get("admissionPolicyResources"), list):
                self.admission_api_resources.setdefault(_cluster(item), set()).update(
                    str(name) for name in item["admissionPolicyResources"])
            version = (item.get("serverVersion") or {}).get("gitVersion")
            if isinstance(version, str):
                self.server_versions[_cluster(item)] = version
        self.secrets = []                # (cluster, namespace, name, type, labels, annotations) - metadata only
        self.secret_uids = {}
        self.secret_versions = {}
        for scope, item in items(snap, "secret_metadata"):
            meta = item.get("metadata") or {}
            self.secret_uids.setdefault((_cluster(item), meta.get("namespace"), str(meta.get("name") or "")), []).append(meta.get("uid"))
            self.secret_versions.setdefault((_cluster(item), meta.get("namespace"), str(meta.get("name") or "")), []).append(meta.get("resourceVersion"))
            self.secrets.append((_cluster(item), meta.get("namespace"), str(meta.get("name") or ""), str(item.get("type") or ""),
                                 meta.get("labels") or {}, meta.get("annotations") or {}))
            if str(item.get("type") or "") == "kubernetes.io/service-account-token":
                owner = (meta.get("annotations") or {}).get("kubernetes.io/service-account.name")
                if owner:
                    self.legacy_tokens.setdefault((_cluster(item), meta.get("namespace")), set()).add(str(owner))
        for scope, item in items(snap, "configmap_metadata"):
            meta = item.get("metadata") or {}
            self.configmaps.add((_cluster(item), meta.get("namespace"), meta.get("name")))
        self.ns_annotations = {}
        self.managed_ns = set()          # (cluster, namespace) carrying a provider / addon-manager marker
        self.binding_managed = {}        # (cluster, subject key) -> [binding is provider / control-plane managed]
        self.ns_inventoried = {}         # cluster -> namespaces present in the namespace inventory
        self.ns_labels = {}              # (cluster, namespace) -> labels (kubernetes.io/metadata.name always set)
        for scope, item in items(snap, "namespace"):
            meta = item.get("metadata") or {}
            self.namespaces.setdefault(_cluster(item), set()).add(meta.get("name"))
            self.ns_inventoried.setdefault(_cluster(item), set()).add(meta.get("name"))
            self.ns_labels[(_cluster(item), meta.get("name"))] = {
                "kubernetes.io/metadata.name": str(meta.get("name")), **{str(k): str(v) for k, v in (meta.get("labels") or {}).items()}}
            if _managed_meta(meta):
                self.managed_ns.add((_cluster(item), meta.get("name")))
            annotations = meta.get("annotations") or {}
            rules = {}
            if annotations.get("iam.amazonaws.com/permitted"):
                rules["permitted"] = str(annotations["iam.amazonaws.com/permitted"])  # kiam: regex
            if annotations.get("iam.amazonaws.com/allowed-roles"):
                try:
                    allowed = json.loads(annotations["iam.amazonaws.com/allowed-roles"])  # kube2iam: JSON list of globs
                except (TypeError, ValueError):
                    allowed = [annotations["iam.amazonaws.com/allowed-roles"]]
                rules["allowed_roles"] = [str(a) for a in as_list(allowed)]
            if rules:
                self.ns_annotations.setdefault(_cluster(item), {})[meta.get("name")] = rules
        for scope, item in items(snap, "serviceaccount"):
            meta = item.get("metadata") or {}
            cluster, ns, name = _cluster(item), meta.get("namespace"), meta.get("name")
            node = self._sa(cluster, ns, name)
            node.attrs["annotations"] = meta.get("annotations") or {}
            node.attrs["managed_meta"] = _managed_meta(meta)
            node.attrs["inventoried"] = True
        for scope, item in items(snap, "node"):
            meta = item.get("metadata") or {}
            cluster, name = _cluster(item), meta.get("name")
            provider_id = str((item.get("spec") or {}).get("providerID") or "")
            self.node_providers.setdefault(cluster, set()).add(provider_id.split("://", 1)[0].lower() if "://" in provider_id else "")
            node = Node(f"k8s:{cluster}:node:{name}", "k8s_node", "k8s", cluster, name,
                        attrs={"cluster": cluster, "name": name, "labels": meta.get("labels") or {}, "provider_id": provider_id,
                               "unschedulable": bool((item.get("spec") or {}).get("unschedulable")),
                               "ready": next((str(c.get("status")) for c in as_list((item.get("status") or {}).get("conditions"))
                                              if isinstance(c, dict) and c.get("type") == "Ready"), None),
                               "groups": ["system:nodes", "system:authenticated"], "user": f"system:node:{name}"})
            self.nodes[node.id] = node
            self.principals[node.id] = node
            self.clusters.add(cluster)
        for scope, item in items(snap, "pod"):
            meta, spec = item.get("metadata") or {}, item.get("spec") or {}
            cluster, ns = _cluster(item), meta.get("namespace")
            sa = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
            privileged, host_mount = pod_escape_primitives(spec)
            phase = (item.get("status") or {}).get("phase")
            exec_privileged, exec_host_mount = active_pod_escape_primitives(spec, item.get("status") or {})
            token_volumes = {str(volume.get("name") or "") for volume in as_list(spec.get("volumes"))
                             if isinstance(volume, dict) and any(
                                 isinstance(source, dict) and source.get("serviceAccountToken") is not None
                                 for source in as_list((volume.get("projected") or {}).get("sources")))}
            token_mounts = {str(container.get("name") or ""): bool(token_volumes & {
                str(mount.get("name") or "") for mount in as_list(container.get("volumeMounts"))
                if isinstance(mount, dict)}) for container in as_list(spec.get("containers"))
                if isinstance(container, dict)}
            pod_role = (meta.get("annotations") or {}).get("iam.amazonaws.com/role")
            if pod_role:
                self.pod_roles.setdefault(cluster, set()).add(str(pod_role))
            self.pods.append({"cluster": cluster, "ns": ns, "name": meta.get("name"), "sa": sa,
                              "node": spec.get("nodeName"), "privileged": privileged,
                              "host_mount": host_mount, "exec_privileged": exec_privileged,
                              "exec_host_mount": exec_host_mount, "configmaps": pod_configmap_refs(spec),
                              "stdin_containers": tuple(str(c.get("name") or "") for c in as_list(spec.get("containers"))
                                                        if isinstance(c, dict) and c.get("stdin") is True),
                              "running_containers": tuple(str(c.get("name") or "")
                                                          for c in as_list((item.get("status") or {}).get("containerStatuses"))
                                                          if isinstance(c, dict) and (c.get("state") or {}).get("running") is not None),
                              "token_volumes": frozenset(token_volumes), "token_mounts": token_mounts,
                              "automount_disabled": spec.get("automountServiceAccountToken") is False,
                              "deleting": bool(meta.get("deletionTimestamp")),
                              "owned": any((ref or {}).get("kind") in (
                                  "ReplicaSet", "ReplicationController", "DaemonSet", "StatefulSet", "Job")
                                  and (ref or {}).get("controller") is True
                                  for ref in as_list(meta.get("ownerReferences"))),
                              "running": phase == "Running",
                              "phase": phase})
            self.namespaces.setdefault(cluster, set()).add(ns)
        self.scc_users = {}              # (cluster, ns, name) -> [SCC names] (OpenShift SCC users[] entries)
        self.host_sccs = {}              # cluster -> {SCC name: {"users": [...], "groups": [...]}} (host-level SCCs)
        for scope, item in items(snap, "securitycontextconstraint"):
            meta = item.get("metadata") or {}
            cluster = _cluster(item)
            if any(item.get(f) is True for f in HOST_SCC_FIELDS):
                self.host_sccs.setdefault(cluster, {})[str(meta.get("name"))] = {
                    "users": [str(u) for u in as_list(item.get("users"))], "groups": [str(g) for g in as_list(item.get("groups"))],
                    "impact": "derived" if item.get("allowPrivilegedContainer") is True else "conditional"}
            for user in as_list(item.get("users")):
                parts = str(user).split(":")
                if len(parts) == 4 and parts[:2] == ["system", "serviceaccount"] and parts[2] and parts[3]:
                    self._sa(cluster, parts[2], parts[3])
                    self.scc_users.setdefault((cluster, parts[2], parts[3]), []).append(str(meta.get("name")))
        for kind in ("rolebinding", "clusterrolebinding"):
            for scope, item in items(snap, kind):
                meta = item.get("metadata") or {}
                cluster = _cluster(item)
                self.clusters.add(cluster)
                ns = meta.get("namespace") if kind == "rolebinding" else None
                if ns:
                    self.namespaces.setdefault(cluster, set()).add(ns)
                ref = item.get("roleRef") or {}
                role_ns = ns if ref.get("kind") == "Role" else None
                role_key = (cluster, role_ns, ref.get("name"))
                evidence = {"binding": f"{kind}/{(ns + '/') if ns else ''}{meta.get('name')}",
                            "role": f"{ref.get('kind')}/{ref.get('name')}"}
                managed_binding = _managed_meta(meta) or (
                    str(meta.get("name") or "").startswith("system:") and str(ref.get("name") or "").startswith("system:"))
                for subject in as_list(item.get("subjects")):
                    if not isinstance(subject, dict):
                        continue
                    skind, sname = subject.get("kind"), subject.get("name")
                    # A subject without a recognized kind and nonempty name
                    # cannot identify a usable principal.
                    if skind not in ("ServiceAccount", "Group", "User") or not isinstance(sname, str) or not sname:
                        continue
                    if skind == "ServiceAccount":
                        sns = subject.get("namespace") or ns
                        if not isinstance(sns, str) or not sns:
                            continue
                        key = f"sa:{sns}:{sname}"
                        self._sa(cluster, sns, sname).attrs["binding_ref"] = True
                    elif skind == "Group":
                        key = f"group:{sname}"
                        self._subject(cluster, "k8s_group", sname)
                    elif skind == "User":
                        key = f"user:{sname}"
                        if not str(sname).startswith("system:node:"):
                            self._subject(cluster, "k8s_user", sname)
                    self.bindings.setdefault((cluster, key), []).append((ns, role_key, evidence))
                    self.binding_managed.setdefault((cluster, key), []).append(managed_binding)
        for cluster in self.clusters:
            self.namespaces.setdefault(cluster, set())
        for node in self.principals.values():
            cluster = node.attrs["cluster"]
            keys = self._subject_keys(node)
            bound = []
            for key in keys:
                bound.extend((ns, role, tuple(sorted(ev.items()))) for ns, role, ev in self.bindings.get((cluster, key), []))
            node.attrs["bound"] = tuple(sorted(set(bound), key=repr))
            node.perm_key = (cluster, tuple((ns, role) for ns, role, _ in node.attrs["bound"]))
            self.cluster_scopes.setdefault(cluster, set()).add(node.scope)

    def _sa(self, cluster, ns, name):
        nid = f"k8s:{cluster}:sa:{ns}:{name}"
        if nid not in self.principals:
            node = Node(nid, "k8s_service_account", "k8s", f"{cluster}/{ns}", f"{ns}/{name}",
                        attrs={"cluster": cluster, "namespace": ns, "name": name, "inventoried": False,
                               "groups": ["system:serviceaccounts", f"system:serviceaccounts:{ns}", "system:authenticated"],
                               "user": f"system:serviceaccount:{ns}:{name}"})
            self.principals[nid] = node
            self.sas[nid] = node
            self.namespaces.setdefault(cluster, set()).add(ns)
        return self.principals[nid]

    def _subject(self, cluster, kind, name):
        nid = f"k8s:{cluster}:{'group' if kind == 'k8s_group' else 'user'}:{name}"
        if nid not in self.principals:
            groups = [] if kind == "k8s_group" else ["system:authenticated"]
            self.principals[nid] = Node(nid, kind, "k8s", cluster, name,
                                        attrs={"cluster": cluster, "name": name, "groups": groups, "user": name})
        return self.principals[nid]

    def _subject_keys(self, node):
        if node.kind == "k8s_service_account":
            keys = [f"sa:{node.attrs['namespace']}:{node.attrs['name']}", f"user:{node.attrs['user']}"]
        elif node.kind == "k8s_group":
            keys = [f"group:{node.attrs['name']}"]
        else:
            keys = [f"user:{node.attrs['user']}"]
        return keys + [f"group:{g}" for g in node.attrs.get("groups", [])]

    def external_user(self, cluster, name):
        """Resolve exact User and system:authenticated RBAC grants for a cloud identity."""
        node = self._subject(cluster, "k8s_user", name)
        bound = []
        for key in self._subject_keys(node):
            bound.extend((ns, role, tuple(sorted(ev.items())))
                         for ns, role, ev in self.bindings.get((cluster, key), []))
        node.attrs["bound"] = tuple(sorted(set(bound), key=repr))
        node.perm_key = (cluster, tuple((ns, role) for ns, role, _ in node.attrs["bound"]))
        return node

    # ----------------------------------------------------------------- rules
    def requirement_key(self, req):
        # Requirements repeat a few shapes millions of times; key the derived string by the fields it reads.
        get = req.get
        try:
            shape = (get("verb_prefix"), get("verb"), get("resource_match"), get("api_group", _MISSING),
                     get("resource"), get("subresource"))
            hit = _REQUIREMENT_KEYS.get(shape)
        except TypeError:
            return self._requirement_key(req)
        if hit is None:
            hit = self._requirement_key(req)
            for value in shape:  # equal-hashing non-text values (1, True, 1.0) would collide
                if value is not None and value is not _MISSING and type(value) is not str:
                    return hit
            if len(_REQUIREMENT_KEYS) >= _REQUIREMENT_KEYS_LIMIT:
                _REQUIREMENT_KEYS.clear()
            _REQUIREMENT_KEYS[shape] = hit
        return hit

    def _requirement_key(self, req):
        verb = PREFIX + str(req["verb_prefix"]).lower() if req.get("verb_prefix") else str(req.get("verb", "")).lower()
        if req.get("resource_match") == "any":
            group = str(req["api_group"]) if "api_group" in req else ANY_MATCH
            return "|".join([verb, group, ANY_MATCH, ""])
        return "|".join([verb, str(req.get("api_group", "")), str(req.get("resource", "")),
                         str(req.get("subresource", ""))])

    def requirement_template(self, req):
        ns = req.get("namespace", "*")
        name = req.get("resource_name")
        resource = str(req.get("resource", ""))
        res_tpl = resource if "{" in resource else ""
        if ns in (None, "*") and not name and not res_tpl:
            return None
        return SEP.join([str(ns or "*"), str(name or ""), res_tpl])

    def localizable(self, req):
        # namespace "*" means a cluster-wide grant; only an omitted namespace is evaluated in the target's namespace.
        return req.get("namespace") is None and str(req.get("resource")) not in CLUSTER_SCOPED

    def _rules(self, principal):
        for ns, rule, evidence in self._rule_rows(principal):
            yield ns, rule, dict(evidence) if rule is None else _rule_evidence(ns, rule, evidence)

    def _rule_rows(self, principal):
        """(binding namespace, rule or None for a missing role, binding evidence items) without building the
        per-rule evidence dict; callers that keep a rule build it with _rule_evidence."""
        cluster = principal.attrs["cluster"]
        for ns, role_key, evidence in principal.attrs.get("bound", ()):
            role = self.roles.get(role_key)
            if role is None:
                yield ns, None, evidence
                continue
            for rule in role["rules"]:
                yield ns, rule, evidence
        del cluster

    def possible(self, principal):
        indexes, signature = self.prefilter_indexes()
        key = ("possible", signature, principal.perm_key)
        if key in self._check_cache:
            return self._check_cache[key]
        keys, universal = set(), False
        role_keys = indexes.setdefault("k8s_role_keys", {})
        for ns, role_key, evidence in principal.attrs.get("bound", ()):
            role = self.roles.get(role_key)
            if role is None:
                continue
            if role_key not in role_keys:
                matched, all_permissions = set(), False
                for rule in role["rules"]:
                    verbs, groups, resources = (as_list(rule.get(k)) for k in ("verbs", "apiGroups", "resources"))
                    if "*" in verbs and "*" in resources and "*" in groups:
                        all_permissions = True
                        continue
                    for k in self.catalog_keys:
                        verb, group, resource, sub = k.split("|")
                        if _rule_matches(rule, verb, group, resource, sub, None, partial=True):
                            matched.add(k)
                role_keys[role_key] = frozenset(matched), all_permissions
            matched, all_permissions = role_keys[role_key]
            keys.update(matched)
            universal = universal or all_permissions
        self._check_cache[key] = (frozenset(keys), universal)
        return self._check_cache[key]

    def check(self, principal, req, ref):
        verb, group, resource, sub = self.requirement_key(req).split("|")
        if req.get("resource_match") != "any":
            resource = str(req.get("resource", ""))
        if isinstance(ref, tuple):
            ns, name, res_override = ref
            if res_override:
                resource = res_override
        else:
            ns, name = ANY, None
        # namespace: "*" = cluster-wide: only ClusterRoleBindings count.
        # OpenShift authorizes SCC `use` for a pod's namespace, including from a
        # namespaced RoleBinding, despite SCC objects themselves being cluster scoped.
        scoped_scc_use = verb == "use" and resource == "securitycontextconstraints" and ns not in (ANY, "*")
        cluster_scoped = (resource in CLUSTER_SCOPED and not scoped_scc_use) or (ns is ANY and req.get("namespace") == "*")
        best_grant = None
        for bind_ns, rule, evidence in self._rule_rows(principal):
            if rule is None:
                continue
            if bind_ns is not None:
                if cluster_scoped:
                    continue
                if ns is not ANY and ns != "*" and ns != bind_ns:
                    continue
                if ns == "*":
                    # cluster-wide requirement ('*' = in every namespace) needs a ClusterRoleBinding
                    continue
            match = _rule_matches(rule, verb, group, resource, sub, name)
            if not match:
                continue
            existence = True if req.get("_rbac_only") else self._modify_target_exists(principal, verb, resource, ns, name, rule)
            if existence is False:
                continue
            if (match == "restricted_by_resourceNames" and existence is True and not req.get("_rbac_only") and
                    verb in ("patch", "update") and resource in MODIFIABLE_OBJECTS):
                match = True  # a collected object matches one of the granted names
            conf = "derived" if match is True else "conditional"
            conditions = [] if match is True else [match]
            if existence is None:
                conf = "conditional"
                conditions.append("modify_target_inventory_not_collected")
            grant = self._rule_grant(bind_ns, rule, evidence, conf, conditions)
            if best_grant is None or (best_grant.confidence != "derived" and conf == "derived"):
                best_grant = grant
                if conf == "derived" and bind_ns is None:
                    break
        return best_grant

    def _rule_grant(self, bind_ns, rule, evidence, conf, conditions):
        """Grant(conf, [rule evidence], conditions) for one bound rule. Each check keeps its own Grant (the
        evaluator groups targets by Grant identity, which orders output), but the read-only evidence dict depends
        only on (binding evidence, namespace, rule), so one copy is shared. Entries keep evidence and rule alive,
        so their ids are never reused while cached."""
        memo = self.__dict__.get("_rule_refs")
        if memo is None:
            memo = self.__dict__["_rule_refs"] = {}
        try:
            key = (id(evidence), bind_ns, id(rule))
            hit = memo.get(key)
        except TypeError:
            hit, memo = None, None
        if hit is None or hit[0] is not evidence or hit[1] is not rule:
            hit = (evidence, rule, {**_rule_evidence(bind_ns, rule, evidence), "namespace": bind_ns or "*"})
            if memo is not None:
                memo[key] = hit
        return Grant(conf, [hit[2]], conditions)

    def _name_shared_check(self, principal, req, ref):
        """check(principal, req, ref) for callers that only read the result's confidence (or None).

        When none of the principal's rules lists resourceNames, the object name in ref changes check() only
        through modify-target existence (which then ignores the rule), so one result per (principal rules,
        requirement, namespace, existence) is shared. Any named rule, or an unhashable fact, keeps the
        direct check."""
        if not isinstance(ref, tuple):
            return self.check(principal, req, ref)
        try:
            memo = self.__dict__.setdefault("_name_shared_checks", {})
            cluster = principal.attrs.get("cluster")
            bound = principal.attrs.get("bound", ())
            plain_key = (cluster, bound)
            plain = memo.get(plain_key)
            if plain is None:
                plain = memo[plain_key] = not any(rule is not None and as_list(rule.get("resourceNames"))
                                                  for _, rule, _ in self._rule_rows(principal))
            if not plain:
                return self.check(principal, req, ref)
            ns, name, res_override = ref
            verb = self.requirement_key(req).split("|", 1)[0]
            resource = res_override or ("" if req.get("resource_match") == "any" else str(req.get("resource", "")))
            if req.get("_rbac_only") or verb not in ("patch", "update") or resource not in MODIFIABLE_OBJECTS:
                exists = True
            else:
                exists = self._modify_target_exists(principal, verb, resource, ns, name, _NO_NAMES_RULE)
            shape = tuple(sorted(req.items()))
            shape = memo.setdefault((_MISSING, shape), shape)  # one tuple per requirement shape (sentinel-tagged key)
            key = (cluster, bound, shape, ns, res_override, exists)
            if key not in memo:
                memo[key] = self.check(principal, req, ref)
            return memo[key]
        except TypeError:
            return self.check(principal, req, ref)

    def cached_check(self, principal, req, ref):
        """The base per-(permissions, requirement, ref) cache with compact storage: one table per (permissions,
        requirement) keyed by ref, and one interned copy of each ref (resolve() builds a fresh tuple per target).
        Same values and first-writer semantics as Model.cached_check."""
        outer = (principal.perm_key if principal.perm_key is not None else principal.id, self.requirement_key(req))
        tables = self.__dict__.get("_ref_checks")
        if tables is None:
            tables = self.__dict__["_ref_checks"] = {}
            self.__dict__["_interned_refs"] = {}
        table = tables.get(outer)
        if table is None:
            table = tables[outer] = {}
        try:
            return table[ref]
        except KeyError:
            pass
        ref = self.__dict__["_interned_refs"].setdefault(ref, ref)
        value = table[ref] = self.check(principal, req, ref)
        return value

    def _modify_target_exists(self, principal, verb, resource, namespace, name, rule):
        """A patch/update route needs a real object; missing inventory keeps it conditional."""
        if verb not in ("patch", "update") or resource not in MODIFIABLE_OBJECTS:
            return True
        kind = MODIFIABLE_OBJECTS[resource]
        cluster = principal.attrs.get("cluster")
        names = set(str(v) for v in as_list(rule.get("resourceNames")))
        index = self._modify_target_index(kind, resource == "mutatingwebhookconfigurations")
        if index is not None:
            try:
                pool = (index[0].get(cluster, ()) if namespace in (ANY, "*")
                        else index[1].get((cluster, namespace), ()))
                if name in (None, ANY):
                    found = bool(pool) if not names else any(n in names for n in pool)
                else:
                    found = name in pool and (not names or name in names)
            except TypeError:
                found = None
            if found is not None:
                if found:
                    return True
                states = self._modify_target_states(kind)
                return False if states and not unavailable(states) else None
        for _, item in items(self.snapshot, kind):
            meta = item.get("metadata") or {}
            if resource == "mutatingwebhookconfigurations" and item.get("kind") != "MutatingWebhookConfiguration":
                continue
            if _cluster(item) != cluster or (namespace not in (ANY, "*") and meta.get("namespace") != namespace):
                continue
            object_name = str(meta.get("name") or "")
            if object_name and (name in (None, ANY) or object_name == name) and (not names or object_name in names):
                return True
        states = inventory_status(self.snapshot, kind)
        return False if states and not unavailable(states) else None

    def _modify_target_index(self, kind, webhook_only):
        """({cluster: object names}, {(cluster, namespace): object names}) of one modifiable kind, built once per
        model (the snapshot is frozen); None when a namespace cannot be indexed (callers keep the scan)."""
        store = self.__dict__.setdefault("_modify_target_indexes", {})
        key = (kind, webhook_only)
        if key not in store:
            by_cluster, by_ns = {}, {}
            try:
                for _, item in items(self.snapshot, kind):
                    if webhook_only and item.get("kind") != "MutatingWebhookConfiguration":
                        continue
                    meta = item.get("metadata") or {}
                    object_name = str(meta.get("name") or "")
                    if not object_name:
                        continue
                    cluster = _cluster(item)
                    by_cluster.setdefault(cluster, set()).add(object_name)
                    by_ns.setdefault((cluster, meta.get("namespace")), set()).add(object_name)
                store[key] = (by_cluster, by_ns)
            except TypeError:
                store[key] = None
        return store[key]

    def _modify_target_states(self, kind):
        store = self.__dict__.setdefault("_modify_target_state_cache", {})
        if kind not in store:
            store[kind] = inventory_status(self.snapshot, kind)
        return store[kind]

    def scope_only(self, req, template, localized):
        # Node / SA scopes are "<cluster>" / "<cluster>/<ns>", so namespace-only templates are scope-only.
        if localized:
            return True
        if template is None:
            return False
        ns_tpl, name_tpl, res_tpl = template.split(SEP)
        refs = set(_PH.findall(template))
        return not name_tpl and not res_tpl and {n for n in refs if n.startswith("target.")} <= {"target.namespace"}

    def check_targets(self, principal, req, template, candidates, localized=False):
        placeholder = req.get("resource_name") if isinstance(req, dict) else None
        if placeholder in ("{source_rolebound_clusterrole}", "{source_bound_clusterrole}", "{source_bound_role}"):
            result = {}
            for target in candidates:
                ns = target.attrs.get("namespace")
                names = {role[2] for bind_ns, role, _ in principal.attrs.get("bound", ())
                         if role[0] == target.attrs.get("cluster")
                         and ((placeholder == "{source_rolebound_clusterrole}" and bind_ns == ns
                               and bind_ns is not None and self.roles.get(role, {}).get("kind") == "ClusterRole")
                              or (placeholder == "{source_bound_clusterrole}" and bind_ns is None
                                  and self.roles.get(role, {}).get("kind") == "ClusterRole")
                              or (placeholder == "{source_bound_role}" and bind_ns == ns
                                  and self.roles.get(role, {}).get("kind") == "Role"))}
                resource = "roles" if placeholder == "{source_bound_role}" else "clusterroles"
                for name in names:
                    grants = {}
                    for verb in ("escalate", "update", "patch"):
                        for bind_ns, rule, evidence in self._rule_rows(principal):
                            if rule is None or (bind_ns is not None and (resource != "roles" or bind_ns != ns)):
                                continue
                            match = _rule_matches(rule, verb, "rbac.authorization.k8s.io", resource, "", name)
                            if match:
                                conf = "derived" if match is True else "conditional"
                                evidence = _rule_evidence(bind_ns, rule, evidence)
                                grants[verb] = best(grants.get(verb), Grant(conf, [{**evidence, "namespace": bind_ns or "*"}],
                                                                         [] if match is True else [str(match)]))
                    if grants.get("escalate") and (grants.get("update") or grants.get("patch")) and grants.get(req.get("verb")):
                        # Keep the authorization proof tied to this ClusterRole name.
                        # Returning only the current verb lets the evaluator take a
                        # derived escalate on one name and a derived patch on another,
                        # even when neither name has both permissions derived.
                        companion = (best(grants.get("update"), grants.get("patch"))
                                     if req["verb"] == "escalate" else grants["escalate"])
                        grant = combine(grants[req["verb"]], companion)
                        if resource == "clusterroles" and self.roles.get((target.attrs.get("cluster"), None, name), {}).get("aggregation"):
                            grant = downgrade(grant, "conditional", "aggregated_clusterrole_rules_may_be_overwritten")
                        result[target.id] = best(result.get(target.id), grant)
            return result
        # Most templates depend on the target only through its namespace: evaluate once per namespace.
        by_ns = localized
        target_namespace = localized
        if not localized and template is not None:
            ns_tpl, name_tpl, res_tpl = template.split(SEP)
            target_namespace = ns_tpl == "{target.namespace}"
            target_refs = set(_PH.findall(template))
            by_ns = {n for n in target_refs if n.startswith("target.")} <= {"target.namespace"}
            if not name_tpl and not res_tpl and self.cached_check(principal, req, (ANY, None, "")) is None:
                return {}  # not held in any namespace
        bound_namespaces = None
        if target_namespace:
            bindings = principal.attrs.get("bound", ())
            if not any(namespace is None for namespace, _, _ in bindings):
                bound_namespaces = {namespace for namespace, _, _ in bindings}
        memo, result = {}, {}
        for target in candidates:
            namespace = target.attrs.get("namespace")
            # A RoleBinding cannot authorize a concrete different namespace.
            # Keep unknown namespaces for the ordinary resolver's uncertainty
            # handling, and keep every namespace when a ClusterRoleBinding exists.
            if bound_namespaces is not None and namespace and namespace != "*" and namespace not in bound_namespaces:
                continue
            key = (target.attrs.get("namespace"), target.attrs.get("cluster")) if by_ns else target.id
            if key not in memo:
                if localized:
                    refs, floor = [(target.attrs.get("namespace") or ANY, None, "")], None
                else:
                    refs, floor = self.resolve(template, principal, target)
                grant = None
                for ref in refs:
                    got = self.cached_check(principal, req, ref)
                    if got is not None and (grant is None or got.confidence == "derived"):
                        grant = got
                memo[key] = None if grant is None else (downgrade(grant, floor[0], floor[1]) if floor else grant)
            if memo[key] is not None:
                result[target.id] = memo[key]
        return result

    # ----------------------------------------------------------- placeholders
    def placeholder_values(self, name, source, target, pivot=None):
        if name.startswith("pivot"):
            return [pivot[name]] if pivot and name in pivot else None
        if name == "cluster":
            node = target or source
            return [node.attrs.get("cluster")] if node is not None else None
        if name in ("source_bound_clusterrole", "source_bound_role"):
            wanted = "ClusterRole" if name == "source_bound_clusterrole" else "Role"
            # A ClusterRole only grants cluster-wide power when a ClusterRoleBinding (ns None) binds it to the source;
            # a RoleBinding to a ClusterRole confines it to one namespace, so escalating it does not yield cluster-admin.
            # A Role only helps in its own namespace: with a target, keep only Roles bound in the target's namespace.
            target_ns = target.attrs.get("namespace") if target is not None else None
            return sorted({role[2] for ns, role, ev in source.attrs.get("bound", ())
                           if self.roles.get(role, {}).get("kind") == wanted
                           and (ns is None if wanted == "ClusterRole" else (target_ns is None or ns == target_ns))})
        if name == "source_rolebound_clusterrole":
            ns = target.attrs.get("namespace") if target is not None else None
            return sorted({role[2] for bind_ns, role, _ in source.attrs.get("bound", ())
                           if bind_ns == ns and bind_ns is not None
                           and self.roles.get(role, {}).get("kind") == "ClusterRole"})
        if name == "admin_equivalent_clusterrole":
            cluster = source.attrs["cluster"]
            return sorted(k[2] for k, r in self.roles.items() if k[0] == cluster and k[1] is None and any(
                "*" in as_list(x.get("verbs")) and "*" in as_list(x.get("resources"))
                and "*" in as_list(x.get("apiGroups")) and not as_list(x.get("resourceNames"))
                for x in r["rules"]))
        owner, _, attr = name.partition(".")
        if not attr:
            owner, attr = "source", owner
        node = target if owner == "target" else source
        if node is None:
            return None
        if attr == "namespace":
            value = node.attrs.get("namespace")
            return [value] if value else None
        if attr == "name":
            return [node.attrs.get("name") or node.label]
        if attr == "node":
            if node.kind == "k8s_node":
                return [node.attrs["name"]]
            if node.kind == "k8s_service_account":
                return sorted({p["node"] for p in self._pods_for_sa(node) if p["node"]})
            return None
        if attr == "client_id":
            return None
        return None

    def _sub(self, text, source, target, pivot):
        if not text:
            return [""], None
        names = re.findall(r"(?<!\$)\{([^{}]+)\}", text)
        values = [text]
        for name in names:
            got = self.placeholder_values(name, source, target, pivot)
            if got is None:
                return None, ("unknown", f"placeholder_{name}_not_in_snapshot")
            values = [v.replace("{" + name + "}", g) for v in values for g in got]
        return values, None

    def resolve(self, template, source, target, pivot=None):
        if template is None:
            return [ANY], None
        ns_tpl, name_tpl, res_tpl = template.split(SEP)
        if ns_tpl == "*":
            namespaces, floor = [ANY], None
        else:
            namespaces, floor = self._sub(ns_tpl, source, target, pivot)
            if namespaces is None:
                return [ANY], floor
        names, floor2 = self._sub(name_tpl, source, target, pivot)
        if names is None:
            return [ANY], floor2
        resources, floor3 = self._sub(res_tpl, source, target, pivot)
        if resources is None:
            return [ANY], floor3
        refs = [(ns, name or None, res) for ns in namespaces for name in names for res in resources][:200]
        return refs, None

    def pivot_candidates(self, source):
        cluster = source.attrs["cluster"]
        namespaces = {ns for ns, role, ev in source.attrs.get("bound", ()) if ns}
        if any(ns is None for ns, role, ev in source.attrs.get("bound", ())):
            namespaces |= {n for n in self.namespaces.get(cluster, ()) if n}
        return [{"pivot.namespace": ns} for ns in sorted(namespaces)]

    pivot_is_conditional = False

    def covered_by_requirement(self, key, action, template, kind):
        if key != "resource_permission_covers_target" or not isinstance(action, str):
            return None
        resource, _, verb = action.partition(":")
        if not verb:
            return None
        name = "{target.name}" if kind in ("k8s_user", "k8s_group", "k8s_service_account") else None
        if resource == "serviceaccounts" and verb == "impersonate":
            return {"verb": verb, "resource": resource, "namespace": "{target.namespace}", "resource_name": name}
        # A ServiceAccount (and its token/subresources) lives in its namespace: a namespaced Role there covers it,
        # not only ClusterRoleBindings ("*" would demand a cluster-wide grant).
        namespace = "{target.namespace}" if kind == "k8s_service_account" else "*"
        req = {"verb": verb, "resource": resource, "namespace": namespace}
        if verb.startswith("impersonate:"):
            req["api_group"] = "authentication.k8s.io"
        if name:
            req["resource_name"] = name
        return req

    # --------------------------------------------------------- preconditions
    EKS_PROVIDER_PREFIXES = ("aws", "eks-hybrid")

    def _complete(self, kind):
        statuses = inventory_status(self.snapshot, kind)
        return bool(statuses) and all(st in ("collected", "empty") for st in statuses.values())

    def _is_openshift(self, cluster):
        """True / False / None (api_discovery not collected for the cluster)."""
        groups = self.api_groups.get(cluster)
        if groups is None:
            return None
        return any(g == "openshift.io" or g.endswith(".openshift.io") for g in groups)

    def _is_eks(self, cluster):
        """True / False / None from node providerIDs, EKS API groups and the aws-auth ConfigMap."""
        providers = self.node_providers.get(cluster, set())
        groups = self.api_groups.get(cluster, set())
        if any(p.startswith(self.EKS_PROVIDER_PREFIXES) for p in providers) \
                or any(g.endswith((".k8s.aws", ".amazonaws.com")) for g in groups) \
                or (cluster, "kube-system", "aws-auth") in self.configmaps:
            return True
        nodes_known = self._complete("node") and bool(providers)
        if nodes_known and "" not in providers:
            return False  # every node reports a non-AWS providerID (kind://, gce://, azure://, ...)
        if nodes_known and cluster in self.api_groups and self._complete("configmap_metadata"):
            return False  # no AWS providerID, no EKS API group and no aws-auth ConfigMap
        return None

    def precondition(self, pid, candidates, source):
        checks = {"k8s_eks_cluster": (self._is_eks, "eks_cluster_not_determined"),
                  "k8s_openshift_cluster": (self._is_openshift, "api_discovery_not_collected")}
        if pid not in checks:
            return None
        check, why = checks[pid]
        out = {}
        for tid, n in candidates.items():
            verdict = check(n.attrs.get("cluster"))
            if verdict is True:
                out[tid] = None
            elif verdict is None:
                out[tid] = ("unknown", why)
        return out

    # -------------------------------------------------------------- blockers
    def _load_admission(self):
        """Workload-admission facts: CEL admission policies + bindings, validating webhooks (failurePolicy, rules,
        namespaceSelector) and their collection states (None: not collected / failed; 'absent': API not served)."""
        snap = self.snapshot
        self.admission_policies, self.admission_bindings, self.validating_webhooks = {}, [], []
        states = inventory_status(snap, "admission_policy")
        absent = any(((c.get("error") or {}).get("code") == "admission_policy_api_absent")
                     for c in snap.get("collections", []) if c.get("type") == "admission_policy")
        self.admission_policy_state = "absent" if absent else (
            "collected" if states and not unavailable(states) else None)
        for scope, item in items(snap, "admission_policy"):
            kind, meta, spec = str(item.get("kind") or ""), item.get("metadata") or {}, item.get("spec") or {}
            cluster = _cluster(item)
            if kind.endswith("PolicyBinding"):
                self.admission_bindings.append((cluster, kind, str(meta.get("name")), spec))
            elif kind.endswith("AdmissionPolicy"):
                self.admission_policies[(cluster, kind, str(meta.get("name")))] = spec
        states = inventory_status(snap, "admission_configuration")
        self.webhook_state = "collected" if states and not unavailable(states) else None
        for scope, item in items(snap, "admission_configuration"):
            if str(item.get("kind") or "") != "ValidatingWebhookConfiguration":
                continue  # mutating webhooks usually inject (sidecars, credentials); only validating ones reject
            meta = item.get("metadata") or {}
            for hook in as_list(item.get("webhooks")):
                if isinstance(hook, dict):
                    self.validating_webhooks.append((_cluster(item), str(meta.get("name")), hook))

    def _blocker_resources(self, compiled):
        """(api group, resource[/subresource]) pairs the technique sends through admission: Pods (controllers create
        them too) plus every requirement resource."""
        out = {("", "pods")} if compiled["entry"].get("service") == "workloads" else set()
        for alt in compiled["alternatives"]:
            for req in alt:
                raw = req.raw
                if isinstance(raw, dict) and raw.get("resource"):
                    res = str(raw["resource"]) + ("/" + str(raw["subresource"]) if raw.get("subresource") else "")
                    out.add((str(raw.get("api_group") or ""), res))
                    if raw.get("resource") in ("pods", "deployments", "daemonsets", "statefulsets", "replicasets",
                                               "replicationcontrollers", "jobs", "cronjobs", "deploymentconfigs"):
                        out.add(("", "pods"))
                    if raw.get("subresource"):
                        out.add(("", "pods/" + str(raw["subresource"])) if raw["resource"] == "pods" else ("", "pods"))
        return out

    def _workload_namespaces(self, compiled):
        """('pivot', None) | ('target', None) | ('fixed', [namespaces]) | ('all', None): where the workload is created."""
        cache = self.__dict__.setdefault("_wl_ns", {})
        eid = compiled["entry"].get("id")
        if eid not in cache:
            values = [str(r.raw.get("namespace")) for alt in compiled["alternatives"] for r in alt
                      if isinstance(r.raw, dict) and r.raw.get("namespace") is not None]
            if any("{pivot.namespace}" in v for v in values):
                cache[eid] = ("pivot", None)
            elif any("{target.namespace}" in v for v in values):
                cache[eid] = ("target", None)
            elif values and all(v != "*" and "{" not in v for v in values):
                cache[eid] = ("fixed", sorted(set(values)))
            else:
                cache[eid] = ("all", None)
        return cache[eid]

    K8S_BLOCKERS = ("pod_security_admission", "pivot_namespace_psa_enforce_baseline_or_restricted", "admission_policy",
                    "admission_webhook", "kyverno_policy", "gatekeeper_constraint")
    POLICY_ENGINE_GROUPS = {"kyverno_policy": ("Kyverno", ("kyverno.io", "policies.kyverno.io")),
                            "gatekeeper_constraint": ("OPA Gatekeeper", ("templates.gatekeeper.sh", "constraints.gatekeeper.sh",
                                                                         "config.gatekeeper.sh"))}

    def blocker_verdict(self, blocker, source, compiled, pivots=None, reached=None, cset=None):
        if blocker not in self.K8S_BLOCKERS:
            return None
        cluster = source.attrs.get("cluster")
        if blocker in self.POLICY_ENGINE_GROUPS:
            name, wanted = self.POLICY_ENGINE_GROUPS[blocker]
            groups = self.api_groups.get(cluster)
            if groups is None:
                return None
            served = sorted(g for g in groups if g in wanted)
            if not served:
                return "clear"
            return ("possibly_blocked", f"{name} is installed (API groups {', '.join(served)}); its policies are not "
                                        "collected, so whether one rejects this workload is not decided")
        mode, fixed = self._workload_namespaces(compiled)
        resources = self._blocker_resources(compiled)
        if mode == "pivot":
            namespaces = {p.get("pivot.namespace") for p in pivots or () if p.get("pivot.namespace")}
            # This OpenShift path also has fixed default-project alternatives.
            # Evaluate their admission blockers when the source can create a
            # workload there, even if no run-level namespace pivot was chosen.
            if compiled["entry"].get("id") == "k8s-openshift-privileged-default-projects":
                for alternative in compiled["alternatives"]:
                    for requirement in alternative:
                        raw = requirement.raw
                        ns = raw.get("namespace") if isinstance(raw, dict) else None
                        if (not isinstance(ns, str) or not ns or "{" in ns
                                or ns not in self.ns_inventoried.get(cluster, ())):
                            continue
                        if self.check(source, raw, (ns, raw.get("resource_name"), None)) is not None:
                            namespaces.add(ns)
            if not namespaces:
                return None
            return self._ns_verdict(blocker, cluster, sorted(namespaces), resources)
        if mode == "target":
            if not isinstance(reached, dict) or cset is None:
                return None
            out = {}
            for tid in reached:
                node = cset.members.get(tid)
                if node is not None and node.attrs.get("namespace"):
                    out[tid] = self._ns_verdict(blocker, node.attrs.get("cluster", cluster), [node.attrs["namespace"]], resources)
            return out
        namespaces = fixed if mode == "fixed" else sorted(n for n in self.namespaces.get(cluster, ()) if n)
        return self._ns_verdict(blocker, cluster, namespaces, resources)

    def _ns_verdict(self, blocker, cluster, namespaces, resources):
        """The attacker picks the most permissive namespace: clear < not evaluated < possibly_blocked < blocked."""
        if not namespaces:
            return None
        rank = {"clear": 0, None: 1, "possibly_blocked": 2, "blocked": 3}
        best_state, evidence = "blocked", []
        for ns in namespaces:
            state, why = self._one_ns_verdict(blocker, cluster, ns, resources)
            if rank[state] < rank[best_state]:
                best_state, evidence = state, []
            if state == best_state and why:
                evidence.append(why)
        if best_state in ("clear", None):
            return best_state
        shown = "; ".join(evidence[:3]) + (f"; +{len(evidence) - 3} more" if len(evidence) > 3 else "")
        return (best_state, shown)

    def _one_ns_verdict(self, blocker, cluster, ns, resources):
        """Memoized per (blocker, cluster, namespace, resources): the verdict reads only facts loaded with the model."""
        cache = self.__dict__.setdefault("_ns_verdict_memo", {})
        try:
            key = (blocker, cluster, ns, frozenset(resources))
            return cache[key]
        except KeyError:
            verdict = cache[key] = self._one_ns_verdict_uncached(blocker, cluster, ns, resources)
            return verdict
        except TypeError:
            return self._one_ns_verdict_uncached(blocker, cluster, ns, resources)

    def _one_ns_verdict_uncached(self, blocker, cluster, ns, resources):
        labels = self.ns_labels.get((cluster, ns))
        if blocker in ("pod_security_admission", "pivot_namespace_psa_enforce_baseline_or_restricted"):
            if labels is None:
                return None, None
            level = labels.get("pod-security.kubernetes.io/enforce")
            if level in ("baseline", "restricted"):
                # Baseline already rejects privileged containers, host namespaces, hostPath and added capabilities.
                return "blocked", (f"namespace {ns} enforces Pod Security '{level}' (label pod-security.kubernetes.io/enforce; "
                                   "API-server PSA exemptions are not collected)")
            return "clear", None
        if blocker == "admission_policy":
            if self.admission_policy_state == "absent":
                return "clear", None
            if self.admission_policy_state is None:
                return None, None
            hits, undecided = [], False
            for bcluster, kind, name, spec in self.admission_bindings:
                if bcluster != cluster:
                    continue
                validating = kind.startswith("Validating")
                actions = [str(a) for a in as_list(spec.get("validationActions"))]
                if validating and actions and "Deny" not in actions:
                    continue  # Warn / Audit only
                policy_kind = kind[:-len("Binding")]
                policy = self.admission_policies.get((cluster, policy_kind, str(spec.get("policyName"))))
                if policy is None:
                    continue  # a binding without its policy admits everything
                match = _admission_match(policy.get("matchConstraints") or {}, resources, labels)
                bound = _admission_match(spec.get("matchResources") or {}, resources, labels, default=True)
                if match is False or bound is False:
                    continue
                if match is None or bound is None:
                    undecided = True
                hits.append(f"{policy_kind} {spec.get('policyName')} bound by {name}"
                            + (f" (validationActions {','.join(actions)})" if actions else "")
                            + f" matches the workload in namespace {ns}")
            if hits:
                return "possibly_blocked", "; ".join(hits[:3]) + (" (namespace labels unknown)" if undecided else "")
            return "clear", None
        if blocker == "admission_webhook":
            if self.webhook_state is None:
                return None, None
            hits = []
            for wcluster, config, hook in self.validating_webhooks:
                if wcluster != cluster:
                    continue
                match = _webhook_match(hook, resources, labels)
                if match is False:
                    continue
                hits.append(f"ValidatingWebhookConfiguration {config}/{hook.get('name')} "
                            f"(failurePolicy {hook.get('failurePolicy') or 'Fail'}) intercepts the workload in namespace {ns}")
            if hits:
                return "possibly_blocked", "; ".join(hits[:3])
            return "clear", None
        return None, None

    # --------------------------------------------------------------- targets
    def targets(self, kind):
        if kind == "gcp_verified_authority" and (self.current_selector or {}).get("k8s_kcc_project_policy_grant"):
            from .k8s_config_connector_project_policy import targets
            return list(targets(self).values())
        if kind == "gcp_service_account":
            return [sa for cloud in self.related.models["gcp"] for sa in cloud.sas.values()
                    if sa.attrs.get("resource")]
        if kind == "k8s_verified_authority":
            return list(self.helm_values_rbac_targets.values()) + list(self._bound_role_gain_targets().values()) + [
                node for node in self.verified_pivot_targets.values() if node.kind == kind]
        if kind == "k8s_service_account":
            return list(self.sas.values())
        if kind == "k8s_node":
            return list(self.nodes.values())
        if kind in ("k8s_user", "k8s_group"):
            return [n for n in self.principals.values() if n.kind == kind]
        if kind == "k8s_cluster_admin":
            return [self.entity(c) for c in sorted(self.clusters)]
        if kind == "cloud_identity":
            return [n for n in self._cloud_identities().values()
                    if n.attrs.get("variant") in (None, "oidc_wildcard")] + [
                node for node in self.verified_pivot_targets.values() if node.kind == kind]
        if kind == "k8s_admission_control":
            return [self.admission_entity(c) for c in sorted(self.clusters)]
        if kind == "k8s_remote_cluster":
            return self._remote_clusters() + [
                node for node in self.verified_pivot_targets.values() if node.kind == kind]
        return []

    def admission_entity(self, cluster):
        cache = self.__dict__.setdefault("_admission", {})
        if cluster not in cache:
            cache[cluster] = Node(f"k8s_admission_control:{cluster}", "k8s_admission_control", "k8s", cluster,
                                  f"Admission enforcement of {cluster}", attrs={"cluster": cluster, "name": cluster}, entity=True)
        return cache[cluster]

    def _secret_nodes(self, kind, prefix, label, wanted):
        out = []
        for cluster, ns, name, stype, labels, annotations in self.secrets:
            if stype == "kubernetes.io/service-account-token":
                continue
            hit = wanted(name, stype, labels, annotations)
            if hit:
                out.append(Node(f"{prefix}:{cluster}/{ns}/{name}", kind, "k8s", f"{cluster}/{ns}", label(ns, name),
                                attrs={"cluster": cluster, "namespace": ns, "name": name, "secret_type": stype,
                                       "labels": labels, "hint": hit, "variant": "secret"}))
        return out

    def _remote_clusters(self):
        cache = self.__dict__.get("_remote_cache")
        if cache is None:
            def marker(name, stype, labels, annotations):
                return ["labelled"] if labels else None  # the selector matches the label markers
            cache = self._remote_cache = self._secret_nodes(
                "k8s_remote_cluster", "k8s_remote_cluster", lambda ns, n: f"Remote cluster credential in Secret {ns}/{n}", marker)
        return cache

    def _secret_credentials(self):
        cache = self.__dict__.get("_secret_cred_cache")
        if cache is None:
            def hint(name, stype, labels, annotations):
                if stype in NON_CLOUD_SECRET_TYPES:
                    return None
                text = " ".join([name] + [f"{k} {v}" for k, v in labels.items()] + list(annotations))
                tokens = set(re.split(r"[^a-z0-9]+", text.lower()))
                found = sorted(p for p, hints in SECRET_CLOUD_HINTS.items()
                               if any((h in tokens) if "-" not in h else (h in text.lower()) for h in hints))
                return found or None
            cache = self._secret_nodes("cloud_identity", "cloud:k8s_secret", lambda ns, n: f"Cloud credential in Secret {ns}/{n}", hint)
            if not self._complete("secret_metadata"):
                # Secret metadata missing: one placeholder per cluster, resolved as an unresolved target by the selector.
                cache = cache + [Node(f"cloud:k8s_secret:{c}/*", "cloud_identity", "k8s", c, f"Cloud credentials in Secrets of {c}",
                                      attrs={"cluster": c, "variant": "secret", "placeholder": True}) for c in sorted(self.clusters)]
            self._secret_cred_cache = cache
        return cache

    def target_variant(self, kind, selector):
        if kind == "k8s_service_account":
            # A ServiceAccount only named by a binding subject does not exist: pods, TokenRequests and token Secrets
            # need it. Only the dangling-reference technique (create it) and impersonation (any name) target it.
            # The variant is part of the evaluator's candidate-set key, so the two sets are never shared.
            if {"k8s_sa_absent_but_bound", "k8s_sa_namespace_absent", "k8s_sa_named_in_scc_users",
                    "k8s_sa_missing_in_host_scc_users", "k8s_csr_sa_subject"} & set(selector) \
                    or str(selector.get("resource_permission_covers_target") or "").startswith("serviceaccounts:impersonate"):
                return "with_binding_only_sas"
            return None
        if kind != "cloud_identity":
            return None
        if "k8s_verified_pivot" in selector:
            return "verified_pivot"
        if "k8s_secret_holds_cloud_credential" in selector:
            return "secret_credential"
        if "kube2iam_namespace_permits_role" in selector:
            return "kube2iam"
        if "trust_allows_oidc_subject_wildcard" in selector:
            return "oidc_wildcard"
        return None

    def _constrained_impersonation_gain(self, source, target, mode):
        """Join the impersonation action to an actual target right the source lacks."""
        if source is None or source.attrs.get("cluster") != target.attrs.get("cluster"):
            return False
        prefix = f"impersonate-on:{mode}:"
        action_rules = [(ns, rule) for ns, rule, _ in self._rule_rows(source)
                        if rule and ("*" in as_list(rule.get("verbs")) or
                                     any(str(verb).startswith(prefix) for verb in as_list(rule.get("verbs"))))]
        if not action_rules:
            return False

        def choices(first, second, defaults):
            left, right = set(map(str, as_list(first))), set(map(str, as_list(second)))
            if "*" in left:
                left = set()
            if "*" in right:
                right = set()
            return sorted((left & right) if left and right else (left or right or set(defaults)))

        def new_right(verb, group, resource, ns, name):
            base, _, sub = resource.partition("/")
            own = self.check(source, {"verb": verb, "api_group": group, "resource": base,
                                      "subresource": sub, "_rbac_only": True}, (ns, name, None))
            if own is None:
                return None
            return ("conditional", "source_direct_permission_not_fully_resolved") if own.confidence != "derived" else False

        if target.kind == "k8s_node":
            # Node authorization grants a kubelet get on pods bound to its node. A
            # concrete pod name avoids claiming unrelated node powers from any
            # impersonate-on rule (for example, one limited to deployments).
            pods = self._pods_on_node(target.attrs.get("name"), target.attrs.get("cluster"))
            for pod in pods:
                ns, name = pod.get("ns"), pod.get("name")
                if not ns or not name:
                    continue
                for action_ns, action in action_rules:
                    if action_ns is not None and action_ns != ns:
                        continue
                    if _rule_matches(action, prefix + "get", "", "pods", "", name) is True:
                        verdict = new_right("get", "", "pods", ns, name)
                        if verdict is not False:
                            return verdict
                    sa_name = pod.get("sa")
                    if sa_name and _rule_matches(action, prefix + "create", "", "serviceaccounts", "token", sa_name) is True:
                        verdict = new_right("create", "", "serviceaccounts/token", ns, sa_name)
                        if verdict is not False:
                            return verdict
            return (("unknown", "node_pod_or_action_inventory_incomplete")
                    if not self._complete("pod") else False)

        if target.kind not in ("k8s_user", "k8s_service_account"):
            return False
        target_rules = [(ns, rule) for ns, rule, _ in self._rule_rows(target) if rule]
        cluster = target.attrs.get("cluster")
        known_ns = sorted(ns for ns in self.namespaces.get(cluster, ()) if ns)
        for action_ns, action in action_rules:
            action_verbs = [str(verb)[len(prefix):] for verb in as_list(action.get("verbs"))
                            if str(verb).startswith(prefix)]
            if "*" in as_list(action.get("verbs")):
                action_verbs.append("*")
            for target_ns, rule in target_rules:
                if action_ns is not None and target_ns is not None and action_ns != target_ns:
                    continue
                namespaces = ([action_ns or target_ns] if action_ns or target_ns else known_ns)
                verbs = choices(action_verbs, rule.get("verbs"), ("get", "list", "create", "update", "patch", "delete"))
                groups = choices(action.get("apiGroups"), rule.get("apiGroups"), ("", "apps", "rbac.authorization.k8s.io"))
                resources = choices(action.get("resources"), rule.get("resources"), ("secrets", "pods", "roles"))
                action_names = set(map(str, as_list(action.get("resourceNames"))))
                target_names = set(map(str, as_list(rule.get("resourceNames"))))
                names = sorted(action_names & target_names if action_names and target_names else
                               (action_names or target_names)) or [None]
                for verb in verbs:
                    if verb == "*" or verb.startswith("impersonate"):
                        continue
                    for group in groups:
                        for resource in resources:
                            base, _, sub = resource.partition("/")
                            scoped = ["*"] if base in CLUSTER_SCOPED else namespaces
                            for ns in scoped:
                                for name in names:
                                    if (_rule_matches(action, prefix + verb, group, base, sub, name) is True
                                            and _rule_matches(rule, verb, group, base, sub, name) is True):
                                        verdict = new_right(verb, group, resource, ns, name)
                                        if verdict is not False:
                                            return verdict
        if not all(self._complete(kind) for kind in ("role", "clusterrole", "rolebinding", "clusterrolebinding")):
            return ("unknown", "target_rbac_rules_incomplete")
        return False

    def target_gain_required(self):
        return (self.current_entry or {}).get("id") in {
            "k8s-rbac-impersonate-users", "k8s-rbac-impersonate-groups",
            "k8s-rbac-impersonate-serviceaccounts",
            "k8s-rbac-csr-kube-apiserver-client-user",
            "k8s-rbac-csr-kube-apiserver-client-group",
            "k8s-rbac-csr-kube-apiserver-client-serviceaccount"}

    def target_gain(self, source, target):
        if self.target_gain_required():
            return self._plain_impersonation_gain(source, target)
        return None

    def _rbac_only_confidence(self, principal, req, ref, probe):
        """Confidence of check(principal, req, ref) for an `_rbac_only` probe, or None when no rule grants it.
        It depends only on the principal's bound (namespace, role) rules, which perm_key names (binding evidence
        changes the refs, never the confidence), so principals sharing a perm_key share it."""
        perm_key = principal.perm_key
        if perm_key is None:
            grant = self.check(principal, req, ref)
            return None if grant is None else grant.confidence
        memo = self.__dict__.setdefault("_rbac_only_confidences", {})
        key = (perm_key, probe)
        try:
            if key in memo:
                return memo[key]
        except TypeError:
            grant = self.check(principal, req, ref)
            return None if grant is None else grant.confidence
        grant = self.check(principal, req, ref)
        memo[key] = got = None if grant is None else grant.confidence
        return got

    def _plain_impersonation_gain(self, source, target):
        """A user, group, or ServiceAccount impersonation must add an RBAC right."""
        if (target.kind not in ("k8s_user", "k8s_group", "k8s_service_account") or
                source.attrs.get("cluster") != target.attrs.get("cluster")):
            return False
        complete = all(self._complete(kind) for kind in
                       ("role", "clusterrole", "rolebinding", "clusterrolebinding"))
        cluster = target.attrs["cluster"]
        known_namespaces = sorted(ns for ns in self.namespaces.get(cluster, ()) if ns)
        uncertain = False
        checked = 0
        if target.kind == "k8s_service_account":
            # Impersonate-User does not itself authorize Impersonate-Group headers.
            # A ServiceAccount's group bindings are reachable only when the source
            # can impersonate that exact group as well.
            keys = [f"sa:{target.attrs['namespace']}:{target.attrs['name']}",
                    f"user:{target.attrs['user']}", "group:system:authenticated"]
            for group in target.attrs.get("groups") or ():
                if group == "system:authenticated":
                    continue
                grant = self.check(source, {"verb": "impersonate", "resource": "groups",
                                            "namespace": "*", "resource_name": group},
                                   ("*", group, None))
                if grant is not None and grant.confidence == "derived":
                    keys.append(f"group:{group}")
                elif grant is not None:
                    uncertain = True
            bound = [item for key in keys for item in self.bindings.get((cluster, key), ())]
            rules = ((ns, rule, evidence) for ns, role_key, evidence in bound
                     for rule in (self.roles.get(role_key) or {}).get("rules", ()))
            if any(role_key not in self.roles for _, role_key, _ in bound):
                uncertain = True
        else:
            rules = self._rule_rows(target)
        for bound_ns, rule, _ in rules:
            if rule is None:
                uncertain = True
                continue
            verbs = [str(v) for v in as_list(rule.get("verbs"))]
            groups = [str(g) for g in as_list(rule.get("apiGroups"))]
            resources = [str(r) for r in as_list(rule.get("resources"))]
            names = [str(n) for n in as_list(rule.get("resourceNames"))] or [None]
            if not verbs or not groups or not resources:
                uncertain = uncertain or bool(rule.get("nonResourceURLs"))
                continue
            if "*" in verbs or "*" in groups or "*" in resources:
                uncertain = True
                verbs = [v for v in verbs if v != "*"] or ["get", "create", "update"]
                groups = [g for g in groups if g != "*"] or ["", "apps", "rbac.authorization.k8s.io"]
                resources = [r for r in resources if r != "*"] or ["secrets", "pods", "clusterroles"]
            for verb in verbs:
                for group in groups:
                    for resource in resources:
                        base, _, sub = resource.partition("/")
                        namespaces = (["*"] if base in CLUSTER_SCOPED else
                                      [bound_ns] if bound_ns else known_namespaces)
                        if not namespaces:
                            uncertain = True
                        for ns in namespaces:
                            for name in names:
                                checked += 1
                                if checked > 256:
                                    return ("unknown", "impersonated_user_rule_probe_limit")
                                req = {"verb": verb, "api_group": group, "resource": base,
                                       "_rbac_only": True, **({"subresource": sub} if sub else {})}
                                ref = (ns, name, None)
                                probe = (verb, group, base, sub, ns, name)
                                target_conf = self._rbac_only_confidence(target, req, ref, probe)
                                if target_conf is None:
                                    continue
                                if target_conf != "derived":
                                    uncertain = True
                                    continue
                                source_conf = self._rbac_only_confidence(source, req, ref, probe)
                                if source_conf is None:
                                    return None if complete else ("conditional", "source_rbac_inventory_incomplete")
                                if source_conf != "derived":
                                    return ("conditional", "source_direct_permission_not_fully_resolved")
        if not complete:
            return ("unknown", "impersonated_user_rbac_inventory_incomplete")
        return ("unknown", "impersonated_user_right_not_fully_probed") if uncertain else False

    def _dangling_sa_binding_gain(self, source, target):
        """A missing SA name is useful only when its direct binding adds a right."""
        if source is None or target.kind != "k8s_service_account" or source.attrs.get("cluster") != target.attrs.get("cluster"):
            return False
        cluster, namespace, name = (target.attrs.get(key) for key in ("cluster", "namespace", "name"))
        direct = self.bindings.get((cluster, f"sa:{namespace}:{name}"), ())
        if not direct:
            return False
        incomplete = not all(self._complete(kind) for kind in ("role", "clusterrole", "rolebinding", "clusterrolebinding"))
        uncertain = False
        probes = []
        for bind_ns, role_key, _ in direct:
            role = self.roles.get(role_key)
            if role is None:
                uncertain = uncertain or incomplete
                continue
            for rule in role["rules"]:
                verbs = [str(v) for v in as_list(rule.get("verbs"))]
                groups = [str(g) for g in as_list(rule.get("apiGroups"))]
                resources = [str(r) for r in as_list(rule.get("resources"))]
                names = [str(n) for n in as_list(rule.get("resourceNames"))] or [None]
                for verb in (verbs if "*" not in verbs else ("get", "list", "create", "patch")):
                    for group in (groups if "*" not in groups else ("", "apps", "rbac.authorization.k8s.io")):
                        for resource in (resources if "*" not in resources else ("secrets", "pods", "roles")):
                            base = resource.partition("/")[0]
                            scopes = (["*"] if base in CLUSTER_SCOPED else
                                      ([bind_ns] if bind_ns else [namespace, *sorted(self.namespaces.get(cluster, ()))]) )
                            for scope in scopes:
                                for resource_name in names:
                                    probes.append((bind_ns, rule, verb, group, resource, scope, resource_name))
        for _bind_ns, rule, verb, group, resource, scope, resource_name in probes:
            base, _, sub = resource.partition("/")
            if _rule_matches(rule, verb, group, base, sub, resource_name) is not True:
                continue
            own = self.check(source, {"verb": verb, "api_group": group, "resource": base,
                                      "subresource": sub, "_rbac_only": True}, (scope, resource_name, None))
            if own is None:
                return None
            if own.confidence != "derived":
                uncertain = True
        def covers(have, wanted):
            for field in ("verbs", "apiGroups", "resources"):
                existing, requested = set(map(str, as_list(have.get(field)))), set(map(str, as_list(wanted.get(field))))
                if "*" not in existing and not requested <= existing:
                    return False
            existing_names = set(map(str, as_list(have.get("resourceNames"))))
            requested_names = set(map(str, as_list(wanted.get("resourceNames"))))
            if existing_names and (not requested_names or not requested_names <= existing_names):
                return False
            return set(map(str, as_list(wanted.get("nonResourceURLs")))) <= set(
                map(str, as_list(have.get("nonResourceURLs"))))

        held = [(ns, rule) for ns, rule, _ in self._rule_rows(source) if rule]
        for bind_ns, role_key, _ in direct:
            role = self.roles.get(role_key)
            if role is None:
                continue
            if any(not any((own_ns is None or own_ns == bind_ns) and covers(own_rule, wanted)
                           for own_ns, own_rule in held) for wanted in role["rules"]):
                uncertain = True  # wildcard and non-resource grants may not have a safe concrete probe
        return ("unknown", "service_account_binding_rights_incomplete") if uncertain else False

    def _bound_role_gain_targets(self):
        """One bounded authority per collected role and known binding namespace."""
        if "_role_gain_targets" not in self.__dict__:
            out = {}
            for key, role in sorted(self.roles.items(), key=lambda row: repr(row[0])):
                cluster, role_ns, name = key
                if not name or not role["rules"]:
                    continue
                namespaces = [role_ns] if role_ns else ["*", *sorted(n for n in self.namespaces.get(cluster, ()) if n)]
                for ns in namespaces:
                    digest = hashlib.sha1(repr((key, ns)).encode()).hexdigest()[:16]
                    node_id = f"k8s:role-gain:{cluster}:{ns}:{digest}"
                    out[node_id] = Node(node_id, "k8s_verified_authority", "k8s", f"{cluster}/{ns}",
                                        f"{role['kind']} {name} permissions {'cluster-wide' if ns == '*' else 'in ' + ns}",
                                        attrs={"cluster": cluster, "namespace": ns, "role_key": key,
                                               "role_name": name, "role_kind": role["kind"]}, entity=True)
            self._role_gain_targets = out
        return self._role_gain_targets

    def _role_gain_memo(self):
        """Scan-local plans and verdicts of the bound-role gain selectors, reset with the catalog requirements."""
        indexes, _ = self.prefilter_indexes()
        memo = indexes.get("k8s_role_gain")
        if memo is None:
            memo = indexes["k8s_role_gain"] = {"plans": {}, "gain": {}, "bindings": None}
        return memo

    def _role_gain_plan(self, target, memo):
        """Target-only part of _bound_role_gain: the role rules applicable in the target namespace, the bind
        request and the ordered concrete probes some role rule grants."""
        plans = memo["plans"]
        if target.id in plans:
            return plans[target.id]
        ns = target.attrs["namespace"]
        shared = self._role_gain_rules(target.attrs["role_key"], ns == "*", memo)
        if shared is None:
            plans[target.id] = None
            return None
        role_rules, bind_req, probes = shared
        plan = plans[target.id] = (role_rules, bind_req, (ns, target.attrs["role_name"], None),
                                   tuple(((ns, name, None), req) for name, req in probes))
        return plan

    def _role_gain_rules(self, role_key, cluster_wide, memo):
        """Role rules, bind request and probes of one role; they depend only on whether the gain is cluster-wide
        (namespaced targets of the same role share them)."""
        cache = memo.setdefault("roles", {})
        key = (role_key, cluster_wide)
        if key in cache:
            return cache[key]
        role = self.roles.get(role_key)
        if role is None:
            cache[key] = None
            return None
        role_rules = []
        for rule in role["rules"]:
            if cluster_wide:
                role_rules.append(rule)
                continue
            namespaced_resources = [res for res in as_list(rule.get("resources"))
                                    if str(res).partition("/")[0] not in CLUSTER_SCOPED]
            if namespaced_resources:
                role_rules.append({**rule, "resources": namespaced_resources, "nonResourceURLs": []})
        if not role_rules:
            cache[key] = None
            return None
        resource = "clusterroles" if role["kind"] == "ClusterRole" else "roles"
        probes = set()
        for rule in role_rules:
            names = as_list(rule.get("resourceNames")) or [None]
            for verb in as_list(rule.get("verbs")):
                for group in as_list(rule.get("apiGroups")):
                    for res in as_list(rule.get("resources")):
                        if "*" not in (verb, group, res) and "*/" not in str(res):
                            if not cluster_wide and str(res).partition("/")[0] in CLUSTER_SCOPED:
                                continue
                            probes.update((str(verb).lower(), str(group), str(res), name) for name in names)
        for catalog_key in self.catalog_keys:
            try:
                verb, group, resource_name, sub = catalog_key.split("|")
            except ValueError:
                continue
            if verb.startswith(PREFIX) or group == ANY_MATCH or resource_name == ANY_MATCH:
                continue
            resource_full = resource_name + ("/" + sub if sub else "")
            if not cluster_wide and resource_name in CLUSTER_SCOPED:
                continue
            probes.add((verb, group, resource_full, None))
        ordered = []
        for verb, group, resource_full, name in sorted(probes, key=repr):
            resource_name, _, sub = resource_full.partition("/")
            if not any(_rule_matches(rule, verb, group, resource_name, sub, name) is True for rule in role_rules):
                continue
            ordered.append((name, {"verb": verb, "api_group": group, "resource": resource_name,
                                   "_rbac_only": True, **({"subresource": sub} if sub else {})}))
        cache[key] = (role_rules, {"verb": "bind", "resource": resource, "api_group": "rbac.authorization.k8s.io"},
                      tuple(ordered))
        return cache[key]

    def _bound_role_gain(self, source, target, memo=None):
        """True only if the exact role supplies a concrete permission the source lacks."""
        if source is None or source.attrs.get("cluster") != target.attrs.get("cluster"):
            return False
        memo = self._role_gain_memo() if memo is None else memo
        key = (source.id, target.id)
        gains = memo["gain"]
        if key not in gains:
            gains[key] = self._bound_role_gain_uncached(source, target, memo)
        return gains[key]

    def _bound_role_gain_uncached(self, source, target, memo):
        plan = self._role_gain_plan(target, memo)
        if plan is None:
            return False
        role_rules, bind_req, bind_ref, probes = plan
        ns = target.attrs["namespace"]
        bind = self.check(source, bind_req, bind_ref)
        if bind is None:
            return False
        bind_uncertain = bind.confidence != "derived"
        incomplete = not all(self._complete(kind) for kind in
                             ("role", "clusterrole", "rolebinding", "clusterrolebinding"))
        possible = False
        for ref, req in probes:
            own = self.check(source, req, ref)
            if own is None:
                if incomplete:
                    return ("conditional", "source_rbac_inventory_incomplete")
                return ("conditional", "bind_permission_not_fully_resolved") if bind_uncertain else None
            if own.confidence != "derived":
                possible = True
        if possible:
            return ("conditional", "existing_rights_not_fully_resolved")
        def dimension_covers(have, want):
            have, want = set(map(str, as_list(have))), set(map(str, as_list(want)))
            return "*" in have or want <= have

        def rule_covers(have, want):
            if not all(dimension_covers(have.get(field), want.get(field))
                       for field in ("verbs", "apiGroups", "resources")):
                return False
            wanted_names = set(map(str, as_list(want.get("resourceNames"))))
            held_names = set(map(str, as_list(have.get("resourceNames"))))
            if not wanted_names and held_names:
                return False
            if wanted_names and held_names and not wanted_names <= held_names:
                return False
            return set(map(str, as_list(want.get("nonResourceURLs")))) <= set(map(str, as_list(have.get("nonResourceURLs"))))

        held_rules = [rule for bind_ns, rule, _ in self._rule_rows(source)
                      if rule is not None and (bind_ns is None or (ns != "*" and bind_ns == ns))]
        if all(any(rule_covers(held, wanted) for held in held_rules) for wanted in role_rules):
            return False
        return ("conditional", "role_rule_gain_not_fully_probed")

    def _role_binding_names(self, memo, kind, cluster, binding_ns, role):
        """Names of the collected (cluster)role bindings to one role, in collection order."""
        index = memo["bindings"]
        if index is None:
            index = {}
            for binding_kind in ("rolebinding", "clusterrolebinding"):
                for _, item in items(self.snapshot, binding_kind):
                    meta, ref = item.get("metadata") or {}, item.get("roleRef") or {}
                    binding_name = meta.get("name")
                    if not binding_name:
                        continue
                    try:
                        index.setdefault((binding_kind, _cluster(item), meta.get("namespace"), ref.get("kind"),
                                          ref.get("name")), []).append(binding_name)
                    except TypeError:  # unhashable native values: keep the original scan
                        index = False
                        break
                if index is False:
                    break
            memo["bindings"] = index
        if index is False:
            return self._role_binding_names_scan(kind, cluster, binding_ns, role)
        try:
            return index.get((kind, cluster, binding_ns, role["kind"], role["name"]), ())
        except TypeError:
            return self._role_binding_names_scan(kind, cluster, binding_ns, role)

    def _role_binding_names_scan(self, kind, cluster, binding_ns, role):
        out = []
        for _, item in items(self.snapshot, kind):
            meta, ref = item.get("metadata") or {}, item.get("roleRef") or {}
            if (_cluster(item), meta.get("namespace")) != (cluster, binding_ns):
                continue
            if (ref.get("kind"), ref.get("name")) != (role["kind"], role["name"]):
                continue
            if meta.get("name"):
                out.append(meta.get("name"))
        return out

    def _existing_rolebinding_gain(self, source, target, memo=None):
        """Require an existing binding to the selected role that can gain this subject."""
        role = self.roles.get(target.attrs["role_key"])
        if role is None or source is None:
            return False
        memo = self._role_gain_memo() if memo is None else memo
        cluster, ns = target.attrs["cluster"], target.attrs["namespace"]
        kind = "clusterrolebinding" if ns == "*" else "rolebinding"
        binding_ns = None if ns == "*" else ns
        possible = False
        for binding_name in self._role_binding_names(memo, kind, cluster, binding_ns, role):
            for verb in ("patch", "update"):
                grant = self.check(source, {"verb": verb, "resource": kind + "s",
                                            "api_group": "rbac.authorization.k8s.io"},
                                   (ns, binding_name, None))
                if grant is not None:
                    if grant.confidence == "derived":
                        return self._bound_role_gain(source, target, memo)
                    possible = True
        if possible:
            gain = self._bound_role_gain(source, target, memo)
            return False if gain is False else ("conditional", "existing_binding_write_not_fully_resolved")
        return False

    def targets_for(self, kind, selector):
        from .credential_evidence import ARGOCD_MOUNT, LEGACY_SA_TOKEN, CREATED_SA_TOKEN
        if kind == "k8s_remote_cluster" and selector.get("k8s_challenge_fact") == ARGOCD_MOUNT:
            return self._remote_clusters()
        if kind == "k8s_service_account" and selector.get("k8s_challenge_fact") in (LEGACY_SA_TOKEN, CREATED_SA_TOKEN):
            return [n for n in self.sas.values() if n.attrs.get("inventoried")]
        exact = self.exact_targets_for(kind, selector)
        if exact is not None:
            return exact
        variant = self.target_variant(kind, selector)
        if kind == "k8s_service_account":
            if variant is None and self._complete("serviceaccount"):
                return [n for n in self.sas.values() if n.attrs.get("inventoried")]
            return self.targets(kind)
        if variant is None:
            return self.targets(kind)
        if variant == "secret_credential":
            return self._secret_credentials()
        if variant == "verified_pivot":
            return [node for node in self.verified_pivot_targets.values() if node.kind == kind]
        nodes = self._cloud_identities().values()
        if variant == "kube2iam":
            return [n for n in nodes if n.attrs["binding"] == "kube2iam"]
        return [n for n in nodes if n.attrs["binding"] == "irsa"]

    def set_related(self, snapshots):
        self.related = RelatedClouds(snapshots)
        self.cloud, self._cloud_built = {}, False
        self.__dict__.pop("_kcc_project_policy_targets", None)
        self.__dict__.pop("_kcc_project_policy_ambiguous", None)

    def _cloud_node(self, binding, external, cluster, label, variant=None):
        nid = f"cloud:{binding}:{external}"
        node = self.cloud.get(nid)
        if node is None:
            node = self.cloud[nid] = Node(nid, "cloud_identity", "k8s", cluster, f"{label} {external}",
                                          attrs={"cluster": cluster, "binding": binding, "external_id": external,
                                                 "bound_sas": [], "variant": variant, "bound": ()})
            node.perm_key = (cluster, ())
        return node

    def _cloud_identities(self):
        if not self.__dict__.get("_cloud_built"):
            self._cloud_built = True
            for sa in self.sas.values():
                ann = sa.attrs.get("annotations") or {}
                for key, binding, label in (("eks.amazonaws.com/role-arn", "irsa", "IAM role"),
                                            ("iam.gke.io/gcp-service-account", "gke_workload_identity", "GCP SA"),
                                            ("azure.workload.identity/client-id", "azure_workload_identity", "Entra app")):
                    if ann.get(key):
                        node = self._cloud_node(binding, ann[key], sa.attrs["cluster"], label)
                        node.attrs["bound_sas"].append(sa.id)
            # AKS federation authorizes the projected token's issuer, subject,
            # and audience. The annotation is only webhook configuration;
            # a pod can request the exchange audience itself.
            if self.related.has("azure"):
                context = (self.snapshot.get("metadata") or {}).get("context")
                azure_clients = {str(n.attrs.get("client_id") or n.attrs.get("app_id") or "")
                                 for model in self.related.models["azure"] for n in model.principals.values()}
                for sa in self.sas.values():
                    if not sa.attrs.get("inventoried"):
                        continue
                    subject = f"system:serviceaccount:{sa.attrs['namespace']}:{sa.attrs['name']}"
                    for client_id in azure_clients - {""}:
                        if self.related.azure_fic(client_id, subject, (sa.attrs["cluster"], context)) is True:
                            node = self._cloud_node("azure_workload_identity", client_id,
                                                    sa.attrs["cluster"], "Entra app")
                            if sa.id not in node.attrs["bound_sas"]:
                                node.attrs["bound_sas"].append(sa.id)
            clusters = sorted(self.clusters) or ["cluster"]
            context = str((self.snapshot.get("metadata") or {}).get("context") or "")
            # EKS Pod Identity associations (eks:DescribePodIdentityAssociation) of the matching EKS cluster.
            for cluster in clusters:
                eks = self.related.eks_facts((cluster, context)) if self.related.has("aws") else None
                for assoc in (eks or {}).get("associations") or ():
                    if str(assoc.get("status") or "ACTIVE").upper() in ("DELETING", "DELETED"):
                        continue
                    # EKS first assumes roleArn with the pods.eks.amazonaws.com
                    # service principal. A targetRoleArn is a separate AWS role
                    # chain and must pass the AWS trust/permission evaluator.
                    role = assoc.get("roleArn")
                    if not (role and assoc.get("namespace") and assoc.get("serviceAccount")):
                        continue
                    node = self._cloud_node("eks_pod_identity", role, cluster, "IAM role")
                    sid = f"k8s:{cluster}:sa:{assoc['namespace']}:{assoc['serviceAccount']}"
                    if sid not in node.attrs["bound_sas"]:
                        node.attrs["bound_sas"].append(sid)
                    node.attrs.setdefault("associations", []).append(assoc.get("associationArn") or assoc.get("id"))
            self._node_identities()
            # Roles any SA could federate into (IRSA trust on an OIDC provider), from related AWS snapshots.
            for arn, (model, role) in sorted(self.related.aws_roles.items()):
                if self.related.oidc_subjects(model, role):
                    for cluster in clusters:
                        if f"cloud:irsa:{arn}" not in self.cloud:
                            self._cloud_node("irsa", arn, cluster, "IAM role", variant="oidc_wildcard")
            # kiam/kube2iam: roles requestable through pod annotations.
            for cluster in clusters:
                if not self.ns_annotations.get(cluster):
                    continue
                refs = set(self.related.aws_roles) | self.pod_roles.get(cluster, set())
                for ref in sorted(refs):
                    found = self.related.aws_role(ref)
                    external = found[1].id if found else ref
                    node = self._cloud_node("kube2iam", external, cluster, "IAM role", variant="kube2iam")
                    node.attrs["role_name"] = found[1].label if found else str(ref).rsplit("/", 1)[-1]
        return self.cloud

    def _node_identities(self):
        """Node cloud identities from related cloud snapshots: GKE node-pool SA, EKS node instance role, AKS kubelet
        identity. attrs.nodes lists the K8s nodes carrying it, attrs.imds the metadata reachability per node."""
        context = str((self.snapshot.get("metadata") or {}).get("context") or "")
        self.node_identity_unresolved = set()
        for node in sorted(self.nodes.values(), key=lambda n: n.id):
            provider_id = node.attrs.get("provider_id") or ""
            labels = node.attrs.get("labels") or {}
            found = []  # (binding, external id, label, imds state)
            if provider_id.startswith("gce://") and self.related.has("gcp"):
                project = provider_id[len("gce://"):].split("/", 1)[0]
                pool = self.related.gke_pool((node.attrs["cluster"], context), labels.get("cloud.google.com/gke-nodepool"), project)
                if pool:
                    found.append(("gke_node", pool[0], "GCP SA", pool[1]))
            elif provider_id.startswith("aws://") and self.related.has("aws"):
                instance = self.related.aws_instance(provider_id.rsplit("/", 1)[-1])
                if instance:
                    found += [("eks_node", role, "IAM role", instance[1]) for role in instance[0]]
            elif provider_id.startswith("azure://") and self.related.has("azure"):
                match = re.search(r"/resourcegroups/([^/]+)/", provider_id.lower())
                kubelet = self.related.aks_kubelet(match.group(1)) if match else None
                if kubelet:
                    found.append(("aks_kubelet", kubelet, "AKS kubelet identity", "open"))
            if not found:
                self.node_identity_unresolved.add(node.attrs["cluster"])
            for binding, external, label, state in found:
                ident = self._cloud_node(binding, external, node.attrs["cluster"], label)
                ident.attrs.setdefault("nodes", []).append(node.id)
                ident.attrs.setdefault("imds", {})[node.id] = state
        # EKS access entries (eks:DescribeAccessEntry {type}) of the node roles: k8s_nodes_mapped_to_cloud_identity.
        eks_by_cluster = {}
        for ident in self.cloud.values():
            if ident.attrs.get("binding") != "eks_node":
                continue
            cluster = ident.attrs["cluster"]
            if cluster not in eks_by_cluster:
                eks_by_cluster[cluster] = self.related.eks_facts((cluster, context))
            eks = eks_by_cluster[cluster] or {}
            name = str(ident.attrs["external_id"]).rsplit("/", 1)[-1]
            mine = [e for e in eks.get("entries") or () if str(e.get("principalArn") or "") == ident.attrs["external_id"]
                    or (str(e.get("principalArn") or "").rsplit("/", 1)[-1] == name and ":role/" in str(e.get("principalArn")))]
            typed = [e for e in mine if "type" not in (e.get("_coverage") or {})]
            ident.attrs["access_entry_types"] = sorted({str(e.get("type")) for e in typed if e.get("type")})
            ident.attrs["access_entry_state"] = "collected" if eks.get("entries_state") == "collected" and len(typed) == len(mine) else None
            ident.attrs["auth_mode"] = eks.get("auth_mode")

    def _node_identity_verdict(self, ident, source):
        """None (derived) / (confidence, why) / False for a node cloud identity and a technique source."""
        nodes = ident.attrs.get("nodes") or []
        if source is not None and source.kind == "k8s_node":
            return None if source.id in nodes else False
        if source is not None and source.attrs.get("cluster") not in (None, ident.attrs.get("cluster")):
            return False
        states = [ident.attrs.get("imds", {}).get(n) for n in nodes]
        if "hostnetwork" in str((self.current_entry or {}).get("id") or "") or "host_network" in str(
                (self.current_entry or {}).get("id") or ""):
            # hostNetwork pods are not intercepted by the GKE metadata server nor limited by the IMDS hop limit.
            return None if any(s != "blocked" for s in states) else False
        if "open" in states:
            return None  # a pod can be scheduled (nodeSelector) onto a node whose metadata is reachable
        if None in states:
            return ("conditional", "node_metadata_access_not_verified")
        if "concealed" in states:
            # GKE metadata server hides the node credential, and IMDSv2 with
            # a one-hop response limit blocks ordinary (non-hostNetwork) pods.
            # The hostNetwork route is evaluated by its separate technique.
            return False
        return False

    def _privileged_controller_write(self, source, pivot):
        """Create a controller, or modify one inventoried controller by name."""
        if source is None:
            return False
        namespaces = {p.get("pivot.namespace") for p in (pivot or ()) if p.get("pivot.namespace")}
        resources = (("deployments", "apps"), ("daemonsets", "apps"),
                     ("statefulsets", "apps"), ("replicasets", "apps"),
                     ("replicationcontrollers", ""), ("jobs", "batch"),
                     ("cronjobs", "batch"))
        uncertain = False
        for namespace in namespaces:
            for resource, group in resources:
                create = self.check(source, {"verb": "create", "resource": resource,
                                             "api_group": group, "namespace": namespace},
                                    (namespace, None, None))
                if create is not None:
                    if create.confidence == "derived":
                        return True
                    uncertain = True
                if resource == "jobs":
                    continue  # this contract has no jobs patch/update branch
                kind = MODIFIABLE_OBJECTS.get(resource)
                if kind is None:
                    continue
                status = inventory_status(self.snapshot, kind)
                if not status or unavailable(status):
                    uncertain = True
                    continue
                for _, obj in items(self.snapshot, kind):
                    meta = obj.get("metadata") or {}
                    if _cluster(obj) != source.attrs.get("cluster") or meta.get("namespace") != namespace:
                        continue
                    name = meta.get("name")
                    if not name:
                        continue
                    for verb in ("patch", "update"):
                        grant = self.check(source, {"verb": verb, "resource": resource,
                                                    "api_group": group, "namespace": namespace},
                                           (namespace, name, None))
                        if grant is not None:
                            if grant.confidence == "derived":
                                return True
                            uncertain = True
        return None if uncertain else False

    def join(self, node):
        """(public dict of the joined cloud principal, Grant) or None."""
        binding, external = node.attrs.get("binding"), node.attrs.get("external_id")
        if BINDING_PROVIDER.get(binding) == "aws":
            found = self.related.aws_role(external)
        elif binding == "gke_workload_identity":
            found = self.related.gcp_sa(external)
        elif binding == "gke_node":
            found = self.related.gcp_sa(external)
        elif binding in ("azure_workload_identity", "aks_identity_binding", "aks_kubelet"):
            found = self.related.azure_principal(external)
        else:
            found = None
        if not found:
            return None
        model, principal = found
        data = principal.public()
        data["attrs"] = {"related_snapshot": True, "provider": model.provider}
        return data, Grant("derived", [{"join": binding, "external_id": external, "related_provider": model.provider}])

    def cross_edges(self):
        out = []
        for node in self._cloud_identities().values():
            joined = self.join(node)
            if joined:
                out.append((node, joined[0], joined[1]))
        return out

    def entity(self, cluster):
        cache = self.__dict__.setdefault("_entities", {})
        if cluster not in cache:
            cache[cluster] = Node(f"k8s_cluster_admin:{cluster}", "k8s_cluster_admin", "k8s", cluster,
                                  f"cluster-admin of {cluster}", attrs={"cluster": cluster}, entity=True)
        return cache[cluster]

    def unknown_target_scopes(self, kind):
        from .credential_evidence import LEGACY_SA_TOKEN, CREATED_SA_TOKEN
        if kind == "gcp_verified_authority" and (self.current_selector or {}).get("k8s_kcc_project_policy_grant"):
            from .k8s_config_connector_project_policy import unknown_scopes
            return unknown_scopes(self)
        if (self.current_selector or {}).get("k8s_challenge_fact") in (LEGACY_SA_TOKEN, CREATED_SA_TOKEN):
            return {}
        if kind == "k8s_verified_authority":
            return {}
        if (self.current_selector or {}).get("k8s_challenge_fact"):
            return self.exact_unknown_target_scopes()
        if kind == "k8s_service_account":
            return unavailable(inventory_status(self.snapshot, "serviceaccount"))
        if kind == "k8s_node":
            status = inventory_status(self.snapshot, "node")
            return unavailable(status) if status else {c: "not_collected" for c in sorted(self.clusters)}
        if kind == "k8s_remote_cluster":
            status = inventory_status(self.snapshot, "secret_metadata")
            return unavailable(status) if status else {c: "not_collected" for c in sorted(self.clusters)}
        return {}

    def allowed_scopes(self, rule, source):
        if (self.current_entry or {}).get("id") == "k8s-configconnector-project-iam-grant":
            from .k8s_config_connector_project_policy import targets, unknown_scopes
            cluster = source.attrs.get("cluster")
            scopes = {target.scope for target in targets(self).values()
                      if target.attrs.get("cluster") == cluster}
            if isinstance(cluster, str) and "/locations/" in cluster:
                project = cluster.split("/locations/", 1)[0]
                scopes.update(scope for scope in unknown_scopes(self) if scope == project)
            return scopes
        if (self.current_entry or {}).get("id") == "k8s-configconnector-service-account-key":
            return {sa.scope for cloud in self.related.models["gcp"] for sa in cloud.sas.values()
                    if sa.attrs.get("resource")}
        # RBAC never crosses clusters, whatever the entry's scope rule says.
        cluster = source.attrs.get("cluster")
        cache = self.__dict__.setdefault("_allowed_cache", {})
        if cluster not in cache:
            cache[cluster] = {s for s in self._all_scopes() if s == cluster or s.startswith(f"{cluster}/")}
        return cache[cluster]

    def _all_scopes(self):
        if not hasattr(self, "_scopes_cache"):
            self._scopes_cache = {n.scope for n in self.principals.values()} | set(self.clusters) | {
                f"{cluster}/{ns}" for cluster, ns, *_ in self.secrets} | {
                f"{cluster}/{ns}" for cluster, namespaces in self.namespaces.items() for ns in namespaces} | {
                f"{cluster}/*" for cluster in self.clusters}
        return self._scopes_cache

    def sources(self):
        out = list(self.principals.values())
        if self.related.has("aws"):
            out += [n for n in sorted(self._cloud_identities().values(), key=lambda n: n.id) if n.attrs.get("binding") == "eks_node"]
        return out

    def source_matches(self, source, kinds, selector):
        if ((self.current_entry or {}).get("id") in (
                "k8s-nodes-replacement-pod-to-controlled-node",
                "k8s-nodes-pods-binding-pending-pod-to-controlled-node",
                "k8s-nodes-attract-pending-pod-to-controlled-node")
                and source.kind == "k8s_node"):
            # NodeRestriction does not turn a kubelet credential into the
            # non-node write authority these scheduling techniques require.
            return False
        technique = (self.current_selector or {}).get("k8s_challenge_fact")
        if technique and not self.exact_source_matches(technique, source):
            return False
        if kinds and source.kind not in as_list(kinds):
            return False
        entry_type = (selector or {}).get("eks_access_entry_type")
        if entry_type:
            if source.kind != "cloud_identity" or source.attrs.get("binding") != "eks_node":
                return False
            types = source.attrs.get("access_entry_types") or ()
            if types and entry_type not in types:
                return False  # access entry of another type; no entry / facts missing: decided by the target selector
        aggregated = (selector or {}).get("source_bound_to_aggregated_clusterrole")
        if aggregated and not any(self.roles.get(role, {}).get("aggregation_selectable") and role[1] is None
                                  and ((aggregated == "cluster" and ns is None)
                                       or (aggregated == "namespace" and ns is not None)
                                       or aggregated is True)
                                  for ns, role, ev in source.attrs.get("bound", ())):
            return False
        role = (selector or {}).get("k8s_node_role")
        if role:
            labels = source.attrs.get("labels") or {}
            if f"node-role.kubernetes.io/{role}" not in labels and not (role == "control-plane" and "node-role.kubernetes.io/master" in labels):
                return False
        return True

    def _ns_has_sa_with_host_scc(self, cluster, namespaces):
        """True, conditional, unknown, or False for an inventoried SA and exact SCC."""
        if not self._complete("serviceaccount") or not self._complete("namespace"):
            return None
        sccs = self.host_sccs.get(cluster) or {}
        if not sccs:
            return False
        conditional = False
        for sa in self.sas.values():
            namespace = sa.attrs.get("namespace")
            if (sa.attrs.get("cluster") != cluster or not sa.attrs.get("inventoried") or
                    namespace not in self.ns_inventoried.get(cluster, ()) or
                    (namespaces is not None and namespace not in namespaces)):
                continue
            for name, scc in sccs.items():
                direct = sa.attrs.get("user") in scc["users"] or bool(set(sa.attrs.get("groups") or ()) & set(scc["groups"]))
                grant = self.check(sa, {"verb": "use", "resource": "securitycontextconstraints",
                                        "api_group": "security.openshift.io", "namespace": namespace,
                                        "resource_name": name}, (namespace, name, None))
                if not direct and grant is None:
                    continue
                if scc["impact"] == "derived" and (direct or grant.confidence == "derived"):
                    return True
                conditional = True
        return "conditional" if conditional else False

    def _pod_index(self):
        """({(cluster, ns, sa): [pods]}, {(node, cluster): [pods]}), each list in self.pods order; rebuilt if self.pods grows.
        None when a key value is unhashable (callers then scan self.pods as before)."""
        cached = self.__dict__.get("_pod_index_cache")
        if cached is not None and cached[0] == len(self.pods):
            return cached[1]
        index = None
        try:
            by_sa, by_node = {}, {}
            for p in self.pods:
                by_sa.setdefault((p["cluster"], p["ns"], p["sa"]), []).append(p)
                by_node.setdefault((p["node"], p["cluster"]), []).append(p)
            index = (by_sa, by_node)
        except TypeError:
            index = None
        self._pod_index_cache = (len(self.pods), index)
        return index

    def _pods_for_sa(self, sa):
        index = self._pod_index()
        if index is not None:
            try:
                return list(index[0].get((sa.attrs["cluster"], sa.attrs["namespace"], sa.attrs["name"]), ()))
            except TypeError:
                pass
        return [p for p in self.pods if p["cluster"] == sa.attrs["cluster"] and p["ns"] == sa.attrs["namespace"] and p["sa"] == sa.attrs["name"]]

    def _pods_on_node(self, name, cluster):
        """Pods with p["node"] == name and p["cluster"] == cluster, in self.pods order."""
        index = self._pod_index()
        if index is not None:
            try:
                return index[1].get((name, cluster), ())
            except TypeError:
                pass
        return [p for p in self.pods if p["node"] == name and p["cluster"] == cluster]

    def _node_hosts_pod(self, node):
        index = self._pod_index()
        if index is not None:
            try:
                return (node.attrs["name"], node.attrs["cluster"]) in index[1]
            except TypeError:
                pass
        return any(p["node"] == node.attrs["name"] and p["cluster"] == node.attrs["cluster"] for p in self.pods)

    def selector(self, key, value, candidates, source, pivot=None):
        if key == "openshift_source_host_scc_path":
            if source is None:
                return {}
            cluster = source.attrs.get("cluster")
            if not self._complete("securitycontextconstraint"):
                return {tid: ("unknown", "securitycontextconstraint_inventory_incomplete") for tid in candidates}
            namespaces = {row.get("pivot.namespace") for row in pivot or () if isinstance(row, dict)}
            if not namespaces:
                return {}
            source_user = source.attrs.get("user")
            source_groups = set(source.attrs.get("groups") or ())
            if source.kind == "k8s_group":
                source_groups.add(source.attrs.get("name"))
            conditional = False
            for namespace in namespaces:
                for scc_name, scc in self.host_sccs.get(cluster, {}).items():
                    direct = source_user in scc["users"] or bool(source_groups & set(scc["groups"]))
                    grant = self.check(source, {"verb": "use", "resource": "securitycontextconstraints",
                                                "api_group": "security.openshift.io", "namespace": namespace,
                                                "resource_name": scc_name}, (namespace, scc_name, None))
                    if not direct and grant is None:
                        continue
                    if scc["impact"] == "derived" and (direct or grant.confidence == "derived"):
                        return dict.fromkeys(candidates)
                    conditional = True
            return ({tid: ("conditional", "host_scc_access_or_impact_conditional") for tid in candidates}
                    if conditional else {})
        if key == "openshift_unlabeled_existing_namespace":
            cluster = source.attrs.get("cluster") if source is not None else None
            names = {row.get("pivot.namespace") for row in pivot or () if isinstance(row, dict)}
            if any(ns in self.ns_inventoried.get(cluster, ()) and
                   "openshift.io/run-level" not in self.ns_labels.get((cluster, ns), {}) for ns in names):
                return dict.fromkeys(candidates)
            if names and not self._complete("namespace"):
                return {tid: ("unknown", "namespace_run_level_label_not_collected") for tid in candidates}
            return {}
        if key == "openshift_namespace_without_scc":
            cluster = source.attrs.get("cluster") if source is not None else None
            defaults = {"default", "kube-system", "kube-public", "openshift-node", "openshift-infra", "openshift"}
            if pivot is None:
                if not self._complete("namespace"):
                    return {tid: ("unknown", "namespace_inventory_incomplete") for tid in candidates}
                # A fixed namespace alternative may refer to a project that is absent.
                # Require the same workload-create permission on one inventoried project.
                resources = (("pods", ""), ("deployments", "apps"), ("daemonsets", "apps"),
                             ("statefulsets", "apps"), ("replicasets", "apps"),
                             ("replicationcontrollers", ""), ("jobs", "batch"),
                             ("cronjobs", "batch"))
                for ns in defaults & self.ns_inventoried.get(cluster, set()):
                    for resource, group in resources:
                        grant = self.check(source, {"verb": "create", "resource": resource,
                                                    "api_group": group, "namespace": ns}, (ns, None, None))
                        if grant is not None:
                            return dict.fromkeys(candidates)
                return {}
            names = {row.get("pivot.namespace") for row in pivot if isinstance(row, dict)}
            if any(ns in self.ns_inventoried.get(cluster, ()) and
                   (ns in defaults or "openshift.io/run-level" in self.ns_labels.get((cluster, ns), {}))
                   for ns in names):
                return dict.fromkeys(candidates)
            if names and not self._complete("namespace"):
                return {tid: ("unknown", "namespace_run_level_label_not_collected") for tid in candidates}
            return {}
        if key == "k8s_pod_access_path":
            if source is None:
                return {}
            if not inventory_status(self.snapshot, "pod"):
                return {tid: ("unknown", "pod_inventory_not_collected") for tid in candidates}
            routes = {
                "modify_image": (("patch", ""), ("update", "")),
                "exec": (("create", "exec"),),
                "exec_get_websocket": (("get", "exec"),),
                "attach": (("create", "attach"),),
                "ephemeral_container": (("patch", "ephemeralcontainers"), ("update", "ephemeralcontainers")),
            }
            if value not in routes:
                return {}
            out = {}
            for tid, target in candidates.items():
                if target.kind != "k8s_service_account" or target.attrs.get("cluster") != source.attrs.get("cluster"):
                    continue
                for pod in self._pods_for_sa(target):
                    if not pod["name"] or pod["deleting"] or pod["phase"] in ("Succeeded", "Failed", "Pending"):
                        continue
                    grants = [self._name_shared_check(source, {"verb": verb, "resource": "pods", "subresource": sub,
                                                              "namespace": pod["ns"]}, (pod["ns"], pod["name"], None))
                              for verb, sub in routes[value]]
                    grants = [grant for grant in grants if grant is not None]
                    if not grants:
                        continue
                    if pod["phase"] != "Running":
                        verdict = ("unknown", "pod_phase_not_collected")
                    elif value == "attach" and not pod["stdin_containers"]:
                        continue
                    elif value == "attach" and not set(pod["stdin_containers"]) & set(pod["running_containers"]):
                        verdict = ("unknown", "interactive_container_running_not_recorded")
                    elif pod["automount_disabled"] and not pod["token_volumes"]:
                        continue
                    elif not pod["token_volumes"]:
                        verdict = ("unknown", "pod_service_account_token_volume_not_recorded")
                    elif value != "ephemeral_container" and not any(
                            has_token for name, has_token in pod["token_mounts"].items()
                            if value != "attach" or name in pod["stdin_containers"]):
                        verdict = ("unknown", "service_account_token_mount_not_recorded")
                    else:
                        verdict = ("conditional", "pod_access_runtime_conditions") if value == "attach" else None
                    if any(grant.confidence != "derived" for grant in grants) and verdict is None:
                        verdict = ("conditional", "pod_permission_not_fully_resolved")
                    previous = out.get(tid)
                    if tid not in out or (previous is not None and previous[0] == "unknown" and
                                          (verdict is None or verdict[0] != "unknown")):
                        out[tid] = verdict
                    if verdict is None:
                        break
                if tid not in out and not self._complete("pod"):
                    out[tid] = ("unknown", "pod_inventory_incomplete")
            return out
        if key == "k8s_websocket_exec_get_usable":
            cluster = source.attrs.get("cluster") if source is not None else None
            raw_version = self.server_versions.get(cluster, "")
            match = re.match(r"^v?(\d+)\.(\d+)(?:\.|$)", raw_version)
            if match and (int(match.group(1)), int(match.group(2))) < (1, 35):
                return dict.fromkeys(candidates)
            for _, pod in items(self.snapshot, "pod"):
                if _cluster(pod) != cluster or (pod.get("metadata") or {}).get("namespace") != "kube-system":
                    continue
                for container in as_list((pod.get("spec") or {}).get("containers")):
                    if not isinstance(container, dict) or "kube-apiserver" not in str(container.get("image") or ""):
                        continue
                    flags = " ".join(str(arg) for arg in as_list(container.get("command")) + as_list(container.get("args")))
                    if re.search(r"(?:^|[=,\s])AuthorizePodWebsocketUpgradeCreatePermission=false(?:[,\s]|$)", flags):
                        return {tid: ("conditional", "api_server_websocket_create_gate_disabled") for tid in candidates}
            reason = "websocket_create_feature_gate_not_recorded" if match else "kubernetes_server_version_not_collected"
            return {tid: ("unknown", reason) for tid in candidates}
        if key == "k8s_mutating_admission_policy_served":
            cluster = source.attrs.get("cluster") if source is not None else None
            advertised = self.admission_api_resources.get(cluster)
            if advertised is None:
                return {tid: ("unknown", "mutating_admission_api_discovery_not_collected") for tid in candidates}
            if {"mutatingadmissionpolicies", "mutatingadmissionpolicybindings"} <= advertised:
                return dict.fromkeys(candidates)
            return {}
        if key == "k8s_kcc_project_policy_grant":
            from .k8s_config_connector_project_policy import select
            return select(self, candidates, source) if value is True else {}
        if key == "k8s_kcc_service_account_key_path":
            from .k8s_config_connector_key import select
            return select(self, candidates, source) if value is True else {}
        if key == "k8s_aggregated_rolebinding_namespace":
            if source is None:
                return {}
            cluster = source.attrs.get("cluster")
            namespaces = {ns for ns, role, _ in source.attrs.get("bound", ())
                          if ns and role[0] == cluster and role[1] is None
                          and self.roles.get(role, {}).get("aggregation_selectable")}
            selected = {}
            for tid, target in candidates.items():
                ns = target.attrs.get("namespace")
                if target.attrs.get("cluster") != cluster or ns not in namespaces:
                    continue
                pods = self.check(source, {"verb": "create", "resource": "pods", "_rbac_only": True},
                                  (ns, None, None))
                tokens = self.check(source, {"verb": "create", "resource": "serviceaccounts",
                                             "subresource": "token", "_rbac_only": True},
                                    (ns, target.attrs.get("name"), None))
                if pods is not None and pods.confidence == "derived" and tokens is not None and tokens.confidence == "derived":
                    continue
                selected[tid] = None
            return selected
        if key == "k8s_aggregation_new_role_path":
            if source is None:
                return {}
            cluster = source.attrs.get("cluster")
            complete = self._complete("clusterrole")
            possible, uncertain = False, False
            for bound_ns, rule, _ in self._rule_rows(source):
                if bound_ns is not None or rule is None:
                    continue
                if _rule_matches(rule, "escalate", "rbac.authorization.k8s.io",
                                 "clusterroles", "", None) is False:
                    continue
                names = [str(name) for name in as_list(rule.get("resourceNames"))]
                if not names:
                    possible = True
                    break
                if not complete:
                    uncertain = True
                    continue
                if any(re.fullmatch(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?", name)
                       and (cluster, None, name) not in self.roles for name in names):
                    possible = True
                    break
            if possible:
                return dict.fromkeys(candidates)
            if uncertain:
                return {tid: ("unknown", "clusterrole_names_not_fully_collected") for tid in candidates}
            return {}
        if key == "k8s_csr_same_name_path":
            if source is None:
                return {}
            reads, approvals = [], []
            for bound_ns, rule, _ in self._rule_rows(source):
                if bound_ns is not None or rule is None:
                    continue
                names = set(map(str, as_list(rule.get("resourceNames"))))
                if any(_rule_matches(rule, verb, "certificates.k8s.io", "certificatesigningrequests", "", None)
                       is not False for verb in ("get", "list", "watch")):
                    reads.append(names)
                if any(_rule_matches(rule, verb, "certificates.k8s.io", "certificatesigningrequests", "approval", None)
                       is not False for verb in ("update", "patch")):
                    approvals.append(names)
            compatible = [(read, approval) for read in reads for approval in approvals
                          if not read or not approval or read & approval]
            if any(not read and not approval for read, approval in compatible):
                return dict.fromkeys(candidates)
            if compatible:
                # CSR objects are not collected, so a resourceNames-limited
                # permission cannot establish that the chosen name is free.
                return {tid: ("unknown", "new_csr_name_availability_not_collected") for tid in candidates}
            return {}
        if key == "k8s_csr_sa_subject":
            out = {}
            for tid, target in candidates.items():
                if target.kind != "k8s_service_account" or not target.attrs.get("binding_ref"):
                    continue
                if any(self.roles.get(role, {}).get("rules") for _ns, role, _ in target.attrs.get("bound", ())):
                    out[tid] = None
                elif not all(self._complete(kind) for kind in ("role", "clusterrole", "rolebinding", "clusterrolebinding")):
                    out[tid] = ("unknown", "service_account_binding_role_not_collected")
            return out
        if key == "k8s_bound_role_gain":
            memo = self._role_gain_memo()
            return {tid: verdict for tid, target in candidates.items()
                    if target.id in self._bound_role_gain_targets()
                    and target.attrs.get("namespace") != "*"
                    and (verdict := self._bound_role_gain(source, target, memo)) is not False}
        if key == "k8s_constrained_impersonation_gain":
            return {tid: verdict for tid, target in candidates.items()
                    if (verdict := self._constrained_impersonation_gain(source, target, str(value))) is not False}
        if key == "k8s_dangling_sa_permission_gain":
            return {tid: verdict for tid, target in candidates.items()
                    if (verdict := self._dangling_sa_binding_gain(source, target)) is not False}
        if key == "k8s_cluster_admin_role_exists":
            out = {}
            for tid, target in candidates.items():
                role = self.roles.get((target.attrs.get("cluster"), None, "cluster-admin"))
                if role is None:
                    if not self._complete("clusterrole"):
                        out[tid] = ("unknown", "cluster_admin_clusterrole_not_collected")
                    continue
                rules = role["rules"]
                sa_name = target.attrs.get("name")
                if any(_rule_matches(rule, "create", "", "pods", "", None) is True for rule in rules) or any(
                        _rule_matches(rule, "create", "", "serviceaccounts", "token", sa_name) is True
                        for rule in rules):
                    out[tid] = None
            return out
        if key == "k8s_existing_rolebinding_gain":
            memo = self._role_gain_memo()
            return {tid: verdict for tid, target in candidates.items()
                    if target.id in self._bound_role_gain_targets()
                    and target.attrs.get("namespace") != "*"
                    and (verdict := self._existing_rolebinding_gain(source, target, memo)) is not False}
        if key == "k8s_clusterrolebinding_gain":
            memo = self._role_gain_memo()
            return {tid: verdict for tid, target in candidates.items()
                    if target.id in self._bound_role_gain_targets()
                    and target.attrs.get("namespace") == "*"
                    and (verdict := self._bound_role_gain(source, target, memo)) is not False}
        if key == "k8s_existing_clusterrolebinding_gain":
            memo = self._role_gain_memo()
            return {tid: verdict for tid, target in candidates.items()
                    if target.id in self._bound_role_gain_targets()
                    and target.attrs.get("namespace") == "*"
                    and (verdict := self._existing_rolebinding_gain(source, target, memo)) is not False}
        if key == "k8s_verified_pivot":
            from .k8s_verified_pivots import select
            return select(self, value, candidates, source, pivot)
        if key == "k8s_helm_values_rbac":
            if source is None:
                return None
            return {target_id: ("conditional", "reviewed_helm_values_to_rbac_grant")
                    for target_id in candidates
                    if (record := self.helm_values_rbac_records.get(target_id))
                    and record["SourceId"] == source.id}
        if key == "k8s_challenge_fact":
            from .credential_evidence import (ARGOCD_MOUNT, LEGACY_SA_TOKEN, CREATED_SA_TOKEN,
                                              argocd_credential, legacy_sa_token_credential)
            if value in (LEGACY_SA_TOKEN, CREATED_SA_TOKEN):
                if source is None:
                    return None
                out = {}
                for target_id, target in candidates.items():
                    cluster = target.attrs.get("cluster")
                    records = self.exact_evidence.get((value, source.id, target.kind, target_id, cluster), ())
                    if (self.exact_status.get(cluster) in ("collected", "empty") and len(records) == 1
                            and legacy_sa_token_credential(self, records[0], source, target,
                                                           created=value == CREATED_SA_TOKEN)):
                        out[target_id] = ("conditional", "reviewed_usable_legacy_service_account_token")
                return out
            if value == ARGOCD_MOUNT:
                if source is None:
                    return None
                out = {}
                for target_id, target in candidates.items():
                    cluster = target.attrs.get("cluster")
                    records = self.exact_evidence.get((value, source.id, target.kind, target_id, cluster), ())
                    if not records:
                        continue
                    if (self.exact_status.get(cluster) in ("collected", "empty") and len(records) == 1
                            and argocd_credential(self, records[0], source, target)):
                        out[target_id] = ("conditional", "exact_admitted_mount_and_remote_credential")
                    elif any(record.get("Status") != "disproven" for record in records):
                        out[target_id] = ("unknown", "remote_credential_or_admission_unverified")
                return out
            return self.exact_selector(value, candidates, source)
        if key == "k8s_nodes_mapped_to_cloud_identity":
            if source is None or source.kind != "cloud_identity" or source.attrs.get("binding") != "eks_node":
                return {}
            mapped = [n for n in source.attrs.get("nodes") or () if n in candidates]
            if source.attrs.get("access_entry_state") != "collected":
                return None  # EKS access entries of the cluster not in a related AWS snapshot
            if any(t in ("EC2_LINUX", "EC2_WINDOWS") for t in source.attrs.get("access_entry_types") or ()):
                return dict.fromkeys(mapped)
            if source.attrs.get("auth_mode") == "API":
                return {}  # API-only authentication ignores aws-auth: without a node access entry the role is not mapped
            return {n: ("conditional", "eks_node_mapping_via_aws_auth_not_collected") for n in mapped}
        if key == "k8s_node_cloud_identity":
            self._cloud_identities()
            cluster = source.attrs.get("cluster") if source is not None else None
            out = {}
            for tid, n in candidates.items():
                if n.attrs.get("binding") not in NODE_BINDINGS:
                    continue
                verdict = self._node_identity_verdict(n, source)
                if verdict is not False:
                    out[tid] = verdict
            if not out and (cluster is None or cluster in getattr(self, "node_identity_unresolved", {cluster})):
                return None  # node identity not resolvable without the related cloud snapshot: unresolved
            return out
        pods_known = bool(inventory_status(self.snapshot, "pod"))
        if key == "k8s_sa_has_legacy_token_secret":
            if not self._complete("secret_metadata"):
                from .credential_evidence import LEGACY_SA_TOKEN, CREATED_SA_TOKEN
                if (self.current_selector or {}).get("k8s_challenge_fact") in (LEGACY_SA_TOKEN, CREATED_SA_TOKEN):
                    return {}
                return None
            return {tid: None for tid, n in candidates.items()
                    if n.attrs.get("name") in self.legacy_tokens.get((n.attrs.get("cluster"), n.attrs.get("namespace")), ())}
        if key == "openshift_namespace_has_sa_with_host_scc":
            clusters = {source.attrs.get("cluster")} if source is not None else {n.attrs.get("cluster") for n in candidates.values()}
            if clusters and all(self._is_openshift(c) is False for c in clusters):
                return {}  # not OpenShift: no SCCs exist, the technique does not apply
            if not self._complete("securitycontextconstraint"):
                return None  # securitycontextconstraints not collected (or incomplete)
            if value == "{pivot.namespace}":
                if not pivot:
                    return {}
                namespaces = {p["pivot.namespace"] for p in pivot if "pivot.namespace" in p}
            else:
                namespaces = None if value in ("*", True) else {value}
            verdicts = {c: self._ns_has_sa_with_host_scc(c, namespaces) for c in clusters}
            return {tid: (None if verdicts[n.attrs.get("cluster")] is True else
                          ("conditional", "host_scc_impact_conditional") if verdicts[n.attrs.get("cluster")] == "conditional" else
                          ("unknown", "serviceaccount_or_namespace_inventory_incomplete"))
                    for tid, n in candidates.items() if verdicts.get(n.attrs.get("cluster")) is not False}
        if key == "k8s_sa_in_namespace":
            if value in ("*", "{target.namespace}"):
                return dict.fromkeys(candidates)
            wanted = source.attrs.get("namespace") if value == "{source.namespace}" else value
            return {tid: None for tid, n in candidates.items() if n.attrs.get("namespace") == wanted}
        if key == "any_principal_in_scope":
            return dict.fromkeys(candidates)
        if key == "same_as_source":
            return {source.id: None} if source.id in candidates else {}
        if key == "exclude_names":
            names = set(as_list(value))
            return {tid: None for tid, n in candidates.items() if n.attrs.get("name") not in names}
        if key == "k8s_sa_used_by_pending_pod":
            if not pods_known:
                return None
            out = {}
            technique = (self.current_entry or {}).get("id")
            for tid, n in candidates.items():
                if n.kind != "k8s_service_account":
                    continue
                pods = [p for p in self._pods_for_sa(n) if not p["node"] and not p["deleting"]]
                pending = [p for p in pods if p["phase"] == "Pending"]
                if pending and technique == "k8s-nodes-pods-binding-pending-pod-to-controlled-node":
                    pending = [p for p in pending if any(self._name_shared_check(source, {
                        "verb": "create", "resource": resource, "subresource": sub,
                        "namespace": p["ns"]}, (p["ns"], p["name"], None)) is not None
                        for resource, sub in (("pods", "binding"), ("bindings", None)))]
                elif pending and technique == "k8s-nodes-attract-pending-pod-to-controlled-node":
                    node_grants = [grant for sub in (None, "status") for verb in ("patch", "update")
                                   if (grant := self.check(source, {
                        "verb": verb, "resource": "nodes", "subresource": sub,
                        "namespace": "*"}, (None, None, None))) is not None]
                    node_write = any(grant.confidence == "derived" for grant in node_grants)
                    if not node_write:
                        pending = [p for p in pending if any(self._name_shared_check(source, {
                            "verb": verb, "resource": "pods", "subresource": "status",
                            "namespace": p["ns"]}, (p["ns"], p["name"], None)) is not None
                            for verb in ("patch", "update"))]
                    if not pending and node_grants:
                        out[tid] = ("conditional", "node_write_name_must_match_controlled_node")
                if pending:
                    out[tid] = None
                elif any(p["phase"] is None for p in pods):
                    out[tid] = ("unknown", "pending_pod_phase_not_collected")
            return out
        if key == "k8s_node_hosting_pod_of_source":
            if source is None or source.kind != "k8s_service_account":
                return {}
            if not pods_known:
                return None
            hosts = {p["node"] for p in self._pods_for_sa(source) if p["node"] and p["running"]}
            return {tid: None for tid, n in candidates.items() if n.kind == "k8s_node" and n.attrs.get("name") in hosts}
        if key == "k8s_sa_namespace_absent":
            complete = self._complete("namespace")
            out = {}
            for tid, n in candidates.items():
                cluster, ns = n.attrs.get("cluster"), n.attrs.get("namespace")
                if n.kind != "k8s_service_account" or n.attrs.get("inventoried") or not (
                        n.attrs.get("binding_ref") or (cluster, ns, n.attrs.get("name")) in self.scc_users):
                    continue
                if ns in self.ns_inventoried.get(cluster, ()):
                    continue
                # An SCC users[] entry is only a useful privilege path when the
                # referenced SCC grants host access. A binding must resolve to
                # rules and add a right the source does not already hold.
                host_scc = bool(set(self.scc_users.get((cluster, ns, n.attrs.get("name")), ())) &
                                set(self.host_sccs.get(cluster, ())))
                binding_gain = self._dangling_sa_binding_gain(source, n) if n.attrs.get("binding_ref") else False
                if not host_scc and binding_gain is False:
                    continue
                out[tid] = None if complete else ("unknown", "namespace_inventory_incomplete")
                if complete and not host_scc and binding_gain is not None:
                    out[tid] = binding_gain
            return out
        if key == "k8s_sa_named_in_scc_users":
            if self._complete("securitycontextconstraint"):
                return {tid: None for tid, n in candidates.items()
                        if (n.attrs.get("cluster"), n.attrs.get("namespace"), n.attrs.get("name")) in self.scc_users}
            clusters = {n.attrs.get("cluster") for n in candidates.values()}
            if clusters and all(self._is_openshift(c) is False for c in clusters):
                return {}
            return None
        if key == "k8s_sa_missing_in_host_scc_users":
            if self._complete("securitycontextconstraint"):
                out = {}
                sa_complete, ns_complete = self._complete("serviceaccount"), self._complete("namespace")
                for tid, n in candidates.items():
                    cluster, ns, name = n.attrs.get("cluster"), n.attrs.get("namespace"), n.attrs.get("name")
                    if n.attrs.get("inventoried") or not set(self.scc_users.get((cluster, ns, name), ())) & set(
                            self.host_sccs.get(cluster, ())):
                        continue
                    if ns_complete and ns not in self.ns_inventoried.get(cluster, ()):
                        continue  # the source cannot create the named SA in an absent namespace
                    out[tid] = (None if sa_complete and ns_complete else
                                ("unknown", "serviceaccount_or_namespace_inventory_incomplete"))
                return out
            clusters = {n.attrs.get("cluster") for n in candidates.values()}
            if clusters and all(self._is_openshift(c) is False for c in clusters):
                return {}
            return None  # securitycontextconstraint not collected on an OpenShift (or undetermined) cluster
        if key == "k8s_secret_holds_cloud_credential":
            wanted = {"aws", "gcp", "azure"} if value is True or "any" in as_list(value) else set(as_list(value))
            out = {}
            for tid, n in candidates.items():
                if n.attrs.get("placeholder"):
                    out[tid] = ("unknown", "secret_metadata_not_collected")
                elif set(n.attrs.get("hint") or ()) & wanted:
                    out[tid] = ("conditional", "secret_content_not_verified")
            return out
        if key == "k8s_secret_holds_remote_cluster_credential":
            markers = REMOTE_CLUSTER_MARKERS if value is True else tuple(as_list(value))
            out = {}
            for tid, n in candidates.items():
                labels = n.attrs.get("labels") or {}
                for m in markers:
                    if _label_matches(labels, m) and (m != "cluster.x-k8s.io/cluster-name" or str(n.attrs.get("name")).endswith("-kubeconfig")):
                        out[tid] = None
                        break
            return out
        if key == "k8s_sa_absent_but_bound":
            statuses = inventory_status(self.snapshot, "serviceaccount")
            out = {}
            for tid, n in candidates.items():
                if n.kind != "k8s_service_account" or n.attrs.get("inventoried") or not n.attrs.get("binding_ref"):
                    continue
                cluster, ns = n.attrs.get("cluster"), n.attrs.get("namespace")
                if self._complete("namespace") and ns not in self.ns_inventoried.get(cluster, ()):
                    continue
                complete = statuses and all(st in ("collected", "empty") for st in statuses.values())
                out[tid] = None if complete else ("unknown", "serviceaccount_inventory_incomplete")
                if not self._complete("namespace") and ns not in self.ns_inventoried.get(cluster, ()):
                    out[tid] = ("unknown", "namespace_inventory_incomplete")
            return out
        if key == "kube2iam_namespace_permits_role":
            annotations = self.ns_annotations.get(source.attrs.get("cluster") if source else None, {})
            if not annotations:
                return None  # annotations not collected: unknown
            namespaces = [p["pivot.namespace"] for p in pivot or [] if "pivot.namespace" in p] if pivot else list(annotations)
            rules = [annotations[ns] for ns in namespaces if ns in annotations]
            if not rules:
                return {}
            out = {}
            for tid, n in candidates.items():
                verdict = _kube2iam_permits(rules, n.attrs.get("external_id"), n.attrs.get("role_name"))
                if verdict is False:
                    continue
                if verdict == "invalid_regex":
                    out[tid] = ("conditional", "kube2iam_permitted_regex_invalid")
                elif self.related.aws_role(n.attrs.get("external_id")) is None:
                    out[tid] = ("conditional", "kube2iam_role_not_in_related_snapshot")
                else:
                    out[tid] = None
            return out
        if key == "trust_allows_k8s_sa_oidc_subject":
            if source is None or source.kind != "k8s_service_account":
                return {}
            out = {}
            cluster_facts = self.related.eks_facts((source.attrs.get("cluster"),
                                                    (self.snapshot.get("metadata") or {}).get("context")))
            issuer = (cluster_facts or {}).get("oidc_issuer")
            if not issuer:
                return {tid: ("unknown", "eks_cluster_oidc_issuer_not_collected") for tid in candidates}
            for tid, n in candidates.items():
                arn = n.attrs.get("external_id")
                found = self.related.aws_role(arn)
                if found is None:
                    if self.related.aws_account_covered(arn):
                        continue  # the annotated role does not exist in the related account snapshot
                    out[tid] = ("conditional", "cloud_side_trust_not_verified")
                    continue
                subjects = self.related.oidc_subjects(*found, issuer=issuer)
                if any(_subject_matches(p, source.attrs["namespace"], source.attrs["name"]) for p in subjects):
                    # A matching subject is insufficient: the federated provider
                    # must be this cluster's issuer and the audience must admit STS.
                    out[tid] = ("conditional", "oidc_issuer_and_audience_not_verified")
            return out
        if key == "trust_allows_oidc_subject_wildcard":
            if not self.related.has("aws"):
                return None
            namespaces = [p["pivot.namespace"] for p in pivot or [] if "pivot.namespace" in p]
            cluster_facts = self.related.eks_facts(((source.attrs.get("cluster") if source else None),
                                                    (self.snapshot.get("metadata") or {}).get("context")))
            issuer = (cluster_facts or {}).get("oidc_issuer")
            if not issuer:
                return {tid: ("unknown", "eks_cluster_oidc_issuer_not_collected") for tid in candidates}
            out = {}
            create_new = (self.current_entry or {}).get("id") == "k8s-cloud-eks-irsa-create-matching-sa"
            for tid, n in candidates.items():
                found = self.related.aws_role(n.attrs.get("external_id"))
                if found is None:
                    continue
                subjects = self.related.oidc_subjects(*found, issuer=issuer)
                def applicable(pattern, namespace):
                    existing = [sa.attrs.get("name") for sa in self.sas.values()
                                if sa.attrs.get("cluster") == source.attrs.get("cluster")
                                and sa.attrs.get("namespace") == namespace and sa.attrs.get("inventoried")]
                    if create_new:
                        # A new ServiceAccount is useful only when the trust
                        # accepts a name not already represented by an SA.
                        if not _subject_matches(pattern, namespace):
                            return False
                        if pattern == "*":
                            return True
                        parts = pattern.split(":")
                        if len(parts) != 4:
                            return False
                        name_pattern = parts[3]
                        if "*" in name_pattern or "?" in name_pattern:
                            return True
                        return bool(re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", name_pattern)) and \
                            name_pattern not in existing
                    return any(_subject_matches(pattern, namespace, name) for name in existing)
                if any(applicable(p, ns) for p in subjects for ns in namespaces):
                    out[tid] = ("conditional", "oidc_issuer_and_audience_not_verified")
            return out
        if key == "gcp_workload_identity_user_granted_to_k8s_sa":
            if source is None or source.kind != "k8s_service_account":
                return {}
            if not self.related.has("gcp"):
                return None
            pool = self.related.gke_workload_pool((source.attrs.get("cluster"),
                                                   (self.snapshot.get("metadata") or {}).get("context")))
            if pool is None:
                return {tid: ("unknown", "gke_cluster_workload_pool_not_collected") for tid in candidates}
            if not pool:
                return {}
            out = {}
            for tid, n in candidates.items():
                email = n.attrs.get("external_id")
                verdict = self.related.gcp_wi_grant(email, source.attrs["namespace"], source.attrs["name"], pool)
                if verdict is None:
                    if not self.related.gcp_project_covered(email):
                        out[tid] = ("conditional", "cloud_side_trust_not_verified")
                elif verdict is not False:
                    out[tid] = None if verdict.confidence == "derived" else ("conditional", "binding_condition")
            return out
        if key == "azure_fic_matches_k8s_sa":
            if not self.related.has("azure"):
                return None
            out = {}
            for tid, n in candidates.items():
                subject = f"system:serviceaccount:{source.attrs.get('namespace')}:{source.attrs.get('name')}"
                verdict = self.related.azure_fic(n.attrs.get("external_id"), subject,
                                                 (source.attrs.get("cluster"),
                                                  (self.snapshot.get("metadata") or {}).get("context")))
                if verdict is not False:
                    out[tid] = None if verdict is True else ("conditional", verdict)
            return out
        if key == "k8s_node_schedulable":
            if (self.current_entry or {}).get("id") == "k8s-nodes-privileged-controller-create":
                controller = self._privileged_controller_write(source, pivot)
                if controller is False:
                    return {}
                if controller is None:
                    return {tid: ("unknown", "writable_controller_not_collected") for tid in candidates}
            if (self.current_entry or {}).get("id") == "k8s-nodes-namespace-psa-relabel":
                namespaces = {p.get("pivot.namespace") for p in (pivot or ()) if p.get("pivot.namespace")}
                labels = [self.ns_labels.get((source.attrs.get("cluster"), ns)) for ns in namespaces]
                if not any((row or {}).get("pod-security.kubernetes.io/enforce") in ("baseline", "restricted")
                           for row in labels):
                    if any(row is None for row in labels):
                        return {tid: ("unknown", "namespace_psa_label_not_collected") for tid in candidates}
                    return {}
            # Pod creators can set spec.nodeName and bypass the scheduler, so
            # cordoning alone does not make a node unreachable. A non-Ready
            # kubelet remains a possible route rather than a definite one.
            return {tid: (None if n.attrs.get("ready") == "True" else
                          ("conditional", "node_readiness_not_confirmed"))
                    for tid, n in candidates.items()}
        if key == "k8s_sa_name":
            names = {str(v) for v in as_list(value)}
            return {tid: None for tid, n in candidates.items() if n.attrs.get("name") in names}
        if key == "k8s_sa_used_by_pod_consuming_configmap":
            if not pods_known:
                return None
            return {tid: ("conditional", "configmap_consumer_executes_content_not_verified")
                    for tid, n in candidates.items() if n.kind == "k8s_service_account"
                    and any(p["configmaps"] and p["running"] for p in self._pods_for_sa(n))}
        if key in ("k8s_node_hosting_pods_with_sa", "k8s_sa_used_by_running_pod", "k8s_sa_used_by_controller_managed_pod"):
            if not pods_known:
                return None
            out = {}
            for tid, n in candidates.items():
                if n.kind == "k8s_node":
                    if self._node_hosts_pod(n):
                        out[tid] = None
                    continue
                pods = self._pods_for_sa(n)
                if key == "k8s_node_hosting_pods_with_sa" and source is not None and source.kind == "k8s_node":
                    pods = [p for p in pods if p["node"] == source.attrs["name"]]
                elif key == "k8s_node_hosting_pods_with_sa":
                    pods = [p for p in pods if p["node"]]
                elif key == "k8s_sa_used_by_running_pod":
                    pods = [p for p in pods if p["running"]]
                else:
                    pods = [p for p in pods if p["owned"] and not p["deleting"]]
                    if (self.current_entry or {}).get("id") == "k8s-nodes-replacement-pod-to-controlled-node" and source is not None:
                        broad_node_write = any(
                            (grant := self.check(source, {"verb": verb, "resource": "nodes",
                                                         "namespace": "*"}, (None, None, None))) is not None
                            and grant.confidence == "derived" for verb in ("patch", "update"))
                        if not broad_node_write:
                            actions = (("delete", "pods", ""), ("create", "pods", "eviction"),
                                       ("patch", "pods", ""), ("update", "pods", ""),
                                       ("patch", "pods", "status"), ("update", "pods", "status"))
                            pods = [p for p in pods if p["name"] and any(
                                self.check(source, {"verb": verb, "resource": resource,
                                                    "subresource": sub, "namespace": p["ns"]},
                                           (p["ns"], p["name"], None)) is not None
                                for verb, resource, sub in actions)]
                if key == "k8s_node_hosting_pods_with_sa":
                    if any(p["running"] and not p["deleting"] for p in pods):
                        out[tid] = None
                    elif any(p["phase"] in ("Pending", None) and not p["deleting"] for p in pods):
                        out[tid] = ("conditional", "pod_bound_to_node_but_not_running")
                elif pods:
                    out[tid] = None
                elif key == "k8s_sa_used_by_running_pod" and any(
                        p["phase"] is None for p in self._pods_for_sa(n)):
                    out[tid] = ("unknown", "pod_phase_not_collected")
            return out
        if key == "k8s_sa_used_by_interactive_pod":
            if not pods_known:
                return None
            out = {}
            for tid, n in candidates.items():
                if n.kind != "k8s_service_account":
                    continue
                for pod in self._pods_for_sa(n):
                    if not pod["stdin_containers"] or pod["phase"] in ("Succeeded", "Failed"):
                        continue
                    if pod["running"] and set(pod["stdin_containers"]) & set(pod["running_containers"]):
                        out[tid] = ("conditional", "interactive_process_accepts_commands_not_verified")
                        break
                    if pod["running"] or pod["phase"] is None:
                        out[tid] = ("unknown", "interactive_container_running_not_recorded")
            return out
        if key in ("k8s_node_hosting_pods_in_namespace", "k8s_node_hosting_privileged_pod_in_namespace",
                   "k8s_node_hosting_host_mount_pod_in_namespace"):
            if not pods_known:
                return None
            if value == "{pivot.namespace}":
                namespaces = {p["pivot.namespace"] for p in pivot or []} if pivot else None
            elif value == "*":
                namespaces = None
            else:
                namespaces = {value}
            out = {}
            for tid, n in candidates.items():
                for p in self._pods_on_node(n.attrs.get("name"), n.attrs.get("cluster")):
                    if namespaces is not None and p["ns"] not in namespaces:
                        continue
                    technique = (self.current_entry or {}).get("id") or ""
                    if technique in ("k8s-nodes-exec-into-host-privileged-pod",
                                     "k8s-nodes-exec-into-host-mount-pod"):
                        grant = self._name_shared_check(source, {"verb": "create", "resource": "pods",
                                                                 "subresource": "exec", "namespace": p["ns"]},
                                           (p["ns"], p["name"], None))
                        if grant is None:
                            continue
                    elif technique == "k8s-nodes-privileged-ephemeral-container":
                        grant = self._name_shared_check(source, {"verb": "patch", "resource": "pods",
                                                    "subresource": "ephemeralcontainers", "namespace": p["ns"]},
                                           (p["ns"], p["name"], None)) or self._name_shared_check(
                                               source, {"verb": "update", "resource": "pods",
                                                        "subresource": "ephemeralcontainers", "namespace": p["ns"]},
                                               (p["ns"], p["name"], None))
                        if grant is None:
                            continue
                    field = {"k8s_node_hosting_privileged_pod_in_namespace": "exec_privileged",
                             "k8s_node_hosting_host_mount_pod_in_namespace": "exec_host_mount"}.get(key)
                    if field is None:
                        if p["phase"] == "Running":
                            out[tid] = None
                            break
                        elif p["phase"] is None and tid not in out:
                            out[tid] = ("unknown", "pod_phase_not_collected")
                        continue
                    verdict = p.get(field)
                    if verdict is True:
                        out[tid] = None
                        break
                    if verdict and tid not in out:
                        out[tid] = ("unknown" if verdict == "pod_phase_not_collected" else "conditional", verdict)
            return out
        if key == "k8s_sa_cloud_binding":
            if source is None or source.kind != "k8s_service_account":
                return {}
            out = {}
            for tid, n in candidates.items():
                if n.attrs.get("binding") == value and source.id in n.attrs.get("bound_sas", []):
                    # With the related cloud snapshot the companion selector verifies the cloud side.
                    verified = self.related.has(BINDING_PROVIDER.get(value)) and value in (
                        "irsa", "gke_workload_identity", "azure_workload_identity")
                    if value == "eks_pod_identity":
                        # The association itself comes from the EKS API; the role trust must admit pods.eks.amazonaws.com.
                        trust = self.related.pods_trust(n.attrs.get("external_id"))
                        if trust is False:
                            continue
                        verified = trust is True
                    out[tid] = None if verified else ("conditional", "cloud_side_trust_not_verified")
            return out
        return None

    def managed_source(self, node):
        """Provider / control-plane managed subjects: reserved `system:` / `eks:` users and groups (except the
        groups and users any workload or person can act as), known control-plane users (kube-apiserver,
        kubelet-bootstrap, ...), and ServiceAccounts of kube-system or a provider-managed namespace (gke-managed-*,
        gmp-system, addon-manager labelled, ...) or carrying a provider marker, when every binding naming them is
        provider-created (`kubernetes.io/bootstrapping`, `addonmanager.kubernetes.io/mode`, `components.gke.io/*`,
        reserved `system:` binding to a `system:` role). A user-created binding naming the subject keeps it a source.
        They are never escalation sources; they stay targets (reaching system:masters is still admin)."""
        cache = self.__dict__.setdefault("_managed_cache", {})
        if node.id in cache:
            return cache[node.id]
        cluster = node.attrs.get("cluster")
        verdict = False
        if node.kind in ("k8s_user", "k8s_group"):
            name = str(node.attrs.get("name") or "")
            if name.startswith(MANAGED_SUBJECT_PREFIXES) and name not in ATTACKER_REACHABLE and \
                    not name.startswith(("system:serviceaccounts:", "system:node:", "system:serviceaccount:")):
                verdict = True
            elif name in CONTROL_PLANE_USERS:
                verdict = True
            if verdict:
                kind = "group" if node.kind == "k8s_group" else "user"
                verdict = all(self.binding_managed.get((cluster, f"{kind}:{name}"), [True])) or name.startswith(
                    MANAGED_SUBJECT_PREFIXES)  # reserved names cannot be held by customer credentials
        elif node.kind == "k8s_service_account":
            ns = str(node.attrs.get("namespace") or "")
            managed_ns = ns == "kube-system" or ns in MANAGED_NAMESPACES or ns.startswith(MANAGED_NAMESPACE_PREFIXES) \
                or (cluster, ns) in self.managed_ns
            if managed_ns or node.attrs.get("managed_meta"):
                flags = [f for key in (f"sa:{ns}:{node.attrs.get('name')}", f"user:{node.attrs.get('user')}")
                         for f in self.binding_managed.get((cluster, key), [])]
                verdict = all(flags) if flags else ns != "kube-system" or bool(node.attrs.get("managed_meta"))
        cache[node.id] = verdict
        return verdict

    def admin_targets(self, principal):
        if self.managed_source(principal):
            return []  # control-plane identities: not escalation sources (system:masters stays an admin target)
        for ns, rule, evidence in self._rules(principal):
            if rule is None or ns is not None:
                continue
            if "*" in as_list(rule.get("verbs")) and "*" in as_list(rule.get("resources")) and "*" in as_list(rule.get("apiGroups")) \
                    and not rule.get("resourceNames"):
                return [(self.entity(principal.attrs["cluster"]), Grant("derived", [evidence], permission_refs=[{"permission": "* *", "grant": evidence}]))]
        return []

    def scope_within(self, inner, outer):
        return inner == outer or inner.startswith(outer + "/")

    def scope_containers(self, inner):
        """{outer : scope_within(inner, outer)}: inner itself and every prefix ending right before a '/'."""
        if not isinstance(inner, str):
            return frozenset((inner,))
        return frozenset([inner] + [inner[:i] for i, ch in enumerate(inner) if ch == "/"])


def _kube2iam_permits(rules, arn, name):
    """True / False / 'invalid_regex' for a role against namespace annotations (kiam regex, kube2iam globs)."""
    values = [v for v in (str(arn or ""), str(name or "")) if v]
    invalid = False
    for rule in rules:
        regex = rule.get("permitted")
        if regex:
            try:
                compiled = re.compile(regex)
            except re.error:
                invalid = True
            else:
                if any(compiled.fullmatch(v) for v in values):
                    return True
        for pattern in rule.get("allowed_roles", ()):
            if any(fnmatch.fnmatchcase(v, pattern) for v in values):
                return True
    return "invalid_regex" if invalid else False


def _selector_matches(selector, labels):
    """LabelSelector against labels: True / False / None (labels unknown or unsupported operator)."""
    if not isinstance(selector, dict) or not selector:
        return True
    if labels is None:
        return None
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(str(key)) != str(value):
            return False
    for expr in as_list(selector.get("matchExpressions")):
        if not isinstance(expr, dict):
            return None
        key, op, values = str(expr.get("key")), expr.get("operator"), [str(v) for v in as_list(expr.get("values"))]
        if op == "In":
            ok = labels.get(key) in values
        elif op == "NotIn":
            ok = labels.get(key) not in values
        elif op == "Exists":
            ok = key in labels
        elif op == "DoesNotExist":
            ok = key not in labels
        else:
            return None
        if not ok:
            return False
    return True


def _rule_hits(rule, resources, operations=("CREATE", "UPDATE")):
    """An admission RuleWithOperations / NamedRuleWithOperations covers one of (api group, resource) on CREATE/UPDATE."""
    if not isinstance(rule, dict):
        return False
    ops = [str(o) for o in as_list(rule.get("operations"))]
    if not any(o == "*" or o in operations for o in ops):
        return False
    groups = [str(g) for g in as_list(rule.get("apiGroups"))]
    names = [str(r) for r in as_list(rule.get("resources"))]
    for group, resource in resources:
        if not any(g == "*" or g == group for g in groups):
            continue
        base, _, sub = resource.partition("/")
        for name in names:
            nbase, _, nsub = name.partition("/")
            if (nbase in ("*", base)) and ((not sub and not nsub) or nsub == "*" or (sub and nsub == sub)):
                return True
    return False


def _admission_match(match, resources, labels, default=False):
    """MatchResources of a CEL admission policy / binding: True / False / None (namespace labels unknown). An empty
    binding matchResources defers to the policy (default=True)."""
    rules = as_list(match.get("resourceRules"))
    if rules:
        if not any(_rule_hits(r, resources) for r in rules):
            return False
    elif not default:
        return False  # a policy without resourceRules matches nothing
    if any(_rule_hits(r, resources) for r in as_list(match.get("excludeResourceRules"))):
        return False
    return _selector_matches(match.get("namespaceSelector"), labels)


def _webhook_match(hook, resources, labels):
    if not any(_rule_hits(r, resources) for r in as_list(hook.get("rules"))):
        return False
    return _selector_matches(hook.get("namespaceSelector"), labels)


def _label_matches(labels, selector):
    key, eq, value = str(selector).partition("=")
    return key in labels and (not eq or str(labels[key]) == value)


def _aggregation_selector_satisfiable(selector):
    """Whether a new ClusterRole can carry labels matching one selector."""
    if not isinstance(selector, dict):
        return False
    constraints = {}
    for key, value in (selector.get("matchLabels") or {}).items():
        constraints.setdefault(str(key), {"required": True, "absent": False, "allowed": None,
                                          "forbidden": set()})["allowed"] = {str(value)}
    for expression in as_list(selector.get("matchExpressions")):
        if not isinstance(expression, dict) or not expression.get("key"):
            return False
        key, operator = str(expression["key"]), expression.get("operator")
        values = {str(value) for value in as_list(expression.get("values"))}
        state = constraints.setdefault(key, {"required": False, "absent": False,
                                             "allowed": None, "forbidden": set()})
        if operator == "In":
            state["required"] = True
            state["allowed"] = values if state["allowed"] is None else state["allowed"] & values
        elif operator == "NotIn":
            state["forbidden"].update(values)
        elif operator == "Exists":
            state["required"] = True
        elif operator == "DoesNotExist":
            state["absent"] = True
        else:
            return False
    for state in constraints.values():
        if state["required"] and state["absent"]:
            return False
        if state["allowed"] is not None and not state["allowed"] - state["forbidden"]:
            return False
    return True


def _rule_evidence(ns, rule, evidence):
    return {**dict(evidence), "namespace": ns, "rule": rule}


_MISSING = object()
# requirement field values -> requirement key; the key is a pure function of these fields.
_REQUIREMENT_KEYS = {}
_REQUIREMENT_KEYS_LIMIT = 1 << 14
_NO_NAMES_RULE = {}  # existence lookups for principals without resourceNames (rule only supplies names)

# Sealed (read-only) rules never change, so their normalized verb list is computed once. Entries keep the rule
# alive, so an id is never reused while cached; the table is cleared when it reaches its bound.
_SEALED_RULE_VERBS = {}
_SEALED_RULE_VERBS_LIMIT = 1 << 16


def _rule_verbs(rule):
    if type(rule) is FrozenDict:
        hit = _SEALED_RULE_VERBS.get(id(rule))
        if hit is not None and hit[0] is rule:
            return hit[1]
        verbs = [str(v).lower() for v in as_list(rule.get("verbs"))]
        if len(_SEALED_RULE_VERBS) >= _SEALED_RULE_VERBS_LIMIT:
            _SEALED_RULE_VERBS.clear()
        _SEALED_RULE_VERBS[id(rule)] = (rule, verbs)
        return verbs
    return [str(v).lower() for v in as_list(rule.get("verbs"))]


def _rule_matches(rule, verb, group, resource, sub, name, partial=False):
    """True, a condition string (partial match) or False."""
    verbs = _rule_verbs(rule)
    if verb.startswith(PREFIX):
        prefix = verb[len(PREFIX):]
        if "*" not in verbs and not any(v.startswith(prefix) for v in verbs):
            return False
    elif "*" not in verbs and verb not in verbs:
        return False
    groups = as_list(rule.get("apiGroups"))
    if group != ANY_MATCH and "*" not in groups and group not in groups:
        return False
    if resource == ANY_MATCH:
        # resource_match: any - any resource the rule names (resourceNames only narrow it further).
        return bool(as_list(rule.get("resources")))
    combined = f"{resource}/{sub}" if sub else resource
    ok = False
    for res in as_list(rule.get("resources")):
        res = str(res)
        if res == "*" or res == combined or (sub and res == f"*/{sub}"):
            ok = True
            break
        if partial and "{" in resource:
            ok = True
            break
    if not ok:
        return False
    names = as_list(rule.get("resourceNames"))
    if not names:
        return True
    if verb in NO_NAME_VERBS and not (verb == "create" and (sub or "/" in str(resource))):
        return False  # a create on a subresource (serviceaccounts/token, pods/exec, ...) carries the parent's name
    if partial:
        return True
    if name is None or name is ANY:
        return "restricted_by_resourceNames"
    return True if name in names else False


# ---- container-escape classification (catalog refresh, see SCHEMA_EXTENSIONS.md) -------------------------
# Verdicts: None = no node-escape primitive, True = derived, str = conditional reason id.
# hostNetwork / hostIPC alone and hostPID without SYS_PTRACE or privileged are NOT node escapes; writable
# /var/log (kubelet log symlink) is version dependent and not counted.
_RUNTIME_SOCKETS = ("/run/containerd/containerd.sock", "/run/docker.sock", "/run/crio/crio.sock", "/run/dockershim.sock",
                    "/run/k3s/containerd/containerd.sock", "/run/podman/podman.sock", "/run/buildkit/buildkitd.sock")
# Read access (even readOnly) exposes node credentials: mounting the path or any ancestor (or a credential subtree).
_CRED_LEAVES = ("/var/lib/kubelet/pki", "/var/lib/kubelet/kubeconfig", "/var/lib/kubelet/pods",
                "/var/lib/rancher/k3s/agent")
_CRED_SUBTREES = ("/var/lib/kubelet/pki", "/var/lib/rancher/k3s/agent")
_CRED_LEAVES_CONDITIONAL = ("/etc/kubernetes", "/etc/rancher/k3s")
# Write access yields code execution as host root (paths the host executes or consumes).
_WRITE_LEAVES = ("/etc/crontab", "/etc/cron.d", "/etc/systemd", "/etc/kubernetes/manifests", "/etc/sudoers.d",
                 "/etc/ld.so.preload", "/etc/passwd", "/etc/shadow", "/etc/profile.d", "/root/.ssh", "/usr/bin",
                 "/usr/sbin", "/usr/local/bin", "/usr/lib", "/bin", "/sbin", "/lib", "/lib64", "/opt/cni/bin",
                 "/var/spool/cron", "/proc/sys/kernel/core_pattern", "/sys/kernel/uevent_helper")
_WRITE_SUBTREES = ("/etc/cron.d", "/etc/systemd", "/etc/kubernetes/manifests", "/etc/sudoers.d", "/etc/profile.d",
                   "/root/.ssh", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/lib", "/bin", "/sbin", "/lib",
                   "/lib64", "/opt/cni/bin", "/var/spool/cron")
_WRITE_LEAVES_CONDITIONAL = ("/home", "/var/lib/docker", "/var/lib/containerd", "/sys/fs/cgroup")
_ESCAPE_CAPS = {"SYS_ADMIN": "cap_sys_admin_constrained_by_seccomp_apparmor", "SYS_MODULE": "kernel_module_loading_restricted",
                "ALL": "cap_sys_admin_constrained_by_seccomp_apparmor", "DAC_READ_SEARCH": "open_by_handle_at_blocked_by_seccomp"}


def _norm_path(path):
    path = "/" + str(path or "").strip().strip("/")
    path = re.sub(r"/+", "/", path)
    return "/run" + path[len("/var/run"):] if path == "/var/run" or path.startswith("/var/run/") else path


def _under(path, roots):
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def _ancestor_of(path, targets):
    return any(t == path or path == "/" or t.startswith(path + "/") for t in targets)


def _pod_containers(spec):
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for c in as_list(spec.get(key)):
            if isinstance(c, dict):
                yield c


def pod_escape_primitives(spec):
    """Return (privileged_verdict, host_mount_verdict) for a pod spec."""
    spec = spec or {}
    priv = None
    for c in _pod_containers(spec):
        sc = c.get("securityContext") or {}
        if sc.get("privileged") is True:
            return True, _host_mount_verdict(spec)
        caps = {str(x).upper().removeprefix("CAP_") for x in as_list((sc.get("capabilities") or {}).get("add"))}
        for cap, reason in _ESCAPE_CAPS.items():
            if cap in caps and priv is None:
                priv = reason
        if "SYS_PTRACE" in caps and spec.get("hostPID") and priv is None:
            priv = "ptrace_restricted_by_apparmor_or_yama"
    return priv, _host_mount_verdict(spec)


def active_pod_escape_primitives(spec, status):
    """Host escape primitives in containers that can currently accept exec."""
    if status.get("phase") not in ("Running", None):
        return None, None
    if status.get("phase") is None:
        privileged, mount = pod_escape_primitives(spec)
        reason = "pod_phase_not_collected"
        return (reason if privileged else None, reason if mount else None)
    active = {str(c.get("name") or "") for kind in (
        "containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses")
        for c in as_list(status.get(kind)) if isinstance(c, dict)
        and (c.get("state") or {}).get("running") is not None}
    if not active:
        privileged, mount = pod_escape_primitives(spec)
        reason = "active_container_not_recorded"
        return (reason if privileged else None, reason if mount else None)
    active_spec = {"volumes": spec.get("volumes") or []}
    for kind in ("containers", "initContainers", "ephemeralContainers"):
        active_spec[kind] = [c for c in as_list(spec.get(kind)) if isinstance(c, dict)
                             and str(c.get("name") or "") in active]
    return pod_escape_primitives(active_spec)


def _host_mount_verdict(spec):
    host = {v.get("name"): _norm_path((v.get("hostPath") or {}).get("path"))
            for v in as_list(spec.get("volumes")) if isinstance(v, dict) and isinstance(v.get("hostPath"), dict)}
    if not host:
        return None
    verdict = None
    for c in _pod_containers(spec):
        for m in as_list(c.get("volumeMounts")):
            if not isinstance(m, dict) or m.get("name") not in host:
                continue
            path, writable = host[m["name"]], not m.get("readOnly")
            if m.get("subPath") or m.get("subPathExpr"):
                verdict = verdict or "hostpath_subpath_narrows_mount"
                continue
            if _ancestor_of(path, _RUNTIME_SOCKETS) or _ancestor_of(path, _CRED_LEAVES) or _under(path, _CRED_SUBTREES):
                return True
            if writable and (_ancestor_of(path, _WRITE_LEAVES) or _under(path, _WRITE_SUBTREES)):
                return True
            if _ancestor_of(path, _CRED_LEAVES_CONDITIONAL) or _under(path, _CRED_LEAVES_CONDITIONAL):
                verdict = verdict or "node_credential_location_varies"
            elif writable and (_ancestor_of(path, _WRITE_LEAVES_CONDITIONAL) or _under(path, _WRITE_LEAVES_CONDITIONAL)):
                verdict = verdict or "host_write_needs_host_consumer"
    return verdict


def pod_configmap_refs(spec):
    """Names of ConfigMaps a pod consumes (volumes, projected volumes, envFrom, env valueFrom)."""
    spec, names = spec or {}, set()
    for v in as_list(spec.get("volumes")):
        if not isinstance(v, dict):
            continue
        if isinstance(v.get("configMap"), dict):
            names.add(v["configMap"].get("name"))
        for src in as_list((v.get("projected") or {}).get("sources")):
            if isinstance(src, dict) and isinstance(src.get("configMap"), dict):
                names.add(src["configMap"].get("name"))
    for c in _pod_containers(spec):
        for ef in as_list(c.get("envFrom")):
            if isinstance(ef, dict) and isinstance(ef.get("configMapRef"), dict):
                names.add(ef["configMapRef"].get("name"))
        for e in as_list(c.get("env")):
            ref = ((e or {}).get("valueFrom") or {}).get("configMapKeyRef") if isinstance(e, dict) else None
            if isinstance(ref, dict):
                names.add(ref.get("name"))
    names.discard(None)
    names.discard("kube-root-ca.crt")
    return sorted(names)
