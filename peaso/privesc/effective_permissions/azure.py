"""Azure RBAC + Entra ID effective permissions.

RBAC: role assignments x role definitions (Actions/NotActions, DataActions/
NotDataActions) with scope inheritance root -> management groups ->
subscription -> resource group -> resource, group membership (transitive),
ABAC conditions (standard form ``(!(ActionMatches{...}) ...) OR (...)``): actions the condition does not
name are unrestricted (derived), named ones -> conditional with the expression; deny assignments remove permissions (not
collected -> conditional).

Entra: directory role assignments (directoryScopeId '/', '/<objectId>' or
'/administrativeUnits/<id>') x directory role definitions
(rolePermissions.allowedResourceActions). Graph application permissions, owners,
PIM eligibility (conditional: needs activation; expired / revoked eligibilities are ignored; active
PIM assignments are ordinary directory role assignments), AUs and tenant settings are only evaluated when their
collections exist; otherwise the requirement is reported as globally unknown
(coverage + aggregated unknown edges).
"""
from __future__ import annotations

import re

from . import ANY, Grant, Model, Node, as_list, downgrade, glob_match, inventory_status, items, unavailable
from .exact_evidence import ExactEvidenceMixin

OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
UAA = "18d7d88d-d35e-4fb5-a5c3-7773c4a72d9d"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
EVERYONE = "00000000-0000-0000-0000-000000000000"
_EXACT_SCOPE_CREDENTIALS = {
    "azure-apim-gateway-config-credential": ("microsoft.apimanagement/service", (("microsoft.apimanagement/service/gateways/getconfiguration/action", True),)),
    "azure-appconfig-snapshot-credential": ("microsoft.appconfiguration/configurationstores", (("microsoft.appconfiguration/configurationstores/snapshots/read", True),)),
    "azure-automation-job-output-credential": ("microsoft.automation/automationaccounts", (("microsoft.automation/automationaccounts/jobs/output/read", False), ("microsoft.automation/automationaccounts/jobs/streams/read", False))),
    "azure-automation-runbook-source-credential": ("microsoft.automation/automationaccounts", (("microsoft.automation/automationaccounts/runbooks/content/read", False),)),
    "azure-acr-layer-credential": ("microsoft.containerregistry/registries", (("microsoft.containerregistry/registries/pull/read", True),)),
    "azure-storage-blob-content-credential": ("microsoft.storage/storageaccounts", (("microsoft.storage/storageaccounts/blobservices/containers/blobs/read", True),)),
}
BUILTIN_ROLES = {
    OWNER: ("Owner", [{"actions": ["*"]}]),
    CONTRIBUTOR: ("Contributor", [{"actions": ["*"], "notActions": [
        "Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/elevateAccess/Action",
        "Microsoft.Blueprint/blueprintAssignments/write", "Microsoft.Blueprint/blueprintAssignments/delete",
        "Microsoft.Compute/galleries/share/action", "Microsoft.Purview/consents/write", "Microsoft.Purview/consents/delete",
        "Microsoft.Resources/deploymentStacks/manageDenySetting/action", "Microsoft.Subscription/cancel/action",
        "Microsoft.Subscription/enable/action"]}]),
    UAA: ("User Access Administrator", [{"actions": ["*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"]}]),
    READER: ("Reader", [{"actions": ["*/read"]}]),
}
# Microsoft "who can reset passwords" matrix: roles a target may hold for each column.
RESET_MATRIX = {
    "non_admin_only": set(),
    "password_admin": {"directory readers", "guest inviter", "password administrator"},
    "helpdesk_admin": {"directory readers", "guest inviter", "helpdesk administrator", "message center reader",
                       "password administrator", "reports reader", "user experience success manager",
                       "usage summary reports reader"},
    "authentication_admin": {"authentication administrator", "directory readers", "guest inviter",
                             "message center reader", "password administrator", "reports reader",
                             "user experience success manager", "usage summary reports reader"},
    "user_admin": {"directory readers", "groups administrator", "guest inviter", "helpdesk administrator",
                   "message center reader", "password administrator", "reports reader", "user administrator",
                   "user experience success manager", "usage summary reports reader"},
    "privileged_auth_admin": None,  # every user
}
FACT_COLLECTIONS = {
    "graph_app_permission": "directory_app_role_assignment",
    "entra_owner_of": "directory_owner",
    "entra_pim_eligible_role": "directory_role_eligibility_schedule",
    "entra_tenant_setting": "directory_authorization_policy",
}
# Optional planes outside ARM / Graph directory (Fabric, Intune, entitlement management): requirements of these kinds
# are globally unknown until their collection exists (no load-time coverage entry: most tenants never collect them).
OPTIONAL_FACT_COLLECTIONS = {
    "fabric_workspace_role": "fabric_workspace_role_assignment",
    "intune_permission": "intune_role_assignment",
    "entra_catalog_role": "entitlement_role_assignment",
}
# Requirement kinds whose verdict depends on the principal itself, not only on its RBAC / directory role assignments.
PRINCIPAL_FACT_KINDS = ("graph_app_permission", "entra_owner_of", "entra_pim_eligible_role", "entra_tenant_setting",
                        "entra_group_member", "fabric_workspace_role", "intune_permission", "entra_catalog_role")
_TEMPLATE_PH = re.compile(r"(?<!\$)\{([^{}]+)\}")
_PRINCIPAL_FACT_SET = frozenset(PRINCIPAL_FACT_KINDS)  # isdisjoint(req) == not any(kind in req ...)
FABRIC_RANK = {"admin": 4, "member": 3, "contributor": 2, "viewer": 1}
ASSIGN_UAMI = "microsoft.managedidentity/userassignedidentities/assign/action"
AVD_USER_ROLE = "1d18fff3-a72a-46b5-b4a9-0b38a3cd7e63"  # Desktop Virtualization User (built-in)
# azure_consumer_of_pivot: binding kind -> (pivot resource type, data action a consumer reading it holds).
CONSUMER_READS = {
    "key_vault_reference": ("microsoft.keyvault/vaults", "microsoft.keyvault/vaults/secrets/getsecret/action"),
    "storage_content": ("microsoft.storage/storageaccounts",
                        "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"),
    "queue_trigger": ("microsoft.storage/storageaccounts",
                      "microsoft.storage/storageaccounts/queueservices/queues/messages/read"),
    "app_configuration_reference": ("microsoft.appconfiguration/configurationstores",
                                    "microsoft.appconfiguration/configurationstores/keyvalues/read"),
    "service_bus_trigger": ("microsoft.servicebus/namespaces", "microsoft.servicebus/namespaces/messages/receive/action"),
    "event_subscription": (None, None),
}
# azure_host_linked_to_pivot: value -> (parent type under {pivot}, link collection scoped to the parent, link item type,
# VM id property). avd_session_host reaches its parent (host pool) through the application group's hostPoolArmPath.
HOST_LINKS = {
    "avd_session_host": ("microsoft.desktopvirtualization/hostpools", "avd_session_host",
                         "microsoft.desktopvirtualization/hostpools/sessionhosts", "resourceId"),
    "automation_hybrid_worker": ("microsoft.automation/automationaccounts", "automation_hybrid_worker",
                                 "microsoft.automation/automationaccounts/hybridrunbookworkergroups/hybridrunbookworkers",
                                 "vmResourceId"),
    "devtest_lab_compute_vm": ("microsoft.devtestlab/labs", "devtest_lab_vm", "microsoft.devtestlab/labs/virtualmachines",
                               "computeId"),
}
REQUIRED_COLLECTIONS = {
    "devtest_lab_vm", "devtest_lab_artifact_source", "devtest_lab_artifact",
    "directory_agent_blueprint", "directory_agent_blueprint_principal", "directory_agent_identity",
    "directory_group_pim_policy", "temporary_access_pass_policy",
}
AVD_APP_GROUP = "microsoft.desktopvirtualization/applicationgroups"
ENTRA_DS = "microsoft.aad/domainservices"
LINK_TYPES = {AVD_APP_GROUP, ENTRA_DS, *(spec[2] for spec in HOST_LINKS.values())}
_PRINCIPAL_CSA = re.compile(r"@principal\s*\[\s*microsoft\.directory/customsecurityattributes", re.I)


CONTROLLED_USER = ("source.controlled_user", "target.user")


# Typed resource collections -> ARM type (their items carry `identity`).
TYPED_KINDS = {"vm": "microsoft.compute/virtualmachines", "arc_machine": "microsoft.hybridcompute/machines", "vm_scale_set": "microsoft.compute/virtualmachinescalesets",
               "synapse_workspace": "microsoft.synapse/workspaces",
               "purview_account": "microsoft.purview/accounts",
               "service_fabric_cluster": "microsoft.servicefabric/clusters",
               "analysis_server": "microsoft.analysisservices/servers",
               "api_management": "microsoft.apimanagement/service",
               "app_service": "microsoft.web/sites",
               "container_group": "microsoft.containerinstance/containergroups",
               "container_app_runtime": "microsoft.app/containerapps",
               "container_app_job": "microsoft.app/jobs",
               "mongo_cluster": "microsoft.documentdb/mongoclusters",
               "cosmos_account": "microsoft.documentdb/databaseaccounts",
               "databricks_workspace": "microsoft.databricks/workspaces",
               "batch_pool": "microsoft.batch/batchaccounts/pools",
               "policy_assignment": "microsoft.authorization/policyassignments",
               "aks_cluster": "microsoft.containerservice/managedclusters", "storage_account": "microsoft.storage/storageaccounts",
               "vault": "microsoft.keyvault/vaults", "sql_server": "microsoft.sql/servers",
               "mssql_managed_instance": "microsoft.sql/managedinstances"}
# Child resource types that are tracked resources in Azure Resource Graph's Resources table.
GRAPH_TRACKED_CHILDREN = frozenset({"microsoft.web/sites/slots", "microsoft.containerregistry/registries/tasks",
                                    "microsoft.machinelearningservices/workspaces/computes",
                                    "microsoft.machinelearningservices/workspaces/onlineendpoints"})
_FLUX_CLUSTER_TYPES = frozenset({"microsoft.containerservice/managedclusters", "microsoft.kubernetes/connectedclusters"})
_FLUX_CONFIG_TYPES = {
    "fluxconfigurations": "microsoft.kubernetesconfiguration/fluxconfigurations/write",
    "sourcecontrolconfigurations": "microsoft.kubernetesconfiguration/sourcecontrolconfigurations/write",
}
_ACTION_MATCH = re.compile(r"ActionMatches\s*\{\s*'([^']*)'\s*\}", re.I)


_JOIN = {"AND": re.compile(r"\s*(?:\bAND\b|&&)\s*", re.I), "OR": re.compile(r"\s*(?:\bOR\b|\|\|)\s*", re.I)}


def _split_top(expr, word):
    """Split on a top-level (outside parentheses / braces / quotes) AND / OR (&& / ||)."""
    parts, depth, start, i, quote, rx = [], 0, 0, 0, False, _JOIN[word]
    while i < len(expr):
        ch = expr[i]
        if ch == "'":
            quote = not quote
        elif not quote and ch in "({[":
            depth += 1
        elif not quote and ch in ")}]":
            depth -= 1
        elif not quote and depth == 0 and (ch.isspace() or ch in "&|"):
            m = rx.match(expr, i)
            if m and m.end() > i and expr[i:m.end()].strip():
                parts.append(expr[start:i])
                start = i = m.end()
                continue
        i += 1
    parts.append(expr[start:])
    return [p.strip() for p in parts]


def _strip_parens(expr):
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        for i, ch in enumerate(expr):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(expr) - 1:
                return expr
        expr = expr[1:-1].strip()
    return expr


def _abac_restricts(condition, action):
    """False when an Azure ABAC condition in the documented form provably leaves the action unrestricted:
    ``((!(ActionMatches{'a'}) [AND !(ActionMatches{'b'} ...)]) OR (<expression>)) [AND (...)]``; each clause only
    constrains the actions its negated ActionMatches names. True (restricted / undecidable) otherwise."""
    action = str(action or "").lower()
    for clause in _split_top(_strip_parens(condition), "AND"):
        branches = _split_top(_strip_parens(clause), "OR")
        if len(branches) < 2:
            return True
        guard = _strip_parens(branches[0])
        negations = _split_top(guard, "AND")
        named = []
        for negation in negations:
            negation = negation.strip()
            if not (negation.startswith("!") or negation[:4].upper() == "NOT "):
                return True
            found = _ACTION_MATCH.findall(negation)
            if not found:
                return True
            named += found
        if any(glob_match(n.lower(), action) for n in named):
            return True
    return False


def _low(value):
    return str(value or "").lower()


def _guid(rid):
    return _low(rid).rstrip("/").rsplit("/", 1)[-1]


class RoleDef:
    __slots__ = ("id", "name", "actions", "not_actions", "data", "not_data", "custom", "scopes", "_allows")

    def __init__(self, rid, name, permissions, custom=False, scopes=()):
        self.id, self.name, self.custom, self.scopes = rid, name, custom, tuple(_low(s) for s in scopes)
        self.actions, self.not_actions, self.data, self.not_data = [], [], [], []
        for p in as_list(permissions):
            if not isinstance(p, dict):
                continue
            self.actions += [_low(a) for a in as_list(p.get("actions"))]
            self.not_actions += [_low(a) for a in as_list(p.get("notActions"))]
            self.data += [_low(a) for a in as_list(p.get("dataActions"))]
            self.not_data += [_low(a) for a in as_list(p.get("notDataActions"))]
        self._allows = {}  # (action, data) -> bool; the action lists never change after construction

    def allows(self, action, data=False):
        key = (action, bool(data))
        hit = self._allows.get(key)
        if hit is None:
            allow, deny = (self.data, self.not_data) if data else (self.actions, self.not_actions)
            variants = (action,)
            if action == ASSIGN_UAMI:
                # Azure documents the operation without the child wildcard, while
                # Managed Identity Operator grants its */assign/action form.
                variants += ("microsoft.managedidentity/userassignedidentities/*/assign/action",)
            hit = self._allows[key] = (any(glob_match(a, variant) for a in allow for variant in variants)
                                        and not any(glob_match(a, variant) for a in deny for variant in variants))
        return hit


class AzureModel(ExactEvidenceMixin, Model):
    provider = "azure"

    def __init__(self, snapshot, catalog_keys=()):
        super().__init__(snapshot, catalog_keys)
        self.roles, self.assignments, self.denies = {}, {}, []
        self.parents = {}
        self.scopes = set()
        self.members_of = {}         # object id -> set(group ids) (direct)
        self.dir_roles, self.dir_assignments = {}, {}
        self.dir_objects = {}
        self.resources = {}          # arm id (lower) -> item (type lower, kind, identity)
        self.vmss_instances = {}     # scale-set id -> verified child instance ids
        self.vmss_instance_status = {}
        self.vmss_modes = {}
        self.mi_by_principal = {}
        self.deny_status = {}
        self.tenant = str((snapshot.get("metadata") or {}).get("tenant_id") or "tenant")
        self.app_ids = None
        self._load()
        from .azure_external_principal import load as load_external_principals
        self.external_principal_targets, self.external_principal_records = load_external_principals(self)
        self.load_exact_evidence("azure_privesc_challenge_evidence", {
            "azure_managed_identity", "azure_service_principal", "azure_user",
            "azure_verified_authority", "k8s_service_account"})
        self.scope_credential_status = inventory_status(snapshot, "azure_privesc_challenge_evidence")
        self.scope_credential_evidence = {}
        tenant_scope = f"/tenants/{self.tenant}".lower()
        for collection_scope, item in items(snapshot, "azure_privesc_challenge_evidence"):
            if (not isinstance(item, dict) or item.get("TechniqueId") not in _EXACT_SCOPE_CREDENTIALS
                    or _low(collection_scope) != tenant_scope):
                continue
            fields = (item.get("TechniqueId"), item.get("SourceId"), item.get("TargetId"),
                      _low(item.get("CredentialScope")))
            if all(isinstance(v, str) and v and "*" not in v for v in fields):
                self.scope_credential_evidence.setdefault(fields, []).append(item)
        self.exact_scopes = {s for s in self.scopes if s.lower().startswith("/subscriptions/") and s.count("/") == 2}
        for scope in sorted(self.exact_scopes):
            for foothold in ("anonymous", "broker_token"):
                ident = f"azure_challenge_foothold:{scope}:{foothold}"
                self.principals[ident] = Node(ident, "azure_challenge_foothold", "azure", scope,
                    f"{foothold} foothold at {scope}", attrs={"groups": []}, perm_key=((), (), None))
        # The hierarchy is complete once loaded; ancestors() is memoized from here on (see ancestors).
        self._ancestor_memo = {}
        self.require_collections(("role_assignment", "role_definition"), {
            "role_assignment": "Azure RBAC grants are unknown for this scope",
            "role_definition": "Custom role permissions are unknown (built-in Owner/Contributor/UAA/Reader are known)"})
        for kind, impact in (("directory_role_assignment", "Entra directory role grants are unknown"),
                             ("directory_role_definition", "Entra directory role permissions are unknown"),
                             ("directory_membership", "Group-inherited RBAC/Entra grants are unknown")):
            if not inventory_status(snapshot, kind):
                self.add_coverage("collection", "*", "not_collected", f"{kind} not in snapshot", impact)
        for kind, collection in FACT_COLLECTIONS.items():
            if not inventory_status(snapshot, collection):
                self.add_coverage("collection", f"/tenants/{self.tenant}", "not_collected", f"{collection} not in snapshot",
                                  f"Requirements of type {kind} are unknown")
        if not inventory_status(snapshot, "deny_assignment"):
            self.add_coverage("guardrail", "*", "not_collected", "deny_assignment not in snapshot",
                              "Edges are conditional: deny assignments may block them")
        for scope, status in unavailable(inventory_status(snapshot, "deny_assignment")).items():
            self.add_coverage("guardrail", scope, status, f"deny_assignment collection {status}",
                              "Edges under this scope are conditional: deny assignments may block them")

    # ----------------------------------------------------------------- load
    def _load(self):
        snap = self.snapshot
        for rid, (name, perms) in BUILTIN_ROLES.items():
            self.roles[rid] = RoleDef(rid, name, perms)
        for scope, item in items(snap, "role_definition"):
            props = item.get("properties") or {}
            rid = _guid(item.get("id") or item.get("name"))
            self.roles[rid] = RoleDef(rid, props.get("roleName", rid), props.get("permissions"),
                                      custom=props.get("type") == "CustomRole", scopes=props.get("assignableScopes") or [])
        for scope, item in items(snap, "management_group"):
            self._mg_tree(item.get("id"), (item.get("properties") or {}).get("children"))
            parent = ((item.get("properties") or {}).get("details") or {}).get("parent") or {}
            if parent.get("id") and item.get("id"):
                self.parents.setdefault(_low(item["id"]), _low(parent["id"]))
        for scope, item in items(snap, "subscription"):
            sid = _low(item.get("id") or f"/subscriptions/{item.get('subscriptionId')}")
            self.scopes.add(sid)
        for scope, item in items(snap, "resource_group"):
            if item.get("id"):
                self.scopes.add(_low(item["id"]))
        for kind in ("directory_user", "directory_service_principal", "directory_group"):
            for scope, item in items(snap, kind):
                if item.get("id"):
                    self._directory_principal(kind, item)
        for scope, item in items(snap, "directory_application"):
            self.app_ids = self.app_ids or {}
            if item.get("appId"):
                self.app_ids[_low(item["appId"])] = item
        for scope, item in items(snap, "directory_membership"):
            group = scope.rstrip("/").rsplit("/", 1)[-1]
            if item.get("id"):
                self.members_of.setdefault(item["id"], set()).add(group)
        self.membership_status = {s.rsplit("/", 1)[-1]: st for s, st in inventory_status(snap, "directory_membership").items()}
        for scope, item in items(snap, "directory_role_definition"):
            template = _low(item.get("templateId") or item.get("id"))
            actions = [_low(a) for p in as_list(item.get("rolePermissions")) for a in as_list((p or {}).get("allowedResourceActions"))]
            self.dir_roles[template] = {"id": template, "name": item.get("displayName", template), "actions": actions,
                                        "builtin": item.get("isBuiltIn", True), "def_id": _low(item.get("id")),
                                        "enabled": item.get("isEnabled")}
            self.dir_roles.setdefault(_low(item.get("id")), self.dir_roles[template])
        for scope, item in items(snap, "directory_role_assignment"):
            pid = item.get("principalId")
            if pid:
                self.dir_assignments.setdefault(pid, []).append(
                    (_low(item.get("roleDefinitionId")), item.get("directoryScopeId") or "/", item.get("id")))
        # Resources and their managed identities.
        for kind in ("vm", "arc_machine", "vm_scale_set", "analysis_server", "api_management", "app_service", "aks_cluster", "arc_kubernetes_cluster", "storage_account", "purview_account", "service_fabric_cluster", "spring_cloud_service", "synapse_workspace", "vault", "sql_server", "mssql_managed_instance", "policy_assignment", "managed_identity", "container_group", "container_app_runtime", "container_app_job", "mongo_cluster", "mysql_flexible_server", "postgresql_flexible_server", "cosmos_account", "databricks_workspace", "automation_account", "batch_account", "batch_pool", "devtest_lab_vm", "ml_compute", "resource_graph"):
            for scope, item in items(snap, kind):
                rid = _low(item.get("id"))
                if not rid:
                    continue
                entry = self.resources.setdefault(rid, {"id": item.get("id"), "type": _low(item.get("type")) or ("microsoft.hybridcompute/machines" if kind == "arc_machine" else ""),
                                                        "kind": _low(item.get("kind")), "typed": False, "name": item.get("name")})
                if kind != "resource_graph":
                    entry["typed"] = True
                    entry["kind"] = _low(item.get("kind")) or entry["kind"]
                if entry["type"] in LINK_TYPES and isinstance(item.get("properties"), dict):
                    entry["props"] = item["properties"]
                if kind == "vm" and "resources" in item:
                    # Domain-join extensions (JsonADDomainExtension public settings.Name = AD domain).
                    entry["join_domains"] = _join_domains(item.get("resources"))
                self._identity(item, entry)
                if kind == "vm_scale_set" and entry["type"] == "microsoft.compute/virtualmachinescalesets":
                    self.vmss_modes[rid] = _low((item.get("properties") or {}).get("orchestrationMode"))
                    status = ((item.get("_coverage") or {}).get("virtualMachines") or {}).get("status")
                    self.vmss_instance_status[rid] = status
                    children = set()
                    for child in as_list(item.get("virtualMachines")):
                        cid = _low(child.get("id")) if isinstance(child, dict) else ""
                        if (self.vmss_modes[rid] in ("", "uniform")
                                and cid.startswith(rid + "/virtualmachines/")
                                and re.fullmatch(r"[0-9]+", cid[len(rid + "/virtualmachines/"):])
                                and _low(child.get("type")) == "microsoft.compute/virtualmachinescalesets/virtualmachines"):
                            children.add(cid)
                            self.resources.setdefault(cid, {"id": child["id"], "type": _low(child["type"]),
                                                            "kind": "", "typed": True, "name": child.get("name")})
                    self.vmss_instances[rid] = children
                if entry["type"] == "microsoft.managedidentity/userassignedidentities":
                    props = item.get("properties") or {}
                    if props.get("principalId"):
                        mi = self._mi(props["principalId"], "user_assigned", item.get("id"))
                        mi.attrs["client_id"] = props.get("clientId")
                        mi.attrs["uai_resource_verified"] = True
        self.typed_types = {r["type"] for r in self.resources.values() if r["typed"]}
        # Resource types whose inventory is authoritative (every scope collected or empty): no item of the type
        # means no such resource, hence no identity attached to one.
        self.inventoried = {}      # resource type -> subscriptions whose typed collection is collected / empty
        for kind, rtype in TYPED_KINDS.items():
            self.inventoried[rtype] = {_low(sc) for sc, st in inventory_status(snap, kind).items() if st in ("collected", "empty")}
        self.graph_scopes = {_low(sc) for sc, st in inventory_status(snap, "resource_graph").items() if st in ("collected", "empty")}
        self.resource_types = {r["type"] for r in self.resources.values()}
        sub_status = inventory_status(snap, "subscription")
        self.all_subscriptions = None  # every visible subscription, when the subscription listing is complete
        if sub_status and not unavailable(sub_status):
            self.all_subscriptions = {_low(item.get("id") or f"/subscriptions/{item.get('subscriptionId')}")
                                      for _, item in items(snap, "subscription")} | self.graph_scopes
        for scope, item in items(snap, "role_assignment"):
            props = item.get("properties") or {}
            pid = props.get("principalId")
            if not pid:
                continue
            scope_id = _low(props.get("scope") or scope)
            self.scopes.add(scope_id)
            self.assignments.setdefault(pid, []).append({
                "role": _guid(props.get("roleDefinitionId")), "scope": scope_id, "condition": str(props.get("condition") or ""),
                "id": item.get("id"), "principal_type": props.get("principalType")})
            if pid not in self.principals:
                kind = {"User": "azure_user", "Group": "entra_group", "ServicePrincipal": "azure_service_principal"}.get(
                    props.get("principalType"), "azure_service_principal")
                node = Node(pid, kind, "azure", f"/tenants/{self.tenant}", pid, attrs={"object_id": pid, "directory": False})
                node.incomplete.append("principal not in directory inventory")
                self.principals[pid] = node
        for scope, status in inventory_status(snap, "deny_assignment").items():
            self.deny_status[_low(scope)] = status
        for scope, item in items(snap, "deny_assignment"):
            props = item.get("properties") or {}
            self.denies.append({"scope": _low(props.get("scope") or scope), "perms": RoleDef("deny", "deny", props.get("permissions")),
                                "principals": {p.get("id") for p in as_list(props.get("principals")) if isinstance(p, dict)},
                                "exclude": {p.get("id") for p in as_list(props.get("excludePrincipals")) if isinstance(p, dict)},
                                "id": item.get("id")})
        # Transitive group closure and permission keys.
        for node in self.principals.values():
            groups = self._groups(node.id)
            node.attrs["groups"] = sorted(groups)
            rbac = tuple(sorted((a["role"], a["scope"], a["condition"]) for pid in [node.id, *groups] for a in self.assignments.get(pid, [])))
            entra = tuple(sorted((r, s) for pid in [node.id, *groups] for r, s, _ in self.dir_assignments.get(pid, [])))
            node.perm_key = (rbac, entra, node.id if self.denies else None)
            if node.kind != "entra_group" and self.membership_status and not self.members_of.get(node.id) and \
                    any(st not in ("collected", "empty") for st in self.membership_status.values()):
                node.incomplete.append("group membership partially collected")

    def _mg_tree(self, parent, children):
        for child in as_list(children):
            if isinstance(child, dict) and child.get("id"):
                self.parents.setdefault(_low(child["id"]), _low(parent))
                self.scopes.add(_low(child["id"]))
                self._mg_tree(child["id"], child.get("children"))
        if parent:
            self.scopes.add(_low(parent))

    def _directory_principal(self, kind, item):
        oid = item["id"]
        self.dir_objects[oid] = item
        if kind == "directory_user":
            node_kind = "azure_user"
        elif kind == "directory_group":
            node_kind = "entra_group"
        elif item.get("servicePrincipalType") == "ManagedIdentity":
            node_kind = "azure_managed_identity"
        else:
            node_kind = "azure_service_principal"
        label = item.get("userPrincipalName") or item.get("displayName") or oid
        node = self.principals.get(oid) or Node(oid, node_kind, "azure", f"/tenants/{self.tenant}", label)
        node.kind, node.label = node_kind, label
        node.attrs.update(object_id=oid, directory=True, upn=item.get("userPrincipalName"), app_id=item.get("appId"),
                          sp_type=item.get("servicePrincipalType"), group_types=item.get("groupTypes"),
                          security_enabled=item.get("securityEnabled"), mail_enabled=item.get("mailEnabled"),
                          assignable_to_role=item.get("isAssignableToRole"),
                          membership_rule=item.get("membershipRule"), user_type=item.get("userType"),
                          on_prem_sync=item.get("onPremisesSyncEnabled"),
                          on_prem_sync_recorded="onPremisesSyncEnabled" in item,
                          immutable_id=item.get("onPremisesImmutableId"),
                          immutable_id_recorded="onPremisesImmutableId" in item,
                          creation_type=item.get("creationType"), creation_type_recorded="creationType" in item,
                          identities=item.get("identities"),
                          account_enabled=item.get("accountEnabled"),
                          app_owner_org=_low(item.get("appOwnerOrganizationId")))
        node.attrs.setdefault("hosts", [])
        self.principals[oid] = node

    def _mi(self, principal_id, mi_type, uai=None):
        node = self.principals.get(principal_id)
        if node is None:
            node = Node(principal_id, "azure_managed_identity", "azure", f"/tenants/{self.tenant}", principal_id,
                        attrs={"object_id": principal_id, "directory": False, "hosts": []})
            self.principals[principal_id] = node
        node.kind = "azure_managed_identity"
        node.attrs.setdefault("hosts", [])
        node.attrs["mi_type"] = mi_type
        if uai:
            node.attrs["uai_resource"] = _low(uai)
            node.label = uai.rstrip("/").rsplit("/", 1)[-1]
            node.scope = _subscription(uai) or node.scope
        return node

    def _identity(self, item, entry):
        identity = item.get("identity") or {}
        if not isinstance(identity, dict):
            return
        if identity.get("principalId"):
            mi = self._mi(identity["principalId"], "system_assigned")
            mi.attrs["hosts"].append(_low(item["id"]))
            mi.label = f"{item.get('name')} (system-assigned)"
            mi.scope = _subscription(item["id"]) or mi.scope
        for uai, detail in (identity.get("userAssignedIdentities") or {}).items():
            pid = (detail or {}).get("principalId")
            if not pid:
                pid = next((node.id for node in self.principals.values()
                            if node.kind == "azure_managed_identity"
                            and node.attrs.get("uai_resource") == _low(uai)), None)
            if pid:
                mi = self._mi(pid, "user_assigned", uai)
                if _low(item["id"]) not in mi.attrs["hosts"]:
                    mi.attrs["hosts"].append(_low(item["id"]))

    def _groups(self, oid):
        seen, stack = set(), list(self.members_of.get(oid, ()))
        while stack:
            group = stack.pop()
            if group in seen:
                continue
            seen.add(group)
            stack.extend(self.members_of.get(group, ()))
        return seen

    # ------------------------------------------------------------- hierarchy
    def ancestors(self, ref):
        """Chain from ref up to the root. Memoized after _load (callers never mutate the returned list)."""
        memo = self.__dict__.get("_ancestor_memo")
        if memo is not None:
            try:
                return memo[ref]
            except KeyError:
                chain = memo[ref] = self._ancestors(ref)
                return chain
            except TypeError:
                pass
        return self._ancestors(ref)

    def _ancestors(self, ref):
        ref = _low(ref).rstrip("/") or "/"
        chain = []
        parts = ref.split("/")
        # /subscriptions/s/resourcegroups/rg/providers/ns/type/name[/sub/name...]
        for i in range(len(parts), 1, -1):
            prefix = "/".join(parts[:i])
            if prefix and not prefix.endswith(("/providers", "/resourcegroups", "/subscriptions")):
                chain.append(prefix)
        node = _subscription(ref) or ref
        seen = set(chain)
        while node and node in self.parents and self.parents[node] not in seen:
            node = self.parents[node]
            chain.append(node)
            seen.add(node)
        chain.append("/")
        return chain

    def covers(self, outer, ref):
        """(covered, confidence) for an assignment scope over a ref."""
        outer = _low(outer).rstrip("/") or "/"
        if outer == "/":
            return True, "derived"
        chain = self.ancestors(ref)
        if outer in chain:
            return True, "derived"
        if "/managementgroups/" in outer and _subscription(ref) and not any("/managementgroups/" in c for c in chain):
            return True, "conditional"  # hierarchy not collected
        return False, None

    # ------------------------------------------------------------- interface
    def requirement_key(self, req):
        if "action" in req:
            return ("data:" if req.get("data_action") else "rbac:") + _low(req["action"])
        if "entra_permission" in req:
            return "entra_perm:" + _low(req["entra_permission"])
        if "entra_role" in req:
            return "entra_role:" + _low(req["entra_role"])
        if "graph_app_permission" in req:
            return "graph:" + _low(req["graph_app_permission"])
        if "entra_owner_of" in req:
            return "owner:" + _low(req.get("object_type"))
        if "entra_pim_eligible_role" in req:
            return "pim"
        if "entra_tenant_setting" in req:
            return "tenant:" + _low(req["entra_tenant_setting"])
        if "entra_group_member" in req:
            return "group_member:" + _low(req["entra_group_member"])
        if "fabric_workspace_role" in req:
            return "fabric:" + _low(req["fabric_workspace_role"])
        if "intune_permission" in req:
            return "intune:" + _low(req["intune_permission"])
        if "entra_catalog_role" in req:
            return "catalog_role:" + _low(req["entra_catalog_role"])
        return "?"

    def requirement_template(self, req):
        if "entra_owner_of" in req:
            return req["entra_owner_of"]
        if "entra_pim_eligible_role" in req:
            return req["entra_pim_eligible_role"]
        if "fabric_workspace_role" in req or "entra_catalog_role" in req:
            value = req.get("fabric_workspace", req.get("catalog"))
            return None if value in (None, "*") else value
        if "entra_group_member" in req or "intune_permission" in req:
            return None
        value = req.get("scope", req.get("directory_scope"))
        return None if value in (None, "*") else value

    def localizable(self, req):
        return "action" in req and self.requirement_template(req) is None

    def global_unknown(self, req):
        from ..schema import FACTS_NEEDED
        if "entra_owner_of" in req:
            owner_status = inventory_status(self.snapshot, "directory_owner")
            if not owner_status or unavailable(owner_status):
                return "Azure: service principal, application, or group owner listing incomplete"
        if "graph_app_permission" in req:
            principals = inventory_status(self.snapshot, "directory_service_principal")
            if not principals or (not self.__dict__.get("_graph_resource_ids")
                    and not any(_low(row.get("appId")) == "00000003-0000-0000-c000-000000000000"
                                for _, row in items(self.snapshot, "directory_service_principal"))
                    and unavailable(principals)):
                return "Azure: Microsoft Graph service principal identity unavailable"
        for kind, collection in (*FACT_COLLECTIONS.items(), *OPTIONAL_FACT_COLLECTIONS.items()):
            if kind in req and not inventory_status(self.snapshot, collection):
                return FACTS_NEEDED.get(kind, collection)
        if "entra_group_member" in req and not inventory_status(self.snapshot, "directory_membership"):
            return FACTS_NEEDED["entra_group_member"]
        return None

    def cached_check(self, principal, req, ref):
        if not _PRINCIPAL_FACT_SET.isdisjoint(req):
            # These facts belong to the principal: principals with equal RBAC / directory role keys still differ.
            key = (principal.id, self.requirement_key(req), ref)
            if key not in self._check_cache:
                self._check_cache[key] = self.check(principal, req, ref)
            return self._check_cache[key]
        return super().cached_check(principal, req, ref)

    def unknown_holders(self, req):
        if "graph_app_permission" in req:
            return {n.id for n in self.principals.values() if n.kind in ("azure_service_principal", "azure_managed_identity")}
        if "entra_tenant_setting" in req:
            return {n.id for n in self.principals.values() if n.kind == "azure_user"}
        return {n.id for n in self.principals.values() if n.kind != "entra_group"} if "entra_owner_of" not in req else \
            {n.id for n in self.principals.values() if n.kind in ("azure_user", "azure_service_principal", "azure_managed_identity")}

    def sources(self):
        return [n for n in self.principals.values()]

    def source_matches(self, source, kinds, selector):
        if selector.get("azure_member_user") is True and not (
                source.kind == "azure_user" and str(source.attrs.get("user_type") or "").casefold() == "member"):
            return False
        technique = (self.current_selector or {}).get("azure_challenge_fact")
        if technique and not self.exact_source_matches(technique, source):
            return False
        if source.kind == "azure_challenge_foothold" and "azure_challenge_foothold" not in as_list(kinds):
            return False
        return super().source_matches(source, kinds, selector)

    def possible(self, principal):
        base = self._possible_assignments(principal)
        facts = self._fact_keys(principal)
        if self.exact_source_matches("azure-purview-policy-self-grant", principal):
            # Purview Policy Author is a Purview-native role, not an ARM role
            # assignment. The exact reviewed fact is validated in check().
            facts.add("data:microsoft.purview/policyelements/write")
        return (base[0] | facts, base[1]) if facts else base

    def _possible_assignments(self, principal):
        indexes, signature = self.prefilter_indexes()
        key = ("possible", signature, principal.perm_key)
        if key in self._check_cache:
            return self._check_cache[key]
        keys, universal = set(), False
        if "azure_rbac_keys" not in indexes:
            indexes["azure_rbac_keys"] = [k for k in self.catalog_keys if isinstance(k, str) and k.startswith(("rbac:", "data:"))]
            indexes["azure_directory_keys"] = [k for k in self.catalog_keys if isinstance(k, str) and k.startswith("entra_perm:")]
        role_keys = indexes.setdefault("azure_role_keys", {})
        directory_keys = indexes.setdefault("azure_directory_role_keys", {})
        for role, scope, cond in principal.perm_key[0]:
            definition = self.roles.get(role)
            if definition is None:
                continue
            if role not in role_keys:
                role_keys[role] = frozenset(k for k in indexes["azure_rbac_keys"]
                                           if definition.allows(k[5:], k.startswith("data:")))
            keys.update(role_keys[role])
        for role, scope in principal.perm_key[1]:
            info = self.dir_roles.get(role)
            if info is None:
                continue
            if role not in directory_keys:
                directory_keys[role] = frozenset({"entra_role:" + _low(info["name"]), "entra_role:" + info["id"]} |
                    {k for k in indexes["azure_directory_keys"] if any(glob_match(a, k[11:]) for a in info["actions"])})
            keys.update(directory_keys[role])
        self._check_cache[key] = (frozenset(keys), universal)
        return self._check_cache[key]

    # --------------------------------------------------- principal-specific facts
    def _valid_graph_app_grant(self, item):
        if item.get("appRoleEnabled") is not True or not item.get("resourceId"):
            return False
        graph_ids = self.__dict__.get("_graph_resource_ids")
        if graph_ids is None:
            graph_ids = {_low(row.get("id")) for _, row in items(self.snapshot, "directory_service_principal")
                         if _low(row.get("appId")) == "00000003-0000-0000-c000-000000000000"}
            self._graph_resource_ids = graph_ids
        return _low(item["resourceId"]) in graph_ids

    def _fact_index(self):
        """Requirement key -> ids (principals or groups) that may satisfy it, for the optional fact collections."""
        _, signature = self.prefilter_indexes()
        if "_facts" in self.__dict__ and self.__dict__.get("_facts_catalog") == signature:
            return self._facts
        idx = {}
        add = lambda key, pid: idx.setdefault(key, set()).add(pid) if pid else None  # noqa: E731
        for _, item in items(self.snapshot, "directory_app_role_assignment"):
            if self._valid_graph_app_grant(item):
                add("graph:" + _low(item.get("appRoleValue") or item.get("permission")), item.get("principalId"))
        for _, item in items(self.snapshot, "directory_owner"):
            for owner in as_list(item.get("ownerIds")):
                add("owner:" + _low(item.get("objectType")), owner)
        for item in self._eligibilities():
            add("pim", item.get("principalId"))
        for item in self._fabric_assignments():
            for role, rank in FABRIC_RANK.items():
                if rank <= item["rank"]:
                    add("fabric:" + role, item["principal"])
        wanted = [k for k in self.catalog_keys if isinstance(k, str) and k.startswith("intune:")]
        for item in self._intune_assignments():
            for k in wanted:
                if any(glob_match(a, k[7:]) for a in item["actions"]):
                    for member in item["members"]:
                        add(k, member)
        for item in self._catalog_assignments():
            for name in item["names"]:
                add("catalog_role:" + name, item["principal"])
        self._facts = idx
        self._facts_catalog = signature
        return idx

    def _fact_keys(self, principal):
        indexes, _ = self.prefilter_indexes()
        if "azure_fact_holders" not in indexes:
            direct, inherited = {}, {}
            for key, holders in self._fact_index().items():
                if key not in self.catalog_keys:
                    continue
                if key.startswith("graph:"):
                    target = direct
                elif key.startswith(("owner:", "fabric:", "intune:", "catalog_role:")) or key == "pim":
                    target = inherited
                else:
                    continue
                for holder in holders:
                    target.setdefault(holder, set()).add(key)
            indexes["azure_fact_holders"] = direct, inherited
            indexes["azure_tenant_keys"] = {k for k in self.catalog_keys if isinstance(k, str) and k.startswith("tenant:")}
            indexes["azure_group_member_keys"] = [k for k in self.catalog_keys if isinstance(k, str) and k.startswith("group_member:")]
        direct, inherited = indexes["azure_fact_holders"]
        out = set(indexes["azure_tenant_keys"])
        out.update(direct.get(principal.id, ()))
        for identity in {principal.id, *principal.attrs.get("groups", [])}:
            out.update(inherited.get(identity, ()))
        for key in indexes["azure_group_member_keys"]:
            if self._group_member(principal, key[13:]) is not None:
                out.add(key)
        return out

    def _group_member(self, principal, wanted):
        """Grant when the principal is a transitive member of the group named / identified by `wanted`; unknown when that
        group's membership (or the group inventory) was not fully collected; None otherwise."""
        wanted = _low(wanted)
        match = lambda gid: wanted in (_low(gid), _low((self.dir_objects.get(gid) or {}).get("displayName")))  # noqa: E731
        for gid in principal.attrs.get("groups", []):
            if match(gid):
                return Grant("derived", [{"group_member": gid}])
        indexes, _ = self.prefilter_indexes()
        if "azure_group_names" not in indexes:
            names = {}
            for gid, node in self.principals.items():
                if node.kind == "entra_group":
                    for name in {_low(gid), _low((self.dir_objects.get(gid) or {}).get("displayName"))}:
                        names.setdefault(name, []).append(gid)
            indexes["azure_group_names"] = names
        named = indexes["azure_group_names"].get(wanted, [])
        complete = ("collected", "empty")
        if named:
            if any(self.membership_status.get(g) not in complete for g in named):
                return Grant("unknown", [], ["group_membership_not_collected"])
            return None
        groups = inventory_status(self.snapshot, "directory_group")
        if not groups or unavailable(groups):
            return Grant("unknown", [], ["group_inventory_not_collected"])
        return None

    def _fabric_assignments(self):
        if "_fabric" not in self.__dict__:
            self._fabric = []
            for scope, item in items(self.snapshot, "fabric_workspace_role_assignment"):
                principal = (item.get("principal") or {}).get("id") if isinstance(item.get("principal"), dict) else item.get("principalId")
                rank = FABRIC_RANK.get(_low(item.get("role")))
                if principal and rank:
                    self._fabric.append({"principal": principal, "rank": rank, "role": item.get("role"),
                                         "workspace": _low(item.get("workspaceId") or scope).rsplit("/", 1)[-1], "id": item.get("id")})
        return self._fabric

    def _intune_assignments(self):
        if "_intune" not in self.__dict__:
            self._intune = []
            for _, item in items(self.snapshot, "intune_role_assignment"):
                definition = item.get("roleDefinition") or {}
                actions = [_low(a) for p in as_list(definition.get("rolePermissions")) if isinstance(p, dict)
                           for r in as_list(p.get("resourceActions")) if isinstance(r, dict)
                           for a in as_list(r.get("allowedResourceActions"))]
                self._intune.append({"id": item.get("id"), "members": [m for m in as_list(item.get("members")) if m],
                                     "actions": actions, "role": definition.get("displayName")})
        return self._intune

    def _catalog_assignments(self):
        if "_catalog_roles" not in self.__dict__:
            self._catalog_roles = []
            role_ids = {"ae79f266-94d4-4dab-b730-feca7e132178": "catalog owner",
                        "7f480852-ebdc-47d4-87de-0d8498384a83": "access package manager",
                        "e2182095-804a-4656-ae11-64734e9b7ae5": "access package assignment manager"}
            for _, item in items(self.snapshot, "entitlement_role_assignment"):
                definition = item.get("roleDefinition") or {}
                names = {_low(n) for n in (definition.get("displayName"), item.get("roleDefinitionId")) if n}
                if _low(item.get("roleDefinitionId")) in role_ids:
                    names.add(role_ids[_low(item["roleDefinitionId"])])
                scope = str(item.get("appScopeId") or "/")
                self._catalog_roles.append({"principal": item.get("principalId"), "names": names, "id": item.get("id"),
                                            "catalog": None if scope.strip("/") == "" else _low(scope.rstrip("/").rsplit("/", 1)[-1])})
        return self._catalog_roles

    def _catalog_index(self):
        """Target object id -> catalog ids holding it as a resource (None when catalog resources are not collected)."""
        if "_catalogs" not in self.__dict__:
            self._catalogs = None
            if inventory_status(self.snapshot, "entitlement_catalog_resource"):
                self._catalogs = {}
                for scope, item in items(self.snapshot, "entitlement_catalog_resource"):
                    origin = _low(item.get("originId"))
                    catalog = _low(item.get("catalogId") or scope.rstrip("/").rsplit("/", 1)[-1])
                    if origin:
                        self._catalogs.setdefault(origin, set()).add(catalog)
        return self._catalogs

    def _fabric_identities(self):
        """Service principal id -> Fabric workspace id (None when workspaces are not collected)."""
        if "_fabric_ws" not in self.__dict__:
            self._fabric_ws = None
            if inventory_status(self.snapshot, "fabric_workspace"):
                self._fabric_ws = {}
                for _, item in items(self.snapshot, "fabric_workspace"):
                    sp = (item.get("workspaceIdentity") or {}).get("servicePrincipalId") if isinstance(item.get("workspaceIdentity"), dict) else None
                    if sp and item.get("id"):
                        self._fabric_ws[sp] = _low(item["id"])
        return self._fabric_ws

    def _target_object_ids(self, node):
        ids = {_low(node.id)}
        if node.entity and node.attrs.get("template_id"):
            ids.add(_low(node.attrs["template_id"]))
            if node.kind == "entra_role":
                info = self.dir_roles.get(_low(node.attrs["template_id"]))
                if info:
                    ids.add(_low(info.get("def_id")))
                for _, role in items(self.snapshot, "directory_role"):
                    if _low(role.get("roleTemplateId")) == _low(node.attrs["template_id"]):
                        ids.add(_low(role.get("id")))
        app = (self.app_ids or {}).get(_low(node.attrs.get("app_id")))
        if app and app.get("id"):
            ids.add(_low(app["id"]))
        return ids

    def _rbac_candidates(self, principal, action, data):
        """Ref-independent part of _rbac: the (holder, assignment, role definition) triples whose role allows the
        action, in assignment order. Assignments, roles and group expansion are fixed after _load."""
        groups = principal.attrs.get("groups", [])
        memo = self.__dict__.get("_rbac_candidate_memo")
        if memo is None:
            memo = self.__dict__["_rbac_candidate_memo"] = {}
        key = (principal.id, action, bool(data))
        try:
            hit = memo.get(key)
        except TypeError:
            hit, memo = None, None
        if hit is not None and hit[0] == groups:
            return hit[1]
        found = []
        for pid in [principal.id, *groups]:
            for a in self.assignments.get(pid, []):
                definition = self.roles.get(a["role"])
                if definition is not None and definition.allows(action, data):
                    found.append((pid, a, definition))
        if memo is not None:
            memo[key] = (list(groups), found)
        return found

    def _rbac(self, principal, action, data, ref):
        best_grant = None
        for pid, a, definition in self._rbac_candidates(principal, action, data):
            if ref is ANY:
                ok, conf = True, "derived"
            else:
                ok, conf = self.covers(a["scope"], ref)
            if not ok:
                continue
            conditions = []
            restricted = a["condition"] and _abac_restricts(a["condition"], action)
            if restricted:
                conf, conditions = "conditional", ["role_assignment_condition"]
            if conf == "conditional" and not conditions:
                conditions = ["management_group_hierarchy_not_collected"]
            if pid != principal.id:
                conditions.append("via_group_membership")
            ref_info = {"assignment": a["id"], "role": definition.name, "scope": a["scope"], "via": pid}
            if a["condition"]:
                ref_info["condition"] = a["condition"]
            grant = Grant(conf, [ref_info], conditions)
            if best_grant is None or (best_grant.confidence != "derived" and conf == "derived"):
                best_grant = grant
        if best_grant is None:
            return None
        return self._deny(principal, action, data, ref, best_grant)

    def _deny(self, principal, action, data, ref, grant):
        ids = {principal.id, EVERYONE, *principal.attrs.get("groups", [])}
        for deny in self.denies:
            if not (deny["principals"] & ids) or principal.id in deny["exclude"]:
                continue
            if not deny["perms"].allows(action, data):
                continue
            if ref is ANY:
                grant = downgrade(grant, "conditional", "deny_assignment_may_apply")
                continue
            if self.covers(deny["scope"], ref)[0]:
                return None
        if not self.deny_status:
            return downgrade(grant, "conditional", "deny_assignments_not_collected")
        if ref is not ANY:
            chain = self.ancestors(ref)
            if any(self.deny_status.get(s) not in (None, "collected", "empty") for s in chain):
                grant = downgrade(grant, "conditional", "deny_assignments_not_collected")
        return grant

    def _entra(self, principal, req, ref):
        key = self.requirement_key(req)
        best_grant = None
        for pid in [principal.id, *principal.attrs.get("groups", [])]:
            for role, scope, aid in self.dir_assignments.get(pid, []):
                info = self.dir_roles.get(role)
                if info is None:
                    continue
                if key.startswith("entra_role:"):
                    wanted = key[11:]
                    if wanted not in (_low(info["name"]), info["id"]):
                        continue
                else:
                    perm = key[11:]
                    if not any(glob_match(a, perm) for a in info["actions"]):
                        continue
                    if ref not in (ANY, None) and not self._group_kind_ok(perm, ref):
                        continue
                conf, conditions = self._dir_scope(scope, ref)
                if conf is None:
                    continue
                if pid != principal.id:
                    conditions = conditions + ["via_role_assignable_group"]
                grant = Grant(conf, [{"directory_role_assignment": aid, "role": info["name"], "directory_scope": scope, "via": pid}], conditions)
                if best_grant is None or (best_grant.confidence != "derived" and conf == "derived"):
                    best_grant = grant
        return best_grant

    def _group_kind_ok(self, perm, ref):
        target = self.dir_objects.get(str(ref)[4:]) if isinstance(ref, str) and ref.startswith("dir:") else None
        if target is None:
            return True
        unified = "Unified" in as_list(target.get("groupTypes"))
        if "groups.unified/" in perm:
            return unified
        if "groups.security/" in perm:
            return bool(target.get("securityEnabled")) and not unified
        return True

    def _dir_scope(self, scope, ref):
        if ref is ANY or ref is None:
            return "derived", []
        scope = scope or "/"
        if ref == "dir:/":
            return ("derived", []) if scope == "/" else (None, [])
        if scope == "/":
            return "derived", []
        target = str(ref)[4:]
        if scope.lstrip("/") == target:
            return "derived", []
        if scope.startswith("/administrativeUnits/"):
            members = self._au_members().get(scope.split("/")[2])
            if members is None:
                return "unknown", ["administrative_unit_membership_not_collected"]
            return ("derived", []) if target in members else (None, [])
        return None, []

    def _au_members(self):
        cache = self.__dict__.get("_au_cache")
        if cache is None:
            cache = self._au_cache = {}
            for scope, item in items(self.snapshot, "directory_administrative_unit"):
                if item.get("id") and "memberIds" in item:
                    cache[item["id"]] = set(as_list(item.get("memberIds")))
        return cache

    def _type_inventoried(self, rtype, scope):
        """True when the snapshot lists every resource of this type in the identity's subscription with its identity:
        the typed collection, or Resource Graph (which projects `identity`) for tracked types, collected (or
        authoritatively empty) there. A child type whose parent type has no resource at all cannot exist either."""
        sub = _subscription(scope)
        # An identity known only from the directory (no host found): every visible subscription must be inventoried.
        subs = [sub] if sub else sorted(self.all_subscriptions or ())
        if not subs:
            return False
        tracked = rtype.count("/") == 1 or rtype in GRAPH_TRACKED_CHILDREN
        parentless = "/".join(rtype.split("/")[:2]) not in self.resource_types  # no parent resource: no child either
        return all(s in self.inventoried.get(rtype, ()) or (
            s in self.graph_scopes and not rtype.startswith("microsoft.authorization/") and (tracked or parentless))
            for s in subs)

    def _eligibilities(self):
        """Directory role eligibility schedules still in force: status Provisioned (or unset) and, when schedule
        instances were collected, a matching instance that has not expired."""
        if "_eligible" in self.__dict__:
            return self._eligible
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        status = inventory_status(self.snapshot, "directory_role_eligibility_instance")
        instances, have_instances = {}, bool(status) and all(v in ("collected", "empty") for v in status.values())
        for _, inst in items(self.snapshot, "directory_role_eligibility_instance"):
            start = str(inst.get("startDateTime") or "")
            end = str(inst.get("endDateTime") or "")
            try:
                live = ((not start or datetime.fromisoformat(start.replace("Z", "+00:00")) <= now)
                        and (not end or datetime.fromisoformat(end.replace("Z", "+00:00")) > now))
            except (TypeError, ValueError):
                live = False
            key = (inst.get("principalId"), _low(inst.get("roleDefinitionId")), inst.get("directoryScopeId") or "/")
            instances[key] = instances.get(key, False) or live
        out = []
        for _, item in items(self.snapshot, "directory_role_eligibility_schedule"):
            if str(item.get("status") or "Provisioned").lower() not in ("provisioned", "granted", "scheduled"):
                continue  # revoked / canceled / failed / pending approval
            key = (item.get("principalId"), _low(item.get("roleDefinitionId")), item.get("directoryScopeId") or "/")
            if have_instances and not instances.get(key):
                continue  # instances fully collected and none of this eligibility is current (expired / not started)
            out.append(item)
        self._eligible = out
        return out

    def blocker_verdict(self, blocker, source, compiled, pivots=None, reached=None, cset=None):
        if blocker == "aks_run_command_disabled":
            if cset is None:
                return None
            records = {}
            for collection in ("aks_cluster", "resource_graph"):
                for _, item in items(self.snapshot, collection):
                    rid = _low(item.get("id"))
                    if _low(item.get("type")) != "microsoft.containerservice/managedclusters":
                        continue
                    props = item.get("properties") or {}
                    profile = props.get("apiServerAccessProfile")
                    value = profile.get("disableRunCommand") if isinstance(profile, dict) else None
                    if type(value) is bool:
                        records.setdefault(rid, set()).add(value)
            verdicts = {}
            for tid in (reached if isinstance(reached, dict) else cset.members):
                node = cset.members.get(tid)
                if node is None or node.attrs.get("type") != "microsoft.containerservice/managedclusters":
                    continue
                values = records.get(node.scope, set())
                if values == {False}:
                    verdicts[tid] = "clear"
                elif values == {True}:
                    grant = self.cached_check(source, {"action": "Microsoft.ContainerService/managedClusters/write"}, node.scope)
                    verdicts[tid] = (("possibly_blocked", "Run Command can be re-enabled by this source")
                                     if grant is not None else
                                     ("blocked", "Run Command is disabled on this cluster"))
                else:
                    verdicts[tid] = ("possibly_blocked", "Run Command setting is missing or conflicting")
            return verdicts
        if blocker == "aks_local_accounts_enabled":
            if cset is None:
                return None
            records = {}
            for collection in ("aks_cluster", "resource_graph"):
                for _, item in items(self.snapshot, collection):
                    rid = _low(item.get("id"))
                    if _low(item.get("type")) != "microsoft.containerservice/managedclusters":
                        continue
                    value = (item.get("properties") or {}).get("disableLocalAccounts")
                    if type(value) is bool:
                        records.setdefault(rid, set()).add(value)
            verdicts = {}
            for tid in (reached if isinstance(reached, dict) else cset.members):
                node = cset.members.get(tid)
                if node is None or node.attrs.get("type") != "microsoft.containerservice/managedclusters":
                    continue
                values = records.get(node.scope, set())
                if values == {True}:
                    verdicts[tid] = "clear"
                elif values == {False}:
                    verdicts[tid] = ("blocked", "local accounts are already enabled on this cluster")
                else:
                    verdicts[tid] = ("possibly_blocked", "local account setting is missing or conflicting")
            return verdicts
        if blocker == "aks_entra_integration_enabled":
            if cset is None:
                return None
            records = {}
            for collection in ("aks_cluster", "resource_graph"):
                for _, item in items(self.snapshot, collection):
                    rid = _low(item.get("id"))
                    if _low(item.get("type")) != "microsoft.containerservice/managedclusters":
                        continue
                    props = item.get("properties")
                    if not isinstance(props, dict):
                        continue
                    if isinstance(props.get("aadProfile"), dict):
                        records.setdefault(rid, set()).add(True)
                    elif props.get("aadProfile", object()) is None:
                        records.setdefault(rid, set()).add(False)
                    elif collection == "aks_cluster" and "aadProfile" not in props:
                        # The native managed-cluster response omits a null AAD profile.
                        records.setdefault(rid, set()).add(False)
            verdicts = {}
            for tid in (reached if isinstance(reached, dict) else cset.members):
                node = cset.members.get(tid)
                if node is None or node.attrs.get("type") != "microsoft.containerservice/managedclusters":
                    continue
                values = records.get(node.scope, set())
                if values == {True}:
                    verdicts[tid] = ("blocked", "Entra integration is enabled on this cluster")
                elif values == {False}:
                    verdicts[tid] = "clear"
                else:
                    verdicts[tid] = ("possibly_blocked", "Entra integration is missing or conflicting")
            return verdicts
        if blocker == "aks_local_accounts_disabled":
            if cset is None:
                return None
            records = {}
            for collection in ("aks_cluster", "resource_graph"):
                for _, item in items(self.snapshot, collection):
                    rid = _low(item.get("id"))
                    if _low(item.get("type")) != "microsoft.containerservice/managedclusters":
                        continue
                    value = (item.get("properties") or {}).get("disableLocalAccounts")
                    if type(value) is bool:
                        records.setdefault(rid, set()).add(value)
            verdicts = {}
            for tid in (reached if isinstance(reached, dict) else cset.members):
                node = cset.members.get(tid)
                if node is None or node.attrs.get("type") != "microsoft.containerservice/managedclusters":
                    continue
                values = records.get(node.scope, set())
                if values == {False}:
                    verdicts[tid] = "clear"
                elif values == {True}:
                    grant = self.cached_check(source, {"action": "Microsoft.ContainerService/managedClusters/write"}, node.scope)
                    verdicts[tid] = (("possibly_blocked", "local accounts can be re-enabled by this source")
                                     if grant is not None else
                                     ("blocked", "local accounts are disabled on this cluster"))
                else:
                    verdicts[tid] = ("possibly_blocked", "local account setting is missing or conflicting")
            return verdicts
        if blocker != "disabled_azure_identity":
            return super().blocker_verdict(blocker, source, compiled, pivots=pivots, reached=reached, cset=cset)
        if cset is None:
            return None
        verdicts = {}
        for tid in (reached if isinstance(reached, dict) else cset.members):
            node = cset.members.get(tid)
            if node is None:
                continue
            verdicts[tid] = (("possibly_blocked", "target identity is disabled; token issuance may be blocked")
                             if node.attrs.get("account_enabled") is False else "clear")
        return verdicts

    def check(self, principal, req, ref):
        if "action" in req:
            if ((self.current_entry or {}).get("id") == "azure-purview-policy-self-grant"
                    and _low(req["action"]) == "microsoft.purview/policyelements/write"):
                from .azure_self_grants import valid as self_grant_valid
                grant = None
                for (tid, sid, kind, resource, scope), records in self.exact_evidence.items():
                    if (tid == "azure-purview-policy-self-grant" and sid == principal.id
                            and kind == "azure_verified_authority" and _low(scope) == _low(ref) and len(records) == 1
                            and self_grant_valid(tid, records[0], sid, resource, scope, self.snapshot)):
                        grant = Grant("conditional", [{"reviewed_purview_policy_author": records[0]["PolicyAuthorEvidenceRef"]}],
                                      ["purview_policy_author_reviewed"])
                        break
            elif ((self.current_entry or {}).get("id") == "azure-storage-blob-content-credential"
                    and _low(req["action"]) == "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"
                    and ref is not ANY and ref in self.resources
                    and self.resources[ref].get("type") == "microsoft.storage/storageaccounts"):
                grant = None
                for (tid, sid, target, resource), records in self.scope_credential_evidence.items():
                    if tid != "azure-storage-blob-content-credential" or sid != principal.id or resource != ref:
                        continue
                    for fact in records:
                        if not self._scope_credential_fact_bound(tid, sid, target, resource, fact):
                            continue
                        candidate = self._rbac(principal, _low(req["action"]), True,
                                               _low(fact["BlobResourceId"]))
                        if candidate is not None and (grant is None or candidate.confidence == "derived"):
                            grant = candidate
            else:
                grant = self._rbac(principal, _low(req["action"]), bool(req.get("data_action")), ref)
        elif "entra_permission" in req or "entra_role" in req:
            grant = self._entra(principal, req, ref)
        elif "entra_owner_of" in req:
            grant = self._fact_requirement(principal, req, ref)
        else:
            reason = self.global_unknown(req)
            grant = (Grant("unknown", [], [f"facts_not_collected:{reason}"]) if reason
                     else self._fact_requirement(principal, req, ref))
        return (downgrade(grant, "conditional", "source_identity_disabled")
                if grant is not None and principal.attrs.get("account_enabled") is False else grant)

    def _shared_unknown(self, reason):
        """One evidence-free unknown Grant per reason: Grants are immutable, and per-target results that share
        the object are tagged and combined once (evaluator dedupes by identity)."""
        shared = self.__dict__.setdefault("_shared_unknown_grants", {})
        grant = shared.get(reason)
        if grant is None:
            grant = shared[reason] = Grant("unknown", [], [reason])
        return grant

    def _owned_rows(self, principal_id):
        """directory_owner rows that may list principal_id among ownerIds, in collection order (callers still apply
        the exact membership test). Falls back to every row when the id or an owner id cannot be indexed."""
        index = self.__dict__.get("_owner_row_index")
        if index is None:
            index = {}
            for scope, item in items(self.snapshot, "directory_owner"):
                for owner in dict.fromkeys(o for o in as_list(item.get("ownerIds")) if isinstance(o, str)):
                    index.setdefault(owner, []).append((scope, item))
                if any(not isinstance(o, str) for o in as_list(item.get("ownerIds"))):
                    index = False
                    break
            self.__dict__["_owner_row_index"] = index
        if index is False or not isinstance(principal_id, str):
            return items(self.snapshot, "directory_owner")
        return index.get(principal_id, ())

    def _fact_requirement(self, principal, req, ref):
        """Requirements backed by optional collections (evaluated when present)."""
        if "graph_app_permission" in req:
            if principal.kind not in ("azure_service_principal", "azure_managed_identity"):
                return None
            wanted = _low(req["graph_app_permission"])
            for scope, item in items(self.snapshot, "directory_app_role_assignment"):
                if (item.get("principalId") == principal.id and self._valid_graph_app_grant(item)
                        and _low(item.get("appRoleValue") or item.get("permission")) == wanted):
                    return Grant("derived", [{"app_role_assignment": item.get("id"), "permission": req["graph_app_permission"]}])
            return None
        if "entra_owner_of" in req:
            target = str(ref)[4:] if isinstance(ref, str) and ref.startswith("dir:") else None
            object_type = _low(req.get("object_type"))
            endpoint = {"application": "applications", "serviceprincipal": "servicePrincipals",
                        "group": "groups"}.get(object_type)
            wanted_scope = (f"/tenants/{self.tenant}/{endpoint}/{target}".casefold()
                            if target and endpoint else None)
            for scope, item in self._owned_rows(principal.id):
                if (principal.id in as_list(item.get("ownerIds"))
                        and (target is None or _low(item.get("objectId")) == _low(target))
                        and _low(item.get("objectType")) == object_type
                        and (wanted_scope is None or _low(scope) == wanted_scope)):
                    return Grant("derived", [{"owner_of": item.get("objectId")}])
            statuses = self.__dict__.get("_owner_statuses")
            if statuses is None:
                statuses = self.__dict__["_owner_statuses"] = inventory_status(self.snapshot, "directory_owner")
            if wanted_scope and statuses.get(wanted_scope) not in ("collected", "empty"):
                return self._shared_unknown("owner_listing_not_collected_for_target")
            if target is None and (not statuses or unavailable(statuses)):
                return self._shared_unknown("owner_listings_incomplete")
            return None
        if "entra_pim_eligible_role" in req:
            target = str(ref)[4:] if isinstance(ref, str) and ref.startswith("dir:") else None
            wanted_scope = req.get("directory_scope")
            if wanted_scope == "dir:/":
                wanted_scope = "/"
            instance_status = inventory_status(self.snapshot, "directory_role_eligibility_instance")
            instances_complete = bool(instance_status) and all(
                state in ("collected", "empty") for state in instance_status.values())
            found = None
            for item in self._eligibilities():
                role_id = _low(item.get("roleDefinitionId"))
                role_info = self.dir_roles.get(role_id)
                if item.get("principalId") in (principal.id, *principal.attrs.get("groups", [])) and \
                        (target is None or target in (role_id, (role_info or {}).get("id"))) and \
                        (wanted_scope is None or (item.get("directoryScopeId") or "/") == wanted_scope):
                    conditions = ["pim_activation_required"]
                    if (item.get("directoryScopeId") or "/") != "/":
                        conditions.append("pim_eligibility_scope_restricted")
                    grant = Grant("conditional" if instances_complete else "unknown",
                                  [{"eligibility": item.get("id"), "directory_scope": item.get("directoryScopeId") or "/"}],
                                  conditions if instances_complete else conditions + ["pim_eligibility_instance_not_collected"])
                    if found is None or len(grant.conditions) < len(found.conditions):
                        found = grant
            return found
        if "entra_tenant_setting" in req:
            for scope, item in items(self.snapshot, "directory_authorization_policy"):
                allowed = _low(item.get("allowInvitesFrom"))
                if allowed in ("everyone", "adminsguestinvitersandallmembers") and principal.attrs.get("user_type") != "Guest":
                    return Grant("derived", [{"authorization_policy": item.get("id"), "allowInvitesFrom": allowed}])
                if allowed == "everyone":
                    return Grant("derived", [{"authorization_policy": item.get("id")}])
            return None
        ids = {principal.id, *principal.attrs.get("groups", [])}
        if "entra_group_member" in req:
            return self._group_member(principal, req["entra_group_member"])
        if "fabric_workspace_role" in req:
            wanted = FABRIC_RANK[_low(req["fabric_workspace_role"])]
            workspace = str(ref)[7:] if isinstance(ref, str) and ref.startswith("fabric:") else None
            if ref not in (ANY, None) and workspace is None:
                return None  # not a Fabric workspace (e.g. an identity that is no workspace identity)
            for item in self._fabric_assignments():
                if item["principal"] in ids and item["rank"] >= wanted and workspace in (None, item["workspace"]):
                    return Grant("derived", [{"fabric_role_assignment": item["id"], "workspace": item["workspace"],
                                              "role": item["role"], "via": item["principal"]}],
                                 ["via_group_membership"] if item["principal"] != principal.id else [])
            return None
        if "intune_permission" in req:
            perm = _low(req["intune_permission"])
            for item in self._intune_assignments():
                if set(item["members"]) & ids and any(glob_match(a, perm) for a in item["actions"]):
                    # Scope tags / scope groups limit which devices the assignment manages: not evaluated.
                    return Grant("conditional", [{"intune_role_assignment": item["id"], "role": item["role"]}],
                                 ["intune_scope_tags_not_evaluated"])
            return None
        if "entra_catalog_role" in req:
            wanted = _low(req["entra_catalog_role"])
            catalog = str(ref)[8:] if isinstance(ref, str) and ref.startswith("catalog:") else None
            if ref not in (ANY, None) and catalog is None:
                return None
            for item in self._catalog_assignments():
                if item["principal"] in ids and wanted in item["names"] and (
                        catalog is None or item["catalog"] in (None, catalog)):
                    return Grant("derived", [{"entitlement_role_assignment": item["id"], "catalog": item["catalog"] or "/"}])
            return None
        return None

    def check_targets(self, principal, req, template, candidates, localized=False):
        result = {}
        for target in candidates:
            if localized:
                refs, floor = self.localize_refs(target), None
            else:
                refs, floor = self.resolve(template, principal, target)
            grant = None
            for ref in refs:
                got = self.cached_check(principal, req, ref)
                if got is not None and (grant is None or got.confidence == "derived"):
                    grant = got
            if grant is not None:
                result[target.id] = downgrade(grant, floor[0], floor[1]) if floor else grant
        return result

    def localize_refs(self, target):
        if target.entity:
            return [target.scope]
        hosts = list(target.attrs.get("hosts") or [])
        if target.attrs.get("uai_resource"):
            hosts.append(target.attrs["uai_resource"])
        return hosts or [ANY]

    def placeholder_values(self, name, source, target, pivot=None):
        if name == "pivot":
            return [pivot["pivot"]] if pivot and pivot.get("pivot") else None
        owner, _, attr = name.partition(".")
        if not attr:
            owner, attr = "source", owner
        node = target if owner == "target" else source
        if node is None:
            return None
        if attr == "catalog":
            index = self._catalog_index()
            if index is None:
                return None
            return sorted({"catalog:" + c for i in self._target_object_ids(node) for c in index.get(i, ())})
        if attr == "host_resource":
            hosts = node.attrs.get("hosts")
            if hosts:
                return list(hosts)
            if node.kind == "azure_service_principal" and not node.entity:
                workspaces = self._fabric_identities()
                if workspaces is not None and node.id in workspaces:
                    return ["fabric:" + workspaces[node.id]]
            return [] if node.attrs.get("uai_resource") else None
        if attr in ("apim_api_resource", "apim_api_policy_resource",
                    "apim_operation_policy_resource", "apim_product_policy_resource"):
            # RBAC can be assigned to a single API, operation or product. A
            # service-only permission test would miss those grants. Keep the
            # service as a candidate for inherited permissions, and admit only
            # child scopes of the exact APIM service carrying this identity.
            hosts = [host for host in node.attrs.get("hosts") or ()
                     if self.resources.get(host, {}).get("type") == "microsoft.apimanagement/service"]
            if not hosts:
                return []
            refs = set(hosts)
            for host in hosts:
                known_apis = None
                native_status = inventory_status(self.snapshot, "apim_native")
                if native_status.get(_subscription(host)) in ("collected", "empty"):
                    for _, fact in items(self.snapshot, "apim_native"):
                        if _low(fact.get("id")) != host:
                            continue
                        coverage = ((fact.get("_coverage") or {}).get("apis") or {}).get("status")
                        if coverage in ("collected", "empty"):
                            known_apis = {_low(api.get("id")) for api in fact.get("apis") or ()
                                          if isinstance(api, dict)}
                for pid in ([source.id, *source.attrs.get("groups", [])] if source is not None else []):
                    for assignment in self.assignments.get(pid, ()):
                        scope = assignment["scope"]
                        suffix = scope[len(host) + 1:] if scope.startswith(host + "/") else ""
                        patterns = {
                            "apim_api_resource": r"apis/[^/]+",
                            "apim_api_policy_resource": r"apis/[^/]+(?:/policies/[^/]+)?",
                            "apim_operation_policy_resource": r"apis/[^/]+(?:/operations/[^/]+(?:/policies/[^/]+)?)?",
                            "apim_product_policy_resource": r"products/[^/]+(?:/policies/[^/]+)?",
                        }
                        if re.fullmatch(patterns[attr], suffix):
                            if suffix.startswith("apis/") and known_apis is not None:
                                api_id = host + "/" + "/".join(suffix.split("/")[:2])
                                if api_id not in known_apis:
                                    continue
                            refs.add(scope)
            return sorted(refs)
        if attr.startswith("host_resource."):
            if attr == "host_resource.workspace":
                hosts = node.attrs.get("hosts") or []
                return sorted({h.split("/computes/", 1)[0] for h in hosts
                               if "/providers/microsoft.machinelearningservices/workspaces/" in h
                               and "/computes/" in h}) if hosts else None
            return None
        if attr == "scope":
            if node.kind == "azure_external_principal":
                return [node.attrs["resource"]]
            if node.kind == "azure_storage_local_user":
                return [node.scope]
            technique = (self.current_selector or {}).get("azure_challenge_fact")
            if owner == "target" and technique and node.kind in (
                    "azure_user", "azure_service_principal", "azure_managed_identity"):
                # A principal's directory home scope is not the ARM scope where
                # this particular technique's reviewed action must be allowed.
                scopes = {scope for tid, sid, kind, target_id, scope in self.exact_evidence
                          if tid == technique and source is not None and sid == source.id
                          and kind == node.kind and target_id == node.id}
                return [next(iter(scopes))] if len(scopes) == 1 else None
            if node.entity:
                return [node.scope]
            return ["dir:" + node.id]
        if attr == "id":
            if node.entity:
                return ["dir:" + node.attrs["template_id"]] if node.attrs.get("template_id") else [node.scope]
            if node.kind == "azure_managed_identity":
                return [node.attrs["uai_resource"]] if node.attrs.get("uai_resource") else []
            return ["dir:" + node.id]
        if attr == "application_id":
            app = (self.app_ids or {}).get(_low(node.attrs.get("app_id")))
            return ["dir:" + app["id"]] if app and app.get("id") else None
        if attr in ("name",):
            return [node.label]
        return None

    def resolve(self, template, source, target, pivot=None):
        if template is None:
            return [ANY], None
        if template == "/":
            return ["/"], None
        names = _TEMPLATE_PH.findall(template)
        if not names:
            return [_low(template)], None
        refs = [template]
        for name in names:
            if name in CONTROLLED_USER:
                # The user object the source modifies: itself when it is a user; otherwise a user it controls,
                # which the snapshot does not identify (any scope holding the permission, conditional).
                if source is None or source.kind != "azure_user":
                    return [ANY], ("conditional", "controlled_user_not_identified")
                refs = [r.replace("{" + name + "}", "dir:" + source.id) for r in refs]
                continue
            got = self.placeholder_values(name, source, target, pivot)
            if got is None:
                if name == "pivot":
                    return [ANY], ("conditional", "pivot_resource_not_verified")
                return [ANY], ("unknown", f"placeholder_{name}_not_in_snapshot")
            refs = [r.replace("{" + name + "}", v) for r in refs for v in got]
        return [r if r.startswith("dir:") else _low(r) for r in refs], None

    def pivot_candidates(self, source):
        technique = (self.current_entry or {}).get("id")
        if technique == "azure-devtestlabs-apply-artifacts":
            lab_vms = sorted(rid for rid, resource in self.resources.items()
                             if resource["type"] == "microsoft.devtestlab/labs/virtualmachines"
                             and re.fullmatch(
                                 r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.devtestlab/labs/[^/]+/virtualmachines/[^/]+",
                                 rid))
            if lab_vms:
                return [{"pivot": rid} for rid in lab_vms]
            status = inventory_status(self.snapshot, "devtest_lab_vm")
            if (self.exact_scopes and all(scope in self.graph_scopes or status.get(scope) in ("collected", "empty")
                                          for scope in self.exact_scopes)):
                return []
            return None
        if technique == "azure-automation-assign-user-assigned-identity":
            from .azure_automation_assign import pivots
            return pivots(self)
        if technique == "azure-appservice-assign-user-assigned-identity":
            sites = sorted(rid for rid, resource in self.resources.items()
                           if resource["type"] == "microsoft.web/sites"
                           and re.fullmatch(
                               r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+",
                               rid))
            candidates = [{"pivot": rid} for rid in sites]
            plans = sorted(rid for rid, resource in self.resources.items()
                           if resource["type"] == "microsoft.web/serverfarms" and re.fullmatch(
                               r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/serverfarms/[^/]+",
                               rid))
            plans += sorted(_low(item["id"]) for _, item in items(self.snapshot, "app_service_plan")
                            if isinstance(item, dict) and isinstance(item.get("id"), str)
                            and _low(item.get("type")) == "microsoft.web/serverfarms"
                            and re.fullmatch(
                                r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/serverfarms/[^/]+",
                                _low(item["id"])))
            for _, group in items(self.snapshot, "resource_group"):
                rg = _low(group.get("id")) if isinstance(group, dict) else ""
                if not re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+", rg):
                    continue
                for plan_id in sorted(set(plans)):
                    if _subscription(plan_id) != _subscription(rg):
                        continue
                    join = self.cached_check(source, {"action": "microsoft.web/serverfarms/join/action"}, plan_id)
                    if join is not None and join.confidence != "unknown":
                        candidates.append({"pivot": rg + "/providers/microsoft.web/sites/peaso-privesc-probe",
                                           "plan": plan_id, "created": True})
            if candidates:
                return candidates
            statuses = [inventory_status(self.snapshot, kind)
                        for kind in ("app_service", "resource_group", "app_service_plan")]
            if not self.exact_scopes or any(status.get(scope) not in ("collected", "empty")
                                            for status in statuses for scope in self.exact_scopes):
                return None
            return []
        if technique == "azure-aks-vmss-node-run-command":
            action = {"action": "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action"}
            instances = sorted({iid for ids in self.vmss_instances.values() for iid in ids
                                if self.cached_check(source, action, iid) is not None})
            if instances:
                return [{"pivot": iid} for iid in instances]
            if any(status not in ("collected", "empty") for status in self.vmss_instance_status.values()):
                return None
            return []
        if technique == "azure-aks-flux-configuration-write":
            clusters = sorted(rid for rid, resource in self.resources.items()
                              if resource["type"] in _FLUX_CLUSTER_TYPES
                              and re.fullmatch(
                                  r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/(?:microsoft\.containerservice/managedclusters|microsoft\.kubernetes/connectedclusters)/[^/]+",
                                  rid))
            cluster_set = set(clusters)
            configs = set()
            for cluster in clusters:
                prefix = cluster + "/providers/microsoft.kubernetesconfiguration/"
                for kind in _FLUX_CONFIG_TYPES:
                    configs.add(prefix + kind + "/peaso-probe")
            for rid, resource in self.resources.items():
                parent, marker, suffix = rid.rpartition("/providers/microsoft.kubernetesconfiguration/")
                if (marker and parent in cluster_set
                        and re.fullmatch(r"(fluxconfigurations|sourcecontrolconfigurations)/[^/]+", suffix)
                        and resource["type"] == "microsoft.kubernetesconfiguration/" + suffix.split("/", 1)[0]):
                    configs.add(rid)
            for pid in [source.id, *source.attrs.get("groups", ())]:
                for assignment in self.assignments.get(pid, ()):
                    rid = assignment["scope"]
                    parent, marker, suffix = rid.rpartition("/providers/microsoft.kubernetesconfiguration/")
                    if (marker and parent in cluster_set
                            and re.fullmatch(r"(fluxconfigurations|sourcecontrolconfigurations)/[^/]+", suffix)):
                        configs.add(rid)
            return [{"pivot": rid} for rid in sorted(configs)]
        if technique == "azure-acr-task-assign-user-assigned-identity":
            writable_targets = sorted(rid for rid, resource in self.resources.items()
                                      if resource["type"] in (
                                          "microsoft.containerregistry/registries",
                                          "microsoft.containerregistry/registries/tasks")
                                      and re.fullmatch(
                                          r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.containerregistry/registries/[^/]+(?:/tasks/[^/]+)?",
                                          rid))
            if writable_targets:
                return [{"pivot": rid} for rid in writable_targets]
            # Missing registry/task inventory is unresolved, rather than proof neither exists.
            if not self.exact_scopes or any(scope not in self.graph_scopes for scope in self.exact_scopes):
                return None
            return []
        if technique in _EXACT_SCOPE_CREDENTIALS:
            if not self._scope_credential_collection_complete():
                return None
            scopes = {resource for (tid, sid, target, resource), records in self.scope_credential_evidence.items()
                      if tid == technique and sid == source.id and any(
                          self._scope_credential_fact_bound(tid, sid, target, resource, fact)
                          for fact in records)}
            return [{"pivot": scope} for scope in sorted(scopes)]
        scopes = {a["scope"] for pid in [source.id, *source.attrs.get("groups", [])] for a in self.assignments.get(pid, [])}
        return [{"pivot": s} for s in sorted(scopes)]

    def _scope_credential_collection_complete(self):
        statuses = [status for scope, status in self.scope_credential_status.items()
                    if _low(scope) == f"/tenants/{self.tenant}".lower()]
        return bool(statuses) and all(status in ("collected", "empty") for status in statuses)

    def _scope_credential_fact_bound(self, technique, source_id, target_id, resource, fact):
        expected_type, actions = _EXACT_SCOPE_CREDENTIALS[technique]
        source = self.principals.get(source_id)
        target = self.principals.get(target_id)
        resource_item = self.resources.get(resource)
        if technique == "azure-apim-gateway-config-credential":
            gateway = _low(fact.get("GatewayResourceId"))
            if (not re.fullmatch(re.escape(resource) + r"/gateways/[^/]+", gateway)
                    or fact.get("GatewayConfigurationReadVerified") is not True
                    or fact.get("CredentialInGatewayConfigurationVerified") is not True
                    or not isinstance(fact.get("GatewayConfigurationEvidenceRef"), str)
                    or not fact["GatewayConfigurationEvidenceRef"].strip()):
                return False
        if technique == "azure-appconfig-snapshot-credential":
            name = fact.get("SnapshotName")
            if (not isinstance(name, str) or not name.strip() or "/" in name
                    or fact.get("SnapshotContentReadVerified") is not True
                    or fact.get("CredentialInSnapshotVerified") is not True
                    or not isinstance(fact.get("SnapshotContentEvidenceRef"), str)
                    or not fact["SnapshotContentEvidenceRef"].strip()):
                return False
        if technique == "azure-automation-job-output-credential":
            job = _low(fact.get("JobResourceId"))
            if (not re.fullmatch(re.escape(resource) + r"/jobs/[^/]+", job)
                    or fact.get("JobContentReadVerified") is not True
                    or fact.get("CredentialInJobContentVerified") is not True
                    or not isinstance(fact.get("JobContentEvidenceRef"), str)
                    or not fact["JobContentEvidenceRef"].strip()):
                return False
        if technique == "azure-automation-runbook-source-credential":
            runbook = _low(fact.get("RunbookResourceId"))
            if (not re.fullmatch(re.escape(resource) + r"/runbooks/[^/]+", runbook)
                    or fact.get("RunbookContentReadVerified") is not True
                    or fact.get("CredentialInRunbookContentVerified") is not True
                    or not isinstance(fact.get("RunbookContentEvidenceRef"), str)
                    or not fact["RunbookContentEvidenceRef"].strip()):
                return False
        if technique == "azure-storage-blob-content-credential":
            blob = _low(fact.get("BlobResourceId"))
            if (not re.fullmatch(re.escape(resource) + r"/blobservices/default/containers/[^/]+/blobs/.+", blob)
                    or fact.get("BlobContentReadVerified") is not True
                    or fact.get("CredentialInBlobContentVerified") is not True
                    or not isinstance(fact.get("BlobContentEvidenceRef"), str)
                    or not fact["BlobContentEvidenceRef"].strip()):
                return False
        return (source is not None and source.kind != "azure_challenge_foothold"
                and target is not None and target.kind == "azure_service_principal"
                and target.attrs.get("directory") is True
                and target.scope.lower() == f"/tenants/{self.tenant}".lower()
                and fact.get("TechniqueId") == technique and fact.get("SourceId") == source_id
                and fact.get("TargetKind") == "azure_service_principal"
                and fact.get("TargetId") == target_id
                and _low(fact.get("TargetScope")) == target.scope.lower()
                and fact.get("CredentialSubjectId") == target_id
                and fact.get("CredentialKind") == "entra_service_principal_client_secret"
                and _low(fact.get("CredentialScope")) == resource
                and resource_item is not None and resource_item.get("type") == expected_type
                and _low(fact.get("AccessAction")) in {action for action, _ in actions})

    # --------------------------------------------------------------- targets
    def targets_for(self, kind, selector):
        if (selector or {}).get("azure_static_site_deployment_token"):
            if kind != "azure_verified_authority":
                return []
            return [Node(f"azure_verified_authority:{rid}", kind, "azure", rid,
                         f"Deployment authority for {resource.get('name') or rid}",
                         attrs={"scope": rid, "type": resource["type"], "name": resource.get("name")},
                         entity=True)
                    for rid, resource in sorted(self.resources.items())
                    if resource["type"] == "microsoft.web/staticsites"
                    and re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/staticsites/[^/]+", rid)]
        if (selector or {}).get("azure_external_principal_evidence"):
            return list(self.external_principal_targets.values()) if kind == "azure_external_principal" else []
        exact = self.exact_targets_for(kind, selector)
        return exact if exact is not None else self.targets(kind)

    def service_managed(self, node):
        """Microsoft first-party service principals (application owned by a Microsoft tenant) are not customer
        controlled; entries that model them explicitly (condition/blocker microsoft_first_party_sp) keep them."""
        if node.kind != "azure_service_principal":
            return False
        return node.attrs.get("app_owner_org") in MICROSOFT_TENANTS

    def include_service_managed(self, compiled):
        entry = compiled.get("entry") or {}
        ids = [b if isinstance(b, str) else (b or {}).get("id")
               for b in list(entry.get("blockers") or []) + list(entry.get("conditions") or [])]
        return super().include_service_managed(compiled) or "microsoft_first_party_sp" in ids

    def targets(self, kind):
        if kind == "azure_storage_local_user":
            from .storage_local_identity import targets
            return targets(self)
        if kind in ("azure_user", "azure_service_principal", "azure_managed_identity", "entra_group"):
            return [n for n in self.principals.values() if n.kind == kind]
        if kind == "azure_scope_owner":
            scopes = set(self.scopes) | {"/"}
            for rid in self.resources:
                sub = _subscription(rid)
                if sub:
                    scopes.add(sub)
                rg = _resource_group(rid)
                if rg:
                    scopes.add(rg)
            return [self.entity(kind, s) for s in sorted(scopes) if s == "/" or s.count("/") <= 4 or "/managementgroups/" in s]
        if kind in ("azure_dataplane_admin", "k8s_cluster_admin"):
            return [self.entity(kind, rid, r) for rid, r in sorted(self.resources.items())]
        if kind == "entra_role":
            seen, out = set(), []
            for info in self.dir_roles.values():
                if info["id"] in seen:
                    continue
                seen.add(info["id"])
                out.append(self.entity(kind, info["id"], {"name": info["name"]}))
            if not out:
                out.append(self.entity(kind, GLOBAL_ADMIN, {"name": "Global Administrator"}))
            return out
        return []

    def entity(self, kind, scope, extra=None):
        cache = self.__dict__.setdefault("_entities", {})
        key = (kind, scope)
        if key not in cache:
            extra = extra or {}
            if kind == "azure_scope_owner":
                label = "Owner of " + ("tenant root (/)" if scope == "/" else scope)
            elif kind == "entra_role":
                label = f"Entra role {extra.get('name', scope)}"
            elif kind == "k8s_cluster_admin":
                label = f"cluster-admin of {extra.get('name') or scope}"
            else:
                label = f"Data-plane admin of {extra.get('name') or scope}"
            cache[key] = Node(f"{kind}:{scope}", kind, "azure", scope if kind != "entra_role" else f"/tenants/{self.tenant}",
                              label, attrs={"scope": scope, "type": extra.get("type"), "template_id": scope if kind == "entra_role" else None,
                                            "name": extra.get("name")}, entity=True)
        return cache[key]

    def unknown_target_scopes(self, kind):
        if (self.current_selector or {}).get("azure_static_site_deployment_token"):
            graph = inventory_status(self.snapshot, "resource_graph")
            return {scope: graph.get(scope, "not_collected") for scope in self.exact_scopes
                    if graph.get(scope) not in ("collected", "empty")}
        if (self.current_selector or {}).get("azure_external_principal_evidence"):
            return {}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_servicefabric_application_uami_path"):
            native_cluster = inventory_status(self.snapshot, "service_fabric_cluster")
            graph = inventory_status(self.snapshot, "resource_graph")
            identities = inventory_status(self.snapshot, "managed_identity")
            return {scope: "not_collected" for scope in self.exact_scopes
                    if (native_cluster.get(scope) not in ("collected", "empty")
                        or graph.get(scope) not in ("collected", "empty")
                        or (identities.get(scope) not in ("collected", "empty")
                            and graph.get(scope) not in ("collected", "empty")))}
        if (kind == "azure_dataplane_admin" and _low((self.current_selector or {}).get("azure_resource_type"))
                == "microsoft.purview/accounts"):
            native = inventory_status(self.snapshot, "purview_account")
            graph = inventory_status(self.snapshot, "resource_graph")
            return {scope: native.get(scope, graph.get(scope, "not_collected"))
                    for scope in self.exact_scopes
                    if native.get(scope, graph.get(scope)) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_aci_assignable_uami"):
            status = inventory_status(self.snapshot, "managed_identity")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_aci_exec_running_identity"):
            status = inventory_status(self.snapshot, "container_group")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_aci_existing_write_identity"):
            status = inventory_status(self.snapshot, "container_group")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_batch_job_pool_identity"):
            status = inventory_status(self.snapshot, "batch_pool")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_batch_shared_key_pool_identity"):
            status = inventory_status(self.snapshot, "batch_pool")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_batch_pool_starttask_identity"):
            status = inventory_status(self.snapshot, "batch_pool")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_batch_pool_assignable_uami"):
            status = inventory_status(self.snapshot, "managed_identity")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_containerapp_assignable_uami"):
            status = inventory_status(self.snapshot, "managed_identity")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_containerapp_create_uami_path"):
            status = inventory_status(self.snapshot, "managed_identity")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_containerapp_exec_identity"):
            status = inventory_status(self.snapshot, "container_app_runtime")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_containerapp_write_existing_identity"):
            status = inventory_status(self.snapshot, "container_app_runtime")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_containerapp_job_assignable_uami"):
            status = inventory_status(self.snapshot, "managed_identity")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_managed_identity" and (self.current_selector or {}).get("azure_containerapp_job_execution_identity"):
            status = inventory_status(self.snapshot, "container_app_job")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_dataplane_admin" and (self.current_selector or {}).get("azure_confidential_ledger_admin_path"):
            status = inventory_status(self.snapshot, "resource_graph")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_dataplane_admin" and ((self.current_selector or {}).get("azure_mysql_flexible_admin_password_reset")
                or (self.current_selector or {}).get("azure_mysql_flexible_entra_admin_write")):
            status = inventory_status(self.snapshot, "mysql_flexible_server")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_dataplane_admin" and ((self.current_selector or {}).get("azure_postgresql_flexible_admin_password_reset")
                or (self.current_selector or {}).get("azure_postgresql_flexible_entra_admin_write")):
            status = inventory_status(self.snapshot, "postgresql_flexible_server")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_dataplane_admin" and ((self.current_selector or {}).get("azure_sql_server_admin_password_reset")
                or (self.current_selector or {}).get("azure_sql_server_entra_admin_write")):
            status = inventory_status(self.snapshot, "sql_server")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_dataplane_admin" and ((self.current_selector or {}).get("azure_sqlmi_admin_password_reset")
                or (self.current_selector or {}).get("azure_sqlmi_entra_admin_write")):
            status = inventory_status(self.snapshot, "mssql_managed_instance")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_dataplane_admin" and ((self.current_selector or {}).get("azure_mongo_cluster_admin_password")
                or (self.current_selector or {}).get("azure_mongo_cluster_self_root")):
            status = inventory_status(self.snapshot, "mongo_cluster")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_dataplane_admin" and ((self.current_selector or {}).get("azure_cosmos_mongo_user_write")
                or (self.current_selector or {}).get("azure_cosmos_other_api_role_grant")
                or (self.current_selector or {}).get("azure_cosmos_sql_role_grant")):
            status = inventory_status(self.snapshot, "cosmos_account")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind == "azure_dataplane_admin" and (self.current_selector or {}).get("azure_databricks_workspace_admin"):
            native = inventory_status(self.snapshot, "databricks_workspace")
            graph = inventory_status(self.snapshot, "resource_graph")
            return {scope: native.get(scope, graph.get(scope, "not_collected")) for scope in self.exact_scopes
                    if native.get(scope, graph.get(scope)) not in ("collected", "empty")}
        if (self.current_selector or {}).get("credential_stored_in_scope"):
            # A missing credential review cannot establish any target principal.
            return {}
        if kind == "azure_storage_local_user":
            states = inventory_status(self.snapshot, "storage_local_user")
            return unavailable(states) if states else {scope: "not_collected" for scope in self.exact_scopes}
        if (self.current_selector or {}).get("azure_challenge_fact"):
            from .azure_self_grants import CONTRACT as self_grant_contract
            from .azure_deployment_pivots import CONTRACT as deployment_contract
            technique = self.current_selector["azure_challenge_fact"]
            if technique == "azure-datafactory-dataplane-access-token":
                return {}
            if technique in deployment_contract:
                # A source-control binding is not a deployment. Only an exact
                # reviewed build/revision/identity record can name a target.
                return {}
            if technique in self_grant_contract:
                # These grants are bound to individually reviewed resource IDs.
                # Missing subscription-wide inventory cannot name another grant.
                scopes = {scope for tid, _, _, _, scope in self.exact_evidence if tid == technique}
                return {scope: self.exact_status.get(scope, "not_collected") for scope in scopes
                        if self.exact_status.get(scope) not in ("collected", "empty")}
            return self.exact_unknown_target_scopes()
        if kind == "azure_managed_identity" and any(
                str(service).lower() == "microsoft.machinelearningservices/workspaces/computes"
                for service in as_list((self.current_selector or {}).get("attached_to_service"))):
            status = inventory_status(self.snapshot, "resource_graph")
            return {scope: status.get(scope, "not_collected") for scope in self.exact_scopes
                    if status.get(scope) not in ("collected", "empty")}
        if kind in ("azure_user", "azure_service_principal", "entra_group"):
            collection = {"azure_user": "directory_user", "azure_service_principal": "directory_service_principal",
                          "entra_group": "directory_group"}[kind]
            status = inventory_status(self.snapshot, collection)
            return unavailable(status) if status else {f"/tenants/{self.tenant}": "not_collected"}
        return {}

    def allowed_scopes(self, rule, source):
        return None

    def selector(self, key, value, candidates, source, pivot=None):
        if key == "azure_static_site_deployment_token":
            return {ident: ("conditional", "site_deployment_token_not_retrieved")
                    for ident in candidates} if value is True else {}
        if key == "azure_vmss_instance_runcommand_action_path":
            from .azure_vmss_runcommand import select_action
            return select_action(self, candidates, source) if value is True else {}
        if key == "azure_vmss_instance_runcommand_path":
            from .azure_vmss_runcommand import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_vmss_model_rollout_path":
            from .azure_vmss_model import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_vm_runcommand_action_path":
            from .azure_vm_assign_existing import select_runcommand_action
            return select_runcommand_action(self, candidates, source) if value is True else {}
        if key == "azure_vm_os_disk_swap_path":
            from .azure_vm_assign_existing import select_os_disk_swap
            return select_os_disk_swap(self, candidates, source) if value is True else {}
        if key == "azure_vm_managed_runcommand_path":
            from .azure_vm_assign_existing import select_managed_runcommand
            return select_managed_runcommand(self, candidates, source) if value is True else {}
        if key == "azure_vm_gallery_application_path":
            from .azure_vm_gallery_application import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_vm_extension_execution_path":
            from .azure_vm_assign_existing import select_extension_execution
            return select_extension_execution(self, candidates, source) if value is True else {}
        if key == "azure_vm_reimage_customdata_path":
            from .azure_vm_assign_existing import select_reimage_customdata
            return select_reimage_customdata(self, candidates, source) if value is True else {}
        if key == "azure_vm_create_uami_path":
            from .azure_vm_assign_existing import select_create
            return select_create(self, candidates, source) if value is True else {}
        if key == "azure_vm_assign_indirect_uami_path":
            from .azure_vm_assign_existing import select_indirect
            return select_indirect(self, candidates, source) if value is True else {}
        if key == "azure_vm_assign_existing_uami_path":
            from .azure_vm_assign_existing import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_synapse_entra_admin_path":
            from .azure_synapse_entra_admin import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_spring_deployment_identity_path":
            from .azure_spring_app_identity import select_existing_deployment
            return select_existing_deployment(self, candidates, source) if value is True else {}
        if key == "azure_spring_app_uami_path":
            from .azure_spring_app_identity import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_servicefabric_application_uami_path":
            from .azure_servicefabric_application import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_policy_assignment_identity_path":
            from .azure_policy_assignment_identity import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_auth_admin_user_takeover":
            from .azure_auth_admin_takeover import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_helpdesk_password_reset":
            from .azure_helpdesk_password_reset import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_password_admin_reset":
            from .azure_helpdesk_password_reset import select
            return select(self, candidates, source, role_name="password administrator") if value is True else {}
        if key == "entra_user_admin_password_reset":
            from .azure_helpdesk_password_reset import select
            return select(self, candidates, source, role_name="user administrator", allow_app=True,
                          allow_target_enable=True) if value is True else {}
        if key == "entra_nonadmin_password_reset":
            from .azure_nonadmin_password_reset import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_privileged_auth_user_takeover":
            from .azure_privileged_auth_takeover import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_pim_eligible_for_source":
            from .azure_pim_role_activation import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_graph_group_user_membership":
            from .azure_graph_group_membership import select_controlled_user
            return select_controlled_user(self, candidates, source) if value is True else {}
        if key == "entra_pim_controlled_user_eligibility":
            from .azure_graph_group_membership import select_pim_controlled_user_eligibility
            return select_pim_controlled_user_eligibility(self, candidates, source) if value is True else {}
        if key == "entra_graph_group_sp_membership":
            from .azure_graph_group_membership import select_service_principal
            return select_service_principal(self, candidates, source) if value is True else {}
        if key == "entra_graph_directory_role_self_grant":
            from .azure_graph_role_self_grant import select_directory_role_self_grant
            return select_directory_role_self_grant(self, candidates, source) if value is True else {}
        if key == "entra_role_assignment_self_grant":
            from .azure_role_assignment_manage import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_graph_tap_user_target":
            from .azure_graph_tap import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_pim_active_sp_membership":
            from .azure_graph_group_membership import select_pim_active_service_principal
            return select_pim_active_service_principal(self, candidates, source) if value is True else {}
        if key == "entra_graph_self_grant_directory_role":
            from .azure_graph_role_self_grant import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_graph_application_credential_target":
            from .azure_graph_app_credentials import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_catalog_self_grant_role":
            from .azure_entitlement_catalog import select_role
            return select_role(self, candidates, source) if value is True else {}
        if key == "entra_catalog_self_grant_group":
            from .azure_entitlement_catalog import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_auto_assignment_package_group":
            from .azure_entitlement_auto import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_user_upn_on_federatable_custom_domain":
            from .azure_domain_federation import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_custom_role_assigned_to_source":
            from .azure_custom_role import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_source_is_owner_of_application":
            from .azure_app_owner import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_agent_blueprint_principal_or_child_identity":
            from .azure_agent_blueprint import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_devtestlab_artifact_identity":
            from .azure_devtestlab_artifacts import select
            return select(self, candidates, pivot) if value is True else {}
        if key == "azure_automation_assignable_uami":
            from .azure_automation_assign import select
            return select(self, candidates, source, pivot) if value is True else {}
        if key == "azure_automation_runbook_identity_path":
            from .azure_automation_assign import select_attached_identity
            return select_attached_identity(self, candidates, source) if value is True else {}
        if key == "azure_automation_hybrid_worker_path":
            from .azure_automation_assign import select_hybrid_worker
            return select_hybrid_worker(self, candidates, source) if value is True else {}
        if key == "azure_batch_job_pool_identity":
            from .azure_batch_job import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_batch_shared_key_pool_identity":
            from .azure_batch_shared_key import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_batch_pool_starttask_identity":
            from .azure_batch_pool_starttask import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_batch_pool_assignable_uami":
            from .azure_batch_pool_assign import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_containerapp_assignable_uami":
            from .azure_containerapp_assign import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_containerapp_create_uami_path":
            from .azure_containerapp_create import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_containerapp_exec_identity":
            from .azure_containerapp_exec import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_containerapp_write_existing_identity":
            from .azure_containerapp_write_existing import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_containerapp_job_assignable_uami":
            from .azure_containerapp_job_assign import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_containerapp_job_execution_identity":
            from .azure_containerapp_job_start import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_confidential_ledger_admin_path":
            from .azure_confidential_ledger import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_mongo_cluster_admin_password":
            from .azure_mongo_cluster_admin_password import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_mysql_flexible_admin_password_reset":
            from .azure_mysql_flexible_admin_password_reset import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_mysql_flexible_entra_admin_write":
            from .azure_mysql_flexible_entra_admin_write import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_postgresql_flexible_admin_password_reset":
            from .azure_postgresql_flexible_admin_password_reset import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_postgresql_flexible_entra_admin_write":
            from .azure_postgresql_flexible_entra_admin_write import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_sql_server_admin_password_reset":
            from .azure_sql_server_admin_password_reset import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_sql_server_entra_admin_write":
            from .azure_sql_server_entra_admin_write import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_sqlmi_admin_password_reset":
            from .azure_sqlmi_admin_password_reset import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_sqlmi_entra_admin_write":
            from .azure_sqlmi_entra_admin_write import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_mongo_cluster_self_root":
            from .azure_mongo_cluster_self_root import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_cosmos_mongo_user_write":
            from .azure_cosmos_mongo_user_write import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_cosmos_sql_role_grant":
            from .azure_cosmos_sql_role_grant import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_databricks_workspace_admin":
            from .azure_databricks_workspace_admin import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_cosmos_other_api_role_grant":
            from .azure_cosmos_other_api_role_grant import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_apim_restorable_backup":
            from .azure_apim_restore import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_vmss_instance_identity":
            if value is not True:
                return {}
            instances = {_low(item.get("pivot")) for item in as_list(pivot)
                         if isinstance(item, dict) and isinstance(item.get("pivot"), str)}
            out = {}
            for tid, target in candidates.items():
                hosts = set(target.attrs.get("hosts") or ())
                if any(self.vmss_modes.get(host) in ("", "uniform")
                       and iid in self.vmss_instances.get(host, ()) for host in hosts for iid in instances):
                    out[tid] = None
                elif not instances and any(self.vmss_instance_status.get(host) not in ("collected", "empty")
                                           for host in hosts if self.resources.get(host, {}).get("type") == "microsoft.compute/virtualmachinescalesets"):
                    out[tid] = ("unknown", "vmss_instance_inventory_unavailable")
            return out
        if key == "azure_flux_cluster_path":
            if value is not True or source is None:
                return {}
            pivots = {_low(item.get("pivot")) for item in as_list(pivot)
                      if isinstance(item, dict) and isinstance(item.get("pivot"), str)}
            out = {}
            for tid, target in candidates.items():
                cluster = _low(target.scope)
                if target.attrs.get("type") not in _FLUX_CLUSTER_TYPES or cluster not in self.resources:
                    continue
                prefix = cluster + "/providers/microsoft.kubernetesconfiguration/"
                possible = False
                unresolved = False
                for rid in pivots:
                    if not rid.startswith(prefix):
                        continue
                    suffix = rid[len(prefix):]
                    match = re.fullmatch(r"(fluxconfigurations|sourcecontrolconfigurations)/([^/]+)", suffix)
                    if not match:
                        continue
                    kind, name = match.groups()
                    resource = self.resources.get(rid)
                    if resource is not None and resource.get("type") != "microsoft.kubernetesconfiguration/" + kind:
                        continue
                    # A new child needs a grant inherited from its parent. A child-scoped
                    # grant can update only that already inventoried configuration.
                    if resource is None and name != "peaso-probe":
                        if self.cached_check(source, {"action": _FLUX_CONFIG_TYPES[kind]}, rid) is not None:
                            unresolved = True
                        continue
                    ref = cluster if resource is None else rid
                    grant = self.cached_check(source, {"action": _FLUX_CONFIG_TYPES[kind]}, ref)
                    if grant is None:
                        continue
                    if grant.confidence == "unknown":
                        unresolved = True
                    else:
                        possible = True
                        break
                if possible:
                    out[tid] = ("conditional", "flux_configuration_writable_on_exact_cluster")
                elif unresolved:
                    out[tid] = ("unknown", "flux_configuration_write_unresolved")
            return out
        if key in ("azure_aks_rbac_group_impersonation", "azure_aks_rbac_cluster_binding"):
            if value is not True or source is None:
                return {}
            states = {}
            for collection in ("aks_cluster", "resource_graph"):
                for _, item in items(self.snapshot, collection):
                    rid = _low(item.get("id"))
                    if _low(item.get("type")) != "microsoft.containerservice/managedclusters":
                        continue
                    props = item.get("properties") or {}
                    aad = props.get("aadProfile") if isinstance(props, dict) else None
                    enabled = aad.get("enableAzureRBAC") if isinstance(aad, dict) else None
                    if type(enabled) is bool:
                        states.setdefault(rid, set()).add(enabled)
            facts = {}
            for fact_scope, fact in items(self.snapshot, "azure_privesc_challenge_evidence"):
                if (isinstance(fact, dict)
                        and fact.get("TechniqueId") == (self.current_entry or {}).get("id")
                        and fact.get("SourceId") == source.id
                        and fact.get("TargetKind") == "k8s_cluster_admin"
                        and _low(fact_scope) == _low(fact.get("TargetScope"))
                        and _low(fact.get("TargetId")) == _low(fact_scope)):
                    facts.setdefault(_low(fact_scope), []).append(fact)
            out = {}
            for tid, target in candidates.items():
                scope = _low(target.scope)
                if target.attrs.get("type") != "microsoft.containerservice/managedclusters":
                    continue
                enabled = states.get(scope, set())
                if enabled == {False}:
                    continue
                if enabled != {True}:
                    out[tid] = ("unknown", "aks_azure_rbac_setting_unresolved")
                    continue
                grant = self.cached_check(source, {
                    "action": "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"}, scope)
                records = facts.get(scope, ())
                reviewed = (len(records) == 1 and records[0].get("Status") == "verified"
                            and records[0].get("VerifiedPreconditions") is True
                            and records[0].get("KubernetesApiAuthenticated") is True
                            and isinstance(records[0].get("EvidenceRef"), str)
                            and bool(records[0]["EvidenceRef"]))
                if records and not reviewed:
                    out[tid] = ("unknown", "aks_api_authentication_review_unresolved")
                elif reviewed or (grant is not None and grant.confidence != "unknown"):
                    out[tid] = ("conditional", "authenticated_aks_api_and_azure_rbac")
                else:
                    out[tid] = ("unknown", "aks_api_authentication_not_verified")
            return out
        if key == "azure_acr_existing_task_identity":
            if value is not True or source is None:
                return {}
            if "_acr_task_records" not in self.__dict__:
                tasks = {}
                for _, item in items(self.snapshot, "resource_graph"):
                    rid = _low(item.get("id"))
                    if (_low(item.get("type")) == "microsoft.containerregistry/registries/tasks"
                            and re.fullmatch(
                                r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.containerregistry/registries/[^/]+/tasks/[^/]+",
                                rid)):
                        tasks.setdefault(rid, []).append(item)
                self._acr_task_records = tasks
            out = {}
            write = {"action": "Microsoft.ContainerRegistry/registries/tasks/write"}
            identity_status = inventory_status(self.snapshot, "managed_identity")
            for tid, target in candidates.items():
                possible = False
                unresolved = False
                for host in target.attrs.get("hosts") or ():
                    records = self._acr_task_records.get(_low(host), ())
                    if len(records) != 1:
                        unresolved |= len(records) > 1
                        continue
                    identity = records[0].get("identity")
                    if not isinstance(identity, dict):
                        unresolved = True
                        continue
                    attached = (target.attrs.get("mi_type") == "system_assigned"
                                and identity.get("principalId") == tid)
                    if target.attrs.get("mi_type") == "user_assigned":
                        uamis = identity.get("userAssignedIdentities")
                        if isinstance(uamis, dict):
                            attached = any(_low(resource) == target.attrs.get("uai_resource")
                                           and isinstance(detail, dict)
                                           and detail.get("principalId") in (None, tid)
                                           for resource, detail in uamis.items())
                        if attached and target.attrs.get("uai_resource_verified") is not True:
                            unresolved |= identity_status.get(_subscription(target.attrs.get("uai_resource"))) not in ("collected", "empty")
                            attached = False
                    if not attached:
                        continue
                    grant = self.cached_check(source, write, _low(host))
                    if grant is None:
                        continue
                    if grant.confidence == "unknown":
                        unresolved = True
                    else:
                        possible = True
                        break
                if possible:
                    out[tid] = ("conditional", "exact_acr_task_identity_and_write_right")
                elif unresolved:
                    out[tid] = ("unknown", "acr_task_identity_or_write_unresolved")
            return out
        if key == "azure_acr_assignable_uami":
            if value is not True or source is None:
                return {}
            known_task_target = bool(pivot) and any(
                isinstance(item, dict) and self.resources.get(_low(item.get("pivot")), {}).get("type")
                in ("microsoft.containerregistry/registries",
                    "microsoft.containerregistry/registries/tasks") for item in pivot)
            registry_incomplete = not self.exact_scopes or any(
                scope not in self.graph_scopes for scope in self.exact_scopes)
            identity_status = inventory_status(self.snapshot, "managed_identity")
            out = {}
            for tid, target in candidates.items():
                resource = target.attrs.get("uai_resource")
                if not isinstance(resource, str) or not re.fullmatch(
                        r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+", resource):
                    out[tid] = ("unknown", "acr_uami_resource_not_identified")
                elif target.attrs.get("uai_resource_verified") is True and known_task_target:
                    out[tid] = ("conditional", "known_acr_task_write_target_and_exact_uami")
                elif (not target.attrs.get("uai_resource_verified") and
                      identity_status.get(_subscription(resource)) not in ("collected", "empty")) or registry_incomplete:
                    out[tid] = ("unknown", "acr_registry_or_uami_inventory_incomplete")
            return out
        if key == "azure_aci_existing_write_identity":
            if value is not True or source is None:
                return {}
            groups = {}
            for _, item in items(self.snapshot, "container_group"):
                rid = _low(item.get("id"))
                if (re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.containerinstance/containergroups/[^/]+", rid)
                        and _low(item.get("type")) == "microsoft.containerinstance/containergroups"):
                    groups.setdefault(rid, []).append(item)
            status = inventory_status(self.snapshot, "container_group")
            complete = bool(self.exact_scopes) and all(
                status.get(scope) in ("collected", "empty") for scope in self.exact_scopes)
            out = {}
            for tid, target in candidates.items():
                possible = False
                unresolved = not complete
                for host in target.attrs.get("hosts") or ():
                    native = groups.get(_low(host), ())
                    if len(native) != 1:
                        unresolved |= len(native) > 1
                        continue
                    item = native[0]
                    identity = item.get("identity") or {}
                    if not isinstance(identity, dict):
                        unresolved = True
                        continue
                    attached = target.attrs.get("mi_type") == "system_assigned" and identity.get("principalId") == tid
                    uamis = identity.get("userAssignedIdentities") or {}
                    if target.attrs.get("mi_type") == "user_assigned" and isinstance(uamis, dict):
                        attached = any(_low(resource) == target.attrs.get("uai_resource")
                                       and isinstance(detail, dict)
                                       and detail.get("principalId") in (None, tid)
                                       for resource, detail in uamis.items())
                    if not attached:
                        continue
                    props = item.get("properties")
                    view = props.get("instanceView") if isinstance(props, dict) else None
                    state = _low(view.get("state")) if isinstance(view, dict) else ""
                    if state != "running":
                        unresolved |= state not in ("succeeded", "failed")
                        continue
                    containers = props.get("containers") if isinstance(props, dict) else None
                    if not isinstance(containers, list) or not any(
                            isinstance(container, dict) and isinstance(container.get("name"), str)
                            and container["name"] for container in containers):
                        unresolved = True
                        continue
                    grant = self.cached_check(source, {"action": "Microsoft.ContainerInstance/containerGroups/write"}, _low(host))
                    if grant is None:
                        continue
                    if grant.confidence == "unknown":
                        unresolved = True
                    else:
                        possible = True
                        break
                if possible:
                    out[tid] = ("conditional", "existing_aci_group_with_identity_and_write_right")
                elif unresolved:
                    out[tid] = ("unknown", "aci_existing_group_or_write_unresolved")
            return out
        if key == "azure_aci_exec_running_identity":
            if value is not True or source is None:
                return {}
            groups = {}
            for _, item in items(self.snapshot, "container_group"):
                rid = _low(item.get("id"))
                if (not re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.containerinstance/containergroups/[^/]+", rid)
                        or _low(item.get("type")) != "microsoft.containerinstance/containergroups"):
                    continue
                groups.setdefault(rid, []).append(item)
            status = inventory_status(self.snapshot, "container_group")
            complete = bool(self.exact_scopes) and all(
                status.get(scope) in ("collected", "empty") for scope in self.exact_scopes)
            def container_state(container):
                if not isinstance(container, dict) or not isinstance(container.get("properties"), dict):
                    return None
                view = container["properties"].get("instanceView")
                if not isinstance(view, dict) or not isinstance(view.get("currentState"), dict):
                    return None
                value = view["currentState"].get("state")
                return _low(value) if isinstance(value, str) else None
            out = {}
            for tid, target in candidates.items():
                possible = False
                unresolved = not complete
                for host in target.attrs.get("hosts") or ():
                    native = groups.get(_low(host), ())
                    if len(native) != 1:
                        unresolved |= len(native) > 1
                        continue
                    item = native[0]
                    identity = item.get("identity") or {}
                    if not isinstance(identity, dict):
                        unresolved = True
                        continue
                    uamis = identity.get("userAssignedIdentities") or {}
                    attached = (target.attrs.get("mi_type") == "system_assigned"
                                and identity.get("principalId") == tid)
                    if (target.attrs.get("mi_type") == "user_assigned" and isinstance(uamis, dict)):
                        attached = any(_low(resource) == target.attrs.get("uai_resource")
                                       and isinstance(detail, dict)
                                       and detail.get("principalId") in (None, tid)
                                       for resource, detail in uamis.items())
                    if not attached:
                        continue
                    props = item.get("properties") or {}
                    view = (props.get("instanceView") or {}) if isinstance(props, dict) else {}
                    state = _low(view.get("state")) if isinstance(view, dict) else ""
                    if state != "running":
                        unresolved |= state not in ("stopped", "pending", "succeeded", "failed")
                        continue
                    containers = props.get("containers") if isinstance(props, dict) else None
                    if not isinstance(containers, list) or not containers:
                        unresolved = True
                        continue
                    states = [container_state(container) for container in containers]
                    running = "running" in states
                    if not running:
                        unresolved |= None in states
                        continue
                    grant = self.cached_check(source, {"action": "Microsoft.ContainerInstance/containerGroups/containers/exec/action"}, _low(host))
                    if grant is not None:
                        if grant.confidence == "unknown":
                            unresolved = True
                        else:
                            possible = True
                            break
                if possible:
                    out[tid] = ("conditional", "running_container_with_exact_identity_and_exec_right")
                elif unresolved:
                    out[tid] = ("unknown", "aci_running_container_or_identity_unresolved")
            return out
        if key == "azure_aci_assignable_uami":
            if value is not True or source is None:
                return {}
            write = {"action": "Microsoft.ContainerInstance/containerGroups/write"}
            groups = sorted({_low(item.get("id")) for _, item in items(self.snapshot, "container_group")
                             if isinstance(item.get("id"), str)
                             and _low(item.get("type")) == "microsoft.containerinstance/containergroups"
                             and re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.containerinstance/containergroups/[^/]+", _low(item["id"]))})
            resource_groups = sorted({_low(item.get("id")) for _, item in items(self.snapshot, "resource_group")
                                      if isinstance(item.get("id"), str)
                                      and re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+", _low(item["id"]))})
            group_refs = groups + [rg + "/providers/microsoft.containerinstance/containergroups/peaso-aci-probe"
                                   for rg in resource_groups]
            grants = [self.cached_check(source, write, ref) for ref in group_refs]
            known = [grant for grant in grants if grant is not None]
            statuses = [inventory_status(self.snapshot, kind)
                        for kind in ("container_group", "resource_group")]
            complete = bool(self.exact_scopes) and all(
                status.get(scope) in ("collected", "empty")
                for status in statuses for scope in self.exact_scopes)
            out = {}
            for tid, target in candidates.items():
                resource = target.attrs.get("uai_resource")
                if not isinstance(resource, str) or not re.fullmatch(
                        r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+", resource):
                    out[tid] = ("unknown", "aci_identity_resource_not_verified")
                    continue
                if known:
                    out[tid] = (("unknown", "aci_write_or_deny_unresolved")
                                if all(grant.confidence == "unknown" for grant in known) else
                                ("conditional", "writable_aci_group_or_resource_group"))
                elif not complete:
                    out[tid] = ("unknown", "aci_group_or_resource_group_inventory_incomplete")
            return out
        if key == "azure_external_plane":
            return {ident: ("conditional", "reviewed_external_plane") for ident, node in candidates.items()
                    if node.attrs.get("external_plane") == value}
        if key == "azure_external_principal_evidence":
            from .azure_external_principal import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_storage_local_credential":
            from .storage_local_identity import select
            return select(self, value, candidates)
        if key == "azure_challenge_fact":
            if value == "azure-datafactory-dataplane-access-token":
                # Historical YAML claimed this read-only token could run a
                # pipeline. Never revive that edge from a versioned catalog.
                return {}
            return self.exact_selector(value, candidates, source)
        if key == "credential_stored_in_scope":
            technique = (self.current_entry or {}).get("id")
            if technique not in _EXACT_SCOPE_CREDENTIALS or value != "{pivot}" or source is None:
                return {}
            if not self._scope_credential_collection_complete():
                return {}
            scopes = {_low(item.get("pivot")) for item in as_list(pivot) if isinstance(item, dict)}
            if technique in ("azure-automation-job-output-credential",
                             "azure-automation-runbook-source-credential") and not scopes:
                scopes = {resource for tid, sid, _, resource in self.scope_credential_evidence
                          if tid == technique and sid == source.id}
            if not scopes:
                return {}
            actions = dict(_EXACT_SCOPE_CREDENTIALS[technique][1])
            out = {}
            for target_id, target in candidates.items():
                if target.kind != "azure_service_principal" or not target.attrs.get("directory"):
                    continue
                for resource in scopes:
                    records = self.scope_credential_evidence.get((technique, source.id, target_id, resource), ())
                    if len(records) != 1:
                        continue
                    fact = records[0]
                    if not self._scope_credential_fact_bound(technique, source.id, target_id, resource, fact):
                        continue
                    if fact.get("Status") == "disproven":
                        continue
                    if (fact.get("Status") != "verified" or fact.get("VerifiedPreconditions") is not True
                            or fact.get("CredentialUsable") is not True
                            or not isinstance(fact.get("EvidenceRef"), str) or not fact["EvidenceRef"]):
                        continue
                    action = _low(fact["AccessAction"])
                    checked_resource = (_low(fact["JobResourceId"])
                                        if technique == "azure-automation-job-output-credential" else
                                        _low(fact["RunbookResourceId"])
                                        if technique == "azure-automation-runbook-source-credential" else
                                        _low(fact["BlobResourceId"])
                                        if technique == "azure-storage-blob-content-credential" else resource)
                    grants = [self.check(source, {"action": action, "data_action": actions[action]}, checked_resource)]
                    if all(grant is not None for grant in grants):
                        if all(grant.confidence != "unknown" for grant in grants):
                            out[target_id] = ("conditional", "exact_credential_subject_and_scope")
            return out
        if key == "_resource_type_from_action":
            action = _low(value)
            types = {r["type"] for r in self.resources.values()}
            match = max((t for t in types if action.startswith(t + "/")), key=len, default=None)
            return {tid: None for tid, n in candidates.items() if match and n.attrs.get("type") == match}
        if key == "any_principal_in_scope":
            return dict.fromkeys(candidates)
        if key == "azure_resource_type":
            wanted = {_low(t) for t in as_list(value)}
            return {tid: None for tid, node in candidates.items()
                    if node.attrs.get("type") in wanted}
        if key == "azure_root_scope_only":
            return {tid: None for tid, node in candidates.items()
                    if value is True and node.kind == "azure_scope_owner" and node.scope == "/"}
        if key == "same_as_source":
            return {source.id: None} if source.id in candidates else {}
        if key == "managed_identity_type":
            out = {}
            for tid, n in candidates.items():
                mi_type = n.attrs.get("mi_type")
                if mi_type is None:
                    out[tid] = ("unknown", "managed_identity_type_unknown")
                elif mi_type == value:
                    out[tid] = None
            return out
        if key == "attached_to_service":
            wanted = [_low(v) for v in as_list(value)]
            out = {}
            for tid, n in candidates.items():
                hosts = [self.resources.get(h, {}).get("type", "") for h in n.attrs.get("hosts", [])]
                if any(any(h == w or h.startswith(w + "/") or w.startswith(h + "/") for w in wanted) for h in hosts):
                    out[tid] = None
                elif n.attrs.get("mi_type") == "system_assigned" and hosts:
                    continue
                elif any(not self._type_inventoried(w, n.scope) for w in wanted):
                    out[tid] = ("unknown", "resource_identity_inventory_not_collected")
            return out
        if key == "azure_site_kind":
            wanted = [_low(v) for v in as_list(value)]
            out = {}
            for tid, n in candidates.items():
                kinds = [self.resources.get(h, {}).get("kind", "") for h in n.attrs.get("hosts", [])
                         if self.resources.get(h, {}).get("type") == "microsoft.web/sites"]
                if any(w in k for k in kinds for w in wanted):
                    out[tid] = None
                elif not kinds and n.attrs.get("mi_type") != "system_assigned":
                    out[tid] = ("unknown", "site_kind_unknown")
            return out
        if key == "custom_role_assigned_to_source":
            scopes = [a["scope"] for pid in [source.id, *source.attrs.get("groups", [])] for a in self.assignments.get(pid, [])
                      if self.roles.get(a["role"]) is not None and self.roles[a["role"]].custom]
            return {tid: None for tid, n in candidates.items() if any(self.covers(s, n.scope)[0] for s in scopes)}
        if key == "entra_role_assignable":
            wanted = {_low(v) for v in as_list(value)}
            if wanted & {"any", "*"}:
                return dict.fromkeys(candidates)
            return {tid: None for tid, n in candidates.items() if _low(n.attrs.get("name")) in wanted or _low(n.attrs.get("template_id")) in wanted}
        if key == "entra_role_assignment_scope_covers_target":
            return dict.fromkeys(candidates)  # enforced by the requirement's directory scope check
        if key == "entra_reset_matrix_column":
            return self._reset_matrix(value, candidates)
        if key == "entra_target_not_in_restricted_au":
            units = inventory_status(self.snapshot, "directory_administrative_unit")
            if not units:
                return None
            restricted, incomplete = set(), bool(unavailable(units))
            for _, item in items(self.snapshot, "directory_administrative_unit"):
                if item.get("isMemberManagementRestricted") is True:
                    member_ids = item.get("memberIds")
                    if not isinstance(member_ids, list):
                        incomplete = True
                    else:
                        restricted.update(_low(ident) for ident in member_ids)
                elif item.get("isMemberManagementRestricted") is not False:
                    incomplete = True
            return {tid: (("unknown", "restricted_au_membership_not_collected") if incomplete else None)
                    for tid in candidates if _low(tid) not in restricted}
        if key == "entra_sp_type_in":
            wanted = set(as_list(value))
            return {tid: (None if n.attrs.get("sp_type") else ("unknown", "sp_type_unknown"))
                    for tid, n in candidates.items() if n.attrs.get("sp_type") in wanted or not n.attrs.get("sp_type")}
        if key == "entra_sp_credential_takeover_target":
            if value is not True or source is None or source.kind not in (
                    "azure_user", "azure_service_principal", "azure_managed_identity") or source.attrs.get("account_enabled") is False:
                return {}
            graph_grant = source.kind != "azure_user" and any(
                    (grant := self.check(source, {"graph_app_permission": permission}, ANY)) is not None
                    and grant.confidence == "derived"
                    for permission in ("Application.ReadWrite.All", "Directory.ReadWrite.All"))
            graph_status = inventory_status(self.snapshot, "directory_app_role_assignment")
            graph_unknown = source.kind != "azure_user" and not graph_grant and (
                not graph_status or unavailable(graph_status))
            if source.kind != "azure_user" and not graph_grant and not graph_unknown:
                return {}
            out = {}
            for tid, n in candidates.items():
                if n.kind != "azure_service_principal" or n.attrs.get("account_enabled") is False:
                    continue
                app = (self.app_ids or {}).get(_low(n.attrs.get("app_id")))
                lock = (app or {}).get("servicePrincipalLockConfiguration")
                if isinstance(lock, dict) and lock.get("isEnabled") is True and (
                        lock.get("allProperties") is True or lock.get("credentialsWithUsageVerify") is True):
                    continue
                reasons = []
                if source.attrs.get("account_enabled") is not True or n.attrs.get("account_enabled") is not True:
                    reasons.append("source_or_target_enabled_state_not_collected")
                if graph_unknown:
                    reasons.append("graph_application_permission_not_collected")
                if app is None:
                    reasons.append("home_application_lock_not_visible")
                elif "servicePrincipalLockConfiguration" not in app:
                    reasons.append("home_application_lock_not_collected")
                out[tid] = (("conditional", ",".join(reasons)) if reasons else None)
            return out
        if key == "entra_sp_owner_update_target":
            if value is not True or source is None or source.kind != "azure_user" or source.attrs.get("account_enabled") is False:
                return {}
            owner_status = {str(scope).casefold(): status for scope, status in
                            inventory_status(self.snapshot, "directory_owner").items()}
            owner_rows = {str(scope).casefold(): row for scope, row in items(self.snapshot, "directory_owner")
                          if isinstance(row, dict) and _low(row.get("objectType")) == "serviceprincipal"}
            out = {}
            for tid, n in candidates.items():
                if n.kind != "azure_service_principal" or n.attrs.get("account_enabled") is False:
                    continue
                scope = f"/tenants/{self.tenant}/servicePrincipals/{tid}".casefold()
                row = owner_rows.get(scope)
                if row is not None and _low(row.get("objectId")) == _low(tid) and (
                        _low(source.id) in {_low(owner) for owner in as_list(row.get("ownerIds"))}):
                    continue
                app = (self.app_ids or {}).get(_low(n.attrs.get("app_id")))
                lock = (app or {}).get("servicePrincipalLockConfiguration")
                if isinstance(lock, dict) and lock.get("isEnabled") is True and (
                        lock.get("allProperties") is True or lock.get("credentialsWithUsageVerify") is True):
                    continue
                reasons = []
                if source.attrs.get("account_enabled") is not True or n.attrs.get("account_enabled") is not True:
                    reasons.append("source_or_target_enabled_state_not_collected")
                if owner_status.get(scope) not in ("collected", "empty"):
                    reasons.append("service_principal_owner_listing_incomplete")
                if app is None:
                    reasons.append("home_application_lock_not_visible")
                elif "servicePrincipalLockConfiguration" not in app:
                    reasons.append("home_application_lock_not_collected")
                out[tid] = (("conditional", ",".join(reasons)) if reasons else None)
            return out
        if key == "entra_source_is_owner_of_service_principal":
            if value is not True or source is None or source.kind not in (
                    "azure_user", "azure_service_principal", "azure_managed_identity") or source.attrs.get("account_enabled") is False:
                return {}
            app_source = source.kind != "azure_user"
            graph_grant = app_source and any(
                (grant := self.check(source, {"graph_app_permission": permission}, ANY)) is not None
                and grant.confidence == "derived"
                for permission in ("Application.ReadWrite.OwnedBy", "Application.ReadWrite.All", "Directory.ReadWrite.All"))
            graph_status = inventory_status(self.snapshot, "directory_app_role_assignment")
            graph_unknown = app_source and not graph_grant and (not graph_status or unavailable(graph_status))
            if app_source and not graph_grant and not graph_unknown:
                return {}
            owner_status = {str(scope).casefold(): status for scope, status in
                            inventory_status(self.snapshot, "directory_owner").items()}
            owner_rows = {str(scope).casefold(): row for scope, row in items(self.snapshot, "directory_owner")
                          if isinstance(row, dict) and _low(row.get("objectType")) == "serviceprincipal"}
            out = {}
            for tid, n in candidates.items():
                if n.kind != "azure_service_principal" or n.attrs.get("account_enabled") is False:
                    continue
                scope = f"/tenants/{self.tenant}/servicePrincipals/{tid}".casefold()
                row = owner_rows.get(scope)
                status = owner_status.get(scope)
                if row is not None and _low(row.get("objectId")) == _low(tid):
                    if _low(source.id) not in {_low(owner) for owner in as_list(row.get("ownerIds"))}:
                        if status in ("collected", "empty"):
                            continue
                        out[tid] = ("unknown", "service_principal_owner_listing_incomplete")
                        continue
                elif status in ("collected", "empty"):
                    continue
                else:
                    out[tid] = ("unknown", "service_principal_owner_listing_not_collected")
                    continue
                app = (self.app_ids or {}).get(_low(n.attrs.get("app_id")))
                lock = (app or {}).get("servicePrincipalLockConfiguration")
                if isinstance(lock, dict) and lock.get("isEnabled") is True and (
                        lock.get("allProperties") is True or lock.get("credentialsWithUsageVerify") is True):
                    continue
                reasons = []
                if source.attrs.get("account_enabled") is not True or n.attrs.get("account_enabled") is not True:
                    reasons.append("source_or_target_enabled_state_not_collected")
                if graph_unknown:
                    reasons.append("graph_application_permission_not_collected")
                if app is None:
                    reasons.append("home_application_lock_not_visible")
                elif "servicePrincipalLockConfiguration" not in app:
                    reasons.append("home_application_lock_not_collected")
                out[tid] = (("conditional", ",".join(reasons)) if reasons else None)
            return out
        if key == "entra_sp_has_tenant_application":
            if self.app_ids is None:
                return None
            return {tid: (None if n.attrs.get("account_enabled") is True
                          else ("unknown", "service_principal_enabled_state_not_collected"))
                    for tid, n in candidates.items()
                    if _low(n.attrs.get("app_id")) in self.app_ids
                    and n.attrs.get("account_enabled") is not False}
        if key == "entra_app_sign_in_audience":
            if self.app_ids is None or not any("signInAudience" in a for a in self.app_ids.values()):
                return None
            wanted = set(as_list(value))
            return {tid: None for tid, n in candidates.items()
                    if (self.app_ids.get(_low(n.attrs.get("app_id"))) or {}).get("signInAudience") in wanted}
        if key == "entra_group_membership_type":
            out = {}
            for tid, n in candidates.items():
                types = n.attrs.get("group_types")
                if types is None:
                    out[tid] = ("unknown", "group_types_not_collected")
                elif ("DynamicMembership" in types) == (value == "dynamic"):
                    out[tid] = None
            return out
        if key == "entra_group_membership_cloud_writable":
            out = {}
            for tid, node in candidates.items():
                if not node.attrs.get("on_prem_sync_recorded"):
                    out[tid] = ("unknown", "group_source_of_authority_not_collected")
                elif node.attrs.get("on_prem_sync") is True:
                    continue
                else:
                    out[tid] = None
            return out
        if key == "entra_group_source_self_membership":
            if source is None:
                return None
            if source.kind not in ("azure_service_principal", "azure_managed_identity"):
                return dict.fromkeys(candidates)
            app_rights = ("Application.ReadWrite.All", "Directory.ReadWrite.All")
            group_rights = ("GroupMember.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All")
            def has_derived(rights):
                return any((grant := self.check(source, {"graph_app_permission": permission}, ANY)) is not None
                           and grant.confidence == "derived" for permission in rights)
            if has_derived(app_rights) and has_derived(group_rights):
                return dict.fromkeys(candidates)
            return {tid: ("conditional", "service_principal_self_membership_permissions_unverified")
                    for tid in candidates}
        if key == "entra_group_source_not_owner":
            if source is None:
                return None
            owner_status = {str(scope).casefold(): status for scope, status in
                            inventory_status(self.snapshot, "directory_owner").items()}
            known_owners = {}
            for _, item in items(self.snapshot, "directory_owner"):
                if _low(item.get("objectType")) == "group" and item.get("objectId"):
                    known_owners.setdefault(_low(item["objectId"]), set()).update(
                        _low(oid) for oid in as_list(item.get("ownerIds")))
            out = {}
            for tid in candidates:
                if _low(source.id) in known_owners.get(_low(tid), set()):
                    continue
                scope = f"/tenants/{self.tenant}/groups/{tid}".casefold()
                if owner_status.get(scope) not in ("collected", "empty"):
                    out[tid] = ("conditional", "group_owner_inventory_incomplete")
                elif source.kind in ("azure_service_principal", "azure_managed_identity"):
                    out[tid] = ("conditional", "service_principal_owner_listing_incomplete")
                else:
                    out[tid] = None
            return out
        if key in ("entra_group_new_self_membership", "entra_group_owner_new_self_membership"):
            if source is None:
                return None
            if source.kind not in ("azure_user", "azure_service_principal", "azure_managed_identity"):
                return {}
            if source.attrs.get("account_enabled") is False:
                return {}
            app_source = source.kind in ("azure_service_principal", "azure_managed_identity")
            if app_source:
                app_rights = ("Application.ReadWrite.All", "Directory.ReadWrite.All")
                group_rights = ("GroupMember.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All")
                def has_derived(rights):
                    return any((grant := self.check(source, {"graph_app_permission": permission}, ANY)) is not None
                               and grant.confidence == "derived" for permission in rights)
                if not (has_derived(app_rights) and has_derived(group_rights)):
                    return {}
            membership = inventory_status(self.snapshot, "directory_membership")
            statuses = {str(scope).casefold(): status for scope, status in membership.items()}
            incomplete = bool(unavailable(membership))
            current_groups = {str(g).casefold() for g in self._groups(source.id)}
            out = {}
            for tid, group in candidates.items():
                types = group.attrs.get("group_types")
                mail = group.attrs.get("mail_enabled")
                security = group.attrs.get("security_enabled")
                if not isinstance(types, list) or mail is None or security is None:
                    out[tid] = ("unknown", "group_type_not_collected")
                    continue
                unified = "Unified" in types
                if not unified and (security is not True or mail is not False):
                    continue
                if app_source and unified:
                    continue  # Microsoft 365 groups cannot contain service principals.
                if key == "entra_group_owner_new_self_membership":
                    role_assignable = group.attrs.get("assignable_to_role")
                    if app_source and role_assignable is True:
                        role_write = self.check(source, {"graph_app_permission": "RoleManagement.ReadWrite.Directory"}, ANY)
                        if role_write is None or role_write.confidence != "derived":
                            continue
                if tid.casefold() in current_groups:
                    continue
                scope = f"/tenants/{self.tenant}/groups/{tid}".casefold()
                if not membership or incomplete or statuses.get(scope) not in ("collected", "empty"):
                    out[tid] = ("conditional", "group_membership_inventory_incomplete")
                elif source.attrs.get("account_enabled") is not True:
                    out[tid] = ("conditional", "source_enabled_state_not_collected")
                elif (key == "entra_group_owner_new_self_membership"
                      and group.attrs.get("assignable_to_role") is not False):
                    out[tid] = ("conditional", "role_assignable_group_owner_membership")
                else:
                    out[tid] = None
            return out
        if key == "entra_group_role_assignable":
            out = {}
            for tid, n in candidates.items():
                flag = n.attrs.get("assignable_to_role")
                if flag is None:
                    out[tid] = ("unknown", "isAssignableToRole_not_collected")
                elif bool(flag) == bool(value):
                    out[tid] = None
            return out
        if key == "entra_group_type_covered_by_permission":
            return dict.fromkeys(candidates)  # enforced in the entra_permission check (groups.security / groups.unified)
        if key in ("entra_dynamic_rule_attributes_writable_by_source", "entra_dynamic_rule_satisfiable_by_invited_guest"):
            if not any(n.attrs.get("membership_rule") for n in candidates.values()):
                return None
            return {tid: ("conditional", "membership_rule_semantics_approximated") for tid, n in candidates.items() if n.attrs.get("membership_rule")}
        return self._selector_ext(key, value, candidates, source, pivot)

    # ------------------------------------------------------- selector extensions
    def _pivot_scopes(self, pivot):
        scopes = [p.get("pivot") for p in (pivot or []) if isinstance(p, dict) and p.get("pivot")]
        return [_low(s) for s in scopes] or ["/"]

    def _resources_under(self, rtype, scopes):
        return [rid for rid, r in self.resources.items() if r["type"] == rtype and any(self.covers(s, rid)[0] for s in scopes)]

    def _selector_ext(self, key, value, candidates, source, pivot):
        if key == "azure_ml_online_endpoint_create_uami_path":
            from .azure_ml_online_endpoint_create_uami import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_ml_existing_online_deployment_identity_path":
            from .azure_ml_online_deployment_existing import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_ml_compute_create_uami_path":
            from .azure_ml_compute_create_uami import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_ml_compute_application_identity_path":
            from .azure_ml_compute_application import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_uami_fic_write_path":
            from .azure_uami_fic_write import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_managedapp_listtokens_path":
            from .azure_managedapp_listtokens import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_logicapp_existing_identity_path":
            from .azure_logicapp_assign_uami import select_existing
            return select_existing(self, candidates, source) if value is True else {}
        if key == "azure_logicapp_assign_uami_path":
            from .azure_logicapp_assign_uami import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_deployment_script_uami_path":
            from .azure_deployment_script import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_arc_run_command_code_path":
            from .azure_arc_runcommand import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_arc_custom_script_code_path":
            from .azure_arc_extension import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_arc_entra_admin_ssh_path":
            from .azure_arc_ssh import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_sourcecontrol_code_path":
            from .azure_appservice_sourcecontrol import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_slot_swap_code_path":
            from .azure_appservice_slot_swap import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_slot_publishing_credentials_code_path":
            from .azure_appservice_slot_publishing_credentials import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_slot_code_path":
            from .azure_appservice_slot_code import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_siteextensions_code_path":
            from .azure_appservice_siteextensions import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_sitecontainers_code_path":
            from .azure_appservice_sitecontainers import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_backup_restore_code_path":
            from .azure_appservice_restore import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_enable_publishing_credentials_code_path":
            from .azure_appservice_publishing_credentials import select
            return select(self, candidates, source, enable=True) if value is True else {}
        if key == "azure_appservice_publishing_credentials_code_path":
            from .azure_appservice_publishing_credentials import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_onedeploy_code_path":
            from .azure_appservice_onedeploy import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_kudu_code_path":
            from .azure_appservice_kudu import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_appservice_config_code_path":
            from .azure_appservice_config import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_function_definition_code_path":
            from .azure_function_definition import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_function_host_vfs_code_path":
            from .azure_function_definition import select
            return select(self, candidates, source, vfs=True) if value is True else {}
        if key == "azure_function_remote_debug_path":
            from .azure_function_remote_debug import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_arc_guest_configuration_path":
            from .azure_arc_guest_configuration import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_hybrid_k8s_admin_credential_path":
            from .azure_hybrid_k8s_admin_credential import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_imagebuilder_new_template_identity_path":
            from .azure_imagebuilder_new_template import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_kusto_cluster_principal_assignment_path":
            from .azure_kusto_cluster_principal_assignment import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_kusto_database_principal_assignment_path":
            from .azure_kusto_cluster_principal_assignment import select
            return select(self, candidates, source, database=True) if value is True else {}
        if key == "azure_loadtesting_assign_uami_path":
            from .azure_loadtesting_assign_uami import select
            return select(self, candidates, source) if value is True else {}
        if key == "azure_loadtesting_existing_engine_identity_path":
            from .azure_loadtesting_assign_uami import select_existing
            return select_existing(self, candidates, source) if value is True else {}
        if key == "azure_appservice_assignable_uami":
            if value is not True or source is None:
                return {}
            if pivot is None:
                statuses = [inventory_status(self.snapshot, kind)
                            for kind in ("app_service", "resource_group", "app_service_plan")]
                if not self.exact_scopes or any(status.get(scope) not in ("collected", "empty")
                                                for status in statuses for scope in self.exact_scopes):
                    return {tid: ("unknown", "app_service_or_plan_inventory_incomplete") for tid in candidates}
                return {}
            sites = []
            for entry in as_list(pivot):
                if not isinstance(entry, dict) or not isinstance(entry.get("pivot"), str):
                    continue
                site = entry["pivot"]
                resource = self.resources.get(site, {})
                creating = entry.get("created") is True
                if not creating and resource.get("type") != "microsoft.web/sites":
                    continue
                if creating:
                    plan_id = entry.get("plan")
                    known_plans = {rid for rid, resource in self.resources.items()
                                   if resource["type"] == "microsoft.web/serverfarms"}
                    known_plans |= {_low(plan.get("id")) for _, plan in items(self.snapshot, "app_service_plan")
                                    if isinstance(plan, dict) and _low(plan.get("type")) == "microsoft.web/serverfarms"}
                    if (not isinstance(plan_id, str) or plan_id not in known_plans
                            or _subscription(plan_id) != _subscription(site)
                            or not re.fullmatch(
                                r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/peaso-privesc-probe",
                                site)
                            or self.cached_check(source, {"action": "microsoft.web/serverfarms/join/action"}, plan_id) is None):
                        continue
                kind = resource.get("kind") or ""
                routes = [
                    ("microsoft.web/sites/publish/action", site),
                    ("microsoft.web/sites/config/write", site + "/config/web"),
                    ("microsoft.web/sites/sourcecontrols/write", site + "/sourcecontrols/web"),
                    ("microsoft.web/sites/extensions/write", site + "/extensions/onedeploy"),
                ]
                if "linux" in kind:
                    routes.append(("microsoft.web/sites/sitecontainers/write",
                                   site + "/sitecontainers/peaso-privesc-probe"))
                if "linux" not in kind:
                    routes.append(("microsoft.web/sites/siteextensions/write",
                                   site + "/siteextensions/peaso-privesc-probe"))
                if "functionapp" in kind:
                    routes.append(("microsoft.web/sites/functions/write",
                                   site + "/functions/peaso-privesc-probe"))
                # An exact child-scoped assignment can authorize updating an
                # existing function or container without authorizing creation.
                for pid in [source.id, *source.attrs.get("groups", ())]:
                    for assignment in self.assignments.get(pid, ()):
                        child = assignment["scope"]
                        if not child.startswith(site + "/") or child.count("/") != site.count("/") + 2:
                            continue
                        suffix = child[len(site) + 1:]
                        if suffix.startswith("sitecontainers/") and "linux" in kind:
                            routes.append(("microsoft.web/sites/sitecontainers/write", child))
                        elif suffix.startswith("functions/") and "functionapp" in kind:
                            routes.append(("microsoft.web/sites/functions/write", child))
                        elif suffix.startswith("siteextensions/") and "linux" not in kind:
                            routes.append(("microsoft.web/sites/siteextensions/write", child))
                if any((grant := self.cached_check(source, {"action": action}, ref)) is not None
                       and grant.confidence != "unknown" for action, ref in routes):
                    sites.append(site)
            if not sites:
                return {}
            out = {}
            for tid, target in candidates.items():
                resource = target.attrs.get("uai_resource")
                if (target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned"
                        or target.attrs.get("uai_resource_verified") is not True
                        or not isinstance(resource, str)
                        or not re.fullmatch(
                            r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+",
                            _low(resource))):
                    continue
                grant = self.cached_check(source, {"action": ASSIGN_UAMI}, _low(resource))
                if grant is not None and grant.confidence != "unknown":
                    out[tid] = ("conditional", "app_code_execution_and_identity_token_use")
            return out
        if key == "azure_host_linked_to_pivot":
            return self._host_linked(value, candidates, self._pivot_scopes(pivot))
        if key == "azure_consumer_of_pivot":
            return self._consumers(value, candidates, self._pivot_scopes(pivot))
        if key == "azure_assignable_via_identity_holding":
            return self._via_identity(_low(value), candidates, source)
        if key == "azure_users_assigned_to_pivot":
            return self._avd_users(candidates, self._pivot_scopes(pivot))
        if key == "attached_to_vm_joined_to_entra_domain_services":
            return self._ds_joined(candidates)
        if key == "azure_assignment_condition_uses_principal_attribute":
            return self._csa_conditioned(candidates, source)
        if key == "fabric_workspace_identity":
            workspaces = self._fabric_identities()
            return None if workspaces is None else {tid: None for tid in candidates if tid in workspaces}
        if key == "entra_resource_in_catalog":
            index = self._catalog_index()
            if index is None:
                return None
            return {tid: None for tid, n in candidates.items() if any(i in index for i in self._target_object_ids(n))}
        if key == "entra_pim_group_eligible_for_source":
            from .azure_pim_group_activation import select
            return select(self, candidates, source) if value is True else {}
        if key == "entra_access_package_auto_assignment_open_to_guest":
            return self._auto_assignment(candidates)
        if key == "intune_managed_device_user":
            if not inventory_status(self.snapshot, "intune_managed_device"):
                return None
            users = {item.get("userId") for _, item in items(self.snapshot, "intune_managed_device")}
            out = {tid: ("conditional", "device_session_not_verified") for tid in candidates if tid in users}
            if unavailable(inventory_status(self.snapshot, "intune_managed_device")):
                out.update({tid: ("unknown", "managed_device_inventory_incomplete") for tid in candidates if tid not in out})
            return out
        return None

    def _host_linked(self, value, candidates, scopes):
        """VM identities linked to the pivot (session hosts, hybrid workers, DevTest lab compute VMs)."""
        spec = HOST_LINKS.get(value)
        if spec is None:
            return {tid: ("unknown", f"{value}_link_not_collected") for tid in candidates}
        parent_type, collection, link_type, field = spec
        complete_parents = True
        if value == "avd_session_host":
            groups = self._resources_under(AVD_APP_GROUP, scopes)
            parents = set()
            for gid in groups:
                path = (self.resources[gid].get("props") or {}).get("hostPoolArmPath")
                if path:
                    parents.add(_low(path))
                else:
                    complete_parents = False
            complete_parents = complete_parents and all(self._type_inventoried(AVD_APP_GROUP, s) for s in scopes)
        else:
            parents = set(self._resources_under(parent_type, scopes))
            complete_parents = all(self._type_inventoried(parent_type, s) for s in scopes)
        status = {_low(sc): st for sc, st in inventory_status(self.snapshot, collection).items()}
        linked, complete = set(), complete_parents
        for kind in (collection, "resource_graph"):
            for scope, item in items(self.snapshot, kind):
                rid = _low(item.get("id"))
                if (_low(item.get("type")) != link_type and kind == "resource_graph") or not rid:
                    continue
                if any(rid.startswith(p + "/") for p in parents):
                    vm = ((item.get("properties") or {}).get(field)) if isinstance(item.get("properties"), dict) else None
                    if vm:
                        linked.add(_low(vm))
                    else:
                        complete = False
        for parent in parents:
            if status.get(parent) not in ("collected", "empty"):
                complete = False
        out = {}
        for tid, n in candidates.items():
            if set(n.attrs.get("hosts") or ()) & linked:
                out[tid] = None
            elif not complete:
                out[tid] = ("unknown", f"{value}_link_not_collected")
        return out

    def _consumers(self, value, candidates, scopes):
        out = {}
        for binding in as_list(value):
            rtype, action = CONSUMER_READS.get(binding, (None, None))
            refs = (self._resources_under(rtype, scopes) or scopes) if rtype else []
            for tid, n in candidates.items():
                if out.get(tid) and out[tid][0] == "conditional":
                    continue
                read = action and any(self.cached_check(n, {"action": action, "data_action": True}, r) for r in refs)
                out[tid] = ("conditional", "consumer_binding_not_collected") if read else \
                    out.get(tid) or ("unknown", "workload_binding_not_collected")
        return out

    def _via_identity(self, action, candidates, source):
        if source is None:
            return None
        hops = [n for n in self.principals.values() if n.kind == "azure_managed_identity" and n.attrs.get("uai_resource")]
        out = {}
        for hop in hops:
            first = self.cached_check(source, {"action": ASSIGN_UAMI}, hop.attrs["uai_resource"])
            if first is None:
                continue
            for tid, n in candidates.items():
                if tid == hop.id or not n.attrs.get("uai_resource"):
                    continue
                second = self.cached_check(hop, {"action": action}, n.attrs["uai_resource"])
                if second is None:
                    continue
                conf = max(first.confidence, second.confidence, key=("derived", "conditional", "unknown").index)
                if tid not in out or ("derived", "conditional", "unknown").index(conf) < \
                        ("derived", "conditional", "unknown").index(out[tid][0]):
                    out[tid] = (conf, f"via_intermediate_identity:{hop.label}")
        return out

    def _avd_users(self, candidates, scopes):
        groups = self._resources_under(AVD_APP_GROUP, scopes)
        if not groups and all(self._type_inventoried(AVD_APP_GROUP, s) for s in scopes):
            return {}  # no application group within the pivot

        def serves(scope):
            if groups:
                return any(self.covers(scope, g)[0] for g in groups)
            # Application groups not inventoried: an assignment inside or above the pivot may be on one.
            return any(self.covers(scope, s)[0] or self.covers(s, scope)[0] for s in scopes)

        out = {}
        for tid, n in candidates.items():
            for pid in [n.id, *n.attrs.get("groups", [])]:
                for a in self.assignments.get(pid, []):
                    definition = self.roles.get(a["role"])
                    if a["role"] != AVD_USER_ROLE and _low(definition.name if definition else "") != "desktop virtualization user":
                        continue
                    if serves(a["scope"]):
                        out[tid] = ("conditional", "user_launches_app" if groups else "application_group_not_inventoried")
        return out

    def _ds_joined(self, candidates):
        domains = {_low((r.get("props") or {}).get("domainName")) for r in self.resources.values() if r["type"] == ENTRA_DS} - {""}
        vm_type = "microsoft.compute/virtualmachines"
        no_domain = not domains and bool(self.all_subscriptions) and all(self._type_inventoried(ENTRA_DS, s) for s in self.all_subscriptions)
        out = {}
        for tid, n in candidates.items():
            vms = [self.resources[h] for h in n.attrs.get("hosts") or () if self.resources.get(h, {}).get("type") == vm_type]
            if any(vm.get("join_domains", set()) & domains for vm in vms):
                out[tid] = ("conditional", "domain_join_state_not_verified")
            elif no_domain:
                continue
            elif vms or not self._type_inventoried(vm_type, n.scope):
                out[tid] = ("unknown", "entra_domain_services_join_not_collected")
        return out

    def _csa_conditioned(self, candidates, source):
        if source is None:
            return None
        conditioned = [a for pid in [source.id, *source.attrs.get("groups", [])] for a in self.assignments.get(pid, [])
                       if a["condition"] and _PRINCIPAL_CSA.search(a["condition"]) and self.roles.get(a["role"]) is not None]
        out = {}
        for tid, n in candidates.items():
            scope = n.attrs.get("scope") or n.scope
            for a in conditioned:
                definition = self.roles[a["role"]]
                if n.kind == "azure_scope_owner":
                    ok = a["scope"] == _low(scope) and definition.allows("microsoft.authorization/roleassignments/write")
                else:
                    ok = bool(definition.data) and self.covers(a["scope"], scope)[0]
                if ok:
                    out[tid] = ("conditional", "attribute_value_satisfying_condition_not_verified")
                    break
        return out

    def _auto_assignment(self, candidates):
        if not inventory_status(self.snapshot, "entitlement_assignment_policy") or \
                not inventory_status(self.snapshot, "entitlement_access_package_resource"):
            return None
        packages = set()
        for _, item in items(self.snapshot, "entitlement_assignment_policy"):
            auto = (item.get("automaticRequestSettings") or {}) if isinstance(item.get("automaticRequestSettings"), dict) else {}
            if not auto.get("requestAccessForAllowedTargets"):
                continue
            if _low(item.get("allowedTargetScope")) in ("allmemberusers", "alldirectoryserviceprincipals", "notspecified"):
                continue
            rules = " ".join(str((t or {}).get("membershipRule") or "") for t in as_list(item.get("specificAllowedTargets"))
                             if isinstance(t, dict))
            if re.search(r'user\.usertype\s+-eq\s+"?member"?', rules, re.I):
                continue
            packages.add(item.get("accessPackageId"))
        origins = {_low(item.get("originId")) for _, item in items(self.snapshot, "entitlement_access_package_resource")
                   if item.get("accessPackageId") in packages}
        return {tid: ("conditional", "auto_assignment_rule_semantics_approximated") for tid, n in candidates.items()
                if self._target_object_ids(n) & origins}

    def _reset_matrix(self, column, candidates):
        if not inventory_status(self.snapshot, "directory_role_assignment"):
            return {tid: ("unknown", "target_directory_roles_not_collected") for tid in candidates}
        allowed = RESET_MATRIX.get(column, set())
        out = {}
        for tid, n in candidates.items():
            roles = set()
            role_definition_missing = False
            via_group = False
            for pid in [n.id, *n.attrs.get("groups", [])]:
                for role, scope, aid in self.dir_assignments.get(pid, []):
                    info = self.dir_roles.get(role)
                    if info:
                        roles.add(_low(info["name"]))
                    else:
                        role_definition_missing = True
                    via_group = via_group or pid != n.id
            if allowed is not None and not roles <= allowed:
                continue
            if via_group and column != "privileged_auth_admin":
                continue  # members of role-assignable groups are protected
            groups = [self.principals.get(g) for g in n.attrs.get("groups", [])]
            if allowed is not None and role_definition_missing:
                out[tid] = ("conditional", "target_directory_role_definition_not_collected")
            elif column != "privileged_auth_admin" and any(g is not None and g.attrs.get("assignable_to_role") is None for g in groups):
                out[tid] = ("conditional", "role_assignable_group_membership_unknown")
            else:
                out[tid] = None
        return out

    def admin_targets(self, principal):
        out = []
        found = {}
        for pid in [principal.id, *principal.attrs.get("groups", [])]:
            for a in self.assignments.get(pid, []):
                definition = self.roles.get(a["role"])
                if definition is None or not definition.allows("microsoft.authorization/roleassignments/write"):
                    continue
                grant = self._rbac(principal, "microsoft.authorization/roleassignments/write", False, a["scope"])
                if grant is not None:
                    found[a["scope"]] = Grant(grant.confidence, grant.refs, grant.conditions,
                        [{"permission": "microsoft.authorization/roleassignments/write", "grant": ref} for ref in grant.refs if "assignment" in ref])
        for scope, grant in sorted(found.items()):
            if any(other != scope and self.covers(other, scope)[0] for other in found):
                continue
            out.append((self.entity("azure_scope_owner", scope), grant))
        for pid in [principal.id, *principal.attrs.get("groups", [])]:
            for role, scope, aid in self.dir_assignments.get(pid, []):
                info = self.dir_roles.get(role)
                template = info["id"] if info else role
                if (template == GLOBAL_ADMIN or (info and info["name"] == "Global Administrator")) and (scope or "/") == "/":
                    ref = {"directory_role_assignment": aid, "role": "Global Administrator", "directory_scope": scope or "/", "via": pid, "role_template_id": template}
                    grant = Grant("derived", [ref], ["via_role_assignable_group"] if pid != principal.id else [],
                                  [{"permission": "Entra directory role: Global Administrator", "grant": ref}])
                    out.append((self.entity("entra_role", GLOBAL_ADMIN if not info else info["id"], {"name": "Global Administrator"}), grant))
        return out

    def scope_within(self, inner, outer):
        return self.covers(outer, inner)[0] if inner.startswith("/") else inner == outer


# Tenants owning Microsoft first-party applications (Microsoft Services, Microsoft corp).
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}


def _subscription(rid):
    match = re.match(r"(/subscriptions/[^/]+)", _low(rid))
    return match.group(1) if match else None


def _resource_group(rid):
    match = re.match(r"(/subscriptions/[^/]+/resourcegroups/[^/]+)", _low(rid))
    return match.group(1) if match else None


def _join_domains(extensions):
    """AD domains named by JsonADDomainExtension public settings (settings.Name) of a VM's extensions."""
    out = set()
    for ext in as_list(extensions):
        props = (ext or {}).get("properties") if isinstance(ext, dict) else None
        if not isinstance(props, dict) or _low(props.get("type")) != "jsonaddomainextension":
            continue
        settings = props.get("settings")
        if isinstance(settings, dict) and settings.get("Name"):
            out.add(_low(settings["Name"]))
    return out
