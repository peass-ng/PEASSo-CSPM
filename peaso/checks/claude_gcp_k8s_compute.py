"""claude_gcp_k8s: Compute Engine, VPC firewall, load balancing and Cloud DNS predicates.

Every predicate evaluates declared configuration only (no reachability or effective-access claim).
Missing, denied or malformed facts are UNKNOWN; joins require complete scoped inventories.
"""
from __future__ import annotations
import re

from .claude_gcp_k8s_common import (gcp, gid, cases, strings, opt_strings, scope_index, context_scope, captured_at,
    parse_time, bindings, root_policy, active_ingress, is_public, source_ranges, exposed_ports, allowed_entries, fw,
    PUBLIC_MEMBERS, SCOPE, policy_case, result, unknown, get, optional, list_of_objects, complete_items, Unavailable, CASES)

COMPUTE_IDS = []
FW_REMEDIATION = ("Restrict the firewall rule source ranges to approved networks (or use IAP/Private Service Connect), "
                  "narrow the allowed protocols and ports, and remove unused rules.")


def track(cid):
    COMPUTE_IDS.append(cid)
    return cid


# --- VPC firewall rules -----------------------------------------------------------------------------------

FIREWALL_PORTS = {
    "dns_port_53": ([53], ("tcp", "udp")), "ftp_port_21": ([21], ("tcp", "udp")), "http_port_80": ([80], ("tcp", "udp")),
    "smtp_port_25": ([25], ("tcp", "udp")), "microsoft_ds_port_445": ([445], ("tcp", "udp")),
    "mongo_db_port_27017": ([27017], ("tcp", "udp")), "mysql_db_port_3306": ([3306], ("tcp", "udp")),
    "netbios_snn_port_139": ([139], ("tcp", "udp")), "oracle_db_port_1521": ([1521], ("tcp", "udp")),
    "pop3_port_110": ([110], ("tcp", "udp")), "postgresql_port_5432": ([5432], ("tcp", "udp")),
    "telnet_port_23": ([23], ("tcp", "udp")), "kubelet_port_10250": ([10250], ("tcp", "udp")),
    "kubelet_read_only_port_10255": ([10255], ("tcp", "udp")), "tcp_port_9090": ([9090], ("tcp",)),
    "tcp_port_9200_9300": ([9200, 9300], ("tcp",)), "tcp_port_7000_7001": ([7000, 7001], ("tcp",)),
    "tcp_port_7199": ([7199], ("tcp",)), "tcp_port_8888": ([8888], ("tcp",)), "tcp_port_9042": ([9042], ("tcp",)),
    "tcp_port_9160": ([9160], ("tcp",)), "tcp_port_61620_61621": ([61620, 61621], ("tcp",)),
    "tcp_port_6379": ([6379], ("tcp",)), "tcp_port_137_to_139": ([137, 138, 139], ("tcp",)),
    "tcp_port_27017_to_27019": ([27017, 27018, 27019], ("tcp",)), "tcp_port_636": ([636], ("tcp",)),
    "tcp_udp_port_389": ([389], ("tcp", "udp")), "tcp_udp_port_11211": ([11211], ("tcp", "udp")),
    "tcp_udp_port_11214_to_11215": ([11214, 11215], ("tcp", "udp")), "tcp_udp_port_2483_to_2484": ([2483, 2484], ("tcp", "udp")),
}
FIREWALL_PORT_IDS = {}


def firewall_port(suffix, ports, protocols):
    slug = "firewall.public_ingress_" + suffix
    label = "/".join(protocols).upper() + " " + ",".join(str(p) for p in ports)

    @gcp(slug, "firewall", "Firewall rule does not allow internet ingress to " + label, severity="high", control="SC-7",
         category="network", remediation=FW_REMEDIATION)
    def evaluate(item, index):
        skip = active_ingress(item)
        if skip:
            return skip
        hits = exposed_ports(item, protocols, ports)
        return result(is_public(item) and bool(hits), ports=ports, protocols=list(protocols), source_ranges=source_ranges(item),
                      matching_allow_entries=hits,
                      semantics="Declared per-rule ingress; priorities, deny rules, targets and hierarchical policies are not evaluated")
    cid = track(gid(slug))
    port = str(ports[0])
    cases(cid, fw(["10.0.0.0/8"], [{"IPProtocol": protocols[0], "ports": [port]}]),
          fw(["0.0.0.0/0"], [{"IPProtocol": protocols[-1], "ports": [str(ports[0] - 1) + "-" + str(ports[-1])]}]),
          not_applicable=fw(["0.0.0.0/0"], [{"IPProtocol": "all"}], disabled=True),
          malformed=fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["abc"]}]))
    FIREWALL_PORT_IDS[suffix] = cid
    return cid


for _suffix, (_ports, _protocols) in FIREWALL_PORTS.items():
    firewall_port(_suffix, _ports, _protocols)

# Ports 10250/10255 are the kubelet API and read-only ports. The earlier ids copied the upstream query names
# (..._postgresql_port_1025x); they stay resolvable for stored scans, diffs and saved check selections.
from . import alias_check
alias_check(gid("firewall.public_ingress_postgresql_port_10250"), FIREWALL_PORT_IDS["kubelet_port_10250"])
alias_check(gid("firewall.public_ingress_postgresql_port_10255"), FIREWALL_PORT_IDS["kubelet_read_only_port_10255"])


@gcp("firewall.public_ingress_all_protocols", "firewall", "Firewall rule does not allow internet ingress over all protocols",
     severity="high", control="SC-7", category="network", remediation=FW_REMEDIATION)
def firewall_all_protocols(item, index):
    skip = active_ingress(item)
    if skip:
        return skip
    entries = allowed_entries(item)
    return result(is_public(item) and any(protocol == "all" for protocol, _ in entries), source_ranges=source_ranges(item),
                  protocols=[protocol for protocol, _ in entries], semantics="Declared per-rule ingress with IPProtocol all")


cases(track(gid("firewall.public_ingress_all_protocols")), fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["443"]}]),
      fw(["::/0"], [{"IPProtocol": "all"}]), not_applicable=fw(["0.0.0.0/0"], [{"IPProtocol": "all"}], direction="EGRESS"),
      malformed=fw(["0.0.0.0/0"], [{"ports": ["1"]}]))


@gcp("firewall.public_ingress_without_target", "firewall", "Internet ingress firewall rule is scoped to target tags or service accounts",
     severity="high", control="SC-7", category="network", remediation=FW_REMEDIATION)
def firewall_without_target(item, index):
    skip = active_ingress(item)
    if skip:
        return skip
    tags, accounts = opt_strings(item, "targetTags"), opt_strings(item, "targetServiceAccounts")
    entries = allowed_entries(item)
    return result(is_public(item) and bool(entries) and not tags and not accounts, source_ranges=source_ranges(item),
                  target_tags=tags, target_service_accounts=accounts,
                  semantics="An internet allow rule without targets applies to every instance in the network")


cases(track(gid("firewall.public_ingress_without_target")),
      fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["443"]}], targetTags=["web"]),
      fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["443"]}]),
      not_applicable=fw(["0.0.0.0/0"], [{"IPProtocol": "tcp"}], disabled=True),
      malformed=fw(["0.0.0.0/0"], [{"IPProtocol": "tcp"}], targetTags="web"))


@gcp("firewall.logging_enabled", "firewall", "Firewall rule logging is enabled", control="AU-12",
     remediation="Enable firewall rule logging (logConfig.enable) for rules that need connection audit records.")
def firewall_logging(item, index):
    enabled = get(item, "logConfig.enable", bool)
    return result(not enabled, log_config_enable=enabled)


cases(track(gid("firewall.logging_enabled")), {"logConfig": {"enable": True}}, {"logConfig": {"enable": False}},
      malformed={"logConfig": {"enable": "yes"}})

DEFAULT_OPEN_RULES = ("default-allow-ssh", "default-allow-icmp", "default-allow-internal", "default-allow-rdp")


def default_rule_network(item, index):
    """Bind a default-named rule to this project's actual default VPC."""
    network = get(item, "network", str)
    for prefix in ("https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"):
        if network.startswith(prefix):
            network = network[len(prefix):]
            break
    match = re.fullmatch(r"projects/([^/]+)/global/networks/([^/]+)", network)
    if match is None:
        raise Unavailable("firewall network reference malformed")
    if match[1] != context_scope(index).removeprefix("projects/"):
        raise Unavailable("firewall network belongs to another project")
    return match[2] == "default"


@gcp("firewall.default_rules_not_open", "firewall", "Default-network firewall rules do not allow internet ingress",
     severity="high", control="SC-7", category="network", remediation=FW_REMEDIATION)
def firewall_default_rules(item, index):
    name = get(item, "name", str)
    if not name.startswith("default-"):
        return "NOT_APPLICABLE", {"reason": "Not an auto-created default-network firewall rule", "name": name}
    skip = active_ingress(item)
    if skip:
        return skip
    if not default_rule_network(item, index):
        return "NOT_APPLICABLE", {"reason": "Rule is outside this project's default network", "name": name}
    ranges = set(source_ranges(item))
    entries = allowed_entries(item)
    return result(name in DEFAULT_OPEN_RULES and bool(entries) and bool(ranges & {"0.0.0.0/0", "::/0"}), name=name, source_ranges=sorted(ranges),
                  semantics="default-allow-http/https are the documented exceptions")


cases(track(gid("firewall.default_rules_not_open")),
      fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["80"]}], name="default-allow-http", network="projects/p/global/networks/default"),
      fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["22"]}], name="default-allow-ssh", network="projects/p/global/networks/default"),
      not_applicable=fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["22"]}], name="corp-ssh"),
      malformed=fw(["0.0.0.0/0"], [{"IPProtocol": "tcp"}], name=7))

COMMON_PORTS = [20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3306, 3389, 5432, 5500, 5601, 8080, 9200, 9300, 27017]
TRANSPORT = ("tcp", "udp", "sctp")


@gcp("firewall.public_ingress_common_ports", "firewall", "Firewall rule does not allow internet ingress to common administrative or database ports",
     severity="high", control="SC-7", category="network", remediation=FW_REMEDIATION)
def firewall_common_ports(item, index):
    skip = active_ingress(item)
    if skip:
        return skip
    ranges = set(source_ranges(item))
    hits = exposed_ports(item, TRANSPORT, COMMON_PORTS)
    return result(bool(ranges & {"0.0.0.0/0", "::/0"}) and bool(hits), ports=COMMON_PORTS, matching_allow_entries=hits,
                  semantics="Corrected: protocol all or a transport protocol without ports opens every listed port")


cases(track(gid("firewall.public_ingress_common_ports")), fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["443"]}]),
      fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["3000-3400"]}]),
      not_applicable=fw(["0.0.0.0/0"], [{"IPProtocol": "all"}], direction="EGRESS"),
      malformed=fw(["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["70000"]}]))


@gcp("firewall.public_ingress_tcp_udp", "firewall", "Firewall rule does not allow internet ingress over TCP or UDP",
     severity="high", control="SC-7", category="network", remediation=FW_REMEDIATION)
def firewall_tcp_udp(item, index):
    skip = active_ingress(item)
    if skip:
        return skip
    ranges = set(source_ranges(item))
    protocols = [protocol for protocol, _ in allowed_entries(item)]
    return result(bool(ranges & {"0.0.0.0/0", "::/0"}) and any(p in ("tcp", "udp", "all") for p in protocols),
                  protocols=protocols, source_ranges=sorted(ranges))


cases(track(gid("firewall.public_ingress_tcp_udp")), fw(["0.0.0.0/0"], [{"IPProtocol": "icmp"}]),
      fw(["::/0"], [{"IPProtocol": "udp", "ports": ["53"]}]),
      not_applicable=fw(["0.0.0.0/0"], [{"IPProtocol": "udp"}], disabled=True), malformed=fw(["0.0.0.0/0"], [7]))


# --- Instance service-account grants (project root policy) ---------------------------------------------------

INSTANCE_PERMISSIONS = {
    "data_destruction": (["compute.instances.delete", "compute.disks.delete", "compute.snapshots.delete", "compute.images.delete",
        "storage.buckets.delete", "cloudsql.databases.delete", "cloudsql.instances.delete", "file.instances.delete"],
        ["roles/cloudsql.admin", "roles/cloudsql.instanceUser", "roles/compute.admin", "roles/compute.instanceAdmin.v1"]),
    "database_write": (["cloudsql.databases.update", "cloudsql.instances.update", "datastore.databases.update",
        "datastore.entities.update", "datastore.indexes.update", "spanner.databases.update", "spanner.databases.write",
        "spanner.instances.update", "bigtable.clusters.update", "bigtable.instances.update", "bigtable.tables.update",
        "redis.instances.update", "memcache.instances.update", "datamigration.migrationjobs.update",
        "datamigration.connectionprofiles.update", "datamigration.conversionworkspaces.update", "alloydb.clusters.update",
        "alloydb.instances.update"],
        ["roles/cloudsql.admin", "roles/cloudsql.instanceUser", "roles/datastore.indexAdmin", "roles/datastore.owner",
         "roles/datastore.user", "roles/alloydb.admin", "roles/bigtable.admin", "roles/datamigration.admin",
         "roles/datamigration.serviceAgent", "roles/memcache.admin", "roles/redis.admin", "roles/redisenterprisecloud.admin",
         "roles/spanner.admin", "roles/spanner.databaseAdmin"]),
    "deployments_manager": (["deploymentmanager.deployments.create", "deploymentmanager.deployments.update"],
        ["roles/deploymentmanager.editor"]),
    "disrupt_logging": (["logging.buckets.delete", "logging.buckets.update", "logging.logMetrics.delete", "logging.logMetrics.update",
        "logging.logs.delete", "logging.sinks.delete", "logging.sinks.update"],
        ["roles/logging.bucketWriter", "roles/logging.configWriter", "roles/logging.admin"]),
    "iam_write": (["accessapproval.requests.approve", "accessapproval.requests.dismiss", "accessapproval.settings.delete",
        "accessapproval.settings.update", "accesscontextmanager.accessLevels.create", "accesscontextmanager.accessLevels.delete",
        "accesscontextmanager.accessLevels.replaceAll", "accesscontextmanager.accessLevels.update",
        "accesscontextmanager.accessPolicies.create", "accesscontextmanager.accessPolicies.delete",
        "accesscontextmanager.accessPolicies.setIamPolicy", "accesscontextmanager.accessPolicies.update",
        "accesscontextmanager.gcpUserAccessBindings.create", "accesscontextmanager.gcpUserAccessBindings.delete",
        "accesscontextmanager.gcpUserAccessBindings.update", "accesscontextmanager.policies.create",
        "accesscontextmanager.policies.delete", "accesscontextmanager.policies.setIamPolicy", "accesscontextmanager.policies.update",
        "iam.roles.create", "iam.roles.delete", "iam.roles.undelete", "iam.roles.update", "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccountKeys.create", "iam.serviceAccountKeys.delete", "iam.serviceAccounts.create", "iam.serviceAccounts.delete",
        "iam.serviceAccounts.disable", "iam.serviceAccounts.enable", "iam.serviceAccounts.setIamPolicy",
        "iam.serviceAccounts.undelete", "iam.serviceAccounts.update", "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt", "iam.serviceAccounts.actAs",
        "compute.backendServices.setIamPolicy", "compute.disks.removeResourcePolicies", "compute.disks.setIamPolicy",
        "compute.firewallPolicies.setIamPolicy", "compute.globalOperations.setIamPolicy", "compute.images.setIamPolicy",
        "compute.instanceTemplates.setIamPolicy", "compute.instances.removeResourcePolicies", "compute.instances.setIamPolicy",
        "compute.instances.setServiceAccount", "compute.machineImages.setIamPolicy", "compute.maintenancePolicies.setIamPolicy",
        "compute.snapshots.setIamPolicy"], []),
    "service_account_impersonate": (["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.actAs"], ["roles/iam.securityAdmin"]),
    "deny_policy_write": (["iam.denypolicies.delete", "iam.denypolicies.update"], []),
}
CUSTOM_ROLE = re.compile(r"(projects|organizations)/[^/]+/roles/[^/]+")


def instance_accounts(item):
    accounts = [get(account, "email", str) for account in list_of_objects(optional(item, "serviceAccounts", [], list))]
    if any(not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", account) for account in accounts):
        raise Unavailable("attached service account identity unavailable or malformed")
    return accounts


def role_grants(role, permissions, predefined, index):
    """Match literal basic-role declarations or permissions from a native role definition."""
    if not permissions:
        return role in predefined
    if not (CUSTOM_ROLE.fullmatch(role) or re.fullmatch(r"roles/[\w.]+", role)):
        raise Unavailable("malformed role reference")
    matches = [r for r in complete_items(index, "iam_role") if get(r, "name", str) == role]
    if len(matches) != 1:
        raise Unavailable("role definition absent or ambiguous in the scoped role inventory: " + role)
    definition = matches[0]
    if optional(definition, "deleted", False, bool) or optional(definition, "stage", "ALPHA", str) == "DISABLED":
        return False
    included = strings(get(definition, "includedPermissions", list), "native role permissions")
    return bool(set(included) & set(permissions))


def instance_grant(slug, title, permissions, predefined, *, skip_gke=False, severity="high"):
    @gcp(slug, "instance", title, severity=severity, control="AC-6", category="least_privilege",
         dependencies=["instance", "iam_policy", "iam_role"],
         remediation="Attach a dedicated least-privilege service account to the VM and remove the project-level grant "
                     "of the listed permissions or roles from that account.")
    def evaluate(item, index):
        if skip_gke and get(item, "name", str).startswith("gke-") and "goog-gke-node" in optional(item, "labels", {}, dict):
            return "NOT_APPLICABLE", {"reason": "GKE node VM; node-pool identity is reviewed separately"}
        accounts = instance_accounts(item)
        if not accounts:
            return result(False, service_accounts=[], semantics="VM has no attached service account")
        members = {"serviceAccount:" + email for email in accounts}
        hits, conditional = [], []
        for binding in bindings(root_policy(index)):
            granted = members & set(binding["members"])
            if granted and role_grants(binding["role"], permissions, predefined, index):
                (conditional if binding["condition"] else hits).append({"role": binding["role"], "members": sorted(granted)})
        if conditional and not hits:
            return "MANUAL", {"conditional_bindings": conditional, "reason": "Only IAM-conditioned grants match"}
        return result(bool(hits), service_accounts=accounts, matching_bindings=hits,
                      semantics="Project root policy declarations; inherited, resource-level and deny policies are not evaluated")
    cid = track(gid(slug))
    role = "projects/p/roles/custom" if permissions else predefined[0]
    roles = [{"name": "projects/p/roles/custom", "includedPermissions": permissions[:1]},
             {"name": "projects/p/roles/viewerish", "includedPermissions": ["compute.instances.get"]}]
    vm = {"name": "vm", "serviceAccounts": [{"email": "app@p.iam.gserviceaccount.com"}]}
    good = [("projects/p/roles/viewerish", ["serviceAccount:app@p.iam.gserviceaccount.com"]),
            (role, ["serviceAccount:other@p.iam.gserviceaccount.com"])]
    bad = [(role, ["serviceAccount:app@p.iam.gserviceaccount.com"])]
    cases(cid, vm, vm, pass_index=policy_case(good, iam_role=roles), fail_index=policy_case(bad, iam_role=roles),
          malformed={"name": "vm", "serviceAccounts": [{"email": 7}]})
    return cid


for _name, (_permissions, _roles) in INSTANCE_PERMISSIONS.items():
    instance_grant("instance.sa_no_" + _name + "_permission",
                   "VM service account has no project-level " + _name.replace("_", " ") + " permission", _permissions, _roles)
instance_grant("instance.sa_no_basic_role", "VM service account has no project-level Owner or Editor role", [],
               ["roles/owner", "roles/editor"], skip_gke=True)


# --- Instance and project configuration ---------------------------------------------------------------------

OSLOGIN_TRUE, OSLOGIN_FALSE = ("true", "y", "yes", "1"), ("false", "n", "no", "0")


def oslogin_value(items, what):
    values = []
    for row in list_of_objects(items):
        if get(row, "key", str).lower() == "enable-oslogin":
            value = get(row, "value", str).lower()
            if value not in OSLOGIN_TRUE + OSLOGIN_FALSE:
                raise Unavailable("unrecognized enable-oslogin value in " + what)
            values.append(value in OSLOGIN_TRUE)
    if len(values) > 1:
        raise Unavailable("duplicated enable-oslogin metadata in " + what)
    return values[0] if values else None


def project_metadata_items(project):
    from . import gcp_project_metadata_items
    return gcp_project_metadata_items(project)


@gcp("project.oslogin_enabled", "project", "Project metadata enables OS Login", severity="medium", control="IA-2",
     remediation="Set project metadata enable-oslogin=TRUE (or enforce constraints/compute.requireOsLogin).",
     dependencies=["project", "org_policy_effective"])
def project_oslogin(item, index):
    from . import ComputeDisabled, gcp_oslogin_unset
    try:
        value = oslogin_value(project_metadata_items(item), "project metadata")
    except ComputeDisabled:
        return "NOT_APPLICABLE", {"reason": "Compute Engine API is disabled in the project; no VM uses project metadata"}
    if value is not None:
        return result(not value, enable_oslogin=value, declared_at="project")
    try:
        enforced, policy = gcp_oslogin_unset(index)
    except Unavailable as exc:
        return unknown("enable-oslogin not declared in project metadata; effective compute.requireOsLogin unavailable", detail=str(exc))
    return result(not enforced, enable_oslogin=None, effective_org_policy=policy, require_os_login_enforced=enforced,
        semantics="enable-oslogin unset: Compute Engine defaults to metadata-managed SSH keys unless compute.requireOsLogin is enforced")


_meta = lambda *items: {"fingerprint": "f", **({"items": list(items)} if items else {})}
_oslogin_policy = lambda enforce: scope_index({"org_policy_effective": [{"constraint": "compute.requireOsLogin",
    "name": "projects/p/policies/compute.requireOsLogin", "spec": {"rules": [{"enforce": enforce}]}}]})
cases(track(gid("project.oslogin_enabled")), {"commonInstanceMetadata": _meta({"key": "enable-oslogin", "value": "TRUE"})},
      {"commonInstanceMetadata": _meta()}, fail_index=_oslogin_policy(False),
      unknown={"commonInstanceMetadata": _meta({"key": "other", "value": "x"})},
      malformed={"commonInstanceMetadata": _meta({"key": "enable-oslogin", "value": "maybe"})})


@gcp("instance.not_preemptible", "instance", "VM is not preemptible", severity="low", control="CP-10",
     remediation="Use standard provisioning for workloads that must not be terminated by Compute Engine.")
def instance_not_preemptible(item, index):
    scheduling = get(item, "scheduling", dict)
    preemptible = optional(scheduling, "preemptible", False, bool)
    return result(preemptible, preemptible=preemptible)


cases(track(gid("instance.not_preemptible")), {"scheduling": {"preemptible": False}}, {"scheduling": {"preemptible": True}},
      malformed={"scheduling": {"preemptible": "no"}})


@gcp("instance.not_preemptible_or_spot", "instance", "VM is neither preemptible nor a Spot VM", control="CP-10",
     remediation="Use the STANDARD provisioning model for workloads that must not be preempted.")
def instance_not_spot(item, index):
    scheduling = get(item, "scheduling", dict)
    preemptible = optional(scheduling, "preemptible", False, bool)
    model = optional(scheduling, "provisioningModel", "STANDARD", str)
    if model not in ("STANDARD", "SPOT", "FLEX_START", "RESERVATION_BOUND"):
        raise Unavailable("unrecognized provisioning model")
    return result(preemptible or model == "SPOT", preemptible=preemptible, provisioning_model=model)


cases(track(gid("instance.not_preemptible_or_spot")), {"scheduling": {"provisioningModel": "STANDARD"}},
      {"scheduling": {"provisioningModel": "SPOT"}}, malformed={"scheduling": {"provisioningModel": "CHEAP"}})


@gcp("instance.disks_csek", "instance", "Every VM disk uses a customer-supplied encryption key (CSEK)", severity="high", control="SC-28",
     remediation="Recreate critical disks with customer-supplied encryption keys where policy requires CSEK.")
def instance_csek(item, index):
    disks = list_of_objects(get(item, "disks", list))
    if not disks:
        return "NOT_APPLICABLE", {"reason": "VM has no attached disks"}
    plain = []
    for disk in disks:
        key = optional(disk, "diskEncryptionKey", {}, dict)
        if not optional(key, "sha256", None, str):
            plain.append(optional(disk, "deviceName", None, str))
    return result(bool(plain), disks_without_csek=plain)


cases(track(gid("instance.disks_csek")), {"disks": [{"deviceName": "d", "diskEncryptionKey": {"sha256": "abc"}}]},
      {"disks": [{"deviceName": "d", "diskEncryptionKey": {"kmsKeyName": "k"}}]}, malformed={"disks": ["d"]})


@gcp("instance.suspended_without_disks", "instance", "Suspended VM has no attached persistent disks", severity="low", control="CM-8",
     remediation="Delete or resume long-suspended VMs and detach or snapshot their persistent disks.")
def instance_suspended(item, index):
    status = get(item, "status", str)
    if status not in ("SUSPENDED", "SUSPENDING"):
        return "NOT_APPLICABLE", {"status": status}
    disks = list_of_objects(optional(item, "disks", [], list))
    return result(bool(disks), status=status, attached_disks=[optional(d, "deviceName", None, str) for d in disks])


cases(track(gid("instance.suspended_without_disks")), {"status": "SUSPENDED", "disks": []},
      {"status": "SUSPENDED", "disks": [{"deviceName": "boot", "type": "PERSISTENT"}]}, not_applicable={"status": "RUNNING"},
      malformed={"status": "SUSPENDED", "disks": "boot"})


@gcp("instance_template.no_ip_forwarding", "instance_template", "Instance template does not enable IP forwarding", control="SC-7",
     remediation="Create a new template revision with canIpForward=false unless the VM routes traffic by design.")
def template_ip_forwarding(item, index):
    return result(get(item, "properties.canIpForward", bool), can_ip_forward=item["properties"]["canIpForward"])


cases(track(gid("instance_template.no_ip_forwarding")), {"properties": {"canIpForward": False}},
      {"properties": {"canIpForward": True}}, malformed={"properties": {"canIpForward": "no"}})


@gcp("project.no_api_keys", "project", "Project has no API keys", control="IA-5", dependencies=["project", "api_key"],
     remediation="Replace API keys with service-account or workload-identity credentials and delete unused keys.")
def project_api_keys(item, index):
    keys = [k for k in complete_items(index, "api_key") if optional(k, "deleteTime", None, str) is None]
    return result(bool(keys), api_keys=[k.get("name") for k in keys], semantics="Active API keys in the complete project inventory")


cases(track(gid("project.no_api_keys")), {"name": "projects/1"}, {"name": "projects/1"},
      pass_index=scope_index({"api_key": [{"name": "k", "deleteTime": "2026-01-01T00:00:00Z"}]}),
      fail_index=scope_index({"api_key": [{"name": "projects/1/locations/global/keys/k"}]}))


# --- Images, snapshots and managed instance groups (collector facts pending) -------------------------------

@gcp("image.not_public", "image", "Custom image IAM policy does not grant public access", severity="high", control="AC-3",
     category="exposure", remediation="Remove allUsers/allAuthenticatedUsers bindings from the image IAM policy.")
def image_public(item, index):
    public = [b for b in bindings(get(item, "iamPolicy", dict)) if set(b["members"]) & set(PUBLIC_MEMBERS)]
    return result(bool(public), public_bindings=public)


cases(track(gid("image.not_public")), {"iamPolicy": {"bindings": []}},
      {"iamPolicy": {"bindings": [{"role": "roles/compute.imageUser", "members": ["allAuthenticatedUsers"]}]}},
      malformed={"iamPolicy": {"bindings": [{"role": "r", "members": "allUsers"}]}})


@gcp("snapshot.not_outdated", "snapshot", "Disk snapshot is not older than 90 days", severity="low", control="CP-9",
     remediation="Review snapshot retention and delete or refresh snapshots older than the approved window.")
def snapshot_age(item, index):
    created = parse_time(get(item, "creationTimestamp", str))
    observed = captured_at(item, index)
    days = (observed - created).days
    return result(days > 90, age_days=days, observed_at=observed.isoformat())


cases(track(gid("snapshot.not_outdated")),
      {"creationTimestamp": "2026-09-01T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}},
      {"creationTimestamp": "2026-01-01T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}},
      malformed={"creationTimestamp": "yesterday"})


@gcp("instance_group_manager.autohealing", "instance_group_manager", "Managed instance group has an autohealing health check",
     severity="medium", control="CP-10", remediation="Configure an autohealing policy with a health check on the managed instance group.")
def mig_autohealing(item, index):
    policies = list_of_objects(optional(item, "autoHealingPolicies", [], list))
    checks = [optional(p, "healthCheck", None, str) for p in policies]
    return result(not any(checks), health_checks=[c for c in checks if c])


cases(track(gid("instance_group_manager.autohealing")),
      {"autoHealingPolicies": [{"healthCheck": "hc", "initialDelaySec": 300}]}, {"name": "mig"},
      malformed={"autoHealingPolicies": "hc"})


@gcp("instance_group_manager.multiple_zones", "instance_group_manager", "Managed instance group spans multiple zones",
     severity="low", control="CP-10", remediation="Use a regional managed instance group distributed across at least two zones.")
def mig_zones(item, index):
    if "zone" in item and "region" not in item:
        return result(True, zones=[get(item, "zone", str)], semantics="Zonal managed instance group")
    zones = list_of_objects(get(item, "distributionPolicy.zones", list))
    names = [get(z, "zone", str) for z in zones]
    return result(len(set(names)) < 2, zones=names)


cases(track(gid("instance_group_manager.multiple_zones")),
      {"region": "r", "distributionPolicy": {"zones": [{"zone": "a"}, {"zone": "b"}]}}, {"zone": "z1"},
      malformed={"region": "r", "distributionPolicy": {"zones": ["a"]}})


@gcp("instance_group_manager.load_balancer_attached", "instance_group_manager", "Managed instance group is attached to a load balancer backend",
     severity="low", control="CP-10", dependencies=["instance_group_manager", "backend_service"],
     remediation="Attach the managed instance group to a backend service or confirm it intentionally serves no load-balanced traffic.")
def mig_backend(item, index):
    group = get(item, "instanceGroup", str)
    attached = []
    for service in complete_items(index, "backend_service"):
        for backend in list_of_objects(optional(service, "backends", [], list)):
            if get(backend, "group", str).split("/compute/")[-1] == group.split("/compute/")[-1]:
                attached.append(service.get("name"))
    if not attached:
        return "MANUAL", {"reason": "No backend in this project's complete inventory references the group; cross-project or "
                          "non-load-balanced use must be reviewed"}
    return result(False, backend_services=attached)


_group = "https://www.googleapis.com/compute/v1/projects/p/zones/z/instanceGroups/g"
cases(track(gid("instance_group_manager.load_balancer_attached")), {"instanceGroup": _group}, None,
      pass_index=scope_index({"backend_service": [{"name": "be", "backends": [{"group": _group}]}]}),
      manual={"instanceGroup": _group}, manual_index=scope_index({"backend_service": []}))
del CASES[gid("instance_group_manager.load_balancer_attached")]["fail"]


# --- Load balancing and TLS ---------------------------------------------------------------------------------

def link_tail(value):
    if not isinstance(value, str) or "projects/" not in value:
        raise Unavailable("malformed resource link")
    return "projects/" + value.split("projects/", 1)[1]


@gcp("backend_service.external_iap", "backend_service", "External backend service enables Identity-Aware Proxy", control="AC-3",
     remediation="Enable IAP on external backend services that serve authenticated users.")
def backend_iap(item, index):
    scheme = get(item, "loadBalancingScheme", str)
    if not scheme.startswith("EXTERNAL"):
        return "NOT_APPLICABLE", {"load_balancing_scheme": scheme}
    enabled = optional(optional(item, "iap", {}, dict), "enabled", False, bool)
    return result(not enabled, load_balancing_scheme=scheme, iap_enabled=enabled)


cases(track(gid("backend_service.external_iap")), {"loadBalancingScheme": "EXTERNAL_MANAGED", "iap": {"enabled": True}},
      {"loadBalancingScheme": "EXTERNAL"}, not_applicable={"loadBalancingScheme": "INTERNAL_MANAGED"},
      malformed={"loadBalancingScheme": "EXTERNAL", "iap": {"enabled": "yes"}})


@gcp("backend_bucket.bucket_exists", "backend_bucket", "Backend bucket references an existing Cloud Storage bucket", severity="high",
     control="CM-8", category="exposure", dependencies=["backend_bucket", "bucket"],
     remediation="Delete backend buckets whose storage bucket no longer exists, or recreate the bucket under your control.")
def backend_bucket_exists(item, index):
    name = get(item, "bucketName", str)
    if any(get(b, "name", str) == name for b in complete_items(index, "bucket")):
        return result(False, bucket=name)
    return "MANUAL", {"bucket": name, "reason": "Bucket not in this project's inventory; it may live in another project. "
                      "Confirm the bucket exists and is owned by you (a dangling name can be claimed by others)."}


cases(track(gid("backend_bucket.bucket_exists")), {"bucketName": "assets"}, None,
      pass_index=scope_index({"bucket": [{"name": "assets"}]}), manual={"bucketName": "gone"},
      manual_index=scope_index({"bucket": [{"name": "assets"}]}), malformed={"bucketName": 1})
del CASES[gid("backend_bucket.bucket_exists")]["fail"]

WEAK_CUSTOM_FEATURES = ("TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CBC_SHA",
                        "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA")
TLS_PROXY_KINDS = ("compute#targetHttpsProxy", "compute#targetSslProxy")


def proxy_policy(item, index):
    """Return (applicable, ssl_policy item or None)."""
    kind = get(item, "kind", str)
    if kind not in TLS_PROXY_KINDS:
        return False, None
    link = optional(item, "sslPolicy", None, str)
    if not link:
        return True, None
    tail = link_tail(link)
    policies = [p for p in complete_items(index, "ssl_policy") if link_tail(get(p, "selfLink", str)) == tail]
    if len(policies) != 1:
        raise Unavailable("referenced SSL policy absent or ambiguous in scoped inventory")
    return True, policies[0]


_policy = "https://www.googleapis.com/compute/v1/projects/p/global/sslPolicies/strict"
_https = {"kind": "compute#targetHttpsProxy", "sslPolicy": _policy}


@gcp("target_proxy.https_custom_ssl_policy", "target_proxy", "HTTPS proxy uses an explicit SSL policy", control="SC-8",
     remediation="Attach a reviewed SSL policy to every target HTTPS proxy instead of relying on the default policy.")
def proxy_has_policy(item, index):
    if get(item, "kind", str) != "compute#targetHttpsProxy":
        return "NOT_APPLICABLE", {"reason": "Not an HTTPS proxy"}
    link = optional(item, "sslPolicy", None, str)
    return result(not link, ssl_policy=link)


cases(track(gid("target_proxy.https_custom_ssl_policy")), _https, {"kind": "compute#targetHttpsProxy"},
      not_applicable={"kind": "compute#targetSslProxy"}, malformed={"kind": "compute#targetHttpsProxy", "sslPolicy": 1})


@gcp("target_proxy.https_min_tls_1_2", "target_proxy", "HTTPS proxy SSL policy requires TLS 1.2 or later", severity="high",
     control="SC-8", dependencies=["target_proxy", "ssl_policy"],
     remediation="Attach an SSL policy with minTlsVersion TLS_1_2 to the target HTTPS proxy.")
def proxy_min_tls(item, index):
    if get(item, "kind", str) != "compute#targetHttpsProxy":
        return "NOT_APPLICABLE", {"reason": "Not an HTTPS proxy"}
    _, policy = proxy_policy(item, index)
    if policy is None:
        return result(True, ssl_policy=None, semantics="Default SSL policy allows TLS 1.0")
    minimum = optional(policy, "minTlsVersion", "TLS_1_0", str)
    if minimum not in ("TLS_1_0", "TLS_1_1", "TLS_1_2", "TLS_1_3"):
        raise Unavailable("unrecognized minimum TLS version")
    return result(minimum not in ("TLS_1_2", "TLS_1_3"), min_tls_version=minimum)


cases(track(gid("target_proxy.https_min_tls_1_2")), _https, _https,
      pass_index=scope_index({"ssl_policy": [{"selfLink": _policy, "profile": "COMPATIBLE", "minTlsVersion": "TLS_1_2"}]}),
      fail_index=scope_index({"ssl_policy": [{"selfLink": _policy, "profile": "MODERN", "minTlsVersion": "TLS_1_0"}]}),
      not_applicable={"kind": "compute#targetSslProxy"}, malformed={"kind": None})


# --- Cloud DNS ---------------------------------------------------------------------------------------------

@gcp("network.dns_logging", "network", "VPC network has a Cloud DNS server policy with logging enabled", control="AU-12",
     dependencies=["network", "dns_policy"],
     remediation="Attach a Cloud DNS server policy with enableLogging=true to the VPC network.")
def network_dns_logging(item, index):
    tail = link_tail(get(item, "selfLink", str))
    attached = []
    for policy in complete_items(index, "dns_policy"):
        for network in list_of_objects(optional(policy, "networks", [], list)):
            if link_tail(get(network, "networkUrl", str)) == tail:
                attached.append(policy)
    if len(attached) > 1:
        raise Unavailable("multiple DNS policies reference the network")
    logging = bool(attached) and optional(attached[0], "enableLogging", False, bool)
    return result(not logging, dns_policy=attached[0].get("name") if attached else None, enable_logging=logging)


_net = "https://www.googleapis.com/compute/v1/projects/p/global/networks/vpc"
cases(track(gid("network.dns_logging")), {"selfLink": _net}, {"selfLink": _net},
      pass_index=scope_index({"dns_policy": [{"name": "pol", "enableLogging": True, "networks": [{"networkUrl": _net}]}]}),
      fail_index=scope_index({"dns_policy": [{"name": "pol", "networks": [{"networkUrl": _net}]}]}), malformed={"selfLink": "vpc"})


def public_zone_dnssec(item):
    visibility = optional(item, "visibility", "public", str)
    if visibility not in ("public", "private"):
        raise Unavailable("unrecognized DNS zone visibility")
    if visibility == "private":
        return None
    config = optional(item, "dnssecConfig", {}, dict)
    state = optional(config, "state", "off", str)
    if state not in ("on", "off", "transfer"):
        raise Unavailable("unrecognized DNSSEC state")
    return state, config


@gcp("dns_zone.dnssec_enabled", "dns_managed_zone", "Public Cloud DNS zone has DNSSEC enabled", control="SC-20",
     remediation="Enable DNSSEC (dnssecConfig.state=on) on public managed zones and publish the DS record.")
def zone_dnssec(item, index):
    zone = public_zone_dnssec(item)
    if zone is None:
        return "NOT_APPLICABLE", {"reason": "Private zones do not support DNSSEC"}
    return result(zone[0] != "on", dnssec_state=zone[0])


cases(track(gid("dns_zone.dnssec_enabled")), {"visibility": "public", "dnssecConfig": {"state": "on"}},
      {"visibility": "public", "dnssecConfig": {"state": "off"}}, not_applicable={"visibility": "private"},
      malformed={"visibility": "public", "dnssecConfig": {"state": "maybe"}})


def rsasha1(slug, key_type, label):
    @gcp(slug, "dns_managed_zone", "DNSSEC " + label + " does not use RSASHA1", control="SC-20",
         remediation="Re-sign the zone with RSASHA256/ECDSAP256SHA256 " + label + " specs (turn DNSSEC off, change keySpecs, re-enable).")
    def evaluate(item, index):
        zone = public_zone_dnssec(item)
        if zone is None or zone[0] == "off":
            return "NOT_APPLICABLE", {"reason": "Private zone or DNSSEC disabled"}
        specs = list_of_objects(get(zone[1], "defaultKeySpecs", list))
        selected, weak = [], []
        for spec in specs:
            selected_type = get(spec, "keyType", str)
            algorithm = get(spec, "algorithm", str).lower()
            if selected_type not in ("keySigning", "zoneSigning"):
                raise Unavailable("unrecognized DNSSEC key type")
            if algorithm not in ("rsasha1", "rsasha256", "rsasha512", "ecdsap256sha256", "ecdsap384sha384"):
                raise Unavailable("unrecognized DNSSEC key algorithm")
            if selected_type == key_type:
                selected.append(spec)
                if algorithm == "rsasha1":
                    weak.append(spec)
        if not selected:
            raise Unavailable("DNSSEC default key specification unavailable for selected key type")
        return result(bool(weak), key_type=key_type, rsasha1_specs=len(weak))
    cid = track(gid(slug))
    spec = lambda algorithm: {"visibility": "public", "dnssecConfig": {"state": "on", "defaultKeySpecs": [
        {"keyType": key_type, "algorithm": algorithm}]}}
    cases(cid, spec("rsasha256"), spec("rsasha1"), not_applicable={"visibility": "public", "dnssecConfig": {"state": "off"}},
          malformed={"visibility": "public", "dnssecConfig": {"state": "on", "defaultKeySpecs": [{"keyType": key_type}]}})


rsasha1("dns_zone.ksk_not_rsasha1", "keySigning", "key-signing key")
rsasha1("dns_zone.zsk_not_rsasha1", "zoneSigning", "zone-signing key")
