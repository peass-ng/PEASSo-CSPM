"""claude_azure COMPUTE group: VMs, disks, scale sets, container instances/registries, Cosmos DB,
Data Box Edge and Databricks predicates.

Predicates read ARM-native shapes and preserve unavailable evidence as UNKNOWN.
Registration alone does not establish that a live collector can produce every prerequisite.
Public automation admission and collected coverage determine which checks can run; see
docs/peaso-checks.md for the current evidence and automation contracts.
"""
from __future__ import annotations
from .claude_azure_common import *  # noqa: F401,F403
from .claude_azure_common import (claude, cid, enum, private_link_states, approved_private_link_case, setting, nsg_rules,
                                  port_range, internet_allow_rules, nsg_rule, nsg_case, INTERNET_SOURCES,
                                  diagnostic_settings, diagnostic_logs, diag_log, diag_case, scoped, scope_index, get,
                                  list_of_objects, optional, Unavailable, result, unknown, CASES, CHECK_IDS)

_FIRST = len(CHECK_IDS)


def _omitted(item, parent, key, proof, default=None):
    """ARM omits some unset properties; a present required sibling (``proof``) shows the object was
    fully returned, so the omission is the documented unset value. Without the proof it stays UNKNOWN."""
    container = get(item, parent, dict)
    if key in container:
        return get(container, key)
    if proof not in container:
        raise Unavailable("cannot distinguish omitted " + parent + "." + key + " from an uncollected fact")
    return default


def _lower_id(value):
    if not isinstance(value, str) or not value:
        raise Unavailable("malformed ARM resource id")
    return value.rstrip("/").lower()


# --- Virtual machine helpers ---------------------------------------------------------------------------

def _os_type(item, path="properties.storageProfile.osDisk.osType"):
    return enum(item, path, ("Windows", "Linux"))


def _extensions(item, path="resources"):
    """VM ``resources`` (GET virtualMachines / extensions list) or a VMSS extensionProfile list."""
    normalized = []
    for extension in list_of_objects(get(item, path, list)):
        props = get(extension, "properties", dict)
        publisher, kind = props.get("publisher"), props.get("type")
        if not isinstance(publisher, str) or not isinstance(kind, str):
            raise Unavailable("malformed extension publisher or type")
        normalized.append({"name": extension.get("name") if isinstance(extension.get("name"), str) else "",
                           "publisher": publisher, "type": kind, "state": props.get("provisioningState"),
                           "auto_upgrade": props.get("autoUpgradeMinorVersion"), "settings": props.get("settings")})
    return normalized


def _ext(publisher, kind, name=None, state="Succeeded", **props):
    return {"name": name or kind, "properties": {"publisher": publisher, "type": kind, "provisioningState": state, **props}}


def _vm(os_type="Linux", **extra):
    data = {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
            "properties": {"storageProfile": {"osDisk": {"osType": os_type}}}}
    for key, value in extra.items():
        data[key] = value
    return data


# Disk attachment state (Microsoft.Compute/disks properties.diskState).
ATTACHED_STATES = ("Attached", "Reserved")
UNATTACHED_STATES = ("Unattached", "ActiveSAS", "ActiveSASFrozen", "ActiveUpload", "ReadyToUpload", "Frozen")
ENCRYPTION_TYPES = ("EncryptionAtRestWithPlatformKey", "EncryptionAtRestWithCustomerKey", "EncryptionAtRestWithPlatformAndCustomerKeys")


def _disk_rule(slug, title, attached, allowed, *, severity="medium"):
    @claude(slug, "disk", title, severity=severity, control="SC-28",
            remediation="Associate the disk with a disk encryption set that uses a customer-managed Key Vault key "
                        "(EncryptionAtRestWithCustomerKey, or PlatformAndCustomerKeys for double encryption).")
    def evaluate(item, index):
        state = enum(item, "properties.diskState", ATTACHED_STATES + UNATTACHED_STATES)
        if (state in ATTACHED_STATES) != attached:
            return "NOT_APPLICABLE", {"disk_state": state, "applies_to": "attached" if attached else "unattached"}
        encryption = enum(item, "properties.encryption.type", ENCRYPTION_TYPES)
        return result(encryption not in allowed, disk_state=state, encryption_type=encryption, accepted=list(allowed))
    evaluate.__name__ = "claude_" + slug
    state = ATTACHED_STATES[0] if attached else UNATTACHED_STATES[0]
    other = UNATTACHED_STATES[0] if attached else ATTACHED_STATES[0]
    disk = lambda s, e: {"properties": {"diskState": s, "encryption": {"type": e}}}
    CASES[cid(slug)] = {"pass": disk(state, allowed[0]), "fail": disk(state, "EncryptionAtRestWithPlatformKey"),
                        "not_applicable": disk(other, "EncryptionAtRestWithPlatformKey"), "missing": {},
                        "malformed": disk(state, "SomethingNew")}


CMK_TYPES = ("EncryptionAtRestWithCustomerKey", "EncryptionAtRestWithPlatformAndCustomerKeys")
_disk_rule("disk_unattached_cmk", "Unattached managed disk is encrypted with a customer-managed key", False, CMK_TYPES)
_disk_rule("disk_unattached_customer_key", "Unattached managed disk uses EncryptionAtRestWithCustomerKey", False,
           ("EncryptionAtRestWithCustomerKey",))
_disk_rule("disk_attached_cmk", "Attached managed disk is encrypted with a customer-managed key", True, CMK_TYPES)
_disk_rule("disk_attached_customer_key", "Attached OS/data disk uses EncryptionAtRestWithCustomerKey", True,
           ("EncryptionAtRestWithCustomerKey",))
_disk_rule("disk_attached_double_encryption", "Attached OS/data disk uses platform and customer-managed keys (double encryption)",
           True, ("EncryptionAtRestWithPlatformAndCustomerKeys",))


@claude("disk_access_private_link", "disk_access", "Disk access resource has an approved private endpoint connection",
        control="SC-7", category="network",
        remediation="Create a private endpoint for the disk access resource and approve the connection; bind disks to it with networkAccessPolicy AllowPrivate.")
def disk_access_private_link(item, index):
    states = private_link_states(item)
    return result("Approved" not in states, connection_states=states)
CASES[cid("disk_access_private_link")] = {"pass": approved_private_link_case(), "fail": {"properties": {"privateEndpointConnections": []}},
                                          "missing": {}}


# --- VM extensions -----------------------------------------------------------------------------------

def _extension_rule(slug, title, match, *, os_only=None, severity="medium", control="CM-6", remediation=None,
                    pass_ext=None, fail_ext=None, kind="vm", path="resources", os_path="properties.storageProfile.osDisk.osType"):
    @claude(slug, kind, title, severity=severity, control=control, remediation=remediation)
    def evaluate(item, index):
        if os_only is not None:
            os_type = _os_type(item, os_path)
            if os_type != os_only:
                return "NOT_APPLICABLE", {"os_type": os_type, "applies_to": os_only}
        extensions = _extensions(item, path)
        hits = [e["name"] for e in extensions if match(e)]
        return result(not hits, matching_extensions=hits, extension_count=len(extensions))
    evaluate.__name__ = "claude_" + slug
    os_type = os_only or "Linux"
    CASES[cid(slug)] = {"pass": _vm(os_type, resources=[pass_ext]), "fail": _vm(os_type, resources=[fail_ext] if fail_ext else []),
                        "missing": _vm(os_type), "malformed": _vm(os_type, resources=[{"properties": {"publisher": 1}}])}
    if os_only is not None:
        CASES[cid(slug)]["not_applicable"] = _vm("Linux" if os_only == "Windows" else "Windows", resources=[])
    return evaluate


GC = "Microsoft.GuestConfiguration"
_extension_rule("vm_guest_configuration_extension", "VM has the Guest Configuration extension provisioned",
                lambda e: e["publisher"] == GC and e["state"] == "Succeeded", severity="low",
                remediation="Deploy the Azure Machine Configuration (Guest Configuration) extension with a system-assigned identity.",
                pass_ext=_ext(GC, "ConfigurationforLinux", "AzurePolicyforLinux"),
                fail_ext=_ext(GC, "ConfigurationforLinux", "AzurePolicyforLinux", state="Failed"))
_extension_rule("vm_guest_configuration_extension_linux", "Linux VM has the AzurePolicyforLinux Guest Configuration extension",
                lambda e: e["publisher"] == GC and e["type"] == "ConfigurationforLinux" and e["name"].endswith("AzurePolicyforLinux")
                and e["state"] == "Succeeded", os_only="Linux", severity="low",
                remediation="Deploy the AzurePolicyforLinux (ConfigurationforLinux) Machine Configuration extension.",
                pass_ext=_ext(GC, "ConfigurationforLinux", "AzurePolicyforLinux"), fail_ext=_ext(GC, "ConfigurationforLinux", "Other"))
_extension_rule("vm_guest_configuration_extension_windows", "Windows VM has the AzurePolicyforWindows Guest Configuration extension",
                lambda e: e["publisher"] == GC and e["type"] == "ConfigurationforWindows" and e["name"].endswith("AzurePolicyforWindows")
                and e["state"] == "Succeeded", os_only="Windows", severity="low",
                remediation="Deploy the AzurePolicyforWindows (ConfigurationforWindows) Machine Configuration extension.",
                pass_ext=_ext(GC, "ConfigurationforWindows", "AzurePolicyforWindows"), fail_ext=_ext(GC, "ConfigurationforWindows", "Other"))

AM = "Microsoft.Azure.Security"
_extension_rule("vm_antimalware_extension", "VM has the Microsoft Antimalware (IaaSAntimalware) extension",
                lambda e: e["publisher"] == AM and e["type"] == "IaaSAntimalware", control="SI-3",
                remediation="Deploy the IaaSAntimalware extension or an approved endpoint protection solution.",
                pass_ext=_ext(AM, "IaaSAntimalware"), fail_ext=_ext("Other", "Other"))
_extension_rule("vm_antimalware_auto_upgrade", "Windows VM Antimalware extension enables automatic minor-version upgrade",
                lambda e: e["publisher"] == AM and e["type"] == "IaaSAntimalware" and e["auto_upgrade"] is True,
                os_only="Windows", control="SI-3",
                remediation="Set autoUpgradeMinorVersion true on the IaaSAntimalware extension so signature/engine updates apply.",
                pass_ext=_ext(AM, "IaaSAntimalware", autoUpgradeMinorVersion=True),
                fail_ext=_ext(AM, "IaaSAntimalware", autoUpgradeMinorVersion=False))

DA = "Microsoft.Azure.Monitoring.DependencyAgent"
_extension_rule("vm_dependency_agent_linux", "Linux VM has the Dependency agent for network traffic data collection",
                lambda e: e["publisher"] == DA and e["type"] == "DependencyAgentLinux" and e["state"] == "Succeeded",
                os_only="Linux", severity="low", control="SI-4",
                remediation="Install the DependencyAgentLinux extension (VM insights) to collect network traffic data.",
                pass_ext=_ext(DA, "DependencyAgentLinux"), fail_ext=_ext(DA, "DependencyAgentLinux", state="Failed"))
_extension_rule("vm_dependency_agent_windows", "Windows VM has the Dependency agent for network traffic data collection",
                lambda e: e["publisher"] == DA and e["type"] == "DependencyAgentWindows" and e["state"] == "Succeeded",
                os_only="Windows", severity="low", control="SI-4",
                remediation="Install the DependencyAgentWindows extension (VM insights) to collect network traffic data.",
                pass_ext=_ext(DA, "DependencyAgentWindows"), fail_ext=_ext(DA, "DependencyAgentWindows", state="Failed"))


IDENTITY_TYPES = ("None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned")


def _identity_parts(item):
    identity = optional(item, "identity", None)
    if identity is None:
        return set()
    if not isinstance(identity, dict):
        raise Unavailable("malformed identity")
    kind = identity.get("type")
    if kind is None:
        return set()
    if kind not in IDENTITY_TYPES:
        raise Unavailable("unrecognized identity type")
    return {part.strip() for part in kind.split(",")} - {"None"}


def _gc_identity_rule(slug, title, decide, cases):
    @claude(slug, "vm", title, severity="low", control="IA-2",
            remediation="Assign a system-assigned managed identity to VMs running the Guest Configuration extension.")
    def evaluate(item, index):
        installed = any(e["publisher"] == GC for e in _extensions(item))
        if not installed:
            return "NOT_APPLICABLE", {"reason": "Guest Configuration extension not installed"}
        return decide(_identity_parts(item))
    evaluate.__name__ = "claude_" + slug
    gc = [_ext(GC, "ConfigurationforLinux", "AzurePolicyforLinux")]
    built = {name: _vm("Linux", resources=gc, **({"identity": {"type": t}} if t else {})) for name, t in cases.items()}
    CASES[cid(slug)] = {**built, "missing": {}, "not_applicable": _vm("Linux", resources=[]),
                        "malformed": _vm("Linux", resources=gc, identity={"type": "Weird"})}


def _decide_any(parts):
    return result(not parts, identity_types=sorted(parts))


def _decide_system(parts):
    return result("SystemAssigned" not in parts, identity_types=sorted(parts))


def _decide_user_and_system(parts):
    if "UserAssigned" not in parts:
        return "NOT_APPLICABLE", {"reason": "no user-assigned identity", "identity_types": sorted(parts)}
    return result("SystemAssigned" not in parts, identity_types=sorted(parts))


_gc_identity_rule("vm_guest_configuration_managed_identity", "VM with Guest Configuration extension has a managed identity",
                  _decide_any, {"pass": "UserAssigned", "fail": None})
_gc_identity_rule("vm_guest_configuration_system_identity", "VM with Guest Configuration extension has a system-assigned identity",
                  _decide_system, {"pass": "SystemAssigned", "fail": "UserAssigned"})
_gc_identity_rule("vm_guest_configuration_user_and_system_identity",
                  "VM with Guest Configuration and a user-assigned identity also has a system-assigned identity",
                  _decide_user_and_system, {"pass": "SystemAssigned, UserAssigned", "fail": "UserAssigned"})


# --- Guest configuration assignments --------------------------------------------------------------------

COMPLIANCE = ("Compliant", "NonCompliant", "Pending")


def _assignment(name, status="Compliant", params=None):
    gc = {"name": name}
    if params is not None:
        gc["configurationParameter"] = [{"name": k, "value": v} for k, v in params.items()]
    return {"name": name, "properties": {"complianceStatus": status, "guestConfiguration": gc}}


def _guest_rule(slug, title, config, os_only, *, severity="medium", control="CM-6", parameter=None, remediation=None):
    @claude(slug, "vm", title, severity=severity, control=control,
            remediation=remediation or ("Assign the built-in Machine Configuration policy for " + config +
                                        " and remediate the guest until the assignment reports Compliant."))
    def evaluate(item, index):
        os_type = _os_type(item)
        if os_type != os_only:
            return "NOT_APPLICABLE", {"os_type": os_type, "applies_to": os_only}
        statuses = []
        for row in list_of_objects(get(item, "guestConfigurationAssignments", list)):
            name = row.get("name")
            gc = get(row, "properties.guestConfiguration", dict)
            if not (gc.get("name") == config or name == config or (isinstance(name, str) and name.startswith(config + "$"))):
                continue
            status = enum(row, "properties.complianceStatus", COMPLIANCE)
            if status == "Compliant" and parameter is not None:
                values = [p.get("value") for p in list_of_objects(gc.get("configurationParameter", []))
                          if p.get("name") == parameter[0]]
                if not values:
                    status = "ParameterUnknown"
                elif parameter[1] not in values:
                    status = "ParameterMismatch"
            statuses.append(status)
        if "Compliant" in statuses:
            return result(False, configuration=config, statuses=statuses)
        if "ParameterUnknown" in statuses or (statuses and set(statuses) <= {"Pending"}):
            return unknown("guest configuration assignment not yet evaluable", configuration=config, statuses=statuses)
        return result(True, configuration=config, statuses=statuses or ["not_assigned"])
    evaluate.__name__ = "claude_" + slug
    params = {parameter[0]: parameter[1]} if parameter else None
    bad = {parameter[0]: "1.2"} if parameter else None
    CASES[cid(slug)] = {"pass": _vm(os_only, guestConfigurationAssignments=[_assignment(config, params=params)]),
                        "fail": _vm(os_only, guestConfigurationAssignments=[_assignment(config, "NonCompliant", params=params)]),
                        "unassigned": _vm(os_only, guestConfigurationAssignments=[]),
                        "pending": _vm(os_only, guestConfigurationAssignments=[_assignment(config, "Pending", params=params)]),
                        "not_applicable": _vm("Linux" if os_only == "Windows" else "Windows", guestConfigurationAssignments=[]),
                        "missing": _vm(os_only),
                        "malformed": _vm(os_only, guestConfigurationAssignments=[_assignment(config, "Weird")])}
    if parameter:
        CASES[cid(slug)]["fail_param"] = _vm(os_only, guestConfigurationAssignments=[_assignment(config, params=bad)])
        CASES[cid(slug)]["unknown_param"] = _vm(os_only, guestConfigurationAssignments=[_assignment(config, params={})])


_guest_rule("vm_linux_no_passwordless_accounts", "Linux VM has no local accounts without passwords (PasswordPolicy_msid232)",
            "PasswordPolicy_msid232", "Linux", severity="high", control="IA-5")
_guest_rule("vm_linux_remote_requires_password", "Linux VM blocks remote connections from accounts without passwords (PasswordPolicy_msid110)",
            "PasswordPolicy_msid110", "Linux", severity="high", control="IA-5")
_guest_rule("vm_windows_max_password_age", "Windows VM maximum password age is 70 days (MaximumPasswordAge)",
            "MaximumPasswordAge", "Windows", control="IA-5")
_guest_rule("vm_windows_min_password_age", "Windows VM minimum password age is 1 day (MinimumPasswordAge)",
            "MinimumPasswordAge", "Windows", control="IA-5")
_guest_rule("vm_windows_min_password_length", "Windows VM minimum password length is 14 (MinimumPasswordLength)",
            "MinimumPasswordLength", "Windows", control="IA-5")
_guest_rule("vm_windows_password_complexity", "Windows VM enforces password complexity (PasswordMustMeetComplexityRequirements)",
            "PasswordMustMeetComplexityRequirements", "Windows", control="IA-5")
_guest_rule("vm_windows_no_reversible_password_encryption", "Windows VM does not store passwords with reversible encryption",
            "StorePasswordsUsingReversibleEncryption", "Windows", severity="high", control="IA-5")
_guest_rule("vm_windows_password_history", "Windows VM prevents reuse of the previous 24 passwords (EnforcePasswordHistory)",
            "EnforcePasswordHistory", "Windows", control="IA-5")
_guest_rule("vm_linux_security_baseline", "Linux VM meets the Azure compute security baseline (AzureLinuxBaseline)",
            "AzureLinuxBaseline", "Linux")
_guest_rule("vm_windows_security_baseline", "Windows VM meets the Azure compute security baseline (AzureWindowsBaseline)",
            "AzureWindowsBaseline", "Windows")
_guest_rule("vm_windows_exploit_guard", "Windows VM has Windows Defender Exploit Guard enabled (WindowsDefenderExploitGuard)",
            "WindowsDefenderExploitGuard", "Windows", control="SI-16")
_guest_rule("vm_windows_secure_protocol_tls13", "Windows VM web servers require TLS 1.3 (AuditSecureProtocol MinimumTLSVersion 1.3)",
            "AuditSecureProtocol", "Windows", control="SC-8", parameter=("MinimumTLSVersion", "1.3"))


# --- VM configuration -----------------------------------------------------------------------------------

@claude("vm_os_managed_disk", "vm", "VM OS disk is a managed disk", control="CM-6",
        remediation="Convert the VM to managed disks (ConvertTo-AzVMManagedDisk / az vm convert).")
def vm_os_managed_disk(item, index):
    os_disk = get(item, "properties.storageProfile.osDisk", dict)
    if isinstance(os_disk.get("diffDiskSettings"), dict) and os_disk["diffDiskSettings"].get("option") == "Local":
        return "NOT_APPLICABLE", {"reason": "ephemeral OS disk"}
    if "managedDisk" not in os_disk:
        if isinstance(os_disk.get("vhd"), dict):
            return result(True, unmanaged_os_disk=True)
        raise Unavailable("OS disk storage type was not collected")
    managed = os_disk["managedDisk"]
    if managed is None:
        return result(True, unmanaged_os_disk=True)
    managed_id = get(os_disk, "managedDisk.id", str)
    return result(False, managed_disk_id=managed_id)
CASES[cid("vm_os_managed_disk")] = {"pass": {"properties": {"storageProfile": {"osDisk": {"managedDisk": {"id": "/d"}}}}},
                                    "fail": {"properties": {"storageProfile": {"osDisk": {"vhd": {"uri": "https://x/vhd"}}}}},
                                    "missing": {}, "malformed": {"properties": {"storageProfile": {"osDisk": {"managedDisk": {"id": 3}}}}}}


@claude("vm_windows_automatic_updates", "vm", "Windows VM enables automatic updates", control="SI-2",
        remediation="Enable osProfile.windowsConfiguration.enableAutomaticUpdates or use Azure Update Manager with an automatic patch mode.")
def vm_windows_automatic_updates(item, index):
    os_type = _os_type(item)
    if os_type != "Windows":
        return "NOT_APPLICABLE", {"os_type": os_type, "applies_to": "Windows"}
    enabled = get(item, "properties.osProfile.windowsConfiguration.enableAutomaticUpdates", bool)
    return result(not enabled, enable_automatic_updates=enabled)
_win = lambda value: {"properties": {"storageProfile": {"osDisk": {"osType": "Windows"}},
                                     "osProfile": {"windowsConfiguration": {"enableAutomaticUpdates": value}}}}
CASES[cid("vm_windows_automatic_updates")] = {"pass": _win(True), "fail": _win(False), "missing": {}, "malformed": _win("yes"),
                                              "not_applicable": _vm("Linux")}


@claude("vm_windows_secure_boot", "vm", "Windows VM enables Secure Boot (Trusted Launch or Confidential VM)", control="SI-7",
        remediation="Deploy Windows VMs as Trusted Launch or Confidential VMs with uefiSettings.secureBootEnabled true.")
def vm_windows_secure_boot(item, index):
    os_type = _os_type(item)
    os_profile = optional(get(item, "properties", dict), "osProfile", None)
    if os_profile is not None:
        if not isinstance(os_profile, dict):
            raise Unavailable("malformed VM OS profile")
        opposite = "linuxConfiguration" if os_type == "Windows" else "windowsConfiguration"
        if optional(os_profile, opposite, None) is not None:
            raise Unavailable("VM OS profile contradicts native OS disk type")
    if os_type != "Windows":
        return "NOT_APPLICABLE", {"os_type": os_type}
    security_type = enum(item, "properties.securityProfile.securityType", ("TrustedLaunch", "ConfidentialVM", "Standard"))
    if security_type == "Standard":
        return result(True, security_type=security_type)
    boot = get(item, "properties.securityProfile.uefiSettings.secureBootEnabled", bool)
    return result(not boot, security_type=security_type, secure_boot=boot)
_sb = lambda st, boot, offer="WindowsServer": {"properties": {"storageProfile": {"osDisk": {"osType": "Windows"}, "imageReference": {"offer": offer}},
                                                              "securityProfile": {"securityType": st, "uefiSettings": {"secureBootEnabled": boot}}}}
CASES[cid("vm_windows_secure_boot")] = {"pass": _sb("TrustedLaunch", True), "fail": _sb("TrustedLaunch", False), "missing": {},
                                        "malformed": _sb("Novel", True), "not_applicable": _sb("TrustedLaunch", False, "sql2019-ubuntu")}


# --- VM network exposure (VM -> NIC -> NSG joins over subscription-scoped inventories) --------------------

def _vm_nics(item, index):
    refs = list_of_objects(get(item, "properties.networkProfile.networkInterfaces", list))
    wanted = {_lower_id(get(ref, "id", str)) for ref in refs}
    nics = {}
    for nic in scoped(index, "nic"):
        nic_id = nic.get("id")
        if isinstance(nic_id, str) and nic_id.lower() in wanted:
            nics[nic_id.lower()] = nic
    if set(nics) != wanted:
        raise Unavailable("VM network interface not in the collected NIC inventory")
    return list(nics.values())


def _nic_nsg_ids(nic, include_subnet, index):
    ids = set()
    ref = _omitted(nic, "properties", "networkSecurityGroup", "ipConfigurations")
    if ref is not None:
        ids.add(_lower_id(get(ref, "id", str)))
    if include_subnet:
        subnets = {_lower_id(get(c, "properties.subnet.id", str))
                   for c in list_of_objects(get(nic, "properties.ipConfigurations", list))}
        for nsg in scoped(index, "nsg"):
            attached = _omitted(nsg, "properties", "subnets", "securityRules", [])
            if any(_lower_id(get(s, "id", str)) in subnets for s in list_of_objects(attached)):
                ids.add(_lower_id(get(nsg, "id", str)))
    return ids


def _nsgs(index, ids):
    found = {}
    for nsg in scoped(index, "nsg"):
        if isinstance(nsg.get("id"), str) and nsg["id"].lower() in ids:
            found[nsg["id"].lower()] = nsg
    if set(found) != ids:
        raise Unavailable("associated NSG not in the collected NSG inventory")
    return list(found.values())


NIC_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1"
NSG_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"
SUBNET_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/a"
_VM_NET = {"id": "/vm1", "properties": {"networkProfile": {"networkInterfaces": [{"id": NIC_ID}]}}}


def _nic(nsg=True, public_ip=False):
    config = {"properties": {"privateIPAddress": "10.0.0.4", "subnet": {"id": SUBNET_ID}}}
    if public_ip:
        config["properties"]["publicIPAddress"] = {"id": "/pip1"}
    props = {"ipConfigurations": [config]}
    if nsg:
        props["networkSecurityGroup"] = {"id": NSG_ID}
    return {"id": NIC_ID, "properties": props}


def _nsg(*rules, subnets=None):
    data = nsg_case(*rules)
    data["id"] = NSG_ID
    if subnets is not None:
        data["properties"]["subnets"] = [{"id": s} for s in subnets]
    return data


@claude("vm_no_public_ip", "vm", "VM network interfaces have no public IP address", severity="high", control="SC-7",
        category="exposure", dependencies=["vm", "nic"],
        remediation="Remove public IP associations from VM NICs; reach VMs through Azure Bastion, VPN or a load balancer/NAT gateway.")
def vm_no_public_ip(item, index):
    public = []
    for nic in _vm_nics(item, index):
        for config in list_of_objects(get(nic, "properties.ipConfigurations", list)):
            ref = _omitted(config, "properties", "publicIPAddress", "privateIPAddress")
            if ref is not None:
                public.append(get(ref, "id", str))
    return result(bool(public), public_ip_ids=public)
CASES[cid("vm_no_public_ip")] = {"pass": _VM_NET, "pass_index": scope_index({"nic": [_nic()]}),
                                 "fail": _VM_NET, "fail_index": scope_index({"nic": [_nic(public_ip=True)]}), "missing": {}}


@claude("vm_nic_nsg_internet_tcp_ingress", "vm", "VM NIC NSG has no inbound TCP/any allow rule from the internet",
        severity="high", control="AC-17", category="network", dependencies=["vm", "nic", "nsg"],
        remediation="Remove or scope NSG inbound Allow rules whose source is Internet/*/0.0.0.0/0 on NSGs attached to the VM NIC.")
def vm_nic_nsg_internet_tcp_ingress(item, index):
    ids = set()
    for nic in _vm_nics(item, index):
        ids |= _nic_nsg_ids(nic, False, index)
    hits = []
    for nsg in _nsgs(index, ids):
        for rule in nsg_rules(nsg):
            if (rule["direction"] == "Inbound" and rule["access"] == "Allow" and rule["protocol"].lower() in ("tcp", "*")
                    and any(s in INTERNET_SOURCES for s in rule["sources"])):
                for spec in rule["ports"]:
                    port_range(spec)
                hits.append({"nsg": nsg["id"], "rule": rule["name"], "protocol": rule["protocol"].lower(), "ports": rule["ports"]})
    return result(bool(hits), internet_allow_rules=hits, nsg_count=len(ids))
CASES[cid("vm_nic_nsg_internet_tcp_ingress")] = {
    "pass": _VM_NET, "pass_index": scope_index({"nic": [_nic()], "nsg": [_nsg(nsg_rule("ok", "Tcp", "10.0.0.0/8", "22"))]}),
    "fail": _VM_NET, "fail_index": scope_index({"nic": [_nic()], "nsg": [_nsg(nsg_rule("web", "Tcp", "Internet", "443"))]}),
    "missing": {}}

MANAGEMENT_PORTS = (22, 3389, 53, 123, 161, 389, 1900)


@claude("vm_nsg_internet_management_ports", "vm", "VM NIC/subnet NSGs block internet TCP/UDP to management and amplification ports",
        severity="high", control="SC-7", category="network", dependencies=["vm", "nic", "nsg"],
        remediation="Restrict inbound internet access to ports 22, 3389, 53, 123, 161, 389 and 1900 on NIC and subnet NSGs; use Bastion or JIT.")
def vm_nsg_internet_management_ports(item, index):
    ids = set()
    for nic in _vm_nics(item, index):
        ids |= _nic_nsg_ids(nic, True, index)
    hits = []
    for nsg in _nsgs(index, ids):
        for rule in internet_allow_rules(nsg, protocols=("tcp", "udp", "*"), ports=MANAGEMENT_PORTS):
            hits.append({"nsg": nsg["id"], **rule})
    return result(bool(hits), internet_allow_rules=hits, nsg_count=len(ids))
CASES[cid("vm_nsg_internet_management_ports")] = {
    "pass": _VM_NET, "pass_index": scope_index({"nic": [_nic(nsg=False)], "nsg": [_nsg(nsg_rule("web", "Tcp", "Internet", "443"), subnets=[SUBNET_ID])]}),
    "fail": _VM_NET, "fail_index": scope_index({"nic": [_nic(nsg=False)], "nsg": [_nsg(nsg_rule("dns", "Udp", "*", "50-60"), subnets=[SUBNET_ID])]}),
    "missing": {}}


# --- VM protection facts from subscription-scoped inventories --------------------------------------------

@claude("vm_jit_access", "vm", "VM is covered by a Defender for Cloud just-in-time network access policy", control="AC-17",
        dependencies=["vm", "jit_network_access_policy"],
        remediation="Enable just-in-time VM access in Defender for Cloud for management ports on this VM.")
def vm_jit_access(item, index):
    vm_id = _lower_id(get(item, "id", str))
    covered = []
    for policy in scoped(index, "jit_network_access_policy"):
        for vm in list_of_objects(get(policy, "properties.virtualMachines", list)):
            if _lower_id(get(vm, "id", str)) == vm_id:
                covered.append(policy.get("name"))
    return result(not covered, jit_policies=covered)
_JIT = lambda vm: {"name": "default", "properties": {"virtualMachines": [{"id": vm, "ports": [{"number": 22}]}]}}
CASES[cid("vm_jit_access")] = {"pass": {"id": "/VM1"}, "pass_index": scope_index({"jit_network_access_policy": [_JIT("/vm1")]}),
                               "fail": {"id": "/vm1"}, "fail_index": scope_index({"jit_network_access_policy": [_JIT("/vm2")]}),
                               "missing": {}}


@claude("vm_site_recovery_enabled", "vm", "VM is protected by Azure Site Recovery (ASR-Protect resource link)", control="CP-10",
        dependencies=["vm", "resource_link"],
        remediation="Enable disaster recovery for the VM with Azure Site Recovery replication to a secondary region.")
def vm_site_recovery_enabled(item, index):
    vm_id = _lower_id(get(item, "id", str))
    links = []
    for link in scoped(index, "resource_link"):
        name = get(link, "name", str)
        if name.startswith("ASR-Protect-") and _lower_id(get(link, "properties.sourceId", str)) == vm_id:
            links.append(name)
    return result(not links, asr_links=links)
_LINK = lambda name: {"name": name, "properties": {"sourceId": "/vm1/", "targetId": "/vault"}}
CASES[cid("vm_site_recovery_enabled")] = {"pass": {"id": "/vm1"}, "pass_index": scope_index({"resource_link": [_LINK("ASR-Protect-vm1")]}),
                                          "fail": {"id": "/vm1"}, "fail_index": scope_index({"resource_link": [_LINK("other")]}),
                                          "missing": {}}


def _backup_items(item, index):
    vm_id = _lower_id(get(item, "id", str))
    return [row for row in scoped(index, "backup_protected_item")
            if get(row, "properties.workloadType", str) == "VM" and _lower_id(get(row, "properties.sourceResourceId", str)) == vm_id]


@claude("vm_backup_protected", "vm", "VM is protected by Azure Backup in a Recovery Services vault", severity="high", control="CP-9",
        dependencies=["vm", "backup_protected_item"],
        remediation="Enable Azure Backup for the VM in a Recovery Services vault with an approved backup policy.")
def vm_backup_protected(item, index):
    items = _backup_items(item, index)
    return result(not items, protected_items=[row.get("name") for row in items])
_BI = lambda vm, policy="/policy1": {"name": "VM;iaasvmcontainerv2;rg;vm1", "properties": {"workloadType": "VM", "sourceResourceId": vm, "policyId": policy}}
CASES[cid("vm_backup_protected")] = {"pass": {"id": "/vm1"}, "pass_index": scope_index({"backup_protected_item": [_BI("/vm1")]}),
                                     "fail": {"id": "/vm1"}, "fail_index": scope_index({"backup_protected_item": [_BI("/vm2")]}),
                                     "missing": {}}

MIN_DAILY_RETENTION = 7


@claude("vm_backup_daily_retention_7_days", "vm", "VM backup policy retains daily recovery points for at least 7 days",
        control="CP-9", dependencies=["vm", "backup_protected_item", "backup_policy"],
        remediation="Set the VM backup policy daily retention to at least 7 days (retentionPolicy.dailySchedule.retentionDuration).")
def vm_backup_daily_retention(item, index):
    items = _backup_items(item, index)
    if not items:
        return "NOT_APPLICABLE", {"reason": "VM is not protected by Azure Backup"}
    if len(items) != 1:
        raise Unavailable("ambiguous VM backup protected-item match")
    policy_id = _lower_id(get(items[0], "properties.policyId", str))
    policies = [p for p in scoped(index, "backup_policy") if _lower_id(get(p, "id", str)) == policy_id]
    if len(policies) != 1:
        raise Unavailable("backup policy not in the collected policy inventory")
    retention = get(policies[0], "properties.retentionPolicy", dict)
    if retention.get("dailySchedule") is None:
        return "NOT_APPLICABLE", {"reason": "backup policy has no daily retention schedule"}
    duration = get(retention, "dailySchedule.retentionDuration", dict)
    if get(duration, "durationType", str) != "Days":
        raise Unavailable("unrecognized daily retention duration type")
    days = get(duration, "count", int)
    return result(days < MIN_DAILY_RETENTION, retention_days=days, minimum=MIN_DAILY_RETENTION)
_BP = lambda days: {"id": "/policy1", "properties": {"backupManagementType": "AzureIaasVM", "retentionPolicy": {
    "retentionPolicyType": "LongTermRetentionPolicy", "dailySchedule": {"retentionDuration": {"count": days, "durationType": "Days"}}}}}
CASES[cid("vm_backup_daily_retention_7_days")] = {
    "pass": {"id": "/vm1"}, "pass_index": scope_index({"backup_protected_item": [_BI("/vm1")], "backup_policy": [_BP(30)]}),
    "fail": {"id": "/vm1"}, "fail_index": scope_index({"backup_protected_item": [_BI("/vm1")], "backup_policy": [_BP(5)]}),
    "missing": {}}


# --- Virtual machine scale sets ------------------------------------------------------------------------

VMSS_PROFILE = "properties.virtualMachineProfile."

setting("vmss_automatic_upgrade_mode", "vm_scale_set", "properties.upgradePolicy.mode", "Automatic", ("Manual", "Rolling"),
        "VM scale set upgrade policy mode is Automatic", severity="low", control="SI-2",
        remediation="Set the scale set upgradePolicy.mode to Automatic (and enable automatic OS image upgrades where supported).")
setting("vmss_boot_diagnostics", "vm_scale_set", VMSS_PROFILE + "diagnosticsProfile.bootDiagnostics.enabled", True, False,
        "VM scale set enables boot diagnostics", severity="low", control="AU-12", expected=bool,
        remediation="Enable boot diagnostics in the scale set virtualMachineProfile.diagnosticsProfile.")


@claude("vmss_linux_ssh_keys", "vm_scale_set", "Linux VM scale set disables SSH password authentication", severity="high",
        control="IA-5", remediation="Set linuxConfiguration.disablePasswordAuthentication true in the scale set osProfile and use SSH keys.")
def vmss_linux_ssh_keys(item, index):
    os_type = _os_type(item, VMSS_PROFILE + "storageProfile.osDisk.osType")
    if os_type != "Linux":
        return "NOT_APPLICABLE", {"os_type": os_type}
    disabled = get(item, VMSS_PROFILE + "osProfile.linuxConfiguration.disablePasswordAuthentication", bool)
    return result(not disabled, password_authentication_disabled=disabled)
_ss = lambda os_type, disabled: {"properties": {"virtualMachineProfile": {"storageProfile": {"osDisk": {"osType": os_type}},
                                                                         "osProfile": {"linuxConfiguration": {"disablePasswordAuthentication": disabled}}}}}
CASES[cid("vmss_linux_ssh_keys")] = {"pass": _ss("Linux", True), "fail": _ss("Linux", False), "missing": {},
                                     "not_applicable": _ss("Windows", False), "malformed": _ss("Linux", "no")}


@claude("vmss_managed_disks", "vm_scale_set", "VM scale set OS and data disks use managed disks",
        remediation="Recreate the scale set with managed OS and data disks instead of vhdContainers storage accounts.")
def vmss_managed_disks(item, index):
    os_disk = get(item, VMSS_PROFILE + "storageProfile.osDisk", dict)
    if os_disk.get("vhdContainers"):
        return result(True, unmanaged_os_disk=True)
    if not isinstance(os_disk.get("managedDisk"), dict):
        raise Unavailable("scale set OS disk storage type was not collected")
    storage = get(item, VMSS_PROFILE + "storageProfile", dict)
    data_disks = list_of_objects(storage.get("dataDisks", []))
    if any(not isinstance(d.get("managedDisk"), dict) for d in data_disks):
        raise Unavailable("scale set data disk storage type was not collected")
    return result(False, data_disk_count=len(data_disks))
_vd = lambda os_disk: {"properties": {"virtualMachineProfile": {"storageProfile": {"osDisk": os_disk, "dataDisks": []}}}}
CASES[cid("vmss_managed_disks")] = {"pass": _vd({"managedDisk": {"storageAccountType": "Premium_LRS"}}),
                                    "fail": _vd({"vhdContainers": ["https://sa.blob.core.windows.net/vhds"]}), "missing": {},
                                    "malformed": _vd({"name": "os"})}


@claude("vmss_load_balancer_backend", "vm_scale_set", "VM scale set NICs are associated with a load balancer backend pool",
        control="CP-10", remediation="Associate the scale set IP configurations with a Standard Load Balancer backend pool.")
def vmss_load_balancer_backend(item, index):
    pools = []
    configs = list_of_objects(get(item, VMSS_PROFILE + "networkProfile.networkInterfaceConfigurations", list))
    for nic in configs:
        for ip in list_of_objects(get(nic, "properties.ipConfigurations", list)):
            refs = _omitted(ip, "properties", "loadBalancerBackendAddressPools", "subnet", [])
            pools.extend(get(ref, "id", str) for ref in list_of_objects(refs))
    return result(not pools, backend_pools=pools)
_lb = lambda pools: {"properties": {"virtualMachineProfile": {"networkProfile": {"networkInterfaceConfigurations": [
    {"name": "n", "properties": {"ipConfigurations": [{"name": "i", "properties": {"subnet": {"id": "/s"}, **pools}}]}}]}}}}
CASES[cid("vmss_load_balancer_backend")] = {"pass": _lb({"loadBalancerBackendAddressPools": [{"id": "/lb/pool"}]}), "fail": _lb({}),
                                            "missing": {}, "malformed": _lb({"loadBalancerBackendAddressPools": [{"id": 1}]})}


@claude("vmss_not_empty", "vm_scale_set", "VM scale set declares nonzero capacity", control="CM-8",
        remediation="Decommission empty scale sets or scale them to the intended capacity.")
def vmss_not_empty(item, index):
    capacity = get(item, "sku.capacity", int)
    if capacity < 0:
        raise Unavailable("malformed scale set capacity")
    return result(capacity == 0, capacity=capacity)
CASES[cid("vmss_not_empty")] = {"pass": {"sku": {"capacity": 2}}, "fail": {"sku": {"capacity": 0}}, "missing": {},
                                "malformed": {"sku": {"capacity": "2"}}}


# --- Container instances --------------------------------------------------------------------------------

@claude("container_group_cmk", "container_group", "Container group encrypts deployment data with a customer-managed key",
        control="SC-28", remediation="Redeploy the container group with encryptionProperties (vaultBaseUrl, keyName, keyVersion).")
def container_group_cmk(item, index):
    props = get(item, "properties", dict)
    if "encryptionProperties" not in props:
        raise Unavailable("container group encryptionProperties not collected (GET containerGroups)")
    encryption = props["encryptionProperties"]
    if encryption is None:
        return result(True, customer_key_configured=False, encryption_properties=None)
    vault, key = get(encryption, "vaultBaseUrl"), get(encryption, "keyName")
    configured = bool(isinstance(vault, str) and vault and isinstance(key, str) and key)
    return result(not configured, customer_key_configured=configured, key_name=key)
CASES[cid("container_group_cmk")] = {"pass": {"properties": {"encryptionProperties": {"vaultBaseUrl": "https://kv.vault.azure.net", "keyName": "k", "keyVersion": "1"}}},
                                     "fail": {"properties": {"encryptionProperties": None}}, "missing": {},
                                     "malformed": {"properties": {"encryptionProperties": {"keyName": "k"}}}}


@claude("container_group_managed_identity", "container_group", "Container group uses a managed identity", severity="low",
        control="IA-2", remediation="Assign a system- or user-assigned managed identity to the container group instead of embedded credentials.")
def container_group_managed_identity(item, index):
    get(item, "properties.containers", list)
    parts = _identity_parts(item)
    return result(not parts, identity_types=sorted(parts))
_cg = lambda **extra: {"properties": {"containers": []}, **extra}
CASES[cid("container_group_managed_identity")] = {"pass": _cg(identity={"type": "SystemAssigned"}), "fail": _cg(identity={"type": "None"}),
                                                  "missing": {}, "malformed": _cg(identity={"type": "Weird"})}


@claude("container_group_virtual_network", "container_group", "Container group is deployed into a virtual network subnet",
        control="SC-7", category="network",
        remediation="Deploy the container group into a delegated VNet subnet (subnetIds) instead of a public IP.")
def container_group_virtual_network(item, index):
    props = get(item, "properties", dict)
    if "subnetIds" not in props:
        raise Unavailable("container group subnetIds not collected (GET containerGroups)")
    subnets = props["subnetIds"]
    if subnets is None:
        return result(True, subnet_ids=[])
    ids = [get(s, "id", str) for s in list_of_objects(subnets)]
    return result(not ids, subnet_ids=ids)
CASES[cid("container_group_virtual_network")] = {"pass": {"properties": {"subnetIds": [{"id": "/subnet"}]}},
                                                 "fail": {"properties": {"subnetIds": []}}, "missing": {},
                                                 "malformed": {"properties": {"subnetIds": "x"}}}


@claude("container_group_secure_environment_variables", "container_group",
        "Container group environment variables use secureValue instead of plain value", severity="high", control="SC-28",
        remediation="Move sensitive container environment variables to secureValue, Key Vault references or mounted secrets.")
def container_group_secure_environment_variables(item, index):
    plain = []
    for container in list_of_objects(get(item, "properties.containers", list)):
        props = get(container, "properties", dict)
        for variable in list_of_objects(props.get("environmentVariables", [])):
            name = get(variable, "name", str)
            if variable.get("value") is not None:
                plain.append(name)
    return result(bool(plain), plain_value_variables=plain, values_redacted=True)
_env = lambda var: {"properties": {"containers": [{"name": "c", "properties": {"environmentVariables": [var]}}]}}
CASES[cid("container_group_secure_environment_variables")] = {"pass": _env({"name": "TOKEN", "secureValue": None}),
                                                              "fail": _env({"name": "MODE", "value": "x"}), "missing": {},
                                                              "malformed": _env({"value": "x"})}


# --- Container registry ---------------------------------------------------------------------------------

setting("acr_admin_user_disabled", "container_registry", "properties.adminUserEnabled", False, True,
        "Container registry disables the admin user", severity="high", control="AC-6", expected=bool,
        remediation="Disable the registry admin user and use Entra identities, scoped tokens or managed identities.")
setting("acr_cmk", "container_registry", "properties.encryption.status", "enabled", "disabled",
        "Container registry is encrypted with a customer-managed key", control="SC-28",
        remediation="Create Premium registries with a customer-managed key (encryption.keyVaultProperties) and a managed identity.")
setting("acr_public_network_access_disabled", "container_registry", "properties.publicNetworkAccess", "Disabled", "Enabled",
        "Container registry disables public network access", severity="high", control="SC-7",
        remediation="Set publicNetworkAccess Disabled and access the registry through private endpoints.")
setting("acr_network_default_deny", "container_registry", "properties.networkRuleSet.defaultAction", "Deny", "Allow",
        "Container registry network rule set denies by default", control="SC-7",
        remediation="Set the Premium registry networkRuleSet.defaultAction to Deny with explicit IP/VNet rules.")
for _slug, _policy, _sev, _ctl, _rem in (
        ("acr_quarantine_policy", "quarantinePolicy", "low", "SI-7", "Enable the registry quarantine policy so images are scanned before being served."),
        ("acr_retention_policy", "retentionPolicy", "low", "CM-6", "Enable the retention policy for untagged manifests."),
        ("acr_trust_policy", "trustPolicy", "medium", "SI-7", "Enable content trust (trustPolicy) for signed images.")):
    setting(_slug, "container_registry", "properties.policies." + _policy + ".status", "enabled", "disabled",
            "Container registry enables " + _policy, severity=_sev, control=_ctl, remediation=_rem)


@claude("acr_geo_replication", "container_registry", "Premium container registry is geo-replicated to more than one region",
        severity="low", control="CP-10", remediation="Add at least one geo-replication to the Premium registry.")
def acr_geo_replication(item, index):
    sku = get(item, "sku.name", str)
    if sku not in ("Basic", "Standard", "Premium", "Classic"):
        raise Unavailable("unrecognized registry SKU")
    if sku != "Premium":
        return "NOT_APPLICABLE", {"sku": sku}
    regions = [get(r, "location", str) for r in list_of_objects(get(item, "replications", list))]
    return result(len(regions) <= 1, replication_regions=regions)
_acr = lambda sku, regions: {"sku": {"name": sku}, "replications": [{"location": r} for r in regions]}
CASES[cid("acr_geo_replication")] = {"pass": _acr("Premium", ["eastus", "westeurope"]), "fail": _acr("Premium", ["eastus"]),
                                     "not_applicable": _acr("Standard", []), "missing": {"sku": {"name": "Premium"}},
                                     "malformed": _acr("Weird", [])}


@claude("acr_vnet_service_endpoint", "container_registry", "Container registry declares a VNet rule with deny-by-default network rules",
        control="SC-7", category="network",
        remediation="Set networkRuleSet.defaultAction Deny and add virtualNetworkRules (or prefer private endpoints).")
def acr_vnet_service_endpoint(item, index):
    action = enum(item, "properties.networkRuleSet.defaultAction", ("Allow", "Deny"))
    if action != "Deny":
        return result(True, default_action=action)
    rules = [get(r, "id", str) for r in list_of_objects(get(item, "properties.networkRuleSet.virtualNetworkRules", list))]
    return result(not rules, default_action=action, virtual_network_rules=rules)
_nr = lambda action, rules: {"properties": {"networkRuleSet": {"defaultAction": action, "virtualNetworkRules": [{"id": r} for r in rules]}}}
CASES[cid("acr_vnet_service_endpoint")] = {"pass": _nr("Deny", ["/subnet"]), "fail": _nr("Deny", []), "fail_allow": _nr("Allow", ["/subnet"]),
                                           "missing": {}, "malformed": _nr("Maybe", [])}


@claude("acr_private_link_approved", "container_registry", "Container registry has an approved private endpoint connection",
        control="SC-7", category="network", remediation="Create and approve a private endpoint connection for the registry.")
def acr_private_link_approved(item, index):
    states = private_link_states(item)
    return result("Approved" not in states, connection_states=states)
CASES[cid("acr_private_link_approved")] = {"pass": approved_private_link_case(), "fail": {"properties": {"privateEndpointConnections": []}},
                                           "missing": {}}


def _private_endpoint_rule(slug, kind, title, proof, severity):
    @claude(slug, kind, title, severity=severity, control="SC-7", category="network",
            remediation="Create a private endpoint for the resource so clients reach it over Private Link.")
    def evaluate(item, index):
        connections = list_of_objects(_omitted(item, "properties", "privateEndpointConnections", proof, []) or [])
        endpoints = [get(c, "properties.privateEndpoint.id", str) for c in connections]
        return result(not endpoints, private_endpoints=endpoints)
    evaluate.__name__ = "claude_" + slug
    conn = {"properties": {"privateEndpoint": {"id": "/pe"}, "privateLinkServiceConnectionState": {"status": "Pending"}}}
    CASES[cid(slug)] = {"pass": {"properties": {proof: "x", "privateEndpointConnections": [conn]}},
                        "fail": {"properties": {proof: "x", "privateEndpointConnections": []}},
                        "missing": {}, "unproven": {"properties": {}},
                        "malformed": {"properties": {proof: "x", "privateEndpointConnections": [{"properties": {}}]}}}


_private_endpoint_rule("acr_private_endpoint_present", "container_registry", "Container registry has a private endpoint connection",
                       "loginServer", "high")


# --- Cosmos DB ------------------------------------------------------------------------------------------

COSMOS_PNA = ("Enabled", "Disabled", "SecuredByPerimeter")
setting("cosmos_public_network_access_disabled", "cosmos_account", "properties.publicNetworkAccess", "Disabled",
        ("Enabled", "SecuredByPerimeter"), "Cosmos DB account disables public network access", severity="high", control="SC-7",
        remediation="Set publicNetworkAccess Disabled and use private endpoints.")
setting("cosmos_public_network_access_restricted", "cosmos_account", "properties.publicNetworkAccess", ("Disabled", "SecuredByPerimeter"),
        "Enabled", "Cosmos DB account public network access is Disabled or SecuredByPerimeter", control="SC-7",
        remediation="Set publicNetworkAccess Disabled (or SecuredByPerimeter with a network security perimeter).")
setting("cosmos_automatic_failover", "cosmos_account", "properties.enableAutomaticFailover", True, False,
        "Cosmos DB account enables service-managed failover", control="CP-10", expected=bool,
        remediation="Enable service-managed (automatic) failover with at least one secondary region.")
setting("cosmos_continuous_backup", "cosmos_account", "properties.backupPolicy.type", "Continuous", "Periodic",
        "Cosmos DB account uses continuous backup", control="CP-9",
        remediation="Migrate the account backup policy to Continuous for point-in-time restore.")
setting("cosmos_virtual_network_filter", "cosmos_account", "properties.isVirtualNetworkFilterEnabled", True, False,
        "Cosmos DB account firewall uses selected networks (virtual network filter enabled)", control="SC-7", expected=bool,
        remediation="Enable isVirtualNetworkFilterEnabled and allow only selected virtual networks.")
setting("cosmos_key_based_metadata_write_disabled", "cosmos_account", "properties.disableKeyBasedMetadataWriteAccess", True, False,
        "Cosmos DB account disables key-based metadata write access", control="AC-6", expected=bool,
        remediation="Set disableKeyBasedMetadataWriteAccess true so control-plane changes require Azure RBAC.")
setting("cosmos_local_auth_disabled", "cosmos_account", "properties.disableLocalAuth", True, False,
        "Cosmos DB account disables local (key) authentication and uses Entra ID with RBAC", severity="high", control="IA-2",
        expected=bool, remediation="Set disableLocalAuth true and grant data-plane access with Cosmos DB RBAC role assignments.")
setting("cosmos_minimum_tls12", "cosmos_account", "properties.minimalTlsVersion", ("Tls12", "Tls13"), ("Tls", "Tls11"),
        "Cosmos DB account requires TLS 1.2 or later", control="SC-8",
        remediation="Set minimalTlsVersion to Tls12.")


@claude("cosmos_cmk", "cosmos_account", "Cosmos DB account encrypts data at rest with a customer-managed key", control="SC-28",
        remediation="Configure keyVaultKeyUri with a Key Vault key (set at account creation).")
def cosmos_cmk(item, index):
    uri = _omitted(item, "properties", "keyVaultKeyUri", "databaseAccountOfferType")
    if uri is not None and (not isinstance(uri, str) or not uri):
        raise Unavailable("malformed keyVaultKeyUri")
    return result(uri is None, key_vault_key_uri_present=uri is not None)
CASES[cid("cosmos_cmk")] = {"pass": {"properties": {"databaseAccountOfferType": "Standard", "keyVaultKeyUri": "https://kv.vault.azure.net/keys/k"}},
                            "fail": {"properties": {"databaseAccountOfferType": "Standard"}}, "missing": {},
                            "unproven": {"properties": {}}, "malformed": {"properties": {"keyVaultKeyUri": 5}}}


@claude("cosmos_cors_no_wildcard", "cosmos_account", "Cosmos DB account CORS does not allow any origin (*)", severity="high",
        control="SC-7", category="exposure", remediation="Replace wildcard CORS allowedOrigins with explicit trusted origins.")
def cosmos_cors_no_wildcard(item, index):
    wildcard = []
    for rule in list_of_objects(get(item, "properties.cors", list)):
        origins = get(rule, "allowedOrigins", str)
        if "*" in [o.strip() for o in origins.split(",")]:
            wildcard.append(origins)
    return result(bool(wildcard), wildcard_rules=wildcard)
CASES[cid("cosmos_cors_no_wildcard")] = {"pass": {"properties": {"cors": [{"allowedOrigins": "https://app.example.com"}]}},
                                         "fail": {"properties": {"cors": [{"allowedOrigins": "*"}]}}, "missing": {},
                                         "malformed": {"properties": {"cors": [{"allowedOrigins": ["*"]}]}}}


@claude("cosmos_network_restricted", "cosmos_account", "Cosmos DB account with public access restricts networks with firewall or VNet rules",
        severity="high", control="SC-7", category="exposure",
        remediation="Disable public network access or add IP firewall rules / enable the virtual network filter.")
def cosmos_network_restricted(item, index):
    access = enum(item, "properties.publicNetworkAccess", COSMOS_PNA)
    if access != "Enabled":
        return result(False, public_network_access=access)
    vnet_filter = get(item, "properties.isVirtualNetworkFilterEnabled", bool)
    ip_rules = list_of_objects(get(item, "properties.ipRules", list))
    return result(not vnet_filter and not ip_rules, public_network_access=access, virtual_network_filter=vnet_filter,
                  ip_rule_count=len(ip_rules))
_cn = lambda access, vnet, rules: {"properties": {"publicNetworkAccess": access, "isVirtualNetworkFilterEnabled": vnet,
                                                  "ipRules": [{"ipAddressOrRange": r} for r in rules]}}
CASES[cid("cosmos_network_restricted")] = {"pass": _cn("Enabled", False, ["203.0.113.4"]), "pass_disabled": _cn("Disabled", False, []),
                                           "fail": _cn("Enabled", False, []), "missing": {}, "malformed": _cn("Odd", False, [])}


@claude("cosmos_vnet_service_endpoint", "cosmos_account", "Cosmos DB account has virtual network service-endpoint rules",
        control="SC-7", category="network", remediation="Add virtualNetworkRules for the subnets that should reach the account.")
def cosmos_vnet_service_endpoint(item, index):
    rules = [get(r, "id", str) for r in list_of_objects(get(item, "properties.virtualNetworkRules", list))]
    return result(not rules, virtual_network_rules=rules)
CASES[cid("cosmos_vnet_service_endpoint")] = {"pass": {"properties": {"virtualNetworkRules": [{"id": "/subnet"}]}},
                                              "fail": {"properties": {"virtualNetworkRules": []}}, "missing": {},
                                              "malformed": {"properties": {"virtualNetworkRules": [{"id": 1}]}}}

_private_endpoint_rule("cosmos_private_endpoint_present", "cosmos_account", "Cosmos DB account has a private endpoint connection",
                       "databaseAccountOfferType", "high")


# --- Data Box Edge / Azure Stack Edge -------------------------------------------------------------------

DOUBLE_ENCRYPTION_SKUS = ("TEA_1Node", "TEA_1Node_UPS", "TEA_1Node_Heater", "TEA_1Node_UPS_Heater", "TEA_4Node_Heater",
                          "TEA_4Node_UPS_Heater", "TMA", "EdgePR_Base", "EdgePR_Base_UPS", "EdgeMR_Mini")


@claude("databox_edge_double_encryption", "databox_edge_device", "Azure Stack Edge device SKU supports double encryption at rest",
        control="SC-28", remediation="Use an Azure Stack Edge Pro/Mini R SKU that provides double encryption for data at rest.")
def databox_edge_double_encryption(item, index):
    sku = get(item, "sku.name", str)
    return result(sku not in DOUBLE_ENCRYPTION_SKUS, sku=sku)
CASES[cid("databox_edge_double_encryption")] = {"pass": {"sku": {"name": "EdgePR_Base"}}, "fail": {"sku": {"name": "Edge"}},
                                                "missing": {}, "malformed": {"sku": {"name": 1}}}


# --- Databricks -----------------------------------------------------------------------------------------

@claude("databricks_managed_disk_cmk", "databricks_workspace", "Databricks workspace encrypts managed disks with a customer-managed key",
        severity="high", control="SC-28",
        remediation="Configure encryption.entities.managedDisk with Key Vault key properties on a Premium workspace.")
def databricks_managed_disk_cmk(item, index):
    encryption = _omitted(item, "properties", "encryption", "managedResourceGroupId")
    if encryption is None:
        return result(True, encryption=None)
    entities = get(encryption, "entities", dict)
    disk = entities.get("managedDisk")
    if disk is None:
        return result(True, managed_disk_encryption=None)
    key = get(disk, "keyVaultProperties", dict)
    return result(not key, key_properties_present=bool(key), key_vault_uri=key.get("keyVaultUri"))
_dbx = lambda entities: {"properties": {"managedResourceGroupId": "/rg", "encryption": {"entities": entities}}}
CASES[cid("databricks_managed_disk_cmk")] = {
    "pass": _dbx({"managedDisk": {"keySource": "Microsoft.Keyvault", "keyVaultProperties": {"keyVaultUri": "https://kv", "keyName": "k", "keyVersion": "1"}}}),
    "fail": _dbx({"managedServices": {"keySource": "Microsoft.Keyvault"}}), "fail_omitted": {"properties": {"managedResourceGroupId": "/rg"}},
    "missing": {}, "unproven": {"properties": {}}, "malformed": _dbx({"managedDisk": {"keyVaultProperties": "x"}})}

DATABRICKS_LOG_CATEGORIES = ("clusters", "accounts", "jobs", "notebook", "workspace", "sqlPermissions")


@claude("databricks_diagnostic_log_delivery", "databricks_workspace",
        "Premium Databricks workspace delivers clusters, accounts, jobs, notebook, workspace and sqlPermissions logs",
        control="AU-2", remediation="Create a diagnostic setting that enables the clusters, accounts, jobs, notebook, workspace and sqlPermissions categories.")
def databricks_diagnostic_log_delivery(item, index):
    sku = enum(item, "sku.name", ("standard", "premium", "trial"))
    if sku != "premium":
        return "NOT_APPLICABLE", {"sku": sku}
    enabled = set()
    for setting_item in diagnostic_settings(item):
        for log in diagnostic_logs(setting_item):
            if get(log, "enabled", bool):
                if log.get("categoryGroup") == "allLogs":
                    enabled |= set(DATABRICKS_LOG_CATEGORIES)
                elif isinstance(log.get("category"), str):
                    enabled.add(log["category"])
    missing = [c for c in DATABRICKS_LOG_CATEGORIES if c not in enabled]
    return result(bool(missing), missing_categories=missing)
_dd = lambda sku, *logs: {"sku": {"name": sku}, **diag_case(*logs)}
CASES[cid("databricks_diagnostic_log_delivery")] = {
    "pass": _dd("premium", *[diag_log(c) for c in DATABRICKS_LOG_CATEGORIES]),
    "pass_group": _dd("premium", diag_log(group="allLogs")),
    "fail": _dd("premium", diag_log("clusters"), diag_log("jobs", enabled=False)),
    "not_applicable": _dd("standard"), "missing": {"sku": {"name": "premium"}}, "malformed": _dd("enterprise")}


@claude("databricks_subnet_nsg", "databricks_workspace", "VNet-injected Databricks workspace subnets have an NSG",
        control="SC-7", category="network", dependencies=["databricks_workspace", "vnet"],
        remediation="Associate a network security group with both Databricks host (public) and container (private) subnets.")
def databricks_subnet_nsg(item, index):
    import re

    params = get(item, "properties.parameters", dict)
    if params.get("customVirtualNetworkId") is None:
        return "NOT_APPLICABLE", {"reason": "workspace uses the Databricks-managed virtual network"}
    vnet_id = _lower_id(get(params, "customVirtualNetworkId.value", str))
    names = [get(params, key + ".value", str) for key in ("customPrivateSubnetName", "customPublicSubnetName")]
    if any(not name.strip() for name in names) or names[0].casefold() == names[1].casefold():
        raise Unavailable("workspace private and public subnet names are missing or ambiguous")
    vnets = [v for v in scoped(index, "vnet") if _lower_id(get(v, "id", str)) == vnet_id]
    if len(vnets) != 1:
        raise Unavailable("workspace virtual network not in the collected VNet inventory")
    subnets = {}
    for subnet in list_of_objects(get(vnets[0], "properties.subnets", list)):
        name = get(subnet, "name", str).casefold()
        sid = _lower_id(get(subnet, "id", str))
        if not name or name in subnets or sid != vnet_id + "/subnets/" + name:
            raise Unavailable("foreign, duplicate or contradictory Databricks subnet identity")
        subnets[name] = subnet
    without = []
    for name in names:
        if name.casefold() not in subnets:
            raise Unavailable("workspace subnet not in the collected VNet subnets")
        association = _omitted(subnets[name.casefold()], "properties", "networkSecurityGroup", "addressPrefix")
        if association is None:
            without.append(name)
        else:
            nsg_id = _lower_id(get(association, "id", str))
            subscription = "/".join(vnet_id.split("/")[:3])
            if not re.fullmatch(re.escape(subscription) + r"/resourcegroups/[^/?#]+/providers/microsoft\.network/networksecuritygroups/[^/?#]+", nsg_id):
                raise Unavailable("invalid or foreign Databricks subnet NSG reference")
    return result(bool(without), subnets=names, subnets_without_nsg=without)
_DBX_VNET = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/dbx"
_dbx_ws = {"properties": {"parameters": {"customVirtualNetworkId": {"value": _DBX_VNET}, "customPrivateSubnetName": {"value": "priv"},
                                         "customPublicSubnetName": {"value": "pub"}}}}
_DBX_NSG = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/dbx-nsg"
_sub = lambda name, nsg: {"id": _DBX_VNET + "/subnets/" + name, "name": name,
                          "properties": {"addressPrefix": "10.0.0.0/24", **({"networkSecurityGroup": {"id": _DBX_NSG}} if nsg else {})}}
CASES[cid("databricks_subnet_nsg")] = {
    "pass": _dbx_ws, "pass_index": scope_index({"vnet": [{"id": _DBX_VNET, "properties": {"subnets": [_sub("priv", True), _sub("pub", True)]}}]}),
    "fail": _dbx_ws, "fail_index": scope_index({"vnet": [{"id": _DBX_VNET, "properties": {"subnets": [_sub("priv", True), _sub("pub", False)]}}]}),
    "not_applicable": {"properties": {"parameters": {"enableNoPublicIp": {"value": True}}}}, "missing": {}}


@claude("databricks_vnet_injection_value", "databricks_workspace",
        "Databricks workspace declares a non-empty customer-managed VNet (VNet injection)", severity="medium", control="SC-7",
        remediation="Deploy the Azure Databricks workspace into a customer-managed virtual network (VNet injection); "
                    "VNet injection is chosen at workspace creation and requires redeployment.")
def databricks_vnet_injection_value(item, index):
    parameters = get(item, "properties.parameters", dict)
    if "customVirtualNetworkId" not in parameters:
        if not parameters:
            raise Unavailable("workspace parameters not returned; cannot distinguish omission from managed VNet")
        return result(True, custom_vnet_id=None, semantics="Parameter omitted: workspace uses the Databricks-managed VNet")
    value = get(parameters, "customVirtualNetworkId.value")
    if value is not None and not isinstance(value, str):
        raise Unavailable("malformed customVirtualNetworkId value")
    return result(not value, custom_vnet_id=value, semantics="Prowler requires a truthy customVirtualNetworkId.value")


CASES[cid("databricks_vnet_injection_value")] = {
    "pass": {"properties": {"parameters": {"customVirtualNetworkId": {"type": "String", "value": "/subscriptions/s/resourceGroups/g/providers/Microsoft.Network/virtualNetworks/v"}}}},
    "fail": {"properties": {"parameters": {"customVirtualNetworkId": {"type": "String", "value": ""}}}},
    "missing": {}, "malformed": {"properties": {"parameters": {"customVirtualNetworkId": {"value": 7}}}}}


GROUP_IDS = tuple(CHECK_IDS[_FIRST:])
