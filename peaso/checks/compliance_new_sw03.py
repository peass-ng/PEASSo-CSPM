"""Signed Azure compliance predicates over complete, scoped native facts."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from urllib.parse import urlsplit
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get

IDS = ('azure.cis.legacy_vhds_encrypted',
 'azure.cis.resource_manager_delete_locks_applied_storage_accounts',
 'azure.gap.machine_learning_workspace_private_link_used',
 'azure_c5_ops_15_02b',
 'azure.cis.endpoint_protection_vms_installed',
 'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled',
 'azure.gap.compute_vm_image_builder_uses_private_link',
 'azure.gap.automation_account_encrypted_with_cmk',
 'azure.gap.stream_analytics_job_encrypted_with_cmk',
 'azure.cis.auto_provisioning_log_analytics_agent_vms',
 'azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3',
 'azure_storage_account_storage_blob_public_access_level_is_disabled_4211794')
_META = {'azure.cis.legacy_vhds_encrypted': {'resource_kind': 'storage_account',
                                     'category': 'encryption',
                                     'severity': 'high',
                                     'title': '[Legacy] Ensure that VHDs are Encrypted',
                                     'remediation_hint': 'Migrate unmanaged VHDs to managed disks; while retained, '
                                                         'enable Blob service encryption on each backing storage '
                                                         'account in Storage account > Encryption.',
                                     'spec_sha': '782daf2a0cca5ca5b5f5fcc413fa7c48776768c83de5539a36ecbec597ebc990'},
 'azure.cis.resource_manager_delete_locks_applied_storage_accounts': {'resource_kind': 'storage_account',
                                                                      'category': 'hardening',
                                                                      'severity': 'medium',
                                                                      'title': 'Ensure Azure Resource Manager Delete '
                                                                               'locks are applied to Azure Storage '
                                                                               'Accounts',
                                                                      'remediation_hint': 'Azure portal > Storage '
                                                                                          'account > Locks > Add, '
                                                                                          'choose Delete '
                                                                                          '(CanNotDelete); '
                                                                                          'alternatively apply a '
                                                                                          'suitable resource-group or '
                                                                                          'subscription lock.',
                                                                      'spec_sha': '7580aac3a6012476e3dd8169d336b4ff0816fe65929eb64203dba1869e8425e3'},
 'azure.gap.machine_learning_workspace_private_link_used': {'resource_kind': 'ml_workspace',
                                                            'category': 'network',
                                                            'severity': 'medium',
                                                            'title': 'Azure Machine Learning workspaces should use '
                                                                     'private link',
                                                            'remediation_hint': 'Azure portal > Machine Learning '
                                                                                'workspace > Networking > Private '
                                                                                'endpoint connections: create a '
                                                                                'private endpoint and approve its '
                                                                                'connection.',
                                                            'spec_sha': '7d4efbf397f021c41066a0030bf4fd8d3ebda3e035f4666945dfcdc088aeba20'},
 'azure_c5_ops_15_02b': {'resource_kind': 'activity_log',
                         'category': 'hardening',
                         'severity': 'medium',
                         'title': 'Azure Activity Log events carry a usable timestamp',
                         'remediation_hint': 'In Azure Monitor > Activity log, inspect malformed events and verify the '
                                             'collection query has a bounded time window and follows every '
                                             'continuation page.',
                         'spec_sha': 'a40dff6e15c01ef634e8850d44d4ad63c8e98453962dd3cbb7ed5053210df05c'},
 'azure.cis.endpoint_protection_vms_installed': {'resource_kind': 'virtual_machine',
                                                 'category': 'vulnerability',
                                                 'severity': 'medium',
                                                 'title': 'Ensure that the endpoint protection for all Virtual '
                                                          'Machines is installed',
                                                 'remediation_hint': 'In Defender for Cloud > Recommendations, open '
                                                                     'the endpoint protection assessment for the '
                                                                     'unhealthy VM; install or repair the approved '
                                                                     'endpoint agent and confirm that VM reports '
                                                                     'Healthy.',
                                                 'spec_sha': 'f746aca26f88aebf6f83b408f4536aaf48ac96d38a3eb5653c47c4832a77eba6'},
 'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled': {'resource_kind': 'log_analytics_cluster',
                                                                     'category': 'encryption',
                                                                     'severity': 'medium',
                                                                     'title': 'Enable infrastructure encryption for '
                                                                              'Log Analytics clusters',
                                                                     'remediation_hint': 'Azure portal > Log Analytics '
                                                                                         'dedicated clusters: enable '
                                                                                         'infrastructure encryption '
                                                                                         'where supported, or create a '
                                                                                         'double-encrypted replacement '
                                                                                         'cluster and move linked '
                                                                                         'workspaces.',
                                                                     'spec_sha': '93f62300dd7e0eb862e878d68807b367e2468436ba9828f6ba4d177636fddfcb'},
 'azure.gap.compute_vm_image_builder_uses_private_link': {'resource_kind': 'image_template',
                                                          'category': 'network',
                                                          'severity': 'medium',
                                                          'title': 'VM Image Builder uses an approved isolated build '
                                                                   'subnet',
                                                          'remediation_hint': 'Set '
                                                                              'properties.vmProfile.vnetConfig.subnetId '
                                                                              'on the image template to an approved '
                                                                              'isolated subnet; apply NSG and route '
                                                                              'controls to that subnet.',
                                                          'spec_sha': '941d9ce7ed99a7b7ed2034cfabbf550f93a282d8c8ca6167c76b9d72da73f82e'},
 'azure.gap.automation_account_encrypted_with_cmk': {'resource_kind': 'automation_account',
                                                     'category': 'encryption',
                                                     'severity': 'medium',
                                                     'title': 'Automation account encrypts with a customer-managed key',
                                                     'remediation_hint': 'Automation account > Encryption: enable a '
                                                                         'system or user-assigned managed identity, '
                                                                         'select Customer-managed key, and choose a '
                                                                         'Key Vault key with access granted to that '
                                                                         'identity.',
                                                     'spec_sha': '4d53cc4cd46d6cb003c58792cbbcc91028a3b77adfec45eec891949a199a0875'},
 'azure.gap.stream_analytics_job_encrypted_with_cmk': {'resource_kind': 'stream_analytics_job',
                                                       'category': 'encryption',
                                                       'severity': 'medium',
                                                       'title': 'Azure Stream Analytics jobs should use '
                                                                'customer-managed keys to encrypt data',
                                                       'remediation_hint': 'Configure jobStorageAccount on the Stream '
                                                                           'Analytics job and select an approved '
                                                                           'storage account using Key Vault '
                                                                           'customer-managed encryption.',
                                                       'spec_sha': '94cabf518ccef18ebb9acad05fa51300154ce978ace8e3e8376e191adf3eb2b0'},
 'azure.cis.auto_provisioning_log_analytics_agent_vms': {'resource_kind': 'defender_auto_provisioning_setting',
                                                         'category': 'logging',
                                                         'severity': 'medium',
                                                         'title': "Ensure that Auto provisioning of 'Log Analytics "
                                                                  "agent for Azure VMs' is Set to 'On'",
                                                         'remediation_hint': 'Azure portal > Defender for Cloud > '
                                                                             'Environment settings: If the legacy '
                                                                             'agent is required by the approved '
                                                                             'baseline, set '
                                                                             'autoProvisioningSettings/default '
                                                                             'autoProvision to On; otherwise retire '
                                                                             'this legacy requirement.',
                                                         'spec_sha': '8958eedb4b5a9b93625782e67202efb4e49764053f5c0d71eb6514cdcbaa59c3'},
 'azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3': {'resource_kind': 'security_pricing',
                                                                          'category': 'hardening',
                                                                          'severity': 'medium',
                                                                          'title': 'Required Defender for Cloud plans '
                                                                                   'use Standard tier',
                                                                          'remediation_hint': 'In Defender for Cloud > '
                                                                                              'Environment settings > '
                                                                                              'Defender plans, enable '
                                                                                              'Standard pricing for '
                                                                                              'each supported plan '
                                                                                              'listed in '
                                                                                              'requiredPlans.',
                                                                          'spec_sha': 'd9f0362e5d8b705dd480647b588e41c53ff2c955123706a3274e8f485987c77d'},
 'azure_storage_account_storage_blob_public_access_level_is_disabled_4211794': {'resource_kind': 'storage_account',
                                                                                'category': 'network',
                                                                                'severity': 'high',
                                                                                'title': 'Storage account network and '
                                                                                         'blob access match approved '
                                                                                         'settings',
                                                                                'remediation_hint': 'Storage account > '
                                                                                                    'Configuration and '
                                                                                                    'Networking: set '
                                                                                                    'blob public '
                                                                                                    'access, public '
                                                                                                    'network access '
                                                                                                    'and default '
                                                                                                    'network action to '
                                                                                                    'the approved '
                                                                                                    'values in '
                                                                                                    'expectedSettings.',
                                                                                'spec_sha': '222fe45d4ac3a7cf978fb27a85af9760aea2b5c1b1fa9e085ac4bb846bae6d6f'}}


def _signed(check_id, *, dependencies=None, target="resource"):
    """Register via the native wrapper, retaining the signed proposal category."""
    spec = _META[check_id]
    native_category = spec["category"] if spec["category"] in {
        "hardening", "exposure", "least_privilege", "iam_graph", "network"
    } else "hardening"
    def decorate(function):
        registered = register(check_id, "azure", native_category, spec["resource_kind"],
            spec["title"], spec["severity"], "CM-6", spec["remediation_hint"],
            target=target, dependencies=dependencies)(function)
        # The shared register helper predates signed proposal categories such as
        # encryption, logging and vulnerability. Its safe evaluator stays intact.
        if native_category != spec["category"]:
            CHECKS[-1] = replace(CHECKS[-1], category=spec["category"])
        return registered
    return decorate


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("foreign provider context")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", scope):
        raise Unavailable("subscription scope authority unavailable")
    return context, scope.casefold()


def _items(index, kind):
    _, scope = _context(index)
    collections = get(index, "collections", dict)
    envelopes = collections.get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("missing or ambiguous scoped collection: " + kind)
    envelope = get(envelopes[0], "type", str)
    if envelope != kind or get(envelopes[0], "scope", str).casefold() != scope:
        raise Unavailable("foreign collection scope: " + kind)
    status = get(envelopes[0], "status", str)
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    native = get(envelopes[0], "items", list)
    if (len(wrappers) != len(rows) or len(native) != len(rows)
            or (status == "empty") != (not rows) or rows != native):
        raise Unavailable("collection cardinality inconsistent: " + kind)
    arm_kinds = {"vm": "Microsoft.Compute/virtualMachines", "storage_account": "Microsoft.Storage/storageAccounts",
                 "ml_workspace": "Microsoft.MachineLearningServices/workspaces",
                 "log_analytics_cluster": "Microsoft.OperationalInsights/clusters",
                 "image_template": "Microsoft.VirtualMachineImages/imageTemplates",
                 "automation_account": "Microsoft.Automation/automationAccounts",
                 "stream_analytics_job": "Microsoft.StreamAnalytics/streamingjobs"}
    for wrapper, row in zip(wrappers, rows):
        if get(wrapper, "type", str) != kind or get(wrapper, "scope", str).casefold() != scope:
            raise Unavailable("foreign resource scope: " + kind)
        if get(wrapper, "data", dict) != row:
            raise Unavailable("resource projection inconsistent: " + kind)
        if kind in arm_kinds and not re.fullmatch(
                re.escape(scope) + r"/resourceGroups/[^/?#]+/providers/" + re.escape(arm_kinds[kind]) + r"/[^/?#]+",
                get(row, "id", str), re.I):
            raise Unavailable("resource identity malformed or wrong native kind: " + kind)
        if kind == "security_assessment" and not re.fullmatch(
                re.escape(scope) + r"(?:/resourceGroups/[^/?#]+/providers/[^/?#]+/[^/?#]+/[^/?#]+(?:/[^/?#]+/[^/?#]+)*)?/providers/Microsoft\.Security/assessments/[^/?#]+",
                get(row, "id", str), re.I):
            raise Unavailable("security assessment ARM identity malformed")
        if kind != "activity_log" and "id" in row and not get(row, "id", str).casefold().startswith(scope + "/"):
            raise Unavailable("foreign resource identity: " + kind)
        if kind == "activity_log" and "resourceId" in row:
            rid = get(row, "resourceId", str)
            if rid.casefold().startswith("/subscriptions/") and not rid.casefold().startswith(scope + "/"):
                raise Unavailable("foreign Activity Log resource identity")
    return rows


def _unique(rows, key="id"):
    result_by_id = {}
    for row in rows:
        identity = get(row, key, str)
        if not identity or identity.casefold() in result_by_id:
            raise Unavailable("missing or duplicate resource identity")
        result_by_id[identity.casefold()] = row
    return result_by_id


def _own(item, index, kind):
    rows = _unique(_items(index, kind))
    identity = get(item, "id", str).casefold()
    if identity not in rows or rows[identity] != item:
        raise Unavailable("resource absent or different from scoped inventory")
    _, scope = _context(index)
    if not identity.startswith(scope + "/"):
        raise Unavailable("resource outside subscription")
    return rows


def _policy(index, name):
    context, scope = _context(index)
    policy = get(context, "metadata.compliance_policy.sw03", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str).casefold() != scope:
        raise Unavailable("owner policy unavailable or foreign to subscription")
    return get(policy, name, dict)


def _scope_item(item, index):
    _, scope = _context(index)
    if get(item, "scope", str).casefold() != scope:
        raise Unavailable("foreign scope target")


def _has(item, key):
    """Inspect API omission only after rejecting a field-level failed read."""
    if not isinstance(item, dict):
        raise Unavailable("malformed fact parent")
    coverage = item.get("_coverage", {})
    if not isinstance(coverage, dict):
        raise Unavailable("malformed field coverage")
    marker = coverage.get(key)
    if marker is not None and (not isinstance(marker, dict) or marker.get("status") not in ("collected", "empty")):
        raise Unavailable("fact unavailable or malformed coverage: " + key)
    return key in item


def _utc(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp missing or malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("timestamp malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Unavailable("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _vault_uri(value):
    if not isinstance(value, str):
        raise Unavailable("Key Vault URI malformed")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise Unavailable("Key Vault URI malformed")
    return value


def _not_applicable(reason):
    return "NOT_APPLICABLE", {"reason": reason}


def _aggregate(rows, evaluate, **evidence):
    outcomes, uncertain = [], []
    for row in rows:
        try:
            status, _ = evaluate(row)
            outcomes.append(status)
        except Unavailable as exc:
            uncertain.append(str(exc))
    if "FAIL" in outcomes:
        return result(True, uncertain_resources=uncertain, **evidence)
    if uncertain or "UNKNOWN" in outcomes:
        return unknown("one or more resource observations unresolved", uncertain_resources=uncertain, **evidence)
    return result(False, **evidence)


def _ml_private_link_one(item, index):
    _own(item, index, "ml_workspace")
    workspace = get(item, "id", str)
    if get(item, "_coverage.privateEndpointConnections.status", str) not in ("collected", "empty"):
        raise Unavailable("ML private endpoint child read incomplete")
    connections = get(item, "privateEndpointConnections", list)
    if (get(item, "_coverage.privateEndpointConnections.status", str) == "empty") != (not connections):
        raise Unavailable("ML private endpoint coverage contradicts rows")
    if any(not isinstance(c, dict) for c in connections):
        raise Unavailable("malformed ML private endpoint connection")
    found = False
    seen = set()
    for connection in connections:
        identity = get(connection, "id", str)
        prefix = workspace.rstrip("/") + "/privateEndpointConnections/"
        if (not identity.casefold().startswith(prefix.casefold()) or identity.casefold() in seen
                or not re.fullmatch(r"[^/?#]+", identity[len(prefix):])):
            raise Unavailable("foreign or duplicate ML private endpoint connection")
        seen.add(identity.casefold())
        status = get(connection, "properties.privateLinkServiceConnectionState.status", str)
        if status not in ("Approved", "Pending", "Rejected", "Disconnected"):
            raise Unavailable("unrecognized ML private endpoint status")
        if status == "Approved":
            endpoint = get(connection, "properties.privateEndpoint.id", str)
            if not re.fullmatch(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\.Network/privateEndpoints/[^/?#]+", endpoint, re.I):
                raise Unavailable("approved ML connection has no valid private endpoint ID")
            found = True
    return result(not found, workspace_id=workspace, approved_connections=int(found),
        semantics="Private Link presence only; exclusive private ingress unverified")


@_signed("azure.gap.machine_learning_workspace_private_link_used", dependencies=["ml_workspace"], target="scope")
def ml_private_link(item, index):
    _scope_item(item, index)
    workspaces = _unique(_items(index, "ml_workspace"))
    if not workspaces:
        return _not_applicable("complete ML workspace inventory is empty")
    return _aggregate(workspaces.values(), lambda row: _ml_private_link_one(row, index), workspaces=len(workspaces),
        semantics="Approved Private Link presence only; exclusive private ingress unverified")


@_signed("azure.gap.monitor_log_cluster_infrastructure_encryption_enabled", dependencies=["log_analytics_cluster"], target="scope")
def log_cluster_infrastructure_encryption(item, index):
    _scope_item(item, index)
    clusters = _unique(_items(index, "log_analytics_cluster"))
    if not clusters:
        return _not_applicable("complete Logs cluster inventory is empty")
    return _aggregate(clusters.values(),
        lambda row: result(get(row, "properties.isDoubleEncryptionEnabled", bool) is False,
                           cluster_id=get(row, "id", str)), cluster_count=len(clusters))


@_signed("azure.cis.auto_provisioning_log_analytics_agent_vms",
         dependencies=["defender_auto_provisioning_setting"], target="scope")
def legacy_agent_auto_provisioning(item, index):
    _scope_item(item, index)
    if get(_policy(index, "legacyAgentBaseline"), "required", bool) is not True:
        return _not_applicable("legacy Log Analytics agent baseline is not required")
    rows = _items(index, "defender_auto_provisioning_setting")
    names = _unique(rows, "name")
    for row in rows:
        identity = get(row, "id", str)
        if identity.casefold() != (get(item, "scope", str) + "/providers/Microsoft.Security/autoProvisioningSettings/" + get(row, "name", str)).casefold():
            raise Unavailable("foreign auto provisioning setting")
    default = names.get("default")
    if default is None:
        return result(True, reason="complete settings list has no default")
    setting = get(default, "properties.autoProvision", str)
    if setting not in ("On", "Off"):
        raise Unavailable("unrecognized auto provisioning value")
    return result(setting == "Off", configured=setting)


@_signed("azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3",
         dependencies=["security_pricing"], target="scope")
def defender_required_plans(item, index):
    _scope_item(item, index)
    policy = _policy(index, "defenderPlans")
    if get(policy, "representsSecurityCenterEnablement", bool) is not True:
        raise Unavailable("selected Defender plan set does not represent frozen Security Center requirement")
    required = get(policy, "requiredPlans", list)
    supported = get(policy, "supportedPlans", list)
    if (not required or any(not isinstance(x, str) or not x for x in required + supported)
            or len(set(required)) != len(required) or len(set(supported)) != len(supported)
            or not set(required) <= set(supported)):
        raise Unavailable("required Defender plan policy unresolved")
    rows = _items(index, "security_pricing")
    plans = _unique(rows, "name")
    for row in rows:
        if get(row, "id", str).casefold() != (get(item, "scope", str) + "/providers/Microsoft.Security/pricings/" + get(row, "name", str)).casefold():
            raise Unavailable("foreign Defender pricing record")
    weak, uncertain = [], []
    for plan in required:
        record = plans.get(plan.casefold())
        if record is None:
            weak.append(plan)
            continue
        try:
            tier = get(record, "properties.pricingTier", str)
            if tier not in ("Free", "Standard"):
                raise Unavailable("unrecognized Defender pricing tier")
            if tier == "Free":
                weak.append(plan)
        except Unavailable:
            uncertain.append(plan)
    if uncertain and not weak:
        return unknown("required Defender pricing tier unresolved", uncertain_plans=uncertain)
    return result(bool(weak), required_plans=required, unsupported_or_free_plans=weak,
        uncertain_plans=uncertain,
        semantics="Configured plan tiers; tenant-wide Defender state unproven")


@_signed("azure_c5_ops_15_02b", dependencies=["activity_log"], target="scope")
def activity_timestamps(item, index):
    _scope_item(item, index)
    policy = _policy(index, "activityLogWindow")
    start, end = _utc(get(policy, "start", str)), _utc(get(policy, "end", str))
    if not start < end:
        raise Unavailable("invalid activity log query window")
    rows = _items(index, "activity_log")
    envelope = index["collections"]["activity_log"][0]
    query = get(envelope, "queryWindow", dict)
    if _utc(get(query, "start", str)) != start or _utc(get(query, "end", str)) != end or get(query, "endExclusive", bool) is not True:
        raise Unavailable("activity log collection window differs from policy")
    if not rows:
        return unknown("no Activity Log events in bounded window")
    seen = set()
    missing = []
    for row in rows:
        rid = get(row, "id", str)
        if not rid or rid in seen:
            raise Unavailable("missing or duplicate Activity Log event ID")
        seen.add(rid)
        present = False
        malformed = False
        for field in ("eventTimestamp", "submissionTimestamp"):
            if _has(row, field):
                try:
                    timestamp = _utc(get(row, field, str))
                except Unavailable:
                    malformed = True
                    continue
                # ARM filters eventTimestamp; submission can occur after the window.
                if field == "eventTimestamp" and not start <= timestamp < end:
                    raise Unavailable("Activity Log event outside verified query window")
                present = True
        if not present:
            if malformed:
                raise Unavailable("Activity Log timestamp malformed")
            missing.append(rid)
    return result(bool(missing), events=len(rows), missing_timestamp_ids=missing)


@_signed("azure.cis.endpoint_protection_vms_installed",
         dependencies=["vm", "security_assessment"], target="scope")
def vm_endpoint_protection(item, index):
    _scope_item(item, index)
    key = get(_policy(index, "endpointProtection"), "assessmentKey", str)
    if not key:
        raise Unavailable("endpoint protection assessment key unavailable")
    vms = _unique(_items(index, "vm"))
    assessments = _items(index, "security_assessment")
    if not vms:
        return _not_applicable("complete VM inventory is empty")
    observed, uncertain = {}, []
    for assessment in assessments:
        assessment_key = get(assessment, "name", str)
        if assessment_key != key:
            continue
        vm_id = get(assessment, "properties.resourceDetails.id", str).casefold()
        if vm_id not in vms:
            continue
        if vm_id in observed:
            raise Unavailable("duplicate endpoint protection assessment for VM")
        try:
            status = get(assessment, "properties.status.code", str)
            if status not in ("Healthy", "Unhealthy", "NotApplicable"):
                raise Unavailable("unrecognized endpoint protection status")
        except Unavailable:
            uncertain.append(vm_id)
            continue
        observed[vm_id] = status
    if any(status == "Unhealthy" for status in observed.values()):
        return result(True, unhealthy_vm_ids=sorted(x for x, s in observed.items() if s == "Unhealthy"),
            semantics="Current assessment state, not independent agent verification")
    if uncertain or len(observed) != len(vms) or any(status != "Healthy" for status in observed.values()):
        return unknown("VM assessment missing or NotApplicable", assessed=len(observed), vm_count=len(vms))
    return result(False, vm_count=len(vms), semantics="Every VM reports Healthy for the selected assessment key")


def _image_builder_one(item, index):
    _own(item, index, "image_template")
    policy = _policy(index, "imageBuilder")
    approved = get(policy, "approvedBuildSubnetIds", list)
    isolated = get(policy, "isolatedSubnetIds", list)
    subnet_pattern = r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\.Network/virtualNetworks/[^/?#]+/subnets/[^/?#]+"
    if (not approved or any(not isinstance(x, str) or not re.fullmatch(subnet_pattern, x, re.I) for x in approved + isolated)
            or len({x.casefold() for x in approved}) != len(approved)
            or len({x.casefold() for x in isolated}) != len(isolated)):
        raise Unavailable("approved isolated build subnet policy unavailable")
    profile = get(item, "properties.vmProfile", dict)
    vnet = get(profile, "vnetConfig", dict) if _has(profile, "vnetConfig") else None
    if vnet is None or not _has(vnet, "subnetId"):
        if get(item, "_provenance.representation", str) != "full":
            raise Unavailable("template subnet omission not proven by full GET")
        return result(True, reason="fully read template has no build subnet")
    subnet = get(vnet, "subnetId", str)
    if not re.fullmatch(subnet_pattern, subnet, re.I):
        raise Unavailable("malformed image builder subnet ID")
    if subnet.casefold() not in {x.casefold() for x in approved}:
        return result(True, configured_subnet=subnet, reason="subnet outside approved set")
    if subnet.casefold() not in {x.casefold() for x in isolated}:
        return unknown("approved subnet isolation unverified", configured_subnet=subnet)
    evidence = get(item, "_subnetIsolation", dict)
    if get(evidence, "status", str) != "collected" or get(evidence, "subnetId", str).casefold() != subnet.casefold():
        raise Unavailable("independent build subnet isolation evidence unavailable")
    if get(evidence, "isolated", bool) is not True:
        return unknown("approved build subnet is not independently verified isolated", configured_subnet=subnet)
    return result(False, configured_subnet=subnet,
        semantics="Approved isolated build subnet signal; dependency Private Link paths unverified")


@_signed("azure.gap.compute_vm_image_builder_uses_private_link", dependencies=["image_template"], target="scope")
def image_builder_subnet(item, index):
    _scope_item(item, index)
    templates = _unique(_items(index, "image_template"))
    if not templates:
        return _not_applicable("complete image template inventory is empty")
    return _aggregate(templates.values(), lambda row: _image_builder_one(row, index), templates=len(templates),
        semantics="Approved isolated build subnet signal only")


def _storage_delete_lock_one(item, index):
    _own(item, index, "storage_account")
    rid = get(item, "id", str)
    match = re.fullmatch(r"(/subscriptions/[0-9a-fA-F-]{36})/(resourceGroups/[^/]+)/providers/Microsoft\.Storage/storageAccounts/[^/]+", rid, re.I)
    if match is None:
        raise Unavailable("storage account ARM identity malformed")
    evidence = get(item, "effectiveLockChain", dict)
    if get(evidence, "status", str) != "collected" or get(evidence, "managementGroupAncestorsComplete", bool) is not True:
        raise Unavailable("effective lock ancestry incomplete")
    chain = get(evidence, "scopes", list)
    expected = [rid.casefold(), (match.group(1) + "/" + match.group(2)).casefold(), match.group(1).casefold()]
    if len(chain) < 3 or any(not isinstance(x, dict) for x in chain):
        raise Unavailable("lock chain incomplete or malformed")
    identities = [get(x, "scope", str).casefold() for x in chain]
    if identities[:3] != expected or len(set(identities)) != len(identities) or any(
        not x.startswith("/providers/microsoft.management/managementgroups/") for x in identities[3:]
    ):
        raise Unavailable("lock chain does not match storage ancestry")
    effective = []
    for scope_row in chain:
        if get(scope_row, "status", str) not in ("collected", "empty"):
            raise Unavailable("lock list incomplete for ancestor")
        locks = get(scope_row, "locks", list)
        if any(not isinstance(x, dict) for x in locks) or (scope_row["status"] == "empty") != (not locks):
            raise Unavailable("lock list malformed")
        for lock in locks:
            level = get(lock, "properties.level", str)
            if level not in ("CanNotDelete", "ReadOnly"):
                raise Unavailable("unrecognized management lock level")
            lock_id = get(lock, "id", str)
            if not re.fullmatch(re.escape(scope_row["scope"].rstrip("/")) + r"/providers/Microsoft\.Authorization/locks/[^/?#]+", lock_id, re.I):
                raise Unavailable("foreign management lock")
            effective.append(lock_id)
    return result(not effective, account_id=rid, effective_lock_ids=effective)


@_signed("azure.cis.resource_manager_delete_locks_applied_storage_accounts",
         dependencies=["storage_account"], target="scope")
def storage_delete_lock(item, index):
    _scope_item(item, index)
    accounts = _unique(_items(index, "storage_account"))
    if not accounts:
        return _not_applicable("complete storage account inventory is empty")
    return _aggregate(accounts.values(), lambda row: _storage_delete_lock_one(row, index), accounts=len(accounts))


@_signed("azure.gap.automation_account_encrypted_with_cmk", dependencies=["automation_account"])
def automation_cmk(item, index):
    _own(item, index, "automation_account")
    encryption = get(item, "properties.encryption", dict)
    source = get(encryption, "keySource", str)
    if source == "Microsoft.Automation":
        return result(True, reason="platform-managed encryption key configured")
    if source != "Microsoft.Keyvault":
        raise Unavailable("unrecognized Automation encryption key source")
    vault = get(encryption, "keyVaultProperties", dict)
    key_name = get(vault, "keyName", str)
    uri = get(vault, "keyvaultUri", str)
    if not key_name or not uri:
        return result(True, reason="complete CMK configuration lacks a usable key reference")
    _vault_uri(uri)
    selected = get(encryption, "identity", dict)
    assigned = get(item, "identity", dict)
    identity_type = get(assigned, "type", str)
    modes = {part.strip() for part in identity_type.split(",")}
    if not modes <= {"SystemAssigned", "UserAssigned", "None"} or not modes or "None" in modes and len(modes) > 1:
        raise Unavailable("unrecognized Automation identity type")
    user_identity = get(selected, "userAssignedIdentity") if _has(selected, "userAssignedIdentity") else None
    if user_identity is not None:
        if not isinstance(user_identity, str) or not user_identity:
            raise Unavailable("malformed selected user-assigned identity")
        if not re.fullmatch(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[^/?#]+", user_identity, re.I):
            raise Unavailable("selected CMK identity is not a managed identity ARM ID")
        if "UserAssigned" not in modes:
            return result(True, reason="selected CMK user identity is not assigned")
        identities = get(assigned, "userAssignedIdentities", dict)
        matches = [value for key, value in identities.items() if isinstance(key, str) and key.casefold() == user_identity.casefold()]
        if len(matches) > 1:
            raise Unavailable("ambiguous selected CMK identity")
        if not matches:
            return result(True, reason="selected CMK identity is not assigned")
        principal = get(matches[0], "principalId", str)
    else:
        if "SystemAssigned" not in modes:
            return result(True, reason="CMK system identity is not assigned")
        principal = get(assigned, "principalId", str)
    if not principal:
        raise Unavailable("selected identity principal unresolved")
    access = get(item, "_cmkKeyAccess", dict)
    if get(access, "status", str) != "collected" or get(access, "principalId", str).casefold() != principal.casefold() or get(access, "keyName", str) != key_name or get(access, "keyvaultUri", str) != uri:
        raise Unavailable("current Key Vault key access unverified")
    allowed = get(access, "usable", bool)
    return result(not allowed, key_name=key_name, principal_id=principal,
        semantics="Current selected identity and key access; rotation not assessed")


@_signed("azure.gap.stream_analytics_job_encrypted_with_cmk",
         dependencies=["stream_analytics_job"])
def stream_analytics_storage_cmk(item, index):
    _own(item, index, "stream_analytics_job")
    applicability = get(item, "_externalStorageRequirement", dict)
    if get(applicability, "status", str) != "collected":
        raise Unavailable("Stream Analytics external storage applicability unresolved")
    required = get(applicability, "required", bool)
    if not required:
        return _not_applicable("job has no private assets requiring external storage")
    accounts = _unique(_items(index, "storage_account"))
    properties = get(item, "properties", dict)
    if not _has(properties, "jobStorageAccount"):
        if (get(item, "_provenance.representation", str) != "full"
                or get(item, "_provenance.source_operation", str) != "get"
                or get(item, "_provenance.read_only", bool) is not True):
            raise Unavailable("job storage absence lacks full GET authority")
        return result(True, reason="required job storage account absent")
    job_storage = get(properties, "jobStorageAccount", dict)
    name = get(job_storage, "accountName", str)
    if not name:
        return result(True, reason="required job storage account absent")
    matches = [row for row in accounts.values() if get(row, "name", str).casefold() == name.casefold()]
    if len(matches) != 1:
        raise Unavailable("job storage account identity unresolved or ambiguous")
    account = matches[0]
    if not get(account, "id", str).casefold().startswith(get(item, "id", str).casefold().split("/resourcegroups/")[0] + "/"):
        raise Unavailable("job storage account outside scoped subscription")
    source = get(account, "properties.encryption.keySource", str)
    if source == "Microsoft.Storage":
        return result(True, storage_account_id=get(account, "id", str), reason="platform-managed key configured")
    if source != "Microsoft.Keyvault":
        raise Unavailable("unrecognized storage encryption key source")
    key = get(account, "properties.encryption.keyVaultProperties", dict)
    if not get(key, "keyName", str):
        raise Unavailable("storage CMK reference unavailable")
    _vault_uri(get(key, "keyVaultUri", str))
    access = get(account, "_cmkKeyAccess", dict)
    if get(access, "status", str) != "collected":
        raise Unavailable("storage CMK key access unverified")
    if get(access, "keyName", str) != key["keyName"] or get(access, "keyVaultUri", str) != key["keyVaultUri"]:
        raise Unavailable("storage CMK access belongs to another key")
    assigned = get(account, "identity", dict)
    selected = get(account, "properties.encryption", dict).get("identity", {})
    if not isinstance(selected, dict):
        raise Unavailable("storage encryption identity malformed")
    user_identity = get(selected, "userAssignedIdentity", str) if _has(selected, "userAssignedIdentity") else None
    modes = {part.strip() for part in get(assigned, "type", str).split(",")}
    if user_identity is not None:
        if "UserAssigned" not in modes:
            raise Unavailable("storage CMK user identity is not assigned")
        identities = get(assigned, "userAssignedIdentities", dict)
        matches = [value for rid, value in identities.items() if rid.casefold() == user_identity.casefold()]
        if len(matches) != 1:
            raise Unavailable("storage CMK identity ambiguous or unavailable")
        principal = get(matches[0], "principalId", str)
    else:
        if "SystemAssigned" not in modes:
            raise Unavailable("storage CMK system identity is not assigned")
        principal = get(assigned, "principalId", str)
    if not principal or get(access, "principalId", str).casefold() != principal.casefold():
        raise Unavailable("storage CMK access belongs to another principal")
    if get(access, "usable", bool) is False:
        return result(True, storage_account_id=get(account, "id", str), reason="configured CMK is unusable")
    return result(False, storage_account_id=get(account, "id", str),
        semantics="Job storage account CMK only; internal service data unassessed")


@_signed("azure.cis.legacy_vhds_encrypted",
         dependencies=["vm", "storage_account"], target="scope")
def unmanaged_vhd_blob_encryption(item, index):
    _scope_item(item, index)
    vms = _unique(_items(index, "vm"))
    accounts = _unique(_items(index, "storage_account"))
    uri_list, unresolved_vms = [], []
    for vm in vms.values():
        try:
            if get(vm, "_provenance.representation", str) != "full":
                raise Unavailable("VM storage profile completeness unverified")
            profile = get(vm, "properties.storageProfile", dict)
            os_disk = get(profile, "osDisk", dict)
            disks = get(profile, "dataDisks", list) if _has(profile, "dataDisks") else []
            if any(not isinstance(x, dict) for x in disks):
                raise Unavailable("malformed VM data disk")
            for disk in [os_disk, *disks]:
                if _has(disk, "vhd"):
                    uri_list.append(get(disk, "vhd.uri", str))
                elif _has(disk, "managedDisk"):
                    if not get(disk, "managedDisk.id", str).casefold().startswith(get(item, "scope", str).casefold() + "/"):
                        raise Unavailable("VM managed disk identity unresolved")
                else:
                    raise Unavailable("VM disk attachment type unresolved")
        except Unavailable as exc:
            unresolved_vms.append(str(exc))
    if not uri_list:
        if unresolved_vms:
            return unknown("VM disk attachment details unresolved", uncertain_vms=unresolved_vms)
        return _not_applicable("complete VM inventory has no unmanaged VHD")
    endpoints = {}
    for account in accounts.values():
        account_id = get(account, "id", str)
        if not account_id.casefold().startswith(get(item, "scope", str).casefold() + "/"):
            raise Unavailable("foreign storage account identity")
        endpoint = get(account, "properties.primaryEndpoints.blob", str)
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or not parsed.hostname:
            raise Unavailable("malformed storage Blob endpoint")
        origin = (parsed.scheme.casefold(), parsed.hostname.casefold(), parsed.port, parsed.path.rstrip("/"))
        if origin in endpoints:
            raise Unavailable("ambiguous Blob endpoint")
        endpoints[origin] = account
    weak, uncertain = [], list(unresolved_vms)
    for uri in uri_list:
        try:
            parsed = urlsplit(uri)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or not parsed.path.strip("/"):
                raise Unavailable("unmanaged VHD URI malformed")
            matching = [account for origin, account in endpoints.items()
                if origin[:3] == (parsed.scheme.casefold(), parsed.hostname.casefold(), parsed.port)
                and parsed.path.startswith(origin[3] + "/")]
            if len(matching) != 1:
                raise Unavailable("unmanaged VHD backing account unresolved")
            account = matching[0]
            if get(account, "properties.encryption.services.blob.enabled", bool) is False:
                weak.append(get(account, "id", str))
        except (Unavailable, ValueError) as exc:
            uncertain.append(str(exc))
    if uncertain and not weak:
        return unknown("one or more unmanaged VHDs unresolved", uncertain_vhds=uncertain)
    return result(bool(weak), unmanaged_vhd_count=len(uri_list),
        unencrypted_backing_account_ids=sorted(set(weak)), uncertain_vhds=uncertain,
        semantics="Blob service encryption for unmanaged VHD storage; guest BitLocker unassessed")


@_signed("azure_storage_account_storage_blob_public_access_level_is_disabled_4211794",
         dependencies=["storage_account"])
def storage_expected_access_settings(item, index):
    _own(item, index, "storage_account")
    policy = _policy(index, "storageAccess")
    expected = get(policy, "expectedSettings", dict)
    allowed = {"allowBlobPublicAccess", "publicNetworkAccess", "networkAcls.defaultAction"}
    if not expected or set(expected) - allowed:
        raise Unavailable("expected storage access settings absent or unsupported")
    if ("allowBlobPublicAccess" in expected and type(expected["allowBlobPublicAccess"]) is not bool
            or "publicNetworkAccess" in expected and expected["publicNetworkAccess"] not in ("Enabled", "Disabled", "SecuredByPerimeter")
            or "networkAcls.defaultAction" in expected and expected["networkAcls.defaultAction"] not in ("Allow", "Deny")):
        raise Unavailable("expected storage access setting malformed")
    properties = get(item, "properties", dict)
    provenance = item.get("_provenance", {})
    full = (isinstance(provenance, dict) and provenance.get("representation") == "full"
            and provenance.get("api_version") in ("2023-05-01", "2026-06-01")
            and provenance.get("source_operation") == "get" and provenance.get("read_only") is True)
    defaults = {"allowBlobPublicAccess": False, "publicNetworkAccess": "Enabled", "networkAcls.defaultAction": "Allow"}
    actual = {}
    for field in expected:
        parent = properties
        parts = field.split(".")
        for part in parts[:-1]:
            if not _has(parent, part):
                if not full:
                    raise Unavailable("storage setting parent omitted without full representation")
                parent = {}
                break
            parent = get(parent, part, dict)
        name = parts[-1]
        if not _has(parent, name):
            if not full:
                raise Unavailable("storage setting omission not authoritative")
            actual[field] = defaults[field]
        else:
            actual[field] = get(parent, name, bool if field == "allowBlobPublicAccess" else str)
        if field == "publicNetworkAccess" and actual[field] not in ("Enabled", "Disabled", "SecuredByPerimeter"):
            raise Unavailable("unrecognized public network access enum")
        if field == "networkAcls.defaultAction" and actual[field] not in ("Allow", "Deny"):
            raise Unavailable("unrecognized network default action enum")
    mismatches = {name: {"expected": expected[name], "actual": actual[name]} for name in expected if expected[name] != actual[name]}
    return result(bool(mismatches), account_id=get(item, "id", str), mismatches=mismatches,
        semantics="Typed storage account API settings; data-plane reachability unverified")
