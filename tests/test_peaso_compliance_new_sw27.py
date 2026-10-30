"""Isolated signed sw27 Azure check tests; run this file with --noconftest."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw27 as sw
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot


SCOPE = "/subscriptions/s"
STAMP = "2026-10-12T12:00:00+00:00"


def rid(provider, kind, name="x"):
    return f"{SCOPE}/resourceGroups/r/providers/{provider}/{kind}/{name}"


def snapshot(kinds, policy=None, *, stamp=STAMP, states=None):
    states = states or {}
    index = {"context": {"provider": "azure", "scope": SCOPE, "created_at": stamp,
        "metadata": {"compliance_policy": {"sw27": {"status": "collected", **(policy or {})}}}},
        "collections": {}}
    for kind, rows in kinds.items():
        state = states.get(kind, "collected" if rows else "empty")
        index["collections"][kind] = [{"type": kind, "scope": SCOPE,
            "status": state, "items": rows}]
        index[kind] = [{"type": kind, "scope": SCOPE, "data": row} for row in rows]
    return index


def status(check_id, item, index):
    return evaluate_check(check_id, item, index)[0]


def covered(row, **fields):
    return {**row, "_coverage": {key: {"status": "collected"} for key in fields}}


def cases():
    c = {}
    patch = covered({"id": rid("Microsoft.Compute", "virtualMachines"), "instanceView": {
        "patchStatus": {"availablePatchSummary": {"status": "Succeeded",
            "lastModifiedTime": STAMP, "criticalAndSecurityPatchCount": 0}}}}, instanceView=True)
    c["azure.cis.latest_os_patches_vms_applied"] = (patch, snapshot({"vm": [patch]}),
        lambda x: x["instanceView"]["patchStatus"]["availablePatchSummary"].update(criticalAndSecurityPatchCount=2))

    cluster = covered({"id": rid("Microsoft.OperationalInsights", "clusters"),
        "properties": {"keyVaultProperties": {"keyVaultUri": "https://v.vault.azure.net", "keyName": "k"}},
        "identity": {"type": "SystemAssigned", "principalId": "p"},
        "keyAccess": {"keyVaultUri": "https://v.vault.azure.net", "keyName": "k", "status": "allowed"}}, keyAccess=True)
    c["azure.gap.monitor_log_cluster_encrypted_with_cmk"] = (cluster,
        snapshot({"log_analytics_cluster": [cluster]}), lambda x: x["keyAccess"].update(status="denied"))

    gateway = covered({"id": rid("Microsoft.Network", "applicationGateways"),
        "scaleObservations": [{"authorized": True, "capacityRatio": 0.85, "crossedAt": STAMP,
            "servingInstancesBefore": 2, "servingInstancesAfter": 3,
            "additionalServingAt": "2026-10-12T12:04:00+00:00"}]}, scaleObservations=True)
    c["azure.other.gateway_vmss_autoscale"] = (gateway,
        snapshot({"application_gateway": [gateway]}), lambda x: x["scaleObservations"][0].update(
            additionalServingAt="2026-10-12T12:06:00+00:00"))

    snap = covered({"id": rid("Microsoft.Compute", "snapshots"),
        "properties": {"networkAccessPolicy": "AllowPrivate", "publicNetworkAccess": "Disabled", "diskAccessId": "a"},
        "effectiveGrantCapableRbac": [{"recipientId": "approved"}], "activeSasGrants": [],
        "sharingTests": [{"recipientId": "intruder", "status": "denied", "current": True}]},
        effectiveGrantCapableRbac=True, activeSasGrants=True, sharingTests=True)
    c["azure.other.snapshot_sharing_scope"] = (snap,
        snapshot({"snapshot": [snap]}, {"approvedRecipientIds": ["approved"]}),
        lambda x: x["sharingTests"][0].update(status="succeeded"))

    pricing = covered({"id": f"{SCOPE}/providers/Microsoft.Security/pricings/CloudPosture",
        "name": "CloudPosture", "properties": {"pricingTier": "Standard"},
        "analysisCoverage": {"scope": SCOPE, "externalPublicAccess": {"status": "enabled"},
            "unusedAccess": {"status": "enabled"}, "assessmentsCurrent": True}}, analysisCoverage=True)
    c["azure.other.access_analysis_coverage"] = (pricing,
        snapshot({"security_pricing": [pricing]}), lambda x: x["analysisCoverage"]["unusedAccess"].update(status="disabled"))

    incident = covered({"id": rid("Microsoft.OperationalInsights", "workspaces") +
        "/providers/Microsoft.SecurityInsights/incidents/i", "properties": {
            "createdTimeUtc": "2026-10-12T10:00:00+00:00", "status": "Active", "severity": "High"},
        "triageHistoryComplete": True, "triageHistory": [
            {"type": "triage", "at": "2026-10-12T10:30:00+00:00"},
            {"type": "response", "step": "ack"}]}, triageHistory=True)
    c["azure.other.incident_triage_trace"] = (incident,
        snapshot({"defender_incident": [incident]}, {"incidentTriage": {
            "approvedTriageHours": 1, "observationWindowHours": 24, "requiredResponseSteps": ["ack"]}}),
        lambda x: x["triageHistory"][0].update(at="2026-10-12T11:30:00+00:00"))

    node = {"id": rid("Microsoft.Automation", "automationAccounts") + "/nodes/n", "properties": {
        "nodeId": "n", "status": "Compliant", "nodeConfiguration": {"name": "config"},
        "lastSeen": STAMP}}
    c["azure_vm_1_2_8_10_1bd35d0"] = (node,
        snapshot({"automation_node": [node]}, {"dscNodes": {
            "requiredNodeIds": ["n"], "maxHeartbeatAgeHours": 1}}),
        lambda x: x["properties"].update(status="NotCompliant"))

    vnet = {"id": rid("Microsoft.Network", "virtualNetworks")}
    pe = {"id": rid("Microsoft.Network", "privateEndpoints"), "properties": {
        "subnet": {"id": vnet["id"] + "/subnets/a"},
        "privateLinkServiceConnections": [{"properties": {
            "privateLinkServiceId": rid("Microsoft.KeyVault", "vaults"),
            "privateLinkServiceConnectionState": {"status": "Pending"}}}],
        "manualPrivateLinkServiceConnections": []}}
    c["azure_azure_resource_keyvault_private_endpoints_c3995a6"] = (vnet,
        snapshot({"vnet": [vnet], "private_endpoint": [pe]},
            {"targetPrivateEndpointServiceType": "Microsoft.KeyVault/vaults"}),
        lambda x: None)

    ase = covered({"id": rid("Microsoft.Web", "hostingEnvironments"),
        "diagnosticCategories": [{"name": "AppServiceEnvironmentPlatformLogs", "type": "Logs",
            "properties": {"categoryGroups": ["allLogs"]}}],
        "diagnosticSettings": [{"properties": {"workspaceId": "workspace", "logs": [
            {"category": "AppServiceEnvironmentPlatformLogs", "enabled": True}]}}],
        "logDelivery": [{"workspaceId": "workspace", "category": "AppServiceEnvironmentPlatformLogs",
            "status": "verified"}]},
        diagnosticCategories=True, diagnosticSettings=True, logDelivery=True)
    c["azure_diagnostic_setting_app_http_logs_enabled_d32e8e1"] = (ase,
        snapshot({"app_service_environment": [ase]}, {"approvedLogAnalyticsWorkspaceIds": ["workspace"]}),
        lambda x: x["diagnosticSettings"][0]["properties"]["logs"][0].update(enabled=False))

    redis = covered({"id": rid("Microsoft.Cache", "redis"), "sku": {"name": "Premium"},
        "properties": {"redisConfiguration": {"rdb-backup-enabled": "true",
            "rdb-backup-frequency": "60"}}, "rdbStorageDestinationId": "container",
        "rdbSnapshots": [{"createdAt": "2026-10-09T12:00:00+00:00", "readable": True,
            "successful": True, "destinationId": "container"},
            {"createdAt": STAMP, "readable": True, "successful": True,
             "destinationId": "container"}]}, rdbSnapshots=True)
    c["azure_redis_cache_10_3_3_17_5912e19"] = (redis,
        snapshot({"redis_cache": [redis]}, {"minimumSnapshotSpanDays": 2}),
        lambda x: x["sku"].update(name="Basic"))

    disk_id, vm_id = rid("Microsoft.Compute", "disks"), rid("Microsoft.Compute", "virtualMachines")
    disk = {"id": disk_id, "managedBy": vm_id, "managedByExtended": [], "properties": {"maxShares": 1}}
    vm = {"id": vm_id, "properties": {"storageProfile": {"osDisk": {
        "managedDisk": {"id": disk_id}, "deleteOption": "Delete"}, "dataDisks": []}}}
    c["azure_vm_vm_ensure_using_managed_disks_11f205b"] = (vm,
        snapshot({"disk": [disk], "vm": [vm]}, {"expectedDiskVmIds": {disk_id: vm_id},
            "deleteWithVm": True}), lambda x: x["properties"]["storageProfile"]["osDisk"].update(deleteOption="Detach"))

    account = covered({"id": rid("Microsoft.Storage", "storageAccounts"),
        "eventSubscriptions": [{"id": rid("Microsoft.Storage", "storageAccounts") +
            "/providers/Microsoft.EventGrid/eventSubscriptions/e", "properties": {
            "provisioningState": "Succeeded", "filter": {"includedEventTypes": ["BlobCreated"]},
            "destination": {"endpointType": "EventHub", "properties": {"resourceId": "hub"}}}}]},
        eventSubscriptions=True)
    c["azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9"] = (
        account, snapshot({"storage_account": [account]}, {"storageEventSubscriptions": {
            account["id"]: {"includedEventTypes": ["BlobCreated"],
                "destinationType": "EventHub", "destinationId": "hub"}}}),
        lambda x: x.update(eventSubscriptions=[]))

    db = covered({"id": rid("Microsoft.DBforPostgreSQL", "flexibleServers"),
        "properties": {"authConfig": {"activeDirectoryAuth": "Enabled"}},
        "administrators": [{"properties": {"principalId": "00000000-0000-4000-8000-000000000001"}}]}, administrators=True)
    c["azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf"] = (db,
        snapshot({"mysql_flexible_server": [], "postgresql_flexible_server": [db]}),
        lambda x: x["properties"]["authConfig"].update(activeDirectoryAuth="Disabled"))

    vm2 = {"id": rid("Microsoft.Compute", "virtualMachines")}
    assessment = {"id": f"{SCOPE}/providers/Microsoft.Security/assessments/k",
        "name": "k", "properties": {"resourceDetails": {"id": vm2["id"]},
            "status": {"code": "Healthy", "changedAt": STAMP}}}
    c["azure_security_pricing_compute_vm_security_configuration_vulnerabilities_remediated_64c8b1c"] = (
        vm2, snapshot({"vm": [vm2], "security_assessment": [assessment]},
            {"vmBaselineAssessmentKeys": ["k"], "assessmentMaxAgeHours": 24}),
        lambda x: None)

    diag = {"id": f"{SCOPE}/providers/Microsoft.Insights/diagnosticSettings/d"}
    siem_index = snapshot({"subscription_diagnostic_setting": [diag]}, {"siem": {
        "requiredSourceIds": ["Administrative"], "approvedDestinationId": "siem"}})
    siem_index["context"]["metadata"]["sw27_siem_evidence"] = {"scope": SCOPE, "status": "collected", "sources": [
        {"sourceId": "Administrative", "destinationId": "siem", "exportStatus": "verified",
            "ingestionStatus": "verified"}], "correlationVerified": True,
        "incidentWorkflowVerified": True, "safeguardInventoryDocumented": True}
    c["azure_c5_ops_13_01b"] = (diag, siem_index, lambda x: None)
    return c


@pytest.mark.parametrize("check_id", sw.IDS)
def test_positive_and_incomplete_inventory(check_id):
    item, index, _ = cases()[check_id]
    assert status(check_id, item, index) == "PASS"
    partial = copy.deepcopy(index)
    first_kind = next(iter(partial["collections"]))
    partial["collections"][first_kind][0]["status"] = "partial"
    assert status(check_id, item, partial) == "UNKNOWN"
    missing = copy.deepcopy(index)
    missing["collections"].pop(first_kind)
    assert status(check_id, item, missing) == "UNKNOWN"
    malformed = copy.deepcopy(index)
    malformed["context"]["scope"] = "/subscriptions/foreign"
    assert status(check_id, item, malformed) == "UNKNOWN"


@pytest.mark.parametrize("check_id", [
    "azure.cis.latest_os_patches_vms_applied",
    "azure.gap.monitor_log_cluster_encrypted_with_cmk",
    "azure.other.gateway_vmss_autoscale",
    "azure.other.snapshot_sharing_scope",
    "azure.other.access_analysis_coverage",
    "azure.other.incident_triage_trace",
    "azure_vm_1_2_8_10_1bd35d0",
    "azure_diagnostic_setting_app_http_logs_enabled_d32e8e1",
    "azure_redis_cache_10_3_3_17_5912e19",
    "azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9",
    "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf",
])
def test_direct_violation(check_id):
    item, index, mutate = cases()[check_id]
    changed = copy.deepcopy(item)
    mutate(changed)
    for kind, envelopes in index["collections"].items():
        for n, row in enumerate(envelopes[0]["items"]):
            if row == item:
                envelopes[0]["items"][n] = changed
                index[kind][n]["data"] = changed
    assert status(check_id, changed, index) == "FAIL"


def test_joined_violations_and_negative_cases():
    c = cases()
    cid = "azure_azure_resource_keyvault_private_endpoints_c3995a6"
    vnet, index, _ = c[cid]
    index["collections"]["private_endpoint"][0]["items"] = []
    index["private_endpoint"] = []
    index["collections"]["private_endpoint"][0]["status"] = "empty"
    assert status(cid, vnet, index) == "FAIL"

    cid = "azure_vm_vm_ensure_using_managed_disks_11f205b"
    vm, index, _ = c[cid]
    index["collections"]["disk"][0]["items"][0]["managedBy"] = rid("Microsoft.Compute", "virtualMachines", "other")
    assert status(cid, vm, index) == "FAIL"

    cid = "azure_security_pricing_compute_vm_security_configuration_vulnerabilities_remediated_64c8b1c"
    vm, index, _ = c[cid]
    index["collections"]["security_assessment"][0]["items"][0]["properties"]["status"]["code"] = "Unhealthy"
    assert status(cid, vm, index) == "FAIL"

    cid = "azure_c5_ops_13_01b"
    diag, index, _ = c[cid]
    index["context"]["metadata"]["sw27_siem_evidence"]["sources"][0]["ingestionStatus"] = "missing"
    assert status(cid, diag, index) == "FAIL"


def test_not_applicable_boundaries():
    c = cases()
    cid = "azure.other.snapshot_sharing_scope"
    item, index, _ = c[cid]
    index["snapshot"] = []
    index["collections"]["snapshot"][0].update(status="empty", items=[])
    assert status(cid, item, index) == "NOT_APPLICABLE"

    cid = "azure_vm_1_2_8_10_1bd35d0"
    item, index, _ = c[cid]
    index["context"]["metadata"]["compliance_policy"]["sw27"]["dscNodes"]["requiredNodeIds"] = []
    assert status(cid, item, index) == "NOT_APPLICABLE"

    cid = "azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9"
    item, index, _ = c[cid]
    index["context"]["metadata"]["compliance_policy"]["sw27"]["storageEventSubscriptions"] = {}
    assert status(cid, item, index) == "UNKNOWN"
    index["context"]["metadata"]["compliance_policy"]["sw27"]["storageEventSubscriptions"] = {
        rid("Microsoft.Storage", "storageAccounts", "other"): {
            "includedEventTypes": ["BlobCreated"], "destinationType": "EventHub", "destinationId": "hub"}}
    assert status(cid, item, index) == "NOT_APPLICABLE"

    cid = "azure_vm_vm_ensure_using_managed_disks_11f205b"
    item, index, _ = c[cid]
    index["context"]["metadata"]["compliance_policy"]["sw27"]["expectedDiskVmIds"] = {}
    assert status(cid, item, index) == "NOT_APPLICABLE"

    cid = "azure.other.incident_triage_trace"
    item, index, _ = c[cid]
    outside = copy.deepcopy(item)
    outside["properties"]["createdTimeUtc"] = "2026-10-01T10:00:00+00:00"
    index["collections"]["defender_incident"][0]["items"][0] = outside
    index["defender_incident"][0]["data"] = outside
    assert status(cid, outside, index) == "NOT_APPLICABLE"

    cid = "azure_azure_resource_keyvault_private_endpoints_c3995a6"
    item, index, _ = c[cid]
    index["vnet"] = []
    index["collections"]["vnet"][0].update(status="empty", items=[])
    assert status(cid, index["context"], index) == "NOT_APPLICABLE"

    cid = "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf"
    item, index, _ = c[cid]
    index["postgresql_flexible_server"] = []
    index["collections"]["postgresql_flexible_server"][0].update(status="empty", items=[])
    assert status(cid, index["context"], index) == "NOT_APPLICABLE"


def test_sparse_observations_and_unresolved_capabilities_are_unknown():
    c = cases()
    cid = "azure.other.gateway_vmss_autoscale"
    item, index, _ = c[cid]
    changed = copy.deepcopy(item)
    changed["scaleObservations"][0].update(servingInstancesAfter=2, additionalServingAt=None)
    index["application_gateway"][0]["data"] = changed
    index["collections"]["application_gateway"][0]["items"][0] = changed
    assert status(cid, changed, index) == "UNKNOWN"

    cid = "azure.other.access_analysis_coverage"
    item, index, _ = c[cid]
    changed = copy.deepcopy(item)
    changed["analysisCoverage"]["unusedAccess"]["status"] = "unknown"
    index["security_pricing"][0]["data"] = changed
    index["collections"]["security_pricing"][0]["items"][0] = changed
    assert status(cid, changed, index) == "UNKNOWN"

    cid = "azure_redis_cache_10_3_3_17_5912e19"
    item, index, _ = c[cid]
    changed = copy.deepcopy(item)
    changed["rdbSnapshots"][0]["destinationId"] = "other-container"
    index["redis_cache"][0]["data"] = changed
    index["collections"]["redis_cache"][0]["items"][0] = changed
    assert status(cid, changed, index) == "UNKNOWN"


def test_explicit_absence_and_optional_disk_policy():
    c = cases()
    cid = "azure.gap.monitor_log_cluster_encrypted_with_cmk"
    item, index, _ = c[cid]
    changed = copy.deepcopy(item)
    changed["properties"]["keyVaultProperties"] = {}
    index["log_analytics_cluster"][0]["data"] = changed
    index["collections"]["log_analytics_cluster"][0]["items"][0] = changed
    assert status(cid, changed, index) == "FAIL"

    cid = "azure_vm_vm_ensure_using_managed_disks_11f205b"
    vm, index, _ = c[cid]
    index["context"]["metadata"]["compliance_policy"]["sw27"].pop("deleteWithVm")
    assert status(cid, vm, index) == "PASS"
    index["collections"]["disk"][0]["items"][0].pop("managedBy")
    assert status(cid, vm, index) == "UNKNOWN"


def test_alternative_good_export_and_subscription_prevent_false_failure():
    c = cases()
    cid = "azure_diagnostic_setting_app_http_logs_enabled_d32e8e1"
    item, index, _ = c[cid]
    changed = copy.deepcopy(item)
    changed["diagnosticSettings"].append(copy.deepcopy(changed["diagnosticSettings"][0]))
    changed["diagnosticSettings"][0]["properties"]["workspaceId"] = "other-workspace"
    changed["logDelivery"].insert(0, {"workspaceId": "other-workspace",
        "category": "AppServiceEnvironmentPlatformLogs", "status": "missing"})
    index["context"]["metadata"]["compliance_policy"]["sw27"]["approvedLogAnalyticsWorkspaceIds"].append("other-workspace")
    index["app_service_environment"][0]["data"] = changed
    index["collections"]["app_service_environment"][0]["items"][0] = changed
    assert status(cid, changed, index) == "PASS"

    cid = "azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9"
    item, index, _ = c[cid]
    changed = copy.deepcopy(item)
    failed = copy.deepcopy(changed["eventSubscriptions"][0])
    failed["id"] = failed["id"].rsplit("/", 1)[0] + "/failed"
    failed["properties"]["provisioningState"] = "Failed"
    changed["eventSubscriptions"].insert(0, failed)
    index["storage_account"][0]["data"] = changed
    index["collections"]["storage_account"][0]["items"][0] = changed
    assert status(cid, changed, index) == "PASS"


def test_incomplete_incident_history_cannot_prove_late_triage():
    cid = "azure.other.incident_triage_trace"
    item, index, _ = cases()[cid]
    changed = copy.deepcopy(item)
    changed["triageHistoryComplete"] = False
    changed["triageHistory"][0]["at"] = "2026-10-12T11:30:00+00:00"
    index["defender_incident"][0]["data"] = changed
    index["collections"]["defender_incident"][0]["items"][0] = changed
    assert status(cid, changed, index) == "UNKNOWN"


def test_ase_supported_category_group_and_pending_manual_endpoint():
    cid = "azure_diagnostic_setting_app_http_logs_enabled_d32e8e1"
    item, index, _ = cases()[cid]
    changed = copy.deepcopy(item)
    log = changed["diagnosticSettings"][0]["properties"]["logs"][0]
    log.pop("category")
    log["categoryGroup"] = "allLogs"
    changed["logDelivery"][0]["category"] = "allLogs"
    index["app_service_environment"][0]["data"] = changed
    index["collections"]["app_service_environment"][0]["items"][0] = changed
    assert status(cid, changed, index) == "PASS"

    cid = "azure_azure_resource_keyvault_private_endpoints_c3995a6"
    vnet, index, _ = cases()[cid]
    endpoint = index["collections"]["private_endpoint"][0]["items"][0]
    endpoint["properties"]["manualPrivateLinkServiceConnections"] = endpoint["properties"].pop(
        "privateLinkServiceConnections")
    endpoint["properties"]["privateLinkServiceConnections"] = []
    assert status(cid, vnet, index) == "PASS"


def test_missing_child_and_malformed_policy_are_unknown():
    c = cases()
    for cid, field in [
        ("azure.cis.latest_os_patches_vms_applied", "instanceView"),
        ("azure.gap.monitor_log_cluster_encrypted_with_cmk", "keyAccess"),
        ("azure.other.gateway_vmss_autoscale", "scaleObservations"),
        ("azure.other.snapshot_sharing_scope", "sharingTests"),
        ("azure.other.incident_triage_trace", "triageHistory"),
        ("azure_diagnostic_setting_app_http_logs_enabled_d32e8e1", "diagnosticCategories"),
        ("azure_redis_cache_10_3_3_17_5912e19", "rdbSnapshots"),
        ("azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9", "eventSubscriptions"),
        ("azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf", "administrators"),
    ]:
        item, index, _ = c[cid]
        changed = copy.deepcopy(item)
        changed.pop(field)
        changed["_coverage"].pop(field)
        for kind in index["collections"]:
            for n, row in enumerate(index["collections"][kind][0]["items"]):
                if row == item:
                    index["collections"][kind][0]["items"][n] = changed
                    index[kind][n]["data"] = changed
        assert status(cid, changed, index) == "UNKNOWN", cid

    for cid in ("azure.other.snapshot_sharing_scope", "azure_vm_vm_ensure_using_managed_disks_11f205b",
                "azure_c5_ops_13_01b"):
        item, index, _ = cases()[cid]
        index["context"]["metadata"]["compliance_policy"]["sw27"]["status"] = "partial"
        assert status(cid, item, index) == "UNKNOWN"


def test_scope_registration_evaluates_source_inventory():
    for cid in sw._SCOPE_SOURCES:
        item, index, _ = cases()[cid]
        assert next(check for check in CHECKS if check.id == cid).target == "scope"
        assert status(cid, index["context"], index) == "PASS", cid


def test_engine_runs_composite_scope_check_over_native_component_kinds():
    cid = "azure_vm_vm_ensure_using_managed_disks_11f205b"
    _, index, _ = cases()[cid]
    collections = [{"type": kind, "scope": SCOPE, "service": "Microsoft.Compute",
        "status": envelope[0]["status"], "items": envelope[0]["items"]}
        for kind, envelope in index["collections"].items()]
    captured = make_snapshot("azure", [SCOPE], collections, created_at=STAMP,
        metadata=index["context"]["metadata"])
    report = evaluate_snapshot(captured, checks=[cid])
    findings = [finding for finding in report["findings"] if finding["check_id"] == cid]
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["resource_id"] == "scope:" + SCOPE


