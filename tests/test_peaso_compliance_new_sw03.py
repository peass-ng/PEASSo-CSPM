"""Signed sw03 Azure checks retain conservative snapshot boundaries."""
from __future__ import annotations

import copy
import importlib
import sys

import pytest

from peaso.checks import CHECKS

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG = SCOPE + "/resourceGroups/rg"
SA = RG + "/providers/Microsoft.Storage/storageAccounts/sa"
VM = RG + "/providers/Microsoft.Compute/virtualMachines/vm"
ML = RG + "/providers/Microsoft.MachineLearningServices/workspaces/ml"
CLUSTER = RG + "/providers/Microsoft.OperationalInsights/clusters/logs"
TEMPLATE = RG + "/providers/Microsoft.VirtualMachineImages/imageTemplates/build"
SUBNET = RG + "/providers/Microsoft.Network/virtualNetworks/vnet/subnets/build"
AUTOMATION = RG + "/providers/Microsoft.Automation/automationAccounts/aa"
STREAM = RG + "/providers/Microsoft.StreamAnalytics/streamingjobs/job"
ENDPOINT = RG + "/providers/Microsoft.Network/privateEndpoints/pe"


@pytest.fixture(scope="module")
def sw03():
    from tests.compliance_draft_isolation import staged_registry
    with staged_registry(["compliance_new_sw03"]):
        try:
            module = importlib.import_module("peaso.checks.compliance_new_sw03")
            yield module
        finally:
            sys.modules.pop("peaso.checks.compliance_new_sw03", None)


def snapshot(collections, *, policy=None, status=None, query=None):
    grouped = {}
    for kind, rows in collections.items():
        state = (status or {}).get(kind, "collected" if rows else "empty")
        envelope = {"type": kind, "scope": SCOPE, "status": state, "items": rows}
        if kind == "activity_log" and query is not None:
            envelope["queryWindow"] = query
        grouped[kind] = [envelope]
    return {"context": {"provider": "azure", "scope": SCOPE,
        "metadata": {"compliance_policy": {"sw03": {"status": "collected", "scope": SCOPE,
            **(policy or {})}}}},
        "collections": grouped,
        **{kind: [{"type": kind, "scope": SCOPE, "data": row} for row in rows]
           for kind, rows in collections.items()}}


def grade(sw03, cid, item, index):
    matches = [check for check in CHECKS if check.id == cid]
    assert len(matches) == 1
    return matches[0].evaluate(item, index)[0]


def matrix():
    ml_pass = {"id": ML, "_coverage": {"privateEndpointConnections": {"status": "collected"}},
        "privateEndpointConnections": [{"id": ML + "/privateEndpointConnections/c1", "properties": {
            "privateLinkServiceConnectionState": {"status": "Approved"},
            "privateEndpoint": {"id": ENDPOINT}}}]}
    cluster = {"id": CLUSTER, "properties": {"isDoubleEncryptionEnabled": True}}
    setting = {"id": SCOPE + "/providers/Microsoft.Security/autoProvisioningSettings/default",
        "name": "default", "properties": {"autoProvision": "On"}}
    pricing = {"id": SCOPE + "/providers/Microsoft.Security/pricings/VirtualMachines",
        "name": "VirtualMachines", "properties": {"pricingTier": "Standard"}}
    window = {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z", "endExclusive": True}
    event = {"id": "azure-activity://event1", "eventTimestamp": "2026-01-01T12:00:00Z"}
    vm = {"id": VM}
    assessment = {"id": VM + "/providers/Microsoft.Security/assessments/endpoint", "name": "endpoint",
        "properties": {"resourceDetails": {"id": VM}, "status": {"code": "Healthy"}}}
    image = {"id": TEMPLATE, "_provenance": {"representation": "full"},
        "_subnetIsolation": {"status": "collected", "subnetId": SUBNET, "isolated": True},
        "properties": {"vmProfile": {"vnetConfig": {"subnetId": SUBNET}}}}
    lock = {"id": SA + "/providers/Microsoft.Authorization/locks/protect",
        "properties": {"level": "CanNotDelete"}}
    locked = {"id": SA, "effectiveLockChain": {"status": "collected",
        "managementGroupAncestorsComplete": True, "scopes": [
            {"scope": SA, "status": "collected", "locks": [lock]},
            {"scope": RG, "status": "empty", "locks": []},
            {"scope": SCOPE, "status": "empty", "locks": []}]}}
    automation = {"id": AUTOMATION, "identity": {"type": "SystemAssigned", "principalId": "principal"},
        "properties": {"encryption": {"keySource": "Microsoft.Keyvault",
            "identity": {}, "keyVaultProperties": {"keyName": "key", "keyvaultUri": "https://vault.vault.azure.net/"}}},
        "_cmkKeyAccess": {"status": "collected", "principalId": "principal", "keyName": "key",
            "keyvaultUri": "https://vault.vault.azure.net/", "usable": True}}
    storage = {"id": SA, "name": "sa", "identity": {"type": "SystemAssigned", "principalId": "storage-principal"}, "properties": {"primaryEndpoints": {"blob": "https://sa.blob.core.windows.net/"},
        "encryption": {"services": {"blob": {"enabled": True}}, "keySource": "Microsoft.Keyvault",
            "keyVaultProperties": {"keyName": "key", "keyVaultUri": "https://vault.vault.azure.net/"}}},
        "_cmkKeyAccess": {"status": "collected", "principalId": "storage-principal", "keyName": "key",
            "keyVaultUri": "https://vault.vault.azure.net/", "usable": True}}
    stream = {"id": STREAM, "_externalStorageRequirement": {"status": "collected", "required": True},
        "properties": {"jobStorageAccount": {"accountName": "sa"}}}
    unmanaged_vm = {"id": VM, "_provenance": {"representation": "full"},
        "properties": {"storageProfile": {"osDisk": {"vhd": {"uri": "https://sa.blob.core.windows.net/vhds/os.vhd"}},
            "dataDisks": []}}}
    expected_storage = {"id": SA, "properties": {"allowBlobPublicAccess": False,
        "publicNetworkAccess": "Disabled", "networkAcls": {"defaultAction": "Deny"}}}
    return {
        "azure.gap.machine_learning_workspace_private_link_used": ({"scope": SCOPE}, {"ml_workspace": [ml_pass]}, {},
            lambda row: (row.update(privateEndpointConnections=[]), row["_coverage"]["privateEndpointConnections"].update(status="empty")),
            lambda row: row.pop("_coverage"),
            lambda row: row.update(privateEndpointConnections="bad"), "NOT_APPLICABLE"),
        "azure.gap.monitor_log_cluster_infrastructure_encryption_enabled": ({"scope": SCOPE}, {"log_analytics_cluster": [cluster]}, {},
            lambda row: row["properties"].update(isDoubleEncryptionEnabled=False),
            lambda row: row["properties"].pop("isDoubleEncryptionEnabled"),
            lambda row: row["properties"].update(isDoubleEncryptionEnabled="true"), "NOT_APPLICABLE"),
        "azure.cis.auto_provisioning_log_analytics_agent_vms": ({"scope": SCOPE}, {"defender_auto_provisioning_setting": [setting]},
            {"legacyAgentBaseline": {"required": True}},
            lambda row: None, lambda row: None, lambda row: None, "NOT_APPLICABLE"),
        "azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3": ({"scope": SCOPE},
            {"security_pricing": [pricing]}, {"defenderPlans": {"requiredPlans": ["VirtualMachines"],
                "supportedPlans": ["VirtualMachines"], "representsSecurityCenterEnablement": True}}, lambda row: None, lambda row: None,
            lambda row: None, None),
        "azure_c5_ops_15_02b": ({"scope": SCOPE}, {"activity_log": [event]},
            {"activityLogWindow": {"start": window["start"], "end": window["end"]}},
            lambda row: None, lambda row: None, lambda row: None, None),
        "azure.cis.endpoint_protection_vms_installed": ({"scope": SCOPE},
            {"vm": [vm], "security_assessment": [assessment]},
            {"endpointProtection": {"assessmentKey": "endpoint"}},
            lambda row: None, lambda row: None, lambda row: None, "NOT_APPLICABLE"),
        "azure.gap.compute_vm_image_builder_uses_private_link": ({"scope": SCOPE}, {"image_template": [image]},
            {"imageBuilder": {"approvedBuildSubnetIds": [SUBNET], "isolatedSubnetIds": [SUBNET]}},
            lambda row: row["properties"]["vmProfile"]["vnetConfig"].update(subnetId=RG + "/providers/Microsoft.Network/virtualNetworks/other/subnets/other"),
            lambda row: (row["properties"]["vmProfile"].pop("vnetConfig"), row.pop("_provenance")),
            lambda row: row["properties"]["vmProfile"]["vnetConfig"].update(subnetId=42), "NOT_APPLICABLE"),
        "azure.cis.resource_manager_delete_locks_applied_storage_accounts": ({"scope": SCOPE}, {"storage_account": [locked]}, {},
            lambda row: row["effectiveLockChain"]["scopes"][0].update(locks=[], status="empty"),
            lambda row: row.pop("effectiveLockChain"),
            lambda row: row["effectiveLockChain"]["scopes"][0].update(locks="bad"), "NOT_APPLICABLE"),
        "azure.gap.automation_account_encrypted_with_cmk": (automation, {"automation_account": [automation]}, {},
            lambda row: row["properties"]["encryption"].update(keySource="Microsoft.Automation"),
            lambda row: row.pop("_cmkKeyAccess"),
            lambda row: row["_cmkKeyAccess"].update(usable="yes"), None),
        "azure.gap.stream_analytics_job_encrypted_with_cmk": (stream,
            {"stream_analytics_job": [stream], "storage_account": [storage]}, {},
            lambda row: None, lambda row: row.pop("_externalStorageRequirement"),
            lambda row: row["_externalStorageRequirement"].update(required="yes"), "NOT_APPLICABLE"),
        "azure.cis.legacy_vhds_encrypted": ({"scope": SCOPE}, {"vm": [unmanaged_vm], "storage_account": [storage]}, {},
            lambda row: None, lambda row: None, lambda row: None, "NOT_APPLICABLE"),
        "azure_storage_account_storage_blob_public_access_level_is_disabled_4211794": (expected_storage,
            {"storage_account": [expected_storage]}, {"storageAccess": {"expectedSettings": {
                "allowBlobPublicAccess": False, "publicNetworkAccess": "Disabled",
                "networkAcls.defaultAction": "Deny"}}},
            lambda row: row["properties"].update(publicNetworkAccess="Enabled"),
            lambda row: row["properties"].pop("publicNetworkAccess"),
            lambda row: row["properties"].update(publicNetworkAccess="unexpected"), None),
    }, window


def run_case(sw03, cid, flavor):
    cases, window = matrix()
    item, collections, policy, fail_mut, missing_mut, malformed_mut, na = cases[cid]
    item, collections, policy = copy.deepcopy((item, collections, policy))
    scoped_resource = cid in {
        "azure.gap.machine_learning_workspace_private_link_used",
        "azure.gap.monitor_log_cluster_infrastructure_encryption_enabled",
        "azure.gap.compute_vm_image_builder_uses_private_link",
        "azure.cis.resource_manager_delete_locks_applied_storage_accounts",
    }
    mutable = next(iter(collections.values()))[0] if scoped_resource else item
    if flavor == "fail":
        fail_mut(mutable)
        if cid == "azure.cis.auto_provisioning_log_analytics_agent_vms":
            collections["defender_auto_provisioning_setting"][0]["properties"]["autoProvision"] = "Off"
        elif cid == "azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3":
            collections["security_pricing"][0]["properties"]["pricingTier"] = "Free"
        elif cid == "azure_c5_ops_15_02b":
            collections["activity_log"][0].pop("eventTimestamp")
        elif cid == "azure.cis.endpoint_protection_vms_installed":
            collections["security_assessment"][0]["properties"]["status"]["code"] = "Unhealthy"
        elif cid == "azure.gap.stream_analytics_job_encrypted_with_cmk":
            collections["storage_account"][0]["properties"]["encryption"]["keySource"] = "Microsoft.Storage"
        elif cid == "azure.cis.legacy_vhds_encrypted":
            collections["storage_account"][0]["properties"]["encryption"]["services"]["blob"]["enabled"] = False
    elif flavor == "missing":
        missing_mut(mutable)
        if cid == "azure.cis.auto_provisioning_log_analytics_agent_vms":
            collections["defender_auto_provisioning_setting"][0]["properties"].pop("autoProvision")
        elif cid == "azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3":
            collections["security_pricing"][0]["properties"].pop("pricingTier")
        elif cid == "azure_c5_ops_15_02b":
            window = None
        elif cid == "azure.cis.endpoint_protection_vms_installed":
            collections["security_assessment"] = []
        elif cid == "azure.cis.legacy_vhds_encrypted":
            collections["storage_account"][0]["properties"]["encryption"]["services"]["blob"].pop("enabled")
    elif flavor == "malformed":
        malformed_mut(mutable)
        if cid == "azure.cis.auto_provisioning_log_analytics_agent_vms":
            collections["defender_auto_provisioning_setting"][0]["properties"]["autoProvision"] = 1
        elif cid == "azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3":
            collections["security_pricing"][0]["properties"]["pricingTier"] = 1
        elif cid == "azure_c5_ops_15_02b":
            collections["activity_log"][0]["eventTimestamp"] = "bad"
        elif cid == "azure.cis.endpoint_protection_vms_installed":
            collections["security_assessment"][0]["properties"]["status"]["code"] = 1
        elif cid == "azure.cis.legacy_vhds_encrypted":
            collections["vm"][0]["properties"]["storageProfile"]["osDisk"]["vhd"]["uri"] = 1
    elif flavor == "na":
        if scoped_resource:
            collections[next(iter(collections))] = []
        elif cid == "azure.cis.auto_provisioning_log_analytics_agent_vms":
            policy["legacyAgentBaseline"]["required"] = False
        elif cid == "azure.cis.endpoint_protection_vms_installed":
            collections["vm"] = []
        elif cid == "azure.gap.stream_analytics_job_encrypted_with_cmk":
            item["_externalStorageRequirement"]["required"] = False
        elif cid == "azure.cis.legacy_vhds_encrypted":
            collections["vm"][0]["properties"]["storageProfile"]["osDisk"] = {"managedDisk": {"id": RG + "/providers/Microsoft.Compute/disks/os"}}
    if flavor in ("fail", "missing", "malformed", "na") and isinstance(item, dict) and "id" in item:
        for rows in collections.values():
            for i, row in enumerate(rows):
                if row.get("id") == item["id"]:
                    rows[i] = item
    status = None
    if flavor == "incomplete":
        status = {next(iter(collections)): "partial"}
    index = snapshot(collections, policy=policy, status=status, query=window)
    return grade(sw03, cid, item, index), na


@pytest.mark.parametrize("flavor,expected", [("pass", "PASS"), ("fail", "FAIL"),
    ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("incomplete", "UNKNOWN")])
@pytest.mark.parametrize("cid", list(matrix()[0]))
def test_signed_predicate_boundaries(sw03, cid, flavor, expected):
    actual, _ = run_case(sw03, cid, flavor)
    assert actual == expected, (cid, flavor, actual)


@pytest.mark.parametrize("cid", [cid for cid, row in matrix()[0].items() if row[-1]])
def test_signed_not_applicable(sw03, cid):
    actual, expected = run_case(sw03, cid, "na")
    assert actual == expected


@pytest.mark.parametrize("cid", list(matrix()[0]))
def test_foreign_collection_scope_is_unknown(sw03, cid):
    cases, query = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    index = snapshot(collections, policy=policy, query=query)
    first = next(iter(index["collections"]))
    index["collections"][first][0]["scope"] = "/subscriptions/00000000-0000-0000-0000-000000000002"
    assert grade(sw03, cid, item, index) == "UNKNOWN"


@pytest.mark.parametrize("cid", list(matrix()[0]))
def test_missing_dependency_collection_is_unknown(sw03, cid):
    cases, query = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    index = snapshot(collections, policy=policy, query=query)
    first = next(iter(index["collections"]))
    del index["collections"][first]
    del index[first]
    assert grade(sw03, cid, item, index) == "UNKNOWN"


@pytest.mark.parametrize('cid', list(matrix()[0]))
@pytest.mark.parametrize('change', ['native', 'scope', 'type', 'empty'])
def test_collection_payload_and_wrappers_must_agree(sw03, cid, change):
    cases, query = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    index = snapshot(collections, policy=policy, query=query)
    kind = next(iter(collections))
    if change == 'native':
        index['collections'][kind][0]['items'] = []
    elif change == 'scope':
        index[kind][0]['scope'] = SCOPE + '-foreign'
    elif change == 'type':
        index[kind][0]['type'] = 'foreign'
    else:
        index['collections'][kind][0]['status'] = 'empty'
    assert grade(sw03, cid, item, index) == 'UNKNOWN'


def test_ml_connection_requires_valid_direct_child_endpoint_and_coverage(sw03):
    cid = 'azure.gap.machine_learning_workspace_private_link_used'
    for change in ('empty', 'nested', 'endpoint'):
        cases, _ = matrix()
        item, collections, policy = copy.deepcopy(cases[cid][:3])
        row = collections['ml_workspace'][0]
        if change == 'empty':
            row['_coverage']['privateEndpointConnections']['status'] = 'empty'
        elif change == 'nested':
            row['privateEndpointConnections'][0]['id'] += '/nested/child'
        else:
            row['privateEndpointConnections'][0]['properties']['privateEndpoint']['id'] = '/subscriptions/invalid/providers/Microsoft.Network/privateEndpoints/'
        assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'


def test_activity_submission_delay_and_alternative_timestamp(sw03):
    cid = 'azure_c5_ops_15_02b'
    for primary in ('2026-01-01T12:00:00Z', 'malformed'):
        cases, query = matrix()
        item, collections, policy = copy.deepcopy(cases[cid][:3])
        collections['activity_log'][0].update(eventTimestamp=primary, submissionTimestamp='2026-01-02T00:01:00Z')
        assert grade(sw03, cid, item, snapshot(collections, policy=policy, query=query)) == 'PASS'


@pytest.mark.parametrize('cid', [
    'azure.gap.machine_learning_workspace_private_link_used',
    'azure.gap.compute_vm_image_builder_uses_private_link',
    'azure.cis.resource_manager_delete_locks_applied_storage_accounts',
    'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled'])
def test_measured_resource_failure_survives_another_unknown(sw03, cid):
    cases, _ = matrix()
    item, collections, policy, failure, *_ = copy.deepcopy(cases[cid])
    kind = next(iter(collections))
    first = collections[kind][0]
    failure(first)
    missing = {'id': first['id'] + '-missing'}
    for rows in ([first, missing], [missing, first]):
        collections[kind] = rows
        assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'FAIL'


def test_image_builder_subnet_policy_requires_real_subnet_id(sw03):
    cid = 'azure.gap.compute_vm_image_builder_uses_private_link'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    malformed = SUBNET + '/nested/child'
    collections['image_template'][0]['properties']['vmProfile']['vnetConfig']['subnetId'] = malformed
    collections['image_template'][0]['_subnetIsolation']['subnetId'] = malformed
    policy['imageBuilder']['approvedBuildSubnetIds'] = [malformed]
    policy['imageBuilder']['isolatedSubnetIds'] = [malformed]
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'


def test_lock_identity_and_coverage_must_be_exact(sw03):
    cid = 'azure.cis.resource_manager_delete_locks_applied_storage_accounts'
    for change in ('nested', 'empty'):
        cases, _ = matrix()
        item, collections, policy = copy.deepcopy(cases[cid][:3])
        scope = collections['storage_account'][0]['effectiveLockChain']['scopes'][0]
        if change == 'nested':
            scope['locks'][0]['id'] += '/nested/child'
        else:
            scope['status'] = 'empty'
        assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'


def test_automation_selected_user_identity_requires_assigned_type(sw03):
    cid = 'azure.gap.automation_account_encrypted_with_cmk'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    selected = RG + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/identity'
    item['properties']['encryption']['identity'] = {'userAssignedIdentity': selected}
    item['identity']['userAssignedIdentities'] = {selected: {'principalId': 'principal'}}
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'FAIL'
    item['identity']['type'] = 'UserAssigned'
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'PASS'


def test_stream_absent_storage_requires_full_get_authority(sw03):
    cid = 'azure.gap.stream_analytics_job_encrypted_with_cmk'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    del item['properties']['jobStorageAccount']
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'
    item['_provenance'] = {'representation': 'full', 'source_operation': 'get', 'read_only': True}
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'FAIL'


def test_stream_key_access_must_match_storage_identity(sw03):
    cid = 'azure.gap.stream_analytics_job_encrypted_with_cmk'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    collections['storage_account'][0]['_cmkKeyAccess']['principalId'] = 'foreign-principal'
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'


def test_storage_omission_defaults_require_read_only_get_and_null_is_unknown(sw03):
    cid = 'azure_storage_account_storage_blob_public_access_level_is_disabled_4211794'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    policy['storageAccess']['expectedSettings'] = {'allowBlobPublicAccess': False}
    del item['properties']['allowBlobPublicAccess']
    item['_provenance'] = {'representation': 'full', 'api_version': '2023-05-01'}
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'
    item['_provenance'].update(source_operation='get', read_only=True)
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'PASS'
    # The collector's current storage-account GET version is also a full read.
    from peaso.collectors.azure import ENDPOINTS
    item['_provenance']['api_version'] = ENDPOINTS['storage_account'][1]
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'PASS'
    item['_provenance']['api_version'] = '2021-01-01'
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'
    item['_provenance']['api_version'] = '2023-05-01'
    item['properties']['allowBlobPublicAccess'] = None
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'


def test_native_resource_type_cannot_be_relabelled_as_logs_cluster(sw03):
    cid = 'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled'
    row = {'id': SA, 'properties': {'isDoubleEncryptionEnabled': True}}
    assert grade(sw03, cid, {'scope': SCOPE}, snapshot({'log_analytics_cluster': [row]})) == 'UNKNOWN'


def test_free_defender_plan_failure_survives_unknown_other_required_plan(sw03):
    cid = 'azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    first = collections['security_pricing'][0]
    first['properties']['pricingTier'] = 'Free'
    other = {'id': SCOPE + '/providers/Microsoft.Security/pricings/StorageAccounts', 'name': 'StorageAccounts', 'properties': {}}
    policy['defenderPlans']['requiredPlans'].append('StorageAccounts')
    policy['defenderPlans']['supportedPlans'].append('StorageAccounts')
    for rows in ([first, other], [other, first]):
        collections['security_pricing'] = rows
        assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'FAIL'
    first['properties']['pricingTier'] = 'Standard'
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'


def test_unhealthy_vm_failure_survives_unknown_other_assessment(sw03):
    cid = 'azure.cis.endpoint_protection_vms_installed'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    first = collections['security_assessment'][0]
    first['properties']['status']['code'] = 'Unhealthy'
    vm2 = VM + '-second'
    collections['vm'].append({'id': vm2})
    other = {'id': vm2 + '/providers/Microsoft.Security/assessments/endpoint', 'name': 'endpoint',
             'properties': {'resourceDetails': {'id': vm2}}}
    for rows in ([first, other], [other, first]):
        collections['security_assessment'] = rows
        assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'FAIL'
    first['properties']['status']['code'] = 'Healthy'
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'


@pytest.mark.parametrize('change', ['uri', 'vm'])
def test_unencrypted_vhd_failure_survives_unknown_other_disk(sw03, change):
    cid = 'azure.cis.legacy_vhds_encrypted'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    collections['storage_account'][0]['properties']['encryption']['services']['blob']['enabled'] = False
    if change == 'uri':
        collections['vm'][0]['properties']['storageProfile']['dataDisks'].append({'vhd': {'uri': 'https://unresolved.blob.core.windows.net/vhds/unknown.vhd'}})
    else:
        collections['vm'].append({'id': VM + '-second'})
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'FAIL'
    collections['storage_account'][0]['properties']['encryption']['services']['blob']['enabled'] = True
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'


def test_vm_assessment_cannot_use_an_unrelated_native_resource_identity(sw03):
    cid = 'azure.cis.endpoint_protection_vms_installed'
    cases, _ = matrix()
    item, collections, policy = copy.deepcopy(cases[cid][:3])
    collections['security_assessment'][0]['id'] = SA
    assert grade(sw03, cid, item, snapshot(collections, policy=policy)) == 'UNKNOWN'
