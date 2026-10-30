"""Evidence boundaries for the signed Azure sw02 slice."""
from __future__ import annotations

import copy

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw02 as sw02


SCOPE = "/subscriptions/sub1"
BASE = SCOPE + "/resourceGroups/rg/providers"
VM = BASE + "/Microsoft.Compute/virtualMachines/vm1"
NIC = BASE + "/Microsoft.Network/networkInterfaces/nic1"
VNET = BASE + "/Microsoft.Network/virtualNetworks/vnet1"
SUBNET = VNET + "/subnets/default"
FW = BASE + "/Microsoft.Network/firewallPolicies/p1"
VMSS = BASE + "/Microsoft.Compute/virtualMachineScaleSets/ss1"
INSTANCE = VMSS + "/virtualMachines/0"
MASTER = "/providers/Microsoft.Management/managementGroups/master"


def scoped(collections, *, policy=None, scope=SCOPE):
    return {"context": {"provider": "azure", "scope": scope,
             "created_at": "2026-10-12T00:00:00+00:00",
             "metadata": {"sw02": {"status": "collected", **(policy or {})}}},
            "collections": {kind: [{"type": kind, "scope": scope,
                "status": "empty" if not rows else "collected", "items": rows}]
                for kind, rows in collections.items()},
            **{kind: [{"type": kind, "scope": scope, "data": row} for row in rows]
               for kind, rows in collections.items()}}


def run(cid, row, facts):
    return evaluate_check(cid, row, facts)[0]


def vm_facts(vnet_id=VNET):
    vm = {"id": VM, "properties": {"networkProfile": {"networkInterfaces": [{"id": NIC}]}}}
    nic = {"id": NIC, "properties": {"virtualMachine": {"id": VM},
        "ipConfigurations": [{"properties": {"subnet": {"id": SUBNET}}}]}}
    vnet = {"id": VNET, "properties": {"subnets": [{"id": SUBNET}]}}
    return vm, scoped({"vm": [vm], "nic": [nic], "vnet": [vnet]},
                      policy={"approvedVnetIds": [vnet_id]})


def group(name="g1", rules=None, *, kind="FirewallPolicyFilterRuleCollection"):
    return {"id": FW + "/ruleCollectionGroups/" + name,
            "_provenance": {"representation": "full", "source_operation": "get_rule_collection_group",
                            "parent_policy_id": FW, "read_only": True},
            "properties": {"ruleCollections": [{"ruleCollectionType": kind,
                "rules": [{"ruleType": "NetworkRule", "name": "allow-approved"}]
                    if rules is None else rules}]}}


def firewall(groups, *, base=None):
    properties = {"basePolicy": None if base is None else {"id": base}}
    return {"id": FW, "properties": properties, "ruleCollectionGroups": groups,
            "_provenance": {"representation": "full", "source_operation": "get", "read_only": True},
            "_coverage": {"ruleCollectionGroups": {"status": "empty" if not groups else "collected"}}}


def vmss(critical=0, security=0):
    return {"id": VMSS, "_coverage": {"instances": {"status": "collected"}},
        "instances": [{"id": INSTANCE, "patchAssessment": {
            "_provenance": {"source": "ResourceGraph.patchassessmentresources.summary", "latest": True},
            "resourceId": INSTANCE, "status": "Succeeded",
            "lastModifiedDateTime": "2026-10-11T00:00:00Z",
            "availablePatchCountByClassification": {"critical": critical, "security": security},
            "errorDetails": [], "unresolvedClassification": False}}]}


def test_vm_vnet_pass_fail_unknown_and_not_applicable():
    row, facts = vm_facts()
    assert run(sw02.VM_VNET_ID, row, facts) == "PASS"
    row, facts = vm_facts(BASE + "/Microsoft.Network/virtualNetworks/other")
    assert run(sw02.VM_VNET_ID, row, facts) == "FAIL"
    row, facts = vm_facts()
    facts["context"]["metadata"]["sw02"]["approvedVnetIds"] = [
        BASE + "/Microsoft.Network/virtualNetworks/other", VNET]
    assert run(sw02.VM_VNET_ID, row, facts) == "PASS"
    row, facts = vm_facts()
    other = BASE + "/Microsoft.Network/virtualNetworks/other"
    facts["collections"]["vnet"][0]["items"].append({"id": other, "properties": {"subnets": []}})
    facts["vnet"].append({"type": "vnet", "scope": SCOPE, "data": facts["collections"]["vnet"][0]["items"][-1]})
    facts["context"]["metadata"]["sw02"]["approvedVnetIds"] = [other]
    assert run(sw02.VM_VNET_ID, row, facts) == "FAIL"
    row, facts = vm_facts()
    row["properties"]["networkProfile"]["networkInterfaces"] = []
    assert run(sw02.VM_VNET_ID, row, facts) == "NOT_APPLICABLE"
    row, facts = vm_facts()
    facts["collections"]["nic"][0]["status"] = "partial"
    assert run(sw02.VM_VNET_ID, row, facts) == "UNKNOWN"
    row, facts = vm_facts()
    del facts["context"]["metadata"]["sw02"]["approvedVnetIds"]
    assert run(sw02.VM_VNET_ID, row, facts) == "UNKNOWN"
    row, facts = vm_facts()
    facts["nic"][0]["data"]["properties"]["ipConfigurations"][0]["properties"]["subnet"]["id"] = "invalid"
    assert run(sw02.VM_VNET_ID, row, facts) == "UNKNOWN"


def test_firewall_policy_effective_rules_and_base_ancestry():
    row = firewall([group()])
    facts = scoped({"firewall_policy": [row]})
    assert run(sw02.FIREWALL_HAS_RULES_ID, row, facts) == "PASS"
    empty = firewall([group(rules=[])])
    assert run(sw02.FIREWALL_HAS_RULES_ID, empty,
               scoped({"firewall_policy": [empty]})) == "FAIL"
    del empty["properties"]["basePolicy"]
    assert run(sw02.FIREWALL_HAS_RULES_ID, empty,
               scoped({"firewall_policy": [empty]})) == "UNKNOWN"
    assert run(sw02.FIREWALL_GROUP_RULES_ID, empty,
               scoped({"firewall_policy": [empty]})) == "FAIL"
    parent_id = BASE + "/Microsoft.Network/firewallPolicies/base"
    parent = copy.deepcopy(row)
    parent["id"] = parent_id
    parent["ruleCollectionGroups"][0]["id"] = parent_id + "/ruleCollectionGroups/g1"
    parent["ruleCollectionGroups"][0]["_provenance"]["parent_policy_id"] = parent_id
    child = firewall([], base=parent_id)
    facts = scoped({"firewall_policy": [child, parent]})
    assert run(sw02.FIREWALL_HAS_RULES_ID, child, facts) == "PASS"
    assert run(sw02.FIREWALL_GROUP_RULES_ID, child, facts) == "NOT_APPLICABLE"
    del facts["firewall_policy"][1]
    assert run(sw02.FIREWALL_HAS_RULES_ID, child, facts) == "UNKNOWN"


def test_firewall_groups_complete_and_malformed_boundaries():
    row = firewall([group(), group("g2", rules=[])])
    facts = scoped({"firewall_policy": [row]})
    assert run(sw02.FIREWALL_HAS_RULES_ID, row, facts) == "PASS"
    assert run(sw02.FIREWALL_GROUP_RULES_ID, row, facts) == "FAIL"
    row = firewall([group()])
    facts = scoped({"firewall_policy": [row]})
    assert run(sw02.FIREWALL_GROUP_RULES_ID, row, facts) == "PASS"
    row["_coverage"]["ruleCollectionGroups"]["status"] = "partial"
    assert run(sw02.FIREWALL_HAS_RULES_ID, row, facts) == "UNKNOWN"
    assert run(sw02.FIREWALL_GROUP_RULES_ID, row, facts) == "UNKNOWN"
    row = firewall([group()])
    del row["ruleCollectionGroups"][0]["_provenance"]
    facts = scoped({"firewall_policy": [row]})
    assert run(sw02.FIREWALL_GROUP_RULES_ID, row, facts) == "UNKNOWN"
    row = firewall([group(rules=[{"ruleType": "NatRule", "name": "bad"}])])
    assert run(sw02.FIREWALL_HAS_RULES_ID, row,
               scoped({"firewall_policy": [row]})) == "UNKNOWN"
    row = firewall([])
    assert run(sw02.FIREWALL_GROUP_RULES_ID, row,
               scoped({"firewall_policy": [row]})) == "NOT_APPLICABLE"


def test_vmss_patch_pass_fail_unknown_and_not_applicable():
    row = vmss()
    facts = scoped({"vm_scale_set": [row]}, policy={"maxAssessmentAgeSeconds": 172800})
    assert run(sw02.VMSS_PATCH_ID, row, facts) == "PASS"
    row = vmss(critical=1)
    facts = scoped({"vm_scale_set": [row]}, policy={"maxAssessmentAgeSeconds": 172800})
    assert run(sw02.VMSS_PATCH_ID, row, facts) == "FAIL"
    uncertain = copy.deepcopy(row["instances"][0])
    uncertain["id"] = VMSS + "/virtualMachines/1"
    uncertain["patchAssessment"]["resourceId"] = uncertain["id"]
    del uncertain["patchAssessment"]["availablePatchCountByClassification"]
    row["instances"].append(uncertain)
    assert run(sw02.VMSS_PATCH_ID, row, facts) == "FAIL"
    row = vmss()
    facts = scoped({"vm_scale_set": [row]}, policy={"maxAssessmentAgeSeconds": 172800})
    row["instances"][0]["patchAssessment"]["lastModifiedDateTime"] = "2026-09-01T00:00:00Z"
    assert run(sw02.VMSS_PATCH_ID, row, facts) == "UNKNOWN"
    row["instances"][0]["patchAssessment"]["lastModifiedDateTime"] = "2026-10-11T00:00:00Z"
    del row["instances"][0]["patchAssessment"]["errorDetails"]
    assert run(sw02.VMSS_PATCH_ID, row, facts) == "UNKNOWN"
    row = vmss()
    facts = scoped({"vm_scale_set": [row]}, policy={"maxAssessmentAgeSeconds": 172800})
    facts["collections"]["vm_scale_set"][0]["status"] = "partial"
    assert run(sw02.VMSS_PATCH_ID, row, facts) == "UNKNOWN"
    row = vmss()
    row["instances"] = []
    row["_coverage"]["instances"]["status"] = "empty"
    assert run(sw02.VMSS_PATCH_ID, row,
               scoped({"vm_scale_set": [row]})) == "NOT_APPLICABLE"


def mg_facts(descendants=None):
    if descendants is None:
        descendants = [{"id": MASTER + "/subscriptions/sub1", "name": "sub1",
            "type": "Microsoft.Management/managementGroups/subscriptions"}]
    facts = scoped({"subscription": [{"id": SCOPE}],
                    "management_group_descendant": descendants},
                   policy={"expectedManagementGroupId": MASTER})
    facts["collections"]["management_group_descendant"][0]["_provenance"] = {
        "source_operation": "get_descendants", "parent_management_group_id": MASTER,
        "pages_complete": True}
    return facts


def test_management_group_descendants_pass_fail_unknown_and_not_applicable():
    facts = mg_facts()
    assert run(sw02.MG_DESCENDANT_ID, facts["context"], facts) == "PASS"
    facts = mg_facts([])
    assert run(sw02.MG_DESCENDANT_ID, facts["context"], facts) == "FAIL"
    facts = mg_facts()
    facts["collections"]["management_group_descendant"][0]["status"] = "partial"
    assert run(sw02.MG_DESCENDANT_ID, facts["context"], facts) == "UNKNOWN"
    facts = mg_facts()
    del facts["context"]["metadata"]["sw02"]["expectedManagementGroupId"]
    assert run(sw02.MG_DESCENDANT_ID, facts["context"], facts) == "UNKNOWN"
    facts = mg_facts()
    facts["management_group_descendant"][0]["data"]["name"] = "other"
    assert run(sw02.MG_DESCENDANT_ID, facts["context"], facts) == "UNKNOWN"
    facts = mg_facts([])
    facts["collections"]["subscription"][0]["status"] = "empty"
    facts["collections"]["subscription"][0]["items"] = []
    facts["subscription"] = []
    assert run(sw02.MG_DESCENDANT_ID, facts["context"], facts) == "NOT_APPLICABLE"


def test_proven_vm_attachment_failure_survives_unresolved_other_nic():
    row, facts = vm_facts(BASE + '/Microsoft.Network/virtualNetworks/other')
    row['properties']['networkProfile']['networkInterfaces'].append({'id': NIC + '-missing'})
    assert run(sw02.VM_VNET_ID, row, facts) == 'FAIL'
    row['properties']['networkProfile']['networkInterfaces'].reverse()
    assert run(sw02.VM_VNET_ID, row, facts) == 'FAIL'


def test_wrong_native_vm_resource_kind_is_unknown():
    row, facts = vm_facts()
    row['id'] = NIC
    facts['nic'][0]['data']['properties']['virtualMachine']['id'] = NIC
    assert run(sw02.VM_VNET_ID, row, facts) == 'UNKNOWN'


def test_firewall_group_requires_direct_child_and_read_only_get():
    for mutation in ('nested', 'writable'):
        row = firewall([group()])
        if mutation == 'nested':
            row['ruleCollectionGroups'][0]['id'] += '/ruleCollections/extra'
        else:
            row['ruleCollectionGroups'][0]['_provenance']['read_only'] = False
        for cid in (sw02.FIREWALL_HAS_RULES_ID, sw02.FIREWALL_GROUP_RULES_ID):
            assert run(cid, row, scoped({'firewall_policy': [row]})) == 'UNKNOWN'


def test_firewall_terminal_base_requires_authoritative_get():
    row = firewall([group()])
    del row['_provenance']
    assert run(sw02.FIREWALL_HAS_RULES_ID, row, scoped({'firewall_policy': [row]})) == 'UNKNOWN'


def test_positive_patch_count_is_failure_despite_unresolved_other_counts():
    for count in (0, 1):
        row = vmss(critical=count)
        row['instances'][0]['patchAssessment']['errorDetails'] = [{'code': 'OtherClassificationUnavailable'}]
        row['instances'][0]['patchAssessment']['unresolvedClassification'] = True
        assert run(sw02.VMSS_PATCH_ID, row, scoped({'vm_scale_set': [row]},
                   policy={'maxAssessmentAgeSeconds': 172800})) == ('FAIL' if count else 'UNKNOWN')


def test_subscription_wrapper_and_native_envelope_must_agree():
    facts = mg_facts()
    facts['subscription'][0]['scope'] = '/subscriptions/foreign'
    assert run(sw02.MG_DESCENDANT_ID, facts['context'], facts) == 'UNKNOWN'
    facts = mg_facts()
    facts['collections']['subscription'][0]['items'] = [{'id': '/subscriptions/foreign'}]
    assert run(sw02.MG_DESCENDANT_ID, facts['context'], facts) == 'UNKNOWN'


def test_management_group_descendant_native_id_and_malformed_suffix():
    facts = mg_facts([{'id': SCOPE, 'name': 'sub1', 'type': 'Microsoft.Management/managementGroups/subscriptions'}])
    assert run(sw02.MG_DESCENDANT_ID, facts['context'], facts) == 'PASS'
    facts = mg_facts([{'id': 'foreign-prefix/subscriptions/sub1', 'name': 'sub1',
                      'type': 'Microsoft.Management/managementGroups/subscriptions'}])
    assert run(sw02.MG_DESCENDANT_ID, facts['context'], facts) == 'UNKNOWN'


def test_approved_vnets_and_subnet_ids_must_have_exact_resource_types():
    row, facts = vm_facts()
    facts['context']['metadata']['sw02']['approvedVnetIds'] = [NIC]
    assert run(sw02.VM_VNET_ID, row, facts) == 'UNKNOWN'
    row, facts = vm_facts()
    nested = SUBNET + '/nested/child'
    facts['nic'][0]['data']['properties']['ipConfigurations'][0]['properties']['subnet']['id'] = nested
    facts['vnet'][0]['data']['properties']['subnets'][0]['id'] = nested
    assert run(sw02.VM_VNET_ID, row, facts) == 'UNKNOWN'


def test_empty_firewall_group_failure_survives_another_malformed_rule_array():
    empty = group('empty', rules=[])
    unresolved = group('unresolved')
    unresolved['properties']['ruleCollections'][0]['rules'] = None
    for groups in ([empty, unresolved], [unresolved, empty]):
        row = firewall(groups)
        assert run(sw02.FIREWALL_GROUP_RULES_ID, row, scoped({'firewall_policy': [row]})) == 'FAIL'
    row = firewall([unresolved])
    assert run(sw02.FIREWALL_GROUP_RULES_ID, row, scoped({'firewall_policy': [row]})) == 'UNKNOWN'
