"""Inert VM patch source and proof field authority checks."""
import pytest
from peaso.collectors.azure_wave_compute_native import KIND, collect
from tests.test_peaso_azure_wave_compute_native_collector import Reader as _CollectorReader, _result, _policy
from tests.test_peaso_azure_wave_compute_native_patch import _vm, _check

class Reader(_CollectorReader):
    # The production reader publishes settled-envelope progress; this inert
    # reader has no progress sink.
    def progress(self, phase=None, scope="", settled=None):
        pass

def deny(row,key):
    row.setdefault("_coverage",{})[key]={"status":"denied"}

def proof(vm):
    return {"id":vm["id"]+"/patchInstallationResults/operation-1", "type":"patchinstallationresults",
        "_provenance":{"source_operation":"ResourceGraph:patchinstallationresources","read_only":True},
        "properties":{"installationActivityId":"operation-1","lastModifiedDateTime":"2026-10-16T09:20:00Z",
                      "status":"Succeeded","installedPatchCount":3,"failedPatchCount":0,"pendingPatchCount":0,
                      "maintenanceWindowExceeded":False,"rebootStatus":"NotNeeded"}}

@pytest.mark.parametrize("part,key,value", [
    ("assessment","status","Succeeded"),
    ("assessment","criticalAndSecurityPatchCount",0),
    ("assessment","criticalAndSecurityPatchCount",2),
    ("assessment","rebootPending",False),
    ("installation","status","Succeeded"),
    ("installation","installedPatchCount",3),
])
def test_denied_vm_patch_field_cannot_select_pass_or_fail(part,key,value):
    vm=_vm();patch=vm["properties"]["instanceView"]["patchStatus"]
    target=patch["availablePatchSummary"] if part=="assessment" else patch["lastPatchInstallationSummary"]
    target[key]=value;deny(target,key)
    assert _check(vm)["state"]=="UNKNOWN"

@pytest.mark.parametrize("key",["status","rebootStatus"])
def test_denied_result_property_cannot_complete_proof(key):
    vm=_vm();result=proof(vm);deny(result["properties"],key)
    assert _check(vm,installation_result=result)["state"]=="UNKNOWN"

def test_denied_assessment_blocks_assessment_only_pass():
    vm=_vm();summary=vm["properties"]["instanceView"]["patchStatus"]["availablePatchSummary"]
    deny(summary,"criticalAndSecurityPatchCount")
    assert _check(vm,require_actual_installation=False)["state"]=="UNKNOWN"

def test_collector_does_not_select_denied_operation_id():
    reader=Reader([_result()]);summary=reader.collections[0]["items"][0]["instanceView"]["patchStatus"]["lastPatchInstallationSummary"]
    deny(summary,"installationActivityId")
    collect(reader,None,[reader.collections[0]["scope"]],{KIND},_policy())
    assert reader.calls==[] and reader.collections[-1]["items"]==[]

def test_collector_rejects_denied_projected_status():
    row=_result();deny(row["properties"],"status")
    reader=Reader([row])
    with pytest.raises(ValueError,match="unavailable|coverage"):
        collect(reader,None,[reader.collections[0]["scope"]],{KIND},_policy())

def test_policy_denial_cannot_authorize_arg_query():
    options=_policy();policy=options["compliance_policy"]["checks"]["azure.gap.compute_vm_system_updates_installed"]
    deny(policy,"requireActualInstallation")
    reader=Reader([_result()]);collect(reader,None,[reader.collections[0]["scope"]],{KIND},options)
    # An unapproved scope is recorded as unknown with an explicit policy error, never collected.
    assert reader.calls==[] and reader.collections[-1]["status"]=="unknown"
    assert reader.collections[-1]["error"]["code"]=="actual_installation_policy_not_approved"


def test_denied_result_provenance_cannot_complete_proof():
    vm=_vm();result=proof(vm);deny(result["_provenance"],"source_operation")
    assert _check(vm,installation_result=result)["state"]=="UNKNOWN"


def test_denied_vm_identity_cannot_prove_result():
    vm=_vm();deny(vm,"id")
    assert _check(vm)["state"]=="UNKNOWN"


def test_denied_inventory_items_cannot_authorize_query():
    reader=Reader([_result()]);deny(reader.collections[0],"items")
    with pytest.raises(ValueError,match="unavailable"):
        collect(reader,None,[reader.collections[0]["scope"]],{KIND},_policy())
    assert reader.calls==[]
