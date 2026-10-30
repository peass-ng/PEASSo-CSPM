# Historical fixture contracts; current native admission is tested separately.
"""Normal hosted native patch pipeline with inert read-only HTTP responses."""
from copy import deepcopy
from urllib.parse import urlsplit
from tests.test_peaso_azure_patch_installation_hosted_pipeline import NativeAPI,options,validate,SCOPE,VM,CHECK
from peaso.collectors import azure,collect_live
from tests.archived_check_contract import plan_collection, evaluate_snapshot
from peaso.snapshot import make_snapshot

ABSENT=object()
class API(NativeAPI):
    def __init__(self,mode='complete',reboot=ABSENT,result_changes=None):
        super().__init__(mode);self.reboot=reboot;self.result_changes=result_changes or {}
    def request(self,url,*,body=None,audience=None):
        response=super().request(url,body=body,audience=audience)
        if body is None and urlsplit(url).path==VM+'/instanceView' and self.reboot is not ABSENT:
            response['patchStatus']['availablePatchSummary']['rebootPending']=self.reboot
        if body is not None and 'patchinstallationresources' in body['query']:
            for row in response.get('data',[]):row['properties'].update(self.result_changes)
        return response

def run(monkeypatch,*,mode='complete',reboot=ABSENT,result_changes=None,mutate=None,require_actual=True,pci=False):
    api=API(mode,reboot,result_changes);monkeypatch.setattr(azure,'AzureTransport',lambda auth:api);monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:api)
    config=options();config['compliance_policy']['checks'][CHECK].update(requireActualInstallation=require_actual,requirePciCompliance=pci)
    validate(config)
    connector={'provider':'azure','scopes':[SCOPE],'auth':{'method':'token','arm_token':'inert'},'options':config}
    planned=plan_collection({'connector':connector,'checks':[CHECK]})
    snapshot=collect_live(connector,planned)
    if mutate:
        snapshot=deepcopy(snapshot);mutate(snapshot)
        snapshot=make_snapshot('azure',snapshot['scopes'],snapshot['collections'],metadata=snapshot['metadata'],created_at=snapshot['created_at'])
    findings=[f for f in evaluate_snapshot(snapshot,checks=[CHECK],include_not_applicable=True)['findings'] if f['check_id']==CHECK]
    assert len(findings)==1 and api.closed
    run.last=findings;run.snapshot=snapshot;run.api=api
    return findings[0]['status']
def rows(snapshot,kind):return [r for c in snapshot['collections'] if c['type']==kind for r in c['items']]

def test_later_pending_reboot_contradicts_completed_installation_proof(monkeypatch):
    assert run(monkeypatch,reboot=True)=='UNKNOWN',run.last

def test_foreign_vm_or_installation_capture_cannot_certify_updates(monkeypatch):
    states=[]
    for kind in ('vm','vm_patch_installation_result'):
        for field in ('credential_context_id','customer_context_id'):
            def mutate(s,kind=kind,field=field):rows(s,kind)[0]['_provenance'][field]='foreign-capture'
            states.append((kind,field,run(monkeypatch,mutate=mutate)))
    assert all(state=='UNKNOWN' for _,_,state in states),states

def test_current_native_capture_matches_and_reports_real_install_count(monkeypatch):
    assert run(monkeypatch,reboot=False)=='PASS',run.last
    s=run.snapshot
    for kind in ('vm','vm_patch_installation_result'):
        for row in rows(s,kind):
            for field in ('credential_context_id','customer_context_id'):
                assert row['_provenance'][field]==s['metadata'][field]
    assert run.last[0]['evidence']['native_installation']['installed_patch_count']==2

def test_reboot_boolean_is_typed_and_absence_preserves_existing_operation_proof(monkeypatch):
    for value in (None,0,1,'false',[],{}):
        assert run(monkeypatch,reboot=value)=='UNKNOWN',run.last
    assert run(monkeypatch)=='PASS',run.last

def test_missing_patches_are_failure_even_with_pending_reboot(monkeypatch):
    assert run(monkeypatch,mode='missing_patches',reboot=True)=='FAIL',run.last

def test_assessment_only_frozen_contract_does_not_require_installation(monkeypatch):
    assert run(monkeypatch,reboot=True,require_actual=False)=='PASS',run.last
    assert not any(body is not None and 'patchinstallationresources' in body['query'] for _,body in run.api.calls)
    assert 'native_installation' not in run.last[0]['evidence']

def test_denied_missing_or_partial_native_job_source_cannot_pass(monkeypatch):
    for mode in ('denied','missing_result','truncated'):
        assert run(monkeypatch,mode=mode,reboot=False)=='UNKNOWN',run.last

def test_native_operation_counter_status_and_reboot_inconsistency_remain_unknown(monkeypatch):
    for changes in ({'installedPatchCount':True},{'installedPatchCount':3},{'status':'InProgress'},{'status':'Failed'},
                    {'pendingPatchCount':1},{'rebootStatus':'Required'},{'maintenanceWindowExceeded':True}):
        assert run(monkeypatch,reboot=False,result_changes=changes)=='UNKNOWN',run.last

def test_completed_record_cannot_follow_current_assessment(monkeypatch):
    def mutate(s):
        summary=rows(s,'vm')[0]['instanceView']['patchStatus']['availablePatchSummary']
        rows(s,'vm_patch_installation_result')[0]['properties']['lastModifiedDateTime']=summary['lastModifiedTime']
    assert run(monkeypatch,reboot=False,mutate=mutate)=='UNKNOWN',run.last

def test_pci_requires_separate_authority_and_patch_mode_is_not_measurement(monkeypatch):
    assert run(monkeypatch,reboot=False,pci=True)=='UNKNOWN',run.last
    assert 'native_installation' not in run.last[0]['evidence']
    def mutate(s):
        machine=rows(s,'vm')[0];machine['instanceView']['patchStatus'].pop('availablePatchSummary')
        machine['properties']['osProfile']={'linuxConfiguration':{'patchSettings':{'patchMode':'AutomaticByPlatform'}}}
    assert run(monkeypatch,reboot=False,mutate=mutate)=='UNKNOWN',run.last
