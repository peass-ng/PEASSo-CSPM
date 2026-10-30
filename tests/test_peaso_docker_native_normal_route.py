"""Normal connector -> SDK HTTP stubs -> engine Docker recommendation verdict."""
from copy import deepcopy
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure,collect_live
from tests.archived_check_contract import evaluate_snapshot
from test_peaso_azure_docker_assessment_native import SCOPE,VM,RID,row
CID='azure.gap.compute_vm_container_security_configurations_vulnerabilities_remediated'
KEY='0677209d-e675-2c6f-e91a-54cef2878663'

@pytest.mark.parametrize('code,expected',[('Unhealthy','FAIL'),('Healthy','UNKNOWN'),('NotApplicable','UNKNOWN')])
def test_normal_read_only_docker_collection_reaches_exact_engine_verdict(monkeypatch,code,expected):
    class Transport:
        tenant=verified_tenant='22222222-2222-2222-2222-222222222222'
        def close(self):pass
        def request(self,url,*,body=None,audience=azure.ARM):
            assert body is None
            path=urlsplit(url).path
            if path==SCOPE+'/providers/Microsoft.Compute/virtualMachines':
                return {'value':[{'id':VM,'name':'vm','type':'Microsoft.Compute/virtualMachines','properties':{}}]}
            if path==VM:return {'id':VM,'name':'vm','type':'Microsoft.Compute/virtualMachines',
                'properties':{'storageProfile':{'osDisk':{'osType':'Linux'}}},'instanceView':{}}
            if path==SCOPE+'/providers/Microsoft.Security/assessments':
                value=row();value['properties'].pop('metadata');value['properties']['status']['code']=code
                return {'value':[value]}
            if path==RID:
                value=row();value['properties']['status']['code']=code;return value
            return {'value':[]}
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:Transport())
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:Transport())
    policy={'status':'collected','scope':SCOPE,'checks':{CID:{'maxReportAgeSeconds':3600,'assessmentKeys':[KEY]}}}
    snapshot=collect_live({'provider':'azure','scopes':[SCOPE],
        'options':{'retries':0,'compliance_policy':policy}},['vm','security_assessment'])
    report=evaluate_snapshot(snapshot,checks=[CID])
    findings=[v for v in report['findings'] if v['check_id']==CID]
    assert len(findings)==1
    assert findings[0]['status']==expected,findings
    assert not any(v['type']=='vm_compliance_applicability' for v in snapshot['collections'])


def test_denied_optional_get_preserves_actual_list_capture_but_does_not_invent_builtin_negative(monkeypatch):
    class Transport:
        tenant=verified_tenant='22222222-2222-2222-2222-222222222222'
        def close(self):pass
        def request(self,url,*,body=None,audience=azure.ARM):
            assert body is None
            path=urlsplit(url).path
            if path==SCOPE+'/providers/Microsoft.Compute/virtualMachines':
                return {'value':[{'id':VM,'name':'vm','type':'Microsoft.Compute/virtualMachines','properties':{}}]}
            if path==VM:return {'id':VM,'name':'vm','type':'Microsoft.Compute/virtualMachines',
                'properties':{'storageProfile':{'osDisk':{'osType':'Linux'}}},'instanceView':{}}
            if path==SCOPE+'/providers/Microsoft.Security/assessments':
                value=row();value['properties'].pop('metadata');return {'value':[value]}
            if path==RID:raise azure.AzureReadError('denied',403)
            return {'value':[]}
    monkeypatch.setattr(azure,'AzureTransport',lambda auth:Transport())
    monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth:Transport())
    policy={'status':'collected','scope':SCOPE,'checks':{CID:{'maxReportAgeSeconds':3600,'assessmentKeys':[KEY]}}}
    snapshot=collect_live({'provider':'azure','scopes':[SCOPE],
        'options':{'retries':0,'compliance_policy':policy}},['vm','security_assessment'])
    value=next(c for c in snapshot['collections'] if c['type']=='security_assessment')['items'][0]
    proof=value['_provenance'];assert proof['source_operation']=='Assessments_List'
    assert 'metadata_expanded' not in proof and 'metadata' not in value['properties']
    assert proof['credential_context_id']==snapshot['metadata']['credential_context_id']
    assert value['properties']['_coverage']['metadata']['status']=='not_collected'
    report=evaluate_snapshot(snapshot,checks=[CID]);assert [f['status'] for f in report['findings']]==['UNKNOWN']
