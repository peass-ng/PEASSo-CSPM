"""Guard real source bindings and replay independent signed/native test facts."""
from copy import deepcopy
import gzip
import json
from pathlib import Path
import pytest
from tests.provider_observation_residual_successors_20261020 import azure_case
from peaso.checks.azure_native_review_copy_20261020 import reviewed_fields
from peaso.checks import CHECKS
from peaso.checks.azure_bulk_clarity_reviewed import ROWS, _digest, description, remediation
from peaso.checks.azure_bulk_finding_summary import evidence_summary
from peaso.checks import storage_immutability_native_successor as immutability

ROOT=Path(__file__).resolve().parents[1]
CHECK_BY_ID={c.id:c for c in CHECKS}
CASES=json.loads(gzip.decompress((ROOT/'tests/fixtures/azure_bulk_clarity_reviewed.json.gz').read_bytes()))

@pytest.fixture(scope='module')
def originals():
    descriptions=json.loads((ROOT/'peaso/rulepacks/check_descriptions.json').read_text())['checks']
    from peaso.checks.azure_vm_ssh_source_correction import description as ssh_description
    descriptions['azure_vm_8_2_1_1_712e1ad']=ssh_description()
    rems={cid:None for cid,row in ROWS.items() if row['remediation_base_sha256']==_digest(None)}
    for path in (ROOT/'peaso/rulepacks').glob('remediation*.json'):
        packed=json.loads(path.read_text())
        if isinstance(packed,dict):
            for cid,row in packed.items():
                if cid in ROWS and _digest(row)==ROWS[cid]['remediation_base_sha256']:rems[cid]=row
    assert set(rems)==set(ROWS)
    return descriptions,rems

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_short_description_preserves_signed_contract(cid,originals):
    original=originals[0][cid];before=deepcopy(original);actual=description(cid,original)
    assert original==before
    assert len(actual['description'].split())<=40
    changed={'description'}
    if cid=='azure_application_gateway_app_http_logs_enabled_2de0361':
        fields=reviewed_fields(cid,'description',ROWS[cid]['description_fields'])
        assert set(fields)=={'description','pass_when','fail_when','not_applicable_when'}
        assert all(actual[k]==v for k,v in fields.items())
        changed=set(fields)
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in original.items() if k not in changed}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_short_actions_preserve_approved_commands_without_promoting_drafts(cid,originals):
    original=originals[1][cid];before=deepcopy(original);actual=remediation(cid,original)
    assert original==before
    assert 1<=len(actual['steps'])<=2 and len(actual['steps'][0].split())<=40
    assert len(actual['caveats'])==1
    changed=set(ROWS[cid]['remediation_fields'])
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in (original or {}).items() if k not in changed}
    if not original or original.get('review_status')!='approved':
        assert actual['review_status']=='approved' and actual['cli']==[] and not actual.get('iac')
    if original is None:
        assert actual['field_binding']['fields'] and actual['references']
        assert all(r['url'].startswith('https://learn.microsoft.com/') for r in actual['references'])

@pytest.mark.parametrize('kind,apply',[('description',description),('remediation',remediation)])
def test_source_hash_guards_fail_closed(kind,apply,originals):
    cid=sorted(ROWS)[0]
    original=deepcopy(originals[kind=='remediation'][cid]) or {}
    original['unreviewed']='source drift'
    with pytest.raises(ValueError,match='Reviewed Azure bulk clarity base changed'):apply(cid,original)


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_replay_real_registered_callback_facts_and_concise_evidence(cid):
    # Captured from the existing signed-wave test constructors and independent
    # native HTTP-stub tests. No policy or credentials are fetched at runtime.
    assert cid in CASES and 'FAIL' in CASES[cid]
    assert 'PASS' in CASES[cid] or cid=='azure.other.audit_storage_access_logging'
    for expected,case in CASES[cid].items():
        native,successor_evidence=azure_case(cid,expected,case)
        item,index=deepcopy((native['item'],native['index']))
        evaluator=immutability._registered.evaluate if cid==immutability.CHECK_ID else CHECK_BY_ID[cid].evaluate
        status,evidence=evaluator(item,index)
        assert status==expected,(cid,expected,status,evidence)
        if successor_evidence is None:
            assert json.loads(json.dumps(evidence, sort_keys=True))==case['evidence']
        finding={'provider':'azure','status':status,'check_id':cid,'evidence':evidence};before=deepcopy(finding)
        assert bool(evidence_summary(finding))==(status=='FAIL')
        assert finding==before


def test_unknown_or_unowned_facts_never_become_positive_observations():
    cid=next(iter(ROWS))
    for status in ['PASS','UNKNOWN','MANUAL','DENIED','EMPTY','NOT_APPLICABLE']:
        assert evidence_summary({'provider':'azure','status':status,'check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'azure','status':'FAIL','check_id':cid,'evidence':None}) is None
    assert evidence_summary({'provider':'azure','status':'FAIL','check_id':'unowned','evidence':{}}) is None
    original={'summary':'keep','nested':[]};out=remediation('unowned',original);out['nested'].append(1)
    assert original['nested']==[]


def test_certificate_summary_uses_actual_modulus_and_never_certificate_contents():
    finding={'provider':'azure','status':'FAIL','check_id':'azure_vault_3_7_1_2_532ecd2','evidence':{'outcomes':[{'status':'FAIL','measured_rsa_modulus_bits':1024,'cer':'DO-NOT-PRINT'}]}}
    summary=evidence_summary(finding)
    assert '1024-bit RSA' in summary and 'DO-NOT-PRINT' not in summary


def test_corrected_ssh_dynamic_guidance_preserves_provenance_and_references():
    from peaso.checks.azure_bulk_clarity_reviewed import dynamic_remediation
    from peaso.checks.azure_vm_ssh_source_correction import REMEDIATION,SOURCE_URL,correction_provenance
    cid='azure_vm_8_2_1_1_712e1ad'
    original={'review_status':'approved','summary':REMEDIATION,
              'steps':['Review the complete VM launch SSH public-key array and the applicable source criterion with the asset owner.',
                       'If this criterion is adopted, update the approved VM deployment configuration and verify the recorded array is explicitly empty.'],
              'caveats':['This criterion does not establish effective guest SSH or password authentication.'],
              'references':[{'title':'Original Azure PCI source at pinned revision','url':SOURCE_URL}],
              'source_correction':correction_provenance()}
    result=dynamic_remediation(cid,original)
    assert len(result['steps'])==1
    assert result['source_correction']==original['source_correction']
    assert result['references']==original['references']

    original['source_correction']={}
    with pytest.raises(ValueError,match='dynamic remediation base changed'):dynamic_remediation(cid,original)
