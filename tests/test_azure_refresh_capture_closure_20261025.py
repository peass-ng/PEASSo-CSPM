"""Exercise exact refresh grant/claim functions without importing native registry."""
import ast
import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from peaso.snapshot import make_snapshot
from peaso.storage import StoreError, FileArtifacts
from peaso.storage.artifacts import check_reference, job_prefix
from peaso.image_findings import SCHEMA

SOURCE=Path(__file__).parents[1]/'peaso/server/scan_resume.py'
FUNCTIONS={'requested_refresh_sections','_refresh_binding','_refresh_digest','_refresh_manifest_json',
           '_refresh_native_incomplete','prove_section_refresh','consume_section_refresh',
           'section_refresh_payload','validate_claimed_section_refresh'}
ASSIGNMENTS={'_REFRESH_SEAL','_REFRESH_ISSUED','_REFRESH_LOCK','_REFRESH_SPECS'}

def exact_api_functions():
    before=set(sys.modules)
    tree=ast.parse(SOURCE.read_text());nodes=[]
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and (node.name in FUNCTIONS or node.name=='_RefreshGrant'):nodes.append(node)
        elif isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ASSIGNMENTS for t in node.targets):nodes.append(node)
    ns={'json':json,'StoreError':StoreError,'job_prefix':job_prefix,'check_reference':check_reference}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(SOURCE),'exec'),ns)
    assert not ({'peaso.engine','peaso.checks'} & (set(sys.modules)-before)), 'No cold native engine import'
    return ns


def setup_case(tmp_path,provider,selected):
    ns=exact_api_functions();art=FileArtifacts(tmp_path/'artifacts');ident='a'*32;tenant='alice'
    scopes={'azure':['/subscriptions/11111111-1111-1111-1111-111111111111'],'gcp':['projects/qa-owned'],'k8s':['qa-owned']}[provider]
    specs=ns['_REFRESH_SPECS'][provider]
    snapshot=make_snapshot(provider,scopes,[{'type':kind,'scope':scopes[0],'status':'collected','items':[{'id':'owned-'+section,marker:{'complete':False}}]} for section,(_,kind,marker) in specs.items()])
    snapshot_ref=art.put(tenant,ident,'snapshot',snapshot)
    projection={'schema':SCHEMA,'scan_id':ident,'observations':[]}
    projection_ref=art.put(tenant,ident,'detail',projection)
    manifest={'bundle_version':1,'summary':{'provider':provider,'scopes':scopes,'snapshot_id':snapshot['snapshot_id'],'snapshot_metadata':{}},'image_vulnerability_scan':{'selected':True,'artifact':projection_ref}}
    report_ref=art.put(tenant,ident,'manifest',manifest)
    selected_checks=[specs[section][0] for section in selected]
    row={'tenant':tenant,'id':ident,'connector_id':'connector','status':'completed','snapshot':snapshot_ref,'report':report_ref,'checkpoint_sequence':0,'resume_attempt':2,
         'connector':json.dumps({'data':{'provider':provider,'scopes':scopes,'input_mode':'live'}}),
         'data':json.dumps({'connector_id':'connector','content_checks':selected_checks,'categories':['hardening']})}
    store=SimpleNamespace(checkpoint_collections=lambda owner,scan:[])
    connector={'provider':provider,'scopes':scopes,'auth':{}}
    return ns,art,row,store,connector,snapshot


@pytest.mark.parametrize('requested',[['images'],['leaks'],['images','leaks'],['leaks','images']])
def test_both_originally_selected_expand_and_claim_exact_descriptors(tmp_path,requested):
    ns,art,row,store,connector,snapshot=setup_case(tmp_path,'azure',['images','leaks']);original=copy.deepcopy(row)
    grant=ns['prove_section_refresh'](row,store,art,requested)
    plan=ns['consume_section_refresh'](grant,row)
    assert plan['sections']==['images','leaks']
    assert plan['checks']==[ns['_REFRESH_SPECS']['azure'][key][0] for key in ['images','leaks']]
    assert plan['kinds']==[ns['_REFRESH_SPECS']['azure'][key][1] for key in ['images','leaks']]
    assert row==original and plan['binding']['data']==original['data']
    claimed=dict(row,resume_attempt=3,resume_phase='collector',native_refresh=plan,status='queued')
    accepted,prior,revisions=ns['validate_claimed_section_refresh'](claimed,[],art,connector)
    assert accepted==plan and prior==snapshot and revisions=={}
    with pytest.raises(StoreError):ns['consume_section_refresh'](grant,row)


@pytest.mark.parametrize('selected,requested',[(['images'],['leaks']),(['leaks'],['images']),(['images'],['images','leaks']),(['leaks'],['images','leaks']),([],['images'])])
def test_never_enable_an_unselected_scanner(tmp_path,selected,requested):
    ns,art,row,store,_,_=setup_case(tmp_path,'azure',selected)
    with pytest.raises(StoreError) as exc:ns['prove_section_refresh'](row,store,art,requested)
    assert exc.value.status==409
    assert len(ns['_REFRESH_ISSUED'])==0


@pytest.mark.parametrize('provider',['gcp','k8s'])
@pytest.mark.parametrize('requested',[['images'],['leaks'],['images','leaks']])
def test_other_providers_do_not_expand(tmp_path,provider,requested):
    ns,art,row,store,connector,_=setup_case(tmp_path,provider,['images','leaks'])
    grant=ns['prove_section_refresh'](row,store,art,requested);plan=ns['consume_section_refresh'](grant,row)
    assert plan['sections']==sorted(requested)
    accepted,_,_=ns['validate_claimed_section_refresh'](dict(row,resume_attempt=3,resume_phase='collector',native_refresh=plan),[],art,connector)
    assert accepted['sections']==sorted(requested)


@pytest.mark.parametrize('only',['images','leaks'])
def test_single_original_selection_is_never_broadened(tmp_path,only):
    ns,art,row,store,_,_=setup_case(tmp_path,'azure',[only]);grant=ns['prove_section_refresh'](row,store,art,[only]);plan=ns['consume_section_refresh'](grant,row)
    assert plan['sections']==[only] and len(plan['checks'])==len(plan['kinds'])==1


def test_original_cas_and_claim_descriptor_and_native_incomplete_fences_remain(tmp_path):
    ns,art,row,store,connector,snapshot=setup_case(tmp_path,'azure',['images','leaks'])
    grant=ns['prove_section_refresh'](row,store,art,['leaks'])
    with pytest.raises(StoreError):ns['consume_section_refresh'](grant,dict(row,report=row['snapshot']))
    grant=ns['prove_section_refresh'](row,store,art,['leaks']);plan=ns['consume_section_refresh'](grant,row)
    wrong=copy.deepcopy(plan);wrong['checks']=wrong['checks'][:1];wrong['plan_sha256']=ns['_refresh_digest']({k:v for k,v in wrong.items() if k!='plan_sha256'})
    claimed=dict(row,resume_attempt=3,resume_phase='collector',native_refresh=wrong)
    with pytest.raises(ValueError,match='selection changed'):ns['validate_claimed_section_refresh'](claimed,[],art,connector)
    for envelope in snapshot['collections']:
        for item in envelope['items']:
            next(v for v in item.values() if isinstance(v,dict))['complete']=True
    assert ns['_refresh_native_incomplete'](snapshot,[ns['_REFRESH_SPECS']['azure'][x] for x in ['images','leaks']])==(False,False)
