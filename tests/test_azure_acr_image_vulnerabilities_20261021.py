"""Offline native ARM/ACR and owned-file lifecycle tests for AZ-2."""
from copy import deepcopy
import json
import shutil
from pathlib import Path
import pytest

@pytest.fixture
def proposal():
    from peaso.collectors import azure_acr_image_secret_indicators as acr
    from peaso.collectors import azure
    from peaso.collectors import azure_acr_image_vulnerabilities_20261021 as native
    from peaso.checks import azure_acr_image_vulnerabilities_20261021 as check
    return acr, azure, native, check


def options(native,target,enabled=True):
    return {native.ENABLE:enabled,native.OPTION:[deepcopy(target)],
            '_image_vulnerability_scan_kinds':[native.KIND]}


def index(native,result,scope):
    import peaso.image_findings
    rows=result['rows']
    meta=native.selection_metadata(options(native,rows[0][native.MARKER]['selection']),[scope])
    meta[native.KIND+'_receipts']=result['receipts']
    meta['context_binding']='scan_local'
    meta['credential_context_id']='offline-credential-context'
    meta['customer_context_id']='offline-customer-context'
    for row in rows:
        row['_provenance']['credential_context_id']=meta['credential_context_id']
        row['_provenance']['customer_context_id']=meta['customer_context_id']
    collection={'type':native.KIND,'scope':scope,'status':'collected','items':rows,
        '_provenance':{'credential_context_id':meta['credential_context_id'],
                       'customer_context_id':meta['customer_context_id']}}
    return rows[0],{'context':{'provider':'azure','scope':scope,'metadata':meta},
                    'collections':{native.KIND:[collection]}}


def fake_runner(status='PASS',mutate=None):
    def run(image,manifest,config,layers,**kwargs):
        verifier=kwargs['native_verifier']
        assert verifier()==image
        if mutate is not None:mutate(layers)
        assert kwargs['enabled'] is True and kwargs['archive_format']=='docker'
        findings=[]
        if status=='FAIL':
            findings=[{'vulnerability_id':'CVE-2026-12345','severity':'HIGH',
                'package_types':['debian'],'package':'example','version':'1.0',
                'fixed_in':['1.1'],'fix_status':'affected','classes':['os-pkgs'],
                'image_digest':image['manifest_digest']}]
        return {'image':image,'status':status,'complete':status!='UNKNOWN',
            'scan_complete':status!='UNKNOWN','coverage_status':'UNKNOWN' if status=='UNKNOWN' else 'COMPLETE',
            'database':{'fresh':status!='UNKNOWN'},'findings':findings,
            'archive':{'format':'docker','manifest_digest':image['manifest_digest'],
                'config_digest':image['config_digest'],'expanded_bytes':len(config)+10240,
                'members':1}}
    return run


def collect(proposal,monkeypatch,tmp_path,*,img=None,enabled=True,runner=None,overrides=None,db=None):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    img=img or existing.image()
    existing.capture(monkeypatch,img=img,overrides=overrides,collect=False)
    class Outer:
        def check_cancelled(self):pass
        def call(self,fn,*args,**kwargs):return fn(*args,**kwargs)
    transport=azure.AzureTransportExposure(None)
    result=native.collect_native(Outer(),transport,[existing.SCOPE],
        options(native,img.target,enabled),db_cache='/unreadable-test-cache',
        cli='/unused-test-trivy',runner=runner or fake_runner(),scratch_parent=tmp_path,
        database_check=db or (lambda _: {'fresh':True}))
    return result


@pytest.mark.parametrize('expected',['PASS','FAIL','UNKNOWN'])
def test_native_streaming_and_images_findings(proposal,monkeypatch,tmp_path,expected):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    result=collect(proposal,monkeypatch,tmp_path,runner=fake_runner(expected))
    row=result['rows'][0][native.MARKER]
    assert result['status']==expected
    assert row['scratch_removed'] is True and list(tmp_path.iterdir())==[]
    assert len(result['receipts'])>=6
    outcome,evidence=check.evaluate(*index(native,result,existing.SCOPE))
    assert outcome==expected
    assert 1 <= len(evidence['Observed'].splitlines()) <= 3
    if expected=='FAIL':
        assert len(evidence['Vulnerabilities'])==1
        assert evidence['Vulnerabilities'][0]['affected_assets'][0]['kind']=='acr_image'
    if expected=='PASS':assert evidence['Vulnerabilities']==[]
    assert existing.TOKEN not in json.dumps(result)


def test_disabled_and_missing_selection_zero_io(proposal):
    acr,azure,native,check=proposal
    class Poison:
        def __getattr__(self,name):raise AssertionError('unexpected credential or network access')
    result=native.collect_native(Poison(),Poison(),[],{},database_check=Poison())
    assert result['reason']=='disabled' and result['receipts']==[]
    with pytest.raises(ValueError):
        native.collect_native(Poison(),Poison(),[],{native.ENABLE:True,
            '_image_vulnerability_scan_kinds':[native.KIND]},database_check=Poison())


@pytest.mark.parametrize('lease_mode',['fresh','unavailable','stale'])
def test_collector_requires_trusted_fresh_database_lease(proposal,monkeypatch,tmp_path,lease_mode):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    from peaso.collectors import selected_image_trivy_database_20261021 as database
    _,azure,native,check=proposal
    img=existing.image()
    _,trace=existing.capture(monkeypatch,img=img,collect=False)
    cache=tmp_path/'trusted-current'
    acquired=[]
    def acquire(stack,*,enabled,cancel,diagnostics=None):
        assert type(diagnostics) is dict
        assert enabled is True
        cancel()
        acquired.append(True)
        return cache if lease_mode!='unavailable' else None
    monkeypatch.setattr(database,'acquire',acquire)
    monkeypatch.setattr(native.trivy,'database_state',lambda path:{'fresh':path==cache and lease_mode=='fresh'})
    runner=fake_runner()
    scanned=[]
    def trusted_runner(*args,**kwargs):
        assert kwargs['db_cache']==cache
        scanned.append(True)
        return runner(*args,**kwargs)
    monkeypatch.setattr(native.trivy,'scan_image',trusted_runner)
    class Outer:
        def __init__(self):self.collections=[]
        def check_cancelled(self):pass
        def call(self,fn,*args,**kwargs):return fn(*args,**kwargs)
        def run(self,jobs):
            for kind,scope,service,fetch in jobs:
                self.collections.append({'type':kind,'scope':scope,'service':service,
                    'status':'collected','items':[row for batch in fetch() for row in batch]})
    outer=Outer()
    native.collect(outer,azure.AzureTransportExposure(None),[existing.SCOPE],[native.KIND],
        options(native,img.target))
    assert acquired==[True]
    row=outer.collections[0]['items'][0][native.MARKER]
    assert row['status']==('PASS' if lease_mode=='fresh' else 'UNKNOWN')
    assert row['complete'] is (lease_mode=='fresh')
    if lease_mode=='fresh':
        assert scanned==[True]
        assert any(call[3]=='manifest' for call in trace.calls)
    else:
        assert scanned==[]
        assert row['reason']=='offline_database_unavailable'
        assert trace.calls==[]


def test_repeated_immutable_layer_descriptor_is_preserved(proposal):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    img=existing.image()
    img.manifest['layers'].append(dict(img.manifest['layers'][0]))
    _,_,layers=native._descriptors(existing.packed(img.manifest))
    assert len(layers)==2
    assert layers[0]==layers[1]
    img.manifest['layers'][1]['size']+=1
    with pytest.raises(ValueError):
        native._descriptors(existing.packed(img.manifest))


@pytest.mark.parametrize('case',['wrong_digest','truncation','denied','rootfs','drift','stale'])
def test_incomplete_native_input_never_passes(proposal,monkeypatch,tmp_path,case):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    img=existing.image();overrides={};db=None;runner=None
    if case=='wrong_digest':overrides['layer_blob']=existing.Response(img.wire[:-1]+b'X')
    if case=='truncation':overrides['layer_blob']=existing.Response(img.wire[:-1])
    if case=='denied':overrides['layer_blob']=existing.Response(b'',403)
    if case=='rootfs':
        img.config['rootfs']['diff_ids']=[acr._sha(b'wrong')]
        img.config_raw=existing.packed(img.config)
        img.manifest['config']['digest']=acr._sha(img.config_raw)
        img.manifest['config']['size']=len(img.config_raw)
        img.manifest_raw=existing.packed(img.manifest)
        img.target['digest']=acr._sha(img.manifest_raw)
    if case=='drift':
        def mutate(paths):paths[0].write_bytes(b'changed')
        runner=fake_runner(mutate=mutate)
    if case=='stale':db=lambda _: {'fresh':False}
    result=collect(proposal,monkeypatch,tmp_path,img=img,overrides=overrides,runner=runner,db=db)
    assert result['status']=='UNKNOWN' and list(tmp_path.iterdir())==[]
    if result['rows']:
        assert check.evaluate(*index(native,result,existing.SCOPE))[0]=='UNKNOWN'


def test_selection_separate_from_secret_option(proposal):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    targets=native.selected_targets({native.ENABLE:True,native.OPTION:[existing.image().target],
        'content_secret_scans':False},[existing.SCOPE])
    assert len(targets)==1
    assert native.enabled({native.ENABLE:True,native.OPTION:targets}) is False

def test_fresh_native_manifest_drift_is_unknown(proposal,monkeypatch,tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    img=existing.image();calls=0
    def manifest_response():
        nonlocal calls
        calls+=1
        return existing.Response(img.manifest_raw if calls==1 else img.manifest_raw+b'changed')
    result=collect(proposal,monkeypatch,tmp_path,img=img,
        overrides={'manifest':manifest_response})
    assert result['status']=='UNKNOWN' and calls>=2 and list(tmp_path.iterdir())==[]


def test_native_registry_identity_drift_is_unknown(proposal,monkeypatch,tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    good={'id':existing.REGISTRY,'name':'reviewregistry',
        'type':'Microsoft.ContainerRegistry/registries','properties':{
        'loginServer':existing.HOST,'provisioningState':'Succeeded',
        'roleAssignmentMode':'LegacyRegistryPermissions',
        'policies':{'azureADAuthenticationAsArmPolicy':{'status':'enabled'}},
        'dataEndpointEnabled':True,'dataEndpointHostNames':[existing.DATA_HOST]}}
    bad=deepcopy(good);bad['properties']['loginServer']='foreign.azurecr.io'
    calls=0
    def registry_response():
        nonlocal calls
        calls+=1
        return existing.Response(good if calls==1 else bad)
    result=collect(proposal,monkeypatch,tmp_path,
        overrides={'registry_identity':registry_response})
    assert result['status']=='UNKNOWN' and calls>=2 and list(tmp_path.iterdir())==[]


def test_pinned_trivy_stale_local_db_cannot_pass(tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    from peaso import trivy_container_runner_20261020 as trivy
    cache=Path.home()/'Library/Caches/trivy'
    binary=Path(shutil.which('trivy') or 'trivy')
    if not (cache/'db/trivy.db').is_file() or not binary.is_file():
        pytest.skip('existing pinned local Trivy cache unavailable')
    state=trivy.database_state(cache)
    if state['fresh']:
        pytest.skip('local DB is fresh; stale negative witness unavailable')
    img=existing.image()
    image={'provider':'azure','scope':existing.SCOPE,
        'immutable_reference':existing.HOST+'/'+existing.REPO+'@'+img.target['digest'],
        'manifest_digest':img.target['digest'],'config_digest':existing.source._sha(img.config_raw)}
    blob=tmp_path/'layer.blob';blob.write_bytes(img.wire)
    result=trivy.scan_image(image,img.manifest_raw,img.config_raw,[blob],
        native_verifier=lambda:dict(image),enabled=True,db_cache=cache,
        cli=str(binary),scratch_parent=tmp_path,timeout=60)
    assert result['status']=='UNKNOWN' and result['complete'] is False
    assert result['invocation']['command']=='trivy image --input <owned archive>'
    assert result['invocation']['archive_format']=='docker'
    assert result['owned_scratch_removed'] is True
    assert sorted(p.name for p in tmp_path.iterdir())==['layer.blob']

def test_stale_db_selection_never_uses_credentials(proposal):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    class Poison:
        def __getattr__(self,name):raise AssertionError('unexpected credential or network access')
    result=native.collect_native(Poison(),Poison(),[existing.SCOPE],
        options(native,existing.image().target),database_check=lambda _: {'fresh':False})
    assert result['status']=='UNKNOWN' and result['receipts']==[]
    assert len(result['rows'])==1 and result['rows'][0][native.MARKER]['status']=='UNKNOWN'


def test_auth_denial_unknown(proposal,monkeypatch,tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    result=collect(proposal,monkeypatch,tmp_path,
        overrides={'oauth_pull':existing.Response(b'',403)})
    assert result['status']=='UNKNOWN' and list(tmp_path.iterdir())==[]


def test_images_findings_deduplicates_same_advisory(proposal,monkeypatch,tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    base=fake_runner('FAIL')
    def duplicated(*args,**kwargs):
        scan=base(*args,**kwargs)
        scan['findings'].append(deepcopy(scan['findings'][0]))
        return scan
    result=collect(proposal,monkeypatch,tmp_path,runner=duplicated)
    status,evidence=check.evaluate(*index(native,result,existing.SCOPE))
    assert status=='FAIL' and len(evidence['Vulnerabilities'])==1


def test_pinned_version_drift_cannot_pass(proposal,monkeypatch,tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    from peaso import trivy_container_runner_20261020 as trivy
    acr,azure,native,check=proposal
    binary=Path(shutil.which('trivy') or 'trivy')
    if not binary.is_file():pytest.skip('pinned installed Trivy binary unavailable')
    img=existing.image()
    image={'provider':'azure','scope':existing.SCOPE,
        'immutable_reference':existing.HOST+'/'+existing.REPO+'@'+img.target['digest'],
        'manifest_digest':img.target['digest'],'config_digest':acr._sha(img.config_raw)}
    layer=tmp_path/'layer.blob';layer.write_bytes(img.wire)
    monkeypatch.setattr(trivy,'database_state',lambda _: {'fresh':True,'schema_version':2})
    monkeypatch.setattr(trivy.process,'_execute',lambda *args,**kwargs:
        (b'Version: 0.69.0\n',b'',0,None,0))
    result=trivy.scan_image(image,img.manifest_raw,img.config_raw,[layer],
        native_verifier=lambda:dict(image),enabled=True,db_cache=tmp_path,
        cli=str(binary),scratch_parent=tmp_path,timeout=60)
    assert result['status']=='UNKNOWN' and result['complete'] is False
    assert result['reason']=='pinned_trivy_version_unavailable'
    assert result['owned_scratch_removed'] is True

def test_azure_collection_hook_is_default_off_and_emits_unknown_without_db(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr,azure,native,check=proposal
    class Outer:
        def __init__(self):self.collections=[]
        def check_cancelled(self):pass
        def run(self,entries):
            for kind,scope,service,fetch in entries:
                self.collections.append((kind,scope,service,list(fetch())[0]))
    class Poison:
        def __getattr__(self,name):raise AssertionError('unexpected credential or network access')
    outer=Outer()
    native.collect(outer,Poison(),[existing.SCOPE],{native.KIND},{})
    assert outer.collections==[]
    from peaso.collectors import selected_image_trivy_database_20261021 as database
    monkeypatch.setattr(database,'acquire',lambda stack,*,enabled,cancel,diagnostics=None:None)
    native.collect(outer,Poison(),[existing.SCOPE],{native.KIND},
        options(native,existing.image().target))
    assert len(outer.collections)==1 and outer.collections[0][0]==native.KIND
    assert outer.collections[0][3][0][native.MARKER]['status']=='UNKNOWN'
    diagnostic=outer.acr_image_vulnerability_metadata['image_database_diagnostics']
    assert diagnostic['phases']['offline_validation']['reason']=='offline_database_not_fresh'
    assert diagnostic['phases']['offline_validation']['status']=='unavailable'

@pytest.mark.parametrize('outcome', ['FAIL', 'UNKNOWN'])
def test_images_findings_native_projection_and_unknown_slot(proposal, monkeypatch, tmp_path, outcome):
    from peaso.image_findings import build_report
    acr, azure, native, check = proposal
    result = collect(proposal, monkeypatch, tmp_path, runner=fake_runner(outcome))
    marker = result['rows'][0][native.MARKER]
    assert marker['observation'] is not None
    report = build_report([marker['observation']], selected=True)
    if outcome == 'FAIL':
        assert report['complete'] is True and report['coverage'] == 'COMPLETE'
        assert len(report['rows']) == 1
        assert report['rows'][0]['affected_assets'][0]['kind'] == 'acr_image'
    else:
        assert report['complete'] is False and report['coverage'] == 'UNKNOWN'
        assert report['rows'] == []
