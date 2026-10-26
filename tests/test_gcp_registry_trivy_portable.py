"""Portable GCP standalone immutable registry image regression tests."""
from pathlib import Path
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import socket
import pytest

ROOT = Path(__file__).resolve().parents[1]
from peaso import gcp_image_selection_20261021 as selection
from peaso.checks import gcp_registry_trivy_review_20261021 as review
from peaso.collectors import gcp_registry_trivy_runtime_20261021 as runtime
from peaso.collectors import gcp_registry_trivy_20261021 as mod
from peaso.collectors import gcp_job_trivy_stream_20261021 as stream
import gcp_job_image_vulnerability_fixture_20261021 as fixture


def released(runner):
    """Fake runners keep the real runner's contract: release staged scratch in finally."""
    from peaso import container_image_archive_20261020 as image_archive
    def run(identity, manifest, config, layers, **kwargs):
        try:
            return runner(identity, manifest, config, layers, **kwargs)
        finally:
            image_archive.release_staged(identity, manifest, config, layers)
    return run

def product_modules():
    return selection, review, runtime

@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    def blocked(*a, **kw):
        pytest.fail('network forbidden')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(stream.tempfile, 'tempdir', str(tmp_path))


def setup(*, fault=None):
    selectors, bodies, blobs = fixture.fixtures()
    reference = selectors[0]['immutable_reference']
    metadata = fixture.MetadataSession(bodies, fault=fault)
    images = fixture.ImageSession(blobs)
    return reference, metadata, images, fixture.transport()


def clean(identity, manifest, config, layers, **kwargs):
    assert kwargs['native_verifier']() == identity
    assert all(isinstance(p, Path) for p in layers)
    return {'image':identity,'status':'PASS','complete':True,'scan_complete':True,
            'coverage_status':'COMPLETE','database':{'fresh':True},'findings':[]}


def collect(ref, metadata, images, wire, **kw):
    return mod.collect_native(wire,scope=fixture.SCOPE,selectors=[ref],enabled=True,
        metadata_session=metadata,image_session=images,**kw)


def test_native_standalone_image_gets_no_job_and_cleans_every_path(tmp_path):
    ref, metadata, images, wire = setup()
    observed=[]
    def runner(*args, **kw):
        observed.extend(args[3]);return clean(*args,**kw)
    result=collect(ref,metadata,images,wire,runner=released(runner))
    assert result['status']=='PASS', result
    assert result['complete']
    assert len(metadata.calls)==6 and not any('run.googleapis' in u for u in metadata.calls)
    assert len(images.calls)==3 and wire.calls==9
    assert observed and all(not p.exists() for p in observed)
    assert metadata.closed and images.closed
    assert list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('enabled,selectors',[(False,object()),(True,[]),(True,['https://example.invalid/a']),
    (True,['us-central1-docker.pkg.dev/other-project/images/app@sha256:'+'a'*64]),
    (True,['us-central1-docker.pkg.dev/review/images/app:latest'])])
def test_disabled_or_invalid_selection_is_zero_access(enabled,selectors):
    result=mod.collect_native(object(),scope=fixture.SCOPE,selectors=selectors,enabled=enabled,
        metadata_session=object(),image_session=object())
    assert result['status']=='UNKNOWN' and result['rows']==[]


@pytest.mark.parametrize('phase',[1,2])
def test_metadata_denial_never_reaches_scanner_and_cleans(tmp_path,phase):
    ref,metadata,images,wire=setup(fault=lambda u,n:'denied' if n==phase else None)
    calls=[]
    result=collect(ref,metadata,images,wire,runner=lambda *a,**kw:calls.append(True))
    assert result['status']=='UNKNOWN' and not result['complete'] and not calls
    assert metadata.closed and images.closed and list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('field,value',[('projectId','foreign'),('state','DELETE_REQUESTED'),('name','projects/not-a-number')])
def test_foreign_or_inactive_project_is_unknown(field,value):
    ref,metadata,images,wire=setup()
    url=mod.requests_for(ref,fixture.SCOPE)[0][0]
    metadata.bodies[url][field]=value
    result=collect(ref,metadata,images,wire,runner=released(clean))
    assert result['status']=='UNKNOWN' and not images.calls


@pytest.mark.parametrize('field,value',[('format','MAVEN'),('name','projects/other/locations/us/repositories/x'),('mode','REMOTE_REPOSITORY')])
def test_wrong_repository_is_unknown(field,value):
    ref,metadata,images,wire=setup();url=mod.requests_for(ref,fixture.SCOPE)[1][0]
    metadata.bodies[url][field]=value
    assert collect(ref,metadata,images,wire,runner=released(clean))['status']=='UNKNOWN'
    assert not images.calls


@pytest.mark.parametrize('kind',['bytes','receipt','metadata','sequence'])
def test_native_verifier_rechecks_all_mutable_sources(tmp_path,kind):
    ref,metadata,images,wire=setup();reached=[]
    def runner(identity,manifest,config,layers,**kw):
        reached.append(True)
        if kind=='bytes':layers[0].write_bytes(b'corrupt')
        elif kind=='receipt':wire.evidence[0]['status']='denied'
        elif kind=='metadata':wire.evidence[0]['body_sha256']='0'*64
        elif kind=='sequence':wire.evidence[-1]['digest']='sha256:'+'0'*64
        kw['native_verifier']();pytest.fail('tamper accepted')
    result=collect(ref,metadata,images,wire,runner=released(runner))
    assert reached and result['status']=='UNKNOWN' and not result['complete']
    assert list(tmp_path.iterdir())==[]


def test_partial_high_cve_is_retained_without_clean_claim():
    ref,metadata,images,wire=setup()
    def runner(identity,*args,**kw):
        kw['native_verifier']()
        return {'image':identity,'status':'FAIL','complete':False,'scan_complete':False,
                'coverage_status':'UNKNOWN','database':{'fresh':False},
                'findings':[{'vulnerability_id':'CVE-2026-12345','severity':'HIGH'}]}
    result=collect(ref,metadata,images,wire,runner=released(runner))
    assert result['status']=='FAIL' and not result['complete']
    assert result['rows'][0]['scan']['findings'][0]['severity']=='HIGH'


def test_scanner_identity_drift_is_unknown():
    ref,metadata,images,wire=setup()
    def wrong(identity,*args,**kw):
        return {**clean(identity,*args,**kw),'image':{**identity,'scope':'projects/other'}}
    assert collect(ref,metadata,images,wire,runner=released(wrong))['status']=='UNKNOWN'


def full_positive(identity,manifest,config,layers,**kwargs):
    result=clean(identity,manifest,config,layers,**kwargs)
    return {**result,'status':'FAIL','complete':False,'scan_complete':False,'coverage_status':'UNKNOWN',
        'database':{'fresh':False},'findings':[{'vulnerability_id':'CVE-2026-12345','severity':'HIGH',
        'package_types':['alpine'],'package':'fixture-package','version':'1.0','fixed_in':['1.1'],
        'fix_status':'fixed','classes':['os-pkgs'],'image_digest':identity['manifest_digest']}]}


@pytest.mark.parametrize('mode,expected',[('clean','PASS'),('positive','FAIL'),('missing','UNKNOWN')])
def test_current_normal_registry_wrapper_and_typed_record(mode,expected):
    selection,review,runtime=product_modules()
    ref,metadata,images,wire=setup()
    result=runtime.collect_selected(wire,scope=fixture.SCOPE,targets=[ref],
        metadata_session=metadata,image_session=images,runner=released(full_positive if mode=='positive' else clean))
    row=result['rows'][0]
    if mode=='missing':row['vulnerability_record']=None
    item={'name':ref,'_resource_id':ref,'native_id':ref,'RegistryImageVulnerabilityReview':row}
    index={'context':{'provider':'gcp','scope':fixture.SCOPE,'metadata':{runtime.OPTION:[ref]}},
           'collections':{runtime.KIND:[{'scope':fixture.SCOPE,'status':'partial' if mode!='clean' else 'collected','items':[item]}]}}
    from peaso.checks import CHECKS
    check=next(c for c in CHECKS if c.id==review.CHECK_ID)
    assert check.allow_incomplete_failure is True
    status,evidence=check.evaluate(item,index)
    assert status==expected,(status,evidence,row)
    assert evidence['Observed'] and 1 <= len(evidence['Observed'].rstrip('.').split('.')) <= 3


@pytest.mark.parametrize('tamper',['scope','provider','reference','missing_receipt','stale_clean','digest','severity'])
def test_typed_consumer_rejects_wrong_scope_or_scan_claims(tamper):
    selection,review,runtime=product_modules();ref,metadata,images,wire=setup()
    result=runtime.collect_selected(wire,scope=fixture.SCOPE,targets=[ref],
        metadata_session=metadata,image_session=images,runner=released(full_positive if tamper=='severity' else clean))
    row=deepcopy(result['rows'][0]);record=row['vulnerability_record']
    ix={'scope':fixture.SCOPE,'selections':[ref],'source_requests':row['source_ledger']}
    if tamper=='scope':record['scope']='projects/other-project'
    elif tamper=='provider':record['image']['provider']='aws'
    elif tamper=='reference':record['selection']=ref.replace('/review/','/foreign/')
    elif tamper=='missing_receipt':ix['source_requests'].pop()
    elif tamper=='stale_clean':record['database_fresh']=False
    elif tamper=='digest':record['image']['manifest_digest']='sha256:'+'0'*64
    else:record['findings'][0]['severity']='LOW'
    assert review.evaluate(record,ix)[0]=='UNKNOWN'


def test_opt_in_capability_is_exact_single_use_and_before_credentials():
    selection,review,runtime=product_modules();ref,_,_,_=setup()
    opts={selection.ENABLE:True,selection.OPTION:[ref]}
    with pytest.raises(ValueError):runtime.authorize_collector(opts,[fixture.SCOPE])
    runtime.issue_engine_grant(opts,[fixture.SCOPE],[runtime.CHECK_ID])
    assert runtime.authorize_collector(opts,[fixture.SCOPE])==[ref]
    with pytest.raises(ValueError):runtime.authorize_collector(opts,[fixture.SCOPE])
    runtime.issue_engine_grant(opts,[fixture.SCOPE],[])
    assert runtime.GRANT not in opts
    assert runtime.prepare({},[fixture.SCOPE],[])==[]


def test_pure_api_selector_has_no_native_or_analysis_imports():
    import subprocess
    code=f'''import sys,importlib.abc
sys.path.insert(0,{str(ROOT)!r})
class Block(importlib.abc.MetaPathFinder):
 def find_spec(self,name,*args):
  if any(name==p or name.startswith(p+'.') for p in ('peaso.collectors','peaso.checks','peaso.engine','peaso.analysis')):
   raise RuntimeError('forbidden native API import:'+name)
sys.meta_path.insert(0,Block())
from peaso import gcp_image_selection_20261021 as m
ref='us-central1-docker.pkg.dev/review/images/app@sha256:'+64*'a'
assert m.selections({{m.OPTION:[ref],m.ENABLE:True}},['projects/review'])==[ref]
assert not any(p in sys.modules for p in ('peaso.collectors','peaso.checks','peaso.engine','peaso.analysis'))
'''
    result=subprocess.run([sys.executable,'-I','-c',code],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr


def test_image_findings_projection_keeps_partial_positive_and_unknown():
    _,_,runtime=product_modules()
    from peaso.image_findings import build_report
    ref,metadata,images,wire=setup()
    positive=runtime.collect_selected(wire,scope=fixture.SCOPE,targets=[ref],
        metadata_session=metadata,image_session=images,runner=released(full_positive))
    report=build_report(positive['observations'],selected=True)
    assert report['coverage']=='UNKNOWN' and report['complete'] is False
    assert len(report['rows'])==1 and report['rows'][0]['vulnerability_id']=='CVE-2026-12345'
    assert report['rows'][0]['coverage']=='UNKNOWN'
    missing=build_report([None],selected=True)
    assert missing['coverage']=='UNKNOWN' and missing['invalid_observations']==1


def test_shared_snapshot_observations_keep_registry_and_job_rows():
    _,_,runtime=product_modules()
    from peaso.collectors import gcp_job_image_vulnerability_runtime_20261021 as old
    ref,_,_,_=setup()
    collector=type('Collector',(),{'registry_image_vulnerability_targets':[ref],
        'registry_image_vulnerability_result':{'observations':[None]}})()
    metadata={}
    runtime.finish_metadata(collector,metadata)
    assert metadata['image_vulnerability_scan']['observations']==[None]
    merged=old.attach_snapshot({'metadata':metadata},
        {'kind':old.KIND,'check_id':old.CHECK_ID,'observations':[{'scan':None}]},selected=True)
    assert merged['metadata']['image_vulnerability_scan']['observations']==[None,{'scan':None}]


def test_real_pinned_trivy_stale_db_cannot_pass(tmp_path):
    from peaso import trivy_container_runner_20261020 as runner
    if not os.getenv('PEASO_TEST_TRIVY_DB') or not os.getenv('PEASO_TEST_TRIVY_CLI'):
        pytest.fail('set PEASO_TEST_TRIVY_DB and PEASO_TEST_TRIVY_CLI for pinned stale-DB case')
    source_db = Path(os.environ['PEASO_TEST_TRIVY_DB']) / 'db'
    stale_db = tmp_path / 'stale-db' / 'db'
    stale_db.mkdir(parents=True)
    os.link(source_db / 'trivy.db', stale_db / 'trivy.db')
    metadata = json.loads((source_db / 'metadata.json').read_text())
    updated = datetime.now(timezone.utc) - timedelta(days=3)
    metadata.update(UpdatedAt=updated.isoformat(),
                    NextUpdate=(updated + timedelta(days=1)).isoformat(),
                    DownloadedAt=(updated + timedelta(minutes=1)).isoformat())
    (stale_db / 'metadata.json').write_text(json.dumps(metadata))
    ref,metadata,images,wire=setup()
    result=collect(ref,metadata,images,wire,runner=runner.scan_image,
        db_cache=stale_db.parent,cli=os.environ['PEASO_TEST_TRIVY_CLI'],timeout=120)
    assert result['status']=='UNKNOWN' and result['complete'] is False
    scan=result['rows'][0]['scan']
    assert scan is not None and scan['database']['fresh'] is False
    assert scan['invocation']['command']=='trivy image --input <owned archive>'
    assert scan['owned_scratch_removed'] is True


def test_validated_same_origin_blob_redirect_reaches_native_cve_verifier(tmp_path):
    ref, metadata, images, wire = setup()
    original = images.request
    pending = {}
    def request(method, url, **kwargs):
        if '/artifacts-downloads/' in url:
            response = pending.pop(url)
            response.url = url
            return response
        response = original(method, url, **kwargs)
        if '/blobs/' in url:
            hop = '/artifacts-downloads/namespaces/review/repositories/images/downloads/' + str(len(images.calls))
            from types import SimpleNamespace
            target = 'https://us-central1-docker.pkg.dev' + hop
            pending[target] = response
            return SimpleNamespace(status_code=302, url=url, history=[], headers={'Location':hop}, close=lambda:None)
        return response
    images.request = request
    result = collect(ref, metadata, images, wire, runner=released(clean))
    assert result['status'] == 'PASS' and result['complete'] is True, result
    redirected = [r for r in wire.evidence if r.get('same_origin_blob_redirect') is True]
    assert len(redirected) == 2 and all(r['http_attempts'] == 2 for r in redirected)
    assert not pending and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('damage', ['missing_proof','extra_attempt','manifest_redirect','bool_attempts'])
def test_unproven_or_incoherent_blob_receipt_does_not_reach_cve_scanner(damage):
    ref, metadata, images, wire = setup()
    original = metadata.request
    def request(*args, **kwargs):
        response = original(*args, **kwargs)
        if len(metadata.calls) == 4:
            receipts = [r for r in wire.evidence if r.get('operation') == 'artifactregistry.registry_content_get']
            target = receipts[-1] if damage != 'manifest_redirect' else receipts[0]
            target['http_attempts'] = True if damage == 'bool_attempts' else 3 if damage == 'extra_attempt' else 2
            if damage in ('extra_attempt','manifest_redirect'):target['same_origin_blob_redirect'] = True
        return response
    metadata.request = request
    reached = []
    result = collect(ref, metadata, images, wire, runner=lambda *a, **kw: reached.append(True))
    assert result['status'] == 'UNKNOWN' and not reached


@pytest.mark.parametrize(('mode','expected'), [('clean','PASS'), ('positive','FAIL'), ('missing','UNKNOWN')])
def test_full_engine_sealed_native_record_preserves_cve_status(mode, expected):
    from peaso import engine
    from peaso.snapshot import make_snapshot
    ref, metadata, images, wire = setup()
    result = runtime.collect_selected(wire, scope=fixture.SCOPE, targets=[ref],
        metadata_session=metadata, image_session=images,
        runner=released(full_positive if mode == 'positive' else clean))
    marker = result['rows'][0]
    if mode == 'missing':marker['vulnerability_record'] = None
    item = {'name':ref,'_resource_id':ref,'native_id':ref,'RegistryImageVulnerabilityReview':marker}
    snapshot = make_snapshot('gcp', [fixture.SCOPE], [{'type':runtime.KIND,'scope':fixture.SCOPE,
        'service':'artifactregistry','status':'collected','items':[item]}], metadata={runtime.OPTION:[ref]})
    report = engine.evaluate_snapshot(snapshot, checks=[review.CHECK_ID])
    assert [f['status'] for f in report['findings']] == [expected]


def test_engine_boundary_still_rejects_arbitrary_container_subclasses():
    ref, metadata, images, wire = setup()
    marker = runtime.collect_selected(wire, scope=fixture.SCOPE, targets=[ref],
        metadata_session=metadata, image_session=images, runner=released(clean))['rows'][0]
    class ForeignList(list):pass
    marker['source_ledger'] = ForeignList(marker['source_ledger'])
    item = {'name':ref,'_resource_id':ref,'native_id':ref,'RegistryImageVulnerabilityReview':marker}
    index = {'context':{'provider':'gcp','scope':fixture.SCOPE,'metadata':{runtime.OPTION:[ref]}},
        'collections':{runtime.KIND:[{'scope':fixture.SCOPE,'status':'collected','items':[item]}]}}
    assert review.evaluate_item(item, index)[0] == 'UNKNOWN'
