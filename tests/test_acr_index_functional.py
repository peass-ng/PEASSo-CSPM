"""Offline native-shaped ACR index producer to consumer regression tests."""
import io
import json
import time
from types import SimpleNamespace

import pytest

from peaso import oci_index_20261021 as oci, secret_scanning as scanning
from peaso.collectors import azure as azure_host
from peaso.collectors import azure_acr_image_secret_indicators as acr
from peaso.collectors import azure_acr_image_stream_inspection_20261021 as stream
from peaso.collectors import azure_acr_image_vulnerabilities_20261021 as vuln
from peaso.checks import azure_acr_image_secret_review_20261020 as secret_check
from peaso.checks import azure_acr_image_vulnerabilities_20261021 as vuln_check
from peaso import selected_image_observations_20261021 as projector
from peaso.snapshot import digest

SCOPE='/subscriptions/11111111-1111-1111-1111-111111111111'
REGISTRY=SCOPE+'/resourceGroups/review/providers/Microsoft.ContainerRegistry/registries/reviewregistry'
HOST='reviewregistry.azurecr.io'
REPO='selected/application'
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


def packed(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def leaf(payload=b'ready = true',*,docker=False,files=None):
    import gzip
    import tarfile
    content=io.BytesIO()
    with tarfile.open(fileobj=content,mode='w',format=tarfile.USTAR_FORMAT) as tar:
        for name,raw in (files if files is not None else [('app/config.txt',payload)]):
            info=tarfile.TarInfo(name);info.size=len(raw)
            tar.addfile(info,io.BytesIO(raw))
    layer=content.getvalue();wire=gzip.compress(layer,mtime=0) if docker else layer
    config=packed({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[acr._sha(layer)]},
        'config':{'Env':['MODE=ready']}})
    manifest=packed({'schemaVersion':2,'mediaType':acr.DOCKER if docker else acr.OCI,
        'config':{'mediaType':'application/vnd.docker.container.image.v1+json' if docker else
            'application/vnd.oci.image.config.v1+json','digest':acr._sha(config),'size':len(config)},
        'layers':[{'mediaType':'application/vnd.docker.image.rootfs.diff.tar.gzip' if docker else
            'application/vnd.oci.image.layer.v1.tar','digest':acr._sha(wire),'size':len(wire)}]})
    return manifest,config,wire


def fixture(index=True,positive=False,docker=False):
    one=leaf(TOKEN.encode() if positive else b'ready = true',docker=docker)
    two=leaf(b'second = ready',docker=docker)
    if not index:
        parent=one[0];children=[one]
    else:
        children=[one,two]
        parent=packed({'schemaVersion':2,'mediaType':oci.DOCKER_LIST if docker else oci.OCI_INDEX,'manifests':[
            {'mediaType':acr.DOCKER if docker else acr.OCI,'digest':acr._sha(item[0]),'size':len(item[0]),
             'platform':{'os':'linux','architecture':'amd64'}} for item in children]})
    target={'registry_id':REGISTRY,'repository':REPO,'digest':acr._sha(parent)}
    blobs={acr._sha(parent):parent}
    for manifest,config,layer in children:
        blobs.update({acr._sha(manifest):manifest,acr._sha(config):config,acr._sha(layer):layer})
    return target,blobs,children


def selected_files(files,*,index=False):
    first=leaf(files=files)
    children=[first]
    if index:
        parent=packed({'schemaVersion':2,'mediaType':oci.OCI_INDEX,'manifests':[
            {'mediaType':acr.OCI,'digest':acr._sha(first[0]),'size':len(first[0]),
             'platform':{'os':'linux','architecture':'amd64'}}]})
    else:parent=first[0]
    target={'registry_id':REGISTRY,'repository':REPO,'digest':acr._sha(parent)}
    blobs={acr._sha(parent):parent}
    for manifest,config,layer in children:
        blobs.update({acr._sha(manifest):manifest,acr._sha(config):config,acr._sha(layer):layer})
    return target,blobs


class FakeReader:
    def __init__(self,target,blobs,*,deny=None,cancel=False):
        self.target=target;self.blobs=blobs;self.deny=deny;self.cancel=cancel
        self.scope=SCOPE;self.ident=acr.identity(target);self.host=HOST
        self.reader=SimpleNamespace(acr_image_secret_redactions=set(),check_cancelled=lambda:None)
        self.receipts=[];self.state={'deadline':time.monotonic()+120,'bytes':0,'calls':0}
        self.mode='LegacyRegistryPermissions';self.auth_audience='arm'
    def check(self):
        if self.cancel:raise azure_host.AzureReadError('collection_cancelled')
    def _receipt(self,operation,digest=None,raw=b'',status='collected'):
        self.receipts.append({'id':'acr-read-'+str(len(self.receipts)+1),'identity':self.ident,
            'scope':SCOPE,'method':'POST' if operation.startswith('oauth_') else 'GET',
            'operation':operation,'endpoint':'arm' if operation=='registry_identity' else 'registry',
            'status':status,'http_status':200 if status=='collected' else 403,
            'bytes':len(raw) if status=='collected' else 0,'digest':digest,
            'verified':status=='collected','bound':status=='collected'})
    def authenticate(self):
        self.check()
        for name in ('registry_identity','oauth_exchange','oauth_pull'):
            self._receipt(name,raw=b'valid-native-record')
        return 'private-token'
    def blob(self,category,digest,cap,token,size=None,destination=None):
        self.check()
        if digest==self.deny:
            self._receipt('manifest' if category=='manifests' else 'blob',digest,status='unavailable')
            raise acr.Incomplete('native_image_read_unavailable')
        raw=self.blobs[digest]
        assert len(raw)<=cap and (size is None or size==len(raw)) and token=='private-token'
        self._receipt('manifest' if category=='manifests' else 'blob',digest,raw)
        if destination is not None:
            destination.write_bytes(raw);destination.chmod(0o600);return destination
        return raw


@pytest.fixture(autouse=True)
def detectors(monkeypatch):
    # These are layout/receipt unit tests over FakeReader, not transport
    # acceptance. Normal Reader retains its exact-type pinned transport check;
    # native ARM/OAuth/registry wire tests exercise that boundary separately.
    original_enable=stream.enable_pinned_shared_data
    def enable(reader):
        if type(reader) is FakeReader:
            return
        return original_enable(reader)
    monkeypatch.setattr(stream,'enable_pinned_shared_data',enable)
    def detect(payload,path,timeout):
        return [(TOKEN,'github-pat',1)] if TOKEN.encode() in payload else []
    monkeypatch.setattr(scanning,'_scan_kingfisher',detect)
    monkeypatch.setattr(scanning,'_scan_trufflehog',detect)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def index_for(row,reader,kind,source,collection_status='collected'):
    if kind==acr.KIND:
        meta=acr.selection_metadata({'content_secret_scans':True,acr.OPTION:[reader.target],
            '_content_secret_scan_kinds':[acr.KIND]},[SCOPE])
    else:
        meta=vuln.selection_metadata({'image_vulnerability_scans':True,vuln.OPTION:[reader.target],
            '_image_vulnerability_scan_kinds':[vuln.KIND]},[SCOPE])
    meta.update(context_binding='scan_local',credential_context_id='offline-credential',
        customer_context_id='offline-customer')
    meta[kind+'_receipts']=reader.receipts
    row['_provenance'].update(credential_context_id='offline-credential',customer_context_id='offline-customer')
    collection={'scope':SCOPE,'status':collection_status,'items':[row],
        '_provenance':{'credential_context_id':'offline-credential','customer_context_id':'offline-customer'}}
    return row,{'context':{'provider':'azure','scope':SCOPE,'metadata':meta},
        'collections':{kind:[collection]}}


@pytest.mark.parametrize('index,positive,expected',[(True,False,'PASS'),(True,True,'FAIL'),
    (False,False,'PASS'),(False,True,'FAIL')])
def test_secret_native_index_and_leaf(index,positive,expected):
    target,blobs,_=fixture(index=index,positive=positive)
    reader=FakeReader(target,blobs)
    row=stream.inspect_image(reader)
    status,evidence=secret_check.evaluate(*index_for(row,reader,acr.KIND,acr))
    assert status==expected,evidence
    assert row[acr.MARKER]['complete'] is True
    assert ('graph' in row[acr.MARKER]) is index
    assert TOKEN not in json.dumps(row)
    assert 1 <= len(evidence['observed'].splitlines()) <= 3
    assert len(evidence['observed']) < 350


@pytest.mark.parametrize('removed', ['name', 'chunk-1'])
def test_clean_index_requires_name_and_content_receipts_for_each_file(removed):
    target,blobs,_=fixture(index=True,positive=False)
    reader=FakeReader(target,blobs)
    row=stream.inspect_image(reader)
    marker=row[acr.MARKER]
    child=marker['child_inspections'][0]
    part=next(p for p in child['parts'] if p.endswith('.member-1.'+removed))
    child['parts'].remove(part)
    marker['parts']=[p for p in marker['parts'] if p['part']!=part]
    assert secret_check.evaluate(*index_for(row,reader,acr.KIND,acr))[0]=='UNKNOWN'


def test_docker_manifest_list_secret_and_cve(monkeypatch,tmp_path):
    target,blobs,_=fixture(docker=True)
    reader=FakeReader(target,blobs)
    row=stream.inspect_image(reader)
    assert secret_check.evaluate(*index_for(row,reader,acr.KIND,acr))[0]=='PASS'
    reader=FakeReader(target,blobs)
    monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
    row=vuln._scan_target(reader.reader,None,reader.receipts,SCOPE,target,reader.state,
        db_cache=tmp_path,cli='/unused',runner=runner('PASS'),scratch_parent=tmp_path)
    assert vuln_check.evaluate(*index_for(row,reader,vuln.KIND,vuln))[0]=='PASS'


def test_secret_positive_survives_later_denied_child():
    target,blobs,children=fixture(positive=True)
    reader=FakeReader(target,blobs,deny=acr._sha(children[1][0]))
    row=stream.inspect_image(reader)
    status,evidence=secret_check.evaluate(*index_for(row,reader,acr.KIND,acr,'partial'))
    assert status=='FAIL',evidence
    assert evidence['complete'] is False
    assert row[acr.MARKER]['graph']['complete'] is False


def test_secret_clean_denied_child_unknown():
    target,blobs,children=fixture()
    reader=FakeReader(target,blobs,deny=acr._sha(children[1][0]))
    row=stream.inspect_image(reader)
    assert secret_check.evaluate(*index_for(row,reader,acr.KIND,acr,'partial'))[0]=='UNKNOWN'


def test_verified_parent_index_positive_survives_first_child_denial():
    target,blobs,children=fixture()
    original=blobs[target['digest']]
    document=json.loads(original)
    document['annotations']={'selected.example/credential':TOKEN}
    amended=packed(document)
    blobs.pop(target['digest'])
    target={**target,'digest':acr._sha(amended)}
    blobs[target['digest']]=amended
    reader=FakeReader(target,blobs,deny=acr._sha(children[0][0]))
    row=stream.inspect_image(reader)
    status,evidence=secret_check.evaluate(*index_for(row,reader,acr.KIND,acr,'partial'))
    assert status=='FAIL' and evidence['complete'] is False
    assert row[acr.MARKER]['graph']['children']==[]


def test_secret_wrong_child_bytes_and_cancel():
    target,blobs,children=fixture()
    reader=FakeReader(target,{**blobs,acr._sha(children[1][0]):b'foreign bytes'})
    assert stream.inspect_image(reader)[acr.MARKER]['complete'] is False
    with pytest.raises(azure_host.AzureReadError):stream.inspect_image(FakeReader(target,blobs,cancel=True))


@pytest.mark.parametrize('first',[b'\x00\x01binary-data',b'\x1f\x8binner-archive',b'DETECTOR_FAIL'])
@pytest.mark.parametrize('index',[False,True])
def test_unsupported_first_file_keeps_later_verified_positive(monkeypatch,first,index):
    if first==b'DETECTOR_FAIL':
        original=scanning._scan_kingfisher
        def detector(payload,path,timeout):
            if b'DETECTOR_FAIL' in payload:raise RuntimeError('synthetic detector unavailable')
            return original(payload,path,timeout)
        monkeypatch.setattr(scanning,'_scan_kingfisher',detector)
    target,blobs=selected_files([('a/first.bin',first),('z/later.txt',TOKEN.encode())],index=index)
    reader=FakeReader(target,blobs)
    row=stream.inspect_image(reader)
    marker=row[acr.MARKER]
    assert marker['complete'] is False and marker['scan_partial'] is True
    assert marker['skipped_files']==1
    if index:assert marker['graph']['complete'] is True
    status,evidence=secret_check.evaluate(*index_for(row,reader,acr.KIND,acr,'partial'))
    assert status=='FAIL',evidence
    assert evidence['complete'] is False
    assert TOKEN not in json.dumps(row)


def test_clean_with_unsupported_first_file_is_unknown():
    target,blobs=selected_files([('a/first.bin',b'\x00binary'),('z/later.txt',b'plain text')])
    reader=FakeReader(target,blobs)
    row=stream.inspect_image(reader)
    assert secret_check.evaluate(*index_for(row,reader,acr.KIND,acr,'partial'))[0]=='UNKNOWN'


@pytest.mark.parametrize('index',[False,True])
@pytest.mark.parametrize('suffix',[b'\x00binary',b'DETECTOR_FAIL'])
def test_complete_first_chunk_secret_survives_incomplete_later_chunk(monkeypatch,index,suffix):
    if suffix==b'DETECTOR_FAIL':
        original=scanning._scan_kingfisher
        def incomplete(payload,path,timeout):
            if suffix in payload:raise RuntimeError('synthetic detector unavailable')
            return original(payload,path,timeout)
        monkeypatch.setattr(scanning,'_scan_kingfisher',incomplete)
    first=TOKEN.encode()+b'A'*(stream.WINDOW-len(TOKEN))
    target,blobs=selected_files([('app/long.txt',first+suffix)],index=index)
    reader=FakeReader(target,blobs)
    row=stream.inspect_image(reader)
    status,evidence=secret_check.evaluate(*index_for(row,reader,acr.KIND,acr,'partial'))
    assert status=='FAIL',evidence
    assert row[acr.MARKER]['complete'] is False
    assert row[acr.MARKER]['scan_partial'] is True
    assert any(p['part'].endswith('.chunk-1') for p in row[acr.MARKER]['parts'])
    assert not any(p['part'].endswith('.chunk-2') for p in row[acr.MARKER]['parts'])
    assert all(not loc['path'].endswith('.chunk-2') for leak in row[acr.MARKER]['leaks']
        for loc in leak['locations'])


def test_incomplete_second_chunk_does_not_create_positive(monkeypatch):
    original=scanning._scan_kingfisher
    def incomplete(payload,path,timeout):
        if b'DETECTOR_FAIL' in payload:raise RuntimeError('synthetic detector unavailable')
        return original(payload,path,timeout)
    monkeypatch.setattr(scanning,'_scan_kingfisher',incomplete)
    target,blobs=selected_files([('app/long.txt',b'A'*stream.WINDOW+b'DETECTOR_FAIL'+TOKEN.encode())])
    reader=FakeReader(target,blobs)
    row=stream.inspect_image(reader)
    assert secret_check.evaluate(*index_for(row,reader,acr.KIND,acr,'partial'))[0]=='UNKNOWN'
    assert row[acr.MARKER]['leaks']==[]


@pytest.mark.parametrize('code',['collection_cancelled','intentional_scan_deadline','deadline_exceeded'])
def test_typed_abort_code_propagates_without_specific_exception_class(code):
    target,blobs=selected_files([('app/config.txt',b'plain text')])
    reader=FakeReader(target,blobs)
    class CodedAbort(RuntimeError):
        def __init__(self):
            super().__init__(code)
            self.code=code
    reader.check=lambda: (_ for _ in ()).throw(CodedAbort())
    with pytest.raises(CodedAbort):stream.inspect_image(reader)


def test_native_scan_deadline_propagates():
    target,blobs=selected_files([('app/config.txt',b'plain text')])
    reader=FakeReader(target,blobs)
    reader.state['deadline']=0
    with pytest.raises(acr.Incomplete,match='scanner_deadline'):
        stream.inspect_image(reader)


def runner(status):
    def scan(image,manifest,config,layers,**kwargs):
        assert kwargs['native_verifier']()==image
        findings=([{'vulnerability_id':'CVE-2026-12345','severity':'HIGH',
            'package_types':['debian'],'package':'example','version':'1.0',
            'fixed_in':['1.1'],'fix_status':'affected','classes':['os-pkgs'],
            'image_digest':image['manifest_digest']}] if status=='FAIL' else [])
        return {'image':image,'status':status,'complete':True,'scan_complete':True,
            'coverage_status':'COMPLETE','database':{'fresh':True},'findings':findings,
            'archive':{'format':kwargs['archive_format'],'manifest_digest':image['manifest_digest'],
                'config_digest':image['config_digest'],'expanded_bytes':len(config)+10240,'members':1}}
    return scan


@pytest.mark.parametrize('status',['PASS','FAIL'])
def test_vulnerability_native_index_to_consumer(monkeypatch,tmp_path,status):
    target,blobs,_=fixture()
    reader=FakeReader(target,blobs)
    monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
    row=vuln._scan_target(reader.reader,None,reader.receipts,SCOPE,target,reader.state,
        db_cache=tmp_path,cli='/unused',runner=runner(status),scratch_parent=tmp_path)
    result,evidence=vuln_check.evaluate(*index_for(row,reader,vuln.KIND,vuln))
    assert result==status,evidence
    assert row[vuln.MARKER]['graph']['complete'] is True
    assert len(row[vuln.MARKER]['child_vulnerability_scans'])==2
    assert list(tmp_path.iterdir())==[]


def test_vulnerability_later_child_denied_keeps_positive(monkeypatch,tmp_path):
    target,blobs,children=fixture()
    reader=FakeReader(target,blobs,deny=acr._sha(children[1][0]))
    monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
    row=vuln._scan_target(reader.reader,None,reader.receipts,SCOPE,target,reader.state,
        db_cache=tmp_path,cli='/unused',runner=runner('FAIL'),scratch_parent=tmp_path)
    assert vuln_check.evaluate(*index_for(row,reader,vuln.KIND,vuln))[0]=='FAIL'
    assert row[vuln.MARKER]['complete'] is False


def test_vulnerability_incomplete_second_scan_keeps_first_positive(monkeypatch,tmp_path):
    target,blobs,_=fixture()
    reader=FakeReader(target,blobs)
    monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
    calls=[0]
    def mixed(image,manifest,config,layers,**kwargs):
        calls[0]+=1
        if calls[0]==1:return runner('FAIL')(image,manifest,config,layers,**kwargs)
        row=runner('PASS')(image,manifest,config,layers,**kwargs)
        row.update(status='UNKNOWN',complete=False,scan_complete=False,
            coverage_status='UNKNOWN',database={'fresh':False})
        return row
    row=vuln._scan_target(reader.reader,None,reader.receipts,SCOPE,target,reader.state,
        db_cache=tmp_path,cli='/unused',runner=mixed,scratch_parent=tmp_path)
    status,evidence=vuln_check.evaluate(*index_for(row,reader,vuln.KIND,vuln))
    assert status=='FAIL',evidence
    assert row[vuln.MARKER]['complete'] is False


def test_vulnerability_clean_denied_and_foreign_host(monkeypatch,tmp_path):
    target,blobs,children=fixture()
    for deny,foreign in ((acr._sha(children[1][0]),False),(None,True)):
        reader=FakeReader(target,blobs,deny=deny)
        if foreign:reader.host='foreign.azurecr.io'
        monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
        row=vuln._scan_target(reader.reader,None,reader.receipts,SCOPE,target,reader.state,
            db_cache=tmp_path,cli='/unused',runner=runner('PASS'),scratch_parent=tmp_path)
        assert vuln_check.evaluate(*index_for(row,reader,vuln.KIND,vuln))[0]=='UNKNOWN'


def test_vulnerability_leaf_and_typed_cancel(monkeypatch,tmp_path):
    target,blobs,_=fixture(index=False)
    reader=FakeReader(target,blobs)
    monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
    row=vuln._scan_target(reader.reader,None,reader.receipts,SCOPE,target,reader.state,
        db_cache=tmp_path,cli='/unused',runner=runner('PASS'),scratch_parent=tmp_path)
    assert vuln_check.evaluate(*index_for(row,reader,vuln.KIND,vuln))[0]=='PASS'
    reader=FakeReader(target,blobs,cancel=True)
    monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
    with pytest.raises(azure_host.AzureReadError):
        vuln._scan_target(reader.reader,None,reader.receipts,SCOPE,target,reader.state,
            db_cache=tmp_path,cli='/unused',runner=runner('PASS'),scratch_parent=tmp_path)


def test_disabled_and_stale_db_have_zero_native_io():
    target,_,_=fixture()
    class Poison:
        def __getattr__(self,name):raise AssertionError('native I/O before authorization')
    empty=SimpleNamespace()
    acr.collect(empty,Poison(),[SCOPE],[acr.KIND],{})
    assert empty.acr_image_secret_metadata[acr.KIND+'_authorized'] is False
    disabled=vuln.collect_native(Poison(),Poison(),[SCOPE],{},database_check=Poison())
    assert disabled['rows']==[] and disabled['reason']=='disabled'
    stale=vuln.collect_native(Poison(),Poison(),[SCOPE],
        {'image_vulnerability_scans':True,vuln.OPTION:[target],
         '_image_vulnerability_scan_kinds':[vuln.KIND]},database_check=lambda _: {'fresh':False})
    assert stale['reason']=='offline_database_unavailable'
    assert stale['rows'][0][vuln.MARKER]['status']=='UNKNOWN'


def test_cve_collection_projects_each_child_to_existing_image_artifact(monkeypatch,tmp_path):
    target,blobs,children=fixture()
    reader=FakeReader(target,blobs)
    monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
    result=vuln.collect_native(reader.reader,None,[SCOPE],
        {'image_vulnerability_scans':True,vuln.OPTION:[target],
         '_image_vulnerability_scan_kinds':[vuln.KIND]},
        db_cache=tmp_path,cli='/unused',runner=runner('PASS'),scratch_parent=tmp_path,
        database_check=lambda _: {'fresh':True})
    assert result['status']=='PASS' and len(result['observations'])==2
    assert {o['scan']['image']['manifest_digest'] for o in result['observations']}=={
        acr._sha(item[0]) for item in children}
    assert all(o['asset_id'].endswith('@'+target['digest']) for o in result['observations'])


def test_native_manifest_route_and_media_accept_are_parent_bound(monkeypatch):
    target,blobs,children=fixture()
    digest=acr._sha(children[0][0]);raw=blobs[digest]
    calls=[]
    class Response:
        status=200
        def __init__(self):self.stream=io.BytesIO(raw)
        def getheader(self,key):return str(len(raw)) if key=='Content-Length' else None
        def read(self,size):return self.stream.read(size)
        def close(self):pass
    class Connection:
        sock=None
        def __init__(self,host,timeout):assert host==HOST
        def set_debuglevel(self,level):assert level==0
        def request(self,method,route,body=None,headers=None):
            calls.append((method,route,headers))
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(acr.http.client,'HTTPSConnection',Connection)
    outer=SimpleNamespace(check_cancelled=lambda:None,call=lambda fn,*a,**k:fn(*a,**k))
    native_reader=acr.Reader(outer,None,[],SCOPE,target,
        {'deadline':time.monotonic()+30,'calls':0,'bytes':0})
    native_reader.host=HOST
    assert native_reader.blob('manifests',digest,acr.MAX_MANIFEST,'private-token',len(raw))==raw
    method,route,headers=calls[0]
    assert method=='GET' and route=='/v2/'+REPO+'/manifests/'+digest
    assert oci.OCI_INDEX in headers['Accept'] and oci.DOCKER_LIST in headers['Accept']
    assert headers['Authorization']=='Bearer private-token'


@pytest.mark.parametrize('index,status',[(True,'PASS'),(True,'FAIL'),(False,'PASS'),(False,'FAIL')])
def test_evaluated_acr_projection_binds_parent_and_child(monkeypatch,tmp_path,index,status):
    target,blobs,_=fixture(index=index)
    reader=FakeReader(target,blobs)
    monkeypatch.setattr(vuln.acr,'Reader',lambda *args,**kwargs:reader)
    row=vuln._scan_target(reader.reader,None,reader.receipts,SCOPE,target,reader.state,
        db_cache=tmp_path,cli='/unused',runner=runner(status),scratch_parent=tmp_path)
    assert vuln_check.evaluate(*index_for(row,reader,vuln.KIND,vuln))[0]==status
    native_id=row['id']
    evaluated=digest(['azure',SCOPE,vuln.KIND,native_id])
    raw=(vuln._observation(SCOPE,target,scan['image'],scan)
        for scan in row[vuln.MARKER].get('child_vulnerability_scans',[]))
    prior=list(raw) if index else [row[vuln.MARKER]['observation']]
    snapshot={'provider':'azure','collections':[{'type':vuln.KIND,'scope':SCOPE,'items':[row]}],
        'metadata':{'image_vulnerability_scan':{'selected':True,'observations':prior}}}
    finding={'check_id':vuln.CHECK,'provider':'azure','scope':SCOPE,
        'resource_id':evaluated,'scanner_status':status,'status':status}
    projected=projector.metadata_for_report(snapshot,{'provider':'azure','findings':[finding]})
    observed=[value for value in projected['observations'] if value is not None]
    assert len(observed)==(2 if index else 1)
    assert all(value['asset_id']==evaluated and value['asset_kind']==vuln.KIND for value in observed)
    assert all(value['scan']['image']['manifest_digest']!=target['digest'] for value in observed) if index else True
    assert all(value['scan']['image']['manifest_digest']==target['digest'] for value in observed) if not index else True
    denied=projector.metadata_for_report(snapshot,{'provider':'azure','findings':[]})
    assert denied['observations']==[None]
    row[vuln.MARKER]['selection']['registry_id']=REGISTRY.replace('reviewregistry','foreignregistry')
    drift=projector.metadata_for_report(snapshot,{'provider':'azure','findings':[finding]})
    assert drift['observations']==[None]
