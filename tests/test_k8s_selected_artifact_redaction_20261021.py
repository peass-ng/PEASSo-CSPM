"""Native synthetic canary redaction through selected image and Flux collectors."""
import base64
from contextlib import nullcontext
from copy import deepcopy
import gzip
from hashlib import sha256
import io
import json
from pathlib import Path
import random
import string
import tarfile
from types import SimpleNamespace

import pytest

from peaso.collectors import k8s_selected_log_sample_secret_indicators as native
from peaso.collectors import k8s_selected_metadata_runtime_20261020 as selected_metadata
from peaso.collectors import k8s_selected_registry_image_20261021 as registry
from peaso.collectors import k8s_selected_flux_artifact_20261021 as flux
from peaso import container_image_archive_20261020 as archive
from peaso import secret_scanning
from peaso.snapshot import make_snapshot, canonical
from tests.pinned_secret_scanners import require_pinned_scanners

rng = random.Random(314159)
def token(length, alphabet=string.ascii_letters + string.digits):
    return ''.join(rng.choice(alphabet) for _ in range(length))
KEY = 'AKIA' + token(16, string.ascii_uppercase + string.digits)
SECRET = token(40)
CANARY = ('AWS_ACCESS_KEY_ID=' + KEY + '\nAWS_SECRET_ACCESS_KEY=' + SECRET + '\n').encode()

def digest(raw): return 'sha256:' + sha256(raw).hexdigest()

def tar_bytes(name, content):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        member = tarfile.TarInfo(name)
        member.size = len(content)
        tar.addfile(member, io.BytesIO(content))
    return buffer.getvalue()

def registry_fixture(content):
    raw_tar = tar_bytes('app/settings.txt', content)
    layer = gzip.compress(raw_tar, mtime=0)
    config = json.dumps({'os':'linux','architecture':'amd64','rootfs':{'type':'layers',
        'diff_ids':[digest(raw_tar)]}},separators=(',',':')).encode()
    manifest = json.dumps({'schemaVersion':2,'mediaType':archive.OCI,
        'config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':digest(config),'size':len(config)},
        'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip','digest':digest(layer),'size':len(layer)}]},
        separators=(',',':')).encode()
    image = 'ghcr.io/owned/demo@' + digest(manifest)
    target = {'cluster_id':'cluster.example','namespace':'default','pod':'pod-a','uid':'abc123',
        'resource_version':'42','container_type':'regular','container_name':'app','image':image}
    pod = {'apiVersion':'v1','kind':'Pod','metadata':{'namespace':'default','name':'pod-a','uid':'abc123',
        'resourceVersion':'42','annotations':{'innocent':KEY}},
        'spec':{'containers':[{'name':'app','image':image}]},
        'status':{'containerStatuses':[{'name':'app','image':image,'imageID':'docker-pullable://'+image,
        'state':{'running':{'startedAt':'2026-10-21T10:00:00Z','containerID':'containerd://abc123'}},
        'containerID':'containerd://abc123','restartCount':0,'ready':True}]}}
    blobs = {('manifests',digest(manifest)):manifest,('blobs',digest(config)):config,
             ('blobs',digest(layer)):layer}
    return target,pod,blobs

def flux_fixture(content):
    raw = gzip.compress(tar_bytes('chart/values.yaml',content),mtime=0)
    target = {'cluster_id':'cluster.example','kind':'HelmChart','namespace':'default','name':'chart',
        'uid':'11111111-1111-4111-8111-111111111111','resource_version':'42','generation':2,
        'artifact_digest':digest(raw),'artifact_revision':'1.2.3',
        'artifact_path':'helmchart/default/chart/chart-1.2.3.tgz','artifact_size':len(raw),
        'service_namespace':'flux-system','service_uid':'22222222-2222-4222-8222-222222222222',
        'service_resource_version':'19','service_port_name':'http'}
    source = {'apiVersion':'source.toolkit.fluxcd.io/v1','kind':'HelmChart',
        'metadata':{'namespace':'default','name':'chart','uid':target['uid'],'resourceVersion':'42','generation':2},
        'status':{'observedGeneration':2,'conditions':[{'type':'Ready','status':'True','observedGeneration':2}],
        'artifact':{'digest':target['artifact_digest'],'revision':'1.2.3','path':target['artifact_path'],
        'size':len(raw),'url':'http://source-controller.flux-system.svc.cluster.local./'+target['artifact_path']}}}
    service = {'apiVersion':'v1','kind':'Service','metadata':{'namespace':'flux-system','name':'source-controller',
        'uid':target['service_uid'],'resourceVersion':'19'},'spec':{'type':'ClusterIP',
        'selector':{'app':'source-controller'},'ports':[{'name':'http','port':80,'protocol':'TCP'}]}}
    return target,source,service,raw

class Response:
    def __init__(self, raw, category):
        self.status=200;self.body=io.BytesIO(raw)
        self.headers={'Content-Length':str(len(raw)),'Content-Encoding':'identity',
                      'Content-Type':archive.OCI if category=='manifests' else 'application/octet-stream'}
    def read(self,n):return self.body.read(n)
    def close(self):pass
class Connection:
    def close(self):pass

def reader_class(blobs):
    def wire(host,path,headers,timeout):
        assert host=='ghcr.io' and 'Authorization' not in headers
        category, requested = path.rsplit('/',2)[1:]
        return Connection(),Response(blobs[(category,requested)],category)
    class Reader(registry.RegistryReader):
        def __init__(self,*args,**kwargs):super().__init__(*args,open_https=wire,**kwargs)
    return Reader

def make_reader():
    return SimpleNamespace(budget=SimpleNamespace(max_items=10),total=0,collections=[],
                           check_cancelled=lambda:None)

def fake_native(monkeypatch, pod, source, service, raw):
    pool=SimpleNamespace(literal_paths=frozenset({'/existing'}))
    client=SimpleNamespace(last_response=deepcopy(pod))
    pool.client=client
    monkeypatch.setattr(native,'_context',lambda api,cluster:(client,pool,'https://api.example',
                        {'Authorization':'Bearer synthetic'},'binding'))
    def read(reader,api,cluster,path,fields,state):
        if path.endswith('/pods/pod-a'): return deepcopy(pod),1,'binding'
        if path.endswith('/helmcharts/chart'):return deepcopy(source),1,'binding'
        if path.endswith('/services/source-controller'):return deepcopy(service),1,'binding'
        raise AssertionError('unexpected native path')
    monkeypatch.setattr(native,'_read',read)
    monkeypatch.setattr(native,'private_native_logs',lambda:nullcontext())
    monkeypatch.setattr(flux,'_native_bytes',lambda *args:raw)
    return pool

def test_both_collectors_real_detectors_redact_ordinary_aliases(monkeypatch):
    require_pinned_scanners()
    image_target,pod,blobs=registry_fixture(CANARY)
    flux_target,source,service,raw=flux_fixture(CANARY)
    pool=fake_native(monkeypatch,pod,source,service,raw)
    original_inspect=registry.inspect
    monkeypatch.setattr(registry,'inspect',lambda *args,**kwargs:
                        original_inspect(*args,registry_factory=reader_class(blobs),**kwargs))
    reader=make_reader()
    image_options={registry.OPTION:[image_target],registry.ALLOWLIST:['ghcr.io'],
        'content_secret_scans':True,'_registry_image_named_checks':[registry.SECRET_CHECK]}
    image_meta,image_matches=registry.collect(reader,object(),image_options,['default'],'cluster.example',{})
    flux_options={flux.OPTION:[flux_target],'content_secret_scans':True,
                  '_flux_artifact_named_checks':[flux.CHECK]}
    flux_meta,flux_matches=flux.collect(reader,object(),flux_options,
        ['default','flux-system'],'cluster.example')
    # Found values stay visible: nothing is queued for redaction.
    assert image_matches==set() and flux_matches==set()
    assert reader.collections[0]['items'][0]['SelectedRegistryImage']['status']=='FAIL'
    assert reader.collections[1]['items'][0]['SelectedFluxArtifact']['status']=='FAIL'
    assert KEY not in json.dumps(reader.collections) and SECRET not in json.dumps(reader.collections)
    reader.collections.append({'type':'pod','scope':'default','service':'kubernetes','status':'collected',
        'items':[pod]})
    metadata={**image_meta,**flux_meta,'ordinary_note':KEY,
              'encoded_note':base64.b64encode(SECRET.encode()).decode(),
              'selected_options':{'innocent':SECRET}}
    scopes,collections,metadata=selected_metadata.finalize(['default'],reader.collections,metadata,
        set(),set(),set(),set(),image_matches,flux_matches)
    snapshot=make_snapshot('k8s',scopes,collections,metadata=metadata)
    serialized=canonical(snapshot)
    assert KEY in serialized and SECRET in serialized
    assert base64.b64encode(SECRET.encode()).decode() in serialized
    assert '[redacted]' not in serialized
    assert image_matches==set() and flux_matches==set()
    assert pool.literal_paths==frozenset({'/existing'})
    assert pool.client.last_response is None

def test_clean_and_one_engine_partial_positive_keep_bound_value(monkeypatch):
    require_pinned_scanners()
    target,source,service,raw=flux_fixture(b'mode: ready\n')
    matches=set()
    clean=flux.inspect(target,lambda _:source,lambda _:service,lambda _:raw,
                       redact_values=flux.redaction_callback(matches))
    assert clean['status']=='PASS' and matches==set()
    target,source,service,raw=flux_fixture(CANARY)
    monkeypatch.setattr(secret_scanning,'_scan_trufflehog',lambda *args:(_ for _ in ()).throw(RuntimeError()))
    partial=flux.inspect(target,lambda _:source,lambda _:service,lambda _:raw,
                         redact_values=flux.redaction_callback(matches))
    assert partial['status']=='FAIL' and partial['complete'] is False
    assert matches==set()  # found values are not queued for redaction
    assert {e['status'] for e in partial['parts'][0]['engines']}=={'complete','unavailable'}
    assert KEY not in json.dumps(partial) and SECRET not in json.dumps(partial)
    _,_,metadata=selected_metadata.finalize(['default'],[],{'ordinary_note':KEY},set(),matches)
    assert metadata=={'ordinary_note':KEY} and matches==set()

def test_overflow_aborts_before_snapshot_and_clears_on_failure(monkeypatch):
    for module in (registry,flux):
        matches=set()
        add=module.redaction_callback(matches)
        with pytest.raises(module.RedactionOverflow):
            add(frozenset('value-'+str(i) for i in range(module.MAX_REDACTION_VALUES+1)))
        assert matches==set()
        with pytest.raises(module.RedactionOverflow):
            add(frozenset({'X'*8193}))
        assert matches==set()
    target,source,service,raw=flux_fixture(b'mode: ready\n')
    def overflowing(raw,path,source,check,*,redact_values):
        redact_values(frozenset({'known-value'}))
        redact_values(frozenset('value-'+str(i) for i in range(flux.MAX_REDACTION_VALUES+1)))
    with pytest.raises(flux.RedactionOverflow):
        flux.inspect(target,lambda _:source,lambda _:service,lambda _:raw,
                     scanner=overflowing,redact_values=flux.redaction_callback(set()))

    pool=fake_native(monkeypatch,None,source,service,raw)
    reader=make_reader()
    captured=[]
    def fail_after_value(*args,**kwargs):
        callback=kwargs['redact_values'];captured.append(callback)
        callback(frozenset({'known-value'}))
        raise ValueError('synthetic failure')
    monkeypatch.setattr(flux,'inspect',fail_after_value)
    options={flux.OPTION:[target],'content_secret_scans':True,
             '_flux_artifact_named_checks':[flux.CHECK]}
    with pytest.raises(flux.RedactionOverflow):
        flux.collect(reader,object(),options,['default','flux-system'],'cluster.example')
    assert reader.collections==[] and pool.literal_paths==frozenset({'/existing'})
    assert captured

def test_cancelled_scan_keeps_transient_value_until_finalizer():
    target,source,service,raw=flux_fixture(b'mode: ready\n')
    matches=set()
    def cancelled(raw,path,source,check,*,redact_values):
        redact_values(frozenset({KEY}))
        raise flux.Incomplete('cancelled')
    marker=flux.inspect(target,lambda _:source,lambda _:service,lambda _:raw,
                        scanner=cancelled,redact_values=flux.redaction_callback(matches))
    assert marker['status']=='UNKNOWN' and KEY in matches
    assert KEY not in json.dumps(marker)
    scopes,collections,metadata=selected_metadata.finalize(['default'],[],{'ordinary_note':KEY},
                                                             set(),matches)
    # The transient match set is still released; the found value stays visible.
    assert metadata=={'ordinary_note':KEY}
    assert matches==set()

def test_default_off_zero_io():
    class NoIO:
        def __getattr__(self,key):raise AssertionError('I/O attempted')
    assert registry.collect(NoIO(),NoIO(),{},['default'],'cluster.example',{})==({},set())
    assert flux.collect(NoIO(),NoIO(),{},['default','flux-system'],'cluster.example')==({},set())
