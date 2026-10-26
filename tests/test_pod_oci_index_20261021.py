"""Normal-module Pod -> fixed registry -> typed dual-engine consumer fixture."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile

import pytest

HERE=Path(__file__).resolve().parents[1]
from peaso import container_image_archive_20261020 as archive
from peaso import secret_scanning, trivy_container_runner_20261020 as trivy
from peaso import oci_index_20261021 as index
from peaso.collectors import k8s_selected_registry_image_20261021 as source
from peaso.checks import k8s_selected_registry_image_review_20261021 as consumer
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'

def wire(value):return json.dumps(value,separators=(',',':')).encode()

def leaf(arch,hit=False):
    data=('TOKEN='+TOKEN+'\n' if hit else 'MODE=ready\n').encode()
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as tar:
        member=tarfile.TarInfo('etc/source.env');member.size=len(data);tar.addfile(member,io.BytesIO(data))
    layer=stream.getvalue()
    config=wire({'os':'linux','architecture':arch,'rootfs':{'type':'layers','diff_ids':[archive.sha(layer)]}})
    manifest=wire({'schemaVersion':2,'mediaType':archive.OCI,
        'annotations':{'fixture':TOKEN if hit else 'mode=ready'},
        'config':{'mediaType':next(x for x in archive.CONFIGS if 'oci' in x),'size':len(config),'digest':archive.sha(config)},
        'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar','size':len(layer),'digest':archive.sha(layer)}]})
    return {'manifest':manifest,'config':config,'layer':layer,'digest':archive.sha(manifest),'architecture':arch}

def capture(*,index_image=True,first_hit=False,second_hit=False,case='clean',vuln=False,vuln_first=False,
            real_detectors=False):
    leaves=[leaf('amd64',first_hit)]
    if index_image:leaves.append(leaf('arm64',second_hit))
    if index_image:
        descriptors=[{'mediaType':archive.OCI,'digest':x['digest'],'size':len(x['manifest']),
                      'platform':{'os':'linux','architecture':x['architecture']}} for x in leaves]
        if case=='platform_mismatch':descriptors[-1]['platform']['architecture']='amd64'
        if case=='attestation':
            descriptors.append({'mediaType':archive.OCI,'digest':'sha256:'+'a'*64,'size':100,
                                'platform':{'os':'unknown','architecture':'unknown'}})
        parent=wire({'schemaVersion':2,'mediaType':index.OCI_INDEX,'manifests':descriptors})
    else:parent=leaves[0]['manifest']
    digest=archive.sha(parent);image='ghcr.io/owned/demo@'+digest
    target={'cluster_id':'cluster.example','namespace':'default','pod':'pod-a','uid':'abc123',
            'resource_version':'42','container_type':'regular','container_name':'app','image':image}
    pod={'apiVersion':'v1','kind':'Pod','metadata':{'namespace':'default','name':'pod-a','uid':'abc123','resourceVersion':'42'},
         'spec':{'containers':[{'name':'app','image':image}]},
         'status':{'containerStatuses':[{'name':'app','image':image,'imageID':'docker-pullable://'+image,
            'state':{'running':{'startedAt':'2026-10-21T10:00:00Z','containerID':'containerd://abc123'}},
            'containerID':'containerd://abc123','restartCount':0,'ready':True}]}}
    blobs={('manifests',digest):(parent,index.OCI_INDEX if index_image else archive.OCI)}
    for x in leaves:
        blobs[('manifests',x['digest'])]=(x['manifest'],archive.OCI)
        blobs[('blobs',archive.sha(x['config']))]=(x['config'],'application/octet-stream')
        blobs[('blobs',archive.sha(x['layer']))]=(x['layer'],'application/octet-stream')
    calls=[];responses=[];connections=[];redacted=set();origins=[]
    class Response:
        def __init__(self,body,media,status=200):
            self.status=status;self.stream=io.BytesIO(body);self.closed=False
            self.headers={'Content-Length':str(len(body)),'Content-Type':media,'Content-Encoding':'identity'}
        def read(self,n):return self.stream.read(n)
        def close(self):self.closed=True
    class Connection:
        def __init__(self):self.closed=False
        def close(self):self.closed=True
    def open_https(host,path,headers,timeout):
        assert host=='ghcr.io' and 'Authorization' not in headers
        category,requested=path.rsplit('/',2)[-2:]
        calls.append((category,requested,headers['Accept']))
        body,media=blobs[(category,requested)]
        status=403 if case=='denied_child' and requested==leaves[-1]['digest'] else 200
        if case=='truncated_child' and requested==leaves[-1]['digest']:body=body[:-1]
        response=Response(body,media,status);connection=Connection()
        responses.append(response);connections.append(connection)
        return connection,response
    def registry_factory(host,repository,check,authorization=None):
        assert host=='ghcr.io' and repository=='owned/demo' and authorization is None
        return source.RegistryReader(host,repository,check,authorization=authorization,open_https=open_https)
    def detector(raw,path,timeout):
        return [(TOKEN,'github-pat',1)] if TOKEN.encode() in raw else []
    def scan(raw,path,origin,check,leaks,parts,**kwargs):
        origins.append(origin)
        return source._scan(raw,path,origin,check,leaks,parts,**kwargs)
    def pod_get(_):
        value=copy.deepcopy(pod)
        if case=='pod_drift' and len(calls)>0:value['metadata']['resourceVersion']='43'
        return value
    def trivy_runner(identity,manifest,config,layers,**kwargs):
        assert kwargs['native_verifier']()==identity
        archive.validate(identity,manifest,config,layers)
        selected=vuln_first and identity['manifest_digest']==leaves[0]['digest']
        diff=archive.sha(layers[0].read_bytes())
        row={'VulnerabilityID':'CVE-2026-0001','PkgName':'fixture-package','InstalledVersion':'1.0',
             'FixedVersion':'1.1','Status':'fixed','Severity':'HIGH'}
        report={'SchemaVersion':2,'ArtifactType':'container_image',
            'Metadata':{'ImageID':identity['config_digest'],'DiffIDs':[diff],
                        'RepoDigests':[identity['immutable_reference']]},
            'Results':[{'Target':'fixture-image','Class':'os-pkgs','Type':'alpine',
                        'Packages':[{'Name':'fixture-package'}],
                        'Vulnerabilities':[row] if selected else []}]}
        parsed=trivy.parse_report(wire(report),0,identity,diff_ids=[diff],database={'fresh':True})
        if case=='trivy_unknown':parsed['status']='UNKNOWN'
        return parsed
    mp=pytest.MonkeyPatch()
    if not real_detectors:
        mp.setattr(secret_scanning,'_scan_kingfisher',detector)
        if case=='detector_missing':
            def unavailable(*args):raise RuntimeError('offline engine unavailable')
            mp.setattr(secret_scanning,'_scan_trufflehog',unavailable)
        else:
            mp.setattr(secret_scanning,'_scan_trufflehog',detector)
    secret_scanning._RESULTS.clear()
    def cancel():
        if case=='cancelled' and calls:raise KeyboardInterrupt('cancelled')
    try:
        marker=source.inspect(target,pod_get,allowed_hosts=['ghcr.io'],registry_factory=registry_factory,
            trivy_enabled=vuln,trivy_runner=trivy_runner if vuln else None,
            redact_values=redacted.update,cancel=cancel,scanner=scan)
    finally:
        mp.undo();secret_scanning._RESULTS.clear()
    item={'id':source.identity(target),'name':source.identity(target),'SelectedRegistryImage':marker}
    contexts={kind:{'context':{'provider':'k8s','scope':'default',
        'metadata':{kind+'_authorized':True,source.OPTION:[target]}},
        'collections':{kind:[{'scope':'default','status':'collected' if marker['status']=='PASS' else 'partial',
            'items':[item]}]}} for kind in (source.SECRET_KIND,source.VULN_KIND)}
    secret=consumer.evaluate(item,contexts[source.SECRET_KIND],source.SECRET_KIND)
    vulnerability=consumer.evaluate(item,contexts[source.VULN_KIND],source.VULN_KIND)
    return locals()

def test_supported_index_clean_and_positive():
    clean=capture()
    assert clean['secret'][0]=='PASS',clean['secret']
    hit=capture(second_hit=True)
    assert hit['secret'][0]=='FAIL',hit['secret']
    assert not hit['redacted'] and TOKEN not in json.dumps(hit['marker'])
    assert len(hit['marker']['graph']['children'])==2
    assert any(o.get('source')==hit['leaves'][1]['digest'] and o.get('layer')==archive.sha(hit['leaves'][1]['layer'])
               and o['image_digest']==hit['digest'] and o['resource_id']==source.identity(hit['target'])
               and o['scope']==hit['target']['cluster_id'] for o in hit['origins'])
    assert all(x.closed for x in hit['responses']+hit['connections'])


def test_clean_index_requires_exact_child_config_receipt():
    clean = capture()
    item = copy.deepcopy(clean['item'])
    index = copy.deepcopy(clean['contexts'][source.SECRET_KIND])
    index['collections'][source.SECRET_KIND][0]['items'] = [item]
    config_digest = item['SelectedRegistryImage']['graph']['children'][0]['config_digest']
    receipt, = [row for row in item['SelectedRegistryImage']['registry_receipts']
                if row['category'] == 'blobs' and row['digest'] == config_digest]
    receipt['digest'] = 'sha256:' + 'f' * 64
    assert consumer.evaluate(item, index, source.SECRET_KIND)[0] == 'UNKNOWN'

def test_later_missing_child_keeps_first_confirmed_positive():
    for case in ('denied_child','truncated_child','attestation'):
        assert capture(case=case)['secret'][0]=='UNKNOWN'
        hit=capture(first_hit=True,case=case)
        assert hit['secret'][0]=='FAIL',(case,hit['secret'])

def test_child_cve_and_partial_positive_identity():
    hit=capture(vuln=True,vuln_first=True)
    assert hit['vulnerability'][0]=='FAIL',hit['vulnerability']
    scans=hit['marker']['child_vulnerability_scans']
    assert [scan['image']['manifest_digest'] for scan in scans]==[x['digest'] for x in hit['leaves']]
    assert hit['vulnerability'][1]['vulnerabilities'][0]['image_digest']==hit['leaves'][0]['digest']
    assert capture(vuln=True)['vulnerability'][0]=='PASS'
    partial=capture(vuln=True,vuln_first=True,case='denied_child')
    assert partial['vulnerability'][0]=='FAIL',partial['vulnerability']
    assert partial['vulnerability'][1]['complete'] is False
    assert capture(vuln=True,case='trivy_unknown')['vulnerability'][0]=='UNKNOWN'

def test_leaf_unchanged_and_pod_drift_unknown():
    assert capture(index_image=False)['secret'][0]=='PASS'
    assert capture(index_image=False,first_hit=True)['secret'][0]=='FAIL'
    assert capture(case='pod_drift')['secret'][0]=='UNKNOWN'

def test_platform_mismatch_and_partial_detector_never_clean():
    assert capture(case='platform_mismatch')['secret'][0]=='UNKNOWN'
    assert capture(case='detector_missing')['secret'][0]=='UNKNOWN'
    hit=capture(index_image=False,first_hit=True,case='detector_missing')
    assert hit['secret'][0]=='FAIL' and hit['secret'][1]['complete'] is False

def test_cancellation_propagates():
    with pytest.raises(KeyboardInterrupt):
        capture(case='cancelled')

def test_pinned_offline_detectors_on_selected_child():
    assert capture(second_hit=True,real_detectors=True)['secret'][0]=='FAIL'
