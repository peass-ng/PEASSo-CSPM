"""Actual HTTP framing and full image-layer archive validation, offline only."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import threading
from types import SimpleNamespace

import pytest
from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from peaso.collectors import aws_package_content_indicators as content
from peaso import container_image_archive_20261020 as archive

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
pipeline=load('peaso.collectors._pipeline_http_test',ROOT/'peaso/collectors/aws_image_layer_pipeline_20261022.py')
bench=load('_pipeline_http_fixture',ROOT/'tests/synthetic/benchmark_peaso_ecr_layer_pipeline.py')


def bodies():
    result={}
    for i in range(3):
        body=((f'layer-{i}-'*100).encode()*1500)[:1024*1024]
        result[archive.sha(body)]=body
    return result


def test_real_http_exact_order_bytes_modes_and_native_budgets():
    payloads=bodies()
    before=bench.measure(pipeline,payloads,False,parallel=False)
    after=bench.measure(pipeline,payloads,False,parallel=True)
    for key in ('http_requests','transferred_bytes','sdk_calls','all_request_calls','ordered_hashes','source_ledger_sha256'):
        assert before[key]==after[key]
    assert before['peak_http']==1 and after['peak_http']==2


def test_real_http_bad_digest_never_returns_complete_layer_list(monkeypatch,tmp_path):
    payloads=bodies();descs=[dict(digest=k,size=len(v)) for k,v in payloads.items()]
    q=SimpleNamespace(_lock=threading.RLock(),max_calls=None,calls=0,deadline=None,
                      timeout=5,check_deadline=lambda:None)
    class Client:
        def get_download_url_for_layer(self,**args):
            return dict(ResponseMetadata={'HTTPStatusCode':200},layerDigest=args['layerDigest'],
                        downloadUrl=bench.PREFIX+args['layerDigest']+'?fixture=synthetic')
    reader=native.Reader(q,SimpleNamespace(client=lambda *a,**kw:Client()),'123456789012','us-east-1')
    tmp_path.chmod(0o700)
    with bench.Fixture(payloads,corrupt=descs[0]['digest']) as fixture:
        monkeypatch.setattr(content,'build_opener',fixture.opener)
        with pytest.raises(ValueError,match='image_blob_download_unavailable'):
            pipeline.download_layers(reader,'fixture',descs,tmp_path,'sha256:'+'a'*64)
        assert fixture.active==0 and fixture.peak<=2 and fixture.calls<=len(descs)
        assert not (tmp_path/'layer-0.blob').exists()
        assert all(row.get('digest')!=descs[0]['digest'] for row in reader.ledger)


@pytest.mark.parametrize('corrupt',[False,True])
def test_scan_bound_all_layer_validation_precedes_runner_and_scratch_cleanup(monkeypatch,tmp_path,corrupt):
    current=load('peaso.collectors._pipeline_native_test',ROOT/'peaso/collectors/aws_image_vulnerability_native_20261021.py')
    monkeypatch.setitem(sys.modules,'peaso.collectors.aws_image_layer_pipeline_20261022',pipeline)
    layers=[]
    for i in range(3):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as tar:
            data=b'ID=alpine\nVERSION_ID=3.22.0\n' if i==0 else f'file-{i}'.encode()
            info=tarfile.TarInfo('etc/os-release' if i==0 else f'usr/fixture-{i}')
            info.size=len(data);tar.addfile(info,io.BytesIO(data))
        layers.append(output.getvalue())
    config=json.dumps({'os':'linux','architecture':'amd64',
        'rootfs':{'type':'layers','diff_ids':[archive.sha(layer) for layer in layers]}}).encode()
    doc={'schemaVersion':2,'mediaType':archive.OCI,
        'config':dict(mediaType=next(x for x in archive.CONFIGS if 'oci' in x),size=len(config),digest=archive.sha(config)),
        'layers':[dict(mediaType='application/vnd.oci.image.layer.v1.tar',size=len(layer),digest=archive.sha(layer)) for layer in layers]}
    manifest=json.dumps(doc).encode();digest=archive.sha(manifest)
    payloads={archive.sha(value):value for value in [config,*layers]}
    q=SimpleNamespace(_lock=threading.RLock(),max_calls=None,calls=0,deadline=None,
                      timeout=5,check_deadline=lambda:None)
    class Client:
        def get_download_url_for_layer(self,**args):
            return dict(ResponseMetadata={'HTTPStatusCode':200},layerDigest=args['layerDigest'],
                        downloadUrl=bench.PREFIX+args['layerDigest']+'?fixture=synthetic')
    reader=native.Reader(q,SimpleNamespace(client=lambda *a,**kw:Client()),'123456789012','us-east-1')
    verified=[];reader.caller=lambda:verified.append('caller');reader.manifest=lambda *a:(manifest,doc)
    ran=[]
    def runner(identity,manifest,configuration,paths,**kwargs):
        assert [path.read_bytes() for path in paths]==layers
        archive.validate(identity,manifest,configuration,paths)
        assert kwargs['native_verifier']()==identity
        assert kwargs['native_verifier']()==identity
        ran.append(True)
        return {'image':identity,'status':'PASS','complete':True,'findings':[]}
    with bench.Fixture(payloads,corrupt=archive.sha(layers[0]) if corrupt else None) as fixture:
        monkeypatch.setattr(content,'build_opener',fixture.opener)
        args=(reader,{'scope':'123456789012/us-east-1'},'fixture',digest,
              '123456789012.dkr.ecr.us-east-1.amazonaws.com/fixture@'+digest,None,
              manifest,doc,None,runner,None,str(tmp_path))
        if corrupt:
            with pytest.raises(ValueError):current._scan_bound(*args)
            assert not ran and not verified
        else:
            image,scan=current._scan_bound(*args)
            assert scan['complete'] and scan['image']==image and ran==[True]
            assert verified==['caller']*4
        assert fixture.active==0
    assert not list(tmp_path.iterdir())
