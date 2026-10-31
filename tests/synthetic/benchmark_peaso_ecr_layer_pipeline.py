"""Real loopback HTTP layer pipeline replay; no cloud calls or workloads.

A test-only endpoint adapter maps synthetic allowed S3 URLs to loopback. Native
URL, byte-count, whole-digest, permission and deadline checks still run. Per-
connection delay models transport stalls; shared delay models saturated egress.
Neither fixture predicts live AWS throughput or complete CVE scan duration.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
from urllib.request import Request, build_opener

from peaso.collectors import aws_image_vulnerability_native_20261021 as native
from peaso.collectors import aws_package_content_indicators as content

REGION='us-east-1'
PREFIX='https://fixture.s3.us-east-1.amazonaws.com/'


def load(path):
    spec=importlib.util.spec_from_file_location('peaso.collectors._layer_pipeline_benchmark',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class Fixture:
    def __init__(self,bodies,*,shared=False,corrupt=None):
        self.bodies=bodies;self.shared=shared;self.corrupt=corrupt
        self.lock=threading.Lock();self.bandwidth=threading.Lock()
        self.active=self.peak=self.bytes=self.calls=0
        owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.0'
            def log_message(self,*args):pass
            def do_GET(self):
                key=self.path[1:].split('?',1)[0];body=owner.bodies[key]
                if key == owner.corrupt:body=body[:-1]+bytes([body[-1]^1])
                with owner.lock:
                    owner.active+=1;owner.peak=max(owner.peak,owner.active);owner.calls+=1
                try:
                    self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
                    for i in range(0,len(body),65536):
                        chunk=body[i:i+65536]
                        if owner.shared:
                            with owner.bandwidth:
                                time.sleep(.002);self.wfile.write(chunk);self.wfile.flush()
                        else:
                            time.sleep(.002);self.wfile.write(chunk);self.wfile.flush()
                        with owner.lock:owner.bytes+=len(chunk)
                except (BrokenPipeError,ConnectionResetError):pass
                finally:
                    with owner.lock:owner.active-=1
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.01})
    def __enter__(self):self.thread.start();return self
    def __exit__(self,*args):
        self.server.shutdown();self.thread.join();self.server.server_close()
    def opener(self,*handlers):
        base=build_opener(*handlers);port=self.server.server_port
        class Response:
            def __init__(self,response,url):self.response=response;self.url=url
            def __getattr__(self,key):return getattr(self.response,key)
            def geturl(self):return self.url
            def __enter__(self):self.response.__enter__();return self
            def __exit__(self,*args):return self.response.__exit__(*args)
        class Opener:
            def open(self,url,**kwargs):
                assert isinstance(url,str) and url.startswith(PREFIX)
                return Response(base.open(Request(f'http://127.0.0.1:{port}/'+url[len(PREFIX):]),**kwargs),url)
        return Opener()


def measure(pipeline,bodies,shared,*,parallel):
    q=SimpleNamespace(_lock=threading.RLock(),max_calls=None,calls=0,deadline=time.monotonic()+60,
                      timeout=5,check_deadline=lambda:None)
    class Client:
        def get_download_url_for_layer(self,**args):
            return {'layerDigest':args['layerDigest'],'downloadUrl':PREFIX+args['layerDigest']+'?fixture=synthetic',
                    'ResponseMetadata':{'HTTPStatusCode':200}}
        def close(self):pass
    reader=native.Reader(q,SimpleNamespace(client=lambda *args,**kwargs:Client()),'123456789012',REGION)
    descs=[dict(digest=key,size=len(body)) for key,body in bodies.items()]
    original=content.build_opener
    try:
        with tempfile.TemporaryDirectory(prefix='peaso-layer-pipeline-') as folder, Fixture(bodies,shared=shared) as fixture:
            root=Path(folder);root.chmod(0o700);content.build_opener=fixture.opener
            start=time.perf_counter()
            if parallel:paths=pipeline.download_layers(reader,'fixture',descs,root,'sha256:'+'a'*64)
            else:paths=[reader.blob('fixture',desc,path=root/f'layer-{i}.blob',image_digest='sha256:'+'a'*64) for i,desc in enumerate(descs)]
            elapsed=time.perf_counter()-start
            assert [path.read_bytes() for path in paths]==list(bodies.values())
            assert all(path.stat().st_mode & 0o777 == 0o600 for path in paths)
            expected=[entry for desc in descs for entry in (
                {'operation':'ecr:get_download_url_for_layer','status':'collected'},
                {'operation':'ecr:signed_layer_download','status':'collected','digest':desc['digest'],'bytes':desc['size']})]
            assert reader.ledger==expected and fixture.active==0
            return dict(wall_seconds=elapsed,http_requests=fixture.calls,transferred_bytes=fixture.bytes,
                sdk_calls=reader.calls,all_request_calls=q.calls,peak_http=fixture.peak,
                ordered_hashes=[hashlib.sha256(body).hexdigest() for body in bodies.values()],
                source_ledger_sha256=hashlib.sha256(json.dumps(reader.ledger,sort_keys=True).encode()).hexdigest())
    finally:content.build_opener=original;reader.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pipeline',type=Path);parser.add_argument('--mib',type=int,default=8)
    parser.add_argument('--layers',type=int,default=6);args=parser.parse_args()
    assert 1<=args.mib<=64 and 1<=args.layers<=16
    pipeline=load(args.pipeline);bodies={}
    for i in range(args.layers):
        seed=(f'synthetic-layer-{i}-'*1024).encode();size=args.mib*1024*1024
        body=(seed*(size//len(seed)+1))[:size]
        bodies['sha256:'+hashlib.sha256(body).hexdigest()]=body
    output=[]
    for shared in (False,True):
        old=measure(pipeline,bodies,shared,parallel=False);new=measure(pipeline,bodies,shared,parallel=True)
        for key in ('http_requests','transferred_bytes','sdk_calls','all_request_calls','ordered_hashes','source_ledger_sha256'):assert old[key]==new[key]
        output.append(dict(shared_bandwidth=shared,before=old,after=new,exact_parity=True))
    print(json.dumps(dict(cloud_calls=0,fixture='loopback HTTP with controlled2ms/64KiB delay',results=output),indent=2))
