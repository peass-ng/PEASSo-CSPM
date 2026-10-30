"""Isolated native Flux and Service-proxy fixtures; no release-tree import or network."""
import ast
from contextlib import nullcontext
from copy import deepcopy
import gzip
from hashlib import sha256
import importlib.util
import io
import json
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tarfile
import time
from types import FunctionType, SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
from peaso.collectors import k8s_selected_flux_artifact_20261021 as flux_module
from peaso.collectors import k8s_selected_log_sample_secret_indicators as native_module
from peaso.checks import k8s_selected_flux_artifact_review_20261021 as review_module
source = vars(flux_module)
review = vars(review_module)


def fixture(payload=b'mode=ready\n', *, second=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, content in [('chart/values.yaml', payload)] + ([('chart/README.md', b'hello\n')] if second else []):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    raw = gzip.compress(buffer.getvalue(), mtime=0)
    digest = 'sha256:' + sha256(raw).hexdigest()
    target = {'cluster_id': 'cluster.example', 'kind': 'HelmChart', 'namespace': 'default',
              'name': 'chart', 'uid': '11111111-1111-4111-8111-111111111111', 'resource_version': '42',
              'generation': 2, 'artifact_digest': digest, 'artifact_revision': '1.2.3',
              'artifact_path': 'helmchart/default/chart/chart-1.2.3.tgz', 'artifact_size': len(raw),
              'service_namespace': 'flux-system', 'service_uid': '22222222-2222-4222-8222-222222222222',
              'service_resource_version': '19', 'service_port_name': 'http'}
    native = {'apiVersion': 'source.toolkit.fluxcd.io/v1', 'kind': 'HelmChart',
              'metadata': {'namespace': 'default', 'name': 'chart', 'uid': target['uid'],
                           'resourceVersion': '42', 'generation': 2},
              'status': {'observedGeneration': 2, 'conditions': [{'type': 'Ready', 'status': 'True', 'observedGeneration': 2}],
                         'artifact': {'digest': digest, 'revision': '1.2.3', 'path': target['artifact_path'],
                                      'size': len(raw), 'url': 'http://source-controller.flux-system.svc.cluster.local./' + target['artifact_path']}}}
    service = {'apiVersion': 'v1', 'kind': 'Service',
               'metadata': {'namespace': 'flux-system', 'name': 'source-controller',
                            'uid': target['service_uid'], 'resourceVersion': '19'},
               'spec': {'type': 'ClusterIP', 'selector': {'app': 'source-controller'},
                        'ports': [{'name': 'http', 'port': 80, 'protocol': 'TCP'}]}}
    return target, native, service, raw


def scanner(raw, path, native, check, *, redact_values=None):
    check()
    leak = (b'mode=ready' in raw and scanner.hit)
    return {'complete': True, 'engines': [{'engine': 'kingfisher', 'version': '1.4.0', 'status': 'complete'},
            {'engine': 'trufflehog', 'version': '3.92.5', 'status': 'complete'}],
            'leaks': [{'fingerprint': 'a'*64, 'locations': [{'path': path}],
                       'detectors': [{'engine': 'kingfisher', 'rule': 'fixture'}]}] if leak else []}
scanner.hit = False


def inspect_case(target, native, service, raw, *, source_get=None, service_get=None, proxy_get=None):
    return source['inspect'](target, source_get or (lambda _: deepcopy(native)),
        service_get or (lambda _: deepcopy(service)), proxy_get or (lambda _: raw), scanner=scanner)


def index(target, item, status='collected'):
    return {'context': {'provider': 'k8s', 'scope': target['namespace'], 'metadata':
            {source['KIND']+'_authorized': True, source['OPTION']: [target]}},
            'collections': {source['KIND']: [{'type': source['KIND'], 'scope': target['namespace'],
               'service': 'kubernetes', 'status': status, 'items': [item]}]}}


class FluxTests(unittest.TestCase):
    def setUp(self):
        self.target, self.native, self.service, self.raw = fixture()
        scanner.hit = False

    def test_default_off_and_exact_selector(self):
        self.assertEqual(source['selected_targets']({}, ['default', 'flux-system']), [])
        self.assertEqual(source['collect'](object(), None, {}, ['default', 'flux-system'], 'cluster.example'), ({}, set()))
        options = {source['OPTION']: [self.target], 'content_secret_scans': True}
        self.assertEqual(source['selected_targets'](options, ['default', 'flux-system'], [source['CHECK']]), [self.target])
        self.assertFalse(source['enabled'](options, []))
        self.assertEqual(source['proxy_path'](self.target),
            '/api/v1/namespaces/flux-system/services/http:source-controller:http/proxy/helmchart/default/chart/chart-1.2.3.tgz')
        for field, value in [('artifact_path', 'helmchart/default/chart/../secret.tgz'),
                             ('artifact_path', 'helmchart/default/chart/%2e%2e.tgz'),
                             ('service_namespace', 'foreign')]:
            target = dict(self.target, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(source['Incomplete']):
                source['selected_targets']({source['OPTION']: [target]}, ['default', 'flux-system'])

    def test_clean_and_positive(self):
        for hit, expected in ((False, 'PASS'), (True, 'FAIL')):
            with self.subTest(hit=hit):
                scanner.hit = hit
                result = inspect_case(self.target, self.native, self.service, self.raw)
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['read']['digest'], self.target['artifact_digest'])
                item = {'id': source['identity'](self.target), 'name': source['identity'](self.target),
                        'SelectedFluxArtifact': result}
                self.assertEqual(review['evaluate'](item, index(self.target, item))[0], expected)
                self.assertNotIn('mode=ready', json.dumps(result))
                if not hit:
                    unversioned=deepcopy(item)
                    unversioned['SelectedFluxArtifact']['parts'][0]['engines'][0].pop('version')
                    self.assertEqual(review['evaluate'](unversioned,index(self.target,unversioned))[0],'UNKNOWN')
                    empty=deepcopy(item)
                    empty['SelectedFluxArtifact']['parts']=[]
                    self.assertEqual(review['evaluate'](empty,index(self.target,empty))[0],'UNKNOWN')

    def test_gitrepository_native_artifact(self):
        target=dict(self.target,kind='GitRepository',name='repo',
                    artifact_path='gitrepository/default/repo/abc123.tar.gz',
                    artifact_revision='main@sha1:abc123')
        native=deepcopy(self.native)
        native['kind']='GitRepository';native['metadata']['name']='repo'
        native['status']['artifact'].update(path=target['artifact_path'],revision=target['artifact_revision'],
            url='http://source-controller.flux-system.svc.cluster.local./'+target['artifact_path'])
        self.assertEqual(source['selected_targets']({source['OPTION']:[target]},['default','flux-system']),[target])
        self.assertEqual(inspect_case(target,native,self.service,self.raw)['status'],'PASS')

    def test_denied_foreign_service_digest_truncation_and_drift(self):
        def denied(_): raise source['Incomplete']('artifact_denied')
        faults = [('denied', lambda: inspect_case(self.target, self.native, self.service, self.raw, proxy_get=denied)),
                  ('foreign_service', lambda: inspect_case(self.target, self.native, dict(self.service,
                           metadata={**self.service['metadata'], 'uid': 'foreign'}), self.raw)),
                  ('truncated', lambda: inspect_case(self.target, self.native, self.service, self.raw[:-1])),
                  ('digest_drift', lambda: inspect_case(self.target, self.native, self.service, self.raw[:-1] + b'X'))]
        for label, fn in faults:
            with self.subTest(fault=label):
                result = fn()
                self.assertEqual(result['status'], 'UNKNOWN')
        calls = [0]
        def source_get(_):
            calls[0] += 1
            value = deepcopy(self.native)
            if calls[0] > 1: value['metadata']['resourceVersion'] = '43'
            return value
        result = inspect_case(self.target, self.native, self.service, self.raw, source_get=source_get)
        self.assertEqual(result['status'], 'UNKNOWN')

    def test_cancel_and_partial_positive(self):
        def cancelled(): raise source['Incomplete']('cancelled')
        count = [0]
        result = source['inspect'](self.target, lambda _: self.native, lambda _: self.service,
                                  lambda _: self.raw, scanner=scanner, cancel=cancelled)
        self.assertEqual(result['status'], 'UNKNOWN')
        target, native, service, raw = fixture(second=True)
        scanner.hit = True
        def partial(payload, path, native, check):
            count[0] += 1
            if count[0] > 1: raise source['Incomplete']('detector_unavailable')
            return scanner(payload, path, native, check)
        result = source['inspect'](target, lambda _: native, lambda _: service, lambda _: raw, scanner=partial)
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['complete'])

    def test_native_binary_get_shape(self):
        # The native adapter receives the API bearer only on the API-server origin.
        class Response:
            status=200
            def __init__(self, raw):
                self.raw=io.BytesIO(raw);self.headers={'Content-Length':str(len(raw)),
                    'Content-Type':'application/gzip','Content-Encoding':'identity'}
                self.closed=False;self.released=False
            def read(self, n): return self.raw.read(n)
            def close(self): self.closed=True
            def release_conn(self): self.released=True
        class Pool:
            def __init__(self, raw): self.raw=raw;self.calls=[];self.response=None
            def request(self, method, url, **kwargs):
                self.calls.append((method,url,kwargs))
                self.response=Response(self.raw)
                return self.response
        pool=Pool(self.raw)
        client=SimpleNamespace(last_response=None)
        fake_native=SimpleNamespace(_context=lambda api,cluster:(client,pool,'https://api.example',
            {'Authorization':'Bearer kube-only'},'binding'))
        api=object();reader=SimpleNamespace(call=lambda f:f(),check_cancelled=lambda:None)
        state={'deadline':time.monotonic()+30,'calls':0,'bytes':0,'context':None}
        native_get=source['_native_bytes']
        with patch.object(native_module, '_context', fake_native._context):
            self.assertEqual(native_get(reader,api,'cluster.example',self.target,state),self.raw)
        method,url,kwargs=pool.calls[0]
        self.assertEqual(method,'GET')
        self.assertEqual(url,'https://api.example'+source['proxy_path'](self.target))
        self.assertEqual(kwargs['headers']['Authorization'],'Bearer kube-only')
        self.assertFalse(kwargs['redirect'] if 'redirect' in kwargs else False)
        self.assertTrue(pool.response.closed and pool.response.released)

    def test_native_collector_proxy_positive_and_clean(self):
        class Response:
            def __init__(self, raw, fault):
                self.status = 403 if fault == 'denied' else 200
                self.raw = io.BytesIO(raw)
                self.headers = {'Content-Length': str(len(raw)), 'Content-Encoding': 'identity'}
            def read(self, size): return self.raw.read(size)
            def close(self): pass
            def release_conn(self): pass
        class Pool:
            literal_paths = frozenset()
            def __init__(self, fault): self.calls = [];self.fault=fault
            def request(self, method, url, **kwargs):
                self.calls.append((method, url, dict(kwargs)))
                self_outer.assertIn(source['proxy_path'](self_outer.target), self.literal_paths)
                body=(self_outer.raw[:-1] if self.fault == 'truncated' else
                      self_outer.raw[:-1]+b'X' if self.fault == 'digest' else self_outer.raw)
                response=Response(body,self.fault)
                if self.fault == 'truncated':response.headers['Content-Length']=str(len(self_outer.raw))
                return response
        self_outer = self
        for hit,fault,expected in ((False,None,'PASS'),(True,None,'FAIL'),
                                   (False,'denied','UNKNOWN'),(False,'truncated','UNKNOWN'),
                                   (False,'digest','UNKNOWN')):
            with self.subTest(hit=hit,fault=fault):
                scanner.hit = hit
                pool = Pool(fault)
                client = SimpleNamespace(last_response=None)
                seen = []
                def read(reader, api, cluster, path, fields, state):
                    seen.append(path)
                    self.assertIn(path, pool.literal_paths)
                    return (deepcopy(self.native if path == source['source_path'](self.target) else self.service), 1, 'binding')
                native = SimpleNamespace(_context=lambda api, cluster:(client,pool,'https://api.example',
                    {'Authorization':'Bearer kube-only'},'binding'), _read=read,
                    private_native_logs=lambda:nullcontext())
                reader=SimpleNamespace(budget=SimpleNamespace(max_items=10),total=0,collections=[],
                    call=lambda f:f(),check_cancelled=lambda:None)
                options={source['OPTION']:[self.target],'content_secret_scans':True,
                         '_flux_artifact_named_checks':[source['CHECK']]}
                original=source['inspect']
                source['inspect']=lambda *args,**kwargs:original(*args,scanner=scanner,**kwargs)
                try:
                    with patch.object(native_module, '_context', native._context), \
                         patch.object(native_module, '_read', native._read), \
                         patch.object(native_module, 'private_native_logs', native.private_native_logs):
                        metadata,_=source['collect'](reader,object(),options,['default','flux-system'],'cluster.example')
                finally:
                    source['inspect']=original
                self.assertTrue(metadata[source['KIND']+'_authorized'])
                self.assertEqual(reader.collections[0]['items'][0]['SelectedFluxArtifact']['status'],expected)
                self.assertEqual(seen.count(source['source_path'](self.target)),2)
                self.assertEqual(seen.count(source['service_path'](self.target)),2)
                self.assertEqual(len(pool.calls),1)
                self.assertEqual(pool.literal_paths,frozenset())

    def test_zip_parser_is_bounded_and_never_extracts(self):
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('chart/values.yaml',b'mode=ready\n')
        target=dict(self.target,artifact_path='helmchart/default/chart/chart.zip')
        leaks,parts,complete=source['_scan'](data.getvalue(),target,lambda:None,scanner)
        self.assertEqual(leaks,[])
        self.assertTrue(complete)
        self.assertEqual(len(parts),1)
        nested=io.BytesIO()
        with zipfile.ZipFile(nested,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('chart/inner.zip',b'PK\x03\x04nested')
        with self.assertRaises(source['Incomplete']):
            source['_scan'](nested.getvalue(),target,lambda:None,scanner)

    def test_serialized_cases_replay_in_other_process(self):
        script='''import importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
# Only the reviewed evaluator and its collector, not the whole check registry.
spec=importlib.util.spec_from_file_location("replay_review",root/"peaso/checks/k8s_selected_flux_artifact_review_20261021.py")
review=importlib.util.module_from_spec(spec);spec.loader.exec_module(review)
assert "peaso.checks" not in sys.modules
source=review.source
cases=json.loads((root/"peaso/checks/k8s_selected_flux_artifact_review_20261021_cases.json").read_text())[source.CHECK]
for branch,expected in (("pass","PASS"),("fail","FAIL"),("unknown","UNKNOWN"),("missing","UNKNOWN")):
 item,index=cases[branch],cases[branch+"_index"]
 assert review.evaluate(item,index)[0]==expected
 if branch!="missing":assert source.identity(index["context"]["metadata"][source.OPTION][0])==item["id"]
print("4 serialized branches replayed")'''
        p=subprocess.run([sys.executable,'-I','-c',script,str(ROOT)],capture_output=True,text=True,timeout=60)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('4 serialized branches replayed',p.stdout)
