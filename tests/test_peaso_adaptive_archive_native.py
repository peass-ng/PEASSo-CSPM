"""Isolated real extraction/decoder tests, not source-admission certification."""
import importlib.util,io,json,sys,tarfile,threading,time,zipfile
from pathlib import Path
from types import SimpleNamespace
import pytest
from peaso import secret_scanning as scanner,secret_scanning_batch as batch,secret_evidence as evidence
from peaso import collection_lease as lease, secret_scanning_errors as errors, secret_scanning_adaptive as adaptive
from peaso.collectors import aws_package_content_indicators as package
SECRET='synthetic_offline_secret'

def files(count=1025):return [(f'file-{i:04}.txt',(f'mode={i}\n'+('value='+SECRET+'\n'if i%512==0 else'')).encode())for i in range(count)]
def archive(kind,rows):
    output=io.BytesIO()
    if kind=='zip':
        with zipfile.ZipFile(output,'w')as z:
            for name,payload in rows:z.writestr(name,payload)
    else:
        with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT)as z:
            for name,payload in rows:
                info=tarfile.TarInfo(name);info.size=len(payload);z.addfile(info,io.BytesIO(payload))
    return output.getvalue()

def reader(seconds=600):
    r=SimpleNamespace(deadline=None if seconds is None else time.monotonic()+seconds,_lock=threading.RLock(),cancel_event=threading.Event())
    def check():
        if r.deadline is not None and time.monotonic()>=r.deadline:raise TimeoutError('native lease expired')
    r.check_deadline=check;return r

def clear_caches():
    with scanner._RESULT_LOCK:scanner._RESULTS.clear()
    try:from peaso import secret_scan_clean
    except ImportError:return
    with secret_scan_clean._LOCK:secret_scan_clean._CLEAN.clear()

@pytest.fixture
def tools(monkeypatch):
    calls=[];captured=[]
    def prepare(items,timeout):
        assert 0<timeout<=60;calls.append(len(items));result={}
        for payload,path in items:
            row={'Raw':SECRET,'DetectorName':'fixture','Verified':False}
            result[(payload,path)]=json.dumps(row).encode()if SECRET.encode()in payload else b''
        return result
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',prepare)
    monkeypatch.setattr(scanner,'_trufflehog',lambda:'synthetic-offline')
    monkeypatch.setattr(scanner,'_run',lambda argv,payload,timeout:json.dumps({'Raw':SECRET,'DetectorName':'fixture','Verified':False}).encode()if SECRET.encode()in payload else b'')
    monkeypatch.setattr(scanner,'_scan_kingfisher',lambda payload,path,timeout:[(SECRET,'fixture',2)]if SECRET.encode()in payload else[])
    monkeypatch.setattr(evidence,'enabled',lambda:True)
    def remember(value,fingerprint,**kw):
        captured.append((kw['path'],kw['line'],kw['engine'],dict(getattr(evidence._source,'fields',{})),kw['observed_bytes']))
    monkeypatch.setattr(evidence,'remember',remember)
    clear_caches()
    return calls,captured,prepare

def extract(kind,payload,r):
    with evidence.source_context(resource_id='owned-resource',scope='owned-scope',image_digest='sha256:'+'a'*64,layer='sha256:'+'b'*64):
        return package.scan_zip(payload,r)if kind=='zip'else package.scan_tar(payload,'application/vnd.oci.image.layer.v1.tar',r)


def test_typed_stdout_fallback_retains_all_native_files_and_disables_one_probe(monkeypatch,tools):
    calls,_,prepare=tools
    def dense(items,timeout):
        if len(items)>512:calls.append(len(items));raise errors.ScannerStdoutBound('scanner output bound')
        return prepare(items,timeout)
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',dense)
    r=reader();first=extract('zip',archive('zip',files()),r)
    assert len(first[0])==3 and calls==[1025,512,512,1]
    assert adaptive.archive_batch_items(r)==512
    assert r._archive_adaptive_th.metrics['consumed_sources']==1025
    clear_caches();calls.clear();second=extract('tar',archive('tar',files()),r)
    assert second[0]==first[0] and calls==[512,512]

def test_preparation_failure_uses_original_scan_and_keeps_partial_kf_positive(monkeypatch,tools):
    calls,_,_=tools
    def unavailable(items,timeout):
        calls.append(len(items))
        if len(items)>512:raise RuntimeError('offline unavailable')
        return None
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',unavailable)
    monkeypatch.setattr(scanner,'_trufflehog',lambda:'synthetic')
    monkeypatch.setattr(scanner,'_run',lambda *a:(_ for _ in()).throw(RuntimeError('offline unavailable')))
    with pytest.raises(package.PartialArchive)as exc:extract('zip',archive('zip',files()),reader())
    assert exc.value.refs and exc.value.refs[0]['Leaks']
    assert {d['engine']for d in exc.value.refs[0]['Leaks'][0]['detectors']}=={'kingfisher'}
    assert calls[:2]==[1025,512]

def test_consumer_partial_preserves_earlier_positive_without_rescanning(monkeypatch,tools):
    calls,captured,prepare=tools
    def dense(items,timeout):
        if len(items)>512:calls.append(len(items));raise errors.ScannerStdoutBound('scanner output bound')
        return prepare(items,timeout)
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',dense)
    original=package._scan;seen=[]
    def consume(payload,name,requests):
        seen.append(name)
        if name=='file-0512.txt':raise package.PartialArchive([],0,0)
        return original(payload,name,requests)
    monkeypatch.setattr(package,'_scan',consume);monkeypatch.setattr(package,'_DEFAULT_SCAN',consume)
    with pytest.raises(package.PartialArchive)as exc:extract('zip',archive('zip',files()),reader())
    assert exc.value.refs[0]['File']=='file-0000.txt'
    assert len(seen)==513 and len(set(seen))==513
    assert calls==[1025,512,512]
    assert batch._PREPARED_BATCH.get()is None


def test_no_absolute_lease_retains_legacy_limits_and_no_adaptive_state(tools):
    calls,_,_=tools;r=reader(None)
    assert adaptive.archive_batch_items(r)==512
    assert len(extract('tar',archive('tar',files()),r)[0])==3
    assert calls==[512,512] and not hasattr(r,'_archive_adaptive_th')


def test_original_ecr_row_layer_and_file_object_identity_preserved(tools):
    calls,_,_=tools;rows=[(payload,name,'layer-'+str(i%2),object())for i,(name,payload)in enumerate(files())];observed=[]
    with adaptive.prepared_archive_batches(rows,reader())as groups:
        for group in groups:observed.extend(group)
    assert len(observed)==len(rows)and all(got is expected for got,expected in zip(observed,rows))
    assert calls==[1025] and batch._PREPARED_BATCH.get()is None


def test_native_stdout_bound_has_exact_type_and_unchanged_message():
    candidate=scanner
    with pytest.raises(errors.ScannerStdoutBound)as exc:
        candidate._run([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*4194305)'],b'',10)
    assert exc.value.args==('scanner output bound',)
    assert candidate._run([sys.executable,'-c','print("safe")'],b'',10)==b'safe\n'

def test_metrics_accept_2048_but_public_legacy_preparation_stays_512():
    candidate=batch
    event=dict(schema=1,batch=1,items=2048,input_bytes=2048,unique_payloads=2048,unique_bytes=2048,prepared=1,reason='none',preparation_ms=1,consumer_ms=1,lookups=2048,prepared_reads=2048,serial_lookups=0,consumer_failed=0)
    assert candidate.safe_metrics(event)==event
    assert candidate.safe_metrics({**event,'items':2049})is None
    with pytest.raises(ValueError,match='content batch bound'):
        with candidate.prepared_content_batch([(b'x',str(i))for i in range(513)]):pass


def test_expired_existing_archive_lease_never_refreshes_or_prepares(tools):
    calls,_,_=tools;r=reader(-1);deadline=r.deadline
    with pytest.raises(TimeoutError):extract('zip',archive('zip',files()),r)
    assert not calls and r.deadline==deadline


def test_final_group_is_resumed_for_accounting_then_maps_cleared(tools):
    calls,_,_=tools;r=reader();rows=[(payload,name)for name,payload in files()]
    with adaptive.prepared_archive_batches(rows,r)as groups:
        assert sum(len(group)for group in groups)==1025
    assert r._archive_adaptive_th.metrics['consumed_sources']==1025
    assert batch._PREPARED_BATCH.get()is None
