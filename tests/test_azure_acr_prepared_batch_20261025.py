"""Bounded ACR batching retains source witnesses and complete prefix semantics."""
import contextlib
import json
import pytest
from peaso import secret_evidence, secret_scanning as scanning
from peaso.collectors import azure_acr_image_stream_inspection_20261021 as stream
from peaso.collectors import azure_acr_image_secret_indicators as native
from tests import test_acr_index_functional as fixtures

class Cipher:
    def encrypt(self, value): return json.dumps(value, sort_keys=True)
    def decrypt(self, value): return json.loads(value)

@pytest.fixture
def batches(monkeypatch):
    observed=[]
    @contextlib.contextmanager
    def prepared(items,timeout):
        assert 0<timeout<=30
        assert len(items)<=stream.MAX_BATCH_ITEMS
        assert sum(len(raw)for raw,_ in items)<=stream.MAX_BATCH_BYTES
        observed.append([(len(raw),path)for raw,path in items])
        yield
    monkeypatch.setattr(stream,'prepared_content_batch',prepared)
    monkeypatch.setattr(stream,'enable_pinned_shared_data',lambda reader:None)
    def detect(payload,path,timeout):
        if b'DETECTOR_FAIL'in payload:raise RuntimeError('synthetic unavailable')
        return [(fixtures.TOKEN,'github-pat',1)]if fixtures.TOKEN.encode()in payload else[]
    monkeypatch.setattr(scanning,'_scan_kingfisher',detect)
    monkeypatch.setattr(scanning,'_scan_trufflehog',detect)
    scanning._RESULTS.clear()
    yield observed
    scanning._RESULTS.clear()

def inspect(files):
    target,blobs=fixtures.selected_files(files)
    cipher=Cipher()
    with secret_evidence.capture(cipher,tenant='same',scan_id='same')as sink:
        row=stream.inspect_image(fixtures.FakeReader(target,blobs))
        records=[cipher.decrypt(value)for value in sink.records.values()]
    return row[native.MARKER],records

@pytest.mark.parametrize('cap',[2,7,512])
def test_layer_sources_share_bounded_prepared_batches(batches,monkeypatch,cap):
    monkeypatch.setattr(stream,'MAX_BATCH_ITEMS',cap)
    marker,records=inspect([(f'app/{n:03}.txt',b'clean')for n in range(40)])
    assert marker['complete'] is True and marker['regular_files']==40
    assert len(marker['parts'])==82  # manifest, config, 40 names and contents
    assert sum(len(batch)for batch in batches)==80
    assert len(batches)==(80+cap-1)//cap
    assert not marker['leaks'] and not records

@pytest.mark.parametrize('failed',[b'DETECTOR_FAIL',b'\x00binary',b'\x1f\x8bnested'])
def test_incomplete_file_does_not_suppress_later_source(batches,failed):
    marker,records=inspect([('app/a.txt',failed),('app/b.txt',fixtures.TOKEN.encode())])
    assert marker['complete'] is False
    assert marker['scan_partial'] is True and marker['skipped_files']==1
    assert marker['regular_files']==2 and len(marker['leaks'])==1
    assert records and fixtures.TOKEN not in json.dumps(marker)
    assert all(part['complete']is True for part in marker['parts'])
    assert any(part['part'].endswith('member-2.chunk-1')for part in marker['parts'])

@pytest.mark.parametrize('failure',[b'DETECTOR_FAIL',b'\x00binary',b'\x1f\x8bnested'])
def test_completed_positive_chunk_survives_later_partial_file(batches,failure):
    first=fixtures.TOKEN.encode()+b'A'*(stream.WINDOW-len(fixtures.TOKEN))
    marker,records=inspect([('app/one.txt',first+failure)])
    assert marker['complete'] is False and marker['skipped_files']==1
    assert len(marker['leaks'])==1 and records
    assert any(part['part'].endswith('chunk-1')for part in marker['parts'])
    assert not any(part['part'].endswith('chunk-2')for part in marker['parts'])

@pytest.mark.parametrize('index',[False,True])
def test_exact_layer_provenance_preserved_for_each_source(batches,index):
    target,blobs,_=fixtures.fixture(index=index,positive=True)
    cipher=Cipher()
    with secret_evidence.capture(cipher,tenant='same',scan_id='same')as sink:
        row=stream.inspect_image(fixtures.FakeReader(target,blobs))
        records=[cipher.decrypt(value)for value in sink.records.values()]
    marker=row[native.MARKER]
    assert marker['complete'] is True and len(marker['leaks'])==1 and records
    assert marker['manifest_digest']==target['digest']
    assert marker['source_requests']
    if index:assert len(marker['child_inspections'])==2 and marker['graph']['complete']is True

def test_failed_preparation_uses_fresh_serial_source_witnesses(batches,monkeypatch):
    from peaso import secret_scanning_batch as batch
    attempts=[]
    def fail(items,timeout):
        attempts.append(len(items))
        raise OSError('synthetic unavailable')
    monkeypatch.setattr(batch,'_prepare_trufflehog_batch',fail)
    monkeypatch.setattr(stream,'prepared_content_batch',batch.prepared_content_batch)
    marker,records=inspect([('app/one.txt',fixtures.TOKEN.encode()),('app/two.txt',b'clean')])
    assert attempts==[4]
    assert marker['complete'] is True and len(marker['leaks'])==1 and records

def test_retained_native_witness_source_inverse_is_exact_and_fail_closed():
    import hashlib
    from pathlib import Path
    from tests.azure_native_successor_inputs_20261020 import _current_acr_stream_predecessor
    name='peaso/collectors/azure_acr_image_stream_inspection_20261021.py'
    raw=Path(stream.__file__).read_bytes()
    expected='4f51b5162e6809840049aaa6f6528018d4c99f60b01d869759f50df961e0beeb'
    assert hashlib.sha256(_current_acr_stream_predecessor(name,raw)).hexdigest()==expected
    changed=raw.replace(b'WINDOW = 1024',b'WINDOW = 1025',1)
    assert changed!=raw
    assert hashlib.sha256(_current_acr_stream_predecessor(name,changed)).hexdigest()!=expected
    assert _current_acr_stream_predecessor('peaso/collectors/other.py',raw)==raw
