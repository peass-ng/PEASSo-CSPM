"""Future local bound positives; independent of any current release suite."""
from copy import deepcopy
import json
import pytest
from portable_fixture import load_fixture
from peaso import secret_scanning as scanning
from peaso.collectors import gcp_sourcerepo_secret_indicators as producer
from peaso.checks import gcp_sourcerepo_secret_review_20261019 as consumer

fixture = load_fixture("test_gcp_sourcerepo_secret_review_20261019.py")

@pytest.fixture(autouse=True)
def restore_scan_cache():
 scanning._RESULTS.clear()
 yield
 scanning._RESULTS.clear()
TOKEN='synthetic-supported-positive-only'

def native(patch,positive=True,failed=None,paths=None):
 scanning._RESULTS.clear()
 patch.setattr(fixture,'adapter',producer)
 c,*_=fixture.fixture(patch,payload=TOKEN.encode() if positive else b'clean',mock_engines=False,paths=paths)
 for engine in ('kingfisher','trufflehog'):
  if engine==failed:
   def scanner(*args,**kwargs):raise RuntimeError('synthetic unavailable detector')
  else:
   def scanner(payload,path,timeout):return [(TOKEN,'synthetic-rule',1)] if positive else []
  patch.setattr(scanning,'_scan_'+engine,scanner)
 row,index=fixture.produce(c)
 status,evidence=consumer.evaluate(row,index)
 assert TOKEN not in json.dumps([row,evidence])
 return row,index,status,evidence

@pytest.mark.parametrize('positive',[False,True])
@pytest.mark.parametrize('failed',[None,'kingfisher','trufflehog'])
def test_positive_and_negative_completion(monkeypatch,positive,failed):
 row,index,status,evidence=native(monkeypatch,positive,failed)
 assert status==('FAIL' if positive else 'UNKNOWN' if failed else 'PASS'),(row,evidence)
 if positive:
  assert len(evidence['secret_leaks'])==1
  assert evidence['complete'] is (failed is None)

@pytest.mark.parametrize('mutation',['scope','commit','project','blob','receipt','wire','location','unavailable_engine','complete','coverage','accounting'])
def test_partial_positive_must_retain_every_native_binding(monkeypatch,mutation):
 row,index,status,evidence=native(monkeypatch,True,'trufflehog')
 assert status=='FAIL'
 row=deepcopy(row);index=deepcopy(index)
 # Replace the copied inventory row so equality/membership checks do not mask
 # the particular native binding intentionally invalidated below.
 index['collections'][producer.KIND][0]['items']=[row]
 marker=row[producer.MARKER]
 if mutation=='scope':index['context']['scope']='projects/foreign'
 elif mutation=='commit':marker['selection']['commit']='f'*40
 elif mutation=='project':index['collections']['project'][0]['items'][0]['projectId']='foreign'
 elif mutation=='blob':marker['files'][0]['identity']='foreign'
 elif mutation=='receipt':marker['read_receipts'][-1]['http_status']=403
 elif mutation=='wire':marker['content_accounting']['wire_bytes']+=1
 elif mutation=='location':marker['leaks'][0]['locations'][0]['path']='sourcerepo.selected_file.'+'f'*64
 elif mutation=='unavailable_engine':marker['leaks'][0]['detectors']=[{'engine':'trufflehog','rule':'synthetic-rule'}]
 elif mutation=='complete':marker['complete']=True;marker['reason']='complete'
 elif mutation=='coverage':row['_coverage'][producer.MARKER]['status']='collected'
 elif mutation=='accounting':marker['content_accounting']['selected_bytes']=0
 assert consumer.evaluate(row,index)[0]=='UNKNOWN',mutation

def test_duplicate_engine_matches_have_one_leak(monkeypatch):
 row,index,status,evidence=native(monkeypatch,True)
 assert status=='FAIL' and len(evidence['secret_leaks'])==1
 assert {d['engine'] for d in evidence['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}


def test_later_selected_file_failure_keeps_prior_native_bound_positive(monkeypatch):
 original=scanning.scan_content;calls=[]
 def inspect(payload,path,**kwargs):
  calls.append(path)
  if len(calls)==2:raise RuntimeError('synthetic later inspection failure')
  return original(payload,path,**kwargs)
 monkeypatch.setattr(producer,'scan_content',inspect)
 row,index,status,evidence=native(monkeypatch,True,paths=['a.txt','b.txt'])
 assert len(calls)==2 and len(row[producer.MARKER]['files'])==1
 assert status=='FAIL', (row,evidence)
 assert evidence['complete'] is False and len(evidence['secret_leaks'])==1


def test_later_selected_file_failure_with_no_positive_remains_unknown(monkeypatch):
 original=scanning.scan_content;calls=[]
 def inspect(payload,path,**kwargs):
  calls.append(path)
  if len(calls)==2:raise RuntimeError('synthetic later inspection failure')
  return original(payload,path,**kwargs)
 monkeypatch.setattr(producer,'scan_content',inspect)
 row,index,status,evidence=native(monkeypatch,False,paths=['a.txt','b.txt'])
 assert len(calls)==2 and status=='UNKNOWN'




def test_partial_positive_public_projection_deduplicates_both_tools(monkeypatch):
 from peaso.secret_findings import deduplicate_secret_findings
 row,index,status,evidence=native(monkeypatch,True,'trufflehog')
 finding={'provider':'gcp','scope':fixture.SCOPE,'resource_id':row['name'],
          'native_resource_id':row['name'],'resource_type':producer.KIND,
          'check_id':consumer.CHECK_ID,'status':status,'frameworks':[],
          'evidence':evidence,'severity':'high','category':'hardening'}
 full_row,full_index,full_status,full_evidence=native(monkeypatch,True)
 assert full_status=='FAIL' and full_row['name']==row['name']
 full=dict(finding,evidence=full_evidence)
 result=deduplicate_secret_findings([finding,full,deepcopy(finding)])
 assert len(result)==1
 assert TOKEN not in json.dumps(result)
