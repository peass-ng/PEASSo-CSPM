"""Publication diagnostics stay numeric, cross-thread, bounded, and read-only."""
from concurrent.futures import ThreadPoolExecutor
import json,threading
from peaso.storage import artifacts as storage

class MemoryS3:
 def __init__(self):self.objects={};self.order=[];self.lock=threading.Lock()
 def put_object(self,**value):
  with self.lock:self.objects[value['Key']]=value;self.order.append(value['Key'])

def test_actual_shared_helper_captures_worker_uploads_and_active_wait_without_values():
 from peaso import runtime_metrics as metrics
 module=storage
 frames=[];metrics.configure(frames.append,role='analyzer',interval_seconds=60)
 entered=threading.Barrier(3,timeout=5);release=threading.Event()
 class Client(MemoryS3):
  def put_object(self,**value):
   if '/manifest-' not in value['Key']:entered.wait();assert release.wait(5)
   super().put_object(**value)
 client=Client();store=module.S3Artifacts('private-bucket-DO_NOT_LOG',client=client)
 def publish():
  with store.batch(workers=2) as writer:
   refs=[writer.put('private-tenant-DO_NOT_LOG','d'*32,'findings',{'secret':'UNUSED_SYNTHETIC_VALUE_DO_NOT_LOG','i':i}) for i in range(2)]
   return writer.put('private-tenant-DO_NOT_LOG','d'*32,'manifest',{'references':refs})
 try:
  with ThreadPoolExecutor(max_workers=1) as pool:
   future=pool.submit(publish)
   try:
    entered.wait();metrics.flush()
    assert any(r['stage']=='artifact.s3.put' and r['count']==2 for r in frames[-1][1]['active'])
    assert not future.done() and not client.order
   finally:release.set()
   manifest=future.result(timeout=5)
  metrics.flush()
 finally:metrics.close()
 assert client.order[-1]=='artifacts/'+manifest
 assert all(tag=='__runtime_metrics__' and metrics.validate(event) for tag,event in frames)
 assert len(frames)<=3 and all(len(event['rows'])<=6 and len(json.dumps(event))<10000 for _,event in frames)
 rows={row['stage']:row for row in frames[-1][1]['rows']}
 assert rows['artifact.s3.put']['count']==3 and rows['artifact.s3.put']['bytes']==sum(len(v['Body']) for v in client.objects.values())
 assert rows['artifact.batch.wait']['count']>=1
 encoded=json.dumps(frames)
 for marker in ['UNUSED_SYNTHETIC_VALUE_DO_NOT_LOG','private-bucket-DO_NOT_LOG','private-tenant-DO_NOT_LOG','artifacts/','references']:
  assert marker not in encoded


def test_actual_shared_helper_disabled_path_never_reads_clocks(monkeypatch):
 from peaso import runtime_metrics as metrics
 metrics.close()
 monkeypatch.setattr(metrics.time,'monotonic',lambda:(_ for _ in ()).throw(AssertionError('disabled metrics clocked')))
 monkeypatch.setattr(metrics.time,'thread_time',lambda:(_ for _ in ()).throw(AssertionError('disabled metrics clocked')))
 monkeypatch.setattr(metrics.time,'process_time',lambda:(_ for _ in ()).throw(AssertionError('disabled metrics clocked')))
 with metrics.span('artifact.serialize'):metrics.add_bytes('artifact.serialize',500)
