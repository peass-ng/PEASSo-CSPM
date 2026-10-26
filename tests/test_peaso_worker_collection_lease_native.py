"""Canonical worker child lease/protocol gate, stops before artifacts/auth."""
import json,os,subprocess,sys,textwrap
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
@pytest.mark.parametrize('role,include,valid,configured',[('collector',True,True,True),('collector',False,True,False),('analyzer',True,True,False),('collector',True,False,False)])
def test_actual_child_hook_and_failure_protocol(tmp_path,role,include,valid,configured):
    result=tmp_path/'result.json'
    code='''
import importlib.util,json,time
from pathlib import Path
from types import SimpleNamespace
import sys
root=Path(sys.argv[1]);result=Path(sys.argv[2])
from peaso import collection_lease as lease, worker
assert worker._process.__module__=='peaso.worker'
class Pipe:
 def __init__(self):self.frames=[]
 def send(self,value):self.frames.append(value)
 def close(self):pass
pipe=Pipe();request={'connector':{'provider':'k8s'}}
if sys.argv[4]=='True':request['deadline']=time.time()+60 if sys.argv[5]=='True'else None
worker._process(sys.argv[3],request,pipe)
term=[f for f in pipe.frames if isinstance(f,tuple)and f and type(f[0])is bool]
deadline=lease.effective_deadline(SimpleNamespace(deadline=None))
result.write_text(json.dumps({'configured':deadline is not None,'terminal_count':len(term),'terminal_success':term[0][0],'error_code':term[0][1],'lease_remaining_seconds':deadline-time.monotonic()if deadline is not None else None}))
'''
    proc=subprocess.run([sys.executable,'-c',textwrap.dedent(code),str(ROOT),str(result),role,str(include),str(valid)],capture_output=True,text=True,timeout=60)
    assert proc.returncode==0,proc.stderr[:1000]
    row=json.loads(result.read_text());assert row['configured']is configured
    assert row['terminal_count']==1 and row['terminal_success']is False and row['error_code']=='invalid_input'
    if configured:assert 0<row['lease_remaining_seconds']<=60
