import hashlib,importlib.util,json,socket
from io import BytesIO
from pathlib import Path
import pytest
from peaso.collectors import k8s_selected_registry_image_20261021 as m
HOST='us-central1-docker.pkg.dev';REPO='owned-project/owned-repository/image';PREFIX='/artifacts-downloads/namespaces/owned-project/repositories/owned-repository/downloads/'
class Connection:
 def close(self):pass
class Response:
 def __init__(self,status,body=b'',location=None,extra=None):
  self.status=status;self.data=BytesIO(body);self.headers={'Content-Length':str(len(body)),'Content-Encoding':'identity'}
  if location is not None:self.headers['Location']=location
  self.headers.update(extra or {})
 def read(self,count):return self.data.read(count)
 def close(self):pass

def test_repository_bound_same_origin_blob_auth_digest_and_receipt():
 body=b'exact-owned-immutable-layer';digest='sha256:'+hashlib.sha256(body).hexdigest();calls=[]
 def wire(host,path,headers,timeout):
  calls.append((host,path,dict(headers)))
  return Connection(),Response(302,location=PREFIX+'opaque-provider-download') if len(calls)==1 else Response(200,body)
 reader=m.RegistryReader(HOST,REPO,lambda:None,authorization='Basic OWN_AUTH_NOT_FOR_OUTPUT',open_https=wire)
 assert reader.get('blobs',digest,1024,size=len(body))==body
 assert len(calls)==2 and calls[1][0]==HOST and calls[1][1].startswith(PREFIX)
 assert calls[1][2]['Authorization']==calls[0][2]['Authorization']
 assert reader.calls==2 and reader.receipts[0]['status']=='collected' and reader.receipts[0]['bytes']==len(body)
 assert 'OWN_AUTH' not in json.dumps(reader.receipts) and 'opaque-provider' not in json.dumps(reader.receipts)

@pytest.mark.parametrize('location',[
 'https://'+HOST+PREFIX+'token','https://evil.example'+PREFIX+'token','//evil.example'+PREFIX+'token',
 '/artifacts-downloads/namespaces/foreign-project/repositories/owned-repository/downloads/token',
 '/artifacts-downloads/namespaces/owned-project/repositories/foreign-repository/downloads/token',
 PREFIX+'token?signature=not-allowed',PREFIX+'token#fragment',PREFIX+'../token',PREFIX+'./token',
 PREFIX+'%2e%2e/token',PREFIX+'%252e%252e/token',PREFIX+'%2Ftoken',PREFIX+'%5ctoken',
 PREFIX+'%3Ftoken',PREFIX+'%23token',PREFIX+'%00token',PREFIX+'%FFtoken',PREFIX+'token\\next',
 PREFIX+'token\nnext',PREFIX+'token\tnext',PREFIX+'token//next',PREFIX,PREFIX+'x'*2049,
])
def test_foreign_encoded_or_ambiguous_paths_rejected_before_second_http_call(location):
 calls=[]
 def wire(*args):calls.append(args);return Connection(),Response(302,location=location)
 reader=m.RegistryReader(HOST,REPO,lambda:None,authorization='Basic private',open_https=wire)
 with pytest.raises(m.Incomplete,match='redirect_unsupported'):reader.get('blobs','sha256:'+'a'*64,1024)
 assert len(calls)==1

@pytest.mark.parametrize('status',[301,303,307,308])
def test_only_documented_gar_302_supported(status):
 calls=[]
 def wire(*args):calls.append(args);return Connection(),Response(status,location=PREFIX+'token')
 with pytest.raises(m.Incomplete,match='redirect_unsupported'):
  m.RegistryReader(HOST,REPO,lambda:None,open_https=wire).get('blobs','sha256:'+'a'*64,1024)
 assert len(calls)==1

@pytest.mark.parametrize('headers',[{'Content-Encoding':'gzip'},{'WWW-Authenticate':'Bearer realm=foreign'}])
def test_redirect_cannot_smuggle_encoded_body_or_auth_challenge(headers):
 with pytest.raises(m.Incomplete,match='redirect_unsupported'):
  m.RegistryReader(HOST,REPO,lambda:None,open_https=lambda *_:(Connection(),Response(302,location=PREFIX+'token',extra=headers))).get('blobs','sha256:'+'a'*64,1024)


def test_gar_redirect_once_only_and_manifest_never_redirects():
 for category,expected_calls in [('blobs',2),('manifests',1)]:
  calls=[]
  def wire(*args):calls.append(args);return Connection(),Response(302,location=PREFIX+'token')
  with pytest.raises(m.Incomplete,match='redirect_unsupported'):
   m.RegistryReader(HOST,REPO,lambda:None,open_https=wire).get(category,'sha256:'+'a'*64,1024)
  assert len(calls)==expected_calls

@pytest.mark.parametrize('body,limit,size',[ (b'corrupt',1024,None),(b'too-large',3,None),(b'valid',1024,6)])
def test_redirected_bytes_still_require_size_and_digest(body,limit,size):
 calls=[]
 def wire(*args):calls.append(args);return Connection(),Response(302,location=PREFIX+'token') if len(calls)==1 else Response(200,body)
 with pytest.raises(m.Incomplete):m.RegistryReader(HOST,REPO,lambda:None,open_https=wire).get('blobs','sha256:'+hashlib.sha256(b'valid').hexdigest(),limit,size=size)


def test_nonpublic_redirect_dns_still_rejected_before_connection(monkeypatch):
 monkeypatch.setattr(m.socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('169.254.169.254',443))])
 with pytest.raises(m.Incomplete,match='nonpublic_registry_address'):m._open_https(HOST,PREFIX+'token',{},1)
