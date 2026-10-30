"""Selected AKS intake uses exact native validation without native registry startup."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def test_selected_registry_collector_import_does_not_start_checks_registry():
    script = r'''
import importlib.util, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
source = root / 'peaso/collectors/k8s_selected_registry_image_20261021.py'
spec = importlib.util.spec_from_file_location('selected_registry_under_test', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert 'peaso.checks' not in sys.modules
assert module.association.__file__ == str(root / 'peaso/k8s_image_source_association_20261020.py')
'''
    completed = subprocess.run([sys.executable, '-I', '-c', script, str(ROOT)],
                               capture_output=True, text=True, timeout=25)
    assert completed.returncode == 0, completed.stderr


def test_hosted_aks_registry_auth_is_structured_without_native_boot():
    # A disposable CA is test material, never cloud auth or a published credential.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime,timedelta,timezone
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'offline-test-ca')]);now=datetime.now(timezone.utc)
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(123).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256())
    ca=cert.public_bytes(serialization.Encoding.PEM).decode()
    scope='/subscriptions/12345678-1234-1234-1234-123456789abc'
    cluster=scope+'/resourceGroups/group/providers/Microsoft.ContainerService/managedClusters/cluster'
    target=dict(cluster_id=cluster,namespace='default',pod='pod-a',uid='poduid',resource_version='42',container_type='regular',container_name='app',image='registry.example.com/owned/demo@sha256:'+'a'*64)
    auth=dict(method='token',arm_token='offline-arm-token',aks_workloads=[dict(cluster_id=cluster,server='https://api.example.com',ca_cert_data=ca,token='offline-kube-token')],registry_auth=[dict(host='registry.example.com',repository='owned/demo',method='bearer',token='offline-registry-token')])
    options=dict(selected_azure_aks_pod_images=[target],selected_registry_hosts=['registry.example.com'])
    script=r'''
import importlib.abc,json,socket,sys
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
class Deny(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname.startswith(('peaso.collectors','peaso.checks','peaso.engine','peaso.analysis','boto3','botocore','google.auth','azure.identity','kubernetes')):raise AssertionError('native import '+fullname)
sys.meta_path.insert(0,Deny())
def blocked(*a,**kw):raise AssertionError('network attempted')
socket.socket.connect=blocked;socket.create_connection=blocked;socket.getaddrinfo=blocked
from peaso.server import validation
body=json.loads(sys.argv[2]);auth,options,scopes=body
validation.validate_connector('azure',auth,options,SimpleNamespace(auth_mode='cognito'),scopes=scopes)
# Foreign auth cannot bypass exact registry repository matching.
auth['registry_auth'][0]['repository']='foreign/repo'
try:validation.validate_connector('azure',auth,options,SimpleNamespace(auth_mode='cognito'),scopes=scopes)
except Exception as exc:assert getattr(exc,'status_code',None)==422
else:raise AssertionError('foreign registry credential accepted')
print('hosted-aks-native-free')
'''
    completed=subprocess.run([sys.executable,'-I','-c',script,str(ROOT),json.dumps([auth,options,[scope]])],capture_output=True,text=True,timeout=25)
    assert completed.returncode==0,completed.stderr
    assert 'hosted-aks-native-free' in completed.stdout
