"""Live registry/plan contracts and real offline OCI consumers; no cloud calls."""
from copy import deepcopy
import json
from types import SimpleNamespace
from pathlib import Path
import pytest
from peaso import engine,content_scan_selection as selection
from peaso.finding_types import type_for

SCOPES={'aws':['123456789012/us-east-1'],'gcp':['projects/fixture-project'],'azure':['/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'],'k8s':['default']}


def test_every_capability_is_active_owned_native_check_with_reviewed_tool_taxonomy():
 registry={c.id:c for c in engine._registry()}
 for provider,option,stage,cid in selection.ROWS:
  assert cid in registry,cid
  c=registry[cid]
  assert c.provider==provider
  assert type_for(cid)==('secrets' if stage=='leaks' else 'vulnerabilities')
  assert c.kind and c.dependencies
  assert option is None or option.startswith('selected_')
 # Pure configuration and provider-assessment controls are intentionally excluded.
 ids={cid for _,_,_,cid in selection.ROWS}
 assert not {'aws.review.ecs_task_definition.configuration_secret_indicators','azure.claude.defender_assessment_running_images_vulnerabilities','gcp.compute.os_config_fixable_vulnerabilities','gcp.review.gke_workload.literal_configuration_secret_indicators'}&ids


@pytest.mark.parametrize('provider',['aws','gcp'])
def test_all_automatic_native_readers_pass_real_engine_preflight_and_plan(provider):
 request={'connector':{'provider':provider,'scopes':SCOPES[provider],'auth':{},'options':{'content_secret_scans':True}},'categories':[],'checks':[],'leaks_enabled':True,'images_enabled':False}
 expected={cid for owner,opt,stage,cid in selection.ROWS if owner==provider and opt is None and stage=='leaks'}
 assert expected
 effective=selection.normalize_request(request)
 actual=engine._request(effective)
 chosen=engine._selection(provider,[],[],[],content_checks=effective['content_checks'])[1]
 assert {c.id for c in chosen}==expected
 plan=set(engine.plan_collection(effective))
 assert all(c.kind in plan for c in chosen)
 assert actual['options']['content_secret_scans'] is True


def test_disabled_capture_uses_authoritative_taxonomy_not_absent_check_attribute():
 request={'connector':{'provider':'gcp','scopes':SCOPES['gcp'],'options':{'content_secret_scans':True}},'categories':['hardening'],'checks':['gcp.review.function.literal_environment_secret_indicators'],'leaks_enabled':False}
 chosen=engine._selection('gcp',['hardening'],request['checks'],[])[1]
 assert chosen and not hasattr(chosen[0],'finding_type')
 assert type_for(chosen[0].id)=='secrets'
 assert selection.capture_checks(request)==set()


def _poison_secret_tools(monkeypatch):
 from peaso import secret_scanning
 calls=[]
 def poison(*a,**kw):calls.append(True);raise AssertionError('images-only reached secret tools')
 for name in ('scan_content','_scan_kingfisher','_scan_trufflehog','_kingfisher','_trufflehog'):
  monkeypatch.setattr(secret_scanning,name,poison)
 return calls,poison


def test_aws_images_only_executes_real_native_sdk_oci_and_trivy_without_secrets(monkeypatch):
 from tests import test_aws_image_vulnerability_runtime_20261021 as fixture
 from peaso.collectors import aws_image_vulnerability_native_20261021 as native
 calls,_=_poison_secret_tools(monkeypatch)
 image=fixture.image.__wrapped__()
 request={'connector':{'provider':'aws','scopes':[fixture.SCOPE],'options':{'content_secret_scans':True,'image_vulnerability_scans':True,'selected_aws_images':[image.target]}},'categories':[],'leaks_enabled':False,'images_enabled':True}
 # Use the exact native contract's option, avoiding guessed field aliases.
 from peaso import aws_image_selection_20261021 as contract
 request['connector']['options'][contract.OPTION]=request['connector']['options'].pop('selected_aws_images')
 effective=selection.normalize_request(request);runtime=engine._request(effective)
 assert contract.KIND in engine.plan_collection(effective)
 counter=[];run=fixture.scan_runner()
 def trivy(*a,**kw):counter.append(True);return run(*a,**kw)
 with fixture.aws_fixture(image,monkeypatch) as (session,_):
  requests=fixture.requests();requests.content_secret_scans=runtime['options']['content_secret_scans']
  result=native.collect_native(requests,session,fixture.ACCOUNT,fixture.REGION,[image.target],enabled=runtime['options']['image_vulnerability_scans'],runner=trivy)
 assert result['status']=='FAIL' and result['complete'] and counter==[True] and calls==[]


@pytest.mark.parametrize('provider',['k8s','azure'])
def test_pod_bound_images_only_executes_real_native_oci_trivy_without_secrets(provider,monkeypatch):
 from tests.test_azure_selected_aks_image_20261021 import fixture,Wire,RID,SCOPE
 from peaso.collectors import k8s_selected_registry_image_20261021 as native,azure_selected_aks_image_20261021 as aks
 target,pod,blobs=fixture();calls,poison=_poison_secret_tools(monkeypatch);counter=[]
 option=native.OPTION if provider=='k8s' else aks.OPTION
 scopes=[target['namespace']] if provider=='k8s' else [SCOPE]
 request={'connector':{'provider':provider,'scopes':scopes,'options':{'content_secret_scans':True,'image_vulnerability_scans':True,option:[target],native.ALLOWLIST:['ghcr.io']}},'categories':[],'leaks_enabled':False,'images_enabled':True}
 effective=selection.normalize_request(request);runtime=engine._request(effective);opts=runtime['options'];named=selection.named_checks(effective)
 selected=(native.selected_targets if provider=='k8s' else aks.selected_targets)(opts,scopes,named)
 assert selected==[target]
 assert opts['content_secret_scans'] is False and opts['image_vulnerability_scans'] is True
 kind=native.VULN_KIND if provider=='k8s' else aks.VULN_KIND
 assert kind in engine.plan_collection(effective)
 def trivy(image,manifest,config,layers,**kw):
  assert kw['native_verifier']()==image;counter.append(True)
  return {'image':deepcopy(image),'status':'FAIL','complete':True,'scan_complete':True,'coverage_status':'COMPLETE','database':{'fresh':True},'findings':[{'vulnerability_id':'CVE-2026-1001','severity':'HIGH','package_types':['debian'],'package':'openssl','version':'1.0','fixed_in':['1.1'],'fix_status':'fixed','classes':['os-pkgs'],'image_digest':image['manifest_digest']}]}
 wire=Wire(blobs);factory=lambda host,repo,cancel,**kw:native.RegistryReader(host,repo,cancel,open_https=wire,**kw)
 kwargs=dict(allowed_hosts=['ghcr.io'],registry_factory=factory,scanner=poison,secret_enabled=opts['content_secret_scans'],trivy_enabled=opts['image_vulnerability_scans'],trivy_runner=trivy)
 if provider=='k8s':marker=native.inspect(target,lambda _:deepcopy(pod),**kwargs);image=marker
 else:
  arm={'id':RID,'name':'aks','type':'Microsoft.ContainerService/managedClusters','properties':{'provisioningState':'Succeeded','fqdn':'aks.example.com','resourceUID':'arm-uid'}}
  marker=aks.inspect_selected(target,arm_get=lambda _:deepcopy(arm),namespace_get=lambda:{'apiVersion':'v1','kind':'Namespace','metadata':{'name':'kube-system','uid':'cluster-uid'}},pod_get=lambda _:deepcopy(pod),context={'cluster_id':RID,'server':'https://aks.example.com','ca_cert_data':'test-only','token':'test-only'},tenant='tenant-id',**kwargs);image=marker['image']
 assert image['vulnerability']['complete'] and image['vulnerability']['status']=='FAIL' and counter==[True] and calls==[]
 assert wire.calls and all(response.closed for response in wire.responses)


def test_gcp_images_only_executes_real_native_metadata_oci_and_trivy_without_secrets(monkeypatch,tmp_path):
 from tests import gcp_job_image_vulnerability_fixture_20261021 as fixture
 from peaso.collectors import gcp_registry_trivy_20261021 as native
 from peaso import gcp_image_selection_20261021 as contract
 _,bodies,blobs=fixture.fixtures();row,_=fixture.image();reference=row['uri'].removeprefix('https://')
 calls,_=_poison_secret_tools(monkeypatch);trivy_calls=[]
 request={'connector':{'provider':'gcp','scopes':[fixture.SCOPE],'options':{'content_secret_scans':True,'image_vulnerability_scans':True,contract.OPTION:[reference]}},'categories':[],'leaks_enabled':False,'images_enabled':True}
 effective=selection.normalize_request(request);runtime=engine._request(effective)
 assert 'artifact_selected_image_vulnerabilities' in engine.plan_collection(effective)
 def trivy(image,manifest,config,layers,**kw):
  assert kw['native_verifier']()==image;trivy_calls.append(True)
  return {'image':deepcopy(image),'status':'FAIL','complete':True,'scan_complete':True,'coverage_status':'COMPLETE','database':{'fresh':True},'findings':[{'vulnerability_id':'CVE-2026-1001','severity':'HIGH','package_types':['debian'],'package':'openssl','version':'1.0','fixed_in':['1.1'],'fix_status':'fixed','classes':['os-pkgs'],'image_digest':image['manifest_digest']}]}
 metadata=fixture.MetadataSession(bodies);image=fixture.ImageSession(blobs)
 result=native.collect_native(fixture.transport(),scope=fixture.SCOPE,selectors=[reference],enabled=runtime['options']['image_vulnerability_scans'],metadata_session=metadata,image_session=image,db_cache=tmp_path,runner=trivy)
 assert result['status']=='FAIL' and result['complete'] and trivy_calls==[True] and calls==[]
 assert metadata.calls and image.calls and metadata.closed and image.closed


def test_gke_images_only_native_cluster_binding_and_trivy_without_secrets(monkeypatch):
 import base64
 from datetime import datetime,timedelta,timezone
 from cryptography import x509
 from cryptography.x509.oid import NameOID
 from cryptography.hazmat.primitives.asymmetric import ed25519
 from cryptography.hazmat.primitives.serialization import Encoding
 from tests.test_azure_selected_aks_image_20261021 import fixture,Wire
 from peaso.collectors import k8s_selected_registry_image_20261021 as image,gcp_gke_selected_pod_image_20261021 as native
 from peaso import gcp_gke_image_selection_20261021 as contract
 target,pod,blobs=fixture();target['cluster_id']='projects/fixture-project/locations/us-central1/clusters/fixture';calls,poison=_poison_secret_tools(monkeypatch);counter=[]
 request={'connector':{'provider':'gcp','scopes':['projects/fixture-project'],'options':{'content_secret_scans':True,'image_vulnerability_scans':True,contract.OPTION:[target],contract.HOSTS:['ghcr.io']}},'categories':[],'leaks_enabled':False,'images_enabled':True}
 effective=selection.normalize_request(request);runtime=engine._request(effective);opts=runtime['options']
 assert contract.selected(opts,['projects/fixture-project'],selection.named_checks(effective))==[target]
 assert native.VULN_KIND in engine.plan_collection(effective)
 key=ed25519.Ed25519PrivateKey.generate();name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Offline test CA')]);now=datetime.now(timezone.utc)
 cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,None);pem=cert.public_bytes(Encoding.PEM)
 cluster={'name':'fixture','location':'us-central1','selfLink':'https://container.googleapis.com/v1/'+target['cluster_id'],'status':'RUNNING','id':'native-cluster-id','endpoint':'8.8.8.8','masterAuth':{'clusterCaCertificate':base64.b64encode(pem).decode()}}
 def trivy(identity,manifest,config,layers,**kw):
  assert kw['native_verifier']()==identity;counter.append(True)
  return {'image':deepcopy(identity),'status':'FAIL','complete':True,'scan_complete':True,'coverage_status':'COMPLETE','database':{'fresh':True},'findings':[{'vulnerability_id':'CVE-2026-1001','severity':'HIGH','package_types':['debian'],'package':'openssl','version':'1.0','fixed_in':['1.1'],'fix_status':'fixed','classes':['os-pkgs'],'image_digest':identity['manifest_digest']}]}
 wire=Wire(blobs);factory=lambda host,repo,cancel,**kw:image.RegistryReader(host,repo,cancel,open_https=wire,**kw)
 marker=native.inspect_selected(target,gke_get=lambda _:deepcopy(cluster),namespace_get=lambda:{'apiVersion':'v1','kind':'Namespace','metadata':{'name':'kube-system','uid':'cluster-uid'}},pod_get=lambda _:deepcopy(pod),context={'cluster_id':target['cluster_id'],'server':'https://8.8.8.8','ca_cert_data':pem.decode(),'token':'synthetic-context-token'},allowed_hosts=['ghcr.io'],registry_factory=factory,scanner=poison,secret_enabled=opts['content_secret_scans'],trivy_enabled=opts['image_vulnerability_scans'],trivy_runner=trivy)
 assert marker['complete'] and marker['image']['vulnerability']['status']=='FAIL' and counter==[True] and calls==[]


@pytest.mark.parametrize('backend',['sqlite','dynamodb'])
def test_scheduled_dispatch_retains_content_and_analysis_ai_flags(backend,tmp_path):
 from contextlib import ExitStack
 from peaso.storage.sqlite import SQLiteStore
 with ExitStack() as stack:
  if backend=='sqlite':store=SQLiteStore(tmp_path/'state')
  else:
   import moto,boto3
   from peaso.storage.dynamodb import DynamoStore
   stack.enter_context(moto.mock_aws());client=boto3.client('dynamodb',region_name='us-east-1')
   client.create_table(TableName='content-contract',KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},{'AttributeName':'SK','KeyType':'RANGE'}],AttributeDefinitions=[{'AttributeName':'PK','AttributeType':'S'},{'AttributeName':'SK','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST');store=DynamoStore('content-contract',client)
  connector=store.add_connector('alice',{'provider':'aws','name':'schedule'},'ciphertext')
  data={'connector_id':connector['id'],'categories':[],'checks':[],'content_checks':['aws.review.ecr.selected_image_vulnerabilities'],'leaks_enabled':False,'images_enabled':True,'frameworks':[],'ai_enabled':True,'ai_priorities_enabled':False,'ai_network_enabled':True,'ai_user_id':'alice','interval_hours':24}
  import time
  now=time.time();store.add_schedule('alice',data,now-1);row=store.due_schedules(now=now)[0];job=store.trigger_schedule(row,limit=10,now=now)
  saved=json.loads(store.job('alice',job['id'])['data'])
  for field in ('content_checks','leaks_enabled','images_enabled','ai_enabled','ai_priorities_enabled','ai_network_enabled','ai_user_id'):assert saved[field]==data[field]
