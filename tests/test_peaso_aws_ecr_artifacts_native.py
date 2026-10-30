"""Real ECR SDK shapes through native collector and unchanged SW43."""
import base64,hashlib,json
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION
from peaso.collectors import aws,collect_live
from peaso.collectors import aws_ecr_artifacts_native as native
from tests.archived_check_contract import evaluate_snapshot, collect_snapshot
SIGN='aws_ecr_image_provenance';SBOM='aws_ecr_sbom_present';REPO='native-fixture'
URL='https://native-bucket.s3.us-east-1.amazonaws.com/blob?X-Amz-Signature=private-query'
sha=lambda b:'sha256:'+hashlib.sha256(b).hexdigest()
encode=lambda x:json.dumps(x,separators=(',',':'))
CONFIG={'mediaType':'application/vnd.oci.empty.v1+json','size':2,'digest':sha(b'{}')}

def capture(sdk,monkeypatch,mode='good',hosted=False):
 session,add=sdk;sts=add('sts');ecr=add('ecr')
 sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/fixture','UserId':'fixture'},{})
 parent=encode({'schemaVersion':2,'mediaType':native.OCI,'config':CONFIG,'layers':[]});digest=sha(parent.encode());key=Ed25519PrivateKey.generate()
 public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
 policy={'profile':native.PROFILE,'content_read_approved':True,'images':[{'scope':ACCOUNT+'/'+REGION,'repository_name':REPO,'image_digest':digest}],'approved_signing_public_keys':[{'KeyId':'approved','PublicKeyPem':public}]}
 options={'regions':[REGION],'retry_attempts':1,'compliance_parameters':{'aws_ecr_artifacts':policy}}
 if mode=='no_keys':policy['approved_signing_public_keys']=[]
 if mode=='no_optin':options.pop('compliance_parameters')
 if hosted:
  from peaso.server.validation import validate_connector
  options.pop('retry_attempts');validate_connector('aws',{'method':'assume_role','role_arn':f'arn:aws:iam::{ACCOUNT}:role/ReadOnly','external_id':'peaso-fixture'},options,SimpleNamespace(auth_mode='cognito'),server_external_id=True)
 args={'registryId':ACCOUNT,'repositoryName':REPO}
 def response(manifest,selector):return {'images':[{'registryId':ACCOUNT,'repositoryName':REPO,'imageId':{'imageDigest':sha(manifest.encode()),**selector},'imageManifest':manifest,'imageManifestMediaType':json.loads(manifest)['mediaType']}],'failures':[]}
 parent_response=response(parent,{'imageDigest':digest})
 if mode in ('alias_good','alias_conflict'):
  parent_response['images'][0]['imageId']['imageTag']='stable'
  alias=json.loads(json.dumps(parent_response['images'][0]));alias['imageId']['imageTag']='release'
  if mode=='alias_conflict':alias['imageManifestMediaType']=native.DOCKER
  parent_response['images'].append(alias)
 ecr.add_response('batch_get_image',parent_response,{**args,'imageIds':[{'imageDigest':digest}]})
 value={'critical':{'identity':{'docker-reference':'ignored.invalid/repo'},'image':{'docker-manifest-digest':digest},'type':'cosign container image signature'},'optional':None}
 if mode=='foreign_digest':value['critical']['image']['docker-manifest-digest']='sha256:'+'b'*64
 payload=(json.dumps(value,indent=2)if mode=='pretty'else encode(value)).encode();sigkey=Ed25519PrivateKey.generate()if mode=='unapproved'else key
 signed=json.dumps(value,indent=2).encode()if mode=='reserialized'else payload
 signature=base64.b64encode(sigkey.sign(signed)if mode!='bad_signature'else b'bad').decode()
 sbom=encode({'spdxVersion':'SPDX-2.3','packages':[]}if mode!='bad_sbom'else{'wrong':'schema'}).encode()
 content=[(native.SIGN,payload,signature),('application/spdx+json',sbom,None)]
 if mode in('none','partial','ref_denied','ref_page_cap'):content=[]
 refs=[];manifests=[];downloads=[];blobs={};legacy=mode in('legacy','legacy_artifact_budget')or mode.startswith('legacy_join_')
 for i,(typ,body,sig)in enumerate(content):
  layer={'mediaType':typ,'size':len(body),'digest':sha(body)}
  if sig is not None:layer['annotations']={'dev.cosignproject.cosign/signature':sig,'untrustedKeyId':'approved','token':'must-not-persist'}
  if mode=='external':layer['urls']=['https://untrusted.invalid/blob']
  if mode=='unknown_layer':layer['mediaType']='application/unknown'
  document={'schemaVersion':2,'mediaType':native.OCI,'artifactType':typ,'config':CONFIG,'subject':{'digest':digest},'layers':[layer]}
  if mode=='wrong_subject':document['subject']['digest']='sha256:'+'b'*64
  if mode=='multilayer':document['layers']*=2
  if legacy:
   document.pop('subject');document.pop('artifactType')
   if typ in native.SBOM:
    if mode=='legacy_join_foreign_subject':document['subject']={'digest':'sha256:'+'b'*64}
    if mode=='legacy_join_null_subject':document['subject']=None
    if mode=='legacy_join_malformed_subject':document['subject']='not-an-OCI-descriptor'
    if mode=='legacy_join_foreign_type':document['artifactType']=native.SIGN
    if mode=='legacy_join_null_type':document['artifactType']=None
    if mode=='legacy_join_consistent':document.update(subject={'digest':digest},artifactType=typ)
  manifest=encode(document);aid=sha(manifest.encode());ref={'digest':aid,'mediaType':native.OCI,'artifactType':typ,'size':len(manifest.encode()),'artifactStatus':'ACTIVE'}
  if mode=='wrong_size':ref['size']+=1
  refs.append(ref);manifests.append((manifest,aid));url=URL+'&part='+str(i);blobs[url]=b'x'*len(body)if mode=='tamper'else body
  download={'layerDigest':layer['digest'],'downloadUrl':'http://127.0.0.1/private'if mode=='bad_url'else url}
  if mode=='wrong_layer':download['layerDigest']='sha256:'+'b'*64
  downloads.append((layer,download))
 refargs={**args,'subjectId':{'imageDigest':digest},'maxResults':50};wire=[]if legacy else refs
 if mode=='duplicate':wire*=2
 if mode=='bundle':wire=[{'digest':'sha256:'+'b'*64,'mediaType':native.OCI,'artifactType':'application/vnd.dev.sigstore.bundle.v0.3+json','size':100,'artifactStatus':'ACTIVE'}]
 if mode=='ref_page_cap':
  for page in range(3):ecr.add_response('list_image_referrers',{'referrers':[],'nextToken':'page'+str(page+1)},{**refargs,**({'nextToken':'page'+str(page)}if page else{})})
  ecr.add_response('list_image_referrers',{'referrers':[]},{**refargs,'nextToken':'page3'})
 elif mode=='ref_denied':ecr.add_client_error('list_image_referrers','AccessDeniedException',expected_params=refargs)
 else:ecr.add_response('list_image_referrers',{'referrers':wire,**({'nextToken':'next'}if mode in('paged','partial')else{})},refargs)
 if mode=='paged':ecr.add_response('list_image_referrers',{'referrers':[]},{**refargs,'nextToken':'next'})
 if mode=='partial':options['max_pages']=1
 if not legacy:
  for manifest,aid in manifests:
   result=response(manifest,{'imageDigest':aid})
   if mode=='foreign_registry':result['images'][0]['registryId']='999999999999'
   if mode=='wrong_manifest':result['images'][0]['imageManifest']+=' '
   ecr.add_response('batch_get_image',result,{**args,'imageIds':[{'imageDigest':aid}]})
 for suffix in('sig','sbom','att'):
  selector={'imageTag':digest.replace(':','-')+'.'+suffix}
  if legacy and suffix!='att':result=response(manifests[0 if suffix=='sig'else 1][0],selector)
  elif mode=='att'and suffix=='att':result=response(parent,selector)
  else:result={'images':[],'failures':[{'imageId':selector,'failureCode':'ImageNotFound'}]}
  ecr.add_response('batch_get_image',result,{**args,'imageIds':[selector]})
 for layer,download in downloads:
  if mode=='layer_denied':ecr.add_client_error('get_download_url_for_layer','AccessDeniedException',expected_params={**args,'layerDigest':layer['digest']})
  else:ecr.add_response('get_download_url_for_layer',download,{**args,'layerDigest':layer['digest']})
 monkeypatch.setattr(native,'fetch_layer',lambda requests,url,size:blobs[url]);monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
 if mode=='near_manifest_budget':monkeypatch.setattr(native,'MAX_CONTENT_BYTES',len(parent.encode())+sum(len(x[0].encode())for x in manifests)-1)
 if mode=='layer_shared_budget':monkeypatch.setattr(native,'MAX_CONTENT_BYTES',len(parent.encode())+sum(len(x[0].encode())for x in manifests)+len(payload)+len(sbom)-1)
 if mode=='content_budget':monkeypatch.setattr(native,'MAX_CONTENT_BYTES',1)
 if mode in('artifact_budget','legacy_artifact_budget'):monkeypatch.setattr(native,'MAX_ARTIFACTS',1)
 connector={'provider':'aws','scopes':[ACCOUNT],'options':options}
 snapshot=collect_snapshot({'connector':connector,'checks':[SIGN,SBOM]})if hosted else collect_live(connector,['ecr_image','ecr_oci_artifact'])
 findings=evaluate_snapshot(snapshot,checks=[SIGN,SBOM],include_not_applicable=True)['findings'];results={f['check_id']:f['status']for f in findings}
 assert set(results)=={SIGN,SBOM},findings
 assert 'private-query'not in json.dumps(snapshot)and'must-not-persist'not in json.dumps(snapshot)
 if mode in('good','alias_good','pretty','legacy','paged','none','bad_signature','unapproved','foreign_digest','reserialized','bad_sbom','no_keys'):sts.assert_no_pending_responses();ecr.assert_no_pending_responses()
 if mode.startswith('legacy_join_'):
  if mode=='legacy_join_consistent':ecr.assert_no_pending_responses()
  else:
   assert len(ecr._queue)==1
   assert ecr._queue[0]['expected_params']=={**args,'layerDigest':downloads[1][0]['digest']}
 if mode=='ref_page_cap':
  assert ecr._queue[0]['expected_params'].get('nextToken')=='page3'
  env=next(c for c in snapshot['collections']if c['type']=='ecr_oci_artifact')
  assert env['status']not in('collected','empty')and env['error']['code']=='page_limit'
 return results,snapshot

@pytest.mark.parametrize('mode,signature,sbom',[
 ('good','PASS','PASS'),('pretty','PASS','PASS'),('legacy','PASS','PASS'),('paged','PASS','PASS'),('none','FAIL','FAIL'),('bad_signature','FAIL','PASS'),('unapproved','FAIL','PASS'),('foreign_digest','FAIL','PASS'),('reserialized','FAIL','PASS'),('bad_sbom','PASS','FAIL'),('no_keys','UNKNOWN','PASS'),
 ('content_budget','UNKNOWN','UNKNOWN'),('artifact_budget','UNKNOWN','UNKNOWN'),('no_optin','UNKNOWN','UNKNOWN'),('partial','UNKNOWN','UNKNOWN'),('bundle','UNKNOWN','UNKNOWN'),('att','UNKNOWN','UNKNOWN'),('multilayer','UNKNOWN','UNKNOWN'),('unknown_layer','UNKNOWN','UNKNOWN'),('external','UNKNOWN','UNKNOWN'),('wrong_subject','UNKNOWN','UNKNOWN'),('wrong_size','UNKNOWN','UNKNOWN'),('duplicate','UNKNOWN','UNKNOWN'),('foreign_registry','UNKNOWN','UNKNOWN'),('wrong_manifest','UNKNOWN','UNKNOWN'),('wrong_layer','UNKNOWN','UNKNOWN'),('tamper','UNKNOWN','UNKNOWN'),('bad_url','UNKNOWN','UNKNOWN'),('ref_denied','DENIED','DENIED'),('layer_denied','DENIED','DENIED')])
def test_native_sdk_to_frozen_engine(sdk,monkeypatch,mode,signature,sbom):assert capture(sdk,monkeypatch,mode)[0]=={SIGN:signature,SBOM:sbom}

def test_hosted_owner_policy_to_actual_planner_engine(sdk,monkeypatch):
 results,snapshot=capture(sdk,monkeypatch,hosted=True);assert set(results.values())=={'PASS'}
 assert snapshot['metadata']['ecr_artifact_profile']['deployed_images_observed']is False
 artifact=next(a for c in snapshot['collections']if c['type']=='ecr_oci_artifact'for a in c['items']if a['artifactType']==native.SIGN)
 assert artifact['keyId']=='approved'


@pytest.mark.parametrize('mode,expected',[('alias_good','PASS'),('alias_conflict','UNKNOWN')])
def test_artifact_collector_digest_tag_aliases(sdk,monkeypatch,mode,expected):
 results,snapshot=capture(sdk,monkeypatch,mode)
 assert results=={SIGN:expected,SBOM:expected}
 collections={row['type']:row for row in snapshot['collections']}
 assert (collections['ecr_oci_artifact']['status']=='collected') is (mode=='alias_good')
 if mode=='alias_conflict':assert collections['ecr_oci_artifact']['items']==[]

@pytest.mark.parametrize('url',['http://bucket.s3.us-east-1.amazonaws.com/blob','https://127.0.0.1/blob','https://s3.us-east-1.amazonaws.com.evil.invalid/blob','https://bucket.s3.us-east-1.amazonaws.com:8443/blob','https://user@bucket.s3.us-east-1.amazonaws.com/blob','https://bucket.s3.us-west-2.amazonaws.com/blob','https://bucket.s3.us-east-1.amazonaws.com/blob#part','https://bucket.s3.us-east-1.amazonaws.com%2fevil.invalid/object','https://bucket.s3.us-east-1.amazonaws.com%40evil.invalid/object','https://user%40evil@bucket.s3.us-east-1.amazonaws.com/object'])
def test_url_cannot_escape_aws_s3_boundary(url):
 with pytest.raises(ValueError):native.validate_url(url,REGION,'aws')

@pytest.mark.parametrize('mode',['good','oversize','bad_length','encoding','redirect','failure','budget'])
def test_real_http_reader_no_redirect_bounded_and_global_budget(monkeypatch,mode):
 req=aws.Requests({'max_calls':1,'read_timeout':3});body=b'content';headers={'Content-Length':str(len(body))};calls=[]
 if mode=='bad_length':headers['Content-Length']='123'
 if mode=='encoding':headers['Content-Encoding']='gzip'
 if mode=='budget':req.calls=1
 class Response:
  status=200
  def __enter__(self):return self
  def __exit__(self,*args):pass
  def geturl(self):return 'https://elsewhere.invalid/'if mode=='redirect'else URL
  def read(self,limit):calls.append(limit);return body+b'x'if mode=='oversize'else body
 Response.headers=headers
 class Opener:
  def open(self,url,timeout):
   assert url==URL and 0<timeout<=3
   if mode=='failure':raise RuntimeError('do not disclose URL')
   return Response()
 def build(*handlers):
  assert any(type(h).__name__=='_NoRedirect'for h in handlers)
  assert any(isinstance(h,native.ProxyHandler)and h.proxies=={}for h in handlers)
  return Opener()
 monkeypatch.setattr(native,'build_opener',build)
 if mode=='good':assert native.fetch_layer(req,URL,len(body))==body and calls==[len(body)+1]
 else:
  with pytest.raises(aws.ReadFailure):native.fetch_layer(req,URL,len(body))
 assert req.calls==1


def proposal_options():
 key=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
 return {'compliance_parameters':{'aws_ecr_artifacts':{'profile':native.PROFILE,'content_read_approved':True,'images':[
  {'scope':ACCOUNT+'/us-east-1','repository_name':'service/one','image_digest':'sha256:'+'a'*64},
  {'scope':ACCOUNT+'/us-east-1','repository_name':'service/two','image_digest':'sha256:'+'b'*64},
  {'scope':ACCOUNT+'/eu-west-1','repository_name':'service/three','image_digest':'sha256:'+'c'*64}],
  'approved_signing_public_keys':[{'KeyId':'approved','PublicKeyPem':key}]}}}

def test_companion_proposal_exact_two_actions_three_repositories_and_denials():
 from fnmatch import fnmatchcase
 options=proposal_options();policy=native.companion_policy(options);statement=policy['Statement'][0]
 assert policy['Version']=='2012-10-17'and statement['Effect']=='Allow'
 assert statement['Action']==['ecr:BatchGetImage','ecr:GetDownloadUrlForLayer']and len(statement['Resource'])==3
 def allowed(action,resource):return any(fnmatchcase(action,a)for a in statement['Action'])and any(fnmatchcase(resource,r)for r in statement['Resource'])
 for region,repo in [('us-east-1','service/one'),('us-east-1','service/two'),('eu-west-1','service/three')]:
  for action in statement['Action']:assert allowed(action,f'arn:aws:ecr:{region}:{ACCOUNT}:repository/{repo}')
 for action in ['ecr:GetAuthorizationToken','ecr:PutImage','ecr:DeleteRepository','ecr:SetRepositoryPolicy']:
  assert not allowed(action,f'arn:aws:ecr:us-east-1:{ACCOUNT}:repository/service/one')
 for resource in [f'arn:aws:ecr:us-west-2:{ACCOUNT}:repository/service/one',f'arn:aws:ecr:us-east-1:999999999999:repository/service/one',f'arn:aws:ecr:us-east-1:{ACCOUNT}:repository/service/foreign']:
  assert not allowed('ecr:BatchGetImage',resource)

def test_content_operations_never_expand_default_metadata_customer_policy():
 from scripts import peaso_deploy_customer_policy as role
 assert role.iam_action('ecr','list_image_referrers')=='ecr:BatchGetImage'
 assert role.iam_action('ecr','batch_get_image')=='ecr:BatchGetImage'
 assert role.iam_action('ecr','get_download_url_for_layer')=='ecr:GetDownloadUrlForLayer'
 assert {op for op in role.UNGRANTED_CONTENT_OPERATIONS if op[0]=='ecr'}==native.READ_ACTIONS
 assert role.UNGRANTED_CONTENT_OPERATIONS>=native.READ_ACTIONS|{
  ('lambda','get_function'),('lambda','get_layer_version'),
  ('codecommit','get_repository'),('codecommit','get_branch'),('codecommit','get_folder'),
  ('codecommit','get_file'),('logs','filter_log_events'),
  ('amplify','get_app'),('apigateway','get_stage'),
  ('glue','get_job'),('glue','get_connection'),('ssm','describe_document'),
  ('s3','head_object'),('s3','get_object')}
 policy=role.build_policy(include_credential_report_generation=False)
 assert policy==role.build_policy(aws.READ_ACTIONS|role.PRESERVED_TEMPLATE_READ_ACTIONS|native.READ_ACTIONS,
                                 include_credential_report_generation=False)
 text=json.dumps(policy)
 assert 'ecr:BatchGetImage'not in text and'ecr:GetDownloadUrlForLayer'not in text and'ecr:GetAuthorizationToken'not in text

@pytest.mark.parametrize('mode',['observed','no_optin','unknown_profile','duplicate_digest','wildcard_repo','foreign_fields','duplicate_key_material','private_key'])
def test_normative_policy_cannot_supply_observation_or_expand_scope(mode):
 options=proposal_options();p=options['compliance_parameters']['aws_ecr_artifacts']
 if mode=='observed':p['inventory_complete']=True
 if mode=='no_optin':p['content_read_approved']=False
 if mode=='unknown_profile':p['profile']='all-registry-formats'
 if mode=='duplicate_digest':p['images'][1]['image_digest']=p['images'][0]['image_digest']
 if mode=='wildcard_repo':p['images'][0]['repository_name']='service/*'
 if mode=='foreign_fields':p['images'][0]['payload']='invented'
 if mode=='duplicate_key_material':p['approved_signing_public_keys'].append({**p['approved_signing_public_keys'][0],'KeyId':'alias'})
 if mode=='private_key':p['approved_signing_public_keys'][0]['PublicKeyPem']=Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
 with pytest.raises(ValueError):native.normalize(options)


@pytest.mark.parametrize('parameters',[None,[],True])
def test_local_malformed_policy_namespace_rejected_before_any_read(parameters):
 with pytest.raises(ValueError):native.normalize({'compliance_parameters':parameters})


@pytest.mark.parametrize('mode,ref_fetches,downloads', [('artifact_budget',0,0),('near_manifest_budget',2,0),('layer_shared_budget',2,1),('ref_page_cap',0,0)])
def test_manifest_inventory_and_content_budgets_precede_further_fetches(sdk,monkeypatch,mode,ref_fetches,downloads):
 calls=[];original=aws.Requests.detail
 def detail(self,session,service,region,operation,**kwargs):
  calls.append((operation,kwargs.get('imageIds')))
  return original(self,session,service,region,operation,**kwargs)
 monkeypatch.setattr(aws.Requests,'detail',detail)
 statuses,snapshot=capture(sdk,monkeypatch,mode)
 assert statuses=={SIGN:'UNKNOWN',SBOM:'UNKNOWN'}
 assert sum(op=='batch_get_image'and ids and'imageDigest'in ids[0]for op,ids in calls)-1==ref_fetches
 assert sum(op=='get_download_url_for_layer'for op,ids in calls)==downloads
 if mode=='near_manifest_budget':assert not any(op=='batch_get_image'and ids and'imageTag'in ids[0]for op,ids in calls)


def test_legacy_artifact_capacity_reserved_before_request(sdk,monkeypatch):
 calls=[];original=aws.Requests.detail
 def detail(self,session,service,region,operation,**kwargs):
  calls.append((operation,kwargs.get('imageIds')))
  return original(self,session,service,region,operation,**kwargs)
 monkeypatch.setattr(aws.Requests,'detail',detail)
 statuses,snapshot=capture(sdk,monkeypatch,'legacy_artifact_budget')
 assert statuses=={SIGN:'UNKNOWN',SBOM:'UNKNOWN'}
 tags=[ids[0]['imageTag']for op,ids in calls if op=='batch_get_image'and ids and'imageTag'in ids[0]]
 assert len(tags)==1 and tags[0].endswith('.sig')
 assert not any(op=='get_download_url_for_layer'for op,ids in calls)


@pytest.mark.parametrize('mode,expected',[
 ('legacy_join_foreign_subject','UNKNOWN'),('legacy_join_null_subject','UNKNOWN'),
 ('legacy_join_malformed_subject','UNKNOWN'),('legacy_join_foreign_type','UNKNOWN'),
 ('legacy_join_null_type','UNKNOWN'),('legacy_join_consistent','PASS')])
def test_legacy_tags_cannot_override_present_native_manifest_identity(sdk,monkeypatch,mode,expected):
 results,snapshot=capture(sdk,monkeypatch,mode)
 assert results=={SIGN:expected,SBOM:expected}
