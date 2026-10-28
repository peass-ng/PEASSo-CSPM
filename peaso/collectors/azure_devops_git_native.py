"""Explicit Azure DevOps project applicability, metadata-only Git URL facts."""
import base64,json,re,uuid,time,threading
from urllib.parse import urlsplit,parse_qs,urlencode
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError
from peaso.azure_devops_git_policy import normalize,assess_urls,UUID,ORG,OPERATIONS
KIND='devops_project'
MAX_BYTES=2_000_000
MAX_TOTAL_BYTES=16_000_000
MAX_PAGES=20
MAX_REPOS=1000
MAX_CALLS=512
MAX_SECONDS=120

class _NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise ValueError('DevOps redirect rejected')

def endpoint(url,org):
 if not isinstance(url,str)or any(ord(c)<=32 or ord(c)>=127 for c in url)or '%'in url or '\\'in url:raise ValueError('DevOps endpoint rejected')
 p=urlsplit(url);q=parse_qs(p.query,strict_parsing=True)
 if p.scheme!='https'or p.netloc!='dev.azure.com'or p.fragment or not re.fullmatch(ORG,org)or not p.path.startswith('/'+org+'/'):raise ValueError('DevOps endpoint origin rejected')
 suffix=p.path[len(org)+2:]
 patterns=[r'_apis/projects',r'_apis/projects/'+UUID,UUID+r'/_apis/git/repositories',UUID+r'/_apis/git/repositories/'+UUID]
 if not any(re.fullmatch(x,suffix)for x in patterns)or q.get('api-version')!=['7.1']or any(len(v)!=1 for v in q.values()):raise ValueError('DevOps endpoint path rejected')
 allowed={'api-version'}
 if suffix=='_apis/projects':
  allowed|={'stateFilter','$top','continuationToken'}
  if q.get('stateFilter')!=['all']or q.get('$top')!=['100']:raise ValueError('DevOps project list options rejected')
  if 'continuationToken'in q and not re.fullmatch(r'[0-9]{1,10}',q['continuationToken'][0]):raise ValueError('DevOps continuation rejected')
 elif suffix.endswith('/repositories'):
  allowed|={'includeHidden','includeAllUrls'}
  if q.get('includeHidden')!=['true']or q.get('includeAllUrls')!=['true']:raise ValueError('DevOps repository options rejected')
 if set(q)-allowed:raise ValueError('DevOps query rejected')
 return p.path

def _object(pairs):
 out={}
 for k,v in pairs:
  if k in out:raise ValueError('duplicate DevOps JSON field')
  out[k]=v
 return out

def request_metadata(url,credential,state):
 """Project before returning; no raw URLs, response errors or auth enter caches."""
 from .azure import AzureReadError
 org=credential['server'].rsplit('/',1)[-1];path=endpoint(url,org)
 if state['bytes']>=MAX_TOTAL_BYTES:raise AzureReadError('devops_byte_limit')
 token=credential['token'];header='Bearer '+token if credential['method']=='bearer'else'Basic '+base64.b64encode((':'+token).encode()).decode()
 try:
  with build_opener(ProxyHandler({}),_NoRedirect()).open(Request(url,headers={'Authorization':header,'Accept':'application/json'},method='GET'),timeout=max(0.01,min(20,state.get('deadline',time.monotonic()+20)-time.monotonic())))as response:
   with state.setdefault('lock',threading.Lock()):
    if state['bytes']>=MAX_TOTAL_BYTES:raise AzureReadError('devops_byte_limit')
    body=response.read(min(MAX_BYTES,MAX_TOTAL_BYTES-state['bytes'])+1)
    state['bytes']+=len(body)
    if len(body)>MAX_BYTES or state['bytes']>MAX_TOTAL_BYTES:raise AzureReadError('devops_byte_limit')
   continuation=response.headers.get('x-ms-continuationtoken')
  raw=json.loads(body,object_pairs_hook=_object)
  return project_response(raw,path,continuation)
 except HTTPError as exc:
  status=exc.code;exc.close();raise AzureReadError('devops_http_error',status)from None

def project_response(raw,path,continuation=None):
 def item(row,repository):
  if not isinstance(row,dict):raise ValueError('DevOps native object malformed')
  out={'id':row.get('id')}
  if repository:
   project=row.get('project');out['projectId']=project.get('id')if isinstance(project,dict)else None
   from peaso.secret_evidence import url_credentials
   urls=[('remoteUrl',row.get('remoteUrl'))]+[('validRemoteUrls['+str(i)+']',u)for i,u in enumerate(row.get('validRemoteUrls',[]) if isinstance(row.get('validRemoteUrls'),list) else [])]
   for field,url in urls:
    url_credentials(url,resource_id=out['projectId'] or out['id'],path=field,check_id='azure.review.devops.visible_clone_urls_without_userinfo',source=path+'/repository/'+str(out['id']))
   out['url_assessments']=assess_urls(row)
   out['remote_assessment']=assess_urls({'remoteUrl':row.get('remoteUrl'),'validRemoteUrls':[]})
  else:
   out['state']=row.get('state')
   out['visibility']=row.get('visibility') if row.get('visibility') in ('public','private') else None
  return out
 repository='/_apis/git/repositories'in path
 listing=path.endswith('/projects')or path.endswith('/repositories')
 if listing:
  if not isinstance(raw,dict)or set(raw)!={'count','value'}or not isinstance(raw.get('value'),list)or type(raw.get('count'))is not int or raw['count']!=len(raw['value'])or len(raw['value'])>MAX_REPOS:raise ValueError('DevOps native list malformed')
  if continuation is not None and (not isinstance(continuation,str)or not re.fullmatch(r'[0-9]{1,10}',continuation)or int(continuation)>2147483647):raise ValueError('DevOps continuation malformed')
  if repository and continuation is not None:raise ValueError('DevOps repository pagination unsupported')
  return {'items':[item(r,repository)for r in raw['value']],'continuation':continuation}
 if continuation is not None:raise ValueError('DevOps unexpected continuation')
 return item(raw,repository)

def collect(reader,request,transport,scopes,wanted,options,auth):
 if KIND not in wanted:return
 from .azure import AzureReadError
 policies=normalize(options,auth);credentials={c['server']:c for c in auth.get('devops_credentials',[])};state={'bytes':0,'calls':0,'deadline':time.monotonic()+MAX_SECONDS,'lock':threading.Lock()};capture=str(uuid.uuid4());jobs=[]
 for scope in scopes:
  def inventory(scope=scope):
   policy=policies.get(scope.lower())
   if policy is None:raise AzureReadError('devops_owner_applicability_missing')
   org=policy['organization'];server='https://dev.azure.com/'+org;credential=credentials.get(server)
   if credential is None:raise AzureReadError('devops_explicit_credential_missing')
   # Owner binding states applicability only. ARM establishes the selected Azure
   # subscription/tenant; it does not turn DevOps projects into ARM children.
   def bounded_call(operation,*args):
    def execute():
     with state['lock']:
      if time.monotonic()>=state['deadline']:raise AzureReadError('deadline_exceeded',408)
      if state['calls']>=MAX_CALLS:raise AzureReadError('call_limit')
      state['calls']+=1
     from peaso.secret_evidence import source_context
     with source_context(scope=scope):
      return operation(*args)
    return reader.call(execute)
   subscription=bounded_call(request,'https://management.azure.com'+scope+'?api-version=2022-12-01')
   tenant=getattr(transport,'verified_tenant',None)
   if (not isinstance(subscription,dict)or not isinstance(subscription.get('id'),str)
       or subscription['id'].lower()!=scope.lower()or not isinstance(tenant,str)
       or not isinstance(subscription.get('tenantId'),str)or subscription['tenantId'].lower()!=tenant.lower()):raise AzureReadError('devops_subscription_tenant_unverified')
   def read(path,query=''):
    reader.check_cancelled()
    return bounded_call(request_metadata,server+path+'?api-version=7.1'+query,credential,state)
   visible={};seen_tokens=set();token=None
   for page in range(min(MAX_PAGES,reader.budget.max_pages or MAX_PAGES)):
    data=read('/_apis/projects','&stateFilter=all&$top=100'+('&continuationToken='+token if token is not None else''))
    for row in data['items']:
     identity=row.get('id')
     if not isinstance(identity,str)or not re.fullmatch(UUID,identity)or identity.lower()in visible:raise ValueError('DevOps project identity duplicate or malformed')
     visible[identity.lower()]=row
     if len(visible)>10000:raise AzureReadError('devops_project_limit')
    token=data['continuation']
    if token is None:break
    if token in seen_tokens:raise ValueError('DevOps repeated continuation')
    seen_tokens.add(token)
   else:raise AzureReadError('page_limit')
   if not set(policy['project_ids'])<=set(visible):raise AzureReadError('devops_declared_project_not_visible')
   projects=[];repo_count=0
   for pid in policy['project_ids']:
    row=visible[pid];detail=read('/_apis/projects/'+pid)
    if detail.get('id','').lower()!=pid or row.get('state')!='wellFormed'or detail.get('state')!='wellFormed':raise ValueError('DevOps project LIST GET identity or state mismatch')
    project={'id':pid,'visibility':detail.get('visibility') if detail.get('visibility')==row.get('visibility') else None,'_provenance':{'native_devops_git_schema':2,'source_operations':OPERATIONS.copy(),'read_only':True,'api_version':'7.1','includeHidden':True,'includeAllUrls':True,'owner_scope':scope.lower(),'organization':org,'project_id':pid,'declared_project_ids':policy['project_ids'].copy(),'capture_id':capture},'repositories':[],'_coverage':{}}
    try:
     rows=read('/'+pid+'/_apis/git/repositories','&includeHidden=true&includeAllUrls=true')['items'];seen=set()
     for repo in rows:
      rid=repo.get('id');repo_count+=1
      if repo_count>min(MAX_REPOS,reader.budget.max_items or MAX_REPOS):raise AzureReadError('resource_limit')
      if not isinstance(rid,str)or not re.fullmatch(UUID,rid)or rid.lower()in seen or not isinstance(repo.get('projectId'),str)or repo['projectId'].lower()!=pid:raise ValueError('DevOps repository LIST identity mismatch')
      rid=rid.lower();seen.add(rid);detail=read('/'+pid+'/_apis/git/repositories/'+rid)
      if not isinstance(detail.get('id'),str)or detail['id'].lower()!=rid or not isinstance(detail.get('projectId'),str)or detail['projectId'].lower()!=pid:raise ValueError('DevOps repository GET identity mismatch')
      # GET may omit validRemoteUrls; the explicitly requested LIST remains
      # the authoritative all-URLs source. Compare complete projections when both exist.
      if detail['remote_assessment']!=repo['remote_assessment']or detail['url_assessments']['fields_complete']and detail['url_assessments']!=repo['url_assessments']:raise ValueError('DevOps repository URL assessment changed')
      project['repositories'].append({'id':rid,'projectId':pid,'url_assessments':repo['url_assessments']})
     project['_coverage']['repositories']={'status':'partial','reason':'repository_authorization_universe_unverified','api_pages_complete':True}
    except Exception as exc:
     # No raw provider error body/message is retained, even for URL parser failures.
     project['repositories']=[];project['_coverage']['repositories']={'status':'denied'if getattr(exc,'status_code',None)==403 else'not_collected','reason':'native_repository_metadata_unresolved'}
    projects.append(project)
   yield projects
  jobs.append((KIND,scope,'AzureDevOps',inventory))
 reader.run(jobs)
