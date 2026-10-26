"""Role-free hosted agent isolation; no live AWS/model calls."""
import base64
import http.client
from http.server import ThreadingHTTPServer
import io
import json
import tarfile
import threading
import pytest
from peaso.ai import fargate, isolation, model_relay, task_runtime
from tests.test_peaso_aws_iam_contract import field, policies, resource_blocks, values
from pathlib import Path


def definition():
    return {'taskDefinitionArn': 'arn:aws:ecs:us-east-1:111122223333:task-definition/cspm-ai:1',
        'networkMode': 'awsvpc', 'requiresCompatibilities': ['FARGATE'],
        'volumes': [{'name': n+'-scratch'} for n in ('agent','relay')],
        'containerDefinitions': [{'name': n, 'essential': True, 'user': '10001:10001',
            'readonlyRootFilesystem': True, 'image': 'registry/worker@sha256:'+'a'*64,
            'mountPoints': [{'sourceVolume': n+'-scratch', 'containerPath':'/tmp', 'readOnly':False}],
            'linuxParameters': {'capabilities': {'drop':['ALL']}},
            'entryPoint':['python','-m','peaso.ai.task_runtime'], 'command':[n]} for n in ('agent','relay')]}


def test_ai_ecs_roles_are_separate_and_minimal():
    source = (Path(__file__).resolve().parents[1] / 'infra/aws/ai_runtime.tf').read_text()
    task = resource_blocks(source, 'aws_ecs_task_definition')['ai']
    with pytest.raises(AssertionError, match='Missing HCL field task_role_arn'):
        field(task, 'task_role_arn')
    assert values(task, 'execution_role_arn') == ('aws_iam_role.ai_execution.arn',)
    assert values(task, 'depends_on') == ('aws_iam_role_policy.ai_execution',)
    assert 'PEASO_AI_FARGATE_CLUSTER         = aws_ecs_cluster.ai.arn' in source
    assert 'aws_ecs_cluster.cspm.arn' not in source
    assert 'aws_iam_role.execution.arn' not in source
    execution = policies(source)['ai_execution']
    assert {(action, resource) for row in execution for action in row.actions for resource in row.resources} == {
        ('ecr:GetAuthorizationToken', '*'),
        ('ecr:BatchGetImage', 'aws_ecr_repository.worker.arn'),
        ('ecr:GetDownloadUrlForLayer', 'aws_ecr_repository.worker.arn'),
        ('ecr:BatchCheckLayerAvailability', 'aws_ecr_repository.worker.arn'),
        ('logs:CreateLogStream', '${aws_cloudwatch_log_group.ai_tasks.arn}:*'),
        ('logs:PutLogEvents', '${aws_cloudwatch_log_group.ai_tasks.arn}:*'),
    }


@pytest.mark.parametrize('credential', [
    'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', 'AWS_CONTAINER_CREDENTIALS_FULL_URI',
    'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
    'AWS_PROFILE', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN',
])
def test_ai_task_rejects_ambient_aws_identity_before_bootstrap(monkeypatch, credential):
    for name in ('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', 'AWS_CONTAINER_CREDENTIALS_FULL_URI',
                 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                 'AWS_PROFILE', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(credential, 'unexpected')
    monkeypatch.setattr(task_runtime.sys, 'argv', ['task_runtime', 'relay'])
    monkeypatch.setattr(task_runtime, 'transfer', lambda *args, **kwargs: pytest.fail('bootstrap attempted'))
    with pytest.raises(SystemExit) as error:
        task_runtime.main()
    assert error.value.code == 1


def test_ai_task_allows_region_without_aws_identity(monkeypatch):
    for name in ('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', 'AWS_CONTAINER_CREDENTIALS_FULL_URI',
                 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                 'AWS_PROFILE', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')
    task_runtime.reject_ambient_aws_credentials()


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr('peaso.ai.providers.validate_before_launch', lambda access: access)
    values={'CLUSTER':'cluster','TASK_DEFINITION':definition()['taskDefinitionArn'],
        'SUBNETS':'subnet-12345678','SECURITY_GROUPS':'sg-12345678','BUCKET':'private-ai-bucket'}
    for key,value in values.items(): monkeypatch.setenv('PEASO_AI_FARGATE_'+key,value)
    monkeypatch.setenv('PEASO_AI_RUNTIME','fargate')


@pytest.mark.parametrize('mutation',[
    lambda d:d.update(taskRoleArn='platform'), lambda d:d.update(pidMode='task'),
    lambda d:d['volumes'].append({'name':'platform','host':{'sourcePath':'/'}}),
    lambda d:d['containerDefinitions'][0].update(environment=[{'name':'AWS_ACCESS_KEY_ID','value':'inert'}]),
    lambda d:d['containerDefinitions'][0].update(secrets=[{'name':'secret','valueFrom':'arn'}]),
    lambda d:d['containerDefinitions'][0].update(privileged=True),
    lambda d:d['containerDefinitions'][0].update(readonlyRootFilesystem=False),
    lambda d:d['containerDefinitions'][0].update(mountPoints=[{'sourceVolume':'relay-scratch','containerPath':'/tmp','readOnly':False}]),
    lambda d:d['containerDefinitions'][0].update(user='0'),
    lambda d:d['containerDefinitions'][0].update(image='registry/worker:latest'),
    lambda d:d['containerDefinitions'][0].update(essential=False)])
def test_unsafe_task_definitions_fail_closed(mutation):
    item=definition(); mutation(item)
    with pytest.raises(RuntimeError,match='unsafe_ai_task_definition'):fargate.validate_task(item)


def test_capability_requires_complete_configuration(configured,monkeypatch):
    assert isolation.available()
    monkeypatch.delenv('PEASO_AI_FARGATE_BUCKET')
    assert not isolation.available()


class Storage:
    def __init__(self):self.objects={};self.deleted=[]
    def put_object(self,**kw):
        assert kw['ServerSideEncryption']=='AES256'
        self.objects[kw['Key']]=kw['Body']
    def generate_presigned_url(self,operation,Params,ExpiresIn):
        assert 0<ExpiresIn<=3600
        return 'https://private-ai-bucket.s3.us-east-1.amazonaws.com/'+Params['Key']+'?signature=inert'
    def get_object(self,**kw):return {'Body':io.BytesIO(b'{"items":[]}')}
    def delete_objects(self,**kw):self.deleted.extend(x['Key'] for x in kw['Delete']['Objects'])


class Tasks:
    def __init__(self,stopped=True):self.stopped=stopped;self.requests=[];self.stops=[]
    def describe_task_definition(self,**kw):return {'taskDefinition':definition()}
    def run_task(self,**kw):
        self.requests.append(kw)
        return {'tasks':[{'taskArn':'arn:task/invocation'}]}
    def describe_tasks(self,**kw):return {'tasks':[{'lastStatus':'STOPPED' if self.stopped else 'RUNNING','containers':[{'name':'agent','exitCode':0}]}]}
    def stop_task(self,**kw):self.stops.append(kw)


@pytest.mark.parametrize('provider', [None, 'codex', 'openai', 'anthropic', 'anthropic_token', 'openrouter'])
def test_task_transport_never_exposes_real_model_token(configured,tmp_path,provider):
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    (tmp_path/'findings.json').write_text('{"items":[]}')
    tasks,storage=Tasks(),Storage()
    from peaso.ai.providers import ModelAccess
    access = ModelAccess(provider, 'selected-model', 'medium', 'real-private-token') if provider else 'real-private-token'
    assert fargate.invoke('hardening',tmp_path,access,30,ecs=tasks,s3=storage)=={'items':[]}
    relay=next(v for k,v in storage.objects.items() if k.endswith('relay.json'))
    assert json.loads(relay)['token']=='real-private-token'
    assert json.loads(relay)['ai_configuration'] == ({'provider': provider, 'model': 'selected-model', 'thinking': 'medium'} if provider else {})
    data=next(v for k,v in storage.objects.items() if k.endswith('input.tgz'))
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        assert set(archive.getnames())=={'credentials.json','findings.json'}
        assert all(b'real-private-token' not in archive.extractfile(n).read() for n in archive.getnames())
    request=tasks.requests[0]
    assert 'taskRoleArn' not in request['overrides'] and request['enableExecuteCommand'] is False
    assert len(request['overrides']['containerOverrides'])==1
    assert request['overrides']['containerOverrides'][0]['name']=='relay'
    assert 'real-private-token' not in json.dumps(request)
    assert tasks.stops and len(storage.deleted)==3


def test_timeout_stops_task_and_deletes_transport(configured,tmp_path):
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    tasks,storage,now=Tasks(False),Storage(),[0]
    def sleep(seconds):now[0]+=seconds
    with pytest.raises(TimeoutError):
        fargate.invoke('network',tmp_path,'private',3,ecs=tasks,s3=storage,clock=lambda:now[0],sleep=sleep)
    assert tasks.stops and len(storage.deleted)==3


def test_unsafe_definition_prevents_staging_or_launch(configured,tmp_path):
    tasks,storage=Tasks(),Storage();bad=definition();bad['taskRoleArn']='platform'
    tasks.describe_task_definition=lambda **kw:{'taskDefinition':bad}
    with pytest.raises(RuntimeError):fargate.invoke('network',tmp_path,'private',30,ecs=tasks,s3=storage)
    assert not tasks.requests and not storage.objects


@pytest.mark.parametrize('name,symlink',[('codex-auth.json',False),('credentials.json',True)])
def test_model_auth_or_symlinks_cannot_enter_bundle(tmp_path,name,symlink):
    if symlink:(tmp_path/name).symlink_to('/etc/passwd')
    else:(tmp_path/name).write_text('private')
    with pytest.raises(ValueError):fargate.pack_workspace(tmp_path)


@pytest.mark.parametrize('name,kind',[('../escape','file'),('/escape','file'),('codex-auth.json','file'),('result.json','file'),('file','symlink')])
def test_archive_cannot_escape_or_inject_model_auth(tmp_path,name,kind):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz') as archive:
        member=tarfile.TarInfo(name)
        if kind=='symlink':member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd'
        archive.addfile(member)
    with pytest.raises(ValueError):task_runtime.unpack(output.getvalue(),tmp_path)


def test_pipeline_remote_branch_never_creates_model_auth_file(configured,monkeypatch):
    from peaso.ai import pipeline
    def invoke(stage,root,token,timeout):
        assert stage=='hardening' and token=='private-token'
        assert not (root/'codex-auth.json').exists()
        assert json.loads((root/'credentials.json').read_text())['entries']==[]
        assert (root/'findings.json').is_file()
        return {'items':[]}
    monkeypatch.setattr(fargate,'invoke',invoke)
    monkeypatch.setattr(pipeline.subprocess,'Popen',lambda *a,**kw:pytest.fail('local agent launched'))
    assert pipeline.invoke('hardening',{},[],'private-token',[],[],10)=={'items':[]}


def test_private_relay_has_no_auth_or_general_proxy_endpoint(monkeypatch):
    claims={'https://api.openai.com/auth':{'chatgpt_account_id':'account'}}
    token='e30.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.private-signature'
    captured,upstream,ready=[],[],threading.Event()
    def factory(address,handler):
        server=ThreadingHTTPServer(('127.0.0.1',0),handler)
        captured.append(server);ready.set();return server
    class Response:
        status_code=200
        headers={'Content-Type':'text/event-stream','Set-Cookie':token}
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def iter_content(self,*args,**kw):yield b'data: {"ok":true}\n\n'
    class Session:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def request(self,method,url,**kw):upstream.append((method,url,kw));return Response()
        def get(self,url,**kw):upstream.append(('GET',url,kw));return Response()
    monkeypatch.setattr('requests.Session',Session)
    config={'token':token,'stage':'hardening','timeout':10,'input_url':'https://private-ai-bucket.s3.us-east-1.amazonaws.com/input?sig=inert','output_url':'https://private-ai-bucket.s3.us-east-1.amazonaws.com/output?sig=inert'}
    thread=threading.Thread(target=lambda:model_relay.serve(config,server_class=factory),daemon=True)
    thread.start();assert ready.wait(3)
    server=captured[0]
    def call(method,path,body=None,auth=None):
        connection=http.client.HTTPConnection(*server.server_address,timeout=3)
        connection.request(method,path,body=body,headers={'Authorization':'Bearer '+auth} if auth else {})
        response=connection.getresponse();status=response.status;headers=dict(response.getheaders());data=response.read()
        connection.close();return status,headers,data
    try:
        status,_,data=call('GET','/bootstrap')
        assert status==200 and token.encode() not in data
        capability=json.loads(data)['relay_token']
        assert 'input_url' not in json.loads(data) and 'output_url' not in json.loads(data)
        assert call('POST','/codex/responses','{}')[0]==403
        assert call('GET','/api/accounts',auth=capability)[0]==403
        status,headers,body=call('POST','/codex/responses','{}',capability)
        assert status==200 and token.encode() not in body and 'Set-Cookie' not in headers
        assert upstream[0][1]=='https://chatgpt.com/backend-api/codex/responses'
        assert upstream[0][2]['headers']['Authorization']=='Bearer '+token
        assert upstream[0][2]['allow_redirects'] is False
        assert call('GET','/input',auth=capability)[2]==b'data: {"ok":true}\n\n'
        assert call('POST','/result','{"items":[]}',capability)[0]==200
        assert any(method=='PUT' and url==config['output_url'] for method,url,kw in upstream)
        Response.status_code=401
        status,headers,body=call('POST','/codex/responses','{}',capability)
        assert status==502 and token.encode() not in body
    finally:server.shutdown();thread.join(timeout=3)


@pytest.mark.parametrize('provider', [None, 'codex', 'openai'])
def test_pinned_codex_cli_and_chack_use_only_private_relay(tmp_path,monkeypatch,provider):
    """Opt-in actual pinned CLI/Chack, with a local fake SSE model, no paid call."""
    import os,subprocess,sys
    from pathlib import Path
    binary=os.getenv('PEASO_TEST_CODEX_BIN')
    if not binary:pytest.skip('set PEASO_TEST_CODEX_BIN to the pinned Codex 0.147.0 executable')
    from http.server import BaseHTTPRequestHandler
    routes=[]
    requests=[]
    prefix = '/openai/v1' if provider == 'openai' else '/codex'
    item={'id':'msg_fixture','type':'message','role':'assistant','content':[{'type':'output_text','text':'{"items":[]}'}]}
    events=[{'type':'response.created','response':{'id':'resp_fixture'}},
        {'type':'response.output_item.done','output_index':0,'item':item},
        {'type':'response.completed','response':{'id':'resp_fixture','output':[item],
         'usage':{'input_tokens':10,'output_tokens':5,'total_tokens':15}}}]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            if self.path == '/validate':
                raw=b'{"valid":true}';self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);return
            routes.append(('GET',self.path))
            raw=b'{"models":[]}' if self.path.startswith(prefix+'/models') else b'{}'
            self.send_response(200 if self.path.startswith(prefix+'/models') else 403)
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_POST(self):
            body=self.rfile.read(int(self.headers.get('Content-Length','0')));routes.append(('POST',self.path))
            if self.path == prefix+'/responses': requests.append(json.loads(body))
            raw=''.join('data: '+json.dumps(e)+'\n\n' for e in events).encode() if self.path==prefix+'/responses' else b'{}'
            self.send_response(200 if self.path==prefix+'/responses' else 403)
            self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(raw)))
            self.end_headers();self.wfile.write(raw)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    bindir=tmp_path/'bin';bindir.mkdir();(bindir/'codex').symlink_to(Path(binary).resolve())
    root=tmp_path/'work';root.mkdir()
    (root/'credentials.json').write_text('{"entries":[]}')
    (root/'findings.json').write_text('{"scan":{},"items":[]}')
    authentication = {'access_token': model_relay.placeholder('account')}
    if provider:
        authentication.update(provider=provider, model='gpt-5.3-codex', thinking='high')
    (root/'codex-auth.json').write_text(json.dumps(authentication))
    env={'PATH':str(bindir)+os.pathsep+os.environ['PATH'],'HOME':str(root),'TMPDIR':str(root),
         'PYTHONPATH':str(Path(__file__).resolve().parents[1]),'CODEX_HOME':str(root/'.codex'),
         'PEASO_AI_MODEL_RELAY':'http://127.0.0.1:'+str(server.server_port),'CHACK_CODEX_DIRECT_CACHE_TRANSPORT':'off'}
    try:
        process=subprocess.run([sys.executable,'-m','peaso.ai.runner','hardening'],cwd=root,env=env,
                               capture_output=True,text=True,timeout=60)
        assert process.returncode==0,process.stderr[-2000:]
        assert json.loads((root/'result.json').read_text())=={'items':[]}
        assert ('POST',prefix+'/responses') in routes
        if provider:
            assert requests[-1]['model'] == 'gpt-5.3-codex'
            assert requests[-1]['reasoning']['effort'] == 'high'
    finally:server.shutdown();thread.join(timeout=3)


@pytest.mark.parametrize('kind',['symlink','fifo','oversized'])
def test_result_uploader_rejects_untrusted_file_types(tmp_path,kind):
    import os
    result=tmp_path/'result.json'
    if kind=='symlink':result.symlink_to('/etc/passwd')
    elif kind=='fifo':os.mkfifo(result)
    else:
        with result.open('wb') as stream:stream.truncate(fargate.MAX_OUTPUT+1)
    with pytest.raises((OSError,ValueError)):task_runtime.read_result(tmp_path)


def test_ecs_empty_host_scratch_is_safe():
    item=definition()
    for volume in item['volumes']:volume['host']={}
    fargate.validate_task(item)


def test_shared_platform_identity_capture_can_be_disabled():
    from peaso.ai import access
    access.begin(allow_live=False)
    access.bearer('gcp','https://www.googleapis.com/','shared-platform-token',target_scopes=['projects/customer'])
    assert access.enabled() is False and access.finish()==[]
    access.begin()
    access.bearer('gcp','https://www.googleapis.com/','customer-token',target_scopes=['projects/customer'])
    assert access.finish()[0]['token']=='customer-token'


def test_old_gcp_and_aws_access_are_not_exported():
    from peaso.ai import access
    old = [{'provider': 'gcp', 'token': 'legacy'}, {'provider': 'k8s', 'token': 'derived'}]
    snapshot = {'provider': 'gcp'}
    assert access.eligible_entries(old, snapshot) == []
    access.begin()
    access.bearer('gcp', 'https://www.googleapis.com/', 'customer-token')
    current = access.finish()
    assert access.eligible_entries(current, snapshot) == current
    assert access.eligible_entries(current + [{'provider': 'aws', 'format': 'aws-session'}], snapshot) == current
    aws = [{'provider': 'aws', 'format': 'aws-session', 'aws_access_key_id': 'legacy'},
           {'provider': 'k8s', 'token': 'independent'}]
    assert access.eligible_entries(aws, {'provider': 'aws'}) == aws[1:]
    access.begin(allow_live=False)
    assert access.enabled() is False and access.finish() == []


def test_aws_and_shared_gcp_credentials_are_not_captured_for_agents():
    from peaso.ai import access
    assert not access.may_capture_live({'provider': 'aws', 'auth': {'method': 'assume_role'}})
    assert not access.may_capture_live({'provider': 'aws', 'auth': {'method': 'access_keys'}})
    assert not access.may_capture_live({'provider': 'gcp', 'auth': {'method': 'platform-service-account'}})
    assert access.may_capture_live({'provider': 'gcp', 'auth': {'method': 'service-account'}})
    assert access.may_capture_live({'provider': 'azure', 'auth': {}})


def test_agent_launch_rejects_aws_sessions_even_if_a_caller_passes_them(tmp_path):
    from peaso.ai import pipeline
    aws_entry = {'provider': 'aws', 'format': 'aws-session', 'aws_access_key_id': 'inert'}
    with pytest.raises(ValueError, match='aws_live_ai_access_disabled'):
        pipeline.invoke('hardening', {}, [aws_entry], 'inert', [], [], 30)
    (tmp_path / 'credentials.json').write_text(json.dumps({'entries': [aws_entry]}))
    with pytest.raises(ValueError, match='aws_live_ai_access_disabled'):
        fargate.pack_workspace(tmp_path)


def test_infrastructure_startup_failure_is_retryable_and_still_cleans_transport(configured, tmp_path):
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    tasks, storage = Tasks(), Storage()
    tasks.describe_tasks = lambda **kw: {'tasks': [{'lastStatus': 'STOPPED', 'stopCode': 'TaskFailedToStart',
        'containers': [{'name': 'agent'}]}]}
    with pytest.raises(fargate.TaskStartupError, match='ai_task_startup_failed'):
        fargate.invoke('network', tmp_path, 'private', 30, ecs=tasks, s3=storage)
    assert tasks.stops and len(storage.deleted) == 3


def test_started_agent_failure_is_not_classified_as_an_infrastructure_retry(configured, tmp_path):
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    tasks, storage = Tasks(), Storage()
    tasks.describe_tasks = lambda **kw: {'tasks': [{'lastStatus': 'STOPPED', 'stopCode': 'EssentialContainerExited',
        'containers': [{'name': 'agent', 'exitCode': 1}]}]}
    with pytest.raises(RuntimeError, match='agent_failed') as failed:
        fargate.invoke('network', tmp_path, 'private', 30, ecs=tasks, s3=storage)
    assert not isinstance(failed.value, fargate.TaskStartupError)
    assert tasks.stops and len(storage.deleted) == 3


def test_runtime_credential_validation_failure_is_not_retried(configured, tmp_path, monkeypatch):
    from peaso.ai import providers
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    tasks, storage = Tasks(), Storage()
    tasks.describe_tasks = lambda **kw: {'tasks': [{'lastStatus': 'STOPPED',
        'containers': [{'name': 'agent', 'exitCode': 78}]}]}
    storage.get_object = lambda **kw: pytest.fail('Preflight failure has no agent result')
    reported = []
    def report(access):
        reported.append(access)
        return providers.ConfigurationError('AI configuration needs validation.')
    monkeypatch.setattr(providers, 'launch_error', report)
    with pytest.raises(providers.ConfigurationError):
        fargate.invoke('network', tmp_path, 'private', 30, ecs=tasks, s3=storage)
    assert reported == ['private'] and len(tasks.requests) == 1
    assert tasks.stops and len(storage.deleted) == 3


def test_completed_agent_result_does_not_wait_for_task_deprovisioning(configured, tmp_path):
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    tasks, storage = Tasks(), Storage()
    tasks.describe_tasks = lambda **kw: {'tasks': [{'lastStatus': 'DEPROVISIONING',
        'containers': [{'name': 'agent', 'lastStatus': 'STOPPED', 'exitCode': 0},
                       {'name': 'relay', 'lastStatus': 'RUNNING'}]}]}
    assert fargate.invoke('network', tmp_path, 'private', 3, ecs=tasks, s3=storage,
        sleep=lambda _: pytest.fail('A completed agent result must be collected immediately')) == {'items': []}
    assert tasks.stops and len(storage.deleted) == 3


def test_failed_agent_result_is_never_accepted_during_deprovisioning(configured, tmp_path):
    (tmp_path/'credentials.json').write_text('{"entries":[]}')
    tasks, storage = Tasks(), Storage()
    tasks.describe_tasks = lambda **kw: {'tasks': [{'lastStatus': 'DEPROVISIONING',
        'containers': [{'name': 'agent', 'lastStatus': 'STOPPED', 'exitCode': 1}]}]}
    storage.get_object = lambda **kw: pytest.fail('Failed agent output must not be accepted')
    with pytest.raises(RuntimeError, match='agent_failed'):
        fargate.invoke('network', tmp_path, 'private', 3, ecs=tasks, s3=storage)
    assert tasks.stops and len(storage.deleted) == 3


@pytest.mark.parametrize('names', [(), ('agent',), ('relay',), ('agent', 'relay')])
def test_only_exact_trusted_build_constant_is_allowed(names):
    item = definition()
    for container in item['containerDefinitions']:
        if container['name'] in names:
            container['environment'] = [{'name': 'PEASO_SOURCE_ATTESTATION', 'value': 'trusted'}]
    fargate.validate_task(item)


@pytest.mark.parametrize('environment', [
    [{'name': 'PEASO_SOURCE_ATTESTATION', 'value': 'once'}],
    [{'name': 'PEASO_SOURCE_ATTESTATION', 'value': 'trusted', 'extra': 'inert'}],
    [{'name': 'PEASO_SOURCE_ATTESTATION', 'value': 'trusted'}] * 2,
    [{'name': 'PEASO_SOURCE_ATTESTATION', 'value': 'trusted'}, {'name': 'AWS_PROFILE', 'value': 'inert'}],
    [{'name': 'PEASO_SOURCE_ATTESTATION', 'value': 'trusted'}, {'name': 'PATH', 'value': '/tmp'}],
    {'PEASO_SOURCE_ATTESTATION': 'trusted'},
])
def test_trusted_build_constant_does_not_admit_other_environment(environment):
    item = definition()
    item['containerDefinitions'][0]['environment'] = environment
    with pytest.raises(RuntimeError, match='unsafe_ai_task_definition'):
        fargate.validate_task(item)
