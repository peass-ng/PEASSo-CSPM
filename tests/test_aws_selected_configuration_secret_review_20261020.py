"""Fifteen independent native SDK responses -> selected reader -> public engine."""
from copy import deepcopy
from contextlib import ExitStack
from datetime import datetime,timezone
from concurrent.futures import Future
import base64,gzip,hashlib,inspect,json,socket
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit,quote
import boto3
from botocore.stub import Stubber
import pytest
from peaso import engine,checks,secret_scanning as scanning
from peaso.collectors import aws,aws_selected_configuration_secret_indicators as source
from peaso.checks import aws_selected_configuration_secret_review_20261020 as consumer

ACCOUNT='123456789012';REGION='us-east-1';SCOPE=ACCOUNT+'/'+REGION
TOKEN='ghp_'+'7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
OTHER='ghp_'+'8nR3aS0xM5dW9pL2tG7bJ4kQ6vE1yC3zF0sU'
CALLER={'Account':ACCOUNT,'Arn':'arn:aws:iam::'+ACCOUNT+':user/reviewer','UserId':'AIDAREVIEWER'}
NOW=datetime(2026,10,20,tzinfo=timezone.utc)
SCRATCH=Path('/tmp/peasso-secret-surface-review-20261020/aws-selected-configuration')
SURFACES=list(source.SURFACES)
LEGACY_SURFACES=[surface for surface in SURFACES if surface not in ('cloudformation_template','codepipeline_configuration')]

def arn(service,resource):return f'arn:aws:{service}:{REGION}:{ACCOUNT}:{resource}'
def encoded(text):return base64.b64encode(text.encode()).decode()
def metadata():return {'HTTPStatusCode':200,'RequestId':'11111111-1111-4111-8111-111111111111','HTTPHeaders':{'echo':TOKEN}}


def native(surface,positive=False,*,name='AuditResource'):
    text='TOKEN='+TOKEN if positive else 'MODE=production'
    value=TOKEN if positive else 'production'
    target={'surface':surface,'scope':SCOPE}
    if surface=='cloudformation_template':
        target['resource_id']=arn('cloudformation','stack/'+name+'/11111111-1111-4111-8111-111111111111')
        responses=[{'TemplateBody':json.dumps({'AWSTemplateFormatVersion':'2010-09-09',
            'Resources':{'Review':{'Type':'AWS::CloudFormation::WaitConditionHandle'}},
            'Outputs':{'ReviewValue':{'Value':value}}}),'StagesAvailable':['Original']}]
    elif surface=='codepipeline_configuration':
        target.update(resource_id=arn('codepipeline',name),version=3)
        responses=[{'pipeline':{'name':name,'roleArn':'arn:aws:iam::'+ACCOUNT+':role/pipeline-reader',
            'artifactStore':{'type':'S3','location':'offline-artifacts'},'version':3,
            'stages':[{'name':'Build','actions':[{'name':'Review','actionTypeId':{
                'category':'Build','owner':'AWS','provider':'CodeBuild','version':'1'},
                'configuration':{'ProjectName':name,'EnvironmentVariables':json.dumps([
                    {'name':'TOKEN' if positive else 'MODE','value':value,'type':'PLAINTEXT'}])}}]}]},
            'metadata':{'pipelineArn':target['resource_id'],'created':NOW,'updated':NOW}}]
    elif surface=='cloudformation_outputs':
        target['resource_id']=arn('cloudformation','stack/'+name+'/11111111-1111-4111-8111-111111111111')
        responses=[{'Stacks':[{'StackId':target['resource_id'],'StackName':name,'StackStatus':'CREATE_COMPLETE','CreationTime':NOW,'Description':TOKEN,
                   'Outputs':[{'OutputKey':'TOKEN' if positive else 'MODE','OutputValue':value,'Description':TOKEN}]}]}]
    elif surface=='codebuild_environment':
        target['resource_id']=arn('codebuild','project/'+name)
        responses=[{'projects':[{'name':name,'arn':target['resource_id'],'description':TOKEN,
          'source':{'type':'NO_SOURCE'},'artifacts':{'type':'NO_ARTIFACTS'},
          'environment':{'type':'LINUX_CONTAINER','image':'aws/codebuild/standard:7.0','computeType':'BUILD_GENERAL1_SMALL',
                         'environmentVariables':[{'name':'TOKEN' if positive else 'MODE','value':value,'type':'PLAINTEXT'}]}}]}]
    elif surface=='rest_stage_variables':
        target['resource_id']=f'arn:aws:apigateway:{REGION}::/restapis/a1b2c3/stages/'+name
        responses=[{'stageName':name,'description':TOKEN,'variables':{'TOKEN' if positive else 'MODE':value}}]
    elif surface=='ecs_environment':
        target['resource_id']=arn('ecs','task-definition/'+name+':3')
        responses=[{'taskDefinition':{'taskDefinitionArn':target['resource_id'],'family':name,'revision':3,'status':'ACTIVE',
           'containerDefinitions':[{'name':'app','image':'public.ecr.aws/example/app:latest','environment':[{'name':'TOKEN' if positive else 'MODE','value':value}]}]}}]
    elif surface=='amplify_environment':
        target['resource_id']=arn('amplify','apps/d1abc123')
        responses=[{'app':{'appId':'d1abc123','appArn':target['resource_id'],'name':name,'description':TOKEN,'repository':'',
          'platform':'WEB','createTime':NOW,'updateTime':NOW,'environmentVariables':{'TOKEN' if positive else 'MODE':value},
          'defaultDomain':'d1abc123.amplifyapp.com','enableBranchAutoBuild':False,'enableBasicAuth':False}}]
    elif surface=='batch_environment':
        target['resource_id']=arn('batch','job-definition/'+name+':3')
        responses=[{'jobDefinitions':[{'jobDefinitionArn':target['resource_id'],'jobDefinitionName':name,'revision':3,'status':'ACTIVE','type':'container',
          'containerProperties':{'image':'public.ecr.aws/example/app:latest','environment':[{'name':'TOKEN' if positive else 'MODE','value':value}]}}]}]
    elif surface=='beanstalk_options':
        target['resource_id']=arn('elasticbeanstalk','environment/'+name+'/AuditEnvironment')
        responses=[{'ConfigurationSettings':[{'ApplicationName':name,'EnvironmentName':'AuditEnvironment','DeploymentStatus':'deployed',
          'Description':TOKEN,'OptionSettings':[{'Namespace':'aws:elasticbeanstalk:application:environment','OptionName':'TOKEN' if positive else 'MODE','Value':value}]}]}]
    elif surface=='glue_job_arguments':
        target['resource_id']=arn('glue','job/'+name)
        responses=[{'Job':{'Name':name,'Description':TOKEN,'DefaultArguments':{'--TOKEN' if positive else '--MODE':value},'NonOverridableArguments':{}}}]
    elif surface=='glue_connection_properties':
        target['resource_id']=arn('glue','connection/'+name)
        responses=[{'Connection':{'Name':name,'Description':TOKEN,'ConnectionType':'KAFKA',
          'ConnectionProperties':{'KAFKA_BOOTSTRAP_SERVERS':'broker.internal:9092','KAFKA_SSL_ENABLED':'true','USERNAME':value}}}]
    elif surface=='launch_template_userdata':
        target.update(resource_id=arn('ec2','launch-template/lt-0123456789abcdef0'),version=3)
        responses=[{'LaunchTemplateVersions':[{'LaunchTemplateId':'lt-0123456789abcdef0','VersionNumber':3,'DefaultVersion':False,
             'VersionDescription':TOKEN,'LaunchTemplateData':{'UserData':encoded(text)}}]}]
    elif surface=='launch_configuration_userdata':
        target['resource_id']=arn('autoscaling','launchConfiguration:11111111-1111-4111-8111-111111111111:launchConfigurationName/'+name)
        responses=[{'LaunchConfigurations':[{'LaunchConfigurationName':name,'LaunchConfigurationARN':target['resource_id'],
          'ImageId':'ami-0123456789abcdef0','InstanceType':'t3.micro','CreatedTime':NOW,'UserData':encoded(text)}]}]
    elif surface=='ssm_document':
        target.update(resource_id=arn('ssm','document/'+name),version=3)
        responses=[{'Document':{'Name':name,'DocumentVersion':'3','Owner':ACCOUNT,'Status':'Active','DocumentType':'Command','DocumentFormat':'JSON'}},
                   {'Name':name,'DocumentVersion':'3','Status':'Active','DocumentFormat':'JSON','DocumentType':'Command',
                    'Content':json.dumps({'schemaVersion':'2.2','mainSteps':[{'action':'aws:runShellScript','name':'test','inputs':{'runCommand':[text]}}]})}]
    elif surface=='state_machine_definition':
        target['resource_id']=arn('states','stateMachine:'+name)
        responses=[{'stateMachineArn':target['resource_id'],'name':name,'status':'ACTIVE','type':'STANDARD',
          'roleArn':arn('iam','role/unused'),'creationDate':NOW,
          'definition':json.dumps({'StartAt':'Review','States':{'Review':{'Type':'Pass','End':True,'Result':{'TOKEN' if positive else 'MODE':value}}}})}]
    elif surface=='notebook_lifecycle':
        target['resource_id']=arn('sagemaker','notebook-instance-lifecycle-config/'+name)
        responses=[{'NotebookInstanceLifecycleConfigName':name,'NotebookInstanceLifecycleConfigArn':target['resource_id'],
            'CreationTime':NOW,'LastModifiedTime':NOW,'OnCreate':[{'Content':encoded(text)}],'OnStart':[]}]
    else:
        target['resource_id']=arn('datapipeline','pipeline/df-0123456789ABC')
        responses=[{'pipelineObjects':[{'id':'ReviewTask','name':'ReviewTask','fields':[{'key':'type','stringValue':'ShellCommandActivity'},{'key':'command','stringValue':text}]}],
          'parameterObjects':[],'parameterValues':[]}]
    for response in responses:response['ResponseMetadata']=metadata()
    return target,responses


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    attempts=[]
    def blocked(*a,**kw):attempts.append('network/auth');raise AssertionError('No live IO or default credentials')
    for name in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo'):monkeypatch.setattr(socket,name,blocked)
    for name in ('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,name,blocked)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED','true')
    monkeypatch.setenv('AWS_CONFIG_FILE','/nonexistent/selected-config-review')
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE','/nonexistent/selected-config-review')
    monkeypatch.setattr(aws,'_session',blocked)
    original=list(checks.CHECKS)
    if not any(c.id==source.CHECK for c in checks.CHECKS):consumer.install(checks.register)
    scanning._RESULTS.clear()
    yield
    checks.CHECKS[:]=original;scanning._RESULTS.clear()
    assert not attempts


def request(targets,**options):
    return {'connector':{'provider':'aws','scopes':[SCOPE],
      'auth':{'method':'access_keys','aws_access_key_id':'offline-key','aws_secret_access_key':'offline-secret'},
      'options':{'content_secret_scans':True,source.OPTION:targets,'retry_attempts':1,**options}},'checks':[source.CHECK]}


def capture(monkeypatch,targets,responses,*,real=False,error=False,one_engine=None,opts=None,caller=None,req=None,seed_metadata=False,untrusted_endpoint=False):
    trace=SimpleNamespace(readers=[],calls=[],scans=[],clients={},progress=[])
    session=boto3.Session(aws_access_key_id='offline-key',aws_secret_access_key='offline-secret',region_name=REGION)
    services={'sts'}|{source.SURFACES[t['surface']][0] for t in targets}
    clients={s:session.client(s,region_name=REGION) for s in services};trace.clients=clients;trace.session=session
    if untrusted_endpoint:
        for service,sdk in clients.items():
            if service!='sts':sdk.meta._endpoint_url='https://untrusted.invalid/'
    original_init=aws.Requests.__init__
    def init(self,*a,**kw):original_init(self,*a,**kw);trace.readers.append(self)
    monkeypatch.setattr(aws.Requests,'__init__',init)
    def client(self,selected,service,region,**kw):
        assert selected is session and region==REGION and service in clients
        if kw:assert kw=={'_metadata_profile':source.PROFILE}
        return clients[service]
    monkeypatch.setattr(aws.Requests,'client',client)
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'offline-pinned'))
    if not real:
        def detector(payload,path,timeout):
            trace.scans.append((bytes(payload),path,timeout))
            return [(v,'github-pat',1) for v in (TOKEN,OTHER) if v.encode() in payload]
        monkeypatch.setattr(scanning,'_scan_kingfisher',detector);monkeypatch.setattr(scanning,'_scan_trufflehog',detector)
    if one_engine:
        def unavailable(*a,**kw):raise RuntimeError(TOKEN)
        monkeypatch.setattr(scanning,'_scan_'+one_engine,unavailable)
    req=deepcopy(req or request(targets,**(opts or {})));req['connector']['options']['_progress_callback']=trace.progress.append
    enabled=req['connector']['options'].get('content_secret_scans') is True and source.CHECK in req.get('checks',[]) and source.MAX_SECONDS>0
    expected=[]
    if enabled and (caller or CALLER)['Account']==ACCOUNT:
        for target in targets:
            phases=(True,False) if target['surface']=='ssm_document' else (False,)
            for phase,payload in zip(phases,responses[source.identity(target)]):
                service,operation,args=source.route(target,ownership=phase)
                if phase is False and target['surface']=='ssm_document' and responses[source.identity(target)][0]['Document'].get('Owner')!=ACCOUNT:break
                expected.append((service,operation,args,payload,phase))
                if error:break
    maximum=req['connector']['options'].get('max_calls')
    if type(maximum) is int:expected=expected[:max(0,maximum-1)]
    if untrusted_endpoint:expected=[]
    if seed_metadata:
        assert len(targets)==1 and targets[0]['surface']=='codebuild_environment'
        original_selected=source.collect_selected
        def selected(reader,selected_session,region,identity,options,scopes):
            service,operation,args=source.route(targets[0])
            reader.call(selected_session,service,region,operation,**args)
            trace.earlier_futures=[f for k,f in reader._cache.items() if k[1]=='codebuild' and len(k)==5]
            assert len(trace.earlier_futures)==1 and TOKEN in json.dumps(trace.earlier_futures[0].result(),default=str)
            return original_selected(reader,selected_session,region,identity,options,scopes)
        monkeypatch.setattr(source,'collect_selected',selected)
    for service,sdk in clients.items():
        def before(params,model,context,_service=service,_sdk=sdk,**kw):
            serialized=_sdk._convert_to_request_dict(params,model,endpoint_url=_sdk.meta.endpoint_url)
            parsed=urlsplit(serialized['url']);assert parsed.scheme=='https'
            assert parsed.hostname==({'stepfunctions':'states','sagemaker':'api.sagemaker'}.get(_service,_service))+'.'+REGION+'.amazonaws.com'
            if _service=='sts':assert model.name=='GetCallerIdentity' and params=={}
            else:
                matches=[(s,o,a) for s,o,a,_,_ in expected if s==_service and ''.join(x.capitalize() for x in o.split('_'))==model.name and a==params]
                assert matches,(_service,model.name,params)
                assert serialized['method']==('GET' if _service in ('apigateway','amplify') else 'POST')
                if _service=='apigateway':assert parsed.path=='/restapis/'+params['restApiId']+'/stages/'+params['stageName']
                elif _service=='amplify':assert parsed.path=='/apps/'+params['appId']
                elif _service=='batch':assert parsed.path=='/v1/describejobdefinitions'
                else:assert parsed.path=='/'
                trace.calls.append((_service,model.name,deepcopy(params),serialized['method'],parsed.hostname,parsed.path))
        sdk.meta.events.register('before-parameter-build.'+sdk.meta.service_model.service_id.hyphenize()+'.*',before)
    def run():
        with ExitStack() as stack:
            stubs={s:stack.enter_context(Stubber(sdk)) for s,sdk in clients.items()}
            # Each Stubber receipt is an independent provider object. The
            # withholding path intentionally scrubs cached mutable responses.
            stubs['sts'].add_response('get_caller_identity',deepcopy(caller or CALLER),{})
            if seed_metadata:
                service,operation,args,payload,_=expected[0]
                stubs[service].add_response(operation,payload,args)
            for service,operation,args,payload,phase in expected:
                if error:stubs[service].add_client_error(operation,service_error_code='AccessDeniedException',service_message=TOKEN,http_status_code=403,expected_params=args)
                else:stubs[service].add_response(operation,payload,args)
            snapshot=engine.collect_snapshot(req)
            for stub in stubs.values():stub.assert_no_pending_responses()
        return snapshot
    trace.run=run
    return run(),trace


def one(monkeypatch,surface,positive=False,**kw):
    target,responses=native(surface,positive)
    return capture(monkeypatch,[target],{source.identity(target):responses},**kw)


def findings(snapshot):return engine.evaluate_snapshot(snapshot,checks=[source.CHECK])['findings']


def test_capture_native_admission_fixtures_with_real_engines(monkeypatch):
    """Durable successor inputs originate in real SDK reads, never historical CASES."""
    fixtures={}
    for case in ('pass','fail','unknown'):
        with monkeypatch.context() as local:
            snapshot,_=one(local,'codebuild_environment',case=='fail',real=True,error=case=='unknown')
            assert {r['status'] for r in findings(snapshot)}=={case.upper() if case!='unknown' else 'UNKNOWN'}
            collection=next(c for c in snapshot['collections'] if c['type']==source.KIND)
            item=deepcopy(collection['items'][0]) if collection['items'] else {'id':'unreadable-selected-content'}
            # Losslessly retain only this predicate's dependencies; omit the
            # hundreds of unrelated not-selected inventory envelopes.
            native_metadata={k:deepcopy(v) for k,v in snapshot['metadata'].items()
                             if k.startswith(source.KIND+'_') or k=='caller_identities'}
            index={'collections':{},'context':{'provider':'aws','scope':SCOPE,'metadata':native_metadata}}
            for c in snapshot['collections']:
                if c['type'] in (source.KIND,'aws_account'):
                    index['collections'].setdefault(c['type'],[]).append(deepcopy(c))
            assert consumer.evaluate(item,index)[0]==case.upper()
            fixtures[case]=item;fixtures[case+'_index']=index
    fixtures['index']=deepcopy(fixtures['pass_index']);fixtures['missing']={};fixtures['malformed']={'id':42}
    serialized=json.dumps({source.CHECK:fixtures},indent=2,sort_keys=True)+'\n'
    assert TOKEN not in serialized and OTHER not in serialized
    SCRATCH.mkdir(parents=True,exist_ok=True)
    (SCRATCH/'native-derived-fixtures.json').write_text(serialized)


def retained(reader):
    result=[]
    for future in reader._cache.values():
        if future.exception() is None:result.append(future.result())
        else:
            failure=future.exception();assert failure.__traceback__ is None
            result.append((failure.status,failure.code,failure.args))
    return json.dumps([list(reader._cache),result,reader.configuration_content_metadata,
       list(reader.configuration_content_approved.items()),reader.configuration_content_owned,reader.configuration_content_redactions],default=str)


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('positive',[False,True])
def test_native_surface_good_bad_both_engines_and_redaction(monkeypatch,surface,positive):
    snapshot,trace=one(monkeypatch,surface,positive)
    rows=findings(snapshot)
    assert len(rows)==1 and rows[0]['status']==('FAIL' if positive else 'PASS'),rows
    assert len(trace.scans)==2
    assert TOKEN not in json.dumps([snapshot,rows,trace.progress])+retained(trace.readers[0])
    assert all(path.startswith(source.KIND+':') and path.endswith('.content') for _,path,_ in trace.scans)


@pytest.mark.parametrize('surface',SURFACES)
def test_native_denied_is_unresolved_without_any_scan(monkeypatch,surface):
    snapshot,trace=one(monkeypatch,surface,error=True)
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert not trace.scans and TOKEN not in json.dumps(snapshot)+retained(trace.readers[0])


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('positive',[False,True])
def test_true_both_pinned_offline_detectors_for_each_native_surface(monkeypatch,surface,positive):
    calls=[];original=scanning._run
    def run(argv,payload,timeout):calls.append(list(argv));return original(argv,payload,timeout)
    monkeypatch.setattr(scanning,'_run',run)
    snapshot,trace=one(monkeypatch,surface,positive,real=True)
    rows=findings(snapshot)
    assert len(rows)==1 and rows[0]['status']==('FAIL' if positive else 'PASS'),rows
    native_item=next(c for c in snapshot['collections'] if c['type']==source.KIND)['items'][0]
    assert native_item[source.MARKER]['engines']==[
      {'engine':'kingfisher','version':scanning.KINGFISHER_VERSION,'status':'complete'},
      {'engine':'trufflehog','version':scanning.TRUFFLEHOG_VERSION,'status':'complete'}]
    runs=[a for a in calls if 'stdin' in a];assert runs
    assert all({'--no-verification','--no-update','--no-verification-cache','--force-skip-archives','--fail-on-scan-errors'}<=set(a) for a in runs)
    assert TOKEN not in json.dumps([snapshot,rows])+retained(trace.readers[0])


@pytest.mark.parametrize('engine_name',['kingfisher','trufflehog'])
@pytest.mark.parametrize('positive',[False,True])
def test_one_engine_absent_no_clean_pass_but_observed_leak_is_decisive(monkeypatch,engine_name,positive):
    snapshot,_=one(monkeypatch,'codebuild_environment',positive,one_engine=engine_name)
    assert {r['status'] for r in findings(snapshot)}==({'FAIL'} if positive else {'UNKNOWN'})


def alter(surface,responses,case):
    response=responses[-1]
    if case=='partial':response['ResponseMetadata']['HTTPStatusCode']=206;return
    if case=='empty':
        if surface=='cloudformation_template':response.pop('TemplateBody')
        elif surface=='codepipeline_configuration':response.pop('pipeline')
        elif surface=='cloudformation_outputs':response['Stacks'][0].pop('Outputs')
        elif surface=='codebuild_environment':response['projects'][0]['environment'].pop('environmentVariables')
        elif surface=='rest_stage_variables':response['variables']={}
        elif surface=='ecs_environment':response['taskDefinition']['containerDefinitions'][0].pop('environment')
        elif surface=='amplify_environment':response['app']['environmentVariables']={}
        elif surface=='batch_environment':response['jobDefinitions'][0]['containerProperties']['environment']=[]
        elif surface=='beanstalk_options':response['ConfigurationSettings'][0]['OptionSettings']=[]
        elif surface=='glue_job_arguments':response['Job'].update(DefaultArguments={},NonOverridableArguments={})
        elif surface=='glue_connection_properties':response['Connection']['ConnectionProperties']={}
        elif surface=='launch_template_userdata':response['LaunchTemplateVersions'][0]['LaunchTemplateData'].pop('UserData')
        elif surface=='launch_configuration_userdata':response['LaunchConfigurations'][0]['UserData']=''
        elif surface=='ssm_document':response.pop('Content')
        elif surface=='state_machine_definition':response['definition']=' '
        elif surface=='notebook_lifecycle':response.update(OnCreate=[],OnStart=[])
        else:response['pipelineObjects']=[]
    elif case=='malformed':
        if surface=='cloudformation_template':response['TemplateBody']='{broken-json}'
        elif surface=='codepipeline_configuration':response['metadata']['pipelineArn']='not-an-arn'
        elif surface=='cloudformation_outputs':response['Stacks'][0]['Outputs']*=2
        elif surface=='codebuild_environment':response['projects']*=2
        elif surface=='rest_stage_variables':response['variables']={'VALUE':'\ud800'}
        elif surface=='ecs_environment':response['taskDefinition']['containerDefinitions']*=2
        elif surface=='amplify_environment':response['app']['environmentVariables']={'VALUE':'\ud800'}
        elif surface=='batch_environment':response['jobDefinitions'][0]['type']='multinode'
        elif surface=='beanstalk_options':response['ConfigurationSettings'][0]['OptionSettings']*=2
        elif surface=='glue_job_arguments':response['Job']['DefaultArguments']={'--VALUE':'\ud800'}
        elif surface=='glue_connection_properties':response['Connection']['ConnectionProperties']={'USERNAME':'\ud800'}
        elif surface=='launch_template_userdata':response['LaunchTemplateVersions']*=2
        elif surface=='launch_configuration_userdata':response['LaunchConfigurations'][0]['UserData']='!!not-base64!!'
        elif surface=='ssm_document':response['Content']='{broken-json}'
        elif surface=='state_machine_definition':response['definition']='{broken-json}'
        elif surface=='notebook_lifecycle':response['OnCreate'][0]['Content']='!!not-base64!!'
        else:response['pipelineObjects'][0]['fields'][0]['refValue']='unsupported-both-representations'
    elif case=='foreign':
        if surface=='codepipeline_configuration':response['metadata']['pipelineArn']=response['metadata']['pipelineArn'].replace(ACCOUNT,'000000000000')
        elif surface=='cloudformation_outputs':response['Stacks'][0]['StackId']=response['Stacks'][0]['StackId'].replace(ACCOUNT,'000000000000')
        elif surface=='codebuild_environment':response['projects'][0]['arn']=response['projects'][0]['arn'].replace(ACCOUNT,'000000000000')
        elif surface=='rest_stage_variables':response['stageName']='OtherStage'
        elif surface=='ecs_environment':response['taskDefinition']['taskDefinitionArn']=response['taskDefinition']['taskDefinitionArn'].replace(ACCOUNT,'000000000000')
        elif surface=='amplify_environment':response['app']['appArn']=response['app']['appArn'].replace(ACCOUNT,'000000000000')
        elif surface=='batch_environment':response['jobDefinitions'][0]['jobDefinitionArn']=response['jobDefinitions'][0]['jobDefinitionArn'].replace(ACCOUNT,'000000000000')
        elif surface=='beanstalk_options':response['ConfigurationSettings'][0]['EnvironmentName']='OtherEnvironment'
        elif surface=='glue_job_arguments':response['Job']['Name']='OtherJob'
        elif surface=='glue_connection_properties':response['Connection']['Name']='OtherConnection'
        elif surface=='launch_template_userdata':response['LaunchTemplateVersions'][0]['VersionNumber']=4
        elif surface=='launch_configuration_userdata':response['LaunchConfigurations'][0]['LaunchConfigurationARN']=response['LaunchConfigurations'][0]['LaunchConfigurationARN'].replace(ACCOUNT,'000000000000')
        elif surface=='ssm_document':response['Name']='ForeignDocument'
        elif surface=='state_machine_definition':response['stateMachineArn']=response['stateMachineArn'].replace(ACCOUNT,'000000000000')
        elif surface=='notebook_lifecycle':response['NotebookInstanceLifecycleConfigArn']=response['NotebookInstanceLifecycleConfigArn'].replace(ACCOUNT,'000000000000')
        # GetPipelineDefinition has no echo/owner field: its foreign scope case
        # is exercised through real STS account contradiction instead below.


@pytest.mark.parametrize('surface',SURFACES)
@pytest.mark.parametrize('case',['empty','malformed','partial','foreign'])
def test_each_native_surface_incomplete_or_foreign_never_clean(monkeypatch,surface,case):
    target,responses=native(surface)
    alter(surface,responses,case)
    kwargs={}
    if surface in ('pipeline_definition','cloudformation_template') and case=='foreign':
        kwargs['caller']={'Account':'000000000000','Arn':'arn:aws:iam::000000000000:user/reviewer','UserId':'AIDAOTHER'}
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses},**kwargs)
    rows=findings(snapshot)
    assert rows and {r['status'] for r in rows}=={'UNKNOWN'},rows
    assert not trace.scans and TOKEN not in json.dumps(snapshot)+retained(trace.readers[0])


@pytest.mark.parametrize('surface',SURFACES)
def test_credential_account_contradiction_reads_no_selected_content(monkeypatch,surface):
    target,responses=native(surface)
    caller={'Account':'000000000000','Arn':'arn:aws:iam::000000000000:user/reviewer','UserId':'AIDAOTHER'}
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses},caller=caller)
    assert not trace.calls and not trace.scans and {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}


@pytest.mark.parametrize('owned', [False,True])
def test_ssm_native_owner_is_required_before_document_content(monkeypatch,owned):
    target,responses=native('ssm_document')
    if not owned:responses[0]['Document']['Owner']='000000000000'
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses})
    assert len(trace.calls)==(2 if owned else 1)
    assert {r['status'] for r in findings(snapshot)}==({'PASS'} if owned else {'UNKNOWN'})


@pytest.mark.parametrize('reference_type',['PARAMETER_STORE','SECRETS_MANAGER'])
def test_intended_codebuild_references_are_not_dereferenced_or_counted_leaks(monkeypatch,reference_type):
    target,responses=native('codebuild_environment',True)
    responses[0]['projects'][0]['environment']['environmentVariables'][0]['type']=reference_type
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses})
    assert not trace.scans and {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert len(trace.calls)==1 and trace.calls[0][0]=='codebuild'
    assert TOKEN not in json.dumps(snapshot)+retained(trace.readers[0])


@pytest.mark.parametrize('surface',['launch_template_userdata','launch_configuration_userdata'])
@pytest.mark.parametrize('positive',[False,True])
def test_strict_bounded_gzip_userdata_is_real_scannable_content(monkeypatch,surface,positive):
    target,responses=native(surface,positive);text='TOKEN='+TOKEN if positive else 'echo ready\n'*300
    data=base64.b64encode(gzip.compress(text.encode())).decode()
    if surface=='launch_template_userdata':responses[0]['LaunchTemplateVersions'][0]['LaunchTemplateData']['UserData']=data
    else:responses[0]['LaunchConfigurations'][0]['UserData']=data
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses})
    assert {r['status'] for r in findings(snapshot)}==({'FAIL'} if positive else {'PASS'})
    assert len(trace.scans)==2


@pytest.mark.parametrize('surface',SURFACES)
def test_explicit_content_flag_is_required_for_every_surface(monkeypatch,surface):
    snapshot,trace=one(monkeypatch,surface,opts={'content_secret_scans':False})
    assert not trace.calls and not trace.scans and {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}

@pytest.mark.parametrize('case',['missing','empty','duplicate','too_many','foreign_scope','foreign_arn','qualified_version','extra_url','bad_version','bad_surface'])
def test_public_selection_rejects_before_authentication(monkeypatch,case):
    target,_=native('codebuild_environment');targets=[target]
    if case=='missing':targets=None
    elif case=='empty':targets=[]
    elif case=='duplicate':targets*=2
    elif case=='too_many':targets=[{**target,'resource_id':target['resource_id']+str(i)} for i in range(17)]
    elif case=='foreign_scope':target['scope']='000000000000/'+REGION
    elif case=='foreign_arn':target['resource_id']=target['resource_id'].replace(ACCOUNT,'000000000000')
    elif case=='qualified_version':target['version']=3
    elif case=='extra_url':target['url']='https://untrusted.invalid/content'
    elif case=='bad_version':target.update(surface='launch_template_userdata',resource_id=arn('ec2','launch-template/lt-0123456789abcdef0'),version='$Latest')
    else:target['surface']='secretsmanager_value'
    req=request(targets)
    if case=='missing':
        req['connector']['options'].pop(source.OPTION)
        class InventoryPlanning(Exception):
            pass
        def inventory(connector):
            raise InventoryPlanning
        monkeypatch.setattr(aws, '_selection', inventory)
        with pytest.raises(InventoryPlanning):
            engine.collect_snapshot(req)
        return
    with pytest.raises(ValueError):engine.collect_snapshot(req)


@pytest.mark.parametrize('flag',['true',1,{},None])
def test_strict_content_flag_type_before_credentials(monkeypatch,flag):
    target,_=native('codebuild_environment')
    with pytest.raises(ValueError):engine.collect_snapshot(request([target],content_secret_scans=flag))


def test_no_category_or_bulk_selection_enables_content(monkeypatch):
    target,_=native('codebuild_environment');req=request([target]);req.pop('checks');req['categories']=['exposure']
    class Captured(Exception):pass
    observed=[]
    def collect(connector,requirements):observed.append(connector['options']);raise Captured()
    monkeypatch.setattr(aws,'collect',collect)
    with pytest.raises(Captured):engine.collect_snapshot(req)
    assert source.KIND not in observed[0]['_content_secret_scan_kinds']


@pytest.mark.parametrize('surface',SURFACES)
def test_trusted_native_endpoint_required_before_content_read(monkeypatch,surface):
    snapshot,trace=one(monkeypatch,surface,untrusted_endpoint=True)
    assert not trace.calls and not trace.scans and {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}


@pytest.mark.parametrize('operation,service',[('get_stage','apigateway'),('describe_document','ssm')])
def test_new_native_operations_are_optional_projected_only(monkeypatch,operation,service):
    requests=aws.Requests({})
    with pytest.raises(aws.ReadFailure,match='selected_configuration_requires_safe_projection'):
        requests.call(object(),service,REGION,operation)
    assert requests.calls==0 and not requests._clients


def test_profile_rejects_undeclared_native_request_before_client(monkeypatch):
    target,_=native('codebuild_environment');options=request([target])['connector']['options']
    options['_content_secret_scan_kinds']=[source.KIND]
    requests=aws.Requests(options);requests.content_secret_scan_kinds=frozenset({source.KIND})
    source.initialize(requests,options,[SCOPE]);session=object()
    requests.configuration_content_sessions[id(session)]={'account':ACCOUNT,'partition':'aws','principal':'unused'}
    with pytest.raises(aws.ReadFailure,match='selected_configuration_request_unbound'):
        requests.call(session,'codebuild',REGION,'batch_get_projects',_metadata_profile=source.PROFILE,names=[arn('codebuild','project/Foreign')])
    assert requests.calls==0 and not requests._cache


def test_earlier_native_metadata_future_and_secret_bearing_cache_alias_are_scrubbed(monkeypatch):
    target,responses=native('codebuild_environment',True,name=TOKEN)
    caller={**CALLER,'Arn':'arn:aws:iam::'+ACCOUNT+':user/'+TOKEN}
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses},seed_metadata=True,caller=caller)
    assert {r['status'] for r in findings(snapshot)}=={'FAIL'}
    assert TOKEN not in json.dumps([snapshot,trace.progress])+retained(trace.readers[0])
    assert TOKEN not in json.dumps(trace.earlier_futures[0].result(),default=str)
    assert all(TOKEN not in repr(key) for key in trace.readers[0]._cache)
    assert snapshot['metadata']['caller_identities'][0]['Arn'].endswith('/[redacted]')


def test_union_of_disjoint_engine_values_is_hidden_in_prior_metadata_and_keys(monkeypatch):
    def kingfisher(payload,path,timeout):return [(TOKEN,'github',1)]
    def trufflehog(payload,path,timeout):return [(OTHER,'github',1)]
    monkeypatch.setattr(scanning,'_scan_kingfisher',kingfisher);monkeypatch.setattr(scanning,'_scan_trufflehog',trufflehog)
    target,responses=native('codebuild_environment',True,name=TOKEN)
    responses[0]['projects'][0]['description']=OTHER
    responses[0]['projects'][0]['environment']['environmentVariables'].append({'name':'OTHER','value':OTHER,'type':'PLAINTEXT'})
    # Preserve the disjoint controlled detector outputs; native SDK projection
    # and the shared real union/dedup machinery remain unchanged.
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses},seed_metadata=True,real=True)
    assert len(findings(snapshot))==2
    assert {d['engine'] for row in findings(snapshot) for leak in row['evidence']['secret_leaks'] for d in leak['detectors']}=={'kingfisher','trufflehog'}
    assert all(value not in json.dumps([snapshot,trace.progress])+retained(trace.readers[0]) for value in (TOKEN,OTHER))


def test_descriptor_overflow_withholds_earlier_native_future_aliases(monkeypatch):
    monkeypatch.setattr(source,'MAX_REDACTION_DESCRIPTORS',1)
    target,responses=native('codebuild_environment',True,name='Audit'+TOKEN)
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses},seed_metadata=True)
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert TOKEN not in json.dumps([snapshot,[f.result() for f in trace.earlier_futures]],default=str)
    assert not trace.readers[0]._cache


@pytest.mark.parametrize('bound',['response','total','content','calls','deadline','descriptor','redaction'])
def test_native_budgets_never_produce_clean_results(monkeypatch,bound):
    kwargs={}
    if bound=='response':monkeypatch.setattr(source,'MAX_RESPONSE',32)
    elif bound=='total':monkeypatch.setattr(source,'MAX_TOTAL',1)
    elif bound=='content':monkeypatch.setattr(source,'MAX_CONTENT',1)
    elif bound=='calls':kwargs['opts']={'max_calls':1}
    elif bound=='deadline':monkeypatch.setattr(source,'MAX_SECONDS',0)
    elif bound=='descriptor':monkeypatch.setattr(source,'MAX_REDACTION_DESCRIPTORS',0)
    else:monkeypatch.setattr(source,'MAX_REDACTION_WINDOWS',0)
    snapshot,trace=one(monkeypatch,'codebuild_environment',True,**kwargs)
    assert {r['status'] for r in findings(snapshot)}=={'UNKNOWN'}
    assert TOKEN not in json.dumps([snapshot,trace.progress])+retained(trace.readers[0])
    if bound in ('calls','deadline'):assert not trace.calls


def test_exact_value_dedup_across_all_fifteen_native_surfaces(monkeypatch):
    targets=[];responses={}
    for surface in LEGACY_SURFACES:
        target,payloads=native(surface,True);targets.append(target);responses[source.identity(target)]=payloads
    snapshot,trace=capture(monkeypatch,targets,responses)
    result=findings(snapshot)
    assert len(result)==1 and result[0]['status']=='FAIL'
    leak,=result[0]['evidence']['secret_leaks'];assert len(leak['locations'])==15 and len(leak['detectors'])==2
    assert len(trace.calls)==16 and TOKEN not in json.dumps(snapshot)+retained(trace.readers[0])


def test_partial_global_resource_budget_preserves_observed_failure_and_unknown_coverage(monkeypatch):
    targets=[];responses={}
    for surface in ('codebuild_environment','ecs_environment'):
        target,payloads=native(surface,True);targets.append(target);responses[source.identity(target)]=payloads
    snapshot,_=capture(monkeypatch,targets,responses,opts={'max_resources':2})
    result=findings(snapshot)
    assert {r['status'] for r in result}=={'FAIL','UNKNOWN'}


def test_real_multiline_private_key_literals_are_not_json_escape_blinded(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048).private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()).decode()
    target,responses=native('codebuild_environment')
    responses[0]['projects'][0]['environment']['environmentVariables']=[{'name':'TEST_PRIVATE_KEY','value':private,'type':'PLAINTEXT'}]
    snapshot,trace=capture(monkeypatch,[target],{source.identity(target):responses},real=True)
    assert {r['status'] for r in findings(snapshot)}=={'FAIL'}
    assert private not in json.dumps(snapshot)+retained(trace.readers[0])
    assert '-----BEGIN PRIVATE KEY-----' not in retained(trace.readers[0])
