"""Bounded exact-selected AWS configuration reads; opaque, offline projections.

SDK responses are allocated before this projection. Bounds limit inspected and
retained bytes, not transport allocation. No secret store, execution or writes.
"""

from peaso.secret_evidence import scan_with_source, source_context, target_source
from copy import deepcopy
from datetime import date, datetime
import base64
import json
import math
import re
import time
from uuid import uuid4
from urllib.parse import urlsplit
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from .aws_configuration_payload_secret_indicators import decode, _json

KIND = 'configuration_selected_content'
CHECK = 'aws.review.configuration.selected_content_secret_indicators'
OPTION = 'selected_aws_configuration_content'
PROFILE = 'aws-selected-configuration-content-v1'
MARKER = 'SelectedConfigurationSecretIndicators'
SCHEMA = 'aws-selected-configuration-content-v1'
MAX_TARGETS = 16
MAX_SELECTED_SCOPES = 8
MAX_RESPONSE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_CONTENT = 1024 * 1024
MAX_PAIRS = 256
MAX_LEAKS = 128
MAX_LOCATIONS = 512
MAX_SECONDS = 120
MAX_CALLS = 32
MAX_REDACTION_WINDOWS = 1000000
MAX_REDACTION_DESCRIPTORS = 512
MAX_REDACTION_VALUE = 65536
SCOPE = re.compile(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\Z')
# A real operation descriptor is required by the existing planner; every read is
# dispatched by collect_selected, never by the generic DescribeStacks handler.
SPECS = {KIND: ('cloudformation', 'describe_stacks', None)}
NATIVE_IDS = {KIND: 'id'}
SURFACES = {
 'cloudformation_template': ('cloudformation','get_template','cloudformation','stack/([A-Za-z][A-Za-z0-9-]{0,127})/([A-Za-z0-9-]{1,128})'),
 'codepipeline_configuration': ('codepipeline','get_pipeline','codepipeline','([A-Za-z0-9.@_-]{1,100})'),
 'cloudformation_outputs': ('cloudformation','describe_stacks','cloudformation','stack/([A-Za-z][A-Za-z0-9-]{0,127})/([A-Za-z0-9-]{1,128})'),
 'codebuild_environment': ('codebuild','batch_get_projects','codebuild','project/([A-Za-z0-9][A-Za-z0-9_-]{1,254})'),
 'rest_stage_variables': ('apigateway','get_stage','apigateway','/restapis/([a-z0-9]{1,32})/stages/([A-Za-z0-9_-]{1,128})'),
 'ecs_environment': ('ecs','describe_task_definition','ecs','task-definition/([A-Za-z0-9_-]{1,255}):([1-9][0-9]{0,9})'),
 'amplify_environment': ('amplify','get_app','amplify','apps/([a-z0-9]{1,20})'),
 'batch_environment': ('batch','describe_job_definitions','batch','job-definition/([A-Za-z0-9_-]{1,128}):([1-9][0-9]{0,9})'),
 'beanstalk_options': ('elasticbeanstalk','describe_configuration_settings','elasticbeanstalk','environment/([A-Za-z0-9_-]{1,100})/([A-Za-z0-9-]{4,40})'),
 'glue_job_arguments': ('glue','get_job','glue','job/([A-Za-z0-9_. -]{1,255})'),
 'glue_connection_properties': ('glue','get_connection','glue','connection/([A-Za-z0-9_. -]{1,255})'),
 'launch_template_userdata': ('ec2','describe_launch_template_versions','ec2','launch-template/(lt-[a-f0-9]{8,17})'),
 'launch_configuration_userdata': ('autoscaling','describe_launch_configurations','autoscaling','launchConfiguration:([A-Za-z0-9-]{1,128}):launchConfigurationName/([A-Za-z0-9_.-]{1,255})'),
 'ssm_document': ('ssm','get_document','ssm','document/([A-Za-z0-9_.-]{3,128})'),
 'state_machine_definition': ('stepfunctions','describe_state_machine','states','stateMachine:([A-Za-z0-9_-]{1,80})'),
 'notebook_lifecycle': ('sagemaker','describe_notebook_instance_lifecycle_config','sagemaker','notebook-instance-lifecycle-config/([A-Za-z0-9-]{1,63})'),
 'pipeline_definition': ('datapipeline','get_pipeline_definition','datapipeline','pipeline/(df-[A-Za-z0-9]{1,128})'),
}
PROJECTION_OPERATIONS = {(s,o) for s,o,_,_ in SURFACES.values()} | {('ssm','describe_document')}
READ_ACTIONS = PROJECTION_OPERATIONS


def enabled(options):
    return (options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'),list)
            and KIND in options['_content_secret_scan_kinds'])


def parse(target):
    if not isinstance(target,dict) or set(target)-{'surface','scope','resource_id','version'} or not {'surface','scope','resource_id'}<=set(target):
        raise ValueError('invalid_configuration_selection')
    surface=target['surface'];scope=target['scope'];arn=target['resource_id']
    if not isinstance(surface,str) or surface not in SURFACES or not isinstance(scope,str) or not SCOPE.fullmatch(scope) or not isinstance(arn,str) or len(arn)>2048:
        raise ValueError('invalid_configuration_selection')
    account,region=SCOPE.fullmatch(scope).groups()
    partition='aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    if '-iso' in region:raise ValueError('invalid_configuration_selection')
    service,operation,arn_service,resource=SURFACES[surface]
    arn_account='' if surface=='rest_stage_variables' else account
    match=re.fullmatch('arn:'+partition+':'+arn_service+':'+region+':'+arn_account+':'+resource,arn)
    if not match:raise ValueError('invalid_configuration_selection')
    versioned=surface in ('launch_template_userdata','ssm_document','codepipeline_configuration')
    if versioned:
        if type(target.get('version')) is not int or not 1<=target['version']<=2147483647:raise ValueError('invalid_configuration_selection')
    elif 'version' in target:raise ValueError('invalid_configuration_selection')
    return surface,account,region,partition,match.groups()


def selected_targets(options,scopes):
    """Credential-free public selector validator; numeric versions, no URLs."""
    if not isinstance(options,dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):raise ValueError('invalid_configuration_selection')
    if OPTION not in options and not enabled(options):return []
    targets=options.get(OPTION)
    if (not isinstance(scopes,list) or not scopes
            or any(not isinstance(s,str) or not SCOPE.fullmatch(s) for s in scopes) or len(set(scopes))!=len(scopes)
            or not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_configuration_selection')
    seen=set();selected_scopes=set()
    for target in targets:
        parse(target);key=identity(target)
        if target['scope'] not in scopes or key in seen:raise ValueError('invalid_configuration_selection')
        seen.add(key)
        selected_scopes.add(target['scope'])
        if len(selected_scopes)>MAX_SELECTED_SCOPES:raise ValueError('invalid_configuration_selection')
    return deepcopy(targets)


def identity(target):return KIND+':'+_fingerprint(json.dumps(target,sort_keys=True,separators=(',',':')))
def opaque_arguments(arguments):return {'request_locator':'configuration-request:'+_fingerprint(json.dumps(arguments,sort_keys=True,separators=(',',':')))}


def route(target,*,ownership=False):
    surface,account,region,partition,names=parse(target)
    service,operation,_,_=SURFACES[surface];arn=target['resource_id']
    arguments={
      'cloudformation_template':lambda:{'StackName':arn,'TemplateStage':'Original'},
      'codepipeline_configuration':lambda:{'name':names[0],'version':target['version']},
      'cloudformation_outputs':lambda:{'StackName':arn},
      'codebuild_environment':lambda:{'names':[arn]},
      'rest_stage_variables':lambda:{'restApiId':names[0],'stageName':names[1]},
      'ecs_environment':lambda:{'taskDefinition':arn},
      'amplify_environment':lambda:{'appId':names[0]},
      'batch_environment':lambda:{'jobDefinitions':[arn]},
      'beanstalk_options':lambda:{'ApplicationName':names[0],'EnvironmentName':names[1]},
      'glue_job_arguments':lambda:{'JobName':names[0]},
      'glue_connection_properties':lambda:{'CatalogId':account,'Name':names[0],'HidePassword':True},
      'launch_template_userdata':lambda:{'LaunchTemplateId':names[0],'Versions':[str(target['version'])]},
      'launch_configuration_userdata':lambda:{'LaunchConfigurationNames':[names[1]]},
      'ssm_document':lambda:{'Name':arn,'DocumentVersion':str(target['version'])},
      'state_machine_definition':lambda:{'stateMachineArn':arn,'includedData':'ALL_DATA'},
      'notebook_lifecycle':lambda:{'NotebookInstanceLifecycleConfigName':names[0]},
      'pipeline_definition':lambda:{'pipelineId':names[0],'version':'latest'},
    }[surface]()
    return service,('describe_document' if ownership else operation),arguments


def initialize(requests,options,scopes):
    targets=selected_targets(options,scopes)
    requests.configuration_content_metadata={KIND+'_authorized':enabled(options),KIND+'_selection':{
        scope:[identity(t) for t in targets if t['scope']==scope] for scope in scopes},KIND+'_capture':'configuration-capture:'+uuid4().hex,
        KIND+'_principals':{}}
    requests.configuration_content_metadata[KIND+'_redaction_complete']=True
    requests.configuration_content_sessions={};requests.configuration_content_approved={};requests.configuration_content_owned={}
    requests.configuration_content_state={'deadline':None,'responses':0,'bytes':0,'attempts':0}
    requests.configuration_content_redactions={}
    requests.configuration_content_redaction_overflow=False
    for target in targets:
        surface,account,region,partition,names=parse(target)
        for ownership in ((True,False) if surface=='ssm_document' else (False,)):
            service,operation,args=route(target,ownership=ownership)
            key=(service,operation,region,opaque_arguments(args)['request_locator'])
            if key in requests.configuration_content_approved:raise ValueError('ambiguous_configuration_selection')
            # No raw selection, request argument, name, ARN or content is retained.
            requests.configuration_content_approved[key]={'id':identity(target),'scope':target['scope'],'surface':surface,
                'account':account,'region':region,'partition':partition,'version':target.get('version'),'ownership':ownership}


def remaining(requests):
    requests.check_deadline()
    with requests._lock:
        state=requests.configuration_content_state
        if state['deadline'] is None:state['deadline']=time.monotonic()+MAX_SECONDS
        left=state['deadline']-time.monotonic()
    if left<=0:raise ValueError('configuration_deadline')
    return left


def before_request(requests):
    from .aws import ReadFailure
    remaining(requests)
    with requests._lock:
        state=requests.configuration_content_state
        if state['attempts']>=MAX_CALLS:raise ReadFailure('not_collected','selected_configuration_call_bound')
        state['attempts']+=1


def validate_request(service,operation,arguments,*,request_context=None,region=None):
    from .aws import ReadFailure
    try:
        requests,session=request_context
        info=requests.configuration_content_approved[(service,operation,region,opaque_arguments(arguments)['request_locator'])]
        if (requests.content_secret_scans is not True or KIND not in requests.content_secret_scan_kinds
                or requests.configuration_content_metadata[KIND+'_authorized'] is not True
                or requests.configuration_content_sessions[id(session)]['account']!=info['account']
                or requests.configuration_content_sessions[id(session)]['partition']!=info['partition']):raise ValueError()
        if info['surface']=='ssm_document' and not info['ownership'] and info['id'] not in requests.configuration_content_owned:raise ValueError()
        remaining(requests)
    except (ValueError,TypeError,KeyError,AttributeError):
        raise ReadFailure('not_collected','selected_configuration_request_unbound') from None


def validate_native_client(client,service,region):
    from .aws import ReadFailure
    try:
        endpoint=urlsplit(client.meta.endpoint_url)
        prefix={'sagemaker':'api.sagemaker','stepfunctions':'states'}.get(service,service)
        suffix='amazonaws.com.cn' if region.startswith('cn-') else 'amazonaws.com'
        if (endpoint.scheme!='https' or endpoint.netloc!=prefix+'.'+region+'.'+suffix
                or endpoint.path not in ('','/') or endpoint.query or endpoint.fragment):raise ValueError()
    except (ValueError,TypeError,AttributeError):
        raise ReadFailure('not_collected','selected_configuration_endpoint_unbound') from None


def response_size(value):
    stack=[(value,0)];nodes=0
    while stack:
        v,depth=stack.pop();nodes+=1
        if nodes>65536 or depth>32:raise ValueError('response_bound')
        if isinstance(v,str):
            if len(v)>MAX_RESPONSE:raise ValueError('response_bound')
        elif isinstance(v,dict):
            if len(v)>65536 or any(not isinstance(k,str) for k in v):raise ValueError('response_shape')
            stack.extend((x,depth+1) for pair in v.items() for x in pair)
        elif isinstance(v,list):
            if len(v)>65536:raise ValueError('response_bound')
            stack.extend((x,depth+1) for x in v)
        elif isinstance(v,(date,datetime)):pass
        elif v is not None and type(v) not in (bool,int,float):raise ValueError('response_shape')
        elif isinstance(v,float) and not math.isfinite(v):raise ValueError('response_shape')
    total=0
    for chunk in json.JSONEncoder(ensure_ascii=False,allow_nan=False,default=lambda v:v.isoformat(),separators=(',',':')).iterencode(value):
        total+=len(chunk.encode('utf-8'))
        if total>MAX_RESPONSE:raise ValueError('response_bound')
    return total


def mapping(value):
    if not isinstance(value,dict) or len(value)>MAX_PAIRS:raise ValueError('map_shape')
    return pairs(list(value.items()))


def pairs(value):
    if not isinstance(value,list) or len(value)>MAX_PAIRS:raise ValueError('pairs_bound')
    out={}
    for key,text in value:
        if (not isinstance(key,str) or not key or len(key)>4096 or key in out or not isinstance(text,str)
                or len(text)>MAX_CONTENT):raise ValueError('pair_shape')
        out[key]=text
    return out


def environment(rows,*,typed=False):
    if not isinstance(rows,list) or len(rows)>MAX_PAIRS:raise ValueError('environment_shape')
    values=[]
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('name'),str) or not isinstance(row.get('value'),str) or 'valueFrom' in row:raise ValueError('environment_shape')
        if typed:
            if row.get('type') not in ('PLAINTEXT','PARAMETER_STORE','SECRETS_MANAGER'):raise ValueError('environment_type')
            if row['type']!='PLAINTEXT':continue
        values.append((row['name'],row['value']))
    return pairs(values)


def batch_literals(row):
    """Read bounded literal declarations from one pinned Batch job definition."""
    entries=[]

    def strings(values,prefix):
        if not isinstance(values,list) or len(values)>MAX_PAIRS:
            raise ValueError('batch_strings_shape')
        for index,item in enumerate(values):
            if not isinstance(item,str) or len(item)>MAX_CONTENT:
                raise ValueError('batch_strings_shape')
            entries.append((prefix+':'+str(index),item))

    def container(item,prefix,*,eks=False):
        if not isinstance(item,dict) or 'environmentFiles' in item or 'envFrom' in item:
            raise ValueError('batch_container_shape')
        for key,text in environment(item.get('env' if eks else 'environment',[])).items():
            entries.append((prefix+':env:'+key,text))
        if 'command' in item:
            strings(item['command'],prefix+':command')
        if eks and 'args' in item:
            strings(item['args'],prefix+':args')

    def named_containers(rows,prefix,*,eks=False):
        if not isinstance(rows,list) or not rows or len(rows)>10:
            raise ValueError('batch_containers_shape')
        seen=set()
        for index,item in enumerate(rows):
            if not isinstance(item,dict):raise ValueError('batch_container_shape')
            name=item.get('name','Default' if eks else None)
            if not isinstance(name,str) or not name or len(name)>256 or name in seen:
                raise ValueError('batch_container_identity')
            seen.add(name)
            container(item,prefix+':'+str(index)+':'+name,eks=eks)

    def variant(properties,prefix,kind):
        if not isinstance(properties,dict):raise ValueError('batch_variant_shape')
        if kind=='container':
            container(properties,prefix)
        elif kind=='ecsProperties':
            tasks=properties.get('taskProperties')
            if not isinstance(tasks,list) or len(tasks)!=1 or not isinstance(tasks[0],dict):
                raise ValueError('batch_tasks_shape')
            if 'envFrom' in tasks[0]:raise ValueError('batch_tasks_shape')
            named_containers(tasks[0].get('containers'),prefix+':task')
        elif kind=='eksProperties':
            pod=properties.get('podProperties')
            if not isinstance(pod,dict) or 'envFrom' in pod:raise ValueError('batch_pod_shape')
            containers=pod.get('containers')
            named_containers(containers,prefix+':pod',eks=True)
            if 'initContainers' in pod:
                named_containers(pod['initContainers'],prefix+':init',eks=True)
        else:raise ValueError('batch_variant_shape')

    kinds=[key for key in ('containerProperties','ecsProperties','eksProperties','nodeProperties') if key in row]
    if len(kinds)!=1:raise ValueError('batch_variant')
    kind=kinds[0]
    platforms=row.get('platformCapabilities',['EC2'])
    if (not isinstance(platforms,list) or len(platforms)!=1
            or platforms[0] not in ('EC2','FARGATE','MANAGED_INSTANCES')):
        raise ValueError('batch_platform')
    if (kind=='nodeProperties' and platforms[0]!='EC2') or (platforms[0]=='MANAGED_INSTANCES' and kind!='ecsProperties'):
        raise ValueError('batch_platform_variant')
    orchestration=row.get('containerOrchestrationType','ECS')
    if orchestration not in ('ECS','EKS'):
        raise ValueError('batch_orchestration')
    if kind=='eksProperties' and orchestration!='EKS':raise ValueError('batch_orchestration')
    if kind in ('containerProperties','ecsProperties') and orchestration!='ECS':raise ValueError('batch_orchestration')
    if kind=='nodeProperties':
        node=row[kind]
        if not isinstance(node,dict) or type(node.get('numNodes')) is not int or not 1<=node['numNodes']<=100000:
            raise ValueError('batch_nodes_shape')
        if type(node.get('mainNode')) is not int or not 0<=node['mainNode']<node['numNodes']:
            raise ValueError('batch_nodes_shape')
        ranges=node.get('nodeRangeProperties')
        if not isinstance(ranges,list) or not ranges or len(ranges)>32:
            raise ValueError('batch_ranges_shape')
        seen=set()
        for index,item in enumerate(ranges):
            if not isinstance(item,dict):raise ValueError('batch_range_shape')
            target=item.get('targetNodes')
            if (not isinstance(target,str) or len(target)>32
                    or not re.fullmatch(r'[0-9]{1,6}(?::[0-9]{1,6})?|:[0-9]{1,6}|[0-9]{1,6}:',target)
                    or target in seen):raise ValueError('batch_range_identity')
            bounds=target.split(':')
            first=int(bounds[0] or 0)
            last=int(bounds[1] or node['numNodes']-1) if len(bounds)==2 else first
            if not 0<=first<=last<node['numNodes']:
                raise ValueError('batch_range_identity')
            seen.add(target)
            inner=[key for key in ('container','ecsProperties','eksProperties') if key in item]
            if len(inner)!=1:raise ValueError('batch_range_variant')
            if (inner[0]=='eksProperties')!=(orchestration=='EKS'):
                raise ValueError('batch_orchestration')
            variant(item[inner[0]],'node:'+str(index)+':'+target,inner[0])
    else:
        variant(row[kind],kind,kind if kind!='containerProperties' else 'container')
    return pairs(entries)


def one(response,field):
    rows=response.get(field)
    if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):raise ValueError('response_cardinality')
    return rows[0]


def json_literals(text):
    """Inspect source bytes and decoded JSON string literals, never execute."""
    parsed=_json(text);stack=[(parsed,0)];strings=[];nodes=0;total=len(text.encode('utf-8'))
    while stack:
        child,depth=stack.pop();nodes+=1
        if nodes>65536 or depth>32:raise ValueError('definition_structure_bound')
        if isinstance(child,str):
            total+=len(child.encode('utf-8'))
            if total>MAX_CONTENT:raise ValueError('decoded_definition_bound')
            strings.append(child)
        elif isinstance(child,dict):stack.extend((v,depth+1) for pair in child.items() for v in pair)
        elif isinstance(child,list):stack.extend((v,depth+1) for v in child)
    return text+'\n\n'+'\n\n'.join(strings)



def _document_literals(value):
    """Bounded literal text from native document objects; no evaluation or reads."""
    stack=[(value,0)];strings=[];nodes=0;total=0
    while stack:
        child,depth=stack.pop();nodes+=1
        if nodes>65536 or depth>32:raise ValueError('document_structure_bound')
        if isinstance(child,str):
            total+=len(child.encode('utf-8'))+2
            if total>MAX_CONTENT:raise ValueError('document_content_bound')
            strings.append(child)
        elif isinstance(child,dict):
            if any(not isinstance(key,str) for key in child):raise ValueError('document_structure_bound')
            stack.extend((v,depth+1) for pair in reversed(list(child.items())) for v in reversed(pair))
        elif isinstance(child,list):stack.extend((v,depth+1) for v in reversed(child))
        elif child is not None and type(child) not in (bool,int,float):raise ValueError('document_structure_bound')
    return '\n\n'.join(strings)


def extract(response,service,operation,args,info):
    """Return inspected literal bytes only; no provider text escapes this frame."""
    surface=info['surface'];account=info['account'];region=info['region'];arn_prefix='arn:'+info['partition']+':'
    value=None
    if surface=='cloudformation_template':
        # AWS GetTemplate is bound to the exact selected stack ARN by the signed
        # request; it does not echo StackId. Do not invent a response identity.
        if args!={'StackName':args.get('StackName'),'TemplateStage':'Original'}:
            raise ValueError('template_request')
        stages=response.get('StagesAvailable')
        if (not isinstance(stages,list) or 'Original' not in stages or len(stages)!=len(set(stages))
                or any(s not in ('Original','Processed') for s in stages)):raise ValueError('template_stage')
        body=response.get('TemplateBody')
        if isinstance(body,str):
            # Preserve YAML/multiline literals; decode JSON string literals too.
            value=json_literals(body) if body.lstrip().startswith('{') else body
        elif isinstance(body,dict):value=_document_literals(body)
        else:raise ValueError('template_body')
    elif surface=='codepipeline_configuration':
        row=response.get('pipeline');metadata=response.get('metadata')
        expected=arn_prefix+'codepipeline:'+region+':'+account+':'+args['name']
        if (not isinstance(row,dict) or row.get('name')!=args['name']
                or type(row.get('version'))is not int or row['version']!=args['version']
                or not isinstance(metadata,dict) or metadata.get('pipelineArn')!=expected
                or not isinstance(row.get('stages'),list) or not 1<=len(row['stages'])<=50):
            raise ValueError('pipeline_configuration_identity')
        # The exact returned version is inspected; source/artifact links are not
        # dereferenced and no secret-store reference is resolved.
        value=_document_literals(row)
    elif surface=='cloudformation_outputs':
        row=one(response,'Stacks')
        if (row.get('StackId')!=args['StackName'] or row.get('StackName')!=args['StackName'].split(':stack/',1)[1].split('/',1)[0]
                or row.get('StackStatus') not in ('CREATE_COMPLETE','UPDATE_COMPLETE','IMPORT_COMPLETE','ROLLBACK_COMPLETE','UPDATE_ROLLBACK_COMPLETE','IMPORT_ROLLBACK_COMPLETE')):raise ValueError('stack_identity_state')
        rows=row.get('Outputs')
        if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)-{'OutputKey','OutputValue','Description','ExportName'} for r in rows):raise ValueError('outputs_shape')
        value=pairs([(r.get('OutputKey'),r.get('OutputValue')) for r in rows])
    elif surface=='codebuild_environment':
        if response.get('projectsNotFound'):raise ValueError('project_missing')
        row=one(response,'projects')
        if row.get('arn')!=args['names'][0] or row.get('name')!=args['names'][0].split(':project/',1)[1]:raise ValueError('project_identity')
        env=row.get('environment')
        if not isinstance(env,dict):raise ValueError('environment_shape')
        value=environment(env.get('environmentVariables'),typed=True)
    elif surface=='rest_stage_variables':
        if response.get('stageName')!=args['stageName']:raise ValueError('stage_identity')
        value=mapping(response.get('variables'))
    elif surface=='ecs_environment':
        row=response.get('taskDefinition')
        if not isinstance(row,dict) or row.get('taskDefinitionArn')!=args['taskDefinition'] or row.get('status')!='ACTIVE':raise ValueError('task_identity')
        if row.get('family')!=args['taskDefinition'].split(':task-definition/',1)[1].rsplit(':',1)[0] or str(row.get('revision'))!=args['taskDefinition'].rsplit(':',1)[1]:raise ValueError('task_revision')
        rows=row.get('containerDefinitions')
        if not isinstance(rows,list) or not rows or len(rows)>32:raise ValueError('containers_shape')
        value={};seen=set()
        for index,row in enumerate(rows):
            name=row.get('name') if isinstance(row,dict) else None
            if not isinstance(name,str) or not name or name in seen:raise ValueError('containers_identity')
            seen.add(name)
            for key,text in environment(row.get('environment',[])).items():value[str(index)+':'+key]=text
            # These are inline task-definition configuration literals. The
            # adjacent secretOptions fields are manager references, not leaked
            # values, and are deliberately never resolved or scanned.
            for field in ('logConfiguration','firelensConfiguration'):
                config=row.get(field)
                if config is None:continue
                if not isinstance(config,dict):raise ValueError('container_configuration_shape')
                options=config.get('options',{})
                for key,text in mapping(options).items():
                    value[str(index)+':'+field+'.options.'+key]=text
    elif surface=='amplify_environment':
        row=response.get('app')
        if not isinstance(row,dict) or row.get('appId')!=args['appId'] or row.get('appArn')!=arn_prefix+'amplify:'+region+':'+account+':apps/'+args['appId']:raise ValueError('app_identity')
        value=mapping(row.get('environmentVariables'))
    elif surface=='batch_environment':
        row=one(response,'jobDefinitions')
        # A deregistered (INACTIVE) revision stays readable through
        # DescribeJobDefinitions with its original literals, so it is reviewed
        # like an ACTIVE one rather than left without an assessment.
        if row.get('jobDefinitionArn')!=args['jobDefinitions'][0] or row.get('status') not in ('ACTIVE','INACTIVE') or row.get('type')!='container':raise ValueError('batch_identity_state')
        if (type(row.get('revision')) is not int or str(row['revision'])!=args['jobDefinitions'][0].rsplit(':',1)[1]
                or row.get('jobDefinitionName')!=args['jobDefinitions'][0].split(':job-definition/',1)[1].rsplit(':',1)[0]):raise ValueError('batch_identity')
        value=batch_literals(row)
    elif surface=='beanstalk_options':
        row=one(response,'ConfigurationSettings')
        if row.get('ApplicationName')!=args['ApplicationName'] or row.get('EnvironmentName')!=args['EnvironmentName'] or row.get('DeploymentStatus')!='deployed':raise ValueError('environment_identity_state')
        rows=row.get('OptionSettings')
        if not isinstance(rows,list) or len(rows)>MAX_PAIRS:raise ValueError('options_shape')
        entries=[]
        for row in rows:
            if not isinstance(row,dict) or not isinstance(row.get('Namespace'),str) or not isinstance(row.get('OptionName'),str):raise ValueError('options_shape')
            entries.append((row.get('ResourceName','')+'|'+row['Namespace']+'|'+row['OptionName'],row.get('Value')))
        value=pairs(entries)
    elif surface=='glue_job_arguments':
        row=response.get('Job')
        if not isinstance(row,dict) or row.get('Name')!=args['JobName']:raise ValueError('job_identity')
        value={}
        for field in ('DefaultArguments','NonOverridableArguments'):
            for key,text in mapping(row.get(field,{})).items():value[field+':'+key]=text
    elif surface=='glue_connection_properties':
        row=response.get('Connection')
        if not isinstance(row,dict) or row.get('Name')!=args['Name'] or args.get('CatalogId')!=account or args.get('HidePassword') is not True:raise ValueError('connection_identity')
        props=mapping(row.get('ConnectionProperties'))
        value={key:text for key,text in props.items() if key not in ('PASSWORD','ENCRYPTED_PASSWORD')}
    elif surface=='launch_template_userdata':
        row=one(response,'LaunchTemplateVersions')
        if row.get('LaunchTemplateId')!=args['LaunchTemplateId'] or type(row.get('VersionNumber')) is not int or str(row['VersionNumber'])!=args['Versions'][0]:raise ValueError('template_version')
        data=row.get('LaunchTemplateData')
        if not isinstance(data,dict) or 'UserData' not in data:raise ValueError('userdata_missing')
        value=decode(data['UserData'],gzip_ok=True)
    elif surface=='launch_configuration_userdata':
        row=one(response,'LaunchConfigurations')
        if row.get('LaunchConfigurationName')!=args['LaunchConfigurationNames'][0] or not isinstance(row.get('LaunchConfigurationARN'),str) or row['LaunchConfigurationARN']!=info['expected_arn']:raise ValueError('launch_configuration_identity')
        value=decode(row['UserData'],gzip_ok=True)
    elif surface=='ssm_document':
        name=args['Name'].split(':document/',1)[1]
        if response.get('Name')!=name or response.get('DocumentVersion')!=args['DocumentVersion'] or response.get('Status')!='Active':raise ValueError('document_version')
        text=response.get('Content');form=response.get('DocumentFormat')
        if not isinstance(text,str) or not text or len(text.encode())>65536:raise ValueError('document_bound')
        if form=='JSON':
            if not isinstance(_json(text),dict):raise ValueError('document_json')
            text=json_literals(text)
        elif form=='YAML':
            import yaml
            if not isinstance(yaml.compose(text),yaml.MappingNode):raise ValueError('document_yaml')
        elif form!='TEXT':raise ValueError('document_format')
        value=text
    elif surface=='state_machine_definition':
        if response.get('stateMachineArn')!=args['stateMachineArn'] or response.get('name')!=args['stateMachineArn'].split(':stateMachine:',1)[1] or response.get('status')!='ACTIVE':raise ValueError('state_machine_identity_state')
        text=response.get('definition')
        if not isinstance(text,str) or len(text.encode())>MAX_CONTENT:raise ValueError('definition_bound')
        parsed=_json(text)
        if not isinstance(parsed,dict) or not isinstance(parsed.get('States'),dict) or parsed.get('StartAt') not in parsed['States']:raise ValueError('asl_shape')
        value=json_literals(text)
    elif surface=='notebook_lifecycle':
        name=args['NotebookInstanceLifecycleConfigName']
        if response.get('NotebookInstanceLifecycleConfigName')!=name or response.get('NotebookInstanceLifecycleConfigArn')!=arn_prefix+'sagemaker:'+region+':'+account+':notebook-instance-lifecycle-config/'+name:raise ValueError('lifecycle_identity')
        texts=[]
        for field in ('OnCreate','OnStart'):
            rows=response.get(field,[])
            if not isinstance(rows,list) or len(rows)>1:raise ValueError('lifecycle_shape')
            for row in rows:
                if not isinstance(row,dict) or set(row)!={'Content'}:raise ValueError('lifecycle_shape')
                texts.append(field+'\n'+decode(row['Content']))
        value='\n\n'.join(texts)
    else:
        # Latest definition is request-bound: API does not echo the pipeline ID.
        values=[]
        objects=response.get('pipelineObjects')
        if not isinstance(objects,list) or not objects or len(objects)>MAX_PAIRS:raise ValueError('pipeline_shape')
        for obj in objects:
            if not isinstance(obj,dict) or not isinstance(obj.get('id'),str) or not isinstance(obj.get('name'),str) or not isinstance(obj.get('fields'),list):raise ValueError('pipeline_object')
            for field in obj['fields']:
                if not isinstance(field,dict) or not isinstance(field.get('key'),str) or ('stringValue' in field)==('refValue' in field):raise ValueError('pipeline_field')
                if 'stringValue' in field:values.append((str(len(values))+':'+field['key'],field['stringValue']))
                elif not isinstance(field['refValue'],str):raise ValueError('pipeline_reference')
        for obj in response.get('parameterObjects',[]):
            if not isinstance(obj,dict) or not isinstance(obj.get('attributes'),list):raise ValueError('pipeline_parameters')
            for field in obj['attributes']:
                if not isinstance(field,dict):raise ValueError('pipeline_parameters')
                values.append((str(len(values))+':'+str(field.get('key')),field.get('stringValue')))
        for obj in response.get('parameterValues',[]):
            if not isinstance(obj,dict):raise ValueError('pipeline_parameters')
            values.append((str(len(values))+':'+str(obj.get('id')),obj.get('stringValue')))
        value=pairs(values)
    if isinstance(value,dict):
        if not value or not any(value.values()) or len(value)>MAX_PAIRS:raise ValueError('empty_literal_content')
        # Preserve multiline literal values (not JSON-escaped private keys).
        payload=b'\n\n'.join(key.encode('utf-8')+b'='+text.encode('utf-8') for key,text in value.items());count=len(value)
    else:
        if not isinstance(value,str) or not value.strip():raise ValueError('empty_literal_content')
        payload=value.encode('utf-8');count=1
    if not 1<=len(payload)<=MAX_CONTENT:raise ValueError('content_bound')
    return payload,count


def base(info,requests,locator):
    return {'schema':SCHEMA,'kind':KIND,'surface':info['surface'],'identity':info['id'],'scope':info['scope'],
        'account':info['account'],'region':info['region'],'partition':info['partition'],'version':info['version'],
        'capture':requests.configuration_content_metadata[KIND+'_capture'],'principal':None,
        'native_complete':False,'complete':False,'verification':'not_attempted','literal_count':0,'bytes':0,'response_bytes':0,
        'engines':[],'leaks':[],'requests':[],'status':'unavailable','selection_locator':info['id']}


def remember_matches(requests,values):
    # Raw matches exist only during the callback; retained union descriptors are
    # keyed HMACs plus lengths, including one common encoded layer.
    if len(values)>MAX_REDACTION_DESCRIPTORS or any(len(value)>MAX_REDACTION_VALUE for value in values):
        requests.configuration_content_redaction_overflow=True
        return
    patterns=set(values)
    for value in values:
        patterns.add(json.dumps(value,ensure_ascii=True)[1:-1])
        for encoder in (base64.b64encode,base64.urlsafe_b64encode):
            encoded=encoder(value.encode()).decode();patterns.update((encoded,encoded.rstrip('=')))
    with requests._lock:
        descriptors=requests.configuration_content_redactions
        for text in patterns:
            if text:descriptors.setdefault(len(text),set()).add(_fingerprint(text))
        if sum(len(v) for v in descriptors.values())>MAX_REDACTION_DESCRIPTORS:
            requests.configuration_content_redaction_overflow=True


# The context is collector-owned and never enters options, native envelopes or
# Requests' projected-response cache. Only this ECS producer enables deferral.
from contextvars import ContextVar
_DEFERRED_ECS = ContextVar('selected_ecs_content_phase', default=None)


def _complete_content(requests, info, marker, payload, native, *, timeout=None):
    """Original per-source parser, privacy callback and result bounds."""
    allowance=min(60,remaining(requests))
    if timeout is not None:allowance=min(allowance,timeout)
    outcome=scan_with_source(scan_content,payload,info['id']+'.content',
        timeout=allowance,
        _redact_values=lambda values:remember_matches(requests,values),
        source={'scope':info['scope'],'path':info['surface'],'location_kind':'configuration'},native=native)
    leaks=merge_leaks(outcome['leaks'])
    for leak in leaks:leak['locations']=[{'path':info['id']+'.content'}]
    if len(leaks)>MAX_LEAKS or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS:
        raise ValueError('findings_bound')
    marker.update(engines=deepcopy(outcome['engines']),leaks=leaks)
    remaining(requests)
    marker['complete']=outcome['complete'] is True


def _ecs_phase_remaining(requests):
    # Convert no new authority and create no fresh deadline. The worker's
    # inherited lease and any explicit Requests deadline only tighten the
    # existing selected-reader absolute deadline.
    from peaso.collection_lease import effective_deadline
    left=remaining(requests)
    deadline=effective_deadline(requests)
    if deadline is not None:left=min(left,deadline-time.monotonic())
    if left<=0:raise TimeoutError('ecs_phase_deadline')
    return left


class _DeferredEcsContent:
    """Bounded native admission, followed by one source-bound detector consumer.

    Native groups retain their existing call/response reservations. Committed
    groups gather once for at most one second, never once per subsequent group.
    Slow later reads cannot hold an earlier committed group indefinitely.
    """
    def __init__(self,requests,targets,session):
        from threading import Condition,Thread
        from collections import namedtuple
        if not 1<len(targets)<=2048:raise ValueError('ecs_phase_bound')
        self.requests=requests
        from .aws_request_pool import canonical_wrapper
        session_id=id(canonical_wrapper(requests,session))
        self.cache_keys={}
        for target in targets:
            service,operation,args=route(target)
            self.cache_keys[identity(target)]=(session_id,service,parse(target)[2],operation,
                json.dumps(opaque_arguments(args),sort_keys=True),PROFILE)
        self.bindings={identity(t):(t['scope'],tuple(sorted(target_source(t,
            path=parse(t)[0],location_kind='configuration').items())))for t in targets}
        if len(self.bindings)!=len(targets):
            raise ValueError('ecs_phase_identity')
        self.Job=namedtuple('_EcsContentJob','member payload native info marker source requests response_bytes')
        self.condition=Condition();self.jobs={};self.groups=[];self.completed={}
        self.response_bytes=self.payload_bytes=0
        self.done=False;self.stopped=False;self.running=False;self.gather_until=None
        self.thread=Thread(target=self._consume,name='ecs-content-preparation',daemon=False)
        self.thread.start()

    def enqueue(self,requests,info,marker,payload,native,response_bytes):
        ident=info['id'];binding=self.bindings.get(ident)
        if (getattr(requests,'_cache',None) is not self.requests._cache or binding is None
                or info['scope']!=binding[0] or type(payload)is not bytes
                or not 0<len(payload)<=MAX_CONTENT or type(response_bytes)is not int
                or not 0<response_bytes<=MAX_RESPONSE):raise ValueError('ecs_phase_identity')
        # Own a bounded copy, so a later mutation of the SDK response cannot
        # change this source's literal field bindings or native identity.
        owned=deepcopy(native)
        with self.condition:
            if self.stopped or self.done or ident in self.jobs or ident in self.completed:
                raise ValueError('ecs_phase_closed')
            while (self.response_bytes+response_bytes>16*1024*1024
                    or self.payload_bytes+len(payload)>16*1024*1024):
                # Only earlier committed native groups can fill the window:
                # one current read batch is bounded independently at 8 MiB.
                self.gather_until=time.monotonic()
                self.condition.notify_all()
                if (not self.groups and not self.running) or self.stopped:
                    raise ValueError('ecs_phase_bound')
                self.condition.wait(min(.1,_ecs_phase_remaining(requests)))
            self.response_bytes+=response_bytes;self.payload_bytes+=len(payload)
            self.jobs[ident]=self.Job(ident,payload,owned,tuple(sorted(info.items())),marker,binding[1],requests,response_bytes)

    def _matches(self,item,ident,expected):
        from .aws import _safe
        if not isinstance(item,dict)or item.get('id')!=ident:return False
        marker=item.get(MARKER)
        if not isinstance(marker,dict):return False
        immutable=lambda v:{k:x for k,x in v.items()if k not in {'complete','engines','leaks'}}
        expected=_safe(expected)
        return (immutable(marker)==immutable(expected)
            and item.get('_provenance')=={'scope':self.bindings[ident][0],
                'capture':expected['capture'],'selection_locator':ident})

    def _cached(self,ident):
        future=getattr(self.requests,'_cache',{}).get(self.cache_keys[ident])
        if future is None or not future.done()or future.exception()is not None:return None
        return future.result()

    def commit(self,targets,items):
        returned={item.get('id'):item for item in items if isinstance(item,dict)}
        with self.condition,self.requests._lock:
            group=[]
            for target in targets:
                ident=identity(target);job=self.jobs.get(ident)
                if job is None:continue
                cached=self._cached(ident)
                if self._matches(returned.get(ident),ident,job.marker)and self._matches(cached,ident,job.marker):
                    group.append(job)
                else:
                    # A failed safe projection or a changed binding never gains
                    # a successful result from the earlier native payload.
                    job.marker['complete']=False;job.native.clear();self.jobs.pop(ident,None)
                    self.response_bytes-=job.response_bytes;self.payload_bytes-=len(job.payload)
            if group:
                self.groups.append(tuple(group))
                if self.gather_until is None:self.gather_until=time.monotonic()+1.0
            self.condition.notify_all()

    def _finish(self,job):
        try:
            with source_context(**dict(job.source)):
                _complete_content(job.requests,dict(job.info),job.marker,job.payload,job.native,
                    timeout=_ecs_phase_remaining(job.requests))
        except Exception:
            job.marker['complete']=False
        finally:
            # Only safe projected metadata is retained after source consumption.
            with self.condition:
                self.completed[job.member]=deepcopy(job.marker)
                self.jobs.pop(job.member,None)
                self.response_bytes-=job.response_bytes;self.payload_bytes-=len(job.payload)
                self.condition.notify_all()
            job.native.clear()

    def _small(self,group):
        from peaso.secret_scanning_batch import prepared_content_batch
        try:
            timeout=min(30,*(_ecs_phase_remaining(j.requests) for j in group))
            with prepared_content_batch([(j.payload,j.member+'.content')for j in group],
                    timeout=timeout):
                for job in group:self._finish(job)
        except Exception:
            # An expired earlier native batch cannot poison later batches in
            # the same window. _finish checks each job's own lease again.
            for job in group:
                if job.member in self.jobs:self._finish(job)

    def _prepare(self,groups):
        from peaso import secret_scanning_batch as batch
        if len(groups)==1:
            self._small(groups[0]);return
        jobs=[]
        for group in groups:
            for job in group:
                try:_ecs_phase_remaining(job.requests)
                except Exception:self._finish(job)
                else:jobs.append(job)
        if not jobs:return
        if len(jobs)>2048 or sum(len(j.payload)for j in jobs)>16*1024*1024:
            raise ValueError('content_window_bound')
        prepared=None
        try:
            prepared=batch._prepare_trufflehog_batch(
                [(j.payload,j.member+'.content')for j in jobs],
                min(60,*(_ecs_phase_remaining(j.requests) for j in jobs)))
        except Exception:
            pass
        if prepared is None:
            # Dense output, unavailable preparation or scanner failure keeps
            # the original native batch boundaries and per-source fallback.
            for group in groups:
                live=[job for job in group if job.member in self.jobs]
                if live:self._small(live)
            return
        token=batch._PREPARED_BATCH.set(prepared)
        try:
            for job in jobs:self._finish(job)
        finally:
            batch._PREPARED_BATCH.reset(token)
            prepared.clear()

    def _consume(self):
        from peaso.runtime_metrics import span
        try:
            while True:
                with self.condition:
                    while not self.groups and not self.done:
                        with span('secret.trufflehog.ecs_queue_wait'):
                            self.requests.check_deadline()
                            self.condition.wait(.1)
                    if not self.groups:
                        if self.done:return
                        continue
                    self.requests.check_deadline()
                    left=max(.1,(self.requests.deadline-time.monotonic()) if self.requests.deadline else MAX_SECONDS)
                    gather_left=min(max(0,(self.gather_until or 0)-time.monotonic()),max(0,left-60))
                    if not self.done and gather_left>0:
                        with span('secret.trufflehog.ecs_queue_wait'):
                            self.condition.wait(min(left,gather_left))
                        continue
                    groups=self.groups;self.groups=[];self.gather_until=None;self.running=True
                try:self._prepare(groups)
                finally:
                    with self.condition:
                        self.running=False
                        self.condition.notify_all()
        except Exception:
            # Fixed incomplete markers only; no exception or raw traceback is
            # stored in a Future, cache, collection or diagnostic frame.
            pass
        finally:
            with self.condition:
                self.stopped=True
                for job in self.jobs.values():
                    job.marker['complete']=False;job.native.clear()
                self.jobs.clear();self.groups.clear();self.condition.notify_all()

    def close(self):
        with self.condition:self.done=True;self.condition.notify_all()
        # The original bounded tool/lease owns cancellation. Never return while
        # a background consumer could still mutate markers or private capture.
        self.thread.join()

    def apply(self,items):
        from .aws import _safe
        with self.requests._lock:
            for item in items:
                ident=item.get('id');marker=self.completed.get(ident)
                if marker is None:continue
                cached=self._cached(ident)
                # Reconcile the real Requests._safe copy, not a presumed alias
                # of the original projector dictionary. Only the exact scoped
                # profile Future and immutable native provenance may change.
                if not self._matches(item,ident,marker):
                    item[MARKER]['complete']=False
                    continue
                final=_safe({**item,MARKER:marker})
                if not self._matches(cached,ident,marker):
                    # Preserve positives bound to this returned native source,
                    # but never certify or overwrite a changed cache identity.
                    final[MARKER]['complete']=False
                else:
                    cached.clear();cached.update(deepcopy(final))
                item.clear();item.update(deepcopy(final))
        self.completed.clear()


def _defer_ecs_content(requests,targets,workers,session):
    """Enable only a full native ECS contract with ample original headroom."""
    if (workers<=1 or getattr(requests,'max_calls',None)is not None or not 1<len(targets)<=MAX_TARGETS
            or any(parse(t)[0]!='ecs_environment'for t in targets)):return None
    for target in targets:
        service,operation,args=route(target)
        info=requests.configuration_content_approved.get((service,operation,parse(target)[2],opaque_arguments(args)['request_locator']),{})
        if (info.get('id')!=identity(target) or info.get('scope')!=target['scope']
                or info.get('surface')!='ecs_environment' or info.get('ownership')is not False):return None
    try:
        from peaso.secret_scanning_batch import _volatile_shm_available
        if not _volatile_shm_available(MAX_TOTAL) or _ecs_phase_remaining(requests)<61:return None
        from peaso.secret_scanning import _trufflehog
        _trufflehog()
        return _DeferredEcsContent(requests,targets,session)
    except Exception:return None


def project_response(response,service,operation,arguments,*,request_context=None,region=None):
    validate_request(service,operation,arguments,request_context=request_context,region=region)
    requests,session=request_context;locator=opaque_arguments(arguments)['request_locator']
    info=deepcopy(requests.configuration_content_approved[(service,operation,region,locator)])
    marker=base(info,requests,locator);marker['principal']=requests.configuration_content_sessions[id(session)]['principal']
    try:
        remaining(requests);size=response_size(response)
        with requests._lock:
            state=requests.configuration_content_state;state['responses']+=1;state['bytes']+=size
            if state['responses']>MAX_CALLS or state['bytes']>MAX_TOTAL:raise ValueError('total_response_bound')
        if (not isinstance(response,dict) or set(response)&{'Error','_coverage','partial','Partial'}
                or any(response.get(field) not in (None,'') for field in ('NextToken','nextToken','nextMarker','NextMarker'))):raise ValueError('partial_native_response')
        meta=response.get('ResponseMetadata')
        if (not isinstance(meta,dict) or type(meta.get('HTTPStatusCode')) is not int or meta['HTTPStatusCode']!=200
                or not isinstance(meta.get('RequestId'),str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}',meta['RequestId'])):raise ValueError('native_read_provenance')
        receipt={'locator':locator,'service':service,'operation':operation,'method':'GET' if service in ('apigateway','amplify') else 'POST',
                 'http_status':200,'request_id':'configuration-response:'+_fingerprint(meta['RequestId'])}
        marker['requests']=[receipt];marker['response_bytes']=size
        if info['ownership']:
            row=response.get('Document');name=arguments['Name'].split(':document/',1)[1]
            if (not isinstance(row,dict) or row.get('Name')!=name or row.get('Owner')!=info['account'] or row.get('DocumentVersion')!=arguments['DocumentVersion'] or row.get('Status')!='Active'):raise ValueError('owned_document_authority')
            with requests._lock:requests.configuration_content_owned[info['id']]=deepcopy(receipt)
            marker.update(status='owned_document_metadata',native_complete=True)
        else:
            if info['surface']=='launch_configuration_userdata':
                # Reconstruct actual ARN from the native response and exact
                # approved selector hash; never invent a different read route.
                row=one(response,'LaunchConfigurations');candidate=row.get('LaunchConfigurationARN')
                selection={'surface':info['surface'],'scope':info['scope'],'resource_id':candidate}
                if identity(selection)!=info['id']:raise ValueError('launch_configuration_binding')
                info['expected_arn']=candidate
            payload,count=extract(response,service,operation,arguments,info)
            if info['surface']=='ssm_document':marker['requests'].insert(0,deepcopy(requests.configuration_content_owned[info['id']]))
            marker.update(native_complete=True,status='collected',literal_count=count,bytes=len(payload))
            deferred=_DEFERRED_ECS.get()
            if deferred is not None:
                deferred.enqueue(requests,info,marker,payload,response,size)
            else:
                _complete_content(requests,info,marker,payload,response)
            del payload
    except Exception as exc:
        marker['complete']=False
        if marker['status']=='unavailable':
            # Own ValueError codes are short identifiers; never keep provider text.
            code=str(exc) if type(exc) is ValueError else ''
            marker['reason']=code if re.fullmatch(r'[a-z][a-z_]{2,63}',code) else 'selected_configuration_read_unavailable'
    return {'id':info['id'],MARKER:marker,'_provenance':{'scope':info['scope'],'capture':marker['capture'],'selection_locator':info['id']}}


def _record_read_failure(requests,failure):
    """Finite aggregate diagnostics, never an exception message or payload."""
    from .aws import ReadFailure
    code=failure.code if isinstance(failure,ReadFailure)else None
    expired={'ExpiredToken','ExpiredTokenException','RequestExpired'}
    denied={'AccessDenied','AccessDeniedException','UnauthorizedOperation','ForbiddenException'}
    if code in expired:category='credential_expiry'
    elif code in denied:category='access_denied'
    elif code in {'selected_configuration_call_bound','call_limit'}:category='call_bound'
    elif code in {'intentional_scan_deadline','retry_wait_exceeds_deadline'}:category='local_deadline'
    else:
        now=time.monotonic()
        with requests._lock:
            state=requests.configuration_content_state
            deadlines=(state.get('deadline'),getattr(requests,'deadline',None))
            elapsed=any(type(value)in(int,float)and value<=now for value in deadlines)
            bounded=state['attempts']>=MAX_CALLS
        category='local_deadline'if elapsed else'call_bound'if bounded else'unknown_read_failure'
    exception=type(failure).__name__
    if exception not in {'ReadFailure','TimeoutError','ValueError','TypeError','KeyError'}:exception='OtherException'
    with requests._lock:
        metadata=requests.configuration_content_metadata
        counts=metadata.setdefault(KIND+'_read_failures',{})
        key=category+':'+exception
        counts[key]=counts.get(key,0)+1
        if code in expired:
            codes=metadata.setdefault(KIND+'_credential_expiry_codes',[])
            if code not in codes:codes.append(code);codes.sort()
    return code if code in expired else None


def collect_selected(requests,session,region,caller,options,scopes,*,deferred_window=None):
    from .aws import ReadResult
    targets=selected_targets(options,scopes)
    if not enabled(options):return ReadResult([],'not_collected',{'code':'selected_configuration_disabled'})
    account=caller.get('Account') if isinstance(caller,dict) else None;arn=caller.get('Arn') if isinstance(caller,dict) else None
    if not isinstance(account,str) or not re.fullmatch('[0-9]{12}',account) or not isinstance(arn,str):return ReadResult([],'unknown',{'code':'selected_configuration_caller_unbound'})
    m=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):(?:iam|sts)::'+account+r':.+',arn)
    if not m:return ReadResult([],'unknown',{'code':'selected_configuration_caller_unbound'})
    principal='configuration-principal:'+_fingerprint(arn+'\n'+str(caller.get('UserId')))
    with requests._lock:
        requests.configuration_content_sessions[id(session)]={'account':account,'partition':m[1],'principal':principal}
        requests.configuration_content_metadata[KIND+'_principals'][account]=principal
    from contextlib import nullcontext
    read_failures=[]
    def read(target, cohort=None, deferred=None):
        surface,selected_account,selected_region,partition,_=parse(target)
        service,operation,args=route(target);locator=opaque_arguments(args)['request_locator']
        info=requests.configuration_content_approved[(service,operation,region,locator)]
        member=info['id']+'.content'
        deferred_token=_DEFERRED_ECS.set(deferred)
        try:
            from peaso.secret_scanning_batch import prepared_content_member
            with prepared_content_member(cohort,member) if cohort is not None else nullcontext():
                with source_context(**target_source(target, path=surface, location_kind='configuration')):
                    if surface=='ssm_document':
                        own_service,own_operation,own_args=route(target,ownership=True)
                        owned=requests.call(session,own_service,region,own_operation,_metadata_profile=PROFILE,**own_args)
                        if owned[MARKER]['status']!='owned_document_metadata':raise ValueError('document_owner_unresolved')
                    item=requests.call(session,service,region,operation,_metadata_profile=PROFILE,**args)
        except Exception as exc:
            failure_code=_record_read_failure(requests,exc)
            with requests._lock:read_failures.append(failure_code)
            from .workload_environment_discovery import record_denial
            record_denial(requests, exc, info['id'], service, operation)
            marker=base(info,requests,locator);marker['principal']=principal
            item={'id':info['id'],MARKER:marker,'_provenance':{'scope':info['scope'],'capture':marker['capture'],'selection_locator':info['id']}}
        finally:
            _DEFERRED_ECS.reset(deferred_token)
            if cohort is not None:cohort.finish(member)
        return item

    selected=[target for target in targets if parse(target)[1:3]==(account,region)]
    items=[]
    workers=max(1,min(8,getattr(requests,'workers',1)))
    # Native response/call allowances are shared across regional invocations.
    # Serialize admission and serial reads without holding the SDK state lock
    # while worker projections account their actual responses.
    with requests._lock:
        admission=getattr(requests,'configuration_content_admission_lock',None)
        if admission is None:
            from threading import Lock
            admission=Lock()
            requests.configuration_content_admission_lock=admission

    deferred=None

    def collect_group(group):
        cohort=None
        if deferred is None and len(group)>1 and workers>1 and getattr(requests,'max_calls',None) is None:
            try:
                from peaso.secret_scanning_batch import _volatile_shm_available
                if _volatile_shm_available(MAX_CONTENT*len(group)):
                    remaining(requests)
                    from peaso.secret_scanning import _trufflehog
                    _trufflehog()
                    from peaso.secret_scanning_cohort import ContentCohort
                    cohort=ContentCohort([identity(target)+'.content' for target in group],
                        min(requests.configuration_content_state['deadline'],getattr(requests,'deadline',None) or requests.configuration_content_state['deadline']),
                        max_bytes=MAX_CONTENT*len(group),cancelled=getattr(requests,'cancel_event',None))
            except Exception:
                cohort=None
        if cohort is None and deferred is None:
            items.extend(read(target) for target in group)
            return
        try:
            from concurrent.futures import ThreadPoolExecutor
            pending=[];unsubmitted=[]
            try:pool=ThreadPoolExecutor(max_workers=min(workers,len(group)),thread_name_prefix='ecs-content')
            except RuntimeError:
                if cohort is not None:cohort.close()
                items.extend(read(target,deferred=deferred) for target in group)
                return
            with pool:
                for index,target in enumerate(group):
                    try:pending.append(pool.submit(read,target,cohort,deferred))
                    except RuntimeError:
                        unsubmitted=group[index:]
                        if cohort is not None:
                            for missing in unsubmitted:cohort.finish(identity(missing)+'.content')
                        break
                try:items.extend(future.result() for future in pending)
                except BaseException:
                    if cohort is not None:cohort.close()
                    raise
            items.extend(read(target,deferred=deferred) for target in unsubmitted)
        finally:
            if cohort is not None:cohort.close()
    try:
        deferred=deferred_window if deferred_window is not None else _defer_ecs_content(requests,selected,workers,session)
        # Keep other invocations from observing a cached safe-but-incomplete
        # marker until its source-bound consumer has joined.
        with admission if deferred is not None else nullcontext():
            cursor=0
            while cursor<len(selected):
                with nullcontext() if deferred is not None else admission:
                    width=1
                    if (workers>1 and getattr(requests,'max_calls',None) is None
                            and parse(selected[cursor])[0]=='ecs_environment'):
                        with requests._lock:
                            state=requests.configuration_content_state
                            allowance=min(8, workers,
                                max(0,(MAX_TOTAL-state['bytes'])//MAX_RESPONSE),
                                max(0,MAX_CALLS-state['responses']),
                                max(0,MAX_CALLS-state['attempts']))
                        while (width<allowance and cursor+width<len(selected)
                                and parse(selected[cursor+width])[0]=='ecs_environment'):
                            width+=1
                    group=selected[cursor:cursor+width]
                    cursor+=width
                    first=len(items)
                    collect_group(group)
                    if deferred is not None:deferred.commit(group,items[first:])
            if deferred is not None and deferred_window is None:
                deferred.close()
                deferred.apply(items)
    finally:
        if deferred is not None and deferred_window is None:deferred.close()
    if not items:return ReadResult([],'not_collected',{'code':'selected_configuration_scope_omitted'})
    if read_failures:
        error={'code':'selected_configuration_read_incomplete'}
        expired=sorted({code for code in read_failures if code is not None})
        if expired:error['additional_errors']=[{'code':code}for code in expired]
        return ReadResult(items,'partial',error)
    return ReadResult(items)


def finalize(requests,collections,metadata):
    """Redact the detected union without retaining raw values between reads.

    This is opt-in value redaction, not a change to generic security-key policy.
    On bounded-work exhaustion, opaque surrogates replace uninspected free text.
    """
    if requests.configuration_content_redaction_overflow:
        # There is no retained raw match set with which to finish redaction.
        # Withhold all affected projections and cached aliases, never a clean
        # result from metadata whose redaction could not be established.
        with requests._lock:
            # Consumers may hold a completed Future's mutable projection;
            # clearing cache entries alone cannot erase that earlier alias.
            for future in requests._cache.values():
                if not future.done():continue
                if future.exception() is None:
                    value=future.result()
                    if isinstance(value,dict):
                        value.clear();value['_coverage']={'content':{'status':'unknown','reason':'selected_configuration_redaction_bound'}}
                    elif isinstance(value,list):value.clear()
                else:
                    failure=future.exception()
                    if hasattr(failure,'code'):
                        failure.code='selected_configuration_redaction_bound';failure.args=(failure.code,)
            requests._cache.clear()
        withheld=[]
        for collection in collections:
            safe={k:deepcopy(collection[k]) for k in ('type','scope','service','account_id','region','global') if k in collection}
            safe.update(status='unknown',items=[],error={'code':'selected_configuration_redaction_bound'})
            withheld.append(safe)
        return withheld,{KIND+'_redaction_complete':False,'intentional_partial':True}
    descriptors=requests.configuration_content_redactions
    if not descriptors:return collections,metadata
    windows=0
    exhausted=False
    def text(value):
        nonlocal windows,exhausted
        if not isinstance(value,str):return value
        matches=[]
        for length,fingerprints in descriptors.items():
            if length>len(value):continue
            for start in range(len(value)-length+1):
                windows+=1
                if windows>MAX_REDACTION_WINDOWS:
                    exhausted=True
                    return 'configuration-redacted:'+_fingerprint(value)
                if _fingerprint(value[start:start+length]) in fingerprints:matches.append((start,start+length))
        if not matches:return value
        result=[];offset=0
        for start,end in sorted(matches):
            if start<offset:offset=max(offset,end);continue
            result.extend((value[offset:start],'[redacted]'));offset=end
        result.append(value[offset:]);return ''.join(result)
    def scrub(value):
        if isinstance(value,str):return text(value)
        if isinstance(value,(list,tuple)):
            rows=[scrub(v) for v in value];return tuple(rows) if isinstance(value,tuple) else rows
        if not isinstance(value,dict):return value
        result={};changed=[]
        for key,child in value.items():
            safe_key=text(key);safe_child=scrub(child);result[safe_key]=safe_child
            if key!='_coverage' and (safe_key!=key or safe_child!=child):changed.append(safe_key)
        if changed:
            coverage=result.get('_coverage');coverage=dict(coverage) if isinstance(coverage,dict) else {}
            coverage.update({key:{'status':'unknown','reason':'detected_secret_redacted'} for key in changed});result['_coverage']=coverage
        return result
    with requests._lock:
        for key,future in list(requests._cache.items()):
            safe_key=scrub(key)
            if future.done() and future.exception() is None:
                current=future.result();safe=scrub(current)
                if isinstance(current,dict):current.clear();current.update(safe)
                elif isinstance(current,list):current[:]=safe
            elif future.done():
                failure=future.exception()
                if hasattr(failure,'code') and text(failure.code)!=failure.code:
                    failure.code='detected_secret_metadata_withheld'
                    failure.args=(failure.code,)
            if safe_key!=key:
                # Do not forge a cache alias that could serve a different native
                # request; evict its already-scrubbed completed projection.
                requests._cache.pop(key,None)
    safe_collections,safe_metadata=scrub(collections),scrub(metadata)
    if exhausted:
        safe_metadata[KIND+'_redaction_complete']=False
        for collection in safe_collections:
            if collection.get('type')==KIND:
                collection.update(status='partial',error={'code':'selected_configuration_redaction_bound'})
    return safe_collections,safe_metadata
