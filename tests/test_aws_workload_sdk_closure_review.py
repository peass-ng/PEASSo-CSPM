"""Bounded workload SDK contracts; no live AWS, old fixtures, or fabricated snapshots."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import threading

import boto3
import pytest
from botocore.stub import Stubber
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
TD = f'arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/review:1'
CL = f'arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/review'
SVC = f'arn:aws:ecs:{REGION}:{ACCOUNT}:service/review/review'
FN = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:review'
EKS = f'arn:aws:eks:{REGION}:{ACCOUNT}:cluster/review'
CB = f'arn:aws:codebuild:{REGION}:{ACCOUNT}:project/review'
ROLE = f'arn:aws:iam::{ACCOUNT}:role/review'
CANARY = 'WORKLOAD_REVIEW_INERT_VALUE_20261019'


@pytest.fixture
def pipeline(monkeypatch):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    original_requests = aws.Requests
    def collect(kinds, responses):
        calls, clients, errors = [], {}, []
        # Botocore Stubber mutates the shared SDK client's event handlers.
        # Use the collector's actual concurrency option to serialize this
        # deterministic harness; max_workers is not a supported option.
        requests = original_requests({'retry_attempts': 1, 'service_concurrency': 1, 'max_calls': 400}, sleep=lambda _: None)
        requests.observed_at = NOW
        native = {('sts', 'get_caller_identity'): {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/review', 'UserId': 'inert'}, **responses}
        class Client:
            def __init__(self, service, region):
                self.service = service
                self.sdk = session.client(service, region_name=region)
                self.lock = threading.Lock()  # Stubber state is per client; collectors may use threads.
                self.meta = self.sdk.meta
            def can_paginate(self, operation):
                return self.sdk.can_paginate(operation)
            def get_paginator(self, operation):
                return self.sdk.get_paginator(operation)
            def __getattr__(self, operation):
                def call(**arguments):
                    calls.append((self.service, operation, deepcopy(arguments)))
                    response = native.get((self.service, operation))
                    if callable(response):
                        response = response(arguments)
                    with self.lock, Stubber(self.sdk) as stub:
                        try:
                            if response is None or isinstance(response, tuple):
                                stub.add_client_error(operation, service_error_code=response[0] if isinstance(response, tuple) else 'AccessDeniedException', expected_params=arguments)
                            else:
                                stub.add_response(operation, deepcopy(response), arguments)
                        except Exception as exc:
                            errors.append((self.service, operation, str(exc)))
                            raise
                        result = getattr(self.sdk, operation)(**arguments)
                        stub.assert_no_pending_responses()
                        return result
                return call
        def client(_session, service, region):
            if (service, region) not in clients:
                clients[service, region] = Client(service, region)
            return clients[service, region]
        requests.client = client
        monkeypatch.setattr(aws, 'Requests', lambda options: requests)
        monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'inert'))
        snapshot = aws.collect({'provider': 'aws', 'scopes': [SCOPE], 'options': {'regions': [REGION]}}, [kinds] if isinstance(kinds, str) else kinds)
        assert not errors, errors  # Collector must not disguise invalid SDK test input as denial.
        cached = [f.result() for f in requests._cache.values() if not f.exception()]
        assert CANARY not in str(snapshot) + str(cached)
        return snapshot, calls
    return collect


def verdict(snapshot, cid):
    # A retired duplicate id stays selectable but reports under its surviving check.
    from peaso.checks import resolve_check_id
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)['findings']
            if row['check_id'] == resolve_check_id(cid)]
    assert rows and len({r['status'] for r in rows}) == 1, rows
    return rows[0]['status']




def codebuild(**fields):
    row = {'name': 'review', 'arn': CB, 'environment': {'type': 'LINUX_CONTAINER', 'image': 'review', 'computeType': 'BUILD_GENERAL1_SMALL', 'privilegedMode': False, 'environmentVariables': []},
           'source': {'type': 'NO_SOURCE'}, 'artifacts': {'type': 'NO_ARTIFACTS'}, **fields}
    return {('codebuild', 'list_projects'): {'projects': ['review']},
            ('codebuild', 'batch_get_projects'): {'projects': [row]}}


def task(container=None, **fields):
    row = {'taskDefinitionArn': TD, 'family': 'review', 'revision': 1, 'status': 'ACTIVE', 'networkMode': 'awsvpc',
           'containerDefinitions': [container or {'name': 'app'}], **fields}
    return {('ecs', 'list_task_definitions'): {'taskDefinitionArns': [TD]}, ('ecs', 'describe_task_definition'): {'taskDefinition': row}}


def cluster(**fields):
    row = {'clusterArn': CL, 'clusterName': 'review', 'activeServicesCount': 1, 'registeredContainerInstancesCount': 1,
           'settings': [{'name': 'containerInsights', 'value': 'enabled'}], **fields}
    return {('ecs', 'list_clusters'): {'clusterArns': [CL]}, ('ecs', 'describe_clusters'): {'clusters': [row], 'failures': []},
            ('ecs', 'list_services'): {'serviceArns': []}}


def service(**fields):
    row = {'serviceArn': SVC, 'serviceName': 'review', 'clusterArn': CL, 'taskDefinition': TD,
           'networkConfiguration': {'awsvpcConfiguration': {'subnets': ['subnet-0123456789abcdef0'], 'assignPublicIp': 'DISABLED'}}, **fields}
    return {('ecs', 'list_clusters'): {'clusterArns': [CL]}, ('ecs', 'list_services'): {'serviceArns': [SVC]},
            ('ecs', 'describe_services'): {'services': [row], 'failures': []}}


def function(**fields):
    row = {'FunctionName': 'review', 'FunctionArn': FN, 'Role': ROLE, 'Runtime': 'python3.13', 'PackageType': 'Zip', **fields}
    return {('lambda', 'list_functions'): {'Functions': [row]}, ('lambda', 'get_function_configuration'): {**row, 'State': 'Active'}}


def eks(**fields):
    row = {'name': 'review', 'arn': EKS, 'version': '1.35', 'resourcesVpcConfig': {'endpointPublicAccess': False, 'securityGroupIds': []}, **fields}
    return {('eks', 'list_clusters'): {'clusters': ['review']}, ('eks', 'describe_cluster'): {'cluster': row}}


# Each tuple is derived from native consumer reads, not the existing fixture cases.
SCALARS = [
 ('codebuild_project', 'aws.b.codebuild.nonprivileged', 'environment', {'type':'LINUX_CONTAINER','image':'review','computeType':'BUILD_GENERAL1_SMALL','privilegedMode':False}, {'type':'LINUX_CONTAINER','image':'review','computeType':'BUILD_GENERAL1_SMALL','privilegedMode':True}),
 ('codebuild_project', 'aws.c2b.codebuild.project_private', 'projectVisibility', 'PRIVATE', 'PUBLIC_READ'),
 ('codebuild_project', 'aws.b.codebuild.logs_enabled', 'logsConfig', {'cloudWatchLogs':{'status':'ENABLED'}}, {'cloudWatchLogs':{'status':'DISABLED'}}),
 ('codebuild_project', 'aws.b.codebuild.s3_log_encryption', 'logsConfig', {'s3Logs':{'status':'ENABLED','encryptionDisabled':False}}, {'s3Logs':{'status':'ENABLED','encryptionDisabled':True}}),
 ('codebuild_project', 'aws.c2b.codebuild.s3_logs_encrypted_when_enabled', 'logsConfig', {'s3Logs':{'status':'ENABLED','encryptionDisabled':False}}, {'s3Logs':{'status':'ENABLED','encryptionDisabled':True}}),
 ('codebuild_project', 'aws.b.codebuild.artifact_encryption', 'artifacts', {'type':'S3','encryptionDisabled':False}, {'type':'S3','encryptionDisabled':True}),
 ('codebuild_project', 'aws.b.codebuild.s3_artifact_encryption', 'artifacts', {'type':'S3','encryptionDisabled':False}, {'type':'S3','encryptionDisabled':True}),
 ('lambda_function', 'aws.b.lambda.active_tracing', 'TracingConfig', {'Mode':'Active'}, {'Mode':'PassThrough'}),
 ('lambda_function', 'aws.b.lambda.insights_layer', 'Layers', [{'Arn':f'arn:aws:lambda:{REGION}:580247275435:layer:LambdaInsightsExtension:60'}], []),
 ('lambda_function', 'aws.cb.lambda.kms_key_configured', 'KMSKeyArn', f'arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111', ''),
 ('lambda_function', 'aws.c2b.lambda.runtime_not_obsolete', 'Runtime', 'python3.13', 'python2.7'),
 ('lambda_function', 'aws.cb.lambda.runtime_not_deprecated_list', 'Runtime', 'python3.13', 'python2.7'),
 ('lambda_function', 'aws.lambda.dead_letter_queue', 'DeadLetterConfig', {'TargetArn':f'arn:aws:sqs:{REGION}:{ACCOUNT}:review'}, {}),
 ('lambda_function', 'aws.lambda.vpc_configuration', 'VpcConfig', {'VpcId':'vpc-0123456789abcdef0'}, {}),
 ('ecs_cluster', 'aws.c2b.ecs.container_insights', 'settings', [{'name':'containerInsights','value':'enhanced'}], [{'name':'containerInsights','value':'disabled'}]),
 ('ecs_cluster', 'aws.c2b.ecs.container_insights_setting', 'settings', [{'name':'containerInsights','value':'enabled'}], []),
 ('ecs_cluster', 'aws.c2b.ecs.cluster_has_active_services', 'activeServicesCount', 1, 0),
 ('ecs_cluster', 'aws.htbp.ecs.exec_session_logging_not_disabled', 'configuration', {'executeCommandConfiguration':{'logging':'OVERRIDE'}}, {'executeCommandConfiguration':{'logging':'NONE'}}),
 ('ecs_service', 'aws.c2b.ecs.service_no_public_ip', 'networkConfiguration', {'awsvpcConfiguration':{'assignPublicIp':'DISABLED'}}, {'awsvpcConfiguration':{'assignPublicIp':'ENABLED'}}),
 ('ecs_service', 'aws.c2b.ecs.fargate_latest_platform', 'platformVersion', 'LATEST', '1.3.0'),
 ('eks_cluster', 'aws.b.eks.disable_public_endpoint', 'resourcesVpcConfig', {'endpointPublicAccess':False}, {'endpointPublicAccess':True,'publicAccessCidrs':['::/0']}),
 ('eks_cluster', 'aws.c2b.eks.single_security_group', 'resourcesVpcConfig', {'endpointPublicAccess':False,'securityGroupIds':['sg-01234567']}, {'endpointPublicAccess':False,'securityGroupIds':['sg-01234567','sg-12345678']}),
 ('eks_cluster', 'aws.c2b.eks.secrets_encryption_configured', 'encryptionConfig', [{'resources':['secrets'],'provider':{'keyArn':f'arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111'}}], []),
]
BUILDERS = {'codebuild_project':codebuild,'lambda_function':function,'ecs_cluster':cluster,'ecs_service':service,'eks_cluster':eks,'ecs_task_definition':task}


@pytest.mark.parametrize('kind,cid,field,good,bad', SCALARS, ids=[r[1] for r in SCALARS])
def test_native_scalar_positive_negative(pipeline, kind, cid, field, good, bad):
    for value, expected in [(good, 'PASS'), (bad, 'FAIL')]:
        fields = {field:deepcopy(value)}
        if kind == 'ecs_service' and field == 'networkConfiguration':
            fields[field]['awsvpcConfiguration']['subnets'] = ['subnet-0123456789abcdef0']
        if cid.endswith('fargate_latest_platform'):
            fields.update(launchType='FARGATE', platformFamily='Linux')
        if kind == 'ecs_service' and field == 'networkConfiguration':
            # The surviving awsvpc check joins the service to its task definition's network mode.
            snapshot, _ = pipeline(['ecs_service', 'ecs_task_definition'], {**task(), **BUILDERS[kind](**fields)})
        else:
            snapshot, _ = pipeline(kind, BUILDERS[kind](**fields))
        assert verdict(snapshot, cid) == expected


CONTAINERS = [
 ('aws.b.ecs.no_privileged_containers', {'privileged':False}, {'privileged':True}),
 ('aws.b.ecs.all_readonly_roots', {'readonlyRootFilesystem':True}, {'readonlyRootFilesystem':False}),
 ('aws.b.ecs.some_logging_configuration', {'logConfiguration':{'logDriver':'awslogs'}}, {}),
 ('aws.c2b.ecs.all_containers_logging', {'logConfiguration':{'logDriver':'awslogs'}}, {}),
 ('aws_g6_ecs_all_containers_logging', {'logConfiguration':{'logDriver':'awslogs'}}, {}),
 ('aws.c2b.ecs.logging_non_blocking', {'logConfiguration':{'logDriver':'awslogs','options':{'mode':'non-blocking'}}}, {'logConfiguration':{'logDriver':'awslogs','options':{'mode':'blocking'}}}),
 ('aws.b.ecs.declared_nonroot_users', {'user':'1000:1000'}, {'user':'0:1000'}),
 ('aws.b.ecs.host_network_nonprivileged', {'user':'1000','privileged':False}, {'user':'0','privileged':False}),
 ('aws.c2b.ecs.host_network_root_user', {'user':'1000'}, {'user':'root'}),
 ('aws.c2b.ecs.no_credential_named_env_vars', {'environment':[{'name':'LOG_LEVEL','value':CANARY}]}, {'environment':[{'name':'AWS_SECRET_ACCESS_KEY','value':CANARY}]}),
 ('aws_ecs_task_definition_credential_environment_names', {'environment':[{'name':'LOG_LEVEL','value':CANARY}]}, {'environment':[{'name':'AWS_SECRET_ACCESS_KEY','value':CANARY}]}),
]


@pytest.mark.parametrize('cid,good,bad', CONTAINERS, ids=[r[0] for r in CONTAINERS])
def test_native_container_positive_negative(pipeline, cid, good, bad):
    for fields, expected in [(good, 'PASS'), (bad, 'FAIL')]:
        snapshot, _ = pipeline('ecs_task_definition', task({'name':'app', **fields}, networkMode='host'))
        assert verdict(snapshot, cid) == expected


@pytest.mark.parametrize('mode,expected', [('task','PASS'),('host','FAIL')])
def test_native_pid_case(pipeline, mode, expected):
    snapshot,_ = pipeline('ecs_task_definition', task(pidMode=mode))
    assert verdict(snapshot,'aws.b.ecs.no_host_pid') == expected


@pytest.mark.parametrize('cid', ['aws.c2b.codebuild.buildspec_not_user_controlled','aws.c2b.codebuild.buildspec_not_yml_file'])
def test_buildspec_projection(pipeline,cid):
    for spec, expected in [('version: 0.2\nphases: {} # '+CANARY,'PASS'),('ci/review.yml','FAIL')]:
        snapshot,_ = pipeline('codebuild_project',codebuild(source={'type':'NO_SOURCE','buildspec':spec}))
        assert verdict(snapshot,cid) == expected


@pytest.mark.parametrize('kind,cid', [('lambda_function','aws.review.lambda.configuration_secret_indicators'),('codebuild_project','aws.review.codebuild_project.configuration_secret_indicators'),('ecs_task_definition','aws.review.ecs_task_definition.configuration_secret_indicators')])
def test_safe_config_values_and_identity(pipeline,kind,cid):
    for value, expected in [(CANARY,'PASS'),('-----BEGIN PRIVATE KEY-----\n'+CANARY+'\n-----END PRIVATE KEY-----','FAIL')]:
        if kind=='lambda_function': responses=function(Environment={'Variables':{'REVIEW':value}})
        elif kind=='codebuild_project': responses=codebuild(environment={'type':'LINUX_CONTAINER','image':'review','computeType':'BUILD_GENERAL1_SMALL','environmentVariables':[{'name':'REVIEW','value':value,'type':'PLAINTEXT'}]})
        else: responses=task({'name':'app','environment':[{'name':'REVIEW','value':value}]})
        snapshot,_=pipeline(kind,responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('kind,cid,operation,member,identity',[
 ('codebuild_project','aws.b.codebuild.nonprivileged','batch_get_projects','projects','arn'),
 ('lambda_function','aws.review.lambda.configuration_secret_indicators','get_function_configuration',None,'FunctionArn'),
 ('ecs_task_definition','aws.b.ecs.no_privileged_containers','describe_task_definition','taskDefinition','taskDefinitionArn'),
 ('ecs_cluster','aws.htbp.ecs.exec_session_logging_not_disabled','describe_clusters','clusters','clusterArn'),
 ('eks_cluster','aws.b.eks.disable_public_endpoint','describe_cluster','cluster','arn'),
])
@pytest.mark.parametrize('identity_case',['foreign','missing','malformed'])
@pytest.mark.parametrize('setting',['safe','unsafe'])
def test_detail_identity_must_bind(pipeline,kind,cid,operation,member,identity,identity_case,setting):
    responses=BUILDERS[kind]()
    svc={'codebuild_project':'codebuild','lambda_function':'lambda','eks_cluster':'eks'}.get(kind,'ecs')
    response=responses[svc,operation]
    row=response if member is None else response[member][0] if isinstance(response[member],list) else response[member]
    if setting=='unsafe':
        if kind=='codebuild_project': row['environment']['privilegedMode']=True
        elif kind=='ecs_task_definition': row['containerDefinitions'][0]['privileged']=True
        elif kind=='ecs_cluster': row['configuration']={'executeCommandConfiguration':{'logging':'NONE'}}
        elif kind=='eks_cluster': row['resourcesVpcConfig']={'endpointPublicAccess':True,'publicAccessCidrs':['0.0.0.0/0']}
        else: row['Environment']={'Variables':{'REVIEW':'-----BEGIN PRIVATE KEY-----\n'+CANARY+'\n-----END PRIVATE KEY-----'}}
    if identity_case=='missing': row.pop(identity)
    else: row[identity]=row[identity].replace(ACCOUNT,'999999999999') if identity_case=='foreign' else 'malformed'
    snapshot,_=pipeline(kind,responses)
    assert verdict(snapshot,cid)=='UNKNOWN'


@pytest.mark.parametrize('case',['foreign','missing','duplicate','failure'])
def test_service_batch_identity(pipeline,case):
    responses=service()
    detail=responses['ecs','describe_services']
    if case=='foreign': detail['services'][0]['serviceArn']=SVC.replace(ACCOUNT,'999999999999')
    elif case=='missing': detail['services']=[]
    elif case=='duplicate': detail['services'].append(deepcopy(detail['services'][0]))
    else: detail.update(services=[],failures=[{'arn':SVC,'reason':'ACCESS_DENIED'}])
    snapshot,_=pipeline('ecs_service',responses)
    assert verdict(snapshot,'aws.c2b.ecs.service_no_public_ip')=='UNKNOWN'


@pytest.mark.parametrize('case,expected',[('enabled','PASS'),('disabled','FAIL'),('absent','MANUAL'),('denied','UNKNOWN')])
def test_eks_native_addon_configuration(pipeline,case,expected):
    responses=eks()
    responses['eks','describe_addon']=('ResourceNotFoundException',) if case=='absent' else None if case=='denied' else {'addon':{'addonName':'vpc-cni','clusterName':'review','configurationValues':json.dumps({'enableNetworkPolicy':case=='enabled'})}}
    snapshot,_=pipeline('eks_cluster',responses)
    assert verdict(snapshot,'aws.c2b.eks.vpc_cni_network_policy')==expected


@pytest.mark.parametrize('kind,service_name,operation,key,rows',[
 ('codebuild_project','codebuild','list_projects','projects',['review']),
 ('lambda_function','lambda','list_functions','Functions',[{'FunctionName':'review','FunctionArn':FN}]),
 ('ecs_task_definition','ecs','list_task_definitions','taskDefinitionArns',[TD]),
 ('ecs_cluster','ecs','list_clusters','clusterArns',[CL]),
 ('eks_cluster','eks','list_clusters','clusters',['review']),
])
@pytest.mark.parametrize('last_page_denied',[False,True])
def test_native_pagination(pipeline,kind,service_name,operation,key,rows,last_page_denied):
    responses=BUILDERS[kind]()
    # Native CodeBuild/Lambda/ECS/EKS paginator casing differs.
    token='nextToken' if service_name in {'codebuild','ecs','eks'} else 'NextMarker'
    input_token='Marker' if service_name=='lambda' else 'nextToken'
    responses[service_name,operation]=lambda args: (None if last_page_denied else {key:['review2'] if service_name=='codebuild' else []}) if input_token in args else {key:rows,token:'page-two'}
    snapshot,calls=pipeline(kind,responses)
    envelopes=[x for x in snapshot['collections'] if x['type']==kind]
    assert len(envelopes)==1
    assert envelopes[0]['status']==('partial' if last_page_denied else 'collected')
    assert any(s==service_name and op==operation and args.get(input_token)=='page-two' for s,op,args in calls)


SELECTED = [('aws.b.codebuild.artifact_encryption', 'codebuild_project'), ('aws.b.codebuild.logs_enabled', 'codebuild_project'), ('aws.b.codebuild.nonprivileged', 'codebuild_project'), ('aws.b.codebuild.s3_artifact_encryption', 'codebuild_project'), ('aws.b.codebuild.s3_log_encryption', 'codebuild_project'), ('aws.b.ecs.all_readonly_roots', 'ecs_task_definition'), ('aws.b.ecs.declared_nonroot_users', 'ecs_task_definition'), ('aws.b.ecs.host_network_nonprivileged', 'ecs_task_definition'), ('aws.b.ecs.no_host_pid', 'ecs_task_definition'), ('aws.b.ecs.no_privileged_containers', 'ecs_task_definition'), ('aws.b.ecs.some_logging_configuration', 'ecs_task_definition'), ('aws.b.eks.disable_public_endpoint', 'eks_cluster'), ('aws.b.eks.no_default_vpc', 'eks_cluster'), ('aws.b.lambda.active_tracing', 'lambda_function'), ('aws.b.lambda.insights_layer', 'lambda_function'), ('aws.c2b.codebuild.buildspec_not_user_controlled', 'codebuild_project'), ('aws.c2b.codebuild.buildspec_not_yml_file', 'codebuild_project'), ('aws.c2b.codebuild.built_within_90_days', 'codebuild_project'), ('aws.c2b.codebuild.invoked_last_90_days', 'codebuild_project'), ('aws.c2b.codebuild.no_plaintext_sensitive_env_names', 'codebuild_project'), ('aws.c2b.codebuild.project_private', 'codebuild_project'), ('aws.c2b.codebuild.s3_logs_encrypted_when_enabled', 'codebuild_project'), ('aws.c2b.codebuild.source_repo_oauth', 'codebuild_project'), ('aws.c2b.codebuild.source_url_no_credentials', 'codebuild_project'), ('aws.c2b.codebuild.webhook_filters_anchored', 'codebuild_project'), ('aws.c2b.ecs.all_containers_logging', 'ecs_task_definition'), ('aws.c2b.ecs.awsvpc_service_no_public_ip', 'ecs_service'), ('aws.c2b.ecs.cluster_has_active_services', 'ecs_cluster'), ('aws.c2b.ecs.cluster_has_registered_instances', 'ecs_cluster'), ('aws.c2b.ecs.cluster_instance_volumes_encrypted', 'ecs_cluster'), ('aws.c2b.ecs.container_insights', 'ecs_cluster'), ('aws.c2b.ecs.container_insights_setting', 'ecs_cluster'), ('aws.c2b.ecs.container_instance_agents_connected', 'ecs_cluster'), ('aws.c2b.ecs.fargate_latest_platform', 'ecs_service'), ('aws.c2b.ecs.host_network_root_user', 'ecs_task_definition'), ('aws.c2b.ecs.logging_non_blocking', 'ecs_task_definition'), ('aws.c2b.ecs.no_credential_named_env_vars', 'ecs_task_definition'), ('aws.c2b.ecs.service_no_public_ip', 'ecs_service'), ('aws.c2b.eks.secrets_encryption_configured', 'eks_cluster'), ('aws.c2b.eks.single_security_group', 'eks_cluster'), ('aws.c2b.eks.vpc_cni_network_policy', 'eks_cluster'), ('aws.c2b.lambda.env_vars_cmk', 'lambda_function'), ('aws.c2b.lambda.invoke_cloudtrail_logged', 'lambda_function'), ('aws.c2b.lambda.no_cross_account_layers', 'lambda_function'), ('aws.c2b.lambda.policy_not_public', 'lambda_function'), ('aws.c2b.lambda.runtime_not_obsolete', 'lambda_function'), ('aws.c2b.lambda.url_cors_no_wildcard', 'lambda_function'), ('aws.cb.lambda.cloudtrail_data_events', 'lambda_function'), ('aws.cb.lambda.kms_key_configured', 'lambda_function'), ('aws.cb.lambda.logging_config_present', 'lambda_function'), ('aws.cb.lambda.policy_no_wildcard_allow', 'lambda_function'), ('aws.cb.lambda.policy_prohibit_public_access_perimeter', 'lambda_function'), ('aws.cb.lambda.runtime_not_deprecated_list', 'lambda_function'), ('aws.cb.lambda.vpc_multiple_az', 'lambda_function'), ('aws.htbp.ecs.exec_session_logging_not_disabled', 'ecs_cluster'), ('aws.htbp.ecs.no_sensitive_host_mounts', 'ecs_task_definition'), ('aws.lambda.dead_letter_queue', 'lambda_function'), ('aws.lambda.vpc_configuration', 'lambda_function'), ('aws.nist.codebuild_exact_aws_key_env_names', 'codebuild_project'), ('aws.pci.codebuild.aws_key_environment_vars', 'codebuild_project'), ('aws.review.codebuild_project.configuration_secret_indicators', 'codebuild_project'), ('aws.review.ecs_task_definition.configuration_secret_indicators', 'ecs_task_definition'), ('aws.review.eks.native_version_supported', 'eks_cluster'), ('aws.review.lambda.configuration_secret_indicators', 'lambda_function'), ('aws.review.lambda.execution_role_policy_admin_grants', 'lambda_function'), ('aws.review.lambda_function.package_content_secret_indicators', 'lambda_function'), ('aws_cis_lambda_config_recorded', 'lambda_function'), ('aws_cis_lambda_execution_role_exists', 'lambda_function'), ('aws_cis_lambda_execution_role_no_admin', 'lambda_function'), ('aws_cis_lambda_execution_role_unique', 'lambda_function'), ('aws_ecs_task_definition_credential_environment_names', 'ecs_task_definition'), ('aws_g6_ecs_all_containers_logging', 'ecs_task_definition'), ('aws_g6_ecs_fargate_storage_encryption', 'ecs_cluster'), ('aws_lambda_code_signing_configured', 'lambda_function')]


@pytest.mark.parametrize('kind', list(BUILDERS))
def test_denied_inventory_never_security_pass(pipeline, kind):
    snapshot,_ = pipeline(kind, {})
    for cid, target in SELECTED:
        if target == kind:
            assert verdict(snapshot,cid)=='DENIED'


@pytest.mark.parametrize('kind,service_name,operation,key',[
 ('lambda_function','lambda','list_functions','Functions'),
 ('ecs_task_definition','ecs','list_task_definitions','taskDefinitionArns'),
 ('ecs_cluster','ecs','list_clusters','clusterArns'),
 ('ecs_service','ecs','list_clusters','clusterArns'),
 ('eks_cluster','eks','list_clusters','clusters'),
])
def test_empty_inventory_is_not_pass(pipeline,kind,service_name,operation,key):
    snapshot,_=pipeline(kind,{(service_name,operation):{key:[]}})
    for cid,target in SELECTED:
        if target==kind:
            assert verdict(snapshot,cid)=='EMPTY'


@pytest.mark.parametrize('kind,cid,operation',[
 ('codebuild_project','aws.b.codebuild.nonprivileged',('codebuild','batch_get_projects')),
 ('lambda_function','aws.b.lambda.active_tracing',('lambda','get_function_configuration')),
 ('ecs_task_definition','aws.b.ecs.no_privileged_containers',('ecs','describe_task_definition')),
 ('ecs_cluster','aws.c2b.ecs.container_insights',('ecs','describe_clusters')),
 ('eks_cluster','aws.b.eks.disable_public_endpoint',('eks','describe_cluster')),
])
def test_denied_detail_never_security_pass(pipeline,kind,cid,operation):
    responses=BUILDERS[kind]();responses[operation]=None
    snapshot,_=pipeline(kind,responses)
    assert verdict(snapshot,cid)=='UNKNOWN'


@pytest.mark.parametrize('case',['not_found','empty','wrong_name','duplicate'])
def test_codebuild_incomplete_detail(pipeline,case):
    responses=codebuild()
    detail=responses['codebuild','batch_get_projects']
    if case in {'not_found','empty'}:
        detail['projects']=[]
        if case=='not_found':detail['projectsNotFound']=['review']
    elif case=='wrong_name':detail['projects'][0]['name']='other'
    else:detail['projects'].append(deepcopy(detail['projects'][0]))
    snapshot,_=pipeline('codebuild_project',responses)
    assert verdict(snapshot,'aws.b.codebuild.nonprivileged')=='UNKNOWN'


@pytest.mark.parametrize('cid', ['aws.c2b.codebuild.no_plaintext_sensitive_env_names','aws.nist.codebuild_exact_aws_key_env_names','aws.pci.codebuild.aws_key_environment_vars'])
def test_codebuild_native_env_names_case(pipeline,cid):
    for name,expected in [('LOG_LEVEL','PASS'),('AWS_SECRET_ACCESS_KEY','FAIL')]:
        responses=codebuild(environment={'type':'LINUX_CONTAINER','image':'review','computeType':'BUILD_GENERAL1_SMALL',
            'environmentVariables':[{'name':name,'value':CANARY,'type':'PLAINTEXT'}]})
        snapshot,_=pipeline('codebuild_project',responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('case,expected',[('^refs/heads/main$','PASS'),('refs/heads/main','FAIL')])
def test_codebuild_native_webhook_projection(pipeline,case,expected):
    snapshot,_=pipeline('codebuild_project',codebuild(webhook={'filterGroups':[[{'type':'HEAD_REF','pattern':case}]]}))
    assert verdict(snapshot,'aws.c2b.codebuild.webhook_filters_anchored')==expected


@pytest.mark.parametrize('case,expected',[('https://bitbucket.org/review/review.git','PASS'),('https://x-token-auth:'+CANARY+'@bitbucket.org/review/review.git','FAIL')])
def test_codebuild_source_url_redaction(pipeline,case,expected):
    snapshot,_=pipeline('codebuild_project',codebuild(source={'type':'BITBUCKET','location':case}))
    assert verdict(snapshot,'aws.c2b.codebuild.source_url_no_credentials')==expected


@pytest.mark.parametrize('auth,expected',[('OAUTH','PASS'),('PERSONAL_ACCESS_TOKEN','FAIL')])
def test_codebuild_oauth_native_join(pipeline,auth,expected):
    responses=codebuild(source={'type':'GITHUB','location':'https://github.com/review/review'})
    responses['codebuild','list_source_credentials']={'sourceCredentialsInfos':[{'arn':f'arn:aws:codebuild:{REGION}:{ACCOUNT}:token/github','serverType':'GITHUB','authType':auth}]}
    snapshot,_=pipeline(['codebuild_project','codebuild_source_credential'],responses)
    assert verdict(snapshot,'aws.c2b.codebuild.source_repo_oauth')==expected


@pytest.mark.parametrize('cid',['aws.c2b.codebuild.invoked_last_90_days','aws.c2b.codebuild.built_within_90_days'])
@pytest.mark.parametrize('state,expected',[('recent','PASS'),('old','FAIL'),('denied','UNKNOWN'),('missing','UNKNOWN')])
def test_codebuild_build_details(pipeline,cid,state,expected):
    build_id='review:11111111-2222-3333-4444-555555555555'
    responses=codebuild()
    responses['codebuild','list_builds_for_project']={'ids':[build_id]}
    responses['codebuild','batch_get_builds']=None if state=='denied' else {'builds':[]} if state=='missing' else {'builds':[{'id':build_id,'projectName':'review','buildStatus':'SUCCEEDED','endTime':NOW if state=='recent' else datetime(2025,1,1,tzinfo=timezone.utc)}]}
    snapshot,_=pipeline('codebuild_project',responses)
    assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('path,expected',[('/srv/review','PASS'),('/var/run/docker.sock','FAIL')])
def test_ecs_native_host_mounts(pipeline,path,expected):
    responses=task({'name':'app','mountPoints':[{'sourceVolume':'review','containerPath':'/review'}]},volumes=[{'name':'review','host':{'sourcePath':path}}])
    snapshot,_=pipeline('ecs_task_definition',responses)
    assert verdict(snapshot,'aws.htbp.ecs.no_sensitive_host_mounts')==expected


@pytest.mark.parametrize('cid',['aws.b.codebuild.s3_artifact_encryption','aws.c2b.codebuild.s3_logs_encrypted_when_enabled'])
def test_codebuild_native_nonapplicability(pipeline,cid):
    snapshot,_=pipeline('codebuild_project',codebuild())
    assert verdict(snapshot,cid)=='NOT_APPLICABLE'


@pytest.mark.parametrize('case,expected',[('nonempty','FAIL'),('omitted','PASS'),('denied','UNKNOWN')])
def test_lambda_environment_count_projection(pipeline,case,expected):
    responses=function()
    if case!='omitted':responses['lambda','get_function_configuration']['Environment']={'Variables':{'REVIEW':CANARY}}
    if case=='denied':responses['lambda','get_function_configuration']=None
    snapshot,_=pipeline('lambda_function',responses)
    # Empty environment is a positive no-environment branch, not a missing CMK violation.
    assert verdict(snapshot,'aws.c2b.lambda.env_vars_cmk')==expected


@pytest.mark.parametrize('cid',['aws.c2b.ecs.container_instance_agents_connected','aws.c2b.ecs.cluster_instance_volumes_encrypted'])
@pytest.mark.parametrize('case',['denied','empty','omitted_detail','foreign_detail'])
def test_ecs_missing_container_instance_join(pipeline,cid,case):
    ci=f'arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/review/11111111222233334444555555555555'
    responses=cluster()
    responses['ecs','list_container_instances']=None if case=='denied' else {'containerInstanceArns':[] if case=='empty' else [ci]}
    responses['ecs','describe_container_instances']={'containerInstances':[] if case=='omitted_detail' else [{'containerInstanceArn':ci.replace(ACCOUNT,'999999999999'),'ec2InstanceId':'i-0123456789abcdef0','status':'ACTIVE','agentConnected':True}]}
    responses['ec2','describe_instances']={'Reservations':[]}
    responses['ec2','describe_volumes']={'Volumes':[]}
    snapshot,_=pipeline(['ecs_cluster','ecs_container_instance','instance','ebs_volume'],responses)
    assert verdict(snapshot,cid)=='UNKNOWN'


@pytest.mark.parametrize('connected,expected',[(True,'PASS'),(False,'FAIL')])
def test_ecs_container_instance_agent_native_join(pipeline,connected,expected):
    ci=f'arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/review/11111111222233334444555555555555'
    responses=cluster()
    responses['ecs','list_container_instances']={'containerInstanceArns':[ci]}
    responses['ecs','describe_container_instances']={'containerInstances':[{'containerInstanceArn':ci,'status':'ACTIVE','agentConnected':connected}]}
    snapshot,_=pipeline(['ecs_cluster','ecs_container_instance'],responses)
    assert verdict(snapshot,'aws.c2b.ecs.container_instance_agents_connected')==expected


@pytest.mark.parametrize('default,expected',[(False,'PASS'),(True,'FAIL'),(None,'UNKNOWN')])
def test_eks_default_vpc_native_join(pipeline,default,expected):
    vpc='vpc-0123456789abcdef0'
    responses=eks(resourcesVpcConfig={'vpcId':vpc})
    responses['ec2','describe_vpcs']=None if default is None else {'Vpcs':[{'VpcId':vpc,'IsDefault':default}]}
    snapshot,_=pipeline(['eks_cluster','vpc'],responses)
    assert verdict(snapshot,'aws.b.eks.no_default_vpc')==expected


@pytest.mark.parametrize('cid,field,good,bad',[
 ('aws.c2b.ecs.awsvpc_service_no_public_ip','assignPublicIp','DISABLED','ENABLED'),
])
def test_ecs_service_task_network_native_join(pipeline,cid,field,good,bad):
    for value,expected in [(good,'PASS'),(bad,'FAIL')]:
        responses={**task(),**service(networkConfiguration={'awsvpcConfiguration':{'subnets':['subnet-0123456789abcdef0'],field:value}})}
        snapshot,_=pipeline(['ecs_service','ecs_task_definition'],responses)
        assert verdict(snapshot,cid)==expected


@pytest.mark.parametrize('account,expected',[(ACCOUNT,'PASS'),('999999999999','FAIL')])
def test_lambda_layer_native_account(pipeline,account,expected):
    snapshot,_=pipeline('lambda_function',function(Layers=[{'Arn':f'arn:aws:lambda:{REGION}:{account}:layer:review:1'}]))
    assert verdict(snapshot,'aws.c2b.lambda.no_cross_account_layers')==expected


@pytest.mark.parametrize('case,expected',[('json','PASS'),('absent','UNKNOWN')])
def test_lambda_logging_native_member(pipeline,case,expected):
    snapshot,_=pipeline('lambda_function',function(**({'LoggingConfig':{'LogFormat':'JSON'}} if case=='json' else {})))
    assert verdict(snapshot,'aws.cb.lambda.logging_config_present')==expected


@pytest.mark.parametrize('case,expected',[('specific','PASS'),('wildcard','FAIL'),('absent','NOT_APPLICABLE'),('denied','UNKNOWN')])
def test_lambda_url_native_cors(pipeline,case,expected):
    responses=function()
    responses['lambda','get_function_url_config']=('ResourceNotFoundException',) if case=='absent' else None if case=='denied' else {
        'FunctionUrl':'https://review.lambda-url.us-east-1.on.aws/','FunctionArn':FN,'CreationTime':'2026-10-01T00:00:00Z','LastModifiedTime':'2026-10-01T00:00:00Z','AuthType':'AWS_IAM',
        'Cors':{'AllowOrigins':['*'] if case=='wildcard' else ['https://example.test']}}
    snapshot,_=pipeline('lambda_function',responses)
    assert verdict(snapshot,'aws.c2b.lambda.url_cors_no_wildcard')==expected


@pytest.mark.parametrize('case,expected',[('enforce','PASS'),('warn','FAIL'),('absent','FAIL'),('foreign_function','UNKNOWN'),('foreign_config','UNKNOWN'),('denied','UNKNOWN')])
def test_lambda_signing_native_function_name(pipeline,case,expected):
    config_arn=f'arn:aws:lambda:{REGION}:{ACCOUNT}:code-signing-config:csc-11111111111111111'
    responses=function()
    attachment={'FunctionName':'other' if case=='foreign_function' else 'review','CodeSigningConfigArn':''}
    if case!='absent':attachment['CodeSigningConfigArn']=config_arn
    responses['lambda','get_function_code_signing_config']=None if case=='denied' else attachment
    responses['lambda','get_code_signing_config']={'CodeSigningConfig':{'CodeSigningConfigId':'csc-11111111111111111',
        'CodeSigningConfigArn':config_arn.replace(ACCOUNT,'999999999999') if case=='foreign_config' else config_arn,
        'AllowedPublishers':{'SigningProfileVersionArns':[f'arn:aws:signer:{REGION}:{ACCOUNT}:/signing-profiles/review/1111111111']},
        'CodeSigningPolicies':{'UntrustedArtifactOnDeployment':'Warn' if case=='warn' else 'Enforce'},'LastModified':'2026-10-01T00:00:00Z'}}
    snapshot,_=pipeline('lambda_function',responses)
    assert verdict(snapshot,'aws_lambda_code_signing_configured')==expected


@pytest.mark.parametrize('setting',[True,False])
@pytest.mark.parametrize('identity_case',['foreign_cluster','foreign_addon','missing_cluster'])
def test_eks_addon_detail_subject_identity(pipeline,setting,identity_case):
    responses=eks()
    addon={'clusterName':'review','addonName':'vpc-cni','configurationValues':json.dumps({'enableNetworkPolicy':setting})}
    if identity_case=='foreign_cluster':addon['clusterName']='other'
    elif identity_case=='foreign_addon':addon['addonName']='coredns'
    else:addon.pop('clusterName')
    responses['eks','describe_addon']={'addon':addon}
    snapshot,_=pipeline('eks_cluster',responses)
    assert verdict(snapshot,'aws.c2b.eks.vpc_cni_network_policy')=='UNKNOWN'


@pytest.mark.parametrize('encrypted,expected',[(True,'PASS'),(False,'FAIL')])
def test_ecs_volume_encryption_native_join(pipeline,encrypted,expected):
    ci=f'arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/review/11111111222233334444555555555555'
    instance_id,volume_id='i-0123456789abcdef0','vol-0123456789abcdef0'
    responses=cluster()
    responses['ecs','list_container_instances']={'containerInstanceArns':[ci]}
    responses['ecs','describe_container_instances']={'containerInstances':[{'containerInstanceArn':ci,'ec2InstanceId':instance_id,'status':'ACTIVE','agentConnected':True}]}
    responses['ec2','describe_instances']={'Reservations':[{'Instances':[{'InstanceId':instance_id,'BlockDeviceMappings':[{'DeviceName':'/dev/xvda','Ebs':{'VolumeId':volume_id}}]}]}]}
    responses['ec2','describe_volumes']={'Volumes':[{'VolumeId':volume_id,'Encrypted':encrypted}]}
    snapshot,_=pipeline(['ecs_cluster','ecs_container_instance','instance','ebs_volume'],responses)
    assert verdict(snapshot,'aws.c2b.ecs.cluster_instance_volumes_encrypted')==expected


@pytest.mark.parametrize('cid',['aws.c2b.ecs.container_instance_agents_connected','aws.c2b.ecs.cluster_instance_volumes_encrypted'])
def test_ecs_zero_registered_instances_nonapplicable(pipeline,cid):
    snapshot,_=pipeline('ecs_cluster',cluster(registeredContainerInstancesCount=0))
    assert verdict(snapshot,cid)=='NOT_APPLICABLE'
