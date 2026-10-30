"""Missing exact15 contracts over inert SDK responses and registered public evaluators."""
from copy import deepcopy
from datetime import datetime, timezone
import json

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
    def collect(kinds, responses, *, account_wide=False):
        calls, clients, errors = [], {}, []
        requests = original_requests({'retry_attempts': 1, 'service_concurrency': 1, 'max_calls': 400}, sleep=lambda _: None)
        # Stubber installs mutable handlers on each shared SDK client. Keep
        # these contract fixtures serial using the collector's actual option.
        assert requests.workers == 1
        requests.observed_at = NOW
        native = {('sts', 'get_caller_identity'): {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/review', 'UserId': 'inert'}, **responses}
        class Client:
            def __init__(self, service, region):
                self.service = service
                self.sdk = session.client(service, region_name=region)
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
                    with Stubber(self.sdk) as stub:
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
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT if account_wide else SCOPE], 'options': {} if account_wide else {'regions': [REGION]}}, [kinds] if isinstance(kinds, str) else kinds)
        assert not errors, errors  # Collector must not disguise invalid SDK test input as denial.
        cached = [f.result() for f in requests._cache.values() if not f.exception()]
        assert CANARY not in str(snapshot) + str(cached)
        return snapshot, calls
    return collect


def verdict(snapshot, cid):
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid], include_not_applicable=True)['findings'] if row['check_id'] == cid]
    resources = [row for row in rows if not row['resource_id'].startswith('inventory:')]
    rows = resources or rows
    assert rows and len({r['status'] for r in rows}) == 1, rows
    return rows[0]['status']




from test_aws_workload_sdk_closure_review import function, cluster, service, task, eks
from pathlib import Path


@pytest.mark.parametrize('count,launch,expected', [
    (1,'EC2','PASS'), (0,'EC2','FAIL'), (0,'FARGATE','NOT_APPLICABLE'), (0,None,'UNKNOWN')])
def test_registered_ecs_capacity(pipeline,count,launch,expected):
    responses={**service(desiredCount=1, **({'launchType':launch} if launch else {})),
               **cluster(registeredContainerInstancesCount=count)}
    responses['ecs','list_services']={'serviceArns':[SVC]}
    responses['ecs','list_tasks']={'taskArns':[]}
    snapshot,_=pipeline(['ecs_cluster','ecs_service','ecs_task'],responses)
    assert verdict(snapshot,'aws.c2b.ecs.cluster_has_registered_instances')==expected


@pytest.mark.parametrize('case,expected',[('two','PASS'),('one','FAIL'),('missing','UNKNOWN'),('denied','UNKNOWN'),('none','NOT_APPLICABLE')])
def test_lambda_native_subnet_join(pipeline,case,expected):
    ids=['subnet-0123456789abcdef0','subnet-1123456789abcdef0']
    responses=function(VpcConfig={'VpcId':'vpc-0123456789abcdef0','SubnetIds':ids} if case!='none' else {'VpcId':'','SubnetIds':[]})
    responses['ec2','describe_subnets']=None if case=='denied' else {'Subnets': [
        {'SubnetId':sid,'AvailabilityZoneId':'use1-az1' if case=='one' else 'use1-az'+str(i+1)}
        for i,sid in enumerate(ids[:1] if case=='missing' else ids)]}
    snapshot,_=pipeline(['lambda_function','subnet'],responses)
    assert verdict(snapshot,'aws.cb.lambda.vpc_multiple_az')==expected


@pytest.mark.parametrize('case,expected',[('data','PASS'),('management','FAIL'),('denied','UNKNOWN')])
def test_prowler_native_trail_selector(pipeline,case,expected):
    arn=f'arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/review'
    responses=function()
    responses['cloudtrail','describe_trails']={'trailList':[{'Name':'review','TrailARN':arn,'HomeRegion':REGION}]}
    responses['cloudtrail','get_event_selectors']=None if case=='denied' else {'TrailARN':arn,'EventSelectors':[
        {'DataResources':[{'Type':'AWS::Lambda::Function' if case=='data' else 'AWS::S3::Object','Values':[FN]}]}]}
    snapshot,_=pipeline(['lambda_function','cloudtrail'],responses)
    assert verdict(snapshot,'aws.c2b.lambda.invoke_cloudtrail_logged')==expected


@pytest.mark.parametrize('status,expected',[('STANDARD_SUPPORT','PASS'),('EXTENDED_SUPPORT','PASS'),('UNSUPPORTED','FAIL'),('denied','UNKNOWN'),('missing','UNKNOWN')])
def test_eks_registered_native_catalog(pipeline,status,expected):
    responses=eks()
    responses['eks','describe_cluster_versions']=None if status=='denied' else {'clusterVersions':[] if status=='missing' else [
        {'clusterVersion':'1.35','versionStatus':status}]}
    snapshot,_=pipeline(['eks_cluster','eks_version_catalog'],responses)
    assert verdict(snapshot,'aws.review.eks.native_version_supported')==expected


def iam_response(admin=False):
    return {'RoleDetailList':[{'Arn':ROLE,'RoleName':'review','Path':'/','RoleId':'AROAREVIEW123456789',
        'CreateDate':NOW,'AssumeRolePolicyDocument':'{}','RolePolicyList':[{'PolicyName':'review',
        'PolicyDocument':json.dumps({'Statement':[{'Effect':'Allow','Action':'*' if admin else 'logs:CreateLogStream','Resource':'*'}]})}],
        'AttachedManagedPolicies':[]}], 'Policies':[], 'IsTruncated':False}


@pytest.mark.parametrize('case,expected',[('exists','PASS'),('absent','FAIL'),('denied','UNKNOWN')])
def test_lambda_registered_role_exists(pipeline,case,expected):
    responses=function()
    responses['iam','get_account_authorization_details']=None if case=='denied' else {'RoleDetailList':[],'IsTruncated':False} if case=='absent' else iam_response()
    snapshot,_=pipeline(['lambda_function','iam_role'],responses)
    assert verdict(snapshot,'aws_cis_lambda_execution_role_exists')==expected


@pytest.mark.parametrize('case,expected',[('narrow','PASS'),('admin','FAIL'),('denied','UNKNOWN')])
def test_lambda_registered_declared_admin(pipeline,case,expected):
    responses=function()
    responses['iam','get_account_authorization_details']=None if case=='denied' else iam_response(case=='admin')
    snapshot,_=pipeline(['lambda_function','iam_role','iam_policy'],responses)
    assert verdict(snapshot,'aws.review.lambda.execution_role_policy_admin_grants')==expected
    # Legacy check deliberately leaves custom all-action grants unresolved.
    assert verdict(snapshot,'aws_cis_lambda_execution_role_no_admin')==('UNKNOWN' if case in {'admin','denied'} else 'PASS')


@pytest.mark.parametrize('case,expected',[('unique','PASS'),('shared','FAIL'),('denied_regions','DENIED'),('inactive','NOT_APPLICABLE')])
def test_lambda_registered_account_role_usage(pipeline,case,expected):
    responses=function()
    responses['ec2','describe_regions']=None if case=='denied_regions' else {'Regions':[{'RegionName':REGION,'OptInStatus':'opt-in-not-required'}]}
    if case=='shared':
        row={**responses['lambda','list_functions']['Functions'][0],'FunctionName':'second','FunctionArn':FN+'2'}
        responses['lambda','list_functions']['Functions'].append(row)
        responses['lambda','get_function_configuration']=lambda args: {**row,'FunctionName':args['FunctionName'],
            'FunctionArn':FN if args['FunctionName']=='review' else FN+'2','State':'Active'}
    if case=='inactive':responses['lambda','get_function_configuration']['State']='Inactive'
    snapshot,_=pipeline('lambda_function',responses,account_wide=True)
    assert verdict(snapshot,'aws_cis_lambda_execution_role_unique')==expected


@pytest.mark.parametrize('encrypted,expected',[(True,'PASS'),(False,'FAIL'),(None,'UNKNOWN')])
def test_ecs_registered_native_managed_volume(pipeline,encrypted,expected):
    volume={'name':'data','managedEBSVolume':{'roleArn':ROLE,'encrypted':encrypted is True}}
    responses={**cluster(),**task(volumes=[{'name':'data','configuredAtLaunch':True}]),
               **service(deployments=[{'status':'PRIMARY','taskDefinition':TD,'volumeConfigurations':[volume]}])}
    if encrypted is None:responses['ecs','describe_services']=None
    responses['efs','describe_file_systems']={'FileSystems':[]}
    snapshot,_=pipeline(['ecs_cluster','ecs_service','ecs_task_definition','efs_file_system'],responses)
    assert verdict(snapshot,'aws_g6_ecs_fargate_storage_encryption')==expected


@pytest.mark.parametrize('case,expected',[('recording','PASS'),('stopped','FAIL'),('denied','UNKNOWN')])
def test_lambda_registered_config_recording(pipeline,case,expected):
    responses=function()
    responses['config','describe_configuration_recorders']={'ConfigurationRecorders':[{'name':'review','recordingGroup':{'allSupported':True}}]}
    responses['config','describe_configuration_recorder_status']=None if case=='denied' else {
        'ConfigurationRecordersStatus':[{'name':'review','recording':case!='stopped','lastStatus':'Success'}]}
    snapshot,_=pipeline(['lambda_function','config_recorder'],responses)
    assert verdict(snapshot,'aws_cis_lambda_config_recorded')==expected


@pytest.mark.parametrize('cid',['aws.c2b.lambda.policy_not_public','aws.cb.lambda.policy_no_wildcard_allow',
    'aws.cb.lambda.policy_prohibit_public_access_perimeter'])
@pytest.mark.parametrize('case,expected',[('private','PASS'),('public','FAIL'),('denied','UNKNOWN')])
def test_registered_lambda_policy(pipeline,cid,case,expected):
    responses=function()
    responses['lambda','get_policy']=None if case=='denied' else {'Policy':json.dumps({'Version':'2012-10-17',
        'Statement':[{'Effect':'Allow','Principal':'*' if case=='public' else {'AWS':f'arn:aws:iam::{ACCOUNT}:root'},
        'Action':'lambda:InvokeFunction','Resource':FN}]})}
    snapshot,_=pipeline('lambda_function',responses)
    assert verdict(snapshot,cid)==expected


def test_registered_lambda_content_default_is_unavailable(pipeline):
    snapshot,calls=pipeline('lambda_function',function())
    assert verdict(snapshot,'aws.review.lambda_function.package_content_secret_indicators')=='UNKNOWN'
    assert not any(service=='lambda' and operation=='get_function' for service,operation,args in calls)


def test_lambda_partial_inventory_retains_observed_duplicate(pipeline):
    responses=function()
    responses['ec2','describe_regions']={'Regions':[{'RegionName':REGION,'OptInStatus':'opt-in-not-required'}]}
    responses['lambda','list_functions']=lambda args: None if 'Marker' in args else {
        'Functions':[{'FunctionName':name,'FunctionArn':FN if name=='review' else FN+'2','Role':ROLE} for name in ['review','second']],
        'NextMarker':'next'}
    responses['lambda','get_function_configuration']=lambda args: {'FunctionName':args['FunctionName'],
        'FunctionArn':FN if args['FunctionName']=='review' else FN+'2','Role':ROLE,'State':'Active'}
    snapshot,_=pipeline('lambda_function',responses,account_wide=True)
    assert verdict(snapshot,'aws_cis_lambda_execution_role_unique')=='FAIL'
    assert next(row for row in snapshot['collections'] if row['type']=='lambda_function')['status']=='partial'


def test_lambda_legacy_exact_aws_admin_attachment(pipeline):
    responses=function()
    native=iam_response()
    native['RoleDetailList'][0]['AttachedManagedPolicies']=[{'PolicyName':'AdministratorAccess',
        'PolicyArn':'arn:aws:iam::aws:policy/AdministratorAccess'}]
    responses['iam','get_account_authorization_details']=native
    snapshot,_=pipeline(['lambda_function','iam_role','iam_policy'],responses)
    assert verdict(snapshot,'aws_cis_lambda_execution_role_no_admin')=='FAIL'
