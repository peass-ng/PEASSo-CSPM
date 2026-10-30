"""Offline SDK -> Requests -> public AWS collector -> registered predicate review.

Only this bounded 51-ID cohort is accounted. Successful branches and exact field
emission witnesses never certify unvisited branches or dependent inventories.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from scripts import audit_aws_native_contracts as native
from scripts import audit_aws_field_producers as fields
from tests.test_peaso_collectors_aws import sdk, ACCOUNT, REGION, IDENTITY
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'docs/aws-review/network-closure-review.json'
KINDS={'rest_api','rest_api_stage','cloudfront_distribution','vpc','subnet','network_acl'}
IDS={r['id'] for r in json.loads(BASE.read_text())['checks'] if r['kind'] in KINDS}
CHECKS={c.id:c for c in native.registry() if c.id in IDS}
assert IDS and len(IDS)==len(CHECKS)
SCOPE=ACCOUNT+'/'+REGION
ARN=f'arn:aws:cloudfront::{ACCOUNT}:distribution/E123'
CURRENT_REQUESTS=[]


@pytest.fixture(autouse=True)
def trace_read_requests(monkeypatch):
    CURRENT_REQUESTS.clear()
    original=aws.Requests.call
    def traced(self,session,service,region,operation,**arguments):
        assert operation.startswith(('get_','describe_','list_'))
        CURRENT_REQUESTS.append({'service':service,'region':region,'operation':operation,
            'argument_names':sorted(arguments)})
        return original(self,session,service,region,operation,**arguments)
    monkeypatch.setattr(aws.Requests,'call',traced)


def public(sdk,kinds):
    sdk[1]('sts').add_response('get_caller_identity',IDENTITY,{})
    return aws.collect({'provider':'aws','scopes':[ACCOUNT],'options':{'regions':[REGION],
        'retry_attempts':1,'service_concurrency':1}},kinds)


def decision(snapshot,cid,variant):
    findings=evaluate_snapshot(snapshot,checks=[cid])['findings']
    assert findings
    status=findings[0]['status']
    return status


def api_snapshot(sdk,variant='positive',cid=''):
    api=sdk[1]('apigateway')
    policy={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':'*','Action':'execute-api:Invoke','Resource':'*',
        **({} if variant=='negative' else {'Condition':{'StringEquals':{'aws:SourceAccount':ACCOUNT}}})}]}
    api.add_response('get_rest_apis',{'items':[{'id':'abc123','name':'review','endpointConfiguration':{'types':['REGIONAL']},
        **({} if variant=='policy_absent' else {'policy':json.dumps(policy).replace(chr(34),chr(92)+chr(34)) if variant=='policy_escaped' else json.dumps(policy)})}]}, {})
    api.add_response('get_stages',{'item':[]},{'restApiId':'abc123'})
    authorizers=[] if variant=='negative' else [{'id':'auth123','name':'review','type':'TOKEN'}]
    if variant=='missing_authorizer_id':authorizers=[{'type':'TOKEN'}]
    if variant=='duplicate_authorizer_id':authorizers*=2
    if variant=='denied':api.add_client_error('get_authorizers','UnauthorizedException',http_status_code=401,expected_params={'restApiId':'abc123'})
    else:api.add_response('get_authorizers',{'items':authorizers},{'restApiId':'abc123'})
    method={'httpMethod':'GET','authorizationType':'NONE' if variant=='negative' else 'AWS_IAM'}
    if variant!='negative':method['requestValidatorId']='valid123'
    if variant=='foreign_method':method['httpMethod']='POST'
    if variant=='denied':api.add_client_error('get_resources','UnauthorizedException',http_status_code=401,expected_params={'restApiId':'abc123','embed':['methods']})
    else:api.add_response('get_resources',{'items':[{'id':'res123','path':'/','resourceMethods':{'GET':method}}]}, {'restApiId':'abc123','embed':['methods']})
    return public(sdk,['rest_api'])

REST_IDS=sorted(cid for cid,c in CHECKS.items() if c.kind=='rest_api')
@pytest.mark.parametrize('cid',REST_IDS)
@pytest.mark.parametrize('variant',['positive','negative','denied'])
def test_rest_native_method_authorizer_policy_pipeline(sdk,cid,variant):
    snapshot=api_snapshot(sdk,variant,cid)
    status=decision(snapshot,cid,variant)
    # Parent GetRestApis policy is independent of unavailable child inventories.
    expected='FAIL' if variant=='negative' else 'PASS'
    if variant=='denied' and not cid.endswith('rest_api_policy_not_public'):expected='UNKNOWN'
    assert status==expected


@pytest.mark.parametrize('variant',['policy_absent','policy_escaped'])
def test_rest_policy_native_optional_and_escaped_string(sdk,variant):
    cid='aws.c2b.apigateway.rest_api_policy_not_public'
    assert decision(api_snapshot(sdk,variant),cid,variant)=='PASS'


@pytest.mark.parametrize('variant',['missing_authorizer_id','duplicate_authorizer_id'])
@pytest.mark.parametrize('cid',[c for c in REST_IDS if c.endswith(('rest_api_has_authorizer','public_rest_api_authorizer','authorizers_or_authorized_methods'))])
def test_authorizer_identity_required(sdk,cid,variant):
    assert decision(api_snapshot(sdk,variant),cid,variant)=='UNKNOWN'


def stage_snapshot(sdk,variant='positive',cid=''):
    api=sdk[1]('apigateway')
    api.add_response('get_rest_apis',{'items':[{'id':'abc123','name':'review'}]}, {})
    if variant=='denied':
        api.add_client_error('get_stages','UnauthorizedException',http_status_code=401,expected_params={'restApiId':'abc123'})
    else:
        settings={'*/*':{'loggingLevel':'INFO','cachingEnabled':True,'cacheDataEncrypted':True},
            '~1pets/GET':{'loggingLevel':'INFO','cachingEnabled':True,'cacheDataEncrypted':True}}
        if variant=='negative':
            for value in settings.values():value.update(loggingLevel='OFF',cacheDataEncrypted=False,cachingEnabled=True)
        stage={'stageName':'review','tracingEnabled':variant!='negative','cacheClusterEnabled':True,'cacheClusterStatus':'AVAILABLE',
            'deploymentId':'dep123','methodSettings':settings,'webAclArn':'acl' if variant!='negative' else ''}
        if variant not in {'missing_certificate','negative'}:stage['clientCertificateId']='cert123'
        if variant=='duplicate_alias':stage['methodSettings']['/*/*']={'loggingLevel':'OFF','cachingEnabled':True,'cacheDataEncrypted':False}
        if variant=='native_slash':stage['methodSettings']={('/*/*' if k=='*/*' else k.replace('~1','/')):v for k,v in settings.items()}
        if variant=='native_slash_root':stage['methodSettings']={'/*/*':settings['*/*'],'//GET':settings['~1pets/GET']}
        if variant=='encoded_root':stage['methodSettings']={'*/*':settings['*/*'],'~1/GET':settings['~1pets/GET']}
        if variant=='foreign_parent':stage['stageName']='other'
        api.add_response('get_stages',{'item':[stage]},{'restApiId':'abc123'})
        if cid=='aws_nist_apigateway_stage_cache_encryption_at_rest_enabled':
            api.add_response('get_deployment',{'id':'other123' if variant=='foreign_deployment' else 'dep123',
                'apiSummary':{'/pets':{'GET':{'authorizationType':'AWS_IAM','apiKeyRequired':False}}}},
                {'restApiId':'abc123','deploymentId':'dep123','embed':['apisummary']})
        if 'clientCertificateId' in stage:
            api.add_response('get_client_certificate',{'clientCertificateId':'foreign' if variant=='foreign_certificate' else 'cert123',
                'expirationDate':datetime(2030,1,1,tzinfo=timezone.utc)}, {'clientCertificateId':'cert123'})
    return public(sdk,['rest_api_stage',*(['rest_api_method'] if cid=='aws_nist_apigateway_stage_cache_encryption_at_rest_enabled' else [])])

STAGE_BASE=[c for c in CHECKS if c.startswith(('aws.b.apigateway.','aws.c2b.apigateway.stage_','aws.pci.apigateway.'))]
@pytest.mark.parametrize('cid',STAGE_BASE)
@pytest.mark.parametrize('variant',['positive','negative','denied'])
def test_stage_method_map_public_pipeline(sdk,cid,variant):
    status=decision(stage_snapshot(sdk,variant,cid),cid,variant)
    expected='PASS' if variant=='positive' else 'FAIL' if variant=='negative' else 'DENIED'
    # A wildcard-only logging/cache failure needs deployed-method binding; our
    # negative contains an explicit unsafe method override and must FAIL.
    assert status in ({'UNKNOWN','DENIED'} if variant=='denied' else {expected})

@pytest.mark.parametrize('cid',STAGE_BASE)
@pytest.mark.parametrize('variant',['native_slash','native_slash_root','encoded_root'])
def test_stage_native_slash_method_settings(sdk,cid,variant):
    assert decision(stage_snapshot(sdk,variant,cid),cid,variant)=='PASS'


@pytest.mark.parametrize('cid',['aws.b.apigateway.rest_execution_logging','aws.b.apigateway.wildcard_cache_encryption',
    'aws.pci.apigateway.all_methods_logging','aws.pci.apigateway.all_methods_cache_encrypted'])
def test_stage_conflicting_wildcard_aliases(sdk,cid):
    assert decision(stage_snapshot(sdk,'duplicate_alias',cid),cid,'duplicate_alias')=='UNKNOWN'


@pytest.mark.parametrize('variant',['positive','negative','foreign_certificate','denied'])
def test_stage_certificate_binding(sdk,variant):
    cid='aws_g6_api_stage_valid_client_certificate'
    observed=decision(stage_snapshot(sdk,variant),cid,variant)
    assert observed in ({'UNKNOWN','DENIED'} if variant=='denied' else {{'positive':'PASS','negative':'FAIL','foreign_certificate':'UNKNOWN'}[variant]})



@pytest.mark.parametrize('variant',['positive','negative','denied','foreign_deployment','native_slash'])
def test_deployed_method_stage_cache_join(sdk,variant):
    cid='aws_nist_apigateway_stage_cache_encryption_at_rest_enabled'
    observed=decision(stage_snapshot(sdk,variant,cid),cid,variant)
    assert observed in ({'UNKNOWN','DENIED'} if variant=='denied' else {'UNKNOWN'} if variant=='foreign_deployment' else {'FAIL'} if variant=='negative' else {'PASS'})


def cf_config():
    return {'CallerReference':'review','Comment':'','Enabled':True,
        'Origins':{'Quantity':1,'Items':[{'Id':'origin','DomainName':'origin.example.org',
            'CustomOriginConfig':{'HTTPPort':80,'HTTPSPort':443,'OriginProtocolPolicy':'https-only',
                'OriginSslProtocols':{'Quantity':1,'Items':['TLSv1.2']}}}]},
        'DefaultCacheBehavior':{'TargetOriginId':'origin','ViewerProtocolPolicy':'https-only','FieldLevelEncryptionId':'field'},
        'CacheBehaviors':{'Quantity':0},'DefaultRootObject':'index.html','WebACLId':'acl',
        'Logging':{'Enabled':True,'Bucket':'logs.s3.amazonaws.com','Prefix':'','IncludeCookies':False},
        'ViewerCertificate':{'ACMCertificateArn':f'arn:aws:acm:{REGION}:{ACCOUNT}:certificate/review',
            'Certificate':f'arn:aws:acm:{REGION}:{ACCOUNT}:certificate/review','SSLSupportMethod':'sni-only','MinimumProtocolVersion':'TLSv1.2_2021'},
        'Restrictions':{'GeoRestriction':{'RestrictionType':'whitelist','Quantity':1,'Items':['ES']}},'OriginGroups':{'Quantity':0}}


def cf_snapshot(sdk,variant='positive',cid=''):
    config=cf_config()
    if variant=='negative':
        if cid.endswith(('access_logging','logging_any')):config['Logging']['Enabled']=False
        elif cid.endswith('.sni'):config['ViewerCertificate']['SSLSupportMethod']='vip'
        elif cid.endswith('custom_acm_certificate'):config['ViewerCertificate']={'CloudFrontDefaultCertificate':True}
        elif cid.endswith('default_root_object'):config['DefaultRootObject']=''
        elif cid.endswith('field_level_encryption'):config['DefaultCacheBehavior']['FieldLevelEncryptionId']=''
        elif cid.endswith('waf_reference'):config['WebACLId']=''
        elif cid.endswith('geo_restrictions'):config['Restrictions']['GeoRestriction']={'RestrictionType':'none','Quantity':0}
        elif cid.endswith('origin_no_deprecated_ssl'):config['Origins']['Items'][0]['CustomOriginConfig']['OriginSslProtocols']['Items']=['TLSv1']
        elif cid.endswith('origin_traffic_encrypted'):config['Origins']['Items'][0]['CustomOriginConfig']['OriginProtocolPolicy']='http-only'
        elif cid.endswith('recommended_tls_policy'):config['ViewerCertificate']['MinimumProtocolVersion']='TLSv1'
    if cid.endswith('origin_group_metadata') and variant!='negative':
        config['OriginGroups']={'Quantity':1,'Items':[{'Id':'g','FailoverCriteria':{'StatusCodes':{'Quantity':1,'Items':[500]}},
            'Members':{'Quantity':2,'Items':[{'OriginId':'origin'},{'OriginId':'backup'}]}}]}
    if cid=='aws_cloudfront_origin_failover_configured' and variant!='negative':
        backup=deepcopy(config['Origins']['Items'][0]);backup['Id']='backup'
        config['Origins']={'Quantity':2,'Items':[config['Origins']['Items'][0],backup]}
        config['OriginGroups']={'Quantity':1,'Items':[{'Id':'g','FailoverCriteria':{'StatusCodes':{'Quantity':1,'Items':[500]}},
            'Members':{'Quantity':2,'Items':[{'OriginId':'origin'},{'OriginId':'backup'}]}}]}
    summary={'Id':'E123','ARN':ARN if variant!='foreign_account' else ARN.replace(ACCOUNT,'999999999999'),
        'Status':'Deployed','LastModifiedTime':datetime(2026,10,19,tzinfo=timezone.utc),'DomainName':'example.cloudfront.net',
        'Aliases':{'Quantity':0},'Origins':deepcopy(config['Origins']),'DefaultCacheBehavior':deepcopy(config['DefaultCacheBehavior']),
        'CacheBehaviors':{'Quantity':0},'CustomErrorResponses':{'Quantity':0},'Comment':'','PriceClass':'PriceClass_100','Enabled':True,
        'ViewerCertificate':deepcopy(config['ViewerCertificate']),'Restrictions':deepcopy(config['Restrictions']),
        'WebACLId':config['WebACLId'],'HttpVersion':'http2','IsIPV6Enabled':True,'Staging':False}
    cf=sdk[1]('cloudfront')
    cf.add_response('list_distributions',{'DistributionList':{'Marker':'','MaxItems':100,'Quantity':1,'IsTruncated':False,'Items':[summary]}},{})
    if variant=='denied':cf.add_client_error('get_distribution_config','AccessDenied',http_status_code=403,expected_params={'Id':'E123'})
    else:cf.add_response('get_distribution_config',{'DistributionConfig':config},{'Id':'E123'})
    sdk[1]('logs').add_response('describe_delivery_sources',{'deliverySources':[]},{})
    sdk[1]('logs').add_response('describe_deliveries',{'deliveries':[]},{})
    return public(sdk,['cloudfront_distribution'])

CF_BASE=sorted(c for c in CHECKS if CHECKS[c].kind=='cloudfront_distribution' and c not in {
    'aws.cb.shield.cloudfront_protected','aws.c2b.cloudfront.s3_origin_bucket_exists'})
@pytest.mark.parametrize('cid',CF_BASE)
@pytest.mark.parametrize('variant',['positive','negative','denied','foreign_account'])
def test_cloudfront_public_identity_and_config(sdk,cid,variant):
    status=decision(cf_snapshot(sdk,variant,cid),cid,variant)
    assert status==('PASS' if variant=='positive' else 'FAIL' if variant=='negative' else 'UNKNOWN')



EC2_KINDS={'vpc','subnet','network_acl','network_interface','route_table','vpc_endpoint','flow_log','dhcp_options'}
EC2_IDS=[cid for cid,c in CHECKS.items() if c.kind in {'vpc','subnet','network_acl'} and set(c.dependencies)<={c.kind,*EC2_KINDS}]

def native_projection(value,shape):
    if shape.type_name=='structure':return {k:native_projection(v,shape.members[k]) for k,v in value.items() if k in shape.members}
    if shape.type_name=='list':return [native_projection(v,shape.member) for v in value]
    if shape.type_name=='map':return {k:native_projection(v,shape.value) for k,v in value.items()}
    return value

@pytest.mark.parametrize('cid,variant',[(cid,variant) for cid in EC2_IDS for variant in ['positive','negative','denied','foreign_join'] if variant!='foreign_join' or CHECKS[cid].kind!='network_acl'])
def test_ec2_network_native_public_projection(sdk,cid,variant):
    c=CHECKS[cid];case=native.behavior_module().CASES[cid]
    state='fail' if variant=='negative' else 'pass'
    root=deepcopy(case[state]);index=case.get(state+'_index',case.get('case_indices',{}).get(state,case.get('index',{})))
    payload={c.kind:[root]}
    for kind in c.dependencies:
        if kind==c.kind:continue
        payload[kind]=[deepcopy(w['data']) for w in index.get(kind,[])]
    ec2=sdk[1]('ec2');models=fields.Models()
    for kind,rows in sorted(payload.items()):
        service,operation,expression=aws.SPECS[kind]
        assert service=='ec2' and '.' not in expression
        shape=models.output(service,operation).members[expression].member
        for row in rows:
            if 'OwnerId' in row:row['OwnerId']=ACCOUNT
            if variant=='foreign_join' and kind!=c.kind:
                if 'VpcId' in row:row['VpcId']='vpc-foreign'
                if 'SubnetId' in row:row['SubnetId']='subnet-foreign'
                if kind=='dhcp_options':row['OwnerId']='999999999999'
        if variant=='denied' and kind==c.kind:
            ec2.add_client_error(operation,'UnauthorizedOperation',http_status_code=403,expected_params={})
        else:ec2.add_response(operation,{expression:[native_projection(row,shape) for row in rows]}, {})
    observed=decision(public(sdk,list(payload)),cid,variant)
    expected='PASS' if variant=='positive' else case.get('fail_expect','FAIL')
    assert observed in ({'UNKNOWN','DENIED'} if variant=='denied' else {'UNKNOWN','FAIL','NOT_APPLICABLE'} if variant=='foreign_join' else {expected})
