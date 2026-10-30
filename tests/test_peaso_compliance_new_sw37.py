"""Isolated draft checks: signed metadata and conservative outcomes."""
import copy

import pytest
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw37 as sw

S='123456789012/us-east-1'

def index(kind, rows, *, extras=None, policy=None, created='2026-10-12T00:00:00Z'):
    allrows={kind:rows, **(extras or {})}
    result={'context':{'provider':'aws','scope':S,'policy_inputs':{'status':'collected','scope':S,**(policy or {})},'created_at':created},'collections':{}}
    for k,rr in allrows.items():
        scope=S.split('/')[0]+'/global' if k in sw.GLOBAL_KINDS else S
        result['collections'][k]=[{'type':k,'scope':scope,'status':'collected' if rr else 'empty','items':rr}]
        result[k]=[{'type':k,'scope':scope,'data':r} for r in rr]
    return result

def ev(cid,row,facts): return evaluate_check(cid,row,facts)[0]

@pytest.mark.parametrize('cid',list(sw.SPECS))
def test_every_check_rejects_missing_partial_and_foreign_scope(cid):
    kind=sw.SPECS[cid][0]
    row={}
    facts=index(kind,[row])
    assert ev(cid,row,facts)=='UNKNOWN'
    partial=copy.deepcopy(facts)
    partial['collections'][kind][0]['status']='partial'
    assert ev(cid,row,partial)=='UNKNOWN'
    foreign=copy.deepcopy(facts)
    foreign['context']['scope']='999999999999/us-east-1'
    assert ev(cid,row,foreign)=='UNKNOWN'
    malformed=copy.deepcopy(facts)
    malformed[kind][0]['data']='malformed'
    assert ev(cid,row,malformed)=='UNKNOWN'

def test_shield_protection_inventory_and_srt():
    cid='aws.pci.shield.protection_all_internet_resources'
    arn='arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/a/b'
    extras={'load_balancer':[{'Type':'application','Scheme':'internet-facing','LoadBalancerArn':arn}],
            'classic_load_balancer':[],'cloudfront_distribution':[],'elastic_ip':[]}
    facts=index('shield_protection',[],extras=extras)
    assert ev(cid,{},facts)=='FAIL'
    facts=index('shield_protection',[{'Id':'p','ResourceArn':arn}],extras=extras)
    assert ev(cid,{},facts)=='PASS'
    assert ev(cid,{},index('shield_protection',[],extras={**extras,'load_balancer':[]}))=='PASS'
    nlb=copy.deepcopy(extras);nlb['load_balancer'][0]['Type']='network'
    assert ev(cid,{},index('shield_protection',[],extras=nlb))=='PASS'
    broken=copy.deepcopy(facts); broken['collections']['elastic_ip'][0]['status']='partial'
    assert ev(cid,{},broken)=='UNKNOWN'
    broken=copy.deepcopy(facts);broken['load_balancer'][0]['data']['Scheme']=5
    assert ev(cid,{},broken)=='UNKNOWN'
    assert ev(cid,{},index('shield_protection',[]))=='UNKNOWN'
    srt='aws.pci.shield.srt_access'; p={'Id':'p','ResourceArn':arn}
    e={'shield_subscription':[{'SubscriptionState':'ACTIVE'}], 'shield_drt_access':[{'RoleArn':'arn:aws:iam::123456789012:role/DRT','LogBucketList':['logs']} ]}
    f=index('shield_protection',[p],extras=e,policy={'required_shield_log_buckets':['logs']})
    assert ev(srt,p,f)=='PASS'
    bad=copy.deepcopy(f);bad['shield_drt_access'][0]['data']['RoleArn']=''
    bad['collections']['shield_drt_access'][0]['items'][0]['RoleArn']=''
    assert ev(srt,p,bad)=='FAIL'
    assert ev(srt,p,index('shield_protection',[p],extras={'shield_subscription':[{'SubscriptionState':'INACTIVE'}]}))=='NOT_APPLICABLE'
    assert ev(srt,p,index('shield_protection',[p],extras={'shield_subscription':[{'SubscriptionState':'ACTIVE'}]}))=='UNKNOWN'
    bad=copy.deepcopy(f);bad['collections']['shield_drt_access'][0]['status']='partial'
    assert ev(srt,p,bad)=='UNKNOWN'

def test_api_stage_waf_and_cache():
    arn='arn:aws:apigateway:us-east-1::/restapis/abc/stages/prod'
    acl='arn:aws:wafv2:us-east-1:123456789012:regional/webacl/a/b'
    stage={'id':arn,'ParentApiId':'abc','stageName':'prod',
           '_provenance':{'source_operation':'get_stages','parent_api_id':'abc','read_only':True},
           'webAclArn':acl,'methodSettings':{'*/*':{'cachingEnabled':True,'cacheDataEncrypted':True},'~1x/GET':{'cachingEnabled':True,'cacheDataEncrypted':False}}}
    waf='aws_g6_api_stage_effective_waf_acl'
    extras={'stage_waf_association':[{'stageArn':arn,'webAclArn':acl}],'wafv2_web_acl':[{'ARN':acl}]}
    f=index('rest_api_stage',[stage],extras=extras)
    assert ev(waf,stage,f)=='PASS'
    bad=copy.deepcopy(f);bad['stage_waf_association'][0]['data']['webAclArn']=''
    assert ev(waf,stage,bad)=='FAIL'
    no_acl=copy.deepcopy(stage);del no_acl['webAclArn']
    assert ev(waf,no_acl,index('rest_api_stage',[no_acl],extras={'stage_waf_association':[{'stageArn':arn,'webAclArn':''}],'wafv2_web_acl':[]}))=='FAIL'
    assert ev(waf,stage,index('rest_api_stage',[stage]))=='UNKNOWN'
    bad=copy.deepcopy(f);bad['collections']['rest_api_stage'][0]['status']='partial'
    assert ev(waf,stage,bad)=='UNKNOWN'
    cache='aws_nist_apigateway_stage_cache_encryption_at_rest_enabled'
    methods={'rest_api_method':[{'stageArn':arn,'methodSettingKey':'~1x/GET'}]}
    assert ev(cache,stage,index('rest_api_stage',[stage],extras=methods))=='FAIL'
    good=copy.deepcopy(stage);good['methodSettings']['~1x/GET']['cacheDataEncrypted']=True
    assert ev(cache,good,index('rest_api_stage',[good],extras=methods))=='PASS'
    assert ev(cache,stage,index('rest_api_stage',[stage]))=='UNKNOWN'
    malformed=copy.deepcopy(stage);malformed['methodSettings']['~1x/GET']['cacheDataEncrypted']='yes'
    assert ev(cache,malformed,index('rest_api_stage',[malformed],extras=methods))=='UNKNOWN'

def test_organizations_delegation_and_scps():
    org={'id':'o-123','Organization':{'Id':'o-123','MasterAccountId':'123456789012'}}
    svc='aws_cis_organizations_integrated_services_delegated'
    extras={'organization_service_access':[{'EnabledServicePrincipals':[{'ServicePrincipal':'config.amazonaws.com'}]}],
            'organization_delegated_admin':[{'ServicePrincipal':'config.amazonaws.com','AccountId':'222222222222','Status':'ACTIVE'}]}
    p={'required_service_principals':['config.amazonaws.com']}
    assert ev(svc,org,index('organization',[org],extras=extras,policy=p))=='PASS'
    bad=copy.deepcopy(extras);bad['organization_delegated_admin']=[]
    assert ev(svc,org,index('organization',[org],extras=bad,policy=p))=='FAIL'
    assert ev(svc,org,index('organization',[org],policy=p))=='UNKNOWN'
    delegate='aws_cis_organizations_policy_management_delegated'
    stmt={'Effect':'Allow','Principal':{'AWS':'222222222222'},'Action':['organizations:CreatePolicy','organizations:UpdatePolicy','organizations:AttachPolicy'],'Resource':'*'}
    ext={'organization_resource_policy':[{'Content':{'Statement':[stmt]}}], 'organization_account':[{'Id':'222222222222','Status':'ACTIVE'}]}
    assert ev(delegate,org,index('organization',[org],extras=ext))=='PASS'
    bad=copy.deepcopy(ext);bad['organization_resource_policy'][0]['Content']['Statement']=[]
    assert ev(delegate,org,index('organization',[org],extras=bad))=='FAIL'
    assert ev(delegate,org,index('organization',[org]))=='UNKNOWN'
    acct='222222222222'; base={'organization_effective_scp':[{'AccountId':acct,'Policies':[]}]}
    allowed=['t3.micro']
    restrict='aws_organizations_restrict_ec2_instance_types'
    rp={'audited_account_ids':[acct],'allowed_instance_types':allowed}
    assert ev(restrict,org,index('organization',[org],extras=base,policy=rp))=='FAIL'
    deny={'Effect':'Deny','Action':['ec2:RunInstances'],'Resource':'*','Condition':{'StringNotEquals':{'ec2:InstanceType':allowed}}}
    protected={'organization_effective_scp':[{'AccountId':acct,'Policies':[{'Content':{'Statement':[deny]}}]}]}
    assert ev(restrict,org,index('organization',[org],extras=protected,policy=rp))=='PASS'
    ambiguous=copy.deepcopy(protected);ambiguous['organization_effective_scp'][0]['Policies'][0]['Content']['Statement'][0]['Condition']={'StringNotLike':{'ec2:InstanceType':['t3.*']}}
    assert ev(restrict,org,index('organization',[org],extras=ambiguous,policy=rp))=='UNKNOWN'
    assert ev(restrict,org,index('organization',[org],policy=rp))=='UNKNOWN'
    tamper='aws_organizations_security_service_tamper_scp'
    tp={'audited_account_ids':[acct],'approved_break_glass_principals':[]}
    assert ev(tamper,org,index('organization',[org],extras=base,policy=tp))=='FAIL'
    actions=['cloudtrail:*','config:*','guardduty:*','securityhub:*']
    tprotected={'organization_effective_scp':[{'AccountId':acct,'Policies':[{'Content':{'Statement':[{'Effect':'Deny','Action':actions,'Resource':'*'}]}}]}]}
    assert ev(tamper,org,index('organization',[org],extras=tprotected,policy=tp))=='PASS'
    narrower=copy.deepcopy(tprotected);narrower['organization_effective_scp'][0]['Policies'][0]['Content']['Statement'][0]['Action']=['cloudtrail:StopLogging']
    assert ev(tamper,org,index('organization',[org],extras=narrower,policy=tp))=='UNKNOWN'
    assert ev(tamper,org,index('organization',[org],policy=tp))=='UNKNOWN'

def test_iam_identity_predicates():
    arn='arn:aws:iam::123456789012:user/shared-admin'
    user={'Arn':arn,'UserName':'shared-admin','LoginProfile':{'collection_status':'collected'},'AccessKeys':{'collection_status':'empty','items':[]}}
    cid='aws.pci.iam.generic_user_ids'
    p={'shared_account_patterns':['shared-.*'],'approved_service_identity_ids':[]}
    assert ev(cid,user,index('iam_user',[user],policy=p))=='FAIL'
    assert ev(cid,user,index('iam_user',[user],policy={**p,'approved_service_identity_ids':['shared-admin']}))=='PASS'
    assert ev(cid,user,index('iam_user',[user],policy={**p,'approved_service_identity_ids':[arn]}))=='PASS'
    assert ev(cid,user,index('iam_user',[user]))=='UNKNOWN'
    bad=copy.deepcopy(user);bad['LoginProfile']['collection_status']='denied'
    assert ev(cid,bad,index('iam_user',[bad],policy=p))=='UNKNOWN'
    report={'user':'shared-admin','ReportGeneratedTime':'2026-10-12T00:00:00Z','password_enabled':'false','access_key_1_active':'false','access_key_2_active':'false',
        'user_creation_time':'2020-01-01T00:00:00Z','password_last_used':'N/A','access_key_1_last_used_date':'N/A','access_key_1_last_rotated':'2020-01-01T00:00:00Z','access_key_2_last_used_date':'N/A','access_key_2_last_rotated':'2020-01-01T00:00:00Z'}
    departed='aws_iam_departed_identity_disabled'; roster={'departure_roster':{'shared-admin':{'termination_deadline':'2026-10-01T00:00:00Z'}}}
    f=index('iam_user',[user],extras={'iam_credential_report':[report]},policy=roster)
    assert ev(departed,user,f)=='PASS'
    active=copy.deepcopy(report);active['password_enabled']='true'
    assert ev(departed,user,index('iam_user',[user],extras={'iam_credential_report':[active]},policy=roster))=='FAIL'
    assert ev(departed,user,index('iam_user',[user],extras={'iam_credential_report':[report]},policy={'departure_roster':{}}))=='NOT_APPLICABLE'
    assert ev(departed,user,index('iam_user',[user],policy=roster))=='UNKNOWN'
    inactive='aws_iam_inactive_accounts_disabled_after_policy_days'; ip={'inactivity_days':90,'approved_service_account_exclusions':[]}
    assert ev(inactive,user,index('iam_user',[user],extras={'iam_credential_report':[report]},policy=ip))=='PASS'
    assert ev(inactive,user,index('iam_user',[user],extras={'iam_credential_report':[active]},policy=ip))=='FAIL'
    assert ev(inactive,user,index('iam_user',[user],extras={'iam_credential_report':[report]},policy={**ip,'approved_service_account_exclusions':['shared-admin']}))=='NOT_APPLICABLE'
    assert ev(inactive,user,index('iam_user',[user],policy=ip))=='UNKNOWN'
    stale=copy.deepcopy(report);stale['ReportGeneratedTime']='2020-01-01T00:00:00Z'
    assert ev(inactive,user,index('iam_user',[user],extras={'iam_credential_report':[stale]},policy=ip))=='UNKNOWN'

def test_ec2_network_and_tenancy():
    instance={'InstanceId':'i-12345678','State':{'Name':'running'},'Placement':{'Tenancy':'dedicated'}}
    net={'InstanceId':'i-12345678','joins_complete':True,'direct_public_paths':[],'public_listener_target_paths':[]}
    ext={'ec2_effective_ingress':[net]}
    ids=['aws.nist.ec2_instance_effective_public_reachability','aws_fedramp_ec2_effective_public_exposure']
    for cid in ids:
        assert ev(cid,instance,index('ec2_instance',[instance],extras=ext))=='PASS'
        exposed=copy.deepcopy(net);exposed['direct_public_paths']=[{'address':'8.8.8.8','internet_route':True,'permitted_ingress':True}]
        assert ev(cid,instance,index('ec2_instance',[instance],extras={'ec2_effective_ingress':[exposed]}))=='FAIL'
        assert ev(cid,instance,index('ec2_instance',[instance]))=='UNKNOWN'
        malformed=copy.deepcopy(net);malformed['joins_complete']='yes'
        assert ev(cid,instance,index('ec2_instance',[instance],extras={'ec2_effective_ingress':[malformed]}))=='UNKNOWN'
    tenancy='aws_ec2_dedicated_tenancy_for_sensitive_workloads'; p={'scope_instance_ids':['i-12345678']}
    assert ev(tenancy,{},index('ec2_instance',[instance],policy=p))=='PASS'
    default=copy.deepcopy(instance);default['Placement']['Tenancy']='default'
    assert ev(tenancy,{},index('ec2_instance',[default],policy=p))=='FAIL'
    assert ev(tenancy,{},index('ec2_instance',[],policy=p))=='FAIL'
    assert ev(tenancy,{},index('ec2_instance',[instance],policy={'scope_instance_ids':[]}))=='NOT_APPLICABLE'
    assert ev(tenancy,{},index('ec2_instance',[instance]))=='UNKNOWN'

def test_ecs_plaintext_environment():
    cid='aws_nist_ecs_task_definition_container_environment_no_secret'
    task={'taskDefinitionArn':'arn:aws:ecs:us-east-1:123456789012:task-definition/a:1',
          'Definition':{'collection_status':'collected','taskDefinition':{'containerDefinitions':[{'name':'web','environment':[{'name':'MODE','value':'prod'}]}]}}}
    p={'approved_secret_values':['secret!'],'approved_sensitive_name_patterns':['.*PASSWORD.*']}
    assert ev(cid,task,index('ecs_task_definition',[task],policy=p))=='PASS'
    bad=copy.deepcopy(task);bad['Definition']['taskDefinition']['containerDefinitions'][0]['environment'][0]['value']='secret!'
    assert ev(cid,bad,index('ecs_task_definition',[bad],policy=p))=='FAIL'
    bad=copy.deepcopy(task);bad['Definition']['taskDefinition']['containerDefinitions'][0]['environment'][0]['name']='DB_PASSWORD'
    assert ev(cid,bad,index('ecs_task_definition',[bad],policy=p))=='FAIL'
    assert ev(cid,task,index('ecs_task_definition',[task]))=='UNKNOWN'
    bad=copy.deepcopy(task);del bad['Definition']['taskDefinition']['containerDefinitions'][0]['environment'][0]['value']
    assert ev(cid,bad,index('ecs_task_definition',[bad],policy=p))=='UNKNOWN'
    bad=copy.deepcopy(task);bad['Definition']['collection_status']='partial'
    assert ev(cid,bad,index('ecs_task_definition',[bad],policy=p))=='UNKNOWN'
