"""Isolated contract tests for signed AWS swarm slice 41."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks import compliance_new_sw41 as sw

SCOPE='123456789012/us-east-1'
GLOBAL='123456789012/global'
ACCOUNT='123456789012'


def index(kind,row,extra=None,params=None):
    context={'provider':'aws','scope':SCOPE,'metadata':{'parameters':params or {}}}
    collections={}; wrappers={}
    for k,rows in {kind:[row],**(extra or {})}.items():
        scope=GLOBAL if k=='iam_role' else SCOPE
        collections[k]=[{'type':k,'scope':scope,'status':'collected','items':rows}]
        wrappers[k]=[{'type':k,'scope':scope,'data':r} for r in rows]
    return {'context':context,'collections':collections,**wrappers}


def run(cid,row,idx):
    check=next(c for c in CHECKS if c.id==cid)
    return check.evaluate(row,idx)[0]


def sg(**fields):
    return {'GroupId':'sg-1','OwnerId':ACCOUNT,'IpPermissions':[],'IpPermissionsEgress':[],**fields}


def lam(**fields):
    return {'FunctionArn':f'arn:aws:lambda:us-east-1:{ACCOUNT}:function:fn','FunctionName':'fn',
            'Role':f'arn:aws:iam::{ACCOUNT}:role/r','PackageType':'Zip','Runtime':'python3.13',
            'Environment':{'Variables':{}},'Policy':{'collection_status':'empty','absent':True},**fields}


def role(**fields):
    return {'Arn':f'arn:aws:iam::{ACCOUNT}:role/r',**fields}


def kms(**fields):
    return {'KeyId':'key-1','KeyArn':f'arn:aws:kms:us-east-1:{ACCOUNT}:key/key-1',
            'Metadata':{'collection_status':'collected','KeyMetadata':{'KeyId':'key-1','Origin':'EXTERNAL','KeySpec':'RSA_2048','KeyUsage':'ENCRYPT_DECRYPT'}},
            'Policy':{'collection_status':'collected','Policy':{'Statement':[{'Effect':'Allow','Action':'kms:Decrypt','Condition':{'StringEquals':{'kms:RecipientAttestation:ImageSha384':'abc'}}}]}},**fields}


def emr(**fields):
    return {'Id':'j-1','ClusterArn':f'arn:aws:elasticmapreduce:us-east-1:{ACCOUNT}:cluster/j-1',
            'Status':{'State':'RUNNING'},'MasterInstances':{'collection_status':'collected','complete':True,
            'PrimaryEc2InstanceId':'i-1','items':[{'Ec2InstanceId':'i-1'}]},**fields}


def instance(**fields):
    return {'InstanceId':'i-1','State':{'Name':'running'},
            'NetworkInterfaces':[{'Association':{},'Ipv6Addresses':[]}],**fields}


def vpc(**fields): return {'VpcId':'vpc-1',**fields}


def test_kms_origin_pass_fail_na_and_unknown():
    cid='aws_kms_imported_key_origin_spec'; row=kms()
    assert run(cid,row,index('kms_key',row))=='PASS'
    bad=kms(Metadata={'collection_status':'collected','KeyMetadata':{'KeyId':'key-1','Origin':'EXTERNAL','KeySpec':'HMAC_256','KeyUsage':'GENERATE_VERIFY_MAC'}})
    assert run(cid,bad,index('kms_key',bad))=='FAIL'
    other=kms(Metadata={'collection_status':'collected','KeyMetadata':{'KeyId':'key-1','Origin':'AWS_KMS'}})
    assert run(cid,other,index('kms_key',other))=='NOT_APPLICABLE'
    for broken in (kms(Metadata={'collection_status':'denied'}),kms(Metadata={'collection_status':'collected','KeyMetadata':{'KeyId':'key-1','Origin':'EXTERNAL'}})):
        assert run(cid,broken,index('kms_key',broken))=='UNKNOWN'


def test_attestation_pass_fail_na_and_unknown():
    cid='aws_nitro_attestation_key_policy'; row=kms(); params={'nitro_enclave_key_arns':[row['KeyArn']]}
    assert run(cid,row,index('kms_key',row,params=params))=='PASS'
    bad=kms(Policy={'collection_status':'collected','Policy':{'Statement':[{'Effect':'Allow','Action':'kms:Decrypt'}]}})
    assert run(cid,bad,index('kms_key',bad,params=params))=='FAIL'
    assert run(cid,row,index('kms_key',row,params={'nitro_enclave_key_arns':[]}))=='NOT_APPLICABLE'
    assert run(cid,row,index('kms_key',row))=='UNKNOWN'
    optional=kms(Policy={'collection_status':'collected','Policy':{'Statement':[
        {'Effect':'Allow','Action':'kms:Decrypt','Condition':{
            'StringEqualsIfExists':{'kms:RecipientAttestation:ImageSha384':'abc'}}}]}})
    assert run(cid,optional,index('kms_key',optional,params=params))=='UNKNOWN'
    bad['Policy']={'collection_status':'denied'}
    assert run(cid,bad,index('kms_key',bad,params=params))=='UNKNOWN'


def test_config_recorder_pass_fail_unknown():
    cid='aws_cis_lambda_config_recorded'; row=lam()
    rec={'name':'default','recordingGroup':{'allSupported':True,'resourceTypes':[]},
         'Status':{'collection_status':'collected','ConfigurationRecordersStatus':[{'name':'default','recording':True}]}}
    assert run(cid,row,index('lambda_function',row,{'config_recorder':[rec]}))=='PASS'
    off=deepcopy(rec); off['Status']['ConfigurationRecordersStatus'][0]['recording']=False
    assert run(cid,row,index('lambda_function',row,{'config_recorder':[off]}))=='FAIL'
    excluded=deepcopy(rec)
    excluded['recordingGroup']['recordingStrategy']={'useOnly':'EXCLUSION_BY_RESOURCE_TYPES'}
    excluded['recordingGroup']['resourceTypes']=['AWS::Lambda::Function']
    assert run(cid,row,index('lambda_function',row,{'config_recorder':[excluded]}))=='FAIL'
    assert run(cid,row,index('lambda_function',row,{'config_recorder':[]}))=='FAIL'
    assert run(cid,row,index('lambda_function',row))=='UNKNOWN'
    off['Status']={'collection_status':'denied'}
    assert run(cid,row,index('lambda_function',row,{'config_recorder':[off]}))=='UNKNOWN'


def test_lambda_runtime_pass_fail_unknown():
    cid='aws_nist_lambda_function_use_latest_runtime'; row=lam()
    params={'required_runtime_by_language':{'python':['python3.13']}}
    assert run(cid,row,index('lambda_function',row,params=params))=='PASS'
    older=lam(Runtime='python3.12')
    assert run(cid,older,index('lambda_function',older,params=params))=='FAIL'
    assert run(cid,row,index('lambda_function',row))=='UNKNOWN'
    malformed=lam(Runtime=9)
    assert run(cid,malformed,index('lambda_function',malformed,params=params))=='UNKNOWN'
    image=lam(PackageType='Image')
    assert run(cid,image,index('lambda_function',image,params=params))=='UNKNOWN'


def test_lambda_trusted_accounts_pass_fail_unknown():
    cid='aws_cis_lambda_resource_policy_trusted_accounts'; params={'trusted_account_ids':[ACCOUNT]}
    row=lam(); assert run(cid,row,index('lambda_function',row,params=params))=='PASS'
    policy={'collection_status':'collected','Policy':{'Statement':[{'Effect':'Allow','Principal':{'AWS':'999999999999'},'Action':'lambda:InvokeFunction'}]}}
    bad=lam(Policy=policy)
    assert run(cid,bad,index('lambda_function',bad,params=params))=='FAIL'
    unrelated=lam(Policy={'collection_status':'collected','Policy':{'Statement':[
        {'Effect':'Allow','Principal':{'AWS':'999999999999'},'Action':'lambda:GetFunction'}]}})
    assert run(cid,unrelated,index('lambda_function',unrelated,params=params))=='PASS'
    conditioned=deepcopy(bad)
    conditioned['Policy']['Policy']['Statement'][0]['Condition']={'StringEquals':{'aws:PrincipalOrgID':'o-example'}}
    assert run(cid,conditioned,index('lambda_function',conditioned,params=params))=='UNKNOWN'
    assert run(cid,bad,index('lambda_function',bad))=='UNKNOWN'
    malformed=lam(Policy={'collection_status':'collected','Policy':{'Statement':'bad'}})
    assert run(cid,malformed,index('lambda_function',malformed,params=params))=='UNKNOWN'


def test_lambda_role_admin_pass_fail_unknown():
    cid='aws_cis_lambda_execution_role_no_admin'; row=lam()
    provenance={'operation':'iam:GetAccountAuthorizationDetails','native_response_complete':True}
    def facts(principal):
        value=index('lambda_function',row,{'iam_role':[principal]})
        value['collections']['iam_policy']=[{'type':'iam_policy','scope':GLOBAL,'status':'empty','items':[]}]
        value['iam_policy']=[]
        return value
    safe=role(RoleName='r',RolePolicyList=[{'PolicyName':'narrow','PolicyDocument':{'Statement':[
        {'Effect':'Allow','Action':'logs:CreateLogStream','Resource':'*'}]}}],AttachedManagedPolicies=[],_provenance=provenance)
    assert run(cid,row,facts(safe))=='PASS'
    bad=role(RoleName='r',RolePolicyList=[],AttachedManagedPolicies=[{'PolicyArn':
        'arn:aws:iam::aws:policy/AdministratorAccess','PolicyName':'AdministratorAccess'}],_provenance=provenance)
    assert run(cid,row,facts(bad))=='FAIL'
    custom=deepcopy(safe)
    custom['RolePolicyList'][0]['PolicyDocument']['Statement'][0]['Action']='*'
    assert run(cid,row,facts(custom))=='UNKNOWN'
    assert run(cid,row,facts(role()))=='UNKNOWN'
    assert run(cid,row,index('lambda_function',row))=='UNKNOWN'


def test_lambda_database_secret_pass_fail_na_unknown():
    cid='aws_cis_lambda_database_secrets_manager'; secret_arn=f'arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:db-123'
    params={'approved_database_connection_environment_variable_names':['DB_SECRET']}
    row=lam(DatabaseCredentialReferences={'collection_status':'collected','complete':True,'items':[
        {'name':'DB_SECRET','value_kind':'secret_arn','secret_arn':secret_arn}]})
    auth={'collection_status':'collected','complete':True,'role_arn':row['Role'],'get_secret_value_arns':[secret_arn]}
    safe=role(SecretReadAuthorization=auth); secret={'ARN':secret_arn}
    assert run(cid,row,index('lambda_function',row,{'iam_role':[safe],'secret':[secret]},params))=='PASS'
    literal=lam(DatabaseCredentialReferences={'collection_status':'collected','complete':True,'items':[
        {'name':'DB_SECRET','value_kind':'literal'}]})
    assert run(cid,literal,index('lambda_function',literal,{'iam_role':[safe],'secret':[secret]},params))=='FAIL'
    other=lam(DatabaseCredentialReferences={'collection_status':'empty','complete':True,'items':[]})
    assert run(cid,other,index('lambda_function',other,{'iam_role':[safe],'secret':[secret]},params))=='NOT_APPLICABLE'
    assert run(cid,row,index('lambda_function',row,{'iam_role':[safe]},params))=='UNKNOWN'
    broken=role(SecretReadAuthorization={'collection_status':'denied'})
    assert run(cid,row,index('lambda_function',row,{'iam_role':[broken],'secret':[secret]},params))=='UNKNOWN'


def test_world_ingress_pass_fail_unknown():
    cid='aws.pci.vpc.world_ingress_authorized_ports'; p={'approved_ports':[{'protocol':'tcp','from_port':443,'to_port':443}]}
    permission={'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'0.0.0.0/0'}],'Ipv6Ranges':[],'UserIdGroupPairs':[]}
    row=sg(IpPermissions=[permission])
    assert run(cid,row,index('security_group',row,params=p))=='PASS'
    bad=sg(IpPermissions=[{**permission,'FromPort':80,'ToPort':80}])
    assert run(cid,bad,index('security_group',bad,params=p))=='FAIL'
    assert run(cid,row,index('security_group',row))=='UNKNOWN'
    malformed=sg(IpPermissions=[{**permission,'IpRanges':[{'CidrIp':'bad'}]}])
    assert run(cid,malformed,index('security_group',malformed,params=p))=='UNKNOWN'


def test_approved_egress_pass_fail_na_unknown():
    cid='aws.pci.vpc.approved_egress'
    p={'cde_security_group_ids':['sg-1'],'approved_cde_egress':[{'protocol':'tcp','from_port':443,'to_port':443,'cidr':'10.0.0.0/8'}]}
    rule={'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'10.1.0.0/16'}],'Ipv6Ranges':[],'UserIdGroupPairs':[]}
    row=sg(IpPermissionsEgress=[rule])
    assert run(cid,row,index('security_group',row,params=p))=='PASS'
    bad=sg(IpPermissionsEgress=[{**rule,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}])
    assert run(cid,bad,index('security_group',bad,params=p))=='FAIL'
    assert run(cid,row,index('security_group',row,params={**p,'cde_security_group_ids':[]}))=='NOT_APPLICABLE'
    assert run(cid,row,index('security_group',row))=='UNKNOWN'
    malformed=sg(IpPermissionsEgress=[{**rule,'IpRanges':[{'CidrIp':'invalid'}]}])
    assert run(cid,malformed,index('security_group',malformed,params=p))=='UNKNOWN'


@pytest.mark.parametrize('cid',[
 'aws.nist.emr_master_nodes_no_public_ip','aws_fedramp_emr_master_no_public_ip',
 'aws_g6_emr_master_nodes_no_public_address','aws_nist_emr_cluster_master_nodes_no_public_ip'])
def test_emr_pass_fail_na_unknown(cid):
    row=emr(); ec2=instance()
    assert run(cid,row,index('emr_cluster',row,{'instance':[ec2]}))=='PASS'
    pub=instance(NetworkInterfaces=[{'Association':{'PublicIp':'8.8.8.8'},'Ipv6Addresses':[]}])
    assert run(cid,row,index('emr_cluster',row,{'instance':[pub]}))=='FAIL'
    stopped=emr(Status={'State':'TERMINATED'})
    assert run(cid,stopped,index('emr_cluster',stopped,{'instance':[]}))=='NOT_APPLICABLE'
    assert run(cid,row,index('emr_cluster',row))=='UNKNOWN'
    malformed=emr(MasterInstances={'collection_status':'partial','items':[]})
    assert run(cid,malformed,index('emr_cluster',malformed,{'instance':[ec2]}))=='UNKNOWN'
    invalid_ip=instance(PublicIpAddress=123)
    assert run(cid,row,index('emr_cluster',row,{'instance':[invalid_ip]}))=='UNKNOWN'


def test_dns_firewall_pass_fail_unknown():
    cid='aws_cis_route53_dns_firewall'; row=vpc(); p={'approved_firewall_domain_list_ids':['rslvr-fdl-1']}
    assoc={'VpcId':'vpc-1','FirewallRuleGroupId':'rslvr-frg-1','Status':'COMPLETE'}
    rule={'FirewallRuleGroupId':'rslvr-frg-1','Action':'BLOCK','FirewallDomainListId':'rslvr-fdl-1'}
    assert run(cid,row,index('vpc',row,{'resolver_firewall_rule_group_association':[assoc],'resolver_firewall_rule':[rule]},p))=='PASS'
    assert run(cid,row,index('vpc',row,{'resolver_firewall_rule_group_association':[],'resolver_firewall_rule':[rule]},p))=='FAIL'
    assert run(cid,row,index('vpc',row,{'resolver_firewall_rule_group_association':[assoc],'resolver_firewall_rule':[rule]}))=='UNKNOWN'
    assert run(cid,row,index('vpc',row,{'resolver_firewall_rule_group_association':[assoc]},p))=='UNKNOWN'


def test_vpc_endpoint_pass_fail_unknown():
    cid='aws_nist_vpc_configured_to_use_vpc_endpoints'; row=vpc(); p={'required_service_name':'com.amazonaws.us-east-1.s3'}
    ep={'VpcEndpointId':'vpce-1','VpcId':'vpc-1','ServiceName':p['required_service_name'],'State':'available'}
    assert run(cid,row,index('vpc',row,{'vpc_endpoint':[ep]},p))=='PASS'
    assert run(cid,row,index('vpc',row,{'vpc_endpoint':[]},p))=='FAIL'
    assert run(cid,row,index('vpc',row,{'vpc_endpoint':[ep]}))=='UNKNOWN'
    assert run(cid,row,index('vpc',row,params=p))=='UNKNOWN'


@pytest.mark.parametrize('cid',list(sw.SPECS))
def test_partial_and_foreign_primary_inventory_unknown(cid):
    kind=sw.SPECS[cid][0]
    row={'kms_key':kms,'lambda_function':lam,'security_group':sg,'emr_cluster':emr,'vpc':vpc}[kind]()
    idx=index(kind,row)
    idx['collections'][kind][0]['status']='partial'
    assert run(cid,row,idx)=='UNKNOWN'
    idx=index(kind,row)
    idx['collections'][kind][0]['scope']='999999999999/us-east-1'
    assert run(cid,row,idx)=='UNKNOWN'
