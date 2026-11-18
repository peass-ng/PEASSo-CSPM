"""Signed AWS compliance predicates; incomplete or unauthoritative facts stay unknown."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import ipaddress
import json
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard

# The signed ledger is the source of these immutable metadata fields. The native
# registry calls its equivalent of compliance 'hardening'; restore the signed
# category on the resulting Check without changing the registry implementation.
SPECS = {
 'aws.pci.shield.protection_all_internet_resources': ('shield_protection','hardening','medium','Internet resources have Shield Advanced protection','8c1bb42cdabf76a3560383d07ad88f584dd346a8a9abcc69caef8df5d03259f4'),
 'aws.pci.shield.srt_access': ('shield_protection','hardening','medium','Shield Response Team has account access','3fcc67c0fa62948516c736f8c5c7920908e1767aef1e2d9c76b2767d9a225547'),
 'aws_g6_api_stage_effective_waf_acl': ('rest_api_stage','hardening','medium','REST API stages have effective WAF web ACLs','42b2d6da1911cd25d33059638381c183b511a3fd879dd4474a14fe104c8483d2'),
 'aws_nist_apigateway_stage_cache_encryption_at_rest_enabled': ('rest_api_stage','compliance','medium','API Gateway stage cache encryption at rest should be enabled','b87a72b3d8befd2e35a2601447ed664f32610c304bdf3bee64e092dc8e26fb39'),
 'aws_cis_organizations_integrated_services_delegated': ('organization','least_privilege','medium','Integrated services have delegated administrators','d745780eaeebdf7658d80f5cbe07f5685d92505bdbe1c6653f3a5b785aec52a4'),
 'aws_cis_organizations_policy_management_delegated': ('organization','least_privilege','medium','Organizations policy management has an approved delegate','daa7ba2a30fa80079288b6fbe206dd627a837bc73928ec40b30dcdb3184ce7b6'),
 'aws_organizations_restrict_ec2_instance_types': ('organization','hardening','medium','Restrict instances types','4dc448034a3dde88ef0800a66f5df7bc6d902f6cc36b076697bbea25f0e2ff18'),
 'aws_organizations_security_service_tamper_scp': ('organization','hardening','medium','Block tampering with security-related settings and services','8d0b3650aea99774a2c7d53759f13650b25f6990c9de4927ec29b2f8c6a7c9ad'),
 'aws.pci.iam.generic_user_ids': ('iam_user','identity','medium','Generic or shared IAM identities are reviewed','c4cc982f092d2e5946ea113b635e72fcf0418056341ab61f8ed19e030020cc8d'),
 'aws_iam_departed_identity_disabled': ('iam_user','hardening','medium','Departed IAM identities have no active credentials','0e94b3aa7b093c43f034fb53a2857ffd8dfa866824efe4435cb8c8a05ffe7dd8'),
 'aws_iam_inactive_accounts_disabled_after_policy_days': ('iam_user','identity','high','Inactive IAM user credentials are disabled after the policy period','2f20bc70c18abdea310d9dcac90648001c4dd99acc11c9f85fdda596754bee16'),
 'aws.nist.ec2_instance_effective_public_reachability': ('ec2_instance','hardening','medium','EC2 instances have no effective public ingress path','a47a62bd613e6588ee893c2a334b71c91e73e52ca100706910a0e7df2fd30645'),
 'aws_ec2_dedicated_tenancy_for_sensitive_workloads': ('ec2_instance','hardening','medium','Sensitive EC2 workloads use dedicated tenancy','43ffa7b23dd10eb7c462b4ea764ee9331dd5634d7b39529f8644b7caf58fe300'),
 'aws_fedramp_ec2_effective_public_exposure': ('ec2_instance','compliance','medium','EC2 instances have no effective public ingress','f3b8d08d945a6e699be695269181d666412d574edb81e2bc3d9dc075c2904d46'),
 'aws_nist_ecs_task_definition_container_environment_no_secret': ('ecs_task_definition','compliance','medium','ECS task definition containers should not have secrets passed as environment variables','cfb4a0df54f8bd903c409bccba8fc8faaeaa51d12e484417e62f23b8c5fa0128'),
}
GLOBAL_KINDS={'shield_protection','shield_subscription','shield_drt_access','cloudfront_distribution',
              'organization','organization_service_access','organization_delegated_admin',
              'organization_resource_policy','organization_account','organization_effective_scp',
              'iam_user','iam_credential_report'}

def signed(cid, *, dependencies=None, target='resource'):
    kind, category, severity, title, _ = SPECS[cid]
    def decorate(fn):
        register(cid, 'aws', category if category in {'hardening','least_privilege'} else 'hardening',
                 kind, title, severity, 'CM-6', 'Review the named resource and approved policy inputs.',
                 dependencies=dependencies or [kind], target=target)(fn)
        if category not in {'hardening','least_privilege'}:
            CHECKS[-1] = replace(CHECKS[-1], category=category)
        return fn
    return decorate

def _scope(index):
    ctx = get(index, 'context', dict)
    if get(ctx,'provider',str) != 'aws':
        raise Unavailable('foreign provider')
    scope = get(ctx,'scope',str)
    if not re.fullmatch(r'\d{12}/[a-z0-9-]+',scope):
        raise Unavailable('invalid AWS scope')
    return scope

def _rows(index, kind):
    active_scope = _scope(index)
    scope = active_scope.split('/')[0]+'/global' if kind in GLOBAL_KINDS else active_scope
    env = get(index,'collections',dict).get(kind)
    if not isinstance(env,list) or len(env)!=1 or not isinstance(env[0],dict) or env[0].get('type')!=kind or env[0].get('scope')!=scope:
        raise Unavailable('collection scope unavailable: '+kind)
    if env[0].get('coverage_status','collected') not in ('collected','empty') or env[0].get('provider','aws')!='aws':
        raise Unavailable('collection coverage or provider unavailable: '+kind)
    rows=complete_items(index,kind)
    wrappers=get(index,kind,list)
    if any(not isinstance(w,dict) or w.get('type')!=kind or w.get('scope')!=scope or w.get('provider','aws')!='aws' or w.get('account_id',scope.split('/')[0])!=scope.split('/')[0] for w in wrappers):
        raise Unavailable('foreign resource scope: '+kind)
    if rows!=get(env[0],'items',list) or len(rows)!=len(wrappers):
        raise Unavailable('collection/resource count disagreement: '+kind)
    if env[0].get('status')=='empty' and rows:
        raise Unavailable('empty inventory contains rows: '+kind)
    return rows

def _member(item,index,kind,key):
    rows=_rows(index,kind)
    identity=get(item,key,str)
    matches=[r for r in rows if get(r,key,str)==identity]
    if len(matches)!=1 or matches[0]!=item:
        raise Unavailable('resource identity missing or ambiguous')
    return identity

def _policy(index,key,typ):
    context=get(index,'context',dict)
    if 'policy_inputs' in context:
        policy=get(context,'policy_inputs',dict)
    else:
        policy=get(get(context,'metadata',dict),'compliance_policy',dict)
        policy=get(policy,'aws_organizations',dict)
        if 'by_scope' in policy:
            policy=get(get(policy,'by_scope',dict),_scope(index),dict)
    if get(policy,'status',str)!='collected' or get(policy,'scope',str)!=_scope(index):
        raise Unavailable('policy scope or collection unavailable')
    return get(policy,key,typ)

def _strings(values, *, nonempty=False):
    if not isinstance(values,list) or (nonempty and not values) or any(not isinstance(x,str) or not x for x in values) or len(values)!=len(set(values)):
        raise Unavailable('malformed policy string list')
    return values

def _date(value):
    if not isinstance(value,str): raise Unavailable('malformed date')
    try:
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None: raise ValueError('timezone missing')
        return parsed.astimezone(timezone.utc)
    except ValueError: raise Unavailable('malformed date')

def _account(index): return _scope(index).split('/')[0]

def _arn(value,service=None):
    if not isinstance(value,str) or not re.fullmatch(r'arn:aws(?:-[\w-]+)?:[^:]+:[^:]*:[^:]*:.+',value):
        raise Unavailable('malformed ARN')
    if service and value.split(':')[2]!=service: raise Unavailable('wrong ARN service')
    return value

def _account_arn(value,index,service=None):
    value=_arn(value,service)
    if value.split(':')[4]!=_account(index): raise Unavailable('resource ARN belongs to another account')
    return value

def _stage(item,index):
    stage=_member(item,index,'rest_api_stage','id')
    api=get(item,'ParentApiId',str); name=get(item,'stageName',str)
    region=_scope(index).split('/')[1]
    if not re.fullmatch(r'arn:aws(?:-[\w-]+)?:apigateway:'+re.escape(region)+r'::/restapis/'+re.escape(api)+r'/stages/'+re.escape(name),stage):
        raise Unavailable('stage ARN does not match scoped API identity')
    source=get(item,'_provenance',dict)
    if get(source,'source_operation',str)!='get_stages' or get(source,'parent_api_id',str)!=api or get(source,'read_only',bool) is not True:
        raise Unavailable('GetStages provenance unavailable')
    return stage

@ signed('aws.pci.shield.protection_all_internet_resources',dependencies=['shield_protection','load_balancer','classic_load_balancer','cloudfront_distribution','elastic_ip'],target='scope')
def shield_all(item,index):
    protected={_arn(get(r,'ResourceArn',str)) for r in _rows(index,'shield_protection')}
    public=[]
    for kind in ('load_balancer','classic_load_balancer','cloudfront_distribution','elastic_ip'):
        for r in _rows(index,kind):
            if kind=='load_balancer':
                lb_type=get(r,'Type',str)
                if lb_type not in ('application','network','gateway'): raise Unavailable('unknown LB type')
                if lb_type!='application': continue
                scheme=get(r,'Scheme',str)
                if scheme not in ('internet-facing','internal'): raise Unavailable('unknown LB scheme')
                if scheme=='internal': continue
                public.append(_account_arn(get(r,'LoadBalancerArn',str),index,'elasticloadbalancing'))
            elif kind=='classic_load_balancer':
                scheme=get(r,'Scheme',str)
                if scheme not in ('internet-facing','internal'): raise Unavailable('unknown Classic ELB scheme')
                if scheme=='internet-facing': public.append(_account_arn(get(r,'ShieldResourceArn',str),index,'elasticloadbalancing'))
            elif kind=='cloudfront_distribution':
                public.append(_account_arn(get(r,'ARN',str),index,'cloudfront'))
            else:
                public.append(_account_arn(get(r,'ShieldResourceArn',str),index,'ec2'))
    missing=sorted(set(public)-protected)
    return result(bool(missing),unprotected_resource_arns=missing,assessed=len(set(public)))

@ signed('aws.pci.shield.srt_access',dependencies=['shield_protection','shield_subscription','shield_drt_access'])
def shield_srt(item,index):
    _member(item,index,'shield_protection','Id')
    subs=_rows(index,'shield_subscription')
    if len(subs)!=1: raise Unavailable('subscription authority unavailable')
    state=get(subs[0],'SubscriptionState',str)
    if state not in ('ACTIVE','INACTIVE'): raise Unavailable('unknown Shield state')
    if state=='INACTIVE': return 'NOT_APPLICABLE',{'reason':'Shield Advanced disabled'}
    drt=_rows(index,'shield_drt_access')
    if len(drt)!=1: raise Unavailable('DRT access fact unavailable')
    role=get(drt[0],'RoleArn',str)
    buckets=_strings(get(drt[0],'LogBucketList',list))
    required=_strings(_policy(index,'required_shield_log_buckets',list))
    if role:
        _account_arn(role,index,'iam')
        if not re.fullmatch(r'arn:aws(?:-[\w-]+)?:iam::\d{12}:role/.+',role): raise Unavailable('DRT role ARN malformed')
    absent=sorted(set(required)-set(buckets))
    return result(not role or bool(absent),role_arn=role,missing_log_buckets=absent)

@ signed('aws_g6_api_stage_effective_waf_acl',dependencies=['rest_api_stage','stage_waf_association','wafv2_web_acl'])
def stage_waf(item,index):
    stage=_stage(item,index)
    if 'webAclArn' in item or 'webAclArn' in item.get('_coverage',{}):
        declared=get(item,'webAclArn',str)
    else:
        declared=''
    associations=[r for r in _rows(index,'stage_waf_association') if get(r,'stageArn',str)==stage]
    if len(associations)!=1: raise Unavailable('stage WAF association absent or ambiguous')
    effective=get(associations[0],'webAclArn',str)
    if declared: _arn(declared,'wafv2')
    if effective: _arn(effective,'wafv2')
    acls={_arn(get(r,'ARN',str),'wafv2') for r in _rows(index,'wafv2_web_acl')}
    return result(not declared or not effective or declared!=effective or declared not in acls,stage_arn=stage,declared_acl=declared,effective_acl=effective)

@ signed('aws_nist_apigateway_stage_cache_encryption_at_rest_enabled',dependencies=['rest_api_stage','rest_api_method'])
def stage_cache(item,index):
    stage=_stage(item,index)
    if 'cacheClusterEnabled' in item or 'cacheClusterStatus' in item:
        cluster_enabled=get(item,'cacheClusterEnabled',bool)
        cluster_status=get(item,'cacheClusterStatus',str)
        if cluster_status not in ('CREATE_IN_PROGRESS','AVAILABLE','DELETE_IN_PROGRESS','NOT_AVAILABLE','FLUSH_IN_PROGRESS'):
            raise Unavailable('unrecognized API Gateway cache cluster status')
        if not cluster_enabled and cluster_status=='NOT_AVAILABLE':
            return 'NOT_APPLICABLE',{'reason':'stage has no cache cluster','stage_arn':stage}
        if not cluster_enabled or cluster_status!='AVAILABLE':
            raise Unavailable('cache cluster is transitioning or its state is inconsistent')
    raw_settings=get(item,'methodSettings',dict)
    settings={}
    for key,value in raw_settings.items():
        if not isinstance(key,str) or not isinstance(value,dict): raise Unavailable('malformed method setting map')
        guard(value)
        # AWS returns /*/* and /resource/METHOD. Legacy reviewed fixtures
        # encode resource slashes as ~1; accept either exact spelling only.
        normalized='*/*' if key in ('*/*','/*/*') else key.replace('~1','/')
        if '*' in normalized and normalized!='*/*': raise Unavailable('partial wildcard method setting semantics unresolved')
        if normalized in settings: raise Unavailable('ambiguous duplicate method setting key')
        settings[normalized]=value
    routes=[r for r in _rows(index,'rest_api_method') if get(r,'stageArn',str)==stage]
    if not routes: raise Unavailable('deployed method inventory absent')
    unsafe=[]
    for route in routes:
        key=get(route,'methodSettingKey',str).replace('~1','/')
        if key.endswith('/ANY') and any(setting!='*/*' for setting in settings):
            raise Unavailable('ANY method-specific override precedence unresolved')
        if key not in settings and '*/*' not in settings: raise Unavailable('method setting missing')
        override=settings.get(key,{})
        wildcard=settings.get('*/*',{})
        if not isinstance(override,dict) or not isinstance(wildcard,dict): raise Unavailable('malformed method settings')
        cache=get(override if 'cachingEnabled' in override else wildcard,'cachingEnabled',bool)
        if cache:
            encrypted=get(override if 'cacheDataEncrypted' in override else wildcard,'cacheDataEncrypted',bool)
            if not encrypted: unsafe.append(key)
    return result(bool(unsafe),stage_arn=stage,unencrypted_methods=sorted(set(unsafe)))

@ signed('aws_cis_organizations_integrated_services_delegated',dependencies=['organization','organization_service_access','organization_delegated_admin'])
def org_services(item,index):
    _member(item,index,'organization','id')
    required=_strings(_policy(index,'required_service_principals',list))
    access=_rows(index,'organization_service_access')
    if len(access)!=1: raise Unavailable('service access list absent')
    enabled={get(r,'ServicePrincipal',str) for r in get(access[0],'EnabledServicePrincipals',list)}
    admins=_rows(index,'organization_delegated_admin')
    for admin in admins:
        if get(admin,'Status',str) not in ('ACTIVE','SUSPENDED','PENDING_CLOSURE') or not re.fullmatch(r'\d{12}',get(admin,'AccountId',str)):
            raise Unavailable('delegated administrator status or account malformed')
    missing=[]
    for principal in required:
        if principal not in enabled: continue
        matches=[r for r in admins if get(r,'ServicePrincipal',str)==principal and get(r,'Status',str)=='ACTIVE' and get(r,'AccountId',str)!=_account(index)]
        if not matches: missing.append(principal)
    return result(bool(missing),missing_delegated_services=missing)

@ signed('aws_cis_organizations_policy_management_delegated',dependencies=['organization','organization_resource_policy','organization_account'])
def org_policy_delegate(item,index):
    _member(item,index,'organization','id')
    org=get(item,'Organization',dict); orgid=get(org,'Id',str); management=get(org,'MasterAccountId',str)
    policies=_rows(index,'organization_resource_policy')
    if len(policies)!=1: raise Unavailable('resource policy absent')
    doc=get(policies[0],'Content')
    if isinstance(doc,str): doc=json.loads(doc)
    statements=get(doc,'Statement',list)
    accounts=set()
    for r in _rows(index,'organization_account'):
        status=get(r,'State' if 'State' in r else 'Status',str)
        if status not in ('ACTIVE','SUSPENDED','PENDING_CLOSURE','PENDING_ACTIVATION','CLOSED'): raise Unavailable('account status malformed')
        if status=='ACTIVE': accounts.add(get(r,'Id',str))
    accounts.discard(management)
    needed={'organizations:createpolicy','organizations:updatepolicy','organizations:attachpolicy'}
    covered=set()
    for stmt in statements:
        if get(stmt,'Effect',str)!='Allow': continue
        actions=get(stmt,'Action'); actions=[actions] if isinstance(actions,str) else actions
        if not isinstance(actions,list) or any(not isinstance(a,str) for a in actions): raise Unavailable('invalid policy actions')
        resources=get(stmt,'Resource'); resources=[resources] if isinstance(resources,str) else resources
        if not isinstance(resources,list): raise Unavailable('invalid policy resource')
        if '*' not in resources and not any(isinstance(r,str) and re.fullmatch(r'arn:aws(?:-[\w-]+)?:organizations::\d{12}:organization/'+re.escape(orgid),r) for r in resources): continue
        if 'Condition' in stmt or 'NotPrincipal' in stmt: raise Unavailable('conditional delegate policy')
        principal=get(stmt,'Principal'); aws=principal.get('AWS') if isinstance(principal,dict) else principal
        aws=[aws] if isinstance(aws,str) else aws
        if not isinstance(aws,list): raise Unavailable('invalid delegate principal')
        for p in aws:
            if not isinstance(p,str): raise Unavailable('invalid delegate principal')
            if p=='*': raise Unavailable('wildcard delegate principal needs account-level review')
            acct=p if re.fullmatch(r'\d{12}',p) else p.split(':')[4] if p.startswith('arn:') and len(p.split(':'))>=6 else ''
            granted={a.lower() for a in actions}
            if acct in accounts and (needed <= granted or '*' in granted or 'organizations:*' in granted): covered.add(acct)
    return result(not bool(covered),delegated_accounts=sorted(covered))

# SCP checks use a normalized, account-resolved policy fact supplied by a future
# collector: account_id, inherited/attached Policy.Content, complete target path.
def _scp_accounts(item,index):
    _member(item,index,'organization','id')
    accounts=_strings(_policy(index,'audited_account_ids',list),nonempty=True)
    if any(not re.fullmatch(r'\d{12}',a) for a in accounts): raise Unavailable('invalid audited account')
    rows=_rows(index,'organization_effective_scp')
    by={get(r,'TargetAccountId' if 'TargetAccountId' in r else 'AccountId',str):r for r in rows}
    if len(by)!=len(rows) or any(a not in by for a in accounts): raise Unavailable('effective SCP path incomplete')
    selected={}
    for account in accounts:
        row=by[account]
        if row.get('ScpApplicable') is False:
            org=get(item,'Organization',dict)
            if (account!=get(org,'MasterAccountId',str) or get(row,'OrganizationId',str)!=get(org,'Id',str)
                    or get(row,'Complete',bool) is not True):
                raise Unavailable('SCP exemption is not bound to management account')
            continue  # SCPs do not restrict the organization's management account.
        selected[account]=get(row,'Policies',list)
    return selected

def _deny_statements(policies):
    out=[]
    for p in policies:
        doc=get(p,'Content')
        if isinstance(doc,str): doc=json.loads(doc)
        for s in get(doc,'Statement',list):
            if get(s,'Effect',str)=='Deny': out.append(s)
    return out

@ signed('aws_organizations_restrict_ec2_instance_types',dependencies=['organization','organization_effective_scp'])
def org_instance_types(item,index):
    allowed=_strings(_policy(index,'allowed_instance_types',list),nonempty=True)
    missing=[]
    assessed=_scp_accounts(item,index)
    if not assessed:
        return 'NOT_APPLICABLE',{'reason':'audited accounts are exempt from SCPs'}
    for account,policies in assessed.items():
        good=False; uncertain=False
        for s in _deny_statements(policies):
            actions=get(s,'Action'); actions=[actions] if isinstance(actions,str) else actions
            if not isinstance(actions,list): raise Unavailable('malformed SCP Action')
            relevant='ec2:RunInstances' in actions or 'ec2:*' in actions or '*' in actions
            if not relevant: continue
            condition=get(s,'Condition',dict)
            if set(condition)!={'StringNotEquals'}:
                uncertain=True; continue
            clause=get(condition,'StringNotEquals',dict)
            if set(clause)!={'ec2:InstanceType'}:
                uncertain=True; continue
            types=clause.get('ec2:InstanceType')
            types=[types] if isinstance(types,str) else types
            if isinstance(types,list) and set(types)==set(allowed) and get(s,'Resource')=='*' and 'NotPrincipal' not in s:
                good=True
            else: uncertain=True
        if not good:
            if uncertain: raise Unavailable('SCP instance-type condition needs semantic review')
            missing.append(account)
    return result(bool(missing),accounts_without_restriction=missing)

@ signed('aws_organizations_security_service_tamper_scp',dependencies=['organization','organization_effective_scp'])
def org_tamper(item,index):
    required={'cloudtrail:*','config:*','guardduty:*','securityhub:*'}
    approved=_strings(_policy(index,'approved_break_glass_principals',list))
    missing=[]
    assessed=_scp_accounts(item,index)
    if not assessed:
        return 'NOT_APPLICABLE',{'reason':'audited accounts are exempt from SCPs'}
    for account,policies in assessed.items():
        denied=set()
        for s in _deny_statements(policies):
            if get(s,'Resource')!='*': continue
            condition=s.get('Condition',{})
            if condition and condition!={'ArnNotEquals':{'aws:PrincipalArn':approved}}: continue
            actions=get(s,'Action'); actions=[actions] if isinstance(actions,str) else actions
            if not isinstance(actions,list): raise Unavailable('malformed SCP Action')
            denied.update(a.lower() for a in actions if isinstance(a,str))
        if '*' not in denied and not required <= denied:
            if policies: raise Unavailable('SCP action coverage needs semantic review')
            missing.append(account)
    return result(bool(missing),accounts_without_tamper_deny=missing)

@ signed('aws.pci.iam.generic_user_ids',dependencies=['iam_user'])
def generic_user(item,index):
    _member(item,index,'iam_user','Arn'); name=get(item,'UserName',str)
    _account_arn(get(item,'Arn',str),index,'iam')
    patterns=_strings(_policy(index,'shared_account_patterns',list),nonempty=True)
    approved=_strings(_policy(index,'approved_service_identity_ids',list))
    try: shared=any(re.fullmatch(p,name,re.IGNORECASE) for p in patterns)
    except re.error: raise Unavailable('invalid account-name pattern')
    profile=get(item,'LoginProfile',dict); state=get(profile,'collection_status',str)
    if state not in ('collected','empty'): raise Unavailable('login profile unavailable')
    keys=get(item,'AccessKeys',dict)
    if get(keys,'collection_status',str) not in ('collected','empty'): raise Unavailable('access keys unavailable')
    statuses=[get(k,'Status',str) for k in get(keys,'items',list)]
    if any(s not in ('Active','Inactive') for s in statuses): raise Unavailable('invalid access-key status')
    active='Active' in statuses
    return result(bool(shared and name not in approved and get(item,'Arn',str) not in approved and (state=='collected' or active)),user_name=name)

@ signed('aws_iam_departed_identity_disabled',dependencies=['iam_user','iam_credential_report'])
def departed_user(item,index):
    _member(item,index,'iam_user','Arn'); name=get(item,'UserName',str)
    _account_arn(get(item,'Arn',str),index,'iam')
    roster=_policy(index,'departure_roster',dict)
    if name not in roster: return 'NOT_APPLICABLE',{'reason':'user not in approved departure roster'}
    deadline=_date(get(roster[name],'termination_deadline',str))
    now=_date(get(get(index,'context',dict),'created_at',str))
    if now<deadline: return 'NOT_APPLICABLE',{'reason':'termination deadline not reached'}
    reports=[r for r in _rows(index,'iam_credential_report') if get(r,'user',str)==name]
    if len(reports)!=1: raise Unavailable('credential report user absent or duplicate')
    r=reports[0]
    generated=_date(get(r,'ReportGeneratedTime',str))
    if generated<deadline or generated>now: raise Unavailable('report date outside assessed window')
    flags=[get(r,f,str).lower() for f in ('password_enabled','access_key_1_active','access_key_2_active')]
    if any(f not in ('true','false') for f in flags): raise Unavailable('invalid credential flag')
    active='true' in flags
    return result(active,user_name=name,deadline=deadline.isoformat())

@ signed('aws_iam_inactive_accounts_disabled_after_policy_days',dependencies=['iam_user','iam_credential_report'])
def inactive_user(item,index):
    _member(item,index,'iam_user','Arn'); name=get(item,'UserName',str)
    _account_arn(get(item,'Arn',str),index,'iam')
    days=_policy(index,'inactivity_days',int)
    if days<=0: raise Unavailable('invalid inactivity days')
    exclusions=_strings(_policy(index,'approved_service_account_exclusions',list))
    if name in exclusions: return 'NOT_APPLICABLE',{'reason':'approved service account exclusion'}
    now=_date(get(get(index,'context',dict),'created_at',str))
    reports=[r for r in _rows(index,'iam_credential_report') if get(r,'user',str)==name]
    if len(reports)!=1: raise Unavailable('credential report user absent or duplicate')
    r=reports[0]
    report_age=(now-_date(get(r,'ReportGeneratedTime',str))).total_seconds()
    if report_age<0 or report_age>86400: raise Unavailable('credential report stale or future dated')
    created=_date(get(r,'user_creation_time',str)); dates=[]
    active=[]
    for prefix in ('password','access_key_1','access_key_2'):
        enabled=get(r,prefix+'_enabled' if prefix=='password' else prefix+'_active',str).lower()
        if enabled not in ('true','false'): raise Unavailable('invalid credential active flag')
        if enabled=='true': active.append(prefix)
        raw=get(r,prefix+'_last_used' if prefix=='password' else prefix+'_last_used_date',str)
        if raw not in ('N/A','no_information','not_supported'):
            dates.append(_date(raw))
        elif enabled=='true':
            dates.append(created if prefix=='password' else max(created,_date(get(r,prefix+'_last_rotated',str))))
    if created>now or any(d>now for d in dates): raise Unavailable('activity date after capture')
    if not active: return result(False,user_name=name)
    if not dates: raise Unavailable('activity dates unavailable')
    return result((now-max(dates)).days>days,user_name=name,active_credentials=active,last_activity=max(dates).isoformat())

# A collector-computed reachability join must be explicit about every route,
# SG, ENI, listener and target join. A boolean alone is not authoritative.
def _reachability(item,index):
    instance=_member(item,index,'ec2_instance','InstanceId')
    rows=[r for r in _rows(index,'ec2_effective_ingress') if get(r,'InstanceId',str)==instance]
    if len(rows)!=1: raise Unavailable('effective ingress join missing')
    row=rows[0]
    if row.get('proof_model')=='aws-public-config-witness-v1':
        from peaso.analysis.aws_public_ingress import DEPENDENCIES, witness, prepare, blocked
        from peaso.snapshot import make_snapshot
        from peaso.checks.facts import memoized
        def build_model():
            collections=[]
            for kind in sorted(DEPENDENCIES):
                native_rows=_rows(index,kind)
                collections.append({'type':kind,'scope':_scope(index),'status':'collected'if native_rows else'empty','items':native_rows})
            snap=make_snapshot('aws',[_scope(index)],collections)
            return snap,prepare(snap,_scope(index))
        snap,model=memoized(index,('public_ingress_native_model',),build_model)
        block = blocked(snap, _scope(index), instance)
        if block is not None and row.get('configured_block_witness') == block and row.get('configured_path_witness') is None:
            natives = [r for r in _rows(index, 'instance') if r.get('InstanceId') == instance]
            if natives == [item]:
                return False, {'instance_id': instance, 'configured_block_witness': block, 'public_paths': []}
        if model is None:raise Unavailable('native public-ingress model incomplete or unsupported')
        native_instance=model.find('instance',instance,_scope(index))
        if native_instance is None or native_instance['data']!=item:
            raise Unavailable('instance projection disagrees with independent native instance')
        proof=memoized(index,('public_ingress_native_witness',instance),lambda:witness(snap,_scope(index),instance,prepared=model))
        if proof is None or row.get('configured_path_witness')!=proof:
            raise Unavailable('no independently verified configured direct IPv4 witness; remaining paths unresolved')
        return True,{'instance_id':instance,'configured_path_witness':proof,'all_paths_evaluated':False}
    if get(row,'joins_complete',bool) is not True: raise Unavailable('network join incomplete')
    direct=get(row,'direct_public_paths',list); lbs=get(row,'public_listener_target_paths',list)
    found=[]
    for path in direct:
        address=get(path,'address',str)
        if not ipaddress.ip_address(address).is_global: raise Unavailable('direct path address is not public')
        if get(path,'internet_route',bool) and get(path,'permitted_ingress',bool): found.append({'direct_address':address})
    for path in lbs:
        arn=_account_arn(get(path,'load_balancer_arn',str),index,'elasticloadbalancing')
        if get(path,'internet_facing',bool) and get(path,'active_target',bool) and get(path,'listener_reaches_target_port',bool):
            found.append({'load_balancer_arn':arn})
    return (True,{'instance_id':instance,'public_paths':found}) if found else (False,{'instance_id':instance,'public_paths':[]})

@ signed('aws.nist.ec2_instance_effective_public_reachability',dependencies=['ec2_instance','ec2_effective_ingress'])
def nist_reach(item,index):
    failed,evidence=_reachability(item,index); return result(failed,**evidence)

@ signed('aws_fedramp_ec2_effective_public_exposure',dependencies=['ec2_instance','ec2_effective_ingress'])
def fedramp_reach(item,index):
    failed,evidence=_reachability(item,index); return result(failed,**evidence)

@ signed('aws_ec2_dedicated_tenancy_for_sensitive_workloads',dependencies=['ec2_instance'],target='scope')
def dedicated(item,index):
    scoped=_strings(_policy(index,'scope_instance_ids',list))
    if not scoped: return 'NOT_APPLICABLE',{'reason':'no sensitive instances configured'}
    rows=_rows(index,'ec2_instance')
    by={get(r,'InstanceId',str):r for r in rows}
    if len(by)!=len(rows): raise Unavailable('duplicate instance identity')
    unsafe=[]
    for instance in scoped:
        if instance not in by:
            unsafe.append(instance)
            continue
        state=get(by[instance],'State.Name',str)
        if state=='terminated': raise Unavailable('sensitive instance is terminated; tenancy no longer effective')
        if state not in ('pending','running','stopping','stopped'): raise Unavailable('unknown instance state')
        tenancy=get(by[instance],'Placement.Tenancy',str)
        if tenancy not in ('default','dedicated','host'): raise Unavailable('unknown tenancy')
        if tenancy=='default': unsafe.append(instance)
    return result(bool(unsafe),non_dedicated_or_missing_instances=unsafe)

@ signed('aws_nist_ecs_task_definition_container_environment_no_secret',dependencies=['ecs_task_definition'])
def ecs_secrets(item,index):
    _member(item,index,'ecs_task_definition','taskDefinitionArn')
    secrets=_strings(_policy(index,'approved_secret_values',list))
    patterns=_strings(_policy(index,'approved_sensitive_name_patterns',list))
    definition=get(item,'Definition',dict)
    if get(definition,'collection_status',str)!='collected': raise Unavailable('task definition incomplete')
    containers=get(get(definition,'taskDefinition',dict),'containerDefinitions',list)
    found=[]
    for container in containers:
        name=get(container,'name',str)
        for entry in get(container,'environment',list):
            key=get(entry,'name',str); value=get(entry,'value',str)
            try: sensitive=any(re.fullmatch(p,key,re.IGNORECASE) for p in patterns)
            except re.error: raise Unavailable('invalid sensitive-name pattern')
            if value in secrets or sensitive: found.append(name+':'+key)
    return result(bool(found),plaintext_secret_variable_names=sorted(found))
