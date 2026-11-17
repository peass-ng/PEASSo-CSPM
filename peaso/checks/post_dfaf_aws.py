"""Offline signed AWS candidates; no registry mutation, source file, or API reads.

Companion SPECS are literal signed rows. The integrator must decide admission,
including the signed compliance category which register() currently disallows.
"""
from __future__ import annotations
from datetime import datetime, timezone
import re
from peaso.checks import Check, result, unknown
from peaso.checks.facts import Unavailable, get, guard, list_of_objects, optional, memoized
from .post_dfaf_aws_specs import SPECS

KEYS = {'vpc_peering_connection':'VpcPeeringConnectionId', 'vpc':'VpcId',
        'dhcp_options':'DhcpOptionsId', 'efs_access_point':'AccessPointArn',
        'load_balancer_v2':'LoadBalancerArn', 'rest_api_stage':'id',
        'rds_cluster':'DBClusterIdentifier', 'rds_instance':'DBInstanceIdentifier',
        'shield_protection':'Id', 'elasticache_replication_group':'ReplicationGroupId',
        'elasticache_cluster':'CacheClusterId', 'autoscaling_group':'AutoScalingGroupARN'}
ARN_FIELDS={'efs_access_point':('AccessPointArn','elasticfilesystem'),
            'load_balancer_v2':('LoadBalancerArn','elasticloadbalancing'),
            'rds_cluster':('DBClusterArn','rds'), 'rds_instance':('DBInstanceArn','rds'),
            'elasticache_replication_group':('ARN','elasticache'),
            'elasticache_cluster':('ARN','elasticache'),
            'autoscaling_group':('AutoScalingGroupARN','autoscaling')}


def scope(index):
    c=get(index,'context',dict)
    if get(c,'provider',str)!='aws':raise Unavailable('foreign provider')
    s=get(c,'scope',str)
    if not re.fullmatch(r'[0-9]{12}/[a-z0-9-]+',s):raise Unavailable('missing AWS scope')
    account,region=s.split('/')
    partition='aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    return s,account,region,partition


def _rows_uncached(index,kind):
    s,account,region,partition=scope(index)
    expected=account+'/global' if kind=='shield_protection' else s
    env=get(index,'collections',dict).get(kind)
    if not isinstance(env,list) or len(env)!=1:raise Unavailable('inventory missing: '+kind)
    e=env[0]
    if not isinstance(e,dict) or e.get('type')!=kind or e.get('scope')!=expected or e.get('status') not in ('collected','empty','partial'):
        raise Unavailable('foreign or unreadable inventory: '+kind)
    if kind=='shield_protection' and (e.get('global') is not True or e.get('account_id')!=account):raise Unavailable('unverified global account')
    wrappers=list_of_objects(get(index,kind,list)); out=[]
    for w in wrappers:
        if w.get('provider')!='aws' or w.get('type')!=kind or w.get('scope')!=expected:raise Unavailable('foreign resource wrapper')
        row=get(w,'data',dict);identity=get(row,KEYS[kind],str)
        if not identity:raise Unavailable('empty identity')
        field,service=ARN_FIELDS.get(kind,(None,None))
        if field and not get(row,field,str).startswith(f'arn:{partition}:{service}:{region}:{account}:'):
            raise Unavailable('foreign resource ARN')
        if kind=='rest_api_stage' and not identity.startswith(f'arn:{partition}:apigateway:{region}::/restapis/'):
            raise Unavailable('foreign stage ARN')
        if kind=='efs_access_point' and get(row,'OwnerId',str)!=account:raise Unavailable('foreign EFS owner')
        if kind in ('vpc','dhcp_options') and get(row,'OwnerId',str)!=account:raise Unavailable('foreign EC2 owner')
        if kind=='shield_protection':
            arn=get(row,'ResourceArn',str).split(':',5)
            if len(arn)!=6 or arn[1]!=partition or arn[4]!=account:raise Unavailable('foreign Shield protected resource')
        if kind=='vpc_peering_connection':
            endpoints=[get(row,side,dict) for side in ('RequesterVpcInfo','AccepterVpcInfo')]
            if not any(get(v,'OwnerId',str)==account and optional(v,'Region',region,str)==region for v in endpoints):
                raise Unavailable('foreign peering endpoints')
        out.append(row)
    if len({get(r,KEYS[kind],str) for r in out})!=len(out):raise Unavailable('duplicate resource identity')
    if out!=e.get('items') or e.get('status')=='empty' and out:raise Unavailable('inventory projection mismatch')
    return out,e['status'] in ('collected','empty')


def rows(index,kind):
    current_scope=scope(index)[0]
    return memoized(index,('post_dfaf_aws_rows',current_scope,kind),lambda:_rows_uncached(index,kind))


def inventory_map(index,kind):
    current_scope=scope(index)[0]
    def build():
        objects,complete=rows(index,kind)
        return {get(row,KEYS[kind],str):row for row in objects},complete
    return memoized(index,('post_dfaf_aws_members',current_scope,kind),build)


def member(item,index,kind):
    inventory,complete=inventory_map(index,kind)
    if inventory.get(get(item,KEYS[kind],str))!=item:raise Unavailable('resource outside inventory')
    return complete


def all_rows(objects,fn,complete=True):
    """An observed failure survives unrelated unavailable children/pages."""
    uncertain=not complete
    for obj in objects:
        try:
            status,evidence=fn(obj)
        except (Unavailable,ValueError,TypeError,KeyError):
            uncertain=True;continue
        if status=='FAIL':return status,evidence
        if status=='UNKNOWN':uncertain=True
    return unknown('incomplete predicate facts') if uncertain else result(False)


def peering(item,index):
    state=get(item,'Status.Code',str)
    if state!='active':
        if state not in ('initiating-request','pending-acceptance','provisioning','failed','rejected','expired','deleting','deleted'):raise Unavailable('unknown peering state')
        return 'NOT_APPLICABLE',{'reason':'peering is not active'}
    outcome = all_rows(['RequesterVpcInfo','AccepterVpcInfo'],lambda side:result(not (enabled := get(item,side+'.PeeringOptions.AllowDnsResolutionFromRemoteVpc',bool)), peering_side=side, remote_dns_resolution=enabled))
    if outcome[0] == 'PASS':
        return outcome[0], {'dns_options': {side: get(item,side+'.PeeringOptions.AllowDnsResolutionFromRemoteVpc',bool) for side in ('RequesterVpcInfo','AccepterVpcInfo')}}
    return outcome


def efs(item,index):
    # Explicit coverage denial overrides absent fields; absence is unsafe on a
    # successfully collected DescribeAccessPoints row (allowlist retains field).
    root=get(item,'RootDirectory',dict)
    path=get(root,'Path',str)
    if path and (len(path)>100 or re.fullmatch(r'(\/|(\/(?!\.)+[^$#<>;`|&?{}^*/\n]+){1,4})',path) is None):
        raise Unavailable('malformed EFS API root-directory Path')
    return result(not path or path=='/',root_path=path)


def dhcp(item,index):
    identity=get(item,'DhcpOptionsId',str);inventory,complete=inventory_map(index,'dhcp_options')
    candidate=inventory.get(identity)
    if candidate is None:raise Unavailable('DHCP join unresolved')
    options=list_of_objects(get(candidate,'DhcpConfigurations',list))
    dns=[x for x in options if get(x,'Key',str)=='domain-name-servers']
    if len(dns)!=1:return result(True,reason='no unique DNS-server option') if complete else unknown('partial DHCP join')
    values=[get(v,'Value',str) for v in list_of_objects(get(dns[0],'Values',list))]
    if set(values)=={'AmazonProvidedDNS'} and not complete:return unknown('DHCP inventory incomplete')
    return result(set(values)!={'AmazonProvidedDNS'},dns_servers=values)


def listeners(item,index):
    typ=get(item,'Type',str)
    if typ=='gateway':return 'NOT_APPLICABLE',{'reason':'GWLB is outside ALB/NLB source predicate'}
    if typ not in ('application','network'):raise Unavailable('unknown load balancer type')
    guard(item)
    coverage_entries=item.get('_coverage',{})
    coverage=coverage_entries.get('Listeners')
    if 'Listeners' in coverage_entries and (not isinstance(coverage,dict) or coverage.get('status') not in ('collected','empty')):
        raise Unavailable('listener field coverage unavailable')
    # A partial child list retains measured listeners; do not pass it through
    # get(), whose resource guard correctly rejects partial single GET facts.
    envelope=item.get('Listeners')
    if not isinstance(envelope,dict):raise Unavailable('missing or malformed listener envelope')
    if coverage is not None and coverage['status']=='empty' and envelope:
        raise Unavailable('empty listener coverage contradicts present envelope')
    field_coverage=envelope.get('_coverage',{})
    if not isinstance(field_coverage,dict):raise Unavailable('malformed listener coverage')
    items_coverage=field_coverage.get('items')
    if 'items' in field_coverage and (not isinstance(items_coverage,dict) or items_coverage.get('status') not in ('collected','empty','partial')):
        raise Unavailable('listener item facts unavailable')
    if items_coverage is not None and items_coverage['status']=='empty' and envelope.get('items'):
        raise Unavailable('empty listener item coverage contradicts present items')
    status=envelope.get('collection_status')
    if status not in ('collected','empty','partial'):raise Unavailable('listeners unavailable')
    load_arn=get(item,'LoadBalancerArn',str)
    def check(listener):
        arn=get(listener,'ListenerArn',str)
        # ELB listener and parent share /app|net/name/id/ hierarchy.
        expected=load_arn.replace(':loadbalancer/',':listener/')+'/'
        if not arn.startswith(expected):raise Unavailable('listener belongs to different load balancer')
        protocol=get(listener,'Protocol',str)
        if protocol not in ('HTTP','HTTPS','TCP','TLS','UDP','TCP_UDP','GENEVE','QUIC','TCP_QUIC'):raise Unavailable('unknown protocol')
        if protocol=='HTTP' and typ=='application':
            # Security Hub ELB.1: an HTTP listener whose default action and every rule redirect
            # to HTTPS serves nothing in plaintext; a redirect default with incomplete rules is UNKNOWN.
            from .claude2_aws_b_edge import http_redirect_only_status
            redirect=http_redirect_only_status(listener)
            if redirect=='unresolved':raise Unavailable('HTTP redirect listener rules incomplete')
            if redirect=='redirect':return result(False,protocol=protocol,https_redirect_only=True)
        if protocol not in ('HTTPS','TLS'):return result(True,protocol=protocol)
        certs=list_of_objects(get(listener,'Certificates',list))
        return result(not (has_cert := any(get(c,'CertificateArn',str) for c in certs)),protocol=protocol,certificate_configured=has_cert)
    outcome = all_rows(list_of_objects(envelope.get('items')),check,status in ('collected','empty') and (items_coverage or {}).get('status')!='partial')
    if outcome[0] == 'PASS':
        return outcome[0], {'listener_protocols': [row['Protocol'] for row in envelope['items']], 'evaluated_listener_count': len(envelope['items'])}
    return outcome


def certificate(item,index):
    cid=get(item,'clientCertificateId',str)
    if not cid:return result(True,reason='no client certificate')
    detail=item.get('ClientCertificate')
    if not isinstance(detail,dict):raise Unavailable('missing certificate detail')
    if detail.get('absent') is True and detail.get('collection_status')=='empty':return result(True,reason='certificate not found')
    if detail.get('collection_status')!='collected':raise Unavailable('certificate detail denied or incomplete')
    if get(detail,'clientCertificateId',str)!=cid:raise Unavailable('foreign certificate identity')
    def date(v):
        if not isinstance(v,str):raise Unavailable('malformed capture or expiry date')
        t=datetime.fromisoformat(v.replace('Z','+00:00'))
        if t.tzinfo is None:raise Unavailable('date timezone missing')
        return t.astimezone(timezone.utc)
    return result(date(get(detail,'expirationDate',str))<=date(get(index,'context.created_at',str)), certificate_expires_at=get(detail,'expirationDate',str), evaluation_time=get(index,'context.created_at',str))


def monitoring(item,index):
    cluster=get(item,'DBClusterIdentifier',str)
    members=list_of_objects(get(item,'DBClusterMembers',list)); by_id,complete=inventory_map(index,'rds_instance')
    def check(ref):
        row=by_id.get(get(ref,'DBInstanceIdentifier',str))
        if row is None:raise Unavailable('unresolved cluster member')
        if get(row,'DBClusterIdentifier',str)!=cluster:raise Unavailable('foreign cluster member')
        interval=get(row,'MonitoringInterval',int)
        if interval<0:raise Unavailable('invalid monitoring interval')
        if interval==0:return result(True,reason='monitoring disabled')
        return result(not get(row,'MonitoringRoleArn',str),member=get(row,'DBInstanceIdentifier',str))
    return all_rows(members,check,complete)


def shield_response(item,index):
    arn=get(item,'ResourceArn',str)
    if ':cloudfront:' not in arn and ':loadbalancer/app/' not in arn:
        return 'NOT_APPLICABLE',{'reason':'automatic application-layer response is only applicable to ALB/CloudFront'}
    p=get(item,'Protection',dict)
    if get(p,'Id',str)!=get(item,'Id',str):raise Unavailable('foreign protection detail')
    state=get(p,'ApplicationLayerAutomaticResponse.Status',str)
    if state not in ('ENABLED','DISABLED'):raise Unavailable('unknown Shield response state')
    return result(state!='ENABLED', response_status=state)


def shield_health(item,index):
    ids=get(item,'HealthCheckIds',list)
    if any(not isinstance(x,str) or not x for x in ids) or len(set(ids))!=len(ids):raise Unavailable('malformed health-check IDs')
    if not ids:return result(True,reason='no health checks')
    details=list_of_objects(get(item,'HealthChecks',list))
    def check(identity):
        hits=[r for r in details if r.get('Id')==identity]
        if len(hits)!=1:raise Unavailable('health-check detail missing')
        row=hits[0]
        if row.get('collection_status')=='empty' and row.get('absent') is True:return result(True,reason='health check does not exist')
        if row.get('collection_status')!='collected':raise Unavailable('health check read unavailable')
        if get(row,'HealthCheck.Id',str)!=identity:raise Unavailable('foreign health-check identity')
        return result(False)
    outcome = all_rows(ids,check)
    return (outcome[0], dict(outcome[1], verified_health_check_ids=ids)) if outcome[0]=='PASS' else outcome


def retention(item,index):
    names=get(item,'MemberClusters',list)
    if not names or any(not isinstance(n,str) or not n for n in names):raise Unavailable('Redis applicability unresolved')
    by_id,complete=inventory_map(index,'elasticache_cluster')
    engines=[]
    for name in names:
        if name not in by_id:raise Unavailable('cache member missing')
        row=by_id[name]
        if get(row,'ReplicationGroupId',str)!=get(item,'ReplicationGroupId',str):raise Unavailable('foreign replication group member')
        engines.append(get(row,'Engine',str))
    if any(e not in ('redis','valkey','memcached') for e in engines):raise Unavailable('unknown cache engine')
    if len(set(engines))!=1:raise Unavailable('conflicting cache engines')
    if engines[0]!='redis':return 'NOT_APPLICABLE',{'reason':'signed predicate applies to Redis'}
    if 'SnapshotRetentionLimit' in item or 'SnapshotRetentionLimit' in item.get('_coverage',{}):value=get(item,'SnapshotRetentionLimit',int)
    elif item.get('_provenance',{}).get('native_response_complete') is True and item.get('_provenance',{}).get('operation')=='elasticache:DescribeReplicationGroups':value=0
    else:raise Unavailable('retention field incomplete')
    if value<0:raise Unavailable('invalid retention')
    if value>=15 and not complete:return unknown('cache member inventory incomplete')
    return result(value<15,retention_days=value)


def autoscaling(item,index):
    zones=get(item,'AvailabilityZones',list)
    if any(not isinstance(z,str) or not z for z in zones):raise Unavailable('malformed AZs')
    if len(set(zones))<2:return result(True,reason='fewer than two zones')
    overrides=list_of_objects(get(item,'MixedInstancesPolicy.LaunchTemplate.Overrides',list))
    types=set();unresolved=False
    for row in overrides:
        if 'InstanceRequirements' in row or 'InstanceType' not in row:unresolved=True;continue
        types.add(get(row,'InstanceType',str))
    if '' in types:raise Unavailable('empty instance type')
    if len(types)>=2:return result(False, instance_types=sorted(types), availability_zones=zones)
    if unresolved or not overrides:raise Unavailable('effective launch-template type selection unresolved')
    return result(True,reason='one explicit instance type')


HANDLERS={
 'aws.pci.vpc.peering_dns_resolution':('vpc_peering_connection',peering,()),
 'aws_vpc_uses_amazonprovided_dns':('vpc',dhcp,('dhcp_options',)),
 'aws_nist_efs_access_point_enforce_root_directory':('efs_access_point',efs,()),
 'aws_g6_elbv2_only_https_tls_listeners':('load_balancer_v2',listeners,()),
 'aws_g6_api_stage_valid_client_certificate':('rest_api_stage',certificate,()),
 'aws_fedramp_rds_cluster_members_enhanced_monitoring':('rds_cluster',monitoring,('rds_instance',)),
 'aws.nist.rds_cluster_member_enhanced_monitoring':('rds_cluster',monitoring,('rds_instance',)),
 'aws_shield_automatic_application_layer_response':('shield_protection',shield_response,()),
 'aws_shield_protection_health_checks':('shield_protection',shield_health,()),
 'aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days':('elasticache_replication_group',retention,('elasticache_cluster',)),
 'aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az':('autoscaling_group',autoscaling,()),
}


def callback(kind,fn):
    def evaluate(item,index):
        try:
            complete=member(item,index,kind)
            status,evidence=fn(item,index)
            if status=='PASS' and not complete:return unknown('parent inventory incomplete')
            return status,evidence
        except (Unavailable,ValueError,TypeError,KeyError,IndexError,AttributeError,OverflowError) as exc:
            return unknown(str(exc))
    return evaluate

CANDIDATES=[Check(cid,'aws',SPECS[cid]['category'],kind,SPECS[cid]['title'],
                  SPECS[cid]['severity'],'source_bound',SPECS[cid]['remediation_hint'],
                  callback(kind,fn),'resource',(kind,*deps))
            for cid,(kind,fn,deps) in HANDLERS.items()]
EVALUATORS={c.id:c.evaluate for c in CANDIDATES}


def install():
    """Opt-in registry admission; import alone remains inert.

    Matches accepted signed/native category compatibility; signed categories
    remain literal SPECS and source-bound companions, with controls unaltered.
    """
    from peaso.checks import register
    supported={'hardening','exposure','least_privilege','iam_graph','network'}
    for candidate in CANDIDATES:
        if candidate.id not in READY_IDS:
            continue
        runtime_category=candidate.category if candidate.category in supported else 'hardening'
        register(candidate.id,candidate.provider,runtime_category,candidate.kind,
                 candidate.title,candidate.severity,candidate.control,
                 candidate.remediation,dependencies=candidate.dependencies)(candidate.evaluate)

READY_IDS = ('aws.pci.vpc.peering_dns_resolution', 'aws_g6_api_stage_valid_client_certificate', 'aws_g6_elbv2_only_https_tls_listeners', 'aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az', 'aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days', 'aws_shield_automatic_application_layer_response', 'aws_shield_protection_health_checks', 'aws_vpc_uses_amazonprovided_dns')
