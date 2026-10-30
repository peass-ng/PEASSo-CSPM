"""Bounded offline AWS network closure review; no cloud access or secret content.

SDK identity and protocol regressions assert the root-integrated corrections.
Fixture-only witnesses never promote a row to semantic completion.
"""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path

import pytest
from scripts import audit_aws_native_contracts as native
from tests.test_peaso_collectors_aws import sdk, ACCOUNT, REGION, IDENTITY

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'docs/aws-review/network-closure-review.json'
SCOPE = ACCOUNT + '/' + REGION
LB = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/review/0123456789abcdef'
LISTENER = LB.replace(':loadbalancer/', ':listener/') + '/0123456789abcdef'
WID = '12345678-1234-1234-1234-123456789012'
WARN = f'arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/review/{WID}'
FARN = f'arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall/review'

@lru_cache(None)
def inputs():
    return tuple(json.loads(REPORT.read_text())['checks'])

@lru_cache(None)
def cohort():
    ids = {r['id'] for r in inputs()}
    return tuple(c for c in native.registry() if c.id in ids)

@lru_cache(None)
def cases():
    return native.behavior_module().CASES

def case_index(case, state):
    return deepcopy(case.get(state + '_index', case.get('case_indices', {}).get(state, case.get('index', {}))))

def check(cid):
    return next(c for c in cohort() if c.id == cid)

def run(snap, cid):
    from peaso.engine import evaluate_snapshot
    findings = evaluate_snapshot(snap, checks=[cid])['findings']
    assert findings
    return findings[0]['status']

def collect(sdk, kinds):
    from peaso.collectors import aws
    sdk[1]('sts').add_response('get_caller_identity', IDENTITY, {})
    return aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'options': {
        'regions': [REGION], 'service_concurrency': 1, 'retry_attempts': 1}}, kinds)

@pytest.mark.parametrize('c', cohort(), ids=lambda c: c.id)
def test_registered_witnesses(c):
    """Actual callbacks, explicitly synthetic and never SDK producer proof."""
    case = cases()[c.id]
    for state, default in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        if state in case:
            data, index = deepcopy(case[state]), case_index(case, state)
            before = deepcopy((data, index))
            assert c.evaluate(data, index)[0] == case.get(state + '_expect', default)
            assert (data, index) == before

@pytest.mark.parametrize('c', cohort(), ids=lambda c: c.id)
@pytest.mark.parametrize('status', ['denied', 'partial', 'not_collected', 'malformed'])
def test_unavailable_subject_and_dependencies_cannot_pass(c, status):
    from peaso.snapshot import make_snapshot
    snap = make_snapshot('aws', [SCOPE], [{'type': kind, 'scope': SCOPE, 'service': 'ec2',
        'status': status, 'items': []} for kind in {c.kind, *c.dependencies}])
    assert run(snap, c.id) != 'PASS'

@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('negative','FAIL'), ('denied','UNKNOWN'), ('missing','UNKNOWN'), ('foreign','UNKNOWN')])
def test_sdk_listener_parent_identity(sdk, mode, expected):
    elb = sdk[1]('elbv2')
    elb.add_response('describe_load_balancers', {'LoadBalancers': [{'LoadBalancerArn': LB, 'Type': 'application'}]}, {})
    elb.add_response('describe_load_balancer_attributes', {'Attributes': []}, {'LoadBalancerArn': LB})
    if mode == 'denied':
        elb.add_client_error('describe_listeners', 'AccessDenied', http_status_code=403, expected_params={'LoadBalancerArn': LB})
    else:
        rows = [] if mode == 'negative' else [{'ListenerArn': LISTENER, 'LoadBalancerArn': LB if mode != 'foreign' else LB + 'bad', 'Protocol': 'HTTPS', 'Port': 443}]
        elb.add_response('describe_listeners', {} if mode == 'missing' else {'Listeners': rows}, {'LoadBalancerArn': LB})
    observed = run(collect(sdk, ['load_balancer']), 'aws.c2b.elbv2.has_listeners')
    assert observed == expected

@pytest.mark.parametrize('value,expected', [('true','PASS'), ('false','FAIL'), ('denied','UNKNOWN'), ('absent','UNKNOWN')])
def test_sdk_alb_attribute_native_key_value(sdk, value, expected):
    elb = sdk[1]('elbv2')
    elb.add_response('describe_load_balancers', {'LoadBalancers': [{'LoadBalancerArn': LB, 'Type': 'application'}]}, {})
    args = {'LoadBalancerArn': LB}
    if value == 'denied':
        elb.add_client_error('describe_load_balancer_attributes', 'AccessDenied', http_status_code=403, expected_params=args)
    else:
        elb.add_response('describe_load_balancer_attributes', {'Attributes': [] if value == 'absent' else [{'Key':'access_logs.s3.enabled','Value':value}]}, args)
    elb.add_response('describe_listeners', {'Listeners': []}, args)
    assert run(collect(sdk, ['load_balancer']), 'aws.b.alb.access_logs') == expected


def web_acl(with_rule=True, foreign=False):
    arn = WARN.replace('/review/', '/foreign/') if foreign else WARN
    return {'Name': 'foreign' if foreign else 'review', 'Id': WID, 'ARN': arn,
        'DefaultAction': {'Allow': {}}, 'VisibilityConfig': {'SampledRequestsEnabled': True,
        'CloudWatchMetricsEnabled': True, 'MetricName': 'review'},
        'Rules': [{'Name':'rate', 'Priority':1, 'Statement': {'RateBasedStatement': {'Limit': 100, 'AggregateKeyType':'IP'}},
        'Action': {'Block':{}}, 'VisibilityConfig': {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled':True, 'MetricName':'rate'}}] if with_rule else []}

@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('negative','FAIL'), ('denied','UNKNOWN'), ('missing','UNKNOWN'), ('foreign','UNKNOWN')])
def test_sdk_waf_detail_identity(sdk, mode, expected):
    waf = sdk[1]('wafv2')
    waf.add_response('list_web_acls', {'WebACLs':[{'Name':'review','Id':WID,'ARN':WARN}]}, {'Scope':'REGIONAL','Limit':100})
    args = {'Name':'review','Id':WID,'Scope':'REGIONAL'}
    if mode == 'denied':
        waf.add_client_error('get_web_acl', 'AccessDeniedException', http_status_code=403, expected_params=args)
    else:
        waf.add_response('get_web_acl', {} if mode == 'missing' else {'WebACL':web_acl(mode != 'negative', mode == 'foreign')}, args)
    waf.add_client_error('get_logging_configuration', 'WAFNonexistentItemException', expected_params={'ResourceArn':WARN})
    from peaso.collectors.aws_facts_compute_edge import _WAFV2_RESOURCE_TYPES
    for resource_type in _WAFV2_RESOURCE_TYPES:
        waf.add_response('list_resources_for_web_acl', {'ResourceArns':[]}, {'WebACLArn':WARN,'ResourceType':resource_type})
    waf.add_response('list_web_acls', {'WebACLs':[]}, {'Scope':'CLOUDFRONT','Limit':100})
    observed = run(collect(sdk, ['wafv2_web_acl']), 'aws.cb.wafv2.web_acl_has_rules')
    assert observed == expected


@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('negative','FAIL'), ('denied','UNKNOWN'), ('foreign','UNKNOWN')])
def test_sdk_waf_logging_identity(sdk, mode, expected):
    from peaso.collectors import aws
    session, add, _ = sdk
    waf = add('wafv2')
    args = {'ResourceArn': WARN}
    if mode == 'denied':
        waf.add_client_error('get_logging_configuration', 'AccessDeniedException', http_status_code=403, expected_params=args)
    elif mode == 'negative':
        waf.add_client_error('get_logging_configuration', 'WAFNonexistentItemException', expected_params=args)
    else:
        waf.add_response('get_logging_configuration', {'LoggingConfiguration': {
            'ResourceArn':WARN+'foreign' if mode == 'foreign' else WARN,
            'LogDestinationConfigs':[f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:aws-waf-logs-review']}}, args)
    response = aws.Requests({'retry_attempts':1}).detail(session,'wafv2',REGION,'get_logging_configuration',
        ResourceArn=WARN, absent=('WAFNonexistentItemException',))
    # Invoke the actual fetcher for projection/identity validation separately in
    # detail tests; this directed consumer join currently has no identity guard.
    item = {'ARN':WARN, 'Id':WID, 'Name':'review', 'LoggingConfiguration':response}
    observed = check('aws.cb.wafv2.web_acl_logging').evaluate(item,{})[0]
    assert observed == expected


@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('denied','UNKNOWN'), ('missing','UNKNOWN'), ('foreign','UNKNOWN')])
def test_sdk_firewall_detail_identity(sdk, mode, expected):
    fw = sdk[1]('network-firewall')
    fw.add_response('list_firewalls', {'Firewalls':[{'FirewallName':'review','FirewallArn':FARN}]}, {})
    if mode == 'denied':
        fw.add_client_error('describe_firewall', 'AccessDeniedException', http_status_code=403, expected_params={'FirewallArn':FARN})
    else:
        fw.add_response('describe_firewall', {} if mode == 'missing' else {'Firewall': {'FirewallName':'review','FirewallArn': FARN + '-foreign' if mode == 'foreign' else FARN,
            'FirewallPolicyArn':FARN.replace(':firewall/', ':firewall-policy/'), 'VpcId':'vpc-1234',
            'SubnetMappings':[{'SubnetId':'subnet-1234'}], 'FirewallId': WID}}, {'FirewallArn':FARN})
    # This call uses the foreign identity before the proposed merge guard.
    # ANY keeps the SDK response validated without guessing runtime integration.
    from botocore.stub import ANY
    fw.add_response('describe_logging_configuration', {}, {'FirewallArn': ANY})
    observed = run(collect(sdk, ['network_firewall']), 'aws.claude_a.networkfirewall.in_vpc')
    assert observed == expected

@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('negative','FAIL'), ('denied','UNKNOWN')])
def test_sdk_stage_dynamic_method_map(sdk, mode, expected):
    api = sdk[1]('apigateway')
    api.add_response('get_rest_apis', {'items':[{'id':'abc123','name':'review'}]}, {})
    if mode == 'denied':
        api.add_client_error('get_stages', 'AccessDeniedException', http_status_code=403, expected_params={'restApiId':'abc123'})
    else:
        api.add_response('get_stages', {'item':[{'stageName':'review', 'tracingEnabled':mode == 'positive',
            'methodSettings': {'*/*': {'loggingLevel': 'INFO', 'cachingEnabled':True, 'cacheDataEncrypted':True}}}]}, {'restApiId':'abc123'})
    observed = run(collect(sdk, ['rest_api_stage']), 'aws.b.apigateway.rest_xray')
    assert observed in ({'DENIED','UNKNOWN'} if mode == 'denied' else {expected})

@pytest.mark.parametrize('tokens,expected', [('required','PASS'), ('optional','FAIL'), ('denied','DENIED')])
def test_sdk_instance_native_projection(sdk, tokens, expected):
    ec2 = sdk[1]('ec2')
    if tokens == 'denied':
        ec2.add_client_error('describe_instances', 'UnauthorizedOperation', http_status_code=403, expected_params={})
    else:
        ec2.add_response('describe_instances', {'Reservations':[{'Instances':[{'InstanceId':'i-1234567890abcdef0',
            'State':{'Name':'running'}, 'MetadataOptions':{'HttpTokens':tokens,'HttpEndpoint':'enabled'}}]}]}, {})
        ec2.add_response('describe_instance_attribute', {'InstanceId':'i-1234567890abcdef0'}, {'InstanceId':'i-1234567890abcdef0','Attribute':'userData'})
        ec2.add_response('describe_instance_attribute', {'InstanceId':'i-1234567890abcdef0','DisableApiTermination':{'Value':False}}, {'InstanceId':'i-1234567890abcdef0','Attribute':'disableApiTermination'})
    assert run(collect(sdk, ['instance']), 'aws.ec2.imdsv2') == expected




CF_CHECKS = [c for c in cohort() if c.kind=='cloudfront_distribution' and c.id not in {
    'aws.cb.shield.cloudfront_protected','aws.c2b.cloudfront.s3_origin_bucket_exists','aws_cloudfront_origin_failover_configured'}]

@pytest.mark.parametrize('c',CF_CHECKS,ids=lambda c:c.id)
@pytest.mark.parametrize('mode',['positive','negative','missing','denied'])
def test_sdk_cloudfront_config_projection(sdk,c,mode):
    from peaso.collectors import aws, aws_b_services, aws_facts_compute_edge as edge
    session,add,_=sdk
    config={'CallerReference':'review','Comment':'','Enabled':True,
        'Origins':{'Quantity':1,'Items':[{'Id':'origin','DomainName':'app.example.org',
            'CustomOriginConfig':{'HTTPPort':80,'HTTPSPort':443,'OriginProtocolPolicy':'https-only',
                'OriginSslProtocols':{'Quantity':1,'Items':['TLSv1.2']}}}]},
        'DefaultCacheBehavior':{'TargetOriginId':'origin','ViewerProtocolPolicy':'https-only','FieldLevelEncryptionId':'field'},
        'CacheBehaviors':{'Quantity':0},
        'Logging':{'Enabled':True,'Bucket':'logs.s3.amazonaws.com','Prefix':'','IncludeCookies':False},
        'ViewerCertificate':{'ACMCertificateArn':f'arn:aws:acm:{REGION}:{ACCOUNT}:certificate/review',
            'Certificate':f'arn:aws:acm:{REGION}:{ACCOUNT}:certificate/review','SSLSupportMethod':'sni-only',
            'MinimumProtocolVersion':'TLSv1.2_2021'},
        'DefaultRootObject':'index.html','WebACLId':WARN,
        'Restrictions':{'GeoRestriction':{'RestrictionType':'whitelist','Quantity':1,'Items':['ES']}},
        'OriginGroups':{'Quantity':1,'Items':[{'Id':'group','FailoverCriteria':{'StatusCodes':{'Quantity':1,'Items':[500]}},
            'Members':{'Quantity':2,'Items':[{'OriginId':'origin'},{'OriginId':'backup'}]}}]}}
    if c.id.endswith('origin_traffic_encrypted'):config['OriginGroups']={'Quantity':0}
    if mode=='negative':
        cid=c.id
        if cid.endswith(('access_logging','logging_any')):config['Logging']['Enabled']=False
        elif cid.endswith('.sni'):config['ViewerCertificate']['SSLSupportMethod']='vip'
        elif cid.endswith('custom_acm_certificate'):config['ViewerCertificate']={'CloudFrontDefaultCertificate':True}
        elif cid.endswith('default_root_object'):config['DefaultRootObject']=''
        elif cid.endswith('field_level_encryption'):config['DefaultCacheBehavior']['FieldLevelEncryptionId']=''
        elif cid.endswith('waf_reference'):config['WebACLId']=''
        elif cid.endswith('geo_restrictions'):config['Restrictions']['GeoRestriction']={'RestrictionType':'none','Quantity':0}
        elif cid.endswith('origin_group_metadata'):config['OriginGroups']={'Quantity':0}
        elif cid.endswith('origin_no_deprecated_ssl'):config['Origins']['Items'][0]['CustomOriginConfig']['OriginSslProtocols']['Items']=['TLSv1']
        elif cid.endswith('origin_traffic_encrypted'):config['Origins']['Items'][0]['CustomOriginConfig']['OriginProtocolPolicy']='http-only'
        elif cid.endswith('recommended_tls_policy'):config['ViewerCertificate']['MinimumProtocolVersion']='TLSv1'
        else:raise AssertionError('unhandled CloudFront case '+cid)
    if mode=='denied':add('cloudfront').add_client_error('get_distribution_config','AccessDenied',http_status_code=403,expected_params={'Id':'E123'})
    else:add('cloudfront').add_response('get_distribution_config',{} if mode=='missing' else {'DistributionConfig':config},{'Id':'E123'})
    requests=aws.Requests({'retry_attempts':1})
    item=aws_b_services._enricher('cloudfront_distribution')(requests,session,REGION,[{'Id':'E123','ARN':f'arn:aws:cloudfront::{ACCOUNT}:distribution/E123'}])[0]
    if c.id.endswith('logging_any'):
        add('logs').add_response('describe_delivery_sources',{'deliverySources':[]},{})
        add('logs').add_response('describe_deliveries',{'deliveries':[]},{})
        item=edge._cloudfront_log_deliveries(requests,session,REGION,[item])[0]
    assert c.evaluate(item,{})[0] == ('PASS' if mode=='positive' else 'FAIL' if mode=='negative' else 'UNKNOWN')


PORT_CHECKS = [c for c in cohort() if '.instance_port_' in c.id or c.id in {
    'aws.claude_a.ec2.enclave_host_ingress_allowlist', 'aws.claude_a.ec2.enclave_host_vsock_ports_closed'}]

@pytest.mark.parametrize('c', PORT_CHECKS, ids=lambda c: c.id)
@pytest.mark.parametrize('mode', ['closed', 'tcp', '6', '17', 'all', 'reversed', 'missing', 'missing_ranges', 'malformed_cidr', 'wrong_family', 'denied'])
def test_sdk_instance_security_group_join(sdk, c, mode):
    from peaso.checks.claude_aws_a_ec2 import INSTANCE_PORTS
    ec2 = sdk[1]('ec2')
    instance_id = 'i-1234567890abcdef0'
    instance = {'InstanceId': instance_id, 'State': {'Name':'running'},
        'SecurityGroups': [{'GroupId':'sg-1234'}], 'EnclaveOptions': {'Enabled': True}}
    ec2.add_response('describe_instances', {'Reservations':[{'Instances':[instance]}]}, {})
    ec2.add_response('describe_instance_attribute', {'InstanceId':instance_id}, {'InstanceId':instance_id,'Attribute':'userData'})
    ec2.add_response('describe_instance_attribute', {'InstanceId':instance_id,'DisableApiTermination':{'Value':False}}, {'InstanceId':instance_id,'Attribute':'disableApiTermination'})
    if mode == 'denied':
        ec2.add_client_error('describe_security_groups', 'UnauthorizedOperation', http_status_code=403, expected_params={})
    else:
        service = c.id.split('.instance_port_')[-1].split('_not_internet_exposed')[0]
        port = INSTANCE_PORTS[service][0] if service in INSTANCE_PORTS else 8000
        rule = {'IpProtocol': '-1' if mode == 'all' else mode if mode in {'6','17'} else 'tcp',
            'FromPort':port+1 if mode == 'reversed' else port, 'ToPort':port,
            'IpRanges':[{'CidrIp':'0.0.0.0/0'}], 'Ipv6Ranges':[]}
        if mode in {'missing','all'}:
            rule.pop('FromPort'); rule.pop('ToPort')
        if mode == 'missing_ranges':rule.pop('IpRanges')
        if mode == 'malformed_cidr':rule['IpRanges']=[{'CidrIp':'invalid-world-cidr'}]
        if mode == 'wrong_family':rule['IpRanges']=[{'CidrIp':'::/0'}]
        ec2.add_response('describe_security_groups', {'SecurityGroups':[{'GroupId':'sg-1234',
            'IpPermissions':[] if mode == 'closed' else [rule]}]}, {})
    expected = 'PASS' if mode == 'closed' else 'UNKNOWN' if mode in {'reversed','missing','missing_ranges','malformed_cidr','wrong_family','denied'} else 'FAIL'
    if mode=='17' and c.id!='aws.claude_a.ec2.enclave_host_ingress_allowlist':expected='PASS'
    observed = run(collect(sdk, ['instance','security_group']), c.id)
    assert observed == expected



@pytest.mark.parametrize('cid', ['aws.claude_a.ec2.enclave_host_ingress_allowlist','aws.claude_a.ec2.enclave_host_vsock_ports_closed'])
@pytest.mark.parametrize('cidr', [None, 17, {}, []])
def test_enclave_nonstring_cidr_unavailable(cid, cidr):
    case=cases()[cid]
    item,index=deepcopy(case['pass']),case_index(case,'pass')
    for wrapper in index['security_group']:
        wrapper['data']['IpPermissions']=[{'IpProtocol':'tcp','FromPort':8000,'ToPort':8000,
            'IpRanges':[{'CidrIp':cidr}],'Ipv6Ranges':[]}]
    observed=check(cid).evaluate(item,index)[0]
    assert observed=='UNKNOWN'
