"""Native direct-ingress configuration counterexamples and independent joins."""
import copy
import pytest
from peaso.snapshot import make_snapshot
from peaso.analysis.aws_public_ingress import witness,MODEL,DEPENDENCIES
from peaso.collectors import aws,aws_public_ingress_native as native
from peaso.collectors import collect_live
from peaso.engine import evaluate_snapshot
from peaso.analysis import analyze
from test_peaso_aws_bulk_inventory import sdk,ACCOUNT,REGION

SCOPE=ACCOUNT+'/'+REGION
CHECKS=['aws.nist.ec2_instance_effective_public_reachability','aws_fedramp_ec2_effective_public_exposure']


def facts():
    eni={'NetworkInterfaceId':'eni-12345678','VpcId':'vpc-12345678','SubnetId':'subnet-12345678',
         'Status':'in-use','InterfaceType':'interface','RequesterManaged':False,
         'Attachment':{'AttachmentId':'eni-attach-12345678','InstanceId':'i-12345678','Status':'attached'},
         'PrivateIpAddress':'10.0.1.5','PrivateIpAddresses':[{'PrivateIpAddress':'10.0.1.5','Primary':True,'Association':{'PublicIp':'54.1.2.3'}}],
         'Groups':[{'GroupId':'sg-12345678'}]}
    instance={'InstanceId':'i-12345678','State':{'Name':'running'},'VpcId':eni['VpcId'],'SubnetId':eni['SubnetId'],
              'PublicIpAddress':'54.1.2.3','NetworkInterfaces':[copy.deepcopy(eni)]}
    return {'instance':[instance],'network_interface':[eni],
      'vpc':[{'VpcId':eni['VpcId'],'CidrBlock':'10.0.0.0/16','State':'available'}],
      'subnet':[{'SubnetId':eni['SubnetId'],'VpcId':eni['VpcId'],'CidrBlock':'10.0.1.0/24','State':'available'}],
      'security_group':[{'GroupId':'sg-12345678','VpcId':eni['VpcId'],'IpPermissions':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}]}],
      'network_acl':[{'NetworkAclId':'acl-12345678','VpcId':eni['VpcId'],'Associations':[{'SubnetId':eni['SubnetId']}],
                       'Entries':[{'RuleNumber':100,'Egress':egress,'Protocol':'-1','RuleAction':'allow','CidrBlock':'0.0.0.0/0'}for egress in(False,True)] + [{'RuleNumber':32767,'Egress':egress,'Protocol':'-1','RuleAction':'deny','CidrBlock':'0.0.0.0/0'}for egress in(False,True)]}],
      'route_table':[{'RouteTableId':'rtb-12345678','VpcId':eni['VpcId'],
                      'Associations':[{'Main':True,'AssociationState':{'State':'associated'}}],
                      'Routes':[{'DestinationCidrBlock':'10.0.0.0/16','GatewayId':'local','State':'active'},
                                {'DestinationCidrBlock':'0.0.0.0/0','GatewayId':'igw-12345678','State':'active'}]}],
      'internet_gateway':[{'InternetGatewayId':'igw-12345678','Attachments':[{'VpcId':eni['VpcId'],'State':'available'}]}],
      'vpc_block_public_access_options':[{'VpcBlockPublicAccessOptions':{'InternetGatewayBlockMode':'off','State':'default-state'}}]}


def snapshot(rows,statuses=None,projection=True,proof_override=None):
    env=[{'type':kind,'scope':SCOPE,'status':(statuses or{}).get(kind,'collected'if items else'empty'),'items':[]if(statuses or{}).get(kind)=='not_collected'else items}for kind,items in rows.items()]
    snap=make_snapshot('aws',[SCOPE],env)
    proof=witness(snap,SCOPE,'i-12345678')
    if projection:
        env.extend([{'type':'ec2_instance','scope':SCOPE,'status':'collected','items':rows['instance']},
                    {'type':'ec2_effective_ingress','scope':SCOPE,'status':'collected','items':[{'InstanceId':'i-12345678','proof_model':MODEL,
                    'joins_complete':False,'configured_path_witness':proof if proof_override is None else proof_override}]}])
        snap=make_snapshot('aws',[SCOPE],env)
    return snap


def decisions(snap):return[f['status']for f in evaluate_snapshot(snap,checks=CHECKS)['findings']]


def test_native_witness_is_configuration_counterexample_not_listener_or_universe():
    snap=snapshot(facts());proof=witness(snap,SCOPE,'i-12345678')
    assert proof['destination_port']==443 and proof['protocol']=='tcp'
    assert proof['application_listening']=='unknown' and proof['network_probes']is False
    assert proof['all_paths_evaluated']is False
    assert decisions(snap)==['FAIL','FAIL']


def test_internet_exposure_uses_only_reverified_narrow_public_source_witness():
    rows=facts()
    rows['security_group'][0]['IpPermissions'][0]['IpRanges']=[{'CidrIp':'8.8.8.8/32'}]
    snap=snapshot(rows)
    findings=[f for f in analyze(snap)['findings'] if f['check_id']=='analysis.internet_exposure' and f['status']=='FAIL']
    assert len(findings)==1
    path=findings[0]['evidence']['path']
    assert path[-1]['layer']=='configured_path_witness'
    assert path[-1]['source_address']=='8.8.8.8'
    assert findings[0]['evidence']['exposed_ports']==['tcp/443']
    projection=next(c for c in snap['collections'] if c['type']=='ec2_effective_ingress')
    projection['items'][0]['configured_path_witness']['source_address']='1.1.1.1'
    tampered=make_snapshot('aws',[SCOPE],snap['collections'])
    mismatched=[f for f in analyze(tampered)['findings'] if f['check_id']=='analysis.internet_exposure'
                and f['resource_id']==findings[0]['resource_id']]
    assert len(mismatched)==1 and mismatched[0]['status']=='UNKNOWN'


@pytest.mark.parametrize('mode',[
 'bpa_ingress','bpa_bidirectional','bpa_transition','bpa_unknown','bpa_foreign','missing_bpa',
 'sg_closed','nacl_ingress_deny','nacl_return_deny','nacl_foreign_vpc','missing_nacl',
 'route_blackhole','route_nat','more_specific_nat','edge_appliance','route_transition','route_missing_state',
 'igw_detached','igw_foreign','public_mapping_disagree','public_not_global','private_outside_subnet',
 'eni_foreign_instance','eni_detached','eni_managed','eni_vpc_disagree','eni_missing_native','stopped',
 'sg_foreign_vpc','incomplete_sg','duplicate_subnet','foreign_account','no_eni_declaration'])
def test_incomplete_or_blocked_supported_path_stays_unknown(mode):
    rows=facts();statuses={}
    if mode.startswith('bpa_'):
        options=rows['vpc_block_public_access_options'][0]['VpcBlockPublicAccessOptions']
        if mode=='bpa_ingress':options['InternetGatewayBlockMode']='block-ingress'
        if mode=='bpa_bidirectional':options['InternetGatewayBlockMode']='block-bidirectional'
        if mode=='bpa_transition':options['State']='update-in-progress'
        if mode=='bpa_unknown':options.pop('State')
        if mode=='bpa_foreign':options['AwsAccountId']='999999999999'
    if mode=='missing_bpa':statuses['vpc_block_public_access_options']='not_collected'
    if mode=='sg_closed':rows['security_group'][0]['IpPermissions']=[]
    if mode in('nacl_ingress_deny','nacl_return_deny'):rows['network_acl'][0]['Entries'][0 if mode=='nacl_ingress_deny'else 1]['RuleAction']='deny'
    if mode=='nacl_foreign_vpc':rows['network_acl'][0]['VpcId']='vpc-foreign'
    if mode=='missing_nacl':rows['network_acl']=[]
    if mode=='route_blackhole':rows['route_table'][0]['Routes'][1]['State']='blackhole'
    if mode=='route_nat':rows['route_table'][0]['Routes'][1]['GatewayId']='nat-12345678'
    if mode=='more_specific_nat':rows['route_table'][0]['Routes'].append({'DestinationCidrBlock':'0.0.0.0/1','NatGatewayId':'nat-12345678','State':'active'});rows['route_table'][0]['Routes'].append({'DestinationCidrBlock':'128.0.0.0/1','NatGatewayId':'nat-12345678','State':'active'})
    if mode=='edge_appliance':rows['route_table'].append({'RouteTableId':'rtb-edge','VpcId':'vpc-12345678','Associations':[{'GatewayId':'igw-12345678','AssociationState':{'State':'associated'}}],'Routes':[{'DestinationCidrBlock':'10.0.0.0/16','NetworkInterfaceId':'eni-appliance','State':'active'}]})
    if mode=='route_transition':rows['route_table'][0]['Associations'][0]['AssociationState']['State']='associating'
    if mode=='route_missing_state':rows['route_table'][0]['Associations'][0].pop('AssociationState')
    if mode=='igw_detached':rows['internet_gateway'][0]['Attachments']=[]
    if mode=='igw_foreign':rows['internet_gateway'][0]['Attachments'][0]['VpcId']='vpc-foreign'
    if mode=='public_mapping_disagree':rows['instance'][0]['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['Association']['PublicIp']='54.9.9.9'
    if mode=='public_not_global':
        for obj in(rows['network_interface'][0],rows['instance'][0]['NetworkInterfaces'][0]):obj['PrivateIpAddresses'][0]['Association']['PublicIp']='192.0.2.5'
    if mode=='private_outside_subnet':rows['subnet'][0]['CidrBlock']='10.0.2.0/24'
    if mode=='eni_foreign_instance':rows['network_interface'][0]['Attachment']['InstanceId']='i-foreign'
    if mode=='eni_detached':rows['network_interface'][0]['Attachment']['Status']='detached'
    if mode=='eni_managed':rows['network_interface'][0]['RequesterManaged']=True
    if mode=='eni_vpc_disagree':rows['network_interface'][0]['VpcId']='vpc-foreign'
    if mode=='eni_missing_native':rows['network_interface']=[]
    if mode=='stopped':rows['instance'][0]['State']['Name']='stopped'
    if mode=='sg_foreign_vpc':rows['security_group'][0]['VpcId']='vpc-foreign'
    if mode=='incomplete_sg':statuses['security_group']='partial'
    if mode=='duplicate_subnet':rows['subnet'].append(copy.deepcopy(rows['subnet'][0]))
    if mode=='foreign_account':rows['subnet'][0]['AccountId']='999999999999'
    if mode=='no_eni_declaration':rows['instance'][0]['NetworkInterfaces']=[]
    assert decisions(snapshot(rows,statuses))==['UNKNOWN','UNKNOWN']


def test_forged_projection_rejected_against_independent_native_scope():
    good=snapshot(facts());proof=witness(good,SCOPE,'i-12345678')
    rows=facts();rows['security_group'][0]['IpPermissions']=[]
    assert decisions(snapshot(rows,proof_override=proof))==['UNKNOWN','UNKNOWN']


@pytest.mark.parametrize('native_datetimes',[False,True])
def test_sdk_collect_live_projection_requests_exact_dependencies_and_checks(sdk,native_datetimes):
    session,add=sdk;sts=add('sts');ec2=add('ec2');rows=facts()
    if native_datetimes:
        from datetime import datetime,timezone
        stamp=datetime(2026,10,15,0,0,tzinfo=timezone.utc)
        rows['instance'][0]['LaunchTime']=stamp
        rows['instance'][0]['NetworkInterfaces'][0]['Attachment']['AttachTime']=stamp
        rows['network_interface'][0]['Attachment']['AttachTime']=stamp
    sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/audit','UserId':'audit'}, {})
    rows['instance'][0]['NetworkInterfaces'][0].pop('RequesterManaged')
    rows['instance'][0]['NetworkInterfaces'][0]['Attachment'].pop('InstanceId')
    # The projection is first alphabetically; later native reads hit its cache.
    for dependency in sorted(DEPENDENCIES):
        if dependency=='vpc_block_public_access_options':ec2.add_response('describe_vpc_block_public_access_options',rows[dependency][0],{})
        else:
            _,operation,key=aws.SPECS[dependency]
            response={'Reservations':[{'Instances':rows[dependency]}]}if dependency=='instance'else{key:rows[dependency]}
            ec2.add_response(operation,response,{})
    connector={'provider':'aws','auth':{'profile':'unit-test'},'scopes':[SCOPE],
               'options':{'inventories':['ec2_instance','ec2_effective_ingress'],'max_resources':200,'retry_attempts':1,'service_concurrency':1}}
    # Existing SDK fixture supplies the session; collector auth accepts profile.
    from unittest.mock import patch
    with patch.object(aws,'_session',return_value=(session,'test-pinned')):snap=collect_live(connector,['ec2_instance','ec2_effective_ingress'])
    assert decisions(snap)==['FAIL','FAIL']
    assert DEPENDENCIES<={c['type']for c in snap['collections']if c['status']=='collected'}
    sts.assert_no_pending_responses();ec2.assert_no_pending_responses()


@pytest.mark.parametrize('mode',['udp','custom_source','known_allow_union','higher_nacl_deny','duplicate_gateway','mismatched_projection'])
def test_additional_native_path_and_provenance_semantics(mode):
    rows=facts()
    if mode=='udp':rows['security_group'][0]['IpPermissions'][0].update(IpProtocol='udp',FromPort=53,ToPort=53)
    if mode=='custom_source':rows['security_group'][0]['IpPermissions'][0]['IpRanges']=[{'CidrIp':'54.19.20.0/30'}]
    if mode=='known_allow_union':rows['security_group'][0]['IpPermissions'].insert(0,{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'PrefixListIds':[{'PrefixListId':'pl-unknown'}]})
    if mode=='higher_nacl_deny':rows['network_acl'][0]['Entries'].insert(0,{'RuleNumber':50,'Egress':False,'Protocol':'-1','RuleAction':'deny','CidrBlock':'0.0.0.0/0'})
    if mode=='duplicate_gateway':rows['internet_gateway'].append({**rows['internet_gateway'][0],'Tags':[{'Key':'duplicate','Value':'different'}]})
    snap=snapshot(rows)
    if mode=='mismatched_projection':
        for env in snap['collections']:
            if env['type']=='ec2_instance':env['items'][0]['State']['Name']='stopped'
        snap=make_snapshot('aws',[SCOPE],snap['collections'])
    expected='UNKNOWN'if mode in('higher_nacl_deny','duplicate_gateway','mismatched_projection')else'FAIL'
    assert decisions(snap)==[expected,expected]
    if expected=='FAIL':
        proof=witness(snap,SCOPE,'i-12345678')
        assert {'security_group','network_acl','internet_gateway','instance','network_interface','route_table','vpc_block_public_access_options'}<={r['type']for r in proof['native_evidence_refs']}
        if mode=='udp':assert proof['protocol']=='udp'and proof['destination_port']==53
        if mode=='custom_source':assert proof['source_address'].startswith('54.19.20.')


def test_model_uses_only_existing_readonly_iam_actions():
    from scripts.peaso_deploy_customer_policy import iam_action
    assert native.READ_ACTIONS<=aws.READ_ACTIONS
    assert all(iam_action(*pair).startswith('ec2:Describe')for pair in native.READ_ACTIONS)


def test_dependency_expansion_is_pure_exact_and_provider_scoped():
    from peaso.collectors.bulk_evidence import expand_native_requirements
    selected={'ec2_instance','ec2_effective_ingress'};before=set(selected)
    assert expand_native_requirements('aws',selected)==selected|DEPENDENCIES
    assert selected==before
    assert expand_native_requirements('aws',{'ec2_instance'})=={'ec2_instance'}
    assert expand_native_requirements('azure',selected)==selected


def test_explicit_inventory_omission_does_not_activate_projection_or_parents():
    from types import SimpleNamespace
    from peaso.collectors.bulk_evidence import collect
    seen={}
    def reader(connector,requirements):
        seen.update(inventories=connector['options']['inventories'],requirements=requirements)
        return make_snapshot('aws',[SCOPE],[{'type':'instance','scope':SCOPE,'status':'empty','items':[]}])
    module=SimpleNamespace(AWS_TYPES=aws.AWS_TYPES,collect=reader)
    options={'inventories':['ec2_instance']}
    collect(module,{'provider':'aws','scopes':[SCOPE],'options':options},['ec2_instance','ec2_effective_ingress'])
    assert seen['inventories']==['instance']
    assert options=={'inventories':['ec2_instance']}
    # The provider's existing intersection preserves the explicit allowlist.
    assert set(seen['requirements'])&set(seen['inventories'])=={'instance'}


def test_shared_model_is_prepared_once_for_both_signed_checks():
    from unittest.mock import patch
    from peaso.analysis import aws_public_ingress as analysis
    snap=snapshot(facts())
    with patch.object(analysis,'prepare',wraps=analysis.prepare)as prepare_model:
        assert decisions(snap)==['FAIL','FAIL']
    assert prepare_model.call_count==1


@pytest.mark.parametrize('mode',['denied','partial'])
def test_native_request_failure_never_yields_synthetic_witness(sdk,mode):
    session,add=sdk;ec2=add('ec2');rows=facts()
    if mode=='denied':ec2.add_client_error('describe_instances','UnauthorizedOperation',http_status_code=403,expected_params={})
    else:
        instance=copy.deepcopy(rows['instance'][0]);instance['NetworkInterfaces'][0].pop('RequesterManaged');instance['NetworkInterfaces'][0]['Attachment'].pop('InstanceId')
        ec2.add_response('describe_instances',{'Reservations':[{'Instances':[instance]}],'NextToken':'more'}, {})
    read=native.effective_ingress(aws.Requests({'retry_attempts':1,'max_pages':1}),session,REGION,ACCOUNT)
    assert read.status not in('collected','empty')and read.items==[]
    ec2.assert_no_pending_responses()


def test_self_public_address_is_not_an_external_source_witness():
    rows=facts();rows['security_group'][0]['IpPermissions'][0]['IpRanges']=[{'CidrIp':'54.1.2.3/32'}]
    assert decisions(snapshot(rows))==['UNKNOWN','UNKNOWN']


def test_native_datetime_projection_preserves_shared_sdk_cache_and_real_witness(sdk):
    from datetime import datetime,timezone
    import json
    session,add=sdk;ec2=add('ec2');rows=facts()
    stamp=datetime(2026,10,15,0,0,tzinfo=timezone.utc)
    rows['instance'][0]['LaunchTime']=stamp
    rows['instance'][0]['NetworkInterfaces'][0]['Attachment']['AttachTime']=stamp
    rows['network_interface'][0]['Attachment']['AttachTime']=stamp
    rows['instance'][0]['NetworkInterfaces'][0].pop('RequesterManaged')
    rows['instance'][0]['NetworkInterfaces'][0]['Attachment'].pop('InstanceId')
    before=copy.deepcopy(rows)
    for dependency in sorted(DEPENDENCIES):
        if dependency=='vpc_block_public_access_options':ec2.add_response('describe_vpc_block_public_access_options',rows[dependency][0],{})
        else:
            _,operation,key=aws.SPECS[dependency]
            response={'Reservations':[{'Instances':rows[dependency]}]}if dependency=='instance'else{key:rows[dependency]}
            ec2.add_response(operation,response,{})
    requests=aws.Requests({'retry_attempts':1})
    read=native.effective_ingress(requests,session,REGION,ACCOUNT)
    assert read.status=='collected'and read.items[0]['configured_path_witness']is not None
    instance=requests.pages(session,'ec2',REGION,'describe_instances','Reservations[].Instances[]')
    interface=requests.pages(session,'ec2',REGION,'describe_network_interfaces','NetworkInterfaces')
    assert instance.items==before['instance'] and interface.items==before['network_interface']
    assert type(instance.items[0]['LaunchTime'])is datetime
    assert type(interface.items[0]['Attachment']['AttachTime'])is datetime
    assert instance.items[0]['LaunchTime']==stamp
    assert requests.calls==9 and requests.cache_hits==2
    normalized={kind:aws._safe(items)for kind,items in rows.items()}
    snap=snapshot(normalized)
    for env in snap['collections']:
        if env['type']=='ec2_effective_ingress':env['items']=read.items
    snap=make_snapshot('aws',[SCOPE],snap['collections'])
    assert decisions(snap)==['FAIL','FAIL']
    assert normalized['instance'][0]['LaunchTime']==stamp.isoformat()
    json.dumps(snap)
    assert rows==before
    ec2.assert_no_pending_responses()
