"""A missing launch-configuration IP flag inherits subnet behavior, not false."""
from datetime import datetime, timezone
import boto3
import pytest
from botocore.stub import Stubber
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ACCOUNT='123456789012'
REGION='us-east-1'
SCOPE=f'{ACCOUNT}/{REGION}'
LC_ARN=f'arn:aws:autoscaling:{REGION}:{ACCOUNT}:launchConfiguration:qa:launchConfigurationName/qa'
ASG_ARN=f'arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:12345678-1234-1234-1234-123456789012:autoScalingGroupName/group'
IDS=('aws.c2b.autoscaling.lc_no_public_ip','aws.c2b.autoscaling.group_lc_no_public_ip')


def collect(monkeypatch, value='omitted'):
    session=boto3.Session(aws_access_key_id='INERT',aws_secret_access_key='INERT',region_name=REGION)
    sts, scaling=session.client('sts'),session.client('autoscaling')
    stamp=datetime(2026,1,1,tzinfo=timezone.utc)
    lc={'LaunchConfigurationName':'qa','LaunchConfigurationARN':LC_ARN,'ImageId':'ami-12345678','InstanceType':'t3.micro','CreatedTime':stamp}
    if value!='omitted':lc['AssociatePublicIpAddress']=value
    group={'AutoScalingGroupARN':ASG_ARN,'AutoScalingGroupName':'group','LaunchConfigurationName':'qa',
           'MinSize':0,'MaxSize':1,'DesiredCapacity':0,'DefaultCooldown':300,'AvailabilityZones':['us-east-1a'],
           'HealthCheckType':'EC2','CreatedTime':stamp,'VPCZoneIdentifier':'subnet-12345678'}
    with Stubber(sts) as st, Stubber(scaling) as sc:
        st.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/reviewer','UserId':'AIDAREVIEWER'},{})
        sc.add_response('describe_auto_scaling_groups',{'AutoScalingGroups':[group]},{})
        sc.add_response('describe_launch_configurations',{'LaunchConfigurations':[lc]},{})
        monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'fixture'))
        clients={('sts',REGION):sts,('autoscaling',REGION):scaling}
        monkeypatch.setattr(aws.Requests,'client',lambda self,session,service,region:clients[(service,region)])
        snapshot=aws.collect({'provider':'aws','scopes':[ACCOUNT],'auth':{'profile':'fixture'},
                             'options':{'regions':[REGION],'service_concurrency':1,'scope_concurrency':1}},
                             ['autoscaling_group','launch_configuration'])
        st.assert_no_pending_responses();sc.assert_no_pending_responses()
    return snapshot


def statuses(snapshot):
    rows=evaluate_snapshot(snapshot,checks=list(IDS))['findings']
    return {cid:{r['status'] for r in rows if r['check_id']==cid} for cid in IDS}


@pytest.mark.parametrize('value,expected',[('omitted','UNKNOWN'),(False,'PASS'),(True,'FAIL')])
def test_native_launch_configuration_omission_and_explicit_values(monkeypatch,value,expected):
    snapshot=collect(monkeypatch,value)
    lc=next(c for c in snapshot['collections'] if c['type']=='launch_configuration')
    assert lc['status']=='collected'
    assert ('AssociatePublicIpAddress' in lc['items'][0])==(value!='omitted')
    assert statuses(snapshot)==dict.fromkeys(IDS,{expected})


def test_partial_native_inventory_cannot_prove_inherited_ip_disabled(monkeypatch):
    snapshot=collect(monkeypatch)
    next(c for c in snapshot['collections'] if c['type']=='launch_configuration')['status']='partial'
    snapshot.pop('snapshot_id',None)
    assert statuses(snapshot)==dict.fromkeys(IDS,{'UNKNOWN'})


def test_denied_native_flag_cannot_be_treated_as_false(monkeypatch):
    snapshot=collect(monkeypatch,False)
    lc=next(c for c in snapshot['collections'] if c['type']=='launch_configuration')['items'][0]
    lc['_coverage']={'AssociatePublicIpAddress':{'status':'denied'}}
    snapshot.pop('snapshot_id',None)
    assert statuses(snapshot)==dict.fromkeys(IDS,{'UNKNOWN'})


@pytest.mark.parametrize('cid',IDS)
def test_public_metadata_corrects_omitted_public_ip_criteria(cid):
    from peaso.checks.catalog import _compliance, description_for
    from peaso.checks.aws_launch_ip_description_overlay import VERSION
    original=_compliance()[1]['checks'][cid]
    assert 'false or omitted' in original['pass_when']
    current=description_for(cid)
    assert current['description_correction']['version']==VERSION
    assert 'false or omitted' not in current['pass_when']
    from tests.reviewed_guidance_presentation import assert_description_preserves_contract
    assert_description_preserves_contract(cid)
    assert 'omission' in current['description_correction']['source_relationship']
    assert 'unresolved' in current['description_correction']['source_relationship']
    assert 'public' in current['description'] and 'launch configuration' in current['description']
