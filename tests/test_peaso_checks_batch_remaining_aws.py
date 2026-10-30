"""Portable, real-registry behavior contract for the reviewed AWS batch."""
from __future__ import annotations
import copy
import json
import pytest
from peaso.checks import CHECKS
from peaso.checks import batch_remaining_aws as batch

SCOPE='111111111111/us-east-1'
CONTEXT={'provider':'aws','scope':SCOPE,'metadata':{}}
CHECKS_BY_ID={c.id:c for c in CHECKS}

def indexed(kinds):
    index={'context':copy.deepcopy(CONTEXT),'collections':{}}
    for kind,rows in kinds.items():
        index['collections'][kind]=[{'type':kind,'scope':SCOPE,'status':'collected' if rows else 'empty','items':copy.deepcopy(rows)}]
        index[kind]=[{'provider':'aws','type':kind,'scope':SCOPE,'data':copy.deepcopy(row)} for row in rows]
    return index


def with_global_buckets(index,rows,status=None):
    result=copy.deepcopy(index);scope='111111111111/global'
    result['collections']['bucket']=[{'type':'bucket','scope':scope,'global':True,'account_id':'111111111111',
                                      'status':status or ('collected' if rows else 'empty'),'items':copy.deepcopy(rows)}]
    result['bucket']=[{'provider':'aws','type':'bucket','scope':scope,'data':copy.deepcopy(row)} for row in rows]
    return result

def with_global_customer_iam(index,rows):
    result=copy.deepcopy(index);scope='111111111111/global'
    result['context']['Account']='111111111111'
    result['collections']['iam_customer_policy']=[{'type':'iam_customer_policy','scope':scope,
        'global':True,'account_id':'111111111111',
        'status':'collected' if rows else 'empty','items':copy.deepcopy(rows)}]
    result['iam_customer_policy']=[{'provider':'aws','type':'iam_customer_policy',
        'scope':scope,'data':copy.deepcopy(row)} for row in rows]
    return result

def sg(protocol='tcp',port=22):
    return {'GroupId':'sg-1','OwnerId':'111111111111','IpPermissions':[{'IpProtocol':protocol,'FromPort':port,'ToPort':port,'Ipv6Ranges':[{'CidrIpv6':'::/0'}]}]}

def project(name='OTHER',typ='PLAINTEXT'):
    return {'name':'example','Configuration':{'collection_status':'collected','projects':[{'name':'example','environment':{'environmentVariables':[{'name':name,'type':typ}]}}]}}

def alarm(namespace,metric,dimension,value):
    return {'AlarmArn':'arn:aws:cloudwatch:us-east-1:111111111111:alarm/test','Namespace':namespace,'MetricName':metric,'Dimensions':[{'Name':dimension,'Value':value}],'ActionsEnabled':True,'AlarmActions':['arn:aws:sns:us-east-1:111111111111:alerts']}

def cases():
    configs={}
    for cid in ('aws_security_group_common_ports_ipv6_all','aws_security_group_ssh_ipv6_all','aws_security_group_tcp_udp_ipv6_all'):
        configs[cid]=(CONTEXT,indexed({'security_group':[]}),CONTEXT,indexed({'security_group':[sg()]}))
    configs['aws_msk_in_cluster_tls_enabled']=({'ClusterArn':'arn:aws:kafka:us-east-1:111111111111:cluster/a','ClusterType':'PROVISIONED','Detail':{'ClusterInfo':{'ClusterArn':'arn:aws:kafka:us-east-1:111111111111:cluster/a','Provisioned':{'EncryptionInfo':{'EncryptionInTransit':{'InCluster':True}}}}}} , None, None, None)
    msk=configs['aws_msk_in_cluster_tls_enabled'][0];bad=copy.deepcopy(msk);bad['Detail']['ClusterInfo']['Provisioned']['EncryptionInfo']['EncryptionInTransit']['InCluster']=False
    configs['aws_msk_in_cluster_tls_enabled']=(msk,indexed({'msk_cluster':[msk]}),bad,indexed({'msk_cluster':[bad]}))
    vpn={'ClientVpnEndpointId':'cvpn-endpoint-1','Status':{'Code':'available'},'ServerCertificateArn':'arn:aws:acm:us-east-1:111111111111:certificate/c','AuthenticationOptions':[{'Type':'federated-authentication'}]}
    bad=copy.deepcopy(vpn);bad['AuthenticationOptions']=[]
    configs['aws_client_vpn_authentication_configured']=(vpn,indexed({'client_vpn_endpoint':[vpn]}),bad,indexed({'client_vpn_endpoint':[bad]}))
    for cid,typ in [('aws.nist.codebuild_exact_aws_key_env_names','PLAINTEXT'),('aws.pci.codebuild.aws_key_environment_vars','SECRETS_MANAGER')]:
        good,bad=project(),project('AWS_ACCESS_KEY_ID',typ)
        configs[cid]=(good,indexed({'codebuild_project':[good]}),bad,indexed({'codebuild_project':[bad]}))
    good={'taskDefinitionArn':'arn:aws:ecs:us-east-1:111111111111:task-definition/t:1','Definition':{'collection_status':'collected','taskDefinition':{'taskDefinitionArn':'arn:aws:ecs:us-east-1:111111111111:task-definition/t:1','status':'ACTIVE','containerDefinitions':[{'name':'app','logConfiguration':{'logDriver':'awslogs'}}]}}}
    bad=copy.deepcopy(good);bad['Definition']['taskDefinition']['containerDefinitions'][0].pop('logConfiguration')
    configs['aws_g6_ecs_all_containers_logging']=(good,indexed({'ecs_task_definition':[good]}),bad,indexed({'ecs_task_definition':[bad]}))
    ec2={'InstanceId':'i-1','State':{'Name':'running'}}
    configs['aws_ec2_running_instance_cpu_alarm_present']=(ec2,indexed({'instance':[ec2],'cloudwatch_alarm':[alarm('AWS/EC2','CPUUtilization','InstanceId','i-1')]}),ec2,indexed({'instance':[ec2],'cloudwatch_alarm':[]}))
    sqs={'QueueUrl':'https://sqs.us-east-1.amazonaws.com/111111111111/jobs'}
    configs['aws_sqs_queue_depth_alarm_present']=(sqs,indexed({'sqs_queue':[sqs],'cloudwatch_alarm':[alarm('AWS/SQS','ApproximateNumberOfMessagesVisible','QueueName','jobs')]}),sqs,indexed({'sqs_queue':[sqs],'cloudwatch_alarm':[]}))
    cluster={'DBClusterIdentifier':'db-cluster','DBClusterMembers':[{'DBInstanceIdentifier':'db-1'}]}
    instance={'DBInstanceIdentifier':'db-1','DBInstanceClass':'db.r6g.large','MonitoringInterval':60,'MonitoringRoleArn':'arn:aws:iam::111111111111:role/monitor','EnhancedMonitoringResourceArn':'arn:aws:logs:us-east-1:111111111111:log-group:RDSOSMetrics'}
    bad=copy.deepcopy(instance);bad['MonitoringInterval']=0
    configs['aws_g6_rds_cluster_members_enhanced_monitoring']=(cluster,indexed({'rds_cluster':[cluster],'rds_instance':[instance]}),cluster,indexed({'rds_cluster':[cluster],'rds_instance':[bad]}))
    table={'TableName':'T','Table':{'Table':{'TableName':'T','SSEDescription':{'SSEType':'KMS','KMSMasterKeyArn':'arn:aws:kms:us-east-1:111111111111:key/k','Status':'ENABLED'}}}}
    bad=copy.deepcopy(table);bad['Table']['Table']['SSEDescription']['SSEType']='AES256'
    configs['aws_nist_dynamodb_table_encrypted_with_kms']=(table,indexed({'dynamodb_table':[table]}),bad,indexed({'dynamodb_table':[bad]}))
    zone={'Id':'Z1','Config':{'PrivateZone':False},'DNSSEC':{'HostedZoneId':'Z1','collection_status':'collected','Status':{'ServeSignature':'SIGNING'},'KeySigningKeys':[{'Status':'ACTIVE'}]}}
    bad=copy.deepcopy(zone);bad['DNSSEC']['Status']['ServeSignature']='NOT_SIGNING'
    configs['aws_route53_hosted_zone_dnssec_enabled']=(zone,indexed({'route53_zone':[zone]}),bad,indexed({'route53_zone':[bad]}))
    arn='arn:aws:lambda:us-east-1:111111111111:function:sample';config_arn='arn:aws:lambda:us-east-1:111111111111:code-signing-config:csc-1'
    function={'FunctionArn':arn,'Configuration':{'State':'Active'},'CodeSigning':{'collection_status':'collected','FunctionArn':arn,'CodeSigningConfigArn':config_arn},'CodeSigningConfig':{'collection_status':'collected','CodeSigningConfig':{'CodeSigningConfigArn':config_arn,'AllowedPublishers':{'SigningProfileVersionArns':['arn:aws:signer:us-east-1:111111111111:/signing-profiles/p/1']},'CodeSigningPolicies':{'UntrustedArtifactOnDeployment':'Enforce'}}}}
    bad=copy.deepcopy(function);bad['CodeSigning']['CodeSigningConfigArn']=''
    configs['aws_lambda_code_signing_configured']=(function,indexed({'lambda_function':[function]}),bad,indexed({'lambda_function':[bad]}))
    bucket={'name':'bucket-one','accessLogConfig':{'enabled':True,'destination':'logs'}}
    bad=copy.deepcopy(bucket);bad['accessLogConfig']['enabled']=False
    configs['aws_cis_lightsail_bucket_access_logging']=(bucket,indexed({'lightsail_bucket':[bucket]}),bad,indexed({'lightsail_bucket':[bad]}))
    # Historical ECR Public fixture is superseded by the pinned upstream
    # private-repository policy SQL; retain the original signed JSON separately.
    ecr_base={'repositoryArn':'arn:aws:ecr:us-east-1:111111111111:repository/app',
              'repositoryName':'app','registryId':'111111111111'}
    ecr_private={**ecr_base,'Policy':{'collection_status':'collected','registryId':'111111111111',
        'repositoryName':'app','policyText':{'Statement':[{'Effect':'Allow',
        'Principal':{'AWS':['arn:aws:iam::111111111111:role/ci']},'Action':['ecr:BatchGetImage']}]}}}
    ecr_wildcard={**ecr_base,'Policy':{'collection_status':'collected','registryId':'111111111111',
        'repositoryName':'app','policyText':{'Statement':[{'Effect':'Allow',
        'Principal':{'AWS':['*']},'Action':['ecr:BatchGetImage']}]}}}
    configs['aws_g6_ecr_public_repositories_absent']=(ecr_private,indexed({'ecr_repository':[ecr_private]}),
                                                      ecr_wildcard,indexed({'ecr_repository':[ecr_wildcard]}))
    ec2={'InstanceId':'i-1','State':{'Name':'running'}}
    configs['aws_ec2_status_alarm']=(ec2,indexed({'instance':[ec2],'cloudwatch_alarm':[alarm('AWS/EC2','StatusCheckFailed','InstanceId','i-1')]}),ec2,indexed({'instance':[ec2],'cloudwatch_alarm':[]}))
    function={'FunctionArn':'arn:aws:lambda:us-east-1:111111111111:function:one'}
    recorder={'name':'default','recordingGroup':{'allSupported':True,'resourceTypes':[],
       'exclusionByResourceTypes':{'resourceTypes':[]},'recordingStrategy':{'useOnly':'ALL_SUPPORTED_RESOURCE_TYPES'}},
       'Status':{'ConfigurationRecordersStatus':[{'name':'default','recording':True,'lastStatus':'Success'}]}}
    bad=copy.deepcopy(recorder);bad['recordingGroup']={'allSupported':False,'resourceTypes':['AWS::EC2::Instance'],
        'exclusionByResourceTypes':{'resourceTypes':[]},'recordingStrategy':{'useOnly':'INCLUSION_BY_RESOURCE_TYPES'}}
    configs['aws_cis_lambda_config_recorded']=(function,indexed({'lambda_function':[function],'config_recorder':[recorder]}),function,indexed({'lambda_function':[function],'config_recorder':[bad]}))
    instance={'DBInstanceIdentifier':'db-1','DBClusterIdentifier':'cluster-1','MonitoringInterval':60,
              'MonitoringRoleArn':'arn:aws:iam::111111111111:role/monitor',
              'EnhancedMonitoringResourceArn':'arn:aws:logs:us-east-1:111111111111:log-group:RDSOSMetrics'}
    cluster={'DBClusterIdentifier':'cluster-1','DBClusterMembers':[{'DBInstanceIdentifier':'db-1'}]}
    bad=copy.deepcopy(instance);bad['MonitoringInterval']=0
    configs['aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled']=(instance,indexed({'rds_instance':[instance],'rds_cluster':[cluster]}),bad,indexed({'rds_instance':[bad],'rds_cluster':[cluster]}))
    trail={'TrailARN':'arn:aws:cloudtrail:us-east-1:111111111111:trail/a',
           'HomeRegion':'us-east-1','S3BucketName':'owned-trail-logs'}
    good_bucket={'Name':'owned-trail-logs','AccountId':'111111111111',
                 'Logging':{'collection_status':'collected','LoggingEnabled':{'TargetBucket':'access-logs'}}}
    bad_bucket=copy.deepcopy(good_bucket);bad_bucket['Logging'].pop('LoggingEnabled')
    configs['aws.nist.all_cloudtrail_destination_bucket_access_logging']=(trail,
       with_global_buckets(indexed({'cloudtrail':[trail]}),[good_bucket]),trail,
       with_global_buckets(indexed({'cloudtrail':[trail]}),[bad_bucket]))
    strict_bucket=copy.deepcopy(good_bucket)
    strict_bucket['Logging']['LoggingEnabled']['TargetPrefix']='access/'
    configs['aws_g6_all_cloudtrail_destination_bucket_access_logging']=(trail,
       with_global_buckets(indexed({'cloudtrail':[trail]}),[strict_bucket]),trail,
       with_global_buckets(indexed({'cloudtrail':[trail]}),[bad_bucket]))
    logging_trail={**trail,'Status':{'collection_status':'collected','IsLogging':True}}
    configs['aws_nist_cloudtrail_s3_logging_enabled']=(logging_trail,
       with_global_buckets(indexed({'cloudtrail':[logging_trail]}),[good_bucket]),logging_trail,
       with_global_buckets(indexed({'cloudtrail':[logging_trail]}),[bad_bucket]))
    key_arn='arn:aws:kms:us-east-1:111111111111:key/example'
    kms={'KeyId':'example','KeyArn':key_arn,'Metadata':{'collection_status':'collected',
         'KeyMetadata':{'Arn':key_arn,'Origin':'EXTERNAL','KeySpec':'RSA_2048','KeyUsage':'ENCRYPT_DECRYPT'}}}
    bad=copy.deepcopy(kms);bad['Metadata']['KeyMetadata']['KeySpec']='SYMMETRIC_DEFAULT'
    configs['aws_kms_imported_key_origin_spec']=(kms,indexed({'kms_key':[kms]}),bad,indexed({'kms_key':[bad]}))
    policy_arn='arn:aws:iam::111111111111:policy/narrow'
    policy={'Arn':policy_arn,'AccountId':'111111111111','DefaultVersionId':'v1',
        'DefaultDocument':{'collection_status':'collected','VersionId':'v1',
            'Document':{'Statement':[{'Effect':'Allow','Action':'s3:GetObject',
                'Resource':'arn:aws:s3:::data-bucket/record'}]}},
        '_provenance':{'operation':'iam:ListPolicies','managed_scope':'Local',
            'only_attached':False,'account_id':'111111111111',
            'default_operation':'iam:GetPolicyVersion'}}
    bad=copy.deepcopy(policy);bad['DefaultDocument']['Document']['Statement'][0]['Action']='s3:*'
    configs['aws.pci.iam.wildcard_action_scoped_resource']=(policy,with_global_customer_iam(indexed({}),[policy]),
        bad,with_global_customer_iam(indexed({}),[bad]))
    for cid,source,service,names in (
        ('aws_eventbridge_iam_user_change_alert','aws.iam','iam.amazonaws.com',
         ['CreateUser','DeleteUser','UpdateUser','CreateAccessKey','UpdateAccessKey','DeleteAccessKey']),
        ('aws_eventbridge_snapshot_change_alert','aws.ec2','ec2.amazonaws.com',
         ['CreateSnapshot','ModifySnapshotAttribute','DeleteSnapshot'])):
        rule={'Arn':'arn:aws:events:us-east-1:111111111111:rule/changes',
              'Name':'changes','EventBusName':'default','State':'ENABLED',
              'EventPattern':json.dumps({'source':[source],'detail-type':['AWS API Call via CloudTrail'],
                                          'detail':{'eventSource':[service],'eventName':names}}),
              'Targets':{'collection_status':'collected','items':[
                  {'Id':'notify','Arn':'arn:aws:sns:us-east-1:111111111111:alerts'}]}}
        configs[cid]=(CONTEXT,indexed({'event_rule':[rule]}),CONTEXT,indexed({'event_rule':[]}))
    log_arn='arn:aws:logs:us-east-1:111111111111:log-group:trail-events'
    log_group={'logGroupName':'trail-events','arn':log_arn+':*'}
    logs_trail={**trail,'CloudWatchLogsLogGroupArn':log_arn,
                'CloudWatchLogsRoleArn':'arn:aws:iam::111111111111:role/cloudtrail-delivery',
                'Status':{'collection_status':'collected','IsLogging':True}}
    bad=copy.deepcopy(logs_trail);bad['CloudWatchLogsLogGroupArn']=''
    for cid in ('aws.nist.cloudtrail_cloudwatch_integration','aws_g6_cloudtrail_all_trails_cloudwatch_integration'):
        configs[cid]=(logs_trail,indexed({'cloudtrail':[logs_trail],'log_group':[log_group]}),
                      bad,indexed({'cloudtrail':[bad],'log_group':[log_group]}))
    vault={'BackupVaultName':'vault-one','Notifications':{'collection_status':'collected',
           'SNSTopicArn':'arn:aws:sns:us-east-1:111111111111:backup-alerts',
           'BackupVaultEvents':['BACKUP_JOB_FAILED']}}
    bad=copy.deepcopy(vault);bad['Notifications']['BackupVaultEvents']=[]
    configs['aws_backup_failure_notification']=(vault,indexed({'backup_vault':[vault]}),
         bad,indexed({'backup_vault':[bad]}))
    batch_job={'jobDefinitionArn':'arn:aws:batch:us-east-1:111111111111:job-definition/job:1',
       'status':'ACTIVE','containerProperties':{'logConfiguration':{'logDriver':'awslogs',
       'options':{'awslogs-group':'/aws/batch/job'}}}}
    bad=copy.deepcopy(batch_job);bad['containerProperties'].pop('logConfiguration')
    configs['aws_cis_batch_job_cloudwatch_logging']=(batch_job,indexed({'batch_job_definition':[batch_job]}),
       bad,indexed({'batch_job_definition':[bad]}))
    pipeline={'name':'pipeline-one','Pipeline':{'collection_status':'collected','pipeline':{'name':'pipeline-one',
       'stages':[{'name':'Build','actions':[{'actionTypeId':{'category':'Build'}}]},
                 {'name':'Deploy','actions':[{'actionTypeId':{'category':'Deploy'}}]}]}}}
    bad=copy.deepcopy(pipeline);bad['Pipeline']['pipeline']['stages'][1]['actions'].append(
       {'actionTypeId':{'category':'Deploy'}})
    configs['aws.pci.codepipeline.first_stage_single_deploy']=(pipeline,
       indexed({'codepipeline_pipeline':[pipeline]}),bad,indexed({'codepipeline_pipeline':[bad]}))
    kms_arn='arn:aws:kms:us-east-1:111111111111:key/trail-key'
    key={'KeyId':'trail-key','KeyArn':kms_arn,'Metadata':{'collection_status':'collected',
         'KeyMetadata':{'Arn':kms_arn,'KeyManager':'CUSTOMER','KeyState':'Enabled'}}}
    encrypted_group={**log_group,'kmsKeyId':kms_arn}
    encrypted_trail={**logs_trail,'KmsKeyId':kms_arn}
    bad=copy.deepcopy(encrypted_trail);bad['KmsKeyId']=''
    for cid in ('aws_fedramp_cloudtrail_destination_kms','aws_g6_cloudtrail_kms_destination_join',
                'aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk'):
        configs[cid]=(encrypted_trail,indexed({'cloudtrail':[encrypted_trail],
           'log_group':[encrypted_group],'kms_key':[key]}),bad,
           indexed({'cloudtrail':[bad],'log_group':[encrypted_group],'kms_key':[key]}))
    sns={'TopicArn':'arn:aws:sns:us-east-1:111111111111:notifications',
         'Attributes':{'collection_status':'collected','Attributes':{
           'TopicArn':'arn:aws:sns:us-east-1:111111111111:notifications',
           'SubscriptionsConfirmed':'1'}}}
    configs['aws_sns_delivery_failure_alarm_present']=(sns,indexed({'sns_topic':[sns],
       'cloudwatch_alarm':[alarm('AWS/SNS','NumberOfNotificationsFailed','TopicName','notifications')]}),
       sns,indexed({'sns_topic':[sns],'cloudwatch_alarm':[]}))
    return configs

CASES=cases()

def test_ecs_logging_requires_collected_definition_detail():
    cid='aws_g6_ecs_all_containers_logging'
    bad,index=copy.deepcopy((CASES[cid][2],CASES[cid][3]))
    assert CHECKS_BY_ID[cid].evaluate(bad,index)[0]=='FAIL'
    for status in (None,'partial','denied'):
        incomplete=copy.deepcopy(bad)
        if status is None:
            incomplete['Definition'].pop('collection_status')
        else:
            incomplete['Definition']['collection_status']=status
        incomplete_index=indexed({'ecs_task_definition':[incomplete]})
        assert CHECKS_BY_ID[cid].evaluate(incomplete,incomplete_index)[0]=='UNKNOWN'

@pytest.mark.parametrize('cid',sorted(batch.SPECS))
def test_registry_pass_fail_unknown_and_immutable(cid):
    check=CHECKS_BY_ID[cid]
    good,good_index,bad,bad_index=copy.deepcopy(CASES[cid])
    good_before,bad_before=copy.deepcopy((good,good_index)),copy.deepcopy((bad,bad_index))
    assert check.evaluate(good,good_index)[0]=='PASS'
    assert check.evaluate(bad,bad_index)[0]=='FAIL'
    assert (good,good_index)==good_before and (bad,bad_index)==bad_before
    unknown_index=copy.deepcopy(good_index)
    kind=batch.SPECS[cid][0]
    unknown_index['collections'][kind][0]['status']='partial'
    assert check.evaluate(good,unknown_index)[0]=='UNKNOWN'
    assert check.evaluate(None,good_index)[0]=='UNKNOWN'
    assert check.evaluate(good,{} )[0]=='UNKNOWN'


def test_iam_declared_notaction_equivalent_and_default_version_only():
    cid='aws.pci.iam.wildcard_action_scoped_resource'
    policy,index=copy.deepcopy(CASES[cid][:2])
    statement=policy['DefaultDocument']['Document']['Statement'][0]
    statement.pop('Action');statement['NotAction']=['iam:*']
    index=with_global_customer_iam(indexed({}),[policy])
    assert CHECKS_BY_ID[cid].evaluate(policy,index)[0]=='FAIL'
    statement['Effect']='Deny'
    index=with_global_customer_iam(indexed({}),[policy])
    assert CHECKS_BY_ID[cid].evaluate(policy,index)[0]=='PASS'
    statement['Effect']='Allow';statement['NotAction']=['*']
    index=with_global_customer_iam(indexed({}),[policy])
    assert CHECKS_BY_ID[cid].evaluate(policy,index)[0]=='PASS'
    statement['Effect']='Allow';statement['NotResource']='arn:aws:s3:::other'
    index=with_global_customer_iam(indexed({}),[policy])
    assert CHECKS_BY_ID[cid].evaluate(policy,index)[0]=='UNKNOWN'


def test_eventbridge_rule_has_exact_origin_and_target_coverage():
    cid='aws_eventbridge_iam_user_change_alert'
    item,index=copy.deepcopy(CASES[cid][:2])
    rule=index['collections']['event_rule'][0]['items'][0]
    rule['Targets']['items']=[]
    index['event_rule'][0]['data']['Targets']['items']=[]
    assert CHECKS_BY_ID[cid].evaluate(item,index)[0]=='FAIL'
    rule['Targets']['collection_status']='denied'
    index['event_rule'][0]['data']['Targets']['collection_status']='denied'
    assert CHECKS_BY_ID[cid].evaluate(item,index)[0]=='UNKNOWN'


def test_cloudtrail_log_group_join_and_status_fail_closed():
    cid='aws.nist.cloudtrail_cloudwatch_integration'
    trail,index=copy.deepcopy(CASES[cid][:2])
    index['collections']['log_group'][0]['status']='partial'
    assert CHECKS_BY_ID[cid].evaluate(trail,index)[0]=='UNKNOWN'
    trail,index=copy.deepcopy(CASES[cid][:2])
    trail['Status']['IsLogging']=False
    index['collections']['cloudtrail'][0]['items'][0]['Status']['IsLogging']=False
    index['cloudtrail'][0]['data']['Status']['IsLogging']=False
    assert CHECKS_BY_ID[cid].evaluate(trail,index)[0]=='FAIL'


def test_cloudtrail_kms_unresolved_reference_is_unknown_not_fail():
    cid='aws_g6_cloudtrail_kms_destination_join'
    trail,index=copy.deepcopy(CASES[cid][:2])
    trail['KmsKeyId']='arn:aws:kms:us-east-1:111111111111:key/not-in-inventory'
    index['collections']['cloudtrail'][0]['items'][0]['KmsKeyId']=trail['KmsKeyId']
    index['cloudtrail'][0]['data']['KmsKeyId']=trail['KmsKeyId']
    assert CHECKS_BY_ID[cid].evaluate(trail,index)[0]=='UNKNOWN'
    trail,index=copy.deepcopy(CASES[cid][:2])
    index['collections']['kms_key'][0]['status']='partial'
    assert CHECKS_BY_ID[cid].evaluate(trail,index)[0]=='UNKNOWN'


def test_sns_subscription_count_is_authoritative_native_equivalent():
    cid='aws_sns_delivery_failure_alarm_present'
    sns,index=copy.deepcopy(CASES[cid][:2])
    sns['Attributes']['Attributes']['SubscriptionsConfirmed']='0'
    index['collections']['sns_topic'][0]['items'][0]['Attributes']['Attributes']['SubscriptionsConfirmed']='0'
    index['sns_topic'][0]['data']['Attributes']['Attributes']['SubscriptionsConfirmed']='0'
    assert CHECKS_BY_ID[cid].evaluate(sns,index)[0]=='NOT_APPLICABLE'
    sns['Attributes']['Attributes']['SubscriptionsConfirmed']='unknown'
    index['collections']['sns_topic'][0]['items'][0]['Attributes']['Attributes']['SubscriptionsConfirmed']='unknown'
    index['sns_topic'][0]['data']['Attributes']['Attributes']['SubscriptionsConfirmed']='unknown'
    assert CHECKS_BY_ID[cid].evaluate(sns,index)[0]=='UNKNOWN'


def test_redshift_signed_alias_uses_existing_boolean_predicate():
    assert 'aws_g6_redshift_automatic_version_upgrade' not in batch.SPECS
    canonical=CHECKS_BY_ID['aws.cb.redshift.allow_version_upgrade']
    historic=CHECKS_BY_ID['aws.b.redshift.allow_version_upgrade']
    for setting,expected in ((True,'PASS'),(False,'FAIL')):
        item={'ClusterIdentifier':'cluster-one','AllowVersionUpgrade':setting}
        assert canonical.evaluate(item,{})[0]==historic.evaluate(item,{})[0]==expected
    assert canonical.evaluate({'ClusterIdentifier':'cluster-one'},{})[0]=='UNKNOWN'


def test_cloudtrail_authentication_signed_alias_uses_existing_regional_management_coverage():
    from peaso.checks.fixtures import CASES as SHARED_CASES
    cid='aws.gap.cloudtrail.region_logging_management_events'
    example=SHARED_CASES[cid]
    assert CHECKS_BY_ID[cid].evaluate(copy.deepcopy(example['pass']),copy.deepcopy(example['pass_index']))[0]=='PASS'
    assert CHECKS_BY_ID[cid].evaluate(copy.deepcopy(example['fail']),copy.deepcopy(example['fail_index']))[0]=='FAIL'
    assert CHECKS_BY_ID[cid].evaluate(copy.deepcopy(example['unknown']),copy.deepcopy(example['unknown_index']))[0]=='UNKNOWN'


def test_foreign_scope_and_partial_alarm_cannot_pass():
    cid='aws_security_group_ssh_ipv6_all';item,index=copy.deepcopy(CASES[cid][:2])
    index['context']['scope']='222222222222/us-east-1'
    assert CHECKS_BY_ID[cid].evaluate(item,index)[0]=='UNKNOWN'
    cid='aws_ec2_running_instance_cpu_alarm_present';item,index=copy.deepcopy(CASES[cid][:2])
    index['collections']['cloudwatch_alarm'][0]['status']='denied'
    assert CHECKS_BY_ID[cid].evaluate(item,index)[0]=='UNKNOWN'


def test_lambda_collector_detail_to_snapshot_to_registry():
    from peaso.collectors import aws_facts_swc
    arn='arn:aws:lambda:us-east-1:111111111111:function:sample'
    config_arn='arn:aws:lambda:us-east-1:111111111111:code-signing-config:csc-1'
    class ReadOnlyStub:
        def detail(self, _session, service, region, operation, **_kwargs):
            assert service=='lambda' and region=='us-east-1'
            if operation=='get_function_code_signing_config':
                return {'collection_status':'collected','FunctionArn':arn,'CodeSigningConfigArn':config_arn}
            assert operation=='get_code_signing_config'
            return {'collection_status':'collected','CodeSigningConfig':{'CodeSigningConfigArn':config_arn,
                'AllowedPublishers':{'SigningProfileVersionArns':['profile']},
                'CodeSigningPolicies':{'UntrustedArtifactOnDeployment':'Enforce'}}}
    base={'FunctionName':'sample','FunctionArn':arn,'Configuration':{'State':'Active'}}
    enriched=aws_facts_swc._lambda(ReadOnlyStub(),object(),'us-east-1',[base])[0]
    assert CHECKS_BY_ID['aws_lambda_code_signing_configured'].evaluate(enriched,indexed({'lambda_function':[enriched]}))[0]=='PASS'
    assert 'CodeSigningConfig' in enriched and base=={'FunctionName':'sample','FunctionArn':arn,'Configuration':{'State':'Active'}}


def test_codebuild_omitted_type_uses_documented_plaintext_default():
    cid='aws.nist.codebuild_exact_aws_key_env_names'
    row=project('AWS_ACCESS_KEY_ID')
    row['Configuration']['projects'][0]['environment']['environmentVariables'][0].pop('type')
    assert CHECKS_BY_ID[cid].evaluate(row,indexed({'codebuild_project':[row]}))[0]=='FAIL'


def test_lambda_config_recording_denied_dependency_remains_unknown():
    cid='aws_cis_lambda_config_recorded';item,scan=copy.deepcopy(CASES[cid][:2])
    scan['collections']['config_recorder'][0]['status']='denied'
    assert CHECKS_BY_ID[cid].evaluate(item,scan)[0]=='UNKNOWN'


def test_rds_instance_unresolved_cluster_member_is_unknown():
    cid='aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled';item,scan=copy.deepcopy(CASES[cid][:2])
    scan['collections']['rds_cluster'][0]['items'][0]['DBClusterMembers'][0]['DBInstanceIdentifier']='foreign'
    scan['rds_cluster'][0]['data']['DBClusterMembers'][0]['DBInstanceIdentifier']='foreign'
    assert CHECKS_BY_ID[cid].evaluate(item,scan)[0]=='UNKNOWN'


def test_cloudtrail_logging_foreign_or_denied_bucket_cannot_pass():
    cid='aws.nist.all_cloudtrail_destination_bucket_access_logging';item,scan=copy.deepcopy(CASES[cid][:2])
    scan['collections']['bucket'][0]['items'][0]['AccountId']='222222222222'
    scan['bucket'][0]['data']['AccountId']='222222222222'
    assert CHECKS_BY_ID[cid].evaluate(item,scan)[0]=='UNKNOWN'
    item,scan=copy.deepcopy(CASES[cid][:2])
    scan['collections']['bucket'][0]['status']='denied'
    assert CHECKS_BY_ID[cid].evaluate(item,scan)[0]=='UNKNOWN'
