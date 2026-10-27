#!/usr/bin/env python3
"""Conservative source proof for the exact-992 low-representative audit slice.

This reads sanitized numeric/source inventories and installed evaluator source.
It never loads a cloud snapshot, finding evidence values, or model credentials.
"""
import argparse
import ast
import collections
import gzip
import hashlib
import inspect
import ijson
import json
from pathlib import Path
import sys
import textwrap


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SAFE_CALLS = frozenset({
    'get', 'result', 'unknown', 'isinstance', 'any', 'all', 'len', 'bool',
    'str', 'int', 'set', 'sorted', 'list', 'dict', 'tuple', 'values', 'items',
    'startswith', 'endswith', 'strip', 'lower', 'upper', 'issubset',
    'append', 'count', 'split', 'type', 'sum', 'Unavailable', 'setdefault', 'add',
})
# These names only locate source for provisional candidates. They never make a
# check source-proven; helper chains and optional omissions need separate proof.
CANDIDATE_HELPERS = frozenset({
    'list_of_objects', 'optional', 'absent_or', 'api_optional', 'csv_boolean',
    'password_row', 'complete_items', 'scope_subject', 'home', 'stage',
    'method_settings', 'config', 'viewer_http', 'setting', 'threat_mode',
    'project', 'task', 'certificate', 'lb_attrs', 'lb_attribute',
    '_backup_status', '_insights', 'cluster', '_workgroup', '_cfg',
    '_type', '_viewer_policy', '_settings', '_methods', '_default_data',
    'volume_state', 'access_keys', 'flag', 'split_name', 'strings',
    'encryption_rules', 'section', 'versioning_enabled', 'detector_enabled',
    'customer', 'collected', '_attrs', '_native_optional', '_enabled_lifecycle_rules',
    '_wg_conf', '_wg_enabled', '_wg_encryption', '_origins', '_listeners',
    '_protocol', '_policy', '_tls_listeners', 'detail', 'detail_list',
    '_table_body', 'cluster_body', 'empty', 'meta', 'prowler_flags', 'reader',
    'origins', '_observed_project', '_artifact_setting',
})
# These helpers interpret policy documents, findings or unproved index joins.
# The decision follows their source behavior, irrespective of check ID spelling.
BOUND_REGISTRATIONS = frozenset({
    'aws.a.cloudwatch.any_state_actions',
    'aws.b.cloudfront.access_logging', 'aws.b.cloudfront.sni',
    'aws.b.cognito.no_guest_identities', 'aws.b.dynamodb.deletion_protection',
    'aws.b.dynamodb.point_in_time_recovery', 'aws.b.lambda.active_tracing',
    'aws.b.rds_instance.iam_authentication', 'aws.b.rds_instance.snapshot_tags',
    'aws.b.ssm.parameter_secure_type', 'aws.cloudtrail.kms_encryption',
    'aws.lambda.vpc_configuration', 'aws.sns.kms_encryption',
})
MANUAL_RETAIN = {
    'aws.claude_a.guardduty.detector_no_findings':
        'peaso/checks/claude_aws_a_security.py:24-30 treats missing nested collection_status as collected; a partial HighSeverityFindingIds list could yield FAIL.',
    'aws.claude_a.guardduty.prowler_no_high_severity_findings':
        'peaso/checks/claude_aws_a_security.py:24-30 treats missing nested collection_status as collected; absence of an explicit complete finding-list marker is ambiguous.',
    'aws.claude_a.guardduty.prowler_ai_protection':
        'peaso/checks/claude_aws_a_security.py:182-199 defaults a malformed feature Status to DISABLED via dict.get, which can yield FAIL instead of UNKNOWN.',
    'aws.claude_a.guardduty.prowler_runtime_monitoring':
        'peaso/checks/claude_aws_a_security.py:182-199 defaults missing feature Name/Status via dict.get, so malformed feature rows can reach FAIL.',
    'aws.iam.console_mfa':
        'peaso/checks/__init__.py:358-379 permits MFADevices.collection_status outside collected/empty and can return FAIL for a denied empty list.',
    'aws.logs.retention':
        'peaso/checks/aws.py:26-34 defaults an omitted retentionInDays without requiring DescribeLogGroups native_response_complete; an incomplete row can FAIL.',
    'aws.b.ecr.lifecycle_rules':
        'peaso/checks/aws_b_ecr.py:23 parses lifecyclePolicyText with json.loads; '
        'this is serialized policy content, so rule-presence inference remains AI-reviewed.',
}
SPECIAL_SOURCE_PINS = {
    'peaso/checks/aws_a_iam.py': '87eb85344dfae79d426809f9b711ff06ff5accbecbeb27d879fc2f46a8373168',
    'peaso/checks/aws_a_facts.py': '6499b70ab725fe55edafa8adf436ffd50aab99cd5c105e67dcfdb15e615d339d',
    'peaso/checks/claude2_aws_b_edge.py': '7302840c0c26e9967f88fc0b2e057c9bbdd46a18920ace663ae2337d52dbc54e',
    'peaso/collectors/aws_b_services.py': '5fb58e5f02d8a05f41a70258a2a5108b88334bc165f59b443e5910b7689c10a3',
    'peaso/checks/hacktricks_bp_aws.py': '2b1752f0d615a63966fccc4173dbbb04d5e0178c9252e0f4790ac22ccd563d45',
    'peaso/checks/hacktricks_bp_common.py': 'a7f127c0ecd1a2876c4ea1124304709cf68feff80c5a9d8564b62193d0226b5e',
    'peaso/checks/aws.py': '18b513e7e115dfcff6869e20bb2c776c9c979ac2ad4b7662c6179acb146debbd',
    'peaso/checks/aws_a_s3.py': 'ff02961210c23380ae79b3ea983e7734f5205ef49acb0a3e00bbb5f7eea3916d',
    'peaso/checks/claude_aws_a_s3.py': '18c38c1034a800039d7a11eec8c0d281d42c63051c1d90d02b1a0ba15a4e1160',
    'peaso/collectors/aws.py': '6ddea9d93b1a925503c712660dd9df98e63e460833d156deac9bd8a00ba3fde5',
    'peaso/checks/aws_extended.py': 'aac21cb7a83d89836beb374e72746d9f1f1e3b8de42137d5915397e7a0ea8f4b',
    'peaso/checks/aws_b_ecr.py': '552b98f0e65964ceff93530c4b08f017874bdce2c219055afc9c98e489cb678a',
    'peaso/checks/aws_a_cloudwatch.py': '7cae38304bca4ec34d34d7604f44af5f07c084a49987c204e63988276c5b67f9',
    'peaso/checks/claude_aws_b_messaging.py': '3c01e5e55f6bb580757ad65dd8239f0edd21943b3539f1d2ae4d4c9168fb4084',
    'peaso/checks/claude2_aws_b_devtools.py': '6434e604a4f39fe952b97826c9b4d4e81b969e5ad6aab6196108d4d2b6918caf',
    'peaso/checks/claude_aws_b_common.py': '0755fcb591a940e3e9d4b0483701f7aff2416038f5990f22f7098f95c60079b3',
    'peaso/collectors/aws_facts_data_identity.py': '0f71935bc917f2bce269f5158e68e8a7adedb84fc289aca86a7bda058deca1a0',
    'peaso/checks/aws_b_compute.py': '136f48264836bc8a8a43b495ff71af02cbdafb008358cca8d2ffa162620e3a2e',
    'peaso/checks/claude2_aws_b_compute.py': '8b061001de6711d59ac584c15f09a703fa2f41b8455838bba714d862634db4ed',
    'peaso/checks/aws_b_core.py': '4d184fe488da84bac58622867ae7f91e38c9a560fecd6c93b3f8b1b75fc4a23b',
    'peaso/checks/claude_aws_b_compute.py': '969058175c791c7b7e16c60483ab0e51a09cd7d1567171e961d4f02c015fc8c1',
    'peaso/checks/aws_b_cloudfront.py': 'd84100a1052473bbb5fcba81d36b33d1fdf1b774e2141a6fc6ec815c061853df',
    'peaso/checks/compliance_new_aws.py': '631a322dcfbd561bfbf4ec5cda53949c1030328b42462255e045e9c8cf0a5bce',
    'peaso/collectors/aws_facts_compute_edge.py': '33132a9fd900a55e6e7a259abcbb9af7b9a978a3ceb1cc589d78c4e754de2671',
    'peaso/checks/claude_aws_a_iam.py': '5a1f81ead33c02f957be1d1ee2461afaa7a07b2cb62ec8997dcbc377f3c5c687',
    'peaso/checks/claude_aws_a_common.py': '42218f329b77e55cd56c2f46de0a82ab260c849ca1ae1e89ac95a54e201a87d8',
    'peaso/checks/claude_aws_b_security.py': '47bee249deb92a199d95c1ab027347593261ba336ead84505b8862d1fdd0f394',
    'peaso/collectors/aws_facts_cb_ca.py': '6d0e922b4bd80b371a0ff51bbd0efb1337e309c2c38564163fc4ab1a3b5fe3fe',
    'peaso/checks/aws_b_regional.py': 'e1facce323da71cbe0596bbe151b38419e6062aeec5bb093a93fb71ea051cad5',
    'peaso/checks/aws_b_storage.py': '93943011991f833f90926b65d2f9dbe58d55983828ddb9a87930c940c9b0338a',
    'peaso/checks/aws_a_cloudtrail.py': '00da31c7b56e6a546dd5f89446428b1682c704a2a0beec3909a47a384ee5a5a0',
    'peaso/checks/aws_a_cloudtrail_variants.py': 'f48b7b74843dfc2a9dbafefe059982d6fa4bd811b65308b3016c702efcb54248',
    'peaso/checks/aws_a_account.py': 'e5756eba9a785fbd32ac7235f7a6c68b2db9be173420c1dc7860044a90baf4d8',
    'peaso/checks/aws_b_apigateway.py': '3bba75269b3358c4ac16ef70100b8c7aa68134600cd8829205fb4ea28de526d4',
    'peaso/checks/claude_aws_a_ec2.py': 'fc1c32b17876668b9b812221425b54e7664b0db554dc3ad225d8643c581b5eaa',
    'peaso/checks/aws_b_loadbalancing.py': '7893bd90cb37ab8ea8c489215d5d62f4178e9bf015a4310b889757f037dad6e5',
    'peaso/checks/aws_b_databases.py': 'e8a0014b5f0e5efa018573e8245131e6d327abe8814725f85766c406c8e9f1e5',
    'peaso/checks/aws_b_cognito.py': 'e52eb877a04d385637dd179ec28f3b8b1956ad9b308f3550efb1e9caa9bd40ed',
    'peaso/checks/claude_aws_b_db.py': '332ae9c6f5a2657a90859900d008b2813c08df6fd15f4a2a819f18fdd834ee62',
    'peaso/checks/claude_aws_b_storage.py': '26b0efe39f42a9742da1e821432d49c48a33bba3a1ef42b7eb3901b9bb422a94',
    'peaso/checks/claude_aws_a_security.py': '8081b3cd6ef2bd08d817cfe1a7c5ed31169b4cf30062d2d5edaf7c85630016b8',
    'peaso/checks/facts.py': '15d83fc5f44bfca7bd3022f7528bfd54c5738d6459fe999f59c2fd4498a1c926',
    'peaso/checks/__init__.py': '9e30d82d62313b05b8b0c8c83b4c3bb1de339563dd8976fc2d59929cce4587ae',
}
SNAPSHOT_SHA256 = '3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f'
PRE_AI_SHA256 = '4dcaa76a21c6b3bfff2b4859c1d4c763964c92c69041fe2d95702315fffde2ba'
S3_FIELDS = {
    'aws.a.s3.mfa_delete_enabled': ('Versioning.MFADelete',),
    'aws.s3.versioning': ('Versioning.Status',),
    'aws.s3.access_logging': ('Logging.LoggingEnabled.TargetBucket',),
    'aws.claude_a.s3.default_encryption_kms_key': ('Encryption.ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.KMSMasterKeyID',),
    'aws.claude_a.s3.prowler_kms_encryption': ('Encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm',),
    'aws.claude_a.s3.object_lock_configured': ('ObjectLock.ObjectLockConfiguration',),
    'aws.claude_a.s3.replication_rule_enabled': ('Replication.ReplicationConfiguration.Rules[].Status',),
    'aws.claude_a.s3.lifecycle_rule_enabled': ('Lifecycle.Rules[].Status',),
    'aws.claude_a.s3.versioning_and_lifecycle': ('Versioning.Status', 'Lifecycle.Rules[].Status'),
    'aws.claude_a.s3.prowler_acl_disabled': ('OwnershipControls.OwnershipControls.Rules[0].ObjectOwnership',),
}
OTHER_SNAPSHOT_FIELDS = {
    'aws.a.cloudwatch.log_kms_encryption': ('logGroupName', '_provenance.operation',
                                           '_provenance.native_response_complete', 'kmsKeyId'),
    'aws.b.ecr.all_tags_immutable': ('imageTagMutability',),
    'aws.ecr.lifecycle_policy': ('LifecyclePolicy.collection_status',
                                 'LifecyclePolicy.absent', 'LifecyclePolicy.lifecyclePolicyText'),
    'aws.cb.sqs.cmk_encryption': ('Attributes.Attributes.QueueArn',
                                  'Attributes.Attributes.KmsMasterKeyId'),
    'aws.cb.sqs.dead_letter_queue': ('Attributes.Attributes.QueueArn',
                                     'Attributes.Attributes.RedrivePolicy'),
    'aws.c2b.cloudformation.notifications': ('StackName', 'NotificationARNs'),
    'aws.c2b.cloudformation.termination_protection_root_stacks':
        ('StackName', 'RootId', 'EnableTerminationProtection'),
}
ECS_FIELDS = {
    'aws.c2b.ecs.all_containers_logging':
        ('Definition.taskDefinition.containerDefinitions[].name',
         'Definition.taskDefinition.containerDefinitions[].logConfiguration.logDriver'),
    'aws.b.ecs.some_logging_configuration':
        ('Definition.taskDefinition.containerDefinitions[].name',
         'Definition.taskDefinition.containerDefinitions[].logConfiguration'),
    'aws.b.ecs.no_host_pid': ('Definition.taskDefinition.pidMode',),
    'aws.b.ecs.no_privileged_containers':
        ('Definition.taskDefinition.containerDefinitions[].privileged',),
}
LAMBDA_FIELDS = {
    'aws.b.lambda.active_tracing': ('Configuration.TracingConfig.Mode',),
    'aws.b.lambda.insights_layer': ('Configuration.FunctionName', 'Configuration.Layers[].Arn'),
    'aws.cb.lambda.kms_key_configured': ('FunctionArn', 'KMSKeyArn'),
    'aws.lambda.vpc_configuration': ('VpcConfig.VpcId',),
}
CLOUDFRONT_FIELDS = {
    'aws.b.cloudfront.access_logging': ('Config.DistributionConfig.Logging.Enabled',),
    'aws.b.cloudfront.custom_acm_certificate': ('Config.DistributionConfig.ViewerCertificate.ACMCertificateArn',
                                                  'Config.DistributionConfig.ViewerCertificate.Certificate'),
    'aws.b.cloudfront.custom_origin_encryption': ('Config.DistributionConfig.Origins.Items[].CustomOriginConfig.OriginProtocolPolicy',
                                                   'Config.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy',
                                                   'Config.DistributionConfig.CacheBehaviors.Items[].ViewerProtocolPolicy'),
    'aws.b.cloudfront.default_root_object': ('Config.DistributionConfig.DefaultRootObject',),
    'aws.b.cloudfront.field_level_encryption': ('Config.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId',),
    'aws.b.cloudfront.geo_restrictions': ('Config.DistributionConfig.Restrictions.GeoRestriction.RestrictionType',),
    'aws.b.cloudfront.origin_group_metadata': ('Config.DistributionConfig.OriginGroups.Items',),
    'aws.b.cloudfront.sni': ('Config.DistributionConfig.ViewerCertificate.SSLSupportMethod',),
    'aws.b.cloudfront.viewer_encryption': ('Config.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy',
                                            'Config.DistributionConfig.CacheBehaviors.Items[].ViewerProtocolPolicy'),
    'aws.b.cloudfront.waf_reference': ('Config.DistributionConfig.WebACLId',),
    'aws.c2b.cloudfront.default_behavior_https': ('Config.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy',),
    'aws.c2b.cloudfront.logging_any': ('Config.DistributionConfig.Logging.Enabled',
                                       'Config.DistributionConfig.DefaultCacheBehavior.RealtimeLogConfigArn',
                                       'LogDeliveries.deliveries'),
    'aws.c2b.cloudfront.origin_traffic_encrypted': ('Config.DistributionConfig.Origins.Items',
                                                     'Config.DistributionConfig.DefaultCacheBehavior',
                                                     'Config.DistributionConfig.CacheBehaviors.Items'),
    'aws.c2b.cloudfront.recommended_tls_policy': ('Config.DistributionConfig.ViewerCertificate.MinimumProtocolVersion',),
    'aws_cloudfront_origin_failover_configured': ('Config.DistributionConfig.Origins.Items',
                                                  'Config.DistributionConfig.OriginGroups.Items',
                                                  'Config.DistributionConfig.DefaultCacheBehavior'),
}
IAM_USER_FIELDS = {
    'aws.claude_a.iam.user_in_group': ('GroupList',),
    'aws.claude_a.iam.user_one_active_key': ('AccessKeys.items[].Status',),
    'aws.claude_a.iam.admin_user_has_mfa':
        ('AttachedManagedPolicies[].PolicyArn', 'MFADevices.items'),
}
SECOND_FIELDS = {
    'aws.cb.route53.public_zone_query_logging':
        ('Config.PrivateZone', 'QueryLoggingConfigs.QueryLoggingConfigs[].CloudWatchLogsLogGroupArn'),
    'aws.cb.route53.domain_transfer_lock': ('Detail.DomainName', 'Detail.StatusList'),
    'aws.b.ssm.parameter_secure_type': ('Type',),
    'aws.b.rds_instance.nondefault_port_policy': ('Engine', 'Endpoint.Port'),
    'aws.cb.sns.failure_feedback_role': ('Attributes.Attributes.TopicArn',
                                          'Attributes.Attributes.*FailureFeedbackRoleArn'),
    'aws.iam.access_key_count': ('AccessKeys.items[].Status',),
    'aws.a.cloudtrail.insights_logging_trail': ('Status.IsLogging', 'InsightSelectors.collection_status',
                                                'InsightSelectors.absent', 'InsightSelectors.InsightSelectors'),
    'aws.cloudtrail.kms_encryption': ('KmsKeyId',),
    'aws.a.cloudtrail.home_kms_encryption': ('Region', 'HomeRegion', 'KmsKeyId'),
    'aws.a.cloudtrail.home_logging_with_insights':
        ('Region', 'HomeRegion', 'Status.IsLogging', 'InsightSelectors.collection_status',
         'InsightSelectors.absent', 'InsightSelectors.InsightSelectors'),
}
THIRD_FIELDS = {
    'aws.a.account.security_contact_present': ('Partition', 'SecurityContact.collection_status',
                                                  'SecurityContact.absent', 'SecurityContact.NamePresent'),
    'aws.b.apigateway.client_certificate': ('stageName', 'clientCertificateId'),
    'aws.b.apigateway.rest_execution_logging': ('stageName', 'methodSettings.*/*.loggingLevel'),
    'aws.b.apigateway.rest_xray': ('stageName', 'tracingEnabled'),
    'aws.b.apigateway.waf_reference': ('stageName', 'webAclArn'),
    'aws.b.apigateway.wildcard_cache_encryption':
        ('stageName', 'methodSettings.*/*.cachingEnabled', 'methodSettings.*/*.cacheDataEncrypted'),
    'aws.claude_a.ec2.launch_template_default_imdsv2':
        ('Versions[].DefaultVersion', 'Versions[].LaunchTemplateData.MetadataOptions.HttpTokens'),
}
FOURTH_FIELDS = {
    'aws.a.cloudwatch.any_state_actions':
        ('AlarmActions', 'OKActions', 'InsufficientDataActions'),
    'aws_nist_cloudwatch_alarm_action_enabled':
        ('ActionsEnabled', 'AlarmActions', 'OKActions', 'InsufficientDataActions'),
    'aws.b.alb.access_logs': ('Type', 'Attributes.Attributes[].Key', 'Attributes.Attributes[].Value'),
    'aws.b.alb.deletion_protection': ('Type', 'Attributes.Attributes[].Key', 'Attributes.Attributes[].Value'),
    'aws.b.alb.invalid_header_dropping': ('Type', 'Attributes.Attributes[].Key', 'Attributes.Attributes[].Value'),
    'aws.elbv2.access_logging': ('Type', 'Attributes.Attributes[].Key', 'Attributes.Attributes[].Value'),
    'aws.elbv2.deletion_protection': ('Type', 'Attributes.Attributes[].Key', 'Attributes.Attributes[].Value'),
    'aws.elbv2.drop_invalid_headers': ('Type', 'Attributes.Attributes[].Key', 'Attributes.Attributes[].Value'),
}
FIFTH_FIELDS = {
    'aws.b.cognito.no_guest_identities': ('Configuration.AllowUnauthenticatedIdentities',),
    'aws.b.dynamodb.deletion_protection': ('Table.Table.DeletionProtectionEnabled',),
    'aws.b.dynamodb.point_in_time_recovery':
        ('ContinuousBackups.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus',),
    'aws.b.rds_instance.iam_authentication': ('IAMDatabaseAuthenticationEnabled',),
    'aws.b.rds_instance.snapshot_tags': ('CopyTagsToSnapshot',),
    'aws.sns.kms_encryption': ('Attributes.Attributes.KmsMasterKeyId',),
}
FINAL_FIELDS = {
    'aws.a.iam.report_all_mfa': ('user', 'mfa_active'),
    'aws.b.acm.no_failed_validation': ('Certificate.Certificate.Status',),
    'aws.b.apigateway.http_execution_logging': ('StageName', 'DefaultRouteSettings.LoggingLevel'),
    'aws.b.codebuild.artifact_encryption':
        ('Configuration.projects[].name', 'Configuration.projects[].artifacts.encryptionDisabled',
         'Configuration.projects[].secondaryArtifacts[].encryptionDisabled'),
    'aws.b.codebuild.nonprivileged': ('Configuration.projects[].environment.privilegedMode',),
    'aws.b.cognito.admin_only_signup': ('Configuration.UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly',),
    'aws.b.cognito.block_all_takeover_risks':
        ('Configuration.UserPool.UserPoolAddOns.AdvancedSecurityMode',
         'Risk.RiskConfiguration.AccountTakeoverRiskConfiguration.Actions'),
    'aws.b.cognito.block_compromised_signin':
        ('Configuration.UserPool.UserPoolAddOns.AdvancedSecurityMode',
         'Risk.RiskConfiguration.CompromisedCredentialsRiskConfiguration.EventFilter',
         'Risk.RiskConfiguration.CompromisedCredentialsRiskConfiguration.Actions.EventAction'),
    'aws.b.cognito.deletion_protection': ('Configuration.UserPool.DeletionProtection',),
    'aws.b.cognito.enforced_threat_protection': ('Configuration.UserPool.UserPoolAddOns.AdvancedSecurityMode',),
    'aws.b.cognito.password_minimum_fourteen': ('Configuration.UserPool.Policies.PasswordPolicy.MinimumLength',),
    'aws.b.cognito.required_mfa': ('Configuration.UserPool.MfaConfiguration',),
    'aws.cb.apigatewayv2.stage_access_logging': ('StageName', 'AccessLogSettings'),
    'aws.cb.rds.instance_enhanced_monitoring_except_m1_small':
        ('DBInstanceClass', 'DBInstanceArn', 'EnhancedMonitoringResourceArn'),
    'aws.cb.rds.instance_extended_support': ('DBInstanceArn', 'EngineLifecycleSupport'),
    'aws.cb.rds.instance_iam_auth_supported_engines':
        ('Engine', 'DBInstanceArn', 'IAMDatabaseAuthenticationEnabled'),
    'aws.cb.sagemaker.training_output_kms': ('OutputDataConfig.S3OutputPath', 'OutputDataConfig.KmsKeyId'),
    'aws.cb.sagemaker.training_volume_kms': ('ResourceConfig.InstanceType', 'ResourceConfig.VolumeKmsKeyId'),
    'aws.cb.ssmincidents.active_with_response_plans':
        ('ReplicationSets.items[].status', 'ResponsePlans.items'),
    'aws.claude_a.ebs.attached_delete_on_termination':
        ('State', 'Attachments[].DeleteOnTermination'),
    'aws.claude_a.ec2.ami_ebs_encrypted': ('BlockDeviceMappings[].Ebs.Encrypted',),
    'aws.claude_a.ec2.eni_in_use': ('Status', 'NetworkInterfaceId', 'Attachment.InstanceId'),
    'aws.claude_a.ec2.instance_ebs_delete_on_termination':
        ('BlockDeviceMappings[].Ebs.DeleteOnTermination',),
    'aws.claude_a.ec2.launch_template_default_ebs_encrypted':
        ('Versions[].DefaultVersion', 'Versions[].LaunchTemplateData.BlockDeviceMappings[].Ebs.Encrypted'),
    'aws.claude_a.iam.not_two_active_keys':
        ('user', 'access_key_1_active', 'access_key_2_active'),
    'aws.claude_a.kms.customer_key_not_pending_deletion':
        ('Metadata.KeyMetadata.KeyManager', 'Metadata.KeyMetadata.KeyState'),
    'aws.guardduty.runtime_monitoring':
        ('Configuration.Status', 'Configuration.Features[].Name', 'Configuration.Features[].Status'),
    'aws.kms.rotation':
        ('Metadata.KeyMetadata.KeyManager', 'Metadata.KeyMetadata.Origin',
         'Metadata.KeyMetadata.KeySpec', 'Rotation.KeyRotationEnabled'),
}
FOLLOWUP_FIELDS = {
    'aws.b.dynamodb.kms_description': ('Table.Table.TableName', 'Table.Table.SSEDescription'),
    'aws.b.lambda.reserved_concurrency':
        ('Concurrency.collection_status', 'Concurrency.ReservedConcurrentExecutions'),
    'aws.cb.route53.domain_auto_renew': ('Detail.DomainName', 'Detail.AutoRenew'),
    'aws.cb.sagemaker.training_intercontainer_encryption':
        ('TrainingJobArn', 'EnableInterContainerTrafficEncryption'),
    'aws.cb.trustedadvisor.premium_support': ('PremiumSupport',),
}
FINAL_COLLECTOR_REFS = {
    'acm_certificate': ('peaso/collectors/aws_b_services.py', '129-275,447-535'),
    'http_api_stage': ('peaso/collectors/aws_b_services.py', '129-275,447-535'),
    'codebuild_project': ('peaso/collectors/aws_b_services.py', '129-275,447-535'),
    'cognito_user_pool': ('peaso/collectors/aws_b_services.py', '129-275,447-535'),
    'rds_instance': ('peaso/collectors/aws.py', '1060-1130,1234-1500,2799-2920'),
    'sagemaker_training_job': ('peaso/collectors/aws_facts_cb_ca.py', '887-909,965-975,1092-1105,1316-1330'),
    'ssmincidents_account': ('peaso/collectors/aws_facts_cb_ca.py', '887-909,965-975,1092-1105,1316-1330'),
    'ebs_volume': ('peaso/collectors/aws.py', '1060-1130,1234-1500,2799-2920'),
    'ec2_image': ('peaso/collectors/aws.py', '1060-1130,1234-1500,2799-2920'),
    'network_interface': ('peaso/collectors/aws.py', '1060-1130,1234-1500,2799-2920'),
    'instance': ('peaso/collectors/aws.py', '1060-1130,1234-1500,2799-2920'),
    'ec2_launch_template': ('peaso/collectors/aws_facts_cb_ca.py', '887-909,965-975,1092-1105,1316-1330'),
    'guardduty_detector': ('peaso/collectors/aws.py', '1060-1130,1234-1500,2799-2920'),
    'iam_credential_report': ('peaso/collectors/aws.py', '1060-1130,1234-1500,2799-2920'),
    'kms_key': ('peaso/collectors/aws.py', '1060-1130,1234-1500,2799-2920'),
}
S3_EXPECTED = {
    'Encryption': {'collected': 148}, 'Versioning': {'collected': 148},
    'Logging': {'collected': 148}, 'Lifecycle': {'collected': 10, 'denied': 15, 'empty': 123},
    'Replication': {'denied': 15, 'empty': 133},
    'ObjectLock': {'denied': 15, 'empty': 133},
    'OwnershipControls': {'collected': 147, 'empty': 1},
}


def snapshot_completeness(path):
    source = Path(path)
    if hashlib.sha256(source.read_bytes()).hexdigest() != SNAPSHOT_SHA256:
        raise ValueError('exact 992 snapshot SHA changed')
    counts = collections.defaultdict(collections.Counter)
    bucket_rows = 0
    ecr_rows = 0
    ecr_status = collections.Counter()
    log_rows = 0
    log_provenance = collections.Counter()
    sqs_rows = 0
    sqs_attributes_complete = 0
    cfn_rows = 0
    cfn_complete = 0
    ecs_rows = 0
    ecs_complete = 0
    lambda_rows = 0
    lambda_complete = 0
    cloudfront_rows = 0
    cloudfront_complete = 0
    iam_user_rows = 0
    iam_user_complete = 0
    fourth_counts = collections.Counter()
    fifth_counts = collections.Counter()
    final_counts = collections.Counter()
    followup_counts = collections.Counter()
    second_counts = collections.Counter()
    third_counts = collections.Counter()
    with gzip.open(source, 'rb') as stream:
        for collection in ijson.items(stream, 'collections.item'):
            if collection.get('type') == 'sqs_queue':
                if collection.get('status') != 'collected':
                    raise ValueError('incomplete SQS collection')
                for item in collection.get('items', []):
                    sqs_rows += 1
                    container = item.get('Attributes', {})
                    attributes = container.get('Attributes', {}) if isinstance(container, dict) else {}
                    if (isinstance(container, dict)
                            and container.get('collection_status') == 'collected'
                            and isinstance(attributes, dict) and 'QueueArn' in attributes):
                        sqs_attributes_complete += 1
            if collection.get('type') == 'cloudformation_stack':
                if collection.get('status') != 'collected':
                    raise ValueError('incomplete CloudFormation collection')
                for item in collection.get('items', []):
                    cfn_rows += 1
                    if ('StackName' in item and 'RootId' not in item
                            and 'NotificationARNs' in item):
                        cfn_complete += 1
            if collection.get('type') == 'ecs_task_definition':
                if collection.get('status') != 'collected':
                    raise ValueError('incomplete ECS task definition collection')
                for item in collection.get('items', []):
                    ecs_rows += 1
                    detail = item.get('Definition')
                    if (isinstance(detail, dict)
                            and detail.get('collection_status') == 'collected'
                            and isinstance(detail.get('taskDefinition'), dict)):
                        ecs_complete += 1
            if collection.get('type') == 'lambda_function':
                if collection.get('status') != 'collected':
                    raise ValueError('incomplete Lambda function collection')
                for item in collection.get('items', []):
                    lambda_rows += 1
                    cfg = item.get('Configuration')
                    if (isinstance(cfg, dict) and cfg.get('collection_status') == 'collected'
                            and isinstance(cfg.get('FunctionName'), str)
                            and 'Layers' not in cfg and 'FunctionArn' in item
                            and 'KMSKeyArn' not in item and 'VpcConfig' in item):
                        lambda_complete += 1
            if collection.get('type') == 'cloudfront_distribution':
                if collection.get('status') != 'collected':
                    raise ValueError('incomplete CloudFront collection')
                for item in collection.get('items', []):
                    cloudfront_rows += 1
                    cfg = item.get('Config')
                    deliveries = item.get('LogDeliveries')
                    if (isinstance(cfg, dict) and cfg.get('collection_status') == 'collected'
                            and isinstance(cfg.get('DistributionConfig'), dict)
                            and isinstance(deliveries, dict)
                            and deliveries.get('collection_status') == 'collected'
                            and isinstance(deliveries.get('deliveries'), list)):
                        cloudfront_complete += 1
            if collection.get('type') == 'iam_user':
                if collection.get('status') != 'collected':
                    raise ValueError('incomplete IAM user collection')
                for item in collection.get('items', []):
                    iam_user_rows += 1
                    keys, mfa = item.get('AccessKeys'), item.get('MFADevices')
                    if (isinstance(item.get('GroupList'), list)
                            and item.get('_provenance', {}).get('native_response_complete') is True
                            and isinstance(item.get('AttachedManagedPolicies'), list)
                            and isinstance(keys, dict) and keys.get('collection_status') in {'collected', 'empty'}
                            and isinstance(keys.get('items'), list)
                            and isinstance(mfa, dict) and mfa.get('collection_status') in {'collected', 'empty'}
                            and isinstance(mfa.get('items'), list)):
                        iam_user_complete += 1
            kind = collection.get('type')
            if kind in {'dynamodb_table', 'lambda_function', 'route53_domain',
                        'sagemaker_training_job', 'trustedadvisor_support'}:
                if collection.get('items') and collection.get('status') != 'collected':
                    raise ValueError('incomplete follow-up collection: ' + kind)
                for item in collection.get('items', []):
                    followup_counts[(kind, 'rows')] += 1
                    complete = {
                        'dynamodb_table': lambda: (
                            _has_path(item, 'Table.Table.TableName') and
                            item['Table'].get('collection_status') == 'collected'),
                        'lambda_function': lambda: (
                            _has_path(item, 'Concurrency') and
                            item['Concurrency'].get('collection_status') == 'collected'),
                        'route53_domain': lambda: (
                            _has_path(item, 'Detail.DomainName') and
                            _has_path(item, 'Detail.AutoRenew') and
                            item['Detail'].get('collection_status') == 'collected'),
                        'sagemaker_training_job': lambda: (
                            _has_path(item, 'TrainingJobArn') and
                            type(item.get('EnableInterContainerTrafficEncryption')) is bool),
                        'trustedadvisor_support': lambda: type(item.get('PremiumSupport')) is bool,
                    }[kind]()
                    if complete:
                        followup_counts[(kind, 'complete')] += 1
            final_requirements = {
                'iam_credential_report': ('user', 'mfa_active', 'access_key_1_active', 'access_key_2_active'),
                'acm_certificate': ('Certificate.Certificate.Status',),
                'http_api_stage': ('StageName', 'DefaultRouteSettings'),
                'codebuild_project': ('Configuration.projects',),
                'cognito_user_pool': ('Configuration.UserPool.Id', 'Risk'),
                'rds_instance': ('DBInstanceArn', 'Engine', 'DBInstanceClass'),
                'sagemaker_training_job': ('TrainingJobArn', 'OutputDataConfig.S3OutputPath',
                                            'ResourceConfig.InstanceType'),
                'ssmincidents_account': ('ReplicationSets.items', 'ResponsePlans.items'),
                'ebs_volume': ('State', 'Attachments'),
                'ec2_image': ('BlockDeviceMappings',),
                'network_interface': ('NetworkInterfaceId', 'Status'),
                'instance': ('BlockDeviceMappings',),
                'ec2_launch_template': ('Versions',),
                'guardduty_detector': ('Configuration.Status', 'Configuration.Features'),
                'kms_key': ('Metadata.KeyMetadata.KeyManager', 'Metadata.KeyMetadata.KeyState'),
            }
            if kind in final_requirements:
                if collection.get('items') and collection.get('status') != 'collected':
                    raise ValueError('incomplete final-pass collection: ' + kind)
                for item in collection.get('items', []):
                    final_counts[(kind, 'rows')] += 1
                    if not all(_has_path(item, path) for path in final_requirements[kind]):
                        continue
                    details = {
                        'acm_certificate': ('Certificate',),
                        'codebuild_project': ('Configuration',),
                        'cognito_user_pool': ('Configuration', 'Risk'),
                        'guardduty_detector': ('Configuration',),
                    }.get(kind, ())
                    if any(item[name].get('collection_status') != 'collected' for name in details):
                        continue
                    if kind == 'ssmincidents_account' and any(
                            item[name].get('collection_status') not in ('collected', 'empty')
                            for name in ('ReplicationSets', 'ResponsePlans')):
                        continue
                    if kind == 'codebuild_project' and len(item['Configuration']['projects']) != 1:
                        continue
                    final_counts[(kind, 'complete')] += 1
            if kind in {'cognito_identity_pool', 'dynamodb_table', 'rds_instance', 'sns_topic'}:
                if collection.get('items') and collection.get('status') != 'collected':
                    raise ValueError('incomplete fifth-pass collection: ' + kind)
                required = {
                    'cognito_identity_pool': ('Configuration.AllowUnauthenticatedIdentities',),
                    'dynamodb_table': ('Table.Table.DeletionProtectionEnabled',
                        'ContinuousBackups.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus'),
                    'rds_instance': ('IAMDatabaseAuthenticationEnabled', 'CopyTagsToSnapshot'),
                    'sns_topic': ('Attributes.Attributes.KmsMasterKeyId',),
                }[kind]
                for item in collection.get('items', []):
                    fifth_counts[(kind, 'rows')] += 1
                    if all(_has_path(item, path) for path in required):
                        fifth_counts[(kind, 'complete')] += 1
            if kind in {'cloudwatch_alarm', 'load_balancer'}:
                if collection.get('items') and collection.get('status') != 'collected':
                    raise ValueError('incomplete fourth-pass collection: ' + kind)
                for item in collection.get('items', []):
                    fourth_counts[(kind, 'rows')] += 1
                    if kind == 'cloudwatch_alarm':
                        if (type(item.get('ActionsEnabled')) is bool
                                and all(isinstance(item.get(key), list)
                                        for key in ('AlarmActions', 'OKActions',
                                                    'InsufficientDataActions'))):
                            fourth_counts[(kind, 'complete')] += 1
                    else:
                        detail = item.get('Attributes')
                        attrs = detail.get('Attributes') if isinstance(detail, dict) else None
                        if (isinstance(detail, dict)
                                and detail.get('collection_status') == 'collected'
                                and isinstance(attrs, list)
                                and all(isinstance(row, dict)
                                        and isinstance(row.get('Key'), str)
                                        and isinstance(row.get('Value'), str)
                                        for row in attrs)):
                            fourth_counts[(kind, 'complete')] += 1
            if kind in {'route53_domain', 'route53_zone', 'ssm_parameter_metadata',
                        'rds_instance', 'sns_topic', 'cloudtrail'}:
                # Empty non-collected envelopes are ignored in these global
                # inventory counts only. bind_fail_scopes independently rejects
                # any admitted FAIL from their exact kind/scope.
                if collection.get('items') and collection.get('status') != 'collected':
                    raise ValueError('incomplete second-pass collection: ' + kind)
                for item in collection.get('items', []):
                    second_counts[(kind, 'rows')] += 1
                    if kind == 'route53_domain':
                        detail = item.get('Detail')
                        if isinstance(detail, dict) and detail.get('collection_status') == 'collected' and 'DomainName' in detail:
                            second_counts[(kind, 'complete')] += 1
                    elif kind == 'route53_zone':
                        detail = item.get('QueryLoggingConfigs')
                        if isinstance(detail, dict) and detail.get('collection_status') == 'collected' and isinstance(detail.get('QueryLoggingConfigs'), list):
                            second_counts[(kind, 'complete')] += 1
                    elif kind == 'sns_topic':
                        detail = item.get('Attributes')
                        attrs = detail.get('Attributes') if isinstance(detail, dict) else None
                        if isinstance(detail, dict) and detail.get('collection_status') == 'collected' and isinstance(attrs, dict) and 'TopicArn' in attrs:
                            second_counts[(kind, 'complete')] += 1
                    elif kind == 'cloudtrail':
                        status, insights = item.get('Status'), item.get('InsightSelectors')
                        if (isinstance(status, dict) and status.get('collection_status') == 'collected'
                                and isinstance(insights, dict) and insights.get('collection_status') == 'empty'
                                and insights.get('absent') is True):
                            second_counts[(kind, 'complete')] += 1
                    else:
                        second_counts[(kind, 'complete')] += 1
            if kind in {'aws_account_configuration', 'rest_api_stage', 'ec2_launch_template'}:
                if collection.get('items') and collection.get('status') != 'collected':
                    raise ValueError('incomplete third-pass collection: ' + kind)
                for item in collection.get('items', []):
                    third_counts[(kind, 'rows')] += 1
                    if kind == 'aws_account_configuration':
                        contact = item.get('SecurityContact')
                        if (isinstance(contact, dict) and contact.get('collection_status') == 'empty'
                                and contact.get('absent') is True):
                            third_counts[(kind, 'complete')] += 1
                    elif kind == 'rest_api_stage':
                        if (isinstance(item.get('stageName'), str)
                                and isinstance(item.get('methodSettings'), dict)
                                and isinstance(item.get('tracingEnabled'), bool)
                                and isinstance(item.get('clientCertificateId'), str)):
                            third_counts[(kind, 'complete')] += 1
                    else:
                        versions = item.get('Versions')
                        if (isinstance(versions, list)
                                and sum(isinstance(v, dict) and v.get('DefaultVersion') is True
                                        for v in versions) == 1
                                and all(isinstance(v, dict)
                                        and isinstance(v.get('LaunchTemplateData'), dict)
                                        for v in versions)):
                            third_counts[(kind, 'complete')] += 1
            if collection.get('type') == 'ecr_repository':
                if collection.get('status') != 'collected':
                    raise ValueError('incomplete ECR repository collection')
                for item in collection.get('items', []):
                    ecr_rows += 1
                    detail = item.get('LifecyclePolicy')
                    ecr_status[detail.get('collection_status') if isinstance(detail, dict) else None] += 1
            if collection.get('type') == 'log_group':
                if collection.get('status') != 'collected':
                    raise ValueError('incomplete log group collection')
                for item in collection.get('items', []):
                    log_rows += 1
                    provenance = item.get('_provenance', {})
                    log_provenance[(provenance.get('operation'),
                                    provenance.get('native_response_complete'),
                                    'kmsKeyId' in item)] += 1
            if collection.get('type') != 'bucket':
                continue
            if collection.get('status') != 'collected':
                raise ValueError('incomplete S3 bucket collection')
            for item in collection.get('items', []):
                bucket_rows += 1
                for name in S3_EXPECTED:
                    response = item.get(name)
                    status = response.get('collection_status') if isinstance(response, dict) else None
                    counts[name][status] += 1
    actual = {key: dict(counts[key]) for key in S3_EXPECTED}
    if bucket_rows != 148 or actual != S3_EXPECTED:
        raise ValueError('992 S3 detail completeness changed')
    if ecr_rows != 35 or dict(ecr_status) != {'collected': 26, 'empty': 9}:
        raise ValueError('992 ECR lifecycle detail completeness changed')
    if log_rows != 101 or dict(log_provenance) != {
            ('logs:DescribeLogGroups', True, False): 101}:
        raise ValueError('992 log group response completeness changed')
    if sqs_rows != 32 or sqs_attributes_complete != 32:
        raise ValueError('992 SQS attributes completeness changed')
    if cfn_rows != 22 or cfn_complete != 22:
        raise ValueError('992 CloudFormation root/notification completeness changed')
    if ecs_rows != 4684 or ecs_complete != 4684:
        raise ValueError('992 ECS task definition completeness changed')
    if lambda_rows != 11 or lambda_complete != 11:
        raise ValueError('992 Lambda configuration completeness changed')
    if cloudfront_rows != 10 or cloudfront_complete != 10:
        raise ValueError('992 CloudFront configuration completeness changed')
    if iam_user_rows != 22 or iam_user_complete != 22:
        raise ValueError('992 IAM user configuration completeness changed')
    second_expected = {'route53_domain': 9, 'route53_zone': 12,
                       'ssm_parameter_metadata': 6, 'rds_instance': 4,
                       'sns_topic': 5, 'cloudtrail': 3}
    if any(second_counts[(kind, suffix)] != number
           for kind, number in second_expected.items() for suffix in ('rows', 'complete')):
        raise ValueError('992 second-pass API completeness changed')
    third_expected = {'aws_account_configuration': 2, 'rest_api_stage': 2,
                      'ec2_launch_template': 11}
    if any(third_counts[(kind, suffix)] != number
           for kind, number in third_expected.items() for suffix in ('rows', 'complete')):
        raise ValueError('992 third-pass API completeness changed')
    fourth_expected = {'cloudwatch_alarm': 196, 'load_balancer': 10}
    if any(fourth_counts[(kind, suffix)] != number
           for kind, number in fourth_expected.items() for suffix in ('rows', 'complete')):
        raise ValueError('992 fourth-pass API completeness changed')
    fifth_expected = {'cognito_identity_pool': 3, 'dynamodb_table': 4,
                      'rds_instance': 4, 'sns_topic': 5}
    if any(fifth_counts[(kind, suffix)] != number
           for kind, number in fifth_expected.items() for suffix in ('rows', 'complete')):
        raise ValueError('992 fifth-pass API completeness changed')
    final_expected = {'iam_credential_report': 13, 'acm_certificate': 45,
                      'http_api_stage': 1, 'codebuild_project': 1,
                      'cognito_user_pool': 1, 'rds_instance': 4,
                      'sagemaker_training_job': 5, 'ssmincidents_account': 2,
                      'ebs_volume': 34, 'ec2_image': 1,
                      'network_interface': 104, 'instance': 34,
                      'ec2_launch_template': 11, 'guardduty_detector': 1,
                      'kms_key': 34}
    if any(final_counts[(kind, suffix)] != number
           for kind, number in final_expected.items() for suffix in ('rows', 'complete')):
        raise ValueError('992 final-pass API completeness changed')
    followup_expected = {'dynamodb_table': 4, 'lambda_function': 11,
                         'route53_domain': 9, 'sagemaker_training_job': 5,
                         'trustedadvisor_support': 2}
    if any(followup_counts[(kind, suffix)] != number
           for kind, number in followup_expected.items() for suffix in ('rows', 'complete')):
        raise ValueError('992 follow-up API completeness changed')
    return {'snapshot_sha256': SNAPSHOT_SHA256, 'bucket_rows': bucket_rows,
            'detail_status_counts': actual,
            'ecr_repository_rows': ecr_rows, 'ecr_lifecycle_status_counts': dict(ecr_status),
            'log_group_rows': log_rows,
            'log_group_complete_omitted_kms_key_count': log_rows,
            'sqs_queue_rows': sqs_rows, 'sqs_attributes_complete_count': sqs_attributes_complete,
            'cloudformation_stack_rows': cfn_rows,
            'cloudformation_root_notification_complete_count': cfn_complete,
            'ecs_task_definition_rows': ecs_rows,
            'ecs_task_definition_complete_count': ecs_complete,
            'lambda_function_rows': lambda_rows,
            'lambda_function_complete_count': lambda_complete,
            'cloudfront_distribution_rows': cloudfront_rows,
            'cloudfront_configuration_complete_count': cloudfront_complete,
            'iam_user_rows': iam_user_rows,
            'iam_user_configuration_complete_count': iam_user_complete,
            'second_pass_complete_rows': second_expected,
            'third_pass_complete_rows': third_expected,
            'fourth_pass_complete_rows': fourth_expected,
            'fifth_pass_complete_rows': fifth_expected,
            'final_pass_complete_rows': final_expected,
            'followup_complete_rows': followup_expected}


def _has_path(item, path):
    for part in path.split('.'):
        if not isinstance(item, dict) or part not in item:
            return False
        item = item[part]
    return True


def bind_fail_scopes(snapshot_path, pre_ai_path, rows, inventory_by_id):
    """Bind each admitted FAIL to its collected scope and exact native resource."""
    if hashlib.sha256(Path(pre_ai_path).read_bytes()).hexdigest() != PRE_AI_SHA256:
        raise ValueError('exact 992 pre-AI report SHA changed')
    collected, unavailable, complete_empty = set(), set(), set()
    resources = collections.defaultdict(lambda: collections.defaultdict(list))
    excluded_empty_noncollected = 0
    with gzip.open(snapshot_path, 'rb') as stream:
        for collection in ijson.items(stream, 'collections.item'):
            key = (collection.get('type'), collection.get('scope'))
            status = collection.get('status')
            if status == 'collected' and collection.get('items'):
                collected.add(key)
                for item in collection['items']:
                    if not isinstance(item, dict):
                        continue
                    for field in ('id', 'arn') if key[0] == 'log_group' else ('id',):
                        identity = item.get(field)
                        if isinstance(identity, str) and identity:
                            resources[key][identity].append(item)
            elif status == 'empty' and not collection.get('items'):
                complete_empty.add(key)
            elif status not in ('collected', 'empty'):
                unavailable.add(key)
                if not collection.get('items'):
                    excluded_empty_noncollected += 1
    approved = {row['check_id']: row for row in rows
                if row['decision'] == 'native_final_source_proven'}
    seen = collections.defaultdict(dict)
    scopes = collections.defaultdict(set)
    resource_bound = 0
    complete_scope_dependencies = 0
    with gzip.open(pre_ai_path, 'rb') as stream:
        for group in ijson.items(stream, 'findings.item'):
            for native in group.get('observations') or [group]:
                ident = native.get('check_id')
                if ident not in approved or native.get('status') != 'FAIL':
                    continue
                finding_id, scope = native.get('id'), native.get('scope')
                if (not isinstance(finding_id, str) or not isinstance(scope, str)
                        or finding_id in seen[ident]):
                    raise ValueError('malformed or duplicate exact native FAIL ID: ' + ident)
                key = (inventory_by_id[ident]['kind'], scope)
                if key not in collected or key in unavailable:
                    raise ValueError('native FAIL scope lacks complete collection: ' + ident)
                if inventory_by_id[ident]['target'] == 'scope':
                    for dependency in inventory_by_id[ident]['dependencies']:
                        dep_key = (dependency, scope)
                        if ((dep_key not in collected and dep_key not in complete_empty)
                                or dep_key in unavailable):
                            raise ValueError('native FAIL scope dependency incomplete: ' + ident)
                    complete_scope_dependencies += 1
                    resource_identity = ''
                else:
                    resource_identity = native.get('native_resource_id')
                    matches = resources[key].get(resource_identity, ())
                    if len(matches) != 1:
                        raise ValueError('native FAIL resource identity unresolved: ' + ident)
                    item = matches[0]
                    sections = (approved[ident].get('snapshot_completeness_ref') or {}).get('response_sections') or []
                    for section in sections:
                        detail = item.get(section)
                        if isinstance(detail, dict) and 'collection_status' in detail:
                            if detail['collection_status'] not in ('collected', 'empty'):
                                raise ValueError('native FAIL resource detail incomplete: ' + ident)
                    if ident == 'aws.claude_a.s3.event_notifications' and (
                            not isinstance(item.get('Notifications'), dict) or
                            item['Notifications'].get('collection_status') != 'collected'):
                        raise ValueError('notification absence lacks complete detail: ' + ident)
                    resource_bound += 1
                seen[ident][finding_id] = (scope, resource_identity)
                scopes[ident].add(scope)
    for ident, row in approved.items():
        if len(seen[ident]) != row['native_fail_count']:
            raise ValueError('native FAIL scope coverage count changed: ' + ident)
        digest = hashlib.sha256('\n'.join(
            f'{finding_id}\t{scope}\t{resource}'
            for finding_id, (scope, resource) in sorted(seen[ident].items())
        ).encode()).hexdigest()
        row['exact_fail_scope_binding'] = {
            'pre_ai_report_sha256': PRE_AI_SHA256,
            'matched_native_fail_ids': len(seen[ident]),
            'collected_scope_count': len(scopes[ident]),
            'exact_finding_resource_scope_pairs_sha256': digest,
            'resource_identity_bound': inventory_by_id[ident]['target'] != 'scope',
            'no_partial_or_denied_scope_overlap': True,
        }
    return {'source_sha256': PRE_AI_SHA256,
            'source_proven_fail_ids_bound_to_collected_scopes': sum(map(len, seen.values())),
            'source_proven_fail_ids_bound_to_exact_resources': resource_bound,
            'scope_target_fail_ids_with_complete_dependencies': complete_scope_dependencies,
            'zero_item_partial_or_denied_envelopes_excluded': excluded_empty_noncollected,
            'zero_item_noncollected_envelopes_never_count_as_complete': True}


def call_name(node):
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return '<dynamic>'


def ecs_mount_underlying(function):
    """Pin the register -> HackTricks wrapper -> exact check implementation."""
    chain = []
    current = function
    for _ in range(3):
        cells = [cell.cell_contents for cell in current.__closure__ or ()
                 if inspect.isfunction(cell.cell_contents)]
        if len(cells) != 1:
            raise ValueError('ECS evaluator wrapper chain changed')
        current = cells[0]
        chain.append(str(Path(inspect.getsourcefile(current)).resolve().relative_to(ROOT)))
    if chain != ['peaso/checks/__init__.py', 'peaso/checks/hacktricks_bp_common.py',
                 'peaso/checks/hacktricks_bp_aws.py'] or current.__name__ != 'ecs_host_mounts':
        raise ValueError('ECS evaluator implementation changed')
    return current


def proof(check, inventory, field_specs, *, s3_coverage=None):
    from peaso.checks import CHECKS
    registered = next((row for row in CHECKS if row.id == check['check_id']), None)
    if registered is None:
        raise ValueError('missing registered evaluator: ' + check['check_id'])
    function = inspect.unwrap(registered.evaluate)
    raw, start = inspect.getsourcelines(function)
    body = ''.join(raw)
    relative = str(Path(inspect.getsourcefile(function)).resolve().relative_to(ROOT))
    evaluator_hash = hashlib.sha256(body.encode()).hexdigest()
    if (inventory['evaluator_source_sha256'] != evaluator_hash
            or inventory['native_fail_count'] != check['native_fail_count']
            or inventory['initial_representatives'] != check['initial_representatives']):
        raise ValueError('source or exact-992 count changed: ' + check['check_id'])
    syntax = ast.parse(textwrap.dedent(body))
    definition = next((node for node in ast.walk(syntax)
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if definition is None:
        raise ValueError('evaluator has no source function: ' + check['check_id'])
    nodes = [node for statement in definition.body for node in ast.walk(statement)]
    calls = [{'name': call_name(node), 'line': start + node.lineno - 1}
             for node in nodes if isinstance(node, ast.Call)]
    fields = [{'path': node.args[1].value, 'line': start + node.lineno - 1}
              for node in nodes if isinstance(node, ast.Call) and call_name(node) == 'get'
              and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
              and isinstance(node.args[1].value, str)]
    spec = field_specs.get(check['check_id'])
    if spec:
        fields.append({'path': spec['path'], 'line': start + definition.lineno - 1,
                       'binding': 'FIELD_SPECS registration'})
    result_lines = sorted({start + node.lineno - 1 for node in nodes
                           if isinstance(node, ast.Call) and call_name(node) == 'result'})
    predicates = [
        {'line': start + node.lineno - 1,
         'expression': ast.get_source_segment(textwrap.dedent(body), node.args[0])}
        for node in nodes if isinstance(node, ast.Call) and call_name(node) == 'result'
        and node.args
    ]
    index_read = next((start + node.lineno - 1 for node in nodes
                       if isinstance(node, ast.Name) and node.id == 'index'
                       and isinstance(node.ctx, ast.Load)), None)
    helper_refs = []
    unresolved = []
    for call in calls:
        name = call['name']
        if name == 'acceptable' and check['check_id'].startswith('aws.a.iam.password_policy_'):
            continue  # PASSWORD_SPECS: fixed bool/threshold lambdas, lines 12-20.
        if name in SAFE_CALLS or name in {'get', 'result', 'unknown'}:
            continue
        target = function.__globals__.get(name)
        if name in CANDIDATE_HELPERS and inspect.isfunction(target):
            lines, helper_start = inspect.getsourcelines(target)
            path = str(Path(inspect.getsourcefile(target)).resolve().relative_to(ROOT))
            approved_helper = ((check['check_id'].startswith('aws.a.iam.password_policy_')
                                and name in {'password_row', 'scope_subject'})
                               or (check['check_id'] == 'aws.c2b.cloudfront.custom_ssl_certificate'
                                   and name == '_cfg'))
            helper_refs.append({'path': path, 'lines': f'{helper_start}-{helper_start + len(lines) - 1}',
                                'symbol': target.__name__,
                                'source_file_sha256': hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                                'purpose': ('reviewed strict field/complete collection helper' if approved_helper
                                            else 'candidate helper source; chain and omissions unverified')})
        else:
            unresolved.append(call)
    unsupported = unresolved[0] if unresolved else None
    # A proof here is deliberately narrow. Helpers and scoped joins can be
    # admitted only after a separate exact code-path and completeness review.
    binding_line = None
    binding_path = None
    if check['check_id'] in BOUND_REGISTRATIONS or spec:
        for candidate in sorted((ROOT / 'peaso/checks').glob('*.py')):
            for number, line in enumerate(candidate.read_text().splitlines(), 1):
                if '"' + check['check_id'] + '"' in line:
                    binding_line = number
                    binding_path = str(candidate.relative_to(ROOT))
                    break
            if binding_line is not None:
                break
        if check['check_id'] in {'aws.b.rds_instance.iam_authentication',
                                 'aws.b.rds_instance.snapshot_tags'}:
            binding_path = 'peaso/checks/aws_b_databases.py'
            binding_line = 12 if check['check_id'].endswith('iam_authentication') else 15
        # Dynamically assembled IDs need a separate registration audit.
    bound = bool(fields) or bool(helper_refs) or binding_line is not None or check['check_id'] in {
        'aws.b.cloudfront.waf_reference', 'aws.b.cloudfront.default_root_object',
        'aws.b.cloudfront.field_level_encryption', 'aws.b.cloudfront.geo_restrictions',
        'aws.b.cloudfront.custom_acm_certificate', 'aws.b.ecr.lifecycle_rules',
        'aws.b.cloudfront.origin_group_metadata',
    }
    # The two special parsers below only inspect structured API metadata; the
    # source lines and recorded fields are pinned in the row, not inferred from
    # the control title.
    structured = check['check_id'] == 'aws.b.ecr.lifecycle_rules'
    if structured:
        unresolved = [call for call in unresolved if call['name'] != 'loads']
        unsupported = unresolved[0] if unresolved else None
        helper_refs.append({'path': 'peaso/checks/aws_b_ecr.py', 'lines': '17-29',
                            'symbol': 'lifecycle', 'purpose': 'JSON rules metadata presence only',
                            'source_file_sha256': hashlib.sha256((ROOT / 'peaso/checks/aws_b_ecr.py').read_bytes()).hexdigest()})
    reviewed_scope = check['check_id'].startswith('aws.a.iam.password_policy_')
    reviewed_ecs_mount = check['check_id'] == 'aws.htbp.ecs.no_sensitive_host_mounts'
    reviewed_ecs = (check['check_id'] in ECS_FIELDS
                    and isinstance(s3_coverage, dict)
                    and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                    and s3_coverage.get('ecs_task_definition_rows') == 4684
                    and s3_coverage.get('ecs_task_definition_complete_count') == 4684)
    reviewed_lambda = (check['check_id'] in LAMBDA_FIELDS
                       and isinstance(s3_coverage, dict)
                       and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                       and s3_coverage.get('lambda_function_rows') == 11
                       and s3_coverage.get('lambda_function_complete_count') == 11)
    reviewed_cloudfront = (check['check_id'] in CLOUDFRONT_FIELDS
                           and isinstance(s3_coverage, dict)
                           and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                           and s3_coverage.get('cloudfront_distribution_rows') == 10
                           and s3_coverage.get('cloudfront_configuration_complete_count') == 10)
    reviewed_iam_user = (check['check_id'] in IAM_USER_FIELDS
                         and isinstance(s3_coverage, dict)
                         and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                         and s3_coverage.get('iam_user_rows') == 22
                         and s3_coverage.get('iam_user_configuration_complete_count') == 22)
    second_expected = {'route53_domain': 9, 'route53_zone': 12,
                       'ssm_parameter_metadata': 6, 'rds_instance': 4,
                       'sns_topic': 5, 'cloudtrail': 3}
    reviewed_second = (check['check_id'] in SECOND_FIELDS
                       and isinstance(s3_coverage, dict)
                       and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                       and s3_coverage.get('second_pass_complete_rows') == second_expected)
    third_expected = {'aws_account_configuration': 2, 'rest_api_stage': 2,
                      'ec2_launch_template': 11}
    reviewed_third = (check['check_id'] in THIRD_FIELDS
                      and isinstance(s3_coverage, dict)
                      and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                      and s3_coverage.get('third_pass_complete_rows') == third_expected)
    fourth_expected = {'cloudwatch_alarm': 196, 'load_balancer': 10}
    reviewed_fourth = (check['check_id'] in FOURTH_FIELDS
                       and isinstance(s3_coverage, dict)
                       and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                       and s3_coverage.get('fourth_pass_complete_rows') == fourth_expected)
    fifth_expected = {'cognito_identity_pool': 3, 'dynamodb_table': 4,
                      'rds_instance': 4, 'sns_topic': 5}
    reviewed_fifth = (check['check_id'] in FIFTH_FIELDS
                      and isinstance(s3_coverage, dict)
                      and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                      and s3_coverage.get('fifth_pass_complete_rows') == fifth_expected)
    final_expected = {'iam_credential_report': 13, 'acm_certificate': 45,
                      'http_api_stage': 1, 'codebuild_project': 1,
                      'cognito_user_pool': 1, 'rds_instance': 4,
                      'sagemaker_training_job': 5, 'ssmincidents_account': 2,
                      'ebs_volume': 34, 'ec2_image': 1,
                      'network_interface': 104, 'instance': 34,
                      'ec2_launch_template': 11, 'guardduty_detector': 1,
                      'kms_key': 34}
    reviewed_final = (check['check_id'] in FINAL_FIELDS
                      and isinstance(s3_coverage, dict)
                      and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                      and s3_coverage.get('final_pass_complete_rows') == final_expected)
    followup_expected = {'dynamodb_table': 4, 'lambda_function': 11,
                         'route53_domain': 9, 'sagemaker_training_job': 5,
                         'trustedadvisor_support': 2}
    reviewed_followup = (check['check_id'] in FOLLOWUP_FIELDS
                         and isinstance(s3_coverage, dict)
                         and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                         and s3_coverage.get('followup_complete_rows') == followup_expected)
    if reviewed_followup:
        source_paths = {
            'aws.b.dynamodb.kms_description': ('peaso/checks/aws_b_regional.py', 'peaso/collectors/aws_b_services.py'),
            'aws.b.lambda.reserved_concurrency': ('peaso/checks/aws_b_core.py', 'peaso/collectors/aws_b_services.py'),
            'aws.cb.route53.domain_auto_renew': ('peaso/checks/claude_aws_b_common.py',
                                                   'peaso/checks/claude_aws_b_security.py',
                                                   'peaso/collectors/aws_facts_cb_ca.py'),
            'aws.cb.sagemaker.training_intercontainer_encryption': ('peaso/checks/claude_aws_b_common.py',
                                                                      'peaso/checks/claude_aws_b_compute.py',
                                                                      'peaso/collectors/aws_facts_cb_ca.py'),
            'aws.cb.trustedadvisor.premium_support': ('peaso/checks/claude_aws_b_common.py',
                                                       'peaso/checks/claude_aws_b_security.py',
                                                       'peaso/collectors/aws_facts_cb_ca.py'),
        }[check['check_id']]
        for path in source_paths:
            if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != SPECIAL_SOURCE_PINS[path]:
                raise ValueError('follow-up evaluator/collector source changed: ' + path)
    if reviewed_final:
        collector_path, _ = FINAL_COLLECTOR_REFS[registered.kind]
        for path in {relative, 'peaso/checks/facts.py', collector_path} | {
                helper['path'] for helper in helper_refs}:
            expected = SPECIAL_SOURCE_PINS.get(path)
            if expected is None or hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != expected:
                raise ValueError('reviewed final helper/evaluator source changed: ' + path)
    if reviewed_ecs:
        for helper in helper_refs:
            if helper['symbol'] in {'task', 'optional'}:
                helper['purpose'] = 'reviewed complete DescribeTaskDefinition field helper'
    reviewed_s3 = (check['check_id'] in S3_FIELDS
                   and isinstance(s3_coverage, dict)
                   and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                   and s3_coverage.get('bucket_rows') == 148
                   and s3_coverage.get('detail_status_counts') == S3_EXPECTED)
    reviewed_other_snapshot = (check['check_id'] in OTHER_SNAPSHOT_FIELDS
                               and isinstance(s3_coverage, dict)
                               and s3_coverage.get('snapshot_sha256') == SNAPSHOT_SHA256
                               and s3_coverage.get('ecr_repository_rows') == 35
                               and s3_coverage.get('ecr_lifecycle_status_counts') == {'collected': 26, 'empty': 9}
                               and s3_coverage.get('log_group_rows') == 101
                               and s3_coverage.get('log_group_complete_omitted_kms_key_count') == 101
                               and s3_coverage.get('sqs_queue_rows') == 32
                               and s3_coverage.get('sqs_attributes_complete_count') == 32
                               and s3_coverage.get('cloudformation_stack_rows') == 22
                               and s3_coverage.get('cloudformation_root_notification_complete_count') == 22)
    password_fields = []
    if reviewed_scope:
        from peaso.checks.aws_a_iam import PASSWORD_SPECS, STRONG_FIELDS
        suffix = check['check_id'].removeprefix('aws.a.iam.password_policy_')
        if suffix in PASSWORD_SPECS:
            password_fields = ['iam_password_policy.PasswordPolicy.' + PASSWORD_SPECS[suffix][0]]
        elif suffix == 'strong_min_length_8':
            password_fields = ['iam_password_policy.PasswordPolicy.MinimumPasswordLength'] + [
                'iam_password_policy.PasswordPolicy.' + field for field in STRONG_FIELDS]
        elif suffix == 'strong_min_length_14_reuse_24_age_90':
            password_fields = ['iam_password_policy.PasswordPolicy.MinimumPasswordLength'] + [
                'iam_password_policy.PasswordPolicy.' + field for field in STRONG_FIELDS] + [
                'iam_password_policy.PasswordPolicy.PasswordReusePrevention',
                'iam_password_policy.PasswordPolicy.MaxPasswordAge']
        else:
            raise ValueError('unreviewed password spec: ' + suffix)
    simple = ((registered.target == 'resource' or reviewed_scope)
              and (index_read is None or reviewed_scope)
              and unsupported is None and bound and bool(result_lines))
    from peaso.checks.facts import get as strict_get
    dynamic_gets = [node for node in nodes if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == 'get'
                    and len(node.args) > 1
                    and not (isinstance(node.args[1], ast.Constant)
                             and isinstance(node.args[1].value, str))]
    direct = (registered.target == 'resource' and index_read is None
              and unsupported is None and not helper_refs and bool(fields)
              and bool(result_lines) and function.__globals__.get('get') is strict_get
              and (not dynamic_gets or (spec is not None and binding_line is not None
                                        and all(isinstance(node.args[1], ast.Name)
                                                and node.args[1].id == 'path'
                                                for node in dynamic_gets)))
              and not any(isinstance(node.func, ast.Attribute) and node.func.attr == 'get'
                          for node in nodes if isinstance(node, ast.Call)))
    special = (reviewed_scope or reviewed_s3 or reviewed_other_snapshot or reviewed_ecs or reviewed_lambda
               or reviewed_cloudfront or reviewed_iam_user or reviewed_second or reviewed_third
               or reviewed_fourth or reviewed_fifth or reviewed_final or reviewed_followup or
               check['check_id'] == 'aws.c2b.cloudfront.custom_ssl_certificate')
    if special:
        paths = (('peaso/checks/aws_a_iam.py', 'peaso/checks/aws_a_facts.py')
                 if reviewed_scope else
                 ('peaso/checks/aws.py' if check['check_id'].startswith('aws.s3.') else
                  'peaso/checks/aws_a_s3.py' if check['check_id'].startswith('aws.a.s3.') else
                  'peaso/checks/claude_aws_a_s3.py', 'peaso/collectors/aws.py')
                 if reviewed_s3 else
                 (('peaso/checks/aws_a_cloudwatch.py', 'peaso/checks/aws_a_facts.py',
                   'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.a.cloudwatch.log_kms_encryption' else
                  ('peaso/checks/aws_b_ecr.py', 'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.b.ecr.all_tags_immutable' else
                  ('peaso/checks/aws_extended.py', 'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.ecr.lifecycle_policy' else
                  ('peaso/checks/claude_aws_b_messaging.py', 'peaso/checks/claude_aws_b_common.py',
                   'peaso/collectors/aws.py')
                  if check['check_id'].startswith('aws.cb.sqs.') else
                  ('peaso/checks/claude2_aws_b_devtools.py',
                   'peaso/checks/claude_aws_b_common.py',
                   'peaso/collectors/aws_facts_data_identity.py'))
                 if reviewed_other_snapshot else
                 (('peaso/checks/aws_b_compute.py', 'peaso/collectors/aws_b_services.py')
                  if check['check_id'].startswith('aws.b.ecs.') else
                  ('peaso/checks/claude2_aws_b_compute.py', 'peaso/collectors/aws_b_services.py'))
                 if reviewed_ecs else
                 (('peaso/checks/aws_b_core.py', 'peaso/collectors/aws_b_services.py')
                  if check['check_id'] == 'aws.b.lambda.active_tracing' else
                  ('peaso/checks/aws_b_core.py', 'peaso/collectors/aws_b_services.py')
                  if check['check_id'] == 'aws.b.lambda.insights_layer' else
                  ('peaso/checks/claude_aws_b_compute.py', 'peaso/checks/claude_aws_b_common.py',
                   'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.cb.lambda.kms_key_configured' else
                  ('peaso/checks/aws_extended.py', 'peaso/collectors/aws.py'))
                 if reviewed_lambda else
                 (('peaso/checks/aws_b_core.py', 'peaso/checks/aws_b_cloudfront.py',
                   'peaso/collectors/aws_b_services.py')
                  if check['check_id'] in {'aws.b.cloudfront.access_logging', 'aws.b.cloudfront.sni'} else
                  ('peaso/checks/aws_b_cloudfront.py', 'peaso/collectors/aws_b_services.py')
                  if check['check_id'].startswith('aws.b.cloudfront.') else
                  ('peaso/checks/claude2_aws_b_edge.py', 'peaso/collectors/aws_b_services.py',
                   'peaso/collectors/aws_facts_compute_edge.py')
                  if check['check_id'].startswith('aws.c2b.cloudfront.') else
                  ('peaso/checks/compliance_new_aws.py', 'peaso/collectors/aws_b_services.py'))
                 if reviewed_cloudfront else
                 ('peaso/checks/claude_aws_a_iam.py', 'peaso/checks/claude_aws_a_common.py',
                  'peaso/collectors/aws.py')
                 if reviewed_iam_user else
                 (('peaso/checks/claude_aws_b_security.py', 'peaso/checks/claude_aws_b_common.py',
                   'peaso/collectors/aws_facts_cb_ca.py')
                  if check['check_id'].startswith('aws.cb.route53.') else
                  ('peaso/checks/aws_b_regional.py', 'peaso/checks/aws_b_core.py',
                   'peaso/collectors/aws_b_services.py')
                  if check['check_id'] == 'aws.b.ssm.parameter_secure_type' else
                  ('peaso/checks/aws_b_storage.py', 'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.b.rds_instance.nondefault_port_policy' else
                  ('peaso/checks/claude_aws_b_messaging.py', 'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.cb.sns.failure_feedback_role' else
                  ('peaso/checks/aws.py', 'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.iam.access_key_count' else
                  ('peaso/checks/aws_a_cloudtrail.py', 'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.a.cloudtrail.insights_logging_trail' else
                  ('peaso/checks/aws_extended.py', 'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.cloudtrail.kms_encryption' else
                  ('peaso/checks/aws_a_cloudtrail_variants.py', 'peaso/collectors/aws.py'))
                 if reviewed_second else
                 (('peaso/checks/aws_a_account.py', 'peaso/collectors/aws.py')
                  if check['check_id'] == 'aws.a.account.security_contact_present' else
                  ('peaso/checks/aws_b_apigateway.py', 'peaso/collectors/aws_b_services.py')
                  if check['check_id'].startswith('aws.b.apigateway.') else
                  ('peaso/checks/claude_aws_a_ec2.py', 'peaso/collectors/aws_facts_cb_ca.py'))
                 if reviewed_third else
                 (('peaso/checks/aws_a_cloudwatch.py',) if check['check_id'] ==
                  'aws.a.cloudwatch.any_state_actions' else
                  ('peaso/checks/compliance_new_aws.py',) if check['check_id'] ==
                  'aws_nist_cloudwatch_alarm_action_enabled' else
                  ('peaso/checks/aws_b_loadbalancing.py',) if check['check_id'].startswith('aws.b.alb.') else
                  ('peaso/checks/aws_extended.py',))
                 if reviewed_fourth else
                 (('peaso/checks/aws_b_core.py', 'peaso/checks/aws_b_compute.py')
                  if check['check_id'] == 'aws.b.cognito.no_guest_identities' else
                  ('peaso/checks/aws_b_core.py', 'peaso/checks/aws_b_regional.py')
                  if check['check_id'].startswith('aws.b.dynamodb.') else
                  ('peaso/checks/aws_b_core.py', 'peaso/checks/aws_b_databases.py')
                  if check['check_id'].startswith('aws.b.rds_instance.') else
                  ('peaso/checks/aws_extended.py',))
                 if reviewed_fifth else
                 (relative, 'peaso/checks/facts.py')
                 if reviewed_final else
                 source_paths if reviewed_followup else
                 ('peaso/checks/claude2_aws_b_edge.py', 'peaso/collectors/aws_b_services.py'))
        for path in paths:
            if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != SPECIAL_SOURCE_PINS[path]:
                raise ValueError('reviewed helper or collector source changed: ' + path)
    if check['check_id'] in MANUAL_RETAIN:
        decision, reason = 'retain_ai', MANUAL_RETAIN[check['check_id']]
    elif reviewed_ecs_mount:
        decision, reason = ('native_final_source_proven',
            'peaso/checks/hacktricks_bp_aws.py:231-260 checks normalized '
            'DescribeTaskDefinition host sourcePath membership in a fixed '
            'sensitive-path set and joins it to recorded mountPoints by sourceVolume; '
            'no path content or policy intent is interpreted.')
    elif reviewed_s3:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} reads '
            'typed S3 configuration. Exact 992 bucket detail states and '
            'peaso/collectors/aws.py:1654-1701 prove complete success, '
            'documented absence, or denied/UNKNOWN before optional defaults.')
    elif reviewed_other_snapshot:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} makes a '
            'fixed recorded-configuration predicate; the exact 992 native '
            'response status/provenance and collector source prove the '
            'optional API response complete. Serialized policy text is '
            'tested for presence only, not parsed or interpreted.')
    elif reviewed_ecs:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} reads '
            'ECS DescribeTaskDefinition container or task settings. Exact '
            '992 task definition detail is collected for all 4,684 rows; '
            'optional missing members are the API configuration defaults.')
    elif reviewed_lambda:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} reads '
            'typed Lambda configuration. Exact 992 rows have collected '
            'GetFunctionConfiguration, FunctionArn identity, and explicit '
            'observed optional-field absence or VpcConfig; no source content is read.')
    elif reviewed_cloudfront:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} compares '
            'typed CloudFront distribution configuration, list cardinality, '
            'references, or fixed protocol enums. All 10 exact-992 '
            'GetDistributionConfig and LogDeliveries responses are complete; '
            'unsupported/ambiguous branches do not establish FAIL.')
    elif reviewed_iam_user:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} compares '
            'IAM group membership, access-key Status count, or direct '
            'AdministratorAccess ARN membership with MFA device count. '
            'All 22 exact-992 IAM user rows have complete authorization '
            'metadata and collected/empty credential detail collections.')
    elif reviewed_second:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} uses '
            'typed recorded configuration, fixed membership/count/enum, '
            'and exact-992 collected detail or explicit absent response; '
            'no policy content or subjective intent is read.')
    elif reviewed_third:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} compares '
            'typed API configuration, fixed wildcard settings, or a unique '
            'default launch-template version. Exact-992 API responses and '
            'every native FAIL scope are collection-bound; omissions are '
            'interpreted only after complete response proof.')
    elif reviewed_fourth:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} uses '
            'fixed typed action lists or a typed ELB attribute Key/Value '
            'lookup. The exact 992 response carries every required list or '
            'collected Attributes detail; duplicate/missing/malformed '
            'attributes cannot produce FAIL. Every FAIL scope is bound.')
    elif reviewed_fifth:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} reads '
            'the literal registered typed field through strict facts.get. '
            'Its static DOCS.get only supplies result metadata. Exact 992 '
            'responses contain the registered field in every relevant '
            'resource row, and each FAIL scope is collection-bound.')
    elif reviewed_final:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} and each '
            'listed helper were reviewed as typed recorded-field predicates. '
            'The exact 992 response has the required sentinel fields and '
            'nested API statuses for every resource of this kind; optional '
            'omissions occur only after that complete response. Every FAIL '
            'ID is bound to its collected resource scope.')
    elif reviewed_followup:
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} reads '
            'source-pinned API configuration or a documented support-service '
            'exception boolean. Exact 992 response sentinels and nested '
            'collection statuses are complete in every resource row; each '
            'native FAIL ID is bound to its collected scope. No free-text '
            'content or policy intent is evaluated.')
    elif simple and (direct or special):
        decision, reason = ('native_final_source_proven',
            f'Evaluator {relative}:{start}-{start + len(raw) - 1} uses only '
            'recorded fields, fixed comparisons and cited pure helpers; '
            'malformed or unavailable facts do not establish FAIL.')
    elif simple:
        gaps = []
        method_gets = [start + node.lineno - 1 for node in nodes
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                       and node.func.attr == 'get']
        if method_gets:
            gaps.append(f'dict.get omission/value flow at {relative}:{method_gets[0]}')
        if dynamic_gets and (spec is None or binding_line is None):
            gaps.append(f'dynamic get field at {relative}:{start + dynamic_gets[0].lineno - 1} lacks literal registration binding')
        if helper_refs:
            helper = helper_refs[0]
            gaps.append(f'helper chain {helper.get("symbol", "unknown")} at {helper["path"]}:{helper["lines"]} lacks per-call completeness proof')
        if not gaps:
            gaps.append(f'derived branch at {relative}:{start} lacks field-to-verdict proof')
        decision, reason = ('provisional_source_candidate',
            '; '.join(gaps) + '; AI remains required pending source/API proof.')
    elif index_read is not None:
        decision, reason = 'retain_ai', f'Scoped/index dependency at {relative}:{index_read} is not proven complete in this slice.'
    elif unsupported:
        decision, reason = 'retain_ai', f'Helper {unsupported["name"]} at {relative}:{unsupported["line"]} is not traced to recorded fields in this slice.'
    elif not fields:
        decision, reason = 'retain_ai', f'No strict recorded-field path proved at {relative}:{start}.'
    else:
        decision, reason = 'retain_ai', f'Evaluator branch/length at {relative}:{start} needs separate source proof.'
    underlying = None
    if reviewed_ecs_mount:
        for path in ('peaso/checks/hacktricks_bp_aws.py',
                     'peaso/checks/hacktricks_bp_common.py',
                     'peaso/collectors/aws_b_services.py'):
            if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != SPECIAL_SOURCE_PINS[path]:
                raise ValueError('reviewed ECS evaluator/helper/collector source changed: ' + path)
        actual = ecs_mount_underlying(registered.evaluate)
        actual_lines, actual_start = inspect.getsourcelines(actual)
        actual_path = str(Path(inspect.getsourcefile(actual)).resolve().relative_to(ROOT))
        actual_syntax = ast.parse(textwrap.dedent(''.join(actual_lines)))
        actual_definition = next(node for node in ast.walk(actual_syntax)
                                 if isinstance(node, ast.FunctionDef) and node.name == 'ecs_host_mounts')
        actual_nodes = [node for statement in actual_definition.body for node in ast.walk(statement)]
        predicates = [{'line': actual_start + node.lineno - 1,
                       'expression': ast.get_source_segment(textwrap.dedent(''.join(actual_lines)), node.args[0])}
                      for node in actual_nodes if isinstance(node, ast.Call)
                      and call_name(node) == 'result' and node.args]
        result_lines = [row['line'] for row in predicates]
        underlying = {'path': actual_path, 'first_line': actual_start,
                      'last_line': actual_start + len(actual_lines) - 1,
                      'symbol': 'ecs_host_mounts',
                      'source_file_sha256': SPECIAL_SOURCE_PINS[actual_path],
                      'function_sha256': hashlib.sha256(''.join(actual_lines).encode()).hexdigest()}
    return {
        'check_id': check['check_id'], 'decision': decision, 'reason': reason,
        'followup_owner': ('audit_worker' if check['check_id'].startswith('aws.c2b.')
                           and decision == 'provisional_source_candidate' else
                           'code_worker'),
        'native_fail_count': check['native_fail_count'],
        'initial_representatives': check['initial_representatives'],
        'evaluator': {'path': relative, 'first_line': start,
                      'last_line': start + len(raw) - 1,
                      'source_file_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                      'function_sha256': evaluator_hash,
                      'symbol': definition.name},
        'recorded_field_reads': fields,
        'bound_api_fields': ([field['path'] for field in fields]
                             + password_fields
                             + (list(S3_FIELDS[check['check_id']]) if reviewed_s3 else [])
                             + (list(OTHER_SNAPSHOT_FIELDS[check['check_id']])
                                if reviewed_other_snapshot else [])
                             + (list(ECS_FIELDS[check['check_id']]) if reviewed_ecs else [])
                             + (list(LAMBDA_FIELDS[check['check_id']]) if reviewed_lambda else [])
                             + (list(CLOUDFRONT_FIELDS[check['check_id']]) if reviewed_cloudfront else [])
                             + (list(IAM_USER_FIELDS[check['check_id']]) if reviewed_iam_user else [])
                             + (list(SECOND_FIELDS[check['check_id']]) if reviewed_second else [])
                             + (list(THIRD_FIELDS[check['check_id']]) if reviewed_third else [])
                             + (list(FOURTH_FIELDS[check['check_id']]) if reviewed_fourth else [])
                             + (list(FIFTH_FIELDS[check['check_id']]) if reviewed_fifth else [])
                             + (list(FINAL_FIELDS[check['check_id']]) if reviewed_final else [])
                             + (list(FOLLOWUP_FIELDS[check['check_id']]) if reviewed_followup else [])
                             + (['Definition.taskDefinition.containerDefinitions',
                                 'Definition.taskDefinition.volumes[].host.sourcePath',
                                 'Definition.taskDefinition.volumes[].name',
                                 'Definition.taskDefinition.containerDefinitions[].mountPoints[].sourceVolume',
                                 'Definition.taskDefinition.containerDefinitions[].mountPoints[].readOnly']
                                if reviewed_ecs_mount else [])
                             + (['LifecyclePolicy.collection_status', 'LifecyclePolicy.absent',
                                 'LifecyclePolicy.lifecyclePolicyText', 'rules'] if structured else [])
                             + (['Config.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate']
                                if check['check_id'] == 'aws.c2b.cloudfront.custom_ssl_certificate' else [])),
        'source_field_binding': {'path': binding_path, 'line': binding_line,
                                 'source_file_sha256': hashlib.sha256((ROOT / binding_path).read_bytes()).hexdigest() if binding_path else None,
                                 'purpose': 'literal ID and field/setting registration'} if binding_line else None,
        'result_lines': result_lines,
        'fail_predicates': predicates,
        'underlying_evaluator': underlying,
        'snapshot_completeness_ref': ({'snapshot_sha256': SNAPSHOT_SHA256,
                                       'resource_rows': (s3_coverage['bucket_rows'] if reviewed_s3 else
                                                         s3_coverage['log_group_rows'] if check['check_id'] == 'aws.a.cloudwatch.log_kms_encryption' else
                                                         s3_coverage['sqs_queue_rows'] if check['check_id'].startswith('aws.cb.sqs.') else
                                                         s3_coverage['cloudformation_stack_rows'] if check['check_id'].startswith('aws.c2b.cloudformation.') else
                                                         s3_coverage['ecs_task_definition_rows'] if reviewed_ecs else
                                                         s3_coverage['lambda_function_rows'] if reviewed_lambda else
                                                         s3_coverage['cloudfront_distribution_rows'] if reviewed_cloudfront else
                                                         s3_coverage['iam_user_rows'] if reviewed_iam_user else
                                                         (s3_coverage['iam_user_rows'] if registered.kind == 'iam_user'
                                                          else second_expected[registered.kind]) if reviewed_second else
                                                         third_expected[registered.kind] if reviewed_third else
                                                         fourth_expected[registered.kind] if reviewed_fourth else
                                                         fifth_expected[registered.kind] if reviewed_fifth else
                                                         final_expected[registered.kind] if reviewed_final else
                                                         followup_expected[registered.kind] if reviewed_followup else
                                                         s3_coverage['ecr_repository_rows']),
                                       'response_sections': sorted({path.split('.')[0]
                                                                    for path in (S3_FIELDS.get(check['check_id']) or
                                                                                 OTHER_SNAPSHOT_FIELDS.get(check['check_id']) or
                                                                                 ECS_FIELDS.get(check['check_id']) or
                                                                                 LAMBDA_FIELDS.get(check['check_id']) or
                                                                                 CLOUDFRONT_FIELDS.get(check['check_id']) or
                                                                                 IAM_USER_FIELDS.get(check['check_id']) or
                                                                                 SECOND_FIELDS.get(check['check_id']) or
                                                                                 THIRD_FIELDS.get(check['check_id']) or
                                                                                 FOURTH_FIELDS.get(check['check_id']) or
                                                                                 FIFTH_FIELDS.get(check['check_id']) or
                                                                                 FINAL_FIELDS.get(check['check_id']) or
                                                                                 FOLLOWUP_FIELDS.get(check['check_id'], ()))})}
                                      if reviewed_s3 or reviewed_other_snapshot or reviewed_ecs or reviewed_lambda
                                      or reviewed_cloudfront or reviewed_iam_user or reviewed_second or reviewed_third
                                      or reviewed_fourth or reviewed_fifth or reviewed_final or reviewed_followup else None),
        'helper_source_refs': ([{'path': 'peaso/checks/facts.py', 'lines': '12-53',
                                 'purpose': 'strict coverage-checked get/guard'}]
                               if any(call['name'] == 'get' for call in calls) else [])
                              + ([{'path': 'peaso/checks/__init__.py', 'lines': '178-183',
                                   'purpose': 'pure FAIL/PASS/UNKNOWN construction'}]
                                 if any(call['name'] in {'result', 'unknown'} for call in calls) else [])
                              + helper_refs
                              + ([{'path': 'peaso/checks/aws_a_facts.py', 'lines': '20-50',
                                   'purpose': 'complete scope-matched IAM policy collection'}]
                                 if reviewed_scope else [])
                              + ([{'path': 'peaso/checks/aws_a_iam.py', 'lines': '12-20',
                                   'purpose': 'fixed password-policy acceptable value predicates'}]
                                 if reviewed_scope else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '1321-1324',
                                   'purpose': 'GetLifecyclePolicy response or exact absent marker'}]
                                 if structured else [])
                              + ([{'path': 'peaso/collectors/aws_b_services.py', 'lines': '475-476',
                                   'purpose': 'GetDistributionConfig complete response'}]
                                 if check['check_id'] == 'aws.c2b.cloudfront.custom_ssl_certificate' else [])
                              + ([{'path': 'peaso/checks/hacktricks_bp_common.py', 'lines': '38-61',
                                   'purpose': 'wrapper only validates native row and invokes evaluator'},
                                  {'path': 'peaso/checks/hacktricks_bp_aws.py', 'lines': '220-260',
                                   'purpose': 'fixed sensitive host path list and exact volume/mount join'},
                                  {'path': 'peaso/collectors/aws_b_services.py', 'lines': '458-465',
                                   'purpose': 'complete DescribeTaskDefinition enrichment'}]
                                 if reviewed_ecs_mount else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '952-961',
                                   'purpose': 'successful API response marked collected; documented absent/denied distinct'},
                                  {'path': 'peaso/collectors/aws.py', 'lines': '1654-1701',
                                   'purpose': 'per-bucket S3 detail API reads'},
                                  {'path': 'peaso/checks/claude_aws_a_s3.py', 'lines': '57-72',
                                   'purpose': 'absent S3 section requires exact empty marker and no payload'}]
                                 if reviewed_s3 else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '2908-2911',
                                   'purpose': 'complete DescribeLogGroups response provenance'},
                                  {'path': 'peaso/checks/aws_a_facts.py', 'lines': '70-80',
                                   'purpose': 'optional omission requires matching operation and complete native response'}]
                                 if check['check_id'] == 'aws.a.cloudwatch.log_kms_encryption' else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '1321-1324',
                                   'purpose': 'ECR GetLifecyclePolicy explicit collected or absent response'}]
                                 if check['check_id'] == 'aws.ecr.lifecycle_policy' else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '1424-1430',
                                   'purpose': 'GetQueueAttributes(All) complete response and explicit KMS omission'},
                                  {'path': 'peaso/checks/claude_aws_b_common.py', 'lines': '91-106',
                                   'purpose': 'QueueArn sentinel and coverage-checked optional field'}]
                                 if check['check_id'].startswith('aws.cb.sqs.') else [])
                              + ([{'path': 'peaso/collectors/aws_facts_data_identity.py', 'lines': '714-722',
                                   'purpose': 'DescribeStacks projection retains RootId and NotificationARNs'},
                                  {'path': 'peaso/checks/claude_aws_b_common.py', 'lines': '91-106',
                                   'purpose': 'StackName sentinel and coverage-checked omission'}]
                                 if check['check_id'].startswith('aws.c2b.cloudformation.') else [])
                              + ([{'path': 'peaso/collectors/aws_b_services.py', 'lines': '458-481',
                                   'purpose': 'complete DescribeTaskDefinition enrichment for every revision'},
                                  {'path': 'peaso/checks/facts.py', 'lines': '127-132',
                                   'purpose': 'coverage-checked API optional member default'}]
                                 if reviewed_ecs else [])
                              + ([{'path': 'peaso/collectors/aws_b_services.py', 'lines': '480-490',
                                   'purpose': 'GetFunctionConfiguration collected detail'},
                                  {'path': 'peaso/collectors/aws.py', 'lines': '2947-2957',
                                   'purpose': 'Lambda documented optional VpcConfig projection'}]
                                 if reviewed_lambda else [])
                              + ([{'path': 'peaso/collectors/aws_b_services.py', 'lines': '475-476',
                                   'purpose': 'complete GetDistributionConfig response'},
                                  {'path': 'peaso/collectors/aws_facts_compute_edge.py', 'lines': '554-569',
                                   'purpose': 'collected CloudFront v2 LogDeliveries fact'}]
                                 if reviewed_cloudfront else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '1484-1503',
                                   'purpose': 'per-user access key and MFA device collections'},
                                  {'path': 'peaso/collectors/aws.py', 'lines': '1525-1558',
                                   'purpose': 'complete IAM authorization details and managed policy projection'}]
                                 if reviewed_iam_user else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '952-961',
                                   'purpose': 'recorded collected/empty detail status'},
                                  {'path': 'peaso/collectors/aws_facts_cb_ca.py', 'lines': '821-837',
                                   'purpose': 'Route53 domain detail projection and contact omission'}]
                                 if reviewed_second else [])
                              + ([{'path': 'peaso/collectors/aws.py', 'lines': '952-961',
                                   'purpose': 'per-scope API status and explicit absent response'},
                                  {'path': 'peaso/collectors/aws_b_services.py', 'lines': '252-264',
                                   'purpose': 'GetStages complete response'},
                                  {'path': 'peaso/collectors/aws_facts_cb_ca.py', 'lines': '1092-1103',
                                   'purpose': 'DescribeLaunchTemplateVersions default-version projection'}]
                                 if reviewed_third else [])
                              + ([{'path': 'peaso/checks/aws_b_loadbalancing.py', 'lines': '9-17',
                                   'purpose': 'strict attribute list and duplicate-key rejection'},
                                  {'path': 'peaso/checks/aws_extended.py', 'lines': '121-130',
                                   'purpose': 'exactly one selected attribute or unavailable'}]
                                 if reviewed_fourth and registered.kind == 'load_balancer' else [])
                              + ([{'path': FINAL_COLLECTOR_REFS[registered.kind][0],
                                   'lines': FINAL_COLLECTOR_REFS[registered.kind][1],
                                   'purpose': 'source-pinned exact-992 API collection and nested response projection',
                                   'source_file_sha256': SPECIAL_SOURCE_PINS[FINAL_COLLECTOR_REFS[registered.kind][0]]}]
                                 if reviewed_final else []),
        'index_read_line': index_read,
        'untraced_helper_call': unsupported,
        'evidence_keys': inventory['evidence_keys'],
        'evidence_type_counts': inventory['evidence_type_counts'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('split_ids')
    parser.add_argument('source_inventory')
    parser.add_argument('--disjoint-split', required=True)
    parser.add_argument('--snapshot', required=True,
                        help='SHA-pinned exact 992 snapshot; only metadata status counts are retained')
    parser.add_argument('--pre-ai-report', required=True,
                        help='SHA-pinned grouped 992 pre-AI report for exact FAIL scope binding')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    split = json.loads(Path(args.split_ids).read_text())
    disjoint = json.loads(Path(args.disjoint_split).read_text())
    inventory = json.loads(Path(args.source_inventory).read_text())
    selected = split.get('check_ids')
    if (split.get('scan_id') != inventory.get('scan_id')
            or type(selected) is not list
            or split.get('check_count') != len(selected)
            or inventory.get('zero_disagreement_checks') != 293):
        raise ValueError('wrong audit slice/source inventory')
    by_id = {row['check_id']: row for row in inventory['checks']}
    if (disjoint.get('scan_id') != split['scan_id']
            or disjoint.get('check_count') != 72
            or len(set(selected) & set(disjoint.get('check_ids', []))) != 0):
        raise ValueError('audit worker split overlaps or changed')
    from peaso.checks.facts import FIELD_SPECS
    s3_coverage = snapshot_completeness(args.snapshot)
    rows = [proof(by_id[ident], by_id[ident], FIELD_SPECS, s3_coverage=s3_coverage)
            for ident in selected]
    if (len(rows) != 190 or len({row['check_id'] for row in rows}) != len(rows)
            or any(row['initial_representatives'] >= 3 for row in rows)):
        raise ValueError('low-representative split changed')
    scope_binding = bind_fail_scopes(args.snapshot, args.pre_ai_report, rows, by_id)
    value = {'schema_version': 2, 'status': 'independent_source_review',
             'allowlist_activation': False,
             'scan_id': split['scan_id'], 'source_commit': inventory['source_commit'],
             'scope': 'code-worker 190-ID disjoint low-representative source slice; provisional aws.c2b IDs handed to audit worker',
             'source_inventory_sha256': hashlib.sha256(Path(args.source_inventory).read_bytes()).hexdigest(),
             'split_sha256': hashlib.sha256(Path(args.split_ids).read_bytes()).hexdigest(),
             'disjoint_split_sha256': hashlib.sha256(Path(args.disjoint_split).read_bytes()).hexdigest(),
             's3_snapshot_completeness': s3_coverage,
             'exact_fail_scope_binding': scope_binding,
             'source_proven_count': sum(row['decision'] == 'native_final_source_proven' for row in rows),
             'provisional_candidate_count': sum(row['decision'] == 'provisional_source_candidate' for row in rows),
             'retain_ai_count': sum(row['decision'] == 'retain_ai' for row in rows),
             'checks': rows}
    Path(args.output).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: value[key] for key in ('source_proven_count', 'retain_ai_count')}))


if __name__ == '__main__':
    main()
