"""Check-authorized observed values, independent of finding verdict inference.

Only explicit typed fields are projected; raw evidence remains unchanged.
"""
from math import isfinite

FIELDS = {'aws.rds.no_public_endpoint': ('boolean',
                                'publicly_accessible',
                                'The RDS endpoint is configured as publicly accessible.',
                                'The RDS endpoint is not configured as publicly accessible.'),
 'aws.kms.rotation': ('boolean',
                      'rotation_enabled',
                      'Automatic KMS key rotation is enabled.',
                      'Automatic KMS key rotation is disabled.'),
 'aws.rds.copy_snapshot_tags': ('boolean',
                                'copy_tags_to_snapshot',
                                'RDS copies instance tags to snapshots.',
                                'RDS does not copy instance tags to snapshots.'),
 'aws.b.aurora.mysql_copy_snapshot_tags': ('boolean',
                                           'copy_tags_to_snapshot',
                                           'Aurora MySQL copies cluster tags to snapshots.',
                                           'Aurora MySQL does not copy cluster tags to snapshots.'),
 'aws.b.aurora.postgres_copy_snapshot_tags': ('boolean',
                                              'copy_tags_to_snapshot',
                                              'Aurora PostgreSQL copies cluster tags to snapshots.',
                                              'Aurora PostgreSQL does not copy cluster tags to snapshots.'),
 'aws.b.codebuild.nonprivileged': ('boolean',
                                   'privileged_environment',
                                   'The CodeBuild environment enables privileged container mode.',
                                   'The CodeBuild environment disables privileged container mode.'),
 'aws.b.codebuild.s3_log_encryption': ('boolean',
                                       's3_log_encryption_disabled',
                                       'CodeBuild explicitly disables S3 log encryption.',
                                       'CodeBuild does not explicitly disable S3 log encryption.'),
 'aws.b.apigateway.rest_xray': ('boolean',
                                'tracing_enabled',
                                'The REST API stage enables X-Ray tracing.',
                                'The REST API stage disables X-Ray tracing.'),
 'aws.b.rds_instance.multiple_az': ('boolean',
                                    'multi_az',
                                    'RDS Multi-AZ deployment is enabled.',
                                    'RDS Multi-AZ deployment is disabled.'),
 'aws.claude_a.ec2.client_vpn_connection_logging': ('boolean',
                                                    'connection_logging',
                                                    'Client VPN connection logging is enabled.',
                                                    'Client VPN connection logging is disabled.'),
 'aws.claude_a.ec2.eni_source_dest_check': ('boolean',
                                            'source_dest_check',
                                            'The network interface enables source/destination checking.',
                                            'The network interface disables source/destination checking.'),
 'aws.claude_a.s3.directory_bucket_lifecycle': ('boolean',
                                                'lifecycle',
                                                'The directory bucket has a lifecycle configuration.',
                                                'The directory bucket has no lifecycle configuration.'),
 'aws.cb.apigatewayv2.stage_access_logging': ('boolean',
                                              'access_log_settings',
                                              'The API stage has access-log settings.',
                                              'The API stage has no access-log settings.'),
 'aws.cb.glue.catalog_password_encryption': ('boolean',
                                             'return_connection_password_encrypted',
                                             'Glue encrypts returned connection passwords.',
                                             'Glue does not encrypt returned connection passwords.'),
 'aws.cb.glue.catalog_password_encryption_with_tables': ('boolean',
                                                         'return_connection_password_encrypted',
                                                         'Glue encrypts returned connection passwords.',
                                                         'Glue does not encrypt returned connection passwords.'),
 'aws.cb.glue.catalog_policy_not_public': ('boolean',
                                           'public',
                                           'The Glue catalog policy matches the public-access pattern.',
                                           'The Glue catalog policy does not match the public-access pattern.'),
 'aws.cb.glue.ml_transform_encryption_configured': ('boolean',
                                                    'transform_encryption',
                                                    'The Glue ML transform has encryption settings.',
                                                    'The Glue ML transform has no encryption settings.'),
 'aws.cb.storagegateway.fileshare_kms': ('boolean',
                                         'kms_encrypted',
                                         'The file share enables KMS encryption.',
                                         'The file share does not enable KMS encryption.'),
 'aws.cb.workspaces.root_volume_encryption': ('boolean',
                                              'RootVolumeEncryptionEnabled',
                                              'The WorkSpace root volume is encrypted.',
                                              'The WorkSpace root volume is not encrypted.'),
 'aws.cb.workspaces.user_volume_encryption': ('boolean',
                                              'UserVolumeEncryptionEnabled',
                                              'The WorkSpace user volume is encrypted.',
                                              'The WorkSpace user volume is not encrypted.'),
 'aws.cb.mq.activemq_audit_logs': ('boolean',
                                   'audit',
                                   'Amazon MQ audit logging is enabled.',
                                   'Amazon MQ audit logging is disabled.'),
 'aws.cb.kafka.mutual_tls_authentication': ('boolean',
                                            'tls_authentication',
                                            'MSK TLS client authentication is enabled.',
                                            'MSK TLS client authentication is disabled.'),
 'aws.cb.kafka.unauthenticated_access_disabled': ('boolean',
                                                  'unauthenticated',
                                                  'MSK permits unauthenticated access.',
                                                  'MSK disables unauthenticated access.'),
 'aws.cb.mskconnect.log_delivery': ('boolean',
                                    'log_delivery',
                                    'MSK Connect has a configured log destination.',
                                    'MSK Connect has no configured log destination.'),
 'aws.cb.sns.topic_not_publicly_accessible_prowler': ('boolean',
                                                      'public',
                                                      'The SNS policy matches the public-access pattern.',
                                                      'The SNS policy does not match the public-access pattern.'),
 'aws.cb.sqs.dead_letter_queue': ('boolean',
                                  'redrive_policy',
                                  'The queue has a dead-letter redrive policy.',
                                  'The queue has no dead-letter redrive policy.'),
 'aws.cb.sqs.queue_not_public_prowler': ('boolean',
                                         'public',
                                         'The SQS policy matches the public-access pattern.',
                                         'The SQS policy does not match the public-access pattern.'),
 'aws.cb.ses.identity_policies_not_public': ('boolean',
                                             'public',
                                             'The SES identity policy matches the public-access pattern.',
                                             'The SES identity policy does not match the public-access pattern.'),
 'aws.cb.sagemaker.model_vpc_config': ('boolean',
                                       'vpc_config',
                                       'The SageMaker model has a VPC configuration.',
                                       'The SageMaker model has no VPC configuration.'),
 'aws.cb.sagemaker.training_vpc_config': ('boolean',
                                          'vpc_config',
                                          'The SageMaker training job has a VPC configuration.',
                                          'The SageMaker training job has no VPC configuration.'),
 'aws.c2b.athena.enforce_configuration': ('boolean',
                                          'configured',
                                          'The workgroup enforces its configuration.',
                                          'The workgroup does not enforce its configuration.'),
 'aws.c2b.athena.enforce_configuration_prowler': ('boolean',
                                                  'configured',
                                                  'The workgroup enforces its configuration.',
                                                  'The workgroup does not enforce its configuration.'),
 'aws.c2b.athena.cloudwatch_metrics': ('boolean',
                                       'configured',
                                       'The Athena workgroup publishes CloudWatch metrics.',
                                       'The Athena workgroup does not publish CloudWatch metrics.'),
 'aws.c2b.athena.cloudwatch_metrics_prowler': ('boolean',
                                               'configured',
                                               'The Athena workgroup publishes CloudWatch metrics.',
                                               'The Athena workgroup does not publish CloudWatch metrics.'),
 'aws.c2b.dms.neptune_iam_auth': ('boolean',
                                  'iam_auth_enabled',
                                  'The DMS Neptune endpoint enables IAM authentication.',
                                  'The DMS Neptune endpoint disables IAM authentication.'),
 'aws.c2b.docdb.snapshot_restore_not_all_exact': ('boolean',
                                                  'public_restore_attribute',
                                                  'The snapshot declares public restore access.',
                                                  'The snapshot does not declare public restore access.'),
 'aws.c2b.efs.access_point_user_identity': ('boolean',
                                            'posix_user',
                                            'The EFS access point declares a POSIX user identity.',
                                            'The EFS access point declares no POSIX user identity.'),
 'aws.c2b.emr.block_public_access_enabled': ('boolean',
                                             'block_public_security_group_rules',
                                             'EMR blocks public security-group rules.',
                                             'EMR does not block public security-group rules.'),
 'aws.c2b.es.audit_logs_to_cloudwatch': ('boolean',
                                         'audit_logs_to_cloudwatch',
                                         'OpenSearch audit-log export is enabled.',
                                         'OpenSearch audit-log export is disabled.'),
 'aws.c2b.es.error_logs_to_cloudwatch': ('boolean',
                                         'error_logs_to_cloudwatch',
                                         'OpenSearch error-log export is enabled.',
                                         'OpenSearch error-log export is disabled.'),
 'aws.htbp.cognito.identity_pool_classic_flow_disabled': ('boolean',
                                                          'allow_classic_flow',
                                                          'The Cognito identity pool allows the basic authentication '
                                                          'flow.',
                                                          'The Cognito identity pool disables the basic authentication '
                                                          'flow.'),
 'aws.logs.retention': ('string', 'retention', 'The log group retention is {value}.'),
 'aws.b.alb.desync_mode': ('string', 'desync_mitigation_mode', 'The ALB desynchronization mitigation mode is {value}.'),
 'aws.b.classic_elb.desync_mode': ('string',
                                   'desync_mitigation_mode',
                                   'The Classic ELB desynchronization mitigation mode is {value}.'),
 'aws.b.acm.transparency_logging': ('string', 'transparency_logging', 'Certificate Transparency logging is {value}.'),
 'aws.b.acm.no_wildcard_domain': ('string',
                                  'primary_domain',
                                  "The certificate's primary domain is {value}; alternative names are not assessed "
                                  'here.'),
 'aws.b.acm.no_failed_validation': ('string', 'certificate_status', 'The ACM certificate status is {value}.'),
 'aws.b.cloudfront.geo_restrictions': ('string',
                                       'restriction_type',
                                       'The CloudFront geographic restriction mode is {value}.'),
 'aws.b.apigateway.rest_execution_logging': ('string',
                                             'logging_level',
                                             'The REST stage execution-logging level is {value}.'),
 'aws.b.apigateway.http_execution_logging': ('string',
                                             'logging_level',
                                             'The recorded HTTP-stage execution-logging level is {value}; this is the '
                                             "source's legacy criterion."),
 'aws.claude_a.ec2.tgw_no_auto_accept_shared_attachments': ('string',
                                                            'auto_accept_shared_attachments',
                                                            'Transit Gateway automatic acceptance of shared '
                                                            'attachments is {value}.'),
 'aws.claude_a.ec2.eni_no_public_ip': ('string', 'public_ip', 'The network interface declares public address {value}.'),
 'aws.claude_a.iam.console_password_used_45': ('string',
                                               'password_last_used',
                                               'The recorded last console-password use was {value}.'),
 'aws.cb.glue.connection_jdbc_enforce_ssl': ('string',
                                             'jdbc_enforce_ssl',
                                             "The Glue JDBC connection's enforce-SSL setting is {value}."),
 'aws.cb.glue.catalog_metadata_encryption': ('string',
                                             'catalog_encryption_mode',
                                             'The Glue catalog encryption mode is {value}.'),
 'aws.cb.glue.catalog_metadata_sse_kms_with_tables': ('string',
                                                      'catalog_encryption_mode',
                                                      'The Glue catalog encryption mode is {value}.'),
 'aws.cb.glue.job_continuous_cloudwatch_logging': ('string',
                                                   'continuous_cloudwatch_log',
                                                   "The Glue job's continuous CloudWatch logging setting is {value}."),
 'aws.cb.glue.spark_job_version_3': ('string', 'glue_version', 'The Spark job uses Glue version {value}.'),
 'aws.cb.glue.ml_transform_user_data_encryption': ('string',
                                                   'mode',
                                                   'The Glue ML user-data encryption mode is {value}.'),
 'aws.cb.firehose.server_side_encryption': ('string', 'status', 'The Firehose stream encryption status is {value}.'),
 'aws.cb.kinesis.kms_encryption': ('string', 'encryption_type', 'The Kinesis stream encryption type is {value}.'),
 'aws.cb.kinesis.customer_kms_key': ('string', 'key_id', 'The Kinesis stream declares encryption key {value}.'),
 'aws.cb.storagegateway.gateway_not_on_ec2': ('string', 'host_environment', 'The Storage Gateway runs on {value}.'),
 'aws.cb.mq.activemq_active_standby': ('string', 'deployment_mode', 'The ActiveMQ broker deployment mode is {value}.'),
 'aws.cb.mq.rabbitmq_cluster_deployment': ('string',
                                           'deployment_mode',
                                           'The RabbitMQ broker deployment mode is {value}.'),
 'aws.cb.kafka.cmk_encryption_at_rest': ('string',
                                         'data_volume_kms_key_id',
                                         'MSK declares data-volume encryption key {value}; key ownership is assessed '
                                         'separately.'),
 'aws.cb.kafka.enhanced_monitoring': ('string', 'enhanced_monitoring', 'The MSK enhanced-monitoring level is {value}.'),
 'aws.cb.kafka.public_access_disabled': ('string', 'public_access_type', 'The MSK public-access setting is {value}.'),
 'aws.cb.sns.subscription_not_http': ('string', 'protocol', 'The SNS subscription uses {value} delivery.'),
 'aws.cb.sfn.logging_not_off': ('string', 'level', 'The state machine logging level is {value}.'),
 'aws.cb.stepfunctions.logging_enabled': ('string', 'level', 'The state machine logging level is {value}.'),
 'aws.cb.stepfunctions.cmk_encryption': ('string',
                                         'encryption_type',
                                         'The state machine encryption type is {value}; an AWS-owned key does not mean '
                                         'plaintext storage.'),
 'aws.cb.transfer.fips_security_policy': ('string',
                                          'security_policy',
                                          'The Transfer server declares security policy {value}.'),
 'aws.cb.transfer.pqc_ssh_kex_policy': ('string',
                                        'security_policy',
                                        'The Transfer server declares security policy {value}.'),
 'aws.c2b.ecs.fargate_latest_platform': ('string',
                                         'platform_version',
                                         'The Fargate task declares platform version {value}.'),
 'aws.c2b.cloudfront.default_behavior_https': ('string',
                                               'viewer_protocol_policy',
                                               'The default CloudFront viewer-protocol policy is {value}.'),
 'aws.c2b.cloudfront.https_sni': ('string',
                                  'ssl_support_method',
                                  'The CloudFront certificate delivery method is {value}.'),
 'aws.c2b.elbv2.cross_zone_enabled': ('string', 'cross_zone', 'Cross-zone load balancing is {value}.'),
 'aws.c2b.apigateway.domain_pqc_tls': ('string',
                                       'security_policy',
                                       'The API Gateway custom domain declares TLS policy {value}.'),
 'aws.c2b.appsync.field_level_logging': ('string', 'field_log_level', 'The AppSync field-log level is {value}.'),
 'aws.c2b.appsync.graphql_no_api_key': ('string',
                                        'authentication_type',
                                        'The AppSync API authentication mode is {value}.'),
 'aws.c2b.appsync.no_api_key_auth': ('string',
                                     'authentication_type',
                                     'The AppSync API authentication mode is {value}.'),
 'aws.c2b.datasync.task_logging_level': ('string', 'log_level', 'The DataSync task logging level is {value}.'),
 'aws.c2b.dms.endpoint_ssl': ('string', 'ssl_mode', 'The DMS endpoint SSL mode is {value}.'),
 'aws.c2b.dms.mongodb_auth': ('string', 'auth_type', 'The DMS MongoDB authentication setting is {value}.'),
 'aws.c2b.dms.redis_tls': ('string', 'ssl_security_protocol', 'The DMS Redis transport-security setting is {value}.'),
 'aws.c2b.dms.certificate_not_expired': ('string', 'valid_to', 'The DMS certificate expires at {value}.'),
 'aws.c2b.dynamodb.sse_kms': ('string',
                              'sse_type',
                              'The DynamoDB encryption metadata reports {value}; default encryption still applies.'),
 'aws.c2b.elasticache.cluster_no_default_subnet_group': ('string',
                                                         'subnet_group',
                                                         'The ElastiCache cluster uses subnet group {value}.'),
 'aws.c2b.efs.access_point_root_directory': ('string',
                                             'root_directory',
                                             'The EFS access point root directory is {value}.'),
 'aws.c2b.es.tls_1_2_policy': ('string', 'tls_security_policy', 'The OpenSearch minimum-TLS policy is {value}.'),
 'aws.claude2_a.cloudtrail.trail_bucket_mfa_delete': ('string',
                                                      'mfa_delete',
                                                      "The trail destination bucket's MFA Delete setting is {value}."),
 'aws.b.cognito.block_compromised_signin': ('string',
                                            'threat_protection_mode',
                                            'Cognito threat protection is in {value} mode.'),
 'aws.b.cognito.block_all_takeover_risks': ('string',
                                            'threat_protection_mode',
                                            'Cognito threat protection is in {value} mode.'),
 'aws.b.redshift.nondefault_admin': ('string',
                                     'declared_name',
                                     'The Redshift administrator name is {value}; the name alone does not establish '
                                     'authentication strength.'),
 'aws.b.redshift.nondefault_database': ('string',
                                        'declared_name',
                                        'The Redshift database name is {value}; this is a naming-policy check.'),
 'aws.rds.backups': ('number', 'backup_retention_days', 'RDS automated-backup retention is {value} days.'),
 'aws.b.elbv2.listener_presence': ('number', 'listener_count', 'The load balancer has {value} declared listeners.'),
 'aws.c2b.ecs.service_load_balancer_attached': ('number',
                                                'load_balancers',
                                                'The ECS service has {value} load-balancer attachments.'),
 'aws.c2b.classic_elb.has_registered_instances': ('number',
                                                  'registered_instances',
                                                  'The Classic ELB has {value} registered instances.'),
 'aws.c2b.backup.plans_exist_when_vaults': ('number', 'plans', 'The regional inventory contains {value} backup plans.'),
 'aws.c2b.backup.report_plans_when_plans': ('number',
                                            'report_plans',
                                            'The regional inventory contains {value} backup report plans.'),
 'aws.rds.vpc_configuration': ('empty', 'configured', 'No VPC reference is configured for the RDS subnet group.'),
 'aws.rds.enhanced_monitoring': ('empty', 'configured', 'The RDS instance has no enhanced-monitoring reference.'),
 'aws.cloudtrail.kms_encryption': ('empty',
                                   'configured',
                                   'The trail has no explicit KMS key reference; this does not mean its S3 objects are '
                                   'unencrypted.'),
 'aws.sns.kms_encryption': ('empty', 'configured', 'The SNS topic has no KMS key reference.'),
 'aws.b.cloudfront.waf_reference': ('empty', 'configured', 'The CloudFront distribution has no web ACL reference.'),
 'aws.b.cloudfront.default_root_object': ('empty',
                                          'configured',
                                          'The CloudFront distribution has no default root object.'),
 'aws.b.cloudfront.field_level_encryption': ('empty',
                                             'configured',
                                             'The default CloudFront behavior has no field-level encryption '
                                             'reference.'),
 'aws.b.apigateway.client_certificate': ('empty',
                                         'declared_reference',
                                         'The API stage has no client-certificate reference.'),
 'aws.b.apigateway.waf_reference': ('empty', 'declared_reference', 'The API stage has no web ACL reference.'),
 'aws.claude_a.ec2.eip_associated': ('empty', 'association_id', 'The Elastic IP has no association identifier.'),
 'aws.cb.glue.dev_endpoint_s3_encryption_first_mode': ('empty',
                                                       'security_configuration',
                                                       'The Glue development endpoint has no security-configuration '
                                                       'reference.'),
 'aws.cb.transfer.connector_logging_role': ('empty',
                                            'logging_role',
                                            'The Transfer connector has no logging-role reference.'),
 'aws.cb.sagemaker.notebook_kms_key': ('empty',
                                       'kms_key_id',
                                       'The notebook has no explicit KMS key reference; default volume encryption is a '
                                       'separate setting.'),
 'aws.cb.sagemaker.notebook_cmk': ('empty',
                                   'kms_key_id',
                                   'The notebook has no explicit customer-managed KMS key reference.'),
 'aws.cb.sagemaker.notebook_in_vpc': ('empty', 'subnet_id', 'The notebook has no VPC subnet reference.'),
 'aws.cb.sagemaker.training_output_kms': ('empty',
                                          'kms_key_id',
                                          'The training output has no explicit KMS key reference.'),
 'aws.cb.sagemaker.training_volume_kms': ('empty',
                                          'volume_kms_key_id',
                                          'The training volume has no explicit KMS key reference.'),
 'aws.cb.sagemaker.endpoint_config_kms': ('empty',
                                          'kms_key_id',
                                          'The endpoint configuration has no explicit KMS key reference.'),
 'aws.c2b.datasync.task_log_group': ('empty', 'log_group', 'The DataSync task has no log-group reference.'),
 'aws.c2b.es.in_vpc': ('empty', 'vpc_id', 'The OpenSearch domain has no VPC reference.'),
 'aws.pci.appsync.waf_web_acl': ('empty', 'web_acl_arn', 'The AppSync API has no web ACL reference.'),
 'aws_g6_api_stage_effective_waf_acl': ('empty',
                                        'effective_acl',
                                        'No effective web ACL reference is recorded for the API stage.'),
 'aws.rds.cloudwatch_log_exports': ('strings', 'log_exports', 'RDS log categories exported to CloudWatch'),
 'aws.b.aurora.mysql_audit_export': ('strings', 'exports', 'Aurora MySQL log categories exported to CloudWatch'),
 'aws.elbv2.multiple_availability_zones': ('strings',
                                           'availability_zones',
                                           'Declared load-balancer availability zones'),
 'aws.b.classic_elb.multiple_az': ('strings', 'availability_zones', 'Declared Classic ELB availability zones'),
 'aws.b.elbv2.multiple_az': ('strings', 'availability_zones', 'Declared load-balancer availability zones'),
 'aws.b.cloudfront.viewer_encryption': ('strings', 'viewer_protocol_policies', 'CloudFront viewer-protocol policies'),
 'aws.b.apigateway.private_endpoint_type': ('strings', 'endpoint_types', 'Declared API endpoint types'),
 'aws.b.neptune.audit_logging': ('strings', 'exported_categories', 'Neptune log categories exported to CloudWatch'),
 'aws.claude_a.ec2.spot_fleet_ebs_encrypted': ('strings',
                                               'unencrypted_devices',
                                               'Spot Fleet devices declaring unencrypted EBS volumes'),
 'aws.cb.sns.failure_feedback_role': ('strings', 'failure_feedback_roles', 'Configured SNS failure-feedback roles'),
 'aws.cb.sagemaker.model_vpc_subnets': ('strings', 'subnets', 'Declared SageMaker model VPC subnets'),
 'aws.cb.sagemaker.training_vpc_subnets': ('strings', 'subnets', 'Declared SageMaker training VPC subnets'),
 'aws.cb.sagemaker.endpoint_variants_more_than_one': ('strings',
                                                      'single_instance_variants',
                                                      'SageMaker endpoint variants declaring a single instance'),
 'aws.cb.sagemaker.endpoint_variants_not_exactly_one': ('strings',
                                                        'single_instance_variants',
                                                        'SageMaker endpoint variants declaring a single instance'),
 'aws.cb.sagemaker.monitoring_schedule_active': ('strings', 'scheduled', 'Active SageMaker monitoring schedules'),
 'aws.cb.sagemaker.model_registry_approved_package': ('strings',
                                                      'groups_with_approved_packages',
                                                      'Model groups with approved packages'),
 'aws.cb.sagemaker.clarify_job_exists': ('strings', 'clarify_jobs', 'Recorded SageMaker Clarify jobs'),
 'aws.c2b.cloudfront.s3_origin_access_control': ('strings',
                                                 's3_origins_without_oac',
                                                 'S3 origins without an origin access control'),
 'aws.c2b.cloudfront.s3_origin_access_identity': ('strings',
                                                  'origins_without_oai',
                                                  'S3 origins without an origin access identity'),
 'aws.c2b.classic_elb.sg_inbound_rule': ('strings',
                                         'security_groups_without_rules',
                                         'Classic ELB security groups without ingress rules'),
 'aws.c2b.classic_elb.sg_outbound_rule': ('strings',
                                          'security_groups_without_rules',
                                          'Classic ELB security groups without egress rules'),
 'aws.c2b.apigatewayv2.routes_authorization_type': ('strings',
                                                    'routes_without_authorization',
                                                    'API routes declaring no authorization'),
 'aws.c2b.apigatewayv2.routes_authorizer': ('strings',
                                            'routes_without_authorizer',
                                            'API routes without authorizer references'),
 'aws.c2b.directconnect.connection_redundancy': ('strings', 'locations', 'Observed Direct Connect locations'),
 'aws.c2b.directconnect.virtual_interface_redundancy': ('strings',
                                                        'non_redundant_gateways',
                                                        'Direct Connect gateways without the required interface '
                                                        'redundancy'),
 'aws.c2b.dax.multi_az': ('strings', 'availability_zones', 'Declared DAX availability zones'),
 'aws.c2b.dlm.policy_exists_with_snapshots': ('strings', 'policies', 'Recorded DLM policies'),
 'aws.c2b.dlm.ebs_snapshot_policy_with_snapshots': ('strings', 'policies', 'Recorded DLM EBS snapshot policies'),
 'aws.c2b.dms.task_source_logging': ('strings', 'missing_components', 'DMS source logging components not enabled'),
 'aws.c2b.dms.task_target_logging': ('strings', 'missing_components', 'DMS target logging components not enabled'),
 'aws.c2b.documentdb.cluster_log_exports': ('strings', 'exports', 'DocumentDB log categories exported to CloudWatch'),
 'aws.c2b.dynamodb.capacity_autoscaling': ('strings',
                                           'missing_dimensions',
                                           'Provisioned DynamoDB capacity dimensions without autoscaling'),
 'aws.c2b.es.all_logs_to_cloudwatch': ('strings',
                                       'missing_log_types',
                                       'OpenSearch log categories not exported to CloudWatch'),
 'aws.claude2_a.cloudtrail.account_has_logging_trail': ('strings',
                                                        'logging_trails',
                                                        'Recorded logging CloudTrail trails'),
 'aws.claude2_a.logs.log_group_not_public_via_resource_policy': ('strings',
                                                                 'exposing_policies',
                                                                 'Log-group policies matching the public-principal '
                                                                 'pattern'),
 'aws.claude2_a.config.org_aggregator_all_regions_with_delegated_admin': ('strings',
                                                                          'issues',
                                                                          'Configuration-aggregator issues'),
 'aws_cis_organizations_policy_management_delegated': ('strings',
                                                       'delegated_accounts',
                                                       'Recorded Organizations delegated administrator accounts'),
 'aws_g6_cloudtrail_region_logging_trail_present': ('strings',
                                                    'covering_trails',
                                                    'Logging trails covering this region'),
 'aws_guardduty_high_finding_alert': ('strings',
                                      'matching_rule_names',
                                      'Configured GuardDuty high-finding notification rules'),
 'aws_securityhub_critical_findings_alert': ('strings',
                                             'matching_rule_names',
                                             'Configured Security Hub critical-finding notification rules'),
 'aws_nist_waf_web_acl_resource_associated': ('strings',
                                              'associated_resource_arns',
                                              'Regional Classic WAF resource associations'),
 'aws_vpn_tunnel_encryption_configuration': ('strings',
                                             'unsafe_client_vpns',
                                             'Client VPN endpoints outside the required cipher configuration')}


def evidence_summary(finding):
    if not isinstance(finding,dict) or finding.get('provider')!='aws' or finding.get('status') not in ('PASS','FAIL'):
        return None
    cid=finding.get('check_id');e=finding.get('evidence')
    if not isinstance(cid,str) or not isinstance(e,dict):return None
    custom=_custom(cid,e)
    if custom is not None:return custom
    row=FIELDS.get(cid)
    if row is None:return None
    binding=BINDINGS.get(cid)
    if binding and e.get(binding[0])!=binding[1]:return None
    kind,key,*words=row
    if key not in e:return None
    value=e[key]
    if kind=='boolean':
        return words[0 if value else 1] if type(value) is bool else None
    if kind=='empty':
        return words[0] if value is None or value=='' else None
    if kind=='number':
        return words[0].format(value=value) if type(value) is int and value>=0 else None
    if kind=='string':
        if not isinstance(value,str) or not value.strip() or len(value)>240 or any(c in value for c in '\n\r\x00'):return None
        translations={'never_expire':'unlimited','DISABLED':'disabled','ENABLED':'enabled','OFF':'off','NONE':'none','none':'none','true':'enabled','false':'disabled','enable':'enabled','disable':'disabled','allow-all':'HTTP and HTTPS allowed','AWS_OWNED_KEY':'AWS-owned key','API_KEY':'API key','SINGLE_INSTANCE':'single instance','DEFAULT':'default','TLS_PLAINTEXT':'TLS and plaintext','no':'disabled'}
        return words[0].format(value=translations.get(value,value))
    if kind=='strings':
        if not isinstance(value,list) or any(not isinstance(v,str) or not v or len(v)>240 or any(c in v for c in '\n\r\x00') for v in value):return None
        return words[0]+': '+(', '.join(value[:3])+(' and '+str(len(value)-3)+' others' if len(value)>3 else '') if value else 'none')+'.'
    return None

# Companion discriminator fields prevent projecting a similarly named unrelated setting.
BINDINGS = {
 'aws.rds.vpc_configuration':('field','DBSubnetGroup.VpcId'),
 'aws.rds.enhanced_monitoring':('field','EnhancedMonitoringResourceArn'),
 'aws.cloudtrail.kms_encryption':('field','KmsKeyId'),
 'aws.sns.kms_encryption':('field','Attributes.Attributes.KmsMasterKeyId'),
 'aws.b.cloudfront.waf_reference':('field','WebACLId'),
 'aws.b.cloudfront.default_root_object':('field','DefaultRootObject'),
 'aws.b.cloudfront.field_level_encryption':('field','DefaultCacheBehavior.FieldLevelEncryptionId'),
 'aws.b.apigateway.client_certificate':('field','clientCertificateId'),
 'aws.b.apigateway.waf_reference':('field','webAclArn'),
 **{cid:('field','EnforceWorkGroupConfiguration') for cid in ('aws.c2b.athena.enforce_configuration','aws.c2b.athena.enforce_configuration_prowler')},
 **{cid:('field','PublishCloudWatchMetricsEnabled') for cid in ('aws.c2b.athena.cloudwatch_metrics','aws.c2b.athena.cloudwatch_metrics_prowler')},
}
FIELDS.update({
 'aws.ecr.lifecycle_policy':('string','lifecycle_policy','The ECR lifecycle policy is {value}.'),
 'aws.claude_a.ec2.eni_in_use':('string','status','The network interface status is {value}.'),
 'aws.cb.msk.client_broker_tls':('string','client_broker','MSK client connections use {value}.'),
 'aws.cb.sagemaker.domain_sso':('boolean','sso_linked','The SageMaker domain has an SSO link.','The SageMaker domain has no SSO link.'),
 'aws.cb.ses.dkim_signing':('boolean','signing_enabled','SES DKIM signing is enabled.','SES DKIM signing is disabled.'),
 'aws.c2b.firehose.encrypted_at_rest_or_msk_source':('string','encryption_status','The Firehose stream encryption status is {value}.'),
 'aws.c2b.backup.vault_policy_not_public':('boolean','public_policy','The backup vault policy matches the public-principal pattern.','The backup vault policy does not match the public-principal pattern.'),
 'aws.c2b.docdb.snapshot_not_public_prowler':('boolean','public_attribute','The DocumentDB snapshot declares a public sharing attribute.','The DocumentDB snapshot declares no public sharing attribute.'),
 'aws.cb.rds.instance_snapshot_not_public_prowler':('boolean','public_attribute','The RDS snapshot declares a public sharing attribute.','The RDS snapshot declares no public sharing attribute.'),
 'aws.cb.rds.cluster_snapshot_not_public_prowler':('boolean','public_attribute','The RDS cluster snapshot declares a public sharing attribute.','The RDS cluster snapshot declares no public sharing attribute.'),
 'aws.c2b.dynamodb.policy_not_cross_account':('boolean','cross_account_policy','The DynamoDB policy matches the cross-account access pattern.','The DynamoDB policy does not match the cross-account access pattern.'),
 'aws.c2b.dynamodb.table_protected_resource':('boolean','protected_resource','The table appears in the AWS Backup protected-resource inventory.','The table is absent from the AWS Backup protected-resource inventory.'),
 'aws.c2b.efs.file_system_protected_resource':('boolean','protected_resource','The file system appears in the AWS Backup protected-resource inventory.','The file system is absent from the AWS Backup protected-resource inventory.'),
 'aws.c2b.dynamodb.table_in_backup_selection_prowler':('boolean','backup_selection_match','An AWS Backup selection includes this table.','No AWS Backup selection includes this table.'),
 'aws.c2b.dynamodb.table_in_backup_selection_or_tag':('boolean','backup_selection_match','An AWS Backup selection or tag criterion matches the table.','No AWS Backup selection or checked tag criterion matches the table.'),
 'aws_shield_automatic_application_layer_response':('string','response_status','Shield automatic application-layer response is {value}.'),
 'aws_autoscaling_userdata_plaintext_aws_key':('boolean','has_aws_key_pair','The launch user data contains an AWS access-key/secret-key pair.','No AWS access-key/secret-key pair was detected in launch user data.'),
 'aws.pci.iam.policy_attached_to_active_principal':('boolean','usable_attachment','The policy has a usable identity attachment.','The policy has no usable identity attachment in the collected inventory.'),
 'aws_fedramp_cloudtrail_cloudwatch_integration':('boolean','simulation_allowed','The CloudTrail role simulation permits required log delivery actions.','The CloudTrail role simulation does not permit all required log delivery actions.'),
 'aws_identity_center_sso_configured':('boolean','enabled_assignment','An enabled IAM Identity Center assignment is recorded.','No enabled IAM Identity Center assignment is recorded.'),
 'aws_kms_compromised_key_restricted':('string','key_state','The key marked compromised has state {value}; access restrictions are assessed separately.'),
})
ATTRIBUTES = {
 'aws.elbv2.deletion_protection':('deletion_protection.enabled','Load-balancer deletion protection'),
 'aws.b.alb.deletion_protection':('deletion_protection.enabled','ALB deletion protection'),
 'aws.b.alb.access_logs':('access_logs.s3.enabled','ALB access logging'),
 'aws.b.alb.invalid_header_dropping':('routing.http.drop_invalid_header_fields.enabled','ALB invalid-header dropping'),
}
FEATURES = {
 'aws.guardduty.eks_audit_logs':('EKS_AUDIT_LOGS','EKS audit-log monitoring'),
 'aws.guardduty.lambda_network_logs':('LAMBDA_NETWORK_LOGS','Lambda network-log monitoring'),
 'aws.guardduty.rds_login_events':('RDS_LOGIN_EVENTS','RDS login monitoring'),
 'aws.guardduty.s3_data_events':('S3_DATA_EVENTS','S3 data-event monitoring'),
 'aws.guardduty.runtime_monitoring':('RUNTIME_MONITORING','runtime monitoring'),
}
PUBLIC_COUNTS = {
 'aws.cb.glacier.vault_policy_no_public_principal':('public_statements','Glacier vault'),
 'aws.cb.glacier.vault_policy_prohibit_public_access':('public_statements','Glacier vault'),
 'aws.cb.glacier.vault_policy_star_principal':('public_statements','Glacier vault'),
 'aws.cb.mediastore.container_policy_not_public':('public_statements','MediaStore container'),
 'aws.cb.sns.policy_no_unrestricted_wildcard':('public_statements','SNS topic'),
 'aws.cb.sns.policy_prohibit_public_access_perimeter':('public_statements','SNS topic'),
 'aws.cb.sns.policy_no_public_publish':('statements','SNS Publish'),
 'aws.cb.sns.policy_no_public_subscribe':('statements','SNS Subscribe'),
 'aws.cb.sqs.policy_no_wildcard_allow':('statements','SQS queue'),
 'aws.cb.sqs.policy_prohibit_public_access_perimeter':('statements','SQS queue'),
 'aws.c2b.es.policy_prohibit_public_access':('statements','OpenSearch domain'),
 'aws.claude2_a.logs.resource_policy_not_public':('public_statements','CloudWatch Logs'),
}


def _text(value):
    return isinstance(value,str) and bool(value.strip()) and len(value)<=240 and not any(c in value for c in '\n\r\x00')


def _strings(value):
    return isinstance(value,list) and all(_text(v) for v in value)


def _custom(cid,e):
    if cid=='aws.claude_a.iam.console_password_used_45' and 'password_last_used' not in e:
        # The credential-report successor records per-credential rows instead
        # of a flat password_last_used field.
        stale=e.get('stale_credentials')
        if isinstance(stale,list) and stale:
            rows=[row for row in stale if isinstance(row,dict) and row.get('credential')=='password']
            if len(rows)==1:
                used=rows[0].get('last_used')
                if isinstance(used,str) and used.strip() and len(used)<=64 and not any(c in used for c in '\n\r\x00'):
                    return f'The recorded last console-password use was {used}.'
        return None
    if cid in ATTRIBUTES:
        key,name=ATTRIBUTES[cid]
        if e.get('attribute')==key and e.get('configured') in ('true','false'):
            return name+' is '+('enabled.' if e['configured']=='true' else 'disabled.')
    if cid in FEATURES:
        key,name=FEATURES[cid]
        if e.get('feature')==key and e.get('configured') in ('ENABLED','DISABLED'):
            return 'GuardDuty '+name+' is '+e['configured'].lower()+'.'
    if cid in PUBLIC_COUNTS:
        key,name=PUBLIC_COUNTS[cid];n=e.get(key)
        if type(n) is int and n>=0:return f'The {name} policy has {n} '+('statement' if n==1 else 'statements')+' matching the unrestricted-principal pattern.'
    if cid=='aws.pci.vpc.peering_dns_resolution':
        options=e.get('dns_options')
        if isinstance(options,dict) and options and all(k in {'RequesterVpcInfo','AccepterVpcInfo'} and type(v) is bool for k,v in options.items()):
            return 'Peering remote DNS resolution: '+', '.join(('requester' if k=='RequesterVpcInfo' else 'accepter')+' '+('enabled' if options[k] else 'disabled') for k in ('RequesterVpcInfo','AccepterVpcInfo') if k in options)+'.'
        side=e.get('peering_side');enabled=e.get('remote_dns_resolution')
        if side in ('RequesterVpcInfo','AccepterVpcInfo') and type(enabled) is bool:return 'Remote DNS resolution is '+('enabled' if enabled else 'disabled')+' on the peering '+('requester' if side=='RequesterVpcInfo' else 'accepter')+' side.'
    if cid=='aws_g6_elbv2_only_https_tls_listeners':
        if e.get('certificate_configured') is False:return 'The HTTPS/TLS listener has no configured certificate.'
        protocols=e.get('listener_protocols')
        if _strings(protocols) and protocols:return 'The assessed listeners use '+', '.join(sorted(set(protocols)))+'.'
    if cid in {'aws.c2b.classic_elb.insecure_ssl_ciphers','aws.pci.classic_elb.predefined_ssl_policy'}:
        ports=e.get('listener_ports')
        if isinstance(ports,list) and all(type(v) is int and 0<v<=65535 for v in ports):
            if not ports:return 'No checked Classic ELB listener violates the reviewed SSL-policy criterion.'
            criterion='declares an insecure cipher policy' if cid.endswith('insecure_ssl_ciphers') else 'does not match the reviewed predefined SSL policy'
            return 'Classic ELB listener '+', '.join(str(v) for v in ports[:3])+' '+criterion+'.'
    if cid=='aws.c2b.backup.vault_policy_denies_recovery_point_deletion':
        actions=e.get('required_actions')
        required={'backup:DeleteRecoveryPoint','backup:UpdateRecoveryPointLifecycle','backup:PutBackupVaultAccessPolicy'}
        if _strings(actions) and set(actions)==required:return 'The vault policy does not satisfy the required recovery-point deletion and lifecycle deny pattern.'
    if cid in {'aws.nist.ec2_instance_effective_public_reachability','aws_fedramp_ec2_effective_public_exposure'}:
        paths=e.get('public_paths')
        if isinstance(paths,list) and paths and all(isinstance(v,dict) and _text(v.get('direct_address')) for v in paths):
            from ipaddress import ip_address
            try:addresses=[ip_address(v['direct_address']) for v in paths]
            except ValueError:return None
            if all(a.is_global for a in addresses):return 'The configuration records a public-address path to '+', '.join(str(a) for a in addresses[:3])+'; destination ports were not retained.'
    if cid=='aws.config.service_linked_role':
        a,b=e.get('role_arn'),e.get('expected_role_arn')
        if _text(a) and _text(b) and a.startswith('arn:aws:iam::') and b.startswith('arn:aws:iam::'):
            return 'AWS Config '+('uses' if a==b else 'does not use')+' the expected service-linked role.'
    if cid=='aws.b.acm.not_past_expiry_date':
        from datetime import date
        try:a=date.fromisoformat(e.get('expiry_date'));b=date.fromisoformat(e.get('snapshot_date'))
        except (TypeError,ValueError):return None
        return f'The certificate expiry date is {a}; the assessment date is {b}.'
    if cid=='aws.b.cloudfront.custom_acm_certificate':
        refs=e.get('certificate_references')
        if isinstance(refs,dict) and {'ACMCertificateArn','Certificate'}<=refs.keys():
            if all(v is None or isinstance(v,str) for v in refs.values()):
                return 'CloudFront '+('has' if any(refs.get(k) for k in ('ACMCertificateArn','Certificate')) else 'has no')+' explicit ACM certificate reference; certificate validity is not established.'
    if cid=='aws.b.cloudfront.origin_group_metadata':
        groups=e.get('origin_groups')
        if isinstance(groups,dict) and type(groups.get('Quantity')) is int and groups['Quantity']>=0:
            return f"CloudFront declares {groups['Quantity']} origin groups; failover effectiveness is not established."
    if cid in {'aws.b.cloudfront.origin_secure_protocols','aws.b.cloudfront.no_sslv3_origin'}:
        rejected=e.get('rejected_origins')
        if isinstance(rejected,list) and rejected and all(isinstance(r,dict) and _strings(r.get('ssl_protocols')) and r['ssl_protocols'] for r in rejected):
            versions=sorted({p for r in rejected for p in r['ssl_protocols']})
            return 'CloudFront custom origins permit the flagged TLS/SSL versions: '+', '.join(versions)+'.'
        if rejected==[]:return 'No CloudFront custom origin declares a prohibited TLS/SSL version.'
    if cid=='aws.b.cloudfront.custom_origin_encryption':
        origins=e.get('insecure_origins')
        if isinstance(origins,list) and all(isinstance(o,dict) and o.get('origin_protocol_policy') in ('http-only','match-viewer') for o in origins):
            return f'{len(origins)} CloudFront custom '+('origin can' if len(origins)==1 else 'origins can')+' use plaintext HTTP under the recorded viewer policy.' if origins else 'No assessed CloudFront custom origin permits plaintext HTTP.'
    if cid in {'aws.b.rds_instance.nondefault_port_policy','aws.b.rds_cluster.nondefault_port_policy'}:
        p=e.get('endpoint_port')
        if type(p) is int and 0<p<=65535:return f'The database endpoint uses port {p}; this naming/profile policy does not establish stronger authentication.'
    if cid=='aws.b.cognito.password_policy':
        n,d=e.get('minimum_length'),e.get('temporary_password_validity_days');r=e.get('requirements')
        if type(n) is int and n>=0 and type(d) is int and d>=0 and isinstance(r,dict) and all(type(v) is bool for v in r.values()):
            missing=[label for k,label in [('RequireLowercase','lowercase letters'),('RequireUppercase','uppercase letters'),('RequireNumbers','numbers'),('RequireSymbols','symbols')] if r.get(k) is False]
            return f'Cognito requires at least {n} password characters; temporary passwords last {d} days.'+(' Not required: '+', '.join(missing)+'.' if missing else '')
    if cid=='aws.b.codebuild.logs_enabled':
        a,b=e.get('cloudwatch_status'),e.get('s3_status')
        if a in ('ENABLED','DISABLED') and b in ('ENABLED','DISABLED'):return f'CodeBuild CloudWatch logging is {a.lower()}; S3 logging is {b.lower()}.'
    if cid in {'aws.b.codebuild.artifact_encryption','aws.b.codebuild.s3_artifact_encryption'}:
        if cid.endswith('.s3_artifact_encryption'):
            values=e.get('s3_encryption_disabled')
            if isinstance(values,list) and all(type(v) is bool for v in values):return f'{sum(values)} S3 artifact '+('destination explicitly disables' if sum(values)==1 else 'destinations explicitly disable')+' encryption.'
        else:
            p,s=e.get('primary_encryption_disabled'),e.get('secondary_encryption_disabled')
            if type(p) is bool and isinstance(s,list) and all(type(v) is bool for v in s):return 'CodeBuild primary artifact encryption is '+('explicitly disabled' if p else 'not explicitly disabled')+f'; {sum(s)} secondary artifact destinations explicitly disable encryption.'
    if cid=='aws.b.apigateway.wildcard_cache_encryption':
        m=e.get('wildcard_method_settings')
        if isinstance(m,dict) and type(m.get('cachingEnabled')) is bool and type(m.get('cacheDataEncrypted')) is bool:
            return 'The wildcard stage setting '+('enables' if m['cachingEnabled'] else 'disables')+' caching and '+('enables' if m['cacheDataEncrypted'] else 'disables')+' cache encryption.'
    if cid in {'aws.claude_a.s3.account_public_access_block_all','aws.claude_a.s3.prowler_account_ignore_restrict','aws.claude_a.s3.multi_region_access_point_public_access_block'}:
        s=e.get('settings');names={'BlockPublicAcls':'block public ACLs','IgnorePublicAcls':'ignore public ACLs','BlockPublicPolicy':'block public policies','RestrictPublicBuckets':'restrict public buckets'}
        if isinstance(s,dict) and all(type(s.get(k)) is bool for k in names):
            missing=[v for k,v in names.items() if s[k] is False]
            return 'S3 public-access protections not enabled: '+', '.join(missing)+'.' if missing else 'All four S3 Block Public Access protections are enabled.'
    if cid=='aws.cb.workspaces.root_and_user_volume_encryption' and type(e.get('root')) is bool and type(e.get('user')) is bool:
        return 'WorkSpace root-volume encryption is '+('enabled' if e['root'] else 'disabled')+'; user-volume encryption is '+('enabled' if e['user'] else 'disabled')+'.'
    if cid=='aws.cb.mq.engine_logging' and type(e.get('general')) is bool and type(e.get('audit')) is bool:
        return 'Amazon MQ general logging is '+('enabled' if e['general'] else 'disabled')+'; audit logging is '+('enabled' if e['audit'] else 'disabled')+'.'
    if cid=='aws.cb.kafka.tls_client_and_in_cluster':
        mode=e.get('client_broker');cluster=e.get('in_cluster')
        if mode in ('TLS','TLS_PLAINTEXT','PLAINTEXT') and type(cluster) is bool:
            return 'MSK client connections '+('require TLS' if mode=='TLS' else 'permit plaintext')+'; in-cluster TLS is '+('enabled' if cluster else 'disabled')+'.'
    if cid=='aws.cb.stepfunctions.logging_enabled' and 'level' in e and e['level'] is None:return 'The state machine supplies no logging level.'
    if cid=='aws.cb.sagemaker.notebook_supported_platform':
        platform,ended=e.get('platform_identifier'),e.get('support_ended_on')
        if _text(platform) and _text(ended):return f'The notebook uses platform {platform}; its recorded support end date is {ended}.'
    if cid=='aws.pci.iam.nonconsole_mfa_policy':
        values=e.get('missing_mfa_statement_indexes')
        if isinstance(values,list) and all(type(v) is int and v>=0 for v in values):
            return f'{len(values)} administrative policy '+('statement lacks' if len(values)==1 else 'statements lack')+' the required MFA condition.'
    if cid=='aws_nist_config_enabled_all_regions':
        regions=e.get('failing_regions')
        if isinstance(regions,list) and all(isinstance(r,dict) and _text(r.get('region')) and _text(r.get('reason')) for r in regions):
            return 'AWS Config has regional gaps: '+', '.join(r['region']+' ('+r['reason']+')' for r in regions[:3])+'.' if regions else 'No AWS Config gap was found in the checked regions.'
    return None
