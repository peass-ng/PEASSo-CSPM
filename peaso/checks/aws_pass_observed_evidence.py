"""Explicit per-check observations for successful native AWS evidence.

These labels are reviewed semantic names for supplied evidence fields. They do
not infer configuration from PASS, and retain absent evidence as absent.
"""
REVIEWED_FIELDS = {'aws.s3.versioning': {'field': 'versioning_status', 'label': 'Bucket versioning status'},
 'aws.s3.access_logging': {'field': 'logging_enabled', 'label': 'Logging configuration'},
 'aws.s3.no_public_acl': {'field': 'public_acl_grants', 'label': 'Public bucket ACL grants'},
 'aws.cloudtrail.management_events': {'field': 'event_selectors', 'label': 'CloudTrail event selectors'},
 'aws.eks.control_plane_logging': {'field': 'enabled_categories',
                                   'label': 'EKS control-plane log categories'},
 'aws.logs.retention': {'field': 'retention_days', 'label': 'Log retention in days'},
 'aws.iam.root_mfa': {'field': 'credential_flags', 'label': 'Root credential-report flags'},
 'aws.iam.password_minimum_length': {'field': 'configured',
                                     'label': 'Minimum password length',
                                     'discriminator': 'PasswordPolicy.MinimumPasswordLength'},
 'aws.iam.password_reuse_prevention': {'field': 'configured',
                                       'label': 'Password reuse history length',
                                       'discriminator': 'PasswordPolicy.PasswordReusePrevention'},
 'aws.rds.vpc_configuration': {'field': 'configured',
                               'label': 'RDS subnet-group VPC reference',
                               'discriminator': 'DBSubnetGroup.VpcId'},
 'aws.rds.enhanced_monitoring': {'field': 'configured',
                                 'label': 'RDS enhanced-monitoring reference',
                                 'discriminator': 'EnhancedMonitoringResourceArn'},
 'aws.lambda.vpc_configuration': {'field': 'configured',
                                  'label': 'Lambda VPC reference',
                                  'discriminator': 'VpcConfig.VpcId'},
 'aws.cloudtrail.kms_encryption': {'field': 'configured',
                                   'label': 'Explicit CloudTrail KMS key reference',
                                   'discriminator': 'KmsKeyId'},
 'aws.sns.kms_encryption': {'field': 'configured',
                            'label': 'SNS KMS encryption-key reference',
                            'discriminator': 'Attributes.Attributes.KmsMasterKeyId'},
 'aws.lambda.dead_letter_queue': {'field': 'target_arn', 'label': 'Dead-letter destination'},
 'aws.lambda.function_url_authentication': {'field': 'auth_type',
                                            'label': 'Lambda function URL authentication mode'},
 'aws.elbv2.desync_mitigation': {'field': 'desync_mitigation_mode',
                                 'label': 'Load-balancer desynchronization mitigation mode'},
 'aws.sqs.encryption': {'field': 'encryption', 'label': 'Declared encryption configuration'},
 'aws.ecr.lifecycle_policy': {'field': 'lifecycle_policy_present',
                              'label': 'ECR lifecycle policy configured'},
 'aws.eks.secrets_encryption': {'field': 'version', 'label': 'Recorded cluster version'},
 'aws.b.eks.secret_envelope_encryption': {'field': 'version', 'label': 'Recorded cluster version'},
 'aws.b.acm.expiry_thirty_days': {'field': 'not_after', 'label': 'Certificate expiration timestamp'},
 'aws.b.acm.pending_validation_review': {'field': 'certificate_status', 'label': 'ACM certificate status'},
 'aws.b.acm.rsa_minimum_2048': {'field': 'rsa_bits', 'label': 'Certificate RSA key length in bits'},
 'aws.b.cloudfront.waf_reference': {'field': 'configured',
                                    'label': 'CloudFront web ACL reference',
                                    'discriminator': 'WebACLId'},
 'aws.b.cloudfront.default_root_object': {'field': 'configured',
                                          'label': 'CloudFront default root object',
                                          'discriminator': 'DefaultRootObject'},
 'aws.b.cloudfront.field_level_encryption': {'field': 'configured',
                                             'label': 'CloudFront field-level encryption reference',
                                             'discriminator': 'DefaultCacheBehavior.FieldLevelEncryptionId'},
 'aws.b.ecs.no_privileged_containers': {'field': 'privileged_containers',
                                        'label': 'Containers declaring privileged mode'},
 'aws.b.ecs.some_logging_configuration': {'field': 'containers_with_log_configuration',
                                          'label': 'Containers with a logging configuration'},
 'aws.b.ecs.no_host_pid': {'field': 'pid_mode', 'label': 'ECS task PID mode'},
 'aws.b.ecs.all_readonly_roots': {'field': 'writable_root_containers',
                                  'label': 'Containers declaring writable root filesystems'},
 'aws.b.ecs.declared_nonroot_users': {'field': 'proven_numeric_uid_containers',
                                      'label': 'Containers proven to run as a valid nonzero user ID'},
 'aws.b.ecs.host_network_nonprivileged': {'field': 'privileged_containers',
                                          'label': 'Containers declaring privileged mode'},
 'aws.a.cloudtrail.bucket_mfa_delete': {'field': 'mfa_delete', 'label': 'Bucket MFA Delete setting'},
 'aws.a.cloudtrail.bucket_access_logging': {'field': 'logging_target', 'label': 'Access-log destination'},
 'aws.b.fsx.openzfs_multi_az': {'field': 'deployment_type', 'label': 'File-system deployment type'},
 'aws.b.fsx.netapp_ontap_multi_az': {'field': 'deployment_type', 'label': 'File-system deployment type'},
 'aws.b.fsx.windows_multi_az': {'field': 'deployment_type', 'label': 'File-system deployment type'},
 'aws.b.fsx.openzfs_copy_backup_and_volume_tags': {'field': 'copy_backup_tags', 'label': 'Copy backup tags'},
 'aws.b.fsx.lustre_copy_backup_tags': {'field': 'copy_backup_tags', 'label': 'Copy backup tags'},
 'aws.claude_a.ebs.attached_delete_on_termination': {'field': 'delete_on_termination',
                                                     'label': 'Delete storage on termination'},
 'aws.claude_a.ebs.volume_in_use': {'field': 'state', 'label': 'Recorded resource state'},
 'aws.claude_a.ebs.volume_in_backup_selection': {'field': 'matched',
                                                 'label': 'Backup selection or checked tag-key match'},
 'aws.claude_a.ebs.snapshot_not_public': {'field': 'public', 'label': 'Public-access declaration'},
 'aws.claude_a.ec2.ebs_encryption_by_default': {'field': 'ebs_encryption_by_default',
                                                'label': 'Default EBS encryption'},
 'aws.claude_a.ec2.ebs_encryption_by_default_with_volumes': {'field': 'ebs_encryption_by_default',
                                                             'label': 'Default EBS encryption'},
 'aws.claude_a.ec2.snapshot_block_public_access': {'field': 'state', 'label': 'Recorded resource state'},
 'aws.claude_a.ec2.ami_block_public_access': {'field': 'state', 'label': 'Recorded resource state'},
 'aws.claude_a.ec2.account_imdsv2_default': {'field': 'http_tokens',
                                             'label': 'Instance metadata token requirement'},
 'aws.claude_a.ec2.ami_not_public': {'field': 'public', 'label': 'Public-access declaration'},
 'aws.claude_a.ec2.ami_ebs_encrypted': {'field': 'encrypted', 'label': 'Storage encryption'},
 'aws.claude_a.ec2.ami_not_older_than_90_days': {'field': 'creation_date', 'label': 'Image creation date'},
 'aws.claude_a.ec2.instance_detailed_monitoring': {'field': 'monitoring_state',
                                                   'label': 'Instance monitoring state'},
 'aws.claude_a.ec2.instance_ebs_optimized': {'field': 'ebs_optimized', 'label': 'EBS optimization'},
 'aws.claude_a.ec2.instance_profile_attached': {'field': 'instance_profile',
                                                'label': 'Attached instance-profile reference'},
 'aws.claude_a.ec2.instance_profile_attached_not_terminated': {'field': 'instance_profile',
                                                               'label': 'Attached instance-profile '
                                                                        'reference'},
 'aws.claude_a.ec2.instance_in_vpc': {'field': 'vpc_id', 'label': 'Declared VPC reference'},
 'aws.claude_a.ec2.instance_no_public_ip': {'field': 'public_ip', 'label': 'Public IP address'},
 'aws.claude_a.ec2.instance_no_public_ip_not_terminated': {'field': 'public_ip',
                                                           'label': 'Public IP address'},
 'aws.claude_a.ec2.public_instance_has_profile': {'field': 'public_ip', 'label': 'Public IP address'},
 'aws.claude_a.ec2.internet_facing_without_profile': {'field': 'public_ip', 'label': 'Public IP address'},
 'aws.claude_a.ec2.running_instance_no_key_pair': {'field': 'key_name',
                                                   'label': 'Instance key-pair reference'},
 'aws.claude_a.ec2.instance_imdsv2_applied': {'field': 'http_tokens',
                                              'label': 'Instance metadata token requirement'},
 'aws.claude_a.ec2.instance_imdsv2_or_disabled': {'field': 'http_tokens',
                                                  'label': 'Instance metadata token requirement'},
 'aws.claude_a.ec2.instance_no_launch_wizard_sg': {'field': 'groups',
                                                   'label': 'Attached security-group names'},
 'aws.claude_a.ec2.instance_not_paravirtual': {'field': 'virtualization_type',
                                               'label': 'Instance virtualization type'},
 'aws.claude_a.ec2.instance_not_paravirtual_not_terminated': {'field': 'virtualization_type',
                                                              'label': 'Instance virtualization type'},
 'aws.claude_a.ec2.instance_termination_protection': {'field': 'disable_api_termination',
                                                      'label': 'Instance termination protection'},
 'aws.claude_a.ec2.instance_not_older_than_180_days': {'field': 'launch_time',
                                                       'label': 'Instance launch timestamp'},
 'aws.claude_a.ec2.running_instance_age_180_days': {'field': 'days_since_launch',
                                                    'label': 'Observed instance age in days'},
 'aws.claude_a.ec2.stopped_instance_30_days': {'field': 'stopped_since',
                                               'label': 'Instance stopped timestamp'},
 'aws.claude_a.ec2.stopped_instance_90_days': {'field': 'stopped_since',
                                               'label': 'Instance stopped timestamp'},
 'aws.claude_a.ec2.stopped_instance_more_than_30_days': {'field': 'days_stopped',
                                                         'label': 'Observed stopped duration in days'},
 'aws.claude_a.ec2.instance_ebs_delete_on_termination': {'field': 'devices',
                                                         'label': 'Assessed instance block devices'},
 'aws.claude_a.ec2.instance_single_eni': {'field': 'eni_count', 'label': 'Attached network-interface count'},
 'aws.claude_a.ec2.instance_single_attachable_eni': {'field': 'counted',
                                                     'label': 'Network interfaces counted'},
 'aws.claude_a.ec2.instance_ami_not_deprecated': {'field': 'deprecation_time',
                                                  'label': 'Image deprecation timestamp'},
 'aws.claude_a.ec2.enclave_host_imdsv2': {'field': 'http_tokens',
                                          'label': 'Instance metadata token requirement'},
 'aws.claude_a.ec2.enclave_host_running': {'field': 'state', 'label': 'Recorded resource state'},
 'aws.claude_a.ec2.enclave_host_not_public': {'field': 'reasons',
                                              'label': 'Flagged enclave-host configuration conditions'},
 'aws.claude_a.ec2.enclave_host_ingress_allowlist': {'field': 'exposed',
                                                     'label': 'Enclave-host ingress declarations outside the '
                                                              'allowlist'},
 'aws.claude_a.ec2.enclave_host_vsock_ports_closed': {'field': 'ports',
                                                      'label': 'Flagged Internet-wide port declarations'},
 'aws.claude_a.ec2.instance_port_cassandra_not_internet_exposed': {'field': 'ports',
                                                                   'label': 'Flagged Internet-wide port '
                                                                            'declarations'},
 'aws.claude_a.ec2.instance_port_cifs_not_internet_exposed': {'field': 'ports',
                                                              'label': 'Flagged Internet-wide port '
                                                                       'declarations'},
 'aws.claude_a.ec2.instance_port_elasticsearch_kibana_not_internet_exposed': {'field': 'ports',
                                                                              'label': 'Flagged '
                                                                                       'Internet-wide port '
                                                                                       'declarations'},
 'aws.claude_a.ec2.instance_port_ftp_not_internet_exposed': {'field': 'ports',
                                                             'label': 'Flagged Internet-wide port '
                                                                      'declarations'},
 'aws.claude_a.ec2.instance_port_kafka_not_internet_exposed': {'field': 'ports',
                                                               'label': 'Flagged Internet-wide port '
                                                                        'declarations'},
 'aws.claude_a.ec2.instance_port_kerberos_not_internet_exposed': {'field': 'ports',
                                                                  'label': 'Flagged Internet-wide port '
                                                                           'declarations'},
 'aws.claude_a.ec2.instance_port_ldap_not_internet_exposed': {'field': 'ports',
                                                              'label': 'Flagged Internet-wide port '
                                                                       'declarations'},
 'aws.claude_a.ec2.instance_port_memcached_not_internet_exposed': {'field': 'ports',
                                                                   'label': 'Flagged Internet-wide port '
                                                                            'declarations'},
 'aws.claude_a.ec2.instance_port_mongodb_not_internet_exposed': {'field': 'ports',
                                                                 'label': 'Flagged Internet-wide port '
                                                                          'declarations'},
 'aws.claude_a.ec2.instance_port_mysql_not_internet_exposed': {'field': 'ports',
                                                               'label': 'Flagged Internet-wide port '
                                                                        'declarations'},
 'aws.claude_a.ec2.instance_port_oracle_not_internet_exposed': {'field': 'ports',
                                                                'label': 'Flagged Internet-wide port '
                                                                         'declarations'},
 'aws.claude_a.ec2.instance_port_postgresql_not_internet_exposed': {'field': 'ports',
                                                                    'label': 'Flagged Internet-wide port '
                                                                             'declarations'},
 'aws.claude_a.ec2.instance_port_rdp_not_internet_exposed': {'field': 'ports',
                                                             'label': 'Flagged Internet-wide port '
                                                                      'declarations'},
 'aws.claude_a.ec2.instance_port_redis_not_internet_exposed': {'field': 'ports',
                                                               'label': 'Flagged Internet-wide port '
                                                                        'declarations'},
 'aws.claude_a.ec2.instance_port_sqlserver_not_internet_exposed': {'field': 'ports',
                                                                   'label': 'Flagged Internet-wide port '
                                                                            'declarations'},
 'aws.claude_a.ec2.instance_port_ssh_not_internet_exposed': {'field': 'ports',
                                                             'label': 'Flagged Internet-wide port '
                                                                      'declarations'},
 'aws.claude_a.ec2.instance_port_telnet_not_internet_exposed': {'field': 'ports',
                                                                'label': 'Flagged Internet-wide port '
                                                                         'declarations'},
 'aws.claude_a.ec2.launch_template_default_imdsv2': {'field': 'http_tokens',
                                                     'label': 'Instance metadata token requirement'},
 'aws.claude_a.ec2.launch_template_default_ebs_encrypted': {'field': 'unencrypted_devices',
                                                            'label': 'Devices declaring unencrypted EBS '
                                                                     'storage'},
 'aws.claude_a.ec2.launch_template_any_version_imdsv2': {'field': 'imdsv2_required_versions',
                                                         'label': 'Launch-template versions requiring '
                                                                  'metadata tokens'},
 'aws.claude_a.ec2.launch_template_instances_no_public_ip': {'field': 'instances',
                                                             'label': 'Referenced EC2 instances'},
 'aws.claude_a.ec2.eni_no_public_ip': {'field': 'public_ip', 'label': 'Public IP address'},
 'aws.claude_a.ec2.eip_associated': {'field': 'association_id', 'label': 'Elastic IP association reference'},
 'aws.claude_a.vpc.sg_no_world_ssh': {'field': 'matching_ingress',
                                      'label': 'Security-group ingress rules matching Internet-wide sources'},
 'aws.claude_a.vpc.sg_no_world_rdp': {'field': 'matching_ingress',
                                      'label': 'Security-group ingress rules matching Internet-wide sources'},
 'aws.claude_a.vpc.sg_no_world_cassandra': {'field': 'matching_ingress',
                                            'label': 'Security-group ingress rules matching Internet-wide '
                                                     'sources'},
 'aws.claude_a.vpc.sg_no_world_elasticsearch_kibana': {'field': 'matching_ingress',
                                                       'label': 'Security-group ingress rules matching '
                                                                'Internet-wide sources'},
 'aws.claude_a.vpc.sg_no_world_ftp': {'field': 'matching_ingress',
                                      'label': 'Security-group ingress rules matching Internet-wide sources'},
 'aws.claude_a.vpc.sg_no_world_kafka': {'field': 'matching_ingress',
                                        'label': 'Security-group ingress rules matching Internet-wide '
                                                 'sources'},
 'aws.claude_a.vpc.sg_no_world_memcached': {'field': 'matching_ingress',
                                            'label': 'Security-group ingress rules matching Internet-wide '
                                                     'sources'},
 'aws.claude_a.vpc.sg_no_world_mongodb': {'field': 'matching_ingress',
                                          'label': 'Security-group ingress rules matching Internet-wide '
                                                   'sources'},
 'aws.claude_a.vpc.sg_no_world_mysql': {'field': 'matching_ingress',
                                        'label': 'Security-group ingress rules matching Internet-wide '
                                                 'sources'},
 'aws.claude_a.vpc.sg_no_world_oracle': {'field': 'matching_ingress',
                                         'label': 'Security-group ingress rules matching Internet-wide '
                                                  'sources'},
 'aws.claude_a.vpc.sg_no_world_postgres': {'field': 'matching_ingress',
                                           'label': 'Security-group ingress rules matching Internet-wide '
                                                    'sources'},
 'aws.claude_a.vpc.sg_no_world_redis': {'field': 'matching_ingress',
                                        'label': 'Security-group ingress rules matching Internet-wide '
                                                 'sources'},
 'aws.claude_a.vpc.sg_no_world_sqlserver': {'field': 'matching_ingress',
                                            'label': 'Security-group ingress rules matching Internet-wide '
                                                     'sources'},
 'aws.claude_a.vpc.sg_no_world_telnet': {'field': 'matching_ingress',
                                         'label': 'Security-group ingress rules matching Internet-wide '
                                                  'sources'},
 'aws.claude_a.vpc.vpc_endpoint_ec2': {'field': 'service_name', 'label': 'VPC endpoint service'},
 'aws.claude_a.vpc.interface_endpoint_ecr_api': {'field': 'service_name', 'label': 'VPC endpoint service'},
 'aws.claude_a.vpc.interface_endpoint_ecr_dkr': {'field': 'service_name', 'label': 'VPC endpoint service'},
 'aws.claude_a.vpc.interface_endpoint_ssm': {'field': 'service_name', 'label': 'VPC endpoint service'},
 'aws.claude_a.vpc.interface_endpoint_ssm_contacts': {'field': 'service_name',
                                                      'label': 'VPC endpoint service'},
 'aws.claude_a.vpc.interface_endpoint_ssm_incidents': {'field': 'service_name',
                                                       'label': 'VPC endpoint service'},
 'aws.claude_a.vpc.peering_route_tables_least_privilege': {'field': 'destinations',
                                                           'label': 'Peering route destinations requiring '
                                                                    'review'},
 'aws.claude_a.vpc.vpn_tunnel_logging': {'field': 'tunnel_logging',
                                         'label': 'VPN tunnel logging declarations'},
 'aws.claude_a.iam.user_inline_no_assume_role_text': {'field': 'policies',
                                                      'label': 'Policies matching the checked permission '
                                                               'pattern'},
 'aws.claude_a.iam.prowler_root_hardware_mfa': {'field': 'virtual_root_mfa',
                                                'label': 'Virtual root MFA devices'},
 'aws.claude_a.iam.user_bedrock_access_not_stale': {'field': 'days_since_access',
                                                    'label': 'Days since recorded service access'},
 'aws.claude_a.iam.role_bedrock_access_not_stale': {'field': 'days_since_access',
                                                    'label': 'Days since recorded service access'},
 'aws.claude_a.iam.user_sagemaker_access_not_stale': {'field': 'days_since_access',
                                                      'label': 'Days since recorded service access'},
 'aws.claude_a.iam.support_role_exists': {'field': 'roles', 'label': 'Recorded IAM role matches'},
 'aws.claude_a.iam.securityaudit_role_exists': {'field': 'roles', 'label': 'Recorded IAM role matches'},
 'aws.claude_a.iam.prowler_customer_policy_no_cloudtrail_full_access': {'field': 'full_access',
                                                                        'label': 'Unrestricted '
                                                                                 'service-permission '
                                                                                 'pattern'},
 'aws.claude_a.iam.prowler_customer_policy_no_kms_full_access': {'field': 'full_access',
                                                                 'label': 'Unrestricted service-permission '
                                                                          'pattern'},
 'aws.claude_a.iam.prowler_customer_policy_no_marketplace_subscribe': {'field': 'subscribe_on_all',
                                                                       'label': 'Marketplace subscription '
                                                                                'permission on all '
                                                                                'resources'},
 'aws.claude_a.iam.prowler_customer_policy_no_permissive_role_assumption': {'field': 'permissive',
                                                                            'label': 'Permissive '
                                                                                     'role-assumption '
                                                                                     'pattern'},
 'aws.claude_a.iam.prowler_user_inline_no_admin': {'field': 'failing_policies',
                                                   'label': 'Policies matching the forbidden permission '
                                                            'pattern'},
 'aws.claude_a.iam.prowler_role_inline_no_admin': {'field': 'failing_policies',
                                                   'label': 'Policies matching the forbidden permission '
                                                            'pattern'},
 'aws.claude_a.iam.prowler_group_inline_no_admin': {'field': 'failing_policies',
                                                    'label': 'Policies matching the forbidden permission '
                                                             'pattern'},
 'aws.claude_a.iam.prowler_user_inline_no_cloudtrail_full_access': {'field': 'failing_policies',
                                                                    'label': 'Policies matching the '
                                                                             'forbidden permission pattern'},
 'aws.claude_a.iam.prowler_role_inline_no_cloudtrail_full_access': {'field': 'failing_policies',
                                                                    'label': 'Policies matching the '
                                                                             'forbidden permission pattern'},
 'aws.claude_a.iam.prowler_group_inline_no_cloudtrail_full_access': {'field': 'failing_policies',
                                                                     'label': 'Policies matching the '
                                                                              'forbidden permission pattern'},
 'aws.claude_a.iam.prowler_user_inline_no_kms_full_access': {'field': 'failing_policies',
                                                             'label': 'Policies matching the forbidden '
                                                                      'permission pattern'},
 'aws.claude_a.iam.prowler_role_inline_no_kms_full_access': {'field': 'failing_policies',
                                                             'label': 'Policies matching the forbidden '
                                                                      'permission pattern'},
 'aws.claude_a.iam.prowler_group_inline_no_kms_full_access': {'field': 'failing_policies',
                                                              'label': 'Policies matching the forbidden '
                                                                       'permission pattern'},
 'aws.claude_a.iam.prowler_user_inline_no_marketplace_subscribe': {'field': 'failing_policies',
                                                                   'label': 'Policies matching the forbidden '
                                                                            'permission pattern'},
 'aws.claude_a.iam.prowler_role_inline_no_marketplace_subscribe': {'field': 'failing_policies',
                                                                   'label': 'Policies matching the forbidden '
                                                                            'permission pattern'},
 'aws.claude_a.iam.prowler_group_inline_no_marketplace_subscribe': {'field': 'failing_policies',
                                                                    'label': 'Policies matching the '
                                                                             'forbidden permission pattern'},
 'aws.claude_a.cloudtrail.account_has_logging_multi_region_trail': {'field': 'trail',
                                                                    'label': 'Matching CloudTrail trail'},
 'aws.claude_a.s3.bucket_public_access_block_all': {'field': 'settings',
                                                    'label': 'S3 public-access settings'},
 'aws.claude_a.s3.prowler_bucket_level_public_access_block': {'field': 'level',
                                                              'label': 'Recorded logging or protection '
                                                                       'level'},
 'aws.claude_a.s3.default_encryption_kms_key': {'field': 'kms_rules',
                                                'label': 'Bucket encryption rules declaring KMS'},
 'aws.claude_a.s3.prowler_kms_encryption': {'field': 'algorithm', 'label': 'Bucket encryption algorithm'},
 'aws.claude_a.s3.replication_rule_enabled': {'field': 'enabled_rules', 'label': 'Enabled bucket rules'},
 'aws.claude_a.s3.prowler_cross_region_replication': {'field': 'destination',
                                                      'label': 'Bucket replication destination'},
 'aws.claude_a.s3.lifecycle_rule_enabled': {'field': 'enabled_rules', 'label': 'Enabled bucket rules'},
 'aws.claude_a.s3.versioning_and_lifecycle': {'field': 'versioning',
                                              'label': 'Bucket versioning configuration'},
 'aws.claude_a.s3.object_lock_configured': {'field': 'object_lock',
                                            'label': 'Bucket Object Lock configuration'},
 'aws.claude_a.s3.event_notifications': {'field': 'configured',
                                         'label': 'Declared event-notification configuration'},
 'aws.claude_a.s3.acls_prohibit_user_access': {'field': 'other_grantees',
                                               'label': 'Bucket ACL grants to other users'},
 'aws.claude_a.s3.no_authenticated_users_acl': {'field': 'permissions',
                                                'label': 'Authenticated-users ACL permissions'},
 'aws.claude_a.s3.prowler_acl_disabled': {'field': 'ownership', 'label': 'Bucket object-ownership setting'},
 'aws.claude_a.s3.prowler_public_access': {'field': 'public', 'label': 'Public-access declaration'},
 'aws.claude_a.s3.prowler_public_list_acl': {'field': 'public', 'label': 'Public-access declaration'},
 'aws.claude_a.s3.prowler_public_write_acl': {'field': 'public', 'label': 'Public-access declaration'},
 'aws.claude_a.s3.restrict_public_read': {'field': 'public_acl',
                                          'label': 'Bucket ACL declares public access'},
 'aws.claude_a.s3.policy_no_cross_account_permission_changes': {'field': 'cross_account_statements',
                                                                'label': 'Bucket policy statements '
                                                                         'permitting cross-account '
                                                                         'permission changes'},
 'aws.claude_a.s3.policy_restrict_public_access': {'field': 'unrestricted_public_statements',
                                                   'label': 'Bucket policy statements with unrestricted '
                                                            'public principals'},
 'aws.claude_a.s3.perimeter_policy_not_public': {'field': 'public_statements',
                                                 'label': 'Policy statements with unrestricted public '
                                                          'principals'},
 'aws.claude_a.s3.prowler_cross_account_policy': {'field': 'cross_account',
                                                  'label': 'Cross-account policy declaration'},
 'aws.claude_a.s3.prowler_policy_public_write': {'field': 'public_write',
                                                 'label': 'Public-write policy declaration'},
 'aws.claude_a.s3.static_website_disabled': {'field': 'index_document',
                                             'label': 'Static website index document'},
 'aws.claude_a.s3.object_level_logging': {'field': 'match',
                                          'label': 'Matched object-data logging declaration'},
 'aws.claude_a.s3.protected_by_macie': {'field': 'job', 'label': 'Matched Macie classification job'},
 'aws.claude_a.s3.access_point_public_access_block': {'field': 'settings',
                                                      'label': 'S3 public-access settings'},
 'aws.cb.fsx.copy_tags_to_backups': {'field': 'copy_tags_to_backups',
                                     'label': 'Copy resource tags to backups'},
 'aws.cb.fsx.copy_tags_to_volumes': {'field': 'copy_tags_to_volumes',
                                     'label': 'Copy resource tags to volumes'},
 'aws.cb.fsx.openzfs_copy_tags_backups_and_volumes': {'field': 'copy_tags_to_backups',
                                                      'label': 'Copy resource tags to backups'},
 'aws.cb.fsx.lustre_copy_tags_to_backups': {'field': 'copy_tags_to_backups',
                                            'label': 'Copy resource tags to backups'},
 'aws.cb.fsx.ontap_multi_az': {'field': 'deployment_type', 'label': 'File-system deployment type'},
 'aws.cb.fsx.openzfs_multi_az': {'field': 'deployment_type', 'label': 'File-system deployment type'},
 'aws.cb.fsx.windows_multi_az_deployment': {'field': 'deployment_type',
                                            'label': 'File-system deployment type'},
 'aws.cb.fsx.windows_multiple_subnets': {'field': 'subnet_count',
                                         'label': 'Declared file-system subnet count'},
 'aws.cb.fsx.protected_by_backup_plan': {'field': 'protected',
                                         'label': 'Resource present in the backup protection inventory'},
 'aws.cb.glue.dev_endpoint_cloudwatch_encryption': {'field': 'security_configuration',
                                                    'label': 'Declared security-configuration reference'},
 'aws.cb.glue.dev_endpoint_bookmarks_encryption': {'field': 'security_configuration',
                                                   'label': 'Declared security-configuration reference'},
 'aws.cb.glue.dev_endpoint_s3_encryption_first_mode': {'field': 'security_configuration',
                                                       'label': 'Declared security-configuration reference'},
 'aws.cb.glue.job_cloudwatch_encryption': {'field': 'security_configuration',
                                           'label': 'Declared security-configuration reference'},
 'aws.cb.glue.job_bookmarks_encryption': {'field': 'security_configuration',
                                          'label': 'Declared security-configuration reference'},
 'aws.cb.glue.job_s3_encryption_first_mode': {'field': 'security_configuration',
                                              'label': 'Declared security-configuration reference'},
 'aws.cb.kinesis.retention_at_least_168h': {'field': 'retention_hours', 'label': 'Stream retention in hours'},
 'aws.cb.kinesis.retention_exactly_168h': {'field': 'retention_hours', 'label': 'Stream retention in hours'},
 'aws.cb.workspaces.private_subnet_with_nat_vpc': {'field': 'public_subnets',
                                                   'label': 'Declared subnets with public routes'},
 'aws.cb.rds.cluster_backtrack_window_positive': {'field': 'backtrack_window',
                                                  'label': 'Aurora backtracking window in seconds'},
 'aws.cb.rds.aurora_backtracking_configured': {'field': 'backtrack_window',
                                               'label': 'Aurora backtracking window in seconds'},
 'aws.cb.rds.cluster_cloudwatch_log_exports': {'field': 'exports',
                                               'label': 'Exported database log categories'},
 'aws.cb.rds.multi_az_cluster_minor_upgrade': {'field': 'auto_minor_version_upgrade',
                                               'label': 'Automatic minor database version upgrades'},
 'aws.cb.rds.cluster_engine_default_port_prowler': {'field': 'port', 'label': 'Database endpoint port'},
 'aws.cb.rds.instance_engine_default_port_prowler': {'field': 'port', 'label': 'Database endpoint port'},
 'aws.cb.rds.cluster_in_backup_plan_selection': {'field': 'backup_selection_match',
                                                 'label': 'Resource matched by an AWS Backup selection'},
 'aws.cb.rds.instance_in_backup_plan_selection': {'field': 'backup_selection_match',
                                                  'label': 'Resource matched by an AWS Backup selection'},
 'aws.cb.rds.aurora_cluster_protected_resource': {'field': 'protected_resource_match',
                                                  'label': 'Resource present in AWS Backup '
                                                           'protected-resource inventory'},
 'aws.cb.rds.instance_protected_resource': {'field': 'protected_resource_match',
                                            'label': 'Resource present in AWS Backup protected-resource '
                                                     'inventory'},
 'aws.cb.rds.instance_in_backup_selection_or_tag': {'field': 'selection_or_tag_key_match',
                                                    'label': 'Backup selection or source tag-key match'},
 'aws.cb.rds.aurora_mysql_server_audit_logging': {'field': 'server_audit_logging',
                                                  'label': 'Database server audit logging'},
 'aws.cb.rds.aurora_postgres_postgresql_log_export': {'field': 'exports',
                                                      'label': 'Exported database log categories'},
 'aws.cb.rds.cluster_log_exports_declared': {'field': 'exports', 'label': 'Exported database log categories'},
 'aws.cb.rds.instance_enhanced_monitoring_except_m1_small': {'field': 'enhanced_monitoring_resource_arn',
                                                             'label': 'Enhanced monitoring reference'},
 'aws.cb.rds.mariadb_log_exports': {'field': 'exports', 'label': 'Exported database log categories'},
 'aws.cb.rds.postgres_log_exports': {'field': 'exports', 'label': 'Exported database log categories'},
 'aws.cb.rds.sqlserver_error_log_export': {'field': 'exports', 'label': 'Exported database log categories'},
 'aws.cb.rds.aurora_postgres_local_file_read_versions': {'field': 'engine_version',
                                                         'label': 'Database engine version'},
 'aws.cb.rds.postgres_local_file_read_versions': {'field': 'engine_version',
                                                  'label': 'Database engine version'},
 'aws.cb.rds.instance_backup_retention_nonzero_all': {'field': 'backup_retention_days',
                                                      'label': 'Database backup retention in days'},
 'aws.cb.rds.instance_copy_tags_all_engines': {'field': 'copy_tags_to_snapshot',
                                               'label': 'Copy database tags to snapshots'},
 'aws.cb.rds.instance_iam_auth_all_engines': {'field': 'iam_database_authentication',
                                              'label': 'IAM database authentication'},
 'aws.cb.rds.instance_iam_auth_supported_engines': {'field': 'iam_database_authentication',
                                                    'label': 'IAM database authentication'},
 'aws.cb.rds.instance_default_master_username': {'field': 'master_username',
                                                 'label': 'Database administrator name'},
 'aws.cb.rds.instance_multi_az_or_cluster': {'field': 'multi_az', 'label': 'Database Multi-AZ deployment'},
 'aws.cb.rds.instance_multi_az_non_aurora': {'field': 'multi_az', 'label': 'Database Multi-AZ deployment'},
 'aws.cb.rds.instance_extended_support': {'field': 'engine_lifecycle_support',
                                          'label': 'Database engine lifecycle support'},
 'aws.cb.rds.ca_certificate_valid_3_months': {'field': 'valid_till',
                                              'label': 'Database CA certificate expiration timestamp'},
 'aws.cb.rds.ca_certificate_not_expiring_7_days': {'field': 'valid_till',
                                                   'label': 'Database CA certificate expiration timestamp'},
 'aws.cb.rds.engine_version_available': {'field': 'engine_version', 'label': 'Database engine version'},
 'aws.cb.rds.instance_internet_exposed': {'field': 'open_security_groups',
                                          'label': 'Database security groups permitting Internet-wide '
                                                   'ingress'},
 'aws.cb.rds.instance_no_public_subnet': {'field': 'public_subnets',
                                          'label': 'Declared subnets with public routes'},
 'aws.cb.rds.instance_snapshot_restore_not_all_exact': {'field': 'public_attributes',
                                                        'label': 'Public snapshot-sharing attributes'},
 'aws.cb.rds.cluster_snapshot_restore_not_all_exact': {'field': 'public_attributes',
                                                       'label': 'Public snapshot-sharing attributes'},
 'aws.cb.rds.cluster_critical_event_subscription': {'field': 'matching_subscriptions',
                                                    'label': 'Matching database event subscriptions'},
 'aws.cb.rds.instance_critical_event_subscription': {'field': 'matching_subscriptions',
                                                     'label': 'Matching database event subscriptions'},
 'aws.cb.rds.parameter_group_critical_event_subscription': {'field': 'matching_subscriptions',
                                                            'label': 'Matching database event subscriptions'},
 'aws.cb.rds.security_group_critical_event_subscription': {'field': 'matching_subscriptions',
                                                           'label': 'Matching database event subscriptions'},
 'aws.cb.neptune.backup_retention_7_days': {'field': 'backup_retention_days',
                                            'label': 'Database backup retention in days'},
 'aws.cb.neptune.audit_log_export': {'field': 'exports', 'label': 'Exported database log categories'},
 'aws.cb.neptune.snapshot_not_public_prowler': {'field': 'public_attribute_value_detected',
                                                'label': 'Public snapshot-sharing attribute detected'},
 'aws.cb.neptune.snapshot_restore_not_all_exact': {'field': 'public_restore_attribute',
                                                   'label': 'Public snapshot restore permission'},
 'aws.cb.neptune.no_public_subnet_prowler': {'field': 'public_subnets',
                                             'label': 'Declared subnets with public routes'},
 'aws.cb.neptune.no_public_subnet_steampipe': {'field': 'public_subnets',
                                               'label': 'Declared subnets with public routes'},
 'aws.cb.redshift.non_default_master_username': {'field': 'MasterUsername',
                                                 'label': 'Redshift administrator name'},
 'aws.cb.redshift.non_default_database_name': {'field': 'DBName', 'label': 'Redshift database name'},
 'aws.cb.redshift.audit_logging': {'field': 'logging_enabled', 'label': 'Logging configuration'},
 'aws.cb.redshift.require_ssl': {'field': 'require_ssl', 'label': 'Database TLS requirement'},
 'aws.cb.redshift.has_snapshot': {'field': 'snapshots', 'label': 'Recorded database snapshots'},
 'aws.cb.redshift.snapshot_retention_7_days': {'field': 'retention_days', 'label': 'Log retention in days'},
 'aws.cb.redshift.maintenance_settings': {'field': 'allow_version_upgrade',
                                          'label': 'Database version upgrades allowed'},
 'aws.cb.redshift.internet_exposed': {'field': 'public_subnet',
                                      'label': 'Database subnet has a public route'},
 'aws.cb.redshift.security_group_port_restricted': {'field': 'port', 'label': 'Database endpoint port'},
 'aws.cb.redshiftserverless.connection_user_log_exports': {'field': 'log_exports',
                                                           'label': 'Exported database log categories'},
 'aws.cb.redshiftserverless.non_default_admin_username': {'field': 'adminUsername',
                                                          'label': 'Redshift Serverless administrator name'},
 'aws.cb.redshiftserverless.non_default_database_name': {'field': 'dbName',
                                                         'label': 'Redshift Serverless database name'},
 'aws.cb.redshiftserverless.require_ssl': {'field': 'require_ssl_enabled',
                                           'label': 'Database workgroup TLS requirement'},
 'aws.cb.opensearch.encryption_at_rest': {'field': 'enabled', 'label': 'OpenSearch encryption at rest'},
 'aws.cb.opensearch.fine_grained_access_control': {'field': 'enabled',
                                                   'label': 'OpenSearch fine-grained access control'},
 'aws.cb.opensearch.internal_user_database_disabled': {'field': 'internal_user_database',
                                                       'label': 'Internal OpenSearch user database'},
 'aws.cb.opensearch.service_software_current': {'field': 'update_available',
                                                'label': 'OpenSearch service-software update available'},
 'aws.cb.opensearch.data_node_fault_tolerance': {'field': 'instance_count',
                                                 'label': 'Declared instance count'},
 'aws.cb.opensearch.dedicated_master_nodes': {'field': 'dedicated_master_count',
                                              'label': 'Declared dedicated-master count'},
 'aws.cb.opensearch.cognito_dashboards_auth': {'field': 'cognito',
                                               'label': 'Cognito dashboard authentication'},
 'aws.cb.opensearch.cognito_or_saml_dashboards_auth': {'field': 'cognito',
                                                       'label': 'Cognito dashboard authentication'},
 'aws.cb.opensearch.node_to_node_encryption': {'field': 'enabled',
                                               'label': 'OpenSearch node-to-node encryption'},
 'aws.cb.opensearch.node_to_node_encryption_region_skip': {'field': 'enabled',
                                                           'label': 'OpenSearch node-to-node encryption'},
 'aws.cb.opensearch.enforce_https': {'field': 'enforce_https', 'label': 'HTTPS requirement'},
 'aws.cb.opensearch.audit_logs_enabled': {'field': 'audit_logs', 'label': 'Audit-log export'},
 'aws.cb.opensearch.slow_logs_enabled': {'field': 'search_slow', 'label': 'Search slow-log export'},
 'aws.cb.opensearch.enabled_logs_have_log_group': {'field': 'enabled_without_log_group',
                                                   'label': 'Enabled log exports without a log-group '
                                                            'reference'},
 'aws.cb.opensearch.in_vpc_private_subnets': {'field': 'public_subnets',
                                              'label': 'Declared subnets with public routes'},
 'aws.cb.opensearch.access_policy_not_public': {'field': 'public', 'label': 'Public-access declaration'},
 'aws.cb.kafka.latest_version': {'field': 'kafka_version', 'label': 'MSK Kafka version'},
 'aws.cb.sqs.cmk_encryption': {'field': 'kms_master_key_id',
                               'label': 'Declared customer-managed encryption key'},
 'aws.cb.transfer.connector_logging_role': {'field': 'logging_role', 'label': 'Logging-role reference'},
 'aws.cb.lambda.kms_key_configured': {'field': 'kms_key_arn', 'label': 'Declared KMS encryption key'},
 'aws.cb.lambda.logging_config_present': {'field': 'logging_config', 'label': 'Lambda logging configuration'},
 'aws.cb.lambda.vpc_multiple_az': {'field': 'availability_zone_ids',
                                   'label': 'Declared VPC availability zones'},
 'aws.cb.lambda.policy_no_wildcard_allow': {'field': 'statements',
                                            'label': 'Policy statements matching the checked '
                                                     'unrestricted-principal pattern'},
 'aws.cb.lambda.policy_prohibit_public_access_perimeter': {'field': 'statements',
                                                           'label': 'Policy statements matching the checked '
                                                                    'unrestricted-principal pattern'},
 'aws.cb.lambda.runtime_not_deprecated_list': {'field': 'runtime', 'label': 'Lambda runtime'},
 'aws.cb.lambda.cloudtrail_data_events': {'field': 'trails',
                                          'label': 'Trails with a matching data-event selector'},
 'aws.cb.lightsail.instance_auto_snapshot': {'field': 'auto_snapshot',
                                             'label': 'Lightsail automatic snapshots'},
 'aws.cb.lightsail.instance_ipv6_disabled': {'field': 'ipv6_addresses',
                                             'label': 'Declared Lightsail IPv6 addresses'},
 'aws.cb.lightsail.instance_not_public': {'field': 'public_ip', 'label': 'Public IP address'},
 'aws.cb.lightsail.ssh_rdp_http_world_closed': {'field': 'open_ports',
                                                'label': 'Lightsail TCP ports with worldwide ingress'},
 'aws.cb.lightsail.ssh_restricted': {'field': 'open_ports',
                                     'label': 'Lightsail TCP ports with worldwide ingress'},
 'aws.cb.lightsail.rdp_restricted': {'field': 'open_ports',
                                     'label': 'Lightsail TCP ports with worldwide ingress'},
 'aws.cb.sagemaker.notebook_kms_key': {'field': 'kms_key_id', 'label': 'Explicit encryption-key reference'},
 'aws.cb.sagemaker.notebook_cmk': {'field': 'kms_key_id', 'label': 'Explicit encryption-key reference'},
 'aws.cb.sagemaker.notebook_in_vpc': {'field': 'subnet_id', 'label': 'Declared notebook subnet'},
 'aws.cb.sagemaker.notebook_supported_platform': {'field': 'platform_identifier',
                                                  'label': 'Notebook platform identifier'},
 'aws.cb.sagemaker.training_output_kms': {'field': 'kms_key_id',
                                          'label': 'Explicit encryption-key reference'},
 'aws.cb.sagemaker.training_volume_kms': {'field': 'volume_kms_key_id',
                                          'label': 'Explicit volume-encryption key reference'},
 'aws.cb.sagemaker.endpoint_config_kms': {'field': 'kms_key_id',
                                          'label': 'Explicit encryption-key reference'},
 'aws.c2b.lambda.env_vars_cmk': {'field': 'kms_key_arn', 'label': 'Declared KMS encryption key'},
 'aws.c2b.lambda.invoke_cloudtrail_logged': {'field': 'trails',
                                             'label': 'Trails with a matching data-event selector'},
 'aws.c2b.lambda.policy_not_public': {'field': 'public_policy',
                                      'label': 'Function policy matches the public-principal pattern'},
 'aws.c2b.lambda.url_cors_no_wildcard': {'field': 'allow_origins',
                                         'label': 'Lambda URL CORS allowed origins'},
 'aws.c2b.lambda.no_cross_account_layers': {'field': 'cross_account_layers',
                                            'label': 'Lambda layers from other accounts'},
 'aws.c2b.lambda.runtime_not_obsolete': {'field': 'runtime', 'label': 'Lambda runtime'},
 'aws.c2b.ecs.host_network_root_user': {'field': 'root_containers',
                                        'label': 'Host-network containers declaring root users'},
 'aws.c2b.ecs.all_containers_logging': {'field': 'containers_without_log_driver',
                                        'label': 'Containers without a log driver'},
 'aws.c2b.ecs.logging_non_blocking': {'field': 'blocking_containers',
                                      'label': 'Containers declaring blocking log delivery'},
 'aws.c2b.ecs.no_credential_named_env_vars': {'field': 'credential_environment_variables',
                                              'label': 'Container environment-variable names matching '
                                                       'credential patterns'},
 'aws.c2b.ecs.container_insights': {'field': 'container_insights',
                                    'label': 'ECS Container Insights settings'},
 'aws.c2b.ecs.container_insights_setting': {'field': 'container_insights',
                                            'label': 'ECS Container Insights settings'},
 'aws.c2b.ecs.cluster_has_active_services': {'field': 'active_services', 'label': 'Active ECS services'},
 'aws.c2b.ecs.cluster_has_registered_instances': {'field': 'registered_container_instances',
                                                  'label': 'Registered ECS container instances'},
 'aws.c2b.ecs.container_instance_agents_connected': {'field': 'disconnected_instances',
                                                     'label': 'Disconnected ECS container agents'},
 'aws.c2b.ecs.cluster_instance_volumes_encrypted': {'field': 'unencrypted_volumes',
                                                    'label': 'Attached EBS volumes declaring encryption '
                                                             'disabled'},
 'aws.c2b.ecs.container_instance_in_vpc': {'field': 'vpc_id', 'label': 'Declared VPC reference'},
 'aws.c2b.eks.endpoint_not_public': {'field': 'endpoint_public_access',
                                     'label': 'EKS public endpoint access'},
 'aws.c2b.eks.single_security_group': {'field': 'security_group_ids',
                                       'label': 'Attached EKS security groups'},
 'aws.c2b.eks.version_at_least_1_19': {'field': 'version', 'label': 'Recorded cluster version'},
 'aws.c2b.eks.version_at_least_1_28': {'field': 'version', 'label': 'Recorded cluster version'},
 'aws.c2b.eks.deletion_protection': {'field': 'deletion_protection', 'label': 'EKS deletion protection'},
 'aws.c2b.eks.secrets_encryption_configured': {'field': 'encryption_config',
                                               'label': 'Declared EKS secrets-encryption configurations'},
 'aws.c2b.eks.cluster_security_group_present': {'field': 'cluster_security_group_id',
                                                'label': 'Declared EKS cluster security-group reference'},
 'aws.c2b.autoscaling.multiple_az': {'field': 'availability_zones', 'label': 'Declared availability zones'},
 'aws.c2b.autoscaling.uses_launch_template': {'field': 'launch_template',
                                              'label': 'Auto Scaling launch-template reference present'},
 'aws.c2b.autoscaling.capacity_rebalance': {'field': 'capacity_rebalance',
                                            'label': 'Auto Scaling capacity rebalancing'},
 'aws.c2b.autoscaling.instance_types_per_az': {'field': 'failing_zones',
                                               'label': 'Zones lacking the required instance-type choices'},
 'aws.c2b.autoscaling.mixed_policy_multiple_types': {'field': 'instance_types',
                                                     'label': 'Declared Auto Scaling instance types'},
 'aws.c2b.autoscaling.no_suspended_processes': {'field': 'suspended',
                                                'label': 'Suspended Auto Scaling processes'},
 'aws.c2b.autoscaling.tags_propagate': {'field': 'non_propagating_tags',
                                        'label': 'Auto Scaling tags without instance propagation'},
 'aws.c2b.autoscaling.group_lc_imdsv2': {'field': 'http_tokens',
                                         'label': 'Instance metadata token requirement'},
 'aws.c2b.autoscaling.lc_imdsv2_required': {'field': 'http_tokens',
                                            'label': 'Instance metadata token requirement'},
 'aws.c2b.autoscaling.lc_hop_limit': {'field': 'hop_limit',
                                      'label': 'Launch-configuration metadata response hop limit'},
 'aws.c2b.appstream.max_user_duration_under_10h': {'field': 'max_user_duration_seconds',
                                                   'label': 'AppStream maximum user-session duration in '
                                                            'seconds'},
 'aws.c2b.appstream.disconnect_timeout_5m': {'field': 'disconnect_timeout_seconds',
                                             'label': 'AppStream disconnect timeout in seconds'},
 'aws.c2b.appstream.idle_disconnect_10m': {'field': 'idle_disconnect_timeout_seconds',
                                           'label': 'AppStream idle disconnect timeout in seconds'},
 'aws.c2b.elasticbeanstalk.stream_logs': {'field': 'stream_logs',
                                          'label': 'Elastic Beanstalk log-streaming settings'},
 'aws.c2b.elasticbeanstalk.managed_updates': {'field': 'managed_actions',
                                              'label': 'Elastic Beanstalk managed updates'},
 'aws.c2b.elasticbeanstalk.enhanced_health': {'field': 'system_type',
                                              'label': 'Elastic Beanstalk health-reporting mode'},
 'aws.c2b.cloudfront.custom_ssl_certificate': {'field': 'cloudfront_default_certificate',
                                               'label': 'CloudFront default certificate selection'},
 'aws.c2b.cloudfront.logging_any': {'field': 'standard_logging', 'label': 'CloudFront standard logging'},
 'aws.c2b.cloudfront.origin_traffic_encrypted': {'field': 'unencrypted_origins',
                                                 'label': 'CloudFront origins permitting plaintext traffic'},
 'aws.c2b.cloudfront.s3_origin_bucket_exists': {'field': 'buckets',
                                                'label': 'S3 origin buckets present in inventory'},
 'aws.c2b.cloudfront.origin_no_deprecated_ssl': {'field': 'deprecated_origin_protocols',
                                                 'label': 'CloudFront origins declaring deprecated SSL/TLS '
                                                          'versions'},
 'aws.c2b.elbv2.insecure_ssl_ciphers': {'field': 'insecure_policies',
                                        'label': 'Load-balancer policies matching insecure ciphers'},
 'aws.c2b.elbv2.listener_fips_tls': {'field': 'non_fips_policies',
                                     'label': 'Load-balancer policies outside the reviewed FIPS list'},
 'aws.c2b.elbv2.listener_pqc_tls': {'field': 'non_pq_policies',
                                    'label': 'Load-balancer policies outside the reviewed post-quantum list'},
 'aws.c2b.elbv2.has_listeners': {'field': 'listener_count', 'label': 'Declared load-balancer listener count'},
 'aws.c2b.elbv2.alb_waf_attached': {'field': 'web_acl_families', 'label': 'Attached web ACL families'},
 'aws.c2b.elbv2.alb_wafv2_attached': {'field': 'web_acl_families', 'label': 'Attached web ACL families'},
 'aws.c2b.elbv2.not_internet_facing': {'field': 'scheme', 'label': 'Load-balancer exposure scheme'},
 'aws.c2b.elbv2.listener_certificate_30_days': {'field': 'remaining_days',
                                                'label': 'Certificate days remaining'},
 'aws.c2b.elbv2.listener_certificate_7_days': {'field': 'remaining_days',
                                               'label': 'Certificate days remaining'},
 'aws.c2b.elbv2.alb_http_redirect_default': {'field': 'http_listeners_without_redirect',
                                             'label': 'HTTP listeners without the required redirect'},
 'aws.c2b.elbv2.alb_sg_outbound_rule': {'field': 'security_groups_without_rules',
                                        'label': 'Attached security groups without the required rule '
                                                 'direction'},
 'aws.c2b.elbv2.recommended_tls_policy': {'field': 'approved_policies',
                                          'label': 'Listeners declaring a reviewed TLS policy'},
 'aws.c2b.elbv2.listeners_acm_certificate': {'field': 'listeners_without_acm_certificate',
                                             'label': 'Listeners without an ACM certificate'},
 'aws.c2b.elbv2.listeners_secure_protocol': {'field': 'insecure_listeners',
                                             'label': 'Listeners outside the required secure-protocol set'},
 'aws.c2b.classic_elb.ssl_listeners_only': {'field': 'insecure_protocols',
                                            'label': 'Classic ELB listener protocols outside the '
                                                     'secure-protocol set'},
 'aws.c2b.classic_elb.insecure_ssl_ciphers': {'field': 'listener_ports',
                                              'label': 'Listener ports outside the reviewed SSL-policy '
                                                       'requirement'},
 'aws.c2b.classic_elb.not_internet_facing': {'field': 'scheme', 'label': 'Load-balancer exposure scheme'},
 'aws.c2b.classic_elb.acm_certificates': {'field': 'non_acm_issued',
                                          'label': 'Listener certificates not issued by ACM'},
 'aws.c2b.apigateway.authorizers_or_authorized_methods': {'field': 'authorizers',
                                                          'label': 'Configured API authorizers'},
 'aws.c2b.apigateway.rest_api_has_authorizer': {'field': 'authorizers',
                                                'label': 'Configured API authorizers'},
 'aws.c2b.apigateway.methods_authorization_type': {'field': 'methods_without_authorization',
                                                   'label': 'API methods declaring no authorization'},
 'aws.c2b.apigateway.methods_request_validator': {'field': 'methods_without_validator',
                                                  'label': 'API methods without a request validator'},
 'aws.c2b.apigateway.rest_api_policy_not_public': {'field': 'public_statements',
                                                   'label': 'Policy statements with unrestricted public '
                                                            'principals'},
 'aws.c2b.apigatewayv2.api_has_authorizer': {'field': 'authorizers', 'label': 'Configured API authorizers'},
 'aws.c2b.backup.vault_encrypted': {'field': 'encryption_key_arn',
                                    'label': 'Backup vault encryption-key reference'},
 'aws.c2b.backup.recovery_point_retention_35': {'field': 'delete_after_days',
                                                'label': 'Recovery-point retention in days'},
 'aws.c2b.backup.plan_rules_retention_35': {'field': 'short_retention_rules',
                                            'label': 'Backup rules below the required retention'},
 'aws.c2b.backup.vault_policy_denies_recovery_point_deletion': {'field': 'statement',
                                                                'label': 'Matched backup-vault deny '
                                                                         'statement identifier'},
 'aws.c2b.dynamodb.table_in_backup_selection_or_tag': {'field': 'matched',
                                                       'label': 'Backup selection or checked tag-key match'},
 'aws.c2b.datasync.task_log_group': {'field': 'log_group', 'label': 'Configured log-group reference'},
 'aws.c2b.dms.public_instance_open_sg': {'field': 'open_security_groups',
                                         'label': 'Database security groups permitting Internet-wide '
                                                  'ingress'},
 'aws.c2b.documentdb.backup_retention_7': {'field': 'backup_retention_period',
                                           'label': 'Database backup retention in days'},
 'aws.c2b.drs.region_has_job': {'field': 'replication_states', 'label': 'DRS source replication states'},
 'aws.c2b.elasticache.cluster_public_subnet_prowler': {'field': 'public_subnets',
                                                       'label': 'Declared subnets with public routes'},
 'aws.c2b.elasticache.cluster_public_subnet': {'field': 'public_subnets',
                                               'label': 'Declared subnets with public routes'},
 'aws.c2b.elasticache.rg_backup_retention_7': {'field': 'snapshot_retention_limit',
                                               'label': 'Cache snapshot retention in days'},
 'aws.c2b.elasticache.rg_backup_retention_15': {'field': 'snapshot_retention_limit',
                                                'label': 'Cache snapshot retention in days'},
 'aws.c2b.elasticache.redis_auth_pre6': {'field': 'auth_token_enabled',
                                         'label': 'Redis authentication token enabled'},
 'aws.c2b.elasticache.cmk_enabled': {'field': 'kms_key_id', 'label': 'Explicit encryption-key reference'},
 'aws.c2b.efs.backup_not_disabled': {'field': 'backup_policy_status', 'label': 'EFS backup policy status'},
 'aws.c2b.efs.automatic_backups_enabled': {'field': 'backup_policy_status',
                                           'label': 'EFS backup policy status'},
 'aws.c2b.efs.policy_not_open_to_vpc_clients': {'field': 'public_allow_without_mount_target_condition',
                                                'label': 'Public EFS grants lacking the checked mount-target '
                                                         'condition'},
 'aws.c2b.efs.policy_enforces_ssl': {'field': 'enforces_ssl',
                                     'label': 'EFS policy contains the checked TLS condition'},
 'aws.c2b.efs.policy_no_wildcard_allow': {'field': 'statements',
                                          'label': 'Policy statements matching the checked '
                                                   'unrestricted-principal pattern'},
 'aws.c2b.efs.policy_prohibit_public_access': {'field': 'statements',
                                               'label': 'Policy statements matching the checked '
                                                        'unrestricted-principal pattern'},
 'aws.c2b.efs.multi_az_mount_targets': {'field': 'number_of_mount_targets',
                                        'label': 'Recorded EFS mount-target count'},
 'aws.c2b.efs.no_public_mount_targets': {'field': 'public_mount_targets',
                                         'label': 'EFS mount targets in public subnets'},
 'aws.c2b.efs.access_points_no_root_directory': {'field': 'root_access_points',
                                                 'label': 'EFS access points using the filesystem root'},
 'aws.c2b.efs.access_points_posix_user': {'field': 'access_points_without_posix_user',
                                          'label': 'EFS access points without a POSIX identity'},
 'aws.c2b.emr.cluster_kerberos_enabled': {'field': 'kerberos', 'label': 'EMR Kerberos configuration'},
 'aws.c2b.emr.cluster_security_configuration': {'field': 'security_configuration',
                                                'label': 'Declared security-configuration reference'},
 'aws.c2b.emr.cluster_not_publicly_accessible': {'field': 'public_master_groups',
                                                 'label': 'EMR primary-node groups permitting public '
                                                          'ingress'},
 'aws.c2b.emr.block_public_access_only_port_22': {'field': 'other_permitted_ranges',
                                                  'label': 'EMR public-access exception ranges beyond SSH'},
 'aws.c2b.es.in_vpc': {'field': 'vpc_id', 'label': 'Declared VPC reference'},
 'aws.c2b.es.internal_user_database_enabled': {'field': 'internal_user_database',
                                               'label': 'Internal OpenSearch user database'},
 'aws.c2b.bedrock.custom_model_cmk': {'field': 'kms_key_arn', 'label': 'Declared KMS encryption key'},
 'aws.c2b.bedrock.knowledge_base_data_sources_cmk': {'field': 'data_sources_without_cmk',
                                                     'label': 'Bedrock data sources without explicit '
                                                              'customer-key references'},
 'aws.c2b.bedrock.invocation_logs_encrypted': {'field': 'unencrypted',
                                               'label': 'Log destinations without the required encryption'},
 'aws.c2b.ecr.latest_image_no_medium_plus_findings': {'field': 'scan_status', 'label': 'Image scan status'},
 'aws.claude2_a.cloudtrail.region_has_logging_trail': {'field': 'logging_trail',
                                                       'label': 'Matching regional logging trail'},
 'aws.claude2_a.cloudtrail.threat_detection_enumeration': {'field': 'flagged_identities',
                                                           'label': 'Identities matching the observed '
                                                                    'enumeration-activity threshold'},
 'aws.claude2_a.cloudtrail.threat_detection_llm_jacking': {'field': 'flagged_identities',
                                                           'label': 'Identities matching the observed '
                                                                    'enumeration-activity threshold'},
 'aws.claude2_a.cloudtrail.threat_detection_privilege_escalation': {'field': 'flagged_identities',
                                                                    'label': 'Identities matching the '
                                                                             'observed enumeration-activity '
                                                                             'threshold'},
 'aws.claude2_a.config.org_aggregator_all_regions_with_delegated_admin': {'field': 'delegated_administrators',
                                                                          'label': 'Recorded delegated '
                                                                                   'administrator accounts'},
 'aws.a.cloudtrail.joined_bucket_declared_public_grants': {'field': 'public_acl_groups',
                                                           'label': 'Public bucket ACL groups'},
 'aws.a.cloudtrail.home_bucket_mfa_join': {'field': 'mfa_delete', 'label': 'Bucket MFA Delete setting'},
 'aws.a.iam.unused_credentials_45_days': {'field': 'captured_credentials',
                                          'label': 'Enabled credentials with recorded use'},
 'aws.a.iam.unused_credentials_90_days': {'field': 'captured_credentials',
                                          'label': 'Enabled credentials with recorded use'},
 'aws.a.iam.root_hardware_mfa': {'field': 'account_mfa_enabled',
                                 'label': 'Root MFA enabled in the account summary'},
 'aws.a.s3.mfa_delete_enabled': {'field': 'mfa_delete', 'label': 'Bucket MFA Delete setting'},
 'aws.a.s3.bucket_account_public_blocks': {'field': 'effective_settings',
                                           'label': 'Effective S3 Block Public Access settings'},
 'aws.b.cognito.password_minimum_fourteen': {'field': 'minimum_length', 'label': 'Minimum password length'},
 'aws.b.cognito.temporary_password_seven_days': {'field': 'declared_validity_days',
                                                 'label': 'Declared temporary-password validity in days'},
 'aws.htbp.cognito.client_no_writable_authorization_attributes': {'field': 'clients_evaluated',
                                                                  'label': 'Cognito clients evaluated'},
 'aws.htbp.eks.access_entries_authentication': {'field': 'authentication_mode',
                                                'label': 'EKS API authentication mode'},
 'aws.htbp.ecs.exec_session_logging_not_disabled': {'field': 'exec_logging',
                                                    'label': 'ECS Exec session logging mode'},
 'aws.htbp.ecs.no_sensitive_host_mounts': {'field': 'sensitive_mounts',
                                           'label': 'Containers declaring sensitive host mounts'},
 'aws.htbp.sagemaker.notebook_imdsv2_required': {'field': 'minimum_imds_version',
                                                 'label': 'Minimum SageMaker metadata-service version'},
 'aws.htbp.glue.dev_endpoint_not_public': {'field': 'public_address',
                                           'label': 'Public development-endpoint address'},
 'aws.htbp.appsync.no_api_key_additional_auth': {'field': 'additional_authentication_types',
                                                 'label': 'Additional AppSync authentication modes'},
 'aws.htbp.lambda.layer_version_trust_boundary': {'field': 'policy',
                                                  'label': 'Collected resource-policy document'},
 'aws.htbp.lambda.runtime_updates_not_pinned_manual': {'field': 'update_runtime_on',
                                                       'label': 'Lambda runtime-update mode'},
 'aws.htbp.lambda.env_var_names_not_credentials': {'field': 'credential_like_names',
                                                   'label': 'Lambda environment-variable names matching '
                                                            'credential patterns'},
 'aws.htbp.ecr.registry_policy_trust_boundary': {'field': 'registry_policy',
                                                 'label': 'Collected ECR registry-policy document'},
 'aws.htbp.ecr.replication_destinations_trust_boundary': {'field': 'public',
                                                          'label': 'Public-access declaration'},
 'aws.htbp.ecr.creation_template_policy_trust_boundary': {'field': 'public',
                                                          'label': 'Public-access declaration'},
 'aws.htbp.eks.access_entry_principal_trust_boundary': {'field': 'public',
                                                        'label': 'Public-access declaration'},
 'aws.htbp.kms.grant_grantee_trust_boundary': {'field': 'grantee_principal',
                                               'label': 'KMS grant recipient principal'},
 'aws.htbp.opensearch.connection_peer_trust_boundary': {'field': 'public',
                                                        'label': 'Public-access declaration'},
 'aws.gap.cloudtrail.multi_region_read_write_management': {'field': 'trail',
                                                           'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudtrail.region_logging_management_events': {'field': 'trail',
                                                         'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudtrail.trail_security_best_practices': {'field': 'failures',
                                                      'label': 'CloudTrail configuration checks not '
                                                               'satisfied'},
 'aws.gap.cloudtrail.s3_all_buckets_read_data_events': {'field': 'trail',
                                                        'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudtrail.s3_all_buckets_write_data_events': {'field': 'trail',
                                                         'label': 'Matching CloudTrail trail'},
 'aws.gap.s3.object_read_events_logged': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.s3.object_write_events_logged': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.s3.object_read_write_events_logged': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudtrail.bedrock_api_logging': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.s3.bucket_policy_denies_insecure_transport': {'field': 'bucket_statements',
                                                        'label': 'Bucket-policy deny declarations matching '
                                                                 'the transport-security pattern'},
 'aws.gap.iam.root_not_used_90_days': {'field': 'recent_use',
                                       'label': 'Recorded root activity within the observed window'},
 'aws.gap.iam.root_not_used_1_day': {'field': 'recent_use',
                                     'label': 'Recorded root activity within the observed window'},
 'aws.gap.securityhub.region_hub_enabled': {'field': 'hubs', 'label': 'Enabled Security Hub hub references'},
 'aws.gap.accessanalyzer.no_active_findings': {'field': 'active_findings',
                                               'label': 'Active Access Analyzer findings'},
 'aws.gap.vpc.sg_world_any_common_ports': {'field': 'matching_rules',
                                           'label': 'Security-group rules permitting the checked public '
                                                    'ingress'},
 'aws.gap.classic_elb.ssl_listeners_use_acm': {'field': 'non_acm_certificates',
                                               'label': 'Classic ELB listener certificates outside ACM'},
 'aws.gap.iam.active_keys_used_within_45_days': {'field': 'stale_keys',
                                                 'label': 'Enabled access keys outside the checked use-age '
                                                          'window'},
 'aws.gap.cloudwatch.metric_alarm.unauthorized_api_calls': {'field': 'trail',
                                                            'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.console_sign_in_without_mfa': {'field': 'trail',
                                                                 'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.root_account_usage': {'field': 'trail',
                                                        'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.iam_policy_changes': {'field': 'trail',
                                                        'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.cloudtrail_configuration_changes': {'field': 'trail',
                                                                      'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.console_authentication_failures': {'field': 'trail',
                                                                     'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.cmk_disable_or_scheduled_deletion': {'field': 'trail',
                                                                       'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.s3_bucket_policy_changes': {'field': 'trail',
                                                              'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.config_configuration_changes': {'field': 'trail',
                                                                  'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.security_group_changes': {'field': 'trail',
                                                            'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.network_acl_changes': {'field': 'trail',
                                                         'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.network_gateway_changes': {'field': 'trail',
                                                             'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.route_table_changes': {'field': 'trail',
                                                         'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.vpc_changes': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.metric_alarm.organizations_changes': {'field': 'trail',
                                                           'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.unauthorized_api_calls': {'field': 'trail',
                                                         'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.console_sign_in_without_mfa': {'field': 'trail',
                                                              'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.root_account_usage': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.iam_policy_changes': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.cloudtrail_configuration_changes': {'field': 'trail',
                                                                   'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.console_authentication_failures': {'field': 'trail',
                                                                  'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.cmk_disable_or_scheduled_deletion': {'field': 'trail',
                                                                    'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.s3_bucket_policy_changes': {'field': 'trail',
                                                           'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.config_configuration_changes': {'field': 'trail',
                                                               'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.security_group_changes': {'field': 'trail',
                                                         'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.network_acl_changes': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.network_gateway_changes': {'field': 'trail',
                                                          'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.route_table_changes': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.vpc_changes': {'field': 'trail', 'label': 'Matching CloudTrail trail'},
 'aws.gap.cloudwatch.cis_alarm.organizations_changes': {'field': 'trail',
                                                        'label': 'Matching CloudTrail trail'},
 'aws.gap.ec2.instance_no_iam_role_with_management_level_access': {'field': 'roles',
                                                                   'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_role_with_data_destruction_access': {'field': 'roles',
                                                                   'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_with_write_level_access': {'field': 'roles',
                                                         'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_role_with_database_management_write_access': {'field': 'roles',
                                                                            'label': 'Recorded IAM role '
                                                                                     'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_org_write_access': {'field': 'roles',
                                                            'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_role_with_privilege_escalation_risk_access': {'field': 'roles',
                                                                            'label': 'Recorded IAM role '
                                                                                     'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_new_group_creation_with_attached_policy_access': {'field': 'roles',
                                                                                          'label': 'Recorded '
                                                                                                   'IAM role '
                                                                                                   'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_new_role_creation_with_attached_policy_access': {'field': 'roles',
                                                                                         'label': 'Recorded '
                                                                                                  'IAM role '
                                                                                                  'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_new_user_creation_with_attached_policy_access': {'field': 'roles',
                                                                                         'label': 'Recorded '
                                                                                                  'IAM role '
                                                                                                  'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_write_access_to_resource_based_policies': {'field': 'roles',
                                                                                   'label': 'Recorded IAM '
                                                                                            'role matches'},
 'aws.gap.ec2.instance_no_iam_role_attached_with_credentials_exposure_access': {'field': 'roles',
                                                                                'label': 'Recorded IAM role '
                                                                                         'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_destruction_kms_access': {'field': 'roles',
                                                                  'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_role_with_destruction_rds_access': {'field': 'roles',
                                                                  'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_role_with_cloud_log_tampering_access': {'field': 'roles',
                                                                      'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_role_with_alter_critical_s3_permissions_configuration': {'field': 'roles',
                                                                                       'label': 'Recorded '
                                                                                                'IAM role '
                                                                                                'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_write_permission_on_critical_s3_configuration': {'field': 'roles',
                                                                                         'label': 'Recorded '
                                                                                                  'IAM role '
                                                                                                  'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_security_group_write_access': {'field': 'roles',
                                                                       'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_role_with_defense_evasion_impact_of_aws_security_services_access': {'field': 'roles',
                                                                                                  'label': 'Recorded '
                                                                                                           'IAM '
                                                                                                           'role '
                                                                                                           'matches'},
 'aws.gap.ec2.instance_no_iam_role_with_elastic_ip_hijacking_access': {'field': 'roles',
                                                                       'label': 'Recorded IAM role matches'},
 'aws.gap.ec2.instance_no_iam_passrole_and_lambda_invoke_function_access': {'field': 'roles',
                                                                            'label': 'Recorded IAM role '
                                                                                     'matches'},
 'aws_cloudfront_origin_failover_configured': {'field': 'invalid_origin_groups',
                                               'label': 'CloudFront origin groups without the required '
                                                        'failover configuration'},
 'aws_config_continuous_inventory': {'field': 'all_supported',
                                     'label': 'AWS Config all-supported-resources flag'},
 'aws_acm_certificate_lifecycle': {'field': 'status', 'label': 'Recorded service status'},
 'aws_nist_cloudwatch_alarm_action_enabled': {'field': 'actions_enabled',
                                              'label': 'CloudWatch alarm actions enabled'},
 'aws_config_recorder_all_supported_resources': {'field': 'all_supported',
                                                 'label': 'AWS Config all-supported-resources flag'},
 'aws_fedramp_acm_all_certificates_30_day_expiry': {'field': 'status', 'label': 'Recorded service status'},
 'aws.nist.acm_all_certificates_expiry_30_days': {'field': 'status', 'label': 'Recorded service status'},
 'aws_nist_acm_certificate_expires_30_days': {'field': 'status', 'label': 'Recorded service status'},
 'aws_g6_acm_all_certificates_30_day_expiry': {'field': 'status', 'label': 'Recorded service status'},
 'aws_backup_cross_region_copy': {'field': 'rule_count', 'label': 'Declared WAF rule count'},
 'aws_cis_ec2_default_security_group_not_attached': {'field': 'vpc_id', 'label': 'Declared VPC reference'},
 'aws_g6_ec2_instance_no_public_ipv6': {'field': 'globally_routable_ipv6',
                                        'label': 'Allocated globally routable instance IPv6 addresses'},
 'aws_guardduty_no_active_high_findings': {'field': 'active_high_finding_ids',
                                           'label': 'Active high-severity GuardDuty finding identifiers'},
 'aws_nist_s3_bucket_cross_region_replication_enabled': {'field': 'destination_region',
                                                         'label': 'Replication destination region'},
 'aws_cis_lambda_execution_role_exists': {'field': 'execution_role_arn',
                                          'label': 'Declared Lambda execution role'},
 'aws_cis_lambda_execution_role_unique': {'field': 'execution_role_arn',
                                          'label': 'Declared Lambda execution role'},
 'aws.pci.apigateway.all_methods_logging': {'field': 'logging_level',
                                            'label': 'API stage execution-logging level'},
 'aws.pci.apigateway.all_methods_cache_encrypted': {'field': 'enabled_method_settings',
                                                    'label': 'API method settings declaring cache '
                                                             'encryption'},
 'aws_inspector2_ec2_no_high_critical_findings': {'field': 'active_high_critical_ec2_findings',
                                                  'label': 'Active high/critical EC2 Inspector findings'},
 'aws_config_all_resources_recorded': {'field': 'recording_scope',
                                       'label': 'AWS Config recorder resource scope'},
 'aws.pci.wafv2.rule_group_metrics': {'field': 'cloudwatch_metrics_enabled',
                                      'label': 'WAF rule-group CloudWatch metrics'},
 'aws.pci.wafv2.rule_group_nonempty': {'field': 'rule_count', 'label': 'Declared WAF rule count'},
 'aws.pci.vpc.peering_dns_resolution': {'field': 'dns_options',
                                        'label': 'Peering remote DNS-resolution settings'},
 'aws_vpc_uses_amazonprovided_dns': {'field': 'dns_servers', 'label': 'VPC DHCP-option DNS servers'},
 'aws_g6_elbv2_only_https_tls_listeners': {'field': 'listener_protocols',
                                           'label': 'Declared load-balancer listener protocols'},
 'aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days': {'field': 'retention_days',
                                                                           'label': 'Log retention in days'},
 'aws_cis_elbv2_only_tls_listeners': {'field': 'plaintext_listener_arns',
                                      'label': 'Load-balancer listeners declaring plaintext protocols'},
 'aws.nist.rds_cluster_member_enhanced_monitoring': {'field': 'members_without_monitoring',
                                                     'label': 'Database cluster members without enhanced '
                                                              'monitoring'},
 'aws_ecs_task_definition_credential_environment_names': {'field': 'credential_environment_names',
                                                          'label': 'Container environment-variable names '
                                                                   'matching credential patterns'},
 'aws_fedramp_emr_master_no_public_ip': {'field': 'master_instances_checked',
                                         'label': 'EMR primary instances assessed'},
 'aws.nist.emr_master_nodes_no_public_ip': {'field': 'master_instances_checked',
                                            'label': 'EMR primary instances assessed'},
 'aws_nist_emr_cluster_master_nodes_no_public_ip': {'field': 'master_instances_checked',
                                                    'label': 'EMR primary instances assessed'},
 'aws_nist_efs_access_point_enforce_root_directory': {'field': 'root_path',
                                                      'label': 'EFS access-point root directory'},
 'aws_g6_emr_master_nodes_no_public_address': {'field': 'master_instances_checked',
                                               'label': 'EMR primary instances assessed'},
 'aws.nist.cloudtrail_cloudwatch_destination_kms': {'field': 'trails_without_enabled_customer_keys',
                                                    'label': 'Trails missing the checked customer-key '
                                                             'configuration'},
 'aws.nist.waf_classic_regional_acl_logging': {'field': 'regional_acl_ids_without_logging',
                                               'label': 'Regional Classic WAF ACLs without logging'},
 'aws.pci.appsync.waf_web_acl': {'field': 'web_acl_arn', 'label': 'Declared web ACL reference'},
 'aws.pci.classic_elb.predefined_ssl_policy': {'field': 'listener_ports',
                                               'label': 'Listener ports outside the reviewed SSL-policy '
                                                        'requirement'},
 'aws.pci.iam.policy_attached_to_active_principal': {'field': 'active_attachment',
                                                     'label': 'Usable policy attachment reference'},
 'aws.pci.shield.protection_all_internet_resources': {'field': 'unprotected_resource_arns',
                                                      'label': 'Assessed resources without Shield Advanced '
                                                               'protection'},
 'aws.pci.sns.delivery_status_logging': {'field': 'missing_feedback_protocols',
                                         'label': 'SNS delivery protocols without complete feedback logging'},
 'aws_api_customer_log_delivery': {'field': 'access_log_destination_configured',
                                   'label': 'API access-log destination configured'},
 'aws_backup_recent_restore_test': {'field': 'missing_recent_restore_tests',
                                    'label': 'Backup plan/resource-type pairs without a recent completed '
                                             'restore test'},
 'aws_cis_aws_resource_policy_unrestricted_principal': {'field': 'unrestricted_statements',
                                                        'label': 'Resource-policy statements with '
                                                                 'unrestricted principals'},
 'aws_cis_lightsail_bucket_private': {'field': 'public_get_object',
                                      'label': 'Lightsail bucket public object-read declaration'},
 'aws_cloudtrail_bucket_lifecycle_retention_365': {'field': 'retained_buckets',
                                                   'label': 'Trail buckets satisfying the checked '
                                                            'lifecycle-retention condition'},
 'aws_cloudtrail_s3_siem_delivery': {'field': 'undelivered_trails',
                                     'label': 'Trails missing the checked recent S3 delivery evidence'},
 'aws_elbv2_stickiness_duration_30_minutes': {'field': 'excessive_stickiness_sources',
                                              'label': 'Declared stickiness settings exceeding the profile '
                                                       'duration'},
 'aws_fedramp_iam_all_policies_no_admin_star': {'field': 'matching_policy_sources',
                                                'label': 'Customer policies matching the checked '
                                                         'wildcard-action pattern'},
 'aws_fedramp_iam_all_policies_no_service_wildcard': {'field': 'matching_policy_sources',
                                                      'label': 'Customer policies matching the checked '
                                                               'wildcard-action pattern'},
 'aws_g6_api_stage_effective_waf_acl': {'field': 'effective_acl',
                                        'label': 'Effective API-stage web ACL reference'},
 'aws_inspector_critical_image_findings_alert': {'field': 'missing_resource_types',
                                                 'label': 'Inspector resource types without matching '
                                                          'notification rules'},
 'aws_kms_key_expiry': {'field': 'imported_material_expired', 'label': 'Imported KMS key material expired'},
 'aws_log_archive_immutable': {'field': 'has_default_retention',
                               'label': 'Default Object Lock retention configured'},
 'aws_nist_apigateway_stage_cache_encryption_at_rest_enabled': {'field': 'unencrypted_methods',
                                                                'label': 'API method settings declaring '
                                                                         'caching without encryption'},
 'aws_nist_apigateway_stage_logging_enabled': {'field': 'disabled_deployed_rest_methods',
                                               'label': 'Deployed REST methods without the required '
                                                        'execution logging'},
 'aws_nist_cloudtrail_trail_integrated_with_logs': {'field': 'trails_without_integration',
                                                    'label': 'Trails lacking the checked log integration'},
 'aws_nist_config_enabled_all_regions': {'field': 'enabled_regions',
                                         'label': 'Regions declaring enabled AWS Config'},
 'aws_nist_elb_application_gateway_network_lb_multiple_az_configured': {'field': 'healthy_target_zones',
                                                                        'label': 'Zones containing healthy '
                                                                                 'load-balancer targets'},
 'aws_nist_rds_db_cluster_aurora_backtracking_enabled': {'field': 'backtrack_window',
                                                         'label': 'Aurora backtracking window in seconds'},
 'aws_nist_sns_topic_notification_delivery_status_enabled': {'field': 'protocols_without_complete_feedback',
                                                             'label': 'SNS protocols without complete '
                                                                      'delivery feedback'},
 'aws_nist_waf_web_acl_logging_enabled': {'field': 'acl_ids_without_logging',
                                          'label': 'Checked web ACLs without logging destinations'},
 'aws_route53resolver_blocked_query_alert': {'field': 'vpcs_without_blocked_query_alarm',
                                             'label': 'Protected VPCs without blocked-query alarms'},
 'aws_securityhub_findings_alerted': {'field': 'covered_values',
                                      'label': 'Security Hub severities covered by configured notification '
                                               'rules'},
 'aws_securityhub_medium_findings_alert': {'field': 'covered_values',
                                           'label': 'Security Hub severities covered by configured '
                                                    'notification rules'},
 'aws_securityhub_no_critical_findings': {'field': 'unresolved_finding_ids',
                                          'label': 'Active critical Security Hub findings unresolved and '
                                                   'unsuppressed'},
 'aws_shield_ddos_detected_alarm': {'field': 'protection_resources_without_alarm',
                                    'label': 'Shield protections without the required DDoS alarm'},
 'aws_ssm_application_inventory_fresh': {'field': 'unmanaged_instance_ids',
                                         'label': 'Running instances without SSM application inventory'},
 'aws_wafv2_rate_rule_alarm': {'field': 'web_acl_arn', 'label': 'Declared web ACL reference'},
 'aws_wafv2_request_validation_rules': {'field': 'web_acl_arn', 'label': 'Declared web ACL reference'}}


def _noun(label):
    first=label.split(' ',1)[0]
    return label if any(char.isupper() for char in first[1:]) else label[0].lower()+label[1:]


def _readable(value):
    return isinstance(value,str) and bool(value.strip()) and len(value)<=320 and not any(c in value for c in '\n\r\x00')


_CURRENT_CREDENTIAL_USE = {
    'aws.a.iam.unused_credentials_45_days': 45,
    'aws.a.iam.unused_credentials_90_days': 90,
    'aws.gap.iam.active_keys_used_within_45_days': 45,
}


def _current_credential_use(cid, evidence):
    captured = evidence.get('captured_credentials')
    generated = evidence.get('report_generated_at')
    if (evidence.get('threshold_days') != _CURRENT_CREDENTIAL_USE[cid]
            or not isinstance(captured, list) or not captured
            or any(not isinstance(row, dict) or row.get('state') != 'active'
                   or not _readable(row.get('last_used')) for row in captured)
            or evidence.get('stale_credentials') != []
            or not _readable(generated) or len(generated) < 10):
        return None
    family = 'active access keys' if cid.startswith('aws.gap.') else 'enabled credentials'
    return (f'The IAM user has {len(captured)} {family} with recorded recent use within {_CURRENT_CREDENTIAL_USE[cid]} days.\n'
            f'The credential report was generated on {generated[:10]}.\n'
            'Those credentials may still be used to reach account resources and related data.')


def evidence_summary(finding):
    if not isinstance(finding,dict) or finding.get('provider')!='aws' or finding.get('status')!='PASS':return None
    cid=finding.get('check_id');e=finding.get('evidence')
    if not isinstance(cid,str) or not isinstance(e,dict):return None
    if cid in _CURRENT_CREDENTIAL_USE:return _current_credential_use(cid,e)
    from .aws_pass_specific_observations import evidence_summary as specific_summary
    specific=specific_summary(finding)
    if specific is not None:return specific
    fresh=_fresh(cid,e)
    if fresh is not None:return fresh
    custom=_custom(cid,e)
    if custom is not None:return custom
    row=REVIEWED_FIELDS.get(cid)
    if row is None:return None
    if 'discriminator' in row and e.get('field')!=row['discriminator']:return None
    key,label=row['field'],row['label']
    if key not in e:return None
    value=e[key]
    if type(value) is bool:
        phrases=BOOLEAN_SENTENCES.get(key)
        return phrases[0 if value else 1] if phrases else label+' is '+('enabled.' if value else 'disabled.')
    if value is None or value=='':return 'No '+_noun(label)+' is recorded.'
    if type(value) is int and value>=0:
        if key=='retention_days':return label.replace(' in days','')+f' is {value} days.'
        if key=='backup_retention_days':return f'Automated database backups are retained for {value} days.'
        if key=='retention_hours':return f'The stream retains data for {value} hours.'
        if key=='days_since_access':return f'The last recorded service access was {value} days ago.'
        if key=='days_since_launch':return f'The instance was launched {value} days before the assessment.'
        if key=='days_stopped':return f'The instance has been stopped for {value} recorded days.'
        if key=='rsa_bits':return f'The certificate declares an RSA key with {value} bits.'
        return label+f' is {value}.'
    if _readable(value):
        translation={'required':'required','Enabled':'enabled','Disabled':'disabled','AWS_IAM':'AWS IAM','SQS-managed':'SQS-managed encryption','never_expire':'unlimited'}
        return label+' is '+translation.get(value,value)+'.'
    if isinstance(value,dict):
        if not value:return 'No '+_noun(label)+' entries are recorded.'
        if all(isinstance(k,str) for k in value):return f'{len(value)} '+_noun(label)+' entries are recorded.'
    if isinstance(value,list):
        if not value:return 'No '+_noun(label)+' are recorded.'
        if all(_readable(v) for v in value):return label+' include '+', '.join(value[:3])+(' and '+str(len(value)-3)+' others' if len(value)>3 else '')+'.'
        if all(isinstance(v,dict) for v in value):return f'{len(value)} '+_noun(label)+' are recorded.'
    return None

# These source callbacks deliberately retain no decisive success witness.
# Explain that limit without turning a stored PASS into a fabricated setting.
LIMITED_WITNESSES = {
 'aws.claude_a.ebs.volume_has_snapshot':('snapshot identifiers','volume_id'),
 'aws.claude_a.ebs.volume_protected_by_backup':('backup recovery-point details','volume_arn'),
 'aws.claude_a.ebs.volume_in_backup_plan_resources':('matched backup-selection details','volume_arn'),
 'aws.claude_a.ec2.instance_protected_by_backup':('backup recovery-point details','instance_arn'),
 'aws.claude_a.ec2.instance_ssm_managed':('the SSM management record','instance_id'),
 'aws.claude_a.ec2.active_instance_ssm_managed':('the SSM management record','instance_id'),
 'aws.claude_a.ec2.launch_template_no_public_ip':('launch-template public-IP settings',None),
 'aws.c2b.elbv2.http_listeners_redirect_https':('HTTP listener redirect settings',None),
 'aws_g6_api_stage_valid_client_certificate':('the client certificate and its validity dates',None),
 'aws_shield_protection_health_checks':('Shield health-check associations',None),
 'aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az':('instance types by availability zone',None),
 'aws.nist.ec2_instance_effective_public_reachability':('the assessed public-path layers','instance_id'),
 'aws_fedramp_ec2_effective_public_exposure':('the assessed public-path layers','instance_id'),
 'aws_nist_secretsmanager_secret_automatic_rotation_enabled':('secret rotation settings',None),
}


def _custom(cid,e):
    if cid not in REVIEWED_FIELDS and cid not in LIMITED_WITNESSES and cid not in {'aws.b.apigateway.client_certificate','aws.b.apigateway.waf_reference'}:return None
    if cid.startswith(('aws.gap.cloudwatch.metric_alarm.','aws.gap.cloudwatch.cis_alarm.')):
        event=ALARM_EVENTS.get(cid.rsplit('.',1)[-1])
        if event and e.get('matching_metric_alarm') is True and e.get('trail_logging') is True:
            return 'A logging CloudTrail trail has a configured metric filter and alarm for '+event+'; notification delivery is unverified.'
    if cid.startswith('aws.claude_a.vpc.sg_no_world_'):
        ports=e.get('ports');matches=e.get('matching_ingress')
        if isinstance(ports,list) and ports and all(type(v) is int and 0<v<=65535 for v in ports) and isinstance(matches,list):
            names=', '.join('TCP/'+str(v) for v in ports)
            return 'No security-group rule declares Internet-wide ingress to '+names+'.' if not matches else f'{len(matches)} security-group rules declare Internet-wide ingress to '+names+'.'
    if cid in {'aws.cb.lightsail.ssh_restricted','aws.cb.lightsail.rdp_restricted','aws.cb.lightsail.ssh_rdp_http_world_closed'}:
        ports=e.get('open_ports');checked={'aws.cb.lightsail.ssh_restricted':[22],'aws.cb.lightsail.rdp_restricted':[3389],'aws.cb.lightsail.ssh_rdp_http_world_closed':[22,80,3389]}[cid]
        if isinstance(ports,list) and all(type(v) is int and v in checked for v in ports):return 'No worldwide Lightsail ingress is declared for checked ports '+', '.join('TCP/'+str(v) for v in checked)+'.' if not ports else 'Worldwide Lightsail ingress is declared for '+', '.join('TCP/'+str(v) for v in ports)+'.'
    if cid=='aws.cb.redshift.security_group_port_restricted':
        port=e.get('port');groups=e.get('offending_security_groups')
        if type(port) is int and 0<port<=65535 and isinstance(groups,list) and all(_readable(g) for g in groups):return f'No checked security group declares Internet-wide ingress to TCP/{port}.' if not groups else f'{len(groups)} security groups declare Internet-wide ingress to TCP/{port}.'
    if cid=='aws.cb.lightsail.instance_not_public':
        ports=e.get('public_ports');ip=e.get('public_ip')
        if type(ports) is int and ports>=0 and (ip is None or _readable(ip)):
            return f'The Lightsail instance declares {ports} public port ranges'+('; a public IP is assigned.' if ip else '; no public IP is recorded.')
    if cid=='aws.claude_a.s3.prowler_bucket_level_public_access_block':
        level=e.get('level')
        if level in ('account','bucket'):return 'The result identifies '+level+'-level S3 protection; the individual Block Public Access settings were not retained.'
    if cid.startswith('aws.claude_a.ec2.instance_port_'):
        ports=e.get('ports')
        if isinstance(ports,list) and ports and all(type(v) is int and 0<v<=65535 for v in ports):
            return 'The recorded exposure result names checked ports '+', '.join(str(v) for v in ports)+'; path details were not retained.'
    if cid in {'aws.claude_a.ebs.attached_delete_on_termination','aws.claude_a.ec2.ami_ebs_encrypted','aws.claude_a.vpc.vpn_tunnel_logging'}:
        key,label={'aws.claude_a.ebs.attached_delete_on_termination':('delete_on_termination','Attached-volume delete-on-termination declarations'),'aws.claude_a.ec2.ami_ebs_encrypted':('encrypted','AMI EBS encryption declarations'),'aws.claude_a.vpc.vpn_tunnel_logging':('tunnel_logging','VPN tunnel logging declarations')}[cid]
        values=e.get(key)
        if isinstance(values,list) and all(type(v) is bool for v in values):return f'{label}: {sum(values)} enabled, {len(values)-sum(values)} disabled.'
    if cid in LIMITED_WITNESSES:
        detail,identifier=LIMITED_WITNESSES[cid]
        if not e or identifier and set(e)=={identifier} and _readable(e[identifier]):
            return 'The recorded result does not retain '+detail+' needed to explain it.'
    if cid=='aws.claude_a.ec2.instance_no_launch_wizard_sg':
        names=e.get('groups')
        if isinstance(names,list) and all(_readable(v) and v.startswith('launch-wizard') for v in names):return 'No attached security-group name starts with launch-wizard.' if not names else 'Attached security groups have launch-wizard names: '+', '.join(names)+'.'
    if cid=='aws_backup_cross_region_copy':
        n=e.get('cross_region_rules')
        if type(n) is int and n>=0:return f'The backup plan declares {n} cross-region copy '+('rule.' if n==1 else 'rules.')
    if cid in {'aws.claude_a.ebs.snapshot_not_public','aws.claude_a.ec2.ami_not_public'} and type(e.get('public')) is bool:
        asset='EBS snapshot restore permissions' if '.ebs.' in cid else 'AMI launch permissions'
        return asset+' '+('include' if e['public'] else 'do not include')+' a public grant.'
    if cid in {'aws.cb.opensearch.access_policy_not_public','aws.claude_a.s3.prowler_public_access','aws.claude_a.s3.prowler_public_list_acl','aws.claude_a.s3.prowler_public_write_acl','aws.htbp.ecr.replication_destinations_trust_boundary','aws.htbp.ecr.creation_template_policy_trust_boundary','aws.htbp.eks.access_entry_principal_trust_boundary','aws.htbp.opensearch.connection_peer_trust_boundary'} and type(e.get('public')) is bool:
        labels={
            'aws.cb.opensearch.access_policy_not_public':'OpenSearch access-policy public-principal grants',
            'aws.claude_a.s3.prowler_public_access':'Public bucket ACL or policy grants',
            'aws.claude_a.s3.prowler_public_list_acl':'Public bucket listing ACL grants',
            'aws.claude_a.s3.prowler_public_write_acl':'Public bucket write ACL grants',
            'aws.htbp.ecr.replication_destinations_trust_boundary':'Unrestricted ECR replication destination declarations',
            'aws.htbp.ecr.creation_template_policy_trust_boundary':'Unrestricted ECR template principals',
            'aws.htbp.eks.access_entry_principal_trust_boundary':'Unrestricted EKS access-entry principals',
            'aws.htbp.opensearch.connection_peer_trust_boundary':'Unrestricted OpenSearch peer declarations',
        }
        label=labels[cid]
        return label+' are recorded.' if e['public'] else 'No '+_noun(label)+' are recorded.'
    if cid in {'aws_acm_certificate_lifecycle','aws_fedramp_acm_all_certificates_30_day_expiry','aws.nist.acm_all_certificates_expiry_30_days','aws_nist_acm_certificate_expires_30_days','aws_g6_acm_all_certificates_30_day_expiry'}:
        from datetime import datetime
        raw=e.get('expiry',e.get('not_after'))
        try:
            end=datetime.fromisoformat(raw.replace('Z','+00:00'))
            if end.tzinfo is None:return None
        except (AttributeError,TypeError,ValueError):return None
        return f'The assessed ACM certificate expires on {end.date()}.'
    if cid=='aws_config_continuous_inventory':
        overrides=e.get('override_frequencies')
        if e.get('recording') is True and e.get('all_supported') is True and e.get('frequency')=='CONTINUOUS' and isinstance(overrides,list) and all(v=='CONTINUOUS' for v in overrides):
            return 'The AWS Config recorder is running with continuous recording for all supported resource types in this region.'
    if cid=='aws.htbp.cognito.client_no_writable_authorization_attributes':
        clients=e.get('clients');n=e.get('clients_evaluated')
        if clients==[] and type(n) is int and n>=0 and e.get('coverage_incomplete') is False:return f'None of the {n} assessed Cognito clients declares a writable attribute matching the authorization-field heuristic.'
    if cid.startswith('aws.gap.cloudwatch.cis_alarm.'):
        if _readable(e.get('trail')) and _readable(e.get('log_group')):
            return 'The CIS alarm review retains the CloudTrail log-group reference '+e['log_group']+'; alarm-target details were not retained.'
    if cid=='aws.s3.access_logging':
        s=e.get('logging_enabled')
        if isinstance(s,dict) and _readable(s.get('TargetBucket')):return 'Bucket access logging targets '+s['TargetBucket']+'.'
    if cid=='aws.iam.root_mfa':
        flags=e.get('credential_flags')
        if isinstance(flags,dict) and flags.get('mfa_active') in ('true','false'):return 'The root credential report records MFA as '+('active.' if flags['mfa_active']=='true' else 'inactive.')
    if cid in {'aws.claude_a.s3.bucket_public_access_block_all','aws.claude_a.s3.access_point_public_access_block','aws.claude_a.s3.prowler_bucket_level_public_access_block','aws.a.s3.bucket_account_public_blocks'}:
        s=e.get('effective_settings',e.get('settings'));labels={'BlockPublicAcls':'block public ACLs','IgnorePublicAcls':'ignore public ACLs','BlockPublicPolicy':'block public policies','RestrictPublicBuckets':'restrict public buckets'}
        if isinstance(s,dict) and all(type(s.get(k)) is bool for k in labels):
            missing=[v for k,v in labels.items() if not s[k]]
            return 'S3 public-access protections not enabled: '+', '.join(missing)+'.' if missing else 'All four collected S3 Block Public Access settings are enabled.'
    if cid=='aws_config_all_resources_recorded' and e.get('run_state')=='running' and e.get('recording_scope')=='all_supported':
        return 'The regional AWS Config recorder is running with all-supported-resource scope; account-wide coverage is not established.'
    if cid=='aws.b.apigateway.client_certificate' and e.get('field')=='clientCertificateId' and _readable(e.get('declared_reference')):
        return 'The API stage declares a client-certificate reference; certificate validity is not established.'
    if cid=='aws.b.apigateway.waf_reference' and e.get('field')=='webAclArn' and _readable(e.get('declared_reference')):
        return 'The API stage declares a web ACL reference; effective protection is not established.'
    if cid.startswith('aws.gap.cloudwatch.metric_alarm.'):
        if _readable(e.get('trail')) and _readable(e.get('log_group')):
            return 'The alarm review retains the CloudTrail log-group reference '+e['log_group']+'; alarm-target details were not retained.'
    if cid.startswith('aws.gap.ec2.instance_') and isinstance(e.get('roles'),dict):
        return f"Instance-profile roles retained in the permission review: {len(e['roles'])}."
    if cid in {'aws.cb.rds.cluster_critical_event_subscription','aws.cb.rds.instance_critical_event_subscription','aws.cb.rds.parameter_group_critical_event_subscription','aws.cb.rds.security_group_critical_event_subscription'}:
        values=e.get('matching_subscriptions')
        if isinstance(values,list):return f'{len(values)} matching database event subscriptions are recorded; delivery is unverified.'
    return None

BOOLEAN_SENTENCES = {
 'access_log_destination_configured':('The API stage declares an access-log destination.','The API stage declares no access-log destination.'),
 'actions_enabled':('CloudWatch alarm actions are enabled.','CloudWatch alarm actions are disabled.'),
 'all_supported':('AWS Config declares all supported resource types in its recording scope.','AWS Config does not declare all supported resource types in its recording scope.'),
 'allow_version_upgrade':('Database version upgrades are allowed.','Database version upgrades are not allowed.'),
 'backup_selection_match':('An AWS Backup selection matches the resource.','No AWS Backup selection match is recorded.'),
 'cloudfront_default_certificate':('CloudFront uses its default certificate.','CloudFront does not use its default certificate.'),
 'copy_backup_tags':('Tags are copied to file-system backups.','Tags are not copied to file-system backups.'),
 'copy_tags_to_backups':('Tags are copied to file-system backups.','Tags are not copied to file-system backups.'),
 'copy_tags_to_volumes':('Tags are copied to file-system volumes.','Tags are not copied to file-system volumes.'),
 'copy_tags_to_snapshot':('Database tags are copied to snapshots.','Database tags are not copied to snapshots.'),
 'cross_account':('The bucket policy matches the cross-account access pattern.','The bucket policy does not match the cross-account access pattern.'),
 'enforce_https':('The OpenSearch endpoint requires HTTPS.','The OpenSearch endpoint does not require HTTPS.'),
 'enforces_ssl':('The EFS policy contains the checked TLS condition; effective enforcement is unverified.','The EFS policy lacks the checked TLS condition.'),
 'full_access':('The policy matches the unrestricted service-action pattern.','The policy does not match the unrestricted service-action pattern.'),
 'has_default_retention':('The log archive declares default Object Lock retention.','The log archive declares no default Object Lock retention.'),
 'imported_material_expired':('Imported KMS key material has expired.','Imported KMS key material is not marked expired.'),
 'launch_template':('The Auto Scaling group declares a launch template.','The Auto Scaling group declares no launch template.'),
 'lifecycle_policy_present':('The ECR repository has a lifecycle policy.','The ECR repository has no lifecycle policy.'),
 'logging_config':('The Lambda function has logging settings.','The Lambda function has no logging settings.'),
 'object_lock':('The bucket declares an Object Lock configuration.','The bucket declares no Object Lock configuration.'),
 'permissive':('The policy matches the permissive role-assumption pattern.','The policy does not match the permissive role-assumption pattern.'),
 'protected':('The resource appears in the backup protection inventory.','The resource is absent from the backup protection inventory.'),
 'protected_resource_match':('The resource appears in the AWS Backup protected-resource inventory.','The resource is absent from the AWS Backup protected-resource inventory.'),
 'public':('The declaration matches the public-principal model.','The declaration does not match the public-principal model.'),
 'public_acl':('The bucket ACL declares public access.','The bucket ACL declares no public access.'),
 'public_attribute_value_detected':('The snapshot declares a public-sharing attribute.','The snapshot declares no public-sharing attribute.'),
 'public_get_object':('The Lightsail bucket declares public object-read access.','The Lightsail bucket does not declare public object-read access.'),
 'public_policy':('The function policy matches the public-principal pattern.','The function policy does not match the public-principal pattern.'),
 'public_restore_attribute':('The snapshot declares public restore access.','The snapshot does not declare public restore access.'),
 'public_subnet':('The database subnet declares a public route.','The database subnet declares no public route.'),
 'public_write':('The bucket policy declares public write access.','The bucket policy does not declare public write access.'),
 'selection_or_tag_key_match':('The resource ARN or an exact tag key and value matches a backup selection.','Neither the resource ARN nor an exact tag key and value matches a backup selection.'),
 'subscribe_on_all':('The policy declares Marketplace subscription access on all resources.','The policy does not declare Marketplace subscription access on all resources.'),
 'update_available':('An OpenSearch service-software update is available.','No OpenSearch service-software update is reported.'),
 'versioning':('Bucket versioning is enabled.','Bucket versioning is disabled.'),
 'virtual_root_mfa':('A virtual root MFA device is recorded.','No virtual root MFA device is recorded.'),
}
FRESH_BOOLEAN_WITNESSES = {
 'aws.claude_a.ebs.volume_has_snapshot':('snapshot_found','A snapshot match is recorded for the EBS volume.','No snapshot match is recorded for the EBS volume.'),
 'aws.claude_a.ebs.volume_protected_by_backup':('protected_resource','The EBS volume appears in the AWS Backup protected-resource inventory.','The EBS volume is absent from the AWS Backup protected-resource inventory.'),
 'aws.claude_a.ebs.volume_in_backup_plan_resources':('backup_selection_match','An AWS Backup selection includes the EBS volume.','No AWS Backup selection includes the EBS volume.'),
 'aws.claude_a.ec2.instance_protected_by_backup':('protected_resource','The instance appears in the AWS Backup protected-resource inventory.','The instance is absent from the AWS Backup protected-resource inventory.'),
 'aws.claude_a.ec2.instance_ssm_managed':('ssm_managed','The instance appears in the SSM managed-instance inventory.','The instance is absent from the SSM managed-instance inventory.'),
 'aws.claude_a.ec2.active_instance_ssm_managed':('ssm_managed','The active instance appears in the SSM managed-instance inventory.','The active instance is absent from the SSM managed-instance inventory.'),
 'aws.claude_a.ec2.launch_template_no_public_ip':('public_ip_assignment_found','A launch-template version enables public-IP assignment.','No checked launch-template version enables public-IP assignment.'),
 'aws_nist_secretsmanager_secret_automatic_rotation_enabled':('rotation_enabled','Automatic secret rotation is enabled.','Automatic secret rotation is disabled.'),
}


def _fresh(cid,e):
    if cid in REVIEWED_FIELDS and cid.startswith('aws.claude_a.ec2.instance_port_'):
        ports=e.get('ports');open_ingress=e.get('checked_ports_world_ingress')
        if type(open_ingress) is bool and isinstance(ports,list) and ports and all(type(v) is int and 0<v<=65535 for v in ports):
            return ('Internet-wide security-group ingress is recorded' if open_ingress else 'No Internet-wide security-group ingress is recorded')+' for checked TCP ports '+', '.join(str(v) for v in ports)+'; endpoint reachability is not established.'
    if cid=='aws.claude_a.s3.prowler_bucket_level_public_access_block':
        settings=e.get('settings');level=e.get('level')
        if level in ('account','bucket') and isinstance(settings,dict) and type(settings.get('IgnorePublicAcls')) is bool and type(settings.get('RestrictPublicBuckets')) is bool:
            if settings['IgnorePublicAcls'] and settings['RestrictPublicBuckets']:return 'The '+level+'-level S3 settings ignore public ACLs and restrict public buckets.'
            return 'S3 '+level+'-level public ACL ignoring is '+('enabled' if settings['IgnorePublicAcls'] else 'disabled')+'; public bucket restriction is '+('enabled' if settings['RestrictPublicBuckets'] else 'disabled')+'.'
    if cid in FRESH_BOOLEAN_WITNESSES:
        key,a,b=FRESH_BOOLEAN_WITNESSES[cid]
        if type(e.get(key)) is bool:return a if e[key] else b
    if cid=='aws.c2b.elbv2.http_listeners_redirect_https':
        rows=e.get('http_listeners_without_redirect')
        if isinstance(rows,list) and all(_readable(v) for v in rows):return 'No checked HTTP listener lacks an HTTPS redirect.' if not rows else f'{len(rows)} HTTP listeners lack an HTTPS redirect.'
    if cid=='aws_g6_api_stage_valid_client_certificate':
        from datetime import datetime
        try:
            end=datetime.fromisoformat(e.get('certificate_expires_at').replace('Z','+00:00'));at=datetime.fromisoformat(e.get('evaluation_time').replace('Z','+00:00'))
            if end.tzinfo is None or at.tzinfo is None:return None
        except (AttributeError,TypeError,ValueError):return None
        return f'The client certificate expires on {end.date()}; the assessment date is {at.date()}.'
    if cid=='aws_shield_protection_health_checks':
        ids=e.get('verified_health_check_ids')
        if isinstance(ids,list) and all(_readable(v) for v in ids):return f'{len(ids)} referenced Shield health '+('check is' if len(ids)==1 else 'checks are')+' present in the collected inventory.'
    if cid=='aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az':
        types,zones=e.get('instance_types'),e.get('availability_zones')
        if isinstance(types,list) and isinstance(zones,list) and all(_readable(v) for v in types+zones):return f'The Auto Scaling group declares {len(set(types))} instance types across {len(set(zones))} availability zones.'
    if cid in {'aws.nist.ec2_instance_effective_public_reachability','aws_fedramp_ec2_effective_public_exposure'} and e.get('public_paths')==[]:
        return 'The configuration model records no public-address path to the instance.'
    return None

# The same provider field name can have different meanings in different services.
REVIEWED_FIELDS['aws.cb.redshift.snapshot_retention_7_days']['label']='Redshift automated-snapshot retention in days'
REVIEWED_FIELDS['aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days']['label']='ElastiCache automated-snapshot retention in days'
REVIEWED_FIELDS['aws.claude2_a.cloudtrail.threat_detection_llm_jacking']['label']='Identities matching the observed LLM-service activity threshold'
REVIEWED_FIELDS['aws.claude2_a.cloudtrail.threat_detection_privilege_escalation']['label']='Identities matching the observed privilege-escalation activity threshold'
REVIEWED_FIELDS['aws.claude_a.ec2.instance_no_launch_wizard_sg']['label']='Attached security groups whose name starts with launch-wizard'
REVIEWED_FIELDS['aws.cb.redshift.audit_logging']['label']='Redshift audit logging'
REVIEWED_FIELDS['aws_backup_cross_region_copy']={'field':'cross_region_rules','label':'Backup rules declaring a cross-region copy'}
for _cid,_label in {
 'aws.claude_a.ebs.volume_in_use':'EBS volume state',
 'aws.claude_a.ec2.snapshot_block_public_access':'Regional EBS snapshot Block Public Access mode',
 'aws.claude_a.ec2.ami_block_public_access':'Regional AMI Block Public Access mode',
 'aws.claude_a.ec2.enclave_host_running':'Enclave host instance state',
 'aws.claude_a.s3.prowler_bucket_level_public_access_block':'S3 public-access blocking level',
}.items():REVIEWED_FIELDS[_cid]['label']=_label

# These CIS aliases use the same retained alarm-review witness schema.
for _cid in ('aws.gap.cloudwatch.cis_alarm.unauthorized_api_calls',
 'aws.gap.cloudwatch.cis_alarm.console_sign_in_without_mfa',
 'aws.gap.cloudwatch.cis_alarm.root_account_usage',
 'aws.gap.cloudwatch.cis_alarm.iam_policy_changes',
 'aws.gap.cloudwatch.cis_alarm.cloudtrail_configuration_changes',
 'aws.gap.cloudwatch.cis_alarm.console_authentication_failures',
 'aws.gap.cloudwatch.cis_alarm.cmk_disable_or_scheduled_deletion',
 'aws.gap.cloudwatch.cis_alarm.s3_bucket_policy_changes',
 'aws.gap.cloudwatch.cis_alarm.config_configuration_changes',
 'aws.gap.cloudwatch.cis_alarm.security_group_changes',
 'aws.gap.cloudwatch.cis_alarm.network_acl_changes',
 'aws.gap.cloudwatch.cis_alarm.network_gateway_changes',
 'aws.gap.cloudwatch.cis_alarm.route_table_changes',
 'aws.gap.cloudwatch.cis_alarm.vpc_changes',
 'aws.gap.cloudwatch.cis_alarm.organizations_changes'):
    REVIEWED_FIELDS[_cid]={'field':'log_group','label':'CloudTrail log-group reference for the CIS alarm review'}

ALARM_EVENTS={
 'unauthorized_api_calls':'unauthorized API calls',
 'console_sign_in_without_mfa':'console sign-ins without MFA',
 'root_account_usage':'root-account use',
 'iam_policy_changes':'IAM policy changes',
 'cloudtrail_configuration_changes':'CloudTrail configuration changes',
 'console_authentication_failures':'console authentication failures',
 'cmk_disable_or_scheduled_deletion':'KMS key disablement or scheduled deletion',
 's3_bucket_policy_changes':'S3 bucket policy changes',
 'config_configuration_changes':'AWS Config configuration changes',
 'security_group_changes':'security-group changes',
 'network_acl_changes':'network ACL changes',
 'network_gateway_changes':'network gateway changes',
 'route_table_changes':'route-table changes',
 'vpc_changes':'VPC changes',
 'organizations_changes':'AWS Organizations changes',
}
