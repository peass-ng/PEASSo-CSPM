"""Thirty individually reviewed, hash-bound customer-facing copy corrections.

Only display prose changes. Detection, signed provenance, requirement mappings,
pass/fail criteria and commands remain in their original contracts. The copy
review is distinct from runtime validation and does not approve other checks.
"""
from copy import deepcopy
import hashlib
import json

VERSION = "finding-clarity-first30-v1"
ROWS = {'aws.c2b.acm.in_use_not_expiring_7_days': {'description_base_sha256': '837970b33642b55ee18e74f60685a7e8626e1a7883605e289dca88241552275b',
                                            'description_fields': {'description': 'Compares an in-use '
                                                                                  'certificate’s expiry with '
                                                                                  'the scan time.'},
                                            'remediation_base_sha256': '5ee9a2b86d23ebd736b38ccaed96984f92b0f1f915c4d6b21c8f6c87c2408979',
                                            'remediation_fields': {'caveats': ['Certificate replacement can '
                                                                               'affect attached services; '
                                                                               'imported certificates '
                                                                               'require renewal through '
                                                                               'their issuer.'],
                                                                   'steps': ['Renew the certificate before '
                                                                             'it expires.',
                                                                             'For an imported certificate, '
                                                                             'reimport the renewed '
                                                                             'certificate; otherwise fix '
                                                                             'managed renewal and confirm '
                                                                             'attached services use the '
                                                                             'renewed certificate.'],
                                                                   'summary': 'Renew the certificate before '
                                                                              'it expires.'}},
 'aws.c2b.bedrock.custom_model_cmk': {'description_base_sha256': '0ae19cb1e919d38c0ed95bac27a8e8275c4e22976d8d22b9100a3075d6697551',
                                      'description_fields': {'description': 'Checks whether the custom model '
                                                                            'has a KMS key ARN.'},
                                      'remediation_base_sha256': '67e993ca644d4295bf8827f8702842ed91a3fbc010310874dc37b660936f0195',
                                      'remediation_fields': {'caveats': ['Changing this key configuration '
                                                                         'requires a replacement model and '
                                                                         'consumer migration; this check '
                                                                         'does not establish that stored '
                                                                         'weights are plaintext.'],
                                                             'steps': ['If a dedicated key is required, '
                                                                       'create an encrypted replacement '
                                                                       'model and migrate its consumers.'],
                                                             'summary': 'If a dedicated key is required, '
                                                                        'create an encrypted replacement '
                                                                        'model and migrate its consumers.'}},
 'aws.c2b.bedrock.invocation_logs_encrypted': {'description_base_sha256': '06de0a25104a895a57486a2f86f52056244325f944fa03b9cda8a9382e68e8f3',
                                               'description_fields': {'description': 'Checks default '
                                                                                     'encryption settings on '
                                                                                     'the collected S3 '
                                                                                     'buckets and KMS key '
                                                                                     'associations on '
                                                                                     'CloudWatch log groups '
                                                                                     'used for Bedrock '
                                                                                     'invocation logs.'},
                                               'remediation_base_sha256': '9c48074e905bd02fc78f938bc0a50587b4608756c8592120fd3d2d5924b437d4',
                                               'remediation_fields': {'caveats': ['S3 automatically encrypts '
                                                                                  'new objects with SSE-S3; '
                                                                                  'absent default-encryption '
                                                                                  'metadata does not prove '
                                                                                  'plaintext or describe '
                                                                                  'existing log objects.'],
                                                                      'steps': ['Configure the required '
                                                                                'encryption on the named log '
                                                                                'destination.'],
                                                                      'summary': 'Configure the required '
                                                                                 'encryption on the named '
                                                                                 'log destination.'}},
 'aws.c2b.cloudfront.s3_origin_bucket_exists': {'description_base_sha256': 'f93ff5674feabdc7d18159eeb4a972b65df0f6d999e5250f6e1b27e8bb2b557c',
                                                'description_fields': {'description': 'Checks CloudFront S3 '
                                                                                      'origins against '
                                                                                      'bucket inventory and '
                                                                                      'collected HeadBucket '
                                                                                      'responses; only a '
                                                                                      'HeadBucket 404 '
                                                                                      'fails.'},
                                                'remediation_base_sha256': '52f33f4d489fd4716efde68579cee65f2ee9540d51773dca30b5d0de5ca426b3',
                                                'remediation_fields': {'caveats': ['Do not create or claim a '
                                                                                   'bucket name solely from '
                                                                                   'this finding; missing '
                                                                                   'probes remain UNKNOWN, '
                                                                                   'and a 403 does not '
                                                                                   'establish ownership or '
                                                                                   'working origin access.'],
                                                                       'steps': ['Repoint the affected '
                                                                                 'origin to its intended '
                                                                                 'bucket, or remove it after '
                                                                                 'updating the behaviors '
                                                                                 'that use it.'],
                                                                       'summary': 'Repoint the affected '
                                                                                  'origin to its intended '
                                                                                  'bucket, or remove it '
                                                                                  'after updating the '
                                                                                  'behaviors that use it.'}},
 'aws.c2b.ecr.latest_image_no_medium_plus_findings': {'description_base_sha256': '967bf82f02cd1c293c21243f8abf4ef47a54b609c2a9e5feb054e4635c518450',
                                                      'description_fields': {'description': 'Selects the '
                                                                                            'newest '
                                                                                            'scannable '
                                                                                            'non-signature '
                                                                                            'image by '
                                                                                            'imagePushedAt '
                                                                                            'and checks that '
                                                                                            'exact digest’s '
                                                                                            'completed scan '
                                                                                            'for '
                                                                                            'medium-or-higher '
                                                                                            'findings; a '
                                                                                            'failed scan '
                                                                                            'also fails.'},
                                                      'remediation_base_sha256': '77545f2478475e66d292a106e03125ebf2c87b4dc7c9a80211cdb39ac45a941f',
                                                      'remediation_fields': {'caveats': ['Missing scan '
                                                                                         'status, counts, '
                                                                                         'completion time or '
                                                                                         'complete '
                                                                                         'pagination remains '
                                                                                         'UNKNOWN; current '
                                                                                         'Basic Scanning '
                                                                                         'needs exact-digest '
                                                                                         'scan details, not '
                                                                                         'DescribeImages '
                                                                                         'alone.'],
                                                                             'steps': ['Patch the affected '
                                                                                       'packages and publish '
                                                                                       'a tested replacement '
                                                                                       'image.',
                                                                                       'If the scan failed, '
                                                                                       'fix the scan failure '
                                                                                       'before treating the '
                                                                                       'image as assessed.'],
                                                                             'summary': 'Patch the affected '
                                                                                        'packages and '
                                                                                        'publish a tested '
                                                                                        'replacement '
                                                                                        'image.'}},
 'aws.c2b.elasticache.cluster_public_subnet': {'description_base_sha256': '42701d208f51951ef29047667581429bd9b1eb6ed994f2dc4a198d6a16176535',
                                               'description_fields': {'description': 'Checks whether a cache '
                                                                                     'subnet’s effective '
                                                                                     'route table sends its '
                                                                                     'IPv4 default route to '
                                                                                     'an internet gateway.'},
                                               'remediation_base_sha256': '47aba68d32e999c4cf12c3a9b6ea5afffe85971999bb047995ed9c83a7b947db',
                                               'remediation_fields': {'caveats': ['An internet-gateway route '
                                                                                  'alone does not prove '
                                                                                  'cache reachability; '
                                                                                  'required NAT egress must '
                                                                                  'not be removed during '
                                                                                  'migration.'],
                                                                      'steps': ['If internet routing is '
                                                                                'unnecessary, migrate the '
                                                                                'cache to subnets without '
                                                                                'that route; preserve '
                                                                                'NAT-only egress.'],
                                                                      'summary': 'If internet routing is '
                                                                                 'unnecessary, migrate the '
                                                                                 'cache to subnets without '
                                                                                 'that route.'}},
 'aws.c2b.elasticache.cluster_public_subnet_prowler': {'description_base_sha256': '043c9c7f34f0ebc9a33f43cacd2d9491464bd75b302faad0b41bfe31dc308f1e',
                                                       'description_fields': {'description': 'Checks whether '
                                                                                             'a cache '
                                                                                             'subnet’s '
                                                                                             'effective '
                                                                                             'route table '
                                                                                             'sends its IPv4 '
                                                                                             'default route '
                                                                                             'to an internet '
                                                                                             'gateway.'},
                                                       'remediation_base_sha256': 'eb4b88a081523ae77f9c66b1630fe239e816da33580bb2be282bdcf021d926d3',
                                                       'remediation_fields': {'caveats': ['An '
                                                                                          'internet-gateway '
                                                                                          'route alone does '
                                                                                          'not prove cache '
                                                                                          'reachability; '
                                                                                          'required NAT '
                                                                                          'egress must not '
                                                                                          'be removed during '
                                                                                          'migration.'],
                                                                              'steps': ['If internet routing '
                                                                                        'is unnecessary, '
                                                                                        'migrate the cache '
                                                                                        'to subnets without '
                                                                                        'that route; '
                                                                                        'preserve NAT-only '
                                                                                        'egress.'],
                                                                              'summary': 'If internet '
                                                                                         'routing is '
                                                                                         'unnecessary, '
                                                                                         'migrate the cache '
                                                                                         'to subnets without '
                                                                                         'that route.'}},
 'aws.c2b.elasticache.cmk_enabled': {'description_base_sha256': 'f2d0e18e6fcf6327b35d1bff2542fc92ccaf0551371ae6ffecb689f29ba740ca',
                                     'description_fields': {'description': 'Checks the replication group’s '
                                                                           'encryption flag, configured KMS '
                                                                           'key, and that key’s enabled '
                                                                           'state.'},
                                     'remediation_base_sha256': '3c3180725918ba7d798ebb2e416e91e7030d957db3c086cfb80f73d01af07c6d',
                                     'remediation_fields': {'caveats': ['Missing key configuration does not '
                                                                        'prove plaintext storage; changing a '
                                                                        'group’s encryption configuration '
                                                                        'can require replacement.'],
                                                            'steps': ['Restore access to the configured key '
                                                                      'if it is disabled.',
                                                                      'If the group needs a different '
                                                                      'encryption configuration, migrate to '
                                                                      'a replacement group configured with '
                                                                      'the required key.'],
                                                            'summary': 'Restore access to the configured key '
                                                                       'if it is disabled.'}},
 'aws.c2b.elasticache.redis_auth_pre6': {'description_base_sha256': 'dee9756c99190a50acfdcfbdb2092f85a24161acb9acde44e456dc5affc09842',
                                         'description_fields': {'description': 'Checks whether a replication '
                                                                               'group with a Redis member '
                                                                               'older than 6.0 has an AUTH '
                                                                               'token enabled.'},
                                         'remediation_base_sha256': 'e547b9506438808fdb3d7726d53b8a56aa83976ddb1a15efc35829f4bff6283f',
                                         'remediation_fields': {'caveats': ['Enable TLS and migrate clients '
                                                                            'before requiring AUTH; the '
                                                                            'initial ROTATE phase alone '
                                                                            'still allows unauthenticated '
                                                                            'clients.'],
                                                                'steps': ['Migrate clients to TLS and AUTH, '
                                                                          'then require AUTH after clients '
                                                                          'are updated.',
                                                                          'Upgrade or replace older versions '
                                                                          'that cannot enable AUTH in '
                                                                          'place.'],
                                                                'summary': 'Migrate clients to TLS and AUTH, '
                                                                           'then require AUTH after clients '
                                                                           'are updated.'}},
 'aws.c2b.elbv2.listeners_secure_protocol': {'description_base_sha256': 'c9141ff7634477ba1e3bdd2af3769aafa89fa512d308c0e905e23f0cabba1ee2',
                                             'description_fields': {'description': 'Checks that ALB '
                                                                                   'listeners use HTTPS and '
                                                                                   'NLB listeners use TLS.'},
                                             'remediation_base_sha256': '6e1964fa511e866cd047f1dc38bcbb5d04805598285bf6d1fa9aed208282e9ca',
                                             'remediation_fields': {'caveats': ['This strict '
                                                                                'listener-protocol check '
                                                                                'also flags HTTP redirects '
                                                                                'and TCP TLS pass-through; '
                                                                                'it does not establish that '
                                                                                'their traffic is '
                                                                                'plaintext.'],
                                                                    'steps': ['Use HTTPS or TLS termination '
                                                                              'where appropriate for the '
                                                                              'application.',
                                                                              'Retain deliberate TLS '
                                                                              'pass-through or HTTP '
                                                                              'redirects under the '
                                                                              'appropriate listener policy.'],
                                                                    'summary': 'Use HTTPS or TLS termination '
                                                                               'where appropriate for the '
                                                                               'application.'}},
 'aws.c2b.emr.cluster_not_publicly_accessible': {'description_base_sha256': 'af8c442664822a0a667a9e2233d1195861cd269d1fcf1e624d497f20915dd2f5',
                                                 'description_fields': {'description': 'Checks public-DNS '
                                                                                       'EMR clusters for '
                                                                                       'attached security '
                                                                                       'groups allowing '
                                                                                       'every protocol or '
                                                                                       'all ports from '
                                                                                       'public networks.'},
                                                 'remediation_base_sha256': '203a1da07da675139bc387e5040e3dff215ca0953b2a3c7e58dacc2638551344',
                                                 'remediation_fields': {'caveats': ['Change only the matched '
                                                                                    'public ingress rule; '
                                                                                    'security groups may be '
                                                                                    'shared and '
                                                                                    'cluster-internal rules '
                                                                                    'may be required.'],
                                                                        'steps': ['Replace the identified '
                                                                                  'all-traffic ingress rule '
                                                                                  'with only the sources and '
                                                                                  'ports the cluster needs.'],
                                                                        'summary': 'Replace the identified '
                                                                                   'all-traffic ingress rule '
                                                                                   'with only the sources '
                                                                                   'and ports the cluster '
                                                                                   'needs.'}},
 'aws.c2b.es.internal_user_database_enabled': {'description_base_sha256': '651e68318d914fb616ad881b6870f7f7846197a5bf5b111f363302e751502741',
                                               'description_fields': {'description': 'Checks whether the '
                                                                                     'OpenSearch domain’s '
                                                                                     'internal user database '
                                                                                     'is enabled.'},
                                               'remediation_base_sha256': 'fcfd72c6b731109d2b3efadbb11d424326c0a6e8a8e85c4df86c43121ae5b76f',
                                               'remediation_fields': {'caveats': ['External identity '
                                                                                  'authentication can be '
                                                                                  'intentional; this flag '
                                                                                  'alone does not establish '
                                                                                  'that authentication is '
                                                                                  'secure.'],
                                                                      'steps': ['Enable internal users only '
                                                                                'if this domain is intended '
                                                                                'to use that authentication '
                                                                                'model; retain the chosen '
                                                                                'external identity model '
                                                                                'otherwise.'],
                                                                      'summary': 'Enable internal users only '
                                                                                 'if this domain is intended '
                                                                                 'to use that authentication '
                                                                                 'model; retain the chosen '
                                                                                 'external identity model '
                                                                                 'otherwise.'}},
 'aws.cb.kafka.latest_version': {'description_base_sha256': '8e8de4e6a10d83fb6d18d818501304e85a45611e14481947e0bb95aa24922e99',
                                 'description_fields': {'description': 'Compares the cluster’s Kafka version '
                                                                       'with its own supported active '
                                                                       'upgrade targets.'},
                                 'remediation_base_sha256': '27fd44424e89555004ebf84182e1d580cf253d438cde687d6ce728e21ae88d6b',
                                 'remediation_fields': {'caveats': ['Use only a compatible target returned '
                                                                    'for this cluster; if none is available, '
                                                                    'investigate before upgrading. Version '
                                                                    'downgrades are unsupported.',
                                                                              'Obtain a fresh DescribeClusterV2 Version concurrency token before an approved upgrade; review client compatibility, broker availability, maintenance timing and rollback.'],
                                                        'steps': ['Schedule a tested upgrade to an active '
                                                                  'version supported by this cluster.'],
                                                        'summary': 'Schedule a tested upgrade to an active '
                                                                   'version supported by this cluster.'}},
 'aws.cb.rds.instance_iam_auth_all_engines': {'description_base_sha256': '546883065bb95f91dc6947fe2805e12a4ef670affc2e79dfa3582de97522004e',
                                              'description_fields': {'description': 'For supported '
                                                                                    'standalone RDS '
                                                                                    'instances, checks '
                                                                                    'whether IAM database '
                                                                                    'authentication is '
                                                                                    'enabled.'},
                                              'remediation_base_sha256': 'da760017710bd85b3f2bfbbb470d6396a632747cb18f1a237d9bcdf81d0b8284',
                                              'remediation_fields': {'caveats': ['Enabling the setting does '
                                                                                 'not create database users '
                                                                                 'or grant IAM connection '
                                                                                 'permissions.',
                                                                              'Missing or conflicting engine/version/class capability evidence is UNKNOWN; do not change clustered instances or RDS on Outposts through this standalone-instance guidance.',
                                                                              'Review database users, TLS, token refresh and connection pooling first; schedule the change in its maintenance window unless immediate application is separately reviewed.'],
                                                                     'steps': ['If applications will use IAM '
                                                                               'authentication, enable it '
                                                                               'and configure their database '
                                                                               'users and scoped connection '
                                                                               'permissions.'],
                                                                     'summary': 'If applications will use '
                                                                                'IAM authentication, enable '
                                                                                'it and configure their '
                                                                                'database users and scoped '
                                                                                'connection permissions.'}},
 'aws.gap.cloudwatch.cis_alarm.iam_policy_changes': {'description_base_sha256': '16978787dc33ea15b01aff8610c6a029a1f677bb8a324d744957907f846239fd',
                                                     'description_fields': {'description': 'Checks a '
                                                                                           'multi-Region '
                                                                                           'CloudTrail '
                                                                                           'trail, its '
                                                                                           'IAM-policy-change '
                                                                                           'metric filter, '
                                                                                           'and an active '
                                                                                           'alarm with a '
                                                                                           'confirmed SNS '
                                                                                           'subscriber.'},
                                                     'remediation_base_sha256': 'b960616782a13c268ff0749b7139afc2ce238d3ccf1e8cfb03f6ee5f03f603c9',
                                                     'remediation_fields': {'caveats': ['This checks alert '
                                                                                        'configuration and '
                                                                                        'confirmed '
                                                                                        'subscriptions, not '
                                                                                        'actual notification '
                                                                                        'delivery.'],
                                                                            'steps': ['Configure the missing '
                                                                                      'IAM-policy-change '
                                                                                      'filter or matching '
                                                                                      'alarm.',
                                                                                      'Enable alarm '
                                                                                      'notifications to a '
                                                                                      'confirmed SNS '
                                                                                      'subscriber and retain '
                                                                                      'multi-Region trail '
                                                                                      'coverage.'],
                                                                            'summary': 'Configure the '
                                                                                       'missing '
                                                                                       'IAM-policy-change '
                                                                                       'filter or matching '
                                                                                       'alarm.'}},
 'aws.gap.cloudwatch.cis_alarm.organizations_changes': {'description_base_sha256': '7318d7106ebe5007e99a3e81c9863cb1e45b93d672cbcab2852090c625ed7ffc',
                                                        'description_fields': {'description': 'Checks a '
                                                                                              'multi-Region '
                                                                                              'CloudTrail '
                                                                                              'trail, its '
                                                                                              'Organizations-change '
                                                                                              'metric '
                                                                                              'filter, and '
                                                                                              'an active '
                                                                                              'alarm with a '
                                                                                              'confirmed SNS '
                                                                                              'subscriber.'},
                                                        'remediation_base_sha256': 'af4679dfefa86309fd5fbd4df6fe0927adc85a879c837c1b2f5a8a9bedc0902b',
                                                        'remediation_fields': {'caveats': ['This checks '
                                                                                           'alert '
                                                                                           'configuration '
                                                                                           'and confirmed '
                                                                                           'subscriptions, '
                                                                                           'not actual '
                                                                                           'notification '
                                                                                           'delivery.'],
                                                                               'steps': ['Configure the '
                                                                                         'missing '
                                                                                         'Organizations-change '
                                                                                         'filter or matching '
                                                                                         'alarm.',
                                                                                         'Enable alarm '
                                                                                         'notifications to a '
                                                                                         'confirmed SNS '
                                                                                         'subscriber and '
                                                                                         'retain '
                                                                                         'multi-Region trail '
                                                                                         'coverage.'],
                                                                               'summary': 'Configure the '
                                                                                          'missing '
                                                                                          'Organizations-change '
                                                                                          'filter or '
                                                                                          'matching alarm.'}},
 'aws.gap.cloudwatch.metric_alarm.organizations_changes': {'description_base_sha256': '1a112964d849295f922d0f2be2c9df0691c17fef88452ed6f9a772dffe0fbe09',
                                                           'description_fields': {'description': 'Checks '
                                                                                                 'CloudTrail '
                                                                                                 'delivery, '
                                                                                                 'the '
                                                                                                 'Organizations-change '
                                                                                                 'metric '
                                                                                                 'filter, '
                                                                                                 'and its '
                                                                                                 'matching '
                                                                                                 'CloudWatch '
                                                                                                 'alarm.'},
                                                           'remediation_base_sha256': '7b1f329bc81d170c79c0b7212154883f8f85f82d6be9cd1539b608341b20ded8',
                                                           'remediation_fields': {'caveats': ['This variant '
                                                                                              'checks the '
                                                                                              'trail, filter '
                                                                                              'and alarm; it '
                                                                                              'does not '
                                                                                              'require a '
                                                                                              'multi-Region '
                                                                                              'trail or '
                                                                                              'confirmed '
                                                                                              'notification '
                                                                                              'subscriber.'],
                                                                                  'steps': ['Configure the '
                                                                                            'missing '
                                                                                            'Organizations-change '
                                                                                            'filter or '
                                                                                            'matching '
                                                                                            'alarm.'],
                                                                                  'summary': 'Configure the '
                                                                                             'missing '
                                                                                             'Organizations-change '
                                                                                             'filter or '
                                                                                             'matching '
                                                                                             'alarm.'}},
 'aws.gap.ec2.instance_no_iam_role_attached_with_credentials_exposure_access': {'description_base_sha256': '26b37fa69b3faa779bae92e9bd41afd34de3ca6d7560006752488a0dc21d0396',
                                                                                'description_fields': {'description': 'Checks '
                                                                                                                      'the '
                                                                                                                      'instance '
                                                                                                                      'role’s '
                                                                                                                      'declared '
                                                                                                                      'policy '
                                                                                                                      'grants '
                                                                                                                      'and '
                                                                                                                      'permissions '
                                                                                                                      'boundary '
                                                                                                                      'for '
                                                                                                                      'actions '
                                                                                                                      'that '
                                                                                                                      'retrieve '
                                                                                                                      'or '
                                                                                                                      'create '
                                                                                                                      'credentials.'},
                                                                                'remediation_base_sha256': '993aa663f7b17cfdc1edb2cb894f5a18e872666909076529cf151aad37e59f2f',
                                                                                'remediation_fields': {'caveats': ['These '
                                                                                                                   'permissions '
                                                                                                                   'can '
                                                                                                                   'support '
                                                                                                                   'legitimate '
                                                                                                                   'workload '
                                                                                                                   'authentication; '
                                                                                                                   'their '
                                                                                                                   'presence '
                                                                                                                   'does '
                                                                                                                   'not '
                                                                                                                   'prove '
                                                                                                                   'credentials '
                                                                                                                   'were '
                                                                                                                   'exposed.'],
                                                                                                       'steps': ['Remove '
                                                                                                                 'credential-access '
                                                                                                                 'permissions '
                                                                                                                 'the '
                                                                                                                 'application '
                                                                                                                 'does '
                                                                                                                 'not '
                                                                                                                 'need, '
                                                                                                                 'or '
                                                                                                                 'scope '
                                                                                                                 'them '
                                                                                                                 'to '
                                                                                                                 'the '
                                                                                                                 'required '
                                                                                                                 'identities '
                                                                                                                 'and '
                                                                                                                 'resources.'],
                                                                                                       'summary': 'Remove '
                                                                                                                  'credential-access '
                                                                                                                  'permissions '
                                                                                                                  'the '
                                                                                                                  'application '
                                                                                                                  'does '
                                                                                                                  'not '
                                                                                                                  'need, '
                                                                                                                  'or '
                                                                                                                  'scope '
                                                                                                                  'them '
                                                                                                                  'to '
                                                                                                                  'the '
                                                                                                                  'required '
                                                                                                                  'identities '
                                                                                                                  'and '
                                                                                                                  'resources.'}},
 'aws.gap.ec2.instance_no_iam_role_with_org_write_access': {'description_base_sha256': '766516ca5d484da12c1cf4ad8adc0c3823b8e8952eba8b4b02505cfb9ea3e679',
                                                            'description_fields': {'description': 'Checks '
                                                                                                  'the '
                                                                                                  'instance '
                                                                                                  'role’s '
                                                                                                  'declared '
                                                                                                  'policy '
                                                                                                  'grants '
                                                                                                  'and '
                                                                                                  'permissions '
                                                                                                  'boundary '
                                                                                                  'for '
                                                                                                  'organization-changing '
                                                                                                  'actions.'},
                                                            'remediation_base_sha256': 'b37d8aa698b882b4ecd72dbc845a39b92661fd67c717d9d37c37379325c7e018',
                                                            'remediation_fields': {'caveats': ['Policy '
                                                                                               'declarations '
                                                                                               'do not '
                                                                                               'establish '
                                                                                               'effective '
                                                                                               'access under '
                                                                                               'every '
                                                                                               'condition; '
                                                                                               'preserve '
                                                                                               'permissions '
                                                                                               'the '
                                                                                               'application '
                                                                                               'needs.'],
                                                                                   'steps': ['Remove '
                                                                                             'organization-changing '
                                                                                             'permissions '
                                                                                             'the '
                                                                                             'application '
                                                                                             'does not need '
                                                                                             'from the '
                                                                                             'identified '
                                                                                             'role policy.'],
                                                                                   'summary': 'Remove '
                                                                                              'organization-changing '
                                                                                              'permissions '
                                                                                              'the '
                                                                                              'application '
                                                                                              'does not need '
                                                                                              'from the '
                                                                                              'identified '
                                                                                              'role '
                                                                                              'policy.'}},
 'aws.gap.ec2.instance_no_iam_with_write_level_access': {'description_base_sha256': '309c7d14fec334da128d5d5d355a82aa9ab13a6653d84cdf0fbac727604bd367',
                                                         'description_fields': {'description': 'Checks the '
                                                                                               'instance '
                                                                                               'role’s '
                                                                                               'declared '
                                                                                               'policy '
                                                                                               'grants and '
                                                                                               'permissions '
                                                                                               'boundary for '
                                                                                               'IAM-changing '
                                                                                               'actions.'},
                                                         'remediation_base_sha256': '7eeaf448ab83a21ee801ae237b39fe2d1fcbb74c6236d4751deff94cff28b3f2',
                                                         'remediation_fields': {'caveats': ['Policy '
                                                                                            'declarations do '
                                                                                            'not establish '
                                                                                            'effective '
                                                                                            'access under '
                                                                                            'every '
                                                                                            'condition; '
                                                                                            'preserve '
                                                                                            'permissions the '
                                                                                            'application '
                                                                                            'needs.'],
                                                                                'steps': ['Remove '
                                                                                          'IAM-changing '
                                                                                          'permissions the '
                                                                                          'application does '
                                                                                          'not need from the '
                                                                                          'identified role '
                                                                                          'policy.'],
                                                                                'summary': 'Remove '
                                                                                           'IAM-changing '
                                                                                           'permissions the '
                                                                                           'application does '
                                                                                           'not need from '
                                                                                           'the identified '
                                                                                           'role policy.'}},
 'azure.claude.activity_log_alert_subscription_nsg_delete': {'description_base_sha256': '1b9f64f2f2f63f93ce5fa5fee95a09fab157bd542c923fde371751d9e7146906',
                                                             'description_fields': {'description': 'Looks '
                                                                                                   'for an '
                                                                                                   'enabled '
                                                                                                   'subscription-wide '
                                                                                                   'Activity '
                                                                                                   'Log '
                                                                                                   'alert '
                                                                                                   'covering '
                                                                                                   'NSG '
                                                                                                   'deletion.'},
                                                             'remediation_base_sha256': '6a9ca6b8536bbf35b72855b5dece6119ded36134eda79137e104954b0a400848',
                                                             'remediation_fields': {'caveats': ['This checks '
                                                                                                'the enabled '
                                                                                                'alert '
                                                                                                'declaration, '
                                                                                                'not whether '
                                                                                                'notifications '
                                                                                                'were '
                                                                                                'delivered.'],
                                                                                    'steps': ['Create or '
                                                                                              'update the '
                                                                                              'subscription '
                                                                                              'alert for NSG '
                                                                                              'deletion and '
                                                                                              'connect its '
                                                                                              'notification '
                                                                                              'action '
                                                                                              'group.'],
                                                                                    'summary': 'Create or '
                                                                                               'update the '
                                                                                               'subscription '
                                                                                               'alert for '
                                                                                               'NSG deletion '
                                                                                               'and connect '
                                                                                               'its '
                                                                                               'notification '
                                                                                               'action '
                                                                                               'group.'}},
 'azure.claude.activity_log_alert_subscription_nsg_rule_delete': {'description_base_sha256': '9e2b71d4e55273adb86290820d4a5f06126c7a012d9ccda8182d6e2685c53de5',
                                                                  'description_fields': {'description': 'Looks '
                                                                                                        'for '
                                                                                                        'an '
                                                                                                        'enabled '
                                                                                                        'subscription-wide '
                                                                                                        'Activity '
                                                                                                        'Log '
                                                                                                        'alert '
                                                                                                        'covering '
                                                                                                        'NSG-rule '
                                                                                                        'deletion.'},
                                                                  'remediation_base_sha256': '0179365bf969e700aa127d11d4164e8536c4ffe132bcfe295421d603adffc320',
                                                                  'remediation_fields': {'caveats': ['This '
                                                                                                     'checks '
                                                                                                     'the '
                                                                                                     'enabled '
                                                                                                     'alert '
                                                                                                     'declaration, '
                                                                                                     'not '
                                                                                                     'whether '
                                                                                                     'notifications '
                                                                                                     'were '
                                                                                                     'delivered.'],
                                                                                         'steps': ['Create '
                                                                                                   'or '
                                                                                                   'update '
                                                                                                   'the '
                                                                                                   'subscription '
                                                                                                   'alert '
                                                                                                   'for '
                                                                                                   'NSG-rule '
                                                                                                   'deletion '
                                                                                                   'and '
                                                                                                   'connect '
                                                                                                   'its '
                                                                                                   'notification '
                                                                                                   'action '
                                                                                                   'group.'],
                                                                                         'summary': 'Create '
                                                                                                    'or '
                                                                                                    'update '
                                                                                                    'the '
                                                                                                    'subscription '
                                                                                                    'alert '
                                                                                                    'for '
                                                                                                    'NSG-rule '
                                                                                                    'deletion '
                                                                                                    'and '
                                                                                                    'connect '
                                                                                                    'its '
                                                                                                    'notification '
                                                                                                    'action '
                                                                                                    'group.'}},
 'azure.claude.activity_log_alert_subscription_nsg_rule_write': {'description_base_sha256': '044010d8061650824ab9af0cb3ca1cb4ddb30c8f99a9119ad3d9d5c34c1693bf',
                                                                 'description_fields': {'description': 'Looks '
                                                                                                       'for '
                                                                                                       'an '
                                                                                                       'enabled '
                                                                                                       'subscription-wide '
                                                                                                       'Activity '
                                                                                                       'Log '
                                                                                                       'alert '
                                                                                                       'covering '
                                                                                                       'NSG-rule '
                                                                                                       'creation '
                                                                                                       'or '
                                                                                                       'updates.'},
                                                                 'remediation_base_sha256': 'a1fc1340ebb935230095acd39f15d9c87f4b408eb7fb3532e0bdd36010a01aa6',
                                                                 'remediation_fields': {'caveats': ['This '
                                                                                                    'checks '
                                                                                                    'the '
                                                                                                    'enabled '
                                                                                                    'alert '
                                                                                                    'declaration, '
                                                                                                    'not '
                                                                                                    'whether '
                                                                                                    'notifications '
                                                                                                    'were '
                                                                                                    'delivered.'],
                                                                                        'steps': ['Create or '
                                                                                                  'update '
                                                                                                  'the '
                                                                                                  'subscription '
                                                                                                  'alert for '
                                                                                                  'NSG-rule '
                                                                                                  'creation '
                                                                                                  'or '
                                                                                                  'updates '
                                                                                                  'and '
                                                                                                  'connect '
                                                                                                  'its '
                                                                                                  'notification '
                                                                                                  'action '
                                                                                                  'group.'],
                                                                                        'summary': 'Create '
                                                                                                   'or '
                                                                                                   'update '
                                                                                                   'the '
                                                                                                   'subscription '
                                                                                                   'alert '
                                                                                                   'for '
                                                                                                   'NSG-rule '
                                                                                                   'creation '
                                                                                                   'or '
                                                                                                   'updates '
                                                                                                   'and '
                                                                                                   'connect '
                                                                                                   'its '
                                                                                                   'notification '
                                                                                                   'action '
                                                                                                   'group.'}},
 'azure.claude.activity_log_alert_subscription_nsg_write': {'description_base_sha256': '2c3544ba99adbbc5ac0e5f0d65720b543924a65167f59effbb7cb9350ae8d854',
                                                            'description_fields': {'description': 'Looks for '
                                                                                                  'an '
                                                                                                  'enabled '
                                                                                                  'subscription-wide '
                                                                                                  'Activity '
                                                                                                  'Log alert '
                                                                                                  'covering '
                                                                                                  'NSG '
                                                                                                  'creation '
                                                                                                  'or '
                                                                                                  'updates.'},
                                                            'remediation_base_sha256': 'd98f998862f3bb067df593426efe45d3ba84a7e1f93583a547262fba80b10a83',
                                                            'remediation_fields': {'caveats': ['This checks '
                                                                                               'the enabled '
                                                                                               'alert '
                                                                                               'declaration, '
                                                                                               'not whether '
                                                                                               'notifications '
                                                                                               'were '
                                                                                               'delivered.'],
                                                                                   'steps': ['Create or '
                                                                                             'update the '
                                                                                             'subscription '
                                                                                             'alert for NSG '
                                                                                             'creation or '
                                                                                             'updates and '
                                                                                             'connect its '
                                                                                             'notification '
                                                                                             'action group.'],
                                                                                   'summary': 'Create or '
                                                                                              'update the '
                                                                                              'subscription '
                                                                                              'alert for NSG '
                                                                                              'creation or '
                                                                                              'updates and '
                                                                                              'connect its '
                                                                                              'notification '
                                                                                              'action '
                                                                                              'group.'}},
 'azure.claude.activity_log_alert_subscription_public_ip_delete': {'description_base_sha256': 'e78d9124f777b8a970ed73cf1556d58f0bfa0502e0f81c61e6c1da4ac436bcc0',
                                                                   'description_fields': {'description': 'Looks '
                                                                                                         'for '
                                                                                                         'an '
                                                                                                         'enabled '
                                                                                                         'subscription-wide '
                                                                                                         'Activity '
                                                                                                         'Log '
                                                                                                         'alert '
                                                                                                         'covering '
                                                                                                         'public-IP '
                                                                                                         'deletion.'},
                                                                   'remediation_base_sha256': '4a4ed9fcb080f95f49c5d497617aaf42cd21a132121bd9f32e56b2e97b6372e0',
                                                                   'remediation_fields': {'caveats': ['This '
                                                                                                      'checks '
                                                                                                      'the '
                                                                                                      'enabled '
                                                                                                      'alert '
                                                                                                      'declaration, '
                                                                                                      'not '
                                                                                                      'whether '
                                                                                                      'notifications '
                                                                                                      'were '
                                                                                                      'delivered.'],
                                                                                          'steps': ['Create '
                                                                                                    'or '
                                                                                                    'update '
                                                                                                    'the '
                                                                                                    'subscription '
                                                                                                    'alert '
                                                                                                    'for '
                                                                                                    'public-IP '
                                                                                                    'deletion '
                                                                                                    'and '
                                                                                                    'connect '
                                                                                                    'its '
                                                                                                    'notification '
                                                                                                    'action '
                                                                                                    'group.'],
                                                                                          'summary': 'Create '
                                                                                                     'or '
                                                                                                     'update '
                                                                                                     'the '
                                                                                                     'subscription '
                                                                                                     'alert '
                                                                                                     'for '
                                                                                                     'public-IP '
                                                                                                     'deletion '
                                                                                                     'and '
                                                                                                     'connect '
                                                                                                     'its '
                                                                                                     'notification '
                                                                                                     'action '
                                                                                                     'group.'}},
 'azure.claude.activity_log_alert_subscription_public_ip_write': {'description_base_sha256': '8eed6c4dbee40da8e1b0f52f9e958b72155022198a7933eb4199a097dcdac012',
                                                                  'description_fields': {'description': 'Looks '
                                                                                                        'for '
                                                                                                        'an '
                                                                                                        'enabled '
                                                                                                        'subscription-wide '
                                                                                                        'Activity '
                                                                                                        'Log '
                                                                                                        'alert '
                                                                                                        'covering '
                                                                                                        'public-IP '
                                                                                                        'creation '
                                                                                                        'or '
                                                                                                        'updates.'},
                                                                  'remediation_base_sha256': 'e88a5ec464ca720fbb4a3e7840b1a99420f2d83f542768f8982d506e7e3f78b5',
                                                                  'remediation_fields': {'caveats': ['This '
                                                                                                     'checks '
                                                                                                     'the '
                                                                                                     'enabled '
                                                                                                     'alert '
                                                                                                     'declaration, '
                                                                                                     'not '
                                                                                                     'whether '
                                                                                                     'notifications '
                                                                                                     'were '
                                                                                                     'delivered.'],
                                                                                         'steps': ['Create '
                                                                                                   'or '
                                                                                                   'update '
                                                                                                   'the '
                                                                                                   'subscription '
                                                                                                   'alert '
                                                                                                   'for '
                                                                                                   'public-IP '
                                                                                                   'creation '
                                                                                                   'or '
                                                                                                   'updates '
                                                                                                   'and '
                                                                                                   'connect '
                                                                                                   'its '
                                                                                                   'notification '
                                                                                                   'action '
                                                                                                   'group.'],
                                                                                         'summary': 'Create '
                                                                                                    'or '
                                                                                                    'update '
                                                                                                    'the '
                                                                                                    'subscription '
                                                                                                    'alert '
                                                                                                    'for '
                                                                                                    'public-IP '
                                                                                                    'creation '
                                                                                                    'or '
                                                                                                    'updates '
                                                                                                    'and '
                                                                                                    'connect '
                                                                                                    'its '
                                                                                                    'notification '
                                                                                                    'action '
                                                                                                    'group.'}},
 'azure.claude.activity_log_alert_subscription_security_solution_write': {'description_base_sha256': '2a7b71f4db386f6a6d7ee7ac8c3d4093c74c47617716281d2cb22c50bbd465f0',
                                                                          'description_fields': {'description': 'Looks '
                                                                                                                'for '
                                                                                                                'an '
                                                                                                                'enabled '
                                                                                                                'subscription-wide '
                                                                                                                'Activity '
                                                                                                                'Log '
                                                                                                                'alert '
                                                                                                                'covering '
                                                                                                                'security-solution '
                                                                                                                'creation '
                                                                                                                'or '
                                                                                                                'updates.'},
                                                                          'remediation_base_sha256': 'd312d7d854b4309b2e85a5b206ad484bb8327b38032121e0bd855e30bb5b42b4',
                                                                          'remediation_fields': {'caveats': ['This '
                                                                                                             'checks '
                                                                                                             'the '
                                                                                                             'enabled '
                                                                                                             'alert '
                                                                                                             'declaration, '
                                                                                                             'not '
                                                                                                             'whether '
                                                                                                             'notifications '
                                                                                                             'were '
                                                                                                             'delivered.'],
                                                                                                 'steps': ['Create '
                                                                                                           'or '
                                                                                                           'update '
                                                                                                           'the '
                                                                                                           'subscription '
                                                                                                           'alert '
                                                                                                           'for '
                                                                                                           'security-solution '
                                                                                                           'creation '
                                                                                                           'or '
                                                                                                           'updates '
                                                                                                           'and '
                                                                                                           'connect '
                                                                                                           'its '
                                                                                                           'notification '
                                                                                                           'action '
                                                                                                           'group.'],
                                                                                                 'summary': 'Create '
                                                                                                            'or '
                                                                                                            'update '
                                                                                                            'the '
                                                                                                            'subscription '
                                                                                                            'alert '
                                                                                                            'for '
                                                                                                            'security-solution '
                                                                                                            'creation '
                                                                                                            'or '
                                                                                                            'updates '
                                                                                                            'and '
                                                                                                            'connect '
                                                                                                            'its '
                                                                                                            'notification '
                                                                                                            'action '
                                                                                                            'group.'}},
 'azure.claude.activity_log_alert_subscription_sql_firewall_rule_delete': {'description_base_sha256': '4cebd06237112e5dab05c62b69a032b9b7471645c63e3151867534d7726f7ea8',
                                                                           'description_fields': {'description': 'Looks '
                                                                                                                 'for '
                                                                                                                 'an '
                                                                                                                 'enabled '
                                                                                                                 'subscription-wide '
                                                                                                                 'Activity '
                                                                                                                 'Log '
                                                                                                                 'alert '
                                                                                                                 'covering '
                                                                                                                 'SQL '
                                                                                                                 'firewall-rule '
                                                                                                                 'deletion.'},
                                                                           'remediation_base_sha256': '4835317ebbae2b2611c66116726f1531fce72d77fc13d7696a3e83117051b8ec',
                                                                           'remediation_fields': {'caveats': ['This '
                                                                                                              'checks '
                                                                                                              'the '
                                                                                                              'enabled '
                                                                                                              'alert '
                                                                                                              'declaration, '
                                                                                                              'not '
                                                                                                              'whether '
                                                                                                              'notifications '
                                                                                                              'were '
                                                                                                              'delivered.'],
                                                                                                  'steps': ['Create '
                                                                                                            'or '
                                                                                                            'update '
                                                                                                            'the '
                                                                                                            'subscription '
                                                                                                            'alert '
                                                                                                            'for '
                                                                                                            'SQL '
                                                                                                            'firewall-rule '
                                                                                                            'deletion '
                                                                                                            'and '
                                                                                                            'connect '
                                                                                                            'its '
                                                                                                            'notification '
                                                                                                            'action '
                                                                                                            'group.'],
                                                                                                  'summary': 'Create '
                                                                                                             'or '
                                                                                                             'update '
                                                                                                             'the '
                                                                                                             'subscription '
                                                                                                             'alert '
                                                                                                             'for '
                                                                                                             'SQL '
                                                                                                             'firewall-rule '
                                                                                                             'deletion '
                                                                                                             'and '
                                                                                                             'connect '
                                                                                                             'its '
                                                                                                             'notification '
                                                                                                             'action '
                                                                                                             'group.'}},
 'azure.claude.activity_log_alert_subscription_sql_firewall_rule_write': {'description_base_sha256': 'a853b73e9c4c6f6e61b9e87ce5fd6029eb3dcd76e0e6e40b6467bcb7b72c5007',
                                                                          'description_fields': {'description': 'Looks '
                                                                                                                'for '
                                                                                                                'an '
                                                                                                                'enabled '
                                                                                                                'subscription-wide '
                                                                                                                'Activity '
                                                                                                                'Log '
                                                                                                                'alert '
                                                                                                                'covering '
                                                                                                                'SQL '
                                                                                                                'firewall-rule '
                                                                                                                'creation '
                                                                                                                'or '
                                                                                                                'updates.'},
                                                                          'remediation_base_sha256': '1fe57372b11d9933ef631c31baf165778fde7793fea065ee1d1c6c50d5d9224c',
                                                                          'remediation_fields': {'caveats': ['This '
                                                                                                             'checks '
                                                                                                             'the '
                                                                                                             'enabled '
                                                                                                             'alert '
                                                                                                             'declaration, '
                                                                                                             'not '
                                                                                                             'whether '
                                                                                                             'notifications '
                                                                                                             'were '
                                                                                                             'delivered.'],
                                                                                                 'steps': ['Create '
                                                                                                           'or '
                                                                                                           'update '
                                                                                                           'the '
                                                                                                           'subscription '
                                                                                                           'alert '
                                                                                                           'for '
                                                                                                           'SQL '
                                                                                                           'firewall-rule '
                                                                                                           'creation '
                                                                                                           'or '
                                                                                                           'updates '
                                                                                                           'and '
                                                                                                           'connect '
                                                                                                           'its '
                                                                                                           'notification '
                                                                                                           'action '
                                                                                                           'group.'],
                                                                                                 'summary': 'Create '
                                                                                                            'or '
                                                                                                            'update '
                                                                                                            'the '
                                                                                                            'subscription '
                                                                                                            'alert '
                                                                                                            'for '
                                                                                                            'SQL '
                                                                                                            'firewall-rule '
                                                                                                            'creation '
                                                                                                            'or '
                                                                                                            'updates '
                                                                                                            'and '
                                                                                                            'connect '
                                                                                                            'its '
                                                                                                            'notification '
                                                                                                            'action '
                                                                                                            'group.'}},
 'gcp.ports.sql_private_ip_assignments': {'description_base_sha256': 'ad72fe155249850041050504613d61273b9b734cc387afbc76a9e0743f125c83',
                                          'description_fields': {'description': 'Checks for incoming public '
                                                                                'Cloud SQL addresses of type '
                                                                                'PRIMARY or '
                                                                                'MIGRATED_1ST_GEN; OUTGOING '
                                                                                'is an outbound source.'},
                                          'remediation_base_sha256': '889b5eadedd65702d54207a4aef0495f31cfdf6988f9858e29650fe266aad9aa',
                                          'remediation_fields': {'caveats': ['Do not remove OUTGOING '
                                                                             'addresses; they are outbound, '
                                                                             'not ingress. Migrate clients '
                                                                             'before removing public '
                                                                             'incoming addresses. Unknown '
                                                                             'address types remain UNKNOWN; '
                                                                             'this check does not establish '
                                                                             'private connectivity.'],
                                                                 'steps': ['If public access is unnecessary, '
                                                                           'migrate clients to a private '
                                                                           'connection and disable its '
                                                                           'public IP.'],
                                                                 'summary': 'If public access is '
                                                                            'unnecessary, migrate clients to '
                                                                            'a private connection and '
                                                                            'disable its public IP.'}}}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def _apply(check_id, original, kind):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    if not isinstance(original, dict) or _digest(original) != row[kind + "_base_sha256"]:
        raise ValueError("Reviewed finding clarity base changed: " + check_id + " (" + kind + ")")
    updated = deepcopy(original)
    updated.update(deepcopy(row[kind + "_fields"]))
    return updated


def description(check_id, original):
    """Replace only the concise description after validating its reviewed base."""
    return _apply(check_id, original, "description")


def remediation(check_id, original):
    """Replace only summary/actions/cautions after validating their reviewed base."""
    return _apply(check_id, original, "remediation")
