"""Generate a static metadata-audit role policy from verified API/IAM mappings.

No role deployment or live grant occurs. API names are candidates only: explicit
aliases and IAM namespace mappings are validated against a pinned AWS-published
action reference. New operations fail closed until their mapping is reviewed.
"""
from __future__ import annotations
import hashlib
import json
from functools import lru_cache
from pathlib import Path
import sys
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from peaso import deployment

REFERENCE_URL = "https://awspolicygen.s3.amazonaws.com/js/policies.js"
REFERENCE_DATE = "2026-10-10"
REFERENCE_SHA256 = 'f8a0d6de023ec7ce1dbb2e65c88f11424f1f1e4d1ba45332c35b41da61ad36b9'
VERIFIED_ACTIONS = frozenset(('access-analyzer:ListAnalyzers', 'access-analyzer:ListFindings', 'account:GetAlternateContact', 'account:GetContactInformation', 'acm-pca:ListCertificateAuthorities', 'acm:DescribeCertificate', 'acm:ListCertificates', 'amplify:ListApps', 'amplify:ListBackendEnvironments', 'apigateway:GET', 'application-autoscaling:DescribeScalableTargets', 'appstream:DescribeFleets', 'appsync:GetApiCache', 'appsync:ListGraphqlApis', 'athena:GetWorkGroup', 'athena:ListWorkGroups', 'autoscaling:DescribeAutoScalingGroups', 'autoscaling:DescribeLaunchConfigurations', 'backup:DescribeBackupVault', 'backup:DescribeRegionSettings', 'backup:GetBackupPlan', 'backup:GetBackupSelection', 'backup:GetBackupVaultAccessPolicy', 'backup:ListBackupPlans', 'backup:ListBackupSelections', 'backup:ListBackupVaults', 'backup:ListProtectedResources', 'backup:ListRecoveryPointsByBackupVault', 'backup:ListReportPlans', 'batch:DescribeComputeEnvironments', 'bedrock:GetCustomModel', 'bedrock:GetDataSource', 'bedrock:GetGuardrail', 'bedrock:GetModelInvocationLoggingConfiguration', 'bedrock:GetPrompt', 'bedrock:ListAgents', 'bedrock:ListCustomModels', 'bedrock:ListDataSources', 'bedrock:ListGuardrails', 'bedrock:ListKnowledgeBases', 'bedrock:ListPrompts', 'cloudformation:DescribeStacks', 'cloudformation:ListStackInstances', 'cloudformation:ListStackSets', 'cloudfront:GetDistributionConfig', 'cloudfront:ListDistributions', 'cloudfront:ListDistributionsByWebACLId', 'cloudtrail:DescribeTrails', 'cloudtrail:GetEventSelectors', 'cloudtrail:GetInsightSelectors', 'cloudtrail:GetTrailStatus', 'cloudtrail:LookupEvents', 'cloudwatch:DescribeAlarms', 'codeartifact:GetDomainPermissionsPolicy', 'codeartifact:GetRepositoryPermissionsPolicy', 'codeartifact:ListDomains', 'codeartifact:ListPackageVersions', 'codeartifact:ListPackages', 'codeartifact:ListRepositories', 'codebuild:BatchGetBuilds', 'codebuild:BatchGetProjects', 'codebuild:BatchGetReportGroups', 'codebuild:ListBuildsForProject', 'codebuild:ListProjects', 'codebuild:ListReportGroups', 'codebuild:ListSourceCredentials', 'codedeploy:BatchGetDeploymentGroups', 'codedeploy:ListApplications', 'codedeploy:ListDeploymentGroups', 'codepipeline:ListPipelines', 'cognito-identity:DescribeIdentityPool', 'cognito-identity:GetIdentityPoolRoles', 'cognito-identity:ListIdentityPools', 'cognito-idp:DescribeRiskConfiguration', 'cognito-idp:DescribeUserPool', 'cognito-idp:DescribeUserPoolClient', 'cognito-idp:GetUserPoolMfaConfig', 'cognito-idp:GetWebACLForResource', 'cognito-idp:ListGroups', 'cognito-idp:ListIdentityProviders', 'cognito-idp:ListUserPoolClients', 'cognito-idp:ListUserPools', 'config:DescribeAggregationAuthorizations', 'config:DescribeConfigurationAggregators', 'config:DescribeConfigurationRecorderStatus', 'config:DescribeConfigurationRecorders', 'config:DescribeDeliveryChannels', 'connect:DescribeInstanceAttribute', 'connect:ListInstances', 'datasync:DescribeTask', 'datasync:ListTasks', 'dax:DescribeClusters', 'directconnect:DescribeConnections', 'directconnect:DescribeVirtualInterfaces', 'dlm:GetLifecyclePolicies', 'dlm:GetLifecyclePolicy', 'dms:DescribeCertificates', 'dms:DescribeEndpoints', 'dms:DescribeReplicationInstances', 'dms:DescribeReplicationTasks', 'drs:DescribeJobs', 'ds:DescribeDirectories', 'ds:DescribeEventTopics', 'ds:DescribeSharedDirectories', 'ds:GetSnapshotLimits', 'ds:ListCertificates', 'ds:ListLogSubscriptions', 'dynamodb:DescribeContinuousBackups', 'dynamodb:DescribeTable', 'dynamodb:DescribeTableReplicaAutoScaling', 'dynamodb:GetResourcePolicy', 'dynamodb:ListTables', 'dynamodb:ListTagsOfResource', 'ec2:DescribeAddresses', 'ec2:DescribeClientVpnEndpoints', 'ec2:DescribeFlowLogs', 'ec2:DescribeImageAttribute', 'ec2:DescribeImages', 'ec2:DescribeInstanceAttribute', 'ec2:DescribeInstanceConnectEndpoints', 'ec2:DescribeInstances', 'ec2:DescribeInternetGateways', 'ec2:DescribeLaunchTemplateVersions', 'ec2:DescribeLaunchTemplates', 'ec2:DescribeManagedPrefixLists', 'ec2:DescribeNatGateways', 'ec2:DescribeNetworkAcls', 'ec2:DescribeNetworkInterfaces', 'ec2:DescribeRegions', 'ec2:DescribeRouteTables', 'ec2:DescribeSecurityGroups', 'ec2:DescribeSnapshotAttribute', 'ec2:DescribeSnapshots', 'ec2:DescribeSpotFleetRequests', 'ec2:DescribeSubnets', 'ec2:DescribeTransitGatewayAttachments', 'ec2:DescribeTransitGatewayRouteTables', 'ec2:DescribeTransitGateways', 'ec2:DescribeVolumes', 'ec2:DescribeVpcBlockPublicAccessOptions', 'ec2:DescribeVpcEndpointServiceConfigurations', 'ec2:DescribeVpcEndpointServicePermissions', 'ec2:DescribeVpcEndpoints', 'ec2:DescribeVpcPeeringConnections', 'ec2:DescribeVpcs', 'ec2:DescribeVpnConnections', 'ec2:DescribeVpnGateways', 'ec2:GetEbsEncryptionByDefault', 'ec2:GetImageBlockPublicAccessState', 'ec2:GetInstanceMetadataDefaults', 'ec2:GetManagedPrefixListEntries', 'ec2:GetSnapshotBlockPublicAccessState', 'ecr:DescribeImages', 'ecr:DescribePullThroughCacheRules', 'ecr:DescribeRegistry', 'ecr:DescribeRepositories', 'ecr:DescribeRepositoryCreationTemplates', 'ecr:GetLifecyclePolicy', 'ecr:GetRegistryPolicy', 'ecr:GetRegistryScanningConfiguration', 'ecr:GetRepositoryPolicy', 'ecs:DescribeClusters', 'ecs:DescribeContainerInstances', 'ecs:DescribeServices', 'ecs:DescribeTaskDefinition', 'ecs:DescribeTasks', 'ecs:ListAccountSettings', 'ecs:ListClusters', 'ecs:ListContainerInstances', 'ecs:ListServices', 'ecs:ListTaskDefinitions', 'ecs:ListTasks', 'eks:DescribeAccessEntry', 'eks:DescribeAddon', 'eks:DescribeCluster', 'eks:DescribePodIdentityAssociation', 'eks:ListAccessEntries', 'eks:ListAssociatedAccessPolicies', 'eks:ListClusters', 'eks:ListPodIdentityAssociations', 'elasticache:DescribeCacheClusters', 'elasticache:DescribeCacheParameters', 'elasticache:DescribeCacheSubnetGroups', 'elasticache:DescribeReplicationGroups', 'elasticache:DescribeUsers', 'elasticbeanstalk:DescribeConfigurationSettings', 'elasticbeanstalk:DescribeEnvironments', 'elasticfilesystem:DescribeAccessPoints', 'elasticfilesystem:DescribeBackupPolicy', 'elasticfilesystem:DescribeFileSystemPolicy', 'elasticfilesystem:DescribeFileSystems', 'elasticfilesystem:DescribeMountTargets', 'elasticloadbalancing:DescribeListeners', 'elasticloadbalancing:DescribeLoadBalancerAttributes', 'elasticloadbalancing:DescribeLoadBalancers', 'elasticloadbalancing:DescribeRules', 'elasticloadbalancing:DescribeTargetGroups', 'elasticloadbalancing:DescribeTargetHealth', 'elasticmapreduce:DescribeCluster', 'elasticmapreduce:DescribeSecurityConfiguration', 'elasticmapreduce:GetBlockPublicAccessConfiguration', 'elasticmapreduce:ListClusters', 'elasticmapreduce:ListSecurityConfigurations', 'es:DescribeDomain', 'es:DescribeInboundConnections', 'es:DescribeOutboundConnections', 'es:ListDomainNames', 'events:DescribeEventBus', 'events:ListEndpoints', 'events:ListEventBuses', 'firehose:DescribeDeliveryStream', 'firehose:ListDeliveryStreams', 'fms:ListComplianceStatus', 'fms:ListPolicies', 'fsx:DescribeFileSystems', 'glacier:GetVaultAccessPolicy', 'glacier:ListVaults', 'globalaccelerator:ListAccelerators', 'glue:GetConnections', 'glue:GetDataCatalogEncryptionSettings', 'glue:GetDatabases', 'glue:GetDevEndpoints', 'glue:GetJobs', 'glue:GetMLTransforms', 'glue:GetResourcePolicy', 'glue:GetSecurityConfigurations', 'glue:GetTables', 'grafana:ListWorkspaces', 'guardduty:DescribeOrganizationConfiguration', 'guardduty:GetAdministratorAccount', 'guardduty:GetDetector', 'guardduty:GetFindings', 'guardduty:ListDetectors', 'guardduty:ListFindings', 'guardduty:ListMembers', 'guardduty:ListOrganizationAdminAccounts', 'iam:GenerateCredentialReport', 'iam:GenerateServiceLastAccessedDetails', 'iam:GetAccessKeyLastUsed', 'iam:GetAccountAuthorizationDetails', 'iam:GetAccountPasswordPolicy', 'iam:GetAccountSummary', 'iam:GetCredentialReport', 'iam:GetLoginProfile', 'iam:GetOpenIDConnectProvider', 'iam:GetServiceLastAccessedDetails', 'iam:ListAccessKeys', 'iam:ListMFADevices', 'iam:ListOpenIDConnectProviders', 'iam:ListOrganizationsFeatures', 'iam:ListSAMLProviders', 'iam:ListServerCertificates', 'iam:ListServiceSpecificCredentials', 'iam:ListUsers', 'iam:ListVirtualMFADevices', 'identitystore:ListGroups', 'identitystore:ListUsers', 'imagebuilder:GetImageRecipe', 'imagebuilder:ListImagePipelines', 'imagebuilder:ListInfrastructureConfigurations', 'inspector2:BatchGetAccountStatus', 'inspector2:BatchGetFindingDetails', 'inspector2:DescribeOrganizationConfiguration', 'inspector2:GetDelegatedAdminAccount', 'inspector2:ListCoverage', 'inspector2:ListFindings', 'kafka:ListClustersV2', 'kafka:ListKafkaVersions', 'kafkaconnect:ListConnectors', 'kinesis:DescribeStreamSummary', 'kinesis:ListStreams', 'kms:DescribeKey', 'kms:GetKeyPolicy', 'kms:GetKeyRotationStatus', 'kms:ListGrants', 'kms:ListKeys', 'lambda:GetFunctionConcurrency', 'lambda:GetFunctionConfiguration', 'lambda:GetFunctionUrlConfig', 'lambda:GetLayerVersionPolicy', 'lambda:GetPolicy', 'lambda:GetRuntimeManagementConfig', 'lambda:ListAliases', 'lambda:ListEventSourceMappings', 'lambda:ListFunctions', 'lambda:ListLayerVersions', 'lambda:ListLayers', 'lightsail:GetInstances', 'lightsail:GetRelationalDatabases', 'lightsail:GetStaticIps', 'logs:DescribeDeliveries', 'logs:DescribeDeliverySources', 'logs:DescribeLogGroups', 'logs:DescribeMetricFilters', 'logs:DescribeResourcePolicies', 'macie2:DescribeClassificationJob', 'macie2:GetAutomatedDiscoveryConfiguration', 'macie2:GetMacieSession', 'macie2:ListClassificationJobs', 'mediastore:GetContainerPolicy', 'mediastore:ListContainers', 'memorydb:DescribeClusters', 'mq:DescribeBroker', 'mq:ListBrokers', 'network-firewall:DescribeFirewall', 'network-firewall:DescribeFirewallPolicy', 'network-firewall:DescribeLoggingConfiguration', 'network-firewall:DescribeRuleGroup', 'network-firewall:ListFirewallPolicies', 'network-firewall:ListFirewalls', 'network-firewall:ListRuleGroups', 'organizations:DescribeOrganization', 'organizations:DescribePolicy', 'organizations:ListAccounts', 'organizations:ListAccountsForParent', 'organizations:ListDelegatedAdministrators', 'organizations:ListOrganizationalUnitsForParent', 'organizations:ListParents', 'organizations:ListPolicies', 'organizations:ListPoliciesForTarget', 'organizations:ListRoots', 'organizations:ListTargetsForPolicy', 'quicksight:ListUsers', 'ram:GetResourceShareAssociations', 'ram:GetResourceShares', 'rds:DescribeCertificates', 'rds:DescribeDBClusterParameters', 'rds:DescribeDBClusterSnapshotAttributes', 'rds:DescribeDBClusterSnapshots', 'rds:DescribeDBClusters', 'rds:DescribeDBEngineVersions', 'rds:DescribeDBInstances', 'rds:DescribeDBParameters', 'rds:DescribeDBProxies', 'rds:DescribeDBSnapshotAttributes', 'rds:DescribeDBSnapshots', 'rds:DescribeDBSubnetGroups', 'rds:DescribeEventSubscriptions', 'rds:DescribeOptionGroups', 'redshift-serverless:ListNamespaces', 'redshift-serverless:ListWorkgroups', 'redshift:DescribeClusterParameters', 'redshift:DescribeClusterSnapshots', 'redshift:DescribeClusterSubnetGroups', 'redshift:DescribeClusters', 'redshift:DescribeLoggingStatus', 'resource-explorer-2:ListIndexes', 'rolesanywhere:ListProfiles', 'rolesanywhere:ListTrustAnchors', 'route53:GetQueryLoggingConfig', 'route53:ListHealthChecks', 'route53:ListHostedZones', 'route53:ListQueryLoggingConfigs', 'route53:ListResourceRecordSets', 'route53domains:GetDomainDetail', 'route53domains:ListDomains', 's3:GetAccessPoint', 's3:GetAccountPublicAccessBlock', 's3:GetBucketAcl', 's3:GetBucketLocation', 's3:GetBucketLogging', 's3:GetBucketNotification', 's3:GetBucketObjectLockConfiguration', 's3:GetBucketOwnershipControls', 's3:GetBucketPolicy', 's3:GetBucketPolicyStatus', 's3:GetBucketPublicAccessBlock', 's3:GetBucketTagging', 's3:GetBucketVersioning', 's3:GetBucketWebsite', 's3:GetEncryptionConfiguration', 's3:GetLifecycleConfiguration', 's3:GetReplicationConfiguration', 's3:ListAccessPoints', 's3:ListAllMyBuckets', 's3:ListMultiRegionAccessPoints', 's3express:ListAllMyDirectoryBuckets', 'sagemaker:DescribeCluster', 'sagemaker:DescribeDomain', 'sagemaker:DescribeEndpointConfig', 'sagemaker:DescribeModel', 'sagemaker:DescribeNotebookInstance', 'sagemaker:DescribeProcessingJob', 'sagemaker:DescribeTrainingJob', 'sagemaker:DescribeUserProfile', 'sagemaker:ListClusters', 'sagemaker:ListDomains', 'sagemaker:ListEndpointConfigs', 'sagemaker:ListModelPackageGroups', 'sagemaker:ListModelPackages', 'sagemaker:ListModels', 'sagemaker:ListMonitoringSchedules', 'sagemaker:ListNotebookInstances', 'sagemaker:ListProcessingJobs', 'sagemaker:ListTrainingJobs', 'sagemaker:ListUserProfiles', 'schemas:GetResourcePolicy', 'schemas:ListRegistries', 'scn:ListInstances', 'secretsmanager:GetResourcePolicy', 'secretsmanager:ListSecrets', 'securityhub:DescribeHub', 'securityhub:DescribeOrganizationConfiguration', 'securityhub:GetEnabledStandards', 'securityhub:ListEnabledProductsForImport', 'securityhub:ListOrganizationAdminAccounts', 'servicecatalog:DescribeConstraint', 'servicecatalog:DescribePortfolioShares', 'servicecatalog:ListConstraintsForPortfolio', 'servicecatalog:ListPortfolios', 'ses:GetEmailIdentity', 'ses:ListEmailIdentities', 'shield:GetSubscriptionState', 'shield:ListProtections', 'sns:GetTopicAttributes', 'sns:ListSubscriptions', 'sns:ListTopics', 'sqs:GetQueueAttributes', 'sqs:ListQueues', 'ssm-incidents:GetReplicationSet', 'ssm-incidents:ListReplicationSets', 'ssm-incidents:ListResponsePlans', 'ssm:DescribeDocumentPermission', 'ssm:DescribeInstanceInformation', 'ssm:DescribeParameters', 'ssm:GetServiceSetting', 'ssm:ListDocuments', 'ssm:ListResourceComplianceSummaries', 'sso:DescribePermissionSet', 'sso:GetInlinePolicyForPermissionSet', 'sso:GetPermissionsBoundaryForPermissionSet', 'sso:ListAccountAssignments', 'sso:ListAccountsForProvisionedPermissionSet', 'sso:ListInstances', 'sso:ListManagedPoliciesInPermissionSet', 'sso:ListPermissionSets', 'states:DescribeStateMachine', 'states:ListStateMachines', 'storagegateway:DescribeNFSFileShares', 'storagegateway:DescribeSMBFileShares', 'storagegateway:ListFileShares', 'storagegateway:ListGateways', 'support:DescribeSeverityLevels', 'support:DescribeTrustedAdvisorCheckSummaries', 'support:DescribeTrustedAdvisorChecks', 'transfer:DescribeConnector', 'transfer:DescribeServer', 'transfer:ListConnectors', 'transfer:ListServers', 'waf-regional:GetLoggingConfiguration', 'waf-regional:GetRule', 'waf-regional:GetWebACL', 'waf-regional:ListActivatedRulesInRuleGroup', 'waf-regional:ListResourcesForWebACL', 'waf-regional:ListRuleGroups', 'waf-regional:ListRules', 'waf-regional:ListWebACLs', 'waf:GetLoggingConfiguration', 'waf:GetRule', 'waf:GetWebACL', 'waf:ListActivatedRulesInRuleGroup', 'waf:ListRuleGroups', 'waf:ListRules', 'waf:ListWebACLs', 'wafv2:GetLoggingConfiguration', 'wafv2:GetRuleGroup', 'wafv2:GetWebACL', 'wafv2:GetWebACLForResource', 'wafv2:ListResourcesForWebACL', 'wafv2:ListRuleGroups', 'wafv2:ListWebACLs', 'wellarchitected:ListWorkloads', 'workspaces:DescribeWorkspaces'))

# Reviewed metadata-only reads: IAM ListPolicies and EMR ListInstances.
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {"iam:ListPolicies", "iam:GetPolicyVersion", "elasticmapreduce:ListInstances"}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {"amplify:ListBranches"}
WELLARCHITECTED_SHARE_READS = frozenset({
    "wellarchitected:ListLenses", "wellarchitected:ListLensShares",
    "wellarchitected:ListProfiles", "wellarchitected:ListProfileShares",
    "wellarchitected:ListReviewTemplates", "wellarchitected:ListTemplateShares",
    "wellarchitected:ListWorkloadShares",
})
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_wellarchitected.html
VERIFIED_ACTIONS = VERIFIED_ACTIONS | WELLARCHITECTED_SHARE_READS
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {"mediapackage:ListOriginEndpoints", "mediatailor:ListPlaybackConfigurations"}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {"quicksight:ListDashboards", "quicksight:DescribeDashboardPermissions", "quicksight:DescribeAccountSettings"}
# The Grafana workspace list is followed by a workspace-scoped, metadata-only
# service-account list. It exposes role and disabled state, never token values.
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_grafana.html
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {"grafana:ListWorkspaceServiceAccounts"}
# Exact queue-to-role binding for the Deadline Cloud privilege-escalation map.
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_deadline.html
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {"deadline:ListQueues", "deadline:GetQueue", "deadline:ListWorkers"}
# Studio space inventory reads the existing space and its execution-role owner.
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_sagemaker.html
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {"sagemaker:ListSpaces", "sagemaker:DescribeSpace"}
# Current collector reads verified against the AWS service authorization references:
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_elb.html
# https://docs.aws.amazon.com/macie/latest/user/security_iam_id-based-policy-examples.html
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {
    "elasticloadbalancing:DescribeLoadBalancerPolicies",
    "macie2:GetFindings",
    "macie2:ListFindings",
}
# Exact metadata-only mappings for the native bulk inventory extension.
BULK_METADATA_REFERENCES = {
    'ce:GetAnomalyMonitors': 'https://docs.aws.amazon.com/cost-management/latest/userguide/billing-permissions-ref.html',
    'ce:GetAnomalySubscriptions': 'https://docs.aws.amazon.com/cost-management/latest/userguide/billing-permissions-ref.html',
    'backup:ListRestoreJobs': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_backup.html',
    'backup:ListRestoreTestingPlans': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_backup.html',
    'backup:ListRestoreTestingSelections': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_backup.html',
    'organizations:ListAWSServiceAccessForOrganization': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_organizations.html',
    'route53resolver:ListFirewallRuleGroupAssociations': REFERENCE_URL,
    'route53resolver:ListFirewallRules': REFERENCE_URL,
    'route53resolver:ListFirewallRuleGroups': REFERENCE_URL,
    'route53resolver:ListResolverQueryLogConfigs': REFERENCE_URL,
    'route53resolver:ListResolverQueryLogConfigAssociations': REFERENCE_URL,
    'logs:DescribeSubscriptionFilters': REFERENCE_URL,
    'logs:DescribeDestinations': REFERENCE_URL,
    'ec2:DescribeInstanceTypes': REFERENCE_URL,
    'eks:DescribeClusterVersions': REFERENCE_URL,
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(BULK_METADATA_REFERENCES)
WAF_IP_SET_REFERENCE_SHA256 = '0e24619d9b2d738a072c129d20668ad3e25fe3b76ab0793adae3820f981cbfaa'
WAF_IP_SET_ACTIONS = frozenset({'wafv2:ListIPSets', 'wafv2:GetIPSet'})
VERIFIED_ACTIONS = VERIFIED_ACTIONS | WAF_IP_SET_ACTIONS
NETWORK_SERVICE_READ_REFERENCES = {
    'cloudhsm:DescribeClusters': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudhsm.html',
    **dict.fromkeys({'ec2:DescribeVerifiedAccessEndpoints', 'ec2:DescribeVerifiedAccessGroups', 'ec2:DescribeVerifiedAccessInstances'},
        'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVerifiedAccessEndpoints.html'),
    'elasticbeanstalk:DescribeConfigurationSettings': 'https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeConfigurationSettings.html',
    **dict.fromkeys({'lightsail:GetLoadBalancers', 'lightsail:GetContainerServices'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_lightsail.html'),
    **dict.fromkeys({'vpc-lattice:ListTargetGroups', 'vpc-lattice:GetTargetGroup', 'vpc-lattice:ListTargets',
        'vpc-lattice:ListResourceConfigurations', 'vpc-lattice:GetResourceConfiguration', 'vpc-lattice:ListServiceNetworkResourceAssociations',
        'vpc-lattice:ListListeners', 'vpc-lattice:GetListener', 'vpc-lattice:ListRules', 'vpc-lattice:GetRule'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_vpc-lattice.html'),
    'route53:GetHostedZone': 'https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetHostedZone.html',
    'quicksight:ListVPCConnections': 'https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ListVPCConnections.html',
    **dict.fromkeys({'timestream-influxdb:ListDbInstances', 'timestream-influxdb:GetDbInstance',
                     'timestream-influxdb:ListDbClusters', 'timestream-influxdb:GetDbCluster'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_timestream-influxdb.html'),
    **dict.fromkeys({'osis:ListPipelines', 'osis:GetPipeline'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_osis.html'),
    **dict.fromkeys({'eks:ListNodegroups', 'eks:DescribeNodegroup', 'eks:ListFargateProfiles', 'eks:DescribeFargateProfile'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html'),
    'datasync:ListAgents': 'https://docs.aws.amazon.com/datasync/latest/apireference/API_ListAgents.html',
    'datasync:DescribeAgent': 'https://docs.aws.amazon.com/datasync/latest/apireference/API_DescribeAgent.html',
    'storagegateway:DescribeGatewayInformation': 'https://docs.aws.amazon.com/storagegateway/latest/APIReference/API_DescribeGatewayInformation.html',
    'cloudfront:ListVpcOrigins': 'https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListVpcOrigins.html',
    'cloudfront:GetVpcOrigin': 'https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetVpcOrigin.html',
    'elasticfilesystem:DescribeMountTargetSecurityGroups': 'https://docs.aws.amazon.com/efs/latest/ug/API_DescribeMountTargetSecurityGroups.html',
    'ec2:DescribeNetworkInterfaceAttribute': 'https://docs.aws.amazon.com/efs/latest/APIReference/API_DescribeMountTargetSecurityGroups.html',
    'memorydb:DescribeSubnetGroups': 'https://docs.aws.amazon.com/memorydb/latest/APIReference/API_DescribeSubnetGroups.html',
    **dict.fromkeys({'apprunner:ListServices', 'apprunner:DescribeService', 'apprunner:ListVpcConnectors',
        'apprunner:ListVpcIngressConnections', 'apprunner:DescribeVpcIngressConnection'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_apprunner.html'),
    **dict.fromkeys({'route53resolver:ListResolverEndpoints', 'route53resolver:ListResolverEndpointIpAddresses',
        'route53resolver:ListResolverRuleAssociations'}, 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_route53resolver.html'),
    **dict.fromkeys({'directconnect:DescribeDirectConnectGateways', 'directconnect:DescribeDirectConnectGatewayAssociations'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_directconnect.html'),
    **dict.fromkeys({'globalaccelerator:ListListeners', 'globalaccelerator:ListEndpointGroups'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_globalaccelerator.html'),
    'dax:DescribeSubnetGroups': 'https://docs.aws.amazon.com/dax/latest/APIReference/API_DescribeSubnetGroups.html',
    'ec2:DescribeCustomerGateways': 'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeCustomerGateways.html',
    'grafana:DescribeWorkspace': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_grafana.html',
    'elasticache:DescribeServerlessCaches': 'https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeServerlessCaches.html',
    **dict.fromkeys({'emr-serverless:GetApplication', 'emr-serverless:ListApplications'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_emr-serverless.html'),
    **dict.fromkeys({'aoss:ListVpcEndpoints', 'aoss:BatchGetVpcEndpoint'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_opensearchserverless.html'),
    **dict.fromkeys({'vpc-lattice:ListResourceGateways', 'vpc-lattice:GetResourceGateway', 'vpc-lattice:ListServiceNetworks',
        'vpc-lattice:ListServices', 'vpc-lattice:ListServiceNetworkVpcAssociations', 'vpc-lattice:GetServiceNetworkVpcAssociation',
        'vpc-lattice:ListServiceNetworkServiceAssociations'}, 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_vpc-lattice.html'),
}
_NATIVE_NETWORK_IAM = json.loads((Path(__file__).resolve().parents[1] / 'peaso/collectors/aws_network_inventory_iam.json').read_text())
NETWORK_SERVICE_READ_REFERENCES.update({action: row['source'] for action, row in _NATIVE_NETWORK_IAM['actions'].items()})
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(NETWORK_SERVICE_READ_REFERENCES)
INLINE_SECURITY_IR_READS = frozenset({
    ('security-ir', 'get_case'), ('security-ir', 'get_membership'),
    ('security-ir', 'list_cases'), ('security-ir', 'list_memberships'),
})
# AWS EC2 service authorization lists both as route-table metadata reads.
# SearchTransitGatewayRoutes is an exact read-only exception to the usual
# Get/List/Describe operation-name rule.
TRANSIT_GATEWAY_ROUTE_READ_ACTIONS = frozenset({
    'ec2:DescribeTransitGatewayVpcAttachments',
    'ec2:GetTransitGatewayRouteTableAssociations', 'ec2:SearchTransitGatewayRoutes'})
# GetAnalyzer returns the unused-access window and exclusions omitted by ListAnalyzers.
ACCESS_ANALYZER_CONFIGURATION_REFERENCE = {
    "access-analyzer:GetAnalyzer": "https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_GetAnalyzer.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | TRANSIT_GATEWAY_ROUTE_READ_ACTIONS | frozenset({"access-analyzer:GetFinding"}) | frozenset(ACCESS_ANALYZER_CONFIGURATION_REFERENCE)
NATIVE_BATCH_REFERENCE_SHA256 = '72e537c6b0c83b43f1c818b7d7b8db0e434dd54c304352b35875f2c46376d7c2'
NATIVE_BATCH_ACTIONS = frozenset({'organizations:DescribeResourcePolicy', 'cloudwatch:ListMetrics'})
VERIFIED_ACTIONS = VERIFIED_ACTIONS | NATIVE_BATCH_ACTIONS
IDENTITY_CENTER_REFERENCE_SHA256 = '72e537c6b0c83b43f1c818b7d7b8db0e434dd54c304352b35875f2c46376d7c2'
IDENTITY_CENTER_ACTIONS = frozenset({'identitystore:DescribeUser', 'identitystore:ListGroupMemberships'})
VERIFIED_ACTIONS = VERIFIED_ACTIONS | IDENTITY_CENTER_ACTIONS
SPRINT_METADATA_REFERENCE_SHA256 = '1074cf47af183b9f4920ff4237a38132ccc33afd6d564c428ab873b9a255b8c4'
# Four separately reviewed metadata reads needed by already collected native facts.
# The published action reference and normal SDK/IAM-name validation still apply.
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset({
    # Present in the already published 7e customer-role template; keep it on regeneration.
    "cloudformation:ListStacks",
    "drs:DescribeSourceServers",
    "kafka:GetCompatibleKafkaVersions",
    "ecr:DescribeImageScanFindings",
    "rds:DescribeOrderableDBInstanceOptions",
    # Immutable 25b and 9254 customer-role versions add only these reviewed
    # configuration reads; keep regeneration aligned with their exact grants.
    "backup:GetBackupVaultNotifications",
    "batch:DescribeJobDefinitions",
    "codepipeline:GetPipeline",
    "ec2:DescribeClientVpnAuthorizationRules",
    "ecr-public:DescribeRepositories",
    "kafka:DescribeClusterV2",
    "kms:DescribeCustomKeyStores",
    "kms:ListResourceTags",
    "lambda:GetCodeSigningConfig",
    "lambda:GetFunctionCodeSigningConfig",
    "lightsail:GetBuckets",
    "route53:GetDNSSEC",
    "route53:GetHealthCheck",
    "securityhub:GetFindings",
    "shield:DescribeProtection",
    "detective:ListGraphs",
    "ec2:DescribeDhcpOptions",
    "events:ListRules",
    "events:ListTargetsByRule",
    "shield:DescribeDRTAccess",
    "ssm:ListComplianceItems",
    "ssm:ListInventoryEntries",
})
# This one post-9254 collector operation has an exact AWS API/IAM mapping.
# Keep the source and action adjacent so future additions cannot piggyback on
# a generic SDK title-case conversion or silently alter the signed role.
ASSOCIATION_REFERENCE = (
    "ec2:DescribeIamInstanceProfileAssociations",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html",
)
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset({ASSOCIATION_REFERENCE[0]})
SECRET_METADATA_REFERENCE = (
    "secretsmanager:DescribeSecret",
    "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html",
)
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset({SECRET_METADATA_REFERENCE[0]})
IAM_ROLE_POLICY_METADATA_REFERENCES = {
    "iam:GetPolicy": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html",
    "iam:GetRolePolicy": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRolePolicy.html",
    "iam:ListAttachedRolePolicies": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedRolePolicies.html",
    "iam:ListRolePolicies": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRolePolicies.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(IAM_ROLE_POLICY_METADATA_REFERENCES)
# Enclave applicability uses aliases as configuration metadata; no cryptographic
# operation or key material is exposed by this read.
KMS_ALIAS_METADATA_REFERENCE = (
    "kms:ListAliases", "https://docs.aws.amazon.com/kms/latest/APIReference/API_ListAliases.html")
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {KMS_ALIAS_METADATA_REFERENCE[0]}
BEDROCK_DRAFT_ROLE_METADATA_REFERENCE = (
    "bedrock:GetAgent", "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_GetAgent.html")
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {BEDROCK_DRAFT_ROLE_METADATA_REFERENCE[0]}
S3_ACL_SAMPLE_METADATA_REFERENCES = {
    "s3:ListBucket": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html",
    "s3:GetObjectAcl": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(S3_ACL_SAMPLE_METADATA_REFERENCES)
CONFIGURATION_PAYLOAD_READ_REFERENCES = {
    "ssm:GetDocument": "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetDocument.html",
    "sagemaker:DescribeNotebookInstanceLifecycleConfig": "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeNotebookInstanceLifecycleConfig.html",
    "datapipeline:ListPipelines": "https://docs.aws.amazon.com/datapipeline/latest/APIReference/API_ListPipelines.html",
    "datapipeline:GetPipelineDefinition": "https://docs.aws.amazon.com/datapipeline/latest/APIReference/API_GetPipelineDefinition.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(CONFIGURATION_PAYLOAD_READ_REFERENCES)
LAUNCH_TEMPLATE_INSTANCE_READ_REFERENCES = {
    "ec2:GetLaunchTemplateData": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetLaunchTemplateData.html",
    "ec2:DescribeSpotInstanceRequests": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetLaunchTemplateData.html",
    "ec2:DescribeInstanceCreditSpecifications": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetLaunchTemplateData.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(LAUNCH_TEMPLATE_INSTANCE_READ_REFERENCES)
CLOCK_METRIC_READ_REFERENCE = (
    "cloudwatch:GetMetricStatistics", "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricStatistics.html")
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {CLOCK_METRIC_READ_REFERENCE[0]}
BEANSTALK_RUNTIME_READ_REFERENCE = (
    "elasticbeanstalk:DescribeEnvironmentResources",
    "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeEnvironmentResources.html")
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {BEANSTALK_RUNTIME_READ_REFERENCE[0]}
PROJECTED_CONFIGURATION_OPERATIONS = frozenset({("ssm", "get_document")})
# Exact read-only native Budgets API/IAM mapping; no execution grant.
BUDGET_STOP_REFERENCE = (
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_budgets.html",
    ("budgets:DescribeBudgetActionsForAccount", "budgets:DescribeBudgetAction"),
)
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(BUDGET_STOP_REFERENCE[1])
# Resolver metadata read, reviewed against the service authorization reference.
RESOLVER_METADATA_REFERENCE = ('https://docs.aws.amazon.com/service-authorization/latest/reference/list_route53resolver.html', 'route53resolver:ListFirewallDomainLists')
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {RESOLVER_METADATA_REFERENCE[1]}
SAGEMAKER_CLARIFY_REFERENCE = ("https://docs.aws.amazon.com/service-authorization/latest/reference/list_sagemaker.html", frozenset({"sagemaker:ListEndpoints", "sagemaker:DescribeEndpoint", "sagemaker:ListMonitoringExecutions"}))
VERIFIED_ACTIONS = VERIFIED_ACTIONS | SAGEMAKER_CLARIFY_REFERENCE[1]
# Read-only actions for native Organizations/tag controls, reviewed against the
# service authorization references. This does not authorize tag/report writes.
ORGANIZATION_TAG_METADATA_REFERENCES = {
    'tag:GetResources': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_resourcegroupstaggingapi.html',
    'organizations:DescribeEffectivePolicy': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_organizations.html',
    'organizations:DescribeOrganizationalUnit': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_organizations.html',
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(ORGANIZATION_TAG_METADATA_REFERENCES)
# Configuration metadata for published Bedrock agent/guardrail associations.
# Runtime invocation, workflow creation and policy writes are not granted.
BEDROCK_REASONING_METADATA_REFERENCES = {
    'bedrock:ListAgentAliases': 'https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-agent.html',
    'bedrock:GetAgentAlias': 'https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-agent.html',
    'bedrock:GetAgentVersion': 'https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-agent.html',
    'bedrock:GetAutomatedReasoningPolicy': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock.html',
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(BEDROCK_REASONING_METADATA_REFERENCES)
# Exact native incident-history read; no workflow mutation permission.
SECURITYHUB_HISTORY_METADATA_REFERENCE = (
    'securityhub:GetFindingHistory',
    'https://docs.aws.amazon.com/service-authorization/latest/reference/list_securityhub.html',
)
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {SECURITYHUB_HISTORY_METADATA_REFERENCE[0]}
# Source53's observed cloudformation_stack denial required ListStacks in the
# published 7e template, but the collector's direct READ_ACTIONS tuple is
# DescribeStacks. Keep that certified supplemental read during regeneration.
PRESERVED_TEMPLATE_READ_ACTIONS = frozenset({("cloudformation", "list_stacks")})
# The currently pinned botocore model has no eventbridgev2 client. The collector
# declares this read so unsupported inventory stays explicit, but no IAM action
# can make the unavailable SDK request run. Revisit when the runtime ships it.
UNAVAILABLE_SDK_METADATA_OPERATIONS = frozenset({("eventbridgev2", "list_event_buses")})
SERVICE_PREFIXES = {'elbv2': 'elasticloadbalancing', 'elb': 'elasticloadbalancing', 'docdb': 'rds', 'neptune': 'rds', 'opensearch': 'es', 's3control': 's3', 'efs': 'elasticfilesystem', 'apigatewayv2': 'apigateway', 'sso-admin': 'sso', 'accessanalyzer': 'access-analyzer', 'emr': 'elasticmapreduce', 'bedrock-agent': 'bedrock', 'sesv2': 'ses', 'stepfunctions': 'states', 'supplychain': 'scn', 'eventbridgev2': 'events'}
SERVICE_PREFIXES['resourcegroupstaggingapi'] = 'tag'
SERVICE_PREFIXES['opensearchserverless'] = 'aoss'
SERVICE_PREFIXES['cloudhsmv2'] = 'cloudhsm'
SERVICE_PREFIXES.update(_NATIVE_NETWORK_IAM['prefixes'])
ACTION_ALIASES = {('s3', 'list_buckets'): 's3:ListAllMyBuckets', ('s3', 'get_public_access_block'): 's3:GetBucketPublicAccessBlock', ('s3', 'get_bucket_encryption'): 's3:GetEncryptionConfiguration', ('s3control', 'get_public_access_block'): 's3:GetAccountPublicAccessBlock', ('s3', 'get_bucket_lifecycle_configuration'): 's3:GetLifecycleConfiguration', ('s3', 'get_object_lock_configuration'): 's3:GetBucketObjectLockConfiguration', ('s3', 'get_bucket_notification_configuration'): 's3:GetBucketNotification', ('s3', 'get_bucket_replication'): 's3:GetReplicationConfiguration', ('s3', 'list_directory_buckets'): 's3express:ListAllMyDirectoryBuckets', ('accessanalyzer', 'list_findings_v2'): 'access-analyzer:ListFindings', ('accessanalyzer', 'get_finding_v2'): 'access-analyzer:GetFinding'}
ACTION_ALIASES[('lambda-microvms', 'list_microvm_images')] = 'lambda:ListMicrovmImages'

# S3Control's Outposts list uses a distinct IAM service namespace.
ACTION_ALIASES[('s3', 'list_objects_v2')] = 's3:ListBucket'
ACTION_ALIASES[('s3control', 'list_regional_buckets')] = 's3-outposts:ListRegionalBuckets'

GATEWAY_PATHS = {
    ("apigatewayv2", "get_integrations"): ("/apis/*/integrations",),
    ("apigatewayv2", "get_api_mappings"): ("/domainnames/*/apimappings",),
    ("apigatewayv2", "get_domain_names"): ("/domainnames",),
    ("apigateway", "get_vpc_links"): ("/vpclinks",),
    ("apigatewayv2", "get_vpc_links"): ("/vpclinks",),
    ("apigateway", "get_rest_apis"): ("/restapis",),
    ("apigateway", "get_stages"): ("/restapis/*/stages",),
    ("apigatewayv2", "get_apis"): ("/apis",),
    ("apigatewayv2", "get_stages"): ("/apis/*/stages",),
    ("apigateway", "get_domain_names"): ("/domainnames",),
    ("apigateway", "get_base_path_mappings"): ("/domainnames/*/basepathmappings",),
    ("apigateway", "get_resources"): ("/restapis/*/resources",),
    ("apigateway", "get_authorizers"): ("/restapis/*/authorizers",),
    ("apigatewayv2", "get_routes"): ("/apis/*/routes",),
    ("apigatewayv2", "get_authorizers"): ("/apis/*/authorizers",),
    ("apigateway", "get_client_certificate"): ("/clientcertificates/*",),
    ("apigateway", "get_deployment"): ("/restapis/*/deployments/*",),
    # ExportApi is an HTTP GET on this exact OAS30 resource. The collector
    # pins a stage and projects route authorization before caching the result.
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/arn-format-reference.html
    ("apigatewayv2", "export_api"): ("/apis/*/exports/OAS30",),
}
# Reviewed companion permissions AWS documents for one SDK call (reference-verified like any action).
DEPENDENT_ACTIONS = {("wafv2", "get_web_acl_for_resource"): ("cognito-idp:GetWebACLForResource",)}
DEPENDENT_ACTIONS[("efs", "describe_mount_target_security_groups")] = ("ec2:DescribeNetworkInterfaceAttribute",)
DEPENDENT_ACTIONS[("ec2", "get_launch_template_data")] = (
    "ec2:DescribeSpotInstanceRequests", "ec2:DescribeInstanceCreditSpecifications",
    "ec2:DescribeVolumes", "ec2:DescribeInstanceAttribute")

FORBIDDEN_OPERATIONS = frozenset({
    "get_secret_value", "batch_get_secret_value", "get_parameter", "get_parameters", "get_parameters_by_path",
    "get_password_data", "get_object", "get_log_events", "filter_log_events", "get_function",
    "get_api_key", "get_api_keys", "list_api_keys", "get_authorization_token", "get_login",
    "export_certificate", "get_document", "download_db_log_file_portion", "get_records", "get_shard_iterator",
})
# This collector operation can return a key value. It remains declared for
# collection coverage, but the published 9254 role intentionally grants no IAM
# action for it; generation must not broaden the role to retrieve credentials.
UNGRANTED_CREDENTIAL_OPERATIONS = frozenset({("lightsail", "get_bucket_access_keys")})
# Explicit opt-in artifact content reads require a separate repository-scoped
# companion grant; never add them to the default metadata-only customer role.
UNGRANTED_CONTENT_OPERATIONS = frozenset({('ecr','list_image_referrers'),
    ('ecr','batch_get_image'),('ecr','get_download_url_for_layer'),
    # Selected image provenance reads use separate customer authorization.
    ('ecr-public','describe_images'),('ecr-public','describe_registries'),
    ('lambda','get_function'),('lambda','get_layer_version'),
    ('codecommit','get_repository'),('codecommit','get_branch'),('codecommit','get_folder'),
    ('codecommit','get_file'),('logs','filter_log_events')})
ECR_CONTENT_IAM_ACTIONS = frozenset({'ecr:BatchGetImage','ecr:GetDownloadUrlForLayer'})
VERIFIED_ACTIONS = VERIFIED_ACTIONS | ECR_CONTENT_IAM_ACTIONS
ACTION_ALIASES[('ecr','list_image_referrers')] = 'ecr:BatchGetImage'

# These newly declared calls are reachable only in the explicitly selected
# content profile. Their IAM mappings are reviewed, but they never broaden the
# generated default metadata role.
OPTIONAL_CONFIGURATION_READ_REFERENCES = {
    ('cloudformation', 'get_template'): ('cloudformation:GetTemplate', 'https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_GetTemplate.html'),
    ('amplify', 'get_app'): ('amplify:GetApp', 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_amplify.html'),
    ('apigateway', 'get_stage'): ('apigateway:GET', 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_apigateway.html'),
    ('glue', 'get_job'): ('glue:GetJob', 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_glue.html'),
    ('glue', 'get_connection'): ('glue:GetConnection', 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_glue.html'),
    ('ssm', 'describe_document'): ('ssm:DescribeDocument', 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_ssm.html'),
}
UNGRANTED_CONTENT_OPERATIONS = UNGRANTED_CONTENT_OPERATIONS | frozenset(OPTIONAL_CONFIGURATION_READ_REFERENCES)
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(row[0] for row in OPTIONAL_CONFIGURATION_READ_REFERENCES.values())
GATEWAY_PATHS[('apigateway', 'get_stage')] = ('/restapis/*/stages/*',)

# S3 source reads are opt-in only. Version access is a permission on GetObject,
# not a fictitious get_object_version SDK operation. Never grant these by default.
OPTIONAL_S3_SOURCE_READ_REFERENCES = {
    ('s3', 'head_object'): ('s3:GetObject', 'https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html'),
    ('s3', 'get_object'): ('s3:GetObject', 'https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html'),
}
OPTIONAL_S3_SOURCE_VERSION_PERMISSION = ('s3:GetObjectVersion', 'https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html')
ACTION_ALIASES.update({key: row[0] for key, row in OPTIONAL_S3_SOURCE_READ_REFERENCES.items()})
UNGRANTED_CONTENT_OPERATIONS = UNGRANTED_CONTENT_OPERATIONS | frozenset(OPTIONAL_S3_SOURCE_READ_REFERENCES)
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(row[0] for row in OPTIONAL_S3_SOURCE_READ_REFERENCES.values()) | {OPTIONAL_S3_SOURCE_VERSION_PERMISSION[0]}


# Exact metadata-only grants reviewed against the AWS programmatic policy
# reference. Keep the receipt alongside the finite discovery recipes.
RESOURCE_POLICY_REFERENCE = json.loads((Path(__file__).resolve().parents[1] /
    "peaso/collectors/aws_resource_policy_permissions.json").read_text())
for _pair, _action in RESOURCE_POLICY_REFERENCE["mappings"].items():
    ACTION_ALIASES[tuple(_pair.split("/", 1))] = _action
for _pair, _actions in RESOURCE_POLICY_REFERENCE["additional_actions"].items():
    DEPENDENT_ACTIONS[tuple(_pair.split("/", 1))] = tuple(_actions)
VERIFIED_ACTIONS = VERIFIED_ACTIONS | set(RESOURCE_POLICY_REFERENCE["mappings"].values()) | {
    action for actions in RESOURCE_POLICY_REFERENCE["additional_actions"].values() for action in actions}

IAM_INLINE_ROLE_LIMIT = 10240
IAM_MANAGED_POLICY_LIMIT = 6144
IAM_MANAGED_POLICIES_PER_ROLE = 10  # default IAM quota for attached managed policies
MANAGED_POLICY_PREFIX = "CspmConfigurationReadOnly"
REVIEWED_ROLE_SHA256 = "0ce4fa48e6c0e625520303644e4f7c465772a4dec90d0fa8f46b07726a2f7e5a"
REVIEWED_ROLE_PATH = Path(__file__).resolve().parents[1] / "infra/aws" / "customer-policy-allocation.json"
EVIDENCE_OPERATION = ("iam", "generate_credential_report")
# AWS service authorization explicitly classifies these report APIs as Read.
# They create report results, not IAM configuration or credentials.
IAM_REPORT_READ_REFERENCES = {
    "iam:GenerateCredentialReport": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html",
    "iam:GenerateServiceLastAccessedDetails": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(IAM_REPORT_READ_REFERENCES)
# Reviewed non-Get/List names that only read or create an access-report job; both are in
# the AWS managed SecurityAudit policy (iam:GenerateServiceLastAccessedDetails explicitly).
READ_OPERATION_EXCEPTIONS = frozenset({("cloudtrail", "lookup_events"), ("iam", "generate_service_last_accessed_details"),
    ("iam", "simulate_principal_policy"), ("ec2", "search_transit_gateway_routes"),
    ("braket", "search_devices"), ("apigatewayv2", "export_api")})
VERIFIED_ACTIONS = VERIFIED_ACTIONS | {"apigateway:ListPortals"}
ACTION_ALIASES[("apigatewayv2", "list_portals")] = "apigateway:ListPortals"
for _operation in ("describe_budgets", "describe_notifications_for_budget",
                   "describe_subscribers_for_notification"):
    # AWS maps these three read APIs to ViewBudget, not their SDK names.
    ACTION_ALIASES[("budgets", _operation)] = "budgets:ViewBudget"
    DEPENDENT_ACTIONS[("budgets", _operation)] = ("aws-portal:ViewBilling",)
ACTION_ALIASES[("backupsearch", "get_search_result_export_job")] = "backup-search:GetSearchResultExportJob"
ACTION_ALIASES[("backupsearch", "list_search_result_export_jobs")] = "backup-search:ListSearchResultExportJobs"
# Reviewed exact read actions for the combined Exposure inventory. Each action is
# tied to the AWS Service Authorization Reference; no action wildcard is admitted.
BIG_WAVE_EXPOSURE_READ_REFERENCES = {
    'appconfig:GetConfigurationProfile': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appconfig.html',
    'appconfig:GetExtension': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appconfig.html',
    'appconfig:GetExtensionAssociation': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appconfig.html',
    'appconfig:ListApplications': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appconfig.html',
    'appconfig:ListConfigurationProfiles': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appconfig.html',
    'appconfig:ListExtensionAssociations': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appconfig.html',
    'appflow:DescribeFlow': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appflow.html',
    'appflow:ListFlows': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appflow.html',
    'athena:BatchGetQueryExecution': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_athena.html',
    'athena:ListQueryExecutions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_athena.html',
    'auditmanager:GetAssessment': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_auditmanager.html',
    'auditmanager:GetSettings': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_auditmanager.html',
    'auditmanager:ListAssessments': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_auditmanager.html',
    'autoscaling:DescribeLifecycleHooks': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_autoscaling.html',
    'autoscaling:DescribeNotificationConfigurations': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_autoscaling.html',
    'aws-portal:ViewBilling': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_aws-portal.html',
    'backup-search:GetSearchResultExportJob': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_backupsearch.html',
    'backup-search:ListSearchResultExportJobs': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_backupsearch.html',
    'bedrock-agentcore:GetGateway': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock-agentcore.html',
    'budgets:ViewBudget': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_budgets.html',
    'cloudsearch:DescribeDomainEndpointOptions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudsearch.html',
    'cloudtrail:DescribeQuery': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudtrail.html',
    'cloudtrail:ListQueries': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudtrail.html',
    'codepipeline:ListWebhooks': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_codepipeline.html',
    'codestar-notifications:DescribeNotificationRule': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_codestar-notifications.html',
    'codestar-notifications:ListNotificationRules': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_codestar-notifications.html',
    'cognito-idp:DescribeUserPoolDomain': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cognito-idp.html',
    'config:DescribeConfigRules': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html',
    'config:DescribeConformancePacks': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html',
    'config:DescribeOrganizationConfigRules': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html',
    'config:DescribeOrganizationConformancePacks': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html',
    'ds:DescribeTrusts': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_ds.html',
    'dsql:GetCluster': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_dsql.html',
    'elasticfilesystem:DescribeReplicationConfigurations': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_efs.html',
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(BIG_WAVE_EXPOSURE_READ_REFERENCES)



@lru_cache(maxsize=256)
def _sdk_operation_names(service):
    # The pinned botocore build does not publish a FinSpace client, but the
    # published customer template already carries these three read grants.
    # Keep their exact AWS-authorized names while preserving the template on
    # regeneration; this is not a fallback for arbitrary unavailable clients.
    if service == 'finspace':
        return {
            'get_kx_cluster': 'GetKxCluster',
            'list_kx_clusters': 'ListKxClusters',
            'list_kx_environments': 'ListKxEnvironments',
        }
    # The pinned botocore predates the Custom Event Bus client. These three
    # exact read operations are published by the EventBridgeV2 API and map to
    # the EventBridge `events:` IAM namespace. No other operation is admitted.
    if service == 'eventbridgev2':
        return {
            'get_resource_policy': 'GetResourcePolicy',
            'list_resource_policies': 'ListResourcePolicies',
            'list_subscribers': 'ListSubscribers',
        }
    import botocore.session
    from botocore import xform_name
    model = botocore.session.get_session().get_service_model(service)
    return {xform_name(name): name for name in model.operation_names}


def iam_action(service, operation):
    """Resolve only a reviewed metadata API; never derive an unverified grant."""
    if (service, operation) in UNGRANTED_CREDENTIAL_OPERATIONS:
        raise ValueError("Credential API prohibited: " + service + "/" + operation)
    if (operation in FORBIDDEN_OPERATIONS and (service, operation) not in PROJECTED_CONFIGURATION_OPERATIONS
            and (service, operation) not in OPTIONAL_S3_SOURCE_READ_REFERENCES):
        raise ValueError("Value/content/credential API prohibited: " + service + "/" + operation)
    if (service, operation) == EVIDENCE_OPERATION:
        return "iam:GenerateCredentialReport"
    if service == "sts":
        if operation in {"get_caller_identity", "assume_role"}:
            return None
        raise ValueError("Unreviewed STS operation")
    if (service, operation) not in READ_OPERATION_EXCEPTIONS and (service, operation) not in OPTIONAL_S3_SOURCE_READ_REFERENCES and not operation.startswith(("list_", "get_", "describe_", "batch_get_")):
        raise ValueError("Mutation outside metadata policy: " + service + "/" + operation)
    if service in {"apigateway", "apigatewayv2"}:
        if (service, operation) in GATEWAY_PATHS:
            return "apigateway:GET"
        if (service, operation) not in NATIVE_METADATA_STATEMENTS and service + "/" + operation not in RESOURCE_POLICY_REFERENCE["mappings"]:
            raise ValueError("API Gateway path mapping requires reference review")
    names = _sdk_operation_names(service)
    if operation not in names:
        raise ValueError("Unknown SDK operation: " + service + "/" + operation)
    action = ACTION_ALIASES.get((service, operation), SERVICE_PREFIXES.get(service, service) + ":" + names[operation])
    if (service, operation) == ("ec2", "describe_iam_instance_profile_associations"):
        if action != ASSOCIATION_REFERENCE[0]:
            raise ValueError("EC2 association IAM mapping differs from reviewed reference")
    if (service, operation) == ("secretsmanager", "describe_secret"):
        if action != SECRET_METADATA_REFERENCE[0]:
            raise ValueError("Secrets Manager metadata IAM mapping differs from reviewed reference")
    if action not in VERIFIED_ACTIONS:
        raise ValueError("IAM mapping requires reference review: " + service + "/" + operation + " -> " + action)
    return action


# Source-reviewed, metadata-only reads for native recheck applicability.
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_scheduler.html
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ListDeadLetterSourceQueues.html
RECHECK_METADATA_READ_REFERENCES = {
    'scheduler:GetSchedule': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_scheduler.html',
    'scheduler:ListSchedules': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_scheduler.html',
    'sqs:ListDeadLetterSourceQueues': 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ListDeadLetterSourceQueues.html',
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | set(RECHECK_METADATA_READ_REFERENCES)

# Exact metadata and list actions introduced by the Exposure A/B collectors.
# Each action is listed in its provider's AWS service authorization reference.
EXPOSURE_METADATA_READ_REFERENCES = {
    'appsync:GetApiAssociation': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appsync.html',
    'appsync:ListApis': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appsync.html',
    'appsync:ListDomainNames': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appsync.html',
    'backup:ListRestoreAccessBackupVaults': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_backup.html',
    'appstream:DescribeImagePermissions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_appstream.html',
    'auditmanager:ListAssessmentFrameworkShareRequests': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_auditmanager.html',
    'backup:ListCopyJobs': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_backup.html',
    'cleanrooms:ListConfiguredTableAssociations': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cleanrooms.html',
    'cleanrooms:ListMembers': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cleanrooms.html',
    'cleanrooms:ListMemberships': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cleanrooms.html',
    'cloud9:DescribeEnvironmentMemberships': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloud9.html',
    'cloud9:DescribeEnvironments': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloud9.html',
    'cloud9:ListEnvironments': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloud9.html',
    'dataexchange:ListDataGrants': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_dataexchange.html',
    'ec2:DescribeFpgaImageAttribute': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html',
    'ec2:DescribeFpgaImages': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html',
    'ec2:DescribeTransitGatewayPeeringAttachments': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html',
    'imagebuilder:GetDistributionConfiguration': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_imagebuilder.html',
    'imagebuilder:ListDistributionConfigurations': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_imagebuilder.html',
    'lakeformation:ListPermissions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_lakeformation.html',
    'license-manager:ListDistributedGrants': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_license-manager.html',
    'omics:ListShares': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_omics.html',
    'quicksight:DescribeAccountSettings': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_quicksight.html',
    'quicksight:DescribeDashboardPermissions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_quicksight.html',
    'quicksight:ListDashboards': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_quicksight.html',
    'redshift:DescribeDataSharesForProducer': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_redshift.html',
    's3:ListAccessGrants': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html',
    'securitylake:ListSubscribers': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_securitylake.html',
    'wellarchitected:ListLensShares': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_wellarchitected.html',
    'wellarchitected:ListLenses': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_wellarchitected.html',
    'wellarchitected:ListProfileShares': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_wellarchitected.html',
    'wellarchitected:ListProfiles': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_wellarchitected.html',
    'wellarchitected:ListReviewTemplates': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_wellarchitected.html',
    'wellarchitected:ListTemplateShares': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_wellarchitected.html',
    'wellarchitected:ListWorkloadShares': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_wellarchitected.html',
    'workdocs:DescribeFolderContents': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_workdocs.html',
    'workdocs:DescribeResourcePermissions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_workdocs.html',
    'workdocs:DescribeUsers': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_workdocs.html',
    'workspaces:DescribeConnectionAliasPermissions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_workspaces.html',
    'workspaces:DescribeConnectionAliases': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_workspaces.html',
    'workspaces:DescribeWorkspaceImagePermissions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_workspaces.html',
    'workspaces:DescribeWorkspaceImages': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_workspaces.html',
    'cloudfront:GetCloudFrontOriginAccessIdentity': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudfront.html',
    'cloudfront:GetOriginAccessControl': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudfront.html',
    'kafka:GetBootstrapBrokers': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_kafka.html',
    'mediapackagev2:GetChannel': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_mediapackagev2.html',
    'mediapackagev2:ListHarvestJobs': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_mediapackagev2.html',
    'ses:GetRelay': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_mailmanager.html',
    'ses:GetRuleSet': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_mailmanager.html',
    'logs:DescribeAccountPolicies': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_logs.html',
    'sns:ListSubscriptionsByTopic': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_sns.html',
    'sns:ListPlatformApplications': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_sns.html',
    'sns:ListEndpointsByPlatformApplication': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_sns.html',
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | set(EXPOSURE_METADATA_READ_REFERENCES)

# Finite read-only additions from the second exposure sweep. The EventBridgeV2
# SDK namespace authorizes through the existing EventBridge `events:` prefix.
# Each URL is the service's action/resource authorization table; operations
# absent from this map still fail closed in iam_action().
EXPOSURE_SWEEP_READ_REFERENCES = {
    **dict.fromkeys({'events:GetResourcePolicy', 'events:ListResourcePolicies', 'events:ListSubscribers'},
        'https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-custom-bus-access-actions.html'),
    'gamelift:DescribeFleetPortSettings': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_gamelift.html',
    **dict.fromkeys({'glacier:GetVaultLock', 'glacier:GetVaultNotifications', 'glacier:ListJobs'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_glacier.html'),
    **dict.fromkeys({'globalaccelerator:ListCrossAccountAttachments', 'globalaccelerator:ListCustomRoutingAccelerators',
        'globalaccelerator:ListCustomRoutingEndpointGroups', 'globalaccelerator:ListCustomRoutingListeners'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_globalaccelerator.html'),
    **dict.fromkeys({'iot:DescribeDomainConfiguration', 'iot:DescribeEndpoint', 'iot:GetTopicRule',
        'iot:ListDomainConfigurations', 'iot:ListTopicRules'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_iot.html'),
    'lakeformation:GetDataLakeSettings': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_lakeformation.html',
    'lightsail:GetDistributions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_lightsail.html',
    **dict.fromkeys({'rum:GetAppMonitor', 'rum:ListRumMetricsDestinations'},
        'https://docs.aws.amazon.com/cloudwatchrum/latest/APIReference/API_Operations.html'),
    **dict.fromkeys({'servicediscovery:ListInstances', 'servicediscovery:ListNamespaces',
        'servicediscovery:ListServices'},
        'https://docs.aws.amazon.com/service-authorization/latest/reference/list_servicediscovery.html'),
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(EXPOSURE_SWEEP_READ_REFERENCES)

# These endpoint-bound EC2 List reads support the client-vpn-endpoint resource.
# Keep them outside the broad configuration statement so the customer role
# only grants them for endpoints in its own account.
CLIENT_VPN_ROUTE_READ_REFERENCES = {
    'ec2:DescribeClientVpnRoutes': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html',
    'ec2:DescribeClientVpnTargetNetworks': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html',
}
CLIENT_VPN_ROUTE_READ_PAIRS = {
    ('ec2', 'describe_client_vpn_routes'),
    ('ec2', 'describe_client_vpn_target_networks'),
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | set(CLIENT_VPN_ROUTE_READ_REFERENCES)


def policy_size(policy):
    # IAM excludes whitespace; every generated permission token is ASCII.
    return len(json.dumps(policy, separators=(",", ":"), ensure_ascii=True))


WAF_ASSOCIATION_REFERENCE = "https://docs.aws.amazon.com/waf/latest/developerguide/security_iam_service-with-iam.html"
# Exact companion reads required by the existing WAF association operations.
# Three actions support customer-account resources; three require Resource:*.
# Resource types follow each service authorization reference, which corrects
# the generic WAF guide examples for Cognito, App Runner and Verified Access.
WAF_ASSOCIATION_STATEMENTS = {
    ("wafv2", "get_web_acl_for_resource"): [
        {"Sid": "WafAppSyncAssociationRead", "Effect": "Allow", "Action": "appsync:GetWebACLForResource",
         "Resource": {"Fn::Sub": "arn:${AWS::Partition}:appsync:*:${AWS::AccountId}:apis/*"}},
    ],
    ("wafv2", "list_resources_for_web_acl"): [
        {"Sid": "WafAssociationListRead", "Effect": "Allow",
         "Action": ["appsync:ListResourcesForWebACL", "elasticloadbalancing:DescribeWebACLAssociation"], "Resource": "*"},
        {"Sid": "WafCognitoAssociationListRead", "Effect": "Allow", "Action": "cognito-idp:ListResourcesForWebACL",
         "Resource": {"Fn::Sub": "arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:regional/webacl/*/*"}},
        {"Sid": "WafAppRunnerAssociationListRead", "Effect": "Allow", "Action": "apprunner:ListAssociatedServicesForWebAcl",
         "Resource": {"Fn::Sub": "arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:regional/webacl/*/*"}},
        {"Sid": "WafVerifiedAccessAssociationListRead", "Effect": "Allow", "Action": "ec2:DescribeVerifiedAccessInstanceWebAclAssociations",
         "Resource": "*"},
    ],
}


WAF_ASSOCIATION_ACTIONS = frozenset(action for statements in WAF_ASSOCIATION_STATEMENTS.values()
    for statement in statements for action in
    ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]))
# Four service-reference-verified metadata reads. Keep scoped reads out of the
# Resource:* configuration statement and preserve the original three policies.
NATIVE_METADATA_REFERENCE_SHA256 = "72e537c6b0c83b43f1c818b7d7b8db0e434dd54c304352b35875f2c46376d7c2"
NATIVE_METADATA_RESOURCE_REFERENCES = [
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_budgets.html",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_lambda.html",
]
NATIVE_METADATA_RESOURCE_REFERENCES += [RESOLVER_METADATA_REFERENCE[0], SAGEMAKER_CLARIFY_REFERENCE[0]]
NATIVE_METADATA_STATEMENTS = {
    ("budgets", "describe_budget_actions_for_account"): {"Sid": "NativeBudgetAndEc2TagInventoryRead", "Effect": "Allow", "Action": ["budgets:DescribeBudgetActionsForAccount"], "Resource": "*"},
    ("budgets", "describe_budget_action"): {"Sid": "NativeBudgetActionMetadataRead", "Effect": "Allow", "Action": "budgets:DescribeBudgetAction", "Resource": {"Fn::Sub": "arn:${AWS::Partition}:budgets::${AWS::AccountId}:budget/*/action/*"}},
    ("ec2", "describe_tags"): {"Sid": "NativeBudgetAndEc2TagInventoryRead", "Effect": "Allow", "Action": ["ec2:DescribeTags"], "Resource": "*"},
    ("lambda", "list_tags"): {"Sid": "NativeLambdaFunctionTagsRead", "Effect": "Allow", "Action": "lambda:ListTags", "Resource": {"Fn::Sub": "arn:${AWS::Partition}:lambda:*:${AWS::AccountId}:function:*"}},
}
NATIVE_METADATA_STATEMENTS.update({
    ("apigatewayv2", "list_portals"): {"Sid": "NativeApiGatewayPortalInventoryRead", "Effect": "Allow",
        "Action": "apigateway:ListPortals",
        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:apigateway:*:${AWS::AccountId}:/portals/*"}},
    ("mediapackagev2", "list_harvest_jobs"): {"Sid":"NativeMediaPackageHarvestRead","Effect":"Allow","Action":"mediapackagev2:ListHarvestJobs","Resource":{"Fn::Sub":"arn:${AWS::Partition}:mediapackagev2:*:${AWS::AccountId}:channelGroup/*"}},
    ("route53resolver", "list_firewall_domain_lists"): {"Sid":"NativeResolverDomainListsRead","Effect":"Allow","Action":"route53resolver:ListFirewallDomainLists","Resource":"*"},
    ("sagemaker", "list_endpoints"): {"Sid":"NativeSageMakerEndpointInventoryRead","Effect":"Allow","Action":"sagemaker:ListEndpoints","Resource":"*"},
    ("sagemaker", "describe_endpoint"): {"Sid":"NativeSageMakerEndpointMetadataRead","Effect":"Allow","Action":"sagemaker:DescribeEndpoint","Resource":{"Fn::Sub":"arn:${AWS::Partition}:sagemaker:*:${AWS::AccountId}:endpoint/*"}},
    ("sagemaker", "list_monitoring_executions"): {"Sid":"NativeSageMakerMonitoringExecutionsRead","Effect":"Allow","Action":"sagemaker:ListMonitoringExecutions","Resource":"*"},
    ("apigatewayv2", "list_routing_rules"): {"Sid":"NativeApiGatewayRoutingRulesRead","Effect":"Allow","Action":"apigateway:ListRoutingRules","Resource":{"Fn::Sub":"arn:${AWS::Partition}:apigateway:*:${AWS::AccountId}:/domainnames/*/routingrules/*"}},
    ("cloudfront", "get_continuous_deployment_policy"): {"Sid":"NativeCloudFrontContinuousDeploymentPolicyRead","Effect":"Allow","Action":"cloudfront:GetContinuousDeploymentPolicy","Resource":{"Fn::Sub":"arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:continuous-deployment-policy/*"}},
})
NATIVE_METADATA_RESOURCE_REFERENCES.append("https://docs.aws.amazon.com/service-authorization/latest/reference/list_apigatewayv2.html")
NATIVE_METADATA_RESOURCE_REFERENCES.append("https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudfront.html")
# Metadata only; no repository contents or mutation permissions.
CODECOMMIT_REVIEW_REFERENCE = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_codecommit.html"
for _operation, _action in {
    "list_repositories": "ListRepositories", "list_pull_requests": "ListPullRequests",
    "get_pull_request": "GetPullRequest", "describe_pull_request_events": "DescribePullRequestEvents",
    "get_pull_request_approval_states": "GetPullRequestApprovalStates",
}.items():
    NATIVE_METADATA_STATEMENTS[("codecommit", _operation)] = {
        "Sid": "NativeCodeCommit" + _action + "Read", "Effect": "Allow",
        "Action": "codecommit:" + _action,
        "Resource": "*" if _operation == "list_repositories" else
            {"Fn::Sub": "arn:${AWS::Partition}:codecommit:*:${AWS::AccountId}:*"}}
NATIVE_METADATA_RESOURCE_REFERENCES.append(CODECOMMIT_REVIEW_REFERENCE)

# Scoped, read-only CloudTrail delivery policy simulation; no policy overrides.
NATIVE_METADATA_STATEMENTS[('iam', 'get_role')] = {'Sid': 'NativeCloudTrailDeliveryRoleMetadataRead', 'Effect': 'Allow', 'Action': 'iam:GetRole', 'Resource': {'Fn::Sub': 'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*'}}
NATIVE_METADATA_STATEMENTS[('iam', 'get_context_keys_for_principal_policy')] = {'Sid': 'NativeCloudTrailDeliveryContextKeysRead', 'Effect': 'Allow', 'Action': 'iam:GetContextKeysForPrincipalPolicy', 'Resource': {'Fn::Sub': 'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*'}}
NATIVE_METADATA_STATEMENTS[('iam', 'simulate_principal_policy')] = {'Sid': 'NativeCloudTrailDeliveryPolicySimulationRead', 'Effect': 'Allow', 'Action': 'iam:SimulatePrincipalPolicy', 'Resource': {'Fn::Sub': 'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*'}}
NATIVE_METADATA_RESOURCE_REFERENCES.append('https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html')
# Exact metadata-only storage inventory actions, independently verified against
# the 2026-10-15 official programmatic service authorization reference.
DATA_REGION_METADATA_RESOURCE_REFERENCES = ['https://docs.aws.amazon.com/service-authorization/latest/reference/list_outposts.html',
 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3outposts.html',
 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3tables.html',
 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3vectors.html',
 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_dynamodb.html',
 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_rds.html',
 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_redshift-serverless.html']
DATA_REGION_METADATA_STATEMENTS = {('outposts', 'list_outposts'): {'Sid': 'NativeDataRegionListOutpostsRead',
                                 'Effect': 'Allow',
                                 'Action': 'outposts:ListOutposts',
                                 'Resource': '*'},
 ('s3control', 'list_regional_buckets'): {'Sid': 'NativeDataRegionListRegionalBucketsRead',
                                          'Effect': 'Allow',
                                          'Action': 's3-outposts:ListRegionalBuckets',
                                          'Resource': '*'},
 ('s3tables', 'list_table_buckets'): {'Sid': 'NativeDataRegionListTableBucketsRead',
                                      'Effect': 'Allow',
                                      'Action': 's3tables:ListTableBuckets',
                                      'Resource': '*'},
 ('s3vectors', 'list_vector_buckets'): {'Sid': 'NativeDataRegionListVectorBucketsRead',
                                        'Effect': 'Allow',
                                        'Action': 's3vectors:ListVectorBuckets',
                                        'Resource': '*'},
 ('dynamodb', 'list_backups'): {'Sid': 'NativeDataRegionListBackupsRead',
                                'Effect': 'Allow',
                                'Action': 'dynamodb:ListBackups',
                                'Resource': '*'},
 ('rds', 'describe_db_instance_automated_backups'): {'Sid': 'NativeDataRegionDescribeDBInstanceAutomatedBackupsRead',
                                                     'Effect': 'Allow',
                                                     'Action': 'rds:DescribeDBInstanceAutomatedBackups',
                                                     'Resource': [{'Fn::Sub': 'arn:${AWS::Partition}:rds:*:${AWS::AccountId}:auto-backup:*'},
                                                                  {'Fn::Sub': 'arn:${AWS::Partition}:rds:*:${AWS::AccountId}:db:*'}]},
 ('rds', 'describe_db_cluster_automated_backups'): {'Sid': 'NativeDataRegionDescribeDBClusterAutomatedBackupsRead',
                                                    'Effect': 'Allow',
                                                    'Action': 'rds:DescribeDBClusterAutomatedBackups',
                                                    'Resource': [{'Fn::Sub': 'arn:${AWS::Partition}:rds:*:${AWS::AccountId}:cluster:*'},
                                                                 {'Fn::Sub': 'arn:${AWS::Partition}:rds:*:${AWS::AccountId}:cluster-auto-backup:*'}]},
 ('redshift-serverless', 'list_snapshots'): {'Sid': 'NativeDataRegionListSnapshotsRead',
                                             'Effect': 'Allow',
                                             'Action': 'redshift-serverless:ListSnapshots',
                                             'Resource': {'Fn::Sub': 'arn:${AWS::Partition}:redshift-serverless:*:${AWS::AccountId}:snapshot/*'}},
 ('redshift-serverless', 'list_recovery_points'): {'Sid': 'NativeDataRegionListRecoveryPointsRead',
                                                   'Effect': 'Allow',
                                                   'Action': 'redshift-serverless:ListRecoveryPoints',
                                                   'Resource': {'Fn::Sub': 'arn:${AWS::Partition}:redshift-serverless:*:${AWS::AccountId}:recoverypoint/*'}}}
NATIVE_METADATA_STATEMENTS.update(DATA_REGION_METADATA_STATEMENTS)
NATIVE_METADATA_RESOURCE_REFERENCES += DATA_REGION_METADATA_RESOURCE_REFERENCES

# Actions whose AWS authorization tables name a resource are kept out of the
# account-wide inventory statement. Wildcards below are limited to the
# customer's own account and the one documented resource type.
EXPOSURE_SWEEP_SCOPED_READS = {
    ('eventbridgev2', 'get_resource_policy'): ('events:GetResourcePolicy', 'arn:${AWS::Partition}:events:*:${AWS::AccountId}:event-busv2/*'),
    ('eventbridgev2', 'list_resource_policies'): ('events:ListResourcePolicies', 'arn:${AWS::Partition}:events:*:${AWS::AccountId}:event-busv2/*'),
    ('gamelift', 'describe_fleet_port_settings'): ('gamelift:DescribeFleetPortSettings', 'arn:${AWS::Partition}:gamelift:*:${AWS::AccountId}:fleet/*'),
    ('glacier', 'get_vault_lock'): ('glacier:GetVaultLock', 'arn:${AWS::Partition}:glacier:*:${AWS::AccountId}:vaults/*'),
    ('glacier', 'get_vault_notifications'): ('glacier:GetVaultNotifications', 'arn:${AWS::Partition}:glacier:*:${AWS::AccountId}:vaults/*'),
    ('glacier', 'list_jobs'): ('glacier:ListJobs', 'arn:${AWS::Partition}:glacier:*:${AWS::AccountId}:vaults/*'),
    ('globalaccelerator', 'list_custom_routing_endpoint_groups'): ('globalaccelerator:ListCustomRoutingEndpointGroups', 'arn:${AWS::Partition}:globalaccelerator::${AWS::AccountId}:accelerator/*/listener/*'),
    ('globalaccelerator', 'list_custom_routing_listeners'): ('globalaccelerator:ListCustomRoutingListeners', 'arn:${AWS::Partition}:globalaccelerator::${AWS::AccountId}:accelerator/*'),
    ('iot', 'describe_domain_configuration'): ('iot:DescribeDomainConfiguration', 'arn:${AWS::Partition}:iot:*:${AWS::AccountId}:domainconfiguration/*'),
    ('iot', 'get_topic_rule'): ('iot:GetTopicRule', 'arn:${AWS::Partition}:iot:*:${AWS::AccountId}:rule/*'),
    ('rum', 'get_app_monitor'): ('rum:GetAppMonitor', 'arn:${AWS::Partition}:rum:*:${AWS::AccountId}:appmonitor/*'),
    ('rum', 'list_rum_metrics_destinations'): ('rum:ListRumMetricsDestinations', 'arn:${AWS::Partition}:rum:*:${AWS::AccountId}:appmonitor/*'),
    ('servicediscovery', 'list_instances'): ('servicediscovery:ListInstances', 'arn:${AWS::Partition}:servicediscovery:*:${AWS::AccountId}:service/*'),
}
for (_service, _operation), (_action, _resource) in EXPOSURE_SWEEP_SCOPED_READS.items():
    NATIVE_METADATA_STATEMENTS[(_service, _operation)] = {
        'Sid': 'ExposureSweep' + _action.split(':', 1)[1] + 'Read',
        'Effect': 'Allow', 'Action': _action,
        'Resource': {'Fn::Sub': _resource},
    }
NATIVE_METADATA_RESOURCE_REFERENCES += sorted(set(EXPOSURE_SWEEP_READ_REFERENCES.values()))
NATIVE_METADATA_ACTIONS = frozenset(action for statement in NATIVE_METADATA_STATEMENTS.values()
    for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]))


def native_metadata_statements(read_actions):
    """Coalesce only the two exact Resource:* reads, without adding unselected reads."""
    result = {}
    for operation, statement in NATIVE_METADATA_STATEMENTS.items():
        if operation not in read_actions:
            continue
        sid = statement["Sid"]
        if sid in result:
            result[sid]["Action"] = sorted(set(result[sid]["Action"]) | set(statement["Action"]))
        else:
            result[sid] = json.loads(json.dumps(statement))
    return list(result.values())


# Exact single-operation grants and the one coalesced two-operation grant.
NATIVE_METADATA_REVIEWED_STATEMENTS = list(NATIVE_METADATA_STATEMENTS.values()) + [
    native_metadata_statements(set(NATIVE_METADATA_STATEMENTS))[0]]

# Exact primary Control Tower AuthorizedActions, including permission-only reads.
CONTROLTOWER_REFERENCE = "https://docs.aws.amazon.com/service-authorization/latest/reference/list_controltower.html"
CONTROLTOWER_STATEMENTS = {
    ('controltower', 'list_landing_zones'): [
        {'Sid': 'NativeControlTowerLandingZoneDiscoveryRead', 'Effect': 'Allow',
         'Action': ['controltower:GetHomeRegion', 'controltower:ListLandingZones'], 'Resource': '*'}],
    ('controltower', 'get_landing_zone'): [
        {'Sid': 'NativeControlTowerLandingZoneRead', 'Effect': 'Allow',
         'Action': 'controltower:GetLandingZone',
         'Resource': {'Fn::Sub': 'arn:${AWS::Partition}:controltower:*:${AWS::AccountId}:landingzone/*'}},
        {'Sid': 'NativeControlTowerLandingZonePermissionOnlyReads', 'Effect': 'Allow',
         'Action': ['controltower:DescribeLandingZoneConfiguration', 'controltower:GetAvailableUpdates',
                    'controltower:GetLandingZoneDriftStatus', 'controltower:GetLandingZoneStatus'], 'Resource': '*'}],
}
CONTROLTOWER_ACTIONS = frozenset(action for rows in CONTROLTOWER_STATEMENTS.values()
    for row in rows for action in ([row['Action']] if isinstance(row['Action'], str) else row['Action']))

VERIFIED_ACTIONS = VERIFIED_ACTIONS | WAF_ASSOCIATION_ACTIONS | NATIVE_METADATA_ACTIONS | CONTROLTOWER_ACTIONS

# Session inventory is required to join an existing Athena Spark session to its
# exact execution role. These APIs return metadata, never endpoint/notebook tokens.
ATHENA_SESSION_METADATA_REFERENCES = {
    "athena:ListSessions": "https://docs.aws.amazon.com/athena/latest/APIReference/API_ListSessions.html",
    "athena:GetSession": "https://docs.aws.amazon.com/athena/latest/APIReference/API_GetSession.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(ATHENA_SESSION_METADATA_REFERENCES)

# The exact live session and its RoleArn are needed for the GameLift Streams
# administrative-shell route; both APIs return session metadata only.
GAMELIFT_STREAM_SESSION_METADATA_REFERENCES = {
    "gameliftstreams:ListStreamGroups": "https://docs.aws.amazon.com/gameliftstreams/latest/apireference/API_ListStreamGroups.html",
    "gameliftstreams:ListStreamSessions": "https://docs.aws.amazon.com/gameliftstreams/latest/apireference/API_ListStreamSessions.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(GAMELIFT_STREAM_SESSION_METADATA_REFERENCES)

# Fleet configuration and compute IDs bind GetComputeAccess to the exact
# existing EC2 instance role. These reads return metadata, not shell credentials.
GAMELIFT_FLEET_METADATA_REFERENCES = {
    "gamelift:ListFleets": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_gamelift.html",
    "gamelift:DescribeFleetAttributes": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_gamelift.html",
    "gamelift:ListCompute": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_gamelift.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(GAMELIFT_FLEET_METADATA_REFERENCES)

# Existing IoT aliases are read with their target role to bind certificate paths
# to an exact IAM principal. These calls return no certificate or private key.
IOT_ROLE_ALIAS_METADATA_REFERENCE = {
    "iot:ListRoleAliases": "https://docs.aws.amazon.com/iot/latest/apireference/API_ListRoleAliases.html",
    "iot:DescribeRoleAlias": "https://docs.aws.amazon.com/iot/latest/apireference/API_DescribeRoleAlias.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(IOT_ROLE_ALIAS_METADATA_REFERENCE)

# Device Farm upload and device-pool names are needed to bind a custom test
# specification to an existing project and run. Upload URLs are discarded.
DEVICEFARM_TEST_METADATA_REFERENCES = {
    "devicefarm:GetDevicePoolCompatibility": "https://docs.aws.amazon.com/devicefarm/latest/APIReference/API_GetDevicePoolCompatibility.html",
    "devicefarm:ListUploads": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_devicefarm.html",
    "devicefarm:ListDevicePools": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_devicefarm.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(DEVICEFARM_TEST_METADATA_REFERENCES)

# Exact lifecycle-configuration names prevent a create permission on an
# already occupied name from being mistaken for notebook role execution.
SAGEMAKER_NOTEBOOK_LIFECYCLE_METADATA_REFERENCE = {
    "sagemaker:ListNotebookInstanceLifecycleConfigs":
        "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ListNotebookInstanceLifecycleConfigs.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(SAGEMAKER_NOTEBOOK_LIFECYCLE_METADATA_REFERENCE)
SAGEMAKER_STUDIO_LIFECYCLE_METADATA_REFERENCE = {
    "sagemaker:ListStudioLifecycleConfigs":
        "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ListStudioLifecycleConfigs.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(SAGEMAKER_STUDIO_LIFECYCLE_METADATA_REFERENCE)
BRAKET_DEVICE_METADATA_REFERENCE = {
    "braket:SearchDevices": "https://docs.aws.amazon.com/braket/latest/APIReference/API_SearchDevices.html",
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(BRAKET_DEVICE_METADATA_REFERENCE)
# Metadata reads used by the AWS privilege-escalation graph, each checked
# against the service's authorization reference before being granted.
ADDITIONAL_PRIVESC_METADATA_REFERENCES = {
    **dict.fromkeys({"appstream:DescribeAppBlockBuilderAppBlockAssociations",
                     "appstream:DescribeAppBlocks", "appstream:DescribeImages",
                     "appstream:ListAssociatedStacks"},
        "https://docs.aws.amazon.com/service-authorization/latest/reference/list_appstream.html"),
    "batch:DescribeJobQueues": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_batch.html",
    "cloudformation:DescribeOrganizationsAccess": "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeOrganizationsAccess.html",
    **dict.fromkeys({"glue:GetTriggers", "glue:ListSessions"},
        "https://docs.aws.amazon.com/service-authorization/latest/reference/list_glue.html"),
    "iam:ListSSHPublicKeys": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html",
    "lambda:ListMicrovmImages": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_lambda.html",
    "quicksight:DescribeAccountSubscription": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_quicksight.html",
    "sagemaker:ListApps": "https://docs.aws.amazon.com/service-authorization/latest/reference/list_sagemaker.html",
    **dict.fromkeys({"ssm:DescribeMaintenanceWindowTasks", "ssm:DescribeMaintenanceWindows"},
        "https://docs.aws.amazon.com/service-authorization/latest/reference/list_ssm.html"),
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(ADDITIONAL_PRIVESC_METADATA_REFERENCES)

# Exact existing collector metadata reads. AWS classifies each as Read or List;
# the FinSpace grants were already present in the signed customer template.
EXACT_COLLECTOR_READ_REFERENCES = {
    'lakeformation:ListPermissions': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_lakeformation.html',
    'redshift:DescribeEndpointAuthorization': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_redshift.html',
    'amplify:ListDomainAssociations': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_amplify.html',
    'rds:DescribeDBClusterEndpoints': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_rds.html',
    'elasticloadbalancing:DescribeInstanceHealth': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_elb.html',
    'elasticloadbalancing:DescribeTargetGroupAttributes': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_elasticloadbalancing.html',
    'finspace:GetKxCluster': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_finspace.html',
    'finspace:ListKxClusters': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_finspace.html',
    'finspace:ListKxEnvironments': 'https://docs.aws.amazon.com/service-authorization/latest/reference/list_finspace.html',
}
VERIFIED_ACTIONS = VERIFIED_ACTIONS | frozenset(EXACT_COLLECTOR_READ_REFERENCES)


def build_policy(read_actions=None, *, include_credential_report_generation=None,
                 include_waf_association_companions=True):
    if read_actions is None:
        from peaso.collectors.aws import READ_ACTIONS
        read_actions = READ_ACTIONS | PRESERVED_TEMPLATE_READ_ACTIONS
    read_actions = set(read_actions)
    if include_credential_report_generation is None:
        include_credential_report_generation = EVIDENCE_OPERATION in read_actions
    actions = set()
    gateway_paths = set()
    client_vpn_route_actions = set()
    for service, operation in sorted(read_actions):
        if (service, operation) in (UNGRANTED_CREDENTIAL_OPERATIONS | UNGRANTED_CONTENT_OPERATIONS |
                                    UNAVAILABLE_SDK_METADATA_OPERATIONS):
            continue  # Declared collector operation, never a customer-role grant.
        if service == "sts":
            if operation not in {"get_caller_identity", "assume_role"}:
                raise ValueError("Unreviewed STS operation")
            continue  # Intrinsic identity/selected role authentication is not a customer grant.
        if (service, operation) == EVIDENCE_OPERATION:
            continue
        action = iam_action(service, operation)
        if action in {"mq:DescribeSharedResources", "mq:DescribeConfigurationRevision", "oam:ListLinks",
                      "es:ListVpcEndpointAccess", "es:ListApplications", "es:GetApplication",
                      "securitylake:ListSubscribers", "securitylake:GetDataLakeExceptionSubscription",
                      "machinelearning:DescribeMLModels"}:
            # The attached AWS ReadOnlyAccess policy already grants these reads.
            # Keep this one read out of the size-bound custom policy.
            continue
        if (service, operation) in INLINE_SECURITY_IR_READS:
            # Four exact metadata reads fit the role's inline-policy quota;
            # the managed-policy attachment quota is already full.
            continue
        if (service, operation) in CONTROLTOWER_STATEMENTS:
            continue  # Exact multi-action authorization sets appended below.
        if (service, operation) in NATIVE_METADATA_STATEMENTS:
            expected = NATIVE_METADATA_STATEMENTS[(service, operation)]["Action"]
            if action not in ([expected] if isinstance(expected, str) else expected):
                raise ValueError("Native metadata mapping differs from reviewed reference")
            continue  # Appended below with its exact service resource boundary.
        if action == "apigateway:GET":
            gateway_paths.update(GATEWAY_PATHS[(service, operation)])
        elif (service, operation) in CLIENT_VPN_ROUTE_READ_PAIRS:
            client_vpn_route_actions.add(action)
        elif action:
            actions.add(action)
            for dependent in DEPENDENT_ACTIONS.get((service, operation), ()):
                if dependent not in VERIFIED_ACTIONS:
                    raise ValueError("IAM mapping requires reference review: " + dependent)
                actions.add(dependent)
    statements = [{"Sid": "ConfigurationAndInventoryRead", "Effect": "Allow", "Action": sorted(actions), "Resource": "*"}] if actions else []
    if client_vpn_route_actions:
        statements.append({"Sid": "ClientVpnRouteInventoryRead", "Effect": "Allow",
            "Action": sorted(client_vpn_route_actions),
            "Resource": {"Fn::Sub": "arn:${AWS::Partition}:ec2:*:${AWS::AccountId}:client-vpn-endpoint/*"}})
    if include_credential_report_generation:
        # This narrowly authorized evidence refresh is NOT an IAM configuration mutation.
        statements.append({"Sid": "CredentialReportEvidenceGeneration", "Effect": "Allow", "Action": "iam:GenerateCredentialReport", "Resource": "*"})
    if gateway_paths:
        statements.append({"Sid": "ApiGatewayConfigurationRead", "Effect": "Allow", "Action": "apigateway:GET",
            "Resource": [{"Fn::Sub": "arn:${AWS::Partition}:apigateway:*::" + path}
                for path in sorted(gateway_paths)]})
    for operation, companions in WAF_ASSOCIATION_STATEMENTS.items():
        if include_waf_association_companions and operation in read_actions:
            for companion in companions:
                actions_to_check = [companion["Action"]] if isinstance(companion["Action"], str) else companion["Action"]
                if any(action not in WAF_ASSOCIATION_ACTIONS for action in actions_to_check):
                    raise ValueError("WAF companion IAM mapping requires reference review")
            statements.extend(json.loads(json.dumps(companions)))
    statements.extend(native_metadata_statements(read_actions))
    for operation, rows in CONTROLTOWER_STATEMENTS.items():
        if operation in read_actions:
            statements.extend(json.loads(json.dumps(rows)))
    if not statements:
        raise ValueError("No reviewed metadata permissions selected")
    policy = {"Version": "2012-10-17", "Statement": statements}
    split_policy(policy)  # fails closed when the grant cannot fit the role's managed-policy quota
    return policy


def _reviewed_policy_allocation():
    """Bind the current full grant to its byte-frozen, reviewed IAM partition."""
    content = REVIEWED_ROLE_PATH.read_bytes()
    if hashlib.sha256(content).hexdigest() != REVIEWED_ROLE_SHA256:
        raise ValueError("Reviewed customer-role archive changed")
    role = json.loads(content)
    resources = role["Resources"]
    names = [f"{MANAGED_POLICY_PREFIX}{number}" for number in (1, 2, 3)]
    documents = [resources[name]["Properties"]["PolicyDocument"] for name in names]
    if any(resources[name]["Type"] != "AWS::IAM::ManagedPolicy" for name in names):
        raise ValueError("Reviewed customer-role allocation is invalid")
    if any(document["Version"] != "2012-10-17" or policy_size(document) > IAM_MANAGED_POLICY_LIMIT
           for document in documents) or len(documents) > IAM_MANAGED_POLICIES_PER_ROLE:
        raise ValueError("Reviewed customer-role allocation exceeds IAM limits")

    ordinary = []
    ordinary_shape = None
    evidence = gateway = None
    for document in documents:
        for statement in document["Statement"]:
            sid = statement["Sid"]
            if sid.startswith("ConfigurationAndInventoryRead") or sid == "ComplianceWaveReadOnlyMetadata":
                if not isinstance(statement["Action"], list):
                    raise ValueError("Reviewed metadata action list is invalid")
                shape = {key: value for key, value in statement.items() if key not in {"Sid", "Action"}}
                if ordinary_shape is None:
                    ordinary_shape = shape
                elif ordinary_shape != shape:
                    raise ValueError("Reviewed metadata statement scope differs")
                ordinary.extend(statement["Action"])
            elif sid == "CredentialReportEvidenceGeneration" and evidence is None:
                evidence = statement
            elif sid == "ApiGatewayConfigurationRead" and gateway is None:
                gateway = statement
            else:
                raise ValueError("Reviewed customer-role statement is invalid")
    if ordinary_shape is None or evidence is None or gateway is None or len(ordinary) != len(set(ordinary)):
        raise ValueError("Reviewed customer-role grants are incomplete or duplicate")
    logical = {"Version": "2012-10-17", "Statement": [
        {"Sid": "ConfigurationAndInventoryRead", "Action": sorted(ordinary), **ordinary_shape},
        evidence, gateway,
    ]}
    return logical, documents


def split_policy(policy):
    """Split the logical policy into customer-managed documents, each within the 6144-character limit.

    Only the explicit action list is partitioned; no wildcard or broader grant is introduced."""
    # Keep the existing credential-report grant intact while using the
    # remaining space in the companion document for this fixed statement.
    credential_report = {"Sid": "CredentialReportEvidenceGeneration", "Effect": "Allow",
                         "Action": "iam:GenerateCredentialReport", "Resource": "*"}
    known_companions = ([s for rows in WAF_ASSOCIATION_STATEMENTS.values() for s in rows] +
                        NATIVE_METADATA_REVIEWED_STATEMENTS +
                        [s for rows in CONTROLTOWER_STATEMENTS.values() for s in rows])
    companions = [s for s in policy["Statement"] if s in known_companions]
    if companions:
        companions += [s for s in policy["Statement"] if s == credential_report]
        original = {**policy, "Statement": [s for s in policy["Statement"] if s not in companions]}
        documents = split_policy(original) if original["Statement"] else []
        extra = {"Version": "2012-10-17", "Statement": companions}
        # A small scoped read can be moved beside the companion statements to
        # make room for the final scoped statement in the preceding document.
        # This preserves every action and resource while avoiding an extra
        # managed-policy attachment when the ordinary read list grows.
        if len(documents) >= 2:
            previous, final = documents[-2:]
            for statement in previous["Statement"]:
                if not isinstance(statement["Action"], str) and len(statement["Action"]) != 1:
                    continue
                combined = {"Version": "2012-10-17", "Statement": [
                    s for s in previous["Statement"] if s is not statement] + final["Statement"]}
                shifted_extra = {"Version": "2012-10-17", "Statement": companions + [statement]}
                if (combined["Statement"] and policy_size(combined) <= IAM_MANAGED_POLICY_LIMIT and
                        policy_size(shifted_extra) <= IAM_MANAGED_POLICY_LIMIT):
                    documents[-2:] = [combined]
                    extra = shifted_extra
                    break
        if policy_size(extra) > IAM_MANAGED_POLICY_LIMIT:
            # Pack exact scoped companion statements into unused space in the
            # ordinary read partitions. The combined Exposure reads otherwise
            # need a ninth generated attachment, above the customer role cap.
            remaining = list(extra["Statement"])
            largest_first = sorted(remaining, key=lambda statement: policy_size(
                {"Version": "2012-10-17", "Statement": [statement]}), reverse=True)
            for document in reversed(documents):
                for statement in largest_first:
                    if statement not in remaining:
                        continue
                    candidate = {"Version": "2012-10-17", "Statement": document["Statement"] + [statement]}
                    if policy_size(candidate) <= IAM_MANAGED_POLICY_LIMIT:
                        document["Statement"].append(statement)
                        remaining.remove(statement)
                if policy_size({"Version": "2012-10-17", "Statement": remaining}) <= IAM_MANAGED_POLICY_LIMIT:
                    break
            extra = {"Version": "2012-10-17", "Statement": remaining}
        extras = [extra]
        if policy_size(extra) > IAM_MANAGED_POLICY_LIMIT:
            # Unused space was not enough. Keep each exact companion statement
            # whole and spread the rest over as few new documents as fit; the
            # role attachment quota is still enforced below and in refresh().
            extras = []
            for statement in extra["Statement"]:
                if extras and policy_size({"Version": "2012-10-17",
                                           "Statement": extras[-1]["Statement"] + [statement]}) <= IAM_MANAGED_POLICY_LIMIT:
                    extras[-1]["Statement"].append(statement)
                else:
                    extras.append({"Version": "2012-10-17", "Statement": [statement]})
        if (any(policy_size(item) > IAM_MANAGED_POLICY_LIMIT for item in extras) or
                len(documents) + len(extras) > IAM_MANAGED_POLICIES_PER_ROLE):
            raise ValueError("WAF association metadata exceeds existing IAM policy budgets")
        return documents + extras
    reviewed_logical, reviewed_documents = _reviewed_policy_allocation()
    if policy == reviewed_logical:
        # The signed role kept its original two near-limit partitions and
        # appended a distinct reviewed statement to partition three. Generic
        # repartitioning would change its exact published document structure.
        return reviewed_documents
    # Keep the published 9254 allocation intact for the sole newly reviewed
    # collector read. This candidate remains a separate, local prospective
    # policy; the signed template and its three existing documents are frozen.
    association_action = "ec2:DescribeIamInstanceProfileAssociations"
    candidate = json.loads(json.dumps(reviewed_logical))
    candidate["Statement"][0]["Action"] = sorted(
        candidate["Statement"][0]["Action"] + [association_action])
    secret_action = SECRET_METADATA_REFERENCE[0]
    full_candidate = json.loads(json.dumps(candidate))
    full_candidate["Statement"][0]["Action"] = sorted(
        candidate["Statement"][0]["Action"] + [secret_action])
    native_actions = {"iam:ListPolicies", "iam:GetPolicyVersion", "elasticmapreduce:ListInstances"}
    native_candidate = json.loads(json.dumps(full_candidate))
    native_candidate["Statement"][0]["Action"] = sorted(set(full_candidate["Statement"][0]["Action"]) | native_actions)
    bulk_candidate = json.loads(json.dumps(native_candidate))
    bulk_candidate['Statement'][0]['Action'] = sorted(set(native_candidate['Statement'][0]['Action']) | set(BULK_METADATA_REFERENCES))
    waf_candidate = json.loads(json.dumps(bulk_candidate))
    waf_candidate['Statement'][0]['Action'] = sorted(set(bulk_candidate['Statement'][0]['Action']) | WAF_IP_SET_ACTIONS)
    batch_candidate = json.loads(json.dumps(waf_candidate))
    batch_candidate['Statement'][0]['Action'] = sorted(set(waf_candidate['Statement'][0]['Action']) | NATIVE_BATCH_ACTIONS)
    deployment_resource = {'Fn::Sub': 'arn:${AWS::Partition}:apigateway:*::/restapis/*/deployments/*'}
    batch_candidate['Statement'][2]['Resource'] = sorted(
        batch_candidate['Statement'][2]['Resource'] + [deployment_resource], key=lambda value: value['Fn::Sub'])
    identity_candidate = json.loads(json.dumps(batch_candidate))
    identity_candidate['Statement'][0]['Action'] = sorted(set(batch_candidate['Statement'][0]['Action']) | IDENTITY_CENTER_ACTIONS)
    if policy in (candidate, full_candidate, native_candidate, bulk_candidate, waf_candidate, batch_candidate, identity_candidate):
        documents = json.loads(json.dumps(reviewed_documents))
        documents[2]["Statement"].append({
            "Sid": "V4AssociationInventoryRead", "Effect": "Allow",
            "Action": association_action, "Resource": "*",
        })
        if policy in (full_candidate, native_candidate, bulk_candidate, waf_candidate, batch_candidate, identity_candidate):
            documents[2]["Statement"].append({
                "Sid": "SecretRotationMetadataRead", "Effect": "Allow",
                "Action": secret_action, "Resource": "*",
            })
        if policy in (native_candidate, bulk_candidate, waf_candidate, batch_candidate, identity_candidate):
            documents[2]["Statement"].append({"Sid": "NativePolicyAndEmrInventoryRead", "Effect": "Allow", "Action": sorted(native_actions), "Resource": "*"})
        if policy in (bulk_candidate, waf_candidate, batch_candidate, identity_candidate):
            documents[2]['Statement'].append({'Sid': 'BulkInventoryMetadataRead', 'Effect': 'Allow',
                'Action': sorted(BULK_METADATA_REFERENCES), 'Resource': '*'})
        if policy in (waf_candidate, batch_candidate, identity_candidate):
            documents[2]['Statement'].append({'Sid': 'WafIpSetMetadataRead', 'Effect': 'Allow',
                'Action': sorted(WAF_IP_SET_ACTIONS), 'Resource': '*'})
        if policy in (batch_candidate, identity_candidate):
            documents[2]['Statement'].append({'Sid': 'NativeOrganizationAndMetricInventoryRead', 'Effect': 'Allow',
                'Action': sorted(NATIVE_BATCH_ACTIONS), 'Resource': '*'})
            documents[2]['Statement'].append({'Sid': 'ApiGatewayDeploymentConfigurationRead', 'Effect': 'Allow',
                'Action': 'apigateway:GET', 'Resource': [deployment_resource]})
        if policy == identity_candidate:
            documents[2]['Statement'].append({'Sid': 'IdentityCenterMembershipMetadataRead', 'Effect': 'Allow',
                'Action': sorted(IDENTITY_CENTER_ACTIONS), 'Resource': '*'})
        if policy_size(documents[2]) > IAM_MANAGED_POLICY_LIMIT:
            raise ValueError("Customer policy exceeds managed policy size limit")
        return documents
    documents, current = [], []

    def fits(statements):
        return policy_size({"Version": "2012-10-17", "Statement": statements}) <= IAM_MANAGED_POLICY_LIMIT

    def flush():
        if current:
            documents.append({"Version": "2012-10-17", "Statement": list(current)})
            current.clear()

    for statement in policy["Statement"]:
        actions = statement["Action"]
        if isinstance(actions, str) or len(actions) <= 1:
            if not fits(current + [statement]):
                flush()
            if not fits([statement]):
                raise ValueError("Customer policy statement exceeds managed policy size limit")
            current.append(statement)
            continue
        chunk = []
        for action in actions:
            # New allocations use a short statement ID so the exact read actions
            # fit within the existing customer role's managed-policy quota.
            candidate = {**statement, "Sid": "ConfigRead" + str(len(documents) + 1), "Action": chunk + [action]}
            if not fits(current + [candidate]):
                if chunk:
                    current.append({**statement, "Sid": "ConfigRead" + str(len(documents) + 1), "Action": chunk})
                flush()
                chunk = [action]
            else:
                chunk.append(action)
        if chunk:
            current.append({**statement, "Sid": "ConfigRead" + str(len(documents) + 1), "Action": chunk})
    flush()
    if len(documents) > IAM_MANAGED_POLICIES_PER_ROLE:
        raise ValueError("Customer policy exceeds the attached managed-policy quota")
    return documents


def refresh(root: Path, *, read_actions=None, include_credential_report_generation=None):
    import sys
    sys.path.insert(0, str(root))
    policy = build_policy(read_actions, include_credential_report_generation=include_credential_report_generation)
    documents = split_policy(policy)
    path = root / "infra/aws/customer-role.json"
    template = json.loads(path.read_text())
    resources = template["Resources"]
    previous_resources = json.loads(json.dumps(resources))
    role = resources["AuditRole"]["Properties"]
    # New customer templates must trust the dedicated broker, never the ECS
    # task role that also holds platform storage permissions.
    template["Parameters"]["CollectorRoleArn"] = {
        "Type": "String", "AllowedPattern": "arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+",
        "Description": "Collector role ARN shown by the CSPM connector setup",
    }
    role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"] = {"Ref": "CollectorRoleArn"}
    # Remove the redundant broad Access Analyzer attachment before deciding
    # whether an exact API Gateway statement must move inline. The complete
    # collector reads must already be present in the reviewed custom policy.
    analyzer_managed = "arn:aws:iam::aws:policy/IAMAccessAnalyzerFullAccess"
    if len(documents) + len(role.get("ManagedPolicyArns", [])) > IAM_MANAGED_POLICIES_PER_ROLE:
        from peaso.collectors.aws import READ_ACTIONS
        required = {iam_action(service, operation) for service, operation in READ_ACTIONS
                    if service == "accessanalyzer"}
        explicit = {action for document in documents for statement in document["Statement"]
                    for action in ([statement["Action"]] if isinstance(statement["Action"], str)
                                   else statement["Action"])}
        if required <= explicit:
            role["ManagedPolicyArns"] = [arn for arn in role.get("ManagedPolicyArns", [])
                                         if arn != analyzer_managed]
    # Keep the exact scoped API Gateway statement inline if one additional
    # ordinary read partition would exceed the role's attachment quota.
    gateway_inline_name = "CspmApiGatewayConfigurationRead"
    inline = [item for item in role.get("Policies", []) if item.get("PolicyName") not in
              (MANAGED_POLICY_PREFIX, gateway_inline_name)]
    if len(documents) + len(role.get("ManagedPolicyArns", [])) > IAM_MANAGED_POLICIES_PER_ROLE:
        candidate = documents[-2] if len(documents) >= 2 else None
        statements = candidate.get("Statement") if isinstance(candidate, dict) else None
        if (not isinstance(statements, list) or len(statements) != 1 or
                statements[0].get("Sid") != "ApiGatewayConfigurationRead"):
            raise ValueError("Customer role exceeds the attached managed-policy quota")
        inline.append({"PolicyName": gateway_inline_name, "PolicyDocument": candidate})
        documents.pop(-2)
    aggregate = sum(policy_size(item["PolicyDocument"]) for item in inline)
    if aggregate > IAM_INLINE_ROLE_LIMIT:
        raise ValueError("Customer role aggregate inline policies exceed 10240-character limit")
    if len(documents) + len(role.get("ManagedPolicyArns", [])) > IAM_MANAGED_POLICIES_PER_ROLE:
        raise ValueError("Customer role exceeds the attached managed-policy quota")
    if inline:
        role["Policies"] = inline
    else:
        role.pop("Policies", None)
    for name in [name for name in resources if name.startswith(MANAGED_POLICY_PREFIX)]:
        del resources[name]
    for number, document in enumerate(documents, 1):
        resources[f"{MANAGED_POLICY_PREFIX}{number}"] = {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "Description": (previous_resources.get(f"{MANAGED_POLICY_PREFIX}{number}", {}).get("Properties", {}).get("Description")
                            or f"HackTricks CSPM read-only configuration metadata ({number}/{len(documents)})"),
            "Roles": [{"Ref": "AuditRole"}], "PolicyDocument": document}}
    current_metadata = json.loads(json.dumps(template.get("Metadata", {})))
    template.setdefault("Metadata", {})["PeasoPermissionReference"] = {
        "Source": REFERENCE_URL, "CapturedDate": REFERENCE_DATE, "SHA256": REFERENCE_SHA256,
        "Mapping": "Reviewed SDK/IAM aliases and namespaces; action names verified against AWS-published reference",
        "Boundary": "No explicit secret-value/content/credential APIs or IAM configuration writes; optional authorized credential-report evidence refresh is separate",
    }
    template['Metadata']['PeasoSprintMetadataReference'] = {
        'Source': REFERENCE_URL, 'CapturedDate': '2026-10-14', 'SHA256': SPRINT_METADATA_REFERENCE_SHA256,
        'Actions': sorted(action for action, source in BULK_METADATA_REFERENCES.items() if source == REFERENCE_URL),
        'Boundary': 'Exact metadata inventory reads; no writes, log content or credential values',
    }
    template['Metadata']['PeasoWafIpSetMetadataReference'] = {
        'Source': REFERENCE_URL, 'CapturedDate': '2026-10-15', 'SHA256': WAF_IP_SET_REFERENCE_SHA256,
        'Actions': sorted(WAF_IP_SET_ACTIONS), 'Boundary': 'IP set configuration reads only; no ACL changes or request samples',
    }
    template['Metadata']['PeasoNativeBatchMetadataReference'] = {
        'Source': REFERENCE_URL, 'CapturedDate': '2026-10-15', 'SHA256': NATIVE_BATCH_REFERENCE_SHA256,
        'Actions': sorted(NATIVE_BATCH_ACTIONS),
        'ApiGatewayDeploymentResource': 'arn:${AWS::Partition}:apigateway:*::/restapis/*/deployments/*',
        'ApiGatewayDeploymentReference': 'https://docs.aws.amazon.com/apigateway/latest/api/API_GetDeployment.html',
        'Boundary': 'Organization policy metadata and metric names only; no writes or metric values',
    }
    if IDENTITY_CENTER_ACTIONS <= set(policy['Statement'][0]['Action']):
        template['Metadata']['PeasoIdentityCenterMetadataReference'] = {
            'Source': REFERENCE_URL, 'CapturedDate': '2026-10-15', 'SHA256': IDENTITY_CENTER_REFERENCE_SHA256,
            'Actions': sorted(IDENTITY_CENTER_ACTIONS),
            'Boundary': 'Identity status and group membership metadata only; no credentials, sessions or writes',
        }
    companions = [statement for statement in policy["Statement"]
                  if statement in [row for rows in WAF_ASSOCIATION_STATEMENTS.values() for row in rows]]
    if companions:
        actions = sorted({action for statement in companions
                          for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])})
        template["Metadata"]["PeasoWafAssociationMetadataReference"] = {
            "Source": WAF_ASSOCIATION_REFERENCE, "CapturedDate": "2026-10-15", "Actions": actions,
            "ResourceReferences": ["https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncognitouserpools.html", "https://docs.aws.amazon.com/service-authorization/latest/reference/list_apprunner.html", "https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html"],
            "Boundary": "Association metadata only; existing three managed policies and trust preserved; resource-scoped reads use the customer account",
        }
    native = [statement for statement in policy["Statement"]
              if statement in NATIVE_METADATA_REVIEWED_STATEMENTS]
    native_actions = sorted({action for s in native for action in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])})
    if native:
        template["Metadata"]["PeasoBudgetAndTagsMetadataReference"] = {
            "Source": REFERENCE_URL, "SHA256": NATIVE_METADATA_REFERENCE_SHA256,
            "CapturedDate": "2026-10-15", "Actions": native_actions,
            "ResourceReferences": NATIVE_METADATA_RESOURCE_REFERENCES,
            "Boundary": "Exact metadata reads; budget actions and Lambda functions scoped to customer account. No action execution, tag mutation or secret values.",
        }
    if "HackTricksCspmPermissionReference" in current_metadata:
        # Published HackTricks templates already carry the legacy source records
        # under their branded keys. Keep those records verbatim on regeneration.
        template["Metadata"] = current_metadata
        template["Metadata"]["HackTricksCspmIamRolePolicyMetadataReference"] = {
            "Actions": sorted(IAM_ROLE_POLICY_METADATA_REFERENCES),
            "Sources": IAM_ROLE_POLICY_METADATA_REFERENCES,
            "Boundary": "Read IAM role policy names and documents for CloudTrail delivery-role configuration; no IAM writes.",
        }
    report_actions = sorted({action for statement in policy["Statement"]
                             for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
                             if action in IAM_REPORT_READ_REFERENCES})
    if report_actions:
        template["Metadata"]["PeasoIamReportReadReference"] = {
            "Actions": report_actions,
            "Sources": {action: IAM_REPORT_READ_REFERENCES[action] for action in report_actions},
            "AccessLevel": "Read",
            "Boundary": "Selection-gated metadata reports; no IAM identity, credential or permission changes.",
        }
    template["Metadata"]["PeasoResourcePolicyMetadataReference"] = {
        "Source": RESOURCE_POLICY_REFERENCE["source_url"],
        "SHA256": RESOURCE_POLICY_REFERENCE["source_sha256"],
        "CapturedDate": RESOURCE_POLICY_REFERENCE["reviewed_on"],
        "Actions": sorted(set(RESOURCE_POLICY_REFERENCE["mappings"].values()) | {
            action for actions in RESOURCE_POLICY_REFERENCE["additional_actions"].values() for action in actions}),
        "Boundary": "Explicit policy and resource inventory reads only; no resource writes or secret values.",
    }
    template['Metadata']['PeasoNativeRecheckMetadataReference'] = {
        'Actions': sorted(RECHECK_METADATA_READ_REFERENCES),
        'References': RECHECK_METADATA_READ_REFERENCES,
        'Boundary': 'Selection-gated metadata reads only; no schedule payloads, messages or writes',
    }
    template["Metadata"]["PeasoNetworkServiceMetadataReference"] = {
        "Sources": NETWORK_SERVICE_READ_REFERENCES,
        "Boundary": "Read-only VPC origin and subnet/security-group attachments; no application content or network changes.",
    }
    template["Metadata"]["PeasoGameLiftFleetMetadataReference"] = {
        "Actions": sorted(GAMELIFT_FLEET_METADATA_REFERENCES),
        "Sources": GAMELIFT_FLEET_METADATA_REFERENCES,
        "Boundary": "Fleet role configuration and compute identifiers only; no remote access or role credentials.",
    }
    template["Metadata"]["PeasoIoTRoleAliasMetadataReference"] = {
        "Actions": sorted(IOT_ROLE_ALIAS_METADATA_REFERENCE),
        "Sources": IOT_ROLE_ALIAS_METADATA_REFERENCE,
        "Boundary": "Existing IoT role alias names and target role ARNs only; no certificates, private keys or role credentials.",
    }
    template["Metadata"]["PeasoDeviceFarmTestMetadataReference"] = {
        "Actions": sorted(DEVICEFARM_TEST_METADATA_REFERENCES),
        "Sources": DEVICEFARM_TEST_METADATA_REFERENCES,
        "Boundary": "Project upload and device-pool metadata only; no signed upload URLs, test content or role credentials.",
    }
    # Compact new templates to preserve source export budgets. Archived versions
    # are never reformatted or overwritten; CloudFormation parses the same JSON.
    path.write_text(json.dumps(template, separators=(",", ":"), ensure_ascii=True, sort_keys=True) + "\n")
    count = len(policy["Statement"][0]["Action"]) + len(actions if companions else []) + len(native_actions)
    evidence_note = ", separate authorized report evidence operation" if any(
        statement["Sid"] == "CredentialReportEvidenceGeneration" for statement in policy["Statement"]) else ""
    print(f"Customer policy: {count} verified metadata actions in {len(documents)} managed policies "
          f"({', '.join(str(policy_size(d)) for d in documents)} characters), scoped API Gateway GET{evidence_note}")


if __name__ == "__main__":
    refresh(Path(__file__).resolve().parents[1])
