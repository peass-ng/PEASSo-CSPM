# Native AWS snapshot collector

`peaso.collectors.aws.collect(connector, requirements=None)` returns a sealed schema
1.0 snapshot. It collects AWS configuration and declared permissions for offline
defensive review. The finite operation allowlist contains configuration and metadata reads,
including STS authentication; general reads exclude resource mutations, secret-value
reads, object downloads, log-event reads, network probes, and exploit/path validation.
A dedicated Access Analyzer lifecycle creates missing external analyzers per scanned
Region and one unused analyzer per account/partition when authorized. It waits at
least 180 seconds, collects available findings and their details, then deletes only
scan-created analyzers, including after errors or cancellation. Existing analyzers
in scanned Regions are reused and retained. Temporary unused analyzers use a 90-day
inactivity window and incur AWS charges. Initial findings may still be incomplete;
temporary evidence remains partial. Snapshot metadata records creation and cleanup
outcomes and ARNs under `access_analyzer_lifecycle`. This lifecycle requires
`IAMAccessAnalyzerFullAccess` or equivalent permissions; the hosted metadata-only
role template does not itself grant creation or deletion. No Steampipe, Powerpipe
or Prowler runtime is used.

## Selection, credentials and account identity

```python
from peaso.collectors.aws import collect

snapshot = collect({
    "provider": "aws",
    "auth": {"profile": "audit-sso"},
    "scopes": ["123456789012"],
    "options": {
        "regions": ["us-east-1", "eu-west-1"],
        "max_calls": 200,
        "max_pages": 10,
        "max_resources": 10000,
        "service_concurrency": 4,
        "region_concurrency": 2,
        "scope_concurrency": 2,
    },
}, ["bucket", "iam_user", "iam_role", "iam_policy", "security_group"])
```

`requirements` contains resource types; `None` requests all supported types.
`options.inventories` can further restrict selection. The intersection is read;
every omitted supported inventory has a `not_collected` envelope. Unsupported
requirements receive `not_collected` with `unsupported_inventory`. Caller identity
is always required and represented by the `aws_account` collection and
`metadata.caller_identities`.

Scopes accept account IDs or precise `account/region` pairs. Account-only scopes
use `options.regions`; precise pairs are retained without expanding them into an
account/region Cartesian product. Legacy bare region scopes are accepted and
resolved to the verified caller account. With no account selection, the verified
selected credential context is scanned; the default region is `us-east-1`.
Global inventories occur once per account under its first selected region.
Collection scopes and resource identity include the verified account and region;
native items retain their fields and gain `id`, `AccountId`, and `Region`.
The input connector is not modified.

Authentication supports boto3's SDK credential chain: environment/shared-file
credentials, configured profiles and credential processes, cached IAM Identity
Center/SSO sessions, configured profile assume-role chains, web identity, container
task credentials, and instance credentials. The selected credentials are resolved
and frozen before concurrent clients are created. An expired or unavailable
selected profile/provider fails that context; no default-profile recovery occurs.
Credentials remain in memory inside the collector and never enter snapshots.
The frozen context does not renew during a long scan; expiry produces explicit
denial evidence rather than switching contexts.

`auth.profile` selects one exact SDK profile. Explicit key authentication uses
`aws_access_key_id`, `aws_secret_access_key`, and optional `aws_session_token`;
partial keys and simultaneous explicit keys/profile are rejected. `auth.method`
accepts `default`, `auto`, `sdk`, `profile`, `sso`, `access_keys`, `web_identity`,
`container`, `instance`, or `task_role`. Profile/SSO and access-key methods require
their corresponding configuration. Explicit metadata/web-identity methods select
only that SDK provider and fail if it cannot produce credentials. SSO login/token
refresh configuration remains the responsibility of the selected SDK profile.
`task_role` accepts temporary credentials from the runtime environment (including
Lambda), container, instance or web-identity role provider; it requires a session
token and rejects shared/profile credentials, avoiding profile fallback when the
selected scanner runtime role is unavailable.

`auth.role_chain` accepts up to ten role ARN strings or objects with `role_arn`,
`external_id`, and `role_session_name`. `auth.role_arn` appends a final role.
Default `auth.external_id` and `auth.role_session_name` apply unless overridden
per hop; the default session name is `peaso-read-only`. The platform scanner's
task role can supply the initial SDK/container context before assuming a target
role. These are credential exchanges; they do not create or modify cloud resources.

`auth.assume_roles` selects up to 100 independent cross-account targets from that
initial or chained context. Every target is verified with `GetCallerIdentity`
against the account embedded in the role ARN. Explicit account scopes are an
allowlist; unspecified accounts are not scanned. A selected account without a
configured/accessible role gets explicit unavailable coverage. Within an account,
the first successfully verified selected role context supplies collection;
permissions from multiple roles are never silently unioned.

For an authorized organization-wide inventory, set
`options.organization_role_name` to an explicitly configured accessible role name
or path. The collector lists organization accounts, selects active accounts, and
attempts only that role, up to 100 independent targets. It does not guess roles or
grant access. Per-target failures are retained in
`metadata.authentication_errors`. Organization account listing alone does not
enable cross-account collection. `options.trusted_scope_ids` contains explicit
12-digit account IDs for offline trust interpretation; selection never implies
trust.

See [boto3 credential provider documentation](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html)
and [STS AssumeRole](https://docs.aws.amazon.com/boto3/latest/reference/services/sts/client/assume_role.html)
for the SDK's credential/session semantics.

## Bounds and evidence semantics

| Option | Default | Accepted range | Meaning |
| --- | ---: | --- | --- |
| `max_calls` | 200 | 1–10000 | Total scanner-managed configuration/STS requests, including retries |
| `max_pages` | 10 | 1–100 | Maximum pages per native list operation |
| `max_resources` | 10000 | 1–100000 | Total emitted resources, including caller identity; also bounds each list projection |
| `service_concurrency` | 32 | 1–32 | Global concurrent work/request ceiling for configuration reads |
| `activity_concurrency` | enabled Regions (max 32) | 1–32 | Dedicated CloudTrail LookupEvents threads, one Region each, each paced at 2 requests/second |
| `service_last_accessed_concurrency` | 4 | 1–8 | Concurrent IAM access-report generate/poll calls (adaptively paced) |
| `service_last_accessed_wait_seconds` | 120 | 1–600 | Deadline for IAM access-report jobs; late principals stay UNKNOWN |
| `region_concurrency` | 2 | 1–8 | Maximum selected regions per account in a work batch |
| `scope_concurrency` | 2 | 1–8 | Maximum account contexts in a work batch |
| `retry_attempts` | 3 | 1–5 | Total attempts per identical request |
| `connect_timeout` | 5 seconds | 1–30 | SDK connection timeout |
| `read_timeout` | 15 seconds | 1–120 | SDK per-read timeout |

One thread pool bounds all service/scope/region configuration work; these settings do not
multiply the global request concurrency. CloudTrail LookupEvents (2 TPS per account and Region) runs on its own
rate-limited per-Region threads, and IAM access reports use their own small paced pool, so neither occupies the
configuration workers for minutes. SDK automatic retries are disabled so
every attempt consumes the scan budget. Throttle/service-unavailable errors use
bounded exponential backoff. Identical context/service/region/operation/argument
requests share a single cached future, including failures. This avoids repeated
IAM authorization requests across four native projections and duplicate detail
reads within a scan; no cache persists across scans. Clients are created under
a lock, while reads run concurrently. Emission order is deterministic.
Initial SDK credential-provider resolution (for example SSO, metadata or
profile-configured role exchanges) occurs before collection and is managed by
the SDK; those provider requests are not counted in the collector request budget.
This is explicit in `metadata.credential_resolution_calls`.

Pagination uses the installed SDK's native pagination metadata, preserving IAM
Marker/IsTruncated, EC2 NextToken, S3 continuation, ELB NextMarker, and lowercase
CloudWatch tokens. Repeated or missing required tokens are malformed evidence;
page/call/resource caps never produce a complete collection. List responses are
validated, and resources are deduplicated using type-specific native identifiers.
Multiple subnets or instances in one VPC remain separate resources.

| Collection status | Meaning |
| --- | --- |
| `collected` | List/configuration retrieval completed and contains evidence |
| `empty` | Successful retrieval established no resources/configuration |
| `partial` | Evidence exists, but a page, resource, call limit or later failure prevents completeness |
| `denied` | AWS authorization or credential validity denied collection |
| `timeout` | SDK connection/read timeout prevented collection |
| `not_collected` | Inventory was omitted, unsupported, lacked a configured account role, or hit a budget before evidence |
| `malformed` | Native response/list/pagination validation failed without usable evidence |
| `unknown` | Other retrieval failure without usable evidence |

Resource detail failures have `{collection_status, error:{code}}` beside the
resource's successfully collected fields. A parent `collected` list does not imply
complete security details. Documented missing S3 policies/public-access-block
controls or Lambda URL/policy configuration have `collection_status:"empty"` and
`absent:true`; absence and denial remain distinct. Empty/unavailable collection
envelopes contain no items. Exception bodies and request values are never logged
or serialized, only bounded AWS error codes. Access-key metadata retains a SHA-256
`AccessKeyFingerprint`, status, creation and last-used evidence, not the key ID.
Lambda environment/code, STS credentials/tokens, secret values, VPN pre-shared
keys/customer gateway configuration XML, and binary content are removed at
serialization boundaries.

## Optional selected Lambda environment secret scanning

Standard Lambda metadata collection already uses `GetFunctionConfiguration` and
drops variable values before caching. The optional dual-engine reader uses an
isolated projection and an additional exact selected read before that boundary;
it cannot infer secret absence from the stripped metadata cache.

Name `aws.review.lambda.selected_environment_secret_indicators` in `checks`, set
`options.content_secret_scans` to `true`, and provide
`options.selected_aws_lambda_functions`: 1–8 unique, exact **unqualified** native
Lambda function ARNs. Select explicit matching `account/Region` pair scopes.
Aliases, published-version qualifiers, partial ARNs, names alone, wildcard scopes
and broad category/framework selection do not enable this reader.

```json
{
  "connector": {
    "provider": "aws",
    "scopes": ["123456789012/us-east-1"],
    "options": {
      "content_secret_scans": true,
      "selected_aws_lambda_functions": [
        "arn:aws:lambda:us-east-1:123456789012:function:example-function"
      ]
    }
  },
  "checks": ["aws.review.lambda.selected_environment_secret_indicators"]
}
```

The only function-content API is
`GetFunctionConfiguration(FunctionName=<exact selected ARN>)`, with no
`Qualifier`. It requires **`lambda:GetFunctionConfiguration`** at the selected
function ARN; this action is already part of the existing metadata permission
set, so this feature introduces no role-template or grant change. The existing
mandatory `sts:GetCallerIdentity` read binds the selected caller account and
partition. No list, invoke, update or direct decrypt operation is added.

For environment variables encrypted with a customer-managed KMS key, Lambda may
also require the caller's preexisting key-scoped **`kms:Decrypt`** authorization
to return readable variables. This reader never calls KMS directly, creates a
grant, changes a key/role policy or recommends broad key permissions. Missing
key access, `Environment.Error` and native KMS access errors remain UNKNOWN.
Intended Secrets Manager/Parameter Store payloads are never fetched. Client-side
ciphertext or other encodings are not decrypted; coverage describes the literal
string bytes returned by Lambda, not hidden plaintext.

The response must bind the exact function ARN/name, `$LATEST`, a native revision
ID and successful read provenance to the verified account/Region. Missing or
pending/failed configuration status, denied/deleted reads, omitted/error/empty
variables, unsupported values, byte limits or incomplete engines remain UNKNOWN.
Kingfisher 1.4.0 and TruffleHog 3.92.5 run offline with credential verification
disabled; both must complete before PASS. Exact-value matches are redacted and
merged with other AWS secret findings. Native function names, variable keys,
values, revision/request IDs, raw request parameters and error text are absent
from this profile's exported evidence and request-cache keys; only opaque keyed
locators and typed scan results remain.

Bounds are 8 selected functions, 128 variables, ASCII variable keys of 2–128
characters and 4 KiB of key/value bytes per function, 8 KiB per scan input, 128 KiB per parsed SDK response and 1 MiB across
responses. A shared 60-second inspection deadline, cancellation and call budgets
are checked around SDK reads and scans; this profile caps SDK connect/read
inactivity timeouts at 3/5 seconds and disables SDK automatic retries. The
collector's bounded retries permit at most 5 attempts per selected function.
Boto3 has already allocated the complete response before the adapter checks these
limits: these are post-receipt inspection/retention bounds, not HTTP streaming or
preallocation guarantees. SDK credential resolution and a continuously arriving
response use the existing SDK transport behavior; late completion cannot become
PASS. No content files, package downloads, runtime execution or credential
validation occur. Coverage excludes other versions, runtime-injected variables,
code/packages, logs and unselected functions.

References: [GetFunctionConfiguration](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunctionConfiguration.html),
[environment response](https://docs.aws.amazon.com/lambda/latest/api/API_EnvironmentResponse.html),
[literal environment semantics and quota](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html),
and [customer-managed encryption prerequisites](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html).

## Actual service coverage

| Service | Native resource types | Collected configuration and practical limits |
| --- | --- | --- |
| STS | `aws_account` | Mandatory verified account, caller ARN and user ID; chosen/assumed context fails closed |
| IAM | `iam_user`, `iam_group`, `iam_role`, `iam_policy` | Shared paginated account authorization details; inline policies, managed policy versions, attachments, group membership, trust documents, permissions boundaries, native role last-used metadata; `PolicySources` records declarations/attribution |
| IAM account/usage | `iam_account_summary`, `iam_password_policy`, `iam_credential_report` | Summary/password policy, user access-key last use, login profile and MFA devices; selected credential-report checks may refresh a missing or expired credential report using the AWS Read-classified report API |
| S3 | `bucket`, `s3_account_public_access_block` | Region/location, bucket and account Public Access Block, policy/status, default encryption, versioning, ACL, ownership controls, logging; no objects, object ACLs, access points, replication or lifecycle inventory |
| EC2/network | `vpc`, `subnet`, `route_table`, `security_group`, `network_acl`, `network_interface`, `instance`, `ebs_volume` | Native configuration, associations, routes, SG rules, NACL order/direction, addresses, instance metadata options, EBS encryption and attachments; no user data |
| EC2 connectivity | `internet_gateway`, `nat_gateway`, `vpc_endpoint`, `vpc_peering`, `transit_gateway`, `transit_gateway_attachment`, `transit_gateway_route_table`, `vpn_connection`, `vpn_gateway` | Native connectivity declarations and endpoint policies; no transit route searches/propagation tables, firewall appliance semantics or active reachability validation |
| ELB | `load_balancer`, `classic_load_balancer`, `target_group` | Classic/v2 configuration and attributes; v2 listeners and target health; listener rules, target-group attributes and WAF associations are not collected |
| KMS | `kms_key` | Metadata, rotation and default key policy; no key material/decryption |
| CloudTrail | `cloudtrail` | Home-region trails, logging status and event selectors; shadow trails excluded, so selected regions do not prove account-wide trail coverage; no logs/events |
| AWS Config | `config_recorder`, `config_delivery_channel` | Existing recorder/channel configuration and recorder status; no rules/evaluation inventory or recorder creation |
| GuardDuty | `guardduty_detector` | Existing detectors and detector configuration; no findings, member graph or detector creation |
| RDS | `rds_instance`, `rds_cluster`, `rds_snapshot` | Native instance/cluster backup, encryption, public-access and network settings; snapshot sharing attributes; no cluster snapshot/parameter/security-option-group inventory or database contents |
| EKS | `eks_cluster` | Described cluster endpoint/access configuration, network, encryption and logging; no in-cluster objects, node groups or cluster credentials (access entries and Pod Identity associations: see the facts extension below) |
| Lambda | `lambda_function` | Listed function metadata, VPC configuration, policy and function URL; environment values and code removed (the facts extension keeps environment variable *names* only); no invocations or downloads |
| ECR | `ecr_repository` | Native encryption/tag/scanning configuration, repository policy and lifecycle policy; no images/content or registry-level enhanced-scanning settings (registry replication/policy/pull-through cache/creation templates: `ecr_registry`, facts extension) |
| CloudWatch | `log_group`, `cloudwatch_alarm` | Log-group retention/encryption metadata and metric alarms; no log events, dashboards or composite alarms |
| Secrets Manager | `secret` | Secret metadata, native rotation/KMS configuration and resource policy; **never retrieves secret values** |
| SNS/SQS | `sns_topic`, `sqs_queue` | Topic/queue attributes, parsed resource policies, native encryption and transport declarations; no subscriptions/messages |
| API Gateway | `rest_api`, `http_api` | Listed endpoint/configuration metadata; no stages, authorizers, routes, integrations or full method authorization semantics |
| OpenSearch | `opensearch_domain` | Described domain security/network/access policy configuration; no index data |
| DynamoDB | `dynamodb_table` | Table metadata/encryption/stream configuration; no records, backups, PITR or resource policies |
| Organizations | `organization_account`, `scp_policy` | Accessible account list and directly attached account SCP documents; inherited root/OU policies explicitly `not_collected`, so complete effective SCP permissions are unknown |

The IAM implementation reuses the legacy scanner's defensive read patterns
(managed/inline policy source attribution and credential last-use reads), without
importing its entrypoint, global credential/policy caches, signal handlers, or
Access Analyzer write lifecycle. Native declared grants are not asserted as
effective access: SCP inheritance, session policy, resource policies, explicit
denies, permission boundaries and conditions require further interpretation.

Native relationship evidence is retained in items and
`metadata.network_relationships`: VPC/subnet membership, SG references, route
targets, associations and gateway attachments. Every derived relationship has
`reachability:"unknown"`. Public addresses and listeners are inventory facts;
complete SG/NACL/routing/return path/endpoint/application semantics are not proven.
Incomplete inventory cannot establish isolation or end-to-end exposure.

Role and credential last-use data are AWS observations within service-dependent
tracking windows. Missing last-use values do not prove credentials or policies
are unused. Existing credential-report generation time is retained with each row;
missing/expired/not-ready reports produce `not_collected` coverage. Policy/action
usage evidence is not collected, and Access Analyzer unused-access findings are
not collected. See [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_account_authorization_details.html),
[GetAccessKeyLastUsed](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_access_key_last_used.html)
and [GetCredentialReport](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_credential_report.html).

## Verification and exact live evidence

Account IDs, profiles and resource identifiers in historical QA examples are anonymized. They are illustrative targets, not deployment defaults; original measurement counts are retained.


Unit verification: `.venv/bin/python -m pytest -q tests/test_peaso_collectors_aws.py`.
The suite currently has 47 passing tests and uses validating botocore Stubber
responses and checks pagination,
single-flight cache behavior, throttling/retry exhaustion, denial, malformed/native
responses, timeout, call/resource caps, native ID preservation, account scope,
credential-context pinning, assume-role chains/external IDs/session names,
redaction, existing-only credential reports and blocked sensitive/write APIs.

Minimal authorized live smoke performed **2026-10-10 at
17:10:03.459485+00:00**, using exact profile `example-audit-profile`, selected region
`us-east-1`, requirements `vpc` and `iam_account_summary`, and bounds
`max_calls=4`, `max_pages=1`, `max_resources=50`, `service_concurrency=1`.

| Evidence | Observed value |
| --- | --- |
| Verified account/scope | `222233334444/us-east-1` |
| Caller ARN | `arn:aws:iam::222233334444:user/testenv` |
| Native calls | `sts:GetCallerIdentity`, `iam:GetAccountSummary`, `ec2:DescribeVpcs` |
| Actual request count | 3 |
| `aws_account` | `collected`, 1 resource |
| `iam_account_summary` | `collected`, 1 resource |
| `vpc` | `collected`, 4 resources |
| Snapshot content digest | `sha256:1cef31998fb012754e3f87ad66192f413e10de1758e8ef0708d858e6e4cfbdcb` |

Only those three live APIs were exercised. The smoke establishes real SDK auth,
account identity, sealed snapshot construction and the selected reads; it does
not establish live coverage for the other services, regions, organization roles,
SSO/web identity/metadata providers, throttling or denial paths. Those paths have
stubbed evidence or documented limitations. No credential values or resource
contents were persisted, and no cloud resources were created or modified.

## Reviewed native AWS check extension

`peaso/checks/aws_extended.py` adds **36 pure native checks** with no additional
cloud calls. `peaso/rulepacks/reviewed_aws.json` records **35 exact reviewed source
associations** and one pending broader source. Sources are pinned to Prowler
`61d2cc55c4539a6b48a3cf9f3729d8f2af300882` and AWS compliance queries
`803dda1f7555ed5cea959aef30cfa0719b030d8c`; the shard preserves each evaluator
digest, rationale and official API references. The catalog lead merges all
declared root framework/control/version mappings from those exact sources;
these mappings are reference coverage, not compliance certification.
The completed merge conserves **1,027 pinned framework/control/version records**
for the 35 supported associations, verified against the registry mappings.

| Native check group | Reviewed behavior |
| --- | --- |
| IAM password policy, 7 checks | Require uppercase/lowercase/numbers/symbols; minimum length at least 14; reuse prevention exactly 24; password age 1–90 days |
| RDS, 9 checks | Automatic minor upgrades, VPC declaration, enhanced-monitoring ARN, CloudWatch log export existence; instance tag-copy excludes Aurora engines; cluster IAM authentication, Multi-AZ, tag-copy; instance snapshot encryption |
| Lambda, 3 checks | VPC declaration, dead-letter target, existing URL AWS_IAM authentication; absent URL is not applicable |
| CloudTrail/SNS/SQS, 3 checks | Declared CloudTrail/SNS KMS configuration; SQS KMS or SQS-managed encryption, preserving both source alternatives |
| ELBv2, 5 checks | Deletion protection, access logging, application-only invalid-header dropping, application-only desync mitigation, at least two distinct availability zones |
| ECR, 1 check | Lifecycle policy presence; explicit policy-not-found fails and unavailable detail is unknown |
| KMS, 1 check | Customer-managed keys are not PendingDeletion; pinned source default excludes disabled/unused keys |
| AWS Config, 1 check | Recording recorders use their account/partition's AWSServiceRoleForConfig; non-recording recorders are not applicable |
| EKS, 1 check | Version 1.28+ service encryption defaults, otherwise explicit secret-encryption resources; retains the reviewed query's full version logic |
| GuardDuty, 5 checks | Existing detector EKS audit logs, Lambda network logs, RDS login events, S3 data events and runtime-monitoring feature status; complete empty feature list fails while missing/denied lists are unknown |

ELB desync mitigation preserves `defensive`/`strictest` **or** invalid-header
dropping, rather than incorrectly failing the source's allowed alternative. EKS
default encryption is based on the collected version, not the wall clock. Missing
or malformed fields and denied detail envelopes remain `UNKNOWN`; an available
parent resource never overrides denied child evidence. Configuration declarations
do not establish network isolation, invocability or effective authorization.

The native `aws.rds.snapshot_encryption` check covers instance snapshots only.
Its related source `aws-compliance.control.rds_db_snapshot_encrypted_at_rest`
remains **pending** with `native_checks:[]` because the source combines instance
and cluster snapshots in a UNION. Cluster snapshots are not currently collected,
so the shard does not claim complete source support or inherit that source's
framework mappings. Per-instance RDS Multi-AZ/IAM checks with cluster joins and
CloudTrail's last-24-hour CloudWatch delivery predicate are also not substituted
with narrower field checks.

Verification:
`.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_extended.py tests/test_peaso_collectors_aws.py tests/test_peaso_checks.py tests/test_peaso_checks_batch.py`
passed **1,418 tests**, including 124 extension tests and 47 collector tests.
Every extended
check has passing, failing, missing, malformed and denied fixtures, with
applicability, nested-denial, threshold, compound-alternative and input-immutability
cases. Reviewed IDs/revisions are checked against the pinned manifest. No upstream
runtime code was executed and no extra live API requests were needed for these
checks.

## HackTricks / privesc facts extension (`peaso/collectors/aws_facts_ext.py`)

Loaded through `EXTENSION_MODULES` like the other `aws_facts_*` modules (read-only
`get_`/`list_`/`describe_` operations only). Secret-bearing fields are never kept:
Lambda environment *values*, Amplify `environmentVariables`/`basicAuthCredentials`/`buildSpec`,
Grafana tokens, Pod Identity `externalId`, QuickSight e-mail, Glue public keys (only
`PublicKeyCount`), KMS grant constraint values (only `ConstraintKeys` names), ESM filter
patterns (only `FilterCount`) and non-address Route 53 values (only `ValueCount`).

| Kind / enrichment | Read actions | Kept facts |
| --- | --- | --- |
| `lambda_layer_version` | `lambda:ListLayers`, `ListLayerVersions`, `GetLayerVersionPolicy` | Version metadata and parsed layer policy (absent policy = `empty`/`absent`) |
| `lambda_alias` | `lambda:ListAliases` | Alias, version and routing weights |
| `lambda_event_source_mapping` | `lambda:ListEventSourceMappings` | Source ARN, state, function, filter count, source access configuration references |
| `lambda_function` enrichment | (cached `GetFunctionConfiguration`), `lambda:GetRuntimeManagementConfig` | `EnvironmentVariableNames.names`, `RuntimeManagement.UpdateRuntimeOn`/`RuntimeVersionArn` |
| `ecr_registry` | `ecr:DescribeRegistry`, `GetRegistryPolicy`, `DescribePullThroughCacheRules`, `DescribeRepositoryCreationTemplates` | One row per account/region: replication rules, registry policy, PTC rules, creation templates (parsed `repositoryPolicy`) |
| `eks_access_entry` | `eks:ListAccessEntries`, `DescribeAccessEntry`, `ListAssociatedAccessPolicies` | Principal ARN, type, Kubernetes groups, username, associated access policies and scopes; CONFIG_MAP-only clusters are skipped |
| `eks_pod_identity_association` | `eks:ListPodIdentityAssociations`, `DescribePodIdentityAssociation` | Namespace, service account, role / target role, session-tag setting |
| `kms_grant` | `kms:ListGrants` (customer managed keys only) | Grantee/retiring principal, issuing account, operations, constraint key names |
| `cognito_identity_pool` enrichment | `cognito-identity:GetIdentityPoolRoles` | `Roles.Roles`, `Roles.RoleMappings` |
| `cognito_user_pool` enrichment | `cognito-idp:ListIdentityProviders`, `GetUserPoolMfaConfig`, `ListGroups` | IdP name/type, MFA mode and configured factors, groups with `RoleArn`/precedence |
| `opensearch_connection` | `es:DescribeOutboundConnections`, `DescribeInboundConnections` | Direction, status, mode, local/remote domain owner and name |
| `route53_record_set` (global) | `route53:ListResourceRecordSets` | Name, type, alias target, A/AAAA/CNAME/NS values, `PrivateZone` |
| `cloudformation_stack_instance` | `cloudformation:ListStackSets`, `ListStackInstances` | StackSet instance account/region/status |
| `ec2_instance_connect_endpoint` | `ec2:DescribeInstanceConnectEndpoints` | Endpoint, subnet/VPC, security groups, `PreserveClientIp`, state |
| `rolesanywhere_profile` | `rolesanywhere:ListProfiles` | Profile ARN, enabled, role ARNs, managed policy ARNs, parsed session policy, attribute mappings (trust anchors come from the existing presence inventory) |
| `imagebuilder_pipeline` | `imagebuilder:ListImagePipelines`, `ListInfrastructureConfigurations`, `GetImageRecipe` (one read per distinct recipe) | Pipeline plus joined `InstanceProfileName`; `RecipeComponents` = status + image-recipe component ARNs only (no recipe content, component parameters, block devices or user data; a denied/failed read keeps its status) |
| `sagemaker_user_profile`, `sagemaker_domain` enrichment | `sagemaker:ListUserProfiles`, `DescribeUserProfile` | Execution role (`user_settings` or `domain_default`), domain default user/space roles |
| `sagemaker_cluster` | `sagemaker:ListClusters`, `DescribeCluster` | HyperPod instance groups with execution roles |
| `grafana_workspace`, `quicksight_user`, `supplychain_instance`, `amplify_app` | `grafana:ListWorkspaces`, `quicksight:ListUsers`, `scn:ListInstances`, `amplify:ListApps`, `ListBackendEnvironments`, `ListBranches` | Service-plane presence (ARN, status, role), Amplify backend environments and branch metadata without build specifications or secret values |
| `aws_identity_center_account_assignment` | `sso:ListAccountsForProvisionedPermissionSet`, `ListAccountAssignments`, `identitystore:ListGroups` | Permission set / account / principal type and id, group display name |
| `glue_dev_endpoint` (existing) | unchanged | adds `PublicKeyCount` |
| `codedeploy_deployment_group` (existing) | unchanged | adds EC2/on-prem tag filters and tag sets, Auto Scaling groups |
| `athena_session` | `athena:ListWorkGroups`, `ListSessions`, `GetSession` | Session ID, workgroup, state, engine, notebook version and exact execution role; endpoint and notebook tokens are never requested |

The current customer role template grants `athena:ListWorkGroups`, `athena:ListSessions` and
`athena:GetSession` for existing-session privilege-path analysis. If a customer supplies an
equivalent role instead of the template, it needs all three reads; a denied session read
leaves the role path unresolved.

Customer policy: 41 actions added to `VERIFIED_ACTIONS` (431 -> 472; each checked against the
pinned policy-generator action list) and the `supplychain -> scn` IAM prefix. Regenerated
`infra/aws/customer-role.json`: 470 actions (was 429) in the same 3 managed policies of
6102 / 6122 / 3265 characters (limit 6144 each; previously 6136 / 6141 / 1958).
Follow-up: `imagebuilder:GetImageRecipe` added to `VERIFIED_ACTIONS` (Image Builder recipe
component ARNs for `consumer_input_writable_via`); regenerated template: 471 actions in the same 3
managed policies of 6102 / 6123 / 3294 characters. The action name follows the Image Builder
Service Authorization Reference; it was not re-checked against the pinned policies.js offline.

Consumers: `peaso/privesc/effective_permissions/aws.py` (Cognito group/identity-pool roles,
CodeDeploy instance roles, Roles Anywhere profiles/trust anchors, Image Builder/SageMaker/HyperPod
hosts (Image Builder recipe component ARNs -> `{target.consumer_input_arn}` = `component/<name>/*`), service planes, Identity Center group assignments) and
`peaso/checks/hacktricks_bp_aws_ext.py` (9 HackTricks Best Practices checks: layer policy,
runtime pinning, credential-like env var names, ECR registry policy / replication / creation templates, EKS access entry
principal, KMS grant grantee, OpenSearch connection peer). Trust-boundary checks treat the
audited account, collected `organization_account` members and `metadata.trusted_scope_ids`
as trusted; out-of-account parties without the organization inventory are `MANUAL`.

Verification: `tests/test_peaso_collectors_aws_ext.py` (validating botocore Stubber, one
response per call), `tests/test_peaso_checks_hacktricks_bp_aws_ext.py`,
`tests/test_peaso_privesc_aws_ext_facts.py`.

## Organizations policy evidence

Three native inventories share the collector's existing request cache, retry,
pagination, cancellation and resource budgets:

* `organization_effective_scp` lists organization accounts, follows every member
  account's parent chain to its root, and reads the SCP attachments and documents
  at every level. `TargetAccountId` identifies the assessed member; `AccountId`
  remains the authenticated collection owner. This distinction prevents global
  collection normalization from merging different member accounts. Denied parent
  or document reads, malformed identities, cycles and truncated pages remain
  incomplete. The management account is explicitly exempt from SCP restrictions.
* `organization_tag_policy` reads TAG_POLICY attachments on the authenticated
  account's complete account/OU/root path. It projects only literal `@@assign`
  tag keys and values. Merge operators, wildcards and ambiguous definitions stay
  UNKNOWN. Matching an attached declaration does not establish effective merged
  policy enforcement or that all resources have the required tags.
* `organization_resource_policy` reads the organization resource-based delegation
  policy. The documented `ResourcePolicyNotFoundException` produces a verified
  empty Statement list, allowing an absent delegation policy to fail the check.
  AccessDenied and arbitrary missing/malformed responses do not prove absence.

Policy IDs, ARNs, organization, owner account, partition and attachment paths are
joined before a complete inventory is emitted. AWS-managed FullAWSAccess is
recognized by its distinct AWS-owned ARN. Organization account `State` is used
when supplied; the legacy `Status` field remains supported.

For the two organization SCP checks, supply approved policy inputs through
`options.compliance_policy.aws_organizations`, for example:

```json
{
  "status": "collected",
  "scope": "123456789012/global",
  "audited_account_ids": ["234567890123"],
  "allowed_instance_types": ["t3.micro"],
  "approved_break_glass_principals": []
}
```

For several collection accounts, place those scoped objects in
`aws_organizations.by_scope`, keyed by `<collection-account>/global`. Approved
values are operator policy inputs; they do not substitute for native facts.
The tag-policy check consumes `options.compliance_parameters.approved_ec2_tag_values`,
for example `{"Environment": ["Production", "Test"]}`. Explicit legacy policy
locations retain precedence. Missing approved values remain UNKNOWN.

`organizations:DescribeResourcePolicy` is required in addition to the existing
Organizations describe/list permissions. SCP reads generally require management
or authorized delegated-administrator access; unavailable organization visibility
is retained as a coverage limitation. References:
[AWS SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html),
[tag policy syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_example-tag-policies.html)
and [DescribeResourcePolicy](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeResourcePolicy.html).

## Deployed API Gateway stage evidence

`rest_api_method` resolves each REST stage's `deploymentId` through
`GetDeployment(embed=['apisummary'])`. Its routes describe the deployed snapshot,
rather than undeployed resources currently being edited. Stage ARN, API ID,
deployment ID, route path and HTTP method remain bound in every row. An absent
or malformed deployment summary, a failed child read, or a canary receiving
traffic keeps the inventory incomplete. No API endpoint is invoked.

`stage_waf_association` queries `GetWebACLForResource` for the exact regional REST
stage ARN and validates the returned ACL's account, partition, region and ID.
Only a successful response without a WebACL proves no association. An access
denial or WAFNonexistentItemException remains unavailable. The check compares
that effective association with the stage's declared ACL and the collected ACL
inventory; it does not substitute the declaration for a successful WAF read.

Both inventories share the existing API/stage listing cache. The cache-encryption
check understands documented `*/*` / `/*/*` wildcard settings and encoded or
unencoded resource paths, including per-method overrides. Conflicting duplicate
spellings, partial wildcard semantics and ANY routes with method-specific
overrides remain UNKNOWN. No field omission is converted into an assumed safe
caching value. A native `cacheClusterEnabled=false` together with
`cacheClusterStatus=NOT_AVAILABLE` establishes that no cache exists and yields
NOT_APPLICABLE; transitioning or inconsistent cache states remain UNKNOWN. References:
[GetDeployment](https://docs.aws.amazon.com/apigateway/latest/api/API_GetDeployment.html),
[GetStage native output](https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-stage.html)
and [GetWebACLForResource](https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACLForResource.html).

## IAM attachment identities and CloudWatch metric metadata

`iam_identity` requests `GetAccountAuthorizationDetails` with
`Filter=["User", "Group", "Role"]`, excluding managed-policy definitions that
are unnecessary for attachment checks. The three identity projections reuse
identical cached response pages, request up to the API's supported 1,000 items
per page, and retain pagination limits. AWS may still return fewer items per
page. Every projected principal ARN is joined to its native type, account and
partition. Only attached policy ARNs are retained; inline policy contents,
passwords, access keys and usage-report generation are not part of this inventory.

The approved required policy comes from
`options.compliance_parameters.required_policy_arn`. Both current-account
customer-managed and AWS-managed policy ARNs are supported. A policy in another
account or partition remains UNKNOWN. This checks direct attachment to each
identity, not effective permissions or a policy inherited through a group.

`cloudwatch_metric` requests `ListMetrics(IncludeLinkedAccounts=false)` and emits
stable identities from namespace, metric name and sorted dimension metadata.
It does not read metric values. ListMetrics can take up to 15 minutes to show a
new metric and omits metrics without reported data in the preceding two weeks;
metric presence does not prove fresh ingestion or successful ECR event delivery.
The ECR export check combines these metadata with a collected EventBridge rule
and target, using the approved `metric_ingestion_target_arn`,
`ecr_scan_metric_namespace` and `ecr_scan_metric_name` parameters.

The added read permission is `cloudwatch:ListMetrics`; IAM authorization metadata
uses the existing read permission. References:
[GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
and [ListMetrics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_ListMetrics.html).

## Scoped transport endpoint declarations

`transport_endpoint` joins ELBv2 listeners to their load balancer's account,
region and scheme; API Gateway REST custom domains to their endpoint types and
security policy; and every account-owned CloudFront distribution to its viewer
protocol and minimum TLS policy. Private API domains and internal load balancers
are retained as non-external. Every CloudFront cache behavior is inspected, so
an HTTP-capable path cannot be hidden behind a secure default behavior. All
CloudFront pages must have consistent quantities, continuation flags and cursors.

The two SC-8 checks consume
`options.compliance_policy.sw38_policy = {"status":"collected", "scope":"123456789012/eu-west-1", "approved_tls_policies":["TLS_1_2", "TLSv1.2_2021", "ELBSecurityPolicy-TLS13-1-2-2021-06"]}`.
For several regions, place these scoped objects under `sw38_policy.by_scope`.
Legacy direct `metadata.sw38_policy` retains precedence. This is an explicit
approved policy set; no TLS baseline is silently assumed.

Missing source families and unsupported TCP/UDP passthrough semantics remain
UNKNOWN. These checks cover the three declared endpoint families, including
REST custom domains; they do not establish TLS for every arbitrary application
socket, API default hostname or backend connection. They do not probe endpoints
or verify peer certificates, negotiated ciphers or runtime reachability. Origin
headers, arbitrary CDN configuration and domain descriptions are omitted from
these projected snapshots. No new IAM read actions are needed for this inventory.

### Identity Center account assignment and enabled-user evidence

Native `identity_center` evidence joins regional `ListInstances` and
`ListPermissionSets` results to `ListAccountAssignments` for the exact audited
account. Direct users are resolved with Identity Store `DescribeUser`; group
assignments expand every `ListGroupMemberships` page and resolve each current
member's native `UserStatus` (`ENABLED` or `DISABLED`). The check
`aws_identity_center_sso_configured` requires an enabled user assignment. A real
ACTIVE instance with complete empty assignments or only disabled users yields
FAIL; an enabled direct/group user yields PASS. Both the group and user lookups
are cached per exact identity store and ID within the read, alongside the shared
request cache. An explicit resource limit also bounds the expanded assignment
count, preventing nested groups/permission sets from bypassing scan limits.

An empty **regional** instance listing does not establish account-wide absence;
SSO may use a different home region. It yields UNKNOWN with
`identity_center_home_region_unresolved`. Missing/unsupported instance or user
status, wrong account/permission-set/instance/store/user/group bindings,
duplicates, denied reads and incomplete pagination likewise remain UNKNOWN.
The collector never substitutes “has an assignment” for “user is enabled.”

The snapshot retains only service IDs, assignment relationships, current user
status and read-operation provenance; user name, email, phone, display name,
photo and other profile fields are omitted. This validates configuration and
assignment state, not a tested interactive login, MFA, federation availability,
or downstream entitlement. No user/session/token is created.

In addition to existing `sso:ListInstances`, `sso:ListPermissionSets` and
`sso:ListAccountAssignments`, the adapter requires two metadata permissions:
`identitystore:DescribeUser` and `identitystore:ListGroupMemberships`. Their
operation-to-IAM mappings are listed in the
[Identity Store service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_identitystore.html).
The native enabled/disabled field is documented by
[DescribeUser](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_DescribeUser.html).
These reads do not request secret values or grant KMS decryption or mutation.

### Enabled-region and Shield metric-region evidence

Native `aws_region` reads complete `DescribeRegions(AllRegions=True)` state and
emits only the exact requested region, with the provider's `OptInStatus` and its
explicit enabled/disabled interpretation. Missing regions, duplicate identities,
foreign partitions, unrecognized opt-in states and denied/incomplete reads remain
UNKNOWN. The CloudTrail-per-region check also requires the existing complete
account-wide `cloudtrail_account_inventory`; an explicit partial region scan
cannot prove that account inventory. Automatic account-only region discovery
shares the same cached DescribeRegions response with this adapter.

Native `shield_protection_region` projects each actual `ListProtections`
resource ARN to its CloudWatch metric region. Regional load balancers and Elastic
IPs retain their resource ARN region. AWS documents CloudFront and Route 53
Shield metrics in `us-east-1`; those global protections are assessed there.
Global Accelerator/other unsupported global metric-region joins remain UNKNOWN,
without guessing a region or silently dropping a protection. Duplicate IDs or
resources, foreign owners/partitions, incomplete pagination and API failures
(including ResourceNotFoundException) do not establish verified absence. A
successful complete empty protection listing yields NOT_APPLICABLE. Names and
unrelated protection configuration are omitted. All regions share the existing
account-global request cache; no subscription or protection is created.

For `aws_shield_ddos_detected_alarm`, `DDoSDetected` is binary. A configured alarm
must match exactly the protection's ResourceArn dimension, have enabled nonempty
actions, and breach at attack value 1 while remaining non-breaching at quiet
value 0. Valid configurations use `GreaterThanThreshold` with a threshold in
`[0,1)`, or `GreaterThanOrEqualToThreshold` with a threshold in `(0,1]`.
Less-than comparisons, `GreaterThanThreshold: 1`, always-breaching thresholds,
disabled actions and nonexistent extra metric dimensions do not satisfy the
control. Missing or unsupported comparison operators remain UNKNOWN. This is
configuration validation, not a generated DDoS event or a notification-delivery
test. Only the existing `ec2:DescribeRegions` and `shield:ListProtections` IAM
permissions are used.

References: [DescribeRegions](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html),
[Shield metric reporting locations and DDoSDetected](https://docs.aws.amazon.com/waf/latest/developerguide/shield-metrics.html),
and [ListProtections](https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_ListProtections.html).

### Direct EC2 public-ingress configuration witnesses

`ec2_effective_ingress` computes bounded positive witnesses for the two effective-public-exposure controls. Selecting it also retains nine independent, complete, same-account/region native inventories: instances, interfaces, VPCs, subnets, security groups, network ACLs, route tables, internet gateways and VPC Block Public Access options. These use existing read-only EC2 Describe permissions; no traffic probes or cloud mutations occur. The signed predicates independently recompute each witness from those original inventories rather than trusting projection booleans.

A supported witness binds a running instance to its attached ordinary ENI, matching primary private/public IPv4 mapping, available subnet and VPC, active unique longest-prefix return route to the VPC's attached internet gateway, an attached CIDR security-group ingress allowance, and ordered NACL ingress plus return allowances for the exact TCP/UDP destination/source ports. Regional BPA must explicitly be `off` in `default-state` or `update-complete`. Gateway edge route-table associations, managed ENIs and unsupported translations are not admitted. Native field references accompany each proof. This demonstrates a configured allowance; application listening and packet delivery remain unknown.

This adapter never sets `joins_complete`, never emits PASS, and never claims all public paths were examined. A bounded search that finds no witness remains UNKNOWN, including closed direct paths, IPv6, load balancers, secondary-address mappings, BPA exclusions, appliance paths, denied/partial inventories and ambiguous or conflicting associations. The previously accepted explicit complete join contract retains its existing behavior.

AWS references: [internet gateway requirements](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html), [gateway edge routes](https://docs.aws.amazon.com/vpc/latest/userguide/gateway-route-tables.html), [BPA modes and state](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_VpcBlockPublicAccessOptions.html).


## Native operational groups

The `recovery_group` and `capacity_group` collectors accept grouping and minimum-capacity decisions in `options.compliance_parameters.operational_groups`. The declaration supplies intent only. EC2/RDS placement, lifecycle state and Auto Scaling configured capacity come from paged native read-only APIs. Hosted intake validates the same policy and rejects supplied observations. No extra IAM actions beyond the existing EC2, RDS and Auto Scaling inventory reads are required.

Example owner declaration for one selected account/region:

```json
{"compliance_parameters":{"operational_groups":{"recovery_groups":[{"scope":"123456789012/us-east-1","id":"critical","members":[{"kind":"instance","id":"i-11111111111111111"},{"kind":"rds_instance","id":"database"}]}],"capacity_groups":[{"scope":"123456789012/us-east-1","id":"workers","autoscaling_group_arn":"arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:11111111-1111-1111-1111-111111111111:autoScalingGroupName/workers","minimum_capacity":2,"capacity_unit":"units"}]}}}
```

`aws.nist.sc_36_coverage` evaluates the approved members' actual running EC2 or available RDS primary availability zones; it does not invent standby placements. `aws.nist.sc_5_2_coverage` compares the approved minimum with actual configured Auto Scaling `DesiredCapacity` in the matching `units`, `vcpu` or `memory-mib` unit and configured availability zones. This is configuration evidence, not proof of healthy runtime capacity. Missing policy, members, complete inventory, usable native state, or matching scope yields UNKNOWN.



### SSM inventory read events: observed CloudTrail management-event window

The native `ssm_inventory_read_event` producer supports the frozen `aws_ssm_software_inventory_enumeration` predicate. It reads all returned pages for exactly `GetInventory` and `ListInventoryEntries` using `cloudtrail:LookupEvents`, at the actual selected AWS account and Region. The configured `activity_minutes` window uses a single captured end time and the existing call/page/resource/deadline budgets and CloudTrail pacing. No SSM inventory payload, agent installation, remote execution or mutation is performed by this new producer.

The approved reader set is normative input only:

```json
{"compliance_parameters":{"approved_inventory_reader_arns":["arn:aws:iam::123456789012:user/inventory-reader"]}}
```

Only this unique bounded principal-ARN list is projected into the signed predicate's `metadata.compliance_inputs` namespace. No event, success, completeness or authorization observation is accepted from this field. Invalid lists fail before credentials or API calls. Missing approval remains UNKNOWN. The predicate compares the actual CloudTrail actor ARN literally; an STS assumed-role session ARN is not silently replaced by its issuer role ARN.

At the SDK response boundary, before any cache or Future retains a response, each CloudTrail body is parsed with duplicate-key rejection. Its event ID/name/source/time must agree with the outer event and exact query. It must explicitly identify a read-only management `AwsApiCall`, recipient account, Region and actor ARN. The projection retains only these identifiers, the actual success/error outcome and bounded window provenance. Access key IDs, requests, responses, messages and other body fields are discarded. No error code means recorded success; a nonempty native error code means failure; ambiguous error metadata is unavailable.

A successful observed read by an unapproved actor yields FAIL. Complete returned pages with only approved successful reads, denied API attempts, or no matching reads can yield PASS under the existing frozen predicate. This means only **the collected management-event history in the stated window**: it does not prove effective IAM restrictions, delivery completeness, older activity, application behavior or a global absence of unauthorized reads. Missing actor/category fields, duplicate IDs, conflicting/foreign scope, malformed events, out-of-window events, denied queries, pagination limits or an unavailable second query never become successful empty coverage. Collection failure discards earlier successful query rows.

No new customer-role grant is introduced; `cloudtrail:LookupEvents` is already required by the existing native collector. Primary contracts: [Systems Manager CloudTrail integration](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html), [CloudTrail LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html), and [CloudTrail event record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html).



### Native AWS Budgets stop-action configuration

`aws_budgets_stop_action` has an additive native API dialect. The historical imported evidence dialect remains separate; native responses are never translated into fictional `SsmActionDefinition.DocumentArn`, `TargetRoleArns`, or `ActionStatus` fields.

The collector reads all `DescribeBudgetActionsForAccount(AccountId=STS-account)` pages, then `DescribeBudgetAction(AccountId, BudgetName, ActionId)` for each action. Response account, budget name and UUID must match; projected LIST/detail configurations must agree. Complete results use the account-wide `<account>/global` `budget_action` collection. Denials remain DENIED. Limits, missing/malformed fields, changed configuration, duplicate/foreign identities and unavailable reads cannot become complete empty inventories. Subscriber addresses and irrelevant IAM/SCP definition details are stripped.

The actual SSM definition is `Definition.SsmActionDefinition` with `ActionSubType`, `InstanceIds`, and `Region`; other native fields are `ExecutionRoleArn`, `Status`, `ApprovalModel`, `NotificationType`, and `ActionThreshold`. Native stop subtypes/targets, finite positive thresholds, states and approval/notification enums are validated. Execution-role account/partition must agree with real STS identity; target-region partition is checked using SDK endpoint metadata. The evaluator independently verifies exact native source operations, schema integer 1 (not boolean True), read-only/detail flags, caller partition/account, complete membership, scope and configuration shape.

The provider-bound normative declaration is `options.compliance_parameters.aws_budget_stop`:

```json
{"scope":"123456789012/global","status":"collected","authorized_by":"security-owner","document_id":"budget-stop-review","observed_at":"2026-10-15T00:00:00Z","expires_at":"2026-10-16T00:00:00Z","budgets":{"reviewed-budget":{"ActionSubType":"STOP_EC2_INSTANCES","Region":"us-east-1","InstanceIds":["i-0123456789abcdef0"],"ExecutionRoleArn":"arn:aws:iam::123456789012:role/BudgetStop","ApprovalModel":"AUTOMATIC","NotificationType":"ACTUAL","ActionThreshold":{"ActionThresholdType":"PERCENTAGE","ActionThresholdValue":90}}}}
```

Each reviewed budget has one explicit desired stop configuration. At least one native action for that budget must match target set, subtype, region, execution role, threshold/type, notification and approval model exactly, with status STANDBY or EXECUTION_IN_PROGRESS. Known other states, including PENDING/EXECUTION_SUCCESS and reverse/reset/failure states, do not meet this ready-action predicate. A past execution does not prove instances remain stopped. Unfamiliar states are UNKNOWN. A known IAM/SCP action without a suitable SSM peer FAILs this configuration obligation. Unreviewed budgets and missing/foreign/expired policies remain UNKNOWN. Complete zero-action inventory yields EMPTY, not a fabricated budget failure or security PASS. Budgets with no actions are not separately inventoried; this resource-targeted check does not prove every account budget has an action.

Owner inputs select obligations and cannot supply Status, provenance, completion or execution observations. Hosted/local intake validates the same namespace. Existing compliance-policy namespaces remain unchanged; obligations use existing `metadata.parameters`. Approval is checked at evaluation-time UTC; replay after expiry becomes UNKNOWN rather than extending approval using snapshot capture time.

PASS means the matching native stop action is configured in a ready/in-progress state. This path does not observe successful execution, runtime IAM effectiveness, instance existence/state, threshold crossing, notification delivery or eventual behavior. No action execution, SSM command, resource creation, stop call, secret access or create/update/delete occurs.

Two new read permissions are required: `budgets:DescribeBudgetActionsForAccount` on `*`, and `budgets:DescribeBudgetAction` on applicable budget-action ARNs (or `*` in the existing generated inventory-role structure). The private policy-generator patch adds exactly those reviewed mappings; no role template is changed or published. Hosted availability requires a separately published role-version update.

Primary references: [Action](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_budgets_Action.html), [SsmActionDefinition](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_budgets_SsmActionDefinition.html), [account LIST](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_budgets_DescribeBudgetActionsForAccount.html), [action detail](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_budgets_DescribeBudgetAction.html), [configuration semantics](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-controls.html), and [IAM mappings](https://docs.aws.amazon.com/service-authorization/latest/reference/list_budgets.html).


### DNS Firewall evidence limits

The managed-domain-list check evaluates configuration facts. A BLOCK rule's
membership alone cannot prove unconditional filtering: ALLOW and ALERT terminate
matching, and query types or redirection settings can restrict enforcement. The
current evaluator returns UNKNOWN for mixed actions with apparently complete
BLOCK coverage, any query-type restriction, unsupported redirection semantics,
or a rule with an explicit lifecycle status other than COMPLETE. Synchronous
rules may omit status according to the AWS API. Complete absence of an approved
BLOCK remains FAIL; simple complete all-BLOCK evidence retains its prior verdict.
This change does not add a native DNS Firewall producer or establish effective
DNS filtering, domain-list overlap, VPC coverage, or execution behavior.

References: [AWS evaluation order](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-overview.html)
and [FirewallRule schema](https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_FirewallRule.html).


### Cosign Simple Signing contract

The provenance predicate verifies the original payload bytes against an explicitly approved signing public key. It reads `critical.image.docker-manifest-digest` and requires `critical.type` to equal `cosign container image signature`. The previous invented root `subject.digest` payload is unsupported. The outer OCI subject, selected deployed digest, exact collection scope/completeness and approved key ID remain required. Reformatting a signed JSON payload invalidates its signature; the evaluator never rewrites it.

Duplicate JSON members, non-JSON constants, unknown top-level/critical fields, malformed critical objects and unsupported types produce UNKNOWN. A correctly parsed signature for another digest or a cryptographically invalid signature does not verify. Cosign explicitly ignores `critical.identity.docker-reference`; matching image content may be portable across repositories. This does not introduce repository trust policy. Optional claims may be an object or null: null is emitted by official Cosign output with no optional claims.

Primary references: [Cosign signature specification](https://github.com/sigstore/cosign/blob/63d9aa14a70c03e73c7b2a2a9a6501566194f5f4/specs/SIGNATURE_SPEC.md), [pinned underlying Simple Signing JSON rules](https://github.com/containers/image/blob/a5061e5a5f00333ea3a92e7103effd11c6e2f51d/docs/containers-signature.5.md#json-data-format), and [actual lower-case payload with optional:null](https://github.com/sigstore/cosign/blob/63d9aa14a70c03e73c7b2a2a9a6501566194f5f4/README.md#L319). The specification's example capitalized digest key is a typo; the normative schema and actual payload use lower-case `docker-manifest-digest`.

This correction does not add native ECR collection. DescribeImages/artifact media types alone prove neither a parsed SBOM nor a verified signature. Actual bounded payload acquisition, OCI content-digest verification and genuine deployment selection remain necessary; no global native coverage or full CSPM completion is claimed.


### SageMaker Clarify native metadata joins

The native Clarify path enumerates all endpoints in each explicitly selected account/Region, reads each endpoint/configuration, and verifies every production/shadow variant's model through DescribeModel. Only stable InService endpoint configurations get verified model linkage; transitional, foreign, malformed, denied or partial sources cannot establish coverage.

Complete monitoring schedule metadata uses the real AWS Scheduled/Pending/Failed/Stopped vocabulary. Scheduled is the active state; the former ENABLED fixture value is unsupported. Processing job records remain a complete inventory. A non-Clarify native image can be ignored without manufacturing an endpoint. Potential Clarify jobs require DescribeProcessingJob.MonitoringScheduleArn joined to exactly one native ModelBias schedule and exactly one ListMonitoringExecutions record with matching ProcessingJobArn, endpoint, schedule, type and completed execution. A missing schedule ARN, conflicting or missing execution is UNKNOWN, rather than invented EndpointLinkedInput=false. An unrelated native job plus a valid witness can pass; an unresolved potentially-Clarify job stays UNKNOWN.

The owner must provide compliance_parameters.clarify_monitoring_interval_days as a positive integer; it is never inferred from observed jobs. Every enumerated endpoint needs an active schedule and an actual recent completed linked Clarify-image job. This verifies configuration/execution metadata, not model fairness, report contents, container image provenance or bias thresholds. No report, training/input data, model content, container arguments or environment is emitted. Reads share the existing pagination, deadline, cache and resource limits.

Three additional read permissions are required: sagemaker:ListEndpoints, sagemaker:DescribeEndpoint, sagemaker:ListMonitoringExecutions. The implementation declares these operations but does not change a role; a current underprivileged connector returns DENIED/UNKNOWN until explicitly granted. Existing DescribeEndpointConfig, DescribeModel, DescribeProcessingJob and ListMonitoringSchedules grants are reused.

Primary API references: [DescribeEndpoint](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeEndpoint.html), [DescribeEndpointConfig](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeEndpointConfig.html), [DescribeModel](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeModel.html), [DescribeProcessingJob](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeProcessingJob.html), [ListMonitoringSchedules](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ListMonitoringSchedules.html), and [ListMonitoringExecutions](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ListMonitoringExecutions.html).


### Optional native Resolver DNS Firewall configuration

The explicit owner policy `options.compliance_parameters.aws_resolver_firewall` is a list of `{"scope":"123456789012/us-east-1","vpc_id":"vpc-12345678","approved_managed_domain_list_ids":["rslvr-fdl-example"]}`. Scope and list approval are normative declarations, never observations. No policy defaults are supplied: absent policy yields UNKNOWN; an explicitly empty designation list yields EMPTY after native VPC enumeration. A designated VPC absent from the complete native inventory yields UNKNOWN. Hosted intake rejects this namespace for other providers.

Native evidence reuses scan-local STS identity and DescribeVpcs, lists every DNS Firewall association without filters, and paginates ListFirewallRules per exact associated group. ListFirewallDomainLists verifies approved IDs exist in the actual Region/partition and have managed owner `Route 53 Resolver DNS Firewall`. API list ARNs, VPC ownership, association ARN/account/Region, unique native IDs/priorities and group joins are checked. Only COMPLETE associations and synchronous rules (Status absent) or explicit COMPLETE rules can support a result. Explicit unknown status, transitions, malformed/foreign facts, unsupported advanced rules and incomplete pages cannot produce PASS. Denials retain DENIED.

The existing signed SW44 predicate remains byte-identical. Literal BLOCK configuration can PASS, complete absence of an approved BLOCK can FAIL, while mixed ordered actions, restricted query types/redirection and custom override behavior remain UNKNOWN. This verifies configured rules, without probing DNS behavior, claiming fail-open outage behavior, or proving runtime traffic filtering. All selected VPCs are joined against actual native inventory; arbitrary child lists or fabricated coverage flags are not used.

The one additional metadata grant is `route53resolver:ListFirewallDomainLists` on `*` (the action has no resource-level ARN support). Existing role grants already cover DescribeVpcs, ListFirewallRuleGroupAssociations and ListFirewallRules. `proposed-grant.json` is a proposal only: neither customer role templates nor deployed roles are changed. Missing permission yields DENIED, never PASS. No live validation has been performed.

Primary API references: https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_ListFirewallDomainLists.html ; https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_ListFirewallRuleGroupAssociations.html ; https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_ListFirewallRules.html . Managed-owner example: https://docs.aws.amazon.com/cli/latest/reference/route53resolver/list-firewall-domain-lists.html . IAM resource bounds: https://docs.aws.amazon.com/service-authorization/latest/reference/list_route53resolver.html .

### Native CodeCommit review approvals

The `codecommit_pull_request` inventory uses complete paginated ListRepositories,
OPEN and CLOSED ListPullRequests, GetPullRequest, DescribePullRequestEvents and
GetPullRequestApprovalStates. A merged target is joined to exactly one provider
merge event by repository, destination branch and merge commit. Its internal
`MergedAt` is that event's real `eventDate`; CodeCommit's MergeMetadata response
has no timestamp field. Approval actors, decisions and timestamps are read from
approval-state events for the exact current PR revision and joined to that
revision's current approvals. No approval-rule content, descriptions, titles,
source files or repository source is retained, including in the request cache.

The operator explicitly supplies `compliance_policy` with `status: collected`,
`scope: ACCOUNT/REGION`, and nonempty, unique `security_reviewer_arns` from that
same account/partition. This is reviewer selection, not an observation that any
review occurred. Collection requires that exact single selected scope. Hosted
and local intake reject malformed and foreign-provider reviewer declarations;
the collection library also validates them before authentication/API calls.
Known lack of a qualifying independent approval produces FAIL. Unmerged PRs
are not applicable. Missing or ambiguous merge history, incomplete pagination,
foreign identities and unresolved revision/target joins remain UNKNOWN; actual
permission denial remains DENIED. Only single-target PRs are supported.

Five additional IAM reads are proposed: ListRepositories with Resource `*`, and
ListPullRequests, GetPullRequest, DescribePullRequestEvents and
GetPullRequestApprovalStates scoped to own-account CodeCommit repository ARNs.
No source/content, GitPull, writes, credentials, PassRole or IAM changes are
required. Installing this source alone does not grant those permissions.
Configuration can race during a scan; this is provider metadata review evidence,
not a transactional attestation of the development process or code quality.
Control Tower AI-account classification and Bedrock application-to-policy active
state remain separate unresolved contracts; this producer does not close them.

Primary API and permission references:

- https://docs.aws.amazon.com/codecommit/latest/APIReference/API_ListPullRequests.html
- https://docs.aws.amazon.com/codecommit/latest/APIReference/API_DescribePullRequestEvents.html
- https://docs.aws.amazon.com/codecommit/latest/APIReference/API_PullRequestMergedStateChangedEventMetadata.html
- https://docs.aws.amazon.com/codecommit/latest/APIReference/API_MergeMetadata.html
- https://docs.aws.amazon.com/codecommit/latest/APIReference/API_GetPullRequestApprovalStates.html
- https://docs.aws.amazon.com/service-authorization/latest/reference/list_codecommit.html


## Native CloudTrail delivery simulation and retained Macie evidence gap


### Macie remains unresolved

`aws.pci.s3.sensitive_auth_data_findings` requires exactly one complete, authorized `macie_scan_coverage` envelope matching the owner's approved bucket ARNs, before evaluating `macie_finding` records. Those authorization and coverage booleans are not native Macie response fields.

`DescribeClassificationJob` exposes selection, sampling, job status and approximate processing statistics. `COMPLETE` and `samplingPercentage=100` describe the configured job and eligible objects; they do not prove every object/version in each approved bucket was analyzed. Macie can skip unsupported/encrypted/inaccessible objects and partially analyze archives. Empty findings do not establish absence of sensitive data. `GetResourceProfile` and `ListResourceProfileArtifacts` are automated-discovery profile evidence, not a complete, fixed object/version manifest for a classification job. Full per-object discovery results are separately exported records; this collector does not read object bodies or invent an inventory/scan join.

No `authorized=true` or `complete=true` is manufactured, no Macie finding-only producer is added, and this control remains UNKNOWN with its actual evidence gaps. The earlier configuration-coverage collector continues to describe configuration only.

References: [job API](https://docs.aws.amazon.com/macie/latest/APIReference/jobs-jobid.html), [job results](https://docs.aws.amazon.com/macie/latest/user/discovery-jobs-manage-results.html), [supported objects](https://docs.aws.amazon.com/macie/latest/user/discovery-supported-storage.html), [classification errors](https://docs.aws.amazon.com/macie/latest/user/discovery-coverage-remediate.html).

### CloudTrail alternative

This adapter currently supports the commercial `aws` partition; other partitions remain unresolved. The new native `cloudtrail_trail` inventory reads home-region trails with `DescribeTrails(includeShadowTrails=False)`, then `GetTrailStatus` and `GetEventSelectors`. Native omission of either CloudWatch destination field is recorded as empty configuration. Foreign identities, duplicate trails, inaccessible reads and partial enumeration cannot certify an inventory.

`cloudtrail_delivery_permission` binds a delivery role and log-group ARN to one active, same-account, same-region trail. `GetRole` must return the exact role ARN/name. Only supported CloudTrail `sts:AssumeRole` trust statements are evaluated; `aws:SourceArn` and `aws:SourceAccount` conditions use the observed trail/account. Unknown conditions, policy variables, unsupported principal forms and ambiguous shared role/group pairs remain unresolved. Explicit matching trust denies win.

`GetContextKeysForPrincipalPolicy` must supply a complete key list. Only native `aws:RequestedRegion` can be supplied as simulation context; other keys remain UNKNOWN. `SimulatePrincipalPolicy` evaluates exactly `logs:CreateLogStream` and `logs:PutLogEvents` on the documented concrete base log-stream ARN, not the log-group ARN. All pages, both action identities, resource bindings and empty top-level/per-resource missing-context lists must be verified. Boundary/organization decision contradictions cannot pass. No policy, boundary, resource-policy, exclusion or caller override is accepted by the request guard.

The existing signed predicate is unchanged. PASS means supported trust plus an allowed IAM simulation for this concrete base stream. It does not attest live event receipt, SCP/RCP coverage, resource-policy authorization, future numbered streams or all-region/organization delivery. Organization and multi-region trails are explicitly unresolved. No CloudTrail role is assumed and no log events are read or sent.

References: [CloudTrail stream naming](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-log-group-log-stream-naming-for-cloudtrail.html), [required role permissions](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html), [simulation API and limits](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html), [context-key API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetContextKeysForPrincipalPolicy.html).

### Required IAM reads and validation scope

The adapter requires three metadata reads: `iam:GetRole`, `iam:GetContextKeysForPrincipalPolicy` and `iam:SimulatePrincipalPolicy`, scoped to `arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*`. The [IAM authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html) supports role resources for each. Append reviewed statements to the fourth managed policy; keep the first three documents byte-identical and preserve the existing 6144-byte policy limits. The policy mapper also needs an explicit, single-operation simulation read exception. The default metadata role scopes these reads to roles in the audited account. No role assumption or CloudTrail writes are needed.

An active trail without its CloudWatch destination or delivery role produces FAIL. Access denials and unresolved context remain unavailable evidence. Empty inventory does not establish positive delivery or permission evidence.



### Explicit ECR SBOM and approved-key Cosign content profile

This optional collector reads repository content. It is disabled without `options.compliance_parameters.aws_ecr_artifacts`; the normal metadata-only role gains no image/content permissions. The provided `example-options.json` is a configuration template: replace account/Region/repository/digests and the public-PEM placeholder with reviewed values. `images` is an operator declaration of deployed immutable digests, not native evidence of deployment. Public keys and IDs express the trust policy; the collector never trusts an artifact-provided key ID.

The only supported acceptance profile is `oci11-and-cosign-v2-same-repository`. For each explicitly selected account/Region/repository/image, it reads the exact subject manifest using BatchGetImage, lists every ACTIVE OCI1.1 referrer using ListImageReferrers (explicit nextToken paging, maxResults50), gets each exact referrer manifest, and checks the standard deterministic legacy `sha256-<digest>.sig`, `.sbom` and `.att` tags. Native registry/repository/image identities and SHA256 manifest bytes must agree. OCI subject references must bind the exact declared image. Legacy signature/SBOM tags provide their documented storage binding. The profile accepts artifacts registered in this same repository; it does not search arbitrary external signature repositories or infer their absence.

Single-layer simple-signing JSON, SPDX JSON and CycloneDX JSON are supported. Sigstore bundles, DSSE, legacy attestations, unknown formats, external layer URLs and multi-layer artifact manifests remain UNKNOWN. Missing/denied/partial/ambiguous native responses also cannot PASS. Only after all supported discovery paths finish can the native artifact collection be complete; a missing supported artifact then FAILs within this declared acceptance profile. An empty OCI referrer list alone never proves absence: all deterministic legacy probes still run. No global claim that every registry artifact format or external repository was searched is made.

Layers use GetDownloadUrlForLayer and strictly bounded HTTPS downloads from the expected partition/Region Amazon S3 endpoint. There are no registry logins, GetAuthorizationToken, redirects, environment proxies or arbitrary hosts. Body length is bounded by its descriptor and4MiB per payload; total accepted payloads are limited to16MiB/128 artifacts per account/Region batch. Limits yield UNKNOWN rather than fabricated completeness. HTTP attempts consume the same scan-wide call budget as SDK operations. SHA256 is verified before UTF-8/JSON decoding. Signature payload strings retain their original bytes; JSON reserialization is never used before cryptographic verification. Approved Ed25519/RSA-PKCS1v1.5-SHA256/ECDSA-SHA256 keys are matched cryptographically; only a successful match assigns its approved key ID. Invalid or unapproved signatures cannot PASS.

Content is deliberately retained in the resulting snapshot, including complete SBOM JSON and signed payload text; it can contain dependency or application metadata. `content_read_approved=true` is explicit consent for that content capture, not an observation or coverage flag. Presigned URLs, untrusted annotations and private signing keys are not persisted. The companion-template.proposed.json demonstrates the two necessary repository-scoped grants and attaches a managed policy only to an explicitly named existing role if an operator later chooses to deploy it. It is a proposal, not a deployed template. Replace its example repository ARNs with the exact reviewed set before deployment. The helper `companion_policy(options)` generates the exact policy from valid owner configuration without performing IAM operations.

IAM: ListImageReferrers requires ecr:BatchGetImage, not a fabricated ecr:ListImageReferrers action. The additional content companion grants only ecr:BatchGetImage and ecr:GetDownloadUrlForLayer on exact repository ARNs. All three SDK tuples are explicitly classified as content operations and excluded from the default metadata-role generator; no prefix-based exception exists. Existing metadata templates, signed predicates and pins are unchanged. Hosted intake validates the provider-specific typed policy; malformed or observation-bearing input is rejected before collection.

Example Python integration after filling the real public PEM and reviewed inputs:

    from peaso.collectors import collect_live
    from peaso.engine import evaluate_snapshot
    snapshot = collect_live(connector, ["ecr_image", "ecr_oci_artifact"])
    results = evaluate_snapshot(snapshot, checks=["aws_ecr_sbom_present", "aws_ecr_image_provenance"])

Primary contracts: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ListImageReferrers.html ; https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchGetImage.html ; https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetDownloadUrlForLayer.html . Signature storage/annotations/raw bytes: https://raw.githubusercontent.com/sigstore/cosign/main/specs/SIGNATURE_SPEC.md . Legacy SBOM storage: https://raw.githubusercontent.com/sigstore/cosign/main/specs/SBOM_SPEC.md . Current registry/external repository behavior: https://docs.sigstore.dev/cosign/system_config/registry_support/ .

The stage has SDK-shaped offline collector-to-engine and HTTP-boundary coverage. No real ECR artifact content has been downloaded or cloud resources created by this stage. Native live validation and any deliberate fixture creation/cleanup remain separate integration work.


V2 bound corrections: Referrers pagination is limited to three native pages (maxResults50), and a complete list exceeding remaining global artifact capacity becomes UNKNOWN before any artifact manifest request. Artifact capacity is reserved before referrer/legacy manifest fetches; exact ImageNotFound frees its reservation. All subject/referrer/legacy manifest UTF8 bytes plus downloaded layer bytes share the same16MiB logical content budget, checked before JSON decoding/pending use. The SDK necessarily receives/caches its final response before this local validation; one additional native response and decoded-object/cache overhead are outside the logical content budget. This is not a16MiB resident-memory guarantee. Native manifests exceeding4MiB are rejected after receipt. Socket timeout is not a hard wallclock guarantee against slow-drip responses. Exceeding any bound remains UNKNOWN, never absence/FAIL. No cap was raised and no default content grant was added.

Legacy Cosign `.sig`/`.sbom` tags may omit OCI `subject` and `artifactType`.
When either field is present, it is authoritative metadata that must agree with
the explicitly requested image digest and actual single layer media type.
Null, malformed or foreign subjects and contradictory declared artifact types
leave both native envelopes incomplete/UNKNOWN. A legacy tag never overwrites a
present foreign OCI subject or turns a declared signature artifact into an SBOM.
Consistent hybrid manifests and ordinary legacy manifests remain supported.

CodeCommit merge-event identity: `MergeMetadata.mergeCommitId` is optional in
DescribePullRequestEvents. When absent, the collector requires a closed merged
single-target PR with a known commit, exact PR/repository/destination identity,
identical valid GetPullRequest mergedBy, event mergedBy and actorArn, identical
native mergeOption, and exactly one matching merge event. Only its eventDate
supplies merge time. Present null, malformed or foreign commits never use this
fallback. CLOSED pull requests cannot reopen; approval updates on closed PRs
are rejected by CodeCommit. Missing or contradictory anchors remain UNKNOWN.
Primary API contracts:
https://docs.aws.amazon.com/codecommit/latest/APIReference/API_MergeMetadata.html
https://docs.aws.amazon.com/codecommit/latest/APIReference/API_UpdatePullRequestStatus.html
https://docs.aws.amazon.com/codecommit/latest/APIReference/API_UpdatePullRequestApprovalState.html

Control Tower landing-zone status (bounded native path)

`aws_controltower_landing_zone_active` accepts an explicit owner classification
under `options.compliance_parameters.aws_controltower`:

```json
{"scope":"123456789012/us-east-1","organization_id":"o-abcdefghij","ai_account_ids":["123456789012"]}
```

These are normative AI-account/organization selections, not cloud observations.
Only the exact selected audited account is supported. Missing policy remains
UNKNOWN; malformed or foreign policy is rejected before authentication in both
hosted/local intake and direct library collection. No API response is accepted
through this policy. Other compliance parameter namespaces remain independent.

The native supported path requires commercial `us-east-1`, an exact successful
DescribeOrganization membership/organization ARN join, and the audited account
being the organization management account. ListLandingZones is paginated through
the shared budgets and must expose at most one unique ARN. GetLandingZone uses
the ARN's native, SDK-supported home Region, not an owner-supplied URL. Its exact
ARN/status is joined to the inventory. ACTIVE passes; native PROCESSING/FAILED
fails. Successful complete empty listing fails only in this documented
cross-home-region management-account path. Member accounts, other query Regions
or partitions, denied/partial reads, unknown states, foreign/missing identities,
duplicate records and list/detail changes do not establish a compliant state.
A detail 404 is UNKNOWN, not proof that the organization has no landing zone.

This checks deployment status only. It does not prove AI workloads are enrolled,
controls are enforced, individual governed Regions are complete, or drift is
absent. AI account classification remains the owner's explicit decision.
Manifests and organization email addresses are excluded before the request cache.
AWS documents that ListLandingZones can allocate an identifier for an existing
account; no actual Control Tower calls or cloud mutations were made in this
implementation's SDK tests.

The current customer role is unchanged. A separate private mapper proposal adds
the exact seven read/list AuthorizedActions published for the two Control Tower
operations: ListLandingZones/GetHomeRegion, and GetLandingZone with
DescribeLandingZoneConfiguration/GetAvailableUpdates/GetLandingZoneDriftStatus/
GetLandingZoneStatus. Only GetLandingZone supports the own-account landing-zone
ARN boundary; the six remaining read/list actions require Resource `*`. These
are proposed permissions, not a claim that a deployed role grants them.
Integration requires owner review, live IAM validation and a new immutable role
version; no current or historical role template is edited by this collector.

Bedrock remains unsupported for this signed control: GetGuardrail can expose
an Automated Reasoning policy attachment, but GetAutomatedReasoningPolicy has
no PolicyStatus field matching ACTIVE/INACTIVE/DELETING/FAILED. Neither guardrail
READY nor existence of a policy proves that state or actual application usage.
No native Bedrock alias is registered and no state or business context inferred.

Primary references:
https://docs.aws.amazon.com/controltower/latest/userguide/lz-api-list.html
https://docs.aws.amazon.com/controltower/latest/APIReference/API_ListLandingZones.html
https://docs.aws.amazon.com/controltower/latest/APIReference/API_GetLandingZone.html
https://docs.aws.amazon.com/controltower/latest/APIReference/API_LandingZoneDetail.html
https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html
https://docs.aws.amazon.com/service-authorization/latest/reference/list_controltower.html
https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GetAutomatedReasoningPolicy.html
https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GetGuardrail.html

### Optional explicitly selected configuration-content scanning

The local check proposal `aws.review.configuration.selected_content_secret_indicators`
adds dual offline scanning for the 15 literal surfaces below. It preserves the
existing pattern-only checks; a pattern-only clean result does not mean both
engines scanned the content. Registration and hosted option admission are separate
integration steps; this section does not assert deployed availability.

Name that exact check, set `content_secret_scans: true`, and supply
`selected_aws_configuration_content`: 1–16 unique objects with exactly `surface`,
`scope` and `resource_id`, plus a numeric `version` only for launch templates and
SSM documents. Scopes must be 1–8 explicit matching `account/Region` pairs. All
resource IDs are full native ARNs; REST stage ARNs have an empty account member
and bind to the authenticated selected account. Numeric versions are 1–2147483647;
`$Latest`, `$Default`, document aliases, arbitrary URLs and wildcard scope are not
accepted. Supported resource names use each adapter's documented conservative
ASCII grammar; unsupported names are rejected before credentials are requested.

```json
{
  "connector": {
    "provider": "aws",
    "scopes": ["123456789012/us-east-1"],
    "options": {
      "content_secret_scans": true,
      "selected_aws_configuration_content": [
        {"surface":"codebuild_environment","scope":"123456789012/us-east-1",
         "resource_id":"arn:aws:codebuild:us-east-1:123456789012:project/example"},
        {"surface":"ssm_document","scope":"123456789012/us-east-1",
         "resource_id":"arn:aws:ssm:us-east-1:123456789012:document/example","version":3}
      ]
    }
  },
  "checks": ["aws.review.configuration.selected_content_secret_indicators"]
}
```

| `surface` | Exact selected read and inspected bytes | Minimum read authorization |
| --- | --- | --- |
| `cloudformation_outputs` | `DescribeStacks(StackName=stackARN)`; completed stack output keys/values | `cloudformation:DescribeStacks` |
| `codebuild_environment` | `BatchGetProjects(names=[projectARN])`; `PLAINTEXT` environment names/values | `codebuild:BatchGetProjects` |
| `rest_stage_variables` | `GetStage(restApiId, stageName)`; stage variable keys/values | `apigateway:GET` on the selected REST stage resource path |
| `ecs_environment` | `DescribeTaskDefinition(taskDefinition=familyRevisionARN)`; active container literal environment | `ecs:DescribeTaskDefinition` |
| `amplify_environment` | `GetApp(appId)`; selected app environment | `amplify:GetApp` |
| `batch_environment` | `DescribeJobDefinitions(jobDefinitions=[revisionARN])`; active classic container environment | `batch:DescribeJobDefinitions` |
| `beanstalk_options` | `DescribeConfigurationSettings(ApplicationName,EnvironmentName)`; deployed option values | `elasticbeanstalk:DescribeConfigurationSettings` |
| `glue_job_arguments` | `GetJob(JobName)`; default and non-overridable argument keys/values | `glue:GetJob` |
| `glue_connection_properties` | `GetConnection(CatalogId,Name,HidePassword=true)`; visible connection properties excluding password members | `glue:GetConnection` |
| `launch_template_userdata` | `DescribeLaunchTemplateVersions(LaunchTemplateId,Versions=[numericVersion])`; decoded user data | `ec2:DescribeLaunchTemplateVersions` |
| `launch_configuration_userdata` | `DescribeLaunchConfigurations(LaunchConfigurationNames=[name])`; decoded user data | `autoscaling:DescribeLaunchConfigurations` |
| `ssm_document` | `DescribeDocument` proves native account ownership, then `GetDocument` at the same numeric version | `ssm:DescribeDocument` and `ssm:GetDocument` |
| `state_machine_definition` | `DescribeStateMachine(stateMachineArn,includedData=ALL_DATA)`; ASL source and decoded string literals | `states:DescribeStateMachine` |
| `notebook_lifecycle` | `DescribeNotebookInstanceLifecycleConfig(name)`; decoded OnCreate/OnStart source | `sagemaker:DescribeNotebookInstanceLifecycleConfig` |
| `pipeline_definition` | `GetPipelineDefinition(pipelineId,version=latest)`; literal definition/parameter fields | `datapipeline:GetPipelineDefinition` |

Scope reads to selected resources wherever the service supports resource-level
permissions; some Describe operations require `Resource: "*"`. Exact request
selection does not create resource-level IAM support. These are read permissions,
not a recommendation for service administrator policies. `sts:GetCallerIdentity`
binds account/partition without requiring an allow grant. No role template, write,
execute, invoke, attachment fetch or secret-store read is added.

For encrypted Step Functions definitions, AWS can additionally require existing
key-scoped `kms:Decrypt` authorization to return `ALL_DATA`. The adapter makes no
KMS call or grant change and does not substitute metadata-only output. See
[DescribeStateMachine](https://docs.aws.amazon.com/step-functions/latest/apireference/API_DescribeStateMachine.html),
[GetConnection HidePassword](https://docs.aws.amazon.com/glue/latest/webapi/API_GetConnection.html),
[DescribeDocument ownership](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeDocument.html)
and [API Gateway read authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_apigateway.html).

References such as CodeBuild secret/parameter variables, ECS secret/env-file
references, Glue password/authentication stores and Data Pipeline reference fields
are not dereferenced. Amplify branches, Batch ECS/EKS/multinode variants, attached
SSM files, notebook attachment/runtime state, Step Functions executions and active
Data Pipeline execution state are outside this reader. A lifecycle configuration
is selected directly; it does not prove that a notebook uses that script. The
Data Pipeline `latest` definition is the saved definition, not the active version.

Bounds: 32 selected content calls, 120 seconds across reads/scans, 2 MiB per parsed
SDK response, 8 MiB total responses, 1 MiB rendered content per target, 256 literal
pairs and 128 retained matches. Decoded user data/lifecycle scripts are limited to
16 KiB, SSM content to 64 KiB. SDK responses are allocated before projection;
these are inspection/retention limits, not streaming transport memory guarantees.
Connect/read timeouts are bounded and existing shared budgets can stop reads
earlier. Native denied, missing/deleted, empty, partial, malformed, changed,
unsupported and oversized results stay UNKNOWN. Both pinned offline engines must
complete before PASS; an observed supported leak can still FAIL when another
engine is unavailable. Neither engine verifies credentials.

Only typed results and opaque HMAC locations/request locators survive projection.
Detected values are merged across engines and surfaces. A bounded union scrub also
redacts matching earlier request-cache records, keys and snapshot metadata; if it
cannot finish, affected content is withheld and coverage remains unresolved.
Evidence does not expose content, native names or matched values. A clean result
covers only these returned literal bytes, not all service configurations or runtime
environments.

### Bounded configuration and optional content indicators

Configuration-secret checks inspect selected returned configuration values in memory
and retain only indicator categories, completeness and native resource identity.
They do not verify credentials or test whether a detected credential works. Raw
values, snippets and value hashes are not written to the snapshot or request cache.
Owned SSM documents use an exact numeric version; notebook lifecycle scripts and
Data Pipeline literal definitions are inspected within explicit size limits.
Denied, malformed, truncated or unsupported coverage remains `UNKNOWN`.

Package, repository and log-message scans require the JSON option
`"content_secret_scans": true`; the default is `false`. Select the relevant checks
explicitly for these content scans. Lambda archives/layers, the uniquely latest
ECR image, the CodeCommit default-branch commit and at most 24 hours of bounded
CloudWatch messages are separate coverage surfaces. These scans are read-only,
use strict limits and retain categories rather than content. Their read permissions
are separate from the default configuration role. An empty bounded sample is not
proof that all versions, files, images or historical messages contain no secrets.

For example, to inspect only a selected repository check, set the option in a
private options file and name the check:

```sh
hacktricks-cspm scan --provider aws --profile YOUR_PROFILE \
  --scopes 123456789012 --options-file content-options.json \
  --checks aws.review.codecommit.default_commit_secret_indicators \
  --output content-report.json
```

`content-options.json` can contain
`{"regions":["us-east-1"],"content_secret_scans":true}`. Selecting all checks,
a category or a framework does not authorize these content reads, even when
that option is true. Select individual IDs instead:

| Content surface | Explicit check ID | Additional read actions |
|---|---|---|
| EC2 instance user data (dual scanners) | `aws_cis_ec2_userdata_embedded_secrets` | `ec2:DescribeInstanceAttribute` (already in configuration role) |
| CodeCommit default commit | `aws.review.codecommit.default_commit_secret_indicators` | `codecommit:GetRepository`, `GetBranch`, `GetFolder`, `GetFile` |
| CloudWatch sample | `aws.review.cloudwatch.sampled_log_secret_indicators` | `logs:FilterLogEvents` |
| Lambda deployment ZIP | `aws.review.lambda_function.package_content_secret_indicators` | `lambda:GetFunction` |
| Lambda layer ZIP | `aws.review.lambda_layer_version.package_content_secret_indicators` | `lambda:GetLayerVersion` |
| Latest ECR image | `aws.review.ecr_repository.package_content_secret_indicators` | `ecr:BatchGetImage`, `GetDownloadUrlForLayer` |

Inventory reads still apply. Grant these extra reads separately on the intended
own-account resources; the generated default customer role omits them. No
`secretsmanager:GetSecretValue`, SSM parameter-value, S3 object-content or ECR
login-token permission is needed. CodeCommit `GetFile` cannot cap network bytes:
AWS may return a file of up to 6 MiB, although this scanner inspects at most
1 MiB across the selected files. An oversized file yields incomplete coverage.

The EC2 clock check now reads the exact `CWAgent/time_offset` CloudWatch stream
with the single `InstanceId` dimension and `Milliseconds` unit. It retains the
latest five-minute minimum/maximum extreme from the previous day. It does not
install/configure an agent, run a host command or infer clock drift from instance
metadata. Missing, denied or differently dimensioned/unit telemetry remains
`UNKNOWN`; missing this exact stream does not prove every monitoring system is
absent. Only the selected clock check triggers this additional read.


### Dual-engine optional secret scanning

The six explicitly selected content checks above use **Kingfisher SDK 1.4.0**
and **TruffleHog 3.92.5**. Kingfisher scans memory buffers with embedded rules;
TruffleHog receives the same bounded content through stdin. Neither engine
validates, revokes or uses discovered credentials. Update checks and automatic
archive extraction are disabled. The existing bounded ZIP/tar readers supply
individual files, including image build configuration and deleted-file layers.

Install the Python extra with `pip install '.[cloud,secrets]'` and install
TruffleHog **3.92.5** on PATH using its official release. The hosted worker image
installs both, with the TruffleHog image pinned by digest. Merely installing them
does not enable content collection: `content_secret_scans=true` and the exact
content check selections are both required.

A secret's exact value receives a random-key HMAC fingerprint inside the
collector. Only fingerprints, detector names/rules and source locations survive
projection. Equal values detected by either engine in multiple files, images or
checks produce **one finding per collection**, listing every collected location.
Different values stay separate; similar tokens are never merged heuristically.
The random key is not persisted, so separate scans are not correlated by value.
Repeated input uses a small bounded metadata-only cache; no files are staged on
disk, and no archive content is executed.

Both engines must finish successfully for a complete negative result. An absent
binary, mismatched version, timeout or malformed tool response leaves a negative
scan incomplete/UNKNOWN; a proven positive from the other engine is retained.
The result is not proof that unseen branches, older images, truncated logs or
uninspected content contain no secrets. Supplemental configuration patterns are
retained and do not establish detector parity with every Prowler scan mode.

References: [Kingfisher SDK](https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md),
[TruffleHog](https://github.com/trufflesecurity/trufflehog/tree/v3.92.5).

### EC2 user-data secret detection

The existing `aws_cis_ec2_userdata_embedded_secrets` configuration check inspects
user data for bounded private-key, AWS-credential and literal-password indicators.
For the broader offline **Kingfisher + TruffleHog** scan, explicitly select that
check and set `content_secret_scans` to `true`. The scanner decodes the native
base64 response in memory within EC2's 16 KiB raw limit. It does not run the script,
validate credentials, or store raw scripts or matched values. Repeated secrets
across engines, instances and other selected content surfaces become one redacted
finding with all observed locations. Both engines must complete for a negative
content result; a missing engine cannot produce a clean PASS. Denied, malformed,
unsupported or oversized data stays UNKNOWN. Compressed/binary user data is not
expanded by this path. The baseline configuration indicators still run without
invoking external scanners when content selection is absent.

```sh
hacktricks-cspm scan --provider aws --profile YOUR_PROFILE \
  --options-file content-options.json \
  --checks aws_cis_ec2_userdata_embedded_secrets --output ec2-secrets.json
```

References: [DescribeInstanceAttribute](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceAttribute.html)
and [EC2 user-data encoding and size](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html).


### Resource-policy wildcard grants

The shared `aws_resource_policy` collector supplements service-specific inventories with explicit policy discovery across 145 reviewed resource families and 86 SDK services. It includes qualified/nested resources and typed sharing APIs. Policies granting wildcard principals without recognized required caller or network conditions feed `aws_cis_aws_resource_policy_unrestricted_principal`. Existing collectors' narrower resource shapes do not bound this shared review. See [the coverage and predicate review](aws-resource-policy-review.md) for the generated inventory, exclusions, evidence limits and offline verification commands. The customer-role generator includes the exact additional read permissions; existing deployed roles need their template updated to collect newly covered families.

## Selected IAM metadata reports

The scan engine enables `GenerateCredentialReport` only when the selected checks need the credential report, and `GenerateServiceLastAccessedDetails` only for the four IAM usage-history checks. AWS classifies both APIs as **Read** ([IAM service authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html)); they create report results without modifying identities, credentials or permissions. Direct collector requests leave report generation disabled unless the internal selection gates are set.

Existing credential reports are read first; only missing, expired or still-preparing reports trigger the selected refresh. AccessDenied never triggers a retry through generation. Service-access jobs are tied to the verified account, principal, session and generated job identifier, use bounded concurrency and a shared batch deadline, and require complete consistent pagination. Denied, malformed, late or incomplete reports remain unavailable evidence. These reports describe recorded access attempts, not current effective permissions or successful access.

### Selected inline CodeBuild build instructions (local addition)

A separate named optional check inspects returned inline buildspecs. It does not follow source files or build artifacts; see [exact selectors, read permissions and limits](peaso-aws-selected-codebuild-buildspecs.md).

## Selected ECS and Batch command literals

The optional [selected workload command reader](peaso-aws-selected-workload-commands.md) reads exact ECS task-definition or classic Batch job-definition revisions. It requires the explicit check, content-scan opt-in, and `ecs:DescribeTaskDefinition` or `batch:DescribeJobDefinitions`; it does not execute workloads or fetch referenced environment files. Local native acceptance does not certify deployment.

### Unused access from IAM Access Analyzer

The collector reuses existing account or organization analyzers. It reads every page of active findings and every page of each finding’s details, including unused roles, access keys, console passwords, services and individual actions. Analyzer configuration supplies the analysis window and exclusions; available last-access timestamps and current finding status are retained. Existing analyzers are never deleted by the scan.

The Hardening Access Analyzer control records all active unused-access findings, including identities and credentials that have no Least Privilege permission recommendation. Its details list the principal, unused access, available last-use date and configured analysis window. Least Privilege separately shows the provider-reported unused actions or services; it does not invent an action’s last-use date from service-level activity.

Findings already read remain visible if later pagination or detail collection fails. Coverage errors remain attached, an incomplete empty read cannot pass, and a finding resolved during collection is not treated as active. A missing last-use timestamp means AWS did not return a date; it does not establish that the principal has never been used.
