# Network cross-service SDK review

The exact six requested IDs have 50 passing offline SDK/public-pipeline scenarios under botocore 1.43.38. Native responses pass Stubber validation and flow through real Requests into public `aws.collect` and existing registered consumers. No shared runtime files changed and no reproduced runtime defect requires a patch proposal.

The client adapter delegates SDK pagination metadata and serves each requested operation with Stubber. Unprovided read responses deliberately return AccessDeniedException and are recorded as denied; they never become empty inventories. Synthetic identity-corruption and duplicate-response cases exercise defensive behavior and are not claims that AWS normally returns those responses.

The stage canary is synthetic and was never verified. The tests assert its raw value is absent from completed request-cache futures, snapshots and findings. Only the selected bounded detector is assessed.

| Existing ID | Scenarios | Observed statuses |
| --- | ---: | --- |
| `aws.c2b.bedrock.vpc_endpoints` | 10 | FAIL: 3, NOT_APPLICABLE: 2, PASS: 1, UNKNOWN: 4 |
| `aws.c2b.cloudfront.s3_origin_bucket_exists` | 7 | NOT_APPLICABLE: 1, PASS: 1, UNKNOWN: 5 |
| `aws.cb.shield.cloudfront_protected` | 8 | FAIL: 2, NOT_APPLICABLE: 1, PASS: 1, UNKNOWN: 4 |
| `aws.claude_a.networkfirewall.in_use_vpc_has_firewall` | 9 | FAIL: 2, NOT_APPLICABLE: 1, PASS: 1, UNKNOWN: 5 |
| `aws.review.rest_api_stage.configuration_secret_indicators` | 7 | DENIED: 1, FAIL: 1, PASS: 2, UNKNOWN: 3 |
| `aws_g6_api_stage_effective_waf_acl` | 9 | FAIL: 3, PASS: 1, UNKNOWN: 5 |

## `aws.c2b.bedrock.vpc_endpoints`

All five available service endpoints in the active in-use VPC pass. Missing, pending and foreign-VPC endpoints fail; denied or partial dependencies stay UNKNOWN. Idle VPCs and regions without observed Bedrock activity are not applicable.

Tested: all_available → PASS, missing_mantle → FAIL, pending → FAIL, foreign_vpc → FAIL, no_interfaces → NOT_APPLICABLE, inactive → NOT_APPLICABLE, endpoints_denied → UNKNOWN, interfaces_denied → UNKNOWN, activity_denied → UNKNOWN, endpoint_partial → UNKNOWN.

Unproved: Only invocation-logging activity establishes the positive activity branch; guardrail-only and agent-only activation are unproved. Endpoint type, private DNS, FIPS alternatives, endpoint service availability, endpoint policies and actual traffic routing are outside the tested predicate. Other partitions, regions, successful multi-page inventories and races remain unproved.

Primary AWS references: [AWS vpc-interface-endpoints](https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html), [AWS API_DescribeVpcEndpoints](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcEndpoints.html).

## `aws.c2b.cloudfront.s3_origin_bucket_exists`

An owned inventory bucket matching the origin passes. Unowned, unrelated, denied and partial bucket inventories remain UNKNOWN. A custom origin is not applicable; no bucket nonexistence is inferred.

Tested: owned → PASS, external → UNKNOWN, unrelated_bucket → UNKNOWN, inventory_denied → UNKNOWN, inventory_partial → UNKNOWN, custom_origin → NOT_APPLICABLE, config_denied → UNKNOWN.

Unproved: External or unowned bucket origin existence remains explicit UNKNOWN; no native origin-bound HeadBucket producer is claimed. No FAIL witness exists for nonexistent buckets because ListBuckets absence and ambiguous HTTP errors cannot prove their nonexistence. Access point, website, multi-region origin variants and successful multi-page inventories remain unproved.

Primary AWS references: [AWS API_GetDistributionConfig](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetDistributionConfig.html), [AWS API_ListBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html), [AWS API_HeadBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html).

## `aws.cb.shield.cloudfront_protected`

An active subscription and exact protection ResourceArn match pass. Empty or unrelated protection inventories fail. Inactive subscriptions are not applicable; denied, partial and foreign-owner inputs remain UNKNOWN.

Tested: matching → PASS, empty → FAIL, foreign_resource → FAIL, inactive → NOT_APPLICABLE, protections_denied → UNKNOWN, subscription_denied → UNKNOWN, protections_partial → UNKNOWN, foreign_distribution_owner → UNKNOWN.

Unproved: Only the account-global CloudFront distribution ARN/subscription/protection joins in the selected region were tested. Cross-partition ARN normalization, duplicate protection IDs and successful multi-page inventories remain unproved. Protection membership does not prove mitigation effectiveness, routing or service health.

Primary AWS references: [AWS API_ListProtections](https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_ListProtections.html), [AWS API_GetSubscriptionState](https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_GetSubscriptionState.html).

## `aws.claude_a.networkfirewall.in_use_vpc_has_firewall`

A firewall detail joined by ARN and VpcId to an in-use VPC passes. Empty or foreign-VPC firewall inventories fail; unused VPCs are not applicable. Denied details, mismatched detail ARNs and partial inventories remain UNKNOWN.

Tested: matching → PASS, empty → FAIL, foreign_vpc → FAIL, unused → NOT_APPLICABLE, denied → UNKNOWN, detail_denied → UNKNOWN, foreign_detail → UNKNOWN, interfaces_denied → UNKNOWN, partial → UNKNOWN.

Unproved: The consumer proves matching firewall presence in an in-use VPC only; route enforcement, endpoints, firewall policy correctness and runtime traffic protection remain unproved. Cross-account/region identities beyond the mismatched DescribeFirewall ARN case and successful multi-page inventories remain unproved.

Primary AWS references: [AWS API_DescribeFirewall](https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_DescribeFirewall.html), [AWS API_DescribeNetworkInterfaces](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkInterfaces.html).

## `aws.review.rest_api_stage.configuration_secret_indicators`

Clean and omitted ordinary stage variables pass the bounded detector. A synthetic password canary fails and its raw value is absent from cache, snapshot and findings. Denied reads, invalid stage identity, oversize maps and partial parent traversal never pass.

Tested: clean → PASS, canary → FAIL, omitted_variables → PASS, oversize → UNKNOWN, denied → DENIED, parent_partial → UNKNOWN, invalid_stage → UNKNOWN.

Unproved: Only ordinary stage variables and the selected password-assignment detector were tested; canary stageVariableOverrides and other configuration content are unproved. PASS means no selected indicator in the bounded returned variables, not an exhaustive absence of secrets. Other indicator categories and service-valid maximum-size boundary values remain unproved.

Primary AWS references: [AWS API_GetStages](https://docs.aws.amazon.com/apigateway/latest/api/API_GetStages.html).

## `aws_g6_api_stage_effective_waf_acl`

Matching declared, effective and inventoried ACL ARNs pass. Absent, mismatched or missing-inventory associations fail. Denied, partial, foreign-account and duplicate-stage association inputs remain UNKNOWN.

Tested: matching → PASS, absent → FAIL, declaration_mismatch → FAIL, inventory_missing → FAIL, association_denied → UNKNOWN, inventory_denied → UNKNOWN, foreign_acl_owner → UNKNOWN, association_partial → UNKNOWN, duplicate_stage → UNKNOWN.

Unproved: The tests bind GetStages parent/name to the requested stage ARN and compare declared, effective and inventoried regional WAF ACL ARNs. Other partitions, races, successful multi-page WAF inventories and multiple APIs with colliding stage names remain unproved. Association membership does not prove effective rule behavior or request filtering.

Primary AWS references: [AWS API_GetStages](https://docs.aws.amazon.com/apigateway/latest/api/API_GetStages.html), [AWS API_GetWebACLForResource](https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACLForResource.html), [AWS API_ListWebACLs](https://docs.aws.amazon.com/waf/latest/APIReference/API_ListWebACLs.html).

## Evidence and reproduction

The adjacent JSON records per-scenario requests and arguments, real emitted collection paths and statuses, consumer source hashes, collector producer paths, and the source manifest. JUnit contains 117 `aws_field_emission` properties; receipts remain bounded execution witnesses and never prove unvisited branches.

```sh
.venv/bin/python -m pytest tests/test_aws_network_cross_service_sdk_review.py -q -o junit_family=legacy --junitxml=/tmp/peasso-aws-review-20261019/network-cross-service-sdk/junit.xml
```

Temporary JUnit, stdout, raw receipts and the report generator are under `/tmp/peasso-aws-review-20261019/network-cross-service-sdk`. No proposal patch was needed. External/unowned S3-origin coverage remains explicit UNKNOWN.

Collector/snapshot pipeline fingerprint: `b7dbf12a6b8391c62ac7f2187eeef20df25b1156fd4f113b1420cc397b6048e9`. Test source SHA-256: `78b58905630091ab4693ce8b9b840933e55402b2a4ffa83f558bdb463927fbc2`.
