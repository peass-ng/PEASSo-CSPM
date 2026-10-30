# CloudTrail and KMS SDK closure review — 2026-10-19

The exact requested 48 IDs are covered: 32 CloudTrail, 14 KMS, one enclave event and one Organizations consumer. The owned directed file passes **86 tests** with no failures, errors or skips, and records 572 current field-emission properties and 180 actual consumer outcomes.

All 48 consumers executed; 47 have a PASS witness. The delivery-role integration consumer has only missing-destination FAIL and denied-role UNKNOWN witnesses; its positive permission proof remains explicitly unproved and owned by the role agent. No row claims semantic or branch completeness.

## Reproduced defects and acceptance

Two defects were proposed and integrated by the coordinator: foreign GetKeyRotationStatus identity previously PASSed both rotation consumers, and foreign GetEventSelectors identity previously PASSed the regional management consumer. Fresh tests require UNKNOWN for these mismatches and for missing native selector identity, while preserving successful optional rotation-identity omission. The worker changed only its owned test and two reports; the shared runtime patch was applied by root.

[GetKeyRotationStatus](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html) identifies the key whose rotation is returned, while [GetEventSelectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html) identifies the trail whose selectors are returned. The proposed guards bind those responses to the enumerated subject.

The original expanded red receipt is retained. Its S3 fresh failure was traced to concurrent Stubber contexts sharing one SDK client: the copied max_workers option did not constrain Requests concurrency. The owned harness now sets service_concurrency=1; S3 fresh, empty, denied, foreign and partial branches pass. Intermediate pipeline-change failures are stale-source receipts and are not promoted to closure evidence.

## Native contracts exercised

| Family | Bounded executed contracts |
| --- | --- |
| CloudTrail | Base KMS/validation flags; native datetime conversion; Insights and logging state; management and S3 selectors; bucket logging/MFA/public-grant joins; discovered account inventory; log-group/KMS joins; Object Lock/lifecycle; metadata-only S3 delivery; partial inventory and identity omissions. |
| KMS | DescribeKey identity; enabled/deletion/multi-Region states; rotation and optional identity; native JSON policy private/public/malformed/denied branches; enclave policy enforcement and deployment; tag applicability, denied/partial inventories and foreign aliases; imported algorithm and lifecycle tags. |
| Enclave events | Synthetic native LookupEvents envelopes projected at the SDK boundary; nonzero/zero PCR measurements; foreign account, malformed PCR and denied history. Raw event JSON is discarded before the public snapshot. |
| Organizations | Native organization/resource-policy/member inventories; delegated action set, absent policy, denied policy and foreign resource-policy identity. |

The S3 delivery cases prove bounded metadata correlation only; they read no object content and do not establish SIEM receipt. Enclave cases prove only recorded measurements, as documented in [AWS KMS enclave CloudTrail metadata](https://docs.aws.amazon.com/kms/latest/developerguide/ct-nitro-enclave.html). Lifecycle cases preserve the native [Object Lock response wrapper](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html).

## Exact evidence

- Test SHA256: `3eb3246d6baf3792a0782708ce1143630a79b408467a3f224d59876b67ae2833`
- Pipeline fingerprint: `b7dbf12a6b8391c62ac7f2187eeef20df25b1156fd4f113b1420cc397b6048e9`
- Acceptance JUnit SHA256: `afcc5af25cf7d5021c742d22e106bae5504fb9f952672c970027c4f7c4c0001c`
- Acceptance receipt: `/tmp/peasso-aws-review-20261019/trail-kms-sdk-closure/acceptance.xml`
- Historical red receipt: `/tmp/peasso-aws-review-20261019/trail-kms-sdk-closure/expanded-red.xml`
- Narrow proposal: `/tmp/peasso-aws-review-20261019/trail-kms-sdk-closure/identity-guards.patch`

[The JSON report](trail-kms-sdk-closure-review.json) lists every ID, actual test/outcome pairs, current callback sources and hashes, primary AWS references and explicit remaining branches. Input field paths are marked only for witnessed SDK emission; emission in another passing scenario never certifies a consumer accessor or unvisited branch.

```sh
.venv/bin/python -m pytest -q tests/test_aws_trail_kms_sdk_closure_review.py \
  -o junit_family=xunit1 \
  --junitxml=/tmp/peasso-aws-review-20261019/trail-kms-sdk-closure/acceptance.xml
```

Only affected owned tests were run. No live accounts, content retrieval, exploitation, deployment, goal/budget changes, new IDs, UI groups or shared evidence-copy changes were performed.

## Per-ID actual outcomes

| Check ID | Executed statuses | Remaining proof |
| --- | --- | --- |
| `aws.a.cloudtrail.bucket_access_logging` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.a.cloudtrail.bucket_mfa_delete` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.a.cloudtrail.cloudwatch_delivery_24h` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.a.cloudtrail.home_bucket_access_logging` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.a.cloudtrail.home_bucket_mfa_join` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.a.cloudtrail.home_cloudwatch_date` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.a.cloudtrail.home_multiregion_cloudwatch_date` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.a.cloudtrail.insights_logging_trail` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.a.cloudtrail.joined_bucket_declared_public_grants` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude2_a.cloudtrail.region_has_logging_trail` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude2_a.cloudtrail.trail_bucket_mfa_delete` | FAIL, MANUAL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude_a.kms.customer_key_enabled_or_pending_deletion` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude_a.kms.customer_key_not_pending_deletion` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude_a.kms.key_policy_not_public` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude_a.kms.prowler_cmk_rotation` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude_a.kms.prowler_cmk_single_region` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude_a.kms.prowler_cmk_used` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.claude_a.kms.prowler_key_not_public` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.cloudtrail.kms_encryption` | DENIED, FAIL, PASS | Unvisited branches remain open |
| `aws.cloudtrail.log_validation` | DENIED, FAIL, PASS | Unvisited branches remain open |
| `aws.cloudtrail.management_events` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.gap.cloudtrail.bedrock_api_logging` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.gap.cloudtrail.multi_region_read_write_management` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.gap.cloudtrail.region_logging_management_events` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.gap.cloudtrail.s3_all_buckets_read_data_events` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.gap.cloudtrail.s3_all_buckets_write_data_events` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.gap.cloudtrail.trail_security_best_practices` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.kms.rotation` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.nist.all_cloudtrail_destination_bucket_access_logging` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.nist.cloudtrail_cloudwatch_destination_kms` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.nist.cloudtrail_cloudwatch_integration` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.review.kms.enclave_attestation_enforced` | FAIL, NOT_APPLICABLE, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.review.kms.enclave_debug_measurements` | DENIED, FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.review.kms.enclave_deployment_binding` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws.review.kms.enclave_no_bypass` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_cis_organizations_policy_management_delegated` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_cloudtrail_bucket_lifecycle_retention_365` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_cloudtrail_s3_siem_delivery` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_fedramp_cloudtrail_destination_kms` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_g6_all_cloudtrail_destination_bucket_access_logging` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_g6_cloudtrail_all_trails_cloudwatch_integration` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_g6_cloudtrail_kms_destination_join` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_kms_compromised_key_restricted` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_kms_imported_key_origin_spec` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_kms_key_expiry` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_nist_cloudtrail_s3_logging_enabled` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
| `aws_nist_cloudtrail_trail_integrated_with_logs` | FAIL, UNKNOWN | Positive role permission proof unvisited |
| `aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk` | FAIL, PASS, UNKNOWN | Unvisited branches remain open |
