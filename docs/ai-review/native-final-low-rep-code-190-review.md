# Independent source review: 190 low-representative Hardening IDs

This receipt covers the code worker's 190 exact zero-disagreement IDs below three
initial representatives. The audit worker owns the disjoint 72-ID indexed slice.
The JSON receipt pins both split hashes and each evaluator's source hash. It
contains the exact FAIL predicate line and bound API field paths for every ID.

The current review classifies **34 source-proven**, **131 provisional**, and
**25 retained for AI**. The earlier 166 candidate count was provisional. A
function named `get`, a helper name, or a check title never establishes proof.
The receipt is not an activated allowlist; the versioned runtime manifest
remains empty and pending hosted replay qualification.

Source-proven examples:

- IAM password settings use the complete, scope-matched `iam_password_policy`
  collection before strict typed field reads and fixed thresholds:
  `peaso/checks/aws_a_facts.py:20-50`, `peaso/checks/aws_a_iam.py:12-76`.
- CloudFront's default-certificate predicate reads
  `ViewerCertificate.CloudFrontDefaultCertificate` from a successful
  `get_distribution_config` response: `peaso/checks/claude2_aws_b_edge.py:129-162`,
  `peaso/collectors/aws_b_services.py:475-476`.
- Direct scalar examples read strict fields through `facts.get`, which rejects
  missing, denied, malformed, or contradictory coverage:
  `peaso/checks/facts.py:12-53`. Each per-ID field, predicate, and registration
  line is in the JSON receipt.

Fail-closed examples:

- `aws.b.ecr.lifecycle_rules` parses serialized `lifecyclePolicyText` at
  `peaso/checks/aws_b_ecr.py:23`; it stays AI-reviewed. ECR policy *presence*
  controls that use recorded metadata alone remain eligible by source proof.
- `aws.b.cloudfront.custom_acm_certificate` uses `dict.get` for omitted
  certificate references at `peaso/checks/aws_b_cloudfront.py:72-75` and stays
  provisional until omission completeness is proved for that row.
- Untraced optional-field helpers, dynamic field bindings, and index joins stay
  provisional or AI-reviewed. The 72 indexed IDs assigned to the audit worker
  are absent from this receipt.

This source review does not activate any ID. Zero AI disagreement is necessary
but each final admission still needs per-check direct API evidence, source pins,
and the root's hosted replay decision.
