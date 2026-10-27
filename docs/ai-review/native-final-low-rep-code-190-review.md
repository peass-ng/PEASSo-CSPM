# Independent source review: 190 low-representative Hardening IDs

This receipt covers the code worker's 190 exact zero-disagreement IDs below three
initial representatives. The audit worker owns the disjoint 72-ID indexed slice.
The JSON receipt pins both split hashes and each evaluator's source hash. It
contains the exact FAIL predicate line and bound API field paths for every ID.

The current checkpoint classifies **95 source-proven** (6,470 exact native FAILs,
151 initial representatives), **72 provisional** (360 FAILs), and **23 retained
for AI** (190 FAILs). The earlier 166 candidate
count was provisional. A
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
- The exact snapshot SHA `3d7828c7…2592f` verifies complete S3, SQS,
  CloudFormation, ECS task, Lambda, CloudFront, ECR, log group, and IAM user
  response metadata before the corresponding optional-field predicates are
  source-proven. The receipt stores counts and status markers only.
- The grouped pre-AI report SHA `4dcaa76a…de2ba` binds every one of the
  6,470 source-proven native FAIL IDs to its exact resource scope. Its resource
  kind and scope must have a collected envelope with items and no partial or
  denied envelope for that same kind and scope. Empty non-collected envelopes
  never establish absence, even when a different scope has collected data.
  The 193 empty partial or denied envelopes in unrelated scopes are excluded
  from completeness. Each ID's scope-pair hash and matched count are in the
  JSON receipt. Global collection counts are supplementary and never override
  the per-FAIL scope check.
- `aws.b.cloudfront.custom_acm_certificate` checks only the presence of
  certificate references at `peaso/checks/aws_b_cloudfront.py:69-75`; the
  snapshot confirms all 10 `GetDistributionConfig` responses were collected.

Fail-closed examples:

- `aws.b.ecr.lifecycle_rules` parses serialized `lifecyclePolicyText` at
  `peaso/checks/aws_b_ecr.py:23`; it stays AI-reviewed. ECR policy *presence*
  controls that use recorded metadata alone remain eligible by source proof.
- Untraced optional-field helpers, dynamic field bindings, and index joins stay
  provisional or AI-reviewed. The 72 indexed IDs assigned to the audit worker
  are absent from this receipt.

This source review does not activate any ID. Zero AI disagreement is necessary
but each final admission still needs per-check direct API evidence, source pins,
and the root's hosted replay decision.

The nine source-proven `aws.c2b.*` IDs are included in this checkpoint. The
remaining 24 provisional `aws.c2b.*` IDs are assigned to the audit worker for
independent source review. Their exact disjoint lists are recorded in the
persistent `native-final-code-c2b-proven-9-ids.json` and
`native-final-audit-c2b-provisional-24-ids.json` handoff receipts.
