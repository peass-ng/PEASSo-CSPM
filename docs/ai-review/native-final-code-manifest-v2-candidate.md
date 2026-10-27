# Inactive schema-v2 code-manifest candidate: 84 source-proven checks

The [candidate JSON](native-final-code-manifest-v2-candidate.json) combines the frozen [high-20 candidate](native-final-code-manifest-v2-candidate-high20.json) and 64 IDs from the separately signed [scoped low-rep proof receipt](native-final-scoped-low-rep-proofs-v3.json). The scoped receipt is pinned to the code worker's disjoint low-rep source receipt SHA256 `333ccb7146e02db59f14b2f8056c54bcbad266c5b55e696ced3ab5f19eb52eb3`. The code worker's other 190-ID slice is absent.

The candidate remains `replay_qualification.status=pending` with a null replay receipt. It is not the production allowlist. Each check has a typed API field, a SHA256-pinned exact 992 snapshot reference, an operation descriptor, and an evaluator symbol plus whole-file source hash. List-inventory absence is referenced through its successful collection status; the exact same-scope completeness and missing-field branches are in the per-check proof receipts. The gate's operation schema classifies the predicate; the source-line proofs define exact branches and comparisons. In particular, the CloudTrail prior-UTC-date boundary and Secrets Manager schedule's recorded `AutomaticallyAfterDays` threshold must be read from their pinned source proofs, rather than treating the schema's simple age threshold as an executable replay formula.

The [exact validation receipt](../../outputs/native-final-code-manifest-v2-84-validation.json) resolves all 248 recorded field references against snapshot SHA256 `3d7828c701a9457eeeb7d5aa497e1efd07a7977ccddeed498a73a2ba9dc2592f`, verifies 84 whole-file source hashes and 21 captured-clock references, and tests the unchanged code gate SHA256 `2be0d2e5db9e2beae26a7fce2a9193c87e65b1c2f55c5f89243ba512e91cc159`. The pending candidate admits zero. A temporary qualified copy of each row admits 78 and rejects the six below. A temporary qualified copy of the combined manifest admits zero because the gate fails closed on any rejected entry. No gate widening, model replay, production manifest edit, push, or deploy occurred.

| Check ID | Evaluator path | Current gate reason |
| --- | --- | --- |
| `aws.a.iam.unused_credentials_45_days` | `peaso/unused_iam_aws_completion.py` | Path outside current allowlist |
| `aws.a.iam.unused_credentials_90_days` | `peaso/unused_iam_aws_completion.py` | Path outside current allowlist |
| `aws.claude_a.iam.access_keys_used_45` | `peaso/unused_iam_aws_completion.py` | Path outside current allowlist |
| `aws.gap.iam.active_keys_used_within_45_days` | `peaso/unused_iam_aws_completion.py` | Path outside current allowlist |
| `aws.network.target_group_has_load_balancer` | `peaso/unused_network_aws.py` | Path outside current allowlist |
| `aws.cb.lambda.runtime_not_deprecated_list` | `peaso/checks/claude_aws_b_compute.py` | Runtime is a recorded API enum, compared with a pinned source-code deprecation date and captured clock; no recorded API timestamp field exists for the gate's age schema |

The six remain pending for independent code-gate review. The single-row admissions above are test-only and do not qualify this candidate for use.
