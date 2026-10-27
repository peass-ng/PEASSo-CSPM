# Native-final non-c2b scope limit

The exact 992 replay proves the recorded FAIL branch for six checks (20 FAIL observations, six initial representatives). It does **not** qualify their check IDs for a global native-final allowlist. All six retain AI review until their evaluators fail closed on future incomplete or malformed input and those paths are verified:

| Check ID | Future-path blocker |
| --- | --- |
| `aws.claude_a.guardduty.detector_no_findings` | `collected()` accepts a missing nested collection status. |
| `aws.claude_a.guardduty.prowler_no_high_severity_findings` | `collected()` accepts a missing nested collection status. |
| `aws.claude_a.guardduty.prowler_ai_protection` | `prowler_flags()` defaults a missing feature name or status. |
| `aws.claude_a.guardduty.prowler_runtime_monitoring` | `prowler_flags()` defaults a missing feature name or status. |
| `aws.iam.console_mfa` | `aws_mfa()` can return FAIL when MFA device collection status is outside the complete states. |
| `aws.logs.retention` | `_native_optional()` can treat an omitted retention field as complete without the native response-complete marker. |

The [source proof](native-final-nonc2b-remaining-proofs-v1.json) records both the exact 992 evidence and each unresolved future path. The six are marked `retain_ai_pending_evaluator_fail_closed_fix`; `new_allowlist_candidate_count` is zero. This note and receipt do not activate a manifest or run a model replay.
