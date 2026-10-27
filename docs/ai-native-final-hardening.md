# Reviewed native-final Hardening gate

The committed `peaso/ai/native_final_allowlist.json` is empty and pending. It
admits no checks. A check can enter a new reviewed manifest only when the
prod992 audit records every reviewed FAIL for that exact `check_id`, finds zero
AI disagreements, and proves that the check is a pure, deterministic function
of recorded API fields. Eligible operations include literal comparisons,
fixed count thresholds, list membership, boolean combinations, and fixed age
thresholds calculated from a recorded scan time. Free-text or content analysis,
policy intent, and similar titles do not qualify.

The version-2 manifest names the exact prod992 scan and d3 base. Each admitted
check records the audit receipt digest, typed recorded API fields and their
recorded evidence references, a structured operation and fixed threshold, the
scan-time source when age is calculated, and an exact code-path audit reference
with a verified source-file SHA-256 pin.
These declarations require source review; their presence alone does not prove
that an evaluator is pure. Root sets
`replay_qualification.status` to `qualified` and records the replay receipt
digest only after the same-input replay gates pass. After committing that
manifest, activation requires both
`PEASO_HARDENING_NATIVE_FINAL_ENABLED=1` and
`PEASO_HARDENING_NATIVE_FINAL_SHA256=<sha256 of exact manifest bytes>`.
Any missing pin, changed bytes, unsupported version, malformed entry, or
pending replay disables the whole allowlist.

For admitted checks, the AI pipeline retains each original Hardening FAIL and
supplies a validated FAIL review with its exact finding ID to Priorities. It
does not send those rows to the Hardening reviewer or change their published
finding, outcome, or coverage. The finding API does not attach an `ai_review`
to those rows; the AI API labels their synthetic review rows with
`source: native_final`. Grouped report observations retain their native IDs.
UNKNOWN results and FAILs with incomplete dependency evidence continue through
the ordinary AI path. Unknown check IDs continue through AI review.
