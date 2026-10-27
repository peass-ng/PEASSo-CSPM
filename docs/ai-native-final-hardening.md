# Reviewed native-final Hardening gate

The committed `peaso/ai/native_final_allowlist.json` is empty and pending. It
admits no checks. A check can enter a new reviewed manifest only when the
prod992 audit records every reviewed FAIL for that exact `check_id`, finds zero
AI disagreements, and identifies the recorded cloud API response and setting
path that directly proves the native result. Judgment, inferred context, and
similar titles do not qualify.

The manifest names the exact prod992 scan and d3 base. Each admitted check
records its audit receipt digest and evidence reference. Root sets
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
finding, outcome, or coverage. Unknown check IDs continue through AI review.
