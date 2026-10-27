# GCP native-final scalar audit v1

This is a reviewed, inactive proposal based on deployed source `f204f3a5`.
The [receipt](native-final-gcp-scalar-v1.json) lists all 12 registered GCP
Hardening checks implemented by `field_check`. The exact field path, typed
passing and failing values, source references, and whole-file SHA-256 pins are
recorded there. The evaluator returns UNKNOWN for missing, malformed, denied,
or incomplete native data. It also returns UNKNOWN for unrecognized string
enums. Each candidate evaluates a recorded scalar setting, not the security
outcome of a running service.

`scripts/audit_gcp_native_final_scalar.py` replays the five fixture boundaries
for every ID and refuses an inventory or source-contract change. With a
same-snapshot saved pre-AI and final GCP report pair, it additionally compares
every selected native FAIL to the exact saved AI review row and the final
status, severity, base severity, evidence, and evidence summary. Its output
contains counts and hashes, not finding evidence.

No saved GCP report pair was available in this worktree or the local replay
directory, so the receipt is `source_proven_replay_pending`. It records no
production disagreement counts, model cost, or wall-time estimate. The
existing runtime gate admits AWS IDs only; this proposal changes no gate,
manifest, environment switch, or deployed behavior. GCP Hardening AI remains
enabled pending saved-review parity, a hosted cost and quality replay, and a
separately reviewed GCP admission change.

Reproduce with Python 3.12:

```sh
PYTHONPATH=. python3.12 scripts/audit_gcp_native_final_scalar.py \
  --output docs/ai-review/native-final-gcp-scalar-v1.json
```
