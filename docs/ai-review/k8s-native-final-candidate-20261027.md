# K8s Hardening native-final source audit (2026-10-27)

The [offline receipt](../../outputs/k8s-native-final-source-audit-20261027.json)
records 24 controller Pod-template check IDs from
`peaso/checks/k8s_extended.py`: six controller kinds times four predicates
(`no_privileged`, `non_root`, `no_host_network`, `no_host_ports`). The source
file is SHA256-pinned in the receipt. `PYTHONPATH=. python
scripts/audit_k8s_native_final_candidates.py` reproduces it without cloud or
model calls.

For each ID, the script exercises the registered evaluator with PASS, FAIL,
missing, and malformed source fixtures; all 96 results match their expected
statuses and inputs remain unchanged. A collected synthetic Deployment also
passes through `evaluate_snapshot` with the four predicates and yields the
expected two FAIL and two PASS statuses. The source checks declared PodSpec
configuration, including init and ephemeral containers. They do not establish
runtime admission enforcement.

The [saved-pair audit](../../outputs/k8s-native-final-saved-pairs-20261027.json)
supersedes the initial absence finding. Read-only DDB and S3 discovery found
seven pre-AI/final manifest pairs on exact matching snapshots in five K8s
scans. Only the `05a1919e…` pair has FAILs in this 24-ID source candidate:
15 `k8s.deployment.non_root` and 15 `k8s.replicaset.non_root`. All 30 exact
finding IDs occur in the AI Hardening stage inputs, have AI verdict `FAIL`,
retain final `FAIL`, and retain identical evidence. Current source evaluates
the 30 bound snapshot resources as `FAIL` with identical evidence. The other
22 IDs have zero observed FAILs, so zero disagreement alone does not qualify
them. The other six pairs have no candidate FAILs. The `05a1919e…` DDB job is
completed; its AI artifact says `partial`, although Hardening coverage is
1594/1594 and all 30 selected reviews are present.

The separate [K8s allowlist](../../peaso/ai/k8s_native_final_allowlist.json)
contains only those two IDs. Its gate requires
`PEASO_K8S_HARDENING_NATIVE_FINAL_ENABLED=1` and an exact
`PEASO_K8S_HARDENING_NATIVE_FINAL_SHA256` manifest pin, and verifies the
reviewed source file hash. Both runtime settings are absent by default. The
offline substitution replaces exactly 30 saved AI FAILs with native FAILs,
keeps the other 1564 Hardening inputs in that pair, and preserves the entire
1594-ID verdict map. No hosted model cost or production scan gate was run.
