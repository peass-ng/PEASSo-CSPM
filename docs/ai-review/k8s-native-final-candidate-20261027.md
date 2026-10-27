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

**Admission remains pending.** The available K8s paired replay covers Internet
Exposure, not Hardening. It supplies no matching native FAIL and AI verdicts
for these IDs. The AWS native-final manifest is pinned to the exact AWS 992
scan and its runtime gate accepts AWS IDs only. Reusing that receipt or adding
these K8s IDs to it would claim unmeasured zero disagreement. A K8s
same-snapshot Hardening baseline and candidate replay, source-field binding,
and a separate reviewed manifest gate are required before activation. No
runtime allowlist, deployment setting, or production scan is changed here.
