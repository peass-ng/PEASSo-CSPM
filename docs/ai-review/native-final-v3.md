# Hardening native-final v3 proposal: scan 992d7b8cbd4340a79e41139ba1a44c1e

Status: **proposal only**. No model replay, deployment, or production change was made.

The exact pre-AI native FAIL set has 16,113 findings across 341 check IDs. The exact final AI review contains the same 16,113 IDs: 15,983 FAIL, 128 UNKNOWN, and 2 NOT_APPLICABLE. There are 130 verdict downgrades across 48 check IDs and zero published severity changes. The final grouped report alone omits 130 downgraded native FAIL observations, so the native mapping comes from the pre-AI receipt and exact finding chunks. Of the 341 check IDs, 293 have zero verdict disagreement and cover 15,788 native FAILs.

The [proof ledger](native-final-proofs-v3.json) explicitly approves 20 zero-disagreement checks with at least three initial representatives. Each approval names its installed evaluator line, helper lines, source digest, observed evidence keys, and exact predicate. The [reviewed manifest](native-final-reviewed-v3.json) records every zero-disagreement check's representative count and decision. Eleven high-representative checks have source-cited exclusions. All 262 checks with fewer than three representatives retain AI pending the code worker's independently signed receipt; none of those IDs is included here.

The approved predicates use recorded API fields and captured scan time: fixed age thresholds, counts, structured membership, boolean flags, and configuration enum combinations. Exclusions cover content secret indicators, free-text timestamp or naming interpretation, policy intent, and inferred configuration type without a bound source field. An approved control proves only the recorded predicate, not downstream effectiveness.

| Hardening queue | Exact 992 baseline | v3 proposal |
|---|---:|---:|
| Native FAIL rows sent to AI | 16,113 | 10,786 |
| Initial representatives | 778 | 527 |
| Initial tasks (capacity 40) | 20 | 14 |
| Observed recheck rows | 53 | 53 |
| Observed recheck tasks | 7 | 5 |
| Total Hardening tasks | 27 | 19 |

The fixed Exposure tail observed in the same saved run was eight tasks, so the Hardening plus Exposure planning count is 35 to 27 tasks. Scaling the saved mixed reviewer wall of 1,287.173 seconds by that task ratio gives **992.962 seconds** as a planning proxy. This is not a measured replay wall: scheduling, task latency, Network, Priorities, and model cost gates are not validated by this audit.

The [numeric receipt](../../outputs/native-final-audit-992-v3-numeric.json) contains per-check native FAIL, AI verdict, disagreement, representative, and decision counts without finding evidence or secret values. The [allowlist artifact](native-final-direct-derived-v3.json) contains only the 20 approved IDs and remains disabled until separately implemented and validated.
