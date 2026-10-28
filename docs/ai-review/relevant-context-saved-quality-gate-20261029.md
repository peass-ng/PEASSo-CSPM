# Saved AI context quality gate, 2026-10-29

Both candidates kept `OPENAI_BEST_QUALITY`, high effort, 30 turns, their deadlines and tools. Exact relevant source records remained available through the existing context reader. Neither candidate is admitted for release.

| Stage and saved input | First-read bytes before | After | Reduction | Quality result |
| --- | ---: | ---: | ---: | --- |
| Network, GCP 66da | 244,811 | 203,055 | 17.06% | First model arm had a configuration error; no paired verdict. |
| Network, K8s e109 | 146,339 | 115,088 | 21.36% | Fresh baseline and candidate each returned 0 findings and 0 graph citations. Prior saved high-effort output had 1 architecture finding with 10 valid graph citations. Historical floor failed. |
| Priorities, AWS bf67 | 484,074 | 442,295 | 8.63% | Fresh baseline 13 critical citations; candidate 10. Prior saved high-effort output had 21. Candidate omitted the `least_privilege` critical category. |

Network preserved all 54 saved exposure IDs, statuses, observations and evidence, with exact original rows reachable through `source_ref`; the graph and topology were unchanged. This input parity did not establish output quality. The K8s hosted receipt is `~/peaso-work/network-relevant-private/k8s-relevance-historical-quality-gate.json` (SHA256 `c389c1a6`).

Priorities grouped 91 unlinked, non-FAIL low-severity Hardening or compliance cases into eight orientation buckets. The first read retained 588 higher-signal cases and each deferred case's signal and ID. All 105,661 original findings stayed in `context.sqlite` for exact lookup; seven saved critical check IDs were present in the input. A future unknown category is kept visible by default. In the paired alias/high/30 replay, baseline completed in 336.730 seconds with 15 actions and 48 finding citations; candidate completed in 391.691 seconds with 15 actions and 54 citations. The candidate covered 10 critical findings and 7 critical checks versus 13/9 in the fresh baseline and 21/11 in the prior high-effort output. The private comparison receipt is `~/peaso-work/replay/priorities-relevance-bf67-pair/quality-receipt.json` (SHA256 `0e042b97`).

The candidates are retained as research branches. Do not merge the Network or Priorities context changes. The GCP Service Usage quota recovery is independent and can be released separately after source review.
