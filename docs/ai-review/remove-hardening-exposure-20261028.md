# Native Hardening and Exposure finality

Scans on AWS, GCP, Azure and Kubernetes now use native Hardening and Exposure verdicts as final. Network and Priorities are the only model stages. The scan selector, collection watcher, final analyzer, local runner and Fargate entry point reject or omit the removed stages. The former reviewer batch queue is now a Network-only call; the progressive child rejects non-Network stages and has no Hardening window or Exposure final-stage dispatch. Priorities receives native FAIL findings and the Network result; native verdicts are labeled `native_final` in the AI API and do not overlay finding status.

## Saved AWS snapshot measurement

Input: `~/peaso-work/replay/aws-bf67-collected-snapshot.json.gz`, the saved collection for scan `bf67a39766d14a19baf9d8298f23f7af`. Offline evaluation used `evaluate_snapshot` and the previous `review_groups.plan` batch size of 40; no cloud or model calls were made during measurement.

| Measure | Previous route on saved input | New route on saved input |
| --- | ---: | ---: |
| Native Hardening FAILs in offline evaluation | 16,284 | 16,284, all final |
| Native Exposure FAILs in offline evaluation | 505 | 505, all final |
| First-pass reviewer batches planned with native admission disabled | 21 Hardening + 5 Exposure | 0 |
| Hardening/Exposure model launches | 26 first-pass batches in the offline no-admission plan; actual deployed launch count unavailable | 0 |
| Hardening/Exposure model calls | Unavailable without a model replay | 0 |
| Hardening/Exposure model tokens | Unavailable without a model replay | 0 |
| Hardening/Exposure model wall time | Unavailable without a model replay | 0 seconds |
| Native evaluation wall time | 114.405 seconds (second local replay) | Same native evaluation; 114.405 seconds |

The second local replay loaded the compressed snapshot in 5.626 seconds, evaluated 124,416 native findings in 114.405 seconds, and peaked at 2,411,053,056 bytes RSS on macOS. First replay: 4.316 seconds loading and 96.428 seconds evaluating, with 2,285,223,936 bytes peak RSS. These timings vary with concurrent work on the host and do not include AI inference.

The matching production bf67 receipt, `~/peaso-work/receipts/prod-aws-ai-836a-full-final-summary.json`, records 1,316 Hardening and 504 Exposure AI inputs after its deployed native-final allowlist, Network completed, Priorities produced 15 actions, and the whole Analyze phase took 1,273.142 seconds. That phase includes native evaluation, AI and report publication; it is not model-only wall time. The offline 26-batch plan intentionally disables native admission to measure the former full-review route, so it is not the deployed bf67 task count.

For a separate production AWS scan, `~/peaso-work/receipts/prod-aws-ai-f204-final-summary.json` and its ECS task receipt record **16 total AI ECS tasks** across all stages, spanning 1,088.576 seconds from first creation to last stop (4,648.563 summed task seconds). That scan had 1,312 Hardening and 504 Exposure AI inputs after its native-final allowlist, plus Network and Priorities. The receipt has no per-stage task labels or token counts, so its wall time cannot be assigned specifically to the removed agents or compared as a same-snapshot before/after runtime.

## Verification

The targeted Network, Priorities, native finding, stage guard, Fargate, provider, briefing, output validation and release smoke suite passes with 316 passed and 4 skipped using the repository release Python environment and `--noconftest`. The selected progressive Network watcher tests and removed-stage ECS guards pass; 16 obsolete progressive reviewer cases were deselected. The release-only live smoke now uses the shipped Network/Priorities pipeline with offline native Hardening/Exposure findings; it no longer invokes the removed reviewer agents. Frontend TypeScript and Vite production build pass. The reviewed API Python source pin verifies 1,717 files, 30 direct SDK client sites and 12 used services; its focused gate has 9 passing tests. The combined API source and locked attestation gate passes 18 tests in `PEASO_SOURCE_ATTESTATION=always` mode.

## Decommissioned test coverage and current limitations

The earlier broad run (`/tmp/remove-ai-broad-tests.log`, before the targeted test revisions) had 615 passed, 86 failed and 6 skipped. Most red cases assert behavior intentionally removed by this change: Hardening/Exposure model launch and output validation in `test_peaso_ai_providers.py`, `test_peaso_ai_fargate.py`, `test_peaso_ai_output_validation.py`; reviewer batching and grouping in `test_ai_section_concurrency_20261022.py` and `test_ai_review_groups_20261026.py`; and Hardening/Exposure progressive windows, claims and reuse in `test_progressive_hardening_windows.py`, `test_progressive_analyzer_20261022.py`, `test_progressive_poll_cost.py` and `test_progressive_owned_tasks.py`. The focused review suite replaces those assertions with four-provider native-final inputs, Network/Priorities execution, direct stage rejection and ECS stage rejection.

Three GCP firewall index observed-text parity failures in `test_ai_net_speed_20261026.py` and one report projection failure in `test_api_report_projection_static_20261020.py` are separate current-path failures in the broad run. They do not exercise the removed agents and were not changed here. The source-attestation Terraform index tests also fail on a pre-existing `workflow.tf` hash mismatch in this worktree; the API Python source manifest and its locked gate are verified separately. Actual before model calls, tokens and model wall for the saved bf67 collection are unavailable because it has no AI task receipt; this report does not infer them from a different scan.
