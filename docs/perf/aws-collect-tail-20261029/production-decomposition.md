# 2dce production Collect decomposition

Supervisor follow-up, 2026-10-29. This analysis uses the actual saved
`2dce0099e79f4b04bed6bf2236488228` collector counters, not the local Docker
audit's execution time. `production-spans.json` retains every production
collector row and pins the saved export by SHA256. The generic four-cloud
baseline file contains **a51**, not 2dce; it adds no 2dce time series.
Root-owned saved exporter run `40840420069` later succeeded. Its mode0600
`~/peaso-work/receipts/aws-2dce-stage-metrics.json` (SHA256
`33b0df78eac0836afc57ce9dd9eaaf25ae7b935353a348102fce2ad694531d1c`)
has exact shared-field parity for all 43 collector/32 analyzer span rows and
elapsed/CPU/RSS counters. It compacts rows to count/process-CPU/wall and has null
task timestamps; it retains no job identity, per-call maximum, thread CPU,
artifact bytes or child CPU. Earlier richer numeric receipts remain the source
of those additional fields and bounds. No worker production read was made.

## Actual pipeline counters

| Component | Calls | Additive wall s | Longest call s | Thread CPU s |
| --- | ---: | ---: | ---: | ---: |
| Collection jobs, including nested dispatch | 1352 | 6039.321 | 1207.353 | 397.803 |
| CloudTrail pacing waits | 1461 | 1943.494 | 8.639 | 0.184 |
| IAM access-report pacing waits | 2209 | 947.957 | 4.662 | 0.087 |
| TruffleHog prepared subprocess | 148 | 855.931 | 29.501 | 0.609 |
| Public checkpoints | 66 | 551.671 | 317.341 | 141.304 |
| Automatic content scopes | 2 | 374.743 | 369.889 | 4.202 |
| Markdown rendering | 3 | 367.571 | 231.310 | 74.860 |
| Artifact S3 writes | 1750 | 147.203 | 8.237 | 5.592 |
| Kingfisher native | 98863 | 138.306 | 8.271 | 4.361 |
| Retry backoff | 295 | 76.088 | 1.686 | 0 |
| Artifact compression | 1612 | 55.974 | 9.547 | 19.476 |
| Kingfisher lock waits | 98863 | 23.685 | 5.880 | 0.004 |
| Final public snapshot adapter/redaction/seal | 1 | 12.750 | 12.750 | 13.362 |
| Artifact JSON serialization | 137 | 11.261 | 3.594 | 10.538 |
| ECS preparation queue waits | 35 | 3.515 | 0.363 | 0 |
| Checkpoint finish | 1 | 0.437 | 0.437 | 0.280 |

**Top three non-container spans by additive wall:** CloudTrail pacing,
IAM report pacing, TruffleHog preparation. Enclosing collection/checkpoint
spans are deliberately excluded from that ranking. This ranks measured
operation/wait totals, not exclusive critical-path cost or removable time.

Per-inventory wall cannot be recovered: the label `collection.job` has no
inventory/scope key. `global_job` can also call `regional_job` inside a second
`collection.job` span, so 1352 spans are not 1352 distinct inventories and
6039.321s is not a sum of independent work. The measured longest span occupies
at least **92.373%** of `worker.collect`'s 1307.040s. The longest inventory's
identity and allocation between content, API reads and pacing remain unknown.

CloudTrail's pacing span encloses `_sleep` before `lookup_events`, reserving
slots at 0.5s intervals per session/region. IAM's span encloses adaptive pacing
for `generate_service_last_accessed_details` / `get_service_last_accessed_details`
per session; the interval is clamped to 0.1–1s. These IAM report operations
are distinct from IAM Access Analyzer; none was invoked by this audit.
Neither wait counter is a count of service throttling errors. The separate
retry span combines service/transport failures and throttling; it cannot
supply a 429/throttle count or per-inventory retry attribution. Raising rates
would require error/call/cost evidence and does not qualify from these totals.

Checkpoint wall includes snapshot publication and full report publication.
Markdown's timer encloses rendering; its upload occurs after that timer.
Artifact serialization/compression/upload counters span the whole collector,
including operations outside checkpoints. They cannot all be assigned to
checkpoint calls or added to checkpoint wall. The final snapshot span wraps
redaction + public adapter + seal, placing a **12.750s upper bound on that
one final seal's wall time**, not all sealing during collection/evaluation.
No separate copy/seal/digest timer exists. `engine.validate` is not a seal
timer. A checkpoint/seal contention claim therefore remains unmeasured.

## What the production comparison supports

| Actual counter, 2dce minus a51 | Delta s |
| --- | ---: |
| Longest collection job | -50.429 |
| TruffleHog prepared-process additive wall | -50.917 |
| `worker.collect` | -48.263 |
| DDB Collect stage | -47.623 |
| Public checkpoint additive wall | +6.971 |
| Markdown additive wall | +10.083 |

Inference: the observed improvement aligns with the faster longest job/content
path, while aggregate publication wall increased. It does not demonstrate
that checkpoint removal caused the change. Inputs and inventories changed,
and there is no identity-bound before/after job timeline. Parent CPU increased
4.058s; completed-child CPU decreased 68.147s. These are task-wide counters,
not per-detector CPU measurements.

Concrete bound: all jobs are contained in `worker.collect`, so time after all
jobs finish is **0–99.687s** (`1307.040 - 1207.353`). A pure post-job-tail
optimization cannot directly remove 551.671s of checkpoint wall from that
tail. Checkpoint work earlier in Collect might also contend, but its saving
is unquantified. The difference between DDB Collect and `worker.collect` is
39.188s; it must not be relabeled serialization or sealing without a timeline.

## Fix disposition and exact missing evidence

**No same-output/same-cost throughput fix is measured or qualified.** At audit
checkpoint `2fa8a465`, no runtime source or rate setting changed. Later requested
per-job diagnostics are documented separately in `job-telemetry.md`. Eliminating waits, splitting the
longest job, or removing publication is not authorized by aggregate timing
alone. Prior synthetic scanner candidates do not meet the complete-content,
private-binding, RSS and billed-resource gate. Existing fanout stays disabled.

The next evidence needed is specific:

- Inventory type + hashed scope + queued/start/end times, with nested-parent
  identity, to name the longest job and the last non-content inventory.
- Batch/image binding, prep/consumer start/end, child CPU and full original
  replay bytes to test the longest image without changing its output.
- Checkpoint sequence/start/end and separate copy/redact/seal/digest timings,
  aligned to scanner activity, to establish contention or a serial barrier.
- Per-operation attempts, throttle/error counts and pacing history on the
  longest inventory; service wait sums alone cannot establish that path.
- Candidate/control complete native and private-reference output parity,
  cgroup/process-tree RSS and all billed task lifetimes. Parent RSS alone and
  idealized fanout division do not establish same cost.

All numbers above are existing production measurements or explicitly marked
bounds/inferences. Worker provider/model/Access Analyzer calls, production
reads/writes, scans, deploys and pushes remain zero. The new offline diagnostic
tests pass **4/4 with `--noconftest`**; the prior normal six-test receipt remains
historical evidence for its earlier tree. No new full runtime gate is claimed.
