# AWS Collect saved critical-path audit, 2026-10-29

Throughput disposition: **no scheduling/scanner candidate qualifies**. The
branch now also adds requested bounded per-job telemetry for the next measured
scan; see [job-telemetry.md](job-telemetry.md). The earlier audit/disposition
receipts describe the unchanged runtime at commit `06d40219`. Scanner,
checkpoint, Markdown, task sizing and fanout behavior remain unchanged.
No provider/model operation, paid IAM Access Analyzer operation, deployment,
push, connector write or production scan ran.

The supervisor follow-up in [production-decomposition.md](production-decomposition.md)
adds the complete 2dce production pipeline and top-three non-container spans,
including pacing/backoff, serialization and the concrete final-seal bound.
Its reproducible numeric source is `production-spans.json`; these measurements
come from production counters rather than local audit execution time.

## Measurements and attribution

`saved-analysis.json` is reproduced from the exact saved files whose SHA256s
it records. bf67/dfa have complete event streams; a51/N+1 export only the latest
cumulative frame, despite recording the number of frames originally observed.
N+1 is `2dce0099e79f4b04bed6bf2236488228`. dfa names the source wave; its actual
scan ID is `8ec972d12d4c433fbab217f33dfb084c`. These historical executions have
different inventories and are not controlled before/after experiments.

| Collector measurement | bf67 | dfa | a51 | N+1 |
| --- | ---: | ---: | ---: | ---: |
| `worker.collect`, s | 1607.691 | 1325.751 | 1355.303 | 1307.040 |
| Longest `collection.job`, s | 1276.834 | 1250.266 | 1257.782 | 1207.353 |
| TruffleHog process calls / additive wall s | 151 / 883.840 | 149 / 807.795 | 149 / 906.848 | 148 / 855.931 |
| Public checkpoint calls / additive wall s | 43 / 725.394 | 46 / 614.718 | 66 / 544.700 | 66 / 551.671 |
| Markdown calls / additive wall s | 6 / 419.969 | 5 / 361.002 | 3 / 357.488 | 3 / 367.571 |
| Parent CPU, s | 1452.202 | 1179.777 | 1148.154 | 1152.212 |
| Completed subprocess CPU, s | 803.925 | 739.980 | 836.346 | 768.199 |
| Parent peak RSS, bytes | 7372439552 | 7368720384 | 6927974400 | 7005929472 |

Use the final runtime frame for these counters. Earlier handoff excerpts can
refer to an earlier frame. Preparation timers in content-batch records also
include staging/adaptation, so they differ from `prepared_process` spans.

The N+1 authoritative DDB Collect stage was **1346.228s**, 39.188s longer than
`worker.collect`. Its runtime recorder window was 1345.036s. These clocks
measure different boundaries. a51 DDB Collect was 1393.851s: a historical
47.623s decrease, not a measured effect of any change on this branch.

For N+1, `publication.markdown` recorded **74.860 thread CPU seconds** and
333.567 process CPU seconds during 367.571 additive wall seconds.
`worker.public_checkpoint` recorded **141.304 thread CPU seconds** and 527.387
process CPU seconds during 551.671 additive wall seconds. Process CPU includes
all concurrent threads in the collector; it is not exclusive renderer CPU.
Markdown is nested inside publication/checkpoint work, so these counters must
not be added. Thread CPU can also omit work performed by native helper threads.

TruffleHog spans recorded only 0.609 thread CPU seconds on the waiting caller,
plus 541.023 process CPU seconds from concurrent parent work. Neither is the
scanner subprocess CPU. The task-wide **768.199 completed-child CPU seconds**
cannot be allocated to individual batches/images from these receipts.
Parent + completed-child CPU was 1920.411s, about **1.428 average CPU cores**
over the 1345.036s recorder window. This is observed utilization, not proof
that a smaller task or more scanner lanes would preserve throughput/RSS.

## Critical path and per-image limit

The full bf67 stream brackets the last job completion at process
1286.805–1300.282s and the post-job tail at **317.380–330.857s**. The dfa stream
brackets last job completion at 1265.113–1295.136s and the post-job tail at
**40.201–70.224s**. Bounds use the last sampled active job, the first sampled
final completed-job count, and the longest job's minimum possible completion
time. Millisecond counters are rounded. The retained tail samples show active
checkpoint/Markdown work after bf67 jobs end; dfa's tail is already much smaller.

a51/N+1 cannot support this reconstruction. However, every collection job is
inside `worker.collect`, so time after all jobs finish is at most
`worker.collect - longest_job`: **97.521s / 99.687s** respectively. This is an
upper bound, not an observed tail duration or a saving. N+1's longest job
occupies at least 92.37% of that collect interval. Earlier full-stream analysis
identified one late ECR image job; attributing the N+1 longest job to that same
image would be an inference, not an identity-bound measurement.

bf67's 136 batch records contain 101555 items / 837871664 input bytes;
dfa's 132 contain 101534 / 837994276. The receipt bins completion timestamps,
not work executed exclusively inside each bin. Batches overlap and their
consumer timer includes caller-side parsing, Kingfisher, private capture and
reference assembly. Their aggregate duration is not elapsed critical-path
time. Removing checkpoint work could reduce contention, but these differing
content mixes and missing N+1 frames cannot establish that causal saving.

The saved bf67 snapshot contains **35 repository selections**: 23 collected
package sources and 12 not collected. It preserves **146 references in seven
repositories**. A collected source does not imply complete content: all 23
indicator records explicitly have `NativeResponseComplete=false`. The receipt
retains hashed repository/scope/selected-digest bindings and reference counts,
with per-image wall/CPU/RSS explicitly null. Batch IDs are not joined to image
identities in the saved stream, and original complete image content is absent.
There is no justified per-repository throughput or memory ranking.

The current source explains where serialization remains:
`aws_package_content_indicators.enrich` walks repositories in inventory order;
`_image.flush_pending` consumes prepared groups and their source windows in
order; `scan_content` creates one Kingfisher executor for each uncached source
while TruffleHog parsing and private capture remain on the caller. Parallel
repository inspection could overlap independent work, but cannot divide the
one late image's ordered consumer. A consumer change must preserve complete
file/chunk receipts, positive/partial refs, output bounds and source contexts.

## Resource-time and code gate

N+1's saved ECS collector timestamps span image-pull start to stopped:
**1435.948s**, rounded upward to **1436s**. At repository defaults 4 vCPU / 16 GiB,
the collector provisioned-resource proxy is **5744 vCPU-seconds / 22976
GiB-seconds**. This includes startup/termination overhead, unlike multiplying
Collect alone (5384.912 vCPU-seconds). It is not an invoice or verification of
the deployed task-definition sizing. Dollar prices and unrelated task costs
are not inferred. Parent RSS is **6.525 GiB** and excludes child/process-tree
and tmpfs peaks, so it cannot qualify a 2-GiB scanner task.

For a candidate using the same collector size plus 1-vCPU / 2-GiB scanner
tasks, the saved sizing proxy requires both:

```
4 * billed_collector_seconds + sum(billed_scanner_seconds) <= 5744
16 * billed_collector_seconds + 2 * sum(billed_scanner_seconds) <= 22976
```

Each lifetime includes pull/startup/idle/termination and its applicable minimum
and rounding. Any changed analyzer lifetime, retries, fallback scanning,
transport/storage and log charges also belong in a complete no-extra-cost
gate. An unmeasured ideal four-way division does not pass it.

The prior executor-reuse experiment had only small clean synthetic parity;
the larger four-Kingfisher-instance experiment regressed CPU × peak RSS by
about 15.2% (`cspm-aws-scanner-tail-20261028`, receipt commit `24322e66`). Neither
has full content/private-reference parity. Repeating that synthetic benchmark
would not repair the missing full input. Remote preparation alone also leaves
the ordered consumer/private-capture path in the collector.

No scanner implementation is admitted. Qualification still needs pinned
Linux detector versions, complete clean/positive/decoded/partial/error output
and private-source/reference parity, exact source-successor reconstruction,
measured critical-path throughput, process-tree/cgroup RSS, and total billed
resource-time parity. The disabled Fargate candidate stays disabled. No
historical hash, guard or source pin is weakened. `disposition.json` records
the exact unchanged audit-checkpoint runtime hashes against base `fc288107`
and validation. Later telemetry has its own exact successor proof.

## Reproduction

Run from this checkout with the existing saved artifacts; this uses only the
Python standard library and local files:

```sh
python3 scripts/audit_aws_collect_tail.py \
  --events bf67 /private/tmp/aws-bf67-collector-events.json \
  --events dfa /private/tmp/aws-dfa-collector-events.json \
  --metrics a51 "$HOME/peaso-work/receipts/prod-aws-a51ff5a9-stage-metrics.json" \
  --metrics n1 "$HOME/peaso-work/receipts/stage-metrics-40815739922/cspm-postrelease-stage-metrics/cspm-postrelease-stage-metrics.json" \
  --snapshot "$HOME/peaso-work/replay/aws-bf67-collected-snapshot.json.gz" \
  --output /tmp/aws-collect-tail-reproduced.json
cmp docs/perf/aws-collect-tail-20261029/saved-analysis.json /tmp/aws-collect-tail-reproduced.json
```
