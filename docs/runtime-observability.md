# Scan performance diagnostics

Hosted collector and analyzer workers emit bounded structured performance aggregates every 30 seconds and before their terminal result. These diagnostics do not enter snapshots, reports, findings or AI inputs. They do not add cloud requests or validate discovered credentials.

The supervisor logs `peaso runtime metrics` with fixed stage labels and numeric counters. Each row contains execution count, cumulative and maximum wall time, thread CPU, process CPU observed during the span, error count and byte count. Active spans include their age, so a long operation remains visible before it finishes. Top-level elapsed time, process CPU and peak process RSS accompany every frame. Completed child-process CPU is separate; it excludes tools that are still running.

| Stage group | Work measured |
| --- | --- |
| AWS collection | Global and regional jobs, CloudTrail pacing, IAM report pacing, application retry waits |
| Engine | Snapshot validation, inventory extraction/indexing, native checks, analysis, graph generation, privilege escalation |
| Worker | Collection, evaluation, redaction, final snapshot, checkpoint publication, AI, final publication |
| Publication | Private-value filtering, review application, grouping, native expansion, Markdown, findings/coverage/resource chunks, least privilege and graph projections, network snapshot and manifest commit |
| Artifact storage | JSON serialization, compression, file writes, S3 uploads and batch backpressure/fences |

`aws_sdk_metrics` records cumulative per-service/operation calls, completed and inflight calls, summed/maximum latency, SDK retries, throttled attempts, failed attempts, terminal errors and declared response sizes. Operation names come from the local SDK model. Request arguments, account/region identifiers, URLs, headers, exception messages, response contents and credentials are excluded. Rows are bounded to 4,096 operation pairs and 64 rows per frame. The final overflow row aggregates further pairs. Clients created after instrumentation is installed are observed; hosted workers install it before credential preflight and artifact clients.

Content-batch diagnostics separately record preparation time, caller-body time, prepared/serial lookup counts, byte/window counts and fixed fallback reasons. Caller-body time may include multiple detector operations; it is not an individual detector CPU measurement. SDK latency does not measure subsequent consumption of a streaming response. Artifact S3 timing measures its synchronous request; numeric declared response bytes are not downloaded-image byte counts.

## Reading the measurements

Compare the elapsed critical path with active spans and the slowest stages first. High thread CPU points to local computation. High wall time with low thread CPU can indicate network, subprocess, lock, queue or backpressure waits; distinguish those using the narrower spans and SDK counters. Sustained throttling/retry counts identify retry pressure. Separate application pacing from SDK latency before raising concurrency.

Nested or concurrent span durations overlap and must not be summed into a scan duration. Process CPU measured inside concurrent spans overlaps too; thread CPU is narrower. RSS is a process high-water mark, not per-stage allocation or current usage. SDK counters are cumulative, so do not sum successive frames; compare deltas within the same worker process. Error counters are diagnostic and do not replace the finding's status or coverage.

Transport and logging failures are contained. Disabled spans do not read clocks. Existing findings, native data, ordering, validation, checkpoints, lease acknowledgements and manifest fences retain their original semantics. Local helper overhead benchmarks and fake-provider tests qualify instrumentation behavior; they do not establish which stage dominates a production scan. Use an actual instrumented scan before attributing a long runtime to cloud rate limits or claiming a speed improvement.
