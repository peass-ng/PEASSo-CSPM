# Bounded job identity for the next measured AWS scan

The saved 2dce counters cannot identify the 1207.353s inventory. A search of
384 local root receipt files under 10 MiB found no identity-bearing job timing
records; the available complete event streams are bf67/dfa/d565, not 2dce.
The existing recorder and exporter never retained a job kind/scope binding.
Export run `40840420069` succeeded; its newly saved mode0600 compact receipt
has exact shared-field parity with the earlier counters but no job identities.
It cannot reconstruct information that was not emitted. No inventory is
inferred from the additive pacing totals.

This change adds diagnostics only. **No scheduling, concurrency, API pacing,
scanner, content, snapshot/report output or Fargate activation changes.**
Root owns review, integration, deployment and the next production scan after
the independent K8s/AI repair release. There is no measured throughput win.

## Data and privacy contract

The existing global/regional `collection.job` contexts now supply their
code-owned kind and scope to an optional diagnostic context. One event is
emitted on completion under the constant log marker:

```
peaso collection job metrics:
```

Events contain only version, process-local sequence/parent numbers,
`kind_sha256`, `scope_hmac_sha256`, start/end/wall milliseconds, thread/process
CPU milliseconds and an exception-raised bit. No native item, resource ID,
account, region, source path, credential, exception value or HMAC key is logged.
The bit means an exception escaped the job, not that returned inventory was
complete. Process CPU includes concurrent parent threads; child CPU and
per-job RSS are not measured by these events. Start/end are relative to the
collector recorder; queue time is not separately measured.

Kind hashes are accepted and decoded **only against the immutable reviewed
730-kind roster** `peaso/collection_job_kinds_20261029.json`, SHA256
`37e677633d601df85231f732f7ee6d04e2d9a497391274cc91f66d23974123b9`.
The module verifies those exact bytes and exposes an immutable mapping.
Arbitrary kind strings never enter the event channel; roster failure disables
the diagnostic for that job and increments the rejection count without
changing collection. The roster exactly covers the current
`SPECS | GLOBAL_TYPES | FETCHERS` dispatch labels. Adding inventory requires
an explicit roster/source-pin review, not automatic discovery during a scan.

Scopes use HMAC-SHA256 with 32 fresh random key bytes per collector
configuration, which occurs once per worker scan. The global job hashes its
account scope; regional jobs hash account/region. A new scan cannot correlate
the old scope hashes. Closing the recorder releases the key, and the fork hook
discards inherited state without acquiring an inherited lock or logging a
parent summary. Scope hashes remain opaque; the decoder cannot recover an
account or region. Nested global-to-regional calls have parent sequence links,
so their durations must not be summed as independent inventories.

## Cardinality and retention bounds

- At most **4096 completed-job events** are streamed per collector scan.
- The recorder keeps only the **16 longest completed jobs**, plus fixed
  counters; it never retains a list of all raw inputs or all jobs.
- Close emits **one final summary** with started/completed/streamed/suppressed,
  delivery-failure/rejected counts and those 16 longest rows. A late longest
  job remains available even when streaming hit the cap.
- The exporter retains at most 4096 streamed rows plus 16 summary rows.
  Schema/integers/hashes are validated again before logging or retention.
  These are ordinary log fields, not dynamically named metric dimensions.
- A missing summary, started/completed mismatch, rejected jobs, delivery
  failures, invalid/overflow events or mismatch with final `collection.job`
  count is incomplete evidence. Suppression is explicitly reported. Full
  per-job retention above the cap is not claimed, even though longest-job
  summaries remain bounded and available after a successful close.

## Concrete exporter path for root

`exporter-job-retention.patch` adds `JobRetention` to the existing root-owned
`cspm/export_saved_stage_metrics.py` read loop **before** it skips messages
without the old runtime marker. It returns the validated job envelope at
`scans[].tasks[].collection_job_metrics` alongside the unchanged numeric
frame. It uses the same existing paginated log reads, with no second AWS
read loop. The worker did not modify root's operator checkout or run it.
If root saves the compact `roles[].spans` representation used for 40840420069,
it must also copy `collection_job_metrics` into the collector role; a numeric
span-only projection would discard the new evidence again. The decoder accepts
both full saved exports and that compact representation with retained jobs,
and fails explicitly when a compact receipt lacks them.

`exporter-job-retention-proof.json` pins the exact original/candidate exporter
source and patch bytes. The actual patched exporter was executed against two
fake pages: it retained the hashed job and final summary, retained the legacy
numeric frame, rejected malformed job data, and exposed no synthetic resource
values. The saved-export decoder was also exercised end to end.
The patch applies cleanly to a temporary copy of the pinned original exporter;
both full and compact saved-export decoding were verified. A compact receipt
without retained jobs is explicitly rejected. Linux decoding reproduced the
saved decoded bytes with networking disabled.
The patch has zero context to avoid trailing-whitespace context lines in the
saved artifact. Verify the original source SHA256 from the proof first, then
use `git apply --unidiff-zero --check` and `git apply --unidiff-zero` in the
operator checkout after review.

Root can review/apply that patch after K8s repair and package the new module
and fixed JSON roster from this branch in the next release. The wheel
package-data list explicitly includes the roster, as does Docker's directory
copy; the package-data entry has a focused check. The API source
review correctly reports one new module/four changed modules and **29 direct
SDK client sites, unchanged**. Root must refresh generated source/catalog
bindings on the final assembled tree; this worker does not overwrite those
root-owned release bindings or claim a deployment-ready release gate.

After that release and a root-owned measured scan, save the patched export
mode0600 and decode locally:

```sh
PYTHONPATH=. python scripts/decode_collection_job_metrics.py \
  --events /path/to/saved-stage-export.json --scan-id SCAN_ID \
  --output /path/to/decoded-job-timings.json
```

The decoder accepts raw saved event arrays/log lines too. It resolves only
the fixed roster and preserves opaque scope hashes, parent links and summary
limits. First confirm final summary completeness against the numeric job
counter; then identify the longest job by kind, opaque scope and sequence.
Only that measured result can justify an intra-job split or scheduling change.

## Qualification and overhead

Normal focused suite: **19 passed**, including the actual worker IPC/parser,
logging/delivery failures, Access Analyzer live-call ban, cap/late-longest
retention, fixed-roster rejection/tamper behavior, scan-key rotation/privacy,
and exact whole historical source reconstruction. Actual collector baseline,
enabled and broken-diagnostic arms return the **same complete snapshot and
snapshot ID**, with two scripted SDK calls each. Producer clock/capture UUID
generators are fixed for that comparison; no returned metadata is excluded.
These are synthetic native responses, not a production full-content replay.
The latest offline diagnostic/publication selection passes 9 tests, including
the subsequent package-data check; those tests overlap the normal suite.

The exact AWS file and `collect` callable inverse transitions reconstruct
their unchanged historical predecessors. Only the two span invocations gain
diagnostic arguments; no old historical digest or guard is relaxed.

Pinned network-disabled Linux/amd64 image `eca921607a21ead7acf1ad02c55a6d151cc2e252fc14db8300db8dcfc47b38d6`
ran fresh-process ABBA on 1352 synthetic empty jobs, 16 threads, 4 CPUs/1 GiB.
Both instrumented runs emitted 1352 events + one summary, **436328 bytes** of
diagnostic text, and the same complete synthetic output digest as controls.
Instrumented CPU was 0.092680/0.089212s versus controls 0.036418/0.026310s.
This warm-roster microbenchmark includes JSON sink serialization but excludes
worker IPC, hosted log ingestion and production contention. It establishes
neither production speedup nor billed-cost parity; extra diagnostic log volume
is explicit. The numerical receipt is `job-telemetry-qualification.json`.

The unchanged-duration reordering floor remains **1207.353s**; sub-15m Collect
requires at least **307.353s (25.46%)** internal reduction before other
overhead. No such reduction is claimed. Provider/model/paid Access Analyzer
calls, worker production reads/writes/scans, deploys, pushes and connector
changes are zero.
