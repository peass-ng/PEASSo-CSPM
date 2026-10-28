# AWS b440 versus bf67 Collect timeline

Read-only CloudWatch collector streams were compared from process startup:
bf67 `collector/collector/54aa8062173e4c2895cedf7d6fe30c57` and b440
`collector/collector/0ffaac239aac47b59e4acdf329881fbc`. b440 ran the
pre-optimization d7 release; this is a regression diagnosis, not an
after-deployment result for this branch.

| Collector measure | bf67 | b440 | Change |
| --- | ---: | ---: | ---: |
| `worker.collect` wall | 1,607.7 s | 1,721.2 s | +113.5 s |
| Longest `collection.job` | 1,276.8 s | 1,380.1 s | +103.3 s |
| Last job completed, sampled | ~1,300 s | ~1,416 s | ~+116 s |
| ECR layer URL calls | 179 | 179 | 0 |
| ECR layer URL SDK additive wall | 6.0 s | 7.3 s | +1.3 s |
| Scanner windows / input | 101,555 / 837.9 MB | 101,536 / 837.7 MB | effectively equal |
| Scanner preparation additive wall | 954.1 s | 1,043.1 s | +89.0 s |
| Scanner consumer additive wall | 1,202.8 s | 1,229.3 s | +26.5 s |
| Public checkpoint additive wall | 725.4 s | 940.7 s | +215.3 s |
| Markdown additive wall | 420.0 s | 484.6 s | +64.6 s |

The regression is in the long content job, not in ECR API volume or throttling.
Scanner preparation plus consumption rose 115.5 additive seconds on almost
identical input. Checkpoint and Markdown work also increased, overlapping that
job; the trace cannot assign the entire job delay to either source. On bf67,
the first Markdown finished by about t61 in 3.8 seconds, while reports 2–5
added 356.4 seconds and completed before t850. On b440 those four reports
added 420.5 seconds, including a 224.6-second fourth render. Both runs still
started content near t0 and finished the other API chains before the last
content job.

The eight immutable bf67 report manifests were read through the wiki profile.
The first six are Collect publications. Reports 2 and 3 (sequences 276 and
478) completed no new section; reports 4 and 5 first completed
Images/Network and Least Privilege, respectively. Report 6 first completed
Exposure/Privesc and was the terminal pass already deferred by `7fcaae4c`.
The saved CloudWatch Markdown counter puts reports 2 and 3 at 78.196 seconds
of additive render wall. Their S3 manifests were committed at 23:35:05 and
23:37:39 UTC. No report bodies or secret values were printed.

Selected AWS content scans now defer category-only cumulative report refreshes
after 256 durable native envelopes, even before automatic content begins. A
newly completed section still publishes immediately, including a late leaks
section needed by progressive analysis. The threshold was crossed by about
t46 in both saved streams. Bounded raw
batches continue to commit completed envelopes; an interrupted collection
still forces its latest partial report. Analyze builds the complete final
report and Markdown from the same final native snapshot, so their bytes and
coverage inputs do not change. The live partial report can be less recent
for category-only changes while content collection runs.

**bf67-based projection:** the earlier terminal deferral removes an estimated
218–228 seconds of post-job evaluation/checkpoint wall, putting `worker.collect`
near t1379–1389 if job time is unchanged. The verified section states identify
reports 2 and 3 as category-only refreshes, so this gate is eligible to avoid
78.196 additive seconds of bf67 Markdown. Those renders overlapped collection;
no further Collect wall seconds are credited without a paired production scan.
The 30-second post-job target and
the ≤800-second Collect target remain unproven. bf67 has 198 incomplete
collection statuses, so the literal zero-incomplete target is also unmet.

Normal pinned Python 3.12 focused checkpoint tests passed: 27/27, including
the late-section and explicit-flush regression. This owner
made no cloud scan, push, or deployment.
