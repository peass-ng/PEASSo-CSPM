# AWS bf67 native Analyze, second optimization pass

The local replay uses the private saved bf67 collected snapshot. It makes no
cloud/API calls. Local timings vary with other workers on the shared host and
do not prove hosted wall time. The production receipt in the preceding
`aws-bf67-analyze-native-20261028.md` measured 327.593 s of non-AI Analyze;
the new target is 150 s.

## Current local baseline

On the current branch, Python 3.13 replayed 391,100 resources and 105,659
findings. Native evaluation took 41.66 s wall / 40.45 s CPU; one complete
local file publication took 56.25 s wall / 48.48 s CPU. Whole-process peak
RSS was 2.718 GiB. Largest spans were Markdown 30.13 / 27.61 s,
resource chunks 11.56 / 8.82 s, native checks 9.38 / 9.27 s, privesc
6.74 / 6.54 s, analysis 3.44 / 3.31 s, and graphs 2.99 / 2.89 s.
Local file publication does not exercise hosted gzip or S3 upload.

## Resource chunk memory and CPU

The publisher previously made every resource output dict before sorting all
391,100 rows. It now sorts references to the existing inventory rows and
constructs output dicts as chunks are encoded. The same 1,576 chunk bodies,
403,164,270 bytes in total, matched byte for byte in both paths (concatenated
SHA-256 `aa3267e7801ccc4c3e1db60789bd8f8f6b34c54385694f36674a40f78d680c17`).
The local capture made zero cloud/API calls.

| Run | Before | After |
| --- | ---: | ---: |
| First wall / CPU | 10.50 / 8.60 s | 6.83 / 5.59 s |
| First peak RSS | 1.827 GB | 1.655 GB |
| Reverse-order wall / CPU | 13.35 / 9.72 s | 30.83 / 11.43 s |
| Reverse-order peak RSS | 1.747 GB | 1.302 GB |

The reverse-order run coincided with eight other CPU-heavy Python processes
and is not evidence of a wall-time gain. Both runs show lower peak RSS; the
first shows lower CPU, while the contended reverse run does not. Focused
publication tests passed 30/32. The two failures also occur on the unchanged
publisher: `test_complete_publisher_retains_native_artifacts_and_private_output_boundaries`
reads a closed simulated S3 file. The API source manifest still covers 1,717
files with the same direct SDK client closure.

## Markdown sink writes

The binary Markdown sink now writes an ordinary complete byte string directly
and constructs a memoryview only when a custom or short-writing stream accepts
part of it. Error and partial-write behavior is unchanged. The full
861,313,699-byte export matched SHA-256
`64b4d3c1d563c64352a842892c5ed77804592dd48cf67031b7c1b984281db9ac`
before and after in both pair orders.

| Pair order | Before wall / CPU | After wall / CPU |
| --- | ---: | ---: |
| Before, after | 32.19 / 30.16 s | 27.20 / 26.55 s |
| After, before | 43.28 / 32.63 s | 51.02 / 31.40 s |

CPU improved in both runs; wall time was unstable under host contention.
The paired process high-water RSS was 2.464 GB in the first pair and
2.725 GB in the second, so it cannot attribute memory to one renderer.
No cloud/API calls were made. Focused Markdown tests passed 108/108.

## Hosted-style compression and upload profile

A local S3 adapter used the real serializer, batch, gzip, and file upload
paths, but discarded upload bodies instead of calling AWS. One saved-report
publication, with its grouping prepared as in the current evaluator, took
89.72 s wall / 60.72 s process CPU under host load and peaked at 2.362 GB
RSS. It issued 1,637 simulated puts carrying 243,005,150 bytes; 1,614
objects were gzipped. Compression spans summed to 23.71 s wall / 6.82 s
thread CPU; simulated upload read spans summed to 0.02 s wall. The
upload simulation made zero cloud/API calls and cannot model S3 latency.
The old production bf67 receipt measured 130.679 s of SDK put wall summed
across 2,511 calls in two publications, some of which overlap through the
bounded upload batch.

## Check, privesc, exposure and network profile

The current AWS replay selected 1,412 native checks and again produced
391,100 resources and 105,659 findings. With check timing instrumentation
and heavy host contention, it took 109.50 s wall / 53.04 s CPU. Native checks
used 38.70 / 17.17 s, privesc 22.00 / 11.24 s, analysis 10.62 / 5.40 s,
and graph building 3.60 / 2.08 s. Within analysis, principal exposure used
1.00 / 0.57 s and internet exposure 0.47 / 0.27 s. IAM graph build used
3.19 / 1.81 s; network graph build 0.42 / 0.26 s and network annotation
about 0.001 s. The privesc evaluator reported 19.34 s evaluate and 1.51 s
graph wall within its span. These phases made zero cloud/API calls.

One Secrets Manager CMK check dominated native-check CPU: 23.48 s wall /
8.90 s CPU in the contended detailed replay. It rebuilt the same validated
secret inventory map for every secret in a scope. The shared `_secret_index`
helper now uses the existing `MemoIndex` cache; ordinary dict callers still
recompute. A paired full evaluation of the saved bf67 snapshot produced the
same 211,024,918-byte serialized report (SHA-256
`8009ae5069032bfd503a49c23bdb7e5f83e91ce1a98e732b8b046c4cf2b79a48`),
391,100 resources and 105,659 findings. CPU fell 57.11→49.36 s; wall was
159.51→173.17 s under severe host contention. Pair-process high-water RSS
was 1.801 GB and cannot attribute memory to either variant. API calls were
zero. The relevant native-check and native-final source-audit tests passed
55/55. The audited check implementation file is unchanged; this change
only caches its immutable per-scope helper result.

## Content, reachability and other clouds

The exact ten content selectors from the hosted request were not in the saved
snapshot. As a proxy, a separate AWS replay selected all 18 known AWS content
checks. Those checks took 1.93 s wall / 1.01 s CPU after inventory preparation;
the full content-only replay took 25.84 / 13.78 s under contention and produced
4,891 findings. EC2 user-data indicators used 0.59 s CPU and selected
configuration content indicators 0.39 s; the other 16 checks shared about
0.03 s. Matching over captured content is therefore small compared with
inventory preparation on this snapshot. No collection or API calls occurred.

Native Analyze builds a network graph and a scoped network snapshot; the
explicit reachability evaluators are called from server query endpoints, not
from the scan evaluator. On bf67, network graph build used 0.42 s wall /
0.26 s CPU in the detailed replay. Network AI input preparation used
2.37 / 2.05 s and selected 1,410 inventory resources; the publication's
network snapshot projection used 0.03 / 0.03 s for 32 collections. These
local calls made zero cloud/API requests.

Saved private GCP, Azure, and K8s snapshots were also replayed. Their scale
and selectors differ from bf67, and wall times reflect shared-host contention.

| Provider | Resources / findings | Native evaluation wall / CPU | Local publication wall / CPU | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| GCP | 41,072 / 2,310 | 92.96 / 29.22 s | 11.82 / 9.06 s | 0.510 GiB |
| Azure | 13,058 / 2,716 | 23.80 / 18.06 s | 6.50 / 4.39 s | 0.662 GiB |
| K8s | 901 / 6,788 | 22.41 / 16.26 s | 2.22 / 1.69 s | 0.553 GiB |

GCP's largest measured phase CPU was privesc (4.19 s) followed by native
checks (3.22 s); Markdown used 6.84 s CPU in publication. Azure native checks
used 1.45 s CPU and analysis 1.05 s; Markdown used 2.32 s. K8s native checks
used 1.21 s CPU and Markdown 0.91 s. Each replay made zero cloud/API calls.
The saved K8s exposure fixture with only 14 resources was also profiled, but
the 901-resource sample above is the better cross-cloud comparison.

## Native/final Markdown reuse when rendered input is unchanged

The analyzer publishes a native checkpoint, then a final report after Network
and Priorities AI. Markdown does not render `ai` metadata or publication state.
The publisher now hashes every other sanitized report field and reuses the
durable native Markdown reference if the final rendering inputs are identical
on the same snapshot and job. Network findings, review overlays, changed
resources, or other rendered changes produce a fresh export. Hashing one
top-level field at a time bounds the temporary serialization to the largest
field; this was 113 MB on the saved grouped report and took 1.36 s CPU.

A local two-publication replay used the saved bf67 report with an AI-only
final state and a capture store that hashes, then discards, artifact bodies.
The previous publisher wrote two identical 861,244,352-byte Markdown files
(SHA-256 `07a43140fd87abc093f208ab7c336ca122fd7a70ac8c3b8c91b0c874f4d1867a`).
The new publisher wrote one identical file and referenced it from both
manifests. The pair used 100.98→58.06 s process CPU and 165.73→73.37 s wall;
wall was highly affected by other host jobs. Artifact puts fell 1,696→1,695,
with zero cloud/API calls in the capture store. Measured peak RSS was
1.466→2.724 GB across separate contended processes, so a memory benefit is
not established; the signature adds bounded temporary memory. This is a
conditional gain: a final report with new Network findings or effective
review changes still renders and uploads its own Markdown. Focused
publication tests passed 11/11. A broader suite passed 44/57; the 13 worker
handoff failures never reached publication and one was reproduced on the
unchanged publisher.

## ECS scheduled-task privesc inventory lookups

A direct cProfile run of the saved AWS privesc evaluator showed repeated
`items()` scans in the ECS new-task-definition/EventBridge precondition:
over 27 million `items()` generator resumptions through nested candidate loops and 53.85 s
profiled cumulative wall in that precondition under contention. The model
now builds exact scope-bound sets of event rule ARNs, task-definition family
prefixes and connected container instances once per immutable model instance.
The same collected/unknown branches and target comparisons remain.

Two paired privesc evaluations matched the complete 729,945-byte result,
including 95 findings, 66 nodes and 113 edges (SHA-256
`60dab8ee26185043a80159f707d775c9d4521f041f9fc4f6b498eb6e495fd448`
after excluding nondeterministic timing metadata). Before→after wall / CPU
was 38.62 / 11.78 s → 12.33 / 4.86 s in the first pair and
22.35 / 9.87 s → 14.88 / 6.40 s in reversed order. Pair-process high-water
RSS was 1.447 GB and 1.810 GB respectively; each pair shares one high-water
mark, so variant memory cannot be separated. No cloud/API calls were made.
The focused ECS scheduled-task and AWS follow-up privesc suites passed 129/129;
the 1,717-file API source gate retained its 30 direct SDK sites.

## Bounded S3 upload concurrency

The hosted bf67 receipt attributed 130.679 s summed wall time to 2,511 S3
puts. The report artifact batch now defaults to eight upload workers instead
of four, while retaining its 16 MiB pending-byte cap and the rule that the
manifest waits for all referenced artifacts. In two paired local latency
replays of 200 compressed finding artifacts plus a manifest, with 50 ms
simulated S3 latency per put, four workers took 2.900 and 2.911 s wall;
eight took 1.503 and 1.491 s. Process CPU was 0.127–0.138 s across the
four runs. Peak RSS ranged from 25.6–28.8 MB without a consistent worker
effect. Each run made 201 simulated puts with the same encoded body-map
SHA-256 `ccc624c319cec29f0584af6d65039531c6084d7976b1466e96bc38b7d8799b03`;
the manifest was last. No cloud/API calls occurred. This isolates latency
overlap and does not establish a production wall-time improvement, where
serialization, compression and network behavior may differ.
