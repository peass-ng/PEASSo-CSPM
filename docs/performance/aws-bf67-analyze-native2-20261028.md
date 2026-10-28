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

That 1,637-put local fixture was already grouped. The analyzer's native
publication receives the raw finding report, so the exact-selector integrated
replay below is the stronger artifact-count estimate: 2,057 puts in its
native publication alone.

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
snapshot when this proxy was run. A separate AWS replay selected all 18 known AWS content
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

## Exact production-selector integrated replay

A read-only DynamoDB query recovered the bf67 job's selector shape: 20
categories, 10 content checks, and no additional check or framework selectors.
The private selector file has canonical SHA-256
`62ed9da5b02d12afe70c52a243858bd95b089cfbe1ef0bb0663d64d7762d523e`.
Release Python 3.12.13 replayed the saved snapshot with those selectors on
current source: 391,100 resources, 105,750 raw findings, and 4,189 coverage
items. Evaluation took 45.204 s wall / 39.441 s process CPU and peaked at
2,156,019,712 bytes RSS. The 211,304,904-byte raw JSON report has SHA-256
`8f8cca03fb6594efa1dce697666b4552a5925658a9b3c01b3cbb4758cde088cd`.
Largest evaluation thread-CPU spans were native checks 6.045 s, privesc
4.842 s, analysis 4.515 s, graph building 1.709 s, validation 1.610 s,
resource preparation 1.588 s, and index building 1.020 s.

In a separate process, the integrated path evaluated that exact selection,
redacted it, and passed the raw report to native publication through the real
`S3Artifacts` serializer, gzip, and upload batch with a local body-reading S3
adapter. Its stage wall / process CPU was evaluation 58.103 / 44.620 s,
redaction 3.679 / 3.142 s, and native publication 95.687 / 57.885 s;
combined before-AI time was 157.469 / 105.647 s. Peak process RSS was
2,269,495,296 bytes. Native publication issued 2,057 simulated puts, 2,034
gzipped, carrying 261,065,195 encoded bytes; the manifest was last. Its
largest thread-CPU spans were Markdown 27.326 s, native expansion 7.756 s,
gzip 6.367 s across objects, resource chunks 6.315 s, inventory 2.607 s,
least privilege 2.539 s, serialization 1.921 s, and finding chunks 1.504 s.
The local adapter made zero cloud/API calls and cannot model S3 latency.

The exact-selector raw report grouped to 1,251 findings. Production bf67's
older-source partial report grouped to 1,160; 1,154 IDs were common, 97
current-only and 6 production-only, all within Exposure. This is a
cross-source comparison, not an output-parity check. An isolated publication
of the saved raw report showed a large cold `group_report` span because it
imported checks for the first time. Once `peaso.checks` was imported,
grouping fell to 1.734 s CPU; evaluation already imports it in the integrated
path, so the cold span is not a production bottleneck.

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

A follow-up used the complete saved bf67 native publication with the real
JSON serializer, Markdown file, gzip path and artifact queue. The fake S3
client added 50 ms per put and hashed every uploaded body. Both worker counts
made 1,637 puts (1,614 gzip) totaling 242,976,204 bytes, with identical
artifact-map SHA-256
`504f8d0ad5b63af5ae5751316fde0b0b64ee2fe46b742fefb79fa12bcc827318`.
In before→after order, four→eight workers took 158.02→148.85 s wall and
64.44→66.80 s CPU. Reversed, eight→four took 151.08→159.42 s wall and
65.51→62.85 s CPU. Eight workers saved 8.34–9.18 s wall in these paired
replays while using 2.36–2.67 s more CPU. Sampled peak RSS varied from
1.469 to 2.064 GB across separate contended processes; memory impact is
unproven. Cloud/API calls were zero. Real S3 latency and Fargate CPU
throttling still require hosted verification.

## Skip unused inventory in an AI-only final publication

The second publication can reuse native Markdown, resource chunks and least
privilege projections when only AI metadata and publication state change. It
previously rebuilt the 391,100-resource snapshot inventory even though none
of those cached paths used it. Inventory creation is now lazy within a
publication. The first projection that needs it builds it once; an unchanged
AI-only final does not build it. The earlier hosted-style profile measured
one inventory build at 3.02 s thread CPU / 5.47 s wall under contention.

Two pairs of local bf67 native/final publications matched one
861,244,352-byte Markdown artifact (SHA-256
`07a43140fd87abc093f208ab7c336ca122fd7a70ac8c3b8c91b0c874f4d1867a`),
1,695 capture-store writes and both manifest reference positions. The first
before→after pair took 63.76→56.47 s process CPU and 100.68→70.37 s wall;
the reversed after→before pair took 57.56→88.45 s CPU and
86.96→199.63 s wall. The shared host was heavily contended, especially in
the second baseline, so those whole-run differences are not an attributable
inventory saving. The measured avoided inventory span is the better local
estimate. Separate-process sampled peak RSS was 1.689→2.884 GB in the first
pair and 2.867→2.133 GB in the reverse pair; memory effect is undetermined.
The focused publication tests passed 27/27, including a direct assertion
that an AI-only final performs no second inventory build. Capture-store
cloud/API calls were zero. The 1,717-file API source gate retained its 30
direct SDK sites.

## Reuse unchanged finding, coverage and graph artifacts

An AI-only final publication with an identical sanitized rendered-input
signature now reuses native finding details, finding indexes, coverage chunks
and graph artifacts. Changed report fields invalidate the cache; unsupported
signature values keep the ordinary publication path. The full current AWS
evaluation replay used 31.18 s CPU / 36.28 s wall under host load, with
391,100 resources, 105,659 findings and zero cloud/API calls. Native checks
used 7.11 s CPU, privesc 4.85 s, analysis 4.83 s; the slowest single check
used 1.13 s CPU. Publication remains the largest local phase.

In a paired local bf67 native/final capture, the final publication fell from
58 to 4 artifact writes and from 6.03 to 5.16 s process CPU, with wall time
11.59→9.12 s under contention. Total two-publication CPU was
58.36→59.10 s and wall 111.78→118.55 s, so the whole-run timing does not
show a gain beyond the isolated final phase. Both versions wrote one
861,244,352-byte Markdown body with SHA-256
`07a43140fd87abc093f208ab7c336ca122fd7a70ac8c3b8c91b0c874f4d1867a`.
Peak sampled RSS was 2.012→1.962 GB across separate processes, which is
too weak to establish a memory improvement. Cloud/API calls were zero.
Focused publication and artifact tests passed 57/57, including materialized
shared-versus-uncached output equality and changed-finding invalidation.

## Copy unchanged Markdown inventory when final findings change

The saved bf67 final report adds two Network findings, so its full Markdown
cannot use whole-document reference reuse. Its 391,100 compact resource rows
are identical to the native report. The publisher now keeps the already
uploaded native Markdown file open in the scan's private temporary storage
and copies only its resource-inventory byte section into a final render when
the complete resource rows and frozen snapshot facts match. Changed findings
and guidance still render normally. The cached source is scoped to one scan;
an unlinked 861 MB temporary file persists through the AI stage, with up to
another final file open during publication.

In a paired local native/final capture using the saved final bf67 report,
the final Markdown was exactly 861,435,060 bytes with SHA-256
`ef5f56aa897cc6159c84d70fcfce1213ddd683e1da6dadef22b16f0a217c6bf7`
before and after. The final publication used 42.53→27.29 s process CPU
and 55.48→47.44 s wall under contention; total two-publication CPU was
97.66→82.61 s. Both paths made 59 final artifact writes; cloud/API calls
were zero. Sampled peak RSS was 2.704→2.728 GB across separate processes,
so no memory improvement is established. A focused changed-finding test
matched the complete cached and fresh Markdown documents.

## Production partial/final finding delta

The two manifests referenced by the same production bf67 job were read through
the wiki profile, followed by its partial report. This resolves the earlier
comparison of a locally regenerated native report with a production final
report: those were different sources. The actual native partial has 1,160
grouped findings and the final has 1,162. All 1,160 IDs persist, but only 951
rows are byte-equivalent as JSON values. Another 209 rows change, including
208 `ai_review`/`scanner_status` overlays, 30 evidence changes, and 25 status
changes; two Network findings are added. Coverage (4,189 rows), graphs,
check metadata, 391,100 resource rows, native data and finding aggregates
match. The 1,576 resource chunk references and 17 coverage chunk references
also match. These production inputs validate inventory reuse, but show that
copying the whole native Markdown findings section would be incorrect.
The read-only comparison made no cloud writes or model calls.

## Rejected follow-up experiments

Building the native-ID graph lookup only for referenced documents was tested
without editing the pinned engine source. The exact-selector expanded report
was equal across old/new/new/old calls (391,100 resources and 5,362 graph
nodes). In the warm reverse pair, the filtered candidate took 3.850 s wall /
1.625 s CPU versus the original 2.742 / 1.481 s; the first candidate call
was also slower under cold/contended conditions. Process high-water RSS was
2,205,351,936 bytes across retained outputs, without variant attribution.
The index is not a measurable bottleneck here; no runtime code or cloud/API
calls changed.

Eight versus twelve S3 upload workers were also tested on the exact-selector
raw native/final pair with a local body-reading adapter and 50 ms latency per
put, near the old bf67 production mean. In 8→12 order, combined publication
wall / CPU was 116.894 / 89.006 versus 153.132 / 98.520 s; in reversed
12→8 order it was 138.131 / 99.511 versus 174.244 / 105.690 s. Each run
made 2,057 native and 480 final simulated puts, with 2,034 and 461 gzipped
objects respectively and each manifest last. Random references change encoded
body sizes slightly. Peak RSS ranged from 2.376 to 3.196 GB across separate
processes, with no consistent worker effect. No real cloud/API calls occurred.
The large order effect and opposing pair results do not establish a twelve-
worker wall gain on the shared CPU-constrained host; the default stays eight.

Copying unchanged grouped evidence bytes between native and final Markdown
was prototyped with a full grouped-finding digest, leaving sequential guidance
anchors freshly rendered. The actual production bf67 partial/final pair
matched native Markdown at 861,222,317 bytes (SHA-256 `9e0ebaac...`) and
final Markdown at 861,435,060 bytes (SHA-256 `ef5f56aa...`) in all four
old→new→new→old renders. The first pair had a cold import skew. In the
reverse pair, native CPU rose 33.536→42.640 s while final CPU fell
12.567→8.335 s; combined publication CPU regressed 46.103→50.975 s and
wall rose 48.256→55.200 s under host load. All final runs made 59 capture
artifact writes. Peak process RSS was 3,656,237,056 bytes across the shared
four-run process, without variant attribution; cloud/API calls were zero.
The digest cost exceeds the final render saving, so the prototype was reverted.

Per-chunk finding reuse was checked against both actual production grouped
partial/final reports and the current exact-selector raw report with the two
production Network additions. The grouped reports shared 15 of 37 encoded
chunks (52,508,551 bytes), but grouping is a presentation artifact: the
analyzer publishes raw findings. On that worker input, only 2 of 424 final
chunks (1,018,483 bytes) matched native chunks. The two additions shift
sorted chunk boundaries, so an exact-byte chunk cache would save almost no
compression or S3 writes. The raw comparison took 1.751 s wall / 1.354 s
CPU, peak process RSS 2,608,939,008 bytes across both comparisons, and zero
cloud/API calls. No chunk format or runtime code was changed.

Raising the S3 batch from eight to sixteen workers helped a 201-object fake
S3 latency test at 50 ms per put: wall 1.462/1.484 s at eight versus
0.791/0.797 s at sixteen, with identical encoded-body multiset SHA-256
`32cba7f5ffb8a652666e7a23d28376162516c65574d5b0617a8104fe48de4a64`
and manifest last. On the full saved bf67 partial publication, however,
the first eight→sixteen pair took 112.364→60.745 s wall and
79.894→54.038 s CPU, while the reverse sixteen→eight pair took
56.619→50.626 s wall and 53.069→42.462 s CPU. All four issued 1,637
simulated puts, of which 1,613 non-manifest objects were gzip encoded;
manifest upload was last. Random artifact references change downstream
serialized bodies, so their whole-artifact digests are not directly
comparable. The process high-water RSS rose from 2.937 to 3.227 GB during
the paired run, without variant attribution. The full reverse pair does not
support a sixteen-worker default on this CPU-constrained workload; the code
remains at eight. No cloud API calls were made.

Combining each small Markdown JSON block into one sink append also matched
the 861,222,317-byte production partial Markdown SHA-256
`9e0ebaacac4efc6b324553b910ab8fb6b270120dabff76106777036f3fa3a75c`
in four old/new renders. Its reverse full pair regressed from 31.031 s CPU
with the existing code to 32.551 s CPU with the candidate. That edit was
reverted. A proposed lazy native expansion was also reverted when the engine
factory source guard correctly rejected the altered source; no output or
release pin from that prototype was retained.

An optional native sorted/indented JSON encoder was evaluated without a
source change. Its bytes matched stdlib for all 391,100 saved bf67 resource
objects. A guarded prototype retained the current bounded exact-type walk
and fell back for floats, unusual keys, oversized values, and native encoder
errors. Complete Markdown renders in old→candidate→candidate→old order were
all 861,222,317 bytes with SHA-256
`9e0ebaacac4efc6b324553b910ab8fb6b270120dabff76106777036f3fa3a75c`.
Wall / CPU seconds were 59.302 / 47.068, 30.862 / 27.053,
37.410 / 28.798, and 41.879 / 30.346. The reverse pair supports only
1.548 s CPU and 4.469 s wall improvement; the first pair has a large
cold-run effect. Peak process RSS was 2.687 GB across the paired run and
does not distinguish variants. The encoder is not a declared analyzer-image
dependency. Adding it for this steady-state gain was deferred; production
code and API call count remain unchanged.

## Single-pass bounded Markdown dictionary preparation

A fresh local publication of the actual bf67 partial report used 83.324 s
process CPU / 171.191 s wall under heavy host contention, with a capture
adapter that hashed its full Markdown file and discarded other artifact
bodies. Numeric spans identified Markdown at 50.164 s thread CPU, native
expansion at 9.433 s, resource chunks at 7.677 s, least-privilege projection
at 5.692 s, and inventory at 3.190 s. The capture made zero cloud/API calls.

Profiling a 50,000-resource inventory slice found that bounded JSON
preparation first tested all dictionary keys, then sorted and visited them.
It now sorts, validates, and visits in one pass. Non-string or incomparable
keys still use the original stdlib fallback. The complete production bf67
partial Markdown was rendered old→new→new→old against one expanded report.
All four files were exactly 861,222,317 bytes, SHA-256
`9e0ebaacac4efc6b324553b910ab8fb6b270120dabff76106777036f3fa3a75c`.
First pair old→new took 92.829→52.771 s wall / 54.997→32.333 s CPU;
the reverse pair new→old took 54.696→71.085 s wall / 33.604→35.052 s CPU.
The first pair includes a large cold-start effect; the reverse pair supports
a conservative 1.448 s CPU gain. Peak process RSS was 1.501 GB across all
four runs, so the measurement does not attribute a memory change. The
50,000-resource slice independently matched at 91,026,207 bytes and the
same SHA-256 in all four runs, with reverse-pair CPU 3.017→2.790 s.
No cloud/API calls were made. Focused streaming and golden Markdown tests
passed 54/54, including numeric and mixed-key fallback; the reviewed source
gate covers 1,718 Python files and 30 SDK client sites.

## Skip native expansion when copying the final Markdown inventory

The final bf67 Markdown still expanded all 391,100 native resource rows before
copying its unchanged inventory byte section. It also expanded the unchanged
graphs a second time. The final publisher now hydrates the changed findings
and reuses the earlier expanded graphs only when the exact serialized graph
signature and frozen-snapshot resource-section signature match. It keeps the
full expansion path if either guard misses. The native publication still
expands the resources and graphs normally.

The actual production bf67 partial and final reports and saved collected
snapshot were published in a local capture adapter that hashes the complete
Markdown file and discards other artifact bodies. In before→after order,
final publication fell from 60.897 s wall / 29.962 s process CPU to
42.463 / 17.578 s. In reversed after→before order it fell from
40.564 / 25.440 s to 30.028 / 18.546 s. Host contention changed between
runs, but both orders save 6.894–12.384 s CPU and 10.536–18.434 s wall.
All four final files were exactly 861,435,060 bytes with SHA-256
`ef5f56aa897cc6159c84d70fcfce1213ddd683e1da6dadef22b16f0a217c6bf7`.
Process high-water RSS was 1.771 GB in the first paired run and 2.433 GB in
the second; this cannot attribute a memory change to either path. The replay
made zero cloud/API calls. It measures local publication, so hosted S3 and
Fargate wall savings remain unverified. The focused Markdown, artifact and
publication suite passed 86/86; a separate changed-graph invalidation test
passed 1/1. The reviewed source gate still covers 1,718 Python files and
30 direct SDK client sites.

## Batch large Markdown JSON spool writes

Function profiling of the exact-selector bf67 native Markdown render counted
19,684,795 writes to the text spool in large JSON blocks. The streaming
fallback now joins encoder tokens into bounded batches before writing the
same temporary file. Fence detection still scans every token and output
order is unchanged. The process retained the same 2,160,214,016-byte
high-water RSS across the paired run; this does not isolate variant memory.

The same expanded 391,100-resource report rendered old→new→new→old on release
Python 3.12.13. All four Markdown files were exactly 862,974,435 bytes with
SHA-256 `ea0fcd5f082d011156b73699e8cb17ec2c07be1c60cb680cef3948103c7374c4`.
The first pair took 41.487→33.891 s wall / 27.732→25.235 s CPU; the
reverse pair took 32.760→33.023 s wall / 26.756→25.586 s CPU. Both orders
saved 1.170–2.497 s process CPU. Wall time was unstable under shared-host
load. This local render made zero cloud/API calls and did not exercise S3.
Streaming, JSON fast-path and golden Markdown tests passed 106/106. The
reviewed source gate covers 1,718 Python files and 30 direct SDK client sites.

An integrated exact-selector replay after this change used the current
`S3Artifacts` upload batch and a zero-latency, body-reading local S3 adapter.
Evaluation took 62.250 s wall / 45.227 s process CPU, redaction 4.764 /
3.315 s, and native publication 67.886 / 52.709 s: 134.900 s wall and
101.251 s CPU before AI. Process peak RSS was 2,294,169,600 bytes. Native
publication made 2,057 simulated puts, 2,034 gzipped, carrying 261,065,210
encoded bytes; the manifest was last. Its largest thread-CPU spans were
Markdown 24.699 s, native expansion 6.637 s, compression 6.227 s, resource
chunks 5.623 s, inventory 2.553 s, least privilege 2.082 s, and artifact
serialization 2.001 s. Batch waiting summed to only 0.223 s wall in this
local adapter. Compared with the prior integrated replay above, the Markdown
span fell 27.326→24.699 s CPU; the whole-process wall difference is not a
causal estimate because the runs were separate and shared-host load changed.
The replay made zero real cloud/API calls and does not model hosted S3 latency
or the second publication.

## Exact-selector two-publication profile

A separate local run published the saved exact-selector raw report, then a
final report with the two Network findings and AI metadata from the actual
production bf67 final. It used the current serializer, gzip and bounded S3
batch with a zero-latency client that reads every body. The native publication
took 117.071 s wall / 73.711 s process CPU and made 2,057 simulated puts
(2,034 gzip, 261,065,211 encoded bytes). Its grouping span included a cold
checks import of 17.487 s thread CPU. The real analyzer evaluates checks
before publication, so that cold cost is already paid earlier; the integrated
replay above is the better native-phase estimate.

The final publication took 41.981 s wall / 25.734 s process CPU and made
480 simulated puts (461 gzip, 180,684,297 encoded bytes). The manifest was
last in each publication; process peak RSS was 2,407,972,864 bytes. Final
thread-CPU spans were Markdown 10.436 s, compression 4.878 s, private-value
filtering 3.987 s, finding chunks 1.655 s, and serialization 1.581 s.
Inventory and least-privilege projections were reused. This run used the
current-source raw report with older-source production AI additions, so it
measures publication scale rather than production output parity. It made
zero real cloud/API calls, excluded evaluation and AI time, and cannot model
hosted S3 latency.

Per-finding Markdown section copying was also checked before changing code.
The actual production grouped partial/final pair has 1,160 common findings,
of which 951 are identical values, but only 19 retain the same sequential
guidance anchor after final additions. A copied whole section would therefore
change links in most final findings. No section cache or renderer behavior was
changed.

## Final d565 production Analyze attribution

Read-only CloudWatch `/ecs/hacktricks-cspm` stream
`analyzer/analyzer/7a77e85418f5449f870c89caf6d7799e` has the terminal
runtime event at 2026-10-28 08:36:46.203 UTC. DynamoDB stage timestamps
give 908.402 s Analyze; the analyzer process reports 908.182 s wall,
353.471 s CPU and 3,056,001,024 B peak RSS. Its three largest relevant
measured wall totals are:

| Item | Production wall | Interpretation |
| --- | ---: | --- |
| `worker.ai` | 615.739 s | AI review and its launch/poll waits; Network completed during Collect, so the Analyze critical path is Priorities. Model-only time is unavailable. |
| `worker.final_publish`, two calls | 220.411 s | Native and final publications; longest single pass 123.084 s. This is the non-AI item above 60 s. |
| `artifact.s3.put`, 2,529 calls | 200.938 s summed SDK wall | Nested in the publication passes and concurrent, so it is **not** another 200.938 s on the critical path. Longest put 0.923 s; 437,813,272 encoded bytes. |

The two Markdown renders account for 114.775 s of publication wall (longest
57.441 s). Compression totals 48.131 s over 2,511 calls. Native evaluation
was 56.542 s. The non-AI process remainder is 292.443 s, including both
publications and evaluation. These nested totals must not be added to the
908.182 s process wall.

This branch has already attacked the publication item: byte-identical
Markdown batching and native/final inventory reuse, plus bounded S3 upload
concurrency (four to eight workers). The exact-selector integrated local
replay measured native publication 67.886 s wall / 52.709 s CPU; the separate
two-publication replay measured final publication 41.981 s wall / 25.734 s
CPU. A 50 ms/put full native replay measured eight workers 8.34–9.18 s
faster than four, while the later eight-to-twelve-worker experiment found
no stable gain. The local fake S3 runs made zero real cloud API calls. These
are candidate gains, not a hosted d565 after-measurement; the branch has
not been deployed. The remaining ~616 s AI critical path belongs to the
Network/Priorities owner. No further measurable local native/publication
win survived the final two experiments.
