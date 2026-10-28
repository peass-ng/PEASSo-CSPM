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
publication took 114.60 s wall / 86.27 s process CPU under host load and
peaked at 1.835 GB RSS. It issued 2,057 simulated puts carrying 260,615,658
bytes; 2,034 objects were gzipped. Compression spans summed to 21.11 s wall /
7.20 s thread CPU; simulated upload read spans summed to 0.04 s wall. The
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
