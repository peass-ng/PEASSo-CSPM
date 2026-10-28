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
