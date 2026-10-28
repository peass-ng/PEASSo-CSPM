# Azure f95a7c9a near-empty Analyze wait

Read-only evidence from the `wiki` AWS profile on 2026-10-28. The scan ID is
`f95a7c9aa44d46dd96aca7f866c1e69d`; no cloud resources were modified or
credentials printed. This was an authentication-broken Azure collection, not
a representative healthy Azure inventory.

| Evidence | UTC time or duration |
| --- | ---: |
| DynamoDB queued | 04:22:54.796 |
| DynamoDB collecting | 04:24:35.164 |
| DynamoDB collected / analyzing | 04:24:56.218 / 04:24:56.473 |
| Analyzer final runtime event / DynamoDB completed | 04:33:24.126 / 04:33:24.130 |
| Analyzer elapsed / process CPU / peak RSS | 507.473 s / 3.067 s / 393,699,328 bytes |
| `worker.ai` wall / thread CPU | 503.978 s / 0.920 s |
| `worker.evaluate` wall / both publications wall | 0.092 s / 1.900 s |

The final report has four resources, all ACR selected-image artifacts; 730
grouped findings are 691 DENIED and 39 UNKNOWN. Two UNKNOWN network findings
refer to uncollected Front Door and SQL Server paths. The final AI result has
zero actions, Network `not_available`, and status `partial`. The Network input
projection is empty, so no Network model task had evidence to review.

One AI Fargate task was created at 04:25:04.492, began image pull at
04:25:18.838, finished pulling at 04:26:17.602, and started at 04:26:19.394.
The agent logged `invalid_output` at 04:33:02.281 and exited 65; cleanup
stopped the task at 04:33:46.802. It was the Priorities invocation. The
relay logged three denied requests but no upstream status code; their cause
is not established by this receipt. The ~75 s task startup and ~403 s from
start to invalid output account for the fixed wait. Step Functions/DynamoDB
status handoff added less than one second after the analyzer runtime event.
The deployed task definitions have `PEASO_SOURCE_ATTESTATION=trusted`, and
analyzer startup plus catalog/check execution took milliseconds; source
attestation and native evaluation did not cause the 500 s wait.

Priorities action validation accepts confirmed FAIL findings, plus MANUAL or
UNKNOWN Network/privesc paths. The pipeline now checks that there is at least
one such candidate after reviewer verdicts, requiring captured Network input
for a Network MANUAL/UNKNOWN candidate. This scan has none supported by
collected evidence. It skips the Priorities task, leaves deterministic
findings and coverage intact, and records a clear limitation. Confirmed
failures and observed Network/privesc paths still invoke Priorities.

The same saved final report and snapshot were replayed locally: four
resources and 730 grouped findings, Network input absent, candidate gate
false in 0.014 s wall / 0.012 s CPU, process peak RSS 110,444,544 bytes.
That read-only replay used three S3 gets plus eight DynamoDB scan pages and
one item get to locate the scan; it made zero cloud writes and launched zero
AI tasks. With auth and the remote launcher stubbed only, a second replay of
the complete `review_scan` control flow on the same saved final report and
snapshot took 0.036 s wall / 0.025 s CPU, peaked at 95,813,632 bytes RSS,
returned `completed` with zero actions and Network `not_available`, and made
zero model invocations or cloud writes. These local figures isolate the gate
and AI control flow. A new hosted scan is required
to verify the resulting Analyze wall time; the old hosted receipt remains
507.473 s wall / 3.067 s CPU / 393,699,328 bytes peak RSS with one failed AI
task and 31 artifact S3 puts. The binding brief reserves production scans and
deployment for root.

Six focused AI pipeline tests passed, covering the denied-inventory skip,
confirmed and observed candidates, and the reviewer-to-Priorities barrier.
After the earlier rebase on `origin/main` at `112f1a5e`, the combined Markdown, publication and AI
suite passed 335 tests with one skip. Six other AI review tests fail
identically on untouched `origin/main`: two report API detail tests return a
catalog error and four local Chack loader cases expect the unavailable
`resolve_config_aliases` helper. The 1,718-file source gate retained 30
direct SDK client sites.

After rebasing onto Network/Priorities-only `origin/main` at `b0b9a518`,
the evidence gate was placed immediately before the Priorities launch in
that flow. The focused AI tests passed 8/8, covering the denied-inventory
skip, observed paths, native FAILs for all four providers, and the Network
barrier. The combined release, production source attestation, Markdown and
publication suite passed 64/64. The refreshed reviewed-source gate covers
1,718 Python files and 30 direct SDK client sites. These tests verify the
rebased code path; the local 0.036 s replay above remains the only measured
f95 final-review timing until root deploys this branch.

The later Exposure-wave default branch `dfa17870` changed no Analyze,
Markdown, or Network runtime file touched by this optimization. After
rebasing onto it, the source closure grew to 1,720 reviewed Python files
with the same 30 direct SDK client sites. The combined release and production
source-attestation gate passed 10/10 on release Python 3.12.13. Hosted Analyze
timing remains unverified.
