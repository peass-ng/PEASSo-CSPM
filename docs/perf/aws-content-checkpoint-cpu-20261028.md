# AWS content checkpoint CPU reduction

The read-only d565 collector trace recorded 48 public checkpoints during
Collect, seven of them cumulative reports. `worker.public_checkpoint` used
887.9 additive process CPU-seconds and 918.3 additive wall seconds. The seven
Markdown renders alone used 508.9 process CPU-seconds and 524.3 additive wall
seconds. bf67 recorded 43 checkpoints/704.6 process CPU-seconds, with six
Markdown renders/391.1 process CPU-seconds. These spans overlapped collection;
additive CPU is not Collect wall time.

Selected AWS content scans retain append-only raw snapshot batches throughout
Collect. The first completion of each section publishes a paired partial
snapshot and report immediately. Images, Network and Least Privilege can
therefore start their progressive stages independently during Collect;
Network does not wait for IAM. Category-only and repeated cumulative renders
are suppressed. Analyze regenerates the complete report from the final native
snapshot. Explicit `flush()` and interrupted `close()` still publish the
latest partial report. No Markdown work was moved into another thread on the
scanner task.

Raw batch bounds remain 64 envelopes/8 MiB/1 second. The earlier proposal to
raise them to 256/32 MiB/5 seconds was rejected because local replay raised
peak RSS and extended the uncommitted crash window without a stable CPU win.
The saved bf67 final snapshot contains 1,292 distinct envelope identities and
305.4 MB of serialized envelope data; the d565 trace had 41 raw calls.

A bounded offline replay of the first 128 bf67 envelopes, with no AWS API
calls and the same identity digest, measured:

| Raw batch setting | Old | New |
| --- | ---: | ---: |
| Raw checkpoint calls | 5 | 3 |
| Wall seconds | 2.583 | 1.745 |
| Process CPU seconds | 2.327 | 1.718 |
| Peak process RSS bytes | 2,116,403,200 | 2,640,920,576 |
| Identity SHA-256 | `c56fc93a7668e978705d9ca42b8e9a528d8b78f5259f173f3a605ddb67d56f90` | same |

After the final selected-content gate, a second sequential pair on the same
128 envelopes measured old/new: 5/3 raw calls, 4.475/3.235 wall seconds,
2.522/2.535 CPU seconds, and 941,801,472/1,707,048,960 peak RSS bytes.
The CPU difference is not stable across the two local pairs; no CPU saving
is attributed to the larger batch limit alone. Both show higher peak RSS
with larger batches. bf67's reported
collector peak was about 7.37 GB on a 16 GiB task; the combined next-wave
production scan must verify its own peak and coverage before rollout.

**Historical attribution and projection:** read-only d565 CloudWatch
runtime-metric deltas show seven Markdown renders at process t~60, 90, 224,
404, 734, 1008 and 1615 seconds, consuming respectively 2.550, 27.211,
48.769, 114.813, 158.735, 104.451 and 52.396 CPU-seconds. Read-only
inspection of the seven paired d565 public manifests shows first completed
sections at sequences 651 (Images), 1244 (Network), 1247 (Least Privilege),
and 1284 (Exposure and Privilege Escalation). The sequence 29, 282 and 1238
reports introduced no completed section. Suppressing only those three
historical renders projects `2.550 + 27.211 + 114.813 = 144.574` fewer
Markdown CPU-seconds. If all other checkpoint work were unchanged, d565's
`887.875` checkpoint CPU-seconds would become `743.301`. The read-only
attribution receipt `~/peaso-work/receipts/aws-content-checkpoint-first-section-d565-20261028.json`
records the seven manifest names, section states and CPU deltas. This is not
a measured successor saving. Additive CPU overlaps collection and cannot be
subtracted directly from the 1,781-second Collect wall time.
The next paired production run must measure actual Collect wall, checkpoint
CPU, each progressive stage's start/finish, peak RSS and coverage.

The later dfa production scan narrowed this opportunity. Its five Collect
report manifests first published Images at sequence 538, Network at 1255,
and Least Privilege at 1258. Only sequences 30 and 222 had no newly completed
section; their combined Markdown process CPU was 12.275 seconds. The corrected
gate would retain the three first-section reports and suppress those two.
With all other checkpoint work unchanged, the historical dfa checkpoint CPU
of 609.480 seconds projects to 597.205 seconds. This is a CPU attribution,
not a measured Collect wall or RSS gain. The read-only source receipt is
`~/peaso-work/receipts/aws-collect-dfa-vs-d565-20261028.json`, SHA-256
`e6d825ab04297854931f804def12a145a108424004e99f0aacba304cbfcb6b8b`.
This source is included in the combined release wave by user direction.
The production wall, RSS, cost and full-collection effect remain unmeasured.
