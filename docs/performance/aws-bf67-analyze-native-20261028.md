# AWS bf67a397 saved Analyze replay

The saved collected snapshot is private at
`~/peaso-work/replay/aws-bf67-collected-snapshot.json.gz`. The replay used
`include_not_applicable=False` and the default category selection. It made no
cloud calls. The production request selected all 20 categories and 10 content
checks; the local replay matched its published counts (391,100 resources and
105,659 findings), but this does not prove identical selectors or a production
wall-time reduction.

## Baseline

On local Python 3.13, full native evaluation took 191.49 s wall, 75.79 s CPU,
and 1.79 GiB peak RSS. Its phase spans were: index 29.99 s wall / 6.55 s CPU;
native checks 25.82 / 15.99; resources 18.43 / 3.82; privesc 17.38 / 11.12;
graphs 7.37 / 4.47; analysis 7.30 / 5.20; validation 6.71 / 2.82. The
unspanned remainder includes selection and final report construction.

A second baseline replay included one local report publication: native
evaluation 160.79 s wall / 119.97 s CPU; publication 80.46 s wall / 59.68 s
CPU; whole-process peak RSS 2.06 GiB. Publication spans: Markdown 42.18 s,
resource chunks 10.97 s, native expansion 9.33 s, findings chunks 4.27 s,
inventory rebuild 3.81 s, least-privilege projection 2.69 s. Host contention
varied between the two baselines, so their aggregate times are not directly
comparable.

## Index change

The engine previously built a position map from collection order and sorted
all inventory wrappers. It now walks collection order and looks up wrappers
directly, preserving duplicate handling and the stable fallback for an extra
wrapper supplied by a caller. On the same loaded snapshot in one process, the
isolated index pass fell from 10.28 s wall / 4.58 s CPU to 1.89 s wall /
1.29 s CPU. All 391,100 wrapper identities and their order matched exactly.

The full after replay took 174.96 s wall / 80.11 s CPU and 1.71 GiB peak RSS;
the index span fell to 6.20 s wall / 3.77 s CPU. Resource and finding counts
remained 391,100 and 105,659. The focused inventory-order suite passed 10/10
under Python 3.12, including duplicate identity and incomplete inventory
cases. The API source manifest gate accepted all 1,717 reviewed Python files.
In a paired full evaluation on the same loaded snapshot and process, swapping
only the index implementation yielded identical 211,024,918-byte serialized
reports (SHA-256 `c6ca8c7ab93e546f187f27419881177f40f26280e53a51344d884ecb38f98122`);
the old path took 54.98 s wall and the new path 44.29 s wall. This proves
report byte identity for the saved replay, beyond matching counts.

## Production stage receipt

The final numeric runtime event for the completed analyzer was read from
CloudWatch `/ecs/hacktricks-cspm`, stream
`analyzer/analyzer/dc2f0d905bd44c5eae7935321dcd16c0`, at
2026-10-28 00:22:29.932 UTC. It reports 1,272.955 s process elapsed,
401.518 s process CPU, and 3.089 GB peak RSS. `worker.ai` accounts for
945.362 s wall / 76.491 s thread CPU. The measured non-AI remainder is
327.593 s, 25.7% of the production Analyze baseline of 1,273.142 s. This
proves the requested non-AI ≤50% of the current figure (≤636.571 s) for this
scan before the index change is deployed.

Other production spans: native evaluation 77.724 s wall / 75.814 s thread
CPU; two final publications 234.484 / 208.217; Markdown in those publications
130.389 / 127.170; resource chunks 25.039 / 13.401; privesc 16.360 /
15.971; native checks 28.454 / 27.734; index 4.001 / 3.900. S3 puts total
130.679 s summed SDK wall across 2,511 calls and may overlap publication
spans. The AI span contains Hardening and Exposure as well as Network and
Priorities; the existing runtime event does not split their walls. The local
replay's 241.25 s evaluation plus one publication does not include hosted
uploads or an exact reconstruction of the production request.
