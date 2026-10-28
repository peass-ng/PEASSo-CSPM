# Next safe optimization wave after details presentation hotfix

This isolated candidate is based on `origin/main` hotfix `112f1a5e`. It takes
only the non-ECR changes missing from main: account-bound S3 policy read reuse,
final AWS snapshot ownership, count-only collection coverage comparison,
automatic-content scope timing, successful terminal checkpoint deferral,
bounded category-only cumulative reports during and before the AWS content tail, and
immutable ECS task-definition read reuse within the original 96 MiB raw cache.
Main already contains the equivalent native inventory-index and Markdown
streaming improvements, so those commits were not duplicated. The ECR package
content, image capture, and adaptive scanner source files remain byte-identical
to hotfix main. No ECR throughput change is admitted while incomplete images
and private references await the pinned Linux full-output parity gate.

The Client VPN role closure uses cached, endpoint-bound route and target reads.
The customer role retains the same action set, but its two Client VPN route
actions move from `Resource: "*"` to a customer-account endpoint ARN. Its
finding evidence names the observed all-client rule, route, unresolved network
controls and possible impact in connected resource-first lines. The exact
presentation source closure and the API source inventory were rebound to this
tree after the details API hotfix.

Late Images, Network and Least Privilege sections still produce a partial
report after more than 256 AWS collections, including before the automatic
content tail starts. The bf67 report manifests identify sequences 276 and 478
as category-only refreshes, with 78.196s additive Markdown render wall. Those
renders overlapped Collect, so this is not a credited wall saving. Routine
category-only cumulative report refreshes wait for Analyze; raw batches, final watermark,
explicit flushes and interrupted partial publication remain available. The
bf67 terminal 218–228s Collect reduction is a projection only. Its additional
cadence gate has no credited wall saving because the saved Markdown spans
were additive and overlapped collection. The S3 sample reduced calls 241→225
and CPU 1.344→1.175s while peak RSS rose 229.9→244.3 MB; production resource
cost remains to be measured. ECS sample physical calls 20→10 on ten task
revisions; full-scan cache hit rate at the retained 96 MiB cap remains open.

Focused collector, lifecycle and Client VPN tests before the manifest-backed
cadence extension: 532 passed. Its targeted late/early section tests: six
passed, including Images, Network and Least Privilege. Source
successor import, 1,718-file API source closure, compliance materialization
(`stale=[]`) and Client VPN source hashes pass. The locked source-attestation
and combined release suite passed 19/19 in default mode after the exact
presentation closure pin was refreshed. No cloud
write, model call, production scan, push or deployment was made here.
