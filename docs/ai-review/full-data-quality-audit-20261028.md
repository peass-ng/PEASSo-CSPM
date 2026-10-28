# Network and Priorities full-data audit — 2026-10-28

Base: configured default `origin/main`, fetched and verified at `ec306486`.
Pre-optimization reference: `76e0449badcc443f996452e914a3832ea62ea563`, the last
first-parent state before 2026-10-26 00:00 +0200 (end of October 25).
The later side-branch commit `ebf01a39` has identical `peaso/ai` bytes; neither
choice changes the AI comparison.
No push or deployment is authorized for this branch.

## Commit audit

The baseline and current Network/Priorities YAML files and deadline wrapper are
byte-identical: high reasoning, 30 turns, five configured runtime minutes,
60-second tools and 16,000-character shell output. The wrapper raises runtime
to the remaining invocation budget. The shared budget remains 600 seconds
remote / 300 local by default, bounded by the scan deadline and publication
reserve. `03ff6def` increased remote Network 600→900 seconds and Priorities
600→1500; local remains 150. No reduction needs reverting.

- `ea60df75`: intentionally removes Hardening/Exposure model agents. Native
  verdicts replace model verdicts. The inherited FAIL-only evidence filter in
  `briefing.py` still hid unresolved and nonfailing native findings. This audit
  removes that filter and retains every status. Removed reviewer dispatch is
  not restored, per the binding optimization decision.
- `bfc42e77`: deletes dormant reviewer dispatch/windows, preserves the two
  holistic stages and their existing limits.
- `020a7d73`: changes smoke coverage to the remaining stages, not their inputs.
- `3ddd407f`: batches identical record/link inserts and defers secondary index
  creation. No data/turn/reasoning/deadline loss; retained.
- `b7fb3958`: explicitly reviewed, absent from current origin/main. Its
  summary-first prompt/reader changes are not imported.
- `ecf55dbd`: explicitly reviewed, absent from current origin/main. Startup
  overlap is not required for this quality fix and is not imported.
- `ee491bfc`: moves SQLite secondary indexes to the bulk-load boundary and
  avoids computing Network context when that stage is not selected. No loss
  when either holistic stage is selected.
- `17ff621a`: caches normalized collection coverage per reviewer scope and
  validates the isolated image identity. No Network/Priorities data reduction.
- Native-final admissions, pinned catalog/source updates, collection-receipt
  additions and provider alias changes in the complete list below do not
  lower the remaining agents' YAML/runtime/tool limits. Native provenance and
  all original report fields remain reachable after this patch.

Complete commit scope reviewed (`git log BASE..ec306486 -- peaso/ai`):

```text
c683c6c9 Preserve native review coverage and pin integrated AI source
bfc42e77 Remove dormant reviewer dispatch and progressive AI windows
020a7d73 Align live AI smoke with Network and Priorities only
ea60df75 Remove Hardening and Exposure AI from scans (bf67: 26 planned batches to zero)
32832554 Merge commit 'c6ac4160d59acf46e5ac680d00b8e35cd913215b' into cspm-analyze-native-integration-20261028
c6ac4160 Repin Exposure wave2 sources, catalogs, and reviewed policy
8fc73542 Merge commit '95d6c3ab21dcaf04eb13252aa4176f557aaab84b' into cspm-analyze-native-integration-20261028
25eda8bf Integrate committed Azure Exposure B delta through 70b2673e
3ddd407f Batch Priorities context SQLite inserts
7e7a4e7f Inventory Azure gallery image versions for sharing evidence
8a719b33 Collect Azure ML workspace ACLs through current ARM API
0a914b39 Preserve native Exposure provenance in AI-off release
adc8a37a Disable hosted Hardening and Exposure agents while retaining priorities
899cc1a9 Require complete scoped coverage for GCP and K8s native-final reviews
fa6960e2 Bind Azure native-final admission to shipped paired hosted receipt
932b87df Expand pending Azure native-final source audit and stage two-pair replay
2698256a Widen GCP native-final offline candidate with source audit and held replay
b06fd66b Qualify expanded K8s native-final checks offline and stage held replay
d2367663 Repin pending Azure gate after auth collection
d74dbc21 Repin pending Azure gate to reviewed collector bytes
a6c42ad9 Require hosted receipt before K8s native-final admission
c81bf05a Refresh Azure native-final source pin on Exposure release
6aa5c2c6 Add pending Azure native-final gate with saved-scan proof
d456b598 Qualify two K8s Hardening checks for gated native-final review
bb1a6ccb Add default-off GCP native-final gate with saved replay proof
ac4e2f78 Activate 245 audited native-final Hardening checks
40ed62e7 Admit up to twelve hosted AI reviewers with memory headroom
4294c384 Fence progressive Exposure and stage complete Hardening windows
9e89c056 Default Kubernetes Exposure AI off after paired native parity
499b7bbf Audit remaining non-c2b checks and build inactive v2 fragment
62e877df Pin two audited evaluator paths and versioned Lambda runtime lookup
8c04b31c Resolve platform Codex default through Codex model alias
f265fbd4 Permit pinned IAM activity evaluator for native-final audit
4fe6f4d6 Generalize native-final gate to pinned deterministic evidence
c7d40604 Gate native-final Hardening reviews behind pinned qualification
03ff6def Review each group of equivalent findings once and give holistic AI stages the scan budget
17ff621a Accept only the trusted build constant in isolated AI tasks and bound repeated preparation and index reads [skip ci]
0314821e Write each check's shared control definition once per reviewer batch
ee491bfc Speed up AI review stages and internet exposure indexing
```

## Final input contract

Network keeps its topology index and projected structural records, backed by
`source_resources` containing the entire unprojected inventory, including
uncatalogued/new types. `source_report` retains every original report field,
including every finding and graph; full native Exposure records are also in
`exposure.json`. Both prepare passes preserve the originals. Output validation
accepts original resource IDs even when they are absent from the structural
projection; local and backend validation agree.

Priorities retains every finding/status, full inventory, IAM/privesc/network
graph nodes and edges, least-privilege records, secret/exposure report fields,
complete Network output and account context. Candidate cases cover every
finding category, with critical cases first. PASS and other noncandidate
records remain enumerable and retrievable. Native verdicts remain final.

Both agents receive `data_index` with domain/type counts and source field
names. `get` returns complete native records by default; large arrays/strings
are paginated without truncation. `--keys` enumerates every object key so a
large object never becomes inaccessible. Literal full-detail search and exact
resource-type filtering support uncatalogued native fields. Prompts require
exact native evidence rather than sampled focus bundles. Explicit index
metadata remains available with `--summary`; it is not the default evidence
read. Existing reasoning, tool-output, turn, transport and deadline limits
are preserved.

`source_snapshot` contains all noncollection snapshot fields (including
account metadata) and full collection receipts with item counts. Native item
data is reached through the original inventory. No cloud credentials or
platform tokens are added to the evidence; captured secret evidence remains
available without printing its values.

## Evidence and limits

The JSON receipts alongside this report enumerate every supported network
collection and native network/resource check for AWS, GCP, Azure and K8s.
The tests additionally feed every supported collector type and every native
network/resource check through both Network prepare passes, including future
fields and all finding statuses. Separate tests cover every Priorities source,
large object keys, literal search, unchanged quality limits, and output
references to unprojected resources.

The saved AWS bf67 snapshot/report pair is replayed through the original and
new workspace builders. Receipts compare every original inventory record and
report field by decoded exact equality, count findings by category/status,
and record build wall/CPU, process peak RSS, file sizes, cloud calls and model
calls. Peak RSS is the process high-water mark, not an isolated per-arm peak;
wall measurements run on a busy shared host. The larger context is the cost
of restoring full evidence, not a speed improvement. No API call or live
resource change is needed for this audit.

These are input coverage and transport checks, not a hosted model-output
parity result. No new top-15/architecture quality claim is made without a
paired high-effort model replay. The original evidence and critical categories
are retained, and lower effort/turn experiments are excluded.

## Saved Network result

AWS bf67: **391,100/391,100 original inventory records** and every original
report field pass exact decoded equality. The saved report has **105,659
findings**, all reachable through `source_report`; Network keeps its typed
network-finding domain and full native Exposure catalog too. The per-type
counts and all four provider catalogs are in
`full-data-network-saved-bf67-20261028.json`.

Original workspace build: 3.589s wall / 1.683s CPU. Full-data build: 151.570s
wall / 41.168s CPU on this heavily contended host; process high-water RSS
2,096,496,640 bytes in both arms. This intentionally restores substantially
more evidence; it is not a runtime saving. Zero cloud/model calls.

Final focused suite: **216 passed, 1 skipped**; the final original-resource
service/reference boundary regression also passed independently. Tests use `--noconftest`; no source-attestation gate is
run. The Access Analyzer ban was read and honored; no analyzer was created.

## Agent runtime memory headroom

The 2,096,496,640-byte figure above is the **local capture/builder process**
loading the saved snapshot/report and building both arms. It is not an agent
task measurement. Production workspace preparation runs in the collector or
analyzer (16/8 GiB defaults in `infra/aws/variables.tf`); the separate agent
task has 2 GiB (`infra/aws/ai_runtime.tf`).

Large original fields now use lossless indexed JSON fragments of at most
**128 KiB**. Objects/arrays retain their complete ordered keys/members. Long
strings retain every character in 8,192-character chunks. Exact JSON Pointer
reads select the fragment directly; they never deserialize the enclosing
report or graph. Oversized whole-object reads give paging guidance. Arrays,
object keys and strings remain fully pageable. Existing shell/output/turn
limits are unchanged. The reader explicitly uses a **2 MiB SQLite cache** and
disk-backed temporary storage; a paged materialization has a 128 KiB JSON
budget. Large native resource/finding records receive the same treatment
after decision/index construction, with reference-validation metadata intact.
Source-only rows do not populate unused alias maps after graph linking.

The isolated reader fixture ran in the existing worker image with networking
disabled, a read-only mount/root, **128 MiB hard memory**, no swap, no cloud
credentials, and no capabilities. Exact nested lookup, key pagination and a
Unicode string read crossing chunk boundaries succeeded. A large whole-object
read returned targeted paging guidance. Maximum process RSS was **30,638,080
bytes**; maximum cgroup peak was **24,592,384 bytes**. This proves bounded
reader behavior with headroom under 128 MiB; it is not an end-to-end model
memory or quality claim. Commands and image/source hashes are recorded in
`full-data-reader-headroom-20261028.json`.

The earlier flat-format Priorities capture was superseded and stopped. The
replacement runs the complete saved bf67 inputs against bounded storage,
without sampling or any AWS/model call. Its receipt will include fragment
counts/maxima, exact source comparisons and the unchanged transport cap.

Bounded-storage focused suite: **218 passed, 1 skipped**; the final large-value and Unicode/chunk-boundary regressions also passed independently (2 tests).
