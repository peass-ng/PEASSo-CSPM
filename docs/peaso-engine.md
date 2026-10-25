# Peaso native snapshot engine

Peaso separates bounded read-only collection from offline evaluation. `peaso.engine.collect_snapshot(request)` produces a content-addressed snapshot; `evaluate_snapshot(snapshot, categories=None, checks=None, frameworks=None)` evaluates collected facts without credentials or provider calls. `run_scan(request)` returns the report plus its snapshot, and `peaso.reports.render_markdown(report)` exports all findings, structured evidence, native inventory, coverage, and both defensive graphs.

The original IAM/RBAC scanner entrypoints now delegate configuration review to this native engine. External hardening runtimes, images, database workers, credential materializers and their image/runtime/timeout flags have been removed. Historical Prowler/Turbot source definitions are provenance for reviewed native adaptations only; they are not executable coverage. Existing scanner authentication and IAM behavior remain intact, including the legacy AWS scanner's opt-in/out Access Analyzer behavior: supply `--no-access-analyzer` for a read-only legacy invocation. The native AWS collector can request IAM access reports and manage temporary Access Analyzers when the connector enables those operations; collection records their lifecycle and cleanup evidence. See the [AWS collector guide](peaso-aws-collector.md) for the required permissions and options.

## Install and reproducible commands

From the repository root:

```sh
python3 -m pip install -e '.[cloud,test,hosted,analytics]'
peaso catalog -o /tmp/peaso-catalog.json
peaso scan --provider aws --demo --snapshot-output /tmp/aws-snapshot.json -o /tmp/aws-report.json
peaso evaluate /tmp/aws-snapshot.json --format markdown -o /tmp/aws-report.md
peaso report /tmp/aws-report.json --format markdown -o /tmp/aws-export.md
peaso diff /tmp/aws-report.json /tmp/aws-report.json --format markdown -o /tmp/aws-diff.md
peaso scan --provider gcp --demo --format markdown -o /tmp/gcp-report.md
peaso scan --provider azure --demo --format markdown -o /tmp/azure-report.md
peaso scan --provider k8s --demo --format markdown -o /tmp/k8s-report.md
```

The offline demos contain authored synthetic data and denied/missing coverage; they are not live cloud assessment evidence. [AWS sample snapshot](../examples/aws-demo-snapshot.json), [JSON report](../examples/aws-demo-report.json), and [full Markdown report](../examples/aws-demo-report.md) are durable examples.

`scan`, `collect` and `evaluate` emit progress to stderr by default; redirected JSON/Markdown stdout remains machine-readable. Updates show phase, provider, selected scope, settled inventory/check count, resource count and elapsed time. ETA is estimated only when a fixed total is known; discovery and expanding child inventories report unknown ETA. A background heartbeat continues during blocked provider reads. Use `--quiet` to suppress progress. The callback is runtime-only and is absent from connectors, snapshots and reports. Existing processes load their prior code; the new behavior applies to new invocations.

For live operation, select `--provider`, `--scopes`, and provider authentication through `--profile`, `--context`, or a private JSON/YAML `--auth-file`. Full JSON/YAML requests can be supplied with `--request`. An existing JSON snapshot can be evaluated through `--snapshot` without cloud calls. Supported auth field names and scope formats are documented in the [AWS](peaso-aws-collector.md), [GCP](peaso-gcp-collector.md), and [Azure/Kubernetes](peaso-azure-k8s-collectors.md) collector guides; hosted availability depends on those portable credential contracts.

A complete request has this shape:

```json
{
  "connector": {
    "provider": "aws",
    "name": "audit",
    "auth": {"profile": "auditor"},
    "scopes": ["111111111111"],
    "options": {"regions": ["us-east-1"], "max_pages": 10, "max_resources": 10000, "max_calls": 200}
  },
  "categories": ["hardening"],
  "checks": ["aws.ec2.imdsv2"],
  "frameworks": ["hacktricks"]
}
```

Common categories include `hardening`, `exposure`, `least_privilege`, `iam_graph`, and `network`; `peaso catalog` lists the complete current selection. Missing or empty category/check/framework lists mean the default selection, matching the API. Check IDs and framework names come from `peaso catalog`; unknown IDs and unsupported frameworks fail early. `hacktricks` aliases `HackTricks Cloud Best Practices`; NIST aliases are available only where reviewed mappings support that family.

## Planning, bounds and immutable facts

Default live collection unions selected native-check dependencies with selected graph and defensive-review prerequisites. A hardening scan containing only `aws.ec2.imdsv2` plans `instance` inventory. Explicit `connector.options.inventories` overrides the plan to exactly the requested supported types, allowing inventory-only resources to be requested; selected checks whose facts are omitted remain unknown. `options.collect_all=true` requests all supported inventories and cannot be combined with an explicit inventory list. Snapshot metadata records whether collection followed dependencies, an explicit inventory override, or complete inventory selection.

Adapters bound total calls, page counts, resources, concurrency and retries. They deduplicate provider requests and native IDs, validate continuation tokens/origins, and preserve successful facts when later pages fail or reach a cap. Native payloads keep provider fields, constraints and conditions. Snapshots contain no connector credentials; collectors redact literal workload secrets and sensitive metadata where appropriate. Configuration inventory does not execute workloads or apply remediation. Optional selected-content checks download the explicitly selected artifacts and run offline secret/CVE scanners; private secret values are stored separately from public snapshots. AWS report generation and temporary Access Analyzer operations follow the connector configuration and permissions.

Schema `1.0` uses collections `{type,scope,service,status,items,error?}` with `collected`, `empty`, `partial`, `denied`, `unknown`, `malformed`, `timeout`, and `not_collected` states. Unavailable and empty collections have no items; partial collections retain observed facts. A missing detail remains unknown rather than inheriting a safe default. Successful facts can have a resource-level PASS while incomplete inventory also produces an explicit UNKNOWN coverage result.

Snapshots are canonical JSON addressed by a SHA-256 content digest. Validation rejects inconsistent digests, duplicate collection keys, unsupported schemas and malformed envelopes. Evaluation copies its input and does not rewrite the source snapshot. Caller-owned JSON remains editable; edited content must be sealed as a new snapshot. Resource IDs are stable global digests of provider, authoritative scope, type and native identity; `native_id` retains the provider reference. Account/region, project/location and cluster/namespace identities prevent similarly named resources from aliasing.

## Report and coverage semantics

Reports have `schema_version`, `snapshot_id`, `provider`, `scopes`, `created_at`, `resources`, `findings`, `coverage`, `graphs`, and `stats`. Findings include stable IDs, category/check/title, service/resource/scope, severity/status, framework names, structured evidence and remediation. Native statuses are PASS, FAIL, UNKNOWN, DENIED, EMPTY, MANUAL and NOT_APPLICABLE. EMPTY is an inventory result, never a security pass. Framework tags identify reviewed reference relationships and are not compliance certification.

`stats.coverage_complete` describes the selected check assessments, including unknown and manual prerequisites. `stats.inventory_complete` describes the broader declared collection envelopes, including deliberately uncollected inventory. Neither field establishes that an entire upstream catalog or compliance framework has been implemented. The catalog's `upstream_coverage` counts actual reference dispositions, and pending references do not count as supported. Native per-check fixtures and semantic scope define implemented behavior; see the native rules tests and generated manifest in `peaso/rulepacks/` for the current count.

Registered check definitions and framework mappings are distinct from evidence that a live collector can produce. `catalog_summary.json` reports `inventory_coverage` with native types, reviewed aliases and unavailable projections separately. A scan records requested unavailable projections under `snapshot.metadata.bulk_evidence.unavailable_projections`; their collections have `status=not_collected` and error code `native_evidence_projection_unavailable`. Checks that need those facts remain UNKNOWN. A declared evidence type, a positive unit fixture, or a complete framework mapping does not establish live collection coverage.

Network graph edges describe observed topology references and separately identified modeled rule relationships. They do not establish end-to-end reachability, route priority, ACL/CNI enforcement, or active service exposure. IAM graph edges describe declared policy, trust, membership and binding evidence with confidence and preserved constraints. They do not resolve all AWS SCP/boundary/session-policy intersections, GCP deny/inherited/conditional access, Azure PIM/deny inheritance, or Kubernetes external authorizers. Reference-only principals are labeled as such. Defensive review annotations provide mitigation/manual-review metadata; there are no exploit actions or executable escalation chains.

Diffs compare stable finding IDs, statuses and collected evidence within the same provider and scope selection. A source snapshot-digest change alone is ignored; configuration/evidence changes remain visible. Added/removed findings can reflect coverage or selection differences, so before/after coverage is included in every diff.

## Incremental results and performance

Hosted collectors commit bounded batches of settled inventories (64 envelopes, one second, or 8 MiB by default) before publishing their results. Completed sections become available independently; a later timeout retains the last durable partial snapshot and report. An interrupted process can lose the uncommitted batch. Section completion describes finished collection, and denied or incomplete evidence keeps its existing status.

AWS collection reserves separate bounded slots for ordinary inventory and selected artifact content, so slow image downloads do not occupy every inventory worker. Access Analyzer preparation overlaps ordinary reads. A section becomes ready only after its authoritative account/region discovery and required inventories settle; missing or denied discovery cannot declare it complete.

Public report updates coalesce repeated changes to already available sections for at least eight seconds. After an expensive cumulative publication, this quiet period grows to twice its measured thread CPU cost, capped at 60 seconds. Newly completed sections and categories publish immediately; explicit flushes and final publication bypass the quiet period. An explicit `min_report_interval` retains the configured fixed cadence. Raw checkpoint durability is independent of that cadence. The watcher reads small publication metadata once per immutable report reference; stage workers load and validate their own complete inputs. Unchanged public artifacts reuse exact same-scan content references. The scan-local cache retains up to 8,192 hashes and references, without payloads, so large report working sets do not evict every fragment before the next checkpoint. Reuse still requires identical bytes and successful durable publication.

Image checks share captured payloads, and complete platform-specific CVE results can be reused only under the same account, repository, exact image digest and fresh database lease. Incomplete analyses remain incomplete. Progressive reviews expand grouped cards back into their native observations and reuse only conclusive reviews with identical evidence, referenced resources, access context and section revision. A newer revision waits for the running review of that section to settle; unrelated sections remain parallel.

Privilege evaluation indexes native collections once per model. Network evaluation indexes Kubernetes labels and AWS subnet associations within each evaluation, preserving native order, per-resource evidence and uncertain matches. These changes remove repeated work without reducing the selected checks, pages, resources or graph relationships. Offline phase benchmarks do not establish a cloud scan completion time.

## Validation and maintenance

Run focused tests for the changed component before the release gate:

```sh
.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_peaso_engine.py tests/test_peaso_analysis.py
.venv/bin/python scripts/peaso_compliance_materialize.py
.venv/bin/python examples/benchmark_peaso.py --resources 30000
.venv/bin/python examples/benchmark_peaso_k8s.py --resources 10000
.venv/bin/python examples/benchmark_peaso_saved_snapshot.py /path/to/private-snapshot.json
```

Benchmarks measure the supplied snapshot or synthetic fixture on the current host. They do not establish provider collection latency, effective access or production capacity. Keep live snapshots and generated results outside the repository. Do not interpret old test totals as acceptance of current source.

For an installed-package check, build and install the wheel into temporary directories, then run the offline verifier:

```sh
python -m pip wheel --no-deps --wheel-dir /tmp/peaso-wheels .
python -m pip install --no-deps --target /tmp/peaso-installed /tmp/peaso-wheels/*.whl
python -I examples/verify_installed_peaso.py /tmp/peaso-installed
```

The verifier exercises bundled native rules without network access. Provider collection, tenant isolation, API lifecycle and UI flows have separate tests. CI runs the broader Python and frontend gates; a mocked fixture proves its stated contract, not successful live collection across an entire account.

Compliance inputs and reviewed descriptions live in [compliance-ledgers](compliance-ledgers/README.md). Unsupported organizational, historical or unavailable evidence must remain excluded or explicitly unassessed; a complete mapping is not a complete live assessment.


### API and worker catalogs

Hosted API packages contain a build-generated privilege display index: technique descriptions, required permissions, references and exact historical report bindings. The API serves this metadata without loading the evaluator or reading privilege YAML catalogs. Complete catalogs and historical replay data stay in the worker image and CLI source. Local server installations retain the engine for local scans.

Release source archives store repeated historical catalog archives and manifests in `peaso/privesc/catalog_versions/runtime-history-v1.zip`. The source freezer verifies every original before omitting its duplicate copy; Git checkouts retain the originals. To restore exact historical files from a release source archive, run `python scripts/peaso_build_privesc_history_pack.py --materialize` in the pinned Linux Python build environment. Exact gzip reproduction depends on the recorded zlib behavior; incompatible compressors fail closed. Current catalog evaluation does not require restoring historical archives, and API historical views use the independent display index.

### Log-page scanning and interrupted image downloads

AWS and GCP application-log pages share one bounded offline TruffleHog preparation pass. Each admitted message still runs through both detectors with its own source, timestamps and private evidence locations; failed preparation falls back to individual scanning. Message, byte, output and time limits remain in force.

ECR layer downloads can resume twice after an interrupted read using the same validated signed URL. A continuation must return the exact remaining byte range; only a file with the full expected size and SHA-256 enters the image scanners. Resumes share the original download deadline, and explicit request caps retain their existing behavior.

Section readiness aggregates settled collection keys once per poll. Sections still publish independently when their required reads finish; denied and partial evidence keep their original status.

### Repeated network map pages

The API reuses containment pages and incident-edge indexes for each tenant, immutable graph reference and page size. A new graph artifact always creates a new index; every request still checks scan ownership. The existing four-entry graph cache retains at most one page-size index per graph, sharing references to graph nodes and edges without changing their evidence, ordering or display limits. Standalone `page_graph` calls avoid building the reusable edge index.

In an offline 20,401-node / 20,000-edge fixture, 22 page requests used about 0.07 CPU seconds including preparation, versus 0.88 seconds rebuilding each page. This measures page projection, not whole-scan or browser latency. Reproduce against a saved earlier `projection.py` with `python -m examples.benchmark_peaso_network_paging --baseline /path/to/baseline_projection.py`.

The API also builds the 500-node expansion view only when an expansion requests it. Page requests share the same bounded artifact cache without retaining an unused expansion view. A synthetic first-page HTTP request over 20,401 nodes and 20,000 edges used median 0.201 CPU seconds instead of 0.334 across five pairs; peak request allocations fell from 26.9 MB to 14.0 MB. Responses matched exactly. This includes in-memory artifact copying and response serialization, excluding app startup and cloud storage latency; it is not a whole-scan timing.


The checkpoint replay benchmark runs the normal native evaluator, redaction, local durable writes and report publication. Use `python -m examples.benchmark_peaso_checkpoint_cadence snapshot.json --baseline /path/to/predecessor/incremental.py --candidate peaso/incremental.py --arrival-gap 8`; `--candidate-first` reverses comparison order. The optional gap uses a controlled arrival clock without sleeping. It measures replay CPU and writes, not live collection latency or S3 traffic. In a retained-workload comparison, four raw batches stayed durable and final report bytes matched while cumulative publications fell from four to two. Reverse-order CPU fell from 48.3 to 28.1 seconds; the first order measured 65.1 to 25.7 seconds. First-use caches and host load affect the timings. The worker can separately reuse unchanged artifact references, which this local writer benchmark does not model.

### Multicloud IAM usage and permission detail reads

AWS usage enrichment overlaps at most two independent account sessions, while keeping each account's report deadline, principal/job binding and evidence intact. Explicit call, page or item caps and shared sessions retain serial admission. Results remain in the original account and native-item order.

AWS report publication also stores a compact, snapshot-bound permission-input artifact containing all IAM user, role, group and policy records plus workload and endpoint records needed to label principal exposures. Permission detail and grant-group endpoints use this input instead of loading unrelated metrics or other inventory. Historical reports remain supported with bounded native-chunk reads. High-risk permission rows, usage evidence and unresolved grants are unchanged.

Hosted JSON exports with completed progressive AI reviews are materialized as private artifacts and returned through signed download URLs. This preserves the exact native checkpoint and its eligible AI revisions without sending the full report through Lambda's response body.

Final native analysis publishes its report before waiting for already-running AI reviews. The supervisor continues renewing their leases and checking cancellation, then supplies their newly durable stage references to final AI processing. Review fingerprint and section revision checks remain unchanged. The collector also carries its validated final metadata into the last cumulative checkpoint, so completed selected image and literal observations retain their cluster and target bindings.

Selected Kubernetes image file names and content windows use bounded detector batches, preserving the original per-part source, paths, order, native read count and cancellation behavior. In one pinned Linux two-file OCI comparison, wall time fell from 18.728 to 11.256 seconds with identical normalized output and three native reads; this is a detector consumer benchmark, not a whole-scan latency claim.

Selected Azure ACR file names and content windows also share bounded TruffleHog batches. Each result still passes through its original per-source detector and private-evidence context, and complete prefix matches survive later incomplete files. A pinned Linux comparison of two exported qualification images reduced detector time from 698.49 to 104.01 seconds with identical public and private semantic hashes; registry download and whole-scan latency were outside that measurement.

Raw checkpoint durability and cumulative report uploads use separate critical sections. A slow report cannot hold up the collector's next raw batch acknowledgment. Encrypted private evidence writes and each supervisor exchange stay serialized, with a fresh private-evidence commit before exposing a completed report; raw sequence and published-report sequence retain their separate monotonic fences.

Image database provisioning records `image.database.acquire` and `image.database.download` through the worker runtime metrics. Azure selected-image metadata also records bounded phase durations and classified failures in `image_database_diagnostics`; it never includes subprocess output, URLs, credentials or local paths. An unavailable or stale database still produces UNKNOWN, and the existing freshness, disk, download and lease limits remain enforced.

AI review preserves a normalized, source-bound Kingfisher or TruffleHog detection as FAIL when the remaining image content has incomplete coverage. The original detector evidence remains intact; incomplete inspection describes coverage rather than removing a demonstrated match.

Large Top 15 SQLite contexts are transported as deterministic gzip when they exceed 64 MiB, retaining every record. The existing 256 MiB agent transport limit remains unchanged. The role-free sandbox streams the database back to a private SQLite file before agent startup, with a 2 GiB expansion limit, CRC/header validation and exclusive no-follow files; corrupt or oversized inputs fail before the agent runs. Small contexts retain the existing format.
