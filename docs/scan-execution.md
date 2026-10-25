# Scan execution and saved sections

A scan does not wait for unrelated sections before publishing results. Completed
native evidence is saved during collection. Each report identifies the status
and data revision of Checks, Exposure, IAM, Network, Privilege Escalation, Leaks
and Image CVEs in `publication.sections`.

The collector and progressive analyzer run concurrently. On AWS, AI tasks have
no task role and receive presigned transport for each invocation. The collector
reads the selected cloud scope and publishes sanitized
snapshots. Native checks and graph evaluation use the evidence already read;
missing dependencies remain unresolved. A section is complete when its required
reads have finished across its planned scopes, including reads that returned
access denied or incomplete evidence. Complete execution does not mean a pass.

Hardening, exposure and network AI reviews start independently when their input
section is complete. Their outputs are saved separately from advancing native
reports. Top 15 Actions waits for the reviews it uses. Final analysis reuses
completed reviews only when their section revision and finding inputs match.
AI tools remain isolated. AWS AI reviews use captured evidence only and receive
no AWS session; native deterministic checks still use customer credentials.
Eligible GCP, Azure and Kubernetes connectors may permit targeted read-only
verification by AI tools.
The progressive analyzer admits up to two sections concurrently. Each section
uses the memory-aware review pool (two batches by default, up to 40 findings per
batch), allowing up to four simultaneous AI agents per scan.
`PEASO_AI_MAX_CONCURRENCY` sets the per-section limit from one to six; available
task memory can reduce admission (512 MiB per local agent, 128 MiB of local
staging per Fargate-isolated agent). Top 15 runs after its prerequisite reviews.

The UI and the normal authenticated scan APIs expose saved results while other
sections are running. Saved partial results remain available after a later
failure, cancellation or timeout. A completed final report takes precedence.

Up to ten scans can be admitted concurrently. Additional requests wait in a
durable queue; waiting does not consume the execution budget. A request that
cannot obtain a slot within one hour ends with `queue_exhausted` and a specific
explanation. Cancellation and terminal transitions release admission capacity.

## Resume after credentials expire

An explicit provider credential-expiration code ends collection as
`credentials_expired`; ordinary access denial remains an incomplete native read.
The latest sealed snapshot and committed batches stay on the original scan row.
After updating the same connector's credentials, `POST /api/scans/{id}/resume`
with `{}` queues that row again. Its scan ID, creation time, selectors, saved
reports, checkpoints and private evidence remain attached. Resume does not use
another weekly scan allowance. A changed provider, selected scope, connector
identity or options requires a new scan.

The queue admits a resume under the same ten-scan limit and one-hour wait.
Each attempt has a new owner and hosted workflow execution name; the previous
worker cannot publish through its old lease. When the native snapshot is sealed,
the resumed collector reuses a kind only if all explicitly selected scopes for
that kind were fully collected or empty. It reruns unfinished or denied kinds
with the refreshed connector, merges their envelopes with prior native evidence,
and continues report evaluation. A saved checkpoint without a sealed native
snapshot retains its partial results but is not exposed as resumable: that batch
cannot prove the complete scope and metadata plan needed to skip settled work.
Resuming a scan interrupted during analysis uses its
sealed snapshot and matching review-stage checkpoints without recollecting.

Selected content uses bounded parallel reads and offline detector batches.
TruffleHog and Kingfisher do not validate discovered credentials. Scan duration
still depends on the selected cloud scope, data volume, rate limits and enabled
content or image scans; section publication does not wait for the entire scan.
