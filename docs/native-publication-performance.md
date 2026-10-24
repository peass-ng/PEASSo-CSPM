# Native snapshot and publication reuse

`make_snapshot` validates its newly constructed document once. Validation already makes an independent structural copy, checks every collection, and calculates the canonical snapshot digest. External snapshot validation still verifies supplied digests; the builder has no inherited digest to verify. Malformed collections, non-finite values, mismatched digests and unsupported providers remain rejected.

A publication prepares its immutable native inventory once and shares it between Markdown expansion, resource chunks and least-privilege projection. This inventory belongs only to that snapshot and publication. It is released before subsequent projections and is never cached across scans, revisions or identities. Legacy reports retain their existing path.

Offline Python 3.12 measurements on a captured 349,768-item snapshot reduced builder time from 7.375 to 3.360 seconds while preserving its exact full digest. On the corresponding large report, a complete warm publication fell from 46.06 to 38.30 seconds, CPU time from 44.78 to 38.13 seconds, and peak RSS from 3.907 to 3.353 GB. All 2,152 independent compressed artifact payloads remained identical. Manifest references are newly allocated; separate regressions compare fully dereferenced manifests, including complete native resource details.

These are local macOS stage measurements, excluding cloud collection and network writes. They do not establish production or whole-scan latency. The changes preserve requested inventories, coverage and durable section publication.

When AI is explicitly disabled, the analyzer records the actual skipped AI result before publishing its native bundle. It acknowledges that same final bundle instead of serializing and uploading a second equivalent report. AI-enabled scans retain native publication before review and a later reviewed publication. Publication revisions invalidate the frontend result cache even when the job status has not yet changed.

Bulk evidence assembly retains the existing collection references only until the snapshot builder makes its validated independent copy. Alias envelopes still receive their own defensive copies. Source snapshots and aliases remain independently mutable after assembly.

AWS usage reports can overlap independent collection with at most two account jobs. Reports remain bound to the authenticated session, region, account and principal ARN. A pending report can receive one bounded late retry using its original authenticated job, rather than generating another report. Explicit shared call/page/item limits retain the serial path. This removes a dependency barrier; it does not promise a particular end-to-end runtime.

An explicit credential-expiry code in a native IAM usage report marks the scan as credentials expired while retaining its saved snapshot and findings. The affected IAM collection remains partial so resume retries it; ordinary access denial does not expire credentials, and completed unrelated collections remain reusable.
