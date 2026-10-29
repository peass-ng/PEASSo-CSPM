Kubernetes automatic-content startup failure
===========================================

An API bootstrap exception can occur before workload discovery initializes its
automatic-content metadata. The collector already catches that exception and
creates degraded native rows, but exporting their metadata then raises
`AttributeError: automatic_literal_coverage`, masking the original failure.

Initialize incomplete/uninspected coverage and an empty batch list before API
bootstrap. Early failures now return sealed snapshots with their original
unknown, malformed or denied rows and sanitized error codes. Zero discovered
targets means discovery did not run: `complete=False` and
`reason=source_inventory_unavailable` preserve that distinction. Successful
discovery replaces the defaults through the existing code; explicit selection
and disabled-content metadata shapes stay unchanged.

Observed trigger: the local Linux benchmark used a non-writable temporary
mount for image UID10001. `TemporaryDirectory` raised `FileNotFoundError` before
any provider call, followed by the secondary metadata error. Correct tmpfs
permissions fixed the benchmark environment. This source repair separately
handles startup failures, without changing TLS, permissions or detector behavior.

The three automatic-mode regression cases fail on the parent; the unchanged
nonautomatic case passes. The repaired tree passes **142 focused tests**, seven
combined release checks, nine strict source checks, and the whole historical
epoch reconstruction. Generated catalogs have no stale files. The exact current
collector/API source pins are rebound; historical epochs, inverse bytes, source
rosters and guard code are unchanged. Numeric receipts and log hashes are in the
companion JSON.

No live scan, model, connector operation, resource creation, push, deployment or
Access Analyzer call was made. Azure/K8s fixtures were already deleted at the
user's direction. The GCP fixture remains held for root's post-release firewall
measurement. This repair has no performance claim.
