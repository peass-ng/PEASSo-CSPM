# Exposure wave 2 integration receipt

This local wave extends `95d6c3ab` (deployed `d7a9fd42` ancestry) with committed Azure A/B, AWS A/B, and GCP A/B slices. It excludes the AWS B Client VPN route read until its customer-role grant is closed. The owner worktrees' uncommitted work is not included. K8s B was already present in the `95d6c3ab` predecessor.

Integrated owner boundaries:

- Azure A through `070009d8`; Azure B `2cbcfbb3..70b2673e`.
- AWS A `e41b4d76..ae570662`; AWS B `423e6fcb..406673ba`, excluding the Client VPN route commits `8e553888` and `d1a0005e`.
- GCP A `dff2ce86..052680a5`; GCP B `f7910e1b..1b5565bf`.

The merge preserves the existing provider detections and adds the new resource conditions, collection fields, and 3–5 line observed evidence. It refreshes the reviewed collector successor, Azure native-final source pin, API service-source manifest, materialized catalog and privilege display catalog, and AWS customer-role policy for the newly used reads.

The 2026-10-20 historical bridge fixtures are frozen to an older source epoch. The exact current-vs-frozen file hashes and deployed-baseline comparison are in [exposure-wave2-bridge-receipt-20261028.json](exposure-wave2-bridge-receipt-20261028.json). Its catalog comparison shows the same 3,553 check IDs, no added or removed IDs, and a changed `clarity_evaluation_contract` fingerprint on each row. The historical bridge's exact-byte assertions therefore fail on intentional source/catalog changes. The frozen fixture remains unchanged; current source, catalog, and release gates are run separately.
