# Azure ML workspace ACL source proof

The Azure collector changed from SHA-256
`ba4b8bc54cdcbb1e35ef50a7dea9d04928a6fe5ed6ca885e4722ec1c8e750d67`
to `8727e003b43da456c709908dae7e9fbd84824ade6fdf4ea8fabaed6f5a781d13`.
The collector diff only changes the existing subscription workspace LIST from
`2024-04-01` to `2026-03-01`. It remains one paged, read-only ARM request through
the per-scan reader; no second workspace fetch is introduced. The current
[workspace schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.machinelearningservices/2026-03-01/workspaces)
includes `properties.networkAcls.defaultAction` and `ipRules`, which the native
ML exposure assessment already evaluates. If the response omits `networkAcls`,
the assessment remains `UNKNOWN`.

`scripts/peaso_repin_sources.py --base dff2ce86` refreshed current successor
pins for this branch's reviewed changes and left archived digests fixed. The
focused normal-attestation collector and exposure tests passed 4/4. They verify
the API version, one workspace LIST, retained ACL data, and native ACL decisions.
No Azure resource was read or modified during this proof.
