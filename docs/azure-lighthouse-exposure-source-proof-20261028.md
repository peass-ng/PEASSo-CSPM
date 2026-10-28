# Azure Lighthouse exposure source proof

The reviewed Azure collector SHA-256 after this change is
`5719831b33f0d5c2f3b28e09c5ac8fd0879a0cb071952c6687b5b38238b9bd97`.

[Azure Lighthouse architecture](https://learn.microsoft.com/en-us/azure/lighthouse/concepts/azure-delegated-resource-management) states that a registration assignment at a subscription or resource group scope activates a registration definition's managing-tenant authorizations. The collector uses one paged, read-only [registration assignment LIST](https://learn.microsoft.com/en-us/rest/api/managedservices/registration-assignments/list?view=rest-managedservices-2022-10-01) per selected subscription and enumerated resource group, with `$expandRegistrationDefinition=true`. It reuses the selected subscription and resource-group inventory and the per-scan request cache. Assignment IDs are bound to the requested scope; only tenant IDs, status and role/principal identifiers are retained. Missing expansion, malformed children and incomplete group enumeration cannot prove absence.

The native assessment reports a succeeded foreign managing-tenant assignment with active authorization as a delegated access finding. Eligible-only just-in-time roles remain unresolved until activation; same-tenant or empty authorizations are inactive. The finding establishes a configured ARM delegation, not a specific data-plane operation or observed request.

Focused fake-transport tests cover subscription and resource-group scope reads, the foreign/same-tenant/eligible decisions, and incomplete group-list coverage. No Azure resource was read or modified for this proof.
