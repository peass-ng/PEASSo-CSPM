# Azure exact federated subject ownership (2026-10-28)

The [Microsoft Graph federated credential model](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-1.0) requires an incoming token's issuer, subject, and audience to match a configured credential. An exact subject narrows which external workload token can be exchanged; the credential alone does not establish that the scanned tenant controls the subject at the issuer. The native classifier now reports a well-formed exact subject as MANUAL with its selectors, and missing issuer or audience evidence as UNKNOWN. The existing collection, token exchange, and flexible-expression decisions are unchanged.

Current trust analyzer SHA-256: `49d6e32f8feaa6d555fab22967846a5dfcdba498f7044c0abf19409ad18839e5`.
