# Azure Data Share exposure source proof

The reviewed Azure collector SHA-256 after this change is
`4b5bb4e9c4ca71508533cd0a4a696f97efdf63319cbaa9c39f8845fce83f78cb`.

The collector uses paged, read-only ARM LISTs for
[accounts](https://learn.microsoft.com/en-us/rest/api/datashare/accounts/list-by-subscription?view=rest-datashare-2021-08-01),
[shares](https://learn.microsoft.com/en-us/rest/api/datashare/shares/list-by-account?view=rest-datashare-2021-08-01),
[invitations](https://learn.microsoft.com/en-us/rest/api/datashare/invitations/list-by-share?view=rest-datashare-2021-08-01), and
[provider share subscriptions](https://learn.microsoft.com/en-us/rest/api/datashare/provider-share-subscriptions/list-by-share?view=rest-datashare-2021-08-01).
The existing per-scan reader caches requests and checks continuation URLs. Child IDs and types are bound to the observed parent; malformed or duplicate children cannot establish complete collection. Only recipient and status fields needed for exposure reach the snapshot.

An Active provider share subscription produces a native data-sharing finding. An accepted invitation with a foreign target tenant is recorded as unresolved until an active provider subscription is observed; pending invitations and email-only recipients are likewise unresolved. Revoked subscriptions and rejected or withdrawn invitations are inactive. The provider subscription API supplies a tenant name rather than a tenant ID, so recipient ownership cannot be proven from that response alone. The finding represents sharing capability and does not claim a dataset was transferred.

Focused fake-transport tests cover exact reads, no duplicate calls, a foreign child ID, and native decisions. No Azure resource was read or modified for this proof.
