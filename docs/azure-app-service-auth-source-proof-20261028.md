# Azure App Service slot authentication source proof

The reviewed Azure collector changes from SHA-256
`7f44e70205f6fb4ffbea3b787af2947871236d16e50095eb8660f6ac846d690f`
to `4ae95e535801cc62f2ee08015bfd6458957cf0247f40a8fb9a153b9949cf623c`.
Its source diff adds a slot `config/authsettingsV2` singleton read at API version
`2025-05-01` and retains `globalValidation.excludedPaths` in the existing
redacted authentication projection. The [Microsoft slot API](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-auth-settings-v-2-without-secrets-slot?view=rest-appservice-2025-05-01)
documents this read-only, without-secrets GET.

The existing singleton path validates the returned child ID, uses the per-scan
request cache, records read status, and stores only platform enabled, the
authentication action and requirement, excluded route paths, and provider
enabled flags. It does not store provider registrations or secrets. The native
assessment treats the built-in authentication requirement as evidence about
request authorization, while retaining a public-listener finding where network
access permits traffic. A missing, partial, mismatched, or exception-bearing
auth configuration does not prove all routes require authentication.

`scripts/peaso_repin_sources.py` refreshed current-byte source pins. The
archived epoch source and predecessor digests remain fixed. A focused
transport test checks that a mock provider secret is absent from the snapshot.
