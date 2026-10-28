# Event Hubs SAS rule source proof

The Azure collector SHA-256 after this change is
`4ae95e535801cc62f2ee08015bfd6458957cf0247f40a8fb9a153b9949cf623c`.
The existing collector reads paged namespace [authorization rules](https://learn.microsoft.com/en-us/rest/api/eventhub/authorization-rules-namespaces/list-authorization-rules?view=rest-eventhub-2024-01-01)
and paged namespace Event Hubs. The new read uses the observed Event Hub ID
for the paged [entity authorization-rule LIST](https://learn.microsoft.com/en-us/rest/api/eventhub/event-hubs/list-authorization-rules?view=rest-eventhub-2026-01-01):
`GET {eventHubId}/authorizationRules?api-version=2026-01-01`. It runs through
the per-scan ARM reader without a request body. Parent and child identities are
validated; only rule identity and `Manage`/`Send`/`Listen` rights are retained.
No key or connection-string operation is called. Denied, malformed, and
incomplete pages retain explicit coverage rather than becoming empty lists.

Microsoft's [Event Hubs SAS documentation](https://learn.microsoft.com/azure/event-hubs/authenticate-shared-access-signature)
states that namespace and entity rules grant rights to whoever holds a key,
and `disableLocalAuth: true` disables SAS. The native endpoint assessment
reports observed namespace and entity rights when local auth is explicitly
enabled. It does not infer key holders, issued tokens, or recipients from rule
existence. Fake-transport tests cover rights, redaction, denied reads, and the
disabled local-auth setting. No Azure resource was read or modified.
