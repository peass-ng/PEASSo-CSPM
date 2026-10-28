# Service Bus namespace SAS rule source proof

The Azure collector SHA-256 after this change is
`5eb0bbe375f851c6e66b247bc6f49291f40a8079550538775780f28368bb5961`.
The added [Service Bus authorization-rule LIST](https://learn.microsoft.com/en-us/rest/api/servicebus/controlplane/namespaces/list-authorization-rules?view=rest-servicebus-controlplane-2024-01-01)
is `GET {namespace}/AuthorizationRules?api-version=2024-01-01`. It uses the
existing paged, read-only per-scan ARM reader. Only rule identity and `rights`
(`Manage`, `Send`, `Listen`) enter the snapshot; keys and other response fields
are discarded. Missing, denied, or malformed reads retain explicit coverage
status and cannot imply an empty rule set.

Microsoft's [SAS authorization documentation](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas)
describes namespace, queue, and topic rules. A rule records a capability of
whoever holds its key, not the identity of those key holders or issued token
recipients. The [local-authentication setting](https://learn.microsoft.com/en-us/azure/service-bus-messaging/disable-local-authentication)
can disable SAS. Native exposure evidence therefore reports namespace rule
rights only when `disableLocalAuth` is explicitly false; it does not infer a
third-party recipient from a rule's existence. Queue and topic rule inventory
and issued-token recipients remain separate gaps.

`scripts/peaso_repin_sources.py --base HEAD` refreshed current successor pins
after the collector edit. Archived epoch digests remain fixed. Tests use a fake
transport; no Azure resource was read or modified.
