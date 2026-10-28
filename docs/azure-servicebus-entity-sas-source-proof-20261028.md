# Service Bus queue and topic SAS rule source proof

The Azure collector SHA-256 after this change is
`e6739b54f408957f1504a9fa7d2014fce9cae90d09be7ccafb5574fee1c81110`.
The collector adds paged ARM GETs for [queues](https://learn.microsoft.com/en-us/rest/api/servicebus/controlplane/queues/list-by-namespace?view=rest-servicebus-controlplane-2024-01-01)
and [topics](https://learn.microsoft.com/en-us/rest/api/servicebus/controlplane/topics/list-by-namespace?view=rest-servicebus-controlplane-2024-01-01)
within each observed namespace, then paged GETs for each observed
[queue authorization rule](https://learn.microsoft.com/en-us/rest/api/servicebus/controlplane/queues/list-authorization-rules?view=rest-servicebus-controlplane-2024-01-01)
and [topic authorization rule](https://learn.microsoft.com/en-us/rest/api/servicebus/controlplane/topics/list-authorization-rules?view=rest-servicebus-controlplane-2024-01-01).
All use API version `2024-01-01`, the existing per-scan reader, and no request
body. Entity IDs must remain under their observed namespace; rule IDs must
remain under their observed entity. Only IDs, names, types and rule rights enter
the snapshot. Keys and entity properties are discarded. Duplicate identities,
malformed pages, and denied reads retain non-complete coverage instead of
asserting an empty rule set.

The native Service Bus endpoint assessment records observed queue/topic SAS
rights when local SAS authentication is explicitly enabled, without deriving
key holders or issued-token recipients from rule existence. A partial child
inventory is identified in the finding notes. Existing namespace SAS rule
inventory remains in place. No Azure resource was read or modified for this
proof; tests use a fake transport.
