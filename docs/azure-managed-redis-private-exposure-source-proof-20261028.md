# Azure Managed Redis private exposure source proof

The [Redis Enterprise private endpoint connection LIST API](https://learn.microsoft.com/en-us/rest/api/redis/redisenterprisecache/private-endpoint-connections/list?view=rest-redis-redisenterprisecache-2025-07-01) returns each connection's private endpoint ARM ID, approval status, and provisioning state. The collector uses a read-only call through the existing per-scan cache and validates the returned child IDs against the selected cluster.

`internet_exposure._azure_redis_enterprise` identifies approved, provisioned private endpoints in another subscription. Such a connection provides a third-party route to the database listener even with public network access disabled, subject to database authentication. An incomplete list or ambiguous connection state produces UNKNOWN when no public listener is established.
