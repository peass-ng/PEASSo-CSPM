# Azure Managed Redis exposure source proof (2026-10-28)

Microsoft identifies `Microsoft.Cache/redisEnterprise` as both Redis Enterprise and Azure Managed Redis. A database child is required for a functioning instance: [ARM resource reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.cache/redisenterprise).

The existing network catalog parent LIST uses stable API version `2025-07-01`, whose [Redis Enterprise GET schema](https://learn.microsoft.com/en-us/rest/api/redis/redisenterprisecache/redis-enterprise/get?view=rest-redis-redisenterprisecache-2025-07-01) exposes `properties.publicNetworkAccess` and `properties.hostName`. The new bounded, paged read-only child operation is [Databases - List By Cluster](https://learn.microsoft.com/en-us/rest/api/redis/redisenterprisecache/databases/list-by-cluster?view=rest-redis-redisenterprisecache-2025-07-01), `GET {clusterId}/databases?api-version=2025-07-01`; it exposes each database's client TCP `port` and `clientProtocol`.

The collector validates parent-bound child IDs and preserves incomplete/denied status. Native analysis reports an explicit public gate with an observed valid database port as a declared listener; a disabled gate blocks, and an incomplete child read without a positive listener stays unresolved. It does not claim authentication or successful connection.
