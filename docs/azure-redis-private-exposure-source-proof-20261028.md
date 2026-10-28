# Azure Cache for Redis private exposure source proof

The [Redis private endpoint connection LIST API](https://learn.microsoft.com/en-us/rest/api/redis/private-endpoint-connections/list?view=rest-redis-2024-11-01) is a read-only child request for each cache. It returns the private endpoint resource ID, approval status, and provisioning state. The collector uses its existing per-scan reader cache, validates the child path against the selected parent, and preserves incomplete collection as UNKNOWN.

`internet_exposure._azure_redis` compares approved, provisioned endpoint subscription IDs with the cache subscription. A foreign subscription is a third-party private route even when `publicNetworkAccess` blocks the public listener. Pending or local connections are not reported as external; ambiguous approval or ownership stays UNKNOWN. A private route establishes network reachability, subject to Redis authentication.
