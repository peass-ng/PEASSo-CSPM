# Notification Hubs exposure source proof

The collector uses read-only ARM LIST operations, once per selected subscription, namespace, and hub, through the existing per-scan request cache. It never invokes `listKeys` or `getPnsCredentials`.

| Fact | Authoritative source | Snapshot projection |
| --- | --- | --- |
| Namespace public endpoint, ACL and sharing | [Namespaces List All, 2023-09-01](https://learn.microsoft.com/en-us/rest/api/notificationhubs/namespaces/list-all?view=rest-notificationhubs-2023-09-01) | `publicNetworkAccess`, `serviceBusEndpoint`, public and IP rule rights, namespace state, approved private endpoint subscription IDs, configured push-provider names |
| Namespace SAS grants | [Namespace authorization rules LIST](https://learn.microsoft.com/en-us/rest/api/notificationhubs/namespaces/list-authorization-rules?view=rest-notificationhubs-2023-09-01) | Rule ID, name, rights |
| Hubs | [Notification Hubs LIST](https://learn.microsoft.com/en-us/rest/api/notificationhubs/notification-hubs/list?view=rest-notificationhubs-2023-09-01) | Hub ID, name, and configured push-provider names |
| Hub SAS grants | [Hub authorization rules LIST](https://learn.microsoft.com/en-us/rest/api/notificationhubs/notification-hubs/list-authorization-rules?view=rest-notificationhubs-2023-09-01) | Rule ID, name, rights |

The hub LIST schema permits PNS credentials and embedded SAS keys. `azure_notification_hubs_native` projects an allowlist before snapshot assembly. An approved private endpoint in a different subscription is a separate access path even when public network access is disabled. The provider does not expose issued SAS tokens or their recipients in these LIST APIs, so native assessment records the grant capabilities without attributing key ownership.
