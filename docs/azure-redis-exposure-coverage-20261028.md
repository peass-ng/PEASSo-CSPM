# Azure Redis exposure coverage

The native internet-exposure assessment covers these practical direct-ingress paths. Each item is exercised by an existing test run on this branch.

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| Azure Cache for Redis public network gate | Disabled blocks; Enabled proceeds to firewall and listener assessment | `test_redis_public_listeners_preserve_firewall_uncertainty` |
| Redis public IPv4/IPv6 firewall range, including an empty rule list | A collected public source or unrestricted empty list exposes the listener; private-only ranges block direct public ingress | `test_redis_public_listeners_preserve_firewall_uncertainty`; `test_redis_firewall_list_once_and_assess_public_rule` |
| Premium VNet-injected cache | A validated subnet reference blocks direct public cache ingress | `test_redis_public_listeners_preserve_firewall_uncertainty` |
| TLS and optional non-TLS Redis listener | Reports observed public hostname and TCP ports | `test_redis_public_listeners_preserve_firewall_uncertainty` |
| Azure Managed Redis / Redis Enterprise public database listener and cluster firewall | Joins parent public gate, child database port, and public/private firewall sources | `test_redis_enterprise_managed_redis_database_listener_gates`; `test_redis_enterprise_parent_and_database_are_read_once` |

Residual UNKNOWN handling: absent or malformed public gate, hostname, port, firewall, subnet identity, or denied/partial child collection cannot prove a closed path. A proxy in another resource is assessed at that proxy's ingress, and authentication or possession of Redis credentials is not inferred from a public listener. The tests above cover the corresponding UNKNOWN decisions. This row describes declared direct reachability, not a live connection attempt.
