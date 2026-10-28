# Azure managed endpoint exposure coverage

This row covers declared direct public and third-party Azure source paths. Authorization to use a reachable service is assessed by the corresponding identity or resource-policy row.

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| Key Vault public gate, ACL default and public IP rules | Public allow is flagged; explicit closed ACL blocks; trusted-service bypass is UNKNOWN | `test_managed_endpoint_explicit_network_gate[vault]` |
| ACR and Cognitive Services public gate and parent IP rules | Public allow is flagged; private-only rules block direct public ingress | `test_managed_endpoint_parent_public_ip_rules`; `test_managed_endpoint_explicit_network_gate[container_registry]` |
| Azure AI Search IP restrictions and App Configuration public gate | Collected public sources or unrestricted gate are flagged; private-only rules block | `test_search_ip_restrictions_and_app_configuration_public_gate` |
| Service Bus and Event Hubs namespace network-rule children | Joined `networkRuleSet` public IP masks are evaluated; trusted-service and denied reads remain UNKNOWN | `test_broker_namespace_cached_network_rule_child`; `test_denied_or_missing_rule_set_and_unsupported_public_mode_are_unknown` |
| Cosmos DB public IP rules and cross-tenant Azure marker | Public source or `0.0.0.0` Azure-services rule is flagged; malformed lists remain UNKNOWN | `test_cosmos_ip_allow_rules_and_cross_tenant_azure_marker` |
| Cosmos DB VNet-only direct public path | Validated same-subscription subnet identities plus closed bypass block a direct public IP path; foreign subnet/bypass remains UNKNOWN | `test_cosmos_ip_allow_rules_and_cross_tenant_azure_marker` |
| MySQL and PostgreSQL flexible-server public firewall children | Complete public ranges and cross-tenant Azure marker are flagged; private-only ranges block direct public ingress | `test_flexible_database_firewall_public_and_cross_tenant_sources`; `test_mysql_flexible_firewall_child_list_once` |
| ACR anonymous pull on an observed public listener | Reports unauthenticated pull capability without claiming images exist | `test_acr_anonymous_pull_follows_the_public_network_path` |

Residual UNKNOWN handling: malformed or missing gates/rules, denied or partial children, trusted-service bypass, Cosmos foreign-subnet authorization, flexible-server delegated-subnet routes and database-specific data-plane firewall effects do not prove absence of access. Private endpoint and proxy ingress are separate network paths. A public listener does not prove successful authenticated data access.
