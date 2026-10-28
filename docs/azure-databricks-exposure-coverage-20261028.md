# Azure Databricks workspace exposure coverage

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| ARM public-network gate and workspace URL | Disabled blocks direct public workspace ingress; enabled proceeds to policy joins | `test_databricks_arm_public_gate_keeps_external_ingress_policy_unknown` |
| Workspace IP access list ALLOW and BLOCK rules | Collected lists are joined to a concrete public IPv4 witness; BLOCK overrides the same source | `test_collected_ip_lists_join_workspace`; `test_workspace_block_overrides_same_public_allow_under_full_context_access` |
| Account context-based ingress policy | Workspace binding joins the account policy; full or restricted access and empty rules receive native decisions | `test_account_policy_join_and_exposure`; `test_full_ingress_and_disabled_ip_lists_prove_public_listener` |
| Workspace UI source, identity and destination policy | Supported broad UI allow and deny rules intersect with IP lists | `test_restricted_public_ui_rule_with_ip_intersection`; `test_nonempty_deny_rules_prevent_unqualified_public_claim` |
| Workspace API/SQL and service-principal policy | Supported API destination and identity-class rules intersect with their applicable denies | `test_workspace_api_and_ui_deny_destinations`; `test_api_identity_classes_and_matching_denies` |
| Credential-bound policy collection | Workspace-ID keyed PAT and account authorization are validated; missing credentials or denied reads remain UNKNOWN without a speculative policy claim | `test_missing_pat_never_calls_workspace`; `test_denied_policy_read_keeps_ingress_unknown` |

Residual UNKNOWN handling: expired or absent owner-approved credentials, partial reads, selected identities, unsupported source/destination selectors, unresolved deny semantics and runtime policy do not establish a closed path. A public listener decision concerns declared authenticated ingress and does not claim anonymous data access.
