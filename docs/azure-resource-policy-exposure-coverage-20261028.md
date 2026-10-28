# Azure key, secret, messaging, registry and Function policy coverage

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| Key Vault legacy access policy grants keys or secrets to an outside principal | Observed Guest, foreign service principal and nested group member grants are flagged; RBAC mode does not activate legacy policies | `test_guest_vault_access_policy_is_external_data_grant`; `test_vault_group_policy_reaches_nested_foreign_service_principal`; `test_rbac_mode_and_non_grants_do_not_activate_legacy_policy` |
| Managed HSM local key-scoped grant | Local `/keys/{name}` assignment and role rights join observed outside principals | `test_hsm_local_assignments_include_individual_key_scope`; `test_hsm_local_assignment_to_observed_guest_is_external_principal` |
| Service Bus namespace SAS authorization | Collected rights and the local-authentication gate are recorded without key material or inferred recipients | `test_namespace_sas_rights_are_collected_without_key_material`; `test_disabled_local_auth_does_not_claim_sas_recipient` |
| Service Bus queue and topic entity SAS authorization | Rights are bound to each observed entity; denied pages are incomplete | `test_entity_sas_rule_rights_are_bound_to_observed_entity`; `test_entity_rule_denial_is_not_an_empty_inventory` |
| Event Hubs namespace and entity SAS authorization | Bound rule rights are recorded only with enabled local authentication; keys are redacted | `test_eventhub_sas_rule_rights_are_bound_and_keys_are_redacted`; `test_disabled_eventhub_local_auth_does_not_apply_sas_rights` |
| ACR anonymous pull | Public network path plus anonymous-pull setting reports unauthenticated pull capability | `test_acr_anonymous_pull_follows_the_public_network_path` |
| ACR repository tokens, scope maps and admin credentials | Enabled token actions and admin capability are recorded without inferring credential possession | `test_enabled_acr_token_reports_bounded_repository_rights`; `test_admin_credentials_capability_does_not_override_network_block` |
| Function HTTP authorization and App Service authentication | Anonymous versus function/admin-key triggers are reported beside the site's separate built-in authentication and network gates | `test_function_http_trigger_auth_levels_are_native_evidence`; `test_app_service_parent_authentication_is_informational_for_public_listener` |

Residual UNKNOWN/MANUAL handling: denied or partial policy inventories, application-bound vault policies, conditional RBAC, issued SAS/key/token recipients, stored or signed URLs, Function route code authorization and runtime identity decisions are not inferred. Native findings report configured capabilities and observed outside grants. They do not claim that an unobserved credential has been issued or used.
