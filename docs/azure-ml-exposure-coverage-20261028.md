# Azure Machine Learning exposure coverage

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| Workspace public network gate and selected-IP ACL | Joins the recorded gate and public/private ACL sources; absent ACL evidence stays UNKNOWN | `test_ml_workspace_online_endpoint_and_selected_ip_acl`; `test_ml_workspace_uses_one_current_acl_capable_list_read` |
| Online scoring endpoint public gate and URI | Joins each cached child to its workspace; disabled child blocks direct scoring ingress | `test_ml_workspace_online_endpoint_and_selected_ip_acl`; `test_ml_online_endpoints_paged_once_and_bound_to_workspace` |
| Lingering selected-IP access after a workspace public-gate change | A collected public source on an enabled child remains an exposure candidate | `test_ml_workspace_online_endpoint_and_selected_ip_acl` |
| Key, AMLToken and AADToken scoring authorization modes | Reports the observed mode and its credential or RBAC requirement without inferring token possession | `test_public_scoring_path_records_native_auth_mode`; `test_disabled_endpoint_does_not_claim_public_scoring_auth_path` |
| Outside-principal scoring or credential-retrieval RBAC grant, including group descendants | Joins mode-specific actions, role scope and exclusions to the observed principal | `test_external_guest_has_declared_mode_specific_scoring_grant`; `test_mode_scope_and_exclusions_prevent_false_scoring_grant` |
| Inherited all-principal deny for the scoring action | Blocks the matching observed grant | `test_inherited_all_principal_data_deny_blocks_aad_scoring_action` |

Residual UNKNOWN handling: missing or unsupported gates, incomplete child or directory inventory, issued key/token recipients, conditional or narrower deny effects, PIM activation, principal-specific network path and runtime scoring authorization are not inferred. A declared public scoring path does not establish anonymous scoring.
