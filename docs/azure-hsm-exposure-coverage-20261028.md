# Azure Managed HSM exposure coverage

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| Public HSM endpoint and public-network gate | Enabled/Disabled gate is joined to the recorded HSM endpoint | `test_managed_endpoint_explicit_network_gate[managed_hsm]` |
| Network ACL default action, public IP allow, and trusted-service bypass | Public allow is flagged, explicit closed ACL blocks, unresolved bypass remains UNKNOWN | `test_managed_endpoint_explicit_network_gate[managed_hsm]` |
| HSM local RBAC grant at root or `/keys` | Read-only local assignment inventory is bound to the HSM and reviewed for outside principals | `test_hsm_local_assignments_read_once_per_top_level_scope`; `test_hsm_local_assignment_to_observed_guest_is_external_principal` |
| Individual key-scoped local grant | Observed key names and `/keys/{name}` assignments are joined; denied inventory is incomplete | `test_hsm_local_assignments_include_individual_key_scope`; `test_hsm_key_inventory_denial_keeps_local_rbac_partial` |
| Role-definition rights and exclusions | Collected local permissions are attached to the principal finding | `test_hsm_role_definition_denial_is_visible` |
| Nested directory-group grant to an outside member | Observed guest and foreign service-principal descendants are flagged with membership path | `test_hsm_local_group_assignment_reaches_nested_outside_members` |

Residual UNKNOWN handling: denied or partial data-plane reads, incomplete group membership, conditional authorization, PIM activation, unobserved key names, and perimeter policy do not prove the absence of outside access. This row reports declared network and local grant paths; it does not test a live secret or key operation.
